package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
)

func main() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Error finding home directory: %v", err)
	}
	defaultShell := os.Getenv("SHELL")
	if defaultShell == "" {
		defaultShell = "/bin/sh"
	}

	defaultHostKey := filepath.Join(homeDir, ".ssh", "single_user_host_key")
	defaultAuthKeys := filepath.Join(homeDir, ".ssh", "authorized_keys")

	listenAddr := flag.String("addr", ":2222", "Address to listen on")
	hostKeyFile := flag.String("hostkey", defaultHostKey, "Path to private host key")
	authKeysFile := flag.String("authkeys", defaultAuthKeys, "Path to authorized_keys file")
	shell := flag.String("shell", defaultShell, "shell to use")
	flag.Parse()

	s := &ssh.Server{
		Addr: *listenAddr,

		LocalPortForwardingCallback: func(ctx ssh.Context, dHost string, dPort uint32) bool {
			log.Println("Denied local port forwarding request")
			return false
		},
		ReversePortForwardingCallback: func(ctx ssh.Context, bHost string, bPort uint32) bool {
			log.Println("Denied reverse port forwarding request")
			return false
		},

		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			data, err := ioutil.ReadFile(*authKeysFile)
			if err != nil {
				log.Printf("Auth Error: Could not read %s", *authKeysFile)
				return false
			}
			for len(data) > 0 {
				allowed, _, _, rest, err := ssh.ParseAuthorizedKey(data)
				if err != nil {
					break
				}
				if ssh.KeysEqual(key, allowed) {
					return true
				}
				data = rest
			}
			return false
		},
	}

	if _, err := os.Stat(*hostKeyFile); err == nil {
		log.Printf("Using host key: %s", *hostKeyFile)
		s.SetOption(ssh.HostKeyFile(*hostKeyFile))
	} else {
		log.Printf("Host key not found at %s. Using ephemeral key.", *hostKeyFile)
	}

	s.Handler = func(s ssh.Session) {
		if ptyReq, winCh, isPty := s.Pty(); isPty && len(s.Command()) == 0 {
			cmd := exec.Command(*shell)
			cmd.Env = append(os.Environ(), fmt.Sprintf("TERM=%s", ptyReq.Term))

			f, err := pty.Start(cmd)
			if err != nil {
				io.WriteString(s, "Error allocating PTY: "+err.Error())
				s.Exit(1)
				return
			}

			go func() {
				for win := range winCh {
					pty.Setsize(f, &pty.Winsize{Rows: uint16(win.Height), Cols: uint16(win.Width)})
				}
			}()

			var wg sync.WaitGroup
			wg.Add(1)

			go func() {
				io.Copy(f, s)
				f.Close()
			}()

			go func() {
				defer wg.Done()
				io.Copy(s, f)
			}()

			cmd.Wait()
			wg.Wait()
			return
		}

		var cmd *exec.Cmd

		if len(s.Command()) > 0 {
			cmd = exec.Command(*shell, "-c", strings.Join(s.Command(), " "))
		} else {
			cmd = exec.Command(*shell)
		}

		cmd.Stdout, cmd.Stderr, cmd.Stdin = s, s, s

		if err := cmd.Run(); err != nil {
			if exitError, ok := err.(*exec.ExitError); ok {
				s.Exit(exitError.ExitCode())
			} else {
				s.Exit(1)
			}
		}
	}

	log.Printf("Starting restricted SSH server on %s...", *listenAddr)
	log.Fatal(s.ListenAndServe())
}
