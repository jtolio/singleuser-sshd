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
	"sync/atomic"

	"github.com/creack/pty"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
)

type contextKey string

const authMethodKey contextKey = "authMethod"

var connCounter uint64

func main() {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Error finding home directory: %v", err)
	}
	defaultShell := os.Getenv("SHELL")
	if defaultShell == "" {
		defaultShell = "/bin/sh"
	}

	defaultHostKey := filepath.Join(homeDir, ".ssh", "singleuser-sshd-host-key")
	defaultAuthKeys := filepath.Join(homeDir, ".ssh", "authorized_keys")

	listenAddr := flag.String("addr", ":2222", "Address to listen on")
	hostKeyFile := flag.String("hostkey", defaultHostKey, "Path to host key (auto-generated if missing)")
	authKeysFile := flag.String("authkeys", defaultAuthKeys, "Path to authorized_keys file")
	shell := flag.String("shell", defaultShell, "shell to use")
	password := flag.String("password", "", "If set, enable password authentication with this password")
	username := flag.String("user", "", "Username to accept for authentication (default: any)")
	enableSFTP := flag.Bool("sftp", false, "Enable SFTP subsystem for file transfers")
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
			if *username != "" && ctx.User() != *username {
				return false
			}
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
					ctx.SetValue(authMethodKey, "publickey")
					return true
				}
				data = rest
			}
			return false
		},
	}

	if *enableSFTP {
		s.SubsystemHandlers = map[string]ssh.SubsystemHandler{
			"sftp": func(sess ssh.Session) {
				server, err := sftp.NewServer(sess)
				if err != nil {
					log.Printf("sftp server init error: %v", err)
					return
				}
				if err := server.Serve(); err != io.EOF {
					log.Printf("sftp server error: %v", err)
				}
			},
		}
	}

	if *password != "" {
		s.PasswordHandler = func(ctx ssh.Context, pass string) bool {
			if (*username == "" || ctx.User() == *username) && pass == *password {
				ctx.SetValue(authMethodKey, "password")
				return true
			}
			return false
		}
	}

	if _, err := os.Stat(*hostKeyFile); os.IsNotExist(err) {
		log.Printf("Generating new host key at %s", *hostKeyFile)
		if err := generateHostKey(*hostKeyFile); err != nil {
			log.Fatalf("Failed to generate host key: %v", err)
		}
	} else if err != nil {
		log.Fatalf("Failed to stat host key %s: %v", *hostKeyFile, err)
	} else {
		log.Printf("Using host key: %s", *hostKeyFile)
	}
	s.SetOption(ssh.HostKeyFile(*hostKeyFile))

	s.Handler = func(s ssh.Session) {
		connID := atomic.AddUint64(&connCounter, 1)
		authMethod, _ := s.Context().Value(authMethodKey).(string)
		if authMethod == "" {
			authMethod = "unknown"
		}
		log.Printf("[conn %d] user %q connected (auth: %s, remote: %s)", connID, s.User(), authMethod, s.RemoteAddr())
		defer log.Printf("[conn %d] user %q disconnected", connID, s.User())

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
