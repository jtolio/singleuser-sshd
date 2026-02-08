# singleuser sshd

This is a basic SSH server that:

a) only allows the user running the server to connect
b) only allows ssh key authentication
c) only runs in the foreground

it does not support user switching, pam, etc.

this is useful for letting untrusted ssh clients connect to a shell
running in something like [ajail](https://github.com/jtolio/ajail)

## LLM statement

Gemini 3 wrote almost all this

## license

MIT
