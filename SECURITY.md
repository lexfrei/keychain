# Security policy

## Reporting a vulnerability

Report security issues privately — please do not open a public issue for them. Use GitHub's [private vulnerability reporting](https://github.com/lexfrei/keychain/security/advisories/new) for this repository, or email <f@lex.la>. I aim to acknowledge a report within a few days.

## Threat model

`keychain` stores secrets in the operating system's native store and inherits that store's protection of data at rest. It deliberately makes an item readable, without a prompt, by processes of the same user — the trade a headless daemon needs — and therefore does not defend against code already executing as that user.

Two points worth calling out:

- The `WithSecurityCLI` option (macOS) hands the secret to `/usr/bin/security` on standard input, so it is not in the process list. Two cases still put it on the command line, where it is briefly visible to the same user: a secret too large for the roughly 4 KB line the tool reads per command (about 3 KB of secret, since it is stored base64-encoded), and a service or account holding a newline, which one line cannot carry. The tool's interactive mode leaves nothing behind on disk — it links neither readline nor libedit and writes no history file — so standard input is not traded for a transcript. The option is opt-in and documented as such.
- On Linux the secret crosses the session D-Bus to the Secret Service; the plain transport is used, so it is not encrypted on that local IPC.

See the [Security](README.md#security) and [Known limitations](README.md#known-limitations) sections of the README for the full picture.

## Supported versions

Fixes land on the latest 1.x release.
