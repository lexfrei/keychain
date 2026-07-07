# Security policy

## Reporting a vulnerability

Report security issues privately — please do not open a public issue for them. Use GitHub's [private vulnerability reporting](https://github.com/lexfrei/keychain/security/advisories/new) for this repository, or email <f@lex.la>. I aim to acknowledge a report within a few days.

## Threat model

`keychain` stores secrets in the operating system's native store and inherits that store's protection of data at rest. It deliberately makes an item readable, without a prompt, by processes of the same user — the trade a headless daemon needs — and therefore does not defend against code already executing as that user.

Two points worth calling out:

- The `WithSecurityCLI` option (macOS) passes the secret as a command-line argument, so it is briefly visible to the same user in the process list. It is opt-in and documented as such.
- On Linux the secret crosses the session D-Bus to the Secret Service; the plain transport is used, so it is not encrypted on that local IPC.

See the [Security](README.md#security) and [Known limitations](README.md#known-limitations) sections of the README for the full picture.

## Supported versions

Fixes land on the latest 1.x release.
