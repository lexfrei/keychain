# keychain

[![CI](https://github.com/lexfrei/keychain/actions/workflows/ci.yaml/badge.svg)](https://github.com/lexfrei/keychain/actions/workflows/ci.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/lexfrei/keychain.svg)](https://pkg.go.dev/github.com/lexfrei/keychain)

A cgo-free Go library for storing secrets in the operating system's native secret store — macOS Keychain, Linux/\*BSD Secret Service, Windows Credential Manager — behind one small interface.

It is a `zalando/go-keyring` successor. On macOS it calls the Security.framework API directly instead of shelling out to `/usr/bin/security` (no subprocess, no secret on a command line), and on Windows it removes the 2560-byte credential-blob cap by chunking transparently — all with no cgo and no interactive prompt for a daemon. A multi-KB secret round-trips on every platform.

## Status

All three backends have shipped: macOS (native Security.framework, with an optional `/usr/bin/security` delegation — see [macOS access](#macos-rebuild-stability-and-code-signing)), Windows (Credential Manager via inline advapi32, with transparent chunking past the 2560-byte blob cap), and Linux/\*BSD (freedesktop Secret Service over D-Bus). Every backend is exercised by a gated integration job on its own OS runner. The public API is stable.

## Install

```bash
go get github.com/lexfrei/keychain
```

## Usage

```go
package main

import (
	"errors"
	"fmt"

	"github.com/lexfrei/keychain"
)

func main() {
	if err := keychain.Set("myapp", "alice", []byte("s3cr3t")); err != nil {
		panic(err)
	}

	secret, err := keychain.Get("myapp", "alice")
	switch {
	case errors.Is(err, keychain.ErrNotFound):
		fmt.Println("no such item")
	case err != nil:
		panic(err)
	default:
		fmt.Printf("got %d bytes\n", len(secret))
	}

	if err := keychain.Delete("myapp", "alice"); err != nil {
		panic(err)
	}
}
```

## Errors

`Get` and `Delete` distinguish the cases a caller needs to branch on, all testable with `errors.Is`:

- `keychain.ErrNotFound` — no such item (`Get` only; `Delete` of an absent item is a nil no-op).
- `keychain.ErrInvalidKey` — an empty service or account.
- `keychain.ErrLocked` — the store is locked and would need an interactive unlock (a locked Linux collection; a macOS read that would prompt).
- `keychain.ErrUnavailable` — no reachable store (no Linux session bus or default collection; the macOS Security framework failed to load) — a signal to fall back rather than retry.
- `keychain.ErrAccessDenied` — macOS only: the item exists but this process's code identity is denied by the access partition (typically an unsigned binary reading its own item after a rebuild) — fall back to `WithSecurityCLI` or another store.
- `keychain.ErrUnsupported` — a platform with no backend.

Every other error carries the platform detail in its message.

## Configuration and logging

The package-level functions use a silent default. For a logger or a non-default access mode, build a `Keychain` with `New` and call its methods:

```go
logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
kc := keychain.New(keychain.WithLogger(logger))

_ = kc.Set("myapp", "alice", []byte("s3cr3t"))
```

The library emits nothing unless you pass `WithLogger`. Debug lines record the backend, the lookup key, and payload length — never the secret value.

## Access-control model per platform

| Platform | Store | Default read scope | Rebuild-safe | Size limit |
| --- | --- | --- | --- | --- |
| macOS | Keychain (Security API) | trust-all ACL (opt: current-app) | same binary or stable Team ID | none (API) |
| Linux/\*BSD | Secret Service (D-Bus) | user session collection | yes | none |
| Windows | Credential Manager | current user | yes | 2560 B → chunked |

`AccessMode` only changes behaviour on macOS. Linux and Windows secrets are user-scoped, and every mode there behaves like `TrustAll`.

### macOS: rebuild-stability and code signing

macOS gates each keychain item by an access partition tied to the creating binary's code identity. A process of the same identity reads without a prompt across restarts and rebuilds — this holds for the same binary and for any binary code-signed with the same stable Apple **Team ID**. An unsigned or ad-hoc-signed binary (the default `go build` output) is bound to its cdhash, which changes on every rebuild, so a rebuilt copy can no longer read what it stored. There is no OS mechanism to make an item readable by every app of the user; the partition exists precisely to prevent that.

If you cannot sign with a stable Team ID and still need an unsigned binary to keep access across rebuilds — or to share an item with another app — opt into the `/usr/bin/security` delegation:

```go
kc := keychain.New(keychain.WithSecurityCLI())
```

Items written this way live in the stable `apple-tool` partition and stay readable across rebuilds and apps. The trade: the secret is passed as a command-line argument, so it is briefly visible to the same user in `ps` and is bounded by the OS argument-length limit (`ARG_MAX`, ~1 MB — ample for typical secrets, but not uncapped like the native path). That is acceptable only because such an item is already readable by any process of the user. Use it consistently — an item written with it must also be read with it; mixing the two paths on one item returns a garbled or missing value, not an error. It is a no-op on Linux and Windows.

### Linux/\*BSD: Secret Service availability

The backend talks to the freedesktop Secret Service (gnome-keyring / KWallet) over the session D-Bus, so it needs a session bus and an unlocked default collection. On a bare server or container with no secret-service provider — or a locked collection that would need an interactive unlock — every operation returns a clear error rather than hanging, and no prompt is ever shown. A daemon that must run in such an environment should detect the error and fall back to another store (for example a plaintext file behind an explicit opt-in). DragonFly BSD is not covered — its D-Bus library does not build there — and reports `ErrUnsupported`.

## Security

Every backend protects data-at-rest and never writes a plaintext file itself. On Linux and Windows an item is readable, without a prompt, by any process of the same user — the deliberate trade for a headless daemon. On macOS the reader must additionally match the item's access partition (see [macOS access](#macos-rebuild-stability-and-code-signing)). None of the backends defends against code already running as that user. See the package documentation for the full threat model.

## Known limitations

- **macOS, unsigned binaries.** The native backend is rebuild-stable only for the same binary or a stable Apple Team ID. An unsigned or ad-hoc-signed binary — the default `go build` output — loses access to its own items after a rebuild. `WithSecurityCLI` works around it but passes the secret on a command line, briefly visible to the same user in `ps`. There is no cgo-free way to make a native item readable by an arbitrary process; the OS partition mechanism prevents that by design.
- **Linux/\*BSD provider and OS coverage.** The integration contract runs in CI against gnome-keyring on Linux, FreeBSD, and OpenBSD. NetBSD uses the identical D-Bus path and cross-compiles, but is not integration-tested (its pkgsrc Go packaging complicates the CI VM); treat it as best-effort. The backend calls only the standard `org.freedesktop.secrets` interface, so any compliant provider — gnome-keyring, KWallet, KeePassXC — should work, but only gnome-keyring is exercised in CI (KWallet and KeePassXC prompt for an interactive unlock that is impractical to drive headless). DragonFly is unsupported. The backend needs a session bus and an existing default collection — a fresh headless keyring must be provisioned out of band.
- **macOS relies on deprecated ACL APIs.** The trust-all ACL uses `SecAccess`/`SecACL` calls Apple deprecated (but has not removed) for the legacy keychain. If a future macOS drops them, `Set` falls back to a per-app ACL.
- **Operations are serialized.** A process-wide mutex serializes every store call, which keeps the read-modify-write paths simple and is ample for a daemon, but is not built for high-throughput concurrent access.
- **Not yet battle-tested.** v1.x is API-stable and passes the full behavioural contract against each real store in CI, but it has no production mileage yet; validate it against your own store before relying on it.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
