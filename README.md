# keychain

[![CI](https://github.com/lexfrei/keychain/actions/workflows/ci.yaml/badge.svg)](https://github.com/lexfrei/keychain/actions/workflows/ci.yaml)
[![Go Reference](https://pkg.go.dev/badge/github.com/lexfrei/keychain.svg)](https://pkg.go.dev/github.com/lexfrei/keychain)

A cgo-free Go library for storing secrets in the operating system's native secret store — macOS Keychain, Linux/\*BSD Secret Service, Windows Credential Manager — behind one small interface.

It is a `zalando/go-keyring` successor that drops go-keyring's two hard limits — the ~4 KB macOS command-line cap and the 2560-byte Windows credential-blob cap — while keeping the convenience: no cgo, no interactive prompt for a daemon, and survival across binary rebuilds. A multi-KB secret round-trips on every platform.

## Status

Under construction. The public API is stable; platform backends are landing one at a time (macOS → Windows → Linux). Until a platform's backend ships, that platform reports `ErrUnsupported`.

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
| macOS | Keychain (Security API) | trust-all ACL (opt: current-app) | yes (trust-all) | none (API) |
| Linux/\*BSD | Secret Service (D-Bus) | user session collection | yes | none |
| Windows | Credential Manager | current user | yes | 2560 B → chunked |

`AccessMode` only changes behaviour on macOS. Linux and Windows secrets are user-scoped, and every mode there behaves like `TrustAll`.

## Security

Every backend protects data-at-rest and is readable, without a prompt, by any process of the same user — the deliberate trade for a headless daemon. None of them defends against code already running as that user. See the package documentation for the full threat model.

## License

BSD-3-Clause. See [LICENSE](LICENSE).
