package keychain_test

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/lexfrei/keychain"
)

// Store, read, then remove a secret with the package-level API.
func Example() {
	err := keychain.Set("myapp", "alice", []byte("s3cr3t"))
	if err != nil {
		fmt.Println("set:", err)

		return
	}

	secret, err := keychain.Get("myapp", "alice")
	if err != nil {
		fmt.Println("get:", err)

		return
	}

	fmt.Printf("stored %d bytes\n", len(secret))

	err = keychain.Delete("myapp", "alice")
	if err != nil {
		fmt.Println("delete:", err)
	}
}

// Branch on the typed errors with errors.Is instead of matching a message.
func ExampleGet() {
	secret, err := keychain.Get("myapp", "alice")

	switch {
	case errors.Is(err, keychain.ErrNotFound):
		fmt.Println("no such item")
	case errors.Is(err, keychain.ErrLocked):
		fmt.Println("unlock the store and retry")
	case errors.Is(err, keychain.ErrUnavailable):
		fmt.Println("no secret store available; fall back")
	case errors.Is(err, keychain.ErrAccessDenied):
		fmt.Println("this build cannot read the item; sign it or use WithSecurityCLI")
	case err != nil:
		fmt.Println("error:", err)
	default:
		fmt.Printf("got %d bytes\n", len(secret))
	}
}

// Construct a Keychain that traces at debug level; the library is silent
// otherwise, and never logs the secret value.
func ExampleNew() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	kc := keychain.New(keychain.WithLogger(logger))

	err := kc.Set("myapp", "alice", []byte("s3cr3t"))
	if err != nil {
		fmt.Println("set:", err)
	}
}
