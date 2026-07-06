// Package keychain stores and retrieves secrets in the operating system's
// native secret store — the macOS Keychain, the Linux/*BSD Secret Service, or
// the Windows Credential Manager — behind one small, cgo-free interface.
//
// It is a successor to zalando/go-keyring that removes go-keyring's two hard
// limits: the ~4 KB macOS command-line cap and the 2560-byte Windows
// credential-blob cap. Secrets of any size round-trip on every platform
// (Windows chunks transparently under the hood). There is no cgo on any
// platform, so callers cross-compile freely, and a rebuilt binary keeps access
// to what it stored — the properties a headless, frequently-rebuilt daemon
// needs.
//
// # Semantics
//
// Set is an upsert. Get returns the exact bytes previously stored, or
// ErrNotFound. Delete is idempotent — removing an absent item is not an error.
// Service and account together form the lookup key; neither may be empty. An
// empty secret is allowed and is distinct from an absent item.
//
// # Security
//
// Every backend protects data-at-rest and is readable, without a prompt, by any
// process of the same user. That is the deliberate trade for a headless daemon;
// none of the backends defends against code already executing as that user. The
// only mechanism that would — the macOS TrustCurrentApp per-binary ACL — breaks
// on rebuild and is offered strictly as opt-in. The library never writes a
// plaintext file itself.
package keychain

import (
	"errors"
	"sync"
)

// ErrNotFound is returned by Get when no item matches the service and account.
var ErrNotFound = errors.New("keychain: item not found")

// ErrInvalidKey is returned when service or account is empty. The two together
// form the lookup key, so neither may be blank.
var ErrInvalidKey = errors.New("keychain: service and account must both be non-empty")

// ErrUnsupported is returned on a platform whose backend is not implemented.
var ErrUnsupported = errors.New("keychain: platform not supported")

// AccessMode controls read access. It is only meaningful on macOS; on Linux and
// Windows secrets are user-scoped and every mode behaves like TrustAll.
type AccessMode int

const (
	// TrustAll lets any process of the same user read without a prompt. It
	// matches security -A, go-keyring, and the Linux and Windows default:
	// rebuild-safe and daemon-friendly. It protects data-at-rest, not against
	// code already running as the user. This is the default.
	TrustAll AccessMode = iota

	// TrustCurrentApp, on macOS only, lets only the creating binary read
	// silently; other apps are prompted. Stronger, but a rebuilt binary loses
	// access.
	TrustCurrentApp
)

// Option configures a Set call.
type Option func(*config)

// config is the resolved set of options for one operation. Its zero value is
// the default: TrustAll and no label.
type config struct {
	accessMode AccessMode
	label      string
}

// WithAccessMode selects the macOS read-access ACL. It defaults to TrustAll and
// is a no-op on Linux and Windows.
func WithAccessMode(mode AccessMode) Option {
	return func(cfg *config) { cfg.accessMode = mode }
}

// WithLabel sets a human-readable label where the store supports one — the
// macOS Keychain item label. It is ignored on Linux and Windows.
func WithLabel(label string) Option {
	return func(cfg *config) { cfg.label = label }
}

func newConfig(opts ...Option) config {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}

	return cfg
}

// mu serializes backend calls and guards the lazy backend handle below. The OS
// stores are themselves thread-safe; the lock keeps the library's own
// read-modify-write upsert paths (notably Windows chunking) simple.
//
//nolint:gochecknoglobals // one process-wide lock is the whole concurrency model (§14)
var mu sync.Mutex

// activeBackend is the process's lazily-initialised backend, set under mu on
// first use. Tests swap it to inject a fake.
//
//nolint:gochecknoglobals // the single lazily-initialised backend handle (§14)
var activeBackend backend

// backendLocked returns the process backend, initialising it on first use. The
// caller must hold mu.
func backendLocked() backend {
	if activeBackend == nil {
		activeBackend = platformBackend()
	}

	return activeBackend
}

// Set stores secret under service and account, replacing any existing value.
func Set(service, account string, secret []byte, opts ...Option) error {
	if service == "" || account == "" {
		return ErrInvalidKey
	}

	cfg := newConfig(opts...)

	mu.Lock()
	defer mu.Unlock()

	return backendLocked().set(service, account, secret, cfg)
}

// Get returns the secret stored under service and account, or ErrNotFound.
func Get(service, account string) ([]byte, error) {
	if service == "" || account == "" {
		return nil, ErrInvalidKey
	}

	mu.Lock()
	defer mu.Unlock()

	secret, err := backendLocked().get(service, account)
	if errors.Is(err, errItemNotFound) {
		return nil, ErrNotFound
	}

	if err != nil {
		return nil, err
	}

	return secret, nil
}

// Delete removes the item under service and account. A missing item is not an
// error: Delete is idempotent.
func Delete(service, account string) error {
	if service == "" || account == "" {
		return ErrInvalidKey
	}

	mu.Lock()
	defer mu.Unlock()

	err := backendLocked().del(service, account)
	if errors.Is(err, errItemNotFound) {
		return nil
	}

	return err
}
