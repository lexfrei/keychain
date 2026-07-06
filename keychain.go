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
// # Usage
//
// The package-level Set, Get, and Delete cover the common case with a silent
// default configuration. For a logger or a non-default access mode, construct a
// [Keychain] with [New] and call its methods.
//
// # Semantics
//
// Set is an upsert. Get returns the exact bytes previously stored, or
// [ErrNotFound]. Delete is idempotent — removing an absent item is not an
// error. Service and account together form the lookup key; neither may be
// empty. An empty secret is allowed and is distinct from an absent item.
//
// # Logging
//
// The library is silent by default. Pass [WithLogger] a *slog.Logger to trace,
// at debug level, which backend ran and how an operation resolved. The secret
// value is never logged.
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
	"log/slog"
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

// Option configures a Keychain (via New) or a single Set call.
type Option func(*config)

// config is the resolved set of options. Its zero value is the default:
// TrustAll, no label, and a silent logger.
type config struct {
	accessMode AccessMode
	label      string
	logger     *slog.Logger
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

// WithLogger routes debug-level tracing to logger. Without it the library is
// silent. The secret value is never logged, only its length and the lookup key.
func WithLogger(logger *slog.Logger) Option {
	return func(cfg *config) { cfg.logger = logger }
}

func newConfig(opts ...Option) config {
	var cfg config
	for _, opt := range opts {
		opt(&cfg)
	}

	return cfg
}

// log returns the configured logger, or a silent one, so a nil logger never
// panics a backend that traces its work.
func (c config) log() *slog.Logger {
	if c.logger != nil {
		return c.logger
	}

	return silentLogger
}

// silentLogger is the library's quiet default — a library must emit nothing
// unless the caller opts in with WithLogger.
//
//nolint:gochecknoglobals // immutable shared silent logger
var silentLogger = slog.New(slog.DiscardHandler)

// Keychain is a handle to the OS secret store with a fixed configuration (a
// logger and a default access mode). Construct one with New; the package-level
// Set, Get, and Delete delegate to a default, silent instance.
type Keychain struct {
	cfg config
}

// New returns a Keychain configured by opts. Without WithLogger it is silent.
func New(opts ...Option) *Keychain {
	return &Keychain{cfg: newConfig(opts...)}
}

// Set stores secret under service and account, replacing any existing value.
// Per-call opts (for example WithLabel) override the Keychain's configuration
// for this call only.
func (k *Keychain) Set(service, account string, secret []byte, opts ...Option) error {
	if service == "" || account == "" {
		return ErrInvalidKey
	}

	cfg := k.cfg
	for _, opt := range opts {
		opt(&cfg)
	}

	mu.Lock()
	defer mu.Unlock()

	err := backendLocked().set(service, account, secret, cfg)
	cfg.log().Debug("keychain: set", "service", service, "account", account, "bytes", len(secret), "err", err)

	return err
}

// Get returns the secret stored under service and account, or ErrNotFound.
func (k *Keychain) Get(service, account string) ([]byte, error) {
	if service == "" || account == "" {
		return nil, ErrInvalidKey
	}

	mu.Lock()
	defer mu.Unlock()

	secret, err := backendLocked().get(service, account, k.cfg)
	if errors.Is(err, errItemNotFound) {
		k.cfg.log().Debug("keychain: get miss", "service", service, "account", account)

		return nil, ErrNotFound
	}

	if err != nil {
		k.cfg.log().Debug("keychain: get error", "service", service, "account", account, "err", err)

		return nil, err
	}

	k.cfg.log().Debug("keychain: get hit", "service", service, "account", account, "bytes", len(secret))

	return secret, nil
}

// Delete removes the item under service and account. A missing item is not an
// error: Delete is idempotent.
func (k *Keychain) Delete(service, account string) error {
	if service == "" || account == "" {
		return ErrInvalidKey
	}

	mu.Lock()
	defer mu.Unlock()

	err := backendLocked().del(service, account, k.cfg)
	if errors.Is(err, errItemNotFound) {
		k.cfg.log().Debug("keychain: delete no-op (absent)", "service", service, "account", account)

		return nil
	}

	k.cfg.log().Debug("keychain: delete", "service", service, "account", account, "err", err)

	return err
}

// Set stores secret under service and account using the default configuration.
func Set(service, account string, secret []byte, opts ...Option) error {
	return defaultKeychain().Set(service, account, secret, opts...)
}

// Get returns the secret stored under service and account, or ErrNotFound.
func Get(service, account string) ([]byte, error) {
	return defaultKeychain().Get(service, account)
}

// Delete removes the item under service and account; a missing item is not an
// error.
func Delete(service, account string) error {
	return defaultKeychain().Delete(service, account)
}

// defaultOnce and defaultInst back the package-level API with one silent
// Keychain, built lazily.
//
//nolint:gochecknoglobals // the process-wide default instance behind the package-level API
var (
	defaultOnce sync.Once
	defaultInst *Keychain
)

func defaultKeychain() *Keychain {
	defaultOnce.Do(func() { defaultInst = New() })

	return defaultInst
}

// mu serializes backend calls and guards the lazy backend handle. The OS stores
// are thread-safe; the lock keeps the library's own read-modify-write upsert
// paths (notably Windows chunking) simple, and is shared by every Keychain
// because they all reach the same process-wide store.
//
//nolint:gochecknoglobals // one process-wide lock and one lazy backend handle (§14)
var (
	mu            sync.Mutex
	activeBackend backend
)

// backendLocked returns the process backend, initialising it on first use. The
// caller must hold mu.
func backendLocked() backend {
	if activeBackend == nil {
		activeBackend = platformBackend()
	}

	return activeBackend
}
