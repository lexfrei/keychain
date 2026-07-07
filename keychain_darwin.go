//go:build darwin

package keychain

import (
	"fmt"
	"slices"

	"github.com/lexfrei/keychain/internal/cf"
	"github.com/lexfrei/keychain/internal/secitem"
)

// darwinBackend stores secrets in the legacy login keychain through
// Security.framework, reached cgo-free via purego. Set attaches a trust-all
// decrypt ACL, so an item is not bound to the creating binary's on-disk path.
// macOS still gates every read by an access partition keyed to the creator's
// code identity: a process of the same identity — the same binary, or another
// binary signed with the same stable Apple Team ID — reads without a prompt
// across rebuilds, while an unsigned or ad-hoc-signed binary is bound to its
// cdhash and loses access on rebuild (WithSecurityCLI is the escape hatch for
// that case). The payload is a CFData, not a command-line argument, so there is
// no size cap: the 16 KB secret round-trips as an ordinary item.
type darwinBackend struct{}

func platformBackend() backend {
	return darwinBackend{}
}

func (b darwinBackend) set(service, account string, secret []byte, cfg config) error {
	if cfg.securityCLI {
		return cliSet(service, account, secret)
	}

	return b.apiSet(service, account, secret, cfg)
}

func (darwinBackend) apiSet(service, account string, secret []byte, cfg config) error {
	err := secitem.Load()
	if err != nil {
		return failDarwin(err)
	}

	arena := &cfArena{}
	defer arena.release()

	// SecItemAdd fails with DuplicateItem when the service+account primary key
	// already exists; upsert then falls through to an update of the value only.
	status := secitem.ItemAdd(arena.addAttributes(service, account, secret, cfg))
	if status == secitem.DuplicateItem {
		return updateItem(arena, service, account, secret)
	}

	return failDarwin(secitem.StatusError(status))
}

func (b darwinBackend) get(service, account string, cfg config) ([]byte, error) {
	if cfg.securityCLI {
		return cliGet(service, account)
	}

	return b.apiGet(service, account)
}

func (darwinBackend) apiGet(service, account string) ([]byte, error) {
	err := secitem.Load()
	if err != nil {
		return nil, failDarwin(err)
	}

	arena := &cfArena{}
	defer arena.release()

	attrs := secitem.Constants()
	query := arena.dict(
		[]cf.Ref{attrs.Class, attrs.Service, attrs.Account, attrs.ReturnData, attrs.MatchLimit},
		[]cf.Ref{attrs.GenericPassword, arena.str(service), arena.str(account), cf.BooleanTrue(), attrs.MatchLimitOne},
	)

	result, status := secitem.ItemCopyMatching(query)
	if status == secitem.ItemNotFound {
		return nil, errItemNotFound
	}

	if status != secitem.Success {
		return nil, failDarwin(secitem.StatusError(status))
	}

	// A stored empty secret can come back as a NULL result rather than an empty
	// CFData; both mean "present but empty", so normalise to a non-nil,
	// zero-length slice — distinct from ErrNotFound.
	if result == 0 {
		return []byte{}, nil
	}

	defer cf.Releaser(result)()

	return cf.DataToBytes(result), nil
}

func (b darwinBackend) del(service, account string, cfg config) error {
	if cfg.securityCLI {
		return cliDel(service, account)
	}

	return b.apiDel(service, account)
}

func (darwinBackend) apiDel(service, account string) error {
	err := secitem.Load()
	if err != nil {
		return failDarwin(err)
	}

	arena := &cfArena{}
	defer arena.release()

	attrs := secitem.Constants()
	query := arena.dict(
		[]cf.Ref{attrs.Class, attrs.Service, attrs.Account},
		[]cf.Ref{attrs.GenericPassword, arena.str(service), arena.str(account)},
	)

	status := secitem.ItemDelete(query)
	if status == secitem.ItemNotFound {
		return errItemNotFound
	}

	return failDarwin(secitem.StatusError(status))
}

// updateItem replaces an existing item's value. It deliberately omits
// kSecAttrAccess: rewriting the ACL of a stored item triggers a user prompt, and
// upsert only needs to replace the value — the trust-all ACL set when the item
// was first created is preserved.
func updateItem(arena *cfArena, service, account string, secret []byte) error {
	attrs := secitem.Constants()
	query := arena.dict(
		[]cf.Ref{attrs.Class, attrs.Service, attrs.Account},
		[]cf.Ref{attrs.GenericPassword, arena.str(service), arena.str(account)},
	)
	update := arena.dict(
		[]cf.Ref{attrs.ValueData},
		[]cf.Ref{arena.data(secret)},
	)

	return failDarwin(secitem.StatusError(secitem.ItemUpdate(query, update)))
}

// failDarwin tags a backend error with the darwin path so a caller can see which
// platform produced it. It returns nil unchanged, so it can wrap a StatusError
// result directly (StatusError is nil on success).
func failDarwin(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("keychain: darwin: %w", err)
}

// cfArena collects CF release functions so a builder can create several
// temporary references and release them all with one deferred call. Because
// CFDictionaryCreate retains its keys and values, component references are safe
// to release once the dictionary that holds them has been built and used.
type cfArena struct {
	releases []func()
}

func (a *cfArena) track(release func()) {
	a.releases = append(a.releases, release)
}

// release runs the tracked releasers in reverse creation order.
func (a *cfArena) release() {
	for _, release := range slices.Backward(a.releases) {
		release()
	}
}

func (a *cfArena) str(value string) cf.Ref {
	ref, release := cf.NewString(value)
	a.track(release)

	return ref
}

func (a *cfArena) data(value []byte) cf.Ref {
	ref, release := cf.NewData(value)
	a.track(release)

	return ref
}

func (a *cfArena) dict(keys, values []cf.Ref) cf.Ref {
	ref, release := cf.NewDict(keys, values)
	a.track(release)

	return ref
}

// addAttributes builds the SecItemAdd attribute dictionary: the generic-password
// class, the service+account key, the secret value, an optional label, and — in
// the default TrustAll mode — the trust-all ACL. If the ACL cannot be built (the
// deprecated API is gone, or the OS rejects it), the item is still stored with
// the default per-app ACL and the loss is logged rather than failing Set.
func (a *cfArena) addAttributes(service, account string, secret []byte, cfg config) cf.Ref {
	attrs := secitem.Constants()
	keys := []cf.Ref{attrs.Class, attrs.Service, attrs.Account, attrs.ValueData}
	values := []cf.Ref{attrs.GenericPassword, a.str(service), a.str(account), a.data(secret)}

	if cfg.label != "" {
		keys = append(keys, attrs.Label)
		values = append(values, a.str(cfg.label))
	}

	if cfg.accessMode == TrustAll {
		access, release, err := secitem.TrustAllAccess(cfg.label)
		if err != nil {
			cfg.log().Debug("keychain: trust-all ACL unavailable; storing with the default per-app ACL", "err", err)
		} else {
			a.track(release)

			keys = append(keys, attrs.Access)
			values = append(values, access)
		}
	}

	return a.dict(keys, values)
}
