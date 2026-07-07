//go:build linux || freebsd || openbsd || netbsd

// This file is deliberately not named keychain_linux.go: a _linux.go suffix is
// an implicit GOOS=linux constraint that would AND with the build tag below and
// silently drop the BSDs. A neutral name lets the one Secret Service backend
// cover every org.freedesktop.secrets platform godbus can reach. DragonFly is
// excluded: godbus does not compile there, so it falls back to ErrUnsupported.

package keychain

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/godbus/dbus/v5"
)

// The freedesktop Secret Service names, provided by gnome-keyring / KWallet.
const (
	ssName        = "org.freedesktop.secrets"
	ssServicePath = "/org/freedesktop/secrets"

	ifaceService    = "org.freedesktop.Secret.Service"
	ifaceCollection = "org.freedesktop.Secret.Collection"
	ifaceItem       = "org.freedesktop.Secret.Item"

	attrService = "service"
	attrAccount = "account"

	// nullPath is the "/" object path: the Secret Service returns it both as the
	// "no interactive prompt was needed" sentinel and as an unset alias.
	nullPath = dbus.ObjectPath("/")

	// The Secret Service transports opaque bytes; the content type is advisory.
	contentTypeOctet = "application/octet-stream"

	// ssTimeout bounds every D-Bus round-trip so a wedged keyring daemon can
	// never hang a caller — the primary no-hang guard alongside never prompting.
	ssTimeout = 10 * time.Second
)

// Clear, never-hang errors for the two headless dead-ends: no reachable service
// (no session bus, or no default collection) and a collection that would need an
// interactive unlock. Both are wrapped by failSecretService before surfacing.
var (
	errSecretServiceUnavailable = errors.New("secret service unavailable (no session bus or no default collection)")
	errSecretServiceLocked      = errors.New("collection is locked and needs an interactive unlock")
)

// dbusSecret mirrors the org.freedesktop.Secret Secret struct, D-Bus signature
// (oayays): session path, transport parameters, value, content type. godbus
// marshals exported fields positionally, so this field order is load-bearing.
type dbusSecret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

type secretServiceBackend struct{}

func platformBackend() backend {
	return secretServiceBackend{}
}

func (secretServiceBackend) set(service, account string, secret []byte, cfg config) error {
	ctx, cancel := context.WithTimeout(context.Background(), ssTimeout)
	defer cancel()

	sess, err := openSession(ctx)
	if err != nil {
		return failSecretService(err)
	}
	defer sess.close()

	value := secret
	if value == nil {
		value = []byte{}
	}

	properties := map[string]dbus.Variant{
		ifaceItem + ".Label":      dbus.MakeVariant(itemLabel(service, account, cfg)),
		ifaceItem + ".Attributes": dbus.MakeVariant(searchAttrs(service, account)),
	}
	item := dbusSecret{Session: sess.path, Parameters: []byte{}, Value: value, ContentType: contentTypeOctet}

	var itemPath, prompt dbus.ObjectPath

	// replace=true makes CreateItem an upsert against the matching attributes.
	err = sess.collection.CallWithContext(ctx, ifaceCollection+".CreateItem", 0, properties, item, true).
		Store(&itemPath, &prompt)
	if err != nil {
		return failSecretService(fmt.Errorf("create item: %w", err))
	}

	if prompt != nullPath {
		return failSecretService(errSecretServiceLocked)
	}

	return nil
}

func (secretServiceBackend) get(service, account string, _ config) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ssTimeout)
	defer cancel()

	sess, err := openSession(ctx)
	if err != nil {
		return nil, failSecretService(err)
	}
	defer sess.close()

	items, err := sess.search(ctx, service, account)
	if err != nil {
		return nil, failSecretService(err)
	}

	if len(items) == 0 {
		return nil, errItemNotFound
	}

	var secret dbusSecret

	err = sess.conn.Object(ssName, items[0]).CallWithContext(ctx, ifaceItem+".GetSecret", 0, sess.path).Store(&secret)
	if err != nil {
		return nil, failSecretService(fmt.Errorf("get secret: %w", err))
	}

	// make(len 0) is non-nil, so an empty stored value reads back as a non-nil
	// zero-length slice — "present but empty", distinct from absent.
	out := make([]byte, len(secret.Value))
	copy(out, secret.Value)

	return out, nil
}

func (secretServiceBackend) del(service, account string, _ config) error {
	ctx, cancel := context.WithTimeout(context.Background(), ssTimeout)
	defer cancel()

	sess, err := openSession(ctx)
	if err != nil {
		return failSecretService(err)
	}
	defer sess.close()

	items, err := sess.search(ctx, service, account)
	if err != nil {
		return failSecretService(err)
	}

	if len(items) == 0 {
		return errItemNotFound
	}

	// Delete every match, not just the first, so the upsert-then-single-delete
	// invariant holds even if another writer left a duplicate.
	for _, path := range items {
		var prompt dbus.ObjectPath

		err = sess.conn.Object(ssName, path).CallWithContext(ctx, ifaceItem+".Delete", 0).Store(&prompt)
		if err != nil {
			return failSecretService(fmt.Errorf("delete item: %w", err))
		}
	}

	return nil
}

// session bundles a private connection, an opened plain session, and the
// unlocked default collection. It is built per operation — mu already serializes
// calls — so there is no shared, staleable global connection.
type session struct {
	conn       *dbus.Conn
	service    dbus.BusObject
	collection dbus.BusObject
	path       dbus.ObjectPath
}

func openSession(ctx context.Context) (*session, error) {
	conn, err := dbus.ConnectSessionBus(dbus.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errSecretServiceUnavailable, err)
	}

	sess := &session{conn: conn, service: conn.Object(ssName, ssServicePath)}

	err = sess.open(ctx)
	if err != nil {
		sess.close()

		return nil, err
	}

	return sess, nil
}

// open runs the plain OpenSession, resolves the default collection, and unlocks
// it — the shared prelude for every operation.
func (s *session) open(ctx context.Context) error {
	var output dbus.Variant

	err := s.service.CallWithContext(ctx, ifaceService+".OpenSession", 0, "plain", dbus.MakeVariant("")).
		Store(&output, &s.path)
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}

	var collectionPath dbus.ObjectPath

	err = s.service.CallWithContext(ctx, ifaceService+".ReadAlias", 0, "default").Store(&collectionPath)
	if err != nil {
		return fmt.Errorf("read default collection: %w", err)
	}

	if collectionPath == nullPath {
		return errSecretServiceUnavailable
	}

	s.collection = s.conn.Object(ssName, collectionPath)

	return s.unlock(ctx, collectionPath)
}

func (s *session) close() {
	_ = s.conn.Close()
}

// unlock unlocks the given object, returning errSecretServiceLocked if the store
// would need an interactive prompt (which a headless caller cannot answer).
func (s *session) unlock(ctx context.Context, path dbus.ObjectPath) error {
	var unlocked []dbus.ObjectPath

	var prompt dbus.ObjectPath

	err := s.service.CallWithContext(ctx, ifaceService+".Unlock", 0, []dbus.ObjectPath{path}).
		Store(&unlocked, &prompt)
	if err != nil {
		return fmt.Errorf("unlock: %w", err)
	}

	if prompt != nullPath {
		return errSecretServiceLocked
	}

	return nil
}

// search returns the item paths matching service+account in the unlocked default
// collection. An empty result is not an error — the caller maps it to not-found.
func (s *session) search(ctx context.Context, service, account string) ([]dbus.ObjectPath, error) {
	var results []dbus.ObjectPath

	err := s.collection.CallWithContext(ctx, ifaceCollection+".SearchItems", 0, searchAttrs(service, account)).
		Store(&results)
	if err != nil {
		return nil, fmt.Errorf("search items: %w", err)
	}

	return results, nil
}

func searchAttrs(service, account string) map[string]string {
	return map[string]string{attrService: service, attrAccount: account}
}

func itemLabel(service, account string, cfg config) string {
	if cfg.label != "" {
		return cfg.label
	}

	return service + "/" + account
}

// failSecretService tags a backend error with the Secret Service path. It returns
// nil unchanged so it can wrap a call result directly.
func failSecretService(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("keychain: secret service: %w", err)
}
