//go:build darwin

package secitem

import (
	"errors"
	"fmt"
	"sync"

	"github.com/lexfrei/keychain/internal/cf"
)

// OSStatus is a Security.framework result code.
type OSStatus int32

// The handful of OSStatus values the backend branches on. The rest are reported
// verbatim through StatusError.
const (
	Success               OSStatus = 0
	ItemNotFound          OSStatus = -25300
	DuplicateItem         OSStatus = -25299
	InteractionNotAllowed OSStatus = -25308
)

// Attrs holds the resolved kSec* constants used to build query and attribute
// dictionaries. Each is a CFStringRef/CFBooleanRef global owned by Security —
// never retained or released by us.
type Attrs struct {
	Class           cf.Ref
	GenericPassword cf.Ref
	Service         cf.Ref
	Account         cf.Ref
	Label           cf.Ref
	ValueData       cf.Ref
	ReturnData      cf.Ref
	MatchLimit      cf.Ref
	MatchLimitOne   cf.Ref
	Access          cf.Ref
}

// Static sentinels for the two ACL conditions that are not a raw OSStatus; both
// drive the trust-all fallback in the backend.
var (
	errACLUnavailable = errors.New("secitem: trust-all ACL API is unavailable on this system")
	errNoDecryptACL   = errors.New("secitem: SecAccess has no decrypt ACL to make allow-all")
)

// Error is a non-success Security result. Callers can errors.As it to read the
// Status — for example to detect InteractionNotAllowed on a headless read.
type Error struct {
	Status  OSStatus
	Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("secitem: OSStatus %d", int32(e.Status))
	}

	return fmt.Sprintf("secitem: OSStatus %d (%s)", int32(e.Status), e.Message)
}

// The resolved Security binding: the const table, the internal decrypt-ACL tag,
// whether the deprecated ACL calls are present, and the C function pointers.
//
//nolint:gochecknoglobals // resolved-once Security binding: const table, ACL-availability flag, and C function pointers; a dynamic-linking binding is package-global by nature.
var (
	loadOnce sync.Once
	errLoad  error

	resolved             Attrs
	authorizationDecrypt cf.Ref
	aclAvailable         bool

	secItemAdd                   func(attributes cf.Ref, result *cf.Ref) OSStatus
	secItemCopyMatching          func(query cf.Ref, result *cf.Ref) OSStatus
	secItemUpdate                func(query, attributes cf.Ref) OSStatus
	secItemDelete                func(query cf.Ref) OSStatus
	secCopyErrorMessageString    func(status OSStatus, reserved uintptr) cf.Ref
	secAccessCreate              func(descriptor, trustedList cf.Ref, access *cf.Ref) OSStatus
	secAccessCopyMatchingACLList func(access, authorizationTag cf.Ref) cf.Ref
	secACLSetContents            func(acl, applicationList, description cf.Ref, promptSelector uint16) OSStatus
)

// Load resolves CoreFoundation, then Security, and its symbols exactly once. It
// is safe to call repeatedly and from any goroutine. A missing deprecated ACL
// symbol is not a load failure — it only disables trust-all (see TrustAllAccess).
func Load() error {
	loadOnce.Do(load)

	return errLoad
}

func load() {
	errLoad = cf.Load()
	if errLoad != nil {
		return
	}

	handle, err := cf.Open("/System/Library/Frameworks/Security.framework/Security")
	if err != nil {
		errLoad = err

		return
	}

	errLoad = registerFuncs(handle)
	if errLoad != nil {
		return
	}

	errLoad = resolveConstants(handle)
	if errLoad != nil {
		return
	}

	registerACLFuncs(handle)
}

func registerFuncs(handle uintptr) error {
	funcs := []struct {
		fptr any
		name string
	}{
		{&secItemAdd, "SecItemAdd"},
		{&secItemCopyMatching, "SecItemCopyMatching"},
		{&secItemUpdate, "SecItemUpdate"},
		{&secItemDelete, "SecItemDelete"},
		{&secCopyErrorMessageString, "SecCopyErrorMessageString"},
	}

	for _, reg := range funcs {
		err := cf.Register(reg.fptr, handle, reg.name)
		if err != nil {
			return fmt.Errorf("secitem: bind Security functions: %w", err)
		}
	}

	return nil
}

// registerACLFuncs binds the deprecated SecAccess/SecACL calls. They are absent
// only on a hypothetical future OS that removed them; aclAvailable records the
// outcome so TrustAllAccess can fail cleanly instead of calling a nil pointer.
func registerACLFuncs(handle uintptr) {
	funcs := []struct {
		fptr any
		name string
	}{
		{&secAccessCreate, "SecAccessCreate"},
		{&secAccessCopyMatchingACLList, "SecAccessCopyMatchingACLList"},
		{&secACLSetContents, "SecACLSetContents"},
	}

	// aclAvailable starts false (zero value); every early return below leaves it
	// so, and only the fully-resolved path flips it true.
	for _, reg := range funcs {
		err := cf.Register(reg.fptr, handle, reg.name)
		if err != nil {
			return
		}
	}

	tag, err := cf.ConstValue(handle, "kSecACLAuthorizationDecrypt")
	if err != nil {
		return
	}

	authorizationDecrypt = tag
	aclAvailable = true
}

func resolveConstants(handle uintptr) error {
	consts := []struct {
		dst  *cf.Ref
		name string
	}{
		{&resolved.Class, "kSecClass"},
		{&resolved.GenericPassword, "kSecClassGenericPassword"},
		{&resolved.Service, "kSecAttrService"},
		{&resolved.Account, "kSecAttrAccount"},
		{&resolved.Label, "kSecAttrLabel"},
		{&resolved.ValueData, "kSecValueData"},
		{&resolved.ReturnData, "kSecReturnData"},
		{&resolved.MatchLimit, "kSecMatchLimit"},
		{&resolved.MatchLimitOne, "kSecMatchLimitOne"},
		{&resolved.Access, "kSecAttrAccess"},
	}

	for _, entry := range consts {
		value, err := cf.ConstValue(handle, entry.name)
		if err != nil {
			return fmt.Errorf("secitem: resolve Security constants: %w", err)
		}

		*entry.dst = value
	}

	return nil
}

// Constants returns the resolved kSec* constants. Load must have succeeded.
func Constants() Attrs { return resolved }

// ItemAdd wraps SecItemAdd, discarding the added item (result NULL).
func ItemAdd(attributes cf.Ref) OSStatus { return secItemAdd(attributes, nil) }

// ItemCopyMatching wraps SecItemCopyMatching. On Success the returned ref is the
// matched value with a +1 reference the caller must release.
func ItemCopyMatching(query cf.Ref) (cf.Ref, OSStatus) {
	var result cf.Ref

	status := secItemCopyMatching(query, &result)

	return result, status
}

// ItemUpdate wraps SecItemUpdate.
func ItemUpdate(query, attributes cf.Ref) OSStatus { return secItemUpdate(query, attributes) }

// ItemDelete wraps SecItemDelete.
func ItemDelete(query cf.Ref) OSStatus { return secItemDelete(query) }

// StatusError turns a non-success OSStatus into a *Error carrying the framework's
// own message when one is available. It returns nil for Success.
func StatusError(status OSStatus) error {
	if status == Success {
		return nil
	}

	return &Error{Status: status, Message: errorMessage(status)}
}

func errorMessage(status OSStatus) string {
	if secCopyErrorMessageString == nil {
		return ""
	}

	ref := secCopyErrorMessageString(status, 0)
	if ref == 0 {
		return ""
	}

	release := cf.Releaser(ref)
	defer release()

	return cf.GoString(ref)
}

// TrustAllAccess builds a SecAccess whose decrypt ACL trusts every application
// of the current user — the API form of `security add-generic-password -A`. The
// returned ref carries a +1 reference; the caller passes it as kSecAttrAccess
// and then calls release (SecItemAdd retains it into the stored item).
//
// A NULL trusted-application list on the decrypt ACL is what makes it allow-all
// rather than owner-only; that is the whole reason the item reads with no prompt
// from any process, including a rebuilt binary.
func TrustAllAccess(label string) (cf.Ref, func(), error) {
	if !aclAvailable {
		return 0, nil, errACLUnavailable
	}

	descriptor, releaseDescriptor := cf.NewString(label)
	defer releaseDescriptor()

	var access cf.Ref

	status := secAccessCreate(descriptor, 0, &access)
	if status != Success {
		return 0, nil, StatusError(status)
	}

	releaseAccess := cf.Releaser(access)

	err := makeACLAllowAll(access)
	if err != nil {
		releaseAccess()

		return 0, nil, err
	}

	return access, releaseAccess, nil
}

// makeACLAllowAll rewrites the decrypt authorization ACL of access to trust all
// applications by setting its trusted-application list to NULL with no prompt.
func makeACLAllowAll(access cf.Ref) error {
	aclList := secAccessCopyMatchingACLList(access, authorizationDecrypt)
	if aclList == 0 {
		return errNoDecryptACL
	}

	releaseACLList := cf.Releaser(aclList)
	defer releaseACLList()

	if cf.Len(aclList) == 0 {
		return errNoDecryptACL
	}

	// The element is borrowed from the array; it must not be released, and the
	// SecACLSetContents call below completes before the array is released.
	acl := cf.At(aclList, 0)

	status := secACLSetContents(acl, 0, 0, 0)
	if status != Success {
		return StatusError(status)
	}

	return nil
}
