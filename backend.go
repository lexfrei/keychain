package keychain

import "errors"

// backend is the per-GOOS secret store. Exactly one implementation is selected
// at build time by platformBackend. Each backend hides its platform's quirks
// (notably Windows chunking) and reports an absent item as errItemNotFound,
// which the public functions translate to ErrNotFound.
type backend interface {
	set(service, account string, secret []byte, cfg config) error
	get(service, account string) ([]byte, error)
	del(service, account string) error
}

// errItemNotFound is the internal not-found sentinel every backend returns for
// an absent item. Get maps it to the exported ErrNotFound; Delete maps it to
// nil so that deleting an absent item is a no-op.
var errItemNotFound = errors.New("keychain: backend item not found")

// unsupportedBackend is returned by platformBackend on a GOOS whose real
// backend has not shipped yet, and on genuinely unsupported platforms. Every
// operation reports ErrUnsupported.
type unsupportedBackend struct{}

func (unsupportedBackend) set(_, _ string, _ []byte, _ config) error {
	return ErrUnsupported
}

func (unsupportedBackend) get(_, _ string) ([]byte, error) {
	return nil, ErrUnsupported
}

func (unsupportedBackend) del(_, _ string) error {
	return ErrUnsupported
}
