//go:build windows

package keychain

import (
	"errors"
	"fmt"

	"github.com/lexfrei/keychain/internal/chunk"
	"github.com/lexfrei/keychain/internal/winapi"
)

// windowsBackend stores secrets in the Windows Credential Manager through inline
// advapi32 syscalls (no cgo, no third-party wrapper). A credential blob is capped
// at 2560 bytes, so larger secrets are split transparently by the chunk
// container: callers see an arbitrary-size value, the store sees several
// generic, local-machine credentials. Items are user-scoped and prompt-free, so
// a rebuilt binary keeps access.
type windowsBackend struct{}

func platformBackend() backend {
	return windowsBackend{}
}

func (windowsBackend) set(service, account string, secret []byte, _ config) error {
	return failWindows(chunker().Set(service, account, secret))
}

func (windowsBackend) get(service, account string, _ config) ([]byte, error) {
	secret, err := chunker().Get(service, account)
	if errors.Is(err, chunk.ErrNotFound) {
		return nil, errItemNotFound
	}

	if err != nil {
		return nil, failWindows(err)
	}

	return secret, nil
}

func (windowsBackend) del(service, account string, _ config) error {
	err := chunker().Delete(service, account)
	if errors.Is(err, chunk.ErrNotFound) {
		return errItemNotFound
	}

	return failWindows(err)
}

func chunker() chunk.Chunker {
	return chunk.Chunker{Store: winStore{}, MaxBlob: chunk.DefaultMaxBlob}
}

// failWindows tags a backend error with the Windows path. It returns nil
// unchanged so it can wrap a call result directly.
func failWindows(err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("keychain: windows: %w", err)
}

// winStore adapts the flat winapi credential calls to the chunk.Store the
// chunker drives, translating winapi's not-found into chunk's ErrMissing.
type winStore struct{}

func (winStore) Get(target string) ([]byte, error) {
	blob, err := winapi.Read(target)
	if errors.Is(err, winapi.ErrNotFound) {
		return nil, chunk.ErrMissing
	}

	if err != nil {
		return nil, fmt.Errorf("winstore: %w", err)
	}

	return blob, nil
}

func (winStore) Set(target string, blob []byte) error {
	err := winapi.Write(target, blob)
	if err != nil {
		return fmt.Errorf("winstore: %w", err)
	}

	return nil
}

func (winStore) Delete(target string) error {
	err := winapi.Delete(target)
	if errors.Is(err, winapi.ErrNotFound) {
		return chunk.ErrMissing
	}

	if err != nil {
		return fmt.Errorf("winstore: %w", err)
	}

	return nil
}
