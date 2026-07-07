//go:build windows

package winapi

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// ErrNotFound is returned by Read and Delete when no credential matches target.
var ErrNotFound = errors.New("winapi: credential not found")

const (
	credTypeGeneric         = 1    // CRED_TYPE_GENERIC
	credPersistLocalMachine = 2    // CRED_PERSIST_LOCAL_MACHINE
	errorNotFound           = 1168 // ERROR_NOT_FOUND
)

// The resolved advapi32 procedures. syscall.NewLazyDLL resolves them on first
// use; a dynamic-linking binding is inherently process-global.
//
//nolint:gochecknoglobals // resolved-once advapi32 handle and procedure entries.
var (
	advapi32       = syscall.NewLazyDLL("advapi32.dll")
	procCredWrite  = advapi32.NewProc("CredWriteW")
	procCredRead   = advapi32.NewProc("CredReadW")
	procCredDelete = advapi32.NewProc("CredDeleteW")
	procCredFree   = advapi32.NewProc("CredFree")
)

// credentialW mirrors the Win32 CREDENTIALW struct. Field order and natural
// alignment match the C layout, which is what CredWriteW/CredReadW require.
type credentialW struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// Write stores blob under target as a generic, local-machine credential,
// replacing any existing value.
func Write(target string, blob []byte) error {
	name, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("winapi: encode target: %w", err)
	}

	cred := credentialW{
		Type:       credTypeGeneric,
		TargetName: name,
		//nolint:gosec // G115: blob is a single chunk bounded by the 2560-byte cap, well within uint32.
		CredentialBlobSize: uint32(len(blob)),
		Persist:            credPersistLocalMachine,
	}
	if len(blob) > 0 {
		cred.CredentialBlob = &blob[0]
	}

	ret, _, callErr := procCredWrite.Call(uintptr(unsafe.Pointer(&cred)), 0)

	// CredWrite copies the credential, so these only need to survive the call.
	runtime.KeepAlive(name)
	runtime.KeepAlive(blob)
	runtime.KeepAlive(&cred)

	if ret == 0 {
		return fmt.Errorf("winapi: CredWrite %q: %w", target, callErr)
	}

	return nil
}

// Read returns the blob stored under target, or ErrNotFound.
func Read(target string) ([]byte, error) {
	name, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return nil, fmt.Errorf("winapi: encode target: %w", err)
	}

	var pcred *credentialW

	ret, _, callErr := procCredRead.Call(
		uintptr(unsafe.Pointer(name)),
		credTypeGeneric,
		0,
		uintptr(unsafe.Pointer(&pcred)),
	)
	runtime.KeepAlive(name)

	if ret == 0 {
		if errors.Is(callErr, syscall.Errno(errorNotFound)) {
			return nil, ErrNotFound
		}

		return nil, fmt.Errorf("winapi: CredRead %q: %w", target, callErr)
	}

	defer freeCredential(pcred)

	// CredReadW returns CredentialBlob in a buffer it owns; copy it into Go memory
	// before CredFree reclaims it.
	blob := make([]byte, pcred.CredentialBlobSize)
	if pcred.CredentialBlobSize > 0 {
		copy(blob, unsafe.Slice(pcred.CredentialBlob, pcred.CredentialBlobSize))
	}

	return blob, nil
}

// Delete removes the credential under target, or reports ErrNotFound.
func Delete(target string) error {
	name, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return fmt.Errorf("winapi: encode target: %w", err)
	}

	ret, _, callErr := procCredDelete.Call(uintptr(unsafe.Pointer(name)), credTypeGeneric, 0)
	runtime.KeepAlive(name)

	if ret == 0 {
		if errors.Is(callErr, syscall.Errno(errorNotFound)) {
			return ErrNotFound
		}

		return fmt.Errorf("winapi: CredDelete %q: %w", target, callErr)
	}

	return nil
}

func freeCredential(cred *credentialW) {
	//nolint:dogsled // CredFree returns no meaningful result; all three values are intentionally discarded.
	_, _, _ = procCredFree.Call(uintptr(unsafe.Pointer(cred)))
}
