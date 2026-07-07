//go:build linux || freebsd || openbsd || netbsd

package keychain

import (
	"errors"
	"testing"
)

// TestSecretServiceErrorsWrapSentinels pins that the Secret Service dead-ends are
// reachable through the exported typed errors — directly and through the
// failSecretService wrapper — so a caller can detect "locked" and "unavailable"
// with errors.Is rather than by matching a message.
func TestSecretServiceErrorsWrapSentinels(t *testing.T) {
	if !errors.Is(errSecretServiceLocked, ErrLocked) {
		t.Error("errSecretServiceLocked must wrap ErrLocked")
	}

	if !errors.Is(errSecretServiceUnavailable, ErrUnavailable) {
		t.Error("errSecretServiceUnavailable must wrap ErrUnavailable")
	}

	if !errors.Is(failSecretService(errSecretServiceLocked), ErrLocked) {
		t.Error("failSecretService must preserve the ErrLocked chain")
	}

	if !errors.Is(failSecretService(errSecretServiceUnavailable), ErrUnavailable) {
		t.Error("failSecretService must preserve the ErrUnavailable chain")
	}
}
