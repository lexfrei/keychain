//go:build darwin

package keychain

import (
	"errors"
	"testing"

	"github.com/lexfrei/keychain/internal/secitem"
)

// TestFailDarwinClassifiesInteractionAsLocked pins that a headless read blocked
// by errSecInteractionNotAllowed surfaces as ErrLocked, so a caller can branch
// on it with errors.Is instead of matching a message string.
func TestFailDarwinClassifiesInteractionAsLocked(t *testing.T) {
	err := failDarwin(&secitem.Error{Status: secitem.InteractionNotAllowed})

	if !errors.Is(err, ErrLocked) {
		t.Fatalf("interaction-not-allowed should wrap ErrLocked, got %v", err)
	}
}

// TestFailDarwinClassifiesAuthFailedAsAccessDenied pins that a partition/ACL
// denial (the rebuilt-unsigned-binary case) surfaces as ErrAccessDenied, and not
// as ErrLocked — an unlock cannot clear it.
func TestFailDarwinClassifiesAuthFailedAsAccessDenied(t *testing.T) {
	err := failDarwin(&secitem.Error{Status: secitem.AuthFailed})

	if !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("auth-failed should wrap ErrAccessDenied, got %v", err)
	}

	if errors.Is(err, ErrLocked) {
		t.Fatalf("auth-failed must not be ErrLocked, got %v", err)
	}
}

// TestFailDarwinGenericNotClassified pins that an ordinary Security error is not
// mislabelled as one of the typed conditions.
func TestFailDarwinGenericNotClassified(t *testing.T) {
	err := failDarwin(&secitem.Error{Status: secitem.DuplicateItem})

	if err == nil {
		t.Fatal("failDarwin returned nil for a non-nil error")
	}

	if errors.Is(err, ErrLocked) || errors.Is(err, ErrUnavailable) || errors.Is(err, ErrAccessDenied) {
		t.Fatalf("a generic Security error must be none of the typed conditions, got %v", err)
	}
}
