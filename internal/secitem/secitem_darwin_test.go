//go:build darwin

package secitem

import (
	"errors"
	"strings"
	"testing"
)

// TestStatusError pins the OSStatus-to-error mapping without a live store:
// Success is nil, and any other status becomes a *Error that carries the status
// and prints it. This is the shape the darwin backend's typed-error
// classification (ErrLocked / ErrAccessDenied) relies on.
func TestStatusError(t *testing.T) {
	if StatusError(Success) != nil {
		t.Fatal("StatusError(Success) should be nil")
	}

	err := StatusError(ItemNotFound)

	var secErr *Error
	if !errors.As(err, &secErr) {
		t.Fatalf("StatusError should return a *Error, got %T", err)
	}

	if secErr.Status != ItemNotFound {
		t.Errorf("Status = %d, want %d", secErr.Status, ItemNotFound)
	}

	if !strings.Contains(err.Error(), "-25300") {
		t.Errorf("error message %q should carry the OSStatus number", err.Error())
	}
}

// TestErrorMessageWithoutMessage pins that Error prints cleanly when the
// framework message is absent (the binding is not loaded in this unit test).
func TestErrorMessageWithoutMessage(t *testing.T) {
	err := &Error{Status: AuthFailed}

	got := err.Error()
	if !strings.Contains(got, "-25293") {
		t.Errorf("Error() = %q, want it to contain the status", got)
	}
}

// TestErrorWithMessage pins the other Error branch: when the framework message is
// present it is included alongside the status.
func TestErrorWithMessage(t *testing.T) {
	err := &Error{Status: ItemNotFound, Message: "the specified item could not be found"}

	got := err.Error()
	if !strings.Contains(got, "-25300") || !strings.Contains(got, "could not be found") {
		t.Errorf("Error() = %q, want both the status and the message", got)
	}
}
