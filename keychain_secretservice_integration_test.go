//go:build (linux || freebsd || openbsd || netbsd) && keychain_integration

package keychain

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"testing"
)

// TestSecretServiceContract runs the full behavioural contract against the real
// freedesktop Secret Service (gnome-keyring / KWallet) over the session D-Bus.
// It requires a session bus with an unlocked default collection; CI provides one
// under dbus-run-session + gnome-keyring.
func TestSecretServiceContract(t *testing.T) {
	runContract(t, New(), uniqueService(t))
}

// uniqueService builds a throwaway service name no real application would use,
// tagged with the pid and random bytes, so an integration run never collides
// with a genuine item or with a parallel CI job on the same bus.
func uniqueService(t *testing.T) string {
	t.Helper()

	var raw [6]byte

	_, err := rand.Read(raw[:])
	if err != nil {
		t.Fatalf("rand: %v", err)
	}

	return "com.lexfrei.keychain.itest." + strconv.Itoa(os.Getpid()) + "." + hex.EncodeToString(raw[:])
}
