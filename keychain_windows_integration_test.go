//go:build windows && keychain_integration

package keychain

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"testing"
)

// TestWindowsContract runs the full behavioural contract against the real
// Windows Credential Manager. The 16 KB subtest is stored across several 2560 B
// credential blobs by the chunk container, and the upsert subtest proves a
// replacement value reads back cleanly even though the previous one spanned more
// chunks — the transparent-chunking guarantee.
func TestWindowsContract(t *testing.T) {
	runContract(t, New(), uniqueService(t))
}

// uniqueService builds a throwaway service name no real application would use,
// tagged with the pid and random bytes, so an integration run never collides
// with a genuine credential or with a parallel CI job on the same runner.
func uniqueService(t *testing.T) string {
	t.Helper()

	var raw [6]byte

	_, err := rand.Read(raw[:])
	if err != nil {
		t.Fatalf("rand: %v", err)
	}

	return "com.lexfrei.keychain.itest." + strconv.Itoa(os.Getpid()) + "." + hex.EncodeToString(raw[:])
}
