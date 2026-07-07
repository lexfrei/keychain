//go:build darwin && keychain_integration

package keychain

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"testing"
)

// TestDarwinContract runs the full behavioural contract against the real macOS
// login keychain through the native Security.framework backend. No fake is
// injected, so Set/Get/Delete resolve to the darwin backend under test — the
// darwin half of the one-contract-run-everywhere design. The 16 KB subtest is a
// payload past go-keyring's Windows cap and includes NUL bytes.
func TestDarwinContract(t *testing.T) {
	runContract(t, New(), uniqueService(t))
}

// TestDarwinCLIContract runs the same contract against the security-CLI opt-in
// backend (WithSecurityCLI), so both macOS code paths uphold the identical
// behaviour. This path base64-transcodes the value, so the 16 KB NUL-containing
// payload also proves the transcoding round-trips arbitrary bytes through argv.
func TestDarwinCLIContract(t *testing.T) {
	runContract(t, New(WithSecurityCLI()), uniqueService(t))
}

// uniqueService builds a throwaway service name no real application would use,
// tagged with the pid and random bytes, so an integration run never collides
// with a genuine keychain item or with a parallel CI job on the same runner.
func uniqueService(t *testing.T) string {
	t.Helper()

	var raw [6]byte

	_, err := rand.Read(raw[:])
	if err != nil {
		t.Fatalf("rand: %v", err)
	}

	return "com.lexfrei.keychain.itest." + strconv.Itoa(os.Getpid()) + "." + hex.EncodeToString(raw[:])
}
