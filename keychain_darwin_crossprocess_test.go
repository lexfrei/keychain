//go:build darwin && keychain_integration

package keychain

import (
	"bytes"
	"context"
	"encoding/base64"
	"os/exec"
	"strings"
	"testing"
)

// TestDarwinCLICrossIdentity proves the WithSecurityCLI path is genuinely
// cross-identity, which the native path cannot be for an unsigned binary. It
// writes through the CLI backend, then reads the item with a raw /usr/bin/security
// invocation — a different code identity than this test. Because the CLI path
// stores into the stable apple-tool partition, security reads it with no prompt.
// The value is the base64 the CLI path writes, so it is decoded before comparing.
func TestDarwinCLICrossIdentity(t *testing.T) {
	kc := New(WithSecurityCLI())
	service := uniqueService(t)

	const account = "cli-cross-identity"

	secret := patternBytes(crossProcessSize)

	t.Cleanup(func() { _ = kc.Delete(service, account) })

	err := kc.Set(service, account, secret)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "/usr/bin/security",
		"find-generic-password", "-s", service, "-a", account, "-w")

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("security find-generic-password: %v (output %q)", err, out)
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimRight(string(out), "\n"))
	if err != nil {
		t.Fatalf("decode security output: %v", err)
	}

	if !bytes.Equal(decoded, secret) {
		t.Fatalf("cross-identity read changed the bytes: got %d, want %d", len(decoded), len(secret))
	}
}
