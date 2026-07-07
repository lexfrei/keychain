//go:build darwin && keychain_integration

package keychain

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// TestDarwinNativeACLIsAllowAll pins the load-bearing macOS security claim: an
// item written by the native backend carries a decrypt ACL with a NULL trusted-
// application list (allow-all), the API equivalent of
// `security add-generic-password -A`. If SecACLSetContents ever stopped passing
// a NULL app list, the item would become owner-only and this test would fail.
// It parses `security dump-keychain -a` with the helpers pinned by
// TestDecryptACLParser; when the live output cannot be parsed (a future format
// change) it skips rather than flaking, and only fails on a genuine allow-all
// regression it could read.
func TestDarwinNativeACLIsAllowAll(t *testing.T) {
	service := uniqueService(t)

	const account = "acl-allow-all"

	t.Cleanup(func() { _ = Delete(service, account) })

	err := Set(service, account, []byte("v"))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "/usr/bin/security", "dump-keychain", "-a").Output()
	if err != nil {
		t.Skipf("dump-keychain unavailable: %v", err)
	}

	block := itemDumpBlock(string(out), service)
	if block == "" {
		t.Skip("could not locate the item in dump-keychain output (format may have changed)")
	}

	allowAll, parsed := decryptACLIsAllowAll(block)
	if !parsed {
		t.Skip("could not parse the decrypt ACL from dump-keychain output (format may have changed)")
	}

	if !allowAll {
		t.Fatal("native trust-all item's decrypt ACL is not allow-all: the NULL trusted-application list regressed")
	}
}
