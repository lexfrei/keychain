//go:build darwin && keychain_integration

package keychain

import (
	"context"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestDarwinNativeACLIsAllowAll pins the load-bearing macOS security claim: an
// item written by the native backend carries a decrypt ACL with a NULL trusted-
// application list (allow-all), the API equivalent of
// `security add-generic-password -A`. If SecACLSetContents ever stopped passing
// a NULL app list, the item would become owner-only and this test would fail.
// It parses `security dump-keychain -a`; when the output cannot be parsed (a
// future format change) it skips rather than flaking, and only fails on a
// genuine allow-all regression it could read.
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

// itemDumpBlock extracts the single dump-keychain record that carries the given
// (unique) service, from its "keychain:" header to the next one.
func itemDumpBlock(dump, service string) string {
	marker := `"svce"<blob>="` + service + `"`

	at := strings.Index(dump, marker)
	if at < 0 {
		return ""
	}

	start := strings.LastIndex(dump[:at], "\nkeychain:")
	if start < 0 {
		start = 0
	} else {
		start++
	}

	end := strings.Index(dump[at:], "\nkeychain:")
	if end < 0 {
		return dump[start:]
	}

	return dump[start : at+end]
}

// decryptACLIsAllowAll reports whether the record's decrypt-authorization ACL
// entry lists a NULL application set (allow-all). The second result is false
// when the expected structure is absent, so the caller can skip rather than fail.
func decryptACLIsAllowAll(block string) (bool, bool) {
	inDecryptEntry := false

	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "authorizations") {
			inDecryptEntry = authorizationsInclude(trimmed, "decrypt")

			continue
		}

		if inDecryptEntry && strings.HasPrefix(trimmed, "applications") {
			return trimmed == "applications: <null>", true
		}
	}

	return false, false
}

// authorizationsInclude reports whether an "authorizations (N): a b c" line lists
// the given authorization as an exact token.
func authorizationsInclude(line, want string) bool {
	at := strings.Index(line, "): ")
	if at < 0 {
		return false
	}

	return slices.Contains(strings.Fields(line[at+len("): "):]), want)
}
