//go:build darwin

package keychain

import (
	"slices"
	"strings"
	"testing"
)

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
// entry lists a NULL application set (allow-all). The second result is false when
// the expected structure is absent, so the caller can skip rather than fail.
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

// TestDecryptACLParser pins the dump-keychain parser deterministically, so the
// live ACL regression guard cannot silently pass on a broken parser: an allow-all
// decrypt ACL must report allow-all, and an owner-scoped one must not.
func TestDecryptACLParser(t *testing.T) {
	const allowAll = `keychain: "login.keychain-db"
class: "genp"
attributes:
    "svce"<blob>="my-service"
access: 2 entries
    entry 0:
        authorizations (1): encrypt
        applications: <null>
    entry 1:
        authorizations (6): decrypt derive export_clear export_wrapped mac sign
        applications: <null>
`

	const ownerOnly = `keychain: "login.keychain-db"
class: "genp"
attributes:
    "svce"<blob>="my-service"
access: 2 entries
    entry 0:
        authorizations (1): encrypt
        applications: <null>
    entry 1:
        authorizations (6): decrypt derive export_clear export_wrapped mac sign
        applications (1):
            0: /usr/bin/foo
`

	block := itemDumpBlock(allowAll, "my-service")
	if block == "" {
		t.Fatal("itemDumpBlock did not find the service in the allow-all sample")
	}

	got, parsed := decryptACLIsAllowAll(block)
	if !parsed {
		t.Fatal("the allow-all sample should parse")
	}

	if !got {
		t.Error("a NULL application set must be reported as allow-all")
	}

	got, parsed = decryptACLIsAllowAll(itemDumpBlock(ownerOnly, "my-service"))
	if !parsed {
		t.Fatal("the owner-only sample should parse")
	}

	if got {
		t.Error("an owner-scoped application set must NOT be reported as allow-all")
	}

	if itemDumpBlock(allowAll, "absent-service") != "" {
		t.Error("itemDumpBlock should return empty for a service that is not present")
	}
}
