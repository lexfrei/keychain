//go:build darwin && keychain_integration && keychain_cfdebug

package keychain

import (
	"testing"

	"github.com/lexfrei/keychain/internal/cf"
)

// TestDarwinNoCFLeak runs a full Set/Get/Delete cycle — including the trust-all
// ACL path — under the cfdebug reference counter and asserts every
// CoreFoundation reference it created was released. A leaked CF ref is invisible
// to Go's GC, so this balance check is the only guard against a create wrapper
// whose release was skipped. It measures a delta rather than an absolute so it
// is robust to references other tests in the same binary hold.
func TestDarwinNoCFLeak(t *testing.T) {
	service := uniqueService(t)

	const account = "cf-leak"

	t.Cleanup(func() { _ = Delete(service, account) })

	before := cf.LeakCount()

	secret := patternBytes(2048)

	err := Set(service, account, secret)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := Get(service, account)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if len(got) != len(secret) {
		t.Fatalf("Get returned %d bytes, want %d", len(got), len(secret))
	}

	err = Delete(service, account)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	after := cf.LeakCount()
	if after != before {
		t.Fatalf("CoreFoundation reference leak: %d references created and not released", after-before)
	}
}
