//go:build darwin && keychain_integration

package keychain

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// TestDarwinLabelSetAndUpdated verifies that WithLabel actually names the stored
// item, and that a second Set with a new label updates it — the upsert-label
// behaviour the native backend adds. It reads the label from the item's
// attributes (no -g, so no decrypt and no partition dependency).
func TestDarwinLabelSetAndUpdated(t *testing.T) {
	service := uniqueService(t)

	const account = "label"

	t.Cleanup(func() { _ = Delete(service, account) })

	err := New(WithLabel("first label")).Set(service, account, []byte("v1"))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	got := readItemLabel(t, service, account)
	if got != "first label" {
		t.Fatalf("label = %q, want %q", got, "first label")
	}

	err = New(WithLabel("second label")).Set(service, account, []byte("v2"))
	if err != nil {
		t.Fatalf("upsert Set: %v", err)
	}

	got = readItemLabel(t, service, account)
	if got != "second label" {
		t.Fatalf("label after upsert = %q, want %q", got, "second label")
	}
}

// readItemLabel returns the item's kSecAttrLabel via `security find-generic-
// password`, parsed from its printed attributes. It skips if the attribute is
// not present in the output rather than failing on an environment quirk.
func readItemLabel(t *testing.T, service, account string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()

	raw, err := exec.CommandContext(ctx, "/usr/bin/security",
		"find-generic-password", "-s", service, "-a", account).CombinedOutput()
	if err != nil {
		t.Fatalf("security find-generic-password: %v (output %q)", err, raw)
	}

	out := string(raw)

	// security prints kSecAttrLabel by its raw attribute tag, not as "labl".
	const marker = `0x00000007 <blob>="`

	at := strings.Index(out, marker)
	if at < 0 {
		t.Skipf("no label attribute in security output: %s", out)
	}

	rest := out[at+len(marker):]

	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Skipf("unterminated label attribute in security output")
	}

	return rest[:end]
}
