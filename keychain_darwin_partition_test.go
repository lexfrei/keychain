//go:build darwin && keychain_integration

package keychain

import (
	"context"
	"os/exec"
	"testing"
)

// TestDarwinNativePartitionRestricted verifies the other half of the macOS
// security model: although the native item's decrypt ACL is allow-all, the OS
// access partition still binds it to the creating binary's code identity. A
// different identity — /usr/bin/security, in the apple-tool partition — must be
// denied when it tries to read the item's value (decrypt). This is exactly what
// makes an unsigned rebuild lose access, and it is the condition the backend
// maps to ErrAccessDenied.
//
// -w decrypts the value; with no controlling terminal the prompt cannot be
// shown, so the request fails fast (errSecAuthFailed) rather than hanging.
func TestDarwinNativePartitionRestricted(t *testing.T) {
	service := uniqueService(t)

	const account = "partition"

	t.Cleanup(func() { _ = Delete(service, account) })

	err := Set(service, account, []byte("secret"))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()

	// Finding the item (metadata) must succeed; reading its value across code
	// identities must not.
	value := exec.CommandContext(ctx, "/usr/bin/security",
		"find-generic-password", "-s", service, "-a", account, "-w")

	err = value.Run()
	if err == nil {
		t.Fatal("security decrypted the native item's value across code identities; the access partition did not restrict it")
	}
}
