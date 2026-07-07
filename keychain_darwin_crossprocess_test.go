//go:build darwin && keychain_integration

package keychain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lexfrei/keychain/internal/secitem"
)

// The child process re-executes this same test binary. TestMain dispatches on
// helperEnv before running any test, so the child never runs the suite — it
// reads one item and reports the outcome on stdout.
const (
	helperEnv        = "TEST_KEYCHAIN_HELPER"
	helperServiceEnv = "TEST_KEYCHAIN_SERVICE"
	helperAccountEnv = "TEST_KEYCHAIN_ACCOUNT"

	helperTimeout    = 30 * time.Second
	crossProcessSize = 4096
)

// TestMain turns this binary into a keychain read helper whenever helperEnv is
// set, so a test can re-exec it as a separate process; otherwise it runs the
// suite normally.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "" {
		os.Exit(runReadHelper())
	}

	os.Exit(m.Run())
}

// runReadHelper is the child role: read the item named by the environment and
// print a single result token. The child re-executes the same on-disk binary, so
// it shares this test's code identity (cdhash) and therefore the item's access
// partition — the native read succeeds with no prompt.
func runReadHelper() int {
	secret, err := Get(os.Getenv(helperServiceEnv), os.Getenv(helperAccountEnv))

	switch {
	case err == nil:
		fmt.Fprintln(os.Stdout, "OK "+hex.EncodeToString(secret))
	case errors.Is(err, ErrNotFound):
		fmt.Fprintln(os.Stdout, "NOTFOUND")
	default:
		var secErr *secitem.Error
		if errors.As(err, &secErr) && secErr.Status == secitem.InteractionNotAllowed {
			fmt.Fprintln(os.Stdout, "INTERACTION")
		} else {
			fmt.Fprintln(os.Stdout, "ERROR "+err.Error())
		}
	}

	return 0
}

// TestDarwinCrossProcessRead proves the headless-daemon guarantee for the native
// backend: a separate process of the same binary reads what this process wrote,
// with no prompt. The child re-execs the same binary and reads it back.
func TestDarwinCrossProcessRead(t *testing.T) {
	service := uniqueService(t)

	const account = "cross-process"

	secret := patternBytes(crossProcessSize)

	t.Cleanup(func() { _ = Delete(service, account) })

	err := Set(service, account, secret)
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	out := runReadChild(t, service, account)

	want := "OK " + hex.EncodeToString(secret)
	if strings.TrimSpace(out) != want {
		t.Fatalf("cross-process read = %q, want %q", strings.TrimSpace(out), want)
	}
}

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

// runReadChild re-execs this test binary as the read helper and returns its stdout.
func runReadChild(t *testing.T, service, account string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = append(os.Environ(),
		helperEnv+"=read",
		helperServiceEnv+"="+service,
		helperAccountEnv+"="+account,
	)

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper process: %v (output %q)", err, out)
	}

	return string(out)
}
