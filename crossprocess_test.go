//go:build keychain_integration

package keychain

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A re-executed copy of this test binary becomes a read helper: TestMain
// dispatches on helperEnv before running any test, so the child reads one item
// and prints the outcome instead of running the suite.
const (
	helperEnv        = "TEST_KEYCHAIN_HELPER"
	helperServiceEnv = "TEST_KEYCHAIN_SERVICE"
	helperAccountEnv = "TEST_KEYCHAIN_ACCOUNT"

	helperTimeout    = 30 * time.Second
	crossProcessSize = 4096
)

// TestMain turns this binary into a keychain read helper whenever helperEnv is
// set; otherwise it runs the suite normally.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "" {
		os.Exit(runReadHelper())
	}

	os.Exit(m.Run())
}

// runReadHelper is the child role: read the named item and print one result
// token. It branches on the exported typed errors, so it is platform-agnostic.
func runReadHelper() int {
	secret, err := Get(os.Getenv(helperServiceEnv), os.Getenv(helperAccountEnv))

	switch {
	case err == nil:
		fmt.Fprintln(os.Stdout, "OK "+hex.EncodeToString(secret))
	case errors.Is(err, ErrNotFound):
		fmt.Fprintln(os.Stdout, "NOTFOUND")
	case errors.Is(err, ErrLocked):
		fmt.Fprintln(os.Stdout, "LOCKED")
	default:
		fmt.Fprintln(os.Stdout, "ERROR "+err.Error())
	}

	return 0
}

// TestCrossProcessRead proves the headless-daemon guarantee on every backend: a
// separate process — a re-executed copy of this binary with its own fresh store
// connection — reads what this process wrote, with no prompt. It runs in each
// per-OS integration job.
func TestCrossProcessRead(t *testing.T) {
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
