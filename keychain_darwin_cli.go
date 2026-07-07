//go:build darwin

package keychain

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// The CLI path delegates to /usr/bin/security so an item lands in the stable
// "apple-tool" access partition, readable across rebuilds and apps. It is the
// opt-in escape hatch for unsigned binaries (see WithSecurityCLI); the native
// API path is the default.
const (
	securityPath = "/usr/bin/security"

	// security(1) maps errSecItemNotFound (-25300) to exit status 44 (the low
	// byte of the OSStatus). That is how an absent item is detected on read and
	// delete.
	securityCLINotFound = 44

	// securityCLITimeout bounds each security(1) invocation so a wedged tool can
	// never hang a caller; a local keychain operation completes in milliseconds.
	securityCLITimeout = 30 * time.Second
)

// cliSet upserts via `security add-generic-password -U`. The value is base64 so
// arbitrary bytes survive: an argv element cannot contain a NUL, and Go's exec
// rejects any argument that does, yet real secrets (and the 16 KB contract
// payload) contain NUL bytes.
func cliSet(service, account string, secret []byte) error {
	encoded := base64.StdEncoding.EncodeToString(secret)

	_, err := runSecurity("add-generic-password", "-U", "-s", service, "-a", account, "-w", encoded)

	return err
}

// cliGet reads the value with `security find-generic-password -w` and decodes
// the base64 that cliSet wrote. An absent item maps to errItemNotFound.
func cliGet(service, account string) ([]byte, error) {
	stdout, err := runSecurity("find-generic-password", "-s", service, "-a", account, "-w")
	if err != nil {
		if isSecurityNotFound(err) {
			return nil, errItemNotFound
		}

		return nil, err
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimRight(string(stdout), "\n"))
	if err != nil {
		return nil, fmt.Errorf("keychain: darwin cli: decode stored value: %w", err)
	}

	// A stored empty secret decodes to a zero-length slice; return a non-nil one
	// so "present but empty" stays distinct from absent.
	if len(decoded) == 0 {
		return []byte{}, nil
	}

	return decoded, nil
}

// cliDel removes the item. An absent item maps to errItemNotFound, which the
// public Delete turns into a no-op (idempotent).
func cliDel(service, account string) error {
	_, err := runSecurity("delete-generic-password", "-s", service, "-a", account)
	if err != nil {
		if isSecurityNotFound(err) {
			return errItemNotFound
		}

		return err
	}

	return nil
}

// runSecurity runs /usr/bin/security and returns its standard output. The
// command path is a fixed absolute path and the arguments are passed as separate
// argv elements (no shell), so service, account, and value are data, never code.
func runSecurity(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), securityCLITimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, securityPath, args...)

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return stdout.Bytes(), securityError(args[0], stderr.String(), err)
	}

	return stdout.Bytes(), nil
}

// isSecurityNotFound reports whether err is a security(1) exit for an absent item.
func isSecurityNotFound(err error) bool {
	var exitErr *exec.ExitError

	return errors.As(err, &exitErr) && exitErr.ExitCode() == securityCLINotFound
}

func securityError(subcommand, stderr string, err error) error {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return fmt.Errorf("keychain: darwin cli: security %s: %w", subcommand, err)
	}

	return fmt.Errorf("keychain: darwin cli: security %s: %w: %s", subcommand, err, stderr)
}
