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

	// securityInteractive makes the tool read its subcommand from standard input
	// instead of argv, which is how a value stays out of the process list.
	securityInteractive = "-i"

	addGenericPassword    = "add-generic-password"
	findGenericPassword   = "find-generic-password"
	deleteGenericPassword = "delete-generic-password"

	// security(1) maps errSecItemNotFound (-25300) to exit status 44 (the low
	// byte of the OSStatus). That is how an absent item is detected on read and
	// delete, both of which run as one-shot argv invocations.
	securityCLINotFound = 44

	// securityCLITimeout bounds each security(1) invocation so a wedged tool can
	// never hang a caller; a local keychain operation completes in milliseconds.
	securityCLITimeout = 30 * time.Second

	// securityCLILineMax is the longest command line the interactive mode can be
	// given safely, newline excluded. The tool reads at most 4095 bytes per line
	// and counts the newline against that, so 4094 is the last length where one
	// read takes the whole command and nothing is left over. Measured on macOS
	// 27.0; CI re-measures it on every run (TestDarwinCLIReadsAtMost4095Bytes).
	//
	// Both bytes above it fail silently, which is why the margin is not
	// cosmetic. At 4095 the command runs correctly but its newline is left for
	// the next read, where the empty line counts as a command that succeeds —
	// and since the tool exits with the LAST command's status, a real failure is
	// reported as success. At 4096 and beyond the read cuts mid-command, so the
	// value loses its tail and the remainder is parsed as another command.
	//
	// The same tool buffer is what limits go-keyring on macOS, which guards the
	// identical line with ErrSetDataTooBig — but counts the newline into its
	// 4096, so it admits a 4095-byte line, the length where a failed add reports
	// success. This cap is a byte tighter on purpose. A value that would cross it
	// goes back on argv instead, where the only bound is ARG_MAX.
	securityCLILineMax = 4094
)

// securityTool runs the security(1) subcommands behind the CLI backend. Its zero
// value spawns the real tool; the unit tests substitute spawn to read back the
// argv and standard input an invocation would have received.
type securityTool struct {
	spawn func(stdin string, args ...string) (stdout, stderr []byte, err error)
}

// set upserts via `security add-generic-password -U`. The value is base64 so
// arbitrary bytes survive: neither an argv element nor a line of the tool's
// standard input can contain a NUL, and real secrets (and the 16 KB contract
// payload) do.
//
// The command line goes to the tool's standard input, keeping the value out of
// this process's argv and so out of `ps` and out of anything that records
// process arguments. Where the line does not fit (see upsertLine) the value
// falls back to argv: exposure in the process list is the lesser fault against a
// silently truncated item.
func (s securityTool) set(service, account string, secret []byte) error {
	encoded := base64.StdEncoding.EncodeToString(secret)

	line, ok := upsertLine(service, account, encoded)
	if !ok {
		_, err := s.runArgs(addGenericPassword, "-U", "-s", service, "-a", account, "-w", encoded)

		return err
	}

	_, err := s.runLine(addGenericPassword, line)

	return err
}

// get reads the value with `security find-generic-password -w` and decodes the
// base64 that set wrote. An absent item maps to errItemNotFound. It stays on
// argv: the subcommand prints a value, it never receives one.
func (s securityTool) get(service, account string) ([]byte, error) {
	stdout, err := s.runArgs(findGenericPassword, "-s", service, "-a", account, "-w")
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

// del removes the item. An absent item maps to errItemNotFound, which the public
// Delete turns into a no-op (idempotent). It carries no value, so it stays on
// argv too.
func (s securityTool) del(service, account string) error {
	_, err := s.runArgs(deleteGenericPassword, "-s", service, "-a", account)
	if err != nil {
		if isSecurityNotFound(err) {
			return errItemNotFound
		}

		return err
	}

	return nil
}

// upsertLine renders the upsert as one line for the interactive mode, or reports
// false when the tool cannot receive it and the caller must use argv.
//
// Two things do not fit on that line. A line longer than securityCLILineMax is
// split, and its tail is parsed as a further command. And a service or account
// holding a newline or a NUL cannot be transported at all: the newline would end
// the line early, letting the remainder of a crafted name run as a second
// security command, and the NUL would cut the tool's C string short.
//
// Both fall back to argv, which is the route they took before this transport
// existed. What happens there differs, and neither outcome is new: argv carries
// a newline intact, while a NUL fails inside Go before the process starts, so a
// NUL-bearing key has never reached the tool by either route.
func upsertLine(service, account, encoded string) (string, bool) {
	if strings.ContainsAny(service, "\n\x00") || strings.ContainsAny(account, "\n\x00") {
		return "", false
	}

	line := addGenericPassword + " -U -s " + quoteSecurityArg(service) +
		" -a " + quoteSecurityArg(account) +
		" -w " + quoteSecurityArg(encoded)

	if len(line) > securityCLILineMax {
		return "", false
	}

	return line, true
}

// quoteSecurityArg wraps s as one argument for the interactive mode's splitter,
// which is not a shell. Measured on macOS 27.0: a quote is honoured only at a
// token's start and the matching quote ends the token, while a backslash means
// "take the next byte literally" everywhere — inside single quotes too. So
// double quotes with the backslash and the quote escaped round-trip every byte a
// line can carry (verified over 0x01–0x7f except the newline, plus UTF-8), and
// go-keyring's single-quote escaping
// does not: it drops a backslash from a service name and breaks outright on a
// quote. The dollar sign and backtick are literal in this parser and are escaped
// only so a parser that ever learns to expand them cannot corrupt a value.
func quoteSecurityArg(s string) string {
	escaper := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`")

	return `"` + escaper.Replace(s) + `"`
}

// runLine runs subcommand by feeding line to `security -i`, so nothing but the
// flag reaches argv. line must carry the subcommand itself; subcommand is what
// names the operation in an error.
func (s securityTool) runLine(subcommand, line string) ([]byte, error) {
	return s.exec(subcommand, line, securityInteractive)
}

// runArgs runs subcommand as a one-shot argv invocation.
func (s securityTool) runArgs(subcommand string, args ...string) ([]byte, error) {
	return s.exec(subcommand, "", append([]string{subcommand}, args...)...)
}

// exec spawns the tool and wraps a failure with the subcommand's name, so the
// two transports produce identical diagnostics even though only one of them puts
// the subcommand in argv.
func (s securityTool) exec(subcommand, stdin string, argv ...string) ([]byte, error) {
	spawn := s.spawn
	if spawn == nil {
		spawn = spawnSecurity
	}

	stdout, stderr, err := spawn(stdin, argv...)
	if err != nil {
		return stdout, securityError(subcommand, string(stderr), err)
	}

	return stdout, nil
}

// spawnSecurity runs /usr/bin/security. The command path is a fixed absolute
// path and no shell is involved, so the service, account, and value are data
// either way: as separate argv elements, or as one quoted line on the tool's
// standard input.
func spawnSecurity(stdin string, args ...string) ([]byte, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), securityCLITimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, securityPath, args...)

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if stdin != "" {
		// The interactive mode reads commands until EOF, which closing the pipe
		// after the single line delivers.
		cmd.Stdin = strings.NewReader(stdin + "\n")
	}

	err := cmd.Run()

	return stdout.Bytes(), stderr.Bytes(), err
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
