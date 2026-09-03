//go:build darwin

package keychain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// errSpawnFailed stands in for the error a failing security(1) run returns. Its
// message is not what the tests assert; the wrapping around it is.
var errSpawnFailed = errors.New("exit status 45")

// spawnCall is one /usr/bin/security invocation as the OS would have seen it.
type spawnCall struct {
	stdin string
	args  []string
}

// fakeSpawn stands in for the process seam so these tests assert what would be
// spawned — argv and standard input — without touching a real keychain.
type fakeSpawn struct {
	calls  []spawnCall
	stdout []byte
	stderr []byte
	err    error
}

func (f *fakeSpawn) spawn(stdin string, args ...string) ([]byte, []byte, error) {
	f.calls = append(f.calls, spawnCall{stdin: stdin, args: args})

	return f.stdout, f.stderr, f.err
}

func (f *fakeSpawn) only(t *testing.T) spawnCall {
	t.Helper()

	if len(f.calls) != 1 {
		t.Fatalf("security invocations = %d, want exactly 1", len(f.calls))
	}

	return f.calls[0]
}

// TestQuoteSecurityArg pins the quoting that `security -i` actually accepts. Its
// parser is not a shell: a quote is honoured only at a token's start, the
// matching quote ends the token, and a backslash means "take the next byte
// literally" everywhere — inside single quotes too. That last rule is why
// go-keyring's single-quote escaping cannot be reused here: it turns a service
// name containing a backslash into a different name (silently, exit 0) and makes
// one containing a quote a usage error. Every case below round-trips through
// /usr/bin/security on macOS 27.0.
func TestQuoteSecurityArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "svc", `"svc"`},
		{"space", "my svc", `"my svc"`},
		{"double quote", `sv"c`, `"sv\"c"`},
		{"single quote", "sv'c", `"sv'c"`},
		{"both quotes", `sv'c"d`, `"sv'c\"d"`},
		{"backslash", `sv\c`, `"sv\\c"`},
		{"trailing backslash", `svc\`, `"svc\\"`},
		{"dollar", "sv$c", `"sv\$c"`},
		{"backtick", "sv`c", "\"sv\\`c\""},
		{"tab", "sv\tc", "\"sv\tc\""},
		{"carriage return", "sv\rc", "\"sv\rc\""},
		{"empty", "", `""`},
		{"utf8", "пароль", `"пароль"`},
		{"base64 padding", "aGVsbG8=", `"aGVsbG8="`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := quoteSecurityArg(tt.in)
			if got != tt.want {
				t.Errorf("quoteSecurityArg(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestCLISetKeepsTheSecretOffArgv is the point of the stdin transport: a value in
// argv is readable by any process of the same user for the duration of the call
// (ps) and is kept by anything that records process arguments. The tool must see
// exactly `-i`, with the command line — and the value — on its standard input.
func TestCLISetKeepsTheSecretOffArgv(t *testing.T) {
	t.Parallel()

	secret := []byte("s3cr3t\x00with-NUL")
	encoded := base64.StdEncoding.EncodeToString(secret)
	spy := &fakeSpawn{}

	err := securityTool{spawn: spy.spawn}.set("svc", "acct", secret)
	if err != nil {
		t.Fatalf("set: %v", err)
	}

	call := spy.only(t)

	if len(call.args) != 1 || call.args[0] != securityInteractive {
		t.Fatalf("argv = %q, want [%q]", call.args, securityInteractive)
	}

	for _, arg := range call.args {
		if strings.Contains(arg, encoded) || strings.Contains(arg, string(secret)) {
			t.Errorf("argv element %q carries the secret", arg)
		}
	}

	want := `add-generic-password -U -s "svc" -a "acct" -w "` + encoded + `"`
	if call.stdin != want {
		t.Errorf("stdin = %q, want %q", call.stdin, want)
	}
}

// TestCLISetQuotesTheKeyOnStdin covers the keys the line has to survive: the
// service and account are caller data and may hold whitespace or a quote, which
// the tool's splitter would otherwise read as another argument.
func TestCLISetQuotesTheKeyOnStdin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		service string
		account string
		want    string
	}{
		{
			name:    "space in both",
			service: "my service",
			account: "my account",
			want:    `add-generic-password -U -s "my service" -a "my account" -w "dg=="`,
		},
		{
			name:    "double quote in both",
			service: `sv"c`,
			account: `ac"ct`,
			want:    `add-generic-password -U -s "sv\"c" -a "ac\"ct" -w "dg=="`,
		},
		{
			name:    "space and double quote",
			service: `my "quoted" service`,
			account: `my "quoted" account`,
			want:    `add-generic-password -U -s "my \"quoted\" service" -a "my \"quoted\" account" -w "dg=="`,
		},
		{
			name:    "single quote and backslash",
			service: `sv'c\d`,
			account: `ac'ct\d`,
			want:    `add-generic-password -U -s "sv'c\\d" -a "ac'ct\\d" -w "dg=="`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			spy := &fakeSpawn{}

			err := securityTool{spawn: spy.spawn}.set(tt.service, tt.account, []byte("v"))
			if err != nil {
				t.Fatalf("set: %v", err)
			}

			call := spy.only(t)
			if call.stdin != tt.want {
				t.Errorf("stdin = %q, want %q", call.stdin, tt.want)
			}
		})
	}
}

// TestCLISetTransportBoundary pins where a value stops fitting on stdin. Past
// securityCLILineMax the tool's read cuts the command, so the value loses its
// tail and the remainder is parsed as another command: fed the 16 KB contract
// payload it stored a 4008-byte prefix of the 21848 base64 bytes and created
// the item regardless (measured with a 43-byte service name; how much survives
// depends on how much of the line the key spends). Byte-exactness at any size
// is the contract, so a value that does not fit goes back on argv, where the
// only bound is ARG_MAX. What the cap itself is worth is measured against the
// tool in TestDarwinCLIReadsAtMost4095Bytes, not asserted here.
func TestCLISetTransportBoundary(t *testing.T) {
	t.Parallel()

	const service, account = "svc", "acct"

	// Ask the renderer where the boundary falls rather than restating its
	// arithmetic here: what has to fit is the whole line, and how much of it the
	// key spends is the renderer's business.
	fits := largestStdinSecret(t, service, account)

	tests := []struct {
		name      string
		size      int
		wantStdin bool
	}{
		{"largest value that fits on one line", fits, true},
		{"one byte past the line buffer", fits + 1, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			secret := patternBytes(tt.size)
			encoded := base64.StdEncoding.EncodeToString(secret)
			spy := &fakeSpawn{}

			err := securityTool{spawn: spy.spawn}.set(service, account, secret)
			if err != nil {
				t.Fatalf("set: %v", err)
			}

			call := spy.only(t)

			if !tt.wantStdin {
				assertArgvUpsert(t, call, service, account, encoded)

				return
			}

			if len(call.args) != 1 || call.args[0] != securityInteractive {
				t.Fatalf("argv = %q, want [%q]", call.args, securityInteractive)
			}

			if len(call.stdin) > securityCLILineMax {
				t.Errorf("stdin line = %d bytes, over the %d the tool reads", len(call.stdin), securityCLILineMax)
			}

			if !strings.Contains(call.stdin, encoded) {
				t.Error("stdin line does not carry the encoded value")
			}
		})
	}
}

// TestCLISetUsesArgvForAKeyTheLineCannotCarry keeps the upsert working for a key
// the stdin form cannot express. A command reaches `security -i` as one line, so
// a service or account holding a newline would end the line early and the tail
// would be parsed as a second security command. argv carries a newline intact,
// which is what the path did before the stdin transport, so such a key keeps
// working rather than starting to fail.
func TestCLISetUsesArgvForAKeyTheLineCannotCarry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		service string
		account string
	}{
		{"newline in service", "sv\nc", "acct"},
		{"newline in account", "svc", "ac\nct"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			secret := []byte("v")
			encoded := base64.StdEncoding.EncodeToString(secret)
			spy := &fakeSpawn{}

			err := securityTool{spawn: spy.spawn}.set(tt.service, tt.account, secret)
			if err != nil {
				t.Fatalf("set: %v", err)
			}

			assertArgvUpsert(t, spy.only(t), tt.service, tt.account, encoded)
		})
	}
}

// TestCLISetFailsForAKeyHoldingNUL pins what a NUL in the key actually does,
// which is neither transport working. The stdin line cannot carry it, and the
// argv fallback does not get as far as the tool: Go refuses to build the
// argument vector, so no process starts and no item is written. This is
// unchanged from before the stdin transport and is asserted against the real
// spawn precisely because the failure happens before any keychain is touched.
func TestCLISetFailsForAKeyHoldingNUL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		service string
		account string
	}{
		{"NUL in service", "sv\x00c", "acct"},
		{"NUL in account", "svc", "ac\x00ct"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := securityTool{}.set(tt.service, tt.account, []byte("v"))
			if err == nil {
				t.Fatal("set with a NUL in the key returned nil")
			}

			if !strings.Contains(err.Error(), "add-generic-password") {
				t.Errorf("error %q does not name the subcommand", err)
			}

			// Assert the mechanism, not just that something failed: EINVAL from
			// building the argument vector is what guarantees no process ran. An
			// exit status would mean the tool was spawned after all, and this
			// test — which runs under a plain `go test` — would be writing a
			// NUL-bearing key into the developer's own login keychain.
			if !errors.Is(err, syscall.EINVAL) {
				t.Errorf("error %v is not EINVAL, so the argument vector was accepted", err)
			}

			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Errorf("error %v is an exit status, so a process was spawned", err)
			}
		})
	}
}

// TestCLIGetRejectsAValueItDidNotWrite covers the decode path a caller reaches
// after the mistake the docs warn about: an item written straight through
// `security add-generic-password`, or by the native backend, holds something
// that is not the base64 this path stores. That has to be an error, and not the
// absent-item error either, or a caller retries a write over a value that is
// really there.
func TestCLIGetRejectsAValueItDidNotWrite(t *testing.T) {
	t.Parallel()

	spy := &fakeSpawn{stdout: []byte("this is not base64\n")}

	got, err := securityTool{spawn: spy.spawn}.get("svc", "acct")
	if err == nil {
		t.Fatalf("get returned %q and no error for a value it did not write", got)
	}

	if errors.Is(err, errItemNotFound) {
		t.Errorf("a value that will not decode must not read as absent: %v", err)
	}

	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("error %q does not say the value failed to decode", err)
	}
}

// assertArgvUpsert checks that call is the one-shot argv form of the upsert.
func assertArgvUpsert(t *testing.T, call spawnCall, service, account, encoded string) {
	t.Helper()

	if call.stdin != "" {
		t.Errorf("stdin = %q, want empty (the argv form feeds nothing)", call.stdin)
	}

	want := []string{"add-generic-password", "-U", "-s", service, "-a", account, "-w", encoded}
	if len(call.args) != len(want) {
		t.Fatalf("argv = %q, want %q", call.args, want)
	}

	for i := range want {
		if call.args[i] != want[i] {
			t.Fatalf("argv = %q, want %q", call.args, want)
		}
	}
}

// TestCLIGetAndDeleteStayOnArgv pins that only the write moved. find-generic-
// password prints a value and receives none; delete-generic-password carries
// none. Neither has a secret to hide, and argv keeps them one-shot, so the
// exit-status mapping below is the tool's own.
func TestCLIGetAndDeleteStayOnArgv(t *testing.T) {
	t.Parallel()

	spy := &fakeSpawn{stdout: []byte("dg==\n")}

	got, err := securityTool{spawn: spy.spawn}.get("svc", "acct")
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	if string(got) != "v" {
		t.Errorf("get = %q, want %q", got, "v")
	}

	call := spy.only(t)
	if call.stdin != "" || len(call.args) == 0 || call.args[0] != "find-generic-password" {
		t.Errorf("get spawned %q with stdin %q, want the find-generic-password argv form", call.args, call.stdin)
	}

	spy = &fakeSpawn{}

	err = securityTool{spawn: spy.spawn}.del("svc", "acct")
	if err != nil {
		t.Fatalf("del: %v", err)
	}

	call = spy.only(t)
	if call.stdin != "" || len(call.args) == 0 || call.args[0] != "delete-generic-password" {
		t.Errorf("del spawned %q with stdin %q, want the delete-generic-password argv form", call.args, call.stdin)
	}
}

// TestCLIErrorNamesTheSubcommand keeps the diagnostics identical across the two
// transports. The stdin form's argv is just `-i`, so the subcommand in the
// message has to come from the line the tool was fed, and the tool's stderr must
// still reach the caller.
func TestCLIErrorNamesTheSubcommand(t *testing.T) {
	t.Parallel()

	spy := &fakeSpawn{
		stderr: []byte("security: SecKeychainItemCreateFromContent: some failure\n"),
		err:    errSpawnFailed,
	}

	err := securityTool{spawn: spy.spawn}.set("svc", "acct", []byte("v"))
	if err == nil {
		t.Fatal("set returned nil for a failing security invocation")
	}

	if !strings.Contains(err.Error(), "add-generic-password") {
		t.Errorf("error %q does not name the subcommand", err)
	}

	if !strings.Contains(err.Error(), "some failure") {
		t.Errorf("error %q drops the tool's stderr", err)
	}
}

// TestCLINotFoundClassification pins the absent-item mapping the public Get and
// Delete depend on: security(1) reports errSecItemNotFound (-25300) as exit 44,
// and this maps it to errItemNotFound. It drives a fake spawn, so it covers the
// classification and nothing about the tool; that the interactive mode really
// does return a failing subcommand's own status is a claim about the tool and is
// pinned against it by TestDarwinCLIPropagatesSubcommandStatus.
func TestCLINotFoundClassification(t *testing.T) {
	t.Parallel()

	notFound := exitStatus(t, securityCLINotFound)

	_, err := securityTool{spawn: (&fakeSpawn{err: notFound}).spawn}.get("svc", "acct")
	if !errors.Is(err, errItemNotFound) {
		t.Errorf("get on exit 44 = %v, want errItemNotFound", err)
	}

	err = securityTool{spawn: (&fakeSpawn{err: notFound}).spawn}.del("svc", "acct")
	if !errors.Is(err, errItemNotFound) {
		t.Errorf("del on exit 44 = %v, want errItemNotFound", err)
	}

	other := exitStatus(t, 1)

	_, err = securityTool{spawn: (&fakeSpawn{err: other}).spawn}.get("svc", "acct")
	if errors.Is(err, errItemNotFound) {
		t.Errorf("get on exit 1 = %v, want a plain error, not errItemNotFound", err)
	}
}

// largestStdinSecret returns the largest secret, in bytes, whose upsert line
// still fits the interactive mode for this key. It asks the production renderer
// instead of repeating its arithmetic, so the boundary under test is the one the
// backend actually applies.
func largestStdinSecret(t *testing.T, service, account string) int {
	t.Helper()

	for size := securityCLILineMax; size > 0; size-- {
		_, ok := upsertLine(service, account, base64.StdEncoding.EncodeToString(patternBytes(size)))
		if ok {
			return size
		}
	}

	t.Fatalf("no secret size fits one line for service %q", service)

	return 0
}

// exitStatus returns the error of a process that exited with code, so the
// exit-status mapping can be tested without a keychain or a real security run.
func exitStatus(t *testing.T, code int) error {
	t.Helper()

	err := exec.CommandContext(t.Context(), "/bin/sh", "-c", "exit "+strconv.Itoa(code)).Run()

	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != code {
		t.Fatalf("helper process did not exit %d: %v", code, err)
	}

	return fmt.Errorf("helper process: %w", err)
}
