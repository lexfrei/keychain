//go:build darwin && keychain_integration

package keychain

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// TestDarwinCLIReadsAtMost4095Bytes measures the tool's line buffer directly,
// so securityCLILineMax is checked against the tool instead of against itself.
// A test that derives its sizes from the constant can only confirm the constant
// is self-consistent; this one fails if the buffer ever moves, which is the
// property the cap depends on.
//
// It touches no keychain item: every line below is a nonsense command, so the
// tool parses, complains and exits.
//
// The three cases are the cap and the two bytes above it, and both of those
// fail silently in production shape. At the cap, the line and its newline are
// one read: one command runs and its failing status is what the caller sees. One
// byte more and the newline is left for the next read, where an empty line
// counts as a command that succeeds — and the tool exits with the LAST command's
// status, so the failure is reported as success. Two bytes more and the read
// cuts the command itself, leaving a tail that is parsed as another command.
func TestDarwinCLIReadsAtMost4095Bytes(t *testing.T) {
	// The exit assertion is zero versus non-zero on purpose: which non-zero code
	// a nonsense command earns is security's business and not what this test is
	// about, so pinning the literal would point a future failure at the buffer
	// when the dispatcher had merely renumbered itself.
	tests := []struct {
		name           string
		lineLen        int
		wantCommands   int
		wantStatusLost bool
	}{
		{"at the cap, the status survives", securityCLILineMax, 1, false},
		{"one over, the empty line resets the status", securityCLILineMax + 1, 1, true},
		{"two over, the command itself is cut", securityCLILineMax + 2, 2, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// An unquoted token ending in a marker: a quoted one would hide a
			// dropped closing quote behind an unterminated quote the parser
			// accepts, which is how the cap was mismeasured in the first place.
			line := strings.Repeat("z", tt.lineLen-3) + "END"

			commands, exit := feedInteractive(t, line)

			if commands != tt.wantCommands {
				t.Errorf("tool attempted %d commands, want %d (line %d bytes)",
					commands, tt.wantCommands, tt.lineLen)
			}

			if lost := exit == 0; lost != tt.wantStatusLost {
				t.Errorf("exit = %d (status lost = %v), want lost = %v (line %d bytes)",
					exit, lost, tt.wantStatusLost, tt.lineLen)
			}
		})
	}
}

// TestDarwinCLIPropagatesSubcommandStatus pins the property securityCLILineMax
// exists to protect, against the tool itself. A one-shot argv invocation reports
// a failing subcommand through its own exit status; the interactive mode reports
// the status of the last command it ran, which is the same thing only while
// exactly one command reaches it. If that ever stopped holding, a failing Set on
// the stdin route would return nil having written nothing — the same silent
// class as a truncated value, one level up.
//
// It reads an item that does not exist, so it writes nothing: the expected
// answer is errSecItemNotFound, which is exit 44.
func TestDarwinCLIPropagatesSubcommandStatus(t *testing.T) {
	line := findGenericPassword + " -s " + quoteSecurityArg(uniqueService(t)) +
		" -a " + quoteSecurityArg("absent") + " -w"

	_, exit := feedInteractive(t, line)
	if exit != securityCLINotFound {
		t.Errorf("exit = %d, want %d: the interactive mode no longer returns the subcommand's own status",
			exit, securityCLINotFound)
	}
}

// TestDarwinCLITransportBoundary is the real-tool half of the transport rule the
// unit tests pin. It writes with the longest key whose line still fits, so the
// line lands exactly on the cap, and then with the first key whose line does not
// fit, which is the first value to go back on argv. Both must read back
// byte-for-byte.
//
// Each case also compares the stored value against the base64 the writer sent.
// That string is what the argv form has always written, so it proves the two
// transports store identical bytes and an item written by either is readable by
// the other — no migration, no mode to keep track of.
func TestDarwinCLITransportBoundary(t *testing.T) {
	kc := New(WithSecurityCLI())
	secret := patternBytes(2048)
	encoded := base64.StdEncoding.EncodeToString(secret)

	const account = "boundary"

	atCap, overCap := keysAroundTheCap(t, uniqueService(t), account, encoded)

	tests := []struct {
		name      string
		service   string
		wantStdin bool
	}{
		{"line exactly at the cap", atCap, true},
		{"line one byte over the cap", overCap, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, onStdin := upsertLine(tt.service, account, encoded)
			if onStdin != tt.wantStdin {
				t.Fatalf("stdin transport = %v, want %v", onStdin, tt.wantStdin)
			}

			if onStdin && len(line) != securityCLILineMax {
				t.Fatalf("line = %d bytes, want exactly the cap %d", len(line), securityCLILineMax)
			}

			t.Cleanup(func() { _ = kc.Delete(tt.service, account) })

			err := kc.Set(tt.service, account, secret)
			if err != nil {
				t.Fatalf("Set: %v", err)
			}

			got, err := kc.Get(tt.service, account)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}

			if !bytes.Equal(got, secret) {
				t.Fatalf("value changed: got %d bytes, want %d", len(got), len(secret))
			}

			stored := rawSecurityValue(t, tt.service, account)
			if stored != encoded {
				t.Fatalf("stored value is not the base64 the writer sent: got %d chars, want %d",
					len(stored), len(encoded))
			}
		})
	}
}

// TestDarwinCLIContractPayloadStaysOnArgv pins that the payload this library
// exists for is nowhere near the line: 16 KB of base64 is several times the cap,
// so it takes the argv route and the contract's byte-exactness is unaffected by
// anything the interactive mode does.
func TestDarwinCLIContractPayloadStaysOnArgv(t *testing.T) {
	_, onStdin := upsertLine("svc", "acct",
		base64.StdEncoding.EncodeToString(patternBytes(16*1024)))
	if onStdin {
		t.Fatal("the 16 KB contract payload was routed to the stdin line")
	}
}

// keysAroundTheCap pads base until the rendered line stops fitting, and returns
// the last service whose line lands exactly on the cap and the first whose line
// is one byte over. The production renderer decides both, so no arithmetic is
// duplicated here.
func keysAroundTheCap(t *testing.T, base, account, encoded string) (string, string) {
	t.Helper()

	for pad := 0; pad <= securityCLILineMax; pad++ {
		service := base + strings.Repeat("p", pad)

		line, ok := upsertLine(service, account, encoded)
		if ok && len(line) == securityCLILineMax {
			return service, base + strings.Repeat("p", pad+1)
		}

		if !ok {
			t.Fatalf("line jumped past the cap at pad %d without landing on it", pad)
		}
	}

	t.Fatal("no padding put the line on the cap")

	return "", ""
}

// feedInteractive runs one line through `security -i` and reports how many
// fragments the tool rejected as unknown commands, and the status it exited
// with. The count is a proxy for how many commands the read produced and holds
// only while every fragment is nonsense: a real subcommand that fails is not an
// unknown command and does not count.
func feedInteractive(t *testing.T, line string) (int, int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, securityPath, securityInteractive)
	cmd.Stdin = strings.NewReader(line + "\n")

	var stderr strings.Builder

	cmd.Stderr = &stderr

	err := cmd.Run()

	exit := 0

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exit = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("security -i: %v", err)
	}

	return strings.Count(stderr.String(), "unknown command"), exit
}

// TestDarwinCLIQuotedKeyRoundTrip proves the quoting against the tool itself. A
// service or account holding whitespace or a quote is what the interactive
// mode's splitter would otherwise read as further arguments, and a wrong
// escaping fails quietly — the item lands under a name nobody asks for again, so
// the read below would report an absent item rather than a corrupt one.
func TestDarwinCLIQuotedKeyRoundTrip(t *testing.T) {
	kc := New(WithSecurityCLI())
	base := uniqueService(t)

	tests := []struct {
		name    string
		service string
		account string
	}{
		{"space", base + " with space", "acct with space"},
		{"double quote", base + ` with "quotes"`, `acct with "quotes"`},
		{"single quote and backslash", base + ` o'brien\path`, `acct o'brien\path`},
		{"tab", base + "\twith-tab", "acct\twith-tab"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := []byte("value for a quoted key")

			line, onStdin := upsertLine(tt.service, tt.account, base64.StdEncoding.EncodeToString(want))
			if !onStdin {
				t.Fatalf("a short value with this key did not go to stdin")
			}

			if !strings.Contains(line, `"`) {
				t.Fatalf("line %q is not quoted", line)
			}

			t.Cleanup(func() { _ = kc.Delete(tt.service, tt.account) })

			err := kc.Set(tt.service, tt.account, want)
			if err != nil {
				t.Fatalf("Set: %v", err)
			}

			got, err := kc.Get(tt.service, tt.account)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}

			if !bytes.Equal(got, want) {
				t.Fatalf("Get returned %q, want %q", got, want)
			}
		})
	}
}

// rawSecurityValue reads the item with a plain /usr/bin/security run — a
// different code identity than this test binary, and the same command a person
// would type.
func rawSecurityValue(t *testing.T, service, account string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), helperTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, securityPath,
		findGenericPassword, "-s", service, "-a", account, "-w")

	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("security %s: %v (output %q)", findGenericPassword, err, out)
	}

	return strings.TrimRight(string(out), "\n")
}
