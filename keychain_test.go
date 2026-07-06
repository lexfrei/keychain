package keychain

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// TestContractAgainstFake runs the full behavioural contract against the
// in-memory fake. It is the platform-agnostic half of the contract; the gated
// integration tests run the same runContract against each real OS store.
func TestContractAgainstFake(t *testing.T) {
	useBackend(t, newFakeBackend())
	runContract(t, "keychain-unit-contract")
}

func TestOptionsApply(t *testing.T) {
	def := newConfig()
	if def.accessMode != TrustAll {
		t.Errorf("default accessMode = %v, want TrustAll", def.accessMode)
	}

	if def.label != "" {
		t.Errorf("default label = %q, want empty", def.label)
	}

	cfg := newConfig(WithAccessMode(TrustCurrentApp), WithLabel("my label"))
	if cfg.accessMode != TrustCurrentApp {
		t.Errorf("accessMode = %v, want TrustCurrentApp", cfg.accessMode)
	}

	if cfg.label != "my label" {
		t.Errorf("label = %q, want %q", cfg.label, "my label")
	}
}

// TestNewInstanceRoundTrip exercises the struct API (New + methods), which the
// package-level functions delegate to.
func TestNewInstanceRoundTrip(t *testing.T) {
	useBackend(t, newFakeBackend())

	kc := New()

	err := kc.Set("svc", "acct", []byte("v"))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := kc.Get("svc", "acct")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if string(got) != "v" {
		t.Fatalf("Get = %q, want v", got)
	}

	err = kc.Delete("svc", "acct")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
}

// TestLoggerSilentByDefault pins the library's contract that it emits nothing
// unless the caller opts in: DiscardHandler reports disabled at every level.
func TestLoggerSilentByDefault(t *testing.T) {
	kc := New()
	if kc.cfg.log().Enabled(context.Background(), slog.LevelError) {
		t.Error("default Keychain is not silent; a library must emit nothing without WithLogger")
	}
}

// TestLoggerInjectedNeverLogsSecret proves two things at once: WithLogger wires
// debug tracing, and the secret value never reaches the log — only its length
// and the lookup key.
func TestLoggerInjectedNeverLogsSecret(t *testing.T) {
	useBackend(t, newFakeBackend())

	var buf bytes.Buffer

	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	kc := New(WithLogger(logger))

	const secret = "TOP-SECRET-DO-NOT-LOG"

	err := kc.Set("svc", "acct", []byte(secret))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	logged := buf.String()
	if !strings.Contains(logged, "keychain: set") {
		t.Errorf("debug log is missing the set line; got %q", logged)
	}

	if strings.Contains(logged, secret) {
		t.Errorf("secret value leaked into the debug log: %q", logged)
	}
}

// TestInvalidKey pins that an empty service or account is rejected before the
// backend is ever consulted — the key is malformed, not merely absent.
func TestInvalidKey(t *testing.T) {
	useBackend(t, newFakeBackend())

	cases := []struct {
		name    string
		service string
		account string
	}{
		{"empty service", "", "acct"},
		{"empty account", "svc", ""},
		{"both empty", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Set(tc.service, tc.account, []byte("x"))
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("Set: got %v, want ErrInvalidKey", err)
			}

			_, err = Get(tc.service, tc.account)
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("Get: got %v, want ErrInvalidKey", err)
			}

			err = Delete(tc.service, tc.account)
			if !errors.Is(err, ErrInvalidKey) {
				t.Errorf("Delete: got %v, want ErrInvalidKey", err)
			}
		})
	}
}

// TestUnsupportedBackend injects the stub explicitly rather than depending on
// the current GOOS, so it stays deterministic on every platform — including one
// whose real backend has already shipped.
func TestUnsupportedBackend(t *testing.T) {
	useBackend(t, unsupportedBackend{})

	err := Set("svc", "acct", []byte("x"))
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("Set: got %v, want ErrUnsupported", err)
	}

	_, err = Get("svc", "acct")
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("Get: got %v, want ErrUnsupported", err)
	}

	err = Delete("svc", "acct")
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("Delete: got %v, want ErrUnsupported", err)
	}
}

// TestConcurrentDistinctKeys drives the public API from many goroutines on
// disjoint keys under -race, guarding both the package lock and the fake.
func TestConcurrentDistinctKeys(t *testing.T) {
	useBackend(t, newFakeBackend())

	const workers = 16

	var wg sync.WaitGroup

	wg.Add(workers)

	for n := range workers {
		go func() {
			defer wg.Done()

			account := fmt.Sprintf("worker-%d", n)
			secret := patternBytes(1024 + n)

			err := Set("concurrent", account, secret)
			if err != nil {
				t.Errorf("worker %d Set: %v", n, err)

				return
			}

			got, err := Get("concurrent", account)
			if err != nil {
				t.Errorf("worker %d Get: %v", n, err)

				return
			}

			if !bytes.Equal(got, secret) {
				t.Errorf("worker %d: secret changed in flight", n)

				return
			}

			err = Delete("concurrent", account)
			if err != nil {
				t.Errorf("worker %d Delete: %v", n, err)
			}
		}()
	}

	wg.Wait()
}
