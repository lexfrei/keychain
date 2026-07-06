package keychain

import (
	"bytes"
	"errors"
	"fmt"
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
