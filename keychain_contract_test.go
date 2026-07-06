package keychain

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

// fakeBackend is an in-memory backend and the reference implementation of the
// backend contract. The platform-agnostic tests run the same assertions against
// it that the gated integration tests run against each real OS store, so any
// divergence between the fake and a real backend surfaces as a failing contract
// test rather than as a surprise in production.
type fakeBackend struct {
	mu    sync.Mutex
	items map[string][]byte
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{items: make(map[string][]byte)}
}

// fakeKey joins service and account with NUL, which cannot occur in either on
// any real store, so ("a","bc") stays distinct from ("ab","c").
func fakeKey(service, account string) string {
	return service + "\x00" + account
}

func (f *fakeBackend) set(service, account string, secret []byte, _ config) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	stored := make([]byte, len(secret))
	copy(stored, secret)
	f.items[fakeKey(service, account)] = stored

	return nil
}

func (f *fakeBackend) get(service, account string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	stored, ok := f.items[fakeKey(service, account)]
	if !ok {
		return nil, errItemNotFound
	}

	// make(len 0) returns a non-nil slice, so a stored empty secret reads back
	// as non-nil empty — the contract's "present but empty" state.
	out := make([]byte, len(stored))
	copy(out, stored)

	return out, nil
}

func (f *fakeBackend) del(service, account string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	key := fakeKey(service, account)

	_, ok := f.items[key]
	if !ok {
		return errItemNotFound
	}

	delete(f.items, key)

	return nil
}

// useBackend swaps the process backend for the duration of a test and restores
// it afterwards, so a test can inject the fake without touching a real store.
func useBackend(t *testing.T, b backend) {
	t.Helper()

	mu.Lock()
	prev := activeBackend
	activeBackend = b
	mu.Unlock()

	t.Cleanup(func() {
		mu.Lock()
		activeBackend = prev
		mu.Unlock()
	})
}

// patternBytes returns n deterministic bytes — a reproducible stand-in for a
// real secret that fails loudly if a backend truncates or reorders.
func patternBytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*7 + 3) % 251)
	}

	return b
}

// runContract exercises the full behavioural contract through the public API
// against whichever backend is active. It is called by the fake-backed unit
// test and by each gated per-OS integration test, so the contract lives in one
// place. service must be unique to the caller so a real store is not clobbered.
func runContract(t *testing.T, service string) {
	t.Helper()

	t.Run("round trip returns exact bytes", func(t *testing.T) {
		const account = "round-trip"

		t.Cleanup(func() { _ = Delete(service, account) })

		want := []byte("a modest secret value")

		err := Set(service, account, want)
		if err != nil {
			t.Fatalf("Set: %v", err)
		}

		got, err := Get(service, account)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Fatalf("Get returned %q, want %q", got, want)
		}
	})

	t.Run("large payload round trips", func(t *testing.T) {
		const account = "large-payload"

		t.Cleanup(func() { _ = Delete(service, account) })

		// 16 KB is past go-keyring's macOS 4 KB and Windows 2560 B caps: the
		// failure case that motivates this library.
		want := patternBytes(16 * 1024)

		err := Set(service, account, want)
		if err != nil {
			t.Fatalf("Set 16 KB: %v", err)
		}

		got, err := Get(service, account)
		if err != nil {
			t.Fatalf("Get 16 KB: %v", err)
		}

		if !bytes.Equal(got, want) {
			t.Fatalf("16 KB payload changed: got %d bytes, want %d", len(got), len(want))
		}
	})

	t.Run("set is upsert, not duplicate", func(t *testing.T) {
		const account = "upsert"

		t.Cleanup(func() { _ = Delete(service, account) })

		err := Set(service, account, []byte("first"))
		if err != nil {
			t.Fatalf("first Set: %v", err)
		}

		err = Set(service, account, []byte("second"))
		if err != nil {
			t.Fatalf("second Set: %v", err)
		}

		got, err := Get(service, account)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}

		if string(got) != "second" {
			t.Fatalf("upsert kept %q, want the replacement %q", got, "second")
		}

		// A single Delete must fully remove it; if the first Set had left a
		// duplicate item, a stale value would remain readable here.
		err = Delete(service, account)
		if err != nil {
			t.Fatalf("Delete after upsert: %v", err)
		}

		_, err = Get(service, account)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("item still present after upsert+delete, err = %v", err)
		}
	})

	t.Run("get absent is ErrNotFound", func(t *testing.T) {
		_, err := Get(service, "never-written")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("Get absent: got %v, want ErrNotFound", err)
		}
	})

	t.Run("delete is idempotent", func(t *testing.T) {
		const account = "idempotent-delete"

		t.Cleanup(func() { _ = Delete(service, account) })

		err := Delete(service, account)
		if err != nil {
			t.Fatalf("Delete of absent item: got %v, want nil", err)
		}

		err = Set(service, account, []byte("x"))
		if err != nil {
			t.Fatalf("Set: %v", err)
		}

		err = Delete(service, account)
		if err != nil {
			t.Fatalf("first Delete: %v", err)
		}

		err = Delete(service, account)
		if err != nil {
			t.Fatalf("second Delete (idempotent): got %v, want nil", err)
		}
	})

	t.Run("empty secret is allowed and distinct from absent", func(t *testing.T) {
		const account = "empty-secret"

		t.Cleanup(func() { _ = Delete(service, account) })

		err := Set(service, account, []byte{})
		if err != nil {
			t.Fatalf("Set empty: %v", err)
		}

		got, err := Get(service, account)
		if err != nil {
			t.Fatalf("Get empty: got %v, want a stored empty item", err)
		}

		if got == nil {
			t.Fatal("empty secret read back as nil; want a non-nil empty slice")
		}

		if len(got) != 0 {
			t.Fatalf("empty secret read back as %d bytes, want 0", len(got))
		}
	})
}
