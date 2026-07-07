package chunk

import (
	"bytes"
	"errors"
	"testing"
)

// fakeStore is an in-memory Store. Tests reach into its map directly to simulate
// a torn write (a chunk that went missing between the chunk writes and the
// header commit).
type fakeStore struct {
	items map[string][]byte
}

func newFakeStore() *fakeStore {
	return &fakeStore{items: make(map[string][]byte)}
}

func (f *fakeStore) Get(target string) ([]byte, error) {
	blob, ok := f.items[target]
	if !ok {
		return nil, ErrMissing
	}

	out := make([]byte, len(blob))
	copy(out, blob)

	return out, nil
}

func (f *fakeStore) Set(target string, blob []byte) error {
	stored := make([]byte, len(blob))
	copy(stored, blob)
	f.items[target] = stored

	return nil
}

func (f *fakeStore) Delete(target string) error {
	_, ok := f.items[target]
	if !ok {
		return ErrMissing
	}

	delete(f.items, target)

	return nil
}

// seq returns n deterministic bytes that fail loudly if a chunk is reordered,
// truncated, or dropped.
func seq(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*7 + 3) % 251)
	}

	return out
}

// TestRoundTrip covers the 0-byte, sub-chunk, exact-boundary, and multi-chunk
// cases with a small blob cap, and pins that an empty secret reads back non-nil.
func TestRoundTrip(t *testing.T) {
	const blob = 8

	sizes := []int{0, 1, blob - 1, blob, blob + 1, 3 * blob, 3*blob + 1, 100}

	for _, size := range sizes {
		chunker := Chunker{Store: newFakeStore(), MaxBlob: blob}
		want := seq(size)

		err := chunker.Set("svc", "acct", want)
		if err != nil {
			t.Fatalf("size %d: Set: %v", size, err)
		}

		got, err := chunker.Get("svc", "acct")
		if err != nil {
			t.Fatalf("size %d: Get: %v", size, err)
		}

		if got == nil {
			t.Fatalf("size %d: Get returned nil, want a non-nil slice", size)
		}

		if !bytes.Equal(got, want) {
			t.Fatalf("size %d: round trip changed the bytes", size)
		}
	}
}

func TestGetAbsent(t *testing.T) {
	chunker := Chunker{Store: newFakeStore(), MaxBlob: 8}

	_, err := chunker.Get("svc", "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get absent: got %v, want ErrNotFound", err)
	}
}

// TestUpsertShrink pins the commit protocol's tail cleanup: replacing a
// five-chunk value with a one-chunk value leaves exactly the header and one
// chunk, no stale tail.
func TestUpsertShrink(t *testing.T) {
	const blob = 8

	store := newFakeStore()
	chunker := Chunker{Store: store, MaxBlob: blob}

	err := chunker.Set("svc", "acct", seq(5*blob))
	if err != nil {
		t.Fatalf("Set large: %v", err)
	}

	small := seq(5)

	err = chunker.Set("svc", "acct", small)
	if err != nil {
		t.Fatalf("Set small: %v", err)
	}

	got, err := chunker.Get("svc", "acct")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if !bytes.Equal(got, small) {
		t.Fatalf("after shrink Get returned %d bytes, want %d", len(got), len(small))
	}

	// One header + one chunk; the four stale chunks must be gone.
	if len(store.items) != 2 {
		t.Fatalf("store holds %d targets after shrink, want 2 (header + 1 chunk)", len(store.items))
	}
}

// TestTornWriteMissingChunk pins that a header referencing a vanished chunk reads
// as ErrNotFound, never as a truncated secret.
func TestTornWriteMissingChunk(t *testing.T) {
	const blob = 8

	store := newFakeStore()
	chunker := Chunker{Store: store, MaxBlob: blob}

	err := chunker.Set("svc", "acct", seq(3*blob))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	delete(store.items, chunkTarget("svc", "acct", 1))

	_, err = chunker.Get("svc", "acct")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get with a missing chunk: got %v, want ErrNotFound", err)
	}
}

// TestTornWriteShortChunk pins that a chunk shorter than the header's total
// length is rejected as ErrNotFound.
func TestTornWriteShortChunk(t *testing.T) {
	const blob = 8

	store := newFakeStore()
	chunker := Chunker{Store: store, MaxBlob: blob}

	err := chunker.Set("svc", "acct", seq(3*blob))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	store.items[chunkTarget("svc", "acct", 0)] = []byte("short")

	_, err = chunker.Get("svc", "acct")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get with a short chunk: got %v, want ErrNotFound", err)
	}
}

func TestDeleteRemovesEverything(t *testing.T) {
	const blob = 8

	store := newFakeStore()
	chunker := Chunker{Store: store, MaxBlob: blob}

	err := chunker.Set("svc", "acct", seq(3*blob))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	err = chunker.Delete("svc", "acct")
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if len(store.items) != 0 {
		t.Fatalf("store holds %d targets after Delete, want 0", len(store.items))
	}

	_, err = chunker.Get("svc", "acct")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete: got %v, want ErrNotFound", err)
	}
}

func TestDeleteAbsent(t *testing.T) {
	chunker := Chunker{Store: newFakeStore(), MaxBlob: 8}

	err := chunker.Delete("svc", "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete absent: got %v, want ErrNotFound", err)
	}
}

// TestKeyCollisionFree pins that the length-prefixed key encoding keeps ("a/b",
// "c") and ("a", "b/c") — which naive "/" joining would merge — in separate
// namespaces, and that a chunk target never collides with another item's header.
func TestKeyCollisionFree(t *testing.T) {
	if headerTarget("a/b", "c") == headerTarget("a", "b/c") {
		t.Fatal(`headerTarget("a/b","c") collides with headerTarget("a","b/c")`)
	}

	store := newFakeStore()
	chunker := Chunker{Store: store, MaxBlob: 8}

	first := []byte("first value")
	second := []byte("second value")

	err := chunker.Set("a/b", "c", first)
	if err != nil {
		t.Fatalf("Set first: %v", err)
	}

	err = chunker.Set("a", "b/c", second)
	if err != nil {
		t.Fatalf("Set second: %v", err)
	}

	got, err := chunker.Get("a/b", "c")
	if err != nil {
		t.Fatalf("Get first: %v", err)
	}

	if !bytes.Equal(got, first) {
		t.Fatalf(`("a/b","c") read back %q, want %q — a key collision`, got, first)
	}
}

func TestSplitBoundaries(t *testing.T) {
	const blob = 8

	cases := map[int]int{0: 0, 1: 1, blob: 1, blob + 1: 2, 3 * blob: 3, 3*blob + 1: 4}

	for size, wantChunks := range cases {
		chunks := split(seq(size), blob)
		if len(chunks) != wantChunks {
			t.Errorf("split(%d bytes) into %d chunks, want %d", size, len(chunks), wantChunks)
		}

		total := 0
		for _, chunk := range chunks {
			if len(chunk) > blob {
				t.Errorf("split(%d): a chunk is %d bytes, over the %d cap", size, len(chunk), blob)
			}

			total += len(chunk)
		}

		if total != size {
			t.Errorf("split(%d): chunks total %d bytes", size, total)
		}
	}
}

// TestDefaultBlobCap pins that a zero MaxBlob falls back to DefaultMaxBlob rather
// than dividing by zero or making a chunk per byte.
func TestDefaultBlobCap(t *testing.T) {
	store := newFakeStore()
	chunker := Chunker{Store: store} // MaxBlob 0 → DefaultMaxBlob

	err := chunker.Set("svc", "acct", seq(DefaultMaxBlob+1))
	if err != nil {
		t.Fatalf("Set: %v", err)
	}

	// header + two chunks (DefaultMaxBlob + 1 byte).
	if len(store.items) != 3 {
		t.Fatalf("store holds %d targets, want 3 (header + 2 chunks)", len(store.items))
	}
}
