package chunk

import (
	"bytes"
	"testing"
)

// FuzzRoundTrip drives arbitrary payloads through Set then Get across a range of
// blob caps, asserting a byte-exact round trip. It hardens the header encode/
// decode, the split/join boundary math, and the total-length check against
// inputs the hand-written cases do not enumerate — an off-by-one in an offset or
// a boundary would surface as a changed or lost payload.
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte{}, uint8(1))
	f.Add([]byte("x"), uint8(1))
	f.Add([]byte("a modest secret"), uint8(4))
	f.Add(bytes.Repeat([]byte{0x00}, 100), uint8(8))
	f.Add(seq(1000), uint8(7))
	f.Add(seq(255), uint8(255))

	f.Fuzz(func(t *testing.T, secret []byte, blob uint8) {
		// Bound the chunk count so a pathological (tiny cap, large payload) input
		// cannot blow up the in-memory store; size beyond this is unit-tested.
		if len(secret) > 8*1024 {
			return
		}

		maxBlob := int(blob)
		if maxBlob == 0 {
			maxBlob = 1
		}

		chunker := Chunker{Store: newFakeStore(), MaxBlob: maxBlob}

		err := chunker.Set("svc", "acct", secret)
		if err != nil {
			t.Fatalf("Set (%d bytes, cap %d): %v", len(secret), maxBlob, err)
		}

		got, err := chunker.Get("svc", "acct")
		if err != nil {
			t.Fatalf("Get (%d bytes, cap %d): %v", len(secret), maxBlob, err)
		}

		if got == nil {
			t.Fatalf("Get returned nil for a %d-byte secret", len(secret))
		}

		if !bytes.Equal(got, secret) {
			t.Fatalf("round trip changed the bytes: got %d, want %d (cap %d)", len(got), len(secret), maxBlob)
		}

		// Upsert to a shorter value over the same store to exercise the shrink
		// path (deleteTail): the replacement, not a stale chunk tail, must read.
		shrunk := secret[:len(secret)/2]

		err = chunker.Set("svc", "acct", shrunk)
		if err != nil {
			t.Fatalf("upsert Set (%d bytes, cap %d): %v", len(shrunk), maxBlob, err)
		}

		after, err := chunker.Get("svc", "acct")
		if err != nil {
			t.Fatalf("upsert Get (cap %d): %v", maxBlob, err)
		}

		if !bytes.Equal(after, shrunk) {
			t.Fatalf("upsert-shrink changed the bytes: got %d, want %d (cap %d)", len(after), len(shrunk), maxBlob)
		}
	})
}

// FuzzGetCorrupt puts arbitrary bytes at the header and first-chunk targets and
// calls Get. A secret store must never panic on a tampered or truncated blob: it
// must return the value or ErrNotFound (corrupt reads as absent), and a nil error
// must come with a non-nil slice. The fuzzer flags any panic automatically.
func FuzzGetCorrupt(f *testing.F) {
	f.Add([]byte("KCC1"), []byte("payload"), uint8(4))
	f.Add([]byte{}, []byte{}, uint8(1))
	f.Add([]byte("KCC1\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x07"), []byte("payload"), uint8(8))

	f.Fuzz(func(t *testing.T, header, chunk0 []byte, blob uint8) {
		if len(header) > 4*1024 || len(chunk0) > 4*1024 {
			return
		}

		store := newFakeStore()
		store.items[headerTarget("svc", "acct")] = header
		store.items[chunkTarget("svc", "acct", 0)] = chunk0

		maxBlob := int(blob)
		if maxBlob == 0 {
			maxBlob = 1
		}

		got, err := Chunker{Store: store, MaxBlob: maxBlob}.Get("svc", "acct")

		if err == nil && got == nil {
			t.Fatal("Get returned a nil error with a nil slice")
		}
	})
}
