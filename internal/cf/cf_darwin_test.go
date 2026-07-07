//go:build darwin

package cf

import (
	"bytes"
	"testing"
)

// TestDataRoundTrip exercises the CFData FFI signatures without touching the
// keychain: bytes copied into a CFData and read back out must be byte-for-byte
// identical at any size, and an empty input must survive as a non-nil,
// zero-length slice (the "present but empty" state the backend relies on). A
// wrong CFDataCreate / CFDataGetBytePtr / CFDataGetLength binding fails here,
// well before the gated integration suite ever reaches a real store.
func TestDataRoundTrip(t *testing.T) {
	err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	cases := map[string][]byte{
		"empty":  {},
		"one":    []byte("x"),
		"small":  []byte("a modest secret value"),
		"binary": {0x00, 0xff, 0x00, 0x7f, 0x80},
		"large":  bytes.Repeat([]byte{0xa5}, 16*1024),
	}

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			data, release := NewData(want)
			defer release()

			got := DataToBytes(data)
			if got == nil {
				t.Fatal("DataToBytes returned nil; want a non-nil slice")
			}

			if !bytes.Equal(got, want) {
				t.Fatalf("round trip changed the bytes: got %d, want %d", len(got), len(want))
			}
		})
	}
}

// TestNewDictBuilds proves a dictionary can be built from CF keys and values
// without a crash and yields a non-zero ref — enough to catch a broken
// CFDictionaryCreate signature or a bad callbacks-struct address.
func TestNewDictBuilds(t *testing.T) {
	err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	key, releaseKey := NewString("service")
	defer releaseKey()

	value, releaseValue := NewData([]byte("secret"))
	defer releaseValue()

	dict, releaseDict := NewDict([]Ref{key}, []Ref{value})
	defer releaseDict()

	if dict == 0 {
		t.Fatal("NewDict returned a null dictionary")
	}
}
