// Package chunk stores an arbitrary-size secret across several fixed-capacity
// credential blobs, hiding the Windows Credential Manager per-blob byte cap
// behind a header-plus-chunks layout. It is pure and store-agnostic — the caller
// injects a Store — so the split/join, the commit protocol, and the shrink
// cleanup are unit-tested on any OS without a real credential store.
//
// Layout: a header blob under the base target records the chunk count and the
// total length; the payload lives in chunk blobs beside it. The header is
// written last, so it is the commit point — a crash before it leaves orphaned
// chunks that no header references, and a header pointing at a missing or short
// chunk reads back as "not found" rather than as a truncated secret.
package chunk

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// DefaultMaxBlob is the Windows Credential Manager CRED_MAX_CREDENTIAL_BLOB_SIZE:
// the most bytes a single credential blob can hold.
const DefaultMaxBlob = 2560

// ErrMissing is what a Store's Get and Delete return for an absent target.
var ErrMissing = errors.New("chunk: target not found")

// ErrNotFound is returned by Get and Delete when no intact chunked item exists:
// an absent header, or a header that references a missing or short chunk.
var ErrNotFound = errors.New("chunk: item not found")

// Store is the per-target blob store the chunker drives. A target is an opaque
// key; Get and Delete report an absent target with ErrMissing.
type Store interface {
	Get(target string) ([]byte, error)
	Set(target string, blob []byte) error
	Delete(target string) error
}

// Chunker splits secrets across a Store's blobs. MaxBlob is the per-blob byte cap
// (DefaultMaxBlob when zero); tests set a small value to exercise the boundaries.
type Chunker struct {
	Store   Store
	MaxBlob int
}

// Header binary layout: a 4-byte magic, a 1-byte version, a big-endian uint32
// chunk count, and a big-endian uint64 total length. Named offsets keep the
// slice math free of bare numbers.
const (
	headerMagic   = "KCC1"
	headerVersion = 1

	offVersion = 4
	offCount   = 5
	offTotal   = 9
	headerLen  = 17
)

// Set writes secret as chunk blobs followed by the committing header, then
// removes any chunk tail left over from a larger previous value.
func (c Chunker) Set(service, account string, secret []byte) error {
	chunks := split(secret, c.blobCap())

	oldCount, err := c.priorChunkCount(service, account)
	if err != nil {
		return err
	}

	for i, data := range chunks {
		target := chunkTarget(service, account, i)

		err = c.Store.Set(target, data)
		if err != nil {
			return storeErr("write", target, err)
		}
	}

	//nolint:gosec // G115: counts and lengths come from len() (non-negative); a secret large enough to overflow a uint32 chunk count (~10 TB at 2560 B) is unreachable.
	header := encodeHeader(uint32(len(chunks)), uint64(len(secret)))

	target := headerTarget(service, account)

	err = c.Store.Set(target, header)
	if err != nil {
		return storeErr("write", target, err)
	}

	return c.deleteTail(service, account, len(chunks), oldCount)
}

// Get reassembles the secret, returning ErrNotFound if the header is absent or
// references a chunk that is missing or shorter than the header promises.
func (c Chunker) Get(service, account string) ([]byte, error) {
	count, totalLen, err := c.readHeader(service, account)
	if err != nil {
		return nil, err
	}

	secret := []byte{}

	for i := range count {
		target := chunkTarget(service, account, i)

		data, getErr := c.Store.Get(target)
		if errors.Is(getErr, ErrMissing) {
			return nil, ErrNotFound
		}

		if getErr != nil {
			return nil, storeErr("read", target, getErr)
		}

		secret = append(secret, data...)
	}

	if uint64(len(secret)) != totalLen {
		return nil, ErrNotFound
	}

	return secret, nil
}

// Delete removes the chunks and then the header. An absent item is ErrNotFound,
// which the caller maps to a no-op so Delete stays idempotent.
func (c Chunker) Delete(service, account string) error {
	count, _, err := c.readHeader(service, account)
	if err != nil {
		return err
	}

	for i := range count {
		err = c.deleteTarget(chunkTarget(service, account, i))
		if err != nil {
			return err
		}
	}

	return c.deleteTarget(headerTarget(service, account))
}

func (c Chunker) blobCap() int {
	if c.MaxBlob > 0 {
		return c.MaxBlob
	}

	return DefaultMaxBlob
}

// readHeader loads and decodes the header, mapping absent or corrupt to
// ErrNotFound so a torn write never surfaces as a partial secret.
func (c Chunker) readHeader(service, account string) (int, uint64, error) {
	target := headerTarget(service, account)

	blob, err := c.Store.Get(target)
	if errors.Is(err, ErrMissing) {
		return 0, 0, ErrNotFound
	}

	if err != nil {
		return 0, 0, storeErr("read", target, err)
	}

	count, total, decErr := decodeHeader(blob)
	if decErr != nil {
		return 0, 0, ErrNotFound
	}

	return int(count), total, nil
}

// priorChunkCount reports how many chunks the existing value occupies, or zero
// if there is none or its header is unreadable (best-effort tail cleanup).
func (c Chunker) priorChunkCount(service, account string) (int, error) {
	target := headerTarget(service, account)

	blob, err := c.Store.Get(target)
	if errors.Is(err, ErrMissing) {
		return 0, nil
	}

	if err != nil {
		return 0, storeErr("read", target, err)
	}

	count, _, decErr := decodeHeader(blob)
	if decErr != nil {
		//nolint:nilerr // a corrupt existing header yields no trustworthy prior count; fall back to zero for best-effort tail cleanup, not an error.
		return 0, nil
	}

	return int(count), nil
}

func (c Chunker) deleteTail(service, account string, newCount, oldCount int) error {
	for i := newCount; i < oldCount; i++ {
		err := c.deleteTarget(chunkTarget(service, account, i))
		if err != nil {
			return err
		}
	}

	return nil
}

func (c Chunker) deleteTarget(target string) error {
	err := c.Store.Delete(target)
	if err != nil && !errors.Is(err, ErrMissing) {
		return storeErr("delete", target, err)
	}

	return nil
}

func split(secret []byte, maxBlob int) [][]byte {
	if len(secret) == 0 {
		return nil
	}

	chunks := make([][]byte, 0, (len(secret)+maxBlob-1)/maxBlob)
	for start := 0; start < len(secret); start += maxBlob {
		end := min(start+maxBlob, len(secret))
		chunks = append(chunks, secret[start:end])
	}

	return chunks
}

func encodeHeader(chunkCount uint32, totalLen uint64) []byte {
	buf := make([]byte, headerLen)
	copy(buf[0:offVersion], headerMagic)
	buf[offVersion] = headerVersion
	binary.BigEndian.PutUint32(buf[offCount:offTotal], chunkCount)
	binary.BigEndian.PutUint64(buf[offTotal:headerLen], totalLen)

	return buf
}

func decodeHeader(blob []byte) (uint32, uint64, error) {
	if len(blob) != headerLen || string(blob[0:offVersion]) != headerMagic || blob[offVersion] != headerVersion {
		return 0, 0, ErrNotFound
	}

	return binary.BigEndian.Uint32(blob[offCount:offTotal]), binary.BigEndian.Uint64(blob[offTotal:headerLen]), nil
}

// encodeKey injectively encodes service and account into one string by
// length-prefixing each, so distinct pairs never collide (e.g. "a/b"+"c" versus
// "a"+"b/c"). The result is never parsed back — it is only a unique map key.
func encodeKey(service, account string) string {
	return strconv.Itoa(len(service)) + ":" + service + ":" + strconv.Itoa(len(account)) + ":" + account
}

func headerTarget(service, account string) string {
	return "kc1:h:" + encodeKey(service, account)
}

func chunkTarget(service, account string, index int) string {
	return "kc1:c" + strconv.Itoa(index) + ":" + encodeKey(service, account)
}

func storeErr(op, target string, err error) error {
	return fmt.Errorf("chunk: %s %q: %w", op, target, err)
}
