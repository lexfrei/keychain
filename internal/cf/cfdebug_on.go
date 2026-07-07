//go:build darwin && keychain_cfdebug

package cf

import "sync/atomic"

// The cfdebug leak counters exist only under this diagnostic build tag; they are
// process-wide by design.
//
//nolint:gochecknoglobals // diagnostic-only leak counters, present solely under the keychain_cfdebug build tag.
var (
	created  atomic.Int64
	released atomic.Int64
)

func onCreate()  { created.Add(1) }
func onRelease() { released.Add(1) }

// LeakCount reports outstanding CoreFoundation references — creates minus
// releases. A balanced Set/Get/Delete cycle must leave it at zero; a positive
// value means a create wrapper's release was skipped, a leak GC cannot catch.
// Built only under the keychain_cfdebug tag.
func LeakCount() int64 { return created.Load() - released.Load() }
