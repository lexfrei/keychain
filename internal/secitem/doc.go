// Package secitem is the cgo-free Security.framework binding for the darwin
// keychain backend. It resolves the SecItem CRUD calls, the kSec* attribute
// constants, and the SecAccess/SecACL calls that build the trust-all ACL, all
// through purego over the CoreFoundation primitives in the sibling cf package.
//
// The trust-all ACL (SecAccessCreate with a NULL trusted-application list on the
// decrypt authorization) reproduces `security add-generic-password -A`: any
// process of the same user reads the item without a prompt, and a rebuilt binary
// keeps access. Those SecAccess/SecACL calls are deprecated but not removed and
// still operate on the legacy login keychain; if a future OS drops them, Load
// records the loss and TrustAllAccess reports it so the backend can fall back.
//
// The package is internal to keychain and carries real code only on darwin; this
// file keeps it a valid, buildable package on every other GOOS.
package secitem
