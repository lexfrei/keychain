# CLAUDE.md — keychain

Project guidance for this repository. Inherits every rule from the global `~/CLAUDE.md` (git workflow, commit format, public-communication language, etc.); the points below are what is specific to this library. When they conflict with a general habit, these win.

## Working principle

Always act correctly, completely, and without cutting corners ("правильно, полно и не срезая углы"). No stubbed-out happy paths passed off as done, no silently narrowed scope, no test weakened to make a build pass. If the correct thing is bigger than expected, do the correct thing — or stop and say why, never quietly ship the shortcut.

## Hard invariant: maximally pure Go

- No cgo, ever, on any platform. `CGO_ENABLED=0` is the permanent build mode; `import "C"` is forbidden. CI cross-compiles every GOOS with cgo disabled to enforce this.
- Dependency ceiling is two, both pure Go and each imported only under its own GOOS build tag: `github.com/ebitengine/purego` (darwin) and `github.com/godbus/dbus/v5` (linux/\*bsd). macOS, Windows, and all core/chunk logic are standard-library only — Windows Credential Manager is reached through inlined `syscall.NewLazyDLL("advapi32.dll")` calls, not `x/sys`, not a third-party wrapper.
- Adding a third dependency requires a written justification in the PR that opens it. purego is unavoidable (the only pure-Go way to call Security.framework); godbus is kept rather than hand-rolling the D-Bus wire protocol. Everything else we inline.

## TDD and tests as contract

- Test first. Write the failing test, watch it fail for the right reason, then implement. This holds for the pure logic (`internal/chunk`, option and error handling) and for each backend's behaviour.
- Tests are the second documentation and the contract — they describe how the library must and must NOT behave, not a happy-path demo. Assert error paths, edge cases, and the invariants below; a test that only proves the sunny case is not done.
- One behavioural contract, run everywhere: the same assertions run against an in-memory fake backend (every platform, unit CI) and against each real OS store (gated integration CI). Changing behaviour starts by changing that contract.

The contract every backend upholds:

- `Set` is upsert — a second `Set` on the same `service`+`account` replaces, never duplicates or errors.
- `Get` returns the exact bytes stored, byte-for-byte, at any size (the 16 KB payload is the go-keyring failure case and the reason this library exists).
- `Get` on an absent item returns `ErrNotFound` — never a zero value with a nil error, never a different error type.
- `Delete` is idempotent — removing an absent item returns nil.
- Empty `service` or empty `account` is `ErrInvalidKey`. Empty `secret` is allowed and is distinct from absent (`Get` returns an empty, non-nil slice).
- A separate process reads what another wrote, with no prompt (the headless-daemon guarantee, exercised cross-process).

## Linting is a ratchet

Never disable a linter or loosen a rule to make code pass — fix the code instead. The config only tightens over time; a stricter threshold or a newly enabled linter is always welcome, a relaxation needs a written, rule-specific justification in the PR that does it. Inline suppressions are a last resort and must be specific and explained (`//nolint:thelinter // why`, which `nolintlint` already enforces); prefer removing the need for the suppression over adding one. "The linter is annoying" is not a reason — the linter is the floor, and we raise it.

## No-slop comments

Comments follow noslopgrenade.com: a comment earns its place by explaining the non-obvious WHY — a platform quirk, a memory rule, a protocol invariant — never by restating the code. Human-length, no throat-clearing, no scaffolding heavier than the content. Same bar for godoc and test names.

- Good: `// trustedApplications == NULL ⇒ the ACL allows ALL apps of this user`
- Bad: `// set the service attribute`

## CoreFoundation memory discipline (darwin)

Create/Copy returns a +1 reference — the caller releases it. Wrap every CF create in a helper returning `(ref, release)` and `defer release()`. Elements borrowed out of a CFArray/CFDictionary are not retained; copy them before the container is released. The `keychain_cfdebug` build tag counts create vs release to catch leaks.

## Backend contract

- Each backend implements the unexported `backend` interface and hides its own platform quirk internally. Windows chunking lives in the Windows backend; macOS and Linux items stay a single, inspectable, raw entry with no shared chunking layer.
- Each backend maps its native not-found (`errSecItemNotFound`, an empty D-Bus search, `ERROR_NOT_FOUND`) to the internal `errItemNotFound`, which the public functions map to the exported `ErrNotFound`.

## CI and merge gate

- CI (GitHub Actions) runs: lint, cross-compile of every GOOS with `CGO_ENABLED=0`, unit tests on ubuntu/macos/windows, and per-OS gated integration tests. Integration tests are opt-in via `-tags keychain_integration` so a plain `go test` never touches a real store.
- Merge gate (from the first backend PR onward): no PR merges without two independent LGTM reviews, one Codex review, all CI green, and explicit maintainer approval. Repository bootstrap (the initial scaffolding) was committed directly to master; everything after is branch + PR.
