//go:build !darwin && !windows && !linux && !freebsd && !openbsd && !netbsd

package keychain

// platformBackend on a platform with no native secret store (js/wasm, plan9,
// and the like) returns the unsupported backend, so every operation reports
// ErrUnsupported rather than failing to compile.
func platformBackend() backend {
	return unsupportedBackend{}
}
