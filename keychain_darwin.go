//go:build darwin

package keychain

// darwin reports ErrUnsupported until the purego Security.framework backend
// (trust-all ACL, no size limit) lands. Keeping the stub lets the package build
// and the platform-agnostic contract tests run on macOS CI in the meantime.
func platformBackend() backend {
	return unsupportedBackend{}
}
