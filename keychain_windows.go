//go:build windows

package keychain

// windows reports ErrUnsupported until the advapi32 Credential Manager backend
// (transparent chunking past the 2560-byte blob cap) lands. The stub keeps the
// package building and the contract tests running on Windows CI meanwhile.
func platformBackend() backend {
	return unsupportedBackend{}
}
