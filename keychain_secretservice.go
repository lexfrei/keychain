//go:build linux || freebsd || openbsd || netbsd || dragonfly

// This file is deliberately not named keychain_linux.go: a _linux.go suffix is
// an implicit GOOS=linux constraint that would AND with the build tag below and
// silently drop the BSDs. A neutral name lets the one Secret Service backend
// cover every org.freedesktop.secrets platform.

package keychain

// Until the godbus Secret Service backend lands, these platforms report
// ErrUnsupported so the package builds and the contract tests run.
func platformBackend() backend {
	return unsupportedBackend{}
}
