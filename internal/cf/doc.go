// Package cf is a minimal, cgo-free CoreFoundation binding for the darwin
// keychain backend. It loads CoreFoundation at runtime through purego (assembly
// trampolines, no import "C"), wraps every CF object create in a
// release-coupled helper so a reference cannot be created without a paired
// release, and hides the pointer-dereference idiom needed to read
// CoreFoundation's const global symbols.
//
// The package is internal to keychain and carries real code only on darwin;
// this file keeps it a valid, buildable package on every other GOOS so a
// cross-compile of the whole module never trips over an all-excluded directory.
package cf
