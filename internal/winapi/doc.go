// Package winapi is a dependency-free Windows Credential Manager binding: inline
// advapi32 CredWriteW/CredReadW/CredDeleteW/CredFree calls through the standard
// library's syscall package, with no golang.org/x/sys and no third-party
// wrapper. It exposes a flat per-target blob store (Write/Read/Delete) that the
// Windows backend drives through the chunk container.
//
// The package carries real code only on Windows; this file keeps it a valid,
// buildable package on every other GOOS so a cross-compile of the whole module
// never trips over an all-excluded directory.
package winapi
