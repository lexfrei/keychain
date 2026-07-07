//go:build darwin

package cf

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unicode/utf8"
	"unsafe"

	"github.com/ebitengine/purego"
)

// Ref is any CoreFoundation object reference. Every CF*Ref and CFTypeRef is a
// pointer-sized handle, so one type covers strings, data, dictionaries, arrays,
// and the Security refs that are themselves CFTypeRefs.
type Ref uintptr

// Sentinels for the resolutions purego reports as a zero result with no error:
// a framework handle or a symbol address that came back null.
var (
	errNullHandle     = errors.New("cf: null framework handle")
	errSymbolNotFound = errors.New("cf: symbol not found")
)

// utf8Encoding is CFStringEncoding kCFStringEncodingUTF8. CoreFoundation exports
// no symbol for it — the value is fixed in the framework's ABI.
const utf8Encoding uint32 = 0x08000100

// allocatorDefault is kCFAllocatorDefault: a NULL allocator tells CoreFoundation
// to use the current default, so it is passed as 0 rather than resolved.
const allocatorDefault Ref = 0

// The resolved CoreFoundation binding: the framework handle, the const globals
// that CFDictionaryCreate and boolean query flags need, and the C function
// pointers. A runtime dynamic-linking shim is inherently process-global.
//
//nolint:gochecknoglobals // resolved-once framework handle, const globals, and C function pointers; a dynamic-linking binding table is package-global by nature.
var (
	loadOnce sync.Once
	errLoad  error

	booleanTrue        Ref
	dictKeyCallBacks   uintptr
	dictValueCallBacks uintptr

	cfRelease               func(ref Ref)
	cfStringCreateWithBytes func(alloc Ref, bytes *byte, length int, encoding uint32, isExternal bool) Ref
	cfStringGetLength       func(str Ref) int
	cfStringGetCString      func(str Ref, buffer *byte, bufferSize int, encoding uint32) bool
	cfDataCreate            func(alloc Ref, bytes *byte, length int) Ref
	cfDataGetBytePtr        func(data Ref) *byte
	cfDataGetLength         func(data Ref) int
	cfDictionaryCreate      func(alloc Ref, keys, values *Ref, count int, keyCB, valueCB uintptr) Ref
	cfArrayGetCount         func(array Ref) int
	cfArrayGetValueAtIndex  func(array Ref, index int) Ref
)

// Load resolves the CoreFoundation framework and its symbols exactly once. It
// is safe to call repeatedly and from any goroutine; every later call returns
// the first attempt's result. secitem calls it before opening Security.
func Load() error {
	loadOnce.Do(load)

	return errLoad
}

func load() {
	handle, err := Open("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
	if err != nil {
		errLoad = err

		return
	}

	errLoad = registerFuncs(handle)
	if errLoad != nil {
		return
	}

	booleanTrue, errLoad = ConstValue(handle, "kCFBooleanTrue")
	if errLoad != nil {
		return
	}

	dictKeyCallBacks, errLoad = symbolAddr(handle, "kCFTypeDictionaryKeyCallBacks")
	if errLoad != nil {
		return
	}

	dictValueCallBacks, errLoad = symbolAddr(handle, "kCFTypeDictionaryValueCallBacks")
}

func registerFuncs(handle uintptr) error {
	funcs := []struct {
		fptr any
		name string
	}{
		{&cfRelease, "CFRelease"},
		{&cfStringCreateWithBytes, "CFStringCreateWithBytes"},
		{&cfStringGetLength, "CFStringGetLength"},
		{&cfStringGetCString, "CFStringGetCString"},
		{&cfDataCreate, "CFDataCreate"},
		{&cfDataGetBytePtr, "CFDataGetBytePtr"},
		{&cfDataGetLength, "CFDataGetLength"},
		{&cfDictionaryCreate, "CFDictionaryCreate"},
		{&cfArrayGetCount, "CFArrayGetCount"},
		{&cfArrayGetValueAtIndex, "CFArrayGetValueAtIndex"},
	}

	for _, reg := range funcs {
		err := Register(reg.fptr, handle, reg.name)
		if err != nil {
			return err
		}
	}

	return nil
}

// Open loads a framework by path with lazy, globally-visible relocation. secitem
// uses it to open Security while reusing this package's symbol helpers.
func Open(path string) (uintptr, error) {
	handle, err := purego.Dlopen(path, purego.RTLD_LAZY|purego.RTLD_GLOBAL)
	if err != nil {
		return 0, fmt.Errorf("cf: load %s: %w", path, err)
	}

	if handle == 0 {
		return 0, fmt.Errorf("cf: load %s: %w", path, errNullHandle)
	}

	return handle, nil
}

// Register binds the C function named name in handle to the Go function pointer
// fptr. It returns an error instead of panicking (as purego.RegisterLibFunc
// would) so a missing symbol can drive a graceful fallback rather than crash.
func Register(fptr any, handle uintptr, name string) error {
	sym, err := purego.Dlsym(handle, name)
	if err != nil {
		return fmt.Errorf("cf: resolve %s: %w", name, err)
	}

	if sym == 0 {
		return fmt.Errorf("cf: resolve %s: %w", name, errSymbolNotFound)
	}

	purego.RegisterFunc(fptr, sym)

	return nil
}

// ConstValue reads a const CFTypeRef global (kCFBooleanTrue, kSecClass, …). Such
// a symbol is itself a pointer variable, so Dlsym returns its address and the
// value must be dereferenced once to get the ref the API expects.
func ConstValue(handle uintptr, name string) (Ref, error) {
	addr, err := symbolAddr(handle, name)
	if err != nil {
		return 0, err
	}

	return Ref(symbolValue(addr)), nil
}

func symbolAddr(handle uintptr, name string) (uintptr, error) {
	addr, err := purego.Dlsym(handle, name)
	if err != nil {
		return 0, fmt.Errorf("cf: resolve %s: %w", name, err)
	}

	if addr == 0 {
		return 0, fmt.Errorf("cf: resolve %s: %w", name, errSymbolNotFound)
	}

	return addr, nil
}

// symbolValue dereferences a symbol address once to read the pointer it holds.
// It casts only a real Go pointer (&addr) to unsafe.Pointer, never a bare
// uintptr, so it stays within vet's unsafeptr rules.
func symbolValue(addr uintptr) uintptr {
	return uintptr(**(**unsafe.Pointer)(unsafe.Pointer(&addr)))
}

// Releaser accounts a +1 CoreFoundation reference and returns a function that
// releases it exactly once. Every CF create or copy — from this package or from
// Security — is paired with a Releaser so the cfdebug leak counter stays
// balanced and no reference is released twice.
func Releaser(ref Ref) func() {
	onCreate()

	var once sync.Once

	return func() {
		once.Do(func() {
			if ref != 0 {
				cfRelease(ref)
			}

			onRelease()
		})
	}
}

// NewString copies str into a CFString. An explicit byte length is used, not a C
// string, so a service or account containing an interior NUL is preserved rather
// than truncated at the first NUL.
func NewString(str string) (Ref, func()) {
	data := []byte(str)

	var ptr *byte
	if len(data) > 0 {
		ptr = &data[0]
	}

	ref := cfStringCreateWithBytes(allocatorDefault, ptr, len(data), utf8Encoding, false)
	runtime.KeepAlive(data)

	return ref, Releaser(ref)
}

// NewData copies bytes into a CFData. A zero-length secret yields a valid empty
// CFData (NULL pointer, length 0) — that is how "present but empty" is stored,
// distinct from an absent item.
func NewData(raw []byte) (Ref, func()) {
	var ptr *byte
	if len(raw) > 0 {
		ptr = &raw[0]
	}

	ref := cfDataCreate(allocatorDefault, ptr, len(raw))
	runtime.KeepAlive(raw)

	return ref, Releaser(ref)
}

// NewDict builds an immutable CFDictionary from paired keys and values. The
// dictionary retains each key and value, so the caller still releases its own
// references afterward. keys and values must have equal length.
func NewDict(keys, values []Ref) (Ref, func()) {
	count := len(keys)

	var keyPtr, valuePtr *Ref
	if count > 0 {
		keyPtr = &keys[0]
		valuePtr = &values[0]
	}

	ref := cfDictionaryCreate(allocatorDefault, keyPtr, valuePtr, count, dictKeyCallBacks, dictValueCallBacks)

	// keyPtr and valuePtr point into the keys and values backing arrays; keep
	// both arrays reachable until the create call that reads through those
	// pointers has returned.
	runtime.KeepAlive(keys)
	runtime.KeepAlive(values)

	return ref, Releaser(ref)
}

// DataToBytes copies a CFData's contents into a fresh, GC-managed slice. The
// copy happens before the CFData is released because CFDataGetBytePtr returns a
// pointer into CoreFoundation-owned memory the copy must not outlive. An empty
// CFData yields a non-nil, zero-length slice so it stays distinct from absent.
func DataToBytes(data Ref) []byte {
	length := cfDataGetLength(data)
	out := make([]byte, length)

	if length > 0 {
		copy(out, unsafe.Slice(cfDataGetBytePtr(data), length))
	}

	return out
}

// Len reports the number of elements in a CFArray.
func Len(array Ref) int { return cfArrayGetCount(array) }

// At returns the element at index. The element is borrowed — CoreFoundation does
// not retain it for the caller — so it must not be released and must be copied
// out before the array is released.
func At(array Ref, index int) Ref { return cfArrayGetValueAtIndex(array, index) }

// BooleanTrue is kCFBooleanTrue, the CFDictionary value for boolean query flags
// such as kSecReturnData.
func BooleanTrue() Ref { return booleanTrue }

// GoString copies a CFString into a Go string through a UTF-8 buffer. It returns
// "" when the string is empty or the conversion fails, which is acceptable for
// its only use — turning a Security OSStatus into a human-readable message.
func GoString(str Ref) string {
	length := cfStringGetLength(str)
	if length == 0 {
		return ""
	}

	// UTF-8 needs at most utf8.UTFMax bytes per UTF-16 unit, plus a NUL slot.
	buffer := make([]byte, length*utf8.UTFMax+1)
	if !cfStringGetCString(str, &buffer[0], len(buffer), utf8Encoding) {
		return ""
	}

	end := bytes.IndexByte(buffer, 0)
	if end < 0 {
		end = len(buffer)
	}

	return string(buffer[:end])
}
