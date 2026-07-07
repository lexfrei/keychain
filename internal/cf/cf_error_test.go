//go:build darwin

package cf

import "testing"

const coreFoundationPath = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

// TestOpenBadPath exercises the dlopen failure branch with a real, failing load
// — no mock — so the error path that drives ErrUnavailable is covered.
func TestOpenBadPath(t *testing.T) {
	_, err := Open("/System/Library/Frameworks/DefinitelyNotAFramework.framework/Nope")
	if err == nil {
		t.Fatal("Open of a nonexistent framework should return an error")
	}
}

// TestRegisterMissingSymbol exercises the dlsym failure branch: CoreFoundation
// loads, but the requested symbol does not exist.
func TestRegisterMissingSymbol(t *testing.T) {
	handle, err := Open(coreFoundationPath)
	if err != nil {
		t.Fatalf("Open CoreFoundation: %v", err)
	}

	var fn func()

	err = Register(&fn, handle, "KeychainNoSuchSymbol12345")
	if err == nil {
		t.Fatal("Register of a missing symbol should return an error")
	}
}

// TestConstValueMissingSymbol exercises the same failure through the const-global
// resolution path.
func TestConstValueMissingSymbol(t *testing.T) {
	handle, err := Open(coreFoundationPath)
	if err != nil {
		t.Fatalf("Open CoreFoundation: %v", err)
	}

	_, err = ConstValue(handle, "KeychainNoSuchConstant12345")
	if err == nil {
		t.Fatal("ConstValue of a missing symbol should return an error")
	}
}
