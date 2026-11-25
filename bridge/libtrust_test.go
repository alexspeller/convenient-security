package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The pinned library must satisfy the AgileBits requirement as installed. This
// also guards against 1Password moving or renaming it in a future release.
func TestCanonicalLibIsSignedByAgileBits(t *testing.T) {
	if _, err := os.Stat(canonicalLibPath); err != nil {
		t.Skip("1Password desktop app is not installed")
	}
	if err := verifyCanonicalLib(); err != nil {
		t.Fatalf("pinned 1Password library failed verification: %v", err)
	}
}

// A modified copy must fail: this is the check that stands in for the loader's
// library validation, which this process disables in order to load the library
// at all.
func TestTamperedLibraryIsRejected(t *testing.T) {
	original, err := os.ReadFile(canonicalLibPath)
	if err != nil {
		t.Skip("1Password desktop app is not installed")
	}
	tampered := filepath.Join(t.TempDir(), "libop_sdk_ipc_client.dylib")
	// Flip a byte well inside the __TEXT segment so the signature no longer
	// matches the contents.
	modified := make([]byte, len(original))
	copy(modified, original)
	modified[len(modified)/2] ^= 0xFF
	if err := os.WriteFile(tampered, modified, 0o755); err != nil {
		t.Fatalf("writing tampered copy: %v", err)
	}
	if err := verifySignature(tampered, onePasswordRequirement); err == nil {
		t.Fatal("expected a tampered library to fail verification")
	}
}

// A binary signed by anyone other than AgileBits must fail, so the requirement
// is really pinning the team and not merely asking for "some valid signature".
func TestForeignlySignedLibraryIsRejected(t *testing.T) {
	// The Go toolchain ad-hoc signs the test binary itself, which is the
	// closest to-hand example of code this bridge must refuse to load.
	self, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate test binary: %v", err)
	}
	if err := verifySignature(self, onePasswordRequirement); err == nil {
		t.Fatal("expected a non-AgileBits binary to fail verification")
	}
}
