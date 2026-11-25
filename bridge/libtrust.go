package main

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

// verify_code_signature returns 0 when the file at path carries a valid
// signature satisfying requirement, and a non-zero OSStatus (or a negative
// setup code) otherwise.
static int verify_code_signature(const char *path, const char *requirement) {
	CFStringRef path_string = CFStringCreateWithCString(NULL, path, kCFStringEncodingUTF8);
	if (path_string == NULL) {
		return -1;
	}
	CFURLRef url = CFURLCreateWithFileSystemPath(NULL, path_string, kCFURLPOSIXPathStyle, false);
	CFRelease(path_string);
	if (url == NULL) {
		return -2;
	}

	SecStaticCodeRef code = NULL;
	OSStatus status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
	CFRelease(url);
	if (status != errSecSuccess || code == NULL) {
		return -3;
	}

	CFStringRef requirement_string = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
	if (requirement_string == NULL) {
		CFRelease(code);
		return -4;
	}
	SecRequirementRef parsed = NULL;
	status = SecRequirementCreateWithString(requirement_string, kSecCSDefaultFlags, &parsed);
	CFRelease(requirement_string);
	if (status != errSecSuccess || parsed == NULL) {
		CFRelease(code);
		return -5;
	}

	status = SecStaticCodeCheckValidity(
		code,
		kSecCSCheckAllArchitectures | kSecCSStrictValidate,
		parsed);
	CFRelease(parsed);
	CFRelease(code);
	return (int)status;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// onePasswordRequirement is the exact code requirement the IPC library must
// satisfy: Apple's chain, AgileBits' team. It is the same shape of check csecd
// applies to the `op` CLI, and it is what makes the library-validation
// exemption this process carries safe to hold.
const onePasswordRequirement = `anchor apple generic and certificate leaf[subject.OU] = "2BUA8C4S2C"`

// verifyCanonicalLib checks the pinned library's signature immediately before
// the SDK dlopens it.
//
// This process is signed with com.apple.security.cs.disable-library-validation,
// because the SDK reaches 1Password by dlopening a library signed by AgileBits
// rather than by us, and the loader would otherwise refuse it. That exemption
// removes the loader's own check, so the check is made here instead. A window
// remains between this verification and the load; closing it entirely would
// need a file-handle-based loader API that does not exist. The window is
// narrow, and an attacker able to use it can already rewrite the 1Password
// application this provider trusts as its root.
func verifyCanonicalLib() error {
	return verifySignature(canonicalLibPath, onePasswordRequirement)
}

// verifySignature reports whether the file at libPath satisfies requirement.
func verifySignature(libPath string, req string) error {
	path := C.CString(libPath)
	defer C.free(unsafe.Pointer(path))
	requirement := C.CString(req)
	defer C.free(unsafe.Pointer(requirement))

	if status := C.verify_code_signature(path, requirement); status != 0 {
		return fmt.Errorf(
			"1Password library at %s is not validly signed by AgileBits (status %d)",
			libPath, int(status))
	}
	return nil
}
