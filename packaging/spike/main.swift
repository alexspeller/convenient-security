import Foundation
import Security
import LocalAuthentication

// Signed-build verification for the SE-cache. It checks two properties on real
// hardware:
//
//   1. A Developer-ID-signed, hardened, provisioned (NOT sandboxed) binary can
//      store and retrieve a Touch-ID-gated item in the data-protection keychain
//      under our access group.
//
//   2. Whether one biometric authorizes the following keychain read. The
//      agent's cold-start path is
//      "consent (LAContext.evaluatePolicy) → read the cached item with that SAME
//      context". This executable performs that sequence and reports whether the
//      read prompted again.
//
// Run the SIGNED binary. Unsigned/unprovisioned it fails at store with -34018.

let service = "com.alexspeller.convenient-security.spike"
let account = "spike-secret"
let secretValue = "spike-value-\(ProcessInfo.processInfo.processIdentifier)"

func fail(_ message: String, status: OSStatus? = nil) -> Never {
    var line = "❌ \(message)"
    if let status {
        let detail = SecCopyErrorMessageString(status, nil).map { $0 as String } ?? "unknown"
        line += " (OSStatus \(status): \(detail))"
    }
    FileHandle.standardError.write(Data((line + "\n").utf8))
    if status == errSecMissingEntitlement {
        FileHandle.standardError.write(Data(
            "   -34018 means the entitlements aren't authorized — the binary isn't signed with an embedded profile granting the access group.\n".utf8
        ))
    }
    exit(1)
}

/// Wall time of a block, in seconds, off the monotonic clock. A sub-second read
/// means no interactive sheet appeared; a multi-second one means a prompt did.
func timed(_ body: () -> OSStatus) -> (status: OSStatus, seconds: Double) {
    let start = DispatchTime.now()
    let status = body()
    let seconds = Double(DispatchTime.now().uptimeNanoseconds - start.uptimeNanoseconds) / 1_000_000_000
    return (status, seconds)
}

// Access control: use requires a current-set biometric (Touch ID); item is
// device-only and unavailable when locked.
var accessError: Unmanaged<CFError>?
guard let access = SecAccessControlCreateWithFlags(
    kCFAllocatorDefault,
    kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    .biometryCurrentSet,
    &accessError
) else {
    fail("SecAccessControlCreateWithFlags failed: \(accessError!.takeRetainedValue())")
}

// The item identity (no explicit access group → defaults to our
// application-identifier group, 8RS6GD89Y7.com.alexspeller.convenient-security).
let identity: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrService as String: service,
    kSecAttrAccount as String: account,
]

// Start clean, then store the biometry-gated secret (no prompt on write).
SecItemDelete(identity as CFDictionary)
var addQuery = identity
addQuery[kSecAttrAccessControl as String] = access
addQuery[kSecValueData as String] = Data(secretValue.utf8)
let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
guard addStatus == errSecSuccess else { fail("SecItemAdd failed", status: addStatus) }
print("✓ stored a Touch-ID-gated secret in the data-protection keychain")

func readValue(context: LAContext) -> (status: OSStatus, seconds: Double, value: String?) {
    var query = identity
    query[kSecReturnData as String] = true
    query[kSecUseAuthenticationContext as String] = context
    var result: CFTypeRef?
    let (status, seconds) = timed { SecItemCopyMatching(query as CFDictionary, &result) }
    let value = (result as? Data).flatMap { String(data: $0, encoding: .utf8) }
    return (status, seconds, value)
}

// ── The fold test: consent, then read with the SAME context ──────────────────
print("\n── Fold test — the agent's exact cold-start path ──")
let context = LAContext()
context.localizedReason = "convenient-security: authorize this dev session"

var canError: NSError?
guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &canError) else {
    fail("biometrics unavailable: \(canError.map { String(describing: $0) } ?? "unknown")")
}

print("STEP 1/2 — CONSENT: approve the Touch ID prompt now (this authenticates the context).")
let consentSemaphore = DispatchSemaphore(value: 0)
var consentOK = false
var consentError: Error?
context.evaluatePolicy(
    .deviceOwnerAuthenticationWithBiometrics,
    localizedReason: "authorize this dev session"
) { ok, error in
    consentOK = ok
    consentError = error
    consentSemaphore.signal()
}
consentSemaphore.wait()
guard consentOK else {
    fail("consent was not granted: \(consentError.map { String(describing: $0) } ?? "cancelled")")
}
print("✓ consent granted (one Touch ID)")

print("""
STEP 2/2 — READ: reading the cached item with that SAME context.
           WATCH THE SCREEN: a second Touch ID here → the fold does NOT work (cold start = two touches).
                             no prompt, instant read     → the fold WORKS (cold start = one touch).
""")
let fold = readValue(context: context)
guard fold.status == errSecSuccess else { fail("SecItemCopyMatching (fold) failed", status: fold.status) }
guard fold.value == secretValue else {
    fail("round-trip mismatch: stored \(secretValue), read \(fold.value ?? "nil")")
}

let folded = fold.seconds < 0.5
print(String(format: "→ read returned in %.3fs — %@", fold.seconds,
             folded
             ? "no second prompt observed. THE FOLD WORKS: one touch covers consent + cache read."
             : "that delay suggests a SECOND prompt. THE FOLD LIKELY FAILS: cold start needs a separate cache-unlock touch."))

// Clean up regardless.
SecItemDelete(identity as CFDictionary)

print("""

Verdict is what YOU saw: how many Touch ID prompts total?
  • 1 prompt  → the same context covered consent and the cold cache read.
  • 2 prompts → the cold cache read required a separate biometric action.
""")
print("✅ round-trip OK; fold measurement above.")
exit(0)
