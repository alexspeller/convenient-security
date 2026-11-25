import Foundation
import LocalAuthentication
import Security
#if canImport(Darwin)
import Darwin
#endif

// Signed with the product's Developer ID certificate but deliberately without
// the provisioned keychain-access-group entitlement. This models another
// same-UID executable going after csec's Keychain items. It prints one
// value-free status line per attempt and never prints or otherwise returns
// Keychain data: every read asks for attributes only, and every update, delete
// and add targets a fresh probe-only account that holds nothing, never the
// account of a real item.
//
// Exit status: 0 when every attempt was refused, 1 when any attempt reached
// csec's access group.
//
// It is compiled as main.swift beside agent/Sources/CSECBuildIdentity, which
// names the team and identifier (build-spike.sh, bin/ci).

let accessGroup = CSECBuildIdentity.keychainAccessGroup

// The items ProtectedStores.swift declares, in its order, each service by the
// suffix it adds to the build identifier; bin/ci fails when a declared item is
// missing here.
let protectedItems: [(service: String, account: String)] = [
    ("delegation", "settings-v1"),
    ("delegation", "registrations-v1"),
    ("grants", "live-v1"),
    ("pairing", "v1"),
    ("runtime", "last-run-v1"),
    ("decision-log", "key-v1"),
    ("decision-log", "head-v1"),
    ("baseline", "pointer-v1"),
    ("automation", "runs-v1"),
    ("github-proxy", "settings-v1"),
    ("native-store-backup", "v1"),
    ("machine-identity", "catalog-v1"),
].map { (CSECBuildIdentity.named($0.0), $0.1) }

// Unique per run, so no real item can ever share it.
let probeAccount = "unentitled-probe-\(UUID().uuidString.lowercased())"

var attempts = 0
var reached = 0

func describe(_ status: OSStatus) -> String {
    let detail = SecCopyErrorMessageString(status, nil).map { $0 as String } ?? "unknown"
    return "OSStatus \(status) (\(detail))"
}

/// Records one attempt. `refusals` are the statuses that prove this process
/// was kept out; anything else, success included, counts as reaching the group.
func record(_ attempt: String, _ target: String, _ status: OSStatus, refusals: Set<OSStatus>) {
    attempts += 1
    let refused = refusals.contains(status)
    if !refused { reached += 1 }
    print("\(refused ? "refused" : "REACHED") \(attempt) \(target): \(describe(status))")
}

func nonInteractiveContext() -> LAContext {
    let context = LAContext()
    context.interactionNotAllowed = true
    return context
}

/// An item exactly as ProtectedStores.swift shapes it: generic password in the
/// data-protection keychain, the explicit group, never synchronizable.
func protectedIdentity(service: String, account: String) -> [String: Any] {
    [
        kSecClass as String: kSecClassGenericPassword,
        kSecUseDataProtectionKeychain as String: true,
        kSecAttrAccessGroup as String: accessGroup,
        kSecAttrSynchronizable as String: false,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
    ]
}

func attributeRead(_ base: [String: Any]) -> OSStatus {
    var query = base
    query[kSecReturnAttributes as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    query[kSecUseAuthenticationContext as String] = nonInteractiveContext()
    var result: CFTypeRef?
    return SecItemCopyMatching(query as CFDictionary, &result)
}

let missingEntitlement: Set<OSStatus> = [errSecMissingEntitlement]
// Without naming a group, a query only searches the caller's own groups, so an
// excluded process sees no item at all or is refused outright.
let notVisible: Set<OSStatus> = [errSecItemNotFound, errSecMissingEntitlement]

// The spike's biometric native-store record, created by the spike before it
// runs this helper. Authentication failure would be insufficient: it would mean
// the helper reached the item's biometric ACL rather than being excluded by
// code identity/access group.
record(
    "read (default groups)",
    CSECBuildIdentity.named("native-store-key-spike/spike-store"),
    attributeRead([
        kSecClass as String: kSecClassGenericPassword,
        kSecUseDataProtectionKeychain as String: true,
        kSecAttrService as String: CSECBuildIdentity.named("native-store-key-spike"),
        kSecAttrAccount as String: "spike-store",
    ]),
    refusals: notVisible
)

// csecd's protected items: no biometric ACL, AfterFirstUnlockThisDeviceOnly,
// explicit group. Their protection is the access group alone, so each of read,
// update, delete and add must be refused by the group check itself.
for item in protectedItems {
    let real = "\(item.service)/\(item.account)"
    let probe = "\(item.service)/\(probeAccount)"
    let probeIdentity = protectedIdentity(service: item.service, account: probeAccount)

    record(
        "read (explicit group)", real,
        attributeRead(protectedIdentity(service: item.service, account: item.account)),
        refusals: missingEntitlement
    )
    record(
        "read (default groups)", real,
        attributeRead([
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: item.service,
            kSecAttrAccount as String: item.account,
        ]),
        refusals: notVisible
    )
    record(
        "update", probe,
        SecItemUpdate(
            probeIdentity as CFDictionary,
            [kSecValueData as String: Data("unentitled-probe".utf8)] as CFDictionary
        ),
        refusals: missingEntitlement
    )
    record("delete", probe, SecItemDelete(probeIdentity as CFDictionary), refusals: missingEntitlement)

    var add = probeIdentity
    add[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    add[kSecValueData as String] = Data("unentitled-probe".utf8)
    let added = SecItemAdd(add as CFDictionary, nil)
    record("add", probe, added, refusals: missingEntitlement)
    if added == errSecSuccess {
        // Only this run's own probe item can exist here; remove it again.
        print("cleanup delete \(probe): \(describe(SecItemDelete(probeIdentity as CFDictionary)))")
    }
}

if reached == 0 {
    print("unentitled keychain probe: all \(attempts) attempts refused")
    exit(0)
}
print("unentitled keychain probe: \(reached) of \(attempts) attempts reached csec's access group")
exit(1)
