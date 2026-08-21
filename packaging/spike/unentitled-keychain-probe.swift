import Foundation
import LocalAuthentication
import Security
#if canImport(Darwin)
import Darwin
#endif

// Signed with the product's Developer ID certificate but deliberately without
// the provisioned keychain-access-group entitlement. This models another
// same-UID executable trying to query the native-store record. It never prints
// or otherwise returns Keychain data.
let identity: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecUseDataProtectionKeychain as String: true,
    kSecAttrService as String: "com.alexspeller.convenient-security.native-store-key-spike",
    kSecAttrAccount as String: "spike-store",
    kSecReturnData as String: true,
]

let context = LAContext()
context.interactionNotAllowed = true
var query = identity
query[kSecUseAuthenticationContext as String] = context
var result: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &result)

// Depending on the macOS/keychain path, an executable outside the access group
// sees either no matching item or a missing-entitlement error. Authentication
// failure would be insufficient: it would mean the helper reached the item's
// biometric ACL rather than being excluded by code identity/access group.
if status == errSecItemNotFound || status == errSecMissingEntitlement {
    exit(0)
}
exit(status == errSecSuccess ? 1 : 2)
