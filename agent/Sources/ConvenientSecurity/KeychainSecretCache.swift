import Foundation
import LocalAuthentication

/// One cached secret plus the instant it goes stale. Stored natively in the warm
/// tier and JSON-encoded as the keychain item's data in the cold tier, so a
/// restored value carries its own expiry across an agent restart.
struct CacheEntry: Codable, Sendable {
    let value: String
    let expiresAt: Date
}

/// The at-rest half of the SE-cache, isolated behind a protocol so the cache's
/// warm/cold logic is testable with an in-memory fake, while production uses the
/// data-protection keychain. `load` may raise a biometric; `store`/`delete` never
/// do (writing and removing a `.biometryCurrentSet` item needs no authentication).
public protocol KeychainBackend: Sendable {
    func store(account: String, data: Data) async throws
    func load(account: String, unlock: CacheUnlock?) async throws -> Data?
    func delete(account: String) async
}

/// The production SE-cache: a warm in-heap tier for zero-touch in-grant fetches,
/// over a cold data-protection-keychain tier whose items are gated by a
/// `.biometryCurrentSet` ACL.
///
/// - **Warm hit** — value held in memory and unexpired → returned with no touch.
///   This is what makes in-grant re-fetches free over a multi-hour grant; the
///   grant already authorized a human, and the design accepts plaintext-in-use.
/// - **Cold read** — only when an `unlock` (the consent context) is supplied, so
///   the cache never raises a prompt out of nowhere. On an agent restart the warm
///   tier is empty, so the first post-consent read comes from the keychain and,
///   if the OS reuses the consent context, folds into that one touch.
/// - **Miss** — the resolver falls through to the provider and re-populates.
///
/// The warm tier never outlives the process (the design keeps only the grant
/// table and the SE-cache across restarts, and the grant table is memory-only).
public actor KeychainSecretCache: SecretCache {
    private let backend: KeychainBackend
    private var warm: [String: CacheEntry] = [:]

    public init(backend: KeychainBackend) {
        self.backend = backend
    }

    /// Convenience for the signed agent: the real data-protection-keychain backend.
    public init(service: String = SecurityKeychainBackend.defaultService) {
        self.backend = SecurityKeychainBackend(service: service)
    }

    public func get(_ uri: String, unlock: CacheUnlock?) async throws -> String? {
        let now = Date()

        if let entry = warm[uri] {
            if entry.expiresAt > now { return entry.value }
            warm[uri] = nil // expired; fall through to a possible cold read
        }

        // No cold read without a consent context — a keychain read would raise an
        // unsolicited biometric. In-grant fetches after a warm expiry become a
        // provider re-fetch instead of a surprise prompt.
        guard let unlock else { return nil }

        guard let data = try await backend.load(account: uri, unlock: unlock) else {
            return nil
        }
        guard let entry = try? JSONDecoder().decode(CacheEntry.self, from: data) else {
            // Unreadable/legacy item: drop it rather than wedge on it.
            await backend.delete(account: uri)
            return nil
        }
        guard entry.expiresAt > now else {
            await backend.delete(account: uri)
            return nil
        }

        warm[uri] = entry // promote the cold hit so later in-grant fetches are free
        return entry.value
    }

    public func put(_ uri: String, value: String, maxAge: TimeInterval) async throws {
        let entry = CacheEntry(value: value, expiresAt: Date().addingTimeInterval(maxAge))
        warm[uri] = entry
        let data = try JSONEncoder().encode(entry)
        try await backend.store(account: uri, data: data)
    }

    public func invalidate(_ uri: String) async {
        warm[uri] = nil
        await backend.delete(account: uri)
    }
}

/// Errors from the real keychain backend, carrying the raw `OSStatus` and its
/// system message so failures are legible in the agent log.
public struct KeychainError: Error, CustomStringConvertible {
    public let operation: String
    public let status: OSStatus

    public var description: String {
        let detail = SecCopyErrorMessageString(status, nil).map { $0 as String } ?? "unknown"
        return "keychain \(operation) failed (OSStatus \(status): \(detail))"
    }
}

/// The data-protection-keychain backend, one generic-password item per URI under
/// a `.biometryCurrentSet` ACL. Mirrors `packaging/spike`, which proves this exact
/// shape round-trips on signed hardware. Blocking `SecItem*` calls run on a
/// private serial queue so a biometric sheet never stalls the cooperative pool.
public struct SecurityKeychainBackend: KeychainBackend {
    public static let defaultService = "com.alexspeller.convenient-security.cache"

    private let service: String
    private let queue = DispatchQueue(label: "com.alexspeller.convenient-security.keychain")

    public init(service: String = defaultService) {
        self.service = service
    }

    /// Whether this process can actually use the data-protection keychain — i.e.
    /// it's signed with the provisioned access-group entitlement. Adds and deletes
    /// a throwaway, ACL-free item; never prompts. Returns the `OSStatus` so the
    /// caller can log *why* it's unavailable (typically `errSecMissingEntitlement`,
    /// -34018, in an unsigned dev run). `errSecSuccess` means the cache is usable.
    public static func probe(service: String = defaultService) -> OSStatus {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: service,
            kSecAttrAccount as String: "com.alexspeller.convenient-security.probe",
        ]
        SecItemDelete(base as CFDictionary)
        var add = base
        add[kSecValueData as String] = Data("probe".utf8)
        let status = SecItemAdd(add as CFDictionary, nil)
        if status == errSecSuccess {
            SecItemDelete(base as CFDictionary)
        }
        return status
    }

    /// The item identity. No explicit access group → defaults to the agent's
    /// `application-identifier` group (TeamID.bundleID), matching the spike.
    private func identity(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    public func store(account: String, data: Data) async throws {
        try await withBlocking {
            SecItemDelete(identity(account: account) as CFDictionary) // idempotent overwrite

            var accessError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .biometryCurrentSet,
                &accessError
            ) else {
                throw KeychainError(operation: "access-control", status: errSecParam)
            }

            var query = identity(account: account)
            query[kSecAttrAccessControl as String] = access
            query[kSecValueData as String] = data
            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else {
                throw KeychainError(operation: "add", status: status)
            }
        }
    }

    public func load(account: String, unlock: CacheUnlock?) async throws -> Data? {
        try await withBlocking {
            var query = identity(account: account)
            query[kSecReturnData as String] = true
            if let context = unlock?.context {
                query[kSecUseAuthenticationContext as String] = context
            }
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess:
                return result as? Data
            case errSecItemNotFound:
                return nil
            default:
                throw KeychainError(operation: "read", status: status)
            }
        }
    }

    public func delete(account: String) async {
        _ = try? await withBlocking {
            SecItemDelete(identity(account: account) as CFDictionary)
        }
    }

    /// Run a blocking Security call off the cooperative pool, on a private serial
    /// queue, so a biometric prompt can't stall other tasks.
    private func withBlocking<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async {
                continuation.resume(with: Result { try body() })
            }
        }
    }
}
