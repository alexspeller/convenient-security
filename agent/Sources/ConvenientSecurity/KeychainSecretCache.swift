import Foundation
import LocalAuthentication
import CSECBuildIdentity

/// One cached secret. Stored natively in the warm tier and JSON-encoded as the
/// keychain item's data in the cold tier, so a restored value survives an agent
/// restart. There is no wall-clock expiry: a cached value is kept until it is
/// explicitly invalidated (e.g. on rotation). A legacy item that still carries an
/// `expiresAt` key decodes fine — the extra key is ignored.
struct CacheEntry: Codable, Sendable {
    let value: Data
}

/// The at-rest half of the SE-cache, isolated behind a protocol so the cache's
/// warm/cold logic is testable with an in-memory fake, while production uses the
/// data-protection keychain. `load` may raise a biometric; `store`/`delete` never
/// do (writing and removing a `.biometryCurrentSet` item needs no authentication).
public protocol KeychainBackend: Sendable {
    func store(account: String, data: Data) async throws
    func load(account: String, unlock: CacheUnlock?) async throws -> Data?
    func delete(account: String) async
    /// Whether an item exists for `account`, found by its attributes alone:
    /// its data is not read, so this never needs or raises a biometric.
    func contains(account: String) async -> Bool
    /// Every cached account (canonical reference), listed with an evaluated
    /// local context so the listing itself can never raise a sheet. Used only
    /// to write remote-unlock mirrors at enrollment.
    func accounts(unlock: CacheUnlock) async throws -> [String]
}

public extension KeychainBackend {
    func accounts(unlock: CacheUnlock) async throws -> [String] { [] }
}

/// The production SE-cache: a warm in-heap tier for zero-touch in-grant fetches,
/// over a cold data-protection-keychain tier whose items are gated by a
/// `.biometryCurrentSet` ACL.
///
/// - **Warm hit** — value held in memory → returned with no touch. This is what
///   makes in-grant re-fetches free over a long-lived grant; the grant already
///   authorized a human, and the design accepts plaintext-in-use.
/// - **Cold read** — only when an `unlock` (the consent context) is supplied, so
///   the cache never raises a prompt out of nowhere. On an agent restart the warm
///   tier is empty, so the first post-consent read comes from the keychain and,
///   if the OS reuses the consent context, folds into that one touch.
/// - **Remote cold read** — a remote unlock (a verified phone approval) cannot
///   open the biometric item; it reads the entry's remote-unlock mirror instead,
///   the same encoded `CacheEntry` sealed to the enrollment's remote key. The
///   biometric item is never queried for it.
/// - **Miss** — the resolver falls through to the provider and re-populates.
///
/// When remote unlock is enrolled, every value written to the cold tier is
/// also sealed to its mirror, and dropping an entry drops both. A write
/// removes the old mirror before the item changes and seals the new one after,
/// so a failure or crash in between leaves no mirror rather than one older
/// than its item. Without an enrollment the mirror paths touch nothing.
///
/// An invalidation (a rotation) is never undone by a read or write that was
/// in flight when it began: the mirror goes first, then the item, then the
/// warm value, and a read or write that an invalidation overtook serves its
/// caller at most, promoting, re-sealing and keeping nothing.
///
/// The warm tier never outlives the process; the cold tier is the only part of
/// this cache that survives a restart. (Grants survive one too, in csecd's
/// protected grants item, but they hold references, never values.)
public actor KeychainSecretCache: SecretCache {
    private let backend: KeychainBackend
    private let remoteUnlock: RemoteUnlockStore?
    private var warm: [String: CacheEntry] = [:]
    /// Per reference, bumped when an invalidation begins and again when it
    /// ends. A read or write notes it before its first suspension; if it has
    /// moved, or an invalidation is still running (`invalidating`), the read
    /// or write was overtaken.
    private var invalidations: [String: UInt64] = [:]
    private var invalidating: [String: Int] = [:]
    /// Per reference, writes not finished yet: a read re-seals no mirror
    /// while one is, and only the last write re-seals.
    private var writing: [String: Int] = [:]

    public init(backend: KeychainBackend, remoteUnlock: RemoteUnlockStore? = nil) {
        self.backend = backend
        self.remoteUnlock = remoteUnlock
    }

    /// Convenience for the signed agent: the real data-protection-keychain backend.
    public init(
        service: String = SecurityKeychainBackend.defaultService,
        remoteUnlock: RemoteUnlockStore? = nil
    ) {
        self.backend = SecurityKeychainBackend(service: service)
        self.remoteUnlock = remoteUnlock
    }

    public func get(_ uri: String, unlock: CacheUnlock?) async throws -> Data? {
        if let entry = warm[uri] { return entry.value }

        // No cold read without a consent context — a keychain read would raise an
        // unsolicited biometric, so a warm miss with no unlock is a plain miss and
        // the resolver re-fetches from the provider.
        guard let unlock else { return nil }
        let since = invalidationMark(uri)
        if let remote = unlock.remote {
            return try await remoteValue(for: uri, remote: remote, since: since)
        }

        guard let data = try await backend.load(account: uri, unlock: unlock) else {
            return nil
        }
        guard let entry = try? JSONDecoder().decode(CacheEntry.self, from: data) else {
            // Unreadable item: drop it rather than wedge on it.
            await backend.delete(account: uri)
            return nil
        }
        // An invalidation that began while this read was in flight wins: the
        // value goes to this one caller, and is kept nowhere.
        guard !overtaken(uri, since: since) else { return entry.value }

        warm[uri] = entry // promote the cold hit so later in-grant fetches are free
        // A mirror a restart's epoch check cleared comes back on the next local
        // read, so a later phone approval can reopen this entry too. A write
        // in flight seals its own.
        if let remoteUnlock, writing[uri, default: 0] == 0, await remoteUnlock.isEnrolled(),
           !(await remoteUnlock.exists(.cache(uri: uri))), !overtaken(uri, since: since) {
            await sealMirror(uri, data: data, since: since)
        }
        return entry.value
    }

    public func put(_ uri: String, value: Data) async throws {
        let entry = CacheEntry(value: value)
        let data = try JSONEncoder().encode(entry)
        let since = invalidationMark(uri)
        warm[uri] = entry
        writing[uri, default: 0] += 1
        do {
            // The old mirror goes before the item changes, as a native store's
            // does before its key record moves: a failure or crash between the
            // two then leaves no mirror, never one older than the item. If it
            // can be neither deleted nor neutralized, the item is not changed.
            _ = try await remoteUnlock?.remove(.cache(uri: uri))
            try await backend.store(account: uri, data: data)
        } catch {
            endWrite(uri)
            throw error
        }
        endWrite(uri)
        if overtaken(uri, since: since) {
            // An invalidation ran while this was written, and this item may
            // have landed after its delete: what it removed must stay gone.
            await backend.delete(account: uri)
            return
        }
        guard writing[uri, default: 0] == 0 else { return } // a later write seals its own
        await sealMirror(uri, data: data, since: since)
    }

    @discardableResult
    public func invalidate(_ uri: String) async -> Bool {
        invalidations[uri, default: 0] &+= 1
        invalidating[uri, default: 0] += 1
        warm[uri] = nil
        // The mirror goes first, then the item, then (again) the warm value:
        // a read in flight meanwhile is overtaken and keeps nothing, and one
        // that starts afterwards finds nothing to read.
        var removed = true
        if let remoteUnlock {
            do {
                if try await remoteUnlock.remove(.cache(uri: uri)) == .neutralized {
                    Self.log("the remote-unlock copy of \(uri) could not be deleted; it is refused "
                        + "for this run and every copy is cleared at the next start")
                }
            } catch {
                Self.log("the remote-unlock copy of \(uri) may remain after invalidation (\(error))")
                removed = false
            }
        }
        await backend.delete(account: uri)
        warm[uri] = nil
        let remaining = invalidating[uri, default: 1] - 1
        invalidating[uri] = remaining > 0 ? remaining : nil
        invalidations[uri, default: 0] &+= 1
        return removed
    }

    public func holds(_ uri: String) async -> Bool {
        if warm[uri] != nil { return true }
        if await backend.contains(account: uri) { return true }
        return await holdsRemoteUnlockMirror(uri)
    }

    public func holdsRemoteUnlockMirror(_ uri: String) async -> Bool {
        guard let remoteUnlock else { return false }
        return await remoteUnlock.exists(.cache(uri: uri))
    }

    /// Mirror every cold entry with the enrollment's one local context. The
    /// warm tier is not touched: enrolling approved nothing for use.
    public func backfillRemoteUnlockMirrors(localUnlock: CacheUnlock) async -> RemoteUnlockBackfillReport {
        var report = RemoteUnlockBackfillReport()
        guard let remoteUnlock, localUnlock.isLocal, await remoteUnlock.isEnrolled() else { return report }
        let accounts: [String]
        do {
            accounts = try await backend.accounts(unlock: localUnlock)
        } catch {
            Self.log("cached entries could not be listed for remote unlock (\(error))")
            report.failed += 1
            return report
        }
        for uri in Set(accounts).sorted() {
            let since = invalidationMark(uri)
            do {
                guard let data = try await backend.load(account: uri, unlock: localUnlock),
                      (try? JSONDecoder().decode(CacheEntry.self, from: data)) != nil,
                      !overtaken(uri, since: since) else { continue }
                if try await remoteUnlock.sealAndStore(.cache(uri: uri), payload: data) {
                    if overtaken(uri, since: since) {
                        _ = try? await remoteUnlock.remove(.cache(uri: uri))
                    } else {
                        report.mirrored += 1
                    }
                }
            } catch {
                Self.log("cached entry \(uri) not mirrored for remote unlock (\(error))")
                report.failed += 1
            }
        }
        return report
    }

    /// A cold read for a remote unlock: the entry's mirror, never the
    /// biometric item. It decodes the same `CacheEntry` the item holds, so a
    /// mirrored value is served exactly as the item's would be.
    private func remoteValue(for uri: String, remote: RemoteUnlockKey, since: UInt64) async throws -> Data? {
        guard let remoteUnlock else { return nil }
        let payload: Data?
        do {
            payload = try await remote.open(.cache(uri: uri))
        } catch RemoteUnlockStoreError.mirrorUnreadable {
            // A mirror that does not open for the current enrollment never
            // will: drop it, so it no longer reads as covering this entry. The
            // next local read or write seals a good one.
            _ = try? await remoteUnlock.remove(.cache(uri: uri))
            throw RemoteUnlockStoreError.mirrorUnreadable
        }
        guard let payload else { return nil }
        guard let entry = try? JSONDecoder().decode(CacheEntry.self, from: payload) else {
            // An authenticated mirror that does not decode: drop it rather than
            // wedge on it, as the item path does.
            _ = try? await remoteUnlock.remove(.cache(uri: uri))
            return nil
        }
        guard !overtaken(uri, since: since) else { return entry.value }
        warm[uri] = entry
        return entry.value
    }

    /// `data` is the item's encoded `CacheEntry`; the mirror seals the same
    /// bytes. A no-op without an enrollment. A failure is logged: the mirror
    /// store has already removed (or neutralized) any older mirror, so none
    /// can serve a value this entry replaced. An invalidation that began
    /// while this sealed may have deleted the mirror before this one landed,
    /// so it is removed again.
    private func sealMirror(_ uri: String, data: Data, since: UInt64) async {
        guard let remoteUnlock else { return }
        do {
            try await remoteUnlock.sealAndStore(.cache(uri: uri), payload: data)
        } catch {
            Self.log("cached entry \(uri) not mirrored for remote unlock (\(error))")
        }
        if overtaken(uri, since: since) {
            _ = try? await remoteUnlock.remove(.cache(uri: uri))
        }
    }

    private func invalidationMark(_ uri: String) -> UInt64 {
        invalidations[uri, default: 0]
    }

    /// Whether an invalidation of `uri` began since `since` was noted, or is
    /// running now.
    private func overtaken(_ uri: String, since: UInt64) -> Bool {
        invalidations[uri, default: 0] != since || invalidating[uri, default: 0] > 0
    }

    private func endWrite(_ uri: String) {
        let remaining = writing[uri, default: 1] - 1
        writing[uri] = remaining > 0 ? remaining : nil
    }

    private static func log(_ message: String) {
        FileHandle.standardError.write(Data("csecd: cache: \(message)\n".utf8))
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
    public static let defaultService = CSECBuildIdentity.named("cache")

    private let service: String
    private let queue = DispatchQueue(label: CSECBuildIdentity.named("keychain"))

    public init(service: String = defaultService) {
        self.service = service
    }

    /// Whether this process can actually use the data-protection keychain — i.e.
    /// it's signed with the provisioned access-group entitlement. Adds and deletes
    /// a throwaway, ACL-free item; never prompts. Returns the `OSStatus` so the
    /// caller can log *why* it's unavailable (typically `errSecMissingEntitlement`,
    /// -34018, in an unsigned dev run). `errSecSuccess` means the cache is usable.
    public static func probe(service: String = defaultService) -> OSStatus {
        let match = probeQuery(service: service, adding: false)
        SecItemDelete(match as CFDictionary)
        let status = SecItemAdd(probeQuery(service: service, adding: true) as CFDictionary, nil)
        if status == errSecSuccess {
            SecItemDelete(match as CFDictionary)
        }
        return status
    }

    /// The probe item has the protected items' shape: the explicit access group
    /// they are gated on, and `AfterFirstUnlockThisDeviceOnly`, which is
    /// writable while the screen is locked. With the default `WhenUnlocked`
    /// class, a csecd that launchd restarts behind a locked screen (after a
    /// crash, say) would fail the probe and run with every Keychain feature
    /// off until its next restart. Matching omits the class, so a leftover
    /// probe item of any class is still found and deleted.
    public static func probeQuery(service: String = defaultService, adding: Bool) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: ProtectedItem.accessGroup,
            kSecAttrSynchronizable as String: false,
            kSecAttrService as String: service,
            kSecAttrAccount as String: CSECBuildIdentity.named("probe"),
        ]
        if adding {
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            query[kSecValueData as String] = Data("probe".utf8)
        }
        return query
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
        // A remote unlock carries no context, and a query for this item with
        // none would raise its own Touch ID sheet: it never reaches one.
        if let unlock, !unlock.isLocal { return nil }
        return try await withBlocking {
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

    /// An attributes-only match under a context that may not interact, so
    /// no sheet can appear whatever the item's ACL: an item whose attributes
    /// would need authentication answers `errSecInteractionNotAllowed`, which
    /// still says it exists. Any other failure reads as absent, so the caller
    /// treats the value as one no touch can reopen.
    public func contains(account: String) async -> Bool {
        (try? await withBlocking {
            var query = identity(account: account)
            query[kSecReturnAttributes as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            let context = LAContext()
            context.interactionNotAllowed = true
            query[kSecUseAuthenticationContext as String] = context
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return status == errSecSuccess || status == errSecInteractionNotAllowed
        }) ?? false
    }

    /// Attributes only, under the evaluated context, so the listing cannot
    /// raise a sheet whatever the items' ACL.
    public func accounts(unlock: CacheUnlock) async throws -> [String] {
        guard unlock.isLocal else {
            throw KeychainError(operation: "list", status: errSecInteractionNotAllowed)
        }
        let service = self.service
        return try await withBlocking {
            guard let context = unlock.context else {
                throw KeychainError(operation: "list", status: errSecInteractionNotAllowed)
            }
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecUseDataProtectionKeychain as String: true,
                kSecAttrService as String: service,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecUseAuthenticationContext as String: context,
            ]
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess:
                guard let rows = result as? [[String: Any]] else {
                    throw KeychainError(operation: "list", status: errSecDecode)
                }
                return rows.compactMap { $0[kSecAttrAccount as String] as? String }
            case errSecItemNotFound:
                return []
            default:
                throw KeychainError(operation: "list", status: status)
            }
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
