import CSECRemoteApproval
import CryptoKit
import Foundation
import Security
import CSECBuildIdentity

// The Mac-side storage of the phone-held cold-unlock factor.
//
// csec's cold storage opens only with an evaluated local `LAContext`: the
// native stores' key records (`.biometryAny`) and the Keychain cache's items
// (`.biometryCurrentSet`). A verified phone approval carries no such context,
// so after a csecd restart it could open nothing. The remote-unlock factor
// fills that gap without touching those items: at enrollment the Mac makes a
// key pair R and wraps its private half so that only the paired phone's
// Face-ID-gated key agreement can unwrap it (`RemoteUnlockCrypto`). Every
// cold item csec holds is then *mirrored*: a copy of the same payload sealed to
// R's public half. Sealing needs only that public half, so mirrors are kept
// current as storage changes with no phone involved; opening one needs R's
// private half, which exists only for the one transaction a phone approval
// unwrapped it for (`RemoteUnlockKey`).
//
// Every item here lives in the data-protection Keychain in csecd's explicit
// restricted access group, `AfterFirstUnlockThisDeviceOnly`, with no access
// control and never synchronized, exactly like the protected items
// (`ProtectedItem`): readable behind a locked screen, and outside the group a
// same-UID process can neither read, write, add nor delete them. What a mirror
// holds is ciphertext under R in any case; the access group is what keeps a
// same-UID process from planting or replaying one.

/// What one mirror item holds a sealed copy of. Names are value-free metadata:
/// a native store name, or a canonical reference.
public enum RemoteUnlockMirrorKind: Hashable, Sendable, CustomStringConvertible {
    /// A native store's document-tier key record (the `NativeStoreKeyRecord`
    /// its `.biometryAny` Keychain item holds).
    case nativeDocuments(store: String)
    /// A native store's blob-tier key record.
    case nativeBlobs(store: String)
    /// One Keychain cache entry (the `CacheEntry` its `.biometryCurrentSet`
    /// item holds), by canonical reference.
    case cache(uri: String)

    var tag: String {
        switch self {
        case .nativeDocuments: return "doc"
        case .nativeBlobs: return "blob"
        case .cache: return "cache"
        }
    }

    var name: String {
        switch self {
        case let .nativeDocuments(store), let .nativeBlobs(store): return store
        case let .cache(uri): return uri
        }
    }

    /// The mirror item's account: `<tag>/<name>`. A tag never contains `/`, so
    /// the first `/` always ends it, whatever the name holds.
    var account: String { "\(tag)/\(name)" }

    init?(account: String) {
        guard let slash = account.firstIndex(of: "/") else { return nil }
        let tag = account[..<slash]
        let name = String(account[account.index(after: slash)...])
        guard !name.isEmpty else { return nil }
        switch tag {
        case "doc": self = .nativeDocuments(store: name)
        case "blob": self = .nativeBlobs(store: name)
        case "cache": self = .cache(uri: name)
        default: return nil
        }
    }

    public var description: String { account }
}

/// The enrollment record: the pairing it belongs to and the wrapped remote
/// key. It holds no usable secret (see `RemoteUnlockCrypto.Enrollment`).
public struct RemoteUnlockEnrollmentRecord: Codable, Equatable, Sendable {
    public static let currentFormatVersion = 1

    public let formatVersion: Int
    public let enrollmentID: String
    public let macDeviceID: String
    public let phoneDeviceID: String
    public let enrollment: RemoteUnlockCrypto.Enrollment

    public init(macDeviceID: String, phoneDeviceID: String, enrollment: RemoteUnlockCrypto.Enrollment) {
        self.formatVersion = Self.currentFormatVersion
        self.enrollmentID = enrollment.enrollmentID
        self.macDeviceID = macDeviceID.lowercased()
        self.phoneDeviceID = phoneDeviceID.lowercased()
        self.enrollment = enrollment
    }

    /// The canonical pairing bytes the wrap authenticates
    /// (`RemoteUnlockCrypto.enroll(…binding:)` and `openRemoteKey(…binding:)`).
    public var binding: Data {
        Self.binding(macDeviceID: macDeviceID, phoneDeviceID: phoneDeviceID)
    }

    public static func binding(macDeviceID: String, phoneDeviceID: String) -> Data {
        RemoteUnlockStore.canonicalBytes([
            Data("csec.remote-unlock.binding.v1".utf8),
            Data(macDeviceID.lowercased().utf8),
            Data(phoneDeviceID.lowercased().utf8),
        ])
    }

    var isWellFormed: Bool {
        formatVersion == Self.currentFormatVersion
            && enrollmentID == enrollment.enrollmentID
            && !enrollmentID.isEmpty && enrollmentID.utf8.count <= 64
            && !macDeviceID.isEmpty && macDeviceID.utf8.count <= 64
            && !phoneDeviceID.isEmpty && phoneDeviceID.utf8.count <= 64
            && enrollment.remotePublicKey.count == 33
            && enrollment.ephemeralPublicKey.count == 33
            && enrollment.wrappedRemoteKey.count <= 256
            && enrollment.phoneKeyAgreementPublicKey.count <= 256
    }
}

/// The build that last kept the mirrors current. See `reconcileEpoch`.
struct RemoteUnlockEpoch: Codable, Equatable, Sendable {
    static let currentFormatVersion = 1
    let formatVersion: Int
    let buildIdentity: String
}

public enum RemoteUnlockStoreError: Error, Sendable, Equatable, CustomStringConvertible {
    case notEnrolled
    /// The enrollment item exists but this build cannot read it.
    case enrollmentUnreadable
    /// An enrollment that fails its own bounds check.
    case invalidEnrollment
    /// A remote key opened for an enrollment that has since been replaced.
    case enrollmentMismatch
    /// The remote key was dropped (`RemoteUnlockKey.invalidate`).
    case unlockInvalidated
    /// A mirror that did not open: malformed, bound to another name or another
    /// enrollment, or not sealed to this remote key.
    case mirrorUnreadable
    /// A mirror whose delete failed and whose stale content could not be
    /// neutralized either: it may still open until it is deleted.
    case staleMirrorMayRemain(OSStatus)
    /// `removeAllRemoteUnlockState` could not delete everything: which of the
    /// mirrors, the epoch and the enrollment may remain.
    case removalIncomplete(mirrors: Bool, epoch: Bool, enrollment: Bool)
    case keychain(operation: String, status: OSStatus)

    public var description: String {
        switch self {
        case .notEnrolled: return "remote unlock is not enrolled"
        case .enrollmentUnreadable: return "the remote-unlock enrollment cannot be read"
        case .invalidEnrollment: return "the remote-unlock enrollment is malformed"
        case .enrollmentMismatch: return "the remote unlock belongs to an earlier enrollment"
        case .unlockInvalidated: return "the remote unlock was already used up"
        case .mirrorUnreadable: return "a remote-unlock mirror did not open"
        case let .staleMirrorMayRemain(status):
            return "a remote-unlock mirror could not be deleted (OSStatus \(status))"
        case let .removalIncomplete(mirrors, epoch, enrollment):
            let remaining = [
                mirrors ? "mirrors" : nil, epoch ? "the epoch" : nil, enrollment ? "the enrollment" : nil,
            ].compactMap { $0 }
            return "remote-unlock state was not all deleted (\(remaining.joined(separator: ", ")) may remain)"
        case let .keychain(operation, status):
            let detail = SecCopyErrorMessageString(status, nil).map { $0 as String } ?? "unknown"
            return "remote-unlock keychain \(operation) failed (OSStatus \(status): \(detail))"
        }
    }
}

/// How `RemoteUnlockStore.remove` left a mirror.
public enum RemoteUnlockRemoval: Sendable, Equatable {
    /// There is no enrollment, so there are no mirrors; nothing was touched.
    case notEnrolled
    /// The mirror is gone (or never existed).
    case removed
    /// The delete failed, but the mirror is refused for the rest of this run
    /// and the epoch was cleared, so the next start deletes every mirror
    /// before one can be served.
    case neutralized
}

/// What `RemoteUnlockStore.reconcileEpoch` found at startup.
public enum RemoteUnlockEpochOutcome: String, Sendable, Equatable {
    /// No enrollment: nothing was read beyond that, nothing was written.
    case notEnrolled
    /// The enrollment item exists but could not be read: no mirror is served
    /// this run, and the epoch was deleted, so the next start clears them.
    case enrollmentUnreadable
    /// Only this build (or another mirror-keeping one) ran since the mirrors
    /// were written: they are kept.
    case kept
    /// Another build may have run in between: every mirror was deleted, and
    /// each comes back the next time its item is opened locally or written.
    case cleared
    /// The mirrors had to be cleared and could not be: none is served this
    /// run, and the next start tries again.
    case clearFailed
}

/// Value-free counts from writing mirrors for existing storage at enrollment.
public struct RemoteUnlockBackfillReport: Sendable, Equatable {
    public var mirrored: Int
    public var failed: Int

    public init(mirrored: Int = 0, failed: Int = 0) {
        self.mirrored = mirrored
        self.failed = failed
    }

    public mutating func add(_ other: RemoteUnlockBackfillReport) {
        mirrored += other.mirrored
        failed += other.failed
    }
}

/// Which references a remote unlock could serve. `needsUnlock` are the
/// references whose provider needs a cold item opened (and, for a restore,
/// those only the cold cache holds); `coveredRemotely` are
/// those among them a remote unlock opens (from a cache mirror, or from the
/// provider's own mirrors). A request is phone-servable exactly when every
/// reference needing an unlock is covered. `cachedRemotely` are released
/// references whose provider can fetch them with no unlock but whose cached
/// value a remote unlock also opens: reading that copy spares asking the
/// provider (1Password, say, locked along with the Mac), and without it the
/// provider is asked as before, so they never make a request less servable.
/// `needsAttendance` are released references csecd does not hold warm whose
/// provider would raise its own authorization at the Mac now
/// (`SecretProvider.requiresAttendanceToResolve`): a phone approval can
/// deliver one only from its cached copy (`cachedRemotely`), so any other is
/// `unattendable`, and the request stays on the Mac.
public struct RemoteUnlockCoverage: Sendable, Equatable {
    public let needsUnlock: Set<String>
    public let coveredRemotely: Set<String>
    public let cachedRemotely: Set<String>
    public let needsAttendance: Set<String>

    public init(
        needsUnlock: Set<String>, coveredRemotely: Set<String>, cachedRemotely: Set<String> = [],
        needsAttendance: Set<String> = []
    ) {
        self.needsUnlock = needsUnlock
        self.coveredRemotely = coveredRemotely
        self.cachedRemotely = cachedRemotely
        self.needsAttendance = needsAttendance
    }

    public var isComplete: Bool { needsUnlock.isSubset(of: coveredRemotely) }
    public var uncovered: Set<String> { needsUnlock.subtracting(coveredRemotely) }
    /// References a phone approval could not deliver even with the remote
    /// unlock: each would wait on its provider's prompt at the Mac.
    public var unattendable: Set<String> { needsAttendance.subtracting(cachedRemotely) }
}

/// What a review's coverage is asked about: `references`, which its approval
/// would resolve, and `restoring`, which a restore section would reopen from
/// local sealed state alone (`SecretResolver.remoteUnlockCoverage(_:restoring:)`).
public struct RemoteUnlockCoverageRequest: Sendable, Equatable {
    public let references: [SecretRef]
    public let restoring: [SecretRef]

    public init(references: [SecretRef], restoring: [SecretRef] = []) {
        self.references = references
        self.restoring = restoring
    }
}

/// One transaction's opened remote-unlock key: what a `CacheUnlock` carries
/// after a verified phone approval. It reads mirrors through the store that
/// opened it, only for the enrollment it was opened for, and is dropped by
/// `invalidate()` like a context.
///
/// `@unchecked Sendable`: every stored property is immutable and `Sendable`
/// except the key, which is read and cleared only under `lock`.
public final class RemoteUnlockKey: @unchecked Sendable {
    public let enrollmentID: String
    private let reader: RemoteUnlockStore
    private let lock = NSLock()
    private var key: P256.KeyAgreement.PrivateKey?

    init(key: P256.KeyAgreement.PrivateKey, enrollmentID: String, reader: RemoteUnlockStore) {
        self.key = key
        self.enrollmentID = enrollmentID
        self.reader = reader
    }

    public func invalidate() {
        lock.lock()
        defer { lock.unlock() }
        key = nil
    }

    public var isInvalidated: Bool { currentKey() == nil }

    /// The payload mirrored for `kind`, or nil when there is no mirror this
    /// run may serve.
    func open(_ kind: RemoteUnlockMirrorKind) async throws -> Data? {
        guard let current = currentKey() else { throw RemoteUnlockStoreError.unlockInvalidated }
        return try await reader.load(kind, remoteKey: current, enrollmentID: enrollmentID)
    }

    private func currentKey() -> P256.KeyAgreement.PrivateKey? {
        lock.lock()
        defer { lock.unlock() }
        return key
    }
}

/// The name of one remote-unlock Keychain item.
public struct RemoteUnlockItemName: Hashable, Sendable, CustomStringConvertible {
    public let service: String
    public let account: String

    public init(service: String, account: String) {
        self.service = service
        self.account = account
    }

    public var description: String { "\(service)/\(account)" }
}

/// Where remote-unlock items live: the data-protection Keychain in production,
/// memory in tests. No operation needs or raises a biometric.
public protocol RemoteUnlockItemBackend: Sendable {
    func read(_ item: RemoteUnlockItemName) async throws -> Data?
    /// Creates or replaces the item.
    func write(_ item: RemoteUnlockItemName, data: Data) async throws
    /// Deleting an absent item succeeds.
    func delete(_ item: RemoteUnlockItemName) async throws
    /// Whether the item exists, from its attributes alone.
    func exists(_ item: RemoteUnlockItemName) async throws -> Bool
    /// Every account under `service`.
    func accounts(service: String) async throws -> [String]
}

/// The operations the Keychain backend issues, for `query(_:operation:)`.
public enum RemoteUnlockKeychainOperation: String, Sendable, CaseIterable {
    case read
    case add
    case update
    case delete
    case exists
    case list
}

/// The production backend. Every query names the explicit access group, the
/// data-protection Keychain and `synchronizable = false`; creation fixes the
/// class at `AfterFirstUnlockThisDeviceOnly`. None sets an access control, so
/// no operation can raise a sheet, and the items stay readable behind a locked
/// screen, which is when a phone approval needs them.
public struct SecurityRemoteUnlockItemBackend: RemoteUnlockItemBackend {
    private let queue = DispatchQueue(label: CSECBuildIdentity.named("remote-unlock-keychain"))

    public init() {}

    /// The dictionary each `SecItem` call sends. `account` is nil only for
    /// `.list`. Matching omits the class, so a write or delete still finds an
    /// item whatever class it holds.
    public static func query(
        service: String,
        account: String?,
        operation: RemoteUnlockKeychainOperation
    ) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: ProtectedItem.accessGroup,
            kSecAttrSynchronizable as String: false,
            kSecAttrService as String: service,
        ]
        if let account { query[kSecAttrAccount as String] = account }
        switch operation {
        case .read:
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
        case .add:
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .exists:
            query[kSecReturnAttributes as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
        case .list:
            query[kSecReturnAttributes as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitAll
        case .update, .delete:
            break
        }
        return query
    }

    public func read(_ item: RemoteUnlockItemName) async throws -> Data? {
        try await blocking {
            var result: CFTypeRef?
            let status = SecItemCopyMatching(
                Self.query(service: item.service, account: item.account, operation: .read) as CFDictionary,
                &result
            )
            switch status {
            case errSecSuccess:
                guard let data = result as? Data else {
                    throw RemoteUnlockStoreError.keychain(operation: "read", status: errSecDecode)
                }
                return data
            case errSecItemNotFound:
                return nil
            default:
                throw RemoteUnlockStoreError.keychain(operation: "read", status: status)
            }
        }
    }

    public func write(_ item: RemoteUnlockItemName, data: Data) async throws {
        try await blocking {
            var status = SecItemUpdate(
                Self.query(service: item.service, account: item.account, operation: .update) as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            if status == errSecItemNotFound {
                var attributes = Self.query(service: item.service, account: item.account, operation: .add)
                attributes[kSecValueData as String] = data
                status = SecItemAdd(attributes as CFDictionary, nil)
            }
            guard status == errSecSuccess else {
                throw RemoteUnlockStoreError.keychain(operation: "write", status: status)
            }
        }
    }

    public func delete(_ item: RemoteUnlockItemName) async throws {
        try await blocking {
            let status = SecItemDelete(
                Self.query(service: item.service, account: item.account, operation: .delete) as CFDictionary
            )
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw RemoteUnlockStoreError.keychain(operation: "delete", status: status)
            }
        }
    }

    public func exists(_ item: RemoteUnlockItemName) async throws -> Bool {
        try await blocking {
            var result: CFTypeRef?
            let status = SecItemCopyMatching(
                Self.query(service: item.service, account: item.account, operation: .exists) as CFDictionary,
                &result
            )
            switch status {
            case errSecSuccess: return true
            case errSecItemNotFound: return false
            default: throw RemoteUnlockStoreError.keychain(operation: "exists", status: status)
            }
        }
    }

    public func accounts(service: String) async throws -> [String] {
        try await blocking {
            var result: CFTypeRef?
            let status = SecItemCopyMatching(
                Self.query(service: service, account: nil, operation: .list) as CFDictionary,
                &result
            )
            switch status {
            case errSecSuccess:
                guard let rows = result as? [[String: Any]] else {
                    throw RemoteUnlockStoreError.keychain(operation: "list", status: errSecDecode)
                }
                return rows.compactMap { $0[kSecAttrAccount as String] as? String }
            case errSecItemNotFound:
                return []
            default:
                throw RemoteUnlockStoreError.keychain(operation: "list", status: status)
            }
        }
    }

    private func blocking<T: Sendable>(_ body: @escaping @Sendable () throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result { try body() }) }
        }
    }
}

/// In-memory remote-unlock items for tests: raw access to plant or tamper with
/// an item, injected failures, and a log of every operation.
public actor InMemoryRemoteUnlockItemBackend: RemoteUnlockItemBackend {
    public struct Operation: Sendable, Equatable, CustomStringConvertible {
        public let kind: RemoteUnlockKeychainOperation
        public let item: RemoteUnlockItemName?

        public var description: String { "\(kind.rawValue) \(item?.description ?? "*")" }
    }

    private var items: [RemoteUnlockItemName: Data] = [:]
    private var failingDeletes: [String: OSStatus] = [:]
    private var failingWrites: [String: OSStatus] = [:]
    public private(set) var operations: [Operation] = []

    public init() {}

    /// Deletes of items under `service` (every account when `account` is nil)
    /// fail with `status`; nil clears the failure.
    public func failDeletes(service: String, account: String? = nil, status: OSStatus?) {
        failingDeletes[Self.failureKey(service: service, account: account)] = status
    }

    public func failWrites(service: String, account: String? = nil, status: OSStatus?) {
        failingWrites[Self.failureKey(service: service, account: account)] = status
    }

    public func rawItems() -> [RemoteUnlockItemName: Data] { items }

    public func setRaw(_ data: Data?, for item: RemoteUnlockItemName) {
        items[item] = data
    }

    public func clearOperations() { operations = [] }

    public func read(_ item: RemoteUnlockItemName) -> Data? {
        operations.append(Operation(kind: .read, item: item))
        return items[item]
    }

    public func write(_ item: RemoteUnlockItemName, data: Data) throws {
        operations.append(Operation(kind: .update, item: item))
        if let status = failure(in: failingWrites, for: item) {
            throw RemoteUnlockStoreError.keychain(operation: "write", status: status)
        }
        items[item] = data
    }

    public func delete(_ item: RemoteUnlockItemName) throws {
        operations.append(Operation(kind: .delete, item: item))
        if let status = failure(in: failingDeletes, for: item) {
            throw RemoteUnlockStoreError.keychain(operation: "delete", status: status)
        }
        items[item] = nil
    }

    public func exists(_ item: RemoteUnlockItemName) -> Bool {
        operations.append(Operation(kind: .exists, item: item))
        return items[item] != nil
    }

    public func accounts(service: String) -> [String] {
        operations.append(Operation(kind: .list, item: nil))
        return items.keys.filter { $0.service == service }.map(\.account).sorted()
    }

    private func failure(in table: [String: OSStatus], for item: RemoteUnlockItemName) -> OSStatus? {
        table[Self.failureKey(service: item.service, account: item.account)]
            ?? table[Self.failureKey(service: item.service, account: nil)]
    }

    private static func failureKey(service: String, account: String?) -> String {
        "\(service)\u{0}\(account ?? "*")"
    }
}

/// Owns every remote-unlock item: the enrollment, the epoch, and the mirrors.
///
/// Writing a mirror needs only the enrollment's public key, so storage keeps
/// its mirrors current with no phone. Reading one needs a `RemoteUnlockKey`,
/// which exists only after a verified phone approval unwrapped it.
///
/// A user who never enrolled pays one read of the enrollment item per csecd
/// run (cached here), and, since no phone is paired, the start's sweep for
/// state a failed removal left (a listing of the mirrors and a delete of the
/// epoch, `removeAllRemoteUnlockState`); nothing is ever written.
public actor RemoteUnlockStore {
    public static let service = CSECBuildIdentity.named("remote-unlock")
    public static let mirrorService = CSECBuildIdentity.named("remote-unlock-mirror")
    static let enrollmentItem = RemoteUnlockItemName(service: service, account: "enrollment-v1")
    static let epochItem = RemoteUnlockItemName(service: service, account: "epoch-v1")
    /// The mirror context's domain, so a mirror box can never open as anything
    /// else sealed to the same key.
    static let mirrorContextDomain = Data("csec.remote-unlock.mirror.v1".utf8)

    private enum EnrollmentState: Sendable {
        case unknown
        case absent
        case enrolled(RemoteUnlockEnrollmentRecord)
        case unreadable
    }

    private let backend: RemoteUnlockItemBackend
    private let buildIdentity: String?
    private var enrollmentState: EnrollmentState = .unknown
    /// Set once this run has checked that no other build ran since the
    /// mirrors were written (`reconcileEpoch`), or has written the enrollment
    /// itself. Until then no mirror is served.
    private var mirrorsTrusted = false
    /// Mirror accounts whose delete failed: their content may be stale, so
    /// they are never served this run. Cleared when the mirror is rewritten.
    private var refusedAccounts: Set<String> = []

    /// `buildIdentity` names this build for the epoch (csecd passes its
    /// cdhash). A nil identity is never trusted across a restart.
    public init(backend: RemoteUnlockItemBackend, buildIdentity: String?) {
        self.backend = backend
        self.buildIdentity = buildIdentity
    }

    /// The Keychain-backed store for the running csecd.
    public static func dataProtectionKeychain(
        buildIdentity: String? = CsecdRunFacts.currentCDHash()
    ) -> RemoteUnlockStore {
        RemoteUnlockStore(backend: SecurityRemoteUnlockItemBackend(), buildIdentity: buildIdentity)
    }

    // MARK: - Enrollment

    /// The current enrollment, or nil when there is none or it is unreadable.
    public func enrollment() async -> RemoteUnlockEnrollmentRecord? {
        if case let .enrolled(record) = await loadEnrollmentState() { return record }
        return nil
    }

    public func isEnrolled() async -> Bool {
        await enrollment() != nil
    }

    /// Enroll against the phone's key-agreement public key and store the
    /// record, replacing any earlier enrollment (and deleting its mirrors,
    /// which could never open again). The remote key's private half is
    /// discarded here: only the phone can unwrap it again.
    @discardableResult
    public func enroll(
        phoneKeyAgreementPublicKeyX963: Data,
        macDeviceID: String,
        phoneDeviceID: String
    ) async throws -> RemoteUnlockEnrollmentRecord {
        let binding = RemoteUnlockEnrollmentRecord.binding(
            macDeviceID: macDeviceID, phoneDeviceID: phoneDeviceID
        )
        let enrolled = try RemoteUnlockCrypto.enroll(
            phoneKeyAgreementPublicKeyX963: phoneKeyAgreementPublicKeyX963,
            binding: binding
        )
        let record = RemoteUnlockEnrollmentRecord(
            macDeviceID: macDeviceID, phoneDeviceID: phoneDeviceID, enrollment: enrolled.enrollment
        )
        try await storeEnrollment(record)
        return record
    }

    /// Store `record` as the enrollment. Every earlier mirror is deleted
    /// first; the epoch is written for this build, so the mirrors this run
    /// writes survive its restart.
    public func storeEnrollment(_ record: RemoteUnlockEnrollmentRecord) async throws {
        guard record.isWellFormed else { throw RemoteUnlockStoreError.invalidEnrollment }
        // Stop sealing to the old key before its mirrors go.
        enrollmentState = .unknown
        mirrorsTrusted = false
        try await deleteAllMirrorItems()
        refusedAccounts = []
        let data = try JSONEncoder().encode(record)
        try await backend.write(Self.enrollmentItem, data: data)
        enrollmentState = .enrolled(record)
        await writeEpoch()
        mirrorsTrusted = true
    }

    /// Everything remote unlock keeps: every mirror, then the epoch, then the
    /// enrollment. Sealing stops at once, and every deletion is attempted even
    /// after one fails: deleting the enrollment destroys the only wrapped copy
    /// of the remote key, so a mirror left behind can never open again.
    /// Throws `removalIncomplete` naming what may remain; every start with no
    /// phone paired calls this again (`RemoteApprovalManager`), so what is
    /// left is swept then. With nothing enrolled it lists the mirrors and
    /// deletes the epoch, and writes nothing.
    public func removeAllRemoteUnlockState() async throws {
        let enrollmentMayExist: Bool
        switch await loadEnrollmentState() {
        case .absent: enrollmentMayExist = false
        case .enrolled, .unreadable, .unknown: enrollmentMayExist = true
        }
        enrollmentState = .absent
        mirrorsTrusted = false
        refusedAccounts = []
        var mirrorsLeft = false
        var epochLeft = false
        var enrollmentLeft = false
        do { try await deleteAllMirrorItems() } catch { mirrorsLeft = true }
        do { try await backend.delete(Self.epochItem) } catch { epochLeft = true }
        if enrollmentMayExist {
            do { try await backend.delete(Self.enrollmentItem) } catch { enrollmentLeft = true }
        }
        if enrollmentLeft {
            // The enrollment item may remain; read it again next time.
            enrollmentState = .unknown
        }
        if mirrorsLeft || epochLeft || enrollmentLeft {
            throw RemoteUnlockStoreError.removalIncomplete(
                mirrors: mirrorsLeft, epoch: epochLeft, enrollment: enrollmentLeft
            )
        }
    }

    /// A fresh blinding of the enrollment for one phone request.
    public func challenge() async throws -> (challenge: RemoteUnlockCrypto.Challenge, enrollmentID: String) {
        guard let record = try await requireEnrollment() else { throw RemoteUnlockStoreError.notEnrolled }
        return (try RemoteUnlockCrypto.challenge(for: record.enrollment), record.enrollmentID)
    }

    /// Unblind a verified phone answer to `challenge` and hand back the
    /// one-transaction remote unlock. `enrollmentID` is the one `challenge()`
    /// returned: an enrollment replaced in between fails.
    public func openRemoteUnlock(
        challenge: RemoteUnlockCrypto.Challenge,
        answer: Data,
        enrollmentID: String
    ) async throws -> CacheUnlock {
        guard let record = try await requireEnrollment() else { throw RemoteUnlockStoreError.notEnrolled }
        guard record.enrollmentID == enrollmentID else { throw RemoteUnlockStoreError.enrollmentMismatch }
        let key = try RemoteUnlockCrypto.openRemoteKey(
            enrollment: record.enrollment,
            challenge: challenge,
            answer: answer,
            binding: record.binding
        )
        return CacheUnlock(remote: RemoteUnlockKey(key: key, enrollmentID: record.enrollmentID, reader: self))
    }

    // MARK: - Mirrors

    /// Seal `payload` to the enrolled remote key and store it as `kind`'s
    /// mirror, replacing any earlier one. Returns false, touching nothing,
    /// when there is no enrollment. When the enrollment exists but cannot be
    /// read, nothing can be sealed, and the older mirror is removed (or
    /// neutralized) instead of being left to outlive what it copied; false.
    /// A failed write removes the old mirror (or neutralizes it) before
    /// throwing, so a stale mirror is never left servable.
    @discardableResult
    public func sealAndStore(_ kind: RemoteUnlockMirrorKind, payload: Data) async throws -> Bool {
        let record: RemoteUnlockEnrollmentRecord
        switch await loadEnrollmentState() {
        case let .enrolled(enrolled):
            record = enrolled
        case .absent:
            return false
        case .unreadable, .unknown:
            try await remove(kind)
            return false
        }
        let sealed = try RemoteUnlockCrypto.seal(
            payload,
            toRemotePublicKey: record.enrollment.remotePublicKey,
            context: Self.sealContext(kind, enrollmentID: record.enrollmentID)
        )
        do {
            try await backend.write(Self.mirrorItem(kind), data: sealed)
        } catch {
            _ = try? await remove(kind)
            throw error
        }
        // The enrollment may have been replaced or removed while the write was
        // in flight; a mirror sealed to the old key must not outlive it.
        guard case let .enrolled(current) = enrollmentState,
              current.enrollmentID == record.enrollmentID else {
            try? await backend.delete(Self.mirrorItem(kind))
            return false
        }
        refusedAccounts.remove(kind.account)
        return true
    }

    /// The payload mirrored for `kind`, opened with `remoteKey`. Nil when
    /// there is no mirror this run may serve: none stored, none trusted yet
    /// (`reconcileEpoch` has not run or failed), or one a failed delete may
    /// have left stale.
    func load(
        _ kind: RemoteUnlockMirrorKind,
        remoteKey: P256.KeyAgreement.PrivateKey,
        enrollmentID: String
    ) async throws -> Data? {
        guard case let .enrolled(record) = await loadEnrollmentState() else {
            throw RemoteUnlockStoreError.notEnrolled
        }
        guard record.enrollmentID == enrollmentID else { throw RemoteUnlockStoreError.enrollmentMismatch }
        guard mirrorsTrusted, !refusedAccounts.contains(kind.account) else { return nil }
        guard let sealed = try await backend.read(Self.mirrorItem(kind)) else { return nil }
        do {
            return try RemoteUnlockCrypto.open(
                sealed,
                remoteKey: remoteKey,
                context: Self.sealContext(kind, enrollmentID: enrollmentID)
            )
        } catch {
            throw RemoteUnlockStoreError.mirrorUnreadable
        }
    }

    /// Whether this run could serve `kind`'s mirror: enrolled, trusted, not
    /// refused, and the item exists. Reads attributes only; never opens it.
    public func exists(_ kind: RemoteUnlockMirrorKind) async -> Bool {
        guard case .enrolled = await loadEnrollmentState(),
              mirrorsTrusted,
              !refusedAccounts.contains(kind.account) else { return false }
        return (try? await backend.exists(Self.mirrorItem(kind))) ?? false
    }

    /// Delete `kind`'s mirror. Touches nothing when not enrolled. When the
    /// delete fails the mirror is refused for the rest of this run and the
    /// epoch is deleted, so the next start deletes every mirror before
    /// serving one (`.neutralized`); only if that fails too does this throw.
    @discardableResult
    public func remove(_ kind: RemoteUnlockMirrorKind) async throws -> RemoteUnlockRemoval {
        switch await loadEnrollmentState() {
        case .absent:
            return .notEnrolled
        case .enrolled, .unreadable, .unknown:
            break
        }
        do {
            try await backend.delete(Self.mirrorItem(kind))
            refusedAccounts.remove(kind.account)
            return .removed
        } catch let deleteError {
            refusedAccounts.insert(kind.account)
            Self.log("mirror \(kind) could not be deleted (\(deleteError)); refused for this run")
            do {
                try await backend.delete(Self.epochItem)
            } catch {
                Self.log("epoch could not be cleared either (\(error)); mirror \(kind) may remain")
                throw RemoteUnlockStoreError.staleMirrorMayRemain(Self.status(of: deleteError))
            }
            return .neutralized
        }
    }

    /// Every mirror item stored, whatever its enrollment.
    public func mirrors() async throws -> [RemoteUnlockMirrorKind] {
        try await backend.accounts(service: Self.mirrorService).compactMap(RemoteUnlockMirrorKind.init(account:))
    }

    /// Delete every mirror; each comes back the next time its item is opened
    /// locally or written.
    public func removeAllMirrors() async throws {
        try await deleteAllMirrorItems()
    }

    // MARK: - Epoch

    /// The downgrade guard, run once at startup after csecd recorded this
    /// run in `runtime`/`last-run-v1` (`CsecdLifecycle.start`), with the
    /// previous run that item held, and before anything is served.
    ///
    /// A build that does not keep mirrors can commit a native store or drop a
    /// cache entry without touching its mirror, which would leave the mirror
    /// naming state the Keychain no longer holds. So the epoch item records
    /// the build that last kept the mirrors, and when the run before this one
    /// was not that build — an older or unknown build ran in between, or the
    /// previous run is unknown — every mirror is deleted before one can be
    /// served. Then this build is recorded. With no enrollment nothing but the
    /// enrollment item is read, and nothing is written.
    @discardableResult
    public func reconcileEpoch(previousRun: CsecdLastRun?) async -> RemoteUnlockEpochOutcome {
        enrollmentState = .unknown
        switch await loadEnrollmentState() {
        case .absent:
            mirrorsTrusted = false
            return .notEnrolled
        case .unreadable, .unknown:
            mirrorsTrusted = false
            // This run cannot seal to the enrollment, so it cannot keep the
            // mirrors current: the epoch goes, and the next start drops them.
            do {
                try await backend.delete(Self.epochItem)
            } catch {
                Self.log("epoch could not be cleared while the enrollment is unreadable (\(error)); "
                    + "each write this run removes its mirror instead")
            }
            return .enrollmentUnreadable
        case .enrolled:
            break
        }
        let recorded = await readEpoch()
        let consistent = previousRun?.cdHash != nil && previousRun?.cdHash == recorded
        var outcome = RemoteUnlockEpochOutcome.kept
        if !consistent {
            do {
                try await deleteAllMirrorItems()
                outcome = .cleared
            } catch {
                mirrorsTrusted = false
                Self.log("mirrors from another build could not be cleared (\(error)); none served this run")
                // The epoch still names the build that last kept the mirrors:
                // if that build starts next, it would trust what is left.
                do {
                    try await backend.delete(Self.epochItem)
                } catch let epochError {
                    Self.log("the epoch could not be cleared either (\(epochError)); "
                        + "each write this run removes its mirror instead")
                }
                return .clearFailed
            }
        }
        refusedAccounts = []
        await writeEpoch()
        mirrorsTrusted = true
        return outcome
    }

    // MARK: - Internals

    /// The cached enrollment state; the item is read once per run (and again
    /// after an unreadable read).
    private func loadEnrollmentState() async -> EnrollmentState {
        switch enrollmentState {
        case .absent, .enrolled:
            return enrollmentState
        case .unknown, .unreadable:
            break
        }
        let state: EnrollmentState
        do {
            if let data = try await backend.read(Self.enrollmentItem) {
                if let record = try? JSONDecoder().decode(RemoteUnlockEnrollmentRecord.self, from: data),
                   record.isWellFormed {
                    state = .enrolled(record)
                } else {
                    state = .unreadable
                }
            } else {
                state = .absent
            }
        } catch {
            state = .unreadable
        }
        enrollmentState = state
        return state
    }

    private func requireEnrollment() async throws -> RemoteUnlockEnrollmentRecord? {
        switch await loadEnrollmentState() {
        case let .enrolled(record): return record
        case .absent: return nil
        case .unreadable, .unknown: throw RemoteUnlockStoreError.enrollmentUnreadable
        }
    }

    private func readEpoch() async -> String? {
        guard let data = try? await backend.read(Self.epochItem),
              let epoch = try? JSONDecoder().decode(RemoteUnlockEpoch.self, from: data),
              epoch.formatVersion == RemoteUnlockEpoch.currentFormatVersion,
              !epoch.buildIdentity.isEmpty else { return nil }
        return epoch.buildIdentity
    }

    /// Records this build as the one keeping the mirrors. A build with no
    /// identity deletes the epoch instead, so the next start clears them. A
    /// failure is logged and leaves the older epoch, which can only make the
    /// next start clear mirrors it could have kept.
    private func writeEpoch() async {
        do {
            if let buildIdentity, !buildIdentity.isEmpty {
                let epoch = RemoteUnlockEpoch(
                    formatVersion: RemoteUnlockEpoch.currentFormatVersion, buildIdentity: buildIdentity
                )
                try await backend.write(Self.epochItem, data: try JSONEncoder().encode(epoch))
            } else {
                try await backend.delete(Self.epochItem)
            }
        } catch {
            Self.log("epoch not recorded (\(error)); the next start clears the mirrors")
        }
    }

    private func deleteAllMirrorItems() async throws {
        var firstFailure: Error?
        for account in try await backend.accounts(service: Self.mirrorService) {
            do {
                try await backend.delete(RemoteUnlockItemName(service: Self.mirrorService, account: account))
            } catch {
                firstFailure = firstFailure ?? error
            }
        }
        if let firstFailure { throw firstFailure }
    }

    static func mirrorItem(_ kind: RemoteUnlockMirrorKind) -> RemoteUnlockItemName {
        RemoteUnlockItemName(service: mirrorService, account: kind.account)
    }

    /// kind ‖ name ‖ enrollment ID, length-prefixed: a mirror opens only
    /// under the name and enrollment it was sealed for.
    static func sealContext(_ kind: RemoteUnlockMirrorKind, enrollmentID: String) -> Data {
        canonicalBytes([
            mirrorContextDomain, Data(kind.tag.utf8), Data(kind.name.utf8), Data(enrollmentID.utf8),
        ])
    }

    static func canonicalBytes(_ fields: [Data]) -> Data {
        var data = Data()
        for field in fields {
            let count = UInt32(field.count)
            data.append(contentsOf: [
                UInt8((count >> 24) & 0xff), UInt8((count >> 16) & 0xff),
                UInt8((count >> 8) & 0xff), UInt8(count & 0xff),
            ])
            data.append(field)
        }
        return data
    }

    private static func status(of error: Error) -> OSStatus {
        if case let RemoteUnlockStoreError.keychain(_, status) = error { return status }
        return errSecInternalError
    }

    static func log(_ message: String) {
        FileHandle.standardError.write(Data("csecd: remote unlock: \(message)\n".utf8))
    }
}
