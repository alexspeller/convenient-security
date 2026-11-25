import Foundation
import Security
import CSECBuildIdentity

/// One csecd-only document slot in the data-protection Keychain.
///
/// Threat model (measured with an unentitled same-UID binary; the signed
/// `packaging/spike` probe re-proves it on a Developer ID build): every item
/// here lives in csecd's restricted access group, which only the app bundle's
/// main executable may claim; AMFI kills any other binary that claims it. A
/// same-UID process outside the group can therefore neither read, write, add,
/// delete nor roll back these items, so a document needs no tamper detection of
/// its own: what csecd loads is what csecd last stored. That process can still
/// kill csecd or drive the genuine `csec` over the socket, so a document must
/// never hold more authority than csecd would grant again through its
/// authenticated paths.
///
/// The items carry no biometric ACL and are readable from the first unlock after
/// boot: csecd loads them at startup without a prompt, including after a crash
/// while the screen is locked. Consent lives in csecd's mutation paths, never in
/// the item.
public struct ProtectedItem: Sendable, Hashable, CustomStringConvertible {
    public let service: String
    public let account: String
    /// The largest encoded document this item accepts on write or on read.
    public let maximumBytes: Int

    /// Set explicitly on every item rather than inherited from the first
    /// `keychain-access-groups` entry: these items' protection *is* this group,
    /// so adding a second entry to the entitlement must not silently move them.
    public static let accessGroup = CSECBuildIdentity.keychainAccessGroup

    public static let delegationSettings = ProtectedItem(
        service: CSECBuildIdentity.named("delegation"), account: "settings-v1",
        maximumBytes: 256 * 1_024
    )
    /// The Claude Code registrations already bound to a running command, so
    /// a restarted csecd keeps serving commands that outlived it.
    public static let delegationRegistrations = ProtectedItem(
        service: CSECBuildIdentity.named("delegation"), account: "registrations-v1",
        maximumBytes: 1_024 * 1_024
    )
    public static let grants = ProtectedItem(
        service: CSECBuildIdentity.named("grants"), account: "live-v1",
        maximumBytes: 1_024 * 1_024
    )
    public static let pairing = ProtectedItem(
        service: CSECBuildIdentity.named("pairing"), account: "v1",
        maximumBytes: 512 * 1_024
    )
    public static let lastRun = ProtectedItem(
        service: CSECBuildIdentity.named("runtime"), account: "last-run-v1",
        maximumBytes: 4 * 1_024
    )
    /// One 32-byte key inside its JSON envelope (under 100 bytes encoded).
    public static let decisionLogKey = ProtectedItem(
        service: CSECBuildIdentity.named("decision-log"), account: "key-v1",
        maximumBytes: 512
    )
    public static let decisionLogCheckpoint = ProtectedItem(
        service: CSECBuildIdentity.named("decision-log"), account: "head-v1",
        maximumBytes: 4 * 1_024
    )
    public static let baselinePointer = ProtectedItem(
        service: CSECBuildIdentity.named("baseline"), account: "pointer-v1",
        maximumBytes: 4 * 1_024
    )

    /// Every in-flight automation run lease, so a restarted csecd keeps
    /// serving the jobs whose launchers outlived it.
    public static let automationRuns = ProtectedItem(
        service: CSECBuildIdentity.named("automation"), account: "runs-v1",
        maximumBytes: 128 * 1_024
    )

    /// The reference of the token csecd injects for `gh` (`GitHubProxyDocument`).
    public static let githubProxy = ProtectedItem(
        service: CSECBuildIdentity.named("github-proxy"), account: "settings-v1",
        maximumBytes: 8 * 1_024
    )

    /// The native-store backup's public material, folder and manifest.
    public static let nativeStoreBackup = ProtectedItem(
        service: CSECBuildIdentity.named("native-store-backup"), account: "v1",
        maximumBytes: 1_024 * 1_024
    )

    /// The machine identities' key handles and sign-in targets
    /// (`MachineIdentityDocument`). A Secure Enclave handle signs for any
    /// process that holds it, so it must never leave this group.
    public static let machineIdentity = ProtectedItem(
        service: CSECBuildIdentity.named("machine-identity"), account: "catalog-v1",
        maximumBytes: 128 * 1_024
    )

    public static let all: [ProtectedItem] = [
        .delegationSettings, .delegationRegistrations, .grants, .pairing, .lastRun,
        .decisionLogKey, .decisionLogCheckpoint, .baselinePointer, .automationRuns,
        .githubProxy,
        .nativeStoreBackup,
        .machineIdentity,
    ]

    private init(service: String, account: String, maximumBytes: Int) {
        self.service = service
        self.account = account
        self.maximumBytes = maximumBytes
    }

    public var description: String { "\(service)/\(account)" }

    /// What the item holds, for `csec status` and the decision log.
    public var displayName: String {
        switch self {
        case .delegationSettings: return "the Claude Code auto-mode settings"
        case .delegationRegistrations: return "the Claude Code auto-mode registrations"
        case .grants: return "the saved grants"
        case .pairing: return "the auto-mode project pairings"
        case .lastRun: return "the last-run record"
        case .decisionLogKey: return "the decision log's key"
        case .decisionLogCheckpoint: return "the decision log's checkpoint"
        case .baselinePointer: return "the host-audit baseline pointer"
        case .automationRuns: return "the automation run leases"
        case .githubProxy: return "the GitHub token proxy registration"
        case .nativeStoreBackup: return "the native-store backup settings"
        case .machineIdentity: return "the machine identity catalog"
        default: return description
        }
    }

    /// What deletes this item when csecd cannot read it.
    public var discardCommand: String {
        switch self {
        case .delegationSettings, .delegationRegistrations: return "turning delegated approvals off in csec setup"
        case .grants, .pairing: return "csec revoke --all"
        case .githubProxy: return "csec github remove"
        case .nativeStoreBackup: return "csec backup off"
        default: return "csec uninstall"
        }
    }

    /// The exact dictionary each `SecItem` call sends for this item. Every
    /// operation names the explicit group, the data-protection Keychain and
    /// `synchronizable = false`; creation also fixes the accessibility class.
    /// None sets `kSecAttrAccessControl`: the item never carries a biometric
    /// ACL, so reading it never prompts. Matching deliberately omits the class
    /// so a write or delete still finds the item whatever class it holds.
    public func keychainQuery(for operation: ProtectedKeychainOperation) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: Self.accessGroup,
            kSecAttrSynchronizable as String: false,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        switch operation {
        case .read:
            query[kSecReturnData as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
        case .add:
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .update, .delete:
            break
        }
        return query
    }
}

public enum ProtectedKeychainOperation: String, Sendable, Equatable, CaseIterable {
    case read
    case update
    case add
    case delete
}

/// A document persisted in one protected item. The store wraps it in an
/// envelope that carries `formatVersion`, so a document type neither encodes
/// nor checks its own version.
///
/// Any change to the encoded shape bumps `formatVersion`. `JSONDecoder` ignores
/// unknown keys, so a field added without a bump would be dropped silently when
/// an older csecd rewrites the item; with a bump the older build reads the item
/// as unreadable and leaves it for the build that wrote it. The build that bumps
/// the version keeps reading items written before the bump through `migrate`.
///
/// Each item is bound to exactly one document type per backend: the first type
/// to ask `ProtectedStores` for a store on an item owns it, and a store for any
/// other type on that item can neither read nor write it.
///
/// An item this build loads as unreadable is held for the rest of the process
/// (see `ProtectedStore.load()`): it is never overwritten or deleted, except by
/// `prepareDiscard()` or uninstall, so an older csecd, or a Keychain read that
/// failed, can never erase what the build that wrote it recorded.
public protocol ProtectedDocument: Codable, Sendable {
    /// The one item this document type is stored in.
    static var protectedItem: ProtectedItem { get }
    /// The only envelope version this build writes, and the only one it reads
    /// without `migrate`.
    static var formatVersion: Int { get }
    /// Bounds and invariants decoding cannot express. Checked before every
    /// write and after every read, including a migrated read.
    var isWellFormed: Bool { get }
    /// Converts an item written under an older `formatVersion` into the current
    /// document, or returns `nil` to leave it unreadable. Only versions below
    /// `formatVersion` reach it; a newer version is always unreadable. The
    /// default migrates nothing.
    static func migrate(from legacy: ProtectedLegacyDocument) -> Self?
    /// Whether an unreadable item of this type is held rather than overwritten.
    /// Only a document that records no human decision and that csecd rewrites
    /// whole from its own state may opt out. The default holds.
    static var holdsUnreadableItem: Bool { get }
}

extension ProtectedDocument {
    public static func migrate(from legacy: ProtectedLegacyDocument) -> Self? { nil }
    public static var holdsUnreadableItem: Bool { true }
}

/// An item written under an older format version, as `migrate` sees it.
public struct ProtectedLegacyDocument: Sendable {
    public let formatVersion: Int
    private let data: Data

    init(formatVersion: Int, data: Data) {
        self.formatVersion = formatVersion
        self.data = data
    }

    /// Decodes the enveloped document as `type`, the shape that version wrote,
    /// or returns `nil` when the item is not that shape.
    public func decode<Legacy: Decodable>(_ type: Legacy.Type) -> Legacy? {
        (try? JSONDecoder().decode(LegacyEnvelope<Legacy>.self, from: data))?.document
    }

    private struct LegacyEnvelope<Legacy: Decodable>: Decodable {
        let document: Legacy
    }
}

/// What a protected item held. `unreadable` is not `absent`: the item exists
/// but this build cannot accept it, and each consumer decides what that means
/// (for delegation settings: delegation stays off and `csec status` says why).
/// The item is left exactly as found, because a newer csecd may read what this
/// one cannot: the store holds it (`ProtectedStoreError.held`) for the rest of
/// the process, so a consumer that starts empty cannot write over it.
public enum ProtectedLoad<Document: ProtectedDocument>: Sendable {
    case absent
    case document(Document)
    case unreadable(ProtectedUnreadableReason)
}

extension ProtectedLoad: Equatable where Document: Equatable {}

public enum ProtectedUnreadableReason: Error, Sendable, Equatable, CustomStringConvertible {
    /// The Keychain refused the read (for example before the first unlock).
    case keychainError(OSStatus)
    case oversized(byteCount: Int, maximum: Int)
    /// Not JSON, trailing bytes after the value, or not this document's shape.
    case invalidJSON
    /// Written by a newer format version, or by an older one `migrate` declined.
    case unsupportedFormatVersion(found: Int, supported: Int)
    /// Decoded, but the document's own bounds check failed.
    case notWellFormed
    /// The item belongs to another document type; this store never reads it.
    case itemBoundToAnotherDocument(String)

    /// Whether the store holds an item it loaded for this reason. An item from
    /// an older format that `migrate` declined is not held: no build that
    /// reads it remains, since every newer one declines it too. Another
    /// document type's item is refused by its binding instead.
    var holdsItem: Bool {
        switch self {
        case let .unsupportedFormatVersion(found, supported): return found > supported
        case .itemBoundToAnotherDocument: return false
        case .keychainError, .oversized, .invalidJSON, .notWellFormed: return true
        }
    }

    /// Written by a build newer than this one.
    public var isNewerFormat: Bool {
        if case let .unsupportedFormatVersion(found, supported) = self { return found > supported }
        return false
    }

    public var description: String {
        switch self {
        case let .keychainError(status):
            return "the Keychain read failed (\(osStatusDescription(status)))"
        case let .oversized(byteCount, maximum):
            return "\(byteCount) bytes exceeds the \(maximum)-byte limit"
        case .invalidJSON:
            return "not a valid encoding of this document"
        case let .unsupportedFormatVersion(found, supported):
            return "format version \(found) is not the supported version \(supported)"
        case .notWellFormed:
            return "the document failed its bounds check"
        case let .itemBoundToAnotherDocument(owner):
            return "the item belongs to \(owner)"
        }
    }
}

/// Why `prepare(_:)` refused a document. Nothing was sent to the Keychain, so
/// the item still holds whatever it held before.
public enum ProtectedDocumentRejection: Sendable, Equatable, CustomStringConvertible {
    case notWellFormed
    case unencodable
    case oversized(byteCount: Int, maximum: Int)
    /// The encoded bytes would not load back as a well-formed document, so
    /// writing them would leave an item the next start reads as unreadable.
    case doesNotRoundTrip

    public var description: String {
        switch self {
        case .notWellFormed: return "the document failed its bounds check"
        case .unencodable: return "the document could not be encoded"
        case let .oversized(byteCount, maximum):
            return "\(byteCount) bytes exceeds the \(maximum)-byte limit"
        case .doesNotRoundTrip: return "the encoded document does not load back"
        }
    }
}

public enum ProtectedStoreError: Error, Sendable, Equatable, CustomStringConvertible {
    /// Refused before any Keychain call; the item is unchanged. A caller for
    /// whom the previous document must not survive (a synchronous revoke)
    /// follows this with a committed `prepareDeletion()`.
    case rejected(ProtectedDocumentRejection)
    /// The write failed and the item was deleted instead, so it is now absent.
    case writeFailedItemDeleted(write: OSStatus)
    /// The write failed and so did the fallback delete: the item may still
    /// hold an earlier document. A caller that must not leave that document
    /// behind (a synchronous revoke) reports this rather than succeeding.
    case writeAndDeleteFailed(write: OSStatus, delete: OSStatus)
    /// A deletion failed; the item may still be present.
    case deleteFailed(OSStatus)
    /// A later change to this item was committed first and failed to settle
    /// it, so this older change was skipped and the item may still hold an
    /// earlier document than this one.
    case supersededByUnsettledChange(sequence: UInt64)
    /// Reported only by a deletion batch: a newer change to the item was
    /// committed first, so its deletion was skipped and the item may hold that
    /// change's document. A single change returns `.superseded` instead.
    case supersededByNewerChange(sequence: UInt64)
    /// The item belongs to another document type; nothing was sent.
    case itemBoundToAnotherDocument(String)
    /// This process loaded the item as unreadable, so it is kept as found for
    /// the build that can read it: nothing was sent. What the caller meant to
    /// write holds for this process only.
    case held(ProtectedUnreadableReason)
    /// csecd is being uninstalled: every write is refused from the moment
    /// cleanup begins, so nothing it deletes can be recreated behind it.
    /// Nothing was sent.
    case uninstalled

    /// Whether the item is known to be absent after this error.
    public var itemIsAbsent: Bool {
        if case .writeFailedItemDeleted = self { return true }
        return false
    }

    public var description: String {
        switch self {
        case let .rejected(reason):
            return "protected document refused: \(reason)"
        case let .writeFailedItemDeleted(write):
            return "protected item write failed (\(osStatusDescription(write))); the item was deleted"
        case let .writeAndDeleteFailed(write, delete):
            return "protected item write failed (\(osStatusDescription(write))) and the fallback "
                + "delete also failed (\(osStatusDescription(delete))); an earlier document may remain"
        case let .deleteFailed(status):
            return "protected item delete failed (\(osStatusDescription(status)))"
        case let .supersededByUnsettledChange(sequence):
            return "a later change (\(sequence)) to this protected item failed; an earlier document may remain"
        case let .supersededByNewerChange(sequence):
            return "a newer change (\(sequence)) to this protected item came first; it may still hold a document"
        case let .itemBoundToAnotherDocument(owner):
            return "protected item belongs to \(owner)"
        case let .held(reason):
            return "the saved item is kept as found because this csecd cannot read it (\(reason))"
        case .uninstalled:
            return "csecd is uninstalling; protected items are no longer written"
        }
    }
}

/// How a committed change ended when it did not throw.
public enum ProtectedCommitResult: Sendable, Equatable {
    case applied
    /// A later change to the item was committed first and settled it, so this
    /// one was skipped: the item already reflects a newer state than this
    /// change carried. Nothing was sent to the Keychain.
    case superseded(by: UInt64)
}

/// A write or deletion with its place in the item's change order. The place
/// is taken when the change is prepared, not when it is committed: commits
/// hop off the caller's actor and can reach the backend in any order, and the
/// backend applies only a change newer than the last one it applied. A stale
/// change is skipped whole, so a stale write that would fail can never delete
/// a newer document.
public struct ProtectedChange: Sendable {
    public let item: ProtectedItem
    /// Increasing per item and backend, in the order changes were prepared.
    public let sequence: UInt64
    private let payload: ProtectedItemChange
    private let backend: any ProtectedItemBackend

    fileprivate init(
        item: ProtectedItem,
        sequence: UInt64,
        payload: ProtectedItemChange,
        backend: any ProtectedItemBackend
    ) {
        self.item = item
        self.sequence = sequence
        self.payload = payload
        self.backend = backend
    }

    /// Applies the change unless a later one already has. A write that fails
    /// deletes the item instead; see `ProtectedStoreError` for what each
    /// failure leaves behind.
    @discardableResult
    public func commit() async throws -> ProtectedCommitResult {
        switch await backend.commit(payload, sequence: sequence, to: item) {
        case .applied:
            return .applied
        case let .superseded(latest):
            return .superseded(by: latest)
        case let .supersededUnsettled(latest):
            throw ProtectedStoreError.supersededByUnsettledChange(sequence: latest)
        case let .writeFailedItemDeleted(write):
            throw ProtectedStoreError.writeFailedItemDeleted(write: write)
        case let .writeAndDeleteFailed(write, delete):
            throw ProtectedStoreError.writeAndDeleteFailed(write: write, delete: delete)
        case let .deleteFailed(status):
            throw ProtectedStoreError.deleteFailed(status)
        case .refusedUninstalled:
            throw ProtectedStoreError.uninstalled
        }
    }
}

/// Typed access to the one item `Document` is bound to. Loads never write.
/// Every change is prepared synchronously, which fixes its place in the item's
/// order, and then committed:
///
///     // on the actor that owns the persisted state
///     let change = try store.prepare(snapshot())
///     Task { try? await change.commit() }        // write-behind
///     try await store.prepare(snapshot()).commit() // synchronous
///
/// Prepare in the same synchronous section that built the document, on the
/// one actor that owns the item's state: a later-prepared change must carry a
/// later state, because it is the one that survives.
public struct ProtectedStore<Document: ProtectedDocument>: Sendable {
    private let backend: any ProtectedItemBackend
    /// The type that owns the item when it is not `Document`.
    private let owner: String?

    fileprivate init(backend: any ProtectedItemBackend, owner: String?) {
        self.backend = backend
        self.owner = owner
    }

    public var item: ProtectedItem { Document.protectedItem }

    /// Reads the item. One this build cannot read (a newer format, a failed
    /// Keychain read, damaged bytes) is held from then on, for the life of the
    /// backend (the process, for the real Keychain): `prepare` and
    /// `prepareDeletion` refuse it with `.held`, so a consumer that starts
    /// empty cannot write its empty state over it. On 14 Oct 2026 an older
    /// csecd, installed for 25 minutes, read the newer pairing format as
    /// unreadable and overwrote every project pairing with its first new one.
    /// A later load that reads the item (or finds it absent) lifts the hold,
    /// because its caller now holds what the item holds: only a consumer that
    /// adopts what it reloads may load an item twice.
    public func load() async -> ProtectedLoad<Document> {
        if let owner { return .unreadable(.itemBoundToAnotherDocument(owner)) }
        let result: ProtectedLoad<Document>
        switch await backend.read(item) {
        case .absent:
            result = .absent
        case let .failed(status):
            result = .unreadable(.keychainError(status))
        case let .bytes(data):
            result = Self.decode(data)
        }
        switch result {
        case let .unreadable(reason):
            if reason.holdsItem, Document.holdsUnreadableItem { backend.ledger.hold(item, reason: reason) }
        case .absent, .document:
            backend.ledger.release(item)
        }
        return result
    }

    /// Why this process keeps the item as found, or `nil` when it may write it.
    public var heldReason: ProtectedUnreadableReason? {
        owner == nil ? backend.ledger.heldReason(for: item) : nil
    }

    /// Encodes `document` and takes the item's next place in its change order.
    /// Throws `.rejected` without taking a place when the document is refused,
    /// `.held` when this process could not read the item, and `.uninstalled`
    /// once csecd's uninstall cleanup has begun.
    public func prepare(_ document: Document) throws -> ProtectedChange {
        if let owner { throw ProtectedStoreError.itemBoundToAnotherDocument(owner) }
        if backend.ledger.isUninstalled { throw ProtectedStoreError.uninstalled }
        if let reason = backend.ledger.heldReason(for: item) { throw ProtectedStoreError.held(reason) }
        let data = try Self.encode(document)
        return ProtectedChange(
            item: item, sequence: backend.ledger.nextSequence(for: item),
            payload: .write(data), backend: backend
        )
    }

    /// Takes the item's next place for a deletion. Deleting an absent item
    /// succeeds. Throws `.held` when this process could not read the item:
    /// emptying what it holds is no reason to delete what it never read.
    public func prepareDeletion() throws -> ProtectedChange {
        if let owner { throw ProtectedStoreError.itemBoundToAnotherDocument(owner) }
        if let reason = backend.ledger.heldReason(for: item) { throw ProtectedStoreError.held(reason) }
        return ProtectedChange(
            item: item, sequence: backend.ledger.nextSequence(for: item),
            payload: .delete, backend: backend
        )
    }

    /// A deletion that goes ahead even when the item is held, and lifts the
    /// hold once the item is gone. Only for a human's explicit request to
    /// remove everything the item grants (`csec revoke --all`, turning
    /// delegation off): keeping an item this csecd cannot read would hand that
    /// authority back at the next upgrade. A discard that fails leaves the item
    /// held. `csec uninstall` deletes through `prepareDeletionOfAll()`.
    public func prepareDiscard() throws -> ProtectedChange {
        if let owner { throw ProtectedStoreError.itemBoundToAnotherDocument(owner) }
        return ProtectedChange(
            item: item, sequence: backend.ledger.nextSequence(for: item),
            payload: .discard, backend: backend
        )
    }

    static func decode(_ data: Data) -> ProtectedLoad<Document> {
        let maximum = Document.protectedItem.maximumBytes
        guard data.count <= maximum else {
            return .unreadable(.oversized(byteCount: data.count, maximum: maximum))
        }
        let decoder = JSONDecoder()
        // The version is read on its own first, so a newer document whose body
        // this build cannot decode is reported as a version, not as corruption.
        guard let header = try? decoder.decode(ProtectedEnvelopeHeader.self, from: data) else {
            return .unreadable(.invalidJSON)
        }
        let document: Document
        if header.formatVersion == Document.formatVersion {
            guard let envelope = try? decoder.decode(
                ProtectedEnvelope<Document>.self, from: data
            ) else {
                return .unreadable(.invalidJSON)
            }
            document = envelope.document
        } else if header.formatVersion < Document.formatVersion,
                  let migrated = Document.migrate(from: ProtectedLegacyDocument(
                      formatVersion: header.formatVersion, data: data
                  )) {
            document = migrated
        } else {
            return .unreadable(.unsupportedFormatVersion(
                found: header.formatVersion, supported: Document.formatVersion
            ))
        }
        guard document.isWellFormed else { return .unreadable(.notWellFormed) }
        return .document(document)
    }

    static func encode(_ document: Document) throws -> Data {
        guard document.isWellFormed else {
            throw ProtectedStoreError.rejected(.notWellFormed)
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let envelope = ProtectedEnvelope(formatVersion: Document.formatVersion, document: document)
        guard let data = try? encoder.encode(envelope) else {
            throw ProtectedStoreError.rejected(.unencodable)
        }
        let maximum = Document.protectedItem.maximumBytes
        guard data.count <= maximum else {
            throw ProtectedStoreError.rejected(.oversized(byteCount: data.count, maximum: maximum))
        }
        // Refuse what `load` would call unreadable, so an asymmetric Codable
        // conformance fails at the write instead of at the next csecd start.
        guard case .document = decode(data) else {
            throw ProtectedStoreError.rejected(.doesNotRoundTrip)
        }
        return data
    }
}

private struct ProtectedEnvelopeHeader: Decodable {
    let formatVersion: Int
}

private struct ProtectedEnvelope<Document: ProtectedDocument>: Codable {
    let formatVersion: Int
    let document: Document
}

/// csecd's protected items as one value its services are handed. Release csecd
/// builds it only when the startup Keychain probe proved the access group is
/// usable; without it, the features these items back stay off instead of
/// persisting anywhere weaker. DEBUG builds without the group use
/// `processLocal()`, which keeps nothing past the process.
public struct ProtectedStores: Sendable {
    public enum Persistence: String, Sendable, Equatable {
        case dataProtectionKeychain = "data-protection keychain"
        case processLocal = "process-local"
    }

    public let persistence: Persistence
    private let backend: any ProtectedItemBackend

    private init(persistence: Persistence, backend: any ProtectedItemBackend) {
        self.persistence = persistence
        self.backend = backend
    }

    /// The real Keychain. Every value shares one process-wide change order and
    /// one binding of items to document types, because they share the items.
    public static func dataProtectionKeychain() -> ProtectedStores {
        ProtectedStores(
            persistence: .dataProtectionKeychain,
            backend: KeychainProtectedItemBackend(
                functions: .system, ledger: KeychainProtectedItemBackend.systemLedger
            )
        )
    }

    /// The Keychain backend over substitute `SecItem` functions, with a ledger
    /// of its own, so a test can see exactly what each call receives. csecd
    /// uses `dataProtectionKeychain()`; bin/ci keeps this out of shipping code.
    public static func dataProtectionKeychain(calling functions: ProtectedKeychainFunctions) -> ProtectedStores {
        ProtectedStores(
            persistence: .dataProtectionKeychain,
            backend: KeychainProtectedItemBackend(functions: functions, ledger: ProtectedItemLedger())
        )
    }

    /// In-memory items. Two values built over the same backend share its
    /// items, change order and bindings, which is how a test models csecd
    /// restarting over surviving items.
    public static func processLocal(
        _ backend: InMemoryProtectedItemBackend = InMemoryProtectedItemBackend()
    ) -> ProtectedStores {
        ProtectedStores(persistence: .processLocal, backend: backend)
    }

    /// The store for `Document`'s item. The first type to ask for an item owns
    /// it on this backend; a store for another type on that item refuses every
    /// read and write, so two types can never overwrite each other.
    public func store<Document: ProtectedDocument>(
        for type: Document.Type = Document.self
    ) -> ProtectedStore<Document> {
        ProtectedStore(
            backend: backend,
            owner: backend.ledger.bind(Document.protectedItem, to: Document.self)
        )
    }

    /// Takes every protected item's next place for a deletion, synchronously,
    /// so a change prepared earlier can no longer recreate any item.
    ///
    /// The result is exact only once nothing else writes: a change an owner
    /// prepares after this call is newer and wins, and its item is reported as
    /// possibly remaining. Stop every owner's writes first (csecd enters its
    /// uninstalled state before deleting).
    public func prepareDeletionOfAll() -> ProtectedDeletionBatch {
        ProtectedDeletionBatch(deletions: ProtectedItem.all.map {
            ProtectedChange(
                item: $0, sequence: backend.ledger.nextSequence(for: $0),
                payload: .delete, backend: backend
            )
        })
    }

    /// `prepareDeletionOfAll()` committed at once; the same caveat applies.
    public func deleteAll() async -> [ProtectedItem: ProtectedStoreError] {
        await prepareDeletionOfAll().commit()
    }

    /// The terminal state `csec uninstall` puts csecd in. From this call on,
    /// every write to every protected item is refused: at `prepare`, and again
    /// inside the backend's exclusive section for a change prepared earlier
    /// and committed later. Deletions still run, since deleting is what
    /// uninstall does. It is one switch for all items because the backend's
    /// ledger is the one place every change passes through; csecd's other
    /// persistence (the decision log's files, the shutdown flush, the sealed
    /// baseline) consults `isUninstalled` before writing. There is no way
    /// back: the process is about to be unregistered.
    ///
    /// Enter it before `prepareDeletionOfAll()`, so no owner can prepare a
    /// newer write that would outlive the deletion.
    public func enterUninstalledState() {
        backend.ledger.enterUninstalled()
    }

    /// Whether `enterUninstalledState()` has been called on this backend. For
    /// the real Keychain the state is process-wide, like its change order.
    public var isUninstalled: Bool {
        backend.ledger.isUninstalled
    }

    /// Every item this process loaded as unreadable and keeps as found, in
    /// `ProtectedItem.all` order.
    public var heldItems: [(item: ProtectedItem, reason: ProtectedUnreadableReason)] {
        ProtectedItem.all.compactMap { item in
            backend.ledger.heldReason(for: item).map { (item, $0) }
        }
    }
}

/// A deletion of every protected item whose places are already taken.
public struct ProtectedDeletionBatch: Sendable {
    private let deletions: [ProtectedChange]

    fileprivate init(deletions: [ProtectedChange]) {
        self.deletions = deletions
    }

    /// Commits each deletion, trying every item even after a failure, and
    /// returns the items that may remain: a deletion that failed, and one a
    /// newer change superseded, since that change may have written the item.
    public func commit() async -> [ProtectedItem: ProtectedStoreError] {
        var remaining: [ProtectedItem: ProtectedStoreError] = [:]
        for deletion in deletions {
            do {
                if case let .superseded(latest) = try await deletion.commit() {
                    remaining[deletion.item] = .supersededByNewerChange(sequence: latest)
                }
            } catch let error as ProtectedStoreError {
                remaining[deletion.item] = error
            } catch {
                remaining[deletion.item] = .deleteFailed(errSecInternalError)
            }
        }
        return remaining
    }
}

/// The four Security calls the Keychain backend makes, as the dictionaries it
/// passes them. Production uses `system`; a test substitutes recorders to prove
/// every call carries the explicit group and the right shape.
public struct ProtectedKeychainFunctions: Sendable {
    public var copyMatching: @Sendable (_ query: [String: Any]) -> (status: OSStatus, data: Data?)
    public var update: @Sendable (_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus
    public var add: @Sendable (_ attributes: [String: Any]) -> OSStatus
    public var delete: @Sendable (_ query: [String: Any]) -> OSStatus

    public init(
        copyMatching: @escaping @Sendable (_ query: [String: Any]) -> (status: OSStatus, data: Data?),
        update: @escaping @Sendable (_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus,
        add: @escaping @Sendable (_ attributes: [String: Any]) -> OSStatus,
        delete: @escaping @Sendable (_ query: [String: Any]) -> OSStatus
    ) {
        self.copyMatching = copyMatching
        self.update = update
        self.add = add
        self.delete = delete
    }

    public static let system = ProtectedKeychainFunctions(
        copyMatching: { query in
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return (status, result as? Data)
        },
        update: { query, attributes in
            SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        },
        add: { attributes in SecItemAdd(attributes as CFDictionary, nil) },
        delete: { query in SecItemDelete(query as CFDictionary) }
    )
}

enum ProtectedItemRead: Sendable {
    case absent
    case bytes(Data)
    case failed(OSStatus)
}

enum ProtectedItemChange: Sendable {
    case write(Data)
    case delete
    /// A deletion that also lifts the item's hold once the item is gone.
    case discard
}

enum ProtectedCommitOutcome: Sendable {
    case applied
    case superseded(UInt64)
    case supersededUnsettled(UInt64)
    case writeFailedItemDeleted(write: OSStatus)
    case writeAndDeleteFailed(write: OSStatus, delete: OSStatus)
    case deleteFailed(OSStatus)
    case refusedUninstalled
}

/// Per backend: the change order of every item and which document type owns
/// it. Sequences are handed out synchronously on the preparing caller's
/// executor; admission and settlement run inside the backend's exclusive
/// section, so the check against the last applied change and the change
/// itself are one step.
final class ProtectedItemLedger: @unchecked Sendable {
    enum Admission {
        case proceed
        case superseded(UInt64)
        case supersededUnsettled(UInt64)
    }

    private struct Applied {
        var sequence: UInt64
        /// Whether that change left the item holding its document or absent.
        var settled: Bool
    }

    private let lock = NSLock()
    private var uninstalled = false
    private var held: [ProtectedItem: ProtectedUnreadableReason] = [:]
    private var issued: [ProtectedItem: UInt64] = [:]
    private var applied: [ProtectedItem: Applied] = [:]
    private var owners: [ProtectedItem: (type: ObjectIdentifier, name: String)] = [:]

    func nextSequence(for item: ProtectedItem) -> UInt64 {
        lock.lock(); defer { lock.unlock() }
        let next = (issued[item] ?? 0) + 1
        issued[item] = next
        return next
    }

    func admit(_ item: ProtectedItem, sequence: UInt64) -> Admission {
        lock.lock(); defer { lock.unlock() }
        guard let last = applied[item], sequence <= last.sequence else { return .proceed }
        return last.settled ? .superseded(last.sequence) : .supersededUnsettled(last.sequence)
    }

    /// Keeps the first reason: a later load cannot make the item writable.
    func hold(_ item: ProtectedItem, reason: ProtectedUnreadableReason) {
        lock.lock(); defer { lock.unlock() }
        if held[item] == nil { held[item] = reason }
    }

    func release(_ item: ProtectedItem) {
        lock.lock(); defer { lock.unlock() }
        held[item] = nil
    }

    func heldReason(for item: ProtectedItem) -> ProtectedUnreadableReason? {
        lock.lock(); defer { lock.unlock() }
        return held[item]
    }

    func enterUninstalled() {
        lock.lock(); defer { lock.unlock() }
        uninstalled = true
    }

    var isUninstalled: Bool {
        lock.lock(); defer { lock.unlock() }
        return uninstalled
    }

    func settle(_ item: ProtectedItem, sequence: UInt64, settled: Bool) {
        lock.lock(); defer { lock.unlock() }
        applied[item] = Applied(sequence: sequence, settled: settled)
    }

    /// Binds `item` to `type` if it is unbound, and returns the owning type's
    /// name when another type already holds it.
    func bind(_ item: ProtectedItem, to type: Any.Type) -> String? {
        lock.lock(); defer { lock.unlock() }
        let identifier = ObjectIdentifier(type)
        if let owner = owners[item] {
            return owner.type == identifier ? nil : owner.name
        }
        owners[item] = (identifier, String(reflecting: type))
        return nil
    }
}

/// A place protected items live. Each read and each commit runs as one
/// exclusive section on the backend, and a commit's admission against the
/// item's change order happens inside it.
protocol ProtectedItemBackend: Sendable {
    var ledger: ProtectedItemLedger { get }
    func read(_ item: ProtectedItem) async -> ProtectedItemRead
    func commit(
        _ change: ProtectedItemChange, sequence: UInt64, to item: ProtectedItem
    ) async -> ProtectedCommitOutcome
}

/// The four status-level operations both backends provide. The sequences built
/// on them are written once here, so an injected in-memory failure exercises
/// exactly the path a Keychain failure takes.
protocol ProtectedItemPrimitives {
    mutating func copy(_ item: ProtectedItem) -> (status: OSStatus, data: Data?)
    mutating func update(_ item: ProtectedItem, data: Data) -> OSStatus
    mutating func add(_ item: ProtectedItem, data: Data) -> OSStatus
    mutating func delete(_ item: ProtectedItem) -> OSStatus
}

extension ProtectedItemPrimitives {
    mutating func read(_ item: ProtectedItem) -> ProtectedItemRead {
        let (status, data) = copy(item)
        switch status {
        case errSecSuccess:
            guard let data else { return .failed(errSecDecode) }
            return .bytes(data)
        case errSecItemNotFound:
            return .absent
        default:
            return .failed(status)
        }
    }

    /// Runs inside the backend's exclusive section. A stale change touches
    /// nothing; an applied one records whether it left the item settled. A
    /// write reaching the section after uninstall began is refused whole: it
    /// neither writes nor falls back to deleting, and takes no place.
    mutating func commit(
        _ change: ProtectedItemChange,
        sequence: UInt64,
        to item: ProtectedItem,
        ledger: ProtectedItemLedger
    ) -> ProtectedCommitOutcome {
        if case .write = change, ledger.isUninstalled {
            return .refusedUninstalled
        }
        switch ledger.admit(item, sequence: sequence) {
        case let .superseded(latest):
            return .superseded(latest)
        case let .supersededUnsettled(latest):
            return .supersededUnsettled(latest)
        case .proceed:
            break
        }
        let outcome: ProtectedCommitOutcome
        switch change {
        case let .write(data):
            outcome = writeOrDelete(data, to: item)
        case .delete, .discard:
            let status = delete(item)
            outcome = status == errSecSuccess || status == errSecItemNotFound
                ? .applied : .deleteFailed(status)
            if case .discard = change, case .applied = outcome { ledger.release(item) }
        }
        let settled: Bool
        switch outcome {
        case .applied, .writeFailedItemDeleted: settled = true
        default: settled = false
        }
        ledger.settle(item, sequence: sequence, settled: settled)
        return outcome
    }

    private mutating func writeOrDelete(_ data: Data, to item: ProtectedItem) -> ProtectedCommitOutcome {
        var status = update(item, data: data)
        if status == errSecItemNotFound {
            status = add(item, data: data)
        }
        if status == errSecSuccess { return .applied }
        let deleted = delete(item)
        guard deleted == errSecSuccess || deleted == errSecItemNotFound else {
            return .writeAndDeleteFailed(write: status, delete: deleted)
        }
        return .writeFailedItemDeleted(write: status)
    }
}

private struct SecItemPrimitives: ProtectedItemPrimitives {
    let functions: ProtectedKeychainFunctions

    func copy(_ item: ProtectedItem) -> (status: OSStatus, data: Data?) {
        functions.copyMatching(item.keychainQuery(for: .read))
    }

    func update(_ item: ProtectedItem, data: Data) -> OSStatus {
        functions.update(item.keychainQuery(for: .update), [kSecValueData as String: data])
    }

    func add(_ item: ProtectedItem, data: Data) -> OSStatus {
        var attributes = item.keychainQuery(for: .add)
        attributes[kSecValueData as String] = data
        return functions.add(attributes)
    }

    func delete(_ item: ProtectedItem) -> OSStatus {
        functions.delete(item.keychainQuery(for: .delete))
    }
}

private struct KeychainProtectedItemBackend: ProtectedItemBackend {
    /// The real items are process-wide, so their change order and bindings are too.
    static let systemLedger = ProtectedItemLedger()

    // One queue for every protected item and every instance: it is the
    // exclusive section each read and commit runs in, and it keeps the
    // blocking SecItem calls off the cooperative pool.
    private static let queue = DispatchQueue(
        label: CSECBuildIdentity.named("protected-items-keychain")
    )

    let functions: ProtectedKeychainFunctions
    let ledger: ProtectedItemLedger

    func read(_ item: ProtectedItem) async -> ProtectedItemRead {
        let functions = self.functions
        return await Self.blocking {
            var primitives = SecItemPrimitives(functions: functions)
            return primitives.read(item)
        }
    }

    func commit(
        _ change: ProtectedItemChange, sequence: UInt64, to item: ProtectedItem
    ) async -> ProtectedCommitOutcome {
        let functions = self.functions
        let ledger = self.ledger
        return await Self.blocking {
            var primitives = SecItemPrimitives(functions: functions)
            return primitives.commit(change, sequence: sequence, to: item, ledger: ledger)
        }
    }

    private static func blocking<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: body()) }
        }
    }
}

/// Process-local protected items: the DEBUG fallback when csecd lacks the
/// access group, and the double consumers use to prove their fail-safe paths.
/// It runs the same change order and write-or-delete sequence as the Keychain
/// backend, and a test can inject per-item failures, plant raw bytes, and read
/// back the operations each item saw.
public actor InMemoryProtectedItemBackend: ProtectedItemBackend {
    /// `OSStatus` values the matching operation returns instead of running.
    public struct Failures: Sendable, Equatable {
        public var read: OSStatus?
        public var update: OSStatus?
        public var add: OSStatus?
        public var delete: OSStatus?

        public init(
            read: OSStatus? = nil,
            update: OSStatus? = nil,
            add: OSStatus? = nil,
            delete: OSStatus? = nil
        ) {
            self.read = read
            self.update = update
            self.add = add
            self.delete = delete
        }

        /// Every write fails with `status`, whether it would update or add.
        public static func failingWrites(_ status: OSStatus, delete: OSStatus? = nil) -> Failures {
            Failures(update: status, add: status, delete: delete)
        }
    }

    nonisolated let ledger = ProtectedItemLedger()
    private var primitives = InMemoryProtectedItemPrimitives()

    public init() {}

    public func inject(_ failures: Failures, for item: ProtectedItem) {
        primitives.failures[item] = failures
    }

    /// Plants bytes as they would sit in the Keychain, bypassing encoding, or
    /// removes the item with `nil`. Not recorded as an operation.
    public func setRawBytes(_ data: Data?, for item: ProtectedItem) {
        primitives.items[item] = data
    }

    public func rawBytes(for item: ProtectedItem) -> Data? {
        primitives.items[item]
    }

    /// Every operation `item` saw, in order, including injected failures.
    public func operations(on item: ProtectedItem) -> [ProtectedKeychainOperation] {
        primitives.operations[item] ?? []
    }

    public func clearOperations() {
        primitives.operations = [:]
    }

    func read(_ item: ProtectedItem) -> ProtectedItemRead {
        primitives.read(item)
    }

    func commit(
        _ change: ProtectedItemChange, sequence: UInt64, to item: ProtectedItem
    ) -> ProtectedCommitOutcome {
        primitives.commit(change, sequence: sequence, to: item, ledger: ledger)
    }
}

private struct InMemoryProtectedItemPrimitives: ProtectedItemPrimitives {
    var items: [ProtectedItem: Data] = [:]
    var failures: [ProtectedItem: InMemoryProtectedItemBackend.Failures] = [:]
    var operations: [ProtectedItem: [ProtectedKeychainOperation]] = [:]

    mutating func copy(_ item: ProtectedItem) -> (status: OSStatus, data: Data?) {
        operations[item, default: []].append(.read)
        if let status = failures[item]?.read { return (status, nil) }
        guard let data = items[item] else { return (errSecItemNotFound, nil) }
        return (errSecSuccess, data)
    }

    mutating func update(_ item: ProtectedItem, data: Data) -> OSStatus {
        operations[item, default: []].append(.update)
        if let status = failures[item]?.update { return status }
        guard items[item] != nil else { return errSecItemNotFound }
        items[item] = data
        return errSecSuccess
    }

    mutating func add(_ item: ProtectedItem, data: Data) -> OSStatus {
        operations[item, default: []].append(.add)
        if let status = failures[item]?.add { return status }
        guard items[item] == nil else { return errSecDuplicateItem }
        items[item] = data
        return errSecSuccess
    }

    mutating func delete(_ item: ProtectedItem) -> OSStatus {
        operations[item, default: []].append(.delete)
        if let status = failures[item]?.delete { return status }
        guard items.removeValue(forKey: item) != nil else { return errSecItemNotFound }
        return errSecSuccess
    }
}

private func osStatusDescription(_ status: OSStatus) -> String {
    let detail = SecCopyErrorMessageString(status, nil).map { $0 as String } ?? "unknown"
    return "OSStatus \(status): \(detail)"
}
