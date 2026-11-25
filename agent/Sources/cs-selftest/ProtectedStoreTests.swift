import ConvenientSecurity
import Foundation
import Security
import CSECBuildIdentity

/// A synthetic document bound to the last-run item, so caps and bounds are
/// checked against a real item's limits. `count < 0` is its malformed shape.
private struct SyntheticRuntimeDocument: ProtectedDocument, Equatable {
    static let protectedItem = ProtectedItem.lastRun
    static let formatVersion = 3

    var label: String
    var count: Int

    var isWellFormed: Bool { count >= 0 }
}

/// A second type claiming the last-run item: the binding rule must lock it out.
private struct RivalRuntimeDocument: ProtectedDocument, Equatable {
    static let protectedItem = ProtectedItem.lastRun
    static let formatVersion = 3

    var label: String
    var count: Int

    var isWellFormed: Bool { true }
}

/// A second document type on another item, to show stores stay item-scoped.
private struct SyntheticPairingDocument: ProtectedDocument, Equatable {
    static let protectedItem = ProtectedItem.pairing
    static let formatVersion = 1

    var projects: [String]

    var isWellFormed: Bool { projects.count <= 8 }
}

/// The shape a grants owner persists: a generation it bumps on every change
/// and the live grant identifiers.
private struct SyntheticGrantsDocument: ProtectedDocument, Equatable {
    static let protectedItem = ProtectedItem.grants
    static let formatVersion = 1

    var generation: Int
    var grantIDs: [String]

    var isWellFormed: Bool { generation >= 0 }
}

/// Version 2 of a settings-like document; version 1 held a single `name`.
private struct VersionedSettingsDocument: ProtectedDocument, Equatable {
    static let protectedItem = ProtectedItem.delegationSettings
    static let formatVersion = 2

    var names: [String]
    var enabled: Bool

    var isWellFormed: Bool { !names.isEmpty && names.count <= 4 }

    private struct Version1: Decodable {
        let name: String
    }

    static func migrate(from legacy: ProtectedLegacyDocument) -> VersionedSettingsDocument? {
        guard legacy.formatVersion == 1, let old = legacy.decode(Version1.self) else { return nil }
        return VersionedSettingsDocument(names: old.name.isEmpty ? [] : [old.name], enabled: false)
    }
}

/// The pairing item as an older build saw it, one format behind the build
/// that wrote it: the shape of the 14 Oct 2026 downgrade.
private struct OlderPairingDocument: ProtectedDocument, Equatable {
    static let protectedItem = ProtectedItem.pairing
    static let formatVersion = 2

    var projects: [String]

    var isWellFormed: Bool { true }
}

/// The pairing item as the newer build wrote it.
private struct NewerPairingDocument: ProtectedDocument, Equatable {
    static let protectedItem = ProtectedItem.pairing
    static let formatVersion = 3

    var projects: [String]
    var sudo: Bool

    var isWellFormed: Bool { true }
}

/// Records nothing a human decided and is rewritten whole, so it opts out.
private struct RewrittenEachStartDocument: ProtectedDocument, Equatable {
    static let protectedItem = ProtectedItem.lastRun
    static let formatVersion = 1
    static let holdsUnreadableItem = false

    var pid: Int

    var isWellFormed: Bool { true }
}

/// Migrates anything it is shown, so a load that stays unreadable proves the
/// hook was never consulted.
private struct EagerMigrationDocument: ProtectedDocument, Equatable {
    static let protectedItem = ProtectedItem.delegationSettings
    static let formatVersion = 2

    var migrated: Bool

    var isWellFormed: Bool { true }

    static func migrate(from legacy: ProtectedLegacyDocument) -> EagerMigrationDocument? {
        EagerMigrationDocument(migrated: true)
    }
}

/// JSONEncoder refuses a non-finite Double, which makes this unencodable.
private struct MeasurementDocument: ProtectedDocument {
    static let protectedItem = ProtectedItem.decisionLogCheckpoint
    static let formatVersion = 1

    var ratio: Double

    var isWellFormed: Bool { true }
}

/// Encodes a key its decoder never reads: a document that cannot load back.
private struct AsymmetricDocument: ProtectedDocument {
    static let protectedItem = ProtectedItem.baselinePointer
    static let formatVersion = 1

    var generation: Int

    var isWellFormed: Bool { true }

    init(generation: Int) { self.generation = generation }

    private enum CodingKeys: String, CodingKey { case written, expected }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        generation = try container.decode(Int.self, forKey: .expected)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(generation, forKey: .written)
    }
}

/// Stands in for the four `SecItem` calls behind the production Keychain
/// backend: keeps items in memory, records every dictionary each call
/// receives, and fails an operation on request.
private final class RecordingKeychain: @unchecked Sendable {
    struct Call {
        let operation: ProtectedKeychainOperation
        let query: NSDictionary
        let attributes: NSDictionary?
    }

    private let lock = NSLock()
    private var items: [String: Data] = [:]
    private var recorded: [Call] = []
    private var failures: [ProtectedKeychainOperation: OSStatus] = [:]

    var functions: ProtectedKeychainFunctions {
        ProtectedKeychainFunctions(
            copyMatching: { query in self.copy(query) },
            update: { query, attributes in self.update(query, attributes) },
            add: { attributes in self.add(attributes) },
            delete: { query in self.delete(query) }
        )
    }

    var calls: [Call] {
        lock.lock(); defer { lock.unlock() }
        return recorded
    }

    func bytes(for item: ProtectedItem) -> Data? {
        lock.lock(); defer { lock.unlock() }
        return items[item.description]
    }

    func fail(_ operation: ProtectedKeychainOperation, with status: OSStatus?) {
        lock.lock(); defer { lock.unlock() }
        failures[operation] = status
    }

    func clearCalls() {
        lock.lock(); defer { lock.unlock() }
        recorded = []
    }

    private static func key(_ query: [String: Any]) -> String {
        "\(query[kSecAttrService as String] as? String ?? "?")/\(query[kSecAttrAccount as String] as? String ?? "?")"
    }

    private func copy(_ query: [String: Any]) -> (status: OSStatus, data: Data?) {
        lock.lock(); defer { lock.unlock() }
        recorded.append(Call(operation: .read, query: query as NSDictionary, attributes: nil))
        if let status = failures[.read] { return (status, nil) }
        guard let data = items[Self.key(query)] else { return (errSecItemNotFound, nil) }
        return (errSecSuccess, data)
    }

    private func update(_ query: [String: Any], _ attributes: [String: Any]) -> OSStatus {
        lock.lock(); defer { lock.unlock() }
        recorded.append(Call(
            operation: .update, query: query as NSDictionary, attributes: attributes as NSDictionary
        ))
        if let status = failures[.update] { return status }
        let key = Self.key(query)
        guard items[key] != nil else { return errSecItemNotFound }
        items[key] = attributes[kSecValueData as String] as? Data
        return errSecSuccess
    }

    private func add(_ attributes: [String: Any]) -> OSStatus {
        lock.lock(); defer { lock.unlock() }
        recorded.append(Call(operation: .add, query: attributes as NSDictionary, attributes: nil))
        if let status = failures[.add] { return status }
        let key = Self.key(attributes)
        guard items[key] == nil else { return errSecDuplicateItem }
        items[key] = attributes[kSecValueData as String] as? Data
        return errSecSuccess
    }

    private func delete(_ query: [String: Any]) -> OSStatus {
        lock.lock(); defer { lock.unlock() }
        recorded.append(Call(operation: .delete, query: query as NSDictionary, attributes: nil))
        if let status = failures[.delete] { return status }
        return items.removeValue(forKey: Self.key(query)) == nil ? errSecItemNotFound : errSecSuccess
    }
}

/// A consumer shaped like the planned grants owner: one actor holds the live
/// state and persists a snapshot after each change. Mint persists write-behind;
/// revoke persists before it returns. With `jitter`, a persisting change
/// suspends for up to a millisecond between prepare and commit, as an owner
/// doing other async work first would, so commits reach the backend in a
/// random order.
private actor PersistedGrantTable {
    private var generation = 0
    private var grantIDs: Set<String> = []
    private let store: ProtectedStore<SyntheticGrantsDocument>
    private let jitter: Bool

    init(store: ProtectedStore<SyntheticGrantsDocument>, jitter: Bool) {
        self.store = store
        self.jitter = jitter
    }

    private func snapshot() -> SyntheticGrantsDocument {
        SyntheticGrantsDocument(generation: generation, grantIDs: grantIDs.sorted())
    }

    private func pause() async {
        guard jitter else { return }
        try? await Task.sleep(nanoseconds: UInt64.random(in: 0...1_000_000))
    }

    /// Bumps the generation and persists, awaiting the commit.
    func bump() async {
        generation += 1
        guard let change = try? store.prepare(snapshot()) else { return }
        await pause()
        _ = try? await change.commit()
    }

    /// Returns the write-behind task so a test can wait for it to land.
    func mint(_ id: String) -> Task<Void, Never> {
        generation += 1
        grantIDs.insert(id)
        let change = try? store.prepare(snapshot())
        return Task {
            await pause()
            _ = try? await change?.commit()
        }
    }

    func revoke(_ id: String) async throws {
        generation += 1
        grantIDs.remove(id)
        try await store.prepare(snapshot()).commit()
    }
}

func protectedStoreTests() async {
    print("\n# Protected stores (csecd-only data-protection Keychain items)")

    protectedItemQueryTests()
    await protectedStoreRoundTripTests()
    await protectedStoreCapTests()
    await protectedStoreFailSafeDecodeTests()
    await protectedStoreMigrationTests()
    await protectedStoreHoldTests()
    await protectedStoreWriteOrDeleteTests()
    await protectedStoreOrderingTests()
    await protectedStoreConcurrentOwnerTests()
    await protectedKeychainCallTests()
    await protectedStoreBindingTests()
    await protectedStoresValueTests()
    protectedStoreUnentitledReadTests()
}

private func protectedItemQueryTests() {
    let expected: [(ProtectedItem, String, String, Int)] = [
        (.delegationSettings, CSECBuildIdentity.named("delegation"), "settings-v1", 256 * 1_024),
        (.delegationRegistrations, CSECBuildIdentity.named("delegation"), "registrations-v1", 1_024 * 1_024),
        (.grants, CSECBuildIdentity.named("grants"), "live-v1", 1_024 * 1_024),
        (.pairing, CSECBuildIdentity.named("pairing"), "v1", 512 * 1_024),
        (.lastRun, CSECBuildIdentity.named("runtime"), "last-run-v1", 4 * 1_024),
        (.decisionLogKey, CSECBuildIdentity.named("decision-log"), "key-v1", 512),
        (.decisionLogCheckpoint, CSECBuildIdentity.named("decision-log"), "head-v1", 4 * 1_024),
        (.baselinePointer, CSECBuildIdentity.named("baseline"), "pointer-v1", 4 * 1_024),
        (.automationRuns, CSECBuildIdentity.named("automation"), "runs-v1", 128 * 1_024),
        (.githubProxy, CSECBuildIdentity.named("github-proxy"), "settings-v1", 8 * 1_024),
        (.nativeStoreBackup, CSECBuildIdentity.named("native-store-backup"), "v1", 1_024 * 1_024),
        (.machineIdentity, CSECBuildIdentity.named("machine-identity"), "catalog-v1", 128 * 1_024),
    ]
    check(ProtectedItem.all == expected.map(\.0),
          "protected items: the catalog is exactly the twelve planned items")
    for (item, service, account, cap) in expected {
        check(item.service == service && item.account == account && item.maximumBytes == cap,
              "protected items: \(service)/\(account) has the planned identity and a \(cap)-byte cap")
    }
    check(Set(ProtectedItem.all.map(\.description)).count == ProtectedItem.all.count,
          "protected items: no two items share a service and account")
    check(ProtectedItem.lastRun.maximumBytes <= 16 * 1_024,
          "protected items: the last-run record stays small (≤16 KiB)")
    check(ProtectedItem.accessGroup == CSECBuildIdentity.keychainAccessGroup,
          "protected items: the access group is csecd's provisioned group")

    let classShape = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String
    for item in ProtectedItem.all {
        for operation in ProtectedKeychainOperation.allCases {
            let query = item.keychainQuery(for: operation)
            let label = "protected items: \(item) \(operation.rawValue) query"
            check((query[kSecClass as String] as? String) == (kSecClassGenericPassword as String),
                  "\(label) is a generic password")
            check((query[kSecUseDataProtectionKeychain as String] as? Bool) == true,
                  "\(label) uses the data-protection keychain")
            check((query[kSecAttrAccessGroup as String] as? String) == ProtectedItem.accessGroup,
                  "\(label) names the access group explicitly")
            check((query[kSecAttrSynchronizable as String] as? Bool) == false,
                  "\(label) is never synchronizable")
            check(query[kSecAttrAccessControl as String] == nil,
                  "\(label) carries no access control (no biometric ACL)")
            check(query[kSecUseAuthenticationContext as String] == nil,
                  "\(label) carries no authentication context")
            check((query[kSecAttrService as String] as? String) == item.service
                    && (query[kSecAttrAccount as String] as? String) == item.account,
                  "\(label) targets its own service and account")
            if operation == .add {
                check((query[kSecAttrAccessible as String] as? String) == classShape,
                      "\(label) creates the item AfterFirstUnlockThisDeviceOnly")
            } else {
                check(query[kSecAttrAccessible as String] == nil,
                      "\(label) matches whatever class the item holds")
            }
            if operation == .read {
                check((query[kSecReturnData as String] as? Bool) == true
                        && (query[kSecMatchLimit as String] as? String) == (kSecMatchLimitOne as String),
                      "\(label) returns the one item's data")
            } else {
                check(query[kSecReturnData as String] == nil,
                      "\(label) returns no data")
            }
        }
    }
}

private func protectedStoreRoundTripTests() async {
    let backend = InMemoryProtectedItemBackend()
    let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
    let item = ProtectedItem.lastRun

    check(store.item == item, "protected store: a document type's store targets its bound item")
    check(await store.load() == .absent, "protected store: a missing item loads as absent")

    let first = SyntheticRuntimeDocument(label: "first/run", count: 1)
    do {
        let result = try await store.prepare(first).commit()
        check(result == .applied, "protected store: a fresh change is applied")
        check(await store.load() == .document(first),
              "protected store: a stored document loads back unchanged")
        check(await backend.operations(on: item) == [.read, .update, .add, .read],
              "protected store: the first write updates, finds nothing, then adds")
        let raw = await backend.rawBytes(for: item).map { String(decoding: $0, as: UTF8.self) }
        check(raw == #"{"document":{"count":1,"label":"first/run"},"formatVersion":3}"#,
              "protected store: bytes are the sorted-key envelope carrying the format version")

        await backend.clearOperations()
        let second = SyntheticRuntimeDocument(label: "second", count: 2)
        try await store.prepare(second).commit()
        check(await backend.operations(on: item) == [.update],
              "protected store: rewriting an existing item is a single update")
        check(await store.load() == .document(second),
              "protected store: the rewritten document replaces the first")
    } catch {
        check(false, "protected store: round trip threw \(error)")
    }

    let pairing = ProtectedStores.processLocal(backend).store(for: SyntheticPairingDocument.self)
    let projects = SyntheticPairingDocument(projects: ["/synthetic/project"])
    do {
        try await pairing.prepare(projects).commit()
        let pairingLoad = await pairing.load()
        let runtimeLoad = await store.load()
        check(pairingLoad == .document(projects)
                && runtimeLoad == .document(SyntheticRuntimeDocument(label: "second", count: 2)),
              "protected store: documents on different items do not disturb each other")
    } catch {
        check(false, "protected store: second item threw \(error)")
    }
}

private func protectedStoreCapTests() async {
    let backend = InMemoryProtectedItemBackend()
    let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
    let item = ProtectedItem.lastRun
    let cap = item.maximumBytes

    // The envelope's fixed bytes, so a label can fill the cap exactly.
    let overhead = #"{"document":{"count":0,"label":""},"formatVersion":3}"#.utf8.count
    let atCap = SyntheticRuntimeDocument(label: String(repeating: "a", count: cap - overhead), count: 0)
    do {
        try await store.prepare(atCap).commit()
        check(await backend.rawBytes(for: item)?.count == cap,
              "protected store caps: a document encoding to exactly the cap is written")
        check(await store.load() == .document(atCap),
              "protected store caps: a document at the cap loads back")
    } catch {
        check(false, "protected store caps: a document at the cap threw \(error)")
    }

    await backend.clearOperations()
    let overCap = SyntheticRuntimeDocument(label: String(repeating: "a", count: cap - overhead + 1), count: 0)
    do {
        _ = try store.prepare(overCap)
        check(false, "protected store caps: a document one byte over the cap is refused")
    } catch let error as ProtectedStoreError {
        check(error == .rejected(.oversized(byteCount: cap + 1, maximum: cap)),
              "protected store caps: a document one byte over the cap is refused as oversized")
        check(!error.itemIsAbsent, "protected store caps: a refusal does not claim the item is gone")
    } catch {
        check(false, "protected store caps: an oversized document threw \(error)")
    }
    check(await backend.operations(on: item).isEmpty,
          "protected store caps: a refused document makes no Keychain call")
    check(await store.load() == .document(atCap),
          "protected store caps: a refused write leaves the previous document in place")

    let oversized = Data(repeating: UInt8(ascii: " "), count: cap + 1)
    await backend.setRawBytes(oversized, for: item)
    await backend.clearOperations()
    check(await store.load() == .unreadable(.oversized(byteCount: cap + 1, maximum: cap)),
          "protected store caps: oversized bytes on read are unreadable, not absent")
    check(await onlyReadAndUnchanged(item, holding: oversized, in: backend),
          "protected store caps: an oversized item is left untouched")
}

/// Whether `item` still holds exactly `bytes` and saw nothing but one read.
private func onlyReadAndUnchanged(
    _ item: ProtectedItem,
    holding bytes: Data,
    in backend: InMemoryProtectedItemBackend
) async -> Bool {
    let current = await backend.rawBytes(for: item)
    let operations = await backend.operations(on: item)
    return current == bytes && operations == [.read]
}

private func protectedStoreFailSafeDecodeTests() async {
    let item = ProtectedItem.lastRun
    let valid = #"{"document":{"count":1,"label":"x"},"formatVersion":3}"#
    let cases: [(String, Data, ProtectedUnreadableReason)] = [
        ("corrupt JSON", Data(#"{"document":{"count":1,"#.utf8), .invalidJSON),
        ("trailing garbage", Data((valid + "garbage").utf8), .invalidJSON),
        ("a second top-level value", Data((valid + "{}").utf8), .invalidJSON),
        ("a bare document without the envelope", Data(#"{"count":1,"label":"x"}"#.utf8), .invalidJSON),
        ("the right version with the wrong document shape",
         Data(#"{"document":{"count":"one"},"formatVersion":3}"#.utf8), .invalidJSON),
        ("a non-integral format version",
         Data(#"{"document":{"count":1,"label":"x"},"formatVersion":3.5}"#.utf8), .invalidJSON),
        ("an unknown format version",
         Data(#"{"document":{"count":1,"label":"x"},"formatVersion":0}"#.utf8),
         .unsupportedFormatVersion(found: 0, supported: 3)),
        ("an older format version under the default (no) migration",
         Data(#"{"document":{"count":1,"label":"x"},"formatVersion":2}"#.utf8),
         .unsupportedFormatVersion(found: 2, supported: 3)),
        ("a newer format version with a body this build cannot decode",
         Data(#"{"document":{"entries":[1,2]},"formatVersion":4}"#.utf8),
         .unsupportedFormatVersion(found: 4, supported: 3)),
        ("a document failing its own bounds check",
         Data(#"{"document":{"count":-1,"label":"x"},"formatVersion":3}"#.utf8), .notWellFormed),
    ]
    for (label, bytes, reason) in cases {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        await backend.setRawBytes(bytes, for: item)
        check(await store.load() == .unreadable(reason),
              "protected store decode: \(label) is unreadable (\(reason))")
        check(await onlyReadAndUnchanged(item, holding: bytes, in: backend),
              "protected store decode: \(label) is left in place, unmodified")
    }

    let backend = InMemoryProtectedItemBackend()
    let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
    await backend.setRawBytes(Data(valid.utf8), for: item)
    await backend.inject(.init(read: errSecInteractionNotAllowed), for: item)
    check(await store.load() == .unreadable(.keychainError(errSecInteractionNotAllowed)),
          "protected store decode: a Keychain read error is unreadable, not absent")
    check(await onlyReadAndUnchanged(item, holding: Data(valid.utf8), in: backend),
          "protected store decode: a failed read modifies nothing")
}

private func protectedStoreMigrationTests() async {
    let item = ProtectedItem.delegationSettings
    let cases: [(String, String, ProtectedLoad<VersionedSettingsDocument>)] = [
        ("an older version the document migrates loads as the current document",
         #"{"document":{"name":"alpha"},"formatVersion":1}"#,
         .document(VersionedSettingsDocument(names: ["alpha"], enabled: false))),
        ("an older version in a shape its migration does not recognise stays unreadable",
         #"{"document":{"title":"alpha"},"formatVersion":1}"#,
         .unreadable(.unsupportedFormatVersion(found: 1, supported: 2))),
        ("an older version the migration declines stays unreadable",
         #"{"document":{"name":"alpha"},"formatVersion":0}"#,
         .unreadable(.unsupportedFormatVersion(found: 0, supported: 2))),
        ("a migrated document still faces the bounds check",
         #"{"document":{"name":""},"formatVersion":1}"#,
         .unreadable(.notWellFormed)),
        ("the current version decodes directly",
         #"{"document":{"enabled":true,"names":["beta"]},"formatVersion":2}"#,
         .document(VersionedSettingsDocument(names: ["beta"], enabled: true))),
    ]
    for (label, text, expected) in cases {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: VersionedSettingsDocument.self)
        await backend.setRawBytes(Data(text.utf8), for: item)
        check(await store.load() == expected, "protected store migration: \(label)")
        check(await onlyReadAndUnchanged(item, holding: Data(text.utf8), in: backend),
              "protected store migration: \(label), and the item is not rewritten on read")
    }

    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: VersionedSettingsDocument.self)
        await backend.setRawBytes(Data(#"{"document":{"name":"alpha"},"formatVersion":1}"#.utf8), for: item)
        if case let .document(migrated) = await store.load() {
            try await store.prepare(migrated).commit()
        }
        let raw = await backend.rawBytes(for: item).map { String(decoding: $0, as: UTF8.self) }
        check(raw == #"{"document":{"enabled":false,"names":["alpha"]},"formatVersion":2}"#,
              "protected store migration: storing a migrated document writes the current version")
    } catch {
        check(false, "protected store migration: rewrite threw \(error)")
    }

    let eagerBackend = InMemoryProtectedItemBackend()
    let eager = ProtectedStores.processLocal(eagerBackend).store(for: EagerMigrationDocument.self)
    await eagerBackend.setRawBytes(Data(#"{"document":{},"formatVersion":3}"#.utf8), for: item)
    check(await eager.load() == .unreadable(.unsupportedFormatVersion(found: 3, supported: 2)),
          "protected store migration: a newer version never reaches migrate")
    await eagerBackend.setRawBytes(Data(#"{"document":{},"formatVersion":1}"#.utf8), for: item)
    check(await eager.load() == .document(EagerMigrationDocument(migrated: true)),
          "protected store migration: an older version does reach migrate")
}

private func isHeld(_ error: Error, _ reason: ProtectedUnreadableReason) -> Bool {
    if case let ProtectedStoreError.held(held) = error { return held == reason }
    return false
}

/// What a store does after loading an item it cannot read: keep it exactly as
/// found, however the consumer that started empty tries to write.
private func protectedStoreHoldTests() async {
    let item = ProtectedItem.lastRun
    let valid = Data(#"{"document":{"count":1,"label":"x"},"formatVersion":3}"#.utf8)
    let replacement = SyntheticRuntimeDocument(label: "older build", count: 2)
    let cases: [(String, Data, InMemoryProtectedItemBackend.Failures?, ProtectedUnreadableReason)] = [
        ("a newer format version", Data(#"{"document":{"entries":[1]},"formatVersion":4}"#.utf8), nil,
         .unsupportedFormatVersion(found: 4, supported: 3)),
        ("a Keychain read error", valid, .init(read: errSecInteractionNotAllowed),
         .keychainError(errSecInteractionNotAllowed)),
        ("damaged JSON", Data(#"{"document":{"count":1,"#.utf8), nil, .invalidJSON),
        ("a document failing its bounds check",
         Data(#"{"document":{"count":-1,"label":"x"},"formatVersion":3}"#.utf8), nil, .notWellFormed),
        ("an item over its size limit", Data(repeating: 0x20, count: item.maximumBytes + 1), nil,
         .oversized(byteCount: item.maximumBytes + 1, maximum: item.maximumBytes)),
    ]
    for (label, bytes, failures, reason) in cases {
        let backend = InMemoryProtectedItemBackend()
        let stores = ProtectedStores.processLocal(backend)
        let store = stores.store(for: SyntheticRuntimeDocument.self)
        await backend.setRawBytes(bytes, for: item)
        if let failures { await backend.inject(failures, for: item) }
        check(await store.load() == .unreadable(reason), "protected store hold: \(label) loads unreadable")
        check(store.heldReason == reason && stores.heldItems.map(\.item) == [item]
                && stores.heldItems.first?.reason == reason,
              "protected store hold: \(label) is held, and the stores list it")
        do {
            _ = try store.prepare(replacement)
            check(false, "protected store hold: \(label) refuses a write")
        } catch {
            check(isHeld(error, reason), "protected store hold: \(label) refuses a write as held (\(error))")
        }
        do {
            _ = try store.prepareDeletion()
            check(false, "protected store hold: \(label) refuses a deletion")
        } catch {
            check(isHeld(error, reason), "protected store hold: \(label) refuses a deletion as held (\(error))")
        }
        check(await onlyReadAndUnchanged(item, holding: bytes, in: backend),
              "protected store hold: \(label) is left exactly as found")
    }

    // A later load that reads the item lifts the hold: its caller now holds
    // what the item holds. A new process starts with nothing held.
    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        await backend.setRawBytes(valid, for: item)
        await backend.inject(.init(read: errSecInteractionNotAllowed), for: item)
        _ = await store.load()
        await backend.inject(.init(), for: item)
        check(store.heldReason == .keychainError(errSecInteractionNotAllowed),
              "protected store hold: a failed Keychain read holds the item")
        let reread = await store.load()
        check(reread == .document(SyntheticRuntimeDocument(label: "x", count: 1))
                && store.heldReason == nil && (try? store.prepare(replacement)) != nil,
              "protected store hold: a later load that reads the item lifts the hold")
        let restarted = ProtectedStores.processLocal(InMemoryProtectedItemBackend())
        check(restarted.heldItems.isEmpty, "protected store hold: a new process starts with nothing held")
    }

    // Not held: an older format no build reads any more, an absent item, and
    // a document type that opts out.
    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        await backend.setRawBytes(Data(#"{"document":{"count":1,"label":"x"},"formatVersion":2}"#.utf8), for: item)
        check(await store.load() == .unreadable(.unsupportedFormatVersion(found: 2, supported: 3))
                && store.heldReason == nil,
              "protected store hold: an older format migrate declines is not held")
        let written = (try? await store.prepare(replacement).commit()) == .applied
        let rewritten = await store.load()
        check(written && rewritten == .document(replacement),
              "protected store hold: an older format migrate declines is overwritten")

        let absentStore = ProtectedStores.processLocal().store(for: SyntheticRuntimeDocument.self)
        let absentLoad = await absentStore.load()
        check(absentLoad == .absent && absentStore.heldReason == nil,
              "protected store hold: an absent item is not held")

        let optOutBackend = InMemoryProtectedItemBackend()
        let optOut = ProtectedStores.processLocal(optOutBackend).store(for: RewrittenEachStartDocument.self)
        await optOutBackend.setRawBytes(Data(#"{"document":{"pid":1},"formatVersion":2}"#.utf8), for: item)
        _ = await optOut.load()
        let optOutWrite = try? await optOut.prepare(RewrittenEachStartDocument(pid: 2)).commit()
        check(optOut.heldReason == nil && optOutWrite == .applied,
              "protected store hold: a document that opts out is rewritten")
    }

    // The discard a human asks for (`csec revoke --all`, delegation off)
    // deletes a held item and lifts the hold; uninstall deletes it too.
    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        await backend.setRawBytes(Data(#"{"document":{},"formatVersion":9}"#.utf8), for: item)
        _ = await store.load()
        let discarded = (try? await store.prepareDiscard().commit()) == .applied
        let afterDiscard = await backend.rawBytes(for: item)
        check(discarded && afterDiscard == nil && store.heldReason == nil,
              "protected store hold: a discard deletes a held item and lifts the hold")
        let rewrite = try? await store.prepare(replacement).commit()
        check(rewrite == .applied,
              "protected store hold: after a discard the item is written again")

        let failingBackend = InMemoryProtectedItemBackend()
        let failing = ProtectedStores.processLocal(failingBackend).store(for: SyntheticRuntimeDocument.self)
        let future = Data(#"{"document":{},"formatVersion":9}"#.utf8)
        await failingBackend.setRawBytes(future, for: item)
        _ = await failing.load()
        await failingBackend.inject(.init(delete: errSecInteractionNotAllowed), for: item)
        let failedDiscard = try? await failing.prepareDiscard().commit()
        let afterFailedDiscard = await failingBackend.rawBytes(for: item)
        check(failedDiscard == nil && afterFailedDiscard == future
                && failing.heldReason == .unsupportedFormatVersion(found: 9, supported: 3)
                && (try? failing.prepare(replacement)) == nil,
              "protected store hold: a discard whose delete fails leaves the item held")

        let uninstallBackend = InMemoryProtectedItemBackend()
        let stores = ProtectedStores.processLocal(uninstallBackend)
        await uninstallBackend.setRawBytes(Data(#"{"document":{},"formatVersion":9}"#.utf8), for: item)
        _ = await stores.store(for: SyntheticRuntimeDocument.self).load()
        stores.enterUninstalledState()
        let remaining = await stores.deleteAll()
        let afterUninstall = await uninstallBackend.rawBytes(for: item)
        check(remaining.isEmpty && afterUninstall == nil,
              "protected store hold: uninstall deletes a held item")
    }

    // What csec status is told about a held item, by cause.
    do {
        let keychain = HeldProtectedItem(item: .grants, reason: .keychainError(errSecInteractionNotAllowed))
        let damaged = HeldProtectedItem(item: .delegationSettings, reason: .invalidJSON)
        let damagedLog = HeldProtectedItem(item: .decisionLogKey, reason: .notWellFormed)
        check(keychain.cause == .keychain && keychain.remedy.contains("restart csecd")
                && damaged.cause == .damaged && damaged.remedy.contains("turning delegated approvals off")
                && damagedLog.remedy.contains("csec uninstall")
                && HeldProtectedItem(item: .pairing, reason: .invalidJSON).remedy.contains("csec revoke --all"),
              "protected store hold: each held item names its cause and the remedy for it")
        let decoder = JSONDecoder()
        let unknown = try? decoder.decode(
            HeldProtectedItem.self,
            from: Data(#"{"name":"n","cause":"from_the_future","reason":"r","remedy":"m"}"#.utf8)
        )
        let older = try? decoder.decode(
            DecisionLogStatus.self,
            from: Data(#"{"state":"active","integrityEvents":0,"unrecordedFinding":false,"droppedRecords":0,"checkpointWriteFailures":0,"stuckFiles":[]}"#.utf8)
        )
        check(unknown?.cause == .unrecognized && older != nil && older?.heldItems == nil,
              "protected store hold: an unknown cause decodes as unrecognized, and an older csecd's status as no report")
    }

    // 14 Oct 2026: an older csecd read the newer pairing format as unreadable,
    // started empty and wrote its first new pairing over every saved one.
    do {
        let newerBackend = InMemoryProtectedItemBackend()
        let saved = NewerPairingDocument(projects: ["/a", "/b", "/c"], sudo: true)
        _ = try? await ProtectedStores.processLocal(newerBackend).store(for: NewerPairingDocument.self)
            .prepare(saved).commit()
        let savedBytes = await newerBackend.rawBytes(for: .pairing) ?? Data()

        let olderBackend = InMemoryProtectedItemBackend()
        await olderBackend.setRawBytes(savedBytes, for: .pairing)
        let older = ProtectedStores.processLocal(olderBackend).store(for: OlderPairingDocument.self)
        check(await older.load() == .unreadable(.unsupportedFormatVersion(found: 3, supported: 2)),
              "protected store hold: the older build cannot read the newer pairings")
        _ = try? await older.prepare(OlderPairingDocument(projects: ["/new"])).commit()
        _ = try? await older.prepareDeletion().commit()

        let upgraded = InMemoryProtectedItemBackend()
        await upgraded.setRawBytes(await olderBackend.rawBytes(for: .pairing), for: .pairing)
        check(await ProtectedStores.processLocal(upgraded).store(for: NewerPairingDocument.self).load()
                == .document(saved),
              "protected store hold: after a downgrade's pairing, the newer build finds every pairing it saved")
    }
}

private func protectedStoreWriteOrDeleteTests() async {
    let item = ProtectedItem.lastRun
    let previous = SyntheticRuntimeDocument(label: "previous", count: 1)
    let next = SyntheticRuntimeDocument(label: "next", count: 2)

    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        try await store.prepare(previous).commit()
        await backend.clearOperations()
        await backend.inject(.failingWrites(errSecIO), for: item)
        do {
            try await store.prepare(next).commit()
            check(false, "write-or-delete: a failed write throws")
        } catch let error as ProtectedStoreError {
            check(error == .writeFailedItemDeleted(write: errSecIO) && error.itemIsAbsent,
                  "write-or-delete: a failed write reports that the item was deleted instead")
        }
        check(await backend.operations(on: item) == [.update, .delete],
              "write-or-delete: a failed update is followed by a delete")
        await backend.inject(.init(), for: item)
        check(await store.load() == .absent,
              "write-or-delete: after a failed write the item is absent, not stale")
    } catch {
        check(false, "write-or-delete: failed-write setup threw \(error)")
    }

    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        await backend.inject(.init(add: errSecIO), for: item)
        try await store.prepare(next).commit()
        check(false, "write-or-delete: a failed add throws")
    } catch let error as ProtectedStoreError {
        check(error == .writeFailedItemDeleted(write: errSecIO),
              "write-or-delete: a failed first add on an absent item reports the deleted fallback")
    } catch {
        check(false, "write-or-delete: failed add threw \(error)")
    }

    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        try await store.prepare(previous).commit()
        let previousBytes = await backend.rawBytes(for: item)
        await backend.clearOperations()
        await backend.inject(.failingWrites(errSecIO, delete: errSecInteractionNotAllowed), for: item)
        do {
            try await store.prepare(next).commit()
            check(false, "write-or-delete: a failed write and delete throws")
        } catch let error as ProtectedStoreError {
            check(error == .writeAndDeleteFailed(write: errSecIO, delete: errSecInteractionNotAllowed),
                  "write-or-delete: a failed write and delete is a distinct error naming both statuses")
            check(!error.itemIsAbsent,
                  "write-or-delete: that error does not claim the item is gone")
            check(error.description.contains("\(errSecIO)")
                    && error.description.contains("\(errSecInteractionNotAllowed)"),
                  "write-or-delete: its description names both statuses")
        }
        check(await backend.operations(on: item) == [.update, .delete],
              "write-or-delete: the delete is still attempted after the failed write")
        check(await backend.rawBytes(for: item) == previousBytes,
              "write-or-delete: when both fail the previous document is what remains")
    } catch {
        check(false, "write-or-delete: double-failure setup threw \(error)")
    }

    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        let result = try await store.prepareDeletion().commit()
        let operations = await backend.operations(on: item)
        check(result == .applied && operations == [.delete],
              "delete: deleting an absent item succeeds")
        try await store.prepare(previous).commit()
        try await store.prepareDeletion().commit()
        check(await store.load() == .absent, "delete: deleting a present item leaves it absent")

        try await store.prepare(previous).commit()
        await backend.inject(.init(delete: errSecInteractionNotAllowed), for: item)
        do {
            try await store.prepareDeletion().commit()
            check(false, "delete: a failed delete throws")
        } catch let error as ProtectedStoreError {
            check(error == .deleteFailed(errSecInteractionNotAllowed),
                  "delete: a failed delete reports its status")
        }
        await backend.inject(.init(), for: item)
        check(await store.load() == .document(previous),
              "delete: a failed delete leaves the item in place")
    } catch {
        check(false, "delete: setup threw \(error)")
    }

    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        try await store.prepare(previous).commit()
        await backend.clearOperations()
        do {
            _ = try store.prepare(SyntheticRuntimeDocument(label: "bad", count: -1))
            check(false, "write refusal: a document failing its bounds check is refused")
        } catch let error as ProtectedStoreError {
            check(error == .rejected(.notWellFormed),
                  "write refusal: a document failing its bounds check is refused before writing")
        }
        check(await backend.operations(on: item).isEmpty,
              "write refusal: a malformed document makes no Keychain call")
        check(await store.load() == .document(previous),
              "write refusal: a malformed document leaves the previous document in place")
    } catch {
        check(false, "write refusal: setup threw \(error)")
    }

    let asymmetricBackend = InMemoryProtectedItemBackend()
    let asymmetric = ProtectedStores.processLocal(asymmetricBackend).store(for: AsymmetricDocument.self)
    do {
        _ = try asymmetric.prepare(AsymmetricDocument(generation: 7))
        check(false, "write refusal: a document that cannot load back is refused")
    } catch let error as ProtectedStoreError {
        check(error == .rejected(.doesNotRoundTrip),
              "write refusal: a document whose encoding does not load back is refused")
    } catch {
        check(false, "write refusal: the asymmetric document threw \(error)")
    }
    check(await asymmetricBackend.operations(on: .baselinePointer).isEmpty,
          "write refusal: nothing unreadable is ever written")

    let measurementBackend = InMemoryProtectedItemBackend()
    let measurement = ProtectedStores.processLocal(measurementBackend).store(for: MeasurementDocument.self)
    do {
        _ = try measurement.prepare(MeasurementDocument(ratio: .nan))
        check(false, "write refusal: a document the encoder rejects is refused")
    } catch let error as ProtectedStoreError {
        check(error == .rejected(.unencodable),
              "write refusal: a document the encoder rejects is refused as unencodable")
    } catch {
        check(false, "write refusal: the unencodable document threw \(error)")
    }
    check(await measurementBackend.operations(on: .decisionLogCheckpoint).isEmpty,
          "write refusal: an unencodable document makes no Keychain call")
}

/// Changes commit in whatever order they reach the backend; the item must
/// still end in the state of the change prepared last.
private func protectedStoreOrderingTests() async {
    let item = ProtectedItem.lastRun
    let older = SyntheticRuntimeDocument(label: "older", count: 1)
    let newer = SyntheticRuntimeDocument(label: "newer", count: 2)

    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        let first = try store.prepare(older)
        let second = try store.prepare(newer)
        check(second.sequence > first.sequence,
              "ordering: a change prepared later takes a later place")
        check(try await second.commit() == .applied, "ordering: the later change commits first and applies")
        await backend.clearOperations()
        check(try await first.commit() == .superseded(by: second.sequence),
              "ordering: the earlier change arriving last is superseded, not applied")
        check(await backend.operations(on: item).isEmpty,
              "ordering: a superseded change makes no Keychain call")
        check(await store.load() == .document(newer),
              "ordering: the item keeps the later-prepared document")
        check(try await first.commit() == .superseded(by: second.sequence),
              "ordering: committing a change twice changes nothing")
    } catch {
        check(false, "ordering: out-of-order commit threw \(error)")
    }

    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        let stale = try store.prepare(older)
        try await store.prepare(newer).commit()
        await backend.clearOperations()
        await backend.inject(.failingWrites(errSecIO), for: item)
        check(try await stale.commit() == .superseded(by: stale.sequence + 1),
              "ordering: a stale write that would fail is skipped")
        check(await backend.operations(on: item).isEmpty,
              "ordering: the skipped stale write runs no fallback delete")
        await backend.inject(.init(), for: item)
        check(await store.load() == .document(newer),
              "ordering: a stale failing write cannot delete the newer document")
    } catch {
        check(false, "ordering: stale failing write threw \(error)")
    }

    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        let staleDeletion = try store.prepareDeletion()
        try await store.prepare(newer).commit()
        check(try await staleDeletion.commit() == .superseded(by: staleDeletion.sequence + 1),
              "ordering: a stale deletion is superseded")
        check(await store.load() == .document(newer),
              "ordering: a stale deletion leaves the newer document")

        let staleWrite = try store.prepare(older)
        try await store.prepareDeletion().commit()
        check(try await staleWrite.commit() == .superseded(by: staleWrite.sequence + 1),
              "ordering: a write prepared before a committed deletion is superseded")
        check(await store.load() == .absent,
              "ordering: a stale write cannot recreate a deleted item")
    } catch {
        check(false, "ordering: stale deletion threw \(error)")
    }

    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        try await store.prepare(older).commit()
        let olderBytes = await backend.rawBytes(for: item)
        let stale = try store.prepare(SyntheticRuntimeDocument(label: "middle", count: 3))
        let failing = try store.prepare(newer)
        await backend.inject(.failingWrites(errSecIO, delete: errSecInteractionNotAllowed), for: item)
        do {
            try await failing.commit()
            check(false, "ordering: the newer change fails to settle the item")
        } catch let error as ProtectedStoreError {
            check(error == .writeAndDeleteFailed(write: errSecIO, delete: errSecInteractionNotAllowed),
                  "ordering: the newer change fails to settle the item")
        }
        await backend.inject(.init(), for: item)
        await backend.clearOperations()
        do {
            try await stale.commit()
            check(false, "ordering: an older change behind an unsettled newer one throws")
        } catch let error as ProtectedStoreError {
            check(error == .supersededByUnsettledChange(sequence: failing.sequence),
                  "ordering: an older change behind an unsettled newer one reports that an earlier "
                    + "document may remain")
        }
        let skippedOperations = await backend.operations(on: item)
        let remainingBytes = await backend.rawBytes(for: item)
        check(skippedOperations.isEmpty && remainingBytes == olderBytes,
              "ordering: that older change still writes nothing over the newer attempt")
        let recovery = try await store.prepare(newer).commit()
        let recovered = await store.load()
        check(recovery == .applied && recovered == .document(newer),
              "ordering: a change prepared after the failure applies and settles the item")
    } catch {
        check(false, "ordering: unsettled case threw \(error)")
    }

    do {
        let backend = InMemoryProtectedItemBackend()
        let store = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        let stale = try store.prepare(older)
        await backend.inject(.failingWrites(errSecIO), for: item)
        _ = try? await store.prepare(newer).commit()
        await backend.inject(.init(), for: item)
        let staleResult = try await stale.commit()
        let settled = await store.load()
        check(staleResult == .superseded(by: stale.sequence + 1) && settled == .absent,
              "ordering: a newer write that fell back to deleting still settles the item")
    } catch {
        check(false, "ordering: deleted-fallback case threw \(error)")
    }

    do {
        let backend = InMemoryProtectedItemBackend()
        let before = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        let earlier = try before.prepare(older)
        let after = ProtectedStores.processLocal(backend).store(for: SyntheticRuntimeDocument.self)
        let later = try after.prepare(newer)
        check(later.sequence > earlier.sequence,
              "ordering: a new value over the same backend continues the item's order")

        let grants = ProtectedStores.processLocal(backend).store(for: SyntheticGrantsDocument.self)
        let pending = try grants.prepare(SyntheticGrantsDocument(generation: 1, grantIDs: ["g1"]))
        let remaining = await ProtectedStores.processLocal(backend).deleteAll()
        check(remaining.isEmpty, "ordering: deleteAll succeeds over absent items")
        let pendingResult = try await pending.commit()
        let afterDeleteAll = await grants.load()
        check(pendingResult == .superseded(by: pending.sequence + 1) && afterDeleteAll == .absent,
              "ordering: a write prepared before deleteAll cannot recreate the item")
    } catch {
        check(false, "ordering: cross-value case threw \(error)")
    }
}

/// The two interleavings found in review, through both backends: many
/// concurrent snapshots from one owner, and a write-behind mint followed by an
/// awaited revoke. Each runs as the review wrote it and again with jitter
/// between prepare and commit. Without per-item ordering both lose the last
/// state; the jittered runs lose it in nearly every run.
private func protectedStoreConcurrentOwnerTests() async {
    let shapes: [(backend: String, jitter: Bool, runs: Int, trials: Int)] = [
        ("in-memory", false, 50, 1_000),
        ("Keychain", false, 50, 1_000),
        ("in-memory", true, 20, 200),
        ("Keychain", true, 20, 200),
    ]
    for shape in shapes {
        func makeStore() -> ProtectedStore<SyntheticGrantsDocument> {
            let stores = shape.backend == "in-memory"
                ? ProtectedStores.processLocal()
                : ProtectedStores.dataProtectionKeychain(calling: RecordingKeychain().functions)
            return stores.store(for: SyntheticGrantsDocument.self)
        }
        let label = "concurrent owner (\(shape.backend)\(shape.jitter ? ", jittered" : ""))"

        var staleRuns = 0
        let callsPerRun = 200
        for _ in 0..<shape.runs {
            let grants = makeStore()
            let table = PersistedGrantTable(store: grants, jitter: shape.jitter)
            await withTaskGroup(of: Void.self) { group in
                for _ in 0..<callsPerRun { group.addTask { await table.bump() } }
            }
            guard case let .document(persisted) = await grants.load(),
                  persisted.generation == callsPerRun else {
                staleRuns += 1
                continue
            }
        }
        check(staleRuns == 0,
              "\(label): \(callsPerRun) concurrent snapshots always persist the last one "
                + "(\(staleRuns)/\(shape.runs) runs stale)")

        var resurrected = 0
        for _ in 0..<shape.trials {
            let grants = makeStore()
            let table = PersistedGrantTable(store: grants, jitter: shape.jitter)
            let writeBehind = await table.mint("g1")
            do {
                try await table.revoke("g1")
            } catch {
                resurrected += 1
                continue
            }
            await writeBehind.value
            if case let .document(persisted) = await grants.load(), persisted.grantIDs.contains("g1") {
                resurrected += 1
            }
        }
        check(resurrected == 0,
              "\(label): a write-behind mint never outlives the revoke awaited after it "
                + "(\(resurrected)/\(shape.trials) trials resurrected)")
    }
}

/// What the production Keychain backend hands each `SecItem` call.
private func protectedKeychainCallTests() async {
    let item = ProtectedItem.lastRun
    let keychain = RecordingKeychain()
    let stores = ProtectedStores.dataProtectionKeychain(calling: keychain.functions)
    let store = stores.store(for: SyntheticRuntimeDocument.self)
    check(stores.persistence == .dataProtectionKeychain,
          "Keychain calls: the substituted backend is still the Keychain backend")

    func same(_ actual: NSDictionary?, _ expected: [String: Any]) -> Bool {
        actual?.isEqual(to: expected) == true
    }
    func withData(_ query: [String: Any], _ data: Data?) -> [String: Any] {
        var query = query
        query[kSecValueData as String] = data
        return query
    }

    check(await store.load() == .absent, "Keychain calls: an absent item loads as absent")
    var calls = keychain.calls
    check(calls.count == 1 && calls[0].operation == .read
            && same(calls[0].query, item.keychainQuery(for: .read)),
          "Keychain calls: a load sends exactly the read query")

    do {
        keychain.clearCalls()
        try await store.prepare(SyntheticRuntimeDocument(label: "first", count: 1)).commit()
        let written = keychain.bytes(for: item)
        calls = keychain.calls
        check(calls.map(\.operation) == [.update, .add],
              "Keychain calls: a first write updates, then adds")
        check(calls.count == 2
                && same(calls[0].query, item.keychainQuery(for: .update))
                && same(calls[0].attributes, [kSecValueData as String: written as Any]),
              "Keychain calls: the update sends the update query and only the new data")
        check(calls.count == 2 && same(calls[1].query, withData(item.keychainQuery(for: .add), written)),
              "Keychain calls: the add sends the add query (group, class, no ACL) plus the data")

        keychain.clearCalls()
        try await store.prepare(SyntheticRuntimeDocument(label: "second", count: 2)).commit()
        calls = keychain.calls
        check(calls.count == 1 && calls[0].operation == .update
                && same(calls[0].query, item.keychainQuery(for: .update))
                && same(calls[0].attributes, [kSecValueData as String: keychain.bytes(for: item) as Any]),
              "Keychain calls: a rewrite sends one update with the new data")

        keychain.clearCalls()
        check(await store.load() == .document(SyntheticRuntimeDocument(label: "second", count: 2)),
              "Keychain calls: a present item loads through the read query")
        calls = keychain.calls
        check(calls.count == 1 && same(calls[0].query, item.keychainQuery(for: .read)),
              "Keychain calls: that load sent exactly the read query")

        keychain.clearCalls()
        keychain.fail(.update, with: errSecIO)
        do {
            try await store.prepare(SyntheticRuntimeDocument(label: "third", count: 3)).commit()
            check(false, "Keychain calls: a failed update throws")
        } catch let error as ProtectedStoreError {
            check(error == .writeFailedItemDeleted(write: errSecIO),
                  "Keychain calls: a failed update falls back to deleting")
        }
        keychain.fail(.update, with: nil)
        calls = keychain.calls
        check(calls.map(\.operation) == [.update, .delete]
                && same(calls[1].query, item.keychainQuery(for: .delete)),
              "Keychain calls: the fallback delete sends exactly the delete query")

        try await store.prepare(SyntheticRuntimeDocument(label: "fourth", count: 4)).commit()
        keychain.clearCalls()
        try await store.prepareDeletion().commit()
        calls = keychain.calls
        check(calls.count == 1 && calls[0].operation == .delete
                && same(calls[0].query, item.keychainQuery(for: .delete)),
              "Keychain calls: a deletion sends exactly the delete query")
        check(keychain.bytes(for: item) == nil, "Keychain calls: the deletion removed the item")

        let stale = try store.prepare(SyntheticRuntimeDocument(label: "stale", count: 5))
        try await store.prepare(SyntheticRuntimeDocument(label: "fresh", count: 6)).commit()
        keychain.clearCalls()
        check(try await stale.commit() == .superseded(by: stale.sequence + 1) && keychain.calls.isEmpty,
              "Keychain calls: a superseded change reaches no SecItem call")
    } catch {
        check(false, "Keychain calls: threw \(error)")
    }
}

private func protectedStoreBindingTests() async {
    let item = ProtectedItem.lastRun
    let backend = InMemoryProtectedItemBackend()
    let stores = ProtectedStores.processLocal(backend)
    let owner = stores.store(for: SyntheticRuntimeDocument.self)
    let rival = stores.store(for: RivalRuntimeDocument.self)
    let ownerName = String(reflecting: SyntheticRuntimeDocument.self)
    let document = SyntheticRuntimeDocument(label: "owned", count: 1)

    do {
        try await owner.prepare(document).commit()
    } catch {
        check(false, "binding: the first type's write threw \(error)")
    }
    await backend.clearOperations()
    check(await rival.load() == .unreadable(.itemBoundToAnotherDocument(ownerName)),
          "binding: a second type on a bound item cannot read it")
    do {
        _ = try rival.prepare(RivalRuntimeDocument(label: "clobber", count: 9))
        check(false, "binding: a second type on a bound item cannot write it")
    } catch let error as ProtectedStoreError {
        check(error == .itemBoundToAnotherDocument(ownerName),
              "binding: a second type on a bound item cannot write it")
    } catch {
        check(false, "binding: the rival write threw \(error)")
    }
    do {
        _ = try rival.prepareDeletion()
        check(false, "binding: a second type on a bound item cannot delete it")
    } catch let error as ProtectedStoreError {
        check(error == .itemBoundToAnotherDocument(ownerName),
              "binding: a second type on a bound item cannot delete it")
    } catch {
        check(false, "binding: the rival deletion threw \(error)")
    }
    check(await backend.operations(on: item).isEmpty,
          "binding: the locked-out type never reaches the item")
    let ownerLoad = await owner.load()
    let askedAgain = await stores.store(for: SyntheticRuntimeDocument.self).load()
    check(ownerLoad == .document(document) && askedAgain == .document(document),
          "binding: the owning type keeps its item and may ask for its store again")
    check(await ProtectedStores.processLocal(backend).store(for: RivalRuntimeDocument.self).load()
            == .unreadable(.itemBoundToAnotherDocument(ownerName)),
          "binding: the binding survives a new value over the same backend")

    let otherBackend = InMemoryProtectedItemBackend()
    let otherRival = ProtectedStores.processLocal(otherBackend).store(for: RivalRuntimeDocument.self)
    check(await otherRival.load() == .absent,
          "binding: another backend binds its items independently")
}

private func protectedStoresValueTests() async {
    let backend = InMemoryProtectedItemBackend()
    let before = ProtectedStores.processLocal(backend)
    check(before.persistence == .processLocal,
          "protected stores: the in-memory fallback reports process-local persistence")
    check(ProtectedStores.dataProtectionKeychain().persistence == .dataProtectionKeychain,
          "protected stores: the production value reports the data-protection keychain")

    let document = SyntheticRuntimeDocument(label: "survives", count: 4)
    do {
        try await before.store(for: SyntheticRuntimeDocument.self).prepare(document).commit()
        let after = ProtectedStores.processLocal(backend)
        check(await after.store(for: SyntheticRuntimeDocument.self).load() == .document(document),
              "protected stores: a new value over the same backend sees what the old one stored")
    } catch {
        check(false, "protected stores: restart model threw \(error)")
    }

    for item in ProtectedItem.all {
        await backend.setRawBytes(Data("synthetic".utf8), for: item)
    }
    await backend.inject(.init(delete: errSecInteractionNotAllowed), for: .grants)
    let remaining = await before.deleteAll()
    check(remaining == [.grants: .deleteFailed(errSecInteractionNotAllowed)],
          "protected stores: deleteAll reports exactly the item whose delete failed")
    var othersGone = true
    for item in ProtectedItem.all where item != .grants {
        if await backend.rawBytes(for: item) != nil { othersGone = false }
    }
    check(othersGone, "protected stores: deleteAll still deletes every other item after a failure")
    check(await backend.rawBytes(for: .grants) != nil,
          "protected stores: the item whose delete failed is still there")
    await backend.inject(.init(), for: .grants)
    check(await before.deleteAll().isEmpty,
          "protected stores: deleteAll over absent and present items reports nothing remaining")

    // An owner write prepared after the batch took its places is newer and
    // wins; the batch must report that item as possibly remaining.
    do {
        let racing = InMemoryProtectedItemBackend()
        let stores = ProtectedStores.processLocal(racing)
        let grants = stores.store(for: SyntheticGrantsDocument.self)
        for item in ProtectedItem.all {
            await racing.setRawBytes(Data("synthetic".utf8), for: item)
        }
        let batch = stores.prepareDeletionOfAll()
        let ownerWrite = try grants.prepare(SyntheticGrantsDocument(generation: 1, grantIDs: ["g2"]))
        check(try await ownerWrite.commit() == .applied,
              "deletion batch: an owner write prepared after the batch applies first")
        let remaining = await batch.commit()
        check(remaining == [.grants: .supersededByNewerChange(sequence: ownerWrite.sequence)],
              "deletion batch: a deletion a newer write superseded is reported as possibly remaining")
        check(await grants.load() == .document(SyntheticGrantsDocument(generation: 1, grantIDs: ["g2"])),
              "deletion batch: that item does still hold the newer document")
        var othersGone = true
        for item in ProtectedItem.all where item != .grants {
            if await racing.rawBytes(for: item) != nil { othersGone = false }
        }
        check(othersGone, "deletion batch: every other item is deleted")

        for item in ProtectedItem.all {
            await racing.setRawBytes(Data("synthetic".utf8), for: item)
        }
        let second = stores.prepareDeletionOfAll()
        let failing = try grants.prepare(SyntheticGrantsDocument(generation: 2, grantIDs: []))
        await racing.inject(.failingWrites(errSecIO, delete: errSecInteractionNotAllowed), for: .grants)
        _ = try? await failing.commit()
        await racing.inject(.init(), for: .grants)
        check(await second.commit() == [.grants: .supersededByUnsettledChange(sequence: failing.sequence)],
              "deletion batch: a deletion behind an unsettled newer change is reported as possibly remaining")
    } catch {
        check(false, "deletion batch: threw \(error)")
    }
}

/// The unsigned selftest is outside csecd's access group, like any same-UID
/// process. The production read call with each item's read query must come
/// back refused, never as not-found, which is what a query missing the explicit
/// group would report. Read-only: nothing here writes to the real Keychain.
private func protectedStoreUnentitledReadTests() {
    for item in ProtectedItem.all {
        let (status, data) = ProtectedKeychainFunctions.system.copyMatching(item.keychainQuery(for: .read))
        check(status == errSecMissingEntitlement && data == nil,
              "protected stores: an unentitled process reading \(item) is refused (OSStatus \(status))")
    }
}
