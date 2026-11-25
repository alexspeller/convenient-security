import ConvenientSecurity
import CryptoKit
import CSECRemoteApproval
import Foundation
import LocalAuthentication
import Security

// The Mac-side storage of the phone-held cold-unlock factor: remote-unlock
// mirrors of the native stores' key records and of the Keychain cache, read
// with the key a verified phone approval opens. Every backend here is in
// memory and every value synthetic; a software P-256 key stands in for the
// phone's Secure Enclave key.

/// The Keychain cache's biometric items, in memory. Like the real items, an
/// entry opens only with a local unlock, so a remote read that reached one
/// would throw instead of passing. Lists its accounts for enrollment backfill.
actor RemoteUnlockFakeKeychain: KeychainBackend {
    private var items: [String: Data] = [:]
    private(set) var loadCount = 0

    func store(account: String, data: Data) { items[account] = data }

    func load(account: String, unlock: CacheUnlock?) throws -> Data? {
        guard unlock?.isLocal == true else { throw NativeStoreError.authenticationRequired }
        loadCount += 1
        return items[account]
    }

    func delete(account: String) { items[account] = nil }
    func contains(account: String) -> Bool { items[account] != nil }
    func accounts(unlock: CacheUnlock) throws -> [String] { items.keys.sorted() }
    func has(_ account: String) -> Bool { items[account] != nil }
    func plant(_ data: Data, for account: String) { items[account] = data }
}

/// A provider of any scheme whose answers to the unlock questions are fixed,
/// so coverage is shown to come from the provider seam, never from knowing a
/// scheme. Its values are cacheable, like a remote provider's. Locked, it
/// refuses every fetch, as 1Password does while it is locked with the Mac.
/// Attended, it would raise its own authorization at the Mac, as 1Password
/// does with no session open.
actor RemoteCoverageFixtureProvider: SecretProvider {
    nonisolated let schemes: Set<String>
    private let needsUnlock: Bool
    private let opensRemotely: Bool
    private let attended: Bool
    private let value: Data
    private var locked = false
    private(set) var resolveCount = 0

    init(scheme: String, needsUnlock: Bool, opensRemotely: Bool, value: String, attended: Bool = false) {
        self.schemes = [scheme]
        self.needsUnlock = needsUnlock
        self.opensRemotely = opensRemotely
        self.attended = attended
        self.value = Data(value.utf8)
    }

    func setLocked(_ locked: Bool) { self.locked = locked }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        resolveCount += 1
        guard !locked else { throw ProviderError.notAuthenticated }
        return ResolvedSecret(value: value, cacheHint: .cacheable)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
    func requiresUnlockToResolve(_ ref: SecretRef) async -> Bool { needsUnlock }
    func canResolveWithRemoteUnlock(_ ref: SecretRef) async -> Bool { opensRemotely }
    func requiresAttendanceToResolve(_ ref: SecretRef) async -> Bool { attended }
}

/// What survives a csecd restart: every backend. Each `boot` builds fresh
/// actors over them, the way a restarted csecd starts with nothing warm.
private struct RemoteUnlockWorld {
    let docKeys = InMemoryNativeStoreKeyBackend()
    let docFiles = InMemoryNativeStoreFileBackend()
    let blobKeys = InMemoryNativeStoreKeyBackend()
    let blobFiles = InMemoryNativeStoreFileBackend()
    let cacheItems = RemoteUnlockFakeKeychain()
    let items = InMemoryRemoteUnlockItemBackend()
    /// Stands in for a remote provider (1Password): external state, so one
    /// instance across restarts.
    let remoteProvider = RemoteCoverageFixtureProvider(
        scheme: "op", needsUnlock: false, opensRemotely: false, value: "synthetic-op-value"
    )
}

private struct RemoteUnlockRun {
    let store: RemoteUnlockStore
    let blobs: NativeBlobStore
    let provider: NativeEncryptedFileProvider
    let cache: KeychainSecretCache
    let resolver: SecretResolver
    let epoch: RemoteUnlockEpochOutcome?
}

private func remoteUnlockLastRun(_ cdHash: String?) -> CsecdLastRun {
    CsecdLastRun(bootSessionUUID: "synthetic-boot", pid: 4242, startTimeMicros: 1, cdHash: cdHash, version: nil)
}

private func bootRemoteUnlockRun(
    _ world: RemoteUnlockWorld,
    build: String? = "build-a",
    previous: CsecdLastRun?,
    reconcile: Bool = true
) async -> RemoteUnlockRun {
    let store = RemoteUnlockStore(backend: world.items, buildIdentity: build)
    let epoch = reconcile ? await store.reconcileEpoch(previousRun: previous) : nil
    let blobs = NativeBlobStore(keyBackend: world.blobKeys, fileBackend: world.blobFiles, remoteUnlock: store)
    let provider = NativeEncryptedFileProvider(
        keyBackend: world.docKeys, fileBackend: world.docFiles, blobStore: blobs, remoteUnlock: store
    )
    let cache = KeychainSecretCache(backend: world.cacheItems, remoteUnlock: store)
    let resolver = SecretResolver(cache: cache)
    await resolver.register(provider)
    await resolver.register(world.remoteProvider)
    return RemoteUnlockRun(
        store: store, blobs: blobs, provider: provider, cache: cache, resolver: resolver, epoch: epoch
    )
}

/// The phone's side of one approval, then the Mac's: blind, answer with the
/// phone key, unblind.
private func phoneApprovedUnlock(
    _ store: RemoteUnlockStore,
    phone: P256.KeyAgreement.PrivateKey
) async throws -> CacheUnlock {
    let (challenge, enrollmentID) = try await store.challenge()
    let answer = try RemoteUnlockCrypto.answer(blindedPoint: challenge.blindedPoint) {
        try phone.sharedSecretFromKeyAgreement(with: $0)
    }
    return try await store.openRemoteUnlock(challenge: challenge, answer: answer, enrollmentID: enrollmentID)
}

private func expectNativeError<T>(
    _ expected: NativeStoreError,
    _ label: String,
    _ body: () async throws -> T
) async {
    do {
        _ = try await body()
        check(false, "\(label) (expected \(expected), nothing was thrown)")
    } catch let error as NativeStoreError {
        check(error == expected, "\(label) (threw \(error))")
    } catch {
        check(false, "\(label) (threw \(error) instead of \(expected))")
    }
}

private func mirrorItem(_ account: String) -> RemoteUnlockItemName {
    RemoteUnlockItemName(service: RemoteUnlockStore.mirrorService, account: account)
}

func remoteUnlockStorageTests() async {
    print("\n# Remote-unlock storage (phone-held cold-unlock factor)")

    let world = RemoteUnlockWorld()
    let local = CacheUnlock(LAContext()) // in-memory backends only; never prompts
    var phone = P256.KeyAgreement.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()
    var phoneDeviceID = UUID().uuidString.lowercased()
    let callerPID: pid_t = 4242
    let callerStart: UInt64 = 1

    let storeA = try! NativeStoreName("remote-a")
    let storeB = try! NativeStoreName("remote-b")
    let docRef = try! SecretRef("csec://remote-a/API_TOKEN")
    let docRefB = try! SecretRef("csec://remote-b/API_TOKEN")
    let blobRef = try! SecretRef("csec://remote-a/service_json")
    let opURI = "op://vault/item/field"
    let opRef = try! SecretRef(opURI)
    let docValue1 = Data("synthetic-doc-value-1".utf8)
    let docValue2 = Data("synthetic-doc-value-2".utf8)
    let docValueB = Data("synthetic-doc-value-b".utf8)
    let blobValue = Data("{\"synthetic\":\"blob\"}".utf8)
    let opValue = Data("synthetic-op-value".utf8)
    let docMirrorA = mirrorItem("doc/remote-a")
    let docMirrorB = mirrorItem("doc/remote-b")
    let cacheMirrorOp = mirrorItem("cache/\(opURI)")
    let epochItem = RemoteUnlockItemName(service: RemoteUnlockStore.service, account: "epoch-v1")
    let kept = remoteUnlockLastRun("build-a")

    func commitDocument(_ run: RemoteUnlockRun, _ store: NativeStoreName, _ values: [String: String]) async throws {
        let session = try await run.provider.beginEdit(
            store: store, callerPID: callerPID, callerStartTime: callerStart, unlock: local
        )
        _ = try await run.provider.commitEdit(
            sessionID: session.sessionID,
            document: try NativeStoreDocument(values: values).encoded(),
            callerPID: callerPID,
            callerStartTime: callerStart
        )
    }

    do {
        // MARK: Not enrolled: nothing new is written.
        let run1 = await bootRemoteUnlockRun(world, previous: nil)
        check(run1.epoch == .notEnrolled, "a first start with no enrollment reconciles to notEnrolled")
        try await commitDocument(run1, storeA, ["API_TOKEN": String(decoding: docValue1, as: UTF8.self)])
        try await commitDocument(run1, storeB, ["API_TOKEN": String(decoding: docValueB, as: UTF8.self)])
        _ = try await run1.blobs.putBlobs(
            store: storeA,
            requests: [.init(key: "service_json", data: blobValue, mode: 0o600, path: "config/service.json")],
            unlock: local
        )
        _ = try await run1.resolver.resolve(opRef, unlock: local)
        _ = await run1.cache.holds(opURI)
        _ = await run1.resolver.invalidate(references: ["op://vault/never/cached"])
        let unenrolledOps = await world.items.operations
        check(unenrolledOps.count == 1 && unenrolledOps.first?.kind == .read
                  && unenrolledOps.first?.item?.account == "enrollment-v1",
              "without an enrollment, commits, blob writes and cache writes cost one cached enrollment read and nothing else (\(unenrolledOps))")
        check(await world.items.rawItems().isEmpty, "without an enrollment no remote-unlock item is ever written")
        let coverageUnenrolled = await run1.resolver.remoteUnlockCoverage([docRef])
        check(coverageUnenrolled.coveredRemotely.isEmpty,
              "without an enrollment nothing is covered remotely")

        // MARK: Enrollment
        let record = try await run1.store.enroll(
            phoneKeyAgreementPublicKeyX963: phone.publicKey.x963Representation,
            macDeviceID: macDeviceID, phoneDeviceID: phoneDeviceID
        )
        check(await run1.store.enrollment() == record, "enroll stores and returns the enrollment record")
        check(record.binding == RemoteUnlockEnrollmentRecord.binding(
                  macDeviceID: macDeviceID, phoneDeviceID: phoneDeviceID),
              "the enrollment binds the Mac and phone device IDs")
        let enrolledItems = await world.items.rawItems()
        check(enrolledItems[RemoteUnlockItemName(service: RemoteUnlockStore.service, account: "enrollment-v1")] != nil
                  && enrolledItems[epochItem] != nil && enrolledItems.count == 2,
              "enrolling writes exactly the enrollment and the epoch")

        // MARK: Backfill at enable, after a restart so every store is cold.
        let run2 = await bootRemoteUnlockRun(world, previous: kept)
        check(run2.epoch == .kept, "a restart of the enrolling build keeps the mirrors")
        let docLoadsBeforeBackfill = await world.docKeys.loadCount
        let backfill = await run2.resolver.backfillRemoteUnlockMirrors(localUnlock: local)
        check(backfill == RemoteUnlockBackfillReport(mirrored: 4, failed: 0),
              "backfill mirrors both document stores, the blob store and the cached entry (\(backfill))")
        check(await world.docKeys.loadCount > docLoadsBeforeBackfill,
              "backfill reads the existing key records with the enrollment's local context")
        check(await run2.provider.requiresUnlockToResolve(docRef),
              "backfill leaves the document tier cold: the enrollment touch approved no use")
        check(await run2.blobs.requiresUnlock(store: storeA), "backfill leaves the blob tier cold")
        check(await run2.resolver.resolveWithoutInteraction(opRef) == nil,
              "backfill leaves the cache's warm tier empty")
        let listed = Set(try await run2.store.mirrors())
        check(listed == [.nativeDocuments(store: "remote-a"), .nativeDocuments(store: "remote-b"),
                         .nativeBlobs(store: "remote-a"), .cache(uri: opURI)],
              "the mirrors listed are exactly the backfilled items")
        let backfillRemote = await run2.resolver.backfillRemoteUnlockMirrors(
            localUnlock: try await phoneApprovedUnlock(run2.store, phone: phone)
        )
        check(backfillRemote == RemoteUnlockBackfillReport(mirrored: 0, failed: 1),
              "backfill refuses a remote unlock: it needs the local context")

        // MARK: Cold remote read after a restart, with no local context.
        let run3 = await bootRemoteUnlockRun(world, previous: kept)
        let coverage = await run3.resolver.remoteUnlockCoverage([docRef, blobRef, opRef])
        check(coverage.needsUnlock == [docRef.uri, blobRef.uri] && coverage.isComplete,
              "mixed references: both cold native references need an unlock and are covered; the remote provider's needs none")
        let remote3 = try await phoneApprovedUnlock(run3.store, phone: phone)
        check(!remote3.isLocal && remote3.context == nil && remote3.remote != nil,
              "a phone-approved unlock is remote and carries no LAContext")
        let docLoads = await world.docKeys.loadCount
        let blobLoads = await world.blobKeys.loadCount
        let cacheLoads = await world.cacheItems.loadCount
        let remoteResolves = await world.remoteProvider.resolveCount
        check(try await run3.resolver.resolve(docRef, unlock: remote3) == docValue1,
              "a remote unlock resolves a document-tier value from its mirror after a restart")
        check(try await run3.resolver.resolve(blobRef, unlock: remote3) == blobValue,
              "a remote unlock resolves a blob-tier value from its mirror after a restart")
        check(try await run3.resolver.resolve(opRef, unlock: remote3) == opValue,
              "a remote unlock resolves a cached value from its cache mirror after a restart")
        let docLoadsAfter = await world.docKeys.loadCount
        let blobLoadsAfter = await world.blobKeys.loadCount
        check(docLoadsAfter == docLoads && blobLoadsAfter == blobLoads,
              "a remote read never touches a native key record's biometric item")
        check(await world.cacheItems.loadCount == cacheLoads,
              "a remote read never touches the cache's biometric item")
        check(await world.remoteProvider.resolveCount == remoteResolves,
              "a cache mirror hit never reaches the remote provider")
        check(!(await run3.provider.requiresUnlockToResolve(docRef)),
              "a remote open leaves the store warm for the rest of the run")
        check(try await run3.resolver.resolve(docRef, unlock: nil) == docValue1,
              "after a remote open, a grant reuse with no unlock resolves")

        // MARK: A remote unlock never writes.
        let recordBefore = await world.docKeys.record(for: "remote-a")
        await expectNativeError(.authenticationRequired, "beginEdit refuses a remote unlock") {
            try await run3.provider.beginEdit(
                store: storeA, callerPID: callerPID, callerStartTime: callerStart, unlock: remote3
            )
        }
        await expectNativeError(.authenticationRequired, "putBlobs refuses a remote unlock") {
            try await run3.blobs.putBlobs(
                store: storeA,
                requests: [.init(key: "other_json", data: blobValue, mode: 0o600, path: "config/other.json")],
                unlock: remote3
            )
        }
        await expectNativeError(.authenticationRequired, "removeBlobs refuses a remote unlock") {
            try await run3.blobs.removeBlobs(store: storeA, keys: ["service_json"], unlock: remote3)
        }
        check(await world.docKeys.record(for: "remote-a") == recordBefore,
              "the key record is unchanged after the refused remote writes")

        // MARK: A commit re-seals the mirror.
        let oldMirror = await world.items.rawItems()[docMirrorA]
        let oldFiles = Set(await world.docFiles.snapshot().keys)
        let loadsBeforeEdit = await world.docKeys.loadCount
        try await commitDocument(run3, storeA, ["API_TOKEN": String(decoding: docValue2, as: UTF8.self)])
        check(await world.docKeys.loadCount == loadsBeforeEdit + 1,
              "an edit of a store opened remotely re-reads the key record with its local context first")
        let newMirror = await world.items.rawItems()[docMirrorA]
        check(newMirror != nil && newMirror != oldMirror, "a commit re-seals the document mirror")
        let run4 = await bootRemoteUnlockRun(world, previous: kept)
        let remote4 = try await phoneApprovedUnlock(run4.store, phone: phone)
        check(try await run4.resolver.resolve(docRef, unlock: remote4) == docValue2,
              "after a commit and a restart, a remote read serves the committed value")
        check(!oldFiles.isSubset(of: Set(await world.docFiles.snapshot().keys)),
              "the commit removed the previous generation's file")
        await world.items.setRaw(oldMirror, for: docMirrorA)
        let run5 = await bootRemoteUnlockRun(world, previous: kept)
        let remote5 = try await phoneApprovedUnlock(run5.store, phone: phone)
        await expectNativeError(.integrityFailure,
                                "a replayed pre-commit mirror fails closed instead of serving the old value") {
            try await run5.resolver.resolve(docRef, unlock: remote5)
        }
        check(await run5.provider.requiresUnlockToResolve(docRef),
              "a mirror that failed validation leaves nothing warm")
        check(try await run5.resolver.resolve(docRef, unlock: local) == docValue2,
              "a local open still works after a failed remote open")
        check(await world.items.rawItems()[docMirrorA] != oldMirror,
              "a local open re-seals the mirror")

        // MARK: Missing, corrupt, swapped and foreign mirrors fail closed.
        await world.items.setRaw(nil, for: docMirrorA)
        let run6 = await bootRemoteUnlockRun(world, previous: kept)
        let missingCoverage = await run6.resolver.remoteUnlockCoverage([docRef, docRefB])
        check(missingCoverage.uncovered == [docRef.uri],
              "a store whose mirror is missing is reported not covered; its neighbour still is")
        let remote6 = try await phoneApprovedUnlock(run6.store, phone: phone)
        await expectNativeError(.authenticationRequired, "a missing mirror needs a local touch") {
            try await run6.resolver.resolve(docRef, unlock: remote6)
        }
        check(await world.docKeys.record(for: "remote-a") != nil,
              "a missing mirror never reinitializes the store")
        _ = try await run6.resolver.resolve(docRef, unlock: local)

        if var corrupt = await world.items.rawItems()[docMirrorA] {
            corrupt[corrupt.count - 1] ^= 0x01
            await world.items.setRaw(corrupt, for: docMirrorA)
        }
        let run7 = await bootRemoteUnlockRun(world, previous: kept)
        let remote7 = try await phoneApprovedUnlock(run7.store, phone: phone)
        await expectNativeError(.keyUnavailable, "a corrupt mirror fails closed") {
            try await run7.resolver.resolve(docRef, unlock: remote7)
        }
        _ = try await run7.resolver.resolve(docRef, unlock: local)

        await world.items.setRaw(await world.items.rawItems()[docMirrorB], for: docMirrorA)
        let run8 = await bootRemoteUnlockRun(world, previous: kept)
        let remote8 = try await phoneApprovedUnlock(run8.store, phone: phone)
        await expectNativeError(.keyUnavailable, "a mirror moved to another store's name does not open") {
            try await run8.resolver.resolve(docRef, unlock: remote8)
        }
        _ = try await run8.resolver.resolve(docRef, unlock: local)

        let foreignItems = InMemoryRemoteUnlockItemBackend()
        let foreignStore = RemoteUnlockStore(backend: foreignItems, buildIdentity: "build-a")
        try await foreignStore.enroll(
            phoneKeyAgreementPublicKeyX963: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
            macDeviceID: macDeviceID, phoneDeviceID: UUID().uuidString
        )
        if let currentRecord = await world.docKeys.record(for: "remote-a") {
            try await foreignStore.sealAndStore(
                .nativeDocuments(store: "remote-a"), payload: try JSONEncoder().encode(currentRecord)
            )
        }
        await world.items.setRaw(await foreignItems.rawItems()[docMirrorA], for: docMirrorA)
        let run9 = await bootRemoteUnlockRun(world, previous: kept)
        let remote9 = try await phoneApprovedUnlock(run9.store, phone: phone)
        await expectNativeError(.keyUnavailable, "a mirror sealed for another enrollment does not open") {
            try await run9.resolver.resolve(docRef, unlock: remote9)
        }
        _ = try await run9.resolver.resolve(docRef, unlock: local)

        // A key opened for an enrollment that was then replaced opens nothing.
        let run10 = await bootRemoteUnlockRun(world, previous: kept)
        let staleUnlock = try await phoneApprovedUnlock(run10.store, phone: phone)
        let (staleChallenge, staleEnrollmentID) = try await run10.store.challenge()
        phone = P256.KeyAgreement.PrivateKey()
        phoneDeviceID = UUID().uuidString.lowercased()
        try await run10.store.enroll(
            phoneKeyAgreementPublicKeyX963: phone.publicKey.x963Representation,
            macDeviceID: macDeviceID, phoneDeviceID: phoneDeviceID
        )
        check(try await run10.store.mirrors().isEmpty, "re-enrolling deletes every earlier mirror")
        let rebackfill = await run10.resolver.backfillRemoteUnlockMirrors(localUnlock: local)
        check(rebackfill.mirrored == 4 && rebackfill.failed == 0, "backfill after re-enrolling mirrors everything again")
        let run10b = await bootRemoteUnlockRun(world, previous: kept)
        await expectNativeError(.keyUnavailable, "a remote key from the replaced enrollment opens nothing") {
            try await run10b.provider.resolve(docRef, unlock: staleUnlock)
        }
        do {
            _ = try await run10.store.openRemoteUnlock(
                challenge: staleChallenge, answer: Data(repeating: 1, count: 32), enrollmentID: staleEnrollmentID
            )
            check(false, "a challenge from the replaced enrollment is refused")
        } catch {
            check(error as? RemoteUnlockStoreError == .enrollmentMismatch,
                  "a challenge from the replaced enrollment is refused (\(error))")
        }

        // MARK: Cache invalidation removes the mirror, and never silently.
        let run11 = await bootRemoteUnlockRun(world, previous: kept)
        check(await run11.cache.holdsRemoteUnlockMirror(opURI), "the cached entry is mirrored")
        check(await run11.resolver.invalidate(references: [opURI]).isEmpty,
              "invalidation reports nothing left behind")
        check(!(await world.cacheItems.has(opURI)), "invalidation drops the cache's biometric item")
        check(await world.items.rawItems()[cacheMirrorOp] == nil, "invalidation drops the cache mirror")
        check(!(await run11.cache.holds(opURI)), "an invalidated entry is no longer held in any tier")
        let remote11 = try await phoneApprovedUnlock(run11.store, phone: phone)
        check(try await run11.cache.get(opURI, unlock: remote11) == nil,
              "a remote read after invalidation misses")
        _ = try await run11.resolver.resolve(opRef, unlock: local)
        check(await world.items.rawItems()[cacheMirrorOp] != nil, "a later cache write seals a new mirror")

        await world.items.failDeletes(
            service: RemoteUnlockStore.mirrorService, account: "cache/\(opURI)", status: errSecIO
        )
        check(await run11.resolver.invalidate(references: [opURI]).isEmpty,
              "a mirror whose delete fails is neutralized, so invalidation still holds")
        check(await world.items.rawItems()[cacheMirrorOp] != nil, "the undeletable mirror item is still there")
        check(!(await run11.cache.holdsRemoteUnlockMirror(opURI)),
              "an undeletable mirror is not reported as held")
        check(try await run11.cache.get(opURI, unlock: remote11) == nil,
              "an undeletable mirror is never served for the rest of the run")
        check(await world.items.rawItems()[epochItem] == nil,
              "an undeletable mirror clears the epoch, so the next start deletes every mirror")
        await world.items.failDeletes(
            service: RemoteUnlockStore.mirrorService, account: "cache/\(opURI)", status: nil
        )
        let run12 = await bootRemoteUnlockRun(world, previous: kept)
        check(run12.epoch == .cleared, "a start after a neutralized mirror clears the mirrors")
        check(try await run12.store.mirrors().isEmpty, "the neutralized mirror is gone after the restart")

        _ = try await run12.resolver.resolve(opRef, unlock: local)
        check(await world.items.rawItems()[cacheMirrorOp] != nil, "a local read restores the cleared cache mirror")
        await world.items.failDeletes(
            service: RemoteUnlockStore.mirrorService, account: "cache/\(opURI)", status: errSecIO
        )
        await world.items.failDeletes(service: RemoteUnlockStore.service, account: "epoch-v1", status: errSecIO)
        check(await run12.resolver.invalidate(references: [opURI]) == [opURI],
              "when neither the mirror nor the epoch can be deleted, invalidation reports the reference")
        await world.items.failDeletes(
            service: RemoteUnlockStore.mirrorService, account: "cache/\(opURI)", status: nil
        )
        await world.items.failDeletes(service: RemoteUnlockStore.service, account: "epoch-v1", status: nil)
        check(await run12.resolver.invalidate(references: [opURI]).isEmpty,
              "invalidation succeeds again once the Keychain does")

        // MARK: Expiry: a mirror is served exactly as the Keychain entry is.
        // Cache entries carry no expiry; a legacy `expiresAt` is ignored by both.
        let legacyURI = "op://vault/legacy/field"
        let legacyValue = Data("synthetic-legacy-value".utf8)
        let legacyEntry = Data(
            "{\"value\":\"\(legacyValue.base64EncodedString())\",\"expiresAt\":1}".utf8
        )
        let run13 = await bootRemoteUnlockRun(world, previous: kept)
        await world.cacheItems.plant(legacyEntry, for: legacyURI)
        try await run13.store.sealAndStore(.cache(uri: legacyURI), payload: legacyEntry)
        let run14 = await bootRemoteUnlockRun(world, previous: kept)
        let localLegacy = try await run14.cache.get(legacyURI, unlock: local)
        let run15 = await bootRemoteUnlockRun(world, previous: kept)
        let remote15 = try await phoneApprovedUnlock(run15.store, phone: phone)
        let remoteLegacy = try await run15.cache.get(legacyURI, unlock: remote15)
        check(localLegacy == legacyValue && remoteLegacy == localLegacy,
              "an entry with a long-past legacy expiresAt is served identically by the item and its mirror")
        try await run15.store.sealAndStore(.cache(uri: legacyURI), payload: Data("not a cache entry".utf8))
        let run15b = await bootRemoteUnlockRun(world, previous: kept)
        let remote15b = try await phoneApprovedUnlock(run15b.store, phone: phone)
        check(try await run15b.cache.get(legacyURI, unlock: remote15b) == nil,
              "a mirror that does not decode as a cache entry is a miss")
        check(await world.items.rawItems()[mirrorItem("cache/\(legacyURI)")] == nil,
              "an undecodable mirror is dropped, as an undecodable item is")

        // MARK: Epoch: another build in between clears every mirror.
        let run16 = await bootRemoteUnlockRun(world, previous: remoteUnlockLastRun("build-older"))
        check(run16.epoch == .cleared, "a previous run of another build clears the mirrors")
        check(try await run16.store.mirrors().isEmpty, "no mirror survives an unknown build's run")
        let remote16 = try await phoneApprovedUnlock(run16.store, phone: phone)
        await expectNativeError(.authenticationRequired, "after the epoch clears the mirrors a remote read needs a touch") {
            try await run16.resolver.resolve(docRef, unlock: remote16)
        }
        _ = try await run16.resolver.resolve(docRef, unlock: local)
        _ = try await run16.resolver.resolve(blobRef, unlock: local)
        _ = try await run16.resolver.resolve(opRef, unlock: local)
        let recreated = Set(try await run16.store.mirrors())
        check(recreated.isSuperset(of: [.nativeDocuments(store: "remote-a"), .nativeBlobs(store: "remote-a"),
                                        .cache(uri: opURI)]),
              "local opens bring back the document, blob and cache mirrors")
        check(await world.items.rawItems()[epochItem] != nil, "the epoch is rewritten for this build")
        check(await bootRemoteUnlockRun(world, previous: nil).epoch == .cleared,
              "an unknown previous run clears the mirrors")
        let run17 = await bootRemoteUnlockRun(world, build: nil, previous: kept)
        let epochAfterAnonymousBuild = await world.items.rawItems()[epochItem]
        check(run17.epoch == .kept && epochAfterAnonymousBuild == nil,
              "a build with no identity keeps what is consistent but records no epoch")
        check(await bootRemoteUnlockRun(world, previous: kept).epoch == .cleared,
              "the start after a build with no identity clears the mirrors")

        // A clear that fails must not leave the epoch vouching for what it
        // could not delete: the next start of the same build clears it.
        let run17b = await bootRemoteUnlockRun(world, previous: kept)
        _ = try await run17b.resolver.resolve(docRef, unlock: local)
        await world.items.failDeletes(service: RemoteUnlockStore.mirrorService, status: errSecInteractionNotAllowed)
        let failedClear = await bootRemoteUnlockRun(world, previous: remoteUnlockLastRun("build-older"))
        await world.items.failDeletes(service: RemoteUnlockStore.mirrorService, status: nil)
        let epochAfterFailedClear = await world.items.rawItems()[epochItem]
        let leftBehind = try await failedClear.store.mirrors()
        check(failedClear.epoch == .clearFailed && epochAfterFailedClear == nil && !leftBehind.isEmpty,
              "a mirror clear that fails drops the epoch, so it no longer vouches for the mirrors left behind")
        let afterFailedClear = await bootRemoteUnlockRun(world, previous: kept)
        let survivors = try await afterFailedClear.store.mirrors()
        check(afterFailedClear.epoch == .cleared && survivors.isEmpty,
              "the next start of the same build clears the mirrors a failed clear left")

        // MARK: Nothing is served before the epoch is reconciled.
        let run18 = await bootRemoteUnlockRun(world, previous: kept)
        _ = try await run18.resolver.resolve(docRef, unlock: local)
        let run19 = await bootRemoteUnlockRun(world, previous: kept, reconcile: false)
        let remote19 = try await phoneApprovedUnlock(run19.store, phone: phone)
        await expectNativeError(.authenticationRequired, "no mirror is served before reconcileEpoch runs") {
            try await run19.resolver.resolve(docRef, unlock: remote19)
        }
        check(!(await run19.resolver.remoteUnlockCoverage([docRef]).isComplete),
              "nothing is reported covered before reconcileEpoch runs")

        // MARK: Native values are noCache and never reach the cache mirror.
        let cacheMirrors = try await run18.store.mirrors().filter {
            if case let .cache(uri) = $0 { return uri.hasPrefix("csec://") }
            return false
        }
        let nativeValueCached = await world.cacheItems.has(docRef.uri)
        check(cacheMirrors.isEmpty && !nativeValueCached,
              "native (noCache) values never enter the cache or its mirror")

        // MARK: warm() works with a remote unlock (the mirrored restore panel).
        _ = try await run18.resolver.resolve(blobRef, unlock: local)
        _ = try await run18.resolver.resolve(opRef, unlock: local)
        let run20 = await bootRemoteUnlockRun(world, previous: kept)
        let remote20 = try await phoneApprovedUnlock(run20.store, phone: phone)
        await run20.resolver.warm([docRef, blobRef, opRef], unlock: remote20)
        check(!(await run20.resolver.requiresUnlock([docRef, blobRef])),
              "warm with a remote unlock opens both native tiers")
        check(await run20.resolver.resolveWithoutInteraction(opRef) == opValue,
              "warm with a remote unlock promotes the cached entry into the warm tier")

        // MARK: A remote unlock is invalidated like a context.
        let run21 = await bootRemoteUnlockRun(world, previous: kept)
        let remote21 = try await phoneApprovedUnlock(run21.store, phone: phone)
        remote21.invalidate()
        check(remote21.remote?.isInvalidated == true, "invalidate drops the remote key")
        await expectNativeError(.authenticationRequired, "an invalidated remote unlock opens nothing") {
            try await run21.resolver.resolve(docRef, unlock: remote21)
        }
        check(local.isLocal && local.context != nil && local.remote == nil,
              "a context unlock is local and carries its LAContext")

        // MARK: Disable removes everything, and nothing is written after.
        let run22 = await bootRemoteUnlockRun(world, previous: kept)
        try await run22.store.removeAllRemoteUnlockState()
        check(await world.items.rawItems().isEmpty, "removing remote-unlock state deletes every item")
        check(!(await run22.store.isEnrolled()), "after removal nothing is enrolled")
        await world.items.clearOperations()
        _ = try await run22.resolver.resolve(docRef, unlock: local)
        try await commitDocument(run22, storeA, ["API_TOKEN": String(decoding: docValue1, as: UTF8.self)])
        _ = await run22.resolver.invalidate(references: [opURI])
        _ = try await run22.resolver.resolve(opRef, unlock: local)
        let opsAfterRemoval = await world.items.operations
        let itemsAfterRemoval = await world.items.rawItems()
        check(opsAfterRemoval.isEmpty && itemsAfterRemoval.isEmpty,
              "after removal, opens, commits and cache writes touch no remote-unlock item")
    } catch {
        check(false, "remote-unlock storage flow threw unexpectedly (\(error))")
    }

    await remoteUnlockCommitOrderingTests()
    await remoteUnlockCoverageNeutralityTests()
    remoteUnlockKeychainQueryShapeTests()
    await remoteUnlockConsistencyFixTests()
}

/// A key backend that "crashes" csecd right after the record moves: the
/// update lands, and nothing after it in the commit ever runs.
actor CrashingNativeKeyBackend: NativeStoreKeyBackend {
    let inner = InMemoryNativeStoreKeyBackend()
    private var crashNextUpdate = false
    private(set) var crashed = false

    func armCrash() { crashNextUpdate = true }

    func load(store: String, unlock: CacheUnlock?) async throws -> NativeStoreKeyRecord? {
        try await inner.load(store: store, unlock: unlock)
    }

    func create(store: String, record: NativeStoreKeyRecord) async throws {
        try await inner.create(store: store, record: record)
    }

    func update(store: String, record: NativeStoreKeyRecord, unlock: CacheUnlock?) async throws {
        try await inner.update(store: store, record: record, unlock: unlock)
        guard crashNextUpdate else { return }
        crashNextUpdate = false
        crashed = true
        // The process is gone from here on: nothing after the update may run,
        // so this never returns (the test process exits first). It is never
        // cancelled; a cancelled sleep would let the "dead" write finish.
        while true {
            try? await Task.sleep(nanoseconds: 3_600 * 1_000_000_000)
        }
    }

    func recordExists(store: String) async -> Bool { await inner.recordExists(store: store) }
    func storeNames(unlock: CacheUnlock) async throws -> [String] { try await inner.storeNames(unlock: unlock) }
}

/// The mirror goes before the key record moves: a crash between the update
/// and the re-seal leaves no mirror, never one that still opens the previous
/// generation while its file lingers; and a commit whose old mirror can be
/// neither deleted nor neutralized does not move the record at all.
private func remoteUnlockCommitOrderingTests() async {
    let local = CacheUnlock(LAContext())
    let phone = P256.KeyAgreement.PrivateKey()
    let keys = CrashingNativeKeyBackend()
    let files = InMemoryNativeStoreFileBackend()
    let items = InMemoryRemoteUnlockItemBackend()
    let kept = remoteUnlockLastRun("build-a")
    let ref = try! SecretRef("csec://ordered/API_TOKEN")
    let store = try! NativeStoreName("ordered")
    let first = "synthetic-ordered-1"
    let second = "synthetic-ordered-2"

    func boot() async -> (RemoteUnlockStore, NativeEncryptedFileProvider) {
        let remoteStore = RemoteUnlockStore(backend: items, buildIdentity: "build-a")
        await remoteStore.reconcileEpoch(previousRun: kept)
        return (remoteStore, NativeEncryptedFileProvider(keyBackend: keys, fileBackend: files, remoteUnlock: remoteStore))
    }
    func commit(_ provider: NativeEncryptedFileProvider, _ value: String) async throws {
        let session = try await provider.beginEdit(store: store, callerPID: 4242, callerStartTime: 1, unlock: local)
        _ = try await provider.commitEdit(
            sessionID: session.sessionID,
            document: try NativeStoreDocument(values: ["API_TOKEN": value]).encoded(),
            callerPID: 4242, callerStartTime: 1
        )
    }

    do {
        let (enrolling, provider1) = await boot()
        try await enrolling.enroll(
            phoneKeyAgreementPublicKeyX963: phone.publicKey.x963Representation,
            macDeviceID: UUID().uuidString, phoneDeviceID: UUID().uuidString
        )
        try await commit(provider1, first)
        let filesBeforeCrash = Set(await files.snapshot().keys)

        await keys.armCrash()
        // Never cancelled: waking it would let the "dead" commit finish.
        _ = Task { try await commit(provider1, second) }
        var waited = 0
        while !(await keys.crashed), waited < 10_000 {
            try? await Task.sleep(nanoseconds: 1_000_000)
            waited += 1
        }
        check(await keys.crashed, "the commit reached the key-record update before the simulated crash")
        let filesAfterCrash = Set(await files.snapshot().keys)
        check(filesBeforeCrash.isSubset(of: filesAfterCrash),
              "after the crash the previous generation's file still lingers")

        let (restarted, provider2) = await boot()
        let remote = try await phoneApprovedUnlock(restarted, phone: phone)
        await expectNativeError(.authenticationRequired,
                                "after a crash between the record update and the re-seal no mirror is left to open the old generation") {
            try await provider2.resolve(ref, unlock: remote)
        }
        let reopened = try await provider2.resolve(ref, unlock: local)
        check(reopened.value == Data(second.utf8), "the key record the crash left holds the committed generation")
        let (restartedAgain, provider3) = await boot()
        let remoteAgain = try await phoneApprovedUnlock(restartedAgain, phone: phone)
        check(try await provider3.resolve(ref, unlock: remoteAgain).value == Data(second.utf8),
              "the local open after the crash re-sealed the mirror for the committed generation")

        let (_, provider4) = await boot()
        await items.failDeletes(service: RemoteUnlockStore.mirrorService, account: "doc/ordered", status: errSecIO)
        await items.failDeletes(service: RemoteUnlockStore.service, account: "epoch-v1", status: errSecIO)
        let recordBefore = await keys.inner.record(for: "ordered")
        let filesBefore = Set(await files.snapshot().keys)
        await expectNativeError(.keyUnavailable,
                                "a commit whose old mirror can be neither deleted nor neutralized is refused") {
            try await commit(provider4, "synthetic-ordered-3")
        }
        let recordAfter = await keys.inner.record(for: "ordered")
        let filesAfter = Set(await files.snapshot().keys)
        check(recordAfter == recordBefore && filesAfter == filesBefore,
              "the refused commit moved no key record and left no new file behind")
        await items.failDeletes(service: RemoteUnlockStore.mirrorService, account: "doc/ordered", status: nil)
        await items.failDeletes(service: RemoteUnlockStore.service, account: "epoch-v1", status: nil)

        // The blob tier keeps the same order.
        let blobKeys = CrashingNativeKeyBackend()
        let blobFiles = InMemoryNativeStoreFileBackend()
        func bootBlobs() async -> (RemoteUnlockStore, NativeBlobStore) {
            let remoteStore = RemoteUnlockStore(backend: items, buildIdentity: "build-a")
            await remoteStore.reconcileEpoch(previousRun: kept)
            return (remoteStore, NativeBlobStore(keyBackend: blobKeys, fileBackend: blobFiles, remoteUnlock: remoteStore))
        }
        func put(_ blobs: NativeBlobStore, _ value: String) async throws {
            _ = try await blobs.putBlobs(
                store: store,
                requests: [.init(key: "blob_json", data: Data(value.utf8), mode: 0o600, path: "blob.json")],
                unlock: local
            )
        }
        let (_, blobs1) = await bootBlobs()
        try await put(blobs1, first)
        await blobKeys.armCrash()
        _ = Task { try await put(blobs1, second) }
        waited = 0
        while !(await blobKeys.crashed), waited < 10_000 {
            try? await Task.sleep(nanoseconds: 1_000_000)
            waited += 1
        }
        check(await blobKeys.crashed, "the blob write reached the key-record update before the simulated crash")
        let (blobRestarted, blobs2) = await bootBlobs()
        let blobRemote = try await phoneApprovedUnlock(blobRestarted, phone: phone)
        await expectNativeError(.authenticationRequired,
                                "after a crash mid blob write no mirror is left to open the old index") {
            try await blobs2.loadBlob(store: store, key: "blob_json", unlock: blobRemote)
        }
        check(try await blobs2.loadBlob(store: store, key: "blob_json", unlock: local).data == Data(second.utf8),
              "a local open after the crash serves the committed blob and re-seals its mirror")
        let (blobRestartedAgain, blobs3) = await bootBlobs()
        let blobRemoteAgain = try await phoneApprovedUnlock(blobRestartedAgain, phone: phone)
        check(try await blobs3.loadBlob(store: store, key: "blob_json", unlock: blobRemoteAgain).data
                  == Data(second.utf8),
              "after the re-seal a remote read serves the committed blob")
    } catch {
        check(false, "remote-unlock commit ordering threw unexpectedly (\(error))")
    }
}

/// Coverage comes from the provider seam and the cache, whatever the scheme.
private func remoteUnlockCoverageNeutralityTests() async {
    let local = CacheUnlock(LAContext())
    do {
        let items = InMemoryRemoteUnlockItemBackend()
        let store = RemoteUnlockStore(backend: items, buildIdentity: "build-a")
        try await store.enroll(
            phoneKeyAgreementPublicKeyX963: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
            macDeviceID: UUID().uuidString, phoneDeviceID: UUID().uuidString
        )
        let cache = KeychainSecretCache(backend: RemoteUnlockFakeKeychain(), remoteUnlock: store)
        let resolver = SecretResolver(cache: cache)
        await resolver.register(RemoteCoverageFixtureProvider(
            scheme: "vault", needsUnlock: true, opensRemotely: false, value: "synthetic-vault"
        ))
        await resolver.register(RemoteCoverageFixtureProvider(
            scheme: "keyring", needsUnlock: true, opensRemotely: true, value: "synthetic-keyring"
        ))
        await resolver.register(RemoteCoverageFixtureProvider(
            scheme: "plain", needsUnlock: false, opensRemotely: false, value: "synthetic-plain"
        ))
        let vault = try SecretRef("vault://a/b")
        let keyring = try SecretRef("keyring://a/b")
        let plain = try SecretRef("plain://a/b")

        let mixed = await resolver.remoteUnlockCoverage([vault, keyring, plain])
        check(mixed.needsUnlock == [vault.uri, keyring.uri],
              "coverage asks each provider whether its reference needs an unlock")
        check(mixed.coveredRemotely == [keyring.uri] && mixed.uncovered == [vault.uri] && !mixed.isComplete,
              "a provider that cannot open with a remote unlock leaves its reference uncovered")
        check(await resolver.remoteUnlockCoverage([keyring, plain]).isComplete,
              "a provider that can open with a remote unlock covers its reference")
        _ = try await resolver.resolve(vault, unlock: local)
        let viaCache = await resolver.remoteUnlockCoverage([vault])
        check(viaCache.isComplete && viaCache.coveredRemotely == [vault.uri],
              "a reference whose value the cache mirror holds is covered whatever its provider says")
    } catch {
        check(false, "remote-unlock coverage neutrality threw unexpectedly (\(error))")
    }
}

/// Every remote-unlock item: explicit access group, data-protection Keychain,
/// never synchronized, no access control, readable after first unlock.
private func remoteUnlockKeychainQueryShapeTests() {
    for operation in RemoteUnlockKeychainOperation.allCases {
        let query = SecurityRemoteUnlockItemBackend.query(
            service: RemoteUnlockStore.mirrorService,
            account: operation == .list ? nil : "doc/synthetic",
            operation: operation
        )
        check((query[kSecAttrAccessGroup as String] as? String) == ProtectedItem.accessGroup
                  && (query[kSecUseDataProtectionKeychain as String] as? Bool) == true
                  && (query[kSecAttrSynchronizable as String] as? Bool) == false
                  && query[kSecAttrAccessControl as String] == nil,
              "remote-unlock \(operation.rawValue) query: explicit group, data-protection, not synchronizable, no ACL")
    }
    let add = SecurityRemoteUnlockItemBackend.query(
        service: RemoteUnlockStore.service, account: "enrollment-v1", operation: .add
    )
    check((add[kSecAttrAccessible as String] as? String)
              == (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String),
          "remote-unlock items are created AfterFirstUnlockThisDeviceOnly, readable behind a locked screen")
}
