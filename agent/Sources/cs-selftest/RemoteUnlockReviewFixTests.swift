import CryptoKit
import CSECRemoteApproval
import ConvenientSecurity
import Foundation
import LocalAuthentication
import OnePasswordAdapter
import Security
import CSECBuildIdentity

// Regressions from an adversarial review of the Mac side of remote unlock:
// what a phone-approved restore can reopen, cache invalidation racing a read,
// a cache copy older than its item, copies left behind by a failed removal,
// and a re-pairing that fails half-way. Every backend is in memory and every
// value synthetic; software P-256 keys stand in for the phone's.

// MARK: - Fixtures

private let fixContainerIdentifier = CSECBuildIdentity.cloudKitContainer

/// The bytes a cache item holds for `value` (a `CacheEntry`).
private func fixCacheEntry(_ value: String) -> Data {
    Data("{\"value\":\"\(Data(value.utf8).base64EncodedString())\"}".utf8)
}

private func fixMirrorItem(_ uri: String) -> RemoteUnlockItemName {
    RemoteUnlockItemName(service: RemoteUnlockStore.mirrorService, account: "cache/\(uri)")
}

private let fixEpochItem = RemoteUnlockItemName(service: RemoteUnlockStore.service, account: "epoch-v1")

private func fixLastRun(_ cdHash: String) -> CsecdLastRun {
    CsecdLastRun(bootSessionUUID: "synthetic-boot", pid: 4242, startTimeMicros: 1, cdHash: cdHash, version: nil)
}

/// A pairing record for `phone`, signed for by a software Mac key.
private func fixPairingRecord(for phone: SyntheticPhone) -> StoredRemoteApprovalConfiguration {
    let macKey = P256.Signing.PrivateKey()
    return StoredRemoteApprovalConfiguration(
        macDeviceID: UUID().uuidString.lowercased(),
        macDeviceName: "Mac",
        macSigningKeyRepresentation: macKey.rawRepresentation,
        macPublicKeyX963: macKey.publicKey.x963Representation,
        phoneDeviceID: phone.deviceID,
        phoneDeviceName: phone.name,
        phonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
        phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
        cloudKitContainerIdentifier: fixContainerIdentifier
    )
}

/// Enroll `store` for exactly `pairing`.
private func fixEnroll(
    _ store: RemoteUnlockStore,
    for pairing: StoredRemoteApprovalConfiguration
) async throws {
    try await store.enroll(
        phoneKeyAgreementPublicKeyX963: pairing.phoneKeyAgreementPublicKeyX963,
        macDeviceID: pairing.macDeviceID,
        phoneDeviceID: pairing.phoneDeviceID
    )
}

/// The phone's side of one approval, then the Mac's.
private func fixPhoneUnlock(
    _ store: RemoteUnlockStore,
    phone: P256.KeyAgreement.PrivateKey
) async throws -> CacheUnlock {
    let (challenge, enrollmentID) = try await store.challenge()
    let answer = try RemoteUnlockCrypto.answer(blindedPoint: challenge.blindedPoint) {
        try phone.sharedSecretFromKeyAgreement(with: $0)
    }
    return try await store.openRemoteUnlock(challenge: challenge, answer: answer, enrollmentID: enrollmentID)
}

private final class FixLog: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []

    func append(_ line: String) {
        lock.lock()
        lines.append(line)
        lock.unlock()
    }

    var all: [String] {
        lock.lock()
        defer { lock.unlock() }
        return lines
    }
}

/// Touch ID that approves with a local (never evaluated, synthetic) context.
private actor FixConsent: ConsentProvider {
    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        .approved(unlock: CacheUnlock(LAContext()))
    }
}

private func fixManager(
    store: any RemoteApprovalConfigurationStore,
    relay: V3MailboxRelay,
    remoteUnlock: RemoteUnlockStore?,
    resolver: SecretResolver?,
    log: FixLog
) -> RemoteApprovalManager {
    RemoteApprovalManager(
        store: store,
        relay: relay,
        consent: FixConsent(),
        cloudKitContainerIdentifier: fixContainerIdentifier,
        accountStatus: { .available },
        macKeys: v3SoftwareMacKeys(),
        remoteUnlock: remoteUnlock,
        coverage: resolver.map { resolver in
            { @Sendable request in await resolver.remoteUnlockCoverage(request) }
        },
        backfill: resolver.map { resolver in
            { @Sendable unlock in await resolver.backfillRemoteUnlockMirrors(localUnlock: unlock) }
        },
        log: { log.append($0) }
    )
}

private func fixWaitForRequest(_ relay: V3MailboxRelay) async -> SignedRemoteApprovalRequest? {
    for _ in 0..<600 {
        if let envelope = await relay.request(number: 0) { return envelope }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return nil
}

private let fixSilentTerminal = TerminalSessionInspector(
    environment: { _ in nil }, parent: { _ in nil }, terminalName: { _ in nil }, titleQuery: { _ in nil }
)

private func fixCaller() -> CallerInfo {
    let me = getpid()
    return CallerInfo(pid: me, startTime: ProcessAncestry.startTime(of: me) ?? 0, description: "synthetic restore requester")
}

/// The Mac panel, held open until the test answers it. An approval carries
/// a local (synthetic, never evaluated) context, as a real touch would.
private actor HeldLocalReview: PolicyReviewProvider {
    private var waiting: [CheckedContinuation<Bool, Never>] = []
    private(set) var reviews = 0

    var pendingCount: Int { waiting.count }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews += 1
        let approved: Bool = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(returning: false)
                } else {
                    waiting.append(continuation)
                }
            }
        } onCancel: {
            Task { await self.cancelAll() }
        }
        guard approved else { return .denied(.requesterGone) }
        return .approved(AccessPolicyApproval(authenticationSession: LocalContextSession()))
    }

    func approve() {
        guard !waiting.isEmpty else { return }
        waiting.removeFirst().resume(returning: true)
    }

    private func cancelAll() {
        let held = waiting
        waiting = []
        for continuation in held { continuation.resume(returning: false) }
    }
}

private actor LocalContextSession: AccessPolicyAuthenticationSession {
    private var used = false

    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        guard !used else { return .denied }
        used = true
        return .approved(unlock: CacheUnlock(LAContext()))
    }

    func cancel() async { used = true }
}

/// A paired Claude Code project's restore row: its references a delegated
/// release could not resolve now but a touch could reopen, as
/// `DelegationRestoreSource` lists them.
private actor RestorableProjectSource: RestoreItemSource {
    private let resolver: SecretResolver
    private let references: [SecretRef]
    private(set) var finished: [RestoreItemOutcome] = []

    init(resolver: SecretResolver, references: [SecretRef]) {
        self.resolver = resolver
        self.references = references
    }

    func restoreItems() async -> [RestoreEntry] {
        let restorable = await resolver.referencesRestorable(references)
        let listed = references.filter { restorable.contains($0.uri) }
        guard !listed.isEmpty else { return [] }
        return [RestoreEntry(
            grantID: nil,
            row: RestoreReviewRow(
                kind: .pairedProject, title: "project", detail: "Claude Code auto mode in project",
                references: listed.map(\.uri)
            ),
            references: listed
        )]
    }

    func restoreFinished(_ outcome: RestoreItemOutcome) async {
        finished.append(outcome)
    }
}

/// A phone leg that is always ready without an unlock and approves without
/// one: what a readiness check that missed a cold reference would produce.
private actor UnlocklessPhone: RemoteAccessPolicyReviewProvider {
    private(set) var reviews = 0

    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        .ready(unlock: .notNeeded)
    }

    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        reviews += 1
        return .approved(
            selection: RemoteApprovalSelection(scopeOptionID: nil, durationIndex: nil, unlockAnswer: nil),
            unlock: nil
        )
    }
}

/// The cache's biometric items, in memory, whose loads and deletes can be
/// held open: a load returns what it read only when released, so it can be
/// overtaken by an invalidation after it read.
private actor HoldingCacheKeychain: KeychainBackend {
    enum Step: Hashable { case load, delete, store }

    private var items: [String: Data] = [:]
    private var holding: Set<Step> = []
    private var held: [Step: [CheckedContinuation<Void, Never>]] = [:]
    /// Runs as a store starts, before the item is written.
    private var onStore: (@Sendable (String) async -> Void)?

    func hold(_ step: Step) { holding.insert(step) }

    func release(_ step: Step) {
        holding.remove(step)
        let waiting = held[step] ?? []
        held[step] = nil
        for continuation in waiting { continuation.resume() }
    }

    func isHolding(_ step: Step) -> Bool { !(held[step] ?? []).isEmpty }

    func observeStores(_ observer: @escaping @Sendable (String) async -> Void) { onStore = observer }

    func raw(_ account: String) -> Data? { items[account] }

    func store(account: String, data: Data) async throws {
        await onStore?(account)
        await pause(.store)
        items[account] = data
    }

    func load(account: String, unlock: CacheUnlock?) async throws -> Data? {
        guard unlock?.isLocal == true else { throw NativeStoreError.authenticationRequired }
        let read = items[account]
        await pause(.load)
        return read
    }

    func delete(account: String) async {
        await pause(.delete)
        items[account] = nil
    }

    func contains(account: String) async -> Bool { items[account] != nil }

    private func pause(_ step: Step) async {
        guard holding.contains(step) else { return }
        await withCheckedContinuation { held[step, default: []].append($0) }
    }
}

/// Remote-unlock items whose mirror reads can be held after reading, and
/// whose enrollment read can fail.
private actor HoldingRemoteUnlockBackend: RemoteUnlockItemBackend {
    let inner = InMemoryRemoteUnlockItemBackend()
    private var failEnrollmentReads = false
    private var holdingAccount: String?
    private var held: [CheckedContinuation<Void, Never>] = []

    func failEnrollmentReads(_ fail: Bool) { failEnrollmentReads = fail }
    func holdReads(of account: String) { holdingAccount = account }

    func releaseReads() {
        holdingAccount = nil
        let waiting = held
        held = []
        for continuation in waiting { continuation.resume() }
    }

    var isHoldingRead: Bool { !held.isEmpty }

    func read(_ item: RemoteUnlockItemName) async throws -> Data? {
        if failEnrollmentReads, item.service == RemoteUnlockStore.service, item.account == "enrollment-v1" {
            throw RemoteUnlockStoreError.keychain(operation: "read", status: errSecInteractionNotAllowed)
        }
        let read = await inner.read(item)
        if item.account == holdingAccount {
            await withCheckedContinuation { held.append($0) }
        }
        return read
    }

    func write(_ item: RemoteUnlockItemName, data: Data) async throws { try await inner.write(item, data: data) }
    func delete(_ item: RemoteUnlockItemName) async throws { try await inner.delete(item) }
    func exists(_ item: RemoteUnlockItemName) async throws -> Bool { await inner.exists(item) }
    func accounts(service: String) async throws -> [String] { await inner.accounts(service: service) }
}

private struct FixStoreFailure: Error {}

/// A pairing store whose writes can be made to fail.
private actor FailingConfigurationStore: RemoteApprovalConfigurationStore {
    private let inner = V3MemoryConfigurationStore()
    private var failStores = false

    func failStores(_ fail: Bool) { failStores = fail }
    func current() async -> StoredRemoteApprovalConfiguration? { await inner.current() }

    func load() async throws -> StoredRemoteApprovalConfiguration? { try await inner.load() }

    func store(_ configuration: StoredRemoteApprovalConfiguration) async throws {
        if failStores { throw FixStoreFailure() }
        try await inner.store(configuration)
    }

    func delete() async throws { try await inner.delete() }
}

// MARK: - 1. A restore reopens cache-only references only from their copies

/// Run from `restorePanelTests`.
func remoteRestoreCoverageFixTests() async {
    print("\n# Remote restore coverage (a restore's cache-only references need their copies)")
    await restoreCoverageFromTheResolver()
    await restoreReadinessFromTheManager()
    await releaseCoverageOfCachedCopies()
    await releaseReadinessPrefersCachedCopies()
    await mirroredReviewPassesRestoreReferencesApart()
    await phoneRestoreOfCacheOnlyReferences(withCopy: true)
    await phoneRestoreOfCacheOnlyReferences(withCopy: false)
    await restoreClaimsOnlyWhatItReopened()
}

/// A restore reopens from local sealed state only, so its references are
/// judged by what that state holds; a release's keep their own sense.
private func restoreCoverageFromTheResolver() async {
    do {
        let items = InMemoryRemoteUnlockItemBackend()
        let store = RemoteUnlockStore(backend: items, buildIdentity: "build-fix")
        _ = await store.reconcileEpoch(previousRun: nil)
        try await store.enroll(
            phoneKeyAgreementPublicKeyX963: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
            macDeviceID: UUID().uuidString, phoneDeviceID: UUID().uuidString
        )
        let cacheItems = RemoteUnlockFakeKeychain()
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: cacheItems, remoteUnlock: store))
        await resolver.register(RemoteCoverageFixtureProvider(
            scheme: "op", needsUnlock: false, opensRemotely: false, value: "synthetic-coverage-fetched"
        ))
        await resolver.register(RemoteCoverageFixtureProvider(
            scheme: "vault", needsUnlock: true, opensRemotely: true, value: "synthetic-coverage-vault"
        ))
        let cached = try SecretRef("op://Fix/Coverage/cached")
        let uncached = try SecretRef("op://Fix/Coverage/uncached")
        let sealed = try SecretRef("vault://fix/coverage")
        await cacheItems.plant(fixCacheEntry("synthetic-coverage-cached"), for: cached.uri)

        let released = await resolver.remoteUnlockCoverage([cached])
        check(released.needsUnlock.isEmpty,
              "restore coverage: released, a reference its provider can fetch needs no unlock")
        let noCopy = await resolver.remoteUnlockCoverage([SecretRef](), restoring: [cached])
        check(noCopy.needsUnlock == [cached.uri] && !noCopy.isComplete,
              "restore coverage: restored, a reference only the cold cache holds needs an unlock, "
                + "and without its copy no phone approval covers it")
        let both = await resolver.remoteUnlockCoverage(
            RemoteUnlockCoverageRequest(references: [cached], restoring: [cached])
        )
        check(both.needsUnlock == [cached.uri] && !both.isComplete,
              "restore coverage: a reference both released and restored is judged as the restore reopens it")
        try await store.sealAndStore(.cache(uri: cached.uri), payload: fixCacheEntry("synthetic-coverage-cached"))
        let withCopy = await resolver.remoteUnlockCoverage([SecretRef](), restoring: [cached])
        check(withCopy.isComplete && withCopy.coveredRemotely == [cached.uri],
              "restore coverage: its cache copy covers it")
        let nothingToReopen = await resolver.remoteUnlockCoverage([SecretRef](), restoring: [uncached])
        check(nothingToReopen.needsUnlock.isEmpty,
              "restore coverage: a reference no touch could reopen adds no unlock to a restore")
        let providerOpens = await resolver.remoteUnlockCoverage([SecretRef](), restoring: [sealed])
        check(providerOpens.needsUnlock == [sealed.uri] && providerOpens.isComplete,
              "restore coverage: a sealed provider that opens with a remote unlock covers its restore reference")
        await resolver.warm([cached], unlock: CacheUnlock(LAContext()))
        let warmed = await resolver.remoteUnlockCoverage([SecretRef](), restoring: [cached])
        check(warmed.needsUnlock.isEmpty, "restore coverage: a value csecd already holds needs nothing reopened")
    } catch {
        check(false, "restore coverage from the resolver ran (\(error))")
    }
}

private func restoreReadinessFromTheManager() async {
    do {
        let phone = SyntheticPhone()
        let pairing = fixPairingRecord(for: phone)
        let items = InMemoryRemoteUnlockItemBackend()
        let store = RemoteUnlockStore(backend: items, buildIdentity: "build-fix")
        _ = await store.reconcileEpoch(previousRun: nil)
        try await fixEnroll(store, for: pairing)
        let cacheItems = RemoteUnlockFakeKeychain()
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: cacheItems, remoteUnlock: store))
        await resolver.register(RemoteCoverageFixtureProvider(
            scheme: "op", needsUnlock: false, opensRemotely: false, value: "synthetic-readiness-fetched"
        ))
        let reference = try SecretRef("op://Fix/Readiness/field")
        await cacheItems.plant(fixCacheEntry("synthetic-readiness-cached"), for: reference.uri)
        let manager = fixManager(
            store: V3MemoryConfigurationStore(record: pairing), relay: V3MailboxRelay(),
            remoteUnlock: store, resolver: resolver, log: FixLog()
        )
        await manager.prepare()
        let releasing = await manager.remoteReadiness(for: [reference])
        let restoringNoCopy = await manager.remoteReadiness(for: [], restoring: [reference])
        let nothing = await manager.remoteReadiness(for: [])
        check(releasing == .ready(unlock: .notNeeded) && nothing == .ready(unlock: .notNeeded),
              "restore readiness: releasing a fetchable reference, or naming none, needs no unlock")
        check(restoringNoCopy == .unavailable,
              "restore readiness: restoring a reference only the cold cache holds, with no copy, stays on the Mac")
        try await store.sealAndStore(.cache(uri: reference.uri), payload: fixCacheEntry("synthetic-readiness-cached"))
        let restoringWithCopy = await manager.remoteReadiness(for: [], restoring: [reference])
        check(restoringWithCopy == .ready(unlock: .required),
              "restore readiness: with its copy, the phone may restore it, carrying an unlock challenge")
    } catch {
        check(false, "restore readiness from the manager ran (\(error))")
    }
}

/// Released, a reference its provider can fetch with no unlock still names
/// its cached copy, so a phone approval can read that copy first; it never
/// makes the request need an unlock.
private func releaseCoverageOfCachedCopies() async {
    do {
        let items = InMemoryRemoteUnlockItemBackend()
        let store = RemoteUnlockStore(backend: items, buildIdentity: "build-fix")
        _ = await store.reconcileEpoch(previousRun: nil)
        try await store.enroll(
            phoneKeyAgreementPublicKeyX963: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
            macDeviceID: UUID().uuidString, phoneDeviceID: UUID().uuidString
        )
        let cacheItems = RemoteUnlockFakeKeychain()
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: cacheItems, remoteUnlock: store))
        await resolver.register(RemoteCoverageFixtureProvider(
            scheme: "op", needsUnlock: false, opensRemotely: false, value: "synthetic-cached-copy-fetched"
        ))
        await resolver.register(RemoteCoverageFixtureProvider(
            scheme: "vault", needsUnlock: true, opensRemotely: true, value: "synthetic-cached-copy-vault"
        ))
        let cached = try SecretRef("op://Fix/CachedCopy/cached")
        let uncached = try SecretRef("op://Fix/CachedCopy/uncached")
        let sealed = try SecretRef("vault://fix/cached-copy")
        await cacheItems.plant(fixCacheEntry("synthetic-cached-copy"), for: cached.uri)

        let noMirror = await resolver.remoteUnlockCoverage([cached])
        check(noMirror.needsUnlock.isEmpty && noMirror.cachedRemotely.isEmpty,
              "release coverage: a cache entry with no remote-unlock mirror offers the phone no cached read")
        try await store.sealAndStore(.cache(uri: cached.uri), payload: fixCacheEntry("synthetic-cached-copy"))
        let fetchable = await resolver.remoteUnlockCoverage([cached, uncached])
        check(fetchable.needsUnlock.isEmpty && fetchable.isComplete && fetchable.cachedRemotely == [cached.uri],
              "release coverage: a fetchable reference with a cache mirror is read from it first, and needs no unlock")
        let mixed = await resolver.remoteUnlockCoverage([cached, sealed])
        check(mixed.needsUnlock == [sealed.uri] && mixed.isComplete && mixed.cachedRemotely == [cached.uri],
              "release coverage: next to a reference that needs the unlock, the cached copy is still named")
        let restored = await resolver.remoteUnlockCoverage(
            RemoteUnlockCoverageRequest(references: [cached], restoring: [cached])
        )
        check(restored.needsUnlock == [cached.uri] && restored.cachedRemotely.isEmpty,
              "release coverage: a reference the restore must reopen needs the unlock, not merely prefers it")
    } catch {
        check(false, "release coverage of cached copies ran (\(error))")
    }
}

/// A phone approval of a fetchable reference carries the unlock challenge
/// when this pairing's factor could open its cached copy, and never stops
/// reaching the phone for want of one.
private func releaseReadinessPrefersCachedCopies() async {
    do {
        let phone = SyntheticPhone()
        let pairing = fixPairingRecord(for: phone)
        let reference = try SecretRef("op://Fix/CachedReadiness/field")
        let cacheEntry = fixCacheEntry("synthetic-cached-readiness")

        func readiness(enrolledFor enrolled: StoredRemoteApprovalConfiguration?, sealed: Bool,
                       with extra: [SecretRef] = []) async throws -> RemoteReviewReadiness {
            let store = RemoteUnlockStore(backend: InMemoryRemoteUnlockItemBackend(), buildIdentity: "build-fix")
            _ = await store.reconcileEpoch(previousRun: nil)
            if let enrolled { try await fixEnroll(store, for: enrolled) }
            if sealed { try await store.sealAndStore(.cache(uri: reference.uri), payload: cacheEntry) }
            let cacheItems = RemoteUnlockFakeKeychain()
            await cacheItems.plant(cacheEntry, for: reference.uri)
            let resolver = SecretResolver(cache: KeychainSecretCache(backend: cacheItems, remoteUnlock: store))
            await resolver.register(RemoteCoverageFixtureProvider(
                scheme: "op", needsUnlock: false, opensRemotely: false, value: "synthetic-cached-readiness-fetched"
            ))
            await resolver.register(RemoteCoverageFixtureProvider(
                scheme: "vault", needsUnlock: true, opensRemotely: true, value: "synthetic-cached-readiness-vault"
            ))
            let manager = fixManager(
                store: V3MemoryConfigurationStore(record: pairing), relay: V3MailboxRelay(),
                remoteUnlock: store, resolver: resolver, log: FixLog()
            )
            await manager.prepare()
            return await manager.remoteReadiness(for: [reference] + extra)
        }

        let withCopy = try await readiness(enrolledFor: pairing, sealed: true)
        check(withCopy == .ready(unlock: .preferred),
              "release readiness: a fetchable reference whose cached copy the pairing's factor opens prefers the unlock")
        let noCopy = try await readiness(enrolledFor: pairing, sealed: false)
        check(noCopy == .ready(unlock: .notNeeded),
              "release readiness: with no cached copy a fetchable reference needs no unlock")
        let otherPairing = fixPairingRecord(for: SyntheticPhone())
        let foreign = try await readiness(enrolledFor: otherPairing, sealed: true)
        check(foreign == .ready(unlock: .notNeeded),
              "release readiness: a copy only another pairing's factor opens still reaches the phone, with no challenge")
        let vault = try SecretRef("vault://fix/cached-readiness")
        let required = try await readiness(enrolledFor: pairing, sealed: true, with: [vault])
        check(required == .ready(unlock: .required),
              "release readiness: a reference that only opens with the unlock makes it required")
    } catch {
        check(false, "release readiness of cached copies ran (\(error))")
    }
}

/// Records what readiness was asked; never ready, so the Mac decides.
private actor ReadinessSpy: RemoteAccessPolicyReviewProvider {
    private(set) var asked: [(references: [String], restoring: [String])] = []

    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        asked.append((references.map(\.uri), restoring.map(\.uri)))
        return .unavailable
    }

    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        .unavailable
    }
}

private struct RefusingLocalReview: PolicyReviewProvider {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        .denied(.authenticationFailed)
    }
}

private func mirroredReviewPassesRestoreReferencesApart() async {
    do {
        let released = try SecretRef("op://Fix/Apart/released")
        let restored = "op://Fix/Apart/restored"
        let caller = CallerInfo(pid: 1, startTime: 1, description: "synthetic mirrored review")
        let restore = RestoreReviewDetails(
            cause: .restart,
            rows: [RestoreReviewRow(kind: .pairedProject, title: "project", detail: "d", references: [restored])],
            storeCount: 1
        )
        let plan = DeliveryPlan(
            mechanism: .unrestrictedInitialEnvironment,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/fix-apart", assurance: .unverified),
            root: .caller, descendantScope: .subtree, destination: .localDevelopment,
            requestedTTLSeconds: nil, operationContext: "synthetic mirrored review",
            outputGuard: OutputGuardPlan(mode: .tty)
        )
        let spy = ReadinessSpy()
        let mirrored = MirroredPolicyReview(local: RefusingLocalReview(), remote: spy, log: { _ in })
        _ = await mirrored.reviewAccess(AccessPolicyReview(
            caller: caller, reason: "mixed", plan: plan,
            credentials: [PolicyReviewCredential(references: [released])], restore: restore
        ))
        _ = await mirrored.reviewAccess(AccessPolicyReview.restoreOnly(caller: caller, restore: restore))
        let asked = await spy.asked
        check(asked.count == 2
                && asked[0].references == [released.uri] && asked[0].restoring == [restored]
                && asked[1].references.isEmpty && asked[1].restoring == [restored],
              "restore readiness: the mirrored review asks about its release's references and its restore rows apart")
    } catch {
        check(false, "mirrored review readiness ran (\(error))")
    }
}

private func phoneRestoreOfCacheOnlyReferences(withCopy: Bool) async {
    let label = withCopy ? "with its copy" : "without a copy"
    do {
        let phone = SyntheticPhone()
        let pairing = fixPairingRecord(for: phone)
        let items = InMemoryRemoteUnlockItemBackend()
        let store = RemoteUnlockStore(backend: items, buildIdentity: "build-fix")
        _ = await store.reconcileEpoch(previousRun: nil)
        try await fixEnroll(store, for: pairing)
        let reference = try SecretRef("op://Fix/Restore/field")
        let cacheItems = RemoteUnlockFakeKeychain()
        await cacheItems.plant(fixCacheEntry("synthetic-restore-cached"), for: reference.uri)
        if withCopy {
            try await store.sealAndStore(.cache(uri: reference.uri), payload: fixCacheEntry("synthetic-restore-cached"))
        }
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: cacheItems, remoteUnlock: store))
        await resolver.register(RemoteCoverageFixtureProvider(
            scheme: "op", needsUnlock: false, opensRemotely: false, value: "synthetic-restore-fetched"
        ))
        let relay = V3MailboxRelay()
        let manager = fixManager(
            store: V3MemoryConfigurationStore(record: pairing), relay: relay,
            remoteUnlock: store, resolver: resolver, log: FixLog()
        )
        await manager.prepare()
        let local = HeldLocalReview()
        let restoration = GrantRestoration(
            resolver: resolver,
            policyReview: MirroredPolicyReview(local: local, remote: manager, log: { _ in }),
            consent: FixConsent(),
            terminalInspection: fixSilentTerminal
        )
        await restoration.addItemSource(RestorableProjectSource(resolver: resolver, references: [reference]))
        let caller = fixCaller()
        let waiting = Task { await restoration.ensureWarmForDelegation(for: [reference], requester: caller) }

        if withCopy {
            guard let envelope = await fixWaitForRequest(relay) else {
                waiting.cancel()
                check(false, "restore coverage: a cache-only reference with its copy reaches the phone")
                return
            }
            check(envelope.request.review.kind == .restore && envelope.request.unlockChallenge != nil,
                  "restore coverage: a restore of a reference only the cache holds reaches the phone "
                    + "with an unlock challenge, since only its copy can reopen it")
            try await relay.publishResponse(try phone.approve(envelope))
        } else {
            let panelUp = await eventuallyTrue { await local.pendingCount == 1 }
            let published = await relay.published
            check(panelUp && published.isEmpty,
                  "restore coverage: a restore of a reference only the cache holds, with no copy, stays on the Mac")
            await local.approve()
        }
        let outcome = await waiting.value
        let held = await resolver.resolveWithoutInteraction(reference) != nil
        let usedUp = await restoration.isUsedUp
        check(outcome == .warmed && held && usedUp,
              "restore coverage: the approval (\(label)) reopens the cached value, and the restore is used up "
                + "(\(outcome), held \(held), used up \(usedUp))")
    } catch {
        check(false, "restore coverage: \(label) ran (\(error))")
    }
}

/// An approval whose unlock reopens nothing (here, a phone leg that approved
/// with none) must not be reported, logged or spent as a restore.
private func restoreClaimsOnlyWhatItReopened() async {
    do {
        let reference = try SecretRef("op://Fix/Honest/field")
        let cacheItems = RemoteUnlockFakeKeychain()
        await cacheItems.plant(fixCacheEntry("synthetic-honest-cached"), for: reference.uri)
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: cacheItems))
        await resolver.register(RemoteCoverageFixtureProvider(
            scheme: "op", needsUnlock: false, opensRemotely: false, value: "synthetic-honest-fetched"
        ))
        let logStores = ProtectedStores.processLocal()
        let decisionLog = DecisionLog(
            directory: SealedRecordDirectory(path: (NSTemporaryDirectory() as NSString)
                .appendingPathComponent("csec-restore-honesty-\(UUID().uuidString)")),
            stores: logStores
        )
        _ = await decisionLog.open()
        let phoneLeg = UnlocklessPhone()
        let restoration = GrantRestoration(
            resolver: resolver,
            policyReview: MirroredPolicyReview(local: HeldLocalReview(), remote: phoneLeg, log: { _ in }),
            consent: FixConsent(),
            decisionLog: decisionLog,
            terminalInspection: fixSilentTerminal
        )
        let source = RestorableProjectSource(resolver: resolver, references: [reference])
        await restoration.addItemSource(source)
        let caller = fixCaller()

        let first = await restoration.ensureWarmForDelegation(for: [reference], requester: caller)
        let usedUp = await restoration.isUsedUp
        let finished = await source.finished
        let held = await resolver.resolveWithoutInteraction(reference) != nil
        check(!held && first != .warmed,
              "restore honesty: an approval that reopened nothing does not answer its waiter as reopened (\(first))")
        check(!usedUp, "restore honesty: an approval that left a row cold does not use the restore up")
        check(finished.isEmpty,
              "restore honesty: a row that stayed cold is not reported to its source as reopened (\(finished))")
        await decisionLog.flushUsageCheckpoint()
        let records = await decisionLog.read(DecisionLogQuery(streams: [.decisions], kinds: [.restore])).records
        let detail = records.first?.detail ?? ""
        check(records.count == 1 && detail.contains("could not be reopened")
                && !detail.hasSuffix("reopened what csecd approved before it restarted"),
              "restore honesty: the log records the approval without claiming the cold row reopened (\(detail))")

        let second = await restoration.ensureWarmForDelegation(for: [reference], requester: caller)
        let reviews = await phoneLeg.reviews
        check(second != .usedUp && reviews == 2,
              "restore honesty: a later request raises the restore again for what is still cold (\(second), \(reviews))")
    } catch {
        check(false, "restore honesty ran (\(error))")
    }
}

// MARK: - 2-4. Cache copies: invalidation races, ordering, removal

/// Run from `remoteUnlockStorageTests`.
func remoteUnlockConsistencyFixTests() async {
    print("\n# Remote-unlock copy consistency (invalidation races, write order, removal)")
    await invalidationOvertakesReads()
    await cacheCopyNeverOutlivesItsItem()
    await failedRemovalIsSweptAtNextStart()
}

private func invalidationOvertakesReads() async {
    do {
        let phone = P256.KeyAgreement.PrivateKey()
        let items = HoldingRemoteUnlockBackend()
        let store = RemoteUnlockStore(backend: items, buildIdentity: "build-fix")
        _ = await store.reconcileEpoch(previousRun: nil)
        try await store.enroll(
            phoneKeyAgreementPublicKeyX963: phone.publicKey.x963Representation,
            macDeviceID: UUID().uuidString, phoneDeviceID: UUID().uuidString
        )
        let keychain = HoldingCacheKeychain()
        let writer = KeychainSecretCache(backend: keychain, remoteUnlock: store)
        let local = CacheUnlock(LAContext())

        // A phone-approved read while the invalidation deletes the item.
        let rotated = "op://Fix/Rotated/password"
        try await writer.put(rotated, value: Data("synthetic-before-rotation".utf8))
        let cache = KeychainSecretCache(backend: keychain, remoteUnlock: store)
        let remote = try await fixPhoneUnlock(store, phone: phone)
        await keychain.hold(.delete)
        let invalidation = Task { await cache.invalidate(rotated) }
        let deleting = await eventuallyTrue { await keychain.isHolding(.delete) }
        let during = try await cache.get(rotated, unlock: remote)
        await keychain.release(.delete)
        let invalidated = await invalidation.value
        let after = try await cache.get(rotated, unlock: nil)
        check(deleting && during == nil,
              "cache invalidation: the copy is gone before the Keychain item is deleted, so a phone read meanwhile misses")
        check(invalidated && after == nil,
              "cache invalidation: a phone-approved read racing an invalidation never leaves the old value warm")

        // A local read that read the item before the invalidation and
        // returns after it: it must neither promote nor re-seal the copy.
        let localURI = "op://Fix/LocalRace/password"
        try await writer.put(localURI, value: Data("synthetic-local-before".utf8))
        let localCache = KeychainSecretCache(backend: keychain, remoteUnlock: store)
        await keychain.hold(.load)
        let localRead = Task { try await localCache.get(localURI, unlock: local) }
        let loading = await eventuallyTrue { await keychain.isHolding(.load) }
        _ = await localCache.invalidate(localURI)
        await keychain.release(.load)
        _ = try await localRead.value
        let localWarm = try await localCache.get(localURI, unlock: nil)
        let localCopy = await items.inner.rawItems()[fixMirrorItem(localURI)]
        check(loading && localWarm == nil,
              "cache invalidation: a local read the invalidation overtook does not promote the old value")
        check(localCopy == nil,
              "cache invalidation: a local read the invalidation overtook does not re-seal the copy it removed")

        // A phone read that read the copy before the invalidation and
        // returns after it.
        let remoteURI = "op://Fix/RemoteRace/password"
        try await writer.put(remoteURI, value: Data("synthetic-remote-before".utf8))
        let remoteCache = KeychainSecretCache(backend: keychain, remoteUnlock: store)
        let remoteAgain = try await fixPhoneUnlock(store, phone: phone)
        await items.holdReads(of: "cache/\(remoteURI)")
        let remoteRead = Task { try await remoteCache.get(remoteURI, unlock: remoteAgain) }
        let reading = await eventuallyTrue { await items.isHoldingRead }
        _ = await remoteCache.invalidate(remoteURI)
        await items.releaseReads()
        _ = try await remoteRead.value
        let remoteWarm = try await remoteCache.get(remoteURI, unlock: nil)
        check(reading && remoteWarm == nil,
              "cache invalidation: a phone read the invalidation overtook does not promote the old value")

        // A write the invalidation overtook keeps nothing it wrote.
        let writtenURI = "op://Fix/WriteRace/password"
        let writeCache = KeychainSecretCache(backend: keychain, remoteUnlock: store)
        await keychain.hold(.store)
        let write = Task { try await writeCache.put(writtenURI, value: Data("synthetic-write-before".utf8)) }
        let storing = await eventuallyTrue { await keychain.isHolding(.store) }
        _ = await writeCache.invalidate(writtenURI)
        await keychain.release(.store)
        try await write.value
        let writtenWarm = try await writeCache.get(writtenURI, unlock: nil)
        let writtenItem = await keychain.raw(writtenURI)
        let writtenCopy = await items.inner.rawItems()[fixMirrorItem(writtenURI)]
        check(storing && writtenWarm == nil && writtenItem == nil && writtenCopy == nil,
              "cache invalidation: a write the invalidation overtook leaves no value warm, in the Keychain or copied")

        // A copy that does not open for the current enrollment is dropped,
        // so it no longer reads as covering its entry.
        let corruptURI = "op://Fix/Corrupt/password"
        try await writer.put(corruptURI, value: Data("synthetic-corrupt".utf8))
        if var corrupt = await items.inner.rawItems()[fixMirrorItem(corruptURI)] {
            corrupt[corrupt.count - 1] ^= 0x01
            await items.inner.setRaw(corrupt, for: fixMirrorItem(corruptURI))
        }
        let corruptCache = KeychainSecretCache(backend: keychain, remoteUnlock: store)
        let corruptUnlock = try await fixPhoneUnlock(store, phone: phone)
        let corruptRead = try? await corruptCache.get(corruptURI, unlock: corruptUnlock)
        let stillCovered = await corruptCache.holdsRemoteUnlockMirror(corruptURI)
        check(corruptRead == nil && !stillCovered,
              "cache copy: a copy that does not open is dropped and no longer counts as covering its entry")
    } catch {
        check(false, "cache invalidation races ran (\(error))")
    }
}

private func cacheCopyNeverOutlivesItsItem() async {
    do {
        let phone = P256.KeyAgreement.PrivateKey()
        let items = HoldingRemoteUnlockBackend()
        let keychain = HoldingCacheKeychain()
        let uri = "op://Fix/Order/password"

        // The copy goes before the item is written.
        let first = RemoteUnlockStore(backend: items, buildIdentity: "build-fix")
        _ = await first.reconcileEpoch(previousRun: nil)
        try await first.enroll(
            phoneKeyAgreementPublicKeyX963: phone.publicKey.x963Representation,
            macDeviceID: UUID().uuidString, phoneDeviceID: UUID().uuidString
        )
        let cache = KeychainSecretCache(backend: keychain, remoteUnlock: first)
        try await cache.put(uri, value: Data("synthetic-order-1".utf8))
        let copyWhileWriting = CopyObservation()
        await keychain.observeStores { _ in
            await copyWhileWriting.record(await items.inner.rawItems()[fixMirrorItem(uri)] != nil)
        }
        try await cache.put(uri, value: Data("synthetic-order-2".utf8))
        await keychain.observeStores { _ in }
        let seen = await copyWhileWriting.seen
        let resealed = await items.inner.rawItems()[fixMirrorItem(uri)] != nil
        check(seen == [false] && resealed,
              "cache order: a write removes the old copy before the Keychain item changes, and seals a new one after")

        // A run whose enrollment cannot be read keeps no copy older than its item.
        await items.failEnrollmentReads(true)
        let unreadable = RemoteUnlockStore(backend: items, buildIdentity: "build-fix")
        let unreadableOutcome = await unreadable.reconcileEpoch(previousRun: fixLastRun("build-fix"))
        let epochLeft = await items.inner.rawItems()[fixEpochItem] != nil
        check(unreadableOutcome == .enrollmentUnreadable && !epochLeft,
              "cache order: a start that cannot read the enrollment deletes the epoch, so the next start drops every copy")
        try await KeychainSecretCache(backend: keychain, remoteUnlock: unreadable)
            .put(uri, value: Data("synthetic-order-3".utf8))
        let staleCopy = await items.inner.rawItems()[fixMirrorItem(uri)]
        check(staleCopy == nil,
              "cache order: a write while the enrollment cannot be read removes the older copy instead of leaving it")

        await items.failEnrollmentReads(false)
        let readable = RemoteUnlockStore(backend: items, buildIdentity: "build-fix")
        let readableOutcome = await readable.reconcileEpoch(previousRun: fixLastRun("build-fix"))
        let remote = try await fixPhoneUnlock(readable, phone: phone)
        let served = try await KeychainSecretCache(backend: keychain, remoteUnlock: readable).get(uri, unlock: remote)
        check(readableOutcome == .cleared && served == nil,
              "cache order: after that run, a phone read never serves a value older than the Keychain item "
                + "(\(readableOutcome))")
    } catch {
        check(false, "cache order ran (\(error))")
    }
}

private actor CopyObservation {
    private(set) var seen: [Bool] = []
    func record(_ exists: Bool) { seen.append(exists) }
}

private func failedRemovalIsSweptAtNextStart() async {
    do {
        let items = InMemoryRemoteUnlockItemBackend()
        let store = RemoteUnlockStore(backend: items, buildIdentity: "build-fix")
        _ = await store.reconcileEpoch(previousRun: nil)
        try await store.enroll(
            phoneKeyAgreementPublicKeyX963: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
            macDeviceID: UUID().uuidString, phoneDeviceID: UUID().uuidString
        )
        let uri = "op://Fix/Removal/field"
        try await store.sealAndStore(.cache(uri: uri), payload: fixCacheEntry("synthetic-removal"))
        await items.failDeletes(service: RemoteUnlockStore.mirrorService, account: "cache/\(uri)", status: errSecIO)
        var reported: RemoteUnlockStoreError?
        do {
            try await store.removeAllRemoteUnlockState()
        } catch let error as RemoteUnlockStoreError {
            reported = error
        }
        let enrolled = await store.isEnrolled()
        check(reported == .removalIncomplete(mirrors: true, epoch: false, enrollment: false) && !enrolled,
              "remote-unlock removal: a copy that cannot be deleted is reported, and the enrollment that "
                + "alone could open it is still deleted (\(String(describing: reported)))")
        await items.failDeletes(service: RemoteUnlockStore.mirrorService, account: "cache/\(uri)", status: nil)

        let restarted = RemoteUnlockStore(backend: items, buildIdentity: "build-fix")
        let manager = fixManager(
            store: V3MemoryConfigurationStore(), relay: V3MailboxRelay(),
            remoteUnlock: restarted, resolver: nil, log: FixLog()
        )
        await manager.prepare()
        let left = await items.rawItems()
        check(left.isEmpty,
              "remote-unlock removal: a start with no phone paired deletes the copies a failed removal left, "
                + "enrolled or not (\(left.keys.map(\.description).sorted()))")

        let never = InMemoryRemoteUnlockItemBackend()
        let neverManager = fixManager(
            store: V3MemoryConfigurationStore(), relay: V3MailboxRelay(),
            remoteUnlock: RemoteUnlockStore(backend: never, buildIdentity: "build-fix"), resolver: nil, log: FixLog()
        )
        await neverManager.prepare()
        let writes = await never.operations.filter { $0.kind == .update || $0.kind == .add }
        let neverItems = await never.rawItems()
        check(writes.isEmpty && neverItems.isEmpty,
              "remote-unlock removal: a start that never enrolled writes nothing while sweeping")
    } catch {
        check(false, "remote-unlock removal ran (\(error))")
    }
}

// MARK: - 5. A re-pairing that fails after enrolling

/// Run from `remotePairingTests`.
func remotePairingFixTests() async {
    print("\n# Remote pairing: a failed re-pairing")
    await failedRePairingKeepsTheUnlock()
}

private func failedRePairingKeepsTheUnlock() async {
    do {
        let first = SyntheticPhone()
        var second = SyntheticPhone()
        second.name = "Replacement iPhone"
        let items = InMemoryRemoteUnlockItemBackend()
        let remoteUnlock = RemoteUnlockStore(backend: items, buildIdentity: "build-fix")
        _ = await remoteUnlock.reconcileEpoch(previousRun: nil)
        let store = FailingConfigurationStore()
        let log = FixLog()
        let manager = fixManager(
            store: store, relay: V3MailboxRelay(), remoteUnlock: remoteUnlock, resolver: nil, log: log
        )
        _ = try await manager.enable(phonePairingCode: try first.pairingCode, caller: setupCaller)
        let before = await manager.pairingHealth()
        check(before?.remoteUnlockEnrolled == true, "failed re-pairing: the first pairing is enrolled")

        await store.failStores(true)
        var failed = false
        do {
            _ = try await manager.enable(phonePairingCode: try second.pairingCode, caller: setupCaller)
        } catch {
            failed = true
        }
        let kept = await store.current()
        let status = await manager.status()
        let health = await manager.pairingHealth()
        check(failed && kept?.phoneDeviceID == first.deviceID && status.isEnabled,
              "failed re-pairing: the phone paired before stays paired (\(status))")
        let enrollment = await remoteUnlock.enrollment()
        check(health?.remoteUnlockEnrolled == true
                && enrollment?.phoneDeviceID == first.deviceID && enrollment?.macDeviceID == kept?.macDeviceID,
              "failed re-pairing: the kept pairing's phone-held unlock is enrolled again for that pairing")
        let summary = RemoteApprovalStatusReport.summary(RemoteApprovalConfigurationStatus(status, health: health))
        check(!summary.lines.contains { $0.contains("phone-held unlock is not enrolled") },
              "failed re-pairing: status does not report a missing phone-held unlock")
        check(log.all.contains { $0.contains("not re-paired") && $0.contains("enrolled again") },
              "failed re-pairing: the log says the new pairing was not saved and the kept one's unlock is back")
    } catch {
        check(false, "failed re-pairing ran (\(error))")
    }
}

private extension RemoteApprovalManagerStatus {
    var isEnabled: Bool {
        if case .enabled = self { return true }
        return false
    }
}

// MARK: - A phone approval whose provider would prompt at the Mac (csec-0.65.5)

private final class AttendanceClock: @unchecked Sendable {
    private let lock = NSLock()
    private var now = Date(timeIntervalSince1970: 1_700_000_000)
    func date() -> Date { lock.withLock { now } }
    func advance(_ seconds: TimeInterval) { lock.withLock { now = now.addingTimeInterval(seconds) } }
}

/// A one-time code approved on the iPhone while csecd held no 1Password
/// session for its account waited on 1Password's own prompt at the Mac and
/// failed two minutes later (csec-0.65.5, 7 Nov 2026). The phone is now
/// offered a review only when its approval could deliver: every value either
/// held warm, read from a cached copy the phone's unlock opens, or served by a
/// provider that would raise no prompt of its own. Run from `oneTimeCodeTests`.
func phoneApprovalAttendanceTests() async {
    print("\n# Phone approvals never wait on a provider's prompt at the Mac (csec-0.65.5)")
    await attendanceFromTheOnePasswordProvider()
    await attendanceReadinessThroughOnePassword()
    await attendanceReadinessWithCachedCopies()
}

private let attendanceCode = "op://Personal/npm/one-time password?attribute=otp"
private let attendancePlain = "op://Personal/npm/token"

private func attendanceProvider(
    _ bridges: FakeBackendRegistry, clock: AttendanceClock
) async -> OnePasswordProvider {
    let runner = FakeOnePasswordCommandRunner()
    await runner.setAccounts([("user-personal", "my.1password.com")], vaults: [:])
    return OnePasswordProvider(
        cliPath: "/synthetic/op",
        configuration: OnePasswordConnectionConfiguration(
            keepaliveInterval: 4, sessionIdleWindow: 10, authenticationTimeout: 7
        ),
        makeBackend: bridges.factory(),
        runCommand: { path, arguments, timeout in
            try await runner.run(path: path, arguments: arguments, timeout: timeout)
        },
        currentDate: { clock.date() }
    )
}

private func attendanceBridges() -> FakeBackendRegistry {
    FakeBackendRegistry { _ in
        FakeOnePasswordBackend(
            vaults: [OnePasswordVault(id: "vault-personal", name: "Personal")],
            values: [attendanceCode: "123456", attendancePlain: "synthetic-attendance-token"]
        )
    }
}

/// The provider answers from warm state: attended until a read or keepalive
/// proves the account's session, and again once the session may have lapsed.
/// Asking never starts a bridge, so it never authorizes.
private func attendanceFromTheOnePasswordProvider() async {
    do {
        let code = try SecretRef(attendanceCode)
        let plain = try SecretRef(attendancePlain)
        let clock = AttendanceClock()
        let bridges = attendanceBridges()
        let onePassword = await attendanceProvider(bridges, clock: clock)

        let coldCode = await onePassword.requiresAttendanceToResolve(code)
        let coldPlain = await onePassword.requiresAttendanceToResolve(plain)
        check(coldCode && coldPlain,
              "attendance: with no session held, reading a code or a field would prompt at the Mac")
        check(bridges.createdAccounts().isEmpty,
              "attendance: asking starts no bridge, so it authorizes nothing")

        _ = try await onePassword.resolve(plain, unlock: nil)
        let warmCode = await onePassword.requiresAttendanceToResolve(code)
        let warmPlain = await onePassword.requiresAttendanceToResolve(plain)
        check(!warmCode && !warmPlain,
              "attendance: once a read proves the account's session, its code and fields need nobody at the Mac")

        clock.advance(11)
        check(await onePassword.requiresAttendanceToResolve(code),
              "attendance: past 1Password's idle window the session may have lapsed, so a code is attended again")
        await onePassword.keepaliveTick()
        check(!(await onePassword.requiresAttendanceToResolve(code)),
              "attendance: the keepalive proves the session again")

        // A seed refusal is the session answering: it stays proven, over the
        // running session and over an ordinary read alike.
        let seedRefusal = OnePasswordBridgeError.remote(kind: "otp_seed", message: "synthetic seed refusal")
        await bridges.backend("user-personal")?.failResolves(with: seedRefusal)
        clock.advance(6)
        _ = await onePassword.resolveFromOpenSession(plain)
        clock.advance(6)
        let afterOpenRefusal = await onePassword.requiresAttendanceToResolve(code)
        check(!afterOpenRefusal,
              "attendance: a seed refusal over the open session keeps the session proven")
        clock.advance(6)
        _ = try? await onePassword.resolve(plain, unlock: nil)
        clock.advance(6)
        let afterReadRefusal = await onePassword.requiresAttendanceToResolve(code)
        check(!afterReadRefusal,
              "attendance: a seed refusal from an ordinary read proves the session too")

        await onePassword.suspendKeepalive()
        check(await onePassword.requiresAttendanceToResolve(code),
              "attendance: after a lock or sleep the session could only re-authorize, so a code is attended")
        check(bridges.createdAccounts() == ["user-personal"],
              "attendance: only the read itself ever authorized")
    } catch {
        check(false, "attendance from the 1Password provider ran (\(error))")
    }
}

/// The csec-0.65.5 sequence through the real resolver and remote approval
/// manager: a code is kept from the phone while no session is held, reaches
/// it once one is, and a field csecd holds warm reaches it either way.
private func attendanceReadinessThroughOnePassword() async {
    do {
        let code = try SecretRef(attendanceCode)
        let plain = try SecretRef(attendancePlain)
        let clock = AttendanceClock()
        let bridges = attendanceBridges()
        let onePassword = await attendanceProvider(bridges, clock: clock)
        let resolver = SecretResolver(cache: KeychainSecretCache(backend: RemoteUnlockFakeKeychain()))
        await resolver.register(onePassword)
        let pairing = fixPairingRecord(for: SyntheticPhone())
        let log = FixLog()
        let manager = fixManager(
            store: V3MemoryConfigurationStore(record: pairing), relay: V3MailboxRelay(),
            remoteUnlock: nil, resolver: resolver, log: log
        )
        await manager.prepare()

        let coldCoverage = await resolver.remoteUnlockCoverage([code, plain])
        check(coldCoverage.needsAttendance == [code.uri, plain.uri] && coldCoverage.needsUnlock.isEmpty,
              "attendance: with no session, a code and an uncached field need someone at the Mac, and no unlock")
        check(await manager.remoteReadiness(for: [code]) == .unavailable,
              "attendance: a code csecd holds no session for stays on the Mac")
        check(log.all.contains { $0.contains("stays on the Mac") && $0.contains("authorize at the Mac") },
              "attendance: csecd says why the request stays on the Mac")
        check(!log.all.contains { $0.contains("123456") || $0.contains("synthetic-attendance-token") },
              "attendance: the reason is value-free")
        check(bridges.createdAccounts().isEmpty,
              "attendance: judging readiness authorized nothing")

        // A read at the Mac opens the session (and caches the field).
        _ = try await resolver.resolve(plain, unlock: CacheUnlock(LAContext()))
        check(await manager.remoteReadiness(for: [code]) == .ready(unlock: .notNeeded),
              "attendance: while csecd holds the session open, the phone may approve a code")

        await onePassword.suspendKeepalive()
        check(await manager.remoteReadiness(for: [code]) == .unavailable,
              "attendance: once the session could only re-authorize, a code stays on the Mac again")
        check(await manager.remoteReadiness(for: [plain]) == .ready(unlock: .notNeeded),
              "attendance: a field csecd holds warm is served without 1Password, so it still reaches the phone")
        check(await manager.remoteReadiness(for: [plain, code]) == .unavailable,
              "attendance: one attended value keeps the whole request on the Mac")
    } catch {
        check(false, "attendance readiness through 1Password ran (\(error))")
    }
}

/// A cached copy the phone's unlock opens serves an attended value without its
/// provider, so the request reaches the phone, with the unlock required; with
/// no factor enrolled for this pairing it cannot, and stays on the Mac.
private func attendanceReadinessWithCachedCopies() async {
    do {
        let pairing = fixPairingRecord(for: SyntheticPhone())
        let reference = try SecretRef("op://Fix/Attended/field")
        let cacheEntry = fixCacheEntry("synthetic-attended-cached")

        func readiness(
            enrolledFor enrolled: StoredRemoteApprovalConfiguration?, sealed: Bool
        ) async throws -> RemoteReviewReadiness {
            let store = RemoteUnlockStore(backend: InMemoryRemoteUnlockItemBackend(), buildIdentity: "build-fix")
            _ = await store.reconcileEpoch(previousRun: nil)
            if let enrolled { try await fixEnroll(store, for: enrolled) }
            if sealed { try await store.sealAndStore(.cache(uri: reference.uri), payload: cacheEntry) }
            let cacheItems = RemoteUnlockFakeKeychain()
            await cacheItems.plant(cacheEntry, for: reference.uri)
            let resolver = SecretResolver(cache: KeychainSecretCache(backend: cacheItems, remoteUnlock: store))
            await resolver.register(RemoteCoverageFixtureProvider(
                scheme: "op", needsUnlock: false, opensRemotely: false,
                value: "synthetic-attended-fetched", attended: true
            ))
            let manager = fixManager(
                store: V3MemoryConfigurationStore(record: pairing), relay: V3MailboxRelay(),
                remoteUnlock: store, resolver: resolver, log: FixLog()
            )
            await manager.prepare()
            return await manager.remoteReadiness(for: [reference])
        }

        check(try await readiness(enrolledFor: pairing, sealed: true) == .ready(unlock: .required),
              "attendance: an attended value with a copy the phone's unlock opens reaches the phone, which must open it")
        check(try await readiness(enrolledFor: pairing, sealed: false) == .unavailable,
              "attendance: an attended value with no copy the phone could open stays on the Mac")
        let otherPairing = fixPairingRecord(for: SyntheticPhone())
        check(try await readiness(enrolledFor: otherPairing, sealed: true) == .unavailable,
              "attendance: a copy only another pairing's factor opens does not serve an attended value")
    } catch {
        check(false, "attendance readiness with cached copies ran (\(error))")
    }
}
