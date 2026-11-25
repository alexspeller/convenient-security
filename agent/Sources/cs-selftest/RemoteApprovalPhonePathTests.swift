import CryptoKit
import CSECRemoteApproval
import ConvenientSecurity
import Foundation
import LocalAuthentication

// The phone path end to end on the Mac side, and the requester's lifecycle
// edges. A phone-minted grant covers the next identical request; SSH signing
// approved on the phone works for a key in cold native storage and for one
// behind an unrelated provider scheme; nothing is resolved or read before the
// phone decides; a mixed release with a failing provider releases nothing. The
// requester refuses a replay past its consumed-ID rollover and an answer to a
// previous run's request, is never held by a relay call that does not return,
// and is never parked by a relay's retry hint. Every key is a synthetic
// software key, every backend is in memory, and every value is synthetic.

// MARK: - Fixtures: storage that survives a simulated restart

private let phonePathStoreName = "phone-path"
private let phonePathNativeURI = "csec://phone-path/API_TOKEN"
private let phonePathNativeValue = "synthetic-phone-path-native-value"
private let phonePathSSHNativeURI = "csec://phone-path/id_ed25519"
private let phonePathSSHSealedURI = "keyring://login/id_ed25519"
/// A value fetched at the Mac before the restart, so the cache holds it with
/// its remote-unlock mirror.
private let phonePathCachedURI = "op://Vault/Cached/password"
private let phonePathPlainURI = "op://Vault/Plain/password"
private let phonePathLockedURI = "locked://vault/item/password"
private let phonePathOpValue = "synthetic-phone-path-op-value"
private let phonePathLockedValue = "synthetic-phone-path-locked-value"

private let phonePathLastRun = CsecdLastRun(
    bootSessionUUID: "synthetic-boot", pid: 4242, startTimeMicros: 1, cdHash: "build-phone-path", version: nil
)

/// The native stores' key records in memory, counting every read whatever
/// unlock it carries (the in-memory backend counts only reads that open).
private actor PhoneCountingKeyBackend: NativeStoreKeyBackend {
    private let inner = InMemoryNativeStoreKeyBackend()
    private(set) var loads = 0

    func load(store: String, unlock: CacheUnlock?) async throws -> NativeStoreKeyRecord? {
        loads += 1
        return try await inner.load(store: store, unlock: unlock)
    }

    func create(store: String, record: NativeStoreKeyRecord) async throws {
        try await inner.create(store: store, record: record)
    }

    func update(store: String, record: NativeStoreKeyRecord, unlock: CacheUnlock?) async throws {
        try await inner.update(store: store, record: record, unlock: unlock)
    }

    func recordExists(store: String) async throws -> Bool { await inner.recordExists(store: store) }
    func storeNames(unlock: CacheUnlock) async throws -> [String] { try await inner.storeNames(unlock: unlock) }
}

/// The Keychain cache's biometric items in memory, counting every read
/// whatever unlock it carries.
private actor PhoneCountingKeychain: KeychainBackend {
    private let inner = RemoteUnlockFakeKeychain()
    private(set) var loads = 0

    func store(account: String, data: Data) async throws { await inner.store(account: account, data: data) }

    func load(account: String, unlock: CacheUnlock?) async throws -> Data? {
        loads += 1
        return try await inner.load(account: account, unlock: unlock)
    }

    func delete(account: String) async { await inner.delete(account: account) }
    func contains(account: String) async -> Bool { await inner.contains(account: account) }
    func accounts(unlock: CacheUnlock) async throws -> [String] { try await inner.accounts(unlock: unlock) }
}

/// A provider of an unrelated scheme whose storage is sealed until an unlock
/// opens it, and which keeps its own remote-unlock mirrors: a phone approval's
/// remote unlock opens it, and it then stays open for the run, as native
/// storage does. It refuses to open with no unlock or a dropped one.
private actor PhoneSealedKeyProvider: SecretProvider {
    nonisolated let schemes: Set<String>
    private let values: [String: Data]
    private var opened = false
    private(set) var resolveCount = 0
    /// Opens made with a live remote unlock.
    private(set) var remoteOpens = 0

    init(scheme: String, values: [String: Data]) {
        schemes = [scheme]
        self.values = values
    }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        resolveCount += 1
        if !opened {
            guard let unlock else { throw ProviderError.notAuthenticated }
            if let remote = unlock.remote {
                guard !remote.isInvalidated else { throw ProviderError.notAuthenticated }
                remoteOpens += 1
            }
            opened = true
        }
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
    func requiresUnlockToResolve(_ ref: SecretRef) async -> Bool { !opened }
    func canResolveWithRemoteUnlock(_ ref: SecretRef) async -> Bool { true }
}

/// Every backend, which a restart keeps. Each boot builds fresh actors over
/// them, so native storage and the sealed provider start cold.
private struct PhonePathWorld {
    let docKeys = PhoneCountingKeyBackend()
    let docFiles = InMemoryNativeStoreFileBackend()
    let cacheItems = PhoneCountingKeychain()
    let items = InMemoryRemoteUnlockItemBackend()
    /// Like 1Password: fetches behind its own authorization, needs no unlock.
    let fetchable = RemoteCoverageFixtureProvider(
        scheme: "op", needsUnlock: false, opensRemotely: false, value: phonePathOpValue
    )
    /// Like a provider locked along with the Mac: needs no unlock, and refuses
    /// every fetch with `ProviderError.notAuthenticated` while locked.
    let locked = RemoteCoverageFixtureProvider(
        scheme: "locked", needsUnlock: false, opensRemotely: false, value: phonePathLockedValue
    )
    let nativeSSHKey: Ed25519SSHFixture
    let sealedSSHKey: Ed25519SSHFixture
}

private struct PhonePathRun {
    let store: RemoteUnlockStore
    let provider: NativeEncryptedFileProvider
    let sealed: PhoneSealedKeyProvider
    let resolver: SecretResolver
}

private struct PhonePathFixture {
    let world: PhonePathWorld
    let phone: SyntheticPhone
    let pairing: StoredRemoteApprovalConfiguration
    /// This process, as the requester of every release.
    let caller: CallerInfo
}

private func phonePathBoot(_ world: PhonePathWorld, previous: CsecdLastRun?) async -> PhonePathRun {
    let store = RemoteUnlockStore(backend: world.items, buildIdentity: "build-phone-path")
    _ = await store.reconcileEpoch(previousRun: previous)
    let provider = NativeEncryptedFileProvider(
        keyBackend: world.docKeys, fileBackend: world.docFiles, remoteUnlock: store
    )
    let sealed = PhoneSealedKeyProvider(
        scheme: "keyring", values: [phonePathSSHSealedURI: world.sealedSSHKey.privateKeyPEM]
    )
    let resolver = SecretResolver(cache: KeychainSecretCache(backend: world.cacheItems, remoteUnlock: store))
    await resolver.register(provider)
    await resolver.register(world.fetchable)
    await resolver.register(world.locked)
    await resolver.register(sealed)
    return PhonePathRun(store: store, provider: provider, sealed: sealed, resolver: resolver)
}

/// Run 1 writes the native store with this Mac's own touch. Run 2 enrolls the
/// phone's unlock factor (its one touch mirrors the store) and caches a value
/// fetched at the Mac. Every test then boots its own cold run over the same
/// backends.
private func phonePathFixture() async -> PhonePathFixture? {
    let me = getpid()
    guard let myStart = ProcessAncestry.startTime(of: me) else {
        check(false, "phone path: the fixture reads its own start time")
        return nil
    }
    do {
        let world = PhonePathWorld(
            nativeSSHKey: try Ed25519SSHFixture(seed: 0x51), sealedSSHKey: try Ed25519SSHFixture(seed: 0x61)
        )
        let phone = SyntheticPhone()
        let pairing = v3StoredPairing(phone: phone, macKey: P256.Signing.PrivateKey())
        let local = CacheUnlock(LAContext()) // in-memory backends only; never prompts
        await world.locked.setLocked(true)

        let run1 = await phonePathBoot(world, previous: nil)
        let session = try await run1.provider.beginEdit(
            store: try NativeStoreName(phonePathStoreName), callerPID: 4242, callerStartTime: 1, unlock: local
        )
        _ = try await run1.provider.commitEdit(
            sessionID: session.sessionID,
            document: try NativeStoreDocument(values: [
                "API_TOKEN": phonePathNativeValue,
                "id_ed25519": String(decoding: world.nativeSSHKey.privateKeyPEM, as: UTF8.self),
            ]).encoded(),
            callerPID: 4242, callerStartTime: 1
        )

        let run2 = await phonePathBoot(world, previous: phonePathLastRun)
        _ = try await run2.store.enroll(
            phoneKeyAgreementPublicKeyX963: phone.keyAgreementKey.publicKey.x963Representation,
            macDeviceID: pairing.macDeviceID, phoneDeviceID: phone.deviceID
        )
        let backfill = await run2.resolver.backfillRemoteUnlockMirrors(localUnlock: local)
        let fetched = try await run2.resolver.resolve(try SecretRef(phonePathCachedURI), unlock: local)
        let cacheMirrored = await run2.store.exists(.cache(uri: phonePathCachedURI))
        check(backfill.mirrored >= 1 && backfill.failed == 0 && fetched == Data(phonePathOpValue.utf8) && cacheMirrored,
              "phone path: the fixture's native store is mirrored for the enrolled phone, and a value cached at the Mac has its mirror")
        return PhonePathFixture(
            world: world, phone: phone, pairing: pairing,
            caller: CallerInfo(pid: me, startTime: myStart, description: "synthetic phone path")
        )
    } catch {
        check(false, "phone path: the fixture builds (\(error))")
        return nil
    }
}

private func phonePathManager(
    _ fixture: PhonePathFixture,
    _ run: PhonePathRun,
    relay: V3MailboxRelay,
    log: V3LogLines = V3LogLines()
) async -> RemoteApprovalManager {
    let manager = v3Manager(
        store: V3MemoryConfigurationStore(record: fixture.pairing), relay: relay,
        remoteUnlock: run.store, resolver: run.resolver, log: log
    )
    await manager.prepare()
    return manager
}

private func phonePathAgent(
    _ run: PhonePathRun,
    local: any PolicyReviewProvider,
    remote: any RemoteAccessPolicyReviewProvider,
    consent: V3CountingConsent = V3CountingConsent(),
    grants: GrantTable = GrantTable(),
    decisionLog: DecisionLog? = nil
) -> Agent {
    Agent(
        resolver: run.resolver, grants: grants, consent: consent,
        policyReview: MirroredPolicyReview(local: local, remote: remote, log: { _ in }),
        allowUnverifiedPlansForTesting: true, processInspection: v3Inspection(),
        terminalInspection: v3SilentTerminal, decisionLog: decisionLog
    )
}

/// Every read that could reach a value: provider resolutions, reads of the
/// cache's and the key records' biometric items, and reads of remote-unlock
/// mirror items (attribute checks and the enrollment record are not reads of
/// a value and are not counted).
private struct PhonePathReads: Equatable, CustomStringConvertible {
    var providerResolves: [Int]
    var cacheLoads: Int
    var keyRecordLoads: Int
    var mirrorReads: Int

    var description: String {
        "resolves \(providerResolves), cache item reads \(cacheLoads), key record reads \(keyRecordLoads), "
            + "mirror reads \(mirrorReads)"
    }

    /// What changed since `earlier`, for a failure message.
    func change(since earlier: PhonePathReads) -> String {
        self == earlier ? "none" : "\(earlier) -> \(self)"
    }
}

private func phonePathReads(_ fixture: PhonePathFixture, _ run: PhonePathRun) async -> PhonePathReads {
    let operations = await fixture.world.items.operations
    return PhonePathReads(
        providerResolves: [
            await fixture.world.fetchable.resolveCount,
            await fixture.world.locked.resolveCount,
            await run.sealed.resolveCount,
        ],
        cacheLoads: await fixture.world.cacheItems.loads,
        keyRecordLoads: await fixture.world.docKeys.loads,
        mirrorReads: operations.filter {
            $0.kind == .read && $0.item?.service == RemoteUnlockStore.mirrorService
        }.count
    )
}

/// A decision log in its own temporary directory over process-local items.
private struct PhonePathDecisionLog {
    let directory = NSTemporaryDirectory() + "cs-selftest-phone-path-log-\(UUID().uuidString.lowercased())"

    func open() async -> DecisionLog {
        let log = DecisionLog(
            directory: SealedRecordDirectory(path: directory),
            stores: .processLocal(InMemoryProtectedItemBackend()),
            limits: DecisionLogLimits(
                segmentBytes: 64 * 1_024, decisionsCapBytes: 1 << 20, usageCapBytes: 1 << 20,
                usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
            ),
            bootSessionUUID: "00000000-0000-0000-0000-00000000b007"
        )
        _ = await log.open()
        return log
    }

    func remove() { try? FileManager.default.removeItem(atPath: directory) }
}

private func phonePathRecords(
    _ log: DecisionLog,
    streams: [DecisionLogStream] = [.decisions, .usage],
    kinds: [DecisionLogRecord.Kind]? = nil
) async -> [DecisionLogRecord] {
    var query = DecisionLogQuery(streams: streams, kinds: kinds)
    var records: [DecisionLogRecord] = []
    for _ in 0..<100 {
        let page = await log.read(query)
        records += page.records
        guard let next = page.next, !page.records.isEmpty else { break }
        query.after = next
    }
    return records
}

// MARK: - Fixtures: requester-level relays

private let phonePathFastCleanup = RemoteApprovalRetrySchedule(
    initialNanoseconds: 5_000_000, maximumNanoseconds: 20_000_000
)

private func phonePathRequester(
    phone: SyntheticPhone,
    macKey: P256.Signing.PrivateKey,
    macDeviceID: String,
    relay: any RemoteApprovalRelay,
    exchangeDrainNanoseconds: UInt64 = RemoteApprovalBound.readNanoseconds
) throws -> RemoteApprovalRequester {
    try RemoteApprovalRequester(
        configuration: RemoteApprovalRequesterConfiguration(
            macDeviceID: macDeviceID,
            macDeviceName: "Alex’s Mac",
            pinnedPhoneDeviceID: phone.deviceID,
            pinnedPhonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
            pollIntervalNanoseconds: 50_000_000
        ),
        signer: V3SoftwareSigner(key: macKey),
        relay: relay,
        cleanup: RemoteApprovalCleanupQueue(schedule: phonePathFastCleanup),
        exchangeDrainNanoseconds: exchangeDrainNanoseconds
    )
}

/// Resumes a continuation exactly once, with a value or with the deadline's nil.
private final class PhoneOnce<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<T?, Never>?

    init(_ continuation: CheckedContinuation<T?, Never>) { self.continuation = continuation }

    /// True for the call that resumed it.
    @discardableResult
    func resume(_ value: T?) -> Bool {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: value)
        return pending != nil
    }
}

/// `task`'s value, or nil if it has none within `nanoseconds` (the task is then
/// cancelled), so a regression fails a check instead of hanging the suite. It
/// returns at the deadline even when the task ignores cancellation: nothing
/// here waits for the task to end.
private func phoneBounded<T: Sendable>(
    _ task: Task<T, Never>,
    within nanoseconds: UInt64 = 5_000_000_000
) async -> T? {
    await withCheckedContinuation { continuation in
        let once = PhoneOnce<T>(continuation)
        let deadline = Task {
            try? await Task.sleep(nanoseconds: nanoseconds)
            if once.resume(nil) { task.cancel() }
        }
        Task {
            let value = await task.value
            if once.resume(value) { deadline.cancel() }
        }
    }
}

/// `probe`'s first non-nil answer, polled every 10 ms for up to 5 s.
private func phoneEventually<T>(_ probe: () async -> T?) async -> T? {
    for _ in 0..<500 {
        if let value = await probe() { return value }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return nil
}

/// A mailbox the synthetic phone answers at once: each request is approved
/// with its offered defaults the moment it is published, until told to stop.
/// It can throttle the first save or the first poll with a given retry hint.
private actor PhoneLoopbackRelay: RemoteApprovalRelay {
    enum Stage: Sendable { case publish, poll }

    private let phone: SyntheticPhone
    private var throttleOnce: Stage?
    private let throttleHint: UInt64
    private var answering = true
    private var requests: [String: SignedRemoteApprovalRequest] = [:]
    /// Response slots by request ID; the requester reads only its pinned phone's.
    private var responses: [String: SignedRemoteApprovalResponse] = [:]
    private var answers: [SignedRemoteApprovalResponse] = []
    private var publishedIDs: [String] = []
    private(set) var discarded: [String] = []
    private(set) var publishAttempts: [ContinuousClock.Instant] = []
    private(set) var polls: [ContinuousClock.Instant] = []

    init(phone: SyntheticPhone, throttleOnce: Stage? = nil, throttleHint: UInt64 = .max) {
        self.phone = phone
        self.throttleOnce = throttleOnce
        self.throttleHint = throttleHint
    }

    var answerCount: Int { answers.count }
    func answer(number index: Int) -> SignedRemoteApprovalResponse? {
        answers.indices.contains(index) ? answers[index] : nil
    }
    func publishedID(number index: Int) -> String? {
        publishedIDs.indices.contains(index) ? publishedIDs[index] : nil
    }
    func stopAnswering() { answering = false }
    /// Put `response` in the slot of `requestID`, as any mailbox writer could.
    func plant(_ response: SignedRemoteApprovalResponse, inSlotOf requestID: String) {
        responses[requestID] = response
    }

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        publishAttempts.append(.now)
        if throttleOnce == .publish {
            throttleOnce = nil
            throw RemoteApprovalRelayFailure.throttled(retryAfterNanoseconds: throttleHint)
        }
        let requestID = request.request.requestID
        requests[requestID] = request
        publishedIDs.append(requestID)
        if answering {
            let answer = try phone.approve(request)
            responses[requestID] = answer
            answers.append(answer)
        }
    }

    func response(for requestID: String, phoneDeviceID: String) async throws -> SignedRemoteApprovalResponse? {
        polls.append(.now)
        if throttleOnce == .poll {
            throttleOnce = nil
            throw RemoteApprovalRelayFailure.throttled(retryAfterNanoseconds: throttleHint)
        }
        guard phoneDeviceID == phone.deviceID else { return nil }
        return responses[requestID]
    }

    func discardResponse(for requestID: String, phoneDeviceID: String) async {
        responses[requestID] = nil
        discarded.append(requestID)
    }

    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] { Array(requests.values) }
    func requestIsPending(requestID: String) async throws -> Bool { requests[requestID] != nil }
    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {
        responses[response.response.requestID] = response
    }
    func publishAlert(requestID: String, macDeviceID: String) async throws {}
    func deleteExchange(requestID: String, phoneDeviceID: String?) async throws {
        requests[requestID] = nil
        responses[requestID] = nil
    }
    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation? { nil }
    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws {}
    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? { nil }
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {}
    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {}
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? { nil }
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async throws {}
}

/// One csecd's view of a shared mailbox, which can stop the way a process
/// does: after `sever()` nothing it does reaches the mailbox, so what it
/// published stays there and nothing it would have deleted is deleted.
private actor PhoneSeverableRelay: RemoteApprovalRelay {
    private let inner: HardenedMailboxRelay
    private var severed = false

    init(_ inner: HardenedMailboxRelay) { self.inner = inner }

    func sever() { severed = true }

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        guard !severed else { throw RemoteApprovalRelayFailure.permanentlyUnavailable }
        try await inner.publishRequest(request)
    }

    func response(for requestID: String, phoneDeviceID: String) async throws -> SignedRemoteApprovalResponse? {
        guard !severed else { throw RemoteApprovalRelayFailure.permanentlyUnavailable }
        return try await inner.response(for: requestID, phoneDeviceID: phoneDeviceID)
    }

    func discardResponse(for requestID: String, phoneDeviceID: String) async {
        guard !severed else { return }
        await inner.discardResponse(for: requestID, phoneDeviceID: phoneDeviceID)
    }

    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] {
        guard !severed else { throw RemoteApprovalRelayFailure.permanentlyUnavailable }
        return try await inner.pendingRequests()
    }

    func requestIsPending(requestID: String) async throws -> Bool {
        guard !severed else { throw RemoteApprovalRelayFailure.permanentlyUnavailable }
        return try await inner.requestIsPending(requestID: requestID)
    }

    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {
        guard !severed else { throw RemoteApprovalRelayFailure.permanentlyUnavailable }
        try await inner.publishResponse(response)
    }

    func publishAlert(requestID: String, macDeviceID: String) async throws {
        guard !severed else { throw RemoteApprovalRelayFailure.permanentlyUnavailable }
        try await inner.publishAlert(requestID: requestID, macDeviceID: macDeviceID)
    }

    /// A process that has stopped deletes nothing.
    func deleteExchange(requestID: String, phoneDeviceID: String?) async throws {
        guard !severed else { return }
        try await inner.deleteExchange(requestID: requestID, phoneDeviceID: phoneDeviceID)
    }

    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation? { nil }
    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws {}
    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? { nil }
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {}
    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {}
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? { nil }
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async throws {}
}

/// A relay one of whose calls never returns until the test releases it, and
/// ignores cancellation meanwhile, like a transport call with no timeout.
private actor PhoneHangingRelay: RemoteApprovalRelay {
    enum Stage: Sendable { case publish, poll }

    private let stage: Stage
    private var released = false
    private var parked: [CheckedContinuation<Void, Never>] = []
    private(set) var parkedCalls = 0
    private(set) var publishedIDs: [String] = []
    private var requests: [String: SignedRemoteApprovalRequest] = [:]
    private var responses: [String: SignedRemoteApprovalResponse] = [:]
    private(set) var deleted: [String] = []

    init(hanging stage: Stage) { self.stage = stage }

    func publishedRequest(number index: Int) -> SignedRemoteApprovalRequest? {
        publishedIDs.indices.contains(index) ? requests[publishedIDs[index]] : nil
    }

    /// Lets every parked call return, and no later call park.
    func release() {
        released = true
        let waiting = parked
        parked = []
        for continuation in waiting { continuation.resume() }
    }

    private func park() async {
        guard !released else { return }
        parkedCalls += 1
        await withCheckedContinuation { continuation in parked.append(continuation) }
    }

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        publishedIDs.append(request.request.requestID)
        if stage == .publish { await park() }
        requests[request.request.requestID] = request
    }

    func response(for requestID: String, phoneDeviceID: String) async throws -> SignedRemoteApprovalResponse? {
        if stage == .poll { await park() }
        return responses[requestID]
    }

    func discardResponse(for requestID: String, phoneDeviceID: String) async { responses[requestID] = nil }
    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] { Array(requests.values) }
    func requestIsPending(requestID: String) async throws -> Bool { requests[requestID] != nil }
    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {
        responses[response.response.requestID] = response
    }
    func publishAlert(requestID: String, macDeviceID: String) async throws {}
    func deleteExchange(requestID: String, phoneDeviceID: String?) async throws {
        requests[requestID] = nil
        responses[requestID] = nil
        deleted.append(requestID)
    }
    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation? { nil }
    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws {}
    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? { nil }
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {}
    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {}
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? { nil }
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async throws {}
}

/// The Mac panel answered with a human Deny shortly after it opened.
private struct PhonePathPromptLocalDeny: PolicyReviewProvider {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        try? await Task.sleep(nanoseconds: 100_000_000)
        return .denied(.human(decidedAt: .now))
    }
}

// MARK: - Suite

func remoteApprovalPhonePathTests() async {
    print("\n# Remote approval phone path: grant reuse, SSH signing, no reads before a decision, mixed failure")
    if let fixture = await phonePathFixture() {
        await phoneGrantReuseTests(fixture)
        await phoneSSHSigningTests(fixture)
        await phoneNoEarlyReadTests(fixture)
        await phoneMixedFailureTests(fixture)
    }
    print("\n# Remote approval requester: replay past the rollover, restart, relay calls that never return, retry hints")
    await requesterRolloverReplayTests()
    await requesterRestartTests()
    await requesterHungRelayTests()
    await requesterThrottleTests()
}

// MARK: - A phone-minted grant covers the next identical request

private func phoneGrantReuseTests(_ fixture: PhonePathFixture) async {
    do {
        let run = await phonePathBoot(fixture.world, previous: phonePathLastRun)
        let relay = V3MailboxRelay()
        let spy = V3SpyRemote(await phonePathManager(fixture, run, relay: relay))
        let localPanel = V3UnansweredLocal()
        let consent = V3CountingConsent()
        let grantItems = InMemoryProtectedItemBackend()
        let persistence = GrantPersistence(stores: .processLocal(grantItems), facts: grantTestFacts)
        let grants = GrantTable(persistence: persistence)
        let agent = phonePathAgent(run, local: localPanel, remote: spy, consent: consent, grants: grants)
        let nativeRef = try SecretRef(phonePathNativeURI)
        let nativeValue = Data(phonePathNativeValue.utf8)
        let coldBefore = await run.provider.requiresUnlockToResolve(nativeRef)
        let keyLoadsBefore = await fixture.world.docKeys.loads

        let request = try AccessRequest(references: [phonePathNativeURI], reason: "phone grant reuse", deliveryPlan: v3AccessPlan())
        let first = Task { await agent.handle(request: request, caller: fixture.caller) }
        guard let envelope = await v3WaitForRequest(relay) else {
            first.cancel()
            check(false, "phone grant reuse: the first request reaches the phone")
            return
        }
        let offered = envelope.request.review
        try await relay.publishResponse(try fixture.phone.approve(envelope))
        let delivered = await phoneBounded(first, within: 10_000_000_000)
        let firstCounts = [await localPanel.reviews, await spy.reviews, await spy.readinessCalls, await relay.published.count]
        check(coldBefore && delivered?.values?[phonePathNativeURI] == nativeValue && firstCounts == [1, 1, 1, 1],
              "phone grant reuse: a cold native value is released on the phone's approval of its offered defaults "
                + "(panel, phone reviews, readiness checks, requests published: \(firstCounts))")

        let again = try AccessRequest(references: [phonePathNativeURI], reason: "phone grant reuse", deliveryPlan: v3AccessPlan())
        // Bounded: were it not covered, it would wait on a panel nobody answers.
        let reused = await phoneBounded(Task { await agent.handle(request: again, caller: fixture.caller) })
        let secondCounts = [await localPanel.reviews, await spy.reviews, await spy.readinessCalls, await relay.published.count]
        check(reused?.values?[phonePathNativeURI] == nativeValue && secondCounts == [1, 1, 1, 1],
              "phone grant reuse: the next identical request from the same root is delivered under the phone-minted "
                + "grant: no Mac panel, no phone review, no readiness check, no new mailbox request (\(secondCounts))")
        let stillCold = await run.provider.requiresUnlockToResolve(nativeRef)
        let keyLoads = await fixture.world.docKeys.loads
        let consentAsked = await consent.requests
        check(!stillCold && keyLoads == keyLoadsBefore && consentAsked == 0,
              "phone grant reuse: the store the phone's unlock opened stays open for the run; no local Touch ID and "
                + "no key-record read was needed")

        await persistence.settle()
        let minted = await grants.summaries(now: Date())
        let stored = await storedGrantsDocument(grantItems)?.secret ?? []
        let defaultDuration = offered.defaultDurationIndex.flatMap { index in
            offered.durationOptions.indices.contains(Int(index)) ? offered.durationOptions[Int(index)] : nil
        }
        check(minted.count == 1 && minted[0].scopeKind == .terminalSession && minted[0].expiresAt == nil
                && offered.defaultScopeID?.hasPrefix("terminal_session") == true && defaultDuration == "Until it exits"
                && stored.count == 1 && stored[0].origin == .phone && stored[0].scopeKind == .terminalSession,
              "phone grant reuse: the one grant is the phone's: its default scope (this terminal session) and "
                + "lifetime (until it exits), persisted with origin phone")
    } catch {
        check(false, "phone grant reuse (\(error))")
    }
}

// MARK: - SSH signing approved on the phone, for two backends

/// Whether `review` is an SSH review carrying exactly these facts. Kept out of
/// the async test below: Swift 6.3.3's optimizer (CopyPropagation) crashes on
/// these optional chains inline there.
private func phonePathCarriesSSHFacts(
    _ review: RemoteApprovalReview,
    hostNames: [String], hostContext: String, remoteUser: String, keyLabel: String, keyAlgorithm: String
) -> Bool {
    guard review.kind == .ssh, let ssh = review.ssh else { return false }
    return ssh.hostNames == hostNames && ssh.unknownHost == hostNames.isEmpty && ssh.hostContext == hostContext
        && ssh.remoteUser == remoteUser && ssh.keyLabel == keyLabel && ssh.keyAlgorithm == keyAlgorithm
}

private func phoneSSHSigningTests(_ fixture: PhonePathFixture) async {
    // A terminal (fish) running two ssh processes.
    let fish: pid_t = 74_000
    let nativeSSH: pid_t = 74_010
    let sealedSSH: pid_t = 74_020
    let parents: [pid_t: pid_t] = [fish: 1, nativeSSH: fish, sealedSSH: fish]
    let starts = Dictionary(uniqueKeysWithValues: parents.keys.map { ($0, UInt64($0) + 100) })
    let inspection = ProcessInspection(
        startTime: { starts[$0] },
        parent: { parents[$0] },
        name: { $0 == fish ? "fish" : "ssh" },
        executablePath: { $0 == fish ? "/opt/homebrew/bin/fish" : "/usr/bin/ssh" },
        hasControllingTerminal: { $0 == fish }
    )
    let session = Data(repeating: 0x5a, count: 32)

    do {
        let knownHost = try Ed25519SSHFixture(seed: 0x71)
        let unknownHost = try Ed25519SSHFixture(seed: 0x81)
        let knownBinding = try SSHDestinationBinding(
            hostKeyBlob: knownHost.publicKeyBlob, sessionIdentifier: session,
            signature: knownHost.signatureBlob(for: session), isForwarding: false
        )
        let unknownBinding = try SSHDestinationBinding(
            hostKeyBlob: unknownHost.publicKeyBlob, sessionIdentifier: session,
            signature: unknownHost.signatureBlob(for: session), isForwarding: false
        )
        let knownFingerprint = knownBinding.hostKeyFingerprint
        let lookup = SSHKnownHostsLookup { $0 == knownFingerprint ? ["phone.example.test"] : [] }

        let run = await phonePathBoot(fixture.world, previous: phonePathLastRun)
        let nativeRef = try SecretRef(phonePathSSHNativeURI)
        let coldNative = await run.provider.requiresUnlockToResolve(nativeRef)
        let coldSealed = await run.sealed.requiresUnlockToResolve(try SecretRef(phonePathSSHSealedURI))
        check(coldNative && coldSealed,
              "phone SSH: after the restart both keys' storage is sealed: the native store and the keyring provider")

        let relay = V3MailboxRelay()
        let spy = V3SpyRemote(await phonePathManager(fixture, run, relay: relay))
        let localPanel = V3UnansweredLocal()
        let consent = V3CountingConsent()
        let grantItems = InMemoryProtectedItemBackend()
        let persistence = GrantPersistence(stores: .processLocal(grantItems), facts: grantTestFacts)
        let nativeKey = fixture.world.nativeSSHKey
        let sealedKey = fixture.world.sealedSSHKey
        let catalog = SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [
            SSHKeyMetadata(
                reference: phonePathSSHNativeURI, fingerprint: sshFingerprint(nativeKey.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: nativeKey.publicKeyBlob, label: "phone native key"
            ),
            SSHKeyMetadata(
                reference: phonePathSSHSealedURI, fingerprint: sshFingerprint(sealedKey.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: sealedKey.publicKeyBlob, label: "phone keyring key"
            ),
        ]))
        let service = SSHSigningService(
            resolver: run.resolver, catalog: catalog, consent: consent,
            policyReview: MirroredPolicyReview(local: localPanel, remote: spy, log: { _ in }),
            allowUnverifiedCallersForTesting: true, processInspection: inspection, knownHostsLookup: lookup,
            terminalInspection: v3SilentTerminal, persistence: persistence
        )
        let keyLoadsBefore = await fixture.world.docKeys.loads

        let cases: [(name: String, key: Ed25519SSHFixture, label: String, binding: SSHDestinationBinding,
                     hostNames: [String], pid: pid_t)] = [
            ("cold native store, known host", nativeKey, "phone native key", knownBinding, ["phone.example.test"], nativeSSH),
            ("keyring provider, unknown host", sealedKey, "phone keyring key", unknownBinding, [], sealedSSH),
        ]
        for (index, sshCase) in cases.enumerated() {
            let name = sshCase.name
            let caller = CallerInfo(pid: sshCase.pid, startTime: starts[sshCase.pid] ?? 0, description: "synthetic phone SSH")
            let signedData = userAuthenticationRequest(
                sessionIdentifier: session, remoteUser: "deploy",
                publicKeyBlob: sshCase.key.publicKeyBlob, hostKeyBlob: sshCase.binding.hostKeyBlob
            )
            let publishedBefore = await relay.published.count
            let signing = Task {
                try? await service.signSSHAuthentication(
                    publicKeyBlob: sshCase.key.publicKeyBlob, signedData: signedData, flags: 0,
                    binding: sshCase.binding, caller: caller
                )
            }
            guard let envelope = await v3WaitForRequest(relay, number: publishedBefore) else {
                signing.cancel()
                check(false, "phone SSH (\(name)): the signing request reaches the phone")
                continue
            }
            try envelope.verify(macPublicKeyX963: fixture.pairing.macPublicKeyX963, at: currentTimeMilliseconds())
            let offered = envelope.request.review
            let details = SSHAccessReviewDetails(
                hostNames: sshCase.hostNames, remoteUser: "deploy", keyLabel: sshCase.label, keyAlgorithm: "ssh-ed25519"
            )
            check(phonePathCarriesSSHFacts(
                        offered, hostNames: sshCase.hostNames, hostContext: details.hostContext,
                        remoteUser: "deploy", keyLabel: sshCase.label, keyAlgorithm: "Ed25519"
                    )
                    && offered.warnings == (sshCase.hostNames.isEmpty ? [DeliveryReviewCopy.unknownHostWarning] : [])
                    && offered.footnote == DeliveryReviewCopy.sshFootnote
                    && envelope.request.unlockChallenge != nil,
                  "phone SSH (\(name)): the signed phone review carries the SSH facts (host names or UNKNOWN HOST, "
                    + "remote user, key label and algorithm), the signature-only footnote and an unlock challenge")
            let choices = GrantScopeInspector.choices(
                planRootPID: sshCase.pid, planRootStartTime: caller.startTime, requestingLabel: "ssh", inspection: inspection
            )
            check(offered.scopeOptions.map(\.id) == choices.options.map(\.id)
                    && offered.scopeOptions.map(\.title) == choices.options.map(ReviewDisplay.sshScopeTitle)
                    && offered.scopeOptions.map(\.detail) == choices.options.map(ReviewDisplay.sshScopeDetail)
                    && offered.defaultScopeID == choices.defaultOption.id
                    && offered.durationOptions == ["Until it exits", "1 hour", "12 hours"],
                  "phone SSH (\(name)): the phone is offered the SSH panel's scope titles and details, its default "
                    + "and its lifetimes")
            guard let requesting = choices.options.first(where: { $0.kind == .requestingCommand }),
                  requesting.id != choices.defaultOption.id else {
                signing.cancel()
                check(false, "phone SSH (\(name)): the requesting command is offered and is not the default")
                continue
            }

            // The phone picks the non-default scope (this SSH command) and 1 hour.
            try await relay.publishResponse(try fixture.phone.approve(envelope, scopeID: requesting.id, durationIndex: 1))
            let signature = await phoneBounded(signing, within: 10_000_000_000) ?? nil
            check(signature.map { sshCase.key.verifies(signatureBlob: $0, message: signedData) } == true,
                  "phone SSH (\(name)): the phone's approval returns a valid signature")

            let fingerprint = sshFingerprint(sshCase.key.publicKeyBlob)
            let summaries = await service.grantSummaries().filter { $0.ssh?.keyFingerprint == fingerprint }
            let expiry = summaries.first?.expiresAt?.timeIntervalSinceNow ?? 0
            await persistence.settle()
            let persisted = (await storedGrantsDocument(grantItems))?.ssh.filter { $0.keyFingerprint == fingerprint } ?? []
            check(summaries.count == 1 && summaries[0].scopeKind == .requestingCommand && summaries[0].rootPID == sshCase.pid
                    && expiry > 3_500 && expiry <= 3_600
                    && persisted.count == 1 && persisted[0].origin == .phone
                    && persisted[0].scopeKind == .requestingCommand && persisted[0].rootPID == sshCase.pid,
                  "phone SSH (\(name)): the grant has the phone's scope (this SSH command, not the default) and its "
                    + "1-hour lifetime, persisted with origin phone")
            let unlocks = await spy.unlocks
            check(unlocks.count == index + 1 && unlocks.last?.remote?.isInvalidated == true,
                  "phone SSH (\(name)): the phone's remote unlock is dropped once the signature is made")

            let before = [await localPanel.reviews, await spy.reviews, await relay.published.count]
            // Bounded: were it not covered, it would wait on a panel nobody answers.
            let again = await phoneBounded(Task {
                try? await service.signSSHAuthentication(
                    publicKeyBlob: sshCase.key.publicKeyBlob, signedData: signedData, flags: 0,
                    binding: sshCase.binding, caller: caller
                )
            }) ?? nil
            let after = [await localPanel.reviews, await spy.reviews, await relay.published.count]
            check(again.map { sshCase.key.verifies(signatureBlob: $0, message: signedData) } == true
                    && before == [index + 1, index + 1, index + 1] && after == before,
                  "phone SSH (\(name)): the next signing in that root is covered by the phone-minted grant: no Mac "
                    + "panel, no phone review, no new mailbox request (\(before) -> \(after))")
        }

        let keyLoads = await fixture.world.docKeys.loads
        let consentAsked = await consent.requests
        let sealedOpens = await run.sealed.remoteOpens
        let sealedResolves = await run.sealed.resolveCount
        let nativeOpen = !(await run.provider.requiresUnlockToResolve(nativeRef))
        check(keyLoads == keyLoadsBefore && consentAsked == 0 && nativeOpen && sealedOpens == 1 && sealedResolves == 2,
              "phone SSH: neither backend needed this Mac's Touch ID: the native key record was never read and the "
                + "store opened from its mirror; the keyring provider was opened once, by the phone's live unlock "
                + "(resolutions \(sealedResolves), remote opens \(sealedOpens))")
    } catch {
        check(false, "phone SSH (\(error))")
    }
}

// MARK: - Nothing is read before the phone decides

private func phoneNoEarlyReadTests(_ fixture: PhonePathFixture) async {
    // One reference of every kind the phone can carry: cold native storage, a
    // value cached at the Mac, a value only its provider can fetch, a sealed
    // provider's, and a provider that is locked.
    let references = [
        phonePathNativeURI, phonePathCachedURI, phonePathPlainURI, phonePathSSHSealedURI, phonePathLockedURI,
    ]

    // Pending, then a phone Deny.
    do {
        let run = await phonePathBoot(fixture.world, previous: phonePathLastRun)
        let relay = V3MailboxRelay()
        let agent = phonePathAgent(run, local: V3UnansweredLocal(), remote: await phonePathManager(fixture, run, relay: relay))
        let before = await phonePathReads(fixture, run)
        let request = try AccessRequest(references: references, reason: "phone no early reads", deliveryPlan: v3AccessPlan())
        let asked = Task { await agent.handle(request: request, caller: fixture.caller) }
        guard let envelope = await v3WaitForRequest(relay) else {
            asked.cancel()
            check(false, "phone no early reads: the request reaches the phone")
            return
        }
        let pollsAtPublish = await relay.polls
        let polled = await eventuallyTrue { await relay.polls >= pollsAtPublish + 2 }
        let pending = await phonePathReads(fixture, run)
        check(envelope.request.unlockChallenge != nil && polled && pending == before,
              "phone no early reads: while the phone request is pending nothing is resolved and no cache, key-record "
                + "or mirror item is read (reads since the request: \(pending.change(since: before)))")
        try await relay.publishResponse(try fixture.phone.respond(to: envelope, .deny))
        let denied = await phoneBounded(asked, within: 10_000_000_000)
        let afterDeny = await phonePathReads(fixture, run)
        check(denied?.failure?.code == .consentDenied && denied?.values == nil && afterDeny == before,
              "phone no early reads: after a phone Deny still nothing was resolved or read "
                + "(\(afterDeny.change(since: before)))")
    } catch {
        check(false, "phone no early reads: pending and denied (\(error))")
    }

    // Withdrawn: the Mac panel answers first.
    do {
        let run = await phonePathBoot(fixture.world, previous: phonePathLastRun)
        let relay = V3MailboxRelay()
        let localGate = GatedPolicyReview()
        let agent = phonePathAgent(run, local: localGate, remote: await phonePathManager(fixture, run, relay: relay))
        let before = await phonePathReads(fixture, run)
        let request = try AccessRequest(references: references, reason: "phone no early reads", deliveryPlan: v3AccessPlan())
        let asked = Task { await agent.handle(request: request, caller: fixture.caller) }
        guard let envelope = await v3WaitForRequest(relay) else {
            asked.cancel()
            check(false, "phone no early reads: the withdrawn request reaches the phone")
            return
        }
        let panelUp = await eventuallyTrue { await localGate.pendingCount == 1 }
        let pollsAtPublish = await relay.polls
        let polled = await eventuallyTrue { await relay.polls >= pollsAtPublish + 1 }
        let pending = await phonePathReads(fixture, run)
        await localGate.decide(.deny(.human(decidedAt: .now)))
        let refused = await phoneBounded(asked, within: 10_000_000_000)
        let withdrawn = await eventuallyTrue { await relay.deleted.contains(envelope.request.requestID) }
        let after = await phonePathReads(fixture, run)
        check(panelUp && polled && pending == before && refused?.failure?.code == .consentDenied && withdrawn
                && after == before,
              "phone no early reads: when the Mac panel answers first the phone request is withdrawn, and nothing "
                + "was resolved or read before or after (pending: \(pending.change(since: before)); after: "
                + "\(after.change(since: before)))")
    } catch {
        check(false, "phone no early reads: withdrawn (\(error))")
    }
}

// MARK: - A mixed release with a failing provider, approved on the phone

private func phoneMixedFailureTests(_ fixture: PhonePathFixture) async {
    let logDirectory = PhonePathDecisionLog()
    defer { logDirectory.remove() }
    let references = [phonePathNativeURI, phonePathPlainURI, phonePathLockedURI]
    do {
        let log = await logDirectory.open()
        let run = await phonePathBoot(fixture.world, previous: phonePathLastRun)
        let relay = V3MailboxRelay()
        let managerLog = V3LogLines()
        let spy = V3SpyRemote(await phonePathManager(fixture, run, relay: relay, log: managerLog))
        let grants = GrantTable()
        let agent = phonePathAgent(run, local: V3UnansweredLocal(), remote: spy, grants: grants, decisionLog: log)
        let request = try AccessRequest(references: references, reason: "phone mixed failure", deliveryPlan: v3AccessPlan())
        let asked = Task { await agent.handle(request: request, caller: fixture.caller) }
        guard let envelope = await v3WaitForRequest(relay) else {
            asked.cancel()
            check(false, "phone mixed failure: the request reaches the phone")
            return
        }
        check(envelope.request.unlockChallenge != nil,
              "phone mixed failure: a cold native reference makes the request carry an unlock challenge")
        try await relay.publishResponse(try fixture.phone.approve(envelope))
        let response = await phoneBounded(asked, within: 10_000_000_000)
        let minted = await grants.summaries(now: Date())
        check(response?.failure?.code == .resolutionFailed && response != nil && response?.values == nil
                && response?.failure?.message.contains("could not resolve") == true
                && response?.failure?.message.contains("locked://") == true && minted.isEmpty,
              "phone mixed failure: a phone-approved release whose locked provider refuses fails as resolution_failed, "
                + "delivers no value and mints no grant")
        let unlocks = await spy.unlocks
        check(unlocks.count == 1 && unlocks[0].remote?.isInvalidated == true,
              "phone mixed failure: the phone's remote unlock opened and was dropped after the failed release")

        let records = await phonePathRecords(log, streams: [.decisions], kinds: [.panel, .deliveryFailed])
        check(records.map(\.kind) == [.panel, .deliveryFailed]
                && records.first?.outcome == .phoneApproved && records.first?.decider == .humanPhone
                && records.first?.grantIDs == nil
                && records.last?.outcome == nil && records.last?.refs == references.sorted()
                && records.last?.detail?.contains("could not resolve") == true
                && records.last?.detail?.contains("no grant was minted") == true,
              "phone mixed failure: the decision log records the phone's approval, then the value-free delivery failure")
        let everything = await phonePathRecords(log)
        let values = [phonePathNativeValue, phonePathOpValue, phonePathLockedValue]
        let leaked = everything.contains { record in
            values.contains { (record.detail ?? "").contains($0) || (record.command ?? "").contains($0) }
        } || values.contains { managerLog.all.joined().contains($0) }
        check(!everything.isEmpty && !leaked, "phone mixed failure: no log line or record holds a value")

        // Nothing was minted, so the same request is reviewed again; with the
        // provider back it is delivered.
        await fixture.world.locked.setLocked(false)
        let retry = try AccessRequest(references: references, reason: "phone mixed failure", deliveryPlan: v3AccessPlan())
        let publishedBefore = await relay.published.count
        let retried = Task { await agent.handle(request: retry, caller: fixture.caller) }
        guard let second = await v3WaitForRequest(relay, number: publishedBefore) else {
            retried.cancel()
            await fixture.world.locked.setLocked(true)
            check(false, "phone mixed failure: the retried request reaches the phone again")
            return
        }
        try await relay.publishResponse(try fixture.phone.approve(second))
        let delivered = await phoneBounded(retried, within: 10_000_000_000)
        await fixture.world.locked.setLocked(true)
        let phoneReviews = await spy.reviews
        let mintedAfterRetry = await grants.summaries(now: Date())
        check(phoneReviews == 2 && delivered?.values?.count == 3 && !mintedAfterRetry.isEmpty,
              "phone mixed failure: the next identical request is reviewed on the phone again, and once the provider "
                + "is back it is delivered and minted")
    } catch {
        check(false, "phone mixed failure (\(error))")
    }
}

// MARK: - Replay past the consumed-ID rollover

private func requesterRolloverReplayTests() async {
    let phone = SyntheticPhone()
    let relay = PhoneLoopbackRelay(phone: phone)
    let review = v3SudoReviewFixture()
    do {
        let requester = try phonePathRequester(
            phone: phone, macKey: P256.Signing.PrivateKey(), macDeviceID: UUID().uuidString.lowercased(), relay: relay
        )
        let total = RemoteApprovalRequester.maximumConsumedRequestIDs + 1
        let started = Date()
        var approved = 0
        var replayBeforeRollover: RemoteApprovalAcceptance?
        for index in 0..<total {
            if await requester.requestApproval(for: review) == .approved(remoteApprovalNoSelection) {
                approved += 1
            }
            if index == 0, let first = await relay.answer(number: 0) {
                replayBeforeRollover = await requester.accept(first)
            }
        }
        let seconds = Date().timeIntervalSince(started)
        let answers = await relay.answerCount
        check(approved == total && answers == total,
              "requester rollover: \(total) phone approvals through one requester are each accepted "
                + "(\(String(format: "%.1f", seconds)) s)")
        check(replayBeforeRollover == .rejected(.alreadyConsumed),
              "requester rollover: before the rollover the first decision offered again is already consumed")
        guard let first = await relay.answer(number: 0),
              let middle = await relay.answer(number: total / 2),
              let last = await relay.answer(number: total - 1) else {
            check(false, "requester rollover: the phone's answers were kept")
            return
        }
        let replayed = [await requester.accept(first), await requester.accept(middle)]
        check(replayed == [.rejected(.notPending), .rejected(.notPending)],
              "requester rollover: past the \(RemoteApprovalRequester.maximumConsumedRequestIDs)-ID rollover the first "
                + "decision (and one from the middle) offered again is refused as not pending, never accepted")
        let latest = await requester.accept(last)
        check(latest == .rejected(.alreadyConsumed),
              "requester rollover: the decision consumed after the rollover is still refused as consumed")

        // Offered through the mailbox, in a live request's slot.
        await relay.stopAnswering()
        let live = Task { await requester.requestApproval(for: review) }
        guard let liveID = await phoneEventually({ await relay.publishedID(number: total) }) else {
            live.cancel()
            check(false, "requester rollover: a live request reaches the mailbox after the rollover")
            return
        }
        await relay.plant(first, inSlotOf: liveID)
        let cleared = await eventuallyTrue { await relay.discarded.contains(liveID) }
        let stillPending = await requester.isPending(requestID: liveID)
        await requester.withdraw(requestID: liveID)
        let ended = await phoneBounded(live)
        check(cleared && stillPending && ended == .unavailable,
              "requester rollover: the first decision planted in a live request's slot after the rollover is refused "
                + "and cleared, and approves nothing")
    } catch {
        check(false, "requester rollover (\(error))")
    }
}

// MARK: - A restarted requester and the previous run's request

private func requesterRestartTests() async {
    let phone = SyntheticPhone()
    let macKey = P256.Signing.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()
    let mailbox = HardenedMailboxRelay()
    let review = v3AccessReviewFixture(withRestore: false)
    do {
        // A: the csecd that published and then stopped.
        let severable = PhoneSeverableRelay(mailbox)
        let previous = try phonePathRequester(phone: phone, macKey: macKey, macDeviceID: macDeviceID, relay: severable)
        let waitingA = Task { await previous.requestApproval(for: review) }
        guard let envelopeA = await phoneEventually({ await mailbox.publishedRequest(number: 0) }) else {
            waitingA.cancel()
            check(false, "requester restart: the previous run's request reaches the mailbox")
            return
        }
        await severable.sever()
        let endedA = await phoneBounded(waitingA)
        let idA = envelopeA.request.requestID
        let slotA = "response-\(idA)-\(phone.deviceID)"
        let leftBehind = await mailbox.requestRecordNames().contains("request-\(idA)")
        check(endedA == .unavailable && leftBehind,
              "requester restart: a csecd that stops leaves its published request in the mailbox (setup)")

        // The phone answers the stopped run's request.
        let answerA = try phone.approve(envelopeA)
        try await mailbox.publishResponse(answerA)

        // B: the restarted csecd, with the same Mac key, Mac ID and phone pin.
        let restarted = try phonePathRequester(phone: phone, macKey: macKey, macDeviceID: macDeviceID, relay: mailbox)
        let offered = await restarted.accept(answerA)
        check(offered == .rejected(.notPending),
              "requester restart: the restarted requester refuses the phone's answer to the previous run's request "
                + "as not pending")
        // Reads from here on are the restarted run's; the stopped run polled its own slot.
        let readsBeforeRestart = await mailbox.responseReads.count
        let waitingB = Task { await restarted.requestApproval(for: review) }
        guard let envelopeB = await phoneEventually({ await mailbox.publishedRequest(number: 1) }) else {
            waitingB.cancel()
            check(false, "requester restart: the restarted run's request reaches the mailbox")
            return
        }
        let idB = envelopeB.request.requestID
        let slotB = "response-\(idB)-\(phone.deviceID)"
        let polled = await eventuallyTrue { await mailbox.responseReads.filter { $0 == slotB }.count >= 3 }
        let reads = await mailbox.responseReads.dropFirst(readsBeforeRestart)
        let pendingB = await restarted.isPending(requestID: idB)
        check(polled && !reads.contains(slotA) && pendingB,
              "requester restart: the restarted requester's own wait never reads the answer to the previous run's "
                + "request, and stays pending")

        await restarted.withdrawStaleRequests()
        let swept = await eventuallyTrue {
            let requests = await mailbox.requestRecordNames()
            let responses = await mailbox.responseRecordNames()
            return !requests.contains("request-\(idA)") && !responses.contains(slotA)
        }
        let remaining = await mailbox.requestRecordNames()
        let deletes = await mailbox.deleteRequests
        let deletedResponses = await mailbox.deletedResponseNames
        check(swept && remaining.contains("request-\(idB)") && deletes.contains(idA) && !deletes.contains(idB)
                && deletedResponses.contains(slotA),
              "requester restart: the startup sweep deletes the previous run's request and the phone's response to "
                + "it, and leaves the live request alone")
        let afterSweep = await restarted.accept(answerA)
        let stillPendingB = await restarted.isPending(requestID: idB)
        check(afterSweep == .rejected(.notPending) && stillPendingB,
              "requester restart: after the sweep the old answer is still refused, and the live request still waits")
        waitingB.cancel()
        _ = await phoneBounded(waitingB)
    } catch {
        check(false, "requester restart (\(error))")
    }
}

// MARK: - Relay calls that never return

private func requesterHungRelayTests() async {
    let phone = SyntheticPhone()
    let macKey = P256.Signing.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()

    // The request's save never returns; the request is withdrawn.
    do {
        let relay = PhoneHangingRelay(hanging: .publish)
        let requester = try phonePathRequester(phone: phone, macKey: macKey, macDeviceID: macDeviceID, relay: relay)
        let waiting = Task { await requester.requestApproval(for: v3SudoReviewFixture()) }
        let hung = await eventuallyTrue { await relay.parkedCalls == 1 }
        guard let requestID = await relay.publishedIDs.first else {
            waiting.cancel()
            await relay.release()
            check(false, "requester hung relay: the save is attempted")
            return
        }
        await requester.withdraw(requestID: requestID)
        let result = await phoneBounded(waiting, within: 2_000_000_000)
        let pending = await requester.isPending(requestID: requestID)
        check(hung && result == .unavailable && !pending,
              "requester hung relay: with the request's save never returning, a withdrawal answers the caller at once")
        await relay.release()
        let deleted = await eventuallyTrue { await relay.deleted.contains(requestID) }
        check(deleted, "requester hung relay: once the save returns, the withdrawn request is deleted from the mailbox")
    } catch {
        check(false, "requester hung relay: hung save (\(error))")
    }

    // The save stays hung past the drain bound: the delete goes out anyway,
    // and again once the save lands, so neither leaves a prompt on the phone.
    do {
        let relay = PhoneHangingRelay(hanging: .publish)
        let requester = try phonePathRequester(
            phone: phone, macKey: macKey, macDeviceID: macDeviceID, relay: relay,
            exchangeDrainNanoseconds: 100_000_000
        )
        let waiting = Task { await requester.requestApproval(for: v3SudoReviewFixture()) }
        let hung = await eventuallyTrue { await relay.parkedCalls == 1 }
        guard let requestID = await relay.publishedIDs.first else {
            waiting.cancel()
            await relay.release()
            check(false, "requester hung relay: the save is attempted (drain bound)")
            return
        }
        await requester.withdraw(requestID: requestID)
        _ = await phoneBounded(waiting, within: 2_000_000_000)
        let deletedWhileHung = await eventuallyTrue { await relay.deleted == [requestID] }
        let stillParked = await relay.parkedCalls == 1
        check(hung && deletedWhileHung && stillParked,
              "requester hung relay: past the drain bound the withdrawal deletes the exchange while the save is still hung")
        await relay.release()
        let redeleted = await eventuallyTrue { await relay.deleted == [requestID, requestID] }
        let landedThenGone = await relay.publishedRequest(number: 0) == nil
        check(redeleted && landedThenGone,
              "requester hung relay: once the late save lands, the exchange is deleted again, so it does not outlive the wait")
    } catch {
        check(false, "requester hung relay: drain bound (\(error))")
    }

    // The save never returns; the Mac panel answers.
    do {
        let relay = PhoneHangingRelay(hanging: .publish)
        let requester = try phonePathRequester(phone: phone, macKey: macKey, macDeviceID: macDeviceID, relay: relay)
        let review = MirroredPolicyReview(
            local: PhonePathPromptLocalDeny(),
            remote: RequesterRemoteAccessPolicyReviewProvider(requester: requester),
            log: { _ in }
        )
        let access = AccessPolicyReview(
            caller: CallerInfo(pid: 42, startTime: 7, description: "synthetic hung relay"),
            reason: "hung relay", plan: v3AccessPlan(),
            credentials: [PolicyReviewCredential(references: [try SecretRef("op://Vault/Hung/password")])]
        )
        let deciding = Task { await review.reviewAccess(access) }
        let outcome = await phoneBounded(deciding, within: 3_000_000_000)
        let hungCalls = await relay.parkedCalls
        var deniedOnMac = false
        if case .denied(.human)? = outcome { deniedOnMac = true }
        check(hungCalls == 1 && deniedOnMac,
              "requester hung relay: with the phone leg's save never returning, the Mac panel's answer is returned at once")
        await relay.release()
        if let requestID = await relay.publishedIDs.first {
            let deleted = await eventuallyTrue { await relay.deleted.contains(requestID) }
            check(deleted, "requester hung relay: once the save returns, the request the Mac panel decided is deleted")
        } else {
            check(false, "requester hung relay: the phone leg attempted its save")
        }
    } catch {
        check(false, "requester hung relay: hung save while the Mac decides (\(error))")
    }

    // The response poll never returns; the caller goes away; the phone answers late.
    do {
        let relay = PhoneHangingRelay(hanging: .poll)
        let requester = try phonePathRequester(phone: phone, macKey: macKey, macDeviceID: macDeviceID, relay: relay)
        let waiting = Task { await requester.requestApproval(for: v3SudoReviewFixture()) }
        let hung = await eventuallyTrue { await relay.parkedCalls == 1 }
        guard let envelope = await relay.publishedRequest(number: 0) else {
            waiting.cancel()
            await relay.release()
            check(false, "requester hung relay: the request is published before its poll hangs")
            return
        }
        waiting.cancel()
        let result = await phoneBounded(waiting, within: 2_000_000_000)
        check(hung && result == .unavailable,
              "requester hung relay: with the response poll never returning, cancelling the caller (the local prompt "
                + "won) answers it at once")
        let late = try phone.approve(envelope)
        try await relay.publishResponse(late)
        await relay.release()
        let deleted = await eventuallyTrue { await relay.deleted.contains(envelope.request.requestID) }
        let replay = await requester.accept(late)
        check(deleted && replay == .rejected(.notPending),
              "requester hung relay: the phone's approval the hung poll returns late is refused as not pending, and "
                + "the exchange is then deleted")
    } catch {
        check(false, "requester hung relay: hung poll (\(error))")
    }
}

// MARK: - A relay's retry hint

private func requesterThrottleTests() async {
    let phone = SyntheticPhone()
    let macKey = P256.Signing.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()

    // A hint far past the cap neither traps nor holds the caller.
    for stage in [PhoneLoopbackRelay.Stage.publish, .poll] {
        do {
            let relay = PhoneLoopbackRelay(phone: phone, throttleOnce: stage, throttleHint: .max)
            let requester = try phonePathRequester(phone: phone, macKey: macKey, macDeviceID: macDeviceID, relay: relay)
            let waiting = Task { await requester.requestApproval(for: v3SudoReviewFixture()) }
            let throttled = await eventuallyTrue {
                stage == .publish ? await relay.publishAttempts.count == 1 : await relay.polls.count == 1
            }
            // Past the poll interval: the requester is now waiting out the hint.
            try? await Task.sleep(nanoseconds: 200_000_000)
            let attempts = stage == .publish ? await relay.publishAttempts.count : await relay.polls.count
            waiting.cancel()
            let result = await phoneBounded(waiting, within: 2_000_000_000)
            check(throttled && attempts == 1 && result == .unavailable,
                  "requester throttle: a retry hint of UInt64.max on the \(stage == .publish ? "save" : "poll") is "
                    + "waited out, not retried at the poll interval, and the caller leaving ends the wait at once")
        } catch {
            check(false, "requester throttle: \(stage) hint (\(error))")
        }
    }

    // The 60 s cap itself, in real time: opt-in, since it takes a minute.
    guard ProcessInfo.processInfo.environment["CSEC_SELFTEST_THROTTLE_CAP"] == "1" else {
        print("skip - requester throttle cap in real time (about 60 s; set CSEC_SELFTEST_THROTTLE_CAP=1)")
        return
    }
    do {
        let publishRelay = PhoneLoopbackRelay(phone: phone, throttleOnce: .publish, throttleHint: .max)
        let pollRelay = PhoneLoopbackRelay(phone: phone, throttleOnce: .poll, throttleHint: .max)
        let publishing = try phonePathRequester(phone: phone, macKey: macKey, macDeviceID: macDeviceID, relay: publishRelay)
        let polling = try phonePathRequester(phone: phone, macKey: macKey, macDeviceID: macDeviceID, relay: pollRelay)
        // Bounded past the cap, so a requester that waits out the whole hint
        // fails the check instead of hanging the suite.
        let published = Task { await publishing.requestApproval(for: v3SudoReviewFixture()) }
        let polled = Task { await polling.requestApproval(for: v3SudoReviewFixture()) }
        let results = [await phoneBounded(published, within: 90_000_000_000),
                       await phoneBounded(polled, within: 90_000_000_000)]
        let publishTimes = await publishRelay.publishAttempts
        let pollTimes = await pollRelay.polls
        let cap = Duration.nanoseconds(Int64(RemoteApprovalRequester.maximumThrottleDelayNanoseconds))
        let gaps = [publishTimes, pollTimes].map { $0.count >= 2 ? $0[1] - $0[0] : nil }
        // The OS fires a timer this long a few percent late (coalescing); a
        // wait for the whole hint would never end, so 15% over is the bound.
        let withinCap = gaps.allSatisfy { gap in gap.map { $0 >= cap && $0 < cap * 1.15 } ?? false }
        check(results == [.approved(remoteApprovalNoSelection), .approved(remoteApprovalNoSelection)] && withinCap,
              "requester throttle: a retry hint of UInt64.max on a save and on a poll is waited for the "
                + "\(RemoteApprovalRequester.maximumThrottleDelayNanoseconds / 1_000_000_000) s cap, then the exchange "
                + "completes (\(gaps.map { $0.map { "\($0)" } ?? "none" }))")
    } catch {
        check(false, "requester throttle: real-time cap (\(error))")
    }
}
