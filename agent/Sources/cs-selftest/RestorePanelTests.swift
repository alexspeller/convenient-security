import CSECRemoteApproval
import ConvenientSecurity
import Foundation
import LocalAuthentication

// The restore panel: after a csecd restart, restored grants match exactly as
// before, but their sealed stores are cold. The first covered request that
// needs an unlock raises one panel for every restored grant needing one, and
// every concurrent request (secret or SSH) waits on it. Approve reopens the
// listed batch with one context, then invalidates it; "Forget these
// approvals" drops the batch and refuses every waiter; either uses the restore
// up. A requester that went away uses nothing up and drops nothing.

// MARK: - Fixtures

/// An LAContext that records being invalidated, standing in for the panel's
/// evaluated context.
final class RecordingContext: LAContext, @unchecked Sendable {
    private let lock = NSLock()
    private var wasInvalidated = false

    var invalidated: Bool {
        lock.lock()
        defer { lock.unlock() }
        return wasInvalidated
    }

    override func invalidate() {
        lock.lock()
        wasInvalidated = true
        lock.unlock()
        super.invalidate()
    }
}

/// A provider whose values are sealed until an evaluated context opens them:
/// the shape of the native store after a restart, under any scheme.
actor SealedFixtureProvider: SecretProvider {
    nonisolated let schemes: Set<String>
    private let values: [String: Data]
    private let opensOnWarm: Bool
    private var open = false
    private(set) var warmBatches: [[String]] = []
    private(set) var resolves = 0
    /// Contexts seen by `warm` and by an unlocked `resolve`, and whether each
    /// was already invalidated when it arrived.
    private(set) var contextsSeen: [ObjectIdentifier] = []
    private(set) var usedAfterInvalidation = false

    init(schemes: Set<String>, values: [String: Data], opensOnWarm: Bool = true) {
        self.schemes = schemes
        self.values = values
        self.opensOnWarm = opensOnWarm
    }

    var isOpen: Bool { open }

    func requiresUnlockToResolve(_ ref: SecretRef) async -> Bool { !open }

    func warm(_ refs: [SecretRef], unlock: CacheUnlock) async {
        note(unlock)
        warmBatches.append(refs.map(\.uri).sorted())
        if opensOnWarm { open = true }
    }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        resolves += 1
        if let unlock {
            note(unlock)
            open = true
        }
        guard open else { throw NativeStoreError.authenticationRequired }
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }

    private func note(_ unlock: CacheUnlock) {
        if let context = unlock.context { contextsSeen.append(ObjectIdentifier(context)) }
        if let recording = unlock.context as? RecordingContext, recording.invalidated {
            usedAfterInvalidation = true
        }
    }
}

/// A provider that serves with no unlock (1Password over its own session).
actor OpenFixtureProvider: SecretProvider {
    nonisolated let schemes: Set<String>
    private let values: [String: Data]
    private(set) var resolves = 0

    init(schemes: Set<String>, values: [String: Data]) {
        self.schemes = schemes
        self.values = values
    }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        resolves += 1
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

/// Holds every review open until the test answers it, like a human at the
/// panel. An approval carries a session whose context is a `RecordingContext`.
actor RestoreReviewGate: PolicyReviewProvider {
    enum Answer: Sendable {
        case approve
        /// Approved on the paired phone: nobody need be at the Mac.
        case approveOnPhone
        case deny(AccessPolicyDenialReason)
    }

    private var waiting: [(UUID, CheckedContinuation<Answer, Never>)] = []
    private(set) var reviews: [AccessPolicyReview] = []
    private(set) var contexts: [RecordingContext] = []
    private(set) var cancelled = 0
    private var automatic: Answer?

    var pendingCount: Int { waiting.count }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews.append(review)
        let id = UUID()
        let answer: Answer = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(returning: .deny(.requesterGone))
                } else if let automatic {
                    continuation.resume(returning: automatic)
                } else {
                    waiting.append((id, continuation))
                }
            }
        } onCancel: {
            Task { await self.cancel(id) }
        }
        switch answer {
        case .approve, .approveOnPhone:
            let context = RecordingContext()
            contexts.append(context)
            var surface = HumanDecisionSurface.mac
            if case .approveOnPhone = answer { surface = .phone }
            return .approved(AccessPolicyApproval(
                authenticationSession: RestoreFixtureSession(context: context),
                decisionLatency: .milliseconds(1_500),
                decidedOn: surface
            ))
        case let .deny(reason):
            return .denied(reason)
        }
    }

    private func cancel(_ id: UUID) {
        guard let index = waiting.firstIndex(where: { $0.0 == id }) else { return }
        cancelled += 1
        waiting.remove(at: index).1.resume(returning: .deny(.requesterGone))
    }

    func decide(_ answer: Answer) {
        guard !waiting.isEmpty else { return }
        waiting.removeFirst().1.resume(returning: answer)
    }

    func decideAll(_ answer: Answer) {
        automatic = answer
        let held = waiting
        waiting = []
        for (_, continuation) in held { continuation.resume(returning: answer) }
    }
}

private actor RestoreFixtureSession: AccessPolicyAuthenticationSession {
    let context: RecordingContext
    private var used = false

    init(context: RecordingContext) { self.context = context }

    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        guard !used else { return .denied }
        used = true
        return .approved(unlock: CacheUnlock(context))
    }

    func cancel() async {
        used = true
        context.invalidate()
    }
}

/// Resumes a continuation once, from whichever of two tasks gets there first.
private final class FirstResume<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var resumed = false
    private let continuation: CheckedContinuation<T, Never>

    init(_ continuation: CheckedContinuation<T, Never>) { self.continuation = continuation }

    func resume(_ value: T) {
        lock.lock()
        defer { lock.unlock() }
        guard !resumed else { return }
        resumed = true
        continuation.resume(returning: value)
    }
}

/// A task's value, or `fallback` if it has not finished within `seconds`. A
/// regression that raises an unexpected panel nobody answers then fails a
/// check instead of hanging the suite.
private func race<T: Sendable>(_ task: Task<T, Never>, otherwise fallback: T, seconds: UInt64 = 20) async -> T {
    await withCheckedContinuation { continuation in
        let once = FirstResume(continuation)
        Task { once.resume(await task.value) }
        Task {
            try? await Task.sleep(nanoseconds: seconds * 1_000_000_000)
            once.resume(fallback)
        }
    }
}

private func settled(_ task: Task<Response, Never>) async -> Response {
    await race(task, otherwise: .failed(.internalError, message: "timed out waiting for the request"))
}

private func settled(_ task: Task<Data?, Never>) async -> Data? {
    await race(task, otherwise: nil)
}

private func settled(_ task: Task<GrantRestoration.Wait, Never>) async -> GrantRestoration.Wait {
    await race(task, otherwise: .failed)
}

private func restorePlan(_ name: String) -> DeliveryPlan {
    DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/\(name)", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: 600, operationContext: "synthetic \(name)"
    )
}

private struct RestoreHarness {
    let agent: Agent
    let resolver: SecretResolver
    let grants: GrantTable
    let ssh: SSHSigningService
    let restoration: GrantRestoration
    let gate: RestoreReviewGate
    let persistence: GrantPersistence
    let backend: InMemoryProtectedItemBackend
    let accessQueue: ConsentQueue
    let log: DecisionLog?
    let sshKey: Ed25519SSHFixture
    let hostKey: Ed25519SSHFixture
    let binding: SSHDestinationBinding
}

private let sshKeyReference = "vault://restore-ssh/key"

private func makeRestoreHarness(
    providers: [any SecretProvider],
    sshKey: Ed25519SSHFixture,
    withLog: Bool = false,
    secondSSHKey: Ed25519SSHFixture? = nil,
    cache: SecretCache = NullSecretCache(),
    itemSources: [any RestoreItemSource] = []
) async throws -> RestoreHarness {
    let resolver = SecretResolver(cache: cache)
    for provider in providers { await resolver.register(provider) }
    let backend = InMemoryProtectedItemBackend()
    let stores = ProtectedStores.processLocal(backend)
    let persistence = GrantPersistence(stores: stores, facts: grantTestFacts)
    var log: DecisionLog?
    if withLog {
        let directory = (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("csec-restore-log-\(UUID().uuidString)")
        let opened = DecisionLog(directory: SealedRecordDirectory(path: directory), stores: stores)
        _ = await opened.open()
        log = opened
    }
    let gate = RestoreReviewGate()
    let uiQueue = ConsentQueue()
    let reviewer = QueuedPolicyReview(underlying: gate, queue: uiQueue)
    let restoration = GrantRestoration(
        resolver: resolver, policyReview: reviewer, consent: SilentApprovingConsent(),
        persistence: persistence, decisionLog: log, terminalInspection: .unavailable
    )
    await restoration.setRestartCause(.restart)
    let grants = GrantTable(persistence: persistence)
    await restoration.addGrantSource(grants)
    for source in itemSources { await restoration.addItemSource(source) }
    let hostKey = try Ed25519SSHFixture(seed: 157)
    let session = Data(repeating: 0x42, count: 32)
    let binding = try SSHDestinationBinding(
        hostKeyBlob: hostKey.publicKeyBlob, sessionIdentifier: session,
        signature: hostKey.signatureBlob(for: session), isForwarding: false
    )
    let ssh = SSHSigningService(
        resolver: resolver,
        catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [SSHKeyMetadata(
            reference: sshKeyReference, fingerprint: sshFingerprint(sshKey.publicKeyBlob),
            algorithm: "ssh-ed25519", publicKeyBlob: sshKey.publicKeyBlob, label: "restore key"
        )] + (secondSSHKey.map { second in [SSHKeyMetadata(
            reference: sshKeyReference + "2", fingerprint: sshFingerprint(second.publicKeyBlob),
            algorithm: "ssh-ed25519", publicKeyBlob: second.publicKeyBlob, label: "second key"
        )] } ?? []))),
        consent: SilentApprovingConsent(), policyReview: reviewer,
        allowUnverifiedCallersForTesting: true,
        knownHostsLookup: SSHKnownHostsLookup { _ in ["restore.example.test"] },
        terminalInspection: .unavailable,
        decisionLog: log,
        persistence: persistence,
        restoration: restoration
    )
    await restoration.addGrantSource(ssh)
    let accessQueue = ConsentQueue()
    let agent = Agent(
        resolver: resolver, grants: grants,
        consent: QueuedConsentProvider(underlying: SilentApprovingConsent(), queue: uiQueue),
        policyReview: reviewer, sshSigningService: ssh,
        allowUnverifiedPlansForTesting: true, terminalInspection: .unavailable,
        accessConsentQueue: accessQueue, decisionLog: log,
        grantPersistence: persistence, restoration: restoration
    )
    return RestoreHarness(
        agent: agent, resolver: resolver, grants: grants, ssh: ssh, restoration: restoration, gate: gate,
        persistence: persistence, backend: backend, accessQueue: accessQueue, log: log,
        sshKey: sshKey, hostKey: hostKey, binding: binding
    )
}

/// A restored secret grant covering `references` for `plan`'s exact digest.
private func restoredGrant(
    root: pid_t, start: UInt64, references: Set<String>, plan: DeliveryPlan, label: String = "fish"
) -> Grant {
    Grant(
        rootPID: root, rootStartTime: start, references: references, reason: "restored fixture",
        deliveryPlanDigest: try? plan.digest(), rootProcessLabel: label,
        restored: true, warm: false
    )
}

private func restoredSSHGrant(_ harness: RestoreHarness, root: pid_t, start: UInt64) -> PersistedSSHGrant {
    persistedSSHGrant(
        root: root, start: start, fingerprint: sshFingerprint(harness.sshKey.publicKeyBlob),
        hostKeyFingerprint: harness.binding.hostKeyFingerprint, remoteUser: "deploy"
    )
}

private func ask(
    _ harness: RestoreHarness, _ references: [String], plan: DeliveryPlan, caller: CallerInfo
) -> Task<Response, Never> {
    let request = try! AccessRequest(
        references: references, reason: plan.operationContext, ttlSeconds: 600, deliveryPlan: plan
    )
    let agent = harness.agent
    return Task { await agent.handle(request: request, caller: caller) }
}

private func signTask(
    _ harness: RestoreHarness, caller: CallerInfo, key signingKey: Ed25519SSHFixture? = nil
) -> Task<Data?, Never> {
    let ssh = harness.ssh, key = signingKey ?? harness.sshKey, host = harness.hostKey
    let binding = harness.binding
    return Task {
        try? await ssh.signSSHAuthentication(
            publicKeyBlob: key.publicKeyBlob,
            signedData: userAuthenticationRequest(
                sessionIdentifier: binding.sessionIdentifier, remoteUser: "deploy",
                publicKeyBlob: key.publicKeyBlob, hostKeyBlob: host.publicKeyBlob
            ),
            flags: 0, binding: binding, caller: caller
        )
    }
}

/// A live process outside this test's own ancestry: another terminal's root.
private func otherRoot() -> (process: Process, pid: pid_t, start: UInt64)? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sleep")
    process.arguments = ["60"]
    guard (try? process.run()) != nil,
          let start = ProcessAncestry.startTime(of: process.processIdentifier) else { return nil }
    return (process, process.processIdentifier, start)
}

// MARK: - Suite

func restorePanelTests() async {
    print("\n# The restore panel (restart warm-up)")
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let myStart = ProcessAncestry.startTime(of: me),
          let sshKey = try? Ed25519SSHFixture(seed: 151),
          let other = otherRoot() else {
        check(false, "restore-panel fixtures can be built")
        return
    }
    defer { other.process.terminate() }
    let context = RestoreContext(me: me, myStart: myStart, sshKey: sshKey, other: (other.pid, other.start))
    restoreCopyTests()
    await mirroredRestoreTests()
    await remoteRestoreCoverageFixTests()
    await singleFlightTests(context)
    await forgetTests(context)
    await approvalUsedUpTests(context)
    await requesterGoneTests(context)
    await representTests(context)
    await orphanedSharedRestoreTests(context)
    await mixedPanelTests(context)
    await mixedDenyTests(context)
    await opOnlyTests(context)
    await backendNeutralityTests(context)
    await restoreRecordTests(context)
    await staleWaitTests(context)
    await latecomerTests(context)
    await sshForgetEndsConnectionTests(context)
    await authenticationFailureTests(context)
    await installerRestoreTests(context)
    await fetchAheadAfterMacApprovalTests(context)
    await installerRestoreJoinTests(context)
    await installerRestoreOutcomeTests(context)
    installerRestoreWireTests()
    await installerRestoreClientTests()
}

// MARK: - An attended installer owns the existing restore

private func installRestore(_ harness: RestoreHarness, caller: CallerInfo) -> Task<Response, Never> {
    Task { await harness.agent.restoreApprovals(request: RestoreApprovalsRequest(), caller: caller) }
}

private func installerRestoreTests(_ context: RestoreContext) async {
    let sealed = context.sealed()
    let op = SealedFixtureProvider(schemes: ["op"], values: ["op://Fixture/Install/password": Data("fixture".utf8)])
    guard let harness = try? await makeRestoreHarness(providers: [sealed, op], sshKey: context.sshKey) else {
        check(false, "installer restore harness builds")
        return
    }
    let plan = restorePlan("install")
    await harness.grants.restore([
        restoredGrant(root: context.me, start: context.myStart,
                      references: ["csec://restore/A", "op://Fixture/Install/password"], plan: plan),
    ])
    await harness.ssh.restore([restoredSSHGrant(harness, root: context.me, start: context.myStart)])
    let installer = installRestore(harness, caller: context.caller)
    check(await eventuallyTrue { await harness.gate.pendingCount == 1 }, "installer raises a restore before a consumer needs it")
    for _ in 0..<3 {
        let access = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
        let signing = signTask(harness, caller: context.caller)
        check(await eventuallyTrue { await harness.restoration.waitingCount == 3 },
              "secret and SSH requests join the installer's restore")
        access.cancel()
        signing.cancel()
        _ = await settled(access)
        _ = await settled(signing)
        let waiting = await harness.restoration.waitingCount
        let reviews = await harness.gate.reviews.count
        let cancelled = await harness.gate.cancelled
        check(waiting == 1 && reviews == 1 && cancelled == 0,
              "successive secret/SSH cancellations leave the installer's one review pending")
    }
    let review = await harness.gate.reviews.first
    check(review?.isRestoreOnly == true && review?.restore?.rows.count == 2
            && review?.restore?.rows.contains { $0.references.contains("op://Fixture/Install/password") } == true,
          "the installer uses server-selected secret and SSH rows across native, op and vault schemes")
    await harness.gate.decide(.approve)
    let response = await settled(installer)
    let grantCount = await harness.grants.summaries(now: Date()).count
    let resolves = await sealed.resolves + op.resolves
    let contexts = await harness.gate.contexts
    check(response.restorationStatus == .reopened && response.values == nil && grantCount == 1 && resolves == 0,
          "installer approval warms existing authority without resolving or returning values or creating a grant")
    check(contexts.count == 1 && contexts.allSatisfy(\.invalidated), "the installer's one touch context is invalidated")
    let again = await settled(installRestore(harness, caller: context.caller))
    let reviews = await harness.gate.reviews.count
    check(again.restorationStatus == .alreadyRestored && reviews == 1, "an already completed restore prompts no more")
}

private func installerRestoreJoinTests(_ context: RestoreContext) async {
    for mixed in [false, true] {
        guard let harness = try? await makeRestoreHarness(providers: [context.sealed()], sshKey: context.sshKey) else {
            check(false, "installer join harness builds")
            return
        }
        let plan = restorePlan(mixed ? "install-mixed" : "install-join")
        await harness.grants.restore([
            restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan),
        ])
        let access = ask(harness, mixed ? ["csec://restore/A", "csec://restore/N"] : ["csec://restore/A"],
                         plan: plan, caller: context.caller)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let installer = installRestore(harness, caller: context.caller)
        check(await eventuallyTrue { await harness.restoration.waitingCount == (mixed ? 1 : 2) },
              "installer joins an existing \(mixed ? "mixed" : "restore-only") panel")
        await harness.gate.decide(.approve)
        let result = await settled(installer)
        let accessResult = await settled(access)
        let reviews = await harness.gate.reviews.count
        check(result.restorationStatus == .reopened && accessResult.values != nil && reviews == 1,
              "the existing \(mixed ? "mixed" : "restore-only") review answers installer and consumer once")
    }
    // A failed authentication must not be retried for an installer that
    // joined someone else's restore-only or mixed review.
    for mixed in [false, true] {
        guard let harness = try? await makeRestoreHarness(providers: [context.sealed()], sshKey: context.sshKey) else { return }
        let plan = restorePlan("install-join-failure")
        await harness.grants.restore([
            restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan),
        ])
        let access = ask(harness, mixed ? ["csec://restore/A", "csec://restore/N"] : ["csec://restore/A"],
                         plan: plan, caller: context.caller)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let installer = installRestore(harness, caller: context.caller)
        _ = await eventuallyTrue { await harness.restoration.waitingCount == (mixed ? 1 : 2) }
        await harness.gate.decide(.deny(.authenticationFailed))
        let response = await settled(installer)
        _ = await settled(access)
        let reviews = await harness.gate.reviews.count
        check(response.failure != nil && reviews == 1, "a joined \(mixed ? "mixed" : "restore-only") authentication failure is never retried for the installer")
    }
}

private func installerRestoreOutcomeTests(_ context: RestoreContext) async {
    guard let empty = try? await makeRestoreHarness(providers: [context.sealed()], sshKey: context.sshKey) else { return }
    let nothing = await settled(installRestore(empty, caller: context.caller))
    let emptyReviews = await empty.gate.reviews.count
    check(nothing.restorationStatus == .notNeeded && emptyReviews == 0, "nothing pending means no installer prompt")

    for failure in [false, true] {
        guard let harness = try? await makeRestoreHarness(providers: [context.sealed()], sshKey: context.sshKey) else { return }
        let plan = restorePlan("install-outcome")
        await harness.grants.restore([
            restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan),
        ])
        let installer = installRestore(harness, caller: context.caller)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        await harness.gate.decide(.deny(failure ? .authenticationFailed : .human(decidedAt: .now, on: .mac)))
        let response = await settled(installer)
        let used = await harness.restoration.isUsedUp
        let reviews = await harness.gate.reviews.count
        check(failure ? response.failure?.code == .consentDenied && !used : response.restorationStatus == .forgotten && used,
              failure ? "authentication failure fails the installer and leaves restoration unused"
                      : "Forget is a completed installer choice, with no grant or value returned")
        check(reviews == 1 && response.values == nil, "the installer never retries an undecided or forgotten restore")
    }

    let cold = SealedFixtureProvider(schemes: ["csec"], values: ["csec://restore/A": Data("fixture".utf8)], opensOnWarm: false)
    if let harness = try? await makeRestoreHarness(providers: [cold], sshKey: context.sshKey) {
        await harness.grants.restore([
            restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: restorePlan("cold")),
        ])
        let installer = installRestore(harness, caller: context.caller)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        await harness.gate.decide(.approve)
        let response = await settled(installer)
        check(response.failure != nil && response.restorationStatus == nil, "a row that stayed cold cannot report installer success")
    }

    for processLoss in [false, true] {
        guard let child = otherRoot(),
              let harness = try? await makeRestoreHarness(providers: [context.sealed()], sshKey: context.sshKey) else { return }
        defer { if child.process.isRunning { child.process.terminate() } }
        await harness.grants.restore([
            restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: restorePlan("install-gone")),
        ])
        let caller = processLoss ? CallerInfo(pid: child.pid, startTime: child.start, description: "installer") : context.caller
        let installer = installRestore(harness, caller: caller)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        if processLoss { child.process.terminate() } else { installer.cancel() }
        let response = await settled(installer)
        _ = await eventuallyTrue { await harness.gate.cancelled == 1 }
        let used = await harness.restoration.isUsedUp
        let remaining = await harness.grants.summaries(now: Date()).count
        check(response.failure?.code == .consentDenied && !used && remaining == 1,
              "installer \(processLoss ? "process loss" : "cancellation") withdraws without dropping or restoring approvals")
    }

    let untrusted = Agent(resolver: SecretResolver(cache: NullSecretCache()), grants: GrantTable(),
                          consent: SilentApprovingConsent(), policyReview: RestoreReviewGate(), terminalInspection: .unavailable)
    let rejected = await untrusted.restoreApprovals(request: RestoreApprovalsRequest(), caller: context.caller)
    check(rejected.failure?.code == .unverifiedPeer, "an unverified peer cannot request restoration")
}

private func installerRestoreWireTests() {
    let request = RestoreApprovalsRequest()
    let encoded = try? JSONEncoder().encode(Request.restoreApprovals(request))
    let object = encoded.flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    let decoded = encoded.flatMap { try? JSONDecoder().decode(Request.self, from: $0) }
    if case let .restoreApprovals(roundTrip) = decoded {
        check(roundTrip.requestID == request.requestID && Set(object?.keys.map { $0 } ?? []) == ["type", "version", "requestID"],
              "restore wire round-trip contains only a discriminator, protocol version and nonce")
    } else { check(false, "restore wire round-trip decodes") }
    for nonce in ["", "not-a-uuid"] {
        let data = try! JSONSerialization.data(withJSONObject: ["type": "restore_approvals", "requestID": nonce])
        check((try? JSONDecoder().decode(Request.self, from: data)) == nil, "restore wire refuses an invalid request nonce")
    }
    for role: ProductCodeRole in [.launcher, .sudoReviewHelper, .agent, .rootHelper, .other] {
        check(SocketPeerTrustPolicy.permits(.restoreApprovals(request), role: role) == (role == .launcher),
              "restore is available only to the verified launcher (\(role))")
    }
    for status in RestorationStatus.allCases {
        let response = Response(requestID: request.requestID, restorationStatus: status)
        let data = try! JSONEncoder().encode(response)
        let object = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
        check(Set(object.keys) == ["version", "requestID", "restorationStatus"], "restore replies carry only nonce, version and bounded status")
    }
}

private actor InstallerReply {
    enum Mode: Sendable {
        case status(RestorationStatus), fetched(FetchAheadSummary), unbounded, wrongNonce, wrongVersion, missingStatus, value, failure
    }
    var mode: Mode = .status(.notNeeded)
    func set(_ mode: Mode) { self.mode = mode }
    func response(_ request: RestoreApprovalsRequest) -> Response {
        switch mode {
        case let .status(status): return Response(requestID: request.requestID, restorationStatus: status)
        case let .fetched(summary):
            return Response(requestID: request.requestID, restorationStatus: .notNeeded, restoreFetchAhead: summary)
        case .unbounded:
            // Built by hand past `FetchAheadSummary.init`'s own bounds, as a
            // misbehaving daemon could send it.
            let json = #"{"fetched":1,"alreadyHeld":0,"failureCount":1,"failures":[{"reference":"not a reference","reason":"r"}]}"#
            let summary = try! JSONDecoder().decode(FetchAheadSummary.self, from: Data(json.utf8))
            return Response(requestID: request.requestID, restorationStatus: .notNeeded, restoreFetchAhead: summary)
        case .wrongNonce: return Response(requestID: UUID().uuidString, restorationStatus: .reopened)
        case .wrongVersion: return Response(version: 99, requestID: request.requestID, restorationStatus: .reopened)
        case .missingStatus: return Response(requestID: request.requestID)
        case .value: return Response(requestID: request.requestID, values: ["fixture": Data("fixture".utf8)], restorationStatus: .reopened)
        case .failure: return .failed(.consentDenied, message: "synthetic restore failure", requestID: request.requestID)
        }
    }
}

private func installerRestoreClientTests() async {
    let base = URL(fileURLWithPath: "/tmp/cs-ir-\(UUID().uuidString.prefix(8))")
    try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: base) }
    let socket = base.appendingPathComponent("agent.sock").path
    let reply = InstallerReply()
    let server = SocketServer(path: socket, clientTrustPolicy: .allowUnverifiedForTesting) { request, _ in
        guard case let .restoreApprovals(request) = request else { return .failed(.invalidRequest, message: "unexpected") }
        return await reply.response(request)
    }
    Thread.detachNewThread { try? server.run() }
    guard waitForSocket(socket) else { check(false, "installer restore socket starts"); return }
    let client = AgentClient(path: socket, serverTrustPolicy: .allowUnverifiedForTesting)
    for status in RestorationStatus.allCases {
        await reply.set(.status(status))
        // What was thrown goes in the check's line: this once failed for
        // every status on a loaded runner, with nothing to say why.
        let outcome = await Task.detached { Result { try client.restoreApprovals() } }.value
        let received = try? outcome.get()
        check(received?.status == status && received?.fetchedAhead == nil,
              "restore client accepts bounded status \(status.rawValue)"
                  + (received == nil ? " (\(outcome))" : ""))
    }
    let summary = FetchAheadSummary(fetched: 2, alreadyHeld: 1, failures: [
        .init(reference: "op://Paired/Item/credential", reason: "1Password did not authorize this request"),
    ])
    await reply.set(.fetched(summary))
    let fetched = await Task.detached { try? client.restoreApprovals() }.value
    check(fetched?.status == .notNeeded && fetched?.fetchedAhead == summary,
          "restore client accepts a bounded fetch-ahead summary")
    for mode: InstallerReply.Mode in [.unbounded, .wrongNonce, .wrongVersion, .missingStatus, .value, .failure] {
        await reply.set(mode)
        let received = await Task.detached { try? client.restoreApprovals() }.value
        check(received == nil, "restore client rejects nonce, shape and consent failures")
    }
    #if DEBUG
    let csec = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent().appendingPathComponent("csec")
    do {
        await reply.set(.fetched(summary))
        let child = Process(), out = Pipe(), err = Pipe()
        let exit = ChildProcessExit(child)
        child.executableURL = csec
        child.arguments = ["restore"]
        child.environment = ["PATH": "/usr/bin:/bin", "HOME": base.path, "CSEC_SOCKET": socket]
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = out
        child.standardError = err
        if (try? child.run()) != nil, await exit.wait(within: 15) {
            let output = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            check(child.terminationStatus == 0
                    && output.contains("2 fetched, 1 already held, 1 not fetched")
                    && output.contains("not fetched: op://Paired/Item/credential: 1Password did not authorize this request"),
                  "restore CLI reports what it fetched ahead and why the rest was not, and still succeeds")
        } else {
            child.terminate()
            check(false, "restore CLI with a fetch-ahead summary finishes")
        }
    }
    for failure in [false, true] {
        await reply.set(failure ? .failure : .status(.forgotten))
        let child = Process(), out = Pipe(), err = Pipe()
        let exit = ChildProcessExit(child)
        child.executableURL = csec
        child.arguments = ["restore"]
        child.environment = ["PATH": "/usr/bin:/bin", "HOME": base.path, "CSEC_SOCKET": socket]
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = out
        child.standardError = err
        guard (try? child.run()) != nil else { check(false, "restore CLI starts"); return }
        guard await exit.wait(within: 15) else { child.terminate(); check(false, "restore CLI finishes"); return }
        let output = String(decoding: out.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        let errors = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        check(failure ? child.terminationStatus == 1 && output.isEmpty && errors.contains("synthetic restore failure")
                      : child.terminationStatus == 0 && output == "Restored approvals forgotten as requested.\n",
              "restore CLI \(failure ? "fails without retrying or printing values" : "reports Forget as a completed choice")")
    }
    #endif
}

private struct RestoreContext {
    let me: pid_t
    let myStart: UInt64
    let sshKey: Ed25519SSHFixture
    let other: (pid: pid_t, start: UInt64)

    var caller: CallerInfo { CallerInfo(pid: me, startTime: myStart, description: "synthetic restore caller") }

    func sealed(_ extra: [String: Data] = [:]) -> SealedFixtureProvider {
        var values: [String: Data] = [
            "csec://restore/A": Data("synthetic-restore-a".utf8),
            "csec://restore/B": Data("synthetic-restore-b".utf8),
            "csec://restore/C": Data("synthetic-restore-c".utf8),
            "csec://restore/N": Data("synthetic-restore-new".utf8),
            sshKeyReference: sshKey.privateKeyPEM,
        ]
        values.merge(extra) { _, new in new }
        return SealedFixtureProvider(schemes: ["csec", "vault"], values: values)
    }
}

// MARK: - Copy and phone gate

private func restoreCopyTests() {
    let rows = [RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "d", references: ["csec://x/Y"])]
    check(RestoreReviewDetails(cause: .upgrade, rows: rows, storeCount: 2).header
            == "csecd restarted (upgrade): reopen what you approved"
          && RestoreReviewDetails(cause: .crash, rows: rows, storeCount: 1).header
            == "csecd restarted (crash): reopen what you approved"
          && RestoreReviewDetails(cause: nil, rows: rows, storeCount: 1).header
            == "csecd restarted: reopen what you approved",
          "the restore header names the restart cause")
    check(RestoreReviewDetails(cause: .restart, rows: rows, storeCount: 1).footnote
            == "Touch ID reopens 1 store. Nothing new is approved."
          && RestoreReviewDetails(cause: .restart, rows: rows, storeCount: 3).footnote
            == "Touch ID reopens 3 stores. Nothing new is approved.",
          "the restore footnote counts the stores the touch reopens")
    check(RestoreReviewDetails.forgetButtonTitle == "Forget these approvals",
          "the restore panel's refusing button is Forget these approvals")
    let mixed = RestoreReviewDetails(cause: .restart, rows: rows, storeCount: 2).mixedFootnote
    check(!mixed.contains("Nothing new") && mixed.contains("also reopens 2 stores")
            && mixed.contains("Deny refuses this request"),
          "a mixed panel's restore note never says nothing new is approved (\(mixed))")
    check(RestoreReviewDetails(cause: .restart, rows: rows, storeCount: 1).mixedFootnote
            == "Touch ID also reopens 1 store for approvals you already made. "
                + "Deny refuses this request and forgets these approvals too.",
          "the mixed note counts the stores it also reopens")
    let caller = CallerInfo(pid: 1, startTime: 1, description: "x")
    let only = AccessPolicyReview.restoreOnly(
        caller: caller, restore: RestoreReviewDetails(cause: .restart, rows: rows, storeCount: 1)
    )
    check(only.isRestoreOnly && only.credentials.isEmpty && only.scopeChoices == nil
            && only.durationChoices == nil && only.ssh == nil && only.automation == nil
            && DeliveryReviewCopy.warning(for: only) == nil,
          "a restore-only review offers no scope, duration or delivery warning")
}

/// A phone leg whose readiness the test sets per reference, the way the
/// resolver reports coverage: ready when no listed reference is uncovered.
private actor CountingRemoteReview: RemoteAccessPolicyReviewProvider {
    private(set) var reviews = 0
    private(set) var reviewedKinds: [RemoteApprovalReview.Kind] = []
    private(set) var askedUnlock: [RemoteUnlockUse] = []
    private let uncovered: Set<String>
    private let needsUnlock: Set<String>

    init(uncovered: Set<String> = [], needsUnlock: Set<String> = []) {
        self.uncovered = uncovered
        self.needsUnlock = needsUnlock
    }

    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        let uris = Set((references + restoring).map(\.uri))
        guard uris.isDisjoint(with: uncovered) else { return .unavailable }
        return .ready(unlock: uris.isDisjoint(with: needsUnlock) ? .notNeeded : .required)
    }

    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        reviews += 1
        reviewedKinds.append(review.kind)
        askedUnlock.append(unlock)
        return .unavailable
    }
}

private struct SlowLocalReview: PolicyReviewProvider {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        try? await Task.sleep(nanoseconds: 200_000_000)
        return .denied(.authenticationFailed)
    }
}

private func mirroredRestoreTests() async {
    let caller = CallerInfo(pid: 1, startTime: 1, description: "synthetic phone gate")
    let opReferences = [try! SecretRef("op://Restore/Item/field")]
    let restore = RestoreReviewDetails(
        cause: .restart,
        rows: [RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "d", references: ["op://Restore/Item/field"])],
        storeCount: 1
    )
    let plan = restorePlan("phone")
    let ordinary = AccessPolicyReview(
        caller: caller, reason: "op", plan: plan,
        credentials: [PolicyReviewCredential(references: opReferences)]
    )
    let mixed = AccessPolicyReview(
        caller: caller, reason: "op", plan: plan,
        credentials: [PolicyReviewCredential(references: opReferences)], restore: restore
    )
    let only = AccessPolicyReview.restoreOnly(caller: caller, restore: restore)

    // Covered: a restore reaches the phone exactly like a release, alone or
    // as a section of one.
    let covered = CountingRemoteReview()
    let mirrored = MirroredPolicyReview(local: SlowLocalReview(), remote: covered)
    _ = await mirrored.reviewAccess(ordinary)
    _ = await mirrored.reviewAccess(mixed)
    _ = await mirrored.reviewAccess(only)
    let coveredReviews = await covered.reviews
    let coveredKinds = await covered.reviewedKinds
    check(coveredReviews == 3 && coveredKinds == [.access, .access, .restore],
          "a restore section, alone or on a release, reaches the phone when a phone approval could reopen it "
            + "(\(coveredReviews), \(coveredKinds))")

    // A restore row naming a reference no phone approval could reopen keeps
    // the whole review on the Mac, while an ordinary release still mirrors.
    let uncoveredURI = "vault://restore/uncovered"
    let uncoveredRestore = RestoreReviewDetails(
        cause: .restart,
        rows: [
            RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "d", references: ["op://Restore/Item/field"]),
            RestoreReviewRow(kind: .pairedProject, title: "project", detail: "d", references: [uncoveredURI]),
        ],
        storeCount: 2
    )
    let partial = CountingRemoteReview(uncovered: [uncoveredURI])
    let partialMirror = MirroredPolicyReview(local: SlowLocalReview(), remote: partial)
    _ = await partialMirror.reviewAccess(ordinary)
    _ = await partialMirror.reviewAccess(AccessPolicyReview(
        caller: caller, reason: "op", plan: plan,
        credentials: [PolicyReviewCredential(references: opReferences)], restore: uncoveredRestore
    ))
    _ = await partialMirror.reviewAccess(AccessPolicyReview.restoreOnly(caller: caller, restore: uncoveredRestore))
    let partialReviews = await partial.reviews
    check(partialReviews == 1,
          "a restore whose rows are not all covered stays on the Mac, alone or mixed (\(partialReviews) mirrored)")

    // A restore whose store is still sealed asks the phone for the unlock factor.
    let needing = CountingRemoteReview(needsUnlock: ["op://Restore/Item/field"])
    _ = await MirroredPolicyReview(local: SlowLocalReview(), remote: needing).reviewAccess(only)
    check(await needing.askedUnlock == [.required],
          "a restore that needs an unlock carries the unlock challenge to the phone")
}

// MARK: - Single flight

private func singleFlightTests(_ context: RestoreContext) async {
    let sealed = context.sealed()
    guard let harness = try? await makeRestoreHarness(providers: [sealed], sshKey: context.sshKey) else {
        check(false, "single-flight harness builds")
        return
    }
    let plan = restorePlan("flight")
    await harness.grants.restore([
        restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A", "csec://restore/B"], plan: plan),
        restoredGrant(root: context.other.pid, start: context.other.start, references: ["csec://restore/C"], plan: plan, label: "zsh"),
    ])
    await harness.ssh.restore([restoredSSHGrant(harness, root: context.me, start: context.myStart)])

    let requests = (0..<3).map { _ in ask(harness, ["csec://restore/A", "csec://restore/B"], plan: plan, caller: context.caller) }
    let signatures = (0..<2).map { _ in signTask(harness, caller: context.caller) }
    let allWaiting = await eventuallyTrue {
        let pending = await harness.gate.pendingCount
        let waiting = await harness.restoration.waitingCount
        return pending == 1 && waiting == 5
    }
    check(allWaiting, "three covered secret requests and two SSH signings wait on one restore panel")
    let reviews = await harness.gate.reviews
    let review = reviews.first
    let kinds = review?.restore?.rows.map(\.kind) ?? []
    check(reviews.count == 1 && review?.isRestoreOnly == true && review?.ssh == nil
            && review?.scopeChoices == nil && review?.durationChoices == nil
            && kinds.filter { $0 == .secretGrant }.count == 2 && kinds.filter { $0 == .sshGrant }.count == 1
            && review?.restore?.rows.contains { $0.title == "zsh" } == true
            && review?.restore?.rows.first { $0.kind == .sshGrant }?.ssh?.hostTitle == "restore.example.test"
            && review?.restore?.cause == .restart,
          "the one panel lists every restored grant needing an unlock (another terminal's and the SSH grant too)")

    await harness.gate.decide(.approve)
    var values = 0
    for request in requests where (await settled(request)).values?["csec://restore/A"] == Data("synthetic-restore-a".utf8) {
        values += 1
    }
    var signed = 0
    for signature in signatures {
        if let blob = await settled(signature), !blob.isEmpty { signed += 1 }
    }
    let warmBatches = await sealed.warmBatches
    let contextsSeen = await sealed.contextsSeen
    let contexts = await harness.gate.contexts
    let invalidated = contexts.first?.invalidated
    let usedAfter = await sealed.usedAfterInvalidation
    check(values == 3 && signed == 2, "after approval every waiter proceeds (\(values) releases, \(signed) signatures)")
    // The resolver hands each scheme's references to its provider once; this
    // fixture serves two schemes, so the one batch arrives as two calls.
    check(warmBatches.count == 2
            && Set(warmBatches.flatMap { $0 })
              == ["csec://restore/A", "csec://restore/B", "csec://restore/C", sshKeyReference]
            && contexts.count == 1 && Set(contextsSeen) == [ObjectIdentifier(contexts[0])],
          "one touch's one context warms exactly the listed batch, once")
    check(invalidated == true && !usedAfter,
          "the panel's context is invalidated after the batch, and used for nothing after that")
    let reviewCount = await harness.gate.reviews.count
    let usedUp = await harness.restoration.isUsedUp
    check(reviewCount == 1 && usedUp, "approving uses the restore up")
    let laterTask = ask(harness, ["csec://restore/A"], plan: restorePlan("flight-later"), caller: context.caller)
    _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
    let laterReview = await harness.gate.reviews.last
    await harness.gate.decide(.approve)
    let later = await settled(laterTask)
    check(later.values != nil && laterReview?.restore == nil && laterReview?.credentials.isEmpty == false,
          "a later request for new references gets an ordinary panel, not the restore")
}

// MARK: - Forget

private func forgetTests(_ context: RestoreContext) async {
    let sealed = context.sealed()
    guard let harness = try? await makeRestoreHarness(providers: [sealed], sshKey: context.sshKey) else {
        check(false, "forget harness builds")
        return
    }
    let plan = restorePlan("forget")
    let mine = restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan)
    let theirs = restoredGrant(root: context.other.pid, start: context.other.start, references: ["csec://restore/C"], plan: plan)
    await harness.grants.restore([mine, theirs])
    await harness.persistence.settle()
    let first = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
    let second = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await harness.restoration.waitingCount == 2 }
    await harness.gate.decide(.deny(.human(decidedAt: .now, on: .mac)))
    let firstResponse = await settled(first)
    let secondResponse = await settled(second)
    let stored = await storedGrantsDocument(harness.backend)
    check(firstResponse.failure?.code == .consentDenied && secondResponse.failure?.code == .consentDenied,
          "Forget these approvals refuses every waiter")
    check(stored?.secret.isEmpty == true,
          "the forgotten grants are dropped, and the removal is persisted before anyone is answered")
    let listed = await harness.grants.summaries(now: Date())
    let usedUp = await harness.restoration.isUsedUp
    check(listed.isEmpty && usedUp, "the listed grants are forgotten and the restore is used up")
    let again = await harness.restoration.ensureWarm(
        for: [try! SecretRef("csec://restore/A")], requester: context.caller
    )
    check(again == .usedUp, "the restore never returns in this daemon lifetime")
    let later = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
    let laterReview = await harness.gate.reviews.last
    await harness.gate.decide(.approve)
    check(await settled(later).values != nil && laterReview?.restore == nil && laterReview?.credentials.isEmpty == false,
          "after forgetting, the same request gets an ordinary panel")
}

// MARK: - Approval: used up, and a grant that could not be reopened

private func approvalUsedUpTests(_ context: RestoreContext) async {
    let reopening = context.sealed()
    let failing = SealedFixtureProvider(
        schemes: ["stuck"], values: ["stuck://restore/S": Data("synthetic-stuck".utf8)], opensOnWarm: false
    )
    guard let harness = try? await makeRestoreHarness(providers: [reopening, failing], sshKey: context.sshKey) else {
        check(false, "used-up harness builds")
        return
    }
    let plan = restorePlan("usedup")
    let good = restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan)
    let stuck = restoredGrant(root: context.me, start: context.myStart, references: ["stuck://restore/S"], plan: plan)
    await harness.grants.restore([good, stuck])
    let request = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
    await harness.gate.decide(.approve)
    let response = await settled(request)
    let remaining = await harness.grants.summaries(now: Date()).map(\.id)
    check(response.values != nil && remaining == [good.id.uuidString.lowercased()],
          "a restored grant the touch could not reopen is dropped; the others proceed")
    let stuckRequest = ask(harness, ["stuck://restore/S"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
    let stuckReview = await harness.gate.reviews.last
    await harness.gate.decide(.approve)
    _ = await settled(stuckRequest)
    check(stuckReview?.restore == nil && stuckReview?.isRestoreOnly == false,
          "the dropped grant's next request gets an ordinary panel, never a second restore")
}

// MARK: - Requester gone

private func requesterGoneTests(_ context: RestoreContext) async {
    let sealed = context.sealed()
    guard let harness = try? await makeRestoreHarness(providers: [sealed], sshKey: context.sshKey) else {
        check(false, "requester-gone harness builds")
        return
    }
    let plan = restorePlan("gone")
    await harness.grants.restore([
        restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan),
    ])
    let alone = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
    alone.cancel()
    let gone = await settled(alone)
    _ = await eventuallyTrue { await harness.gate.cancelled == 1 }
    let usedUp = await harness.restoration.isUsedUp
    let stillRestored = await harness.grants.summaries(now: Date()).filter { $0.restored == true }.count
    check(gone.values == nil && !usedUp && stillRestored == 1,
          "every waiter leaving closes the panel without using the restore up or dropping anything")

    // With two waiting, one leaving keeps the panel up.
    let leaving = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
    let staying = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue {
        let pending = await harness.gate.pendingCount
        let waiting = await harness.restoration.waitingCount
        return pending == 1 && waiting == 2
    }
    let reviewsBefore = await harness.gate.reviews.count
    leaving.cancel()
    _ = await settled(leaving)
    try? await Task.sleep(nanoseconds: 200_000_000)
    let cancelledAfter = await harness.gate.cancelled
    let pendingAfter = await harness.gate.pendingCount
    check(reviewsBefore == 2 && cancelledAfter == 1 && pendingAfter == 1,
          "a later covered request raises the restore again, and one waiter leaving keeps it up")
    await harness.gate.decide(.approve)
    check(await settled(staying).values != nil, "the remaining waiter proceeds after approval")
}

// MARK: - Re-present after the shown requester went away

private actor StubRestoreSource: RestoredGrantSource {
    let entry: RestoreEntry
    private(set) var settled: [Set<UUID>] = []

    init(entry: RestoreEntry) { self.entry = entry }

    func restoreEntries() async -> [RestoreEntry] { settled.isEmpty ? [entry] : [] }
    func settleRestore(forgetting: Set<UUID>) async -> Int {
        settled.append(forgetting)
        return forgetting.count
    }
}

private func representTests(_ context: RestoreContext) async {
    let sealed = context.sealed()
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(sealed)
    let gate = RestoreReviewGate()
    let restoration = GrantRestoration(
        resolver: resolver, policyReview: gate, consent: SilentApprovingConsent(),
        terminalInspection: .unavailable
    )
    let reference = try! SecretRef("csec://restore/A")
    await restoration.addGrantSource(StubRestoreSource(entry: RestoreEntry(
        grantID: UUID(),
        row: RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "d", references: [reference.uri]),
        references: [reference]
    )))
    let child = Process()
    child.executableURL = URL(fileURLWithPath: "/bin/sleep")
    child.arguments = ["30"]
    // Awaited, never waitUntilExit(): after the awaits below this task may be
    // on another thread, where that wait can miss the exit and never return.
    let childExit = ChildProcessExit(child)
    guard (try? child.run()) != nil,
          let childStart = ProcessAncestry.startTime(of: child.processIdentifier) else {
        check(false, "the short-lived requester starts")
        return
    }
    let childCaller = CallerInfo(pid: child.processIdentifier, startTime: childStart, description: "short-lived")
    let first = Task { await restoration.ensureWarm(for: [reference], requester: childCaller) }
    _ = await eventuallyTrue { await gate.pendingCount == 1 }
    let second = Task { await restoration.ensureWarm(for: [reference], requester: context.caller) }
    _ = await eventuallyTrue { await restoration.waitingCount == 2 }
    let shownFirst = await gate.reviews.first?.caller.pid
    child.terminate()
    check(await childExit.wait(within: 10), "the short-lived requester exits when terminated")
    // What the unlock re-present does when the requester it shows has exited.
    await gate.decide(.deny(.requesterGone))
    let firstResult = await settled(first)
    _ = await eventuallyTrue { await gate.pendingCount == 1 }
    let reviews = await gate.reviews
    let usedUpBetween = await restoration.isUsedUp
    check(shownFirst == child.processIdentifier && firstResult == .requesterGone
            && reviews.count == 2 && reviews.last?.caller.pid == context.me && !usedUpBetween,
          "a panel closed because its shown requester went away is raised again for the waiters still running")
    await gate.decide(.approve)
    check(await settled(second) == .warmed, "the re-presented panel's approval reopens for the remaining waiter")
}

// MARK: - The mixed panel

private func orphanedSharedRestoreTests(_ context: RestoreContext) async {
    let sealed = context.sealed(), resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(sealed)
    let gate = RestoreReviewGate()
    let restoration = GrantRestoration(
        resolver: resolver, policyReview: QueuedPolicyReview(underlying: gate, queue: ConsentQueue()),
        consent: SilentApprovingConsent(), terminalInspection: .unavailable
    )
    let reference = try! SecretRef("csec://restore/A")
    await restoration.addGrantSource(StubRestoreSource(entry: RestoreEntry(
        grantID: UUID(),
        row: RestoreReviewRow(kind: .secretGrant, title: "fixture", detail: "shared restore", references: [reference.uri]),
        references: [reference]
    )))
    let firstPID: pid_t = 95_101, secondPID: pid_t = 95_102
    let firstParent: pid_t = 95_111, secondParent: pid_t = 95_112
    let tree = AnchorFixtureTree(
        starts: [firstPID: 951, secondPID: 952, firstParent: 961, secondParent: 962],
        parents: [firstPID: firstParent, firstParent: 1, secondPID: secondParent, secondParent: 1], terminal: 0
    )
    let firstCaller = CallerInfo(pid: firstPID, startTime: 951, description: "first restore caller")
        .anchored(using: tree.inspection)
    let secondCaller = CallerInfo(pid: secondPID, startTime: 952, description: "surviving restore caller")
        .anchored(using: tree.inspection)
    let wait = HumanWait(
        requester: .init(pid: firstPID, startTime: 951), summary: "shared restore fixture", limit: nil,
        requestAnchor: firstCaller.requestAnchor, processInspection: tree.inspection,
        requesterPollInterval: .milliseconds(10)
    )
    let first = Task {
        await wait.bounding { await restoration.ensureWarm(for: [reference], requester: firstCaller) }
    }
    _ = await eventuallyTrue { await gate.pendingCount == 1 }
    let second = Task { await restoration.ensureWarm(for: [reference], requester: secondCaller) }
    _ = await eventuallyTrue { await restoration.waitingCount == 2 }
    tree.reparent(firstPID)
    let firstResult = await settled(first)
    let represented = await eventuallyTrue {
        let reviews = await gate.reviews, pending = await gate.pendingCount
        return reviews.count == 2 && reviews.last?.caller.pid == secondPID && pending == 1
    }
    let cancelled = await gate.cancelled, usedUp = await restoration.isUsedUp
    check(represented && firstResult == .requesterGone && cancelled == 1 && !usedUp,
          "an orphaned shared restore's displayed caller is withdrawn and replaced by its surviving waiter")
    await gate.decideAll(.approve)
    check(await settled(second) == .warmed,
          "the surviving shared-restore caller proceeds after its own panel is approved")
    check(await sealed.warmBatches.count == 1,
          "the orphaned shared restore opens nothing before the surviving caller's approval")
}

private func mixedPanelTests(_ context: RestoreContext) async {
    let sealed = context.sealed()
    guard let harness = try? await makeRestoreHarness(providers: [sealed], sshKey: context.sshKey) else {
        check(false, "mixed harness builds")
        return
    }
    let plan = restorePlan("mixed")
    await harness.grants.restore([
        restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan),
        restoredGrant(root: context.other.pid, start: context.other.start, references: ["csec://restore/C"], plan: plan, label: "zsh"),
    ])
    let mixed = ask(harness, ["csec://restore/A", "csec://restore/N"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
    let covered = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
    let joined = await eventuallyTrue { await harness.restoration.waitingCount == 1 }
    let reviews = await harness.gate.reviews
    let review = reviews.first
    check(joined && reviews.count == 1 && review?.restore != nil && review?.isRestoreOnly == false
            && review?.credentials.flatMap(\.references).map(\.uri).contains("csec://restore/N") == true
            && review?.durationChoices != nil
            && review?.restore?.rows.count == 2,
          "new references plus restore-cold ones get one panel: the release section and the restore section")
    await harness.gate.decide(.approve)
    let mixedResponse = await settled(mixed)
    let coveredResponse = await settled(covered)
    let contexts = await harness.gate.contexts
    let seen = await sealed.contextsSeen
    let warmBatches = await sealed.warmBatches
    let usedAfter = await sealed.usedAfterInvalidation
    check(mixedResponse.values?["csec://restore/N"] == Data("synthetic-restore-new".utf8)
            && mixedResponse.values?["csec://restore/A"] == Data("synthetic-restore-a".utf8)
            && coveredResponse.values != nil && contexts.count == 1,
          "approving the mixed panel releases the new references and the covered waiter proceeds")
    check(warmBatches.count == 1 && Set(warmBatches.first ?? []) == ["csec://restore/A", "csec://restore/C"]
            && Set(seen) == [ObjectIdentifier(contexts[0])] && !usedAfter
            && contexts[0].invalidated,
          "one context warms the restore batch and the new references' stores, then is invalidated")
    let minted = await harness.grants.summaries(now: Date()).filter { $0.restored != true }
    let usedUp = await harness.restoration.isUsedUp
    check(minted.contains { $0.references.contains("csec://restore/N") } && usedUp,
          "the mixed approval mints the new grant and uses the restore up")
}

private func mixedDenyTests(_ context: RestoreContext) async {
    let sealed = context.sealed()
    guard let harness = try? await makeRestoreHarness(providers: [sealed], sshKey: context.sshKey) else {
        check(false, "mixed-deny harness builds")
        return
    }
    let plan = restorePlan("mixed-deny")
    await harness.grants.restore([
        restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan),
        restoredGrant(root: context.other.pid, start: context.other.start, references: ["csec://restore/C"], plan: plan),
    ])
    let mixed = ask(harness, ["csec://restore/A", "csec://restore/N"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
    let covered = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await harness.restoration.waitingCount == 1 }
    await harness.gate.decide(.deny(.human(decidedAt: .now, on: .mac)))
    let mixedResponse = await settled(mixed)
    let coveredResponse = await settled(covered)
    let remaining = await harness.grants.summaries(now: Date())
    let usedUp = await harness.restoration.isUsedUp
    let opened = await sealed.isOpen
    check(mixedResponse.failure?.code == .consentDenied && coveredResponse.failure?.code == .consentDenied
            && remaining.isEmpty && usedUp && !opened,
          "the mixed panel's one Deny refuses the new references and forgets the restore section")

    // A mixed panel whose requester goes away leaves the restore to the
    // covered request still waiting on it.
    let sealedAgain = context.sealed()
    guard let second = try? await makeRestoreHarness(providers: [sealedAgain], sshKey: context.sshKey) else {
        check(false, "mixed-gone harness builds")
        return
    }
    await second.grants.restore([
        restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan),
    ])
    let leaving = ask(second, ["csec://restore/A", "csec://restore/N"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await second.gate.pendingCount == 1 }
    let waiter = ask(second, ["csec://restore/A"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await second.restoration.waitingCount == 1 }
    leaving.cancel()
    _ = await settled(leaving)
    let raised = await eventuallyTrue {
        let reviews = await second.gate.reviews
        let pending = await second.gate.pendingCount
        return reviews.count == 2 && pending == 1
    }
    let restoreOnly = await second.gate.reviews.last?.isRestoreOnly
    check(raised && restoreOnly == true,
          "when a mixed panel's requester goes away, the covered waiter gets a restore-only panel")
    await second.gate.decide(.approve)
    check(await settled(waiter).values != nil, "that waiter proceeds after the restore-only approval")
}

// MARK: - op:// only

private func opOnlyTests(_ context: RestoreContext) async {
    let onePassword = OpenFixtureProvider(
        schemes: ["op"], values: ["op://Restore/Item/field": Data("synthetic-op".utf8)]
    )
    guard let harness = try? await makeRestoreHarness(
        providers: [context.sealed(), onePassword], sshKey: context.sshKey
    ) else {
        check(false, "op-only harness builds")
        return
    }
    let plan = restorePlan("oponly")
    await harness.grants.restore([
        restoredGrant(root: context.me, start: context.myStart, references: ["op://Restore/Item/field"], plan: plan),
    ])
    let response = await settled(ask(harness, ["op://Restore/Item/field"], plan: plan, caller: context.caller))
    let reviews = await harness.gate.reviews.count
    let resolves = await onePassword.resolves
    let usedUp = await harness.restoration.isUsedUp
    check(response.values?["op://Restore/Item/field"] == Data("synthetic-op".utf8)
            && reviews == 0 && resolves == 1 && !usedUp,
          "an op://-only restored grant resolves through its provider with no panel")
}

// MARK: - Backend neutrality

private func backendNeutralityTests(_ context: RestoreContext) async {
    let unlock = CacheUnlock(LAContext())
    let documentKeys = InMemoryNativeStoreKeyBackend(), documentFiles = InMemoryNativeStoreFileBackend()
    let blobKeys = InMemoryNativeStoreKeyBackend(), blobFiles = InMemoryNativeStoreFileBackend()
    do {
        let seeding = NativeEncryptedFileProvider(
            keyBackend: documentKeys, fileBackend: documentFiles,
            blobStore: NativeBlobStore(keyBackend: blobKeys, fileBackend: blobFiles)
        )
        let edit = try await seeding.beginEdit(
            store: try NativeStoreName("neutral"), callerPID: 4_001, callerStartTime: 9, unlock: unlock
        )
        _ = try await seeding.commitEdit(
            sessionID: edit.sessionID, document: Data(#"{"TOKEN":"synthetic-neutral-doc"}"#.utf8),
            callerPID: 4_001, callerStartTime: 9
        )
        _ = try await NativeBlobStore(keyBackend: blobKeys, fileBackend: blobFiles).putBlobs(
            store: try NativeStoreName("neutralblob"),
            requests: [.init(key: "envrc", data: Data("synthetic-neutral-blob".utf8), mode: 0o600, path: ".envrc")],
            unlock: unlock
        )
    } catch {
        check(false, "the native neutrality fixture is seeded (\(error))")
        return
    }
    // A restarted csecd: the native provider is cold.
    let native = NativeEncryptedFileProvider(
        keyBackend: documentKeys, fileBackend: documentFiles,
        blobStore: NativeBlobStore(keyBackend: blobKeys, fileBackend: blobFiles)
    )
    let onePassword = OpenFixtureProvider(
        schemes: ["op"], values: ["op://Neutral/Item/field": Data("synthetic-neutral-op".utf8)]
    )
    let vault = SealedFixtureProvider(
        schemes: ["vault"],
        values: ["vault://neutral/key": Data("synthetic-neutral-vault".utf8), sshKeyReference: context.sshKey.privateKeyPEM]
    )
    guard let harness = try? await makeRestoreHarness(
        providers: [native, onePassword, vault], sshKey: context.sshKey
    ) else {
        check(false, "neutrality harness builds")
        return
    }
    let plan = restorePlan("neutral")
    let references = [
        "csec://neutral/TOKEN", "csec://neutralblob/envrc", "op://Neutral/Item/field", "vault://neutral/key",
    ]
    await harness.grants.restore([
        restoredGrant(root: context.me, start: context.myStart, references: Set(references), plan: plan),
    ])
    let request = ask(harness, references, plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
    let review = await harness.gate.reviews.first
    await harness.gate.decide(.approve)
    let response = await settled(request)
    check(review?.isRestoreOnly == true && review?.restore?.storeCount == 3
            && response.values?["csec://neutral/TOKEN"] == Data("synthetic-neutral-doc".utf8)
            && response.values?["csec://neutralblob/envrc"] == Data("synthetic-neutral-blob".utf8)
            && response.values?["op://Neutral/Item/field"] == Data("synthetic-neutral-op".utf8)
            && response.values?["vault://neutral/key"] == Data("synthetic-neutral-vault".utf8),
          "one restore reopens native document and blob stores and a third scheme, and op:// resolves as usual")
    let reviews = await harness.gate.reviews.count
    check(reviews == 1, "backends of three schemes need one restore panel between them")
}

// MARK: - Decision log

private func restoreRecordTests(_ context: RestoreContext) async {
    let sealed = context.sealed()
    guard let harness = try? await makeRestoreHarness(providers: [sealed], sshKey: context.sshKey, withLog: true),
          let log = harness.log else {
        check(false, "decision-log harness builds")
        return
    }
    let plan = restorePlan("logged")
    let grant = restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan)
    await harness.grants.restore([grant])
    let request = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
    await harness.gate.decide(.approve)
    _ = await settled(request)
    _ = await settled(ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller))
    await log.flushUsageCheckpoint()
    let restores = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.restore])).records
    let record = restores.first
    check(restores.count == 1 && record?.surface == .restore && record?.cause == "restart_restore"
            && record?.outcome == .approved && record?.decider == .humanLocal && record?.ttdMs == 1_500
            && record?.grantIDs == [grant.id.uuidString.lowercased()]
            && record?.grants?.secret == 1 && record?.detail?.contains("csecd restarted (restart)") == true,
          "the restore is logged with its outcome, decider, grants and cause")
    let reuses = await log.read(DecisionLogQuery(streams: [.usage], kinds: [.reuse])).records
    check(reuses.count == 2 && reuses.allSatisfy { $0.decider == .restoredGrant },
          "a release covered by a restored grant is recorded as the restored grant's")

    let lifecycleStores = ProtectedStores.processLocal()
    let lifecycleLog = DecisionLog(
        directory: SealedRecordDirectory(path: (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("csec-restart-counts-\(UUID().uuidString)")),
        stores: lifecycleStores
    )
    _ = await lifecycleLog.open()
    let counts = DecisionLogRecord.GrantCounts(secret: 2, ssh: 1, dropped: ["expired": 1, "root_exited": 3])
    _ = await CsecdLifecycle(stores: lifecycleStores, log: lifecycleLog).start(grantCounts: counts)
    let restart = await lifecycleLog.read(DecisionLogQuery(streams: [.decisions], kinds: [.restart])).records.first
    check(restart?.grants == counts, "the restart record carries what the grants item restored and dropped")
}

// MARK: - A wait on the restore is checked again at the present (review F1)

private func staleWaitTests(_ context: RestoreContext) async {
    // A restored grant whose chosen lifetime ends while the restore panel is
    // up: approving the restore must not release under it.
    do {
        guard let harness = try? await makeRestoreHarness(providers: [context.sealed()], sshKey: context.sshKey) else {
            check(false, "stale-wait harness builds")
            return
        }
        let plan = restorePlan("stale")
        await harness.grants.restore([Grant(
            rootPID: context.me, rootStartTime: context.myStart, references: ["csec://restore/A"],
            reason: "expires during the wait", expiresAt: Date().addingTimeInterval(1.5),
            deliveryPlanDigest: try? plan.digest(), rootProcessLabel: "fish",
            restored: true, warm: false
        )])
        let request = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let first = await harness.gate.reviews.first
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        await harness.gate.decide(.approve)
        let raised = await eventuallyTrue {
            let reviews = await harness.gate.reviews.count
            let pending = await harness.gate.pendingCount
            return reviews == 2 && pending == 1
        }
        let second = await harness.gate.reviews.last
        await harness.gate.decide(.approve)
        let response = await settled(request)
        check(first?.isRestoreOnly == true && raised && second?.isRestoreOnly == false
                && second?.credentials.flatMap(\.references).map(\.uri) == ["csec://restore/A"]
                && response.values != nil,
              "a restored grant that expired while the restore panel waited gets an ordinary panel, not a release")
    }

    // The same for an SSH signing grant.
    do {
        guard let harness = try? await makeRestoreHarness(providers: [context.sealed()], sshKey: context.sshKey) else {
            check(false, "stale-wait SSH harness builds")
            return
        }
        await harness.ssh.restore([persistedSSHGrant(
            root: context.me, start: context.myStart,
            fingerprint: sshFingerprint(harness.sshKey.publicKeyBlob),
            hostKeyFingerprint: harness.binding.hostKeyFingerprint, remoteUser: "deploy",
            expiresAt: Date().addingTimeInterval(1.5)
        )])
        let signature = signTask(harness, caller: context.caller)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let first = await harness.gate.reviews.first
        try? await Task.sleep(nanoseconds: 2_000_000_000)
        await harness.gate.decide(.approve)
        let raised = await eventuallyTrue {
            let reviews = await harness.gate.reviews.count
            let pending = await harness.gate.pendingCount
            return reviews == 2 && pending == 1
        }
        let second = await harness.gate.reviews.last
        await harness.gate.decide(.approve)
        let signed = await settled(signature)
        check(first?.isRestoreOnly == true && raised && second?.ssh != nil && signed != nil,
              "a restored SSH grant that expired while the restore panel waited gets an ordinary SSH panel")
    }

    // A restored grant revoked while the restore panel is up.
    do {
        guard let harness = try? await makeRestoreHarness(providers: [context.sealed()], sshKey: context.sshKey) else {
            check(false, "revoked-wait harness builds")
            return
        }
        let plan = restorePlan("revokedwait")
        await harness.grants.restore([
            restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan),
        ])
        let request = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let revoked = await harness.agent.handleGrants(
            request: GrantsRequest(action: .revoke, all: true), caller: context.caller
        )
        await harness.gate.decide(.approve)
        let raised = await eventuallyTrue {
            let reviews = await harness.gate.reviews.count
            let pending = await harness.gate.pendingCount
            return reviews == 2 && pending == 1
        }
        let second = await harness.gate.reviews.last
        await harness.gate.decide(.approve)
        let response = await settled(request)
        check(revoked.revokedGrantCount == 1 && raised && second?.isRestoreOnly == false
                && response.values != nil,
              "a restored grant revoked while the restore panel waited gets an ordinary panel, not a release")
    }
}

// MARK: - Requests that join after the decision came back (review F4)

/// A grant source whose restore settlement the test holds open.
private actor HeldRestoreSource: RestoredGrantSource {
    let entry: RestoreEntry
    private var settled = false
    private var waiting: CheckedContinuation<Void, Never>?
    private(set) var settling = false

    init(entry: RestoreEntry) { self.entry = entry }

    func restoreEntries() async -> [RestoreEntry] { settled ? [] : [entry] }

    func settleRestore(forgetting: Set<UUID>) async -> Int {
        settling = true
        await withCheckedContinuation { waiting = $0 }
        settled = true
        return forgetting.count
    }

    func release() {
        waiting?.resume()
        waiting = nil
    }
}

/// A reviewer the test answers with any outcome.
private actor ScriptedRestoreReviewer: PolicyReviewProvider {
    private var held: CheckedContinuation<AccessPolicyReviewOutcome, Never>?
    private(set) var reviews = 0

    var isHolding: Bool { held != nil }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews += 1
        return await withCheckedContinuation { held = $0 }
    }

    func answer(_ outcome: AccessPolicyReviewOutcome) {
        held?.resume(returning: outcome)
        held = nil
    }
}

/// An approval whose completion the test holds, then fails.
private actor HeldFailingSession: AccessPolicyAuthenticationSession {
    private var waiting: CheckedContinuation<Void, Never>?
    private(set) var started = false

    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        started = true
        await withCheckedContinuation { waiting = $0 }
        return .denied
    }

    func cancel() async {}

    func release() {
        waiting?.resume()
        waiting = nil
    }
}

private func latecomerTests(_ context: RestoreContext) async {
    let reference = try! SecretRef("csec://restore/A")
    func entry() -> RestoreEntry {
        RestoreEntry(
            grantID: UUID(),
            row: RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "d", references: [reference.uri]),
            references: [reference]
        )
    }

    // Forget: the waiter the human answered is refused; one that joined while
    // the forget was being persisted is told the restore is over.
    do {
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(context.sealed())
        let gate = RestoreReviewGate()
        let restoration = GrantRestoration(
            resolver: resolver, policyReview: gate, consent: SilentApprovingConsent(),
            terminalInspection: .unavailable
        )
        let source = HeldRestoreSource(entry: entry())
        await restoration.addGrantSource(source)
        let first = Task { await restoration.ensureWarm(for: [reference], requester: context.caller) }
        _ = await eventuallyTrue { await gate.pendingCount == 1 }
        await gate.decide(.deny(.human(decidedAt: .now, on: .mac)))
        _ = await eventuallyTrue { await source.settling }
        let late = Task { await restoration.ensureWarm(for: [reference], requester: context.caller) }
        let joined = await eventuallyTrue { await restoration.waitingCount == 2 }
        await source.release()
        let firstResult = await settled(first)
        let lateResult = await settled(late)
        check(joined && firstResult == .forgotten && lateResult == .usedUp,
              "Forget refuses the requests it answered; one that joined afterwards is told the restore is over (\(firstResult), \(lateResult))")
    }

    // A Touch ID failure: the waiter that saw the panel is refused; one that
    // joined while the approval was being completed gets the panel again.
    do {
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(context.sealed())
        let reviewer = ScriptedRestoreReviewer()
        let restoration = GrantRestoration(
            resolver: resolver, policyReview: reviewer, consent: SilentApprovingConsent(),
            terminalInspection: .unavailable
        )
        await restoration.addGrantSource(StubRestoreSource(entry: entry()))
        let failing = HeldFailingSession()
        let first = Task { await restoration.ensureWarm(for: [reference], requester: context.caller) }
        _ = await eventuallyTrue { await reviewer.isHolding }
        await reviewer.answer(.approved(AccessPolicyApproval(authenticationSession: failing)))
        _ = await eventuallyTrue { await failing.started }
        let late = Task { await restoration.ensureWarm(for: [reference], requester: context.caller) }
        let joined = await eventuallyTrue { await restoration.waitingCount == 2 }
        await failing.release()
        let firstResult = await settled(first)
        let represented = await eventuallyTrue {
            let reviews = await reviewer.reviews
            let holding = await reviewer.isHolding
            return reviews == 2 && holding
        }
        await reviewer.answer(.approved(AccessPolicyApproval(
            authenticationSession: RestoreFixtureSession(context: RecordingContext())
        )))
        let lateResult = await settled(late)
        check(joined && firstResult == .failed && represented && lateResult == .warmed,
              "after a failed restore panel, a request that joined late gets the panel again (\(firstResult), \(lateResult))")
    }
}

// MARK: - Forget ends a waiting SSH connection's signing (review F5)

private func sshForgetEndsConnectionTests(_ context: RestoreContext) async {
    guard let secondKey = try? Ed25519SSHFixture(seed: 163),
          let harness = try? await makeRestoreHarness(
              providers: [context.sealed()], sshKey: context.sshKey, secondSSHKey: secondKey
          ) else {
        check(false, "forget-SSH harness builds")
        return
    }
    await harness.ssh.restore([restoredSSHGrant(harness, root: context.me, start: context.myStart)])
    let waiting = signTask(harness, caller: context.caller)
    _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
    await harness.gate.decide(.deny(.human(decidedAt: .now, on: .mac)))
    let refused = await settled(waiting)
    // The same `ssh` offers its next catalog key: no panel for it.
    let nextKey = await settled(signTask(harness, caller: context.caller, key: secondKey))
    try? await Task.sleep(nanoseconds: 200_000_000)
    let reviewsAfterNextKey = await harness.gate.reviews.count
    // Another connection still gets its own panel.
    let otherCaller = CallerInfo(
        pid: context.other.pid, startTime: context.other.start, description: "another ssh"
    )
    let other = signTask(harness, caller: otherCaller, key: secondKey)
    let otherPanel = await eventuallyTrue { await harness.gate.pendingCount == 1 }
    await harness.gate.decide(.deny(.authenticationFailed))
    _ = await settled(other)
    check(refused == nil && nextKey == nil && reviewsAfterNextKey == 1 && otherPanel,
          "Forget ends a waiting SSH connection's signing: its next key raises no panel; another connection's does")
}

// MARK: - A Touch ID error refuses only the request it was shown for (review R1)

private func authenticationFailureTests(_ context: RestoreContext) async {
    let reference = try! SecretRef("csec://restore/A")

    // Two waiters from the start: the panel is shown for the first and ends
    // with a Touch ID error. Only the first is refused; the restore is not
    // used up, and the second gets a fresh presentation.
    do {
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(context.sealed())
        let gate = RestoreReviewGate()
        let restoration = GrantRestoration(
            resolver: resolver, policyReview: gate, consent: SilentApprovingConsent(),
            terminalInspection: .unavailable
        )
        let source = StubRestoreSource(entry: RestoreEntry(
            grantID: UUID(),
            row: RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "d", references: [reference.uri]),
            references: [reference]
        ))
        await restoration.addGrantSource(source)
        let first = Task { await restoration.ensureWarm(for: [reference], requester: context.caller) }
        _ = await eventuallyTrue { await gate.pendingCount == 1 }
        let second = Task { await restoration.ensureWarm(for: [reference], requester: context.caller) }
        let bothWaiting = await eventuallyTrue { await restoration.waitingCount == 2 }
        await gate.decide(.deny(.authenticationFailed))
        let firstResult = await settled(first)
        let represented = await eventuallyTrue {
            let reviews = await gate.reviews.count
            let pending = await gate.pendingCount
            return reviews == 2 && pending == 1
        }
        let usedUpBetween = await restoration.isUsedUp
        await gate.decide(.approve)
        let secondResult = await settled(second)
        let dropped = await source.settled
        check(bothWaiting && firstResult == .failed && represented && !usedUpBetween
                && secondResult == .warmed && dropped == [[]],
              "a Touch ID error refuses only the request its panel was shown for; the other waiter gets a fresh panel (\(firstResult), \(secondResult))")
    }

    // A mixed panel ending with a Touch ID error: its requester is refused,
    // and a covered request waiting on its restore section gets a
    // restore-only panel instead of being refused.
    do {
        let sealed = context.sealed()
        guard let harness = try? await makeRestoreHarness(providers: [sealed], sshKey: context.sshKey) else {
            check(false, "mixed auth-failure harness builds")
            return
        }
        let plan = restorePlan("mixed-authfail")
        await harness.grants.restore([
            restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan),
        ])
        let mixed = ask(harness, ["csec://restore/A", "csec://restore/N"], plan: plan, caller: context.caller)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let covered = ask(harness, ["csec://restore/A"], plan: plan, caller: context.caller)
        _ = await eventuallyTrue { await harness.restoration.waitingCount == 1 }
        await harness.gate.decide(.deny(.authenticationFailed))
        let mixedResponse = await settled(mixed)
        let represented = await eventuallyTrue {
            let reviews = await harness.gate.reviews.count
            let pending = await harness.gate.pendingCount
            return reviews == 2 && pending == 1
        }
        let restoreOnly = await harness.gate.reviews.last?.isRestoreOnly
        let usedUpBetween = await harness.restoration.isUsedUp
        let kept = await harness.grants.summaries(now: Date()).count
        await harness.gate.decide(.approve)
        let coveredResponse = await settled(covered)
        check(mixedResponse.failure?.code == .consentDenied && represented && restoreOnly == true
                && !usedUpBetween && kept == 1 && coveredResponse.values != nil,
              "a mixed panel's Touch ID error refuses its requester; the covered waiter gets a restore-only panel")
    }
}

// MARK: - Fetched ahead after an approval at the Mac

/// Serves `op://` with no csec unlock, as 1Password does over its own session,
/// and refuses while told to, as 1Password does when nobody answers its own
/// authorization. Its values may be kept, so a fetched one is held.
private actor AuthorizingFixtureProvider: SecretProvider {
    nonisolated let schemes: Set<String> = ["op"]
    private var refusing: Bool
    private(set) var resolved: [String] = []

    init(refusing: Bool = false) { self.refusing = refusing }

    func refuse(_ value: Bool) { refusing = value }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        resolved.append(ref.uri)
        if refusing { throw ProviderError.notAuthenticated }
        return ResolvedSecret(value: Data("synthetic-\(ref.path)".utf8), cacheHint: .cacheable)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

/// Paired references a later request will want, as `DelegationRestoreSource`
/// names them, and no panel rows.
private struct PairedReferencesSource: RestoreItemSource {
    let references: [String]

    func restoreItems() async -> [RestoreEntry] { [] }
    func restoreFinished(_ outcome: RestoreItemOutcome) async {}
    func fetchAheadReferences() async -> [SecretRef] { references.compactMap { try? SecretRef($0) } }
}

/// csec-0.64.13: only the install's `csec restore` fetched paired values
/// ahead. After the 5 Nov reboot, the restore panel a request raised was
/// approved at the Mac, nothing was fetched ahead, and unattended releases of
/// two paired 1Password values declined not held all night (91 panels). And
/// an install whose fetch ahead 1Password did not answer was never retried.
/// Now every panel approved at this Mac (the restore panel, an ordinary
/// release panel, an SSH signing panel) fetches ahead while that person is
/// there; a phone approval never does, as nobody need be at the Mac.
private func fetchAheadAfterMacApprovalTests(_ context: RestoreContext) async {
    let paired = ["op://Paired/Alpha/credential", "op://Paired/Beta/credential"]
    let plan = restorePlan("fetch-ahead")

    func harness(
        _ onePassword: AuthorizingFixtureProvider, label: String
    ) async -> (RestoreHarness, SealedFixtureProvider)? {
        let sealed = context.sealed()
        guard let built = try? await makeRestoreHarness(
            providers: [sealed, onePassword], sshKey: context.sshKey, withLog: true,
            cache: KeychainSecretCache(backend: FakeKeychainBackend()),
            itemSources: [PairedReferencesSource(references: paired)]
        ) else {
            check(false, "fetch ahead [\(label)]: harness builds")
            return nil
        }
        return (built, sealed)
    }

    func held(_ harness: RestoreHarness) async -> Int {
        var count = 0
        for uri in paired {
            guard let ref = try? SecretRef(uri) else { continue }
            if await harness.resolver.resolveWithoutInteraction(ref) != nil { count += 1 }
        }
        return count
    }

    func fetchRecords(_ harness: RestoreHarness) async -> [DecisionLogRecord] {
        await harness.log?.read(DecisionLogQuery(streams: [.decisions], kinds: [.fetchAhead])).records ?? []
    }

    // The reboot: a covered request raises the restore panel, and it is
    // approved at the Mac.
    let rebootProvider = AuthorizingFixtureProvider()
    guard let (reboot, _) = await harness(rebootProvider, label: "reboot") else { return }
    await reboot.grants.restore([
        restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan),
    ])
    let covered = ask(reboot, ["csec://restore/A"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await reboot.gate.pendingCount == 1 }
    let restoreReview = await reboot.gate.reviews.first
    await reboot.gate.decide(.approve)
    let coveredReply = await settled(covered)
    await reboot.restoration.fetchAheadSettled()
    let rebootHeld = await held(reboot)
    let rebootRecords = await fetchRecords(reboot)
    let rebootResolved = await rebootProvider.resolved
    check(restoreReview?.isRestoreOnly == true && coveredReply.values?["csec://restore/A"] != nil
            && rebootHeld == 2 && Set(rebootResolved) == Set(paired),
          "fetch ahead: a restore panel a request raised, approved at the Mac, fetches every paired value ahead")
    check(rebootRecords.count == 1
            && rebootRecords.first?.detail?.contains("after an approval at this Mac") == true
            && rebootRecords.first?.detail?.contains("fetched 2, already held 0, failed 0") == true,
          "fetch ahead: the run after an approval at the Mac is logged once, value-free, and says what started it")

    // The same restore approved on the phone fetches nothing: 1Password's
    // own prompt would come up on a Mac nobody may be at.
    let phoneProvider = AuthorizingFixtureProvider()
    guard let (phone, _) = await harness(phoneProvider, label: "phone") else { return }
    await phone.grants.restore([
        restoredGrant(root: context.me, start: context.myStart, references: ["csec://restore/A"], plan: plan),
    ])
    let phoneCovered = ask(phone, ["csec://restore/A"], plan: plan, caller: context.caller)
    _ = await eventuallyTrue { await phone.gate.pendingCount == 1 }
    await phone.gate.decide(.approveOnPhone)
    let phoneReply = await settled(phoneCovered)
    await phone.restoration.fetchAheadSettled()
    let phoneResolved = await phoneProvider.resolved
    let phoneRecords = await fetchRecords(phone)
    check(phoneReply.values?["csec://restore/A"] != nil && phoneResolved.isEmpty && phoneRecords.isEmpty,
          "fetch ahead: a restore approved on the phone fetches nothing ahead")

    // The install's fetch ahead was refused; an ordinary panel approved at
    // the Mac later fetches the rest.
    let retryProvider = AuthorizingFixtureProvider(refusing: true)
    guard let (retry, _) = await harness(retryProvider, label: "retry") else { return }
    let install = await retry.agent.restoreApprovals(request: RestoreApprovalsRequest(), caller: context.caller)
    let installHeld = await held(retry)
    check(install.restoreFetchAhead?.failureCount == 2 && installHeld == 0,
          "fetch ahead: the install's fetch ahead that 1Password refused leaves the paired values cold")
    await retryProvider.refuse(false)
    let unpaired = "op://Other/Gamma/credential"
    let ordinary = ask(retry, [unpaired], plan: restorePlan("fetch-ahead-ordinary"), caller: context.caller)
    _ = await eventuallyTrue { await retry.gate.pendingCount == 1 }
    let ordinaryReview = await retry.gate.reviews.last
    await retry.gate.decide(.approve)
    let ordinaryReply = await settled(ordinary)
    await retry.restoration.fetchAheadSettled()
    let retryHeld = await held(retry)
    check(ordinaryReview?.isRestoreOnly == false && ordinaryReply.values?[unpaired] != nil && retryHeld == 2,
          "fetch ahead: an ordinary panel approved at the Mac fetches what an earlier fetch ahead could not")

    // Everything held: a later approval at the Mac asks 1Password for
    // nothing and logs nothing.
    let askedBefore = await retryProvider.resolved.count
    let recordsBefore = await fetchRecords(retry).count
    let later = ask(retry, ["op://Other/Delta/credential"], plan: restorePlan("fetch-ahead-later"), caller: context.caller)
    _ = await eventuallyTrue { await retry.gate.pendingCount == 1 }
    await retry.gate.decide(.approve)
    _ = await settled(later)
    await retry.restoration.fetchAheadSettled()
    let askedAfter = await retryProvider.resolved.count
    let recordsAfter = await fetchRecords(retry).count
    check(askedAfter == askedBefore + 1 && recordsAfter == recordsBefore,
          "fetch ahead: with every paired value held, an approval at the Mac asks the provider for nothing more")

    // An SSH signing panel approved at the Mac is a person there too.
    let sshProvider = AuthorizingFixtureProvider()
    guard let (ssh, _) = await harness(sshProvider, label: "ssh") else { return }
    let signing = signTask(ssh, caller: context.caller)
    _ = await eventuallyTrue { await ssh.gate.pendingCount == 1 }
    let sshReview = await ssh.gate.reviews.last
    await ssh.gate.decide(.approve)
    let signature = await settled(signing)
    await ssh.restoration.fetchAheadSettled()
    let sshHeld = await held(ssh)
    check(sshReview?.ssh != nil && signature?.isEmpty == false && sshHeld == 2,
          "fetch ahead: an SSH signing panel approved at the Mac fetches the paired values ahead")
}
