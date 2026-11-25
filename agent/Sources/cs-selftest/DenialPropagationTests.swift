import CryptoKit
import CSECRemoteApproval
import ConvenientSecurity
import Foundation
import LocalAuthentication

// Why a review ended without an approval, and what that does to the other
// requests. Only a human Deny is a decision about the request: it refuses the
// identical requests already waiting behind it (never a later one), while a
// requester that went away or a Touch ID error affects nothing else. The SSH
// side of the same rule is in SSHProtectionTests (T5 and the denied
// connection) and SocketLivenessTests (T7–T10).

// MARK: - A reviewer the test answers

/// What the test answers one held review with.
enum GatedReviewDecision: Sendable {
    /// Approve, selecting the offered scope of this kind (nil: the default).
    case approve(GrantScopeKind?)
    case deny(AccessPolicyDenialReason)
}

/// Holds each review open until the test decides it, like a window waiting on
/// a human. Its approval carries an authentication session, so
/// `QueuedPolicyReview` keeps the UI turn until the agent consumes it, as in
/// production. Cancelling a held review is the requester going away.
actor GatedPolicyReview: PolicyReviewProvider {
    private var waiting: [(UUID, CheckedContinuation<GatedReviewDecision, Never>)] = []
    private var automatic: GatedReviewDecision?
    private let onApproval: (@Sendable () -> Void)?
    private(set) var reviews = 0
    private(set) var reviewedPIDs: [pid_t] = []
    private(set) var reviewedReferences: [Set<String>] = []
    private(set) var cancelledReviews = 0

    init(automatic: GatedReviewDecision? = nil, onApproval: (@Sendable () -> Void)? = nil) {
        self.automatic = automatic
        self.onApproval = onApproval
    }

    var pendingCount: Int { waiting.count }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews += 1
        reviewedPIDs.append(review.caller.pid)
        reviewedReferences.append(Set(review.credentials.flatMap(\.references).map(\.uri)))
        let id = UUID()
        let decision: GatedReviewDecision = await withTaskCancellationHandler {
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
        switch decision {
        case let .deny(reason):
            return .denied(reason)
        case let .approve(kind):
            onApproval?()
            let selected = kind.flatMap { kind in
                review.scopeChoices?.options.first { $0.kind == kind }?.id
            }
            return .approved(AccessPolicyApproval(
                authenticationSession: GatedReviewSession(),
                selectedScopeOptionID: selected
            ))
        }
    }

    private func cancel(_ id: UUID) {
        guard let index = waiting.firstIndex(where: { $0.0 == id }) else { return }
        cancelledReviews += 1
        waiting.remove(at: index).1.resume(returning: .deny(.requesterGone))
    }

    /// Answer the oldest held review.
    func decide(_ decision: GatedReviewDecision) {
        guard !waiting.isEmpty else { return }
        waiting.removeFirst().1.resume(returning: decision)
    }

    /// Answer every held review, and every later one, the same way.
    func decideAll(_ decision: GatedReviewDecision) {
        automatic = decision
        let held = waiting
        waiting = []
        for (_, continuation) in held { continuation.resume(returning: decision) }
    }
}

private actor GatedReviewSession: AccessPolicyAuthenticationSession {
    private var used = false

    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        guard !used else { return .denied }
        used = true
        return .approved(unlock: nil)
    }

    func cancel() async { used = true }
}

/// Wait for an observable scheduling boundary, never an assumed sleep order.
func eventuallyTrue(_ condition: () async -> Bool) async -> Bool {
    for _ in 0..<500 {
        if await condition() { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return false
}

// MARK: - Suite

func denialPropagationTests() async {
    print("\n# Deny reasons and human-Deny propagation (access)")
    humanDenialLedgerTests()
    denialReasonRuleTests()
    await reasonPassThroughTests()
    await agentDenialPropagationTests()
}

private func humanDenialLedgerTests() {
    typealias Ledger = HumanDenialLedger<String>
    let root = Ledger.Root(pid: 500, startTime: 5_000)
    let inside: (Ledger.Root) -> Bool = { $0 == root }
    let outside: (Ledger.Root) -> Bool = { _ in false }
    // Fixed instants on the ledger's clock, so the order under test is exact.
    let origin = ContinuousClock.now
    func at(_ milliseconds: Int) -> ContinuousClock.Instant { origin + .milliseconds(milliseconds) }

    var ledger = Ledger()
    let denied = ledger.arrive(at: at(0))
    let waiter = ledger.arrive(at: at(10))
    // The human decided at 20 ms; the outcome is recorded only after a request
    // arrived at 30 ms (a mirrored review withdrawing its phone request first).
    let arrivedBeforeRecord = ledger.arrive(at: at(30))
    ledger.recordHumanDenial(shape: "same", root: root, decidedAt: at(20))
    let later = ledger.arrive(at: at(40))
    let simultaneous = ledger.arrive(at: at(20))
    check(ledger.refuses(waiter, shape: "same", matchesRoot: inside),
          "ledger: a human Deny refuses an identical request that was already waiting")
    check(!ledger.refuses(later, shape: "same", matchesRoot: inside),
          "ledger: a request that arrived after the Deny is never refused (not a cooldown)")
    check(!ledger.refuses(arrivedBeforeRecord, shape: "same", matchesRoot: inside),
          "ledger: a request that arrived after the decision but before the Deny was recorded is not refused")
    check(!ledger.refuses(simultaneous, shape: "same", matchesRoot: inside),
          "ledger: only a request that arrived strictly before the decision is refused")
    ledger.depart(arrivedBeforeRecord)
    ledger.depart(simultaneous)
    check(!ledger.refuses(waiter, shape: "different", matchesRoot: inside),
          "ledger: a waiting request of another shape is not refused")
    check(!ledger.refuses(waiter, shape: "same", matchesRoot: outside),
          "ledger: a waiting request outside the denied root is not refused")
    ledger.depart(denied)
    ledger.depart(waiter)
    check(ledger.recordedDenials == 1, "ledger: a Deny is kept while any request is still waiting")
    ledger.depart(later)
    check(ledger.recordedDenials == 0,
          "ledger: once nothing waits, no recorded Deny outlives the requests it could refuse")

    var idle = Ledger()
    idle.recordHumanDenial(shape: "same", root: root, decidedAt: .now)
    check(idle.recordedDenials == 0, "ledger: a Deny with nothing waiting records nothing")
    let fresh = idle.arrive()
    check(!idle.refuses(fresh, shape: "same", matchesRoot: inside),
          "ledger: a request after an unrecorded Deny is not refused")

    var unknownRoot = Ledger()
    _ = unknownRoot.arrive()
    unknownRoot.recordHumanDenial(
        shape: "same", root: Ledger.Root(pid: 500, startTime: 0), decidedAt: .now
    )
    check(unknownRoot.recordedDenials == 0,
          "ledger: a Deny whose root has no known incarnation refuses nothing")

    var flood = Ledger()
    let held = flood.arrive(at: at(0))
    for index in 0..<(Ledger.maximumDenials + 10) {
        flood.recordHumanDenial(shape: "shape-\(index)", root: root, decidedAt: at(1))
    }
    check(flood.recordedDenials == Ledger.maximumDenials,
          "ledger: recorded Denies stay bounded while one request never leaves")
    check(flood.refuses(held, shape: "shape-\(Ledger.maximumDenials + 9)", matchesRoot: inside)
          && !flood.refuses(held, shape: "shape-0", matchesRoot: inside),
          "ledger: the bound drops the oldest Deny, which can only show a panel, never refuse one")
}

private func denialReasonRuleTests() {
    let beforeUserCancel = ContinuousClock.now
    if case let .human(decidedAt, _, _) = AccessPolicyDenialReason.afterAuthenticationFailure(
        LAError(.userCancel)
    ) {
        check(decidedAt >= beforeUserCancel && decidedAt <= .now,
              "reason: the Touch ID sheet's own Deny (userCancel) is a human refusal, stamped when it happened")
    } else {
        check(false, "reason: the Touch ID sheet's own Deny (userCancel) is a human refusal")
    }
    for code in [LAError.Code.systemCancel, .appCancel, .authenticationFailed, .biometryLockout,
                 .invalidContext, .notInteractive] {
        check(AccessPolicyDenialReason.afterAuthenticationFailure(LAError(code)) == .authenticationFailed,
              "reason: Touch ID error \(code.rawValue) is not a human refusal")
    }
    check(AccessPolicyDenialReason.afterAuthenticationFailure(nil) == .authenticationFailed
          && AccessPolicyDenialReason.afterAuthenticationFailure(
              NSError(domain: "synthetic", code: -2)) == .authenticationFailed,
          "reason: a missing or foreign error is not a human refusal")

    check(AccessReviewUnlock.action(screenLocked: true, requesterAlive: true) == .keepWaiting
          && AccessReviewUnlock.action(screenLocked: true, requesterAlive: false) == .keepWaiting,
          "unlock: a review behind the lock screen keeps waiting")
    check(AccessReviewUnlock.action(screenLocked: false, requesterAlive: true) == .represent,
          "unlock: a live requester is re-presented after unlock")
    check(AccessReviewUnlock.action(screenLocked: false, requesterAlive: false) == .requesterGone,
          "unlock: a requester that exited while the Mac was locked finishes as requesterGone, not re-presented")

    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    let myStart = ProcessAncestry.startTime(of: me) ?? 0
    check(AccessReviewRequester.isAlive(CallerInfo(pid: me, startTime: myStart, description: "self")),
          "unlock: the running requester incarnation is alive")
    check(!AccessReviewRequester.isAlive(CallerInfo(pid: me, startTime: myStart &+ 1, description: "recycled")),
          "unlock: a recycled pid is not the requester")
    check(!AccessReviewRequester.isAlive(CallerInfo(pid: me, startTime: 0, description: "unknown")),
          "unlock: a requester with no known start time cannot be shown alive")
    do {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/true")
        try child.run()
        let childPID = child.processIdentifier
        let childStart = ProcessAncestry.startTime(of: childPID) ?? 1
        child.waitUntilExit()
        check(!AccessReviewRequester.isAlive(
            CallerInfo(pid: childPID, startTime: childStart, description: "exited")),
              "unlock: an exited requester is gone")
    } catch {
        check(false, "unlock: the exited-requester fixture runs (\(error))")
    }
}

private struct FixedPolicyReview: PolicyReviewProvider {
    let outcome: AccessPolicyReviewOutcome
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome { outcome }
}

private actor FixedRemoteReview: RemoteAccessPolicyReviewProvider {
    let result: RemoteAccessReviewResult
    init(_ result: RemoteAccessReviewResult) { self.result = result }
    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        .ready(unlock: .notNeeded)
    }
    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        result
    }
}

private func reasonFixtureReview() -> AccessPolicyReview {
    AccessPolicyReview(
        caller: CallerInfo(pid: 42, startTime: 7, description: "ruby"),
        reason: "run migrations",
        plan: DeliveryPlan(
            mechanism: .directHeap,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: 900,
            operationContext: "run migrations"
        ),
        credentials: [PolicyReviewCredential(references: [try! SecretRef("op://Development/Database/password")])]
    )
}

private func deniedReason(_ outcome: AccessPolicyReviewOutcome) -> AccessPolicyDenialReason? {
    if case let .denied(reason) = outcome { return reason }
    return nil
}

private func reasonPassThroughTests() async {
    let review = reasonFixtureReview()
    let reasons: [AccessPolicyDenialReason] = [
        .human(decidedAt: .now), .requesterGone, .authenticationFailed,
    ]
    for reason in reasons {
        let queued = QueuedPolicyReview(
            underlying: FixedPolicyReview(outcome: .denied(reason)), queue: ConsentQueue()
        )
        check(deniedReason(await queued.reviewAccess(review)) == reason,
              "reason: QueuedPolicyReview carries a \(reason) denial through unchanged")
        let mirrored = MirroredPolicyReview(
            local: FixedPolicyReview(outcome: .denied(reason)),
            remote: FixedRemoteReview(.unavailable)
        )
        check(deniedReason(await mirrored.reviewAccess(review)) == reason,
              "reason: MirroredPolicyReview carries the Mac window's \(reason) denial through unchanged")
    }

    // A verified phone Deny is the human's decision, carrying the instant this
    // Mac received it.
    let phoneReceivedAt = ContinuousClock.now
    let phoneDeny = MirroredPolicyReview(
        local: GatedPolicyReview(),
        remote: FixedRemoteReview(.denied(receivedAt: phoneReceivedAt))
    )
    if case let .human(decidedAt, _, _)? = deniedReason(await phoneDeny.reviewAccess(review)) {
        check(decidedAt == phoneReceivedAt,
              "reason: a phone Deny arrives as a human denial stamped when this Mac received it")
    } else {
        check(false, "reason: a phone Deny arrives as a human denial")
    }

    // A request cancelled while it waits for its turn on the UI queue was
    // never shown: it is withdrawn, not a panel outcome.
    let queue = ConsentQueue()
    let held = try? await queue.acquire()
    let waiting = Task {
        await QueuedPolicyReview(underlying: GatedPolicyReview(), queue: queue).reviewAccess(review)
    }
    _ = await eventuallyTrue { await queue.waitingCount == 1 }
    waiting.cancel()
    check(deniedReason(await waiting.value) == .withdrawn,
          "reason: a review cancelled while queued is withdrawn, never shown")
    await held?.release()

    // A review cancelled while on screen is its requester leaving, too.
    let gate = GatedPolicyReview()
    let shown = Task {
        await QueuedPolicyReview(underlying: gate, queue: ConsentQueue()).reviewAccess(review)
    }
    _ = await eventuallyTrue { await gate.pendingCount == 1 }
    shown.cancel()
    check(deniedReason(await shown.value) == .requesterGone,
          "reason: a review cancelled while on screen is requesterGone")
}

/// A phone leg that is slow to finish once cancelled: it waits until the local
/// window answers and cancels it, then holds a withdrawal the test releases
/// before returning, and `MirroredPolicyReview` waits for it. The real
/// requester answers on an actor hop and deletes in the background; this keeps
/// a late-returning leg covered for any provider that does not.
private actor SlowWithdrawingRemoteReview: RemoteAccessPolicyReviewProvider {
    private(set) var reviews = 0
    private(set) var withdrawing = false
    private var released = false
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        .ready(unlock: .notNeeded)
    }
    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        reviews += 1
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        withdrawing = true
        // Not cancellable, like the detached withdrawal in production.
        await Task.detached { await self.waitForRelease() }.value
        return .unavailable
    }

    private func waitForRelease() async {
        if released { return }
        await withCheckedContinuation { releaseWaiters.append($0) }
    }

    func releaseWithdrawal() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters = []
        for waiter in waiters { waiter.resume() }
    }
}

/// Signs as the Mac, for a real `RemoteApprovalRequester`. Synthetic key.
private struct PropagationMacSigner: RemoteApprovalRequestSigner {
    let key = P256.Signing.PrivateKey()
    func publicKeyX963Representation() async throws -> Data { key.publicKey.x963Representation }
    func sign(_ data: Data) async throws -> Data { try key.signature(for: data).derRepresentation }
}

/// A relay whose pinned phone denies the first request it sees, and whose
/// withdrawal of that request (two CloudKit deletes in production) waits until
/// the test releases it. Later requests get no answer from the phone.
private actor SlowWithdrawingDenyingRelay: RemoteApprovalRelay {
    let phoneDeviceID = UUID().uuidString.lowercased()
    let phoneKey = P256.Signing.PrivateKey()
    private var deniedRequestID: String?
    private var denial: SignedRemoteApprovalResponse?
    private var published: Set<String> = []
    private(set) var withdrawing = false
    private var released = false
    private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        published.insert(request.request.requestID)
        guard deniedRequestID == nil else { return }
        deniedRequestID = request.request.requestID
        denial = try .signed(RemoteApprovalResponse(
            requestID: request.request.requestID,
            requestDigest: try request.request.digest(),
            phoneDeviceID: phoneDeviceID,
            decision: .deny,
            decidedAtMilliseconds: currentTimeMilliseconds(),
            phoneAppVersion: "synthetic"
        ), by: phoneKey)
    }

    func response(for requestID: String, phoneDeviceID: String) async throws -> SignedRemoteApprovalResponse? {
        requestID == deniedRequestID && phoneDeviceID == self.phoneDeviceID ? denial : nil
    }

    func discardResponse(for requestID: String, phoneDeviceID: String) async {}

    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] { [] }
    func requestIsPending(requestID: String) async throws -> Bool { published.contains(requestID) }
    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {}

    func publishAlert(requestID: String, macDeviceID: String) async throws {}

    func deleteExchange(requestID: String, phoneDeviceID: String?) async {
        published.remove(requestID)
        guard requestID == deniedRequestID, !released else { return }
        withdrawing = true
        await withCheckedContinuation { releaseWaiters.append($0) }
    }

    func releaseWithdrawal() {
        released = true
        let waiters = releaseWaiters
        releaseWaiters = []
        for waiter in waiters { waiter.resume() }
    }

    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation? { nil }
    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws {}
    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? { nil }
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {}
    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {}
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? { nil }
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async {}
}

// MARK: - The access path

private actor PropagationFixtureProvider: SecretProvider {
    nonisolated let schemes: Set<String> = ["op", "csec"]
    private(set) var reads = 0
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        reads += 1
        return ResolvedSecret(value: Data("synthetic-propagation-value".utf8), cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private func propagationPlan(_ command: String, heap: Bool = false) -> DeliveryPlan {
    DeliveryPlan(
        mechanism: heap ? .directHeap : .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/\(command)", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: 600, operationContext: "synthetic \(command)",
        outputGuard: heap ? nil : OutputGuardPlan(mode: .tty)
    )
}

private func agentDenialPropagationTests() async {
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let start = ProcessAncestry.startTime(of: me),
          let parent = ProcessAncestry.parent(of: me), parent > 1 else {
        check(false, "propagation fixtures can read their own live ancestry")
        return
    }
    // A live process the injected ancestry places outside this test's terminal.
    let outsider = Process()
    outsider.executableURL = URL(fileURLWithPath: "/bin/sleep")
    outsider.arguments = ["30"]
    do { try outsider.run() } catch {
        check(false, "the outsider requester fixture starts (\(error))")
        return
    }
    defer { if outsider.isRunning { outsider.terminate() } }
    let outsiderPID = outsider.processIdentifier
    guard let outsiderStart = ProcessAncestry.startTime(of: outsiderPID) else {
        check(false, "the outsider requester fixture has a live incarnation")
        return
    }
    let inspection = ProcessInspection(
        startTime: { ProcessAncestry.startTime(of: $0) },
        parent: { $0 == outsiderPID ? 1 : ProcessAncestry.parent(of: $0) },
        name: { $0 == parent ? "zsh" : ProcessAncestry.name(of: $0) },
        executablePath: { ProcessAncestry.executablePath(of: $0) },
        hasControllingTerminal: { $0 == parent }
    )
    let caller = CallerInfo(pid: me, startTime: start, description: "synthetic propagation caller")
    let outsiderCaller = CallerInfo(
        pid: outsiderPID, startTime: outsiderStart, description: "synthetic outsider caller"
    )
    let refs = ["op://deny-propagation/item/password", "csec://deny-propagation/key"]
    let otherRefs = ["op://deny-propagation/other/password"]

    struct Harness {
        let agent: Agent
        let gate: GatedPolicyReview
        let accessQueue: ConsentQueue
    }
    /// With `remote`, the production composition: the window mirrored to a phone.
    func makeHarness(remote: (any RemoteAccessPolicyReviewProvider)? = nil) async -> Harness {
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(PropagationFixtureProvider())
        let gate = GatedPolicyReview()
        let uiQueue = ConsentQueue(), accessQueue = ConsentQueue()
        let reviewer: any PolicyReviewProvider = remote.map {
            MirroredPolicyReview(local: gate, remote: $0)
        } ?? gate
        let agent = Agent(
            resolver: resolver, grants: GrantTable(),
            consent: QueuedConsentProvider(underlying: AutoApproveConsent(), queue: uiQueue),
            policyReview: QueuedPolicyReview(underlying: reviewer, queue: uiQueue),
            allowUnverifiedPlansForTesting: true, processInspection: inspection,
            terminalInspection: .unavailable,
            accessConsentQueue: accessQueue
        )
        return Harness(agent: agent, gate: gate, accessQueue: accessQueue)
    }
    func ask(
        _ harness: Harness, _ references: [String], _ command: String,
        heap: Bool = false, as requester: CallerInfo? = nil
    ) -> Task<Response, Never> {
        let request = try! AccessRequest(
            references: references, reason: command, ttlSeconds: 600,
            deliveryPlan: propagationPlan(command, heap: heap)
        )
        let agent = harness.agent
        let requester = requester ?? caller
        return Task { await agent.handle(request: request, caller: requester) }
    }

    // A human Deny with four requests waiting behind it: only the identical one
    // (same references and release shape, a caller inside the denied root) is
    // refused; the others each get their own panel.
    do {
        let harness = await makeHarness()
        let denied = ask(harness, refs, "one")
        check(await eventuallyTrue { await harness.gate.pendingCount == 1 },
              "propagation: the first access review is on screen")
        let identical = ask(harness, refs, "two")
        _ = await eventuallyTrue { await harness.accessQueue.waitingCount == 1 }
        let otherShape = ask(harness, refs, "three", heap: true)
        _ = await eventuallyTrue { await harness.accessQueue.waitingCount == 2 }
        let otherReferences = ask(harness, otherRefs, "four")
        _ = await eventuallyTrue { await harness.accessQueue.waitingCount == 3 }
        let otherRoot = ask(harness, refs, "five", as: outsiderCaller)
        check(await eventuallyTrue { await harness.accessQueue.waitingCount == 4 },
              "propagation: four access requests wait behind the first review")
        await harness.gate.decide(.deny(.human(decidedAt: .now)))
        await harness.gate.decideAll(.approve(nil))

        let deniedResponse = await denied.value
        let identicalResponse = await identical.value
        check(deniedResponse.failure?.code == .consentDenied,
              "propagation: the human-denied access request is refused")
        check(identicalResponse.values == nil && identicalResponse.failure?.code == .consentDenied,
              "propagation: a human Deny refuses the identical access request already waiting")
        check(await otherShape.value.values != nil,
              "propagation: a waiting request of another release shape gets its own panel")
        check(await otherReferences.value.values != nil,
              "propagation: a waiting request for other references gets its own panel")
        check(await otherRoot.value.values != nil,
              "propagation: a waiting request from outside the denied root gets its own panel")
        let reviewed = await harness.gate.reviewedReferences
        check(reviewed.count == 4,
              "propagation: exactly four access panels were shown (\(reviewed.count))")
        let reviewedCallers = await harness.gate.reviewedPIDs
        check(reviewedCallers.filter { $0 == me }.count == 3 && reviewedCallers.last == outsiderPID,
              "propagation: the refused identical request never raised a panel")

        // A request that arrives after the Deny is a new question.
        let later = await ask(harness, refs, "six").value
        let reviewsAfterLater = await harness.gate.reviews
        check(later.values != nil && reviewsAfterLater == 5,
              "propagation: an identical access request after a human Deny gets its own panel")
    }

    // Only the human's Deny propagates.
    for reason in [AccessPolicyDenialReason.requesterGone, .authenticationFailed] {
        let harness = await makeHarness()
        let first = ask(harness, refs, "one")
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let identical = ask(harness, refs, "two")
        _ = await eventuallyTrue { await harness.accessQueue.waitingCount == 1 }
        await harness.gate.decide(.deny(reason))
        await harness.gate.decideAll(.approve(nil))
        let firstResponse = await first.value
        let identicalResponse = await identical.value
        let reviews = await harness.gate.reviews
        check(firstResponse.values == nil && identicalResponse.values != nil && reviews == 2,
              "propagation: a \(reason) access denial does not refuse the identical waiting request")
    }

    // The Deny is ordered by when the human decided, not by when its outcome
    // reaches the agent. A reviewer that returns late (decision instant earlier
    // than the return): a request that was waiting before the decision is
    // refused, one that arrived after it gets its own panel.
    do {
        let harness = await makeHarness()
        let denied = ask(harness, refs, "one")
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let earlier = ask(harness, refs, "two")
        _ = await eventuallyTrue { await harness.accessQueue.waitingCount == 1 }
        let decidedAt = ContinuousClock.now
        let afterDecision = ask(harness, refs, "three")
        check(await eventuallyTrue { await harness.accessQueue.waitingCount == 2 },
              "propagation: a request arrives after the human decided, before the outcome returns")
        await harness.gate.decide(.deny(.human(decidedAt: decidedAt)))
        await harness.gate.decideAll(.approve(nil))
        let deniedResponse = await denied.value
        let earlierResponse = await earlier.value
        let afterResponse = await afterDecision.value
        let reviews = await harness.gate.reviews
        check(deniedResponse.values == nil && earlierResponse.values == nil,
              "propagation: a request waiting before the human decided is refused")
        check(afterResponse.values != nil && reviews == 2,
              "propagation: a request that arrived after the decision instant gets its own panel")
    }

    // The same through the production composition: the Mac window mirrored to
    // a phone, whose request is withdrawn before the mirror returns the Deny.
    do {
        let phone = SlowWithdrawingRemoteReview()
        let harness = await makeHarness(remote: phone)
        let opRefs = ["op://deny-propagation/item/password", "op://deny-propagation/item/username"]
        let denied = ask(harness, opRefs, "one")
        _ = await eventuallyTrue {
            let pending = await harness.gate.pendingCount
            let mirrored = await phone.reviews
            return pending == 1 && mirrored == 1
        }
        await harness.gate.decide(.deny(.human(decidedAt: .now)))
        check(await eventuallyTrue { await phone.withdrawing },
              "propagation: the mirrored phone request is being withdrawn after the Mac Deny")
        let retried = ask(harness, opRefs, "two")
        check(await eventuallyTrue { await harness.accessQueue.waitingCount == 1 },
              "propagation: a retry arrives while the Deny is still on its way back")
        await harness.gate.decideAll(.approve(nil))
        await phone.releaseWithdrawal()
        let deniedResponse = await denied.value
        let retriedResponse = await retried.value
        let reviews = await harness.gate.reviews
        check(deniedResponse.values == nil && retriedResponse.values != nil && reviews == 2,
              "propagation: a request made after a mirrored Deny, during the phone withdrawal, gets its own panel")
    }

    // A Deny made on the phone, through the real requester: it is ordered by
    // when this Mac received it, and it reaches the agent without waiting for
    // the mailbox delete, which runs in the background. A request made while
    // that delete is still running is on its own panel at once.
    do {
        let relay = SlowWithdrawingDenyingRelay()
        let signer = PropagationMacSigner()
        guard let requester = try? RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: UUID().uuidString.lowercased(),
                macDeviceName: "Synthetic Mac",
                pinnedPhoneDeviceID: relay.phoneDeviceID,
                pinnedPhonePublicKeyX963: relay.phoneKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: signer,
            relay: relay
        ) else {
            check(false, "propagation: the phone requester fixture builds")
            return
        }
        let harness = await makeHarness(
            remote: RequesterRemoteAccessPolicyReviewProvider(requester: requester)
        )
        let opRefs = ["op://deny-propagation/phone/password", "op://deny-propagation/phone/username"]
        let denied = ask(harness, opRefs, "one")
        check(await eventuallyTrue { await relay.withdrawing },
              "propagation: the phone's Deny is received and its request is being withdrawn")
        let retried = ask(harness, opRefs, "two")
        // The UI turn is free before the delete finishes: the retry's own
        // panel is showing while the withdrawal is still blocked.
        check(await eventuallyTrue { await harness.gate.pendingCount == 1 },
              "propagation: a request made after the phone Deny is on its own panel before the withdrawal finishes")
        await relay.releaseWithdrawal()
        let deniedResponse = await denied.value
        await harness.gate.decideAll(.approve(nil))
        let retriedResponse = await retried.value
        let reviews = await harness.gate.reviews
        check(deniedResponse.values == nil && retriedResponse.values != nil && reviews == 2,
              "propagation: a request made after a phone Deny, during its withdrawal, gets its own panel")
    }
}
