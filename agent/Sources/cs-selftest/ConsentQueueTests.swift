import ConvenientSecurity
import Foundation

/// Wait for an observable scheduling boundary, never an assumed sleep order.
private func queueEventually(_ condition: () async -> Bool) async -> Bool {
    for _ in 0..<500 {
        if await condition() { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return false
}

private actor QueueOrder {
    private(set) var values: [Int] = []
    func record(_ value: Int) { values.append(value) }
}

/// What the modeled human (or the requester's side) does with one prompt.
enum QueueDecision: Sendable, Equatable {
    case approve
    case deny(AccessPolicyDenialReason)
}

/// Models a window that stays active after Touch ID until the agent consumes
/// its session. It also models standalone biometrics and host remediation.
private actor QueuePresenter: PolicyReviewProvider, ConsentProvider {
    private var pending: [(UUID, CheckedContinuation<QueueDecision, Never>)] = []
    private var autoApprove = false
    private(set) var labels: [String] = []
    private(set) var referenceSets: [Set<String>] = []
    private(set) var active = 0
    private(set) var maximumActive = 0
    private(set) var cancelledSessions = 0

    private func present(_ label: String) async -> QueueDecision {
        labels.append(label)
        active += 1
        maximumActive = max(maximumActive, active)
        let id = UUID()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                // A cancelled prompt is the requester going away, as the real
                // window reports it.
                if Task.isCancelled { continuation.resume(returning: .deny(.requesterGone)) }
                else if autoApprove { continuation.resume(returning: .approve) }
                else { pending.append((id, continuation)) }
            }
        } onCancel: {
            Task { await self.cancelPending(id) }
        }
    }

    private func cancelPending(_ id: UUID) {
        guard let index = pending.firstIndex(where: { $0.0 == id }) else { return }
        pending.remove(at: index).1.resume(returning: .deny(.requesterGone))
    }

    /// `false` is the human pressing Deny.
    func decideNext(_ approved: Bool) {
        decideNext(approved ? .approve : .deny(.human(decidedAt: .now)))
    }

    func decideNext(_ decision: QueueDecision) {
        guard !pending.isEmpty else { return }
        pending.removeFirst().1.resume(returning: decision)
    }

    func finishAll() {
        autoApprove = true
        let remaining = pending
        pending = []
        for (_, continuation) in remaining { continuation.resume(returning: .approve) }
    }

    func close(cancelled: Bool = false) {
        active -= 1
        if cancelled { cancelledSessions += 1 }
    }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        referenceSets.append(Set(review.credentials.flatMap(\.references).map(\.uri)))
        if case let .deny(reason) = await present(review.reason) {
            close()
            return .denied(reason)
        }
        return .approved(AccessPolicyApproval(
            authenticationSession: QueueAuthentication(presenter: self),
            selectedScopeOptionID: review.scopeChoices?.options.first {
                $0.kind == .terminalSession
            }?.id,
            selectedDurationIndex: review.durationChoices?.defaultIndex
        ))
    }

    func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        let approved = await present("remediation") == .approve
        close()
        return approved ? .approved(selectedKeys: review.items.map(\.key)) : .denied
    }

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String,
        ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        await authenticate(reason: reason)
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        let approved = await present(reason) == .approve
        close()
        return approved ? .approved(unlock: nil) : .denied
    }
}

private actor QueueAuthentication: AccessPolicyAuthenticationSession {
    private let presenter: QueuePresenter
    private var finished = false
    init(presenter: QueuePresenter) { self.presenter = presenter }
    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        guard !finished else { return .denied }
        finished = true
        await presenter.close()
        return .approved(unlock: nil)
    }
    func cancel() async {
        guard !finished else { return }
        finished = true
        await presenter.close(cancelled: true)
    }
}

private func queuePlan(_ command: String, heap: Bool = false) -> DeliveryPlan {
    DeliveryPlan(
        mechanism: heap ? .directHeap : .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/\(command)", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: 600, operationContext: "synthetic \(command)",
        outputGuard: heap ? nil : OutputGuardPlan(mode: .tty)
    )
}

func reviewPresentationQueueTests() async {
    let directory = NSTemporaryDirectory() + "csec-review-queue-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: directory) }
    let gate = ReviewPresentationLock(directory: directory)
    let caller = CallerInfo(pid: 1, startTime: 1, description: "synthetic")
    let credential = PolicyReviewCredential(references: [try! SecretRef("op://queue/item/password")])
    let restore = RestoreReviewDetails(
        cause: .restart,
        rows: [RestoreReviewRow(kind: .secretGrant, title: "synthetic", detail: "synthetic",
                                references: ["op://queue/item/password"])], storeCount: 1
    )
    let plan = queuePlan("fixture")
    let job = AutomationJob(
        id: "00000000-0000-0000-0000-000000000001",
        revision: "00000000-0000-0000-0000-000000000002",
        name: "synthetic", reason: "synthetic", references: ["op://queue/item/password"],
        command: AutomationCommand(
            executable: plan.executable, commandLine: ["/usr/bin/true"],
            workingDirectory: "/tmp", commandDigest: "synthetic"
        ), minimumIntervalSeconds: 0, maximumRuntimeSeconds: 30, consumerTrust: .mutableInterpreted,
        createdAt: Date(timeIntervalSince1970: 1_700_000_000), updatedAt: Date(timeIntervalSince1970: 1_700_000_000)
    )
    let fixtures: [(String, AccessPolicyReview)] = [
        ("access", AccessPolicyReview(caller: caller, reason: "access", plan: plan, credentials: [credential])),
        ("SSH", AccessPolicyReview(
            caller: caller, reason: "SSH", plan: plan, credentials: [credential],
            ssh: SSHAccessReviewDetails(hostNames: ["example.invalid"], remoteUser: "git",
                                        keyLabel: "synthetic", keyAlgorithm: "ssh-ed25519")
        )),
        ("automation", AccessPolicyReview(caller: caller, reason: "automation", plan: plan,
                                          credentials: [credential], automation: AutomationReviewDetails(job: job))),
        ("restore", .restoreOnly(caller: caller, restore: restore)),
        ("release with restore", AccessPolicyReview(caller: caller, reason: "release with restore", plan: plan,
                                                    credentials: [credential], restore: restore)),
    ]
    for (label, fixture) in fixtures {
        do {
            let sudoTurn = try await gate.acquire()
            let queue = ConsentQueue(presentationLock: gate), presenter = QueuePresenter()
            let reviewer = QueuedPolicyReview(underlying: presenter, queue: queue)
            let review = Task { await reviewer.reviewAccess(fixture) }
            // Once two acquisitions exist, one is the cross-process head and
            // one is in the FIFO. Both are cancellable without presenting.
            let marker = Task { try await queue.acquire() }
            check(await queueEventually { await queue.waitingCount == 1 }, "\(label) waits behind a sudo turn")
            marker.cancel()
            _ = try? await marker.value
            check(await presenter.labels.isEmpty, "\(label) never presents while sudo owns the turn")
            sudoTurn.release()
            guard await queueEventually({ await presenter.labels.count == 1 }) else {
                check(false, "\(label) presents after sudo finishes")
                review.cancel()
                _ = await review.value
                continue
            }
            await presenter.decideNext(true)
            guard case let .approved(approval) = await review.value,
                  let session = approval.authenticationSession else {
                check(false, "\(label) preserves its live authentication session")
                continue
            }
            let order = QueueOrder()
            let sudo = Task {
                await order.record(1)
                return await SudoReviewRace.run(
                    presentationLock: gate,
                    local: { await order.record(2); return .approved }, phone: { .unavailable }
                )
            }
            check(await queueEventually { await order.values == [1] },
                  "\(label) retains the shared turn while its approved authentication is unconsumed")
            if label == "SSH" {
                await session.cancel()
            } else {
                check(await session.completeAfterPolicyApproval(policySummary: "synthetic").isApproved,
                      "\(label) consumes only its own authentication")
            }
            check(await sudo.value == .approved(on: .mac), "sudo presents after \(label)'s session closes")
            check(await order.values == [1, 2], "\(label) and sudo never overlap")
        } catch { check(false, "\(label) presentation fixture runs (\(error))") }
    }
    do {
        let sudoTurn = try await gate.acquire()
        let queue = ConsentQueue(presentationLock: gate), presenter = QueuePresenter()
        let consent = QueuedConsentProvider(underlying: presenter, queue: queue)
        let waiting = Task { await consent.authenticate(reason: "standalone") }
        let marker = Task { try await queue.acquire() }
        check(await queueEventually { await queue.waitingCount == 1 }, "standalone biometrics waits behind sudo")
        marker.cancel(); _ = try? await marker.value
        check(await presenter.labels.isEmpty, "standalone biometrics cannot overlap sudo")
        sudoTurn.release()
        check(await queueEventually { await presenter.labels.count == 1 }, "standalone biometrics gets the released turn")
        await presenter.decideNext(true)
        check(await waiting.value.isApproved, "standalone biometrics keeps its normal consent result")
    } catch { check(false, "standalone presentation fixture runs (\(error))") }
}

func consentQueueTests() async {
    print("\n# Consent queue (FIFO, cancellation, and shared presentation)")
    do {
        let queue = ConsentQueue()
        let first = try await queue.acquire()
        let order = QueueOrder()
        let second = Task {
            let permit = try await queue.acquire()
            await order.record(2)
            return permit
        }
        check(await queueEventually { await queue.waitingCount == 1 }, "the second consent waits for the first")
        let cancelled = Task { try await queue.acquire() }
        check(await queueEventually { await queue.waitingCount == 2 }, "another consent joins the FIFO")
        cancelled.cancel()
        do {
            _ = try await cancelled.value
            check(false, "a cancelled queued consent must not receive a turn")
        } catch { check(error is CancellationError, "cancelling a queued consent removes only that waiter") }
        let third = Task {
            let permit = try await queue.acquire()
            await order.record(3)
            await permit.release()
        }
        check(await queueEventually { await queue.waitingCount == 2 }, "later consent stays queued after cancellation")
        await first.release()
        let secondPermit = try await second.value
        await first.release()
        let waitingAfterStaleRelease = await queue.waitingCount
        check(await order.values == [2] && waitingAfterStaleRelease == 1,
              "a stale or repeated release cannot release the next owner's turn")
        await secondPermit.release()
        try await third.value
        check(await order.values == [2, 3], "consents run in FIFO order around a cancelled waiter")
        check(await queue.waitingCount == 0, "the consent queue drains fully")
    } catch { check(false, "FIFO consent tests run (\(error))") }

    let queue = ConsentQueue()
    let presenter = QueuePresenter()
    let review = QueuedPolicyReview(underlying: presenter, queue: queue)
    let consent = QueuedConsentProvider(underlying: presenter, queue: queue)
    let caller = CallerInfo(pid: 1, startTime: 1, description: "synthetic")
    let accessReview = AccessPolicyReview(
        caller: caller, reason: "access", plan: queuePlan("fixture"),
        credentials: [PolicyReviewCredential(references: [try! SecretRef("op://queue/item/password")])]
    )
    let first = Task { await review.reviewAccess(accessReview) }
    check(await queueEventually { await presenter.labels.count == 1 }, "the first shared review is presented")
    await presenter.decideNext(true)
    guard case let .approved(approval) = await first.value,
          let session = approval.authenticationSession else {
        check(false, "the queued review preserves its authentication session")
        return
    }
    let second = Task { await consent.authenticate(reason: "standalone") }
    check(await queueEventually { await queue.waitingCount == 1 },
          "an approved window keeps its turn until the agent completes policy validation")
    let cancelled = Task { await review.reviewAccess(accessReview) }
    check(await queueEventually { await queue.waitingCount == 2 }, "a second review queues behind standalone biometrics")
    cancelled.cancel()
    if case .denied = await cancelled.value {
        check(true, "a cancelled queued review is removed without presenting a window")
    } else { check(false, "cancelled queued review was approved") }
    let host = Task { await review.reviewHostRemediation(HostRemediationReview(
        items: [], caller: CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
    )) }
    check(await queueEventually { await queue.waitingCount == 2 }, "host remediation uses the same presentation queue")
    check(await presenter.labels == ["access"], "no second biometric prompt starts while an approved review is open")
    check(await session.completeAfterPolicyApproval(policySummary: "synthetic").isApproved,
          "the reviewed authentication is consumed by its own request")
    check(await queueEventually { await presenter.labels.count == 2 }, "standalone biometrics gets the next turn")
    await session.cancel()
    check(await queue.waitingCount == 1, "cancelling an already-completed session cannot release another review")
    await presenter.decideNext(false)
    check(!(await second.value.isApproved), "denial belongs only to the active consent")
    check(await queueEventually { await presenter.labels.count == 3 }, "denial advances to the next queued request")
    await presenter.decideNext(true)
    check(await host.value == .approved(selectedKeys: []), "a later independent consent can still be approved")
    check(await presenter.maximumActive == 1, "all presentation paths share at most one active window")

    let active = Task { await consent.authenticate(reason: "cancel active") }
    check(await queueEventually { await presenter.labels.count == 4 }, "the active cancellation fixture starts")
    let following = Task { await consent.authenticate(reason: "after cancellation") }
    check(await queueEventually { await queue.waitingCount == 1 }, "the next request waits during active authentication")
    active.cancel()
    check(!(await active.value.isApproved), "cancelling active authentication is never an approval")
    check(await queueEventually { await presenter.labels.count == 5 }, "active cancellation closes its prompt and advances the queue")
    await presenter.decideNext(true)
    check(await following.value.isApproved, "cancelling one consent does not deny the next")

    // Dropping an unconsumed approval must close its window before admitting
    // another request, even if a caller exits an error path without cancel().
    await presenter.finishAll()
    var abandoned: AccessPolicyReviewOutcome? = await review.reviewAccess(accessReview)
    check(abandoned != nil, "an abandoned-review fixture owns a turn")
    abandoned = nil
    let afterAbandon = Task { await consent.authenticate(reason: "after abandonment") }
    check(await afterAbandon.value.isApproved, "abandoning an approval releases its queued turn")
    let maximumAfterAbandonment = await presenter.maximumActive
    check(await presenter.cancelledSessions == 1 && maximumAfterAbandonment == 1,
          "an abandoned authentication window is cancelled before the next prompt")

    await agentConsentQueueTests()
}

private actor QueueFixtureProvider: SecretProvider {
    nonisolated let schemes: Set<String> = ["op", "csec"]
    private(set) var reads: [String] = []
    private var failNext: Bool
    init(failNext: Bool = false) { self.failNext = failNext }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        reads.append(ref.uri)
        if failNext {
            failNext = false
            throw ProviderError.referenceNotFound(ref.uri)
        }
        return ResolvedSecret(value: Data("synthetic-queue-value".utf8), cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private func agentConsentQueueTests() async {
    print("\n# Agent consent queue (concurrent requests and grant rechecking)")
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let start = ProcessAncestry.startTime(of: me),
          let parent = ProcessAncestry.parent(of: me), parent > 1 else {
        check(false, "queue fixtures can read their own live ancestry")
        return
    }
    let caller = CallerInfo(pid: me, startTime: start, description: "synthetic queue caller")
    let inspection = ProcessInspection(
        startTime: { ProcessAncestry.startTime(of: $0) },
        parent: { ProcessAncestry.parent(of: $0) },
        name: { $0 == parent ? "zsh" : ProcessAncestry.name(of: $0) },
        executablePath: { ProcessAncestry.executablePath(of: $0) },
        hasControllingTerminal: { $0 == parent }
    )
    let refs = ["op://queue/item/password", "csec://queue/key"]
    for scenario in [
        "covered", "new-reference", "different-shape", "denied", "denied-authentication-failed",
        "cancelled", "provider-failure",
    ] {
        let resolver = SecretResolver(cache: NullSecretCache())
        let provider = QueueFixtureProvider(failNext: scenario == "provider-failure")
        await resolver.register(provider)
        let presenter = QueuePresenter()
        let uiQueue = ConsentQueue(), accessQueue = ConsentQueue()
        let agent = Agent(
            resolver: resolver, grants: GrantTable(),
            consent: QueuedConsentProvider(underlying: presenter, queue: uiQueue),
            policyReview: QueuedPolicyReview(underlying: presenter, queue: uiQueue),
            allowUnverifiedPlansForTesting: true, processInspection: inspection,
            terminalInspection: .unavailable,
            accessConsentQueue: accessQueue
        )
        let firstRefs = scenario == "new-reference" ? [refs[0]] : refs
        let firstRequest = try! AccessRequest(
            references: firstRefs, reason: "first", ttlSeconds: 600, deliveryPlan: queuePlan("one")
        )
        let secondRequest = try! AccessRequest(
            references: refs, reason: "second", ttlSeconds: 600,
            deliveryPlan: queuePlan("two", heap: scenario == "different-shape")
        )
        let first = Task { await agent.handle(request: firstRequest, caller: caller) }
        check(await queueEventually { await presenter.labels == ["first"] }, "the first Agent review starts (\(scenario))")
        let second = Task { await agent.handle(request: secondRequest, caller: caller) }
        check(await queueEventually { await accessQueue.waitingCount == 1 }, "parallel access waits through authorization (\(scenario))")
        check(await provider.reads.isEmpty, "neither provider scheme resolves before consent (\(scenario))")
        if scenario == "cancelled" {
            second.cancel()
            let cancelled = await second.value
            check(cancelled.values == nil, "a cancelled queued request releases no value")
            check(await accessQueue.waitingCount == 0, "cancelled access leaves the FIFO immediately")
        }
        let approvedAt = Date()
        switch scenario {
        case "denied": await presenter.decideNext(.deny(.human(decidedAt: .now)))
        case "denied-authentication-failed": await presenter.decideNext(.deny(.authenticationFailed))
        default: await presenter.decideNext(.approve)
        }
        let firstResponse = await first.value
        let firstFails = ["denied", "denied-authentication-failed", "provider-failure"].contains(scenario)
        check((firstResponse.values == nil) == firstFails, "the first request keeps its own result (\(scenario))")
        // A human Deny answers the identical request already waiting behind it;
        // a Deny that was not the human's (here a Touch ID error) does not.
        let secondRefusedByHumanDeny = scenario == "denied"
        // A release that failed after its approval mints no grant, so the
        // identical request waiting behind it is reviewed again.
        let needsSecondReview = [
            "new-reference", "different-shape", "denied-authentication-failed", "provider-failure",
        ].contains(scenario)
        if needsSecondReview {
            check(await queueEventually { await presenter.labels.count == 2 }, "uncovered access gets its own review (\(scenario))")
            await presenter.decideNext(true)
        }
        await presenter.finishAll()
        let secondResponse = await second.value
        if secondRefusedByHumanDeny {
            check(secondResponse.values == nil && secondResponse.failure?.code == .consentDenied,
                  "a human Deny refuses the identical request already waiting behind it (\(scenario))")
        } else {
            check((secondResponse.values != nil) == (scenario != "cancelled"),
                  "the next request is not denied by concurrency (\(scenario))")
        }
        check(await presenter.labels.count == (needsSecondReview ? 2 : 1),
              "waiting requests recheck grants and prompt only when still required (\(scenario))")
        let activeAfterRequests = await presenter.active
        check(await presenter.maximumActive == 1 && activeAfterRequests == 0, "no consent windows overlap or remain open (\(scenario))")
        if scenario == "covered" {
            check(Set(secondResponse.values?.keys.map { $0 } ?? []) == Set(refs),
                  "grant rechecking works identically for canonical references from both schemes")
            check(firstResponse.accessExpiresAt.map { $0 >= approvedAt.addingTimeInterval(599) } == true,
                  "the approved lifetime begins after waiting for consent")
        }
        if scenario == "new-reference" {
            check(await presenter.referenceSets == [Set([refs[0]]), Set([refs[1]])],
                  "a queued request reviews only references not covered by the preceding approval")
        }
    }

    // A grant that was present when the request joined the queue can be revoked
    // while another consent is on screen. Review the whole uncovered set again.
    do {
        let queue = ConsentQueue()
        let held = try await queue.acquire()
        let presenter = QueuePresenter()
        let provider = QueueFixtureProvider()
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(provider)
        let grants = GrantTable()
        let plan = queuePlan("revocation")
        await grants.add(Grant(
            rootPID: me, rootStartTime: start, references: [refs[0]],
            reason: "temporary fixture grant", expiresAt: Date().addingTimeInterval(600),
            deliveryPlanDigest: try plan.digest()
        ))
        let agent = Agent(
            resolver: resolver, grants: grants, consent: presenter, policyReview: presenter,
            allowUnverifiedPlansForTesting: true, processInspection: inspection,
            terminalInspection: .unavailable,
            accessConsentQueue: queue
        )
        let request = try AccessRequest(references: refs, reason: "revoked while queued", ttlSeconds: 600, deliveryPlan: plan)
        let waiting = Task { await agent.handle(request: request, caller: caller) }
        check(await queueEventually { await queue.waitingCount == 1 }, "a partially covered request waits for consent")
        _ = await grants.revokeAll()
        await held.release()
        check(await queueEventually { await presenter.labels.count == 1 }, "the revoked request reaches review")
        check(await presenter.referenceSets == [Set(refs)], "revocation while queued is respected when building the review")
        await presenter.finishAll()
        check(await waiting.value.values != nil, "the revoked references are released only after fresh consent")
    } catch { check(false, "queued revocation fixture runs (\(error))") }

    // A caller can exit while waiting. Revalidate the process incarnation before
    // opening its window, not only after the user has spent time approving it.
    do {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = ["30"]
        try child.run()
        defer { if child.isRunning { child.terminate() } }
        guard let childStart = ProcessAncestry.startTime(of: child.processIdentifier) else {
            check(false, "the queued caller fixture has a live process incarnation")
            return
        }
        let queue = ConsentQueue()
        let held = try await queue.acquire()
        let presenter = QueuePresenter()
        let provider = QueueFixtureProvider()
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(provider)
        let agent = Agent(
            resolver: resolver, grants: GrantTable(), consent: presenter, policyReview: presenter,
            allowUnverifiedPlansForTesting: true, terminalInspection: .unavailable, accessConsentQueue: queue
        )
        let request = try AccessRequest(references: refs, reason: "exited while queued", ttlSeconds: 600, deliveryPlan: queuePlan("exit"))
        let childCaller = CallerInfo(pid: child.processIdentifier, startTime: childStart, description: "synthetic child")
        let waiting = Task { await agent.handle(request: request, caller: childCaller) }
        check(await queueEventually { await queue.waitingCount == 1 }, "a live caller can join the consent queue")
        child.terminate()
        // Foundation dispatches process termination asynchronously. Blocking
        // this executor in waitUntilExit() can prevent that callback running.
        let exited = await queueEventually { !child.isRunning }
        check(exited, "the queued caller exits without blocking the consent executor")
        // If liveness validation regresses, fail the assertions below instead
        // of stranding this test at an unexpected synthetic consent window.
        await presenter.finishAll()
        await held.release()
        check(await waiting.value.values == nil, "an exited queued caller receives no values")
        check(await presenter.labels.isEmpty, "an exited queued caller never opens a consent window")
        check(await provider.reads.isEmpty, "an exited queued caller never reaches a provider")
    } catch { check(false, "queued caller-liveness fixture runs (\(error))") }
}
