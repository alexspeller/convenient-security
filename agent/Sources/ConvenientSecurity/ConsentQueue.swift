import Foundation

/// A FIFO permit for one complete consent transaction. Actor isolation alone
/// cannot provide this: another request can enter whenever a review awaits UI.
/// With a presentation lock, its FIFO head also waits for independent sudo
/// helpers. The queue holds only ownership IDs, continuations and an empty-file
/// lock descriptor, never resolved values.
public actor ConsentQueue {
    private struct Waiter {
        let id: UUID
        let continuation: CheckedContinuation<Permit, Error>
    }

    private var owner: UUID?
    private var waiters: [Waiter] = []
    private let presentationLock: ReviewPresentationLock?
    private var presentationPermit: ReviewPresentationLock.Permit?

    public init(presentationLock: ReviewPresentationLock? = nil) {
        self.presentationLock = presentationLock
    }

    public var waitingCount: Int { waiters.count }

    public func acquire() async throws -> Permit {
        let id = UUID()
        return try await withTaskCancellationHandler {
            try Task.checkCancellation()
            let permit: Permit = try await withCheckedThrowingContinuation { continuation in
                if owner == nil {
                    owner = id
                    continuation.resume(returning: Permit(queue: self, id: id, waited: false))
                } else {
                    waiters.append(Waiter(id: id, continuation: continuation))
                    // Queued behind a review that is waiting on a human: tell
                    // the request's session now, not when its own turn comes.
                    HumanWait.current?.notifyWaiting()
                }
            }
            do {
                // Keep the daemon's FIFO while its head waits behind a sudo
                // helper. The same permit covers every local/phone variant
                // and survives until the authentication session is consumed.
                presentationPermit = try await presentationLock?.acquire()
                try Task.checkCancellation()
            } catch {
                release(id)
                throw error
            }
            return permit
        } onCancel: {
            Task { await self.cancelWaiting(id) }
        }
    }

    private func cancelWaiting(_ id: UUID) {
        guard let index = waiters.firstIndex(where: { $0.id == id }) else { return }
        waiters.remove(at: index).continuation.resume(throwing: CancellationError())
    }

    fileprivate func release(_ id: UUID) {
        guard owner == id else { return }
        presentationPermit?.release()
        presentationPermit = nil
        guard !waiters.isEmpty else {
            owner = nil
            return
        }
        let next = waiters.removeFirst()
        owner = next.id
        next.continuation.resume(returning: Permit(queue: self, id: next.id, waited: true))
    }

    /// Explicit release is awaited at transaction boundaries. Deinitialization
    /// is a fallback for an abandoned owner; IDs make repeated release harmless.
    public final class Permit: Sendable {
        private let queue: ConsentQueue
        private let id: UUID
        /// The turn was taken only after another transaction released it.
        public let waited: Bool

        fileprivate init(queue: ConsentQueue, id: UUID, waited: Bool) {
            self.queue = queue
            self.id = id
            self.waited = waited
        }

        public func release() async { await queue.release(id) }

        deinit {
            let queue = queue, id = id
            Task { await queue.release(id) }
        }
    }
}

/// Refuses, without a panel, the requests that were already waiting behind a
/// review when a human denied an identical request in it.
///
/// A burst of identical requests (parallel tool calls, a retry loop, several
/// `ssh` connections at once) queues behind one panel. When the human presses
/// Deny, the ones already waiting are the same question they just answered, so
/// they are refused rather than raising the same panel again. This is not a
/// cooldown: a request that arrives after the Deny is never matched. Arrivals
/// and the decision are ordered on one monotonic clock, by the instant the
/// human decided rather than when the outcome is recorded, since a mirrored
/// review returns only after the phone's request is withdrawn; nothing is ever
/// compared with the present. Only a human Deny is recorded; a requester that
/// went away or a Touch ID error says nothing about the others.
///
/// "Identical" is the caller's to define through `Shape`. The root is the
/// denied review's default scope; how a waiter must relate to it is the
/// caller's to decide through `matchesRoot` (a secret request: its caller runs
/// inside that root; an SSH request: its own default scope is that root). A
/// request from another terminal or agent always gets its own panel.
public struct HumanDenialLedger<Shape: Hashable & Sendable>: Sendable {
    /// A request's arrival, taken before it waits for a turn.
    public struct Ticket: Sendable, Hashable {
        fileprivate let sequence: UInt64
        fileprivate let arrivedAt: ContinuousClock.Instant
    }

    /// The process a human Deny applied to: the denied review's default scope.
    public struct Root: Sendable, Equatable {
        public let pid: pid_t
        public let startTime: UInt64

        public init(pid: pid_t, startTime: UInt64) {
            self.pid = pid
            self.startTime = startTime
        }
    }

    private struct Denial: Sendable {
        let shape: Shape
        let root: Root
        /// Tickets that arrived strictly before this are the question the
        /// human answered.
        let decidedAt: ContinuousClock.Instant
    }

    /// A backstop only: the records are dropped as soon as no request is
    /// waiting, so this is reached only by a pathological stream of Denies
    /// while one request never leaves. Dropping the oldest can only show a
    /// panel that would have been refused, never refuse one.
    public static var maximumDenials: Int { 64 }

    private var nextSequence: UInt64 = 0
    private var waiting: Set<UInt64> = []
    private var denials: [Denial] = []

    public init() {}

    /// Number of recorded human denials still able to refuse a waiter.
    public var recordedDenials: Int { denials.count }

    /// Called when a request joins the queue for a review turn, before it
    /// waits. `at` exists for tests; production stamps the present.
    public mutating func arrive(at arrivedAt: ContinuousClock.Instant = .now) -> Ticket {
        let ticket = Ticket(sequence: nextSequence, arrivedAt: arrivedAt)
        nextSequence += 1
        waiting.insert(ticket.sequence)
        return ticket
    }

    /// Called when that request leaves, whatever its outcome. Once nothing is
    /// waiting no recorded Deny can match any request, so the records go: none
    /// outlives the requests it could refuse.
    public mutating func depart(_ ticket: Ticket) {
        waiting.remove(ticket.sequence)
        if waiting.isEmpty { denials.removeAll() }
    }

    /// Record a human Deny, made at `decidedAt`, of a request of this shape
    /// reviewed with `root` as its default scope. It matches only requests
    /// that had arrived before the human decided.
    public mutating func recordHumanDenial(
        shape: Shape, root: Root, decidedAt: ContinuousClock.Instant
    ) {
        guard !waiting.isEmpty, root.pid > 0, root.startTime > 0 else { return }
        denials.append(Denial(shape: shape, root: root, decidedAt: decidedAt))
        if denials.count > Self.maximumDenials {
            denials.removeFirst(denials.count - Self.maximumDenials)
        }
    }

    /// Whether a human denied a request of the same shape after this one had
    /// arrived, with `matchesRoot` accepting the denied root for this request.
    /// A request that arrived at or after the decision instant never matches.
    public func refuses(
        _ ticket: Ticket,
        shape: Shape,
        matchesRoot: (Root) -> Bool
    ) -> Bool {
        denials.contains {
            ticket.arrivedAt < $0.decidedAt && $0.shape == shape && matchesRoot($0.root)
        }
    }
}

/// Standalone biometrics share the same presentation queue as embedded reviews.
public struct QueuedConsentProvider: ConsentProvider {
    private let underlying: any ConsentProvider
    private let queue: ConsentQueue

    public init(underlying: any ConsentProvider, queue: ConsentQueue) {
        self.underlying = underlying
        self.queue = queue
    }

    public func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String,
        ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        guard let permit = try? await queue.acquire() else { return .denied }
        let outcome = await underlying.requestConsent(
            caller: caller, newReferences: newReferences, reason: reason,
            ttl: ttl, policySummary: policySummary
        )
        await permit.release()
        return Task.isCancelled ? .denied : outcome
    }

    public func authenticate(reason: String) async -> ConsentOutcome {
        await authenticateExplaining(reason: reason).outcome
    }

    public func authenticateExplaining(reason: String) async -> ConsentAnswer {
        let permit: ConsentQueue.Permit
        do { permit = try await queue.acquire() }
        catch is CancellationError { return .refused(ConsentRefusal(cause: .requesterGone)) }
        catch { return .refused(ConsentRefusal(cause: .notShown)) }
        let answer = await underlying.authenticateExplaining(reason: reason)
        await permit.release()
        guard Task.isCancelled else { return answer }
        var gone = answer.refusal ?? ConsentRefusal(cause: .requesterGone)
        gone.cause = .requesterGone
        return .refused(gone)
    }
}

/// Queue the whole local/phone review race. An embedded review retains the turn
/// until its window closes and the agent consumes or cancels its authentication.
public struct QueuedPolicyReview: PolicyReviewProvider {
    private let underlying: any PolicyReviewProvider
    private let queue: ConsentQueue

    public init(underlying: any PolicyReviewProvider, queue: ConsentQueue) {
        self.underlying = underlying
        self.queue = queue
    }

    public func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        // The request (`HumanWait.current`, nil for a restore-only panel) now
        // waits on a human, whether or not another panel is ahead of it, and
        // is told where one can answer it.
        let wait = HumanWait.current
        let reach = wait == nil ? ApprovalReach.notJudged : await underlying.approvalReach(for: review)
        wait?.notifyWaiting(place: reach.place)
        // A cancelled wait is a withdrawal, not a human denial. An unsafe or
        // unavailable cross-process lock fails without presenting either copy.
        let permit: ConsentQueue.Permit
        do { permit = try await queue.acquire() }
        catch is CancellationError { return .denied(.withdrawn) }
        catch { return .denied(.authenticationFailed) }
        // The parent or original scope can disappear on the turn handoff,
        // before the poll cancels us. Never present such a queued request.
        // Restore-only panels intentionally have no HumanWait: other live
        // waiters may still need them after the displayed requester leaves.
        // Recheck that caller's anchor too, so the restore can choose another
        // live waiter without ever showing the stale queued panel.
        let restoreRequesterGone = wait == nil && review.caller.requestAnchor?.abandonment() != nil
        guard !Task.isCancelled, wait?.abandonment == nil, !restoreRequesterGone else {
            await permit.release()
            return .denied(.withdrawn)
        }
        wait?.markShown()
        // A request that took the turn at once is presented on the judgement
        // its notice was given; one that waited is judged again.
        let outcome = await ApprovalReach.$prejudged.withValue(permit.waited ? nil : reach) {
            await underlying.reviewAccess(review)
        }
        // A human decision ends the deadline's hold on the request, so the
        // approval below is never discarded by it (`HumanWait.decide`). One
        // made after the deadline had already withdrawn the request is too
        // late, and is answered as the withdrawal it lost to.
        var decidedInTime = true
        switch outcome {
        case .approved, .denied(.human):
            decidedInTime = wait?.decide() ?? true
        case .denied:
            break
        }
        guard case let .approved(approval) = outcome else {
            await permit.release()
            // The reason is the reviewer's own and passes through unchanged:
            // whether a Deny propagates depends on who made it.
            return decidedInTime ? outcome : .denied(.timedOut)
        }
        if Task.isCancelled || !decidedInTime {
            await approval.authenticationSession?.cancel()
            await permit.release()
            return .denied(decidedInTime ? .requesterGone : .timedOut)
        }
        guard let session = approval.authenticationSession else {
            // Injected/headless review has no live UI; its separate consent
            // call will acquire the same queue through QueuedConsentProvider.
            await permit.release()
            return outcome
        }
        return .approved(AccessPolicyApproval(
            authenticationSession: QueuedAuthenticationSession(session: session, permit: permit),
            selectedScopeOptionID: approval.selectedScopeOptionID,
            selectedDurationIndex: approval.selectedDurationIndex,
            decisionLatency: approval.decisionLatency,
            pairingLineShown: approval.pairingLineShown,
            decidedOn: approval.decidedOn
        ))
    }

    public func approvalReach(for review: AccessPolicyReview) async -> ApprovalReach {
        await underlying.approvalReach(for: review)
    }

    public func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        guard let permit = try? await queue.acquire() else { return .denied }
        let outcome = await underlying.reviewHostRemediation(review)
        await permit.release()
        return Task.isCancelled ? .denied : outcome
    }
}

private actor QueuedAuthenticationSession: AccessPolicyAuthenticationSession {
    private let session: any AccessPolicyAuthenticationSession
    private var permit: ConsentQueue.Permit?

    init(session: any AccessPolicyAuthenticationSession, permit: ConsentQueue.Permit) {
        self.session = session
        self.permit = permit
    }

    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        guard let permit else { return .denied }
        self.permit = nil
        let outcome = await withTaskCancellationHandler {
            if Task.isCancelled {
                await session.cancel()
                return ConsentOutcome.denied
            }
            return await session.completeAfterPolicyApproval(policySummary: policySummary)
        } onCancel: { [session] in
            Task { await session.cancel() }
        }
        await permit.release()
        return Task.isCancelled ? .denied : outcome
    }

    func cancel() async {
        let permit = permit
        self.permit = nil
        await session.cancel()
        await permit?.release()
    }

    deinit {
        if let permit {
            let session = session
            Task {
                await session.cancel()
                await permit.release()
            }
        }
    }
}
