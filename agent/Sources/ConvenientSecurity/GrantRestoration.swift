import Foundation

/// One row a restore panel lists, and the references its touch reopens.
public struct RestoreEntry: Sendable {
    /// The restored grant the row stands for; nil for an item another
    /// `RestoreItemSource` adds.
    public let grantID: UUID?
    public let row: RestoreReviewRow
    public let references: [SecretRef]

    public init(grantID: UUID?, row: RestoreReviewRow, references: [SecretRef]) {
        self.grantID = grantID
        self.row = row
        self.references = references
    }
}

/// Holds grants the persisted grants item restored: the secret grant table
/// and the SSH signing service.
public protocol RestoredGrantSource: Sendable {
    /// Its restored grants still waiting for the restore panel whose root is
    /// alive, as the panel lists them.
    func restoreEntries() async -> [RestoreEntry]
    /// The restore is over: drop `forgetting`, and let every other restored
    /// grant stop waiting. Returns how many grants were dropped.
    func settleRestore(forgetting: Set<UUID>) async -> Int
}

/// What a restore panel did with an item a `RestoreItemSource` added.
public enum RestoreItemOutcome: Sendable, Equatable {
    /// The touch reopened what the item needs.
    case reopened
    /// The human chose "Forget these approvals". Items are not grants, and
    /// their source decides what, if anything, that forgets.
    case forgotten
}

/// Something besides restored grants that the one restore panel of a daemon
/// lifetime also reopens. The rows it adds are listed and warmed with the
/// grants' rows under the same touch.
public protocol RestoreItemSource: Sendable {
    /// Items that would need an unlock right now (`grantID` nil). The source
    /// decides what "needs" means for its rows; the panel lists them as given.
    func restoreItems() async -> [RestoreEntry]
    func restoreFinished(_ outcome: RestoreItemOutcome) async
    /// References a later request will want from a provider that needs no
    /// csec unlock, so the attended restore fetches them ahead
    /// (`GrantRestoration.fetchAhead`). Nothing is listed or approved by it.
    func fetchAheadReferences() async -> [SecretRef]
}

public extension RestoreItemSource {
    func fetchAheadReferences() async -> [SecretRef] { [] }
}

/// The paired projects of every live, verified Claude Code session, as
/// restore rows: after a restart the values a delegated release would use are
/// cold, and a delegated release never unlocks anything itself, so the one
/// restore panel reopens them under its touch. A row lists what a delegated
/// release there could not resolve now and only the touch can reopen
/// (`SecretResolver.referencesRestorable`). A reference whose provider needs
/// no csec unlock, such as a 1Password one, is never listed: the delegated
/// release fetches it from its provider itself. A project with
/// nothing to reopen gets no row. A use paired for csecd alone
/// (the GitHub token) covers auto mode in every project, so while any live
/// session exists it is reopened too, in an "Every project" row when no
/// live project's row lists it. With delegation off there are no rows. "Forget these approvals" forgets restored grants, never pairings.
public struct DelegationRestoreSource: RestoreItemSource {
    private let delegation: ClaudeDelegationService
    private let resolver: SecretResolver
    private let sshKeys: SSHSigningService?

    public init(delegation: ClaudeDelegationService, resolver: SecretResolver, sshKeys: SSHSigningService? = nil) {
        self.delegation = delegation
        self.resolver = resolver
        self.sshKeys = sshKeys
    }

    public func restoreItems() async -> [RestoreEntry] {
        let (projects, everyProjectUses) = await delegation.livePairings()
        guard !projects.isEmpty || !everyProjectUses.isEmpty else { return [] }
        let keyReferences = await sshKeys?.keyReferences() ?? [:]
        var entries: [RestoreEntry] = []
        var listed: Set<String> = []
        for pairing in projects {
            let uris = pairing.references + pairing.usedReferences
                + pairing.ssh.compactMap({ keyReferences[$0.keyFingerprint] })
            guard let entry = await entry(
                uris, title: pairing.project.displayName,
                detail: "Claude Code auto mode in \(pairing.project.displayDescription)"
            ) else { continue }
            entries.append(entry)
            listed.formUnion(entry.references.map(\.uri))
        }
        // A use paired for every project may be needed by a live session in
        // a project that holds none: its own row, unless a project's row
        // already reopens it.
        if let entry = await entry(
            everyProjectUses.filter { !listed.contains($0) }, title: "Every project",
            detail: "Claude Code auto mode in every project, used inside csec and never released"
        ) {
            entries.append(entry)
        }
        return entries
    }

    private func entry(_ uris: [String], title: String, detail: String) async -> RestoreEntry? {
        var paired: [SecretRef] = []
        for uri in uris {
            guard let reference = try? SecretRef(uri), !paired.contains(reference) else { continue }
            paired.append(reference)
        }
        guard !paired.isEmpty else { return nil }
        // A delegated release fetches a value its provider serves with no
        // csec unlock itself, so the panel reopens only what needs the touch.
        let restorable = await resolver.referencesRestorable(paired)
            .subtracting(await resolver.referencesResolvableWithoutUnlock(paired))
        let references = paired.filter { restorable.contains($0.uri) }
        guard !references.isEmpty else { return nil }
        return RestoreEntry(
            grantID: nil,
            row: RestoreReviewRow(kind: .pairedProject, title: title, detail: detail, references: references.map(\.uri)),
            references: references
        )
    }

    /// Pairings stay whatever the panel's outcome: they are the human's
    /// standing decision about a project, not something this run approved.
    public func restoreFinished(_ outcome: RestoreItemOutcome) async {}

    /// Every paired reference, in every project and not only those of a live
    /// session: a delegated release fetches a 1Password value itself, and
    /// after a restart that fetch is the restarted bridge's first, which
    /// 1Password authorizes only with a person there to answer it. Sessions
    /// start all day after an install, mostly unattended, so the attended
    /// restore fetches what any of them could be released.
    public func fetchAheadReferences() async -> [SecretRef] {
        await delegation.allPairedReferences().compactMap { try? SecretRef($0) }
    }
}

/// The restart warm-up: one panel per daemon lifetime that reopens, with a
/// single touch, the sealed stores behind what the human approved before
/// csecd restarted.
///
/// A restored grant matches exactly as it did before the restart, but the
/// providers that seal its values start cold, and a covered release carries
/// no unlock. The attended install, or the first covered request that needs
/// one after another restart, raises the panel, and
/// every concurrent request needing it (secret or SSH) waits on that same
/// panel: the restore is single-flight. Its rows are every restored grant
/// needing an unlock at that moment, not only the requester's.
///
/// - Approve: the approval's unlock — the touch's context, or the remote
///   unlock a paired phone's approval opened — reopens exactly the listed
///   batch (`SecretResolver.warm`, local reads only), is then invalidated, and
///   every waiter proceeds with no unlock. Only what it actually opened counts
///   as reopened. A grant that still could not be reopened is dropped, so its
///   next request gets an ordinary panel; a paired project's row that stayed
///   cold leaves the restore unused, so a later request raises it again.
/// - "Forget these approvals" (the human's Deny): the listed grants are
///   dropped, the removal is persisted before anyone is answered, and every
///   request that was waiting when the human decided is refused. One that
///   joined afterwards is told the restore is over and gets its own panel.
/// - Either one uses the restore up (an approval, unless a paired project's
///   row stayed cold); it never returns in this daemon lifetime.
///   A waiter re-checks its grants at the present afterwards: one that
///   expired or was revoked while the panel was up covers nothing.
/// - Every waiter is answered before the outcome is logged, so a request that
///   arrives during the log write never joins a flight that is already over.
/// - Every waiter going away closes the panel without using the restore up or
///   dropping anything; a later covered request raises it again. A panel
///   closed because the requester it showed went away (the unlock re-present
///   check) is raised again for the waiters still running.
/// - A request that also asks for new references gets one panel for both: the
///   access path claims the restore (`claimForMixedPanel`) and reports its
///   outcome back (`completeClaim`).
///
/// The panel goes through the shared policy reviewer, so it holds the ordinary
/// UI turn and never overlaps another panel, and it reaches the paired phone
/// exactly when a phone approval could reopen every row it lists
/// (`MirroredPolicyReview`); a row no phone approval could reopen keeps it on
/// this Mac.
public actor GrantRestoration {
    /// What a request waiting on the restore gets back.
    public enum Wait: Sendable, Equatable {
        /// Reopened: resolve with no unlock.
        case warmed
        /// The human chose "Forget these approvals".
        case forgotten
        /// Nothing this request needs is waiting for the restore — or the
        /// approval could not reopen it: a grant it rests on was dropped, or
        /// a paired project's row waits for a later restore. Judged again.
        case notNeeded
        /// The restore already happened in this daemon lifetime.
        case usedUp
        /// This request's requester went away while it waited.
        case requesterGone
        /// The panel failed (a Touch ID error), or an explicit whole-batch
        /// restore could not reopen every row. Authentication failure leaves
        /// restoration unused; an incomplete reopen follows normal settlement.
        case failed
    }

    /// The restore section a mixed panel carries.
    public struct Claim: Sendable {
        public let id: UUID
        public let details: RestoreReviewDetails
    }

    public enum ClaimResult: Sendable {
        case claimed(Claim)
        /// Another panel is restoring; wait on it with `ensureWarm`.
        case inFlight
        case notNeeded
        case usedUp
    }

    public enum ClaimOutcome: Sendable {
        /// Approved: `unlock` is the panel's context, which the caller still
        /// uses for its own new references and invalidates afterwards.
        case approved(unlock: CacheUnlock?, approval: AccessPolicyApproval)
        case denied(AccessPolicyDenialReason)
        /// Approved on screen, but the approval could not be completed.
        case failed
    }

    private enum Presenter: Equatable {
        /// A restore-only panel this actor presents.
        case panel
        /// The restore section of a mixed panel the access path presents.
        case mixed
    }

    private struct Waiter {
        let id: UUID
        let caller: CallerInfo
        /// What the request waits on the restore for; nil means the entire
        /// daemon-selected batch (`csec restore`), including refreshed rows.
        let references: Set<String>?
        let continuation: CheckedContinuation<Wait, Never>
    }

    private struct Flight {
        let id: UUID
        var presenter: Presenter
        var entries: [RestoreEntry]
        var waiters: [Waiter] = []
        var presenting = false
        var reviewTask: Task<AccessPolicyReviewOutcome, Never>?
        /// Set once the panel returned a decision: from then on a waiter
        /// leaving can no longer close it.
        var deciding = false
        /// The waiters there were when the decision came back: the requests
        /// it answered. One that joins while the outcome is being applied
        /// arrived after the human decided.
        var decidedWaiters: Set<UUID> = []
        /// The waiter the restore-only panel on screen was raised for; nil
        /// for a mixed panel, whose requester is the claimant, not a waiter.
        var shownWaiter: UUID?
        var presentations = 0

        mutating func markDecided() {
            deciding = true
            decidedWaiters = Set(waiters.map(\.id))
        }
    }

    /// A bound on re-presenting one restore after panels closed because the
    /// requester they showed went away, not a clock: each re-present needs a
    /// requester to have exited, so this only stops a pathological loop.
    private static let maximumPresentations = 16

    private let resolver: SecretResolver
    private let policyReview: any PolicyReviewProvider
    private let consent: any ConsentProvider
    private let persistence: GrantPersistence?
    private let decisionLog: DecisionLog?
    private let terminalInspection: TerminalSessionInspector
    private var grantSources: [any RestoredGrantSource] = []
    private var itemSources: [any RestoreItemSource] = []
    private var cause: CsecdRestartCause?
    private var usedUp = false
    private var flight: Flight?

    /// What started a fetch ahead, for its log record.
    private enum FetchAheadTrigger {
        /// The attended install's `csec restore`.
        case restore
        /// A panel a person approved at this Mac.
        case approvalAtMac
    }

    /// The fetch ahead running now, whoever started it. One at a time, so a
    /// provider whose own app asks for authorization asks once, not once per
    /// approval made while it waits for an answer.
    private var fetchAheadRun: (id: UUID, task: Task<FetchAheadSummary?, Never>)?

    public init(
        resolver: SecretResolver,
        policyReview: any PolicyReviewProvider,
        consent: any ConsentProvider,
        persistence: GrantPersistence? = nil,
        decisionLog: DecisionLog? = nil,
        terminalInspection: TerminalSessionInspector
    ) {
        self.resolver = resolver
        self.policyReview = policyReview
        self.consent = consent
        self.persistence = persistence
        self.decisionLog = decisionLog
        self.terminalInspection = terminalInspection
    }

    public func addGrantSource(_ source: any RestoredGrantSource) {
        grantSources.append(source)
    }

    /// Adds rows of another kind to the restore panel (paired projects).
    public func addItemSource(_ source: any RestoreItemSource) {
        itemSources.append(source)
    }

    /// Why the previous csecd stopped, for the panel's header.
    public func setRestartCause(_ cause: CsecdRestartCause?) {
        self.cause = cause
    }

    /// Whether this daemon lifetime's restore has happened (approved or
    /// forgotten).
    public var isUsedUp: Bool { usedUp }

    /// Requests waiting on the restore now.
    public var waitingCount: Int { flight?.waiters.count ?? 0 }

    /// The attended install owns a real request, keeping one restore alive
    /// while short-lived secret/SSH requests join and leave it. This follows
    /// exactly the ordinary review, cancellation and caller-liveness paths.
    /// No values or grants are delivered to this caller.
    public func restoreApprovals(requester: CallerInfo) async -> Wait {
        guard !Task.isCancelled else { return .requesterGone }
        if flight == nil {
            if usedUp { return .usedUp }
            let entries = await pendingEntries()
            if flight == nil {
                if usedUp { return .usedUp }
                guard !entries.isEmpty else { return .notNeeded }
                flight = Flight(id: UUID(), presenter: .panel, entries: entries)
            }
        }
        return await join(requester, references: nil)
    }

    /// The attended restore's second half: fetch what the item sources say a
    /// later request will want from a provider that needs no csec unlock
    /// (`SecretResolver.fetchAhead`), while the person whose `csec restore`
    /// this is can answer that provider's own authorization. Raises no csec
    /// panel and approves nothing: a later release still passes every gate.
    /// Logged once, value-free, when anything was fetched or failed. Nil when
    /// no source names a reference (delegated approvals off, or no pairing).
    /// A run an approval started first is waited for, and this one then finds
    /// held whatever that one got.
    public func fetchAhead() async -> FetchAheadSummary? {
        while let running = fetchAheadRun {
            _ = await running.task.value
        }
        let run = startFetchAhead(.restore)
        return await withTaskCancellationHandler {
            await run.task.value
        } onCancel: {
            run.task.cancel()
        }
    }

    /// A person approved a panel at this Mac: the restore panel, a release
    /// panel or an SSH signing panel, never one approved on the phone, as
    /// nobody need be at the Mac for that. Fetch ahead again while they are
    /// here, so that a value an unattended release will want, and that no
    /// attended `csec restore` fetched (a reboot raises its restore panel
    /// from a request) or that the provider then refused, is asked for now
    /// rather than at night with nobody to answer. Held values are counted
    /// from csecd's own cache without asking the provider, so with
    /// everything held this asks nothing and logs nothing; otherwise the
    /// provider asks at most once per source it serves from (its own
    /// `fetchAhead` rule). Returns at once: the approved request never waits
    /// on it. Skipped while a fetch ahead is already running.
    public func approvedAtMac() {
        guard fetchAheadRun == nil else { return }
        _ = startFetchAhead(.approvalAtMac)
    }

    /// Waits for the fetch ahead running now, if any. For tests: the one an
    /// approval starts runs on its own.
    public func fetchAheadSettled() async {
        while let running = fetchAheadRun {
            _ = await running.task.value
        }
    }

    private func startFetchAhead(_ trigger: FetchAheadTrigger) -> (id: UUID, task: Task<FetchAheadSummary?, Never>) {
        let id = UUID()
        // Its own task, which no request's wait bounds: it belongs to no
        // request (`HumanWait.current`), as the restore-only panel does not.
        let task = HumanWait.$current.withValue(nil) {
            Task { () -> FetchAheadSummary? in
                let summary = await self.fetchAheadNow(trigger)
                self.fetchAheadEnded(id)
                return summary
            }
        }
        fetchAheadRun = (id, task)
        return (id, task)
    }

    private func fetchAheadEnded(_ id: UUID) {
        if fetchAheadRun?.id == id { fetchAheadRun = nil }
    }

    private func fetchAheadNow(_ trigger: FetchAheadTrigger) async -> FetchAheadSummary? {
        guard !Task.isCancelled else { return nil }
        var references: [SecretRef] = []
        for source in itemSources {
            references += await source.fetchAheadReferences()
        }
        guard !references.isEmpty else { return nil }
        let report = await resolver.fetchAhead(references)
        let summary = report.summary
        guard summary.fetched > 0 || summary.failureCount > 0, let decisionLog else { return summary }
        // Distinct reasons with counts, over every failure: the detail is
        // bounded, and `refs` names the references the summary lists.
        let reasons = report.reasonCounts.map { "\($0.reason) (\($0.count))" }.joined(separator: "; ")
        let started: String
        switch trigger {
        case .restore: started = cause.map { "csecd restarted (\($0.rawValue)); " } ?? ""
        case .approvalAtMac: started = "after an approval at this Mac; "
        }
        await decisionLog.record(DecisionLogRecord(
            kind: .fetchAhead,
            surface: .restore,
            refs: summary.failures.isEmpty ? nil : summary.failures.map(\.reference),
            cause: trigger == .restore ? DecisionLogPromptCause.restartRestore.rawValue : nil,
            detail: started
                + "fetched \(summary.fetched), already held \(summary.alreadyHeld), failed \(summary.failureCount)"
                + (reasons.isEmpty ? "" : ": " + reasons)
        ))
        return summary
    }

    /// Called by a covered request whose `references` rest on restored grants
    /// still waiting for the restore. Returns at once when none of them needs
    /// an unlock; otherwise raises the restore panel, or waits on the one
    /// already up, and returns its outcome.
    public func ensureWarm(for references: [SecretRef], requester: CallerInfo) async -> Wait {
        if flight == nil {
            if usedUp { return .usedUp }
            guard await resolver.requiresUnlock(references) else { return .notNeeded }
            if flight == nil {
                if usedUp { return .usedUp }
                let entries = await pendingEntries()
                if flight == nil {
                    if usedUp { return .usedUp }
                    guard !entries.isEmpty else { return .notNeeded }
                    flight = Flight(id: UUID(), presenter: .panel, entries: entries)
                }
            }
        }
        return await join(requester, references: references)
    }

    /// Called by a delegation-eligible request (every gate holds, its
    /// references are paired) whose paired references a delegated release
    /// could not resolve: the restore's second trigger. Raises the restore
    /// panel, or joins the one already up and waits for its outcome. This
    /// join is how delegation "waits for an in-flight restore before
    /// declining": a request never declines as not held while a panel in
    /// flight may reopen what it needs. Only references this lifetime's touch
    /// could reopen take part (`SecretResolver.referencesRestorable`): one no
    /// touch reopens, such as a 1Password value csecd never cached or whose
    /// cache entry was invalidated, neither raises nor joins a panel and
    /// declines as not held at once. A delegated release never sends one whose
    /// provider needs no csec unlock: it fetched that from the provider. A request of a lifetime whose restore is
    /// used up gets `.usedUp` and declines as not held. The caller judges the
    /// request again after any of these outcomes: while the panel was up its
    /// grants, pairing or delegation itself may have changed.
    public func ensureWarmForDelegation(for references: [SecretRef], requester: CallerInfo) async -> Wait {
        if flight == nil, usedUp { return .usedUp }
        guard !(await resolver.referencesRestorable(references)).isEmpty else { return .notNeeded }
        if flight == nil {
            if usedUp { return .usedUp }
            let entries = await pendingEntries()
            if flight == nil {
                if usedUp { return .usedUp }
                guard !entries.isEmpty else { return .notNeeded }
                flight = Flight(id: UUID(), presenter: .panel, entries: entries)
            }
        }
        return await join(requester, references: references)
    }

    /// Claims the restore for the one panel of a request that also asks for
    /// new references. The caller presents it with the returned section,
    /// then reports the outcome with `completeClaim`.
    public func claimForMixedPanel(for references: [SecretRef]) async -> ClaimResult {
        if flight != nil { return .inFlight }
        if usedUp { return .usedUp }
        guard await resolver.requiresUnlock(references) else { return .notNeeded }
        let entries = await pendingEntries()
        if flight != nil { return .inFlight }
        if usedUp { return .usedUp }
        guard !entries.isEmpty else { return .notNeeded }
        let id = UUID()
        flight = Flight(id: id, presenter: .mixed, entries: entries)
        return .claimed(Claim(id: id, details: await details(for: entries)))
    }

    /// The outcome of a mixed panel's restore section. Approval reopens the
    /// listed batch with the panel's context (the caller invalidates it after
    /// resolving its own references); the human's Deny forgets the batch; a
    /// requester that went away leaves the restore unused, raised again as a
    /// restore-only panel for anyone else waiting on it.
    public func completeClaim(_ claim: Claim, outcome: ClaimOutcome) async {
        guard var current = flight, current.id == claim.id, current.presenter == .mixed else { return }
        current.markDecided()
        flight = current
        switch outcome {
        case let .approved(unlock, approval):
            await reopen(claim.id, unlock: unlock, invalidateAfterward: false, approval: approval, shown: nil)
        case let .denied(reason):
            await concluded(claim.id, denial: reason, shown: nil)
        case .failed:
            await failed(claim.id, shown: nil)
        }
    }

    // MARK: - Waiting

    private func join(_ requester: CallerInfo, references: [SecretRef]?) async -> Wait {
        let id = UUID()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Wait, Never>) in
                guard flight != nil else {
                    continuation.resume(returning: usedUp ? .usedUp : .notNeeded)
                    return
                }
                if Task.isCancelled {
                    continuation.resume(returning: .requesterGone)
                    closeIfUnwatched()
                    return
                }
                flight?.waiters.append(Waiter(
                    id: id, caller: requester, references: references.map { Set($0.map(\.uri)) },
                    continuation: continuation
                ))
                // This request now waits on a human: tell its session, once.
                HumanWait.current?.notifyWaiting()
                if let current = flight, current.presenter == .panel,
                   !current.presenting, !current.deciding {
                    startPresentation()
                }
            }
        } onCancel: {
            Task { await self.leave(id) }
        }
    }

    private func leave(_ id: UUID) {
        guard let index = flight?.waiters.firstIndex(where: { $0.id == id }),
              let waiter = flight?.waiters.remove(at: index) else { return }
        waiter.continuation.resume(returning: .requesterGone)
        // A shared restore may still have live waiters, but it must not keep
        // the orphaned displayed caller's context. Its cancellation outcome
        // selects a survivor. A live caller with another waiting request can
        // keep the existing panel, as before.
        if let current = flight, current.presenter == .panel,
           current.shownWaiter == id, !current.waiters.isEmpty, !current.deciding,
           !AccessReviewRequester.isAlive(waiter.caller) {
            current.reviewTask?.cancel()
        }
        closeIfUnwatched()
    }

    /// Every waiter left a restore-only panel that has not been decided:
    /// close it, and its outcome comes back as `.requesterGone`. One not on
    /// screen yet simply ends; `present` notices on its own if it is midway.
    private func closeIfUnwatched() {
        guard let current = flight, current.presenter == .panel,
              current.waiters.isEmpty, !current.deciding else { return }
        if let reviewTask = current.reviewTask {
            reviewTask.cancel()
        } else if !current.presenting {
            endFlight(current.id, answering: .requesterGone)
        }
    }

    // MARK: - The restore-only panel

    private func startPresentation() {
        guard let flightID = flight?.id else { return }
        flight?.presenting = true
        flight?.presentations += 1
        // The panel belongs to every waiter, not to the request whose join
        // happened to start it: it must not inherit that request's wait, or
        // its deadline latch and notice (`HumanWait.current`).
        HumanWait.$current.withValue(nil) {
            Task { await self.present(flightID) }
        }
    }

    private func present(_ flightID: UUID) async {
        // Rows are taken fresh at each presentation: a root may have exited.
        let entries = await pendingEntries()
        guard let current = flight, current.id == flightID else { return }
        guard !entries.isEmpty else {
            endFlight(flightID, answering: .notNeeded)
            return
        }
        flight?.entries = entries
        guard let shownWaiter = current.waiters.first(where: {
            AccessReviewRequester.isAlive($0.caller)
        }) ?? current.waiters.first else {
            endFlight(flightID, answering: .requesterGone)
            return
        }
        flight?.shownWaiter = shownWaiter.id
        var shown = shownWaiter.caller
        shown.terminal = await terminalInspection.context(forCallerPID: shown.pid)
        let review = AccessPolicyReview.restoreOnly(caller: shown, restore: await details(for: entries))
        guard let ready = flight, ready.id == flightID else { return }
        guard !ready.waiters.isEmpty else {
            // Everyone left before the panel was shown: nothing to decide.
            endFlight(flightID, answering: .requesterGone)
            return
        }
        // Terminal lookup and restore descriptions awaited above. If the
        // chosen caller left meanwhile, choose a live waiter before either
        // the Mac or its phone mirror is presented.
        guard AccessReviewRequester.isAlive(shown) else {
            await requesterWentAway(flightID, shown: shown)
            return
        }
        let reviewer = policyReview
        let reviewTask = Task { await reviewer.reviewAccess(review) }
        flight?.reviewTask = reviewTask
        let outcome = await reviewTask.value
        guard let decided = flight, decided.id == flightID else { return }
        flight?.reviewTask = nil
        flight?.markDecided()
        switch outcome {
        case let .approved(approval):
            let completion: ConsentOutcome
            if let session = approval.authenticationSession {
                completion = await session.completeAfterPolicyApproval(
                    policySummary: "reopen \(review.restore?.storeCount ?? 0) stores csecd held before "
                        + "it restarted; nothing new is approved"
                )
            } else {
                completion = await consent.requestConsent(
                    caller: shown,
                    newReferences: entries.flatMap(\.references),
                    reason: review.reason,
                    ttl: nil,
                    policySummary: "reopen approvals after csecd restarted"
                )
            }
            guard case let .approved(unlock) = completion else {
                await failed(flightID, shown: shown)
                return
            }
            // Before any waiter is answered, so its request resolves after it.
            if approval.decidedOn == .mac { await resolver.personApprovedAtMac() }
            await reopen(flightID, unlock: unlock, invalidateAfterward: true, approval: approval, shown: shown)
            // After every waiter was answered. A mixed panel's approval is
            // the access path's, which starts it there.
            if approval.decidedOn == .mac { approvedAtMac() }
        case let .denied(reason):
            await concluded(flightID, denial: reason, shown: shown)
        }
    }

    private func concluded(_ flightID: UUID, denial: AccessPolicyDenialReason, shown: CallerInfo?) async {
        switch denial {
        case .human:
            await forget(flightID, denial: denial, shown: shown)
        case .requesterGone, .withdrawn, .timedOut:
            // Nobody decided: the restore stays unused, raised again for
            // anyone else waiting on it.
            await requesterWentAway(flightID, shown: shown)
        case .authenticationFailed:
            await failed(flightID, shown: shown)
        }
    }

    // MARK: - Outcomes

    /// Approved: reopen the listed batch with the one evaluated context, and
    /// use it for nothing else. Only what that actually opened counts as
    /// reopened — a restored grant once its providers need no unlock, a paired
    /// project's row once csecd holds each of its values, which is how a
    /// delegated release resolves them. An approval can open less than it
    /// listed (a phone approval whose copies did not all open): a grant it
    /// left cold is dropped, so its next request gets an ordinary panel; a
    /// paired project's row it left cold keeps the restore unused, so a later
    /// request raises it again for what is still cold. Nothing left cold is
    /// logged, reported to its source or answered as reopened.
    private func reopen(
        _ flightID: UUID,
        unlock: CacheUnlock?,
        invalidateAfterward: Bool,
        approval: AccessPolicyApproval,
        shown: CallerInfo?
    ) async {
        guard let current = flight, current.id == flightID else { return }
        let entries = current.entries
        if let unlock {
            await resolver.warm(entries.flatMap(\.references), unlock: unlock)
            if invalidateAfterward { unlock.invalidate() }
        }
        var coldGrants: [RestoreEntry] = []
        var coldItems = 0
        var reopened: [RestoreEntry] = []
        var coldReferences: Set<String> = []
        for entry in entries {
            let stayedCold: Bool
            if entry.grantID != nil {
                stayedCold = await resolver.requiresUnlock(entry.references)
                if stayedCold { coldGrants.append(entry) }
            } else {
                stayedCold = !(await resolver.referencesNotHeld(entry.references)).isEmpty
                if stayedCold { coldItems += 1 }
            }
            if stayedCold {
                coldReferences.formUnion(entry.references.map(\.uri))
            } else {
                reopened.append(entry)
            }
        }
        usedUp = coldItems == 0
        let dropped = await settle(forgetting: Set(coldGrants.compactMap(\.grantID)))
        if usedUp {
            for source in itemSources { await source.restoreFinished(.reopened) }
        }
        // Every waiter is answered before the record is written, so a request
        // arriving during the write finds the restore over rather than a
        // flight that will answer it without a panel.
        endFlight(flightID, answering: .warmed, stillCold: coldReferences)
        let decision = DecisionLogRecord.outcome(for: approval)
        var detail = "reopened what csecd approved before it restarted"
        let coldCount = entries.count - reopened.count
        if coldCount > 0 {
            detail = "reopened \(reopened.count) of \(entries.count) approvals csecd held before it restarted; "
                + "\(coldCount) could not be reopened"
            if !coldGrants.isEmpty { detail += "; \(coldGrants.count) restored grants were dropped" }
            if coldItems > 0 { detail += "; the restore stays unused for \(coldItems) paired projects" }
        }
        await recordRestore(
            entries: entries, reopened: reopened,
            outcome: decision.outcome, decider: decision.decider, ttdMs: decision.ttdMs,
            dropped: dropped > 0 ? ["not_reopened": dropped] : nil, shown: shown,
            detail: detail
        )
    }

    /// "Forget these approvals": the human's Deny drops every listed grant,
    /// persisted before any waiter is answered. Only the requests that were
    /// waiting when the human decided are refused; one that joined while the
    /// forget was being persisted is told the restore is over, and gets a
    /// panel of its own for whatever is no longer covered.
    private func forget(_ flightID: UUID, denial: AccessPolicyDenialReason, shown: CallerInfo?) async {
        guard let current = flight, current.id == flightID else { return }
        usedUp = true
        let entries = current.entries
        let dropped = await settle(forgetting: Set(entries.compactMap(\.grantID)))
        for source in itemSources { await source.restoreFinished(.forgotten) }
        endFlight(flightID, answering: .forgotten, latecomers: .usedUp)
        let decision = DecisionLogRecord.outcome(for: denial)
        await recordRestore(
            entries: entries, reopened: [],
            outcome: decision.outcome, decider: decision.decider, ttdMs: decision.ttdMs,
            dropped: dropped > 0 ? ["forgotten": dropped] : nil, shown: shown,
            detail: "forgot what csecd approved before it restarted"
        )
    }

    /// The panel closed because its requester went away. Waiters whose
    /// process is gone are answered; if any are still running, the panel is
    /// raised again for them. Otherwise the restore stays unused and nothing
    /// is dropped.
    private func requesterWentAway(_ flightID: UUID, shown: CallerInfo?) async {
        guard var current = flight, current.id == flightID else { return }
        let running = current.waiters.filter { AccessReviewRequester.isAlive($0.caller) }
        for waiter in current.waiters where !AccessReviewRequester.isAlive(waiter.caller) {
            waiter.continuation.resume(returning: .requesterGone)
        }
        current.waiters = running
        current.presenter = .panel
        current.presenting = false
        current.deciding = false
        current.decidedWaiters = []
        current.shownWaiter = nil
        current.reviewTask = nil
        flight = current
        guard !running.isEmpty, current.presentations < Self.maximumPresentations else {
            let entries = current.entries
            endFlight(flightID, answering: running.isEmpty ? .requesterGone : .failed)
            await recordRestore(
                entries: entries, reopened: [], outcome: .requesterGone, decider: nil,
                ttdMs: nil, dropped: nil, shown: shown,
                detail: "every waiting requester went away; nothing was reopened or dropped"
            )
            return
        }
        startPresentation()
    }

    /// No decision (a Touch ID error, which says nothing about what the human
    /// wants): nothing is reopened or dropped and the restore is not used up.
    /// The request the failed panel was raised for gets the failure (for
    /// a mixed panel, its claimant, which the access path answers), as does
    /// every explicit whole-batch waiter: an install never retries a failed
    /// authentication, even when it joined someone else's panel. Every
    /// other waiter still running gets a fresh presentation of the restore,
    /// within the presentation bound. With no such waiter the flight ends.
    private func failed(_ flightID: UUID, shown: CallerInfo?) async {
        guard var current = flight, current.id == flightID else { return }
        let entries = current.entries
        var remaining: [Waiter] = []
        for waiter in current.waiters {
            if waiter.id == current.shownWaiter || waiter.references == nil {
                waiter.continuation.resume(returning: .failed)
            } else if !AccessReviewRequester.isAlive(waiter.caller) {
                waiter.continuation.resume(returning: .requesterGone)
            } else {
                remaining.append(waiter)
            }
        }
        current.waiters = remaining
        flight = current
        if remaining.isEmpty || current.presentations >= Self.maximumPresentations {
            endFlight(flightID, answering: .failed)
        } else {
            current.presenter = .panel
            current.presenting = false
            current.deciding = false
            current.decidedWaiters = []
            current.shownWaiter = nil
            current.reviewTask = nil
            flight = current
            startPresentation()
        }
        await recordRestore(
            entries: entries, reopened: [], outcome: .authenticationFailed, decider: nil,
            ttdMs: nil, dropped: nil, shown: shown,
            detail: "the restore panel ended without a decision; nothing was reopened or dropped"
        )
    }

    /// Answers every waiter with `wait`, and ends the flight. With
    /// `latecomers`, a waiter that joined after the panel's decision came back
    /// is answered with that instead. A waiter told `.warmed` that waits on
    /// any of `stillCold` is told `.notNeeded` instead: nothing reopened it.
    /// A whole-batch waiter gets `.failed` if any listed reference stayed cold.
    private func endFlight(
        _ flightID: UUID,
        answering wait: Wait,
        latecomers: Wait? = nil,
        stillCold: Set<String> = []
    ) {
        guard let current = flight, current.id == flightID else { return }
        flight = nil
        for waiter in current.waiters {
            let arrivedLate = current.deciding && !current.decidedWaiters.contains(waiter.id)
            var answer = arrivedLate ? (latecomers ?? wait) : wait
            if answer == .warmed {
                if let references = waiter.references {
                    if !references.isDisjoint(with: stillCold) { answer = .notNeeded }
                } else if !stillCold.isEmpty {
                    // The installer must not announce a complete restore if
                    // even one listed row stayed cold. Never retry its touch.
                    answer = .failed
                }
            }
            waiter.continuation.resume(returning: answer)
        }
    }

    /// Ends the restore in every grant source, and persists any grants that
    /// were dropped before a waiter is answered: a forgotten grant written
    /// back by a later restart would be one the human refused.
    private func settle(forgetting forgotten: Set<UUID>) async -> Int {
        var dropped = 0
        for source in grantSources {
            dropped += await source.settleRestore(forgetting: forgotten)
        }
        if dropped > 0, let failure = await persistence?.persistNow() {
            FileHandle.standardError.write(Data(
                "csecd: forgotten restored grants could not be persisted: \(failure)\n".utf8
            ))
        }
        return dropped
    }

    // MARK: - Rows

    /// Every restored grant that needs an unlock right now, and every item
    /// its source says needs reopening.
    private func pendingEntries() async -> [RestoreEntry] {
        var needing: [RestoreEntry] = []
        for source in grantSources {
            for entry in await source.restoreEntries() where await resolver.requiresUnlock(entry.references) {
                needing.append(entry)
            }
        }
        for source in itemSources { needing += await source.restoreItems() }
        return needing
    }

    /// The restore section for `entries`. The store count is the credential
    /// groups (for a native reference, its store) that actually need the unlock.
    private func details(for entries: [RestoreEntry]) async -> RestoreReviewDetails {
        let references = entries.flatMap(\.references)
        let cold = await resolver.referencesRequiringUnlock(references)
        let coldReferences = Array(Set(references.filter { cold.contains($0.uri) }))
        // Each row names its references as a release names its secrets.
        let described = await resolver.reviewSecrets(for: references)
        return RestoreReviewDetails(
            cause: cause,
            rows: entries.map { $0.row.described(by: described) },
            storeCount: max(1, CredentialGrouping.groups(for: coldReferences).count)
        )
    }

    private func recordRestore(
        entries: [RestoreEntry],
        reopened: [RestoreEntry],
        outcome: DecisionLogRecord.Outcome,
        decider: DecisionLogRecord.Decider?,
        ttdMs: Int?,
        dropped: [String: Int]?,
        shown: CallerInfo?,
        detail: String
    ) async {
        guard let decisionLog else { return }
        var record = DecisionLogRecord(
            kind: .restore,
            surface: .restore,
            requester: shown.map {
                DecisionLogRecord.Requester(
                    class: "restore", rootPID: $0.pid, terminal: $0.terminal?.summary
                )
            },
            refs: Array(Set(entries.flatMap(\.references).map(\.uri))).sorted(),
            outcome: outcome,
            decider: decider,
            ttdMs: ttdMs,
            cause: DecisionLogPromptCause.restartRestore.rawValue,
            grantIDs: entries.compactMap { $0.grantID?.uuidString.lowercased() },
            detail: (cause.map { "csecd restarted (\($0.rawValue)); " } ?? "") + detail
        )
        record.grants = DecisionLogRecord.GrantCounts(
            secret: reopened.filter { $0.row.kind == .secretGrant }.count,
            ssh: reopened.filter { $0.row.kind == .sshGrant }.count,
            dropped: dropped
        )
        await decisionLog.record(record)
    }
}
