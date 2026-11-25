import Foundation

/// The policy core: matches callers against subtree grants, gates newly-seen
/// references through consent, then resolves the approved references.
public actor Agent {
    /// One open `csec edit` session, owned by the exact process incarnation that
    /// opened it. Nothing here records a deadline: an edit ends when it is saved,
    /// cancelled, or when the editor process it belongs to is gone. A human may
    /// sit in an editor for as long as they like without losing the edit.
    private struct NativeEditAuthorization {
        let callerPID: pid_t
        let callerStartTime: UInt64
        let store: NativeStoreName
        let mode: NativeStoreEditorMode

        func isLive(using inspection: ProcessInspection) -> Bool {
            callerPID > 1 && callerStartTime > 0
                && inspection.startTime(of: callerPID) == callerStartTime
        }
    }

    private struct RedactionCaller: Sendable {
        let pid: pid_t
        let startTime: UInt64

        func matches(_ caller: CallerInfo) -> Bool {
            caller.pid == pid && caller.startTime == startTime
        }

        func isLive(using inspection: ProcessInspection) -> Bool {
            pid > 1 && startTime > 0 && inspection.startTime(of: pid) == startTime
        }
    }

    private struct RedactionSession: Sendable {
        let caller: RedactionCaller
        let destination: DestinationClass
        var redactors: [OutputRedactionStream: StreamingOutputRedactor]
        var finishedStreams: Set<OutputRedactionStream>
        var registryGeneration: UInt64
        let includeShortValues: Bool
        let labelStyle: OutputRedactionLabelStyle
    }

    private struct RegisteredSession: Sendable {
        let rootPID: pid_t
        let rootStartTime: UInt64
        let auditSessionID: UInt32?
    }

    /// What makes two access requests the same question for a human Deny: the
    /// whole requested reference set and the release shape, the same pair a
    /// widened grant is reused on. The command itself is deliberately absent,
    /// as it is from a widened grant.
    private struct AccessDenialShape: Hashable, Sendable {
        let references: Set<String>
        let releaseShapeDigest: String
        /// A lasting GitHub request shares its release shape with ordinary
        /// `gh` use, but a Deny of one answers only the other lasting
        /// requests waiting with it, and the reverse.
        let lastingAccess: Bool
    }

    /// What csecd remembers of one approval this run, so a later panel for
    /// the same references can say why it appeared. Bounded by count, never
    /// by a clock, and holding no more than the grant itself did.
    private struct ApprovalMemory: Sendable {
        let references: Set<String>
        let rootPID: pid_t
        let rootStartTime: UInt64
        let expiresAt: Date?
        let grantIDs: [String]
        var revoked = false
    }

    private static let maximumApprovalMemories = 256

    private static let maximumOutputChunkBytes = 64 * 1024
    /// Live output-redaction sessions, one per running `csec ai` or protected
    /// launch. A session lasts as long as its command, and every coding-agent
    /// session on the Mac holds some at once: test runs, `until` loops waiting
    /// on a file, background jobs and (wrapped like Bash) Claude Code's
    /// Monitor watches, which can run for the whole session. A request over
    /// the bound runs its command without csec, unscanned and with no secrets,
    /// so the bound must sit far above that load: 12 agent sessions held 34 on
    /// 17 Oct. It only stops runaway growth; each session holds a few
    /// streaming redactors over one shared pattern list.
    public static let maximumRedactionSessions = 256
    private static let maximumRegisteredSessions = 64
    // Whole-file import batch bounds. A single csec exec/import call carries the
    // files' bytes over the socket; hundreds of small dotenv files or a handful
    // of large ones fit, and larger sets are imported in successive batches.
    private static let maximumImportBlobs = 256
    private static let maximumImportTotalBytes = 16 * 1024 * 1024

    private let resolver: SecretResolver
    private let grants: GrantTable
    private let consent: ConsentProvider
    private let policyReview: PolicyReviewProvider
    private let nativeStore: NativeEncryptedFileProvider?
    private let sshSigningService: SSHSigningService?
    /// The GitHub token proxy's registration. Nil: `csec github` and
    /// `csec protect --gh` report the proxy unavailable.
    private let githubProxy: GitHubProxyService?
    private let automationService: AutomationService?
    private let allowLegacyAccessForTesting: Bool
    private let allowUnverifiedPlansForTesting: Bool
    private let allowUnverifiedAutomationCallersForTesting: Bool
    /// Kernel process metadata used to resolve and re-verify grant scopes.
    /// Production always uses `.live`; the seam keeps synthetic-ancestry tests
    /// possible without weakening any release check.
    private let processInspection: ProcessInspection
    /// Resolves the terminal tab a request came from, only when a review is
    /// about to be shown: the lookup asks the terminal application over
    /// AppleScript, so it is never paid on the grant-reuse path.
    private let terminalInspection: TerminalSessionInspector
    /// Serialize access requests that need new consent through grant creation
    /// and initial resolution. Waiting requests then recheck the live grants.
    /// This is separate from the shared UI queue used by all daemon services.
    private let accessConsentQueue: ConsentQueue
    /// Human Denies that refuse the identical requests already waiting on
    /// `accessConsentQueue` when they were made. See `HumanDenialLedger`.
    private var humanDenials = HumanDenialLedger<AccessDenialShape>()
    /// Which refusals before a panel this run has recorded.
    private var absentReferenceRecords = AbsentReferenceRecords()
    private var approvalMemories: [ApprovalMemory] = []
    /// Where panels, refusals, revocations and grant reuses are recorded. Nil
    /// when csecd has no protected stores to anchor a log in.
    private let decisionLog: DecisionLog?
    /// The one owner of the persisted grants item: a revocation is written
    /// through it before csecd replies.
    private let grantPersistence: GrantPersistence?
    /// The restart warm-up that grants restored after a csecd restart wait on
    /// before their sealed stores are reopened.
    private let restoration: GrantRestoration?
    /// Claude Code auto mode standing in for the panel, for a `csec ai`
    /// request in a paired project. Nil: every new reference gets a panel.
    private let delegation: ClaudeDelegationService?
    private var activeSecrets = ActiveSecretRegistry()
    /// Requests waiting on a human, for `csec ai` to report the ones started
    /// under it that cannot say so themselves (`HumanWaitBoard`). Shared with
    /// the SSH signing service.
    private let humanWaitBoard: HumanWaitBoard?
    /// Minutes a coding agent's request may wait on a human
    /// (`ApprovalWaitLimit`); injected so tests need not wait for real.
    private let approvalWaitLimit: @Sendable () -> Duration
    private var redactionSessions: [String: RedactionSession] = [:]
    private var nativeEditAuthorizations: [String: NativeEditAuthorization] = [:]
    private var registeredSessions: [String: RegisteredSession] = [:]

    public init(
        resolver: SecretResolver,
        grants: GrantTable,
        consent: ConsentProvider,
        policyReview: PolicyReviewProvider,
        nativeStore: NativeEncryptedFileProvider? = nil,
        sshSigningService: SSHSigningService? = nil,
        githubProxy: GitHubProxyService? = nil,
        automationService: AutomationService? = nil,
        allowLegacyAccessForTesting: Bool = false,
        allowUnverifiedPlansForTesting: Bool = false,
        allowUnverifiedAutomationCallersForTesting: Bool = false,
        processInspection: ProcessInspection = .live,
        terminalInspection: TerminalSessionInspector,
        accessConsentQueue: ConsentQueue = ConsentQueue(),
        decisionLog: DecisionLog? = nil,
        grantPersistence: GrantPersistence? = nil,
        restoration: GrantRestoration? = nil,
        delegation: ClaudeDelegationService? = nil,
        humanWaitBoard: HumanWaitBoard? = nil,
        approvalWaitLimit: @escaping @Sendable () -> Duration = {
            .seconds(ApprovalWaitLimit.current().minutes * 60)
        }
    ) {
        self.delegation = delegation
        self.humanWaitBoard = humanWaitBoard
        self.approvalWaitLimit = approvalWaitLimit
        self.decisionLog = decisionLog
        self.grantPersistence = grantPersistence
        self.restoration = restoration
        self.processInspection = processInspection
        self.terminalInspection = terminalInspection
        self.accessConsentQueue = accessConsentQueue
        self.resolver = resolver
        self.grants = grants
        self.consent = consent
        self.policyReview = policyReview
        self.nativeStore = nativeStore
        self.sshSigningService = sshSigningService
        self.githubProxy = githubProxy
        self.automationService = automationService
        self.allowLegacyAccessForTesting = allowLegacyAccessForTesting
        self.allowUnverifiedPlansForTesting = allowUnverifiedPlansForTesting
        self.allowUnverifiedAutomationCallersForTesting =
            allowUnverifiedAutomationCallersForTesting
    }

    /// Restoration changes no authorization and never delivers a value. The
    /// normal anchored human wait still bounds the request and its review.
    public func restoreApprovals(request: RestoreApprovalsRequest, caller: CallerInfo) async -> Response {
        guard allowUnverifiedPlansForTesting || caller.peerIdentity?.code.role == .launcher else {
            return .failed(.unverifiedPeer, message: "a verified launcher is required for restoration",
                           requestID: request.requestID)
        }
        guard let restoration else {
            return .failed(.providerUnavailable, message: "approval restoration is unavailable",
                           requestID: request.requestID)
        }
        let caller = caller.anchored(using: processInspection)
        let wait = HumanWait(
            requester: HumanWait.Requester(pid: caller.pid, startTime: caller.startTime),
            summary: "reopen approvals after csecd restarted",
            limit: HumanWait.limit(forRequesterPID: caller.pid, startTime: caller.startTime,
                                  inspection: processInspection, limit: approvalWaitLimit),
            sink: RequestNotices.sink, board: humanWaitBoard,
            requestAnchor: caller.requestAnchor, processInspection: processInspection
        )
        // After the restore's own outcome, and only while its requester is
        // still here: the fetch ahead is for the person the attended install
        // waited for, so that whatever authorization a provider's own app
        // raises comes now, not hours later to nobody. Pairings outlive
        // "Forget these approvals", so it follows that outcome too.
        let (outcome, fetchedAhead) = await wait.bounding { () -> (GrantRestoration.Wait, FetchAheadSummary?) in
            let outcome = await restoration.restoreApprovals(requester: caller)
            switch outcome {
            case .warmed, .forgotten, .notNeeded, .usedUp:
                guard !Task.isCancelled else { return (outcome, nil) }
                return (outcome, await restoration.fetchAhead())
            case .requesterGone, .failed:
                return (outcome, nil)
            }
        }
        if wait.isExpired {
            return .failed(.consentDenied, message: wait.timeoutMessage, requestID: request.requestID)
        }
        if let abandonment = wait.abandonment {
            return .failed(.consentDenied, message: abandonment.message, requestID: request.requestID)
        }
        guard !Task.isCancelled else {
            return .failed(.consentDenied, message: "approval restoration cancelled", requestID: request.requestID)
        }
        let status: RestorationStatus
        switch outcome {
        case .warmed: status = .reopened
        case .forgotten: status = .forgotten
        case .notNeeded: status = .notNeeded
        case .usedUp: status = .alreadyRestored
        case .requesterGone:
            return .failed(.consentDenied, message: "approval restoration requester went away",
                           requestID: request.requestID)
        case .failed:
            return .failed(.consentDenied, message: "approval restoration did not complete; nothing was retried",
                           requestID: request.requestID)
        }
        return Response(requestID: request.requestID, restorationStatus: status, restoreFetchAhead: fetchedAhead)
    }

    public func handle(request: AccessRequest, caller: CallerInfo) async -> Response {
        await handle(request: request, caller: caller, daemonUse: false)
    }

    /// `daemonUse` is true only for a request csecd built itself, for a value
    /// it uses on the caller's behalf and never returns to it (the GitHub
    /// token proxy, `authorizeGitHubTokenUse`). Such a request carries a
    /// `daemon_proxy` plan in place of a signed launcher's; no request from a
    /// socket client may carry one.
    private func handle(request: AccessRequest, caller: CallerInfo, daemonUse: Bool) async -> Response {
        // Root selection reads process facts only; complete plan/peer checks
        // still precede policy and delivery below. A registered session may be
        // the default root even when no terminal or coding agent is above it.
        let scopeRoot = request.deliveryPlan.flatMap { verifyRoot($0.root, caller: caller) }
        let caller = caller.anchored(using: processInspection, scopeRoot: scopeRoot)
        // A coding agent's request is withdrawn if it waits on a human longer
        // than the limit, and its session is told when it starts waiting.
        let limit = approvalWaitLimit
        let wait = HumanWait(
            requester: HumanWait.Requester(pid: caller.pid, startTime: caller.startTime),
            summary: Self.waitSummary(references: request.references),
            limit: HumanWait.limit(
                forRequesterPID: caller.pid, startTime: caller.startTime,
                inspection: processInspection, limit: limit
            ),
            sink: RequestNotices.sink,
            board: humanWaitBoard,
            requestAnchor: caller.requestAnchor,
            processInspection: processInspection
        )
        var response = await wait.bounding {
            await self.handleAccess(request: request, caller: caller, consentTurn: nil, daemonUse: daemonUse)
        }
        if wait.isExpired, response.values == nil {
            response = .failed(.consentDenied, message: wait.timeoutMessage, requestID: request.requestID)
        } else if let abandonment = wait.abandonment, response.values == nil {
            response = .failed(.consentDenied, message: abandonment.message, requestID: request.requestID)
        }
        // A `csec ai` whose request went to Touch ID because delegated
        // approvals wait on setup hears why, approved or not.
        if let delegation { response.delegationNotice = await delegation.takeSetupNotice(for: caller) }
        return response
    }

    /// `consentTurn` is set only while the request holds its turn on
    /// `accessConsentQueue`; it is the request's place in arrival order there.
    private func handleAccess(
        request: AccessRequest,
        caller: CallerInfo,
        consentTurn: HumanDenialLedger<AccessDenialShape>.Ticket?,
        daemonUse: Bool
    ) async -> Response {
        guard !Task.isCancelled else {
            return .failed(.consentDenied, message: "consent request cancelled", requestID: request.requestID)
        }
        let requestID = request.requestID
        let rootPID: pid_t
        let rootStartTime: UInt64
        let planDigest: String?
        let plan: DeliveryPlan?

        if request.isLegacy {
            guard allowLegacyAccessForTesting else {
                return .failed(
                    .upgradeRequired,
                    message: "client must use protocol v2 with a delivery plan"
                )
            }
            rootPID = caller.pid
            rootStartTime = caller.startTime
            planDigest = nil
            plan = nil
        } else {
            guard request.protocolVersion == WireProtocol.version else {
                return .failed(
                    .upgradeRequired,
                    message: "unsupported protocol version",
                    requestID: requestID
                )
            }
            guard let requestID,
                  UUID(uuidString: requestID) != nil,
                  let deliveryPlan = request.deliveryPlan,
                  let claimedDigest = request.deliveryPlanDigest,
                  Self.isSHA256Digest(claimedDigest),
                  (try? deliveryPlan.digest()) == claimedDigest,
                  deliveryPlan.requestedTTLSeconds == request.ttlSeconds,
                  Self.hasValidMetadata(deliveryPlan) else {
                return .failed(
                    .invalidRequest,
                    message: "invalid or incomplete delivery-plan binding",
                    requestID: requestID
                )
            }
            // csecd alone builds daemon-proxy plans, from kernel facts about
            // the caller; a client that sends one is refused outright.
            guard (deliveryPlan.mechanism == .daemonProxy) == daemonUse,
                  request.githubLastingAccess == nil || daemonUse else {
                return .failed(
                    .invalidRequest,
                    message: "daemon_proxy delivery plans are built by csecd only",
                    requestID: requestID
                )
            }
            guard allowUnverifiedPlansForTesting || daemonUse
                    || caller.peerIdentity?.code.role == .launcher else {
                return .failed(
                    .unverifiedPeer,
                    message: "a verified launcher is required for delivery plans",
                    requestID: requestID
                )
            }
            pruneRegisteredSessions()
            guard let verifiedRoot = verifyDeliveryRoot(deliveryPlan, caller: caller) else {
                return .failed(
                    .invalidRequest,
                    message: "the requested grant root does not match process ancestry",
                    requestID: requestID
                )
            }
            if deliveryPlan.mechanism == .credentialProtocol {
                guard let parentPID = ProcessAncestry.parent(of: caller.pid),
                      parentPID > 1,
                      ProcessAncestry.executablePath(of: parentPID)
                        == URL(fileURLWithPath: deliveryPlan.executable.canonicalPath)
                            .standardizedFileURL.resolvingSymlinksInPath().path else {
                    return .failed(
                        .invalidRequest,
                        message: "the credential consumer does not match the verified parent",
                        requestID: requestID
                    )
                }
            }
            rootPID = verifiedRoot.pid
            rootStartTime = verifiedRoot.startTime
            planDigest = claimedDigest
            plan = deliveryPlan
        }

        guard !request.references.isEmpty,
              request.references.count <= 64,
              request.references.allSatisfy({
                  !$0.isEmpty && $0.utf8.count <= 4_096 && !$0.utf8.contains(0)
              }),
              // nil ⇒ process-lifetime (allowed); an explicit TTL must be
              // positive but is otherwise uncapped — the grant is bounded by its
              // process subtree, not a clock.
              (request.ttlSeconds.map { $0 > 0 } ?? true),
              !request.reason.isEmpty,
              request.reason.utf8.count <= 512,
              plan?.operationContext.utf8.count ?? 0 <= 512 else {
            return .failed(
                .invalidRequest,
                message: "request fields are outside supported bounds",
                requestID: requestID
            )
        }
        guard request.hasValidCommandLine else {
            return .failed(
                .invalidRequest,
                message: "the command line does not match the delivery plan's command digest",
                requestID: requestID
            )
        }

        var refs: [SecretRef] = []
        for raw in request.references {
            guard let ref = try? SecretRef(raw) else {
                return .failed(
                    .invalidRequest,
                    message: "one or more references are invalid",
                    requestID: requestID
                )
            }
            refs.append(ref)
        }

        let now = Date()
        guard let plan, let planDigest else {
            return await handleLegacyAccess(
                refs: refs,
                request: request,
                caller: caller,
                rootPID: rootPID,
                rootStartTime: rootStartTime,
                now: now,
                ownsConsentTurn: consentTurn != nil
            )
        }

        if let automationService {
            switch await automationService.authorizeAccess(
                references: refs,
                plan: plan,
                caller: caller
            ) {
            case .notApplicable:
                break
            case let .allowed(values, expiresAt):
                activeSecrets.register(valuesByReference: values, expiresAt: expiresAt)
                return Response(
                    requestID: request.requestID,
                    values: values,
                    accessExpiresAt: expiresAt
                )
            case let .denied(error):
                return automationFailure(error, requestID: request.requestID)
            }
        }

        return await handlePolicyAccess(
            refs: refs,
            request: request,
            caller: caller,
            rootPID: rootPID,
            rootStartTime: rootStartTime,
            plan: plan,
            planDigest: planDigest,
            now: now,
            consentTurn: consentTurn
        )
    }

    private func handleQueuedAccess(
        request: AccessRequest,
        caller: CallerInfo,
        logWithdrawn: (_ cause: String?) async -> Void = { _ in }
    ) async -> Response {
        // The ticket is taken before waiting, so a human Deny made while this
        // request waits can refuse it and one made after it leaves cannot.
        let ticket = humanDenials.arrive()
        defer { humanDenials.depart(ticket) }
        guard let permit = try? await accessConsentQueue.acquire() else {
            // Cancelled while it waited for its turn: its requester went away,
            // or its deadline passed. It was never shown.
            await logWithdrawn(nil)
            return .failed(.consentDenied, message: "consent request cancelled", requestID: request.requestID)
        }
        guard AccessReviewRequester.isAlive(caller, using: processInspection) else {
            await permit.release()
            await logWithdrawn("its requester exited while it waited for its turn")
            return .failed(
                .invalidRequest,
                message: "the requester exited or changed while waiting for consent",
                requestID: request.requestID
            )
        }
        // Re-enter validation with a fresh clock and the live grant table. The
        // caller/root may have exited or changed while waiting, and an earlier
        // review may already cover every reference under this release shape.
        // Only a request `handleAccess` already admitted waits here, so a
        // daemon-proxy plan arriving here is csecd's own.
        let response = await handleAccess(
            request: request, caller: caller, consentTurn: ticket,
            daemonUse: request.deliveryPlan?.mechanism == .daemonProxy
        )
        await permit.release()
        return response
    }

    /// How long a just-released value stays registered in the active-secret
    /// (output-redaction) catalog, and what `accessExpiresAt` the caller is told.
    /// A process-lifetime grant registers for redaction with no clock but tells
    /// the caller no expiry, since the grant is bounded by process liveness.
    private enum ReleaseWindow {
        /// Do not track for redaction (the legacy/test path).
        case unregistered
        /// Track with no wall-clock expiry — a process-lifetime grant.
        case untilProcessExits
        /// Track until this instant — a deliberate bounded grant.
        case until(Date)

        /// A registered window from a granted TTL: nil ⇒ process lifetime.
        static func granted(ttlSeconds: Int?, from now: Date) -> ReleaseWindow {
            guard let ttlSeconds else { return .untilProcessExits }
            return .until(now.addingTimeInterval(TimeInterval(ttlSeconds)))
        }
    }

    private func handlePolicyAccess(
        refs: [SecretRef],
        request: AccessRequest,
        caller: CallerInfo,
        rootPID: pid_t,
        rootStartTime: UInt64,
        plan: DeliveryPlan,
        planDigest: String,
        now requestTime: Date,
        consentTurn: HumanDenialLedger<AccessDenialShape>.Ticket?,
        restoreWait: HumanDenialLedger<AccessDenialShape>.Ticket? = nil,
        rulesReviewed: Bool = false
    ) async -> Response {
        // The instant every grant check below is made at. A wait on the restore
        // panel can last as long as the panel is up (all night behind a locked
        // screen), so after it this moves to the present: a restored grant whose
        // chosen lifetime ran out during the wait must not cover the release.
        var now = requestTime
        // The value-free release decision depends only on the plan: a bounded
        // grant lifetime, a mechanism-derived output policy, and the csec-get
        // plaintext-exposure gate. There is no risk classification, no
        // compatibility-acceptance ledger, and no per-credential policy.
        let decision = ReleasePolicy.evaluate(plan: plan)
        guard decision.allowed else {
            return policyDenied(decision, plan: plan, requestID: request.requestID)
        }
        // nil ⇒ a process-lifetime grant (no clock).
        let grantedTTL = decision.grantedTTLSeconds

        // Grant reuse: a live grant rooted at the caller or an ancestor covers
        // these references without another prompt. A per-command grant needs this
        // exact delivery-plan digest; a grant the human widened to an agent or
        // terminal session needs the same release shape (see
        // `DeliveryPlan.releaseShapeDigest`).
        //
        // A capability-GID launch mints a new root of its own, so it may ride
        // only a deliberately widened grant — never the incidental per-command
        // grant its own outer launcher left behind, which would let a nested
        // launch outlive the authorization that created it. Riding a widened one
        // is exactly what the human chose, and exposes strictly less than the
        // environment-injection mechanism the same choice already covers: the
        // bytes reach a root-owned tmpfs behind a one-time capability GID, and
        // never pass through the launcher.
        let releaseShapeDigest = try? plan.releaseShapeDigest()
        let requestedURIs = Set(refs.map(\.uri))
        // A one-time code is never covered: each command that needs one gets
        // its own panel, however the grants a human approved are scoped, and
        // nothing is minted or restored for it (csec-0.65). Nor is the token
        // for a GitHub request that can give access outlasting any approval
        // (`GitHubLastingAccess`, csec-0.49): every reference it uses is
        // reviewed for that one request.
        let lastingAccess = request.githubLastingAccess != nil
        let perRequestURIs = lastingAccess ? requestedURIs : Set(refs.filter(\.isOneTimeCode).map(\.uri))
        func reviewedPerRequest(_ ref: SecretRef) -> Bool { perRequestURIs.contains(ref.uri) }
        var coverage = await grants.coverage(
            for: caller.pid,
            now: now,
            deliveryPlanDigest: planDigest,
            releaseShapeDigest: releaseShapeDigest,
            callerAuditSessionID: caller.peerIdentity?.audit.auditSessionID,
            widenedScopeOnly: plan.mechanism == .capabilityGIDFile
        )
        var newReferenceURIs = requestedURIs.subtracting(coverage.references).union(perRequestURIs)

        // A request that cannot be delivered whatever a human decides is
        // refused before anything can show it a panel: the restore panel, the
        // Deny ledger's wait, delegation, or its own review. One reference
        // that cannot resolve fails the whole release, so every reference is
        // checked, covered or new. A release that is wholly covered and warm
        // shows no panel, so it resolves as before and says why it failed.
        // A request that waited for its turn runs this again.
        let mayShowPanel = !newReferenceURIs.isEmpty
            || refs.contains { coverage.awaitingRestore.contains($0.uri) && !reviewedPerRequest($0) }
        if mayShowPanel, let refusal = await refuseKnownAbsent(
            refs: refs, request: request, plan: plan, rootPID: rootPID,
            releaseShapeDigest: releaseShapeDigest, now: now
        ) {
            return refusal
        }

        // Covered, but only by grants restored after a csecd restart whose
        // sealed stores are still closed: a covered release carries no unlock,
        // so it waits for the one restore panel of this daemon lifetime.
        if newReferenceURIs.isEmpty, let restoration {
            let awaiting = refs.filter { coverage.awaitingRestore.contains($0.uri) && !reviewedPerRequest($0) }
            if !awaiting.isEmpty {
                switch await restoration.ensureWarm(for: awaiting, requester: caller) {
                case .forgotten:
                    return .failed(
                        .consentDenied,
                        message: "policy review denied (the approvals restored after csecd restarted were forgotten)",
                        requestID: request.requestID
                    )
                case .requesterGone:
                    await recordWithdrawn(
                        request: request, plan: plan, refs: refs, rootPID: rootPID,
                        releaseShapeDigest: releaseShapeDigest, now: now,
                        cause: nil, waitedFor: "the restore panel"
                    )
                    return .failed(.consentDenied, message: "consent request cancelled", requestID: request.requestID)
                case .failed:
                    return .failed(.consentDenied, message: "consent denied", requestID: request.requestID)
                case .notNeeded, .warmed, .usedUp:
                    // Anything may have changed while this request waited: a
                    // covering grant expired, was revoked, lost its root, or
                    // could not be reopened and was dropped. Check again, at
                    // the present; what is no longer covered gets a panel.
                    now = Date()
                    coverage = await grants.coverage(
                        for: caller.pid,
                        now: now,
                        deliveryPlanDigest: planDigest,
                        releaseShapeDigest: releaseShapeDigest,
                        callerAuditSessionID: caller.peerIdentity?.audit.auditSessionID,
                        widenedScopeOnly: plan.mechanism == .capabilityGIDFile
                    )
                    newReferenceURIs = requestedURIs.subtracting(coverage.references).union(perRequestURIs)
                    // What is no longer covered gets a panel, and the restore
                    // touch may have opened a store that lacks a key.
                    if !newReferenceURIs.isEmpty, let refusal = await refuseKnownAbsent(
                        refs: refs, request: request, plan: plan, rootPID: rootPID,
                        releaseShapeDigest: releaseShapeDigest, now: now
                    ) {
                        return refusal
                    }
                }
            }
        }

        if newReferenceURIs.isEmpty {
            // Everything is covered by a live grant — resolve without a prompt.
            guard let releaseRoot = verifyDeliveryRoot(plan, caller: caller),
                  releaseRoot.pid == rootPID,
                  releaseRoot.startTime == rootStartTime else {
                return .failed(
                    .invalidRequest,
                    message: "the granted requester changed before release",
                    requestID: request.requestID
                )
            }
            let response = await resolve(
                refs: refs,
                requestID: request.requestID,
                unlock: nil,
                window: .granted(ttlSeconds: grantedTTL, from: now)
            )
            guard let finalRoot = verifyDeliveryRoot(plan, caller: caller),
                  finalRoot.pid == rootPID,
                  finalRoot.startTime == rootStartTime else {
                return .failed(
                    .invalidRequest,
                    message: "the granted requester changed during release",
                    requestID: request.requestID
                )
            }
            if response.failure == nil, let decisionLog {
                let restoredOnly = !requestedURIs.isDisjoint(with: coverage.coveredOnlyByRestored)
                await decisionLog.record(accessRecord(
                    kind: .reuse, request: request, plan: plan, refs: refs,
                    rootPID: rootPID, releaseShapeDigest: releaseShapeDigest, now: now,
                    outcome: .approved, decider: restoredOnly ? .restoredGrant : .grant
                ))
            }
            return response
        }

        // A human just denied this same question while this request waited
        // behind it (for its consent turn, or on the restore panel): refuse it
        // rather than raise the same panel again, and before delegation judges
        // it again, so a Deny of an identical request is never overruled by
        // auto mode. A request that arrived after the Deny never matches. The
        // earlier of the two arrivals is the one that counts.
        let denialShape = releaseShapeDigest.map {
            AccessDenialShape(references: Set(refs.map(\.uri)), releaseShapeDigest: $0, lastingAccess: lastingAccess)
        }
        if let waited = consentTurn ?? restoreWait, let denialShape, humanDenials.refuses(
            waited,
            shape: denialShape,
            matchesRoot: { root in
                processInspection.descends(caller.pid, from: root.pid, rootStartTime: root.startTime)
            }
        ) {
            await decisionLog?.record(accessRecord(
                kind: .refusal, request: request, plan: plan, refs: refs,
                rootPID: rootPID, releaseShapeDigest: releaseShapeDigest, now: now,
                outcome: .denied, decider: nil,
                detail: "answered by the Deny of an identical request it waited behind"
            ))
            return .failed(
                .consentDenied,
                message: "policy review denied (an identical request waiting with this one was denied)",
                requestID: request.requestID
            )
        }

        // Claude Code auto mode may stand in for the panel: a `csec ai`
        // request whose command the classifier approved, from a verified
        // Claude Code session whose settings leave the classifier the only
        // approver, for references a human paired with the project. This
        // runs before the consent queue, so a delegated release never waits
        // behind a panel on screen and never reaches the phone. It mints no
        // grant: one registration authorizes exactly one command. A request
        // that waited for its turn is judged again, since the panel it waited
        // behind may have paired or unlocked what it needs; so is one that
        // went to the restore panel (`.waitedForRestore` below).
        var delegationNote: DelegationDecline?
        var delegatedSession: DelegationSession?
        if let delegation {
            let newRefs = refs.filter { newReferenceURIs.contains($0.uri) }
            // A `csec ai` is judged as the command auto mode approved; any
            // other request (a bridge client, a nested `csec get` or `csec
            // exec`) as part of the approved command it runs under, if any.
            let evaluation: DelegationEvaluation
            if let commandLine = request.commandLine,
               AICommandExec.isAIRequest(plan: plan, commandLine: commandLine) {
                evaluation = await delegation.evaluateRelease(
                    caller: caller, commandLine: commandLine, newReferences: newRefs
                )
            } else {
                // Only csecd builds a daemon_proxy plan (`handle` refuses a
                // client's), so this is csecd's own use of the value.
                evaluation = await delegation.evaluateNested(
                    caller: caller, newReferences: newRefs, daemonUse: plan.mechanism == .daemonProxy,
                    lastingAccess: request.githubLastingAccess
                )
            }
            switch evaluation {
            case .notApplicable:
                break
            case let .declined(reason, session):
                // Declined only because Claude Code's auto-mode rules changed
                // or a hook was added: csecd shows the change in one panel,
                // and once it is acknowledged the request starts over and auto
                // mode approves it, with no panel of its own (csec-0.64,
                // csec-0.64.7). Only on the first pass, which holds no consent
                // turn the panel would wait behind, and once per request.
                if reason.isUnacknowledgedSettings, consentTurn == nil, restoreWait == nil, !rulesReviewed,
                   await delegation.acknowledgeChangedRules(for: caller) {
                    return await handlePolicyAccess(
                        refs: refs, request: request, caller: caller,
                        rootPID: rootPID, rootStartTime: rootStartTime,
                        plan: plan, planDigest: planDigest, now: Date(),
                        consentTurn: nil, rulesReviewed: true
                    )
                }
                delegationNote = reason
                delegatedSession = session
            case let .approved(ticket):
                switch await releaseDelegated(
                    ticket, delegation: delegation, refs: refs, newReferenceURIs: newReferenceURIs,
                    request: request, caller: caller, plan: plan, rootPID: rootPID,
                    rootStartTime: rootStartTime, releaseShapeDigest: releaseShapeDigest, now: now,
                    mayWaitForRestore: restoreWait == nil
                ) {
                case let .released(response), let .refused(response):
                    return response
                case let .declined(reason):
                    delegationNote = reason
                    delegatedSession = ticket.session
                case let .waitedForRestore(arrival):
                    // The restore panel can stay up for hours, and anything
                    // the approval rested on may have changed meanwhile: a
                    // covering grant expired or was revoked, the project was
                    // unpaired, delegation was turned off, or a human denied
                    // an identical request's panel. So the request starts over
                    // at the present, as the grant path does after its own
                    // wait: coverage, the Deny ledger (with `arrival`, the
                    // ledger ticket taken before the wait, which also keeps a
                    // Deny made during it on record once the denied request
                    // has left) and delegation are judged again. Its
                    // registration stays bound to this `csec ai` and a decline
                    // is counted once per requester, so nothing is consumed or
                    // logged twice; the second pass never waits again, so a
                    // value still cold declines as not held.
                    defer { humanDenials.depart(arrival) }
                    return await handlePolicyAccess(
                        refs: refs, request: request, caller: caller,
                        rootPID: rootPID, rootStartTime: rootStartTime,
                        plan: plan, planDigest: planDigest, now: Date(),
                        consentTurn: consentTurn, restoreWait: arrival
                    )
                }
            }
        }

        guard let consentTurn else {
            return await handleQueuedAccess(request: request, caller: caller) { cause in
                await self.recordWithdrawn(
                    request: request, plan: plan, refs: refs, rootPID: rootPID,
                    releaseShapeDigest: releaseShapeDigest, now: now, cause: cause
                )
            }
        }

        // New references alongside covered ones still sealed behind the
        // restore: one panel for both, whose one touch also reopens every
        // restored grant it lists. If another panel is already restoring, wait
        // for it and start over with the grants it left.
        var restoreClaim: GrantRestoration.Claim?
        if let restoration {
            let awaiting = refs.filter { coverage.awaitingRestore.contains($0.uri) && !reviewedPerRequest($0) }
            if !awaiting.isEmpty {
                switch await restoration.claimForMixedPanel(for: awaiting) {
                case let .claimed(claim):
                    restoreClaim = claim
                case .inFlight:
                    switch await restoration.ensureWarm(for: awaiting, requester: caller) {
                    case .forgotten:
                        return .failed(
                            .consentDenied,
                            message: "policy review denied (the approvals restored after csecd restarted were forgotten)",
                            requestID: request.requestID
                        )
                    case .requesterGone:
                        await recordWithdrawn(
                            request: request, plan: plan, refs: refs, rootPID: rootPID,
                            releaseShapeDigest: releaseShapeDigest, now: now,
                            cause: nil, waitedFor: "the restore panel"
                        )
                        return .failed(.consentDenied, message: "consent request cancelled", requestID: request.requestID)
                    case .failed:
                        return .failed(.consentDenied, message: "consent denied", requestID: request.requestID)
                    case .warmed, .notNeeded, .usedUp:
                        // Start over at the present, with what the other
                        // panel left (see `now` above).
                        return await handlePolicyAccess(
                            refs: refs, request: request, caller: caller,
                            rootPID: rootPID, rootStartTime: rootStartTime,
                            plan: plan, planDigest: planDigest, now: Date(),
                            consentTurn: consentTurn, restoreWait: restoreWait
                        )
                    }
                case .notNeeded, .usedUp:
                    break
                }
            }
        }

        // New references → one display-only trusted review + Touch ID. The
        // window shows the references, destination, and any inspectable-shape
        // warning; a successful biometric is itself the authorization.
        // Providers get to say where each value will come from before the window
        // asks for Touch ID — an `op://` reference names no account, so this is
        // where the chosen one becomes visible.
        // A panel for one-time codes alone grants nothing past this command,
        // so it offers no wider root and no lifetime: the codes are released
        // to the requesting command and nothing is minted. It lists only the
        // codes, which are all it asks about: anything beside them in their
        // item is already granted. A lasting GitHub request's panel is the
        // same, for that one request.
        let onlyPerRequest = newReferenceURIs.isSubset(of: perRequestURIs)
        let reviewCredentials = await resolver.reviewCredentials(
            for: CredentialGrouping.groups(for: refs)
                .filter { group in
                    group.references.contains { newReferenceURIs.contains($0.uri) }
                }
                .map { group in group.references.filter { !onlyPerRequest || reviewedPerRequest($0) } }
        )
        // csecd — not the launcher — resolves which roots may be offered, by
        // walking kernel ancestry above the already-verified plan root.
        let inspectedScopeChoices: GrantScopeChoices? = GrantScopeInspector.choices(
            planRootPID: rootPID,
            planRootStartTime: rootStartTime,
            requestingLabel: scopeRequestingLabel(plan: plan, rootPID: rootPID),
            inspection: processInspection
        )
        let scopeChoices = onlyPerRequest
            ? inspectedScopeChoices.flatMap { choices in
                choices.options.first { $0.kind == .requestingCommand }.map {
                    GrantScopeChoices(options: [$0], defaultOptionID: $0.id)
                }
            }
            : inspectedScopeChoices
        let offersScopeChoice = (scopeChoices?.options.count ?? 0) > 1
        var reviewedCaller = displayedCaller(
            caller, plan: plan, rootPID: rootPID,
            statesGrantRoot: !offersScopeChoice
        )
        reviewedCaller.terminal = await terminalInspection.context(forCallerPID: caller.pid)
        let durationChoices = GrantDurationChoices.offered(
            requestedTTLSeconds: grantedTTL
        )
        // A Claude Code request delegation declined says why, and approving it
        // with the default Claude Code scope for the session's lifetime pairs
        // its new references with the project.
        var pairingOffer: DelegationPairingOffer?
        if let delegation, let delegatedSession {
            // A one-time code is never paired: auto mode never releases one,
            // nor uses a token for a lasting GitHub request.
            pairingOffer = await delegation.pairingOffer(
                for: delegatedSession,
                decline: delegationNote,
                references: refs.filter { newReferenceURIs.contains($0.uri) && !reviewedPerRequest($0) },
                daemonUse: plan.mechanism == .daemonProxy,
                scopeChoices: scopeChoices,
                durationChoices: durationChoices
            )
        }
        let review = AccessPolicyReview(
            caller: reviewedCaller,
            reason: request.reason,
            plan: plan,
            commandLine: request.commandLine.map { displayCommandLine($0, plan: plan, now: now) },
            requesterCommandLine: requesterCommandLine(request: request, plan: plan, now: now),
            credentials: reviewCredentials,
            scopeChoices: scopeChoices,
            durationChoices: onlyPerRequest ? nil : durationChoices,
            restore: restoreClaim?.details,
            delegationNote: delegationNote,
            pairingOffer: pairingOffer,
            githubLastingAccess: request.githubLastingAccess
        )
        let cause = await promptCause(
            newReferences: newReferenceURIs, lastingAccess: lastingAccess, caller: caller, now: now,
            deliveryPlanDigest: planDigest, releaseShapeDigest: releaseShapeDigest,
            widenedScopeOnly: plan.mechanism == .capabilityGIDFile
        )
        let reviewOutcome = await policyReview.reviewAccess(review)
        guard case let .approved(approval) = reviewOutcome else {
            // Only the human's own Deny answers the identical requests waiting
            // behind this one; a requester that left or a Touch ID error does
            // not. The root is the scope the window offered by default. It is
            // recorded before anything is awaited: the panel's turn is already
            // over, so a waiter can run (a restore panel queued behind this one
            // can be approved) during the awaits below, and it must find the
            // Deny when it does.
            if case let .denied(.human(decidedAt, _, _)) = reviewOutcome, let denialShape {
                let root = scopeChoices?.defaultOption
                humanDenials.recordHumanDenial(
                    shape: denialShape,
                    root: HumanDenialLedger<AccessDenialShape>.Root(
                        pid: root?.pid ?? rootPID,
                        startTime: root?.startTime ?? rootStartTime
                    ),
                    decidedAt: decidedAt
                )
            }
            // The one Deny refuses the new references and forgets the restore
            // section; a requester that went away leaves the restore unused.
            // A review the deadline withdrew, queued or on screen, reads as
            // `.timedOut` whatever ended it there.
            let denial: AccessPolicyDenialReason? = {
                guard case let .denied(reason) = reviewOutcome else { return nil }
                return HumanWait.current?.effectiveReason(reason) ?? reason
            }()
            if let restoreClaim, let denial {
                await restoration?.completeClaim(restoreClaim, outcome: .denied(denial))
            }
            if let denial {
                let ended = DecisionLogRecord.outcome(for: denial)
                let kind = DecisionLogRecord.kind(for: denial)
                // The record names the scope the window offered by default,
                // so its root is that scope's process, as for the Deny ledger.
                await decisionLog?.record(panelRecord(
                    kind: kind,
                    review: review, rootPID: scopeChoices?.defaultOption.pid ?? rootPID,
                    releaseShapeDigest: releaseShapeDigest,
                    outcome: ended.outcome, decider: ended.decider, ttdMs: ended.ttdMs, cause: cause,
                    scope: scopeChoices?.defaultOption.kind.rawValue,
                    duration: DecisionLogRecord.durationText(
                        ttlSeconds: durationChoices.defaultOption.ttlSeconds
                    ),
                    detail: kind == .withdrawn || HumanWait.current?.abandonment != nil
                        ? HumanWait.current?.withdrawnDetail() : nil
                ))
            }
            return .failed(
                .consentDenied,
                message: denial?.deniedMessage() ?? AccessPolicyDenialReason.deniedPrefix,
                requestID: request.requestID
            )
        }

        // Resolve the reviewer's selection against the list csecd itself built,
        // then prove the chosen root is still the same live process and still
        // contains the plan root. An unknown identifier resolves to the displayed
        // default and can never widen the grant.
        let selectedScope = scopeChoices.map {
            $0.resolved(selectedID: approval.selectedScopeOptionID)
        }
        // Likewise the lifetime: only an option the window offered can be minted,
        // and an out-of-range index falls back to the displayed default. nil ⇒ a
        // process-lifetime grant.
        let approvedTTL = durationChoices
            .resolved(selectedIndex: approval.selectedDurationIndex)
            .ttlSeconds
        func recordFailedApproval(_ detail: String) async {
            let approved = DecisionLogRecord.outcome(for: approval)
            let failedRoot = selectedScope?.pid ?? rootPID
            await decisionLog?.record(panelRecord(
                review: review, rootPID: failedRoot, releaseShapeDigest: releaseShapeDigest,
                outcome: approved.outcome, decider: approved.decider, ttdMs: approved.ttdMs, cause: cause,
                scope: selectedScope?.kind.rawValue,
                duration: DecisionLogRecord.durationText(ttlSeconds: approvedTTL),
                detail: "nothing was delivered, so nothing was minted"
            ))
            await decisionLog?.record(deliveryFailedRecord(
                review: review, rootPID: failedRoot, releaseShapeDigest: releaseShapeDigest, detail: detail
            ))
        }
        if let selectedScope, selectedScope.kind != .requestingCommand {
            guard verifiedScopeRoot(selectedScope, planRootPID: rootPID) else {
                await approval.authenticationSession?.cancel()
                if let restoreClaim {
                    await restoration?.completeClaim(restoreClaim, outcome: .failed)
                }
                await recordFailedApproval("the selected grant scope changed before release")
                return .failed(
                    .invalidRequest,
                    message: "the selected grant scope changed before release",
                    requestID: request.requestID
                )
            }
        }

        let newReferences = refs.filter { newReferenceURIs.contains($0.uri) }
        let outcome = await authenticateReviewedAccess(
            approval: approval,
            caller: displayedCaller(
                caller, plan: plan, rootPID: rootPID,
                statesGrantRoot: !offersScopeChoice
            ),
            newReferences: newReferences,
            reason: request.reason,
            ttl: approvedTTL.map(TimeInterval.init),
            policySummary: releasePolicySummary(plan: plan, scope: selectedScope)
        )
        let approved = DecisionLogRecord.outcome(for: approval)
        guard case let .approved(approvedUnlock) = outcome else {
            if let restoreClaim {
                await restoration?.completeClaim(restoreClaim, outcome: .failed)
            }
            await decisionLog?.record(panelRecord(
                review: review, rootPID: rootPID, releaseShapeDigest: releaseShapeDigest,
                outcome: .authenticationFailed, decider: nil, cause: cause,
                scope: selectedScope?.kind.rawValue,
                duration: DecisionLogRecord.durationText(ttlSeconds: approvedTTL)
            ))
            return .failed(
                .consentDenied,
                message: "consent denied",
                requestID: request.requestID
            )
        }
        // The touch approved the restore section as well: its context reopens
        // that batch now, whatever happens to this request's own release, and
        // after this request's resolution it is used for nothing else.
        if let restoreClaim {
            await restoration?.completeClaim(
                restoreClaim, outcome: .approved(unlock: approvedUnlock, approval: approval)
            )
        }
        defer {
            if restoreClaim != nil { approvedUnlock?.invalidate() }
            // A phone approval's remote unlock serves this request's release
            // and nothing after it, whether the release succeeded or failed.
            if approvedUnlock?.isLocal == false { approvedUnlock?.invalidate() }
        }

        guard let releaseRoot = verifyDeliveryRoot(plan, caller: caller),
              releaseRoot.pid == rootPID,
              releaseRoot.startTime == rootStartTime else {
            await recordFailedApproval("the approved requester changed before release")
            return .failed(
                .invalidRequest,
                message: "the approved requester changed before release",
                requestID: request.requestID
            )
        }

        // The chosen root must still be live and still contain the plan root at
        // the moment the grant is minted, not only when the window was shown.
        let scope = selectedScope ?? GrantScopeOption(
            kind: .requestingCommand,
            pid: rootPID,
            startTime: rootStartTime,
            processLabel: ReviewDisplay.sanitized(
                scopeRequestingLabel(plan: plan, rootPID: rootPID)
            )
        )
        guard scope.kind == .requestingCommand
                || verifiedScopeRoot(scope, planRootPID: rootPID) else {
            await recordFailedApproval("the selected grant scope changed before release")
            return .failed(
                .invalidRequest,
                message: "the selected grant scope changed before release",
                requestID: request.requestID
            )
        }

        // Resolve before minting anything. A grant stands for a release that
        // happened: one minted for a release that failed would cover the next
        // identical request, which would then fail the same way with no panel
        // to show why. So a failure mints nothing, and the next request is
        // reviewed again; the log keeps the human's approval and the failure.
        let approvedAt = Date()
        if approval.decidedOn == .mac { await resolver.personApprovedAtMac() }
        let response = await resolve(
            refs: refs,
            requestID: request.requestID,
            unlock: approvedUnlock,
            window: .granted(ttlSeconds: approvedTTL, from: approvedAt)
        )
        // Someone is at the Mac now, whatever became of this release: fetch
        // ahead what later unattended releases will want, after this
        // request's own resolution so the provider is asked one thing at a
        // time (`GrantRestoration.approvedAtMac`).
        if approval.decidedOn == .mac { await restoration?.approvedAtMac() }
        let rootUnchanged = verifyDeliveryRoot(plan, caller: caller).map {
            $0.pid == rootPID && $0.startTime == rootStartTime
        } ?? false
        if let undelivered = response.failure?.message
            ?? (rootUnchanged ? nil : "the approved requester changed during release") {
            await decisionLog?.record(panelRecord(
                review: review, rootPID: scope.pid, releaseShapeDigest: releaseShapeDigest,
                outcome: approved.outcome, decider: approved.decider, ttdMs: approved.ttdMs, cause: cause,
                scope: scope.kind.rawValue,
                duration: DecisionLogRecord.durationText(ttlSeconds: approvedTTL),
                rootLabel: scope.processLabel,
                detail: "nothing was delivered, so nothing was minted"
            ))
            await decisionLog?.record(deliveryFailedRecord(
                review: review, rootPID: scope.pid, releaseShapeDigest: releaseShapeDigest,
                detail: undelivered
            ))
            if response.failure != nil { return response }
            return .failed(
                .invalidRequest,
                message: "the approved requester changed during release",
                requestID: request.requestID
            )
        }

        var mintedGrantIDs: [String] = []
        // Mint one subtree-bound grant per credential group for the newly
        // approved references, valid for the bounded lifetime. A one-time
        // code, or a lasting GitHub request's token, was approved for this
        // release only, so no grant names it.
        let grantedURIs = newReferenceURIs.subtracting(perRequestURIs)
        for group in CredentialGrouping.groups(for: refs) {
            let references = Set(group.references.compactMap {
                grantedURIs.contains($0.uri) ? $0.uri : nil
            })
            guard !references.isEmpty else { continue }
            let grantID = UUID()
            mintedGrantIDs.append(grantID.uuidString.lowercased())
            await grants.add(Grant(
                id: grantID,
                rootPID: scope.pid,
                rootStartTime: scope.startTime,
                references: references,
                reason: request.reason,
                expiresAt: approvedTTL.map { approvedAt.addingTimeInterval(TimeInterval($0)) },
                requestID: request.requestID,
                deliveryPlanDigest: planDigest,
                peerPIDVersion: caller.peerIdentity?.audit.pidVersion,
                peerCDHash: caller.peerIdentity?.code.cdHash,
                plannedExecutable: plan.executable,
                scopeKind: scope.kind,
                // A per-command root keeps the original exact-digest binding; a
                // widened one is reusable by any command of the same shape.
                scopeReuseDigest: scope.kind.reusesAcrossCommands
                    ? releaseShapeDigest : nil,
                auditSessionID: caller.peerIdentity?.audit.auditSessionID,
                rootProcessLabel: scope.processLabel,
                origin: approval.decidedOn == .phone ? .phone : .humanLocal,
                mintedAt: approvedAt
            ))
        }
        rememberApproval(ApprovalMemory(
            references: grantedURIs, rootPID: scope.pid, rootStartTime: scope.startTime,
            expiresAt: approvedTTL.map { approvedAt.addingTimeInterval(TimeInterval($0)) },
            grantIDs: mintedGrantIDs
        ))
        // Pairing happens only here, on the human-approval path: approved on
        // a human surface that showed the pairing line, for the panel of a
        // request delegation declined, with exactly the default Claude Code
        // scope for the session's lifetime. A nested `csec get` or `csec exec`
        // under Claude Code is never judged, so it never pairs.
        if let delegation, let delegatedSession, let pairingOffer, let surface = approval.decidedOn,
           approval.pairingLineShown,
           pairingOffer.applies(
            scopeOptionID: scope.id,
            duration: durationChoices.resolved(selectedIndex: approval.selectedDurationIndex)
           ) {
            // A daemon_proxy panel approved csecd's use of the value, so the
            // pairing covers that use and never a release of it.
            await delegation.recordHumanApproval(
                session: delegatedSession, references: newReferences.filter { !reviewedPerRequest($0) },
                daemonUse: plan.mechanism == .daemonProxy, surface: surface
            )
        }
        await decisionLog?.record(panelRecord(
            review: review, rootPID: scope.pid, releaseShapeDigest: releaseShapeDigest,
            outcome: approved.outcome, decider: approved.decider, ttdMs: approved.ttdMs, cause: cause,
            scope: scope.kind.rawValue,
            duration: DecisionLogRecord.durationText(ttlSeconds: approvedTTL),
            grantIDs: mintedGrantIDs,
            rootLabel: scope.processLabel
        ))
        return response
    }

    private enum DelegatedRelease {
        case released(Response)
        /// The approval stands, but a value is not held: the panel follows.
        case declined(DelegationDecline)
        /// Refused outright (the requester changed, or went away while the
        /// restore panel it waited on was up).
        case refused(Response)
        /// The request went to this lifetime's restore panel for a value it
        /// needs. Nothing is released on the strength of the approval made
        /// before that: the caller judges the request again at the present,
        /// with the Deny-ledger ticket taken before the wait, and departs it.
        case waitedForRestore(HumanDenialLedger<AccessDenialShape>.Ticket)
    }

    /// Releases what Claude Code auto mode approved. New references resolve
    /// with no csec unlock (`resolveForDelegation`): warm, or fetched from a
    /// provider that needs no csec touch, never with a prompt of csec's own;
    /// references a live grant already covers resolve as the grant path does. A value csecd does not hold may still be reopened by this
    /// lifetime's one restore panel, raised for it or already up; a request
    /// that went there returns `.waitedForRestore` and is judged again. With
    /// `mayWaitForRestore` false (that second judgment) a value still cold
    /// declines as not held and the request gets its panel. The values are
    /// registered for redaction as a process-lifetime release.
    private func releaseDelegated(
        _ ticket: DelegationTicket,
        delegation: ClaudeDelegationService,
        refs: [SecretRef],
        newReferenceURIs: Set<String>,
        request: AccessRequest,
        caller: CallerInfo,
        plan: DeliveryPlan,
        rootPID: pid_t,
        rootStartTime: UInt64,
        releaseShapeDigest: String?,
        now: Date,
        mayWaitForRestore: Bool
    ) async -> DelegatedRelease {
        guard let releaseRoot = verifyDeliveryRoot(plan, caller: caller),
              releaseRoot.pid == rootPID, releaseRoot.startTime == rootStartTime else {
            return .refused(.failed(
                .invalidRequest, message: "the delegated requester changed before release", requestID: request.requestID
            ))
        }
        var values: [String: Data] = [:]
        var cold: [SecretRef] = []
        var coldReasons: [String: String] = [:]
        for ref in refs {
            switch await heldValue(ref, isNew: newReferenceURIs.contains(ref.uri)) {
            case let .value(value):
                values[ref.uri] = value
            case let .notHeld(reason):
                cold.append(ref)
                if let reason { coldReasons[ref.uri] = reason }
            }
        }
        // A cold value whose provider needs no csec unlock could not be
        // fetched just now (1Password locked, say); the restore panel does not
        // list it, so only values that need csec's touch wait on it.
        let resolvableWithoutUnlock = await resolver.referencesResolvableWithoutUnlock(cold)
        let needTouch = cold.filter { !resolvableWithoutUnlock.contains($0.uri) }
        if !needTouch.isEmpty, mayWaitForRestore, let restoration {
            // Waiting on the restore panel is waiting behind whatever panel is
            // on screen, so the request joins the Deny ledger before it waits,
            // as a queued request does: a human Deny of an identical request
            // made meanwhile then answers it too.
            let arrival = humanDenials.arrive()
            switch await restoration.ensureWarmForDelegation(for: needTouch, requester: caller) {
            case .forgotten:
                humanDenials.depart(arrival)
                return .refused(.failed(
                    .consentDenied,
                    message: "policy review denied (the approvals restored after csecd restarted were forgotten)",
                    requestID: request.requestID
                ))
            case .requesterGone:
                humanDenials.depart(arrival)
                await recordWithdrawn(
                    request: request, plan: plan, refs: refs, rootPID: rootPID,
                    releaseShapeDigest: releaseShapeDigest, now: now,
                    cause: nil, waitedFor: "the restore panel"
                )
                return .refused(.failed(.consentDenied, message: "consent request cancelled", requestID: request.requestID))
            case .failed:
                humanDenials.depart(arrival)
                return .refused(.failed(.consentDenied, message: "consent denied", requestID: request.requestID))
            case .warmed, .notNeeded, .usedUp:
                return .waitedForRestore(arrival)
            }
        }
        if let first = cold.first {
            // The provider's reason goes on the note and into the log, so a
            // value 1Password could not serve says why (csec-0.64.6).
            return .declined(await delegation.noteNotHeld(ticket, reference: first, reason: coldReasons[first.uri]))
        }
        guard let finalRoot = verifyDeliveryRoot(plan, caller: caller),
              finalRoot.pid == rootPID, finalRoot.startTime == rootStartTime else {
            return .refused(.failed(
                .invalidRequest, message: "the delegated requester changed during release", requestID: request.requestID
            ))
        }
        activeSecrets.register(valuesByReference: values, expiresAt: nil)
        await delegation.noteDelegatedRelease(ticket)
        var record = accessRecord(
            kind: .delegatedRelease, request: request, plan: plan, refs: refs,
            rootPID: ticket.session.agent.pid, releaseShapeDigest: releaseShapeDigest, now: now,
            outcome: .approved, decider: .delegated
        )
        record.requester?.class = "coding_agent:claude"
        record.delegation = DecisionLogRecord.Delegation(
            decision: "approved", claudeBuild: ticket.session.buildLabel,
            identityLookup: ticket.session.identityLookup?.logDescription
        )
        await decisionLog?.record(record)
        return .released(Response(requestID: request.requestID, values: values, accessExpiresAt: nil))
    }

    /// A value for a delegated release: with no csec unlock for a reference
    /// the request is new to, as the grant path resolves one a live grant
    /// covers.
    private func heldValue(_ ref: SecretRef, isNew: Bool) async -> DelegatedValue {
        if isNew { return await resolver.resolveForDelegation(ref) }
        return await resolver.resolveWithoutCsecUnlock(ref)
    }

    private func handleLegacyAccess(
        refs: [SecretRef],
        request: AccessRequest,
        caller: CallerInfo,
        rootPID: pid_t,
        rootStartTime: UInt64,
        now: Date,
        ownsConsentTurn: Bool
    ) async -> Response {
        let accessible = await grants.accessibleReferences(for: caller.pid, now: now)
        let newReferences = refs.filter { !accessible.contains($0.uri) }
        var unlock: CacheUnlock?
        if !newReferences.isEmpty {
            if !ownsConsentTurn {
                return await handleQueuedAccess(request: request, caller: caller)
            }
            let outcome = await consent.requestConsent(
                caller: caller,
                newReferences: newReferences,
                reason: request.reason,
                ttl: request.ttlSeconds.map(TimeInterval.init),
                policySummary: nil
            )
            guard case let .approved(approvedUnlock) = outcome else {
                return .failed(.consentDenied, message: "consent denied")
            }
            unlock = approvedUnlock
            await grants.add(Grant(
                rootPID: rootPID,
                rootStartTime: rootStartTime,
                references: Set(newReferences.map(\.uri)),
                reason: request.reason,
                expiresAt: request.ttlSeconds.map { now.addingTimeInterval(TimeInterval($0)) }
            ))
        }
        return await resolve(
            refs: refs,
            requestID: request.requestID,
            unlock: unlock,
            window: .unregistered
        )
    }

    private func resolve(
        refs: [SecretRef],
        requestID: String?,
        unlock: CacheUnlock?,
        window: ReleaseWindow
    ) async -> Response {
        // Releasing means it was decided — by this request's panel, an
        // earlier one's grant, or a restore it waited on — so its deadline no
        // longer applies to the provider work below.
        HumanWait.current?.decide()
        var values: [String: Data] = [:]
        for ref in refs {
            do {
                values[ref.uri] = try await resolver.resolve(ref, unlock: unlock)
            } catch {
                // The reference URI is value-free metadata the consent window
                // already displayed; naming it turns an opaque failure into an
                // actionable one. A provider may add a reason only through
                // `ProviderDiagnosableError`, which is csec-authored and
                // bounded; a tool's own error output never reaches a client.
                var message = "the provider could not resolve \(ref.safeInlineURI)"
                if let diagnosable = error as? ProviderDiagnosableError {
                    message += ": " + ReviewDisplay.bounded(
                        ReviewDisplay.sanitized(diagnosable.boundedReason),
                        maxBytes: 512
                    )
                }
                return .failed(.resolutionFailed, message: message, requestID: requestID)
            }
        }
        // Register released values for output redaction. A process-lifetime grant
        // registers with no clock (nil), so redaction covers it for as long as the
        // daemon holds the value; the caller is told no expiry, since liveness —
        // not a clock — bounds the grant.
        let accessExpiresAt: Date?
        switch window {
        case .unregistered:
            accessExpiresAt = nil
        case .untilProcessExits:
            activeSecrets.register(valuesByReference: values, expiresAt: nil)
            accessExpiresAt = nil
        case let .until(date):
            activeSecrets.register(valuesByReference: values, expiresAt: date)
            accessExpiresAt = date
        }
        return Response(
            requestID: requestID,
            values: values,
            accessExpiresAt: accessExpiresAt
        )
    }

    /// Planted-sidecar defense for symlink-delivered (`*.csec`) bindings that name
    /// a native `csec://` blob: the value must come from a blob whose recorded
    /// `csec protect` path equals the sidecar's own project location, so a sidecar
    /// dropped or moved by same-uid malware cannot redirect a native value to a
    /// path it was never protected at. It reuses the store key record cached by the
    /// just-completed resolution, so it adds no second Touch ID, and fails closed:
    /// a native binding whose recorded path differs (or is absent) is rejected.
    ///
    /// A sidecar is source-neutral, so a non-native reference (`op://`, …) has no
    /// recorded protect-path and cannot be path-bound; it is allowed here and, like
    /// `op://` everywhere else in csec, relies on the Touch ID review that shows the
    /// reference before release. Environment-delivered bindings are unaffected.
    ///
    /// A home-rooted link (`homeSymlink`, a home token file restored for its tool
    /// from any directory) is bound the same way against its home-relative path,
    /// which is what a store rooted at home records.
    public func protectedFilePathsAreBound(_ bindings: [ProtectedFileBinding]) async -> Bool {
        for binding in bindings {
            guard let target = binding.symlinkTarget ?? binding.homeSymlinkTarget else { continue }
            guard let reference = try? SecretRef(binding.reference) else { return false }
            // Only native references carry a recorded protect-path to bind against.
            guard reference.scheme == "csec" else { continue }
            guard let nativeStore,
                  let nativeReference = try? NativeSecretReference(reference),
                  let recordedPath = await nativeStore.recordedBlobPath(
                      store: nativeReference.store, key: nativeReference.key),
                  recordedPath == target else {
                return false
            }
        }
        return true
    }

    private func displayedCaller(
        _ caller: CallerInfo,
        plan: DeliveryPlan,
        rootPID: pid_t,
        // When the review offers a scope selector, that selector is the
        // authoritative statement of the grant root; naming a root here too
        // would contradict a live selection.
        statesGrantRoot: Bool = true
    ) -> CallerInfo {
        var displayed = caller
        let executableName = URL(fileURLWithPath: plan.executable.canonicalPath).lastPathComponent
        if case .directParent = plan.root {
            let requester = plan.requestingExecutable ?? plan.executable
            // Derive the label from the independently checked executable path,
            // not the process's mutable display name.
            let requesterName = URL(fileURLWithPath: requester.canonicalPath).lastPathComponent
            displayed.description = "\(requesterName) [\(requester.assurance.rawValue)] "
                + "(pid \(rootPID)) via \(caller.description)"
        } else {
            let root = statesGrantRoot ? " (grant root pid \(rootPID))" : ""
            displayed.description = "\(caller.description) for \(executableName) "
                + "[\(plan.executable.assurance.rawValue)]\(root)"
        }
        return displayed
    }

    private func policyDenied(
        _ decision: ReleaseDecision,
        plan: DeliveryPlan,
        requestID: String?
    ) -> Response {
        let reason = decision.denialReason?.rawValue ?? "denied"
        return .failed(
            .policyDenied,
            message: "release policy denied \(plan.mechanism.rawValue) delivery (\(reason))",
            requestID: requestID
        )
    }

    /// Label for the plan's own root, which is not always the emitter. For a
    /// direct-parent root (an interactive `csec get`) the root process is the
    /// requester — the shell — not the signed csec that emits the bytes; for a
    /// registered session it is neither, so the live kernel name is the only
    /// honest description of that pid.
    private func scopeRequestingLabel(plan: DeliveryPlan, rootPID: pid_t) -> String {
        if case .registeredSession = plan.root {
            return processInspection.name(of: rootPID)
                ?? URL(fileURLWithPath: plan.executable.canonicalPath).lastPathComponent
        }
        let requester = plan.requestingExecutable ?? plan.executable
        return URL(fileURLWithPath: requester.canonicalPath).lastPathComponent
    }

    /// A widened root is honored only while it is the same live process it was
    /// when the window was drawn, and only while it still contains the plan root.
    /// Both are fresh kernel checks; nothing the reviewer returns is trusted.
    private func verifiedScopeRoot(
        _ scope: GrantScopeOption,
        planRootPID: pid_t
    ) -> Bool {
        scope.pid > 1
            && processInspection.startTime(of: scope.pid) == scope.startTime
            && processInspection.descends(
                planRootPID, from: scope.pid, rootStartTime: scope.startTime
            )
    }

    /// A value-free one-line summary of the delivery shown in the Touch ID
    /// reason string. It names the mechanism, root, scope, destination, and
    /// recipient — there is no risk level, because there no longer is one. When
    /// the review offered a scope selector, the root is the option that was
    /// actually selected.
    private func releasePolicySummary(
        plan: DeliveryPlan,
        scope: GrantScopeOption? = nil
    ) -> String {
        let root: String
        if let scope {
            root = ReviewDisplay.scopeSummary(scope)
        } else if case .registeredSession = plan.root {
            root = "registered session"
        } else {
            root = "per-command"
        }
        return "delivery \(plan.mechanism.rawValue); root \(root); "
            + "scope \(plan.descendantScope.rawValue); "
            + "destination \(plan.destination.rawValue); recipient "
            + "\(plan.recipientAssurance?.rawValue ?? "planned_consumer")"
    }

    /// Production policy review freezes its visible choices at biometric
    /// success and keeps the trusted window and evaluated LAContext alive while
    /// this actor validates that snapshot. Test/headless reviewers have no
    /// embedded session and continue through the injected consent seam.
    private func authenticateReviewedAccess(
        approval: AccessPolicyApproval,
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval?,
        policySummary: String
    ) async -> ConsentOutcome {
        if let session = approval.authenticationSession {
            let displaySummary = policySummary
                + "; duration \(BiometricConsent.formatDuration(ttl))"
            return await session.completeAfterPolicyApproval(
                policySummary: displaySummary
            )
        }
        return await consent.requestConsent(
            caller: caller,
            newReferences: newReferences,
            reason: reason,
            ttl: ttl,
            policySummary: policySummary
        )
    }

    /// The launcher's argv as the review window shows it. Every argument goes
    /// through the same redaction catalog `csec exec` output does — built from
    /// the values csecd has already released and still holds live — so a
    /// plaintext credential pasted into a command is labelled, never echoed.
    /// The values this very request asks for are not yet resolved (that needs
    /// the approval), so they cannot appear here; a literal never seen by csecd
    /// is outside what any catalog can recognize.
    private func displayCommandLine(_ arguments: [String], plan: DeliveryPlan, now: Date) -> String {
        let snapshot = activeSecrets.snapshot(now: now)
        let catalog = OutputRedactionCatalog(
            referenceByValue: snapshot.referenceByValue,
            labelStyle: plan.outputGuard?.labelStyle ?? .opaque,
            includeShortValues: plan.outputGuard?.includeShortValues ?? false
        )
        var redactor = StreamingOutputRedactor(patterns: catalog.patterns)
        let redacted = arguments.map { argument -> String in
            var bytes = redactor.process(Data(argument.utf8)).data
            bytes.append(redactor.finish().data)
            return String(decoding: bytes, as: UTF8.self)
        }
        return ReviewDisplay.commandLine(redacted)
    }

    /// The command line of a direct-parent requester (a language client over
    /// `csec bridge`, a `csec get`) whose request carried no argv, as the
    /// review shows it under the reason that requester wrote. csecd reads it
    /// from the kernel by the plan root's pid, only while that pid is still
    /// the process that started at the root's start time; nothing the
    /// request says goes into it. It takes the same redaction, sanitizing
    /// and bound as the launcher's argv. Nil when it cannot be read: the
    /// review then shows the reason alone, as before.
    private func requesterCommandLine(request: AccessRequest, plan: DeliveryPlan, now: Date) -> String? {
        guard request.commandLine == nil,
              case let .directParent(pid, startTime) = plan.root,
              let arguments = processInspection.arguments(of: pid, startedAt: startTime) else { return nil }
        return displayCommandLine(arguments, plan: plan, now: now)
    }

    /// The record of one native-store edit panel (`csec edit`, an import): the
    /// store's edit-consent reference, never its contents.
    private func nativeEditRecord(
        kind: DecisionLogRecord.Kind = .panel,
        review: AccessPolicyReview,
        store: NativeStoreName,
        outcome: DecisionLogRecord.Outcome,
        decider: DecisionLogRecord.Decider?,
        ttdMs: Int?,
        failure: String? = nil
    ) -> DecisionLogRecord {
        DecisionLogRecord(
            kind: kind,
            surface: .nativeEdit,
            requester: DecisionLogRecord.Requester(
                class: "edit", rootPID: review.caller.pid, terminal: review.caller.terminal?.summary
            ),
            refs: review.credentials.flatMap(\.references).map(\.uri).sorted(),
            mechanism: review.plan.mechanism.rawValue,
            outcome: outcome,
            decider: decider,
            ttdMs: ttdMs,
            detail: "\(review.plan.operationContext) for store \(store.value)"
                + (failure.map { ": \($0)" } ?? "")
        )
    }

    /// A value-free record of a request decided without a panel of its own (a
    /// grant reuse, or a refusal by an earlier Deny). The command is the same
    /// redacted display string a panel would have shown.
    private func accessRecord(
        kind: DecisionLogRecord.Kind,
        request: AccessRequest,
        plan: DeliveryPlan,
        refs: [SecretRef],
        rootPID: pid_t,
        releaseShapeDigest: String?,
        now: Date,
        outcome: DecisionLogRecord.Outcome?,
        decider: DecisionLogRecord.Decider?,
        rootLabel: String? = nil,
        detail: String? = nil
    ) -> DecisionLogRecord {
        DecisionLogRecord(
            kind: kind,
            surface: .secretAccess,
            requester: DecisionLogRecord.Requester(
                class: DecisionLogRecord.requesterClass(plan: plan, scopeChoices: nil),
                rootPID: rootPID,
                rootLabel: rootLabel
            ),
            refs: refs.map(\.uri).sorted(),
            shape: releaseShapeDigest.map { String($0.prefix(16)) },
            mechanism: plan.mechanism.rawValue,
            command: request.commandLine.map { displayCommandLine($0, plan: plan, now: now) },
            commandDigest: plan.commandDigest,
            outcome: outcome,
            decider: decider,
            detail: detail
        )
    }

    /// `reference_not_found` for a request with a reference its provider
    /// already knows cannot resolve, and its `absent_reference` record; nil
    /// when every reference may resolve. Value-free: the message and the
    /// record carry each provider's own bounded reason.
    private func refuseKnownAbsent(
        refs: [SecretRef],
        request: AccessRequest,
        plan: DeliveryPlan,
        rootPID: pid_t,
        releaseShapeDigest: String?,
        now: Date
    ) async -> Response? {
        let absent = await resolver.referencesKnownAbsent(refs)
        guard let summary = Self.absentSummary(absent) else { return nil }
        if let decisionLog, let record = absentReferenceRecords.admit(accessRecord(
            kind: .absentReference, request: request, plan: plan, refs: refs,
            rootPID: rootPID, releaseShapeDigest: releaseShapeDigest, now: now,
            outcome: nil, decider: nil, detail: summary + "; refused before a panel"
        )) {
            await decisionLog.record(record)
        }
        return .failed(
            .referenceNotFound,
            message: summary + "; no approval was asked",
            requestID: request.requestID
        )
    }

    /// "csec://harbor/RELAY_TOKEN: the requested key does not exist in the
    /// native store", naming the first of `absent` and counting the rest; nil
    /// when `absent` is empty.
    static func absentSummary(_ absent: [KnownAbsentReference]) -> String? {
        guard let first = absent.first else { return nil }
        let others = absent.count - 1
        guard others > 0 else { return first.summary }
        return first.summary + " (and \(others) more reference\(others == 1 ? "" : "s") that cannot resolve)"
    }

    /// The `withdrawn` record of a request that left a wait on a human (its
    /// turn, the UI queue, the restore panel) with nobody having decided:
    /// its requester went away, or its deadline passed.
    private func recordWithdrawn(
        request: AccessRequest,
        plan: DeliveryPlan,
        refs: [SecretRef],
        rootPID: pid_t,
        releaseShapeDigest: String?,
        now: Date,
        cause: String?,
        waitedFor: String? = nil
    ) async {
        guard let decisionLog else { return }
        let wait = HumanWait.current
        let place = waitedFor.map { "waited for \($0)" }
        let detail = wait?.withdrawnDetail(cause: cause, place: place)
            ?? "\(place ?? "never shown"); \(cause ?? "its requester went away")"
        await decisionLog.record(accessRecord(
            kind: .withdrawn, request: request, plan: plan, refs: refs,
            rootPID: wait?.requestAnchor?.scope.pid ?? rootPID, releaseShapeDigest: releaseShapeDigest, now: now,
            outcome: wait?.isExpired == true ? .timedOut : .requesterGone, decider: nil,
            rootLabel: wait?.requestAnchor?.scope.label, detail: detail
        ))
    }

    /// How a request's notice names it: the references, which every review
    /// and record already shows. Never a value.
    static func waitSummary(references: [String]) -> String {
        let shown = references.prefix(1).map { (try? SecretRef($0))?.safeInlineURI ?? "a secret reference" }
        guard let first = shown.first else { return "secret access" }
        let more = references.count - 1
        return "secret access to \(first)" + (more > 0 ? " (+\(more) more)" : "")
    }

    /// The record of one access panel, built from the review exactly as the
    /// window showed it.
    private func panelRecord(
        kind: DecisionLogRecord.Kind = .panel,
        review: AccessPolicyReview,
        rootPID: pid_t,
        releaseShapeDigest: String?,
        outcome: DecisionLogRecord.Outcome,
        decider: DecisionLogRecord.Decider?,
        ttdMs: Int? = nil,
        cause: DecisionLogPromptCause? = nil,
        scope: String?,
        duration: String?,
        grantIDs: [String]? = nil,
        rootLabel: String? = nil,
        detail: String? = nil
    ) -> DecisionLogRecord {
        DecisionLogRecord(
            kind: kind,
            surface: .secretAccess,
            requester: DecisionLogRecord.Requester(
                class: DecisionLogRecord.requesterClass(plan: review.plan, scopeChoices: review.scopeChoices),
                rootPID: rootPID,
                rootLabel: rootLabel ?? review.scopeChoices?.defaultOption.processLabel,
                terminal: review.caller.terminal?.summary
            ),
            refs: review.credentials.flatMap(\.references).map(\.uri).sorted(),
            shape: releaseShapeDigest.map { String($0.prefix(16)) },
            mechanism: review.plan.mechanism.rawValue,
            command: review.commandLine ?? review.requesterCommandLine,
            commandDigest: review.plan.commandDigest,
            scope: scope,
            duration: duration,
            outcome: outcome,
            decider: decider,
            ttdMs: ttdMs,
            cause: cause?.rawValue,
            grantIDs: grantIDs,
            detail: detail
        )
    }

    /// The record of an approved release that delivered nothing, written right
    /// after the approval's own panel record. `detail` is the value-free
    /// failure the client is given.
    private func deliveryFailedRecord(
        review: AccessPolicyReview,
        rootPID: pid_t,
        releaseShapeDigest: String?,
        detail: String
    ) -> DecisionLogRecord {
        DecisionLogRecord(
            kind: .deliveryFailed,
            surface: .secretAccess,
            requester: DecisionLogRecord.Requester(
                class: DecisionLogRecord.requesterClass(plan: review.plan, scopeChoices: review.scopeChoices),
                rootPID: rootPID,
                terminal: review.caller.terminal?.summary
            ),
            refs: review.credentials.flatMap(\.references).map(\.uri).sorted(),
            shape: releaseShapeDigest.map { String($0.prefix(16)) },
            mechanism: review.plan.mechanism.rawValue,
            commandDigest: review.plan.commandDigest,
            detail: detail + "; no grant was minted"
        )
    }

    /// Why a panel for `newReferences` appeared: this run's approvals first,
    /// then the persisted grants the restart dropped, in the precedence
    /// `DecisionLogPromptCause.accountingForRestart` states.
    private func promptCause(
        newReferences: Set<String>,
        lastingAccess: Bool = false,
        caller: CallerInfo,
        now: Date,
        deliveryPlanDigest: String?,
        releaseShapeDigest: String?,
        widenedScopeOnly: Bool
    ) async -> DecisionLogPromptCause {
        // No approval ever covers a lasting GitHub request or a one-time
        // code, so only the other references can say why the panel came;
        // with none, the codes did.
        if lastingAccess { return .lastingAccess }
        let newReferences = newReferences.filter { (try? SecretRef($0))?.isOneTimeCode != true }
        guard !newReferences.isEmpty else { return .oneTimeCode }
        let inRun = inRunPromptCause(newReferences: newReferences, caller: caller, now: now)
        let dropped = await grantPersistence?.droppedGrantCovering(
            references: newReferences,
            callerPID: caller.pid,
            deliveryPlanDigest: deliveryPlanDigest,
            releaseShapeDigest: releaseShapeDigest,
            callerAuditSessionID: caller.peerIdentity?.audit.auditSessionID,
            widenedScopeOnly: widenedScopeOnly,
            now: now,
            processInspection: processInspection
        )
        return .accountingForRestart(inRun: inRun, droppedAtLoad: dropped)
    }

    /// Why a panel for `newReferences` appeared, from this run's approvals: a
    /// live approval covering this process tree for another release shape; one
    /// that reached its chosen lifetime; one revoked; one for a process tree
    /// this request is not in (or that exited); or none at all.
    private func inRunPromptCause(
        newReferences: Set<String>, caller: CallerInfo, now: Date
    ) -> DecisionLogPromptCause {
        let related = approvalMemories.filter { !$0.references.isDisjoint(with: newReferences) }
        guard !related.isEmpty else { return .newRefs }
        let covering = related.filter { memory in
            memory.rootPID > 1
                && processInspection.startTime(of: memory.rootPID) == memory.rootStartTime
                && processInspection.descends(caller.pid, from: memory.rootPID, rootStartTime: memory.rootStartTime)
        }
        func expired(_ memory: ApprovalMemory) -> Bool { memory.expiresAt.map { now >= $0 } ?? false }
        if covering.contains(where: { !$0.revoked && !expired($0) }) { return .newReleaseShape }
        if covering.contains(where: { !$0.revoked && expired($0) }) { return .grantExpired }
        if covering.contains(where: \.revoked) { return .grantRevoked }
        return .newProcess
    }

    private func rememberApproval(_ memory: ApprovalMemory) {
        guard !memory.references.isEmpty else { return }
        approvalMemories.append(memory)
        if approvalMemories.count > Self.maximumApprovalMemories {
            approvalMemories.removeFirst(approvalMemories.count - Self.maximumApprovalMemories)
        }
    }

    public func beginOutputRedaction(
        request: BeginOutputRedactionRequest,
        caller: CallerInfo,
        now: Date = Date()
    ) -> Response {
        pruneRedactionSessions()
        let owner = RedactionCaller(pid: caller.pid, startTime: caller.startTime)
        guard UUID(uuidString: request.requestID) != nil,
              owner.isLive(using: processInspection),
              request.destination == .aiTool || request.destination == .localDevelopment,
              !request.streams.isEmpty,
              request.streams.count <= OutputRedactionStream.allCases.count,
              Set(request.streams).count == request.streams.count,
              redactionSessions.count < Self.maximumRedactionSessions else {
            return .failed(
                .invalidRequest,
                message: "output-redaction request is outside supported bounds",
                requestID: request.requestID
            )
        }

        let snapshot = activeSecrets.snapshot(now: now)
        let catalog = OutputRedactionCatalog(
            referenceByValue: snapshot.referenceByValue,
            labelStyle: request.labelStyle,
            includeShortValues: request.includeShortValues
        )
        let sessionID = UUID().uuidString.lowercased()
        redactionSessions[sessionID] = RedactionSession(
            caller: owner,
            destination: request.destination,
            redactors: Dictionary(uniqueKeysWithValues: request.streams.map {
                ($0, StreamingOutputRedactor(
                    patterns: catalog.patterns,
                    interpretsTerminalControls: $0 == .terminal
                ))
            }),
            finishedStreams: [],
            registryGeneration: snapshot.generation,
            includeShortValues: request.includeShortValues,
            labelStyle: request.labelStyle
        )
        return Response(
            requestID: request.requestID,
            outputRedactionSessionID: sessionID,
            protectedValueCount: catalog.protectedValueCount,
            skippedShortValueCount: catalog.skippedShortValueCount
        )
    }

    public func redactOutputChunk(
        request: RedactOutputChunkRequest,
        caller: CallerInfo,
        now: Date = Date()
    ) -> Response {
        pruneRedactionSessions()
        guard UUID(uuidString: request.requestID) != nil,
              UUID(uuidString: request.sessionID) != nil,
              request.data.count <= Self.maximumOutputChunkBytes,
              var session = redactionSessions[request.sessionID],
              session.destination == .aiTool || session.destination == .localDevelopment,
              session.caller.matches(caller),
              !session.finishedStreams.contains(request.stream),
              !(request.prime == true && request.finish),
              var redactor = session.redactors[request.stream] else {
            return .failed(
                .invalidRequest,
                message: "invalid or inactive output-redaction session",
                requestID: request.requestID
            )
        }

        // Values released while the command is running join the matcher before
        // the next output chunk. Existing patterns are never removed mid-stream,
        // preserving any prefix already withheld by this session.
        let snapshot = activeSecrets.snapshot(now: now)
        if snapshot.generation != session.registryGeneration {
            let catalog = OutputRedactionCatalog(
                referenceByValue: snapshot.referenceByValue,
                labelStyle: session.labelStyle,
                includeShortValues: session.includeShortValues
            )
            for stream in Array(session.redactors.keys) {
                session.redactors[stream]?.add(patterns: catalog.patterns)
            }
            session.registryGeneration = snapshot.generation
            redactor = session.redactors[request.stream]!
        }

        var result = redactor.process(request.data)
        if request.prime == true {
            // The launcher already forwarded what the old scanner emitted of
            // these bytes; only the matcher state they leave behind matters.
            result = OutputRedactionResult(data: Data(), matches: [])
        }
        if request.finish {
            let final = redactor.finish()
            result = OutputRedactionResult(
                data: result.data + final.data,
                matches: result.matches + final.matches
            )
            session.finishedStreams.insert(request.stream)
        }
        session.redactors[request.stream] = redactor
        redactionSessions[request.sessionID] = session

        return Response(
            requestID: request.requestID,
            redactedData: result.data,
            redactionMatches: result.matches
        )
    }

    public func endOutputRedaction(
        request: EndOutputRedactionRequest,
        caller: CallerInfo
    ) async -> Response {
        pruneRedactionSessions()
        guard UUID(uuidString: request.requestID) != nil,
              UUID(uuidString: request.sessionID) != nil,
              let session = redactionSessions[request.sessionID],
              session.caller.matches(caller) else {
            return .failed(
                .invalidRequest,
                message: "invalid or inactive output-redaction session",
                requestID: request.requestID
            )
        }
        redactionSessions.removeValue(forKey: request.sessionID)
        // The session's peer is the `csec ai` its command ran under: an SSH
        // signature or a sudo under it that delegation declined for a setup
        // reason left its notice there.
        return Response(
            requestID: request.requestID, redactedData: Data(),
            delegationNotice: await delegation?.takeSetupNotice(for: caller)
        )
    }

    /// The notices a `csec ai` prints for requests started under it that
    /// wait on a human and could not say so themselves (`HumanWaitBoard`).
    /// Only the live session's own `csec ai` may ask, and each notice is
    /// handed to it once.
    public func takeApprovalNotices(
        request: TakeApprovalNoticesRequest,
        caller: CallerInfo
    ) async -> Response {
        pruneRedactionSessions()
        guard UUID(uuidString: request.requestID) != nil,
              UUID(uuidString: request.sessionID) != nil,
              let session = redactionSessions[request.sessionID],
              session.caller.matches(caller) else {
            return .failed(
                .invalidRequest,
                message: "invalid or inactive output-redaction session",
                requestID: request.requestID
            )
        }
        let notices = humanWaitBoard?.take(
            forSession: request.sessionID,
            ancestorPID: caller.pid,
            ancestorStartTime: caller.startTime,
            inspection: processInspection
        ) ?? []
        return Response(requestID: request.requestID, approvalNotices: notices)
    }

    public func beginNativeStoreEdit(
        request: BeginNativeStoreEditRequest,
        caller: CallerInfo
    ) async -> Response {
        await HumanWait.tracking(caller: caller, inspection: processInspection) { caller in
            await self.beginNativeStoreEditPending(request: request, caller: caller)
        }
    }

    private func beginNativeStoreEditPending(
        request: BeginNativeStoreEditRequest, caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              request.store.utf8.count <= 64,
              caller.startTime > 0,
              isVerifiedLauncher(caller),
              Self.hasValidNativeEditorMetadata(request),
              request.origin.map(NativeStoreOriginMarker.isValidOrigin) ?? true else {
            return .failed(
                .invalidRequest,
                message: "the native-store edit request is invalid",
                requestID: request.requestID
            )
        }
        guard let nativeStore else {
            return .failed(
                .nativeStoreUnavailable,
                message: "the native encrypted store is unavailable",
                requestID: request.requestID
            )
        }
        // Reclaim the sessions of editors that are gone before this one competes
        // for a slot, so a crashed editor never costs a human their next edit —
        // and so the reclaim happens before the review, not after a Touch ID that
        // would then fail on a full table.
        await sweepNativeEditSessions()
        let store: NativeStoreName
        do {
            store = try NativeStoreName(request.store)
        } catch {
            return .failed(
                .invalidRequest,
                message: "the native store name is invalid",
                requestID: request.requestID
            )
        }

        let plannedExecutable: PlannedExecutable
        switch request.mode {
        case .builtInMemory, .onboardingImport, .sshKeyImport, .githubTokenImport:
            guard let executablePath = ProcessAncestry.executablePath(of: caller.pid) else {
                return .failed(
                    .unverifiedPeer,
                    message: "the native-store editor process is unavailable",
                    requestID: request.requestID
                )
            }
            plannedExecutable = PlannedExecutable(
                canonicalPath: executablePath,
                signingIdentifier: ProductCodeIdentity.launcherIdentifier,
                teamIdentifier: ProductCodeIdentity.teamIdentifier,
                assurance: .verifiedProduct
            )
        case .externalTemporaryFile:
            plannedExecutable = PlannedExecutable(
                canonicalPath: request.externalEditorPath!,
                assurance: .unverified
            )
        }
        let consentReference = NativeSecretReference.editConsentReference(for: store)
        let operationContext: String
        switch request.mode {
        case .builtInMemory:
            operationContext = "built-in native-store editor"
        case .onboardingImport:
            operationContext = "explicit onboarding import into the native encrypted store"
        case .sshKeyImport:
            operationContext = "protect and register private SSH keys for signature-only use"
        case .githubTokenImport:
            operationContext = "protect the GitHub CLI token and register it for use only inside csecd"
        case .externalTemporaryFile:
            operationContext = "external native-store editor using a named plaintext file"
        }
        let plan = DeliveryPlan(
            mechanism: request.mode == .externalTemporaryFile
                ? .namedPlaintextFile
                : .directHeap,
            executable: plannedExecutable,
            root: .caller,
            descendantScope: .exactProcess,
            destination: .localDevelopment,
            // No clock: the edit lives as long as the editor process that opened
            // it. An expiry here would throw away a human's unsaved work while
            // they were still typing, and would bound nothing that the
            // caller-liveness sweep does not already bound.
            requestedTTLSeconds: nil,
            operationContext: operationContext,
            // Choosing `csec edit --editor` (the only path that uses the
            // named-plaintext-file mechanism here) is itself the explicit
            // acknowledgment of the temporary plaintext file it warns about.
            plaintextExposureAcknowledged: request.mode == .externalTemporaryFile
        )

        do {
            // A native-store edit is authorized by one display-only review +
            // Touch ID, exactly like a secret release: no classification, no
            // acceptance. The plan requests no lifetime, so the decision carries
            // none either — the edit session is bound to its editor process.
            let decision = ReleasePolicy.evaluate(plan: plan)
            guard decision.allowed else {
                return policyDenied(decision, plan: plan, requestID: request.requestID)
            }
            var reviewedCaller = caller
            reviewedCaller.terminal = await terminalInspection.context(forCallerPID: caller.pid)
            // An edit or import is setup at this Mac: only a local Touch ID
            // can write sealed storage, so it is never mirrored to the phone.
            let review = AccessPolicyReview(
                caller: reviewedCaller,
                reason: plan.operationContext,
                plan: plan,
                credentials: [await resolver.reviewCredential(for: [consentReference])],
                macOnly: true
            )
            let reviewOutcome = await policyReview.reviewAccess(review)
            guard case let .approved(approval) = reviewOutcome else {
                var message = "native-store \(AccessPolicyDenialReason.deniedPrefix)"
                if case let .denied(reason) = reviewOutcome {
                    let reason = HumanWait.current?.effectiveReason(reason) ?? reason
                    let ended = DecisionLogRecord.outcome(for: reason)
                    await decisionLog?.record(nativeEditRecord(
                        kind: DecisionLogRecord.kind(for: reason),
                        review: review, store: store, outcome: ended.outcome,
                        decider: ended.decider, ttdMs: ended.ttdMs,
                        failure: HumanWait.current?.abandonment != nil ? HumanWait.current?.withdrawnDetail() : nil
                    ))
                    message = reason.deniedMessage(prefix: message)
                }
                return .failed(
                    .consentDenied,
                    message: message,
                    requestID: request.requestID
                )
            }
            let outcome = await authenticateReviewedAccess(
                approval: approval,
                caller: caller,
                newReferences: [consentReference],
                reason: plan.operationContext,
                ttl: decision.grantedTTLSeconds.map(TimeInterval.init),
                policySummary: releasePolicySummary(plan: plan)
            )
            guard case let .approved(unlock) = outcome else {
                await decisionLog?.record(nativeEditRecord(
                    review: review, store: store, outcome: .authenticationFailed, decider: nil, ttdMs: nil
                ))
                return .failed(
                    .consentDenied,
                    message: "consent denied",
                    requestID: request.requestID
                )
            }

            let approved = DecisionLogRecord.outcome(for: approval)
            guard isVerifiedLauncher(caller) else {
                await decisionLog?.record(nativeEditRecord(
                    review: review, store: store, outcome: approved.outcome,
                    decider: approved.decider, ttdMs: approved.ttdMs,
                    failure: "the requester was abandoned after approval; no edit began"
                ))
                return .failed(.consentDenied, message: "the approved requester changed", requestID: request.requestID)
            }
            let edit: NativeStoreEditStart
            do {
                edit = try await nativeStore.beginEdit(
                    store: store,
                    callerPID: caller.pid,
                    callerStartTime: caller.startTime,
                    unlock: unlock,
                    origin: request.origin
                )
            } catch {
                await decisionLog?.record(nativeEditRecord(
                    review: review, store: store, outcome: approved.outcome,
                    decider: approved.decider, ttdMs: approved.ttdMs,
                    failure: "the store could not be opened; no edit began"
                ))
                throw error
            }
            await decisionLog?.record(nativeEditRecord(
                review: review, store: store, outcome: approved.outcome,
                decider: approved.decider, ttdMs: approved.ttdMs
            ))
            nativeEditAuthorizations[edit.sessionID] = NativeEditAuthorization(
                callerPID: caller.pid,
                callerStartTime: caller.startTime,
                store: store,
                mode: request.mode
            )
            return Response(
                requestID: request.requestID,
                editSessionID: edit.sessionID,
                document: edit.document
            )
        } catch {
            return nativeStoreFailure(error, requestID: request.requestID)
        }
    }

    public func commitNativeStoreEdit(
        request: CommitNativeStoreEditRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              UUID(uuidString: request.editSessionID) != nil,
              request.document.count <= NativeStoreDocument.maximumBytes,
              caller.startTime > 0,
              isVerifiedLauncher(caller),
              let nativeStore,
              let authorization = nativeEditAuthorizations[request.editSessionID],
              authorization.callerPID == caller.pid,
              authorization.callerStartTime == caller.startTime else {
            return .failed(
                .invalidRequest,
                message: "the native-store edit request is invalid",
                requestID: request.requestID
            )
        }
        do {
            let result = try await nativeStore.commitEdit(
                sessionID: request.editSessionID,
                document: request.document,
                callerPID: caller.pid,
                callerStartTime: caller.startTime
            )
            nativeEditAuthorizations[request.editSessionID] = nil
            return Response(
                requestID: request.requestID,
                generation: result.generation,
                secretCount: result.secretCount
            )
        } catch {
            return nativeStoreFailure(error, requestID: request.requestID)
        }
    }

    public func commitNativeStoreBlobs(
        request: CommitNativeStoreBlobsRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              UUID(uuidString: request.editSessionID) != nil,
              !request.blobs.isEmpty,
              request.blobs.count <= Self.maximumImportBlobs,
              caller.startTime > 0,
              isVerifiedLauncher(caller),
              let nativeStore,
              let authorization = nativeEditAuthorizations[request.editSessionID],
              authorization.callerPID == caller.pid,
              authorization.callerStartTime == caller.startTime,
              request.sshKeyRegistrations.isEmpty || (
                authorization.mode == .sshKeyImport && sshSigningService != nil
              ),
              request.githubTokenRegistration == nil || (
                authorization.mode == .githubTokenImport && githubProxy != nil
                    && request.sshKeyRegistrations.isEmpty && request.blobs.count == 1
              ) else {
            return .failed(
                .invalidRequest,
                message: "the native-store blob import request is invalid",
                requestID: request.requestID
            )
        }
        var totalBytes = 0
        var keys = Set<String>()
        for blob in request.blobs {
            totalBytes += blob.data.count
            guard keys.insert(blob.key).inserted else {
                return .failed(
                    .invalidRequest,
                    message: "the blob import batch contains a duplicate key",
                    requestID: request.requestID
                )
            }
        }
        guard totalBytes <= Self.maximumImportTotalBytes else {
            return .failed(
                .invalidRequest,
                message: "the blob import batch exceeds the per-request size limit",
                requestID: request.requestID
            )
        }
        if !request.sshKeyRegistrations.isEmpty {
            let expected = Set(request.blobs.compactMap {
                try? NativeSecretReference(store: authorization.store, key: $0.key).uri
            })
            let requested = Set(request.sshKeyRegistrations.map(\.reference))
            guard expected.count == request.blobs.count,
                  requested.count == request.sshKeyRegistrations.count,
                  requested == expected else {
                return .failed(
                    .invalidRequest,
                    message: "SSH registrations must exactly match the imported canonical references",
                    requestID: request.requestID
                )
            }
            // Registration happens after the import is durable and refuses a
            // key it cannot parse or a key listed twice, so check both on the
            // bytes in hand first: a refused batch then writes nothing.
            var publicKeys = Set<Data>()
            for blob in request.blobs {
                let key: SSHPrivateKey
                do {
                    key = try SSHPrivateKey.parse(blob.data)
                } catch {
                    return sshFailure(error, requestID: request.requestID)
                }
                guard publicKeys.insert(key.publicKeyBlob).inserted else {
                    return .failed(
                        .invalidRequest,
                        message: "the SSH key batch holds the same key more than once",
                        requestID: request.requestID
                    )
                }
            }
        }
        var githubToken: SecretRef?
        if let registration = request.githubTokenRegistration {
            // The one imported blob, by its canonical reference, and a value
            // that can be a token: checked before anything is written.
            guard let blob = request.blobs.first,
                  let reference = try? NativeSecretReference(store: authorization.store, key: blob.key).secretRef,
                  reference.uri == registration,
                  GitHubProxyToken.isWellFormed(blob.data) else {
                return .failed(
                    .invalidRequest,
                    message: "the GitHub token registration must name the one imported token",
                    requestID: request.requestID
                )
            }
            githubToken = reference
        }
        do {
            let requests = request.blobs.map {
                NativeBlobStore.PutRequest(key: $0.key, data: $0.data, mode: $0.mode, path: $0.path)
            }
            let result = try await nativeStore.commitBlobs(
                sessionID: request.editSessionID,
                requests: requests,
                callerPID: caller.pid,
                callerStartTime: caller.startTime
            )
            nativeEditAuthorizations[request.editSessionID] = nil
            var sshKeys: [SSHKeyMetadata]?
            if !request.sshKeyRegistrations.isEmpty {
                guard let sshSigningService else {
                    return .failed(
                        .sshAgentUnavailable,
                        message: "the SSH signing service is unavailable",
                        requestID: request.requestID
                    )
                }
                do {
                    sshKeys = try await sshSigningService.registerAlreadyAuthorized(
                        request.sshKeyRegistrations,
                        caller: caller
                    )
                } catch {
                    // The encrypted import is already durable. Returning failure
                    // keeps csec from writing sidecars or unlinking plaintext.
                    return sshFailure(error, requestID: request.requestID)
                }
            }
            var github: GitHubProxyStatus?
            if let githubToken {
                // The encrypted import is already durable; failing here keeps
                // csec from touching gh's own credential, and says where the
                // second copy now is.
                guard let githubProxy else {
                    return .failed(
                        .githubProxyUnavailable,
                        message: "the token is stored as \(githubToken.uri), but this csecd has no GitHub socket to register it with",
                        requestID: request.requestID
                    )
                }
                do {
                    try await githubProxy.register(githubToken)
                } catch let error as GitHubProxyError {
                    return .failed(
                        .githubProxyUnavailable,
                        message: "the token is stored as \(githubToken.uri), but it was not registered: \(error.message)",
                        requestID: request.requestID
                    )
                }
                github = await githubProxy.status
            }
            return Response(
                requestID: request.requestID,
                generation: result.generation,
                secretCount: result.secretCount,
                sshKeys: sshKeys,
                github: github
            )
        } catch {
            return nativeStoreFailure(error, requestID: request.requestID)
        }
    }

    public func cancelNativeStoreEdit(
        request: CancelNativeStoreEditRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              UUID(uuidString: request.editSessionID) != nil,
              caller.startTime > 0,
              isVerifiedLauncher(caller),
              let nativeStore else {
            return .failed(
                .invalidRequest,
                message: "the native-store edit request is invalid",
                requestID: request.requestID
            )
        }
        await nativeStore.cancelEdit(
            sessionID: request.editSessionID,
            callerPID: caller.pid,
            callerStartTime: caller.startTime
        )
        // Drop the agent-side record only for the session's own owner, exactly as
        // the store does. Another launcher naming this session must not be able to
        // strand it: with no expiry left to clean up after, an authorization
        // removed here while the store kept its session would hold a slot until
        // csecd restarted, because the liveness sweep walks these records.
        if let authorization = nativeEditAuthorizations[request.editSessionID],
           authorization.callerPID == caller.pid,
           authorization.callerStartTime == caller.startTime {
            nativeEditAuthorizations[request.editSessionID] = nil
        }
        return Response(requestID: request.requestID)
    }

    /// Cancel every open edit whose editor process is gone.
    ///
    /// An open edit holds a decryption context in csecd for one exact process
    /// incarnation, and the store caps how many may exist at once, so something
    /// has to reclaim a session whose `csec edit` died — killed, crashed, or
    /// force-quit — or a dead editor would hold its unlock and its slot until
    /// csecd restarted. Process liveness is the exact bound for that: it
    /// reclaims precisely the sessions nobody can ever present again, and a
    /// session whose caller is still alive is never swept, no matter how long
    /// it has been open.
    private func sweepNativeEditSessions() async {
        guard let nativeStore else { return }
        for (sessionID, authorization) in nativeEditAuthorizations
        where !authorization.isLive(using: processInspection) {
            await nativeStore.cancelEdit(
                sessionID: sessionID,
                callerPID: authorization.callerPID,
                callerStartTime: authorization.callerStartTime
            )
            nativeEditAuthorizations[sessionID] = nil
        }
    }

    /// Advertise the URI schemes the agent can resolve. A capability query — no
    /// consent, no grant, no secret material — so a client can detect which
    /// environment values are secret references.
    public func schemes() async -> Response {
        Response(
            schemes: await resolver.registeredSchemes(),
            providerStatus: await resolver.providerStatuses()
        )
    }

    public func capabilities() -> Response {
        let features = WireCapability.allCases.filter {
            switch $0 {
            case .nativeEncryptedStore, .nativeEditorPolicy:
                return nativeStore != nil
            case .unattendedAutomation:
                return automationService != nil
            case .delegatedApprovals:
                // Only a csecd with a delegation service answers the verbs.
                return delegation != nil
            default:
                return true
            }
        }
        return Response(capabilities: ProtocolCapabilities(features: features))
    }

    public func configureSSH(
        request: SSHKeyCatalogRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              isVerifiedLauncher(caller),
              let sshSigningService else {
            return .failed(
                .sshAgentUnavailable,
                message: "the SSH signing service is unavailable",
                requestID: request.requestID
            )
        }
        do {
            switch request.action {
            case .list:
                guard request.registrations.isEmpty, request.fingerprint == nil else {
                    throw SSHProtectionError.malformedMessage
                }
                return Response(
                    requestID: request.requestID,
                    sshKeys: try await sshSigningService.listedSSHKeys()
                )
            case .register:
                guard request.fingerprint == nil else {
                    throw SSHProtectionError.malformedMessage
                }
                return Response(
                    requestID: request.requestID,
                    sshKeys: try await sshSigningService.register(
                        request.registrations,
                        caller: caller
                    )
                )
            case .remove:
                guard request.registrations.isEmpty,
                      let fingerprint = request.fingerprint else {
                    throw SSHProtectionError.malformedMessage
                }
                guard try await sshSigningService.remove(
                    fingerprint: fingerprint,
                    caller: caller
                ) else { throw SSHProtectionError.keyNotRegistered }
                return Response(
                    requestID: request.requestID,
                    sshKeys: try await sshSigningService.listedSSHKeys()
                )
            }
        } catch {
            return sshFailure(error, requestID: request.requestID)
        }
    }

    // MARK: - GitHub token proxy

    /// The plan context every GitHub proxy review shows.
    public static let githubProxyContext = "GitHub requests through csecd's GitHub socket"
    /// The plan context of a GitHub request that can give lasting access,
    /// which its own review covers alone (`GitHubLastingAccess`).
    public static let githubLastingAccessContext = "one GitHub request through csecd's GitHub socket that can give lasting access"

    /// The headline of a GitHub proxy review. The footnote says the token
    /// stays in csec (`DeliveryReviewCopy.daemonUseFootnote`).
    public static func githubProxyReason(firstRequest: String) -> String {
        "Use your GitHub token for this program's GitHub requests (first: \(firstRequest))"
    }

    /// `csec github status|register|remove`. Registering shows one value-free
    /// review on this Mac, resolves the reference with its touch to check the
    /// value can be a token, and only then records the reference. Nothing is
    /// sent anywhere.
    public func configureGitHub(request: GitHubProxyRequest, caller: CallerInfo) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              isVerifiedLauncher(caller),
              let githubProxy else {
            return .failed(
                .githubProxyUnavailable,
                message: "the GitHub token proxy is unavailable",
                requestID: request.requestID
            )
        }
        switch request.action {
        case .status:
            guard request.reference == nil else { break }
            return Response(requestID: request.requestID, github: await githubProxy.status)
        case .remove:
            guard request.reference == nil else { break }
            let removed: Bool
            do {
                removed = try await githubProxy.remove()
            } catch let error as GitHubProxyError {
                return .failed(.githubProxyUnavailable, message: error.message, requestID: request.requestID)
            } catch {
                return .failed(.internalError, message: "the registration could not be removed", requestID: request.requestID)
            }
            if removed {
                await decisionLog?.record(DecisionLogRecord(
                    kind: .revoke, detail: "GitHub token proxy registration removed"
                ))
            }
            return Response(requestID: request.requestID, github: await githubProxy.status)
        case .register:
            guard let raw = request.reference else { break }
            return await registerGitHubToken(raw, githubProxy: githubProxy, request: request, caller: caller)
        }
        return .failed(.invalidRequest, message: "the GitHub proxy request is malformed", requestID: request.requestID)
    }

    private func registerGitHubToken(
        _ raw: String,
        githubProxy: GitHubProxyService,
        request: GitHubProxyRequest,
        caller: CallerInfo
    ) async -> Response {
        guard let reference = try? SecretRef(raw) else {
            return .failed(.invalidRequest, message: GitHubProxyError.invalidReference.message, requestID: request.requestID)
        }
        guard let executablePath = ProcessAncestry.executablePath(of: caller.pid) else {
            return .failed(.unverifiedPeer, message: "the requesting process is unavailable", requestID: request.requestID)
        }
        let plan = DeliveryPlan(
            mechanism: .daemonProxy,
            executable: PlannedExecutable(
                canonicalPath: executablePath,
                signingIdentifier: ProductCodeIdentity.launcherIdentifier,
                teamIdentifier: ProductCodeIdentity.teamIdentifier,
                assurance: .verifiedProduct
            ),
            root: .caller,
            descendantScope: .exactProcess,
            destination: .credentialConsumer,
            operationContext: "register this GitHub token for use only inside csecd"
        )
        var reviewedCaller = caller
        reviewedCaller.terminal = await terminalInspection.context(forCallerPID: caller.pid)
        // Registration is setup at this Mac, like an import: never mirrored.
        let review = AccessPolicyReview(
            caller: reviewedCaller,
            reason: plan.operationContext,
            plan: plan,
            credentials: [await resolver.reviewCredential(for: [reference])],
            macOnly: true
        )
        let reviewOutcome = await policyReview.reviewAccess(review)
        guard case let .approved(approval) = reviewOutcome else {
            var message = AccessPolicyDenialReason.deniedPrefix
            if case let .denied(reason) = reviewOutcome {
                let ended = DecisionLogRecord.outcome(for: reason)
                await decisionLog?.record(panelRecord(
                    kind: DecisionLogRecord.kind(for: reason), review: review, rootPID: caller.pid,
                    releaseShapeDigest: nil, outcome: ended.outcome, decider: ended.decider, ttdMs: ended.ttdMs,
                    scope: nil, duration: nil
                ))
                message = reason.deniedMessage()
            }
            return .failed(.consentDenied, message: message, requestID: request.requestID)
        }
        let outcome = await authenticateReviewedAccess(
            approval: approval,
            caller: caller,
            newReferences: [reference],
            reason: plan.operationContext,
            ttl: nil,
            policySummary: releasePolicySummary(plan: plan)
        )
        guard case let .approved(unlock) = outcome else {
            await decisionLog?.record(panelRecord(
                review: review, rootPID: caller.pid, releaseShapeDigest: nil,
                outcome: .authenticationFailed, decider: nil, scope: nil, duration: nil
            ))
            return .failed(.consentDenied, message: "consent denied", requestID: request.requestID)
        }
        defer { if unlock?.isLocal == false { unlock?.invalidate() } }
        let approved = DecisionLogRecord.outcome(for: approval)
        func record(_ detail: String? = nil) async {
            await decisionLog?.record(panelRecord(
                review: review, rootPID: caller.pid, releaseShapeDigest: nil,
                outcome: approved.outcome, decider: approved.decider, ttdMs: approved.ttdMs,
                scope: nil, duration: nil, detail: detail
            ))
        }
        let value: Data
        do {
            value = try await resolver.resolve(reference, unlock: unlock)
        } catch {
            await record("the reference could not be resolved; nothing was registered")
            return .failed(
                .resolutionFailed,
                message: "the provider could not resolve \(reference.safeInlineURI)",
                requestID: request.requestID
            )
        }
        guard GitHubProxyToken.isWellFormed(GitHubProxyToken.normalized(value)) else {
            await record("the value is not a GitHub token; nothing was registered")
            return .failed(.invalidRequest, message: GitHubProxyError.malformedToken.message, requestID: request.requestID)
        }
        do {
            try await githubProxy.register(reference)
        } catch let error as GitHubProxyError {
            await record("the registration could not be saved")
            return .failed(.githubProxyUnavailable, message: error.message, requestID: request.requestID)
        } catch {
            return .failed(.internalError, message: "the registration could not be saved", requestID: request.requestID)
        }
        await record()
        return Response(requestID: request.requestID, github: await githubProxy.status)
    }

    /// Puts back the automation run leases the previous csecd persisted, and
    /// registers what each live one can release with the output redactor, so
    /// a launcher that reopens its scanner after the restart still has every
    /// value its command may hold masked. Called once, before serving.
    public func restoreAutomationRuns() async -> AutomationRunRestoration? {
        guard let automationService else { return nil }
        let restored = await automationService.restoreRuns()
        for release in restored.releases {
            activeSecrets.register(
                valuesByReference: release.valuesByReference,
                expiresAt: release.expiresAt
            )
        }
        return restored
    }

    public func configureAutomation(
        request: AutomationRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID)?.uuidString.lowercased()
                == request.requestID else {
            return .failed(
                .invalidRequest,
                message: "the automation request is invalid",
                requestID: request.requestID
            )
        }
        guard allowUnverifiedAutomationCallersForTesting || isVerifiedLauncher(caller) else {
            return .failed(
                .unverifiedPeer,
                message: "unattended automation requires the verified csec launcher",
                requestID: request.requestID
            )
        }
        guard let automationService else {
            return .failed(
                .automationUnavailable,
                message: "unattended automation is unavailable",
                requestID: request.requestID
            )
        }

        do {
            switch request.action {
            case .enroll:
                guard let enrollment = request.enrollment,
                      request.name == nil,
                      request.runID == nil else {
                    throw AutomationServiceError.invalidRequest
                }
                let job = try await automationService.enroll(enrollment, caller: caller)
                return Response(requestID: request.requestID, automationJobs: [job])
            case .list:
                guard request.enrollment == nil,
                      request.name == nil,
                      request.runID == nil else {
                    throw AutomationServiceError.invalidRequest
                }
                return Response(
                    requestID: request.requestID,
                    automationJobs: try await automationService.list()
                )
            case .beginRun:
                guard request.enrollment == nil,
                      let name = request.name,
                      request.runID == nil else {
                    throw AutomationServiceError.invalidRequest
                }
                switch try await automationService.beginRun(name: name, caller: caller) {
                case let .started(run):
                    return Response(requestID: request.requestID, automationRun: run)
                case let .skipped(nextEligibleAt):
                    return Response(
                        requestID: request.requestID,
                        automationNextEligibleAt: nextEligibleAt
                    )
                }
            case .finishRun:
                guard request.enrollment == nil,
                      request.name == nil,
                      let runID = request.runID,
                      await automationService.finishRun(runID: runID, caller: caller) else {
                    throw AutomationServiceError.invalidRequest
                }
                return Response(requestID: request.requestID)
            case .resumeRun:
                guard request.enrollment == nil,
                      request.name == nil,
                      let runID = request.runID,
                      let release = await automationService.resumeRun(
                        runID: runID, caller: caller
                      ) else {
                    throw AutomationServiceError.invalidRequest
                }
                activeSecrets.register(
                    valuesByReference: release.valuesByReference,
                    expiresAt: release.expiresAt
                )
                return Response(requestID: request.requestID)
            case .revoke:
                guard request.enrollment == nil,
                      let name = request.name,
                      request.runID == nil else {
                    throw AutomationServiceError.invalidRequest
                }
                let job = try await automationService.revoke(name: name, caller: caller)
                return Response(requestID: request.requestID, automationJobs: [job])
            }
        } catch let error as AutomationServiceError {
            return automationFailure(error, requestID: request.requestID)
        } catch {
            return automationFailure(.unavailable, requestID: request.requestID)
        }
    }

    private func automationFailure(
        _ error: AutomationServiceError,
        requestID: String?
    ) -> Response {
        let code: WireErrorCode
        switch error {
        case .invalidRequest, .notFound, .expiringValues, .oneTimeCodes:
            code = .invalidRequest
        case .consentDenied:
            code = .consentDenied
        case .resolutionFailed:
            code = .resolutionFailed
        case .referenceNotFound:
            code = .referenceNotFound
        case .alreadyRunning:
            code = .automationAlreadyRunning
        case .unavailable, .materializationUnavailable:
            code = .automationUnavailable
        case .executableChanged:
            code = .policyDenied
        case .runExpired:
            code = .automationRunExpired
        case .runInvalidated:
            code = .automationRunInvalidated
        }
        return .failed(
            code,
            message: error.localizedDescription,
            requestID: requestID
        )
    }

    private func sshFailure(_ error: Error, requestID: String) -> Response {
        guard let error = error as? SSHProtectionError else {
            return .failed(
                .internalError,
                message: "the SSH signing operation failed",
                requestID: requestID
            )
        }
        switch error {
        case .authorizationDenied:
            return .failed(.consentDenied, message: error.localizedDescription, requestID: requestID)
        case .providerResolutionFailed:
            return .failed(.resolutionFailed, message: error.localizedDescription, requestID: requestID)
        case .referenceNotFound:
            return .failed(.referenceNotFound, message: error.localizedDescription, requestID: requestID)
        case .catalogUnavailable:
            return .failed(.sshAgentUnavailable, message: error.localizedDescription, requestID: requestID)
        default:
            return .failed(.invalidSSHKey, message: error.localizedDescription, requestID: requestID)
        }
    }

    /// Batched host remediation: run the audit, present the fixable set as a
    /// single deselectable checklist under one Touch ID, then apply the selected
    /// changes (`.auto` in-process, `.autoPrivileged` via the agent-role root
    /// helper). Implemented by `HostRemediationCoordinator` + the trusted review.
    public func runHostRemediation(
        request: HostRemediationRequest,
        caller: CallerInfo
    ) async -> Response {
        guard isVerifiedLauncher(caller) else {
            return .failed(
                .consentDenied,
                message: "host remediation requires the verified csec launcher",
                requestID: request.requestID
            )
        }
        var shown = caller
        shown.terminal = await terminalInspection.context(forCallerPID: caller.pid)
        let summary = await HostRemediationCoordinator.run(request: request, review: policyReview, caller: shown)
        return Response(requestID: request.requestID, hostRemediation: summary)
    }

    /// Persist the user's value-free triage decisions (exemptions/TODOs/cleared)
    /// into the accepted baseline. Verified-launcher gated like remediation; the
    /// store is csecd-owned so there is a single writer. Returns a plain success.
    public func recordHostTriage(
        request: HostTriageRequest,
        caller: CallerInfo
    ) async -> Response {
        guard isVerifiedLauncher(caller) else {
            return .failed(
                .consentDenied,
                message: "host triage requires the verified csec launcher",
                requestID: request.requestID
            )
        }
        await HostAuditService.recordTriage(
            request, recordedAtHint: ISO8601DateFormatter().string(from: Date()))
        return Response(requestID: request.requestID)
    }

    /// Drop any cached resolution for `request.references` so the next resolve
    /// re-reads the rotated value from its provider rather than serving a stale
    /// cache hit. Verified-launcher gated like the other mutating verbs; since
    /// eviction discloses no value it raises no Touch ID. Called by the launcher
    /// after `csec edit` / `csec protect --env` durably writes a new value —
    /// notably for op://, whose rotation happens outside csecd entirely. Returns
    /// a plain success; invalidating an uncached reference is a harmless no-op.
    public func invalidateCachedReferences(
        request: InvalidateCachedReferencesRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              isVerifiedLauncher(caller) else {
            return .failed(
                .invalidRequest,
                message: "cache invalidation requires the verified csec launcher",
                requestID: request.requestID
            )
        }
        await resolver.invalidate(references: request.references)
        return Response(requestID: request.requestID)
    }

    /// Register the authenticated launcher's current process incarnation. A
    /// descendant can later name the opaque ID, but access succeeds only when
    /// a fresh lineage walk reaches this exact PID/start-time pair.
    public func beginSession(
        request: BeginSessionRequest,
        caller: CallerInfo
    ) -> Response {
        guard UUID(uuidString: request.requestID) != nil,
              caller.pid > 1,
              caller.startTime > 0,
              isVerifiedLauncher(caller),
              ProcessAncestry.startTime(of: caller.pid) == caller.startTime else {
            return .failed(
                .unverifiedPeer,
                message: "a live verified launcher is required to register a session",
                requestID: request.requestID
            )
        }

        pruneRegisteredSessions()
        registeredSessions = registeredSessions.filter {
            $0.value.rootPID != caller.pid || $0.value.rootStartTime != caller.startTime
        }
        guard registeredSessions.count < Self.maximumRegisteredSessions else {
            return .failed(
                .policyDenied,
                message: "too many registered sessions are active",
                requestID: request.requestID
            )
        }

        let sessionID = UUID().uuidString.lowercased()
        registeredSessions[sessionID] = RegisteredSession(
            rootPID: caller.pid,
            rootStartTime: caller.startTime,
            auditSessionID: caller.peerIdentity?.audit.auditSessionID
        )
        return Response(requestID: request.requestID, registeredSessionID: sessionID)
    }

    /// Inspect or drop live grants, and (with delegated approvals) project
    /// pairings, trusted Claude Code builds and acknowledged hooks, each by its
    /// typed id.
    ///
    /// Neither action releases a value: listing returns the same value-free
    /// metadata the review window already showed, and revocation only removes
    /// access, so it fails safe and needs no Touch ID of its own. Both still
    /// require an authenticated signed launcher. An id prefix matches only
    /// entries of its own kind, and one that matches more than one removes
    /// nothing and lists the matches.
    public func handleGrants(
        request: GrantsRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil, isVerifiedLauncher(caller) else {
            return .failed(
                .unverifiedPeer,
                message: "a verified launcher is required to inspect or revoke grants",
                requestID: request.requestID
            )
        }
        let now = Date()
        // The same housekeeping moment the grant table sweeps on. An open edit is
        // not a grant and is not listed here, but it is held by a process in the
        // same way, so a caller that has gone away releases both at once.
        await sweepNativeEditSessions()
        switch request.action {
        case .list:
            var summaries = await grants.summaries(now: now)
            if let sshSigningService {
                summaries += await sshSigningService.grantSummaries()
            }
            return Response(
                requestID: request.requestID, grants: summaries, delegationGrants: await delegationListing()
            )
        case .revoke:
            if request.all {
                await grants.sweep(now: now)
                let secretSummaries = await grants.summaries(now: now)
                let sshSummaries = await sshSigningService?.grantSummaries() ?? []
                let count = await grants.revokeAll()
                    + (await sshSigningService?.revokeAllGrants() ?? 0)
                for index in approvalMemories.indices { approvalMemories[index].revoked = true }
                // Written even when nothing was live, so the persisted item
                // holds nothing a restart could bring back, and discarded
                // when this csecd could not read it.
                let failure = await grantPersistence?.persistNow(discardingUnreadable: true)
                // Every pairing goes too; trusted builds and acknowledged
                // hooks are delegation settings and stay.
                let pairings = await delegation?.removeAllPairings()
                let removed = Array(
                    (secretSummaries.map(Self.revocableEntry) + sshSummaries.map(Self.revocableEntry)
                        + (pairings?.removed ?? [])).prefix(GrantRevocation.maximumEntries)
                )
                await recordRevocation(count: count, detail: "csec revoke --all")
                if let failure {
                    return revocationNotPersisted(count: count, failure, requestID: request.requestID)
                }
                if let pairingFailure = pairings?.failure {
                    return .failed(
                        .internalError, message: "revoked \(removed.count) for this csecd run, but \(pairingFailure)",
                        requestID: request.requestID
                    )
                }
                return Response(
                    requestID: request.requestID,
                    revokedGrantCount: removed.count,
                    grantRevocation: GrantRevocation(removed: removed)
                )
            }
            guard let grantID = request.grantID,
                  let selector = GrantIDSelector(grantID) else {
                return .failed(
                    .invalidRequest,
                    message: "a grant id (or --all) is required",
                    requestID: request.requestID
                )
            }
            await grants.sweep(now: now)
            var removed: [RevocableEntry] = []
            var unpairing: (references: Set<String>, ssh: [PairedSSHUse], root: ProcessIncarnation)?
            let count: Int
            switch selector.kind {
            case .secret:
                let matches = await grants.summaries(now: now).filter { selector.matches(id: $0.id) }
                if matches.count > 1 {
                    return ambiguousRevocation(grantID, matches.map(Self.revocableEntry), requestID: request.requestID)
                }
                guard let match = matches.first else {
                    count = 0
                    break
                }
                // The grant's own root, read before it is dropped, is what an
                // unpairing must match (never a later process with its pid).
                let root = await grants.root(ofGrantID: match.id)
                count = await grants.revoke(idPrefix: match.id.lowercased())
                removed = [Self.revocableEntry(match)]
                if match.scopeKind == .codingAgent, let root {
                    unpairing = (Set(match.references), [], root)
                }
            case .ssh:
                let matches = (await sshSigningService?.grantSummaries() ?? []).filter { selector.matches(id: $0.id) }
                if matches.count > 1 {
                    return ambiguousRevocation(grantID, matches.map(Self.revocableEntry), requestID: request.requestID)
                }
                guard let match = matches.first, let sshSigningService else {
                    count = 0
                    break
                }
                let root = await sshSigningService.grantRoot(id: match.id)
                count = await sshSigningService.revokeGrants(idPrefix: match.id.lowercased())
                removed = [Self.revocableEntry(match)]
                if match.scopeKind == .codingAgent, let ssh = match.ssh, let root {
                    unpairing = ([], [PairedSSHUse(
                        keyFingerprint: ssh.keyFingerprint,
                        hostKeyFingerprint: ssh.hostKeyFingerprint,
                        remoteUser: ssh.remoteUser
                    )], root)
                }
            case .pairing, .build, .hook:
                // The same path `configure_delegation untrust_build` and
                // `forget_hook` take.
                guard let delegation else {
                    count = 0
                    break
                }
                switch await delegation.remove(selector) {
                case let .ambiguous(matches):
                    return ambiguousRevocation(grantID, matches, requestID: request.requestID)
                case let .removed(entries):
                    removed = entries
                    count = entries.count
                case let .notPersisted(entries, failure):
                    await recordRevocation(count: entries.count, detail: "csec revoke \(grantID)")
                    return .failed(
                        .internalError,
                        message: "revoked \(entries.count) for this csecd run, but \(failure)",
                        requestID: request.requestID
                    )
                }
            }
            // These memories are of secret approvals: an `ssh-` id names an SSH
            // grant, whose service marks its own. Both sides are lowercase
            // (grant ids are minted as `uuidString.lowercased()`, and the
            // selector's prefix is lowercased when parsed).
            if count > 0, selector.kind == .secret {
                for index in approvalMemories.indices
                    where approvalMemories[index].grantIDs.contains(where: { $0.hasPrefix(selector.prefix) }) {
                    approvalMemories[index].revoked = true
                }
            }
            // A revocation is persisted before the reply: one that was not
            // would come back at the next csecd start.
            let failure = count > 0 && selector.kind.grantKind != nil ? await grantPersistence?.persistNow() : nil
            // Revoking a grant rooted at a Claude Code process also unpairs
            // what it covered from that process's project. An unpairing that
            // could not be written is reported like a revocation that could
            // not be: it would come back at the next csecd start.
            var unpairingFailure: String?
            if count > 0, let unpairing, let delegation,
               CodingAgentIdentity.client(
                name: processInspection.name(of: unpairing.root.pid),
                executablePath: processInspection.executablePath(of: unpairing.root.pid)
               ) == .claude {
                let unpaired = await delegation.unpair(
                    references: unpairing.references, ssh: unpairing.ssh, root: unpairing.root
                )
                removed += unpaired.removed
                unpairingFailure = unpaired.failure
            }
            await recordRevocation(count: count, detail: "csec revoke \(grantID)")
            if let failure {
                return revocationNotPersisted(count: count, failure, requestID: request.requestID)
            }
            if let unpairingFailure {
                return .failed(
                    .internalError,
                    message: "revoked \(removed.count) for this csecd run, but \(unpairingFailure)",
                    requestID: request.requestID
                )
            }
            return Response(
                requestID: request.requestID,
                revokedGrantCount: removed.count,
                grantRevocation: GrantRevocation(removed: removed)
            )
        }
    }

    /// `delegationGrants` for `csec grants`: only while delegated approvals
    /// are on, so an older client's strict decoding of `grants` never sees
    /// these kinds.
    private func delegationListing() async -> DelegationGrantsListing? {
        guard let delegation, let entries = await delegation.grantEntries() else { return nil }
        var pairings: [ProjectPairingSummary] = []
        for pairing in entries.pairings.prefix(DelegationGrantsListing.maximumPairings) {
            let ssh: [SSHPairingSummary]
            if let sshSigningService {
                ssh = await sshSigningService.pairingSummaries(for: pairing.ssh)
            } else {
                ssh = pairing.ssh.map {
                    SSHPairingSummary(
                        keyReference: nil, keyFingerprint: $0.keyFingerprint, keyLabel: nil,
                        hostKeyFingerprint: $0.hostKeyFingerprint, hostNames: [], remoteUser: $0.remoteUser
                    )
                }
            }
            pairings.append(ProjectPairingSummary(
                id: pairing.id, projectPath: pairing.project.path, references: pairing.references,
                usedReferences: pairing.usedReferences, ssh: ssh,
                launchers: pairing.launchers.map { launcher in
                    LauncherPairingSummary(
                        path: launcher.path, sources: launcher.sources.filter { $0.digest != nil }.map(\.path)
                    )
                },
                sudo: pairing.sudo
            ))
        }
        let listing = DelegationGrantsListing(
            pairings: pairings,
            trustedBuilds: entries.builds.map(\.summary),
            acknowledgedHooks: entries.hooks.map(\.summary.listed)
        )
        return listing.isWellFormed ? listing : nil
    }

    private func ambiguousRevocation(
        _ grantID: String, _ matches: [RevocableEntry], requestID: String
    ) -> Response {
        let shown = Array(matches.prefix(GrantRevocation.maximumEntries))
        return Response(
            requestID: requestID,
            grantRevocation: GrantRevocation(ambiguousMatches: shown),
            failure: ProtocolFailure(
                .invalidRequest,
                message: "\(ReviewDisplay.sanitized(grantID)) matches more than one entry; nothing was revoked: "
                    + shown.map(\.displayID).joined(separator: ", ")
            )
        )
    }

    private static func revocableEntry(_ summary: GrantSummary) -> RevocableEntry {
        let label: String
        if let ssh = summary.ssh {
            label = "SSH as \(ssh.remoteUser) to \(ssh.hostNames.first ?? ssh.hostKeyFingerprint) for \(summary.rootProcessLabel)"
        } else {
            label = "\(summary.references.count) reference\(summary.references.count == 1 ? "" : "s") for \(summary.rootProcessLabel)"
        }
        return RevocableEntry(
            kind: GrantIDKind(summary.grantKind),
            id: summary.id.lowercased(),
            label: ReviewDisplay.bounded(ReviewDisplay.sanitized(label), maxBytes: RevocableEntry.maximumLabelBytes)
        )
    }

    /// `configure_delegation`: the verified launcher only. `enable`,
    /// `trust_build` and `acknowledge_hooks` each raise one bare Touch ID sheet
    /// (in the delegation service) naming the terminal; the others need none.
    public func configureDelegation(
        request: DelegationConfigurationRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil, isVerifiedLauncher(caller) else {
            return .failed(
                .unverifiedPeer,
                message: "a verified launcher is required to configure delegated approvals",
                requestID: request.requestID
            )
        }
        guard request.isWellFormed else {
            return .failed(
                .invalidRequest, message: "the delegation request is outside supported bounds", requestID: request.requestID
            )
        }
        guard let delegation else {
            if request.action == .status {
                return Response(
                    requestID: request.requestID,
                    delegationStatus: DelegationStatus(state: .unavailable, policyVersion: DelegationPolicy.currentVersion)
                )
            }
            return .failed(
                .policyDenied, message: "delegated approvals are not available in this csecd", requestID: request.requestID
            )
        }
        let terminal = request.action.addsAuthority
            ? await terminalInspection.context(forCallerPID: caller.pid) : nil
        return await delegation.configure(request, caller: caller, terminal: terminal)
    }

    private func revocationNotPersisted(
        count: Int,
        _ failure: GrantPersistenceFailure,
        requestID: String
    ) -> Response {
        .failed(
            .internalError,
            message: "revoked \(count) grant\(count == 1 ? "" : "s") for this csecd run, but \(failure)",
            requestID: requestID
        )
    }

    private func recordRevocation(count: Int, detail: String) async {
        guard count > 0 else { return }
        await decisionLog?.record(DecisionLogRecord(
            kind: .revoke, detail: "\(detail): \(count) grant\(count == 1 ? "" : "s") dropped"
        ))
    }

    /// `csec log`: read, verify or report on the decision log. Like the grant
    /// listing it needs the verified launcher but no Touch ID; it releases no
    /// value.
    public func handleDecisionLog(
        request: DecisionLogRequest,
        caller: CallerInfo
    ) async -> Response {
        guard UUID(uuidString: request.requestID) != nil, isVerifiedLauncher(caller) else {
            return .failed(
                .unverifiedPeer,
                message: "a verified launcher is required to read the decision log",
                requestID: request.requestID
            )
        }
        guard let decisionLog else {
            if request.action == .status {
                return Response(
                    requestID: request.requestID,
                    decisionLogStatus: DecisionLogStatus(
                        state: .off, detail: "csecd has no protected stores to anchor the log in"
                    )
                )
            }
            return .failed(
                .decisionLogUnavailable,
                message: "the decision log is off: csecd has no protected stores to anchor it in",
                requestID: request.requestID
            )
        }
        switch request.action {
        case .status:
            return Response(requestID: request.requestID, decisionLogStatus: await decisionLog.status())
        case .verify:
            return Response(
                requestID: request.requestID,
                decisionLogVerification: await decisionLog.verify()
            )
        case .read:
            guard let query = request.query, query.isWellFormed else {
                return .failed(
                    .invalidRequest,
                    message: "the decision log query is outside supported bounds",
                    requestID: request.requestID
                )
            }
            guard case .active = await decisionLog.currentState else {
                let status = await decisionLog.status()
                return .failed(
                    .decisionLogUnavailable,
                    message: "the decision log is unavailable"
                        + (status.detail.map { ": \(ReviewDisplay.sanitized($0))" } ?? ""),
                    requestID: request.requestID
                )
            }
            return Response(requestID: request.requestID, decisionLogPage: await decisionLog.read(query))
        }
    }

    private func isVerifiedLauncher(_ caller: CallerInfo) -> Bool {
        caller.requestAnchor?.abandonment(using: processInspection) == nil
            && (allowUnverifiedPlansForTesting || caller.peerIdentity?.code.role == .launcher)
    }

    private func nativeStoreFailure(_ error: Error, requestID: String) -> Response {
        guard let error = error as? NativeStoreError else {
            return .failed(
                .internalError,
                message: "the native-store operation failed",
                requestID: requestID
            )
        }
        switch error {
        case .invalidStoreName, .invalidReference:
            return .failed(
                .invalidRequest,
                message: "the native-store request is invalid",
                requestID: requestID
            )
        case .invalidDocument, .documentTooLarge, .tooManySecrets:
            return .failed(
                .invalidStoreDocument,
                message: "the store must be a JSON object with unique valid keys and string values",
                requestID: requestID
            )
        case .editSessionNotFound:
            // Reachable only as a malformed or forged session id: the agent has
            // already matched this session to this exact caller, and an edit is
            // never retired underneath a caller that is still running.
            return .failed(
                .invalidRequest,
                message: "the native-store edit session is unknown",
                requestID: requestID
            )
        case .editConflict:
            return .failed(
                .editConflict,
                message: "the native store changed after this edit began",
                requestID: requestID
            )
        case .originConflict:
            return .failed(
                .storeOriginConflict,
                message: "the store name is claimed by a different project directory",
                requestID: requestID
            )
        case .tooManyEditSessions:
            return .failed(
                .policyDenied,
                message: "too many native-store edit sessions are active",
                requestID: requestID
            )
        case .crossTierKeyConflict:
            return .failed(
                .invalidStoreDocument,
                message: "a key cannot exist in both the editable-document and file tiers of one store",
                requestID: requestID
            )
        case .authenticationRequired, .keyUnavailable, .storeNotFound,
             .secretNotFound, .integrityFailure, .filesystemFailure,
             .randomGenerationFailed, .blobTierUnavailable:
            return .failed(
                .nativeStoreUnavailable,
                message: "the native encrypted store is unavailable or failed integrity validation",
                requestID: requestID
            )
        }
    }

    private func pruneRedactionSessions() {
        // A quiet background command still needs its original matcher, including
        // withheld prefixes and patterns whose delivery grants have since expired.
        // Retain it until explicit close or owner exit/PID reuse; wall-clock time
        // and output frequency must never determine whether scanning is available.
        // This does not renew grants or resolve any additional secret values.
        redactionSessions = redactionSessions.filter {
            $0.value.caller.isLive(using: processInspection)
        }
    }

    private func verifyRoot(
        _ root: DeliveryRoot,
        caller: CallerInfo
    ) -> (pid: pid_t, startTime: UInt64)? {
        switch root {
        case .caller:
            guard caller.startTime > 0 else { return nil }
            return (caller.pid, caller.startTime)
        case let .directParent(pid, startTime):
            guard pid > 1,
                  startTime > 0,
                  ProcessAncestry.parent(of: caller.pid) == pid,
                  ProcessAncestry.startTime(of: pid) == startTime else { return nil }
            return (pid, startTime)
        case let .registeredSession(id):
            guard let canonicalID = UUID(uuidString: id)?.uuidString.lowercased(),
                  canonicalID == id.lowercased(),
                  let session = registeredSessions[canonicalID],
                  session.auditSessionID == nil
                    || caller.peerIdentity?.audit.auditSessionID == session.auditSessionID,
                  ProcessInspection.live.descends(
                    caller.pid,
                    from: session.rootPID,
                    rootStartTime: session.rootStartTime
                  ) else { return nil }
            return (session.rootPID, session.rootStartTime)
        }
    }

    private func verifyDeliveryRoot(
        _ plan: DeliveryPlan,
        caller: CallerInfo
    ) -> (pid: pid_t, startTime: UInt64)? {
        guard caller.requestAnchor?.abandonment(using: processInspection) == nil else { return nil }
        guard let root = verifyRoot(plan.root, caller: caller) else { return nil }
        guard case let .directParent(pid, _) = plan.root else { return root }

        let requester = plan.requestingExecutable ?? plan.executable
        let claimedPath = URL(fileURLWithPath: requester.canonicalPath)
            .standardizedFileURL.resolvingSymlinksInPath().path
        guard ProcessAncestry.executablePath(of: pid) == claimedPath else { return nil }

        // A separate requester identity is a signed-launcher assertion, but
        // csecd independently recomputes it and then rechecks the live image.
        if plan.requestingExecutable != nil {
            guard let inspected = try? ExecutableInspection.plannedExecutable(
                command: claimedPath
            ), inspected == requester,
            ProcessAncestry.startTime(of: pid) == root.startTime,
            ProcessAncestry.executablePath(of: pid) == claimedPath else { return nil }
        }
        return root
    }

    private func pruneRegisteredSessions() {
        registeredSessions = registeredSessions.filter {
            ProcessAncestry.startTime(of: $0.value.rootPID) == $0.value.rootStartTime
        }
    }

    private static func hasValidMetadata(_ plan: DeliveryPlan) -> Bool {
        let executable = plan.executable
        return hasValidExecutableMetadata(executable)
            && hasValidRequesterMetadata(plan)
            && hasValidRecipientMetadata(plan)
            && !plan.operationContext.isEmpty
            && plan.operationContext.utf8.count <= 512
            && !plan.operationContext.utf8.contains(0)
            && hasValidRootScope(plan)
            && (plan.commandDigest.map(isSHA256Digest) ?? true)
            && hasValidOutputGuard(plan)
    }

    private static func hasValidRequesterMetadata(_ plan: DeliveryPlan) -> Bool {
        switch (plan.root, plan.requestingExecutable) {
        case (.directParent, .none):
            // Existing direct-parent consumers use `executable` for both roles.
            return true
        case let (.directParent, .some(requester)):
            return hasValidExecutableMetadata(requester)
        case (_, .none):
            return true
        case (_, .some):
            return false
        }
    }

    private static func hasValidExecutableMetadata(_ executable: PlannedExecutable) -> Bool {
        executable.canonicalPath.hasPrefix("/")
            && executable.canonicalPath.utf8.count <= 4_096
            && !executable.canonicalPath.utf8.contains(0)
            && (executable.signingIdentifier.map {
                !$0.isEmpty && $0.utf8.count <= 512 && !$0.utf8.contains(0)
            } ?? true)
            && (executable.teamIdentifier.map {
                !$0.isEmpty && $0.utf8.count <= 128 && !$0.utf8.contains(0)
            } ?? true)
            && (executable.cdHash.map {
                !$0.isEmpty && $0.utf8.count <= 128 && $0.utf8.allSatisfy(isLowerHex)
            } ?? true)
    }

    private static func hasValidRecipientMetadata(_ plan: DeliveryPlan) -> Bool {
        switch (plan.mechanism, plan.destination, plan.recipientAssurance) {
        case (.rawStandardOutput, .humanOutput, .interactiveTerminal),
             (.rawStandardOutput, .shellDelegatedPipe, .unverifiedPipeReader),
             (.namedPlaintextFile, .persistentPlaintextFile, .ordinaryPersistentFile):
            guard plan.executable.assurance == .verifiedProduct,
                  plan.executable.signingIdentifier == ProductCodeIdentity.launcherIdentifier,
                  plan.executable.teamIdentifier == ProductCodeIdentity.teamIdentifier,
                  plan.requestingExecutable != nil,
                  plan.descendantScope == .subtree,
                  case .directParent = plan.root else { return false }
            return true
        case (.rawStandardOutput, _, _):
            // Raw stdout is exposed only through the fully described csec-get
            // shapes above. In particular, omitting the requester/recipient or
            // relabelling a pipe as terminal output is malformed metadata.
            return false
        case (_, .shellDelegatedPipe, _), (_, .persistentPlaintextFile, _):
            return false
        case (_, _, .some):
            return false
        case (_, _, .none):
            return true
        }
    }

    private static func hasValidRootScope(_ plan: DeliveryPlan) -> Bool {
        switch plan.root {
        case .registeredSession:
            return plan.descendantScope == .broadSession
        case .caller, .directParent:
            return plan.descendantScope != .broadSession
        }
    }

    private static func hasValidNativeEditorMetadata(
        _ request: BeginNativeStoreEditRequest
    ) -> Bool {
        switch request.mode {
        case .builtInMemory, .onboardingImport, .sshKeyImport, .githubTokenImport:
            return request.externalEditorPath == nil
        case .externalTemporaryFile:
            guard let path = request.externalEditorPath else { return false }
            return path.hasPrefix("/")
                && path.utf8.count <= 4_096
                && !path.utf8.contains(0)
        }
    }

    private static func isSHA256Digest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy(isLowerHex)
    }

    private static func hasValidOutputGuard(_ plan: DeliveryPlan) -> Bool {
        if plan.mechanism == .unrestrictedInitialEnvironment {
            guard let outputGuard = plan.outputGuard else { return false }
            return outputGuard.matcherVersion == OutputGuardPlan.currentMatcherVersion
        }
        return plan.outputGuard?.matcherVersion == OutputGuardPlan.currentMatcherVersion
            || plan.outputGuard == nil
    }

    private static func isLowerHex(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}

extension Agent: GitHubTokenAuthorizer {
    /// Whether `caller` may have the GitHub token put on one request csecd
    /// makes for it, and the token if so. It is an ordinary access request for
    /// the token's reference, with a plan csecd builds from kernel facts: the
    /// caller's executable, and its argv for the review and the grant's
    /// command digest. So the review, grants and their scopes, the restore
    /// panel, the phone mirror and Claude Code auto mode all apply as they do
    /// to any release. The token never leaves csecd.
    public func authorizeGitHubTokenUse(
        reference: SecretRef,
        use: GitHubProxyUse,
        caller: CallerInfo
    ) async -> GitHubTokenAuthorization {
        guard caller.pid > 1, caller.startTime > 0,
              let path = caller.peerIdentity?.audit.executablePath ?? processInspection.executablePath(of: caller.pid),
              path.hasPrefix("/") else {
            return .denied("the requesting process could not be identified")
        }
        // The kernel's code facts for the connection, not a static signature
        // check: this runs for every request gh makes, and hashing its image
        // each time would cost far more than the request.
        let code = caller.peerIdentity?.code
        let signed = code?.signatureValid == true
        func fact(_ value: String?, maxBytes: Int) -> String? {
            guard signed, let value, !value.isEmpty, value.utf8.count <= maxBytes, !value.utf8.contains(0) else { return nil }
            return value
        }
        let cdHash = fact(code?.cdHash?.lowercased(), maxBytes: 128).flatMap { $0.utf8.allSatisfy(Self.isLowerHex) ? $0 : nil }
        let executable = PlannedExecutable(
            canonicalPath: path,
            signingIdentifier: fact(code?.identifier, maxBytes: 512),
            teamIdentifier: fact(code?.teamIdentifier, maxBytes: 128),
            cdHash: cdHash,
            assurance: ExecutableInspection.independentlyProtected(path: path) ? .independentlyProtected : .userWritable
        )
        // The argv as csecd reads it from the kernel, never as anyone says.
        // One that would not fit an access request is left off the review
        // rather than failing the request.
        var argv = processInspection.arguments(of: caller.pid, startedAt: caller.startTime)
        if let arguments = argv,
           arguments.count > AccessRequest.maximumCommandLineArguments
            || arguments.reduce(0, { $0 + $1.utf8.count }) > AccessRequest.maximumCommandLineBytes
            || arguments.contains(where: { $0.utf8.contains(0) }) {
            argv = nil
        }
        let plan = DeliveryPlan(
            mechanism: .daemonProxy,
            executable: executable,
            root: .caller,
            descendantScope: .subtree,
            destination: .credentialConsumer,
            operationContext: use.lastingAccess == nil ? Self.githubProxyContext : Self.githubLastingAccessContext,
            commandDigest: argv.flatMap { try? ExecutableInspection.commandDigest($0) }
        )
        let target = ReviewDisplay.bounded(ReviewDisplay.sanitized("\(use.method) \(use.host)\(use.path)"), maxBytes: 300)
        let reason = use.lastingAccess?.reason ?? Self.githubProxyReason(firstRequest: target)
        guard var request = try? AccessRequest(
            references: [reference.uri], reason: reason, deliveryPlan: plan, commandLine: argv
        ) else {
            return .denied("the request could not be described")
        }
        request.githubLastingAccess = use.lastingAccess
        let response = await handle(request: request, caller: caller, daemonUse: true)
        if let value = response.values?[reference.uri] {
            let token = GitHubProxyToken.normalized(value)
            guard GitHubProxyToken.isWellFormed(token) else { return .denied(GitHubProxyError.malformedToken.message) }
            return .token(token)
        }
        let detail = response.failure?.message ?? response.error ?? "not approved"
        return .denied("GitHub access through csec was not approved (\(detail))")
    }
}
