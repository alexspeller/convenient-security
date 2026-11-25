import Foundation

public protocol SSHAgentKeyProvider: Sendable {
    func listedSSHKeys() async throws -> [SSHKeyMetadata]
    func signSSHAuthentication(
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        binding: SSHDestinationBinding,
        caller: CallerInfo
    ) async throws -> Data
}

/// Provider-neutral SSH consumer. Catalog entries retain only SecretRef URIs and
/// public metadata. Private key bytes enter this actor only after a complete,
/// destination-bound request is authorized, and leave only as an SSH signature.
public actor SSHSigningService: SSHAgentKeyProvider {
    private struct Grant: Sendable {
        let id: UUID
        let fingerprint: String
        let hostKeyFingerprint: String
        let remoteUser: String
        let rootPID: pid_t
        let rootStartTime: UInt64
        let auditSessionID: UInt32?
        let clientCDHash: String?
        /// Wall-clock cap, or nil for a signing grant that lives as long as its
        /// approved session (the default) — bounded by the root process subtree,
        /// not a clock.
        let expiresAt: Date?
        /// Display and diagnostics only; `rootPID`/`rootStartTime` stay the
        /// authority.
        let scopeKind: GrantScopeKind
        let rootProcessLabel: String?
        let mintedAt: Date
        let origin: GrantOrigin
        let mintedByBuild: String?
        /// Loaded from the persisted grants item when csecd started.
        var restored = false
        /// See `ConvenientSecurity.Grant.warm`.
        var warm = true

        var awaitingRestore: Bool { restored && !warm }

        init(
            id: UUID = UUID(),
            fingerprint: String,
            hostKeyFingerprint: String,
            remoteUser: String,
            rootPID: pid_t,
            rootStartTime: UInt64,
            auditSessionID: UInt32?,
            clientCDHash: String?,
            expiresAt: Date?,
            scopeKind: GrantScopeKind,
            rootProcessLabel: String?,
            mintedAt: Date,
            origin: GrantOrigin,
            mintedByBuild: String? = nil
        ) {
            self.id = id
            self.fingerprint = fingerprint
            self.hostKeyFingerprint = hostKeyFingerprint
            self.remoteUser = remoteUser
            self.rootPID = rootPID
            self.rootStartTime = rootStartTime
            self.auditSessionID = auditSessionID
            self.clientCDHash = clientCDHash
            self.expiresAt = expiresAt
            self.scopeKind = scopeKind
            self.rootProcessLabel = rootProcessLabel
            self.mintedAt = mintedAt
            self.origin = origin
            self.mintedByBuild = mintedByBuild
        }

        /// A grant the persisted item restored: bound to exactly the facts it
        /// was minted with, and waiting for the restore panel.
        init(restoring record: PersistedSSHGrant) {
            self.init(
                id: record.id,
                fingerprint: record.keyFingerprint,
                hostKeyFingerprint: record.hostKeyFingerprint,
                remoteUser: record.remoteUser,
                rootPID: record.rootPID,
                rootStartTime: record.rootStartTime,
                auditSessionID: record.auditSessionID,
                clientCDHash: record.clientCDHash,
                expiresAt: record.expiresAt,
                scopeKind: record.scopeKind,
                rootProcessLabel: record.rootProcessLabel,
                mintedAt: record.mintedAt,
                origin: record.origin,
                mintedByBuild: record.mintedByBuild
            )
            restored = true
            warm = false
        }

        var persisted: PersistedSSHGrant {
            PersistedSSHGrant(
                id: id,
                keyFingerprint: fingerprint,
                hostKeyFingerprint: hostKeyFingerprint,
                remoteUser: remoteUser,
                rootPID: rootPID,
                rootStartTime: rootStartTime,
                auditSessionID: auditSessionID,
                clientCDHash: clientCDHash,
                expiresAt: expiresAt,
                scopeKind: scopeKind,
                rootProcessLabel: rootProcessLabel,
                mintedAt: mintedAt,
                origin: origin,
                mintedByBuild: mintedByBuild
            )
        }

        func covers(
            key: SSHKeyMetadata,
            binding: SSHDestinationBinding,
            authentication: SSHBoundUserAuthentication,
            caller: CallerInfo,
            now: Date,
            processInspection: ProcessInspection
        ) -> Bool {
            guard (expiresAt.map { now < $0 } ?? true),
                  key.fingerprint == fingerprint,
                  binding.hostKeyFingerprint == hostKeyFingerprint,
                  authentication.remoteUser == remoteUser,
                  caller.peerIdentity?.audit.auditSessionID == auditSessionID,
                  caller.peerIdentity?.code.cdHash == clientCDHash,
                  processInspection.startTime(of: rootPID) == rootStartTime else { return false }
            return processInspection.descends(
                caller.pid, from: rootPID, rootStartTime: rootStartTime
            )
        }
    }

    private struct Root: Sendable {
        let pid: pid_t
        let startTime: UInt64
    }

    /// The live grant that covers a request, and whether it was restored.
    private struct Covering: Sendable {
        let root: Root
        let restored: Bool
        let awaitingRestore: Bool
    }

    /// What makes two signing requests the same question for a human Deny: the
    /// key, the verified server identity, and the remote user — the facts the
    /// SSH review shows and a grant is bound to.
    fileprivate struct SSHDenialShape: Hashable, Sendable {
        let fingerprint: String
        let hostKeyFingerprint: String
        let remoteUser: String
    }

    /// One `ssh` process incarnation. `ssh` holds a single agent connection for
    /// its whole life, so this is the connection a human denied.
    fileprivate struct Requester: Hashable, Sendable {
        let pid: pid_t
        let startTime: UInt64
    }

    /// This run's signing approvals, remembered so a later panel for the
    /// same key can say why it appeared. Bounded by count, never by a clock.
    private struct ApprovalMemory: Sendable {
        let fingerprint: String
        let rootPID: pid_t
        let rootStartTime: UInt64
        let expiresAt: Date?
        /// The grant the approval minted, so `csec revoke` can mark it.
        let grantID: UUID
        var revoked = false
    }

    private static let maximumGrants = 256
    private static let maximumDeniedRequesters = 256

    private let resolver: SecretResolver
    private let catalog: SSHKeyCatalog
    private let consent: any ConsentProvider
    private let policyReview: any PolicyReviewProvider
    private let terminalInspection: TerminalSessionInspector
    private let allowUnverifiedCallersForTesting: Bool
    private let processInspection: ProcessInspection
    private let knownHostsLookup: SSHKnownHostsLookup
    /// Injected so grant expiry is testable without sleeping. Production keeps
    /// the default wall clock.
    private let clock: @Sendable () -> Date
    private var grants: [Grant] = []
    /// The SSH review turn: a FIFO permit held from before a review until its
    /// grant is minted, so concurrent same-shape connections (a parallel
    /// fetch, several `ssh` at once) wait behind one panel and then re-check
    /// the grant it minted. Actor isolation alone cannot provide this — the
    /// actor re-enters while a review awaits the human. It is separate from
    /// the shared UI queue inside `policyReview`, like `Agent`'s access queue.
    private let reviewTurns: ConsentQueue
    private var humanDenials = HumanDenialLedger<SSHDenialShape>()
    /// Which refusals before a panel this run has recorded.
    private var absentReferenceRecords = AbsentReferenceRecords()
    /// `ssh` processes whose signing request a human denied. Such a process
    /// gets no further signature: after a refusal `ssh` offers the next
    /// catalog key on the same connection, which would otherwise raise a
    /// second panel for a connection the human already said no to. Bounded by
    /// process liveness, never by a clock.
    private var humanDeniedRequesters: [Requester] = []
    /// `ssh` processes whose signing request nobody answered before its
    /// deadline (`HumanWait`). Like a denied one, such a process gets no
    /// further signature: its next catalog key would otherwise start a fresh
    /// wait of the full length, and a panel nobody is there to see. Bounded by
    /// process liveness.
    private var timedOutRequesters: [Requester] = []
    /// An orphan must not get a fresh review for its next offered key.
    private var abandonedRequesters: [Requester] = []
    /// Requests waiting on a human, shared with `Agent` (`HumanWaitBoard`).
    private let humanWaitBoard: HumanWaitBoard?
    private let approvalWaitLimit: @Sendable () -> Duration
    private var approvalMemories: [ApprovalMemory] = []
    /// Where SSH panels, refusals, key changes and grant reuses are recorded.
    private let decisionLog: DecisionLog?
    /// The one owner of the persisted grants item. This service never writes
    /// it; it hands over its grants after every change, stamped with
    /// `grantGeneration`, which only grows.
    private let persistence: GrantPersistence?
    private var grantGeneration: UInt64 = 0
    /// The restart warm-up a covered request waits on when its grant was
    /// restored and its key's store is still sealed.
    private let restoration: GrantRestoration?
    /// Claude Code auto mode standing in for the panel, for a signing under a
    /// classifier-approved `csec ai` in a paired project. Nil: every signing
    /// not covered by a grant gets a panel.
    private let delegation: ClaudeDelegationService?

    public init(
        resolver: SecretResolver,
        catalog: SSHKeyCatalog,
        consent: any ConsentProvider,
        policyReview: any PolicyReviewProvider,
        allowUnverifiedCallersForTesting: Bool = false,
        processInspection: ProcessInspection = .live,
        knownHostsLookup: SSHKnownHostsLookup = .live,
        terminalInspection: TerminalSessionInspector,
        now: @escaping @Sendable () -> Date = { Date() },
        reviewTurns: ConsentQueue = ConsentQueue(),
        decisionLog: DecisionLog? = nil,
        persistence: GrantPersistence? = nil,
        restoration: GrantRestoration? = nil,
        delegation: ClaudeDelegationService? = nil,
        humanWaitBoard: HumanWaitBoard? = nil,
        approvalWaitLimit: @escaping @Sendable () -> Duration = {
            .seconds(ApprovalWaitLimit.current().minutes * 60)
        }
    ) {
        self.humanWaitBoard = humanWaitBoard
        self.approvalWaitLimit = approvalWaitLimit
        self.persistence = persistence
        self.restoration = restoration
        self.delegation = delegation
        self.decisionLog = decisionLog
        self.reviewTurns = reviewTurns
        self.terminalInspection = terminalInspection
        self.resolver = resolver
        self.catalog = catalog
        self.consent = consent
        self.policyReview = policyReview
        self.allowUnverifiedCallersForTesting = allowUnverifiedCallersForTesting
        self.processInspection = processInspection
        self.knownHostsLookup = knownHostsLookup
        self.clock = now
    }

    public func listedSSHKeys() async throws -> [SSHKeyMetadata] {
        try await catalog.list()
    }

    public func register(
        _ registrations: [SSHKeyRegistrationIntent],
        caller: CallerInfo
    ) async throws -> [SSHKeyMetadata] {
        let result: Result<[SSHKeyMetadata], Error> = await HumanWait.tracking(
            caller: caller, inspection: processInspection
        ) { caller in
            do { return .success(try await self.registerPending(registrations, caller: caller)) }
            catch { return .failure(error) }
        }
        return try result.get()
    }

    private func registerPending(
        _ registrations: [SSHKeyRegistrationIntent], caller: CallerInfo
    ) async throws -> [SSHKeyMetadata] {
        guard verifiedLauncher(caller),
              let references = Self.validatedRegistrations(registrations) else {
            throw SSHProtectionError.authorizationDenied
        }

        let executablePath = caller.peerIdentity?.code.executablePath
            ?? ProcessAncestry.executablePath(of: caller.pid)
            ?? "/usr/local/bin/csec"
        let plan = DeliveryPlan(
            mechanism: .credentialProtocol,
            executable: PlannedExecutable(
                canonicalPath: executablePath,
                signingIdentifier: caller.peerIdentity?.code.identifier,
                teamIdentifier: caller.peerIdentity?.code.teamIdentifier,
                cdHash: caller.peerIdentity?.code.cdHash,
                assurance: caller.peerIdentity?.code.role == .launcher
                    ? .verifiedProduct : .unverified
            ),
            root: .caller,
            descendantScope: .exactProcess,
            destination: .credentialConsumer,
            requestedTTLSeconds: 5 * 60,
            operationContext: "register public metadata for protected SSH keys"
        )
        // A key whose reference cannot resolve can never be registered: say
        // so before the panel rather than after its touch.
        if let summary = Agent.absentSummary(await resolver.referencesKnownAbsent(references)) {
            await recordAbsentReference(DecisionLogRecord(
                kind: .absentReference, surface: .sshSigning,
                requester: DecisionLogRecord.Requester(class: "launcher", rootPID: caller.pid),
                refs: references.map(\.uri).sorted(),
                mechanism: plan.mechanism.rawValue,
                detail: "register SSH keys: \(summary); refused before a panel"
            ))
            throw SSHProtectionError.referenceNotFound(summary)
        }
        var reviewedCaller = caller
        reviewedCaller.terminal = await terminalInspection.context(forCallerPID: caller.pid)
        // Registering keys is setup at this Mac's terminal, like an import:
        // it is decided on this Mac and never mirrored to the phone.
        let review = AccessPolicyReview(
            caller: reviewedCaller,
            reason: plan.operationContext,
            plan: plan,
            credentials: await resolver.reviewCredentials(for: references.map { [$0] }),
            macOnly: true
        )
        let what = "register \(references.count) protected SSH key\(references.count == 1 ? "" : "s")"
        func registrationRecord(
            _ outcome: DecisionLogRecord.Outcome, _ decider: DecisionLogRecord.Decider?,
            _ ttdMs: Int?, failure: String? = nil, kind: DecisionLogRecord.Kind = .panel
        ) -> DecisionLogRecord {
            DecisionLogRecord(
                kind: kind, surface: .sshSigning,
                requester: DecisionLogRecord.Requester(
                    class: "launcher", rootPID: caller.pid, terminal: reviewedCaller.terminal?.summary
                ),
                refs: references.map(\.uri).sorted(),
                mechanism: plan.mechanism.rawValue,
                outcome: outcome, decider: decider, ttdMs: ttdMs,
                detail: what + (failure.map { ": \($0)" } ?? "")
            )
        }
        let reviewOutcome = await policyReview.reviewAccess(review)
        guard case let .approved(approval) = reviewOutcome else {
            if case let .denied(reason) = reviewOutcome {
                let reason = HumanWait.current?.effectiveReason(reason) ?? reason
                let ended = DecisionLogRecord.outcome(for: reason)
                await decisionLog?.record(registrationRecord(
                    ended.outcome, ended.decider, ended.ttdMs,
                    failure: HumanWait.current?.abandonment != nil ? HumanWait.current?.withdrawnDetail() : nil,
                    kind: DecisionLogRecord.kind(for: reason)
                ))
            }
            throw SSHProtectionError.authorizationDenied
        }
        let authentication = await completeReview(
            approval,
            caller: caller,
            references: references,
            reason: plan.operationContext,
            ttl: plan.requestedTTLSeconds.map(TimeInterval.init),
            summary: "register SSH signer metadata; no private key leaves csecd"
        )
        let approved = DecisionLogRecord.outcome(for: approval)
        guard case let .approved(unlock) = authentication else {
            await decisionLog?.record(registrationRecord(.authenticationFailed, nil, nil))
            throw SSHProtectionError.authorizationDenied
        }
        guard verifiedLauncher(caller) else {
            await decisionLog?.record(registrationRecord(
                approved.outcome, approved.decider, approved.ttdMs,
                failure: "the launcher changed after approval; nothing was registered"
            ))
            throw SSHProtectionError.authorizationDenied
        }
        do {
            let registered = try await resolveAndRegister(
                registrations, references: references, unlock: unlock
            )
            await decisionLog?.record(registrationRecord(approved.outcome, approved.decider, approved.ttdMs))
            return registered
        } catch {
            await decisionLog?.record(registrationRecord(
                approved.outcome, approved.decider, approved.ttdMs,
                failure: "the keys could not be registered; nothing was registered"
            ))
            throw error
        }
    }

    /// Used by `csec protect --ssh` after a native blob import that was already
    /// shown and authenticated as an SSH-key import. The caller supplies canonical
    /// references only; this path does not know or retain native blob identifiers.
    public func registerAlreadyAuthorized(
        _ registrations: [SSHKeyRegistrationIntent],
        caller: CallerInfo,
        unlock: CacheUnlock? = nil
    ) async throws -> [SSHKeyMetadata] {
        guard verifiedLauncher(caller),
              let references = Self.validatedRegistrations(registrations) else {
            throw SSHProtectionError.authorizationDenied
        }
        let registered = try await resolveAndRegister(
            registrations, references: references, unlock: unlock
        )
        // The panel was the native-store import's own, recorded there.
        await decisionLog?.record(DecisionLogRecord(
            kind: .settings, surface: .sshSigning,
            refs: references.map(\.uri).sorted(),
            detail: "registered \(references.count) protected SSH key\(references.count == 1 ? "" : "s")"
                + " with the native-store import that protected them"
        ))
        return registered
    }

    public func remove(fingerprint: String, caller: CallerInfo) async throws -> Bool {
        guard verifiedLauncher(caller), Self.validFingerprint(fingerprint) else {
            throw SSHProtectionError.authorizationDenied
        }
        var shown = caller
        shown.terminal = await terminalInspection.context(forCallerPID: caller.pid)
        let outcome = await consent.approveSettingsChange(
            SettingsChangeReviewDetails(
                title: "Remove a Protected SSH Key",
                changes: ["Remove SSH key \(fingerprint) from csec's SSH agent, with every signing grant for it"]
            ),
            caller: shown
        )
        outcome.unlock?.invalidate()
        guard outcome.isApproved, verifiedLauncher(caller) else {
            throw SSHProtectionError.authorizationDenied
        }
        let removed = try await catalog.remove(fingerprint: fingerprint)
        if removed {
            let before = grants.count
            grants.removeAll { $0.fingerprint == fingerprint }
            if grants.count != before { await persistGrants() }
            await decisionLog?.record(DecisionLogRecord(
                kind: .settings, surface: .sshSigning, decider: .humanLocal,
                detail: "removed protected SSH key \(fingerprint)"
            ))
        }
        return removed
    }

    public func signSSHAuthentication(
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        binding: SSHDestinationBinding,
        caller: CallerInfo
    ) async throws -> Data {
        let caller = caller.anchored(using: processInspection)
        guard verifiedSSHClient(caller),
              let key = try await catalog.key(publicKeyBlob: publicKeyBlob) else {
            throw SSHProtectionError.keyNotRegistered
        }
        let authentication = try SSHBoundUserAuthentication.parse(
            signedData: signedData,
            binding: binding,
            requestedKeyBlob: publicKeyBlob,
            flags: flags
        )
        await pruneAndPersistGrants()
        pruneDeniedRequesters()
        guard !humanDeniedRequesters.contains(Requester(caller)) else {
            await decisionLog?.record(signingRecord(
                kind: .refusal, key: key, binding: binding, authentication: authentication,
                rootPID: caller.pid, outcome: .denied, decider: nil,
                detail: "this ssh connection's earlier request was denied"
            ))
            throw SSHProtectionError.authorizationDenied
        }
        guard !timedOutRequesters.contains(Requester(caller)) else {
            await decisionLog?.record(signingRecord(
                kind: .refusal, key: key, binding: binding, authentication: authentication,
                rootPID: caller.pid, outcome: .timedOut, decider: nil,
                detail: "nobody answered this ssh connection's earlier request in time"
            ))
            throw SSHProtectionError.approvalTimedOut
        }
        guard !abandonedRequesters.contains(Requester(caller)) else {
            await decisionLog?.record(signingRecord(
                kind: .refusal, key: key, binding: binding, authentication: authentication,
                rootPID: caller.pid, outcome: .requesterGone, decider: nil,
                detail: "this ssh connection's earlier request was abandoned"
            ))
            throw SSHProtectionError.authorizationDenied
        }
        // A coding agent's request is withdrawn if it waits on a human longer
        // than the limit; its `csec ai` reports the wait (`HumanWaitBoard`).
        let limit = approvalWaitLimit
        let wait = HumanWait(
            requester: HumanWait.Requester(pid: caller.pid, startTime: caller.startTime),
            summary: waitSummary(binding: binding, authentication: authentication),
            limit: HumanWait.limit(
                forRequesterPID: caller.pid, startTime: caller.startTime,
                inspection: processInspection, limit: limit
            ),
            board: humanWaitBoard,
            requestAnchor: caller.requestAnchor,
            processInspection: processInspection
        )
        let result: Result<Data, Error> = await wait.bounding {
            do {
                return .success(try await self.signArrived(
                    key: key, publicKeyBlob: publicKeyBlob, signedData: signedData, flags: flags,
                    binding: binding, authentication: authentication, caller: caller
                ))
            } catch {
                return .failure(error)
            }
        }
        if wait.isExpired, case .failure = result {
            recordTimedOut(caller)
            throw SSHProtectionError.approvalTimedOut
        }
        if wait.abandonment != nil, case .failure = result {
            let requester = Requester(caller)
            if !abandonedRequesters.contains(requester) {
                abandonedRequesters.append(requester)
                if abandonedRequesters.count > Self.maximumDeniedRequesters {
                    abandonedRequesters.removeFirst(abandonedRequesters.count - Self.maximumDeniedRequesters)
                }
            }
        }
        return try result.get()
    }

    /// How a signing request's notice names it.
    private func waitSummary(
        binding: SSHDestinationBinding, authentication: SSHBoundUserAuthentication
    ) -> String {
        let host = knownHostsLookup.names(matchingHostKeyFingerprint: binding.hostKeyFingerprint).first
        return "SSH as \(authentication.remoteUser) to "
            + (host ?? "the server with host key \(binding.hostKeyFingerprint)")
    }

    /// The rest of a signing request, run within its `HumanWait`.
    private func signArrived(
        key: SSHKeyMetadata,
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        binding: SSHDestinationBinding,
        authentication: SSHBoundUserAuthentication,
        caller: CallerInfo
    ) async throws -> Data {
        // A live grant covers the request without waiting for a review turn.
        // One still awaiting the restore panel would show that panel first,
        // so a key that cannot sign is refused before it.
        let covering = coveringGrantRoot(
            key: key, binding: binding, authentication: authentication, caller: caller
        )
        if covering?.awaitingRestore ?? true {
            try await refuseIfKnownAbsent(key: key, binding: binding, authentication: authentication, caller: caller)
        }
        if let covering, let signature = try await signCovered(
            covering, key: key, publicKeyBlob: publicKeyBlob, signedData: signedData,
            flags: flags, binding: binding, authentication: authentication, caller: caller
        ) {
            return signature
        }

        // Not covered (any more): before delegation, the review turn or a
        // panel. A restore that just ran may have opened the key's store.
        try await refuseIfKnownAbsent(key: key, binding: binding, authentication: authentication, caller: caller)

        // Claude Code auto mode may stand in for the panel. It is judged
        // before the review turn, so a delegated signature never waits behind
        // a panel; it mints no grant, so every connection is judged on its own.
        var delegationNote: DelegationDecline?
        if let delegation {
            switch try await delegatedVerdict(
                delegation: delegation, key: key, publicKeyBlob: publicKeyBlob,
                signedData: signedData, flags: flags, binding: binding,
                authentication: authentication, caller: caller
            ) {
            case .notApplicable:
                break
            case let .declined(reason, _):
                delegationNote = reason
            case let .signed(signature):
                return signature
            }
        }

        // Otherwise take the review turn. The ticket comes first, so a human
        // Deny made while this request waits can refuse it.
        let ticket = humanDenials.arrive()
        defer { humanDenials.depart(ticket) }
        let turn: ConsentQueue.Permit
        do {
            turn = try await reviewTurns.acquire()
        } catch {
            // Cancelled while waiting: the requester closed its connection, or
            // its deadline passed, so it is never presented.
            await recordWithdrawn(
                key: key, binding: binding, authentication: authentication, caller: caller, cause: nil
            )
            throw SSHProtectionError.authorizationDenied
        }
        do {
            let signature = try await signHoldingReviewTurn(
                key: key, publicKeyBlob: publicKeyBlob, signedData: signedData,
                flags: flags, binding: binding, authentication: authentication,
                caller: caller, ticket: ticket,
                delegationNote: delegationNote
            )
            await turn.release()
            return signature
        } catch {
            await turn.release()
            throw error
        }
    }

    /// The review path, run only while this request holds the review turn. The
    /// caller releases the turn after the grant is minted, so a waiter behind
    /// it re-checks grants against the one this approval created.
    private func signHoldingReviewTurn(
        key: SSHKeyMetadata,
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        binding: SSHDestinationBinding,
        authentication: SSHBoundUserAuthentication,
        caller: CallerInfo,
        ticket: HumanDenialLedger<SSHDenialShape>.Ticket,
        delegationNote: DelegationDecline? = nil
    ) async throws -> Data {
        // Everything may have changed while this request waited: an earlier
        // approval may now cover it, or a human may have denied this question.
        await pruneAndPersistGrants()
        pruneDeniedRequesters()
        guard !humanDeniedRequesters.contains(Requester(caller)) else {
            await decisionLog?.record(signingRecord(
                kind: .refusal, key: key, binding: binding, authentication: authentication,
                rootPID: caller.pid, outcome: .denied, decider: nil,
                detail: "this ssh connection's earlier request was denied"
            ))
            throw SSHProtectionError.authorizationDenied
        }
        if let covering = coveringGrantRoot(
            key: key, binding: binding, authentication: authentication, caller: caller
        ), let signature = try await signCovered(
            covering, key: key, publicKeyBlob: publicKeyBlob, signedData: signedData,
            flags: flags, binding: binding, authentication: authentication, caller: caller
        ) {
            return signature
        }
        // The panel this request waited behind may have opened the key's
        // store and found it does not hold the key: refuse rather than raise
        // another panel that cannot deliver.
        try await refuseIfKnownAbsent(key: key, binding: binding, authentication: authentication, caller: caller)
        let denialShape = SSHDenialShape(
            fingerprint: key.fingerprint,
            hostKeyFingerprint: binding.hostKeyFingerprint,
            remoteUser: authentication.remoteUser
        )
        let scopeChoices = GrantScopeInspector.choices(
            planRootPID: caller.pid,
            planRootStartTime: caller.startTime,
            requestingLabel: "ssh",
            inspection: processInspection
        )
        let defaultRoot = HumanDenialLedger<SSHDenialShape>.Root(
            pid: scopeChoices.defaultOption.pid,
            startTime: scopeChoices.defaultOption.startTime
        )
        // A human just denied this same question — same key, server identity
        // and remote user, offered for the same default scope — while this
        // request waited behind it. A request under that scope whose own
        // default is narrower (an agent inside the denied terminal) is a
        // different question and gets its own panel. The refusal is that Deny
        // applied to this connection too, so its next catalog key is refused
        // like the denied one's.
        guard !humanDenials.refuses(ticket, shape: denialShape, matchesRoot: { $0 == defaultRoot })
        else {
            recordHumanDenial(of: caller)
            await decisionLog?.record(signingRecord(
                kind: .refusal, key: key, binding: binding, authentication: authentication,
                rootPID: defaultRoot.pid, outcome: .denied, decider: nil,
                detail: "answered by the Deny of an identical request it waited behind"
            ))
            throw SSHProtectionError.authorizationDenied
        }
        // A Claude Code request delegation declined is judged again now that
        // it holds the turn, and only after the Deny ledger (a human's Deny of
        // an identical request it waited behind answers it first): what
        // declined it may have changed while it waited (its registration
        // arrived, the key was unlocked), and its note must say what is true
        // now. A `csec ai` already bound to a registration is found by it.
        var delegationNote = delegationNote
        if let delegation, delegationNote != nil {
            // Holding the turn: no hooks-changed panel waits behind it.
            switch try await delegatedVerdict(
                delegation: delegation, key: key, publicKeyBlob: publicKeyBlob,
                signedData: signedData, flags: flags, binding: binding,
                authentication: authentication, caller: caller, mayReviewSettings: false
            ) {
            case .notApplicable:
                // Delegation was turned off meanwhile, or this time nothing
                // could be read: the first judgment stands unless it is off.
                if !(await delegation.isEnabled()) {
                    delegationNote = nil
                }
            case let .declined(reason, _):
                delegationNote = reason
            case let .signed(signature):
                return signature
            }
        }
        let ssh = SSHAccessReviewDetails(
            hostNames: knownHostsLookup.names(
                matchingHostKeyFingerprint: binding.hostKeyFingerprint
            ),
            remoteUser: authentication.remoteUser,
            keyLabel: key.label,
            keyAlgorithm: key.algorithm
        )
        let operation = ssh.reason
        // An `ssh` that has already exited (Ctrl-C, a timeout, a closed tab)
        // must never be shown: the panel would spend a Touch ID on nothing, and
        // the terminal lookup below would describe a dead pid as "no terminal".
        guard requesterIsAlive(caller) else {
            await recordWithdrawn(
                key: key, binding: binding, authentication: authentication, caller: caller,
                cause: "its ssh exited before its panel"
            )
            throw SSHProtectionError.authorizationDenied
        }
        let terminal = await terminalInspection.context(forCallerPID: caller.pid)
        guard requesterIsAlive(caller) else {
            await recordWithdrawn(
                key: key, binding: binding, authentication: authentication, caller: caller,
                cause: "its ssh exited before its panel"
            )
            throw SSHProtectionError.authorizationDenied
        }
        let reviewedCaller = CallerInfo(
            pid: caller.pid,
            startTime: caller.startTime,
            description: "Apple SSH [verified] (pid \(caller.pid))",
            peerIdentity: caller.peerIdentity,
            terminal: terminal,
            requestAnchor: caller.requestAnchor
        )
        let plan = DeliveryPlan(
            mechanism: .credentialProtocol,
            executable: PlannedExecutable(
                canonicalPath: "/usr/bin/ssh",
                signingIdentifier: "com.apple.ssh",
                cdHash: caller.peerIdentity?.code.cdHash,
                assurance: .independentlyProtected
            ),
            root: .caller,
            descendantScope: .subtree,
            destination: .credentialConsumer,
            // nil ⇒ the signing authority lives for the approved session
            // (its process subtree), no wall-clock cap — like a secret grant.
            requestedTTLSeconds: nil,
            operationContext: operation
        )
        // The human chooses how long this signing authority lasts, exactly as
        // they do for a secret release: session lifetime by default, with the
        // opt-in 1h/12h caps beside it.
        let durationChoices = GrantDurationChoices.offered(
            requestedTTLSeconds: nil
        )
        let review = AccessPolicyReview(
            caller: reviewedCaller,
            reason: operation,
            plan: plan,
            credentials: [PolicyReviewCredential(references: [try SecretRef(key.reference)])],
            scopeChoices: scopeChoices,
            durationChoices: durationChoices,
            ssh: ssh,
            delegationNote: delegationNote
        )
        let cause = await promptCause(
            key: key, binding: binding, authentication: authentication, caller: caller
        )
        let reviewOutcome = await policyReview.reviewAccess(review)
        guard case let .approved(approval) = reviewOutcome else {
            // Only the human's own Deny answers the identical requests waiting
            // behind this one and ends this connection's signing. It is
            // recorded before anything is awaited: the panel's turn is already
            // over, so a waiter can run (a restore panel queued behind this one
            // can be approved) during the log write, and it must find the Deny.
            if case let .denied(.human(decidedAt, _, _)) = reviewOutcome {
                humanDenials.recordHumanDenial(
                    shape: denialShape, root: defaultRoot, decidedAt: decidedAt
                )
                recordHumanDenial(of: caller)
            }
            if case let .denied(reason) = reviewOutcome {
                // A review the deadline withdrew, queued or on screen, reads
                // as `.timedOut` whatever ended it there.
                let denial = HumanWait.current?.effectiveReason(reason) ?? reason
                let ended = DecisionLogRecord.outcome(for: denial)
                let kind = DecisionLogRecord.kind(for: denial)
                await decisionLog?.record(signingRecord(
                    kind: kind, key: key, binding: binding, authentication: authentication,
                    rootPID: defaultRoot.pid, outcome: ended.outcome, decider: ended.decider,
                    ttdMs: ended.ttdMs, cause: cause, review: review,
                    scope: scopeChoices.defaultOption.kind.rawValue,
                    duration: DecisionLogRecord.durationText(ttlSeconds: durationChoices.defaultOption.ttlSeconds),
                    detail: kind == .withdrawn || HumanWait.current?.abandonment != nil
                        ? HumanWait.current?.withdrawnDetail() : nil
                ))
            }
            throw SSHProtectionError.authorizationDenied
        }
        let scope = scopeChoices.resolved(selectedID: approval.selectedScopeOptionID)
        let root = Root(pid: scope.pid, startTime: scope.startTime)
        let approvedTTLSeconds =
            durationChoices.resolved(selectedIndex: approval.selectedDurationIndex).ttlSeconds
        func recordFailedApproval(_ detail: String) async {
            let approved = DecisionLogRecord.outcome(for: approval)
            await decisionLog?.record(signingRecord(
                kind: .panel, key: key, binding: binding, authentication: authentication,
                rootPID: root.pid, outcome: approved.outcome, decider: approved.decider,
                ttdMs: approved.ttdMs, cause: cause, review: review, scope: scope.kind.rawValue,
                duration: DecisionLogRecord.durationText(ttlSeconds: approvedTTLSeconds),
                detail: "no signature was made; no grant was minted"
            ))
            await decisionLog?.record(signingRecord(
                kind: .deliveryFailed, key: key, binding: binding, authentication: authentication,
                rootPID: root.pid, outcome: nil, decider: nil, review: review, detail: detail
            ))
        }
        guard verifiedGrantRoot(root, caller: caller) else {
            await approval.authenticationSession?.cancel()
            await recordFailedApproval("the approved requester or grant scope changed before signing")
            throw SSHProtectionError.authorizationDenied
        }
        // Only an option the window offered can be minted; an out-of-range
        // index falls back to the displayed default (session lifetime) rather
        // than lengthening the grant. nil ⇒ session lifetime.
        let outcome = await completeReview(
            approval,
            caller: reviewedCaller,
            references: [try SecretRef(key.reference)],
            reason: operation,
            ttl: approvedTTLSeconds.map(TimeInterval.init),
            summary: "\(operation); SSH signature only; \(ReviewDisplay.sshScopeRootSummary(scope))"
        )
        let approved = DecisionLogRecord.outcome(for: approval)
        guard case let .approved(unlock) = outcome,
              verifiedGrantRoot(root, caller: caller) else {
            let authenticated: Bool
            if case .approved = outcome { authenticated = true } else { authenticated = false }
            if authenticated {
                if case let .approved(unlock) = outcome, unlock?.isLocal == false { unlock?.invalidate() }
                await recordFailedApproval("the approved requester or grant scope changed during authentication")
            } else {
                await decisionLog?.record(signingRecord(
                    kind: .panel, key: key, binding: binding, authentication: authentication,
                    rootPID: root.pid, outcome: .authenticationFailed, decider: nil,
                    cause: cause, review: review, scope: scope.kind.rawValue,
                    duration: DecisionLogRecord.durationText(ttlSeconds: approvedTTLSeconds)
                ))
            }
            throw SSHProtectionError.authorizationDenied
        }
        // A phone approval's remote unlock serves this one signature and
        // nothing after it, whether signing succeeded or failed.
        defer {
            if unlock?.isLocal == false { unlock?.invalidate() }
        }
        let grantID = UUID()
        approvalMemories.append(ApprovalMemory(
            fingerprint: key.fingerprint, rootPID: root.pid, rootStartTime: root.startTime,
            expiresAt: approvedTTLSeconds.map { clock().addingTimeInterval(TimeInterval($0)) },
            grantID: grantID
        ))
        if approvalMemories.count > Self.maximumGrants {
            approvalMemories.removeFirst(approvalMemories.count - Self.maximumGrants)
        }
        await decisionLog?.record(signingRecord(
            kind: .panel, key: key, binding: binding, authentication: authentication,
            rootPID: root.pid, outcome: approved.outcome, decider: approved.decider,
            ttdMs: approved.ttdMs, cause: cause, review: review, scope: scope.kind.rawValue,
            duration: DecisionLogRecord.durationText(ttlSeconds: approvedTTLSeconds)
        ))
        // The grant is minted only once the signature exists: a signing that
        // failed leaves nothing to cover the next request, which is reviewed
        // again, and the log says why after the approval.
        let signature: Data
        if approval.decidedOn == .mac { await resolver.personApprovedAtMac() }
        do {
            signature = try await sign(
                key: key, publicKeyBlob: publicKeyBlob, signedData: signedData,
                flags: flags, root: root, caller: caller, unlock: unlock
            )
        } catch {
            await decisionLog?.record(signingRecord(
                kind: .deliveryFailed, key: key, binding: binding, authentication: authentication,
                rootPID: root.pid, outcome: nil, decider: nil, review: review,
                detail: "no signature was made ("
                    + ((error as? SSHProtectionError)?.diagnosticCode ?? "\(type(of: error))")
                    + "); no grant was minted"
            ))
            throw error
        }
        let approvedAt = clock()
        // Mint: grants whose root is gone are swept first, so the persisted
        // item never carries them forward.
        pruneGrants(now: approvedAt)
        grants.append(Grant(
            id: grantID,
            fingerprint: key.fingerprint,
            hostKeyFingerprint: binding.hostKeyFingerprint,
            remoteUser: authentication.remoteUser,
            rootPID: root.pid,
            rootStartTime: root.startTime,
            auditSessionID: caller.peerIdentity?.audit.auditSessionID,
            clientCDHash: caller.peerIdentity?.code.cdHash,
            expiresAt: approvedTTLSeconds.map { approvedAt.addingTimeInterval(TimeInterval($0)) },
            scopeKind: scope.kind,
            rootProcessLabel: scope.processLabel,
            mintedAt: approvedAt,
            origin: approval.decidedOn == .phone ? .phone : .humanLocal
        ))
        if grants.count > Self.maximumGrants {
            grants.removeFirst(grants.count - Self.maximumGrants)
        }
        await persistGrants()
        // Someone is at the Mac now (`GrantRestoration.approvedAtMac`).
        if approval.decidedOn == .mac { await restoration?.approvedAtMac() }
        return signature
    }

    /// Sign under a covering grant, with no review turn and no unlock. A
    /// restored grant whose key's store is still sealed waits for the restore
    /// panel first; if that panel's outcome leaves the request uncovered (the
    /// grant could not be reopened), this returns nil and the request takes
    /// the ordinary review path.
    private func signCovered(
        _ found: Covering,
        key: SSHKeyMetadata,
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        binding: SSHDestinationBinding,
        authentication: SSHBoundUserAuthentication,
        caller: CallerInfo
    ) async throws -> Data? {
        var covering = found
        if covering.awaitingRestore, let restoration {
            let reference = try SecretRef(key.reference)
            switch await restoration.ensureWarm(for: [reference], requester: caller) {
            case .forgotten:
                // "Forget these approvals" is the human's Deny of what this
                // connection was waiting on: like a Deny on its own panel, it
                // ends the connection's signing, so `ssh` offering its next
                // key does not raise a panel right after the human said no.
                recordHumanDenial(of: caller)
                await decisionLog?.record(signingRecord(
                    kind: .refusal, key: key, binding: binding, authentication: authentication,
                    rootPID: covering.root.pid, outcome: .denied, decider: nil,
                    detail: "the approvals restored after csecd restarted were forgotten"
                ))
                throw SSHProtectionError.authorizationDenied
            case .requesterGone:
                await recordWithdrawn(
                    key: key, binding: binding, authentication: authentication, caller: caller,
                    cause: nil, waitedFor: "the restore panel"
                )
                throw SSHProtectionError.authorizationDenied
            case .failed:
                throw SSHProtectionError.authorizationDenied
            case .warmed, .notNeeded, .usedUp:
                // Checked again at the present: a covering grant may have
                // expired, been revoked or dropped while this request waited.
                await pruneAndPersistGrants()
                guard let refreshed = coveringGrantRoot(
                    key: key, binding: binding, authentication: authentication, caller: caller
                ) else { return nil }
                covering = refreshed
            }
        }
        let signature = try await sign(
            key: key, publicKeyBlob: publicKeyBlob, signedData: signedData,
            flags: flags, root: covering.root, caller: caller, unlock: nil
        )
        await decisionLog?.record(signingRecord(
            kind: .reuse, key: key, binding: binding, authentication: authentication,
            rootPID: covering.root.pid, outcome: .approved,
            decider: covering.restored ? .restoredGrant : .grant
        ))
        return signature
    }

    /// A key whose reference cannot resolve can never sign, whatever a human
    /// decides: refuse it with `referenceNotFound`, as an unregistered key is
    /// refused, and ssh offers its next identity. Writes its
    /// `absent_reference` record, at most once per refusal and run.
    private func refuseIfKnownAbsent(
        key: SSHKeyMetadata,
        binding: SSHDestinationBinding,
        authentication: SSHBoundUserAuthentication,
        caller: CallerInfo
    ) async throws {
        guard let reference = try? SecretRef(key.reference),
              let summary = Agent.absentSummary(await resolver.referencesKnownAbsent([reference])) else { return }
        await recordAbsentReference(signingRecord(
            kind: .absentReference, key: key, binding: binding, authentication: authentication,
            rootPID: caller.pid, outcome: nil, decider: nil,
            detail: summary + "; refused before a panel"
        ))
        throw SSHProtectionError.referenceNotFound(summary)
    }

    /// Write an `absent_reference` record, at most once per refusal and run
    /// (`AbsentReferenceRecords`).
    private func recordAbsentReference(_ record: DecisionLogRecord) async {
        guard let decisionLog, let admitted = absentReferenceRecords.admit(record) else { return }
        await decisionLog.record(admitted)
    }

    /// A value-free record of one signing decision: the key reference, the
    /// verified server identity and the remote user, never key material.
    private func signingRecord(
        kind: DecisionLogRecord.Kind,
        key: SSHKeyMetadata,
        binding: SSHDestinationBinding,
        authentication: SSHBoundUserAuthentication,
        rootPID: pid_t,
        outcome: DecisionLogRecord.Outcome?,
        decider: DecisionLogRecord.Decider?,
        ttdMs: Int? = nil,
        cause: DecisionLogPromptCause? = nil,
        review: AccessPolicyReview? = nil,
        scope: String? = nil,
        duration: String? = nil,
        rootLabel: String? = nil,
        detail: String? = nil
    ) -> DecisionLogRecord {
        let host = review?.ssh?.hostTitle
        let target = "SSH as \(authentication.remoteUser) to "
            + (host ?? "host key \(binding.hostKeyFingerprint)")
            + " with key \(key.fingerprint)"
        return DecisionLogRecord(
            kind: kind,
            surface: .sshSigning,
            requester: DecisionLogRecord.Requester(
                class: "ssh",
                rootPID: rootPID,
                rootLabel: rootLabel ?? review?.scopeChoices?.defaultOption.processLabel,
                terminal: review?.caller.terminal?.summary
            ),
            refs: [key.reference],
            mechanism: DeliveryMechanism.credentialProtocol.rawValue,
            scope: scope,
            duration: duration,
            outcome: outcome,
            decider: decider,
            ttdMs: ttdMs,
            cause: cause?.rawValue,
            detail: detail.map { "\(target); \($0)" } ?? target
        )
    }

    /// Why an SSH panel for this key appeared: this run's approvals first,
    /// then a persisted signing grant for this exact key, server and user that
    /// the restart dropped, in the precedence
    /// `DecisionLogPromptCause.accountingForRestart` states.
    private func promptCause(
        key: SSHKeyMetadata,
        binding: SSHDestinationBinding,
        authentication: SSHBoundUserAuthentication,
        caller: CallerInfo
    ) async -> DecisionLogPromptCause {
        let now = clock()
        let inRun = inRunPromptCause(fingerprint: key.fingerprint, caller: caller, now: now)
        let dropped = await persistence?.droppedSSHGrantCovering(
            keyFingerprint: key.fingerprint,
            hostKeyFingerprint: binding.hostKeyFingerprint,
            remoteUser: authentication.remoteUser,
            callerPID: caller.pid,
            callerAuditSessionID: caller.peerIdentity?.audit.auditSessionID,
            clientCDHash: caller.peerIdentity?.code.cdHash,
            now: now,
            processInspection: processInspection
        )
        return .accountingForRestart(inRun: inRun, droppedAtLoad: dropped)
    }

    /// Why an SSH panel for this key appeared, from this run's approvals: a
    /// live approval for this process tree but another server or user (a new
    /// destination); one that reached its chosen lifetime; one revoked with
    /// `csec revoke`; one for a process tree this `ssh` is not in (or that
    /// exited); or none for this key.
    private func inRunPromptCause(
        fingerprint: String, caller: CallerInfo, now: Date
    ) -> DecisionLogPromptCause {
        let related = approvalMemories.filter { $0.fingerprint == fingerprint }
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

    /// The root of a live grant covering this exact request. The signing path
    /// revalidates it: the root actually approved may differ from the default
    /// this particular command would be offered. A grant minted in this run is
    /// preferred over a restored one still waiting for the restore.
    private func coveringGrantRoot(
        key: SSHKeyMetadata,
        binding: SSHDestinationBinding,
        authentication: SSHBoundUserAuthentication,
        caller: CallerInfo
    ) -> Covering? {
        let now = clock()
        let covering = grants.filter {
            $0.covers(
                key: key,
                binding: binding,
                authentication: authentication,
                caller: caller,
                now: now,
                processInspection: processInspection
            )
        }
        guard let chosen = covering.first(where: { !$0.awaitingRestore }) ?? covering.first else {
            return nil
        }
        return Covering(
            root: Root(pid: chosen.rootPID, startTime: chosen.rootStartTime),
            restored: chosen.restored,
            awaitingRestore: chosen.awaitingRestore
        )
    }

    /// Resolve the key through its provider only now that the request is
    /// authorized, sign, and return nothing but the signature. The caller and
    /// its root are rechecked on both sides of the resolution.
    private func sign(
        key: SSHKeyMetadata,
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        root: Root,
        caller: CallerInfo,
        unlock: CacheUnlock?
    ) async throws -> Data {
        guard verifiedGrantRoot(root, caller: caller) else {
            throw SSHProtectionError.authorizationDenied
        }
        // Signing means it was decided (this panel, a grant, a restore it
        // waited on): the deadline no longer applies to the provider work.
        HumanWait.current?.decide()
        let reference = try SecretRef(key.reference)
        let bytes: Data
        do {
            bytes = try await resolver.resolve(reference, unlock: unlock)
        } catch {
            throw SSHProtectionError.providerResolutionFailed
        }
        return try signWithResolvedKey(
            bytes, publicKeyBlob: publicKeyBlob, signedData: signedData, flags: flags, root: root, caller: caller
        )
    }

    private func signWithResolvedKey(
        _ bytes: Data,
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        root: Root,
        caller: CallerInfo
    ) throws -> Data {
        let privateKey = try SSHPrivateKey.parse(bytes)
        guard privateKey.publicKeyBlob == publicKeyBlob else {
            throw SSHProtectionError.invalidPrivateKey
        }
        let signature = try privateKey.sign(signedData, flags: flags)
        guard verifiedGrantRoot(root, caller: caller) else {
            throw SSHProtectionError.authorizationDenied
        }
        return signature
    }

    private enum DelegatedSigning {
        case signed(Data)
        /// The key is not held unlocked: the request takes the panel.
        case notHeld(DelegationDecline)
        /// The request went to this lifetime's restore panel for its key.
        /// Nothing is signed on the strength of the approval made before
        /// that: the caller judges the request again at the present, with the
        /// Deny-ledger ticket taken before the wait, and departs it.
        case waitedForRestore(HumanDenialLedger<SSHDenialShape>.Ticket)
    }

    /// What delegation made of a signing request.
    private enum DelegatedVerdict {
        /// Not a Claude Code request, or delegation is off.
        case notApplicable
        /// Signed with no panel: delegated, or (after a wait on the restore
        /// panel) under a grant that now covers it.
        case signed(Data)
        /// A panel follows, carrying this note.
        case declined(DelegationDecline, DelegationSession?)
    }

    /// Judges a signing request for delegation and signs what it approves. A
    /// request that went to the restore panel for its key is judged again at
    /// the present, as the grant path re-checks its covering grant after the
    /// same wait: while the panel was up (for hours, behind a locked screen)
    /// the pairing may have been revoked, delegation turned off, this
    /// connection denied or an identical request's panel denied by a human,
    /// or a grant approved on another panel may now cover it. Its `csec ai`
    /// is found again by the registration it is already bound to, so nothing
    /// is consumed twice, and the second judgment never waits again: a key
    /// still cold declines as not held.
    private func delegatedVerdict(
        delegation: ClaudeDelegationService,
        key: SSHKeyMetadata,
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        binding: SSHDestinationBinding,
        authentication: SSHBoundUserAuthentication,
        caller: CallerInfo,
        mayReviewSettings: Bool = true
    ) async throws -> DelegatedVerdict {
        var mayWaitForRestore = true
        var settingsReviewed = !mayReviewSettings
        // The Deny-ledger ticket the restore wait took, held until the
        // second judgment is over.
        var restoreArrival: HumanDenialLedger<SSHDenialShape>.Ticket?
        defer { if let restoreArrival { humanDenials.depart(restoreArrival) } }
        while true {
            switch await delegation.evaluateSSH(
                sshCaller: caller, key: key, binding: binding, authentication: authentication
            ) {
            case .notApplicable:
                return .notApplicable
            case let .declined(reason, session):
                // A hook added since the last acknowledgement: csecd shows it
                // in one panel, as for a secret request, and once it is
                // acknowledged the signing is judged again (csec-0.64.7).
                // Before any review turn, and once per request.
                if reason.isUnacknowledgedSettings, !settingsReviewed {
                    settingsReviewed = true
                    if await delegation.acknowledgeChangedRules(for: caller) { continue }
                }
                return .declined(reason, session)
            case let .approved(delegated):
                switch try await signDelegated(
                    delegated, delegation: delegation, key: key, publicKeyBlob: publicKeyBlob,
                    signedData: signedData, flags: flags, binding: binding,
                    authentication: authentication, caller: caller,
                    mayWaitForRestore: mayWaitForRestore
                ) {
                case let .signed(signature):
                    return .signed(signature)
                case let .notHeld(reason):
                    return .declined(reason, delegated.session)
                case let .waitedForRestore(arrival):
                    mayWaitForRestore = false
                    restoreArrival = arrival
                    await pruneAndPersistGrants()
                    pruneDeniedRequesters()
                    guard !humanDeniedRequesters.contains(Requester(caller)) else {
                        await decisionLog?.record(signingRecord(
                            kind: .refusal, key: key, binding: binding, authentication: authentication,
                            rootPID: caller.pid, outcome: .denied, decider: nil,
                            detail: "this ssh connection's earlier request was denied"
                        ))
                        throw SSHProtectionError.authorizationDenied
                    }
                    if let covering = coveringGrantRoot(
                        key: key, binding: binding, authentication: authentication, caller: caller
                    ), let signature = try await signCovered(
                        covering, key: key, publicKeyBlob: publicKeyBlob, signedData: signedData,
                        flags: flags, binding: binding, authentication: authentication, caller: caller
                    ) {
                        return .signed(signature)
                    }
                    // A human denied an identical question (same key, server
                    // identity and remote user, offered for the same default
                    // scope) while this request waited on the restore panel:
                    // the review turn's rule, applied before delegation judges
                    // it again, so auto mode never overrules that Deny.
                    let defaultRoot = defaultDenialRoot(of: caller)
                    let shape = SSHDenialShape(
                        fingerprint: key.fingerprint,
                        hostKeyFingerprint: binding.hostKeyFingerprint,
                        remoteUser: authentication.remoteUser
                    )
                    guard !humanDenials.refuses(arrival, shape: shape, matchesRoot: { $0 == defaultRoot }) else {
                        recordHumanDenial(of: caller)
                        await decisionLog?.record(signingRecord(
                            kind: .refusal, key: key, binding: binding, authentication: authentication,
                            rootPID: defaultRoot.pid, outcome: .denied, decider: nil,
                            detail: "answered by the Deny of an identical request it waited behind"
                        ))
                        throw SSHProtectionError.authorizationDenied
                    }
                }
            }
        }
    }

    /// The scope this `ssh`'s own panel would offer by default, which is the
    /// root a human Deny is matched against (as the review turn computes it).
    private func defaultDenialRoot(of caller: CallerInfo) -> HumanDenialLedger<SSHDenialShape>.Root {
        let option = GrantScopeInspector.choices(
            planRootPID: caller.pid,
            planRootStartTime: caller.startTime,
            requestingLabel: "ssh",
            inspection: processInspection
        ).defaultOption
        return HumanDenialLedger<SSHDenialShape>.Root(pid: option.pid, startTime: option.startTime)
    }

    /// A signing Claude Code auto mode approved: no grant is minted and no
    /// unlock is used. The key is resolved warm-only. A key csecd does not
    /// hold may still be reopened by this lifetime's one restore panel, raised
    /// for it or already up, after which the request is judged again
    /// (`.waitedForRestore`); with `mayWaitForRestore` false, or once nothing
    /// can reopen it, the request goes to a human.
    private func signDelegated(
        _ ticket: DelegationTicket,
        delegation: ClaudeDelegationService,
        key: SSHKeyMetadata,
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        binding: SSHDestinationBinding,
        authentication: SSHBoundUserAuthentication,
        caller: CallerInfo,
        mayWaitForRestore: Bool
    ) async throws -> DelegatedSigning {
        let root = Root(pid: caller.pid, startTime: caller.startTime)
        guard verifiedGrantRoot(root, caller: caller) else {
            throw SSHProtectionError.authorizationDenied
        }
        let reference = try SecretRef(key.reference)
        let bytes = await resolver.resolveWithoutInteraction(reference)
        if bytes == nil, mayWaitForRestore, let restoration {
            // Waiting on the restore panel is waiting behind whatever panel is
            // on screen, so the request joins the Deny ledger before it waits,
            // as one waiting for the review turn does.
            let arrival = humanDenials.arrive()
            switch await restoration.ensureWarmForDelegation(for: [reference], requester: caller) {
            case .forgotten:
                humanDenials.depart(arrival)
                recordHumanDenial(of: caller)
                await decisionLog?.record(signingRecord(
                    kind: .refusal, key: key, binding: binding, authentication: authentication,
                    rootPID: caller.pid, outcome: .denied, decider: nil,
                    detail: "the approvals restored after csecd restarted were forgotten"
                ))
                throw SSHProtectionError.authorizationDenied
            case .requesterGone:
                humanDenials.depart(arrival)
                await recordWithdrawn(
                    key: key, binding: binding, authentication: authentication, caller: caller,
                    cause: nil, waitedFor: "the restore panel"
                )
                throw SSHProtectionError.authorizationDenied
            case .failed:
                humanDenials.depart(arrival)
                throw SSHProtectionError.authorizationDenied
            case .warmed, .notNeeded, .usedUp:
                return .waitedForRestore(arrival)
            }
        }
        guard let bytes else {
            return .notHeld(await delegation.noteNotHeld(ticket, reference: reference, surface: .sshSigning))
        }
        let signature = try signWithResolvedKey(
            bytes, publicKeyBlob: publicKeyBlob, signedData: signedData, flags: flags, root: root, caller: caller
        )
        await delegation.noteDelegatedRelease(ticket)
        var record = signingRecord(
            kind: .delegatedRelease, key: key, binding: binding, authentication: authentication,
            rootPID: ticket.session.agent.pid, outcome: .approved, decider: .delegated
        )
        record.delegation = DecisionLogRecord.Delegation(
            decision: "approved", claudeBuild: ticket.session.buildLabel,
            identityLookup: ticket.session.identityLookup?.logDescription
        )
        await decisionLog?.record(record)
        return .signed(signature)
    }

    private func resolveAndRegister(
        _ registrations: [SSHKeyRegistrationIntent],
        references: [SecretRef],
        unlock: CacheUnlock?
    ) async throws -> [SSHKeyMetadata] {
        var metadata: [SSHKeyMetadata] = []
        metadata.reserveCapacity(registrations.count)
        for (registration, reference) in zip(registrations, references) {
            let bytes: Data
            do {
                bytes = try await resolver.resolve(reference, unlock: unlock)
            } catch {
                throw SSHProtectionError.providerResolutionFailed
            }
            let key = try SSHPrivateKey.parse(bytes)
            let publicKey = try SSHPublicKey.parse(key.publicKeyBlob)
            let label = Self.safeLabel(registration.label)
            metadata.append(SSHKeyMetadata(
                reference: reference.uri,
                fingerprint: publicKey.fingerprint,
                algorithm: publicKey.algorithm,
                publicKeyBlob: publicKey.blob,
                label: label
            ))
        }
        return try await catalog.register(metadata)
    }

    private func completeReview(
        _ approval: AccessPolicyApproval,
        caller: CallerInfo,
        references: [SecretRef],
        reason: String,
        ttl: TimeInterval?,
        summary: String
    ) async -> ConsentOutcome {
        if let session = approval.authenticationSession {
            return await session.completeAfterPolicyApproval(
                policySummary: summary + "; duration \(BiometricConsent.formatDuration(ttl))"
            )
        }
        return await consent.requestConsent(
            caller: caller,
            newReferences: references,
            reason: reason,
            ttl: ttl,
            policySummary: summary
        )
    }

    private func verifiedLauncher(_ caller: CallerInfo) -> Bool {
        guard caller.requestAnchor?.abandonment(using: processInspection) == nil else { return false }
        if allowUnverifiedCallersForTesting { return true }
        guard caller.startTime > 0,
              processInspection.startTime(of: caller.pid) == caller.startTime else { return false }
        return caller.peerIdentity?.code.signatureValid == true
            && caller.peerIdentity?.code.role == .launcher
    }

    private func verifiedSSHClient(_ caller: CallerInfo) -> Bool {
        if allowUnverifiedCallersForTesting { return true }
        guard caller.startTime > 0,
              processInspection.startTime(of: caller.pid) == caller.startTime,
              let peer = caller.peerIdentity else { return false }
        return SSHClientCodeIdentity.accepts(peer)
    }

    private func verifiedGrantRoot(_ root: Root, caller: CallerInfo) -> Bool {
        verifiedSSHClient(caller)
            && caller.requestAnchor?.abandonment(using: processInspection) == nil
            && caller.startTime > 0
            && processInspection.startTime(of: caller.pid) == caller.startTime
            && processInspection.startTime(of: root.pid) == root.startTime
            && processInspection.descends(caller.pid, from: root.pid, rootStartTime: root.startTime)
    }

    /// The exact `ssh` incarnation that asked is still running.
    private func requesterIsAlive(_ caller: CallerInfo) -> Bool {
        AccessReviewRequester.isAlive(caller, using: processInspection)
    }

    private func recordHumanDenial(of caller: CallerInfo) {
        let requester = Requester(caller)
        guard requester.startTime > 0, !humanDeniedRequesters.contains(requester) else { return }
        humanDeniedRequesters.append(requester)
        if humanDeniedRequesters.count > Self.maximumDeniedRequesters {
            humanDeniedRequesters.removeFirst(
                humanDeniedRequesters.count - Self.maximumDeniedRequesters
            )
        }
    }

    private func recordTimedOut(_ caller: CallerInfo) {
        let requester = Requester(caller)
        guard requester.startTime > 0, !timedOutRequesters.contains(requester) else { return }
        timedOutRequesters.append(requester)
        if timedOutRequesters.count > Self.maximumDeniedRequesters {
            timedOutRequesters.removeFirst(timedOutRequesters.count - Self.maximumDeniedRequesters)
        }
    }

    /// The `withdrawn` record of a signing request that left a wait on a
    /// human with nobody having decided: its `ssh` went away, or its deadline
    /// passed.
    private func recordWithdrawn(
        key: SSHKeyMetadata,
        binding: SSHDestinationBinding,
        authentication: SSHBoundUserAuthentication,
        caller: CallerInfo,
        cause: String?,
        waitedFor: String? = nil
    ) async {
        guard let decisionLog else { return }
        let wait = HumanWait.current
        let place = waitedFor.map { "waited for \($0)" }
        let detail = wait?.withdrawnDetail(cause: cause, place: place)
            ?? "\(place ?? "never shown"); \(cause ?? "its ssh went away")"
        await decisionLog.record(signingRecord(
            kind: .withdrawn, key: key, binding: binding, authentication: authentication,
            rootPID: wait?.requestAnchor?.scope.pid ?? caller.pid,
            outcome: wait?.isExpired == true ? .timedOut : .requesterGone,
            decider: nil, rootLabel: wait?.requestAnchor?.scope.label, detail: detail
        ))
    }

    /// A denied `ssh` that has exited can never ask again, and its pid may be
    /// reused by an unrelated process that deserves its own panel.
    private func pruneDeniedRequesters() {
        humanDeniedRequesters.removeAll {
            processInspection.startTime(of: $0.pid) != $0.startTime
        }
        timedOutRequesters.removeAll {
            processInspection.startTime(of: $0.pid) != $0.startTime
        }
        abandonedRequesters.removeAll {
            processInspection.startTime(of: $0.pid) != $0.startTime
        }
    }

    @discardableResult
    private func pruneGrants(now: Date) -> Int {
        let before = grants.count
        grants.removeAll {
            // A nil expiry never lapses by clock; the root-process liveness check
            // below is the authority for a session-lifetime signing grant.
            ($0.expiresAt.map { now >= $0 } ?? false)
                || processInspection.startTime(of: $0.rootPID) != $0.rootStartTime
        }
        return before - grants.count
    }

    /// Sweep, and rewrite the persisted item only when something was dropped.
    private func pruneAndPersistGrants() async {
        if pruneGrants(now: clock()) > 0 {
            await persistGrants()
        }
    }

    /// Hands the persistence owner these grants as they now stand. The
    /// snapshot and its generation are taken together, before anything else
    /// can run on this actor, so a snapshot that arrives late is recognized
    /// as older and ignored.
    private func persistGrants() async {
        guard let persistence else { return }
        grantGeneration += 1
        let current = grantGeneration
        let snapshot = grants.map(\.persisted)
        await persistence.update(ssh: snapshot, generation: current)
    }

    // MARK: - Listing, revocation, restore

    /// Each catalogued key's reference by fingerprint, for the restore rows
    /// of paired projects.
    public func keyReferences() async -> [String: String] {
        guard let keys = try? await catalog.list() else { return [:] }
        return Dictionary(keys.map { ($0.fingerprint, $0.reference) }, uniquingKeysWith: { first, _ in first })
    }

    /// How `csec grants` shows a project's paired SSH uses: the key's
    /// reference and label when the catalog still has it, and the server's
    /// known_hosts names.
    public func pairingSummaries(for uses: [PairedSSHUse]) async -> [SSHPairingSummary] {
        let keys = (try? await catalog.list()) ?? []
        let byFingerprint = Dictionary(keys.map { ($0.fingerprint, $0) }, uniquingKeysWith: { first, _ in first })
        return uses.map { use in
            let key = byFingerprint[use.keyFingerprint]
            return SSHPairingSummary(
                keyReference: key?.reference,
                keyFingerprint: use.keyFingerprint,
                keyLabel: key.map { ReviewDisplay.bounded(ReviewDisplay.sanitized($0.label), maxBytes: 256) },
                hostKeyFingerprint: use.hostKeyFingerprint,
                hostNames: Array(SSHKnownHostsLookup.safeNames(
                    knownHostsLookup.names(matchingHostKeyFingerprint: use.hostKeyFingerprint)
                ).prefix(16)),
                remoteUser: use.remoteUser
            )
        }
    }

    /// Fingerprints of the keys in the catalog, for the load check that drops
    /// a persisted grant whose key was removed. Nil when the catalog cannot
    /// be read, which restores no SSH grant.
    public func catalogFingerprints() async -> Set<String>? {
        guard let keys = try? await catalog.list() else { return nil }
        return Set(keys.map(\.fingerprint))
    }

    /// Put back the SSH grants the persisted item restored at startup. They
    /// are bound to exactly the facts they were minted with and wait for the
    /// restore panel before their key is resolved.
    public func restore(_ records: [PersistedSSHGrant]) async {
        let known = Set(grants.map(\.id))
        let added = records.filter { !known.contains($0.id) }.map { Grant(restoring: $0) }
        guard !added.isEmpty else { return }
        grants.append(contentsOf: added)
        if grants.count > Self.maximumGrants {
            grants.removeFirst(grants.count - Self.maximumGrants)
        }
        await persistGrants()
    }

    /// Value-free descriptions of every live SSH grant for `csec grants`:
    /// the key, the verified server identity, the remote user and the root.
    public func grantSummaries() async -> [GrantSummary] {
        await pruneAndPersistGrants()
        let keys = (try? await catalog.list()) ?? []
        let byFingerprint = Dictionary(keys.map { ($0.fingerprint, $0) }, uniquingKeysWith: { first, _ in first })
        return grants.map { grant in
            let key = byFingerprint[grant.fingerprint]
            let hostNames = knownHostsLookup.names(matchingHostKeyFingerprint: grant.hostKeyFingerprint)
            let host = hostNames.first ?? "host key \(grant.hostKeyFingerprint)"
            return GrantSummary(
                id: grant.id.uuidString.lowercased(),
                kind: .ssh,
                rootPID: grant.rootPID,
                rootProcessLabel: ReviewDisplay.bounded(
                    grant.rootProcessLabel
                        ?? ReviewDisplay.sanitized(processInspection.name(of: grant.rootPID) ?? "process"),
                    maxBytes: 256
                ),
                scopeKind: grant.scopeKind,
                references: key.map { [$0.reference] } ?? [],
                reason: ReviewDisplay.bounded(
                    ReviewDisplay.sanitized("SSH as \(grant.remoteUser) to \(host)"), maxBytes: 512
                ),
                expiresAt: grant.expiresAt,
                ssh: SSHGrantSummary(
                    keyFingerprint: grant.fingerprint,
                    keyLabel: key.map { ReviewDisplay.bounded(ReviewDisplay.sanitized($0.label), maxBytes: 256) },
                    hostKeyFingerprint: grant.hostKeyFingerprint,
                    hostNames: Array(SSHKnownHostsLookup.safeNames(hostNames).prefix(16)),
                    remoteUser: grant.remoteUser
                ),
                restored: grant.restored
            )
        }
    }

    /// The root process of the SSH grant whose id is `id`, while it is held
    /// (see `GrantTable.root(ofGrantID:)`).
    public func grantRoot(id: String) -> ProcessIncarnation? {
        let id = id.lowercased()
        return grants.first { $0.id.uuidString.lowercased() == id }
            .map { ProcessIncarnation(pid: $0.rootPID, startTime: $0.rootStartTime) }
    }

    /// Drop every SSH grant whose id begins with `idPrefix`. The caller
    /// persists the removal synchronously before it replies.
    public func revokeGrants(idPrefix: String) async -> Int {
        let prefix = idPrefix.lowercased()
        guard !prefix.isEmpty else { return 0 }
        let before = grants.count
        grants.removeAll { $0.id.uuidString.lowercased().hasPrefix(prefix) }
        let removed = before - grants.count
        if removed > 0 {
            for index in approvalMemories.indices
                where approvalMemories[index].grantID.uuidString.lowercased().hasPrefix(prefix) {
                approvalMemories[index].revoked = true
            }
            await persistGrants()
        }
        return removed
    }

    public func revokeAllGrants() async -> Int {
        let count = grants.count
        grants.removeAll()
        for index in approvalMemories.indices { approvalMemories[index].revoked = true }
        if count > 0 { await persistGrants() }
        return count
    }

    private static func validatedRegistrations(
        _ registrations: [SSHKeyRegistrationIntent]
    ) -> [SecretRef]? {
        guard !registrations.isEmpty,
              registrations.count <= SSHKeyCatalog.maximumKeys else { return nil }
        var references: [SecretRef] = []
        var seen = Set<String>()
        for registration in registrations {
            guard registration.reference.utf8.count <= 4_096,
                  let reference = try? SecretRef(registration.reference),
                  reference.uri == registration.reference,
                  seen.insert(reference.uri).inserted,
                  registration.label?.utf8.count ?? 0 <= 256,
                  !(registration.label?.utf8.contains(0) ?? false) else { return nil }
            references.append(reference)
        }
        return references
    }

    private static func safeLabel(_ value: String?) -> String {
        let sanitized = ReviewDisplay.sanitized(value ?? "csec protected key")
        return String(sanitized.prefix(256))
    }

    private static func validFingerprint(_ value: String) -> Bool {
        value.hasPrefix("SHA256:")
            && value.utf8.count <= 128
            && !value.utf8.contains(0)
    }

}

private extension SSHSigningService.Requester {
    init(_ caller: CallerInfo) {
        self.init(pid: caller.pid, startTime: caller.startTime)
    }
}

extension SSHSigningService: RestoredGrantSource {
    /// Restored SSH grants still waiting for the restore panel whose root is
    /// alive. A row names the key's reference, so the panel reopens its store
    /// through the ordinary provider abstraction; this service never assumes
    /// which backend holds it.
    public func restoreEntries() async -> [RestoreEntry] {
        let now = clock()
        let waiting = grants.filter {
            $0.awaitingRestore && ($0.expiresAt.map { now < $0 } ?? true)
                && processInspection.startTime(of: $0.rootPID) == $0.rootStartTime
        }
        guard !waiting.isEmpty, let keys = try? await catalog.list() else { return [] }
        let byFingerprint = Dictionary(keys.map { ($0.fingerprint, $0) }, uniquingKeysWith: { first, _ in first })
        return waiting.compactMap { grant in
            guard let key = byFingerprint[grant.fingerprint],
                  let reference = try? SecretRef(key.reference) else { return nil }
            let details = SSHAccessReviewDetails(
                hostNames: knownHostsLookup.names(matchingHostKeyFingerprint: grant.hostKeyFingerprint),
                remoteUser: grant.remoteUser,
                keyLabel: key.label,
                keyAlgorithm: key.algorithm
            )
            let label = grant.rootProcessLabel
                ?? ReviewDisplay.sanitized(processInspection.name(of: grant.rootPID) ?? "process")
            let scope = GrantScopeOption(
                kind: grant.scopeKind, pid: grant.rootPID,
                startTime: grant.rootStartTime, processLabel: label
            )
            return RestoreEntry(
                grantID: grant.id,
                row: RestoreReviewRow(
                    kind: .sshGrant,
                    title: label,
                    detail: "\(ReviewDisplay.sshScopeTitle(scope)) · pid \(grant.rootPID)",
                    references: [reference.uri],
                    ssh: RestoreReviewRow.SSH(details)
                ),
                references: [reference]
            )
        }
    }

    public func settleRestore(forgetting forgotten: Set<UUID>) async -> Int {
        let before = grants.count
        grants.removeAll { forgotten.contains($0.id) }
        for index in grants.indices where grants[index].restored {
            grants[index].warm = true
        }
        let removed = before - grants.count
        if removed > 0 { await persistGrants() }
        return removed
    }
}
