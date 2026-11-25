import Foundation
import CSECRemoteApproval
import CSecuritySupport
#if canImport(Darwin)
import Darwin
#endif

/// Minimal client: connects to the agent socket, sends one `access` request, and
/// returns the resolved values. Used by `csec` and by tests. Values arrive in
/// this process's heap over the socket, never via env or argv.
public struct AgentClient {
    private let path: String
    private let serverTrustPolicy: AgentServerTrustPolicy
    private let liveness: AgentLiveness

    public init(
        path: String,
        serverTrustPolicy: AgentServerTrustPolicy = .requireProductAgent,
        liveness: AgentLiveness = .default
    ) {
        self.path = path
        self.serverTrustPolicy = serverTrustPolicy
        self.liveness = liveness
    }

    public enum ClientError: Error, LocalizedError {
        case connectFailed(String)
        case connectPermissionDenied(String)
        case untrustedServer(String)
        case transportFailed
        case denied(String)
        case protocolFailure(WireErrorCode, String)
        case agentError(String)
        /// csecd accepted the connection and then went completely silent — no
        /// response and not even a heartbeat. Distinct from `connectFailed` (no
        /// daemon at all) and from a long human wait, which keeps heartbeats
        /// flowing and is never bounded.
        case daemonUnresponsive(seconds: Int)
        /// The connection to csecd broke mid-request: the request could not be
        /// written, or the connection closed before a response. csecd may have
        /// exited (`AgentOutputRedactionSession.agentHasExited` tells), or it
        /// may have closed this connection itself.
        case connectionLost(String)

        public var errorDescription: String? {
            switch self {
            case let .connectFailed(path):
                return "cannot reach agent at \(path)"
            case let .connectPermissionDenied(path):
                return "permission denied connecting to agent at \(path) (sandbox or filesystem permissions)"
            case let .untrustedServer(reason):
                return "refusing untrusted agent: \(reason)"
            case .transportFailed:
                return "agent transport failed"
            case let .denied(message):
                // csecd's own value-free reason, such as a withdrawal after
                // nobody answered (`HumanWait.timeoutMessage`).
                let shown = ReviewDisplay.fitted(message, maxBytes: 512)
                return shown.isEmpty || shown == "denied" ? "consent denied" : shown
            case let .protocolFailure(code, message):
                return "\(code.rawValue): \(message)"
            case let .agentError(message):
                return message
            case let .daemonUnresponsive(seconds):
                return "the Convenient Security agent (csecd) stopped responding for "
                    + "\(seconds) seconds and may be wedged. Fix: run `csec doctor` to restart it."
            case let .connectionLost(message):
                return message
            }
        }
    }

    /// Request one or more references; returns ref → value bytes on approval.
    /// `delegationNotice` receives csecd's setup notice
    /// (`Response.delegationNotice`) before the reply is checked, so a
    /// refused request still delivers it.
    public func access(
        references: [String],
        reason: String,
        ttlSeconds: Int? = nil,
        deliveryPlan: DeliveryPlan? = nil,
        commandLine: [String]? = nil,
        delegationNotice: ((String) -> Void)? = nil,
        waitingNotice: ((String) -> Void)? = nil
    ) throws -> [String: Data] {
        let plan = deliveryPlan ?? .directHeap(
            executablePath: URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL.path,
            assurance: .unverified,
            ttlSeconds: ttlSeconds,
            operationContext: "direct heap access"
        )
        let request = try AccessRequest(
            references: references,
            reason: reason,
            ttlSeconds: ttlSeconds,
            deliveryPlan: plan,
            commandLine: commandLine
        )
        // `waitingNotice` hears, while the request waits, that it waits on a
        // human (`HumanWait`): the line a coding agent's session needs to
        // know why its command has stopped.
        let response = try AgentConnection(
            path: path, serverTrustPolicy: serverTrustPolicy, liveness: liveness
        ).send(.access(request), onNotice: waitingNotice)
        guard response.requestID == request.requestID else {
            throw ClientError.transportFailed
        }
        if let notice = response.delegationNotice.flatMap(Self.boundedNotice) { delegationNotice?(notice) }
        if let failure = response.failure {
            if failure.code == .consentDenied {
                throw ClientError.denied(failure.message)
            }
            throw ClientError.protocolFailure(failure.code, failure.message)
        }
        if let error = response.error {
            throw error == "denied" ? ClientError.denied(error) : ClientError.agentError(error)
        }
        guard let values = response.values,
              Set(values.keys) == Set(references) else {
            throw ClientError.transportFailed
        }
        return values
    }

    /// Ask the agent which URI schemes it can resolve. No consent, no secrets —
    /// used to detect secret references in the environment.
    public func schemes() throws -> [String] {
        let response = try send(.schemes)
        if let failure = response.failure {
            throw ClientError.protocolFailure(failure.code, failure.message)
        }
        if let error = response.error { throw ClientError.agentError(error) }
        guard let schemes = response.schemes else { throw ClientError.transportFailed }
        return schemes
    }

    /// The same capability query, with each provider's one-line health summary.
    /// Older agents omit the summaries; the schemes are always present.
    public func schemesWithProviderStatus() throws -> (
        schemes: [String], providerStatus: [ProviderStatusSummary]
    ) {
        let response = try send(.schemes)
        if let failure = response.failure {
            throw ClientError.protocolFailure(failure.code, failure.message)
        }
        if let error = response.error { throw ClientError.agentError(error) }
        guard let schemes = response.schemes else { throw ClientError.transportFailed }
        return (schemes, response.providerStatus ?? [])
    }

    /// Wait for the daemon's existing restore batch. No requested references,
    /// credentials or grant are sent back, even when the human approves.
    public func restoreApprovals(waitingNotice: ((String) -> Void)? = nil) throws -> RestorationResult {
        let request = RestoreApprovalsRequest()
        let response = try AgentConnection(
            path: path, serverTrustPolicy: serverTrustPolicy, liveness: liveness
        ).send(.restoreApprovals(request), onNotice: waitingNotice)
        try Self.check(response: response, requestID: request.requestID)
        guard response.version == WireProtocol.version, let status = response.restorationStatus,
              response.values == nil, response.document == nil,
              response.restoreFetchAhead?.isBounded != false else {
            throw ClientError.transportFailed
        }
        return RestorationResult(status: status, fetchedAhead: response.restoreFetchAhead)
    }

    /// `restoreApprovals`'s bounded reply: the restore's status and, when any
    /// paired reference needed no csec unlock, what was fetched ahead.
    public struct RestorationResult: Sendable, Equatable {
        public let status: RestorationStatus
        public let fetchedAhead: FetchAheadSummary?
    }

    /// Live grants, value-free. Bounds are re-checked here so a malformed reply
    /// cannot reach the renderer.
    public func listGrants() throws -> [GrantSummary] {
        let request = GrantsRequest(action: .list)
        let response = try send(.grants(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let grants = response.grants,
              // The persisted caps: 1024 secret and 256 SSH grants.
              grants.count <= 1_280,
              grants.allSatisfy(\.isWellFormed) else {
            throw ClientError.transportFailed
        }
        return grants
    }

    /// Revoke one grant by id (or id prefix), or every live grant. Returns how
    /// many were removed.
    public func revokeGrants(grantID: String? = nil, all: Bool = false) throws -> Int {
        let request = GrantsRequest(action: .revoke, grantID: grantID, all: all)
        let response = try send(.grants(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let count = response.revokedGrantCount, count >= 0 else {
            throw ClientError.transportFailed
        }
        return count
    }

    /// Everything `csec grants` lists: live secret and SSH grants, and, while
    /// delegated approvals are on, pairings, trusted builds and acknowledged
    /// hooks. Bounds are re-checked here so a malformed reply cannot reach the
    /// renderer.
    public func grantListing() throws -> GrantListing {
        let request = GrantsRequest(action: .list)
        let response = try send(.grants(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let grants = response.grants,
              grants.count <= 1_280,
              grants.allSatisfy(\.isWellFormed),
              response.delegationGrants?.isWellFormed ?? true else {
            throw ClientError.transportFailed
        }
        return GrantListing(grants: grants, delegation: response.delegationGrants)
    }

    /// Revoke the one entry a typed id (or bare hex, a secret grant) names.
    /// Removals need no Touch ID. A prefix that matches more than one entry of
    /// its kind removes nothing and comes back as `.ambiguous`.
    public func revoke(id: String) throws -> GrantRevocationOutcome {
        try revocation(GrantsRequest(action: .revoke, grantID: id))
    }

    /// Revoke every secret grant, SSH grant and pairing.
    public func revokeAll() throws -> (count: Int, removed: [RevocableEntry]) {
        switch try revocation(GrantsRequest(action: .revoke, all: true)) {
        case let .revoked(count, removed): return (count, removed)
        case .ambiguous: throw ClientError.transportFailed
        }
    }

    private func revocation(_ request: GrantsRequest) throws -> GrantRevocationOutcome {
        let response = try send(.grants(request))
        if let ambiguous = try Self.ambiguity(in: response, requestID: request.requestID) {
            return .ambiguous(ambiguous)
        }
        try Self.check(response: response, requestID: request.requestID)
        guard let count = response.revokedGrantCount, count >= 0 else {
            throw ClientError.transportFailed
        }
        // A csecd without delegated approvals reports only the count.
        guard let revocation = response.grantRevocation else {
            return .revoked(count: count, removed: [])
        }
        guard revocation.isWellFormed, !revocation.isAmbiguous,
              revocation.removed.count == count else {
            throw ClientError.transportFailed
        }
        return .revoked(count: count, removed: revocation.removed)
    }

    /// The matches of an ambiguous id: an `invalid_request` failure that
    /// carries them. Nil for any other reply.
    private static func ambiguity(in response: Response, requestID: String) throws -> [RevocableEntry]? {
        guard response.requestID == requestID,
              response.failure?.code == .invalidRequest,
              let revocation = response.grantRevocation,
              revocation.isAmbiguous else { return nil }
        guard revocation.isWellFormed else { throw ClientError.transportFailed }
        return revocation.ambiguousMatches
    }

    /// `configure_delegation`. Touch ID refused on `enable`, `trust_build` or
    /// `acknowledge_hooks` throws `ClientError.denied`. `untrust_build` and
    /// `forget_hook` report what they removed, or the matches of an ambiguous
    /// id.
    public func configureDelegation(
        _ request: DelegationConfigurationRequest
    ) throws -> DelegationConfigurationOutcome {
        let response = try send(.configureDelegation(request))
        if let ambiguous = try Self.ambiguity(in: response, requestID: request.requestID) {
            return .ambiguous(ambiguous)
        }
        try Self.check(response: response, requestID: request.requestID)
        guard let status = response.delegationStatus, status.isWellFormed else {
            throw ClientError.transportFailed
        }
        switch request.action {
        case .untrustBuild, .forgetHook:
            guard let revocation = response.grantRevocation,
                  revocation.isWellFormed, !revocation.isAmbiguous else {
                throw ClientError.transportFailed
            }
            return .configured(status, removed: revocation.removed)
        case .status, .enable, .trustBuild, .acknowledgeHooks, .disable:
            return .configured(status, removed: [])
        }
    }

    /// Register the program the matching `csec ai` will run, for `csec hook
    /// claude`. Bounded by `AgentLiveness.agentCommandRegistration` whatever
    /// this client was built with, never retried, and silent: every failure
    /// (no csecd, an untrusted or stale one, a slow one, a refusal) is `false`.
    /// It opts out of heartbeats, so the one-second silence bound holds
    /// whatever csecd's heartbeat interval: no human is ever waited on here.
    /// The check of csecd's signature has no bound of its own, so the whole
    /// call runs on a thread of its own under
    /// `AgentLiveness.agentCommandRegistrationDeadline`; a registration given
    /// up on before it was sent is never sent.
    public func registerAgentCommand(_ registration: AgentCommandRegistration) -> Bool {
        let cancellation = AgentCallCancellation()
        let outcome = RegistrationOutcome()
        let path = self.path
        let trust = self.serverTrustPolicy
        let register: @Sendable () -> Bool = {
            guard !cancellation.isCancelled else { return false }
            let connection: AgentConnection
            do {
                connection = try AgentConnection(
                    path: path,
                    serverTrustPolicy: trust,
                    liveness: .agentCommandRegistration
                )
            } catch {
                return false
            }
            guard cancellation.arm({ connection.interrupt() }) else { return false }
            defer { cancellation.disarm() }
            guard let response = try? connection.send(.registerAgentCommand(registration), supportsHeartbeats: false),
                  response.requestID == registration.requestID,
                  response.failure == nil, response.error == nil else { return false }
            return response.agentCommandRegistered == true
        }
        Thread.detachNewThread { outcome.finish(register()) }
        guard let registered = outcome.wait(seconds: AgentLiveness.agentCommandRegistrationDeadline) else {
            cancellation.cancel()
            return false
        }
        return registered
    }

    /// One page of decision-log records. Bounds are re-checked here so a
    /// malformed reply cannot reach the renderer.
    public func decisionLogPage(_ query: DecisionLogQuery) throws -> DecisionLogPage {
        let request = DecisionLogRequest(action: .read, query: query)
        let response = try send(.decisionLog(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let page = response.decisionLogPage,
              page.records.count <= query.limit else {
            throw ClientError.transportFailed
        }
        return page
    }

    /// Verify the decision log now. A finding is recorded and notified by
    /// csecd exactly as at startup.
    public func verifyDecisionLog() throws -> DecisionLogVerification {
        let request = DecisionLogRequest(action: .verify)
        let response = try send(.decisionLog(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let verification = response.decisionLogVerification else {
            throw ClientError.transportFailed
        }
        return verification
    }

    public func decisionLogStatus() throws -> DecisionLogStatus {
        let request = DecisionLogRequest(action: .status)
        let response = try send(.decisionLog(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let status = response.decisionLogStatus else { throw ClientError.transportFailed }
        return status
    }

    /// Ask csecd to delete its protected items and decision log. csecd shows
    /// one Touch ID sheet first; a refusal throws `ClientError.denied`.
    public func uninstallCleanup() throws -> UninstallCleanupResult {
        let request = UninstallCleanupRequest()
        let response = try send(.uninstallCleanup(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let result = response.uninstallCleanup,
              result.remainingItems.count <= ProtectedItem.all.count,
              result.remainingFiles.count <= 64 else {
            throw ClientError.transportFailed
        }
        return result
    }

    /// `csec backup …`. Setup, sync, restore and off wait on one Touch ID in
    /// csecd; a refusal throws `ClientError.denied`.
    public func nativeStoreBackup(_ request: NativeStoreBackupRequest) throws -> NativeStoreBackupReply {
        let response = try send(.nativeStoreBackup(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let reply = response.nativeStoreBackup,
              (reply.recoveryKit == nil) == (request.action != .beginSetup) else {
            throw ClientError.transportFailed
        }
        return reply
    }

    /// `csec identity …`. Creating, adding a target, accepting keys and
    /// removing an identity wait on one Touch ID in csecd.
    public func machineIdentity(_ request: MachineIdentityRequest) throws -> MachineIdentityReply {
        let response = try send(.configureMachineIdentity(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let reply = response.machineIdentity else { throw ClientError.transportFailed }
        return reply
    }

    /// `csec edit --remove`. Waits on one Touch ID in csecd; a refusal
    /// throws `ClientError.denied`.
    public func removeNativeValues(_ request: NativeStoreRemovalRequest) throws -> NativeStoreRemovalReply {
        let response = try send(.removeNativeValues(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let reply = response.nativeStoreRemoval,
              Set(reply.removed.map(\.reference)) == Set(request.references) else {
            throw ClientError.transportFailed
        }
        return reply
    }

    public func capabilities() throws -> ProtocolCapabilities {
        let response = try send(.capabilities)
        if let failure = response.failure {
            throw ClientError.protocolFailure(failure.code, failure.message)
        }
        guard let capabilities = response.capabilities else { throw ClientError.transportFailed }
        return capabilities
    }

    public func remoteApprovalStatus() throws -> RemoteApprovalConfigurationStatus {
        try configureRemoteApproval(action: .status).status
    }

    /// The reply's Mac code is checked with the pairing protocol's own decoder,
    /// the one the phone uses, so the launcher and the phone agree on what a
    /// valid code is. csecd has already stored the pairing by the time it
    /// replies, so a code this launcher cannot read says so rather than
    /// reading as a failed transport.
    public func enableRemoteApproval(
        phonePairingCode: String
    ) throws -> (
        status: RemoteApprovalConfigurationStatus,
        macPairingCode: String,
        macPairing: RemoteApprovalMacPairing,
        pairingOfferPublished: Bool
    ) {
        let result = try configureRemoteApproval(
            action: .enable,
            phonePairingCode: phonePairingCode
        )
        guard let code = result.macPairingCode,
              let pairing = try? RemoteApprovalPairingCode.decodeMac(code) else {
            throw ClientError.agentError(
                "csecd paired the phone but replied with a Mac pairing code this csec cannot read, "
                    + "so it cannot be shown; this csec and csecd are from different builds. Install the "
                    + "current Convenient Security package, then run csec remote enable again"
            )
        }
        return (result.status, code, pairing, result.pairingOfferPublished ?? false)
    }

    public func disableRemoteApproval() throws -> RemoteApprovalConfigurationStatus {
        try configureRemoteApproval(action: .disable).status
    }

    private func configureRemoteApproval(
        action: RemoteApprovalConfigurationAction,
        phonePairingCode: String? = nil
    ) throws -> (
        status: RemoteApprovalConfigurationStatus,
        macPairingCode: String?,
        pairingOfferPublished: Bool?
    ) {
        let request = RemoteApprovalConfigurationRequest(
            action: action,
            phonePairingCode: phonePairingCode
        )
        let response = try send(.configureRemoteApproval(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let status = response.remoteApprovalStatus else {
            throw ClientError.transportFailed
        }
        return (
            status,
            response.remoteApprovalMacPairingCode,
            response.remoteApprovalPairingOfferPublished
        )
    }

    /// Register this launcher's current process incarnation as an explicit
    /// session root. The returned UUID is safe to inherit but is never treated
    /// as authority without a matching daemon record and kernel ancestry.
    public func beginSession() throws -> String {
        let request = BeginSessionRequest()
        let response = try send(.beginSession(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let sessionID = response.registeredSessionID,
              UUID(uuidString: sessionID) != nil else {
            throw ClientError.transportFailed
        }
        return sessionID.lowercased()
    }

    /// Begin an exact-caller native-store edit session. The agent performs a
    /// fresh Touch ID check before returning the complete decrypted JSON
    /// document to the authenticated product launcher.
    public func beginNativeStoreEdit(
        store: String,
        mode: NativeStoreEditorMode = .builtInMemory,
        externalEditorPath: String? = nil,
        origin: String? = nil
    ) throws -> NativeStoreEditStart {
        let request = BeginNativeStoreEditRequest(
            store: store,
            mode: mode,
            externalEditorPath: externalEditorPath,
            origin: origin
        )
        let response = try send(.beginNativeStoreEdit(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let sessionID = response.editSessionID,
              UUID(uuidString: sessionID) != nil,
              let document = response.document,
              document.count <= NativeStoreDocument.maximumBytes else {
            throw ClientError.transportFailed
        }
        return NativeStoreEditStart(sessionID: sessionID, document: document)
    }

    public func commitNativeStoreEdit(
        sessionID: String,
        document: Data
    ) throws -> NativeStoreEditCommit {
        let request = CommitNativeStoreEditRequest(
            editSessionID: sessionID,
            document: document
        )
        let response = try send(.commitNativeStoreEdit(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let generation = response.generation,
              generation > 0,
              let secretCount = response.secretCount,
              secretCount >= 0,
              secretCount <= NativeStoreDocument.maximumSecrets else {
            throw ClientError.transportFailed
        }
        return NativeStoreEditCommit(generation: generation, secretCount: secretCount)
    }

    /// Import whole-file values into the file/blob tier of the session's store,
    /// committed against an already-authorized edit session (one consent covers
    /// the batch). Returns the new blob-tier generation and the number imported.
    public func commitNativeStoreBlobs(
        sessionID: String,
        blobs: [ProtectedBlobImport]
    ) throws -> NativeStoreEditCommit {
        let request = CommitNativeStoreBlobsRequest(editSessionID: sessionID, blobs: blobs)
        let response = try send(.commitNativeStoreBlobs(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let generation = response.generation,
              generation > 0,
              let secretCount = response.secretCount,
              secretCount >= 0,
              secretCount == blobs.count else {
            throw ClientError.transportFailed
        }
        return NativeStoreEditCommit(generation: generation, secretCount: secretCount)
    }

    /// One already-reviewed native import plus provider-neutral SSH catalog
    /// registration. Private bytes travel inward in `blobs`; only public key
    /// metadata returns.
    public func commitNativeStoreBlobsAndRegisterSSH(
        sessionID: String,
        blobs: [ProtectedBlobImport],
        registrations: [SSHKeyRegistrationIntent]
    ) throws -> (commit: NativeStoreEditCommit, keys: [SSHKeyMetadata]) {
        let request = CommitNativeStoreBlobsRequest(
            editSessionID: sessionID,
            blobs: blobs,
            sshKeyRegistrations: registrations
        )
        let response = try send(.commitNativeStoreBlobs(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let generation = response.generation,
              generation > 0,
              let secretCount = response.secretCount,
              secretCount == blobs.count,
              let keys = response.sshKeys,
              keys.count == registrations.count else {
            throw ClientError.transportFailed
        }
        return (
            NativeStoreEditCommit(generation: generation, secretCount: secretCount),
            keys
        )
    }

    /// `csec protect --gh`: commit the imported token and register it with
    /// the GitHub proxy, under the one review the edit session already had.
    public func commitNativeStoreBlobAndRegisterGitHubToken(
        sessionID: String,
        blob: ProtectedBlobImport,
        reference: SecretRef
    ) throws -> GitHubProxyStatus {
        let request = CommitNativeStoreBlobsRequest(
            editSessionID: sessionID,
            blobs: [blob],
            githubTokenRegistration: reference.uri
        )
        let response = try send(.commitNativeStoreBlobs(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let generation = response.generation, generation > 0,
              response.secretCount == 1,
              let status = response.github,
              status.tokenReference == reference.uri else {
            throw ClientError.transportFailed
        }
        return status
    }

    public func githubProxyStatus() throws -> GitHubProxyStatus {
        try configureGitHub(GitHubProxyRequest(action: .status))
    }

    public func registerGitHubToken(_ reference: SecretRef) throws -> GitHubProxyStatus {
        try configureGitHub(GitHubProxyRequest(action: .register, reference: reference.uri))
    }

    public func removeGitHubToken() throws -> GitHubProxyStatus {
        try configureGitHub(GitHubProxyRequest(action: .remove))
    }

    private func configureGitHub(_ request: GitHubProxyRequest) throws -> GitHubProxyStatus {
        let response = try send(.configureGitHub(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let status = response.github else { throw ClientError.transportFailed }
        return status
    }

    public func listSSHKeys() throws -> [SSHKeyMetadata] {
        try configureSSH(action: .list).sshKeys ?? []
    }

    public func registerSSHKeys(
        _ registrations: [SSHKeyRegistrationIntent]
    ) throws -> [SSHKeyMetadata] {
        guard !registrations.isEmpty else { throw ClientError.transportFailed }
        return try configureSSH(action: .register, registrations: registrations).sshKeys ?? []
    }

    public func removeSSHKey(fingerprint: String) throws -> [SSHKeyMetadata] {
        try configureSSH(action: .remove, fingerprint: fingerprint).sshKeys ?? []
    }

    public func enrollAutomation(_ enrollment: AutomationEnrollment) throws -> AutomationJob {
        let request = AutomationRequest(action: .enroll, enrollment: enrollment)
        let response = try send(.configureAutomation(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let jobs = response.automationJobs, jobs.count == 1,
              let job = jobs.first, job.isWellFormed else {
            throw ClientError.transportFailed
        }
        return job
    }

    public func listAutomation() throws -> [AutomationJob] {
        let request = AutomationRequest(action: .list)
        let response = try send(.configureAutomation(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let jobs = response.automationJobs,
              jobs.count <= 128,
              jobs.allSatisfy(\.isWellFormed) else {
            throw ClientError.transportFailed
        }
        return jobs
    }

    /// Whether a run authorization's remaining runtime agrees with the job's cap:
    /// both nil for a process-lifetime daemon run, or both present with the
    /// remaining runtime positive, finite, and within the cap.
    private static func runtimeAgrees(_ remaining: TimeInterval?, cap: Int?) -> Bool {
        switch (remaining, cap) {
        case (nil, nil): return true
        case (nil, _?), (_?, nil): return false
        case let (remaining?, cap?):
            return remaining.isFinite && remaining > 0 && remaining <= TimeInterval(cap)
        }
    }

    public func beginAutomationRun(name: String) throws -> AutomationRunDecision {
        let request = AutomationRequest(action: .beginRun, name: name)
        let response = try send(.configureAutomation(request))
        try Self.check(response: response, requestID: request.requestID)
        if let run = response.automationRun,
           UUID(uuidString: run.runID)?.uuidString.lowercased() == run.runID,
           run.job.isWellFormed,
           Self.runtimeAgrees(run.remainingRuntimeSeconds, cap: run.job.maximumRuntimeSeconds) {
            return .started(run)
        }
        if let next = response.automationNextEligibleAt,
           response.automationRun == nil {
            return .skipped(nextEligibleAt: next)
        }
        throw ClientError.transportFailed
    }

    public func finishAutomationRun(runID: String) throws {
        let request = AutomationRequest(action: .finishRun, runID: runID)
        let response = try send(.configureAutomation(request))
        try Self.check(response: response, requestID: request.requestID)
    }

    /// Succeeds only when this csecd holds the caller's live lease for
    /// `runID` (it restored it after a restart) and has registered the values
    /// it releases with the output redactor.
    public func resumeAutomationRun(runID: String) throws {
        let request = AutomationRequest(action: .resumeRun, runID: runID)
        let response = try send(.configureAutomation(request))
        try Self.check(response: response, requestID: request.requestID)
    }

    public func revokeAutomation(name: String) throws -> AutomationJob {
        let request = AutomationRequest(action: .revoke, name: name)
        let response = try send(.configureAutomation(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let jobs = response.automationJobs, jobs.count == 1,
              let job = jobs.first, job.isWellFormed else {
            throw ClientError.transportFailed
        }
        return job
    }

    private func configureSSH(
        action: SSHKeyCatalogAction,
        registrations: [SSHKeyRegistrationIntent] = [],
        fingerprint: String? = nil
    ) throws -> Response {
        let request = SSHKeyCatalogRequest(
            action: action,
            registrations: registrations,
            fingerprint: fingerprint
        )
        let response = try send(.configureSSH(request))
        try Self.check(response: response, requestID: request.requestID)
        guard response.sshKeys != nil else { throw ClientError.transportFailed }
        return response
    }

    public func cancelNativeStoreEdit(sessionID: String) {
        let request = CancelNativeStoreEditRequest(editSessionID: sessionID)
        _ = try? send(.cancelNativeStoreEdit(request))
    }

    /// Ask csecd to run the value-free host posture audit and return the report.
    /// The privileged reads, TCC/FDA enumeration, and any parsing happen inside
    /// csecd; only the value-free `HostAuditReport` crosses back to the launcher.
    public func hostAudit(scanFilesystem: Bool = false) throws -> HostAuditReport {
        let request = HostAuditRequest(scanFilesystem: scanFilesystem)
        let response = try send(.hostAudit(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let report = response.hostAuditReport else {
            throw ClientError.transportFailed
        }
        return report
    }

    /// Begin a *streaming* host audit: csecd runs the engine as a background job
    /// and this launcher polls it for value-free progress snapshots so `csec audit`
    /// can animate the scan. Returns a handle carrying the initial snapshot and an
    /// open, authenticated connection; call `poll()` on it until `snapshot.done`,
    /// then read `report`. Falls back to the blocking `hostAudit` is the caller's
    /// job when this throws (an older csecd that lacks the streaming verbs).
    public func beginHostAudit(scanFilesystem: Bool = false) throws -> HostAuditProgressStream {
        let connection = try AgentConnection(
            path: path, serverTrustPolicy: serverTrustPolicy, liveness: liveness
        )
        let request = HostAuditRequest(scanFilesystem: scanFilesystem)
        let response = try connection.send(.hostAuditStart(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let snapshot = response.hostAuditProgress else {
            throw ClientError.transportFailed
        }
        return HostAuditProgressStream(
            connection: connection,
            jobID: request.requestID,
            initial: snapshot,
            report: response.hostAuditReport
        )
    }

    /// Ask csecd to present the batched remediation review (one Touch ID) and
    /// apply the selected fixes. Returns the value-free applied/skipped/failed
    /// summary; csecd owns the review window and the privileged applies.
    public func hostRemediate(
        selectedKeys: [String] = [],
        scanFilesystem: Bool = false
    ) throws -> HostRemediationSummary {
        let request = HostRemediationRequest(selectedKeys: selectedKeys, scanFilesystem: scanFilesystem)
        let response = try send(.hostRemediate(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let summary = response.hostRemediation else {
            throw ClientError.transportFailed
        }
        return summary
    }

    /// Persist a batch of value-free triage decisions into csecd's accepted
    /// baseline: exemptions (accept-risk, with notes), todos (deferred fixes with
    /// weekly reminders), and cleared (remove from triage). csecd owns the store; a
    /// plain non-failure response confirms the merge.
    public func hostRecordTriage(
        exemptions: [HostTriageDecision] = [],
        todos: [String] = [],
        cleared: [String] = []
    ) throws {
        let request = HostTriageRequest(exemptions: exemptions, todos: todos, cleared: cleared)
        let response = try send(.hostRecordTriage(request))
        try Self.check(response: response, requestID: request.requestID)
    }

    /// Tell csecd to drop any cached resolution for `references`, so the next
    /// resolve re-reads the freshly-rotated value instead of a stale cache hit.
    /// Cache eviction only: it carries no secret material, discloses no value,
    /// and raises no Touch ID. Best-effort by design — the value is already
    /// durably written, so callers must not fail their primary operation if this
    /// throws (e.g. against an older daemon that lacks the verb, or no running
    /// agent at all); at worst a running agent serves the previous value until
    /// its cache entry is invalidated (the cache has no clock).
    public func invalidateCachedReferences(_ references: [String]) throws {
        let request = InvalidateCachedReferencesRequest(references: references)
        let response = try send(.invalidateCachedReferences(request))
        try Self.check(response: response, requestID: request.requestID)
    }

    /// Ask csecd to review/resolve a protected-file launch and send the rendered
    /// bytes directly to csec-rootd. A successful response contains only a
    /// boolean; file plaintext is never decoded by this client process.
    public func approveProtectedLaunch(
        rendezvousNonce: String,
        launchPlan: ProtectedLaunchPlan,
        launchPlanDigest: String
    ) throws {
        let request = try ProtectedLaunchApprovalRequest(
            rendezvousNonce: rendezvousNonce,
            launchPlan: launchPlan,
            launchPlanDigest: launchPlanDigest
        )
        let response = try send(.approveProtectedLaunch(request))
        try Self.check(response: response, requestID: request.requestID)
        guard response.protectedLaunchApproved == true, response.values == nil else {
            throw ClientError.transportFailed
        }
    }

    /// Open one authenticated, persistent connection whose output chunks are
    /// scanned against the agent's active-value registry. Raw registry values
    /// never leave `csecd`; only already-redacted bytes and value-free matches
    /// return to the launcher.
    public func beginOutputRedaction(
        destination: DestinationClass,
        streams: [OutputRedactionStream],
        includeShortValues: Bool = false,
        labelStyle: OutputRedactionLabelStyle = .opaque
    ) throws -> AgentOutputRedactionSession {
        let connection = try AgentConnection(
            path: path, serverTrustPolicy: serverTrustPolicy, liveness: liveness
        )
        let request = BeginOutputRedactionRequest(
            destination: destination,
            streams: streams,
            includeShortValues: includeShortValues,
            labelStyle: labelStyle
        )
        let response = try connection.send(.beginOutputRedaction(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let sessionID = response.outputRedactionSessionID,
              UUID(uuidString: sessionID) != nil,
              let protectedValueCount = response.protectedValueCount,
              let skippedShortValueCount = response.skippedShortValueCount else {
            throw ClientError.transportFailed
        }
        return AgentOutputRedactionSession(
            connection: connection,
            sessionID: sessionID,
            streams: Set(streams),
            protectedValueCount: protectedValueCount,
            skippedShortValueCount: skippedShortValueCount
        )
    }

    /// Mirror one sudo review to the paired phone and wait for its answer, for
    /// the sudo review helper. Blocks until csecd answers or `cancellation`
    /// fires, so the helper runs it on a thread of its own
    /// (`SudoRemoteReviewClient`). Every failure — no csecd, a peer that is not
    /// the product agent, an unresponsive or refusing csecd, a malformed or
    /// mismatched reply, a cancellation — is `.unavailable`: the Mac panel then
    /// decides alone. Cancelling shuts the connection down at once, which ends
    /// a read in progress here and makes csecd's peer-exit watch withdraw the
    /// phone's copy.
    public func sudoRemoteReview(
        _ request: SudoRemoteReviewRequest,
        cancellation: AgentCallCancellation
    ) -> SudoRemoteReviewDecision {
        guard !cancellation.isCancelled else { return .unavailable }
        let connection: AgentConnection
        do {
            connection = try AgentConnection(
                path: path, serverTrustPolicy: serverTrustPolicy, liveness: liveness
            )
        } catch {
            return .unavailable
        }
        guard cancellation.arm({ connection.interrupt() }) else { return .unavailable }
        defer { cancellation.disarm() }
        guard let response = try? connection.send(.sudoRemoteReview(request)),
              response.requestID == request.requestID,
              response.failure == nil, response.error == nil,
              let decision = response.sudoRemoteReview else {
            return .unavailable
        }
        return decision
    }

    /// Ask whether Claude Code auto mode's approval stands in for the sudo
    /// review, for the sudo review helper. Blocks like `sudoRemoteReview`,
    /// and every failure is `.notApplicable`: the panel then shows as ever.
    public func sudoDelegation(
        _ request: SudoDelegationRequest,
        cancellation: AgentCallCancellation
    ) -> SudoDelegationAnswer {
        guard !cancellation.isCancelled else { return .notApplicable }
        let connection: AgentConnection
        do {
            connection = try AgentConnection(
                path: path, serverTrustPolicy: serverTrustPolicy, liveness: liveness
            )
        } catch {
            return .notApplicable
        }
        guard cancellation.arm({ connection.interrupt() }) else { return .notApplicable }
        defer { cancellation.disarm() }
        guard let response = try? connection.send(.sudoDelegation(request)),
              response.requestID == request.requestID,
              response.failure == nil, response.error == nil,
              let answer = response.sudoDelegation, answer.isWellFormed else {
            return .notApplicable
        }
        return answer
    }

    /// Report a Mac approval of a sudo panel that showed csecd's pairing
    /// line, for the sudo review helper. False on any failure: the sudo is
    /// approved either way, and the project is simply not paired.
    public func sudoPairing(_ request: SudoPairingRequest, cancellation: AgentCallCancellation) -> Bool {
        guard !cancellation.isCancelled else { return false }
        let connection: AgentConnection
        do {
            connection = try AgentConnection(
                path: path, serverTrustPolicy: serverTrustPolicy, liveness: liveness
            )
        } catch {
            return false
        }
        guard cancellation.arm({ connection.interrupt() }) else { return false }
        defer { cancellation.disarm() }
        guard let response = try? connection.send(.sudoPairing(request)),
              response.requestID == request.requestID,
              response.failure == nil, response.error == nil else { return false }
        return response.sudoPaired == true
    }

    /// Report how this sudo review helper's review ended, for csecd's
    /// decision log. False on any failure: the sudo's outcome stands either
    /// way, and only the record is missing.
    public func sudoReviewEnd(_ request: SudoReviewEndRequest, cancellation: AgentCallCancellation) -> Bool {
        guard !cancellation.isCancelled else { return false }
        let connection: AgentConnection
        do {
            connection = try AgentConnection(
                path: path, serverTrustPolicy: serverTrustPolicy, liveness: liveness
            )
        } catch {
            return false
        }
        guard cancellation.arm({ connection.interrupt() }) else { return false }
        defer { cancellation.disarm() }
        guard let response = try? connection.send(.sudoReviewEnd(request)),
              response.requestID == request.requestID,
              response.failure == nil, response.error == nil else { return false }
        return response.sudoReviewEnded == true
    }

    /// Ask csecd which terminal tab this sudo review helper's sudo came from.
    /// Nil on any failure: the panel then names the PAM tty alone.
    public func sudoTerminal(
        _ request: SudoTerminalRequest,
        cancellation: AgentCallCancellation
    ) -> TerminalSessionContext? {
        guard !cancellation.isCancelled else { return nil }
        let connection: AgentConnection
        do {
            connection = try AgentConnection(
                path: path, serverTrustPolicy: serverTrustPolicy, liveness: liveness
            )
        } catch {
            return nil
        }
        guard cancellation.arm({ connection.interrupt() }) else { return nil }
        defer { cancellation.disarm() }
        guard let response = try? connection.send(.sudoTerminal(request)),
              response.requestID == request.requestID,
              response.failure == nil, response.error == nil else { return nil }
        return response.sudoTerminal
    }

    private func send(_ request: Request) throws -> Response {
        try AgentConnection(
            path: path, serverTrustPolicy: serverTrustPolicy, liveness: liveness
        ).send(request)
    }

    /// A setup notice as csec prints it: sanitized and within
    /// `DelegationDecline.maximumSetupNoticeBytes`, or nil when empty.
    static func boundedNotice(_ notice: String) -> String? {
        let shown = ReviewDisplay.bounded(ReviewDisplay.sanitized(notice), maxBytes: DelegationDecline.maximumSetupNoticeBytes)
        return shown.isEmpty ? nil : shown
    }

    fileprivate static func check(response: Response, requestID: String) throws {
        guard response.requestID == requestID else {
            throw ClientError.agentError("agent response nonce mismatch")
        }
        if let failure = response.failure {
            if failure.code == .consentDenied { throw ClientError.denied(failure.message) }
            throw ClientError.protocolFailure(failure.code, failure.message)
        }
        if let error = response.error { throw ClientError.agentError(error) }
    }
}

fileprivate final class AgentConnection {
    private let fd: Int32
    private let liveness: AgentLiveness
    /// The csecd process this connection reached, by PID and start time, so a
    /// broken connection can be told apart from csecd having exited.
    let serverPID: pid_t
    let serverStartTime: UInt64

    init(path: String, serverTrustPolicy: AgentServerTrustPolicy, liveness: AgentLiveness) throws {
        self.liveness = liveness
        // Bounded connect: a wedged daemon that never calls accept() fills its
        // listen backlog, after which a blocking connect() waits forever.
        let (fd, connectionErrno) = path.withCString {
            let fd = cs_connect_unix_timeout(
                $0, Int32(clamping: Int(liveness.connectDeadline * 1000))
            )
            return (fd, errno)
        }
        guard fd >= 0 else {
            if connectionErrno == EPERM || connectionErrno == EACCES {
                throw AgentClient.ClientError.connectPermissionDenied(path)
            }
            if connectionErrno == ETIMEDOUT {
                throw AgentClient.ClientError.daemonUnresponsive(
                    seconds: Int(liveness.connectDeadline.rounded())
                )
            }
            throw AgentClient.ClientError.connectFailed(path)
        }

        guard let server = PeerIdentity.socketPeer(fd: fd) else {
            close(fd)
            throw AgentClient.ClientError.untrustedServer("the kernel peer identity was unavailable")
        }
        guard server.isCurrentUser else {
            close(fd)
            throw AgentClient.ClientError.untrustedServer("the socket peer belongs to another uid")
        }
        guard serverTrustPolicy.accepts(server) else {
            // Do not reflect attacker-controlled code-signing metadata into a
            // terminal/log error; the diagnostic remains value-free.
            close(fd)
            throw AgentClient.ClientError.untrustedServer(
                "the socket peer has an unexpected code identity; an agent still running after an update may need restarting — run csec doctor")
        }
        self.fd = fd
        serverPID = server.audit.pid
        serverStartTime = server.audit.startTime
    }

    /// Whether the csecd this connection reached is no longer running: its PID
    /// is gone or now belongs to a later process. A process that has exited
    /// but not yet been reaped still reads as running, so this waits up to
    /// `bound` for it to go.
    func serverHasExited(within bound: TimeInterval) -> Bool {
        let deadline = Date().addingTimeInterval(bound)
        while true {
            if ProcessAncestry.startTime(of: serverPID) != serverStartTime { return true }
            if Date() >= deadline { return false }
            usleep(50_000)
        }
    }

    deinit { close(fd) }

    /// End this connection from another thread while `send` may be blocked on
    /// it: a read or write in progress returns at once, and the server sees
    /// the close. `shutdown` rather than `close`: the descriptor stays
    /// allocated until `deinit`, so a concurrent `send` can never reach a
    /// descriptor number that was reused.
    func interrupt() {
        _ = shutdown(fd, SHUT_RDWR)
    }

    /// `supportsHeartbeats: false` makes the silence deadline a bound on the
    /// whole wait: the server then never heartbeats this request, and a
    /// heartbeat that arrives anyway is refused rather than let restart the
    /// clock. Only a request that never waits on a human may opt out.
    ///
    /// `onNotice`, when set, declares that this client reads notice frames
    /// (`WireTransport.noticeType`) and receives each one; without it the
    /// server sends none, and one that arrives anyway is refused.
    func send(
        _ request: Request,
        supportsHeartbeats: Bool = true,
        onNotice: ((String) -> Void)? = nil
    ) throws -> Response {
        // Server authentication happens before references or other request
        // metadata are serialized onto the connection. The envelope normally
        // declares that this client can read heartbeat frames, which is what
        // makes the silence deadline below safe to arm: a request blocked on a
        // human keeps ticking, so only a daemon that has stopped running the
        // request altogether can trip it.
        let encoded = try WireTransport.encodeRequest(
            request, supportsHeartbeats: supportsHeartbeats, supportsNotices: onNotice != nil
        )
        switch writeFrame(fd, encoded, silence: liveness.writeDeadline) {
        case .written:
            break
        case .timedOut:
            throw AgentClient.ClientError.daemonUnresponsive(
                seconds: Int(liveness.writeDeadline.rounded())
            )
        case .failed:
            throw AgentClient.ClientError.connectionLost("agent request write failed")
        }

        // Read until the real response. A heartbeat only restarts the clock; it
        // never satisfies the request, so an hour-long human wait is fine as
        // long as the daemon keeps proving it is alive.
        while true {
            switch readFrame(fd, silence: liveness.silenceDeadline) {
            case .timedOut:
                throw AgentClient.ClientError.daemonUnresponsive(
                    seconds: Int(liveness.silenceDeadline.rounded())
                )
            case .closed:
                throw AgentClient.ClientError.connectionLost("agent response unavailable")
            case let .frame(data):
                if WireTransport.isHeartbeat(data) {
                    guard supportsHeartbeats else {
                        throw AgentClient.ClientError.agentError("agent sent a heartbeat that was not requested")
                    }
                    continue
                }
                if let notice = WireTransport.notice(in: data) {
                    guard let onNotice else {
                        throw AgentClient.ClientError.agentError("agent sent a notice that was not requested")
                    }
                    if !notice.isEmpty { onNotice(notice) }
                    continue
                }
                let response = try JSONDecoder().decode(Response.self, from: data)
                guard response.version == WireProtocol.version else {
                    throw AgentClient.ClientError.protocolFailure(
                        .upgradeRequired, "unsupported agent protocol version"
                    )
                }
                return response
            }
        }
    }
}

/// Caller-facing handle for a daemon-side streaming matcher. One instance is
/// deliberately single-threaded: the process supervisor serializes reads from
/// its stdout/stderr/PTY poll loop onto this authenticated connection.
public final class AgentOutputRedactionSession {
    private let connection: AgentConnection
    fileprivate let sessionID: String
    private let streams: Set<OutputRedactionStream>
    private var finishedStreams = Set<OutputRedactionStream>()
    private var isClosed = false

    public let protectedValueCount: Int
    public let skippedShortValueCount: Int

    fileprivate init(
        connection: AgentConnection,
        sessionID: String,
        streams: Set<OutputRedactionStream>,
        protectedValueCount: Int,
        skippedShortValueCount: Int
    ) {
        self.connection = connection
        self.sessionID = sessionID
        self.streams = streams
        self.protectedValueCount = protectedValueCount
        self.skippedShortValueCount = skippedShortValueCount
    }

    deinit { close() }

    public func process(_ data: Data, stream: OutputRedactionStream) throws -> OutputRedactionResult {
        try exchange(data: data, stream: stream, finish: false)
    }

    public func finish(stream: OutputRedactionStream) throws -> OutputRedactionResult {
        try exchange(data: Data(), stream: stream, finish: true)
    }

    /// Feeds `data` to the matcher without returning any of it: the output
    /// that preceded this session's start, so a value that began before a
    /// csecd restart is still matched when the rest of it arrives.
    public func prime(_ data: Data, stream: OutputRedactionStream) throws {
        var offset = data.startIndex
        while offset < data.endIndex {
            let end = min(offset + 16 * 1_024, data.endIndex)
            _ = try exchange(data: data.subdata(in: offset..<end), stream: stream, finish: false, prime: true)
            offset = end
        }
    }

    /// Whether the csecd running this session has exited (or restarted, which
    /// is the same thing to the session: its matcher lived only in that
    /// process). It waits up to `bound` for an exited csecd to be reaped.
    public func agentHasExited(within bound: TimeInterval = 2) -> Bool {
        connection.serverHasExited(within: bound)
    }

    /// Ends the session. Returns csecd's setup notice for this `csec ai`
    /// (`Response.delegationNotice`), when the end reached csecd and it had
    /// one; a second close returns nil.
    @discardableResult
    public func close() -> String? {
        guard !isClosed else { return nil }
        isClosed = true
        let request = EndOutputRedactionRequest(sessionID: sessionID)
        guard let response = try? connection.send(.endOutputRedaction(request)),
              response.requestID == request.requestID else { return nil }
        return response.delegationNotice.flatMap(AgentClient.boundedNotice)
    }

    private func exchange(
        data: Data,
        stream: OutputRedactionStream,
        finish: Bool,
        prime: Bool = false
    ) throws -> OutputRedactionResult {
        guard !isClosed,
              streams.contains(stream),
              !finishedStreams.contains(stream) else {
            throw AgentClient.ClientError.transportFailed
        }
        let request = RedactOutputChunkRequest(
            sessionID: sessionID,
            stream: stream,
            data: data,
            finish: finish,
            prime: prime ? true : nil
        )
        let response = try connection.send(.redactOutputChunk(request))
        try AgentClient.check(response: response, requestID: request.requestID)
        guard let redactedData = response.redactedData,
              let matches = response.redactionMatches else {
            throw AgentClient.ClientError.agentError("agent returned an incomplete redaction response")
        }
        if finish { finishedStreams.insert(stream) }
        return OutputRedactionResult(data: redactedData, matches: matches)
    }
}

/// The notices of requests started under a `csec ai` that wait on a human
/// and could not say so themselves (an `ssh`, a bridge client), each returned
/// once (`take_approval_notices`). It asks on a connection of its own, never
/// the output-redaction session's: a poll that fails or stalls must cost the
/// command its notices, never its scanner.
public final class ApprovalNoticeChannel {
    private let connection: AgentConnection
    private let sessionID: String

    fileprivate init(connection: AgentConnection, sessionID: String) {
        self.connection = connection
        self.sessionID = sessionID
    }

    public func take() throws -> [String] {
        let request = TakeApprovalNoticesRequest(sessionID: sessionID)
        let response = try connection.send(.takeApprovalNotices(request))
        try AgentClient.check(response: response, requestID: request.requestID)
        guard let notices = response.approvalNotices, notices.count <= HumanWaitBoard.maximumEntries else {
            throw AgentClient.ClientError.transportFailed
        }
        return notices.map {
            ReviewDisplay.fitted($0, maxBytes: WireTransport.maximumNoticeBytes)
        }.filter { !$0.isEmpty }
    }
}

extension AgentClient {
    /// Opens the channel a `csec ai` asks for its session's approval notices
    /// on. csecd answers only the process that opened `session`.
    public func approvalNoticeChannel(for session: AgentOutputRedactionSession) throws -> ApprovalNoticeChannel {
        ApprovalNoticeChannel(
            connection: try AgentConnection(path: path, serverTrustPolicy: serverTrustPolicy, liveness: liveness),
            sessionID: session.sessionID
        )
    }
}

/// Caller-facing handle for a streaming host audit. `poll()` fetches the next
/// value-free progress snapshot over the persistent authenticated connection;
/// once `isDone`, `report` holds the finished value-free report. Deliberately
/// single-threaded — the launcher's render loop drives it at its own cadence.
public final class HostAuditProgressStream {
    private let connection: AgentConnection
    private let jobID: String
    public private(set) var snapshot: HostAuditProgressSnapshot
    public private(set) var report: HostAuditReport?

    fileprivate init(
        connection: AgentConnection,
        jobID: String,
        initial: HostAuditProgressSnapshot,
        report: HostAuditReport?
    ) {
        self.connection = connection
        self.jobID = jobID
        self.snapshot = initial
        self.report = report
    }

    /// True once the audit has finished and its report is available.
    public var isDone: Bool { snapshot.done && report != nil }

    /// Fetch the next progress snapshot. Idempotent once done — it returns the
    /// final snapshot without another round-trip (the server has retired the job).
    @discardableResult
    public func poll() throws -> HostAuditProgressSnapshot {
        if isDone { return snapshot }
        let request = HostAuditPollRequest(jobID: jobID)
        let response = try connection.send(.hostAuditPoll(request))
        try AgentClient.check(response: response, requestID: request.requestID)
        guard let next = response.hostAuditProgress else {
            throw AgentClient.ClientError.transportFailed
        }
        snapshot = next
        if let report = response.hostAuditReport { self.report = report }
        return next
    }
}

/// Everything `csec grants` lists.
public struct GrantListing: Sendable, Equatable {
    /// Live secret and SSH grants.
    public let grants: [GrantSummary]
    /// Pairings, trusted builds and acknowledged hooks; nil while delegated
    /// approvals are off.
    public let delegation: DelegationGrantsListing?

    public init(grants: [GrantSummary], delegation: DelegationGrantsListing?) {
        self.grants = grants
        self.delegation = delegation
    }
}

/// What revoking an id did.
public enum GrantRevocationOutcome: Sendable, Equatable {
    /// `count` entries removed, none when the id matched nothing. `removed`
    /// lists them; a csecd without delegated approvals reports only the count,
    /// and `removed` is then empty.
    case revoked(count: Int, removed: [RevocableEntry])
    /// The id matched more than one entry of its kind, so nothing was removed.
    case ambiguous([RevocableEntry])
}

/// What a `configure_delegation` request did.
public enum DelegationConfigurationOutcome: Sendable, Equatable {
    /// The state after the action, and for `untrust_build` / `forget_hook`
    /// what was removed (none when the id matched nothing).
    case configured(DelegationStatus, removed: [RevocableEntry])
    /// An `untrust_build` / `forget_hook` id matched more than one entry, so
    /// nothing changed.
    case ambiguous([RevocableEntry])
}

extension AgentLiveness {
    /// The bounds of `csec hook claude`'s registration round trip, which sits
    /// in front of every Claude Code Bash call. csecd answers it in
    /// milliseconds without touching a secret, so a daemon that has not
    /// accepted within 250 ms or answered within a second is treated as absent:
    /// the command simply is not delegated. Fixed, whatever the debug liveness
    /// override says.
    public static let agentCommandRegistration = AgentLiveness(
        heartbeatInterval: 5,
        silenceDeadline: 1,
        connectDeadline: 0.25,
        writeDeadline: 0.25
    )

    /// The bound on the whole registration, the check of csecd's signature
    /// included. That check waits on trustd, which serves every process on the
    /// Mac and can stall for minutes behind something else; without this bound
    /// the hook ran into Claude Code's 30 s hook timeout, after which Claude
    /// Code runs the command without csec's wrapper. The phases above add up to
    /// 1.5 s and the check normally takes milliseconds (about 0.1 s at worst
    /// under heavy load), so 2 s cuts off only a stall.
    public static let agentCommandRegistrationDeadline: TimeInterval = 2
}

/// Cancels one blocking agent call from any thread. Cancelling before the call
/// connects makes it return without sending anything; cancelling while it waits
/// interrupts its connection (`AgentConnection.interrupt`). Idempotent.
public final class AgentCallCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    private var interrupt: (() -> Void)?

    public init() {}

    public var isCancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return cancelled
    }

    public func cancel() {
        lock.lock()
        cancelled = true
        let action = interrupt
        interrupt = nil
        lock.unlock()
        // Outside the lock: the action holds the connection, so its descriptor
        // is still open while it is shut down.
        action?()
    }

    /// Register what cancelling interrupts. False when already cancelled: the
    /// caller must not go on to send.
    fileprivate func arm(_ action: @escaping () -> Void) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled else { return false }
        interrupt = action
        return true
    }

    /// The call is over: a later cancel has nothing left to interrupt.
    fileprivate func disarm() {
        lock.lock()
        interrupt = nil
        lock.unlock()
    }
}

/// The answer of a registration running on a thread of its own, which the
/// caller waits for only up to a deadline.
private final class RegistrationOutcome: @unchecked Sendable {
    private let lock = NSLock()
    private let finished = DispatchSemaphore(value: 0)
    private var registered = false

    func finish(_ value: Bool) {
        lock.lock()
        registered = value
        lock.unlock()
        finished.signal()
    }

    /// The answer, or nil when it did not come within `seconds`.
    func wait(seconds: TimeInterval) -> Bool? {
        guard finished.wait(timeout: .now() + seconds) == .success else { return nil }
        lock.lock()
        defer { lock.unlock() }
        return registered
    }
}

/// Reciprocal socket trust used by Swift clients. The testing case is explicit
/// construction only; the shipping launcher always uses the product-agent case.
public enum AgentServerTrustPolicy: Sendable {
    case requireProductAgent
    case allowUnverifiedForTesting
    /// `allowUnverifiedForTesting` once `check` returns: a stand-in for a
    /// check of csecd's signature that takes as long as `check` does.
    case slowUnverifiedForTesting(@Sendable () -> Void)

    fileprivate func accepts(_ peer: PeerIdentity) -> Bool {
        switch self {
        case .requireProductAgent:
            return peer.code.signatureValid && peer.code.role == .agent
        case .allowUnverifiedForTesting:
            return true
        case let .slowUnverifiedForTesting(check):
            check()
            return true
        }
    }
}
