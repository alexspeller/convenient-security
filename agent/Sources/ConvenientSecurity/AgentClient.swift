import Foundation
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

    public init(
        path: String,
        serverTrustPolicy: AgentServerTrustPolicy = .requireProductAgent
    ) {
        self.path = path
        self.serverTrustPolicy = serverTrustPolicy
    }

    public enum ClientError: Error, LocalizedError {
        case connectFailed(String)
        case untrustedServer(String)
        case transportFailed
        case denied(String)
        case protocolFailure(WireErrorCode, String)
        case agentError(String)

        public var errorDescription: String? {
            switch self {
            case let .connectFailed(path):
                return "cannot reach agent at \(path)"
            case let .untrustedServer(reason):
                return "refusing untrusted agent: \(reason)"
            case .transportFailed:
                return "agent transport failed"
            case .denied:
                return "consent denied"
            case let .protocolFailure(code, message):
                return "\(code.rawValue): \(message)"
            case let .agentError(message):
                return message
            }
        }
    }

    /// Request one or more references; returns ref → value bytes on approval.
    public func access(
        references: [String],
        reason: String,
        ttlSeconds: Int,
        deliveryPlan: DeliveryPlan? = nil
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
            deliveryPlan: plan
        )
        let response = try send(.access(request))
        guard response.requestID == request.requestID else {
            throw ClientError.transportFailed
        }
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

    public func capabilities() throws -> ProtocolCapabilities {
        let response = try send(.capabilities)
        if let failure = response.failure {
            throw ClientError.protocolFailure(failure.code, failure.message)
        }
        guard let capabilities = response.capabilities else { throw ClientError.transportFailed }
        return capabilities
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
        externalEditorPath: String? = nil
    ) throws -> NativeStoreEditStart {
        let request = BeginNativeStoreEditRequest(
            store: store,
            mode: mode,
            externalEditorPath: externalEditorPath
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

    public func cancelNativeStoreEdit(sessionID: String) {
        let request = CancelNativeStoreEditRequest(editSessionID: sessionID)
        _ = try? send(.cancelNativeStoreEdit(request))
    }

    public func risk(
        _ operation: RiskOperation,
        reference: String,
        level: RiskLevel? = nil
    ) throws -> RiskInspection {
        let request = RiskOperationRequest(
            operation: operation,
            reference: reference,
            level: level
        )
        let response = try send(.risk(request))
        try Self.check(response: response, requestID: request.requestID)
        guard let inspection = response.riskInspection else {
            throw ClientError.transportFailed
        }
        return inspection
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
        let connection = try AgentConnection(path: path, serverTrustPolicy: serverTrustPolicy)
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
        includeShortValues: Bool = false
    ) throws -> AgentOutputRedactionSession {
        let connection = try AgentConnection(path: path, serverTrustPolicy: serverTrustPolicy)
        let request = BeginOutputRedactionRequest(
            destination: destination,
            streams: streams,
            includeShortValues: includeShortValues
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

    private func send(_ request: Request) throws -> Response {
        try AgentConnection(path: path, serverTrustPolicy: serverTrustPolicy).send(request)
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

    init(path: String, serverTrustPolicy: AgentServerTrustPolicy) throws {
        let fd = path.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { throw AgentClient.ClientError.connectFailed(path) }

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
            throw AgentClient.ClientError.untrustedServer("the socket peer has an unexpected code identity")
        }
        self.fd = fd
    }

    deinit { close(fd) }

    func send(_ request: Request) throws -> Response {
        // Server authentication happens before references or other request
        // metadata are serialized onto the connection.
        let encoded = try JSONEncoder().encode(request)
        guard writeFrame(fd, encoded) else {
            throw AgentClient.ClientError.agentError("agent request write failed")
        }

        guard let data = readFrame(fd) else {
            throw AgentClient.ClientError.agentError("agent response unavailable")
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

/// Caller-facing handle for a daemon-side streaming matcher. One instance is
/// deliberately single-threaded: the process supervisor serializes reads from
/// its stdout/stderr/PTY poll loop onto this authenticated connection.
public final class AgentOutputRedactionSession {
    private let connection: AgentConnection
    private let sessionID: String
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

    public func close() {
        guard !isClosed else { return }
        isClosed = true
        let request = EndOutputRedactionRequest(sessionID: sessionID)
        _ = try? connection.send(.endOutputRedaction(request))
    }

    private func exchange(
        data: Data,
        stream: OutputRedactionStream,
        finish: Bool
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
            finish: finish
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

/// Reciprocal socket trust used by Swift clients. The testing case is explicit
/// construction only; the shipping launcher always uses the product-agent case.
public enum AgentServerTrustPolicy: Sendable {
    case requireProductAgent
    case allowUnverifiedForTesting

    fileprivate func accepts(_ peer: PeerIdentity) -> Bool {
        switch self {
        case .requireProductAgent:
            return peer.code.signatureValid && peer.code.role == .agent
        case .allowUnverifiedForTesting:
            return true
        }
    }
}
