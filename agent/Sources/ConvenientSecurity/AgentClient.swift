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

    /// Request one or more references; returns ref → value on approval.
    public func access(
        references: [String],
        reason: String,
        ttlSeconds: Int,
        deliveryPlan: DeliveryPlan? = nil
    ) throws -> [String: String] {
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

    /// Open one authenticated, persistent connection whose output chunks are
    /// scanned against the agent's active-value registry. Raw registry values
    /// never leave `csecd`; only already-redacted bytes and value-free matches
    /// return to the launcher.
    public func beginOutputRedaction(
        destination: DestinationClass,
        streams: [OutputRedactionStream]
    ) throws -> AgentOutputRedactionSession {
        let connection = try AgentConnection(path: path, serverTrustPolicy: serverTrustPolicy)
        let request = BeginOutputRedactionRequest(destination: destination, streams: streams)
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
