import Foundation

/// Length-prefixed JSON protocol negotiated over the authenticated local socket.
public enum WireProtocol {
    public static let version = 2
    public static let supportedVersions = [2]
}

public enum WireCapability: String, Codable, Sendable, CaseIterable {
    case typedFailures = "typed_failures"
    case deliveryPlans = "delivery_plans"
    case peerCodeIdentity = "peer_code_identity"
    case planDigestBinding = "plan_digest_binding"
    case outputGuardBinding = "output_guard_binding"
    case activeOutputRedaction = "active_output_redaction"
}

public struct ProtocolCapabilities: Codable, Sendable, Equatable {
    public let supportedVersions: [Int]
    public let features: [WireCapability]

    public init(
        supportedVersions: [Int] = WireProtocol.supportedVersions,
        features: [WireCapability] = WireCapability.allCases
    ) {
        self.supportedVersions = supportedVersions
        self.features = features
    }
}

/// Stable machine-readable failures. Messages are deliberately value-free and
/// may be shown to a human; clients must branch on `code`, not message text.
public enum WireErrorCode: String, Codable, Sendable {
    case upgradeRequired = "upgrade_required"
    case unverifiedPeer = "unverified_peer"
    case policyDenied = "policy_denied"
    case deliveryNotSupported = "delivery_not_supported"
    case invalidRequest = "invalid_request"
    case consentDenied = "consent_denied"
    case providerUnavailable = "provider_unavailable"
    case resolutionFailed = "resolution_failed"
    case internalError = "internal_error"
}

public struct ProtocolFailure: Codable, Sendable, Equatable {
    public let code: WireErrorCode
    public let message: String

    public init(_ code: WireErrorCode, message: String) {
        self.code = code
        self.message = message
    }
}

/// `access` payload. Protocol v2 binds a unique request ID to a complete,
/// canonical delivery-plan digest. A missing v2 field is never inferred.
public struct AccessRequest: Codable, Sendable {
    public let protocolVersion: Int
    public let requestID: String?
    public let references: [String]
    public let reason: String
    public let ttlSeconds: Int
    public let deliveryPlan: DeliveryPlan?
    public let deliveryPlanDigest: String?

    public var isLegacy: Bool { protocolVersion < 2 }

    public init(
        references: [String],
        reason: String,
        ttlSeconds: Int,
        deliveryPlan: DeliveryPlan,
        requestID: UUID = UUID()
    ) throws {
        self.protocolVersion = WireProtocol.version
        self.requestID = requestID.uuidString.lowercased()
        self.references = references
        self.reason = reason
        self.ttlSeconds = ttlSeconds
        self.deliveryPlan = deliveryPlan
        self.deliveryPlanDigest = try deliveryPlan.digest()
    }

    /// Decoder-only initializer for the migration window. The production agent
    /// rejects this shape; fake agents can opt in for old client tests.
    static func legacy(references: [String], reason: String, ttlSeconds: Int) -> AccessRequest {
        AccessRequest(
            protocolVersion: 1,
            requestID: nil,
            references: references,
            reason: reason,
            ttlSeconds: ttlSeconds,
            deliveryPlan: nil,
            deliveryPlanDigest: nil
        )
    }

    fileprivate init(
        protocolVersion: Int,
        requestID: String?,
        references: [String],
        reason: String,
        ttlSeconds: Int,
        deliveryPlan: DeliveryPlan?,
        deliveryPlanDigest: String?
    ) {
        self.protocolVersion = protocolVersion
        self.requestID = requestID
        self.references = references
        self.reason = reason
        self.ttlSeconds = ttlSeconds
        self.deliveryPlan = deliveryPlan
        self.deliveryPlanDigest = deliveryPlanDigest
    }
}

/// Logical channels are kept separate so a prefix on stdout cannot be joined to
/// a suffix on stderr. A PTY combines terminal output before it reaches this
/// protocol and therefore uses one `terminal` stream.
public enum OutputRedactionStream: String, Codable, Sendable, Hashable, CaseIterable {
    case stdout
    case stderr
    case terminal
}

/// Open a short-lived, caller-bound scanner in the trusted agent. The scanner
/// is intentionally destination-specific; the first implementation permits
/// only output that is about to be returned to an AI tool.
public struct BeginOutputRedactionRequest: Codable, Sendable {
    public let requestID: String
    public let destination: DestinationClass
    public let streams: [OutputRedactionStream]

    public init(
        destination: DestinationClass,
        streams: [OutputRedactionStream],
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.destination = destination
        self.streams = streams
    }
}

/// One bounded piece of child output. Matching state remains inside `csecd`, so
/// active plaintext values are never returned as a dictionary to the launcher.
public struct RedactOutputChunkRequest: Codable, Sendable {
    public let requestID: String
    public let sessionID: String
    public let stream: OutputRedactionStream
    public let data: Data
    public let finish: Bool

    public init(
        sessionID: String,
        stream: OutputRedactionStream,
        data: Data,
        finish: Bool = false,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.sessionID = sessionID
        self.stream = stream
        self.data = data
        self.finish = finish
    }
}

public struct EndOutputRedactionRequest: Codable, Sendable {
    public let requestID: String
    public let sessionID: String

    public init(sessionID: String, requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
        self.sessionID = sessionID
    }
}

/// Requests retain the v1 flat discriminator so an upgraded agent can return a
/// typed migration error instead of misinterpreting an old access as secure.
public enum Request: Sendable {
    case access(AccessRequest)
    case schemes
    case capabilities
    case beginOutputRedaction(BeginOutputRedactionRequest)
    case redactOutputChunk(RedactOutputChunkRequest)
    case endOutputRedaction(EndOutputRedactionRequest)
}

extension Request: Codable {
    private enum CodingKeys: String, CodingKey {
        case version, type, requestID, references, reason, ttlSeconds
        case deliveryPlan, deliveryPlanDigest
        case destination, streams, sessionID, stream, data, finish
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "access":
            let version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 1
            let references = try container.decode([String].self, forKey: .references)
            let reason = try container.decode(String.self, forKey: .reason)
            let ttl = try container.decode(Int.self, forKey: .ttlSeconds)
            if version >= 2 {
                self = .access(AccessRequest(
                    protocolVersion: version,
                    requestID: try container.decodeIfPresent(String.self, forKey: .requestID),
                    references: references,
                    reason: reason,
                    ttlSeconds: ttl,
                    deliveryPlan: try container.decodeIfPresent(DeliveryPlan.self, forKey: .deliveryPlan),
                    deliveryPlanDigest: try container.decodeIfPresent(String.self, forKey: .deliveryPlanDigest)
                ))
            } else {
                self = .access(.legacy(references: references, reason: reason, ttlSeconds: ttl))
            }
        case "schemes":
            self = .schemes
        case "capabilities":
            self = .capabilities
        case "begin_output_redaction":
            self = .beginOutputRedaction(BeginOutputRedactionRequest(
                destination: try container.decode(DestinationClass.self, forKey: .destination),
                streams: try container.decode([OutputRedactionStream].self, forKey: .streams),
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "redact_output_chunk":
            self = .redactOutputChunk(RedactOutputChunkRequest(
                sessionID: try container.decode(String.self, forKey: .sessionID),
                stream: try container.decode(OutputRedactionStream.self, forKey: .stream),
                data: try container.decode(Data.self, forKey: .data),
                finish: try container.decodeIfPresent(Bool.self, forKey: .finish) ?? false,
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "end_output_redaction":
            self = .endOutputRedaction(EndOutputRedactionRequest(
                sessionID: try container.decode(String.self, forKey: .sessionID),
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .type, in: container, debugDescription: "unknown request type"
            )
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case let .access(request):
            try container.encode("access", forKey: .type)
            try container.encode(request.protocolVersion, forKey: .version)
            try container.encodeIfPresent(request.requestID, forKey: .requestID)
            try container.encode(request.references, forKey: .references)
            try container.encode(request.reason, forKey: .reason)
            try container.encode(request.ttlSeconds, forKey: .ttlSeconds)
            try container.encodeIfPresent(request.deliveryPlan, forKey: .deliveryPlan)
            try container.encodeIfPresent(request.deliveryPlanDigest, forKey: .deliveryPlanDigest)
        case .schemes:
            try container.encode("schemes", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
        case .capabilities:
            try container.encode("capabilities", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
        case let .beginOutputRedaction(request):
            try container.encode("begin_output_redaction", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.destination, forKey: .destination)
            try container.encode(request.streams, forKey: .streams)
        case let .redactOutputChunk(request):
            try container.encode("redact_output_chunk", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.sessionID, forKey: .sessionID)
            try container.encode(request.stream, forKey: .stream)
            try container.encode(request.data, forKey: .data)
            try container.encode(request.finish, forKey: .finish)
        case let .endOutputRedaction(request):
            try container.encode("end_output_redaction", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.sessionID, forKey: .sessionID)
        }
    }

    private static func decodeUUID(
        _ container: KeyedDecodingContainer<CodingKeys>,
        forKey key: CodingKeys
    ) throws -> UUID {
        let value = try container.decode(String.self, forKey: key)
        guard let uuid = UUID(uuidString: value) else {
            throw DecodingError.dataCorruptedError(
                forKey: key, in: container, debugDescription: "invalid request UUID"
            )
        }
        return uuid
    }
}

/// Unified response. `error` exists only so a v2 client can give a useful error
/// while talking to an old fake/test agent; production v2 failures use `failure`.
public struct Response: Codable, Sendable {
    public let version: Int
    public let requestID: String?
    public let values: [String: String]?
    public let schemes: [String]?
    public let capabilities: ProtocolCapabilities?
    public let outputRedactionSessionID: String?
    public let redactedData: Data?
    public let redactionMatches: [OutputRedactionMatch]?
    public let protectedValueCount: Int?
    public let skippedShortValueCount: Int?
    public let failure: ProtocolFailure?
    public let error: String?

    public init(
        version: Int = WireProtocol.version,
        requestID: String? = nil,
        values: [String: String]? = nil,
        schemes: [String]? = nil,
        capabilities: ProtocolCapabilities? = nil,
        outputRedactionSessionID: String? = nil,
        redactedData: Data? = nil,
        redactionMatches: [OutputRedactionMatch]? = nil,
        protectedValueCount: Int? = nil,
        skippedShortValueCount: Int? = nil,
        failure: ProtocolFailure? = nil,
        error: String? = nil
    ) {
        self.version = version
        self.requestID = requestID
        self.values = values
        self.schemes = schemes
        self.capabilities = capabilities
        self.outputRedactionSessionID = outputRedactionSessionID
        self.redactedData = redactedData
        self.redactionMatches = redactionMatches
        self.protectedValueCount = protectedValueCount
        self.skippedShortValueCount = skippedShortValueCount
        self.failure = failure
        self.error = error
    }

    public static func failed(
        _ code: WireErrorCode,
        message: String,
        requestID: String? = nil
    ) -> Response {
        Response(requestID: requestID, failure: ProtocolFailure(code, message: message))
    }
}
