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
    case nativeEncryptedStore = "native_encrypted_store"
    case nativeEditorPolicy = "native_editor_policy"
    case registeredSessionRoots = "registered_session_roots"
    case credentialProtocols = "credential_protocols"
    case inheritedFileDescriptors = "inherited_file_descriptors"
    case protectedRegularFiles = "protected_regular_files"
    case remoteApprovals = "remote_approvals"
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
    case nativeStoreUnavailable = "native_store_unavailable"
    case invalidStoreDocument = "invalid_store_document"
    case editSessionExpired = "edit_session_expired"
    case editConflict = "edit_conflict"
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

/// Register the authenticated launcher's current PID/start-time as a deliberate
/// broad session root. The response identifier contains no authority by itself;
/// every later access is checked against live kernel ancestry.
public struct BeginSessionRequest: Codable, Sendable {
    public let requestID: String

    public init(requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
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
/// is intentionally destination-specific: it permits AI-tool output and the
/// explicit local-development supervision used by protected-file launches.
public struct BeginOutputRedactionRequest: Codable, Sendable {
    public let requestID: String
    public let destination: DestinationClass
    public let streams: [OutputRedactionStream]
    public let includeShortValues: Bool
    public let labelStyle: OutputRedactionLabelStyle

    public init(
        destination: DestinationClass,
        streams: [OutputRedactionStream],
        includeShortValues: Bool = false,
        labelStyle: OutputRedactionLabelStyle = .opaque,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.destination = destination
        self.streams = streams
        self.includeShortValues = includeShortValues
        self.labelStyle = labelStyle
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

public enum NativeStoreEditorMode: String, Codable, Sendable, CaseIterable {
    case builtInMemory = "built_in_memory"
    case onboardingImport = "onboarding_import"
    case externalTemporaryFile = "external_temporary_file"
}

public struct BeginNativeStoreEditRequest: Codable, Sendable {
    public let requestID: String
    public let store: String
    public let mode: NativeStoreEditorMode
    public let externalEditorPath: String?

    public init(
        store: String,
        mode: NativeStoreEditorMode = .builtInMemory,
        externalEditorPath: String? = nil,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.store = store
        self.mode = mode
        self.externalEditorPath = externalEditorPath
    }
}

public struct CommitNativeStoreEditRequest: Codable, Sendable {
    public let requestID: String
    public let editSessionID: String
    public let document: Data

    public init(editSessionID: String, document: Data, requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
        self.editSessionID = editSessionID
        self.document = document
    }
}

public struct CancelNativeStoreEditRequest: Codable, Sendable {
    public let requestID: String
    public let editSessionID: String

    public init(editSessionID: String, requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
        self.editSessionID = editSessionID
    }
}

/// One whole-file value bound for the store's file/blob tier: the value bytes,
/// the intended POSIX mode of the materialized file, and the project-relative
/// path the importer recorded. Never returned to a caller; only sent inward.
public struct ProtectedBlobImport: Codable, Sendable, Equatable {
    public let key: String
    public let data: Data
    public let mode: UInt16
    public let path: String

    public init(key: String, data: Data, mode: UInt16, path: String) {
        self.key = key
        self.data = data
        self.mode = mode
        self.path = path
    }
}

/// Import a batch of whole-file values into the file/blob tier, committed against
/// an already-authorized native-store edit session (one consent covers the batch).
public struct CommitNativeStoreBlobsRequest: Codable, Sendable {
    public let requestID: String
    public let editSessionID: String
    public let blobs: [ProtectedBlobImport]

    public init(editSessionID: String, blobs: [ProtectedBlobImport], requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
        self.editSessionID = editSessionID
        self.blobs = blobs
    }
}

public enum RemoteApprovalConfigurationAction: String, Codable, Sendable {
    case status
    case enable
    case disable
}

/// Local, authenticated launcher request for the explicit remote-approval
/// opt-in. Pairing codes contain public device identity and P-256 keys only.
public struct RemoteApprovalConfigurationRequest: Codable, Sendable {
    public let requestID: String
    public let action: RemoteApprovalConfigurationAction
    public let phonePairingCode: String?

    public init(
        action: RemoteApprovalConfigurationAction,
        phonePairingCode: String? = nil,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.action = action
        self.phonePairingCode = phonePairingCode
    }
}

public enum RemoteApprovalConfigurationState: String, Codable, Sendable {
    case disabled
    case enabled
    case unavailable
}

public struct RemoteApprovalConfigurationStatus: Codable, Equatable, Sendable {
    public let state: RemoteApprovalConfigurationState
    public let phoneName: String?
    public let phoneKeyFingerprint: String?

    public init(
        state: RemoteApprovalConfigurationState,
        phoneName: String? = nil,
        phoneKeyFingerprint: String? = nil
    ) {
        self.state = state
        self.phoneName = phoneName
        self.phoneKeyFingerprint = phoneKeyFingerprint
    }
}

/// Requests retain the v1 flat discriminator so an upgraded agent can return a
/// typed migration error instead of misinterpreting an old access as secure.
public enum Request: Sendable {
    case access(AccessRequest)
    case schemes
    case capabilities
    case beginSession(BeginSessionRequest)
    case beginOutputRedaction(BeginOutputRedactionRequest)
    case redactOutputChunk(RedactOutputChunkRequest)
    case endOutputRedaction(EndOutputRedactionRequest)
    case beginNativeStoreEdit(BeginNativeStoreEditRequest)
    case commitNativeStoreEdit(CommitNativeStoreEditRequest)
    case commitNativeStoreBlobs(CommitNativeStoreBlobsRequest)
    case cancelNativeStoreEdit(CancelNativeStoreEditRequest)
    case approveProtectedLaunch(ProtectedLaunchApprovalRequest)
    case hostAudit(HostAuditRequest)
    case hostAuditStart(HostAuditRequest)
    case hostAuditPoll(HostAuditPollRequest)
    case hostRemediate(HostRemediationRequest)
    case hostRecordTriage(HostTriageRequest)
    case configureRemoteApproval(RemoteApprovalConfigurationRequest)
}

extension Request: Codable {
    private enum CodingKeys: String, CodingKey {
        case version, type, requestID, references, reason, ttlSeconds
        case deliveryPlan, deliveryPlanDigest
        case destination, streams, includeShortValues, labelStyle, sessionID, stream, data, finish
        case store, editSessionID, document, mode, externalEditorPath, blobs
        case protectedLaunchApproval
        case scanFilesystem, selectedKeys, jobID
        case exemptions, todos, cleared
        case action, phonePairingCode
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
        case "begin_session":
            self = .beginSession(BeginSessionRequest(
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "begin_output_redaction":
            self = .beginOutputRedaction(BeginOutputRedactionRequest(
                destination: try container.decode(DestinationClass.self, forKey: .destination),
                streams: try container.decode([OutputRedactionStream].self, forKey: .streams),
                includeShortValues: try container.decodeIfPresent(
                    Bool.self,
                    forKey: .includeShortValues
                ) ?? false,
                labelStyle: try container.decodeIfPresent(
                    OutputRedactionLabelStyle.self,
                    forKey: .labelStyle
                ) ?? .opaque,
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
        case "begin_native_store_edit":
            self = .beginNativeStoreEdit(BeginNativeStoreEditRequest(
                store: try container.decode(String.self, forKey: .store),
                mode: try container.decodeIfPresent(
                    NativeStoreEditorMode.self,
                    forKey: .mode
                ) ?? .builtInMemory,
                externalEditorPath: try container.decodeIfPresent(
                    String.self,
                    forKey: .externalEditorPath
                ),
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "commit_native_store_edit":
            self = .commitNativeStoreEdit(CommitNativeStoreEditRequest(
                editSessionID: try container.decode(String.self, forKey: .editSessionID),
                document: try container.decode(Data.self, forKey: .document),
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "commit_native_store_blobs":
            self = .commitNativeStoreBlobs(CommitNativeStoreBlobsRequest(
                editSessionID: try container.decode(String.self, forKey: .editSessionID),
                blobs: try container.decode([ProtectedBlobImport].self, forKey: .blobs),
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "cancel_native_store_edit":
            self = .cancelNativeStoreEdit(CancelNativeStoreEditRequest(
                editSessionID: try container.decode(String.self, forKey: .editSessionID),
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "approve_protected_launch":
            let approval = try container.decode(
                ProtectedLaunchApprovalRequest.self,
                forKey: .protectedLaunchApproval
            )
            guard try Self.decodeUUID(container, forKey: .requestID).uuidString.lowercased()
                    == approval.requestID else {
                throw DecodingError.dataCorruptedError(
                    forKey: .requestID,
                    in: container,
                    debugDescription: "protected launch request UUID mismatch"
                )
            }
            self = .approveProtectedLaunch(approval)
        case "host_audit":
            self = .hostAudit(HostAuditRequest(
                scanFilesystem: try container.decodeIfPresent(Bool.self, forKey: .scanFilesystem) ?? false,
                requestUUID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "host_audit_start":
            self = .hostAuditStart(HostAuditRequest(
                scanFilesystem: try container.decodeIfPresent(Bool.self, forKey: .scanFilesystem) ?? false,
                requestUUID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "host_audit_poll":
            self = .hostAuditPoll(HostAuditPollRequest(
                jobID: try container.decode(String.self, forKey: .jobID),
                requestUUID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "host_remediate":
            self = .hostRemediate(HostRemediationRequest(
                selectedKeys: try container.decodeIfPresent([String].self, forKey: .selectedKeys) ?? [],
                scanFilesystem: try container.decodeIfPresent(Bool.self, forKey: .scanFilesystem) ?? false,
                requestUUID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "host_record_triage":
            self = .hostRecordTriage(HostTriageRequest(
                exemptions: try container.decodeIfPresent([HostTriageDecision].self, forKey: .exemptions) ?? [],
                todos: try container.decodeIfPresent([String].self, forKey: .todos) ?? [],
                cleared: try container.decodeIfPresent([String].self, forKey: .cleared) ?? [],
                requestUUID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "configure_remote_approval":
            let action = try container.decode(
                RemoteApprovalConfigurationAction.self,
                forKey: .action
            )
            let phonePairingCode = try container.decodeIfPresent(
                String.self,
                forKey: .phonePairingCode
            )
            guard phonePairingCode?.utf8.count ?? 0 <= 16 * 1_024,
                  (action == .enable) == (phonePairingCode != nil) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .phonePairingCode,
                    in: container,
                    debugDescription: "invalid remote approval configuration"
                )
            }
            self = .configureRemoteApproval(RemoteApprovalConfigurationRequest(
                action: action,
                phonePairingCode: phonePairingCode,
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
        case let .beginSession(request):
            try container.encode("begin_session", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
        case let .beginOutputRedaction(request):
            try container.encode("begin_output_redaction", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.destination, forKey: .destination)
            try container.encode(request.streams, forKey: .streams)
            try container.encode(request.includeShortValues, forKey: .includeShortValues)
            try container.encode(request.labelStyle, forKey: .labelStyle)
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
        case let .beginNativeStoreEdit(request):
            try container.encode("begin_native_store_edit", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.store, forKey: .store)
            try container.encode(request.mode, forKey: .mode)
            try container.encodeIfPresent(request.externalEditorPath, forKey: .externalEditorPath)
        case let .commitNativeStoreEdit(request):
            try container.encode("commit_native_store_edit", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.editSessionID, forKey: .editSessionID)
            try container.encode(request.document, forKey: .document)
        case let .commitNativeStoreBlobs(request):
            try container.encode("commit_native_store_blobs", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.editSessionID, forKey: .editSessionID)
            try container.encode(request.blobs, forKey: .blobs)
        case let .cancelNativeStoreEdit(request):
            try container.encode("cancel_native_store_edit", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.editSessionID, forKey: .editSessionID)
        case let .approveProtectedLaunch(request):
            try container.encode("approve_protected_launch", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request, forKey: .protectedLaunchApproval)
        case let .hostAudit(request):
            try container.encode("host_audit", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.scanFilesystem, forKey: .scanFilesystem)
        case let .hostAuditStart(request):
            try container.encode("host_audit_start", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.scanFilesystem, forKey: .scanFilesystem)
        case let .hostAuditPoll(request):
            try container.encode("host_audit_poll", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.jobID, forKey: .jobID)
        case let .hostRemediate(request):
            try container.encode("host_remediate", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.selectedKeys, forKey: .selectedKeys)
            try container.encode(request.scanFilesystem, forKey: .scanFilesystem)
        case let .hostRecordTriage(request):
            try container.encode("host_record_triage", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.exemptions, forKey: .exemptions)
            try container.encode(request.todos, forKey: .todos)
            try container.encode(request.cleared, forKey: .cleared)
        case let .configureRemoteApproval(request):
            try container.encode("configure_remote_approval", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.action, forKey: .action)
            try container.encodeIfPresent(
                request.phonePairingCode,
                forKey: .phonePairingCode
            )
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
    /// Resolved values keyed by canonical reference URI. Bytes, not strings: a
    /// value is bytes (a token or a whole binary file), base64-encoded on the
    /// wire by `Data`'s own `Codable`. Delivery converts to a text environment
    /// value only at the injection boundary, where UTF-8/no-NUL is required.
    public let values: [String: Data]?
    public let schemes: [String]?
    public let capabilities: ProtocolCapabilities?
    public let registeredSessionID: String?
    public let outputRedactionSessionID: String?
    public let redactedData: Data?
    public let redactionMatches: [OutputRedactionMatch]?
    public let protectedValueCount: Int?
    public let skippedShortValueCount: Int?
    public let editSessionID: String?
    public let document: Data?
    public let generation: UInt64?
    public let secretCount: Int?
    public let protectedLaunchApproved: Bool?
    public let accessExpiresAt: Date?
    public let hostAuditReport: HostAuditReport?
    public let hostAuditProgress: HostAuditProgressSnapshot?
    public let hostRemediation: HostRemediationSummary?
    public let remoteApprovalStatus: RemoteApprovalConfigurationStatus?
    public let remoteApprovalMacPairingCode: String?
    public let failure: ProtocolFailure?
    public let error: String?

    public init(
        version: Int = WireProtocol.version,
        requestID: String? = nil,
        values: [String: Data]? = nil,
        schemes: [String]? = nil,
        capabilities: ProtocolCapabilities? = nil,
        registeredSessionID: String? = nil,
        outputRedactionSessionID: String? = nil,
        redactedData: Data? = nil,
        redactionMatches: [OutputRedactionMatch]? = nil,
        protectedValueCount: Int? = nil,
        skippedShortValueCount: Int? = nil,
        editSessionID: String? = nil,
        document: Data? = nil,
        generation: UInt64? = nil,
        secretCount: Int? = nil,
        protectedLaunchApproved: Bool? = nil,
        accessExpiresAt: Date? = nil,
        hostAuditReport: HostAuditReport? = nil,
        hostAuditProgress: HostAuditProgressSnapshot? = nil,
        hostRemediation: HostRemediationSummary? = nil,
        remoteApprovalStatus: RemoteApprovalConfigurationStatus? = nil,
        remoteApprovalMacPairingCode: String? = nil,
        failure: ProtocolFailure? = nil,
        error: String? = nil
    ) {
        self.version = version
        self.requestID = requestID
        self.values = values
        self.schemes = schemes
        self.capabilities = capabilities
        self.registeredSessionID = registeredSessionID
        self.outputRedactionSessionID = outputRedactionSessionID
        self.redactedData = redactedData
        self.redactionMatches = redactionMatches
        self.protectedValueCount = protectedValueCount
        self.skippedShortValueCount = skippedShortValueCount
        self.editSessionID = editSessionID
        self.document = document
        self.generation = generation
        self.secretCount = secretCount
        self.protectedLaunchApproved = protectedLaunchApproved
        self.accessExpiresAt = accessExpiresAt
        self.hostAuditReport = hostAuditReport
        self.hostAuditProgress = hostAuditProgress
        self.hostRemediation = hostRemediation
        self.remoteApprovalStatus = remoteApprovalStatus
        self.remoteApprovalMacPairingCode = remoteApprovalMacPairingCode
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
