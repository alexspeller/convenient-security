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
    case unattendedAutomation = "unattended_automation"
    case selectableGrantScopes = "selectable_grant_scopes"
    case grantRevocation = "grant_revocation"
    /// The server emits a periodic liveness frame while it is handling a request
    /// from a client that opted in, so the client can bound the daemon's silence
    /// without bounding a wait on a human.
    case livenessHeartbeats = "liveness_heartbeats"
    /// The server understands `register_agent_command` and
    /// `configure_delegation`, and lists and revokes the delegation kinds
    /// (`pair-`, `build-`, `hook-`) through `grants`.
    case delegatedApprovals = "delegated_approvals"
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
    /// A reference its provider already knows cannot resolve (no such key,
    /// store or scheme), refused before any review. Retrying cannot succeed
    /// until the reference or the store changes.
    case referenceNotFound = "reference_not_found"
    case nativeStoreUnavailable = "native_store_unavailable"
    case sshAgentUnavailable = "ssh_agent_unavailable"
    case githubProxyUnavailable = "github_proxy_unavailable"
    case invalidSSHKey = "invalid_ssh_key"
    case automationUnavailable = "automation_unavailable"
    case automationAlreadyRunning = "automation_already_running"
    case automationRunExpired = "automation_run_expired"
    case automationRunInvalidated = "automation_run_invalidated"
    case invalidStoreDocument = "invalid_store_document"
    case editConflict = "edit_conflict"
    case storeOriginConflict = "store_origin_conflict"
    case decisionLogUnavailable = "decision_log_unavailable"
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
    /// Requested wall-clock grant lifetime in seconds, or nil for the default
    /// process-lifetime grant. Must equal the bound plan's `requestedTTLSeconds`.
    public let ttlSeconds: Int?
    public let deliveryPlan: DeliveryPlan?
    public let deliveryPlanDigest: String?
    /// The launcher's exact argv, display-only. The review window shows it in
    /// full (passed through csecd's standard output redaction so a value the
    /// agent already released can never be echoed back on screen). When the plan
    /// carries a `commandDigest`, csecd requires this argv to hash to it, so the
    /// command a human reads is the one the grant is keyed on.
    public let commandLine: [String]?
    /// Set only by csecd, on the use of the GitHub token it builds for a
    /// request that can give lasting access (`GitHubLastingAccess`). It is
    /// never encoded or decoded, so no client can send or strip it.
    public internal(set) var githubLastingAccess: GitHubLastingAccess?

    private enum CodingKeys: String, CodingKey {
        case protocolVersion, requestID, references, reason, ttlSeconds,
             deliveryPlan, deliveryPlanDigest, commandLine
    }

    /// The most arguments and the most total argv bytes csecd will accept for
    /// display. Both sit at what `execve` itself allows, so any command that can
    /// run can be shown; the window bounds what it renders separately.
    public static let maximumCommandLineArguments = 65_536
    public static let maximumCommandLineBytes = 1_048_576

    public var isLegacy: Bool { protocolVersion < 2 }

    public init(
        references: [String],
        reason: String,
        ttlSeconds: Int? = nil,
        deliveryPlan: DeliveryPlan,
        commandLine: [String]? = nil,
        requestID: UUID = UUID()
    ) throws {
        self.protocolVersion = WireProtocol.version
        self.requestID = requestID.uuidString.lowercased()
        self.references = references
        self.reason = reason
        self.ttlSeconds = ttlSeconds
        self.deliveryPlan = deliveryPlan
        self.deliveryPlanDigest = try deliveryPlan.digest()
        self.commandLine = commandLine
    }

    /// Whether the optional argv is absent or within the accepted bounds and,
    /// when the plan binds a command digest, hashes to exactly that digest.
    public var hasValidCommandLine: Bool {
        guard let commandLine else { return true }
        guard commandLine.count <= Self.maximumCommandLineArguments else { return false }
        var total = 0
        for argument in commandLine {
            guard !argument.utf8.contains(0) else { return false }
            total += argument.utf8.count
            guard total <= Self.maximumCommandLineBytes else { return false }
        }
        if let digest = deliveryPlan?.commandDigest {
            return (try? ExecutableInspection.commandDigest(commandLine)) == digest
        }
        return true
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
        ttlSeconds: Int?,
        deliveryPlan: DeliveryPlan?,
        deliveryPlanDigest: String?,
        commandLine: [String]? = nil
    ) {
        self.protocolVersion = protocolVersion
        self.requestID = requestID
        self.references = references
        self.reason = reason
        self.ttlSeconds = ttlSeconds
        self.deliveryPlan = deliveryPlan
        self.deliveryPlanDigest = deliveryPlanDigest
        self.commandLine = commandLine
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

/// Ask csecd to reopen its existing eligible approvals after a restart.
/// The daemon selects the whole batch; the caller supplies no references,
/// delivery plan or new authority, and receives no credential material.
public struct RestoreApprovalsRequest: Sendable {
    public let requestID: String

    public init(requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
    }
}

public enum RestorationStatus: String, Codable, Sendable, CaseIterable {
    case reopened
    case forgotten
    case notNeeded = "not_needed"
    case alreadyRestored = "already_restored"
}

/// What `restore_approvals` fetched ahead from providers that need no csec
/// unlock (`SecretResolver.fetchAhead`): counts and, for each reference that
/// could not be fetched, its provider's value-free reason. Never a value.
public struct FetchAheadSummary: Codable, Sendable, Equatable {
    public static let maximumFailures = 32
    public static let maximumReasonBytes = 256

    public struct Failure: Codable, Sendable, Equatable {
        public let reference: String
        public let reason: String

        public init(reference: String, reason: String) {
            self.reference = reference
            self.reason = reason
        }
    }

    /// Values fetched now and held for later releases.
    public let fetched: Int
    /// Values a delegated release can already serve, so they were not fetched.
    public let alreadyHeld: Int
    /// How many could not be fetched; `failures` lists at most
    /// `maximumFailures` of them.
    public let failureCount: Int
    public let failures: [Failure]

    public init(fetched: Int, alreadyHeld: Int, failures: [Failure]) {
        self.fetched = fetched
        self.alreadyHeld = alreadyHeld
        self.failureCount = failures.count
        self.failures = failures.prefix(Self.maximumFailures).map {
            Failure(reference: $0.reference, reason: ReviewDisplay.fitted($0.reason, maxBytes: Self.maximumReasonBytes))
        }
    }

    /// A reply is within bounds: what a client checks before printing it.
    public var isBounded: Bool {
        fetched >= 0 && alreadyHeld >= 0 && failureCount >= failures.count
            && failures.count <= Self.maximumFailures
            && failures.allSatisfy { $0.reason.utf8.count <= Self.maximumReasonBytes && (try? SecretRef($0.reference)) != nil }
    }
}

/// `SecretResolver.fetchAhead`'s result inside csecd: the bounded summary a
/// reply carries, and each distinct failure reason counted over every failure,
/// not only the `maximumFailures` the summary lists, for the decision log.
public struct FetchAheadReport: Sendable, Equatable {
    public struct ReasonCount: Sendable, Equatable {
        public let reason: String
        public let count: Int
    }

    public let summary: FetchAheadSummary
    /// In order of first appearance.
    public let reasonCounts: [ReasonCount]

    public init(summary: FetchAheadSummary, failures: [FetchAheadSummary.Failure]) {
        self.summary = summary
        var counts: [String: Int] = [:]
        var order: [String] = []
        for failure in failures {
            // Fitted as the summary fits it, so one reason never counts twice.
            let reason = ReviewDisplay.fitted(failure.reason, maxBytes: FetchAheadSummary.maximumReasonBytes)
            if counts[reason] == nil { order.append(reason) }
            counts[reason, default: 0] += 1
        }
        reasonCounts = order.map { ReasonCount(reason: $0, count: counts[$0] ?? 0) }
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

/// Open a process-bound scanner in the trusted agent, retained until explicitly
/// closed or its owning process exits. The scanner
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
    /// Scan `data` only to set the matcher's state, and return nothing. A
    /// launcher whose scanner was lost with a csecd restart primes the new
    /// session with the output that came just before, so a value split
    /// across the restart is still matched whole; csecd emits no byte of it.
    /// Absent (an older launcher) means false.
    public let prime: Bool?

    public init(
        sessionID: String,
        stream: OutputRedactionStream,
        data: Data,
        finish: Bool = false,
        prime: Bool? = nil,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.sessionID = sessionID
        self.stream = stream
        self.data = data
        self.finish = finish
        self.prime = prime
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

/// `take_approval_notices`: a `csec ai` asks, on its output-redaction
/// connection while its command runs, for the notices of requests started
/// under it that wait on a human and could not say so themselves
/// (`HumanWaitBoard`): an `ssh`, a language client over `csec bridge`.
public struct TakeApprovalNoticesRequest: Codable, Sendable {
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
    case sshKeyImport = "ssh_key_import"
    case githubTokenImport = "github_token_import"
    case externalTemporaryFile = "external_temporary_file"
}

public struct BeginNativeStoreEditRequest: Codable, Sendable {
    public let requestID: String
    public let store: String
    public let mode: NativeStoreEditorMode
    public let externalEditorPath: String?
    /// The canonical project root the store name was default-resolved from, or
    /// nil for explicit `--store` overrides and direct references. When set,
    /// the daemon stamps it as the store's origin marker on creation/adoption
    /// and refuses the edit if an existing marker names a different root.
    public let origin: String?

    public init(
        store: String,
        mode: NativeStoreEditorMode = .builtInMemory,
        externalEditorPath: String? = nil,
        origin: String? = nil,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.store = store
        self.mode = mode
        self.externalEditorPath = externalEditorPath
        self.origin = origin
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
    /// Canonical provider-neutral references to register after this already-
    /// authorized import. Non-empty only for explicit `csec protect --ssh`.
    public let sshKeyRegistrations: [SSHKeyRegistrationIntent]
    /// The canonical reference of the one imported blob to register as the
    /// GitHub proxy's token. Set only for `csec protect --gh`.
    public let githubTokenRegistration: String?

    public init(
        editSessionID: String,
        blobs: [ProtectedBlobImport],
        sshKeyRegistrations: [SSHKeyRegistrationIntent] = [],
        githubTokenRegistration: String? = nil,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.editSessionID = editSessionID
        self.blobs = blobs
        self.sshKeyRegistrations = sshKeyRegistrations
        self.githubTokenRegistration = githubTokenRegistration
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

/// Why remote approval is `unavailable`, as a bounded, value-free code.
public enum RemoteApprovalUnavailableCause: String, Codable, Sendable, CaseIterable {
    /// csecd lacks the CloudKit container entitlement.
    case unsupportedBuild = "unsupported_build"
    /// A phone is paired but this Mac's iCloud account cannot carry requests.
    case iCloudAccountUnavailable = "icloud_account_unavailable"
    /// The pairing record exists but cannot be used.
    case pairingInvalid = "pairing_invalid"
    /// The Keychain refused to read the pairing record just now.
    case keychainUnavailable = "keychain_unavailable"
}

/// The condition behind a cause: the iCloud account class for
/// `iCloudAccountUnavailable`, what is wrong with the record for
/// `pairingInvalid`.
public enum RemoteApprovalUnavailableDetail: String, Codable, Sendable, CaseIterable {
    case noAccount = "no_account"
    case restricted
    case couldNotDetermine = "could_not_determine"
    case temporarilyUnavailable = "temporarily_unavailable"
    case recordCorrupt = "record_corrupt"
    case containerMismatch = "container_mismatch"
    case macKeyMissing = "mac_key_missing"
    case macKeyMismatch = "mac_key_mismatch"
    /// A pairing an older csec made, before the phone's key-agreement key was
    /// pinned.
    case outdated
}

public struct RemoteApprovalConfigurationStatus: Codable, Equatable, Sendable {
    public let state: RemoteApprovalConfigurationState
    /// Present while a phone is paired: `enabled`, or unavailable because of
    /// this Mac's iCloud account.
    public let phoneName: String?
    public let phoneKeyFingerprint: String?
    /// Why the state is `unavailable`. Nil from a csecd that predates causes,
    /// and for a code this client does not know.
    public let cause: RemoteApprovalUnavailableCause?
    public let detail: RemoteApprovalUnavailableDetail?
    /// The Keychain `OSStatus` behind `keychainUnavailable`.
    public let keychainStatus: Int32?
    /// Whether the paired phone has published a signed confirmation of this
    /// pairing. Nil when there is no usable pairing, or from an older csecd.
    public let phoneConfirmed: Bool?
    /// From the phone's latest signed status record, when csecd has one.
    public let phoneAppVersion: String?
    public let phoneNotificationsAuthorized: Bool?
    /// Whether a request raises an alert on the phone, from the same record.
    public let phoneRequestAlerts: RemoteApprovalPhoneAlertCondition?
    /// Whether the phone-held unlock factor is enrolled for this pairing.
    public let remoteUnlockEnrolled: Bool?
    /// The protocol the phone app reported, and when it last reported
    /// (milliseconds since 1970, by the phone's clock).
    public let phoneProtocolVersion: Int?
    public let phoneStatusUpdatedAtMilliseconds: UInt64?
    /// Whether that record says the app shows settings reviews (the Claude
    /// Code hooks- and rules-changed acknowledgement), which reach the phone
    /// only then. Nil both from an older csecd and when there is no record,
    /// so this client reads `phoneSettingsReviews`; csecd still sends it for
    /// an older one.
    public let phoneShowsSettingsReviews: Bool?
    /// The same, said explicitly in every state, so that a csecd's silence
    /// never reads as a yes: `notReported` from one that predates the field.
    public let phoneSettingsReviews: RemoteApprovalPhoneSettingsReviews
    /// The remote-approval protocol this csecd speaks, which the phone's must
    /// match. Nil from an older csecd.
    public let macProtocolVersion: Int?

    public init(
        state: RemoteApprovalConfigurationState,
        phoneName: String? = nil,
        phoneKeyFingerprint: String? = nil,
        cause: RemoteApprovalUnavailableCause? = nil,
        detail: RemoteApprovalUnavailableDetail? = nil,
        keychainStatus: Int32? = nil,
        phoneConfirmed: Bool? = nil,
        phoneAppVersion: String? = nil,
        phoneNotificationsAuthorized: Bool? = nil,
        phoneRequestAlerts: RemoteApprovalPhoneAlertCondition? = nil,
        remoteUnlockEnrolled: Bool? = nil,
        phoneProtocolVersion: Int? = nil,
        phoneStatusUpdatedAtMilliseconds: UInt64? = nil,
        phoneShowsSettingsReviews: Bool? = nil,
        phoneSettingsReviews: RemoteApprovalPhoneSettingsReviews = .notReported,
        macProtocolVersion: Int? = nil
    ) {
        self.state = state
        self.phoneName = phoneName
        self.phoneKeyFingerprint = phoneKeyFingerprint
        self.cause = cause
        self.detail = detail
        self.keychainStatus = keychainStatus
        self.phoneConfirmed = phoneConfirmed
        self.phoneAppVersion = phoneAppVersion
        self.phoneNotificationsAuthorized = phoneNotificationsAuthorized
        self.phoneRequestAlerts = phoneRequestAlerts
        self.remoteUnlockEnrolled = remoteUnlockEnrolled
        self.phoneProtocolVersion = phoneProtocolVersion
        self.phoneStatusUpdatedAtMilliseconds = phoneStatusUpdatedAtMilliseconds
        self.phoneShowsSettingsReviews = phoneShowsSettingsReviews
        self.phoneSettingsReviews = phoneSettingsReviews
        self.macProtocolVersion = macProtocolVersion
    }

    private enum CodingKeys: String, CodingKey {
        case state, phoneName, phoneKeyFingerprint, cause, detail, keychainStatus
        case phoneConfirmed, phoneAppVersion, phoneNotificationsAuthorized, phoneRequestAlerts
        case remoteUnlockEnrolled, phoneProtocolVersion, phoneStatusUpdatedAtMilliseconds
        case phoneShowsSettingsReviews, phoneSettingsReviews, macProtocolVersion
    }

    /// Each field only when it says something. `notReported` is the
    /// readiness field's absence, so a status built without csecd's facts
    /// encodes as an older csecd's does and decodes back the same.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(state, forKey: .state)
        try container.encodeIfPresent(phoneName, forKey: .phoneName)
        try container.encodeIfPresent(phoneKeyFingerprint, forKey: .phoneKeyFingerprint)
        try container.encodeIfPresent(cause, forKey: .cause)
        try container.encodeIfPresent(detail, forKey: .detail)
        try container.encodeIfPresent(keychainStatus, forKey: .keychainStatus)
        try container.encodeIfPresent(phoneConfirmed, forKey: .phoneConfirmed)
        try container.encodeIfPresent(phoneAppVersion, forKey: .phoneAppVersion)
        try container.encodeIfPresent(phoneNotificationsAuthorized, forKey: .phoneNotificationsAuthorized)
        try container.encodeIfPresent(phoneRequestAlerts, forKey: .phoneRequestAlerts)
        try container.encodeIfPresent(remoteUnlockEnrolled, forKey: .remoteUnlockEnrolled)
        try container.encodeIfPresent(phoneProtocolVersion, forKey: .phoneProtocolVersion)
        try container.encodeIfPresent(phoneStatusUpdatedAtMilliseconds, forKey: .phoneStatusUpdatedAtMilliseconds)
        try container.encodeIfPresent(phoneShowsSettingsReviews, forKey: .phoneShowsSettingsReviews)
        if phoneSettingsReviews != .notReported {
            try container.encode(phoneSettingsReviews, forKey: .phoneSettingsReviews)
        }
        try container.encodeIfPresent(macProtocolVersion, forKey: .macProtocolVersion)
    }

    /// A cause or detail this client does not know reads as absent rather
    /// than failing the whole response: the state alone still says whether
    /// remote approval runs.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        state = try container.decode(RemoteApprovalConfigurationState.self, forKey: .state)
        phoneName = try container.decodeIfPresent(String.self, forKey: .phoneName)
        phoneKeyFingerprint = try container.decodeIfPresent(String.self, forKey: .phoneKeyFingerprint)
        cause = (try? container.decodeIfPresent(String.self, forKey: .cause))
            .flatMap(RemoteApprovalUnavailableCause.init(rawValue:))
        detail = (try? container.decodeIfPresent(String.self, forKey: .detail))
            .flatMap(RemoteApprovalUnavailableDetail.init(rawValue:))
        keychainStatus = try? container.decodeIfPresent(Int32.self, forKey: .keychainStatus)
        phoneConfirmed = try? container.decodeIfPresent(Bool.self, forKey: .phoneConfirmed)
        phoneAppVersion = (try? container.decodeIfPresent(String.self, forKey: .phoneAppVersion))
            .flatMap { $0.utf8.count <= 64 ? $0 : nil }
        phoneNotificationsAuthorized = try? container.decodeIfPresent(
            Bool.self, forKey: .phoneNotificationsAuthorized
        )
        phoneRequestAlerts = (try? container.decodeIfPresent(String.self, forKey: .phoneRequestAlerts))
            .flatMap(RemoteApprovalPhoneAlertCondition.init(rawValue:))
        remoteUnlockEnrolled = try? container.decodeIfPresent(Bool.self, forKey: .remoteUnlockEnrolled)
        phoneProtocolVersion = try? container.decodeIfPresent(Int.self, forKey: .phoneProtocolVersion)
        phoneStatusUpdatedAtMilliseconds = try? container.decodeIfPresent(
            UInt64.self, forKey: .phoneStatusUpdatedAtMilliseconds
        )
        phoneShowsSettingsReviews = try? container.decodeIfPresent(Bool.self, forKey: .phoneShowsSettingsReviews)
        phoneSettingsReviews = (try? container.decodeIfPresent(String.self, forKey: .phoneSettingsReviews))
            .flatMap(RemoteApprovalPhoneSettingsReviews.init(rawValue:)) ?? .notReported
        macProtocolVersion = try? container.decodeIfPresent(Int.self, forKey: .macProtocolVersion)
    }
}

/// Whether the paired phone shows settings reviews (the Claude Code hooks-
/// and rules-changed acknowledgement), which csecd offers it only when it
/// does (`RemoteApprovalManager.remoteSettingsReadiness`). Only `shown` is a
/// yes.
public enum RemoteApprovalPhoneSettingsReviews: String, Codable, Equatable, Sendable, CaseIterable {
    /// The phone's latest status, verified against the pinned phone's key,
    /// lists them.
    case shown
    /// That status does not: an app that predates them, or one that has not
    /// signed a status since it was updated.
    case notShown = "not_shown"
    /// csecd has verified no status from the phone, or has no usable pairing.
    case noPhoneStatus = "no_phone_status"
    /// The csecd that answered did not say: it predates the field, or sent a
    /// value this client does not know. csecd never sends it.
    case notReported = "not_reported"

    /// csecd's reading of the phone's facts (`RemoteApprovalPairingHealth`).
    public init(phoneShows shows: Bool?) {
        switch shows {
        case true?: self = .shown
        case false?: self = .notShown
        case nil: self = .noPhoneStatus
        }
    }
}

/// Whether a new request raises an alert on the paired phone, as the phone
/// last reported it. A condition this client does not know reads as absent.
public enum RemoteApprovalPhoneAlertCondition: String, Codable, Equatable, Sendable {
    case ready
    /// iCloud refused the phone's request subscription, so nothing alerts it.
    case subscriptionRefused = "subscription_refused"
    /// The phone could not register for push notifications.
    case pushRegistrationFailed = "push_registration_failed"
}

/// Drop csecd's cached resolution(s) for the given references so the next
/// resolve re-reads the freshly-rotated value from its provider instead of a
/// stale cache hit. Cache eviction only — it carries no secret material,
/// discloses no value, and needs no Touch ID. Sent by the launcher after
/// `csec edit` rotates a value or `csec protect --env` overwrites an existing
/// reference: a 1Password rotation is performed entirely outside csecd (through
/// the `op` CLI), so the daemon would otherwise keep serving the pre-rotation
/// value: the op:// cache has no wall-clock expiry and holds a value until
/// something invalidates it.
public struct InvalidateCachedReferencesRequest: Codable, Sendable {
    public let requestID: String
    public let references: [String]

    /// A generous ceiling: one edit invalidates a single reference and a whole
    /// env import only a handful, so a larger list is a malformed request.
    public static let maximumReferences = 4096

    public init(references: [String], requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
        self.references = references
    }
}

public enum DecisionLogAction: String, Codable, Sendable {
    /// One page of records.
    case read
    /// Walk both streams against csecd's heads now, recording and notifying
    /// any finding as at startup.
    case verify
    /// The log's state for `csec status`.
    case status
}

/// `csec log`: read, verify, or report on the decision log. Like `csec
/// grants`, it needs the verified launcher but no Touch ID: it releases no
/// value, and the references and commands it lists are metadata the review
/// panels and the agents' own transcripts already show.
public struct DecisionLogRequest: Codable, Sendable {
    public let requestID: String
    public let action: DecisionLogAction
    /// Present exactly when `action` is `read`.
    public let query: DecisionLogQuery?

    public init(action: DecisionLogAction, query: DecisionLogQuery? = nil, requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
        self.action = action
        self.query = query
    }
}

/// `csec uninstall`'s request that csecd delete everything only it can
/// delete: its protected Keychain items, the decision log and the sealed
/// host-audit baseline (`CsecdUninstaller.deletedSummary`). csecd shows one
/// Touch ID panel naming the terminal, then enters a terminal state in which
/// it writes nothing more.
public struct UninstallCleanupRequest: Codable, Sendable {
    public let requestID: String

    public init(requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
    }
}

// MARK: - Delegated approvals

/// Bounds shared by the delegated-approval wire types. Each public type states
/// its own `isWellFormed` in terms of these.
enum WireField {
    static let maximumPathBytes = 4_096
    static let maximumReferenceBytes = 4_096

    static func isLowercaseHex(_ value: String, length: Int) -> Bool {
        value.utf8.count == length && value.utf8.allSatisfy(isLowercaseHexDigit)
    }

    /// An id within a `GrantIDKind`: lowercase hex and dashes.
    static func isTypedIDBody(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= GrantIDSelector.maximumPrefixLength
            && value.utf8.allSatisfy { isLowercaseHexDigit($0) || $0 == 45 }
    }

    static func isAbsolutePath(_ value: String, maximumBytes: Int = maximumPathBytes) -> Bool {
        value.hasPrefix("/") && value.utf8.count <= maximumBytes && !value.utf8.contains(0)
    }

    static func isBoundedText(_ value: String, maximumBytes: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumBytes && !value.utf8.contains(0)
    }

    static func isReference(_ value: String) -> Bool {
        isBoundedText(value, maximumBytes: maximumReferenceBytes)
    }

    /// A Claude Code user settings file: an absolute path within bounds, with
    /// no NUL, no empty, `.` or `..` component, ending in `/settings.json`.
    static func isClaudeSettingsPath(_ value: String) -> Bool {
        guard isAbsolutePath(value) else { return false }
        let components = value.split(separator: "/", omittingEmptySubsequences: false).dropFirst()
        return components.last == "settings.json"
            && components.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }

    /// `[A-Za-z0-9_-]{1,maximumBytes}`: the shape of Claude Code's session,
    /// tool-use and agent ids.
    static func isIdentifier(_ value: String, maximumBytes: Int) -> Bool {
        !value.isEmpty && value.utf8.count <= maximumBytes && value.utf8.allSatisfy {
            ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) || ($0 >= 48 && $0 <= 57)
                || $0 == 95 || $0 == 45
        }
    }

    private static func isLowercaseHexDigit(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}

/// `register_agent_command`: `csec hook claude` tells csecd, before its
/// rewrite reaches Claude Code, which exact program the matching `csec ai`
/// will run. It carries no authority: csecd accepts it only from a verified
/// launcher whose kernel ancestry is `csec hook → shell → P`, and re-verifies P
/// and Claude Code's settings when the `csec ai` consumes it. The program
/// crosses only as a digest, so csecd never holds hook-supplied command text.
///
/// The hook registers in every permission mode; csecd delegates only when the
/// registration says `auto` and declines every other mode with a reason the
/// panel shows.
///
/// A git command the hook left unwrapped (`AICommandGitPassthrough`) that
/// reaches a remote registers with `unwrapped` set: no `csec ai` will run it,
/// and csecd binds it only through the Bash tool shell that evaluates exactly
/// that text (`ClaudeToolShell`), never to a `csec ai`; a wrapped registration
/// binds only to a `csec ai`. Absent on the wire, it is false.
public struct AgentCommandRegistration: Sendable, Equatable {
    public static let maximumIdentifierBytes = 128
    public static let maximumPermissionModeBytes = 32
    /// The one permission mode in which csecd may delegate.
    public static let autoPermissionMode = "auto"

    public let requestID: String
    /// Only Claude Code registers; csecd refuses any other client.
    public let client: AICommandHookClient
    /// Claude Code's `session_id`, `tool_use_id` and (for a subagent)
    /// `agent_id`: `[A-Za-z0-9_-]`, at most 128 bytes each.
    public let sessionID: String
    public let toolUseID: String
    public let agentID: String?
    /// Claude Code's `permission_mode` as the hook saw it: `[A-Za-z]`, at most
    /// 32 bytes (`default`, `plan`, `acceptEdits`, `auto`, `dontAsk`,
    /// `bypassPermissions`, or a mode added later).
    public let permissionMode: String
    /// The hook's `cwd`: absolute, at most 4 KiB, no NUL.
    public let hookCWD: String
    /// `AICommandHook.programDigest` of the program `csec ai` will run
    /// (`AICommandHook.launchedProgram(forCommand:)`), or for an unwrapped
    /// command of the command exactly as typed: 64 lowercase hex.
    public let programSHA256: String
    /// The command runs unwrapped, straight from Claude Code's Bash tool
    /// shell, with no `csec ai`.
    public let unwrapped: Bool

    /// Nil unless every field is within its bounds: the hook then registers
    /// nothing, and the `csec ai` that follows is simply not delegated.
    public init?(
        client: AICommandHookClient = .claude,
        sessionID: String,
        toolUseID: String,
        agentID: String?,
        permissionMode: String,
        hookCWD: String,
        programSHA256: String,
        unwrapped: Bool = false,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.client = client
        self.sessionID = sessionID
        self.toolUseID = toolUseID
        self.agentID = agentID
        self.permissionMode = permissionMode
        self.hookCWD = hookCWD
        self.programSHA256 = programSHA256
        self.unwrapped = unwrapped
        guard isWellFormed else { return nil }
    }

    public var isAutoMode: Bool { permissionMode == Self.autoPermissionMode }

    public var isWellFormed: Bool {
        client == .claude
            && WireField.isIdentifier(sessionID, maximumBytes: Self.maximumIdentifierBytes)
            && WireField.isIdentifier(toolUseID, maximumBytes: Self.maximumIdentifierBytes)
            && (agentID.map { WireField.isIdentifier($0, maximumBytes: Self.maximumIdentifierBytes) } ?? true)
            && !permissionMode.isEmpty
            && permissionMode.utf8.count <= Self.maximumPermissionModeBytes
            && permissionMode.utf8.allSatisfy { ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122) }
            && WireField.isAbsolutePath(hookCWD)
            && WireField.isLowercaseHex(programSHA256, length: 64)
    }
}

/// What `configure_delegation` asks of csecd.
public enum DelegationConfigurationAction: String, Codable, Sendable, CaseIterable {
    /// The delegation status, with csecd's own view of Claude Code's settings
    /// for the request's scope. No Touch ID.
    case status
    /// Turn delegated approvals on, trusting every untrusted build and
    /// acknowledging every other approving hook csecd finds for the scope,
    /// under one bare Touch ID sheet whose reason csecd writes from what it
    /// found. Also re-confirms after a policy version change.
    case enable
    /// Trust the Claude Code build at `target` (an absolute path) by cdhash,
    /// under one bare Touch ID sheet.
    case trustBuild = "trust_build"
    /// Stop trusting the build `target` names (a `build-` id). No Touch ID.
    case untrustBuild = "untrust_build"
    /// Acknowledge every approving hook csecd finds for the scope that is not
    /// yet acknowledged, under one bare Touch ID sheet.
    case acknowledgeHooks = "acknowledge_hooks"
    /// Forget the acknowledged hook `target` names (a `hook-` id). No Touch ID.
    case forgetHook = "forget_hook"
    /// Turn delegated approvals off, deleting the delegation settings and
    /// every pairing. No Touch ID: it only removes authority.
    case disable

    /// Whether the request must carry `target`.
    public var requiresTarget: Bool {
        switch self {
        case .trustBuild, .untrustBuild, .forgetHook: return true
        case .status, .enable, .acknowledgeHooks, .disable: return false
        }
    }

    /// Whether csecd raises its bare Touch ID sheet before acting. The rest
    /// only read or remove authority.
    public var addsAuthority: Bool {
        switch self {
        case .enable, .trustBuild, .acknowledgeHooks: return true
        case .status, .untrustBuild, .forgetHook, .disable: return false
        }
    }
}

/// `configure_delegation`, from `csec setup`, `csec status`/`doctor`, `csec
/// revoke build-…`/`hook-…` and `csec uninstall`. No environment variable,
/// argument or file can enable delegation: only `enable` (or `trust_build`,
/// `acknowledge_hooks`) behind csecd's own Touch ID sheet adds authority.
public struct DelegationConfigurationRequest: Sendable, Equatable {
    public let requestID: String
    public let action: DelegationConfigurationAction
    /// `CLAUDE_CONFIG_DIR` from the launcher's environment, when set to an
    /// absolute path. csecd checks the user owns it before reading it.
    public let claudeConfigDirectory: String?
    /// The launcher's working directory: whose project settings the status
    /// and the inventory for `enable` / `acknowledge_hooks` cover.
    public let projectDirectory: String?
    /// `trust_build`: the build's absolute path; csecd computes its cdhash.
    /// `untrust_build` / `forget_hook`: a `build-` / `hook-` id or a prefix of
    /// one, which must match exactly one entry.
    public let target: String?
    /// `enable` only, and required there: whether `csec setup` itself added
    /// `autoMode.classifyAllShell` to the user settings, so disabling and
    /// uninstalling remove it only then. csecd keeps a recorded `true` while
    /// `claudeSettingsPath` stays the same: a re-confirmation that adds nothing
    /// does not clear it.
    public let setClassifyAllShell: Bool?
    /// `enable` only, and required there: the Claude Code user settings file
    /// `csec setup` wrote `autoMode.classifyAllShell` and csec's
    /// `autoMode.environment` entry into (absolute, `…/settings.json`). csecd
    /// records it with `setClassifyAllShell` and returns it in the status, so
    /// disable and uninstall revert exactly that file even when
    /// `CLAUDE_CONFIG_DIR` differs later.
    public let claudeSettingsPath: String?

    public init(
        action: DelegationConfigurationAction,
        claudeConfigDirectory: String? = nil,
        projectDirectory: String? = nil,
        target: String? = nil,
        setClassifyAllShell: Bool? = nil,
        claudeSettingsPath: String? = nil,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.action = action
        self.claudeConfigDirectory = claudeConfigDirectory
        self.projectDirectory = projectDirectory
        self.target = target
        self.setClassifyAllShell = setClassifyAllShell
        self.claudeSettingsPath = claudeSettingsPath
    }

    public static func status(claudeConfigDirectory: String?, projectDirectory: String?) -> Self {
        Self(action: .status, claudeConfigDirectory: claudeConfigDirectory, projectDirectory: projectDirectory)
    }

    public static func enable(
        claudeConfigDirectory: String?,
        projectDirectory: String?,
        setClassifyAllShell: Bool,
        claudeSettingsPath: String
    ) -> Self {
        Self(
            action: .enable,
            claudeConfigDirectory: claudeConfigDirectory,
            projectDirectory: projectDirectory,
            setClassifyAllShell: setClassifyAllShell,
            claudeSettingsPath: claudeSettingsPath
        )
    }

    public static func trustBuild(
        path: String,
        claudeConfigDirectory: String?,
        projectDirectory: String?
    ) -> Self {
        Self(
            action: .trustBuild,
            claudeConfigDirectory: claudeConfigDirectory,
            projectDirectory: projectDirectory,
            target: path
        )
    }

    public static func untrustBuild(id: String) -> Self {
        Self(action: .untrustBuild, target: id)
    }

    public static func acknowledgeHooks(claudeConfigDirectory: String?, projectDirectory: String?) -> Self {
        Self(action: .acknowledgeHooks, claudeConfigDirectory: claudeConfigDirectory, projectDirectory: projectDirectory)
    }

    public static func forgetHook(id: String) -> Self {
        Self(action: .forgetHook, target: id)
    }

    public static func disable() -> Self {
        Self(action: .disable)
    }

    /// The parsed `untrust_build` / `forget_hook` target, of the action's kind.
    public var targetSelector: GrantIDSelector? {
        let kind: GrantIDKind
        switch action {
        case .untrustBuild: kind = .build
        case .forgetHook: kind = .hook
        default: return nil
        }
        guard let target, let selector = GrantIDSelector(target), selector.kind == kind else { return nil }
        return selector
    }

    public var isWellFormed: Bool {
        guard claudeConfigDirectory.map({ WireField.isAbsolutePath($0) }) ?? true,
              projectDirectory.map({ WireField.isAbsolutePath($0) }) ?? true,
              action.requiresTarget == (target != nil),
              (action == .enable) == (setClassifyAllShell != nil),
              (action == .enable) == (claudeSettingsPath != nil),
              claudeSettingsPath.map(WireField.isClaudeSettingsPath) ?? true else { return false }
        switch action {
        case .trustBuild: return target.map { WireField.isAbsolutePath($0) } ?? false
        case .untrustBuild, .forgetHook: return targetSelector != nil
        case .status, .enable, .acknowledgeHooks, .disable: return true
        }
    }
}

/// Whether delegated approvals are on.
public enum DelegationState: String, Codable, Sendable, CaseIterable {
    /// Never enabled, or disabled.
    case off
    /// Enabled, and confirmed at the policy version this csecd runs.
    case on
    /// Enabled under an older policy version: off until `csec setup` confirms
    /// again, because this build delegates more than the human agreed to.
    case reconfirmationRequired = "reconfirmation_required"
    /// The delegation settings item exists but cannot be read: off, and a bad
    /// status row.
    case unreadable
    /// This csecd has no protected stores to keep the settings in, so
    /// delegation cannot be turned on.
    case unavailable
}

/// Delegation decisions since csecd started. Counts only, never persisted.
public struct DelegationCounters: Codable, Sendable, Equatable {
    public let approved: Int
    public let declined: Int

    public init(approved: Int, declined: Int) {
        self.approved = approved
        self.declined = declined
    }

    public var isWellFormed: Bool { approved >= 0 && declined >= 0 }
}

/// The `configure_delegation` reply, for every action: the state after it.
public struct DelegationStatus: Codable, Sendable, Equatable {
    public static let maximumDiscoveredBuilds = 64
    public static let maximumLastDeclineBytes = 512
    public static let maximumIdentityLookupBytes = 128

    public let state: DelegationState
    /// The policy version this csecd enables at.
    public let policyVersion: Int
    /// The version the human last confirmed, if delegation was ever enabled
    /// and not disabled since.
    public let consentedPolicyVersion: Int?
    /// Whether `csec setup` added `autoMode.classifyAllShell` when it enabled
    /// delegation: disable and uninstall remove it only then. Read it before
    /// `disable`, which deletes the record.
    public let setClassifyAllShell: Bool
    /// The Claude Code settings file `csec setup` edited when it enabled
    /// delegation, as `enable` recorded it; nil when there is no record. Disable
    /// and uninstall revert exactly this file. Read it before `disable`, which
    /// deletes the record.
    public let claudeSettingsPath: String?
    public let trustedBuilds: [ClaudeBuildSummary]
    public let acknowledgedHooks: [AcknowledgedHookSummary]
    /// Claude Code builds csecd found for the scope (installed versions and
    /// live sessions) that are neither signed by Anthropic nor trusted.
    public let discoveredUntrustedBuilds: [ClaudeBuildSummary]
    /// Settings-loader compatibility, separate from publisher/custom trust.
    /// Nil when talking to a csecd predating the release gate.
    public let buildVerification: ClaudeBuildVerificationReport?
    /// Claude Code's settings for the request's scope, exactly as csecd reads
    /// them when it decides; nil when it did not evaluate them.
    public let settings: ClaudeSettingsGateEvaluation?
    public let pairingCount: Int
    public let counters: DelegationCounters
    /// The most recent decline's reason, csecd-authored and value-free.
    public let lastDecline: String?
    /// How csecd located Claude Code's live code at its most recent identity
    /// check this run (`ForeignCodeIdentity.Lookup.logDescription`): the
    /// exec-exact audit token, or the PID when the kernel refused the task
    /// name port. Nil until csecd has checked one.
    public let identityLookup: String?

    public init(
        state: DelegationState,
        policyVersion: Int,
        consentedPolicyVersion: Int? = nil,
        setClassifyAllShell: Bool = false,
        claudeSettingsPath: String? = nil,
        trustedBuilds: [ClaudeBuildSummary] = [],
        acknowledgedHooks: [AcknowledgedHookSummary] = [],
        discoveredUntrustedBuilds: [ClaudeBuildSummary] = [],
        buildVerification: ClaudeBuildVerificationReport? = nil,
        settings: ClaudeSettingsGateEvaluation? = nil,
        pairingCount: Int = 0,
        counters: DelegationCounters = DelegationCounters(approved: 0, declined: 0),
        lastDecline: String? = nil,
        identityLookup: String? = nil
    ) {
        self.state = state
        self.policyVersion = policyVersion
        self.consentedPolicyVersion = consentedPolicyVersion
        self.setClassifyAllShell = setClassifyAllShell
        self.claudeSettingsPath = claudeSettingsPath
        self.trustedBuilds = trustedBuilds
        self.acknowledgedHooks = acknowledgedHooks
        self.discoveredUntrustedBuilds = discoveredUntrustedBuilds
        self.buildVerification = buildVerification
        self.settings = settings
        self.pairingCount = pairingCount
        self.counters = counters
        self.lastDecline = lastDecline
        self.identityLookup = identityLookup
    }

    public var isEnabled: Bool { state == .on }

    /// The approving hooks csecd found for the scope that are not acknowledged.
    public var unacknowledgedHooks: [ClaudeHookSource] {
        settings?.unacknowledgedHooks(acknowledgedDigests: Set(acknowledgedHooks.map(\.digest))) ?? []
    }

    public var isWellFormed: Bool {
        policyVersion > 0
            && (consentedPolicyVersion.map { $0 > 0 } ?? true)
            && (claudeSettingsPath.map(WireField.isClaudeSettingsPath) ?? true)
            // `setClassifyAllShell` records what was done to one file.
            && (!setClassifyAllShell || claudeSettingsPath != nil)
            && trustedBuilds.count <= DelegationGrantsListing.maximumTrustedBuilds
            && trustedBuilds.allSatisfy(\.isWellFormed)
            && acknowledgedHooks.count <= DelegationGrantsListing.maximumAcknowledgedHooks
            && acknowledgedHooks.allSatisfy(\.isWellFormed)
            && discoveredUntrustedBuilds.count <= Self.maximumDiscoveredBuilds
            && discoveredUntrustedBuilds.allSatisfy { $0.isWellFormed && $0.trustedAt == nil }
            && (buildVerification?.isWellFormed ?? true)
            && (settings?.isWellFormed ?? true)
            && pairingCount >= 0 && pairingCount <= DelegationGrantsListing.maximumPairings
            && counters.isWellFormed
            && (lastDecline.map { WireField.isBoundedText($0, maximumBytes: Self.maximumLastDeclineBytes) } ?? true)
            && (identityLookup.map { WireField.isBoundedText($0, maximumBytes: Self.maximumIdentityLookupBytes) } ?? true)
    }
}

/// Requests retain the v1 flat discriminator so an upgraded agent can return a
/// typed migration error instead of misinterpreting an old access as secure.
public enum Request: Sendable {
    case access(AccessRequest)
    case schemes
    case capabilities
    case restoreApprovals(RestoreApprovalsRequest)
    case beginSession(BeginSessionRequest)
    case beginOutputRedaction(BeginOutputRedactionRequest)
    case redactOutputChunk(RedactOutputChunkRequest)
    case endOutputRedaction(EndOutputRedactionRequest)
    case takeApprovalNotices(TakeApprovalNoticesRequest)
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
    case configureSSH(SSHKeyCatalogRequest)
    case configureGitHub(GitHubProxyRequest)
    case configureAutomation(AutomationRequest)
    case grants(GrantsRequest)
    case invalidateCachedReferences(InvalidateCachedReferencesRequest)
    case decisionLog(DecisionLogRequest)
    case uninstallCleanup(UninstallCleanupRequest)
    case registerAgentCommand(AgentCommandRegistration)
    case configureDelegation(DelegationConfigurationRequest)
    /// Only from the sudo review helper (`SocketPeerTrustPolicy.permits`).
    case sudoRemoteReview(SudoRemoteReviewRequest)
    /// Only from the sudo review helper, before it builds a panel.
    case sudoDelegation(SudoDelegationRequest)
    /// Only from the sudo review helper, after a Mac approval of a panel
    /// that showed csecd's pairing line.
    case sudoPairing(SudoPairingRequest)
    /// Only from the sudo review helper, before it builds a panel: csecd
    /// names the terminal tab the sudo came from (`SudoTerminalRequest`).
    case sudoTerminal(SudoTerminalRequest)
    /// Only from the sudo review helper, just before it exits: how its review
    /// ended, for the decision log (`SudoReviewEndRequest`).
    case sudoReviewEnd(SudoReviewEndRequest)
    case nativeStoreBackup(NativeStoreBackupRequest)
    case configureMachineIdentity(MachineIdentityRequest)
    case removeNativeValues(NativeStoreRemovalRequest)
}

extension Request: Codable {
    private enum CodingKeys: String, CodingKey {
        case version, type, requestID, references, reason, ttlSeconds
        case deliveryPlan, deliveryPlanDigest, commandLine
        case destination, streams, includeShortValues, labelStyle, sessionID, stream, data, finish
        case store, editSessionID, document, mode, externalEditorPath, origin, blobs, sshKeyRegistrations
        case githubTokenRegistration, github
        case protectedLaunchApproval
        case scanFilesystem, selectedKeys, jobID
        case exemptions, todos, cleared
        case action, phonePairingCode, registrations, fingerprint, automation
        case grantID, all
        case query
        case client, toolUseID, agentID, permissionMode, hookCWD, programSHA256, unwrapped
        case claudeConfigDirectory, projectDirectory, target, setClassifyAllShell, claudeSettingsPath
        case sudoReview, sudoDelegation, sudoPairing, sudoTerminal, sudoReviewEnd
        case nativeStoreBackup
        case machineIdentity
        case nativeStoreRemoval
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let type = try container.decode(String.self, forKey: .type)
        switch type {
        case "access":
            let version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 1
            let references = try container.decode([String].self, forKey: .references)
            let reason = try container.decode(String.self, forKey: .reason)
            // Absent ⇒ a process-lifetime grant (the v2 default). A legacy client
            // always sends a concrete value.
            let ttl = try container.decodeIfPresent(Int.self, forKey: .ttlSeconds)
            if version >= 2 {
                self = .access(AccessRequest(
                    protocolVersion: version,
                    requestID: try container.decodeIfPresent(String.self, forKey: .requestID),
                    references: references,
                    reason: reason,
                    ttlSeconds: ttl,
                    deliveryPlan: try container.decodeIfPresent(DeliveryPlan.self, forKey: .deliveryPlan),
                    deliveryPlanDigest: try container.decodeIfPresent(String.self, forKey: .deliveryPlanDigest),
                    commandLine: try container.decodeIfPresent([String].self, forKey: .commandLine)
                ))
            } else {
                self = .access(.legacy(
                    references: references,
                    reason: reason,
                    ttlSeconds: ttl ?? ReleasePolicy.defaultTTLSeconds
                ))
            }
        case "schemes":
            self = .schemes
        case "capabilities":
            self = .capabilities
        case "restore_approvals":
            self = .restoreApprovals(RestoreApprovalsRequest(
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "grants":
            self = .grants(GrantsRequest(
                action: try container.decode(GrantsAction.self, forKey: .action),
                grantID: try container.decodeIfPresent(String.self, forKey: .grantID),
                all: try container.decodeIfPresent(Bool.self, forKey: .all) ?? false,
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
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
        case "take_approval_notices":
            self = .takeApprovalNotices(TakeApprovalNoticesRequest(
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
                origin: try container.decodeIfPresent(String.self, forKey: .origin),
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
                sshKeyRegistrations: try container.decodeIfPresent(
                    [SSHKeyRegistrationIntent].self,
                    forKey: .sshKeyRegistrations
                ) ?? [],
                githubTokenRegistration: try container.decodeIfPresent(
                    String.self,
                    forKey: .githubTokenRegistration
                ),
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
        case "configure_ssh":
            self = .configureSSH(SSHKeyCatalogRequest(
                action: try container.decode(SSHKeyCatalogAction.self, forKey: .action),
                registrations: try container.decodeIfPresent(
                    [SSHKeyRegistrationIntent].self,
                    forKey: .registrations
                ) ?? [],
                fingerprint: try container.decodeIfPresent(String.self, forKey: .fingerprint),
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "configure_github":
            let github = try container.decode(GitHubProxyRequest.self, forKey: .github)
            guard try Self.decodeUUID(container, forKey: .requestID).uuidString.lowercased()
                    == github.requestID,
                  github.reference.map({ $0.utf8.count <= 4_096 }) ?? true else {
                throw DecodingError.dataCorruptedError(
                    forKey: .requestID,
                    in: container,
                    debugDescription: "invalid GitHub proxy request"
                )
            }
            self = .configureGitHub(github)
        case "configure_automation":
            let automation = try container.decode(AutomationRequest.self, forKey: .automation)
            guard try Self.decodeUUID(container, forKey: .requestID).uuidString.lowercased()
                    == automation.requestID else {
                throw DecodingError.dataCorruptedError(
                    forKey: .requestID,
                    in: container,
                    debugDescription: "automation request UUID mismatch"
                )
            }
            self = .configureAutomation(automation)
        case "invalidate_cached_references":
            let references = try container.decode([String].self, forKey: .references)
            guard references.count <= InvalidateCachedReferencesRequest.maximumReferences else {
                throw DecodingError.dataCorruptedError(
                    forKey: .references,
                    in: container,
                    debugDescription: "too many references to invalidate"
                )
            }
            self = .invalidateCachedReferences(InvalidateCachedReferencesRequest(
                references: references,
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "decision_log":
            let action = try container.decode(DecisionLogAction.self, forKey: .action)
            let query = try container.decodeIfPresent(DecisionLogQuery.self, forKey: .query)
            guard (action == .read) == (query != nil), query?.isWellFormed ?? true else {
                throw DecodingError.dataCorruptedError(
                    forKey: .query,
                    in: container,
                    debugDescription: "invalid decision log request"
                )
            }
            self = .decisionLog(DecisionLogRequest(
                action: action,
                query: query,
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "uninstall_cleanup":
            self = .uninstallCleanup(UninstallCleanupRequest(
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            ))
        case "register_agent_command":
            guard let client = AICommandHookClient(
                rawValue: try container.decode(String.self, forKey: .client)
            ),
                let registration = AgentCommandRegistration(
                    client: client,
                    sessionID: try container.decode(String.self, forKey: .sessionID),
                    toolUseID: try container.decode(String.self, forKey: .toolUseID),
                    agentID: try container.decodeIfPresent(String.self, forKey: .agentID),
                    permissionMode: try container.decode(String.self, forKey: .permissionMode),
                    hookCWD: try container.decode(String.self, forKey: .hookCWD),
                    programSHA256: try container.decode(String.self, forKey: .programSHA256),
                    unwrapped: try container.decodeIfPresent(Bool.self, forKey: .unwrapped) ?? false,
                    requestID: try Self.decodeUUID(container, forKey: .requestID)
                ) else {
                throw DecodingError.dataCorruptedError(
                    forKey: .programSHA256,
                    in: container,
                    debugDescription: "invalid agent command registration"
                )
            }
            self = .registerAgentCommand(registration)
        case "configure_delegation":
            let request = DelegationConfigurationRequest(
                action: try container.decode(DelegationConfigurationAction.self, forKey: .action),
                claudeConfigDirectory: try container.decodeIfPresent(String.self, forKey: .claudeConfigDirectory),
                projectDirectory: try container.decodeIfPresent(String.self, forKey: .projectDirectory),
                target: try container.decodeIfPresent(String.self, forKey: .target),
                setClassifyAllShell: try container.decodeIfPresent(Bool.self, forKey: .setClassifyAllShell),
                claudeSettingsPath: try container.decodeIfPresent(String.self, forKey: .claudeSettingsPath),
                requestID: try Self.decodeUUID(container, forKey: .requestID)
            )
            guard request.isWellFormed else {
                throw DecodingError.dataCorruptedError(
                    forKey: .action,
                    in: container,
                    debugDescription: "invalid delegation configuration request"
                )
            }
            self = .configureDelegation(request)
        case "native_store_backup":
            let request = try container.decode(NativeStoreBackupRequest.self, forKey: .nativeStoreBackup)
            guard try Self.decodeUUID(container, forKey: .requestID).uuidString.lowercased()
                    == request.requestID, request.isWellFormed else {
                throw DecodingError.dataCorruptedError(
                    forKey: .nativeStoreBackup,
                    in: container,
                    debugDescription: "invalid native-store backup request"
                )
            }
            self = .nativeStoreBackup(request)
        case "configure_machine_identity":
            let request = try container.decode(MachineIdentityRequest.self, forKey: .machineIdentity)
            guard try Self.decodeUUID(container, forKey: .requestID).uuidString.lowercased()
                    == request.requestID, request.isWellFormed else {
                throw DecodingError.dataCorruptedError(
                    forKey: .machineIdentity,
                    in: container,
                    debugDescription: "invalid machine identity request"
                )
            }
            self = .configureMachineIdentity(request)
        case "remove_native_values":
            let request = try container.decode(NativeStoreRemovalRequest.self, forKey: .nativeStoreRemoval)
            guard try Self.decodeUUID(container, forKey: .requestID).uuidString.lowercased()
                    == request.requestID, request.isWellFormed else {
                throw DecodingError.dataCorruptedError(
                    forKey: .nativeStoreRemoval,
                    in: container,
                    debugDescription: "invalid native-store removal request"
                )
            }
            self = .removeNativeValues(request)
        case "sudo_remote_review":
            let review = try container.decode(SudoRemoteReviewRequest.self, forKey: .sudoReview)
            guard try Self.decodeUUID(container, forKey: .requestID).uuidString.lowercased()
                    == review.requestID, review.isWellFormed else {
                throw DecodingError.dataCorruptedError(
                    forKey: .sudoReview,
                    in: container,
                    debugDescription: "invalid sudo remote review request"
                )
            }
            self = .sudoRemoteReview(review)
        case "sudo_delegation":
            let request = try container.decode(SudoDelegationRequest.self, forKey: .sudoDelegation)
            guard try Self.decodeUUID(container, forKey: .requestID).uuidString.lowercased()
                    == request.requestID, request.isWellFormed else {
                throw DecodingError.dataCorruptedError(
                    forKey: .sudoDelegation,
                    in: container,
                    debugDescription: "invalid sudo delegation request"
                )
            }
            self = .sudoDelegation(request)
        case "sudo_pairing":
            let request = try container.decode(SudoPairingRequest.self, forKey: .sudoPairing)
            guard try Self.decodeUUID(container, forKey: .requestID).uuidString.lowercased()
                    == request.requestID, request.isWellFormed else {
                throw DecodingError.dataCorruptedError(
                    forKey: .sudoPairing,
                    in: container,
                    debugDescription: "invalid sudo pairing request"
                )
            }
            self = .sudoPairing(request)
        case "sudo_terminal":
            let request = try container.decode(SudoTerminalRequest.self, forKey: .sudoTerminal)
            guard try Self.decodeUUID(container, forKey: .requestID).uuidString.lowercased()
                    == request.requestID, request.isWellFormed else {
                throw DecodingError.dataCorruptedError(
                    forKey: .sudoTerminal,
                    in: container,
                    debugDescription: "invalid sudo terminal request"
                )
            }
            self = .sudoTerminal(request)
        case "sudo_review_end":
            let request = try container.decode(SudoReviewEndRequest.self, forKey: .sudoReviewEnd)
            guard try Self.decodeUUID(container, forKey: .requestID).uuidString.lowercased()
                    == request.requestID, request.isWellFormed else {
                throw DecodingError.dataCorruptedError(
                    forKey: .sudoReviewEnd,
                    in: container,
                    debugDescription: "invalid sudo review end report"
                )
            }
            self = .sudoReviewEnd(request)
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
            try container.encodeIfPresent(request.ttlSeconds, forKey: .ttlSeconds)
            try container.encodeIfPresent(request.deliveryPlan, forKey: .deliveryPlan)
            try container.encodeIfPresent(request.deliveryPlanDigest, forKey: .deliveryPlanDigest)
            try container.encodeIfPresent(request.commandLine, forKey: .commandLine)
        case .schemes:
            try container.encode("schemes", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
        case .capabilities:
            try container.encode("capabilities", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
        case let .restoreApprovals(request):
            try container.encode("restore_approvals", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
        case let .grants(request):
            try container.encode("grants", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.action, forKey: .action)
            try container.encodeIfPresent(request.grantID, forKey: .grantID)
            try container.encode(request.all, forKey: .all)
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
        case let .takeApprovalNotices(request):
            try container.encode("take_approval_notices", forKey: .type)
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
            try container.encodeIfPresent(request.origin, forKey: .origin)
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
            try container.encode(request.sshKeyRegistrations, forKey: .sshKeyRegistrations)
            try container.encodeIfPresent(request.githubTokenRegistration, forKey: .githubTokenRegistration)
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
        case let .configureSSH(request):
            try container.encode("configure_ssh", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.action, forKey: .action)
            try container.encode(request.registrations, forKey: .registrations)
            try container.encodeIfPresent(request.fingerprint, forKey: .fingerprint)
        case let .configureGitHub(request):
            try container.encode("configure_github", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request, forKey: .github)
        case let .configureAutomation(request):
            try container.encode("configure_automation", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request, forKey: .automation)
        case let .invalidateCachedReferences(request):
            try container.encode("invalidate_cached_references", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.references, forKey: .references)
        case let .decisionLog(request):
            try container.encode("decision_log", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.action, forKey: .action)
            try container.encodeIfPresent(request.query, forKey: .query)
        case let .uninstallCleanup(request):
            try container.encode("uninstall_cleanup", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
        case let .registerAgentCommand(registration):
            try container.encode("register_agent_command", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(registration.requestID, forKey: .requestID)
            try container.encode(registration.client.rawValue, forKey: .client)
            try container.encode(registration.sessionID, forKey: .sessionID)
            try container.encode(registration.toolUseID, forKey: .toolUseID)
            try container.encodeIfPresent(registration.agentID, forKey: .agentID)
            try container.encode(registration.permissionMode, forKey: .permissionMode)
            try container.encode(registration.hookCWD, forKey: .hookCWD)
            try container.encode(registration.programSHA256, forKey: .programSHA256)
            if registration.unwrapped { try container.encode(true, forKey: .unwrapped) }
        case let .configureDelegation(request):
            try container.encode("configure_delegation", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request.action, forKey: .action)
            try container.encodeIfPresent(request.claudeConfigDirectory, forKey: .claudeConfigDirectory)
            try container.encodeIfPresent(request.projectDirectory, forKey: .projectDirectory)
            try container.encodeIfPresent(request.target, forKey: .target)
            try container.encodeIfPresent(request.setClassifyAllShell, forKey: .setClassifyAllShell)
            try container.encodeIfPresent(request.claudeSettingsPath, forKey: .claudeSettingsPath)
        case let .nativeStoreBackup(request):
            try container.encode("native_store_backup", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request, forKey: .nativeStoreBackup)
        case let .configureMachineIdentity(request):
            try container.encode("configure_machine_identity", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request, forKey: .machineIdentity)
        case let .removeNativeValues(request):
            try container.encode("remove_native_values", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request, forKey: .nativeStoreRemoval)
        case let .sudoRemoteReview(request):
            try container.encode("sudo_remote_review", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request, forKey: .sudoReview)
        case let .sudoDelegation(request):
            try container.encode("sudo_delegation", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request, forKey: .sudoDelegation)
        case let .sudoPairing(request):
            try container.encode("sudo_pairing", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request, forKey: .sudoPairing)
        case let .sudoTerminal(request):
            try container.encode("sudo_terminal", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request, forKey: .sudoTerminal)
        case let .sudoReviewEnd(request):
            try container.encode("sudo_review_end", forKey: .type)
            try container.encode(WireProtocol.version, forKey: .version)
            try container.encode(request.requestID, forKey: .requestID)
            try container.encode(request, forKey: .sudoReviewEnd)
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
    /// Per-provider health lines for `csec status`. Value-free and optional, so
    /// an older client simply does not render them.
    public let providerStatus: [ProviderStatusSummary]?
    public let capabilities: ProtocolCapabilities?
    public let restorationStatus: RestorationStatus?
    /// `restore_approvals`: what it fetched ahead from providers that need no
    /// csec unlock. Optional, so an older client ignores it.
    public let restoreFetchAhead: FetchAheadSummary?
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
    /// With the Mac code: whether the same pairing was also offered to the
    /// pinned phone through the mailbox.
    public let remoteApprovalPairingOfferPublished: Bool?
    public let sshKeys: [SSHKeyMetadata]?
    /// `configure_github`: the proxy's registration after the action.
    public let github: GitHubProxyStatus?
    public let automationJobs: [AutomationJob]?
    public let automationRun: AutomationRunAuthorization?
    public let automationNextEligibleAt: Date?
    public let grants: [GrantSummary]?
    /// `grants list`, while delegated approvals are on: pairings, trusted
    /// builds and acknowledged hooks. Kept apart from `grants`, whose entries
    /// an older client decodes strictly.
    public let delegationGrants: DelegationGrantsListing?
    /// `grants revoke`: every removed entry, of every kind. Always equal to
    /// `grantRevocation.removed.count` from a csecd that sends both.
    public let revokedGrantCount: Int?
    /// `grants revoke`, `configure_delegation untrust_build` / `forget_hook`:
    /// what was removed, or (with an `invalid_request` failure) the matches of
    /// an ambiguous id.
    public let grantRevocation: GrantRevocation?
    public let decisionLogPage: DecisionLogPage?
    public let decisionLogVerification: DecisionLogVerification?
    public let decisionLogStatus: DecisionLogStatus?
    public let uninstallCleanup: UninstallCleanupResult?
    /// `register_agent_command`: whether csecd stored the registration. The
    /// hook ignores it; `false` means delegation is off or the peer is not
    /// eligible.
    public let agentCommandRegistered: Bool?
    /// `configure_delegation`: the state after the action.
    public let delegationStatus: DelegationStatus?
    /// `sudo_remote_review`: the paired phone's answer, or `unavailable`.
    public let sudoRemoteReview: SudoRemoteReviewDecision?
    /// `sudo_delegation`: whether auto mode's approval stands in for the panel.
    public let sudoDelegation: SudoDelegationAnswer?
    /// `sudo_pairing`: whether csecd recorded the pairing.
    public let sudoPaired: Bool?
    /// `sudo_terminal`: the terminal tab the sudo came from, as csecd found it.
    public let sudoTerminal: TerminalSessionContext?
    /// `sudo_review_end`: whether csecd logged the review's end.
    public let sudoReviewEnded: Bool?
    /// `native_store_backup`: status, a setup's kit, or what was backed up
    /// or restored. Value-free apart from `begin_setup`'s kit.
    public let nativeStoreBackup: NativeStoreBackupReply?
    /// `configure_machine_identity`: public metadata only.
    public let machineIdentity: MachineIdentityReply?
    /// `remove_native_values`: the references deleted and their recorded
    /// paths. Value-free.
    public let nativeStoreRemoval: NativeStoreRemovalReply?
    /// `access` and `end_output_redaction` to a `csec ai`: a request under it
    /// went to Touch ID because delegated approvals wait on `csec setup
    /// auto-mode` (`DelegationDecline.setupNotice`). csecd-authored and
    /// value-free; `csec ai` prints it for the agent session.
    public var delegationNotice: String?
    /// `take_approval_notices`: notices not yet handed to this `csec ai` of
    /// requests under it waiting on a human. Value-free, csecd-authored.
    public let approvalNotices: [String]?
    public let failure: ProtocolFailure?
    public let error: String?

    public init(
        version: Int = WireProtocol.version,
        requestID: String? = nil,
        values: [String: Data]? = nil,
        schemes: [String]? = nil,
        providerStatus: [ProviderStatusSummary]? = nil,
        capabilities: ProtocolCapabilities? = nil,
        restorationStatus: RestorationStatus? = nil,
        restoreFetchAhead: FetchAheadSummary? = nil,
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
        remoteApprovalPairingOfferPublished: Bool? = nil,
        sshKeys: [SSHKeyMetadata]? = nil,
        github: GitHubProxyStatus? = nil,
        automationJobs: [AutomationJob]? = nil,
        automationRun: AutomationRunAuthorization? = nil,
        automationNextEligibleAt: Date? = nil,
        grants: [GrantSummary]? = nil,
        delegationGrants: DelegationGrantsListing? = nil,
        revokedGrantCount: Int? = nil,
        grantRevocation: GrantRevocation? = nil,
        decisionLogPage: DecisionLogPage? = nil,
        decisionLogVerification: DecisionLogVerification? = nil,
        decisionLogStatus: DecisionLogStatus? = nil,
        uninstallCleanup: UninstallCleanupResult? = nil,
        agentCommandRegistered: Bool? = nil,
        delegationStatus: DelegationStatus? = nil,
        sudoRemoteReview: SudoRemoteReviewDecision? = nil,
        sudoDelegation: SudoDelegationAnswer? = nil,
        sudoPaired: Bool? = nil,
        sudoTerminal: TerminalSessionContext? = nil,
        sudoReviewEnded: Bool? = nil,
        nativeStoreBackup: NativeStoreBackupReply? = nil,
        machineIdentity: MachineIdentityReply? = nil,
        nativeStoreRemoval: NativeStoreRemovalReply? = nil,
        delegationNotice: String? = nil,
        approvalNotices: [String]? = nil,
        failure: ProtocolFailure? = nil,
        error: String? = nil
    ) {
        self.version = version
        self.requestID = requestID
        self.values = values
        self.schemes = schemes
        self.providerStatus = providerStatus
        self.capabilities = capabilities
        self.restorationStatus = restorationStatus
        self.restoreFetchAhead = restoreFetchAhead
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
        self.remoteApprovalPairingOfferPublished = remoteApprovalPairingOfferPublished
        self.sshKeys = sshKeys
        self.github = github
        self.automationJobs = automationJobs
        self.automationRun = automationRun
        self.automationNextEligibleAt = automationNextEligibleAt
        self.grants = grants
        self.delegationGrants = delegationGrants
        self.revokedGrantCount = revokedGrantCount
        self.grantRevocation = grantRevocation
        self.decisionLogPage = decisionLogPage
        self.decisionLogVerification = decisionLogVerification
        self.decisionLogStatus = decisionLogStatus
        self.uninstallCleanup = uninstallCleanup
        self.agentCommandRegistered = agentCommandRegistered
        self.delegationStatus = delegationStatus
        self.sudoRemoteReview = sudoRemoteReview
        self.sudoDelegation = sudoDelegation
        self.sudoPaired = sudoPaired
        self.sudoTerminal = sudoTerminal
        self.sudoReviewEnded = sudoReviewEnded
        self.nativeStoreBackup = nativeStoreBackup
        self.machineIdentity = machineIdentity
        self.nativeStoreRemoval = nativeStoreRemoval
        self.delegationNotice = delegationNotice
        self.approvalNotices = approvalNotices
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
