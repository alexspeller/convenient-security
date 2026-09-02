import Foundation
import CryptoKit

/// Where plaintext will first be placed. This is policy input, not a client
/// preference that the agent blindly accepts.
public enum DeliveryMechanism: String, Codable, Sendable, CaseIterable {
    case directHeap = "direct_heap"
    case execHook = "exec_hook"
    case inheritedFileDescriptor = "inherited_fd"
    case capabilityGIDFile = "capability_gid_file"
    case restrictedLateEnvironment = "restricted_late_env"
    case sealedEnvironment = "sealed_environment"
    case unrestrictedInitialEnvironment = "unrestricted_initial_env"
    case rawStandardOutput = "raw_stdout"
    case namedPlaintextFile = "named_plaintext_file"
    case credentialProtocol = "credential_protocol"

    /// Compatibility mechanisms that deliberately expose plaintext outside a
    /// protected consumer heap/fd/capability boundary. Policy applies explicit
    /// review, authentication, and risk-capped reuse rather than treating the
    /// weaker delivery choice itself as an integrity failure.
    public var isWeakCompatibility: Bool {
        switch self {
        case .unrestrictedInitialEnvironment, .rawStandardOutput, .namedPlaintextFile:
            return true
        default:
            return false
        }
    }
}

public enum ConsumerAssurance: String, Codable, Sendable, CaseIterable {
    /// Exact Convenient Security product code verified from a live audit token.
    case verifiedProduct = "verified_product"
    /// Executable and every controlling path component are independently
    /// protected from the login user (normally root-owned and not group/world writable).
    case independentlyProtected = "independently_protected"
    case userWritable = "user_writable"
    case unverified = "unverified"
    case sealed = "sealed"
}

public enum DescendantScope: String, Codable, Sendable, CaseIterable {
    case exactProcess = "exact_process"
    case subtree
    case broadSession = "broad_session"
}

public enum DestinationClass: String, Codable, Sendable, CaseIterable {
    case localDevelopment = "local_development"
    case staging
    case production
    case aiTool = "ai_tool"
    case humanOutput = "human_output"
    case shellDelegatedPipe = "shell_delegated_pipe"
    case persistentPlaintextFile = "persistent_plaintext_file"
    case credentialConsumer = "credential_consumer"
    case unknown
}

/// What receives plaintext after the planned emitter. This is deliberately
/// separate from `executable`: for `csec get`, signed csec emits the bytes but
/// cannot authenticate a generic pipeline reader or protect an ordinary file.
public enum RecipientAssurance: String, Codable, Sendable, CaseIterable {
    case interactiveTerminal = "interactive_terminal"
    case unverifiedPipeReader = "unverified_pipe_reader"
    case ordinaryPersistentFile = "ordinary_persistent_file"
}

/// The process to which a successful subtree grant is rooted. Only the signed
/// launcher may ask for its direct parent, and the agent independently verifies
/// the actual PPID and start time before honoring it.
public enum DeliveryRoot: Codable, Sendable, Equatable {
    case caller
    case directParent(pid: pid_t, startTime: UInt64)
    /// An opaque daemon registration created by `csec session`. The identifier
    /// is only a lookup hint: csecd still proves that the access caller descends
    /// from the registered PID with the registered process start time.
    case registeredSession(id: String)

    private enum CodingKeys: String, CodingKey { case kind, pid, startTime, id }
    private enum Kind: String, Codable {
        case caller
        case directParent = "direct_parent"
        case registeredSession = "registered_session"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        switch try container.decode(Kind.self, forKey: .kind) {
        case .caller:
            self = .caller
        case .directParent:
            self = .directParent(
                pid: try container.decode(pid_t.self, forKey: .pid),
                startTime: try container.decode(UInt64.self, forKey: .startTime)
            )
        case .registeredSession:
            self = .registeredSession(id: try container.decode(String.self, forKey: .id))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .caller:
            try container.encode(Kind.caller, forKey: .kind)
        case let .directParent(pid, startTime):
            try container.encode(Kind.directParent, forKey: .kind)
            try container.encode(pid, forKey: .pid)
            try container.encode(startTime, forKey: .startTime)
        case let .registeredSession(id):
            try container.encode(Kind.registeredSession, forKey: .kind)
            try container.encode(id, forKey: .id)
        }
    }
}

/// Value-free description of the intended consumer. These fields are claims
/// made by the signed launcher and are re-resolved by stronger launchers where
/// a policy requires it. They are never accepted from an arbitrary interpreter.
public struct PlannedExecutable: Codable, Sendable, Equatable {
    public let canonicalPath: String
    public let signingIdentifier: String?
    public let teamIdentifier: String?
    public let cdHash: String?
    public let assurance: ConsumerAssurance

    public init(
        canonicalPath: String,
        signingIdentifier: String? = nil,
        teamIdentifier: String? = nil,
        cdHash: String? = nil,
        assurance: ConsumerAssurance
    ) {
        self.canonicalPath = canonicalPath
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.cdHash = cdHash
        self.assurance = assurance
    }
}

/// Complete, plaintext-free context for one release decision.
public struct DeliveryPlan: Codable, Sendable, Equatable {
    public let mechanism: DeliveryMechanism
    /// The process that directly receives or emits the plaintext bytes.
    public let executable: PlannedExecutable
    /// Optional identity of a direct-parent requester when it differs from the
    /// byte consumer. The signed launcher supplies this for interactive
    /// `csec get`, and csecd independently resolves the parent before use.
    /// It is invalid for caller and registered-session roots.
    public let requestingExecutable: PlannedExecutable?
    public let root: DeliveryRoot
    public let descendantScope: DescendantScope
    public let destination: DestinationClass
    /// Explicit final-recipient semantics for compatibility output. It carries
    /// no file name, command line, secret reference, or secret value.
    public let recipientAssurance: RecipientAssurance?
    public let requestedTTLSeconds: Int
    /// A bounded human description (for example "rails boot"), never argv.
    public let operationContext: String
    /// SHA-256 of the launcher's canonical command representation. This binds a
    /// decision without putting potentially sensitive argv into protocol JSON.
    public let commandDigest: String?
    /// Output behavior declared and digest-bound for this launch. It is required
    /// for unrestricted environment exec and nil for unrelated mechanisms.
    public let outputGuard: OutputGuardPlan?
    /// Whether the requesting launcher observed a controlling terminal on its
    /// own std descriptors (a human is interactively present). Value-free and
    /// digest-bound; the agent uses it to distinguish an interactive human `csec
    /// get` (pipe to a command is fine) from an automated/agent capture, which is
    /// steered toward injection and requires an explicit acknowledgment.
    public let interactive: Bool
    /// Whether the user passed the shape-appropriate override flag (`--reveal`
    /// for an observing sink, `--allow-plaintext-file` for a persistent file) to
    /// accept raw-plaintext exposure. The launcher only sets this when the exact
    /// matching flag is present; the agent re-derives whether it is required.
    public let plaintextExposureAcknowledged: Bool

    public init(
        mechanism: DeliveryMechanism,
        executable: PlannedExecutable,
        requestingExecutable: PlannedExecutable? = nil,
        root: DeliveryRoot = .caller,
        descendantScope: DescendantScope,
        destination: DestinationClass,
        recipientAssurance: RecipientAssurance? = nil,
        requestedTTLSeconds: Int,
        operationContext: String,
        commandDigest: String? = nil,
        outputGuard: OutputGuardPlan? = nil,
        interactive: Bool = false,
        plaintextExposureAcknowledged: Bool = false
    ) {
        self.mechanism = mechanism
        self.executable = executable
        self.requestingExecutable = requestingExecutable
        self.root = root
        self.descendantScope = descendantScope
        self.destination = destination
        self.recipientAssurance = recipientAssurance
        self.requestedTTLSeconds = requestedTTLSeconds
        self.operationContext = operationContext
        self.commandDigest = commandDigest
        self.outputGuard = outputGuard
        self.interactive = interactive
        self.plaintextExposureAcknowledged = plaintextExposureAcknowledged
    }

    /// Stable digest used in grants and decision/release binding.
    public func digest() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    /// Everything about a release *except* which command performs it.
    private struct ReleaseShape: Encodable {
        let mechanism: DeliveryMechanism
        let descendantScope: DescendantScope
        let destination: DestinationClass
        let recipientAssurance: RecipientAssurance?
        let outputGuard: OutputGuardPlan?
        let interactive: Bool
        let plaintextExposureAcknowledged: Bool
    }

    /// Digest of the exposure shape of a release, used as the reuse key for a
    /// grant the human deliberately widened past the requesting command.
    ///
    /// It deliberately omits `executable`, `requestingExecutable`, `root`,
    /// `requestedTTLSeconds`, `operationContext`, and `commandDigest`: a widened
    /// scope means "anything this subtree runs", so binding the exact command
    /// would defeat it. It retains every field that decides how much plaintext
    /// exposure the human accepted, so an approved sealed/fd/credential-protocol
    /// release can never be silently reused as a raw-plaintext one.
    ///
    /// The digest is domain-separated from `digest()` so the two values can
    /// never be compared or substituted for one another.
    public func releaseShapeDigest() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(ReleaseShape(
            mechanism: mechanism,
            descendantScope: descendantScope,
            destination: destination,
            recipientAssurance: recipientAssurance,
            outputGuard: outputGuard,
            interactive: interactive,
            plaintextExposureAcknowledged: plaintextExposureAcknowledged
        ))
        var hasher = SHA256()
        hasher.update(data: Data("csec-release-shape-v1".utf8))
        hasher.update(data: bytes)
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    public static func directHeap(
        executablePath: String,
        root: DeliveryRoot = .caller,
        assurance: ConsumerAssurance = .unverified,
        ttlSeconds: Int,
        operationContext: String
    ) -> DeliveryPlan {
        DeliveryPlan(
            mechanism: .directHeap,
            executable: PlannedExecutable(
                canonicalPath: executablePath,
                assurance: assurance
            ),
            root: root,
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: ttlSeconds,
            operationContext: operationContext
        )
    }
}
