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
    /// protected consumer heap/fd/capability boundary. Standard-risk use needs
    /// a separately cached acceptance; high and critical policy forbid them.
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
    case credentialConsumer = "credential_consumer"
    case unknown
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
    public let executable: PlannedExecutable
    public let root: DeliveryRoot
    public let descendantScope: DescendantScope
    public let destination: DestinationClass
    public let requestedTTLSeconds: Int
    /// A bounded human description (for example "rails boot"), never argv.
    public let operationContext: String
    /// SHA-256 of the launcher's canonical command representation. This binds a
    /// decision without putting potentially sensitive argv into protocol JSON.
    public let commandDigest: String?
    /// Output behavior declared and digest-bound for this launch. It is required
    /// for unrestricted environment exec and nil for unrelated mechanisms.
    public let outputGuard: OutputGuardPlan?

    public init(
        mechanism: DeliveryMechanism,
        executable: PlannedExecutable,
        root: DeliveryRoot = .caller,
        descendantScope: DescendantScope,
        destination: DestinationClass,
        requestedTTLSeconds: Int,
        operationContext: String,
        commandDigest: String? = nil,
        outputGuard: OutputGuardPlan? = nil
    ) {
        self.mechanism = mechanism
        self.executable = executable
        self.root = root
        self.descendantScope = descendantScope
        self.destination = destination
        self.requestedTTLSeconds = requestedTTLSeconds
        self.operationContext = operationContext
        self.commandDigest = commandDigest
        self.outputGuard = outputGuard
    }

    /// Stable digest used in grants and decision/release binding.
    public func digest() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
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
