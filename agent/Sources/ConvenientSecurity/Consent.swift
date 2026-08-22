import Foundation

/// What the agent knows about a connecting process.
public struct CallerInfo: Sendable {
    public let pid: pid_t
    public let startTime: UInt64
    /// Kernel audit token plus live code-signing result for socket callers.
    /// Nil is reserved for dependency-injected unit tests and non-socket uses.
    public let peerIdentity: PeerIdentity?
    /// Human-facing description. For a signed binary this can be its verified
    /// code-signing identity; for an interpreted client, best-effort + unverified.
    public var description: String

    public init(
        pid: pid_t,
        startTime: UInt64,
        description: String,
        peerIdentity: PeerIdentity? = nil
    ) {
        self.pid = pid
        self.startTime = startTime
        self.description = description
        self.peerIdentity = peerIdentity
    }
}

/// The result of asking a human to approve newly-requested references. On
/// approval it may carry a `CacheUnlock`—the biometric context that was just
/// evaluated—so cold cache or native-key access can fold into the same touch.
public enum ConsentOutcome: Sendable {
    case denied
    case approved(unlock: CacheUnlock?)

    public var isApproved: Bool {
        if case .approved = self { return true }
        return false
    }

    /// The unlock context, if the decision was an approval that produced one.
    public var unlock: CacheUnlock? {
        if case let .approved(unlock) = self { return unlock }
        return nil
    }
}

/// Presents consent for newly-requested references and returns the decision.
/// The production implementation puts bounded request details in the localized
/// reason of a fresh Touch ID evaluation; see DESIGN.md (Consent).
public protocol ConsentProvider: Sendable {
    func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval,
        policySummary: String?
    ) async -> ConsentOutcome

    /// Fresh OS authentication for a policy mutation that releases no value.
    func authenticate(reason: String) async -> ConsentOutcome
}

/// Dev-only consent that approves everything, announcing itself loudly so it can
/// never be mistaken for the real gate. NOT for production.
public struct AutoApproveConsent: ConsentProvider {
    public init() {}

    public func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval,
        policySummary: String?
    ) async -> ConsentOutcome {
        let refs = newReferences.map(\.uri).joined(separator: ", ")
        FileHandle.standardError.write(Data(
            "⚠️  AutoApproveConsent: approving [\(refs)] for \(caller.description) WITHOUT a human. DEV ONLY.\n".utf8
        ))
        // No biometric context (there was no human/touch); cold cache reads stay
        // suppressed, which is correct for a headless approval.
        return .approved(unlock: nil)
    }

    public func authenticate(reason: String) async -> ConsentOutcome {
        FileHandle.standardError.write(Data(
            "⚠️  AutoApproveConsent: authenticating policy metadata WITHOUT a human. DEV ONLY.\n".utf8
        ))
        return .approved(unlock: nil)
    }
}
