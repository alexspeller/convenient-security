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
    /// The terminal window and tab the request came from, resolved by the agent
    /// just before a review is shown (it costs an AppleScript round trip, so it
    /// is not computed for every connection). Display-only.
    public var terminal: TerminalSessionContext?
    /// The request's original parent and scope, retained while it waits.
    public var requestAnchor: RequestAnchor?
    /// When csecd accepted the socket connection, in `mach_absolute_time`
    /// ticks: diagnostics time a request's wait before its handler from it.
    public var acceptedAt: UInt64?
    /// When csecd finished checking the peer's code identity, and when it
    /// read this request's frame, in the same ticks. With `acceptedAt` they
    /// split a slow request's wait into csecd's check, the client's own work
    /// before it sent (`csec hook` checks csecd's signature first, which waits
    /// on trustd) and csecd's queue.
    public var identifiedAt: UInt64?
    public var requestReadAt: UInt64?

    public init(
        pid: pid_t,
        startTime: UInt64,
        description: String,
        peerIdentity: PeerIdentity? = nil,
        terminal: TerminalSessionContext? = nil,
        requestAnchor: RequestAnchor? = nil,
        acceptedAt: UInt64? = nil,
        identifiedAt: UInt64? = nil,
        requestReadAt: UInt64? = nil
    ) {
        self.pid = pid
        self.startTime = startTime
        self.description = description
        self.peerIdentity = peerIdentity
        self.terminal = terminal
        self.requestAnchor = requestAnchor
        self.acceptedAt = acceptedAt
        self.identifiedAt = identifiedAt
        self.requestReadAt = requestReadAt
    }

    /// The terminal line every approval surface shows. A caller whose terminal
    /// was never resolved reads as unidentified rather than being omitted.
    public var terminalSummary: String {
        (terminal ?? .unidentified).summary
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

/// Presents consent and returns the decision. Production access review normally
/// authenticates through its embedded session; this seam remains the fallback
/// for injected/headless reviewers and the authenticator for policy mutations.
/// Bounded request details are still placed in the LAContext localized reason.
public protocol ConsentProvider: Sendable {
    func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval?,
        policySummary: String?
    ) async -> ConsentOutcome

    /// Fresh OS authentication for a policy mutation that releases no value.
    func authenticate(reason: String) async -> ConsentOutcome

    /// `authenticate`, saying why a sheet that did not approve ended, for a
    /// caller that logs it and tells the human (the delegation sheets).
    func authenticateExplaining(reason: String) async -> ConsentAnswer

    /// `authenticateExplaining` for a change to csec's own settings that
    /// `caller` asked for, which csecd shows in its own panel
    /// (`SettingsChangeConsent`). `reason` is the same change as one line,
    /// for a provider with no panel.
    func authenticateSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> ConsentAnswer

    /// `authenticateSettingsChange`, also saying where the human decided,
    /// for a change the paired phone may decide (`phoneOperationDigest`).
    func decideSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> SettingsChangeDecision

    /// Whether the paired phone could decide `change` if it were shown now.
    /// Never prompts and contacts no relay.
    func settingsChangeReachesPhone(_ change: SettingsChangeReviewDetails, caller: CallerInfo) async -> Bool
}

/// A settings change's answer, and where the human gave it.
public struct SettingsChangeDecision: Sendable {
    public let answer: ConsentAnswer
    /// `.phone` when the paired iPhone approved; `.mac` from this Mac's
    /// panel; nil from a provider that is no human surface it can name. A
    /// refusal says where in its own `ConsentRefusal.onPhone`.
    public let decidedOn: HumanDecisionSurface?

    public init(answer: ConsentAnswer, decidedOn: HumanDecisionSurface? = nil) {
        self.answer = answer
        self.decidedOn = decidedOn
    }
}

public extension ConsentProvider {
    /// A provider that cannot say why answers `ConsentRefusal.unexplained`.
    func authenticateExplaining(reason: String) async -> ConsentAnswer {
        switch await authenticate(reason: reason) {
        case let .approved(unlock): return .approved(unlock: unlock)
        case .denied: return .refused(.unexplained)
        }
    }

    /// A provider with no panel of its own asks as it asks for anything else.
    func authenticateSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> ConsentAnswer {
        await authenticateExplaining(reason: reason)
    }

    /// A provider with no phone leg cannot say more than its answer.
    func decideSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> SettingsChangeDecision {
        SettingsChangeDecision(answer: await authenticateSettingsChange(change, caller: caller, reason: reason))
    }

    /// A provider with no phone leg decides at this Mac only.
    func settingsChangeReachesPhone(_ change: SettingsChangeReviewDetails, caller: CallerInfo) async -> Bool {
        false
    }
}

/// Dev-only consent that approves everything, announcing itself loudly so it can
/// never be mistaken for the real gate. NOT for production.
public struct AutoApproveConsent: ConsentProvider {
    public init() {}

    public func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval?,
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
