import Foundation

/// Output masking behavior for a release. Semantics are unchanged from before the
/// risk-level collapse; the value is now derived purely from the delivery
/// mechanism rather than from a per-credential risk classification.
///
/// `stopAndSuppressOnMatch` is retained for wire/test compatibility but is no
/// longer produced: every masked path now redacts in-band and warns.
public enum OutputPolicy: String, Codable, Sendable {
    case exactMatchRedactAndWarn = "exact_match_redact_warn"
    case stopAndSuppressOnMatch = "stop_and_suppress_on_match"
    case intentionalCredentialChannel = "intentional_credential_channel"
}

/// The only pre-resolution refusals that remain after the risk taxonomy is gone.
/// Everything the old table gated on a classification is now advisory (a warning
/// in the trusted review) plus Touch ID.
public enum PolicyDenialReason: String, Codable, Sendable {
    case invalidTTL = "invalid_ttl"
    /// A `csec get` shape that emits a raw plaintext value to an observing sink
    /// (interactive terminal, a non-interactive/agent capture) or a persistent
    /// file was requested without the matching override flag (`--reveal` /
    /// `--allow-plaintext-file`).
    case plaintextExposureNotAcknowledged = "plaintext_exposure_not_acknowledged"
}

/// The value-free decision the agent makes before it resolves a value. After the
/// collapse this is deliberately tiny: a bounded grant lifetime, a mechanism-
/// derived output policy, and the `csec get` plaintext-exposure gate. There is no
/// risk level, no classification, no compatibility-acceptance ledger.
public struct ReleaseDecision: Sendable, Equatable {
    public let allowed: Bool
    public let denialReason: PolicyDenialReason?
    public let grantedTTLSeconds: Int
    public let outputPolicy: OutputPolicy
    /// Whether this plan is a raw-plaintext `csec get` shape that requires an
    /// explicit override. Surfaced so the trusted review can explain the gate.
    public let requiresPlaintextAcknowledgement: Bool

    public init(
        allowed: Bool,
        denialReason: PolicyDenialReason?,
        grantedTTLSeconds: Int,
        outputPolicy: OutputPolicy,
        requiresPlaintextAcknowledgement: Bool
    ) {
        self.allowed = allowed
        self.denialReason = denialReason
        self.grantedTTLSeconds = grantedTTLSeconds
        self.outputPolicy = outputPolicy
        self.requiresPlaintextAcknowledgement = requiresPlaintextAcknowledgement
    }
}

/// The post-collapse release policy. One Touch ID over a value-free display-only
/// review authorizes a release; a grant then covers the requesting process
/// subtree for a bounded lifetime. The only hard, non-advisory refusals are an
/// invalid TTL and an unacknowledged raw-plaintext `csec get` shape.
public enum ReleasePolicy {
    /// Default grant lifetime when the launcher does not request one; the
    /// launcher also defaults `--for` to this. A single Touch ID keeps a
    /// credential usable within its shell/subtree for the working day.
    public static let defaultTTLSeconds = 12 * 60 * 60
    /// Hard backstop so a typo (`--for 999999`) cannot mint a multi-day grant in
    /// the resident daemon. `--for` overrides the default up to this cap.
    public static let maxTTLSeconds = 24 * 60 * 60

    public static func evaluate(plan: DeliveryPlan) -> ReleaseDecision {
        let ackRequired = plaintextAcknowledgementRequired(plan)
        let denial: PolicyDenialReason?
        if plan.requestedTTLSeconds <= 0 {
            denial = .invalidTTL
        } else if ackRequired && !plan.plaintextExposureAcknowledged {
            denial = .plaintextExposureNotAcknowledged
        } else {
            denial = nil
        }
        let granted = min(max(plan.requestedTTLSeconds, 0), maxTTLSeconds)
        let output: OutputPolicy =
            plan.mechanism == .credentialProtocol
            ? .intentionalCredentialChannel
            : .exactMatchRedactAndWarn
        return ReleaseDecision(
            allowed: denial == nil,
            denialReason: denial,
            grantedTTLSeconds: granted,
            outputPolicy: output,
            requiresPlaintextAcknowledgement: ackRequired
        )
    }

    /// Which `csec get` shapes must carry an explicit override before a raw value
    /// is emitted. Protected mechanisms (heap, fd, capability-GID, credential
    /// protocol, sealed/restricted env) never require one — Touch ID alone
    /// authorizes them. Among the raw-output shapes:
    ///   - a persistent plaintext file always requires `--allow-plaintext-file`;
    ///   - an interactive terminal (scrollback) always requires `--reveal`;
    ///   - a pipe/socket (or other sink) requires `--reveal` only when no
    ///     interactive human is present — an interactive human explicitly piping
    ///     to a command is the intended path and needs nothing.
    /// The agent re-derives this from value-free, digest-bound plan fields, so a
    /// launcher cannot skip the gate by omitting the acknowledgment.
    public static func plaintextAcknowledgementRequired(_ plan: DeliveryPlan) -> Bool {
        switch plan.mechanism {
        case .namedPlaintextFile:
            return true
        case .rawStandardOutput:
            if plan.recipientAssurance == .interactiveTerminal { return true }
            return !plan.interactive
        default:
            return false
        }
    }
}
