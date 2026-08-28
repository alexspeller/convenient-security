import Foundation
#if canImport(AppKit)
@preconcurrency import AppKit
#endif

/// One logical credential shown in a trusted access-policy review. It carries
/// value-free reference metadata only — never a resolved value, and (after the
/// risk-level collapse) no classification or acceptance state.
public struct PolicyReviewCredential: Sendable {
    public let references: [SecretRef]

    public init(references: [SecretRef]) {
        self.references = references.sorted { $0.uri < $1.uri }
    }
}

/// Complete value-free context for the review window owned by csecd.
public struct AccessPolicyReview: Sendable {
    public let caller: CallerInfo
    public let reason: String
    public let plan: DeliveryPlan
    public let credentials: [PolicyReviewCredential]

    public init(
        caller: CallerInfo,
        reason: String,
        plan: DeliveryPlan,
        credentials: [PolicyReviewCredential]
    ) {
        self.caller = caller
        self.reason = reason
        self.plan = plan
        self.credentials = credentials
    }
}

/// Value-free copy for the trusted review window and tests. It never accepts a
/// path, argv, reference value, or resolved secret, so warnings cannot disclose
/// the redirection target or plaintext.
public enum DeliveryReviewCopy {
    public static func recipientDescription(for plan: DeliveryPlan) -> String {
        switch plan.recipientAssurance {
        case .interactiveTerminal:
            return "requesting terminal (interactive human output)"
        case .unverifiedPipeReader:
            return "unverified pipe reader (identity unavailable; delegated by the shell)"
        case .ordinaryPersistentFile:
            return "ordinary persistent file (unverified; potentially same-user readable)"
        case nil:
            return "planned executable consumer"
        }
    }

    /// The warning shown in the trusted window for a same-user-inspectable
    /// delivery. Touch ID authorizes it; this text is the WYSIWYG signal that
    /// lets a human decline. For a non-interactive `csec get` (no controlling
    /// terminal — an agent, script, or logger is capturing the output) it also
    /// steers toward the injection commands, which never return the value here.
    public static func warning(for review: AccessPolicyReview) -> String? {
        let plan = review.plan
        let base: String
        switch plan.recipientAssurance {
        case .unverifiedPipeReader:
            base = "UNVERIFIED PIPE READER: The requesting shell delegates csec's output, but generic Unix pipelines do not reveal or authenticate the sibling process that reads it. That reader can retain or forward the plaintext."
        case .ordinaryPersistentFile:
            base = "PERSISTENT PLAINTEXT FILE: Plaintext will persist in an ordinary file. Other processes running as you may be able to read it. Convenient Security cannot control copying, backups, synchronization, or later access."
        case .interactiveTerminal:
            base = "TERMINAL PLAINTEXT: The value will be printed to the requesting terminal and may be retained by terminal logging, scrollback, or screen capture."
        case nil:
            return nil
        }
        if (plan.mechanism == .rawStandardOutput || plan.mechanism == .namedPlaintextFile)
            && !plan.interactive {
            return base + "\n\nNo interactive terminal is attached — a coding agent, script, or logger appears to be capturing this output and would receive the value. Prefer csec exec, exec-file, or a credential helper, which hand the value to the consuming tool without returning it here."
        }
        return base
    }
}

/// The result of a trusted access review. After the collapse there are no policy
/// choices to return — a successful biometric IS the authorization — so this
/// carries only the optional embedded authentication session used to unlock a
/// cold cache or native-store key with the same Touch ID.
public struct AccessPolicyApproval: Sendable {
    /// A trusted review authenticates inside its own window and retains the
    /// evaluated context so a cold cached value or native-store key can be
    /// unlocked by the same biometric. Injected/headless reviewers leave this
    /// nil and use the ordinary ConsentProvider instead.
    public let authenticationSession: (any AccessPolicyAuthenticationSession)?

    public init(authenticationSession: (any AccessPolicyAuthenticationSession)? = nil) {
        self.authenticationSession = authenticationSession
    }
}

/// The completion seam of a trusted access review. Production starts Touch ID in
/// the review window and, on success, retains the evaluated context here; the
/// agent calls `completeAfterPolicyApproval` to release it, or `cancel` to
/// invalidate it. Injected/headless reviewers leave this unused. This is a
/// dependency-injection seam, like PolicyReviewProvider and ConsentProvider.
public protocol AccessPolicyAuthenticationSession: Sendable {
    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome
    func cancel() async
}

public enum AccessPolicyReviewOutcome: Sendable {
    case denied
    case approved(AccessPolicyApproval)
}

public protocol PolicyReviewProvider: Sendable {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome
    /// Present the batched host-remediation checklist (one review, one Touch ID).
    /// Defaulted so existing reviewers need no change.
    func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome
}

public extension PolicyReviewProvider {
    func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        .denied
    }
}

/// Test-only reviewer. It is constructor-injected and is not selectable through
/// shipping arguments or environment variables.
public struct AutoApprovePolicyReview: PolicyReviewProvider {
    public init() {}

    public func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        FileHandle.standardError.write(Data(
            "⚠️  AutoApprovePolicyReview: approving value-free policy metadata WITHOUT a human. DEV ONLY.\n".utf8
        ))
        return .approved(AccessPolicyApproval())
    }

    public func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        FileHandle.standardError.write(Data(
            "⚠️  AutoApprovePolicyReview: approving host remediation WITHOUT a human. DEV ONLY.\n".utf8
        ))
        return .approved(selectedKeys: review.items.map(\.key))
    }
}

/// AppKit review rendered by the authenticated resident agent. The window shows
/// only value-free metadata and embeds Touch ID in that same trusted surface;
/// there are no editable policy controls, so a successful biometric is itself
/// the authorization. csecd owns the display and the decision.
public struct TrustedPolicyReview: PolicyReviewProvider {
    public init() {}

    public func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
        return await TrustedAccessReviewSession.present(review)
        #else
        return .denied
        #endif
    }

    public func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        #if canImport(AppKit)
        return await HostRemediationReviewSession.present(review)
        #else
        return .denied
        #endif
    }
}
