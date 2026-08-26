import Foundation
#if canImport(AppKit)
@preconcurrency import AppKit
#endif

/// One logical credential shown in a trusted access-policy review. It contains
/// reference metadata and opaque identity only, never a resolved value.
public struct PolicyReviewCredential: Sendable {
    public let identity: CredentialIdentity
    public let references: [SecretRef]
    public let storedLevel: RiskLevel
    public let scopeExpanded: Bool
    public let compatibilityReviewOffered: Bool
    public let compatibilityAccepted: Bool

    public init(
        identity: CredentialIdentity,
        references: [SecretRef],
        storedLevel: RiskLevel,
        scopeExpanded: Bool,
        compatibilityReviewOffered: Bool,
        compatibilityAccepted: Bool
    ) {
        self.identity = identity
        self.references = references.sorted { $0.uri < $1.uri }
        self.storedLevel = storedLevel
        self.scopeExpanded = scopeExpanded
        self.compatibilityReviewOffered = compatibilityReviewOffered
        self.compatibilityAccepted = compatibilityAccepted
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
/// path, argv, reference value, or resolved secret, so compatibility warnings
/// cannot accidentally disclose the redirection target or plaintext.
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

    public static func warning(for review: AccessPolicyReview) -> String? {
        let deliveryWarning: String
        switch review.plan.recipientAssurance {
        case .unverifiedPipeReader:
            deliveryWarning = """
            UNVERIFIED PIPE READER: The requesting shell delegates csec's output, but generic Unix pipelines do not reveal or authenticate the sibling process that reads it. That reader can retain or forward the plaintext. Prefer csec exec, exec-fd, exec-file, or a credential helper when practical.
            """
        case .ordinaryPersistentFile:
            deliveryWarning = """
            PERSISTENT PLAINTEXT FILE: Plaintext will persist in an ordinary file. Other processes running as you may be able to read it. Convenient Security cannot control copying, backups, synchronization, or later access. Prefer csec exec-file for a protected regular file.
            """
        case .interactiveTerminal:
            deliveryWarning = """
            TERMINAL PLAINTEXT: The value will be displayed in the requesting terminal and may be retained by terminal logging, scrollback, or screen capture.
            """
        case nil:
            return nil
        }

        let effective = RiskLevel.maximum(review.credentials.map(\.storedLevel))
        switch effective {
        case .critical:
            return "CRITICAL-RISK DELIVERY — strongest warning. Fresh Touch ID is required and reuse is limited to the very short live grant.\n\n\(deliveryWarning)"
        case .high, .unknown:
            return "HIGH-RISK DELIVERY — strong warning. Fresh Touch ID is required and reuse is limited to the short live grant.\n\n\(deliveryWarning)"
        case .low, .standard:
            return deliveryWarning
        }
    }

    public static func compatibilityAcceptanceLabel(
        for plan: DeliveryPlan,
        storedLevel: RiskLevel
    ) -> String {
        let shape: String
        switch plan.recipientAssurance {
        case .interactiveTerminal: shape = "terminal plaintext output"
        case .unverifiedPipeReader: shape = "shell-delegated pipe with an unverified reader"
        case .ordinaryPersistentFile: shape = "ordinary persistent plaintext-file delivery"
        case nil: shape = plan.mechanism.rawValue
        }
        switch storedLevel {
        case .standard:
            return "Accept \(shape) for 30 days"
        case .high:
            return "Explicitly approve \(shape) for this short live grant"
        case .critical:
            return "Explicitly approve \(shape) for this very short live grant"
        case .unknown:
            return "Approve \(shape); high/critical approval is limited to this live grant"
        case .low:
            return "Approve \(shape)"
        }
    }
}

public struct AccessPolicyApproval: Sendable {
    /// Entries are accepted only for credentials that were previously unknown.
    public let classifications: [String: RiskLevel]
    /// Separate affirmative acceptance of a weak compatibility mechanism.
    public let acceptedCompatibilityCredentialKeys: Set<String>
    /// A trusted review can authenticate inside its window, freeze the exact
    /// visible choices, and retain the evaluated context while the agent checks
    /// those choices. Injected/headless reviewers leave this nil and use the
    /// ordinary ConsentProvider instead.
    public let authenticationSession: (any AccessPolicyAuthenticationSession)?

    public init(
        classifications: [String: RiskLevel],
        acceptedCompatibilityCredentialKeys: Set<String>,
        authenticationSession: (any AccessPolicyAuthenticationSession)? = nil
    ) {
        self.classifications = classifications
        self.acceptedCompatibilityCredentialKeys = acceptedCompatibilityCredentialKeys
        self.authenticationSession = authenticationSession
    }
}

/// The policy-bound completion of a trusted access review. Production may start
/// Touch ID while the user reviews the value-free choices, but it must freeze
/// the choices on biometric success and retain the evaluated context here. The
/// agent calls `completeAfterPolicyApproval` only after independently accepting
/// that snapshot; a rejection calls `cancel` and no context, value, or persistent
/// choice leaves the session.
///
/// This is a dependency-injection seam, like PolicyReviewProvider and
/// ConsentProvider. The shipping daemon constructs only TrustedPolicyReview.
public protocol AccessPolicyAuthenticationSession: Sendable {
    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome
    func cancel() async
}

public enum AccessPolicyReviewOutcome: Sendable {
    case denied
    case approved(AccessPolicyApproval)
}

public struct RiskChangeReview: Sendable {
    public let caller: CallerInfo
    public let operation: RiskOperation
    public let reference: SecretRef
    public let currentLevel: RiskLevel
    public let requestedLevel: RiskLevel?
    public let knownMemberCount: Int
    public let scopeExpanded: Bool
    public let requiresBiometric: Bool

    public init(
        caller: CallerInfo,
        operation: RiskOperation,
        reference: SecretRef,
        currentLevel: RiskLevel,
        requestedLevel: RiskLevel?,
        knownMemberCount: Int,
        scopeExpanded: Bool,
        requiresBiometric: Bool
    ) {
        self.caller = caller
        self.operation = operation
        self.reference = reference
        self.currentLevel = currentLevel
        self.requestedLevel = requestedLevel
        self.knownMemberCount = knownMemberCount
        self.scopeExpanded = scopeExpanded
        self.requiresBiometric = requiresBiometric
    }
}

public protocol PolicyReviewProvider: Sendable {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome
    func reviewRiskChange(_ review: RiskChangeReview) async -> Bool
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
    private let defaultLevel: RiskLevel
    private let acceptWeakCompatibility: Bool

    public init(defaultLevel: RiskLevel = .low, acceptWeakCompatibility: Bool = true) {
        precondition(defaultLevel != .unknown)
        self.defaultLevel = defaultLevel
        self.acceptWeakCompatibility = acceptWeakCompatibility
    }

    public func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        let classifications = Dictionary(uniqueKeysWithValues: review.credentials.compactMap {
            $0.storedLevel == .unknown ? ($0.identity.credentialKey, defaultLevel) : nil
        })
        let accepted = acceptWeakCompatibility && review.plan.mechanism.isWeakCompatibility
            ? Set(review.credentials.map { $0.identity.credentialKey })
            : []
        FileHandle.standardError.write(Data(
            "⚠️  AutoApprovePolicyReview: approving value-free policy metadata WITHOUT a human. DEV ONLY.\n".utf8
        ))
        return .approved(AccessPolicyApproval(
            classifications: classifications,
            acceptedCompatibilityCredentialKeys: accepted
        ))
    }

    public func reviewRiskChange(_ review: RiskChangeReview) async -> Bool {
        FileHandle.standardError.write(Data(
            "⚠️  AutoApprovePolicyReview: approving a risk change WITHOUT a human. DEV ONLY.\n".utf8
        ))
        return true
    }

    public func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        FileHandle.standardError.write(Data(
            "⚠️  AutoApprovePolicyReview: approving host remediation WITHOUT a human. DEV ONLY.\n".utf8
        ))
        return .approved(selectedKeys: review.items.map(\.key))
    }
}

/// AppKit review rendered by the authenticated resident agent. The selection
/// crosses no untrusted IPC boundary: csecd owns both the controls and policy
/// decision, and embeds Touch ID in that same trusted window. The exact choices
/// visible at biometric success are still checked before persistence or release.
public struct TrustedPolicyReview: PolicyReviewProvider {
    public init() {}

    public func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
        return await TrustedAccessReviewSession.present(review)
        #else
        return .denied
        #endif
    }

    public func reviewRiskChange(_ review: RiskChangeReview) async -> Bool {
        #if canImport(AppKit)
        return await MainActor.run { Self.presentRiskChange(review) }
        #else
        return false
        #endif
    }

    public func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        #if canImport(AppKit)
        return await HostRemediationReviewSession.present(review)
        #else
        return .denied
        #endif
    }

    #if canImport(AppKit)
    @MainActor
    private static func presentRiskChange(_ review: RiskChangeReview) -> Bool {
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        let alert = NSAlert()
        alert.alertStyle = review.operation == .forget ? .warning : .informational
        alert.messageText = "Confirm secret risk change"
        let requested = review.requestedLevel?.rawValue ?? "unknown (forgotten)"
        let scope = review.scopeExpanded
            ? " The supplied reference will be added to the known credential scope."
            : ""
        let authentication = review.requiresBiometric
            ? " Touch ID will confirm this downgrade or reset."
            : ""
        alert.informativeText = """
        Operation: \(review.operation.rawValue)
        Reference: \(review.reference.safeInlineURI)
        Current risk: \(review.currentLevel.rawValue)
        Resulting risk: \(requested)
        Known members: \(review.knownMemberCount)

        This changes only value-free policy metadata; no secret value is read.\(scope)\(authentication)
        """
        alert.addButton(withTitle: review.requiresBiometric ? "Continue to Touch ID" : "Confirm")
        alert.addButton(withTitle: "Cancel")
        alert.window.title = "Convenient Security"
        alert.window.isRestorable = false
        application.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertFirstButtonReturn
    }

    private static func safe(_ value: String) -> String {
        let bidiControls: Set<UInt32> = [
            0x061c, 0x200e, 0x200f,
            0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
            0x2066, 0x2067, 0x2068, 0x2069,
        ]
        return value.unicodeScalars.map { scalar in
            if CharacterSet.controlCharacters.contains(scalar)
                || CharacterSet.newlines.contains(scalar)
                || bidiControls.contains(scalar.value) {
                return "�"
            }
            return String(scalar)
        }.joined()
    }
    #endif
}
