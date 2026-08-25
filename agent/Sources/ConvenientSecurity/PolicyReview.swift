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

public struct AccessPolicyApproval: Sendable {
    /// Entries are accepted only for credentials that were previously unknown.
    public let classifications: [String: RiskLevel]
    /// Separate affirmative acceptance of a weak compatibility mechanism.
    public let acceptedCompatibilityCredentialKeys: Set<String>
    /// A trusted review can keep its window open and perform Touch ID inside it
    /// after the agent has validated the selected policy. Injected/headless
    /// reviewers leave this nil and use the ordinary ConsentProvider instead.
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

/// The second half of a trusted access review. The review window first returns
/// the user's value-free policy selections; only after the agent independently
/// accepts those selections does it ask this session to authenticate in-place.
///
/// This is a dependency-injection seam, like PolicyReviewProvider and
/// ConsentProvider. The shipping daemon constructs only TrustedPolicyReview.
public protocol AccessPolicyAuthenticationSession: Sendable {
    func authenticate(localizedReason: String, policySummary: String) async -> ConsentOutcome
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
}

/// AppKit review rendered by the authenticated resident agent. The selection
/// crosses no untrusted IPC boundary: csecd owns both the controls and policy
/// decision, then embeds Touch ID in that same trusted window before any choice
/// is persisted or any value is released.
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
