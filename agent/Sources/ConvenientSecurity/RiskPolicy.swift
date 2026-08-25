import Foundation
import CryptoKit

public enum RiskLevel: String, Codable, Sendable, CaseIterable {
    case unknown
    case low
    case standard
    case high
    case critical

    /// Unknown is enforced as high, while remaining distinguishable so policy
    /// can require an explicit classification before release.
    public var effectiveFloor: RiskLevel {
        self == .unknown ? .high : self
    }

    public var severityRank: Int {
        switch effectiveFloor {
        case .low: return 0
        case .standard: return 1
        case .high, .unknown: return 2
        case .critical: return 3
        }
    }

    public static func maximum(_ levels: some Sequence<RiskLevel>) -> RiskLevel {
        levels.map(\.effectiveFloor).max { $0.severityRank < $1.severityRank } ?? .high
    }

    public func isAtLeastAsRestrictive(as other: RiskLevel) -> Bool {
        effectiveFloor.severityRank >= other.effectiveFloor.severityRank
    }
}

/// Opaque logical capability identity. No provider URI, item name, or value is
/// required in the judgment store.
public struct CredentialIdentity: Codable, Sendable, Equatable {
    public let provider: String
    public let providerAccountKey: String
    public let credentialKey: String
    public let memberReferenceKeys: [String]

    public init(
        provider: String,
        providerAccountKey: String,
        credentialKey: String,
        memberReferenceKeys: [String]
    ) {
        self.provider = provider
        self.providerAccountKey = providerAccountKey
        self.credentialKey = credentialKey
        self.memberReferenceKeys = memberReferenceKeys.sorted()
    }
}

public enum RiskEvidenceSource: String, Codable, Sendable {
    case explicitUser = "explicit_user"
    case signedOrganizationPolicy = "signed_organization_policy"
    case devicePolicy = "device_policy"
    case providerMetadata = "provider_metadata"
    case repositoryFloor = "repository_floor"
    case heuristicProposal = "heuristic_proposal"
}

public enum RiskEvidenceCategory: String, Codable, Sendable {
    case environment
    case dataClass = "data_class"
    case authority
    case scope
    case lifetime
    case revocability
    case auditability
    case recoveryCost = "recovery_cost"
    case providerScope = "provider_scope"
}

/// Evidence can raise an effective level. Only an explicit protected judgment
/// is allowed to lower a previously unknown or higher decision.
public struct RiskEvidence: Codable, Sendable, Equatable {
    public let category: RiskEvidenceCategory
    public let floor: RiskLevel
    public let source: RiskEvidenceSource
    public let evidenceDigest: String
    public let observedAt: Date

    public init(
        category: RiskEvidenceCategory,
        floor: RiskLevel,
        source: RiskEvidenceSource,
        evidenceDigest: String,
        observedAt: Date = Date()
    ) {
        self.category = category
        self.floor = floor
        self.source = source
        self.evidenceDigest = evidenceDigest
        self.observedAt = observedAt
    }
}

public struct RiskJudgment: Codable, Sendable, Equatable {
    public let credential: CredentialIdentity
    public let level: RiskLevel
    public let evidence: [RiskEvidence]
    public let source: RiskEvidenceSource
    public let decidedAt: Date
    public let reviewAfter: Date
    public let policyVersion: Int
    public let providerRevision: String?
    public let observedScopeDigest: String?

    public init(
        credential: CredentialIdentity,
        level: RiskLevel,
        evidence: [RiskEvidence],
        source: RiskEvidenceSource,
        decidedAt: Date,
        reviewAfter: Date,
        policyVersion: Int,
        providerRevision: String? = nil,
        observedScopeDigest: String? = nil
    ) {
        self.credential = credential
        self.level = level
        self.evidence = evidence
        self.source = source
        self.decidedAt = decidedAt
        self.reviewAfter = reviewAfter
        self.policyVersion = policyVersion
        self.providerRevision = providerRevision
        self.observedScopeDigest = observedScopeDigest
    }

    public func isCurrent(at date: Date, policyVersion: Int) -> Bool {
        self.policyVersion == policyVersion && date < reviewAfter
    }
}

/// Explicit acceptance of a weaker compatibility delivery, stored separately
/// from the credential's inherent risk judgment.
public struct CompatibilityDeliveryShape: Codable, Sendable, Equatable {
    public let mechanism: DeliveryMechanism
    public let destination: DestinationClass
    public let descendantScope: DescendantScope
    public let emitterAssurance: ConsumerAssurance
    public let requesterAssurance: ConsumerAssurance?
    public let recipientAssurance: RecipientAssurance?

    public init(plan: DeliveryPlan) {
        self.mechanism = plan.mechanism
        self.destination = plan.destination
        self.descendantScope = plan.descendantScope
        self.emitterAssurance = plan.executable.assurance
        self.requesterAssurance = plan.requestingExecutable?.assurance
        self.recipientAssurance = plan.recipientAssurance
    }
}

public struct DeliveryAcceptance: Codable, Sendable, Equatable {
    public let credentialKey: String
    public let shape: CompatibilityDeliveryShape
    public let policyVersion: Int
    public let acceptedAt: Date
    public let reviewAfter: Date

    public var mechanism: DeliveryMechanism { shape.mechanism }
    public var consumerAssurance: ConsumerAssurance { shape.emitterAssurance }

    public init(
        credentialKey: String,
        shape: CompatibilityDeliveryShape,
        policyVersion: Int,
        acceptedAt: Date,
        reviewAfter: Date
    ) {
        self.credentialKey = credentialKey
        self.shape = shape
        self.policyVersion = policyVersion
        self.acceptedAt = acceptedAt
        self.reviewAfter = reviewAfter
    }

    public func permits(
        credentialKey: String,
        plan: DeliveryPlan,
        policyVersion: Int,
        at date: Date
    ) -> Bool {
        self.credentialKey == credentialKey
            && shape == CompatibilityDeliveryShape(plan: plan)
            && self.policyVersion == policyVersion
            && date < reviewAfter
    }
}

public enum OutputPolicy: String, Codable, Sendable {
    case exactMatchRedactAndWarn = "exact_match_redact_warn"
    case stopAndSuppressOnMatch = "stop_and_suppress_on_match"
    case intentionalCredentialChannel = "intentional_credential_channel"
}

public enum PolicyDenialReason: String, Codable, Sendable {
    case classificationRequired = "classification_required"
    case invalidTTL = "invalid_ttl"
    case mechanismForbidden = "mechanism_forbidden"
    case compatibilityAcceptanceRequired = "compatibility_acceptance_required"
    case consumerAssuranceInsufficient = "consumer_assurance_insufficient"
    case descendantScopeTooBroad = "descendant_scope_too_broad"
    case destinationForbidden = "destination_forbidden"
}

public struct RiskPolicyInput: Sendable {
    public let credentialKey: String
    public let storedLevel: RiskLevel
    public let evidence: [RiskEvidence]
    public let plan: DeliveryPlan
    public let acceptance: DeliveryAcceptance?
    public let now: Date

    public init(
        credentialKey: String,
        storedLevel: RiskLevel,
        evidence: [RiskEvidence],
        plan: DeliveryPlan,
        acceptance: DeliveryAcceptance? = nil,
        now: Date = Date()
    ) {
        self.credentialKey = credentialKey
        self.storedLevel = storedLevel
        self.evidence = evidence
        self.plan = plan
        self.acceptance = acceptance
        self.now = now
    }
}

public struct PolicyDecision: Codable, Sendable, Equatable {
    public let policyVersion: Int
    public let effectiveLevel: RiskLevel
    public let classificationRequired: Bool
    public let allowed: Bool
    public let denialReason: PolicyDenialReason?
    public let ttlCapSeconds: Int
    public let grantedTTLSeconds: Int
    public let allowedMechanisms: [DeliveryMechanism]
    public let requiredConsumerAssurance: [ConsumerAssurance]
    public let requiresFreshBiometric: Bool
    public let outputPolicy: OutputPolicy
    public let policyDigest: String
}

/// Single, versioned policy table used by the shipping agent before it resolves
/// plaintext. Review windows live beside the mechanism/TTL matrix so UI, grant,
/// and persistence code cannot silently choose different policy lifetimes.
public enum RiskPolicyV2 {
    public static let version = 2
    public static let judgmentReviewSeconds = 90 * 24 * 60 * 60
    public static let compatibilityAcceptanceReviewSeconds = 30 * 24 * 60 * 60

    public static func evaluate(_ input: RiskPolicyInput) -> PolicyDecision {
        let effective = RiskLevel.maximum(
            [input.storedLevel] + input.evidence.map(\.floor) + destinationFloors(input.plan.destination)
        )
        let classificationRequired = input.storedLevel == .unknown
        let rule = rule(for: effective)
        var mechanisms = rule.mechanisms
        var denial: PolicyDenialReason?
        let compatibilityApprovalRequired = effective != .low
            && input.plan.mechanism.isWeakCompatibility
        let hasCompatibilityApproval = input.acceptance?.permits(
            credentialKey: input.credentialKey,
            plan: input.plan,
            policyVersion: version,
            at: input.now
        ) == true

        if hasCompatibilityApproval {
            mechanisms.insert(input.plan.mechanism)
        }

        if classificationRequired {
            denial = .classificationRequired
        } else if input.plan.requestedTTLSeconds <= 0 {
            denial = .invalidTTL
        } else if !rule.assurances.contains(input.plan.executable.assurance) {
            denial = .consumerAssuranceInsufficient
        } else if (effective == .high || effective == .critical)
                    && input.plan.destination == .aiTool {
            denial = .destinationForbidden
        } else if input.plan.destination == .aiTool
                    && input.plan.descendantScope != .exactProcess {
            // Merely naming an AI tool as the destination must not turn every
            // command it may later launch into an implicit standard-risk grant.
            denial = .descendantScopeTooBroad
        } else if effective == .high && input.plan.descendantScope == .broadSession {
            // High-impact credentials keep a per-command root. A convenience
            // session deliberately expands trust to sibling descendants.
            denial = .descendantScopeTooBroad
        } else if effective == .critical
                    && input.plan.descendantScope != .exactProcess
                    && !isShellScopedGetCompatibility(input.plan) {
            denial = .descendantScopeTooBroad
        } else if compatibilityApprovalRequired && !hasCompatibilityApproval {
            denial = .compatibilityAcceptanceRequired
        } else if !mechanisms.contains(input.plan.mechanism) {
            denial = .mechanismForbidden
        }

        let grantedTTL = min(max(input.plan.requestedTTLSeconds, 0), rule.ttlCap)
        let outputPolicy: OutputPolicy
        if input.plan.mechanism == .credentialProtocol {
            outputPolicy = .intentionalCredentialChannel
        } else if effective == .high || effective == .critical {
            outputPolicy = .stopAndSuppressOnMatch
        } else {
            outputPolicy = .exactMatchRedactAndWarn
        }

        let digestMaterial = PolicyDigestMaterial(
            version: version,
            effectiveLevel: effective,
            mechanism: input.plan.mechanism,
            assurance: input.plan.executable.assurance,
            descendantScope: input.plan.descendantScope,
            destination: input.plan.destination,
            recipientAssurance: input.plan.recipientAssurance,
            outputGuard: input.plan.outputGuard,
            ttl: grantedTTL,
            // A live grant is the proof that a transient high/critical
            // compatibility approval occurred. Keep pending-versus-approved
            // acceptance out of this digest so that exact, risk-capped grant
            // can be reused without persisting a broader acceptance.
            compatibilityDelivery: input.plan.mechanism.isWeakCompatibility
        )
        let digest = (try? digestMaterial.digest()) ?? "policy-digest-error"

        return PolicyDecision(
            policyVersion: version,
            effectiveLevel: effective,
            classificationRequired: classificationRequired,
            allowed: denial == nil,
            denialReason: denial,
            ttlCapSeconds: rule.ttlCap,
            grantedTTLSeconds: grantedTTL,
            allowedMechanisms: mechanisms.sorted { $0.rawValue < $1.rawValue },
            requiredConsumerAssurance: rule.assurances.sorted { $0.rawValue < $1.rawValue },
            requiresFreshBiometric: effective == .high || effective == .critical,
            outputPolicy: outputPolicy,
            policyDigest: digest
        )
    }

    private struct Rule {
        let ttlCap: Int
        let mechanisms: Set<DeliveryMechanism>
        let assurances: Set<ConsumerAssurance>
    }

    private static func rule(for level: RiskLevel) -> Rule {
        switch level.effectiveFloor {
        case .low:
            return Rule(
                ttlCap: 12 * 60 * 60,
                mechanisms: Set(DeliveryMechanism.allCases),
                assurances: Set(ConsumerAssurance.allCases)
            )
        case .standard:
            return Rule(
                ttlCap: 4 * 60 * 60,
                mechanisms: [
                    .directHeap, .execHook, .inheritedFileDescriptor,
                    .capabilityGIDFile, .restrictedLateEnvironment,
                    .sealedEnvironment, .credentialProtocol,
                ],
                assurances: Set(ConsumerAssurance.allCases)
            )
        case .high, .unknown:
            return Rule(
                ttlCap: 15 * 60,
                mechanisms: [
                    .directHeap, .execHook, .inheritedFileDescriptor,
                    .capabilityGIDFile, .restrictedLateEnvironment,
                    .sealedEnvironment, .credentialProtocol,
                ],
                assurances: [.verifiedProduct, .independentlyProtected, .sealed]
            )
        case .critical:
            return Rule(
                ttlCap: 5 * 60,
                mechanisms: [
                    .directHeap, .inheritedFileDescriptor,
                    .capabilityGIDFile, .sealedEnvironment,
                    .credentialProtocol,
                ],
                assurances: [.verifiedProduct, .independentlyProtected, .sealed]
            )
        }
    }

    private static func destinationFloors(_ destination: DestinationClass) -> [RiskLevel] {
        switch destination {
        case .production: return [.high]
        case .staging, .aiTool: return [.standard]
        case .unknown: return [.high]
        case .localDevelopment, .humanOutput, .shellDelegatedPipe,
             .persistentPlaintextFile, .credentialConsumer:
            return []
        }
    }

    /// Critical credentials normally require an exact-process root. Signed
    /// `csec get` is the narrow exception: the explicitly verified parent shell
    /// owns a short, digest-bound grant while csec remains the byte emitter.
    private static func isShellScopedGetCompatibility(_ plan: DeliveryPlan) -> Bool {
        guard plan.executable.assurance == .verifiedProduct,
              plan.requestingExecutable != nil,
              plan.descendantScope == .subtree,
              case .directParent = plan.root else { return false }
        switch (plan.mechanism, plan.destination, plan.recipientAssurance) {
        case (.rawStandardOutput, .humanOutput, .interactiveTerminal),
             (.rawStandardOutput, .shellDelegatedPipe, .unverifiedPipeReader),
             (.namedPlaintextFile, .persistentPlaintextFile, .ordinaryPersistentFile):
            return true
        default:
            return false
        }
    }
}

private struct PolicyDigestMaterial: Codable {
    let version: Int
    let effectiveLevel: RiskLevel
    let mechanism: DeliveryMechanism
    let assurance: ConsumerAssurance
    let descendantScope: DescendantScope
    let destination: DestinationClass
    let recipientAssurance: RecipientAssurance?
    let outputGuard: OutputGuardPlan?
    let ttl: Int
    let compatibilityDelivery: Bool

    func digest() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return SHA256.hash(data: try encoder.encode(self)).map {
            String(format: "%02x", $0)
        }.joined()
    }
}
