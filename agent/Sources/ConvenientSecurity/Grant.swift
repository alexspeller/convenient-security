import Foundation

/// Policy state bound to a live grant. Reuse is allowed only when a fresh
/// evaluation for the same raw reference produces this exact binding.
public struct PolicyGrantBinding: Sendable, Equatable {
    public let credentialKey: String
    public let riskLevel: RiskLevel
    public let policyVersion: Int
    public let policyDigest: String
    public let outputPolicy: OutputPolicy

    public init(
        credentialKey: String,
        riskLevel: RiskLevel,
        policyVersion: Int,
        policyDigest: String,
        outputPolicy: OutputPolicy
    ) {
        self.credentialKey = credentialKey
        self.riskLevel = riskLevel
        self.policyVersion = policyVersion
        self.policyDigest = policyDigest
        self.outputPolicy = outputPolicy
    }
}

/// A consented capability: a set of references granted to a process subtree,
/// until `expiresAt`. Held only in the agent's memory-protected heap.
public struct Grant: Sendable, Identifiable {
    public let id: UUID
    /// Root of the granted process subtree (the process that consented).
    public let rootPID: pid_t
    /// Start time of `rootPID` (epoch seconds), to defeat PID reuse.
    public let rootStartTime: UInt64
    public var references: Set<String>
    public let reason: String
    public var expiresAt: Date
    /// Originating v2 request and delivery context. The nonce is audit/binding
    /// metadata, not a bearer token; plan digest compatibility controls reuse.
    public let requestID: String?
    public let deliveryPlanDigest: String?
    public let peerPIDVersion: Int32?
    public let peerCDHash: String?
    public let plannedExecutable: PlannedExecutable?
    public let policyBinding: PolicyGrantBinding?

    public init(
        id: UUID = UUID(),
        rootPID: pid_t,
        rootStartTime: UInt64,
        references: Set<String>,
        reason: String,
        expiresAt: Date,
        requestID: String? = nil,
        deliveryPlanDigest: String? = nil,
        peerPIDVersion: Int32? = nil,
        peerCDHash: String? = nil,
        plannedExecutable: PlannedExecutable? = nil,
        policyBinding: PolicyGrantBinding? = nil
    ) {
        self.id = id
        self.rootPID = rootPID
        self.rootStartTime = rootStartTime
        self.references = references
        self.reason = reason
        self.expiresAt = expiresAt
        self.requestID = requestID
        self.deliveryPlanDigest = deliveryPlanDigest
        self.peerPIDVersion = peerPIDVersion
        self.peerCDHash = peerCDHash
        self.plannedExecutable = plannedExecutable
        self.policyBinding = policyBinding
    }

    public func isLive(now: Date) -> Bool { now < expiresAt }
}
