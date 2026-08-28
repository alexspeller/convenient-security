import Foundation

/// A consented capability: a set of references granted to a process subtree,
/// until `expiresAt`. Held only in the agent's memory-protected heap. Reuse is
/// bound to the originating delivery-plan digest and the live process subtree;
/// after the risk-level collapse there is no per-credential policy binding.
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
    /// metadata, not a bearer token; plan-digest equality controls reuse.
    public let requestID: String?
    public let deliveryPlanDigest: String?
    public let peerPIDVersion: Int32?
    public let peerCDHash: String?
    public let plannedExecutable: PlannedExecutable?

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
        plannedExecutable: PlannedExecutable? = nil
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
    }

    public func isLive(now: Date) -> Bool { now < expiresAt }
}
