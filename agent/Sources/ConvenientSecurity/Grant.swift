import Foundation

/// A consented capability: a set of references granted to a process subtree,
/// until `expiresAt`. Held only in the agent's memory-protected heap. Reuse is
/// bound to the live process subtree plus either the originating delivery-plan
/// digest (a requesting-command root) or the release-shape digest (a root the
/// human deliberately widened); after the risk-level collapse there is no
/// per-credential policy binding.
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
    /// Which selectable root the human approved. Display and diagnostics only —
    /// `rootPID`/`rootStartTime` remain the authority.
    public let scopeKind: GrantScopeKind
    /// Set only for a widened root: the release-shape digest that a *different*
    /// command in this subtree must match to reuse the grant. Nil keeps the
    /// original exact delivery-plan-digest binding.
    public let scopeReuseDigest: String?
    /// Audit session of the approving caller. Enforced alongside ancestry for a
    /// widened grant, mirroring the binding `SSHSigningService` applies to its
    /// reused grants.
    public let auditSessionID: UInt32?
    /// Human label for the root process, captured at approval time.
    public let rootProcessLabel: String?

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
        scopeKind: GrantScopeKind = .requestingCommand,
        scopeReuseDigest: String? = nil,
        auditSessionID: UInt32? = nil,
        rootProcessLabel: String? = nil
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
        self.scopeKind = scopeKind
        self.scopeReuseDigest = scopeReuseDigest
        self.auditSessionID = auditSessionID
        self.rootProcessLabel = rootProcessLabel
    }

    public func isLive(now: Date) -> Bool { now < expiresAt }
}

public enum GrantsAction: String, Codable, Sendable {
    case list
    case revoke
}

/// Inspect or drop live grants. Listing returns value-free metadata and
/// revocation only removes access, so neither needs Touch ID; both still
/// require an authenticated signed launcher like every other verb.
public struct GrantsRequest: Codable, Sendable {
    public let requestID: String
    public let action: GrantsAction
    /// Grant id, or an unambiguous prefix of one, for `revoke`.
    public let grantID: String?
    /// Revoke every live grant.
    public let all: Bool

    public init(
        action: GrantsAction,
        grantID: String? = nil,
        all: Bool = false,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.action = action
        self.grantID = grantID
        self.all = all
    }
}

/// Value-free description of a live grant for `csec grants`. It carries
/// reference URIs and process metadata, never a resolved value.
public struct GrantSummary: Codable, Sendable, Equatable {
    public let id: String
    public let rootPID: pid_t
    public let rootProcessLabel: String
    public let scopeKind: GrantScopeKind
    public let references: [String]
    public let reason: String
    public let expiresAt: Date

    public init(
        id: String,
        rootPID: pid_t,
        rootProcessLabel: String,
        scopeKind: GrantScopeKind,
        references: [String],
        reason: String,
        expiresAt: Date
    ) {
        self.id = id
        self.rootPID = rootPID
        self.rootProcessLabel = rootProcessLabel
        self.scopeKind = scopeKind
        self.references = references
        self.reason = reason
        self.expiresAt = expiresAt
    }

    public var reusesAcrossCommands: Bool { scopeKind.reusesAcrossCommands }

    /// Bounds for a summary crossing the socket, checked by the client.
    public var isWellFormed: Bool {
        !id.isEmpty && id.utf8.count <= 64
            && rootPID > 0
            && !rootProcessLabel.isEmpty && rootProcessLabel.utf8.count <= 256
            && references.count <= 64
            && references.allSatisfy { !$0.isEmpty && $0.utf8.count <= 4_096 }
            && reason.utf8.count <= 512
    }
}
