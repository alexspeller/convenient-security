import Foundation

/// The live set of grants. A caller's access = the union of all live grants
/// whose root is the caller or an ancestor of it, and whose reuse binding the
/// current request satisfies. New consent creates a grant rooted at the scope
/// the human selected.
public actor GrantTable {
    private var grants: [Grant] = []

    public init() {}

    /// References currently accessible to `pid` via its own or an ancestor's
    /// grant.
    ///
    /// Two reuse bindings coexist:
    /// - A grant rooted at the requesting command keeps the original rule and is
    ///   reusable only for an identical `deliveryPlanDigest`.
    /// - A grant the human widened past the requesting command is reusable by any
    ///   command of the same `releaseShapeDigest` in its subtree, and also
    ///   requires the caller's audit session to match the approving one.
    ///
    /// In both cases the kernel ancestry walk to the exact recorded PID/start-time
    /// pair remains the authority.
    public func accessibleReferences(
        for pid: pid_t,
        now: Date,
        deliveryPlanDigest: String? = nil,
        releaseShapeDigest: String? = nil,
        callerAuditSessionID: UInt32? = nil
    ) -> Set<String> {
        var refs: Set<String> = []
        for grant in grants where grant.isLive(now: now) {
            if let scopeReuseDigest = grant.scopeReuseDigest {
                guard let releaseShapeDigest,
                      scopeReuseDigest == releaseShapeDigest,
                      grant.auditSessionID == nil
                        || grant.auditSessionID == callerAuditSessionID else { continue }
            } else if let deliveryPlanDigest,
                      grant.deliveryPlanDigest != deliveryPlanDigest {
                continue
            }
            if ProcessAncestry.descends(pid, from: grant.rootPID, rootStartTime: grant.rootStartTime) {
                refs.formUnion(grant.references)
            }
        }
        return refs
    }

    public func add(_ grant: Grant) {
        grants.append(grant)
    }

    /// Drop expired grants and grants whose root process is gone.
    public func sweep(now: Date) {
        grants.removeAll { grant in
            !grant.isLive(now: now)
                || ProcessAncestry.startTime(of: grant.rootPID) != grant.rootStartTime
        }
    }

    /// Value-free descriptions of every live grant, newest expiry last.
    public func summaries(now: Date) -> [GrantSummary] {
        sweep(now: now)
        return grants.map { grant in
            GrantSummary(
                id: grant.id.uuidString.lowercased(),
                rootPID: grant.rootPID,
                rootProcessLabel: grant.rootProcessLabel
                    ?? ReviewDisplay.sanitized(
                        ProcessAncestry.name(of: grant.rootPID) ?? "process"
                    ),
                scopeKind: grant.scopeKind,
                references: grant.references.sorted(),
                reason: grant.reason,
                expiresAt: grant.expiresAt
            )
        }.sorted { $0.expiresAt < $1.expiresAt }
    }

    /// Drop every grant whose id begins with `idPrefix` (case-insensitively).
    /// Returns how many were removed. Revocation only removes access, so it
    /// needs no authentication of its own.
    public func revoke(idPrefix: String) -> Int {
        let prefix = idPrefix.lowercased()
        guard !prefix.isEmpty else { return 0 }
        let before = grants.count
        grants.removeAll { $0.id.uuidString.lowercased().hasPrefix(prefix) }
        return before - grants.count
    }

    public func revokeAll() -> Int {
        let count = grants.count
        grants.removeAll()
        return count
    }
}
