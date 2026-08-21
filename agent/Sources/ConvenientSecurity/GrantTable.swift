import Foundation

/// The live set of grants. A caller's access = the union of all live grants
/// whose root is the caller or an ancestor of it. New consent creates a grant
/// rooted at the caller.
public actor GrantTable {
    private var grants: [Grant] = []

    public init() {}

    /// References currently accessible to `pid` via its own or an ancestor's grant.
    public func accessibleReferences(
        for pid: pid_t,
        now: Date,
        deliveryPlanDigest: String? = nil
    ) -> Set<String> {
        var refs: Set<String> = []
        for grant in grants where grant.isLive(now: now) {
            if let deliveryPlanDigest,
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
}
