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
        deliveryPlanDigest: String? = nil,
        policyBindingsByReference: [String: PolicyGrantBinding]? = nil
    ) -> Set<String> {
        var refs: Set<String> = []
        for grant in grants where grant.isLive(now: now) {
            if let deliveryPlanDigest,
               grant.deliveryPlanDigest != deliveryPlanDigest {
                continue
            }
            if ProcessAncestry.descends(pid, from: grant.rootPID, rootStartTime: grant.rootStartTime) {
                if let policyBindingsByReference {
                    guard let grantBinding = grant.policyBinding else { continue }
                    for reference in grant.references
                    where policyBindingsByReference[reference] == grantBinding {
                        refs.insert(reference)
                    }
                } else {
                    refs.formUnion(grant.references)
                }
            }
        }
        return refs
    }

    public func add(_ grant: Grant) {
        grants.append(grant)
    }

    /// Revoke all grants for one opaque logical credential and return only the
    /// raw references already held in memory, so the resolver can invalidate
    /// their cache entries without a reverse map in persistent storage.
    public func revoke(credentialKey: String) -> Set<String> {
        var references = Set<String>()
        grants.removeAll { grant in
            guard grant.policyBinding?.credentialKey == credentialKey else { return false }
            references.formUnion(grant.references)
            return true
        }
        return references
    }

    /// Policy-version changes invalidate every old policy-bound grant. Legacy
    /// test grants are deliberately left alone and are never accepted by the
    /// shipping v2 access path.
    public func revalidate(policyVersion: Int) -> Set<String> {
        var references = Set<String>()
        grants.removeAll { grant in
            guard let binding = grant.policyBinding,
                  binding.policyVersion != policyVersion else { return false }
            references.formUnion(grant.references)
            return true
        }
        return references
    }

    /// Drop expired grants and grants whose root process is gone.
    public func sweep(now: Date) {
        grants.removeAll { grant in
            !grant.isLive(now: now)
                || ProcessAncestry.startTime(of: grant.rootPID) != grant.rootStartTime
        }
    }
}
