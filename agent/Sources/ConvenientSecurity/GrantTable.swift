import Foundation

/// What the live grants cover for one caller and release shape.
public struct GrantCoverage: Sendable, Equatable {
    /// Every reference a live grant covers.
    public var references: Set<String> = []
    /// Covered only by grants restored after a csecd restart, and by no grant
    /// approved in this run. A release of one of these is a restored grant's.
    public var coveredOnlyByRestored: Set<String> = []
    /// Covered only by restored grants whose stores the restore panel has not
    /// reopened yet. Such a release may need that panel first.
    public var awaitingRestore: Set<String> = []

    public init() {}
}

/// The live set of grants. A caller's access = the union of all live grants
/// whose root is the caller or an ancestor of it, and whose reuse binding the
/// current request satisfies. New consent creates a grant rooted at the scope
/// the human selected.
///
/// With `persistence`, every change to the set is handed to that one owner of
/// the persisted grants item, as a snapshot with a generation that only grows.
/// The table never writes the item itself.
public actor GrantTable {
    private var grants: [Grant] = []
    private let persistence: GrantPersistence?
    private var generation: UInt64 = 0

    public init(persistence: GrantPersistence? = nil) {
        self.persistence = persistence
    }

    /// References currently accessible to `pid` via its own or an ancestor's
    /// grant. See `coverage(for:...)`.
    public func accessibleReferences(
        for pid: pid_t,
        now: Date,
        deliveryPlanDigest: String? = nil,
        releaseShapeDigest: String? = nil,
        callerAuditSessionID: UInt32? = nil,
        widenedScopeOnly: Bool = false
    ) -> Set<String> {
        coverage(
            for: pid, now: now, deliveryPlanDigest: deliveryPlanDigest,
            releaseShapeDigest: releaseShapeDigest,
            callerAuditSessionID: callerAuditSessionID, widenedScopeOnly: widenedScopeOnly
        ).references
    }

    /// What the live grants cover for `pid`, and which of it rests only on
    /// grants restored after a restart.
    ///
    /// Two reuse bindings coexist:
    /// - A grant rooted at the requesting command keeps the original rule and is
    ///   reusable only for an identical `deliveryPlanDigest`.
    /// - A grant the human widened past the requesting command is reusable by any
    ///   command of the same `releaseShapeDigest` in its subtree, and also
    ///   requires the caller's audit session to match the approving one.
    ///
    /// In both cases the lineage walk (`ProcessInspection.descends`: kernel
    /// parents, with a detached job linked back through its session) to the
    /// exact recorded PID/start-time pair remains the authority. A restored grant is matched by exactly the
    /// same rule: persistence never widens what a grant covers.
    /// - Parameter widenedScopeOnly: reject per-command grants outright, so only
    ///   a scope the human deliberately widened past the requesting command can
    ///   cover this release. Capability-GID launches set it: each is a fresh
    ///   two-party rendezvous that mints a new root, so it may ride an explicit
    ///   subtree grant but must never be covered by the incidental per-command
    ///   one its own outer launcher left behind.
    public func coverage(
        for pid: pid_t,
        now: Date,
        deliveryPlanDigest: String? = nil,
        releaseShapeDigest: String? = nil,
        callerAuditSessionID: UInt32? = nil,
        widenedScopeOnly: Bool = false
    ) -> GrantCoverage {
        var coverage = GrantCoverage()
        var byRestored: Set<String> = []
        var byMintedHere: Set<String> = []
        var byAwaiting: Set<String> = []
        var byReady: Set<String> = []
        for grant in grants where grant.isLive(now: now) {
            if let scopeReuseDigest = grant.scopeReuseDigest {
                guard let releaseShapeDigest,
                      scopeReuseDigest == releaseShapeDigest,
                      grant.auditSessionID == nil
                        || grant.auditSessionID == callerAuditSessionID else { continue }
            } else {
                guard !widenedScopeOnly else { continue }
                if let deliveryPlanDigest, grant.deliveryPlanDigest != deliveryPlanDigest {
                    continue
                }
            }
            if ProcessInspection.live.descends(pid, from: grant.rootPID, rootStartTime: grant.rootStartTime) {
                coverage.references.formUnion(grant.references)
                if grant.restored {
                    byRestored.formUnion(grant.references)
                } else {
                    byMintedHere.formUnion(grant.references)
                }
                if grant.awaitingRestore {
                    byAwaiting.formUnion(grant.references)
                } else {
                    byReady.formUnion(grant.references)
                }
            }
        }
        coverage.coveredOnlyByRestored = byRestored.subtracting(byMintedHere)
        coverage.awaitingRestore = byAwaiting.subtracting(byReady)
        return coverage
    }

    /// Mint: grants whose root is gone are swept first, so the persisted item
    /// never carries them forward.
    public func add(_ grant: Grant) async {
        removeEnded(now: Date())
        grants.append(grant)
        await persistChange()
    }

    /// Drop expired grants and grants whose root process is gone. The persisted
    /// item is rewritten only when something was dropped.
    public func sweep(now: Date) async {
        if removeEnded(now: now) > 0 {
            await persistChange()
        }
    }

    /// Value-free descriptions of every live grant, soonest expiry first and the
    /// process-lifetime grants (nil expiry, longest-lived) last.
    public func summaries(now: Date) async -> [GrantSummary] {
        await sweep(now: now)
        return grants.map { grant in
            GrantSummary(
                id: grant.id.uuidString.lowercased(),
                kind: .secret,
                rootPID: grant.rootPID,
                rootProcessLabel: label(for: grant),
                scopeKind: grant.scopeKind,
                references: grant.references.sorted(),
                reason: grant.reason,
                expiresAt: grant.expiresAt,
                restored: grant.restored
            )
        }.sorted { lhs, rhs in
            switch (lhs.expiresAt, rhs.expiresAt) {
            case let (l?, r?): return l < r
            case (nil, _?): return false
            case (_?, nil): return true
            case (nil, nil): return false
            }
        }
    }

    /// Drop every grant whose id begins with `idPrefix` (case-insensitively).
    /// Returns how many were removed. Revocation only removes access, so it
    /// needs no authentication of its own. The caller persists the removal
    /// synchronously (`GrantPersistence.persistNow`) before it replies.
    public func revoke(idPrefix: String) async -> Int {
        let prefix = idPrefix.lowercased()
        guard !prefix.isEmpty else { return 0 }
        let before = grants.count
        grants.removeAll { $0.id.uuidString.lowercased().hasPrefix(prefix) }
        let removed = before - grants.count
        if removed > 0 { await persistChange() }
        return removed
    }

    /// Drop every grant that covers any of `references`: what was approved
    /// for them no longer describes what they would release, as when a
    /// machine identity target is removed and a different one may later take
    /// its name. Returns how many were removed.
    public func revoke(references: Set<String>) async -> Int {
        guard !references.isEmpty else { return 0 }
        let before = grants.count
        grants.removeAll { !$0.references.isDisjoint(with: references) }
        let removed = before - grants.count
        if removed > 0 { await persistChange() }
        return removed
    }

    /// The root process of the grant whose id is `id`, while it is held: what
    /// a revocation that also acts on that process (delegation's unpairing)
    /// must match, so a pid reused since cannot stand in for it.
    public func root(ofGrantID id: String) -> ProcessIncarnation? {
        let id = id.lowercased()
        return grants.first { $0.id.uuidString.lowercased() == id }
            .map { ProcessIncarnation(pid: $0.rootPID, startTime: $0.rootStartTime) }
    }

    public func revokeAll() async -> Int {
        let count = grants.count
        grants.removeAll()
        if count > 0 { await persistChange() }
        return count
    }

    /// Put back the grants the persisted item restored at startup. They match
    /// exactly as before; they only wait for the restore panel before their
    /// sealed stores are reopened.
    public func restore(_ restored: [Grant]) async {
        let known = Set(grants.map(\.id))
        let added = restored.filter { !known.contains($0.id) }
        guard !added.isEmpty else { return }
        grants.append(contentsOf: added)
        await persistChange()
    }

    /// The restored grants still waiting for the restore panel whose root is
    /// alive, as the panel lists them.
    public func restoreEntries() -> [RestoreEntry] {
        let now = Date()
        return grants.compactMap { grant in
            guard grant.awaitingRestore, grant.isLive(now: now),
                  ProcessAncestry.startTime(of: grant.rootPID) == grant.rootStartTime else {
                return nil
            }
            let references = grant.references.sorted().compactMap { try? SecretRef($0) }
            let label = label(for: grant)
            let scope = GrantScopeOption(
                kind: grant.scopeKind, pid: grant.rootPID,
                startTime: grant.rootStartTime, processLabel: label
            )
            return RestoreEntry(
                grantID: grant.id,
                row: RestoreReviewRow(
                    kind: .secretGrant,
                    title: label,
                    detail: "\(ReviewDisplay.scopeTitle(scope)) · pid \(grant.rootPID)",
                    references: references.map(\.uri)
                ),
                references: references
            )
        }
    }

    /// The restore is over: the grants it could not reopen, or the human chose
    /// to forget, are dropped, and every other restored grant stops waiting.
    /// Returns how many were dropped; the caller persists that synchronously.
    public func settleRestore(forgetting forgotten: Set<UUID>) async -> Int {
        let before = grants.count
        grants.removeAll { forgotten.contains($0.id) }
        for index in grants.indices where grants[index].restored {
            grants[index].warm = true
        }
        let removed = before - grants.count
        if removed > 0 { await persistChange() }
        return removed
    }

    @discardableResult
    private func removeEnded(now: Date) -> Int {
        let before = grants.count
        grants.removeAll { grant in
            !grant.isLive(now: now)
                || ProcessAncestry.startTime(of: grant.rootPID) != grant.rootStartTime
        }
        return before - grants.count
    }

    private func label(for grant: Grant) -> String {
        grant.rootProcessLabel
            ?? ReviewDisplay.sanitized(ProcessAncestry.name(of: grant.rootPID) ?? "process")
    }

    /// Hands the persistence owner this table as it now stands. The snapshot
    /// and its generation are taken together, before anything else can run on
    /// this actor, so a snapshot that arrives late is recognized as older.
    private func persistChange() async {
        guard let persistence else { return }
        generation += 1
        let snapshot = grants
        let current = generation
        await persistence.update(secret: snapshot, generation: current)
    }
}

extension GrantTable: RestoredGrantSource {}
