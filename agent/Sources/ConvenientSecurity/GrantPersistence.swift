import Foundation

/// A secret grant as the `grants`/`live-v1` protected item holds it: every
/// `Grant` field plus the facts a later csecd checks before restoring it.
/// Value-free: canonical references and kernel facts, never a resolved value.
public struct PersistedSecretGrant: Codable, Sendable, Equatable {
    public var id: UUID
    public var rootPID: Int32
    /// Epoch microseconds, compared exactly at load.
    public var rootStartTime: UInt64
    public var references: [String]
    public var reason: String
    public var expiresAt: Date?
    public var requestID: String?
    public var deliveryPlanDigest: String?
    public var peerPIDVersion: Int32?
    public var peerCDHash: String?
    public var plannedExecutable: PlannedExecutable?
    public var scopeKind: GrantScopeKind
    public var scopeReuseDigest: String?
    public var auditSessionID: UInt32?
    public var rootProcessLabel: String?
    public var bootSessionUUID: String?
    public var mintedAt: Date
    public var origin: GrantOrigin
    public var mintedByBuild: String?
    public var grantPolicyEpoch: Int

    public init(
        id: UUID,
        rootPID: Int32,
        rootStartTime: UInt64,
        references: [String],
        reason: String,
        expiresAt: Date?,
        requestID: String?,
        deliveryPlanDigest: String?,
        peerPIDVersion: Int32?,
        peerCDHash: String?,
        plannedExecutable: PlannedExecutable?,
        scopeKind: GrantScopeKind,
        scopeReuseDigest: String?,
        auditSessionID: UInt32?,
        rootProcessLabel: String?,
        bootSessionUUID: String?,
        mintedAt: Date,
        origin: GrantOrigin,
        mintedByBuild: String?,
        grantPolicyEpoch: Int
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
        self.bootSessionUUID = bootSessionUUID
        self.mintedAt = mintedAt
        self.origin = origin
        self.mintedByBuild = mintedByBuild
        self.grantPolicyEpoch = grantPolicyEpoch
    }

    public var isWellFormed: Bool {
        rootPID > 0 && rootStartTime > 0
            && !references.isEmpty && references.count <= 64
            && references.allSatisfy {
                !$0.isEmpty && $0.utf8.count <= 4_096 && !$0.utf8.contains(0)
            }
            && Set(references).count == references.count
            && reason.utf8.count <= 512
            && (requestID?.utf8.count ?? 0) <= 64
            && (deliveryPlanDigest?.utf8.count ?? 0) <= 128
            && (peerCDHash?.utf8.count ?? 0) <= 128
            && (scopeReuseDigest?.utf8.count ?? 0) <= 128
            && (rootProcessLabel?.utf8.count ?? 0) <= 256
            && (bootSessionUUID?.utf8.count ?? 0) <= 64
            && (mintedByBuild?.utf8.count ?? 0) <= 256
            && grantPolicyEpoch >= 0
            && (plannedExecutable.map(Self.isBounded) ?? true)
    }

    private static func isBounded(_ executable: PlannedExecutable) -> Bool {
        executable.canonicalPath.utf8.count <= 4_096
            && (executable.signingIdentifier?.utf8.count ?? 0) <= 256
            && (executable.teamIdentifier?.utf8.count ?? 0) <= 64
            && (executable.cdHash?.utf8.count ?? 0) <= 128
    }

    /// The grant as it re-enters the table after a restart: restored, and
    /// waiting for the restore panel before its sealed stores are reopened.
    func restoredGrant(references: Set<String>) -> Grant {
        Grant(
            id: id,
            rootPID: rootPID,
            rootStartTime: rootStartTime,
            references: references,
            reason: reason,
            expiresAt: expiresAt,
            requestID: requestID,
            deliveryPlanDigest: deliveryPlanDigest,
            peerPIDVersion: peerPIDVersion,
            peerCDHash: peerCDHash,
            plannedExecutable: plannedExecutable,
            scopeKind: scopeKind,
            scopeReuseDigest: scopeReuseDigest,
            auditSessionID: auditSessionID,
            rootProcessLabel: rootProcessLabel,
            origin: origin,
            mintedAt: mintedAt,
            mintedByBuild: mintedByBuild,
            restored: true,
            warm: false
        )
    }
}

/// An SSH signing grant as the grants item holds it: the facts a signing grant
/// is bound to, plus the same restore facts as a secret grant. The key is
/// named by its public fingerprint; its reference is read from the catalog.
public struct PersistedSSHGrant: Codable, Sendable, Equatable {
    public var id: UUID
    public var keyFingerprint: String
    public var hostKeyFingerprint: String
    public var remoteUser: String
    public var rootPID: Int32
    public var rootStartTime: UInt64
    public var auditSessionID: UInt32?
    public var clientCDHash: String?
    public var expiresAt: Date?
    public var scopeKind: GrantScopeKind
    public var rootProcessLabel: String?
    public var bootSessionUUID: String?
    public var mintedAt: Date
    public var origin: GrantOrigin
    public var mintedByBuild: String?
    public var grantPolicyEpoch: Int

    public init(
        id: UUID,
        keyFingerprint: String,
        hostKeyFingerprint: String,
        remoteUser: String,
        rootPID: Int32,
        rootStartTime: UInt64,
        auditSessionID: UInt32?,
        clientCDHash: String?,
        expiresAt: Date?,
        scopeKind: GrantScopeKind,
        rootProcessLabel: String?,
        mintedAt: Date,
        origin: GrantOrigin,
        mintedByBuild: String?,
        bootSessionUUID: String? = nil,
        grantPolicyEpoch: Int = GrantPersistence.grantPolicyEpoch
    ) {
        self.id = id
        self.keyFingerprint = keyFingerprint
        self.hostKeyFingerprint = hostKeyFingerprint
        self.remoteUser = remoteUser
        self.rootPID = rootPID
        self.rootStartTime = rootStartTime
        self.auditSessionID = auditSessionID
        self.clientCDHash = clientCDHash
        self.expiresAt = expiresAt
        self.scopeKind = scopeKind
        self.rootProcessLabel = rootProcessLabel
        self.bootSessionUUID = bootSessionUUID
        self.mintedAt = mintedAt
        self.origin = origin
        self.mintedByBuild = mintedByBuild
        self.grantPolicyEpoch = grantPolicyEpoch
    }

    public var isWellFormed: Bool {
        rootPID > 0 && rootStartTime > 0
            && !keyFingerprint.isEmpty && keyFingerprint.utf8.count <= 128
            && !hostKeyFingerprint.isEmpty && hostKeyFingerprint.utf8.count <= 128
            && !remoteUser.isEmpty && remoteUser.utf8.count <= 256
            && (clientCDHash?.utf8.count ?? 0) <= 128
            && (rootProcessLabel?.utf8.count ?? 0) <= 256
            && (bootSessionUUID?.utf8.count ?? 0) <= 64
            && (mintedByBuild?.utf8.count ?? 0) <= 256
            && grantPolicyEpoch >= 0
    }
}

/// The `grants`/`live-v1` document: every live secret and SSH grant, so a
/// restarted csecd can put back what the human approved instead of asking
/// again. The item is csecd-only (see `ProtectedItem`), so a same-UID process
/// can neither forge a grant into it nor roll it back to resurrect a revoked one.
public struct GrantsDocument: ProtectedDocument, Equatable {
    public static let protectedItem: ProtectedItem = .grants
    public static let formatVersion = 1

    public var secret: [PersistedSecretGrant]
    public var ssh: [PersistedSSHGrant]

    public init(secret: [PersistedSecretGrant] = [], ssh: [PersistedSSHGrant] = []) {
        self.secret = secret
        self.ssh = ssh
    }

    public var isWellFormed: Bool {
        secret.count <= GrantPersistence.maximumSecretGrants
            && ssh.count <= GrantPersistence.maximumSSHGrants
            && secret.allSatisfy(\.isWellFormed)
            && ssh.allSatisfy(\.isWellFormed)
            && Set(secret.map(\.id)).count == secret.count
            && Set(ssh.map(\.id)).count == ssh.count
    }
}

/// Why a persisted grant was not restored. The checks run in this order and a
/// grant is counted under the first one it fails.
public enum GrantDropReason: String, Codable, Sendable, CaseIterable {
    /// Minted under grant semantics this build has since narrowed.
    case policyEpoch = "policy_epoch"
    /// Minted before the Mac last booted.
    case bootSession = "boot_session"
    /// Its root process is gone, or its pid now belongs to another process.
    case rootExited = "root_exited"
    /// Its chosen lifetime has run out.
    case expired
    /// None of its references parses as a canonical reference of a scheme a
    /// provider still serves.
    case unknownReference = "unknown_reference"
    /// Its key is no longer in the SSH catalog.
    case sshKeyRemoved = "ssh_key_removed"
}

/// A persisted grant the load checks dropped. csecd keeps these in memory for
/// the rest of its lifetime, bounded by the grants item's own caps and read
/// once, so a panel a dropped grant would have spared can be recorded as a
/// re-ask caused by the restart (`restart_not_restored`). Nothing here is ever
/// used to authorize anything.
public struct DroppedGrant: Sendable, Equatable {
    public let kind: GrantKind
    public let reason: GrantDropReason
    public let rootPID: Int32
    public let rootStartTime: UInt64
    /// A secret grant's references, exactly as persisted.
    public let references: Set<String>
    public let deliveryPlanDigest: String?
    public let scopeReuseDigest: String?
    public let auditSessionID: UInt32?
    /// An SSH grant's binding.
    public let keyFingerprint: String?
    public let hostKeyFingerprint: String?
    public let remoteUser: String?
    public let clientCDHash: String?
    /// The lifetime the human chose; a dropped grant past it would not have
    /// covered anything even if it had been restored.
    public let expiresAt: Date?

    init(secret record: PersistedSecretGrant, reason: GrantDropReason) {
        kind = .secret
        self.reason = reason
        expiresAt = record.expiresAt
        rootPID = record.rootPID
        rootStartTime = record.rootStartTime
        references = Set(record.references)
        deliveryPlanDigest = record.deliveryPlanDigest
        scopeReuseDigest = record.scopeReuseDigest
        auditSessionID = record.auditSessionID
        keyFingerprint = nil
        hostKeyFingerprint = nil
        remoteUser = nil
        clientCDHash = nil
    }

    init(ssh record: PersistedSSHGrant, reason: GrantDropReason) {
        kind = .ssh
        self.reason = reason
        expiresAt = record.expiresAt
        rootPID = record.rootPID
        rootStartTime = record.rootStartTime
        references = []
        deliveryPlanDigest = nil
        scopeReuseDigest = nil
        auditSessionID = record.auditSessionID
        keyFingerprint = record.keyFingerprint
        hostKeyFingerprint = record.hostKeyFingerprint
        remoteUser = record.remoteUser
        clientCDHash = record.clientCDHash
    }
}

extension DecisionLogPromptCause {
    /// Why a panel appeared, once the grants the restart dropped are counted.
    ///
    /// Precedence, first that applies:
    /// 1. A cause from an approval made in this run for this process tree
    ///    (`new_release_shape`, `grant_expired`, `grant_revoked`): the human
    ///    has already decided about these references here since the restart,
    ///    so this panel follows from that decision, not from the restart. The
    ///    restart's re-ask was the earlier panel that led to it.
    /// 2. `restart_not_restored`: no such approval, and a grant dropped at
    ///    load would still have covered this exact request.
    /// 3. `grant_expired`: only dropped grants past their chosen lifetime
    ///    would have covered it, so the restart changed nothing.
    /// 4. This run's own `new_process` or `new_refs`.
    public static func accountingForRestart(
        inRun: DecisionLogPromptCause,
        droppedAtLoad: GrantDropReason?
    ) -> DecisionLogPromptCause {
        switch inRun {
        case .newProcess, .newRefs:
            guard let droppedAtLoad else { return inRun }
            return droppedAtLoad == .expired ? .grantExpired : .restartNotRestored
        case .newReleaseShape, .grantExpired, .grantRevoked, .restartNotRestored, .restartRestore, .oneTimeCode,
             .lastingAccess:
            return inRun
        }
    }
}

/// The facts of this csecd run that every persisted grant is stamped with.
public struct GrantPersistenceFacts: Sendable, Equatable {
    public var bootSessionUUID: String?
    /// The running build (cdhash, or the bundle version), for diagnostics.
    public var build: String?

    public init(bootSessionUUID: String?, build: String?) {
        self.bootSessionUUID = bootSessionUUID
        self.build = build
    }

    public static func current() -> GrantPersistenceFacts {
        GrantPersistenceFacts(
            bootSessionUUID: CsecdRunFacts.bootSessionUUID(),
            build: CsecdRunFacts.currentCDHash() ?? CsecdRunFacts.currentVersion()
        )
    }
}

/// What the grants item gave back at startup.
public struct GrantLoadResult: Sendable {
    /// Secret grants to put back in the table, restored and not yet warm.
    public let secret: [Grant]
    /// SSH grants to put back in the signing service.
    public let ssh: [PersistedSSHGrant]
    /// Restored and dropped counts, for the `restart` record.
    public let counts: DecisionLogRecord.GrantCounts
}

/// A synchronous write that could not make the item match csecd's grants:
/// an earlier document, holding a revoked grant, may still be there.
public struct GrantPersistenceFailure: Error, Sendable, Equatable, CustomStringConvertible {
    public let description: String
}

/// The one owner of the `grants`/`live-v1` item. The item holds both secret
/// and SSH grants, and the protected store orders changes by the moment they
/// are prepared, so exactly one actor may prepare them: this one.
///
/// `GrantTable` and `SSHSigningService` never write the item. After every
/// change to what they would persist they hand this actor a snapshot stamped
/// with their own generation, which only ever grows. An older snapshot that
/// arrives late is ignored, so the state this actor holds only moves forward,
/// and every change it prepares carries the newest state of both tables:
/// a later-prepared change is never an older state, and a revoked grant can
/// never be written back.
///
/// Mints and sweeps are written behind (a lost write only means a grant is
/// asked for again after a restart). A revoke is written with `persistNow`
/// before csecd replies: a revoke that was not persisted would come back at
/// the next start, the one way persistence could widen access.
public actor GrantPersistence {
    /// Bumped by any release that narrows what a grant allows (a fix to scope
    /// or ancestry matching, a change to the plan or release-shape digests),
    /// so grants minted under the old rules are dropped rather than restored.
    public static let grantPolicyEpoch = 1
    public static let maximumSecretGrants = 1_024
    public static let maximumSSHGrants = 256

    private let store: ProtectedStore<GrantsDocument>
    private let facts: GrantPersistenceFacts
    /// Where grants left out of the item over its caps are recorded.
    private let decisionLog: DecisionLog?
    /// Grants already recorded as left out, so each is recorded once however
    /// many writes happen while the item stays over its caps.
    private var reportedOmissions: Set<UUID> = []
    /// Grants the last prepared document newly left out, to be recorded.
    private var pendingEviction: (secret: [UUID], ssh: [UUID])?
    private var secret: [PersistedSecretGrant] = []
    private var secretGeneration: UInt64 = 0
    private var ssh: [PersistedSSHGrant] = []
    private var sshGeneration: UInt64 = 0
    private var dirty = false
    private var pendingWrite: Task<Void, Never>?
    private var loaded = false
    /// What the load checks dropped. Written once, at load.
    public private(set) var droppedAtLoad: [DroppedGrant] = []

    public init(
        stores: ProtectedStores,
        facts: GrantPersistenceFacts = .current(),
        decisionLog: DecisionLog? = nil
    ) {
        self.store = stores.store(for: GrantsDocument.self)
        self.facts = facts
        self.decisionLog = decisionLog
    }

    /// Reads the item once, at startup and before csecd serves anything, and
    /// runs the load checks on every grant in `GrantDropReason` order. What
    /// survives becomes this actor's state; if anything was dropped, the
    /// survivors are written back. An item this build cannot read is left as
    /// it is (a newer csecd may read it) and restores nothing; the store holds
    /// it, so the grants this run mints hold for this run only.
    public func load(
        now: Date = Date(),
        processInspection: ProcessInspection = .live,
        registeredSchemes: Set<String>,
        sshKeyFingerprints: Set<String>?
    ) async -> GrantLoadResult {
        guard !loaded else {
            return GrantLoadResult(secret: [], ssh: [], counts: .init())
        }
        loaded = true
        let document: GrantsDocument
        switch await store.load() {
        case .absent:
            return GrantLoadResult(secret: [], ssh: [], counts: .init())
        case let .unreadable(reason):
            FileHandle.standardError.write(Data(
                "csecd: persisted grants unreadable (\(reason)); restoring none and keeping the item as found.\n".utf8
            ))
            return GrantLoadResult(secret: [], ssh: [], counts: .init(unreadable: reason.description))
        case let .document(stored):
            document = stored
        }

        var dropped: [GrantDropReason: Int] = [:]
        var trimmedReferences = false
        var restoredSecret: [Grant] = []
        var survivingSecret: [PersistedSecretGrant] = []
        for record in document.secret {
            if let reason = dropReason(
                epoch: record.grantPolicyEpoch, bootSessionUUID: record.bootSessionUUID,
                rootPID: record.rootPID, rootStartTime: record.rootStartTime,
                expiresAt: record.expiresAt, now: now, processInspection: processInspection
            ) {
                dropped[reason, default: 0] += 1
                droppedAtLoad.append(DroppedGrant(secret: record, reason: reason))
                continue
            }
            let kept = record.references.filter { raw in
                guard let reference = try? SecretRef(raw) else { return false }
                return reference.uri == raw && registeredSchemes.contains(reference.scheme)
            }
            guard !kept.isEmpty else {
                dropped[.unknownReference, default: 0] += 1
                droppedAtLoad.append(DroppedGrant(secret: record, reason: .unknownReference))
                continue
            }
            if kept.count != record.references.count { trimmedReferences = true }
            var survivor = record
            survivor.references = kept
            survivingSecret.append(survivor)
            restoredSecret.append(record.restoredGrant(references: Set(kept)))
        }
        var survivingSSH: [PersistedSSHGrant] = []
        for record in document.ssh {
            if let reason = dropReason(
                epoch: record.grantPolicyEpoch, bootSessionUUID: record.bootSessionUUID,
                rootPID: record.rootPID, rootStartTime: record.rootStartTime,
                expiresAt: record.expiresAt, now: now, processInspection: processInspection
            ) {
                dropped[reason, default: 0] += 1
                droppedAtLoad.append(DroppedGrant(ssh: record, reason: reason))
                continue
            }
            guard sshKeyFingerprints?.contains(record.keyFingerprint) == true else {
                dropped[.sshKeyRemoved, default: 0] += 1
                droppedAtLoad.append(DroppedGrant(ssh: record, reason: .sshKeyRemoved))
                continue
            }
            survivingSSH.append(record)
        }

        secret = survivingSecret
        ssh = survivingSSH
        if !dropped.isEmpty || trimmedReferences { scheduleWrite() }
        return GrantLoadResult(
            secret: restoredSecret,
            ssh: survivingSSH,
            counts: DecisionLogRecord.GrantCounts(
                secret: restoredSecret.count,
                ssh: survivingSSH.count,
                dropped: dropped.isEmpty ? nil : Dictionary(
                    uniqueKeysWithValues: dropped.map { ($0.key.rawValue, $0.value) }
                )
            )
        )
    }

    /// Why a secret request that is about to get a panel would have been
    /// covered by a persisted grant the load checks dropped, or nil. The match
    /// is `GrantTable`'s own rule (reuse binding, audit session, kernel
    /// ancestry to the exact root) applied to the dropped grants, and every
    /// one of `references` must be covered. When only grants past their
    /// chosen lifetime (dropped as expired, or expired since) would have
    /// covered it, the answer is `.expired`: those would not have spared the
    /// panel even without the restart. It only classifies a panel for the
    /// decision log.
    public func droppedGrantCovering(
        references: Set<String>,
        callerPID: pid_t,
        deliveryPlanDigest: String?,
        releaseShapeDigest: String?,
        callerAuditSessionID: UInt32?,
        widenedScopeOnly: Bool = false,
        now: Date = Date(),
        processInspection: ProcessInspection = .live
    ) -> GrantDropReason? {
        guard !references.isEmpty else { return nil }
        var covered: Set<String> = []
        var coveredWhileLive: Set<String> = []
        var liveReason: GrantDropReason?
        for grant in droppedAtLoad where grant.kind == .secret {
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
            guard !grant.references.isDisjoint(with: references),
                  processInspection.descends(
                      callerPID, from: grant.rootPID, rootStartTime: grant.rootStartTime
                  ) else { continue }
            covered.formUnion(grant.references)
            if Self.wouldStillCover(grant, now: now) {
                coveredWhileLive.formUnion(grant.references)
                liveReason = liveReason ?? grant.reason
            }
        }
        if references.isSubset(of: coveredWhileLive) { return liveReason }
        return references.isSubset(of: covered) ? .expired : nil
    }

    /// The SSH twin of `droppedGrantCovering`: a dropped signing grant for
    /// this key, server identity and remote user whose root the `ssh` runs
    /// under, with the same audit session and client identity.
    public func droppedSSHGrantCovering(
        keyFingerprint: String,
        hostKeyFingerprint: String,
        remoteUser: String,
        callerPID: pid_t,
        callerAuditSessionID: UInt32?,
        clientCDHash: String?,
        now: Date = Date(),
        processInspection: ProcessInspection = .live
    ) -> GrantDropReason? {
        let matching = droppedAtLoad.filter { grant in
            grant.kind == .ssh
                && grant.keyFingerprint == keyFingerprint
                && grant.hostKeyFingerprint == hostKeyFingerprint
                && grant.remoteUser == remoteUser
                && grant.auditSessionID == callerAuditSessionID
                && grant.clientCDHash == clientCDHash
                && processInspection.descends(
                    callerPID, from: grant.rootPID, rootStartTime: grant.rootStartTime
                )
        }
        if let live = matching.first(where: { Self.wouldStillCover($0, now: now) }) {
            return live.reason
        }
        return matching.isEmpty ? nil : .expired
    }

    /// A dropped grant that, had it been restored, would still be within the
    /// lifetime the human chose.
    private static func wouldStillCover(_ grant: DroppedGrant, now: Date) -> Bool {
        grant.reason != .expired && (grant.expiresAt.map { now < $0 } ?? true)
    }

    /// The load checks every persisted grant faces, in order. The audit
    /// session and digest bindings stay where they always were, at reuse.
    private func dropReason(
        epoch: Int,
        bootSessionUUID: String?,
        rootPID: Int32,
        rootStartTime: UInt64,
        expiresAt: Date?,
        now: Date,
        processInspection: ProcessInspection
    ) -> GrantDropReason? {
        guard epoch == Self.grantPolicyEpoch else { return .policyEpoch }
        // A boot this csecd cannot name cannot be shown to be the same boot.
        guard let current = facts.bootSessionUUID, bootSessionUUID == current else {
            return .bootSession
        }
        guard rootPID > 1, rootStartTime > 0,
              processInspection.startTime(of: rootPID) == rootStartTime else { return .rootExited }
        if let expiresAt, now >= expiresAt { return .expired }
        return nil
    }

    /// The secret grant table as it now stands. Written behind.
    public func update(secret grants: [Grant], generation: UInt64) {
        guard generation > secretGeneration else { return }
        secretGeneration = generation
        let records = grants.map(stamped)
        guard records != secret else { return }
        secret = records
        scheduleWrite()
    }

    /// The SSH signing grants as they now stand. Written behind.
    public func update(ssh grants: [PersistedSSHGrant], generation: UInt64) {
        guard generation > sshGeneration else { return }
        sshGeneration = generation
        let records = grants.map(stamped)
        guard records != ssh else { return }
        ssh = records
        scheduleWrite()
    }

    /// Writes the current state now and reports whether the item matches it.
    /// A write that fails deletes the whole item instead, which forgets every
    /// persisted grant and is therefore safe; only when that deletion fails
    /// too may an earlier document (holding what was just revoked) remain,
    /// and that is returned for `csec revoke` to report.
    ///
    /// An item this csecd could not read is kept: no grant this run revokes
    /// was ever in it. `discardingUnreadable` (`csec revoke --all`) deletes
    /// it instead, since a newer csecd would restore what it holds.
    public func persistNow(discardingUnreadable: Bool = false) async -> GrantPersistenceFailure? {
        dirty = false
        if discardingUnreadable, let reason = store.heldReason {
            do {
                _ = try await store.prepareDiscard().commit()
                FileHandle.standardError.write(Data(
                    "csecd: discarded the persisted grants this csecd could not read (\(reason)).\n".utf8
                ))
            } catch {
                return GrantPersistenceFailure(
                    description: "the persisted grants item this csecd could not read (\(reason)) could not be "
                        + "deleted (\(error)); a newer csecd could restore what it holds"
                )
            }
        }
        let change: ProtectedChange
        do {
            change = try prepareCurrent()
        } catch ProtectedStoreError.uninstalled {
            // Uninstall is deleting the item; nothing more is written.
            return nil
        } catch ProtectedStoreError.held {
            return nil
        } catch {
            return await deleteItem(after: error)
        }
        let failure: GrantPersistenceFailure?
        do {
            _ = try await change.commit()
            failure = nil
        } catch let error as ProtectedStoreError {
            switch error {
            case .writeFailedItemDeleted, .uninstalled:
                failure = nil
            default:
                failure = await deleteItem(after: error)
            }
        } catch {
            failure = await deleteItem(after: error)
        }
        await recordEviction()
        return failure
    }

    /// Waits until any write-behind, including a commit already under way, has
    /// finished. The state it wrote may already have been superseded; this
    /// only says nothing is pending.
    public func settle() async {
        while let pending = pendingWrite {
            await pending.value
        }
    }

    private func deleteItem(after failure: Error) async -> GrantPersistenceFailure? {
        do {
            _ = try await store.prepareDeletion().commit()
            FileHandle.standardError.write(Data(
                "csecd: persisted grants could not be written (\(failure)); the item was deleted instead.\n".utf8
            ))
            return nil
        } catch {
            let report = GrantPersistenceFailure(
                description: "the persisted grants item could not be written (\(failure)) "
                    + "or deleted (\(error)); an earlier copy may still hold what was revoked, "
                    + "and a csecd restart could restore it"
            )
            FileHandle.standardError.write(Data("csecd: \(report.description).\n".utf8))
            return report
        }
    }

    private func scheduleWrite() {
        dirty = true
        guard pendingWrite == nil else { return }
        pendingWrite = Task { await self.writeBehind() }
    }

    /// Writes the newest state until nothing is left to write. The task stays
    /// registered as `pendingWrite` until its last commit has finished, so
    /// `settle()` (the SIGTERM handler's) waits for a commit already under way,
    /// and a change made during a commit is written by the same task.
    private func writeBehind() async {
        defer { pendingWrite = nil }
        while dirty {
            dirty = false
            let change: ProtectedChange
            do {
                change = try prepareCurrent()
            } catch ProtectedStoreError.uninstalled {
                return
            } catch ProtectedStoreError.held {
                // Said once, at load.
                return
            } catch {
                FileHandle.standardError.write(Data(
                    "csecd: persisted grants not written (\(error)); they hold for this run only.\n".utf8
                ))
                continue
            }
            do {
                _ = try await change.commit()
            } catch ProtectedStoreError.uninstalled {
                return
            } catch {
                FileHandle.standardError.write(Data(
                    "csecd: persisted grants write failed (\(error)).\n".utf8
                ))
            }
            await recordEviction()
        }
    }

    /// Prepares the document for the current state, synchronously, so its
    /// place in the item's order matches the state it carries. Over the caps,
    /// the oldest grants are left out: they still hold for this run, and are
    /// only not restored after a restart.
    private func prepareCurrent() throws -> ProtectedChange {
        var document = GrantsDocument(
            secret: Self.newest(
                secret.filter(\.isWellFormed), limit: Self.maximumSecretGrants, by: \.mintedAt
            ),
            ssh: Self.newest(ssh.filter(\.isWellFormed), limit: Self.maximumSSHGrants, by: \.mintedAt)
        )
        do {
            let change = try store.prepare(document)
            noteOmissions(document)
            return change
        } catch ProtectedStoreError.rejected(.oversized) {
            document = Self.fitting(document, within: GrantsDocument.protectedItem.maximumBytes)
            let change = try store.prepare(document)
            noteOmissions(document)
            return change
        }
    }

    /// Grants left out of `document` that were not left out before: each is
    /// recorded once, as it is first evicted, however many writes follow
    /// while the item stays over its caps.
    private func noteOmissions(_ document: GrantsDocument) {
        let kept = Set(document.secret.map(\.id)).union(document.ssh.map(\.id))
        let live = Set(secret.map(\.id)).union(ssh.map(\.id))
        // A grant that is gone, or back in the item, may be reported again
        // if it is ever evicted again; this keeps the set within the state.
        reportedOmissions.formIntersection(live.subtracting(kept))
        let newSecret = secret.map(\.id).filter { !kept.contains($0) && !reportedOmissions.contains($0) }
        let newSSH = ssh.map(\.id).filter { !kept.contains($0) && !reportedOmissions.contains($0) }
        guard !newSecret.isEmpty || !newSSH.isEmpty else { return }
        reportedOmissions.formUnion(newSecret)
        reportedOmissions.formUnion(newSSH)
        let previous = pendingEviction ?? ([], [])
        pendingEviction = (previous.secret + newSecret, previous.ssh + newSSH)
        let count = newSecret.count + newSSH.count
        FileHandle.standardError.write(Data(
            ("csecd: \(count) oldest grant\(count == 1 ? "" : "s") left out of the persisted "
                + "grants item to stay within its limits; they hold for this run only.\n").utf8
        ))
    }

    /// Records the grants the last prepared document newly left out.
    private func recordEviction() async {
        guard let eviction = pendingEviction else { return }
        pendingEviction = nil
        guard let decisionLog else { return }
        let ids = eviction.secret.map { $0.uuidString.lowercased() }
            + eviction.ssh.map { GrantIDSelector.sshPrefix + $0.uuidString.lowercased() }
        var record = DecisionLogRecord(
            kind: .grantEviction,
            grantIDs: ids,
            detail: "\(ids.count) oldest grant\(ids.count == 1 ? "" : "s") left out of the persisted "
                + "grants item (at most \(Self.maximumSecretGrants) secret, \(Self.maximumSSHGrants) SSH, "
                + "\(GrantsDocument.protectedItem.maximumBytes / 1_024) KiB); they hold for this run "
                + "but will not be restored after a restart"
        )
        record.grants = DecisionLogRecord.GrantCounts(secret: eviction.secret.count, ssh: eviction.ssh.count)
        await decisionLog.record(record)
    }

    private static func newest<Record>(
        _ records: [Record], limit: Int, by mintedAt: KeyPath<Record, Date>
    ) -> [Record] {
        guard records.count > limit else { return records }
        return Array(records.sorted { $0[keyPath: mintedAt] < $1[keyPath: mintedAt] }.suffix(limit))
    }

    /// Drops the oldest grants of either kind until the encoded document fits
    /// the item, with room left for the envelope.
    private static func fitting(_ document: GrantsDocument, within maximumBytes: Int) -> GrantsDocument {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        enum Entry { case secret(PersistedSecretGrant), ssh(PersistedSSHGrant) }
        var entries: [(mintedAt: Date, size: Int, entry: Entry)] =
            document.secret.map { ($0.mintedAt, ((try? encoder.encode($0))?.count ?? maximumBytes) + 1, .secret($0)) }
            + document.ssh.map { ($0.mintedAt, ((try? encoder.encode($0))?.count ?? maximumBytes) + 1, .ssh($0)) }
        entries.sort { $0.mintedAt < $1.mintedAt }
        let budget = maximumBytes - 8 * 1_024
        var total = entries.reduce(0) { $0 + $1.size }
        var first = 0
        while total > budget, first < entries.count {
            total -= entries[first].size
            first += 1
        }
        var fitted = GrantsDocument()
        for (_, _, entry) in entries[first...] {
            switch entry {
            case let .secret(grant): fitted.secret.append(grant)
            case let .ssh(grant): fitted.ssh.append(grant)
            }
        }
        return fitted
    }

    private func stamped(_ grant: Grant) -> PersistedSecretGrant {
        PersistedSecretGrant(
            id: grant.id,
            rootPID: grant.rootPID,
            rootStartTime: grant.rootStartTime,
            references: grant.references.sorted(),
            reason: grant.reason,
            expiresAt: grant.expiresAt,
            requestID: grant.requestID,
            deliveryPlanDigest: grant.deliveryPlanDigest,
            peerPIDVersion: grant.peerPIDVersion,
            peerCDHash: grant.peerCDHash,
            plannedExecutable: grant.plannedExecutable,
            scopeKind: grant.scopeKind,
            scopeReuseDigest: grant.scopeReuseDigest,
            auditSessionID: grant.auditSessionID,
            rootProcessLabel: grant.rootProcessLabel,
            bootSessionUUID: facts.bootSessionUUID,
            mintedAt: grant.mintedAt,
            origin: grant.origin,
            mintedByBuild: grant.mintedByBuild ?? facts.build.map {
                ReviewDisplay.bounded(ReviewDisplay.sanitized($0), maxBytes: 256)
            },
            grantPolicyEpoch: Self.grantPolicyEpoch
        )
    }

    private func stamped(_ grant: PersistedSSHGrant) -> PersistedSSHGrant {
        var record = grant
        record.bootSessionUUID = facts.bootSessionUUID
        record.grantPolicyEpoch = Self.grantPolicyEpoch
        record.mintedByBuild = grant.mintedByBuild ?? facts.build.map {
            ReviewDisplay.bounded(ReviewDisplay.sanitized($0), maxBytes: 256)
        }
        return record
    }
}
