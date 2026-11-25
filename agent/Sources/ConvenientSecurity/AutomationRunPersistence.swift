import Foundation

/// One run lease as the `automation`/`runs-v1` protected item holds it: what a
/// restarted csecd checks before it serves the lease's launcher again.
/// Value-free: the values come back from the job's own materialization, and
/// only while the job still has the revision this run started under.
public struct PersistedAutomationRun: Codable, Sendable, Equatable {
    /// Why a lease stopped being releasable while its launcher may still run.
    public enum Invalidation: String, Codable, Sendable, Equatable {
        case expired
        case invalidated
    }

    public var runID: String
    public var jobName: String
    public var jobID: String
    public var revision: String
    public var launcherPID: Int32
    /// Epoch microseconds, compared exactly at restore.
    public var launcherStartTime: UInt64
    public var auditSessionID: UInt32?
    /// Awake-time deadline (`AutomationClock.awake`); nil for a
    /// process-lifetime daemon run. Awake time counts from boot, so it stays
    /// comparable across csecd restarts within one boot session.
    public var expiresAtAwake: TimeInterval?
    public var invalidation: Invalidation?
    public var bootSessionUUID: String?

    public init(
        runID: String,
        jobName: String,
        jobID: String,
        revision: String,
        launcherPID: Int32,
        launcherStartTime: UInt64,
        auditSessionID: UInt32?,
        expiresAtAwake: TimeInterval?,
        invalidation: Invalidation?,
        bootSessionUUID: String?
    ) {
        self.runID = runID
        self.jobName = jobName
        self.jobID = jobID
        self.revision = revision
        self.launcherPID = launcherPID
        self.launcherStartTime = launcherStartTime
        self.auditSessionID = auditSessionID
        self.expiresAtAwake = expiresAtAwake
        self.invalidation = invalidation
        self.bootSessionUUID = bootSessionUUID
    }

    public var isWellFormed: Bool {
        Self.isUUID(runID) && Self.isUUID(jobID) && Self.isUUID(revision)
            && AutomationJob.validName(jobName)
            && launcherPID > 1 && launcherStartTime > 0
            && (expiresAtAwake.map { $0.isFinite && $0 > 0 } ?? true)
            && (bootSessionUUID.map { !$0.isEmpty && $0.utf8.count <= 256 } ?? true)
    }

    private static func isUUID(_ value: String) -> Bool {
        UUID(uuidString: value)?.uuidString.lowercased() == value
    }
}

/// The `automation`/`runs-v1` document. The item is csecd-only (see
/// `ProtectedItem`), so a same-UID process can neither forge a lease into it
/// nor roll it back, and a restored lease never holds more than its launcher
/// held: the restore re-checks the launcher incarnation and the job revision.
public struct AutomationRunsDocument: ProtectedDocument, Equatable {
    public static let protectedItem: ProtectedItem = .automationRuns
    public static let formatVersion = 1
    public static let maximumRuns = 128
    /// It records no decision (the jobs and their approvals live in the
    /// catalog), and every lease change rewrites it whole from csecd's own
    /// leases. Holding one this build cannot read would only keep this csecd
    /// from persisting its leases and fail every job revoke for the run.
    public static let holdsUnreadableItem = false

    public var runs: [PersistedAutomationRun]

    public init(runs: [PersistedAutomationRun] = []) {
        self.runs = runs
    }

    public var isWellFormed: Bool {
        runs.count <= Self.maximumRuns
            && runs.allSatisfy(\.isWellFormed)
            && Set(runs.map(\.runID)).count == runs.count
    }
}

/// What a restarted csecd put back from the `automation`/`runs-v1` item.
public struct AutomationRunRestoration: Sendable, Equatable {
    /// The values one live restored lease can release, for csecd's output
    /// redactor: the launcher's command may have been given any of them
    /// before the restart, and the launcher reopens its scanner afterwards.
    public struct Release: Sendable, Equatable {
        public var valuesByReference: [String: Data]
        /// nil for a process-lifetime daemon run.
        public var expiresAt: Date?

        public init(valuesByReference: [String: Data], expiresAt: Date?) {
            self.valuesByReference = valuesByReference
            self.expiresAt = expiresAt
        }
    }

    /// Leases restored live, still releasing their job's values.
    public var live: Int
    /// Leases restored as tombstones: the launcher still runs, but its job was
    /// revoked or re-enrolled, its materialization is gone, or its runtime ran
    /// out, so its child is told why instead of being shown a panel.
    public var tombstones: Int
    /// Leases left out: a later boot, or a launcher that has exited.
    public var dropped: Int
    public var releases: [Release]
    /// Set when the item could not be read; nothing was restored.
    public var unreadable: String?

    public init(
        live: Int = 0,
        tombstones: Int = 0,
        dropped: Int = 0,
        releases: [Release] = [],
        unreadable: String? = nil
    ) {
        self.live = live
        self.tombstones = tombstones
        self.dropped = dropped
        self.releases = releases
        self.unreadable = unreadable
    }
}
