import CryptoKit
import Foundation

/// What a verification of the log found.
public struct DecisionLogVerification: Codable, Sendable, Equatable {
    public enum Status: String, Codable, Sendable {
        /// Every frame authenticated and the chain reaches the checkpoint.
        case clean
        /// No key, checkpoint or segments: a fresh log was started.
        case firstRun = "first_run"
        /// Clean, except a partly written final frame after a crash, which was
        /// cut off and recorded. Not tampering.
        case repaired
        /// The log was altered, cut, rolled back or spliced, its key or
        /// checkpoint is missing, a foreign file was planted in it, or its
        /// directory is unusable. Notified; recorded when `recorded` is true.
        case discrepancy
        /// The log could not be checked (no protected stores, a Keychain read
        /// error, an unusable directory before anything was ever recorded).
        case unavailable
    }

    public var status: Status
    public var findings: [DecisionLogRecord.IntegrityFinding]
    public var tornTails: [DecisionLogStream]
    public var decisionsHeadSeq: UInt64?
    public var usageHeadSeq: UInt64?
    public var checkedAt: DecisionLogTime
    public var detail: String?
    /// Whether the findings reached the log as a durable `log_integrity`
    /// record. When they could not, the checkpoint is left where it was, the
    /// log writes nothing more this run, and the next start (or `csec log
    /// --verify`) finds the same discrepancy again.
    public var recorded: Bool

    public init(
        status: Status,
        findings: [DecisionLogRecord.IntegrityFinding] = [],
        tornTails: [DecisionLogStream] = [],
        decisionsHeadSeq: UInt64? = nil,
        usageHeadSeq: UInt64? = nil,
        checkedAt: DecisionLogTime,
        detail: String? = nil,
        recorded: Bool = true
    ) {
        self.status = status
        self.findings = findings
        self.tornTails = tornTails
        self.decisionsHeadSeq = decisionsHeadSeq
        self.usageHeadSeq = usageHeadSeq
        self.checkedAt = checkedAt
        self.detail = detail
        self.recorded = recorded
    }

    public var isDiscrepancy: Bool { status == .discrepancy }
}

/// The log's state for `csec status`.
public struct DecisionLogStatus: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable {
        case active
        /// Persistence is unavailable to this csecd (no protected stores).
        case off
        case unavailable
        case uninstalled
    }

    public var state: State
    public var detail: String?
    public var lastVerification: DecisionLogVerification?
    /// Integrity findings this csecd run has made.
    public var integrityEvents: Int
    /// A finding this run could not record; it stays a live discrepancy.
    public var unrecordedFinding: Bool
    /// Records this run could not write (unavailable, or an I/O failure).
    public var droppedRecords: Int
    /// Checkpoint writes this run that failed or were refused. The
    /// checkpoint is the one anchor same-UID code cannot roll back, so a
    /// failure here is shown, never absorbed.
    public var checkpointWriteFailures: Int
    /// Files in the log directory csecd found but could not set aside or
    /// remove (an immutable entry, say), by name: they hold nothing up, and
    /// they are shown until someone removes them.
    public var stuckFiles: [String]
    /// The protected items, the log's own anchors among them, that this csecd
    /// could not read and keeps as found. `nil` from a csecd that predates
    /// the hold. Any entry fails `csec doctor`.
    public var heldItems: [HeldProtectedItem]?

    public init(
        state: State,
        detail: String? = nil,
        lastVerification: DecisionLogVerification? = nil,
        integrityEvents: Int = 0,
        unrecordedFinding: Bool = false,
        droppedRecords: Int = 0,
        checkpointWriteFailures: Int = 0,
        stuckFiles: [String] = [],
        heldItems: [HeldProtectedItem]? = nil
    ) {
        self.state = state
        self.detail = detail
        self.lastVerification = lastVerification
        self.integrityEvents = integrityEvents
        self.unrecordedFinding = unrecordedFinding
        self.droppedRecords = droppedRecords
        self.checkpointWriteFailures = checkpointWriteFailures
        self.stuckFiles = stuckFiles
        self.heldItems = heldItems
    }
}

/// A protected item csecd loaded as unreadable and keeps as found, value-free:
/// which item, why, and what makes it readable or removes it.
public struct HeldProtectedItem: Codable, Sendable, Equatable {
    /// What makes the item readable again, or removes it.
    public enum Cause: String, Codable, Sendable {
        /// A newer csec wrote it: reinstall the current build.
        case newerFormat = "newer_format"
        /// The Keychain refused the read: a restart reads it again.
        case keychain
        /// Damaged: only discarding it ends the hold.
        case damaged
        case unrecognized

        public init(from decoder: Decoder) throws {
            self = try decodeOpenEnum(decoder, unrecognized: .unrecognized)
        }
    }

    public var name: String
    public var cause: Cause
    public var reason: String
    public var remedy: String

    public init(name: String, cause: Cause, reason: String, remedy: String) {
        self.name = name
        self.cause = cause
        self.reason = reason
        self.remedy = remedy
    }

    public init(item: ProtectedItem, reason: ProtectedUnreadableReason) {
        let cause: Cause
        let remedy: String
        if reason.isNewerFormat {
            cause = .newerFormat
            remedy = "a newer csec wrote it. Install the latest Convenient Security package to read it again"
        } else if case .keychainError = reason {
            cause = .keychain
            remedy = "restart csecd to read it again (csec doctor does)"
        } else {
            cause = .damaged
            remedy = "it is damaged; \(item.discardCommand) removes it"
        }
        self.init(name: item.displayName, cause: cause, reason: reason.description, remedy: remedy)
    }

    /// Bounded and sanitized for display, as received from csecd.
    public var display: String {
        ReviewDisplay.bounded(
            ReviewDisplay.sanitized("\(name) (\(reason)): \(remedy)"), maxBytes: 512
        )
    }
}

/// A page position: the last sequence number examined in each stream.
public struct DecisionLogCursor: Codable, Sendable, Equatable {
    public var decisions: UInt64
    public var usage: UInt64

    public init(decisions: UInt64 = 0, usage: UInt64 = 0) {
        self.decisions = decisions
        self.usage = usage
    }

    subscript(stream: DecisionLogStream) -> UInt64 {
        get { stream == .decisions ? decisions : usage }
        set {
            if stream == .decisions { decisions = newValue } else { usage = newValue }
        }
    }
}

public struct DecisionLogQuery: Codable, Sendable, Equatable {
    public static let maximumLimit = 200

    public var streams: [DecisionLogStream]
    public var kinds: [DecisionLogRecord.Kind]?
    public var since: DecisionLogTime?
    public var after: DecisionLogCursor
    public var limit: Int

    public init(
        streams: [DecisionLogStream],
        kinds: [DecisionLogRecord.Kind]? = nil,
        since: DecisionLogTime? = nil,
        after: DecisionLogCursor = DecisionLogCursor(),
        limit: Int = maximumLimit
    ) {
        self.streams = streams
        self.kinds = kinds
        self.since = since
        self.after = after
        self.limit = limit
    }

    public var isWellFormed: Bool {
        !streams.isEmpty && Set(streams).count == streams.count
            && limit > 0 && limit <= Self.maximumLimit
            && (kinds?.count ?? 0) <= DecisionLogRecord.Kind.allCases.count
    }
}

public struct DecisionLogPage: Codable, Sendable, Equatable {
    public static let maximumEncodedBytes = 4 * 1_024 * 1_024

    public var records: [DecisionLogRecord]
    /// Where the next page starts, or nil when this was the last. A page may
    /// be empty and still have a `next`: the read budget ran out before
    /// anything matched.
    public var next: DecisionLogCursor?
    /// A frame failed to authenticate while reading: run `csec log --verify`.
    public var incomplete: Bool

    public init(records: [DecisionLogRecord], next: DecisionLogCursor?, incomplete: Bool = false) {
        self.records = records
        self.next = next
        self.incomplete = incomplete
    }
}

/// csecd's decision log: two AEAD-sealed, hash-chained, append-only streams of
/// value-free records, anchored by a key and a checkpoint that only csecd can
/// read or write (protected Keychain items).
///
/// Against same-UID code the files are ciphertext. A modified, reordered,
/// spliced, deleted, truncated or rolled-back segment is detected at startup
/// and by `csec log --verify`, recorded as `log_integrity`, notified, and the
/// chain resumes from the checkpoint in a fresh segment, with the damaged
/// segments set aside so the same finding is not raised again. The checkpoint
/// only ever moves forward, and it moves past a finding only once the finding
/// is durably recorded: a finding that cannot be recorded (a full disk, a
/// directory made unwritable) leaves the checkpoint where it was, stops the
/// log for the run, and is found again at the next start. What same-UID code
/// can still do is delete the files (a denial of service the checkpoint makes
/// visible) and, for `usage` only, cut the tail written since the last
/// debounced checkpoint.
///
/// Every file write first checks the protected stores' uninstalled state, the
/// one switch `csec uninstall` flips before deleting everything.
public actor DecisionLog {
    public enum State: Sendable, Equatable {
        case notOpened
        case active
        case unavailable(String)
        case uninstalled
    }

    struct Segment: Sendable {
        let name: DecisionLogSegmentName
        var firstSeq: UInt64
        var lastSeq: UInt64
        var lastTag: Data
        var length: UInt64

        var lastLink: DecisionLogChainLink {
            DecisionLogChainLink(segmentID: name.segmentID, seq: lastSeq, tag: lastTag)
        }
    }

    struct Durable: Sendable {
        let link: DecisionLogChainLink
        let length: UInt64
    }

    /// A file set aside by a finding. Only its size counts (toward the
    /// stream's cap); it is never read again. `number` orders pruning and is
    /// 0 for a name csecd did not write.
    struct QuarantinedFile: Sendable {
        let name: String
        let number: UInt64
        let size: UInt64
    }

    struct StreamState: Sendable {
        var segments: [Segment] = []
        var quarantined: [QuarantinedFile] = []
        var head: DecisionLogChainLink?
        var durable: Durable?
        var prunedThroughSeq: UInt64 = 0
        var nextNumber: UInt64 = 1
        var dirty = false

        /// Only verified segments count toward the stream's cap, so nothing
        /// planted in the directory can make csecd prune real history.
        var liveBytes: UInt64 { segments.reduce(0) { $0 + $1.length } }
        /// Set-aside files have a budget of their own (see `pruneIfNeeded`).
        var setAsideBytes: UInt64 { quarantined.reduce(0) { $0 &+ $1.size } }
    }

    /// A file a load decided to set aside only after its finding is durable,
    /// so a finding that cannot be recorded is found again next time.
    private struct DeferredSetAside {
        let stream: DecisionLogStream
        let name: String
        let number: UInt64
        let size: UInt64
    }

    private struct ForeignFile {
        let name: String
        let size: UInt64
    }

    /// The directory as listed. Names are classified by their exact format
    /// only: a live segment is a name csecd could have generated; a
    /// `.quarantined` name is set aside; any other segment-shaped name is a
    /// foreign file. Nothing here is trusted, and no listed name ever sets a
    /// segment number.
    private struct Listing {
        var live: [DecisionLogStream: [DecisionLogSegmentName]] = [:]
        var quarantined: [DecisionLogStream: [QuarantinedFile]] = [:]
        var foreign: [DecisionLogStream: [ForeignFile]] = [:]
        var sizes: [String: UInt64] = [:]

        var hasSegments: Bool {
            live.values.contains { !$0.isEmpty } || foreign.values.contains { !$0.isEmpty }
        }
    }

    /// Where a verification expects a stream's chain to reach.
    private struct Expectation {
        let link: DecisionLogChainLink
        let length: UInt64
    }

    private struct Walk {
        var kept: [Segment] = []
        /// Live-named files with no authentic frame at all (planted junk, a
        /// segment copied under another name). They are set aside and the
        /// chain carries on past them: they are not part of it.
        var junk: [DecisionLogSegmentName] = []
        var failure: DecisionLogRecord.IntegrityFinding.Kind?
        var failureIndex: Int?
        /// The failed segment's verified prefix, for a torn tail.
        var failedPrefix: Segment?
        var tornCandidate = false
        var reachedExpectation = false
        var highestSeq: UInt64 = 0
        /// Leftovers of an interrupted prune, to delete.
        var prunedLeftovers: [DecisionLogSegmentName] = []
    }

    /// A stream's chain resumes in a fresh segment whose first record says so.
    private struct PendingResume {
        let liveBefore: DecisionLogChainLink?
        let chain: DecisionLogChainLink?
        let seq: UInt64
    }

    /// What a read needs, copied off the actor so the scan runs without it:
    /// releases and SSH signatures that record to the log never wait on a
    /// `csec log` scan.
    struct ReadSnapshot: Sendable {
        let directory: SealedRecordDirectory
        let frameKey: Data
        let limits: DecisionLogLimits
        let segments: [DecisionLogStream: [Segment]]
    }

    private static let ioSlackBytes: UInt64 = 128 * 1_024

    private let directory: SealedRecordDirectory
    private let stores: ProtectedStores
    private let keyStore: ProtectedStore<DecisionLogKeyDocument>
    private let checkpointStore: ProtectedStore<DecisionLogCheckpoint>
    private let limits: DecisionLogLimits
    private let clock: @Sendable () -> Date
    private let bootSessionUUID: String?
    private let onIntegrityEvent: @Sendable (DecisionLogVerification) -> Void

    private var state = State.notOpened
    private var masterKey: SymmetricKey?
    private var frameKey: SymmetricKey?
    private var frameKeyData: Data?
    private var streams: [DecisionLogStream: StreamState] = [.decisions: StreamState(), .usage: StreamState()]
    private var handles: [DecisionLogStream: SealedAppendHandle] = [:]
    /// The heads of the last checkpoint loaded or committed. A checkpoint
    /// never moves a head backwards or drops one.
    private var anchor: [DecisionLogStream: DecisionLogStreamHead] = [:]
    /// Bytes synced with plain `fsync` since the last `F_FULLFSYNC`; flushed
    /// fully before the next checkpoint names them.
    private var pendingFullSync = false
    /// A finding could not be recorded; the next `verify()` reopens from the
    /// Keychain checkpoint and tries again.
    private var recoveryPending = false
    private var usageFlush: Task<Void, Never>?
    private var pruning = false
    private var lastVerification: DecisionLogVerification?
    private var integrityEvents = 0
    private var droppedRecords = 0
    private var checkpointWriteFailures = 0
    /// Digests of recorded files csecd could not set aside (persisted in the
    /// checkpoint), and the names found this run for `csec status`.
    private var unmovable: [String] = []
    private var anchorUnmovable: [String] = []
    /// Digests of csecd's own damaged segments that could not be set aside
    /// (persisted in the checkpoint, never evicted for planted files).
    private var excludedSegments: [String] = []
    private var anchorExcluded: [String] = []
    private var stuckNames: [String] = []
    /// Set-aside files csecd could not remove while pruning; not retried
    /// every append, and shown in `csec status`.
    private var unremovable: Set<String> = []

    public init(
        directory: SealedRecordDirectory = SealedRecordDirectory(path: DecisionLog.defaultDirectoryPath()),
        stores: ProtectedStores,
        limits: DecisionLogLimits = .standard,
        bootSessionUUID: String? = CsecdRunFacts.bootSessionUUID(),
        clock: @escaping @Sendable () -> Date = { Date() },
        onIntegrityEvent: @escaping @Sendable (DecisionLogVerification) -> Void = { _ in }
    ) {
        self.directory = directory
        self.stores = stores
        self.keyStore = stores.store(for: DecisionLogKeyDocument.self)
        self.checkpointStore = stores.store(for: DecisionLogCheckpoint.self)
        self.limits = limits
        self.bootSessionUUID = bootSessionUUID
        self.clock = clock
        self.onIntegrityEvent = onIntegrityEvent
    }

    public static func defaultDirectoryPath() -> String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("ConvenientSecurity", isDirectory: true)
            .appendingPathComponent("DecisionLog", isDirectory: true)
            .path
    }

    public var currentState: State { state }

    public func status() -> DecisionLogStatus {
        let mapped: DecisionLogStatus.State
        var detail: String?
        switch state {
        case .active: mapped = .active
        case .notOpened:
            mapped = .unavailable
            detail = "not opened"
        case let .unavailable(reason):
            mapped = .unavailable
            detail = reason
        case .uninstalled: mapped = .uninstalled
        }
        return DecisionLogStatus(
            state: mapped,
            detail: detail,
            lastVerification: lastVerification,
            integrityEvents: integrityEvents,
            unrecordedFinding: recoveryPending,
            droppedRecords: droppedRecords,
            checkpointWriteFailures: checkpointWriteFailures,
            stuckFiles: Array(uniqueStuckNames().prefix(8)).map {
                ReviewDisplay.bounded(ReviewDisplay.sanitized($0), maxBytes: 128)
            },
            heldItems: stores.heldItems.map { HeldProtectedItem(item: $0.item, reason: $0.reason) }
        )
    }

    /// A file a load found stuck can also be one a prune could not unlink
    /// this run; it is named once.
    private func uniqueStuckNames() -> [String] {
        var seen: Set<String> = []
        return (stuckNames + unremovable.sorted()).filter { seen.insert($0).inserted }
    }

    /// A key for another sealed csecd file, derived from the log's master key
    /// for that `purpose` alone, so neither can stand in for the other. Nil
    /// until the log is open, or when it is unavailable.
    public func sealingKey(purpose: String) -> SymmetricKey? {
        guard let masterKey else { return nil }
        return HKDF<SHA256>.deriveKey(
            inputKeyMaterial: masterKey,
            info: Data("csec-sealed-record-v1 \(purpose)".utf8),
            outputByteCount: 32
        )
    }

    // MARK: - Opening and verification

    /// Loads the key and checkpoint, verifies both streams against them, and
    /// repairs what it must: a torn final frame is cut off and recorded; a
    /// discrepancy is recorded as `log_integrity`, notified, the damaged
    /// segments set aside and the chain resumed from the checkpoint. Only "no
    /// key, no checkpoint, no segments" is a first run; any other absence is a
    /// finding, never a silent fresh start.
    @discardableResult
    public func open() async -> DecisionLogVerification {
        guard state == .notOpened else {
            return lastVerification ?? verification(.unavailable, detail: "already opened")
        }
        guard !stores.isUninstalled else {
            state = .uninstalled
            return verification(.unavailable, detail: "uninstalled")
        }
        let checkpoint: DecisionLogCheckpoint?
        switch await checkpointStore.load() {
        case .absent: checkpoint = nil
        case let .document(document): checkpoint = document
        case let .unreadable(reason):
            return becomeUnavailable("the checkpoint is unreadable: \(reason)")
        }
        let storedKey: Data?
        switch await keyStore.load() {
        case .absent: storedKey = nil
        case let .document(document): storedKey = document.key
        case let .unreadable(reason):
            return becomeUnavailable("the key is unreadable: \(reason)")
        }
        anchor = [:]
        for stream in DecisionLogStream.allCases {
            anchor[stream] = checkpoint?[stream]
        }
        unmovable = checkpoint?.unmovable ?? []
        anchorUnmovable = unmovable
        excludedSegments = checkpoint?.excludedSegments ?? []
        anchorExcluded = excludedSegments
        let listing: Listing
        do {
            listing = try list()
        } catch {
            return directoryUnusable(error, anchored: checkpoint != nil || storedKey != nil)
        }

        guard let storedKey else {
            guard await createKey() else {
                return becomeUnavailable("the log key could not be stored")
            }
            if checkpoint == nil && !listing.hasSegments {
                return await load(
                    expectations: nil, prunedThrough: [:], checkpointMissing: false,
                    listing: listing, firstRun: true
                )
            }
            return await recoverFromMissingKey(checkpoint: checkpoint, listing: listing)
        }
        useKey(storedKey)
        return await load(
            expectations: checkpoint.map { cp in
                Dictionary(uniqueKeysWithValues: DecisionLogStream.allCases.compactMap { stream in
                    cp[stream].map { (stream, Expectation(link: $0.link, length: $0.length)) }
                })
            },
            prunedThrough: DecisionLogStream.allCases.reduce(into: [:]) {
                $0[$1] = checkpoint?[$1]?.prunedThroughSeq ?? 0
            },
            checkpointMissing: checkpoint == nil && listing.hasSegments,
            listing: listing,
            firstRun: false
        )
    }

    /// Re-verifies the files against what this csecd has written: its own
    /// in-memory heads, which are never behind the checkpoint it committed. A
    /// finding is handled exactly as at startup. After a finding this run
    /// could not record, it starts over from the Keychain checkpoint instead,
    /// so the finding is raised again until it is recorded.
    public func verify() async -> DecisionLogVerification {
        guard !stores.isUninstalled, state != .uninstalled else {
            return verification(.unavailable, detail: "uninstalled")
        }
        if recoveryPending {
            resetForReopen()
            return await open()
        }
        guard state == .active else {
            return lastVerification ?? verification(.unavailable, detail: "the log is unavailable")
        }
        await flushUsageCheckpoint()
        closeHandles()
        let listing: Listing
        do {
            listing = try list()
        } catch {
            return directoryUnusable(error, anchored: true)
        }
        var expectations: [DecisionLogStream: Expectation] = [:]
        var prunedThrough: [DecisionLogStream: UInt64] = [:]
        for stream in DecisionLogStream.allCases {
            let current = streams[stream] ?? StreamState()
            prunedThrough[stream] = current.prunedThroughSeq
            if let head = current.head,
               let segment = current.segments.last(where: { $0.name.segmentID == head.segmentID }) {
                expectations[stream] = Expectation(link: head, length: segment.length)
            }
        }
        return await load(
            expectations: expectations, prunedThrough: prunedThrough,
            checkpointMissing: false, listing: listing, firstRun: false
        )
    }

    private func load(
        expectations: [DecisionLogStream: Expectation]?,
        prunedThrough: [DecisionLogStream: UInt64],
        checkpointMissing: Bool,
        listing: Listing,
        firstRun: Bool
    ) async -> DecisionLogVerification {
        guard let frameKey else { return becomeUnavailable("no log key") }
        var findings: [DecisionLogRecord.IntegrityFinding] = []
        var resumes: [DecisionLogStream: PendingResume] = [:]
        var tornTails: [(stream: DecisionLogStream, bytes: UInt64)] = []
        var loaded: [DecisionLogStream: StreamState] = [:]
        var deferred: [DeferredSetAside] = []
        /// Files in a chain finding's set-aside range that cannot be moved:
        /// they are remembered (once the finding is durable) and left out of
        /// every later walk, rather than holding the log. `ownSegment` says
        /// the file is one of csecd's own segments, not a planted name.
        var chainUnmovable: [(name: String, ownSegment: Bool)] = []
        let known = Set(unmovable)
        let knownExcluded = Set(excludedSegments)
        var stillUnmovable: [String] = []
        var stillExcluded: [String] = []
        stuckNames = []

        /// A file already recorded as unmovable is not a new finding: it is
        /// set aside quietly if it can be now, and otherwise left and listed.
        func alreadyRecorded(_ stream: DecisionLogStream, _ name: String, _ number: UInt64, _ size: UInt64) -> Bool {
            let digest = DecisionLogCheckpoint.unmovableDigest(name)
            let excluded = knownExcluded.contains(digest)
            guard excluded || known.contains(digest) else { return false }
            if let target = setAside(name, stream: stream) {
                loaded[stream, default: StreamState()].quarantined.append(
                    QuarantinedFile(name: target, number: number, size: size)
                )
            } else {
                if excluded { stillExcluded.append(digest) } else { stillUnmovable.append(digest) }
                stuckNames.append(name)
            }
            return true
        }

        for stream in DecisionLogStream.allCases {
            // A live-named file an earlier finding recorded but could not move
            // is no part of the chain: it is left out of the walk (and set
            // aside quietly once it can be).
            let live = (listing.live[stream] ?? []).filter { name in
                !alreadyRecorded(stream, name.fileName, name.number, listing.sizes[name.fileName] ?? 0)
            }
            let expectation = expectations?[stream]
            let pruned = prunedThrough[stream] ?? 0
            let walk = self.walk(
                stream: stream, live: live, expectation: expectation,
                prunedThroughSeq: pruned, key: frameKey
            )
            for leftover in walk.prunedLeftovers where (try? directory.remove(leftover.fileName)) == nil {
                // Pruned on purpose already; it only cannot be unlinked.
                stuckNames.append(leftover.fileName)
            }
            var next = StreamState()
            next.prunedThroughSeq = pruned
            next.quarantined = listing.quarantined[stream] ?? []
            next.segments = walk.kept

            // Junk that carried no authentic frame: set aside once recorded.
            var junkNames: [String] = []
            for name in walk.junk {
                let size = listing.sizes[name.fileName] ?? 0
                if alreadyRecorded(stream, name.fileName, name.number, size) { continue }
                junkNames.append(name.fileName)
                deferred.append(DeferredSetAside(stream: stream, name: name.fileName, number: name.number, size: size))
            }
            if !junkNames.isEmpty {
                findings.append(DecisionLogRecord.IntegrityFinding(
                    stream: stream, finding: .splicedSegment, quarantined: junkNames
                ))
            }

            let failedIsLast = walk.failureIndex.map { $0 == live.count - 1 } ?? false
            let reached = expectation == nil || walk.reachedExpectation
            var finding: DecisionLogRecord.IntegrityFinding.Kind?
            var tornHandled = false
            if let failure = walk.failure {
                if walk.tornCandidate && failedIsLast && reached {
                    // Uncommitted bytes after the durable head: a crash cut
                    // the last write short. Keep the verified prefix.
                    let failedName = live[walk.failureIndex!]
                    let fileSize = listing.sizes[failedName.fileName] ?? 0
                    if let prefix = walk.failedPrefix {
                        try? directory.truncate(failedName.fileName, to: prefix.length)
                        next.segments.append(prefix)
                        tornTails.append((stream, fileSize - min(fileSize, prefix.length)))
                    } else {
                        try? directory.remove(failedName.fileName)
                        tornTails.append((stream, fileSize))
                    }
                    tornHandled = true
                } else if walk.tornCandidate && failedIsLast {
                    // Cut short before the durable head: committed frames
                    // are gone.
                    finding = .behindCheckpoint
                } else {
                    finding = failure
                }
            } else if let expectation, !walk.reachedExpectation {
                finding = (walk.kept.last?.lastSeq ?? 0) < expectation.link.seq
                    ? .behindCheckpoint : .checkpointMismatch
            }
            if finding == nil, checkpointMissing, !live.isEmpty {
                finding = .checkpointMissing
            }

            if let finding {
                let quarantineFrom = tornHandled ? live.count : (walk.failureIndex ?? live.count)
                var setAside: [String] = []
                for name in live[quarantineFrom...] {
                    guard let target = self.setAside(name.fileName, stream: stream) else {
                        chainUnmovable.append((
                            name.fileName, isOwnSegment(name, stream: stream, key: frameKey)
                        ))
                        setAside.append(name.fileName)
                        continue
                    }
                    setAside.append(name.fileName)
                    next.quarantined.append(QuarantinedFile(
                        name: target, number: name.number, size: listing.sizes[name.fileName] ?? 0
                    ))
                }
                let liveBefore = next.segments.last?.lastLink
                let resumedFrom = expectation?.link ?? liveBefore
                let seq = max(
                    expectation?.link.seq ?? 0, walk.highestSeq, liveBefore?.seq ?? 0, pruned
                ) + 1
                resumes[stream] = PendingResume(liveBefore: liveBefore, chain: resumedFrom, seq: seq)
                findings.append(DecisionLogRecord.IntegrityFinding(
                    stream: stream, finding: finding, quarantined: setAside,
                    liveBefore: liveBefore, resumedFrom: resumedFrom
                ))
            }

            // A segment-shaped name csecd never writes is set aside unread,
            // once the finding is durable. It breaks no chain, so the stream
            // does not resume, but something other than csecd wrote here.
            var foreignNames: [String] = []
            for file in listing.foreign[stream] ?? [] {
                if alreadyRecorded(stream, file.name, 0, file.size) { continue }
                foreignNames.append(file.name)
                deferred.append(DeferredSetAside(stream: stream, name: file.name, number: 0, size: file.size))
            }
            if !foreignNames.isEmpty {
                findings.append(DecisionLogRecord.IntegrityFinding(
                    stream: stream, finding: .foreignFile, quarantined: foreignNames
                ))
            }

            // Segment numbers come only from verified segments csecd wrote,
            // never from a listed name.
            next.nextNumber = (next.segments.last?.name.number ?? 0) + 1
            if let last = next.segments.last {
                next.head = last.lastLink
                next.durable = Durable(link: last.lastLink, length: last.length)
            }
            next.quarantined += loaded[stream]?.quarantined ?? []
            loaded[stream] = next
        }
        streams = loaded
        state = .active
        attachLastSegments()
        return await finishLoad(
            findings: findings, resumes: resumes, tornTails: tornTails,
            deferred: deferred, chainUnmovable: chainUnmovable,
            stillUnmovable: stillUnmovable, stillExcluded: stillExcluded, firstRun: firstRun
        )
    }

    private func recoverFromMissingKey(
        checkpoint: DecisionLogCheckpoint?,
        listing: Listing
    ) async -> DecisionLogVerification {
        var findings: [DecisionLogRecord.IntegrityFinding] = []
        var resumes: [DecisionLogStream: PendingResume] = [:]
        var loaded: [DecisionLogStream: StreamState] = [:]
        var deferred: [DeferredSetAside] = []
        stuckNames = []
        for stream in DecisionLogStream.allCases {
            var next = StreamState()
            next.quarantined = listing.quarantined[stream] ?? []
            next.prunedThroughSeq = checkpoint?[stream]?.prunedThroughSeq ?? 0
            let unreadable = (listing.live[stream] ?? []).map { ($0.fileName, $0.number) }
                + (listing.foreign[stream] ?? []).map { ($0.name, UInt64(0)) }
            let head = checkpoint?[stream]
            if !unreadable.isEmpty || head != nil {
                let setAside = unreadable.map(\.0)
                for (name, number) in unreadable {
                    deferred.append(DeferredSetAside(
                        stream: stream, name: name, number: number, size: listing.sizes[name] ?? 0
                    ))
                }
                resumes[stream] = PendingResume(
                    liveBefore: nil, chain: head?.link, seq: (head?.seq ?? next.prunedThroughSeq) + 1
                )
                findings.append(DecisionLogRecord.IntegrityFinding(
                    stream: stream, finding: .keyMissing, quarantined: setAside,
                    liveBefore: nil, resumedFrom: head?.link
                ))
            }
            loaded[stream] = next
        }
        streams = loaded
        state = .active
        return await finishLoad(
            findings: findings, resumes: resumes, tornTails: [],
            deferred: deferred, chainUnmovable: [], stillUnmovable: [], stillExcluded: [], firstRun: false
        )
    }

    /// Writes what a load found: each resumed stream's first record, one
    /// `log_integrity` record for all findings, a `torn_tail` record per cut
    /// tail, then the checkpoint. The checkpoint moves past a finding only
    /// once the finding is durably on disk; otherwise the log holds at the
    /// old checkpoint (see `holdAtCheckpoint`).
    private func finishLoad(
        findings: [DecisionLogRecord.IntegrityFinding],
        resumes: [DecisionLogStream: PendingResume],
        tornTails: [(stream: DecisionLogStream, bytes: UInt64)],
        deferred: [DeferredSetAside],
        chainUnmovable: [(name: String, ownSegment: Bool)],
        stillUnmovable: [String],
        stillExcluded: [String],
        firstRun: Bool
    ) async -> DecisionLogVerification {
        if !findings.isEmpty { integrityEvents += 1 }
        var recorded = true
        if recorded, let usageResume = resumes[.usage] {
            var marker = DecisionLogRecord(
                kind: .chainResume,
                detail: "the usage chain resumes after a log_integrity finding"
            )
            marker.integrity = findings.filter { $0.stream == .usage }
            recorded = writeFrame(marker, resume: usageResume, sync: .full)
        }
        if recorded, !findings.isEmpty {
            var record = DecisionLogRecord(
                kind: .logIntegrity,
                detail: findings.map { "\($0.stream.rawValue): \($0.finding.rawValue)" }
                    .joined(separator: "; ")
            )
            record.integrity = findings
            recorded = writeFrame(record, resume: resumes[.decisions], sync: .full)
        }
        guard recorded else {
            return holdAtCheckpoint(findings: findings)
        }
        // Recorded: now set the junk and foreign files aside. One that cannot
        // be moved (an immutable entry), like a damaged chain segment that
        // could not be, is left where it is: it is recorded, it is remembered
        // so later walks leave it out and it is not raised again, and `csec
        // status` lists it. It never holds the log.
        var nowUnmovable = stillUnmovable
        // csecd's own damaged segments go on a list of their own, after the
        // ones already there, so nothing new (least of all a planted file)
        // ever pushes one out: walked again, it would break the chain and set
        // aside everything written since, at every start. Anything else in
        // the range is a planted name, remembered like junk.
        var nowExcluded = stillExcluded
        for entry in chainUnmovable {
            let digest = DecisionLogCheckpoint.unmovableDigest(entry.name)
            if entry.ownSegment { nowExcluded.append(digest) } else { nowUnmovable.append(digest) }
            stuckNames.append(entry.name)
        }
        for entry in deferred {
            if let target = setAside(entry.name, stream: entry.stream) {
                streams[entry.stream]?.quarantined.append(
                    QuarantinedFile(name: target, number: entry.number, size: entry.size)
                )
            } else {
                nowUnmovable.append(DecisionLogCheckpoint.unmovableDigest(entry.name))
                stuckNames.append(entry.name)
            }
        }
        unmovable = Array(Set(nowUnmovable).sorted().prefix(DecisionLogCheckpoint.maximumUnmovable))
        excludedSegments = Array(Self.orderedUnique(nowExcluded).prefix(DecisionLogCheckpoint.maximumExcludedSegments))
        for torn in tornTails {
            _ = writeFrame(DecisionLogRecord(
                kind: .tornTail,
                detail: "cut \(torn.bytes) bytes of a partly written \(torn.stream.rawValue) frame"
            ), resume: nil, sync: .full)
        }
        // Also after a clean load: the verified chain may run past a lagging
        // usage checkpoint, and the checkpoint follows what was verified.
        _ = await commitCheckpoint()
        let status: DecisionLogVerification.Status = !findings.isEmpty
            ? .discrepancy : (!tornTails.isEmpty ? .repaired : (firstRun ? .firstRun : .clean))
        let result = verification(status, findings: findings, tornTails: tornTails.map(\.stream))
        lastVerification = result
        if !findings.isEmpty { onIntegrityEvent(result) }
        return result
    }

    /// A finding that could not be recorded: nothing chains onto what was
    /// found, the checkpoint stays where it was (so the next start finds the
    /// same discrepancy), `csec status` shows it, and the user is notified.
    private func holdAtCheckpoint(findings: [DecisionLogRecord.IntegrityFinding]) -> DecisionLogVerification {
        closeHandles()
        recoveryPending = true
        let reason = "an integrity finding could not be recorded; "
            + "the log is held at its checkpoint and records nothing more until it can be"
        state = .unavailable(reason)
        let result = verification(.discrepancy, findings: findings, detail: reason, recorded: false)
        lastVerification = result
        onIntegrityEvent(result)
        return result
    }

    /// The directory cannot be opened even after csecd restores its own
    /// mode. When the log was already anchored (a key or checkpoint exists),
    /// that is a finding this run cannot record, and the user is notified.
    private func directoryUnusable(_ error: Error, anchored: Bool) -> DecisionLogVerification {
        closeHandles()
        let reason = "the log directory is unusable: \(error)"
        state = .unavailable(reason)
        guard anchored else {
            let result = verification(.unavailable, detail: reason)
            lastVerification = result
            return result
        }
        integrityEvents += 1
        recoveryPending = true
        let result = verification(
            .discrepancy,
            findings: [DecisionLogRecord.IntegrityFinding(stream: .decisions, finding: .directoryUnusable)],
            detail: reason,
            recorded: false
        )
        lastVerification = result
        onIntegrityEvent(result)
        return result
    }

    /// Whether `name`'s first frame authenticates as the first frame of that
    /// segment: it is one of csecd's own segments. A same-UID process can
    /// neither forge one nor copy one under another name (the segment ID is
    /// in every frame's associated data).
    private func isOwnSegment(_ name: DecisionLogSegmentName, stream: DecisionLogStream, key: SymmetricKey) -> Bool {
        guard let data = try? directory.read(
            name.fileName, maximumBytes: Int(limits.segmentBytes + Self.ioSlackBytes)
        ), case let .frame(seq, nonce, ciphertext, tag, _) = DecisionLogFrame.parse(
            [UInt8](data), at: 0, maximumRecordBytes: limits.maximumRecordBytes
        ) else { return false }
        return DecisionLogFrame.open(
            nonce: nonce, ciphertext: ciphertext, tag: tag, key: key,
            associatedData: DecisionLogFrame.associatedData(
                stream: stream, segmentID: name.segmentID, seq: seq, previousTag: DecisionLogFrame.zeroTag
            )
        ) != nil
    }

    private static func orderedUnique(_ values: [String]) -> [String] {
        var seen: Set<String> = []
        return values.filter { seen.insert($0).inserted }
    }

    /// Verifies one stream's live segments in order: every frame authenticates
    /// under the chained associated data, sequence numbers run without a gap,
    /// each segment's first record links to the previous segment's last frame
    /// (or resumes after a recorded finding), and the oldest segment starts
    /// where pruning left off. Only the chain fields of a first record are
    /// decoded, so a newer csecd's records verify here too. Stops at the
    /// first failure.
    private func walk(
        stream: DecisionLogStream,
        live: [DecisionLogSegmentName],
        expectation: Expectation?,
        prunedThroughSeq: UInt64,
        key: SymmetricKey
    ) -> Walk {
        var walk = Walk()
        var previous: DecisionLogChainLink?
        var oldest = true
        let decoder = JSONDecoder()
        for (index, name) in live.enumerated() {
            let data: Data?
            do {
                data = try directory.read(
                    name.fileName, maximumBytes: Int(limits.segmentBytes + Self.ioSlackBytes)
                )
            } catch {
                data = nil
            }
            guard let data else {
                // Unreadable (too large, say): nothing authentic in it.
                walk.junk.append(name)
                continue
            }
            let bytes = [UInt8](data)
            var offset = 0
            var previousTag = DecisionLogFrame.zeroTag
            var segment: Segment?
            var firstAuthentic = false
            var failure: DecisionLogRecord.IntegrityFinding.Kind?
            var torn = false
            var isLeftover = false
            frames: while true {
                switch DecisionLogFrame.parse(bytes, at: offset, maximumRecordBytes: limits.maximumRecordBytes) {
                case .end:
                    break frames
                case .incomplete:
                    failure = .modifiedRecord
                    torn = true
                    break frames
                case .malformed:
                    failure = .modifiedRecord
                    torn = bytes[offset...].allSatisfy { $0 == 0 }
                    break frames
                case let .frame(seq, nonce, ciphertext, tag, next):
                    let first = segment == nil
                    guard let plaintext = DecisionLogFrame.open(
                        nonce: nonce, ciphertext: ciphertext, tag: tag, key: key,
                        associatedData: DecisionLogFrame.associatedData(
                            stream: stream, segmentID: name.segmentID, seq: seq,
                            previousTag: first ? DecisionLogFrame.zeroTag : previousTag
                        )
                    ) else {
                        failure = first ? .splicedSegment : .modifiedRecord
                        // Only the very last bytes of the stream can be a
                        // write a crash cut short.
                        torn = next == bytes.count
                        break frames
                    }
                    if first {
                        firstAuthentic = true
                        guard let record = try? decoder.decode(DecisionLogChainProjection.self, from: plaintext),
                              record.seq == seq else {
                            failure = .modifiedRecord
                            break frames
                        }
                        if oldest, prunedThroughSeq > 0, seq <= prunedThroughSeq {
                            isLeftover = true
                        } else if !Self.linkIsValid(
                            record: record, seq: seq, previous: previous,
                            oldest: oldest, prunedThroughSeq: prunedThroughSeq
                        ) {
                            failure = oldest ? .pruneGap : .missingSegment
                            break frames
                        }
                        // A resume csecd recorded from exactly the checkpoint
                        // head: the finding was written and only the
                        // checkpoint commit after it was lost (a crash).
                        if let expectation, record.resume != nil,
                           record.chain == expectation.link, seq > expectation.link.seq {
                            walk.reachedExpectation = true
                        }
                        segment = Segment(name: name, firstSeq: seq, lastSeq: seq, lastTag: tag, length: UInt64(next))
                    } else {
                        guard seq == segment!.lastSeq + 1 else {
                            failure = .modifiedRecord
                            break frames
                        }
                        segment!.lastSeq = seq
                        segment!.lastTag = tag
                        segment!.length = UInt64(next)
                    }
                    walk.highestSeq = max(walk.highestSeq, seq)
                    if let expectation, seq == expectation.link.seq, !walk.reachedExpectation {
                        guard name.segmentID == expectation.link.segmentID,
                              tag == expectation.link.tag,
                              UInt64(next) == expectation.length else {
                            failure = .checkpointMismatch
                            break frames
                        }
                        walk.reachedExpectation = true
                    }
                    previousTag = tag
                    offset = next
                }
            }
            if !firstAuthentic {
                // No authentic frame at all. As the last file, a crash while
                // starting it (an empty or half-written first frame) is decided
                // after the walk; anywhere else, or anything else, it is junk
                // that is not part of the chain, and the chain goes on past it.
                let crashShaped = failure == nil || torn
                if index == live.count - 1, crashShaped {
                    walk.failure = failure ?? .missingSegment
                    walk.failureIndex = index
                    walk.tornCandidate = true
                    return walk
                }
                walk.junk.append(name)
                continue
            }
            if isLeftover, failure == nil, let segment, segment.lastSeq <= prunedThroughSeq {
                walk.prunedLeftovers.append(name)
                continue
            }
            if isLeftover, failure == nil {
                failure = .pruneGap
            }
            if let failure {
                walk.failure = failure
                walk.failureIndex = index
                walk.failedPrefix = segment
                walk.tornCandidate = torn
                return walk
            }
            walk.kept.append(segment!)
            previous = segment!.lastLink
            oldest = false
        }
        return walk
    }

    private static func linkIsValid(
        record: DecisionLogChainProjection,
        seq: UInt64,
        previous: DecisionLogChainLink?,
        oldest: Bool,
        prunedThroughSeq: UInt64
    ) -> Bool {
        if let resume = record.resume {
            let floor = max(record.chain?.seq ?? 0, resume.liveBefore?.seq ?? 0)
            guard seq > floor else { return false }
            if oldest {
                return resume.liveBefore == nil || (resume.liveBefore!.seq <= prunedThroughSeq)
            }
            return resume.liveBefore == previous
        }
        if oldest {
            if prunedThroughSeq == 0 { return record.chain == nil && seq == 1 }
            return record.chain?.seq == prunedThroughSeq && seq == prunedThroughSeq + 1
        }
        guard let previous else { return false }
        return record.chain == previous && seq == previous.seq + 1
    }

    // MARK: - Appending

    /// Appends one record to its kind's stream. A `decisions` record is
    /// written, fully synced, and the checkpoint updated before this returns;
    /// a `usage` record is written and the checkpoint follows within the
    /// write-coalescing delay (or at shutdown). Never throws: a record that
    /// cannot be written is counted, and the status says so.
    @discardableResult
    public func record(_ record: DecisionLogRecord) async -> Bool {
        let stream = record.stream
        guard writeFrame(record, resume: nil, sync: stream == .decisions ? .full : .none) else { return false }
        if stream == .decisions {
            _ = await commitCheckpoint()
        } else {
            scheduleUsageFlush()
        }
        await pruneIfNeeded()
        return true
    }

    /// Seals and appends one frame, synchronously on this actor, so nothing
    /// interleaves between the uninstalled check and the write. Returns true
    /// only when the frame is on disk to the `sync` level asked for.
    private func writeFrame(
        _ input: DecisionLogRecord,
        resume: PendingResume?,
        sync: SealedSyncLevel
    ) -> Bool {
        guard state == .active, !stores.isUninstalled, let frameKey else {
            droppedRecords += 1
            return false
        }
        let stream = input.stream
        var current = streams[stream] ?? StreamState()
        var record = input.bounded()
        record.v = DecisionLogRecord.formatVersion
        record.seq = resume?.seq ?? ((current.head?.seq ?? current.prunedThroughSeq) + 1)
        record.wallTime = DecisionLogTime(clock())
        record.bootSessionUUID = bootSessionUUID
        guard var plaintext = try? DecisionLogFrame.encoder().encode(record) else {
            droppedRecords += 1
            return false
        }
        let frameOverhead = UInt64(DecisionLogFrame.minimumFrameBytes)
        let startsSegment = resume != nil || handles[stream] == nil || current.segments.isEmpty
            || current.segments.last!.length + UInt64(plaintext.count) + frameOverhead > limits.segmentBytes
        if startsSegment {
            if resume != nil {
                record.chain = resume?.chain
                record.resume = DecisionLogRecord.Resume(liveBefore: resume?.liveBefore)
            } else {
                record.chain = current.head
            }
            guard let encoded = try? DecisionLogFrame.encoder().encode(record) else {
                droppedRecords += 1
                return false
            }
            plaintext = encoded
        }
        guard plaintext.count <= limits.maximumRecordBytes else {
            droppedRecords += 1
            return false
        }
        var createdSegment: DecisionLogSegmentName?
        do {
            let handle: SealedAppendHandle
            let segmentName: DecisionLogSegmentName
            if startsSegment {
                guard let fresh = DecisionLogSegmentName.fresh(stream: stream, number: current.nextNumber) else {
                    droppedRecords += 1
                    return false
                }
                if let previous = handles[stream] {
                    try? previous.synchronize(.fsync)
                    previous.close()
                    handles[stream] = nil
                }
                try directory.prepare()
                segmentName = fresh
                current.nextNumber += 1
                handle = try directory.createExclusive(segmentName.fileName)
                createdSegment = segmentName
                handles[stream] = handle
            } else {
                handle = handles[stream]!
                segmentName = current.segments.last!.name
            }
            let sealed = try DecisionLogFrame.seal(
                plaintext, key: frameKey, stream: stream, segmentID: segmentName.segmentID,
                seq: record.seq, previousTag: startsSegment ? DecisionLogFrame.zeroTag : current.head!.tag
            )
            try handle.append(sealed.frame, sync: sync)
            let link = DecisionLogChainLink(segmentID: segmentName.segmentID, seq: record.seq, tag: sealed.tag)
            if startsSegment {
                current.segments.append(Segment(
                    name: segmentName, firstSeq: record.seq, lastSeq: record.seq,
                    lastTag: sealed.tag, length: handle.length
                ))
            } else {
                current.segments[current.segments.count - 1].lastSeq = record.seq
                current.segments[current.segments.count - 1].lastTag = sealed.tag
                current.segments[current.segments.count - 1].length = handle.length
            }
            current.head = link
            if sync != .none {
                current.durable = Durable(link: link, length: handle.length)
                current.dirty = false
                if sync == .fsync { pendingFullSync = true }
            } else {
                current.dirty = true
            }
            streams[stream] = current
            return true
        } catch {
            // A segment created for this frame holds nothing: remove it rather
            // than leave an empty file the next frame would be mistaken for.
            if let createdSegment {
                handles[stream]?.close()
                handles[stream] = nil
                try? directory.remove(createdSegment.fileName)
            }
            streams[stream] = current
            droppedRecords += 1
            return false
        }
    }

    /// Syncs a stream's written frames and moves its durable head up to them,
    /// so a checkpoint about to be written names only bytes on disk. The
    /// drive-cache flush happens once, just before that checkpoint.
    private func makeDurable(_ stream: DecisionLogStream) -> Bool {
        guard var current = streams[stream], current.dirty else { return true }
        guard let head = current.head,
              let segment = current.segments.last, segment.name.segmentID == head.segmentID else {
            return false
        }
        if let handle = handles[stream] {
            guard (try? handle.synchronize(.fsync)) != nil else { return false }
        }
        current.durable = Durable(link: head, length: segment.length)
        current.dirty = false
        streams[stream] = current
        pendingFullSync = true
        return true
    }

    /// Opens each stream's last verified segment for appending when it is
    /// still exactly as verified (otherwise the next frame starts a new
    /// segment), and syncs it: the load is about to checkpoint what it read,
    /// and a checkpoint must never name bytes that are not on disk.
    private func attachLastSegments() {
        for stream in DecisionLogStream.allCases {
            guard handles[stream] == nil,
                  let last = streams[stream]?.segments.last,
                  let handle = try? directory.openForAppend(last.name.fileName) else { continue }
            guard handle.length == last.length, (try? handle.synchronize(.fsync)) != nil else {
                handle.close()
                continue
            }
            handles[stream] = handle
            pendingFullSync = true
        }
    }

    private func buildCheckpoint() -> DecisionLogCheckpoint {
        var checkpoint = DecisionLogCheckpoint(
            unmovable: unmovable.isEmpty ? nil : unmovable,
            excludedSegments: excludedSegments.isEmpty ? nil : excludedSegments
        )
        for stream in DecisionLogStream.allCases {
            guard let current = streams[stream], let durable = current.durable else { continue }
            checkpoint[stream] = DecisionLogStreamHead(
                segmentID: durable.link.segmentID,
                seq: durable.link.seq,
                tag: durable.link.tag,
                length: durable.length,
                prunedThroughSeq: min(current.prunedThroughSeq, durable.link.seq - 1)
            )
        }
        return checkpoint
    }

    /// Whether a checkpoint keeps every head the anchor had, at the same or a
    /// later position.
    private func advancesAnchor(_ checkpoint: DecisionLogCheckpoint) -> Bool {
        for stream in DecisionLogStream.allCases {
            guard let old = anchor[stream] else { continue }
            guard let new = checkpoint[stream] else { return false }
            if new.seq < old.seq || (new.seq == old.seq && new.link != old.link) { return false }
        }
        return true
    }

    /// Writes both streams' durable heads, after flushing the drive's cache,
    /// and only when no head moves backwards or disappears. Prepared on this
    /// actor, so a later checkpoint always carries a later state and wins
    /// however commits land.
    private func commitCheckpoint() async -> Bool {
        guard state == .active, !stores.isUninstalled else { return false }
        let checkpoint = buildCheckpoint()
        guard advancesAnchor(checkpoint) else {
            checkpointWriteFailures += 1
            return false
        }
        // Nothing moved: the item already says this.
        if DecisionLogStream.allCases.allSatisfy({ checkpoint[$0] == anchor[$0] }),
           (checkpoint.unmovable ?? []) == anchorUnmovable,
           (checkpoint.excludedSegments ?? []) == anchorExcluded { return true }
        if pendingFullSync {
            guard (try? directory.fullSynchronize()) != nil else {
                checkpointWriteFailures += 1
                return false
            }
            pendingFullSync = false
        }
        do {
            let change = try checkpointStore.prepare(checkpoint)
            try await change.commit()
            for stream in DecisionLogStream.allCases {
                if let head = checkpoint[stream] { anchor[stream] = head }
            }
            anchorUnmovable = checkpoint.unmovable ?? []
            anchorExcluded = checkpoint.excludedSegments ?? []
            return true
        } catch {
            checkpointWriteFailures += 1
            return false
        }
    }

    private func scheduleUsageFlush() {
        guard usageFlush == nil else { return }
        let delay = limits.usageCheckpointDelay
        usageFlush = Task { [weak self] in
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            await self?.flushUsageCheckpoint()
        }
    }

    /// Makes the usage stream durable and checkpoints it. Runs after the
    /// write-coalescing delay, before a verification, and from the SIGTERM
    /// handler; a no-op once uninstall has begun.
    public func flushUsageCheckpoint() async {
        usageFlush?.cancel()
        usageFlush = nil
        guard state == .active, !stores.isUninstalled,
              streams[.usage]?.dirty == true, makeDurable(.usage) else { return }
        _ = await commitCheckpoint()
    }

    // MARK: - Pruning

    /// Keeps each stream's verified segments under its cap by size alone. A
    /// live segment is deleted only after a `prune` record raised
    /// `prunedThroughSeq` in a committed checkpoint, so its absence is never
    /// mistaken for tampering. The current segment is never pruned, and the
    /// prune record goes in the pruned stream itself, so no volume of usage
    /// ever adds a byte to the decisions stream.
    ///
    /// Set-aside files are a separate budget of the same size, trimmed oldest
    /// first under one `prune` record per pass. Their names are not csecd's
    /// to trust, so they are never charged against verified history: a
    /// set-aside file that cannot be removed (an immutable one) is skipped,
    /// listed in `csec status`, and costs no live segment.
    private func pruneIfNeeded() async {
        guard !pruning else { return }
        pruning = true
        defer { pruning = false }
        for stream in [DecisionLogStream.usage, .decisions] {
            if state == .active, !stores.isUninstalled,
               let current = streams[stream], current.setAsideBytes > limits.cap(for: stream) {
                var excess = current.setAsideBytes - limits.cap(for: stream)
                var removed: Set<String> = []
                var removedBytes: UInt64 = 0
                for file in current.quarantined.sorted(by: { ($0.number, $0.name) < ($1.number, $1.name) })
                where excess > 0 && !unremovable.contains(file.name) {
                    guard (try? directory.remove(file.name)) != nil else {
                        unremovable.insert(file.name)
                        continue
                    }
                    removed.insert(file.name)
                    removedBytes &+= file.size
                    excess -= min(excess, file.size)
                }
                if !removed.isEmpty {
                    streams[stream]?.quarantined.removeAll { removed.contains($0.name) }
                    _ = writeFrame(pruneRecord(
                        stream: stream, segmentID: nil, throughSeq: current.prunedThroughSeq,
                        bytes: removedBytes, quarantinedFiles: removed.count
                    ), resume: nil, sync: .full)
                    _ = await commitCheckpoint()
                }
            }
            while state == .active, !stores.isUninstalled,
                  let current = streams[stream], current.liveBytes > limits.cap(for: stream) {
                guard current.segments.count > 1, let oldest = current.segments.first,
                      makeDurable(stream) else { break }
                let previousPruned = current.prunedThroughSeq
                streams[stream]?.prunedThroughSeq = oldest.lastSeq
                guard writeFrame(pruneRecord(
                    stream: stream, segmentID: oldest.name.segmentID, throughSeq: oldest.lastSeq,
                    bytes: oldest.length, quarantinedFiles: 0
                ), resume: nil, sync: .full), await commitCheckpoint() else {
                    streams[stream]?.prunedThroughSeq = previousPruned
                    break
                }
                // Its prune is committed: it is history no longer, whether or not
                // the file can be unlinked. One that cannot (an immutable file)
                // leaves the live set anyway, so the next append does not prune
                // it again; it is listed, and the next start removes it as a
                // prune leftover if it can.
                if (try? directory.remove(oldest.name.fileName)) == nil {
                    unremovable.insert(oldest.name.fileName)
                }
                streams[stream]?.segments.removeAll { $0.name == oldest.name }
            }
        }
    }

    private func pruneRecord(
        stream: DecisionLogStream, segmentID: String?, throughSeq: UInt64,
        bytes: UInt64, quarantinedFiles: Int
    ) -> DecisionLogRecord {
        var record = DecisionLogRecord(kind: .prune)
        record.prune = DecisionLogRecord.Prune(
            stream: stream, segmentID: segmentID, throughSeq: throughSeq,
            deletedBytes: bytes, quarantinedFiles: quarantinedFiles
        )
        return record
    }

    // MARK: - Reading

    /// One bounded page of records, oldest first. The scan runs off the actor
    /// on a snapshot of the segment list, so appends never wait on it, and it
    /// decrypts at most `limits.readScanFrames` frames: a filter that matches
    /// little returns a partial (possibly empty) page with a `next` cursor.
    /// Reading never repairs: a frame that fails to authenticate ends that
    /// stream's page and marks it incomplete.
    public nonisolated func read(_ query: DecisionLogQuery) async -> DecisionLogPage {
        guard query.isWellFormed, let snapshot = await readSnapshot() else {
            return DecisionLogPage(records: [], next: nil)
        }
        return snapshot.page(for: query)
    }

    private func readSnapshot() -> ReadSnapshot? {
        guard state == .active, let frameKeyData else { return nil }
        return ReadSnapshot(
            directory: directory, frameKey: frameKeyData, limits: limits,
            segments: streams.mapValues(\.segments)
        )
    }

    // MARK: - Uninstall

    /// Deletes the log directory and stops every later write. Call it after
    /// the protected stores entered their uninstalled state; the key and
    /// checkpoint items go with the rest of the protected items. Returns
    /// whether the directory is gone.
    public func eraseForUninstall() -> Bool {
        state = .uninstalled
        usageFlush?.cancel()
        usageFlush = nil
        closeHandles()
        streams = [.decisions: StreamState(), .usage: StreamState()]
        masterKey = nil
        frameKey = nil
        frameKeyData = nil
        do {
            try directory.removeDirectory()
            return true
        } catch {
            return !directory.exists()
        }
    }

    // MARK: - Helpers

    private func list() throws -> Listing {
        var listing = Listing()
        guard directory.exists() else {
            // Something other than a directory (a file, a symlink) where the
            // log belongs is not an empty log.
            var info = stat()
            if lstat(directory.path, &info) == 0 { throw SealedRecordError.notPrivate }
            return listing
        }
        let entries = try directory.entries()
        let quarantineSuffix = DecisionLogSegmentName.quarantineSuffix
        for entry in entries.files {
            listing.sizes[entry.name] = entry.size
            if let name = DecisionLogSegmentName.parse(entry.name) {
                listing.live[name.stream, default: []].append(name)
            } else if entry.name.hasSuffix(quarantineSuffix),
                      let stream = DecisionLogSegmentName.claimedStream(entry.name) {
                let number = DecisionLogSegmentName.parseQuarantined(entry.name)?.number ?? 0
                listing.quarantined[stream, default: []].append(
                    QuarantinedFile(name: entry.name, number: number, size: entry.size)
                )
            } else if entry.name.hasSuffix(DecisionLogSegmentName.fileExtension) {
                let stream = DecisionLogSegmentName.claimedStream(entry.name) ?? .decisions
                listing.foreign[stream, default: []].append(ForeignFile(name: entry.name, size: entry.size))
            }
        }
        // A symlink or directory under a segment-shaped name is foreign too.
        for name in entries.foreignNames where name.hasSuffix(DecisionLogSegmentName.fileExtension) {
            let stream = DecisionLogSegmentName.claimedStream(name) ?? .decisions
            listing.foreign[stream, default: []].append(ForeignFile(name: name, size: 0))
        }
        for stream in DecisionLogStream.allCases {
            listing.live[stream]?.sort { ($0.number, $0.random) < ($1.number, $1.random) }
        }
        return listing
    }

    /// Renames a file out of the live set, to `<name>.quarantined` or, when a
    /// file already holds that name, a unique variant of it. Returns the new
    /// name, or nil when it could not be moved.
    private func setAside(_ name: String, stream: DecisionLogStream = .decisions) -> String? {
        let suffix = DecisionLogSegmentName.quarantineSuffix
        // `<name>.quarantined` keeps the original name visible; a short
        // generated name covers a name too long to extend or already taken.
        let candidates = [name + suffix]
            + (0..<3).map { _ in "\(stream.rawValue)-setaside-\(UUID().uuidString.lowercased().prefix(12))\(suffix)" }
        for target in candidates where SealedRecordDirectory.isSafeName(target) {
            if (try? directory.rename(name, to: target)) != nil { return target }
        }
        return nil
    }

    private func resetForReopen() {
        usageFlush?.cancel()
        usageFlush = nil
        closeHandles()
        streams = [.decisions: StreamState(), .usage: StreamState()]
        masterKey = nil
        frameKey = nil
        frameKeyData = nil
        recoveryPending = false
        stuckNames = []
        unremovable = []
        state = .notOpened
    }

    private func createKey() async -> Bool {
        let key = SymmetricKey(size: .bits256)
        let data = key.withUnsafeBytes { Data($0) }
        do {
            try await keyStore.prepare(DecisionLogKeyDocument(key: data)).commit()
        } catch {
            return false
        }
        useKey(data)
        return true
    }

    private func useKey(_ data: Data) {
        let key = SymmetricKey(data: data)
        masterKey = key
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: key,
            info: Data("csec-decision-log-v1 frames".utf8),
            outputByteCount: 32
        )
        frameKey = derived
        frameKeyData = derived.withUnsafeBytes { Data($0) }
    }

    private func closeHandles() {
        for handle in handles.values { handle.close() }
        handles = [:]
    }

    private func becomeUnavailable(_ reason: String) -> DecisionLogVerification {
        state = .unavailable(reason)
        let result = verification(.unavailable, detail: reason)
        lastVerification = result
        return result
    }

    private func verification(
        _ status: DecisionLogVerification.Status,
        findings: [DecisionLogRecord.IntegrityFinding] = [],
        tornTails: [DecisionLogStream] = [],
        detail: String? = nil,
        recorded: Bool = true
    ) -> DecisionLogVerification {
        DecisionLogVerification(
            status: status,
            findings: findings,
            tornTails: tornTails,
            decisionsHeadSeq: streams[.decisions]?.head?.seq,
            usageHeadSeq: streams[.usage]?.head?.seq,
            checkedAt: DecisionLogTime(clock()),
            detail: detail,
            recorded: recorded
        )
    }
}

extension DecisionLog.ReadSnapshot {
    /// Scans each requested stream from its cursor, in sequence order, keeping
    /// at most `limit` matches per stream within the frame budget, then merges
    /// the streams by wall time without ever taking a stream's later record
    /// before its earlier one. Each stream's cursor ends at the last record
    /// the page included from it, or, when everything it matched was
    /// included, at the last frame it examined, so no record is skipped or
    /// repeated whatever the wall clock did.
    func page(for query: DecisionLogQuery) -> DecisionLogPage {
        let key = SymmetricKey(data: frameKey)
        let kinds = query.kinds.map { Set($0.map(\.rawValue)) }
        let decoder = JSONDecoder()
        var budget = limits.readScanFrames
        var incomplete = false
        var matched: [DecisionLogStream: [DecisionLogRecord]] = [:]
        var examinedThrough: [DecisionLogStream: UInt64] = [:]
        var finished: [DecisionLogStream: Bool] = [:]

        for stream in query.streams {
            let after = query.after[stream]
            var found: [DecisionLogRecord] = []
            var lastExamined = after
            var done = true
            scan: for segment in segments[stream] ?? [] where segment.lastSeq > after {
                let data: Data?
                do {
                    data = try directory.read(
                        segment.name.fileName, maximumBytes: Int(limits.segmentBytes + 128 * 1_024)
                    )
                } catch {
                    incomplete = true
                    break scan
                }
                // Pruned since the snapshot: nothing left to show from it.
                guard let data else { continue }
                let bytes = [UInt8](data.prefix(Int(segment.length)))
                var offset = 0
                var previousTag = DecisionLogFrame.zeroTag
                var first = true
                while case let .frame(seq, nonce, ciphertext, tag, next) = DecisionLogFrame.parse(
                    bytes, at: offset, maximumRecordBytes: limits.maximumRecordBytes
                ) {
                    let chained = first ? DecisionLogFrame.zeroTag : previousTag
                    previousTag = tag
                    offset = next
                    first = false
                    guard seq > after else { continue }
                    guard budget > 0 else {
                        done = false
                        break scan
                    }
                    budget -= 1
                    guard let plaintext = DecisionLogFrame.open(
                        nonce: nonce, ciphertext: ciphertext, tag: tag, key: key,
                        associatedData: DecisionLogFrame.associatedData(
                            stream: stream, segmentID: segment.name.segmentID, seq: seq, previousTag: chained
                        )
                    ), let projection = try? decoder.decode(DecisionLogFilterProjection.self, from: plaintext),
                       projection.seq == seq else {
                        incomplete = true
                        break scan
                    }
                    lastExamined = seq
                    if let kinds {
                        let kind = DecisionLogRecord.Kind(rawValue: projection.kind)?.rawValue
                            ?? DecisionLogRecord.Kind.unrecognized.rawValue
                        guard kinds.contains(kind) else { continue }
                    }
                    if let since = query.since, let wallTime = projection.wallTime, wallTime < since { continue }
                    found.append(
                        (try? decoder.decode(DecisionLogRecord.self, from: plaintext))
                            ?? DecisionLogRecord.unrecognized(projection)
                    )
                    if found.count == query.limit {
                        done = false
                        break scan
                    }
                }
            }
            matched[stream] = found
            examinedThrough[stream] = lastExamined
            finished[stream] = done
        }

        var taken: [DecisionLogStream: Int] = [:]
        var page: [DecisionLogRecord] = []
        var cursor = query.after
        var bytes = 0
        let encoder = DecisionLogFrame.encoder()
        merge: while page.count < query.limit {
            var pick: (stream: DecisionLogStream, record: DecisionLogRecord)?
            for stream in query.streams {
                let index = taken[stream] ?? 0
                guard let list = matched[stream], index < list.count else { continue }
                let candidate = list[index]
                if let current = pick,
                   (current.record.wallTime, current.stream) <= (candidate.wallTime, stream) { continue }
                pick = (stream, candidate)
            }
            guard let pick else { break merge }
            let size = (try? encoder.encode(pick.record).count) ?? 0
            if !page.isEmpty, bytes + size > DecisionLogPage.maximumEncodedBytes { break merge }
            page.append(pick.record)
            bytes += size
            cursor[pick.stream] = pick.record.seq
            taken[pick.stream, default: 0] += 1
        }
        var more = false
        for stream in query.streams {
            let allTaken = (taken[stream] ?? 0) == (matched[stream]?.count ?? 0)
            if allTaken {
                cursor[stream] = max(cursor[stream], examinedThrough[stream] ?? query.after[stream])
            }
            if !allTaken || !(finished[stream] ?? true) { more = true }
        }
        return DecisionLogPage(records: page, next: more ? cursor : nil, incomplete: incomplete)
    }
}
