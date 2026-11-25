import Foundation

/// The two append-only streams of the decision log. They are separate files
/// with separate size caps, so a flood of grant reuses can never evict the
/// record of a human decision.
public enum DecisionLogStream: String, Codable, Sendable, CaseIterable, Comparable {
    /// Panels and their outcomes, refusals, settings changes, restarts,
    /// integrity events, prunes, uninstall. Every record is durable before
    /// the append returns.
    case decisions
    /// Grant reuses (and, with delegation, delegated releases). Durable within
    /// the usage checkpoint's write-coalescing delay.
    case usage

    public static func < (lhs: DecisionLogStream, rhs: DecisionLogStream) -> Bool {
        lhs == .decisions && rhs == .usage
    }
}

/// A wall-clock instant in a log record, encoded as an ISO 8601 string with
/// milliseconds whatever the surrounding encoder's date strategy, so a record
/// reads the same in its sealed frame, on the wire and in `csec log --json`.
public struct DecisionLogTime: Codable, Sendable, Equatable, Comparable {
    public let date: Date

    public init(_ date: Date) {
        self.date = date
    }

    public init(from decoder: Decoder) throws {
        let text = try decoder.singleValueContainer().decode(String.self)
        guard let date = Self.parse(text) else {
            throw DecodingError.dataCorrupted(.init(
                codingPath: decoder.codingPath, debugDescription: "invalid log timestamp"
            ))
        }
        self.date = date
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(text)
    }

    /// `yyyy-MM-ddTHH:mm:ss.SSSZ` in UTC, built by hand: a formatter object
    /// per call cost more than the rest of a record's decode, and every
    /// record carries a time.
    public var text: String {
        let milliseconds = (date.timeIntervalSince1970 * 1_000).rounded(.down)
        guard milliseconds.isFinite, abs(milliseconds) < 1e15 else { return "1970-01-01T00:00:00.000Z" }
        let total = Int64(milliseconds)
        var seconds = time_t(total >= 0 ? total / 1_000 : (total - 999) / 1_000)
        let millis = Int(total - Int64(seconds) * 1_000)
        var parts = tm()
        guard gmtime_r(&seconds, &parts) != nil else { return "1970-01-01T00:00:00.000Z" }
        return Self.padded(Int(parts.tm_year) + 1_900, 4) + "-" + Self.padded(Int(parts.tm_mon) + 1, 2)
            + "-" + Self.padded(Int(parts.tm_mday), 2) + "T" + Self.padded(Int(parts.tm_hour), 2)
            + ":" + Self.padded(Int(parts.tm_min), 2) + ":" + Self.padded(Int(parts.tm_sec), 2)
            + "." + Self.padded(millis, 3) + "Z"
    }

    public static func < (lhs: DecisionLogTime, rhs: DecisionLogTime) -> Bool {
        lhs.date < rhs.date
    }

    /// The log's own format is parsed by hand; any other ISO 8601 spelling (a
    /// `--since` argument) falls back to a formatter.
    public static func parse(_ text: String) -> Date? {
        if let date = parseCanonical(text) { return date }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: text) { return date }
        return ISO8601DateFormatter().date(from: text)
    }

    private static func parseCanonical(_ text: String) -> Date? {
        let bytes = Array(text.utf8)
        guard bytes.count == 24, bytes[4] == 0x2d, bytes[7] == 0x2d, bytes[10] == 0x54,
              bytes[13] == 0x3a, bytes[16] == 0x3a, bytes[19] == 0x2e, bytes[23] == 0x5a else { return nil }
        func number(_ range: Range<Int>) -> Int? {
            var value = 0
            for index in range {
                let byte = bytes[index]
                guard byte >= 0x30, byte <= 0x39 else { return nil }
                value = value * 10 + Int(byte - 0x30)
            }
            return value
        }
        guard let year = number(0..<4), let month = number(5..<7), let day = number(8..<10),
              let hour = number(11..<13), let minute = number(14..<16), let second = number(17..<19),
              let millis = number(20..<23),
              (1...12).contains(month), (1...31).contains(day), hour < 24, minute < 60, second < 61 else {
            return nil
        }
        var parts = tm()
        parts.tm_year = Int32(year - 1_900)
        parts.tm_mon = Int32(month - 1)
        parts.tm_mday = Int32(day)
        parts.tm_hour = Int32(hour)
        parts.tm_min = Int32(minute)
        parts.tm_sec = Int32(second)
        var seconds = timegm(&parts)
        // timegm normalizes an impossible day (February 31) into March; the
        // log never writes one, so refuse it rather than move it.
        var check = tm()
        guard gmtime_r(&seconds, &check) != nil, check.tm_mday == Int32(day),
              check.tm_mon == Int32(month - 1) else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(seconds) + TimeInterval(millis) / 1_000)
    }

    private static func padded(_ value: Int, _ width: Int) -> String {
        let digits = String(value)
        return digits.count >= width ? digits : String(repeating: "0", count: width - digits.count) + digits
    }
}

/// Decodes one of the log's string enums without refusing a value a newer
/// csecd added: an older build reads it as `unrecognized` rather than calling
/// an authentic record corrupt.
func decodeOpenEnum<Value: RawRepresentable>(
    _ decoder: Decoder, unrecognized: Value
) throws -> Value where Value.RawValue == String {
    Value(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? unrecognized
}

/// A position in a stream's hash chain: the frame with this sequence number
/// in this segment, identified by its AEAD tag.
public struct DecisionLogChainLink: Codable, Sendable, Equatable {
    public let segmentID: String
    public let seq: UInt64
    public let tag: Data

    public init(segmentID: String, seq: UInt64, tag: Data) {
        self.segmentID = segmentID
        self.seq = seq
        self.tag = tag
    }
}

/// One value-free entry in the decision log.
///
/// Nothing here may hold a credential value. References are canonical URIs
/// (the metadata every review already shows), the command is the review
/// panel's own display string (already passed through csecd's output
/// redaction and sanitized), and every string is bounded. The log assigns
/// `v`, `seq`, `wallTime`, `bootSessionUUID` and `chain` when it appends;
/// callers fill the rest.
public struct DecisionLogRecord: Codable, Sendable, Equatable {
    public static let formatVersion = 1
    /// Bounds applied by `bounded()` before a record is sealed.
    public static let maximumReferences = 64
    public static let maximumReferenceBytes = 512
    public static let maximumDecisionCommandBytes = 512
    public static let maximumUsageCommandBytes = 256
    public static let maximumLabelBytes = 160
    public static let maximumDetailBytes = 512
    public static let maximumGrantIDs = 64

    public enum Kind: String, Codable, Sendable, CaseIterable {
        /// A review panel ended: approved, denied, requester gone, or a
        /// Touch ID failure. Carries the decider, time to decision, and the
        /// grants an approval minted.
        case panel
        /// A request refused without a panel because the human denied the
        /// identical request it was waiting behind.
        case refusal
        /// A request that left without a human decision before any panel
        /// answered it: its requester went away while it waited for a turn,
        /// the UI queue or the restore panel (`requester_gone`), or nobody
        /// answered a coding agent's request before its deadline, queued or on
        /// screen (`timed_out`). `detail` says whether a panel was shown and
        /// how long the request waited. Never a human Deny.
        case withdrawn
        /// An approved request that delivered nothing: a value could not be
        /// resolved, the key could not sign, or the requester changed before
        /// release. It follows the `panel` record of the approval, carries the
        /// value-free failure in `detail`, and says that no grant was minted,
        /// so the next identical request is reviewed again.
        case deliveryFailed = "delivery_failed"
        /// A request refused before any panel because a reference in it
        /// cannot resolve: its provider knows the key or store does not exist,
        /// or no provider claims its scheme. `detail` carries the provider's
        /// value-free reason. No human decided, so it has no outcome. These
        /// arrive at socket speed, so csecd writes one per surface, requester
        /// class and reference set per run, and at most
        /// `AbsentReferenceRecords.maximumPerRun` per surface.
        case absentReference = "absent_reference"
        /// A grant minted without a panel of its own (restores, delegation).
        case mint
        /// A request delegation declined, so it went to a panel instead.
        case decline
        /// A settings change: remote approval, SSH keys, delegation.
        case settings
        /// Grants dropped by `csec revoke`.
        case revoke
        /// A release covered by a live grant, with no panel (usage stream).
        case reuse
        /// A release approved by delegation (usage stream).
        case delegatedRelease = "delegated_release"
        /// Restored grants reopened after a restart.
        case restore
        /// The attended restore fetched paired values ahead from providers
        /// that need no csec unlock. `refs` are those it could not fetch,
        /// `detail` the counts and each one's value-free reason.
        case fetchAhead = "fetch_ahead"
        /// csecd started; `cause` says why the previous run ended.
        case restart
        /// Old segments were deleted to keep a stream under its size cap.
        case prune
        /// Verification found the log altered, truncated, rolled back or
        /// spliced, or its key or checkpoint missing.
        case logIntegrity = "log_integrity"
        /// The first record of a usage segment that resumes the chain after a
        /// `log_integrity` finding on that stream.
        case chainResume = "chain_resume"
        /// A partly written final frame after a crash was cut off.
        case tornTail = "torn_tail"
        /// `csec uninstall` was approved; the log is about to be deleted.
        case uninstall
        /// Grants left out of the persisted grants item to keep it within its
        /// caps, oldest first. They hold for this run but are not restored
        /// after a restart.
        case grantEviction = "grant_eviction"
        /// The plaintext host-audit baseline an older csecd kept was imported
        /// into the sealed baseline, once, and deleted.
        case baselineMigration = "baseline_migration"
        /// Something outside csecd changed the sealed host-audit baseline (the
        /// baseline is then treated as absent), or a plaintext baseline
        /// appeared after the sealed one existed (ignored). `cause` says which.
        case baselineIntegrity = "baseline_integrity"
        /// A kind a newer csecd wrote that this build does not know.
        case unrecognized

        public init(from decoder: Decoder) throws {
            self = try decodeOpenEnum(decoder, unrecognized: .unrecognized)
        }

        /// The stream a record of this kind is written to. A `prune` record
        /// goes to the stream it pruned (see `DecisionLogRecord.stream`).
        public var stream: DecisionLogStream {
            switch self {
            case .reuse, .delegatedRelease, .chainResume: return .usage
            default: return .decisions
            }
        }

        /// Every stream a record of this kind can be in, for reading.
        public var streams: [DecisionLogStream] {
            self == .prune ? [.decisions, .usage] : [stream]
        }
    }

    public enum Surface: String, Codable, Sendable, CaseIterable {
        case secretAccess = "secret_access"
        case sshSigning = "ssh_signing"
        case automation
        case nativeEdit = "native_edit"
        case restore
        /// A sudo review's end. csecd logs the paired phone's decision itself
        /// (`sudo_remote_review`); every other end (a Mac approval, Use
        /// Password, the deadline, the sudo exiting) is the installed review
        /// helper's report (`sudo_review_end`), admitted by its code identity,
        /// not a decision csecd attests. A sudo approval mints no grant.
        case sudo
        case unrecognized

        public init(from decoder: Decoder) throws {
            self = try decodeOpenEnum(decoder, unrecognized: .unrecognized)
        }
    }

    /// How a decision ended. `denied` is always the human's own refusal (the
    /// Deny button, closing the panel, the Touch ID sheet's Deny, or a phone
    /// Deny); a locked panel waits and re-presents, so there is no locked
    /// outcome.
    public enum Outcome: String, Codable, Sendable, CaseIterable {
        case approved
        case denied
        case requesterGone = "requester_gone"
        case authenticationFailed = "authentication_failed"
        case phoneApproved = "phone_approved"
        /// Nobody answered a coding agent's request before its deadline.
        case timedOut = "timed_out"
        /// A sudo review ended without approving and the sudo went on to
        /// macOS's own authentication (Use Password, a closed panel, no Touch
        /// ID and no phone to decide), which csec does not see.
        case usePassword = "use_password"
        case unrecognized

        public init(from decoder: Decoder) throws {
            self = try decodeOpenEnum(decoder, unrecognized: .unrecognized)
        }
    }

    public enum Decider: String, Codable, Sendable, CaseIterable {
        /// Touch ID on this Mac's panel.
        case humanLocal = "human_local"
        /// The paired iPhone.
        case humanPhone = "human_phone"
        /// A decision by a reviewer that reported no surface (an injected or
        /// headless reviewer). The trusted panel and the phone always report
        /// theirs.
        case human
        /// Claude Code auto mode, through delegation.
        case delegated
        /// A live grant the human approved earlier.
        case grant
        /// A grant restored after a csecd restart.
        case restoredGrant = "restored_grant"
        case unrecognized

        public init(from decoder: Decoder) throws {
            self = try decodeOpenEnum(decoder, unrecognized: .unrecognized)
        }
    }

    /// Who asked, value-free. `class` is a coarse category (`coding_agent`,
    /// `coding_agent:claude`, `terminal`, `bridge:ruby`, `creds:git`, `get`,
    /// `exec`, `ssh`, `automation`, `launcher`).
    public struct Requester: Codable, Sendable, Equatable {
        public var `class`: String
        public var rootPID: Int32?
        public var rootLabel: String?
        public var terminal: String?

        public init(class requesterClass: String, rootPID: Int32? = nil, rootLabel: String? = nil, terminal: String? = nil) {
            self.class = requesterClass
            self.rootPID = rootPID
            self.rootLabel = rootLabel
            self.terminal = terminal
        }
    }

    /// Delegation's view of a request. Populated by delegation; defined now so
    /// the record format does not change when it arrives.
    public struct Delegation: Codable, Sendable, Equatable {
        public var decision: String?
        public var reason: String?
        public var claudeBuild: String?
        /// How csecd located the Claude Code process's live code
        /// (`ForeignCodeIdentity.Lookup.logDescription`): the audit token, or
        /// the PID when the kernel refused the task name port. Nil when the
        /// decision resolved no identity.
        public var identityLookup: String?
        /// On a `not_registered` decline of a `csec ai`, why no registration
        /// bound: `unreadable_command`, `none_under_agent`, `late_by_<N>ms`,
        /// `command_start_unreadable` or `no_match`, then any registration
        /// csecd refused shortly before. Value-free.
        public var registration: String?

        public init(
            decision: String? = nil, reason: String? = nil, claudeBuild: String? = nil,
            identityLookup: String? = nil, registration: String? = nil
        ) {
            self.decision = decision
            self.reason = reason
            self.claudeBuild = claudeBuild
            self.identityLookup = identityLookup
            self.registration = registration
        }
    }

    /// What a `log_integrity` record found, per stream.
    public struct IntegrityFinding: Codable, Sendable, Equatable {
        public enum Kind: String, Codable, Sendable, CaseIterable {
            /// A frame failed authentication or its sequence number is wrong
            /// with more data after it: a changed or reordered record.
            case modifiedRecord = "modified_record"
            /// A segment's link does not reach the one before it: a segment was
            /// deleted, or one from elsewhere was put in its place.
            case missingSegment = "missing_segment"
            /// A segment that does not authenticate under this log's key.
            case splicedSegment = "spliced_segment"
            /// The log ends before the checkpoint: truncation or rollback.
            case behindCheckpoint = "behind_checkpoint"
            /// The frame at the checkpoint's position is not the one it names.
            case checkpointMismatch = "checkpoint_mismatch"
            /// Segments exist but the checkpoint item is gone.
            case checkpointMissing = "checkpoint_missing"
            /// Segments or a checkpoint exist but the key item is gone; the old
            /// segments can no longer be read and were set aside.
            case keyMissing = "key_missing"
            /// The oldest segment does not start where pruning left off.
            case pruneGap = "prune_gap"
            /// A segment-shaped file whose name csecd never writes (a planted
            /// or malformed name). It was set aside unread.
            case foreignFile = "foreign_file"
            /// The log directory could not be opened or repaired, so nothing
            /// could be verified or recorded this run.
            case directoryUnusable = "directory_unusable"
            case unrecognized

            public init(from decoder: Decoder) throws {
                self = try decodeOpenEnum(decoder, unrecognized: .unrecognized)
            }
        }

        /// The most file names a finding lists; `quarantinedCount` has them all.
        /// A planted directory can hold any number of files, and a finding
        /// must always fit in one record.
        public static let maximumListedNames = 16

        public var stream: DecisionLogStream
        public var finding: Kind
        /// The first files set aside (renamed `.quarantined`), never read again.
        public var quarantined: [String]
        /// How many files were set aside in all.
        public var quarantinedCount: Int
        /// The last verified frame kept in the live chain before the resume.
        public var liveBefore: DecisionLogChainLink?
        /// Where the resumed chain continues from (the checkpoint, when there
        /// was one).
        public var resumedFrom: DecisionLogChainLink?

        public init(
            stream: DecisionLogStream,
            finding: Kind,
            quarantined: [String] = [],
            liveBefore: DecisionLogChainLink? = nil,
            resumedFrom: DecisionLogChainLink? = nil
        ) {
            self.stream = stream
            self.finding = finding
            self.quarantined = Array(quarantined.prefix(Self.maximumListedNames)).map {
                ReviewDisplay.bounded(ReviewDisplay.sanitized($0), maxBytes: 128)
            }
            self.quarantinedCount = quarantined.count
            self.liveBefore = liveBefore
            self.resumedFrom = resumedFrom
        }
    }

    /// Carried by the first record of a segment that resumes a stream after an
    /// integrity finding: the chain gap between `liveBefore` and this record's
    /// `chain` is the one that finding set aside. Only csecd can seal it, so a
    /// verifier accepts that gap and no other.
    public struct Resume: Codable, Sendable, Equatable {
        public var liveBefore: DecisionLogChainLink?

        public init(liveBefore: DecisionLogChainLink?) {
            self.liveBefore = liveBefore
        }
    }

    /// Persisted grants on a `restart` record (restored at load, and dropped
    /// per load check) or a `restore` record (reopened by the panel, and
    /// forgotten or left cold).
    public struct GrantCounts: Codable, Sendable, Equatable {
        public var secret: Int
        public var ssh: Int
        /// Grants dropped, keyed by the reason (`GrantDropReason`).
        public var dropped: [String: Int]?
        /// Set when the whole persisted document could not be read.
        public var unreadable: String?

        public init(secret: Int = 0, ssh: Int = 0, dropped: [String: Int]? = nil, unreadable: String? = nil) {
            self.secret = secret
            self.ssh = ssh
            self.dropped = dropped
            self.unreadable = unreadable
        }
    }

    public struct Prune: Codable, Sendable, Equatable {
        public var stream: DecisionLogStream
        public var segmentID: String?
        public var throughSeq: UInt64
        public var deletedBytes: UInt64
        public var quarantinedFiles: Int

        public init(stream: DecisionLogStream, segmentID: String?, throughSeq: UInt64, deletedBytes: UInt64, quarantinedFiles: Int) {
            self.stream = stream
            self.segmentID = segmentID
            self.throughSeq = throughSeq
            self.deletedBytes = deletedBytes
            self.quarantinedFiles = quarantinedFiles
        }
    }

    public var v: Int
    public var seq: UInt64
    public var wallTime: DecisionLogTime
    public var bootSessionUUID: String?
    public var kind: Kind
    public var surface: Surface?
    public var requester: Requester?
    public var refs: [String]?
    /// A prefix of the release-shape digest, enough to tell shapes apart.
    public var shape: String?
    public var mechanism: String?
    public var command: String?
    public var commandDigest: String?
    public var scope: String?
    /// `process_lifetime`, or the approved cap such as `3600s`.
    public var duration: String?
    public var outcome: Outcome?
    public var decider: Decider?
    /// Panel shown (or re-shown after an unlock) to the biometric result.
    public var ttdMs: Int?
    public var cause: String?
    public var grantIDs: [String]?
    public var delegation: Delegation?
    public var detail: String?
    public var chain: DecisionLogChainLink?
    public var resume: Resume?
    public var integrity: [IntegrityFinding]?
    public var prune: Prune?
    public var grants: GrantCounts?

    public init(
        kind: Kind,
        surface: Surface? = nil,
        requester: Requester? = nil,
        refs: [String]? = nil,
        shape: String? = nil,
        mechanism: String? = nil,
        command: String? = nil,
        commandDigest: String? = nil,
        scope: String? = nil,
        duration: String? = nil,
        outcome: Outcome? = nil,
        decider: Decider? = nil,
        ttdMs: Int? = nil,
        cause: String? = nil,
        grantIDs: [String]? = nil,
        delegation: Delegation? = nil,
        detail: String? = nil
    ) {
        self.v = Self.formatVersion
        self.seq = 0
        self.wallTime = DecisionLogTime(Date(timeIntervalSince1970: 0))
        self.bootSessionUUID = nil
        self.kind = kind
        self.surface = surface
        self.requester = requester
        self.refs = refs
        self.shape = shape
        self.mechanism = mechanism
        self.command = command
        self.commandDigest = commandDigest
        self.scope = scope
        self.duration = duration
        self.outcome = outcome
        self.decider = decider
        self.ttdMs = ttdMs
        self.cause = cause
        self.grantIDs = grantIDs
        self.delegation = delegation
        self.detail = detail
        self.chain = nil
        self.resume = nil
        self.integrity = nil
        self.prune = nil
        self.grants = nil
    }

    /// The stream this record is written to: its kind's, except that a prune
    /// record is kept with the stream it pruned.
    public var stream: DecisionLogStream {
        kind == .prune ? (prune?.stream ?? .decisions) : kind.stream
    }

    /// This record with every caller-supplied string sanitized and bounded, so
    /// no field can grow a frame without limit or smuggle a control sequence
    /// into a terminal that prints it.
    public func bounded() -> DecisionLogRecord {
        var copy = self
        let commandLimit = stream == .usage
            ? Self.maximumUsageCommandBytes : Self.maximumDecisionCommandBytes
        copy.refs = refs.map { refs in
            Array(refs.prefix(Self.maximumReferences)).map {
                Self.clean($0, maxBytes: Self.maximumReferenceBytes)
            }
        }
        copy.command = command.map { Self.clean($0, maxBytes: commandLimit) }
        copy.commandDigest = commandDigest.map { Self.clean($0, maxBytes: 128) }
        copy.shape = shape.map { Self.clean($0, maxBytes: 64) }
        copy.mechanism = mechanism.map { Self.clean($0, maxBytes: 64) }
        copy.scope = scope.map { Self.clean($0, maxBytes: 64) }
        copy.duration = duration.map { Self.clean($0, maxBytes: 64) }
        copy.cause = cause.map { Self.clean($0, maxBytes: 128) }
        copy.detail = detail.map { Self.clean($0, maxBytes: Self.maximumDetailBytes) }
        copy.grantIDs = grantIDs.map { ids in
            Array(ids.prefix(Self.maximumGrantIDs)).map { Self.clean($0, maxBytes: 64) }
        }
        copy.requester = requester.map { requester in
            var bounded = requester
            bounded.class = Self.clean(requester.class, maxBytes: 64)
            bounded.rootLabel = requester.rootLabel.map { Self.clean($0, maxBytes: Self.maximumLabelBytes) }
            bounded.terminal = requester.terminal.map { Self.clean($0, maxBytes: Self.maximumLabelBytes) }
            return bounded
        }
        copy.delegation = delegation.map { delegation in
            Delegation(
                decision: delegation.decision.map { Self.clean($0, maxBytes: 64) },
                reason: delegation.reason.map { Self.clean($0, maxBytes: Self.maximumDetailBytes) },
                claudeBuild: delegation.claudeBuild.map { Self.clean($0, maxBytes: Self.maximumLabelBytes) },
                identityLookup: delegation.identityLookup.map { Self.clean($0, maxBytes: 128) },
                registration: delegation.registration.map { Self.clean($0, maxBytes: Self.maximumDetailBytes) }
            )
        }
        copy.bootSessionUUID = bootSessionUUID.map { Self.clean($0, maxBytes: 64) }
        copy.grants = grants.map { counts in
            var bounded = counts
            bounded.dropped = counts.dropped.map { dropped in
                Dictionary(
                    dropped.sorted { $0.key < $1.key }.prefix(16).map {
                        (Self.clean($0.key, maxBytes: 64), $0.value)
                    },
                    uniquingKeysWith: +
                )
            }
            bounded.unreadable = counts.unreadable.map { Self.clean($0, maxBytes: 256) }
            return bounded
        }
        return copy
    }

    private static func clean(_ value: String, maxBytes: Int) -> String {
        ReviewDisplay.bounded(ReviewDisplay.sanitized(value), maxBytes: maxBytes)
    }
}

/// Why a panel appeared, as far as csecd's memory of this run can tell. A
/// restart's own causes (`restart_not_restored`, `restart_restore`) are
/// added by grant persistence.
public enum DecisionLogPromptCause: String, Sendable, CaseIterable {
    /// No earlier approval in this run covered any of these references.
    case newRefs = "new_refs"
    /// A live approval covers them for this process tree, but for another
    /// release shape or destination (or, for SSH, another host or user).
    case newReleaseShape = "new_release_shape"
    /// They were approved for a process tree this request is not part of,
    /// or one that has since exited.
    case newProcess = "new_process"
    /// The approval that covered them here reached the lifetime the human
    /// chose for it.
    case grantExpired = "grant_expired"
    /// The approval that covered them here was revoked with `csec revoke`.
    case grantRevoked = "grant_revoked"
    /// A grant persisted before csecd restarted would have covered this
    /// exact request, but the load checks dropped it (a narrowed policy
    /// epoch, a reference no provider serves any more).
    case restartNotRestored = "restart_not_restored"
    /// The restore panel: reopening what csecd approved before it restarted.
    case restartRestore = "restart_restore"
    /// Every new reference is a one-time code, which no approval covers:
    /// each command that needs one asks for its own.
    case oneTimeCode = "one_time_code"
    /// A GitHub request that can give lasting access (`GitHubLastingAccess`),
    /// which no approval covers: each one asks for its own.
    case lastingAccess = "lasting_access"
}

/// The fields the chain walk needs from a segment's first record, decoded on
/// their own: a record a newer csecd wrote, with fields or values this build
/// does not know, still verifies.
struct DecisionLogChainProjection: Decodable {
    let seq: UInt64
    let chain: DecisionLogChainLink?
    let resume: DecisionLogRecord.Resume?
}

/// The fields a filtered read looks at before decoding a whole record.
struct DecisionLogFilterProjection: Decodable {
    let seq: UInt64
    let kind: String
    let wallTime: DecisionLogTime?
    let v: Int?
}

extension DecisionLogRecord {
    /// An authenticated record this build could not decode in full (a newer
    /// csecd's shape), shown rather than dropped.
    static func unrecognized(_ projection: DecisionLogFilterProjection) -> DecisionLogRecord {
        var record = DecisionLogRecord(
            kind: .unrecognized,
            detail: "a record written by a newer csecd (format \(projection.v ?? 0), kind \(projection.kind))"
        ).bounded()
        record.seq = projection.seq
        record.v = projection.v ?? 0
        record.wallTime = projection.wallTime ?? DecisionLogTime(Date(timeIntervalSince1970: 0))
        return record
    }

    /// `process_lifetime` or `<seconds>s`, the log's spelling of a grant
    /// lifetime.
    public static func durationText(ttlSeconds: Int?) -> String {
        ttlSeconds.map { "\($0)s" } ?? "process_lifetime"
    }

    /// The panel outcome, decider and time to decision for a review that did
    /// not approve. Only a human refusal has a decider; its time to decision
    /// runs from the panel's latest presentation to the refusal.
    public static func outcome(
        for reason: AccessPolicyDenialReason
    ) -> (outcome: Outcome, decider: Decider?, ttdMs: Int?) {
        switch reason {
        case let .human(decidedAt, surface, shownAt):
            return (.denied, decider(for: surface), shownAt.map { milliseconds($0.duration(to: decidedAt)) })
        case .requesterGone, .withdrawn: return (.requesterGone, nil, nil)
        case .timedOut: return (.timedOut, nil, nil)
        case .authenticationFailed: return (.authenticationFailed, nil, nil)
        }
    }

    /// The kind of record a review that did not approve ends with: a review
    /// that left without a human decision before one was made, the UI-queue
    /// withdrawal and the deadline, is `withdrawn`; the rest are `panel`.
    public static func kind(for reason: AccessPolicyDenialReason) -> Kind {
        switch reason {
        case .withdrawn, .timedOut: return .withdrawn
        case .human, .requesterGone, .authenticationFailed: return .panel
        }
    }

    /// The outcome, decider and time to decision for an approval, from the
    /// surface the approval reports.
    public static func outcome(
        for approval: AccessPolicyApproval
    ) -> (outcome: Outcome, decider: Decider, ttdMs: Int?) {
        let ttd = approval.decisionLatency.map(milliseconds)
        switch approval.decidedOn {
        case .phone: return (.phoneApproved, .humanPhone, ttd)
        case .mac: return (.approved, .humanLocal, ttd)
        case nil: return (.approved, .human, ttd)
        }
    }

    public static func decider(for surface: HumanDecisionSurface?) -> Decider {
        switch surface {
        case .mac: return .humanLocal
        case .phone: return .humanPhone
        case nil: return .human
        }
    }

    public static func milliseconds(_ duration: Duration) -> Int {
        let components = duration.components
        let total = components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000
        return Int(clamping: max(0, total))
    }

    /// A coarse, value-free requester class for a delivery plan.
    public static func requesterClass(plan: DeliveryPlan, scopeChoices: GrantScopeChoices?) -> String {
        if plan.operationContext == AICommandExec.operationContext {
            let agent = scopeChoices?.options.first { $0.kind == .codingAgent }?.processLabel.lowercased()
            if let agent, agent.contains("claude") { return "coding_agent:claude" }
            if let agent, agent.contains("codex") { return "coding_agent:codex" }
            return "coding_agent"
        }
        let requester = plan.requestingExecutable ?? plan.executable
        let name = URL(fileURLWithPath: requester.canonicalPath).lastPathComponent
        switch plan.mechanism {
        case .credentialProtocol:
            return "creds:\(name)"
        case .rawStandardOutput, .namedPlaintextFile:
            return "get"
        case .daemonProxy:
            return "proxy:\(name)"
        case .directHeap:
            if case .directParent = plan.root { return "bridge:\(name)" }
            return "exec"
        default:
            return "exec"
        }
    }
}

extension DecisionLogTime {
    /// A `--since` argument: an ISO 8601 time (`2026-09-25T14:00:00Z`), a date
    /// (`2026-09-25`, local midnight), or an age before `now` such as `90s`,
    /// `30m`, `12h` or `7d`.
    public static func parseSince(_ text: String, now: Date = Date()) -> Date? {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        if let unit = trimmed.last, let amount = Double(trimmed.dropLast()), amount >= 0,
           amount.isFinite {
            let seconds: Double?
            switch unit {
            case "s": seconds = amount
            case "m": seconds = amount * 60
            case "h": seconds = amount * 3_600
            case "d": seconds = amount * 86_400
            default: seconds = nil
            }
            if let seconds { return now.addingTimeInterval(-seconds) }
        }
        if let date = parse(trimmed) { return date }
        let day = DateFormatter()
        day.locale = Locale(identifier: "en_US_POSIX")
        day.timeZone = .current
        day.dateFormat = "yyyy-MM-dd"
        return day.date(from: trimmed)
    }
}

extension DecisionLogRecord {
    /// The fixed-width columns of `csec log`'s table, then a free-text tail.
    private static let columns: [(title: String, width: Int)] = [
        ("TIME", 19), ("KIND", 13), ("OUTCOME", 21), ("DECIDER", 14),
        ("TTD", 6), ("SURFACE", 13), ("CAUSE", 17),
    ]

    /// The header line of `csec log`'s table.
    public static func displayHeader() -> String {
        (columns.map { pad($0.title, $0.width) } + ["WHAT"]).joined(separator: " ")
    }

    /// One row of `csec log`'s table: local time, kind, outcome, decider, time
    /// to decision, surface and cause in aligned columns, then who asked, the
    /// references, and the command or detail. Every field was sanitized and
    /// bounded when it was recorded.
    public func displayLine(timeZone: TimeZone = .current) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let cells = [
            formatter.string(from: wallTime.date),
            kind.rawValue,
            outcome?.rawValue ?? "-",
            decider?.rawValue ?? "-",
            ttdMs.map { String(format: "%.1fs", Double($0) / 1_000) } ?? "-",
            surface?.rawValue ?? "-",
            cause ?? "-",
        ]
        var tail: [String] = []
        if let requester { tail.append(requester.class) }
        if let scope { tail.append("scope \(scope)") }
        if let refs, let first = refs.first {
            tail.append(refs.count > 1 ? "\(first) (+\(refs.count - 1))" : first)
            let codes = refs.filter { (try? SecretRef($0))?.isOneTimeCode == true }.count
            if codes > 0 { tail.append(codes == 1 ? "one-time code" : "\(codes) one-time codes") }
        }
        if let command { tail.append(ReviewDisplay.bounded(command, maxBytes: 120)) }
        if let detail { tail.append(ReviewDisplay.bounded(detail, maxBytes: 200)) }
        let row = zip(cells, Self.columns).map { Self.pad($0, $1.width) }
        return (row + [tail.joined(separator: "  ")]).joined(separator: " ")
    }

    private static func pad(_ text: String, _ width: Int) -> String {
        text.count >= width ? text : text + String(repeating: " ", count: width - text.count)
    }
}
