import CoreFoundation
import Foundation
import CSECBuildIdentity

/// How long a coding agent's request may wait on a human before csecd
/// withdraws it.
///
/// This is one of the few clocks csec keeps, and it earns its place against a
/// concrete harm: a hang. A Claude Code or Codex session whose request needs a
/// panel nobody is there to answer otherwise hangs every command it runs, and
/// because csecd shows one panel at a time, every other session's request
/// queues unseen behind it (csec-ia3q: four sessions stuck for 2.5 hours
/// behind one panel raised at 05:14). It never re-verifies a decision: it
/// bounds only a wait in which nobody has decided anything, and a request
/// withdrawn by it releases nothing. A terminal's own request has a human at
/// the keyboard who can see the panel and press Ctrl-C, so it keeps waiting.
///
/// Each request's clock starts when the request reaches csecd, so ten
/// requests queued behind one unanswered panel all lapse together rather than
/// one per period. The length is the `defaults` key below: it can only make a
/// request fail sooner or wait longer, never release anything, so it needs no
/// Touch ID to change.
public enum ApprovalWaitLimit {
    /// csec's bundle identifier, the domain `defaults` reads and writes.
    public static let preferencesDomain = CSECBuildIdentity.identifier
    public static let preferenceKey = "CodingAgentApprovalWaitMinutes"
    public static let defaultMinutes = 20
    public static let allowedMinutes: ClosedRange<Int> = 1...1_440

    /// What the setting resolves to now: the configured minutes when they are
    /// a whole number in range, otherwise the default, and the raw value that
    /// was ignored, if any, for `csec status` to name.
    public struct Resolution: Sendable, Equatable {
        public let minutes: Int
        public let isDefault: Bool
        public let ignoredValue: String?
    }

    public static func resolve(_ raw: Any?) -> Resolution {
        guard let raw else { return Resolution(minutes: defaultMinutes, isDefault: true, ignoredValue: nil) }
        let minutes: Int?
        switch raw {
        case let number as NSNumber where CFGetTypeID(number) != CFBooleanGetTypeID():
            let value = number.doubleValue
            minutes = value.isFinite && value == value.rounded() && abs(value) < 1e9 ? Int(value) : nil
        case let text as String:
            minutes = Int(text.trimmingCharacters(in: .whitespaces))
        default:
            minutes = nil
        }
        if let minutes, allowedMinutes.contains(minutes) {
            return Resolution(minutes: minutes, isDefault: false, ignoredValue: nil)
        }
        return Resolution(
            minutes: defaultMinutes,
            isDefault: true,
            ignoredValue: ReviewDisplay.bounded(ReviewDisplay.sanitized(String(describing: raw)), maxBytes: 64)
        )
    }

    /// Read on every request, so `defaults write` takes effect for the next
    /// request without a restart.
    public static func current() -> Resolution {
        let domain = preferencesDomain as CFString
        CFPreferencesAppSynchronize(domain)
        return resolve(CFPreferencesCopyAppValue(preferenceKey as CFString, domain))
    }

    /// The command that changes it, for `csec status` and the docs.
    public static var setCommand: String {
        "defaults write \(preferencesDomain) \(preferenceKey) -int <minutes>"
    }
}

/// Where csecd tells a requester, mid-request, that its request is waiting on
/// a human: an opt-in `notice` frame on the requesting connection
/// (`WireTransport.noticeFrame`). Bound by the socket server around the
/// request's handler only when the client declared it reads notice frames.
public struct RequestNoticeSink: Sendable {
    private let deliver: @Sendable (String) -> Void

    public init(_ deliver: @escaping @Sendable (String) -> Void) {
        self.deliver = deliver
    }

    public func send(_ message: String) { deliver(message) }
}

public enum RequestNotices {
    /// The requesting connection's sink, read once when a request arrives
    /// (`HumanWait`). Nil for a client that reads no notices.
    @TaskLocal public static var sink: RequestNoticeSink?
}

/// One request's wait on a human: when it arrived, how long it may wait, the
/// one notice that tells its session it is waiting, and the latch that
/// decides, race-free, whether a human decision or the deadline ended it.
///
/// Every secret-access and SSH signing request gets one when it reaches its
/// service; only a coding agent's has a `limit`. The latch closes the race a
/// plain cancellation would leave open: a human who approves at 19:59.9 must
/// not have that approval thrown away by a cancel at 20:00. `QueuedPolicyReview`
/// marks the request decided the moment a review returns a human decision,
/// and the deadline cancels the request only if it ends the wait first. What
/// is left is the time between the decision and that return: milliseconds on
/// the Mac, and on the phone the withdrawal of its CloudKit request before the
/// mirrored review returns. A decision lost there costs one re-asked panel and
/// releases nothing.
public final class HumanWait: @unchecked Sendable {
    /// The request being handled in this task. Read only by the services that
    /// bind it (`Agent`, `SSHSigningService`) and by the waits they reach in the
    /// request's own task: `ConsentQueue.acquire`, `QueuedPolicyReview` and
    /// `GrantRestoration.join`, and by the panel, which shows its deadline
    /// (`ReviewDeadline`). `GrantRestoration` clears it for the restore
    /// panel tasks it starts, which would otherwise inherit the first waiter's.
    @TaskLocal public static var current: HumanWait?

    public struct Requester: Sendable, Equatable {
        public let pid: pid_t
        public let startTime: UInt64

        public init(pid: pid_t, startTime: UInt64) {
            self.pid = pid
            self.startTime = startTime
        }
    }

    /// Where a human can answer the request, as its notice tells its session.
    /// A request the paired phone cannot carry (`RemoteReviewReadiness`:
    /// nothing paired, or a provider would first have to authorize at the Mac)
    /// is answered at the Mac alone, and a session told the phone could answer
    /// would wait for an approval that cannot come.
    public enum Place: Sendable, Equatable {
        case macOrPhone
        case macOnly
    }

    public enum State: Sendable, Equatable {
        case pending
        /// A human decided (approved or denied); the deadline no longer applies.
        case decided
        /// The deadline ended the wait; the request is being withdrawn.
        case expired
        /// Its arrival-time parent or scope was lost before delivery.
        case abandoned
    }

    public let id = UUID()
    public let requester: Requester
    public let arrivedAt: ContinuousClock.Instant
    public let arrivedAtDate: Date
    /// How long the request may wait on a human; nil for a request with no
    /// coding agent above it, which waits as long as it takes.
    public let limit: Duration?
    public let requestAnchor: RequestAnchor?

    private let lock = NSLock()
    private var state: State = .pending
    private var summary: String
    private var place: Place = .macOrPhone
    private var notified = false
    private var shown = false
    private var abandonmentReason: RequestAbandonment?
    private let processInspection: ProcessInspection
    private let requesterPollInterval: Duration
    private let sink: RequestNoticeSink?
    private let board: HumanWaitBoard?
    private let timeZone: TimeZone

    public init(
        requester: Requester,
        summary: String,
        limit: Duration?,
        sink: RequestNoticeSink? = nil,
        board: HumanWaitBoard? = nil,
        arrivedAt: ContinuousClock.Instant = .now,
        arrivedAtDate: Date = Date(),
        timeZone: TimeZone = .current,
        requestAnchor: RequestAnchor? = nil,
        processInspection: ProcessInspection = .live,
        requesterPollInterval: Duration = .seconds(AgentLiveness.peerExitPollInterval)
    ) {
        self.requester = requester
        self.summary = HumanWait.bounded(summary)
        self.limit = limit
        self.sink = sink
        self.board = board
        self.arrivedAt = arrivedAt
        self.arrivedAtDate = arrivedAtDate
        self.timeZone = timeZone
        self.requestAnchor = requestAnchor
        self.processInspection = processInspection
        self.requesterPollInterval = requesterPollInterval
    }

    /// The limit for a request whose requester is `pid`: the configured one
    /// when a coding agent (Claude Code or Codex) is above it, judged from live
    /// ancestry the way the scope choices are, otherwise nil. The judgement
    /// only shortens a wait and sends a notice; it authorizes nothing, so a
    /// process merely named like an agent can only time out its own requests.
    public static func limit(
        forRequesterPID pid: pid_t,
        startTime: UInt64,
        inspection: ProcessInspection,
        limit: () -> Duration = { .seconds(ApprovalWaitLimit.current().minutes * 60) }
    ) -> Duration? {
        let choices = GrantScopeInspector.choices(
            planRootPID: pid, planRootStartTime: startTime, requestingLabel: "", inspection: inspection
        )
        guard choices.options.contains(where: { $0.kind == .codingAgent }) else { return nil }
        return limit()
    }

    public var deadline: ContinuousClock.Instant? { limit.map { arrivedAt + $0 } }

    public var deadlineDate: Date? {
        limit.map { arrivedAtDate.addingTimeInterval(HumanWait.seconds($0)) }
    }

    public var currentState: State { lock.withLock { state } }
    public var isExpired: Bool { currentState == .expired }
    public var wasShown: Bool { lock.withLock { shown } }
    public var abandonment: RequestAbandonment? {
        guard !isExpired else { return nil }
        return lock.withLock { abandonmentReason } ?? requestAnchor?.abandonment(using: processInspection)
    }

    /// Replaces the notice's description of the request once the service
    /// knows more (an SSH request's host name). No effect after the notice.
    public func describe(_ summary: String) {
        lock.withLock { self.summary = HumanWait.bounded(summary) }
    }

    /// Called by every wait on a human: a queued turn, the UI queue, a
    /// panel, the restore panel. The first call tells the session, once; a
    /// request with no limit says nothing, as before. `place`, when the
    /// caller has judged it, is where the notice says it can be answered.
    public func notifyWaiting(place judged: Place? = nil) {
        let message: String? = lock.withLock {
            guard limit != nil, !notified, state == .pending else { return nil }
            if let judged { place = judged }
            notified = true
            return waitingMessage
        }
        guard let message else { return }
        sink?.send(message)
        board?.post(
            id: id, requester: requester, message: message, toldInBand: sink != nil
        )
    }

    /// The paired phone cannot carry this request after all: judged again
    /// when its panel came up, after a wait in the queue. A session already
    /// told the phone could answer is told once more, so it does not wait for
    /// a phone approval that cannot come; one not yet told is told the Mac.
    public func stayOnMac() {
        let correction: String? = lock.withLock {
            guard place != .macOnly else { return nil }
            place = .macOnly
            guard notified, state == .pending else { return nil }
            return "the iPhone cannot approve this request, so it is " + waitingMessage
        }
        guard let correction else { return }
        sink?.send(correction)
        board?.replace(id: id, message: correction)
    }

    public var currentPlace: Place { lock.withLock { place } }

    /// The review reached the panel (it left the UI queue), for the record.
    public func markShown() {
        lock.withLock { shown = true }
    }

    /// A human decided. True unless the deadline had already ended the wait.
    @discardableResult
    public func decide() -> Bool {
        lock.withLock {
            switch state {
            case .pending:
                state = .decided
                return true
            case .decided:
                return true
            case .expired, .abandoned:
                return false
            }
        }
    }

    /// The deadline passed. True only if nobody had decided: only then is the
    /// request withdrawn.
    public func expire() -> Bool {
        lock.withLock {
            guard state == .pending else { return false }
            state = .expired
            return true
        }
    }

    /// A denial as the service records it: whatever ended a review the
    /// deadline withdrew reads as `.timedOut`.
    public func effectiveReason(_ reason: AccessPolicyDenialReason) -> AccessPolicyDenialReason {
        if isExpired { return .timedOut }
        if abandonment != nil { return wasShown ? .requesterGone : .withdrawn }
        return reason
    }

    public var waited: Duration { arrivedAt.duration(to: .now) }

    /// The message the requester receives when the deadline withdrew it.
    public var timeoutMessage: String {
        let minutes = limit.map { HumanWait.minutesText($0) } ?? "the time allowed"
        return "approval was not given: nobody answered within \(minutes), "
            + "so csec withdrew the request and released nothing (\(lock.withLock { summary }))"
    }

    /// The `detail` of a `withdrawn` record: whether a panel was shown, why
    /// the request left, and how long it waited.
    public func withdrawnDetail(cause: String? = nil, place: String? = nil) -> String {
        let place = place ?? (wasShown ? "shown, not answered" : "never shown")
        let why: String
        if let abandonment {
            why = abandonment.detail
        } else if let cause {
            why = cause
        } else if isExpired, let limit {
            why = "nobody answered within \(HumanWait.minutesText(limit))"
        } else {
            why = "its requester went away"
        }
        return "\(place); \(why); waited \(HumanWait.durationText(waited))"
    }

    /// Ends the request's presence on the board. Called once it is answered.
    public func finish() {
        board?.remove(id: id)
    }

    /// Setup reviews have no coding-agent deadline, but share the same orphan
    /// watch. Non-socket synthetic callers may have no kernel incarnation;
    /// their service's existing identity checks remain authoritative.
    static func tracking<T: Sendable>(
        caller: CallerInfo, inspection: ProcessInspection,
        _ body: @escaping @Sendable (CallerInfo) async -> T
    ) async -> T {
        guard caller.peerIdentity != nil || caller.requestAnchor != nil
            || inspection.startTime(of: caller.pid) == caller.startTime else {
            return await body(caller)
        }
        let caller = caller.anchored(using: inspection)
        let wait = HumanWait(
            requester: Requester(pid: caller.pid, startTime: caller.startTime),
            summary: "setup approval", limit: nil,
            requestAnchor: caller.requestAnchor, processInspection: inspection
        )
        return await wait.bounding { await body(caller) }
    }

    /// Runs `body` with this wait as `HumanWait.current`, withdrawing it at
    /// the deadline if nobody has decided by then: the deadline cancels the
    /// body, and every wait the body is in answers that the way it answers a
    /// requester that went away (a queued request leaves its queue, a panel
    /// closes and its phone copy is withdrawn, a restore waiter leaves).
    public func bounding<T: Sendable>(_ body: @escaping @Sendable () async -> T) async -> T {
        defer { finish() }
        guard deadline != nil || requestAnchor != nil else {
            return await HumanWait.$current.withValue(self) { await body() }
        }
        return await withTaskGroup(of: BoundedLeg<T>.self) { group in
            group.addTask {
                .body(await HumanWait.$current.withValue(self) { await body() })
            }
            if let deadline {
                group.addTask {
                    do {
                        // An explicit tolerance: by default a long sleep may
                        // fire well after the moment the panel's deadline
                        // line counted down to (`ReviewDeadline`).
                        try await Task.sleep(until: deadline, tolerance: .milliseconds(50), clock: .continuous)
                        _ = self.expire()
                    } catch {}
                    return .deadline
                }
            }
            if let requestAnchor {
                group.addTask {
                    while !Task.isCancelled {
                        if let cause = requestAnchor.abandonment(using: self.processInspection) {
                            self.lock.withLock {
                                if self.state != .expired {
                                    self.abandonmentReason = cause
                                    self.state = .abandoned
                                }
                            }
                            return .requesterGone
                        }
                        do { try await Task.sleep(for: self.requesterPollInterval) }
                        catch { break }
                    }
                    return .watchEnded
                }
            }
            var result: T?
            while result == nil, let leg = await group.next() {
                switch leg {
                case let .body(value):
                    result = value
                case .deadline:
                    // Expired: withdraw. Decided: the body goes on, unbounded.
                    if isExpired { group.cancelAll() }
                case .requesterGone:
                    group.cancelAll()
                case .watchEnded:
                    break
                }
            }
            group.cancelAll()
            guard let result else {
                // Unreachable: the body leg always returns a value.
                preconditionFailure("the bounded request ended without a result")
            }
            return result
        }
    }

    /// Read with `lock` held.
    private var waitingMessage: String {
        let whereText = place == .macOnly ? "on the Mac" : "on the Mac or iPhone"
        var message = "waiting for approval \(whereText): \(summary)."
        if let deadlineDate, let limit {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = timeZone
            formatter.dateFormat = "HH:mm"
            message += " If nobody answers, csec withdraws it at \(formatter.string(from: deadlineDate))"
                + " (\(HumanWait.minutesText(limit)) after it was asked) and the command fails."
        }
        return message
    }

    static let maximumSummaryBytes = 200

    private static func bounded(_ text: String) -> String {
        ReviewDisplay.bounded(ReviewDisplay.sanitized(text), maxBytes: maximumSummaryBytes)
    }

    static func seconds(_ duration: Duration) -> TimeInterval {
        let parts = duration.components
        return TimeInterval(parts.seconds) + TimeInterval(parts.attoseconds) / 1e18
    }

    static func minutesText(_ duration: Duration) -> String {
        let total = Int(seconds(duration).rounded())
        if total > 0, total % 60 == 0 {
            let minutes = total / 60
            return minutes == 1 ? "1 minute" : "\(minutes) minutes"
        }
        return total == 1 ? "1 second" : "\(total) seconds"
    }

    /// `2h05m`, `3m12s` or `41s`.
    public static func durationText(_ duration: Duration) -> String {
        let total = max(0, Int(seconds(duration)))
        let hours = total / 3_600, minutes = (total % 3_600) / 60, secs = total % 60
        if hours > 0 { return "\(hours)h" + (minutes < 10 ? "0" : "") + "\(minutes)m" }
        if minutes > 0 { return "\(minutes)m" + (secs < 10 ? "0" : "") + "\(secs)s" }
        return "\(secs)s"
    }
}

private enum BoundedLeg<T: Sendable>: Sendable {
    case body(T)
    case deadline
    case requesterGone
    case watchEnded
}

/// The value-free notices of requests waiting on a human, for the ones that
/// cannot carry a notice of their own: an `ssh` (the agent protocol has no
/// message), a language client over `csec bridge`, an older `csec`. A
/// `csec ai` asks for those started under it while its command runs
/// (`take_approval_notices` on its output-redaction connection) and prints
/// each once on its stderr, which the coding agent reads.
public final class HumanWaitBoard: @unchecked Sendable {
    private struct Entry {
        let requester: HumanWait.Requester
        let message: String
        let toldInBand: Bool
        var deliveredTo: Set<String>
    }

    /// A backstop: an entry leaves when its request ends, so this is reached
    /// only by a flood of waiting requests. The oldest notice is dropped.
    public static let maximumEntries = 256

    private let lock = NSLock()
    private var entries: [UUID: Entry] = [:]
    private var order: [UUID] = []

    public init() {}

    func post(id: UUID, requester: HumanWait.Requester, message: String, toldInBand: Bool) {
        lock.withLock {
            guard entries[id] == nil else { return }
            entries[id] = Entry(requester: requester, message: message, toldInBand: toldInBand, deliveredTo: [])
            order.append(id)
            while order.count > Self.maximumEntries {
                entries[order.removeFirst()] = nil
            }
        }
    }

    /// A request's notice changed (`HumanWait.stayOnMac`): sessions not yet
    /// told read the new one, and those already told read it once more.
    func replace(id: UUID, message: String) {
        lock.withLock {
            guard let entry = entries[id] else { return }
            entries[id] = Entry(
                requester: entry.requester, message: message, toldInBand: entry.toldInBand, deliveredTo: []
            )
        }
    }

    func remove(id: UUID) {
        lock.withLock {
            guard entries.removeValue(forKey: id) != nil else { return }
            order.removeAll { $0 == id }
        }
    }

    public var count: Int { lock.withLock { entries.count } }

    /// The notices not yet handed to `session` of requests started under
    /// `ancestor` (strictly below it, through the same lineage-aware descent a
    /// grant root is checked with), excluding those already told in band.
    public func take(
        forSession session: String,
        ancestorPID: pid_t,
        ancestorStartTime: UInt64,
        inspection: ProcessInspection
    ) -> [String] {
        let candidates: [(UUID, Entry)] = lock.withLock {
            order.compactMap { id in
                guard let entry = entries[id], !entry.toldInBand,
                      !entry.deliveredTo.contains(session),
                      entry.requester.pid != ancestorPID else { return nil }
                return (id, entry)
            }
        }
        let matching = candidates.filter {
            inspection.startTime(of: $0.1.requester.pid) == $0.1.requester.startTime
                && inspection.descends($0.1.requester.pid, from: ancestorPID, rootStartTime: ancestorStartTime)
        }
        return lock.withLock {
            matching.compactMap { id, entry in
                guard entries[id] != nil, entries[id]?.deliveredTo.contains(session) == false else { return nil }
                entries[id]?.deliveredTo.insert(session)
                return entry.message
            }
        }
    }
}
