import Foundation
#if canImport(Darwin)
import Darwin
#endif

// How each sudo review ended, in csecd's decision log.
//
// A sudo review decided on the paired phone is logged by csecd itself
// (`SudoRemoteReviewService`), but one decided on the Mac panel, closed by its
// deadline or abandoned by its sudo never reached csecd: the helper alone knew.
// So a coding agent whose sudo nobody answered left nothing for a supervisor
// to retry once the human was back: on 9 Nov 2026 a Codex session's two
// root-tool installs on a developer Mac each ended "nobody answered the sudo review
// within 5 minutes" with no record at all. The helper now reports its end
// (`sudo_review_end`) and csecd logs it, naming the coding agent above the
// sudo (Claude Code or Codex) as the requester's root, as the SSH signing
// records do. The record is the installed helper's report, admitted by its
// code identity, not a decision csecd attests the way it attests its own
// panels; it changes nothing about the review or who answers it.

// MARK: - Wire

/// `sudo_review_end`: the sudo review helper's report of how its review ended,
/// sent once, just before it exits. Only the ends csecd did not see itself: a
/// phone decision csecd already logged when it answered `sudo_remote_review`.
public struct SudoReviewEndRequest: Codable, Sendable, Equatable {
    public enum Outcome: String, Codable, Sendable, CaseIterable {
        /// Touch ID on this Mac's panel approved the sudo.
        case approvedOnMac = "approved_mac"
        /// The panel ended without approving and the sudo went on to macOS's
        /// own authentication (Use Password, a closed panel, no Touch ID and
        /// no phone to decide), which csec does not see.
        case usePassword = "use_password"
        /// The review's deadline passed with nobody answering.
        case timedOut = "timed_out"
        /// The sudo that asked exited before anyone answered.
        case requesterGone = "requester_gone"
    }

    /// A review never lasts longer than the longest frame allows.
    public static let maximumTTDMilliseconds = Int(SudoReviewDeadline.maximumTimeLimit.components.seconds) * 1_000

    public let requestID: String
    public let outcome: Outcome
    /// The submitted command, `sudo …`, as redacted by the PAM module.
    public let command: String
    /// The PAM tty (`/dev/ttys004`), or `no tty`.
    public let terminal: String
    /// The terminal window and tab the panel named, one line.
    public let terminalSummary: String?
    /// From the review's start (the panel and the phone together) to its end.
    public let ttdMs: Int?

    public init(
        requestID: UUID = UUID(),
        outcome: Outcome,
        command: String,
        terminal: String,
        terminalSummary: String? = nil,
        ttdMs: Int? = nil
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.outcome = outcome
        self.command = command
        self.terminal = terminal
        self.terminalSummary = terminalSummary
        self.ttdMs = ttdMs
    }

    /// The helper's report for the review it raised: the same facts the
    /// phone's copy carried (`SudoRemoteReviewRequest`).
    public init(
        _ outcome: Outcome, review: SudoRemoteReviewRequest, took: Duration?, requestID: UUID = UUID()
    ) {
        self.init(
            requestID: requestID, outcome: outcome, command: review.command, terminal: review.terminal,
            terminalSummary: review.terminalSummary,
            ttdMs: took.map { min(DecisionLogRecord.milliseconds($0), Self.maximumTTDMilliseconds) }
        )
    }

    public var isWellFormed: Bool {
        func fits(_ value: String, _ maximumBytes: Int) -> Bool {
            value.utf8.count <= maximumBytes && !value.utf8.contains(0)
        }
        return UUID(uuidString: requestID)?.uuidString.lowercased() == requestID
            && !command.isEmpty && fits(command, SudoRemoteReviewRequest.maximumCommandBytes)
            && fits(terminal, SudoRemoteReviewRequest.maximumContextBytes)
            && (terminalSummary.map { !$0.isEmpty && fits($0, SudoRemoteReviewRequest.maximumContextBytes) } ?? true)
            && (ttdMs.map { (0...Self.maximumTTDMilliseconds).contains($0) } ?? true)
    }
}

extension Request {
    /// Whether this is the sudo review helper's report of how its review ended.
    public var isSudoReviewEnd: Bool {
        if case .sudoReviewEnd = self { return true }
        return false
    }
}

// MARK: - Who the sudo was for

/// The sudo a review helper serves and, when one ran it, the coding agent
/// above that sudo: the root its decision-log records name.
public struct SudoReviewAttribution: Sendable, Equatable {
    /// The sudo, the helper's kernel parent.
    public let sudoPID: pid_t?
    /// The nearest coding agent above the sudo (`GrantScopeKind.codingAgent`).
    public let agent: GrantScopeOption?

    public init(sudoPID: pid_t?, agent: GrantScopeOption?) {
        self.sudoPID = sudoPID
        self.agent = agent
    }

    /// The requester a sudo record names: always class `sudo`, rooted at the
    /// coding agent when there is one, else at the sudo itself.
    public func requester(terminal: String?) -> DecisionLogRecord.Requester {
        DecisionLogRecord.Requester(
            class: "sudo", rootPID: agent?.pid ?? sudoPID, rootLabel: agent?.processLabel, terminal: terminal
        )
    }

    /// `coding_agent` when a coding agent ran the sudo, as an SSH signing
    /// record names the scope its panel offered; nil otherwise.
    public var scope: String? { agent == nil ? nil : GrantScopeKind.codingAgent.rawValue }

    /// `pid`'s parent by `KERN_PROC_PID`, or nil.
    public static func kernelParent(of pid: pid_t) -> pid_t? {
        sudoKernelProcess(pid)?.kp_eproc.e_ppid
    }

    /// The live lookup, while the sudo still runs: helper → its kernel parent
    /// (the root sudo, read with `KERN_PROC_PID`, which answers where
    /// `proc_pidinfo` refuses a set-id process) → the sudo's parent, a process
    /// of the user's, from which the nearest coding agent is found as a grant
    /// scope's is (`GrantScopeInspector`). The helper's start time is checked
    /// first, so a recycled pid names no one.
    public static func live(
        helper: CallerInfo,
        inspection: ProcessInspection = .live,
        kernelParent: @Sendable (pid_t) -> pid_t? = Self.kernelParent(of:)
    ) -> SudoReviewAttribution? {
        guard helper.pid > 1, inspection.startTime(of: helper.pid) == helper.startTime,
              let sudo = kernelParent(helper.pid), sudo > 1 else { return nil }
        guard let parent = kernelParent(sudo), parent > 1,
              let parentStart = inspection.startTime(of: parent) else {
            return SudoReviewAttribution(sudoPID: sudo, agent: nil)
        }
        // A coding agent that runs sudo with no shell between is itself the
        // sudo's parent; the scope walk looks only above its plan root.
        if let client = CodingAgentIdentity.client(
            name: inspection.name(of: parent), executablePath: inspection.executablePath(of: parent)
        ) {
            return SudoReviewAttribution(sudoPID: sudo, agent: GrantScopeOption(
                kind: .codingAgent, pid: parent, startTime: parentStart,
                processLabel: CodingAgentIdentity.displayName(client)
            ))
        }
        let choices = GrantScopeInspector.choices(
            planRootPID: parent, planRootStartTime: parentStart,
            requestingLabel: inspection.name(of: parent) ?? "", inspection: inspection
        )
        return SudoReviewAttribution(sudoPID: sudo, agent: choices.options.first { $0.kind == .codingAgent })
    }
}

/// csecd's memory of each review helper's attribution, taken while its sudo
/// runs: once the sudo exits (the review's `requester_gone`) the helper is
/// launchd's child and the chain above it is gone. Keyed by the helper's
/// incarnation and pruned as helpers exit, like delegation's sudo notes.
public actor SudoReviewAttributions {
    public typealias Lookup = @Sendable (CallerInfo) -> SudoReviewAttribution?
    /// The Claude Code process delegation judged this helper's sudo for, when
    /// it declined it (`ClaudeDelegationService.sudoAgent(for:)`): the very
    /// pid its `decline` record names, so a supervisor matching the decline
    /// to this end matches one process.
    public typealias DelegatedAgent = @Sendable (CallerInfo) async -> ProcessIncarnation?

    public static let maximumRemembered = 64

    private let lookup: Lookup
    private let delegatedAgent: DelegatedAgent
    private let isLive: @Sendable (ProcessIncarnation) -> Bool
    private var remembered: [ProcessIncarnation: SudoReviewAttribution] = [:]

    public init(
        lookup: @escaping Lookup = { SudoReviewAttribution.live(helper: $0) },
        delegatedAgent: @escaping DelegatedAgent = { _ in nil },
        isLive: @escaping @Sendable (ProcessIncarnation) -> Bool = {
            ProcessInspection.live.startTime(of: $0.pid) == $0.startTime
        }
    ) {
        self.lookup = lookup
        self.delegatedAgent = delegatedAgent
        self.isLive = isLive
    }

    /// Look the helper's sudo up now, while it runs, unless already known.
    public func note(_ helper: CallerInfo) async {
        _ = await attribution(for: helper)
    }

    /// What was remembered for the helper, or a live lookup (remembered if it
    /// found the sudo). Delegation's own agent, when it judged this sudo,
    /// stands over the walk's.
    public func attribution(for helper: CallerInfo) async -> SudoReviewAttribution? {
        let key = ProcessIncarnation(pid: helper.pid, startTime: helper.startTime)
        var found = remembered[key] ?? lookup(helper)
        if let agent = await delegatedAgent(helper), found?.agent?.pid != agent.pid {
            found = SudoReviewAttribution(sudoPID: found?.sudoPID, agent: GrantScopeOption(
                kind: .codingAgent, pid: agent.pid, startTime: agent.startTime,
                processLabel: CodingAgentIdentity.displayName(.claude)
            ))
        }
        if let found, remembered[key] != found {
            remembered = remembered.filter { isLive($0.key) }
            if remembered[key] != nil || remembered.count < Self.maximumRemembered { remembered[key] = found }
        }
        return found
    }

    public var count: Int { remembered.count }
}

// MARK: - csecd

/// csecd's side of `sudo_review_end`: log the review's end, rooted at the
/// coding agent above the sudo when there is one. Only the installed helper
/// may report one (`SocketPeerTrustPolicy`, checked again here).
public struct SudoReviewEndService: Sendable {
    private let attributions: SudoReviewAttributions
    private let record: @Sendable (DecisionLogRecord) async -> Void
    private let allowUnverifiedCallersForTesting: Bool

    public init(
        attributions: SudoReviewAttributions,
        decisionLog: DecisionLog?,
        allowUnverifiedCallersForTesting: Bool = false
    ) {
        self.init(
            attributions: attributions,
            record: { record in _ = await decisionLog?.record(record) },
            allowUnverifiedCallersForTesting: allowUnverifiedCallersForTesting
        )
    }

    public init(
        attributions: SudoReviewAttributions,
        record: @escaping @Sendable (DecisionLogRecord) async -> Void,
        allowUnverifiedCallersForTesting: Bool = false
    ) {
        self.attributions = attributions
        self.record = record
        self.allowUnverifiedCallersForTesting = allowUnverifiedCallersForTesting
    }

    /// True once the end is logged.
    public func handle(_ request: SudoReviewEndRequest, caller: CallerInfo) async -> Bool {
        guard allowUnverifiedCallersForTesting || caller.peerIdentity?.code.role == .sudoReviewHelper,
              request.isWellFormed else { return false }
        let attribution = await attributions.attribution(for: caller)
        await record(Self.logRecord(request, attribution: attribution))
        return true
    }

    /// The value-free record of one sudo review's end: the redacted command
    /// the panel showed, its terminal, and the root the review was for. An
    /// unanswered end is `withdrawn` (`timed_out`) or a `panel` its requester
    /// left (`requester_gone`), as on the secret-access and SSH surfaces.
    public static func logRecord(
        _ request: SudoReviewEndRequest, attribution: SudoReviewAttribution?
    ) -> DecisionLogRecord {
        let kind: DecisionLogRecord.Kind
        let outcome: DecisionLogRecord.Outcome
        let decider: DecisionLogRecord.Decider?
        var detail: String?
        let waited = request.ttdMs.map { HumanWait.durationText(.milliseconds($0)) }
        switch request.outcome {
        case .approvedOnMac:
            (kind, outcome, decider) = (.panel, .approved, .humanLocal)
        case .usePassword:
            (kind, outcome, decider) = (.panel, .usePassword, nil)
            detail = "the sudo went on to macOS's own authentication, which csec does not see"
        case .timedOut:
            (kind, outcome, decider) = (.withdrawn, .timedOut, nil)
            detail = "shown, not answered; nobody answered within "
                + HumanWait.minutesText(SudoReviewDeadline.pamTimeLimit) + (waited.map { "; waited \($0)" } ?? "")
        case .requesterGone:
            (kind, outcome, decider) = (.panel, .requesterGone, nil)
            detail = "shown, not answered; the sudo ended before anyone answered" + (waited.map { "; waited \($0)" } ?? "")
        }
        return DecisionLogRecord(
            kind: kind,
            surface: .sudo,
            requester: (attribution ?? SudoReviewAttribution(sudoPID: nil, agent: nil))
                .requester(terminal: request.terminalSummary ?? request.terminal),
            command: request.command,
            scope: attribution?.scope,
            outcome: outcome,
            decider: decider,
            ttdMs: request.ttdMs,
            detail: detail
        ).bounded()
    }
}

// MARK: - The helper

extension SudoReviewEndRequest.Outcome {
    /// What the helper reports for its review's end: nil for a phone decision,
    /// which csecd logged when it answered. The deadline, once it won the
    /// latch, is the end whatever the race returned; a cancelled race whose
    /// sudo had exited is that exit, not a Use Password.
    public static func reported(
        expired: Bool, parentExited: Bool, outcome: SudoReviewOutcome
    ) -> SudoReviewEndRequest.Outcome? {
        if expired { return .timedOut }
        switch outcome {
        case .approved(on: .mac): return .approvedOnMac
        case .approved(on: .phone), .usePassword(deniedOnPhone: true): return nil
        case .usePassword(deniedOnPhone: false): return parentExited ? .requesterGone : .usePassword
        }
    }
}

/// Set once the sudo that spawned the helper exits during its review
/// (`SudoReviewParentWatch`), so the review's end reads as the sudo leaving
/// rather than as the Use Password its cancelled race returns.
public final class SudoReviewParentExit: @unchecked Sendable {
    /// The helper's own: one helper process serves one review.
    public static let helper = SudoReviewParentExit()

    private let lock = NSLock()
    private var exited = false

    public init() {}

    public func mark() { lock.withLock { exited = true } }

    public var hasExited: Bool { lock.withLock { exited } }
}
