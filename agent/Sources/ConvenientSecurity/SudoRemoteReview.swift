import CryptoKit
import CSECRemoteApproval
import Foundation
#if canImport(Darwin)
import Darwin
#endif

// The sudo review, mirrored to the paired phone.
//
// The sudo review helper (`csec-sudo-review`, spawned by the PAM module as the
// login user) races its own panel against the paired phone. The phone leg is
// one `sudo_remote_review` request to csecd, which csecd takes only from a peer
// whose live code identity is the installed helper and answers by publishing a
// v3 review of kind `sudo` through the remote requester. The first verified
// answer wins; a phone that cannot be reached, or a csecd that cannot, leaves
// the Mac panel deciding alone, exactly as before. A sudo approval opens no
// store, mints no grant and pairs nothing: it ends one sudo authentication.

// MARK: - Wire

/// `sudo_remote_review`: the value-free facts of one sudo authentication, as
/// the helper's own panel shows them. The command is the PAM module's
/// redacted, escaped argv; no argument crosses unredacted and no value crosses
/// at all. The helper's pid and start time are never taken from here: csecd
/// reads them from the kernel (`CallerInfo`).
public struct SudoRemoteReviewRequest: Codable, Sendable, Equatable {
    public static let maximumCommandBytes = 32 * 1_024
    public static let maximumContextBytes = 4 * 1_024
    public static let maximumTargetUserBytes = 256

    public let requestID: String
    /// The submitted command, `sudo …`, as redacted by the PAM module.
    public let command: String
    public let workingDirectory: String
    /// The PAM tty (`/dev/ttys004`), or `no tty`.
    public let terminal: String
    /// The terminal window and tab the helper resolved from the tty, one line.
    public let terminalSummary: String?
    /// Who sudo runs the command as, when the helper knows. The PAM frame does
    /// not carry it today, so the helper sends none.
    public let targetUser: String?
    /// When the helper closes the review unanswered, in Unix milliseconds
    /// (`SudoReviewDeadline.closing`): the moment its panel counts down to,
    /// which the phone's card shows too. Helper and csecd share this Mac's
    /// clock, so it holds however long the review waited for its turn.
    public let closesAtMilliseconds: UInt64?

    public init(
        requestID: UUID = UUID(),
        command: String,
        workingDirectory: String,
        terminal: String,
        terminalSummary: String? = nil,
        targetUser: String? = nil,
        closesAtMilliseconds: UInt64? = nil
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.command = command
        self.workingDirectory = workingDirectory
        self.terminal = terminal
        self.terminalSummary = terminalSummary
        self.targetUser = targetUser
        self.closesAtMilliseconds = closesAtMilliseconds
    }

    /// The helper's request for the review its panel shows, with the terminal
    /// tab it resolved for that panel and the moment it closes that panel.
    public init(
        _ review: SudoAuthorizationReviewRequest,
        terminal context: TerminalSessionContext?,
        closing: ReviewDeadline? = nil,
        requestID: UUID = UUID()
    ) {
        let summary = context.map { ReviewDisplay.sanitized($0.summary) }
        self.init(
            requestID: requestID,
            command: review.submittedCommand,
            workingDirectory: review.workingDirectory,
            terminal: review.terminal,
            terminalSummary: summary?.isEmpty == false ? summary : nil,
            closesAtMilliseconds: closing?.unixMilliseconds
        )
    }

    /// The deadline csecd puts on the phone's card: the helper's, unless it
    /// lies further ahead than any PAM frame allows (`maximumTimeLimit`), which
    /// only a clock change could make it. The card then shows no line rather
    /// than a wrong one; the review itself is mirrored either way.
    public func phoneDeadline(nowMilliseconds: UInt64 = currentTimeMilliseconds()) -> UInt64? {
        guard let closesAtMilliseconds else { return nil }
        let limit = UInt64(SudoReviewDeadline.maximumTimeLimit.components.seconds) * 1_000
        let (latest, overflow) = nowMilliseconds.addingReportingOverflow(limit)
        return !overflow && closesAtMilliseconds <= latest ? closesAtMilliseconds : nil
    }

    public var isWellFormed: Bool {
        func fits(_ value: String, _ maximumBytes: Int) -> Bool {
            value.utf8.count <= maximumBytes && !value.utf8.contains(0)
        }
        return UUID(uuidString: requestID)?.uuidString.lowercased() == requestID
            && !command.isEmpty && fits(command, Self.maximumCommandBytes)
            && fits(workingDirectory, Self.maximumContextBytes)
            && fits(terminal, Self.maximumContextBytes)
            && (terminalSummary.map { !$0.isEmpty && fits($0, Self.maximumContextBytes) } ?? true)
            && (targetUser.map { !$0.isEmpty && fits($0, Self.maximumTargetUserBytes) } ?? true)
    }
}

/// csecd's answer to `sudo_remote_review`.
public enum SudoRemoteReviewDecision: String, Codable, Sendable, Equatable {
    /// The pinned phone's verified approval of this one sudo authentication.
    case approved
    /// The pinned phone's verified Deny: sudo falls back to its password
    /// prompt, exactly as for Use Password on the Mac panel.
    case denied
    /// No phone decision: not paired or not ready, relay trouble, a
    /// withdrawal, or a request csecd would not mirror. Never a denial.
    case unavailable
}

extension Request {
    /// Whether this is the one request the sudo review helper may send.
    public var isSudoRemoteReview: Bool {
        if case .sudoRemoteReview = self { return true }
        return false
    }
}

// MARK: - The review the phone renders

/// The process that asked for a sudo review, as the kernel names it: the
/// helper's parent, which the PAM module runs inside. Display only.
public struct SudoReviewRequester: Sendable, Equatable {
    public let pid: pid_t
    public let name: String

    public init(pid: pid_t, name: String) {
        self.pid = pid
        self.name = name
    }

    /// The helper's parent, or nil when it cannot be read. Both lookups use
    /// `KERN_PROC_PID`, which answers for any process: `proc_pidinfo` and
    /// `proc_name` refuse a same-user caller for a set-id process running as
    /// root, as sudo is.
    public static func parent(ofHelper helperPID: pid_t) -> SudoReviewRequester? {
        guard let helper = sudoKernelProcess(helperPID) else { return nil }
        let parent = helper.kp_eproc.e_ppid
        guard parent > 1, let name = commandName(of: parent) else { return nil }
        return SudoReviewRequester(pid: parent, name: name)
    }

    /// The kernel's short command name for `pid` (`KERN_PROC_PID`).
    public static func commandName(of pid: pid_t) -> String? {
        guard var info = sudoKernelProcess(pid) else { return nil }
        let name = withUnsafeBytes(of: &info.kp_proc.p_comm) { raw in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        return name.isEmpty ? nil : name
    }
}

public extension RemoteApprovalReview {
    /// What approving on the phone does, and what Deny does.
    static let sudoFootnote =
        "Approving authorizes this one sudo authentication; sudo then runs the command with "
        + "administrator (root) privileges, or as the user it names. Deny falls back to sudo's "
        + "password prompt on the Mac."

    /// The phone's copy of the Mac panel's administrator banner.
    static let sudoWarning =
        "ADMINISTRATOR ACCESS: An approved sudo command can modify any local account or system "
        + "file. Verify every displayed argument before approving."

    /// Freeze the sudo review the phone renders from the helper's request and
    /// the kernel's view of the helper. Every string is sanitized and fitted to
    /// its wire bound, so a long command is shortened rather than refused.
    /// It carries no credentials, no delivery and no scope or lifetime choice:
    /// the only thing an approval does is end this one sudo authentication.
    init(
        sudo request: SudoRemoteReviewRequest,
        helperPID: pid_t,
        helperStartTime: UInt64,
        requester: SudoReviewRequester?,
        delegationNote: String? = nil,
        pairingLine: String? = nil,
        closesAtMilliseconds: UInt64? = nil
    ) throws {
        typealias Limit = RemoteApprovalReview.FieldLimit
        let arguments = Self.sudoArguments(request.command)
        let tty = Self.shortTTY(request.terminal)
        let who = requester.map { "\($0.name) (pid \($0.pid))" } ?? "sudo (review helper pid \(helperPID))"
        let caller = tty.isEmpty || tty == "no tty" ? "\(who), no terminal" : "\(who) on \(tty)"
        let terminal = Self.sudoFitted(
            request.terminalSummary ?? request.terminal, maxBytes: Limit.terminalDescription
        )
        self.init(
            kind: .sudo,
            headline: Self.sudoRequired(
                arguments.isEmpty ? "sudo" : "sudo " + arguments,
                maxBytes: Limit.headline, placeholder: "sudo", allowNewlines: true
            ),
            callerDescription: Self.sudoRequired(caller, maxBytes: Limit.callerDescription, placeholder: "sudo"),
            terminalDescription: terminal.isEmpty ? nil : terminal,
            secrets: [],
            referenceSetDigest: Self.emptyReferenceSetDigest,
            delivery: nil,
            warnings: [Self.sudoWarning],
            footnote: Self.sudoFootnote,
            sudo: Sudo(
                command: Self.sudoRequired(
                    arguments, maxBytes: Limit.sudoCommand, placeholder: "(no arguments)", allowNewlines: true
                ),
                workingDirectory: Self.sudoRequired(
                    request.workingDirectory, maxBytes: Limit.workingDirectory, placeholder: "unknown"
                ),
                targetUser: request.targetUser.flatMap {
                    let fitted = Self.sudoFitted($0, maxBytes: Limit.targetUser)
                    return fitted.isEmpty ? nil : fitted
                }
            ),
            delegation: Self.sudoDelegation(note: delegationNote, pairingLine: pairingLine),
            closesAtMilliseconds: closesAtMilliseconds,
            operationDigest: Self.sudoOperationDigest(
                request, helperPID: helperPID, helperStartTime: helperStartTime
            )
        )
        try validate()
    }

    /// What a sudo approval authorizes: exactly this sudo invocation's
    /// authentication. SHA-256 over a domain-separated, length-prefixed
    /// encoding of the submitted facts and the kernel's pid and start time of
    /// the helper that asked, so the same command typed twice (two sudo
    /// invocations, two helpers) is two different operations.
    static func sudoOperationDigest(
        _ request: SudoRemoteReviewRequest, helperPID: pid_t, helperStartTime: UInt64
    ) -> Data {
        var bytes = Data()
        func field(_ value: String) {
            let data = Data(value.utf8)
            let count = UInt32(data.count)
            bytes.append(contentsOf: [
                UInt8((count >> 24) & 0xff), UInt8((count >> 16) & 0xff),
                UInt8((count >> 8) & 0xff), UInt8(count & 0xff),
            ])
            bytes.append(data)
        }
        field("csec.remote-approval.sudo-operation.v1")
        field(request.command)
        field(request.workingDirectory)
        field(request.terminal)
        if let targetUser = request.targetUser {
            field("target-user")
            field(targetUser)
        } else {
            field("no-target-user")
        }
        field(String(helperPID))
        field(String(helperStartTime))
        return Data(SHA256.hash(data: bytes))
    }

    /// A declined sudo's note and, when approving pairs, its line: unscoped,
    /// since a sudo review offers no scope or lifetime. The line is required
    /// whole (`ReviewDisplay.fitted` would shorten what approving agrees to),
    /// so a line over its bound leaves the card without one, and a phone
    /// approval then pairs nothing.
    private static func sudoDelegation(note: String?, pairingLine: String?) -> Delegation? {
        let fittedNote = note.map { sudoFitted($0, maxBytes: FieldLimit.delegationNote) }.flatMap { $0.isEmpty ? nil : $0 }
        let line = pairingLine.flatMap { line -> Delegation.Pairing? in
            let safe = ReviewDisplay.sanitized(line)
            guard !safe.isEmpty, safe.utf8.count <= FieldLimit.pairingLine else { return nil }
            return .unscoped(line: safe)
        }
        guard fittedNote != nil || line != nil else { return nil }
        return Delegation(note: fittedNote, pairing: line)
    }

    /// The reference-set digest of a review that names no reference, as an
    /// access review's digest of an empty set would be.
    private static var emptyReferenceSetDigest: Data {
        Data(SHA256.hash(data: Data("csec.remote-approval.references.v1".utf8)))
    }

    /// The submitted command without the `sudo` the PAM module put first.
    private static func sudoArguments(_ command: String) -> String {
        let trimmed = command.trimmingCharacters(in: .whitespaces)
        if trimmed == "sudo" { return "" }
        if trimmed.hasPrefix("sudo ") {
            return String(trimmed.dropFirst("sudo ".count)).trimmingCharacters(in: .whitespaces)
        }
        return trimmed
    }

    private static func shortTTY(_ terminal: String) -> String {
        let safe = ReviewDisplay.sanitized(terminal).trimmingCharacters(in: .whitespaces)
        return safe.hasPrefix("/dev/") ? String(safe.dropFirst("/dev/".count)) : safe
    }

    private static func sudoFitted(_ value: String, maxBytes: Int, allowNewlines: Bool = false) -> String {
        ReviewDisplay.fitted(value, maxBytes: maxBytes, allowNewlines: allowNewlines)
    }

    private static func sudoRequired(
        _ value: String, maxBytes: Int, placeholder: String, allowNewlines: Bool = false
    ) -> String {
        let fitted = sudoFitted(value, maxBytes: maxBytes, allowNewlines: allowNewlines)
        return fitted.isEmpty ? sudoFitted(placeholder, maxBytes: maxBytes) : fitted
    }
}

// MARK: - csecd

/// csecd's side of `sudo_remote_review`: freeze the review, ask the remote
/// provider (the `RemoteApprovalManager`) directly — never through the consent
/// queue, since nothing on this Mac is shown for it — and answer with the
/// phone's decision. The request's handler task is cancelled when the helper's
/// connection closes (its panel won, its sudo exited, the PAM module killed
/// it), and cancelling withdraws the phone's copy.
public struct SudoRemoteReviewService: Sendable {
    public typealias RequesterLookup = @Sendable (pid_t) -> SudoReviewRequester?
    /// csecd's own note (and pairing line) for the sudo this helper serves,
    /// when delegation declined it (`ClaudeDelegationService.sudoNote(for:)`):
    /// the phone card shows them below its footnote, as the Mac panel does.
    public typealias NoteLookup = @Sendable (CallerInfo) async -> SudoDelegationNote?
    /// Records a phone approval of a card that showed the pairing line
    /// (`ClaudeDelegationService.recordSudoApproval`).
    public typealias PairingRecorder = @Sendable (CallerInfo) async -> Void
    /// Who the helper's sudo is for (`SudoReviewAttributions`): the record of
    /// a phone decision is rooted at the coding agent above the sudo, as the
    /// helper's own end reports are.
    public typealias AttributionLookup = @Sendable (CallerInfo) async -> SudoReviewAttribution?

    private let remote: any RemoteAccessPolicyReviewProvider
    private let record: @Sendable (DecisionLogRecord) async -> Void
    private let requester: RequesterLookup
    private let note: NoteLookup
    private let recordPairing: PairingRecorder
    private let attribution: AttributionLookup
    private let allowUnverifiedCallersForTesting: Bool
    private let log: @Sendable (String) -> Void

    public init(
        remote: any RemoteAccessPolicyReviewProvider,
        decisionLog: DecisionLog?,
        allowUnverifiedCallersForTesting: Bool = false,
        requester: @escaping RequesterLookup = { SudoReviewRequester.parent(ofHelper: $0) },
        note: @escaping NoteLookup = { _ in nil },
        recordPairing: @escaping PairingRecorder = { _ in },
        attribution: @escaping AttributionLookup = { _ in nil },
        log: @escaping @Sendable (String) -> Void = { line in
            FileHandle.standardError.write(Data("\(line)\n".utf8))
        }
    ) {
        self.init(
            remote: remote,
            record: { record in _ = await decisionLog?.record(record) },
            allowUnverifiedCallersForTesting: allowUnverifiedCallersForTesting,
            requester: requester,
            note: note,
            recordPairing: recordPairing,
            attribution: attribution,
            log: log
        )
    }

    public init(
        remote: any RemoteAccessPolicyReviewProvider,
        record: @escaping @Sendable (DecisionLogRecord) async -> Void,
        allowUnverifiedCallersForTesting: Bool = false,
        requester: @escaping RequesterLookup = { SudoReviewRequester.parent(ofHelper: $0) },
        note: @escaping NoteLookup = { _ in nil },
        recordPairing: @escaping PairingRecorder = { _ in },
        attribution: @escaping AttributionLookup = { _ in nil },
        log: @escaping @Sendable (String) -> Void = { line in
            FileHandle.standardError.write(Data("\(line)\n".utf8))
        }
    ) {
        self.remote = remote
        self.attribution = attribution
        self.record = record
        self.requester = requester
        self.note = note
        self.recordPairing = recordPairing
        self.allowUnverifiedCallersForTesting = allowUnverifiedCallersForTesting
        self.log = log
    }

    public func handle(_ request: SudoRemoteReviewRequest, caller: CallerInfo) async -> Response {
        Response(requestID: request.requestID, sudoRemoteReview: await review(request, caller: caller))
    }

    public func review(
        _ request: SudoRemoteReviewRequest, caller: CallerInfo
    ) async -> SudoRemoteReviewDecision {
        // The socket policy already admits only the helper to this request;
        // the service does not rely on that alone.
        guard allowUnverifiedCallersForTesting
                || caller.peerIdentity?.code.role == .sudoReviewHelper,
              request.isWellFormed else { return .unavailable }
        let sudo = requester(caller.pid)
        // Looked up while the sudo runs, before anything can wait on the phone.
        let attributed = await attribution(caller)
        let delegation = await note(caller)
        let review: RemoteApprovalReview
        do {
            review = try RemoteApprovalReview(
                sudo: request, helperPID: caller.pid, helperStartTime: caller.startTime, requester: sudo,
                delegationNote: delegation?.note, pairingLine: delegation?.pairingLine,
                closesAtMilliseconds: request.phoneDeadline()
            )
        } catch {
            log("csecd: a sudo review stays on the Mac; its phone review failed validation (\(error)).")
            return .unavailable
        }
        guard case .ready = await remote.remoteReadiness(for: []) else { return .unavailable }
        let published = ContinuousClock.now
        switch await remote.reviewRemoteAccess(review, unlock: .notNeeded) {
        case .unavailable:
            return .unavailable
        case let .denied(receivedAt):
            await record(logRecord(
                request, requester: sudo, attribution: attributed, caller: caller,
                outcome: Task.isCancelled ? .requesterGone : .denied,
                ttd: published.duration(to: receivedAt)
            ))
            return .denied
        case let .approved(selection, unlock):
            // Never asked for; a sudo approval opens nothing.
            unlock?.invalidate()
            // The phone signed that its card showed the pairing line, and the
            // shared rule agreed: auto mode may run sudo in that project now.
            if selection.pairingLineShown, !Task.isCancelled { await recordPairing(caller) }
            await record(logRecord(
                request, requester: sudo, attribution: attributed, caller: caller,
                outcome: Task.isCancelled ? .requesterGone : .phoneApproved,
                ttd: published.duration(to: .now)
            ))
            return .approved
        }
    }

    /// A value-free `panel` record of a phone-decided sudo: the redacted
    /// command the review showed, the terminal, and who decided. `requester_gone`
    /// when the helper had closed before the answer could reach it. Rooted at
    /// the coding agent above the sudo when there is one (`scope`
    /// `coding_agent`), else at the sudo.
    private func logRecord(
        _ request: SudoRemoteReviewRequest,
        requester: SudoReviewRequester?,
        attribution: SudoReviewAttribution?,
        caller: CallerInfo,
        outcome: DecisionLogRecord.Outcome,
        ttd: Duration
    ) -> DecisionLogRecord {
        let root = SudoReviewAttribution(
            sudoPID: attribution?.sudoPID ?? requester?.pid ?? caller.pid, agent: attribution?.agent
        )
        return DecisionLogRecord(
            kind: .panel,
            surface: .sudo,
            requester: root.requester(terminal: request.terminalSummary ?? request.terminal),
            command: request.command,
            scope: root.scope,
            outcome: outcome,
            decider: .humanPhone,
            ttdMs: DecisionLogRecord.milliseconds(ttd)
        ).bounded()
    }
}

// MARK: - The helper

/// The helper's phone leg: one `sudo_remote_review` round trip to csecd. The
/// socket call blocks, so it runs on a thread of its own; cancelling the
/// calling task answers `.unavailable` at once and shuts the connection down,
/// which withdraws the phone's copy (csecd's peer-exit watch).
public struct SudoRemoteReviewClient: Sendable {
    private let path: String
    private let serverTrustPolicy: AgentServerTrustPolicy
    private let liveness: AgentLiveness

    public init(
        path: String,
        serverTrustPolicy: AgentServerTrustPolicy,
        liveness: AgentLiveness = .default
    ) {
        self.path = path
        self.serverTrustPolicy = serverTrustPolicy
        self.liveness = liveness
    }

    /// The installed csecd. csecd's answer ends a root authentication, so a
    /// release helper takes it only from the product agent; the relaxed trust
    /// exists only in a debug build, like `CSEC_SOCKET`.
    public static var installed: SudoRemoteReviewClient {
        #if DEBUG
        let trust: AgentServerTrustPolicy = .allowUnverifiedForTesting
        #else
        let trust: AgentServerTrustPolicy = .requireProductAgent
        #endif
        return SudoRemoteReviewClient(path: AgentSocket.defaultPath(), serverTrustPolicy: trust)
    }

    public func review(_ request: SudoRemoteReviewRequest) async -> SudoRemoteReviewDecision {
        let cancellation = AgentCallCancellation()
        let answer = SudoRemoteReviewAnswer()
        let path = self.path
        let trust = self.serverTrustPolicy
        let liveness = self.liveness
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                guard answer.arm(continuation) else { return }
                Thread.detachNewThread {
                    let decision = AgentClient(path: path, serverTrustPolicy: trust, liveness: liveness)
                        .sudoRemoteReview(request, cancellation: cancellation)
                    answer.resume(decision)
                }
            }
        } onCancel: {
            // Shut the connection first, so the phone's copy is withdrawn by
            // the time this leg has answered.
            cancellation.cancel()
            answer.resume(.unavailable)
        }
    }
}

/// Resumes one phone-leg continuation exactly once: with csecd's answer, or
/// with `.unavailable` when the leg is cancelled first (the blocked thread
/// then finishes on its own and its answer is dropped).
private final class SudoRemoteReviewAnswer: @unchecked Sendable {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<SudoRemoteReviewDecision, Never>?
    private var early: SudoRemoteReviewDecision?

    /// False when the answer (a cancellation) came before the continuation,
    /// which is then resumed here with it.
    func arm(_ continuation: CheckedContinuation<SudoRemoteReviewDecision, Never>) -> Bool {
        lock.lock()
        if let early {
            lock.unlock()
            continuation.resume(returning: early)
            return false
        }
        self.continuation = continuation
        lock.unlock()
        return true
    }

    func resume(_ decision: SudoRemoteReviewDecision) {
        lock.lock()
        guard early == nil else {
            lock.unlock()
            return
        }
        early = decision
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(returning: decision)
    }
}

/// How a sudo review ended, and so what the helper tells the PAM module.
public enum SudoReviewOutcome: Sendable, Equatable {
    /// Touch ID on the Mac panel, or the paired phone's verified approval.
    case approved(on: HumanDecisionSurface)
    /// Use Password on the Mac panel, the phone's Deny, or the review closing
    /// with nobody deciding: sudo asks for the password.
    case usePassword(deniedOnPhone: Bool)

    /// Zero is the PAM module's only approval signal; 69 lets sudo fall back
    /// to its password prompt. The helper's third status, a review nobody
    /// answered in time, is `SudoReviewDeadline.expiredExitStatus`.
    public var exitStatus: Int32 {
        switch self {
        case .approved: return 0
        case .usePassword: return 69
        }
    }
}

/// The helper's race between its Mac panel and the paired phone.
///
/// Both legs start together, so the phone never delays the panel. The first
/// verified outcome wins: the panel's approval or Use Password, the phone's
/// approval or Deny. A phone leg that is `.unavailable` is no decision: the
/// panel alone decides, exactly as without a phone, and it is told so through
/// the `ReviewPhoneStatus` it was started with, since a panel with no
/// Touch ID then has nobody left to approve. The losing leg is then
/// cancelled and awaited, as `MirroredPolicyReview` does for the access and
/// SSH panels: a panel still up closes and invalidates its LAContext, and a
/// phone request still pending is withdrawn (its connection shut down).
/// Cancelling the race (the sudo that asked has exited) cancels both legs.
public enum SudoReviewRace {
    private enum Leg: Sendable {
        case local(SudoAuthorizationReviewOutcome)
        case phone(SudoRemoteReviewDecision)
    }

    /// A race whose local leg does not need to know what the phone does.
    public static func run(
        presentationLock: ReviewPresentationLock? = nil,
        local: @escaping @Sendable () async -> SudoAuthorizationReviewOutcome,
        phone: @escaping @Sendable () async -> SudoRemoteReviewDecision
    ) async -> SudoReviewOutcome {
        await run(presentationLock: presentationLock, local: { _ in await local() }, phone: phone)
    }

    public static func run(
        presentationLock: ReviewPresentationLock? = nil,
        local: @escaping @Sendable (ReviewPhoneStatus) async -> SudoAuthorizationReviewOutcome,
        phone: @escaping @Sendable () async -> SudoRemoteReviewDecision
    ) async -> SudoReviewOutcome {
        let permit: ReviewPresentationLock.Permit?
        do {
            permit = try await presentationLock?.acquire()
            try Task.checkCancellation()
        } catch {
            return .usePassword(deniedOnPhone: false)
        }
        // Admission precedes both legs: a queued helper publishes no phone
        // request and builds no panel or LAContext. Release only after the
        // losing leg has closed its window or withdrawn its phone copy.
        defer { permit?.release() }
        let status = ReviewPhoneStatus()
        return await withTaskGroup(of: Leg.self) { group in
            group.addTask { .local(await local(status)) }
            group.addTask { .phone(await phone()) }
            var outcome: SudoReviewOutcome?
            while outcome == nil, let leg = await group.next() {
                switch leg {
                case .local(.approved): outcome = .approved(on: .mac)
                case .local(.usePassword): outcome = .usePassword(deniedOnPhone: false)
                case .phone(.approved): outcome = .approved(on: .phone)
                case .phone(.denied): outcome = .usePassword(deniedOnPhone: true)
                case .phone(.unavailable): status.markUnavailable()
                }
            }
            group.cancelAll()
            for await _ in group {}
            // Unreachable while the panel always answers; if it is ever
            // reached, nobody approved.
            return outcome ?? .usePassword(deniedOnPhone: false)
        }
    }
}
