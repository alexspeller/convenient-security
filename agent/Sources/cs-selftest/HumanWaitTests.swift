import ConvenientSecurity
import CSECRemoteApproval
import CSecuritySupport
import Foundation
import CSECBuildIdentity

// A coding agent's request that waits on a human (csec-ia3q): its session is
// told at once, and nobody answering withdraws it at its own deadline, queued
// or on screen, logged as `withdrawn` rather than a Deny. A terminal's request
// waits as long as it takes and hears nothing new.

func humanWaitTests() async {
    print("\n# Approval wait: notices and the coding-agent deadline")
    approvalWaitSettingTests()
    await requestAnchorTests()
    humanWaitLatchTests()
    await humanWaitBoundingTests()
    await queuedReviewLatchTests()
    approvalPlaceNoticeTests()
    await approvalPlaceReviewTests()
    noticeWireTests()
    await noticeSocketTests()
    await approvalNoticeChannelTests()
    withdrawnRecordShapeTests()
    await agentHumanWaitTests()
}

// MARK: - The setting

private func approvalWaitSettingTests() {
    let unset = ApprovalWaitLimit.resolve(nil)
    check(unset.minutes == 20 && unset.isDefault && unset.ignoredValue == nil,
          "wait setting: unset is the 20-minute default")
    let thirty = ApprovalWaitLimit.resolve(NSNumber(value: 30))
    check(thirty.minutes == 30 && !thirty.isDefault, "wait setting: an integer in range is used")
    check(ApprovalWaitLimit.resolve("45").minutes == 45, "wait setting: a numeric string is used")
    for bad: Any in [NSNumber(value: 0), NSNumber(value: 1_441), NSNumber(value: 2.5), kCFBooleanTrue as Any, "soon"] {
        let resolved = ApprovalWaitLimit.resolve(bad)
        check(resolved.minutes == 20 && resolved.isDefault && resolved.ignoredValue != nil,
              "wait setting: \(bad) is ignored for the default and named")
    }
    check(ApprovalWaitLimit.setCommand.contains("defaults write \(CSECBuildIdentity.identifier)"),
          "wait setting: the status command names the defaults domain")
}

// MARK: - The latch and the notice

private func waitFixture(
    limit: Duration? = .seconds(1_200),
    sink: RequestNoticeSink? = nil,
    board: HumanWaitBoard? = nil,
    pid: pid_t = 4_242,
    start: UInt64 = 4_243
) -> HumanWait {
    HumanWait(
        requester: HumanWait.Requester(pid: pid, startTime: start),
        summary: "secret access to op://wait-fixture/item/password",
        limit: limit, sink: sink, board: board
    )
}

private final class NoticeLog: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []
    func append(_ line: String) { lock.withLock { lines.append(line) } }
    var all: [String] { lock.withLock { lines } }
    var sink: RequestNoticeSink { RequestNoticeSink { self.append($0) } }
}

private func humanWaitLatchTests() {
    let decidedFirst = waitFixture()
    check(decidedFirst.decide() && !decidedFirst.expire() && decidedFirst.currentState == .decided,
          "latch: a human decision before the deadline keeps the deadline from withdrawing it")
    let expiredFirst = waitFixture()
    check(expiredFirst.expire() && !expiredFirst.decide() && expiredFirst.isExpired,
          "latch: a decision after the deadline withdrew the request is too late")
    check(expiredFirst.effectiveReason(.requesterGone) == .timedOut
          && decidedFirst.effectiveReason(.requesterGone) == .requesterGone,
          "latch: only an expired request's ending reads as timed out")

    let notices = NoticeLog()
    let board = HumanWaitBoard()
    let told = waitFixture(sink: notices.sink, board: board)
    told.notifyWaiting()
    told.notifyWaiting()
    check(notices.all.count == 1, "notice: a request waiting on a human is told exactly once")
    check(notices.all.first?.hasPrefix("waiting for approval on the Mac or iPhone: secret access to op://wait-fixture") == true
          && notices.all.first?.contains("withdraws it at") == true
          && notices.all.first?.contains("20 minutes after it was asked") == true,
          "notice: it names the request and when it will be withdrawn")
    let silent = NoticeLog()
    let terminal = waitFixture(limit: nil, sink: silent.sink, board: board)
    terminal.notifyWaiting()
    check(silent.all.isEmpty, "notice: a terminal's request (no limit) hears nothing new")
    let late = waitFixture(sink: notices.sink)
    _ = late.decide()
    late.notifyWaiting()
    check(notices.all.count == 1, "notice: a request already decided is not announced")
    told.finish()
    check(board.count == 0, "board: a request told in band leaves the board when it ends")

    check(HumanWait.durationText(.seconds(41)) == "41s"
          && HumanWait.durationText(.seconds(192)) == "3m12s"
          && HumanWait.durationText(.seconds(7_500)) == "2h05m",
          "wait: durations read as 41s, 3m12s and 2h05m")
}

// MARK: - Bounding a request

private func humanWaitBoundingTests() async {
    let quick = waitFixture(limit: .milliseconds(400))
    let answer = await quick.bounding { 7 }
    check(answer == 7 && quick.currentState == .pending,
          "bounding: a request that ends before its deadline is left alone")

    let hung = waitFixture(limit: .milliseconds(150))
    let started = ContinuousClock.now
    let cancelled = await hung.bounding { () -> Bool in
        try? await Task.sleep(for: .seconds(30))
        return Task.isCancelled
    }
    let elapsed = started.duration(to: .now)
    check(cancelled && hung.isExpired && elapsed < .seconds(5),
          "bounding: nobody deciding by the deadline cancels the request (\(elapsed))")

    let decided = waitFixture(limit: .milliseconds(100))
    let survived = await decided.bounding { () -> Bool in
        _ = HumanWait.current?.decide()
        try? await Task.sleep(for: .milliseconds(400))
        return !Task.isCancelled
    }
    check(survived && !decided.isExpired,
          "bounding: once a human decided, the deadline no longer cuts the request")

    let unbounded = waitFixture(limit: nil)
    let bound = await unbounded.bounding { HumanWait.current === unbounded }
    check(bound, "bounding: the request runs with its wait as HumanWait.current")
}

// MARK: - QueuedPolicyReview and the latch

private func latchReviewFixture() -> AccessPolicyReview {
    AccessPolicyReview(
        caller: CallerInfo(pid: 4_242, startTime: 4_243, description: "latch fixture"),
        reason: "latch fixture",
        plan: DeliveryPlan(
            mechanism: .directHeap,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/true", assurance: .unverified),
            root: .caller, descendantScope: .exactProcess, destination: .localDevelopment,
            requestedTTLSeconds: nil, operationContext: "latch fixture"
        ),
        credentials: [PolicyReviewCredential(references: [try! SecretRef("op://latch/item/password")])]
    )
}

private struct ApprovingReview: PolicyReviewProvider {
    let session: LatchFixtureSession
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        .approved(AccessPolicyApproval(authenticationSession: session))
    }
}

private actor LatchFixtureSession: AccessPolicyAuthenticationSession {
    private(set) var cancelled = false
    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome { .approved(unlock: nil) }
    func cancel() async { cancelled = true }
}

private func queuedReviewLatchTests() async {
    let review = latchReviewFixture()

    // A human approval marks the request decided, so its deadline cannot
    // throw the approval away afterwards.
    let session = LatchFixtureSession()
    let wait = waitFixture()
    let outcome = await HumanWait.$current.withValue(wait) {
        await QueuedPolicyReview(underlying: ApprovingReview(session: session), queue: ConsentQueue())
            .reviewAccess(review)
    }
    if case .approved = outcome {
        check(wait.currentState == .decided && !wait.expire(),
              "latch: QueuedPolicyReview marks an approved request decided")
    } else {
        check(false, "latch: QueuedPolicyReview returns the approval")
    }
    check(wait.wasShown, "latch: a review that left the UI queue counts as shown")

    // An approval that lands after the deadline withdrew the request is
    // answered as the withdrawal, and its authentication is cancelled.
    let lateSession = LatchFixtureSession()
    let expired = waitFixture()
    _ = expired.expire()
    let late = await HumanWait.$current.withValue(expired) {
        await QueuedPolicyReview(underlying: ApprovingReview(session: lateSession), queue: ConsentQueue())
            .reviewAccess(review)
    }
    if case .denied(.timedOut) = late {
        check(await lateSession.cancelled, "latch: a too-late approval's authentication is cancelled")
    } else {
        check(false, "latch: an approval after the deadline reads as timed out")
    }

    // Withdrawn from the UI queue before any panel: `.withdrawn`, not shown.
    let queue = ConsentQueue()
    let held = try? await queue.acquire()
    let queuedWait = waitFixture()
    let queuedNotices = NoticeLog()
    let noticed = waitFixture(sink: queuedNotices.sink)
    let waiting = Task {
        await HumanWait.$current.withValue(noticed) {
            await QueuedPolicyReview(underlying: GatedPolicyReview(), queue: queue).reviewAccess(review)
        }
    }
    _ = await eventuallyTrue { await queue.waitingCount == 1 }
    check(queuedNotices.all.count == 1,
          "notice: a review queued behind another panel tells its session at once")
    waiting.cancel()
    if case .denied(.withdrawn) = await waiting.value {
        check(!noticed.wasShown, "latch: a review cancelled while queued was never shown")
    } else {
        check(false, "latch: a review cancelled while queued is withdrawn")
    }
    _ = queuedWait
    await held?.release()
}

// MARK: - Where the request can be answered (csec-0.65.7)

private func approvalPlaceNoticeTests() {
    let summary = "secret access to op://wait-fixture/item/password"
    let macOnly = NoticeLog()
    let onMac = waitFixture(sink: macOnly.sink)
    onMac.notifyWaiting(place: .macOnly)
    check(macOnly.all.count == 1
            && macOnly.all.first?.hasPrefix("waiting for approval on the Mac: \(summary).") == true
            && macOnly.all.first?.contains("iPhone") == false
            && macOnly.all.first?.contains("withdraws it at") == true,
          "place: a request only the Mac can answer is told the Mac, not the iPhone, and its deadline")
    onMac.stayOnMac()
    check(macOnly.all.count == 1, "place: a request already told the Mac is not told again")

    let corrected = NoticeLog()
    let board = HumanWaitBoard()
    let phoneFirst = waitFixture(board: board)
    let inBand = waitFixture(sink: corrected.sink)
    inBand.notifyWaiting()
    phoneFirst.notifyWaiting()
    let session = "place-session"
    // The fixture's requester (pid 4242) runs under a coding agent, pid 4000.
    let tree = ProcessInspection(
        startTime: { [4_242: 4_243, 4_000: 4_001][$0] },
        parent: { $0 == 4_242 ? 4_000 : nil },
        name: { _ in nil },
        executablePath: { _ in nil }
    )
    func take() -> [String] {
        board.take(forSession: session, ancestorPID: 4_000, ancestorStartTime: 4_001, inspection: tree)
    }
    let firstTake = take()
    check(firstTake.count == 1 && firstTake.first?.hasPrefix("waiting for approval on the Mac or iPhone:") == true,
          "place: unjudged, the notice keeps saying the Mac or iPhone")
    inBand.stayOnMac()
    phoneFirst.stayOnMac()
    inBand.stayOnMac()
    check(corrected.all.count == 2
            && corrected.all.last?.hasPrefix(
                "the iPhone cannot approve this request, so it is waiting for approval on the Mac: \(summary).") == true
            && corrected.all.last?.contains("withdraws it at") == true,
          "place: a session told the iPhone could answer is told once that only the Mac can")
    let secondTake = take()
    check(secondTake.count == 1 && secondTake.first?.hasPrefix("the iPhone cannot approve this request") == true
            && take().isEmpty,
          "place: the board hands the correction once to a session that already read the first notice")

    let early = NoticeLog()
    let judgedLate = waitFixture(sink: early.sink)
    judgedLate.stayOnMac()
    check(early.all.isEmpty, "place: a request not yet announced hears nothing when it stays on the Mac")
    judgedLate.notifyWaiting()
    check(early.all.count == 1 && early.all.first?.hasPrefix("waiting for approval on the Mac: ") == true,
          "place: its notice then says the Mac")

    let decided = NoticeLog()
    let answered = waitFixture(sink: decided.sink)
    answered.notifyWaiting()
    _ = answered.decide()
    answered.stayOnMac()
    check(decided.all.count == 1, "place: a request already decided is not corrected")

    check(waitFixture().timeoutMessage.hasPrefix("approval was not given: nobody answered within 20 minutes, ")
            && AccessPolicyDenialReason.timedOut.endedText == "nobody answered in time, so csec withdrew the request",
          "place: the timeout text names no place, which may have been the Mac alone")
}

/// A phone whose readiness is scripted per call; it never decides.
private actor PlacePhone: RemoteAccessPolicyReviewProvider {
    private var answers: [RemoteReviewReadiness]
    private(set) var asked = 0

    init(_ answers: [RemoteReviewReadiness]) { self.answers = answers }

    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        asked += 1
        return answers.count > 1 ? answers.removeFirst() : answers[0]
    }

    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        .unavailable
    }
}

private struct RefusingLocalReview: PolicyReviewProvider {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        .denied(.authenticationFailed)
    }
}

/// csecd's reviewer stack, `QueuedPolicyReview` over `MirroredPolicyReview`:
/// the notice says where the request can be answered, judged once for a
/// request presented at once, and again for one that waited in the queue.
private func approvalPlaceReviewTests() async {
    let review = latchReviewFixture()
    func run(_ phone: PlacePhone, queue: ConsentQueue = ConsentQueue()) async -> [String] {
        let notices = NoticeLog()
        let wait = waitFixture(sink: notices.sink)
        let stack = QueuedPolicyReview(
            underlying: MirroredPolicyReview(local: RefusingLocalReview(), remote: phone, log: { _ in }),
            queue: queue
        )
        _ = await HumanWait.$current.withValue(wait) { await stack.reviewAccess(review) }
        return notices.all
    }

    let cold = PlacePhone([.unavailable])
    let coldNotices = await run(cold)
    let coldAsked = await cold.asked
    check(coldNotices.count == 1 && coldNotices.first?.hasPrefix("waiting for approval on the Mac: ") == true
            && coldAsked == 1,
          "place: a request the phone cannot carry is told the Mac once, judged once")

    let ready = PlacePhone([.ready(unlock: .notNeeded)])
    let readyNotices = await run(ready)
    let readyAsked = await ready.asked
    check(readyNotices.count == 1 && readyNotices.first?.hasPrefix("waiting for approval on the Mac or iPhone: ") == true
            && readyAsked == 1,
          "place: a request the phone can carry is told the Mac or iPhone, judged once")

    // Ready when it queued, not when its turn came: told again.
    let queue = ConsentQueue()
    let held = try? await queue.acquire()
    let lapsed = PlacePhone([.ready(unlock: .notNeeded), .unavailable])
    let waiting = Task { await run(lapsed, queue: queue) }
    _ = await eventuallyTrue { await queue.waitingCount == 1 }
    await held?.release()
    let lapsedNotices = await waiting.value
    let lapsedAsked = await lapsed.asked
    check(lapsedNotices.count == 2
            && lapsedNotices.first?.hasPrefix("waiting for approval on the Mac or iPhone: ") == true
            && lapsedNotices.last?.hasPrefix("the iPhone cannot approve this request, so it is waiting") == true
            && lapsedAsked == 2,
          "place: a queued request judged again at its turn is told when the phone can no longer answer")
}

// MARK: - The notice frame

private func noticeWireTests() {
    let frame = WireTransport.noticeFrame("waiting\u{1b}[31m for approval\nnow")
    let message = WireTransport.notice(in: frame)
    check(message != nil && message?.contains("\u{1b}") == false && message?.contains("\n") == false,
          "notice frame: round-trips, sanitized to one printable line")
    check(WireTransport.notice(in: WireTransport.heartbeatFrame()) == nil
          && !WireTransport.isHeartbeat(frame),
          "notice frame: a notice and a heartbeat are told apart")
    let long = WireTransport.notice(in: WireTransport.noticeFrame(String(repeating: "x", count: 4_000)))
    check((long?.utf8.count ?? 0) <= WireTransport.maximumNoticeBytes, "notice frame: bounded")

    let plain = try! WireTransport.encodeRequest(.schemes, supportsHeartbeats: true)
    check(!String(decoding: plain, as: UTF8.self).contains("supportsNotices")
          && !WireTransport.requestSupportsNotices(plain),
          "notice frame: a client that reads none sends the frame it always did")
    let opted = try! WireTransport.encodeRequest(.schemes, supportsHeartbeats: true, supportsNotices: true)
    check(WireTransport.requestSupportsNotices(opted), "notice frame: the opt-in flag is read")
}

private func noticeSocketTests() async {
    guard let base = makeLivenessSocketDirectory("notice") else {
        check(false, "notice socket: a scratch directory")
        return
    }
    defer { try? FileManager.default.removeItem(at: base) }
    let socketPath = base.appendingPathComponent("agent.sock").path
    let liveness = AgentLiveness.forTesting(silenceDeadline: 2)
    let server = SocketServer(
        path: socketPath, clientTrustPolicy: .allowUnverifiedForTesting, liveness: liveness
    ) { request, _ in
        RequestNotices.sink?.send("waiting for approval on the Mac or iPhone: fixture.")
        try? await Task.sleep(nanoseconds: 200_000_000)
        switch request {
        case let .access(access):
            return Response(
                requestID: access.requestID,
                values: Dictionary(uniqueKeysWithValues: access.references.map { ($0, Data("v".utf8)) })
            )
        case .schemes:
            return Response(schemes: ["op"])
        default:
            return .failed(.invalidRequest, message: "unexpected request in notice test")
        }
    }
    Thread.detachNewThread { try? server.run() }
    guard waitForSocket(socketPath) else {
        check(false, "notice socket: the server bound its socket")
        return
    }
    let heard = await offMainActor(timeoutSeconds: 20) { () -> String in
        let client = AgentClient(path: socketPath, serverTrustPolicy: .allowUnverifiedForTesting, liveness: liveness)
        var notices: [String] = []
        do {
            let values = try client.access(
                references: ["op://notice/item/password"], reason: "notice fixture",
                waitingNotice: { notices.append($0) }
            )
            return "\(values.count) value(s); notices: \(notices.joined(separator: "|"))"
        } catch {
            return "threw: \(error)"
        }
    }
    check(heard == "1 value(s); notices: waiting for approval on the Mac or iPhone: fixture.",
          "notice socket: a client that reads notices hears one mid-request, then its response (\(heard ?? "nil"))")
    let plain = await offMainActor(timeoutSeconds: 20) { () -> String in
        let client = AgentClient(path: socketPath, serverTrustPolicy: .allowUnverifiedForTesting, liveness: liveness)
        return (try? client.schemes().joined()) ?? "threw"
    }
    check(plain == "op", "notice socket: a client that reads no notices is sent none")
}

/// A `csec ai`'s approval-notice channel against a real `Agent` over a real
/// socket: a waiting request under it is reported once, and a refused poll
/// costs only the notices, never the output-redaction session beside it.
private final class RefuseNotices: @unchecked Sendable {
    private let lock = NSLock()
    private var on = false
    var value: Bool {
        get { lock.withLock { on } }
        set { lock.withLock { on = newValue } }
    }
}

private func approvalNoticeChannelTests() async {
    guard let base = makeLivenessSocketDirectory("notice-channel") else {
        check(false, "notice channel: a scratch directory")
        return
    }
    defer { try? FileManager.default.removeItem(at: base) }
    let socketPath = base.appendingPathComponent("agent.sock").path
    let liveness = AgentLiveness.forTesting(silenceDeadline: 5)
    let board = HumanWaitBoard()
    let agent = Agent(
        resolver: SecretResolver(cache: NullSecretCache()), grants: GrantTable(),
        consent: AutoApproveConsent(), policyReview: GatedPolicyReview(),
        allowUnverifiedPlansForTesting: true, terminalInspection: .unavailable, humanWaitBoard: board
    )
    let refuse = RefuseNotices()
    let server = SocketServer(
        path: socketPath, clientTrustPolicy: .allowUnverifiedForTesting, liveness: liveness
    ) { request, caller in
        switch request {
        case let .beginOutputRedaction(begin):
            return await agent.beginOutputRedaction(request: begin, caller: caller)
        case let .redactOutputChunk(chunk):
            return await agent.redactOutputChunk(request: chunk, caller: caller)
        case let .endOutputRedaction(end):
            return await agent.endOutputRedaction(request: end, caller: caller)
        case let .takeApprovalNotices(take):
            if refuse.value { return .failed(.invalidRequest, message: "refused in test", requestID: take.requestID) }
            return await agent.takeApprovalNotices(request: take, caller: caller)
        default:
            return .failed(.invalidRequest, message: "unexpected request in notice channel test")
        }
    }
    Thread.detachNewThread { try? server.run() }
    guard waitForSocket(socketPath) else {
        check(false, "notice channel: the server bound its socket")
        return
    }
    // A waiting request whose requester is a child of this process (as an
    // `ssh` is a descendant of its `csec ai`).
    let child = Process()
    child.executableURL = URL(fileURLWithPath: "/bin/sleep")
    child.arguments = ["30"]
    do { try child.run() } catch {
        check(false, "notice channel: the requester fixture starts (\(error))")
        return
    }
    defer { if child.isRunning { child.terminate() } }
    guard let childStart = ProcessAncestry.startTime(of: child.processIdentifier) else {
        check(false, "notice channel: the requester fixture has a live incarnation")
        return
    }
    let wait = HumanWait(
        requester: HumanWait.Requester(pid: child.processIdentifier, startTime: childStart),
        summary: "SSH as git to github.com", limit: .seconds(1_200), board: board
    )
    wait.notifyWaiting()

    let outcome = await offMainActor(timeoutSeconds: 30) { () -> String in
        let client = AgentClient(path: socketPath, serverTrustPolicy: .allowUnverifiedForTesting, liveness: liveness)
        do {
            let session = try client.beginOutputRedaction(destination: .aiTool, streams: [.stdout])
            let channel = try client.approvalNoticeChannel(for: session)
            let first = try channel.take()
            let second = try channel.take()
            refuse.value = true
            let refused: String
            do {
                _ = try channel.take()
                refused = "answered"
            } catch {
                refused = "threw"
            }
            let scanned = try session.process(Data("still scanning\n".utf8), stream: .stdout)
            let flushed = try session.finish(stream: .stdout)
            let text = String(decoding: scanned.data + flushed.data, as: UTF8.self)
            return "first=\(first.count):\(first.first ?? "") second=\(second.count) refused=\(refused) scanner=\(text)"
        } catch {
            return "threw: \(error)"
        }
    }
    check(outcome?.hasPrefix("first=1:waiting for approval on the Mac or iPhone: SSH as git to github.com.") == true
          && outcome?.contains(" second=0 ") == true,
          "notice channel: a waiting ssh under the csec ai is reported to it once (\(outcome ?? "nil"))")
    check(outcome?.contains("refused=threw scanner=still scanning\n") == true,
          "notice channel: a refused poll leaves the output scanner working (\(outcome ?? "nil"))")
    wait.finish()
}

// MARK: - The record

private func withdrawnRecordShapeTests() {
    check(DecisionLogRecord.kind(for: .timedOut) == .withdrawn
          && DecisionLogRecord.kind(for: .withdrawn) == .withdrawn
          && DecisionLogRecord.kind(for: .requesterGone) == .panel
          && DecisionLogRecord.kind(for: .human(decidedAt: .now)) == .panel,
          "record: only reviews that left without a decision before one was shown or answered are withdrawn")
    let timedOut = DecisionLogRecord.outcome(for: .timedOut)
    let withdrawn = DecisionLogRecord.outcome(for: .withdrawn)
    check(timedOut.outcome == .timedOut && timedOut.decider == nil
          && withdrawn.outcome == .requesterGone && withdrawn.decider == nil,
          "record: a timeout is timed_out and a queue withdrawal requester_gone, neither with a decider")
    let record = DecisionLogRecord(
        kind: .withdrawn, surface: .sshSigning, outcome: .timedOut,
        detail: "never shown; nobody answered within 20 minutes; waited 20m00s"
    )
    let encoded = try? JSONEncoder().encode(record)
    let text = encoded.map { String(decoding: $0, as: UTF8.self) } ?? ""
    check(text.contains("\"withdrawn\"") && text.contains("\"timed_out\""),
          "record: withdrawn and timed_out are written by those names")
    let decoded = encoded.flatMap { try? JSONDecoder().decode(DecisionLogRecord.self, from: $0) }
    check(decoded?.kind == .withdrawn && decoded?.outcome == .timedOut, "record: the new kind round-trips")
    check(record.displayLine().contains("withdrawn") && record.displayLine().contains("timed_out"),
          "record: csec log shows the kind and outcome")
}

// MARK: - The access path

private actor WaitFixtureProvider: SecretProvider {
    nonisolated let schemes: Set<String> = ["op"]
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        ResolvedSecret(value: Data("synthetic-wait-value".utf8), cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private func agentHumanWaitTests() async {
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let start = ProcessAncestry.startTime(of: me),
          let parent = ProcessAncestry.parent(of: me), parent > 1,
          let parentStart = ProcessAncestry.startTime(of: parent) else {
        check(false, "wait fixtures can read their own live ancestry")
        return
    }
    let caller = CallerInfo(pid: me, startTime: start, description: "synthetic wait caller")
    /// This test's parent reads as Claude Code (a coding agent's request) or
    /// as a terminal's shell (a terminal's request). The ancestry stops there,
    /// so a Claude Code running this suite is never seen above it.
    func inspection(agent: Bool) -> ProcessInspection {
        ProcessInspection(
            startTime: { ProcessAncestry.startTime(of: $0) },
            parent: { $0 == parent ? 1 : ProcessAncestry.parent(of: $0) },
            name: { $0 == parent ? (agent ? "claude" : "zsh") : ProcessAncestry.name(of: $0) },
            executablePath: { ProcessAncestry.executablePath(of: $0) },
            hasControllingTerminal: { !agent && $0 == parent }
        )
    }

    struct Harness {
        let agent: Agent
        let gate: GatedPolicyReview
        let accessQueue: ConsentQueue
        let board: HumanWaitBoard
        let log: DecisionLog
        let directory: String
    }
    func makeHarness(
        agent isAgent: Bool, limit: Duration,
        inspectionOverride: ProcessInspection? = nil,
        gate: GatedPolicyReview = GatedPolicyReview(),
        uiQueue: ConsentQueue = ConsentQueue()
    ) async -> Harness {
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(WaitFixtureProvider())
        let accessQueue = ConsentQueue()
        let board = HumanWaitBoard()
        let directory = NSTemporaryDirectory() + "cs-selftest-wait-\(UUID().uuidString.lowercased())"
        let log = DecisionLog(
            directory: SealedRecordDirectory(path: directory),
            stores: .processLocal(InMemoryProtectedItemBackend()),
            bootSessionUUID: "boot-wait"
        )
        _ = await log.open()
        let agent = Agent(
            resolver: resolver, grants: GrantTable(),
            consent: QueuedConsentProvider(underlying: AutoApproveConsent(), queue: uiQueue),
            policyReview: QueuedPolicyReview(underlying: gate, queue: uiQueue),
            allowUnverifiedPlansForTesting: true,
            processInspection: inspectionOverride ?? inspection(agent: isAgent),
            terminalInspection: .unavailable,
            accessConsentQueue: accessQueue, decisionLog: log,
            humanWaitBoard: board, approvalWaitLimit: { limit }
        )
        return Harness(agent: agent, gate: gate, accessQueue: accessQueue, board: board, log: log, directory: directory)
    }
    func ask(_ harness: Harness, _ reference: String, sink: RequestNoticeSink? = nil) -> Task<Response, Never> {
        let request = try! AccessRequest(
            references: [reference], reason: "wait fixture", ttlSeconds: 600,
            deliveryPlan: DeliveryPlan(
                mechanism: .unrestrictedInitialEnvironment,
                executable: PlannedExecutable(canonicalPath: "/usr/bin/env", assurance: .unverified),
                root: .caller, descendantScope: .subtree, destination: .localDevelopment,
                requestedTTLSeconds: 600, operationContext: "wait fixture",
                outputGuard: OutputGuardPlan(mode: .tty)
            )
        )
        let agent = harness.agent
        return Task {
            await RequestNotices.$sink.withValue(sink) {
                await agent.handle(request: request, caller: caller)
            }
        }
    }
    func withdrawnRecords(_ log: DecisionLog) async -> [DecisionLogRecord] {
        let page = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.withdrawn]))
        return page.records
    }

    func orphanTree() -> AnchorFixtureTree {
        AnchorFixtureTree(starts: [me: start, parent: parentStart],
                          parents: [me: parent, parent: 1], terminal: parent)
    }
    // One on screen and one on the access turn: both belong to the lost
    // parent, but a later request is not a propagated human Deny.
    do {
        let tree = orphanTree()
        let harness = await makeHarness(agent: false, limit: .seconds(30), inspectionOverride: tree.inspection)
        defer { try? FileManager.default.removeItem(atPath: harness.directory) }
        let first = ask(harness, "op://orphan/first/password")
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let second = ask(harness, "op://orphan/second/password")
        check(await eventuallyTrue { await harness.accessQueue.waitingCount == 1 },
              "orphan access: a second request waits on the access turn")
        tree.reparent(me)
        let results = [await first.value, await second.value]
        check(results.allSatisfy { $0.values == nil && $0.failure?.message.contains("original scope changed") == true },
              "orphan access: losing the parent withdraws both requests without delivery")
        let records = await harness.log.read(DecisionLogQuery(streams: [.decisions])) .records
        check(records.filter { $0.kind == .panel && $0.outcome == .requesterGone }.count == 1
              && records.filter { $0.kind == .withdrawn }.count == 1
              && records.allSatisfy { $0.detail?.contains("abandoned:") == true },
              "orphan access: shown and never-shown requests each log the abandonment once")
        await harness.gate.decideAll(.approve(nil))
        check(await ask(harness, "op://orphan/later/password").value.failure == nil,
              "orphan access: a subsequent live request is reviewed, not refused as a human Deny")
    }
    // A shared-UI queue withdrawal is never passed to a panel, even when its
    // requester remains alive through the recorded lineage.
    do {
        let tree = orphanTree(), queue = ConsentQueue()
        let held = try! await queue.acquire()
        let harness = await makeHarness(agent: false, limit: .seconds(30),
                                        inspectionOverride: tree.inspection, uiQueue: queue)
        defer { try? FileManager.default.removeItem(atPath: harness.directory) }
        let pending = ask(harness, "op://orphan/ui/password")
        check(await eventuallyTrue { await queue.waitingCount == 1 }, "orphan access: waits on the UI queue")
        tree.reparent(me)
        let result = await pending.value
        let records = await withdrawnRecords(harness.log)
        check(result.values == nil && records.count == 1 && records[0].outcome == .requesterGone
              && records[0].detail?.contains("never shown; abandoned:") == true,
              "orphan access: UI-queued withdrawal logs its cause and never-shown state")
        check(await harness.gate.reviews == 0, "orphan access: the UI-queued orphan is never presented")
        await held.release()
    }
    // The human may win just before the watcher polls: retain the approval
    // and explicitly report why it could not release or mint anything.
    do {
        let tree = orphanTree()
        let gate = GatedPolicyReview(onApproval: { tree.recycle(parent) })
        let harness = await makeHarness(agent: false, limit: .seconds(30),
                                        inspectionOverride: tree.inspection, gate: gate)
        defer { try? FileManager.default.removeItem(atPath: harness.directory) }
        let pending = ask(harness, "op://orphan/approved/password")
        _ = await eventuallyTrue { await gate.pendingCount == 1 }
        await gate.decide(.approve(nil))
        let result = await pending.value
        let records = await harness.log.read(DecisionLogQuery(streams: [.decisions])).records
        check(result.values == nil && records.map(\.kind) == [.panel, .deliveryFailed]
              && records.first?.outcome == .approved && records.first?.grantIDs == nil,
              "orphan access: a failed approved scope logs panel approval plus delivery_failed without minting")
    }

    // On screen: nobody answers, so at the deadline the panel is withdrawn
    // (the reviewer sees its request cancelled), the requester is told why,
    // and the log says withdrawn, timed out, shown.
    do {
        let harness = await makeHarness(agent: true, limit: .milliseconds(1_500))
        defer { try? FileManager.default.removeItem(atPath: harness.directory) }
        let notices = NoticeLog()
        let started = ContinuousClock.now
        let response = await ask(harness, "op://wait/on-screen/password", sink: notices.sink).value
        let elapsed = started.duration(to: .now)
        check(response.values == nil && response.failure?.code == .consentDenied
              && response.failure?.message.contains("nobody answered") == true,
              "deadline: an unanswered coding-agent request fails saying nobody answered (\(response.failure?.message ?? "nil"))")
        check(elapsed >= .milliseconds(1_450) && elapsed < .seconds(6),
              "deadline: it ends at its deadline (\(elapsed))")
        check(await harness.gate.cancelledReviews == 1, "deadline: the panel on screen is withdrawn")
        check(notices.all.count == 1 && notices.all.first?.contains("op://wait/on-screen/password") == true,
              "deadline: its session was told once, at once, what it waits for")
        let records = await withdrawnRecords(harness.log)
        check(records.count == 1 && records.first?.outcome == .timedOut
              && records.first?.decider == nil
              && records.first?.detail?.hasPrefix("shown, not answered; nobody answered within") == true,
              "deadline: logged as withdrawn, timed out, shown (\(records.map { $0.detail ?? "" }))")
        let panelPage = await harness.log.read(DecisionLogQuery(streams: [.decisions], kinds: [.panel]))
        let panels = panelPage.records
        check(panels.isEmpty, "deadline: a withdrawal is not logged as a panel outcome or a Deny")
        check(harness.board.count == 0, "deadline: the ended request leaves the board")
    }

    // Queued: three requests behind one unanswered panel all lapse on their
    // own clocks, together, not one per period.
    do {
        // Each request's wait is timed from its own ask. On their own clocks
        // all three wait about one limit. Served one per period, the second
        // and third would each start their limit only when the one before
        // lapsed, so the third would wait about three limits less the gap
        // between the first and third asks, which is under one limit because
        // both queued behind the first panel before it lapsed. Comparing the
        // waits with each other, not with the wall clock, keeps a loaded Mac's
        // slow start or late timers from reading as one per period.
        let limit = Duration.seconds(2)
        let harness = await makeHarness(agent: true, limit: limit)
        defer { try? FileManager.default.removeItem(atPath: harness.directory) }
        func timedAsk(_ reference: String) -> Task<(Response, Duration), Never> {
            let asked = ContinuousClock.now
            let pending = ask(harness, reference)
            return Task { (await pending.value, asked.duration(to: .now)) }
        }
        let first = timedAsk("op://wait/first/password")
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let second = timedAsk("op://wait/second/password")
        let third = timedAsk("op://wait/third/password")
        check(await eventuallyTrue { await harness.accessQueue.waitingCount == 2 },
              "deadline: two requests queue behind the unanswered panel")
        let outcomes = [await first.value, await second.value, await third.value]
        let responses = outcomes.map(\.0)
        let waits = outcomes.map(\.1)
        check(responses.allSatisfy { $0.values == nil && $0.failure?.message.contains("nobody answered") == true },
              "deadline: every queued request is withdrawn with the same explanation")
        check(waits.allSatisfy { $0 >= limit - .milliseconds(50) },
              "deadline: no queued request lapses before its own limit (\(waits))")
        let spread = (waits.max() ?? .zero) - (waits.min() ?? .zero)
        check(spread < limit,
              "deadline: queued requests lapse together on their own clocks (waits \(waits) for a limit of \(limit))")
        let records = await withdrawnRecords(harness.log)
        check(records.count == 3 && records.allSatisfy { $0.outcome == .timedOut },
              "deadline: each queued request is logged as withdrawn, timed out")
        check(records.contains { $0.detail?.hasPrefix("never shown;") == true },
              "deadline: a request that never reached the panel says never shown")
    }

    // A terminal's request has no deadline and hears nothing new.
    do {
        let harness = await makeHarness(agent: false, limit: .milliseconds(200))
        defer { try? FileManager.default.removeItem(atPath: harness.directory) }
        let notices = NoticeLog()
        let pending = ask(harness, "op://wait/terminal/password", sink: notices.sink)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        try? await Task.sleep(for: .milliseconds(700))
        let stillPending = await harness.gate.pendingCount
        let withdrawnPanels = await harness.gate.cancelledReviews
        check(stillPending == 1 && withdrawnPanels == 0,
              "terminal: a terminal's request keeps waiting past the coding-agent limit")
        await harness.gate.decide(.approve(nil))
        check(await pending.value.values != nil, "terminal: and is released when the human approves")
        check(notices.all.isEmpty, "terminal: a terminal's request gets no waiting notice")
    }

    // Answered in time: the approval stands, with no withdrawal.
    do {
        let harness = await makeHarness(agent: true, limit: .seconds(30))
        defer { try? FileManager.default.removeItem(atPath: harness.directory) }
        let pending = ask(harness, "op://wait/answered/password")
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        await harness.gate.decide(.approve(nil))
        check(await pending.value.values != nil, "deadline: a request answered in time is released")
        check(await withdrawnRecords(harness.log).isEmpty, "deadline: an answered request is not withdrawn")
    }

    // With no notice channel (an `ssh`, a bridge client), the wait goes on
    // the board for the `csec ai` above it, once per session.
    do {
        let harness = await makeHarness(agent: true, limit: .seconds(30))
        defer { try? FileManager.default.removeItem(atPath: harness.directory) }
        let pending = ask(harness, "op://wait/board/password")
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let live = ProcessInspection.live
        let firstTake = harness.board.take(
            forSession: "session-a", ancestorPID: parent, ancestorStartTime: parentStart, inspection: live
        )
        let secondTake = harness.board.take(
            forSession: "session-a", ancestorPID: parent, ancestorStartTime: parentStart, inspection: live
        )
        let otherSession = harness.board.take(
            forSession: "session-b", ancestorPID: parent, ancestorStartTime: parentStart, inspection: live
        )
        let unrelated = harness.board.take(
            forSession: "session-c", ancestorPID: 1, ancestorStartTime: 1, inspection: live
        )
        check(firstTake.count == 1 && firstTake.first?.contains("op://wait/board/password") == true,
              "board: the csec ai above a waiting request gets its notice")
        check(secondTake.isEmpty && otherSession.count == 1,
              "board: each session gets each notice once")
        check(unrelated.isEmpty, "board: a process not above the request gets nothing")
        await harness.gate.decide(.approve(nil))
        _ = await pending.value
        check(harness.board.count == 0, "board: an answered request leaves the board")
    }
}
