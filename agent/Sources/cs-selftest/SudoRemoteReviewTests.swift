import CryptoKit
import CSECRemoteApproval
import CSecuritySupport
import ConvenientSecurity
import Darwin
import Foundation

// The sudo review mirrored to the paired phone (csec-vo4.17). The helper races
// its Mac panel against one `sudo_remote_review` request to csecd; csecd takes
// that request only from the sudo review helper's code identity, mirrors a v3
// review of kind `sudo`, and answers approved, denied or unavailable. Every
// phone here is a fake or a synthetic software key; every socket is a private
// temporary one; no real csecd, relay or panel is involved.

// MARK: - Fixtures

private let sudoFixtureCommand = "sudo /usr/bin/true --api-key \"[csec:secret-like]\" safe"
private let sudoFixtureSummary = "iTerm2 · “deploy — ~/project” · window 1, tab 2 · ttys001"

private func sudoRequestFixture(
    command: String = sudoFixtureCommand,
    terminal: String = "/dev/ttys001",
    terminalSummary: String? = sudoFixtureSummary
) -> SudoRemoteReviewRequest {
    SudoRemoteReviewRequest(
        command: command,
        workingDirectory: "/Users/example/project",
        terminal: terminal,
        terminalSummary: terminalSummary
    )
}

private let sudoFixtureRequester = SudoReviewRequester(pid: 6001, name: "sudo")

private func sudoHelperCaller(pid: pid_t = 4242, startTime: UInt64 = 1_700_000_000_000_001) -> CallerInfo {
    CallerInfo(pid: pid, startTime: startTime, description: "csec-sudo-review (pid \(pid))")
}

/// A remote provider standing in for `RemoteApprovalManager`: it answers
/// readiness as told, records what it was asked to publish, and decides at
/// once, or when `answer(_:)` is called, or never (until it is withdrawn).
private actor ScriptedSudoPhone: RemoteAccessPolicyReviewProvider {
    enum Answer: Sendable { case approve, deny, unavailable }

    private let ready: Bool
    private var pending: Answer?
    private(set) var readinessQueries: [[String]] = []
    private(set) var published: [RemoteApprovalReview] = []
    private(set) var unlockRequested: [RemoteUnlockUse] = []
    private(set) var withdrawals = 0

    init(ready: Bool = true, immediately answer: Answer? = nil) {
        self.ready = ready
        self.pending = answer
    }

    func answer(_ answer: Answer) { pending = answer }

    func remoteReadiness(
        for references: [SecretRef], restoring: [SecretRef]
    ) async -> RemoteReviewReadiness {
        readinessQueries.append((references + restoring).map(\.uri))
        return ready ? .ready(unlock: .notNeeded) : .unavailable
    }

    func reviewRemoteAccess(
        _ review: RemoteApprovalReview, unlock: RemoteUnlockUse
    ) async -> RemoteAccessReviewResult {
        published.append(review)
        unlockRequested.append(unlock)
        while true {
            if Task.isCancelled {
                withdrawals += 1
                return .unavailable
            }
            if let answer = pending {
                switch answer {
                case .approve:
                    // As the phone app signs it: the card showed the line
                    // exactly when the shared rule says it applies.
                    return .approved(
                        selection: RemoteApprovalSelection(
                            scopeOptionID: nil, durationIndex: nil, unlockAnswer: nil,
                            pairingLineShown: review.pairingLineApplies(scopeID: nil, durationIndex: nil)
                        ),
                        unlock: nil
                    )
                case .deny:
                    return .denied(receivedAt: .now)
                case .unavailable:
                    return .unavailable
                }
            }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }
}

private final class SudoRecordedDecisions: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [DecisionLogRecord] = []
    func append(_ record: DecisionLogRecord) { lock.lock(); stored.append(record); lock.unlock() }
    var all: [DecisionLogRecord] { lock.lock(); defer { lock.unlock() }; return stored }
}

private func sudoService(
    _ phone: ScriptedSudoPhone,
    records: SudoRecordedDecisions = SudoRecordedDecisions(),
    allowUnverified: Bool = true,
    requester: SudoReviewRequester? = sudoFixtureRequester,
    note: SudoDelegationNote? = nil,
    paired: SudoPairingRecords = SudoPairingRecords()
) -> SudoRemoteReviewService {
    SudoRemoteReviewService(
        remote: phone,
        record: { records.append($0) },
        allowUnverifiedCallersForTesting: allowUnverified,
        requester: { _ in requester },
        note: { _ in note },
        recordPairing: { paired.append($0) },
        log: { _ in }
    )
}

private final class SudoPairingRecords: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [CallerInfo] = []
    func append(_ caller: CallerInfo) { lock.lock(); stored.append(caller); lock.unlock() }
    var all: [CallerInfo] { lock.lock(); defer { lock.unlock() }; return stored }
}

/// A stand-in for the helper's Mac panel: it opens when the race starts and
/// stays up until `decide(_:)` or until the race cancels it, which closes it
/// as the real panel closes (`.usePassword`, recorded as closed).
private actor FakeSudoPanel {
    private var decision: SudoAuthorizationReviewOutcome?
    private(set) var openedAt: ContinuousClock.Instant?
    private(set) var closedByCancellation = false

    func decide(_ outcome: SudoAuthorizationReviewOutcome) { decision = outcome }

    func present() async -> SudoAuthorizationReviewOutcome {
        openedAt = .now
        while true {
            if Task.isCancelled {
                closedByCancellation = true
                return .usePassword
            }
            if let decision { return decision }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }
}

private func sudoEventually(seconds: Double, _ condition: @Sendable () async -> Bool) async -> Bool {
    let deadline = ContinuousClock.now + .milliseconds(Int(seconds * 1_000))
    while ContinuousClock.now < deadline {
        if await condition() { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return await condition()
}

private func sudoSocketDirectory(_ tag: String) -> URL? {
    let base = URL(fileURLWithPath: "/tmp")
        .appendingPathComponent("cs-sudo-\(tag)-\(UUID().uuidString.prefix(8))", isDirectory: true)
    do {
        try FileManager.default.createDirectory(
            atPath: base.path, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        return base
    } catch {
        check(false, "sudo remote: temp socket directory setup threw (\(error))")
        return nil
    }
}

private func sudoWaitForSocket(_ path: String) -> Bool {
    var waited = 0
    while !FileManager.default.fileExists(atPath: path) && waited < 400 {
        usleep(10_000)
        waited += 1
    }
    return FileManager.default.fileExists(atPath: path)
}

private final class SudoHandlerCount: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.lock(); count += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
}

private let sudoTestLiveness = AgentLiveness.forTesting(silenceDeadline: 5)

/// A csecd stand-in on a private socket: the real `SocketServer` with the
/// given trust policy, routing `sudo_remote_review` to a real
/// `SudoRemoteReviewService` over `phone`. Returns the socket path.
private func startSudoServer(
    _ tag: String,
    policy: SocketPeerTrustPolicy,
    service: SudoRemoteReviewService,
    handled: SudoHandlerCount = SudoHandlerCount()
) -> (path: String, directory: URL)? {
    guard let base = sudoSocketDirectory(tag) else { return nil }
    let path = base.appendingPathComponent("agent.sock").path
    let server = SocketServer(path: path, clientTrustPolicy: policy, liveness: sudoTestLiveness) {
        request, caller in
        handled.increment()
        switch request {
        case let .sudoRemoteReview(review):
            return await service.handle(review, caller: caller)
        case .schemes:
            return Response(schemes: ["op"])
        default:
            return .failed(.invalidRequest, message: "not part of the sudo remote review check")
        }
    }
    Thread.detachNewThread { try? server.run() }
    guard sudoWaitForSocket(path) else {
        check(false, "sudo remote: the \(tag) server never bound its socket")
        try? FileManager.default.removeItem(at: base)
        return nil
    }
    return (path, base)
}

/// One raw request/response on `path`, read on a helper thread.
private func sudoRawExchange(_ path: String, _ request: Request) async -> Response? {
    await withCheckedContinuation { continuation in
        Thread.detachNewThread {
            let fd = path.withCString { cs_connect_unix($0) }
            guard fd >= 0 else { continuation.resume(returning: nil); return }
            defer { close(fd) }
            guard let encoded = try? WireTransport.encodeRequest(request, supportsHeartbeats: false),
                  writeFrame(fd, encoded),
                  case let .frame(data) = readFrame(fd, silence: 10) else {
                continuation.resume(returning: nil)
                return
            }
            continuation.resume(returning: try? JSONDecoder().decode(Response.self, from: data))
        }
    }
}

// MARK: - Suite

func sudoRemoteReviewTests() async {
    print("\n# Sudo review on the paired phone: the sudo_remote_review wire")
    sudoRemoteWireTests()
    print("\n# Sudo review on the paired phone: only the sudo review helper may ask, and only that")
    sudoRemoteRoleGateTests()
    await sudoRemoteRoleGateServerTests()
    print("\n# Sudo review: csecd names the terminal tab, the helper sends no Apple event")
    await sudoTerminalClientTests()
    print("\n# Sudo review on the paired phone: the review csecd mirrors")
    sudoRemoteReviewConstructionTests()
    print("\n# Sudo review on the paired phone: csecd's answer and the decision log")
    await sudoRemoteServiceTests()
    await sudoRemoteRealDecisionLogTests()
    await sudoRemoteSignedExchangeTests()
    print("\n# Sudo review on the paired phone: the helper races its panel against the phone")
    await sudoRemoteRaceTests()
    await sudoReviewWithoutTouchIDTests()
    sudoReviewLogTests()
    print("\n# Sudo review on the paired phone: helper to csecd, through the socket")
    await sudoRemoteEndToEndTests()
    await sudoReviewEndTests()
    #if DEBUG
    await sudoRemoteHelperProbeTests()
    #endif
}

// MARK: - Wire

private func sudoRemoteWireTests() {
    let request = sudoRequestFixture()
    check(request.isWellFormed, "sudo remote wire: the fixture request is well formed")
    do {
        let encoded = try WireTransport.encodeRequest(.sudoRemoteReview(request), supportsHeartbeats: true)
        let decoded = try JSONDecoder().decode(Request.self, from: encoded)
        if case let .sudoRemoteReview(roundTripped) = decoded {
            check(roundTripped == request, "sudo remote wire: a request round-trips through the Request coder")
        } else {
            check(false, "sudo remote wire: a request round-trips through the Request coder (decoded another case)")
        }
        let object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
        check(object?["type"] as? String == "sudo_remote_review"
                && object?["requestID"] as? String == request.requestID
                && object?["sudoReview"] is [String: Any],
              "sudo remote wire: the frame is type sudo_remote_review with its requestID and a sudoReview object")
    } catch {
        check(false, "sudo remote wire: encoding and decoding a request threw (\(error))")
    }

    func decodes(_ mutate: (inout [String: Any]) -> Void) -> Bool {
        guard let encoded = try? WireTransport.encodeRequest(.sudoRemoteReview(request), supportsHeartbeats: false),
              var object = try? JSONSerialization.jsonObject(with: encoded) as? [String: Any] else { return true }
        mutate(&object)
        guard let data = try? JSONSerialization.data(withJSONObject: object) else { return true }
        return (try? JSONDecoder().decode(Request.self, from: data)) != nil
    }
    func review(_ change: @escaping (inout [String: Any]) -> Void) -> (inout [String: Any]) -> Void {
        { object in
            var inner = object["sudoReview"] as? [String: Any] ?? [:]
            change(&inner)
            object["sudoReview"] = inner
        }
    }
    check(!decodes { $0["requestID"] = UUID().uuidString.lowercased() },
          "sudo remote wire: a frame whose requestID differs from the review's is refused")
    check(!decodes(review { $0["command"] = "" }), "sudo remote wire: an empty command is refused")
    check(!decodes(review { $0["command"] = String(repeating: "a", count: SudoRemoteReviewRequest.maximumCommandBytes + 1) }),
          "sudo remote wire: a command over its bound is refused")
    check(!decodes(review { $0["workingDirectory"] = "/Users/x\u{0}/y" }),
          "sudo remote wire: a NUL in the working directory is refused")
    check(!decodes(review { $0["targetUser"] = String(repeating: "u", count: SudoRemoteReviewRequest.maximumTargetUserBytes + 1) }),
          "sudo remote wire: a target user over its bound is refused")
    check(!decodes(review { $0["requestID"] = "not-a-uuid" }),
          "sudo remote wire: a review requestID that is not a lowercase UUID is refused")
    check(decodes(review { $0["terminalSummary"] = nil }),
          "sudo remote wire: a request without a resolved terminal tab still decodes")

    // The response carries the decision in its own field, and a csecd reply
    // without it (every other request) decodes as none.
    for decision in [SudoRemoteReviewDecision.approved, .denied, .unavailable] {
        let response = Response(requestID: request.requestID, sudoRemoteReview: decision)
        let decoded = (try? JSONEncoder().encode(response)).flatMap {
            try? JSONDecoder().decode(Response.self, from: $0)
        }
        check(decoded?.sudoRemoteReview == decision && decoded?.requestID == request.requestID,
              "sudo remote wire: a \(decision.rawValue) answer round-trips in the response")
    }
    let plain = (try? JSONEncoder().encode(Response(schemes: ["op"]))).flatMap {
        try? JSONDecoder().decode(Response.self, from: $0)
    }
    check(plain != nil && plain?.sudoRemoteReview == nil,
          "sudo remote wire: a response to any other request carries no sudo answer")

    check(Request.sudoRemoteReview(request).isSudoRemoteReview && !Request.schemes.isSudoRemoteReview
            && !Request.capabilities.isSudoRemoteReview,
          "sudo remote wire: only sudo_remote_review is the sudo helper's phone request")

    // The delegation question and the pairing report.
    let question = SudoDelegationRequest(command: sudoFixtureCommand)
    let report = SudoPairingRequest()
    for (label, sent, type, key) in [
        ("sudo_delegation", Request.sudoDelegation(question), "sudo_delegation", "sudoDelegation"),
        ("sudo_pairing", Request.sudoPairing(report), "sudo_pairing", "sudoPairing"),
    ] {
        guard let encoded = try? WireTransport.encodeRequest(sent, supportsHeartbeats: false),
              let decoded = try? JSONDecoder().decode(Request.self, from: encoded),
              let object = try? JSONSerialization.jsonObject(with: encoded) as? [String: Any] else {
            check(false, "sudo delegation wire: \(label) round-trips")
            continue
        }
        let same: Bool
        switch (sent, decoded) {
        case let (.sudoDelegation(a), .sudoDelegation(b)): same = a == b
        case let (.sudoPairing(a), .sudoPairing(b)): same = a == b
        default: same = false
        }
        check(same && object["type"] as? String == type && object[key] is [String: Any] && decoded.isSudoDelegation,
              "sudo delegation wire: \(label) round-trips as its own type, and is the helper's delegation request")
        var mismatched = object
        mismatched["requestID"] = UUID().uuidString.lowercased()
        check((try? JSONSerialization.data(withJSONObject: mismatched)).flatMap { try? JSONDecoder().decode(Request.self, from: $0) } == nil,
              "sudo delegation wire: a \(label) frame whose requestID differs from its body's is refused")
    }
    // The terminal question carries nothing to look up: csecd answers for
    // the helper that asked.
    let terminalQuestion = SudoTerminalRequest()
    if let encoded = try? WireTransport.encodeRequest(.sudoTerminal(terminalQuestion), supportsHeartbeats: false),
       let decoded = try? JSONDecoder().decode(Request.self, from: encoded),
       let object = try? JSONSerialization.jsonObject(with: encoded) as? [String: Any] {
        let same: Bool
        if case let .sudoTerminal(received) = decoded { same = received == terminalQuestion } else { same = false }
        check(same && object["type"] as? String == "sudo_terminal"
                && (object["sudoTerminal"] as? [String: Any])?.keys.sorted() == ["requestID"]
                && decoded.isSudoTerminal && !decoded.isSudoDelegation && !decoded.isSudoRemoteReview,
              "sudo terminal wire: sudo_terminal round-trips as its own type, carrying only its requestID")
        var mismatched = object
        mismatched["requestID"] = UUID().uuidString.lowercased()
        check((try? JSONSerialization.data(withJSONObject: mismatched)).flatMap { try? JSONDecoder().decode(Request.self, from: $0) } == nil,
              "sudo terminal wire: a sudo_terminal frame whose requestID differs from its body's is refused")
    } else {
        check(false, "sudo terminal wire: sudo_terminal round-trips")
    }
    let named = TerminalSessionContext(application: "iTerm2", title: "deploy", windowIndex: 1, tabIndex: 2, tty: "ttys012")
    let carried = (try? JSONEncoder().encode(Response(requestID: terminalQuestion.requestID, sudoTerminal: named)))
        .flatMap { try? JSONDecoder().decode(Response.self, from: $0) }
    check(carried?.sudoTerminal == named && plain?.sudoTerminal == nil,
          "sudo terminal wire: csecd's tab round-trips in the response, and no other response carries one")
    check(!Request.schemes.isSudoTerminal && !Request.sudoPairing(SudoPairingRequest()).isSudoTerminal,
          "sudo terminal wire: only sudo_terminal is the helper's terminal question")

    check(!SudoDelegationRequest(command: "").isWellFormed
            && !SudoDelegationRequest(command: String(repeating: "a", count: SudoRemoteReviewRequest.maximumCommandBytes + 1)).isWellFormed,
          "sudo delegation wire: an empty or over-long command is refused")
    for answer in [
        SudoDelegationAnswer(decision: .approved),
        SudoDelegationAnswer(decision: .declined, note: "Auto mode didn't approve this: x", pairingLine: "Approving also …"),
        SudoDelegationAnswer.notApplicable,
    ] {
        let decoded = (try? JSONEncoder().encode(Response(requestID: question.requestID, sudoDelegation: answer)))
            .flatMap { try? JSONDecoder().decode(Response.self, from: $0) }
        check(decoded?.sudoDelegation == answer && answer.isWellFormed,
              "sudo delegation wire: a \(answer.decision.rawValue) answer round-trips in the response")
    }
    check(SudoDelegationAnswer(decision: .approved, note: "x", pairingLine: "y").note == nil
            && SudoDelegationAnswer(decision: .approved, note: "x", pairingLine: "y").pairingLine == nil,
          "sudo delegation wire: only a decline carries a note or a line")

    // The helper's own request copies its panel's facts and the tab it resolved.
    let panel = SudoAuthorizationReviewRequest(
        submittedCommand: sudoFixtureCommand, workingDirectory: "/Users/example/project", terminal: "/dev/ttys001"
    )
    let tab = TerminalSessionContext(application: "iTerm2", title: "deploy", location: "window 1, tab 2", tty: "ttys001")
    let fromPanel = SudoRemoteReviewRequest(panel, terminal: tab)
    check(fromPanel.command == panel.submittedCommand && fromPanel.workingDirectory == panel.workingDirectory
            && fromPanel.terminal == panel.terminal && fromPanel.terminalSummary == tab.summary
            && fromPanel.targetUser == nil && fromPanel.isWellFormed,
          "sudo remote wire: the helper's request is its panel's command, directory, tty and terminal tab")
    check(SudoRemoteReviewRequest(panel, terminal: tab).requestID != fromPanel.requestID,
          "sudo remote wire: every helper request has its own requestID")
}

// MARK: - Role gate

private func sudoRemoteRoleGateTests() {
    typealias Identity = ProductCodeIdentity
    check(Identity.metadataRole(
        identifier: Identity.sudoReviewHelperIdentifier, teamIdentifier: Identity.teamIdentifier, signatureValid: true
    ) == .sudoReviewHelper, "sudo remote gate: the exact helper identity from the product team is the sudo review helper")
    check(Identity.metadataRole(
        identifier: Identity.sudoReviewHelperIdentifier, teamIdentifier: "ATTACKERTEAM", signatureValid: true
    ) == .other, "sudo remote gate: the helper identifier signed by another team is not the helper")
    check(Identity.metadataRole(
        identifier: Identity.sudoReviewHelperIdentifier, teamIdentifier: nil, signatureValid: true
    ) == .other, "sudo remote gate: an ad-hoc signature (no team) is not the helper")
    check(Identity.metadataRole(
        identifier: Identity.sudoReviewHelperIdentifier, teamIdentifier: Identity.teamIdentifier,
        signatureValid: true, hardenedRuntime: false
    ) == .other, "sudo remote gate: the helper without hardened runtime is not the helper")
    check(Identity.metadataRole(
        identifier: Identity.sudoReviewHelperIdentifier, teamIdentifier: Identity.teamIdentifier,
        signatureValid: true, dangerousEntitlements: ["com.apple.security.get-task-allow"]
    ) == .other, "sudo remote gate: the helper with a weakening entitlement is not the helper")
    check(Identity.metadataRole(
        identifier: Identity.sudoReviewHelperIdentifier, teamIdentifier: Identity.teamIdentifier, signatureValid: false
    ) == .other, "sudo remote gate: an invalid signature is not the helper")

    check(SocketPeerTrustPolicy.admits(role: .launcher) && SocketPeerTrustPolicy.admits(role: .sudoReviewHelper)
            && !SocketPeerTrustPolicy.admits(role: .agent) && !SocketPeerTrustPolicy.admits(role: .rootHelper)
            && !SocketPeerTrustPolicy.admits(role: .other),
          "sudo remote gate: csecd admits the launcher and the sudo review helper, and no other role")

    let sudo = Request.sudoRemoteReview(sudoRequestFixture())
    // A v1 access frame, as an old client would send it.
    let legacyFrame = "{\"type\":\"access\",\"references\":[\"op://Vault/Item/password\"],"
        + "\"reason\":\"test\",\"ttlSeconds\":60}"
    guard let legacyAccess = try? JSONDecoder().decode(Request.self, from: Data(legacyFrame.utf8)) else {
        check(false, "sudo remote gate: a legacy access frame decodes")
        return
    }
    let others: [(String, Request)] = [
        ("schemes", .schemes),
        ("capabilities", .capabilities),
        ("access", legacyAccess),
        ("grants", .grants(GrantsRequest(action: .list))),
        ("remote approval status", .configureRemoteApproval(RemoteApprovalConfigurationRequest(action: .status))),
        ("decision log", .decisionLog(DecisionLogRequest(action: .status))),
        ("begin session", .beginSession(BeginSessionRequest())),
        ("uninstall", .uninstallCleanup(UninstallCleanupRequest())),
    ]
    check(SocketPeerTrustPolicy.permits(sudo, role: .sudoReviewHelper),
          "sudo remote gate: the sudo review helper may send sudo_remote_review")
    for (name, request) in [
        ("sudo_delegation", Request.sudoDelegation(SudoDelegationRequest(command: sudoFixtureCommand))),
        ("sudo_pairing", Request.sudoPairing(SudoPairingRequest())),
        ("sudo_terminal", Request.sudoTerminal(SudoTerminalRequest())),
        ("sudo_review_end", Request.sudoReviewEnd(
            SudoReviewEndRequest(outcome: .timedOut, command: sudoFixtureCommand, terminal: "/dev/ttys001"))),
    ] {
        check(SocketPeerTrustPolicy.permits(request, role: .sudoReviewHelper)
                && !SocketPeerTrustPolicy.permits(request, role: .launcher)
                && !ProductCodeRole.allCases.contains { $0 != .sudoReviewHelper && SocketPeerTrustPolicy.permits(request, role: $0) },
              "sudo remote gate: only the sudo review helper may send \(name)")
    }
    for (name, request) in others {
        check(!SocketPeerTrustPolicy.permits(request, role: .sudoReviewHelper),
              "sudo remote gate: the sudo review helper may not send \(name)")
        check(SocketPeerTrustPolicy.permits(request, role: .launcher),
              "sudo remote gate: the launcher may still send \(name)")
    }
    check(!SocketPeerTrustPolicy.permits(sudo, role: .launcher),
          "sudo remote gate: the launcher may not send sudo_remote_review")
    for role in ProductCodeRole.allCases where role != .launcher && role != .sudoReviewHelper {
        check(!SocketPeerTrustPolicy.permits(sudo, role: role)
                && !others.contains { SocketPeerTrustPolicy.permits($0.1, role: role) },
              "sudo remote gate: a \(role.rawValue) peer may send nothing at all")
    }
}

/// The gate as the real server applies it: a refused request is answered
/// `unverified_peer` and never reaches the handler, so nothing is published.
private func sudoRemoteRoleGateServerTests() async {
    // The helper's role: sudo_remote_review reaches the phone; anything else
    // is refused before the handler runs.
    do {
        let phone = ScriptedSudoPhone(immediately: .approve)
        let handled = SudoHandlerCount()
        guard let server = startSudoServer(
            "gate-helper", policy: .assumeRoleForTesting(.sudoReviewHelper),
            service: sudoService(phone), handled: handled
        ) else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }

        let refused = await sudoRawExchange(server.path, .schemes)
        check(refused?.failure?.code == .unverifiedPeer && refused?.schemes == nil && handled.value == 0,
              "sudo remote gate: the server refuses any other request from the sudo review helper before its handler runs")
        let client = SudoRemoteReviewClient(
            path: server.path, serverTrustPolicy: .allowUnverifiedForTesting, liveness: sudoTestLiveness
        )
        let decision = await client.review(sudoRequestFixture())
        let publishedCount = await phone.published.count
        check(decision == .approved && handled.value == 1 && publishedCount == 1,
              "sudo remote gate: the server passes the sudo review helper's sudo_remote_review through to the phone")
    }
    // The launcher's role: sudo_remote_review is refused before the handler
    // runs, so the phone is never asked.
    do {
        let phone = ScriptedSudoPhone(immediately: .approve)
        let handled = SudoHandlerCount()
        guard let server = startSudoServer(
            "gate-launcher", policy: .assumeRoleForTesting(.launcher),
            service: sudoService(phone), handled: handled
        ) else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }

        let raw = await sudoRawExchange(server.path, .sudoRemoteReview(sudoRequestFixture()))
        check(raw?.failure?.code == .unverifiedPeer && raw?.sudoRemoteReview == nil,
              "sudo remote gate: the server answers a launcher's sudo_remote_review with unverified_peer")
        let client = SudoRemoteReviewClient(
            path: server.path, serverTrustPolicy: .allowUnverifiedForTesting, liveness: sudoTestLiveness
        )
        let decision = await client.review(sudoRequestFixture())
        let schemes = await sudoRawExchange(server.path, .schemes)
        let nothingPublished = await phone.published.isEmpty
        let nothingAsked = await phone.readinessQueries.isEmpty
        check(decision == .unavailable && nothingPublished && nothingAsked,
              "sudo remote gate: a launcher's sudo_remote_review never reaches the phone, and the helper reads it as unavailable")
        check(schemes?.schemes == ["op"] && handled.value == 1,
              "sudo remote gate: the launcher's other requests still reach the handler")
    }
}

// MARK: - The terminal tab

/// A csecd stand-in that answers `sudo_terminal` after `delay`, with `answer`,
/// counting the requests that reached it and the callers they came from.
private func startSudoTerminalServer(
    _ tag: String, policy: SocketPeerTrustPolicy, answer: TerminalSessionContext?,
    delay: Duration = .zero, handled: SudoHandlerCount, callers: SudoTerminalCallers
) -> (path: String, directory: URL)? {
    guard let base = sudoSocketDirectory(tag) else { return nil }
    let path = base.appendingPathComponent("agent.sock").path
    let server = SocketServer(path: path, clientTrustPolicy: policy, liveness: sudoTestLiveness) {
        request, caller in
        handled.increment()
        guard case let .sudoTerminal(question) = request else {
            return .failed(.invalidRequest, message: "not part of the sudo terminal check")
        }
        await callers.record(caller.pid)
        try? await Task.sleep(for: delay)
        return Response(requestID: question.requestID, sudoTerminal: answer)
    }
    Thread.detachNewThread { try? server.run() }
    guard sudoWaitForSocket(path) else {
        check(false, "sudo terminal: the \(tag) server never bound its socket")
        try? FileManager.default.removeItem(at: base)
        return nil
    }
    return (path, base)
}

private actor SudoTerminalCallers {
    private(set) var pids: [pid_t] = []
    func record(_ pid: pid_t) { pids.append(pid) }
}

private func sudoTerminalClientTests() async {
    let tab = TerminalSessionContext(
        application: "iTerm2", title: "deploy", windowIndex: 1, tabIndex: 2, tty: "ttys012"
    )
    do {
        let handled = SudoHandlerCount()
        let callers = SudoTerminalCallers()
        guard let server = startSudoTerminalServer(
            "term-helper", policy: .assumeRoleForTesting(.sudoReviewHelper), answer: tab,
            handled: handled, callers: callers
        ) else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }
        let client = SudoDelegationClient(path: server.path, serverTrustPolicy: .allowUnverifiedForTesting)
        let answered = await client.terminal()
        let asked = await callers.pids
        check(answered == tab && handled.value == 1 && asked == [getpid()],
              "sudo terminal: the helper takes csecd's tab, which csecd looked up for the helper's own process")
    }
    do {
        let handled = SudoHandlerCount()
        guard let server = startSudoTerminalServer(
            "term-launcher", policy: .assumeRoleForTesting(.launcher), answer: tab,
            handled: handled, callers: SudoTerminalCallers()
        ) else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }
        let answered = await SudoDelegationClient(path: server.path, serverTrustPolicy: .allowUnverifiedForTesting)
            .terminal()
        check(answered == nil && handled.value == 0,
              "sudo terminal: csecd refuses sudo_terminal from the launcher before any lookup")
    }
    do {
        let handled = SudoHandlerCount()
        guard let server = startSudoTerminalServer(
            "term-silent", policy: .assumeRoleForTesting(.sudoReviewHelper), answer: nil,
            handled: handled, callers: SudoTerminalCallers()
        ) else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }
        let answered = await SudoDelegationClient(path: server.path, serverTrustPolicy: .allowUnverifiedForTesting)
            .terminal()
        check(answered == nil && handled.value == 1,
              "sudo terminal: a csecd that names no tab leaves the panel the PAM tty")
    }
    do {
        let handled = SudoHandlerCount()
        guard let server = startSudoTerminalServer(
            "term-slow", policy: .assumeRoleForTesting(.sudoReviewHelper), answer: tab, delay: .seconds(5),
            handled: handled, callers: SudoTerminalCallers()
        ) else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }
        let started = ContinuousClock.now
        let answered = await SudoDelegationClient(
            path: server.path, serverTrustPolicy: .allowUnverifiedForTesting, terminalDeadline: .milliseconds(300)
        ).terminal()
        let waited = ContinuousClock.now - started
        check(answered == nil && waited < .seconds(2),
              "sudo terminal: a csecd slower than the bound leaves the panel the PAM tty, on time (\(waited))")
    }
    let nowhere = await SudoDelegationClient(
        path: "/tmp/cs-sudo-term-none-\(UUID().uuidString.prefix(8))/agent.sock",
        serverTrustPolicy: .allowUnverifiedForTesting
    ).terminal()
    check(nowhere == nil, "sudo terminal: with no csecd the panel names the PAM tty")
    check(SudoDelegationClient.terminalDeadline > .milliseconds(Int(TerminalTitleQuery.timeout * 1_000)),
          "sudo terminal: the helper waits longer than csecd's own title-query bound")
}

// MARK: - Review construction

private func sudoRemoteReviewConstructionTests() {
    let request = sudoRequestFixture()
    let review: RemoteApprovalReview
    do {
        review = try RemoteApprovalReview(
            sudo: request, helperPID: 4242, helperStartTime: 17, requester: sudoFixtureRequester
        )
    } catch {
        check(false, "sudo remote review: the fixture builds a valid review (\(error))")
        return
    }
    check(review.kind == .sudo, "sudo remote review: the kind is sudo")
    check(review.headline == sudoFixtureCommand,
          "sudo remote review: the headline is `sudo` and the redacted submitted command")
    check(review.sudo == RemoteApprovalReview.Sudo(
        command: "/usr/bin/true --api-key \"[csec:secret-like]\" safe",
        workingDirectory: "/Users/example/project",
        targetUser: nil
    ), "sudo remote review: the sudo facts are the command after sudo, the directory, and no target user it cannot know")
    check(review.callerDescription == "sudo (pid 6001) on ttys001",
          "sudo remote review: the caller names sudo as the kernel names the helper's parent, and the terminal")
    check(review.terminalDescription == sudoFixtureSummary,
          "sudo remote review: the terminal line is the tab the helper resolved")
    check(review.secrets.isEmpty && review.delivery == nil && review.ssh == nil && review.restore == nil,
          "sudo remote review: no credentials, no delivery, no SSH or restore facts")
    check(review.scopeOptions.isEmpty && review.defaultScopeID == nil
            && review.durationOptions.isEmpty && review.defaultDurationIndex == nil,
          "sudo remote review: no scope or lifetime choice: it approves one sudo authentication")
    check(review.footnote == RemoteApprovalReview.sudoFootnote
            && review.footnote?.contains("this one sudo authentication") == true
            && review.footnote?.contains("root") == true
            && review.footnote?.contains("password prompt") == true,
          "sudo remote review: the footnote says one sudo authentication as root, and that Deny falls back to the password prompt")
    check(review.warnings == [RemoteApprovalReview.sudoWarning],
          "sudo remote review: the administrator banner travels as the one warning")
    check(review.referenceSetDigest == Data(SHA256.hash(data: Data("csec.remote-approval.references.v1".utf8))),
          "sudo remote review: the reference-set digest is the empty set's")
    check((try? review.validate()) != nil, "sudo remote review: the review passes v3 validation")
    check(review.operationDigest == RemoteApprovalReview.sudoOperationDigest(
        request, helperPID: 4242, helperStartTime: 17
    ), "sudo remote review: the operation digest is the sudo operation digest of this helper")

    // The operation digest binds this one invocation.
    let digest = RemoteApprovalReview.sudoOperationDigest
    let base = digest(request, 4242, 17)
    check(base.count == SHA256.byteCount && base == digest(request, 4242, 17),
          "sudo remote review: the operation digest is a stable SHA-256")
    check(base != digest(request, 4243, 17),
          "sudo remote review: the same command from another helper pid is another operation")
    check(base != digest(request, 4242, 18),
          "sudo remote review: the same command from a reused pid with another start time is another operation")
    check(base != digest(sudoRequestFixture(command: "sudo /usr/bin/true"), 4242, 17),
          "sudo remote review: another command is another operation")
    check(base != digest(SudoRemoteReviewRequest(
        command: sudoFixtureCommand, workingDirectory: "/tmp", terminal: "/dev/ttys001",
        terminalSummary: sudoFixtureSummary
    ), 4242, 17), "sudo remote review: another working directory is another operation")
    check(base != digest(SudoRemoteReviewRequest(
        command: sudoFixtureCommand, workingDirectory: "/Users/example/project", terminal: "/dev/ttys001",
        terminalSummary: sudoFixtureSummary, targetUser: "root"
    ), 4242, 17), "sudo remote review: naming a target user is another operation")
    let reviewA = try? RemoteApprovalReview(sudo: request, helperPID: 4242, helperStartTime: 17, requester: nil)
    let reviewB = try? RemoteApprovalReview(sudo: request, helperPID: 4343, helperStartTime: 17, requester: nil)
    check(reviewA != nil && reviewB != nil && reviewA?.operationDigest != reviewB?.operationDigest,
          "sudo remote review: two identical commands from two sudo invocations are two different reviews")

    // The caller is named by the kernel. sudo runs set-id as root, which
    // proc_name refuses a same-user caller; KERN_PROC_PID does not.
    check(SudoReviewRequester.commandName(of: 1) == "launchd",
          "sudo remote review: the kernel names a root process for a same-user caller (launchd)")
    let ownParent = SudoReviewRequester.parent(ofHelper: getpid())
    check(ownParent?.pid == getppid() && ownParent?.name.isEmpty == false
            && ownParent?.name == SudoReviewRequester.commandName(of: getppid()),
          "sudo remote review: the requester is the helper's kernel parent, by its kernel name")
    check(SudoReviewRequester.commandName(of: 0x7fff_fff0) == nil
            && SudoReviewRequester.parent(ofHelper: 0x7fff_fff0) == nil,
          "sudo remote review: no process, no requester")

    // Display edges: a parent the kernel would not name, no tty, a long or
    // hostile command, a target user.
    let unnamed = try? RemoteApprovalReview(sudo: request, helperPID: 4242, helperStartTime: 17, requester: nil)
    check(unnamed?.callerDescription == "sudo (review helper pid 4242) on ttys001",
          "sudo remote review: an unreadable parent is named as the review helper, never guessed")
    let noTTY = try? RemoteApprovalReview(
        sudo: sudoRequestFixture(terminal: "no tty", terminalSummary: nil),
        helperPID: 4242, helperStartTime: 17, requester: sudoFixtureRequester
    )
    check(noTTY?.callerDescription == "sudo (pid 6001), no terminal" && noTTY?.terminalDescription == "no tty",
          "sudo remote review: a sudo without a tty says so")
    let long = "sudo " + String(repeating: "x", count: 20_000)
    let fitted = try? RemoteApprovalReview(
        sudo: sudoRequestFixture(command: long), helperPID: 1, helperStartTime: 1, requester: nil
    )
    check(fitted != nil
            && (fitted?.headline.utf8.count ?? .max) <= RemoteApprovalReview.FieldLimit.headline
            && (fitted?.sudo?.command.utf8.count ?? .max) <= RemoteApprovalReview.FieldLimit.sudoCommand
            && fitted?.headline.hasPrefix("sudo xxx") == true,
          "sudo remote review: a command longer than the phone carries is shortened, not refused")
    let hostile = try? RemoteApprovalReview(
        sudo: sudoRequestFixture(command: "sudo rm \u{1b}[2J\u{202e}evil"),
        helperPID: 1, helperStartTime: 1, requester: nil
    )
    check(hostile.map { !$0.headline.unicodeScalars.contains { $0 == "\u{1b}" || $0 == "\u{202e}" } } == true
            && hostile.map { !($0.sudo?.command.unicodeScalars.contains { $0 == "\u{1b}" || $0 == "\u{202e}" } ?? true) } == true,
          "sudo remote review: terminal escapes and bidi controls in the command are neutralized")
    let targeted = try? RemoteApprovalReview(
        sudo: SudoRemoteReviewRequest(
            command: "sudo -u deploy id", workingDirectory: "/", terminal: "/dev/ttys002", targetUser: "deploy"
        ),
        helperPID: 1, helperStartTime: 1, requester: sudoFixtureRequester
    )
    check(targeted?.sudo?.targetUser == "deploy" && targeted?.sudo?.command == "-u deploy id",
          "sudo remote review: a target user the helper knows is shown")
}

// MARK: - csecd's service

private func sudoRemoteServiceTests() async {
    let caller = sudoHelperCaller()
    // Phone approval.
    do {
        let phone = ScriptedSudoPhone(immediately: .approve)
        let records = SudoRecordedDecisions()
        let service = sudoService(phone, records: records)
        let request = sudoRequestFixture()
        let response = await service.handle(request, caller: caller)
        let published = await phone.published
        check(response.sudoRemoteReview == .approved && response.requestID == request.requestID
                && response.failure == nil,
              "sudo remote service: a phone approval answers approved, bound to the request")
        check((await phone.readinessQueries) == [[]],
              "sudo remote service: readiness is asked once, for no references")
        check(published.count == 1 && published.first?.kind == .sudo
                && published.first?.operationDigest == RemoteApprovalReview.sudoOperationDigest(
                    request, helperPID: caller.pid, helperStartTime: caller.startTime),
              "sudo remote service: the phone gets a sudo review bound to the helper's kernel pid and start time")
        check((await phone.unlockRequested) == [.notNeeded],
              "sudo remote service: a sudo review never asks the phone to open cold storage")
        let logged = records.all
        check(logged.count == 1, "sudo remote service: a phone approval writes one decision-log record")
        if let record = logged.first {
            check(record.kind == .panel && record.surface == .sudo && record.outcome == .phoneApproved
                    && record.decider == .humanPhone && record.ttdMs != nil,
                  "sudo remote service: the record is a sudo panel decided on the phone: phone_approved, human_phone")
            check(record.requester?.class == "sudo" && record.requester?.rootPID == sudoFixtureRequester.pid
                    && record.requester?.terminal == sudoFixtureSummary,
                  "sudo remote service: the record names sudo, its pid and its terminal")
            check(record.command == sudoFixtureCommand && record.refs == nil && record.grantIDs == nil
                    && record.scope == nil && record.duration == nil,
                  "sudo remote service: the record carries the redacted command and no reference, grant, scope or lifetime")
            let json = (try? JSONEncoder().encode(record)).map { String(decoding: $0, as: UTF8.self) } ?? ""
            check(json.contains("\"surface\":\"sudo\"") && json.contains("\"decider\":\"human_phone\"")
                    && json.contains("\"outcome\":\"phone_approved\""),
                  "sudo remote service: the record's wire names are surface sudo, human_phone, phone_approved")
        }
    }
    // A Claude Code sudo delegation declined: the phone's card carries csecd's
    // note and its unscoped pairing line, and an approval that signed it
    // showed the line pairs; one with the note alone does not.
    do {
        let phone = ScriptedSudoPhone(immediately: .approve)
        let paired = SudoPairingRecords()
        let note = SudoDelegationNote(
            note: DelegationDecline.sudoNotApproved(project: "app").panelText,
            pairingLine: SudoPairingOffer(projectName: "app").line
        )
        let decision = await sudoService(phone, note: note, paired: paired).review(sudoRequestFixture(), caller: caller)
        let published = await phone.published.first
        check(published?.delegation?.note == note.note && published?.delegation?.pairing == .unscoped(line: note.pairingLine ?? "")
                && (try? published?.validate()) != nil,
              "sudo remote service: the phone's card carries csecd's note and an unscoped pairing line")
        check(decision == .approved && paired.all.map(\.pid) == [caller.pid],
              "sudo remote service: a phone approval that showed the line records the pairing for that helper")
        let notePhone = ScriptedSudoPhone(immediately: .approve)
        let notePaired = SudoPairingRecords()
        _ = await sudoService(
            notePhone, note: SudoDelegationNote(note: note.note, pairingLine: nil), paired: notePaired
        ).review(sudoRequestFixture(), caller: caller)
        check((await notePhone.published.first)?.delegation?.pairing == nil && notePaired.all.isEmpty,
              "sudo remote service: with no line on the card, a phone approval pairs nothing")
        let denyPhone = ScriptedSudoPhone(immediately: .deny)
        let denyPaired = SudoPairingRecords()
        _ = await sudoService(denyPhone, note: note, paired: denyPaired).review(sudoRequestFixture(), caller: caller)
        check(denyPaired.all.isEmpty, "sudo remote service: a phone Deny pairs nothing")
    }
    // Phone Deny.
    do {
        let phone = ScriptedSudoPhone(immediately: .deny)
        let records = SudoRecordedDecisions()
        let decision = await sudoService(phone, records: records).review(sudoRequestFixture(), caller: caller)
        check(decision == .denied, "sudo remote service: a phone Deny answers denied")
        check(records.all.count == 1 && records.all.first?.outcome == .denied
                && records.all.first?.decider == .humanPhone && records.all.first?.surface == .sudo,
              "sudo remote service: a phone Deny is logged as denied by human_phone")
    }
    // No phone decision.
    do {
        let phone = ScriptedSudoPhone(immediately: .unavailable)
        let records = SudoRecordedDecisions()
        let decision = await sudoService(phone, records: records).review(sudoRequestFixture(), caller: caller)
        check(decision == .unavailable && records.all.isEmpty,
              "sudo remote service: relay trouble answers unavailable and logs nothing")
    }
    do {
        let phone = ScriptedSudoPhone(ready: false, immediately: .approve)
        let records = SudoRecordedDecisions()
        let decision = await sudoService(phone, records: records).review(sudoRequestFixture(), caller: caller)
        let nothingPublished = await phone.published.isEmpty
        check(decision == .unavailable && nothingPublished && records.all.isEmpty,
              "sudo remote service: a phone that is not ready is never published to, and the answer is unavailable")
    }
    // A caller that is not the verified helper.
    do {
        let phone = ScriptedSudoPhone(immediately: .approve)
        let records = SudoRecordedDecisions()
        let decision = await sudoService(phone, records: records, allowUnverified: false)
            .review(sudoRequestFixture(), caller: caller)
        let nothingAsked = await phone.readinessQueries.isEmpty
        let nothingPublished = await phone.published.isEmpty
        check(decision == .unavailable && nothingAsked && nothingPublished,
              "sudo remote service: a caller whose code identity is not the sudo review helper reaches nothing")
    }
    // A request that is not well formed.
    do {
        let phone = ScriptedSudoPhone(immediately: .approve)
        let malformed = SudoRemoteReviewRequest(command: "", workingDirectory: "/", terminal: "/dev/ttys001")
        let decision = await sudoService(phone).review(malformed, caller: caller)
        let nothingPublished = await phone.published.isEmpty
        check(decision == .unavailable && nothingPublished,
              "sudo remote service: a malformed request reaches nothing")
    }
    // The helper goes while the phone is still deciding: withdrawn, not logged.
    do {
        let phone = ScriptedSudoPhone()
        let records = SudoRecordedDecisions()
        let service = sudoService(phone, records: records)
        let task = Task { await service.review(sudoRequestFixture(), caller: caller) }
        let published = await sudoEventually(seconds: 5) { await phone.published.count == 1 }
        task.cancel()
        let decision = await task.value
        let withdrawals = await phone.withdrawals
        check(published && decision == .unavailable && withdrawals == 1 && records.all.isEmpty,
              "sudo remote service: a request whose helper went is withdrawn from the phone and logs nothing")
    }
}

/// The record through the real sealed decision log, as csecd builds the
/// service (`decisionLog:`), read back as `csec log` reads it.
private func sudoRemoteRealDecisionLogTests() async {
    let directory = NSTemporaryDirectory() + "cs-selftest-sudo-remote-log-\(UUID().uuidString.lowercased())"
    defer { try? FileManager.default.removeItem(atPath: directory) }
    let log = DecisionLog(
        directory: SealedRecordDirectory(path: directory),
        stores: .processLocal(),
        bootSessionUUID: "00000000-0000-0000-0000-00000000b007"
    )
    _ = await log.open()
    let service = SudoRemoteReviewService(
        remote: ScriptedSudoPhone(immediately: .deny),
        decisionLog: log,
        allowUnverifiedCallersForTesting: true,
        requester: { _ in sudoFixtureRequester },
        log: { _ in }
    )
    let decision = await service.review(sudoRequestFixture(), caller: sudoHelperCaller())
    let page = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.panel]))
    let record = page.records.first
    check(decision == .denied && page.records.count == 1 && record?.surface == .sudo
            && record?.outcome == .denied && record?.decider == .humanPhone
            && record?.command == sudoFixtureCommand && record?.requester?.class == "sudo",
          "sudo remote service: a phone-decided sudo is sealed into the real decision log and reads back")
}

/// The review through the real requester and a synthetic phone's signature:
/// the phone's approval of a sudo review carries no selection and no unlock
/// answer, and the Mac accepts exactly that.
private func sudoRemoteSignedExchangeTests() async {
    let phone = SyntheticPhone()
    let macKey = P256.Signing.PrivateKey()
    let relay = V3MailboxRelay()
    let requester: RemoteApprovalRequester
    do {
        requester = try RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: UUID().uuidString.lowercased(),
                macDeviceName: "Test Mac",
                pinnedPhoneDeviceID: phone.deviceID,
                pinnedPhonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: V3SoftwareSigner(key: macKey),
            relay: relay
        )
    } catch {
        check(false, "sudo remote signed exchange: the requester builds (\(error))")
        return
    }
    let records = SudoRecordedDecisions()
    let service = SudoRemoteReviewService(
        remote: RequesterRemoteAccessPolicyReviewProvider(requester: requester),
        record: { records.append($0) },
        allowUnverifiedCallersForTesting: true,
        requester: { _ in sudoFixtureRequester },
        log: { _ in }
    )
    let answers = [(RemoteApprovalDecision.approve, SudoRemoteReviewDecision.approved), (.deny, .denied)]
    for (index, (answer, expected)) in answers.enumerated() {
        let task = Task { await service.review(sudoRequestFixture(), caller: sudoHelperCaller()) }
        var envelope: SignedRemoteApprovalRequest?
        for _ in 0..<500 where envelope == nil {
            envelope = await relay.request(number: index)
            if envelope == nil { try? await Task.sleep(nanoseconds: 10_000_000) }
        }
        guard let envelope else {
            task.cancel()
            check(false, "sudo remote signed exchange: the sudo review is published to the relay")
            return
        }
        check(envelope.request.review.kind == .sudo && envelope.request.unlockChallenge == nil,
              "sudo remote signed exchange: the published request is a signed sudo review with no unlock challenge")
        do {
            let response = answer == .approve ? try phone.approve(envelope) : try phone.respond(to: envelope, .deny)
            check(response.response.selectedScopeID == nil && response.response.selectedDurationIndex == nil
                    && response.response.unlockAnswer == nil,
                  "sudo remote signed exchange: the phone's \(answer.rawValue) selects nothing")
            try await relay.publishResponse(response)
        } catch {
            task.cancel()
            check(false, "sudo remote signed exchange: the phone signs its \(answer.rawValue) (\(error))")
            return
        }
        let decision = await task.value
        check(decision == expected,
              "sudo remote signed exchange: the Mac accepts the phone's signed \(answer.rawValue) of a sudo review")
    }
    check(records.all.map(\.outcome) == [.phoneApproved, .denied],
          "sudo remote signed exchange: both decisions are logged")
}

// MARK: - The helper's race

private func sudoRemoteRaceTests() async {
    // Phone approval wins: the panel closes (cancelled), the helper approves.
    do {
        let panel = FakeSudoPanel()
        let outcome = await SudoReviewRace.run(
            local: { await panel.present() },
            phone: {
                try? await Task.sleep(nanoseconds: 50_000_000)
                return .approved
            }
        )
        check(outcome == .approved(on: .phone) && outcome.exitStatus == 0,
              "sudo race: a phone approval approves the sudo (exit 0)")
        check(await panel.closedByCancellation,
              "sudo race: a phone approval closes the Mac panel, as a phone decision closes the access and SSH panels")
    }
    // Phone Deny: the panel closes, sudo falls back to its password prompt.
    do {
        let panel = FakeSudoPanel()
        let outcome = await SudoReviewRace.run(
            local: { await panel.present() },
            phone: {
                try? await Task.sleep(nanoseconds: 50_000_000)
                return .denied
            }
        )
        check(outcome == .usePassword(deniedOnPhone: true) && outcome.exitStatus == 69,
              "sudo race: a phone Deny falls back to the password prompt (exit 69), like Use Password")
        check(await panel.closedByCancellation, "sudo race: a phone Deny closes the Mac panel")
    }
    // The panel approves first: the phone leg is withdrawn.
    do {
        let panel = FakeSudoPanel()
        let withdrawn = SudoHandlerCount()
        let task = Task {
            await SudoReviewRace.run(
                local: { await panel.present() },
                phone: {
                    while !Task.isCancelled { try? await Task.sleep(nanoseconds: 5_000_000) }
                    withdrawn.increment()
                    return .unavailable
                }
            )
        }
        _ = await sudoEventually(seconds: 5) { await panel.openedAt != nil }
        await panel.decide(.approved)
        let outcome = await task.value
        check(outcome == .approved(on: .mac) && outcome.exitStatus == 0 && withdrawn.value == 1,
              "sudo race: a Touch ID approval on the Mac approves and withdraws the phone leg")
    }
    // Use Password on the panel: exit 69, the phone leg withdrawn.
    do {
        let panel = FakeSudoPanel()
        let withdrawn = SudoHandlerCount()
        let task = Task {
            await SudoReviewRace.run(
                local: { await panel.present() },
                phone: {
                    while !Task.isCancelled { try? await Task.sleep(nanoseconds: 5_000_000) }
                    withdrawn.increment()
                    return .unavailable
                }
            )
        }
        _ = await sudoEventually(seconds: 5) { await panel.openedAt != nil }
        await panel.decide(.usePassword)
        let outcome = await task.value
        check(outcome == .usePassword(deniedOnPhone: false) && outcome.exitStatus == 69 && withdrawn.value == 1,
              "sudo race: Use Password on the Mac falls back and withdraws the phone leg")
    }
    // No phone: the panel alone decides, and it was up from the start.
    do {
        let panel = FakeSudoPanel()
        let started = ContinuousClock.now
        let task = Task {
            await SudoReviewRace.run(local: { await panel.present() }, phone: { .unavailable })
        }
        _ = await sudoEventually(seconds: 5) { await panel.openedAt != nil }
        try? await Task.sleep(nanoseconds: 100_000_000)
        check(!(await panel.closedByCancellation),
              "sudo race: an unavailable phone leaves the Mac panel up, undecided")
        await panel.decide(.approved)
        let outcome = await task.value
        let opened = await panel.openedAt
        let closed = await panel.closedByCancellation
        check(outcome == .approved(on: .mac) && !closed,
              "sudo race: with the phone unavailable the Mac panel decides alone")
        check(opened.map { started.duration(to: $0) < .milliseconds(250) } == true,
              "sudo race: the Mac panel opens at once whatever the phone leg does")
    }
    // A phone leg that never answers does not delay the panel either.
    do {
        let panel = FakeSudoPanel()
        let started = ContinuousClock.now
        let task = Task {
            await SudoReviewRace.run(
                local: { await panel.present() },
                phone: {
                    while !Task.isCancelled { try? await Task.sleep(nanoseconds: 5_000_000) }
                    return .unavailable
                }
            )
        }
        _ = await sudoEventually(seconds: 5) { await panel.openedAt != nil }
        let opened = await panel.openedAt
        check(opened.map { started.duration(to: $0) < .milliseconds(250) } == true,
              "sudo race: a phone leg still waiting does not delay the Mac panel")
        // The sudo that asked exits: the race is cancelled, both legs end.
        task.cancel()
        let outcome = await task.value
        let closed = await panel.closedByCancellation
        check(outcome == .usePassword(deniedOnPhone: false) && closed,
              "sudo race: when the sudo that asked exits, the panel closes and nothing is approved")
    }
}

// MARK: - End to end through the socket

private func sudoRemoteEndToEndTests() async {
    let helperRole = SocketPeerTrustPolicy.assumeRoleForTesting(.sudoReviewHelper)

    // Phone approval: through the real server and client, the panel closes and
    // the helper approves; csecd logs phone_approved.
    do {
        let phone = ScriptedSudoPhone()
        let records = SudoRecordedDecisions()
        guard let server = startSudoServer("approve", policy: helperRole, service: sudoService(phone, records: records))
        else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }
        let client = SudoRemoteReviewClient(
            path: server.path, serverTrustPolicy: .allowUnverifiedForTesting, liveness: sudoTestLiveness)
        let panel = FakeSudoPanel()
        let request = sudoRequestFixture()
        let task = Task {
            await SudoReviewRace.run(local: { await panel.present() }, phone: { await client.review(request) })
        }
        let published = await sudoEventually(seconds: 5) { await phone.published.count == 1 }
        await phone.answer(.approve)
        let outcome = await task.value
        let closed = await panel.closedByCancellation
        check(published && outcome == .approved(on: .phone) && closed,
              "sudo end to end: the phone's approval through csecd closes the panel and approves (exit 0)")
        check(records.all.map(\.outcome) == [.phoneApproved] && records.all.first?.surface == .sudo,
              "sudo end to end: csecd logs the phone approval of a sudo")
    }
    // Phone Deny: the panel closes and sudo falls back to the password prompt.
    do {
        let phone = ScriptedSudoPhone()
        guard let server = startSudoServer("deny", policy: helperRole, service: sudoService(phone)) else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }
        let client = SudoRemoteReviewClient(
            path: server.path, serverTrustPolicy: .allowUnverifiedForTesting, liveness: sudoTestLiveness)
        let panel = FakeSudoPanel()
        let task = Task {
            await SudoReviewRace.run(local: { await panel.present() }, phone: { await client.review(sudoRequestFixture()) })
        }
        _ = await sudoEventually(seconds: 5) { await phone.published.count == 1 }
        await phone.answer(.deny)
        let outcome = await task.value
        let closed = await panel.closedByCancellation
        check(outcome == .usePassword(deniedOnPhone: true) && outcome.exitStatus == 69 && closed,
              "sudo end to end: the phone's Deny closes the panel and falls back to the password prompt (exit 69)")
    }
    // The panel wins: the helper closes its connection, and csecd withdraws
    // the phone's copy promptly (its peer-exit watch), logging nothing.
    do {
        let phone = ScriptedSudoPhone()
        let records = SudoRecordedDecisions()
        guard let server = startSudoServer("local", policy: helperRole, service: sudoService(phone, records: records))
        else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }
        let client = SudoRemoteReviewClient(
            path: server.path, serverTrustPolicy: .allowUnverifiedForTesting, liveness: sudoTestLiveness)
        let panel = FakeSudoPanel()
        let task = Task {
            await SudoReviewRace.run(local: { await panel.present() }, phone: { await client.review(sudoRequestFixture()) })
        }
        let published = await sudoEventually(seconds: 5) { await phone.published.count == 1 }
        let decidedAt = ContinuousClock.now
        await panel.decide(.approved)
        let outcome = await task.value
        let raceEnded = decidedAt.duration(to: .now)
        check(published && outcome == .approved(on: .mac) && raceEnded < .seconds(1),
              "sudo end to end: a Touch ID approval on the Mac ends the review at once")
        let withdrawn = await sudoEventually(seconds: 2 * AgentLiveness.peerExitPollInterval + 1) {
            await phone.withdrawals == 1
        }
        check(withdrawn && records.all.isEmpty,
              "sudo end to end: the helper closing its connection withdraws the phone's copy, and nothing is logged")
    }
    // No csecd: the phone leg is unavailable at once and the panel decides.
    do {
        guard let base = sudoSocketDirectory("absent") else { return }
        defer { try? FileManager.default.removeItem(at: base) }
        let client = SudoRemoteReviewClient(
            path: base.appendingPathComponent("agent.sock").path,
            serverTrustPolicy: .allowUnverifiedForTesting, liveness: sudoTestLiveness)
        let started = ContinuousClock.now
        let decision = await client.review(sudoRequestFixture())
        check(decision == .unavailable && started.duration(to: .now) < .milliseconds(500),
              "sudo end to end: with no csecd the phone leg is unavailable at once")
        let panel = FakeSudoPanel()
        let task = Task {
            await SudoReviewRace.run(local: { await panel.present() }, phone: { await client.review(sudoRequestFixture()) })
        }
        _ = await sudoEventually(seconds: 5) { await panel.openedAt != nil }
        try? await Task.sleep(nanoseconds: 100_000_000)
        let stillUp = !(await panel.closedByCancellation)
        await panel.decide(.usePassword)
        let outcome = await task.value
        check(stillUp && outcome == .usePassword(deniedOnPhone: false),
              "sudo end to end: with no csecd the Mac panel alone decides, exactly as before")
    }
    // csecd up but no phone ready: unavailable at once, nothing published.
    do {
        let phone = ScriptedSudoPhone(ready: false)
        guard let server = startSudoServer("unready", policy: helperRole, service: sudoService(phone)) else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }
        let client = SudoRemoteReviewClient(
            path: server.path, serverTrustPolicy: .allowUnverifiedForTesting, liveness: sudoTestLiveness)
        let started = ContinuousClock.now
        let decision = await client.review(sudoRequestFixture())
        let elapsed = started.duration(to: .now)
        let nothingPublished = await phone.published.isEmpty
        check(decision == .unavailable && elapsed < .seconds(1) && nothingPublished,
              "sudo end to end: with no phone ready csecd answers unavailable at once and publishes nothing")
    }
    // A leg cancelled before it connects sends nothing.
    do {
        let phone = ScriptedSudoPhone(immediately: .approve)
        let handled = SudoHandlerCount()
        guard let server = startSudoServer(
            "precancel", policy: helperRole, service: sudoService(phone), handled: handled
        ) else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }
        let client = SudoRemoteReviewClient(
            path: server.path, serverTrustPolicy: .allowUnverifiedForTesting, liveness: sudoTestLiveness)
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return await client.review(sudoRequestFixture())
        }
        let decision = await task.value
        try? await Task.sleep(nanoseconds: 200_000_000)
        let nothingPublished = await phone.published.isEmpty
        check(decision == .unavailable && handled.value == 0 && nothingPublished,
              "sudo end to end: a phone leg cancelled before it connects sends nothing")
    }
}

#if DEBUG
/// The built helper's own phone leg (`--phone-probe`), pointed by the debug
/// build's `CSEC_SOCKET` at a private csecd stand-in: the helper binary builds
/// the request from its fixture, sends it, and reports csecd's answer. Debug
/// only: a release helper ignores `CSEC_SOCKET` and would reach the installed
/// csecd.
private func sudoRemoteHelperProbeTests() async {
    let helper = (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0]))
        .deletingLastPathComponent().appendingPathComponent("csec-sudo-review").path
    guard FileManager.default.isExecutableFile(atPath: helper) else {
        check(false, "sudo helper phone probe: the csec-sudo-review helper is built next to cs-selftest (\(helper))")
        return
    }
    for (answer, expected) in [(ScriptedSudoPhone.Answer.approve, "approved"), (.deny, "denied")] {
        let phone = ScriptedSudoPhone(immediately: answer)
        guard let server = startSudoServer(
            "probe", policy: .assumeRoleForTesting(.sudoReviewHelper), service: sudoService(phone)
        ) else { return }
        defer { try? FileManager.default.removeItem(at: server.directory) }
        let output = await withCheckedContinuation { (continuation: CheckedContinuation<String, Never>) in
            Thread.detachNewThread {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: helper)
                process.arguments = ["--phone-probe"]
                process.environment = ["CSEC_SOCKET": server.path, "PATH": "/usr/bin:/bin"]
                let pipe = Pipe()
                process.standardOutput = pipe
                process.standardError = FileHandle.nullDevice
                do {
                    try process.run()
                } catch {
                    continuation.resume(returning: "launch failed")
                    return
                }
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                continuation.resume(returning: String(decoding: data, as: UTF8.self))
            }
        }
        let published = await phone.published
        check(output.contains("sudo review phone probe: \(expected)")
                && published.count == 1 && published.first?.kind == .sudo
                && published.first?.headline == "sudo /usr/bin/true --api-key \"[csec:secret-like]\" safe",
              "sudo helper phone probe: the built helper's phone leg reaches csecd and reports \(expected)")
    }
}
#endif

// MARK: - The deadline on the phone's card (csec-0.69)

/// The helper sends the moment it closes the review, and csecd puts it on the
/// phone's card unless no PAM frame could have produced it.
func sudoPhoneDeadlineTests() async {
    let frame = SudoAuthorizationReviewRequest(
        submittedCommand: sudoFixtureCommand, workingDirectory: "/Users/example/project", terminal: "/dev/ttys001")
    let deadline = SudoReviewDeadline(timeLimit: .seconds(300))
    let sent = SudoRemoteReviewRequest(frame, terminal: nil, closing: deadline.closing)
    check(sent.closesAtMilliseconds == deadline.closing.unixMilliseconds && sent.isWellFormed,
          "sudo phone deadline: the helper sends the moment its panel closes the review")
    check(SudoRemoteReviewRequest(frame, terminal: nil).closesAtMilliseconds == nil,
          "sudo phone deadline: a request made without one sends none")
    if let data = try? JSONEncoder().encode(sent),
       let decoded = try? JSONDecoder().decode(SudoRemoteReviewRequest.self, from: data) {
        check(decoded == sent, "sudo phone deadline: it crosses the socket's JSON intact")
    } else {
        check(false, "sudo phone deadline: the request round-trips through JSON")
    }

    let now: UInt64 = 1_792_000_000_000
    func carried(_ closesAt: UInt64?) -> UInt64? {
        SudoRemoteReviewRequest(
            command: sudoFixtureCommand, workingDirectory: "/tmp", terminal: "/dev/ttys001",
            closesAtMilliseconds: closesAt
        ).phoneDeadline(nowMilliseconds: now)
    }
    check(carried(now + 297_000) == now + 297_000 && carried(now + 600_000) == now + 600_000
            && carried(now - 1_000) == now - 1_000,
          "sudo phone deadline: csecd keeps any moment a PAM frame could give, a passed one included")
    check(carried(now + 600_001) == nil && carried(.max) == nil && carried(nil) == nil,
          "sudo phone deadline: one further ahead than any PAM limit is dropped, leaving the card without a line")

    let phone = ScriptedSudoPhone(immediately: .deny)
    let closesAt = currentTimeMilliseconds() + 297_000
    _ = await sudoService(phone).review(
        SudoRemoteReviewRequest(
            command: sudoFixtureCommand, workingDirectory: "/tmp", terminal: "/dev/ttys001",
            closesAtMilliseconds: closesAt),
        caller: sudoHelperCaller())
    let published = await phone.published.first
    check(published?.kind == .sudo && published?.closesAtMilliseconds == closesAt,
          "sudo phone deadline: csecd signs it into the sudo review the phone shows")
    let far = ScriptedSudoPhone(immediately: .deny)
    _ = await sudoService(far).review(
        SudoRemoteReviewRequest(
            command: sudoFixtureCommand, workingDirectory: "/tmp", terminal: "/dev/ttys001",
            closesAtMilliseconds: currentTimeMilliseconds() + 3_600_000),
        caller: sudoHelperCaller())
    let farPublished = await far.published.first
    check(farPublished != nil && farPublished?.closesAtMilliseconds == nil,
          "sudo phone deadline: a review whose moment was dropped still reaches the phone")
}

// MARK: - How each review ended

/// A synthetic process tree for the attribution walk: pid -> (parent, name,
/// executable path, start time, controlling terminal). The sudo itself is in
/// it only as a kernel parent: csecd cannot read a root sudo's start time.
private struct SudoEndTree: Sendable {
    struct Node: Sendable {
        let parent: pid_t
        let name: String
        let path: String
        let start: UInt64
        let tty: Bool
    }

    var nodes: [pid_t: Node]

    var inspection: ProcessInspection {
        let nodes = self.nodes
        return ProcessInspection(
            startTime: { pid in pid == 6001 ? nil : nodes[pid]?.start },
            parent: { nodes[$0]?.parent },
            name: { nodes[$0]?.name },
            executablePath: { nodes[$0]?.path },
            hasControllingTerminal: { nodes[$0]?.tty ?? false }
        )
    }

    var kernelParent: @Sendable (pid_t) -> pid_t? {
        let nodes = self.nodes
        return { nodes[$0]?.parent }
    }

    /// helper 4242 → sudo 6001 → `csec ai` 7001 → zsh 7002 → `agent` 7003 →
    /// fish 7004 (the terminal) → launchd; `agent` nil leaves 7003 a plain node.
    static func agentRan(_ agent: (name: String, path: String)?, sudoParent: pid_t = 7001) -> SudoEndTree {
        var nodes: [pid_t: Node] = [
            4242: Node(parent: 6001, name: "csec-sudo-review", path: "/usr/local/libexec/csec-sudo-review",
                       start: 1_700_000_000_000_001, tty: false),
            6001: Node(parent: sudoParent, name: "sudo", path: "/usr/bin/sudo", start: 0, tty: true),
            7001: Node(parent: 7002, name: "csec", path: "/usr/local/bin/csec", start: 71, tty: false),
            7002: Node(parent: 7003, name: "zsh", path: "/bin/zsh", start: 72, tty: false),
            7003: Node(parent: 7004, name: agent?.name ?? "node", path: agent?.path ?? "/usr/local/bin/node",
                       start: 73, tty: false),
            7004: Node(parent: 1, name: "fish", path: "/opt/homebrew/bin/fish", start: 74, tty: true),
        ]
        if sudoParent == 7003 { nodes[7001] = nil; nodes[7002] = nil }
        return SudoEndTree(nodes: nodes)
    }
}

private let sudoCodex = (name: "codex", path: "/opt/homebrew/bin/codex")
private let sudoClaude = (name: "2.1.300", path: "/Users/example/.local/share/claude/versions/2.1.300")

private func sudoEndRequest(_ outcome: SudoReviewEndRequest.Outcome, ttdMs: Int? = 297_000) -> SudoReviewEndRequest {
    SudoReviewEndRequest(
        outcome: outcome, command: sudoFixtureCommand, terminal: "/dev/ttys001",
        terminalSummary: sudoFixtureSummary, ttdMs: ttdMs
    )
}

private func sudoEndJSON(_ record: DecisionLogRecord) -> [String: Any] {
    (try? JSONEncoder().encode(record)).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
}

func sudoReviewEndTests() async {
    print("\n# Sudo review: how each review ended, in the decision log, under its coding agent")
    sudoReviewEndWireTests()
    sudoReviewEndAttributionTests()
    await sudoReviewEndMemoryTests()
    await sudoReviewEndServiceTests()
    sudoReviewEndHelperTests()
    await sudoReviewEndPhoneAttributionTests()
    await sudoReviewEndSocketTests()
}

private func sudoReviewEndWireTests() {
    let report = sudoEndRequest(.timedOut)
    guard let encoded = try? WireTransport.encodeRequest(.sudoReviewEnd(report), supportsHeartbeats: false),
          let decoded = try? JSONDecoder().decode(Request.self, from: encoded),
          let object = try? JSONSerialization.jsonObject(with: encoded) as? [String: Any] else {
        check(false, "sudo end wire: sudo_review_end round-trips")
        return
    }
    let same: Bool
    if case let .sudoReviewEnd(received) = decoded { same = received == report } else { same = false }
    check(same && object["type"] as? String == "sudo_review_end"
            && (object["sudoReviewEnd"] as? [String: Any])?["outcome"] as? String == "timed_out"
            && decoded.isSudoReviewEnd && !decoded.isSudoDelegation && !decoded.isSudoTerminal
            && !decoded.isSudoRemoteReview,
          "sudo end wire: sudo_review_end round-trips as its own type, naming its outcome")
    var mismatched = object
    mismatched["requestID"] = UUID().uuidString.lowercased()
    check((try? JSONSerialization.data(withJSONObject: mismatched)).flatMap { try? JSONDecoder().decode(Request.self, from: $0) } == nil,
          "sudo end wire: a frame whose requestID differs from its body's is refused")
    var unknown = object
    var body = object["sudoReviewEnd"] as? [String: Any] ?? [:]
    body["outcome"] = "approved_phone"
    unknown["sudoReviewEnd"] = body
    check((try? JSONSerialization.data(withJSONObject: unknown)).flatMap { try? JSONDecoder().decode(Request.self, from: $0) } == nil,
          "sudo end wire: an outcome the helper never reports is refused")
    check(SudoReviewEndRequest.Outcome.allCases.map(\.rawValue)
            == ["approved_mac", "use_password", "timed_out", "requester_gone"],
          "sudo end wire: the helper reports a Mac approval, Use Password, the deadline and the sudo leaving")
    check(!sudoEndRequest(.timedOut, ttdMs: -1).isWellFormed
            && !sudoEndRequest(.timedOut, ttdMs: SudoReviewEndRequest.maximumTTDMilliseconds + 1).isWellFormed
            && !SudoReviewEndRequest(outcome: .timedOut, command: "", terminal: "no tty").isWellFormed
            && !SudoReviewEndRequest(
                outcome: .timedOut, command: String(repeating: "a", count: SudoRemoteReviewRequest.maximumCommandBytes + 1),
                terminal: "no tty").isWellFormed
            && !SudoReviewEndRequest(outcome: .timedOut, command: "sudo id", terminal: "no tty", terminalSummary: "")
                .isWellFormed
            && SudoReviewEndRequest(outcome: .usePassword, command: "sudo id", terminal: "no tty").isWellFormed,
          "sudo end wire: an empty or over-long command, an empty summary or an impossible wait is refused")
    let carried = (try? JSONEncoder().encode(Response(requestID: report.requestID, sudoReviewEnded: true)))
        .flatMap { try? JSONDecoder().decode(Response.self, from: $0) }
    check(carried?.sudoReviewEnded == true && Response(requestID: report.requestID).sudoReviewEnded == nil,
          "sudo end wire: csecd's answer round-trips, and no other response carries one")
    check(SocketPeerTrustPolicy.permits(.sudoReviewEnd(report), role: .sudoReviewHelper)
            && !ProductCodeRole.allCases.contains {
                $0 != .sudoReviewHelper && SocketPeerTrustPolicy.permits(.sudoReviewEnd(report), role: $0)
            },
          "sudo end gate: only the sudo review helper may send sudo_review_end")
}

private func sudoReviewEndAttributionTests() {
    let helper = sudoHelperCaller()
    for (label, agent, expected) in [("Codex", sudoCodex, "Codex"), ("Claude Code", sudoClaude, "Claude Code")] {
        let tree = SudoEndTree.agentRan(agent)
        let found = SudoReviewAttribution.live(helper: helper, inspection: tree.inspection, kernelParent: tree.kernelParent)
        check(found?.sudoPID == 6001 && found?.agent?.pid == 7003 && found?.agent?.processLabel == expected
                && found?.agent?.kind == .codingAgent && found?.scope == "coding_agent",
              "sudo end attribution: a sudo \(label) ran through its tool shell is rooted at \(label), not the shell or terminal")
        let requester = found?.requester(terminal: "ttys001")
        check(requester == DecisionLogRecord.Requester(class: "sudo", rootPID: 7003, rootLabel: expected, terminal: "ttys001"),
              "sudo end attribution: the requester stays class sudo, its root the coding agent")
    }
    let direct = SudoEndTree.agentRan(sudoCodex, sudoParent: 7003)
    check(SudoReviewAttribution.live(helper: helper, inspection: direct.inspection, kernelParent: direct.kernelParent)?
            .agent?.pid == 7003,
          "sudo end attribution: a coding agent that runs sudo itself, with no shell between, is the root")
    let terminal = SudoEndTree.agentRan(nil)
    let typed = SudoReviewAttribution.live(helper: helper, inspection: terminal.inspection, kernelParent: terminal.kernelParent)
    check(typed == SudoReviewAttribution(sudoPID: 6001, agent: nil) && typed?.scope == nil
            && typed?.requester(terminal: nil).rootPID == 6001,
          "sudo end attribution: a terminal's sudo has no coding agent and is rooted at the sudo, as before")
    let recycled = sudoHelperCaller(startTime: 9)
    check(SudoReviewAttribution.live(helper: recycled, inspection: terminal.inspection, kernelParent: terminal.kernelParent)
            == nil,
          "sudo end attribution: a helper pid that names another process now is attributed to no one")
}

private final class SudoEndTreeBox: @unchecked Sendable {
    private let lock = NSLock()
    private var tree: SudoEndTree
    init(_ tree: SudoEndTree) { self.tree = tree }
    var current: SudoEndTree { lock.withLock { tree } }
    func sudoExited() { lock.withLock { tree.nodes[6001] = nil; tree.nodes[4242] = SudoEndTree.Node(
        parent: 1, name: "csec-sudo-review", path: "/usr/local/libexec/csec-sudo-review",
        start: 1_700_000_000_000_001, tty: false) } }
}

private func sudoReviewEndMemoryTests() async {
    let helper = sudoHelperCaller()
    let box = SudoEndTreeBox(SudoEndTree.agentRan(sudoCodex))
    let attributions = SudoReviewAttributions(
        lookup: { caller in
            let tree = box.current
            return SudoReviewAttribution.live(helper: caller, inspection: tree.inspection, kernelParent: tree.kernelParent)
        },
        isLive: { $0.pid == 4242 }
    )
    await attributions.note(helper)
    box.sudoExited()
    let afterExit = await attributions.attribution(for: helper)
    check(afterExit?.agent?.pid == 7003 && afterExit?.agent?.processLabel == "Codex",
          "sudo end memory: what csecd noted while the sudo ran still names Codex once the sudo has exited")
    let fresh = SudoReviewAttributions(lookup: { _ in nil })
    let unseen = await fresh.attribution(for: helper)
    let kept = await fresh.count
    check(unseen == nil && kept == 0,
          "sudo end memory: a helper csecd never saw under a sudo is attributed to no one, and nothing is kept")

    // Delegation's own Claude Code process stands over the walk's choice.
    let declinedFor = ProcessIncarnation(pid: 9101, startTime: 91)
    let delegated = SudoReviewAttributions(
        lookup: { caller in
            let tree = SudoEndTree.agentRan(sudoClaude)
            return SudoReviewAttribution.live(helper: caller, inspection: tree.inspection, kernelParent: tree.kernelParent)
        },
        delegatedAgent: { _ in declinedFor }
    )
    let override = await delegated.attribution(for: helper)
    check(override?.agent?.pid == 9101 && override?.agent?.processLabel == "Claude Code" && override?.sudoPID == 6001,
          "sudo end memory: a sudo delegation declined is rooted at the Claude Code process its decline names")

    // Bounded, and pruned as helpers exit.
    let many = SudoReviewAttributions(lookup: { SudoReviewAttribution(sudoPID: $0.pid + 1, agent: nil) }, isLive: { $0.pid < 100 })
    for pid in pid_t(2)..<pid_t(2 + SudoReviewAttributions.maximumRemembered + 10) {
        await many.note(CallerInfo(pid: pid, startTime: 1, description: "helper"))
    }
    let manyKept = await many.count
    check(manyKept <= SudoReviewAttributions.maximumRemembered,
          "sudo end memory: csecd keeps at most \(SudoReviewAttributions.maximumRemembered) helpers")
}

private func sudoReviewEndServiceTests() async {
    let codex = SudoReviewAttribution(
        sudoPID: 6001, agent: GrantScopeOption(kind: .codingAgent, pid: 76_769, startTime: 73, processLabel: "Codex"))
    let caller = sudoHelperCaller()
    // The 9 Nov 2026 shape: a Codex session's root-tool installer ran sudo on
    // a developer Mac, nobody answered within 5 minutes, and nothing was logged.
    do {
        let records = SudoRecordedDecisions()
        let service = SudoReviewEndService(
            attributions: SudoReviewAttributions(lookup: { _ in codex }), record: { records.append($0) },
            allowUnverifiedCallersForTesting: true)
        let logged = await service.handle(sudoEndRequest(.timedOut), caller: caller)
        let json = records.all.first.map(sudoEndJSON) ?? [:]
        let requester = json["requester"] as? [String: Any] ?? [:]
        check(logged && records.all.count == 1 && json["kind"] as? String == "withdrawn"
                && json["surface"] as? String == "sudo" && json["outcome"] as? String == "timed_out"
                && json["scope"] as? String == "coding_agent" && json["decider"] == nil
                && requester["class"] as? String == "sudo" && requester["rootPID"] as? Int == 76_769
                && requester["rootLabel"] as? String == "Codex" && requester["terminal"] as? String == sudoFixtureSummary
                && json["command"] as? String == sudoFixtureCommand && json["ttdMs"] as? Int == 297_000,
              "sudo end service: a Codex sudo nobody answered is withdrawn timed_out, rooted at Codex, scope coding_agent")
        check((json["detail"] as? String) == "shown, not answered; nobody answered within 5 minutes; waited 4m57s",
              "sudo end service: its detail says nobody answered within the module's 5 minutes, and how long it waited")
    }
    for (outcome, kind, wire, decider) in [
        (SudoReviewEndRequest.Outcome.approvedOnMac, "panel", "approved", "human_local"),
        (.usePassword, "panel", "use_password", nil),
        (.requesterGone, "panel", "requester_gone", nil),
    ] as [(SudoReviewEndRequest.Outcome, String, String, String?)] {
        let record = SudoReviewEndService.logRecord(sudoEndRequest(outcome), attribution: codex)
        let json = sudoEndJSON(record)
        check(json["kind"] as? String == kind && json["outcome"] as? String == wire
                && json["decider"] as? String == decider && json["surface"] as? String == "sudo"
                && (json["requester"] as? [String: Any])?["rootPID"] as? Int == 76_769,
              "sudo end service: \(outcome.rawValue) is a \(kind) record, \(wire), decided by \(decider ?? "no one")")
    }
    let gone = SudoReviewEndService.logRecord(sudoEndRequest(.requesterGone), attribution: codex)
    check(gone.detail == "shown, not answered; the sudo ended before anyone answered; waited 4m57s",
          "sudo end service: a sudo that left says so")
    let typed = SudoReviewEndService.logRecord(
        sudoEndRequest(.usePassword), attribution: SudoReviewAttribution(sudoPID: 6001, agent: nil))
    check(typed.scope == nil && typed.requester == DecisionLogRecord.Requester(
            class: "sudo", rootPID: 6001, terminal: sudoFixtureSummary),
          "sudo end service: a terminal's sudo is rooted at the sudo, with no scope")
    // Only the installed helper, and only a well-formed report.
    let records = SudoRecordedDecisions()
    let strict = SudoReviewEndService(
        attributions: SudoReviewAttributions(lookup: { _ in codex }), record: { records.append($0) })
    let refused = await strict.handle(sudoEndRequest(.timedOut), caller: caller)
    let malformed = await SudoReviewEndService(
        attributions: SudoReviewAttributions(lookup: { _ in codex }), record: { records.append($0) },
        allowUnverifiedCallersForTesting: true
    ).handle(sudoEndRequest(.timedOut, ttdMs: -5), caller: caller)
    check(!refused && !malformed && records.all.isEmpty,
          "sudo end service: a caller that is not the verified helper, or a malformed report, logs nothing")
}

private func sudoReviewEndHelperTests() {
    typealias Reported = SudoReviewEndRequest.Outcome
    check(Reported.reported(expired: false, parentExited: false, outcome: .approved(on: .mac)) == .approvedOnMac
            && Reported.reported(expired: false, parentExited: false, outcome: .usePassword(deniedOnPhone: false))
            == .usePassword,
          "sudo end helper: a Mac approval and a Use Password are reported as they are")
    check(Reported.reported(expired: false, parentExited: false, outcome: .approved(on: .phone)) == nil
            && Reported.reported(expired: false, parentExited: false, outcome: .usePassword(deniedOnPhone: true)) == nil,
          "sudo end helper: a phone decision, which csecd logged itself, is not reported again")
    check(Reported.reported(expired: true, parentExited: false, outcome: .usePassword(deniedOnPhone: false)) == .timedOut
            && Reported.reported(expired: true, parentExited: true, outcome: .usePassword(deniedOnPhone: false)) == .timedOut,
          "sudo end helper: a review the deadline closed is timed_out, whatever the race returned")
    check(Reported.reported(expired: false, parentExited: true, outcome: .usePassword(deniedOnPhone: false))
            == .requesterGone
            && Reported.reported(expired: false, parentExited: true, outcome: .approved(on: .mac)) == .approvedOnMac,
          "sudo end helper: the sudo exiting is requester_gone, not the Use Password its cancelled race returns")
    let latch = SudoReviewParentExit()
    let before = latch.hasExited
    latch.mark()
    check(!before && latch.hasExited, "sudo end helper: the parent-exit latch is unset until the parent watch marks it")
    let timeLimit = SudoReviewDeadline(timeLimit: .seconds(300))
    let closing = SudoReviewDeadline(timeLimit: .seconds(1))
    check(timeLimit.fitsBeforeModuleDeadline(SudoDelegationClient.endDeadline)
            && !closing.fitsBeforeModuleDeadline(SudoDelegationClient.endDeadline)
            && SudoDelegationClient.endDeadline + .milliseconds(250) < SudoReviewDeadline.closingMargin,
          "sudo end helper: the report fits inside the closing margin, and is skipped when it could outlast the module")
    let request = SudoReviewEndRequest(.timedOut, review: sudoRequestFixture(), took: .seconds(9_999))
    check(request.ttdMs == SudoReviewEndRequest.maximumTTDMilliseconds && request.isWellFormed
            && request.command == sudoFixtureCommand && request.terminalSummary == sudoFixtureSummary,
          "sudo end helper: the report carries the phone copy's command and terminal, its wait clamped")
}

private func sudoReviewEndPhoneAttributionTests() async {
    let codex = SudoReviewAttribution(
        sudoPID: 6001, agent: GrantScopeOption(kind: .codingAgent, pid: 76_769, startTime: 73, processLabel: "Codex"))
    let phone = ScriptedSudoPhone(immediately: .approve)
    let records = SudoRecordedDecisions()
    let service = SudoRemoteReviewService(
        remote: phone, record: { records.append($0) }, allowUnverifiedCallersForTesting: true,
        requester: { _ in sudoFixtureRequester }, attribution: { _ in codex }, log: { _ in })
    let decision = await service.review(sudoRequestFixture(), caller: sudoHelperCaller())
    let record = records.all.first
    check(decision == .approved && records.all.count == 1 && record?.outcome == .phoneApproved
            && record?.requester == DecisionLogRecord.Requester(
                class: "sudo", rootPID: 76_769, rootLabel: "Codex", terminal: sudoFixtureSummary)
            && record?.scope == "coding_agent",
          "sudo end phone: csecd's own record of a phone approval is rooted at the coding agent too")
}

private func sudoReviewEndSocketTests() async {
    guard let base = sudoSocketDirectory("end") else { return }
    defer { try? FileManager.default.removeItem(at: base) }
    let records = SudoRecordedDecisions()
    let handled = SudoHandlerCount()
    let codex = SudoReviewAttribution(
        sudoPID: 6001, agent: GrantScopeOption(kind: .codingAgent, pid: 76_769, startTime: 73, processLabel: "Codex"))
    let service = SudoReviewEndService(
        attributions: SudoReviewAttributions(lookup: { _ in codex }), record: { records.append($0) },
        allowUnverifiedCallersForTesting: true)
    for (tag, role) in [("helper", ProductCodeRole.sudoReviewHelper), ("launcher", .launcher)] {
        let socket = base.appendingPathComponent("\(tag).sock").path
        let server = SocketServer(path: socket, clientTrustPolicy: .assumeRoleForTesting(role), liveness: sudoTestLiveness) {
            request, caller in
            handled.increment()
            guard case let .sudoReviewEnd(report) = request else {
                return .failed(.invalidRequest, message: "not part of the sudo end check")
            }
            return Response(requestID: report.requestID, sudoReviewEnded: await service.handle(report, caller: caller))
        }
        Thread.detachNewThread { try? server.run() }
        guard sudoWaitForSocket(socket) else {
            check(false, "sudo end socket: the \(tag) server never bound its socket")
            continue
        }
        let before = handled.value
        let logged = await SudoDelegationClient(path: socket, serverTrustPolicy: .allowUnverifiedForTesting)
            .end(sudoEndRequest(.timedOut))
        if role == .sudoReviewHelper {
            check(logged && handled.value == before + 1 && records.all.last?.outcome == .timedOut
                    && records.all.last?.requester?.rootPID == 76_769,
                  "sudo end socket: the helper's report reaches csecd and is logged under the coding agent")
            // On the deadline's and the parent's paths the helper's review task
            // is already cancelled, which ends a bounded call made in it at
            // once, so the helper reports from a task of its own (`reportEnd`).
            let client = SudoDelegationClient(path: socket, serverTrustPolicy: .allowUnverifiedForTesting)
            let cancelled = Task { () -> Bool in
                while !Task.isCancelled { try? await Task.sleep(nanoseconds: 1_000_000) }
                return await Task.detached { await client.end(sudoEndRequest(.requesterGone)) }.value
            }
            cancelled.cancel()
            let sent = await cancelled.value
            check(sent && records.all.last?.outcome == .requesterGone,
                  "sudo end socket: from a cancelled review the report still reaches csecd from a task of its own")
        } else {
            check(!logged && handled.value == before && records.all.count == 2,
                  "sudo end socket: csecd refuses sudo_review_end from the launcher before logging anything")
        }
    }
    let started = ContinuousClock.now
    let nowhere = await SudoDelegationClient(
        path: "/tmp/cs-sudo-end-none-\(UUID().uuidString.prefix(8))/agent.sock",
        serverTrustPolicy: .allowUnverifiedForTesting
    ).end(sudoEndRequest(.timedOut))
    check(!nowhere && ContinuousClock.now - started < .seconds(2),
          "sudo end socket: with no csecd the report fails at once and the sudo's outcome stands")
}
