import ConvenientSecurity
import CSECRootProtocol
import Foundation

// Streaming host-audit progress: the progress board's job lifecycle, the wire
// round-trip of the new start/poll verbs and the progress snapshot, and an
// end-to-end streaming run over a real agent socket. The board is driven by a
// fast, deterministic fake run (the real engine over an all-unavailable fake
// context, exactly like the registry smoke test) so these complete in
// milliseconds while still exercising true per-check progress.

/// A fast audit run for the board tests: real engine, fake context, real
/// per-check progress callbacks.
private let fakeAuditRun: HostAuditProgressBoard.RunAudit = { scanFilesystem, onProgress in
    await HostAuditEngine().run(
        makeAuditContext(scanFilesystem: scanFilesystem), onProgress: onProgress)
}

func hostAuditStreamingTests() async {
    await progressBoardTests()
    progressWireRoundTripTests()
}

// MARK: - board job lifecycle

private func progressBoardTests() async {
    let board = HostAuditProgressBoard(runAudit: fakeAuditRun)
    let total = HostCheckRegistry.all.count

    let startResponse = await board.start(HostAuditRequest())
    let jobID = startResponse.requestID ?? ""
    check(startResponse.hostAuditProgress?.total == total,
          "board: the start snapshot reports the full check total")
    check(startResponse.hostAuditProgress?.completed == 0,
          "board: the start snapshot begins at zero completed")
    check(startResponse.hostAuditProgress?.done == false,
          "board: the start snapshot is not done")
    check(startResponse.hostAuditReport == nil,
          "board: start does not carry a report yet")

    var last = 0
    var monotonic = true
    var valueFree = true
    var finalReport: HostAuditReport?
    var polls = 0
    while polls < 20_000 {
        polls += 1
        let response = await board.poll(HostAuditPollRequest(jobID: jobID))
        guard let snapshot = response.hostAuditProgress else {
            check(false, "board: poll returned no snapshot before completion")
            break
        }
        if snapshot.completed < last { monotonic = false }
        last = snapshot.completed
        if snapshot.currentTitle.unicodeScalars.contains(where: {
            CharacterSet.controlCharacters.contains($0)
        }) { valueFree = false }
        if snapshot.done, let report = response.hostAuditReport {
            finalReport = report
            break
        }
        await Task.yield()
    }
    check(monotonic, "board: the completed count is monotonic across polls")
    check(valueFree, "board: progress snapshots carry no control characters")
    check(finalReport?.findings.count == total,
          "board: the terminal poll delivers the full value-free report")

    // Deliver-once: a poll after completion finds the job retired.
    let afterDone = await board.poll(HostAuditPollRequest(jobID: jobID))
    check(afterDone.failure != nil,
          "board: a completed job is retired after its report is delivered")

    // An unknown job id fails closed rather than blocking or reporting a pass.
    let unknown = await board.poll(HostAuditPollRequest(jobID: "not-a-real-job"))
    check(unknown.failure != nil, "board: polling an unknown job id fails")
}

// MARK: - wire round-trips

private func progressWireRoundTripTests() {
    do {
        let start = Request.hostAuditStart(HostAuditRequest(scanFilesystem: true))
        let decodedStart = try JSONDecoder().decode(Request.self, from: JSONEncoder().encode(start))
        if case let .hostAuditStart(request) = decodedStart {
            check(request.scanFilesystem, "wire: host_audit_start round-trips scanFilesystem")
        } else {
            check(false, "wire: host_audit_start decoded to the wrong case")
        }

        let poll = Request.hostAuditPoll(HostAuditPollRequest(jobID: "job-123"))
        let decodedPoll = try JSONDecoder().decode(Request.self, from: JSONEncoder().encode(poll))
        if case let .hostAuditPoll(request) = decodedPoll {
            check(request.jobID == "job-123", "wire: host_audit_poll round-trips the jobID")
        } else {
            check(false, "wire: host_audit_poll decoded to the wrong case")
        }

        let snapshot = HostAuditProgressSnapshot(
            total: 81, completed: 40, currentID: "HA-D03", currentTitle: "Screen recording grants", done: false)
        let response = Response(requestID: "r", hostAuditProgress: snapshot)
        let decodedResponse = try JSONDecoder().decode(Response.self, from: JSONEncoder().encode(response))
        check(decodedResponse.hostAuditProgress == snapshot,
              "wire: Response.hostAuditProgress round-trips")
    } catch {
        check(false, "wire: host-audit streaming round-trip threw (\(error))")
    }
}

// MARK: - end-to-end over a real agent socket

func hostAuditStreamingSocketTests() {
    // A short base under /tmp: a unix socket path must fit in sun_path (~104
    // bytes), which the long per-user /var/folders temp dir would overflow.
    let base = URL(fileURLWithPath: "/tmp")
        .appendingPathComponent("cs-astream-\(UUID().uuidString)", isDirectory: true)
    let socketPath = base.appendingPathComponent("agent.sock").path
    do {
        try FileManager.default.createDirectory(
            atPath: base.path, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
    } catch {
        check(false, "streaming socket: temp dir setup threw (\(error))")
        return
    }
    defer { try? FileManager.default.removeItem(at: base) }

    let board = HostAuditProgressBoard(runAudit: fakeAuditRun)
    let server = SocketServer(path: socketPath, clientTrustPolicy: .allowUnverifiedForTesting) { request, _ in
        switch request {
        case let .hostAuditStart(request):
            return await board.start(request)
        case let .hostAuditPoll(request):
            return await board.poll(request)
        default:
            return .failed(.invalidRequest, message: "unexpected request in streaming test", requestID: nil)
        }
    }
    Thread.detachNewThread { try? server.run() }

    var waited = 0
    while !FileManager.default.fileExists(atPath: socketPath) && waited < 200 {
        usleep(10_000); waited += 1
    }

    let client = AgentClient(path: socketPath, serverTrustPolicy: .allowUnverifiedForTesting)
    do {
        let stream = try client.beginHostAudit(scanFilesystem: false)
        check(stream.snapshot.total == HostCheckRegistry.all.count,
              "streaming socket: the initial snapshot totals every registered check")
        var polls = 0
        while !stream.isDone && polls < 5_000 {
            polls += 1
            usleep(2_000)
            try stream.poll()
        }
        check(stream.isDone, "streaming socket: the audit reaches completion over the wire")
        check(stream.report?.findings.count == HostCheckRegistry.all.count,
              "streaming socket: the value-free report crosses back intact")
    } catch {
        check(false, "streaming socket: client stream threw (\(error))")
    }
}
