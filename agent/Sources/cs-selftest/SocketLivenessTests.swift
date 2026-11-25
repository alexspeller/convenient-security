import ConvenientSecurity
import CSecuritySupport
import Foundation
#if canImport(Darwin)
import Darwin
#endif

// Liveness of the authenticated agent socket: the opt-in server→client
// heartbeat, the client's bound on SILENCE (never on a human's wait), the bound
// on a connection that never sends its first frame (and the deliberate absence
// of one between later frames), the derived ceiling on a streaming audit, and
// the peer-exit watch that cancels a handler whose requester has gone away —
// on the csec socket and on the SSH agent socket alike.
//
// Everything here runs against a real socket. The client half always runs on a
// helper thread: a blocking client call on the main thread would also block the
// main actor, and the heartbeat emitter deliberately round-trips through the
// main actor, so an in-process test that blocked it would starve the very ticks
// it is trying to observe. (In the product, client and daemon are separate
// processes, so this only ever bites a test.) The same holds for a server's
// own process: csecd and cs-fake-agent run `SocketServer.run()` on a detached
// thread and keep the main thread serving the main actor, and any new fixture
// server must do the same, or its first request slower than the silence
// deadline fails as a wedged agent (cs-e2e's slow-agent check).

func socketLivenessTests() async {
    heartbeatFrameCodecTests()
    await heartbeatOptInTests()
    await firstFrameBoundTests()
    await sshFirstFrameBoundTests()
    auditStreamCeilingTests()
    await peerExitCancellationTests()
    await sshPeerExitCancellationTests()
    await quietConnectionTests()
    await sshQuietConnectionTests()
}

// MARK: - helpers

/// A short base under /tmp: a unix socket path must fit in `sun_path` (~104
/// bytes), which the long per-user /var/folders temp dir would overflow.
func makeLivenessSocketDirectory(_ tag: String) -> URL? {
    let base = URL(fileURLWithPath: "/tmp")
        .appendingPathComponent("cs-live-\(tag)-\(UUID().uuidString.prefix(8))", isDirectory: true)
    do {
        try FileManager.default.createDirectory(
            atPath: base.path, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        return base
    } catch {
        check(false, "liveness: temp dir setup threw (\(error))")
        return nil
    }
}

func waitForSocket(_ path: String) -> Bool {
    var waited = 0
    while !FileManager.default.fileExists(atPath: path) && waited < 400 {
        usleep(10_000)
        waited += 1
    }
    return FileManager.default.fileExists(atPath: path)
}

/// Run `body` on a helper thread and wait for it, yielding the main actor while
/// waiting so main-actor work (heartbeat hops) keeps running.
func offMainActor<T: Sendable>(
    timeoutSeconds: Double, _ body: @escaping @Sendable () -> T
) async -> T? {
    let box = ResultBox<T>()
    Thread.detachNewThread { box.set(body()) }
    let deadline = Date().addingTimeInterval(timeoutSeconds)
    while Date() < deadline {
        if let value = box.value { return value }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return box.value
}

private final class ResultBox<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: T?
    var value: T? { lock.lock(); defer { lock.unlock() }; return stored }
    func set(_ value: T) { lock.lock(); stored = value; lock.unlock() }
}

private final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var raised = false
    var isRaised: Bool { lock.lock(); defer { lock.unlock() }; return raised }
    func raise() { lock.lock(); raised = true; lock.unlock() }
}

// MARK: - (d) frame codec

private func heartbeatFrameCodecTests() {
    let beat = WireTransport.heartbeatFrame()
    check(WireTransport.isHeartbeat(beat),
          "liveness: a heartbeat frame round-trips as a heartbeat")
    check(!WireTransport.requestSupportsHeartbeats(beat),
          "liveness: a heartbeat frame is not mistaken for an opt-in request")

    // A real response must never look like a heartbeat — `Response` carries no
    // `type` key, so the discriminator cannot collide.
    if let response = try? JSONEncoder().encode(Response(requestID: "r", schemes: ["op"])) {
        check(!WireTransport.isHeartbeat(response),
              "liveness: a real response is never taken for a heartbeat")
    } else {
        check(false, "liveness: a response could not be encoded")
    }

    do {
        // The opt-in rides beside the verb's own keys in one JSON object, and an
        // older decoder (a keyed container) ignores the key it does not know.
        let optedIn = try WireTransport.encodeRequest(.schemes, supportsHeartbeats: true)
        check(WireTransport.requestSupportsHeartbeats(optedIn),
              "liveness: an opted-in request frame declares heartbeat support")
        if case .schemes = try JSONDecoder().decode(Request.self, from: optedIn) {
            check(true, "liveness: the opt-in key does not disturb request decoding")
        } else {
            check(false, "liveness: the opt-in key disturbed request decoding")
        }

        let plain = try WireTransport.encodeRequest(.schemes, supportsHeartbeats: false)
        check(!WireTransport.requestSupportsHeartbeats(plain),
              "liveness: a request that did not opt in declares no heartbeat support")
        let foreign = try JSONEncoder().encode(Request.schemes)
        check(!WireTransport.requestSupportsHeartbeats(foreign),
              "liveness: a request frame without the key never opts in")
    } catch {
        check(false, "liveness: transport encoding threw (\(error))")
    }
}

// MARK: - (a)(b)(c) heartbeats and the silence deadline

private func heartbeatOptInTests() async {
    // (a) A server that accepts and then never says anything at all.
    if let base = makeLivenessSocketDirectory("silent") {
        defer { try? FileManager.default.removeItem(at: base) }
        let socketPath = base.appendingPathComponent("agent.sock").path
        let listening = Flag()
        Thread.detachNewThread {
            let listenFD = socketPath.withCString { cs_listen_unix($0) }
            guard listenFD >= 0 else { return }
            listening.raise()
            // Accept and hold: the peer is connected, authenticated, and mute.
            while true {
                let fd = cs_accept(listenFD)
                if fd < 0 { continue }
                while true { sleep(60) }
            }
        }
        _ = waitForSocket(socketPath)
        check(listening.isRaised, "liveness: the mute stub is listening")

        let liveness = AgentLiveness.forTesting(silenceDeadline: 0.8)
        let started = Date()
        let outcome = await offMainActor(timeoutSeconds: 10) { () -> String in
            let client = AgentClient(
                path: socketPath, serverTrustPolicy: .allowUnverifiedForTesting,
                liveness: liveness)
            do {
                _ = try client.schemes()
                return "returned"
            } catch AgentClient.ClientError.daemonUnresponsive {
                return "unresponsive"
            } catch {
                return "other: \(error)"
            }
        }
        let elapsed = Date().timeIntervalSince(started)
        check(outcome == "unresponsive",
              "liveness: a daemon that accepts and never replies fails as unresponsive (got \(outcome ?? "nil"))")
        check(elapsed < 5,
              "liveness: the unresponsive failure lands on the deadline, not eventually")
    }

    // (b) A server whose handler takes far longer than the deadline. Heartbeats
    //     extend the wait without bound, so the reply still arrives.
    // (c) …and a request that did not opt in receives no heartbeat frame at all,
    //     even while that same slow handler runs.
    if let base = makeLivenessSocketDirectory("beat") {
        defer { try? FileManager.default.removeItem(at: base) }
        let socketPath = base.appendingPathComponent("agent.sock").path
        let liveness = AgentLiveness.forTesting(silenceDeadline: 0.8)
        let handlerSeconds = 2.5
        let server = SocketServer(
            path: socketPath, clientTrustPolicy: .allowUnverifiedForTesting, liveness: liveness
        ) { request, _ in
            // Stands in for a human staring at an approval prompt.
            try? await Task.sleep(nanoseconds: UInt64(handlerSeconds * 1_000_000_000))
            guard case .schemes = request else {
                return .failed(.invalidRequest, message: "unexpected request in liveness test")
            }
            return Response(schemes: ["op", "csec"])
        }
        Thread.detachNewThread { try? server.run() }
        guard waitForSocket(socketPath) else {
            check(false, "liveness: the heartbeat server never bound its socket")
            return
        }

        let started = Date()
        let optedIn = await offMainActor(timeoutSeconds: 20) { () -> String in
            let client = AgentClient(
                path: socketPath, serverTrustPolicy: .allowUnverifiedForTesting,
                liveness: liveness)
            do {
                return try client.schemes().joined(separator: ",")
            } catch {
                return "threw: \(error)"
            }
        }
        let waited = Date().timeIntervalSince(started)
        check(optedIn == "op,csec",
              "liveness: heartbeats extend a wait far past the deadline and the reply still lands (got \(optedIn ?? "nil"))")
        check(waited > liveness.silenceDeadline,
              "liveness: that wait really did exceed the silence deadline")

        // (c) The same slow handler, asked by a client that never opted in.
        let framesSeen = await offMainActor(timeoutSeconds: 20) { () -> String in
            let fd = socketPath.withCString { cs_connect_unix($0) }
            guard fd >= 0 else { return "connect failed" }
            defer { close(fd) }
            guard let encoded = try? JSONEncoder().encode(Request.schemes),
                  writeFrame(fd, encoded) else { return "write failed" }
            // Read frames with a bound far longer than the handler, and record
            // the kind of each one that arrives before the response.
            var heartbeats = 0
            while true {
                switch readFrame(fd, silence: handlerSeconds + 8) {
                case .timedOut: return "timed out after \(heartbeats) heartbeat(s)"
                case .closed: return "closed after \(heartbeats) heartbeat(s)"
                case let .frame(data):
                    if WireTransport.isHeartbeat(data) {
                        heartbeats += 1
                        continue
                    }
                    return "response after \(heartbeats) heartbeat(s)"
                }
            }
        }
        check(framesSeen == "response after 0 heartbeat(s)",
              "liveness: a client that did not opt in is never sent a heartbeat (got \(framesSeen ?? "nil"))")
    }
}

// MARK: - the first frame, and only the first

private func firstFrameBoundTests() async {
    guard let base = makeLivenessSocketDirectory("first") else { return }
    defer { try? FileManager.default.removeItem(at: base) }
    let socketPath = base.appendingPathComponent("agent.sock").path
    let liveness = AgentLiveness.forTesting(silenceDeadline: 5, firstFrameDeadline: 0.5)
    let server = SocketServer(
        path: socketPath, clientTrustPolicy: .allowUnverifiedForTesting, liveness: liveness
    ) { _, _ in Response(schemes: ["op"]) }
    Thread.detachNewThread { try? server.run() }
    guard waitForSocket(socketPath) else {
        check(false, "liveness: the first-frame server never bound its socket")
        return
    }

    // A client that connects and says nothing is reaped.
    let reaped = await offMainActor(timeoutSeconds: 15) { () -> Bool in
        let fd = socketPath.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { return false }
        defer { close(fd) }
        // The server closing its end makes this read return EOF.
        return readFrame(fd, silence: 8) == .closed
    }
    check(reaped == true, "liveness: a peer that connects and never speaks is reaped")

    // An established connection that idles far beyond that bound is NOT reaped:
    // the AI output broker holds one open across long silent stretches.
    let streamed = await offMainActor(timeoutSeconds: 20) { () -> String in
        let fd = socketPath.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { return "connect failed" }
        defer { close(fd) }
        guard let encoded = try? WireTransport.encodeRequest(.schemes, supportsHeartbeats: true),
              writeFrame(fd, encoded) else { return "first write failed" }
        guard case .frame = readFrame(fd, silence: 8) else { return "no first response" }
        // Idle for several times the first-frame bound.
        Thread.sleep(forTimeInterval: 2.0)
        guard writeFrame(fd, encoded) else { return "second write failed" }
        guard case let .frame(data) = readFrame(fd, silence: 8) else { return "no second response" }
        let response = try? JSONDecoder().decode(Response.self, from: data)
        return response?.schemes == ["op"] ? "served" : "bad second response"
    }
    check(streamed == "served",
          "liveness: an established connection idle past the first-frame bound is not reaped (got \(streamed ?? "nil"))")
}

// MARK: - the same bound on the SSH agent socket

private func sshFirstFrameBoundTests() async {
    guard let base = makeLivenessSocketDirectory("ssh") else { return }
    defer { try? FileManager.default.removeItem(at: base) }
    let socketPath = base.appendingPathComponent("ssh.sock").path
    let server = SSHAgentServer(
        path: socketPath,
        trustPolicy: .allowUnverifiedForTesting,
        provider: EmptySSHKeyProvider(),
        firstFrameDeadline: 0.5
    )
    Thread.detachNewThread { try? server.run() }
    guard waitForSocket(socketPath) else {
        check(false, "liveness: the SSH first-frame server never bound its socket")
        return
    }

    let reaped = await offMainActor(timeoutSeconds: 15) { () -> Bool in
        let fd = socketPath.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { return false }
        defer { close(fd) }
        return readFrame(fd, silence: 8) == .closed
    }
    check(reaped == true, "liveness: an SSH peer that connects and never speaks is reaped")

    // One `ssh` session holds the agent connection open across a long transfer
    // and may go quiet between signatures; that gap must not be bounded.
    let streamed = await offMainActor(timeoutSeconds: 20) { () -> String in
        let fd = socketPath.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { return "connect failed" }
        defer { close(fd) }
        // SSH_AGENTC_REQUEST_IDENTITIES is a single byte.
        let request = Data([11])
        guard writeFrame(fd, request) else { return "first write failed" }
        guard case .frame = readFrame(fd, silence: 8) else { return "no first answer" }
        Thread.sleep(forTimeInterval: 2.0)
        guard writeFrame(fd, request) else { return "second write failed" }
        guard case let .frame(answer) = readFrame(fd, silence: 8) else { return "no second answer" }
        // 12 is SSH_AGENT_IDENTITIES_ANSWER.
        return answer.first == 12 ? "served" : "unexpected answer"
    }
    check(streamed == "served",
          "liveness: an established SSH connection idle past the bound is not reaped (got \(streamed ?? "nil"))")
}

// MARK: - quiet connections never starve the daemon

/// More open connections than Swift's cooperative pool has threads (one per
/// CPU). A connection blocked in a socket call must cost a thread of its own,
/// never one of the pool's: csecd once parked a pool thread in read(2) per
/// quiet csec ai, and sixteen quiet commands left it accepting connections it
/// never answered.
private var crowdSize: Int { ProcessInfo.processInfo.activeProcessorCount + 4 }

/// Connects and sends `request`, then hands the open descriptor to `settle`,
/// which says whether the connection reached the state under test.
private func crowd(
    _ socketPath: String, size: Int, request: Data, settle: (Int32) -> Bool
) -> (opened: [Int32], failedAt: Int?) {
    var opened: [Int32] = []
    for index in 0..<size {
        let fd = socketPath.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { return (opened, index) }
        opened.append(fd)
        guard writeFrame(fd, request), settle(fd) else { return (opened, index) }
    }
    return (opened, nil)
}

private func quietConnectionTests() async {
    guard let base = makeLivenessSocketDirectory("quiet") else { return }
    defer { try? FileManager.default.removeItem(at: base) }
    let socketPath = base.appendingPathComponent("agent.sock").path
    let liveness = AgentLiveness.forTesting(silenceDeadline: 5, firstFrameDeadline: 5)
    // The first `size` answers are far larger than a socket buffer, so a client
    // that never reads leaves the server's write blocked; every later answer
    // is small.
    let size = crowdSize
    let answered = Counter()
    let server = SocketServer(
        path: socketPath, clientTrustPolicy: .allowUnverifiedForTesting, liveness: liveness
    ) { _, _ in
        answered.next() < size
            ? Response(schemes: Array(repeating: String(repeating: "x", count: 1_000), count: 1_000))
            : Response(schemes: ["op"])
    }
    Thread.detachNewThread { try? server.run() }
    guard waitForSocket(socketPath) else {
        check(false, "liveness: the quiet-connection server never bound its socket")
        return
    }
    guard let request = try? WireTransport.encodeRequest(.schemes, supportsHeartbeats: false) else {
        check(false, "liveness: the quiet-connection request could not be encoded")
        return
    }
    // Everything runs on one helper thread and every descriptor is closed
    // before it returns: a starved pool frees itself once its peers hang up,
    // so the rest of the self-test is never left without threads.
    @Sendable func probe() -> String {
        let fd = socketPath.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { return "connect failed" }
        defer { close(fd) }
        guard writeFrame(fd, request) else { return "write failed" }
        guard case let .frame(data) = readFrame(fd, silence: 10) else { return "starved" }
        return (try? JSONDecoder().decode(Response.self, from: data))?.schemes == ["op"] ? "served" : "bad answer"
    }

    // (a) Clients that never read their answer: the server is stuck writing.
    let stuckWriting = await offMainActor(timeoutSeconds: 120) { () -> String in
        let (opened, failedAt) = crowd(socketPath, size: size, request: request) { fd in
            // Bytes waiting means the handler ran and the write has begun.
            var waiter = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            return poll(&waiter, 1, 10_000) == 1
        }
        defer { opened.forEach { close($0) } }
        if let failedAt { return "never answered client \(failedAt + 1) of \(size)" }
        return probe()
    }
    check(stuckWriting == "served",
          "liveness: \(size) clients that never read their answers leave a new client served (got \(stuckWriting ?? "nil"))")

    // (b) Streaming clients that were answered and then go quiet, as a csec ai
    //     does while its command produces no output: the server waits to read.
    let quietReading = await offMainActor(timeoutSeconds: 120) { () -> String in
        let (opened, failedAt) = crowd(socketPath, size: size, request: request) { fd in
            guard case .frame = readFrame(fd, silence: 10) else { return false }
            return true
        }
        defer { opened.forEach { close($0) } }
        if let failedAt { return "never answered client \(failedAt + 1) of \(size)" }
        return probe()
    }
    check(quietReading == "served",
          "liveness: \(size) quiet streaming clients leave a new client served (got \(quietReading ?? "nil"))")
}

private func sshQuietConnectionTests() async {
    guard let base = makeLivenessSocketDirectory("sshquiet") else { return }
    defer { try? FileManager.default.removeItem(at: base) }
    let socketPath = base.appendingPathComponent("ssh.sock").path
    let server = SSHAgentServer(
        path: socketPath,
        trustPolicy: .allowUnverifiedForTesting,
        provider: EmptySSHKeyProvider(),
        firstFrameDeadline: 5
    )
    Thread.detachNewThread { try? server.run() }
    guard waitForSocket(socketPath) else {
        check(false, "liveness: the SSH quiet-connection server never bound its socket")
        return
    }
    let size = crowdSize
    // One `ssh` session holds its agent connection open between signatures.
    let outcome = await offMainActor(timeoutSeconds: 120) { () -> String in
        // SSH_AGENTC_REQUEST_IDENTITIES; 12 is SSH_AGENT_IDENTITIES_ANSWER.
        let request = Data([11])
        let (opened, failedAt) = crowd(socketPath, size: size, request: request) { fd in
            guard case let .frame(answer) = readFrame(fd, silence: 10) else { return false }
            return answer.first == 12
        }
        defer { opened.forEach { close($0) } }
        if let failedAt { return "never answered ssh \(failedAt + 1) of \(size)" }
        let fd = socketPath.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { return "connect failed" }
        defer { close(fd) }
        guard writeFrame(fd, request), case let .frame(answer) = readFrame(fd, silence: 10) else { return "starved" }
        return answer.first == 12 ? "served" : "unexpected answer"
    }
    check(outcome == "served",
          "liveness: \(size) quiet ssh connections leave a new ssh served (got \(outcome ?? "nil"))")
}

private final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    /// The count before this call.
    func next() -> Int { lock.lock(); defer { count += 1; lock.unlock() }; return count }
}

/// An SSH key provider with nothing in it: these tests exercise the connection
/// lifetime, never signing.
private struct EmptySSHKeyProvider: SSHAgentKeyProvider {
    func listedSSHKeys() async throws -> [SSHKeyMetadata] { [] }
    func signSSHAuthentication(
        publicKeyBlob: Data,
        signedData: Data,
        flags: UInt32,
        binding: SSHDestinationBinding,
        caller: CallerInfo
    ) async throws -> Data {
        throw SSHProtectionError.keyNotRegistered
    }
}

// MARK: - the audit poll ceiling

private func auditStreamCeilingTests() {
    // Derived from the engine's real structure, not picked: worst-case waves of
    // one per-command timeout each, tripled.
    let waves = ceil(
        Double(HostCheckRegistry.all.count) / Double(HostAuditEngine.maximumConcurrentChecks)
    )
    let worstLegitimate = waves * SystemCommandRunner.defaultTimeout
    check(HostAuditEngine.streamingCeilingSeconds == 3 * worstLegitimate,
          "audit ceiling: derived from the check count, the concurrency, and the command timeout")
    check(HostAuditEngine.streamingCeilingSeconds > worstLegitimate,
          "audit ceiling: leaves headroom above the worst legitimate full audit")
    check(HostAuditEngine.streamingCeilingSeconds < 3600,
          "audit ceiling: still finite enough to end a dead job in one sitting")
}

// MARK: - peer-exit cancellation (the source csec-1xv.11 builds on)

private func peerExitCancellationTests() async {
    guard let base = makeLivenessSocketDirectory("exit") else { return }
    defer { try? FileManager.default.removeItem(at: base) }
    let socketPath = base.appendingPathComponent("agent.sock").path
    let started = Flag()
    let cancelled = Flag()
    let liveness = AgentLiveness.forTesting(silenceDeadline: 30)
    let server = SocketServer(
        path: socketPath, clientTrustPolicy: .allowUnverifiedForTesting, liveness: liveness
    ) { request, _ in
        guard case .schemes = request else {
            return .failed(.invalidRequest, message: "unexpected request in cancellation test")
        }
        return Response(schemes: ["op"])
    }
    let slowServer = SocketServer(
        path: base.appendingPathComponent("slow.sock").path,
        clientTrustPolicy: .allowUnverifiedForTesting, liveness: liveness
    ) { _, _ in
        // Stands in for a review window waiting on a human.
        started.raise()
        for _ in 0..<600 {
            if Task.isCancelled {
                cancelled.raise()
                return .failed(.consentDenied, message: "requester went away")
            }
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        return Response(schemes: ["op"])
    }
    Thread.detachNewThread { try? server.run() }
    Thread.detachNewThread { try? slowServer.run() }
    let slowPath = base.appendingPathComponent("slow.sock").path
    guard waitForSocket(socketPath), waitForSocket(slowPath) else {
        check(false, "liveness: the cancellation servers never bound their sockets")
        return
    }

    // A requester that sends and then vanishes while its handler runs cancels
    // the handler. It goes once the handler has started, not after a fixed
    // pause: on a loaded Mac the server can take longer than any pause to
    // read the frame, and then no handler is running to be cancelled.
    _ = await offMainActor(timeoutSeconds: 20) { () -> Bool in
        let fd = slowPath.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { return false }
        guard let encoded = try? WireTransport.encodeRequest(.schemes, supportsHeartbeats: true),
              writeFrame(fd, encoded) else { close(fd); return false }
        let deadline = Date().addingTimeInterval(15)
        while !started.isRaised && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        close(fd)
        return true
    }
    check(started.isRaised, "liveness: the slow handler starts for a requester that is still connected")
    var waited = 0
    while !cancelled.isRaised && waited < 400 {
        try? await Task.sleep(nanoseconds: 20_000_000)
        waited += 1
    }
    check(cancelled.isRaised,
          "liveness: a handler whose requester closed the connection is cancelled")

    // A requester that stays connected is NOT cancelled, even though its
    // handler is slow.
    let stayed = Flag()
    let notCancelled = await offMainActor(timeoutSeconds: 20) { () -> String in
        let fd = socketPath.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { return "connect failed" }
        defer { close(fd) }
        guard let encoded = try? WireTransport.encodeRequest(.schemes, supportsHeartbeats: true),
              writeFrame(fd, encoded) else { return "write failed" }
        guard case let .frame(data) = readFrame(fd, silence: 10),
              (try? JSONDecoder().decode(Response.self, from: data))?.schemes == ["op"] else {
            return "no response"
        }
        stayed.raise()
        return "served"
    }
    check(notCancelled == "served" && stayed.isRaised,
          "liveness: a requester that stays connected is served, not cancelled")

    // A streaming client with a second frame already queued is alive, and the
    // peer-exit peek must not have eaten that frame.
    let pipelined = await offMainActor(timeoutSeconds: 20) { () -> String in
        let fd = socketPath.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { return "connect failed" }
        defer { close(fd) }
        guard let encoded = try? WireTransport.encodeRequest(.schemes, supportsHeartbeats: true)
        else { return "encode failed" }
        // Both frames go out before the first response comes back, so the second
        // is sitting in the server's receive buffer while the first is handled.
        guard writeFrame(fd, encoded), writeFrame(fd, encoded) else { return "write failed" }
        var served = 0
        while served < 2 {
            guard case let .frame(data) = readFrame(fd, silence: 10) else {
                return "only \(served) response(s)"
            }
            if WireTransport.isHeartbeat(data) { continue }
            guard (try? JSONDecoder().decode(Response.self, from: data))?.schemes == ["op"] else {
                return "bad response \(served)"
            }
            served += 1
        }
        return "served 2"
    }
    check(pipelined == "served 2",
          "liveness: a queued second frame survives the peer-exit peek intact (got \(pipelined ?? "nil"))")
}

// MARK: - SSH peer-exit cancellation (ssh-duplicates.md §9, T7–T10)

private final class LineCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var lines: [String] = []
    func append(_ line: String) { lock.lock(); lines.append(line); lock.unlock() }
    func contains(_ fragment: String) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return lines.contains { $0.contains(fragment) }
    }
}

/// Connect, bind the session, and send the signing request without waiting for
/// its answer. Returns the open descriptor.
private func sendSSHSign(_ socketPath: String, _ fixture: SSHSocketSigningFixture) -> Int32? {
    let fd = socketPath.withCString { cs_connect_unix($0) }
    guard fd >= 0 else { return nil }
    guard writeFrame(fd, fixture.bindMessage),
          case let .frame(bound) = readFrame(fd, silence: 8), bound == Data([6]),
          writeFrame(fd, fixture.signMessage) else {
        close(fd)
        return nil
    }
    return fd
}

/// The twin of `peerExitCancellationTests` for the SSH agent socket: an `ssh`
/// that goes away while its signing review waits, or is on screen, is never
/// answered and never shown.
private func sshPeerExitCancellationTests() async {
    guard let base = makeLivenessSocketDirectory("sshexit") else { return }
    defer { try? FileManager.default.removeItem(at: base) }
    let gate = GatedPolicyReview()
    let fixture: SSHSocketSigningFixture
    do {
        fixture = try await SSHSocketSigningFixture.make(
            policyReview: QueuedPolicyReview(underlying: gate, queue: ConsentQueue())
        )
    } catch {
        check(false, "liveness: the SSH signing fixture builds (\(error))")
        return
    }
    let diagnostics = LineCapture()
    let socketPath = base.appendingPathComponent("ssh.sock").path
    let server = SSHAgentServer(
        path: socketPath,
        trustPolicy: .allowUnverifiedForTesting,
        provider: fixture.service,
        diagnostics: { diagnostics.append($0) }
    )
    Thread.detachNewThread { try? server.run() }
    guard waitForSocket(socketPath) else {
        check(false, "liveness: the SSH peer-exit server never bound its socket")
        return
    }

    func eventually(seconds: Double, _ condition: () async -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if await condition() { return true }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return await condition()
    }

    // T7: the review is on screen when its ssh goes away. It is cancelled
    // within two peer-exit polls, and no key is resolved or signature written.
    let first = await offMainActor(timeoutSeconds: 10) { sendSSHSign(socketPath, fixture) }
    guard let firstFD = first ?? nil else {
        check(false, "liveness: an SSH client binds and asks for a signature")
        return
    }
    check(await eventually(seconds: 5) { await gate.pendingCount == 1 },
          "liveness: the SSH signing review is on screen")
    close(firstFD)
    let closedAt = Date()
    let cancelled = await eventually(seconds: 10) { await gate.cancelledReviews == 1 }
    let cancelSeconds = Date().timeIntervalSince(closedAt)
    check(cancelled && cancelSeconds <= 2 * AgentLiveness.peerExitPollInterval,
          "T7: an SSH review whose ssh closed its connection is cancelled within two peer-exit polls "
              + "(\(String(format: "%.2f", cancelSeconds)) s)")
    check(await fixture.resolutions.value() == 0,
          "T7: a cancelled SSH review resolves no key and signs nothing")
    // T10: the refusal is logged as the requester going away.
    check(await eventually(seconds: 5) { diagnostics.contains("reason=requester_gone") },
          "T10: the SSH refusal for a vanished ssh says reason=requester_gone")

    // T8: a request queued behind another review, whose ssh goes away while it
    // waits, is never presented once the first review is answered.
    let holding = await offMainActor(timeoutSeconds: 10) { sendSSHSign(socketPath, fixture) }
    guard let holdingFD = holding ?? nil else {
        check(false, "liveness: a second SSH client asks for a signature")
        return
    }
    defer { close(holdingFD) }
    check(await eventually(seconds: 5) { await gate.pendingCount == 1 },
          "liveness: the first of two SSH reviews is on screen")
    let queued = await offMainActor(timeoutSeconds: 10) { sendSSHSign(socketPath, fixture) }
    guard let queuedFD = queued ?? nil else {
        check(false, "liveness: a queued SSH client asks for a signature")
        return
    }
    check(await eventually(seconds: 5) { await fixture.reviewTurns.waitingCount == 1 },
          "liveness: the second SSH request waits for the review turn")
    close(queuedFD)
    check(await eventually(seconds: 2 * AgentLiveness.peerExitPollInterval + 1) {
        await fixture.reviewTurns.waitingCount == 0
    }, "T8: a queued SSH request whose ssh went away leaves the review turn")
    // Not a human decision, so it neither propagates nor ends this process's
    // signing (every client here is this same test process).
    await gate.decide(.deny(.authenticationFailed))
    let answered = await offMainActor(timeoutSeconds: 10) { () -> Bool in
        if case let .frame(answer) = readFrame(holdingFD, silence: 8) { return answer == Data([5]) }
        return false
    }
    check(answered == true, "liveness: the held SSH review is answered")
    // Had the vanished request still been queued, it would take the turn now
    // and be presented as a third review. Give it well over the time that
    // takes, then require that nothing further was shown.
    try? await Task.sleep(nanoseconds: 500_000_000)
    let reviews = await gate.reviews
    let pending = await gate.pendingCount
    check(reviews == 2 && pending == 0,
          "T8: an SSH request that went away while queued is never presented "
              + "(reviews: \(reviews), pending: \(pending))")
    // The turn is free again: a later request is presented at once.
    let later = await offMainActor(timeoutSeconds: 10) { sendSSHSign(socketPath, fixture) }
    guard let laterFD = later ?? nil else {
        check(false, "liveness: a later SSH client asks for a signature")
        return
    }
    defer { close(laterFD) }
    check(await eventually(seconds: 5) { await gate.pendingCount == 1 },
          "liveness: a later SSH review is on screen")
    await gate.decideAll(.deny(.authenticationFailed))
}
