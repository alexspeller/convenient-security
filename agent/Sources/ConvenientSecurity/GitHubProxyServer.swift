import CSecuritySupport
import Foundation
import Network
#if canImport(Darwin)
import Darwin
#endif

// MARK: - Upstream connections

/// One connection from csecd to a GitHub host, carrying one request.
public protocol GitHubUpstreamConnection: Sendable {
    func send(_ data: Data) async throws
    /// The next bytes, or nil once the upstream has closed.
    func receive() async throws -> Data?
    func close()
}

public protocol GitHubUpstreamConnector: Sendable {
    func connect(host: String) async throws -> any GitHubUpstreamConnection
}

public enum GitHubUpstreamError: Error, Equatable, Sendable {
    case unreachable(String)
    case closed
    case stalled

    public var message: String {
        switch self {
        case let .unreachable(detail): return detail
        case .closed: return "the connection to GitHub closed early"
        case .stalled: return "the connection to GitHub went silent"
        }
    }
}

/// TLS to port 443 with the system's trust evaluation, HTTP/1.1 only.
public struct GitHubTLSUpstreamConnector: GitHubUpstreamConnector {
    /// How long a connection may take to become ready. It bounds one harm: a
    /// connection that never completes (no network, or a firewall holding it
    /// while it asks about csecd) would otherwise leave `gh` waiting with no
    /// answer at all.
    public static let connectDeadline: TimeInterval = 30

    public init() {}

    public func connect(host: String) async throws -> any GitHubUpstreamConnection {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        let parameters = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        return try await NetworkUpstreamConnection.open(
            NWConnection(host: NWEndpoint.Host(host), port: 443, using: parameters),
            host: host,
            deadline: Self.connectDeadline
        )
    }
}

/// Plain TCP to a loopback port: the fake GitHub of the integration tests.
public struct GitHubLoopbackUpstreamConnector: GitHubUpstreamConnector {
    let port: UInt16
    public init(port: UInt16) { self.port = port }

    public func connect(host: String) async throws -> any GitHubUpstreamConnection {
        guard let port = NWEndpoint.Port(rawValue: port) else { throw GitHubUpstreamError.unreachable("bad port") }
        return try await NetworkUpstreamConnection.open(
            NWConnection(host: "127.0.0.1", port: port, using: .tcp),
            host: host,
            deadline: GitHubTLSUpstreamConnector.connectDeadline
        )
    }
}

final class NetworkUpstreamConnection: GitHubUpstreamConnection, @unchecked Sendable {
    private let connection: NWConnection

    private init(_ connection: NWConnection) {
        self.connection = connection
    }

    static func open(_ connection: NWConnection, host: String, deadline: TimeInterval) async throws -> NetworkUpstreamConnection {
        let queue = DispatchQueue(label: "com.alexspeller.csecd.github-upstream")
        let gate = ResumeOnce()
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if gate.claim() { continuation.resume() }
                case let .failed(error), let .waiting(error):
                    // Waiting means no route right now (offline, or refused by a
                    // firewall): answer at once rather than hold `gh` open.
                    if gate.claim() {
                        connection.cancel()
                        continuation.resume(throwing: GitHubUpstreamError.unreachable(
                            "could not reach \(host): \(error.localizedDescription)"
                        ))
                    }
                case .cancelled:
                    if gate.claim() {
                        continuation.resume(throwing: GitHubUpstreamError.unreachable("could not reach \(host)"))
                    }
                default:
                    break
                }
            }
            connection.start(queue: queue)
            queue.asyncAfter(deadline: .now() + deadline) {
                if gate.claim() {
                    connection.cancel()
                    continuation.resume(throwing: GitHubUpstreamError.unreachable(
                        "timed out connecting to \(host) (check the network connection and whether a firewall is waiting for a decision about csecd)"
                    ))
                }
            }
        }
        return NetworkUpstreamConnection(connection)
    }

    // A connected server that stops reading or answering is cut off after
    // `GitHubProxyServer.silenceDeadline`, as a client is: a redirect can lead
    // to a host csecd does not trust to keep the exchange moving, and a stall
    // would otherwise hold this task and two descriptors for good.
    func send(_ data: Data) async throws {
        let connection = self.connection
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let gate = ResumeOnce()
            connection.send(content: data, completion: .contentProcessed { error in
                guard gate.claim() else { return }
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
            Self.cutOff(connection, gate: gate) { continuation.resume(throwing: GitHubUpstreamError.stalled) }
        }
    }

    func receive() async throws -> Data? {
        let connection = self.connection
        return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
            let gate = ResumeOnce()
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1_024) { data, _, isComplete, error in
                guard gate.claim() else { return }
                if let data, !data.isEmpty {
                    continuation.resume(returning: data)
                } else if isComplete {
                    continuation.resume(returning: nil)
                } else if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume(returning: Data())
                }
            }
            Self.cutOff(connection, gate: gate) { continuation.resume(throwing: GitHubUpstreamError.stalled) }
        }
    }

    private static func cutOff(_ connection: NWConnection, gate: ResumeOnce, _ resume: @escaping @Sendable () -> Void) {
        DispatchQueue.global().asyncAfter(deadline: .now() + GitHubProxyServer.silenceDeadline) {
            guard gate.claim() else { return }
            connection.cancel()
            resume()
        }
    }

    func close() {
        connection.cancel()
    }
}

private final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false

    func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}

// MARK: - The socket

public enum GitHubSocketPeerTrustPolicy: Sendable {
    /// Any process of the current user. Who asks is shown on the review and
    /// bounds the grant; the socket itself grants nothing.
    case currentUser
    /// Tests that inject callers without a kernel peer identity.
    case allowUnverifiedForTesting
}

/// csecd's GitHub socket. `gh` (or any client of an HTTP/1.1 Unix socket)
/// sends plaintext requests here with the placeholder token; csecd injects
/// the real token for approved callers and forwards over TLS to GitHub.
public final class GitHubProxyServer: @unchecked Sendable {
    public enum ServerError: Error { case bindFailed(String) }

    /// How long a connected client may say nothing before its request head
    /// arrives, and between body bytes. It bounds an abandoned connection; a
    /// request waiting on a human is not bounded by it.
    public static let silenceDeadline: TimeInterval = 60

    private let path: String
    private let service: GitHubProxyService
    private let authorizer: any GitHubTokenAuthorizer
    private let connector: any GitHubUpstreamConnector
    private let processInspection: ProcessInspection
    private let diagnostics: @Sendable (String) -> Void

    public init(
        path: String = GitHubProxySocket.defaultPath(),
        service: GitHubProxyService,
        authorizer: any GitHubTokenAuthorizer,
        connector: any GitHubUpstreamConnector = GitHubTLSUpstreamConnector(),
        processInspection: ProcessInspection = .live,
        diagnostics: @escaping @Sendable (String) -> Void = { line in
            FileHandle.standardError.write(Data((line + "\n").utf8))
        }
    ) {
        self.path = path
        self.service = service
        self.authorizer = authorizer
        self.connector = connector
        self.processInspection = processInspection
        self.diagnostics = diagnostics
    }

    /// How many client connections are served at once. Each holds two
    /// descriptors (the client's and GitHub's) for as long as its request
    /// lasts, and csecd's descriptors also serve every other socket, so a
    /// flood from one process must not exhaust them. gh opens a few at most.
    public static let maximumConnections = 32

    private let connectionLock = NSLock()
    private var connections = 0

    /// Binds the socket and serves until the process ends.
    public func run() throws {
        let listenFD = try bind()
        while true {
            let fd = cs_accept(listenFD)
            if fd < 0 {
                // Out of descriptors or memory: accepting again at once would
                // spin until something closes. EINTR and ECONNABORTED retry.
                if errno == EMFILE || errno == ENFILE || errno == ENOBUFS || errno == ENOMEM { usleep(100_000) }
                continue
            }
            accepted(fd: fd)
        }
    }

    /// Serves one accepted descriptor on its own task, or answers `503` and
    /// closes it when `maximumConnections` are already being served.
    public func accepted(fd: Int32) {
        guard admit() else {
            let response = GitHubProxyResponse.error(status: 503, message: "too many GitHub requests at once; try again")
            _ = writeExactly(fd, [UInt8](response))
            close(fd)
            return
        }
        Task.detached {
            await self.serve(fd: fd)
            self.release()
        }
    }

    /// How many connections are being served now.
    public var activeConnections: Int {
        connectionLock.lock(); defer { connectionLock.unlock() }
        return connections
    }

    private func admit() -> Bool {
        connectionLock.lock(); defer { connectionLock.unlock() }
        guard connections < Self.maximumConnections else { return false }
        connections += 1
        return true
    }

    private func release() {
        connectionLock.lock(); defer { connectionLock.unlock() }
        connections -= 1
    }

    /// Binds the socket; `serve(fd:)` each accepted descriptor. Separate from
    /// `run` so a test can serve on a background task.
    public func bind() throws -> Int32 {
        let listenFD = path.withCString { cs_listen_unix($0) }
        guard listenFD >= 0 else { throw ServerError.bindFailed(path) }
        _ = path.withCString { chmod($0, 0o600) }
        return listenFD
    }

    public func serve(fd: Int32) async {
        defer { close(fd) }
        // A client that stops reading fails csecd's write after the same
        // silence a client that stops sending gets, rather than holding it.
        var sendTimeout = timeval(tv_sec: Int(Self.silenceDeadline), tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &sendTimeout, socklen_t(MemoryLayout<timeval>.size))
        let lane = ConnectionLane("com.alexspeller.csecd.github.connection")
        guard let peer = await lane.run({ PeerIdentity.socketPeer(fd: fd) }), peer.isCurrentUser else { return }
        let caller = CallerInfo(
            pid: peer.audit.pid,
            startTime: peer.audit.startTime,
            description: peer.displayDescription,
            peerIdentity: peer
        )
        let reader = GitHubProxyClientReader(fd: fd, lane: lane)
        let exchange = GitHubProxyExchange(
            reader: reader, lane: lane, fd: fd, caller: caller,
            service: service, authorizer: authorizer, connector: connector,
            processInspection: processInspection, diagnostics: diagnostics
        )
        await exchange.run()
    }
}

// MARK: - One request

/// Reads a client connection's bytes on its lane, keeping what arrived after
/// the head for the body.
final class GitHubProxyClientReader: @unchecked Sendable {
    private let fd: Int32
    private let lane: ConnectionLane
    private(set) var buffered = Data()

    init(fd: Int32, lane: ConnectionLane) {
        self.fd = fd
        self.lane = lane
    }

    enum HeadOutcome {
        case head(Data)
        case tooLarge
        case closed
    }

    func readHead() async -> HeadOutcome {
        let terminator = Data("\r\n\r\n".utf8)
        while true {
            if let range = buffered.range(of: terminator) {
                let head = buffered[buffered.startIndex..<range.upperBound]
                buffered = Data(buffered[range.upperBound...])
                return .head(Data(head))
            }
            guard buffered.count < GitHubProxyHTTP.maximumHeadBytes else { return .tooLarge }
            guard let more = await readSome() else { return .closed }
            buffered.append(more)
        }
    }

    /// Takes up to `limit` bytes: first what is buffered, then from the socket.
    func take(upTo limit: Int) async -> Data? {
        if !buffered.isEmpty {
            let count = min(limit, buffered.count)
            let slice = Data(buffered.prefix(count))
            buffered = Data(buffered.dropFirst(count))
            return slice
        }
        return await readSome(limit: limit)
    }

    private func readSome(limit: Int = 64 * 1_024) async -> Data? {
        let fd = self.fd
        return await lane.run { () -> Data? in
            var waiter = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            while true {
                let ready = poll(&waiter, 1, Int32(GitHubProxyServer.silenceDeadline * 1_000))
                if ready < 0, errno == EINTR { continue }
                guard ready > 0 else { return nil }
                break
            }
            var bytes = [UInt8](repeating: 0, count: limit)
            while true {
                let count = read(fd, &bytes, limit)
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { return nil }
                return Data(bytes[0..<count])
            }
        }
    }
}

struct GitHubProxyExchange: Sendable {
    let reader: GitHubProxyClientReader
    let lane: ConnectionLane
    let fd: Int32
    let caller: CallerInfo
    let service: GitHubProxyService
    let authorizer: any GitHubTokenAuthorizer
    let connector: any GitHubUpstreamConnector
    let processInspection: ProcessInspection
    let diagnostics: @Sendable (String) -> Void

    private func respond(_ status: Int, _ message: String) async {
        let fd = self.fd
        let response = GitHubProxyResponse.error(status: status, message: message)
        _ = await lane.run { writeExactly(fd, [UInt8](response)) }
    }

    private func write(_ data: Data) async -> Bool {
        let fd = self.fd
        return await lane.run { writeExactly(fd, [UInt8](data)) }
    }

    private func note(_ reason: String) {
        diagnostics("csecd: GitHub proxy refused request (reason=\(reason) pid=\(caller.pid))")
    }

    func run() async {
        let head: GitHubProxyRequestHead
        switch await reader.readHead() {
        case .closed:
            return
        case .tooLarge:
            note("head_too_large")
            await respond(400, GitHubProxyRequestError.headTooLarge.message)
            return
        case let .head(bytes):
            do {
                head = try GitHubProxyRequestHead.parse(bytes)
            } catch let error as GitHubProxyRequestError {
                note("malformed_request")
                await respond(400, error.message)
                return
            } catch {
                await respond(400, "the request is malformed")
                return
            }
        }

        // Which token, if any, goes on this request.
        let hostClass = GitHubProxyHosts.classify(head.host)
        let wantsToken = head.credential == .placeholder && hostClass == .token
        if hostClass == .refused {
            guard await service.takeTicket(host: head.host, path: head.path, method: head.method, caller: caller) else {
                note("host_not_allowed")
                await respond(421, "csec's GitHub socket forwards only to GitHub (\(head.host) is not a GitHub host)")
                return
            }
        }

        // A small body is read whole first, however it is framed: once nothing
        // is queued on the socket, its closing is what tells a waiting review
        // its requester left, and what makes a request lasting can be in it.
        // `gh api --input -` sends its body chunked, since stdin has no length.
        var forwarded = head
        var body: Data?
        var chunkedPrefix: (output: Data, reframer: GitHubProxyChunkReframer)?
        switch head.framing {
        case .none:
            body = Data()
        case let .contentLength(length):
            guard length <= UInt64(GitHubProxyHTTP.maximumBufferedBodyBytes) else { break }
            var collected = Data()
            while UInt64(collected.count) < length {
                guard let more = await reader.take(upTo: Int(length) - collected.count) else { return }
                collected.append(more)
            }
            body = collected
        case .chunked:
            let read: ChunkedRead?
            do {
                read = try await readChunkedBody()
            } catch {
                note("malformed_chunked_body")
                await respond(400, "the chunked request body is malformed")
                return
            }
            switch read {
            case nil:
                return
            case let .whole(payload):
                body = payload
                forwarded = head.reframed(payload.isEmpty ? .none : .contentLength(UInt64(payload.count)))
            case let .partial(output, reframer):
                chunkedPrefix = (output, reframer)
            }
        }

        var token: Data?
        if wantsToken {
            guard let reference = await service.tokenReference else {
                note("not_registered")
                await respond(503, GitHubProxyError.notRegistered.message)
                return
            }
            // Judged on the request as GitHub will receive it, body included
            // when it was read: what makes a request lasting can be in either.
            let lasting = GitHubLastingAccess.classify(
                method: head.method, host: head.host, target: head.target, fields: head.fields, body: body
            )
            if let lasting {
                // Metadata only, so the log can say how often each kind asks.
                let unread = lasting.unreadBody.map { " unread=\($0.rawValue)" } ?? ""
                diagnostics("csecd: GitHub proxy lasting request (kind=\(lasting.kind.rawValue)\(unread) pid=\(caller.pid))")
            }
            let use = GitHubProxyUse(method: head.method, host: head.host, path: head.path, lastingAccess: lasting)
            switch await authorize(reference: reference, use: use) {
            case let .token(value):
                token = value
            case let .denied(message):
                await respond(403, message)
                return
            case nil:
                // The requester left while it waited: nobody is reading.
                return
            }
        }

        let upstream: any GitHubUpstreamConnection
        do {
            upstream = try await connector.connect(host: head.host)
        } catch let error as GitHubUpstreamError {
            note("upstream_unreachable")
            await respond(502, error.message)
            return
        } catch {
            note("upstream_unreachable")
            await respond(502, "could not reach \(head.host)")
            return
        }
        defer { upstream.close() }

        do {
            let upstreamHead = try forwarded.upstreamHead(token: token)
            token = nil
            if let body {
                try await upstream.send(upstreamHead + body)
            } else if let chunkedPrefix {
                try await upstream.send(upstreamHead + chunkedPrefix.output)
                guard try await streamChunked(chunkedPrefix.reframer, to: upstream) else { return }
            } else {
                try await upstream.send(upstreamHead)
                guard try await streamBody(head.framing, to: upstream) else { return }
            }
        } catch is GitHubProxyTokenError {
            note("malformed_token")
            await respond(502, GitHubProxyError.malformedToken.message)
            return
        } catch is GitHubProxyChunkError {
            note("malformed_chunked_body")
            await respond(400, "the chunked request body is malformed")
            return
        } catch {
            // The upstream may still have answered (a 413 before the whole
            // body was read): fall through and forward whatever it said.
        }

        // GitHub answers an authenticated request for a log or an artifact
        // with a redirect to its storage. The credential can be csecd's token
        // or the client's own: the client's takes precedence in `gh`, as an
        // `.envrc` `csec_GITHUB_TOKEN` does, and either way GitHub, not the
        // client, chose where the redirect leads.
        let followsRedirects = hostClass == .token && head.credential != .none
        await relayResponse(from: upstream, followsRedirects: followsRedirects, host: head.host)
    }

    /// The token for this request, the authorizer's refusal, or nil when the
    /// requester went away while the authorizer waited on a human.
    private func authorize(reference: SecretRef, use: GitHubProxyUse) async -> GitHubTokenAuthorization? {
        let authorizer = self.authorizer
        let caller = self.caller
        let work = Task { await authorizer.authorizeGitHubTokenUse(reference: reference, use: use, caller: caller) }
        let fd = self.fd
        let inspection = processInspection
        let gone = GitHubRequesterGoneFlag()
        let watch = Task.detached {
            while !Task.isCancelled {
                // Either signal will do: the socket closed with nothing
                // queued, or the process that opened it is no longer the one
                // that did.
                if peerHasClosed(fd) || inspection.startTime(of: caller.pid) != caller.startTime {
                    await gone.set()
                    work.cancel()
                    return
                }
                try? await Task.sleep(nanoseconds: UInt64(AgentLiveness.peerExitPollInterval * 1_000_000_000))
            }
        }
        let result = await work.value
        watch.cancel()
        if await gone.isSet { return nil }
        return result
    }

    enum ChunkedRead {
        /// The whole body, unframed.
        case whole(Data)
        /// A body longer than csecd reads first: what was read, re-framed for
        /// GitHub, and the reframer that carries on from there.
        case partial(output: Data, reframer: GitHubProxyChunkReframer)
    }

    /// Reads a chunked body until it ends or passes
    /// `GitHubProxyHTTP.maximumBufferedBodyBytes`; nil when the client went
    /// quiet or closed first. Throws on framing the reframer refuses.
    private func readChunkedBody() async throws -> ChunkedRead? {
        var reframer = GitHubProxyChunkReframer()
        var output = Data()
        var payload: Data? = Data()
        while !reframer.isComplete {
            guard let piece = await reader.take(upTo: 64 * 1_024) else { return nil }
            output.append(try reframer.consume(piece, payload: &payload).output)
            if let read = payload, read.count > GitHubProxyHTTP.maximumBufferedBodyBytes {
                return .partial(output: output, reframer: reframer)
            }
        }
        return .whole(payload ?? Data())
    }

    /// Forwards a body that was not read whole up front. False when the
    /// client went quiet or closed mid-body: nothing more can be sent.
    private func streamBody(_ framing: GitHubProxyRequestHead.BodyFraming, to upstream: any GitHubUpstreamConnection) async throws -> Bool {
        switch framing {
        case .none:
            return true
        case let .contentLength(length):
            var remaining = length
            while remaining > 0 {
                guard let piece = await reader.take(upTo: Int(min(remaining, 64 * 1_024))) else { return false }
                try await upstream.send(piece)
                remaining -= UInt64(piece.count)
            }
            return true
        case .chunked:
            return try await streamChunked(GitHubProxyChunkReframer(), to: upstream)
        }
    }

    private func streamChunked(_ start: GitHubProxyChunkReframer, to upstream: any GitHubUpstreamConnection) async throws -> Bool {
        var reframer = start
        while !reframer.isComplete {
            guard let piece = await reader.take(upTo: 64 * 1_024) else { return false }
            let (output, _) = try reframer.consume(piece)
            if !output.isEmpty { try await upstream.send(output) }
        }
        return true
    }

    private func relayResponse(from upstream: any GitHubUpstreamConnection, followsRedirects: Bool, host: String) async {
        let terminator = Data("\r\n\r\n".utf8)
        var pending = Data()
        // The head: parsed so that the client is told the connection closes
        // after this response, and so a redirect GitHub sent for an
        // authenticated request can be followed. Interim (1xx) heads pass
        // through first.
        while true {
            if let range = pending.range(of: terminator) {
                let headBytes = Data(pending[pending.startIndex..<range.upperBound])
                pending = Data(pending[range.upperBound...])
                guard let response = GitHubProxyResponseHead.parse(headBytes) else {
                    note("malformed_upstream_response")
                    await respond(502, "\(host) sent a response csec could not read")
                    return
                }
                // The ticket exists before the client sees the redirect: `gh`
                // follows it as soon as it has the head, on a new connection.
                if followsRedirects, response.isRedirect, let location = response.location {
                    await service.noteRedirect(location: location, caller: caller)
                }
                guard await write(response.forwarded) else { return }
                if response.isInterim { continue }
                break
            }
            guard pending.count < GitHubProxyHTTP.maximumHeadBytes else {
                note("upstream_head_too_large")
                await respond(502, "\(host) sent a response head csec could not read")
                return
            }
            guard let more = try? await upstream.receive() else {
                await respond(502, "\(host) closed the connection without a response")
                return
            }
            pending.append(more)
        }
        // The body, as GitHub framed it, until GitHub closes.
        if !pending.isEmpty { guard await write(pending) else { return } }
        while let more = try? await upstream.receive() {
            if more.isEmpty { continue }
            guard await write(more) else { return }
        }
    }
}

private actor GitHubRequesterGoneFlag {
    private(set) var isSet = false
    func set() { isSet = true }
}
