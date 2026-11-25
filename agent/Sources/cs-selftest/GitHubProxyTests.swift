import ConvenientSecurity
import CSECRemoteApproval
import CSecuritySupport
import Darwin
import Foundation

// The GitHub token proxy: gh's requests arrive on csecd's socket with a
// placeholder token; csecd puts the real token on approved requests to GitHub
// hosts and forwards them on a fresh upstream connection. These checks cover
// the parser's refusals, the host policy, the redirect tickets, a live socket
// exchange against a fake GitHub, the Agent authorization path with references
// from two schemes, and the real `gh` end to end when it is installed.

private let fixtureToken = "gho_csecFixtureToken0123456789abcdef"

func gitHubProxyTests() async {
    print("\n# GitHub token proxy")
    gitHubRequestParserTests()
    gitHubLastingAccessTests()
    gitHubHostPolicyTests()
    gitHubDecisionLogClassTests()
    gitHubChunkReframerTests()
    gitHubResponseHeadTests()
    gitHubTokenShapeTests()
    await gitHubRedirectTicketTests()
    await gitHubProxySocketTests()
    await gitHubProxyAgentTests()
    await gitHubProxyRealGHTests()
}

private func head(_ text: String) -> Data { Data(text.replacingOccurrences(of: "\n", with: "\r\n").utf8) }

private func parses(_ text: String) -> GitHubProxyRequestHead? { try? GitHubProxyRequestHead.parse(head(text)) }

private func refusal(_ text: String) -> GitHubProxyRequestError? {
    do {
        _ = try GitHubProxyRequestHead.parse(head(text))
        return nil
    } catch let error as GitHubProxyRequestError {
        return error
    } catch {
        return nil
    }
}

// MARK: - Request parsing

private func gitHubRequestParserTests() {
    let placeholder = GitHubProxyHTTP.placeholderToken
    guard let get = parses("""
        GET /repos/o/r/pulls?state=open HTTP/1.1
        Host: api.github.com
        User-Agent: GitHub CLI 2.101.0
        Authorization: token \(placeholder)
        Accept-Encoding: gzip
        Connection: keep-alive, X-Hop
        X-Hop: dropped
        Keep-Alive: timeout=5
        Expect: 100-continue


        """.replacingOccurrences(of: "\n\n\n", with: "\n\n")) else {
        check(false, "github proxy: a gh GET with the placeholder parses")
        return
    }
    check(get.host == "api.github.com" && get.credential == .placeholder && get.framing == .none
            && get.path == "/repos/o/r/pulls",
          "github proxy: the placeholder is recognized and the path drops the query")
    let upstream = String(decoding: (try? get.upstreamHead(token: Data(fixtureToken.utf8))) ?? Data(), as: UTF8.self)
    check(upstream.hasPrefix("GET /repos/o/r/pulls?state=open HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: token \(fixtureToken)\r\n")
            && upstream.hasSuffix("Connection: close\r\n\r\n"),
          "github proxy: the upstream head carries the token and closes after one request")
    check(!upstream.contains(placeholder) && !upstream.lowercased().contains("keep-alive")
            && !upstream.contains("X-Hop") && !upstream.contains("Expect"),
          "github proxy: the placeholder and every connection header are dropped")
    check(upstream.contains("User-Agent: GitHub CLI 2.101.0\r\n") && upstream.contains("Accept-Encoding: gzip\r\n"),
          "github proxy: end-to-end headers pass through as sent")

    let bare = String(decoding: (try? get.upstreamHead(token: nil)) ?? Data(), as: UTF8.self)
    check(!bare.contains("Authorization"), "github proxy: a placeholder with no token sends no Authorization at all")

    if let own = parses("""
        GET /user HTTP/1.1
        Host: api.github.com
        Authorization: Bearer ghp_theirOwnToken


        """.replacingOccurrences(of: "\n\n\n", with: "\n\n")) {
        let forwarded = String(decoding: (try? own.upstreamHead(token: nil)) ?? Data(), as: UTF8.self)
        check(own.credential == .other("Bearer ghp_theirOwnToken")
                && forwarded.contains("Authorization: Bearer ghp_theirOwnToken\r\n"),
              "github proxy: a credential the client brought is forwarded as sent")
    } else {
        check(false, "github proxy: a request with its own credential parses")
    }

    if let post = parses("POST /graphql HTTP/1.1\nHost: api.github.com:443\nContent-Length: 42\n\n") {
        check(post.framing == .contentLength(42) && post.host == "api.github.com",
              "github proxy: Content-Length framing; :443 is the same host")
        let text = String(decoding: (try? post.upstreamHead(token: nil)) ?? Data(), as: UTF8.self)
        check(text.contains("Content-Length: 42\r\n"), "github proxy: the length csecd counted is the one sent")
    } else {
        check(false, "github proxy: a POST with Content-Length parses")
    }
    if let chunked = parses("PUT /x HTTP/1.1\nHost: uploads.github.com\nTransfer-Encoding: Chunked\n\n") {
        check(chunked.framing == .chunked, "github proxy: chunked framing is recognized")
    } else {
        check(false, "github proxy: a chunked PUT parses")
    }
    if let empty = parses("POST /x HTTP/1.1\nHost: api.github.com\n\n") {
        let text = String(decoding: (try? empty.upstreamHead(token: nil)) ?? Data(), as: UTF8.self)
        check(text.contains("Content-Length: 0\r\n"), "github proxy: a bodiless POST says so")
    }

    let refused: [(String, GitHubProxyRequestError, String)] = [
        ("POST /x HTTP/1.1\nHost: api.github.com\nContent-Length: 4\nTransfer-Encoding: chunked\n\n",
         .conflictingFraming, "both Content-Length and Transfer-Encoding"),
        ("POST /x HTTP/1.1\nHost: api.github.com\nContent-Length: 4\nContent-Length: 4\n\n",
         .invalidContentLength, "a repeated Content-Length, even an identical one"),
        ("POST /x HTTP/1.1\nHost: api.github.com\nContent-Length: +4\n\n",
         .invalidContentLength, "a signed Content-Length"),
        ("POST /x HTTP/1.1\nHost: api.github.com\nTransfer-Encoding: gzip, chunked\n\n",
         .unsupportedTransferEncoding, "a coding other than chunked"),
        ("GET /x HTTP/1.1\nHost: api.github.com\nHost: evil.example\n\n",
         .duplicateHost, "two Hosts"),
        ("GET /x HTTP/1.1\nAccept: */*\n\n", .missingHost, "no Host"),
        ("GET /x HTTP/1.1\nHost: api.github.com:8443\n\n", .invalidHost, "a port other than 443"),
        ("GET /x HTTP/1.1\nHost: api.github.com\nUpgrade: websocket\n\n", .unsupportedUpgrade, "an upgrade"),
        ("GET http://api.github.com/x HTTP/1.1\nHost: api.github.com\n\n", .malformedTarget, "an absolute-form target"),
        ("GET //evil.example/x HTTP/1.1\nHost: api.github.com\n\n", .malformedTarget, "a scheme-relative target"),
        ("GET /x HTTP/1.0\nHost: api.github.com\n\n", .unsupportedVersion, "HTTP/1.0"),
        ("CONNECT /x HTTP/1.1\nHost: api.github.com\n\n", .unsupportedMethod, "CONNECT"),
        ("GET /x HTTP/1.1\nHost: api.github.com\nX-A: one\n folded\n\n", .malformedHeader, "an obs-fold continuation"),
        ("GET /x HTTP/1.1\nHost: api.github.com\nX-A : spaced\n\n", .malformedHeader, "whitespace before a colon"),
        ("GET /x HTTP/1.1\nHost: api.github.com\nAuthorization: token a\nAuthorization: token b\n\n",
         .duplicateAuthorization, "two Authorization headers"),
        ("GET /x HTTP/1.1\nHost: api.github.com\nAuthorization: Basic x\(placeholder)\n\n",
         .malformedAuthorization, "the placeholder in a form csecd does not recognize"),
    ]
    for (text, expected, label) in refused {
        let got = refusal(text)
        check(got == expected, "github proxy: refuses \(label) (got \(got.map { "\($0)" } ?? "a parse"))")
    }
    let bareLF = Data("GET /x HTTP/1.1\nHost: api.github.com\r\n\r\n".utf8)
    check((try? GitHubProxyRequestHead.parse(bareLF)) == nil, "github proxy: refuses a bare LF line ending")
    let embeddedCR = Data("GET /x HTTP/1.1\r\nHost: api.github.com\r\nX-A: a\rb\r\n\r\n".utf8)
    check((try? GitHubProxyRequestHead.parse(embeddedCR)) == nil, "github proxy: refuses a bare CR inside a field")
    let oversized = Data(("GET /x HTTP/1.1\r\nHost: api.github.com\r\nX-A: " + String(repeating: "a", count: 70_000) + "\r\n\r\n").utf8)
    check(refusal(String(decoding: oversized, as: UTF8.self).replacingOccurrences(of: "\r\n", with: "\n")) == .headTooLarge,
          "github proxy: refuses a head over the bound")
}

// MARK: - Decision log

private func gitHubDecisionLogClassTests() {
    let plan = DeliveryPlan(
        mechanism: .daemonProxy,
        executable: PlannedExecutable(canonicalPath: "/opt/homebrew/bin/gh", assurance: .userWritable),
        root: .caller, descendantScope: .subtree, destination: .credentialConsumer,
        operationContext: Agent.githubProxyContext
    )
    check(DecisionLogRecord.requesterClass(plan: plan, scopeChoices: nil) == "proxy:gh",
          "github proxy: the decision log names a proxied use by its program, not as a csec exec")
}

// MARK: - Hosts

private func gitHubHostPolicyTests() {
    let cases: [(String, GitHubProxyHostClass)] = [
        ("github.com", .token), ("api.github.com", .token), ("uploads.github.com", .token),
        ("codeload.github.com", .token), ("gist.github.com", .token),
        // The token goes to the names gh uses, never to any other subdomain.
        ("someone.github.com", .passThrough), ("tuf-repo.github.com", .passThrough),
        ("api.github.com.evil.example", .refused),
        ("objects.githubusercontent.com", .passThrough), ("raw.githubusercontent.com", .passThrough),
        ("evilgithub.com", .refused), ("github.com.evil.example", .refused),
        ("githubusercontent.com", .refused), ("example.com", .refused),
    ]
    for (host, expected) in cases {
        check(GitHubProxyHosts.classify(host) == expected, "github proxy hosts: \(host) is \(expected)")
    }
    check(GitHubProxyHosts.canonical("API.GitHub.com:443") == "api.github.com", "github proxy hosts: canonical form")
    for bad in ["", "localhost", "a..b.com", "-a.com", "a.com.", "a_b.com", "10.0.0.1:80", "a.com:80"] {
        check(GitHubProxyHosts.canonical(bad) == nil, "github proxy hosts: \"\(bad)\" is not a host csec forwards to")
    }
}

// MARK: - Chunked bodies

private func gitHubChunkReframerTests() {
    var reframer = GitHubProxyChunkReframer()
    var output = Data()
    let input = Data("4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\nNEXT".utf8)
    do {
        // Byte by byte: a chunk line or terminator split across reads.
        var used = 0
        for index in input.indices where !reframer.isComplete {
            let (bytes, count) = try reframer.consume(input[index...index])
            output.append(bytes)
            used += count
        }
        check(reframer.isComplete && used == input.count - 4,
              "github proxy chunks: the body ends at the last chunk; what follows is left unused")
        check(output == Data("4\r\nWiki\r\n5\r\npedia\r\ne\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n".utf8),
              "github proxy chunks: forwarded with csecd's own size lines")
    } catch {
        check(false, "github proxy chunks: a valid body reframes (threw \(error))")
    }
    // The body itself, unframed, as csecd judges it before deciding.
    do {
        var reframer = GitHubProxyChunkReframer()
        var payload: Data? = Data()
        var output = Data()
        for index in input.indices where !reframer.isComplete {
            output.append(try reframer.consume(input[index...index], payload: &payload).output)
        }
        check(payload == Data("Wikipedia in\r\n\r\nchunks.".utf8)
                && output == Data("4\r\nWiki\r\n5\r\npedia\r\ne\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n".utf8),
              "github proxy chunks: the body is captured without its framing, and forwarded the same")
    } catch {
        check(false, "github proxy chunks: a valid body is captured (threw \(error))")
    }
    func fails(_ text: String, _ expected: GitHubProxyChunkError, _ label: String) {
        var reframer = GitHubProxyChunkReframer()
        do {
            _ = try reframer.consume(Data(text.utf8))
            check(false, "github proxy chunks: refuses \(label)")
        } catch let error as GitHubProxyChunkError {
            check(error == expected, "github proxy chunks: refuses \(label)")
        } catch {
            check(false, "github proxy chunks: refuses \(label)")
        }
    }
    fails("4;ext=1\r\nWiki\r\n0\r\n\r\n", .chunkExtension, "a chunk extension")
    fails("4\r\nWiki\r\n0\r\nX-Trailer: 1\r\n\r\n", .trailersNotSupported, "a trailer")
    fails("4\r\nWikiX\r\n", .malformedChunkTerminator, "data longer than its size")
    fails("4\nWiki\r\n", .malformedChunkLine, "a bare LF after a size")
    fails("-4\r\n", .malformedChunkLine, "a signed size")
    fails("fffffffffffffff\r\n", .bodyTooLarge, "a chunk over the body bound")
}

// MARK: - Responses

private func gitHubResponseHeadTests() {
    let ok = GitHubProxyResponseHead.parse(head("HTTP/1.1 200 OK\nContent-Length: 2\nConnection: keep-alive\nKeep-Alive: timeout=5\nX-OAuth-Scopes: repo\n\n"))
    let text = ok.map { String(decoding: $0.forwarded, as: UTF8.self) } ?? ""
    check(ok?.status == 200 && text.hasSuffix("Connection: close\r\n\r\n")
            && !text.contains("keep-alive") && !text.contains("Keep-Alive") && text.contains("X-OAuth-Scopes: repo\r\n"),
          "github proxy responses: the client is told the connection closes; other fields pass through")
    let redirect = GitHubProxyResponseHead.parse(head("HTTP/1.1 302 Found\nLocation: https://blob.example.net/a?sig=1\nContent-Length: 0\n\n"))
    check(redirect?.isRedirect == true && redirect?.location == "https://blob.example.net/a?sig=1",
          "github proxy responses: a redirect's Location is read")
    let interim = GitHubProxyResponseHead.parse(head("HTTP/1.1 100 Continue\n\n"))
    check(interim?.isInterim == true && interim.map { !String(decoding: $0.forwarded, as: UTF8.self).contains("Connection") } == true,
          "github proxy responses: an interim response passes through unchanged")
    check(GitHubProxyResponseHead.parse(head("HTTP/1.1 101 Switching Protocols\nUpgrade: websocket\n\n")) == nil,
          "github proxy responses: a protocol switch is refused")
    let error = String(decoding: GitHubProxyResponse.error(status: 403, message: "not approved"), as: UTF8.self)
    check(error.hasPrefix("HTTP/1.1 403 Forbidden\r\n") && error.hasSuffix("{\"message\":\"csec: not approved\"}"),
          "github proxy responses: csecd's own refusals use GitHub's error shape")
}

private func gitHubTokenShapeTests() {
    check(GitHubProxyToken.isWellFormed(Data(fixtureToken.utf8)), "github proxy token: a gho_ token is well formed")
    check(GitHubProxyToken.normalized(Data((fixtureToken + "\n").utf8)) == Data(fixtureToken.utf8),
          "github proxy token: a trailing newline is removed")
    check(!GitHubProxyToken.isWellFormed(Data("a b".utf8)) && !GitHubProxyToken.isWellFormed(Data("a\r\nX: y".utf8))
            && !GitHubProxyToken.isWellFormed(Data()),
          "github proxy token: whitespace, CRLF and empty values are refused before they reach a header")
    check(!GitHubProxyToken.isWellFormed(Data(GitHubProxyHTTP.placeholderToken.utf8)),
          "github proxy token: the placeholder is never a token")
}

// MARK: - Redirect tickets

private func gitHubRedirectTicketTests() async {
    let me = getpid()
    let start = ProcessAncestry.startTime(of: me) ?? 1
    let caller = CallerInfo(pid: me, startTime: start, description: "gh")
    let other = CallerInfo(pid: me, startTime: start &+ 1, description: "gh")
    let service = GitHubProxyService(store: nil, socketPath: "/tmp/unused.sock")
    await service.noteRedirect(location: "https://productionresultssa1.blob.core.windows.net/actions/logs.zip?sig=abc", caller: caller)
    let path = "/actions/logs.zip"
    check(!(await service.takeTicket(host: "productionresultssa1.blob.core.windows.net", path: path, method: "POST", caller: caller)),
          "github proxy tickets: only a GET or HEAD may follow a redirect")
    check(!(await service.takeTicket(host: "productionresultssa1.blob.core.windows.net", path: path, method: "GET", caller: other)),
          "github proxy tickets: another process incarnation has no ticket")
    check(!(await service.takeTicket(host: "productionresultssa1.blob.core.windows.net", path: "/other", method: "GET", caller: caller)),
          "github proxy tickets: another path has no ticket")
    check(await service.takeTicket(host: "productionresultssa1.blob.core.windows.net", path: path, method: "GET", caller: caller),
          "github proxy tickets: the redirect GitHub sent may be followed")
    check(!(await service.takeTicket(host: "productionresultssa1.blob.core.windows.net", path: path, method: "GET", caller: caller)),
          "github proxy tickets: once")
    for location in ["http://blob.example.net/x", "/relative", "https://api.github.com/x",
                     "https://user:pw@blob.example.net/x", "https://blob.example.net:8443/x"] {
        await service.noteRedirect(location: location, caller: caller)
    }
    check(!(await service.takeTicket(host: "blob.example.net", path: "/x", method: "GET", caller: caller)),
          "github proxy tickets: none for plain http, credentials in the URL or another port")
}

// MARK: - A live socket against a fake GitHub

/// A GitHub that records what it was sent and answers from `respond`.
final class FakeGitHubUpstream: GitHubUpstreamConnector, @unchecked Sendable {
    struct Exchange { let host: String; let request: Data }
    private let lock = NSLock()
    private var exchanges: [Exchange] = []
    let respond: @Sendable (String, Data) -> Data

    init(respond: @escaping @Sendable (String, Data) -> Data) { self.respond = respond }

    var received: [Exchange] {
        lock.lock(); defer { lock.unlock() }
        return exchanges
    }

    fileprivate func record(_ exchange: Exchange) {
        lock.lock(); defer { lock.unlock() }
        exchanges.append(exchange)
    }

    func connect(host: String) async throws -> any GitHubUpstreamConnection {
        FakeGitHubConnection(owner: self, host: host)
    }
}

private final class FakeGitHubConnection: GitHubUpstreamConnection, @unchecked Sendable {
    private let lock = NSLock()
    private let owner: FakeGitHubUpstream
    private let host: String
    private var sent = Data()
    private var answered = false

    init(owner: FakeGitHubUpstream, host: String) {
        self.owner = owner
        self.host = host
    }

    func send(_ data: Data) async throws {
        append(data)
    }

    func receive() async throws -> Data? {
        answer()
    }

    private func append(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        sent.append(data)
    }

    /// The canned response once, after the whole request was sent; then EOF.
    private func answer() -> Data? {
        lock.lock(); defer { lock.unlock() }
        guard !answered else { return nil }
        answered = true
        owner.record(.init(host: host, request: sent))
        return owner.respond(host, sent)
    }

    func close() {}
}

actor FakeGitHubAuthorizer: GitHubTokenAuthorizer {
    private(set) var uses: [GitHubProxyUse] = []
    private let decision: GitHubTokenAuthorization

    init(_ decision: GitHubTokenAuthorization) { self.decision = decision }

    func authorizeGitHubTokenUse(reference: SecretRef, use: GitHubProxyUse, caller: CallerInfo) async -> GitHubTokenAuthorization {
        uses.append(use)
        return decision
    }
}

func fakeGitHubResponse(_ body: String, status: String = "200 OK", extra: String = "") -> Data {
    Data("HTTP/1.1 \(status)\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\n\(extra)Connection: keep-alive\r\n\r\n\(body)".utf8)
}

/// Serves `server` on `path` until `stop` is called.
final class GitHubProxyTestListener: @unchecked Sendable {
    private let listenFD: Int32
    let path: String

    init?(server: GitHubProxyServer, path: String) {
        guard let fd = try? server.bind() else { return nil }
        listenFD = fd
        self.path = path
        Thread.detachNewThread {
            while true {
                let client = cs_accept(fd)
                if client < 0 { return }
                server.accepted(fd: client)
            }
        }
    }

    func stop() {
        shutdown(listenFD, SHUT_RDWR)
        close(listenFD)
        unlink(path)
    }
}

/// One raw HTTP exchange over the socket: everything the server sends back.
private func exchange(_ path: String, _ request: Data) -> Data {
    let fd = path.withCString { cs_connect_unix($0) }
    guard fd >= 0 else { return Data() }
    defer { close(fd) }
    _ = writeExactly(fd, [UInt8](request))
    var response = Data()
    var buffer = [UInt8](repeating: 0, count: 65_536)
    while true {
        let count = read(fd, &buffer, buffer.count)
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { break }
        response.append(contentsOf: buffer[0..<count])
    }
    return response
}

/// `body` as a client with no length to give sends it: in chunks of at most
/// `size` bytes, as Go frames `gh api --input -`.
private func chunked(_ body: Data, size: Int = 4_096) -> Data {
    var framed = Data()
    var index = body.startIndex
    while index < body.endIndex {
        let end = min(index + size, body.endIndex)
        framed.append(Data((String(end - index, radix: 16) + "\r\n").utf8))
        framed.append(body[index..<end])
        framed.append(Data("\r\n".utf8))
        index = end
    }
    return framed + Data("0\r\n\r\n".utf8)
}

/// The body of a request as GitHub received it, after its head.
private func receivedBody(_ request: Data) -> Data {
    guard let range = request.range(of: Data("\r\n\r\n".utf8)) else { return Data() }
    return Data(request[range.upperBound...])
}

final class DiagnosticLines: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: [String] = []
    func append(_ line: String) { lock.lock(); stored.append(line); lock.unlock() }
    var lines: [String] { lock.lock(); defer { lock.unlock() }; return stored }
}

private func gitHubProxySocketTests() async {
    let path = "/tmp/csec-ghp-\(getpid()).sock"
    unlink(path)
    let upstream = FakeGitHubUpstream { host, request in
        let text = String(decoding: request, as: UTF8.self)
        if text.hasPrefix("GET /repos/o/r/actions/artifacts/1/zip ") {
            return fakeGitHubResponse("", status: "302 Found", extra: "Location: https://results.blob.core.windows.net/a/1.zip?sig=x\r\n")
        }
        if host == "results.blob.core.windows.net" { return fakeGitHubResponse("ZIPBYTES") }
        return fakeGitHubResponse("{\"login\":\"csec-fixture\"}")
    }
    let service = GitHubProxyService(store: nil, socketPath: path)
    let authorizer = FakeGitHubAuthorizer(.token(Data(fixtureToken.utf8)))
    let diagnostics = DiagnosticLines()
    let server = GitHubProxyServer(
        path: path, service: service, authorizer: authorizer, connector: upstream, diagnostics: { diagnostics.append($0) }
    )
    guard let listener = GitHubProxyTestListener(server: server, path: path) else {
        check(false, "github proxy socket: binds")
        return
    }
    defer { listener.stop() }
    let placeholder = GitHubProxyHTTP.placeholderToken

    // Not registered: nothing is forwarded.
    let unregistered = String(decoding: exchange(path, head("GET /user HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\n\n")), as: UTF8.self)
    check(unregistered.hasPrefix("HTTP/1.1 503 ") && unregistered.contains("csec protect --gh") && upstream.received.isEmpty,
          "github proxy socket: with no token registered gh is told how to set one up, and nothing is forwarded")

    try? await service.register(try! SecretRef("csec://github/gh-token"))
    let response = exchange(path, head("GET /user HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\nConnection: keep-alive\n\n"))
    let text = String(decoding: response, as: UTF8.self)
    let sent = upstream.received.last.map { String(decoding: $0.request, as: UTF8.self) } ?? ""
    check(text.hasPrefix("HTTP/1.1 200 OK\r\n") && text.contains("Connection: close\r\n") && text.hasSuffix("{\"login\":\"csec-fixture\"}"),
          "github proxy socket: GitHub's response reaches the client, marked to close")
    check(sent.contains("Authorization: token \(fixtureToken)\r\n") && !sent.contains(placeholder)
            && upstream.received.last?.host == "api.github.com",
          "github proxy socket: GitHub received the real token in place of the placeholder")
    check(!text.contains(fixtureToken), "github proxy socket: the client never sees the token")

    // A POST body read whole before the request is judged, then forwarded.
    let body = "{\"query\":\"{viewer{login}}\"}"
    _ = exchange(path, head("POST /graphql HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\nContent-Length: \(body.utf8.count)\n\n") + Data(body.utf8))
    let posted = upstream.received.last.map { String(decoding: $0.request, as: UTF8.self) } ?? ""
    check(posted.hasSuffix("\r\n\r\n" + body) && posted.contains("Content-Length: \(body.utf8.count)\r\n"),
          "github proxy socket: a request body is forwarded exactly")
    let ordinaryUse = await authorizer.uses.last
    check(ordinaryUse?.path == "/graphql" && ordinaryUse?.lastingAccess == nil,
          "github proxy socket: an ordinary GraphQL query is not a lasting request")

    // The request as GitHub receives it decides whether it can give lasting
    // access: the head, and the body when it was read first (csec-0.49).
    _ = exchange(path, head("POST /user/keys HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\nContent-Length: 2\n\n") + Data("{}".utf8))
    let keyUse = await authorizer.uses.last
    check(keyUse?.lastingAccess == GitHubLastingAccess(kind: .sshKey, request: "POST api.github.com/user/keys"),
          "github proxy socket: adding an SSH key reaches the authorizer as a lasting request")
    let mutation = "{\"query\":\"mutation { createCommitOnBranch(input: $i) { commit { url } } }\"}"
    _ = exchange(path, head("POST /graphql HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\nContent-Length: \(mutation.utf8.count)\n\n") + Data(mutation.utf8))
    let mutationUse = await authorizer.uses.last
    check(mutationUse?.lastingAccess?.kind == .commit,
          "github proxy socket: a GraphQL mutation in the body is judged on that body")
    check(diagnostics.lines.contains { $0.hasPrefix("csecd: GitHub proxy lasting request (kind=commit pid=") },
          "github proxy socket: a lasting request is logged with its kind, and nothing of the request")

    // `gh api graphql --input -` sends its body chunked, since stdin has no
    // length (csec-0.92). It is read whole before the decision, judged like
    // any other, and forwarded with csecd's own length, so GitHub reads
    // exactly the bytes judged.
    let chunkedHead = head("POST /graphql HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\nContent-Type: application/json\nTransfer-Encoding: chunked\n\n")
    for document in sessionGraphQLBodies {
        let usesBefore = await authorizer.uses.count
        _ = exchange(path, chunkedHead + chunked(Data(document.utf8), size: 37))
        let use = await authorizer.uses.last
        let usesAfter = await authorizer.uses.count
        let forwarded = upstream.received.last?.request ?? Data()
        let forwardedText = String(decoding: forwarded, as: UTF8.self)
        check(usesAfter == usesBefore + 1 && use?.path == "/graphql" && use?.lastingAccess == nil,
              "github proxy socket: a routine GraphQL request sent chunked is read and stays ordinary: \(document.prefix(70))")
        check(receivedBody(forwarded) == Data(document.utf8)
                && forwardedText.contains("Content-Length: \(document.utf8.count)\r\n") && !forwardedText.contains("Transfer-Encoding"),
              "github proxy socket: a chunked body read first is forwarded whole with its length: \(document.prefix(70))")
    }
    _ = exchange(path, chunkedHead + chunked(Data(mutation.utf8), size: 9))
    let chunkedMutationUse = await authorizer.uses.last
    check(chunkedMutationUse?.lastingAccess?.kind == .commit,
          "github proxy socket: a lasting GraphQL mutation sent chunked still asks, as itself")
    _ = exchange(path, chunkedHead + Data("0\r\n\r\n".utf8))
    let emptyUse = await authorizer.uses.last
    let emptyForwarded = upstream.received.last.map { String(decoding: $0.request, as: UTF8.self) } ?? ""
    check(emptyUse?.lastingAccess?.kind == .uncheckedGraphQL && emptyUse?.lastingAccess?.unreadBody == .empty
            && emptyForwarded.hasSuffix("Content-Length: 0\r\nConnection: close\r\n\r\n"),
          "github proxy socket: an empty chunked GraphQL body asks, saying it has no body")
    _ = exchange(path, head("POST /graphql HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\n\n"))
    let bodilessUse = await authorizer.uses.last
    check(bodilessUse?.lastingAccess?.unreadBody == .empty,
          "github proxy socket: a GraphQL POST with no body asks, saying it has no body")
    check(diagnostics.lines.contains { $0.hasPrefix("csecd: GitHub proxy lasting request (kind=unchecked_graphql unread=empty pid=") },
          "github proxy socket: an unread GraphQL request is logged with why it was unread")

    // Over the 1 MiB csecd reads first: what was read is forwarded re-framed,
    // the rest streams after the decision, and the request asks, saying so.
    let padding = String(repeating: "x", count: GitHubProxyHTTP.maximumBufferedBodyBytes + 100_000)
    let large = Data("{\"query\":\"{ viewer { login } }\",\"variables\":{\"pad\":\"\(padding)\"}}".utf8)
    _ = exchange(path, chunkedHead + chunked(large, size: 50_000))
    let largeUse = await authorizer.uses.last
    let largeForwarded = upstream.received.last?.request ?? Data()
    var largePayload: Data? = Data()
    var largeReframer = GitHubProxyChunkReframer()
    _ = try? largeReframer.consume(receivedBody(largeForwarded), payload: &largePayload)
    check(largeUse?.lastingAccess?.kind == .uncheckedGraphQL && largeUse?.lastingAccess?.unreadBody == .tooLarge,
          "github proxy socket: a chunked GraphQL body over 1 MiB asks, saying it is too large to read first")
    check(largeReframer.isComplete && largePayload == large
            && String(decoding: largeForwarded.prefix(4_096), as: UTF8.self).contains("Transfer-Encoding: chunked\r\n"),
          "github proxy socket: a chunked body over 1 MiB reaches GitHub whole, re-chunked")

    // A chunked body csecd refuses to frame is refused before any review.
    let refusedUsesBefore = await authorizer.uses.count
    let refusedSent = upstream.received.count
    let malformed = String(decoding: exchange(path, chunkedHead + Data("2;x=1\r\n{}\r\n0\r\n\r\n".utf8)), as: UTF8.self)
    let refusedUsesAfter = await authorizer.uses.count
    check(malformed.hasPrefix("HTTP/1.1 400 ") && malformed.contains("chunked request body is malformed")
            && refusedUsesAfter == refusedUsesBefore && upstream.received.count == refusedSent,
          "github proxy socket: a malformed chunked body is refused with no review and nothing forwarded")

    // A small chunked upload goes up with its length; a large one keeps
    // csecd's chunk framing.
    _ = exchange(path, head("PUT /up HTTP/1.1\nHost: uploads.github.com\nAuthorization: token \(placeholder)\nTransfer-Encoding: chunked\n\n") + Data("3\r\nabc\r\n0\r\n\r\n".utf8))
    let put = upstream.received.last.map { String(decoding: $0.request, as: UTF8.self) } ?? ""
    check(put.hasSuffix("Content-Length: 3\r\nConnection: close\r\n\r\nabc") && !put.contains("Transfer-Encoding"),
          "github proxy socket: a small chunked body is forwarded with its length")

    // Content hosts: no token, no review.
    let usesBefore = await authorizer.uses.count
    _ = exchange(path, head("GET /a.png HTTP/1.1\nHost: objects.githubusercontent.com\nAuthorization: token \(placeholder)\n\n"))
    let content = upstream.received.last.map { String(decoding: $0.request, as: UTF8.self) } ?? ""
    let usesAfter = await authorizer.uses.count
    check(!content.contains("Authorization") && usesAfter == usesBefore,
          "github proxy socket: a content host gets no token and asks for no approval")

    // Another github.com name: GitHub's, but not one gh puts its token on, so
    // the token never goes there whoever chose the host.
    let otherUsesBefore = await authorizer.uses.count
    _ = exchange(path, head("GET /x HTTP/1.1\nHost: someone.github.com\nAuthorization: token \(placeholder)\n\n"))
    let subdomain = upstream.received.last
    let otherUsesAfter = await authorizer.uses.count
    check(subdomain?.host == "someone.github.com"
            && !String(decoding: subdomain?.request ?? Data(), as: UTF8.self).contains("Authorization")
            && otherUsesAfter == otherUsesBefore,
          "github proxy socket: a github.com subdomain outside gh's token hosts gets no token")

    // Other hosts: refused, unless GitHub redirected an authenticated request there.
    let count = upstream.received.count
    let foreign = String(decoding: exchange(path, head("GET /x HTTP/1.1\nHost: attacker.example\n\n")), as: UTF8.self)
    check(foreign.hasPrefix("HTTP/1.1 421 ") && upstream.received.count == count,
          "github proxy socket: a host outside GitHub is refused and nothing is sent")
    let redirect = String(decoding: exchange(path, head("GET /repos/o/r/actions/artifacts/1/zip HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\n\n")), as: UTF8.self)
    check(redirect.hasPrefix("HTTP/1.1 302 "), "github proxy socket: GitHub's redirect is relayed")
    let followed = String(decoding: exchange(path, head("GET /a/1.zip?sig=x HTTP/1.1\nHost: results.blob.core.windows.net\n\n")), as: UTF8.self)
    let blob = upstream.received.last
    check(followed.hasSuffix("ZIPBYTES") && blob?.host == "results.blob.core.windows.net"
            && !String(decoding: blob?.request ?? Data(), as: UTF8.self).contains("Authorization"),
          "github proxy socket: the redirect is followed once, with no token")
    let again = String(decoding: exchange(path, head("GET /a/1.zip?sig=x HTTP/1.1\nHost: results.blob.core.windows.net\n\n")), as: UTF8.self)
    check(again.hasPrefix("HTTP/1.1 421 "), "github proxy socket: a used redirect ticket admits nothing more")
    // The client's own credential: GitHub's redirect is followed just the same.
    let usesBeforeOwn = await authorizer.uses.count
    _ = exchange(path, head("GET /repos/o/r/actions/artifacts/1/zip HTTP/1.1\nHost: api.github.com\nAuthorization: token gho_clientsOwn\n\n"))
    let ownFollowed = String(decoding: exchange(path, head("GET /a/1.zip?sig=x HTTP/1.1\nHost: results.blob.core.windows.net\n\n")), as: UTF8.self)
    let usesAfterOwn = await authorizer.uses.count
    check(ownFollowed.hasSuffix("ZIPBYTES") && usesAfterOwn == usesBeforeOwn,
          "github proxy socket: a redirect GitHub sent a request with its own credential is followed once, with no review")
    // No credential: GitHub sends Actions storage redirects only to
    // authenticated requests, so an anonymous one earns no ticket.
    _ = exchange(path, head("GET /repos/o/r/actions/artifacts/1/zip HTTP/1.1\nHost: api.github.com\n\n"))
    let anonymous = String(decoding: exchange(path, head("GET /a/1.zip?sig=x HTTP/1.1\nHost: results.blob.core.windows.net\n\n")), as: UTF8.self)
    check(anonymous.hasPrefix("HTTP/1.1 421 "), "github proxy socket: a redirect sent to an anonymous request admits nothing")

    // A malformed request is answered by csecd and never forwarded.
    let before = upstream.received.count
    let smuggle = String(decoding: exchange(path, head("POST /x HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\nContent-Length: 4\nTransfer-Encoding: chunked\n\n")), as: UTF8.self)
    check(smuggle.hasPrefix("HTTP/1.1 400 ") && upstream.received.count == before,
          "github proxy socket: an ambiguous body framing is refused before anything is forwarded")

    // At most `maximumConnections` at once: one more is answered 503 at
    // once, and a slot frees when a connection ends.
    // An earlier exchange's slot is released just after its client sees the
    // close, so start from none in use.
    for _ in 0..<100 where server.activeConnections > 0 {
        try? await Task.sleep(nanoseconds: 50_000_000)
    }
    // One at a time, each admitted before the next: the listen backlog is
    // shorter than the limit, and accepting runs on its own thread, which a
    // loaded Mac can leave behind.
    var silent: [Int32] = []
    for _ in 0..<GitHubProxyServer.maximumConnections {
        let fd = path.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { break }
        silent.append(fd)
        for _ in 0..<200 where server.activeConnections < silent.count {
            try? await Task.sleep(nanoseconds: 25_000_000)
        }
    }
    let active = server.activeConnections
    let overflow = String(decoding: exchange(path, head("GET /user HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\n\n")), as: UTF8.self)
    check(silent.count == GitHubProxyServer.maximumConnections
            && active == GitHubProxyServer.maximumConnections && overflow.hasPrefix("HTTP/1.1 503 ")
            && overflow.contains("too many"),
          "github proxy socket: a connection past the limit is answered 503 rather than held "
            + "(connected \(silent.count), served \(active), answer \(overflow.prefix(12)))")
    for fd in silent { close(fd) }
    var served = ""
    for _ in 0..<50 where !served.hasPrefix("HTTP/1.1 200 ") {
        try? await Task.sleep(nanoseconds: 100_000_000)
        served = String(decoding: exchange(path, head("GET /user HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\n\n")), as: UTF8.self)
    }
    check(served.hasPrefix("HTTP/1.1 200 "), "github proxy socket: closed connections free their slots")

    // A refusal.
    let denyingPath = "/tmp/csec-ghd-\(getpid()).sock"
    unlink(denyingPath)
    let denying = GitHubProxyServer(
        path: denyingPath, service: service,
        authorizer: FakeGitHubAuthorizer(.denied("GitHub access through csec was not approved (policy review denied)")),
        connector: upstream, diagnostics: { _ in }
    )
    guard let denyingListener = GitHubProxyTestListener(server: denying, path: denyingPath) else {
        check(false, "github proxy socket: the denying server binds")
        return
    }
    defer { denyingListener.stop() }
    let beforeDeny = upstream.received.count
    let denied = String(decoding: exchange(denyingPath, head("GET /user HTTP/1.1\nHost: api.github.com\nAuthorization: token \(placeholder)\n\n")), as: UTF8.self)
    check(denied.hasPrefix("HTTP/1.1 403 ") && denied.contains("not approved") && upstream.received.count == beforeDeny,
          "github proxy socket: a refused request is answered 403 and never reaches GitHub")
}

// MARK: - Through Agent: review, grants, two backends

private struct GitHubFixtureProvider: SecretProvider {
    let scheme: String
    let values: [String: Data]
    var schemes: Set<String> { [scheme] }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private actor GitHubCapturingReview: PolicyReviewProvider {
    private(set) var reviews: [AccessPolicyReview] = []
    private let approve: Bool

    init(approve: Bool) { self.approve = approve }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews.append(review)
        guard approve else { return .denied(.human(decidedAt: .now)) }
        let scope = review.scopeChoices?.options.first { $0.kind == .requestingCommand }
        return .approved(AccessPolicyApproval(selectedScopeOptionID: scope?.id, selectedDurationIndex: nil))
    }
}

private func gitHubProxyAgentTests() async {
    let me = getpid()
    guard let start = ProcessAncestry.startTime(of: me) else {
        check(false, "github proxy agent: the fixture reads its own start time")
        return
    }
    let opToken = "op://Private/GitHub/token"
    let nativeToken = "csec://github/gh-token"
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(GitHubFixtureProvider(scheme: "op", values: [
        opToken: Data((fixtureToken + "\n").utf8),
        "op://Private/GitHub/not-a-token": Data("two words".utf8),
    ]))
    await resolver.register(GitHubFixtureProvider(scheme: "csec", values: [nativeToken: Data("ghp_nativeFixture".utf8)]))
    func agent(_ review: GitHubCapturingReview) -> Agent {
        Agent(
            resolver: resolver, grants: GrantTable(), consent: AutoApproveConsent(), policyReview: review,
            terminalInspection: .unavailable
        )
    }
    let review = GitHubCapturingReview(approve: true)
    let csecd = agent(review)
    let caller = CallerInfo(pid: me, startTime: start, description: "gh [unverified] (pid \(me))")
    let use = GitHubProxyUse(method: "GET", host: "api.github.com", path: "/user")

    guard case let .token(first) = await csecd.authorizeGitHubTokenUse(reference: try! SecretRef(opToken), use: use, caller: caller) else {
        check(false, "github proxy agent: an approved request yields the token")
        return
    }
    check(first == Data(fixtureToken.utf8), "github proxy agent: the token, without its trailing newline")
    let shown = await review.reviews.last
    check(shown?.plan.mechanism == .daemonProxy && shown?.plan.executable.canonicalPath.hasPrefix("/") == true,
          "github proxy agent: the review is a daemon-proxy use by the caller's own executable")
    check(shown.map(DeliveryReviewCopy.footnote(for:)) == DeliveryReviewCopy.daemonUseFootnote,
          "github proxy agent: the panel says the token stays in csec")
    check(shown?.commandLine == ReviewDisplay.commandLine(CommandLine.arguments)
            && shown?.plan.commandDigest == (try? ExecutableInspection.commandDigest(CommandLine.arguments)),
          "github proxy agent: the panel shows the caller's argv as csecd read it, bound by digest")
    check(shown?.reason.contains("GET api.github.com/user") == true,
          "github proxy agent: the reason names the first request")
    if let shown {
        let agentScope = GrantScopeOption(kind: .codingAgent, pid: 31163, startTime: 7, processLabel: "Claude Code")
        let line = ReviewDisplay.touchIDReadyText(for: shown, scope: agentScope, duration: .processLifetime)
        check(line == "Touch ID is ready. Touch the sensor to let Claude Code and everything it runs use the requested value for as long as it runs.",
              "github proxy agent: the line beside the sensor says the scope may use the token, not that it is released (\(line))")
        check(ReviewDisplay.secretsHeading(for: shown, count: 1) == "Secret used, never released",
              "github proxy agent: the secrets are headed as used, never released")
    }
    if let shown, let remote = try? RemoteApprovalReview(accessPolicyReview: shown) {
        check(remote.footnote == DeliveryReviewCopy.daemonUseFootnote,
              "github proxy agent: the phone mirror carries the same footnote")
    } else {
        check(false, "github proxy agent: the review mirrors to the phone")
    }

    let reviewsBefore = await review.reviews.count
    let second = await csecd.authorizeGitHubTokenUse(reference: try! SecretRef(opToken), use: use, caller: caller)
    let reviewsAfter = await review.reviews.count
    if case .token = second, reviewsAfter == reviewsBefore {
        check(true, "github proxy agent: a later request under the grant needs no second review")
    } else {
        check(false, "github proxy agent: a later request under the grant needs no second review")
    }

    // A request that can give lasting access is never covered by that grant:
    // it gets its own review for that one request, which mints nothing, so
    // the next one asks again while ordinary use stays covered (csec-0.49).
    let lasting = GitHubLastingAccess(kind: .sshKey, request: "POST api.github.com/user/keys")
    let lastingUse = GitHubProxyUse(method: "POST", host: "api.github.com", path: "/user/keys", lastingAccess: lasting)
    for attempt in 1 ... 2 {
        let before = await review.reviews.count
        let result = await csecd.authorizeGitHubTokenUse(reference: try! SecretRef(opToken), use: lastingUse, caller: caller)
        let after = await review.reviews.count
        if case .token = result {} else { check(false, "github proxy agent: an approved lasting request yields the token (\(attempt))") }
        check(after == before + 1, "github proxy agent: a lasting request under a live grant gets its own review (\(attempt))")
    }
    if let lastingReview = await review.reviews.last {
        check(lastingReview.githubLastingAccess == lasting && lastingReview.durationChoices == nil
                && lastingReview.scopeChoices.map { $0.options.map(\.kind) } ?? [.requestingCommand] == [.requestingCommand]
                && lastingReview.plan.operationContext == Agent.githubLastingAccessContext,
              "github proxy agent: a lasting request's review offers no lifetime or wider scope")
        check(ReviewDisplay.accessHeadline(for: lastingReview) == "Lasting GitHub Access Requested"
                && lastingReview.reason.contains("POST api.github.com/user/keys")
                && ReviewDisplay.fixedLifetime(for: lastingReview)?.title == "This request only",
              "github proxy agent: the panel names the method and endpoint and says it covers this request only")
        check(DeliveryReviewCopy.warning(for: lastingReview)
                == "LASTING ACCESS: POST api.github.com/user/keys can add an SSH key to your GitHub account. What it adds keeps working after every approval ends, so this approval covers this one request only, and the next one asks again.",
              "github proxy agent: the warning names the request and what it can add")
        check(ReviewDisplay.touchIDReadyText(for: lastingReview, scope: nil, duration: .processLifetime)
                == "Touch ID is ready. Touch the sensor to let this command use the requested value for this one request.",
              "github proxy agent: the line beside the sensor says the approval is for this one request")
        if let remote = try? RemoteApprovalReview(accessPolicyReview: lastingReview) {
            check(remote.durationOptions.isEmpty && remote.scopeOptions.count <= 1
                    && remote.warnings == [lasting.warning] && remote.footnote == DeliveryReviewCopy.daemonUseFootnote,
                  "github proxy agent: the phone mirror carries the warning and offers no lifetime or wider scope")
        } else {
            check(false, "github proxy agent: a lasting request's review mirrors to the phone")
        }
    } else {
        check(false, "github proxy agent: a lasting request is reviewed")
    }
    let beforeOrdinary = await review.reviews.count
    let ordinary = await csecd.authorizeGitHubTokenUse(reference: try! SecretRef(opToken), use: use, caller: caller)
    let afterOrdinary = await review.reviews.count
    if case .token = ordinary, afterOrdinary == beforeOrdinary {
        check(true, "github proxy agent: ordinary use stays covered by its grant after lasting requests")
    } else {
        check(false, "github proxy agent: ordinary use stays covered by its grant after lasting requests")
    }
    let lastingRefusing = agent(GitHubCapturingReview(approve: false))
    if case let .denied(message) = await lastingRefusing.authorizeGitHubTokenUse(
        reference: try! SecretRef(opToken), use: lastingUse, caller: caller
    ) {
        check(message.contains("not approved"), "github proxy agent: a denied lasting request is refused")
    } else {
        check(false, "github proxy agent: a denied lasting request is refused")
    }
    // A client cannot claim a lasting marker: it is never on the wire.
    if let request = try? AccessRequest(
        references: [opToken], reason: "r",
        deliveryPlan: .directHeap(executablePath: "/usr/bin/true", operationContext: "c")
    ), let encoded = try? JSONEncoder().encode(request),
       let decoded = try? JSONDecoder().decode(AccessRequest.self, from: encoded) {
        check(!String(decoding: encoded, as: UTF8.self).contains("lasting") && decoded.githubLastingAccess == nil,
              "github proxy agent: the lasting marker is never encoded or decoded")
    } else {
        check(false, "github proxy agent: an access request round-trips")
    }

    // Backend neutrality: a reference of another scheme, same path.
    if case let .token(native) = await csecd.authorizeGitHubTokenUse(reference: try! SecretRef(nativeToken), use: use, caller: caller) {
        check(native == Data("ghp_nativeFixture".utf8), "github proxy agent: a reference of a second scheme works the same way")
    } else {
        check(false, "github proxy agent: a reference of a second scheme works the same way")
    }

    if case let .denied(message) = await csecd.authorizeGitHubTokenUse(
        reference: try! SecretRef("op://Private/GitHub/not-a-token"), use: use, caller: caller
    ) {
        check(message.contains("not a GitHub token"), "github proxy agent: a value that cannot be a token is never used")
    } else {
        check(false, "github proxy agent: a value that cannot be a token is never used")
    }

    let refusing = agent(GitHubCapturingReview(approve: false))
    if case let .denied(message) = await refusing.authorizeGitHubTokenUse(reference: try! SecretRef(opToken), use: use, caller: caller) {
        check(message.contains("not approved"), "github proxy agent: a denied review refuses the request")
    } else {
        check(false, "github proxy agent: a denied review refuses the request")
    }

    // No client may send csecd a daemon-proxy plan.
    let forged = DeliveryPlan(
        mechanism: .daemonProxy,
        executable: PlannedExecutable(canonicalPath: "/opt/homebrew/bin/gh", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .credentialConsumer,
        operationContext: "forged"
    )
    let permissive = Agent(
        resolver: resolver, grants: GrantTable(), consent: AutoApproveConsent(),
        policyReview: GitHubCapturingReview(approve: true), allowUnverifiedPlansForTesting: true,
        terminalInspection: .unavailable
    )
    let response = await permissive.handle(
        request: try! AccessRequest(references: [opToken], reason: "forged", deliveryPlan: forged),
        caller: caller
    )
    check(response.values == nil && response.failure?.code == .invalidRequest,
          "github proxy agent: a socket client's daemon_proxy plan is refused, never released")

    // Registration through `csec github register`: the CLI is not a verified
    // launcher here, so only the refusal path is reachable.
    let service = GitHubProxyService(store: nil, socketPath: "/tmp/unused.sock")
    let withProxy = Agent(
        resolver: resolver, grants: GrantTable(), consent: AutoApproveConsent(),
        policyReview: GitHubCapturingReview(approve: true), githubProxy: service,
        terminalInspection: .unavailable
    )
    let unverified = await withProxy.configureGitHub(
        request: GitHubProxyRequest(action: .register, reference: opToken), caller: caller
    )
    let stillUnregistered = await service.tokenReference == nil
    check(unverified.failure?.code == .githubProxyUnavailable && stillUnregistered,
          "github proxy agent: only the verified csec launcher may register a token")
}

// MARK: - The real gh, end to end

private func gitHubProxyRealGHTests() async {
    guard let gh = try? ExecutableInspection.plannedExecutable(command: "gh").canonicalPath else {
        print("note - github proxy gh: gh is not installed; the real-gh exchange was not run")
        return
    }
    let root = "/tmp/csec-ghe-\(getpid())"
    let config = root + "/config"
    try? FileManager.default.createDirectory(atPath: config, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: root) }
    let path = root + "/gh.sock"
    // gh's own token lookup takes the config's value before its keychain, so
    // with the placeholder here no real credential is ever read.
    try? "http_unix_socket: \(path)\n".write(toFile: config + "/config.yml", atomically: true, encoding: .utf8)
    try? "github.com:\n    oauth_token: \(GitHubProxyHTTP.placeholderToken)\n    git_protocol: ssh\n    user: csec-fixture\n"
        .write(toFile: config + "/hosts.yml", atomically: true, encoding: .utf8)
    chmod(config + "/hosts.yml", 0o600)

    let blobHost = "productionresultssa31.blob.core.windows.net"
    let upstream = FakeGitHubUpstream { host, request in
        let text = String(decoding: request, as: UTF8.self)
        if host == blobHost { return fakeGitHubResponse("job log line\n") }
        if text.hasPrefix("POST /graphql ") {
            return fakeGitHubResponse("{\"data\":{\"viewer\":{\"login\":\"csec-fixture\"}}}")
        }
        // GitHub answers a job-log request with a pre-signed blob-storage URL.
        if let id = text.split(separator: " ").dropFirst().first?.split(separator: "/").dropFirst(5).first,
           text.hasPrefix("GET /repos/o/r/actions/jobs/\(id)/logs ") {
            return fakeGitHubResponse(
                "", status: "302 Found",
                extra: "Location: https://\(blobHost)/actions-results/r\(id)/logs/job/job-logs.txt?rsct=text%2Fplain&sig=x\r\n"
            )
        }
        return fakeGitHubResponse("{\"login\":\"csec-fixture\",\"id\":1}", extra: "X-OAuth-Scopes: repo\r\n")
    }
    let service = GitHubProxyService(store: nil, socketPath: path)
    try? await service.register(try! SecretRef("csec://github/gh-token"))
    let authorizer = FakeGitHubAuthorizer(.token(Data(fixtureToken.utf8)))
    let server = GitHubProxyServer(
        path: path, service: service, authorizer: authorizer, connector: upstream, diagnostics: { _ in }
    )
    guard let listener = GitHubProxyTestListener(server: server, path: path) else {
        check(false, "github proxy gh: the socket binds")
        return
    }
    defer { listener.stop() }

    var environment = ProcessInfo.processInfo.environment
    for name in ["GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST"] {
        environment.removeValue(forKey: name)
    }
    environment["GH_CONFIG_DIR"] = config
    environment["GH_NO_UPDATE_NOTIFIER"] = "1"
    environment["GH_PROMPT_DISABLED"] = "1"
    environment["GH_TELEMETRY"] = "false"
    environment["DO_NOT_TRACK"] = "1"
    environment["NO_COLOR"] = "1"

    let user = await runCapturing(gh, ["api", "user", "--jq", ".login"], environment: environment)
    check(user.status == 0 && user.output.trimmingCharacters(in: .whitespacesAndNewlines) == "csec-fixture",
          "github proxy gh: `gh api user` works through csec's socket (status \(user.status))")
    let graphql = await runCapturing(gh, ["api", "graphql", "-f", "query={viewer{login}}", "--jq", ".data.viewer.login"], environment: environment)
    check(graphql.status == 0 && graphql.output.trimmingCharacters(in: .whitespacesAndNewlines) == "csec-fixture",
          "github proxy gh: a GraphQL POST works through csec's socket (status \(graphql.status))")
    // What sessions pipe in for review threads: `--input -` has no length,
    // so gh sends it chunked, and csecd reads it before deciding (csec-0.92).
    for document in sessionGraphQLBodies {
        let usesBefore = await authorizer.uses.count
        let piped = await runCapturing(
            gh, ["api", "graphql", "--input", "-", "--jq", ".data.viewer.login"], environment: environment, input: Data(document.utf8)
        )
        let uses = await authorizer.uses
        let sent = upstream.received.last.map(\.request) ?? Data()
        check(piped.status == 0 && uses.count == usesBefore + 1 && uses.last?.path == "/graphql" && uses.last?.lastingAccess == nil
                && sent.range(of: Data(document.utf8)) != nil,
              "github proxy gh: `gh api graphql --input -` is read and judged ordinary: \(document.prefix(60)) (status \(piped.status))")
    }
    // gh follows GitHub's redirect as soon as it has read the head, while
    // csecd is still finishing that response; every follow-up must still be
    // admitted (csec-0.63).
    var followed = 0
    for id in 1...20 {
        let log = await runCapturing(gh, ["api", "repos/o/r/actions/jobs/\(id)/logs"], environment: environment)
        if log.status == 0 && log.output == "job log line\n" { followed += 1 }
    }
    check(followed == 20, "github proxy gh: `gh api …/actions/jobs/<id>/logs` follows GitHub's redirect to blob storage (\(followed) of 20)")
    let blobRequests = upstream.received.filter { $0.host == blobHost }.map { String(decoding: $0.request, as: UTF8.self) }
    check(blobRequests.count == followed && blobRequests.allSatisfy { !$0.contains("Authorization") },
          "github proxy gh: blob storage receives no token")
    let requests = upstream.received.filter { $0.host != blobHost }.map { String(decoding: $0.request, as: UTF8.self) }
    check(!requests.isEmpty && requests.allSatisfy {
        $0.contains("Authorization: token \(fixtureToken)\r\n") && !$0.contains(GitHubProxyHTTP.placeholderToken)
    }, "github proxy gh: every request GitHub received carried the real token, none the placeholder")
    check(!user.output.contains(fixtureToken) && !graphql.output.contains(fixtureToken),
          "github proxy gh: gh's output never contains the token")

    // A token of the environment's own (an `.envrc` `csec_GITHUB_TOKEN`)
    // takes precedence over the placeholder; GitHub's redirect for it is
    // followed all the same (csec-0.63).
    let ownToken = "gho_csecFixtureOwnToken0123456789abcd"
    var ownEnvironment = environment
    ownEnvironment["GITHUB_TOKEN"] = ownToken
    let receivedBefore = upstream.received.count
    let ownLog = await runCapturing(gh, ["api", "repos/o/r/actions/jobs/21/logs"], environment: ownEnvironment)
    let ownExchanges = upstream.received.dropFirst(receivedBefore)
    let ownAPI = ownExchanges.first { $0.host == "api.github.com" }.map { String(decoding: $0.request, as: UTF8.self) } ?? ""
    let ownBlob = ownExchanges.first { $0.host == blobHost }.map { String(decoding: $0.request, as: UTF8.self) }
    check(ownLog.status == 0 && ownLog.output == "job log line\n"
            && ownAPI.contains("Authorization: token \(ownToken)\r\n") && ownBlob.map { !$0.contains("Authorization") } == true,
          "github proxy gh: with GITHUB_TOKEN set, a job log follows GitHub's redirect, and blob storage gets no token (status \(ownLog.status))")
}

private func runCapturing(
    _ path: String, _ arguments: [String], environment: [String: String], input: Data? = nil
) async -> (status: Int32, output: String) {
    await withCheckedContinuation { continuation in
        DispatchQueue.global().async {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = arguments
            process.environment = environment
            let pipe = Pipe()
            let stdin = input.map { _ in Pipe() }
            process.standardInput = stdin ?? FileHandle.nullDevice
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice
            do { try process.run() } catch {
                continuation.resume(returning: (127, ""))
                return
            }
            if let stdin, let input {
                stdin.fileHandleForWriting.write(input)
                try? stdin.fileHandleForWriting.close()
            }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            continuation.resume(returning: (process.terminationStatus, String(decoding: data, as: UTF8.self)))
        }
    }
}
