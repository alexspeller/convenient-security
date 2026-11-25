import Foundation

/// The HTTP/1.1 that passes between `gh` and csecd's GitHub socket, and between
/// csecd and GitHub. Pure parsing, policy and serialization: no sockets, no
/// secrets beyond the token handed to `upstreamHead`.
///
/// `gh`'s `http_unix_socket` setting dials the socket for both plain and TLS
/// connections (go-gh `newUnixDomainSocketRoundTripper`), so Go writes
/// plaintext HTTP/1.1 to it, with `gh`'s placeholder token in `Authorization`.
/// csecd replaces that placeholder with the real token and forwards the request
/// over its own TLS connection.
///
/// The parser is deliberately strict. The token enters only a head csecd built
/// itself, written as the first bytes of a fresh upstream connection that
/// carries one request and is then closed. A request csecd frames differently
/// from GitHub therefore cannot carry a later token-bearing head into a body
/// GitHub stores and returns: there is no later head on that connection.
public enum GitHubProxyHTTP {
    /// The non-secret value `csec protect --gh` writes as `gh`'s
    /// `oauth_token`. `gh` sends it as `Authorization: token <placeholder>`.
    public static let placeholderToken = "csec-github-proxy"

    public static let maximumHeadBytes = 64 * 1_024
    public static let maximumHeaderCount = 128
    public static let maximumTargetBytes = 16 * 1_024
    /// Release-asset uploads are the largest bodies `gh` sends; GitHub caps an
    /// asset at 2 GiB.
    public static let maximumBodyBytes: UInt64 = 4 * 1_024 * 1_024 * 1_024
    /// A request body this small is read whole before the request is judged,
    /// so a requester that leaves while its review is up is seen to leave.
    public static let maximumBufferedBodyBytes = 1_024 * 1_024
    public static let maximumChunkLineBytes = 1_024
    public static let maximumTokenBytes = 4_096

    static let allowedMethods: Set<String> = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

    /// Headers that describe one connection, not the request, plus those csecd
    /// writes itself. None of them is forwarded as the client sent it.
    static let connectionHeaders: Set<String> = [
        "connection", "keep-alive", "proxy-connection", "proxy-authorization",
        "proxy-authenticate", "te", "trailer", "transfer-encoding", "upgrade",
        "expect", "content-length", "host", "authorization",
    ]
}

// MARK: - Hosts

/// What csecd does for a request to one host.
public enum GitHubProxyHostClass: Sendable, Equatable {
    /// The GitHub hosts `gh` needs its token on (`GitHubProxyHosts.tokenHosts`).
    /// The placeholder is replaced with the real token here and nowhere else.
    case token
    /// GitHub's content hosts and its other `github.com` names. Forwarded
    /// with no token and no review.
    case passThrough
    /// Anything else. Forwarded only for a redirect GitHub itself issued to an
    /// approved request (`GitHubProxyRedirectTickets`).
    case refused
}

public enum GitHubProxyHosts {
    /// The names `gh` sends an authenticated github.com request to: the API,
    /// release uploads, archive downloads, gists and the web host. go-gh would
    /// put its token on any `*.github.com` name (`isSameDomain`), but there
    /// `gh` chose the host; here any process in a grant's scope chooses it,
    /// so the token goes only to these, never to a subdomain served by
    /// someone else or left dangling.
    public static let tokenHosts: Set<String> = [
        "github.com", "api.github.com", "uploads.github.com", "codeload.github.com", "gist.github.com",
    ]

    /// A lowercase DNS name with no port, or nil.
    public static func canonical(_ raw: String) -> String? {
        var host = raw.lowercased()
        if host.hasSuffix(":443") { host.removeLast(4) }
        guard !host.isEmpty, host.utf8.count <= 253, !host.hasSuffix("."), !host.hasPrefix(".") else { return nil }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return nil }
        for label in labels {
            guard !label.isEmpty, label.utf8.count <= 63,
                  !label.hasPrefix("-"), !label.hasSuffix("-"),
                  label.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7a) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2d })
            else { return nil }
        }
        return host
    }

    public static func classify(_ host: String) -> GitHubProxyHostClass {
        if tokenHosts.contains(host) { return .token }
        if host.hasSuffix(".github.com") || host.hasSuffix(".githubusercontent.com") { return .passThrough }
        return .refused
    }
}

// MARK: - Request head

public enum GitHubProxyRequestError: Error, Equatable, Sendable {
    case headTooLarge
    case malformedRequestLine
    case unsupportedMethod
    case unsupportedVersion
    case malformedTarget
    case malformedHeader
    case tooManyHeaders
    case missingHost
    case duplicateHost
    case invalidHost
    case duplicateAuthorization
    case malformedAuthorization
    case invalidContentLength
    case conflictingFraming
    case unsupportedTransferEncoding
    case bodyTooLarge
    case unsupportedUpgrade

    /// A short, value-free description for the synthesized 400 response.
    public var message: String {
        switch self {
        case .headTooLarge: return "the request head is too large"
        case .malformedRequestLine: return "the request line is malformed"
        case .unsupportedMethod: return "the request method is not supported"
        case .unsupportedVersion: return "only HTTP/1.1 is supported"
        case .malformedTarget: return "the request target must be an origin-form path"
        case .malformedHeader: return "a header line is malformed"
        case .tooManyHeaders: return "the request has too many headers"
        case .missingHost: return "the request has no Host"
        case .duplicateHost: return "the request has more than one Host"
        case .invalidHost: return "the Host is not a valid name on port 443"
        case .duplicateAuthorization: return "the request has more than one Authorization"
        case .malformedAuthorization: return "the Authorization header is malformed"
        case .invalidContentLength: return "the Content-Length is invalid"
        case .conflictingFraming: return "the request has both Content-Length and Transfer-Encoding"
        case .unsupportedTransferEncoding: return "only chunked Transfer-Encoding is supported"
        case .bodyTooLarge: return "the request body is too large"
        case .unsupportedUpgrade: return "protocol upgrades are not supported"
        }
    }
}

public struct GitHubProxyHeaderField: Sendable, Equatable {
    public let name: String
    public let value: String
}

public struct GitHubProxyRequestHead: Sendable, Equatable {
    public enum BodyFraming: Sendable, Equatable {
        case none
        case contentLength(UInt64)
        case chunked
    }

    /// What the request said about authentication.
    public enum Credential: Sendable, Equatable {
        case none
        /// `gh`'s placeholder: csecd decides whether a token goes in its place.
        case placeholder
        /// A credential the client brought itself (`GH_TOKEN`): forwarded as
        /// sent, with no review, since it is not csec's to guard.
        case other(String)
    }

    public let method: String
    /// Origin-form path and query, exactly as sent.
    public let target: String
    /// Canonical: lowercase, no port.
    public let host: String
    /// End-to-end fields in the order sent, without connection headers.
    public let fields: [GitHubProxyHeaderField]
    public let framing: BodyFraming
    public let credential: Credential

    /// The target without its query, for a review's description.
    public var path: String {
        String(target.prefix { $0 != "?" && $0 != "#" })
    }

    public static func parse(_ head: Data) throws -> GitHubProxyRequestHead {
        guard head.count <= GitHubProxyHTTP.maximumHeadBytes else { throw GitHubProxyRequestError.headTooLarge }
        guard let lines = GitHubProxyWire.lines(head) else { throw GitHubProxyRequestError.malformedHeader }
        guard let requestLine = lines.first else { throw GitHubProxyRequestError.malformedRequestLine }
        let parts = requestLine.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw GitHubProxyRequestError.malformedRequestLine }
        let method = String(parts[0])
        let target = String(parts[1])
        guard parts[2] == "HTTP/1.1" else { throw GitHubProxyRequestError.unsupportedVersion }
        guard GitHubProxyHTTP.allowedMethods.contains(method) else { throw GitHubProxyRequestError.unsupportedMethod }
        guard target.hasPrefix("/"), !target.hasPrefix("//"),
              target.utf8.count <= GitHubProxyHTTP.maximumTargetBytes,
              target.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }) else {
            throw GitHubProxyRequestError.malformedTarget
        }
        let headerLines = lines.dropFirst()
        guard headerLines.count <= GitHubProxyHTTP.maximumHeaderCount else { throw GitHubProxyRequestError.tooManyHeaders }

        var host: String?
        var authorization: String?
        var contentLength: UInt64?
        var transferEncoding: String?
        var connectionTokens = Set<String>()
        var fields: [GitHubProxyHeaderField] = []
        for line in headerLines {
            let field = try GitHubProxyWire.field(line)
            let name = field.name.lowercased()
            switch name {
            case "host":
                guard host == nil else { throw GitHubProxyRequestError.duplicateHost }
                guard let canonical = GitHubProxyHosts.canonical(field.value) else {
                    throw GitHubProxyRequestError.invalidHost
                }
                host = canonical
            case "authorization":
                guard authorization == nil else { throw GitHubProxyRequestError.duplicateAuthorization }
                authorization = field.value
            case "content-length":
                guard contentLength == nil,
                      !field.value.isEmpty, field.value.utf8.count <= 19,
                      field.value.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
                      let length = UInt64(field.value) else {
                    throw GitHubProxyRequestError.invalidContentLength
                }
                guard length <= GitHubProxyHTTP.maximumBodyBytes else { throw GitHubProxyRequestError.bodyTooLarge }
                contentLength = length
            case "transfer-encoding":
                guard transferEncoding == nil else { throw GitHubProxyRequestError.unsupportedTransferEncoding }
                transferEncoding = field.value.lowercased()
            case "upgrade":
                throw GitHubProxyRequestError.unsupportedUpgrade
            case "connection":
                for token in field.value.split(separator: ",") {
                    connectionTokens.insert(token.trimmingCharacters(in: .whitespaces).lowercased())
                }
            default:
                break
            }
            if !GitHubProxyHTTP.connectionHeaders.contains(name) {
                fields.append(field)
            }
        }
        guard let host else { throw GitHubProxyRequestError.missingHost }
        if connectionTokens.contains("upgrade") { throw GitHubProxyRequestError.unsupportedUpgrade }
        // A header the client names in Connection is hop-by-hop too.
        fields.removeAll { connectionTokens.contains($0.name.lowercased()) }

        let framing: BodyFraming
        switch (contentLength, transferEncoding) {
        case (.some, .some):
            throw GitHubProxyRequestError.conflictingFraming
        case let (.some(length), nil):
            framing = length == 0 ? .none : .contentLength(length)
        case let (nil, .some(encoding)):
            guard encoding == "chunked" else { throw GitHubProxyRequestError.unsupportedTransferEncoding }
            framing = .chunked
        case (nil, nil):
            framing = .none
        }

        let credential: Credential
        if let authorization {
            let parts = authorization.split(separator: " ", omittingEmptySubsequences: false)
            if parts.count == 2,
               ["token", "bearer"].contains(parts[0].lowercased()),
               parts[1] == GitHubProxyHTTP.placeholderToken {
                credential = .placeholder
            } else if authorization.contains(GitHubProxyHTTP.placeholderToken) {
                // Never forward the placeholder in a form csecd did not
                // recognize: GitHub would see it, and the caller meant csec's.
                throw GitHubProxyRequestError.malformedAuthorization
            } else {
                credential = .other(authorization)
            }
        } else {
            credential = .none
        }

        return GitHubProxyRequestHead(
            method: method, target: target, host: host, fields: fields, framing: framing, credential: credential
        )
    }

    /// The same request with csecd's own body framing: a chunked body csecd
    /// read whole goes upstream with its length, so GitHub reads exactly the
    /// bytes that were judged.
    public func reframed(_ framing: BodyFraming) -> GitHubProxyRequestHead {
        GitHubProxyRequestHead(
            method: method, target: target, host: host, fields: fields, framing: framing, credential: credential
        )
    }

    /// The head csecd writes upstream, as the first bytes of a connection
    /// that carries only this request. `token` replaces the placeholder; a
    /// placeholder with no token sends no `Authorization` at all.
    public func upstreamHead(token: Data?) throws -> Data {
        var head = "\(method) \(target) HTTP/1.1\r\nHost: \(host)\r\n"
        if let token {
            guard GitHubProxyToken.isWellFormed(token) else { throw GitHubProxyTokenError.malformed }
            head += "Authorization: token "
            head += String(decoding: token, as: UTF8.self)
            head += "\r\n"
        } else if case let .other(value) = credential {
            head += "Authorization: \(value)\r\n"
        }
        for field in fields {
            head += "\(field.name): \(field.value)\r\n"
        }
        switch framing {
        case .none:
            // A request with a body framing of its own always says so; a
            // bodiless POST still needs a length GitHub can read.
            if ["POST", "PUT", "PATCH"].contains(method) { head += "Content-Length: 0\r\n" }
        case let .contentLength(length):
            head += "Content-Length: \(length)\r\n"
        case .chunked:
            head += "Transfer-Encoding: chunked\r\n"
        }
        head += "Connection: close\r\n\r\n"
        return Data(head.utf8)
    }
}

// MARK: - Token shape

public enum GitHubProxyTokenError: Error, Equatable, Sendable {
    case malformed
}

public enum GitHubProxyToken {
    /// A GitHub token is printable ASCII with no spaces: `gho_…`, `ghp_…`,
    /// `github_pat_…`, or a classic 40-hex token. Anything else could not be
    /// a token and could break the header it is written into. A trailing
    /// newline, as a token read from a file or `security -w` has, is removed
    /// first by `normalized`.
    public static func isWellFormed(_ token: Data) -> Bool {
        !token.isEmpty && token.count <= GitHubProxyHTTP.maximumTokenBytes
            && token.allSatisfy { $0 > 0x20 && $0 < 0x7f }
            && token != Data(GitHubProxyHTTP.placeholderToken.utf8)
    }

    public static func normalized(_ token: Data) -> Data {
        var bytes = token
        while let last = bytes.last, last == 0x0a || last == 0x0d || last == 0x20 || last == 0x09 {
            bytes.removeLast()
        }
        return bytes
    }
}

// MARK: - Response head

public struct GitHubProxyResponseHead: Sendable, Equatable {
    public let status: Int
    /// The head as forwarded: the upstream's own fields, with its connection
    /// headers replaced by `Connection: close`.
    public let forwarded: Data
    public let location: String?

    public var isInterim: Bool { status >= 100 && status < 200 }
    public var isRedirect: Bool { [301, 302, 303, 307, 308].contains(status) }

    public static func parse(_ head: Data) -> GitHubProxyResponseHead? {
        guard head.count <= GitHubProxyHTTP.maximumHeadBytes,
              let lines = GitHubProxyWire.lines(head),
              let statusLine = lines.first else { return nil }
        let parts = statusLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2,
              parts[0] == "HTTP/1.1" || parts[0] == "HTTP/1.0",
              parts[1].utf8.count == 3, let status = Int(parts[1]), status >= 100, status <= 599,
              status != 101 else { return nil }
        guard lines.count - 1 <= GitHubProxyHTTP.maximumHeaderCount else { return nil }
        var out = statusLine + "\r\n"
        var location: String?
        for line in lines.dropFirst() {
            guard let field = try? GitHubProxyWire.field(line) else { return nil }
            let name = field.name.lowercased()
            if name == "location" {
                guard location == nil else { return nil }
                location = field.value
            }
            if ["connection", "keep-alive", "proxy-connection"].contains(name) { continue }
            out += line + "\r\n"
        }
        let interim = status < 200
        if !interim { out += "Connection: close\r\n" }
        out += "\r\n"
        return GitHubProxyResponseHead(status: status, forwarded: Data(out.utf8), location: location)
    }
}

// MARK: - Synthesized responses

public enum GitHubProxyResponse {
    /// A complete response from csecd itself, in GitHub's error shape so `gh`
    /// prints the message: `HTTP 403: csec: … (https://…)`.
    public static func error(status: Int, message: String) -> Data {
        let reason: String
        switch status {
        case 400: reason = "Bad Request"
        case 403: reason = "Forbidden"
        case 421: reason = "Misdirected Request"
        case 502: reason = "Bad Gateway"
        case 503: reason = "Service Unavailable"
        default: reason = "Error"
        }
        let body = (try? JSONSerialization.data(
            withJSONObject: ["message": "csec: " + message],
            options: [.sortedKeys, .withoutEscapingSlashes]
        )) ?? Data("{}".utf8)
        var head = "HTTP/1.1 \(status) \(reason)\r\n"
        head += "Content-Type: application/json; charset=utf-8\r\n"
        head += "Content-Length: \(body.count)\r\n"
        head += "Connection: close\r\n\r\n"
        return Data(head.utf8) + body
    }
}

// MARK: - Chunked request bodies

public enum GitHubProxyChunkError: Error, Equatable, Sendable {
    case malformedChunkLine
    case chunkExtension
    case malformedChunkTerminator
    case trailersNotSupported
    case bodyTooLarge
}

/// Re-frames a chunked request body as csecd forwards it. Each chunk is
/// written with csecd's own size line; extensions and trailers are refused,
/// so what GitHub reads as the body is exactly the bytes csecd counted.
public struct GitHubProxyChunkReframer: Sendable {
    private enum State: Sendable {
        case sizeLine
        case data(remaining: UInt64)
        case dataCR
        case dataLF
        case trailer
        case trailerLF
        case done
    }

    private var state = State.sizeLine
    private var line = Data()
    private var total: UInt64 = 0

    public init() {}

    public var isComplete: Bool {
        if case .done = state { return true }
        return false
    }

    /// Consumes `input`; returns the bytes to forward and how many input bytes
    /// were used. Input after the final chunk is left unused.
    public mutating func consume(_ input: Data) throws -> (output: Data, used: Int) {
        var payload: Data?
        return try consume(input, payload: &payload)
    }

    /// The same, also appending each chunk's data to `payload` when it is not
    /// nil: the body itself, without its framing, as GitHub will read it.
    public mutating func consume(_ input: Data, payload: inout Data?) throws -> (output: Data, used: Int) {
        var output = Data()
        var index = input.startIndex
        while index < input.endIndex {
            switch state {
            case .done:
                return (output, index - input.startIndex)
            case .sizeLine:
                let byte = input[index]
                index += 1
                if byte == 0x0a {
                    guard line.last == 0x0d else { throw GitHubProxyChunkError.malformedChunkLine }
                    line.removeLast()
                    let size = try Self.chunkSize(line)
                    line.removeAll()
                    if size == 0 {
                        state = .trailer
                    } else {
                        total += size
                        guard total <= GitHubProxyHTTP.maximumBodyBytes else { throw GitHubProxyChunkError.bodyTooLarge }
                        output.append(Data(String(size, radix: 16).utf8))
                        output.append(contentsOf: [0x0d, 0x0a])
                        state = .data(remaining: size)
                    }
                } else {
                    line.append(byte)
                    guard line.count <= GitHubProxyHTTP.maximumChunkLineBytes else {
                        throw GitHubProxyChunkError.malformedChunkLine
                    }
                }
            case let .data(remaining):
                let available = UInt64(input.endIndex - index)
                let take = Int(min(remaining, available))
                output.append(input[index..<(index + take)])
                payload?.append(input[index..<(index + take)])
                index += take
                let left = remaining - UInt64(take)
                state = left == 0 ? .dataCR : .data(remaining: left)
            case .dataCR:
                guard input[index] == 0x0d else { throw GitHubProxyChunkError.malformedChunkTerminator }
                index += 1
                state = .dataLF
            case .dataLF:
                guard input[index] == 0x0a else { throw GitHubProxyChunkError.malformedChunkTerminator }
                index += 1
                output.append(contentsOf: [0x0d, 0x0a])
                state = .sizeLine
            case .trailer:
                // Only an empty trailer section: the CRLF that ends the body.
                guard input[index] == 0x0d else { throw GitHubProxyChunkError.trailersNotSupported }
                index += 1
                state = .trailerLF
            case .trailerLF:
                guard input[index] == 0x0a else { throw GitHubProxyChunkError.trailersNotSupported }
                index += 1
                output.append(Data("0\r\n\r\n".utf8))
                state = .done
            }
        }
        return (output, index - input.startIndex)
    }

    private static func chunkSize(_ line: Data) throws -> UInt64 {
        guard !line.isEmpty else { throw GitHubProxyChunkError.malformedChunkLine }
        if line.contains(0x3b) { throw GitHubProxyChunkError.chunkExtension }
        guard line.count <= 15,
              line.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) || ($0 >= 0x41 && $0 <= 0x46) }),
              let size = UInt64(String(decoding: line, as: UTF8.self), radix: 16) else {
            throw GitHubProxyChunkError.malformedChunkLine
        }
        return size
    }
}

// MARK: - Line and field syntax (RFC 9112)

enum GitHubProxyWire {
    /// The lines of a head without its final empty line. Every line must end
    /// in CRLF; a bare CR or LF anywhere makes the head malformed.
    static func lines(_ head: Data) -> [String]? {
        let terminator = Data("\r\n\r\n".utf8)
        guard head.count >= terminator.count, head.suffix(terminator.count) == terminator else { return nil }
        let body = head.dropLast(2)
        var lines: [String] = []
        var current = Data()
        var index = body.startIndex
        while index < body.endIndex {
            let byte = body[index]
            if byte == 0x0d {
                let next = body.index(after: index)
                guard next < body.endIndex, body[next] == 0x0a else { return nil }
                lines.append(String(decoding: current, as: UTF8.self))
                current.removeAll()
                index = body.index(after: next)
                continue
            }
            if byte == 0x0a || byte == 0x00 { return nil }
            current.append(byte)
            index = body.index(after: index)
        }
        guard current.isEmpty, !lines.isEmpty, !lines.contains(where: \.isEmpty) else { return nil }
        return lines
    }

    static func field(_ line: String) throws -> GitHubProxyHeaderField {
        guard let colon = line.firstIndex(of: ":") else { throw GitHubProxyRequestError.malformedHeader }
        let name = String(line[..<colon])
        guard !name.isEmpty, name.utf8.count <= 256, name.utf8.allSatisfy(isTokenCharacter) else {
            throw GitHubProxyRequestError.malformedHeader
        }
        let rawValue = line[line.index(after: colon)...]
        let value = rawValue.trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
        // VCHAR, SP, HTAB and obs-text; no other control character.
        guard value.utf8.allSatisfy({ $0 == 0x09 || ($0 >= 0x20 && $0 != 0x7f) }) else {
            throw GitHubProxyRequestError.malformedHeader
        }
        return GitHubProxyHeaderField(name: name, value: value)
    }

    private static func isTokenCharacter(_ byte: UInt8) -> Bool {
        switch byte {
        case 0x30...0x39, 0x41...0x5a, 0x61...0x7a: return true
        case UInt8(ascii: "!"), UInt8(ascii: "#"), UInt8(ascii: "$"), UInt8(ascii: "%"), UInt8(ascii: "&"),
             UInt8(ascii: "'"), UInt8(ascii: "*"), UInt8(ascii: "+"), UInt8(ascii: "-"), UInt8(ascii: "."),
             UInt8(ascii: "^"), UInt8(ascii: "_"), UInt8(ascii: "`"), UInt8(ascii: "|"), UInt8(ascii: "~"):
            return true
        default: return false
        }
    }
}
