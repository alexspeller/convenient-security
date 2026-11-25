import Foundation

// MARK: - Socket path

public enum GitHubProxySocket {
    public static func defaultPath() -> String {
        #if DEBUG
        // Isolated integration tests need a socket that cannot collide with a
        // developer's installed agent. Release builds compile out this lookup.
        if let override = ProcessInfo.processInfo.environment["CSEC_GITHUB_SOCKET"],
           !override.isEmpty {
            return override
        }
        #endif
        return (AgentSocket.directory() as NSString).appendingPathComponent("github.sock")
    }
}

// MARK: - Wire types for `csec github`

public enum GitHubProxyAction: String, Codable, Sendable {
    case status
    case register
    case remove
}

public struct GitHubProxyRequest: Codable, Sendable {
    public let requestID: String
    public let action: GitHubProxyAction
    /// The token's canonical reference, for `register` only.
    public let reference: String?

    public init(action: GitHubProxyAction, reference: String? = nil, requestID: UUID = UUID()) {
        self.requestID = requestID.uuidString.lowercased()
        self.action = action
        self.reference = reference
    }
}

/// What `csec github status` and `csec status` report. Value-free: the
/// reference names where the token lives, never the token.
public struct GitHubProxyStatus: Codable, Sendable, Equatable {
    public let tokenReference: String?
    public let socketPath: String

    public init(tokenReference: String?, socketPath: String) {
        self.tokenReference = tokenReference
        self.socketPath = socketPath
    }
}

// MARK: - Persisted registration

/// The `github-proxy`/`settings-v1` document: the canonical reference of the
/// one token csecd injects for `gh`. Never the token, never a provider's own
/// record identifier. csecd-only (see `ProtectedItem`), so a same-UID process
/// can neither point the proxy at another secret nor read which one it uses
/// except through `csec github status`.
public struct GitHubProxyDocument: ProtectedDocument, Equatable {
    public static let protectedItem: ProtectedItem = .githubProxy
    public static let formatVersion = 1

    public var tokenReference: String?

    public init(tokenReference: String? = nil) {
        self.tokenReference = tokenReference
    }

    public var isWellFormed: Bool {
        guard let tokenReference else { return true }
        return (try? SecretRef(tokenReference))?.uri == tokenReference
    }
}

public enum GitHubProxyError: Error, Equatable, Sendable {
    case notRegistered
    case invalidReference
    case malformedToken
    case persistenceFailed(String)

    public var message: String {
        switch self {
        case .notRegistered:
            return "no GitHub token is registered with csec (run `csec protect --gh` or `csec github register <reference>`)"
        case .invalidReference:
            return "the GitHub token reference is not a valid secret reference"
        case .malformedToken:
            return "the referenced value is not a GitHub token (expected one line of printable ASCII)"
        case let .persistenceFailed(detail):
            return "the GitHub token registration could not be saved: \(detail)"
        }
    }
}

// MARK: - Redirect tickets

/// One GitHub-issued redirect csecd may follow without a token: an
/// authenticated request for an artifact, a log or a tarball is answered with
/// a redirect to a storage host outside GitHub's own names. The ticket admits
/// exactly that host and path, once, for the process the redirect was sent to.
/// Bounded by count and by its requester's liveness, never by a clock.
struct GitHubProxyRedirectTicket: Sendable, Equatable {
    let pid: pid_t
    let startTime: UInt64
    let host: String
    let path: String
}

// MARK: - The service

/// The registration and routing half of the GitHub token proxy. It holds the
/// token's reference and the redirect tickets, never the token: the value is
/// resolved per request through `GitHubTokenAuthorizer` (`Agent`), after the
/// same review, grants and delegation every secret release goes through.
public actor GitHubProxyService {
    static let maximumTickets = 64

    private let store: ProtectedStore<GitHubProxyDocument>?
    private let processInspection: ProcessInspection
    private var reference: SecretRef?
    private var tickets: [GitHubProxyRedirectTicket] = []
    public nonisolated let socketPath: String

    /// `store` nil keeps the registration in this process only (tests and
    /// unsigned development builds).
    public init(
        store: ProtectedStore<GitHubProxyDocument>?,
        socketPath: String = GitHubProxySocket.defaultPath(),
        processInspection: ProcessInspection = .live
    ) {
        self.store = store
        self.socketPath = socketPath
        self.processInspection = processInspection
    }

    /// Reads the persisted registration. An unreadable item leaves the proxy
    /// unregistered for this run (the store holds it for the build that wrote it).
    public func load() async {
        guard let store else { return }
        if case let .document(document) = await store.load() {
            reference = document.tokenReference.flatMap { try? SecretRef($0) }
        }
    }

    public var tokenReference: SecretRef? { reference }

    public var status: GitHubProxyStatus {
        GitHubProxyStatus(tokenReference: reference?.uri, socketPath: socketPath)
    }

    /// Records `reference` as the token csecd injects. The caller has already
    /// had the reference reviewed, approved and resolved; this only persists it.
    public func register(_ reference: SecretRef) async throws {
        try await persist(GitHubProxyDocument(tokenReference: reference.uri))
        self.reference = reference
    }

    /// Forgets the registration. The referenced value stays in its backend.
    /// It discards the item even when this csecd could not read it: removing
    /// is the human's explicit request to stop the proxy using any token.
    @discardableResult
    public func remove() async throws -> Bool {
        let held = store?.heldReason != nil
        guard reference != nil || held else { return false }
        if let store {
            do {
                try await store.prepareDiscard().commit()
            } catch {
                throw GitHubProxyError.persistenceFailed(String(describing: error))
            }
        }
        reference = nil
        return true
    }

    private func persist(_ document: GitHubProxyDocument) async throws {
        guard let store else { return }
        do {
            try await store.prepare(document).commit()
        } catch {
            throw GitHubProxyError.persistenceFailed(String(describing: error))
        }
    }

    // MARK: Redirect tickets

    /// Notes a redirect a GitHub token host sent in answer to an
    /// authenticated request: csecd's token, or the client's own. Only an
    /// absolute `https` Location to a host csecd would not otherwise forward
    /// to needs a ticket.
    public func noteRedirect(location: String, caller: CallerInfo) {
        guard let ticket = Self.ticket(for: location, caller: caller) else { return }
        tickets.removeAll { !processIsLive($0) || $0 == ticket }
        tickets.append(ticket)
        if tickets.count > Self.maximumTickets { tickets.removeFirst(tickets.count - Self.maximumTickets) }
    }

    /// Takes the ticket for this request, if it has one. Single use.
    public func takeTicket(host: String, path: String, method: String, caller: CallerInfo) -> Bool {
        guard method == "GET" || method == "HEAD",
              let index = tickets.firstIndex(where: {
                  $0.pid == caller.pid && $0.startTime == caller.startTime && $0.host == host && $0.path == path
              }) else { return false }
        tickets.remove(at: index)
        return true
    }

    static func ticket(for location: String, caller: CallerInfo) -> GitHubProxyRedirectTicket? {
        guard let components = URLComponents(string: location),
              components.scheme?.lowercased() == "https",
              components.user == nil, components.password == nil,
              components.port == nil || components.port == 443,
              let rawHost = components.host,
              let host = GitHubProxyHosts.canonical(rawHost),
              GitHubProxyHosts.classify(host) == .refused else { return nil }
        let path = components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
        return GitHubProxyRedirectTicket(pid: caller.pid, startTime: caller.startTime, host: host, path: path)
    }

    private func processIsLive(_ ticket: GitHubProxyRedirectTicket) -> Bool {
        processInspection.startTime(of: ticket.pid) == ticket.startTime
    }
}

// MARK: - Authorization seam

/// One request csecd is asked to put the token on, for the review's text.
public struct GitHubProxyUse: Sendable, Equatable {
    public let method: String
    public let host: String
    /// Without the query.
    public let path: String
    /// Set when the request can give access outlasting any approval: it is
    /// then reviewed on its own, and nothing covers it or is minted for it.
    public let lastingAccess: GitHubLastingAccess?

    public init(method: String, host: String, path: String, lastingAccess: GitHubLastingAccess? = nil) {
        self.method = method
        self.host = host
        self.path = path
        self.lastingAccess = lastingAccess
    }
}

public enum GitHubTokenAuthorization: Sendable {
    /// The token, for this one request. It stays inside csecd.
    case token(Data)
    case denied(String)
}

/// Decides whether a caller may have the token injected, and resolves it.
/// `Agent` is the production implementation; it runs the ordinary secret
/// review, grants, restore and delegation for the token's reference.
public protocol GitHubTokenAuthorizer: Sendable {
    func authorizeGitHubTokenUse(
        reference: SecretRef,
        use: GitHubProxyUse,
        caller: CallerInfo
    ) async -> GitHubTokenAuthorization
}
