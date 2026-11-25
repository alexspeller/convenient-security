import Foundation

/// A GitHub request that can give access outlasting any approval: a key,
/// a secret, a webhook, a collaborator or member, a self-hosted runner, a
/// change to what GitHub Actions runs, a repository made public. A grant ends
/// when its process or session does, but what such a request adds keeps
/// working afterwards, so a process inside a grant could use it to keep the
/// access the proxy otherwise stops it taking. csecd reviews each one on its
/// own: no grant or auto-mode pairing covers it, and its approval mints
/// nothing (csec-0.49).
///
/// Matching errs towards a panel. A path is decoded, case-folded and
/// dot-resolved before it is matched, a method override counts as a write,
/// and a request whose body decides the answer but cannot be read (over the
/// 1 MiB csecd reads first, or not the JSON GitHub expects) is treated as one
/// that can.
public struct GitHubLastingAccess: Sendable, Equatable {
    /// What a request can add. Each case's `effect` completes "This request …".
    public enum Kind: String, Sendable, Equatable, CaseIterable {
        case sshKey = "ssh_key"
        case sshSigningKey = "ssh_signing_key"
        case gpgKey = "gpg_key"
        case email
        case deployKey = "deploy_key"
        case secret
        case webhook
        case repositoryAccess = "repository_access"
        case organizationAccess = "organization_access"
        case enterpriseAccess = "enterprise_access"
        case appInstallation = "app_installation"
        case appCredentials = "app_credentials"
        case tokenApproval = "token_approval"
        case runner
        case workflow
        case commit
        case visibility
        case transfer
        case uncheckedGraphQL = "unchecked_graphql"

        public var effect: String {
            switch self {
            case .sshKey: return "can add an SSH key to your GitHub account"
            case .sshSigningKey: return "can add an SSH signing key to your GitHub account"
            case .gpgKey: return "can add a GPG key to your GitHub account"
            case .email: return "can add an email address to your GitHub account, which can reset its password"
            case .deployKey: return "can add a deploy key to a repository"
            case .secret: return "can set a secret that GitHub hands to Actions, Dependabot or Codespaces"
            case .webhook: return "can add or redirect a webhook"
            case .repositoryAccess: return "can give someone access to a repository"
            case .organizationAccess: return "can give someone access to an organization or team"
            case .enterpriseAccess: return "can give someone access to an enterprise"
            case .appInstallation: return "can give a GitHub App access to a repository"
            case .appCredentials: return "can create a GitHub App and return its credentials"
            case .tokenApproval: return "can approve a token's access to an organization"
            case .runner: return "can register a self-hosted runner for GitHub Actions jobs"
            case .workflow: return "can change what GitHub Actions runs in a repository"
            case .commit: return "can commit files to a branch, workflows included"
            case .visibility: return "can make a private repository visible to others"
            case .transfer: return "can transfer a repository to another owner"
            case .uncheckedGraphQL: return "is a GraphQL request csecd could not read, so it may be one that adds lasting access"
            }
        }
    }

    /// Why csecd could not read a GraphQL request's document, which the
    /// warning names so an unread request is never a mystery.
    public enum UnreadBody: String, Sendable, Equatable, CaseIterable {
        /// Over `GitHubProxyHTTP.maximumBufferedBodyBytes`: it streams after
        /// the decision instead of being read first.
        case tooLarge = "too_large"
        case empty
        case notJSON = "not_json"
        /// JSON, but not a GraphQL request object (or a batch of them) with a
        /// `query` string, as a persisted query that sends only its hash is not.
        case noQuery = "no_query"

        public var explanation: String {
            switch self {
            case .tooLarge: return "its body is over 1 MiB, more than csecd reads before deciding"
            case .empty: return "it has no body"
            case .notJSON: return "its body is not JSON"
            case .noQuery: return "its body has no GraphQL query"
            }
        }
    }

    public let kind: Kind
    /// The request as the review names it, "POST api.github.com/user/keys":
    /// method, host and path without the query, sanitized and bounded.
    public let request: String
    /// Set only for `.uncheckedGraphQL`.
    public let unreadBody: UnreadBody?

    public init(kind: Kind, request: String, unreadBody: UnreadBody? = nil) {
        self.kind = kind
        self.request = ReviewDisplay.fitted(request, maxBytes: 300)
        self.unreadBody = kind == .uncheckedGraphQL ? unreadBody : nil
    }

    /// What this request can add, with why csecd could not read it when it
    /// could not.
    public var effect: String {
        guard kind == .uncheckedGraphQL, let unreadBody else { return kind.effect }
        return "is a GraphQL request csecd could not read because \(unreadBody.explanation),"
            + " so it may be one that adds lasting access"
    }

    /// The warning banner the secret-access panel and the phone show.
    public var warning: String {
        "LASTING ACCESS: \(request) \(effect). What it adds keeps working after every approval ends,"
            + " so this approval covers this one request only, and the next one asks again."
    }

    /// The review's reason line, which names the request.
    public var reason: String {
        "Use your GitHub token for this one request: \(request)"
    }

    // MARK: - Classification

    /// Whether the request csecd is about to put the token on can give lasting
    /// access, and which. `target` is the origin-form target as sent; `body`
    /// is empty for a request with none, and nil when it was not read before
    /// the decision (one over `GitHubProxyHTTP.maximumBufferedBodyBytes`,
    /// however it is framed).
    public static func classify(
        method: String, host: String, target: String,
        fields: [GitHubProxyHeaderField], body: Data?
    ) -> GitHubLastingAccess? {
        let path = String(target.prefix { $0 != "?" && $0 != "#" })
        let query = target.dropFirst(path.count).dropFirst().prefix { $0 != "#" }
        let overridden = fields.contains { methodOverrideFields.contains($0.name.lowercased()) }
            || query.split(separator: "&").contains { parameter in
                let name = parameter.prefix { $0 != "=" }
                return segments(of: String(name)) == ["_method"]
            }
        // GitHub changes nothing on a GET, HEAD or OPTIONS, and a DELETE only
        // removes access; any of them under a method override could be a write.
        guard overridden || writeMethods.contains(method.uppercased()) else { return nil }
        let request = "\(method) \(host)\(path)"
        let s = segments(of: path)
        // GitHub Enterprise serves GraphQL at `api/graphql`; github.com does
        // not, but nothing is lost by reading it the same way.
        if s == ["graphql"] || s == ["api", "graphql"] {
            switch graphQLDocument(body: body) {
            case let .read(names):
                guard let kind = names.sorted().lazy.compactMap({ graphQLMutations[$0] }).first else { return nil }
                return GitHubLastingAccess(kind: kind, request: request)
            case let .unread(why):
                return GitHubLastingAccess(kind: .uncheckedGraphQL, request: request, unreadBody: why)
            }
        }
        guard let kind = kind(segments: s, body: body) else { return nil }
        return GitHubLastingAccess(kind: kind, request: request)
    }

    static let writeMethods: Set<String> = ["POST", "PUT", "PATCH"]
    static let methodOverrideFields: Set<String> = ["x-http-method-override", "x-http-method", "x-method-override"]

    /// The path as a server that decodes generously would route it: percent
    /// escapes decoded until nothing changes, backslashes read as slashes,
    /// lowercased, matrix parameters (`;…`) and surrounding whitespace dropped,
    /// empty and `.` segments removed and `..` applied, and a leading `api/v3`
    /// (GitHub Enterprise's prefix) removed.
    static func segments(of path: String) -> [String] {
        var bytes = Array(path.utf8)
        for _ in 0 ..< 8 {
            let decoded = percentDecoded(bytes)
            if decoded == bytes { break }
            bytes = decoded
        }
        let text = String(decoding: bytes, as: UTF8.self)
            .replacingOccurrences(of: "\\", with: "/")
            .lowercased()
        var segments: [String] = []
        for raw in text.split(separator: "/", omittingEmptySubsequences: true) {
            let segment = String(raw.prefix { $0 != ";" })
                .trimmingCharacters(in: .whitespacesAndNewlines.union(.controlCharacters))
            switch segment {
            case "", ".": continue
            case "..": if !segments.isEmpty { segments.removeLast() }
            default: segments.append(segment)
            }
        }
        if segments.count >= 2, segments[0] == "api", segments[1] == "v3" { segments.removeFirst(2) }
        return segments
    }

    /// Decodes every well-formed `%XX` and leaves anything else as it is, so a
    /// malformed escape elsewhere in the path cannot stop the rest decoding.
    private static func percentDecoded(_ bytes: [UInt8]) -> [UInt8] {
        func hex(_ byte: UInt8) -> UInt8? {
            switch byte {
            case 0x30 ... 0x39: return byte - 0x30
            case 0x41 ... 0x46: return byte - 0x41 + 10
            case 0x61 ... 0x66: return byte - 0x61 + 10
            default: return nil
            }
        }
        var output: [UInt8] = []
        output.reserveCapacity(bytes.count)
        var index = 0
        while index < bytes.count {
            if bytes[index] == 0x25, index + 2 < bytes.count,
               let high = hex(bytes[index + 1]), let low = hex(bytes[index + 2]) {
                output.append(high << 4 | low)
                index += 3
            } else {
                output.append(bytes[index])
                index += 1
            }
        }
        return output
    }

    private static func kind(segments s: [String], body: Data?) -> Kind? {
        guard let first = s.first else { return nil }
        switch first {
        case "user":
            return userKind(Array(s.dropFirst()))
        case "repos" where s.count >= 3:
            return repositoryKind(Array(s.dropFirst(3)), body: body)
        case "repositories" where s.count >= 2:
            return repositoryKind(Array(s.dropFirst(2)), body: body)
        case "orgs" where s.count >= 2:
            return organizationKind(Array(s.dropFirst(2)))
        case "teams" where s.count >= 2:
            return teamKind(Array(s.dropFirst(2)))
        case "enterprises" where s.count >= 2:
            let rest = Array(s.dropFirst(2))
            return runnerKind(rest) ?? (rest.contains("secrets") ? .secret : nil)
        case "app-manifests":
            return s.last == "conversions" ? .appCredentials : nil
        default:
            return nil
        }
    }

    private static func userKind(_ rest: [String]) -> Kind? {
        switch rest.first {
        case "keys": return .sshKey
        case "ssh_signing_keys": return .sshSigningKey
        case "gpg_keys": return .gpgKey
        case "emails": return .email
        case "installations" where rest.contains("repositories"): return .appInstallation
        default: return rest.contains("secrets") ? .secret : nil
        }
    }

    /// `rest` follows `repos/{owner}/{repo}` or `repositories/{id}`.
    private static func repositoryKind(_ rest: [String], body: Data?) -> Kind? {
        guard let first = rest.first else { return visibilityKind(body: body) }
        switch first {
        case "contents":
            // A local action under `.github/actions` runs in the workflows
            // that use it, so all of `.github/` counts, not only `workflows/`.
            return rest.count >= 2 && rest[1] == ".github" ? .workflow : nil
        case "git":
            return rest == ["git", "trees"] ? treeKind(body: body) : nil
        case "keys": return .deployKey
        case "hooks": return .webhook
        case "collaborators", "invitations": return .repositoryAccess
        case "transfer": return .transfer
        default:
            return runnerKind(rest) ?? (rest.contains("secrets") ? .secret : nil)
        }
    }

    private static func organizationKind(_ rest: [String]) -> Kind? {
        switch rest.first {
        case "hooks": return .webhook
        case "memberships", "invitations", "organization-roles": return .organizationAccess
        case "teams" where rest.count >= 3 && rest[2] == "repos": return .repositoryAccess
        case "teams" where rest.count >= 3 && (rest[2] == "memberships" || rest[2] == "members"): return .organizationAccess
        case "personal-access-token-requests": return .tokenApproval
        default:
            return runnerKind(rest) ?? (rest.contains("secrets") ? .secret : nil)
        }
    }

    /// The legacy `teams/{id}/…` routes.
    private static func teamKind(_ rest: [String]) -> Kind? {
        switch rest.first {
        case "repos": return .repositoryAccess
        case "memberships", "members": return .organizationAccess
        default: return nil
        }
    }

    private static func runnerKind(_ rest: [String]) -> Kind? {
        guard rest.count >= 3, rest[0] == "actions", rest[1] == "runners",
              let last = rest.last, last == "registration-token" || last == "generate-jitconfig" else { return nil }
        return .runner
    }

    /// `PATCH /repos/{owner}/{repo}`: only a change that makes the
    /// repository visible to more people counts.
    private static func visibilityKind(body: Data?) -> Kind? {
        guard let object = jsonObject(body) as? [String: Any] else { return .visibility }
        if let isPrivate = object["private"], (isPrivate as? Bool) != true { return .visibility }
        if let visibility = object["visibility"], (visibility as? String)?.lowercased() != "private" { return .visibility }
        return nil
    }

    /// `POST /repos/{owner}/{repo}/git/trees`: a tree that names `.github`
    /// becomes one once a commit and a ref point at it. A tree for a
    /// subdirectory names only its own entries, but the root tree it ends up
    /// in names `.github`, so that request is the one that asks.
    private static func treeKind(body: Data?) -> Kind? {
        guard let object = jsonObject(body) as? [String: Any],
              let entries = object["tree"] as? [Any] else { return .workflow }
        for entry in entries {
            guard let entry = entry as? [String: Any], let path = entry["path"] as? String else { return .workflow }
            if segments(of: path).first == ".github" { return .workflow }
        }
        return nil
    }

    /// The GraphQL mutations that can give lasting access. Matching is by
    /// name anywhere in the document, so an alias, a fragment on `Mutation`
    /// or a comment that names one still counts.
    static let graphQLMutations: [String: Kind] = [
        "createcommitonbranch": .commit,
        "updateteamsrepository": .repositoryAccess,
        "addenterpriseorganizationmember": .enterpriseAccess,
        "inviteenterpriseadmin": .enterpriseAccess,
        "inviteenterprisemember": .enterpriseAccess,
        "updateenterpriseadministratorrole": .enterpriseAccess,
        "updateenterpriseownerorganizationrole": .enterpriseAccess,
        "grantmigratorrole": .enterpriseAccess,
        "grantenterpriseorganizationsmigratorrole": .enterpriseAccess,
        "transferenterpriseorganization": .enterpriseAccess,
        "setenterpriseidentityprovider": .enterpriseAccess,
        "regenerateenterpriseidentityproviderrecoverycodes": .enterpriseAccess,
    ]

    enum GraphQLDocument: Equatable {
        /// Every name in the request's documents.
        case read(Set<String>)
        case unread(UnreadBody)
    }

    /// A GraphQL request's documents, from its JSON body (one object, or a
    /// batch of them). A body csecd did not read or cannot parse is unread,
    /// and asks.
    static func graphQLDocument(body: Data?) -> GraphQLDocument {
        guard let body else { return .unread(.tooLarge) }
        guard !body.isEmpty else { return .unread(.empty) }
        guard let json = jsonObject(body) else { return .unread(.notJSON) }
        let operations: [Any] = (json as? [Any]) ?? [json]
        var names = Set<String>()
        for operation in operations {
            guard let operation = operation as? [String: Any],
                  let document = operation["query"] as? String else { return .unread(.noQuery) }
            names.formUnion(graphQLNames(document))
        }
        return .read(names)
    }

    /// Every GraphQL name in `document`, lowercased. A name cannot be escaped
    /// in GraphQL, so a field is always spelled out where it is selected.
    static func graphQLNames(_ document: String) -> Set<String> {
        var names = Set<String>()
        var current = ""
        func flush() {
            if let first = current.first, !first.isNumber { names.insert(current.lowercased()) }
            current = ""
        }
        for scalar in document.unicodeScalars {
            if scalar == "_" || (scalar.isASCII && CharacterSet.alphanumerics.contains(scalar)) {
                current.unicodeScalars.append(scalar)
            } else {
                flush()
            }
        }
        flush()
        return names
    }

    private static func jsonObject(_ body: Data?) -> Any? {
        guard let body, !body.isEmpty else { return nil }
        return try? JSONSerialization.jsonObject(with: body, options: [.fragmentsAllowed])
    }
}
