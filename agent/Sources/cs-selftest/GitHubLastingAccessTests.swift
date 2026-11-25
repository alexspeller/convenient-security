import ConvenientSecurity
import Foundation

// Which GitHub requests can give access outlasting any approval
// (`GitHubLastingAccess`, csec-0.49): each listed endpoint, the near misses
// that must stay ordinary, and the spellings of a listed endpoint that a
// server decoding generously would still route to it.

private func classify(
    _ method: String, _ target: String, body: String? = nil,
    fields: [GitHubProxyHeaderField] = [], host: String = "api.github.com"
) -> GitHubLastingAccess.Kind? {
    GitHubLastingAccess.classify(
        method: method, host: host, target: target, fields: fields, body: body.map { Data($0.utf8) }
    )?.kind
}

/// The end-to-end fields of a parsed request head carrying `field`.
private func fields(_ field: String) -> [GitHubProxyHeaderField] {
    let text = "GET / HTTP/1.1\r\nHost: api.github.com\r\n\(field)\r\n\r\n"
    return (try? GitHubProxyRequestHead.parse(Data(text.utf8)))?.fields ?? []
}

private func graphQL(_ document: String) -> String {
    let data = try! JSONSerialization.data(withJSONObject: ["query": document])
    return String(decoding: data, as: UTF8.self)
}

/// GraphQL bodies of the kind sessions pipe to `gh api graphql --input -`:
/// review threads read, replied to and resolved, a pull request and an issue
/// edited, a comment added and hidden. None can give lasting access.
let sessionGraphQLBodies: [String] = {
    func body(_ document: String, _ variables: [String: Any]) -> String {
        let data = try! JSONSerialization.data(withJSONObject: ["query": document, "variables": variables], options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }
    return [
        body("""
        query($owner: String!, $name: String!, $number: Int!) {
          repository(owner: $owner, name: $name) {
            pullRequest(number: $number) {
              reviewThreads(first: 100) { nodes { id isResolved comments(first: 50) { nodes { id body path line } } } }
            }
          }
        }
        """, ["owner": "o", "name": "r", "number": 12]),
        body("mutation($threadId: ID!, $body: String!) { addPullRequestReviewThreadReply(input: {pullRequestReviewThreadId: $threadId, body: $body}) { comment { id url } } }",
             ["threadId": "PRRT_kwDOABC", "body": "Fixed in 1a2b3c: the token now goes through createCommitOnBranch's checks."]),
        body("mutation($threadId: ID!) { resolveReviewThread(input: {threadId: $threadId}) { thread { id isResolved } } }",
             ["threadId": "PRRT_kwDOABC"]),
        body("mutation($id: ID!, $title: String, $body: String) { updatePullRequest(input: {pullRequestId: $id, title: $title, body: $body}) { pullRequest { url } } }",
             ["id": "PR_kwDOABC", "title": "Fix the importer", "body": "Adds a deploy key check; see /user/keys."]),
        body("mutation($id: ID!, $body: String!) { updateIssue(input: {id: $id, body: $body}) { issue { url } } }",
             ["id": "I_kwDOABC", "body": "updateTeamsRepository is not involved."]),
        body("mutation($subjectId: ID!, $body: String!) { addComment(input: {subjectId: $subjectId, body: $body}) { commentEdge { node { url } } } }",
             ["subjectId": "PR_kwDOABC", "body": "Review round 2 addressed."]),
        body("mutation($id: ID!) { minimizeComment(input: {subjectId: $id, classifier: OUTDATED}) { minimizedComment { isMinimized } } }",
             ["id": "IC_kwDOABC"]),
    ]
}()

func gitHubLastingAccessTests() {
    print("\n# GitHub socket: requests that can give lasting access")

    typealias Kind = GitHubLastingAccess.Kind
    let listed: [(String, String, String?, Kind)] = [
        ("POST", "/user/keys", "{\"key\":\"ssh-ed25519 AAAA\"}", .sshKey),
        ("POST", "/user/ssh_signing_keys", nil, .sshSigningKey),
        ("POST", "/user/gpg_keys", nil, .gpgKey),
        ("POST", "/user/emails", nil, .email),
        ("PUT", "/user/codespaces/secrets/TOKEN", nil, .secret),
        ("PUT", "/user/codespaces/secrets/TOKEN/repositories/42", nil, .secret),
        ("PUT", "/user/installations/7/repositories/42", nil, .appInstallation),
        ("POST", "/repos/o/r/keys", nil, .deployKey),
        ("PUT", "/repos/o/r/actions/secrets/NPM_TOKEN", nil, .secret),
        ("PUT", "/repos/o/r/dependabot/secrets/NPM_TOKEN", nil, .secret),
        ("PUT", "/repos/o/r/codespaces/secrets/NPM_TOKEN", nil, .secret),
        ("PUT", "/repos/o/r/environments/prod/secrets/NPM_TOKEN", nil, .secret),
        ("PUT", "/repositories/42/environments/prod/secrets/NPM_TOKEN", nil, .secret),
        ("PUT", "/orgs/o/actions/secrets/NPM_TOKEN", nil, .secret),
        ("PUT", "/orgs/o/actions/secrets/NPM_TOKEN/repositories/42", nil, .secret),
        ("PUT", "/orgs/o/dependabot/secrets/NPM_TOKEN", nil, .secret),
        ("PUT", "/orgs/o/codespaces/secrets/NPM_TOKEN", nil, .secret),
        ("PUT", "/enterprises/e/actions/secrets/NPM_TOKEN", nil, .secret),
        ("POST", "/repos/o/r/hooks", nil, .webhook),
        ("PATCH", "/repos/o/r/hooks/1", nil, .webhook),
        ("PATCH", "/repos/o/r/hooks/1/config", nil, .webhook),
        ("POST", "/orgs/o/hooks", nil, .webhook),
        ("PATCH", "/orgs/o/hooks/1/config", nil, .webhook),
        ("PUT", "/repos/o/r/collaborators/someone", nil, .repositoryAccess),
        ("PATCH", "/repos/o/r/invitations/1", nil, .repositoryAccess),
        ("PUT", "/orgs/o/teams/t/repos/o/r", nil, .repositoryAccess),
        ("PUT", "/teams/1/repos/o/r", nil, .repositoryAccess),
        ("PUT", "/orgs/o/memberships/someone", nil, .organizationAccess),
        ("POST", "/orgs/o/invitations", nil, .organizationAccess),
        ("PUT", "/orgs/o/teams/t/memberships/someone", nil, .organizationAccess),
        ("PUT", "/teams/1/memberships/someone", nil, .organizationAccess),
        ("PUT", "/teams/1/members/someone", nil, .organizationAccess),
        ("PUT", "/orgs/o/organization-roles/users/someone/8", nil, .organizationAccess),
        ("POST", "/orgs/o/personal-access-token-requests", nil, .tokenApproval),
        ("POST", "/orgs/o/personal-access-token-requests/3", nil, .tokenApproval),
        ("POST", "/repos/o/r/actions/runners/registration-token", nil, .runner),
        ("POST", "/repos/o/r/actions/runners/generate-jitconfig", nil, .runner),
        ("POST", "/orgs/o/actions/runners/registration-token", nil, .runner),
        ("POST", "/enterprises/e/actions/runners/generate-jitconfig", nil, .runner),
        ("PUT", "/repos/o/r/contents/.github/workflows/ci.yml", nil, .workflow),
        ("PUT", "/repos/o/r/contents/.github/actions/setup/action.yml", nil, .workflow),
        ("POST", "/repos/o/r/git/trees", "{\"tree\":[{\"path\":\".github/workflows/x.yml\",\"mode\":\"100644\",\"type\":\"blob\",\"content\":\"on: push\"}]}", .workflow),
        ("POST", "/repos/o/r/git/trees", "{\"base_tree\":\"abc\",\"tree\":[{\"path\":\".github\",\"mode\":\"040000\",\"type\":\"tree\",\"sha\":\"def\"}]}", .workflow),
        ("PATCH", "/repos/o/r", "{\"private\":false}", .visibility),
        ("PATCH", "/repos/o/r", "{\"visibility\":\"public\"}", .visibility),
        ("PATCH", "/repos/o/r", "{\"visibility\":\"internal\"}", .visibility),
        ("POST", "/repos/o/r/transfer", nil, .transfer),
        ("POST", "/app-manifests/abc123/conversions", nil, .appCredentials),
        ("POST", "/graphql", graphQL("mutation($i: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $i) { commit { url } } }"), .commit),
        ("POST", "/graphql", graphQL("mutation { updateTeamsRepository(input: {repositoryId: \"R\", teamIds: [\"T\"], permission: ADMIN}) { clientMutationId } }"), .repositoryAccess),
        ("POST", "/graphql", graphQL("mutation { inviteEnterpriseAdmin(input: {}) { clientMutationId } }"), .enterpriseAccess),
        ("POST", "/graphql", graphQL("mutation { grantMigratorRole(input: {}) { success } }"), .enterpriseAccess),
    ]
    for (method, target, body, kind) in listed {
        check(classify(method, target, body: body) == kind,
              "lasting access: \(method) \(target) is \(kind.rawValue)")
    }
    // Every listed REST endpoint without a body still asks: none of them
    // depends on one, except those that ask when the body is unreadable.
    check(classify("POST", "/repos/o/r/git/trees") == .workflow && classify("PATCH", "/repos/o/r") == .visibility
            && classify("POST", "/graphql") == .uncheckedGraphQL,
          "lasting access: a request whose body decides it, unread, asks")
    for body in ["not json", "[]", "{\"tree\":\"x\"}", "{\"tree\":[{\"mode\":\"100644\"}]}"] {
        check(classify("POST", "/repos/o/r/git/trees", body: body) == .workflow,
              "lasting access: a tree request csecd cannot read asks (\(body))")
    }
    for body in ["not json", "{\"variables\":{}}", "[{\"query\":\"{viewer{login}}\"},{}]", "{\"query\":7}"] {
        check(classify("POST", "/graphql", body: body) == .uncheckedGraphQL,
              "lasting access: a GraphQL body csecd cannot read asks (\(body))")
    }
    // An unread GraphQL request's warning says why it could not be read
    // (csec-0.92), so a panel that keeps coming back has a cause on it.
    typealias Unread = GitHubLastingAccess.UnreadBody
    let unread: [(String?, Unread)] = [
        (nil, .tooLarge),
        ("", .empty),
        ("not json", .notJSON),
        ("{\"query\":\"{viewer{login}}\"", .notJSON),
        ("{\"variables\":{}}", .noQuery),
        ("{\"query\":7}", .noQuery),
        ("[{\"query\":\"{viewer{login}}\"},{}]", .noQuery),
        ("{\"extensions\":{\"persistedQuery\":{\"version\":1,\"sha256Hash\":\"0f\"}}}", .noQuery),
    ]
    for (body, why) in unread {
        let lasting = GitHubLastingAccess.classify(
            method: "POST", host: "api.github.com", target: "/graphql", fields: [], body: body.map { Data($0.utf8) }
        )
        check(lasting?.kind == .uncheckedGraphQL && lasting?.unreadBody == why
                && lasting?.warning.contains("could not read because \(why.explanation), so it may be one that adds lasting access") == true,
              "lasting access: an unread GraphQL body says why it was unread (\(why.rawValue): \(body ?? "not read"))")
    }
    check(GitHubLastingAccess.classify(
        method: "POST", host: "api.github.com", target: "/graphql", fields: [], body: Data("not json".utf8)
    )?.warning == "LASTING ACCESS: POST api.github.com/graphql is a GraphQL request csecd could not read because its body is not JSON,"
        + " so it may be one that adds lasting access. What it adds keeps working after every approval ends,"
        + " so this approval covers this one request only, and the next one asks again.",
          "lasting access: the unread GraphQL warning reads as one sentence naming the cause")
    check(GitHubProxyHTTP.maximumBufferedBodyBytes == 1_024 * 1_024 && Unread.tooLarge.explanation.contains("over 1 MiB"),
          "lasting access: the too-large cause names the size csecd reads first")
    check(GitHubLastingAccess(kind: .sshKey, request: "POST api.github.com/user/keys", unreadBody: .notJSON).unreadBody == nil
            && GitHubLastingAccess(kind: .uncheckedGraphQL, request: "POST api.github.com/graphql").effect == Kind.uncheckedGraphQL.effect,
          "lasting access: only an unchecked GraphQL request carries an unread cause")

    // The GraphQL requests sessions send routinely, in the JSON `gh api
    // graphql --input -` sends (a document plus variables): read, they are
    // ordinary, and words in the variables are not the document (csec-0.92).
    for body in sessionGraphQLBodies {
        check(classify("POST", "/graphql", body: body) == nil,
              "lasting access: a routine session GraphQL request stays ordinary: \(body.prefix(90))")
    }

    // Near misses: ordinary gh use stays ordinary.
    let ordinary: [(String, String, String?)] = [
        ("GET", "/user/keys", nil),
        ("GET", "/repos/o/r/hooks", nil),
        ("GET", "/repos/o/r/actions/secrets", nil),
        ("GET", "/repos/o/r/actions/secrets/public-key", nil),
        ("GET", "/repos/o/r/contents/.github/workflows/ci.yml", nil),
        ("DELETE", "/user/keys/1", nil),
        ("DELETE", "/repos/o/r/actions/secrets/NPM_TOKEN", nil),
        ("DELETE", "/repos/o/r/collaborators/someone", nil),
        ("POST", "/user/repos", "{\"name\":\"x\"}"),
        ("POST", "/repos/o/r/issues", "{\"title\":\"keys and secrets\"}"),
        ("POST", "/repos/o/r/pulls", nil),
        ("POST", "/repos/o/r/issues/1/comments", "{\"body\":\"createCommitOnBranch\"}"),
        ("PUT", "/repos/o/r/contents/README.md", nil),
        ("PUT", "/repos/o/r/contents/docs/.github-notes.md", nil),
        ("PUT", "/repos/o/r/contents/src/.github/x", nil),
        ("POST", "/repos/o/r/git/trees", "{\"tree\":[{\"path\":\"src/main.swift\",\"mode\":\"100644\",\"type\":\"blob\",\"content\":\"x\"}]}"),
        ("POST", "/repos/o/r/git/trees", "{\"tree\":[{\"path\":\"docs/.github/x\",\"mode\":\"100644\",\"type\":\"blob\",\"content\":\"x\"}]}"),
        ("POST", "/repos/o/r/git/blobs", nil),
        ("PATCH", "/repos/o/r/git/refs/heads/main", nil),
        ("PATCH", "/repos/o/r", "{\"description\":\"x\",\"has_wiki\":false}"),
        ("PATCH", "/repos/o/r", "{\"private\":true}"),
        ("PATCH", "/repos/o/r", "{\"visibility\":\"private\"}"),
        ("POST", "/repos/o/r/actions/runners/remove-token", nil),
        ("POST", "/orgs/o/teams", nil),
        ("POST", "/graphql", graphQL("{ viewer { login } }")),
        ("POST", "/graphql", graphQL("mutation { addComment(input: {subjectId: \"I\", body: \"x\"}) { clientMutationId } }")),
        ("POST", "/graphql", graphQL("query { repository(owner: \"o\", name: \"createCommitOnBranches\") { id } }")),
        ("POST", "/user/keyring", nil),
        ("POST", "/users/someone/keys", nil),
        ("GET", "/graphql", nil),
        ("GET", "/user/keys?sort_method=POST", nil),
    ]
    for (method, target, body) in ordinary {
        check(classify(method, target, body: body) == nil,
              "lasting access: \(method) \(target) stays ordinary")
    }

    // Spellings a generous server would still route to a listed endpoint.
    let override = fields("X-HTTP-Method-Override: POST")
    check(override.count == 1, "lasting access: the override fixture parses")
    let spellings: [(String, String, [GitHubProxyHeaderField], Kind)] = [
        ("POST", "/USER/KEYS", [], .sshKey),
        ("POST", "/user/keys/", [], .sshKey),
        ("POST", "/user//keys", [], .sshKey),
        ("POST", "/user/./keys", [], .sshKey),
        ("POST", "/repos/o/../../user/keys", [], .sshKey),
        ("POST", "/user%2Fkeys", [], .sshKey),
        ("POST", "/user%252Fkeys", [], .sshKey),
        ("POST", "/%75ser/keys", [], .sshKey),
        ("POST", "/user%zz/../user/keys", [], .sshKey),
        ("POST", "/user/keys;x=1", [], .sshKey),
        ("POST", "/user\\keys", [], .sshKey),
        ("POST", "/user/keys%20", [], .sshKey),
        ("POST", "/api/v3/user/keys", [], .sshKey),
        ("POST", "/user/keys?per_page=1", [], .sshKey),
        ("GET", "/user/keys", override, .sshKey),
        ("GET", "/user/keys?_method=POST", [], .sshKey),
        ("GET", "/user/keys?a=1&%5Fmethod=POST", [], .sshKey),
        ("GET", "/user/keys?_METHOD=post", [], .sshKey),
        ("DELETE", "/user/keys", fields("x-http-method: POST"), .sshKey),
        ("PUT", "/repos/o/r/contents/.GitHub/Workflows/ci.yml", [], .workflow),
        ("PUT", "/repos/o/r/contents/.github%2Fworkflows%2Fci.yml", [], .workflow),
        ("PUT", "/repos/o/r/contents/%2Egithub/workflows/ci.yml", [], .workflow),
        ("PUT", "/repos/o/r/contents/./.github/workflows/ci.yml", [], .workflow),
        ("PUT", "/REPOS/O/R/ACTIONS/SECRETS/X", [], .secret),
        ("POST", "/api/graphql", [], .uncheckedGraphQL),
    ]
    for (method, target, fields, kind) in spellings {
        check(classify(method, target, fields: fields) == kind,
              "lasting access: \(method) \(target)\(fields.isEmpty ? "" : " with \(fields[0].name)") still counts")
    }
    // The document's names, however the request spells its JSON or aliases
    // the field.
    let mutations = [
        "{\"query\":\"mutation { \\u0063reateCommitOnBranch(input: $i) { commit { url } } }\"}",
        graphQL("mutation { c: createCommitOnBranch(input: $i) { commit { url } } }"),
        graphQL("mutation { ...F } fragment F on Mutation { CREATECOMMITONBRANCH(input: $i) { commit { url } } }"),
        graphQL("mutation{createCommitOnBranch(input:$i){commit{url}}}"),
        "[{\"query\":\"{ viewer { login } }\"},{\"query\":\"mutation { createCommitOnBranch(input: $i) { commit { url } } }\"}]",
    ]
    for body in mutations {
        check(classify("POST", "/graphql", body: body) == .commit,
              "lasting access: a GraphQL mutation still counts: \(body)")
    }
    // A tree path spelled otherwise.
    for path in [".GITHUB/workflows/x.yml", "./.github/workflows/x.yml", ".github\\\\workflows\\\\x.yml", "/.github/x"] {
        let body = "{\"tree\":[{\"path\":\"\(path)\",\"mode\":\"100644\",\"type\":\"blob\",\"content\":\"x\"}]}"
        check(classify("POST", "/repos/o/r/git/trees", body: body) == .workflow,
              "lasting access: a tree entry \(path) still counts")
    }

    // What the review is told: the request without its query, bounded and
    // display-safe, whatever the path held.
    let described = GitHubLastingAccess.classify(
        method: "POST", host: "api.github.com", target: "/user/keys?token=x", fields: [], body: nil
    )
    check(described?.request == "POST api.github.com/user/keys" && described?.reason == "Use your GitHub token for this one request: POST api.github.com/user/keys",
          "lasting access: the review names the method, host and path, never the query")
    let long = GitHubLastingAccess(kind: .secret, request: "PUT api.github.com/" + String(repeating: "a", count: 1_000))
    check(long.request.utf8.count <= 300, "lasting access: the request the review names is bounded")
    for kind in Kind.allCases {
        check(!kind.effect.isEmpty && !kind.effect.hasSuffix("."), "lasting access: \(kind.rawValue) says what it can add")
    }
}
