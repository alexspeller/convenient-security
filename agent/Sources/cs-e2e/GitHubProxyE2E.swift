import ConvenientSecurity
import CSecuritySupport
import Darwin
import Foundation

// The GitHub token proxy through the real `csec` launcher and socket: register
// a reference, `csec protect --gh` against a scripted gh, and requests through
// csecd's GitHub socket to a recording fake GitHub. No real gh credential,
// keychain item or network is touched: the scripted gh keeps its state in a
// private config directory, and `--keep-plaintext` leaves the keychain alone.

let gitHubE2EToken = "gho_e2eSyntheticToken0123456789"
let gitHubE2EImportedToken = "gho_e2eImportedToken9876543210"
let gitHubE2EOtherToken = "gho_e2eOtherAccountToken55555"

/// A GitHub that records each request's Authorization line and answers 200.
final class E2EGitHubUpstream: GitHubUpstreamConnector, @unchecked Sendable {
    private let lock = NSLock()
    private var requests: [String] = []

    var received: [String] {
        lock.lock(); defer { lock.unlock() }
        return requests
    }

    fileprivate func record(_ request: String) {
        lock.lock(); defer { lock.unlock() }
        requests.append(request)
    }

    func connect(host: String) async throws -> any GitHubUpstreamConnection {
        E2EGitHubConnection(owner: self)
    }
}

private final class E2EGitHubConnection: GitHubUpstreamConnection, @unchecked Sendable {
    private let lock = NSLock()
    private let owner: E2EGitHubUpstream
    private var sent = Data()
    private var answered = false

    init(owner: E2EGitHubUpstream) { self.owner = owner }

    func send(_ data: Data) async throws { append(data) }
    func receive() async throws -> Data? { answer() }
    func close() {}

    private func append(_ data: Data) {
        lock.lock(); defer { lock.unlock() }
        sent.append(data)
    }

    private func answer() -> Data? {
        lock.lock(); defer { lock.unlock() }
        guard !answered else { return nil }
        answered = true
        owner.record(String(decoding: sent, as: UTF8.self))
        let body = "{\"login\":\"csec-e2e\"}"
        return Data("HTTP/1.1 200 OK\r\nContent-Length: \(body.utf8.count)\r\n\r\n\(body)".utf8)
    }
}

/// One raw request through the GitHub socket, as gh would send it.
private func gitHubSocketRequest(_ path: String) -> String {
    let fd = path.withCString { cs_connect_unix($0) }
    guard fd >= 0 else { return "" }
    defer { close(fd) }
    let request = "GET /user HTTP/1.1\r\nHost: api.github.com\r\nAuthorization: token \(GitHubProxyHTTP.placeholderToken)\r\n\r\n"
    _ = writeExactly(fd, [UInt8](request.utf8))
    var response = Data()
    var buffer = [UInt8](repeating: 0, count: 16_384)
    while true {
        let count = read(fd, &buffer, buffer.count)
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { break }
        response.append(contentsOf: buffer[0..<count])
    }
    return String(decoding: response, as: UTF8.self)
}

/// A gh that answers the five commands `csec protect --gh` and `csec github
/// status` run, from files in its own GH_CONFIG_DIR.
private let scriptedGH = """
#!/bin/sh
set -eu
hosts="$GH_CONFIG_DIR/hosts.yml"
case "$*" in
  "auth token --hostname github.com")
    sed -n 's/^    oauth_token: //p' "$hosts" | head -n 1 ;;
  "config get -h github.com user")
    echo "octo-e2e" ;;
  "config get http_unix_socket")
    cat "$GH_CONFIG_DIR/socket" 2>/dev/null || true ;;
  "config set http_unix_socket "*)
    printf '%s\\n' "$4" > "$GH_CONFIG_DIR/socket" ;;
  "config set -h github.com oauth_token "*)
    sed "s/^    oauth_token: .*/    oauth_token: $6/" "$hosts" > "$hosts.new" && mv "$hosts.new" "$hosts" ;;
  *)
    exit 2 ;;
esac
"""

/// A security(1) that keeps gh's keychain items as empty files named by
/// account in `$CS_E2E_KEYCHAIN`, and logs each call beside that directory.
private let scriptedSecurity = """
#!/bin/sh
set -eu
printf '%s\\n' "$*" >> "$CS_E2E_KEYCHAIN/../security.log"
[ "$2" = "-s" ] && [ "$3" = "gh:github.com" ] && [ "$4" = "-a" ] || exit 2
item="$CS_E2E_KEYCHAIN/${5:-_empty}"
case "$1" in
  find-generic-password) [ -e "$item" ] || exit 44 ;;
  delete-generic-password) [ -e "$item" ] || exit 44; rm "$item" ;;
  *) exit 2 ;;
esac
"""

func gitHubProxyE2ETests(socketPath githubSocketPath: String, upstream: E2EGitHubUpstream) {
    let socket = runCsec(["github", "socket"], extraEnv: [:])
    check(socket.status == 0 && socket.out == githubSocketPath + "\n", "csec github socket prints csecd's GitHub socket")

    let unregistered = gitHubSocketRequest(githubSocketPath)
    check(unregistered.hasPrefix("HTTP/1.1 503 ") && upstream.received.isEmpty,
          "the GitHub socket forwards nothing until a token is registered")

    let malformed = runCsec(["github", "register", "op://demo/github/not-a-token"], extraEnv: [:])
    check(malformed.status != 0 && malformed.err.contains("not a GitHub token"),
          "csec github register refuses a value that cannot be a token")

    let registered = runCsec(["github", "register", "op://demo/github/token"], extraEnv: [:])
    check(registered.status == 0 && registered.out.contains("Registered op://demo/github/token")
            && registered.out.contains("token:        op://demo/github/token"),
          "csec github register records a 1Password-style reference after its review")

    let response = gitHubSocketRequest(githubSocketPath)
    let forwarded = upstream.received.last ?? ""
    check(response.hasPrefix("HTTP/1.1 200 ") && response.contains("csec-e2e") && !response.contains(gitHubE2EToken),
          "a request through the GitHub socket gets GitHub's answer and never the token")
    check(forwarded.contains("Authorization: token \(gitHubE2EToken)\r\n")
            && !forwarded.contains(GitHubProxyHTTP.placeholderToken),
          "GitHub received the registered token in place of gh's placeholder")

    // `csec protect --gh` against a scripted gh and a scripted security(1),
    // so no real gh credential or keychain item is read or removed.
    let root = NSTemporaryDirectory() + "cs-e2e-gh-\(getpid())"
    let bin = root + "/bin"
    let config = root + "/config"
    let keychain = root + "/keychain"
    try? FileManager.default.createDirectory(atPath: bin, withIntermediateDirectories: true)
    try? FileManager.default.createDirectory(atPath: config, withIntermediateDirectories: true)
    try? FileManager.default.createDirectory(atPath: keychain, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: root) }
    try? scriptedGH.write(toFile: bin + "/gh", atomically: true, encoding: .utf8)
    chmod(bin + "/gh", 0o755)
    try? scriptedSecurity.write(toFile: bin + "/security", atomically: true, encoding: .utf8)
    chmod(bin + "/security", 0o755)
    for account in ["_empty", "octo-e2e", "other-e2e"] {
        FileManager.default.createFile(atPath: keychain + "/" + account, contents: Data())
    }
    let hosts = """
    github.com:
        oauth_token: \(gitHubE2EImportedToken)
        users:
            octo-e2e:
                oauth_token: \(gitHubE2EImportedToken)
            other-e2e:
                oauth_token: \(gitHubE2EOtherToken)
        git_protocol: ssh
        user: octo-e2e

    """
    try? hosts.write(toFile: config + "/hosts.yml", atomically: true, encoding: .utf8)
    chmod(config + "/hosts.yml", 0o600)
    let ghEnvironment = [
        "PATH": bin + ":" + (ProcessInfo.processInfo.environment["PATH"] ?? "/usr/bin:/bin"),
        "GH_CONFIG_DIR": config,
        "CSEC_SECURITY_TOOL": bin + "/security",
        "CS_E2E_KEYCHAIN": keychain,
    ]
    func keychainItems() -> Set<String> {
        Set((try? FileManager.default.contentsOfDirectory(atPath: keychain)) ?? [])
    }

    // gh signed in to another host: protect refuses and changes nothing,
    // since gh's socket setting would send that host's requests to csecd.
    let enterpriseConfig = root + "/enterprise"
    try? FileManager.default.createDirectory(atPath: enterpriseConfig, withIntermediateDirectories: true)
    let enterpriseHosts = hosts + "ghe.example.com:\n    oauth_token: \(gitHubE2EOtherToken)\n    user: octo-e2e\n"
    try? enterpriseHosts.write(toFile: enterpriseConfig + "/hosts.yml", atomically: true, encoding: .utf8)
    var enterpriseEnvironment = ghEnvironment
    enterpriseEnvironment["GH_CONFIG_DIR"] = enterpriseConfig
    let enterprise = runCsec(["protect", "--gh", "--store", "e2e-github"], extraEnv: enterpriseEnvironment)
    let enterpriseAfter = (try? String(contentsOfFile: enterpriseConfig + "/hosts.yml", encoding: .utf8)) ?? ""
    check(enterprise.status != 0 && enterprise.err.contains("ghe.example.com") && enterpriseAfter == enterpriseHosts
            && !FileManager.default.fileExists(atPath: enterpriseConfig + "/socket"),
          "csec protect --gh refuses, changing nothing, while gh is signed in to another host")

    let before = runCsec(["github", "status"], extraEnv: ghEnvironment)
    check(before.status == 0 && before.out.contains("gh hosts.yml: holds a plaintext token")
            && before.out.contains("gh socket:    not set") && before.out.contains("gh keychain:  2 token item(s)")
            && !before.out.contains(gitHubE2EImportedToken),
          "csec github status reports gh's plaintext token and keychain items without showing them")

    let dryRun = runCsec(["protect", "--gh", "--dry-run", "--store", "e2e-github"], extraEnv: ghEnvironment)
    let hostsAfterDryRun = (try? String(contentsOfFile: config + "/hosts.yml", encoding: .utf8)) ?? ""
    check(dryRun.status == 0 && dryRun.out.contains("csec://e2e-github/gh-token")
            && dryRun.out.contains("nothing changed") && hostsAfterDryRun == hosts && keychainItems().count == 3,
          "csec protect --gh --dry-run reports the plan and changes nothing")

    // --keep-plaintext: gh is switched, and its own copies stay.
    let protected = runCsec(["protect", "--gh", "--keep-plaintext", "--store", "e2e-github"], extraEnv: ghEnvironment)
    let hostsKept = (try? String(contentsOfFile: config + "/hosts.yml", encoding: .utf8)) ?? ""
    check(protected.status == 0 && protected.out.contains("protected gh's github.com token as csec://e2e-github/gh-token")
            && protected.out.contains("2 gh keychain item(s) and 1 hosts.yml account line(s) still hold the old token")
            && !protected.out.contains(gitHubE2EImportedToken),
          "csec protect --gh --keep-plaintext imports gh's token, registers it and switches gh to the socket (\(protected.err))")
    check(hostsKept.contains("    oauth_token: \(GitHubProxyHTTP.placeholderToken)\n")
            && hostsKept.contains("            oauth_token: \(gitHubE2EImportedToken)\n") && keychainItems().count == 3,
          "--keep-plaintext leaves gh's keychain items and account entry in place")
    let socketSetting = (try? String(contentsOfFile: config + "/socket", encoding: .utf8)) ?? ""
    check(socketSetting == githubSocketPath + "\n", "gh's http_unix_socket names csecd's GitHub socket")

    let after = runCsec(["github", "status"], extraEnv: ghEnvironment)
    check(after.status == 0 && after.out.contains("token:        csec://e2e-github/gh-token")
            && after.out.contains("gh socket:    csec's GitHub socket"),
          "csec github status shows the imported token in use through the socket")

    _ = gitHubSocketRequest(githubSocketPath)
    check(upstream.received.last?.contains("Authorization: token \(gitHubE2EImportedToken)\r\n") == true,
          "the imported token, resolved from the native store, is the one GitHub receives")

    // Run again without --keep-plaintext: it finishes, removing the active
    // account's copies and nothing else.
    let finished = runCsec(["protect", "--gh", "--store", "e2e-github"], extraEnv: ghEnvironment)
    let hostsAfter = (try? String(contentsOfFile: config + "/hosts.yml", encoding: .utf8)) ?? ""
    check(finished.status == 0 && finished.out.contains("replaced 1 plaintext token line(s)")
            && finished.out.contains("deleted 2 gh keychain item(s)") && finished.out.contains("another github.com account"),
          "csec protect --gh run again removes the copies --keep-plaintext left (\(finished.err))")
    check(!hostsAfter.contains(gitHubE2EImportedToken) && hostsAfter.contains("oauth_token: \(gitHubE2EOtherToken)")
            && hostsAfter.components(separatedBy: "oauth_token: \(GitHubProxyHTTP.placeholderToken)").count == 3
            && hostsAfter.contains("git_protocol: ssh") && keychainItems() == ["other-e2e"],
          "only the imported account's copies are replaced; another account's token and item stay")
    let securityLog = (try? String(contentsOfFile: keychain + "/../security.log", encoding: .utf8)) ?? ""
    check(securityLog.contains("delete-generic-password -s gh:github.com -a \n")
            && securityLog.contains("delete-generic-password -s gh:github.com -a octo-e2e\n")
            && !securityLog.contains("other-e2e") && !securityLog.contains("-w"),
          "gh's keychain items are found and deleted by service and account, never read")

    let again = runCsec(["protect", "--gh", "--store", "e2e-github"], extraEnv: ghEnvironment)
    check(again.status == 0 && again.out.contains("already uses csec's GitHub socket; nothing to do"),
          "running csec protect --gh once more changes nothing")

    let removed = runCsec(["github", "remove"], extraEnv: [:])
    let afterRemove = gitHubSocketRequest(githubSocketPath)
    check(removed.status == 0 && afterRemove.hasPrefix("HTTP/1.1 503 "),
          "csec github remove stops the socket using any token")
}
