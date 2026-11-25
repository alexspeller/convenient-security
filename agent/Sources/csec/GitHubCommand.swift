import ConvenientSecurity
import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// The keychain service gh's keyring library stores a github.com token under
/// (zalando/go-keyring, through /usr/bin/security). gh writes one item for the
/// active account with an empty account name and one under the login.
private let ghKeychainService = "gh:github.com"
/// `security(1)`, through which gh's keyring library keeps its items. With
/// `-a ""` it matches only the item with no account (measured: a service
/// whose one item names an account is not found with `-a ""`).
private let securityTool: String = {
    #if DEBUG
    // cs-e2e runs a scripted tool, so a test never finds or deletes a real
    // keychain item. Release builds compile out this lookup.
    if let tool = ProcessInfo.processInfo.environment["CSEC_SECURITY_TOOL"], tool.hasPrefix("/") {
        return tool
    }
    #endif
    return "/usr/bin/security"
}()
private let ghHost = "github.com"
private let defaultGitHubStore = "github"
private let gitHubTokenKey = "gh-token"

// MARK: - csec github

func runGitHub(_ arguments: [String]) -> Never {
    guard let action = arguments.first else { usage("github") }
    switch action {
    case "socket":
        guard arguments.count == 1 else { usage("github") }
        FileHandle.standardOutput.write(Data("\(GitHubProxySocket.defaultPath())\n".utf8))
        exit(0)
    case "status":
        guard arguments.count == 1 else { usage("github") }
        do {
            let status = try makeAgentClient().githubProxyStatus()
            FileHandle.standardOutput.write(Data(gitHubStatusReport(status).utf8))
            exit(0)
        } catch {
            gitHubFail(error.localizedDescription)
        }
    case "register":
        guard arguments.count == 2 else { usage("github") }
        do {
            let reference = try gitHubRegistrationReference(arguments[1])
            let status = try makeAgentClient().registerGitHubToken(reference)
            FileHandle.standardOutput.write(Data(
                "Registered \(reference.safeInlineURI) as the token csecd adds to gh's GitHub requests.\n".utf8
            ))
            FileHandle.standardOutput.write(Data(gitHubStatusReport(status).utf8))
            exit(0)
        } catch {
            gitHubFail(error.localizedDescription)
        }
    case "remove":
        guard arguments.count == 1 else { usage("github") }
        do {
            _ = try makeAgentClient().removeGitHubToken()
            FileHandle.standardOutput.write(Data(
                "Removed the GitHub token registration; the value stays in its store. gh requests through csec's socket now fail until a token is registered again.\n".utf8
            ))
            exit(0)
        } catch {
            gitHubFail(error.localizedDescription)
        }
    default:
        usage("github")
    }
}

private func gitHubFail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("csec github: \(message)\n".utf8))
    exit(1)
}

private func gitHubRegistrationReference(_ argument: String) throws -> SecretRef {
    if argument.contains("://") { return try SecretRef(argument) }
    guard argument.hasSuffix(ProtectedFileSidecar.suffix) else { throw ProtectedFileSidecarError.notASidecar }
    let (data, _) = try readRegularFile(atPath: argument)
    guard data.count <= ProtectedFileSidecar.maximumBytes else { throw ProtectedFileSidecarError.malformed }
    return try ProtectedFileSidecar(data: data).reference
}

/// What gh's own configuration says, from non-secret facts only: the socket
/// setting, whether hosts.yml names a token other than the placeholder (never
/// its value), and whether gh's keychain items still exist (by attributes).
private func gitHubStatusReport(_ status: GitHubProxyStatus) -> String {
    var lines = ["GitHub token proxy: \(status.socketPath)"]
    if let reference = status.tokenReference.flatMap({ try? SecretRef($0) }) {
        lines.append("  token:        \(reference.safeInlineURI)")
    } else {
        lines.append("  token:        not registered (run `csec protect --gh`)")
    }
    guard let gh = GitHubCLI.locate() else {
        lines.append("  gh:           not found on PATH")
        return lines.joined(separator: "\n") + "\n"
    }
    let socket = gh.run(["config", "get", "http_unix_socket"]).text
    if socket == status.socketPath {
        lines.append("  gh socket:    csec's GitHub socket")
    } else if socket.isEmpty {
        lines.append("  gh socket:    not set (gh talks to GitHub directly)")
    } else {
        lines.append("  gh socket:    another socket")
    }
    let tokens = GitHubCLI.hostsTokenLines(configDirectory: gh.configDirectory)
    if tokens.other > 0 {
        lines.append("  gh hosts.yml: holds a plaintext token (run `csec protect --gh`)")
    } else if tokens.placeholder > 0 {
        lines.append("  gh hosts.yml: csec's placeholder only")
    } else {
        lines.append("  gh hosts.yml: no token")
    }
    let items = GitHubCLI.keychainAccounts(login: gh.login).filter(GitHubCLI.keychainItemExists)
    lines.append(items.isEmpty
        ? "  gh keychain:  no token items"
        : "  gh keychain:  \(items.count) token item(s) any process running as you can read (run `csec protect --gh`)")
    return lines.joined(separator: "\n") + "\n"
}

// MARK: - csec protect --gh

func runProtectGitHub(storeOverride: String?, keepPlaintext: Bool, dryRun: Bool) -> Never {
    let reference: SecretRef
    let store: NativeStoreName
    do {
        store = try NativeStoreName(storeOverride ?? defaultGitHubStore)
        reference = try NativeSecretReference(store: store, key: gitHubTokenKey).secretRef
    } catch {
        protectFail("invalid store name (\(error.localizedDescription))")
    }
    guard let gh = GitHubCLI.locate() else {
        protectFail("gh is not on PATH; install the GitHub CLI and run `gh auth login` first")
    }
    let socketPath = GitHubProxySocket.defaultPath()

    // gh's http_unix_socket is one setting for every host, and csec's socket
    // serves github.com only: switching it would cut gh off from any other
    // host it is signed in to.
    let otherHosts = GitHubCLI.hostsFileHosts(configDirectory: gh.configDirectory).filter { $0 != ghHost }
    guard otherHosts.isEmpty else {
        protectFail("gh is also signed in to \(otherHosts.map { ReviewDisplay.sanitized($0) }.joined(separator: ", ")); "
            + "csec's GitHub socket serves github.com only, and gh's http_unix_socket would send those hosts' requests to it too. "
            + "Nothing was changed")
    }

    // The token gh would use for github.com, as gh itself resolves it (its
    // config, then the keychain), with any token in this shell's environment
    // set aside: that is not gh's stored credential.
    let probe = gh.run(["auth", "token", "--hostname", ghHost])
    guard probe.status == 0 else {
        protectFail("gh has no stored token for github.com; run `gh auth login` first")
    }
    let token = GitHubProxyToken.normalized(probe.output)
    if token == Data(GitHubProxyHTTP.placeholderToken.utf8) {
        let registered = (try? makeAgentClient().githubProxyStatus())?.tokenReference != nil
        guard registered else {
            protectFail("gh already uses csec's placeholder but csecd has no token registered; run `csec github register <reference>`")
        }
        // An earlier run may have stopped before removing gh's own copies
        // (`--keep-plaintext`, or a deletion that failed): finish that now.
        finishProtectGitHub(gh: gh, keepPlaintext: keepPlaintext, dryRun: dryRun)
    }
    guard GitHubProxyToken.isWellFormed(token) else {
        protectFail("gh's stored token for github.com is not in a form csec can use")
    }
    let accounts = GitHubCLI.keychainAccounts(login: gh.login)
    let keychainItems = accounts.filter(GitHubCLI.keychainItemExists)

    if dryRun {
        var output = "csec protect --gh (dry run):\n"
        output += "  gh's github.com token  ->  \(reference.uri)  (protect + register)\n"
        output += "  gh config: http_unix_socket -> \(socketPath); oauth_token -> csec's placeholder\n"
        output += keepPlaintext
            ? "  gh's keychain items and account entry left in place (--keep-plaintext)\n"
            : "  then delete \(keychainItems.count) gh keychain item(s) (\(ghKeychainService)) and replace the active account's token in hosts.yml\n"
        output += "  nothing changed (dry run)\n"
        FileHandle.standardOutput.write(Data(output.utf8))
        exit(0)
    }

    // 1. One review and Touch ID: import the token and register it.
    do {
        let client = makeAgentClient()
        let session = try client.beginNativeStoreEdit(store: store.value, mode: .githubTokenImport)
        _ = try client.commitNativeStoreBlobAndRegisterGitHubToken(
            sessionID: session.sessionID,
            blob: ProtectedBlobImport(key: gitHubTokenKey, data: token, mode: 0o600, path: "github/\(gitHubTokenKey)"),
            reference: reference
        )
    } catch {
        // The daemon's message says whether the import itself was kept.
        protectFail("gh is unchanged: \(error.localizedDescription)")
    }

    // 2. Point gh at csec's socket with the placeholder as its active token,
    // and check gh now reports the placeholder. gh's keychain items and its
    // per-account copy in hosts.yml are still in place, so a failure here
    // leaves gh able to recover its own token.
    let configured = gh.run(["config", "set", "http_unix_socket", socketPath]).status == 0
        && gh.run(["config", "set", "-h", ghHost, "oauth_token", GitHubProxyHTTP.placeholderToken]).status == 0
    let check = gh.run(["auth", "token", "--hostname", ghHost])
    guard configured, check.status == 0,
          GitHubProxyToken.normalized(check.output) == Data(GitHubProxyHTTP.placeholderToken.utf8) else {
        protectFail("the token is protected as \(reference.uri), but gh could not be switched to csec's socket. "
            + "gh's keychain items and its account entry in hosts.yml are untouched; "
            + "`gh config set http_unix_socket \"\"` and `gh auth switch` restore gh's own token")
    }

    // 3. Only now: remove gh's own copies of the active account's token.
    var output = "csec protect --gh: protected gh's github.com token as \(reference.uri)\n"
    output += "  gh now sends its GitHub requests to \(socketPath) with a placeholder; csecd adds the token for processes you approve.\n"
    FileHandle.standardOutput.write(Data(output.utf8))
    finishProtectGitHub(gh: gh, keepPlaintext: keepPlaintext, dryRun: false, switched: true)
}

/// Removes gh's own copies of the active github.com account's token once gh
/// reports csec's placeholder: its keychain items and the account's entry in
/// hosts.yml. Other accounts and hosts are not csec's import and stay as they
/// are. Never returns.
private func finishProtectGitHub(gh: GitHubCLI, keepPlaintext: Bool, dryRun: Bool, switched: Bool = false) -> Never {
    let keychainItems = GitHubCLI.keychainAccounts(login: gh.login).filter(GitHubCLI.keychainItemExists)
    let accountLines = GitHubCLI.activeAccountTokenLines(configDirectory: gh.configDirectory, login: gh.login)
    var output = ""
    var retained: [String] = []
    if keychainItems.isEmpty && accountLines == 0 {
        if !switched {
            output += "csec protect --gh: gh already uses csec's GitHub socket; nothing to do.\n"
        }
    } else if keepPlaintext || dryRun {
        output += (switched ? "  " : "csec protect --gh: gh uses csec's GitHub socket; ")
            + "\(keychainItems.count) gh keychain item(s) and \(accountLines) hosts.yml account line(s) still hold the old token"
            + (dryRun ? " (dry run: nothing changed)" : " (--keep-plaintext); run `csec protect --gh` again to remove them")
            + "\n"
    } else {
        let rewritten: Int
        do {
            rewritten = try GitHubCLI.replaceActiveAccountTokens(configDirectory: gh.configDirectory, login: gh.login)
        } catch {
            protectFail("gh uses csec's GitHub socket, but its hosts.yml account entry could not be updated (\(error.localizedDescription))")
        }
        for account in keychainItems where !GitHubCLI.deleteKeychainItem(account: account) {
            retained.append(account.isEmpty ? "(active account)" : account)
        }
        if rewritten > 0 {
            output += "  replaced \(rewritten) plaintext token line(s) in gh's hosts.yml\n"
        }
        output += "  deleted \(keychainItems.count - retained.count) gh keychain item(s)\n"
    }
    if ProcessInfo.processInfo.environment["GH_TOKEN"] != nil
        || ProcessInfo.processInfo.environment["GITHUB_TOKEN"] != nil {
        output += "  note: GH_TOKEN or GITHUB_TOKEN is set in this shell; gh uses it before csec's socket token. Remove it from your environment.\n"
    }
    if !keepPlaintext, !dryRun, GitHubCLI.hostsTokenLines(configDirectory: gh.configDirectory).other > 0 {
        output += "  note: hosts.yml still holds a token for another github.com account, which csec did not import; `gh auth logout` for it, or switch to it and run `csec protect --gh` instead.\n"
    }
    if GitHubCLI.gitUsesGHCredentialHelper() {
        output += "  note: git uses gh as its HTTPS credential helper, which now hands git the placeholder. Use SSH for git (csec ssh) or `csec creds git`.\n"
    }
    output += "  This revokes nothing: a copy of the token taken before now still works until you revoke it on GitHub.\n"
    FileHandle.standardOutput.write(Data(output.utf8))
    if !retained.isEmpty {
        FileHandle.standardError.write(Data(
            "csec protect --gh: warning: \(retained.count) gh keychain item(s) could not be deleted (\(retained.joined(separator: ", ")))\n".utf8
        ))
        exit(1)
    }
    exit(0)
}

// MARK: - gh

struct GitHubCLI {
    let path: String
    let configDirectory: String
    /// The github.com login from gh's hosts.yml, if any.
    let login: String?

    struct Result {
        let status: Int32
        let output: Data
        var text: String { String(decoding: GitHubProxyToken.normalized(output), as: UTF8.self) }
    }

    static func locate() -> GitHubCLI? {
        guard let path = try? ExecutableInspection.resolve(command: "gh") else { return nil }
        let environment = ProcessInfo.processInfo.environment
        let directory: String
        if let configured = environment["GH_CONFIG_DIR"], !configured.isEmpty {
            directory = configured
        } else if let xdg = environment["XDG_CONFIG_HOME"], !xdg.isEmpty {
            directory = (xdg as NSString).appendingPathComponent("gh")
        } else {
            directory = (canonicalHomeDirectory() as NSString).appendingPathComponent(".config/gh")
        }
        var cli = GitHubCLI(path: path, configDirectory: directory, login: nil)
        let login = cli.run(["config", "get", "-h", ghHost, "user"]).text
        if !login.isEmpty, login.utf8.count <= 64,
           login.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7f }) {
            cli = GitHubCLI(path: cli.path, configDirectory: directory, login: login)
        }
        return cli
    }

    /// Runs gh with no token from this shell's environment, no prompts and no
    /// update check, capturing stdout. stderr is discarded: csec reports its
    /// own message rather than echo gh's.
    func run(_ arguments: [String]) -> Result {
        var environment = ProcessInfo.processInfo.environment
        for name in ["GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "GH_HOST"] {
            environment.removeValue(forKey: name)
        }
        environment["GH_CONFIG_DIR"] = configDirectory
        environment["GH_PROMPT_DISABLED"] = "1"
        environment["GH_NO_UPDATE_NOTIFIER"] = "1"
        environment["NO_COLOR"] = "1"
        return Self.capture(path, arguments, environment: environment)
    }

    static func capture(_ path: String, _ arguments: [String], environment: [String: String]? = nil) -> Result {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        if let environment { process.environment = environment }
        let pipe = Pipe()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return Result(status: 127, output: Data()) }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let status = process.terminationReason == .exit ? process.terminationStatus : 128
        return Result(status: status, output: data)
    }

    static func keychainAccounts(login: String?) -> [String] {
        var accounts = [""]
        if let login, !login.isEmpty { accounts.append(login) }
        return accounts
    }

    /// Whether gh's keychain item for `account` exists, by its attributes
    /// alone: no `-w`, so the token is never read.
    static func keychainItemExists(_ account: String) -> Bool {
        capture(securityTool, ["find-generic-password", "-s", ghKeychainService, "-a", account]).status == 0
    }

    static func deleteKeychainItem(account: String) -> Bool {
        let status = capture(securityTool, ["delete-generic-password", "-s", ghKeychainService, "-a", account]).status
        return status == 0 && !keychainItemExists(account)
    }

    /// Lines of hosts.yml that set `oauth_token`, counted by whether they name
    /// csec's placeholder. The values themselves are never kept or shown.
    static func hostsTokenLines(configDirectory: String) -> (placeholder: Int, other: Int) {
        let path = (configDirectory as NSString).appendingPathComponent("hosts.yml")
        guard let (data, _) = try? readRegularFile(atPath: path) else { return (0, 0) }
        var placeholder = 0
        var other = 0
        for line in String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false) {
            guard let value = tokenValue(in: Substring(line)) else { continue }
            if value == GitHubProxyHTTP.placeholderToken { placeholder += 1 } else if !value.isEmpty { other += 1 }
        }
        return (placeholder, other)
    }

    /// The hosts gh's hosts.yml names: its top-level keys.
    static func hostsFileHosts(configDirectory: String) -> [String] {
        hostsFileEntries(configDirectory: configDirectory)?.lines.compactMap { line in
            line.path.isEmpty && line.opensBlock ? line.key : nil
        } ?? []
    }

    /// How many `oauth_token` lines of the active github.com account (the
    /// host's own and `users.<login>`'s) hold something other than csec's
    /// placeholder. Found by where they are in the file, never by value.
    static func activeAccountTokenLines(configDirectory: String, login: String?) -> Int {
        guard let entries = hostsFileEntries(configDirectory: configDirectory) else { return 0 }
        return entries.lines.indices.filter { isActiveAccountToken(entries.lines[$0], login: login) }.count
    }

    /// Replaces those lines' values with the placeholder, in place and
    /// atomically, keeping the file's mode. Other accounts' and other hosts'
    /// tokens are not csec's import and stay. Returns how many.
    static func replaceActiveAccountTokens(configDirectory: String, login: String?) throws -> Int {
        guard let entries = hostsFileEntries(configDirectory: configDirectory) else { return 0 }
        var replaced = 0
        let rewritten = entries.lines.map { line -> String in
            guard isActiveAccountToken(line, login: login), let colon = line.text.firstIndex(of: ":") else {
                return String(line.text)
            }
            replaced += 1
            return String(line.text[...colon]) + " " + GitHubProxyHTTP.placeholderToken
        }
        guard replaced > 0 else { return 0 }
        let temporary = entries.path + ".csec-\(getpid())"
        let output = Data(rewritten.joined(separator: "\n").utf8)
        guard FileManager.default.createFile(
            atPath: temporary, contents: output,
            attributes: [.posixPermissions: NSNumber(value: Int16(entries.mode & 0o777))]
        ) else { throw ProtectError(message: "could not write a replacement hosts.yml") }
        guard rename(temporary, entries.path) == 0 else {
            unlink(temporary)
            throw ProtectError(message: "could not replace hosts.yml")
        }
        return replaced
    }

    private static func isActiveAccountToken(_ line: HostsLine, login: String?) -> Bool {
        guard line.key == "oauth_token",
              let value = tokenValue(in: line.text), !value.isEmpty, value != GitHubProxyHTTP.placeholderToken
        else { return false }
        if line.path == [ghHost] { return true }
        guard let login else { return false }
        return line.path == [ghHost, "users", login]
    }

    /// One line of hosts.yml with the keys of the mappings that enclose it.
    struct HostsLine {
        let text: Substring
        /// The line's own key, or nil for a blank, comment or list line.
        let key: String?
        /// The keys of the enclosing mappings, outermost first.
        let path: [String]
        /// The key has no value on its line, so a nested mapping follows.
        let opensBlock: Bool
    }

    /// gh writes hosts.yml as block mappings indented with spaces; this reads
    /// just that shape: each key's enclosing keys by indentation.
    static func hostsFileEntries(configDirectory: String) -> (path: String, mode: mode_t, lines: [HostsLine])? {
        let path = (configDirectory as NSString).appendingPathComponent("hosts.yml")
        guard FileManager.default.fileExists(atPath: path),
              let (data, info) = try? readRegularFile(atPath: path) else { return nil }
        var stack: [(indent: Int, key: String)] = []
        var lines: [HostsLine] = []
        for text in String(decoding: data, as: UTF8.self).split(separator: "\n", omittingEmptySubsequences: false) {
            let indent = text.prefix { $0 == " " }.count
            let body = text.dropFirst(indent)
            guard !body.isEmpty, !body.hasPrefix("#"), !body.hasPrefix("-"), let colon = body.firstIndex(of: ":") else {
                lines.append(HostsLine(text: text, key: nil, path: stack.map(\.key), opensBlock: false))
                continue
            }
            while let last = stack.last, last.indent >= indent { stack.removeLast() }
            var key = body[..<colon].trimmingCharacters(in: .whitespaces)
            if key.count >= 2, let first = key.first, first == key.last, first == "\"" || first == "'" {
                key = String(key.dropFirst().dropLast())
            }
            let opensBlock = body[body.index(after: colon)...].trimmingCharacters(in: .whitespaces).isEmpty
            lines.append(HostsLine(text: text, key: key, path: stack.map(\.key), opensBlock: opensBlock))
            if opensBlock { stack.append((indent, key)) }
        }
        return (path, info.st_mode, lines)
    }

    private static func tokenValue(in line: Substring) -> String? {
        let trimmed = line.drop { $0 == " " || $0 == "\t" }
        guard trimmed.hasPrefix("oauth_token:") else { return nil }
        var value = trimmed.dropFirst("oauth_token:".count).trimmingCharacters(in: .whitespaces)
        if value.count >= 2, let first = value.first, first == value.last, first == "\"" || first == "'" {
            value = String(value.dropFirst().dropLast())
        }
        return value
    }

    /// Whether git's global configuration hands HTTPS credentials to gh.
    static func gitUsesGHCredentialHelper() -> Bool {
        let result = capture("/usr/bin/git", ["config", "--global", "--get-regexp", "^credential\\..*helper$"])
        return String(decoding: result.output, as: UTF8.self).contains("gh auth git-credential")
    }
}
