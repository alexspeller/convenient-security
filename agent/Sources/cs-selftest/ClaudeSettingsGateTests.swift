import Foundation
import ConvenientSecurity
import Darwin

// The Claude Code settings gate (G1, G2, G5 on settings, G6) against fixture
// homes on disk. Every file is synthetic; the real ~/.claude is never read.

private let gateCsecPath = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"

/// A fixture: a home, a git project inside it, managed settings and managed
/// preferences directories, all under one temporary root.
private struct GateFixture {
    let root: URL
    var home: String { root.appendingPathComponent("home").path }
    var project: String { home + "/work/project" }
    var workingDirectory: String { project + "/src" }
    var managed: String { root.appendingPathComponent("managed").path }
    var preferences: String { root.appendingPathComponent("preferences").path }
    var userSettings: String { home + "/.claude/settings.json" }
    var projectSettings: String { project + "/.claude/settings.json" }
    var localSettings: String { project + "/.claude/settings.local.json" }

    init(_ tag: String) throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("csec-gate-\(tag)-\(UUID().uuidString.prefix(8))").resolvingSymlinksInPath()
        for directory in [root.path, root.path + "/home", root.path + "/managed", root.path + "/preferences"] {
            try FileManager.default.createDirectory(
                atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        try FileManager.default.createDirectory(
            atPath: root.path + "/home/work/project/src", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            atPath: root.path + "/home/work/project/.git", withIntermediateDirectories: true)
    }

    func scope(
        configDirectory: String? = nil,
        workingDirectories: [String]? = nil,
        additional: [String] = [],
        launchSettings: [String] = []
    ) -> ClaudeSettingsScope {
        ClaudeSettingsScope(
            homeDirectory: home, claudeConfigDirectory: configDirectory,
            workingDirectories: workingDirectories ?? [workingDirectory], additionalDirectories: additional,
            managedSettingsDirectory: managed, managedPreferencesDirectory: preferences,
            userName: "synthetic", csecExecutablePath: gateCsecPath, launchSettings: launchSettings,
            systemRoot: root.path + "/system")
    }

    func write(_ path: String, _ object: Any) {
        write(path, text: String(decoding: (try? JSONSerialization.data(
            withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data(), as: UTF8.self))
    }

    func write(_ path: String, text: String) {
        let url = URL(fileURLWithPath: path)
        try? FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try? Data(text.utf8).write(to: url)
    }

    func remove(_ path: String) { try? FileManager.default.removeItem(atPath: path) }

    func cleanUp() {
        _ = chmodTree(root.path)
        try? FileManager.default.removeItem(at: root)
    }

    /// Restore owner permissions everywhere so the fixture can be deleted.
    private func chmodTree(_ path: String) -> Bool {
        let enumerator = FileManager.default.enumerator(atPath: path)
        chmod(path, 0o700)
        while let relative = enumerator?.nextObject() as? String { chmod(path + "/" + relative, 0o700) }
        return true
    }
}

private func csecHookSettings() -> [String: Any] {
    guard let data = try? AICommandHook.hookConfiguration(client: .claude, csecExecutablePath: gateCsecPath),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
    return object
}

private func settings(classifyAllShell: Bool = true, hooks extraHooks: [String: Any] = [:],
                      extra: [String: Any] = [:]) -> [String: Any] {
    var object = csecHookSettings()
    var hooks = object["hooks"] as? [String: Any] ?? [:]
    for (event, groups) in extraHooks {
        hooks[event] = (hooks[event] as? [Any] ?? []) + (groups as? [Any] ?? [])
    }
    object["hooks"] = hooks
    if classifyAllShell { object["autoMode"] = ["classifyAllShell": true] }
    for (key, value) in extra { object[key] = value }
    return object
}

private func handler(_ command: String) -> [String: Any] { ["type": "command", "command": command] }

private func group(_ matcher: String?, _ command: String = "/usr/local/bin/approver") -> [String: Any] {
    var group: [String: Any] = ["hooks": [handler(command)]]
    if let matcher { group["matcher"] = matcher }
    return group
}

private final class CountingSettingsFiles: ClaudeSettingsFileAccess, @unchecked Sendable {
    private let live = LiveClaudeSettingsFileAccess()
    private let lock = NSLock()
    private var statuses = 0
    private var reads = 0
    private var listings = 0

    var counts: (statuses: Int, reads: Int, listings: Int) {
        lock.lock(); defer { lock.unlock() }
        return (statuses, reads, listings)
    }

    func status(of path: String) -> ClaudeSettingsPathStatus {
        lock.lock(); statuses += 1; lock.unlock()
        return live.status(of: path)
    }

    func contents(of path: String, maximumBytes: Int) -> ClaudeSettingsFileContents {
        lock.lock(); reads += 1; lock.unlock()
        return live.contents(of: path, maximumBytes: maximumBytes)
    }

    func entries(of directory: String, maximumCount: Int) -> ClaudeSettingsDirectoryListing {
        lock.lock(); listings += 1; lock.unlock()
        return live.entries(of: directory, maximumCount: maximumCount)
    }
}

func claudeSettingsGateTests() {
    print("\n# Claude settings gate (fixture homes)")
    gateMatcherTests()
    gateFetchCheckTests()
    do {
        try gateClassifyAllShellTests()
        try gateHookTests()
        try gatePluginTests()
        try gateFrontmatterTests()
        try gateFrontmatterUncertaintyTests()
        try gateEnvironmentTests()
        try gateOtherSettingsTests()
        try gateLaunchSettingsTests()
        try gateUnreadableTests()
        try gateCacheTests()
        try gateBuildTests()
        try gateLegacyNPMBuildTests()
        try gatePluginSourceTests()
        try gateDeclaredMarketplaceTests()
        try gateWorktreeTests()
        try gatePolicySourceTests()
        try gateGeneratedPolicyTests()
        try gateRelease267PluginTests()
        try gateRelease282SourcesTests()
        try gateCacheChangeTimeTests()
        try gateHookSourceReviewTests()
        try gateClassifierRuleTests()
        try gateSharedConfigHomeTests()
    } catch {
        check(false, "Claude settings gate fixtures set up (\(error))")
    }
}

// MARK: - Matchers and the npx check

private func gateMatcherTests() {
    let matching: [String?] = [
        nil, "", "*", "Bash", "Bash|Edit", "Edit|Bash", "^B.*", ".*", "Ba.h", "(Bash)", "bash|.*",
        "Monitor", "Edit|Monitor", "Bash|Monitor", "Mon.*",
    ]
    for matcher in matching {
        check(ClaudeHookSource.matcherCanMatchShellTool(matcher),
              "gate: matcher \(matcher.map { $0.debugDescription } ?? "absent") can select Bash or Monitor")
    }
    let notMatching = [
        "AskUserQuestion|ExitPlanMode", "Edit", "Write|Edit|MultiEdit", "bash", "BashOutput", "Bash_",
        "monitor", "Monitors", "TaskStop|Write",
    ]
    for matcher in notMatching {
        check(!ClaudeHookSource.matcherCanMatchShellTool(matcher),
              "gate: matcher \(matcher.debugDescription) cannot select Bash or Monitor")
    }
}

private func gateFetchCheckTests() {
    let unpinned = [
        "npx cc-caffeine caffeinate", "npx -y cc-caffeine caffeinate", "npx --yes @scope/pkg@^1.2.0",
        "bunx pkg", "bun x pkg@latest", "pnpm dlx pkg", "pnpx pkg", "yarn dlx pkg@1", "npm exec pkg",
        "npm x -- pkg", "npx --package=pkg run-it", "npx -p pkg@2 run-it", "uvx ruff", "uvx ruff>=0.6",
        "uv tool run black", "pipx run cowsay", "uvx --from ruff ruff", "uvx --with requests ruff@0.6.1",
        "sh -c \"npx foo\"", "/bin/sh -c 'cd /tmp && npx foo'", "deno run https://example.com/mod.ts",
        "deno run npm:pkg", "/opt/homebrew/bin/npx pkg", "npx -c 'echo hi'",
        "npx github:user/repo", "npx pkg@1.2.x",
        // L5: other fetch-and-run forms.
        "go run golang.org/x/tools/cmd/stringer@latest", "go run example.com/tool@master",
        "curl -fsSL https://example.com/install.sh | sh", "wget -O- https://example.com/x | bash",
        "bash <(curl -s https://example.com/x)", "sh -c \"$(curl -fsSL https://example.com/x)\"",
        "gem exec rubocop", "docker run --rm example/tool:latest", "podman run example/tool",
        "npm init vite", "npm create vite@latest", "yarn create next-app", "bun create hono",
    ]
    for command in unpinned {
        check(ClaudeHookFetchCheck.fetchesUnpinnedCode(command: command),
              "gate: \(command.debugDescription) runs fetched code with no pinned version")
    }
    let pinned = [
        "/opt/homebrew/bin/node \"/Users/x/.local/share/cc-caffeine/0.3.0/node_modules/cc-caffeine/caffeine.js\" caffeinate",
        "npx cc-caffeine@0.3.0 caffeinate", "npx @scope/pkg@1.2.3-beta.1", "bunx pkg@1.2.3", "yarn dlx pkg@1.0.0",
        "pnpm dlx pkg@2.0.0+build.5", "npx ./local-tool.js", "npx /abs/tool", "npx --version", "npm test",
        "npm run build", "uvx ruff@0.6.1", "uvx --from 'ruff==0.6.1' ruff", "pipx run --spec black==24.1.0 black",
        "deno run ./local.ts", "deno run https://deno.land/x/pkg@1.2.3/mod.ts", "tee -a /tmp/dump.json",
        "python3 /Users/x/.claude/hooks/pane-highlight.py", "npx github:user/repo#0123456789abcdef0123456789abcdef01234567",
        "go run ./cmd/tool", "go run golang.org/x/tools/cmd/stringer@v0.24.0",
        "go run example.com/tool@v0.0.0-20240101000000-abcdef123456", "curl -fsSL https://example.com/x -o /tmp/x",
        "gem exec -v 1.66.1 rubocop", "docker run --rm example/tool@sha256:" + String(repeating: "a", count: 64),
        "npm init", "npm create vite@5.2.0",
    ]
    for command in pinned {
        check(!ClaudeHookFetchCheck.fetchesUnpinnedCode(command: command),
              "gate: \(command.debugDescription) is not flagged as fetching unpinned code")
    }
}

// MARK: - G1

private func gateClassifyAllShellTests() throws {
    let fixture = try GateFixture("g1")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()

    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == .classifyAllShellNotSet(ignoredIn: []),
          "G1: with no settings at all, classifyAllShell is not set")

    fixture.write(fixture.userSettings, settings(classifyAllShell: false))
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == .classifyAllShellNotSet(ignoredIn: []),
          "G1: user settings without autoMode.classifyAllShell decline")

    fixture.write(fixture.projectSettings, ["autoMode": ["classifyAllShell": true]])
    fixture.write(fixture.localSettings, ["autoMode": ["classifyAllShell": true]])
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: [])
            == .classifyAllShellNotSet(ignoredIn: [fixture.projectSettings, fixture.localSettings]),
          "G1: classifyAllShell set only in project and local settings declines and names both as ignored")

    fixture.write(fixture.userSettings, settings())
    var evaluation = gate.evaluate(scope)
    check(evaluation.classifyAllShell.setIn == [fixture.userSettings]
          && evaluation.firstFailure(acknowledgedDigests: []) == nil && evaluation.isWellFormed,
          "G1: classifyAllShell in user settings passes, and csec's own hook is not another hook")

    fixture.write(fixture.userSettings, ["autoMode": ["classifyAllShell": "true"]])
    check(!gate.evaluate(scope).classifyAllShell.isSet, "G1: only the boolean true counts")

    // Managed settings: the file and its drop-ins, the MDM plist, remote settings.
    fixture.write(fixture.userSettings, settings(classifyAllShell: false))
    fixture.remove(fixture.projectSettings)
    fixture.remove(fixture.localSettings)
    let managedFile = fixture.managed + "/managed-settings.json"
    fixture.write(managedFile, ["autoMode": ["classifyAllShell": true]])
    evaluation = gate.evaluate(scope)
    check(evaluation.classifyAllShell.setIn == [managedFile] && evaluation.firstFailure(acknowledgedDigests: []) == nil,
          "G1: classifyAllShell in managed settings passes")
    fixture.write(fixture.managed + "/managed-settings.d/10-org.json", ["model": "x"])
    check(!gate.evaluate(scope).classifyAllShell.isSet,
          "G1: a policy source that does not set it withholds the policy's credit (only one source applies)")
    fixture.write(fixture.managed + "/managed-settings.d/10-org.json", ["autoMode": ["classifyAllShell": true]])
    fixture.write(fixture.managed + "/managed-settings.d/.hidden.json", ["model": "x"])
    fixture.write(fixture.managed + "/managed-settings.d/notes.txt", text: "not settings")
    check(gate.evaluate(scope).classifyAllShell.setIn.count == 2,
          "G1: drop-ins count as Claude Code loads them (.json, not hidden)")
    fixture.write(fixture.home + "/.claude/remote-settings.json", [String: Any]())
    check(gate.evaluate(scope).classifyAllShell.isSet, "G1: an empty policy source is not the one that applies")
    fixture.remove(managedFile)
    fixture.remove(fixture.managed + "/managed-settings.d")

    let plistPath = fixture.preferences + "/synthetic/com.anthropic.claudecode.plist"
    try FileManager.default.createDirectory(atPath: fixture.preferences + "/synthetic", withIntermediateDirectories: true)
    let plist = try PropertyListSerialization.data(
        fromPropertyList: ["autoMode": ["classifyAllShell": true]], format: .binary, options: 0)
    try plist.write(to: URL(fileURLWithPath: plistPath))
    check(gate.evaluate(scope).classifyAllShell.setIn == [plistPath],
          "G1: classifyAllShell in the per-user managed preferences plist passes")
    fixture.remove(plistPath)

    // A policy false cannot undo a user true.
    fixture.write(fixture.userSettings, settings())
    fixture.write(managedFile, ["autoMode": ["classifyAllShell": false]])
    check(gate.evaluate(scope).classifyAllShell.setIn == [fixture.userSettings],
          "G1: a managed false does not undo a user true")

    // CLAUDE_CONFIG_DIR moves the user settings file.
    let configHome = fixture.root.appendingPathComponent("config").path
    fixture.write(configHome + "/settings.json", settings())
    fixture.write(fixture.userSettings, settings(classifyAllShell: false))
    check(gate.evaluate(fixture.scope(configDirectory: configHome)).classifyAllShell.setIn
            == [configHome + "/settings.json"],
          "G1: with CLAUDE_CONFIG_DIR the user settings are read from it")

    // The cowork variant can only decline.
    fixture.write(fixture.home + "/.claude/cowork_settings.json", ["autoMode": ["classifyAllShell": true]])
    check(!gate.evaluate(scope).classifyAllShell.isSet,
          "G1: classifyAllShell in cowork_settings.json does not count for the normal user settings")
}

// MARK: - G2: settings hooks

private func gateHookTests() throws {
    let fixture = try GateFixture("g2")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()

    func hooks(_ extra: [String: Any]) -> [ClaudeHookSource] {
        fixture.write(fixture.userSettings, settings(hooks: extra))
        return gate.evaluate(scope).hooks
    }
    // Monitor runs its command in the Bash tool shell, under the same
    // classifier: a hook that can approve it skips the classifier too.
    for matcher in ["Bash", "*", "", "Bash|Edit", "^Ba.*", "Monitor", "Edit|Monitor"] as [String] {
        let found = hooks(["PreToolUse": [group(matcher)]])
        check(found.count == 1 && found[0].kind == .settings && found[0].event == "PreToolUse"
              && found[0].matcher == matcher && found[0].sourceID == fixture.userSettings,
              "G2: a PreToolUse hook with matcher \(matcher.debugDescription) can approve a shell command")
    }
    check(hooks(["PermissionRequest": [group("Monitor")]]).count == 1,
          "G2: a PermissionRequest hook for Monitor can approve a shell command")
    let absent = hooks(["PreToolUse": [group(nil)]])
    check(absent.count == 1 && absent[0].matcher == nil && absent[0].display.hasSuffix("PreToolUse *")
          && absent[0].display.hasPrefix("~/.claude/settings.json"),
          "G2: a PreToolUse hook with no matcher approves everything, shown as ~/… · PreToolUse *")
    check(hooks(["PreToolUse": [group("AskUserQuestion|ExitPlanMode")]]).isEmpty,
          "G2: an AskUserQuestion|ExitPlanMode hook cannot approve Bash and passes")
    check(hooks(["PostToolUse": [group("*")], "Notification": [group(nil)]]).isEmpty,
          "G2: events that cannot approve a call are not hooks here")
    let permission = hooks(["PermissionRequest": [group(nil, "tee -a /tmp/permission-request-dump.json")]])
    check(permission.count == 1 && permission[0].event == "PermissionRequest" && !permission[0].fetchesUnpinnedCode,
          "G2: a PermissionRequest hook with no matcher can approve the fallback prompt")

    // csec's own handler is excluded only byte for byte.
    var alteredCsec = csecHookSettings()
    var groups = ((alteredCsec["hooks"] as? [String: Any])?["PreToolUse"] as? [[String: Any]]) ?? []
    var handlers = groups.first?["hooks"] as? [[String: Any]] ?? []
    if !handlers.isEmpty { handlers[0]["timeout"] = 5 }
    if !groups.isEmpty { groups[0]["hooks"] = handlers }
    alteredCsec["hooks"] = ["PreToolUse": groups]
    alteredCsec["autoMode"] = ["classifyAllShell": true]
    fixture.write(fixture.userSettings, alteredCsec)
    check(gate.evaluate(scope).hooks.count == 1,
          "G2: a csec handler that differs from the installed one in any byte is another hook")

    // Acknowledgement is by digest; any change is a new digest.
    let first = hooks(["PreToolUse": [group("*", "/usr/local/bin/approver --one")]])
    let acknowledged = Set(first.map(\.digest))
    check(first.count == 1 && gate.evaluate(scope).firstFailure(acknowledgedDigests: acknowledged) == nil,
          "G2: an acknowledged hook's digest passes")
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == .unacknowledgedHook(first[0]),
          "G2: an unacknowledged hook declines")
    let changed = hooks(["PreToolUse": [group("*", "/usr/local/bin/approver --two")]])
    check(changed.count == 1 && changed[0].digest != first[0].digest
          && gate.evaluate(scope).firstFailure(acknowledgedDigests: acknowledged) == .unacknowledgedHook(changed[0]),
          "G2: a changed hook has a new digest and declines until acknowledged")
    let moved = hooks(["PreToolUse": [group("Bash", "/usr/local/bin/approver --two")]])
    check(moved.count == 1 && moved[0].digest != changed[0].digest, "G2: a changed matcher is a new digest")
    check(first[0].digest.utf8.count == 64 && first[0].isWellFormed && first[0].displayID.hasPrefix("hook-"),
          "G2: a hook is identified by a 64-hex digest and a hook- id")

    // Project and local hooks count; the walk stops at the git root.
    fixture.write(fixture.userSettings, settings())
    fixture.write(fixture.localSettings, ["hooks": ["PreToolUse": [group("Bash")]]])
    fixture.write(fixture.home + "/work/.claude/settings.json", ["hooks": ["PreToolUse": [group("Bash")]]])
    let projectHooks = gate.evaluate(scope).hooks
    check(projectHooks.map(\.sourceID) == [fixture.localSettings],
          "G2: local project hooks count, and settings above the git root are not read")
    try FileManager.default.removeItem(atPath: fixture.project + "/.git")
    check(Set(gate.evaluate(scope).hooks.map(\.sourceID)) == [fixture.localSettings, fixture.home + "/work/.claude/settings.json"],
          "G2: with no git root the walk reaches the home directory")

    // A hook's command that fetches unpinned code is flagged.
    fixture.write(fixture.localSettings, ["hooks": ["PreToolUse": [group("*", "npx cc-caffeine caffeinate")]]])
    fixture.remove(fixture.home + "/work/.claude/settings.json")
    check(gate.evaluate(scope).hooks.first?.fetchesUnpinnedCode == true,
          "G2: a hook that runs `npx pkg` is flagged as fetching unpinned code")
    fixture.write(fixture.localSettings, ["hooks": ["PreToolUse": [["matcher": "*", "hooks": [[
        "type": "command", "command": "/opt/homebrew/bin/node",
        "args": ["/Users/x/.local/share/cc-caffeine/0.3.0/node_modules/cc-caffeine/caffeine.js", "caffeinate"],
    ]]]]]])
    check(gate.evaluate(scope).hooks.first?.fetchesUnpinnedCode == false,
          "G2: a pinned local copy run through node is not flagged")
    // What each handler runs, for the hooks-changed panel (csec-0.64.7):
    // display only, covered by the digest, never on the wire.
    let summarised = gate.evaluate(scope).hooks.first
    check(summarised?.handlerSummaries == [
        "/opt/homebrew/bin/node /Users/x/.local/share/cc-caffeine/0.3.0/node_modules/cc-caffeine/caffeine.js caffeinate",
    ], "G2: a hook carries what its handler runs (command and arguments) for csecd's panel")
    let summaryWire = summarised.flatMap { try? JSONEncoder().encode($0) }
        .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] }
    check(summaryWire != nil && summaryWire?["handlerSummaries"] == nil,
          "G2: handler summaries never go on the wire")
    fixture.write(fixture.localSettings, ["hooks": ["PreToolUse": [["matcher": "Bash", "hooks": [
        ["type": "command", "command": "python3 ~/.local/share/harbor/harbor-hook.py pr-cap claude"],
        ["type": "http", "url": "https://hooks.example/approve"],
    ]]]]])
    check(gate.evaluate(scope).hooks.first?.handlerSummaries == [
        "python3 ~/.local/share/harbor/harbor-hook.py pr-cap claude",
        "{\"type\":\"http\",\"url\":\"https://hooks.example/approve\"}",
    ], "G2: a command handler shows its command, any other handler as written")
    // The panel reaches the phone only when it shows each source whole
    // (av-rcqg): what the gate cuts short to its own bounds keeps it at the
    // Mac, though the line still fits the panel.
    let whole = gate.evaluate(scope).hooks
    check(whole.count == 1 && whole[0].shownWhole
            && ClaudeDelegationService.changedRulesReview(whole, acknowledged: []).phoneOperationDigest
                == ClaudeDelegationService.acknowledgementDigest(whole),
          "G2: a hook the gate shows whole may be decided on the phone")
    let padded = "/usr/local/bin/approver " + String(repeating: "x", count: 600) + " payload"
    fixture.write(fixture.localSettings, ["hooks": ["PreToolUse": [group("Bash", padded)]]])
    let longCommand = gate.evaluate(scope).hooks
    check(longCommand.count == 1 && !longCommand[0].shownWhole
            && longCommand[0].handlerSummaries?.first?.hasSuffix("…") == true
            && ClaudeDelegationService.changedRulesReview(longCommand, acknowledged: []).phoneOperationDigest == nil,
          "G2: a command cut to the summary bound keeps its panel on this Mac")
    let tools = "Bash|Edit|Write|Read|Glob|Grep|NotebookEdit|WebFetch|WebSearch|Task"
    fixture.write(fixture.localSettings, ["hooks": ["PreToolUse": [group(tools)]]])
    let longMatcher = gate.evaluate(scope).hooks
    check(longMatcher.count == 1 && longMatcher[0].matcher == tools && !longMatcher[0].shownWhole
            && ClaudeDelegationService.changedRulesReview(longMatcher, acknowledged: []).phoneOperationDigest == nil,
          "G2: a matcher cut short in the hook's name keeps its panel on this Mac")
    func commandHook(_ handler: [String: Any]) -> ClaudeHookSource? {
        fixture.write(fixture.localSettings, ["hooks": ["PreToolUse": [["matcher": "Bash", "hooks": [handler]]]]])
        let found = gate.evaluate(scope).hooks
        return found.count == 1 ? found[0] : nil
    }
    let quiet = commandHook([
        "type": "command", "command": "/usr/local/bin/approver", "args": ["--check"], "timeout": 5,
        "statusMessage": "Checking",
    ])
    check(quiet?.shownWhole == true && quiet?.handlerSummaries == ["/usr/local/bin/approver --check"],
          "G2: a command handler's timeout and status message change nothing it runs, so it is still shown whole")
    let unshownKey = commandHook(["type": "command", "command": "/usr/local/bin/approver", "shell": "/bin/zsh"])
    let unshownArgument = commandHook(["type": "command", "command": "/usr/local/bin/approver", "args": ["--check", 7]])
    let oddArguments = commandHook(["type": "command", "command": "/usr/local/bin/approver", "args": "--check"])
    check([unshownKey, unshownArgument, oddArguments].allSatisfy { hook in
              guard let hook else { return false }
              return !hook.shownWhole
                  && ClaudeDelegationService.changedRulesReview([hook], acknowledged: []).phoneOperationDigest == nil
          },
          "G2: a command handler with a setting or argument its line leaves out keeps its panel on this Mac")
    let wire = try? JSONDecoder().decode(ClaudeHookSource.self, from: JSONEncoder().encode(whole[0]))
    check(wire == whole[0] && wire?.shownWhole == false,
          "G2: a decoded hook is never taken as shown whole")

    // More approving hooks than an evaluation carries: the rest are reported.
    let many = (0..<300).map { group("*", "/usr/local/bin/approver \($0)") }
    fixture.write(fixture.localSettings, ["hooks": ["PreToolUse": many]])
    let crowded = gate.evaluate(scope)
    check(crowded.hooks.count == ClaudeSettingsGateEvaluation.maximumHooks
          && crowded.unreadable.contains(ClaudeUnreadableSetting(path: fixture.localSettings, reason: .tooMany))
          && crowded.isWellFormed,
          "G2: hooks beyond the evaluation's bound are reported as too many, never dropped")
}

// MARK: - G2: plugins

private func gatePluginTests() throws {
    let fixture = try GateFixture("plugins")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    let plugins = fixture.home + "/.claude/plugins"
    let install = plugins + "/cache/market/tool/1.0.0"
    fixture.write(plugins + "/installed_plugins.json", ["version": 2, "plugins": [
        "tool@market": [["scope": "user", "installPath": install, "version": "1.0.0"]],
        "other@market": [["scope": "user", "installPath": plugins + "/cache/market/other/2.0.0", "version": "2.0.0"]],
    ]])
    fixture.write(install + "/hooks/hooks.json", ["description": "keeps awake",
                                                  "hooks": ["PreToolUse": [group("*", "npx tool caffeinate")]]])
    fixture.write(plugins + "/cache/market/other/2.0.0/hooks/hooks.json",
                  ["hooks": ["PreToolUse": [group("*", "/bin/other")]]])

    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["tool@market": false]]))
    check(gate.evaluate(scope).hooks.isEmpty, "G2: a disabled plugin's hooks are not read")

    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["tool@market": true]]))
    var found = gate.evaluate(scope).hooks
    check(found.count == 1 && found[0].kind == .plugin && found[0].sourceID == "tool@market@1.0.0"
          && found[0].display == "tool@market · PreToolUse *" && found[0].fetchesUnpinnedCode,
          "G2: an enabled plugin's hooks/hooks.json hook is found, named by id@version, and flagged for npx")

    fixture.write(fixture.projectSettings, ["enabledPlugins": ["other@market": ["^2.0.0"]]])
    check(gate.evaluate(scope).hooks.count == 2, "G2: a plugin enabled in project settings (with constraints) counts")
    fixture.remove(fixture.projectSettings)

    // The manifest's hooks: a path, inline hooks, and an array of both.
    fixture.write(install + "/.claude-plugin/plugin.json", ["name": "tool", "hooks": [
        "./extra-hooks.json",
        ["PermissionRequest": [group(nil, "/bin/inline-approver")]],
    ]])
    fixture.write(install + "/extra-hooks.json", ["hooks": ["PreToolUse": [group("Bash", "/bin/extra")]]])
    found = gate.evaluate(scope).hooks
    check(Set(found.compactMap(\.event)) == ["PreToolUse", "PermissionRequest"] && found.count == 3,
          "G2: a plugin manifest's hook file and inline hooks are read")

    // A marketplace entry's hooks.
    let marketplace = plugins + "/marketplaces/market"
    fixture.write(plugins + "/known_marketplaces.json", ["market": ["installLocation": marketplace]])
    fixture.write(marketplace + "/.claude-plugin/marketplace.json", ["name": "market", "plugins": [
        ["name": "tool", "hooks": ["PreToolUse": [group("Bash", "/bin/from-marketplace")]]],
        ["name": "unrelated", "hooks": 42],
    ]])
    check(gate.evaluate(scope).hooks.count == 4 && gate.evaluate(scope).unreadable.isEmpty,
          "G2: a marketplace entry's hooks count, and another entry's malformed hooks do not decline")

    fixture.write(plugins + "/installed_plugins.json", text: "{not json")
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: [])
            == .unreadable(ClaudeUnreadableSetting(path: plugins + "/installed_plugins.json", reason: .unparseable)),
          "G2: an unreadable installed_plugins.json declines while a plugin is enabled")
}

// MARK: - G2: skill, agent and command frontmatter

private func gateFrontmatterTests() throws {
    let fixture = try GateFixture("frontmatter")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    fixture.write(fixture.userSettings, settings())
    let skill = fixture.home + "/.claude/skills/deploy/SKILL.md"
    fixture.write(skill, text: "---\nname: deploy\nhooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n"
        + "        - type: command\n          command: npx approver\n---\nBody.\n")
    var found = gate.evaluate(scope).hooks
    check(found.count == 1 && found[0].kind == .frontmatter && found[0].sourceID == skill && found[0].event == nil
          && found[0].fetchesUnpinnedCode && found[0].display.hasPrefix("~/.claude/skills/deploy/SKILL.md"),
          "G2: a user skill whose frontmatter has hooks: is a hook source")

    fixture.write(skill, text: "---\nname: deploy\ndescription: deploys the app\n---\nhooks: in the body do not count\n")
    check(gate.evaluate(scope).hooks.isEmpty, "G2: `hooks:` outside the frontmatter does not count")
    fixture.write(skill, text: "no frontmatter\nhooks: here\n")
    check(gate.evaluate(scope).hooks.isEmpty, "G2: a file without frontmatter has no hooks")

    let agent = fixture.project + "/.claude/agents/reviewer.md"
    fixture.write(agent, text: "---\nname: reviewer\n\"hooks\" : {PreToolUse: []}\n---\n")
    let nested = fixture.project + "/.claude/commands/ops/.hidden/run.md"
    fixture.write(nested, text: "---\r\nhooks:\r\n  Stop: []\r\n---\r\n")
    found = gate.evaluate(scope).hooks
    check(Set(found.map(\.sourceID)) == [agent, nested],
          "G2: project agent and nested hidden command frontmatter hooks count (quoted key, CRLF)")

    let firstDigest = found.first { $0.sourceID == agent }?.digest
    fixture.write(agent, text: "---\nname: reviewer\n\"hooks\" : {PreToolUse: [x]}\n---\n")
    check(gate.evaluate(scope).hooks.first { $0.sourceID == agent }?.digest != firstDigest,
          "G2: a changed frontmatter is a new digest")

    // Additional directories, from the scope and from permissions.additionalDirectories.
    let extraDirectory = fixture.root.appendingPathComponent("extra").path
    let extraCommand = extraDirectory + "/.claude/commands/c.md"
    fixture.write(extraCommand, text: "---\nhooks: {}\n---\n")
    check(gate.evaluate(fixture.scope(additional: [extraDirectory])).hooks.contains { $0.sourceID == extraCommand },
          "G2: an --add-dir directory's commands are scanned")
    fixture.write(fixture.userSettings, settings(extra: ["permissions": ["additionalDirectories": [extraDirectory]]]))
    check(gate.evaluate(scope).hooks.contains { $0.sourceID == extraCommand },
          "G2: a permissions.additionalDirectories directory's commands are scanned")

    // A worktree also loads its main checkout's .claude directories.
    let main = fixture.root.appendingPathComponent("main").path
    let worktree = fixture.root.appendingPathComponent("worktree").path
    try FileManager.default.createDirectory(atPath: main + "/.git/worktrees/wt", withIntermediateDirectories: true)
    fixture.write(worktree + "/.git", text: "gitdir: \(main)/.git/worktrees/wt\n")
    let mainSkill = main + "/.claude/skills/s/SKILL.md"
    fixture.write(mainSkill, text: "---\nhooks:\n---\n")
    check(gate.evaluate(fixture.scope(workingDirectories: [worktree])).hooks.contains { $0.sourceID == mainSkill },
          "G2: a worktree's main checkout skills are scanned")

    // An enabled plugin's skills.
    let plugins = fixture.home + "/.claude/plugins"
    let install = plugins + "/cache/m/p/1.0.0"
    fixture.write(plugins + "/installed_plugins.json", ["version": 2, "plugins": [
        "p@m": [["installPath": install, "version": "1.0.0"]]]])
    let pluginSkill = install + "/skills/k/SKILL.md"
    fixture.write(pluginSkill, text: "---\nhooks:\n  PreToolUse: []\n---\n")
    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["p@m": true]]))
    check(gate.evaluate(scope).hooks.contains { $0.sourceID == pluginSkill },
          "G2: an enabled plugin's skill frontmatter hooks are scanned")

    // A symlink loop in a commands tree is walked once.
    try FileManager.default.createDirectory(atPath: fixture.home + "/.claude/commands", withIntermediateDirectories: true)
    try FileManager.default.createSymbolicLink(
        atPath: fixture.home + "/.claude/commands/loop", withDestinationPath: fixture.home + "/.claude/commands")
    let looped = gate.evaluate(scope)
    check(looped.isWellFormed && looped.hooks.contains { $0.sourceID == pluginSkill },
          "G2: a symlink loop in a commands directory is walked once")

    // Skills load one level deep, as Claude Code loads them: a markdown file
    // deeper in an ordinary skill's folder (for example node_modules) is
    // not a skill. The user synced account roots are a separate source.
    let deep = fixture.home + "/.claude/skills/tool/node_modules/pkg/agents/x.prompt.md"
    fixture.write(deep, text: "---\nhooks:\n  PreToolUse: []\n---\n")
    let synced = fixture.home + "/.claude/skills/synced/bucket/xlsx/SKILL.md"
    fixture.write(synced, text: "---\nhooks:\n  PreToolUse: []\n---\n")
    let nestedSkills = gate.evaluate(scope)
    check(!nestedSkills.hooks.contains { $0.sourceID == deep }
            && nestedSkills.hooks.contains { $0.sourceID == synced },
          "G2: ordinary nested markdown is ignored, but a user synced account skill's hooks count")

    // M1: the skill file is opened by name, so a volume that folds case (the
    // default APFS) loads SKILL.MD; commands and agents match .md in any case.
    let upper = fixture.home + "/.claude/skills/evil/SKILL.MD"
    fixture.write(upper, text: "---\nhooks:\n  PreToolUse: []\n---\n")
    let foldsCase = FileManager.default.fileExists(atPath: fixture.home + "/.claude/skills/evil/SKILL.md")
    let upperFound = gate.evaluate(scope).hooks.contains {
        $0.sourceID.lowercased() == (fixture.home + "/.claude/skills/evil/skill.md").lowercased()
    }
    check(upperFound == foldsCase,
          "M1: a skill named SKILL.MD is found exactly when the volume folds case, as Claude Code finds it "
              + "(folds case: \(foldsCase))")
    let upperCommand = fixture.home + "/.claude/commands/Deploy.MD"
    fixture.write(upperCommand, text: "---\nhooks:\n  PreToolUse: []\n---\n")
    check(gate.evaluate(scope).hooks.contains { $0.sourceID == upperCommand },
          "M1: a command file ending in .MD is read")
}

// MARK: - M4: frontmatter the gate cannot read with certainty

private func gateFrontmatterUncertaintyTests() throws {
    let fixture = try GateFixture("uncertain")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    fixture.write(fixture.userSettings, settings())
    let command = fixture.home + "/.claude/commands/case.md"
    func counts(_ block: String) -> Bool {
        fixture.write(command, text: "---\n" + block + "\n---\nBody\n")
        return gate.evaluate(scope).hooks.contains { $0.sourceID == command && $0.kind == .frontmatter }
    }
    let counted: [(String, String)] = [
        ("an escaped key", "name: x\n\"\\x68ooks\":\n  PreToolUse: []"),
        ("a unicode escape", "\"\\u0068ooks\": {}"),
        ("an alias used as a key", "k: &k hooks\n*k :\n  PreToolUse: []"),
        ("an anchor", "base: &b\n  a: 1\nother: *b"),
        ("a tag", "name: !!str deploy"),
        ("a flow mapping", "name: {a: b}"),
        ("a merge key", "<<: {a: 1}"),
        ("a directive", "%YAML 1.2\nname: x"),
        ("a document end marker", "name: x\n..."),
        ("a space before the colon", "hooks :\n  PreToolUse: []"),
        ("an explicit key", "? hooks\n: {}"),
        ("a sequence item alias", "list:\n  - *a"),
        ("a key in capitals", "HOOKS:\n  PreToolUse: []"),
        ("a block scalar as an explicit key", "? |-\n  hooks\n: {}"),
        ("a byte-order mark inside the key", "\u{FEFF}hooks: {}"),
        ("a single-quoted key", "'hooks' : {}"),
        ("a key inside a sequence item", "list:\n  - hooks: x"),
        ("a trailing comment", "hooks # later\n: {}"),
        ("an escaped key in a sequence item", "- \"\\x68ooks\": x"),
        ("a quoted value that turns out to be a key", "name: \"a\\\"b\": c"),
        ("a quoted value continued by an escaped line break", "description: \"first\\\n  \\x68ooks: x\""),
        ("a backslash before a key", "\\x68ooks: x"),
        ("a hooks key with a quoted escaped value", "hooks: \"x\\n\""),
        ("an escape after a quoted value", "name: \"x\" \\x68ooks"),
        ("a backslash on the line that closes another line's quoted value",
         "description: \"start\n\" hooks: \\\"x\""),
        ("an escaped value after a line with a second quoted scalar", "name: \"a\" \"b\nnote: \"c\\nd\""),
        // Bun 1.4 turns a sequence held by an explicit key into its entries'
        // text, so each of these is the key `hooks` (review of csec-q3v.19).
        ("an escaped key on the line after a lone explicit-key indicator", "?\n  \"\\x68ooks\"\n:\n  PreToolUse: []"),
        ("an escaped sequence entry held by an explicit key", "?\n  - \"\\x68ooks\"\n:\n  PreToolUse: []"),
        ("an escaped entry of a multi-line flow sequence explicit key", "? [\n  \"\\x68ooks\"\n  ]\n:\n  PreToolUse: []"),
    ]
    for (name, block) in counted {
        check(counts(block), "M4: frontmatter with \(name) counts as a hook source")
    }
    // N2: Bun makes a flow-sequence key the text of its entries, so each of
    // these is the key `hooks` (Bun 1.3.11 and 1.4.2; no `{` in them, which
    // would count on its own).
    let flowSequenceKeys: [(String, String)] = [
        ("a flow-sequence key", "[hooks]:\n  PreToolUse: []"),
        ("a double-quoted flow-sequence key", "[\"hooks\"]:\n  PreToolUse: []"),
        ("a single-quoted flow-sequence key", "['hooks']:\n  PreToolUse: []"),
        ("a nested flow-sequence key", "[ [ hooks ] ]:\n  PreToolUse: []"),
        ("a flow-sequence key with a trailing comma", "[hooks, ]:\n  PreToolUse: []"),
        ("a flow-sequence explicit key", "? [hooks]\n:\n  PreToolUse: []"),
        ("a flow-sequence explicit key over two lines", "? [\n  hooks ]\n:\n  PreToolUse: []"),
        ("a flow-sequence key in a sequence item", "- [hooks]: x"),
    ]
    for (name, block) in flowSequenceKeys {
        check(counts(block), "N2: frontmatter with \(name) counts as a hook source")
    }
    let plain: [(String, String)] = [
        ("plain keys", "name: deploy\ndescription: Deploy the app to staging"),
        ("markdown in quotes", "description: \"Use **bold** & more *here*\""),
        ("a comment", "name: x # *not an alias* {not a map}"),
        ("a flow sequence", "allowed-tools: [Read, Grep, Bash(git status)]"),
        ("a folded description", "description: >\n  Summarise the diff: files and lines"),
        ("hooks named inside a value", "description: Manages git hooks and webhooks: Hooks"),
        ("a two-entry flow-sequence key", "[hooks, x]: 1"),
        ("hooks in a flow-sequence value", "tools: [hooks]"),
        ("an escape inside a quoted description", "name: x\ndescription: \"Set up a plugin.\\n\""),
        ("an escaped quote inside a quoted value", "description: \"say \\\"hi\\\" & bye\" # note"),
        ("an escape in a quoted sequence entry", "tags:\n  - \"a\\tb\""),
        ("an apostrophe in a plain value beside an escaped quoted value", "description: Don't stop\nnote: \"a\\nb\""),
        ("a doubled single quote beside an escaped quoted value", "title: 'it''s'\nnote: \"a\\nb\""),
        // The synced cowork-plugin-customizer skill (2026-10-01) that turned
        // auto mode off for days: no hooks, a description ending in `\n`.
        ("a synced skill's escaped description", "name: cowork-plugin-customizer\ndescription: \"Customize a Claude Code plugin for a specific organization's tools and workflows. Use when: customize plugin, set up plugin, configure plugin, tailor plugin, adjust plugin settings, customize plugin connectors, customize plugin skill, tweak plugin, modify plugin configuration.\\n\"\ncompatibility: Requires Cowork desktop app environment with access to mounted plugin directories (mnt/.local-plugins, mnt/.plugins)."),
    ]
    for (name, block) in plain {
        check(!counts(block), "M4: frontmatter with \(name) is not a hook source")
    }
}

// MARK: - G5 on settings

private func gateEnvironmentTests() throws {
    let fixture = try GateFixture("g5")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()

    func environment(_ env: [String: Any], at path: String? = nil) -> [ClaudeSettingsEnvironmentFinding] {
        let file = path ?? fixture.userSettings
        fixture.write(fixture.userSettings, settings())
        if file == fixture.userSettings {
            fixture.write(file, settings(extra: ["env": env]))
        } else {
            fixture.write(file, ["env": env])
        }
        let found = gate.evaluate(scope).environment
        fixture.remove(file)
        return found
    }
    check(environment(["ANTHROPIC_BASE_URL": "https://proxy.example"])
            == [ClaudeSettingsEnvironmentFinding(name: "ANTHROPIC_BASE_URL", path: fixture.userSettings)],
          "G5: ANTHROPIC_BASE_URL in a settings env block declines, named by the list entry")
    check(environment(["DYLD_INSERT_LIBRARIES": "/x"], at: fixture.localSettings).map(\.name) == ["DYLD_*"],
          "G5: a listed prefix in project settings declines as PREFIX*")
    check(environment(["CLAUDE_CONFIG_DIR": "/elsewhere"], at: fixture.projectSettings).map(\.name) == ["CLAUDE_CONFIG_DIR"]
          && environment(["HOME": "/elsewhere"]).map(\.name) == ["HOME"],
          "G5: CLAUDE_CONFIG_DIR or HOME in a settings env block declines (they move every later settings read)")
    check(environment(["CLAUDE_CODE_PLUGIN_CACHE_DIR": "/x", "CLAUDE_CODE_USE_COWORK_PLUGINS": "1"]).map(\.name)
            == ["CLAUDE_CODE_PLUGIN_CACHE_DIR", "CLAUDE_CODE_USE_COWORK_PLUGINS"],
          "G5: plugin-directory and cowork redirects in a settings env block decline")
    check(environment(["ZDOTDIR": "/x"]).map(\.name) == ["ZDOTDIR"]
            && ClaudeDelegationGateLists.environmentEntry(matching: "ZDOTDIR") == nil,
          "G5: ZDOTDIR in a settings env block declines (every Bash tool shell inherits it); in P's launch environment it is checked on the command's own environment, for releases, SSH and sudo")
    check(environment(["NODE_OPTIONS": "--max-old-space-size=8192", "EDITOR": "vim"]).isEmpty,
          "G5: NODE_OPTIONS without a code-loading flag and unlisted names pass")
    check(environment(["NODE_OPTIONS": "--require ./x.js"]).map(\.name) == ["NODE_OPTIONS"],
          "G5: NODE_OPTIONS loading code declines")
    check(environment([ClaudeDelegationGateLists.shellPrefixName: "/tmp/other-prefix"]).map(\.name)
            == [ClaudeDelegationGateLists.shellPrefixName],
          "G5: a CLAUDE_CODE_SHELL_PREFIX that is not csec's own prefix script declines in a settings env block")
    check(ClaudeDelegationGateLists.settingsEnvironmentEntry(matching: "CLAUDE_CONFIG_DIR") == "CLAUDE_CONFIG_DIR"
          && ClaudeDelegationGateLists.environmentEntry(matching: "CLAUDE_CONFIG_DIR") == nil
          && ClaudeDelegationGateLists.environmentEntry(matching: "HOME") == nil
          && ClaudeDelegationGateLists.settingsEnvironmentEntry(matching: "ANTHROPIC_BASE_URL") == "ANTHROPIC_BASE_URL",
          "G5: CLAUDE_CONFIG_DIR and HOME decline only in settings; P's exec-time values root the scope")
    for name in ["CLAUDE_CODE_PLUGIN_CACHE_DIR", "CLAUDE_CODE_PLUGIN_SEED_DIR", "CLAUDE_CODE_USE_COWORK_PLUGINS"] {
        check(ClaudeDelegationGateLists.environmentEntry(matching: name) == name
              && ClaudeDelegationGateLists.settingsEnvironmentEntry(matching: name) == name,
              "G5: \(name) declines in P's launch environment and in a settings env block")
    }

    // Verdict overrides and unsupported remote-runtime selectors decline
    // from every settings layer, including a repository's own settings.
    let unsupportedSelectors = [
        "CLAUDE_CODE_EXTRA_BODY": "{\"system\":\"x\"}", "ANTHROPIC_UNIX_SOCKET": "/tmp/x.sock",
        "CLAUDE_CODE_AUTO_MODE_PRIOR_ASSISTANT_CONTEXT": "1",
        "CLAUDE_CODE_USE_BEDROCK": "1", "CLAUDE_CODE_USE_VERTEX": "1", "CLAUDE_CODE_USE_FOUNDRY": "1",
        "CLAUDE_CODE_USE_ANTHROPIC_AWS": "1", "CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD": "1",
        "CLAUDE_CODE_USE_MANTLE": "1", "CLAUDE_CODE_USE_GATEWAY": "1",
        "CLAUDE_CODE_REMOTE": "1",
    ]
    for (name, value) in unsupportedSelectors {
        check(environment([name: value]).map(\.name) == [name]
              && environment([name: value], at: fixture.projectSettings).map(\.name) == [name]
              && ClaudeDelegationGateLists.environmentEntry(matching: name) == name,
              "G5: \(name) declines in user and project settings env blocks and in P's launch environment")
    }
    check(environment(["CLAUDE_CODE_USE_FOUNDRY": "1", "ANTHROPIC_FOUNDRY_RESOURCE": "evil.example/",
                       "CLAUDE_CODE_SKIP_FOUNDRY_AUTH": "1"], at: fixture.projectSettings).map(\.name)
            == ["CLAUDE_CODE_USE_FOUNDRY"],
          "G5: a repository's settings that move the classifier to another Foundry host decline on the selector")
    for path in [fixture.localSettings, fixture.managed + "/managed-settings.json",
                 fixture.managed + "/managed-settings.d/relay.json", fixture.home + "/.claude/remote-settings.json",
                 fixture.home + "/.claude.json", fixture.home + "/.claude/.config.json"] {
        check(environment(["CLAUDE_CODE_REMOTE": "1"], at: path).map(\.name) == ["CLAUDE_CODE_REMOTE"],
              "release 2.1.295 G5: the remote relay selector declines from \((path as NSString).lastPathComponent)")
    }
    // 2.1.315 keeps the apiKeyHelper and string env of a stored remote copy it
    // refuses as stale, unsigned or an unsupported version (`Bu`/`ep`, the
    // helper tier). csecd reads that file whatever Claude Code's trust
    // verdict, so the copy's selectors still decline.
    let refusedRemoteCopy = fixture.home + "/.claude/remote-settings.json"
    check(environment(["ANTHROPIC_BASE_URL": "https://synthetic.invalid"], at: refusedRemoteCopy).map(\.name)
            == ["ANTHROPIC_BASE_URL"],
          "release 2.1.315 G5: a refused remote copy's helper-tier env still declines")
    fixture.write(refusedRemoteCopy, [
        "$signature": "synthetic-unsigned", "apiKeyHelper": "/synthetic/helper",
        "env": ["ANTHROPIC_BASE_URL": "https://synthetic.invalid"],
    ])
    check(gate.evaluate(scope).environment == [ClaudeSettingsEnvironmentFinding(
        name: "ANTHROPIC_BASE_URL", path: refusedRemoteCopy)],
          "release 2.1.315 G5: signature metadata and an apiKeyHelper do not hide the refused copy's env")
    fixture.remove(refusedRemoteCopy)
    fixture.write(fixture.userSettings, settings())
    var relayInline = scope
    relayInline.launchSettings = [#"{"env":{"CLAUDE_CODE_REMOTE":"1"}}"#]
    check(gate.evaluate(relayInline).environment == [ClaudeSettingsEnvironmentFinding(
        name: "CLAUDE_CODE_REMOTE", path: ClaudeSettingsScope.launchSettingsPath)],
          "release 2.1.295 G5: inline settings cannot enable an uninspected remote-session transport")
    let standaloneMode = "CCR_AGENT_PROXY_RELAY_MODE"
    let standaloneEnvironment = [
        standaloneMode: "agent_proxy_standalone",
        "CCR_AGENT_PROXY_STANDALONE_URL": "https://synthetic.invalid",
        "CLAUDE_CODE_ENVIRONMENT_KIND": "byoc",
        "CLAUDE_CODE_AUTO_MODE_MODEL": "claude-sonnet-5",
    ]
    for path in [fixture.userSettings, fixture.projectSettings, fixture.localSettings,
                 fixture.home + "/.claude/cowork_settings.json",
                 fixture.managed + "/managed-settings.json", fixture.managed + "/managed-settings.d/standalone.json",
                 fixture.home + "/.claude/remote-settings.json", fixture.home + "/.claude.json",
                 fixture.home + "/.claude-custom-oauth.json", fixture.home + "/.claude-local-oauth.json",
                 fixture.home + "/.claude-staging-oauth.json", fixture.home + "/.claude/.config.json"] {
        check(environment(standaloneEnvironment, at: path).map(\.name) == [standaloneMode],
              "release 2.1.302 G5: standalone relay without REMOTE declines from \((path as NSString).lastPathComponent)")
    }
    fixture.write(fixture.userSettings, settings())
    var standaloneInline = scope
    standaloneInline.launchSettings = [#"{"env":{"CCR_AGENT_PROXY_RELAY_MODE":"agent_proxy_standalone"}}"#]
    check(gate.evaluate(standaloneInline).environment == [ClaudeSettingsEnvironmentFinding(
        name: standaloneMode, path: ClaudeSettingsScope.launchSettingsPath)],
          "release 2.1.302 G5: inline settings cannot select the separate standalone relay")
    for value in ["", "hosted", "agent_proxy_standalone"] {
        check(environment([standaloneMode: value]).map(\.name) == [standaloneMode]
                && ClaudeDelegationGateLists.environmentEntry(matching: standaloneMode) == standaloneMode,
              "release 2.1.302 G5: the standalone selector declines on presence, independent of its value")
    }
    check(environment(["CCR_AGENT_PROXY_STANDALONE_URL": "https://synthetic.invalid"]).isEmpty,
          "release 2.1.302 G5: an inactive standalone companion does not decline")
    // 2.1.325's delegated-session family chooses the auto-mode classifier's
    // model ahead of server/org precedence and can replace its allowed list;
    // each name declines on presence, from any layer and inline settings.
    let delegatedSessionNames = [
        "CLAUDE_CODE_USER_DELEGATED_SESSION", "CLAUDE_CODE_USER_DELEGATED_SESSION_DIRECT_API",
        "CLAUDE_CODE_USER_DELEGATED_SESSION_ALLOWED_CHECK_MODELS",
        "CLAUDE_CODE_USER_DELEGATED_SESSION_ANY_CHECK_MODEL",
        "CLAUDE_CODE_USER_DELEGATED_SESSION_ALLOWED_PROVIDERS",
    ]
    for name in delegatedSessionNames {
        for path in [fixture.userSettings, fixture.projectSettings, fixture.localSettings,
                     fixture.managed + "/managed-settings.json", fixture.home + "/.claude/remote-settings.json",
                     fixture.home + "/.claude.json"] {
            check(environment([name: "claude-haiku-5-5"], at: path).map(\.name) == [name],
                  "release 2.1.325 G5: \(name) declines from \((path as NSString).lastPathComponent)")
        }
        check(ClaudeDelegationGateLists.environmentEntry(matching: name) == name
              && ClaudeDelegationGateLists.settingsEnvironmentEntry(matching: name) == name,
              "release 2.1.325 G5: \(name) declines in P's launch environment and in a settings env block")
        fixture.write(fixture.userSettings, settings())
        var inline = scope
        inline.launchSettings = ["{\"env\":{\"\(name)\":\"1\"}}"]
        check(gate.evaluate(inline).environment == [ClaudeSettingsEnvironmentFinding(
            name: name, path: ClaudeSettingsScope.launchSettingsPath)],
              "release 2.1.325 G5: inline settings cannot set \(name)")
    }
    // 2.1.302 reads AUTO_MODE_MODEL under server/org/safeguard checks. Like
    // main-model selection, it changes verdict quality within the same API
    // and prompt policy. The other three names still have no reader.
    check(environment([
        "CLAUDE_CODE_AUTO_MODE_GIT_STATUS": "1", "CLAUDE_CODE_AUTO_MODE_REPO_VISIBILITY": "1",
        "CLAUDE_CODE_AUTO_MODE_TEMPERATURE": "0", "CLAUDE_CODE_AUTO_MODE_SERVER": "0",
        "CLAUDE_CODE_AUTO_MODE_MODEL": "claude-sonnet-5", "CLAUDE_CODE_BG_CLASSIFIER_MODEL": "claude-opus-5-5",
        "CLAUDE_CODE_TWO_STAGE_CLASSIFIER": "1", "CLAUDE_CODE_AUTO_MODE_EXTERNAL_PERMISSIONS": "1",
    ]).isEmpty, "G5: quality-only and unread classifier knobs in a settings env block do not decline")

    // The global config file, every variant Claude Code may read.
    fixture.write(fixture.userSettings, settings())
    for name in [".claude.json", ".claude-custom-oauth.json", ".claude-local-oauth.json", ".claude-staging-oauth.json"] {
        let path = fixture.home + "/" + name
        fixture.write(path, ["env": ["ANTHROPIC_BASE_URL": "https://x"], "projects": ["/p": ["history": []]]])
        check(gate.evaluate(scope).environment == [ClaudeSettingsEnvironmentFinding(name: "ANTHROPIC_BASE_URL", path: path)],
              "G5: an env block in the global config file \(name) declines")
        fixture.remove(path)
    }
    let legacy = fixture.home + "/.claude/.config.json"
    fixture.write(legacy, ["env": ["BUN_OPTIONS": "--preload x"]])
    check(gate.evaluate(scope).environment.map(\.path) == [legacy], "G5: the legacy .config.json env block declines")
    fixture.remove(legacy)
    let configHome = fixture.root.appendingPathComponent("config").path
    fixture.write(configHome + "/settings.json", settings())
    fixture.write(configHome + "/.claude.json", ["env": ["SSL_CERT_FILE": "/x"]])
    check(gate.evaluate(fixture.scope(configDirectory: configHome)).environment.map(\.path)
            == [configHome + "/.claude.json"],
          "G5: with CLAUDE_CONFIG_DIR the global config file is read from it")
    fixture.write(fixture.home + "/.claude.json", ["numStartups": 3, "projects": [:]])
    check(gate.evaluate(scope).environment.isEmpty, "G5: a global config file without env passes")
}

// MARK: - G6

private func gateOtherSettingsTests() throws {
    let fixture = try GateFixture("g6")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    fixture.write(fixture.userSettings, settings())

    fixture.write(fixture.projectSettings, ["sandbox": ["enabled": true]])
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == .sandboxEnabled(path: fixture.projectSettings),
          "G6: sandbox.enabled in any layer declines")
    fixture.write(fixture.projectSettings, ["sandbox": ["enabled": false]])
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == nil, "G6: sandbox.enabled false passes")

    fixture.write(fixture.localSettings, ["permissions": ["defaultMode": "bypassPermissions"]])
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: [])
            == .bypassPermissionsDefault(path: fixture.localSettings),
          "G6: permissions.defaultMode bypassPermissions declines")
    fixture.remove(fixture.localSettings)

    fixture.write(fixture.userSettings, settings(extra: ["disableAllHooks": true]))
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: [])
            == .hooksDisabled(ClaudeHooksDisabledFinding(setting: .disableAllHooks, path: fixture.userSettings)),
          "G6: disableAllHooks declines")
    fixture.write(fixture.userSettings, settings())
    fixture.write(fixture.managed + "/managed-settings.json",
                  ["allowManagedHooksOnly": true, "autoMode": ["classifyAllShell": true]])
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: [])
            == .hooksDisabled(ClaudeHooksDisabledFinding(
                setting: .allowManagedHooksOnly, path: fixture.managed + "/managed-settings.json")),
          "G6: allowManagedHooksOnly declines")
}

// MARK: - Inline --settings from P's argv

private func gateLaunchSettingsTests() throws {
    let fixture = try GateFixture("launch")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let launch = ClaudeSettingsScope.launchSettingsPath
    func failure(_ launchSettings: String...) -> ClaudeSettingsGateFailure? {
        gate.evaluate(fixture.scope(launchSettings: launchSettings)).firstFailure(acknowledgedDigests: [])
    }
    func json(_ object: [String: Any]) -> String {
        String(decoding: (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data(),
               as: UTF8.self)
    }
    fixture.write(fixture.userSettings, settings())

    // What a session launcher started sessions with (csec-0.4).
    let harbor = json([
        "env": ["CLAUDE_CODE_DISABLE_WORKFLOWS": "1", "ENABLE_CLAUDEAI_MCP_SERVERS": "false"],
        "permissions": ["deny": ["AskUserQuestion", "SendFeedback", "ReportFindings"]],
        "autoMemoryEnabled": false,
    ])
    check(failure(harbor) == nil && failure("{}") == nil,
          "--settings: inline settings that cut tools, env and memory pass the gate")

    let hooks = gate.evaluate(fixture.scope(launchSettings: [json(["hooks": ["PreToolUse": [group("Bash")]]])])).hooks
    check(hooks.count == 1 && hooks[0].sourceID == launch && hooks[0].kind == .settings
          && hooks[0].display == "Claude Code's --settings · PreToolUse Bash",
          "--settings: a PreToolUse Bash hook is a hook of the --settings layer, named as such")
    check(failure(json(["hooks": ["PreToolUse": [group("Read")], "Notification": [group(nil)]]])) == nil,
          "--settings: hooks that cannot approve Bash pass")
    var csecOnly = csecHookSettings()
    csecOnly["autoMode"] = ["classifyAllShell": true]
    check(gate.evaluate(fixture.scope(launchSettings: [json(csecOnly)])).hooks.count == 1,
          "--settings: a copy of csec's own hook there is another hook")

    check(failure(json(["disableAllHooks": true]))
            == .hooksDisabled(ClaudeHooksDisabledFinding(setting: .disableAllHooks, path: launch)),
          "--settings: disableAllHooks declines")
    check(failure(json(["permissions": ["defaultMode": "bypassPermissions"]])) == .bypassPermissionsDefault(path: launch),
          "--settings: defaultMode bypassPermissions declines")
    check(failure(json(["sandbox": ["enabled": true]])) == .sandboxEnabled(path: launch),
          "--settings: sandbox.enabled declines")
    for name in ["HOME", "CLAUDE_CONFIG_DIR", "BUN_OPTIONS", "ANTHROPIC_BASE_URL"] {
        check(failure(json(["env": [name: "/x"]]))
                == .injectedEnvironment(ClaudeSettingsEnvironmentFinding(name: name, path: launch)),
              "--settings: an env block setting \(name) declines")
    }

    // classifyAllShell there is real to Claude Code, but never credited.
    fixture.write(fixture.userSettings, settings(classifyAllShell: false))
    if case .classifyAllShellNotSet? = failure(json(["autoMode": ["classifyAllShell": true]])) {
        check(true, "--settings: its classifyAllShell is not credited")
    } else {
        check(false, "--settings: its classifyAllShell is not credited")
    }
    fixture.write(fixture.userSettings, settings())

    // Parsed as strictly as a settings file.
    for (label, text) in [
        ("duplicate keys", #"{"env":{},"env":{"HOME":"/x"}}"#), ("truncated JSON", #"{"env":{}"#),
        ("hooks of the wrong shape", #"{"hooks":1}"#), ("a JSON5 comment", "{/* x */}"),
    ] {
        check(failure(text) == .unreadable(ClaudeUnreadableSetting(path: launch, reason: .unparseable)),
              "--settings: \(label) declines as unparseable")
    }
    let huge = "{\"x\":\"" + String(repeating: "a", count: CodingAgentSetup.maximumConfigurationBytes) + "\"}"
    check(failure(huge) == .unreadable(ClaudeUnreadableSetting(path: launch, reason: .oversized)),
          "--settings: an oversized value declines")

    // Every value is read, though Claude Code applies only the last.
    check(failure(json(["disableAllHooks": true]), harbor)
            == .hooksDisabled(ClaudeHooksDisabledFinding(setting: .disableAllHooks, path: launch)),
          "--settings: an earlier value still declines")

    // It enables plugins with the user layer's reach.
    let plugins = fixture.home + "/.claude/plugins"
    let install = plugins + "/cache/market/tool/1.0.0"
    fixture.write(plugins + "/installed_plugins.json", ["version": 2, "plugins": [
        "tool@market": [["scope": "user", "installPath": install, "version": "1.0.0"]],
    ]])
    fixture.write(install + "/hooks/hooks.json", ["hooks": ["PreToolUse": [group("*", "/bin/tool")]]])
    check(failure() == nil, "--settings: a plugin no layer enables is not read")
    let plugin = gate.evaluate(fixture.scope(launchSettings: [json(["enabledPlugins": ["tool@market": true]])])).hooks
    check(plugin.count == 1 && plugin[0].kind == .plugin && plugin[0].sourceID == "tool@market@1.0.0",
          "--settings: a plugin it enables has its hooks read")
}

// MARK: - Unreadable settings

private func gateUnreadableTests() throws {
    let fixture = try GateFixture("unreadable")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    fixture.write(fixture.userSettings, settings())

    fixture.write(fixture.localSettings, text: "{\"hooks\": {}, \"hooks\": {}}")
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: [])
            == .unreadable(ClaudeUnreadableSetting(path: fixture.localSettings, reason: .unparseable)),
          "unreadable: a settings file with a duplicate key declines as unparseable")
    fixture.write(fixture.localSettings, ["hooks": ["PreToolUse": "not a list"]])
    check(gate.evaluate(scope).unreadable == [ClaudeUnreadableSetting(path: fixture.localSettings, reason: .unparseable)],
          "unreadable: a malformed hooks block declines as unparseable")
    fixture.write(fixture.localSettings, text: "[1, 2]")
    check(gate.evaluate(scope).unreadable.first?.reason == .unparseable, "unreadable: a non-object file declines")

    fixture.write(fixture.localSettings, text: "{\"padding\": \"" + String(repeating: "x", count: 1_100_000) + "\"}")
    check(gate.evaluate(scope).unreadable == [ClaudeUnreadableSetting(path: fixture.localSettings, reason: .oversized)],
          "unreadable: a settings file over 1 MiB declines as oversized")

    fixture.write(fixture.localSettings, ["model": "x"])
    chmod(fixture.localSettings, 0)
    check(gate.evaluate(scope).unreadable == [ClaudeUnreadableSetting(path: fixture.localSettings, reason: .unreadable)],
          "unreadable: a settings file that cannot be opened declines and is named")
    chmod(fixture.localSettings, 0o600)
    fixture.remove(fixture.localSettings)

    try FileManager.default.createDirectory(atPath: fixture.localSettings, withIntermediateDirectories: true)
    check(gate.evaluate(scope).unreadable.first?.path == fixture.localSettings,
          "unreadable: a directory where a settings file belongs declines")
    fixture.remove(fixture.localSettings)

    let skills = fixture.home + "/.claude/skills/private"
    try FileManager.default.createDirectory(atPath: skills, withIntermediateDirectories: true)
    chmod(skills, 0)
    check(gate.evaluate(scope).unreadable.contains { $0.path.hasPrefix(skills) },
          "unreadable: a skill folder that cannot be read declines")
    chmod(skills, 0o700)

    let malformed = ClaudeSettingsScope(
        homeDirectory: "relative", userName: "synthetic", csecExecutablePath: gateCsecPath)
    let failClosed = gate.evaluate(malformed)
    check(failClosed.firstFailure(acknowledgedDigests: []) != nil && failClosed.isWellFormed,
          "unreadable: a malformed scope fails closed with a well-formed evaluation")
}

// MARK: - The cache

private func gateCacheTests() throws {
    let fixture = try GateFixture("cache")
    defer { fixture.cleanUp() }
    let files = CountingSettingsFiles()
    let gate = makeClaudeSettingsGate(fileAccess: files)
    let scope = fixture.scope()
    fixture.write(fixture.userSettings, settings(hooks: ["PreToolUse": [group("*")]]))
    fixture.write(fixture.home + "/.claude/skills/a/SKILL.md", text: "---\nname: a\n---\n")
    fixture.write(fixture.home + "/.claude.json", ["projects": [:]])

    let first = gate.evaluate(scope)
    let afterFirst = files.counts
    let second = gate.evaluate(scope)
    let afterSecond = files.counts
    check(first == second && afterSecond.reads == afterFirst.reads && afterSecond.listings == afterFirst.listings
          && afterSecond.statuses > afterFirst.statuses,
          "cache: an unchanged tree is re-stat'ed but not re-read or re-listed "
              + "(\(afterFirst.reads) reads, \(afterFirst.listings) listings, then none)")

    fixture.write(fixture.userSettings, settings(hooks: ["PreToolUse": [group("*", "/bin/changed")]]))
    let third = gate.evaluate(scope)
    check(files.counts.reads == afterSecond.reads + 1 && third.hooks.first?.digest != first.hooks.first?.digest,
          "cache: a changed file is read again, and only that file")

    fixture.write(fixture.home + "/.claude/skills/b/SKILL.md", text: "---\nhooks: {}\n---\n")
    check(gate.evaluate(scope).hooks.count == 2, "cache: a new skill directory is listed and read")
}

// MARK: - Builds

private func gateBuildTests() throws {
    let fixture = try GateFixture("builds")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    check(gate.discoverBuilds(scope) == ClaudeBuildDiscovery(builds: [], unreadable: []),
          "builds: no versions directory, no builds")
    let versions = scope.claudeVersionsDirectory
    try FileManager.default.createDirectory(atPath: versions, withIntermediateDirectories: true)
    try FileManager.default.copyItem(atPath: "/bin/ls", toPath: versions + "/9.9.9")
    fixture.write(versions + "/1.0.0", text: "#!/bin/sh\n")
    fixture.write(versions + "/.1.0.1.partial", text: "")
    let discovery = gate.discoverBuilds(scope)
    let apple = discovery.builds.first { $0.versionLabel == "9.9.9" }
    check(discovery.builds.map(\.versionLabel) == ["1.0.0", "9.9.9"]
          && discovery.builds.first?.cdHash == nil
          && apple?.cdHash.map { $0.utf8.count == 40 && $0 == $0.lowercased() } == true
          && apple?.signedByAnthropic == false && discovery.unreadable.isEmpty,
          "builds: each version is listed with its cdhash; a copy of an Apple binary is not Anthropic's")
    check(discovery.untrusted(trustedCDHashes: []).count == 2
          && discovery.untrusted(trustedCDHashes: Set([apple?.cdHash].compactMap { $0 })).map(\.versionLabel) == ["1.0.0"],
          "builds: a build trusted by cdhash is no longer untrusted")
    let mise = scope.claudeMiseVersionsDirectory
    fixture.write(mise + "/2.99.1/bin/claude", text: "synthetic executable; must never run\n")
    try FileManager.default.createSymbolicLink(atPath: mise + "/latest", withDestinationPath: mise + "/2.99.1")
    try FileManager.default.removeItem(atPath: versions)
    let miseDiscovery = gate.discoverBuilds(scope)
    check(miseDiscovery.builds.map(\.versionLabel) == ["2.99.1"]
            && miseDiscovery.builds.first?.path == mise + "/2.99.1/bin/claude"
            && miseDiscovery.builds.first?.cdHash == nil && miseDiscovery.unreadable.isEmpty,
          "builds: mise is discovered without a native install; aliases of the same inode are listed once and never executed")
    try FileManager.default.removeItem(atPath: mise)

    // Homebrew's cask and a global npm install hold the same image as the
    // native installer (csec-0.39.14); each is listed, with what it is.
    let cask = scope.claudeHomebrewVersionsDirectory
    check(cask == fixture.root.path + "/system/opt/homebrew/Caskroom/claude-code"
            && scope.claudeNpmExecutables.allSatisfy { $0.hasPrefix(fixture.root.path + "/system/") }
            && ClaudeSettingsScope(homeDirectory: "/Users/a", userName: "a", csecExecutablePath: gateCsecPath)
                .claudeHomebrewVersionsDirectory == "/opt/homebrew/Caskroom/claude-code",
          "builds: Homebrew's and npm's system paths are read under the scope's root, the real ones by default")
    fixture.write(cask + "/2.98.0/claude", text: "synthetic executable; must never run\n")
    let npm = try requirePath(scope.claudeNpmExecutables.first)
    fixture.write(npm, text: "synthetic executable; must never run\n")
    let systemDiscovery = gate.discoverBuilds(scope)
    check(systemDiscovery.builds.map(\.path) == [cask + "/2.98.0/claude", npm]
            && systemDiscovery.builds.map(\.versionLabel) == ["2.98.0", ClaudeInstallLayout.npmLabel]
            && systemDiscovery.unreadable.isEmpty,
          "builds: Homebrew's versions and a global npm install are discovered and never executed")
    check(!ClaudeSettingsScope(homeDirectory: "/Users/a", userName: "a", csecExecutablePath: gateCsecPath,
                               systemRoot: "relative").isWellFormed,
          "builds: a relative system root is not a scope")
}

private func requirePath(_ value: String?) throws -> String {
    guard let value else { throw CocoaError(.fileNoSuchFile) }
    return value
}

private func gateLegacyNPMBuildTests() throws {
    let fixture = try GateFixture("legacy-npm-builds")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    let mise = scope.claudeMiseVersionsDirectory
    let marker = fixture.root.appendingPathComponent("candidate-executed").path
    for version in ["0.2.126", "1.0.41"] {
        let install = mise + "/" + version
        let package = install + "/lib/node_modules/@anthropic-ai/claude-code"
        fixture.write(package + "/package.json", [
            "name": "@anthropic-ai/claude-code", "version": version, "bin": ["claude": "cli.js"],
        ])
        let markerJSON = String(decoding: try JSONEncoder().encode(marker), as: UTF8.self)
        fixture.write(package + "/cli.js", text:
            "#!/usr/bin/env -S node --no-warnings --enable-source-maps\n"
                + "require('node:fs').writeFileSync(\(markerJSON), 'executed');\n")
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: package + "/cli.js")
        try FileManager.default.createDirectory(atPath: install + "/bin", withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(
            atPath: install + "/bin/claude", withDestinationPath: "../lib/node_modules/@anthropic-ai/claude-code/cli.js")
    }
    try FileManager.default.createSymbolicLink(atPath: mise + "/0", withDestinationPath: "./0.2.126")

    let discovery = gate.discoverBuilds(scope)
    check(discovery.builds.map(\.path) == [mise + "/0/bin/claude", mise + "/1.0.41/bin/claude"]
            && discovery.builds.allSatisfy { $0.cdHash == nil && !$0.signedByAnthropic }
            && discovery.unreadable.isEmpty,
          "legacy npm: the real alias/bin/cli.js layout yields two unsigned entries, deduplicating the 0 alias")
    let checkedHashes = Set(ClaudeBuildVerification.shipped.records.map(\.cdHash))
    check(discovery.untrusted(trustedCDHashes: checkedHashes) == discovery.builds
            && discovery.builds.allSatisfy { ClaudeBuildVerification.shipped.checkedVersion(cdHash: $0.cdHash) == nil },
          "legacy npm: native build trust and compatibility records cannot certify unsigned scripts")

    try FileManager.default.removeItem(atPath: mise + "/0.2.126")
    let retiredOne = gate.discoverBuilds(scope)
    check(retiredOne.builds.map(\.path) == [mise + "/1.0.41/bin/claude"] && retiredOne.unreadable.isEmpty,
          "legacy npm: removing one install also removes its dangling alias from a warm inventory, retaining the other")

    try FileManager.default.moveItem(atPath: mise + "/1.0.41", toPath: mise + "/2.1.280")
    let renamed = gate.discoverBuilds(scope)
    check(renamed.builds.map(\.versionLabel) == ["2.1.280"] && renamed.builds.first?.cdHash == nil
            && renamed.builds.allSatisfy { ClaudeBuildVerification.shipped.checkedVersion(cdHash: $0.cdHash) == nil },
          "legacy npm: moving the script under an audited release label cannot check it")
    try FileManager.default.removeItem(atPath: mise + "/2.1.280")
    check(gate.discoverBuilds(scope) == ClaudeBuildDiscovery(builds: [], unreadable: []),
          "legacy npm: a warm inventory reports no build after both actual installations are removed")
    check(!FileManager.default.fileExists(atPath: marker), "legacy npm: discovery never executes any candidate script")
}

// MARK: - Review fixes: plugin sources Claude Code loads (H1)

private func gatePluginSourceTests() throws {
    let fixture = try GateFixture("h1")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    let plugins = fixture.home + "/.claude/plugins"
    let approving = ["hooks": ["PreToolUse": [group("Bash", "/bin/approve")]]]

    // H1.1: a directory marketplace's plugin loads from the marketplace folder,
    // whatever installed_plugins.json records (reviewer probe fx/h9).
    let marketplace = fixture.root.appendingPathComponent("mk").path
    fixture.write(plugins + "/known_marketplaces.json", ["mk": [
        "source": ["source": "directory", "path": marketplace], "installLocation": marketplace]])
    fixture.write(marketplace + "/.claude-plugin/marketplace.json", ["name": "mk", "plugins": [
        ["name": "p", "source": "./plugins/p"]]])
    fixture.write(marketplace + "/plugins/p/hooks/hooks.json", approving)
    let clean = plugins + "/cache/mk/p/1.0.0"
    fixture.write(clean + "/.claude-plugin/plugin.json", ["name": "p"])
    fixture.write(plugins + "/installed_plugins.json", ["version": 2, "plugins": [
        "p@mk": [["installPath": clean, "version": "1.0.0"]]]])
    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["p@mk": true]]))
    var hooks = gate.evaluate(scope).hooks
    check(hooks.contains { $0.kind == .plugin && $0.sourceID.hasPrefix("p@mk@") && $0.event == "PreToolUse" },
          "H1: a directory marketplace's plugin hooks are read from the marketplace folder, not only the install record")
    fixture.remove(plugins + "/installed_plugins.json")
    hooks = gate.evaluate(scope).hooks
    check(hooks.contains { $0.sourceID.hasPrefix("p@mk@") },
          "H1: a local-source plugin with no installed_plugins.json record still counts")

    // A url marketplace: its install location is the catalog file itself.
    let urlCatalog = plugins + "/marketplaces/web.json"
    fixture.write(plugins + "/known_marketplaces.json", ["web": [
        "source": ["source": "url", "url": "https://example.com/m.json"], "installLocation": urlCatalog]])
    fixture.write(urlCatalog, ["name": "web", "plugins": [
        ["name": "q", "source": "./q", "hooks": ["PermissionRequest": [group(nil, "/bin/allow-all")]]]]])
    fixture.write(plugins + "/marketplaces/q/hooks/hooks.json", approving)
    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["q@web": true]]))
    hooks = gate.evaluate(scope).hooks
    check(hooks.contains { $0.sourceID == "q@web" && $0.event == "PermissionRequest" }
          && hooks.contains { $0.sourceID.hasPrefix("q@web@") && $0.event == "PreToolUse" },
          "H1: a url marketplace's catalog file is read for entry hooks, and its relative source beside it")

    // H1 (2.1.280): the versioned cache copy loads with no install record.
    fixture.write(plugins + "/known_marketplaces.json", [String: Any]())
    fixture.write(plugins + "/cache/remote/tool/2.3.4/hooks/hooks.json", approving)
    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["tool@remote": true]]))
    check(gate.evaluate(scope).hooks.contains { $0.sourceID == "tool@remote@2.3.4" },
          "H1: every cached version of an enabled plugin counts, recorded or not")

    // H1.4: an install path that is not a directory (a zip) cannot be read
    // the way Claude Code would extract it, so it declines.
    let zip = plugins + "/cache/remote/zipped/1.0.0.zip"
    fixture.write(zip, text: "PK")
    fixture.write(plugins + "/installed_plugins.json", ["version": 2, "plugins": [
        "zipped@remote": [["installPath": zip, "version": "1.0.0"]]]])
    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["zipped@remote": true]]))
    check(gate.evaluate(scope).unreadable.contains { $0.path == zip },
          "H1: an enabled plugin whose install path is a zip declines")
    fixture.remove(plugins + "/installed_plugins.json")

    // H1.2: a plugin enabled only by an --add-dir directory's settings, whose
    // other settings Claude Code does not read (reviewer probe fx/h11).
    let addDirectory = fixture.root.appendingPathComponent("added").path
    fixture.write(fixture.userSettings, settings())
    fixture.write(addDirectory + "/.claude/settings.json", [
        "enabledPlugins": ["tool@remote": true], "sandbox": ["enabled": true],
        "hooks": ["PreToolUse": [group("Bash", "/bin/not-read")]]])
    let withAddDirectory = gate.evaluate(fixture.scope(additional: [addDirectory]))
    check(withAddDirectory.hooks.contains { $0.sourceID == "tool@remote@2.3.4" }
          && !withAddDirectory.hooks.contains { $0.sourceID.hasSuffix("added/.claude/settings.json") }
          && withAddDirectory.sandboxEnabled.isEmpty,
          "H1: a plugin enabled in an --add-dir directory's settings counts; nothing else there is read")
    check(!gate.evaluate(scope).hooks.contains { $0.sourceID == "tool@remote@2.3.4" },
          "H1: without that directory the plugin is not enabled")
    fixture.write(fixture.userSettings, settings(extra: ["permissions": ["additionalDirectories": [addDirectory]]]))
    check(gate.evaluate(scope).hooks.contains { $0.sourceID == "tool@remote@2.3.4" },
          "H1: permissions.additionalDirectories settings enable plugins too (over-approximated)")

    // H1.5: claude.ai-synced plugins load with no enabledPlugins entry.
    fixture.write(fixture.userSettings, settings())
    fixture.write(plugins + "/synced/org_account/helper/hooks/hooks.json", approving)
    fixture.write(plugins + "/synced/org_account/manifest.json", ["plugins": []])
    fixture.write(plugins + "/synced/.hidden/other/hooks/hooks.json", approving)
    hooks = gate.evaluate(scope).hooks
    check(hooks.contains { $0.sourceID == "synced:org_account/helper" && $0.display.hasPrefix("helper (claude.ai)") }
          && !hooks.contains { $0.sourceID.contains(".hidden") },
          "H1: every claude.ai-synced plugin's hooks count; hidden folders are skipped")
    fixture.remove(plugins + "/synced")

    // 2.1.280 adopts a skills-directory folder as <name>@skills-dir.
    let skillPlugin = fixture.home + "/.claude/skills/mine"
    fixture.write(skillPlugin + "/.claude-plugin/plugin.json", ["name": "mine", "hooks": approving["hooks"] as Any])
    fixture.write(fixture.home + "/.claude/skills/.dot/hooks/hooks.json", approving)
    hooks = gate.evaluate(scope).hooks
    check(hooks.contains { $0.sourceID == skillPlugin && $0.display.hasPrefix("mine@skills-dir") }
          && !hooks.contains { $0.sourceID.contains("/.dot") },
          "H1: a skills-directory plugin's hooks count; dot folders are never adopted")
    fixture.remove(skillPlugin)

    // H1.6: a manifest's command map: a file path and inline content.
    let mapped = plugins + "/cache/remote/mapper/1.0.0"
    fixture.write(mapped + "/.claude-plugin/plugin.json", ["name": "mapper", "commands": [
        "one": ["source": "./extra/one.md"],
        "two": ["content": "---\nhooks:\n  PreToolUse: []\n---\nInline command\n"],
    ]])
    fixture.write(mapped + "/extra/one.md", text: "---\nhooks:\n  Stop: []\n---\n")
    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["mapper@remote": true]]))
    hooks = gate.evaluate(scope).hooks
    check(hooks.contains { $0.sourceID == mapped + "/extra/one.md" }
          && hooks.contains { $0.kind == .frontmatter && $0.sourceID == mapped + "/.claude-plugin/plugin.json" },
          "H1: a manifest's command map is read: a named file and inline content")

    // H1.3/H1.4: the plugin-folder redirects decline, in settings and at launch.
    for name in ["CLAUDE_CODE_PLUGIN_DIRS", "CLAUDE_CODE_PLUGIN_USE_ZIP_CACHE"] {
        fixture.write(fixture.userSettings, settings(extra: ["env": [name: "/x"]]))
        check(gate.evaluate(scope).environment.map(\.name) == [name]
              && ClaudeDelegationGateLists.environmentEntry(matching: name) == name,
              "H1: \(name) declines in a settings env block and in P's launch environment")
    }
}

// MARK: - Re-review fixes: marketplaces declared in settings (N1)

private func gateDeclaredMarketplaceTests() throws {
    let fixture = try GateFixture("n1")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    let plugins = fixture.home + "/.claude/plugins"
    let approving = ["hooks": ["PreToolUse": [group("Bash", "/bin/approve")]]]
    func directorySource(_ path: String) -> [String: Any] { ["source": ["source": "directory", "path": path]] }
    func declares(_ extra: [String: Any]) -> [String: Any] {
        settings(extra: extra.merging(["enabledPlugins": ["p@dm": true]]) { current, _ in current })
    }
    func finds(_ evaluation: ClaudeSettingsGateEvaluation) -> Bool {
        evaluation.hooks.contains { $0.kind == .plugin && $0.sourceID.hasPrefix("p@dm@") && $0.event == "PreToolUse" }
    }

    // The reviewer's probe (fx2/n1): nothing recorded, the marketplace only
    // declared in user settings, its plugin enabled.
    let declared = fixture.root.appendingPathComponent("declared").path
    fixture.write(declared + "/.claude-plugin/marketplace.json", ["name": "dm", "plugins": [
        ["name": "p", "source": "./plugins/p"]]])
    fixture.write(declared + "/plugins/p/hooks/hooks.json", approving)
    fixture.write(fixture.userSettings, declares(["extraKnownMarketplaces": ["dm": directorySource(declared)]]))
    check(finds(gate.evaluate(scope)),
          "N1: a directory marketplace declared in user settings and recorded nowhere loads its plugin's hooks")

    // Whatever known_marketplaces.json records under the same name.
    let recorded = plugins + "/marketplaces/dm"
    fixture.write(recorded + "/.claude-plugin/marketplace.json", ["name": "dm", "plugins": [
        ["name": "p", "source": "./plugins/p"]]])
    fixture.write(recorded + "/plugins/p/.claude-plugin/plugin.json", ["name": "p"])
    fixture.write(plugins + "/known_marketplaces.json", ["dm": [
        "source": ["source": "github", "repo": "example/dm"], "installLocation": recorded]])
    check(finds(gate.evaluate(scope)),
          "N1: the declared location is read even when known_marketplaces.json records the name elsewhere")
    fixture.remove(plugins + "/known_marketplaces.json")

    // Project, local and --add-dir settings may declare one too (2.1.280 in a
    // trusted workspace; the gate does not model trust).
    for file in [fixture.projectSettings, fixture.localSettings] {
        fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["p@dm": true]]))
        fixture.write(file, ["extraKnownMarketplaces": ["dm": directorySource(declared)]])
        check(finds(gate.evaluate(scope)), "N1: a marketplace declared in \((file as NSString).lastPathComponent) counts")
        fixture.remove(file)
    }
    check(!finds(gate.evaluate(scope)), "N1: with no declaration the plugin's marketplace is unknown")
    let added = fixture.root.appendingPathComponent("added").path
    fixture.write(added + "/.claude/settings.local.json", ["extraKnownMarketplaces": ["dm": directorySource(declared)]])
    check(finds(gate.evaluate(fixture.scope(additional: [added]))),
          "N1: a marketplace declared in an --add-dir directory's settings counts")
    check(!finds(gate.evaluate(scope)), "N1: without that directory its declaration is not read")

    // A relative path (anchored by the reconcile at the project root) and a
    // home-relative one.
    let inProject = fixture.project + "/tools/mkt"
    fixture.write(inProject + "/.claude-plugin/marketplace.json", ["name": "dm", "plugins": [
        ["name": "p", "source": "./p"]]])
    fixture.write(inProject + "/p/hooks/hooks.json", approving)
    fixture.write(fixture.projectSettings, ["extraKnownMarketplaces": ["dm": directorySource("./tools/mkt")]])
    check(finds(gate.evaluate(scope)), "N1: a relative declared path resolves against the project directories")
    fixture.remove(fixture.projectSettings)
    fixture.write(fixture.userSettings, declares(["extraKnownMarketplaces": ["dm": directorySource("~/work/project/tools/mkt")]]))
    check(finds(gate.evaluate(scope)), "N1: a ~/ declared path resolves under the home directory")

    // A file marketplace: the declared catalog file, and the standard catalog
    // beside it that 2.1.280 reads from the .claude-plugin folder's parent.
    let fileMarketplace = fixture.root.appendingPathComponent("filemk").path
    fixture.write(fileMarketplace + "/.claude-plugin/custom.json", ["name": "dm", "plugins": [
        ["name": "p", "source": "./plugins/p", "hooks": ["PermissionRequest": [group(nil, "/bin/allow")]]]]])
    fixture.write(fileMarketplace + "/plugins/p/hooks/hooks.json", approving)
    fixture.write(fixture.userSettings, declares(["extraKnownMarketplaces": ["dm": [
        "source": ["source": "file", "path": fileMarketplace + "/.claude-plugin/custom.json"]]]]))
    var hooks = gate.evaluate(scope).hooks
    check(hooks.contains { $0.sourceID == "p@dm" && $0.event == "PermissionRequest" }
          && hooks.contains { $0.sourceID.hasPrefix("p@dm@") && $0.event == "PreToolUse" },
          "N1: a declared file marketplace's entry hooks and its plugin folder both count")
    let folderHooks = hooks.filter { $0.sourceID.hasPrefix("p@dm@") }.count
    fixture.write(fileMarketplace + "/.claude-plugin/marketplace.json", ["name": "dm", "plugins": [
        ["name": "p", "source": "./other"]]])
    fixture.write(fileMarketplace + "/other/hooks/hooks.json", ["hooks": ["PreToolUse": [group("Bash", "/bin/other")]]])
    hooks = gate.evaluate(scope).hooks
    check(hooks.filter { $0.sourceID.hasPrefix("p@dm@") }.count == folderHooks + 1,
          "N1: the standard catalog beside a declared file marketplace counts too")

    // A declared catalog the gate cannot read declines.
    let catalog = declared + "/.claude-plugin/marketplace.json"
    fixture.write(fixture.userSettings, declares(["extraKnownMarketplaces": ["dm": directorySource(declared)]]))
    chmod(catalog, 0)
    check(gate.evaluate(scope).unreadable.contains { $0.path == catalog },
          "N1: a declared marketplace whose catalog cannot be read declines")
    chmod(catalog, 0o600)

    // A remote declaration loads nothing until the reconcile records it, and a
    // malformed extraKnownMarketplaces declines.
    fixture.write(fixture.userSettings, declares(["extraKnownMarketplaces": ["dm": [
        "source": ["source": "github", "repo": "example/dm"]]]]))
    let remote = gate.evaluate(scope)
    check(!finds(remote) && remote.unreadable.isEmpty,
          "N1: a remote marketplace declared in settings loads nothing in place")
    fixture.write(fixture.userSettings, declares(["extraKnownMarketplaces": ["dm"]]))
    check(gate.evaluate(scope).unreadable.contains { $0.path == fixture.userSettings && $0.reason == .unparseable },
          "N1: an extraKnownMarketplaces that is not an object declines")
}

// MARK: - Review fixes: worktrees and nested repositories (H2, L6)

private func gateWorktreeTests() throws {
    let fixture = try GateFixture("h2")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    fixture.write(fixture.userSettings, settings())

    // A worktree made by `git worktree add`: .git file → gitdir, with a
    // commondir back to the main checkout's .git (reviewer probe fx/h8).
    let main = fixture.root.appendingPathComponent("main").path
    let worktree = fixture.root.appendingPathComponent("wt").path
    try FileManager.default.createDirectory(atPath: main + "/.git/worktrees/wt", withIntermediateDirectories: true)
    fixture.write(main + "/.git/worktrees/wt/commondir", text: "../..\n")
    fixture.write(main + "/.git/worktrees/wt/gitdir", text: worktree + "/.git\n")
    fixture.write(worktree + "/.git", text: "gitdir: " + main + "/.git/worktrees/wt\n")
    fixture.write(main + "/.claude/settings.local.json", ["hooks": ["PermissionRequest": [group(nil, "/bin/allow")]]])
    let scope = fixture.scope(workingDirectories: [worktree])
    check(gate.evaluate(scope).hooks.contains { $0.sourceID == main + "/.claude/settings.local.json" },
          "H2: a worktree's session reads the main checkout's local settings (2.1.280 localSettings)")
    fixture.write(main + "/.claude/settings.local.json", ["sandbox": ["enabled": true]])
    check(gate.evaluate(scope).sandboxEnabled == [main + "/.claude/settings.local.json"],
          "H2: the main checkout's local sandbox setting declines a worktree session")
    fixture.remove(main + "/.claude/settings.local.json")
    fixture.write(main + "/.claude/settings.json", ["env": ["ANTHROPIC_BASE_URL": "https://x"]])
    check(gate.evaluate(scope).environment.map(\.path) == [main + "/.claude/settings.json"],
          "H2: the main checkout's shared settings are read too (over-approximated)")
    fixture.remove(main + "/.claude/settings.json")

    // A relative gitdir and a bare repository's common directory.
    let bare = fixture.root.appendingPathComponent("repo.git").path
    let bareWorktree = fixture.root.appendingPathComponent("bwt").path
    try FileManager.default.createDirectory(atPath: bare + "/worktrees/bwt", withIntermediateDirectories: true)
    fixture.write(bare + "/worktrees/bwt/commondir", text: "../..\n")
    fixture.write(bareWorktree + "/.git", text: "gitdir: ../repo.git/worktrees/bwt\n")
    fixture.write(bare + "/.claude/settings.local.json", ["hooks": ["PreToolUse": [group("Bash", "/bin/allow")]]])
    check(gate.evaluate(fixture.scope(workingDirectories: [bareWorktree])).hooks.contains {
        $0.sourceID == bare + "/.claude/settings.local.json"
    }, "H2: a bare repository's worktree resolves its relative gitdir and commondir")

    // L6: a repository nested inside the session's project walks on to the
    // project's root (resolveStopBoundary), for the hook's working directory.
    let project = fixture.project
    let nested = project + "/vendor/lib"
    try FileManager.default.createDirectory(atPath: nested + "/.git", withIntermediateDirectories: true)
    let between = project + "/vendor/.claude/commands/between.md"
    fixture.write(between, text: "---\nhooks:\n  PreToolUse: []\n---\n")
    check(gate.evaluate(fixture.scope(workingDirectories: [project, nested])).hooks.contains { $0.sourceID == between },
          "L6: a nested repository's walk continues to the session project's root")
    check(!gate.evaluate(fixture.scope(workingDirectories: [nested])).hooks.contains { $0.sourceID == between },
          "L6: on its own, a repository's walk stops at its own root")
}

// MARK: - Review fixes: policy sources (M2, L4)

private func gatePolicySourceTests() throws {
    let fixture = try GateFixture("m2")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    fixture.write(fixture.userSettings, settings(classifyAllShell: false))

    // M2: remote-settings.json is user-writable and read only for some
    // accounts: it never credits classifyAllShell (reviewer probe fx/h7).
    let remote = fixture.home + "/.claude/remote-settings.json"
    fixture.write(remote, ["autoMode": ["classifyAllShell": true]])
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == .classifyAllShellNotSet(ignoredIn: []),
          "M2: classifyAllShell in remote-settings.json alone does not pass G1")
    fixture.write(fixture.managed + "/managed-settings.json", ["autoMode": ["classifyAllShell": true]])
    fixture.write(remote, ["model": "x"])
    check(!gate.evaluate(scope).classifyAllShell.isSet,
          "M2: a non-empty remote-settings.json may be the policy that applies, so it withholds the managed file's credit")
    fixture.write(remote, ["sandbox": ["enabled": true]])
    check(gate.evaluate(scope).sandboxEnabled == [remote], "M2: remote-settings.json still declines")
    fixture.remove(remote)
    check(gate.evaluate(scope).classifyAllShell.setIn == [fixture.managed + "/managed-settings.json"],
          "M2: without it, the managed file credits classifyAllShell")
    fixture.remove(fixture.managed + "/managed-settings.json")

    // L4: an existing per-user plist, even an empty one, shadows the device plist.
    let perUser = fixture.preferences + "/synthetic/com.anthropic.claudecode.plist"
    let device = fixture.preferences + "/com.anthropic.claudecode.plist"
    try FileManager.default.createDirectory(atPath: fixture.preferences + "/synthetic", withIntermediateDirectories: true)
    try PropertyListSerialization.data(fromPropertyList: ["autoMode": ["classifyAllShell": true]], format: .binary, options: 0)
        .write(to: URL(fileURLWithPath: device))
    check(gate.evaluate(scope).classifyAllShell.setIn == [device], "L4: with no per-user plist the device plist credits")
    try PropertyListSerialization.data(fromPropertyList: [String: Any](), format: .binary, options: 0)
        .write(to: URL(fileURLWithPath: perUser))
    check(!gate.evaluate(scope).classifyAllShell.isSet,
          "L4: an empty per-user plist shadows the device plist, which then does not credit")
    try PropertyListSerialization.data(fromPropertyList: ["sandbox": ["enabled": true]], format: .binary, options: 0)
        .write(to: URL(fileURLWithPath: device))
    check(gate.evaluate(scope).sandboxEnabled == [device], "L4: a shadowed device plist still declines")
}

// MARK: - Release 2.1.282: disk-backed synced skills and managed field salvage

private func gateRelease282SourcesTests() throws {
    let fixture = try GateFixture("release-282-sources")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    fixture.write(fixture.userSettings, settings())
    let synced = fixture.home + "/.claude/skills/synced"
    let first = synced + "/account-one/review/SKILL.md"
    let second = synced + "/account-two/review/SKILL.md"
    fixture.write(first, text: "---\nname: review\n---\nSynthetic skill body.\n")
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == nil,
          "release 2.1.282: a synced skill with no hooks does not need acknowledgement")
    let hookText = "---\nhooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n        - type: command\n          command: /synthetic/approve\n---\nSynthetic skill body.\n"
    fixture.write(first, text: hookText)
    fixture.write(second, text: hookText.replacingOccurrences(of: "PreToolUse", with: "PermissionRequest"))
    fixture.write(synced + "/account-one/SKILL.md", text: hookText)
    fixture.write(synced + "/account-one/review/nested/SKILL.md", text: hookText)
    fixture.write(fixture.project + "/.claude/skills/synced/account/tool/SKILL.md", text: hookText)
    let found = gate.evaluate(scope)
    check(Set(found.hooks.map(\.sourceID)) == [first, second]
            && found.hooks.allSatisfy { $0.kind == .frontmatter }
            && found.firstFailure(acknowledgedDigests: []) != nil,
          "release 2.1.282: hooks in every synced account bucket need acknowledgement without reading account state")
    let acknowledged = Set(found.hooks.map(\.digest))
    check(found.firstFailure(acknowledgedDigests: acknowledged) == nil,
          "release 2.1.282: unchanged synced hooks use the ordinary per-source acknowledgement")
    fixture.write(first, text: hookText.replacingOccurrences(of: "/synthetic/approve", with: "/synthetic/changed"))
    check(gate.evaluate(scope).unacknowledgedHooks(acknowledgedDigests: acknowledged).map(\.sourceID) == [first],
          "release 2.1.282: changing a synced hook invalidates only its own acknowledgement")
    // The agent and MCP-tool descriptors in 2.1.317's expanded plugin hook
    // previews must never look hook-free here. Keep the entire frontmatter,
    // including the failure policy, regardless of the handler type.
    for handler in [
        "type: agent\n          prompt: synthetic review",
        "type: mcp_tool\n          server: synthetic\n          tool: review",
    ] {
        let text = "---\nhooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n        - \(handler)\n"
            + "          on_failure: block\n---\nSynthetic skill body.\n"
        fixture.write(first, text: text)
        let snapshot = gate.evaluate(scope)
        check(snapshot.hooks.contains { $0.kind == .frontmatter && $0.sourceID == first }
                && snapshot.firstFailure(acknowledgedDigests: []) != nil,
              "release 2.1.317: agent and staged MCP-tool synced hooks require acknowledgement")
        let current = Set(snapshot.hooks.map(\.digest))
        check(snapshot.firstFailure(acknowledgedDigests: current) == nil,
              "release 2.1.317: these hook types use the existing per-source acknowledgement")
        fixture.write(first, text: text.replacingOccurrences(of: "on_failure: block", with: "on_failure: continue"))
        check(gate.evaluate(scope).unacknowledgedHooks(acknowledgedDigests: current).map(\.sourceID) == [first],
              "release 2.1.317: changing a synced hook's failure policy invalidates its acknowledgement")
    }
    fixture.write(first, text: String(repeating: "x", count: 1_100_000))
    check(gate.evaluate(scope).unreadable.contains { $0.path == first && $0.reason == .oversized },
          "release 2.1.282: an oversized synced SKILL.md declines instead of looking hook-free")
    fixture.write(first, text: hookText)
    let account = synced + "/account-one"
    chmod(account, 0)
    let unreadable = gate.evaluate(scope)
    chmod(account, 0o700)
    check(unreadable.unreadable.contains { $0.path == account },
          "release 2.1.282: an unreadable synced account bucket declines")
    fixture.remove(synced)

    let redirected = fixture.home + "/alternate-claude"
    let redirectedSkill = redirected + "/skills/synced/account/tool/SKILL.md"
    fixture.write(redirected + "/settings.json", settings())
    fixture.write(redirectedSkill, text: hookText)
    check(gate.evaluate(fixture.scope(configDirectory: redirected)).hooks.map(\.sourceID) == [redirectedSkill],
          "release 2.1.282: synced account discovery follows the selected configuration home only")

    let managed = fixture.managed + "/managed-settings.json"
    fixture.write(managed, [
        "permissions": ["ask": 123],
        "autoMode": ["classifyAllShell": true, "allow": ["synthetic classifier rule"]],
        "hooks": ["PreToolUse": [group("Bash")]],
        "env": ["ANTHROPIC_BASE_URL": "https://synthetic.invalid"],
    ])
    let salvaged = gate.evaluate(scope)
    check(salvaged.hooks.contains { $0.kind == .settings && $0.sourceID == managed }
            && salvaged.hooks.contains { $0.kind == .classifierRules && $0.sourceID == managed }
            && salvaged.environment.contains { $0.path == managed && $0.name == "ANTHROPIC_BASE_URL" },
          "release 2.1.282: invalid nested permission fields cannot hide surviving hooks, classifier rules or environment")
    fixture.write(managed, ["disableAllHooks": "mistyped", "permissions": ["ask": 123]])
    check(gate.evaluate(scope).hooksDisabled.contains { $0.path == managed && $0.setting == .disableAllHooks },
          "release 2.1.282: mistyped managed hook locks retain the ordinary disabled-hooks refusal")
    fixture.write(managed, ["autoMode": ["classifyAllShell": true, "allow": 123]])
    check(gate.evaluate(scope).unreadable.contains { $0.path == managed && $0.reason == .unparseable },
          "release 2.1.282: partially invalid classifier rules decline rather than certifying the salvaged remainder")
}

// MARK: - Release 2.1.267: generated policy and plugin sources

private func gateGeneratedPolicyTests() throws {
    let fixture = try GateFixture("generated-policy")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    fixture.write(fixture.userSettings, settings())
    let perUser = fixture.preferences + "/synthetic/com.anthropic.claudecode.plist"
    let device = fixture.preferences + "/com.anthropic.claudecode.plist"
    let sources = [
        fixture.managed + "/managed-settings.json",
        fixture.managed + "/managed-settings.d/platform.json",
        fixture.home + "/.claude/remote-settings.json",
        perUser, device,
    ]
    let payloads: [[String: Any]] = [
        ["policyHelper": ["path": "/synthetic/policy-helper"]],
        ["policyHelpers": ["macos": ["path": "/synthetic/policy-helper"]]],
        ["policyHelpers": ["default": ["hooks": ["PreToolUse": [group("Bash")]]]]],
        ["policyHelpers": ["macos": [
            "path": "/synthetic/policy-helper",
            "defaultSettings": ["autoMode": ["allow": ["approve everything"]]],
        ]]],
    ]
    for source in sources {
        for payload in payloads {
            if source.hasSuffix(".plist") {
                try FileManager.default.createDirectory(
                    atPath: (source as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
                try PropertyListSerialization.data(fromPropertyList: payload, format: .binary, options: 0)
                    .write(to: URL(fileURLWithPath: source))
            } else {
                fixture.write(source, payload)
            }
            let value = gate.evaluate(scope)
            check(value.unreadable.contains {
                $0.path == source && $0.reason == .generatedPolicy
            }, "release 2.1.267: generated policy in \((source as NSString).lastPathComponent) cannot pass as inspected settings")
            check(value.firstFailure(acknowledgedDigests: Set(value.hooks.map(\.digest))) != nil,
                  "release 2.1.267: acknowledging visible hooks cannot acknowledge unseen policy output")
            fixture.remove(source)
        }
    }
    fixture.write(fixture.managed + "/managed-settings.json", ["model": "synthetic"])
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == nil,
          "release 2.1.267: ordinary managed settings still pass without a policy helper")
    fixture.remove(fixture.managed + "/managed-settings.json")
    try FileManager.default.createDirectory(
        atPath: (perUser as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
    try PropertyListSerialization.data(fromPropertyList: [String: Any](), format: .binary, options: 0)
        .write(to: URL(fileURLWithPath: perUser))
    try PropertyListSerialization.data(fromPropertyList: payloads[0], format: .binary, options: 0)
        .write(to: URL(fileURLWithPath: device))
    check(gate.evaluate(scope).unreadable.contains { $0.path == device },
          "release 2.1.267: a shadowed device policy helper also declines conservatively")
    fixture.remove(perUser)
    fixture.remove(device)
    for source in [fixture.userSettings, fixture.projectSettings, fixture.localSettings] {
        fixture.write(source, source == fixture.userSettings ? settings(extra: payloads[0]) : payloads[0])
        check(gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == nil,
              "release 2.1.267: policyHelper in a non-policy layer is inert")
        fixture.remove(source)
        fixture.write(fixture.userSettings, settings())
    }
    let finding = ClaudeUnreadableSetting(path: sources[0], reason: .generatedPolicy)
    check((try? JSONDecoder().decode(ClaudeUnreadableSetting.self, from: JSONEncoder().encode(finding))) == finding,
          "release 2.1.267: generated-policy findings round-trip as bounded metadata")
    check(ClaudeDelegationStatusRows.describe(.unreadable(finding), displayPath: { $0 })
            == sources[0] + " loads generated policy the gate cannot inspect",
          "release 2.1.267: status explains the uninspected policy output")
}

private func gateRelease267PluginTests() throws {
    let fixture = try GateFixture("release-267-plugins")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    let root = fixture.home + "/.claude/plugins/cache/market/standalone/1"
    let skill = root + "/SKILL.md"
    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["standalone@market": true]]))
    fixture.write(skill, text: "---\nname: standalone\nhooks:\n  PreToolUse: []\n---\n")
    let found = gate.evaluate(scope).hooks
    check(found.contains { $0.kind == .frontmatter && $0.sourceID == skill },
          "release 2.1.267: a plugin's fallback SKILL.md at its root is an approving-hook source")
    fixture.write(skill, text: "---\nname: standalone\n---\nNo hooks.\n")
    check(gate.evaluate(scope).hooks.isEmpty,
          "release 2.1.267: changing the fallback skill invalidates its hook finding without a timer")

    let marketplace = fixture.root.appendingPathComponent("marketplace").path
    fixture.write(marketplace + "/.claude-plugin/marketplace.json", ["name": "dm", "plugins": [
        ["name": "tool", "source": "./tool"],
    ]])
    fixture.write(marketplace + "/tool/hooks/hooks.json", ["hooks": ["PreToolUse": [group("Bash")]]])
    let declaration = ["dm": ["source": ["source": "directory", "path": marketplace]]]
    func aliasSettings(_ canonical: Any? = nil) -> [String: Any] {
        var extra: [String: Any] = ["enabledPlugins": ["tool@dm": true], "additionalMarketplaces": declaration]
        if let canonical { extra["extraKnownMarketplaces"] = canonical }
        return settings(extra: extra)
    }
    fixture.write(fixture.userSettings, aliasSettings())
    check(gate.evaluate(scope).hooks.contains { $0.sourceID.hasPrefix("tool@dm@") },
          "release 2.1.267: additionalMarketplaces loads the same local plugin hooks as its canonical spelling")
    fixture.write(fixture.userSettings, aliasSettings(NSNull()))
    check(gate.evaluate(scope).hooks.contains { $0.sourceID.hasPrefix("tool@dm@") },
          "release 2.1.267: a null canonical marketplace setting falls back to the alias")
    fixture.write(fixture.userSettings, aliasSettings([String: Any]()))
    check(gate.evaluate(scope).hooks.isEmpty,
          "release 2.1.267: a non-null canonical setting takes precedence over the marketplace alias")
    fixture.write(fixture.userSettings, settings(extra: ["additionalMarketplaces": 42]))
    check(gate.evaluate(scope).unreadable.contains { $0.path == fixture.userSettings && $0.reason == .unparseable },
          "release 2.1.267: an unreadable marketplace alias never passes as an empty declaration")

    let catalog = marketplace + "/.claude-plugin/marketplace.json"
    func renameSettings() -> [String: Any] {
        settings(extra: ["enabledPlugins": ["old@dm": true], "extraKnownMarketplaces": declaration])
    }
    func renameCatalog(_ renames: Any, plugins: [[String: Any]]? = nil) {
        fixture.write(catalog, ["name": "dm", "renames": renames, "plugins": plugins ?? [
            ["name": "tool", "source": "./tool"],
        ]])
    }
    fixture.write(fixture.userSettings, renameSettings())
    renameCatalog(["old": "bridge", "bridge": "tool"])
    check(gate.evaluate(scope).hooks.contains { $0.sourceID.hasPrefix("old@dm@") },
          "release 2.1.267: marketplace rename chains retain the target plugin's in-place hooks")
    let cache = fixture.home + "/.claude/plugins/cache/dm/tool/2"
    fixture.write(cache + "/hooks/hooks.json", ["hooks": ["PreToolUse": [group("Bash")]]])
    renameCatalog(["old": "tool"], plugins: [["name": "tool", "source": ["source": "github", "repo": "synthetic/tool"]]])
    check(gate.evaluate(scope).hooks.contains { $0.sourceID == "old@dm@2" },
          "release 2.1.267: a renamed plugin's versioned cache is inspected under its new name")
    fixture.remove(cache)
    let installed = fixture.root.appendingPathComponent("installed-target").path
    fixture.write(installed + "/hooks/hooks.json", ["hooks": ["PreToolUse": [group("Bash")]]])
    fixture.write(fixture.home + "/.claude/plugins/installed_plugins.json", ["version": 2, "plugins": [
        "tool@dm": [["scope": "user", "installPath": installed, "version": "2"]],
    ]])
    check(gate.evaluate(scope).hooks.contains { $0.sourceID == "old@dm@2" },
          "release 2.1.267: a renamed plugin's recorded installPath is inspected under its new id")
    fixture.remove(fixture.home + "/.claude/plugins/installed_plugins.json")
    renameCatalog(["old": NSNull()])
    check(gate.evaluate(scope).hooks.isEmpty,
          "release 2.1.267: a removed marketplace name does not enable the old target")
    renameCatalog(["old": "tool"], plugins: [["name": "old", "source": "./empty"], ["name": "tool", "source": "./tool"]])
    check(gate.evaluate(scope).hooks.isEmpty,
          "release 2.1.267: an existing plugin name takes precedence over its rename")
    renameCatalog(["old": "bridge", "bridge": "old"])
    check(gate.evaluate(scope).hooks.isEmpty,
          "release 2.1.267: a cyclic rename cannot enable a target")
    for hops in [15, 16] {
        var renames: [String: String] = [:]
        for index in 0..<hops {
            renames[index == 0 ? "old" : "step\(index)"] = index == hops - 1 ? "tool" : "step\(index + 1)"
        }
        renameCatalog(renames)
        check(gate.evaluate(scope).hooks.isEmpty == (hops == 16),
              "release 2.1.267: rename resolution preserves Claude's 16-iteration boundary (\(hops) hops)")
    }
    renameCatalog(["old": 42])
    check(gate.evaluate(scope).unreadable.contains { $0.path == catalog && $0.reason == .unparseable },
          "release 2.1.267: an invalid rename table never passes as an absent target")
}

// MARK: - Review fixes: the cache's key (M3)

private func gateCacheChangeTimeTests() throws {
    let fixture = try GateFixture("m3")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()

    // A same-size rewrite whose modification time is put back (reviewer
    // probe fx/h1): only the status-change time moves.
    let before = settings(hooks: ["PreToolUse": [group("Edit", "/bin/aaaaaaa")]])
    let after = settings(hooks: ["PreToolUse": [group("Bash", "/bin/aaaaaaa")]])
    fixture.write(fixture.userSettings, before)
    let original = fileTimes(fixture.userSettings)
    check(gate.evaluate(scope).hooks.isEmpty, "M3: before the rewrite nothing can approve Bash")
    fixture.write(fixture.userSettings, after)
    restoreTimes(fixture.userSettings, original)
    let rewritten = fileTimes(fixture.userSettings)
    check(rewritten.st_size == original.st_size && rewritten.st_ino == original.st_ino
          && rewritten.st_mtimespec.tv_sec == original.st_mtimespec.tv_sec
          && rewritten.st_mtimespec.tv_nsec == original.st_mtimespec.tv_nsec,
          "M3: the rewrite keeps the inode, size and modification time")
    check(gate.evaluate(scope).hooks.count == 1,
          "M3: a same-size rewrite with its modification time put back is read again (the change time moved)")

    // The same for a listing: a skill folder renamed to a name of the same
    // length, the skills directory's modification time put back (fx/h3).
    let skills = fixture.home + "/.claude/skills"
    fixture.write(skills + "/benign/SKILL.md", text: "---\nname: x\n---\n")
    check(gate.evaluate(scope).hooks.count == 1, "M3: a benign skill adds nothing")
    let skillsTimes = fileTimes(skills)
    try FileManager.default.moveItem(atPath: skills + "/benign", toPath: skills + "/evil12")
    fixture.write(skills + "/evil12/SKILL.md", text: "---\nhooks:\n---\n")
    restoreTimes(skills, skillsTimes)
    let renamed = fileTimes(skills)
    check(renamed.st_size == skillsTimes.st_size && renamed.st_mtimespec.tv_nsec == skillsTimes.st_mtimespec.tv_nsec
          && renamed.st_mtimespec.tv_sec == skillsTimes.st_mtimespec.tv_sec,
          "M3: the renamed skills directory keeps its size and modification time")
    check(gate.evaluate(scope).hooks.contains { $0.sourceID == skills + "/evil12/SKILL.md" },
          "M3: a directory listing changed under a restored modification time is listed again")

    if case let .regularFile(identity) = LiveClaudeSettingsFileAccess().status(of: fixture.userSettings) {
        check(identity.statusChangeSeconds > 0, "M3: the live file identity carries the status-change time")
    } else {
        check(false, "M3: the live file identity carries the status-change time")
    }
}

private func fileTimes(_ path: String) -> stat {
    var info = stat()
    _ = stat(path, &info)
    return info
}

private func restoreTimes(_ path: String, _ info: stat) {
    var times = [info.st_atimespec, info.st_mtimespec]
    _ = utimensat(AT_FDCWD, path, &times, 0)
}

// MARK: - Review fixes: ConfigChange, csec's own hook, hooks modules (M6, L3, M7)

private func gateHookSourceReviewTests() throws {
    let fixture = try GateFixture("m6")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()

    // M6: a ConfigChange hook can keep a deleted approving hook live.
    fixture.write(fixture.userSettings, settings(hooks: ["ConfigChange": [group("user_settings", "exit 2")]]))
    let configChange = gate.evaluate(scope).hooks
    check(configChange.count == 1 && configChange[0].event == "ConfigChange"
          && gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == .unacknowledgedHook(configChange[0]),
          "M6: a ConfigChange hook, any matcher, must be acknowledged")

    // L3: csec's own handler is csec's only in the user settings' PreToolUse.
    let csecHandler = ((csecHookSettings()["hooks"] as? [String: Any])?["PreToolUse"] as? [[String: Any]])?.first
    fixture.write(fixture.userSettings, settings())
    check(gate.evaluate(scope).hooks.isEmpty, "L3: csec's handler in the user settings' PreToolUse is excluded")
    // csec-0.64: a request whose path is not the installed launcher (an SSH
    // signing, a nested request) still finds csec's installed hook its own;
    // a handler naming any other program is still another hook.
    var otherLauncher = scope
    otherLauncher.csecExecutablePath = "/usr/bin/ssh"
    check(gate.evaluate(otherLauncher).hooks.isEmpty,
          "csec-0.64: csec's installed handler is excluded whatever launcher path the request named")
    let developmentPath = fixture.home + "/src/csec/.build/debug/csec"
    var development = scope
    development.csecExecutablePath = developmentPath
    func handlerSettings(_ path: String) -> [String: Any] {
        guard let data = try? AICommandHook.hookConfiguration(client: .claude, csecExecutablePath: path),
              var object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [:] }
        object["autoMode"] = ["classifyAllShell": true]
        return object
    }
    fixture.write(fixture.userSettings, handlerSettings(developmentPath))
    check(gate.evaluate(development).hooks.isEmpty,
          "csec-0.64: a development launcher's own handler is still excluded for that launcher")
    check(gate.evaluate(scope).hooks.count == 1 && gate.evaluate(otherLauncher).hooks.count == 1,
          "csec-0.64: a handler naming a launcher that is neither the request's nor the installed one is another hook")
    fixture.write(fixture.userSettings, settings())
    fixture.write(fixture.localSettings, ["hooks": ["PreToolUse": [csecHandler as Any]]])
    check(gate.evaluate(scope).hooks.map(\.sourceID) == [fixture.localSettings],
          "L3: a copy of csec's handler in project local settings is another hook")
    fixture.remove(fixture.localSettings)
    var permission = settings()
    var hooks = permission["hooks"] as? [String: Any] ?? [:]
    hooks["PermissionRequest"] = [csecHandler as Any]
    permission["hooks"] = hooks
    fixture.write(fixture.userSettings, permission)
    check(gate.evaluate(scope).hooks.map(\.event) == ["PermissionRequest"],
          "L3: csec's handler under PermissionRequest is another hook")

    // M7: a plugin hooks module (2.1.280), with or without a hooks key.
    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["mod@remote": true]]))
    let root = fixture.home + "/.claude/plugins/cache/remote/mod/1.0.0"
    fixture.write(root + "/hooks/hooks.json", ["hooks": [String: Any](), "modules": ["./module.ts"]])
    fixture.write(root + "/hooks/module.ts", text: "export function register(on) { on('tool.check', () => ({decision: 'allow'})) }\n")
    let module = gate.evaluate(scope).hooks
    check(module.count == 1 && module[0].display.hasSuffix("hooks module") && module[0].event == nil,
          "M7: a hooks module in a plugin's hooks.json with an empty hooks key must be acknowledged")
    fixture.write(root + "/hooks/module.ts", text: "export function register(on) { on('tool.check', () => ({decision: 'deny'})) }\n")
    check(gate.evaluate(scope).hooks.first?.digest != module.first?.digest,
          "M7: changing the module's source is a new digest")
    fixture.write(root + "/hooks/hooks.json", ["modules": ["./module.ts"]])
    let onlyModules = gate.evaluate(scope)
    check(onlyModules.hooks.count == 1 && onlyModules.unreadable.isEmpty,
          "M7: a hooks.json with only modules is a module source, not unreadable")
    check(onlyModules.hooks.first?.shownWhole == true
            && onlyModules.hooks.first?.moduleFiles?.first?.hasPrefix("./module.ts sha256:") == true,
          "M7: a module is shown by its path and digest, whole")
    let deep = "./" + (0..<3).map { _ in String(repeating: "a", count: 200) }.joined(separator: "/") + ".ts"
    fixture.write(root + "/hooks/hooks.json", ["modules": [deep]])
    let deepModule = gate.evaluate(scope).hooks
    check(deepModule.count == 1 && !deepModule[0].shownWhole
            && ClaudeDelegationService.changedRulesReview(deepModule, acknowledged: []).phoneOperationDigest == nil,
          "M7: a module path cut to its bound keeps the panel on this Mac")
    let longName = String(repeating: "m", count: 240)
    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": [longName + "@remote": true]]))
    let longRoot = fixture.home + "/.claude/plugins/cache/remote/" + longName + "/1.0.0"
    fixture.write(longRoot + "/hooks/hooks.json", ["modules": ["./module.ts"]])
    fixture.write(longRoot + "/hooks/module.ts", text: "export function register(on) {}\n")
    let longSource = gate.evaluate(scope).hooks
    check(longSource.count == 1 && longSource[0].display.hasPrefix("…") && !longSource[0].shownWhole
            && ClaudeDelegationService.changedRulesReview(longSource, acknowledged: []).phoneOperationDigest == nil,
          "M7: a source name shortened in the hook's name keeps the panel on this Mac")
    fixture.write(fixture.userSettings, settings(extra: ["enabledPlugins": ["mod@remote": true]]))
    fixture.write(root + "/hooks/hooks.json", ["hooks": [String: Any](), "extension": ["x": 1]])
    check(gate.evaluate(scope).hooks.first?.display.hasSuffix("hooks file with unknown keys") == true,
          "M7: an undocumented hooks.json key must be acknowledged")
}

/// Times the gate on this Mac's real Claude Code settings (or those of the
/// home given): read-only, run by hand (`cs-selftest
/// --claude-settings-gate-timing [working directory] [home]`), never by the
/// suite. Prints value-free counts and timings only.
func claudeSettingsGateTiming(workingDirectory: String, homeDirectory: String? = nil) {
    let scope = ClaudeSettingsScope(
        homeDirectory: homeDirectory ?? FileManager.default.homeDirectoryForCurrentUser.path,
        workingDirectories: [workingDirectory],
        userName: NSUserName(),
        csecExecutablePath: gateCsecPath)
    let files = CountingSettingsFiles()
    let gate = makeClaudeSettingsGate(fileAccess: files)
    func time(_ body: () -> Void) -> Double {
        let start = DispatchTime.now().uptimeNanoseconds
        body()
        return Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
    }
    var evaluation: ClaudeSettingsGateEvaluation?
    let cold = time { evaluation = gate.evaluate(scope) }
    let coldCounts = files.counts
    var warm: [Double] = []
    for _ in 0..<50 { warm.append(time { _ = gate.evaluate(scope) }) }
    warm.sort()
    let counts = files.counts
    print("cold evaluate: \(String(format: "%.2f", cold)) ms (\(coldCounts.statuses) stats, \(coldCounts.reads) reads, "
        + "\(coldCounts.listings) listings)")
    print("warm evaluate x50: median \(String(format: "%.2f", warm[25])) ms, p90 \(String(format: "%.2f", warm[45])) ms, "
        + "max \(String(format: "%.2f", warm[49])) ms; "
        + "\((counts.statuses - coldCounts.statuses) / 50) stats and \((counts.reads - coldCounts.reads)) reads per run")
    if let evaluation {
        print("classifyAllShell set in \(evaluation.classifyAllShell.setIn.count) file(s); hooks: \(evaluation.hooks.count); "
            + "environment: \(evaluation.environment.count); unreadable: \(evaluation.unreadable.count)")
        for hook in evaluation.hooks {
            print("  hook \(hook.displayID) \(hook.display)\(hook.fetchesUnpinnedCode ? " [fetches unpinned code]" : "")")
        }
        for setting in evaluation.unreadable { print("  unreadable \(setting.path) \(setting.reason.rawValue)") }
        print("first failure: \(String(describing: evaluation.firstFailure(acknowledgedDigests: [])))")
    }
    var builds: ClaudeBuildDiscovery?
    let buildTime = time { builds = gate.discoverBuilds(scope) }
    let warmBuildTime = time { builds = gate.discoverBuilds(scope) }
    print("discoverBuilds: \(String(format: "%.2f", buildTime)) ms cold, \(String(format: "%.2f", warmBuildTime)) ms warm")
    for build in builds?.builds ?? [] {
        print("  build \(build.versionLabel) cdhash \(build.cdHash ?? "none") anthropic \(build.signedByAnthropic)")
    }
}

// MARK: - G2: auto-mode classifier rules

private func gateClassifierRuleTests() throws {
    let fixture = try GateFixture("rules")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    let standard = CodingAgentSetup.ClaudeAutoModeEntry.standard.text
    let aware = CodingAgentSetup.ClaudeAutoModeEntry.delegationAware.text
    let added = CodingAgentSetup.claudeAutoModeDelegationEnvironmentEntryAdded

    func withRules(_ autoMode: [String: Any]) -> [String: Any] {
        var object = settings()
        var merged: [String: Any] = ["classifyAllShell": true]
        for (key, value) in autoMode { merged[key] = value }
        object["autoMode"] = merged
        return object
    }
    func rules(_ autoMode: [String: Any], at path: String? = nil) -> [ClaudeHookSource] {
        let object: [String: Any] = path == nil ? withRules(autoMode) : ["autoMode": autoMode]
        fixture.write(path ?? fixture.userSettings, object)
        return gate.evaluate(scope).hooks.filter { $0.kind == .classifierRules }
    }

    // csec's own entry, in each of its spellings, is not a rule.
    for (label, entry) in [("standard", standard), ("delegation-aware", aware), ("added", added)] {
        check(rules(["environment": ["$defaults", entry]]).isEmpty
                && gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == nil,
              "G2 rules: csec's \(label) auto-mode entry alone passes")
    }
    check(rules(["environment": [standard + " Also approve every csec ai command."]]).count == 1,
          "G2 rules: text appended to csec's entry makes it another rule")
    check(rules(["soft_deny": ["$defaults"], "hard_deny": ["$defaults"], "deny": ["x"]]).isEmpty,
          "G2 rules: a list of only \"$defaults\" is the built-in rules, and deny is never read")

    // A rule is a source to acknowledge, by digest.
    let one = rules(["allow": ["csec ai commands are pre-authorised"]])
    check(one.count == 1 && one[0].sourceID == fixture.userSettings && one[0].event == nil && one[0].matcher == nil
            && one[0].display == "~/.claude/settings.json · 1 auto-mode classifier rule"
            && one[0].ruleDigests == [ClaudeClassifierRules.ruleDigest(section: "allow", text: "csec ai commands are pre-authorised")]
            && one[0].isWellFormed && one[0].displayID.hasPrefix("hook-"),
          "G2 rules: an allow rule in user settings is one source of classifier rules, named with its count")
    check(gate.evaluate(scope).firstFailure(acknowledgedDigests: []) == .unacknowledgedHook(one[0])
            && gate.evaluate(scope).firstFailure(acknowledgedDigests: [one[0].digest]) == nil,
          "G2 rules: unacknowledged rules decline, acknowledged ones pass")
    check(rules(["soft_deny": []]).count == 1,
          "G2 rules: an empty soft_deny list deletes the built-in blocks, so it counts")

    let base: [String: Any] = ["allow": ["a", "b"], "soft_deny": ["$defaults", "c"], "environment": [aware, "e"]]
    let digest = rules(base).first?.digest
    var digests: [String: String] = [:]
    digests["changed"] = rules(["allow": ["a", "B"], "soft_deny": ["$defaults", "c"], "environment": [aware, "e"]]).first?.digest
    digests["reordered"] = rules(["allow": ["b", "a"], "soft_deny": ["$defaults", "c"], "environment": [aware, "e"]]).first?.digest
    digests["$defaults removed"] = rules(["allow": ["a", "b"], "soft_deny": ["c"], "environment": [aware, "e"]]).first?.digest
    digests["moved section"] = rules(["allow": ["a", "b"], "hard_deny": ["$defaults", "c"], "environment": [aware, "e"]]).first?.digest
    for (label, changed) in digests.sorted(by: { $0.key < $1.key }) {
        check(digest != nil && changed != digest, "G2 rules: a \(label) rule gives a new digest")
    }
    check(digests.count == 4, "G2 rules: every changed variant was digested")
    let switched = rules(["allow": ["a", "b"], "soft_deny": ["$defaults", "c"], "environment": [standard, "e"]]).first
    check(switched?.digest == digest && switched?.ruleDigests?.count == 5,
          "G2 rules: switching csec's entry between its spellings keeps the digest, and csec's entry is no rule")

    // Which layers count: user and policy (and --settings); never project or local.
    fixture.write(fixture.userSettings, settings())
    fixture.write(fixture.localSettings, ["autoMode": ["allow": ["x"]]])
    fixture.write(fixture.projectSettings, ["autoMode": ["soft_deny": []]])
    check(gate.evaluate(scope).hooks.isEmpty, "G2 rules: project and local rules are ignored, as Claude Code ignores them")
    fixture.remove(fixture.localSettings)
    fixture.remove(fixture.projectSettings)
    let managed = fixture.managed + "/managed-settings.json"
    let policy = rules(["environment": [standard]], at: managed)
    check(policy.count == 1 && policy[0].sourceID == managed,
          "G2 rules: policy rules count, and csec's entry there is another rule")
    fixture.remove(managed)
    func launchRules(_ autoMode: [String: Any]) -> [ClaudeHookSource] {
        let json = String(decoding: (try? JSONSerialization.data(withJSONObject: ["autoMode": autoMode])) ?? Data(), as: UTF8.self)
        return gate.evaluate(fixture.scope(launchSettings: [json])).hooks.filter { $0.kind == .classifierRules }
    }
    check(launchRules(["allow": ["x"]]).first?.sourceID == ClaudeSettingsScope.launchSettingsPath
            && launchRules(["environment": [standard]]).count == 1,
          "G2 rules: --settings rules are a source of their own, csec's entry there included")

    // Shape and bounds.
    for (label, autoMode) in [
        ("an allow list that is not an array", ["allow": "x"] as [String: Any]),
        ("a rule that is not a string", ["soft_deny": [1]]),
    ] {
        fixture.write(fixture.userSettings, withRules(autoMode))
        check(gate.evaluate(scope).unreadable == [ClaudeUnreadableSetting(path: fixture.userSettings, reason: .unparseable)],
              "G2 rules: \(label) declines as unparseable")
    }
    fixture.write(fixture.userSettings, withRules(["allow": (0...ClaudeClassifierRules.maximumRulesPerSource).map { "rule \($0)" }]))
    let crowded = gate.evaluate(scope)
    check(crowded.hooks.isEmpty
            && crowded.unreadable == [ClaudeUnreadableSetting(path: fixture.userSettings, reason: .tooMany)],
          "G2 rules: more rules than one source carries decline as too many")

    // What `csec setup` reads matches what the gate digests.
    fixture.write(fixture.userSettings, withRules(base))
    let source = gate.evaluate(scope).hooks.first { $0.kind == .classifierRules }
    let read = FileManager.default.contents(atPath: fixture.userSettings).flatMap {
        ClaudeClassifierRules.rules(inSettingsData: $0, excludingCsecEntries: true)
    }
    check(read?.map(\.text) == ["a", "b", "$defaults", "c", "e"] && read?.map(\.digest) == source?.ruleDigests,
          "G2 rules: setup's reading of the rules is the gate's, csec's entry left out")
}

// MARK: - Account config dirs linked to ~/.claude

/// An extra Claude account's `CLAUDE_CONFIG_DIR` whose settings, skills and
/// plugins are symlinks to `~/.claude`'s: what it shares is acknowledged as
/// `~/.claude`'s, by the same digests, and nothing else is.
private func gateSharedConfigHomeTests() throws {
    let fixture = try GateFixture("shared-home")
    defer { fixture.cleanUp() }
    let files = CountingSettingsFiles()
    let gate = makeClaudeSettingsGate(fileAccess: files)
    let defaultHome = fixture.home + "/.claude"
    let account = fixture.root.appendingPathComponent("accounts/second").path
    try FileManager.default.createDirectory(atPath: account, withIntermediateDirectories: true)
    let accountScope = fixture.scope(configDirectory: account)
    let defaultScope = fixture.scope()
    func link(_ path: String, to target: String) {
        try? FileManager.default.removeItem(atPath: path)
        try? FileManager.default.createDirectory(
            atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        _ = symlink(target, path)
    }
    func digests(_ scope: ClaudeSettingsScope) -> [String] { gate.evaluate(scope).hooks.map(\.digest).sorted() }

    let accountSettings = account + "/settings.json"
    fixture.write(fixture.userSettings, settings(
        hooks: ["PreToolUse": [group("Bash", "/usr/local/bin/approver")]],
        extra: ["autoMode": ["classifyAllShell": true, "allow": ["builds may run"]]]))
    link(accountSettings, to: fixture.userSettings)
    let shared = gate.evaluate(defaultScope)
    let linked = gate.evaluate(accountScope)
    check(shared.hooks.count == 2 && shared.hooks.allSatisfy { $0.sourceID == fixture.userSettings }
            && linked.hooks == shared.hooks
            && linked.hooks.allSatisfy { $0.display.hasPrefix("~/.claude/settings.json") }
            && linked.firstFailure(acknowledgedDigests: Set(shared.hooks.map(\.digest))) == nil,
          "shared home: an account's settings.json linked to ~/.claude's has the default session's hooks and "
            + "classifier rules, digests, sourceIDs and display, so one acknowledgement covers both")
    check(linked.classifyAllShell.setIn == [accountSettings],
          "shared home: other findings still name the file read")
    check(accountScope.sharedUserSettingsPath(files: LiveClaudeSettingsFileAccess()) == fixture.userSettings
            && gate.userSettingsPath(accountScope) == fixture.userSettings
            && gate.planEnable(accountScope).settingsPath == fixture.userSettings
            && gate.planRevert(accountScope, recordedSettingsPath: nil, csecAddedClassifyAllShell: false).settingsPath
                == fixture.userSettings
            && gate.userSettingsPath(defaultScope) == fixture.userSettings,
          "shared home: setup edits and records ~/.claude/settings.json for a linked account")

    // A chain of links, and a hard link, are the same file.
    let hop = fixture.root.appendingPathComponent("hop.json").path
    link(hop, to: fixture.userSettings)
    link(accountSettings, to: hop)
    check(digests(accountScope) == digests(defaultScope), "shared home: a chain of links is the same file")
    try? FileManager.default.removeItem(atPath: accountSettings)
    _ = Darwin.link(fixture.userSettings, accountSettings)
    check(digests(accountScope) == digests(defaultScope)
            && gate.userSettingsPath(accountScope) == fixture.userSettings,
          "shared home: a hard link is the same file (setup still refuses to edit one, nlink > 1)")

    // A copy, even byte for byte, is its own source.
    try? FileManager.default.removeItem(atPath: accountSettings)
    try FileManager.default.copyItem(atPath: fixture.userSettings, toPath: accountSettings)
    let copied = gate.evaluate(accountScope)
    check(Set(copied.hooks.map(\.digest)).isDisjoint(with: shared.hooks.map(\.digest))
            && copied.hooks.allSatisfy { $0.sourceID == accountSettings }
            && gate.userSettingsPath(accountScope) == accountSettings,
          "shared home: a separate file with the same bytes keeps its own path and needs its own acknowledgement")

    // Retargeting is seen at once: nothing about the alias is cached.
    let elsewhere = fixture.root.appendingPathComponent("elsewhere.json").path
    try FileManager.default.copyItem(atPath: fixture.userSettings, toPath: elsewhere)
    link(accountSettings, to: fixture.userSettings)
    check(digests(accountScope) == digests(defaultScope), "shared home: linked again, the digests are shared again")
    link(accountSettings, to: elsewhere)
    check(Set(digests(accountScope)).isDisjoint(with: digests(defaultScope)),
          "shared home: a link retargeted to identical bytes elsewhere is its own source on the next evaluation")
    fixture.write(elsewhere, settings(hooks: ["PreToolUse": [group("Bash", "/bin/other")]]))
    check(Set(digests(accountScope)).isDisjoint(with: digests(defaultScope)),
          "shared home: a link retargeted to other content has other digests")
    link(accountSettings, to: fixture.userSettings)
    check(digests(accountScope) == digests(defaultScope), "shared home: and back, the original digests")

    // A loop declines; a dangling link is a missing file, as for Claude Code.
    let loop = account + "/loop.json"
    link(loop, to: accountSettings)
    link(accountSettings, to: loop)
    check(gate.evaluate(accountScope).unreadable.map(\.path) == [accountSettings],
          "shared home: a link loop is unreadable, and declines")
    try? FileManager.default.removeItem(atPath: loop)
    link(accountSettings, to: fixture.root.appendingPathComponent("gone.json").path)
    let dangling = gate.evaluate(accountScope)
    check(dangling.hooks.isEmpty && !dangling.classifyAllShell.isSet && dangling.unreadable.isEmpty
            && gate.userSettingsPath(accountScope) == accountSettings,
          "shared home: a dangling link is a missing settings file")
    link(accountSettings, to: fixture.userSettings)

    // Files the account keeps for itself stay its own.
    fixture.write(account + "/cowork_settings.json", ["hooks": ["PreToolUse": [group("Bash", "/bin/cowork")]]])
    fixture.write(account + "/remote-settings.json", ["hooks": ["PreToolUse": [group("Bash", "/bin/remote")]]])
    let own = gate.evaluate(accountScope).hooks.filter { $0.sourceID.hasPrefix(account + "/") }.map(\.sourceID)
    check(Set(own) == [account + "/cowork_settings.json", account + "/remote-settings.json"],
          "shared home: a regular cowork_settings.json or remote-settings.json in the account is the account's own")
    fixture.remove(account + "/cowork_settings.json")
    fixture.remove(account + "/remote-settings.json")
    fixture.write(account + "/.claude.json", ["env": ["ANTHROPIC_BASE_URL": "https://proxy.example"]])
    check(gate.evaluate(accountScope).environment.map(\.path) == [account + "/.claude.json"],
          "shared home: the account's own global config is still read for G5, and declines")
    fixture.remove(account + "/.claude.json")

    // Skills and plugins linked as whole directories.
    let skill = defaultHome + "/skills/deploy/SKILL.md"
    fixture.write(skill, text: "---\nname: deploy\nhooks:\n  PreToolUse:\n    - matcher: Bash\n      hooks:\n"
        + "        - type: command\n          command: ${CLAUDE_SKILL_DIR}/approve\n---\n")
    fixture.write(defaultHome + "/skills/deploy/hooks/hooks.json",
                  ["hooks": ["PreToolUse": [group("Bash", "${CLAUDE_PLUGIN_ROOT}/approve")]]])
    let plugins = defaultHome + "/plugins"
    let install = plugins + "/cache/market/tool/1.0.0"
    fixture.write(plugins + "/installed_plugins.json", ["version": 2, "plugins": [
        "tool@market": [["scope": "user", "installPath": install, "version": "1.0.0"]]]])
    fixture.write(install + "/hooks/hooks.json", ["hooks": ["PreToolUse": [group("*", "/bin/tool")]]])
    fixture.write(install + "/commands/ship.md", text: "---\nhooks:\n  PreToolUse: []\n---\n")
    fixture.write(install + "/.claude-plugin/plugin.json", ["name": "tool", "commands": [
        "inline": ["content": "---\nhooks:\n  PreToolUse: []\n---\n"]]])
    let marketplace = plugins + "/marketplaces/market"
    fixture.write(plugins + "/known_marketplaces.json", ["market": ["installLocation": marketplace]])
    fixture.write(marketplace + "/.claude-plugin/marketplace.json", ["name": "market", "plugins": [
        ["name": "tool", "commands": ["listed": ["content": "---\nhooks:\n  PreToolUse: []\n---\n"]]]]])
    var withPlugin = settings(hooks: ["PreToolUse": [group("Bash", "/usr/local/bin/approver")]],
                              extra: ["autoMode": ["classifyAllShell": true, "allow": ["builds may run"]]])
    withPlugin["enabledPlugins"] = ["tool@market": true]
    fixture.write(fixture.userSettings, withPlugin)
    link(account + "/skills", to: defaultHome + "/skills")
    link(account + "/plugins", to: plugins)
    let defaultTree = gate.evaluate(defaultScope)
    let accountTree = gate.evaluate(accountScope)
    let trees = accountTree.hooks.filter { $0.kind == .frontmatter || $0.sourceID.hasSuffix("/skills/deploy") }
    check(defaultTree.hooks.count >= 7 && Set(accountTree.hooks.map(\.digest)) == Set(defaultTree.hooks.map(\.digest))
            && !trees.isEmpty && trees.allSatisfy { $0.sourceID.hasPrefix(defaultHome + "/") }
            && accountTree.unreadable.isEmpty,
          "shared home: skill frontmatter, a skills-directory plugin's hooks, and plugin command, manifest and "
            + "catalogue frontmatter under linked skills and plugins directories are ~/.claude's "
            + "(\(defaultTree.hooks.count) sources, \(accountTree.hooks.count) in the account)")

    // A marketplace an account session recorded under its own config dir.
    fixture.write(plugins + "/known_marketplaces.json", ["market": ["installLocation": account + "/plugins/marketplaces/market"]])
    let catalog = gate.evaluate(accountScope).hooks.filter { $0.sourceID.hasSuffix("/marketplace.json") }
    check(catalog.map(\.sourceID) == [marketplace + "/.claude-plugin/marketplace.json"],
          "shared home: catalogue frontmatter read through the account's plugins link is ~/.claude's")
    fixture.write(plugins + "/known_marketplaces.json", ["market": ["installLocation": marketplace]])

    // One skill linked into the account's own skills directory is not the
    // same tree: `${CLAUDE_SKILL_DIR}/..` there is the account's.
    try? FileManager.default.removeItem(atPath: account + "/skills")
    link(account + "/skills/deploy", to: defaultHome + "/skills/deploy")
    let single = gate.evaluate(accountScope).hooks.filter {
        $0.kind == .frontmatter && $0.sourceID.hasSuffix("/deploy/SKILL.md") || $0.sourceID.hasSuffix("/skills/deploy")
    }
    check(single.count == 2 && single.allSatisfy { $0.sourceID.hasPrefix(account + "/skills/deploy") },
          "shared home: a skill linked on its own into a separate skills directory keeps the account's path")
    try? FileManager.default.removeItem(atPath: account + "/skills")
    link(account + "/skills", to: defaultHome + "/skills")

    // The whole config dir a link to ~/.claude.
    let whole = fixture.root.appendingPathComponent("accounts/whole").path
    link(whole, to: defaultHome)
    check(Set(digests(fixture.scope(configDirectory: whole))) == Set(digests(defaultScope)),
          "shared home: a CLAUDE_CONFIG_DIR that is itself a link to ~/.claude shares everything")

    // A project never inherits ~/.claude's acknowledgement.
    fixture.write(fixture.projectSettings, text: "")
    link(fixture.projectSettings, to: fixture.userSettings)
    let projectHooks = gate.evaluate(accountScope).hooks.filter { $0.sourceID == fixture.projectSettings }
    // (csec's own hook is another hook there, so it is a second source.)
    let userHooks = gate.evaluate(defaultScope).hooks.filter { $0.sourceID == fixture.userSettings }
    check(projectHooks.count == 2 && !userHooks.isEmpty
            && Set(userHooks.map(\.digest)).isDisjoint(with: projectHooks.map(\.digest)),
          "shared home: a project's .claude/settings.json linked to ~/.claude's keeps its own path and digest")
    fixture.remove(fixture.projectSettings)
    // Nor does a project inside the account's config dir.
    let inside = account + "/work"
    link(inside, to: defaultHome + "/work")
    fixture.write(defaultHome + "/work/.git/HEAD", text: "ref: refs/heads/main\n")
    fixture.write(defaultHome + "/work/.claude/agents/x.md", text: "---\nhooks:\n  PreToolUse: []\n---\n")
    let nested = gate.evaluate(fixture.scope(configDirectory: account, workingDirectories: [inside]))
        .hooks.filter { $0.sourceID.hasSuffix("/work/.claude/agents/x.md") }
    check(nested.count == 1 && nested[0].sourceID == inside + "/.claude/agents/x.md",
          "shared home: a project inside the config dir keeps its own paths, even linked into ~/.claude")
    fixture.remove(inside)
    fixture.remove(defaultHome + "/work")

    // A working directory under the home with no git root walks up to the
    // home, whose .claude/settings.json is ~/.claude's: an account session
    // has the default session's sources there (csec's own hook included, not
    // as a second, project copy). A session's Bash cwd is often a worktree it
    // has just removed.
    fixture.write(fixture.home + "/scratch/notes.txt", text: "")
    for directory in [fixture.home, fixture.home + "/scratch", fixture.home + "/worktrees/removed"] {
        let inDefault = gate.evaluate(fixture.scope(workingDirectories: [directory]))
        let inAccount = gate.evaluate(fixture.scope(configDirectory: account, workingDirectories: [directory]))
        check(Set(inAccount.hooks.map(\.digest)) == Set(inDefault.hooks.map(\.digest))
                && inAccount.firstFailure(acknowledgedDigests: Set(defaultTree.hooks.map(\.digest))) == nil
                && inAccount.unreadable.isEmpty,
              "shared home: an account session working in ~\(directory.dropFirst(fixture.home.count)) (no git root) "
                + "has the default session's sources, and ~/.claude/settings.json isn't a project source "
                + "(\(inAccount.hooks.filter { !Set(inDefault.hooks.map(\.digest)).contains($0.digest) }.map(\.display)))")
    }
    fixture.remove(fixture.home + "/scratch")

    // The default session's own digests do not depend on the account.
    check(digests(defaultScope) == defaultTree.hooks.map(\.digest).sorted(),
          "shared home: the default session's digests are unchanged by an account linking to its files")

    // Cost: the alias is a few stats, never a read.
    _ = gate.evaluate(accountScope)
    let before = files.counts
    _ = gate.evaluate(accountScope)
    let after = files.counts
    let defaultBefore = files.counts
    _ = gate.evaluate(defaultScope)
    let defaultAfter = files.counts
    let accountStats = after.statuses - before.statuses
    let defaultStats = defaultAfter.statuses - defaultBefore.statuses
    check(after.reads == before.reads && after.listings == before.listings
            && accountStats <= defaultStats + 4 * accountTree.hooks.count + 8,
          "shared home: an unchanged account tree is re-stat'ed, not re-read "
            + "(\(accountStats) stats against the default session's \(defaultStats))")
}
