import Foundation
import ConvenientSecurity
import Darwin

/// `csec status` / `csec doctor` coding-agent rows. Synthetic files only.
func codingAgentHookStatusTests() {
    print("\n# Coding-agent hook status")

    let universal = [
        "Bash(csec:*)", "Bash(csec *)", "Bash(csec ai:*)", "Bash(csec ai -- *)", "Bash(csec ai --:*)",
        "Bash(/Applications/ConvenientSecurity.app/Contents/MacOS/csec ai:*)",
        "Bash(csec exec --set K=op://vault/item/field -- *)", "Bash(csec tool-exec:*)",
        "  Bash(csec session:*)  ", "Bash(csec ai -- bash -c *)", "Bash(csec ai -- env:*)",
        "Bash(csec ai -- python:*)", "Bash(csec ai -- sudo -u root:*)", "Bash(csec ai -- npm run:*)",
    ]
    for rule in universal {
        check(CodingAgentHookStatus.isUniversalCSECClaudeRule(rule),
              "\(rule.debugDescription) pre-approves every csec-wrapped command")
    }
    let specific = [
        "Bash(csec ai -- npm test:*)", "Bash(csec ai)", "Bash(csec get:*)", "Bash(csecx ai:*)",
        "Bash(npm run test:*)", "Read(./csec/**)", "Bash(csec ai -- git status)",
        "Bash(csec ai -- python manage.py test:*)", "Bash(csec ai -- bash scripts/check.sh:*)",
    ]
    for rule in specific {
        check(!CodingAgentHookStatus.isUniversalCSECClaudeRule(rule),
              "\(rule.debugDescription) is not a universal csec allow rule")
    }

    do {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("csec-hook-status-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        let home = root.appendingPathComponent("home")
        let project = root.appendingPathComponent("work/project")
        let nested = project.appendingPathComponent("src/module")
        try fm.createDirectory(at: home, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        try fm.createDirectory(at: nested, withIntermediateDirectories: true)
        try fm.createDirectory(at: project.appendingPathComponent(".claude"), withIntermediateDirectories: true)
        defer { try? fm.removeItem(at: root) }
        let csecPath = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
        let settingsDirectory = home.appendingPathComponent(".claude")
        let settings = settingsDirectory.appendingPathComponent("settings.json")
        func state() -> ClaudeHookState {
            CodingAgentHookStatus.claudeHookState(
                homeDirectory: home.path, pathEnvironment: "", csecExecutablePath: csecPath)
        }
        func write(_ object: [String: Any]) throws {
            try fm.createDirectory(at: settingsDirectory, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
            try JSONSerialization.data(withJSONObject: object).write(to: settings)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: settings.path)
        }

        check(state() == .notDetected, "no Claude executable or settings reports Claude as not detected")
        try write(["theme": "dark"])
        check(state() == .missing, "Claude settings without the csec hook report the hook as missing")

        let fresh = try CodingAgentSetup.planClaudeAutoModeEnvironment(basedOn: try CodingAgentSetup.plan(
            detection: CodingAgentDetection(client: .claude, executablePath: nil,
                                            configurationPath: settings.path, configurationExists: true),
            csecExecutablePath: csecPath))
        try CodingAgentSetup.apply(fresh)
        check(state() == .installed(autoModeContext: true),
              "the exact hook plus the current auto-mode entry reports installed with context")

        // With delegated approvals on, csec's entry is the delegation-aware
        // variant: that is current context too, not an outdated one.
        if case let .write(plan) = CodingAgentSetup.planClaudeDelegationEnable(settingsPath: settings.path).outcome {
            try CodingAgentSetup.apply(plan)
        }
        check(state() == .installed(autoModeContext: true)
              && CodingAgentSetup.claudeAutoModeEntry(inSettingsAt: settings.path) == .delegationAware,
              "the exact hook plus the delegation-aware auto-mode entry reports installed with context")

        var withoutContext = try JSONSerialization.jsonObject(with: Data(contentsOf: settings)) as! [String: Any]
        withoutContext["autoMode"] = nil
        try write(withoutContext)
        check(state() == .installed(autoModeContext: false),
              "the exact hook without csec's auto-mode entry reports the missing context")

        // The current handler under `Bash` alone, as installed before Monitor
        // was wrapped: Claude Code's Monitor commands would run unwrapped, so
        // it is an older csec hook, and setup's replacement covers both tools.
        var bashOnly = withoutContext
        var bashOnlyHooks = bashOnly["hooks"] as! [String: Any]
        var bashOnlyGroups = bashOnlyHooks["PreToolUse"] as! [[String: Any]]
        check(bashOnlyGroups.count == 1 && bashOnlyGroups[0]["matcher"] as? String == "Bash|Monitor",
              "the Claude hook is installed under the Bash|Monitor matcher")
        bashOnlyGroups[0]["matcher"] = "Bash"
        bashOnlyGroups.insert(["matcher": "Edit", "hooks": [["type": "command", "command": "/bin/true"]]], at: 0)
        bashOnlyHooks["PreToolUse"] = bashOnlyGroups
        bashOnly["hooks"] = bashOnlyHooks
        try write(bashOnly)
        check(state() == .outdated, "the current csec handler under the Bash matcher alone reports outdated")
        let bashOnlyDetection = CodingAgentDetection(
            client: .claude, executablePath: nil, configurationPath: settings.path, configurationExists: true)
        let replacement = try CodingAgentSetup.plan(
            detection: bashOnlyDetection, csecExecutablePath: csecPath, replaceExistingCSECHook: true)
        check(replacement.action == .merge, "setup offers to replace a csec hook under the Bash matcher alone")
        try CodingAgentSetup.apply(replacement)
        let replaced = try JSONSerialization.jsonObject(with: Data(contentsOf: settings)) as! [String: Any]
        let replacedGroups = (replaced["hooks"] as? [String: Any])?["PreToolUse"] as? [[String: Any]] ?? []
        check(replacedGroups.map { $0["matcher"] as? String } == ["Edit", "Bash|Monitor"]
              && state() == .installed(autoModeContext: false),
              "the replacement moves csec's handler to Bash|Monitor and keeps the other hook")
        try write(withoutContext)

        // The handler shipped before this change: 5 s timeout, silent failure exit.
        var older = withoutContext
        var hooks = older["hooks"] as! [String: Any]
        var groups = hooks["PreToolUse"] as! [[String: Any]]
        var handlers = groups[0]["hooks"] as! [[String: Any]]
        handlers[0]["timeout"] = 5
        groups[0]["hooks"] = handlers
        hooks["PreToolUse"] = groups
        older["hooks"] = hooks
        try write(older)
        check(state() == .outdated, "a recognized older csec handler reports outdated, not missing")

        older["disableAllHooks"] = true
        try write(older)
        check(state() == .hooksDisabled, "disableAllHooks reports that no hook runs")

        // Allow rules from user settings and the nearest project's local file.
        let paths = CodingAgentHookStatus.claudeSettingsPaths(
            homeDirectory: home.path, workingDirectory: nested.path)
        let projectLocal = project.appendingPathComponent(".claude/settings.local.json").path
        check(paths.contains(settings.path) && paths.contains(projectLocal),
              "allow-rule scanning covers user settings and the nearest project's local settings")
        try write(["permissions": ["allow": ["Bash(git status)", "Bash(csec ai:*)"]]])
        try JSONSerialization.data(withJSONObject: [
            "permissions": ["allow": ["Bash(csec ai -- npm test:*)", "Bash(csec exec -- *)"]],
        ]).write(to: URL(fileURLWithPath: projectLocal))
        let found = CodingAgentHookStatus.claudeUniversalAllowRules(settingsPaths: paths)
        check(found == [
            UniversalAllowRule(client: .claude, source: settings.path, rule: "Bash(csec ai:*)"),
            UniversalAllowRule(client: .claude, source: projectLocal, rule: "Bash(csec exec -- *)"),
        ], "doctor finds exactly the universal csec allow rules across settings files")
        let row = CodingAgentHookStatus.allowRulesRow(found, displayPath: { $0 })
        check(row.state == .warn && row.value.contains("Bash(csec ai:*)") && row.value.contains("+1 more"),
              "universal allow rules produce a warning row naming the first rule")
        check(CodingAgentHookStatus.allowRulesRow([], displayPath: { $0 }).state == .ok,
              "no universal allow rules produce an ok row")
        try write(["permissions": ["allow": ["Bash(csec exec --set API_KEY=sk-literal-value -- *)"]]])
        let redacted = CodingAgentHookStatus.claudeUniversalAllowRules(settingsPaths: [settings.path])
        check(redacted.map(\.rule) == ["Bash(csec exec --set API_KEY=… -- *)"],
              "doctor shows a universal rule with its KEY=value values elided")

        // Codex allow rules that admit a universal csec prefix.
        let codexHome = home.appendingPathComponent(".codex")
        try fm.createDirectory(at: codexHome.appendingPathComponent("rules"), withIntermediateDirectories: true)
        try Data(("prefix_rule(pattern=[\"csec\", \"ai\"], decision=\"allow\")\n"
            + "prefix_rule(pattern=[\"csec\", \"ai\", \"--\", \"npm\", \"test\"], decision=\"allow\")\n"
            + "prefix_rule(pattern=[[\"csec\", \"git\"], \"exec\"], decision=\"allow\")\n").utf8)
            .write(to: codexHome.appendingPathComponent("rules/default.rules"))
        let codexRules = CodingAgentHookStatus.codexUniversalAllowRules(
            homeDirectory: home.path, codexHome: codexHome.path, workingDirectory: nil,
            systemDirectory: root.appendingPathComponent("no-system").path)
        check(codexRules.map(\.rule) == [#"prefix_rule(["csec", "ai"], allow)"#, #"prefix_rule([csec|git], "exec"], allow)"#]
              || codexRules.map(\.rule) == [#"prefix_rule(["csec", "ai"], allow)"#, #"prefix_rule([[csec|git], "exec"], allow)"#],
              "doctor finds Codex allow rules that pre-approve every csec-wrapped command, alternatives included")

        // A malformed autoMode block never hides an installed hook.
        let installed = try CodingAgentSetup.planClaudeAutoModeEnvironment(basedOn: try CodingAgentSetup.plan(
            detection: CodingAgentDetection(client: .claude, executablePath: nil,
                                            configurationPath: settings.path, configurationExists: true),
            csecExecutablePath: csecPath))
        try? fm.removeItem(at: settings)
        try CodingAgentSetup.apply(try CodingAgentSetup.planClaudeAutoModeEnvironment(basedOn: try CodingAgentSetup.plan(
            detection: CodingAgentDetection(client: .claude, executablePath: nil,
                                            configurationPath: settings.path, configurationExists: false),
            csecExecutablePath: csecPath)))
        _ = installed
        var malformed = try JSONSerialization.jsonObject(with: Data(contentsOf: settings)) as! [String: Any]
        malformed["autoMode"] = ["environment": [1, 2]]
        try write(malformed)
        check(state() == .installed(autoModeContext: false),
              "an installed hook with a malformed autoMode block reports missing context, not unreadable")
    } catch {
        check(false, "coding-agent hook status tests completed (\(error))")
    }

    codexSystemHookTests()
    completeUninstallTests()
}

/// csec's Codex hook in Codex's managed System layer. Temporary files stand in
/// for /etc/codex (root ownership is checked separately in production).
private func codexSystemHookTests() {
    print("\n# Codex managed hook document")
    do {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("csec-codex-system-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        let system = root.appendingPathComponent("etc-codex")
        try fm.createDirectory(at: system, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o755])
        defer { try? fm.removeItem(at: root) }
        let hooksFile = system.appendingPathComponent("hooks.json")
        let csecPath = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
        let generated = try AICommandHook.hookConfiguration(client: .codex, csecExecutablePath: csecPath)
        func state() -> CodexSystemHookState {
            CodingAgentSetup.codexSystemHookState(
                csecExecutablePath: csecPath, path: hooksFile.path, requireRootOwnership: false)
        }
        func install(_ data: Data, mode: Int = 0o644) throws {
            try data.write(to: hooksFile)
            try fm.setAttributes([.posixPermissions: mode], ofItemAtPath: hooksFile.path)
        }

        check(try CodingAgentSetup.codexSystemHookDocument(existing: nil, csecExecutablePath: csecPath)
              == generated,
              "with no existing file the managed Codex document is exactly the generated hook configuration")
        check(state() == .missing, "an absent managed hooks file reports missing")
        try codexDetectionForDoctorTests(root: root.appendingPathComponent("detection"))
        try install(generated)
        check(state() == .installed, "the generated document reports installed")
        check(try CodingAgentSetup.codexSystemHookDocument(existing: generated, csecExecutablePath: csecPath)
              == generated,
              "regenerating over the installed document is byte-identical, so payload verification holds")

        // An administrator's own hook survives; an older csec handler is replaced.
        let foreign: [String: Any] = [
            "hooks": ["PreToolUse": [
                ["matcher": "Bash", "hooks": [["type": "command", "command": "/usr/local/bin/org-audit"]]],
                ["matcher": "Bash", "hooks": [["type": "command", "command": "'/old/csec' hook codex",
                                               "timeout": 5, "statusMessage": AICommandHook.managedStatusMessage]]],
            ]],
            "org": ["policy": "keep"],
        ]
        let foreignData = try JSONSerialization.data(withJSONObject: foreign)
        try install(foreignData)
        check(state() == .stale, "an older csec handler in the managed file reports stale")
        let merged = try CodingAgentSetup.codexSystemHookDocument(
            existing: foreignData, csecExecutablePath: csecPath, path: hooksFile.path)
        let mergedObject = try JSONSerialization.jsonObject(with: merged) as? [String: Any]
        let mergedGroups = (mergedObject?["hooks"] as? [String: Any])?["PreToolUse"] as? [[String: Any]]
        let commands = mergedGroups?.compactMap {
            (($0["hooks"] as? [[String: Any]])?.first?["command"] as? String)
        } ?? []
        check((mergedObject?["org"] as? [String: Any])?["policy"] as? String == "keep"
              && commands.count == 2 && commands[0] == "/usr/local/bin/org-audit"
              && !commands.contains("'/old/csec' hook codex"),
              "merging keeps other managed hooks and keys and replaces only the older csec handler")
        try install(merged)
        let regenerated = try CodingAgentSetup.codexSystemHookDocument(
            existing: merged, csecExecutablePath: csecPath, path: hooksFile.path)
        check(state() == .installed && regenerated == merged,
              "the merged document reports installed and regenerates byte-identically")

        try install(generated, mode: 0o666)
        check(state() == .unsafe, "a group- or world-writable managed hooks file reports unsafe")
        try install(Data("{not json".utf8))
        check(state() == .unreadable, "an invalid managed hooks file reports unreadable")

        // The user-level copy is removed once the managed hook covers Codex.
        let userHooks = root.appendingPathComponent("home/.codex/hooks.json")
        try fm.createDirectory(at: userHooks.deletingLastPathComponent(), withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        let detection = CodingAgentDetection(
            client: .codex, executablePath: nil, configurationPath: userHooks.path, configurationExists: true)
        check(try CodingAgentSetup.planCodexUserHookRemoval(detection: detection).action == .unchanged,
              "no user-level hooks file means nothing to remove")
        try generated.write(to: userHooks)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: userHooks.path)
        let removal = try CodingAgentSetup.planCodexUserHookRemoval(detection: detection)
        check(removal.action == .merge, "a user-level csec hook is planned for removal")
        try CodingAgentSetup.apply(removal)
        let emptied = try JSONSerialization.jsonObject(with: Data(contentsOf: userHooks)) as? [String: Any]
        check(emptied?.isEmpty == true,
              "removing csec's only user-level hook leaves an empty document, description included")
        var userWithOther = try JSONSerialization.jsonObject(with: generated) as! [String: Any]
        var otherHooks = userWithOther["hooks"] as! [String: Any]
        var otherGroups = otherHooks["PreToolUse"] as! [[String: Any]]
        otherGroups.insert(["matcher": "Write", "hooks": [["type": "command", "command": "true"]]], at: 0)
        otherHooks["PreToolUse"] = otherGroups
        userWithOther["hooks"] = otherHooks
        try JSONSerialization.data(withJSONObject: userWithOther).write(to: userHooks)
        try CodingAgentSetup.apply(try CodingAgentSetup.planCodexUserHookRemoval(detection: detection))
        let remaining = try JSONSerialization.jsonObject(with: Data(contentsOf: userHooks)) as? [String: Any]
        let remainingGroups = (remaining?["hooks"] as? [String: Any])?["PreToolUse"] as? [[String: Any]]
        let repeatRemoval = try CodingAgentSetup.planCodexUserHookRemoval(detection: detection)
        check(remainingGroups?.count == 1 && remainingGroups?.first?["matcher"] as? String == "Write"
              && remaining?["description"] == nil && repeatRemoval.action == .unchanged,
              "removal keeps other hooks, removes csec's description, and is idempotent")
        var leftover = remaining!
        leftover["description"] = AICommandHook.codexConfigurationDescription
        try JSONSerialization.data(withJSONObject: leftover).write(to: userHooks)
        try CodingAgentSetup.apply(try CodingAgentSetup.planCodexUserHookRemoval(detection: detection))
        let recovered = try JSONSerialization.jsonObject(with: Data(contentsOf: userHooks)) as! [String: Any]
        check(recovered["description"] == nil && recovered["hooks"] != nil,
              "a stale csec description is removed even after its handler is already gone")
        userWithOther["description"] = "My user hook collection"
        try JSONSerialization.data(withJSONObject: userWithOther).write(to: userHooks)
        try CodingAgentSetup.apply(try CodingAgentSetup.planCodexUserHookRemoval(detection: detection))
        let customDescription = try JSONSerialization.jsonObject(with: Data(contentsOf: userHooks)) as! [String: Any]
        check(customDescription["description"] as? String == "My user hook collection",
              "removing a csec handler preserves a user-owned description")
    } catch {
        check(false, "Codex managed hook tests completed (\(error))")
    }
}

/// A Mac without Codex has no use for the managed Codex hook, so `csec doctor`
/// reports its absence without failing; every other defect still fails.
private func codexDetectionForDoctorTests(root: URL) throws {
    let fm = FileManager.default
    let home = root.appendingPathComponent("home")
    let bin = root.appendingPathComponent("bin")
    try fm.createDirectory(at: home, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try fm.createDirectory(at: bin, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
    func detected(path: String = "", codexHome: String? = nil) -> Bool {
        CodingAgentHookStatus.codexDetected(
            homeDirectory: home.path, pathEnvironment: path, codexHome: codexHome,
            standardDirectories: { _ in [] })
    }

    check(!detected(), "no Codex executable or configuration reports Codex as not detected")
    check(!CodingAgentHookStatus.codexSystemHookFailsDoctor(.missing, codexDetected: false),
          "a missing managed Codex hook does not fail doctor when Codex is not installed")
    let absentRows = CodingAgentHookStatus.codexRows(
        state: .missing, codexDetected: false, userHook: .absent, developmentEndpoint: false)
    check(absentRows.count == 1 && absentRows[0].state == .neutral
          && absentRows[0].value.contains("Codex is not installed")
          && !absentRows[0].value.contains("csec setup"),
          "doctor reports the hook as not needed, with no repair, when Codex is not installed")

    for state in [CodexSystemHookState.stale, .unsafe, .unreadable] {
        check(CodingAgentHookStatus.codexSystemHookFailsDoctor(state, codexDetected: false),
              "a managed Codex hook that is \(state.rawValue) fails doctor even when Codex is not installed")
    }
    check(CodingAgentHookStatus.codexSystemHookFailsDoctor(.missing, codexDetected: true),
          "a missing managed Codex hook fails doctor when Codex is installed")
    let missingRows = CodingAgentHookStatus.codexRows(
        state: .missing, codexDetected: true, userHook: .absent, developmentEndpoint: false)
    check(missingRows.first?.state == .bad && missingRows.first?.value.contains("csec setup") == true,
          "a missing hook with Codex installed points to setup")
    check(!CodingAgentHookStatus.codexSystemHookFailsDoctor(.installed, codexDetected: true)
          && !CodingAgentHookStatus.codexSystemHookFailsDoctor(nil, codexDetected: true),
          "an installed or unchecked managed Codex hook does not fail doctor")

    let executable = bin.appendingPathComponent("codex")
    try Data("#!/bin/sh\n".utf8).write(to: executable)
    try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: executable.path)
    check(detected(path: bin.path), "a codex executable on PATH reports Codex as detected")
    check(CodingAgentHookStatus.codexDetected(
        homeDirectory: home.path, pathEnvironment: "", codexHome: nil,
        standardDirectories: { $0 == .codex ? [bin.path] : [] }),
          "a codex executable in a standard install directory reports Codex as detected")

    let codexHome = root.appendingPathComponent("codex-home")
    try fm.createDirectory(at: codexHome, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    check(!detected(codexHome: codexHome.path), "an empty CODEX_HOME alone does not report Codex as detected")
    try Data("model = \"x\"\n".utf8).write(to: codexHome.appendingPathComponent("config.toml"))
    check(detected(codexHome: codexHome.path), "a config.toml in CODEX_HOME reports Codex as detected")

    let userCodex = home.appendingPathComponent(".codex")
    try fm.createDirectory(at: userCodex, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try Data("model = \"x\"\n".utf8).write(to: userCodex.appendingPathComponent("config.toml"))
    check(detected(), "a ~/.codex/config.toml reports Codex as detected")

    check(CodingAgentHookStatus.codexDetected(
        homeDirectory: root.appendingPathComponent("no-such-home").path, pathEnvironment: "", codexHome: nil,
        standardDirectories: { _ in [] }),
          "when detection cannot run, Codex counts as detected so a missing hook still fails doctor")
}
