import Foundation
import ConvenientSecurity
import Darwin

/// `csec uninstall --all`: the managed Codex hook's removal, the user-level
/// hook removal, and the checks before sudo runs the package's uninstaller.
/// Synthetic files in a temporary directory only.
func completeUninstallTests() {
    print("\n# Complete uninstall")
    let fm = FileManager.default
    let created = fm.temporaryDirectory.appendingPathComponent("csec-complete-uninstall-\(UUID().uuidString)")
    defer { try? fm.removeItem(at: created) }
    do {
        try fm.createDirectory(at: created, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        // realpath, not resolvingSymlinksInPath: Foundation maps /private/var
        // back to /var, a symlink, which the uninstaller check rightly refuses.
        guard let real = realpath(created.path, nil) else {
            check(false, "complete uninstall tests: the temporary directory resolves")
            return
        }
        let root = URL(fileURLWithPath: String(cString: real), isDirectory: true)
        free(real)
        try codexSystemHookRemovalTests(root: root)
        try claudeUserHookRemovalTests(root: root)
        try uninstallerChecksTests(root: root)
        try updateCacheRemovalTests(root: root)
    } catch {
        check(false, "complete uninstall tests completed (\(error))")
    }
}

private func codexSystemHookRemovalTests(root: URL) throws {
    let csecPath = CodingAgentSetup.installedLauncherPath
    let generated = try AICommandHook.hookConfiguration(client: .codex, csecExecutablePath: csecPath)
    check(try CodingAgentSetup.codexSystemHookRemoval(existing: generated) == nil,
          "codex system removal: a file holding only csec's hook is deleted, description and all")

    // An administrator's hook beside csec's, in csec's group and its own.
    let foreignHandler: [String: Any] = ["type": "command", "command": "/usr/local/bin/org-audit"]
    let mixed: [String: Any] = [
        "description": AICommandHook.codexConfigurationDescription,
        "org": ["policy": "keep"],
        "hooks": [
            "PreToolUse": [
                ["matcher": "Write", "hooks": [foreignHandler]],
                ["matcher": "Bash", "hooks": [
                    ["type": "command", "command": "'/old/csec' hook codex", "timeout": 5,
                     "statusMessage": AICommandHook.managedStatusMessage],
                ]],
            ],
            "PostToolUse": [["matcher": "Bash", "hooks": [foreignHandler]]],
        ],
    ]
    let mixedData = try JSONSerialization.data(withJSONObject: mixed)
    let merged = try CodingAgentSetup.codexSystemHookDocument(existing: mixedData, csecExecutablePath: csecPath)
    guard let remaining = try CodingAgentSetup.codexSystemHookRemoval(existing: merged),
          let object = try JSONSerialization.jsonObject(with: remaining) as? [String: Any],
          let hooks = object["hooks"] as? [String: Any] else {
        check(false, "codex system removal: a file with other hooks keeps a document")
        return
    }
    let pre = hooks["PreToolUse"] as? [[String: Any]] ?? []
    check(pre.count == 1 && pre.first?["matcher"] as? String == "Write"
          && (hooks["PostToolUse"] as? [[String: Any]])?.count == 1
          && (object["org"] as? [String: Any])?["policy"] as? String == "keep"
          && object["description"] == nil,
          "codex system removal: every csec handler (current and older) and csec's description go; "
            + "other hooks, events and keys stay")
    check(try CodingAgentSetup.codexSystemHookRemoval(existing: remaining) == remaining,
          "codex system removal: a file with nothing of csec's comes back byte for byte")

    let custom = try JSONSerialization.data(withJSONObject: [
        "description": "Org hooks",
        "hooks": ["PreToolUse": [["matcher": "Bash", "hooks": [["type": "command", "command": "true"]]]]],
    ] as [String: Any])
    check(try CodingAgentSetup.codexSystemHookRemoval(existing: custom) == custom,
          "codex system removal: an administrator's own description is not csec's")
    var refused = false
    do { _ = try CodingAgentSetup.codexSystemHookRemoval(existing: Data("{not json".utf8)) } catch { refused = true }
    check(refused, "codex system removal: an invalid document is refused, never rewritten")

    // The file reader: absent, delete, rewrite, unchanged (ownership is the
    // only thing this account cannot reproduce, so an owned file is refused).
    let system = root.appendingPathComponent("etc-codex")
    try FileManager.default.createDirectory(at: system, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o755])
    let path = system.appendingPathComponent("hooks.json").path
    check(try CodingAgentSetup.codexSystemHookRemoval(path: path) == .absent,
          "codex system removal: no file reads as absent")
    try generated.write(to: URL(fileURLWithPath: path))
    var unsafe = false
    do { _ = try CodingAgentSetup.codexSystemHookRemoval(path: path) } catch { unsafe = true }
    check(unsafe, "codex system removal: a hooks file root does not own is refused")
}

private func claudeUserHookRemovalTests(root: URL) throws {
    let fm = FileManager.default
    let claudeDirectory = root.appendingPathComponent("home/.claude")
    try fm.createDirectory(at: claudeDirectory, withIntermediateDirectories: true,
                           attributes: [.posixPermissions: 0o700])
    let settings = claudeDirectory.appendingPathComponent("settings.json")
    let detection = CodingAgentDetection(
        client: .claude, executablePath: nil, configurationPath: settings.path, configurationExists: false)
    check(try CodingAgentSetup.planUserHookRemoval(detection: detection).action == .unchanged,
          "claude hook removal: no settings file means nothing to remove")

    let hook = try JSONSerialization.jsonObject(with: try AICommandHook.hookConfiguration(
        client: .claude, csecExecutablePath: CodingAgentSetup.installedLauncherPath)) as! [String: Any]
    let csecGroup = ((hook["hooks"] as! [String: Any])["PreToolUse"] as! [[String: Any]])[0]
    let legacyHandler: [String: Any] = [
        "type": "command", "command": "/Applications/ConvenientSecurity.app/Contents/MacOS/csec",
        "args": ["hook", "claude"],
    ]
    let userHandler: [String: Any] = ["type": "command", "command": "/usr/local/bin/lint-guard"]
    let original: [String: Any] = [
        "model": "opus",
        "permissions": ["allow": ["Bash(ls:*)"]],
        "hooks": [
            "PreToolUse": [
                csecGroup,
                ["matcher": "Bash", "hooks": [legacyHandler, userHandler]],
            ],
            "Stop": [["hooks": [userHandler]]],
        ],
    ]
    try JSONSerialization.data(withJSONObject: original).write(to: settings)
    try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: settings.path)
    let plan = try CodingAgentSetup.planUserHookRemoval(detection: detection)
    check(plan.action == .merge, "claude hook removal: csec's handlers are planned for removal")
    try CodingAgentSetup.apply(plan)
    let after = try JSONSerialization.jsonObject(with: Data(contentsOf: settings)) as! [String: Any]
    let hooks = after["hooks"] as? [String: Any] ?? [:]
    let pre = hooks["PreToolUse"] as? [[String: Any]] ?? []
    check(pre.count == 1 && (pre[0]["hooks"] as? [[String: Any]])?.count == 1
          && (pre[0]["hooks"] as? [[String: Any]])?.first?["command"] as? String == "/usr/local/bin/lint-guard"
          && hooks["Stop"] != nil && after["model"] as? String == "opus" && after["permissions"] != nil,
          "claude hook removal: the current and the older csec handler go, every other hook and setting stays")
    check(try CodingAgentSetup.planUserHookRemoval(detection: detection).action == .unchanged,
          "claude hook removal: a second run has nothing to remove")

    try JSONSerialization.data(withJSONObject: ["hooks": ["PreToolUse": [csecGroup]], "model": "opus"] as [String: Any])
        .write(to: settings)
    try CodingAgentSetup.apply(try CodingAgentSetup.planUserHookRemoval(detection: detection))
    let emptied = try JSONSerialization.jsonObject(with: Data(contentsOf: settings)) as! [String: Any]
    check(emptied["hooks"] == nil && emptied["model"] as? String == "opus" && fm.fileExists(atPath: settings.path),
          "claude hook removal: an emptied hooks block goes, the settings file stays")

    try fm.setAttributes([.posixPermissions: 0o666], ofItemAtPath: settings.path)
    var refused = false
    do { _ = try CodingAgentSetup.planUserHookRemoval(detection: detection) } catch { refused = true }
    check(refused, "claude hook removal: a settings file others can write is refused")
}

private func uninstallerChecksTests(root: URL) throws {
    let fm = FileManager.default
    let owner = getuid()
    let libexec = root.appendingPathComponent("support/libexec")
    try fm.createDirectory(at: libexec, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
    try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: libexec.deletingLastPathComponent().path)
    let script = libexec.appendingPathComponent("uninstall-csec.sh")
    let bundled = root.appendingPathComponent("bundled-uninstall-csec.sh")

    check(CompleteUninstall.scriptProblem(path: script.path, owner: owner)?.contains("missing") == true,
          "uninstaller check: a missing script is named as missing")
    try Data("#!/bin/bash\n".utf8).write(to: script)
    try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)
    check(CompleteUninstall.scriptProblem(path: script.path, owner: owner) == nil,
          "uninstaller check: a protected regular file under protected directories may run")
    check(CompleteUninstall.scriptProblem(path: script.path) != nil,
          "uninstaller check: in production only root may own it")
    try fm.setAttributes([.posixPermissions: 0o775], ofItemAtPath: script.path)
    check(CompleteUninstall.scriptProblem(path: script.path, owner: owner)?.contains("other users") == true,
          "uninstaller check: a group-writable script is refused")
    try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: script.path)
    try fm.setAttributes([.posixPermissions: 0o777], ofItemAtPath: libexec.path)
    check(CompleteUninstall.scriptProblem(path: script.path, owner: owner)?.contains(libexec.path) == true,
          "uninstaller check: a writable directory above it is refused")
    try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: libexec.path)
    let link = libexec.appendingPathComponent("linked.sh")
    try fm.createSymbolicLink(at: link, withDestinationURL: script)
    check(CompleteUninstall.scriptProblem(path: link.path, owner: owner) != nil,
          "uninstaller check: a symlink is refused")

    check(CompleteUninstall.installedState(path: script.path, bundledCopy: bundled.path, owner: owner)
          != .installed, "uninstaller status: an unreadable app copy is not healthy")
    try fm.copyItem(at: script, to: bundled)
    check(CompleteUninstall.installedState(path: script.path, bundledCopy: bundled.path, owner: owner)
          == .installed, "uninstaller status: the copy the app shipped is installed")
    try Data("#!/bin/bash\necho changed\n".utf8).write(to: bundled)
    check(CompleteUninstall.installedState(path: script.path, bundledCopy: bundled.path, owner: owner)
          == .stale, "uninstaller status: a copy that differs from the app's is stale")
    check(CompleteUninstall.keptAfterCompleteUninstall.contains { $0.contains(CsecdUninstaller.keptSummary) },
          "uninstaller summary: the closing list names the secrets csecd's cleanup keeps")
}

private func updateCacheRemovalTests(root: URL) throws {
    let fm = FileManager.default
    let parent = root.appendingPathComponent("home/Library/Application Support/ConvenientSecurity")
    let updates = parent.appendingPathComponent("Updates")
    check(try CompleteUninstall.removeUpdateCache(directory: updates) == false,
          "update cache removal: nothing to remove is not an error")

    try fm.createDirectory(at: updates, withIntermediateDirectories: true)
    for name in ["manifest.json", "manifest.json.sig", "state.json"] {
        try Data("{}".utf8).write(to: updates.appendingPathComponent(name))
    }
    check(try CompleteUninstall.removeUpdateCache(directory: updates) == true
          && !fm.fileExists(atPath: updates.path) && !fm.fileExists(atPath: parent.path),
          "update cache removal: the cache goes, and its parent with it once empty")

    try fm.createDirectory(at: updates, withIntermediateDirectories: true)
    let other = parent.appendingPathComponent("someone-elses.txt")
    try Data("keep".utf8).write(to: other)
    check(try CompleteUninstall.removeUpdateCache(directory: updates) == true
          && !fm.fileExists(atPath: updates.path) && fm.fileExists(atPath: other.path),
          "update cache removal: a parent holding anything else stays")

    let elsewhere = root.appendingPathComponent("elsewhere")
    try fm.createDirectory(at: elsewhere, withIntermediateDirectories: true)
    let kept = elsewhere.appendingPathComponent("kept.txt")
    try Data("keep".utf8).write(to: kept)
    try fm.createSymbolicLink(at: updates, withDestinationURL: elsewhere)
    var refused = false
    do { _ = try CompleteUninstall.removeUpdateCache(directory: updates) } catch { refused = true }
    check(refused && fm.fileExists(atPath: kept.path),
          "update cache removal: a symlinked cache is refused and what it points at stays")
}
