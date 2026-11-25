import Foundation
import ConvenientSecurity
import Darwin

/// csec's `autoMode.environment` entry in Claude Code's user settings. Synthetic
/// configuration files only.
func claudeAutoModeSetupTests() {
    print("\n# Claude Code auto-mode context setup")
    do {
        let fm = FileManager.default
        let temporaryDirectory = ProcessInfo.processInfo.environment["CSEC_SETUP_TEST_DIRECTORY"]
            .map { URL(fileURLWithPath: $0, isDirectory: true) } ?? fm.temporaryDirectory
        let home = temporaryDirectory.appendingPathComponent("csec-claude-automode-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        try fm.createDirectory(at: home, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: home) }
        let settingsDirectory = home.appendingPathComponent(".claude")
        let settings = settingsDirectory.appendingPathComponent("settings.json")
        let detection = CodingAgentDetection(
            client: .claude, executablePath: nil, configurationPath: settings.path,
            configurationExists: false)
        let csecPath = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
        let entry = CodingAgentSetup.claudeAutoModeEnvironmentEntry

        func composedPlan() throws -> CodingAgentConfigurationPlan {
            try CodingAgentSetup.planClaudeAutoModeEnvironment(
                basedOn: try CodingAgentSetup.plan(detection: detection, csecExecutablePath: csecPath))
        }
        func settingsObject() throws -> [String: Any] {
            try JSONSerialization.jsonObject(with: Data(contentsOf: settings)) as? [String: Any] ?? [:]
        }
        func environment() throws -> [String]? {
            (try settingsObject()["autoMode"] as? [String: Any])?["environment"] as? [String]
        }
        func writeSettings(_ text: String) throws {
            try fm.createDirectory(at: settingsDirectory, withIntermediateDirectories: true,
                                   attributes: [.posixPermissions: 0o700])
            try Data(text.utf8).write(to: settings)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: settings.path)
        }

        // A fresh settings file gets the hook and a new list that keeps Claude
        // Code's built-in entries, in one atomic create.
        let create = try composedPlan()
        check(create.action == .create && create.preview == entry,
              "a fresh Claude setup plans the hook and csec's auto-mode entry as one create")
        try CodingAgentSetup.apply(create)
        let hooks = (try settingsObject()["hooks"] as? [String: Any])?["PreToolUse"] as? [[String: Any]]
        check(try environment() == ["$defaults", entry] && hooks?.count == 1,
              "a new autoMode.environment list starts with $defaults so built-in entries stay in effect")
        check(try composedPlan().action == .unchanged,
              "repeated Claude setup with the current entry is idempotent")

        // An installed exact hook with no autoMode block: the hook plan alone is
        // unchanged, but the composed plan still adds the entry as a merge.
        let hookOnly = String(decoding: try AICommandHook.hookConfiguration(
            client: .claude, csecExecutablePath: csecPath), as: UTF8.self)
        try writeSettings(hookOnly)
        let hookOnlyPlan = try CodingAgentSetup.plan(detection: detection, csecExecutablePath: csecPath)
        let addEntry = try CodingAgentSetup.planClaudeAutoModeEnvironment(basedOn: hookOnlyPlan)
        check(hookOnlyPlan.action == .unchanged && addEntry.action == .merge,
              "an existing exact hook still gains the auto-mode entry through a merge plan")
        try CodingAgentSetup.apply(addEntry)
        check(try environment() == ["$defaults", entry],
              "merging the entry into an existing settings file preserves the hook")

        // A user who owns the whole list (no $defaults) keeps that choice.
        var owned = try settingsObject()
        owned["autoMode"] = ["environment": ["**Organization**: Example Ltd"], "allow": ["$defaults", "x"]]
        owned["theme"] = "dark"
        try writeSettings(String(decoding: try JSONSerialization.data(withJSONObject: owned), as: UTF8.self))
        try CodingAgentSetup.apply(try composedPlan())
        let ownedAfter = try settingsObject()
        check(try environment() == ["**Organization**: Example Ltd", entry]
              && (ownedAfter["autoMode"] as? [String: Any])?["allow"] as? [String] == ["$defaults", "x"]
              && ownedAfter["theme"] as? String == "dark",
              "a user list without $defaults is extended, not given $defaults, and other settings survive")

        // An older csec entry is refreshed in place and duplicates collapse.
        var stale = try settingsObject()
        let olderEntry = "**Secrets management**: Convenient Security (`csec`) — an older wording."
        stale["autoMode"] = ["environment": ["$defaults", olderEntry, "**Organization**: Example Ltd", olderEntry]]
        try writeSettings(String(decoding: try JSONSerialization.data(withJSONObject: stale), as: UTF8.self))
        let refresh = try composedPlan()
        check(refresh.action == .merge && refresh.detail.contains("refresh"),
              "an older csec auto-mode entry is planned as a refresh")
        try CodingAgentSetup.apply(refresh)
        check(try environment() == ["$defaults", entry, "**Organization**: Example Ltd"],
              "the refreshed entry keeps its position and duplicate csec entries are removed")

        // Delegated approvals swap csec's entry for its delegation-aware
        // variant in place; refreshing the hook treats either as current, and
        // only an explicit request swaps it back.
        var delegated = try settingsObject()
        let delegationEntry = CodingAgentSetup.ClaudeAutoModeEntry.delegationAware.text
        delegated["autoMode"] = ["environment": ["$defaults", delegationEntry, "**Organization**: Example Ltd"]]
        try writeSettings(String(decoding: try JSONSerialization.data(withJSONObject: delegated), as: UTF8.self))
        let keep = try composedPlan()
        let hookPlan = try CodingAgentSetup.plan(detection: detection, csecExecutablePath: csecPath)
        let swapBack = try CodingAgentSetup.planClaudeAutoModeEnvironment(basedOn: hookPlan, entry: .standard)
        check(keep.action == .unchanged && swapBack.action == .merge && swapBack.preview == entry,
              "the delegation-aware entry counts as current; only an explicit standard request replaces it")
        try CodingAgentSetup.apply(swapBack)
        check(try environment() == ["$defaults", entry, "**Organization**: Example Ltd"]
              && CodingAgentSetup.claudeAutoModeEntry(inSettingsAt: settings.path) == .standard,
              "swapping the entry back keeps its position and the user's other entries")
        let revertOnly = try CodingAgentSetup.planClaudeAutoModeEnvironmentRevert(
            basedOn: try CodingAgentSetup.plan(detection: detection, csecExecutablePath: csecPath))
        check(revertOnly.action == .unchanged,
              "restoring the standard entry changes nothing when it is already there")
        var noEntry = try settingsObject()
        noEntry["autoMode"] = ["environment": ["$defaults"]]
        try writeSettings(String(decoding: try JSONSerialization.data(withJSONObject: noEntry), as: UTF8.self))
        check(try CodingAgentSetup.planClaudeAutoModeEnvironmentRevert(basedOn: try CodingAgentSetup.plan(
                detection: detection, csecExecutablePath: csecPath)).action == .unchanged
              && CodingAgentSetup.claudeAutoModeEntry(inSettingsAt: settings.path) == nil,
              "restoring the standard entry never adds one where csec has none")

        // A malformed autoMode block is never overwritten.
        var malformed = try settingsObject()
        malformed["autoMode"] = ["environment": "not a list"]
        try writeSettings(String(decoding: try JSONSerialization.data(withJSONObject: malformed), as: UTF8.self))
        checkThrows("a non-list autoMode.environment is refused rather than replaced") {
            _ = try composedPlan()
        }

        checkThrows("the auto-mode entry is refused for Codex") {
            let codexHooks = home.appendingPathComponent(".codex/hooks.json")
            let codexDetection = CodingAgentDetection(
                client: .codex, executablePath: nil, configurationPath: codexHooks.path,
                configurationExists: false)
            _ = try CodingAgentSetup.planClaudeAutoModeEnvironment(
                basedOn: try CodingAgentSetup.plan(detection: codexDetection, csecExecutablePath: csecPath))
        }
    } catch {
        check(false, "Claude auto-mode setup tests completed (\(error))")
    }
}
