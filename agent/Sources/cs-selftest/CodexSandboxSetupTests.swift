import Foundation
import ConvenientSecurity
import Darwin

/// Synthetic configuration files only. Can run independently of provider, host
/// audit, and bulk-protection tests with --codex-sandbox-only.
func codexSandboxSetupTests() {
    print("\n# Codex sandbox setup")
    do {
        let fm = FileManager.default
        let temporaryDirectory = ProcessInfo.processInfo.environment["CSEC_SETUP_TEST_DIRECTORY"]
            .map { URL(fileURLWithPath: $0, isDirectory: true) } ?? fm.temporaryDirectory
        let home = temporaryDirectory.appendingPathComponent("csec-codex-setup-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        try fm.createDirectory(at: home, withIntermediateDirectories: false,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: home) }
        let configDirectory = home.appendingPathComponent(".codex")
        let config = configDirectory.appendingPathComponent("config.toml")
        let hooks = configDirectory.appendingPathComponent("hooks.json")
        let detection = CodingAgentDetection(
            client: .codex, executablePath: nil, configurationPath: hooks.path,
            configurationExists: false)
        let firstSocket = home.appendingPathComponent("first-user/agent.sock").path
        let secondSocket = home.appendingPathComponent("second-user/agent.sock").path
        func merge(_ text: String, socket: String? = nil) throws -> String {
            String(decoding: try CodexSandboxConfiguration.merge(
                Data(text.utf8), socketPath: socket ?? firstSocket).data, as: UTF8.self)
        }

        let create = try CodingAgentSetup.planCodexSandbox(detection: detection, socketPath: firstSocket)
        check(create.action == .create && !fm.fileExists(atPath: config.path),
              "Codex socket planning creates no files")
        try CodingAgentSetup.apply(create)
        let created = try String(contentsOf: config, encoding: .utf8)
        check(created.contains(firstSocket) && !created.contains(secondSocket)
              && created.contains(":workspace") && created.contains("network_proxy")
              && created.contains("unix_sockets"),
              "setup derives the current socket and inherits Codex workspace restrictions")
        let fileMode = try fm.attributesOfItem(atPath: config.path)[.posixPermissions] as? NSNumber
        let directoryMode = try fm.attributesOfItem(atPath: configDirectory.path)[.posixPermissions] as? NSNumber
        check(fileMode?.intValue == 0o600 && directoryMode?.intValue == 0o700,
              "socket configuration and parent directory are created privately")
        let repeatPlan = try CodingAgentSetup.planCodexSandbox(detection: detection, socketPath: firstSocket)
        check(repeatPlan.action == .unchanged, "repeated Codex sandbox setup is idempotent")
        let otherUser = try merge("", socket: secondSocket)
        check(otherUser.contains(secondSocket) && !otherUser.contains(firstSocket),
              "another user's generated profile contains only that user's socket")
        let movedSocket = try merge(created, socket: secondSocket)
        check(movedSocket.contains(secondSocket), "rerunning setup discovers a changed socket location")

        // Old setup allocated -2 whenever Codex selected a built-in again,
        // even when its unchanged, unreferenced generated profile remained.
        let unselected = created.replacingOccurrences(of: "\"default_permissions\" = \"csec-workspace\"",
                                                      with: "\"default_permissions\" = \":workspace\"")
        let reused = try merge(unselected)
        check(reused == created && !reused.contains("csec-workspace-2"),
              "setup reuses its unreferenced generated profile instead of allocating a suffix")
        let duplicate = unselected.replacingOccurrences(of: "csec-workspace", with: "csec-workspace-2")
            .components(separatedBy: "\n").filter {
                !$0.contains("\"default_permissions\"") && !$0.contains("\"features\"")
            }.joined(separator: "\n")
        let duplicates = created + "\n# Neighboring comments survive cleanup.\n" + duplicate
        let pruned = try merge(duplicates)
        let repruned = try merge(pruned)
        check(!pruned.contains("csec-workspace-2") && pruned.contains("Neighboring comments")
              && pruned.contains("csec-workspace") && repruned == pruned,
              "setup removes only the unused generated duplicate and converges")
        let custom = duplicates + "\n[permissions.csec-workspace-2.filesystem]\n\"/synthetic/cache\" = \"write\"\n"
        check(try merge(custom).contains("csec-workspace-2"),
              "a customized csec-named profile is never pruned")
        let customCollision = unselected + "\n[permissions.csec-workspace.filesystem]\n\"/synthetic/private\" = \"deny\"\n"
        let preservedCollision = try merge(customCollision)
        check(preservedCollision.contains("csec-workspace-2")
              && preservedCollision.contains("\"/synthetic/private\" = \"deny\""),
              "setup allocates a suffix for a real user customization collision")
        for reference in [
            "[profiles.saved]\npermissions = 'csec-workspace-2'\n",
            "[permissions.child]\nextends = 'csec-workspace-2'\n",
            "[profiles]\nsaved = { permissions = 'csec-workspace-2' }\n",
            "[profiles.saved]\npermissions = \"csec-workspace-\\u0032\"\n",
        ] {
            check(try merge(duplicates + "\n" + reference).contains("csec-workspace-2"),
                  "profiles referenced by named launches or inheritance are preserved")
        }
        let activeCustom = duplicates.replacingOccurrences(of: "\"default_permissions\" = \"csec-workspace\"",
                                                           with: "\"default_permissions\" = \"csec-workspace-2\"")
            + "\n[permissions.csec-workspace-2.filesystem]\n\"/synthetic/cache\" = \"write\"\n"
        let activePruned = try merge(activeCustom)
        check(!activePruned.contains("\"permissions\".\"csec-workspace\".")
              && activePruned.contains("csec-workspace-2") && activePruned.contains("/synthetic/cache"),
              "cleanup keeps the selected customized -2 profile and removes its unused predecessor")

        let existing = #"""
        # Preserve comments and unrelated tool configuration verbatim.
        default_permissions = 'team.prod'
        model = "example-model"
        developer_instructions = """
        [features]
        network_proxy = false
        """
        [features]
        experimental_hooks = true # keep this comment
        [permissions.'team.prod']
        extends = ":read-only"
        [permissions.'team.prod'.filesystem]
        "/private/example" = "deny"
        [permissions.'team.prod'.network]
        enabled = false # activate only the filtered proxy
        [[skills.config]]
        path = "/synthetic/skill-a"
        [[skills.config]]
        path = "/synthetic/skill-b"
        """#
        let updated = try merge(existing)
        check(updated.contains("default_permissions = 'team.prod'")
              && updated.contains("\"/private/example\" = \"deny\"")
              && updated.contains("extends = \":read-only\"")
              && updated.contains("experimental_hooks = true # keep this comment")
              && updated.contains("network_proxy = false\n\"\"\"")
              && updated.contains("enabled = true # activate only the filtered proxy")
              && updated.contains("path = \"/synthetic/skill-b\""),
              "setup preserves the selected profile, deny rules, comments, multiline values, and array tables")
        check(try merge(updated) == updated, "merging an existing table-based profile is idempotent")

        let readonly = try merge("sandbox_mode = 'read-only'\n")
        check(readonly.contains("csec-read-only") && readonly.contains(":read-only")
              && !readonly.contains(":workspace"), "read-only setup does not grant workspace writes")
        let legacy = try merge(#"""
        sandbox_mode = "workspace-write"
        [sandbox_workspace_write]
        exclude_tmpdir_env_var = true
        exclude_slash_tmp = true
        writable_roots = ["/synthetic/extra", '/synthetic/other', "/synthetic/extra"]
        """#)
        check(legacy.contains("\":tmpdir\" = \"read\"")
              && legacy.contains("\":slash_tmp\" = \"read\"")
              && legacy.components(separatedBy: "\"/synthetic/extra\" = \"write\"").count == 2
              && legacy.contains("\"/synthetic/other\" = \"write\""),
              "legacy temp exclusions and repeated writable roots survive profile migration")

        let filtered = #"""
        default_permissions = "child"
        [features]
        network_proxy = true
        [permissions.base]
        extends = ":workspace"
        [permissions.base.network]
        enabled = true
        proxy_url = "http://127.0.0.1:34567"
        [permissions.base.network.domains]
        "example.invalid" = "allow"
        [permissions.base.network.unix_sockets]
        "/synthetic/other.sock" = "allow"
        [permissions.child]
        extends = "base"
        """#
        let filteredMerged = try merge(filtered)
        check(filteredMerged.hasPrefix(filtered)
              && filteredMerged.contains(firstSocket)
              && !filteredMerged.contains("127.0.0.1:0\"\n\"proxy_url"),
              "an active inherited network policy and listener settings are preserved")
        for unsafe in [
            filtered.replacingOccurrences(of: "enabled = true", with: "enabled = false"),
            "features = { network_proxy = false }\n",
            "[features]\nnetwork_proxy=false\nnetwork_proxy=true\n",
            "[features]\nnetwork_proxy=false\n[\"featur\\u0065s\"]\nnetwork_proxy=true\n",
            "default_permissions = 'missing'\n",
            "default_permissions='cycle'\n[permissions.cycle]\nextends='cycle'\n",
            "model = \"unterminated\n",
        ] {
            checkThrows("ambiguous, unsupported, or broader dormant Codex policy is refused") {
                _ = try merge(unsafe)
            }
        }
        let fullAccess = "sandbox_mode = 'danger-full-access'\n"
        check(try merge(fullAccess) == fullAccess,
              "full-access users are not silently switched to a restricted profile")
        let unrestricted = "[sandbox_workspace_write]\nnetwork_access = true\n"
        check(try merge(unrestricted) == unrestricted,
              "already-available unproxied socket access needs no policy change")

        // Reuse the hook writer's mode, link, and concurrent-edit protections.
        try existing.write(to: config, atomically: false, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o640], ofItemAtPath: config.path)
        let edit = try CodingAgentSetup.planCodexSandbox(detection: detection, socketPath: firstSocket)
        try CodingAgentSetup.apply(edit)
        check((try fm.attributesOfItem(atPath: config.path)[.posixPermissions] as? NSNumber)?.intValue == 0o640,
              "Codex TOML updates retain the original file mode")
        let stale = try CodingAgentSetup.planCodexSandbox(detection: detection, socketPath: secondSocket)
        let concurrent = try String(contentsOf: config) + "\n# concurrent edit\n"
        try concurrent.write(to: config, atomically: false, encoding: .utf8)
        checkThrows("a concurrent Codex TOML edit is not overwritten") { try CodingAgentSetup.apply(stale) }
        check(try String(contentsOf: config) == concurrent, "concurrent user data remains intact")

        // Exercise the same file-backed cleanup used after the managed hook
        // migration, including the historical already-removed handler case.
        let stateKey = hooks.path + ":pre_tool_use:0:0"
        let otherState = hooks.path + ":session_start:0:0"
        let staleConfig = activeCustom + "\n[hooks.state.'\(stateKey)']\ntrusted_hash = 'synthetic-csec'\nenabled = true\n"
            + "[hooks.state.'\(otherState)']\ntrusted_hash = 'synthetic-other'\n"
        try staleConfig.write(to: config, atomically: false, encoding: .utf8)
        let legacyHooks: [String: Any] = [
            "description": AICommandHook.codexConfigurationDescription,
            "hooks": ["SessionStart": [["hooks": [["type": "command", "command": "true"]]]]],
        ]
        let originalHooks = try JSONSerialization.data(withJSONObject: legacyHooks, options: [.sortedKeys])
        try originalHooks.write(to: hooks)
        let removal = try CodingAgentSetup.planCodexUserHookRemoval(detection: detection)
        let cleanup = try CodingAgentSetup.planCodexSandbox(
            detection: detection, socketPath: firstSocket, userHookRemoval: removal)
        check(try String(contentsOf: config) == staleConfig && Data(contentsOf: hooks) == originalHooks,
              "planning stale hook/profile cleanup is read-only")
        let configBackup = try CodingAgentSetup.applyWithBackup(cleanup)!
        let hooksBackup = try CodingAgentSetup.applyWithBackup(removal)!
        let cleaned = try String(contentsOf: config)
        check(!cleaned.contains(stateKey) && cleaned.contains(otherState) && cleaned.contains("synthetic-other")
              && cleaned.contains("/synthetic/cache"),
              "cleanup prunes only the superseded csec slot and preserves active permissions and other trust")
        check(try String(contentsOf: URL(fileURLWithPath: configBackup)) == staleConfig
              && Data(contentsOf: URL(fileURLWithPath: hooksBackup)) == originalHooks,
              "private backups retain both exact pre-cleanup documents for revert")
        check((try fm.attributesOfItem(atPath: configBackup)[.posixPermissions] as? NSNumber)?.intValue == 0o600,
              "configuration backups are owner-only even when the original was more readable")
        let reremoval = try CodingAgentSetup.planCodexUserHookRemoval(detection: detection)
        let recleanup = try CodingAgentSetup.planCodexSandbox(
            detection: detection, socketPath: firstSocket, userHookRemoval: reremoval)
        check(reremoval.action == .unchanged && recleanup.action == .unchanged,
              "a completed cleanup is idempotent")
        try Data(contentsOf: URL(fileURLWithPath: configBackup)).write(to: config)
        try Data(contentsOf: URL(fileURLWithPath: hooksBackup)).write(to: hooks)
        check(try String(contentsOf: config) == staleConfig && Data(contentsOf: hooks) == originalHooks
              && (try CodingAgentSetup.planCodexUserHookRemoval(detection: detection)).action == .merge,
              "reverting from both backups restores the prior migration state exactly")
        let withoutEvidence = try CodingAgentSetup.planCodexSandbox(detection: detection, socketPath: firstSocket)
        try CodingAgentSetup.apply(withoutEvidence)
        check(try String(contentsOf: config).contains(stateKey),
              "ordinary socket setup never guesses ownership of absent hook trust state")
        let link = home.appendingPathComponent("config-link")
        try fm.linkItem(at: config, to: link)
        checkThrows("hard-linked Codex settings are refused") {
            _ = try CodingAgentSetup.planCodexSandbox(detection: detection, socketPath: firstSocket)
        }
        try fm.removeItem(at: config)
        try fm.createSymbolicLink(at: config, withDestinationURL: link)
        checkThrows("symlinked Codex settings are refused") {
            _ = try CodingAgentSetup.planCodexSandbox(detection: detection, socketPath: firstSocket)
        }
        try fm.removeItem(at: config)
        try fm.removeItem(at: link)

        let hookPlan = try CodingAgentSetup.plan(detection: detection, csecExecutablePath: "/synthetic/csec")
        try CodingAgentSetup.apply(hookPlan)
        let existingHook = try CodingAgentSetup.plan(detection: detection, csecExecutablePath: "/synthetic/csec")
        let missingSocketConfig = try CodingAgentSetup.planCodexSandbox(detection: detection, socketPath: firstSocket)
        check(existingHook.action == .unchanged && missingSocketConfig.action == .create,
              "an existing csec hook still receives the missing socket setup")
        try CodingAgentSetup.apply(missingSocketConfig)
        try fm.removeItem(at: hooks)
        let discovered = try CodingAgentSetup.detect(homeDirectory: home.path, pathEnvironment: "")
            .first { $0.client == .codex }!
        check(discovered.sandboxConfigurationExists && discovered.detected,
              "Codex config.toml is detected before a hook has been installed")
    } catch {
        check(false, "Codex sandbox setup tests: \(error)")
    }
}
