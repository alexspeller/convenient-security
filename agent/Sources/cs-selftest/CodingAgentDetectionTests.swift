import ConvenientSecurity
import Foundation

/// Setup, doctor and host-audit detection share Claude Code's selected settings
/// path. Every file and environment value here is a synthetic fixture, and no
/// standard install directory is searched (the fake audit contexts search none
/// either), so the agents installed on the host running the tests take no part.
func codingAgentDetectionTests() async {
    print("\n# Coding-agent detection with CLAUDE_CONFIG_DIR")
    do {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("csec-agent-detection-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        let home = root.appendingPathComponent("home")
        let defaultDirectory = home.appendingPathComponent(".claude")
        let customDirectory = root.appendingPathComponent("custom-config")
        let defaultSettings = defaultDirectory.appendingPathComponent("settings.json")
        let customSettings = customDirectory.appendingPathComponent("settings.json")
        try fm.createDirectory(at: defaultDirectory, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        defer { try? fm.removeItem(at: root) }
        let originalDefault = Data(#"{"theme":"dark"}"#.utf8)
        try originalDefault.write(to: defaultSettings)
        try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: defaultSettings.path)

        func detections(_ configDirectory: String? = nil, path: String = "") throws -> [CodingAgentDetection] {
            try CodingAgentSetup.detect(
                homeDirectory: home.path, pathEnvironment: path, claudeConfigDirectory: configDirectory,
                standardDirectories: { _ in [] })
        }
        func claude(_ configDirectory: String? = nil, path: String = "") throws -> CodingAgentDetection {
            try detections(configDirectory, path: path).first { $0.client == .claude }!
        }
        let defaultDetection = try claude()
        check(defaultDetection.configurationPath == defaultSettings.path && defaultDetection.configurationExists,
              "an unset CLAUDE_CONFIG_DIR detects the default Claude settings")
        let missing = try claude(customDirectory.path)
        check(missing.configurationPath == customSettings.path && !missing.configurationExists && !missing.detected,
              "a custom config directory never falls back to an existing default settings file")
        check(try detections().first { $0.client == .codex }?.configurationPath
                == detections(customDirectory.path).first { $0.client == .codex }?.configurationPath,
              "CLAUDE_CONFIG_DIR leaves Codex detection unchanged")

        let bin = root.appendingPathComponent("bin")
        try fm.createDirectory(at: bin, withIntermediateDirectories: false)
        let executable = bin.appendingPathComponent("claude")
        try Data("#!/bin/sh\nexit 19\n".utf8).write(to: executable)
        try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let executableOnly = try claude(customDirectory.path, path: bin.path)
        check(executableOnly.detected && executableOnly.executablePath == executable.path
                && !executableOnly.configurationExists,
              "Claude on PATH is detected even when the selected config directory does not exist")
        let standardOnly = try CodingAgentSetup.detect(
            homeDirectory: home.path, pathEnvironment: "", claudeConfigDirectory: customDirectory.path,
            standardDirectories: { $0 == .claude ? [bin.path] : [] })
        check(standardOnly.first { $0.client == .claude }?.executablePath == executable.path
                && standardOnly.first { $0.client == .codex }?.detected == false,
              "detection searches each client's standard install directories after an empty PATH")

        let csecPath = (StartupSecurityReport.currentAgent().executablePath as NSString)
            .deletingLastPathComponent + "/csec"
        let create = try CodingAgentSetup.planClaudeAutoModeEnvironment(basedOn: CodingAgentSetup.plan(
            detection: executableOnly, csecExecutablePath: csecPath))
        check(create.path == customSettings.path && create.action == .create,
              "hook and auto-mode creation plans target the selected settings file")
        try CodingAgentSetup.apply(create)
        let installed = try claude(customDirectory.path)
        check(installed.detected && installed.configurationExists,
              "existing custom settings detect Claude without an executable on PATH")
        check(try Data(contentsOf: defaultSettings) == originalDefault,
              "applying the custom settings plan preserves the default settings file")
        check(try CodingAgentSetup.plan(detection: installed, csecExecutablePath: csecPath).action == .unchanged,
              "setup is idempotent in the selected configuration directory")
        check(CodingAgentHookStatus.claudeHookState(
            homeDirectory: home.path, pathEnvironment: "", csecExecutablePath: csecPath,
            claudeConfigDirectory: customDirectory.path) == .installed(autoModeContext: true)
                && CodingAgentHookStatus.claudeHookState(
                    homeDirectory: home.path, pathEnvironment: "", csecExecutablePath: csecPath) == .missing,
              "doctor reports the selected hook rather than the default directory's hook")

        let unnormalized = root.path + "/cafe\u{0301}//./discard/../"
        let scope = ClaudeSettingsScope(
            homeDirectory: home.path, claudeConfigDirectory: unnormalized,
            userName: "synthetic", csecExecutablePath: csecPath)
        check(try claude(unnormalized).configurationPath == scope.userSettingsPath
                && scope.userSettingsPath == root.path + "/caf\u{00e9}/settings.json",
              "setup and the settings gate share lexical and Unicode NFC path normalization")

        let files = FakeFileInspector(homeDirectory: home.path)
        let customContext = makeAuditContext(
            files: files, environment: ["PATH": "", "CLAUDE_CONFIG_DIR": customDirectory.path])
        await expectStatus("HA-K01", in: DomainK_Coverage.checks, customContext, .pass,
                           "host audit verifies the hook in CLAUDE_CONFIG_DIR")
        await expectStatus("HA-K01", in: DomainK_Coverage.checks,
                           makeAuditContext(files: files, environment: ["PATH": ""]), .fail,
                           "host audit without an override still detects the missing default hook")
        try Data(#"{"disableAllHooks":true}"#.utf8).write(to: customSettings)
        await expectStatus("HA-K02", in: DomainK_Coverage.checks, customContext, .fail,
                           "host audit checks hook policy in CLAUDE_CONFIG_DIR")

        for value in ["", "relative/config", "~/.claude"] {
            do {
                _ = try claude(value)
                check(false, "setup rejects an empty or relative CLAUDE_CONFIG_DIR")
            } catch SetupOnboardingError.invalidClaudeConfigDirectory {
                check(true, "setup rejects an empty or relative CLAUDE_CONFIG_DIR")
            }
            check(CodingAgentHookStatus.claudeHookState(
                homeDirectory: home.path, pathEnvironment: "", csecExecutablePath: csecPath,
                claudeConfigDirectory: value) == .unreadable,
                  "doctor cannot report the default hook for an unusable override")
            let invalidContext = makeAuditContext(
                files: files, environment: ["PATH": "", "CLAUDE_CONFIG_DIR": value])
            for id in ["HA-K01", "HA-K02"] {
                await expectStatus(id, in: DomainK_Coverage.checks, invalidContext, .unknown,
                                   "an unusable override leaves host-audit coverage unknown")
            }
        }
    } catch {
        check(false, "coding-agent detection fixtures: \(error)")
    }
}
