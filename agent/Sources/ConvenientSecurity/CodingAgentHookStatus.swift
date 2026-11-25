import Foundation

/// Where the csec Claude Code hook stands, for `csec status` / `csec doctor`.
/// Read-only: the same parser `csec setup` uses decides, so the report and the
/// repair can never disagree.
public enum ClaudeHookState: Sendable, Equatable {
    case notDetected
    /// The exact current hook is installed. `autoModeContext` says whether csec's
    /// `autoMode.environment` entry is current too.
    case installed(autoModeContext: Bool)
    case missing
    /// An older or duplicate csec handler: `csec setup` offers to replace it.
    case outdated
    /// `disableAllHooks` is set, so no hook runs.
    case hooksDisabled
    case unreadable
}

/// An allow rule that pre-approves *every* command the csec hook rewrites.
/// Because every Bash call reaches the client as `csec ai -- <command>`, a rule
/// such as `Bash(csec ai:*)` is equivalent to allowing all Bash commands, and a
/// client's own list of universal wrappers (`bash -c`, `env`, `sudo`, …) does
/// not know about csec. `rule` is display text with `KEY=value` values elided.
public struct UniversalAllowRule: Sendable, Equatable {
    public let client: AICommandHookClient
    public let source: String
    public let rule: String

    public init(client: AICommandHookClient, source: String, rule: String) {
        self.client = client
        self.source = source
        self.rule = rule
    }
}

public enum CodingAgentHookStatus {
    public static func claudeHookState(
        homeDirectory: String,
        pathEnvironment: String?,
        csecExecutablePath: String,
        claudeConfigDirectory: String? = nil
    ) -> ClaudeHookState {
        guard let detection = try? CodingAgentSetup.detect(
            homeDirectory: homeDirectory, pathEnvironment: pathEnvironment,
            claudeConfigDirectory: claudeConfigDirectory
        ).first(where: { $0.client == .claude }) else {
            return .unreadable
        }
        guard detection.detected else { return .notDetected }
        do {
            let plan = try CodingAgentSetup.plan(
                detection: detection, csecExecutablePath: csecExecutablePath)
            switch plan.action {
            case .unchanged:
                // A malformed autoMode block does not make an installed hook unreadable.
                let context = try? CodingAgentSetup.planClaudeAutoModeEnvironment(basedOn: plan)
                return .installed(autoModeContext: context?.action == .unchanged)
            case .create, .merge:
                return .missing
            case .blocked:
                // Exactly setup's distinction: a block that a replacement plan
                // would cleanly merge is a stale csec handler; anything else is
                // a policy block.
                let replacement = try? CodingAgentSetup.plan(
                    detection: detection, csecExecutablePath: csecExecutablePath,
                    replaceExistingCSECHook: true)
                return replacement?.action == .merge ? .outdated : .hooksDisabled
            }
        } catch {
            return .unreadable
        }
    }

    /// Claude Code settings files whose `permissions.allow` apply to sessions
    /// started in `workingDirectory`: user, managed, and the nearest project's
    /// shared and local files ("don't ask again" writes to the local file).
    public static func claudeSettingsPaths(homeDirectory: String, workingDirectory: String) -> [String] {
        var paths = [
            (homeDirectory as NSString).appendingPathComponent(".claude/settings.json"),
            "/Library/Application Support/ClaudeCode/managed-settings.json",
        ]
        var directory = URL(fileURLWithPath: workingDirectory).standardizedFileURL.path
        let home = URL(fileURLWithPath: homeDirectory).standardizedFileURL.path
        while directory.hasPrefix("/"), directory != home, directory != "/" {
            let project = (directory as NSString).appendingPathComponent(".claude")
            if FileManager.default.fileExists(atPath: project) {
                paths.append((project as NSString).appendingPathComponent("settings.json"))
                paths.append((project as NSString).appendingPathComponent("settings.local.json"))
                break
            }
            directory = (directory as NSString).deletingLastPathComponent
        }
        return paths
    }

    public static func claudeUniversalAllowRules(settingsPaths: [String]) -> [UniversalAllowRule] {
        settingsPaths.flatMap { path -> [UniversalAllowRule] in
            guard let data = FileManager.default.contents(atPath: path),
                  data.count <= CodingAgentSetup.maximumConfigurationBytes,
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let permissions = object["permissions"] as? [String: Any],
                  let allow = permissions["allow"] as? [String] else { return [] }
            return allow.filter(isUniversalCSECClaudeRule).map {
                UniversalAllowRule(client: .claude, source: path, rule: redactingAssignments($0))
            }
        }
    }

    /// `Bash(csec:*)`, `Bash(csec ai:*)`, `Bash(csec ai -- *)`,
    /// `Bash(/…/csec exec --set K=op://… -- *)`, `Bash(csec ai -- bash -c *)`
    /// and the like: a wildcard rule whose command is csec's launcher,
    /// optionally with a verb that runs an arbitrary child, then nothing more
    /// specific than options or a code runner. `Bash(csec ai -- npm test:*)`
    /// names a real command, and an exact rule without a wildcard matches only
    /// itself; neither is universal.
    public static func isUniversalCSECClaudeRule(_ rule: String) -> Bool {
        let trimmed = rule.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("Bash("), trimmed.hasSuffix(")") else { return false }
        var spec = String(trimmed.dropFirst(5).dropLast()).trimmingCharacters(in: .whitespaces)
        guard let wildcard = [":*", "*"].first(where: { spec.hasSuffix($0) }) else { return false }
        spec = String(spec.dropLast(wildcard.count))
        return isUniversalCSECPrefix(spec.split(whereSeparator: \.isWhitespace).map(String.init))
    }

    /// Verbs whose argument is an arbitrary command csec then runs.
    static let commandRunningVerbs: Set<String> = ["ai", "tool-exec", "exec", "exec-fd", "exec-file", "session"]

    /// Programs that run arbitrary code from their arguments, so a prefix ending
    /// in one approves everything. Claude Code's own list of rules it drops in
    /// auto mode (`dangerousPatterns`), plus the common command wrappers.
    static let codeRunners: Set<String> = [
        "sh", "bash", "zsh", "fish", "dash", "ksh", "python", "python3", "node", "deno", "ruby", "perl",
        "php", "lua", "npx", "bunx", "ssh", "eval", "exec", "env", "xargs", "sudo", "doas", "command",
        "builtin", "nohup", "time", "nice",
    ]
    /// `sudo`/`doas`/`env` options that take a value.
    static let valueOptions: Set<String> = ["-u", "-g", "-C", "-U", "-h", "-p", "-D", "-r", "-t", "-S", "-P"]
    /// Two-word runners (`npm run <script>` runs arbitrary package scripts).
    static let runnerSubcommands: [String: Set<String>] = [
        "npm": ["run", "exec"], "yarn": ["run", "exec", "dlx"], "pnpm": ["run", "exec", "dlx"], "bun": ["run", "x"],
    ]

    /// An argv prefix that every rewritten or csec-wrapped command, or every
    /// command at all, starts with: the launcher, then at most a
    /// command-running verb, options (`-…`, `--`, `KEY=value`) and code runners.
    /// A word that names a specific command makes the prefix specific.
    public static func isUniversalCSECPrefix(_ words: [String]) -> Bool {
        guard let launcher = words.first,
              (launcher as NSString).lastPathComponent == "csec" else { return false }
        guard words.count > 1 else { return true }
        guard commandRunningVerbs.contains(words[1]) else { return false }
        var index = 2
        var runner = ""
        while index < words.count {
            let word = words[index]
            let program = (word as NSString).lastPathComponent
            if ["sudo", "doas", "env"].contains(runner), valueOptions.contains(word), index + 1 < words.count {
                index += 2  // `sudo -u root`, `env -u NAME`: the option's value.
            } else if word.hasPrefix("-") || word.contains("=") {
                index += 1
            } else if codeRunners.contains(program) {
                runner = program
                index += 1
            } else if let subcommands = runnerSubcommands[program], index + 1 < words.count,
                      subcommands.contains(words[index + 1]) {
                index += 2
            } else if runnerSubcommands[program] != nil, index + 1 == words.count {
                index += 1
            } else {
                return false
            }
        }
        return true
    }

    /// Codex execpolicy `allow` rules csec can read whose pattern admits a
    /// universal csec prefix, e.g. `prefix_rule(["csec", "ai"])`. Such a rule
    /// would also let every command skip Codex's sandbox.
    public static func codexUniversalAllowRules(
        homeDirectory: String,
        codexHome: String? = nil,
        workingDirectory: String?,
        systemDirectory: String = "/etc/codex"
    ) -> [UniversalAllowRule] {
        var found: [UniversalAllowRule] = []
        for directory in CodexCommandGate.rulesDirectories(
            homeDirectory: homeDirectory, codexHome: codexHome,
            workingDirectory: workingDirectory, systemDirectory: systemDirectory) {
            for file in CodexCommandGate.rulesFiles(in: directory) {
                guard let text = CodexCommandGate.readText(file),
                      let rules = try? CodexCommandGate.parseRules(text) else { continue }
                for rule in rules where rule.decision == .allow && patternAdmitsUniversalCSEC(rule.pattern) {
                    let tokens = rule.pattern.map { $0.count == 1 ? "\"\($0[0])\"" : "[" + $0.joined(separator: "|") + "]" }
                    found.append(UniversalAllowRule(
                        client: .codex, source: file,
                        rule: redactingAssignments("prefix_rule([\(tokens.joined(separator: ", "))], allow)")))
                }
            }
        }
        return found
    }

    /// Whether some choice among a pattern's alternatives is a universal prefix.
    static func patternAdmitsUniversalCSEC(_ pattern: [[String]]) -> Bool {
        var combinations: [[String]] = [[]]
        for alternatives in pattern {
            combinations = combinations.flatMap { prefix in alternatives.map { prefix + [$0] } }
            if combinations.count > 4096 { return true }
        }
        return combinations.contains(where: isUniversalCSECPrefix)
    }

    /// `KEY=value` words shown as `KEY=…`, so a literal value in a rule is not
    /// echoed by `csec doctor`.
    public static func redactingAssignments(_ text: String) -> String {
        guard let expression = try? NSRegularExpression(pattern: #"([A-Za-z_][A-Za-z0-9_]*)=[^\s)\]",|]+"#) else {
            return text
        }
        let range = NSRange(text.startIndex..., in: text)
        return expression.stringByReplacingMatches(in: text, range: range, withTemplate: "$1=…")
    }
}

// MARK: - Status rows

extension CodingAgentHookStatus {
    public static func claudeRow(_ state: ClaudeHookState) -> StatusRow {
        let label = "Claude Code hook"
        switch state {
        case .notDetected:
            return StatusRow(label: label, value: "Claude Code not detected", state: .neutral)
        case .installed(autoModeContext: true):
            return StatusRow(label: label, value: "installed, with auto-mode context", state: .ok)
        case .installed(autoModeContext: false):
            return StatusRow(label: label,
                             value: "installed; auto-mode context missing or outdated — run csec setup",
                             state: .warn)
        case .missing:
            return StatusRow(label: label, value: "not configured — run csec setup", state: .warn)
        case .outdated:
            return StatusRow(label: label,
                             value: "an older csec hook is installed — run csec setup to replace it",
                             state: .warn)
        case .hooksDisabled:
            return StatusRow(label: label,
                             value: "disableAllHooks is set; the csec hook does not run",
                             state: .warn)
        case .unreadable:
            return StatusRow(label: label, value: "settings unreadable or unsafe", state: .warn)
        }
    }

    /// `displayPath` abbreviates a source path for display (for example `~/…`).
    public static func allowRulesRow(
        _ rules: [UniversalAllowRule],
        displayPath: (String) -> String
    ) -> StatusRow {
        let label = "Agent allow rules"
        guard let first = rules.first else {
            return StatusRow(label: label, value: "none pre-approve every csec-wrapped command", state: .ok)
        }
        let more = rules.count > 1 ? " (+\(rules.count - 1) more)" : ""
        return StatusRow(
            label: label,
            value: "\(ReviewDisplay.sanitized(String(first.rule.prefix(120)))) in "
                + "\(displayPath(first.source)) pre-approves every csec-wrapped "
                + "command; remove it\(more)",
            state: .warn)
    }
}

// MARK: - Codex

extension CodingAgentHookStatus {
    public enum CodexUserHook: Sendable, Equatable {
        case absent
        case present
        case unreadable
    }

    /// Whether `~/.codex/hooks.json` (or `$CODEX_HOME/hooks.json`) still carries a
    /// csec handler, which would run alongside the managed one.
    public static func codexUserHook(homeDirectory: String, codexHome: String? = nil) -> CodexUserHook {
        let directory = CodexCommandGate.userCodexDirectory(homeDirectory: homeDirectory, codexHome: codexHome)
        let detection = CodingAgentDetection(
            client: .codex, executablePath: nil,
            configurationPath: (directory as NSString).appendingPathComponent("hooks.json"),
            configurationExists: true)
        guard let plan = try? CodingAgentSetup.planCodexUserHookRemoval(detection: detection) else {
            return .unreadable
        }
        return plan.action == .merge ? .present : .absent
    }

    /// Whether this Mac has Codex: setup's detection (an executable on `PATH` or
    /// in a standard install directory, or a `~/.codex` hooks or config file),
    /// plus a hooks or config file in `$CODEX_HOME`. When detection cannot run
    /// it answers true, so a missing managed hook keeps failing `csec doctor`.
    public static func codexDetected(
        homeDirectory: String,
        pathEnvironment: String?,
        codexHome: String?,
        standardDirectories: (AICommandHookClient) -> [String] = CodingAgentSetup.standardExecutableDirectories(for:)
    ) -> Bool {
        let directory = CodexCommandGate.userCodexDirectory(homeDirectory: homeDirectory, codexHome: codexHome)
        // Any lstat answer other than "no such file" counts as present.
        if ["hooks.json", "config.toml"].contains(where: {
            var info = stat()
            return lstat((directory as NSString).appendingPathComponent($0), &info) == 0 || errno != ENOENT
        }) {
            return true
        }
        // Only Codex's detection is wanted, so Claude's config directory is not passed.
        guard let detection = try? CodingAgentSetup.detect(
            homeDirectory: homeDirectory, pathEnvironment: pathEnvironment,
            standardDirectories: standardDirectories
        ).first(where: { $0.client == .codex }) else {
            return true
        }
        return detection.detected
    }

    /// Whether the managed Codex hook's state fails `csec doctor`. Its absence
    /// fails only where Codex is installed: build-and-install writes it, but a
    /// Mac without Codex has nothing for it to protect. A stale, unsafe or
    /// unreadable `/etc/codex/hooks.json` always fails, since Codex would load
    /// it as soon as it is installed. `nil` is not checked.
    public static func codexSystemHookFailsDoctor(_ state: CodexSystemHookState?, codexDetected: Bool) -> Bool {
        switch state {
        case nil, .installed?: return false
        case .missing?: return codexDetected
        case .stale?, .unsafe?, .unreadable?: return true
        }
    }

    /// `nil` state means not checked (the installer's runtime-only gate).
    /// `opaqueRulesSources`: Codex rules files csec cannot interpret
    /// (`CodexCommandGate.Policy.opaqueSources`); `hooksDisabledSources`: Codex
    /// config files that set `features.hooks = false`.
    public static func codexRows(
        state: CodexSystemHookState?,
        codexDetected: Bool,
        userHook: CodexUserHook,
        developmentEndpoint: Bool,
        opaqueRulesSources: [String] = [],
        hooksDisabledSources: [String] = []
    ) -> [StatusRow] {
        let label = "Codex hook"
        var rows: [StatusRow] = []
        if developmentEndpoint {
            rows.append(StatusRow(label: label, value: "development endpoint selected", state: .neutral))
        } else if let state {
            switch state {
            case .installed:
                rows.append(StatusRow(label: label, value: "managed hook installed in /etc/codex", state: .ok))
            case .missing where !codexDetected:
                rows.append(StatusRow(label: label, value: "not needed — Codex is not installed", state: .neutral))
            case .missing:
                rows.append(StatusRow(label: label,
                                      value: "managed hook missing — run csec setup",
                                      state: .bad))
            case .stale:
                rows.append(StatusRow(label: label,
                                      value: "managed hook is stale — run csec setup",
                                      state: .bad))
            case .unsafe:
                rows.append(StatusRow(label: label,
                                      value: "/etc/codex/hooks.json is not root-owned or is writable by others",
                                      state: .bad))
            case .unreadable:
                rows.append(StatusRow(label: label, value: "/etc/codex/hooks.json is not valid JSON",
                                      state: .bad))
            }
        } else {
            rows.append(StatusRow(label: label, value: "not checked (runtime-only mode)", state: .neutral))
        }
        if let unreadable = opaqueRulesSources.first {
            let more = opaqueRulesSources.count > 1 ? " (+\(opaqueRulesSources.count - 1) more)" : ""
            rows.append(StatusRow(
                label: "Codex rules",
                value: "csec cannot read \(ReviewDisplay.sanitized(unreadable))\(more), so every Codex command "
                    + "runs unwrapped, without output scanning; keep rules to literal prefix_rule calls",
                state: .warn))
        }
        if let disabling = hooksDisabledSources.first {
            rows.append(StatusRow(
                label: "Codex hooks",
                value: "features.hooks = false in \(ReviewDisplay.sanitized(disabling)) turns every Codex hook off, "
                    + "the managed csec hook included; Codex commands run without csec",
                state: .warn))
        }
        switch userHook {
        case .absent:
            break
        case .present:
            rows.append(StatusRow(
                label: "Codex user hook",
                value: "~/.codex/hooks.json still has a csec hook that duplicates the managed one — run csec setup",
                state: .warn))
        case .unreadable:
            rows.append(StatusRow(
                label: "Codex user hook",
                value: "~/.codex/hooks.json is unreadable or unsafe; csec cannot check it for a leftover csec hook",
                state: .warn))
        }
        return rows
    }
}
