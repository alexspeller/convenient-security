import Foundation
import ConvenientSecurity

/// The rules-file subset, the on-disk loader, and the hook's use of both.
func codexRulesPolicyTests() {
    print("\n# Codex rules policy (what csec reads of Codex's execpolicy)")

    // Codex's own "always allow" writer produces exactly this line form.
    let amended = #"prefix_rule(pattern=["git", "commit", "-m"], decision="allow")"#
    check((try? CodexCommandGate.parseRules(amended))
          == [CodexCommandGate.PrefixRule(pattern: [["git"], ["commit"], ["-m"]], decision: .allow)],
          "Codex's own amend-form rule line parses")

    let accepted: [(String, [CodexCommandGate.PrefixRule])] = [
        (#"prefix_rule(pattern=["git", ["reset", "clean"]], decision="forbidden")"#,
         [.init(pattern: [["git"], ["reset", "clean"]], decision: .forbidden)]),
        (#"prefix_rule(pattern=[["npm", "pnpm"], "publish"], decision="prompt", match=["npm publish --tag x"], not_match=[["npm", "install"]])"#,
         [.init(pattern: [["npm", "pnpm"], ["publish"]], decision: .prompt)]),
        (#"prefix_rule(["git", "push"], "prompt")"#, [.init(pattern: [["git"], ["push"]], decision: .prompt)]),
        (#"prefix_rule(decision="prompt", pattern=["git", "push"])"#, [.init(pattern: [["git"], ["push"]], decision: .prompt)]),
        ("prefix_rule(\n    pattern=[\"git\", \"push\",],\n    decision=\"prompt\",\n)\n", [.init(pattern: [["git"], ["push"]], decision: .prompt)]),
        (#"prefix_rule(pattern=['git', 'push'], decision='prompt')"#, [.init(pattern: [["git"], ["push"]], decision: .prompt)]),
        (#"prefix_rule(pattern=["terraform"])"#, [.init(pattern: [["terraform"]], decision: .allow)]),
        (#"prefix_rule(pattern=["git"], decision="prompt"); prefix_rule(pattern=["ls"], decision="forbidden")"#,
         [.init(pattern: [["git"]], decision: .prompt), .init(pattern: [["ls"]], decision: .forbidden)]),
        ("# comment\nhost_executable(name=\"git\", paths=[\"/usr/bin/git\"])  # trailing\nprefix_rule(pattern=[\"echo\", \"\\u001b\"], decision=\"prompt\")\n",
         [.init(pattern: [["echo"], ["\u{1b}"]], decision: .prompt)]),
    ]
    for (text, rules) in accepted {
        check((try? CodexCommandGate.parseRules(text)) == rules,
              "the literal subset parses \(text.prefix(60).debugDescription)")
    }
    let outsideSubset = [
        "P = [\"git\", \"push\"]\nprefix_rule(pattern=P, decision=\"prompt\")",
        "for sub in [\"push\"]:\n    prefix_rule(pattern=[\"git\", sub], decision=\"forbidden\")",
        #"prefix_rule(pattern=["git"] + ["push"], decision="prompt")"#,
        #"prefix_rule(pattern=("git", "push"), decision="prompt")"#,
        #"prefix_rule(pattern=["echo", r"a\nb"], decision="prompt")"#,
        #"prefix_rule(pattern=["""git""", "push"], decision="prompt")"#,
        #"prefix_rule(pattern=["git"], decision="deny")"#,
        #"prefix_rule(pattern=[], decision="prompt")"#,
        #"prefix_rule(pattern=["git", []], decision="prompt")"#,
        #"prefix_rule(pattern=["git", 1], decision="prompt")"#,
        #"prefix_rule(pattern=["git"], decision="prompt", foo=1)"#,
        #"prefix_rule(pattern=["git"], decision="prompt", justification="  ")"#,
        #"prefix_rule(pattern=["echo", "a\qb"], decision="prompt")"#,
        #"host_executable(name="git", paths=["bin/git"])"#,
        #"load("other.star", "x")"#,
        "if True:\n    prefix_rule(pattern=[\"git\"], decision=\"prompt\")",
        #"prefix_rule(pattern=["git"], decision="prompt") prefix_rule(pattern=["ls"])"#,
    ]
    for text in outsideSubset {
        checkThrows("a rules file outside the literal subset is opaque: \(text.prefix(60).debugDescription)") {
            _ = try CodexCommandGate.parseRules(text)
        }
    }

    // The gate over a whole policy.
    let pushPrompt = CodexCommandGate.PrefixRule(pattern: [["git"], ["push"]], decision: .prompt)
    check(CodexCommandGate.requiresCodexGate("ls", policy: .init(opaqueSources: ["/x.rules"])),
          "an opaque rules source leaves every command to Codex")
    check(CodexCommandGate.requiresCodexGate("ls", rules: [.init(pattern: [["zsh"]], decision: .prompt)]),
          "a gating rule on the shell itself leaves every command to Codex")
    check(CodexCommandGate.requiresCodexGate("/usr/local/bin/git push origin", rules: [pushPrompt])
          && !CodexCommandGate.requiresCodexGate("git status", rules: [pushPrompt]),
          "a prompt rule gates exactly the commands it prefixes, by path or bare name")
    // Codex's heuristic counts nested shells and wrappers on one depth counter
    // and flags past eight. (It does not read a `'\''`-escaped nested script at
    // all: that is not a literal word.)
    check(CodexCommandGate.requiresCodexGate("bash -c \"bash -c 'env env env env env env env ls'\"", rules: []),
          "commands nested deeper than Codex follows fail closed to Codex's gate")
    check(CodexCommandGate.requiresCodexGate(Array(repeating: "env", count: 9).joined(separator: " ") + " ls", rules: []),
          "more than eight nested wrappers fail closed, as Codex's heuristic does")
    check(CodexCommandGate.requiresCodexGate("apply_patch <<'EOF'\n*** Begin Patch\n*** End Patch\nEOF", rules: [])
          && CodexCommandGate.requiresCodexGate("cd sub && apply_patch <<'EOF'\n*** Begin Patch\n*** End Patch\nEOF", rules: []),
          "apply_patch heredocs are left to Codex's patch engine and approval")
    check(!CodexCommandGate.requiresCodexGate("git status && ls -la | wc -l", rules: [pushPrompt]),
          "ordinary commands are still wrapped")

    // The on-disk loader.
    do {
        let fm = FileManager.default
        let root = fm.temporaryDirectory.appendingPathComponent("csec-codex-rules-\(UUID().uuidString)")
            .resolvingSymlinksInPath()
        defer { try? fm.removeItem(at: root) }
        let home = root.appendingPathComponent("home")
        let codexHome = home.appendingPathComponent(".codex")
        let system = root.appendingPathComponent("etc-codex")
        let trustedRepo = root.appendingPathComponent("work/trusted")
        let untrustedRepo = root.appendingPathComponent("work/untrusted")
        for directory in [codexHome.appendingPathComponent("rules"), system.appendingPathComponent("rules"),
                          trustedRepo.appendingPathComponent(".codex/rules"), trustedRepo.appendingPathComponent("src"),
                          untrustedRepo.appendingPathComponent(".codex/rules"),
                          trustedRepo.appendingPathComponent(".git"), untrustedRepo.appendingPathComponent(".git")] {
            try fm.createDirectory(at: directory, withIntermediateDirectories: true)
        }
        func write(_ text: String, _ url: URL) throws { try Data(text.utf8).write(to: url) }
        // A `.git` directory marks a project root only when it holds HEAD.
        try write("ref: refs/heads/main\n", trustedRepo.appendingPathComponent(".git/HEAD"))
        try write("ref: refs/heads/main\n", untrustedRepo.appendingPathComponent(".git/HEAD"))
        try write(#"prefix_rule(pattern=["git", "push"], decision="prompt")"#,
                  codexHome.appendingPathComponent("rules/default.rules"))
        try write(#"prefix_rule(pattern=["kubectl", "delete"], decision="forbidden")"#,
                  system.appendingPathComponent("rules/org.rules"))
        try write(#"prefix_rule(pattern=["terraform", "apply"], decision="prompt")"#,
                  trustedRepo.appendingPathComponent(".codex/rules/project.rules"))
        try write(#"prefix_rule(pattern=["cat"], decision="prompt")"#,
                  untrustedRepo.appendingPathComponent(".codex/rules/evil.rules"))
        try write("[projects.\"\(trustedRepo.path)\"]\ntrust_level = \"trusted\"\n\n[projects.\"\(untrustedRepo.path)\"]\ntrust_level = \"untrusted\"\n",
                  codexHome.appendingPathComponent("config.toml"))
        try fm.createSymbolicLink(at: codexHome.appendingPathComponent("rules/linked.rules"),
                                  withDestinationURL: untrustedRepo.appendingPathComponent(".codex/rules/evil.rules"))
        func load(_ cwd: URL?) -> CodexCommandGate.Policy {
            CodexCommandGate.loadPolicy(homeDirectory: home.path, codexHome: codexHome.path,
                                        workingDirectory: cwd?.path, systemDirectory: system.path,
                                        includeManagedPreferences: false)
        }
        let inTrusted = load(trustedRepo.appendingPathComponent("src"))
        check(inTrusted.opaqueSources.isEmpty
              && Set(inTrusted.rules.map { $0.pattern.first ?? [] }) == [["git"], ["kubectl"], ["terraform"]],
              "rules load from the System layer, CODEX_HOME and a trusted project, never through a symlink")
        let inUntrusted = load(untrustedRepo)
        check(!inUntrusted.rules.contains { $0.pattern.first == ["cat"] },
              "an untrusted clone's .codex/rules cannot choose commands for csec to leave unscanned")

        // Codex does not inherit trust from arbitrary ancestors, and an explicit
        // `untrusted` entry wins over a trusted parent (decision_for_dir).
        let config = codexHome.appendingPathComponent("config.toml")
        let parentTrusted = "[projects.\"\(root.path)\"]\ntrust_level = \"trusted\"\n"
        try write(parentTrusted + "\n[projects.\"\(untrustedRepo.path)\"]\ntrust_level = \"untrusted\"\n", config)
        try write("x = 1\n", untrustedRepo.appendingPathComponent(".codex/rules/opaque.rules"))
        let underTrustedParent = load(untrustedRepo)
        check(!underTrustedParent.rules.contains { $0.pattern.first == ["cat"] }
              && underTrustedParent.opaqueSources.isEmpty,
              "an explicitly untrusted clone under a trusted parent stays untrusted, opaque rules included")
        try write(parentTrusted, config)
        check(!load(untrustedRepo).rules.contains { $0.pattern.first == ["cat"] },
              "a clone with no trust entry of its own does not inherit a trusted parent's")
        try fm.removeItem(at: untrustedRepo.appendingPathComponent(".codex/rules/opaque.rules"))

        // Every TOML spelling Codex accepts for a trust entry.
        for spelling in [
            "[projects]\n\"\(untrustedRepo.path)\" = { trust_level = \"trusted\" }\n",
            "[projects]\n\"\(untrustedRepo.path)\".trust_level = \"trusted\"\n",
            "projects.\"\(untrustedRepo.path)\".trust_level = \"trusted\"\n",
            "[projects.'\(untrustedRepo.path)']\ntrust_level = 'trusted' # comment\n",
        ] {
            try write(spelling, config)
            check(load(untrustedRepo).rules.contains { $0.pattern.first == ["cat"] },
                  "a trust entry spelled \(spelling.prefix(40).debugDescription) is honoured")
        }
        try write("projects = { \"\(untrustedRepo.path)\" = { trust_level = \"untrusted\" } }\n", config)
        check(load(untrustedRepo).rules.contains { $0.pattern.first == ["cat"] },
              "a projects form csec cannot read counts as trusted, leaving more to Codex")

        // A linked worktree takes its main checkout's trust.
        let worktree = root.appendingPathComponent("work/linked")
        try fm.createDirectory(at: worktree.appendingPathComponent(".codex/rules"), withIntermediateDirectories: true)
        try fm.createDirectory(at: trustedRepo.appendingPathComponent(".git/worktrees/linked"),
                               withIntermediateDirectories: true)
        try write("gitdir: \(trustedRepo.path)/.git/worktrees/linked\n", worktree.appendingPathComponent(".git"))
        try write(#"prefix_rule(pattern=["helm", "delete"], decision="prompt")"#,
                  worktree.appendingPathComponent(".codex/rules/wt.rules"))
        try write("[projects.\"\(trustedRepo.path)\"]\ntrust_level = \"trusted\"\n", config)
        check(load(worktree).rules.contains { $0.pattern.first == ["helm"] },
              "a linked worktree's rules load when its main checkout is trusted")

        // features.hooks = false turns every non-builtin hook off, the managed csec one included.
        check(CodexCommandGate.hooksDisabledSources(homeDirectory: home.path, codexHome: codexHome.path,
                                                    systemDirectory: system.path).isEmpty,
              "Codex hooks are reported enabled by default")
        for spelling in ["[features]\nhooks = false\n", "features.hooks = false\n", "features = { hooks = false }\n",
                         "[profiles.work.features]\nhooks = false\n"] {
            try write(spelling, config)
            check(CodexCommandGate.hooksDisabledSources(homeDirectory: home.path, codexHome: codexHome.path,
                                                        systemDirectory: system.path) == [config.path],
                  "features.hooks = false spelled \(spelling.debugDescription) is reported")
        }
        try write("[features]\nhooks = true\n", config)
        try write("x = 1\n", system.appendingPathComponent("rules/zz.rules"))
        check(load(nil).opaqueSources == [system.appendingPathComponent("rules/zz.rules").path],
              "a rules file outside the subset is reported as opaque")
        try fm.removeItem(at: system.appendingPathComponent("rules/zz.rules"))
        try write("[rules]\nprefix_rules = [{ pattern = [{ token = \"git\" }], decision = \"prompt\" }]\n",
                  system.appendingPathComponent("requirements.toml"))
        check(load(nil).opaqueSources == [system.appendingPathComponent("requirements.toml").path],
              "requirements rules csec does not read are opaque")
    } catch {
        check(false, "Codex rules loader tests completed (\(error))")
    }

    // The hook: Codex abstains on gated commands, Claude never does.
    do {
        func hook(_ command: String, _ client: AICommandHookClient,
                  _ policy: CodexCommandGate.Policy = .init()) throws -> Data {
            let input = try JSONSerialization.data(withJSONObject: [
                "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": "/tmp",
                "tool_input": ["command": command],
            ])
            return try AICommandHook.rewrite(input: input, client: client,
                                             csecExecutablePath: "/usr/local/bin/csec", codexPolicy: { _ in policy })
        }
        check(try hook("rm -rf build", .codex).isEmpty,
              "the Codex hook leaves a forced rm unwrapped so Codex's dangerous-command check applies")
        check(try hook("git push", .codex, .init(rules: [pushPrompt])).isEmpty,
              "the Codex hook leaves a prompt-rule command unwrapped so Codex prompts")
        check(!(try hook("git status", .codex, .init(rules: [pushPrompt]))).isEmpty,
              "the Codex hook still wraps ungated commands")
        check(!(try hook("rm -rf build", .claude)).isEmpty,
              "the Claude hook always wraps; Claude Code's classifier judges the wrapped command")
    } catch {
        check(false, "Codex hook abstain tests completed (\(error))")
    }
}
