import ConvenientSecurity
import CSECRootProtocol
import Foundation

// HA-F13 — package managers hold back just-published releases.
//
// Synthetic, value-free fixtures on the harness's /Users/tester home: fake
// install directories named by version, and config files holding only cooldown
// keys beside placeholder lines that stand in for whatever else a user keeps
// there (a registry line, an index URL). The honest-coverage cases assert that a
// copy which ignores the setting, or a value csec cannot read as a window, is
// never a pass, and that a copy which would fail on the setting withholds the
// fix rather than breaking the tool.

private let home = "/Users/tester"
private let mise = "\(home)/.local/share/mise/installs"
private let corepack = "\(home)/.cache/node/corepack/v1"

func hostAuditTests_F13() async {
    releaseCooldownConfigReadTests()
    releaseCooldownConfigEditTests()
    releaseCooldownDurationTests()
    await releaseCooldownCheckTests()
    await releaseCooldownFixTests()
    await releaseCooldownReviewTests()
    releaseCooldownWriterTests()
}

private func cooldownFinding(_ files: FakeFileInspector) async -> HostFinding? {
    await evaluateAudit("HA-F13", in: DomainF_Developer.checks, makeAuditContext(files: files))
}

/// Every manager present with a seven-day setting and a copy that honours it.
private func fullyCooledHome() -> FakeFileInspector {
    FakeFileInspector(
        texts: [
            "\(home)/.npmrc": "registry=https://registry.example.test/\nmin-release-age=7\n",
            "/opt/homebrew/lib/node_modules/npm/package.json": #"{"name":"npm","version":"11.21.1"}"#,
            "\(home)/Library/Preferences/pnpm/config.yaml": "minimumReleaseAge: 10080\n",
            "\(home)/.yarnrc.yml": "npmMinimalAgeGate: 7d\n",
            "\(home)/.config/uv/uv.toml": "exclude-newer = \"7 days\"\n",
            "\(home)/.config/pip/pip.conf": "[global]\nuploaded-prior-to = P7D\n",
            "\(home)/.config/mise/config.toml": "[tools]\nnode = \"lts\"\n\n[settings]\nminimum_release_age = \"7d\"\n",
            "\(home)/.bundle/config": "---\nBUNDLE_COOLDOWN: \"7\"\n",
            "/opt/homebrew/opt/mise/INSTALL_RECEIPT.json": #"{"source":{"versions":{"stable":"2026.10.17"}}}"#,
        ],
        entries: [
            "\(corepack)/pnpm": ["12.15.0"],
            "\(corepack)/yarn": ["4.14.1"],
            "\(mise)/uv": ["0", "0.13", "0.13.1", "latest"],
            "\(mise)/python": ["3", "3.12", "3.12.13", "latest"],
            "\(mise)/python/3.12.13/lib": ["python3.12", "pkgconfig"],
            "\(mise)/python/3.12.13/lib/python3.12/site-packages": ["pip-26.2.2.dist-info", "setuptools"],
            "\(mise)/ruby": ["4", "4.0", "4.0.9"],
            "\(mise)/ruby/4.0.9/lib/ruby/gems": ["4.0.0"],
            "\(mise)/ruby/4.0.9/lib/ruby/gems/4.0.0/gems": ["bundler-4.0.20", "bundler-audit-0.9.3", "rake-13.0.0"],
        ])
}

// MARK: Reading one key

private func releaseCooldownConfigReadTests() {
    let ini = "registry=https://registry.example.test/\nmin-release-age=3\n; comment\nmin-release-age = 7\n[scope]\nmin-release-age=1\n"
    check(ReleaseCooldownConfig.value(in: ini, key: "min-release-age", format: .ini(section: nil)) == "7",
          "cooldown config: ini root key, last occurrence wins, section lines ignored")
    check(ReleaseCooldownConfig.value(in: "min-release-age=7 # week\n", key: "min-release-age",
                                      format: .ini(section: nil)) == "7 # week",
          "cooldown config: ini keeps an inline # as npm's reader does")
    let pip = "[install]\nuploaded-prior-to = P1D\n[global]\nindex-url = https://index.example.test/simple\nuploaded-prior-to = P7D\n"
    check(ReleaseCooldownConfig.value(in: pip, key: "uploaded-prior-to", format: .ini(section: "global")) == "P7D",
          "cooldown config: ini key read from its own section only")
    let yaml = "---\nnpmScopes:\n  npmMinimalAgeGate: 1\nnpmMinimalAgeGate: \"7d\" # a week\n"
    check(ReleaseCooldownConfig.value(in: yaml, key: "npmMinimalAgeGate", format: .yaml) == "7d",
          "cooldown config: yaml top-level key, indented keys and comments ignored")
    let toml = "exclude-newer = \"7 days\" # week\n[[index]]\nexclude-newer = \"1 day\"\n"
    check(ReleaseCooldownConfig.value(in: toml, key: "exclude-newer", format: .toml(table: nil)) == "7 days",
          "cooldown config: toml root key, array-table keys ignored")
    let mise = "minimum_release_age = \"1d\"\n[settings]\nminimum_release_age = \"7d\"\n"
    check(ReleaseCooldownConfig.value(in: mise, key: "minimum_release_age", format: .toml(table: "settings")) == "7d",
          "cooldown config: toml key read from its table")
    check(ReleaseCooldownConfig.value(in: "[tools]\nnode = \"lts\"\n", key: "minimum_release_age",
                                      format: .toml(table: "settings")) == nil,
          "cooldown config: absent key reads as nil")
}

// MARK: Editing one key

private func releaseCooldownConfigEditTests() {
    typealias C = ReleaseCooldownConfig
    check(C.setting(nil, key: "min-release-age", literal: "7", format: .ini(section: nil)) == "min-release-age=7\n",
          "cooldown edit: a new ini file holds the one line")
    check(C.setting(nil, key: "uploaded-prior-to", literal: "P7D", format: .ini(section: "global"))
            == "[global]\nuploaded-prior-to=P7D\n",
          "cooldown edit: a new sectioned file gets its section")

    let npmrc = "registry=https://registry.example.test/\nmin-release-age=1\nfund=false"
    check(C.setting(npmrc, key: "min-release-age", literal: "7", format: .ini(section: nil))
            == "registry=https://registry.example.test/\nmin-release-age=7\nfund=false\n",
          "cooldown edit: an existing ini value is replaced in place, other lines kept")
    check(C.setting("registry=https://registry.example.test/\n", key: "min-release-age", literal: "7",
                    format: .ini(section: nil))
            == "registry=https://registry.example.test/\nmin-release-age=7\n",
          "cooldown edit: a missing ini key is appended")

    let uv = "# uv settings\nsystem-certs = true\n\n[[index]]\nurl = \"https://index.example.test/simple\"\n"
    check(C.setting(uv, key: "exclude-newer", literal: "\"7 days\"", format: .toml(table: nil))
            == "# uv settings\nsystem-certs = true\n\nexclude-newer = \"7 days\"\n[[index]]\nurl = \"https://index.example.test/simple\"\n",
          "cooldown edit: a toml root key goes before the first table, not into it")

    let miseConfig = "[tools]\nnode = \"lts\"\n\n[settings]\nexperimental = true\n"
    check(C.setting(miseConfig, key: "minimum_release_age", literal: "\"7d\"", format: .toml(table: "settings"))
            == "[tools]\nnode = \"lts\"\n\n[settings]\nminimum_release_age = \"7d\"\nexperimental = true\n",
          "cooldown edit: a toml table key goes into its existing table")
    check(C.setting("[tools]\nnode = \"lts\"\n", key: "minimum_release_age", literal: "\"7d\"",
                    format: .toml(table: "settings"))
            == "[tools]\nnode = \"lts\"\n\n[settings]\nminimum_release_age = \"7d\"\n",
          "cooldown edit: a missing toml table is added at the end")

    check(C.setting("---\nBUNDLE_JOBS: \"4\"\n", key: "BUNDLE_COOLDOWN", literal: "\"7\"", format: .yaml)
            == "---\nBUNDLE_JOBS: \"4\"\nBUNDLE_COOLDOWN: \"7\"\n",
          "cooldown edit: a yaml top-level key is appended to a block mapping")
    check(C.setting("npmMinimalAgeGate: 60\nnpmScopes:\n  example:\n    npmRegistryServer: x\n",
                    key: "npmMinimalAgeGate", literal: "7d", format: .yaml)
            == "npmMinimalAgeGate: 7d\nnpmScopes:\n  example:\n    npmRegistryServer: x\n",
          "cooldown edit: an existing yaml value is replaced, nested keys kept")
    check(C.setting("{npmMinimalAgeGate: 60}\n", key: "npmMinimalAgeGate", literal: "7d", format: .yaml) == nil,
          "cooldown edit: a flow-style yaml document is refused, not guessed at")
    check(C.setting("npmMinimalAgeGate:\n  - 60\n", key: "npmMinimalAgeGate", literal: "7d", format: .yaml) == nil,
          "cooldown edit: a yaml key with a block value is refused")
    check(C.setting("min-release-age=1\r\n", key: "min-release-age", literal: "7", format: .ini(section: nil)) == nil,
          "cooldown edit: CRLF files are refused rather than rewritten with mixed endings")
}

// MARK: Durations

private func releaseCooldownDurationTests() {
    let d = ReleaseCooldownConfig.durationDays
    check(d("7", 1) == 7, "duration: npm bare days")
    check(d("10080", 1.0 / 1_440) == 7, "duration: pnpm bare minutes")
    check(d("7d", 0) == 7 && d("1w", 0) == 7 && d("168h", 0) == 7, "duration: mise/Yarn unit suffixes")
    check(d("7 days", 0) == 7 && d("1 week", 0) == 7, "duration: uv spelled-out units")
    check(d("P7D", 0) == 7 && d("P1W", 0) == 7 && d("PT168H", 0) == 7, "duration: ISO 8601")
    check(d("1d12h", 0) == 1.5, "duration: compound terms add up")
    check(d("2026-01-01", 0) == nil && d("2026-01-01T00:00:00Z", 0) == nil, "duration: a fixed date is not a window")
    check(d("P1M", 0) == nil, "duration: calendar months are refused")
    check(d("7 # week", 1) == nil, "duration: a value with a stray comment is not a window")
    check(d("", 1) == nil && d("-1", 1) == nil, "duration: empty and negative are not windows")
}

// MARK: The check

private func releaseCooldownCheckTests() async {
    // NOT APPLICABLE: no manager anywhere.
    check(await cooldownFinding(FakeFileInspector())?.status == .notApplicable,
          "HA-F13: no package manager -> not applicable")

    // PASS: every manager set to a week, every copy honours it.
    let cooled = await cooldownFinding(fullyCooledHome())
    check(cooled?.status == .pass, "HA-F13: every manager cooled, every copy honours it -> pass "
          + "[got \(cooled?.status.rawValue ?? "nil"): \(cooled?.evidence ?? "")]")
    check(cooled?.remediationKey == nil, "HA-F13: a pass carries no fix")

    // FAIL: npm in use with no setting; the evidence names the file, not its contents.
    let bare = FakeFileInspector(texts: [
        "\(home)/.npmrc": "registry=https://registry.example.test/\n",
        "/opt/homebrew/lib/node_modules/npm/package.json": #"{"version":"11.21.1"}"#,
    ])
    let missing = await cooldownFinding(bare)
    check(missing?.status == .fail, "HA-F13: npm with no min-release-age -> fail")
    check(missing?.remediationKey == "HA-F13", "HA-F13: a fail is batch-fixable")
    check(missing?.evidence.contains("~/.npmrc") == true && missing?.evidence.contains("registry.example") == false,
          "HA-F13: evidence names the file and never its other contents")

    // FAIL: a window shorter than a week.
    let shortWindow = fullyCooledHome()
    shortWindow.texts["\(home)/.config/uv/uv.toml"] = "exclude-newer = \"1 day\"\n"
    let short = await cooldownFinding(shortWindow)
    check(short?.status == .fail && short?.evidence.contains("uv (1 day") == true,
          "HA-F13: a one-day uv window -> fail, naming the window")

    // FAIL: pnpm 11+ with no file falls back to its one-day built-in default.
    let pnpmDefault = fullyCooledHome()
    pnpmDefault.texts["\(home)/Library/Preferences/pnpm/config.yaml"] = nil
    let builtIn = await cooldownFinding(pnpmDefault)
    check(builtIn?.status == .fail && builtIn?.evidence.contains("built-in default") == true,
          "HA-F13: pnpm's one-day default is under a week -> fail")

    // UNKNOWN (never pass): settings all good, but an old pnpm copy ignores them.
    let oldPnpm = fullyCooledHome()
    oldPnpm.entries["\(corepack)/pnpm"] = ["10.7.1", "12.15.0"]
    let ignored = await cooldownFinding(oldPnpm)
    check(ignored?.status == .unknown && ignored?.evidence.contains("pnpm 10.7.1 (Corepack; before pnpm 10.16)") == true,
          "HA-F13: a pnpm copy before 10.16 -> unknown, named")

    // UNKNOWN: Yarn Classic has no cooldown at all.
    let classic = fullyCooledHome()
    classic.entries["\(corepack)/yarn"] = ["1.22.22", "4.14.1"]
    let classicFinding = await cooldownFinding(classic)
    check(classicFinding?.status == .unknown && classicFinding?.evidence.contains("Yarn Classic") == true,
          "HA-F13: Yarn Classic -> unknown")

    // UNKNOWN: Apple's bundled pip ignores the setting too.
    let applePip = fullyCooledHome()
    let clt = "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions"
    applePip.entries[clt] = ["3.9", "Current"]
    applePip.entries["\(clt)/3.9/lib"] = ["python3.9"]
    applePip.entries["\(clt)/3.9/lib/python3.9/site-packages"] = ["pip-21.2.4.dist-info"]
    let appleFinding = await cooldownFinding(applePip)
    check(appleFinding?.status == .unknown
            && appleFinding?.evidence.contains("pip 21.2.4 (Apple Command Line Tools; before pip 26.1)") == true,
          "HA-F13: Apple's Command Line Tools pip -> unknown, and its Current alias is not double-counted")
    check(appleFinding?.evidence.components(separatedBy: "pip 21.2.4").count == 2,
          "HA-F13: one Apple pip is listed once")

    // UNKNOWN: a fixed date is deliberate; csec does not call it a window or replace it.
    let fixedDate = fullyCooledHome()
    fixedDate.texts["\(home)/.config/uv/uv.toml"] = "exclude-newer = \"2026-01-01T00:00:00Z\"\n"
    check(await cooldownFinding(fixedDate)?.status == .unknown, "HA-F13: a fixed exclude-newer date -> unknown")

    // UNKNOWN: a symlinked config is not followed.
    let linked = fullyCooledHome()
    linked.symlinks.insert("\(home)/.npmrc")
    let linkedFinding = await cooldownFinding(linked)
    check(linkedFinding?.status == .unknown && linkedFinding?.evidence.contains("a link, unreadable or too large") == true,
          "HA-F13: a symlinked ~/.npmrc -> unknown, never read through")

    // pnpm 10.16+ reads its ini rc, not config.yaml.
    let pnpm10 = fullyCooledHome()
    pnpm10.entries["\(corepack)/pnpm"] = ["10.20.0"]
    pnpm10.texts["\(home)/Library/Preferences/pnpm/config.yaml"] = nil
    check(await cooldownFinding(pnpm10)?.status == .fail, "HA-F13: pnpm 10.20 with no rc setting -> fail")
    pnpm10.texts["\(home)/Library/Preferences/pnpm/rc"] = "minimum-release-age=10080\n"
    check(await cooldownFinding(pnpm10)?.status == .pass, "HA-F13: pnpm 10.20 with the rc setting -> pass")

    // Yarn 4.10 reads `7d` as seven minutes; 4.11+ reads it as a week.
    let yarn410 = fullyCooledHome()
    yarn410.entries["\(corepack)/yarn"] = ["4.10.3", "4.14.1"]
    let yarn410Finding = await cooldownFinding(yarn410)
    check(yarn410Finding?.status == .fail && yarn410Finding?.evidence.contains("Yarn (7 minutes") == true,
          "HA-F13: Yarn 4.10 with `7d` holds back only seven minutes -> fail")
    yarn410.texts["\(home)/.yarnrc.yml"] = "npmMinimalAgeGate: 10080\n"
    check(await cooldownFinding(yarn410)?.status == .pass, "HA-F13: bare minutes read as a week by Yarn 4.10 and 4.14")

    // pip reads [install] as well as [global].
    let pipInstall = fullyCooledHome()
    pipInstall.texts["\(home)/.config/pip/pip.conf"] = "[install]\nuploaded-prior-to = P7D\n"
    check(await cooldownFinding(pipInstall)?.status == .pass, "HA-F13: pip's [install] section counts")

    // pip 26.1 accepts only P<n>D, Bundler only whole days.
    let pipWeek = fullyCooledHome()
    pipWeek.texts["\(home)/.config/pip/pip.conf"] = "[global]\nuploaded-prior-to = P1W\n"
    check(await cooldownFinding(pipWeek)?.status == .unknown, "HA-F13: pip `P1W`, which pip rejects, is not a week")
    let bundlerDays = fullyCooledHome()
    bundlerDays.texts["\(home)/.bundle/config"] = "---\nBUNDLE_COOLDOWN: \"7d\"\n"
    check(await cooldownFinding(bundlerDays)?.status == .unknown, "HA-F13: Bundler `7d`, which Bundler ignores, is not a week")

    // pip's current file is chosen by directory, and overrides the legacy file.
    let legacyPip = fullyCooledHome()
    legacyPip.texts["\(home)/.config/pip/pip.conf"] = nil
    legacyPip.texts["\(home)/.pip/pip.conf"] = "[global]\nuploaded-prior-to = P7D\n"
    check(await cooldownFinding(legacyPip)?.status == .pass, "HA-F13: the legacy ~/.pip/pip.conf counts")
    legacyPip.directories.insert("\(home)/Library/Application Support/pip")
    legacyPip.texts["\(home)/Library/Application Support/pip/pip.conf"] = "[global]\nuploaded-prior-to = P1D\n"
    check(await cooldownFinding(legacyPip)?.status == .fail,
          "HA-F13: the current pip.conf overrides the legacy one")

    // mise before 2026.10.17 lets vfox-backed tools through.
    let oldMise = fullyCooledHome()
    oldMise.texts["/opt/homebrew/opt/mise/INSTALL_RECEIPT.json"] = #"{"source":{"versions":{"stable":"2026.10.14"}}}"#
    let oldMiseFinding = await cooldownFinding(oldMise)
    check(oldMiseFinding?.status == .unknown && oldMiseFinding?.evidence.contains("vfox") == true,
          "HA-F13: mise 2026.10.14 -> unknown (vfox-backed tools are not held back)")

    // mise alias links are not separate copies.
    let states = ReleaseCooldowns.inspect(makeAuditContext(files: fullyCooledHome()))
    check(states.first { $0.manager == .uv }?.copies.count == 1,
          "HA-F13: mise's 0 / 0.13 / latest aliases count as the one uv install")
}

// MARK: Fixes

private func releaseCooldownFixTests() async {
    // One row per manager that needs it, keyed HA-F13.<manager>.
    let needy = FakeFileInspector(
        texts: [
            "\(home)/.npmrc": "registry=https://registry.example.test/\n",
            "/opt/homebrew/lib/node_modules/npm/package.json": #"{"version":"11.21.1"}"#,
            "\(home)/.config/mise/config.toml": "[tools]\nnode = \"lts\"\n",
            "/opt/homebrew/opt/mise/INSTALL_RECEIPT.json": #"{"source":{"versions":{"stable":"2026.10.17"}}}"#,
        ],
        entries: ["\(mise)/uv": ["0.13.1"]])
    let writer = FakeUserConfigWriter()
    let ctx = makeAuditContext(files: needy, userConfig: writer)
    let report = await HostAuditEngine().run(ctx)
    let plans = await HostRemediationBuilder.plans(for: report, ctx: ctx)
        .filter { $0.item.key.hasPrefix("HA-F13") }
    check(plans.map(\.item.key) == ["HA-F13.npm", "HA-F13.uv", "HA-F13.mise"],
          "HA-F13 fix: one deselectable row per manager [got \(plans.map(\.item.key))]")
    check(plans.allSatisfy { !$0.item.requiresRoot }, "HA-F13 fix: user-level, no root helper")

    let summary = await HostRemediationCoordinator.applySelected(
        plans, selectedKeys: ["HA-F13.npm", "HA-F13.mise"], ctx: ctx)
    check(summary.applied == ["HA-F13.npm", "HA-F13.mise"] && summary.skipped == ["HA-F13.uv"],
          "HA-F13 fix: only the selected rows apply")
    check(writer.writes["\(home)/.npmrc"] == "registry=https://registry.example.test/\nmin-release-age=7\n",
          "HA-F13 fix: ~/.npmrc keeps its other lines and gains the window")
    check(writer.writes["\(home)/.config/mise/config.toml"]
            == "[tools]\nnode = \"lts\"\n\n[settings]\nminimum_release_age = \"7d\"\n",
          "HA-F13 fix: mise's window goes under [settings]")
    check(writer.writes["\(home)/.config/uv/uv.toml"] == nil, "HA-F13 fix: a deselected row writes nothing")

    // Applying writes what the tools then read: re-evaluating the written state passes for npm.
    needy.texts["\(home)/.npmrc"] = writer.writes["\(home)/.npmrc"]
    let after = ReleaseCooldowns.inspect(makeAuditContext(files: needy))
    check(after.first { $0.manager == .npm }?.settings.first?.window == .set(days: 7),
          "HA-F13 fix: the written ~/.npmrc reads back as a seven-day window")

    // Withheld: an old uv fails every command once uv.toml has a relative window.
    let oldUV = FakeFileInspector(entries: ["\(mise)/uv": ["0.5.9", "0.13.1"]])
    let oldUVStates = ReleaseCooldowns.inspect(makeAuditContext(files: oldUV))
    check(ReleaseCooldowns.fixes(oldUVStates).isEmpty, "HA-F13 fix: uv 0.5.9 present -> uv fix withheld")
    let (oldUVStatus, oldUVEvidence) = ReleaseCooldowns.evaluate(oldUVStates)
    check(oldUVStatus == .fail && oldUVEvidence.contains("Fix withheld for uv"),
          "HA-F13 fix: the withheld fix is explained in the evidence")

    // Withheld: a standalone uv whose version csec cannot read without running it.
    let standaloneUV = FakeFileInspector(executables: ["\(home)/.local/bin/uv"])
    check(ReleaseCooldowns.fixes(ReleaseCooldowns.inspect(makeAuditContext(files: standaloneUV))).isEmpty,
          "HA-F13 fix: an undated standalone uv -> uv fix withheld")

    // Withheld: pip 26.0 rejects P7D and would fail every install.
    let pip260 = FakeFileInspector(entries: [
        "\(mise)/python": ["3.12.13"],
        "\(mise)/python/3.12.13/lib": ["python3.12"],
        "\(mise)/python/3.12.13/lib/python3.12/site-packages": ["pip-26.0.1.dist-info"],
    ])
    check(ReleaseCooldowns.fixes(ReleaseCooldowns.inspect(makeAuditContext(files: pip260))).isEmpty,
          "HA-F13 fix: pip 26.0 present -> pip fix withheld")

    // Offered: an old pip that merely ignores the setting does not withhold it.
    let pip25 = FakeFileInspector(entries: [
        "\(mise)/python": ["3.12.13"],
        "\(mise)/python/3.12.13/lib": ["python3.12"],
        "\(mise)/python/3.12.13/lib/python3.12/site-packages": ["pip-25.0.1.dist-info"],
    ])
    let pip25Fixes = ReleaseCooldowns.fixes(ReleaseCooldowns.inspect(makeAuditContext(files: pip25)))
    check(pip25Fixes.map(\.manager) == [.pip]
            && pip25Fixes.first?.settings.first?.relativePath == ".config/pip/pip.conf",
          "HA-F13 fix: pip 25 ignores the setting harmlessly, so the fix is still offered")

    // Not offered: a symlinked config, or one the line-editor cannot change safely.
    let linked = FakeFileInspector(texts: ["\(home)/.npmrc": "registry=x\n"], symlinks: ["\(home)/.npmrc"])
    check(ReleaseCooldowns.fixes(ReleaseCooldowns.inspect(makeAuditContext(files: linked))).isEmpty,
          "HA-F13 fix: a symlinked ~/.npmrc is never written through")
    let flow = FakeFileInspector(texts: ["\(home)/.yarnrc.yml": "{enableTelemetry: false}\n"])
    check(ReleaseCooldowns.fixes(ReleaseCooldowns.inspect(makeAuditContext(files: flow))).isEmpty,
          "HA-F13 fix: a flow-style ~/.yarnrc.yml is left alone")

    // A failed write is reported failed, not applied.
    let failing = makeAuditContext(files: needy, userConfig: FakeUserConfigWriter(succeeds: false))
    let failPlans = await HostRemediationBuilder.plans(for: await HostAuditEngine().run(failing), ctx: failing)
        .filter { $0.item.key == "HA-F13.mise" }
    let failSummary = await HostRemediationCoordinator.applySelected(
        failPlans, selectedKeys: ["HA-F13.mise"], ctx: failing)
    check(failSummary.failed == ["HA-F13.mise"], "HA-F13 fix: a refused write is reported failed")
}

// MARK: Overrides, missing copies, other files and file shapes

private func releaseCooldownReviewTests() async {
    // npm and pnpm take a plain number: `7d` and `inf` are NaN to them, so no cooldown.
    for bad in ["7d", "inf", "1e9", "0x10"] {
        let unit = fullyCooledHome()
        unit.texts["\(home)/.npmrc"] = "min-release-age=\(bad)\n"
        check(await cooldownFinding(unit)?.status == .unknown, "HA-F13: npm min-release-age=\(bad) is not a window")
    }
    let pnpmUnit = fullyCooledHome()
    pnpmUnit.texts["\(home)/Library/Preferences/pnpm/config.yaml"] = "minimumReleaseAge: 7d\n"
    check(await cooldownFinding(pnpmUnit)?.status == .unknown, "HA-F13: pnpm minimumReleaseAge: 7d is not a window")
    check(ReleaseCooldownConfig.durationDays("inf", bareUnitDays: 0) == nil
            && ReleaseCooldownConfig.durationDays("nan", bareUnitDays: 1) == nil,
          "duration: inf and nan are not windows")

    // Keys that override the window or exempt packages are never judged a pass.
    let overrides: [(String, String, String)] = [
        ("\(home)/.npmrc", "min-release-age=7\nbefore=2099-12-31\n", "npm before"),
        ("\(home)/.npmrc", "min-release-age=7\nmin-release-age-exclude[]=*\n", "npm exclude"),
        ("\(home)/Library/Preferences/pnpm/config.yaml", "minimumReleaseAge: 10080\nminimumReleaseAgeStrict: false\n",
         "pnpm non-strict"),
        ("\(home)/.yarnrc.yml", "npmMinimalAgeGate: 7d\nnpmPreapprovedPackages:\n  - \"*\"\n", "Yarn preapproved"),
        ("\(home)/.config/uv/uv.toml", "exclude-newer = \"7 days\"\n\n[exclude-newer-package]\nexample = false\n",
         "uv per-package table"),
        ("\(home)/.config/mise/config.toml", "[settings]\nminimum_release_age = \"7d\"\nminimum_release_age_excludes = [\"*\"]\n",
         "mise excludes"),
    ]
    for (path, text, label) in overrides {
        let home = fullyCooledHome()
        home.texts[path] = text
        let finding = await cooldownFinding(home)
        check(finding?.status == .unknown && finding?.evidence.contains("overrides it or exempts packages") == true,
              "HA-F13: \(label) -> unknown, never pass")
    }
    let strict = fullyCooledHome()
    strict.texts["\(home)/Library/Preferences/pnpm/config.yaml"] = "minimumReleaseAge: 10080\nminimumReleaseAgeStrict: true\n"
    check(await cooldownFinding(strict)?.status == .pass, "HA-F13: pnpm strict true is no override")

    // A setting with no installed copy found cannot be confirmed.
    let noCopy = FakeFileInspector(texts: ["\(home)/.yarnrc.yml": "npmMinimalAgeGate: 10080\n"])
    let noCopyFinding = await cooldownFinding(noCopy)
    check(noCopyFinding?.status == .unknown && noCopyFinding?.evidence.contains("no installed copy found") == true,
          "HA-F13: a set window with no copy found -> unknown, not pass")

    // More install locations: fnm's npm, Yarn installed globally under nvm, pnpm's
    // own installer, and a Ruby's default Bundler gem.
    let more = fullyCooledHome()
    more.entries["\(home)/.local/share/fnm/node-versions"] = ["v22.1.0"]
    more.texts["\(home)/.local/share/fnm/node-versions/v22.1.0/installation/lib/node_modules/npm/package.json"] =
        #"{"version":"10.7.0"}"#
    more.entries["\(home)/.nvm/versions/node"] = ["v20.0.0"]
    more.texts["\(home)/.nvm/versions/node/v20.0.0/lib/node_modules/yarn/package.json"] = #"{"version":"1.22.19"}"#
    more.entries["\(home)/Library/pnpm/.tools"] = ["pnpm"]
    more.entries["\(home)/Library/pnpm/.tools/pnpm"] = ["9.15.0"]
    more.entries["\(mise)/ruby/4.0.9/lib/ruby/gems/4.0.0/specifications/default"] = ["bundler-4.0.3.gemspec", "json-2.9.1.gemspec"]
    let moreEvidence = await cooldownFinding(more)?.evidence ?? ""
    for expected in ["npm 10.7.0 (fnm", "Yarn 1.22.19 (nvm npm global", "pnpm 9.15.0 (pnpm installer",
                     "Bundler 4.0.3 (mise"] {
        check(moreEvidence.contains(expected), "HA-F13: inventory finds \(expected)")
    }

    // A pip-installed uv too old for the setting withholds uv's fix.
    let pipUV = FakeFileInspector(entries: [
        "\(mise)/python": ["3.12.13"],
        "\(mise)/python/3.12.13/lib": ["python3.12"],
        "\(mise)/python/3.12.13/lib/python3.12/site-packages": ["pip-26.2.2.dist-info", "uv-0.8.0.dist-info"],
    ])
    check(!ReleaseCooldowns.fixes(ReleaseCooldowns.inspect(makeAuditContext(files: pipUV))).contains { $0.manager == .uv },
          "HA-F13 fix: a pip-installed uv 0.8 withholds uv's fix")

    // mise: a root dotted key cannot take a [settings] table after it.
    let dotted = fullyCooledHome()
    dotted.texts["\(home)/.config/mise/config.toml"] = "settings.minimum_release_age = \"1d\"\n"
    let dottedStates = ReleaseCooldowns.inspect(makeAuditContext(files: dotted))
    check(ReleaseCooldowns.evaluate(dottedStates).status == .fail, "HA-F13: mise dotted key at 1 day -> fail")
    check(!ReleaseCooldowns.fixes(dottedStates).contains { $0.manager == .mise },
          "HA-F13 fix: a dotted mise key is not rewritten into an invalid document")
    check(ReleaseCooldownConfig.setting("settings.experimental = true\n", key: "minimum_release_age",
                                        literal: "\"7d\"", format: .toml(table: "settings")) == nil,
          "cooldown edit: no [settings] header after root keys that define it")

    // mise: another global file setting a shorter window wins over config.toml's week.
    let miseOther = fullyCooledHome()
    miseOther.texts["\(home)/.mise.toml"] = "[settings]\nminimum_release_age = \"0s\"\n"
    check(await cooldownFinding(miseOther)?.status == .unknown, "HA-F13: ~/.mise.toml at 0s -> unknown")
    let miseConfD = fullyCooledHome()
    miseConfD.entries["\(home)/.config/mise/conf.d"] = ["fast.toml"]
    miseConfD.texts["\(home)/.config/mise/conf.d/fast.toml"] = "[settings]\nminimum_release_age = \"1h\"\n"
    check(await cooldownFinding(miseConfD)?.status == .unknown, "HA-F13: a conf.d window of 1 hour -> unknown")

    // pip: a legacy [install] beats the current file's [global].
    let legacyInstall = fullyCooledHome()
    legacyInstall.texts["\(home)/.pip/pip.conf"] = "[install]\nuploaded-prior-to = P1D\n"
    let legacyStates = ReleaseCooldowns.inspect(makeAuditContext(files: legacyInstall))
    check(ReleaseCooldowns.evaluate(legacyStates).status == .fail, "HA-F13: legacy pip [install] P1D -> fail")
    check(!ReleaseCooldowns.fixes(legacyStates).contains { $0.manager == .pip },
          "HA-F13 fix: withheld when the written line would still be overridden")

    // pip: keys are case-insensitive with `_` read as `-`; the fix replaces that line.
    let spelled = FakeFileInspector(
        texts: ["\(home)/.config/pip/pip.conf": "[global]\nUploaded_Prior_To = P1D\n"],
        entries: [
            "\(mise)/python": ["3.12.13"],
            "\(mise)/python/3.12.13/lib": ["python3.12"],
            "\(mise)/python/3.12.13/lib/python3.12/site-packages": ["pip-26.2.2.dist-info"],
        ])
    let spelledWriter = FakeUserConfigWriter()
    let spelledCtx = makeAuditContext(files: spelled, userConfig: spelledWriter)
    check(await evaluateAudit("HA-F13", in: DomainF_Developer.checks, spelledCtx)?.status == .fail,
          "HA-F13: pip `Uploaded_Prior_To = P1D` is read as pip reads it -> fail")
    if let fix = ReleaseCooldowns.fixes(ReleaseCooldowns.inspect(spelledCtx)).first(where: { $0.manager == .pip }) {
        check(ReleaseCooldowns.apply(fix, ctx: spelledCtx), "HA-F13 fix: pip spelled key applied")
        check(spelledWriter.writes["\(home)/.config/pip/pip.conf"] == "[global]\nuploaded-prior-to = P7D\n",
              "HA-F13 fix: the variant spelling is replaced, not duplicated")
    } else {
        check(false, "HA-F13 fix: pip spelled key fix offered")
    }
    // An indented line is a continuation of the previous value, not a key.
    let continued = fullyCooledHome()
    continued.texts["\(home)/.config/pip/pip.conf"] =
        "[global]\nextra-index-url = https://a.example.test/simple\n    uploaded-prior-to = P7D\n"
    check(await cooldownFinding(continued)?.status == .fail, "HA-F13: an indented pip line is no setting")

    // pip: a short [install] value in the current file is fixed in [install].
    let installShort = fullyCooledHome()
    installShort.texts["\(home)/.config/pip/pip.conf"] = "[global]\nuploaded-prior-to = P7D\n[install]\nuploaded-prior-to = P1D\n"
    let installWriter = FakeUserConfigWriter()
    let installCtx = makeAuditContext(files: installShort, userConfig: installWriter)
    if let fix = ReleaseCooldowns.fixes(ReleaseCooldowns.inspect(installCtx)).first(where: { $0.manager == .pip }) {
        _ = ReleaseCooldowns.apply(fix, ctx: installCtx)
        check(installWriter.writes["\(home)/.config/pip/pip.conf"]
                == "[global]\nuploaded-prior-to = P7D\n[install]\nuploaded-prior-to = P7D\n",
              "HA-F13 fix: pip's winning [install] line is the one raised")
    } else {
        check(false, "HA-F13 fix: pip [install] fix offered")
    }

    // A file too large to read whole, or not UTF-8, is unreadable and never rewritten.
    let large = fullyCooledHome()
    large.texts["\(home)/.npmrc"] = String(repeating: "# padding line\n", count: 20_000)
    check(await cooldownFinding(large)?.status == .unknown, "HA-F13: an oversized ~/.npmrc -> unknown")
    let lossy = FakeFileInspector(texts: [
        "\(home)/.npmrc": "fund=false\n# caf\u{FFFD}\n",
        "/opt/homebrew/lib/node_modules/npm/package.json": #"{"version":"11.21.1"}"#,
    ])
    let lossyStates = ReleaseCooldowns.inspect(makeAuditContext(files: lossy))
    check(ReleaseCooldowns.evaluate(lossyStates).status == .unknown && ReleaseCooldowns.fixes(lossyStates).isEmpty,
          "HA-F13: a ~/.npmrc that was not UTF-8 -> unknown, no fix")

    // A symlinked directory on the way withholds the fix and says why.
    let linkedDir = FakeFileInspector(entries: ["\(mise)/uv": ["0.13.1"]], symlinks: ["\(home)/.config"])
    let linkedStates = ReleaseCooldowns.inspect(makeAuditContext(files: linkedDir))
    check(ReleaseCooldowns.fixes(linkedStates).isEmpty
            && ReleaseCooldowns.evaluate(linkedStates).evidence.contains("~/.config is a link"),
          "HA-F13 fix: withheld when ~/.config is a link")

    // Yarn 4.10 and 4.14 read the same file: one row, one write.
    let twoYarns = FakeFileInspector(entries: ["\(corepack)/yarn": ["4.10.3", "4.14.1"]])
    let yarnFix = ReleaseCooldowns.fixes(ReleaseCooldowns.inspect(makeAuditContext(files: twoYarns)))
        .first { $0.manager == .yarn }
    check(yarnFix?.settings.count == 1, "HA-F13 fix: two Yarns sharing ~/.yarnrc.yml get one write")
}

// MARK: The real writer

private func releaseCooldownWriterTests() {
    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("csec-cooldown-\(UUID().uuidString)").path
    defer { try? fm.removeItem(atPath: root) }
    guard (try? fm.createDirectory(atPath: root, withIntermediateDirectories: false)) != nil else {
        check(false, "cooldown writer: temporary home could not be created")
        return
    }
    let writer = SystemUserConfigWriter()

    // Missing directories are created 0700 and a new file is 0600.
    check(writer.replace(home: root, relativePath: ".config/uv/uv.toml", contents: "exclude-newer = \"7 days\"\n"),
          "cooldown writer: writes a new file under new directories")
    check((try? String(contentsOfFile: "\(root)/.config/uv/uv.toml", encoding: .utf8)) == "exclude-newer = \"7 days\"\n",
          "cooldown writer: the new file holds exactly the contents")
    let fileMode = (try? fm.attributesOfItem(atPath: "\(root)/.config/uv/uv.toml"))?[.posixPermissions] as? Int
    let dirMode = (try? fm.attributesOfItem(atPath: "\(root)/.config/uv"))?[.posixPermissions] as? Int
    check(fileMode == 0o600 && dirMode == 0o700, "cooldown writer: new file 0600, new directories 0700")

    // An existing file keeps its mode, and no temporary file is left behind.
    fm.createFile(atPath: "\(root)/.npmrc", contents: Data("fund=false\n".utf8), attributes: [.posixPermissions: 0o644])
    check(writer.replace(home: root, relativePath: ".npmrc", contents: "fund=false\nmin-release-age=7\n"),
          "cooldown writer: replaces an existing file")
    check(((try? fm.attributesOfItem(atPath: "\(root)/.npmrc"))?[.posixPermissions] as? Int) == 0o644,
          "cooldown writer: an existing file keeps its mode")
    check(((try? fm.contentsOfDirectory(atPath: root)) ?? []).allSatisfy { !$0.hasSuffix(".tmp") },
          "cooldown writer: no temporary file is left behind")

    // A symlinked file or directory is refused, and its target is untouched.
    let target = "\(root)/elsewhere"
    fm.createFile(atPath: target, contents: Data("untouched\n".utf8))
    try? fm.createSymbolicLink(atPath: "\(root)/.yarnrc.yml", withDestinationPath: target)
    check(!writer.replace(home: root, relativePath: ".yarnrc.yml", contents: "npmMinimalAgeGate: 7d\n"),
          "cooldown writer: a symlinked file is refused")
    try? fm.createDirectory(atPath: "\(root)/real-bundle", withIntermediateDirectories: false)
    try? fm.createSymbolicLink(atPath: "\(root)/.bundle", withDestinationPath: "\(root)/real-bundle")
    check(!writer.replace(home: root, relativePath: ".bundle/config", contents: "BUNDLE_COOLDOWN: \"7\"\n"),
          "cooldown writer: a symlinked directory is refused")
    check((try? String(contentsOfFile: target, encoding: .utf8)) == "untouched\n"
            && !fm.fileExists(atPath: "\(root)/real-bundle/config"),
          "cooldown writer: nothing is written through a link")
    check(!writer.replace(home: root, relativePath: "../escape", contents: "x"),
          "cooldown writer: a path leaving the home is refused")
}
