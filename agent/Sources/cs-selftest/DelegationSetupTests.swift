import Foundation
import ConvenientSecurity
import Darwin

// Turning delegated approvals on and off: the settings edits (planEnable,
// planRevert), the transaction with csecd (a recording fake client), the
// uninstall revert, the status rows, and the typed-id CLI against a fake
// csecd. Synthetic files and a synthetic csecd only.

private let setupCsecPath = "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"

private struct SetupFixture {
    let root: URL
    var home: String { root.appendingPathComponent("home").path }
    var settings: String { home + "/.claude/settings.json" }

    init(_ tag: String) throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("csec-dsetup-\(tag)-\(UUID().uuidString.prefix(8))").resolvingSymlinksInPath()
        try FileManager.default.createDirectory(
            atPath: root.path + "/home/.claude", withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        chmod(root.path, 0o700)
    }

    func scope(configDirectory: String? = nil) -> ClaudeSettingsScope {
        ClaudeSettingsScope(
            homeDirectory: home, claudeConfigDirectory: configDirectory, workingDirectories: [home],
            managedSettingsDirectory: root.path + "/managed", managedPreferencesDirectory: root.path + "/prefs",
            userName: "synthetic", csecExecutablePath: setupCsecPath)
    }

    /// The settings file exactly as `csec setup` step 3 writes it: the hook
    /// and csec's standard auto-mode entry, with the user's other settings.
    func writeStepThreeSettings(extra: [String: Any] = [:], path: String? = nil) throws {
        let file = path ?? settings
        let detection = CodingAgentDetection(
            client: .claude, executablePath: nil, configurationPath: file, configurationExists: false)
        if !extra.isEmpty {
            try JSONSerialization.data(withJSONObject: extra).write(to: URL(fileURLWithPath: file))
            chmod(file, 0o600)
        }
        try CodingAgentSetup.apply(try CodingAgentSetup.planClaudeAutoModeEnvironment(
            basedOn: try CodingAgentSetup.plan(detection: detection, csecExecutablePath: setupCsecPath)))
    }

    func bytes(_ path: String? = nil) -> Data? { FileManager.default.contents(atPath: path ?? settings) }

    func object(_ path: String? = nil) -> [String: Any] {
        bytes(path).flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
    }

    func autoMode(_ path: String? = nil) -> [String: Any] { object(path)["autoMode"] as? [String: Any] ?? [:] }

    func cleanUp() { try? FileManager.default.removeItem(at: root) }
}

/// A csecd stand-in for `configure_delegation`: records each request, can look
/// at the settings file when a request arrives, and answers from a script.
private final class FakeDelegationClient: ClaudeDelegationConfiguring, @unchecked Sendable {
    private let lock = NSLock()
    private(set) var requests: [DelegationConfigurationRequest] = []
    var answer: (DelegationConfigurationRequest) throws -> DelegationConfigurationOutcome
    var observe: ((DelegationConfigurationRequest) -> Void)?

    init(answer: @escaping (DelegationConfigurationRequest) throws -> DelegationConfigurationOutcome) {
        self.answer = answer
    }

    func configureDelegation(_ request: DelegationConfigurationRequest) throws -> DelegationConfigurationOutcome {
        lock.lock()
        requests.append(request)
        lock.unlock()
        observe?(request)
        return try answer(request)
    }
}

private func onStatus(path: String?, csecAdded: Bool, state: DelegationState = .on) -> DelegationStatus {
    DelegationStatus(state: state, policyVersion: 1, consentedPolicyVersion: state == .on ? 1 : nil,
                     setClassifyAllShell: csecAdded, claudeSettingsPath: path)
}

func delegationSetupTests() async {
    print("\n# Delegated approvals: setup, disable, uninstall")
    do {
        try delegationEditPlanTests()
        try delegationEnableTransactionTests()
        try delegationDisableAndUninstallTests()
        try delegationRefusedUninstallTests()
        try delegationSharedAccountTests()
    } catch {
        check(false, "delegation setup fixtures set up (\(error))")
    }
    delegationStatusRowTests()
    typedIDParsingTests()
    #if DEBUG
    await typedIDCommandTests()
    #endif
}

/// What `csec revoke` parses before it asks csecd anything.
private func typedIDParsingTests() {
    let pairing = GrantIDSelector("PAIR-AB12")
    check(pairing?.kind == .pairing && pairing?.prefix == "ab12"
          && pairing?.matches(id: "ab12cd34-0000-4000-8000-000000000001") == true
          && pairing?.matches(id: "cd34ab12-0000-4000-8000-000000000001") == false,
          "typed ids: pair-ab12 is a prefix within pairings, case-insensitively")
    check(GrantIDSelector("ab12")?.kind == .secret && GrantIDSelector("grant-ab12")?.kind == .secret
          && GrantIDSelector("ssh-ab12")?.kind == .ssh && GrantIDSelector("build-ab12")?.kind == .build
          && GrantIDSelector("hook-ab12")?.kind == .hook,
          "typed ids: a bare hex id names a secret grant; each prefix names its kind")
    check(["foo-12", "pair-", "pair-xyz", "hook-12 34", ""].allSatisfy { GrantIDSelector($0) == nil },
          "typed ids: an unknown kind, an empty id and a non-hex id are refused")
}

// MARK: - The settings edits

private func delegationEditPlanTests() throws {
    let fixture = try SetupFixture("plan")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    try fixture.writeStepThreeSettings(extra: ["theme": "dark", "permissions": ["allow": ["Bash(git status)"]]])
    let original = fixture.bytes()

    let enable = gate.planEnable(scope)
    guard case let .write(plan) = enable.outcome else {
        check(false, "enable plans one write to a step-3 settings file")
        return
    }
    check(enable.settingsPath == fixture.settings && enable.classifyAllShell == .add
          && enable.environmentEntry == .delegationAware && enable.csecAddsClassifyAllShell,
          "enable plans classifyAllShell (csec adds it) and the delegation-aware entry for the user settings file")
    check(fixture.bytes() == original, "planning enable writes nothing")
    try CodingAgentSetup.apply(plan)
    let enabled = fixture.object()
    let environment = fixture.autoMode()["environment"] as? [String]
    check(fixture.autoMode()["classifyAllShell"] as? Bool == true
          && environment == ["$defaults", CodingAgentSetup.ClaudeAutoModeEntry.delegationAware.text]
          && enabled["theme"] as? String == "dark"
          && (enabled["permissions"] as? [String: Any])?["allow"] as? [String] == ["Bash(git status)"]
          && CodingAgentHookStatus.claudeHookState(
              homeDirectory: fixture.home, pathEnvironment: "", csecExecutablePath: setupCsecPath)
              == .installed(autoModeContext: true),
          "enable writes exactly classifyAllShell and the delegation-aware entry; the hook and other settings stay")
    check(CodingAgentSetup.claudeAutoModeEntry(inSettingsAt: fixture.settings) == .delegationAware,
          "the settings now hold the delegation-aware entry")

    let again = gate.planEnable(scope)
    if case .nothingToChange = again.outcome {
        check(again.classifyAllShell == .alreadySet && !again.csecAddsClassifyAllShell && again.environmentEntry == .unchanged,
              "enabling again changes nothing and records nothing new")
    } else {
        check(false, "enabling again changes nothing")
    }

    // Step 3 never flips the entry: either of csec's entries is current.
    let hookPlan = try CodingAgentSetup.plan(
        detection: CodingAgentDetection(client: .claude, executablePath: nil, configurationPath: fixture.settings,
                                        configurationExists: true),
        csecExecutablePath: setupCsecPath)
    let either = try CodingAgentSetup.planClaudeAutoModeEnvironment(basedOn: hookPlan)
    let aware = try CodingAgentSetup.planClaudeAutoModeEnvironment(basedOn: hookPlan, entry: .delegationAware)
    let standard = try CodingAgentSetup.planClaudeAutoModeEnvironment(basedOn: hookPlan, entry: .standard)
    check(either.action == .unchanged && aware.action == .unchanged && standard.action == .merge
          && standard.preview == CodingAgentSetup.claudeAutoModeEnvironmentEntry,
          "refreshing the hook keeps the delegation-aware entry unless asked for the standard one")

    let revert = gate.planRevert(scope, recordedSettingsPath: fixture.settings, csecAddedClassifyAllShell: true)
    guard case let .write(revertPlan) = revert.outcome else {
        check(false, "the revert plans one write")
        return
    }
    check(revert.classifyAllShell == .remove && revert.environmentEntry == .standard,
          "the revert removes csec's classifyAllShell and restores the standard entry")
    try CodingAgentSetup.apply(revertPlan)
    check(fixture.bytes() == original, "enable then revert leaves the settings byte-for-byte as they were")

    // classifyAllShell the user set is left alone, going in and coming out.
    try fixture.writeStepThreeSettings(extra: ["autoMode": ["classifyAllShell": true, "environment": ["$defaults"]]])
    let userSet = fixture.bytes()
    let userEnable = gate.planEnable(scope)
    check(userEnable.classifyAllShell == .alreadySet && !userEnable.csecAddsClassifyAllShell,
          "a classifyAllShell the user set is not recorded as csec's")
    if case let .write(plan) = userEnable.outcome { try CodingAgentSetup.apply(plan) }
    let userRevert = gate.planRevert(scope, recordedSettingsPath: fixture.settings, csecAddedClassifyAllShell: false)
    if case let .write(plan) = userRevert.outcome { try CodingAgentSetup.apply(plan) }
    check(userRevert.classifyAllShell == .leave && fixture.autoMode()["classifyAllShell"] as? Bool == true
          && fixture.bytes() == userSet,
          "csec did not add classifyAllShell, so the revert leaves it and the file is as it was")

    // A classifyAllShell the user turned off after enabling is theirs now.
    if case let .write(plan) = gate.planEnable(scope).outcome { try CodingAgentSetup.apply(plan) }
    var edited = fixture.object()
    var autoMode = edited["autoMode"] as? [String: Any] ?? [:]
    autoMode["classifyAllShell"] = false
    edited["autoMode"] = autoMode
    try JSONSerialization.data(withJSONObject: edited).write(to: URL(fileURLWithPath: fixture.settings))
    let changedRevert = gate.planRevert(scope, recordedSettingsPath: fixture.settings, csecAddedClassifyAllShell: true)
    if case let .write(plan) = changedRevert.outcome { try CodingAgentSetup.apply(plan) }
    check(changedRevert.classifyAllShell == .unchanged && fixture.autoMode()["classifyAllShell"] as? Bool == false
          && CodingAgentSetup.claudeAutoModeEntry(inSettingsAt: fixture.settings) == .standard,
          "a classifyAllShell the user changed is not removed; the entry still goes back")

    // A revert never adds an entry csec does not have there.
    try JSONSerialization.data(withJSONObject: ["theme": "light"]).write(to: URL(fileURLWithPath: fixture.settings))
    if case .nothingToChange = gate.planRevert(scope, recordedSettingsPath: nil, csecAddedClassifyAllShell: false).outcome {
        check(true, "a revert of a file without csec's edits changes nothing")
    } else {
        check(false, "a revert of a file without csec's edits changes nothing")
    }

    // Unsafe or malformed files are blocked, never rewritten. A revert reads
    // the file too, and refuses what it cannot read safely; a key it would not
    // touch anyway (a classifyAllShell that is not true) leaves it nothing to do.
    let blockedCases: [(String, revertBlocked: Bool, () throws -> Void)] = [
        ("a non-object autoMode", true, {
            try JSONSerialization.data(withJSONObject: ["autoMode": "on"]).write(to: URL(fileURLWithPath: fixture.settings))
        }),
        ("a non-boolean classifyAllShell", false, {
            try JSONSerialization.data(withJSONObject: ["autoMode": ["classifyAllShell": "yes"]])
                .write(to: URL(fileURLWithPath: fixture.settings))
        }),
        ("a duplicate key", true, {
            try Data("{\"a\": 1, \"a\": 2}".utf8).write(to: URL(fileURLWithPath: fixture.settings))
        }),
        ("a group-writable file", true, {
            try JSONSerialization.data(withJSONObject: ["theme": "x"]).write(to: URL(fileURLWithPath: fixture.settings))
            chmod(fixture.settings, 0o660)
        }),
        ("a symlinked file", true, {
            try? FileManager.default.removeItem(atPath: fixture.settings)
            let target = fixture.root.path + "/elsewhere.json"
            try JSONSerialization.data(withJSONObject: ["theme": "x"]).write(to: URL(fileURLWithPath: target))
            try FileManager.default.createSymbolicLink(atPath: fixture.settings, withDestinationPath: target)
        }),
    ]
    for (name, revertBlocked, prepare) in blockedCases {
        try? FileManager.default.removeItem(atPath: fixture.settings)
        try prepare()
        let before = fixture.bytes()
        let enablePlan = gate.planEnable(scope)
        let revertPlan = gate.planRevert(scope, recordedSettingsPath: nil, csecAddedClassifyAllShell: true)
        var enableBlocked = false
        if case .blocked = enablePlan.outcome { enableBlocked = true }
        var revertAsExpected = false
        switch revertPlan.outcome {
        case .blocked: revertAsExpected = revertBlocked
        case .nothingToChange: revertAsExpected = !revertBlocked
        case .write: revertAsExpected = false
        }
        check(enableBlocked && revertAsExpected && !enablePlan.csecAddsClassifyAllShell && fixture.bytes() == before,
              "enable refuses \(name), the revert \(revertBlocked ? "refuses it" : "has nothing to undo"), "
                  + "and nothing is written")
    }
    try? FileManager.default.removeItem(atPath: fixture.settings)

    // L1: a file in Claude Code's own format (two-space indent, keys in
    // insertion order) with no csec entry. Enable adds the delegation-aware
    // entry marked as added, and the revert takes it out again: the file
    // means what it meant before, though csec writes its own format.
    let claudeFormatted = """
        {
          "permissions": {
            "defaultMode": "auto",
            "allow": ["Bash(git status)"]
          },
          "autoMode": {
            "environment": [
              "$defaults",
              "**Organization**: Example Ltd"
            ]
          },
          "theme": "dark"
        }

        """
    try Data(claudeFormatted.utf8).write(to: URL(fileURLWithPath: fixture.settings))
    chmod(fixture.settings, 0o600)
    let meaning = fixture.object() as NSDictionary
    if case let .write(plan) = gate.planEnable(scope).outcome { try CodingAgentSetup.apply(plan) }
    check(fixture.autoMode()["environment"] as? [String]
            == ["$defaults", "**Organization**: Example Ltd", CodingAgentSetup.claudeAutoModeDelegationEnvironmentEntryAdded],
          "L1: where csec had no entry, enable adds the delegation-aware entry marked as added")
    if case let .write(plan) = gate.planRevert(
        scope, recordedSettingsPath: fixture.settings, csecAddedClassifyAllShell: true).outcome {
        try CodingAgentSetup.apply(plan)
    }
    check(fixture.object() as NSDictionary == meaning && fixture.bytes() != Data(claudeFormatted.utf8),
          "L1: enable then revert restores a Claude Code-formatted file in meaning (keys csec added removed, "
              + "values it changed restored), not in bytes")

    // With no autoMode at all, the revert leaves `environment: ["$defaults"]`,
    // which means what no list means.
    try JSONSerialization.data(withJSONObject: ["theme": "dark"]).write(to: URL(fileURLWithPath: fixture.settings))
    if case let .write(plan) = gate.planEnable(scope).outcome { try CodingAgentSetup.apply(plan) }
    if case let .write(plan) = gate.planRevert(
        scope, recordedSettingsPath: fixture.settings, csecAddedClassifyAllShell: true).outcome {
        try CodingAgentSetup.apply(plan)
    }
    check(fixture.object()["theme"] as? String == "dark"
          && fixture.autoMode() as NSDictionary == ["environment": ["$defaults"]] as NSDictionary,
          "L1: a revert where csec created autoMode leaves only [\"$defaults\"], the built-in list")
    try? FileManager.default.removeItem(atPath: fixture.settings)

    // A missing settings file: enable creates it; a revert has nothing to do.
    let fresh = gate.planEnable(scope)
    if case let .write(plan) = fresh.outcome {
        check(plan.action == .create && fresh.classifyAllShell == .add, "enable creates a missing settings file")
    } else {
        check(false, "enable creates a missing settings file")
    }
    let missing = gate.planRevert(
        scope, recordedSettingsPath: fixture.root.path + "/gone/deeper/settings.json", csecAddedClassifyAllShell: true)
    if case .nothingToChange = missing.outcome {
        check(missing.settingsPath == fixture.root.path + "/gone/deeper/settings.json",
              "a revert of a recorded file that no longer exists changes nothing")
    } else {
        check(false, "a revert of a recorded file that no longer exists changes nothing")
    }
}

// MARK: - The enable transaction

private func delegationEnableTransactionTests() throws {
    let fixture = try SetupFixture("enable")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    try fixture.writeStepThreeSettings()
    let original = fixture.bytes()
    let off = DelegationStatus(state: .off, policyVersion: 1)

    // Writes, then asks csecd: csecd sees the edited file when enable arrives.
    var classifyAtEnable: Bool?
    let client = FakeDelegationClient { request in
        .configured(onStatus(path: request.claudeSettingsPath, csecAdded: request.setClassifyAllShell ?? false),
                    removed: [])
    }
    client.observe = { request in
        if request.action == .enable { classifyAtEnable = fixture.autoMode()["classifyAllShell"] as? Bool }
    }
    let result = ClaudeDelegationSetup.enable(
        plan: gate.planEnable(scope), recorded: off, projectDirectory: fixture.home,
        client: client, gate: gate, scope: scope)
    let request = client.requests.first
    check(client.requests.count == 1 && request?.action == .enable && request?.setClassifyAllShell == true
          && request?.claudeSettingsPath == fixture.settings && request?.projectDirectory == fixture.home
          && request?.isWellFormed == true,
          "enable sends one request recording that csec added classifyAllShell, and to which file")
    check(classifyAtEnable == true, "the settings are written before csecd is asked to enable")
    if case .enabled = result {
        check(fixture.autoMode()["classifyAllShell"] as? Bool == true, "an approved enable keeps the edits")
    } else {
        check(false, "an approved enable reports enabled")
    }

    // Touch ID refused: this run's edits are undone byte for byte.
    try? FileManager.default.removeItem(atPath: fixture.settings)
    try fixture.writeStepThreeSettings()
    let denying = FakeDelegationClient { _ in throw AgentClient.ClientError.denied("you pressed Deny") }
    let denied = ClaudeDelegationSetup.enable(
        plan: gate.planEnable(scope), recorded: off, projectDirectory: nil, client: denying, gate: gate, scope: scope)
    if case let .denied(reason, undo) = denied {
        check(undo?.result == .reverted && fixture.bytes() == original,
              "a refused Touch ID undoes the settings edits, leaving the file as it was")
        check(reason == "you pressed Deny", "a refused Touch ID carries csecd's reason for setup to show")
    } else {
        check(false, "a refused Touch ID reports denied")
    }

    // csecd failing: undone too.
    let failing = FakeDelegationClient { _ in throw AgentClient.ClientError.transportFailed }
    let failed = ClaudeDelegationSetup.enable(
        plan: gate.planEnable(scope), recorded: off, projectDirectory: nil, client: failing, gate: gate, scope: scope)
    if case let .failed(_, undo) = failed {
        check(undo?.result == .reverted && fixture.bytes() == original, "a failed enable undoes the settings edits")
    } else {
        check(false, "a failed enable reports failed")
    }

    // L2: a refused re-confirmation undoes only what it wrote. Delegation is
    // on (the delegation-aware entry is in place) and the user removed
    // classifyAllShell by hand; the restore adds it back, Touch ID is refused,
    // and the entry stays delegation-aware.
    if case let .write(plan) = gate.planEnable(scope).outcome { try CodingAgentSetup.apply(plan) }
    var handEdited = fixture.object()
    var handAutoMode = handEdited["autoMode"] as? [String: Any] ?? [:]
    handAutoMode["classifyAllShell"] = nil
    handEdited["autoMode"] = handAutoMode
    try JSONSerialization.data(withJSONObject: handEdited, options: [.prettyPrinted, .sortedKeys])
        .write(to: URL(fileURLWithPath: fixture.settings))
    let beforeRefusal = fixture.object() as NSDictionary
    let restore = gate.planEnable(scope)
    check(restore.classifyAllShell == .add && restore.environmentEntry == .unchanged,
          "L2: restoring a hand-removed classifyAllShell leaves the delegation-aware entry alone")
    let refusedRestore = ClaudeDelegationSetup.enable(
        plan: restore, recorded: onStatus(path: fixture.settings, csecAdded: true), projectDirectory: nil,
        client: denying, gate: gate, scope: scope)
    if case let .denied(_, undo) = refusedRestore {
        check(undo?.environmentEntry == .unchanged && fixture.object() as NSDictionary == beforeRefusal
              && CodingAgentSetup.claudeAutoModeEntry(inSettingsAt: fixture.settings) == .delegationAware,
              "L2: a refused re-confirmation removes the classifyAllShell it added and keeps the delegation-aware entry")
    } else {
        check(false, "L2: a refused re-confirmation reports denied")
    }
    try? FileManager.default.removeItem(atPath: fixture.settings)
    try fixture.writeStepThreeSettings()

    // A path csecd would refuse is caught before anything is written.
    let unrecordable = ClaudeSettingsEditPlan(
        settingsPath: "/" + String(repeating: "d", count: 4_090) + "/settings.json",
        classifyAllShell: .add, environmentEntry: .delegationAware, outcome: .nothingToChange)
    let neverAsked = FakeDelegationClient { _ in .configured(off, removed: []) }
    let refused = ClaudeDelegationSetup.enable(
        plan: unrecordable, recorded: off, projectDirectory: nil, client: neverAsked, gate: gate, scope: scope)
    if case .notStarted = refused {
        check(neverAsked.requests.isEmpty && fixture.bytes() == original,
              "an enable request csecd would refuse is never sent, and nothing is written")
    } else {
        check(false, "an unrecordable settings path does not start")
    }

    // A blocked plan starts nothing.
    let blockedPlan = ClaudeSettingsEditPlan(
        settingsPath: fixture.settings, classifyAllShell: .unchanged, environmentEntry: .unchanged,
        outcome: .blocked("synthetic"))
    if case .notStarted = ClaudeDelegationSetup.enable(
        plan: blockedPlan, recorded: off, projectDirectory: nil, client: neverAsked, gate: gate, scope: scope) {
        check(neverAsked.requests.isEmpty, "a blocked plan asks csecd nothing")
    } else {
        check(false, "a blocked plan does not start")
    }

    // CLAUDE_CONFIG_DIR changed since enable: the new file is edited and
    // recorded, then the recorded one is reverted.
    let oldConfig = fixture.root.path + "/old-config"
    try FileManager.default.createDirectory(atPath: oldConfig, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    let oldSettings = oldConfig + "/settings.json"
    try fixture.writeStepThreeSettings(path: oldSettings)
    let oldOriginal = fixture.bytes(oldSettings)
    if case let .write(plan) = CodingAgentSetup.planClaudeDelegationEnable(settingsPath: oldSettings).outcome {
        try CodingAgentSetup.apply(plan)
    }
    let oldEnabled = fixture.bytes(oldSettings)
    let newOriginal = fixture.bytes()
    // A refused move changes neither file: the recorded one, which every
    // session without this CLAUDE_CONFIG_DIR reads, keeps csec's settings.
    let refusedMove = ClaudeDelegationSetup.enable(
        plan: gate.planEnable(scope), recorded: onStatus(path: oldSettings, csecAdded: true), projectDirectory: nil,
        client: denying, gate: gate, scope: scope)
    if case .denied = refusedMove {
        check(fixture.bytes(oldSettings) == oldEnabled && fixture.bytes() == newOriginal,
              "a refused move under a new CLAUDE_CONFIG_DIR leaves the recorded file and the new one as they were")
    } else {
        check(false, "a refused move under a new CLAUDE_CONFIG_DIR reports denied")
    }
    let failedMove = ClaudeDelegationSetup.enable(
        plan: gate.planEnable(scope), recorded: onStatus(path: oldSettings, csecAdded: true), projectDirectory: nil,
        client: failing, gate: gate, scope: scope)
    if case .failed = failedMove {
        check(fixture.bytes(oldSettings) == oldEnabled && fixture.bytes() == newOriginal,
              "a failed move under a new CLAUDE_CONFIG_DIR leaves both files as they were")
    } else {
        check(false, "a failed move under a new CLAUDE_CONFIG_DIR reports failed")
    }
    let moving = FakeDelegationClient { request in
        // The recorded file is reverted only once csecd has recorded the new one.
        check(fixture.bytes(oldSettings) == oldEnabled,
              "a move keeps the recorded file's settings while csecd's sheet is up")
        return .configured(onStatus(path: request.claudeSettingsPath, csecAdded: true), removed: [])
    }
    let moved = ClaudeDelegationSetup.enable(
        plan: gate.planEnable(scope), recorded: onStatus(path: oldSettings, csecAdded: true), projectDirectory: nil,
        client: moving, gate: gate, scope: scope)
    if case let .enabled(_, replaced) = moved {
        check(replaced?.result == .reverted && fixture.bytes(oldSettings) == oldOriginal
              && fixture.autoMode()["classifyAllShell"] as? Bool == true
              && moving.requests.first?.claudeSettingsPath == fixture.settings,
              "enabling under a new CLAUDE_CONFIG_DIR records the new file and reverts the recorded one")
    } else {
        check(false, "enabling under a new CLAUDE_CONFIG_DIR succeeds")
    }
}

// MARK: - An account config dir linked to ~/.claude

/// An extra Claude account whose `CLAUDE_CONFIG_DIR/settings.json` is a link
/// to `~/.claude/settings.json`: setup detects, edits and records the real
/// file, never the link, and asks to move nothing.
private func delegationSharedAccountTests() throws {
    let fixture = try SetupFixture("shared")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let account = fixture.root.path + "/accounts/second"
    try FileManager.default.createDirectory(atPath: account, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    let accountSettings = account + "/settings.json"
    try fixture.writeStepThreeSettings()
    _ = symlink(fixture.settings, accountSettings)
    let scope = fixture.scope(configDirectory: account)

    let detected = try CodingAgentSetup.detect(
        homeDirectory: fixture.home, pathEnvironment: "", claudeConfigDirectory: account
    ).first { $0.client == .claude }
    check(detected?.configurationPath == fixture.settings
            && (try? CodingAgentSetup.plan(detection: detected!, csecExecutablePath: setupCsecPath))?.action
                == .unchanged
            && CodingAgentHookStatus.claudeHookState(
                homeDirectory: fixture.home, pathEnvironment: "", csecExecutablePath: setupCsecPath,
                claudeConfigDirectory: account) == .installed(autoModeContext: true),
          "shared account: step 3 and status find csec's hook in ~/.claude/settings.json through the account's link")

    let plan = gate.planEnable(scope)
    check(plan.settingsPath == fixture.settings, "shared account: enabling plans an edit of ~/.claude/settings.json")
    let client = FakeDelegationClient { request in
        .configured(onStatus(path: request.claudeSettingsPath, csecAdded: request.setClassifyAllShell ?? false),
                    removed: [])
    }
    let result = ClaudeDelegationSetup.enable(
        plan: plan, recorded: DelegationStatus(state: .off, policyVersion: 1), projectDirectory: fixture.home,
        client: client, gate: gate, scope: scope)
    var linkInfo = stat()
    let stillLinked = lstat(accountSettings, &linkInfo) == 0 && linkInfo.st_mode & S_IFMT == S_IFLNK
        && (try? FileManager.default.destinationOfSymbolicLink(atPath: accountSettings)) == fixture.settings
    if case let .enabled(_, replaced) = result {
        check(replaced == nil && client.requests.first?.claudeSettingsPath == fixture.settings
                && client.requests.first?.claudeConfigDirectory == account
                && fixture.autoMode()["classifyAllShell"] as? Bool == true && stillLinked,
              "shared account: enable edits and records ~/.claude/settings.json, moves nothing, and leaves the "
                + "account's settings.json a link to it")
    } else {
        check(false, "shared account: enable succeeds")
    }
    check(gate.planEnable(scope).settingsPath == onStatus(path: fixture.settings, csecAdded: true).claudeSettingsPath
            && gate.planEnable(fixture.scope()).settingsPath == fixture.settings,
          "shared account: the recorded file is the one every account plans, so setup offers no move")
    check(gate.planRevert(scope, recordedSettingsPath: nil, csecAddedClassifyAllShell: true).settingsPath
            == fixture.settings,
          "shared account: with no record, a revert edits ~/.claude/settings.json too")

    // The real file is held to setup's usual checks.
    chmod(fixture.settings, 0o620)
    if case .blocked = gate.planEnable(scope).outcome {
        check(true, "shared account: a group-writable ~/.claude/settings.json is not edited")
    } else {
        check(false, "shared account: a group-writable ~/.claude/settings.json is not edited")
    }
    chmod(fixture.settings, 0o600)
    try? FileManager.default.removeItem(atPath: accountSettings)
    _ = Darwin.link(fixture.settings, accountSettings)
    let hardLinked = gate.planEnable(scope)
    if hardLinked.settingsPath == fixture.settings, case .blocked = hardLinked.outcome {
        check(true, "shared account: a hard-linked settings file is the same file, and setup still refuses to edit it")
    } else {
        check(false, "shared account: a hard-linked settings file is the same file, and setup still refuses to edit it")
    }

    // A separate file in the account is the account's own.
    try? FileManager.default.removeItem(atPath: accountSettings)
    try FileManager.default.copyItem(atPath: fixture.settings, toPath: accountSettings)
    check(gate.planEnable(scope).settingsPath == accountSettings,
          "shared account: an account's own settings.json is edited where it is")
}

// MARK: - Disable and uninstall

private func delegationDisableAndUninstallTests() throws {
    let fixture = try SetupFixture("disable")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    try fixture.writeStepThreeSettings()
    let original = fixture.bytes()

    func enable() throws {
        if case let .write(plan) = gate.planEnable(scope).outcome { try CodingAgentSetup.apply(plan) }
    }

    // Disable reads the record first, reverts exactly it, then disables.
    try enable()
    let recording = FakeDelegationClient { request in
        switch request.action {
        case .status: return .configured(onStatus(path: fixture.settings, csecAdded: true), removed: [])
        default: return .configured(DelegationStatus(state: .off, policyVersion: 1), removed: [])
        }
    }
    var revertedBeforeDisable = false
    recording.observe = { request in
        if request.action == .disable { revertedBeforeDisable = fixture.bytes() == original }
    }
    let disabled = ClaudeDelegationSetup.disable(
        projectDirectory: fixture.home, client: recording, gate: gate, scope: scope)
    check(recording.requests.map(\.action) == [.status, .disable] && revertedBeforeDisable,
          "disable reads csecd's record, reverts the settings, then asks csecd to disable")
    if case let .disabled(status, revert) = disabled {
        check(status.state == .off && revert.result == .reverted && revert.classifyAllShell == .remove
              && fixture.bytes() == original,
              "disable reverts the settings byte for byte, removing the classifyAllShell csec added")
    } else {
        check(false, "disable reports disabled")
    }

    // The user had set classifyAllShell themselves: it stays.
    try fixture.writeStepThreeSettings(extra: ["autoMode": ["classifyAllShell": true, "environment": ["$defaults"]]])
    let userOriginal = fixture.bytes()
    try enable()
    let userRecord = FakeDelegationClient { request in
        request.action == .status
            ? .configured(onStatus(path: fixture.settings, csecAdded: false), removed: [])
            : .configured(DelegationStatus(state: .off, policyVersion: 1), removed: [])
    }
    if case let .disabled(_, revert) = ClaudeDelegationSetup.disable(
        projectDirectory: nil, client: userRecord, gate: gate, scope: scope) {
        check(revert.classifyAllShell == .leave && fixture.autoMode()["classifyAllShell"] as? Bool == true
              && fixture.bytes() == userOriginal,
              "csec did not add classifyAllShell, so disable leaves it and the file is as it was")
    } else {
        check(false, "disable with a user-set classifyAllShell reports disabled")
    }

    // Uninstall shares the one revert: from the record, or without one.
    try? FileManager.default.removeItem(atPath: fixture.settings)
    try fixture.writeStepThreeSettings()
    try enable()
    let uninstall = ClaudeDelegationSetup.revertRecordedSettings(
        status: onStatus(path: fixture.settings, csecAdded: true), gate: gate, scope: scope)
    check(uninstall.result == .reverted && fixture.bytes() == original && uninstall.manualInstructions == nil,
          "the uninstall revert with csecd's record restores the file byte for byte")

    try enable()
    let unknown = ClaudeDelegationSetup.revertRecordedSettings(status: nil, gate: gate, scope: scope)
    check(unknown.result == .reverted && unknown.classifyAllShell == .leave
          && fixture.autoMode()["classifyAllShell"] as? Bool == true
          && CodingAgentSetup.claudeAutoModeEntry(inSettingsAt: fixture.settings) == .standard,
          "without csecd's record the uninstall revert restores the entry and leaves classifyAllShell")

    // The recorded file wins over the scope's.
    let other = fixture.root.path + "/other-config"
    try FileManager.default.createDirectory(atPath: other, withIntermediateDirectories: true,
                                            attributes: [.posixPermissions: 0o700])
    try? FileManager.default.removeItem(atPath: fixture.settings)
    try fixture.writeStepThreeSettings()
    try enable()
    let elsewhere = ClaudeDelegationSetup.revertRecordedSettings(
        status: onStatus(path: fixture.settings, csecAdded: true), gate: gate,
        scope: fixture.scope(configDirectory: other))
    check(elsewhere.settingsPath == fixture.settings && elsewhere.result == .reverted && fixture.bytes() == original,
          "the revert follows the recorded settings file whatever CLAUDE_CONFIG_DIR says now")

    // A revert that cannot be written names what to undo by hand.
    try enable()
    chmod(fixture.settings, 0o666)
    let stuck = ClaudeDelegationSetup.revertRecordedSettings(
        status: onStatus(path: fixture.settings, csecAdded: true), gate: gate, scope: scope)
    if case .notWritten = stuck.result {
        check(stuck.manualInstructions?.contains("autoMode.classifyAllShell (csec added it)") == true
              && stuck.manualInstructions?.contains(fixture.settings) == true,
              "a revert that cannot be written says which file and which keys to remove by hand")
    } else {
        check(false, "a revert of an unsafe file is not written")
    }
    chmod(fixture.settings, 0o600)
}

/// A refused `csec uninstall` changes nothing: what step one reverted before
/// csecd's Touch ID goes back, and a put-back that cannot be written says
/// which keys to restore.
private func delegationRefusedUninstallTests() throws {
    let fixture = try SetupFixture("refused-uninstall")
    defer { fixture.cleanUp() }
    let gate = makeClaudeSettingsGate()
    let scope = fixture.scope()
    func enable() throws {
        if case let .write(plan) = gate.planEnable(scope).outcome { try CodingAgentSetup.apply(plan) }
    }
    func settingsObject() -> NSDictionary? {
        (try? JSONSerialization.jsonObject(with: Data(contentsOf: URL(fileURLWithPath: fixture.settings)))) as? NSDictionary
    }

    // Each shape `csec setup` can leave: csec added classifyAllShell and the
    // entry; the user had set classifyAllShell; csec replaced its standard
    // entry with the delegation-aware one.
    let shapes: [(label: String, extra: [String: Any], csecAdded: Bool)] = [
        ("csec added classifyAllShell and its entry", [:], true),
        ("the user set classifyAllShell", ["autoMode": ["classifyAllShell": true, "environment": ["$defaults"]]], false),
        ("csec's standard entry was there", ["autoMode": ["environment": ["$defaults", CodingAgentSetup.claudeAutoModeEnvironmentEntry]]], true),
    ]
    for shape in shapes {
        try? FileManager.default.removeItem(atPath: fixture.settings)
        try fixture.writeStepThreeSettings(extra: shape.extra)
        try enable()
        let enabled = fixture.bytes()
        let enabledObject = settingsObject()
        let revert = ClaudeDelegationSetup.revertRecordedSettings(
            status: onStatus(path: fixture.settings, csecAdded: shape.csecAdded), gate: gate, scope: scope)
        let reverted = fixture.bytes() != enabled
        let reapply = ClaudeDelegationSetup.reapplyReverted(revert)
        check(revert.result == .reverted && reverted && reapply.result == .restored
                && settingsObject() == enabledObject && fixture.bytes() == enabled
                && CodingAgentSetup.claudeAutoModeEntry(inSettingsAt: fixture.settings) == .delegationAware,
              "refused uninstall (\(shape.label)): what step one reverted is put back, byte for byte")
        check(ClaudeDelegationSetup.refusedUninstallMessage(reapply) == "Touch ID was not given; nothing was uninstalled",
              "refused uninstall (\(shape.label)): the message says nothing was uninstalled")
    }

    // A revert that changed nothing puts nothing back.
    try? FileManager.default.removeItem(atPath: fixture.settings)
    try fixture.writeStepThreeSettings()
    let untouched = fixture.bytes()
    let nothing = ClaudeDelegationSetup.revertRecordedSettings(
        status: onStatus(path: fixture.settings, csecAdded: true), gate: gate, scope: scope)
    let nothingBack = ClaudeDelegationSetup.reapplyReverted(nothing)
    check(nothing.result == .nothingToChange && nothingBack.result == .nothingToChange && fixture.bytes() == untouched
          && ClaudeDelegationSetup.refusedUninstallMessage(nil) == "Touch ID was not given; nothing was uninstalled",
          "refused uninstall: a revert that changed nothing puts nothing back")

    // The put-back cannot be written: the message names the file and keys.
    try enable()
    let revert = ClaudeDelegationSetup.revertRecordedSettings(
        status: onStatus(path: fixture.settings, csecAdded: true), gate: gate, scope: scope)
    let revertedBytes = fixture.bytes()
    chmod(fixture.settings, 0o666)
    let stuck = ClaudeDelegationSetup.reapplyReverted(revert)
    chmod(fixture.settings, 0o600)
    let message = ClaudeDelegationSetup.refusedUninstallMessage(stuck)
    if case .notWritten = stuck.result {
        check(fixture.bytes() == revertedBytes
                && message.hasPrefix("Touch ID was not given, so csecd deleted nothing and the agent stays registered, "
                    + "but csec's auto-mode settings in \(fixture.settings) were reverted and could not be put back (")
                && message.hasSuffix("); put back autoMode.classifyAllShell: true and csec's auto-mode entry in "
                    + "autoMode.environment in \(fixture.settings), or run csec setup, which writes them again."),
              "refused uninstall: a put-back that cannot be written names the file and the keys to restore by hand")
    } else {
        check(false, "refused uninstall: a put-back into an unsafe file is not written")
    }
}

// MARK: - Status rows

private func delegationStatusRowTests() {
    let path = "/Users/synthetic/.claude/settings.json"
    func rows(_ report: ClaudeDelegationStatusRows.Report, remains: String? = nil) -> [StatusRow] {
        ClaudeDelegationStatusRows.rows(report, delegationEntryRemainsIn: remains, displayPath: { $0 })
    }
    func evaluation(
        classify: Bool = true, hooks: [ClaudeHookSource] = [], environment: [ClaudeSettingsEnvironmentFinding] = [],
        sandbox: [String] = [], unreadable: [ClaudeUnreadableSetting] = []
    ) -> ClaudeSettingsGateEvaluation {
        ClaudeSettingsGateEvaluation(
            classifyAllShell: ClaudeClassifyAllShellFinding(setIn: classify ? [path] : [], ignoredIn: []),
            hooks: hooks, environment: environment, sandboxEnabled: sandbox, bypassPermissionsDefault: [],
            hooksDisabled: [], unreadable: unreadable)
    }
    func onRow(_ settings: ClaudeSettingsGateEvaluation?, acknowledged: [AcknowledgedHookSummary] = []) -> StatusRow? {
        rows(.status(DelegationStatus(
            state: .on, policyVersion: 1, consentedPolicyVersion: 1, setClassifyAllShell: true, claudeSettingsPath: path,
            acknowledgedHooks: acknowledged, settings: settings,
            counters: DelegationCounters(approved: 7, declined: 2)))).first
    }

    let off = rows(.status(DelegationStatus(state: .off, policyVersion: 1)))
    check(off == [StatusRow(label: "Claude auto-mode approvals",
                            value: "off — csec setup can let auto mode approve secret use", state: .neutral)],
          "status: off is a neutral row pointing at csec setup")
    check(rows(.status(DelegationStatus(state: .off, policyVersion: 1)), remains: path).first?.state == .warn,
          "status: off with csec's delegation-aware text left in the settings warns")
    check(onRow(evaluation()) == StatusRow(
            label: "Claude auto-mode approvals", value: "on — 7 approved / 2 sent to Touch ID since csecd started",
            state: .ok),
          "status: on with every gate passing is ok and counts decisions since csecd started")
    check(onRow(evaluation(classify: false))?.value
            == "on, inactive: autoMode.classifyAllShell not set — run csec setup auto-mode"
          && onRow(evaluation(classify: false))?.state == .warn,
          "status: on without classifyAllShell (after a refused uninstall) says to re-run csec setup")
    let hook = ClaudeHookSource(kind: .settings, sourceID: path, event: "PreToolUse", matcher: "*",
                                digest: String(repeating: "a", count: 64), display: "~/.claude/settings.json · PreToolUse *",
                                fetchesUnpinnedCode: false)
    check(onRow(evaluation(hooks: [hook]))?.value
            == "on, inactive: ~/.claude/settings.json · PreToolUse * can approve shell commands — run csec setup auto-mode to review it",
          "status: an unacknowledged hook is named")
    check(onRow(evaluation(hooks: [hook]), acknowledged: [AcknowledgedHookSummary(
            digest: hook.digest, display: hook.display)])?.state == .ok,
          "status: an acknowledged hook passes")
    check(onRow(evaluation(sandbox: [path]))?.value == "on, inactive: sandbox.enabled in \(path)"
          && onRow(evaluation(environment: [ClaudeSettingsEnvironmentFinding(name: "ANTHROPIC_BASE_URL", path: path)]))?
            .value == "on, inactive: ANTHROPIC_BASE_URL set in \(path)"
          && onRow(evaluation(unreadable: [ClaudeUnreadableSetting(path: path, reason: .unparseable)]))?
            .value == "on, inactive: \(path) not valid settings",
          "status: sandbox, an injected environment name and an unreadable file are each named")
    let explained = rows(.status(DelegationStatus(
        state: .on, policyVersion: 1, consentedPolicyVersion: 1, setClassifyAllShell: true, claudeSettingsPath: path,
        settings: evaluation(), counters: DelegationCounters(approved: 1, declined: 1),
        lastDecline: DelegationDecline.notHeld("csec://alpha/TOKEN").statusText,
        identityLookup: "audit-token (exec-exact)")))
    check(explained.count == 4 && explained[1].label == ClaudeDelegationStatusRows.verificationLabel
          && explained[2] == StatusRow(label: "Claude auto-mode last decline",
                                      value: "csec://alpha/TOKEN isn't unlocked in csecd yet.", state: .neutral)
          && explained[3] == StatusRow(label: "Claude Code identity check", value: "audit-token (exec-exact)",
                                      state: .neutral),
          "status: while on, the last decline's reason and the identity lookup follow the counts, neutral")
    check(rows(.status(DelegationStatus(
            state: .off, policyVersion: 1, lastDecline: "Auto mode didn't approve this: x.",
            identityLookup: "audit-token (exec-exact)"))).count == 1,
          "status: with delegation off neither is shown")
    let unreadable = rows(.status(DelegationStatus(state: .unreadable, policyVersion: 1)))
    check(unreadable.first?.state == .bad && unreadable.first?.value == "delegation settings unreadable",
          "status: unreadable delegation settings are the one bad state (doctor fails)")
    let states = [DelegationState.off, .on, .reconfirmationRequired, .unavailable]
    check(states.allSatisfy { state in
        rows(.status(DelegationStatus(state: state, policyVersion: 1))).allSatisfy { $0.state != .bad }
    } && rows(.csecdUnavailable).first?.state == .neutral && rows(.unsupported).first?.state == .neutral,
          "status: every other state, and an absent or older csecd, never fails doctor")
    let builds = rows(.status(DelegationStatus(
        state: .on, policyVersion: 1, discoveredUntrustedBuilds: [
            ClaudeBuildSummary(cdHash: String(repeating: "b", count: 40), versionLabel: "2.1.257",
                               path: "/Users/synthetic/.local/share/claude/versions/2.1.257"),
            ClaudeBuildSummary(cdHash: String(repeating: "c", count: 40), versionLabel: "2.1.256",
                               path: "/Users/synthetic/.local/share/claude/versions/2.1.256"),
        ])))
    check(builds.count == 3 && builds[2].label == "Claude Code builds" && builds[2].state == .warn
          && builds[2].value == "2.1.257 (/Users/synthetic/.local/share/claude/versions) isn't signed by Anthropic or "
            + "trusted — its sessions use Touch ID; csec setup auto-mode can trust it (+1 more)",
          "status: untrusted builds get their own row while delegation is on")
    check(rows(.status(DelegationStatus(state: .off, policyVersion: 1, discoveredUntrustedBuilds: [
        ClaudeBuildSummary(cdHash: String(repeating: "b", count: 40), versionLabel: "2.1.257", path: "/b"),
    ]))).count == 1, "status: no builds row while delegation is off")
}

// MARK: - The typed-id CLI

#if DEBUG
private struct CommandRun {
    let status: Int32
    let stdout: String
    let stderr: String
}

private func siblingCsecBinary() -> URL? {
    guard let executable = Bundle.main.executableURL else { return nil }
    let csec = executable.deletingLastPathComponent().appendingPathComponent("csec")
    return FileManager.default.isExecutableFile(atPath: csec.path) ? csec : nil
}

private func runCsec(_ csec: URL, _ arguments: [String], socket: String) -> CommandRun? {
    let process = Process()
    process.executableURL = csec
    process.arguments = arguments
    var environment = ["PATH": "/usr/bin:/bin", "LANG": "C", "CSEC_SOCKET": socket]
    for key in ["HOME", "USER", "TMPDIR"] {
        if let value = ProcessInfo.processInfo.environment[key] { environment[key] = value }
    }
    process.environment = environment
    let output = Pipe(), errors = Pipe()
    process.standardOutput = output
    process.standardError = errors
    process.standardInput = FileHandle.nullDevice
    do { try process.run() } catch { return nil }
    let errorData = errors.fileHandleForReading.readDataToEndOfFile()
    let outputData = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return CommandRun(status: process.terminationStatus, stdout: String(decoding: outputData, as: UTF8.self),
                      stderr: String(decoding: errorData, as: UTF8.self))
}

private final class GrantsRequestRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [GrantsRequest] = []
    var all: [GrantsRequest] { lock.lock(); defer { lock.unlock() }; return items }
    func append(_ item: GrantsRequest) { lock.lock(); items.append(item); lock.unlock() }
}

private func typedIDCommandTests() async {
    guard let csec = siblingCsecBinary() else {
        check(false, "the debug csec binary sits beside cs-selftest")
        return
    }
    let base = URL(fileURLWithPath: "/tmp").appendingPathComponent("cs-c2-\(UUID().uuidString.prefix(8))")
    try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true,
                                             attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: base) }
    let socket = base.appendingPathComponent("agent.sock").path
    let requests = GrantsRequestRecorder()
    let pairA = RevocableEntry(kind: .pairing, id: "ab12cd34-0000-4000-8000-000000000001", label: "project /p/one")
    let pairB = RevocableEntry(kind: .pairing, id: "ab12cd34-0000-4000-8000-000000000002", label: "project /p/two")
    let hookDigest = "12" + String(repeating: "e", count: 62)
    let server = SocketServer(path: socket, clientTrustPolicy: .allowUnverifiedForTesting) { request, _ in
        guard case let .grants(grants) = request else { return .failed(.invalidRequest, message: "unexpected") }
        requests.append(grants)
        switch (grants.action, grants.grantID, grants.all) {
        case (.list, _, _):
            return Response(
                requestID: grants.requestID,
                grants: [GrantSummary(id: "abcdef0123456789", rootPID: 42, rootProcessLabel: "zsh",
                                      scopeKind: .codingAgent, references: ["op://Vault/Item/field"],
                                      reason: "tests", expiresAt: nil)],
                delegationGrants: DelegationGrantsListing(
                    pairings: [ProjectPairingSummary(id: pairA.id, projectPath: "/p/one",
                                                     references: ["csec://store/key"], ssh: [])],
                    trustedBuilds: [ClaudeBuildSummary(cdHash: String(repeating: "f", count: 40),
                                                       versionLabel: "2.1.257", path: "/v/2.1.257",
                                                       trustedAt: Date(timeIntervalSince1970: 0))],
                    acknowledgedHooks: [AcknowledgedHookSummary(digest: hookDigest, display: "cc-caffeine@samber · PreToolUse *")]))
        case (.revoke, "pair-ab12"?, _):
            return Response(requestID: grants.requestID,
                            grantRevocation: GrantRevocation(ambiguousMatches: [pairA, pairB]),
                            failure: ProtocolFailure(.invalidRequest, message: "pair-ab12 is ambiguous"))
        case (.revoke, "abcd"?, _):
            return Response(requestID: grants.requestID, revokedGrantCount: 1, grantRevocation: GrantRevocation(
                removed: [RevocableEntry(kind: .secret, id: "abcdef0123456789", label: "coding agent zsh")]))
        case (.revoke, "hook-12"?, _):
            return Response(requestID: grants.requestID, revokedGrantCount: 1, grantRevocation: GrantRevocation(
                removed: [RevocableEntry(kind: .hook, id: hookDigest, label: "cc-caffeine@samber · PreToolUse *")]))
        case (.revoke, "build-99"?, _):
            return Response(requestID: grants.requestID, revokedGrantCount: 0, grantRevocation: GrantRevocation())
        case (.revoke, nil, true):
            return Response(requestID: grants.requestID, revokedGrantCount: 3, grantRevocation: GrantRevocation(removed: [
                RevocableEntry(kind: .secret, id: "abcdef0123456789", label: "coding agent zsh"),
                RevocableEntry(kind: .secret, id: "0123456789abcdef", label: "terminal session zsh"),
                pairA,
            ]))
        default:
            return .failed(.invalidRequest, message: "unexpected")
        }
    }
    Thread.detachNewThread { try? server.run() }
    for _ in 0..<400 where !FileManager.default.fileExists(atPath: socket) { usleep(10_000) }

    let listing = runCsec(csec, ["grants"], socket: socket)
    let out = listing?.stdout ?? ""
    check(listing?.status == 0 && out.contains("grant-abcdef01  coding agent") && out.contains("pair-ab12cd34  Claude Code auto mode in /p/one")
          && out.contains("build-ffffffff  trusted Claude Code build 2.1.257")
          && out.contains("hook-12eeeeee  acknowledged hook cc-caffeine@samber · PreToolUse *"),
          "csec grants lists every kind under its typed id")

    let ambiguous = runCsec(csec, ["revoke", "pair-ab12"], socket: socket)
    check(ambiguous?.status == 1 && ambiguous?.stderr.contains("matches 2 entries and revoked none") == true
          && ambiguous?.stderr.contains("pair-\(pairA.id)") == true && ambiguous?.stderr.contains("pair-\(pairB.id)") == true,
          "csec revoke with an ambiguous prefix removes nothing and lists every match in full")

    let bare = runCsec(csec, ["revoke", "abcd"], socket: socket)
    check(bare?.status == 0 && bare?.stdout.contains("csec: revoked 1 grant") == true
          && bare?.stdout.contains("grant-abcdef01") == true
          && requests.all.last?.grantID == "abcd",
          "csec revoke with a bare hex id revokes a secret grant")

    let hook = runCsec(csec, ["revoke", "hook-12"], socket: socket)
    check(hook?.status == 0 && hook?.stdout.contains("csec: revoked 1 acknowledged hook") == true,
          "csec revoke hook-… forgets an acknowledged hook through the same revoke")

    let none = runCsec(csec, ["revoke", "build-99"], socket: socket)
    check(none?.status == 1 && none?.stderr.contains("no live grant matches build-99") == true,
          "csec revoke of an id that matches nothing fails")

    let all = runCsec(csec, ["revoke", "--all"], socket: socket)
    check(all?.status == 0 && all?.stdout.contains("csec: revoked 2 grants and 1 pairing") == true,
          "csec revoke --all reports grants and pairings removed")

    let requestCount = requests.all.count
    for invalid in ["foo-12", "pair-xyz", "grant-", "ssh-ＡＢ"] {
        let run = runCsec(csec, ["revoke", invalid], socket: socket)
        check(run?.status == 2 && run?.stderr.contains("is not an id") == true,
              "csec revoke refuses \(invalid.debugDescription) as an unknown kind or id without asking csecd")
    }
    check(requests.all.count == requestCount, "an invalid id never reaches csecd")
}
#endif
