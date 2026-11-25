import Foundation
@preconcurrency import AppKit
import ConvenientSecurity
#if canImport(Darwin)
import Darwin
#endif

// `csec setup` — a guided, interactive onboarding flow. It assesses the resident
// agent, Full Disk Access, and any detected coding agents, then for each
// actionable item explains what it does, asks, and either applies it or walks the
// user through it. Nothing changes without a per-step confirmation. It finishes
// with the bounded security-audit prompt and an optional host audit.
//
// Guided-only: it requires an interactive terminal and otherwise fails closed
// (mirroring `csec protect --env`). The former flag-driven batch model and its
// secret-import surface are gone; the import *engine* is unchanged and still
// reachable through `csec protect`.

func runSetup(_ arguments: [String]) -> Never {
    // The glob-driven bulk-protect mode stands alone: non-interactive with
    // --glob/--dry-run/--apply, so it dispatches before the TTY guard.
    if let flagIndex = arguments.firstIndex(of: "--protect-files") {
        var rest = arguments
        rest.remove(at: flagIndex)
        runSetupProtectFiles(rest)
    }
    if arguments.first == "auto-mode" {
        runSetupAutoMode(Array(arguments.dropFirst()))
    }
    if arguments.first == "shell-prefix" {
        runSetupShellPrefix(Array(arguments.dropFirst()))
    }
    guard isatty(STDIN_FILENO) == 1, isatty(STDERR_FILENO) == 1 else {
        csecError("setup", "csec setup is an interactive guided flow; run it in a terminal.")
        exit(2)
    }

    let projectDirectory: String
    do {
        projectDirectory = try parseSetupOptions(arguments)
    } catch {
        csecError("setup", ReviewDisplay.sanitized(error.localizedDescription))
        exit(2)
    }

    Prompt.title("Convenient Security setup")
    Prompt.note("A guided walkthrough — nothing changes without your confirmation at each step.")

    // Every approval csec asks for is a touch, so say first whether this Mac
    // can give one, and what will not work until it can.
    let touchID = TouchIDReadiness.current()
    stepTouchID(touchID)

    let environment = ProcessInfo.processInfo.environment
    let homeDirectory = FileManager.default.homeDirectoryForCurrentUser.path

    // --- Assessment (quiet, behind a spinner) ---
    let agentClient = makeAgentClient()
    let detections: [CodingAgentDetection]
    let discovery: LocalSecretDiscovery
    do {
        (detections, discovery) = try withSpinner("Assessing this Mac and project…") {
            let detections = try CodingAgentSetup.detect(
                homeDirectory: homeDirectory, pathEnvironment: environment["PATH"],
                claudeConfigDirectory: environment["CLAUDE_CONFIG_DIR"])
            let discovery = try LocalSecretDiscoveryEngine.discover(
                projectDirectory: projectDirectory, environment: environment)
            return (detections, discovery)
        }
    } catch {
        csecError("setup", ReviewDisplay.sanitized(error.localizedDescription))
        exit(1)
    }
    var agent = probeAgent(agentClient)
    var providerSchemes = agent.capabilities != nil ? ((try? agentClient.schemes()) ?? []) : []
    let claude = ClaudeSettingsContext.current(
        csecExecutablePath: currentExecutablePath(), projectDirectory: projectDirectory)

    // --- Step 1: resident agent (csecd) ---
    var launchStatus = LaunchAgentService.status()
    stepResidentAgent(
        launchStatus: &launchStatus, agentClient: agentClient,
        agent: &agent, providerSchemes: &providerSchemes)
    let agentReachable = agent.capabilities != nil
    let commandLink = reportCommandOnPath()

    // --- Step 2: Full Disk Access (report-only, no Touch ID; needs a reachable csecd) ---
    var auditReport: HostAuditReport?
    if agentReachable {
        auditReport = withSpinner("Reading host posture…") { try? agentClient.hostAudit() }
    }
    let fda = fdaState(from: auditReport)
    stepFullDiskAccess(state: fda)

    // --- Step 3: coding-agent hooks ---
    // Whether delegated approvals are on decides which of csec's auto-mode
    // entries is current, so refreshing the hook never flips it.
    let delegation = agent.capabilities?.features.contains(.delegatedApprovals) == true
        ? readDelegationStatus(agentClient, context: claude) : nil
    let configuredClients = stepCodingAgentHooks(
        detections: detections, autoModeEntry: delegation.map(currentAutoModeEntry))

    // --- Step 3b: bulk secret-file protection (optional sweep) ---
    Prompt.step("3b. Protect secret files")
    Prompt.note("A home-wide sweep finds .env/.envrc files, shell rc exports, SSH keys, "
        + "key material, and standard tool credentials, then protects the selection "
        + "you approve (per-kind defaults, glob-adjustable).")
    printProtectFilesScanNotice(
        scanRoots: [], homeDirectory: canonicalHomeDirectory(), mode: .interactive)
    if Prompt.confirm("Scan for protectable secret files now?") {
        _ = performSetupProtectFiles([], fromGuidedSetup: true, noticeShown: true)
    } else {
        Prompt.note("Skipped. Run `csec setup --protect-files` any time.")
    }

    // --- Step 3c: auto-mode approvals (Claude Code) ---
    if detections.contains(where: { $0.client == .claude && $0.detected }) {
        stepClaudeAutoModeApprovals(agentClient: agentClient, agent: agent, context: claude)
    }

    // --- Step 3d: sudo review (from the package, through sudo) ---
    let sudoReview = stepSudoReview(touchID: touchID)

    // --- Step 4: bounded audit prompt + optional host audit ---
    let sipStatus = StartupSecurityReport.currentAgent().sipStatus
    let rootReachable = setupRootHelperReachable()
    let plans = detections.filter(\.detected).compactMap {
        try? CodingAgentSetup.statusPlan(detection: $0, csecExecutablePath: currentExecutablePath())
    }
    stepAuditPromptAndAudit(
        projectDirectory: projectDirectory, launchStatus: launchStatus,
        agentReachable: agentReachable, providerSchemes: providerSchemes,
        rootReachable: rootReachable, sipStatus: sipStatus, plans: plans, discovery: discovery)

    // --- Recap ---
    setupRecap(
        touchID: touchID, launchStatus: launchStatus, agentReachable: agentReachable,
        commandLink: commandLink, fda: fda, configuredClients: configuredClients, sudoReview: sudoReview)
    exit(0)
}

/// `csec setup auto-mode`: step 3c on its own, for when `csec ai`, a panel
/// or `csec status` says delegated approvals are waiting on setup (new hooks
/// or classifier rules to acknowledge, a build to trust, classifyAllShell to
/// restore), without walking through every other step.
private func runSetupAutoMode(_ arguments: [String]) -> Never {
    guard isatty(STDIN_FILENO) == 1, isatty(STDERR_FILENO) == 1 else {
        csecError("setup", "csec setup auto-mode is interactive; run it in a terminal.")
        exit(2)
    }
    let projectDirectory: String
    do {
        projectDirectory = try parseSetupOptions(arguments)
    } catch {
        csecError("setup", ReviewDisplay.sanitized(error.localizedDescription))
        exit(2)
    }
    Prompt.title("Convenient Security setup: Claude Code auto-mode approvals")
    let agentClient = makeAgentClient()
    let ran = stepClaudeAutoModeApprovals(
        agentClient: agentClient, agent: probeAgent(agentClient),
        context: ClaudeSettingsContext.current(
            csecExecutablePath: currentExecutablePath(), projectDirectory: projectDirectory))
    // A script driving setup tells a skipped step from one that ran,
    // whatever was answered in it.
    exit(ran ? 0 : 1)
}

/// `csec setup shell-prefix [--remove]`: set (or remove) Claude Code's
/// `env.CLAUDE_CODE_SHELL_PREFIX` in the shared user settings to this
/// bundle's prefix script (`ClaudeCodeShellPrefix`, csec-0.83.1). Claude Code
/// then runs every Bash and Monitor command through `csec ai` after auto mode
/// reviewed it as typed, and csec's hook stops rewriting commands, which is
/// what voided auto mode's verdict. Non-interactive: it changes one key,
/// with the same file-safety rules and backup as every other setup edit.
/// New Claude Code sessions pick it up; running ones keep the rewrite.
private func runSetupShellPrefix(_ arguments: [String]) -> Never {
    guard arguments.isEmpty || arguments == ["--remove"] else { usage("setup") }
    switch editClaudeShellPrefix(remove: !arguments.isEmpty) {
    case let .changed(path, backup):
        print("csec: \(arguments.isEmpty ? "set" : "removed") env.\(ClaudeDelegationGateLists.shellPrefixName) "
            + "in \(ReviewDisplay.sanitized(path))"
            + (backup.map { " (backup: \(ReviewDisplay.sanitized($0)))" } ?? ""))
        exit(0)
    case let .unchanged(path):
        print("csec: env.\(ClaudeDelegationGateLists.shellPrefixName) in \(ReviewDisplay.sanitized(path)) "
            + "already \(arguments.isEmpty ? "names csec's prefix" : "does not name csec's prefix")")
        exit(0)
    case .notBundled:
        csecError("setup", "this csec does not run from the app bundle, so it has no shell prefix script")
        exit(1)
    case let .failed(reason):
        csecError("setup", reason)
        exit(1)
    }
}

enum ClaudeShellPrefixEdit {
    /// This csec runs from no app bundle, so it ships no prefix script.
    case notBundled
    case changed(path: String, backup: String?)
    case unchanged(path: String)
    case failed(String)
}

/// Set or remove csec's `env.CLAUDE_CODE_SHELL_PREFIX` in the user settings
/// file `csec setup` edits. Removal touches only a value naming this
/// bundle's prefix script; `csec uninstall` runs it first, because once the
/// bundle is gone that script is too, and a prefix naming it would stop every
/// Bash command.
func editClaudeShellPrefix(remove: Bool) -> ClaudeShellPrefixEdit {
    guard let prefixPath = ClaudeCodeShellPrefix.prefixPath(csecExecutablePath: currentExecutablePath()) else {
        return .notBundled
    }
    let context = ClaudeSettingsContext.current(csecExecutablePath: currentExecutablePath())
    guard let scope = context.scope else {
        return .failed("CLAUDE_CONFIG_DIR is not an absolute path; run again with it unset or absolute")
    }
    let path = scope.sharedUserSettingsPath(files: LiveClaudeSettingsFileAccess())
    do {
        let base = try CodingAgentSetup.planClaudeSettings(path: path)
        let plan: CodingAgentConfigurationPlan
        let changes: Bool
        if remove {
            (plan, changes) = try CodingAgentSetup.planClaudeShellPrefixRemoval(basedOn: base, prefixPath: prefixPath)
        } else {
            (plan, changes) = try CodingAgentSetup.planClaudeShellPrefix(basedOn: base, prefixPath: prefixPath)
        }
        guard changes else { return .unchanged(path: path) }
        let backup = try CodingAgentSetup.applyWithBackup(plan)
        return .changed(path: path, backup: backup)
    } catch {
        return .failed(ReviewDisplay.sanitized(error.localizedDescription))
    }
}

/// What setup learned from csecd: its capabilities, or why it did not answer
/// and how long setup waited for it.
private enum AgentProbe {
    case reachable(ProtocolCapabilities)
    case unreachable(Error, waited: TimeInterval)

    var capabilities: ProtocolCapabilities? {
        if case let .reachable(capabilities) = self { return capabilities }
        return nil
    }

    /// Why csecd did not answer, value-free, for "csecd is not reachable (…)".
    var reason: String {
        guard case let .unreachable(error, waited) = self else { return "" }
        let cause: String
        switch error as? AgentClient.ClientError {
        case let .connectFailed(path)?:
            cause = "nothing answers at \(displayPath(path))"
        case let .connectPermissionDenied(path)?:
            cause = "permission to connect to \(displayPath(path)) was refused (a sandbox or file permissions)"
        case .untrustedServer?:
            cause = "the process answering could not be verified as the installed csecd"
        case let .daemonUnresponsive(seconds)?:
            cause = "it accepted the connection, then stayed silent for \(seconds) s"
        case .connectionLost?, .transportFailed?:
            cause = "the connection broke before it answered"
        case let .protocolFailure(code, _)?:
            cause = "it refused the request (\(code.rawValue)); csec and csecd may be different builds"
        case .denied?, .agentError?, nil:
            cause = ReviewDisplay.sanitized(error.localizedDescription)
        }
        return waited >= 1 ? "\(cause), after waiting \(Int(waited.rounded())) s" : cause
    }
}

/// Ask csecd for its capabilities. While launchd has csecd registered, a
/// failure that a starting csecd explains (an update restarts it) is waited
/// out the way `csec doctor` waits (`AgentStartupWait`), behind a spinner.
private func probeAgent(_ client: AgentClient) -> AgentProbe {
    let first = Result { try client.capabilities() }
    guard case let .failure(error) = first else { return probeResult(first, waited: 0) }
    guard AgentStartupWait.waitingCanFix(error),
          LaunchctlInspection.agentLoaded() || LaunchAgentService.status() == .enabled else {
        return probeResult(first, waited: 0)
    }
    let (result, waited) = withSpinner("Waiting for csecd to start…") {
        AgentStartupWait.poll(age: LaunchctlInspection.agentAge) { try client.capabilities() }
    }
    return probeResult(result, waited: waited)
}

private func probeResult(_ result: Result<ProtocolCapabilities, Error>, waited: TimeInterval) -> AgentProbe {
    switch result {
    case let .success(capabilities): return .reachable(capabilities)
    case let .failure(error): return .unreachable(error, waited: waited)
    }
}

// MARK: - Touch ID

private func stepTouchID(_ readiness: TouchIDReadiness) {
    Prompt.step("Touch ID")
    guard !readiness.canApprove else {
        Prompt.success("Touch ID is ready: csec asks for a touch to approve each request.")
        return
    }
    Prompt.warn(readiness.problem)
    Prompt.body(TouchIDReadiness.consequence)
    Prompt.note(readiness.remedy)
}

// MARK: - Package stages run through sudo

/// How the sudo review stands once setup's step is over, for the summary.
private enum SudoReviewOutcome {
    case active
    /// Not installed, by choice or because nothing could install it.
    case off
    /// Installed but not as it should be, or its update was left for later.
    case attention
}

/// Run one of the package's guarded installers through sudo, in this
/// terminal, so the user authenticates it and reads its progress. Only a
/// root-owned file the package installed is run: root executes it.
private func runPackageInstaller(_ path: String) -> Bool {
    guard PackagePayload.isRootOwnedFile(path) else {
        Prompt.warn("\(displayPath(path)) is not the root-owned installer the package puts there; "
            + "reinstall the Convenient Security package.")
        return false
    }
    Prompt.note("Running: sudo \(displayPath(path))")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
    process.arguments = [path]
    do {
        try process.run()
    } catch {
        Prompt.warn("Could not start sudo: \(ReviewDisplay.sanitized(error.localizedDescription))")
        return false
    }
    process.waitUntilExit()
    return process.terminationReason == .exit && process.terminationStatus == 0
}

/// The installed sudo integration as `csec doctor` inspects it, read afresh.
private func currentSudoIntegrationState() -> SudoIntegrationState {
    let result = SudoStateBox()
    let finished = DispatchSemaphore(value: 0)
    Task.detached {
        result.store(await SudoIntegrationInspection.inspect(
            files: SystemFileInspector(), commands: SystemCommandRunner()))
        finished.signal()
    }
    finished.wait()
    return result.value ?? .helperSignatureUnreadable
}

private final class SudoStateBox: @unchecked Sendable {
    private let lock = NSLock()
    private var state: SudoIntegrationState?
    func store(_ value: SudoIntegrationState) {
        lock.lock(); state = value; lock.unlock()
    }
    var value: SudoIntegrationState? {
        lock.lock(); defer { lock.unlock() }; return state
    }
}

// MARK: - csec on PATH (part of step 1)

/// The package links `/usr/local/bin/csec` to the installed launcher unless
/// another file already held the name; say which, so `csec …` in a new
/// terminal is not a surprise either way.
private func reportCommandOnPath() -> CommandLinkState {
    let state = CommandLinkState.inspect()
    switch state {
    case .linked:
        Prompt.success("`csec` is on PATH (\(PackagePayload.commandLinkPath)).")
    case .missing:
        Prompt.warn("`csec` is not on PATH: \(PackagePayload.commandLinkPath) is missing. Reinstalling the "
            + "Convenient Security package puts it back; until then run \(CodingAgentSetup.installedLauncherPath).")
    case .linksElsewhere, .otherFile:
        Prompt.warn(ReviewDisplay.sanitized(state.rowValue) + ". The package left it alone; `csec` in a "
            + "terminal may run something else. The installed csec is \(CodingAgentSetup.installedLauncherPath).")
    }
    return state
}

// MARK: - Step 3d: sudo review

private func stepSudoReview(touchID: TouchIDReadiness) -> SudoReviewOutcome {
    Prompt.step("3d. sudo review")
    let state = currentSudoIntegrationState()
    let offer = SetupSudoReviewOffer.decide(
        state: state,
        payload: SudoReviewPayloadMatch.compare(),
        packageInstallerPresent: PackagePayload.isRootOwnedFile(PackagePayload.sudoReviewInstaller),
        touchID: touchID)
    let question: String
    switch offer {
    case .current:
        if state.isHealthy {
            Prompt.success("The sudo review is installed and current.")
            return .active
        }
        Prompt.warn("The sudo review is installed, but csec could not read its helper's signature; "
            + "`csec doctor` checks it again.")
        return .attention
    case let .needsTouchID(readiness):
        Prompt.warn("Left \(state == .notInstalled ? "off" : "as it is"): installing the sudo review ends with a "
            + "harmless sudo you approve with a touch, and \(readiness.problem.prefix(1).lowercased() + readiness.problem.dropFirst())")
        return state == .notInstalled ? .off : .attention
    case let .noPackage(found):
        Prompt.warn("The sudo review is \(ReviewDisplay.sanitized(found.rowValue)), and this csec has no package "
            + "payload to install it from. \(PackagePayload.installAdvice) Then run csec setup again.")
        return found == .notInstalled ? .off : .attention
    case .install:
        Prompt.note("With the sudo review on, each sudo in a terminal opens a csec panel that shows the exact "
            + "command, the directory and the terminal before you touch Touch ID, instead of a password prompt "
            + "that says nothing about what it is for. Use Password on the panel still falls back to macOS's "
            + "own prompt.")
        Prompt.note("It adds two lines to /etc/pam.d/sudo_local (keeping a copy of the file as it was), and "
            + "installs a PAM module and the review helper under /usr/local. That needs root, so setup runs the "
            + "package's guarded installer through sudo: macOS asks for your password first. The installer then "
            + "runs a harmless sudo; approve the csec panel that appears. Anything else (a refusal, a timeout, "
            + "or the password instead) puts everything back as it was.")
        question = "Turn on the sudo review now?"
    case .update:
        Prompt.note("The installed sudo review is not the build this package carries. Updating replaces the "
            + "module and helper through the package's guarded installer, run through sudo, and keeps them only "
            + "after you approve the harmless sudo it runs; otherwise the installed ones are put back.")
        question = "Update the sudo review now?"
    case let .repair(found):
        Prompt.warn("The sudo review is installed but \(ReviewDisplay.sanitized(found.rowValue)).")
        Prompt.note("Reinstalling replaces the module and helper through the package's guarded installer, run "
            + "through sudo, and keeps them only after you approve the harmless sudo it runs.")
        question = "Reinstall the sudo review now?"
    }
    guard Prompt.confirm(question) else {
        Prompt.note("Left unchanged. Re-run `csec setup` to change it later.")
        return state == .notInstalled ? .off : .attention
    }
    guard runPackageInstaller(PackagePayload.sudoReviewInstaller) else {
        Prompt.warn("The sudo review was not installed; the installer above says why, and sudo is as it was.")
        return state == .notInstalled ? .off : .attention
    }
    let after = currentSudoIntegrationState()
    guard after.isHealthy else {
        Prompt.warn("The installer finished, but the sudo review is \(ReviewDisplay.sanitized(after.rowValue)); "
            + "run `csec doctor`.")
        return .attention
    }
    Prompt.success("The sudo review is on.")
    return .active
}

// MARK: - Step 1: resident agent

private func stepResidentAgent(
    launchStatus: inout LaunchAgentStatus,
    agentClient: AgentClient,
    agent: inout AgentProbe,
    providerSchemes: inout [String]
) {
    Prompt.step("1. Resident agent (csecd)")
    if launchStatus == .enabled {
        if agent.capabilities != nil {
            Prompt.success("csecd is installed and running.")
        } else {
            Prompt.warn("csecd is installed but not answering (\(agent.reason)). Run `csec doctor`, then re-run setup.")
        }
        return
    }
    if launchStatus == .requiresApproval {
        Prompt.warn("csecd is registered but awaiting your approval in "
            + "System Settings → General → Login Items. Approve it there, then re-run setup.")
        return
    }

    Prompt.note("csecd is the resident agent that resolves secret references behind one Touch ID "
        + "tap and runs the host posture audit. It runs as a per-user login-item LaunchAgent.")
    guard Prompt.confirm("Install and start csecd now?") else {
        Prompt.note("Skipped. Run `csec install` later, or re-run setup.")
        return
    }

    do {
        launchStatus = try LaunchAgentService.install()
        if launchStatus.needsApproval {
            Prompt.warn("Approve “ConvenientSecurity” in System Settings → General → Login Items to let it start, then re-run setup.")
            return
        }
        agent = probeAgent(agentClient)
        if agent.capabilities != nil {
            providerSchemes = (try? agentClient.schemes()) ?? []
            Prompt.success("csecd is installed and running.")
        } else {
            Prompt.warn("csecd was registered but is not answering (\(agent.reason)); run `csec doctor`, then `csec status`.")
        }
    } catch {
        csecError("setup", "could not register csecd: \(ReviewDisplay.sanitized(error.localizedDescription))")
        Prompt.note("csec must run from inside the installed app for install to work. "
            + "\(PackagePayload.installAdvice) Then run csec setup again.")
    }
}

// MARK: - Step 2: Full Disk Access

private func stepFullDiskAccess(state: FDAState) {
    Prompt.step("2. Full Disk Access")
    switch state {
    case .granted:
        Prompt.success("csecd already has Full Disk Access.")
    case .unknown:
        Prompt.warn("csecd must be installed and running before Full Disk Access can be checked. "
            + "Complete step 1, then re-run setup.")
    case .missing:
        Prompt.note("csecd needs Full Disk Access to audit the Mac's privacy grants — which apps hold "
            + "Full Disk Access, Accessibility, Screen Recording, Input Monitoring, and the other "
            + "high-value TCC permissions a same-user attacker would abuse. Without it those checks "
            + "report \"could not verify\" instead of a real result.")
        guard Prompt.confirm("Open the Full Disk Access settings pane now?") else {
            Prompt.note("Skipped. Add ConvenientSecurity under "
                + "System Settings → Privacy & Security → Full Disk Access later.")
            return
        }
        guard let url = URL(
            string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"),
            NSWorkspace.shared.open(url) else {
            Prompt.warn("Could not open System Settings; open the Full Disk Access pane manually.")
            return
        }
        Prompt.note("In the pane that opened: add or enable ConvenientSecurity in the Full Disk "
            + "Access list. csecd must restart to pick up the new grant — toggling it there, or "
            + "`csec doctor`, will restart it.")
    }
}

// MARK: - Step 3: coding-agent hooks

/// `autoModeEntry` nil (csecd could not say whether delegated approvals are
/// on) accepts either of csec's current entries.
private func stepCodingAgentHooks(
    detections: [CodingAgentDetection],
    autoModeEntry: CodingAgentSetup.ClaudeAutoModeEntry?
) -> [String] {
    Prompt.step("3. Coding-agent hooks")
    let detected = detections.filter(\.detected)
    guard !detected.isEmpty else {
        Prompt.note("No supported coding agent (Claude Code or Codex) was detected; nothing to configure.")
        return []
    }

    var configured: [String] = []
    for detection in detected {
        let client = detection.client.rawValue
        if detection.client == .codex {
            if configureCodex(detection) { configured.append(client) }
            continue
        }
        var plan: CodingAgentConfigurationPlan
        do {
            plan = try CodingAgentSetup.plan(
                detection: detection, csecExecutablePath: currentExecutablePath())
        } catch {
            Prompt.warn("\(client): cannot plan a hook — \(ReviewDisplay.sanitized(error.localizedDescription))")
            continue
        }

        var replacesHook = false
        if plan.action == .blocked {
            // Offer replacement only when a replacement plan would cleanly merge —
            // an older, duplicate, or misplaced csec hook. A genuine policy block
            // (Claude's disableAllHooks) or an unsafe/invalid config only reports.
            if let replacement = try? CodingAgentSetup.plan(
                detection: detection, csecExecutablePath: currentExecutablePath(),
                replaceExistingCSECHook: true), replacement.action == .merge {
                Prompt.warn("\(client): \(ReviewDisplay.sanitized(plan.detail))")
                plan = replacement
                replacesHook = true
            } else {
                Prompt.warn("\(client): \(ReviewDisplay.sanitized(plan.detail))")
                continue
            }
        }

        // Claude's auto-mode context lives in the same settings file as the
        // hook, so it is composed onto the hook plan as one atomic write.
        let hookChanges = plan.action != .unchanged
        var environmentChanges = false
        do {
            plan = try CodingAgentSetup.planClaudeAutoModeEnvironment(basedOn: plan, entry: autoModeEntry)
            let entries = [CodingAgentSetup.ClaudeAutoModeEntry.standard.text,
                           CodingAgentSetup.ClaudeAutoModeEntry.delegationAware.text]
            environmentChanges = plan.preview.map(entries.contains) ?? false
        } catch {
            // The hook matters more than the classifier context; configure it alone.
            Prompt.warn("\(client): cannot add the auto-mode context (fix autoMode in "
                + "\(displayPath(plan.path)) and rerun setup) — "
                + ReviewDisplay.sanitized(error.localizedDescription))
        }
        if plan.action == .unchanged {
            Prompt.success("\(client): protected commands are already configured.")
            continue
        }
        if hookChanges { showHookPlan(plan, client: detection.client) }
        if environmentChanges {
            if !hookChanges { Prompt.note("Will edit \(displayPath(plan.path))") }
            Prompt.note("Claude Code's auto-mode classifier will be told what `csec ai -- <command>` is, "
                + "so it judges the inner command. csec adds this autoMode.environment entry and "
                + "leaves your other entries as they are; a new list starts with \"$defaults\" so "
                + "Claude Code's built-in entries stay in effect:")
            Prompt.note(ReviewDisplay.sanitized(plan.preview ?? CodingAgentSetup.claudeAutoModeEnvironmentEntry))
        }
        let question: String
        if !hookChanges {
            question = "Add csec's auto-mode context to \(client)?"
        } else {
            let context = environmentChanges ? " and its auto-mode context" : ""
            question = replacesHook ? "Replace the existing csec hook in \(client)\(context)?"
                : "Configure the \(client) hook\(context) (merges only csec's entries)?"
        }
        guard Prompt.confirm(question) else {
            Prompt.note("\(client): left unchanged.")
            continue
        }
        if applyHookPlan(plan, client: client) {
            configured.append(client)
        }
    }
    return configured
}

/// Install or replace csec's managed Codex hook with the package's guarded
/// installer, through sudo, and return the hook's state afterwards.
private func offerManagedCodexHook(current: CodexSystemHookState) -> CodexSystemHookState {
    let path = CodingAgentSetup.codexSystemHookPath
    guard PackagePayload.isRootOwnedFile(PackagePayload.codexHookInstaller) else {
        Prompt.warn("codex: the managed hook in \(path) is \(current.rawValue), and this csec has no package "
            + "installer for it. Codex commands are not routed through csec. \(PackagePayload.installAdvice) "
            + "Then run csec setup again to enable the hook.")
        return current
    }
    Prompt.note("codex: the managed hook in \(path) is \(current.rawValue). Codex runs a hook in this "
        + "managed file with no per-hook trust step for an update to undo, and code running as you cannot "
        + "edit it. csec merges only its own handler and keeps every other hook. The file is root's, so "
        + "setup runs the package's guarded installer through sudo: macOS asks for your password first.")
    guard Prompt.confirm(current == .missing ? "Install csec's managed Codex hook now?"
                                             : "Replace it with csec's current managed Codex hook?") else {
        Prompt.warn("codex: left unchanged. Codex commands are not routed through csec until the managed "
            + "hook is installed; re-run setup to install it.")
        return current
    }
    _ = runPackageInstaller(PackagePayload.codexHookInstaller)
    let after = CodingAgentSetup.codexSystemHookState(csecExecutablePath: CodingAgentSetup.installedLauncherPath)
    if after == .installed {
        Prompt.success("codex: managed hook installed in \(path).")
    } else {
        Prompt.warn("codex: the managed hook is still \(after.rawValue); the installer above says why.")
    }
    return after
}

/// Codex's csec hook is not user configuration: it lives in Codex's managed
/// System layer (/etc/codex/hooks.json), which Codex runs with no per-hook
/// trust hash for an edit to invalidate. The file is root's, so setup offers
/// the package's guarded installer through sudo when it is missing or stale
/// (build-and-install runs the same installer). Setup then configures the
/// sandbox's access to csecd and removes a user-level copy left by an older
/// csec, which would otherwise run a second time.
private func configureCodex(_ detection: CodingAgentDetection) -> Bool {
    // The managed hook always invokes the installed launcher, whichever csec runs setup.
    var managed = CodingAgentSetup.codexSystemHookState(csecExecutablePath: CodingAgentSetup.installedLauncherPath)
    if managed != .installed {
        managed = offerManagedCodexHook(current: managed)
    }
    // Plan each file on its own: a problem with one must not stop the other.
    var removal: CodingAgentConfigurationPlan?
    if managed == .installed {
        // Only remove the user-level copy once the managed hook covers Codex.
        do {
            removal = try CodingAgentSetup.planCodexUserHookRemoval(detection: detection)
        } catch {
            Prompt.warn("codex: cannot check \(displayPath(detection.configurationPath)) for a leftover csec hook — "
                + ReviewDisplay.sanitized(error.localizedDescription))
        }
    }
    var sandboxPlan: CodingAgentConfigurationPlan?
    do {
        sandboxPlan = try CodingAgentSetup.planCodexSandbox(detection: detection, userHookRemoval: removal)
    } catch {
        Prompt.warn("codex: cannot configure local agent access — " + ReviewDisplay.sanitized(error.localizedDescription))
    }
    let removesUserHook = removal.map { $0.action != .unchanged } ?? false
    let changesSocket = sandboxPlan.map { $0.action != .unchanged } ?? false
    if !removesUserHook && !changesSocket {
        let configured = managed == .installed && sandboxPlan != nil && removal != nil
        if configured { Prompt.success("codex: protected commands are already configured.") }
        return configured
    }
    if let removal, removesUserHook {
        Prompt.note("Will edit \(displayPath(removal.path)): \(ReviewDisplay.sanitized(removal.detail)).")
    }
    if let sandboxPlan, changesSocket {
        Prompt.note("Will configure local agent access in \(displayPath(sandboxPlan.path)). "
            + "The socket path is derived for this macOS user. Codex keeps its filesystem "
            + "restrictions and uses a network proxy to filter other connections.")
        Prompt.note(ReviewDisplay.sanitized(sandboxPlan.detail))
        Prompt.note(ReviewDisplay.sanitized(
            sandboxPlan.preview ?? "", allowNewlines: true, allowOtherControls: true))
    }
    let question = [
        changesSocket ? "configure Codex's local agent access" : nil,
        removesUserHook ? "remove the superseded user-level csec hook" : nil,
    ].compactMap { $0 }.joined(separator: " and ")
    guard Prompt.confirm(question.prefix(1).uppercased() + question.dropFirst() + "?") else {
        Prompt.note("codex: left unchanged.")
        return false
    }
    // Configure access first, so the managed hook is never left without it.
    var succeeded = sandboxPlan != nil && (managed != .installed || removal != nil)
    if let sandboxPlan, changesSocket {
        do {
            if let backup = try CodingAgentSetup.applyWithBackup(sandboxPlan) {
                Prompt.note("Backup: \(displayPath(backup))")
            }
            Prompt.success("Codex local agent access configured. Restart any running Codex sessions "
                + "to use the updated permissions.")
        } catch {
            Prompt.warn("Codex socket configuration failed — " + ReviewDisplay.sanitized(error.localizedDescription))
            succeeded = false
        }
    }
    if let removal, removesUserHook, sandboxPlan != nil, succeeded {
        do {
            if let backup = try CodingAgentSetup.applyWithBackup(removal) {
                Prompt.note("Backup: \(displayPath(backup))")
            }
            Prompt.success("codex: removed the user-level csec hook; the managed hook covers Codex.")
        } catch {
            Prompt.warn("codex: could not remove the user-level csec hook — "
                + ReviewDisplay.sanitized(error.localizedDescription))
            succeeded = false
        }
    }
    return succeeded && managed == .installed
}

/// Show which file csec will touch and the exact value-free hook fragment it
/// would merge. Bidi is neutralized; newlines and other formatting are preserved
/// so the JSON reads normally.
private func showHookPlan(_ plan: CodingAgentConfigurationPlan, client: AICommandHookClient) {
    let verb = plan.action == .create ? "create" : "edit"
    Prompt.note("Will \(verb) \(displayPath(plan.path))")
    guard let data = try? AICommandHook.hookConfiguration(
        client: client, csecExecutablePath: currentExecutablePath()),
        let fragment = String(data: data, encoding: .utf8) else { return }
    Prompt.note("The exact value-free fragment csec will merge:")
    Prompt.note(ReviewDisplay.sanitized(fragment, allowNewlines: true, allowOtherControls: true))
}

private func applyHookPlan(_ plan: CodingAgentConfigurationPlan, client: String) -> Bool {
    do {
        try CodingAgentSetup.apply(plan)
        Prompt.success("\(client): hook configured in \(displayPath(plan.path)) — restart running "
            + "\(client) sessions to pick it up.")
        return true
    } catch {
        csecError("setup", "\(client): could not update the hook — \(ReviewDisplay.sanitized(error.localizedDescription))")
        return false
    }
}

/// A configuration path prepared for display: the user's home directory is
/// abbreviated to `~`, and the whole path is sanitized as untrusted metadata.
private func displayPath(_ path: String) -> String {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let abbreviated: String
    if path == home {
        abbreviated = "~"
    } else if path.hasPrefix(home + "/") {
        abbreviated = "~" + path.dropFirst(home.count)
    } else {
        abbreviated = path
    }
    return ReviewDisplay.sanitized(abbreviated)
}

// MARK: - Step 3c: auto-mode approvals (Claude Code)

/// The Claude Code settings one csec invocation speaks for: csec's home,
/// `CLAUDE_CONFIG_DIR` as csec sees it, and its working directory. `scope` is
/// nil when `CLAUDE_CONFIG_DIR` is empty or relative, since Claude Code then
/// resolves it against its own working directory; `anyScope` ignores such a
/// value, for a revert of a file csecd recorded, which needs no scope path.
struct ClaudeSettingsContext {
    let workingDirectory: String?
    let scope: ClaudeSettingsScope?
    let anyScope: ClaudeSettingsScope

    static func current(csecExecutablePath: String, projectDirectory: String? = nil) -> ClaudeSettingsContext {
        let configDirectory = ClaudeSettingsScope.ConfigDirectory(
            environmentValue: ProcessInfo.processInfo.environment["CLAUDE_CONFIG_DIR"])
        let working = projectDirectory ?? FileManager.default.currentDirectoryPath
        let workingDirectory = working.hasPrefix("/") ? working : nil
        var scope = ClaudeSettingsScope(
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser.path,
            workingDirectories: workingDirectory.map { [$0] } ?? [],
            userName: NSUserName(),
            csecExecutablePath: csecExecutablePath)
        let anyScope = scope
        switch configDirectory {
        case .unset:
            break
        case let .directory(path):
            scope.claudeConfigDirectory = path
        case .unusable:
            return ClaudeSettingsContext(workingDirectory: workingDirectory, scope: nil, anyScope: anyScope)
        }
        return ClaudeSettingsContext(workingDirectory: workingDirectory, scope: scope, anyScope: anyScope)
    }
}

/// csecd's delegation status for `context`, or nil when csecd cannot say.
private func readDelegationStatus(_ client: AgentClient, context: ClaudeSettingsContext) -> DelegationStatus? {
    guard case let .configured(status, _)? = try? client.configureDelegation(.status(
        claudeConfigDirectory: context.scope?.claudeConfigDirectory,
        projectDirectory: context.workingDirectory)) else { return nil }
    return status
}

/// Which of csec's auto-mode entries is current while delegation is in
/// `status`'s state: the delegation-aware one whenever csecd holds a record
/// of it (on, or paused for re-confirmation).
private func currentAutoModeEntry(_ status: DelegationStatus) -> CodingAgentSetup.ClaudeAutoModeEntry {
    switch status.state {
    case .on, .reconfirmationRequired: return .delegationAware
    case .off, .unreadable, .unavailable: return .standard
    }
}

/// Returns false when the step was skipped: something it needs (a usable
/// CLAUDE_CONFIG_DIR, csec's hook, a csecd that answers and can delegate) is
/// missing, so nothing was offered.
@discardableResult
private func stepClaudeAutoModeApprovals(
    agentClient: AgentClient,
    agent: AgentProbe,
    context: ClaudeSettingsContext
) -> Bool {
    Prompt.step("3c. Auto-mode approvals (Claude Code)")
    guard let scope = context.scope else {
        Prompt.warn("CLAUDE_CONFIG_DIR is not an absolute path, so csec cannot tell which settings Claude Code "
            + "reads. Set it to an absolute path, or unset it, and re-run setup.")
        return false
    }
    let settingsPath = makeClaudeSettingsGate().userSettingsPath(scope)
    let detection = CodingAgentDetection(
        client: .claude, executablePath: nil, configurationPath: settingsPath, configurationExists: true)
    guard (try? CodingAgentSetup.plan(detection: detection, csecExecutablePath: currentExecutablePath()))?.action
            == .unchanged else {
        Prompt.note("Skipped: csec's Claude Code hook is not installed in \(displayPath(settingsPath)) "
            + "(step 3), and auto mode can only hand csec its verdicts through it.")
        return false
    }
    guard let capabilities = agent.capabilities else {
        // Scripts driving setup match "csecd is not reachable".
        Prompt.warn("Skipped: csecd is not reachable (\(agent.reason)). Run `csec doctor`, then re-run setup.")
        return false
    }
    guard capabilities.features.contains(.delegatedApprovals) else {
        Prompt.note("Skipped: this csecd cannot delegate approvals. Install the latest Convenient Security "
            + "package, then run csec setup again.")
        return false
    }
    guard let status = readDelegationStatus(agentClient, context: context) else {
        Prompt.warn("csecd could not report delegated approvals; re-run setup once `csec status` shows csecd healthy.")
        return false
    }
    let session = DelegationSetupSession(client: agentClient, scope: scope, context: context)
    switch status.state {
    case .off:
        session.offerEnable(recorded: status)
    case .reconfirmationRequired:
        Prompt.warn("Delegated approvals are paused: this csec lets auto mode approve more than you agreed to. "
            + "Confirm again to resume them.")
        if !session.offerEnable(recorded: status) { session.offerDisable() }
    case .on:
        session.manage(status)
    case .unreadable:
        Prompt.warn("csecd cannot read its delegated-approval settings, so auto mode approves nothing.")
        // Settings a newer csec wrote, or a Keychain read that failed, come
        // back without a reset; resetting would erase them, pairings too.
        let held = (try? agentClient.decisionLogStatus())?.heldItems?
            .first { $0.name == ProtectedItem.delegationSettings.displayName }
        switch held?.cause {
        case .newerFormat?:
            Prompt.note("A newer csec saved these settings. Install the latest Convenient Security package "
                + "to read them again with every pairing.")
        case .keychain?:
            Prompt.note("The Keychain refused them when csecd started: `csec doctor` restarts csecd to read them again.")
        case .damaged?, .unrecognized?, nil:
            session.offerDisable(
                question: "Reset them (turn delegated approvals off, then run setup again to turn them on)?")
        }
    case .unavailable:
        Prompt.note("This csecd has no protected store to keep the setting in, so delegated approvals cannot be "
            + "turned on.")
    }
    return true
}

/// One run of step 3c against one csecd and one Claude Code settings scope.
private struct DelegationSetupSession {
    let client: AgentClient
    let scope: ClaudeSettingsScope
    let context: ClaudeSettingsContext
    let gate = makeClaudeSettingsGate()

    /// Explain, show the inventory and the planned edits, confirm, then write
    /// the settings and have csecd enable (its Touch ID panel). Returns
    /// whether delegation is on afterwards.
    @discardableResult
    func offerEnable(recorded: DelegationStatus) -> Bool {
        Prompt.note("Claude Code's auto mode already has a classifier judge every shell command against what you "
            + "asked for. With delegated approvals on, csecd accepts that verdict in place of a Touch ID panel "
            + "when a command needs secrets you already approved for the same project, signs SSH to a server "
            + "you already approved for auto mode in any project, or runs sudo in a project where you let auto "
            + "mode run it (the panel that approves them says so), in an interactive auto-mode session of a "
            + "Claude Code build signed by Anthropic or trusted here.")
        Prompt.note("New secrets or projects, the first sudo in a project, other permission modes, `claude -p` "
            + "and SDK sessions, and Codex still ask you. The classifier becomes the only check on what an "
            + "approved command does with those secrets, and with root. Every decision is in `csec log`, and "
            + "csec setup turns this off again.")
        showInventory(recorded: recorded)
        let plan = gate.planEnable(scope)
        guard showPlannedEdits(plan, recorded: recorded) else { return false }
        guard Prompt.confirm("Turn on delegated approvals for Claude Code auto mode (asks for Touch ID)?") else {
            Prompt.note("Left off.")
            return false
        }
        return report(ClaudeDelegationSetup.enable(
            plan: plan, recorded: recorded, projectDirectory: context.workingDirectory,
            client: client, gate: gate, scope: scope), settingsPath: plan.settingsPath)
    }

    /// Delegation is on: report it, repair the settings if they drifted, and
    /// offer to acknowledge new hooks, trust new builds, or turn it off.
    func manage(_ status: DelegationStatus) {
        Prompt.success("Delegated approvals are on: \(status.counters.approved) approved / "
            + "\(status.counters.declined) sent to Touch ID since csecd started; \(status.pairingCount) paired "
            + "project\(status.pairingCount == 1 ? "" : "s"), \(status.trustedBuilds.count) trusted "
            + "build\(status.trustedBuilds.count == 1 ? "" : "s"), \(status.acknowledgedHooks.count) acknowledged "
            + "hook\(status.acknowledgedHooks.count == 1 ? "" : "s").")
        let plan = gate.planEnable(scope)
        if let recordedPath = status.claudeSettingsPath, recordedPath != plan.settingsPath {
            // A different CLAUDE_CONFIG_DIR (a scratch one, say) is far more
            // often a mistake than a real move, and moving reverts the file
            // every other session reads: name both files and default to No.
            Prompt.warn("Delegated approvals are set up in \(displayPath(recordedPath)), but with this "
                + "CLAUDE_CONFIG_DIR Claude Code reads \(displayPath(plan.settingsPath)).")
            if showPlannedEdits(plan, recorded: status),
               Prompt.confirm("Move delegated approvals to \(displayPath(plan.settingsPath)) (asks for Touch ID)?") {
                report(ClaudeDelegationSetup.enable(
                    plan: plan, recorded: status, projectDirectory: context.workingDirectory,
                    client: client, gate: gate, scope: scope), settingsPath: plan.settingsPath)
                return
            }
            // Hooks and builds below would be this config dir's, not the
            // recorded file's: leave them to a run that reads the right one.
            Prompt.note("Left in \(displayPath(recordedPath)). Run csec setup auto-mode with the CLAUDE_CONFIG_DIR "
                + "that reads it to manage them.")
            return
        }
        if case .write = plan.outcome {
            // Only a missing classifyAllShell stops delegation; the entry
            // alone only changes what the classifier is told.
            if plan.classifyAllShell == .add {
                Prompt.warn("csec's auto-mode settings are not all in \(displayPath(plan.settingsPath)), so auto "
                    + "mode approves nothing until they are back.")
            } else {
                Prompt.warn("csec's auto-mode entry in \(displayPath(plan.settingsPath)) no longer tells the "
                    + "classifier that approving a command releases this project's secrets.")
            }
            if showPlannedEdits(plan, recorded: status),
               Prompt.confirm("Restore them (asks for Touch ID)?", default: true) {
                report(ClaudeDelegationSetup.enable(
                    plan: plan, recorded: status, projectDirectory: context.workingDirectory,
                    client: client, gate: gate, scope: scope), settingsPath: plan.settingsPath)
                return
            }
        }
        let evaluation = gate.evaluate(scope)
        let hooks = newHooks(status: status, evaluation: evaluation)
        if !hooks.isEmpty {
            showHooks(hooks, recorded: status,
                      heading: "New hooks can approve shell commands, which skips the classifier, so auto mode "
                        + "approves nothing until you acknowledge them (trusting their code):",
                      rulesHeading: "Auto-mode classifier rules changed, so auto mode approves nothing until you "
                        + "acknowledge them as they are now:")
            if Prompt.confirm("Acknowledge \(Self.acknowledgementSubject(hooks)) (asks for Touch ID)?") {
                configure(.acknowledgeHooks(
                    claudeConfigDirectory: scope.claudeConfigDirectory, projectDirectory: context.workingDirectory),
                    success: "Acknowledged.")
            }
        }
        for build in untrustedBuilds(recorded: status) {
            Prompt.note("Claude Code \(build.label) (\(displayPath(build.path))) isn't signed by Anthropic: its "
                + "sessions use Touch ID. Trusting it by its exact code hash lets anything that can modify it act "
                + "as Claude Code.")
            if Prompt.confirm("Trust Claude Code \(build.label) (asks for Touch ID)?") {
                configure(.trustBuild(
                    path: build.path, claudeConfigDirectory: scope.claudeConfigDirectory,
                    projectDirectory: context.workingDirectory),
                    success: "Trusted Claude Code \(build.label).")
            }
        }
        showBlockers(evaluation)
        Prompt.note("Yes keeps delegated approvals on: auto mode can approve previously approved secret use, "
            + "SSH signing and sudo. No turns them off, reverts csec's Claude Code settings and forgets "
            + "every project pairing.")
        if !Prompt.confirm("Keep delegated approvals on?", default: true) {
            disable()
        }
    }

    func offerDisable(question: String = "Turn delegated approvals off?") {
        guard Prompt.confirm(question) else { return }
        disable()
    }

    private func disable() {
        switch ClaudeDelegationSetup.disable(
            projectDirectory: context.workingDirectory, client: client, gate: gate, scope: scope) {
        case let .disabled(_, revert):
            reportRevert(revert)
            Prompt.success("Delegated approvals are off, and every project pairing is gone. Restart open Claude "
                + "Code sessions so they read the reverted settings.")
        case let .failed(reason, revert):
            revert.map(reportRevert)
            Prompt.warn("csecd could not turn delegated approvals off (\(ReviewDisplay.sanitized(reason))); "
                + "re-run setup to try again.")
        }
    }

    // MARK: Inventory

    private func showInventory(recorded: DelegationStatus) {
        let evaluation = gate.evaluate(scope)
        let hooks = newHooks(status: recorded, evaluation: evaluation)
        if !hooks.isEmpty {
            showHooks(hooks, recorded: recorded,
                      heading: "Other hooks can approve shell commands, which skips the classifier. Turning this on "
                        + "acknowledges them, which trusts their code:",
                      rulesHeading: "Your settings carry auto-mode classifier rules. Turning this on acknowledges "
                        + "them as they are now:")
        }
        let builds = untrustedBuilds(recorded: recorded)
        if !builds.isEmpty {
            Prompt.note("Claude Code builds that aren't signed by Anthropic. Turning this on trusts them by their "
                + "exact code hash, which lets anything that can modify them act as Claude Code:")
            for build in builds { Prompt.note("  • \(build.label) (\(displayPath(build.path)))") }
        }
        showBlockers(evaluation)
    }

    private func showHooks(
        _ all: [ClaudeHookSource], recorded: DelegationStatus, heading: String, rulesHeading: String
    ) {
        let rules = all.filter { $0.kind == .classifierRules }
        let hooks = all.filter { $0.kind != .classifierRules }
        if !rules.isEmpty {
            Prompt.note(rulesHeading)
            for source in rules { showClassifierRules(source, recorded: recorded) }
        }
        guard !hooks.isEmpty else { return }
        Prompt.note(heading)
        for hook in hooks { Prompt.note("  • \(ReviewDisplay.sanitized(hook.display))") }
        for hook in hooks where hook.fetchesUnpinnedCode {
            Prompt.warn("\(ReviewDisplay.sanitized(hook.display)) runs a package it downloads when it runs, with no "
                + "version pinned: acknowledging it trusts whatever that download is, every time. Pin an exact "
                + "version (for example `npx pkg@1.2.3`) or run a local copy.")
        }
    }

    /// One source's classifier rules: the ones not in its last
    /// acknowledgement in full, and how many of those are gone. The rules are
    /// read here from the file; what csecd acknowledges is its own reading,
    /// by digest.
    private func showClassifierRules(_ source: ClaudeHookSource, recorded: DelegationStatus) {
        Prompt.note("  • \(ReviewDisplay.sanitized(source.display))")
        Prompt.note("    An allow or environment rule can tell the classifier to approve a command, and a "
            + "soft_deny or hard_deny list without \"$defaults\" replaces Claude Code's built-in blocks.")
        let isUserFile = source.sourceID == gate.userSettingsPath(scope)
        guard let data = FileManager.default.contents(atPath: source.sourceID),
              let rules = ClaudeClassifierRules.rules(inSettingsData: data, excludingCsecEntries: isUserFile) else {
            Prompt.warn("    csec could not read them to show here: review \(displayPath(source.sourceID)) yourself.")
            return
        }
        let previous = recorded.acknowledgedHooks
            .compactMap(\.classifierRules).first { $0.sourceID == source.sourceID }?.ruleDigests ?? []
        let acknowledged = Set(previous)
        let current = Set(rules.map(\.digest))
        let new = rules.filter { !acknowledged.contains($0.digest) }
        let removed = acknowledged.subtracting(current).count
        if !new.isEmpty {
            Prompt.note(acknowledged.isEmpty
                ? "    Its rules:" : "    New or changed since you acknowledged them:")
            for rule in new {
                let text = rule.text == ClaudeClassifierRules.defaultsMarker
                    ? "$defaults (keeps Claude Code's built-in rules)" : ReviewDisplay.sanitized(rule.text)
                Prompt.note("      [\(rule.section)] \(text)")
            }
        }
        if removed > 0 {
            Prompt.note("    \(removed) rule\(removed == 1 ? "" : "s") you acknowledged \(removed == 1 ? "is" : "are") gone.")
        }
        if new.isEmpty, removed == 0 {
            Prompt.note("    No rule was added or removed: their order changed, or a list is now empty, which "
                + "removes that list's built-in rules.")
        }
        let sections = Set(rules.map(\.section))
        for section in ["soft_deny", "hard_deny"] where sections.contains(section)
            && !rules.contains(where: { $0.section == section && $0.text == ClaudeClassifierRules.defaultsMarker }) {
            Prompt.warn("    \(section) has no \"$defaults\", so it replaces Claude Code's built-in \(section) rules.")
        }
    }

    /// What one acknowledgement covers, for its question.
    private static func acknowledgementSubject(_ hooks: [ClaudeHookSource]) -> String {
        let rules = hooks.contains { $0.kind == .classifierRules }
        let others = hooks.contains { $0.kind != .classifierRules }
        switch (others, rules) {
        case (true, true): return "these hooks and classifier rules"
        case (false, true): return "these classifier rules"
        default: return "these hooks"
        }
    }

    /// Settings that keep delegation inactive whatever enable does:
    /// everything but classifyAllShell (enable sets it) and hooks (enable
    /// acknowledges them).
    private func showBlockers(_ evaluation: ClaudeSettingsGateEvaluation) {
        var failures: [ClaudeSettingsGateFailure] = evaluation.unreadable.map { .unreadable($0) }
        failures += evaluation.environment.map { .injectedEnvironment($0) }
        failures += evaluation.sandboxEnabled.map { .sandboxEnabled(path: $0) }
        failures += evaluation.bypassPermissionsDefault.map { .bypassPermissionsDefault(path: $0) }
        failures += evaluation.hooksDisabled.map { .hooksDisabled($0) }
        guard !failures.isEmpty else { return }
        Prompt.warn("Auto mode approves nothing while these hold:")
        for failure in failures {
            Prompt.warn("  • " + ClaudeDelegationStatusRows.describe(failure, displayPath: displayPath))
        }
    }

    /// Hooks neither csecd nor this csec finds acknowledged.
    private func newHooks(status: DelegationStatus, evaluation: ClaudeSettingsGateEvaluation) -> [ClaudeHookSource] {
        var hooks = status.unacknowledgedHooks
        let acknowledged = Set(status.acknowledgedHooks.map(\.digest))
        for hook in evaluation.unacknowledgedHooks(acknowledgedDigests: acknowledged)
        where !hooks.contains(where: { $0.digest == hook.digest }) {
            hooks.append(hook)
        }
        return hooks
    }

    /// Untrusted builds csecd found (installed versions and live sessions),
    /// with the installed versions this csec finds itself.
    private func untrustedBuilds(recorded: DelegationStatus) -> [(label: String, path: String)] {
        var builds = recorded.discoveredUntrustedBuilds.map { (label: ReviewDisplay.sanitized($0.versionLabel), path: $0.path) }
        let trusted = Set(recorded.trustedBuilds.map(\.cdHash))
        for build in gate.discoverBuilds(scope).untrusted(trustedCDHashes: trusted)
        where !builds.contains(where: { $0.path == build.path }) {
            builds.append((ReviewDisplay.sanitized(build.versionLabel), build.path))
        }
        return builds
    }

    // MARK: Edits and results

    /// Show what enabling changes in the settings file; false when it cannot.
    private func showPlannedEdits(_ plan: ClaudeSettingsEditPlan, recorded: DelegationStatus) -> Bool {
        let file = displayPath(plan.settingsPath)
        if case let .blocked(reason) = plan.outcome {
            Prompt.warn("csec cannot edit \(file): \(ReviewDisplay.sanitized(reason)). Fix it and re-run setup.")
            return false
        }
        if let previous = recorded.claudeSettingsPath, previous != plan.settingsPath {
            Prompt.warn("Once you approve, csec reverts what it changed in \(displayPath(previous)), so Claude Code "
                + "sessions that read it (any without this CLAUDE_CONFIG_DIR) get no delegated approvals.")
        }
        switch plan.classifyAllShell {
        case .add:
            Prompt.note("Will set autoMode.classifyAllShell in \(file), so no allow rule can approve a Bash command "
                + "without the classifier. csec records that it added it and removes it when you turn this off.")
        case .alreadySet:
            Prompt.note("autoMode.classifyAllShell is already on in \(file); csec leaves it as you set it.")
        case .remove, .leave, .unchanged:
            break
        }
        if plan.environmentEntry == .delegationAware {
            Prompt.note("Will switch csec's autoMode.environment entry in \(file) to tell the classifier that its "
                + "approval releases this project's secrets:")
            Prompt.note(ReviewDisplay.sanitized(CodingAgentSetup.ClaudeAutoModeEntry.delegationAware.text))
        }
        return true
    }

    @discardableResult
    private func report(_ result: ClaudeDelegationSetup.EnableResult, settingsPath: String) -> Bool {
        switch result {
        case let .enabled(status, replaced):
            replaced.map(reportRevert)
            Prompt.success("Delegated approvals are on. Restart open Claude Code sessions so they read the new "
                + "settings.")
            let acknowledged = Set(status.acknowledgedHooks.map(\.digest))
            if let failure = status.settings?.firstFailure(acknowledgedDigests: acknowledged) {
                Prompt.warn("Auto mode approves nothing until this changes: "
                    + ClaudeDelegationStatusRows.describe(failure, displayPath: displayPath))
            }
            return true
        case let .notStarted(reason):
            Prompt.warn("Nothing changed: \(ReviewDisplay.sanitized(reason)).")
        case let .settingsNotWritten(reason):
            Prompt.warn("csec could not write \(displayPath(settingsPath)) (\(ReviewDisplay.sanitized(reason))); "
                + "nothing changed.")
        case let .denied(reason, undo):
            undo.map(reportRevert)
            Prompt.warn(ClaudeDelegationSetup.notGivenMessage(reason, unchanged: "delegated approvals stay as they were"))
        case let .failed(reason, undo):
            undo.map(reportRevert)
            Prompt.warn("csecd could not turn delegated approvals on (\(ReviewDisplay.sanitized(reason))).")
        }
        return false
    }

    private func reportRevert(_ revert: ClaudeDelegationSetup.SettingsRevert) {
        switch revert.result {
        case .reverted:
            Prompt.note("Reverted csec's auto-mode settings in \(displayPath(revert.settingsPath)).")
        case .nothingToChange:
            break
        case let .notWritten(reason):
            Prompt.warn("csec could not revert \(displayPath(revert.settingsPath)) "
                + "(\(ReviewDisplay.sanitized(reason))): \(revert.manualInstructions ?? "").")
        }
    }

    private func configure(_ request: DelegationConfigurationRequest, success: String) {
        do {
            _ = try client.configureDelegation(request)
            Prompt.success(success)
        } catch let AgentClient.ClientError.denied(reason) {
            Prompt.warn(ClaudeDelegationSetup.notGivenMessage(reason, unchanged: "nothing changed"))
        } catch {
            Prompt.warn("csecd refused (\(ReviewDisplay.sanitized(error.localizedDescription))); nothing changed.")
        }
    }
}

// MARK: - Step 4: audit prompt + host audit

private func stepAuditPromptAndAudit(
    projectDirectory: String,
    launchStatus: LaunchAgentStatus,
    agentReachable: Bool,
    providerSchemes: [String],
    rootReachable: Bool,
    sipStatus: SIPStatus,
    plans: [CodingAgentConfigurationPlan],
    discovery: LocalSecretDiscovery
) {
    Prompt.step("4. Security audit")
    let auditPrompt = try? OnboardingAuditPrompt.generate(facts: OnboardingAuditFacts(
        projectDirectory: projectDirectory,
        launchAgentStatus: launchStatus.description,
        productAgentReachable: agentReachable,
        providerSchemes: providerSchemes,
        rootHelperReachable: rootReachable,
        sipStatus: sipStatus,
        codingAgentPlans: plans,
        discovery: discovery))
    if let auditPrompt {
        if Prompt.confirm("Show the bounded security-audit prompt to paste into a coding agent?") {
            // Copyable data → stdout, so `csec setup | pbcopy`-style capture works
            // and the prompt is not tangled with the guided narrative on stderr.
            FileHandle.standardOutput.write(Data(auditPrompt.utf8))
        }
    }

    guard agentReachable else {
        Prompt.note("Skipping the host audit — csecd is not reachable yet. Run `csec audit` once it is.")
        return
    }
    if Prompt.confirm("Run csec audit now to review host posture?") {
        performHostAudit(scanFilesystem: false, reportOnly: false, json: false)
    }
}

// MARK: - Recap

private func setupRecap(
    touchID: TouchIDReadiness, launchStatus: LaunchAgentStatus, agentReachable: Bool,
    commandLink: CommandLinkState, fda: FDAState, configuredClients: [String], sudoReview: SudoReviewOutcome
) {
    Prompt.step("Summary")
    if touchID.canApprove {
        Prompt.success("Touch ID ready")
    } else {
        Prompt.warn("Touch ID not usable yet: nothing can be approved on this Mac until it is")
    }
    if agentReachable {
        Prompt.success("csecd reachable")
    } else if launchStatus == .requiresApproval {
        Prompt.warn("csecd awaiting approval in Login Items")
    } else {
        Prompt.warn("csecd not running yet")
    }
    if commandLink == .linked {
        Prompt.success("csec on PATH")
    } else {
        Prompt.warn("csec not on PATH (\(ReviewDisplay.sanitized(commandLink.rowValue)))")
    }
    switch fda {
    case .granted: Prompt.success("Full Disk Access granted")
    case .missing: Prompt.warn("Full Disk Access not yet granted")
    case .unknown: Prompt.note("Full Disk Access not checked (csecd unavailable)")
    }
    if configuredClients.isEmpty {
        Prompt.note("Coding-agent hooks: no change")
    } else {
        Prompt.success("Coding-agent hooks configured: \(configuredClients.joined(separator: ", "))")
    }
    switch sudoReview {
    case .active: Prompt.success("sudo review on")
    case .off: Prompt.note("sudo review off")
    case .attention: Prompt.warn("sudo review needs attention (see step 3d)")
    }
    Prompt.note("Next: `csec status` to review everything, `csec audit` to harden the host.")
}

// MARK: - Options + helpers

private func parseSetupOptions(_ arguments: [String]) throws -> String {
    var projectDirectory = FileManager.default.currentDirectoryPath
    var sawProject = false
    var index = 0
    while index < arguments.count {
        switch arguments[index] {
        case "--project":
            index += 1
            guard !sawProject, index < arguments.count, !arguments[index].isEmpty else {
                throw SetupOnboardingError.invalidProjectDirectory
            }
            sawProject = true
            projectDirectory = absoluteSetupPath(arguments[index])
        default:
            throw SetupOnboardingError.configurationConflict(
                "unknown setup option: \(ReviewDisplay.sanitized(arguments[index]))")
        }
        index += 1
    }
    return projectDirectory
}

private func absoluteSetupPath(_ value: String) -> String {
    let url = value.hasPrefix("/")
        ? URL(fileURLWithPath: value)
        : URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent(value)
    return url.standardizedFileURL.path
}

private func setupRootHelperReachable() -> Bool {
    #if DEBUG
    let trust: RootHelperServerTrustPolicy = .allowUnverifiedForTesting
    #else
    let trust: RootHelperServerTrustPolicy = .requireProductRootHelper
    #endif
    do {
        try RootHelperClient(trustPolicy: trust).health()
        return true
    } catch {
        return false
    }
}

/// Run `work` on the calling thread while an indeterminate spinner animates on a
/// helper thread. When stderr is not a terminal, run silently.
private func withSpinner<T>(_ label: String, _ work: () throws -> T) rethrows -> T {
    guard isatty(STDERR_FILENO) == 1 else { return try work() }
    let stop = SetupSpinnerFlag()
    let finished = DispatchSemaphore(value: 0)
    Thread.detachNewThread {
        var spinner = IndeterminateSpinner(label: label)
        while !stop.value {
            spinner.tick()
            usleep(90_000)
        }
        spinner.stop()
        finished.signal()
    }
    defer {
        stop.set()
        finished.wait()
    }
    return try work()
}

/// A tiny lock-guarded flag shared with the spinner helper thread.
private final class SetupSpinnerFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    var value: Bool { lock.lock(); defer { lock.unlock() }; return flag }
    func set() { lock.lock(); flag = true; lock.unlock() }
}
