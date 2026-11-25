import ConvenientSecurity
import Foundation
import CSECBuildIdentity
#if canImport(Darwin)
import Darwin
#endif

private enum InstalledProduct {
    static let appPath = "/Applications/ConvenientSecurity.app"
    static let launcherPath = CodingAgentSetup.installedLauncherPath
    static let agentPath = appPath + "/Contents/MacOS/csecd"
    static let agentLabel = CSECBuildIdentity.identifier
    static let rootLabel = CSECBuildIdentity.named("rootd")
}

private struct CompleteStatus {
    let developmentEndpoint: Bool
    /// `csec doctor --runtime`, build-and-install's gate right after the
    /// package install, before the later stages.
    let runtimeOnly: Bool
    let installedApplicationReady: Bool
    let serviceManagementStatus: LaunchAgentStatus
    let launchAgentLoaded: Bool
    let agentReachable: Bool
    let agentTrustFailure: String?
    let schemes: [String]?
    let providerStatus: [ProviderStatusSummary]
    let sshSocketPresent: Bool
    let sshKeys: Int?
    let sshEnvironmentConfigured: Bool
    /// csecd's GitHub token proxy: its socket, and the registration csecd
    /// reports (nil when csecd could not answer).
    let githubSocketPresent: Bool
    let github: GitHubProxyStatus?
    let remoteApproval: RemoteApprovalConfigurationStatus?
    /// Reported, never part of `healthy`: see `NativeStoreBackupStatusReport`.
    let nativeStoreBackup: NativeStoreBackupStatus?
    let rootHelperReachable: Bool
    /// The package's uninstaller (`csec uninstall --all`); nil with the
    /// development endpoint, which has no package.
    let uninstaller: CompleteUninstall.InstalledState?
    let sudoReview: SudoIntegrationState?
    /// Whether an active sudo review is the build the package carries: a
    /// package upgrade replaces only the payload, and `csec setup` installs
    /// it. Warns, never fails: build-and-install --skip-sudo leaves an older
    /// but sound integration on purpose. `nil` when nothing is compared.
    let sudoReviewPayload: SudoReviewPayloadMatch?
    /// The package's `csec` on PATH; `nil` in the runtime-only gate and for
    /// a development endpoint.
    let commandLink: CommandLinkState?
    /// Installed by build-and-install like the sudo integration; `nil` in the
    /// runtime-only gate, which runs before that stage.
    let codexHook: CodexSystemHookState?
    /// A missing managed hook fails doctor only where Codex is installed.
    let codexDetected: Bool
    /// User configuration: reported, never part of `healthy`.
    let codexUserHook: CodingAgentHookStatus.CodexUserHook
    let codexOpaqueRulesSources: [String]
    let codexHooksDisabledSources: [String]
    let claudeHook: ClaudeHookState
    let universalAllowRules: [UniversalAllowRule]
    /// Reported, never part of `healthy`: an integrity finding is recorded and
    /// the log continues, so nothing is left for doctor to repair. Its
    /// `heldItems` are the exception (see `protectedItemsHeldFailing`).
    let decisionLog: DecisionLogStatus?
    /// Delegated approvals, as csecd reports them.
    let delegation: ClaudeDelegationStatusRows.Report
    /// csec's own reading of Claude Code's settings, when csecd's status came
    /// without one.
    let delegationEvaluation: ClaudeSettingsGateEvaluation?
    /// A user settings file still holding the delegation-aware auto-mode text
    /// while delegation is off.
    let delegationEntryRemainsIn: String?
    /// Whether a newer release is available, from the last verified release
    /// manifest csecd fetched. Reported, never part of `healthy`.
    let updates: ReleaseUpdateStatus

    var healthy: Bool {
        (developmentEndpoint || installedApplicationReady)
            && (developmentEndpoint || launchAgentLoaded)
            && agentReachable
            && schemes?.isEmpty == false
            && sshSocketPresent
            && sshKeys != nil
            && githubSocketPresent
            && github != nil
            && rootHelperReachable
            && (uninstaller == nil || uninstaller == .installed)
            // An installed-but-broken sudo integration is unhealthy: sudo either
            // falls back to the stock prompt or keeps drawing a stale dialog.
            && (developmentEndpoint || sudoReview?.isDefect != true)
            && (developmentEndpoint || !codexHookFailing)
            && commandLink?.failsDoctor != true
            // Every shipped csecd carries the CloudKit entitlement, and an
            // unusable pairing keeps every request off the phone until it is
            // redone; a temporary iCloud or Keychain condition only warns.
            && !RemoteApprovalStatusReport.failsDoctor(
                remoteApproval, developmentEndpoint: developmentEndpoint)
            // Only an unreadable delegation settings item fails doctor; every
            // other delegation state is the user's choice or a warning.
            && !delegationSettingsUnreadable
            && (runtimeOnly || !protectedItemsHeldFailing)
    }

    /// A protected item csecd could not read and keeps as found because a
    /// newer csec wrote it or the Keychain refused it: what is approved
    /// meanwhile lasts only until csecd restarts, so the install is not done.
    /// Not part of the runtime gate, so an install over held items still
    /// finishes every stage before the final doctor fails. A damaged item only
    /// warns: no install mends it, and the row names what removes it.
    var protectedItemsHeldFailing: Bool {
        HeldItemsReport.fails(decisionLog?.heldItems ?? [])
    }

    var codexHookFailing: Bool {
        CodingAgentHookStatus.codexSystemHookFailsDoctor(codexHook, codexDetected: codexDetected)
    }

    var delegationSettingsUnreadable: Bool {
        if case let .status(status) = delegation { return status.state == .unreadable }
        return false
    }
}

/// The sudo inspection spawns `codesign`, and `csec doctor` re-collects status in
/// a loop while it waits for csecd; a `static let` runs it at most once per
/// process, and only when something actually reads it (never in development mode).
private enum SudoReviewInspection {
    static let current: SudoIntegrationState = blocking()

    private static func blocking() -> SudoIntegrationState {
        let box = Box()
        let finished = DispatchSemaphore(value: 0)
        Task.detached {
            box.store(await SudoIntegrationInspection.inspect(
                files: SystemFileInspector(), commands: SystemCommandRunner()))
            finished.signal()
        }
        finished.wait()
        return box.value ?? .helperSignatureUnreadable
    }

    private final class Box: @unchecked Sendable {
        private let lock = NSLock()
        private var state: SudoIntegrationState?
        func store(_ value: SudoIntegrationState) {
            lock.lock(); state = value; lock.unlock()
        }
        var value: SudoIntegrationState? {
            lock.lock(); defer { lock.unlock() }; return state
        }
    }
}

enum LaunchctlInspection {
    static func agentLoaded() -> Bool {
        run(["print", "gui/\(getuid())/\(InstalledProduct.agentLabel)"])
    }

    static func kickstartAgent() -> Bool {
        run(["kickstart", "-k", "gui/\(getuid())/\(InstalledProduct.agentLabel)"])
    }

    /// How long launchd's csecd has been running, or nil when it runs none.
    static func agentAge() -> TimeInterval? {
        guard let output = output(["print", "gui/\(getuid())/\(InstalledProduct.agentLabel)"]),
              let pid = AgentStartupWait.runningPID(launchctlPrint: output) else { return nil }
        return AgentStartupWait.processAge(pid: pid)
    }

    static func kickstartRootHelper() -> Bool {
        run(["kickstart", "-k", "system/\(InstalledProduct.rootLabel)"])
    }

    private static func output(_ arguments: [String]) -> String? {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.environment = ["LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        let pipe = Pipe()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationReason == .exit, process.terminationStatus == 0 else { return nil }
            return String(decoding: data, as: UTF8.self)
        } catch {
            return nil
        }
    }

    private static func run(_ arguments: [String]) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.environment = ["LC_ALL": "C", "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            return process.terminationReason == .exit && process.terminationStatus == 0
        } catch {
            return false
        }
    }
}

func runStatus(_ arguments: [String] = []) -> Never {
    if arguments == ["--claude-builds-json"] { runClaudeBuildStatus() }
    guard arguments.isEmpty else { usage("status") }
    let status = collectCompleteStatus()
    renderCompleteStatus(status)
    exit(status.healthy ? 0 : 1)
}

/// The release watchdog needs only this bounded metadata, not provider,
/// settings or credential contents. Use csecd's catalog and live identities,
/// so a newer source checkout cannot hide an installed daemon's stale gate.
private func runClaudeBuildStatus() -> Never {
    do {
        guard case let .configured(status, _) = try makeAgentClient().configureDelegation(
            .status(claudeConfigDirectory: nil, projectDirectory: nil)),
              let report = status.buildVerification, report.isWellFormed else {
            csecError("status", "csecd could not report Claude Code release verification; update csec")
            exit(1)
        }
        let data = try JSONEncoder().encode(report)
        print(String(decoding: data, as: UTF8.self))
        exit(0)
    } catch {
        csecError("status", "\(error.localizedDescription)")
        exit(1)
    }
}

/// `csec doctor` is an explicit repair command. Its default mode may register or
/// restart csecd, but never edits shell profiles, secret stores, or provider
/// configuration. `--check` is the corresponding read-only diagnostic.
/// `--runtime` is the installer's intermediate gate before the sudo stage; it
/// never claims to verify the complete installation or its sudo integration.
func runDoctor(_ arguments: [String]) -> Never {
    if arguments == ["--report"] {
        let status = collectCompleteStatus()
        let crashes = SupportDiagnostics.recentCrashes()
        let os = ProcessInfo.processInfo.operatingSystemVersion
        var lines = ["Convenient Security diagnostic report",
                     "macOS \(os.majorVersion).\(os.minorVersion).\(os.patchVersion)",
                     "", "Installed components"]
        lines += ReportComponents.rows(phoneVersion: status.remoteApproval?.phoneAppVersion)
        lines += ["", "Doctor: \(status.healthy ? "healthy" : "needs attention")"]
        lines += SupportDiagnostics.doctorChecks(statusRows(status))
        let log = (AgentSocket.directory() as NSString).appendingPathComponent("csecd.log")
        lines += ["", "Recent csecd log (up to 100 lines)", SupportDiagnostics.logTail(path: log),
                  "", "Recent csec crashes (past seven days)"]
        if crashes.isEmpty { lines.append("No readable recent crash reports found.") }
        let formatter = ISO8601DateFormatter()
        for crash in crashes {
            lines += ["\(crash.process) — \(formatter.string(from: crash.date))", crash.stack]
        }
        do {
            let directory = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            let url = try SupportDiagnostics.save(lines.joined(separator: "\n") + "\n", directory: directory)
            print("Review \(url.lastPathComponent) in the current directory before sending it to support.")
            exit(0)
        } catch {
            csecError("doctor", "could not write the report in the current directory")
            exit(1)
        }
    }
    guard Set(arguments).count == arguments.count,
          arguments.allSatisfy({ $0 == "--check" || $0 == "--runtime" }) else {
        usage("doctor")
    }
    let checkOnly = arguments.contains("--check")
    let runtimeOnly = arguments.contains("--runtime")

    if let crash = SupportDiagnostics.recentCrashes(for: "csecd").first {
        Prompt.note("csecd recently crashed (\(ISO8601DateFormatter().string(from: crash.date))). "
            + "Run csec doctor --report to include the crash stack in a support file.")
    }

    Prompt.note(runtimeOnly
        ? "checking the installed runtime (sudo integration is checked separately)"
        : "checking the complete installation")
    var status = collectCompleteStatus(runtimeOnly: runtimeOnly)
    if let problem = StartupSecurityReport.sipStartupProblem(
        developmentEndpoint: status.developmentEndpoint, agentReachable: status.agentReachable,
        sipStatus: StartupSecurityReport.querySIP()
    ) {
        renderCompleteStatus(status)
        csecError("doctor", problem)
        exit(1)
    }
    if checkOnly || status.healthy || status.developmentEndpoint {
        renderCompleteStatus(status)
        if checkOnly, !status.healthy {
            Prompt.note("Repair: run `csec doctor` without --check.")
        }
        if !status.sshEnvironmentConfigured {
            FileHandle.standardOutput.write(Data(sshActivationGuidanceIfNeeded().utf8))
        }
        exit(status.healthy ? 0 : 1)
    }

    guard status.installedApplicationReady else {
        renderCompleteStatus(status)
        csecError("doctor", "the root-owned installed app is missing or incomplete; "
            + "reinstall the Convenient Security package")
        exit(1)
    }

    var repairs: [String] = []
    if !status.launchAgentLoaded {
        switch status.serviceManagementStatus {
        case .requiresApproval:
            renderCompleteStatus(status)
            csecError("doctor", "approve ConvenientSecurity in System Settings > General > Login Items, then rerun csec doctor")
            exit(1)
        case .enabled:
            if LaunchctlInspection.kickstartAgent() {
                repairs.append("requested csecd startup")
            }
        case .notRegistered, .notFound, .unknown:
            do {
                let registered = try LaunchAgentService.install()
                repairs.append("registered the per-user csecd LaunchAgent")
                if registered.needsApproval {
                    renderCompleteStatus(collectCompleteStatus(runtimeOnly: runtimeOnly))
                    csecError("doctor", "approve ConvenientSecurity in System Settings > General > Login Items, then rerun csec doctor")
                    exit(1)
                }
            } catch {
                // A stale ServiceManagement status can disagree with launchd.
                // Reinspect before treating registration failure as terminal.
                guard LaunchctlInspection.agentLoaded() else {
                    renderCompleteStatus(collectCompleteStatus(runtimeOnly: runtimeOnly))
                    csecError("doctor", "could not register the per-user LaunchAgent: \(ReviewDisplay.sanitized(error.localizedDescription))")
                    exit(1)
                }
            }
        }
    }

    status = waitForLaunchAgent(timeout: 3, runtimeOnly: runtimeOnly)
    // A csecd launchd started moments ago may still be starting; restarting it
    // would only begin that work again. Wait for it first (AgentStartupWait).
    if status.launchAgentLoaded, !agentIsHealthy(status),
       !AgentStartupWait.restartNow(trustFailure: status.agentTrustFailure != nil,
                                    age: LaunchctlInspection.agentAge()) {
        status = waitForAgentHealth(runtimeOnly: runtimeOnly)
    }
    if status.launchAgentLoaded, !agentIsHealthy(status) {
        if LaunchctlInspection.kickstartAgent() {
            repairs.append(status.agentTrustFailure == nil
                ? "restarted csecd"
                : "restarted csecd after the live agent failed identity verification")
        }
    }

    status = waitForAgentHealth(runtimeOnly: runtimeOnly)
    // A saved item the Keychain refused to csecd at startup (before the first
    // unlock, say) is read again by a restart; a newer or damaged one is not.
    if status.agentReachable,
       status.decisionLog?.heldItems?.contains(where: { $0.cause == .keychain }) == true,
       LaunchctlInspection.kickstartAgent() {
        repairs.append("restarted csecd to read a saved item the Keychain refused at its start")
        status = waitForAgentHealth(runtimeOnly: runtimeOnly)
    }
    if !status.rootHelperReachable, LaunchctlInspection.kickstartRootHelper() {
        repairs.append("requested root-helper startup")
        status = waitForRootHelper(timeout: 2, runtimeOnly: runtimeOnly)
    }

    for repair in repairs { Prompt.success("repaired — \(repair)") }
    renderCompleteStatus(status)
    if !status.sshEnvironmentConfigured {
        FileHandle.standardOutput.write(Data(sshActivationGuidanceIfNeeded().utf8))
    }

    guard status.healthy else {
        if !status.agentReachable {
            let log = (AgentSocket.directory() as NSString).appendingPathComponent("csecd.log")
            csecError("doctor", "csecd did not become healthy; inspect \(ReviewDisplay.sanitized(log))")
        }
        if !status.rootHelperReachable {
            csecError("doctor", "the authenticated root helper is unavailable; reinstall the Convenient Security package")
        }
        if status.sudoReview?.isDefect == true {
            csecError("doctor", "the sudo review helper is missing or stale. Run csec setup and accept the sudo review step.")
        }
        if let uninstaller = status.uninstaller, uninstaller != .installed {
            csecError("doctor", "the package's uninstaller \(CompleteUninstall.scriptPath) is missing, unprotected "
                + "or not the copy this app shipped; reinstall the Convenient Security package")
        }
        if status.commandLink?.failsDoctor == true {
            csecError("doctor", "\(PackagePayload.commandLinkPath) is missing, so `csec` is not on PATH; "
                + "reinstall the Convenient Security package")
        }
        if status.codexHookFailing, let codexHook = status.codexHook {
            let path = CodingAgentSetup.codexSystemHookPath
            switch codexHook {
            case .missing, .stale:
                csecError("doctor", "the managed Codex hook in \(path) is \(codexHook.rawValue). Run csec setup.")
            case .unsafe:
                csecError("doctor", "ask an administrator to check the ownership and write permissions of \(path), then run csec setup")
            case .unreadable:
                csecError("doctor", "ask an administrator to repair the JSON in \(path), then run csec setup")
            case .installed:
                break
            }
        }
        let held = status.decisionLog?.heldItems ?? []
        for item in held {
            csecError("doctor", "csecd cannot read \(item.display), and keeps it as found: "
                + "what is approved meanwhile lasts only until csecd restarts")
        }
        if status.delegationSettingsUnreadable,
           !held.contains(where: { $0.name == ProtectedItem.delegationSettings.displayName }) {
            csecError("doctor", "csecd cannot read its delegated-approval settings, so auto mode approves nothing; "
                + "run csec setup to turn them off and on again")
        }
        if RemoteApprovalStatusReport.failsDoctor(
            status.remoteApproval, developmentEndpoint: status.developmentEndpoint),
           let repair = RemoteApprovalStatusReport.doctorRepair(status.remoteApproval) {
            csecError("doctor", repair)
        }
        exit(1)
    }
    Prompt.success(runtimeOnly ? "installed runtime is healthy; sudo integration was not checked" : "installation is healthy")
    exit(0)
}

private func collectCompleteStatus(runtimeOnly: Bool = false) -> CompleteStatus {
    let development = AgentSocket.isUsingDebugOverride
    let serviceStatus = development ? .notRegistered : LaunchAgentService.status()
    let launchAgentLoaded = development || LaunchctlInspection.agentLoaded()
    let appReady = development || installedApplicationIsReady()
    let client = makeAgentClient()

    let agentReachable: Bool
    let agentTrustFailure: String?
    var capabilities: ProtocolCapabilities?
    do {
        capabilities = try client.capabilities()
        agentReachable = true
        agentTrustFailure = nil
    } catch AgentClient.ClientError.untrustedServer(let reason) {
        agentReachable = false
        agentTrustFailure = ReviewDisplay.sanitized(String(reason.prefix(300)))
    } catch {
        agentReachable = false
        agentTrustFailure = nil
    }
    let providers = agentReachable ? try? client.schemesWithProviderStatus() : nil
    let schemes = providers?.schemes.sorted()
    let sshKeys = agentReachable ? try? client.listSSHKeys().count : nil
    let remoteApproval = agentReachable ? try? client.remoteApprovalStatus() : nil
    let nativeStoreBackup = agentReachable
        ? (try? client.nativeStoreBackup(NativeStoreBackupRequest(action: .status)))?.status : nil
    let decisionLog = agentReachable ? try? client.decisionLogStatus() : nil
    let sshPath = SSHAgentSocket.defaultPath()
    let github = agentReachable ? try? client.githubProxyStatus() : nil
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let codexHome = ProcessInfo.processInfo.environment["CODEX_HOME"]
    let delegation = collectDelegationStatus(
        client: client, reachable: agentReachable, capabilities: capabilities)
    let sudoReview: SudoIntegrationState? = runtimeOnly
        ? nil : (development ? .notInstalled : SudoReviewInspection.current)

    return CompleteStatus(
        developmentEndpoint: development,
        runtimeOnly: runtimeOnly,
        installedApplicationReady: appReady,
        serviceManagementStatus: serviceStatus,
        launchAgentLoaded: launchAgentLoaded,
        agentReachable: agentReachable,
        agentTrustFailure: agentTrustFailure,
        schemes: schemes,
        providerStatus: providers?.providerStatus ?? [],
        sshSocketPresent: ownedSocketExists(path: sshPath, requiredMode: 0o600),
        sshKeys: sshKeys,
        sshEnvironmentConfigured:
            ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"] == sshPath,
        githubSocketPresent: ownedSocketExists(path: GitHubProxySocket.defaultPath(), requiredMode: 0o600),
        github: github,
        remoteApproval: remoteApproval,
        nativeStoreBackup: nativeStoreBackup,
        rootHelperReachable: rootHelperIsReachable(),
        uninstaller: development ? nil : CompleteUninstall.installedState(),
        sudoReview: sudoReview,
        sudoReviewPayload: sudoReview?.isHealthy == true ? SudoReviewPayloadMatch.compare() : nil,
        commandLink: runtimeOnly || development ? nil : CommandLinkState.inspect(),
        codexHook: runtimeOnly || development ? nil
            : CodingAgentSetup.codexSystemHookState(csecExecutablePath: InstalledProduct.launcherPath),
        codexDetected: CodingAgentHookStatus.codexDetected(
            homeDirectory: home,
            pathEnvironment: ProcessInfo.processInfo.environment["PATH"],
            codexHome: codexHome),
        codexUserHook: CodingAgentHookStatus.codexUserHook(homeDirectory: home, codexHome: codexHome),
        codexOpaqueRulesSources: CodexCommandGate.loadPolicy(
            homeDirectory: home,
            codexHome: codexHome,
            workingDirectory: FileManager.default.currentDirectoryPath).opaqueSources,
        codexHooksDisabledSources: CodexCommandGate.hooksDisabledSources(homeDirectory: home, codexHome: codexHome),
        claudeHook: CodingAgentHookStatus.claudeHookState(
            homeDirectory: home,
            pathEnvironment: ProcessInfo.processInfo.environment["PATH"],
            csecExecutablePath: InstalledProduct.launcherPath,
            claudeConfigDirectory: ProcessInfo.processInfo.environment["CLAUDE_CONFIG_DIR"]),
        universalAllowRules: CodingAgentHookStatus.claudeUniversalAllowRules(
            settingsPaths: CodingAgentHookStatus.claudeSettingsPaths(
                homeDirectory: home,
                workingDirectory: FileManager.default.currentDirectoryPath))
            + CodingAgentHookStatus.codexUniversalAllowRules(
                homeDirectory: home, codexHome: codexHome,
                workingDirectory: FileManager.default.currentDirectoryPath),
        decisionLog: decisionLog,
        delegation: delegation.report,
        delegationEvaluation: delegation.evaluation,
        delegationEntryRemainsIn: delegation.entryRemainsIn,
        updates: currentUpdateStatus()
    )
}

/// csecd's delegation status for this user and working directory. csec reads
/// the settings itself only when csecd sent no evaluation of its own, and
/// checks for the delegation-aware auto-mode text only while delegation is off.
private func collectDelegationStatus(
    client: AgentClient,
    reachable: Bool,
    capabilities: ProtocolCapabilities?
) -> (report: ClaudeDelegationStatusRows.Report, evaluation: ClaudeSettingsGateEvaluation?, entryRemainsIn: String?) {
    guard reachable else { return (.csecdUnavailable, nil, nil) }
    guard capabilities?.features.contains(.delegatedApprovals) == true else { return (.unsupported, nil, nil) }
    let context = ClaudeSettingsContext.current(csecExecutablePath: InstalledProduct.launcherPath)
    let status: DelegationStatus
    do {
        guard case let .configured(reported, _) = try client.configureDelegation(.status(
            claudeConfigDirectory: context.scope?.claudeConfigDirectory,
            projectDirectory: context.workingDirectory)) else {
            return (.failed("csecd answered status with a revocation"), nil, nil)
        }
        status = reported
    } catch {
        return (.failed(error.localizedDescription), nil, nil)
    }
    let evaluation = status.state == .on && status.settings == nil
        ? context.scope.map { makeClaudeSettingsGate().evaluate($0) } : nil
    let settingsPath = context.scope.map { makeClaudeSettingsGate().userSettingsPath($0) }
    let entryRemainsIn = status.state == .off
        ? settingsPath.flatMap { CodingAgentSetup.claudeAutoModeEntry(inSettingsAt: $0) == .delegationAware ? $0 : nil }
        : nil
    return (.status(status), evaluation, entryRemainsIn)
}

private func renderCompleteStatus(_ status: CompleteStatus) {
    print(StatusRenderer.render(
        title: status.sudoReview == nil ? "Convenient Security runtime status" : "Convenient Security status",
        rows: statusRows(status),
        overallHealthy: status.healthy,
        color: TerminalStyle.colorEnabled(STDOUT_FILENO),
        width: TerminalStyle.terminalWidth(fd: STDOUT_FILENO)))
}

/// Map the launcher's `CompleteStatus` facts into colored status rows. A
/// development endpoint reports app/LaunchAgent as neutral (not a real install);
/// otherwise each row grades to ok/warn/bad the way `CompleteStatus.healthy` does.
private func statusRows(_ status: CompleteStatus) -> [StatusRow] {
    var rows: [StatusRow] = []

    if status.developmentEndpoint {
        rows.append(StatusRow(label: "Installed app", value: "development endpoint selected", state: .neutral))
        rows.append(StatusRow(label: "LaunchAgent", value: "development endpoint selected", state: .neutral))
    } else {
        rows.append(StatusRow(
            label: "Installed app",
            value: status.installedApplicationReady ? "installed" : "missing or incomplete",
            state: status.installedApplicationReady ? .ok : .bad))
        if status.launchAgentLoaded {
            rows.append(StatusRow(label: "LaunchAgent", value: "registered with launchd", state: .ok))
        } else {
            rows.append(StatusRow(
                label: "LaunchAgent",
                value: status.serviceManagementStatus.description,
                state: status.serviceManagementStatus == .requiresApproval ? .warn : .bad))
        }
    }

    rows.append(status.updates.doctorRow)

    rows.append(StatusRow(
        label: "Agent control channel",
        value: status.agentReachable ? "reachable and authenticated" : (status.agentTrustFailure ?? "unavailable"),
        state: status.agentReachable ? .ok : .bad))

    switch status.schemes {
    case nil:
        rows.append(StatusRow(label: "Providers", value: "unavailable", state: .bad))
    case .some(let schemes) where schemes.isEmpty:
        rows.append(StatusRow(label: "Providers", value: "none available", state: .warn))
    case .some(let schemes):
        rows.append(StatusRow(label: "Providers", value: schemes.joined(separator: ", "), state: .ok))
    }

    // Per-provider detail (e.g. how many 1Password accounts are authorized and
    // how many vaults are indexed), so a provider that is registered but cannot
    // currently serve is visible without reading csecd's log.
    for provider in status.providerStatus {
        rows.append(StatusRow(
            label: ReviewDisplay.sanitized(String(provider.label.prefix(32))),
            value: ReviewDisplay.sanitized(String(provider.detail.prefix(160))),
            state: provider.healthy ? .ok : .warn))
    }

    if status.sshSocketPresent, status.sshKeys != nil {
        rows.append(StatusRow(label: "SSH agent", value: "ready", state: .ok))
    } else if status.sshSocketPresent {
        rows.append(StatusRow(label: "SSH agent", value: "socket present, signer unavailable", state: .warn))
    } else {
        rows.append(StatusRow(label: "SSH agent", value: "unavailable", state: .bad))
    }

    rows.append(StatusRow(
        label: "Protected SSH keys",
        value: status.sshKeys.map(String.init) ?? "unavailable",
        state: status.sshKeys != nil ? .ok : .bad))

    if status.githubSocketPresent, let github = status.github {
        let token = github.tokenReference.flatMap { try? SecretRef($0) }
        rows.append(StatusRow(
            label: "GitHub token proxy",
            value: token.map { "ready; gh's token is \($0.safeInlineURI)" }
                ?? "ready; no token registered (`csec protect --gh`)",
            state: .ok))
    } else if status.githubSocketPresent {
        rows.append(StatusRow(label: "GitHub token proxy", value: "socket present, csecd did not answer", state: .warn))
    } else {
        rows.append(StatusRow(label: "GitHub token proxy", value: "unavailable", state: .bad))
    }

    rows.append(StatusRow(
        label: "Shell SSH_AUTH_SOCK",
        value: status.sshEnvironmentConfigured ? "configured for csec" : "not configured for csec",
        state: status.sshEnvironmentConfigured ? .ok : .warn))

    rows.append(RemoteApprovalStatusReport.doctorRow(
        status.remoteApproval, developmentEndpoint: status.developmentEndpoint))
    rows.append(approvalWaitRow(ApprovalWaitLimit.current()))
    rows.append(NativeStoreBackupStatusReport.doctorRow(status.nativeStoreBackup))

    rows.append(decisionLogRow(status.decisionLog))
    if let held = status.decisionLog?.heldItems {
        rows.append(heldItemsRow(held))
    }

    rows.append(StatusRow(
        label: "Root helper",
        value: status.rootHelperReachable ? "reachable and authenticated" : "unavailable",
        state: status.rootHelperReachable ? .ok : .bad))

    if let uninstaller = status.uninstaller {
        rows.append(uninstallerRow(uninstaller))
    }
    rows.append(sudoReviewRow(status))
    if let commandLink = status.commandLink {
        rows.append(StatusRow(
            label: "csec on PATH",
            value: ReviewDisplay.sanitized(commandLink.rowValue),
            state: commandLink == .linked ? .ok : (commandLink.failsDoctor ? .bad : .warn)))
    }
    rows.append(contentsOf: CodingAgentHookStatus.codexRows(
        state: status.codexHook,
        codexDetected: status.codexDetected,
        userHook: status.codexUserHook,
        developmentEndpoint: status.developmentEndpoint,
        opaqueRulesSources: status.codexOpaqueRulesSources.map(abbreviatedPath),
        hooksDisabledSources: status.codexHooksDisabledSources.map(abbreviatedPath)))
    rows.append(CodingAgentHookStatus.claudeRow(status.claudeHook))
    rows.append(CodingAgentHookStatus.allowRulesRow(status.universalAllowRules, displayPath: abbreviatedPath))
    rows.append(contentsOf: ClaudeDelegationStatusRows.rows(
        status.delegation,
        evaluation: status.delegationEvaluation,
        delegationEntryRemainsIn: status.delegationEntryRemainsIn,
        displayPath: abbreviatedPath))

    return rows
}

/// The running csec's release against the last manifest csecd verified and
/// kept. The manifest is verified again here against this binary's pinned
/// keys; csec itself never fetches it.
private func currentUpdateStatus() -> ReleaseUpdateStatus {
    let store = ReleaseManifestStore()
    return ReleaseUpdateStatus.evaluate(
        running: ReleaseStamp.current, held: store.load(), state: store.loadState())
}

/// How long a coding agent's request may wait on a human before csecd
/// withdraws it (`ApprovalWaitLimit`), and how to change it.
func approvalWaitRow(_ limit: ApprovalWaitLimit.Resolution) -> StatusRow {
    let minutes = limit.minutes == 1 ? "1 minute" : "\(limit.minutes) minutes"
    if let ignored = limit.ignoredValue {
        return StatusRow(
            label: "Agent approval wait",
            value: "\(minutes) (default): the setting \(ignored) is not a whole number of minutes from "
                + "\(ApprovalWaitLimit.allowedMinutes.lowerBound) to \(ApprovalWaitLimit.allowedMinutes.upperBound); "
                + "change it with \(ApprovalWaitLimit.setCommand)",
            state: .warn)
    }
    return StatusRow(
        label: "Agent approval wait",
        value: "a coding agent's request nobody answers is withdrawn after \(minutes)"
            + (limit.isDefault ? " (default)" : "") + "; change it with \(ApprovalWaitLimit.setCommand)",
        state: .ok)
}

private enum HeldItemsReport {
    static func fails(_ held: [HeldProtectedItem]) -> Bool {
        held.contains { $0.cause != .damaged }
    }
}

private func heldItemsRow(_ held: [HeldProtectedItem]) -> StatusRow {
    guard !held.isEmpty else {
        return StatusRow(label: "Saved approvals", value: "readable", state: .ok)
    }
    return StatusRow(
        label: "Saved approvals",
        value: "csecd cannot read \(held.count == 1 ? "a saved item" : "\(held.count) saved items") and keeps "
            + "\(held.count == 1 ? "it" : "them") as found, so what is approved now lasts only until csecd restarts: "
            + held.prefix(8).map(\.display).joined(separator: "; "),
        state: HeldItemsReport.fails(held) ? .bad : .warn)
}

private func decisionLogRow(_ status: DecisionLogStatus?) -> StatusRow {
    guard let status else {
        return StatusRow(label: "Decision log", value: "unavailable", state: .warn)
    }
    // A finding outranks every other state: it is the one thing the log
    // exists to make visible. It warns but does not fail `csec doctor`,
    // which gates the install and has nothing to repair.
    if status.integrityEvents > 0 || status.unrecordedFinding {
        let findings = (status.lastVerification?.findings ?? [])
            .map { "\($0.stream.rawValue) \($0.finding.rawValue)" }
            .joined(separator: ", ")
        let what = findings.isEmpty ? "see the log" : findings
        return StatusRow(
            label: "Decision log",
            value: status.unrecordedFinding
                ? "altered outside csecd (\(what)); the finding could not be recorded and the log is held, "
                    + "run csec log --verify"
                : "altered outside csecd (\(what)); recorded, see csec log --kind log_integrity",
            state: .warn)
    }
    switch status.state {
    case .off:
        return StatusRow(label: "Decision log", value: "off (no protected stores)", state: .neutral)
    case .uninstalled:
        return StatusRow(label: "Decision log", value: "deleted by csec uninstall", state: .neutral)
    case .unavailable:
        return StatusRow(
            label: "Decision log",
            value: "unavailable" + (status.detail.map { ": \(ReviewDisplay.sanitized(String($0.prefix(120))))" } ?? ""),
            state: .warn)
    case .active:
        var value = "verified"
        if status.lastVerification?.status == .repaired { value += "; a torn final frame was cut" }
        if status.droppedRecords > 0 { value += "; \(status.droppedRecords) record(s) not written" }
        if status.checkpointWriteFailures > 0 {
            value += "; the checkpoint could not be written (\(status.checkpointWriteFailures)x)"
        }
        if !status.stuckFiles.isEmpty {
            value += "; csecd cannot move or remove "
                + status.stuckFiles.map { ReviewDisplay.sanitized($0) }.joined(separator: ", ")
                + " in its log directory (remove it by hand)"
        }
        let healthy = status.droppedRecords == 0 && status.checkpointWriteFailures == 0
            && status.stuckFiles.isEmpty
        return StatusRow(label: "Decision log", value: value, state: healthy ? .ok : .warn)
    }
}

private func abbreviatedPath(_ path: String) -> String {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let shown = path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
    return ReviewDisplay.sanitized(shown)
}

/// The sudo review dialog is installed separately from the app bundle, so a
/// reinstall can leave a stale or absent helper behind. Silent when the
/// integration is not installed; bad when it is installed and will not hand off.
private func uninstallerRow(_ state: CompleteUninstall.InstalledState) -> StatusRow {
    switch state {
    case .installed:
        return StatusRow(label: "Uninstaller", value: "installed (csec uninstall --all)", state: .ok)
    case let .unusable(reason):
        return StatusRow(label: "Uninstaller", value: ReviewDisplay.sanitized(reason), state: .bad)
    case .stale:
        return StatusRow(label: "Uninstaller", value: "not the copy this app shipped", state: .bad)
    }
}

private func sudoReviewRow(_ status: CompleteStatus) -> StatusRow {
    guard let sudoReview = status.sudoReview else {
        return StatusRow(label: "Sudo review", value: "not checked (runtime-only mode)", state: .neutral)
    }
    guard !status.developmentEndpoint else {
        return StatusRow(label: "Sudo review", value: "development endpoint selected", state: .neutral)
    }
    let value = ReviewDisplay.sanitized(sudoReview.rowValue)
    switch sudoReview {
    case .notInstalled:
        return StatusRow(label: "Sudo review", value: value, state: .neutral)
    case .healthy where status.sudoReviewPayload == .differs:
        return StatusRow(
            label: "Sudo review",
            value: "installed, but not the package's build; run csec setup to update it",
            state: .warn)
    case .healthy:
        return StatusRow(label: "Sudo review", value: value, state: .ok)
    case .helperSignatureUnreadable:
        return StatusRow(label: "Sudo review", value: value, state: .warn)
    default:
        return StatusRow(label: "Sudo review", value: value, state: .bad)
    }
}

private func waitForLaunchAgent(timeout: TimeInterval, runtimeOnly: Bool) -> CompleteStatus {
    let deadline = Date().addingTimeInterval(timeout)
    var status = collectCompleteStatus(runtimeOnly: runtimeOnly)
    while !status.launchAgentLoaded, Date() < deadline {
        usleep(200_000)
        status = collectCompleteStatus(runtimeOnly: runtimeOnly)
    }
    return status
}

private func agentIsHealthy(_ status: CompleteStatus) -> Bool {
    status.agentReachable && status.sshSocketPresent && status.sshKeys != nil
}

/// Waits `AgentStartupWait.settle`, and on while launchd still runs a csecd
/// that is starting, up to `AgentStartupWait.ceiling`.
private func waitForAgentHealth(runtimeOnly: Bool) -> CompleteStatus {
    let started = Date()
    var status = collectCompleteStatus(runtimeOnly: runtimeOnly)
    while !agentIsHealthy(status),
          AgentStartupWait.keepWaiting(elapsed: Date().timeIntervalSince(started),
                                       age: LaunchctlInspection.agentAge()) {
        usleep(250_000)
        status = collectCompleteStatus(runtimeOnly: runtimeOnly)
    }
    return status
}

private func waitForRootHelper(timeout: TimeInterval, runtimeOnly: Bool) -> CompleteStatus {
    let deadline = Date().addingTimeInterval(timeout)
    var status = collectCompleteStatus(runtimeOnly: runtimeOnly)
    while !status.rootHelperReachable, Date() < deadline {
        usleep(250_000)
        status = collectCompleteStatus(runtimeOnly: runtimeOnly)
    }
    return status
}

private func installedApplicationIsReady() -> Bool {
    ownedNodeExists(path: InstalledProduct.appPath, type: S_IFDIR)
        && ownedNodeExists(path: InstalledProduct.launcherPath, type: S_IFREG)
        && ownedNodeExists(path: InstalledProduct.agentPath, type: S_IFREG)
}

private func ownedNodeExists(path: String, type: mode_t) -> Bool {
    var info = stat()
    return path.withCString { lstat($0, &info) } == 0
        && (info.st_mode & S_IFMT) == type
        && info.st_uid == 0
}

private func ownedSocketExists(path: String, requiredMode: mode_t) -> Bool {
    var info = stat()
    return path.withCString { lstat($0, &info) } == 0
        && (info.st_mode & S_IFMT) == S_IFSOCK
        && info.st_uid == getuid()
        && (info.st_mode & 0o777) == requiredMode
}

private func rootHelperIsReachable() -> Bool {
    #if DEBUG
    let trustPolicy: RootHelperServerTrustPolicy = .allowUnverifiedForTesting
    #else
    let trustPolicy: RootHelperServerTrustPolicy = .requireProductRootHelper
    #endif
    do {
        try RootHelperClient(trustPolicy: trustPolicy).health()
        return true
    } catch {
        return false
    }
}
