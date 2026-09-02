import ConvenientSecurity
import Foundation
#if canImport(Darwin)
import Darwin
#endif

private enum InstalledProduct {
    static let appPath = "/Applications/ConvenientSecurity.app"
    static let launcherPath = appPath + "/Contents/MacOS/csec"
    static let agentPath = appPath + "/Contents/MacOS/csecd"
    static let agentLabel = "com.alexspeller.convenient-security"
    static let rootLabel = "com.alexspeller.convenient-security.rootd"
}

private struct CompleteStatus {
    let developmentEndpoint: Bool
    let installedApplicationReady: Bool
    let serviceManagementStatus: LaunchAgentStatus
    let launchAgentLoaded: Bool
    let agentReachable: Bool
    let schemes: [String]?
    let providerStatus: [ProviderStatusSummary]
    let sshSocketPresent: Bool
    let sshKeys: Int?
    let sshEnvironmentConfigured: Bool
    let remoteApproval: RemoteApprovalConfigurationState?
    let rootHelperReachable: Bool

    var healthy: Bool {
        (developmentEndpoint || installedApplicationReady)
            && (developmentEndpoint || launchAgentLoaded)
            && agentReachable
            && schemes?.isEmpty == false
            && sshSocketPresent
            && sshKeys != nil
            && rootHelperReachable
    }
}

private enum LaunchctlInspection {
    static func agentLoaded() -> Bool {
        run(["print", "gui/\(getuid())/\(InstalledProduct.agentLabel)"])
    }

    static func kickstartAgent() -> Bool {
        run(["kickstart", "-k", "gui/\(getuid())/\(InstalledProduct.agentLabel)"])
    }

    static func kickstartRootHelper() -> Bool {
        run(["kickstart", "-k", "system/\(InstalledProduct.rootLabel)"])
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

func runStatus() -> Never {
    let status = collectCompleteStatus()
    renderCompleteStatus(status)
    exit(status.healthy ? 0 : 1)
}

/// `csec doctor` is an explicit repair command. Its default mode may register or
/// restart csecd, but never edits shell profiles, secret stores, or provider
/// configuration. `--check` is the corresponding read-only diagnostic.
func runDoctor(_ arguments: [String]) -> Never {
    let checkOnly: Bool
    switch arguments {
    case []: checkOnly = false
    case ["--check"]: checkOnly = true
    default: usage("doctor")
    }

    Prompt.note("checking the complete installation")
    var status = collectCompleteStatus()
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
            + "run ./packaging/bin/build-and-install.sh")
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
                    renderCompleteStatus(collectCompleteStatus())
                    csecError("doctor", "approve ConvenientSecurity in System Settings > General > Login Items, then rerun csec doctor")
                    exit(1)
                }
            } catch {
                // A stale ServiceManagement status can disagree with launchd.
                // Reinspect before treating registration failure as terminal.
                guard LaunchctlInspection.agentLoaded() else {
                    renderCompleteStatus(collectCompleteStatus())
                    csecError("doctor", "could not register the per-user LaunchAgent: \(ReviewDisplay.sanitized(error.localizedDescription))")
                    exit(1)
                }
            }
        }
    }

    status = waitForLaunchAgent(timeout: 3)
    if status.launchAgentLoaded,
       (!status.agentReachable || status.sshKeys == nil || !status.sshSocketPresent) {
        if LaunchctlInspection.kickstartAgent() {
            repairs.append("restarted csecd")
        }
    }

    status = waitForAgentHealth(timeout: 10)
    if !status.rootHelperReachable, LaunchctlInspection.kickstartRootHelper() {
        repairs.append("requested root-helper startup")
        status = waitForRootHelper(timeout: 2)
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
            csecError("doctor", "the authenticated root helper is unavailable; rerun ./packaging/bin/build-and-install.sh")
        }
        exit(1)
    }
    Prompt.success("installation is healthy")
    exit(0)
}

private func collectCompleteStatus() -> CompleteStatus {
    let development = AgentSocket.isUsingDebugOverride
    let serviceStatus = development ? .notRegistered : LaunchAgentService.status()
    let launchAgentLoaded = development || LaunchctlInspection.agentLoaded()
    let appReady = development || installedApplicationIsReady()
    let client = makeAgentClient()

    let agentReachable = (try? client.capabilities()) != nil
    let providers = agentReachable ? try? client.schemesWithProviderStatus() : nil
    let schemes = providers?.schemes.sorted()
    let sshKeys = agentReachable ? try? client.listSSHKeys().count : nil
    let remoteApproval = agentReachable ? try? client.remoteApprovalStatus().state : nil
    let sshPath = SSHAgentSocket.defaultPath()

    return CompleteStatus(
        developmentEndpoint: development,
        installedApplicationReady: appReady,
        serviceManagementStatus: serviceStatus,
        launchAgentLoaded: launchAgentLoaded,
        agentReachable: agentReachable,
        schemes: schemes,
        providerStatus: providers?.providerStatus ?? [],
        sshSocketPresent: ownedSocketExists(path: sshPath, requiredMode: 0o600),
        sshKeys: sshKeys,
        sshEnvironmentConfigured:
            ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"] == sshPath,
        remoteApproval: remoteApproval,
        rootHelperReachable: rootHelperIsReachable()
    )
}

private func renderCompleteStatus(_ status: CompleteStatus) {
    print(StatusRenderer.render(
        title: "Convenient Security status",
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

    rows.append(StatusRow(
        label: "Agent control channel",
        value: status.agentReachable ? "reachable and authenticated" : "unavailable",
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

    rows.append(StatusRow(
        label: "Shell SSH_AUTH_SOCK",
        value: status.sshEnvironmentConfigured ? "configured for csec" : "not configured for csec",
        state: status.sshEnvironmentConfigured ? .ok : .warn))

    rows.append(StatusRow(
        label: "Remote approval",
        value: remoteApprovalDescription(status.remoteApproval),
        state: status.remoteApproval == .enabled ? .ok : .neutral))

    rows.append(StatusRow(
        label: "Root helper",
        value: status.rootHelperReachable ? "reachable and authenticated" : "unavailable",
        state: status.rootHelperReachable ? .ok : .bad))

    return rows
}

private func remoteApprovalDescription(
    _ state: RemoteApprovalConfigurationState?
) -> String {
    switch state {
    case .disabled: return "off"
    case .enabled: return "on"
    case .unavailable: return "unavailable in this build or configuration"
    case nil: return "unavailable"
    }
}

private func waitForLaunchAgent(timeout: TimeInterval) -> CompleteStatus {
    let deadline = Date().addingTimeInterval(timeout)
    var status = collectCompleteStatus()
    while !status.launchAgentLoaded, Date() < deadline {
        usleep(200_000)
        status = collectCompleteStatus()
    }
    return status
}

private func waitForAgentHealth(timeout: TimeInterval) -> CompleteStatus {
    let deadline = Date().addingTimeInterval(timeout)
    var status = collectCompleteStatus()
    while !(status.agentReachable && status.sshSocketPresent && status.sshKeys != nil),
          Date() < deadline {
        usleep(250_000)
        status = collectCompleteStatus()
    }
    return status
}

private func waitForRootHelper(timeout: TimeInterval) -> CompleteStatus {
    let deadline = Date().addingTimeInterval(timeout)
    var status = collectCompleteStatus()
    while !status.rootHelperReachable, Date() < deadline {
        usleep(250_000)
        status = collectCompleteStatus()
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
