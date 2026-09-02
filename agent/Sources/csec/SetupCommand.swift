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

    let environment = ProcessInfo.processInfo.environment
    let homeDirectory = FileManager.default.homeDirectoryForCurrentUser.path

    // --- Assessment (quiet, behind a spinner) ---
    let agentClient = makeAgentClient()
    var agentReachable = false
    var providerSchemes: [String] = []
    let detections: [CodingAgentDetection]
    let discovery: LocalSecretDiscovery
    do {
        (detections, discovery) = try withSpinner("Assessing this Mac and project…") {
            let detections = try CodingAgentSetup.detect(
                homeDirectory: homeDirectory, pathEnvironment: environment["PATH"])
            let discovery = try LocalSecretDiscoveryEngine.discover(
                projectDirectory: projectDirectory, environment: environment)
            agentReachable = (try? agentClient.capabilities()) != nil
            providerSchemes = agentReachable ? ((try? agentClient.schemes()) ?? []) : []
            return (detections, discovery)
        }
    } catch {
        csecError("setup", ReviewDisplay.sanitized(error.localizedDescription))
        exit(1)
    }

    // --- Step 1: resident agent (csecd) ---
    var launchStatus = LaunchAgentService.status()
    stepResidentAgent(
        launchStatus: &launchStatus, agentClient: agentClient,
        agentReachable: &agentReachable, providerSchemes: &providerSchemes)

    // --- Step 2: Full Disk Access (report-only, no Touch ID; needs a reachable csecd) ---
    var auditReport: HostAuditReport?
    if agentReachable {
        auditReport = withSpinner("Reading host posture…") { try? agentClient.hostAudit() }
    }
    let fda = fdaState(from: auditReport)
    stepFullDiskAccess(state: fda)

    // --- Step 3: coding-agent hooks ---
    let configuredClients = stepCodingAgentHooks(detections: detections)

    // --- Step 4: bounded audit prompt + optional host audit ---
    let sipStatus = StartupSecurityReport.currentAgent().sipStatus
    let rootReachable = setupRootHelperReachable()
    let plans = detections.filter(\.detected).compactMap {
        try? CodingAgentSetup.plan(detection: $0, csecExecutablePath: currentExecutablePath())
    }
    stepAuditPromptAndAudit(
        projectDirectory: projectDirectory, launchStatus: launchStatus,
        agentReachable: agentReachable, providerSchemes: providerSchemes,
        rootReachable: rootReachable, sipStatus: sipStatus, plans: plans, discovery: discovery)

    // --- Recap ---
    setupRecap(
        launchStatus: launchStatus, agentReachable: agentReachable,
        fda: fda, configuredClients: configuredClients)
    exit(0)
}

// MARK: - Step 1: resident agent

private func stepResidentAgent(
    launchStatus: inout LaunchAgentStatus,
    agentClient: AgentClient,
    agentReachable: inout Bool,
    providerSchemes: inout [String]
) {
    Prompt.step("1. Resident agent (csecd)")
    if launchStatus == .enabled {
        Prompt.success(agentReachable ? "csecd is installed and running." : "csecd is installed.")
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
        let reachable = withSpinner("Waiting for csecd to come up…") {
            waitForAgentReachable(agentClient, timeout: 5)
        }
        agentReachable = reachable
        if reachable {
            providerSchemes = (try? agentClient.schemes()) ?? []
            Prompt.success("csecd is installed and running.")
        } else {
            Prompt.warn("csecd was registered but is not answering yet; give it a moment, then `csec status`.")
        }
    } catch {
        csecError("setup", "could not register csecd: \(ReviewDisplay.sanitized(error.localizedDescription))")
        Prompt.note("csec must run from inside the installed .app bundle for install to work; "
            + "run ./packaging/bin/build-and-install.sh, then re-run setup.")
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

private func stepCodingAgentHooks(detections: [CodingAgentDetection]) -> [String] {
    Prompt.step("3. Coding-agent hooks")
    let detected = detections.filter(\.detected)
    guard !detected.isEmpty else {
        Prompt.note("No supported coding agent (Claude Code or Codex) was detected; nothing to configure.")
        return []
    }

    var configured: [String] = []
    for detection in detected {
        let client = detection.client.rawValue
        let plan: CodingAgentConfigurationPlan
        do {
            plan = try CodingAgentSetup.plan(
                detection: detection, csecExecutablePath: currentExecutablePath())
        } catch {
            Prompt.warn("\(client): cannot plan a hook — \(ReviewDisplay.sanitized(error.localizedDescription))")
            continue
        }

        switch plan.action {
        case .unchanged:
            Prompt.success("\(client): the exact fail-closed csec hook is already configured.")
        case .create, .merge:
            showHookFragment(for: detection.client)
            if Prompt.confirm("Configure the \(client) hook (merges only the csec hook)?") {
                if applyHookPlan(plan, client: client) { configured.append(client) }
            } else {
                Prompt.note("\(client): left unchanged.")
            }
        case .blocked:
            // Offer replacement only when a replacement plan would cleanly merge —
            // an older, duplicate, or misplaced csec hook. A genuine policy block
            // (Claude's disableAllHooks) or an unsafe/invalid config only reports.
            if let replacement = try? CodingAgentSetup.plan(
                detection: detection, csecExecutablePath: currentExecutablePath(),
                replaceExistingCSECHook: true), replacement.action == .merge {
                Prompt.warn("\(client): \(ReviewDisplay.sanitized(plan.detail))")
                showHookFragment(for: detection.client)
                if Prompt.confirm("Replace the existing csec hook in \(client)?") {
                    if applyHookPlan(replacement, client: client) { configured.append(client) }
                } else {
                    Prompt.note("\(client): left unchanged.")
                }
            } else {
                Prompt.warn("\(client): \(ReviewDisplay.sanitized(plan.detail))")
            }
        }
    }
    return configured
}

/// Show the exact value-free hook fragment csec would merge. Bidi is neutralized;
/// newlines and other formatting are preserved so the JSON reads normally.
private func showHookFragment(for client: AICommandHookClient) {
    guard let data = try? AICommandHook.hookConfiguration(
        client: client, csecExecutablePath: currentExecutablePath()),
        let fragment = String(data: data, encoding: .utf8) else { return }
    Prompt.note("The exact value-free fragment csec will merge:")
    Prompt.note(ReviewDisplay.sanitized(fragment, allowNewlines: true, allowOtherControls: true))
}

private func applyHookPlan(_ plan: CodingAgentConfigurationPlan, client: String) -> Bool {
    do {
        try CodingAgentSetup.apply(plan)
        Prompt.success("\(client): hook configured — restart \(client) and trust the exact hook in "
            + "its hook UI before relying on coverage.")
        return true
    } catch {
        csecError("setup", "\(client): could not update the hook — \(ReviewDisplay.sanitized(error.localizedDescription))")
        return false
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
    launchStatus: LaunchAgentStatus, agentReachable: Bool, fda: FDAState, configuredClients: [String]
) {
    Prompt.step("Summary")
    if agentReachable {
        Prompt.success("csecd reachable")
    } else if launchStatus == .requiresApproval {
        Prompt.warn("csecd awaiting approval in Login Items")
    } else {
        Prompt.warn("csecd not running yet")
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

private func waitForAgentReachable(_ client: AgentClient, timeout: TimeInterval) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    repeat {
        if (try? client.capabilities()) != nil { return true }
        usleep(250_000)
    } while Date() < deadline
    return (try? client.capabilities()) != nil
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
