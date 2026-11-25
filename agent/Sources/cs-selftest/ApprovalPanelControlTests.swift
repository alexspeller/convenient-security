import ConvenientSecurity
import Foundation
#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  import AppKit
#endif

// Every button and pop-up an approval panel draws is held back by its typing
// guard, in every layout variant the panel builds (csec-kua.20). `bin/ci`
// counts constructions against registrations in each panel's source; this
// builds each surface's real window and checks the controls it actually
// contains, including those a disclosure adds once it is opened. The same
// windows show the scope radios in their own layout's words: the release
// panel's and the SSH panel's vocabularies never mix.

/// The settings layout as `ClaudeDelegationService` raises it when auto-mode
/// approvals are turned on: the changes the touch approves, nothing released.
func settingsChangeFixture(caller: CallerInfo) -> AccessPolicyReview {
    .settingsChange(
        caller: caller,
        change: SettingsChangeReviewDetails(
            title: "Turn On Claude Code Auto-Mode Approvals",
            changes: [
                "Let Claude Code auto mode approve csec secrets for its commands in projects you pair",
                "Acknowledge cc-caffeine@samber · PreToolUse *, which can approve Claude Code's shell commands",
                "Acknowledge ~/.claude/settings.json · 119 auto-mode classifier rules, which steer the auto-mode classifier",
            ]
        )
    )
}

/// The settings layout as host remediation raises it (csec-0.60): more fixes
/// than the panel lists, and its own footnote.
func hostFixesFixture(caller: CallerInfo) -> AccessPolicyReview {
    let review = HostRemediationReview(
        items: (1...8).map {
            HostRemediationItem(key: "HA-T0\($0)", title: "Synthetic reversible fix \($0)", detail: "", requiresRoot: false)
        },
        caller: caller
    )
    return .settingsChange(caller: review.caller, change: review.change)
}

func approvalPanelControlTests() async {
    print("\n# Approval panels: every control is held by the typing guard; scope radios use their layout's words")
    sshScopeWordingTests()
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await MainActor.run { approvalPanelControlRegistrationTests() }
    #endif
}

/// The SSH layout's radio titles and details, which the phone mirror copies
/// (RemoteApprovalV3Tests) but nothing else pins down.
private func sshScopeWordingTests() {
    let command = GrantScopeOption(kind: .requestingCommand, pid: 812, startTime: 9, processLabel: "ssh")
    let agent = GrantScopeOption(kind: .codingAgent, pid: 700, startTime: 8, processLabel: "Claude Code")
    let terminal = GrantScopeOption(kind: .terminalSession, pid: 20, startTime: 2, processLabel: "fish")
    check(ReviewDisplay.sshScopeTitle(command) == "This SSH command"
            && ReviewDisplay.sshScopeTitle(agent) == "This Claude Code session"
            && ReviewDisplay.sshScopeTitle(terminal) == "This fish terminal session",
          "SSH scope titles: the command, the agent's session and the terminal session, by name")
    check(ReviewDisplay.sshScopeDetail(command) == "ssh (pid 812) — only this command and its descendants"
            && ReviewDisplay.sshScopeDetail(agent)
                == "Claude Code (pid 700) — includes SSH from the commands this agent runs"
            && ReviewDisplay.sshScopeDetail(terminal)
                == "fish (pid 20) — includes commands and coding agents started in this terminal",
          "SSH scope details: each names its root process and pid and what the scope covers")
    check(ReviewDisplay.sshScopeRootSummary(terminal) == "This fish terminal session — fish (pid 20)",
          "SSH scope root summary: the radio's words, then the root process")
    for option in [command, agent, terminal] {
        check(ReviewDisplay.sshScopeTitle(option) != ReviewDisplay.scopeTitle(option),
              "SSH scope titles: \(option.kind.rawValue) differs from the release panel's wording")
    }
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  @MainActor
  private func approvalPanelControlRegistrationTests() {
    NSApplication.shared.setActivationPolicy(.accessory)
    let caller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
        descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: 3600, operationContext: "run migrations"
    )
    let requesting = GrantScopeOption(kind: .requestingCommand, pid: 51, startTime: 9, processLabel: "ruby")
    let agent = GrantScopeOption(kind: .codingAgent, pid: 30, startTime: 3, processLabel: "Claude Code")
    let terminal = GrantScopeOption(kind: .terminalSession, pid: 20, startTime: 2, processLabel: "fish")
    let wide = GrantScopeChoices(options: [requesting, agent, terminal], defaultOptionID: agent.id)
    let single = GrantScopeChoices(options: [requesting], defaultOptionID: requesting.id)
    let durations = GrantDurationChoices.offered(requestedTTLSeconds: 3600)
    let credentials = [PolicyReviewCredential(references: [try! SecretRef("csec://dev/API_TOKEN")])]
    // Long enough that the command preview offers "Show full command".
    let longCommand = ReviewDisplay.commandLine(
        ["bash", "-c", (1...12).map { "bin/rails task:step\($0) && echo done\($0)" }.joined(separator: "; ")])

    let release = AccessPolicyReview(
        caller: caller, reason: "run migrations", plan: plan, commandLine: longCommand,
        credentials: credentials, scopeChoices: wide, durationChoices: durations,
        delegationNote: .notApprovedForProject(reference: "csec://dev/API_TOKEN", project: "dev"),
        pairingOffer: DelegationPairingOffer(projectName: "dev", scopeOptionID: agent.id)
    )
    let singleRoot = AccessPolicyReview(
        caller: caller, reason: "run migrations", plan: plan, credentials: credentials,
        scopeChoices: single, durationChoices: durations
    )
    // Setup at this Mac's terminal: no scope and no lifetime to choose.
    let setup = AccessPolicyReview(
        caller: caller, reason: "built-in native-store editor",
        plan: DeliveryPlan(
            mechanism: .directHeap,
            executable: PlannedExecutable(canonicalPath: "/opt/csec/bin/csec", assurance: .verifiedProduct),
            descendantScope: .exactProcess, destination: .localDevelopment,
            requestedTTLSeconds: nil, operationContext: "built-in native-store editor"
        ),
        credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/*")])],
        macOnly: true
    )
    let ssh = SSHAccessReviewDetails(
        hostNames: ["github.com"], remoteUser: "git", keyLabel: "work", keyAlgorithm: "ssh-ed25519")
    let sshPlan = DeliveryPlan(
        mechanism: .credentialProtocol,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
        descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
    )
    let sshCommand = GrantScopeOption(kind: .requestingCommand, pid: 51, startTime: 9, processLabel: "ssh")
    let sshWide = GrantScopeChoices(options: [sshCommand, agent, terminal], defaultOptionID: terminal.id)
    let sshCredentials = [PolicyReviewCredential(references: [try! SecretRef("csec://dev/id_ed25519")])]
    let sshReview = AccessPolicyReview(
        caller: caller, reason: ssh.reason, plan: sshPlan, credentials: sshCredentials,
        scopeChoices: sshWide, durationChoices: durations, ssh: ssh,
        delegationNote: .notAutoMode("default")
    )
    let sshSingle = AccessPolicyReview(
        caller: caller, reason: ssh.reason, plan: sshPlan, credentials: sshCredentials,
        scopeChoices: GrantScopeChoices(options: [sshCommand], defaultOptionID: sshCommand.id),
        durationChoices: durations, ssh: ssh
    )
    let automation = v3AutomationDetails()
    let automationReview = AccessPolicyReview(
        caller: caller, reason: automation.job.reason, plan: plan, credentials: credentials,
        automation: automation)
    let restore = RestoreReviewDetails(
        cause: .restart,
        rows: [
            RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "This terminal session · pid 20",
                             references: ["csec://dev/API_TOKEN"]),
            RestoreReviewRow(kind: .sshGrant, title: "fish", detail: "This fish terminal session · pid 20",
                             references: ["csec://dev/id_ed25519"],
                             ssh: RestoreReviewRow.SSH(hostTitle: "github.com", remoteUser: "git", keyLabel: "work")),
        ],
        storeCount: 1
    )
    let releaseWithRestore = AccessPolicyReview(
        caller: caller, reason: "run migrations", plan: plan, credentials: credentials,
        scopeChoices: wide, durationChoices: durations, restore: restore
    )
    let sudoRequest = SudoAuthorizationReviewRequest(
        submittedCommand: "sudo /usr/bin/true", workingDirectory: "/Users/example/project",
        terminal: "/dev/ttys001")
    let sudoTerminal = TerminalSessionContext(
        application: "iTerm2", title: "deploy — ~/project", location: "window 1, tab 2", tty: "ttys001")

    let surfaces: [(name: String, radios: [String], build: () -> ApprovalPanelInspection)] = [
        ("secret-access panel", wide.options.map(ReviewDisplay.scopeTitle), { .access(release) }),
        ("secret-access panel, one root", [], { .access(singleRoot) }),
        ("secret-access panel with a deadline", wide.options.map(ReviewDisplay.scopeTitle), {
            .access(release, deadline: ReviewDeadline(remaining: .seconds(20)))
        }),
        ("setup panel", [], { .access(setup) }),
        ("SSH panel", sshWide.options.map(ReviewDisplay.sshScopeTitle), { .access(sshReview) }),
        ("SSH panel, one root", [], { .access(sshSingle) }),
        ("secret-access panel without Touch ID", wide.options.map(ReviewDisplay.scopeTitle), {
            .access(release, phone: ReviewPhoneStatus(), touchID: .unavailable)
        }),
        ("SSH panel without Touch ID", sshWide.options.map(ReviewDisplay.sshScopeTitle), {
            .access(sshReview, phone: ReviewPhoneStatus(), touchID: .unavailable)
        }),
        ("restore-only panel without Touch ID", [], {
            .access(.restoreOnly(caller: caller, restore: restore), touchID: .unavailable)
        }),
        ("automation panel", [], { .access(automationReview) }),
        ("settings panel", [], { .access(settingsChangeFixture(caller: caller)) }),
        ("settings panel without Touch ID", [], {
            .access(settingsChangeFixture(caller: caller), touchID: .unavailable)
        }),
        ("host fixes panel", [], { .access(hostFixesFixture(caller: caller)) }),
        ("restore-only panel", [], { .access(.restoreOnly(caller: caller, restore: restore)) }),
        ("release panel with a restore section", wide.options.map(ReviewDisplay.scopeTitle), {
            .access(releaseWithRestore)
        }),
        ("sudo panel", [], { .sudo(sudoRequest, terminal: sudoTerminal) }),
        ("sudo panel without Touch ID", [], {
            .sudo(sudoRequest, terminal: sudoTerminal, touchID: .unavailable)
        }),
    ]
    for surface in surfaces {
        let panel = surface.build()
        let window = park(panel.window)
        check(panel.unregisteredControls.isEmpty,
              "\(surface.name): every control is registered with the typing guard"
                + unregisteredSummary(panel))
        // Opening every disclosure builds what was collapsed; anything it adds
        // is held back as well.
        var opened = Set<ObjectIdentifier>()
        while let disclosure = collapsedDisclosures(in: window.contentView)
            .first(where: { !opened.contains(ObjectIdentifier($0)) }) {
            opened.insert(ObjectIdentifier(disclosure))
            disclosure.performClick(nil)
        }
        if !opened.isEmpty {
            check(panel.unregisteredControls.isEmpty,
                  "\(surface.name), details open: every control is registered with the typing guard"
                    + unregisteredSummary(panel))
        }
        check(panel.scopeRadioTitles == surface.radios,
              "\(surface.name): scope radios read \(surface.radios) (got \(panel.scopeRadioTitles))")
        window.orderOut(nil)
        withExtendedLifetime(panel) {}
    }
  }

  @MainActor
  private func unregisteredSummary(_ panel: ApprovalPanelInspection) -> String {
    let stray = panel.unregisteredControls
    guard !stray.isEmpty else { return "" }
    return " (unregistered: " + stray.map { control in
        "\(type(of: control)) “\((control as? NSButton)?.title ?? "")”"
    }.joined(separator: ", ") + ")"
  }

  /// The panels' disclosure buttons that are still collapsed: each says
  /// "Show …" until it is opened.
  @MainActor
  private func collapsedDisclosures(in view: NSView?) -> [NSButton] {
    guard let view else { return [] }
    let own = (view as? NSButton).flatMap { $0.title.hasPrefix("Show ") ? [$0] : nil } ?? []
    return own + view.subviews.flatMap { collapsedDisclosures(in: $0) }
  }

  /// Offscreen and transparent before it is ordered in, so no test window is
  /// ever in front of the developer.
  @MainActor
  private func park(_ window: NSPanel) -> NSPanel {
    window.alphaValue = 0
    window.setFrameOrigin(NSPoint(x: -20_000, y: -20_000))
    window.orderFront(nil)
    return window
  }
#endif
