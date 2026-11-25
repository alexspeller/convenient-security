import ConvenientSecurity
import Foundation
#if canImport(AppKit)
  import AppKit
  import LocalAuthentication
#endif

/// The line beside the armed Touch ID sensor says what one touch grants: the
/// scope and lifetime selected now, on the SSH and the secret-release layouts
/// alike, never just "this connection" or "the requested value" when later
/// commands in that scope will reuse the grant without asking.
func touchIDStatusLineTests() async {
    print("\n# Touch ID status line (states the selected grant)")
    touchIDStatusLineCopyTests()
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await MainActor.run {
        touchIDStatusLinePanelTests()
      }
    #endif
    print("\n# SSH review states its root in SSH words (csec-kua.18)")
    sshScopeVocabularyCopyTests()
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await MainActor.run {
        sshScopeVocabularyPanelTests()
      }
    #endif
}

private let statusCaller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
private let requesting = GrantScopeOption(kind: .requestingCommand, pid: 51, startTime: 9, processLabel: "ssh")
private let agent = GrantScopeOption(kind: .codingAgent, pid: 40, startTime: 4, processLabel: "Claude Code")
private let terminal = GrantScopeOption(kind: .terminalSession, pid: 20, startTime: 2, processLabel: "fish")
private let twelveHours = GrantDuration.bounded(seconds: 12 * 60 * 60)

private func statusSSHReview(scopes: GrantScopeChoices?) -> AccessPolicyReview {
    let ssh = SSHAccessReviewDetails(
        hostNames: ["github.com"], remoteUser: "git", keyLabel: "work", keyAlgorithm: "ssh-ed25519")
    return AccessPolicyReview(
        caller: statusCaller, reason: ssh.reason,
        plan: DeliveryPlan(
            mechanism: .credentialProtocol,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
            descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
        ),
        credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/id_ed25519")])],
        scopeChoices: scopes, durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil), ssh: ssh
    )
}

private func statusReleaseReview(scopes: GrantScopeChoices?, references: [String]) -> AccessPolicyReview {
    AccessPolicyReview(
        caller: statusCaller, reason: "run migrations",
        plan: DeliveryPlan(
            mechanism: .directHeap,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
            descendantScope: .subtree, destination: .localDevelopment,
            requestedTTLSeconds: nil, operationContext: "run migrations"
        ),
        commandLine: "bin/rails db:migrate",
        credentials: [PolicyReviewCredential(references: references.map { try! SecretRef($0) })],
        scopeChoices: scopes, durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil)
    )
}

private func touchIDStatusLineCopyTests() {
    let ssh = statusSSHReview(scopes: nil)
    check(ReviewDisplay.touchIDReadyText(for: ssh, scope: terminal, duration: twelveHours)
            == "Touch ID is ready. Touch the sensor to allow SSH from this fish terminal session for up to 12 hours.",
          "SSH: a terminal-session grant names the shell and the lifetime beside the sensor")
    check(ReviewDisplay.touchIDReadyText(for: ssh, scope: agent, duration: .processLifetime)
            == "Touch ID is ready. Touch the sensor to allow SSH from this Claude Code session for as long as it runs.",
          "SSH: a coding-agent grant for its lifetime says so")
    check(ReviewDisplay.touchIDReadyText(for: ssh, scope: requesting, duration: .bounded(seconds: 3_600))
            == "Touch ID is ready. Touch the sensor to allow this SSH command until it exits, for up to 1 hour.",
          "SSH: a grant to the requesting command alone says it ends with the command")
    check(ReviewDisplay.touchIDReadyText(for: ssh, scope: nil, duration: .processLifetime)
            == "Touch ID is ready. Touch the sensor to allow this SSH command until it exits.",
          "SSH: no scope choice falls back to the command itself")
    for (scope, duration) in [(requesting, twelveHours), (agent, .processLifetime), (terminal, twelveHours)] {
        let summary = ReviewDisplay.sshScopeSummary(scope, duration: duration)
        let status = ReviewDisplay.touchIDReadyText(for: ssh, scope: scope, duration: duration)
        check(status.lowercased().hasSuffix(summary.lowercased()),
              "SSH: the line beside the sensor and the scope summary state the same grant (\(scope.kind.rawValue))")
    }
    check(ReviewDisplay.sshScopeSummary(terminal, duration: twelveHours)
            == "Allow SSH from this fish terminal session for up to 12 hours."
          && ReviewDisplay.sshScopeSummary(requesting, duration: twelveHours)
            == "Allow this SSH command until it exits, for up to 12 hours."
          && ReviewDisplay.sshScopeSummary(agent, duration: .processLifetime)
            == "Allow SSH from this Claude Code session for as long as it runs.",
          "SSH: the scope summary keeps its wording")

    let one = statusReleaseReview(scopes: nil, references: ["csec://dev/API_TOKEN"])
    let two = statusReleaseReview(scopes: nil, references: ["csec://dev/API_TOKEN", "csec://dev/DATABASE_URL"])
    check(ReviewDisplay.touchIDReadyText(for: two, scope: agent, duration: twelveHours)
            == "Touch ID is ready. Touch the sensor to release the requested values to Claude Code and everything it runs for up to 12 hours.",
          "release: a coding-agent grant names the agent, everything it runs, and the lifetime")
    check(ReviewDisplay.touchIDReadyText(for: one, scope: terminal, duration: .processLifetime)
            == "Touch ID is ready. Touch the sensor to release the requested value to this fish terminal session for as long as it runs.",
          "release: a terminal-session grant for its lifetime says so")
    check(ReviewDisplay.touchIDReadyText(for: one, scope: requesting, duration: twelveHours)
            == "Touch ID is ready. Touch the sensor to release the requested value to this command until it exits, for up to 12 hours.",
          "release: a grant to the requesting command alone says it ends with the command")
    check(ReviewDisplay.touchIDReadyText(for: one, scope: nil, duration: .processLifetime)
            == "Touch ID is ready. Touch the sensor to release the requested value.",
          "release: no scope choice keeps the plain release line")

    let restore = RestoreReviewDetails(
        cause: .restart,
        rows: [RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "This terminal session · pid 20",
                                references: ["csec://dev/API_TOKEN"])],
        storeCount: 1
    )
    check(ReviewDisplay.touchIDReadyText(for: .restoreOnly(caller: statusCaller, restore: restore),
                                         scope: terminal, duration: twelveHours)
            == "Touch ID is ready. Touch the sensor to reopen these approvals.",
          "restore: the line says the touch reopens what was approved, whatever the selection")
    let automation = AccessPolicyReview(
        caller: statusCaller, reason: "enroll backup", plan: one.plan,
        credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/X")])],
        automation: v3AutomationDetails()
    )
    check(ReviewDisplay.touchIDReadyText(for: automation, scope: nil, duration: .processLifetime)
            == "Touch ID is ready. Touch the sensor to enable this job until you revoke it.",
          "automation: the line says the job runs until revoked")
    check(ReviewDisplay.touchIDReadyText(for: settingsChangeFixture(caller: statusCaller), scope: nil,
                                         duration: .processLifetime)
            == "Touch ID is ready. Touch the sensor to approve these changes.",
          "settings change: the line says the touch approves the listed changes")
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  /// The real panels put the default selection's line beside the sensor. The
  /// unpresented panel never arms Touch ID, so a change of selection there is
  /// refused; `cs-review-preview` with `CSEC_PREVIEW_SCOPE` /
  /// `CSEC_PREVIEW_DURATION` shows the line following a live selection.
  @MainActor
  private func touchIDStatusLinePanelTests() {
    NSApplication.shared.setActivationPolicy(.accessory)
    let biometrics = LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
    func texts(_ panel: ApprovalPanelInspection) -> [String] {
      panel.window.contentView?.layoutSubtreeIfNeeded()
      func all(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(all) }
      return all(panel.window.contentView ?? NSView()).compactMap { ($0 as? NSTextField)?.stringValue }
    }
    let scopes = GrantScopeChoices(
      options: [requesting, terminal], defaultOptionID: terminal.id
    )
    let sshPanel = ApprovalPanelInspection.access(statusSSHReview(scopes: scopes))
    let releasePanel = ApprovalPanelInspection.access(
      statusReleaseReview(scopes: scopes, references: ["csec://dev/API_TOKEN"]))
    let sshTexts = texts(sshPanel)
    let releaseTexts = texts(releasePanel)
    check(!sshTexts.contains { $0.contains("allow this SSH connection") }
            && !releaseTexts.contains { $0.hasSuffix("release the requested value.") },
          "panels: neither layout understates the grant beside the sensor")
    if biometrics {
      check(sshTexts.contains(
              "Touch ID is ready. Touch the sensor to allow SSH from this fish terminal session for as long as it runs."),
            "SSH panel: the line beside the sensor states the default scope and lifetime")
      check(releaseTexts.contains(
              "Touch ID is ready. Touch the sensor to release the requested value to this fish terminal session for as long as it runs."),
            "release panel: the line beside the sensor states the default scope and lifetime")
    } else {
      print("  (Touch ID unavailable here: the panels show the unavailable line, so only the copy checks ran)")
    }
    withExtendedLifetime([sshPanel, releasePanel]) {}
  }
#endif

/// The SSH review's radios and summary say "This SSH command"; every other
/// statement of its root — the collapsed "Grant root" row, the Touch ID
/// reason — must use those words, not the release panel's "Requesting
/// process only".
private func sshScopeVocabularyCopyTests() {
    check(ReviewDisplay.sshScopeRootSummary(requesting) == "This SSH command — ssh (pid 51)"
            && ReviewDisplay.sshScopeRootSummary(agent) == "This Claude Code session — Claude Code (pid 40)"
            && ReviewDisplay.sshScopeRootSummary(terminal) == "This fish terminal session — fish (pid 20)",
          "SSH root summary: the radio title plus the root process")
    let ssh = statusSSHReview(scopes: nil)
    let release = statusReleaseReview(scopes: nil, references: ["csec://dev/API_TOKEN"])
    for option in [requesting, agent, terminal] {
        check(ReviewDisplay.scopeSummary(option, for: ssh) == ReviewDisplay.sshScopeRootSummary(option)
                && ReviewDisplay.scopeSummary(option, for: release) == ReviewDisplay.scopeSummary(option),
              "root summary for a review: SSH words on the SSH review, release words otherwise (\(option.kind.rawValue))")
    }
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  /// The Touch ID reason states the default root. With one scope there are
  /// no radios, so the details grid states the root itself. On the SSH panel that row sits behind "Show details" but is
  /// built with the window, so the hidden field is read here.
  @MainActor
  private func sshScopeVocabularyPanelTests() {
    NSApplication.shared.setActivationPolicy(.accessory)
    func texts(_ panel: ApprovalPanelInspection) -> [String] {
      panel.window.contentView?.layoutSubtreeIfNeeded()
      func all(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(all) }
      return all(panel.window.contentView ?? NSView()).compactMap { ($0 as? NSTextField)?.stringValue }
    }
    let single = GrantScopeChoices(options: [requesting], defaultOptionID: requesting.id)
    let several = GrantScopeChoices(options: [requesting, terminal], defaultOptionID: terminal.id)
    let sshReason = ApprovalPanelInspection.accessAuthenticationReason(statusSSHReview(scopes: single))
    let sshDefaultReason = ApprovalPanelInspection.accessAuthenticationReason(statusSSHReview(scopes: several))
    let releaseReason = ApprovalPanelInspection.accessAuthenticationReason(
      statusReleaseReview(scopes: single, references: ["csec://dev/API_TOKEN"]))
    check(sshReason.contains("grant scope This SSH command — ssh (pid 51)")
            && !sshReason.contains("Requesting process only"),
          "SSH Touch ID reason: the grant scope is the SSH command, in SSH words")
    check(sshDefaultReason.contains("grant scope This fish terminal session — fish (pid 20)")
            && !sshDefaultReason.contains("This terminal session"),
          "SSH Touch ID reason: a terminal default names the shell as the SSH radios do")
    check(releaseReason.contains("grant scope Requesting process only — ssh (pid 51)"),
          "release Touch ID reason keeps the release panel's words")

    let sshPanel = ApprovalPanelInspection.access(statusSSHReview(scopes: single))
    let sshTexts = texts(sshPanel)
    check(sshTexts.contains("Grant root") && sshTexts.contains("This SSH command — ssh (pid 51)"),
          "SSH panel: the collapsed Grant root row names the SSH command in SSH words")
    check(!sshTexts.contains { $0.contains("Requesting process only") },
          "SSH panel: no text uses the release panel's scope words")
    withExtendedLifetime(sshPanel) {}
  }
#endif
