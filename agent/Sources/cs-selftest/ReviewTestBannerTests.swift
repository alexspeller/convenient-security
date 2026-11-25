import ConvenientSecurity
import Foundation
#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  import AppKit
#endif

// A panel a developer check puts on screen says TEST before anything else
// (csec-xbi), on every surface and layout variant, and a panel built without
// the marker, as csecd and the PAM-spawned helper build every one, never does.
// `cs-review-preview` and the debug `csec-sudo-review` probes show the live
// panels carrying it.

func reviewTestBannerTests() async {
    print("\n# Test banner: a panel a developer check put up says TEST; a real one never does")
    check(ReviewTestBanner.headline == "TEST — NOT A REAL REQUEST",
          "test banner: the headline says plainly that this is no request")
    check(ReviewTestBanner.detail.contains("releases, signs or runs nothing"),
          "test banner: it says approving does nothing, for every surface")
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await MainActor.run { reviewTestBannerPanelTests() }
    #endif
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  @MainActor
  private func reviewTestBannerPanelTests() {
    NSApplication.shared.setActivationPolicy(.accessory)
    let wasShown = ReviewTestBanner.isShown
    defer { ReviewTestBanner.isShown = wasShown }

    let caller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
        descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: nil, operationContext: "run migrations"
    )
    let credentials = [PolicyReviewCredential(references: [try! SecretRef("csec://dev/API_TOKEN")])]
    let access = AccessPolicyReview(
        caller: caller, reason: "run migrations", plan: plan, commandLine: "bin/rails db:migrate",
        credentials: credentials)
    let ssh = SSHAccessReviewDetails(
        hostNames: ["nimbus.local"], remoteUser: "root", keyLabel: "id_rsa", keyAlgorithm: "ssh-rsa")
    let sshReview = AccessPolicyReview(
        caller: caller, reason: ssh.reason,
        plan: DeliveryPlan(
            mechanism: .credentialProtocol,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
            descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
        ),
        credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/id_rsa")])],
        ssh: ssh)
    let automation = v3AutomationDetails()
    let automationReview = AccessPolicyReview(
        caller: caller, reason: automation.job.reason, plan: plan, credentials: credentials,
        automation: automation)
    let restore = AccessPolicyReview.restoreOnly(
        caller: caller, restore: RestoreReviewDetails(cause: .restart, rows: [RestoreReviewRow(
            kind: .secretGrant, title: "fish", detail: "This terminal session · pid 20",
            references: ["csec://dev/API_TOKEN"])], storeCount: 1))
    let sudoRequest = SudoAuthorizationReviewRequest(
        submittedCommand: "sudo id", workingDirectory: "/Users/example", terminal: "/dev/ttys009")
    let terminal = TerminalSessionContext(
        application: "iTerm2", title: "agent", location: "window 1, tab 1", tty: "ttys009")

    func panels() -> [(String, ApprovalPanelInspection)] {
        [
            ("secret-access", .access(access)),
            ("secret-access with a deadline", .access(access, deadline: ReviewDeadline(remaining: .seconds(12)))),
            ("SSH", .access(sshReview)),
            ("automation", .access(automationReview)),
            ("restore", .access(restore)),
            ("settings", .access(settingsChangeFixture(caller: caller))),
            ("sudo", .sudo(sudoRequest, terminal: terminal, deadline: ReviewDeadline(remaining: .seconds(300)))),
            ("sudo without Touch ID", .sudo(
                sudoRequest, terminal: terminal, deadline: ReviewDeadline(remaining: .seconds(300)),
                touchID: .unavailable)),
        ]
    }
    func root(_ panel: ApprovalPanelInspection) -> NSStackView? {
        panel.window.contentView?.layoutSubtreeIfNeeded()
        return panel.window.contentView?.subviews.lazy.compactMap { $0 as? NSStackView }.first
    }
    func rows(_ panel: ApprovalPanelInspection) -> [NSView] { root(panel)?.arrangedSubviews ?? [] }
    func banners(in view: NSView) -> [NSView] {
        (view.identifier == ReviewTestBanner.identifier ? [view] : []) + view.subviews.flatMap(banners)
    }
    func clipped(_ field: NSTextField) -> Bool {
        guard let cell = field.cell else { return true }
        let needed = cell.cellSize(forBounds: NSRect(
            x: 0, y: 0, width: field.bounds.width, height: .greatestFiniteMagnitude))
        return needed.height > field.bounds.height + 0.5
            || field.attributedStringValue.size().width > field.bounds.width + 0.5
                && field.maximumNumberOfLines == 1
    }
    func texts(in view: NSView) -> [NSTextField] {
        ((view as? NSTextField).map { [$0] } ?? []) + view.subviews.flatMap(texts)
    }

    ReviewTestBanner.isShown = false
    let real = panels()
    for (name, panel) in real {
        check(panel.window.contentView.map(banners)?.isEmpty == true,
              "test banner: a \(name) panel built as csecd builds it carries no banner")
        check(panel.window.title == "Convenient Security",
              "test banner: a real \(name) panel keeps its plain title")
    }

    ReviewTestBanner.isShown = true
    let marked = panels()
    for ((name, panel), (_, plain)) in zip(marked, real) {
        let first = rows(panel).first
        check(first?.identifier == ReviewTestBanner.identifier,
              "test banner: on a test \(name) panel it is the first row, above the header")
        check(panel.window.contentView.map(banners)?.count == 1,
              "test banner: a test \(name) panel carries it exactly once")
        check(panel.window.title == "Convenient Security" + ReviewTestBanner.titleSuffix,
              "test banner: a test \(name) panel's title says TEST")
        if let first {
            let shown = texts(in: first)
            check(shown.map(\.stringValue) == [ReviewTestBanner.headline, ReviewTestBanner.detail],
                  "test banner: the \(name) banner shows its headline and detail")
            check(shown.allSatisfy { !$0.isHidden && !clipped($0) && $0.textColor == .white },
                  "test banner: the \(name) banner's text is white and whole")
            check((first as? NSBox)?.fillColor == .systemRed,
                  "test banner: the \(name) banner is solid red")
            let width = root(panel)?.frame.width ?? 0
            check(width > 0 && abs(first.frame.width - width) < 0.5,
                  "test banner: the \(name) banner spans the panel's full content width")
        }
        check(panel.window.frame.width == plain.window.frame.width
                && panel.window.frame.height > plain.window.frame.height,
              "test banner: the \(name) panel grows to fit it and keeps its width")
    }
    withExtendedLifetime((real, marked)) {}
  }
#endif
