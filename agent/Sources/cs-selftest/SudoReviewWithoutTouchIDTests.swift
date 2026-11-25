import ConvenientSecurity
import Foundation
#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  import AppKit
  import LocalAuthentication
  import LocalAuthenticationEmbeddedUI
#endif

// The sudo review on a Mac that cannot take a touch (csec-kua.3): no
// fingerprint enrolled, Touch ID locked out, or the lid closed. The panel
// cannot approve then, so it stays up only while the paired phone may still
// decide, and otherwise ends at once so sudo falls back to Apple's prompt.
// `csec-sudo-review --no-touch-id-probe` shows the live panel doing so.

func sudoReviewWithoutTouchIDTests() async {
    print("\n# Sudo review with Touch ID unavailable: the panel stays up only while the phone can decide")
    sudoWithoutTouchIDDecisionTests()
    sudoReviewPhoneStatusTests()
    await sudoWithoutTouchIDRaceTests()
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await sudoWithoutTouchIDPanelTests()
    #endif
}

private func sudoWithoutTouchIDDecisionTests() {
    check(SudoReviewWithoutTouchID.response(touchIDAvailable: true, phoneCanDecide: true) == .armTouchID
            && SudoReviewWithoutTouchID.response(touchIDAvailable: true, phoneCanDecide: false) == .armTouchID,
          "sudo without Touch ID: with Touch ID available the panel arms it, phone or no phone")
    check(SudoReviewWithoutTouchID.response(touchIDAvailable: false, phoneCanDecide: true) == .waitForPhone,
          "sudo without Touch ID: the panel stays up while the phone may still decide")
    check(SudoReviewWithoutTouchID.response(touchIDAvailable: false, phoneCanDecide: false) == .usePassword,
          "sudo without Touch ID: with no phone able to decide the review ends for the password prompt")
}

private final class Fired: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func increment() { lock.lock(); count += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
}

private func sudoReviewPhoneStatusTests() {
    check(ReviewPhoneStatus().canDecide && !ReviewPhoneStatus.none.canDecide,
          "phone status: a phone leg not yet answered may decide; no phone leg cannot")

    let status = ReviewPhoneStatus()
    let early = Fired()
    status.whenUnavailable { early.increment() }
    check(early.value == 0, "phone status: nothing fires while the phone may still decide")
    status.markUnavailable()
    status.markUnavailable()
    check(early.value == 1 && !status.canDecide,
          "phone status: an observer fires once when the phone turns out unavailable, however often it is marked")
    let late = Fired()
    status.whenUnavailable { late.increment() }
    check(late.value == 1, "phone status: an observer added after the phone is unavailable fires at once")
    let none = Fired()
    ReviewPhoneStatus.none.whenUnavailable { none.increment() }
    check(none.value == 1, "phone status: with no phone leg an observer fires at once")

    // An observer registered while another thread marks the status fires
    // exactly once either way: never lost, never twice.
    var exactlyOnce = true
    for _ in 0..<200 {
        let racing = ReviewPhoneStatus()
        let fired = Fired()
        let group = DispatchGroup()
        DispatchQueue.global().async(group: group) { racing.markUnavailable() }
        DispatchQueue.global().async(group: group) { racing.whenUnavailable { fired.increment() } }
        group.wait()
        if fired.value != 1 { exactlyOnce = false }
    }
    check(exactlyOnce, "phone status: an observer racing the mark fires exactly once")
}

/// The real panel's rule with no Touch ID, without AppKit: it never approves,
/// is up while the phone may decide, and answers Use Password the moment the
/// phone cannot (or at once, with nothing shown, if it already cannot).
private actor NoTouchIDSudoPanel {
    private(set) var shown = false
    private(set) var closedByCancellation = false
    private(set) var closedForPhone = false

    func present(_ phone: ReviewPhoneStatus) async -> SudoAuthorizationReviewOutcome {
        guard SudoReviewWithoutTouchID.response(touchIDAvailable: false, phoneCanDecide: phone.canDecide)
                == .waitForPhone else { return .usePassword }
        shown = true
        let cannotDecide = Fired()
        phone.whenUnavailable { cannotDecide.increment() }
        while true {
            if Task.isCancelled {
                closedByCancellation = true
                return .usePassword
            }
            if cannotDecide.value > 0 {
                closedForPhone = true
                return .usePassword
            }
            try? await Task.sleep(nanoseconds: 5_000_000)
        }
    }
}

private func sudoWithoutTouchIDRaceTests() async {
    // No phone: the race tells the panel at once and sudo falls back.
    do {
        let panel = NoTouchIDSudoPanel()
        let started = ContinuousClock.now
        let outcome = await withinDeadline {
            await SudoReviewRace.run(local: { await panel.present($0) }, phone: { .unavailable })
        }
        check(outcome == .usePassword(deniedOnPhone: false) && outcome?.exitStatus == 69
                && started.duration(to: .now) < .seconds(1),
              "sudo without Touch ID: with the phone unavailable the review ends at once for the password prompt (exit 69)")
    }
    // The phone answers unavailable later (relay trouble): the panel was up
    // for it until then, and closes as the race hears it.
    do {
        let panel = NoTouchIDSudoPanel()
        let task = Task {
            await withinDeadline {
                await SudoReviewRace.run(
                    local: { await panel.present($0) },
                    phone: {
                        try? await Task.sleep(nanoseconds: 200_000_000)
                        return .unavailable
                    })
            }
        }
        let upFirst = await sudoWithoutTouchIDEventually { await panel.shown }
        let outcome = await task.value
        let closedForPhone = await panel.closedForPhone
        check(upFirst && closedForPhone && outcome == .usePassword(deniedOnPhone: false),
              "sudo without Touch ID: the panel is up while the phone may decide and closes once it cannot")
    }
    // The phone approves: Touch ID being unavailable on the Mac never stands
    // in the way of the phone's approval.
    do {
        let panel = NoTouchIDSudoPanel()
        let outcome = await SudoReviewRace.run(
            local: { await panel.present($0) },
            phone: {
                try? await Task.sleep(nanoseconds: 50_000_000)
                return .approved
            })
        let closedByCancellation = await panel.closedByCancellation
        check(outcome == .approved(on: .phone) && outcome.exitStatus == 0 && closedByCancellation,
              "sudo without Touch ID: the phone still approves, and its approval closes the panel")
    }
    // The phone denies: sudo falls back, as a phone Deny always does.
    do {
        let panel = NoTouchIDSudoPanel()
        let outcome = await SudoReviewRace.run(
            local: { await panel.present($0) },
            phone: {
                try? await Task.sleep(nanoseconds: 50_000_000)
                return .denied
            })
        check(outcome == .usePassword(deniedOnPhone: true),
              "sudo without Touch ID: a phone Deny falls back to the password prompt")
    }
    // A local leg given the status by a race that has not heard from the
    // phone yet sees one that may still decide.
    do {
        let seen = Fired()
        let outcome = await SudoReviewRace.run(
            local: { status in
                if status.canDecide { seen.increment() }
                return .usePassword
            },
            phone: {
                while !Task.isCancelled { try? await Task.sleep(nanoseconds: 5_000_000) }
                return .unavailable
            })
        check(seen.value == 1 && outcome == .usePassword(deniedOnPhone: false),
              "sudo race: the panel starts with a phone that may still decide")
    }
}

/// Runs `race`, cancelling it after three seconds: nil when it had to be
/// cancelled, so a review left up for nobody fails its check instead of
/// hanging the suite.
private func withinDeadline(
    _ race: @escaping @Sendable () async -> SudoReviewOutcome
) async -> SudoReviewOutcome? {
    let expired = Fired()
    let task = Task { await race() }
    let deadline = Task {
        try? await Task.sleep(nanoseconds: 3_000_000_000)
        guard !Task.isCancelled else { return }
        expired.increment()
        task.cancel()
    }
    let outcome = await task.value
    deadline.cancel()
    return expired.value > 0 ? nil : outcome
}

private func sudoWithoutTouchIDEventually(_ condition: @Sendable () async -> Bool) async -> Bool {
    let deadline = ContinuousClock.now + .seconds(5)
    while ContinuousClock.now < deadline {
        if await condition() { return true }
        try? await Task.sleep(nanoseconds: 5_000_000)
    }
    return await condition()
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  private let noTouchIDReview = SudoAuthorizationReviewRequest(
      submittedCommand: "sudo /usr/bin/true", workingDirectory: "/Users/example/project", terminal: "/dev/ttys001")
  private let noTouchIDTerminal = TerminalSessionContext(
      application: "iTerm2", title: "deploy", location: "window 1, tab 2", tty: "ttys001")

  @MainActor
  private func allSudoPanelViews(_ view: NSView) -> [NSView] {
      [view] + view.subviews.flatMap(allSudoPanelViews)
  }

  /// The real panel. Its no-phone path returns before any window is shown,
  /// so it runs here; the panel held up for the phone is on screen, which
  /// `csec-sudo-review --no-touch-id-probe` checks on-device instead.
  private func sudoWithoutTouchIDPanelTests() async {
      await MainActor.run {
          NSApplication.shared.setActivationPolicy(.accessory)
          let panel = ApprovalPanelInspection.sudo(
              noTouchIDReview, terminal: noTouchIDTerminal, touchID: .unavailable)
          panel.window.contentView?.layoutSubtreeIfNeeded()
          let views = allSudoPanelViews(panel.window.contentView ?? NSView())
          check(views.contains {
                  ($0 as? NSTextField)?.stringValue == TrustedSudoAuthorizationReviewSession.touchIDUnavailableText
                },
                "sudo panel without Touch ID: the status line says to approve on the iPhone or use the password")
          check(views.contains { $0 is LAAuthenticationView }
                  && views.filter { $0 is LAAuthenticationView }.allSatisfy(\.isHidden),
                "sudo panel without Touch ID: the empty Touch ID view is hidden")
          if LAContext().canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) {
              let armed = ApprovalPanelInspection.sudo(noTouchIDReview, terminal: noTouchIDTerminal)
              let armedViews = allSudoPanelViews(armed.window.contentView ?? NSView())
              check(armedViews.contains { $0 is LAAuthenticationView && !$0.isHidden }
                      && !armedViews.contains {
                          ($0 as? NSTextField)?.stringValue
                              == TrustedSudoAuthorizationReviewSession.touchIDUnavailableText
                      },
                    "sudo panel with Touch ID: the Touch ID view shows and the unavailable line does not")
              withExtendedLifetime(armed) {}
          } else {
              print("  (Touch ID unavailable here: the panel with Touch ID was not checked)")
          }
          withExtendedLifetime(panel) {}
      }

      // No phone: the review ends with no window ever ordered onscreen. A
      // panel shown by mistake is closed by cancelling it, so a regression
      // fails here rather than hanging the suite.
      let review = Task { @MainActor in
          await TrustedSudoAuthorizationReviewSession.present(
              noTouchIDReview, terminal: noTouchIDTerminal, phone: .none, deadline: nil,
              touchID: .unavailable)
      }
      let started = ContinuousClock.now
      let shown = Fired()
      let watch = Task { @MainActor in
          while !Task.isCancelled {
              if NSApplication.shared.windows.contains(where: \.isVisible) { shown.increment() }
              try? await Task.sleep(nanoseconds: 2_000_000)
          }
      }
      let deadline = Task {
          try? await Task.sleep(nanoseconds: 3_000_000_000)
          review.cancel()
      }
      let outcome = await review.value
      deadline.cancel()
      watch.cancel()
      _ = await watch.value
      let took = started.duration(to: .now)
      let sawWindow = shown.value > 0
      check(outcome == .usePassword && took < .seconds(2) && !sawWindow,
            "sudo panel without Touch ID: with no phone the real panel ends at once and never shows a window")
  }
#endif
