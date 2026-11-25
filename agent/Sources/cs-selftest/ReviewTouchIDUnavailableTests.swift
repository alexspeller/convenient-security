import ConvenientSecurity
import CSECRemoteApproval
import Foundation
#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  import AppKit
  import LocalAuthentication
  import LocalAuthenticationEmbeddedUI
#endif

// Every approval panel on a Mac that cannot take a touch (csec-qzr6): no
// fingerprint enrolled, Touch ID locked out, or the lid closed. The status
// line says the paired phone can approve while the review is mirrored to it
// and the phone leg has not given up, and that nothing can otherwise; and a
// panel arms Touch ID if it comes back while the panel is up, and carries
// on without it if it goes away under an armed evaluation (csec-kp2f). The sudo
// panel's own rule (it closes once nobody can approve) is in
// SudoReviewWithoutTouchIDTests. `cs-review-preview` with
// CSEC_PREVIEW_TOUCH_ID_PROBE=1 and `csec-sudo-review --no-touch-id-probe`
// check the live panels on-device.

func reviewTouchIDUnavailableTests() async {
    print("\n# Approval panels with Touch ID unavailable: the phone can approve, and Touch ID re-arms when it returns")
    touchIDUnavailableCopyTests()
    touchIDUnavailablePollTests()
    touchIDLostRuleTests()
    touchIDOverrideTests()
    await mirroredPhoneStatusTests()
    #if canImport(LocalAuthentication)
      await touchIDAvailabilityWatchTests()
    #endif
    #if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
      await MainActor.run { touchIDUnavailablePanelTests() }
    #endif
}

private let phoneLine = "Touch ID is unavailable on this Mac. Approve on your iPhone."
private let nobodyLine = "Touch ID is unavailable on this Mac, so this request cannot be authorized."

private func touchIDUnavailableCopyTests() {
    for surface in [ReviewAuthenticationContext.Surface.secretAccess, .sshSigning] {
        check(ReviewTouchIDUnavailable.statusText(for: surface, phoneCanDecide: true) == phoneLine,
              "Touch ID unavailable (\(surface)): with the phone able to decide, the line says to approve on the iPhone")
        check(ReviewTouchIDUnavailable.statusText(for: surface, phoneCanDecide: false) == nobodyLine,
              "Touch ID unavailable (\(surface)): with no phone, the line says the request cannot be authorized")
    }
    check(ReviewTouchIDUnavailable.statusText(for: .sudo, phoneCanDecide: true)
            == "Touch ID is unavailable on this Mac. Approve on your iPhone, or use your password.",
          "Touch ID unavailable (sudo): the line offers the iPhone and the password")
    for surface in ReviewAuthenticationContext.Surface.allCases {
        check(!ReviewTouchIDUnavailable.statusText(for: surface, phoneCanDecide: false).contains("iPhone"),
              "Touch ID unavailable (\(surface)): with no phone, the line never offers the iPhone")
    }
}

private func touchIDUnavailablePollTests() {
    typealias Rule = ReviewTouchIDUnavailable
    check(Rule.onPoll(touchIDAvailable: false, screenLocked: false, requesterAlive: true) == .keepWaiting
            && Rule.onPoll(touchIDAvailable: false, screenLocked: true, requesterAlive: false) == .keepWaiting,
          "Touch ID re-arm: while Touch ID is unavailable the panel keeps waiting")
    check(Rule.onPoll(touchIDAvailable: true, screenLocked: true, requesterAlive: true) == .keepWaiting
            && Rule.onPoll(touchIDAvailable: true, screenLocked: true, requesterAlive: false) == .keepWaiting,
          "Touch ID re-arm: behind the lock screen nothing is armed or closed")
    check(Rule.onPoll(touchIDAvailable: true, screenLocked: false, requesterAlive: true) == .arm,
          "Touch ID re-arm: Touch ID back, screen unlocked and requester running: arm it")
    check(Rule.onPoll(touchIDAvailable: true, screenLocked: false, requesterAlive: false) == .requesterGone,
          "Touch ID re-arm: Touch ID back but the requester gone: close instead of arming")
}

private func touchIDLostRuleTests() {
    typealias Rule = ReviewTouchIDUnavailable
    let userCancel = LAError.Code.userCancel.rawValue
    check(Rule.afterFailure(errorCode: userCancel, touchIDAvailable: true) == .failed
            && Rule.afterFailure(errorCode: userCancel, touchIDAvailable: false) == .failed,
          "Touch ID lost under an armed panel: Apple's refusing button is the human deciding, whatever Touch ID says now")
    for code in [LAError.Code.systemCancel, .appCancel, .biometryNotAvailable, .biometryLockout,
                 .biometryDisconnected, .authenticationFailed, .notInteractive].map(\.rawValue) + [nil] {
        check(Rule.afterFailure(errorCode: code, touchIDAvailable: false) == .touchIDLost,
              "Touch ID lost under an armed panel (error \(code.map(String.init) ?? "none")): with Touch ID gone when asked again, the panel waits without it")
    }
    for code in [LAError.Code.appCancel, .biometryNotAvailable, .biometryLockout,
                 .biometryDisconnected, .authenticationFailed, .notInteractive].map(\.rawValue) + [nil] {
        check(Rule.afterFailure(errorCode: code, touchIDAvailable: true) == .failed,
              "Touch ID lost under an armed panel (error \(code.map(String.init) ?? "none")): with Touch ID still there, the failure stands")
    }
    // A system cancel (another app forward, another prompt taking the sensor)
    // is never the human's answer, so it must not fail the review.
    check(Rule.afterFailure(errorCode: LAError.Code.systemCancel.rawValue, touchIDAvailable: true) == .systemCancelled,
          "Touch ID system cancel under an armed panel: with Touch ID still there, the human decided nothing and the panel stays up")
}

private func touchIDOverrideTests() {
    let built = ContinuousClock.now
    check(ReviewTouchIDOverride.unavailable.holdsUnavailable(builtAt: built, now: built + .seconds(100))
            && ReviewTouchIDOverride.unavailable.endsArmedEvaluation(builtAt: built) == nil,
          "Touch ID override: unavailable holds for good and ends no evaluation")
    let returns = ReviewTouchIDOverride.returnsAfter(.seconds(3))
    check(returns.holdsUnavailable(builtAt: built, now: built + .seconds(2))
            && !returns.holdsUnavailable(builtAt: built, now: built + .seconds(3))
            && returns.endsArmedEvaluation(builtAt: built) == nil,
          "Touch ID override: returnsAfter holds Touch ID away until its interval, then asks this Mac, and ends no evaluation")
    let lost = ReviewTouchIDOverride.lostAfter(.seconds(3))
    check(!lost.holdsUnavailable(builtAt: built, now: built + .seconds(2))
            && lost.holdsUnavailable(builtAt: built, now: built + .seconds(3))
            && lost.holdsUnavailable(builtAt: built, now: built + .seconds(100)),
          "Touch ID override: lostAfter asks this Mac until its interval, then holds Touch ID away for good")
    check(lost.endsArmedEvaluation(builtAt: built, now: built + .seconds(1)) == .seconds(2)
            && lost.endsArmedEvaluation(builtAt: built, now: built + .seconds(5)) == .zero,
          "Touch ID override: lostAfter ends an armed evaluation when Touch ID goes, or at once once it has gone")
    check(!ReviewTouchIDUnavailable.isAvailableNow(for: .secretAccess, override: lost, builtAt: built - .seconds(10))
            && !ReviewTouchIDUnavailable.isAvailableNow(for: .sudo, override: .unavailable, builtAt: built)
            && ReviewTouchIDUnavailable.isAvailableNow(for: .sshSigning, override: lost, builtAt: built)
            == ReviewTouchIDUnavailable.isAvailable(ReviewAuthenticationContext.make(for: .sshSigning)),
          "Touch ID asked again: an override holding it away answers unavailable, otherwise this Mac answers")
    check(ReviewTouchIDOverride(previewValue: "1") == .unavailable
            && ReviewTouchIDOverride(previewValue: "5") == .returnsAfter(.seconds(5)),
          "Touch ID override: 1 is unavailable for good, a number of seconds is Touch ID returning then")
    check(ReviewTouchIDOverride(previewValue: "0") == nil && ReviewTouchIDOverride(previewValue: "yes") == nil
            && ReviewTouchIDOverride(previewValue: "") == nil,
          "Touch ID override: anything else is refused")
}

// MARK: - The mirror tells its local leg about the phone

private final class SeenStatus: @unchecked Sendable {
    private let lock = NSLock()
    private var status: ReviewPhoneStatus??
    private var canDecideAtStart: Bool?
    func record(_ value: ReviewPhoneStatus?) {
        lock.lock()
        status = .some(value)
        canDecideAtStart = value?.canDecide
        lock.unlock()
    }
    var recorded: Bool { lock.lock(); defer { lock.unlock() }; return status != nil }
    var value: ReviewPhoneStatus? { lock.lock(); defer { lock.unlock() }; return status ?? nil }
    var startedDecidable: Bool? { lock.lock(); defer { lock.unlock() }; return canDecideAtStart }
}

/// A local leg that records the phone status it was presented with and
/// answers `outcome` once `release` says so (or it is cancelled).
private struct RecordingLocalReview: PolicyReviewProvider {
    let seen: SeenStatus
    let outcome: AccessPolicyReviewOutcome
    let release: @Sendable () -> Bool

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        seen.record(ReviewPhoneStatus.current)
        while !release() {
            if Task.isCancelled { return .denied(.requesterGone) }
            try? await Task.sleep(nanoseconds: 2_000_000)
        }
        return outcome
    }

    func reviewHostRemediation(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        .denied
    }
}

private actor ScriptedPhone: RemoteAccessPolicyReviewProvider {
    let readiness: RemoteReviewReadiness
    let answerAfter: Duration?
    let answer: RemoteAccessReviewResult

    init(readiness: RemoteReviewReadiness, answerAfter: Duration?, answer: RemoteAccessReviewResult) {
        self.readiness = readiness
        self.answerAfter = answerAfter
        self.answer = answer
    }

    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        readiness
    }

    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        guard let answerAfter else {
            while !Task.isCancelled { try? await Task.sleep(nanoseconds: 2_000_000) }
            return .unavailable
        }
        try? await Task.sleep(for: answerAfter)
        return answer
    }
}

private final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var set = false
    func raise() { lock.lock(); set = true; lock.unlock() }
    var isRaised: Bool { lock.lock(); defer { lock.unlock() }; return set }
}

private func phoneStatusReview(automation: Bool = false) -> AccessPolicyReview {
    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
        descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: 900, operationContext: "run migrations"
    )
    let details = automation ? v3AutomationDetails() : nil
    return AccessPolicyReview(
        caller: CallerInfo(pid: 42, startTime: 7, description: "ruby"),
        reason: details?.job.reason ?? "run migrations", plan: plan,
        credentials: [PolicyReviewCredential(references: [try! SecretRef("op://Development/Database/password")])],
        automation: details
    )
}

private func eventuallyWithin(_ limit: Duration, _ condition: @Sendable () -> Bool) async -> Bool {
    let deadline = ContinuousClock.now + limit
    while ContinuousClock.now < deadline {
        if condition() { return true }
        try? await Task.sleep(nanoseconds: 2_000_000)
    }
    return condition()
}

private func mirroredPhoneStatusTests() async {
    // A mirrored review: the local panel sees a phone that may decide, and
    // learns when the phone leg gives up, while it keeps the request.
    do {
        let seen = SeenStatus()
        let release = Flag()
        let mirror = MirroredPolicyReview(
            local: RecordingLocalReview(
                seen: seen, outcome: .denied(.human(decidedAt: .now)), release: { release.isRaised }),
            remote: ScriptedPhone(
                readiness: .ready(unlock: .notNeeded), answerAfter: .milliseconds(100), answer: .unavailable),
            log: { _ in })
        let review = Task { await mirror.reviewAccess(phoneStatusReview()) }
        let presented = await eventuallyWithin(.seconds(3)) { seen.recorded }
        check(presented && seen.value != nil && seen.startedDecidable == true,
              "mirrored review: the local panel is told a phone leg may still decide")
        let gaveUp = await eventuallyWithin(.seconds(3)) { seen.value?.canDecide == false }
        check(gaveUp, "mirrored review: the local panel learns when the phone leg gives up")
        release.raise()
        if case .denied(.human) = await review.value {
            check(true, "mirrored review: with the phone given up the local panel still decides")
        } else {
            check(false, "mirrored review: with the phone given up the local panel still decides")
        }
    }
    // The phone approves: the status the local leg held never turned
    // unavailable, and the phone's approval wins.
    do {
        let seen = SeenStatus()
        let mirror = MirroredPolicyReview(
            local: RecordingLocalReview(
                seen: seen, outcome: .denied(.human(decidedAt: .now)), release: { false }),
            remote: ScriptedPhone(
                readiness: .ready(unlock: .notNeeded), answerAfter: .milliseconds(50),
                answer: .approved(selection: remoteApprovalNoSelection, unlock: nil)),
            log: { _ in })
        let outcome = await mirror.reviewAccess(phoneStatusReview())
        if case let .approved(approval) = outcome {
            check(approval.decidedOn == .phone && seen.value?.canDecide == true,
                  "mirrored review: a phone approval wins with the phone never marked unavailable")
        } else {
            check(false, "mirrored review: a phone approval wins with the phone never marked unavailable")
        }
    }
    // Not mirrored (no phone ready, or automation): the panel sees no phone.
    for (name, review, readiness) in [
        ("no phone ready", phoneStatusReview(), RemoteReviewReadiness.unavailable),
        ("automation", phoneStatusReview(automation: true), RemoteReviewReadiness.ready(unlock: .notNeeded)),
        ("settings change", settingsChangeFixture(caller: phoneStatusReview().caller),
         RemoteReviewReadiness.ready(unlock: .notNeeded)),
    ] {
        let seen = SeenStatus()
        let mirror = MirroredPolicyReview(
            local: RecordingLocalReview(seen: seen, outcome: .denied(.human(decidedAt: .now)), release: { true }),
            remote: ScriptedPhone(readiness: readiness, answerAfter: nil, answer: .unavailable),
            log: { _ in })
        _ = await mirror.reviewAccess(review)
        check(seen.recorded && seen.value == nil,
              "unmirrored review (\(name)): the local panel is told no phone can decide")
    }
    check(ReviewPhoneStatus.current == nil, "outside a mirrored review no phone status is bound")
}

// MARK: - The availability watch

#if canImport(LocalAuthentication)
  private func touchIDAvailabilityWatchTests() async {
      // A probe that turns true is reported by the next poll, and a stopped
      // watch reports nothing more.
      let outcome = await withCheckedContinuation { (done: CheckedContinuation<(Bool, Bool, Bool), Never>) in
          Task { @MainActor in
              var available = false
              var polls: [Bool] = []
              let watch = TouchIDAvailabilityWatch(probe: { available })
              watch.start { polls.append($0) }
              watch.start { _ in polls.append(false) }  // a second start does nothing
              let running = watch.isRunning
              try? await Task.sleep(for: .milliseconds(1_300))
              let sawUnavailable = polls.first == false
              available = true
              let deadline = ContinuousClock.now + .seconds(3)
              while polls.last != true, ContinuousClock.now < deadline {
                  try? await Task.sleep(for: .milliseconds(20))
              }
              let sawAvailable = polls.last == true
              watch.stop()
              let count = polls.count
              try? await Task.sleep(for: .milliseconds(1_300))
              done.resume(returning: (running && sawUnavailable && sawAvailable, polls.count == count, !watch.isRunning))
          }
      }
      check(outcome.0, "Touch ID watch: each poll reports the probe, so Touch ID coming back is seen within a poll")
      check(outcome.1 && outcome.2, "Touch ID watch: a stopped watch polls no more")

      let overrides = await MainActor.run { () -> (Bool, Bool, Bool, Bool) in
          let never = TouchIDAvailabilityWatch(surface: .secretAccess, override: .unavailable)
          let longAgo = ContinuousClock.now - .seconds(10)
          let returned = TouchIDAvailabilityWatch(
              surface: .sshSigning, override: .returnsAfter(.seconds(2)), builtAt: longAgo)
          let notYet = TouchIDAvailabilityWatch(surface: .sudo, override: .returnsAfter(.seconds(60)))
          let real = ReviewTouchIDUnavailable.isAvailable(ReviewAuthenticationContext.make(for: .sudo))
          let plain = TouchIDAvailabilityWatch(surface: .secretAccess)
          return (!never.probeNow(), returned.probeNow() == real, !notYet.probeNow(), plain.probeNow() == real)
      }
      check(overrides.0 && overrides.2,
            "Touch ID watch: an override holds Touch ID unavailable for good, or until its interval passes")
      check(overrides.1 && overrides.3,
            "Touch ID watch: with no override, or its interval passed, the watch asks this Mac")
  }
#endif

// MARK: - The real panels

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  @MainActor
  private func allViews(_ view: NSView) -> [NSView] {
      [view] + view.subviews.flatMap(allViews)
  }

  @MainActor
  private func touchIDUnavailablePanelTests() {
      NSApplication.shared.setActivationPolicy(.accessory)
      check(TrustedSudoAuthorizationReviewSession.touchIDUnavailableText
              == ReviewTouchIDUnavailable.statusText(for: .sudo, phoneCanDecide: true),
            "Touch ID unavailable (sudo): the panel draws the shared line")
      let caller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
      let plan = DeliveryPlan(
          mechanism: .directHeap,
          executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
          descendantScope: .subtree, destination: .localDevelopment,
          requestedTTLSeconds: 3600, operationContext: "run migrations"
      )
      let requesting = GrantScopeOption(kind: .requestingCommand, pid: 51, startTime: 9, processLabel: "ruby")
      let credentials = [PolicyReviewCredential(references: [try! SecretRef("csec://dev/API_TOKEN")])]
      let release = AccessPolicyReview(
          caller: caller, reason: "run migrations", plan: plan, credentials: credentials,
          scopeChoices: GrantScopeChoices(options: [requesting], defaultOptionID: requesting.id),
          durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: 3600)
      )
      let ssh = SSHAccessReviewDetails(
          hostNames: ["github.com"], remoteUser: "git", keyLabel: "work", keyAlgorithm: "ssh-ed25519")
      let sshCommand = GrantScopeOption(kind: .requestingCommand, pid: 51, startTime: 9, processLabel: "ssh")
      let sshReview = AccessPolicyReview(
          caller: caller, reason: ssh.reason,
          plan: DeliveryPlan(
              mechanism: .credentialProtocol,
              executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
              descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
          ),
          credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/id_ed25519")])],
          scopeChoices: GrantScopeChoices(options: [sshCommand], defaultOptionID: sshCommand.id),
          durationChoices: GrantDurationChoices.offered(requestedTTLSeconds: nil), ssh: ssh
      )
      let restore = RestoreReviewDetails(
          cause: .restart,
          rows: [
              RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "This terminal session · pid 20",
                               references: ["csec://dev/API_TOKEN"]),
          ],
          storeCount: 1
      )
      let layouts: [(name: String, review: AccessPolicyReview)] = [
          ("secret-access panel", release),
          ("SSH panel", sshReview),
          ("restore-only panel", .restoreOnly(caller: caller, restore: restore)),
          ("settings panel", settingsChangeFixture(caller: caller)),
      ]
      let gaveUp = ReviewPhoneStatus()
      gaveUp.markUnavailable()
      for layout in layouts {
          for (phone, line, phoneName) in [
              (ReviewPhoneStatus?.some(ReviewPhoneStatus()), phoneLine, "a phone that may decide"),
              (ReviewPhoneStatus?.some(gaveUp), nobodyLine, "a phone that gave up"),
              (ReviewPhoneStatus?.none, nobodyLine, "no phone"),
          ] {
              let panel = ApprovalPanelInspection.access(layout.review, phone: phone, touchID: .unavailable)
              panel.window.contentView?.layoutSubtreeIfNeeded()
              let views = allViews(panel.window.contentView ?? NSView())
              let lines = views.compactMap { ($0 as? NSTextField)?.stringValue }
              check(lines.contains(line) && !lines.contains(phoneLine == line ? nobodyLine : phoneLine),
                    "\(layout.name) without Touch ID, \(phoneName): the status line reads “\(line)”")
              check(views.contains { $0 is LAAuthenticationView }
                      && views.filter { $0 is LAAuthenticationView }.allSatisfy(\.isHidden),
                    "\(layout.name) without Touch ID, \(phoneName): the empty Touch ID view is hidden")
              withExtendedLifetime(panel) {}
          }
          if ReviewTouchIDUnavailable.isAvailable(ReviewAuthenticationContext.make(for: .secretAccess)) {
              let armed = ApprovalPanelInspection.access(layout.review, phone: ReviewPhoneStatus())
              let views = allViews(armed.window.contentView ?? NSView())
              let lines = views.compactMap { ($0 as? NSTextField)?.stringValue }
              check(views.contains { $0 is LAAuthenticationView && !$0.isHidden }
                      && !lines.contains(phoneLine) && !lines.contains(nobodyLine),
                    "\(layout.name) with Touch ID: the Touch ID view shows and no unavailable line does")
              withExtendedLifetime(armed) {}
          } else {
              print("  (Touch ID unavailable here: the \(layout.name) with Touch ID was not checked)")
          }
      }
  }
#endif
