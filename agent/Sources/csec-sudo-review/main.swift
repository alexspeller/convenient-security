import AppKit
import CSecuritySupport
import ConvenientSecurity
import CoreGraphics
import Darwin
import Foundation

private let maximumFrameBytes = 9 * 1024

/// The developer modes' (probes, previews, self-tests) failure. A live review
/// refuses through `reject` instead, whose line reaches the unified log.
private func fail(_ message: String, status: Int32 = 64) -> Never {
  FileHandle.standardError.write(Data("csec-sudo-review: \(message)\n".utf8))
  exit(status)
}

/// A live review's refusal: one value-free line in the trail
/// (`SudoReviewLog`), since under PAM stderr is /dev/null, then the exit.
private func reject(_ reason: SudoReviewLog.Rejection, status: Int32 = 64) -> Never {
  SudoReviewLog.record(.rejected(reason, exitStatus: status))
  exit(status)
}

/// Ends this helper unsuccessful whenever AppKit is asked to quit it. Exit
/// zero is the PAM module's only approval signal, and AppKit ends a process
/// that agrees to quit with exit(0). Logout asks, and so can any process of
/// this user with a quit Apple Event (`NSRunningApplication.terminate()`), at
/// any moment of the review: the delegation ask, the terminal lookup, the
/// wait for another review's turn, the panel itself. So neither answer ever
/// reaches AppKit's exit: the helper exits 69 first, sudo falls back to its
/// password prompt, and a logout goes on with the helper gone. Closing the
/// helper's csecd connection withdraws a review mirrored to the phone.
@MainActor
private final class UnsuccessfulTermination: NSObject, NSApplicationDelegate {
  static let shared = UnsuccessfulTermination()
  private static let status = SudoReviewOutcome.usePassword(deniedOnPhone: false).exitStatus

  func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
    exit(Self.status)
  }

  // `terminate(_:)` calls this before its exit(0), so a quit that skips the
  // question above still ends unsuccessful.
  func applicationWillTerminate(_ notification: Notification) {
    exit(Self.status)
  }
}

/// Every AppKit event loop in this helper runs here, with
/// `UnsuccessfulTermination` as the application's delegate for its whole
/// life. AppKit takes quit requests only once its loop is running. Called
/// from this file's top-level code, which runs on the main thread.
private func runApplication() {
  MainActor.assumeIsolated {
    let application = NSApplication.shared
    application.delegate = UnsuccessfulTermination.shared
    application.run()
  }
}

private func readBoundedStandardInput() -> Data? {
  var result = Data()
  var buffer = [UInt8](repeating: 0, count: 1024)
  while true {
    let count = buffer.withUnsafeMutableBytes { bytes in
      read(STDIN_FILENO, bytes.baseAddress, bytes.count)
    }
    if count < 0, errno == EINTR { continue }
    if count < 0 { return nil }
    if count == 0 { return result }
    guard result.count + count <= maximumFrameBytes else { return nil }
    result.append(contentsOf: buffer.prefix(count))
  }
}

private func syntheticFixture() -> SudoAuthorizationReviewRequest {
  SudoAuthorizationReviewRequest(
    submittedCommand:
      "sudo /usr/bin/true --api-key \"[csec:secret-like]\" safe",
    workingDirectory: "/Users/example/project",
    terminal: "/dev/ttys001"
  )
}

private func syntheticTerminal() -> TerminalSessionContext {
  TerminalSessionContext(
    application: "iTerm2", title: "deploy — ~/project",
    location: "window 1, tab 2", tty: "ttys001"
  )
}

/// Dev-only, value-free on-device check of the real sudo panel's typing guard.
/// Unlike `--preview` it presents the synthetic fixture for real — the window
/// is on screen and Touch ID is armed for well under a second — and prints the
/// panel's key/active/control state before and after the grace period through
/// the probe every approval surface shares.
private func runGraceProbe() -> Never {
  let application = NSApplication.shared
  application.setActivationPolicy(.accessory)
  Task { @MainActor in
    // The samples mean nothing once a touch has approved the panel.
    if await TrustedSudoAuthorizationReviewSession.present(
      previewFixture(), terminal: syntheticTerminal(), phone: ReviewPhoneStatus(),
      deadline: previewDeadline()) == .approved
    {
      print("probe: APPROVED — a touch reached this probe's panel; rerun without touching the sensor")
      exit(2)
    }
  }
  PromptInteractionGraceProbe.schedule()
  runApplication()
  exit(1)
}

/// Dev-only, value-free on-device check that the real sudo panel's typing
/// guard waits for the keyboard: keep typing as the panel appears, then stop
/// (`PromptInteractionGraceProbe.scheduleTypingCheck`). Touch ID is armed
/// until the panel goes live and the verdict is printed.
private func runTypingProbe() -> Never {
  let application = NSApplication.shared
  application.setActivationPolicy(.accessory)
  Task { @MainActor in
    // The verdict means nothing once a touch has approved the panel.
    if await TrustedSudoAuthorizationReviewSession.present(
      previewFixture(), terminal: syntheticTerminal(), phone: ReviewPhoneStatus(),
      deadline: previewDeadline()) == .approved
    {
      print("probe: APPROVED — a touch reached this probe's panel; rerun without touching the sensor")
      exit(2)
    }
  }
  PromptInteractionGraceProbe.scheduleTypingCheck()
  runApplication()
  exit(1)
}

/// Dev-only, value-free on-device check that the real sudo panel re-arms Touch
/// ID after another app takes the focus and the panel is key again, through
/// the probe every approval surface shares. Touch ID is armed for about five
/// seconds.
private func runFocusProbe() -> Never {
  let application = NSApplication.shared
  application.setActivationPolicy(.accessory)
  Task { @MainActor in
    // The samples mean nothing once a touch has approved the panel.
    if await TrustedSudoAuthorizationReviewSession.present(
      previewFixture(), terminal: syntheticTerminal(), phone: ReviewPhoneStatus(),
      deadline: previewDeadline()) == .approved
    {
      print("probe: APPROVED — a touch reached this probe's panel; rerun without touching the sensor")
      exit(2)
    }
  }
  PromptFocusRecoveryProbe.schedule()
  runApplication()
  exit(1)
}

/// Dev-only, value-free on-device check that the real sudo panel survives a
/// real screen lock: lock the Mac while it is up and unlock it, and the panel
/// must stay up and ask for Touch ID again, through the probe every approval
/// surface shares. Under PAM the same hold is capped by the module's review
/// timeout; this probe gives the human three minutes.
private func runUnlockProbe() -> Never {
  let application = NSApplication.shared
  application.setActivationPolicy(.accessory)
  Task { @MainActor in
    // The verdict means nothing once a touch has approved the panel, and a
    // panel that closes any other way is the failure the probe reports.
    if await TrustedSudoAuthorizationReviewSession.present(
      previewFixture(), terminal: syntheticTerminal(), phone: ReviewPhoneStatus(),
      deadline: previewDeadline()) == .approved
    {
      print("probe: APPROVED — a touch reached this probe's panel; rerun without touching the sensor")
      exit(2)
    }
  }
  PromptUnlockRecheckProbe.schedule(prefix: "sudo unlock probe")
  runApplication()
  exit(1)
}

/// Dev-only, value-free check that this helper's own process can read the login
/// session's lock state — the question that decides whether a sudo review
/// cancelled by a screen lock is held open for a Touch ID retry or falls through
/// to sudo's password prompt. Under PAM the helper is spawned by root sudo with
/// a two-variable environment, so the probe is worth running through that same
/// spawn shape rather than assumed. It reports booleans only, never the session
/// dictionary's contents, and neither builds a window nor starts Touch ID.
private func runScreenLockProbe() -> Never {
  let session = CGSessionCopyCurrentDictionary() as? [String: Any]
  let lockKeyPresent = session?.keys.contains("CGSSessionScreenIsLocked") ?? false
  print(
    "sudo review screen-lock probe: "
      + "session-dictionary=\(session == nil ? "absent" : "present") "
      + "lock-key=\(lockKeyPresent ? "present" : "absent") "
      + "isScreenLocked=\(ScreenLockState.isScreenLocked)")
  exit(0)
}

/// Dev-only, value-free on-device check of the sudo panel on a Mac that cannot
/// take a touch, with Touch ID treated as unavailable whatever this Mac says
/// (`SudoReviewWithoutTouchID`). First, with no phone, the review must end at
/// once with no window ever shown. Then, through the production race, with a
/// phone leg that answers unavailable after two seconds, the panel must be up
/// with the unavailable line until then and close as it answers, the review
/// falling back to the password prompt (exit 69). Last, with Touch ID coming
/// back two seconds after the panel is built (the lid opened) and the phone
/// giving up later, the panel must arm Touch ID once it is back and stay up
/// when the phone gives up; Touch ID is armed for about two seconds then, so
/// do not touch the sensor. Then Touch ID goes under an armed evaluation (the
/// lid closed with an external display): with the phone pending the panel
/// must stay up for it and close as it gives up, and with no phone the review
/// must end for the password. On a Mac that cannot take a touch at all the
/// Touch ID steps are INCONCLUSIVE.
private func runNoTouchIDProbe() -> Never {
  let application = NSApplication.shared
  application.setActivationPolicy(.accessory)
  @MainActor func visiblePanels() -> [NSWindow] { application.windows.filter(\.isVisible) }
  @MainActor func showsUnavailableLine(_ window: NSWindow) -> Bool {
    func all(_ view: NSView) -> [NSView] { [view] + view.subviews.flatMap(all) }
    return all(window.contentView ?? NSView()).contains {
      ($0 as? NSTextField)?.stringValue == TrustedSudoAuthorizationReviewSession.touchIDUnavailableText
    }
  }
  Task { @MainActor in
    var failures: [String] = []
    let started = ContinuousClock.now
    let alone = await TrustedSudoAuthorizationReviewSession.present(
      previewFixture(), terminal: syntheticTerminal(), phone: .none, deadline: previewDeadline(),
      touchID: .unavailable)
    let aloneTook = started.duration(to: .now)
    print("no-touch-id probe: no phone: outcome=\(alone) took=\(aloneTook) visible=\(visiblePanels().count)")
    if alone != .usePassword || aloneTook > .seconds(1) || !visiblePanels().isEmpty {
      failures.append("with no phone the review did not end at once without a window")
    }

    let phoneAnswers = Duration.seconds(2)
    let raced = ContinuousClock.now
    let race = Task { @MainActor in
      await SudoReviewRace.run(
        local: { status in
          await TrustedSudoAuthorizationReviewSession.present(
            previewFixture(), terminal: syntheticTerminal(), phone: status, deadline: previewDeadline(),
            touchID: .unavailable)
        },
        phone: {
          try? await Task.sleep(for: phoneAnswers)
          return .unavailable
        })
    }
    try? await Task.sleep(for: .seconds(1))
    let up = visiblePanels()
    print("no-touch-id probe: phone pending: visible=\(up.count) unavailableLine=\(up.contains(where: showsUnavailableLine))")
    if up.count != 1 || !up.contains(where: showsUnavailableLine) {
      failures.append("while the phone could decide the panel was not up with the unavailable line")
    }
    let outcome = await race.value
    let took = raced.duration(to: .now)
    print("no-touch-id probe: phone unavailable: outcome=\(outcome) exit=\(outcome.exitStatus) took=\(took) visible=\(visiblePanels().count)")
    if outcome != .usePassword(deniedOnPhone: false) || took > phoneAnswers + .milliseconds(500)
      || !visiblePanels().isEmpty
    {
      failures.append("the panel did not close as the phone answered unavailable")
    }

    let touchIDReturns = Duration.seconds(2)
    let phoneGivesUp = Duration.seconds(4)
    let rearm = Task { @MainActor in
      await SudoReviewRace.run(
        local: { status in
          await TrustedSudoAuthorizationReviewSession.present(
            previewFixture(), terminal: syntheticTerminal(), phone: status, deadline: previewDeadline(),
            touchID: .returnsAfter(touchIDReturns))
        },
        phone: {
          try? await Task.sleep(for: phoneGivesUp)
          return .unavailable
        })
    }
    try? await Task.sleep(for: .seconds(1))
    let waiting = TouchIDUnavailableProbe.sample()
    print("no-touch-id probe: Touch ID still away: \(waiting)")
    if waiting.panels != 1 || waiting.unavailableLine != "sudo" || waiting.touchIDShown {
      failures.append("before Touch ID came back the panel was not up for the phone")
    }
    // Touch ID is back two seconds after the panel was built; the next poll,
    // within a second, arms it.
    try? await Task.sleep(for: .milliseconds(2_500))
    let returned = TouchIDUnavailableProbe.sample()
    print("no-touch-id probe: Touch ID back: \(returned)")
    let canTakeATouch = TouchIDUnavailableProbe.thisMacCanTakeATouch
    if canTakeATouch, returned.panels != 1 || returned.unavailableLine != "none" || !returned.touchIDShown {
      failures.append("once Touch ID was back the panel did not arm it")
    }
    try? await Task.sleep(for: .seconds(1))
    let afterPhone = TouchIDUnavailableProbe.sample()
    print("no-touch-id probe: phone gave up after Touch ID returned: \(afterPhone)")
    if canTakeATouch, afterPhone.panels != 1 || !afterPhone.touchIDShown {
      failures.append("a panel with Touch ID back closed when the phone gave up")
    }
    rearm.cancel()
    let rearmOutcome = await rearm.value
    if rearmOutcome != .usePassword(deniedOnPhone: false) || !visiblePanels().isEmpty {
      failures.append("the re-armed panel did not close unsuccessful when its sudo went away")
    }

    // Touch ID goes under the armed evaluation (the lid closed with an
    // external display). With the phone pending the panel stays up for it
    // and closes when the phone gives up; with no phone, sudo goes on to the
    // password at once.
    if canTakeATouch {
      let touchIDGoes = Duration.seconds(2)
      let lostPhoneGivesUp = Duration.seconds(4)
      let lostRaced = ContinuousClock.now
      let lost = Task { @MainActor in
        await SudoReviewRace.run(
          local: { status in
            await TrustedSudoAuthorizationReviewSession.present(
              previewFixture(), terminal: syntheticTerminal(), phone: status, deadline: previewDeadline(),
              touchID: .lostAfter(touchIDGoes))
          },
          phone: {
            try? await Task.sleep(for: lostPhoneGivesUp)
            return .unavailable
          })
      }
      try? await Task.sleep(for: .seconds(1))
      let armed = TouchIDUnavailableProbe.sample()
      print("no-touch-id probe: armed before Touch ID goes: \(armed)")
      if armed.panels != 1 || !armed.touchIDShown {
        failures.append("before Touch ID went the panel was not up and armed")
      }
      try? await Task.sleep(for: .milliseconds(1_700))
      let gone = TouchIDUnavailableProbe.sample()
      print("no-touch-id probe: Touch ID gone, phone pending: \(gone)")
      if gone.panels != 1 || gone.unavailableLine != "sudo" || gone.touchIDShown {
        failures.append("once Touch ID went with the phone pending the panel did not stay up for the phone")
      }
      let lostOutcome = await lost.value
      let lostTook = lostRaced.duration(to: .now)
      print("no-touch-id probe: Touch ID gone, then phone unavailable: outcome=\(lostOutcome) took=\(lostTook) visible=\(visiblePanels().count)")
      if lostOutcome != .usePassword(deniedOnPhone: false) || lostTook > lostPhoneGivesUp + .milliseconds(500)
        || !visiblePanels().isEmpty
      {
        failures.append("the panel Touch ID left did not close as the phone answered unavailable")
      }

      let alone = Task { @MainActor in
        await TrustedSudoAuthorizationReviewSession.present(
          previewFixture(), terminal: syntheticTerminal(), phone: .none, deadline: previewDeadline(),
          touchID: .lostAfter(.seconds(1)))
      }
      try? await Task.sleep(for: .milliseconds(500))
      let aloneArmed = TouchIDUnavailableProbe.sample()
      let aloneOutcome = await alone.value
      print("no-touch-id probe: Touch ID gone, no phone: armed=\(aloneArmed.touchIDShown) outcome=\(aloneOutcome) visible=\(visiblePanels().count)")
      if !aloneArmed.touchIDShown || aloneOutcome != .usePassword || !visiblePanels().isEmpty {
        failures.append("once Touch ID went with no phone the review did not end for the password")
      }
    }
    if !failures.isEmpty {
      print("no-touch-id probe: FAIL — " + failures.joined(separator: "; "))
      exit(1)
    }
    print(canTakeATouch
      ? "no-touch-id probe: PASS"
      : "no-touch-id probe: INCONCLUSIVE — this Mac cannot take a touch, so the re-arm was not seen")
    exit(canTakeATouch ? 0 : 3)
  }
  runApplication()
  exit(1)
}

/// The deadline line on whichever panel is on screen, for `--deadline-probe`.
@MainActor private func visibleDeadlineLine() -> String? {
  func find(_ view: NSView) -> NSTextField? {
    if let field = view as? NSTextField, field.identifier == ReviewDeadlineCountdown.lineIdentifier {
      return field
    }
    return view.subviews.lazy.compactMap(find).first
  }
  return NSApplication.shared.windows.filter(\.isVisible).lazy
    .compactMap { $0.contentView.flatMap(find) }.first?.stringValue
}

/// Dev-only, value-free on-device check of the deadline's real close: the
/// production race and parent watch with a `SudoReviewDeadline` of 35 s, so
/// the panel closes 32 s after it appears, through the same latch, the same
/// cancellation and the same expired status the PAM module reads. It samples
/// the deadline line quiet at first and counting down after, and checks the
/// panel closed unanswered at the deadline with nothing left on screen. The
/// phone leg is unavailable at once. Do not touch the sensor or click.
private func runDeadlineProbe() -> Never {
  NSApplication.shared.setActivationPolicy(.accessory)
  let timeLimit = Duration.seconds(35)
  let deadline = SudoReviewDeadline(timeLimit: timeLimit)
  let review = SudoAuthorizationReviewRequest(
    submittedCommand: syntheticFixture().submittedCommand,
    workingDirectory: syntheticFixture().workingDirectory,
    terminal: syntheticFixture().terminal,
    timeLimit: timeLimit)
  runWatchingParent(originalParent: getppid(), deadline: deadline) {
    let started = ContinuousClock.now
    let samples = Task { @MainActor in
      var failures: [String] = []
      try? await Task.sleep(for: .seconds(1))
      let quiet = visibleDeadlineLine()
      print("deadline probe: t=1s line=\(quiet ?? "absent")")
      if quiet?.hasPrefix("If nobody answers by") != true { failures.append("no quiet line at first") }
      try? await Task.sleep(for: .seconds(10))
      let counting = visibleDeadlineLine()
      print("deadline probe: t=11s line=\(counting ?? "absent")")
      if counting?.hasPrefix("Closes in 21 seconds") != true { failures.append("no countdown at 21 s left") }
      return failures
    }
    let outcome = await SudoReviewRace.run(
      local: { status in
        await TrustedSudoAuthorizationReviewSession.present(
          review, terminal: syntheticTerminal(), phone: status, deadline: deadline.closing)
      },
      phone: { .unavailable })
    let took = started.duration(to: .now)
    var failures = await samples.value
    let decided = deadline.decide()
    let visible = NSApplication.shared.windows.filter(\.isVisible).count
    print(
      "deadline probe: closed after \(took) outcome=\(outcome) "
        + "exit=\(decided ? outcome.exitStatus : SudoReviewDeadline.expiredExitStatus) visible=\(visible)")
    if decided { failures.append("the review was decided, not closed by the deadline: rerun without touching it") }
    if took < .seconds(31) || took > .seconds(33) { failures.append("it did not close at the deadline") }
    if visible != 0 { failures.append("a window is still on screen") }
    print(failures.isEmpty ? "deadline probe: PASS" : "deadline probe: FAIL — " + failures.joined(separator: "; "))
    return failures.isEmpty ? 0 : 1
  }
}

/// Run the review body with the parent watch armed, then exit with the status
/// the body returns. The watch cancels the body's task when the sudo that
/// spawned this helper exits; the body turns that into an unsuccessful status.
/// A `deadline` cancels it the same way when it passes undecided
/// (`SudoReviewDeadline`), and the body turns that into the expired status.
private func runWatchingParent(
  originalParent: pid_t,
  deadline: SudoReviewDeadline? = nil,
  _ body: @escaping @Sendable @MainActor () async -> Int32
) -> Never {
  let review = Task { @MainActor in
    let status = await body()
    SudoReviewLog.record(.exiting(status: status))
    exit(status)
  }
  deadline?.watch {
    SudoReviewLog.record(.deadlinePassed)
    review.cancel()
  }
  guard
    SudoReviewParentWatch.start(
      originalParent: originalParent,
      onExit: {
        SudoReviewLog.record(.parentExited)
        SudoReviewParentExit.helper.mark()
        review.cancel()
      })
  else {
    review.cancel()
    reject(.parentGone, status: 69)
  }
  runApplication()
  exit(70)
}

/// Dev-only, windowless check of the parent watch on the real helper: it arms
/// the same watch the review path arms, on its real parent, prints one line,
/// and exits unsuccessful only when that parent exits. `cs-selftest` runs it
/// under a throwaway shell and kills the shell.
private func runParentWatchProbe() -> Never {
  let originalParent = getppid()
  NSApplication.shared.setActivationPolicy(.prohibited)
  runWatchingParent(originalParent: originalParent) {
    print("sudo review parent-watch probe: armed parent=\(originalParent)")
    fflush(stdout)
    // Stands in for the open panel: it waits until the watch cancels it.
    while !Task.isCancelled {
      try? await Task.sleep(nanoseconds: 60_000_000_000)
    }
    print("sudo review parent-watch probe: parent exited; review closed unsuccessful")
    fflush(stdout)
    return 69
  }
}

/// Windowless integration check using the production race and parent watch.
/// The caller owns a private directory and holds stdin open while owning the
/// turn; EOF releases it normally. No credentials or installed state are used.
private func runPresentationLockProbe(directory: String) -> Never {
  let originalParent = getppid()
  NSApplication.shared.setActivationPolicy(.prohibited)
  _ = fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK)
  runWatchingParent(originalParent: originalParent) {
    print("sudo presentation probe: waiting")
    fflush(stdout)
    let outcome = await SudoReviewRace.run(
      presentationLock: ReviewPresentationLock(directory: directory),
      local: {
        print("sudo presentation probe: acquired")
        fflush(stdout)
        while !Task.isCancelled {
          var byte: UInt8 = 0
          if read(STDIN_FILENO, &byte, 1) >= 0 { break }
          if errno != EWOULDBLOCK && errno != EINTR { break }
          try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return .usePassword
      },
      phone: { .unavailable }
    )
    return outcome.exitStatus
  }
}

/// Dev-only, value-free on-device check of the phone leg on its own: it sends
/// the synthetic fixture to the installed csecd exactly as a review would, with
/// no panel, and prints csecd's answer. `unavailable` covers every reason the
/// phone cannot decide (no csecd, a csecd that does not accept this binary's
/// code identity, no paired phone ready). A phone approval of the fixture
/// authorizes nothing: no sudo is waiting on this process.
private func runPhoneProbe() -> Never {
  let request = SudoRemoteReviewRequest(
    syntheticFixture(), terminal: syntheticTerminal(), closing: previewDeadline())
  Task {
    let decision = await SudoRemoteReviewClient.installed.review(request)
    print("sudo review phone probe: \(decision.rawValue)")
    exit(0)
  }
  dispatchMain()
}

private func runSelfTest() -> Never {
  let fixture = syntheticFixture()
  guard let frame = SudoAuthorizationReviewWire.encode(fixture),
    SudoAuthorizationReviewWire.decode(frame) == fixture,
    SudoAuthorizationReviewWire.decode(frame.dropLast()) == nil,
    SudoAuthorizationReviewWire.decode(Data(repeating: 0, count: 28)) == nil
  else { fail("wire self-test failed", status: 1) }
  print("sudo review wire self-test: pass")
  exit(0)
}

private func validateSyntheticFrame() -> Never {
  guard cs_fd_is_pipe_or_socket(STDIN_FILENO) == 1,
    let frame = readBoundedStandardInput(),
    SudoAuthorizationReviewWire.decode(frame) == syntheticFixture()
  else { fail("synthetic frame validation failed", status: 1) }
  print("sudo review C/Swift frame check: pass")
  exit(0)
}

/// Build-time check (build-sudo-review.sh): the PAM module's frame for sudo's
/// argument list decodes, through `SudoCommandDisplay`, back to exactly the
/// arguments given here, so csecd's delegation match reads what root rendered.
private func checkDisplayRoundTrip(_ expected: [String]) -> Never {
  guard cs_fd_is_pipe_or_socket(STDIN_FILENO) == 1,
    let frame = readBoundedStandardInput(),
    let review = SudoAuthorizationReviewWire.decode(frame),
    SudoCommandDisplay.arguments(review.submittedCommand)
      == expected.map({ ShellArgumentElement.known(Array($0.utf8)) })
  else { fail("display round trip failed", status: 1) }
  print("sudo review display round trip: pass")
  exit(0)
}

private let previewFixtureNames = ["basic", "long-argv", "multi-line"]

/// The command `--preview <name>` reviews. There is no redactor-unavailable
/// fixture: when the PAM module cannot render the command it never spawns this
/// helper, and Apple's authorization prompt carries that text instead
/// (`csec_build_redactor_unavailable_prompt`, checked by `build-sudo-pam.sh`).
private func previewCommand(_ name: String) -> String? {
  switch name {
  case "basic":
    return syntheticFixture().submittedCommand
  case "long-argv":
    // As many arguments as the module renders, so the command overflows the
    // card into its scroller.
    let files = (1...(SudoCommandDisplay.maximumArguments - 2)).map {
      String(format: "/Library/LaunchDaemons/com.example.fleet-agent.worker-%02d.plist", $0)
    }
    return (["sudo", "/usr/sbin/chown", "root:wheel"] + files).joined(separator: " ")
  case "multi-line":
    // The module writes every byte outside printable ASCII as `\xHH`, so a
    // script's newlines reach the panel as `\x0A` in one wrapped line.
    return #"sudo /bin/sh -c "set -e\x0Alaunchctl bootout system/com.example.agent || true\x0A"#
      + #"install -m 0644 -o root -g wheel build/com.example.agent.plist /Library/LaunchDaemons/\x0A"#
      + #"launchctl bootstrap system /Library/LaunchDaemons/com.example.agent.plist""#
  default:
    return nil
  }
}

/// A preview fixture as a Claude Code sudo that delegation declined:
/// `CSEC_PREVIEW_DELEGATION=<code>` adds that decline's note, and
/// `CSEC_PREVIEW_PAIRING=1` the pairing line, as the access and SSH previews
/// take them (`cs-review-preview`), conditioned on the note's decline as
/// csecd writes it (`launch_option`: "… once Claude Code is started without
/// --settings"). The probes show `basic`.
private func previewFixture(named name: String = "basic") -> SudoAuthorizationReviewRequest {
  guard let command = previewCommand(name) else {
    fail("unknown preview fixture \(name); one of \(previewFixtureNames.joined(separator: ", "))")
  }
  let fixture = SudoAuthorizationReviewRequest(
    submittedCommand: command, workingDirectory: syntheticFixture().workingDirectory,
    terminal: syntheticFixture().terminal)
  // A fixture the module could not send would picture a panel no sudo raises.
  guard SudoCommandDisplay.arguments(command) != nil,
    let frame = SudoAuthorizationReviewWire.encode(fixture),
    SudoAuthorizationReviewWire.decode(frame) == fixture
  else { fail("preview fixture \(name) is not a review the PAM module could send", status: 1) }
  let environment = ProcessInfo.processInfo.environment
  let samples: [String: DelegationDecline] = Dictionary(
    uniqueKeysWithValues: [
      DelegationDecline.sudoNotApproved(project: "garden-lights"), .sudoIndirect("node"), .sudoOption("-E"),
      .commandMismatch(process: "sudo"), .notAutoMode("default"), .notRegistered,
      .classifierRules("~/.claude/settings.json · 119 auto-mode classifier rules"),
      .uncheckedBuild("new release"), .launchOption("--settings"), .gatewaySignIn,
    ].map { ($0.code, $0) })
  var decline: DelegationDecline?
  if let code = environment["CSEC_PREVIEW_DELEGATION"] {
    guard let sample = samples[code] else {
      fail("unknown delegation code \(code); one of \(samples.keys.sorted().joined(separator: ", "))")
    }
    decline = sample
  }
  let line = environment["CSEC_PREVIEW_PAIRING"] == "1"
    ? SudoPairingOffer(projectName: "garden-lights", condition: decline?.pairingCondition).line : nil
  return fixture.withDelegation(note: decline?.panelText, pairingLine: line)
}

/// The deadline line the previews and probes show: a fresh review's, or with
/// `CSEC_PREVIEW_DEADLINE=<seconds>` one that many seconds away (30 or less
/// draws the countdown), as `cs-review-preview` takes it. Nothing closes a
/// probe's panel at it; `--deadline-probe` runs the real close.
private func previewDeadline() -> ReviewDeadline {
  guard let raw = ProcessInfo.processInfo.environment["CSEC_PREVIEW_DEADLINE"] else {
    return SudoReviewDeadline(timeLimit: syntheticFixture().timeLimit).closing
  }
  guard let seconds = Int(raw), seconds > 0 else { fail("CSEC_PREVIEW_DEADLINE must be a number of seconds") }
  return ReviewDeadline(remaining: .seconds(seconds))
}

private func renderSyntheticPreview(arguments: [String]) -> Never {
  guard (4...5).contains(arguments.count) else {
    fail("usage: csec-sudo-review --preview <\(previewFixtureNames.joined(separator: "|"))> <output.png> [light|dark]")
  }
  let review = previewFixture(named: arguments[2])
  let outputPath = arguments[3]
  if arguments.count == 5 {
    guard arguments[4] == "light" || arguments[4] == "dark" else {
      fail("preview appearance must be light or dark")
    }
    NSApplication.shared.appearance = NSAppearance(
      named: arguments[4] == "light" ? .aqua : .darkAqua)
  }
  let application = NSApplication.shared
  application.setActivationPolicy(.accessory)
  Task { @MainActor in
    // `CSEC_PREVIEW_NO_TOUCH_ID=1` draws the panel as a Mac that cannot take
    // a touch shows it while the phone may still decide.
    guard
      let png = TrustedSudoAuthorizationReviewSession.previewPNG(
        review, terminal: syntheticTerminal(), deadline: previewDeadline(),
        touchID: ProcessInfo.processInfo.environment["CSEC_PREVIEW_NO_TOUCH_ID"] == "1" ? .unavailable : nil)
    else {
      fail("could not render preview", status: 1)
    }
    do {
      try png.write(to: URL(fileURLWithPath: outputPath))
    } catch {
      fail("could not write preview", status: 1)
    }
    print("sudo review preview: wrote \(arguments[2]) PNG")
    exit(0)
  }
  runApplication()
  exit(1)
}

if CommandLine.arguments == [CommandLine.arguments[0], "--self-test"] {
  runSelfTest()
}
if CommandLine.arguments == [CommandLine.arguments[0], "--validate-synthetic-frame"] {
  validateSyntheticFrame()
}
if CommandLine.arguments.count >= 2, CommandLine.arguments[1] == "--display-round-trip" {
  checkDisplayRoundTrip(Array(CommandLine.arguments.dropFirst(2)))
}
if CommandLine.arguments.count >= 2, CommandLine.arguments[1] == "--preview" {
  renderSyntheticPreview(arguments: CommandLine.arguments)
}
#if DEBUG
// These probes put the real panel on screen for a developer check, so it
// carries the red TEST banner and nobody mistakes it for a sudo waiting on
// them (ReviewTestBanner). A release helper, which PAM spawns, has none of
// them, and `--preview` renders offscreen, unmarked.
func marksPanelsAsTest() {
  MainActor.assumeIsolated { ReviewTestBanner.isShown = true }
}
if CommandLine.arguments == [CommandLine.arguments[0], "--grace-probe"] {
  marksPanelsAsTest()
  runGraceProbe()
}
if CommandLine.arguments == [CommandLine.arguments[0], "--typing-probe"] {
  marksPanelsAsTest()
  runTypingProbe()
}
if CommandLine.arguments == [CommandLine.arguments[0], "--focus-probe"] {
  marksPanelsAsTest()
  runFocusProbe()
}
if CommandLine.arguments == [CommandLine.arguments[0], "--no-touch-id-probe"] {
  marksPanelsAsTest()
  runNoTouchIDProbe()
}
if CommandLine.arguments == [CommandLine.arguments[0], "--unlock-probe"] {
  marksPanelsAsTest()
  runUnlockProbe()
}
if CommandLine.arguments == [CommandLine.arguments[0], "--deadline-probe"] {
  marksPanelsAsTest()
  runDeadlineProbe()
}
#endif
if CommandLine.arguments == [CommandLine.arguments[0], "--screen-lock-probe"] {
  runScreenLockProbe()
}
if CommandLine.arguments == [CommandLine.arguments[0], "--parent-watch-probe"] {
  runParentWatchProbe()
}
if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--presentation-lock-probe" {
  runPresentationLockProbe(directory: CommandLine.arguments[2])
}
#if DEBUG
if CommandLine.arguments == [CommandLine.arguments[0], "--phone-probe"] {
  runPhoneProbe()
}
// The activation sampler uses the production review body with only this fixed
// fixture. A release helper accepts neither this mode nor any live UI probe.
if CommandLine.arguments == [CommandLine.arguments[0], "--synthetic-review-probe"] {
  guard cs_fd_is_pipe_or_socket(STDIN_FILENO) == 1,
    let frame = readBoundedStandardInput(),
    SudoAuthorizationReviewWire.decode(frame) == syntheticFixture()
  else { fail("invalid synthetic review request") }
  marksPanelsAsTest()
  runReview(
    originalParent: getppid(), review: syntheticFixture(),
    deadline: SudoReviewDeadline(timeLimit: syntheticFixture().timeLimit))
}
#endif
guard CommandLine.arguments.count == 1 else {
  reject(.unexpectedArguments)
}
// Read before anything can block: this is the sudo that spawned the helper.
let originalParent = getppid()
guard SudoReviewParentTrust.isTrusted(originalParent: originalParent) else {
  reject(.untrustedParent, status: 69)
}
guard cs_fd_is_pipe_or_socket(STDIN_FILENO) == 1 else {
  reject(.stdinNotPipe)
}
guard let frame = readBoundedStandardInput(),
  let review = SudoAuthorizationReviewWire.decode(frame)
else {
  reject(.invalidFrame)
}
// The module wrote the time it has left just before the frame: start the
// helper's own deadline from it now, before anything else can take time.
let deadline = SudoReviewDeadline(timeLimit: review.timeLimit)

// Reading stdin can block. Authenticate again before any daemon request or UI;
// the parent watch then bounds the complete review to that same live parent.
guard SudoReviewParentTrust.isTrusted(originalParent: originalParent) else {
  reject(.untrustedParent, status: 69)
}
SudoReviewLog.record(.started(parent: originalParent))
runReview(originalParent: originalParent, review: review, deadline: deadline)

private func runReview(
  originalParent: pid_t, review: SudoAuthorizationReviewRequest, deadline: SudoReviewDeadline
) -> Never {
  runWatchingParent(originalParent: originalParent, deadline: deadline) {
    // A sudo that Claude Code auto mode ran, and whose command the classifier
    // approved, needs no panel: csecd judges it from the kernel's view of the
    // sudo that spawned this helper and the PAM module's rendering of its argv,
    // before anything is drawn. A decline comes with the note the panel shows;
    // anything else (not Claude Code's, delegation off, no csecd, no answer in
    // time) leaves the panel exactly as it was.
    let delegation = await SudoDelegationClient.installed.ask(
      SudoDelegationRequest(command: review.submittedCommand))
    SudoReviewLog.record(.delegation(delegation.decision))
    if delegation.decision == .approved {
      return deadline.decide() ? 0 : SudoReviewDeadline.expiredExitStatus
    }
    let review = review.withDelegation(note: delegation.note, pairingLine: delegation.pairingLine)
    // csecd names the tab, under its own Automation grant: an Apple event from
    // this helper would be charged to whichever application ran sudo
    // (`SudoTerminalRequest`). No answer in time shows the PAM tty alone.
    let named = await SudoDelegationClient.installed.terminal()
    let terminal = named ?? review.ttyOnlyTerminal
    SudoReviewLog.record(.terminal(
        named == nil ? .ttyOnly : named?.application == nil ? .csecdUnnamed : .csecd,
        titled: terminal.title != nil))
    // The panel and the paired phone start together; the first verified answer
    // wins (SudoReviewRace). csecd authenticates this helper by its code
    // identity before it mirrors anything, and this helper takes csecd's answer
    // only from the product agent. With no csecd, no paired phone, or relay
    // trouble, the phone leg is unavailable at once and the panel decides alone.
    // With no Touch ID on this Mac the panel cannot approve, so it stays up only
    // while the phone may still decide (`SudoReviewWithoutTouchID`).
    let phone = SudoRemoteReviewClient.installed
    let phoneRequest = SudoRemoteReviewRequest(review, terminal: terminal, closing: deadline.closing)
    let reviewStarted = ContinuousClock.now
    let outcome = await SudoReviewRace.run(
      presentationLock: .shared,
      local: { phoneStatus in
        await TrustedSudoAuthorizationReviewSession.present(
          review, terminal: terminal, phone: phoneStatus, deadline: deadline.closing)
      },
      phone: { await phone.review(phoneRequest) }
    )
    // The deadline closed the review, wherever it was (the delegation ask,
    // the terminal lookup, the wait for another review's turn, the panel):
    // the module ends sudo without another prompt and tells the terminal why.
    // A decision that won the latch first stands.
    let took = reviewStarted.duration(to: .now)
    guard deadline.decide() else {
      await reportEnd(.timedOut, review: phoneRequest, took: took, deadline: deadline)
      return SudoReviewDeadline.expiredExitStatus
    }
    SudoReviewLog.record(.outcome(outcome))
    // A Touch ID on this panel, which always shows the pairing line it was
    // given, also lets auto mode run sudo in the project: csecd records it only
    // for the helper it offered the line to. A phone approval csecd records
    // itself. Either way the sudo is approved.
    // A touch in the panel's last moments skips the pairing when its call
    // could outlast the module's deadline: the approval must stand, and the
    // module would kill a helper still waiting on csecd.
    if outcome == .approved(on: .mac), review.pairingLine != nil {
      if deadline.fitsBeforeModuleDeadline(SudoDelegationClient.deadline) {
        let paired = await SudoDelegationClient.installed.pair(SudoPairingRequest())
        SudoReviewLog.record(.pairing(paired ? .recorded : .notRecorded))
      } else {
        SudoReviewLog.record(.pairing(.skippedNearDeadline))
      }
    }
    // csecd logs how the review ended, under the coding agent above the sudo,
    // so a supervisor can raise a review nobody answered again. A phone
    // decision csecd logged itself.
    await reportEnd(
      SudoReviewEndRequest.Outcome.reported(
        expired: false, parentExited: SudoReviewParentExit.helper.hasExited, outcome: outcome),
      review: phoneRequest, took: took, deadline: deadline)
    // 0 approves; 69 (Use Password, a phone Deny, or nobody deciding) lets sudo
    // fall back to its password prompt; 75, above, is nobody answering in time.
    return outcome.exitStatus
  }
}

/// Report the review's end to csecd for its decision log (`sudo_review_end`),
/// bounded like the pairing report and only when that bound still ends before
/// the module's deadline. It runs in a task of its own: on the deadline's and
/// the parent's paths the review's task is already cancelled, which would end
/// a bounded call at once. The sudo's outcome stands whatever csecd answers.
@Sendable private func reportEnd(
  _ outcome: SudoReviewEndRequest.Outcome?, review: SudoRemoteReviewRequest, took: Duration,
  deadline: SudoReviewDeadline
) async {
  guard let outcome else { return }
  guard deadline.fitsBeforeModuleDeadline(SudoDelegationClient.endDeadline) else {
    SudoReviewLog.record(.endReport(.skippedNearDeadline))
    return
  }
  let request = SudoReviewEndRequest(outcome, review: review, took: took)
  let logged = await Task.detached { await SudoDelegationClient.installed.end(request) }.value
  SudoReviewLog.record(.endReport(logged ? .recorded : .notRecorded))
}
