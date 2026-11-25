#if canImport(AppKit)
  import AppKit
  import ConvenientSecurity
  import Foundation

  /// The typing guard on approval prompts: a window that has just appeared must
  /// neither take keyboard focus nor accept a button press until the grace
  /// period has passed and the keyboard has gone quiet, a prompt that finishes
  /// early must never see its frozen controls re-enabled by the late timer,
  /// and a live panel's keyboard focus rests where a keystroke presses
  /// nothing.
  ///
  /// The panel is borderless, transparent, and parked far offscreen, and the
  /// focus step is a recorder rather than the production activation, so the
  /// suite never puts a window in front of the developer or steals their focus —
  /// which would be this feature's own bug. The keyboard clock is injected too:
  /// the developer typing while the suite runs must change nothing.
  @MainActor
  final class GraceFixture: NSObject {
    let window: NSPanel
    let sink: PromptKeyboardSink
    let deny: NSButton
    let choice: NSPopUpButton
    private(set) var denyPresses = 0
    private(set) var focusCalls = 0

    override init() {
      window = NSPanel(
        contentRect: NSRect(x: -20_000, y: -20_000, width: 200, height: 120),
        styleMask: [.borderless],
        backing: .buffered,
        defer: false
      )
      window.isReleasedWhenClosed = false
      window.alphaValue = 0
      window.hidesOnDeactivate = false

      deny = NSButton(title: "Deny", target: nil, action: nil)
      deny.keyEquivalent = "\u{1b}"
      choice = NSPopUpButton(frame: .zero, pullsDown: false)
      choice.addItem(withTitle: "1 hour")
      // Built the way both approval panels build theirs.
      sink = PromptKeyboardSink.install(in: window)
      super.init()
      deny.target = self
      deny.action = #selector(denyPressed(_:))

      let stack = NSStackView(views: [choice, deny])
      stack.orientation = .vertical
      stack.translatesAutoresizingMaskIntoConstraints = false
      sink.addSubview(stack)
      NSLayoutConstraint.activate([
        stack.leadingAnchor.constraint(equalTo: sink.leadingAnchor, constant: 10),
        stack.topAnchor.constraint(equalTo: sink.topAnchor, constant: 10),
      ])
    }

    @objc private func denyPressed(_ sender: Any?) { denyPresses += 1 }

    /// `keyboardIdle` defaults to a keyboard nobody has touched for an hour.
    func grace(
      delay: TimeInterval, requiredIdle: TimeInterval = 0.3,
      keyboardIdle: @escaping () -> TimeInterval = { 3600 }
    ) -> PromptInteractionGrace {
      PromptInteractionGrace(
        window: window, controls: [deny, choice], delay: delay,
        requiredKeyboardIdle: requiredIdle, keyboardIdle: keyboardIdle,
        focus: { [unowned self] in
          focusCalls += 1
          // The production step also makes the window key; that needs the
          // process activated, which the suite deliberately never does.
          PromptInteractionGrace.restoreInitialFirstResponder(in: window)
        }
      )
    }

    /// The Escape key equivalent, exactly as AppKit would route it to the panel.
    func pressEscape() -> Bool {
      guard
        let event = NSEvent.keyEvent(
          with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
          windowNumber: window.windowNumber, context: nil, characters: "\u{1b}",
          charactersIgnoringModifiers: "\u{1b}", isARepeat: false, keyCode: 53
        )
      else { return false }
      return window.performKeyEquivalent(with: event)
    }

    /// A key going down in the panel, delivered as AppKit delivers it.
    func press(_ characters: String, keyCode: UInt16) {
      deliverKeyDown(characters, keyCode: keyCode, to: window)
    }

    func tearDown() {
      window.orderOut(nil)
      window.close()
    }
  }

  /// What a live panel has and the suite's panels lack: being the key window.
  /// AppKit turns Tab, and Space on a focused button, into nil-targeted
  /// actions (`selectNextKeyView:`, the button's click), and those walk only
  /// the key window's responder chain, so on a panel that is not key they
  /// reach nothing and every keyboard check passes or fails vacuously.
  /// Production makes a live panel key by activating; the suite never
  /// activates, so for the length of `body` it gives `NSApp` a class whose
  /// `keyWindow` is the panel, then puts the original class back. Nothing
  /// reaches the window server: the process stays inactive, the panel is not
  /// made key, and the developer's keyboard focus stays where it was.
  private final class KeyWindowStandInApplication: NSApplication {
    static weak var window: NSWindow?
    override var keyWindow: NSWindow? { Self.window ?? super.keyWindow }
  }

  @MainActor
  private func asKeyWindow(_ window: NSWindow, _ name: String, _ body: () -> Void) {
    let application = NSApplication.shared
    guard let original = object_getClass(application) else {
      check(false, "\(name): the application's class can be read")
      return
    }
    let wasActive = application.isActive
    KeyWindowStandInApplication.window = window
    object_setClass(application, KeyWindowStandInApplication.self)
    defer {
      object_setClass(application, original)
      KeyWindowStandInApplication.window = nil
    }
    check(application.keyWindow === window && !window.isKeyWindow,
          "\(name): AppKit routes the panel's keys as the key window's, without the panel being made key")
    body()
    check(application.isActive == wasActive,
          "\(name): routing keys as the key window's never activates the process")
  }

  @MainActor
  private func deliverKeyDown(_ characters: String, keyCode: UInt16, to window: NSWindow) {
    guard
      let event = NSEvent.keyEvent(
        with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
        windowNumber: window.windowNumber, context: nil, characters: characters,
        charactersIgnoringModifiers: characters, isARepeat: false, keyCode: keyCode
      )
    else { return }
    window.sendEvent(event)
  }

  /// Seconds since a key went down, as the session counter reports it: a key
  /// press is published only when the step it fell in has closed, dated to
  /// that step's start; before any closed step holds one, an hour.
  private func steppedKeyboardIdle(
    keys: [TimeInterval], now: TimeInterval, step: TimeInterval
  ) -> TimeInterval {
    let published = keys
      .map { (floor($0 / step) * step) }
      .filter { $0 + step <= now }
      .max()
    guard let published else { return 3600 }
    return now - published
  }

  /// The keys of a sentence that must press nothing on a live panel.
  private let strayKeys: [(characters: String, keyCode: UInt16)] = [
    (" ", 49), ("\r", 36), ("x", 7),
  ]

  @MainActor
  private func spinRunLoop(seconds: TimeInterval) {
    RunLoop.main.run(until: Date().addingTimeInterval(seconds))
  }

  @MainActor
  func promptInteractionGraceTests() async {
    NSApplication.shared.setActivationPolicy(.accessory)

    do {
      let fixture = GraceFixture()
      let grace = fixture.grace(delay: 0.15)
      check(grace.phase == .pending, "grace: not started until begin()")
      check(fixture.deny.isEnabled && fixture.choice.isEnabled, "grace: controls start enabled")

      grace.begin()
      check(grace.phase == .waiting, "grace: waiting after begin()")
      check(fixture.window.isVisible, "grace: window is shown immediately")
      check(!fixture.window.isKeyWindow, "grace: window is not key while waiting")
      check(!fixture.deny.isEnabled, "grace: deny button disabled while waiting")
      check(!fixture.choice.isEnabled, "grace: selector disabled while waiting")
      check(fixture.focusCalls == 0, "grace: focus step not run while waiting")

      let escapeHandled = fixture.pressEscape()
      check(!escapeHandled, "grace: Escape is not consumed while waiting")
      check(fixture.denyPresses == 0, "grace: Escape does not press Deny while waiting")

      spinRunLoop(seconds: 0.05)
      check(grace.phase == .waiting, "grace: still waiting before the delay elapses")
      check(!fixture.deny.isEnabled, "grace: deny still disabled before the delay elapses")

      spinRunLoop(seconds: 0.2)
      check(grace.phase == .interactive, "grace: interactive after the delay")
      check(fixture.deny.isEnabled, "grace: deny button enabled after the delay")
      check(fixture.choice.isEnabled, "grace: selector enabled after the delay")
      check(fixture.focusCalls == 1, "grace: focus step ran exactly once")
      check(
        fixture.window.firstResponder === fixture.sink,
        "grace: keyboard focus rests on the keyboard sink once the panel is live")

      let escapeHandledLater = fixture.pressEscape()
      check(escapeHandledLater, "grace: Escape is consumed once interactive")
      check(fixture.denyPresses == 1, "grace: Escape presses Deny once interactive")

      grace.cancel()
      check(grace.phase == .interactive, "grace: cancel after the delay changes nothing")
      check(fixture.deny.isEnabled, "grace: cancel after the delay leaves controls enabled")
      fixture.tearDown()
    }

    do {
      // The owner finished first: biometric success freezes the selector, or a
      // denial closes the window. The late timer must not undo that.
      let fixture = GraceFixture()
      fixture.choice.isEnabled = false
      let grace = fixture.grace(delay: 0.1)
      grace.begin()
      grace.cancel()
      check(grace.phase == .cancelled, "grace: cancelled while waiting")
      check(!fixture.deny.isEnabled, "grace: cancel leaves the disabled controls alone")

      spinRunLoop(seconds: 0.25)
      check(grace.phase == .cancelled, "grace: a cancelled timer never fires")
      check(!fixture.deny.isEnabled, "grace: cancelled grace never re-enables controls")
      check(!fixture.choice.isEnabled, "grace: a control disabled before begin() stays disabled")
      check(fixture.focusCalls == 0, "grace: cancelled grace never takes focus")
      fixture.tearDown()
    }

    do {
      // A control that was already disabled when the grace began returns to
      // disabled, not enabled, when the grace ends.
      let fixture = GraceFixture()
      fixture.choice.isEnabled = false
      let grace = fixture.grace(delay: 0.05)
      grace.begin()
      grace.begin()
      spinRunLoop(seconds: 0.2)
      check(grace.phase == .interactive, "grace: second begin() is a no-op")
      check(fixture.deny.isEnabled, "grace: previously enabled control restored")
      check(!fixture.choice.isEnabled, "grace: previously disabled control stays disabled")
      check(fixture.focusCalls == 1, "grace: duplicate begin() does not focus twice")
      fixture.tearDown()
    }

    do {
      // Re-presenting a prompt after a screen unlock, as both approval panels do
      // in handleUnlockSignal. If the Mac locked inside the first grace period,
      // that grace is still pending and its controls are still disabled. The
      // owner simply begins a new grace over the same window: the class
      // supersedes the stale one — stops its timer, puts the controls back to
      // what it found — before the new grace snapshots them, so nothing is
      // recorded as "was disabled" that the owner never disabled, and the stale
      // timer can never fire under the new grace and take focus early.
      let fixture = GraceFixture()
      // A control the owner itself had frozen before either grace must stay
      // frozen throughout: supersession restores the owner's state, not "on".
      fixture.choice.isEnabled = false
      let stale = fixture.grace(delay: 0.2)
      stale.begin()
      check(!fixture.deny.isEnabled && !fixture.choice.isEnabled,
            "grace: a prompt interrupted mid-grace still holds its controls")

      let represented = fixture.grace(delay: 0.2)
      represented.begin()
      check(stale.phase == .cancelled,
            "grace: beginning a grace on the same window supersedes the one still waiting")
      check(!fixture.deny.isEnabled,
            "grace: the re-presented prompt holds its controls back again")

      // Long enough for both timers to have been due: the stale one first, then
      // the re-presented one. Only the second may act.
      spinRunLoop(seconds: 0.5)
      check(stale.phase == .cancelled, "grace: a superseded grace never fires")
      check(represented.phase == .interactive, "grace: the re-presented grace elapses")
      check(fixture.deny.isEnabled,
            "grace: a re-presented prompt ends with usable controls, never stranded disabled")
      check(!fixture.choice.isEnabled,
            "grace: a control the owner froze before the first grace stays frozen after the second")
      check(fixture.focusCalls == 1, "grace: only the re-presented grace takes focus")
      fixture.tearDown()
    }

    do {
      // A grace that already elapsed is not "waiting" and must not be touched by
      // a later one on the same window; a grace on another window never is.
      let fixture = GraceFixture()
      let first = fixture.grace(delay: 0.05)
      first.begin()
      spinRunLoop(seconds: 0.2)
      check(first.phase == .interactive, "grace: the first grace elapsed normally")
      let second = fixture.grace(delay: 0.05)
      second.begin()
      check(first.phase == .interactive,
            "grace: an elapsed grace is left alone by a later one on the same window")
      let other = GraceFixture()
      let elsewhere = other.grace(delay: 0.2)
      elsewhere.begin()
      check(second.phase == .waiting,
            "grace: a grace on another window supersedes nothing here")
      spinRunLoop(seconds: 0.3)
      check(second.phase == .interactive && elsewhere.phase == .interactive,
            "grace: both later graces elapse on their own windows")
      other.tearDown()
      fixture.tearDown()
    }

    do {
      // The human is typing as the panel appears and keeps on past its
      // shortest delay: the grace waits until the keyboard has been quiet for
      // the quiet period, and every key starts that wait again.
      let fixture = GraceFixture()
      var lastKey = Date()
      let grace = fixture.grace(
        delay: 0.1, requiredIdle: 0.4, keyboardIdle: { Date().timeIntervalSince(lastKey) })
      grace.begin()
      spinRunLoop(seconds: 0.2)
      check(grace.phase == .waiting && !fixture.deny.isEnabled && fixture.focusCalls == 0,
            "grace: a keyboard still busy past the shortest delay holds the panel back")
      lastKey = Date()
      spinRunLoop(seconds: 0.3)
      check(grace.phase == .waiting && !fixture.deny.isEnabled && !fixture.choice.isEnabled,
            "grace: each key pressed while held starts the quiet period again")
      check(!fixture.pressEscape() && fixture.denyPresses == 0,
            "grace: Escape presses nothing while the keyboard is busy")
      spinRunLoop(seconds: 0.35)
      check(grace.phase == .interactive && fixture.deny.isEnabled && fixture.focusCalls == 1,
            "grace: the panel goes live once the keyboard has been quiet for the quiet period")
      fixture.tearDown()
    }

    do {
      // A human who was not typing gets the panel at the shortest delay.
      let fixture = GraceFixture()
      let grace = fixture.grace(delay: 0.1, requiredIdle: 0.4, keyboardIdle: { 5 })
      grace.begin()
      spinRunLoop(seconds: 0.25)
      check(grace.phase == .interactive && fixture.focusCalls == 1,
            "grace: a quiet keyboard adds nothing to the shortest delay")
      fixture.tearDown()
    }

    do {
      // The real counter, as measured: a key press is published only when the
      // step it fell in closes, dated to that step's start, so steady typing
      // reads anything from one step to just under two. Scaled to a
      // quarter-second step: a grace waiting for the quiet period plus one
      // step stays held for as long as the typing goes on, and goes live
      // once it stops.
      let step = 0.25
      let quiet = 0.25
      let started = Date()
      let keys = stride(from: -0.5, through: 1.0, by: 0.06).map { $0 }
      let counter: () -> TimeInterval = {
        steppedKeyboardIdle(keys: keys, now: Date().timeIntervalSince(started), step: step)
      }
      let fixture = GraceFixture()
      let grace = fixture.grace(delay: 0.1, requiredIdle: quiet + step, keyboardIdle: counter)
      grace.begin()
      var liveWhileTyping = false
      while Date().timeIntervalSince(started) < 1.0 {
        spinRunLoop(seconds: 0.02)
        if grace.phase != .waiting { liveWhileTyping = true }
      }
      check(!liveWhileTyping && !fixture.deny.isEnabled && fixture.focusCalls == 0,
            "grace: a stepped keyboard counter never reads quiet while the typing goes on")
      spinRunLoop(seconds: 0.85)
      check(grace.phase == .interactive && fixture.focusCalls == 1,
            "grace: the panel goes live within one step of the quiet period after the typing stops")
      fixture.tearDown()

      // What waiting for the quiet period alone did: the same typing reads
      // past it inside every step, and the panel went live mid-sentence.
      let restarted = Date()
      let unmargined = GraceFixture()
      let early = unmargined.grace(
        delay: 0.1, requiredIdle: quiet,
        keyboardIdle: {
          steppedKeyboardIdle(keys: keys, now: Date().timeIntervalSince(restarted), step: step)
        })
      early.begin()
      spinRunLoop(seconds: 0.3)
      check(early.phase == .interactive,
            "grace: without the counter's step as margin, steady typing reads as quiet (the bug this guards)")
      unmargined.tearDown()
    }

    for reading in [-1.0, .nan, .infinity] {
      let fixture = GraceFixture()
      let grace = fixture.grace(delay: 0.05, requiredIdle: 0.4, keyboardIdle: { reading })
      grace.begin()
      spinRunLoop(seconds: 0.2)
      check(grace.phase == .interactive,
            "grace: a keyboard reading of \(reading), which is not a duration, holds nothing back")
      fixture.tearDown()
    }

    do {
      // The owner finished while the grace was held for typing: the re-check
      // it had scheduled must never fire.
      let fixture = GraceFixture()
      let grace = fixture.grace(delay: 0.05, requiredIdle: 0.3, keyboardIdle: { 0 })
      grace.begin()
      spinRunLoop(seconds: 0.15)
      check(grace.phase == .waiting,
            "grace: a keyboard that never goes quiet keeps the panel held")
      grace.cancel()
      spinRunLoop(seconds: 0.45)
      check(grace.phase == .cancelled && !fixture.deny.isEnabled && fixture.focusCalls == 0,
            "grace: cancelling a grace held for typing stops its re-check for good")
      fixture.tearDown()
    }

    do {
      // Re-presented while the first grace was held for typing.
      let fixture = GraceFixture()
      let stale = fixture.grace(delay: 0.05, requiredIdle: 0.3, keyboardIdle: { 0 })
      stale.begin()
      spinRunLoop(seconds: 0.15)
      let represented = fixture.grace(delay: 0.05)
      represented.begin()
      check(stale.phase == .cancelled,
            "grace: a new grace supersedes one held for typing")
      spinRunLoop(seconds: 0.45)
      check(stale.phase == .cancelled && represented.phase == .interactive
              && fixture.deny.isEnabled && fixture.focusCalls == 1,
            "grace: a superseded grace's re-check never fires; only the new grace takes focus")
      fixture.tearDown()
    }

    do {
      // Once live, the keys of a resumed sentence press nothing; Tab and
      // Escape still give the keyboard a deliberate answer.
      let fixture = GraceFixture()
      let grace = fixture.grace(delay: 0.05)
      grace.begin()
      spinRunLoop(seconds: 0.15)
      check(grace.phase == .interactive && fixture.window.firstResponder === fixture.sink,
            "sink: a live panel's keyboard focus is the sink")
      asKeyWindow(fixture.window, "sink") {
        for key in strayKeys { fixture.press(key.characters, keyCode: key.keyCode) }
        check(fixture.denyPresses == 0 && fixture.window.firstResponder === fixture.sink,
              "sink: Space, Return and a letter on a live panel press nothing")
        // Only Full Keyboard Access lets a button hold focus at all.
        if NSApplication.shared.isFullKeyboardAccessEnabled {
          fixture.press("\t", keyCode: 48)
          check(fixture.window.firstResponder is NSControl,
                "sink: Tab walks from the sink to the panel's controls")
          fixture.window.makeFirstResponder(fixture.deny)
          fixture.press(" ", keyCode: 49)
          check(fixture.denyPresses == 1,
                "sink: a focused button takes Space — the denial the sink is there to prevent")
        }
      }
      check(fixture.pressEscape() && fixture.denyPresses >= 1,
            "sink: Escape still presses the refusing button")
      fixture.tearDown()
    }

    check(
      PromptInteractionGrace.defaultDelay == 0.5,
      "grace: production prompts hold input for at least half a second")
    check(
      PromptInteractionGrace.keyboardQuietPeriod == 1.0
        && PromptInteractionGrace.keyboardCounterStep == 0.5
        && PromptInteractionGrace.requiredKeyboardIdle == 1.5,
      "grace: production prompts wait for a second of keyboard quiet, plus the counter's half-second step")
    let idle = PromptInteractionGrace.secondsSinceLastKeyPress()
    check(idle.isFinite && idle >= 0,
          "grace: this process can read how long the keyboard has been quiet (no Input Monitoring needed)")

    approvalPanelKeyboardTests()

    do {
      // The re-arm's focus step: a panel the human has left since clicking it
      // must neither take the focus back nor move its own keyboard focus.
      let fixture = GraceFixture()
      let wasActive = NSApplication.shared.isActive
      PromptInteractionGrace.refocusIfStillKey(fixture.window)
      check(!fixture.window.isKeyWindow && NSApplication.shared.isActive == wasActive,
            "grace: the re-arm focus step never activates the process or makes the panel key")
      // Only Full Keyboard Access lets a control hold focus; without it every
      // first responder is the window and this half would prove nothing.
      if NSApplication.shared.isFullKeyboardAccessEnabled {
        fixture.window.makeFirstResponder(fixture.choice)
        check(fixture.window.firstResponder === fixture.choice,
              "grace: the fixture can put focus on the selector")
        PromptInteractionGrace.refocusIfStillKey(fixture.window)
        check(fixture.window.firstResponder === fixture.choice,
              "grace: the re-arm focus step leaves the focus of a panel that is no longer key alone")
      }
      fixture.tearDown()
    }

    // Touch ID reaches only the key panel, and the evaluation registered last
    // strands the others, so every surface renews an evaluation armed while
    // it could not take a touch once the panel is key.
    check(ReviewFocusRecovery.onResignKey(authenticating: true) == .showClickToResume,
          "focus: losing key while Touch ID is armed says to click the panel")
    check(ReviewFocusRecovery.onResignKey(authenticating: false) == .none,
          "focus: losing key with Touch ID not armed (waiting for unlock, approved, finished) changes nothing")
    check(ReviewFocusRecovery.onBecomeKey(authenticating: true, lostKeyWhileArmed: true, armedWhileNotKey: false)
            == .rearm,
          "focus: key again after losing key while armed re-arms Touch ID behind a fresh guard")
    check(ReviewFocusRecovery.onBecomeKey(authenticating: true, lostKeyWhileArmed: true, armedWhileNotKey: true)
            == .rearm,
          "focus: a panel that lost key re-arms behind a guard even if it was never key before")
    check(ReviewFocusRecovery.onBecomeKey(authenticating: true, lostKeyWhileArmed: false, armedWhileNotKey: true)
            == .renew,
          "focus: the first key moment after arming unfocused renews the evaluation (another may have registered since)")
    check(ReviewFocusRecovery.onBecomeKey(authenticating: true, lostKeyWhileArmed: false, armedWhileNotKey: false)
            == .none,
          "focus: a panel key since its evaluation started keeps it")
    check(ReviewFocusRecovery.onBecomeKey(authenticating: false, lostKeyWhileArmed: true, armedWhileNotKey: true)
            == .none,
          "focus: a panel no longer armed (waiting for unlock, approved) never renews on focus")
    check(ReviewFocusRecovery.onSystemCancel(windowIsKey: true, renewedWhileKey: false) == .renew,
          "focus: a system cancel on the key panel renews Touch ID at once")
    check(ReviewFocusRecovery.onSystemCancel(windowIsKey: true, renewedWhileKey: true) == .showClickToResume,
          "focus: a second system cancel while key waits for a click away and back, so a repeating cancel cannot loop")
    check(ReviewFocusRecovery.onSystemCancel(windowIsKey: false, renewedWhileKey: false) == .showClickToResume
            && ReviewFocusRecovery.onSystemCancel(windowIsKey: false, renewedWhileKey: true) == .showClickToResume,
          "focus: a system cancel on a panel that is not key says to click it and renews when it becomes key")
    check(ReviewFocusRecovery.onBecomeKey(authenticating: true, lostKeyWhileArmed: true, armedWhileNotKey: false)
            == .rearm,
          "focus: a panel waiting after a system cancel (still armed, marked as having lost key) re-arms once key")
    check(ReviewFocusRecovery.isCurrent(generation: 3, currentGeneration: 3, authenticating: true),
          "focus: the evaluation started last decides while the panel waits on Touch ID")
    check(!ReviewFocusRecovery.isCurrent(generation: 2, currentGeneration: 3, authenticating: true),
          "focus: the cancellation (or a raced success) of an evaluation a re-arm replaced is dropped")
    check(!ReviewFocusRecovery.isCurrent(generation: 3, currentGeneration: 3, authenticating: false),
          "focus: no result counts once the panel has finished or is waiting for unlock")
    check(ReviewFocusRecovery.clickToResumeText.contains("active window"),
          "focus: the click-to-resume line names the active window, not the one in front (the panels float)")
    unlockRecheckTests()
  }

  /// The shared unlock probe's decisions. A panel up when the Mac locks is
  /// paused, not cancelled (measured), so the probe must pass a panel that
  /// renews Touch ID once key after unlock, as well as one held for unlock.
  private func unlockRecheckTests() {
    func sample(
      _ at: TimeInterval, up: Bool = true, locked: Bool, waiting: Bool = false, click: Bool = false,
      key: Bool, view: Int? = 2
    ) -> PromptUnlockRecheck.Sample {
      PromptUnlockRecheck.Sample(
        at: at, panelUp: up, screenLocked: locked, waitingForUnlock: waiting, clickToResume: click,
        panelIsKey: key, touchIDView: view)
    }

    // The 9 Nov runs: key and armed, the lock shield takes key with no
    // cancel, the panel says to click it, and once key it renews.
    var paused = PromptUnlockRecheck()
    check(paused.observe(sample(1, locked: false, key: true)).isEmpty,
          "unlock probe: nothing to report before the lock")
    check(paused.observe(sample(2, locked: true, click: true, key: false)) == [.locked(key: false)],
          "unlock probe: sees the lock itself, with no hold for unlock")
    check(paused.observe(sample(3, locked: false, click: true, key: false)) == [.unlocked],
          "unlock probe: sees the unlock")
    check(paused.observe(sample(4, locked: false, click: false, key: true)).isEmpty,
          "unlock probe: key on the evaluation armed before the lock is not yet a pass")
    check(paused.observe(sample(4.2, locked: false, key: true, view: 3)) == [.passed(.renewedAfterPause)],
          "unlock probe: passes a panel that renewed Touch ID on a fresh context once key after unlock")
    check(!paused.madeKeyByProbe, "unlock probe: says the panel became key by itself")
    check(paused.observe(sample(5, up: false, locked: false, key: false)).isEmpty,
          "unlock probe: nothing counts after the result")

    // The regression: the old probe failed a panel that took this path, and
    // a panel that never renews must still fail.
    var stale = PromptUnlockRecheck()
    _ = stale.observe(sample(1, locked: true, click: true, key: false))
    _ = stale.observe(sample(2, locked: false, click: true, key: false))
    check(stale.observe(sample(3, locked: false, click: true, key: true)).isEmpty
            && stale.observe(sample(4, locked: false, key: true)).isEmpty,
          "unlock probe: a key panel still on its pre-lock Touch ID view does not pass")
    check(stale.timeoutFailure == .noTouchIDAfterUnlock,
          "unlock probe: running out of time after unlock fails for want of fresh Touch ID")
    check(stale.observe(sample(5, locked: false, key: true, view: nil)).isEmpty,
          "unlock probe: a panel with no Touch ID view (up for the phone) does not pass")

    // Not key a while after unlock: the probe makes it key as a click would.
    var unfocused = PromptUnlockRecheck()
    _ = unfocused.observe(sample(1, locked: true, click: true, key: false))
    _ = unfocused.observe(sample(10, locked: false, click: true, key: false))
    check(unfocused.observe(sample(10 + PromptUnlockRecheck.keyWait - 0.2, locked: false, click: true, key: false))
            .isEmpty,
          "unlock probe: waits for the panel to become key on its own first")
    check(unfocused.observe(sample(10 + PromptUnlockRecheck.keyWait, locked: false, click: true, key: false))
            == [.notKeyAfterUnlock],
          "unlock probe: asks once to make a panel key that is not key after the wait")
    check(unfocused.observe(sample(16, locked: false, click: true, key: false)).isEmpty,
          "unlock probe: asks to make it key only once")
    check(unfocused.observe(sample(16.2, locked: false, key: true, view: 3)) == [.passed(.renewedAfterPause)]
            && unfocused.madeKeyByProbe,
          "unlock probe: passes once made key and renewed, and says the probe made it key")
    check(PromptUnlockRecheck.line(for: .passed(.renewedAfterPause), madeKeyByProbe: true)
            .contains("once made key"),
          "unlock probe: the PASS line says the probe made the panel key")

    // A panel raised or re-armed behind the lock screen is cancelled there.
    var held = PromptUnlockRecheck()
    check(held.observe(sample(1, locked: true, waiting: true, key: false, view: 3))
            == [.locked(key: false), .heldForUnlock],
          "unlock probe: reports the hold for unlock")
    check(held.observe(sample(2, locked: false, waiting: true, key: true, view: 3)) == [.unlocked],
          "unlock probe: still waiting at unlock is not a pass")
    check(held.observe(sample(2.5, locked: false, key: true, view: 3)) == [.passed(.heldForUnlock)],
          "unlock probe: passes a held panel that left the wait and armed its rebuilt context while key")
    var heldUnfocused = PromptUnlockRecheck()
    _ = heldUnfocused.observe(sample(1, locked: true, waiting: true, key: false, view: 3))
    _ = heldUnfocused.observe(sample(2, locked: false, key: false, view: 3))
    check(heldUnfocused.observe(sample(3, locked: false, key: false, view: 3)).isEmpty,
          "unlock probe: a held panel that is not key after unlock does not pass yet")

    // The hold text alone proves a lock even if the flag read missed it.
    var holdFirst = PromptUnlockRecheck()
    check(holdFirst.observe(sample(1, locked: false, waiting: true, key: false))
            == [.locked(key: false), .heldForUnlock, .unlocked],
          "unlock probe: the wait text counts as a lock")

    // The panel renewed inside one poll interval after unlock.
    var quick = PromptUnlockRecheck()
    _ = quick.observe(sample(1, locked: true, click: true, key: false))
    check(quick.observe(sample(2, locked: false, key: true, view: 3)) == [.unlocked, .passed(.renewedAfterPause)],
          "unlock probe: a renewal before the first unlocked sample still passes")

    // Locked again before the panel answered: the new lock is judged alone.
    var relocked = PromptUnlockRecheck()
    _ = relocked.observe(sample(1, locked: true, click: true, key: false))
    _ = relocked.observe(sample(2, locked: false, click: true, key: false))
    check(relocked.observe(sample(3, locked: true, click: true, key: false, view: 2)) == [.locked(key: false)],
          "unlock probe: reports a second lock")
    _ = relocked.observe(sample(4, locked: false, click: true, key: false))
    check(relocked.observe(sample(5, locked: false, key: true, view: 3)) == [.passed(.renewedAfterPause)],
          "unlock probe: passes after the second unlock")

    var closed = PromptUnlockRecheck()
    _ = closed.observe(sample(1, locked: true, click: true, key: false))
    check(closed.observe(sample(2, up: false, locked: true, key: false)) == [.failed(.panelClosed)],
          "unlock probe: fails a panel that closed although its requester is alive")
    check(PromptUnlockRecheck().timeoutFailure == .neverLocked,
          "unlock probe: running out of time before a lock says the Mac never locked")
    var stillLocked = PromptUnlockRecheck()
    _ = stillLocked.observe(sample(1, locked: true, key: false))
    check(stillLocked.timeoutFailure == .neverUnlocked,
          "unlock probe: running out of time while locked says the Mac is still locked")
  }

  /// Every surface's own window, built as presenting it builds it but parked
  /// offscreen and transparent with no Touch ID started: its keyboard focus
  /// must rest on the sink in every variant, where Space, Return and a letter
  /// press nothing, while Escape still refuses and Tab still reaches the
  /// controls.
  @MainActor
  private func approvalPanelKeyboardTests() {
    let caller = CallerInfo(pid: 51, startTime: 9, description: "cs-selftest fixture (pid 51)")
    let plan = DeliveryPlan(
      mechanism: .directHeap,
      executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .independentlyProtected),
      descendantScope: .subtree,
      destination: .localDevelopment,
      requestedTTLSeconds: nil,
      operationContext: "run migrations"
    )
    let scopes = GrantScopeChoices(
      options: [
        GrantScopeOption(kind: .requestingCommand, pid: 51, startTime: 9, processLabel: "ruby"),
        GrantScopeOption(kind: .terminalSession, pid: 20, startTime: 2, processLabel: "fish"),
      ],
      defaultOptionID: "terminal_session-20-2"
    )
    let durations = GrantDurationChoices.offered(requestedTTLSeconds: nil)
    let credential = PolicyReviewCredential(references: [try! SecretRef("csec://dev/API_TOKEN")])
    let release = AccessPolicyReview(
      caller: caller, reason: "run migrations", plan: plan, commandLine: "bin/rails db:migrate",
      credentials: [credential], scopeChoices: scopes, durationChoices: durations
    )
    let ssh = SSHAccessReviewDetails(
      hostNames: ["github.com"], remoteUser: "git", keyLabel: "work", keyAlgorithm: "ssh-ed25519")
    let sshReview = AccessPolicyReview(
      caller: caller, reason: ssh.reason,
      plan: DeliveryPlan(
        mechanism: .credentialProtocol,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/ssh", assurance: .independentlyProtected),
        descendantScope: .subtree, destination: .credentialConsumer, operationContext: "ssh"
      ),
      credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://dev/id_ed25519")])],
      scopeChoices: scopes, durationChoices: durations, ssh: ssh
    )
    let restore = RestoreReviewDetails(
      cause: .restart,
      rows: [
        RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "This terminal session · pid 20",
                         references: ["csec://dev/API_TOKEN"])
      ],
      storeCount: 1
    )
    let releaseWithRestore = AccessPolicyReview(
      caller: caller, reason: "run migrations", plan: plan, commandLine: "bin/rails db:migrate",
      credentials: [credential], scopeChoices: scopes, durationChoices: durations, restore: restore
    )
    let surfaces: [(name: String, build: () -> ApprovalPanelInspection)] = [
      ("secret-access panel", { .access(release) }),
      ("SSH panel", { .access(sshReview) }),
      ("restore-only panel", { .access(.restoreOnly(caller: caller, restore: restore)) }),
      // Auto-mode settings changes were a bare OS sheet a Space dismissed:
      // the panel they moved to takes no stray key.
      ("settings panel", { .access(settingsChangeFixture(caller: caller)) }),
      // So were host fixes and the other setup steps (csec-0.60).
      ("host fixes panel", { .access(hostFixesFixture(caller: caller)) }),
      ("release panel with a restore section", { .access(releaseWithRestore) }),
      ("sudo panel", {
        .sudo(
          SudoAuthorizationReviewRequest(
            submittedCommand: "sudo /usr/bin/true", workingDirectory: "/Users/example/project",
            terminal: "/dev/ttys001"),
          terminal: TerminalSessionContext(
            application: "iTerm2", title: "deploy — ~/project", location: "window 1, tab 2",
            tty: "ttys001"))
      }),
    ]
    for surface in surfaces {
      do {
        let panel = surface.build()
        let window = park(panel.window)
        // What the grace's focus step does once the panel is live.
        PromptInteractionGrace.restoreInitialFirstResponder(in: window)
        check(window.contentView is PromptKeyboardSink
                && window.initialFirstResponder === window.contentView
                && window.firstResponder === window.contentView,
              "\(surface.name): keyboard focus rests on the keyboard sink")
        asKeyWindow(window, surface.name) {
          for key in strayKeys { deliverKeyDown(key.characters, keyCode: key.keyCode, to: window) }
          check(window.isVisible && window.firstResponder === window.contentView,
                "\(surface.name): Space, Return and a letter press nothing")
          if NSApplication.shared.isFullKeyboardAccessEnabled {
            deliverKeyDown("\t", keyCode: 48, to: window)
            check(window.firstResponder is NSControl,
                  "\(surface.name): Tab walks from the sink to the panel's controls "
                    + "(focus: \(window.firstResponder.map { String(describing: type(of: $0)) } ?? "none"))")
            // The hazard the sink removes, on this panel's own refusing button.
            if let refusing = refusingButton(in: window.contentView) {
              window.makeFirstResponder(refusing)
              deliverKeyDown(" ", keyCode: 49, to: window)
              check(!window.isVisible,
                    "\(surface.name): a focused refusing button takes Space and closes the panel")
            } else {
              check(false, "\(surface.name): has a refusing button with Escape as its key equivalent")
            }
          }
        }
        window.orderOut(nil)
        withExtendedLifetime(panel) {}
      }
      do {
        let panel = surface.build()
        let window = park(panel.window)
        PromptInteractionGrace.restoreInitialFirstResponder(in: window)
        guard
          let escape = NSEvent.keyEvent(
            with: .keyDown, location: .zero, modifierFlags: [], timestamp: 0,
            windowNumber: window.windowNumber, context: nil, characters: "\u{1b}",
            charactersIgnoringModifiers: "\u{1b}", isARepeat: false, keyCode: 53)
        else {
          check(false, "\(surface.name): builds an Escape event")
          continue
        }
        check(window.performKeyEquivalent(with: escape) && !window.isVisible,
              "\(surface.name): Escape still refuses a live panel")
        window.orderOut(nil)
        withExtendedLifetime(panel) {}
      }
    }
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

  @MainActor
  private func refusingButton(in view: NSView?) -> NSButton? {
    guard let view else { return nil }
    if let button = view as? NSButton, button.keyEquivalent == "\u{1b}" { return button }
    for child in view.subviews {
      if let found = refusingButton(in: child) { return found }
    }
    return nil
  }
#else
  func promptInteractionGraceTests() async {}
#endif
