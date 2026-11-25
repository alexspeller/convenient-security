#if canImport(AppKit)
  import AppKit
  import Foundation

  /// Dev-only, value-free on-device check that a real approval panel honours
  /// its typing guard. It samples the first `NSPanel` the process owns shortly
  /// after the panel appears and again after the grace period has elapsed,
  /// printing whether the panel is key, whether the process is active, which
  /// control holds keyboard focus, and the enabled state of every button and
  /// selector, then exits the process.
  ///
  /// Every approval surface shares this one probe so all of them are checked
  /// the same way: `CSEC_PREVIEW_GRACE_PROBE=1 cs-review-preview <scenario>`
  /// covers the secret-access and SSH reviews, and
  /// `csec-sudo-review --grace-probe` covers the sudo review. The expected
  /// shape of a healthy panel is `key=false active=false` with every control
  /// disabled in the first sample, and `key=true active=true` with the controls
  /// enabled in the second.
  ///
  /// `firstResponder=` names what the keyboard would act on: a button by its
  /// title at that moment, anything else by its class. Every panel's must be
  /// `PromptKeyboardSink`, in both samples and whether or not Full Keyboard
  /// Access (`defaults read -g AppleKeyboardUIMode`, bit 1) is on. A button
  /// title there is a failure: with Full Keyboard Access on, Space presses the
  /// focused button, so the refusing one (`Cancel`, `Deny`, `Forget these
  /// approvals`, `Use Password…`) would turn a resumed sentence into a denial,
  /// and a scope radio or the lifetime popup would reshape the grant.
  ///
  /// `keyboardIdle=` is how long ago a key last went down, as the keyboard
  /// counter reports it, which explains a second sample that is still held:
  /// the grace waits for it to read `PromptInteractionGrace.requiredKeyboardIdle`.
  ///
  /// The typing check (`scheduleTypingCheck()`; `CSEC_PREVIEW_TYPING_PROBE=1
  /// cs-review-preview <scenario>` and `csec-sudo-review --typing-probe`)
  /// needs a human typing while the panel appears, and is the only one that
  /// shows the hold reading the real keyboard.
  ///
  /// `pairingLine=shown|hidden` appears on a panel that carries the delegated
  /// approvals' pairing line, so the scope and lifetime knobs'
  /// (`CSEC_PREVIEW_SCOPE` / `CSEC_PREVIEW_DURATION`) effect on it can be read
  /// from a probe; it is absent from every other panel.
  public enum PromptInteractionGraceProbe {
    /// Marks the pairing line's label, so the probe can report it.
    public static let pairingLineIdentifier = NSUserInterfaceItemIdentifier("csec.pairing-line")

    /// When the first sample is taken: after the panel is on screen, well
    /// inside the grace period.
    public static let earlySample: TimeInterval = 0.1
    /// When the second sample is taken: comfortably after the grace period,
    /// even when the Return that launched the probe went down just before the
    /// panel appeared and the grace waited out the keyboard's quiet period.
    public static let lateSample: TimeInterval = settle

    /// How long a grace can take when nobody types while it runs, plus a
    /// margin: the shortest delay, or the counter reading the grace waits for
    /// after a key pressed just as it began, whichever is longer.
    public static let settle: TimeInterval =
      max(PromptInteractionGrace.defaultDelay, PromptInteractionGrace.requiredKeyboardIdle) + 0.3

    /// Schedule both samples on the main actor. The caller presents the panel
    /// without blocking the main thread and then runs the AppKit event loop; the
    /// probe prints its two lines and exits the process with status 0.
    /// `prepare`, when given, runs first (a preview choosing a scope or
    /// lifetime on the panel), so both samples see what it did.
    public static func schedule(beforeSampling prepare: (@MainActor @Sendable () async -> Void)? = nil) {
      Task { @MainActor in
        await prepare?()
        try? await Task.sleep(nanoseconds: UInt64(earlySample * 1_000_000_000))
        report(label(earlySample))
        try? await Task.sleep(nanoseconds: UInt64((lateSample - earlySample) * 1_000_000_000))
        report(label(lateSample))
        exit(0)
      }
    }

    private static func label(_ seconds: TimeInterval) -> String {
      "t+\(Int((seconds * 1000).rounded()))ms"
    }

    /// One sample line. `extra`, when given, is appended before the controls
    /// (the focus probe's Touch ID fields).
    @MainActor
    static func report(_ label: String, extra: String = "") {
      let application = NSApplication.shared
      guard let panel = application.windows.first(where: { $0 is NSPanel }),
        let content = panel.contentView
      else {
        print("\(label): review panel never appeared")
        return
      }
      let states = controls(in: content).map { control -> String in
        let title = (control as? NSButton)?.title ?? String(describing: type(of: control))
        return "\(title)=\(control.isEnabled ? "enabled" : "disabled")"
      }
      let pairing = pairingLine(in: content).map { "pairingLine=\($0.isHidden ? "hidden" : "shown") " } ?? ""
      print(
        "\(label): visible=\(panel.isVisible) key=\(panel.isKeyWindow) "
          + "active=\(application.isActive) firstResponder=\(firstResponder(of: panel)) "
          + "keyboardIdle=\(milliseconds(PromptInteractionGrace.secondsSinceLastKeyPress())) "
          + pairing + extra
          + "controls[\(states.joined(separator: ", "))]")
    }

    /// The typing check. Run it and keep typing anywhere — the terminal that
    /// launched it (without Return) or a TextEdit window — as the panel
    /// appears, for a few seconds, then stop. While keys go down the panel
    /// must stay held (not key, controls disabled), and it may go live only
    /// once the keyboard counter has read `requiredKeyboardIdle`. Prints the
    /// first sample, the one where the panel went live, and a verdict, then
    /// exits: 0 PASS, 1 FAIL (live before the counter read quiet long enough,
    /// or never live), 3 INCONCLUSIVE when nobody typed long enough to hold
    /// the panel past its shortest delay.
    public static func scheduleTypingCheck() {
      Task { @MainActor in
        let clock = ContinuousClock()
        let start = clock.now
        var shownReported = false
        // When the latest key went down, as the counter dated it at the last
        // held sample.
        var lastKeyAt: TimeInterval?
        // Whether, past the shortest delay, the counter still read too recent
        // a key for the panel to go live: someone was typing.
        var heldByTyping = false
        // Counter steps that published a key while the panel was held.
        var stepsTypedWhileHeld = 0
        while true {
          let elapsed = seconds(start.duration(to: clock.now))
          guard let panel = NSApplication.shared.windows.first(where: { $0 is NSPanel }),
            let content = panel.contentView
          else {
            if elapsed > 5 {
              print("typing probe: review panel never appeared")
              exit(1)
            }
            try? await Task.sleep(nanoseconds: typingSampleNanoseconds)
            continue
          }
          if !shownReported, elapsed >= earlySample {
            report(label(elapsed))
            shownReported = true
          }
          if refusingButton(in: content)?.isEnabled ?? false {
            report("\(label(elapsed)) live")
            verdict(
              liveAt: elapsed, lastKeyAt: lastKeyAt, heldByTyping: heldByTyping,
              stepsTypedWhileHeld: stepsTypedWhileHeld)
          }
          let idle = PromptInteractionGrace.secondsSinceLastKeyPress()
          if idle.isFinite, idle >= 0 {
            let keyAt = elapsed - idle
            if let previous = lastKeyAt, keyAt > previous + typingSampleInterval {
              stepsTypedWhileHeld += 1
            }
            lastKeyAt = keyAt
            if elapsed >= PromptInteractionGrace.defaultDelay,
              idle < PromptInteractionGrace.requiredKeyboardIdle
            {
              heldByTyping = true
            }
          }
          if elapsed > 30 {
            print("typing probe: FAIL — the panel was still held 30 s after it appeared")
            exit(1)
          }
          try? await Task.sleep(nanoseconds: typingSampleNanoseconds)
        }
      }
    }

    private static let typingSampleInterval: TimeInterval = 0.01
    private static let typingSampleNanoseconds = UInt64(typingSampleInterval * 1_000_000_000)

    @MainActor
    private static func verdict(
      liveAt: TimeInterval, lastKeyAt: TimeInterval?, heldByTyping: Bool,
      stepsTypedWhileHeld: Int
    ) -> Never {
      let required = PromptInteractionGrace.requiredKeyboardIdle
      // The counter reading at the moment the panel went live, from the last
      // held sample: a key the counter published after it would have held
      // the panel, so nothing is missed. One sample of slack, since the live
      // moment is seen up to a sample late, never early.
      let reading = lastKeyAt.map { liveAt - $0 } ?? .infinity
      if reading + typingSampleInterval < required {
        print(
          "typing probe: FAIL — live at \(milliseconds(liveAt)) when the keyboard counter "
            + "read \(milliseconds(reading)) (needs \(milliseconds(required)))")
        exit(1)
      }
      guard heldByTyping else {
        print(
          "typing probe: INCONCLUSIVE — live at \(milliseconds(liveAt)) with no typing "
            + "holding it; rerun and keep typing as the panel appears")
        exit(3)
      }
      print(
        "typing probe: PASS — held \(milliseconds(liveAt)) while you typed "
          + "(\(stepsTypedWhileHeld) counter steps with a key); live when the keyboard counter "
          + "read \(milliseconds(reading)) (needs \(milliseconds(required)), "
          + "about \(milliseconds(PromptInteractionGrace.keyboardQuietPeriod)) to "
          + "\(milliseconds(required)) after your last key)")
      exit(0)
    }

    /// The button Escape presses: the refusing one, on every panel.
    @MainActor
    private static func refusingButton(in view: NSView) -> NSButton? {
      if let button = view as? NSButton, button.keyEquivalent == "\u{1b}" { return button }
      for child in view.subviews {
        if let found = refusingButton(in: child) { return found }
      }
      return nil
    }

    private static func seconds(_ duration: Duration) -> TimeInterval {
      let parts = duration.components
      return TimeInterval(parts.seconds) + TimeInterval(parts.attoseconds) / 1e18
    }

    private static func milliseconds(_ seconds: TimeInterval) -> String {
      guard seconds.isFinite, seconds >= 0 else { return "unknown" }
      return "\(Int((seconds * 1000).rounded()))ms"
    }

    @MainActor
    private static func pairingLine(in view: NSView) -> NSView? {
      if view.identifier == pairingLineIdentifier { return view }
      for child in view.subviews {
        if let found = pairingLine(in: child) { return found }
      }
      return nil
    }

    /// The focused control by title, so a wrong initial first responder — a
    /// scope radio or the duration popup rather than the refusing button — is
    /// visible in the sample rather than inferred from the panel's shape.
    @MainActor
    private static func firstResponder(of panel: NSWindow) -> String {
      guard let responder = panel.firstResponder else { return "none" }
      if let button = responder as? NSButton { return button.title }
      if let control = responder as? NSControl {
        return String(describing: type(of: control))
      }
      return String(describing: type(of: responder))
    }

    @MainActor
    private static func controls(in view: NSView) -> [NSControl] {
      var found: [NSControl] = []
      // NSPopUpButton is an NSButton, so this also lists the selectors.
      if let button = view as? NSButton { found.append(button) }
      for child in view.subviews { found += controls(in: child) }
      return found
    }
  }
#endif
