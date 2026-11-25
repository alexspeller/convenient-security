#if canImport(AppKit)
  import AppKit
  import CoreGraphics
  import Foundation

  /// Holds a freshly shown approval window back from the keyboard and mouse for
  /// a short grace period, so keystrokes the human already has in flight cannot
  /// press a button or change a selection in it.
  ///
  /// The problem: an approval panel is usually triggered by something other
  /// than the human's own keystrokes — a coding agent running `csec exec` while
  /// they type a sentence elsewhere. The instant the panel appeared it
  /// activated the agent process and took key-window status, so the next Space,
  /// Return, or Escape of that sentence landed on the focused Deny or Use
  /// Password button (with Full Keyboard Access on, a button is often the
  /// initial key view) and dismissed a request the human never read.
  ///
  /// During the grace period the window is ordered front but not made key, the
  /// application is not activated, and every registered control is disabled, so
  /// a stray click cannot act either. The period lasts at least `defaultDelay`
  /// and then for as long as the human is still typing: it ends only once no
  /// key has gone down anywhere in the session for `keyboardQuietPeriod`, as
  /// far as the session's keyboard counter can tell (`requiredKeyboardIdle`).
  /// A fixed half-second was not enough — a touch typist mid-sentence does not
  /// stop that fast, and a Space 598 ms after a panel appeared denied it. A
  /// human who was waiting for the prompt, not typing, still gets it at the
  /// half-second. When the grace ends, the controls return to their pre-grace
  /// enabled state and the focus step activates the application, makes the
  /// window key, and re-applies the window's intended first responder (a
  /// `PromptKeyboardSink`, so a keystroke that still arrives presses nothing).
  /// Touch ID is a deliberate physical act and is not held back by this: the
  /// owner starts its `LAContext` evaluation immediately, though macOS delivers
  /// a touch to an embedded evaluation only while its window is key, so in
  /// practice it answers once the focus step has run.
  ///
  /// An owner that finishes early (biometric success, a denial, the window
  /// closing) cancels the grace so a late timer can never re-enable controls the
  /// owner has since frozen.
  ///
  /// A prompt can be presented more than once (re-presented after the Mac
  /// unlocks, or Touch ID re-armed when the human clicks it again), and the
  /// second grace may begin while the first is still waiting — the Mac locked,
  /// or the human clicked away and back, inside that first grace. The second
  /// `begin()` therefore supersedes any grace still waiting on the same window: the
  /// earlier timer is stopped and its controls put back to their pre-grace
  /// state before the new snapshot is taken. Without that, the stale timer
  /// would fire under the new grace and take focus early, and the new grace
  /// would have recorded the still-disabled controls as "was disabled" and
  /// restored them that way for good.
  @MainActor
  public final class PromptInteractionGrace: NSObject {
    /// The shortest time a newly shown prompt ignores input: long enough for
    /// the click or keystroke in flight as it appears to land elsewhere; short
    /// enough that a human who was waiting for the prompt never notices it.
    nonisolated public static let defaultDelay: TimeInterval = 0.5

    /// How long the keyboard must have been still before a prompt takes it.
    /// Longer than the gaps between keys in a typed sentence, so a typist who
    /// has not noticed the panel keeps typing into their own window; short
    /// next to the time it takes to read the panel, so a human who stopped to
    /// read it finds it live by the time they reach for the sensor.
    nonisolated public static let keyboardQuietPeriod: TimeInterval = 1.0

    /// How coarsely the session's keyboard counter sees key presses. The
    /// window server publishes them in half-second steps, each dated to the
    /// start of the half second it fell in and published at its end (measured
    /// with steady typing; the HID layer below throttles activity to 250 ms,
    /// IOHIDNXEventTranslatorSessionFilter). So while a human types steadily
    /// the counter reads anything from half a second to just over a second,
    /// and a reading is up to one step older than the key it reflects.
    nonisolated public static let keyboardCounterStep: TimeInterval = 0.5

    /// The counter reading the grace waits for: the quiet period plus one
    /// step, so steady typing — which reads at most just over a second —
    /// never satisfies it, and a reading that does means no key for at least
    /// `keyboardQuietPeriod` up to the last step the counter has published.
    /// A key in the step still open is not visible yet; whatever it lands on
    /// presses nothing (`PromptKeyboardSink`). In practice the panel goes live
    /// one to one and a half seconds after the last key.
    nonisolated public static let requiredKeyboardIdle: TimeInterval =
      keyboardQuietPeriod + keyboardCounterStep

    /// Seconds since a key last went down anywhere in the login session, read
    /// from the window server's event state: when, never which key, and only
    /// to `keyboardCounterStep`. Event taps need the Input Monitoring grant;
    /// this counter does not, and reads the same in csecd, the sudo helper and
    /// a process with no TCC grant at all.
    nonisolated public static func secondsSinceLastKeyPress() -> TimeInterval {
      CGEventSource.secondsSinceLastEventType(.hidSystemState, eventType: .keyDown)
    }

    public enum Phase: Equatable {
      /// `begin()` has not been called; the window is not yet shown.
      case pending
      /// The window is visible and its controls are disabled; it is not key
      /// unless the human clicked it.
      case waiting
      /// The grace period elapsed: controls are enabled and the window has focus.
      case interactive
      /// The owner finished before the grace period elapsed, or a later grace
      /// began on the same window and superseded this one.
      case cancelled
    }

    public private(set) var phase = Phase.pending

    private let window: NSWindow
    private let delay: TimeInterval
    private let requiredKeyboardIdle: TimeInterval
    private let keyboardIdle: () -> TimeInterval
    private let focus: (() -> Void)?
    private let registeredControls: [NSControl]
    /// Snapshotted in `begin()`, after any waiting grace on the same window has
    /// been superseded, so the recorded state is the owner's, not a stale grace's.
    private var controls: [(control: NSControl, wasEnabled: Bool)] = []
    private var timer: Timer?

    /// The grace currently waiting on each window, so a later `begin()` on the
    /// same window can supersede it. Weak: a grace lives as long as its owner
    /// keeps it, and this table must never extend that.
    private static var waitingByWindow: [ObjectIdentifier: WeakGrace] = [:]

    private final class WeakGrace {
      weak var grace: PromptInteractionGrace?
      init(_ grace: PromptInteractionGrace) { self.grace = grace }
    }

    /// - Parameters:
    ///   - window: the prompt panel. `begin()` orders it front; the focus step
    ///     makes it key.
    ///   - controls: every control a keystroke or click could act on — buttons,
    ///     radios, popups. Labels must not be listed: disabling a text field
    ///     greys its text.
    ///   - delay: the shortest grace period; `defaultDelay` in production.
    ///   - requiredKeyboardIdle: the `keyboardIdle` reading the grace waits
    ///     for; `requiredKeyboardIdle` in production.
    ///   - keyboardIdle: seconds since a key last went down;
    ///     `secondsSinceLastKeyPress()` in production. Tests inject a clock, so
    ///     the developer typing while the suite runs changes nothing.
    ///   - focus: what to do once the prompt becomes interactive. `nil` selects
    ///     `activateAndFocus(_:)`; tests inject a recorder so no test ever
    ///     activates the process and steals the developer's focus.
    public init(
      window: NSWindow,
      controls: [NSControl],
      delay: TimeInterval = PromptInteractionGrace.defaultDelay,
      requiredKeyboardIdle: TimeInterval = PromptInteractionGrace.requiredKeyboardIdle,
      keyboardIdle: @escaping () -> TimeInterval = PromptInteractionGrace.secondsSinceLastKeyPress,
      focus: (() -> Void)? = nil
    ) {
      self.window = window
      self.registeredControls = controls
      self.delay = delay
      self.requiredKeyboardIdle = requiredKeyboardIdle
      self.keyboardIdle = keyboardIdle
      self.focus = focus
      super.init()
    }

    /// Show the window without focus, disable its controls, and start the
    /// timer. Calling it more than once is a no-op. A grace still waiting on
    /// the same window is superseded first (see the type comment).
    public func begin() {
      guard phase == .pending else { return }
      let key = ObjectIdentifier(window)
      if let previous = Self.waitingByWindow[key]?.grace, previous !== self {
        previous.supersede()
      }
      phase = .waiting
      Self.waitingByWindow[key] = WeakGrace(self)
      controls = registeredControls.map { ($0, $0.isEnabled) }
      for entry in controls { entry.control.isEnabled = false }
      // `orderFront` is documented to change neither the key nor the main window,
      // so keystrokes keep flowing to whatever the human was typing into.
      window.orderFront(nil)
      schedule(after: delay)
    }

    private func schedule(after interval: TimeInterval) {
      // A target/selector timer fires straight from the main run loop into this
      // main-actor object. A block timer that hopped through
      // `DispatchQueue.main.async` would stall whenever the run loop is being
      // spun from inside a GCD main-queue callback (CoreFoundation does not
      // re-enter the main queue there), which is how the test harness pumps it.
      let timer = Timer(
        timeInterval: interval, target: self, selector: #selector(graceElapsed(_:)),
        userInfo: nil, repeats: false
      )
      // `.common` so the timer still fires if the human is dragging or tracking
      // a menu elsewhere when it is due.
      RunLoop.main.add(timer, forMode: .common)
      self.timer = timer
    }

    /// Stop the timer without touching the controls. The owner is closing the
    /// window or has frozen its controls for good, and either way a late
    /// re-enable would be wrong.
    public func cancel() {
      timer?.invalidate()
      timer = nil
      if phase == .waiting {
        phase = .cancelled
        forgetIfWaiting()
      }
    }

    /// A later grace has begun on this window while this one was still
    /// waiting: stop the timer and put the controls back to the state this
    /// grace found them in, so the successor snapshots the owner's state.
    private func supersede() {
      guard phase == .waiting else { return }
      timer?.invalidate()
      timer = nil
      phase = .cancelled
      for entry in controls { entry.control.isEnabled = entry.wasEnabled }
      forgetIfWaiting()
    }

    private func forgetIfWaiting() {
      let key = ObjectIdentifier(window)
      if Self.waitingByWindow[key]?.grace === self {
        Self.waitingByWindow[key] = nil
      }
    }

    /// The shortest grace is over; hold on while the keyboard is still busy,
    /// and look again when it would have been quiet long enough. There is no
    /// cap: a human who keeps typing has not seen the panel, and the panel
    /// waiting for them is the point. A click on it still makes it key, and
    /// its owner then renews Touch ID there (`ReviewFocusRecovery`).
    @objc private func graceElapsed(_ timer: Timer) {
      guard phase == .waiting else { return }
      let idle = keyboardIdle()
      // A reading that is not a duration holds nothing back.
      if idle.isFinite, idle >= 0, idle < requiredKeyboardIdle {
        schedule(after: max(requiredKeyboardIdle - idle, Self.minimumRecheck))
        return
      }
      becomeInteractive()
    }

    /// The soonest a busy keyboard is looked at again, so a counter that
    /// lags the clock cannot spin the run loop.
    private static let minimumRecheck: TimeInterval = 0.05

    private func becomeInteractive() {
      guard phase == .waiting else { return }
      phase = .interactive
      timer = nil
      forgetIfWaiting()
      for entry in controls { entry.control.isEnabled = entry.wasEnabled }
      if let focus {
        focus()
      } else {
        Self.activateAndFocus(window)
      }
    }

    /// The production focus step: bring the process forward, make the prompt
    /// the key window, and give the intended control keyboard focus.
    public static func activateAndFocus(_ window: NSWindow) {
      NSApplication.shared.activate(ignoringOtherApps: true)
      window.makeKeyAndOrderFront(nil)
      restoreInitialFirstResponder(in: window)
    }

    /// The focus step for a prompt the human has just made key themselves (the
    /// Touch ID re-arm, `ReviewFocusRecovery`): it never activates the process,
    /// because the prompt is already key or the human has since left it, and
    /// taking the focus back would steal it from whatever they went to — or
    /// from another prompt doing the same, forever. A prompt still key gets its
    /// intended control back.
    public static func refocusIfStillKey(_ window: NSWindow) {
      guard window.isKeyWindow else { return }
      restoreInitialFirstResponder(in: window)
    }

    /// AppKit applies `initialFirstResponder` when the window first comes
    /// onscreen, which under a grace period happens while that control is still
    /// disabled and refusing focus. Apply it again now that it can accept. The
    /// key view loop is rebuilt first, now that every control is enabled and
    /// laid out: AppKit's automatic one is computed only on a later display
    /// pass, and until then Tab from the keyboard sink reaches nothing.
    public static func restoreInitialFirstResponder(in window: NSWindow) {
      window.recalculateKeyViewLoop()
      guard let initial = window.initialFirstResponder,
        window.firstResponder !== initial
      else { return }
      window.makeFirstResponder(initial)
    }
  }

  /// The content view of every approval panel, and where its keyboard focus
  /// rests: it takes first responder and acts on nothing. Once a panel is
  /// live, a keystroke that still reaches it — the Space of a sentence the
  /// human resumed after a pause, a Return, a letter — falls through to the
  /// window, which beeps, rather than pressing the focused refusing button
  /// (Full Keyboard Access lets Space press any focused button) or reshaping
  /// the grant through a scope radio or the lifetime popup. A deliberate
  /// keyboard answer stays one key away: Escape is the refusing button's key
  /// equivalent, and Tab walks the key view loop, which `install(in:)` keeps
  /// recalculated, to every control. Approval is a touch, never a key.
  @MainActor
  public final class PromptKeyboardSink: NSView {
    override public var acceptsFirstResponder: Bool { true }

    /// Make a fresh sink `window`'s content view and its initial first
    /// responder, and keep the key view loop recalculated as disclosures
    /// show and hide controls, so Tab from the sink reaches them.
    public static func install(in window: NSWindow) -> PromptKeyboardSink {
      let sink = PromptKeyboardSink()
      window.contentView = sink
      window.initialFirstResponder = sink
      window.autorecalculatesKeyViewLoop = true
      return sink
    }
  }
#endif
