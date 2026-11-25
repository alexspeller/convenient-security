import Foundation

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  import AppKit
  @preconcurrency import LocalAuthenticationEmbeddedUI
#endif

/// What `PromptUnlockRecheckProbe` concludes from its samples of a real
/// approval panel across a screen lock, apart from AppKit so `cs-selftest`
/// drives it.
///
/// macOS takes a panel's armed Touch ID through a lock one of two ways, and
/// the probe accepts either, saying which:
/// - `.heldForUnlock`: the evaluation was cancelled behind the lock screen
///   (`LAError.systemCancel`), the panel said
///   `ScreenLockState.waitingForUnlockText`, and after unlock it left that
///   wait and asked for Touch ID again.
/// - `.renewedAfterPause`: no cancel came. The lock shield took key status
///   from the panel, which paused its evaluation (and the lock screen's own
///   Touch ID may have stranded it), and once the panel was key after unlock
///   it renewed Touch ID on a fresh context (`ReviewFocusRecovery`).
///
/// Measured on a developer Mac (macOS 27.2, 9 Nov 2026, the unified log of three
/// panels across real locks): the shield takes key within about 0.1 s of the
/// lock and an armed evaluation gets no error. The cancel comes only to an
/// evaluation started while the screen is locked, at once and with
/// "System authentication is running.". So a panel already up when the Mac
/// locks takes the second way; the first is for one raised, or re-armed,
/// behind the lock screen.
///
/// Either way the probe passes only once, with the Mac unlocked, the panel
/// is key (Touch ID answers only the key window), shows neither the unlock
/// wait nor the click-to-resume line, and is on a Touch ID view it was not on
/// while locked (the second way; the first rebuilds its context behind the
/// lock and arms it at unlock).
public struct PromptUnlockRecheck: Equatable, Sendable {
  /// One look at the panel.
  public struct Sample: Equatable, Sendable {
    /// Seconds since the probe started.
    public var at: TimeInterval
    public var panelUp: Bool
    public var screenLocked: Bool
    /// The panel shows `ScreenLockState.waitingForUnlockText`.
    public var waitingForUnlock: Bool
    /// The panel shows `ReviewFocusRecovery.clickToResumeText`.
    public var clickToResume: Bool
    public var panelIsKey: Bool
    /// Which embedded Touch ID view the panel shows, numbered in the order
    /// the probe first saw each; a new number is a fresh context. `nil` when
    /// there is none.
    public var touchIDView: Int?

    public init(
      at: TimeInterval, panelUp: Bool, screenLocked: Bool, waitingForUnlock: Bool,
      clickToResume: Bool, panelIsKey: Bool, touchIDView: Int?
    ) {
      self.at = at
      self.panelUp = panelUp
      self.screenLocked = screenLocked
      self.waitingForUnlock = waitingForUnlock
      self.clickToResume = clickToResume
      self.panelIsKey = panelIsKey
      self.touchIDView = touchIDView
    }
  }

  public enum Path: Equatable, Sendable {
    case heldForUnlock
    case renewedAfterPause
  }

  public enum Failure: Equatable, Sendable {
    /// The panel closed although its requester is alive.
    case panelClosed
    /// The probe ran out of time before it saw the Mac lock.
    case neverLocked
    /// The probe ran out of time with the Mac still locked.
    case neverUnlocked
    /// Unlocked, but the panel never had a fresh Touch ID evaluation while
    /// key.
    case noTouchIDAfterUnlock
  }

  public enum Event: Equatable, Sendable {
    /// The screen locked with the panel up. `key` is whether the panel was
    /// still key at that sample.
    case locked(key: Bool)
    case heldForUnlock
    case unlocked
    /// Unlocked for `PromptUnlockRecheck.keyWait` with the panel not key:
    /// the probe makes it key as a click on it would.
    case notKeyAfterUnlock
    case passed(Path)
    case failed(Failure)
  }

  /// How long after unlock the probe waits for the panel to become key on
  /// its own before making it key as a click would. The access panels
  /// measured took key back 1.4 s after unlock.
  public static let keyWait: TimeInterval = 5

  private enum Phase: Equatable, Sendable {
    case waitingForLock
    /// `touchIDView` is the view the panel showed at the last locked sample.
    case locked(touchIDView: Int?)
    case unlocked(at: TimeInterval, touchIDView: Int?)
    case finished
  }

  private var phase = Phase.waitingForLock
  private var sawHold = false
  private var askedForKey = false
  /// Whether the panel became key on its own after the last unlock, or the
  /// probe made it key. Only meaningful once passed.
  public private(set) var madeKeyByProbe = false

  public init() {}

  /// What this sample shows, in order. Once it holds `.passed` or `.failed`,
  /// later samples report nothing.
  public mutating func observe(_ sample: Sample) -> [Event] {
    guard phase != .finished else { return [] }
    guard sample.panelUp else {
      phase = .finished
      return [.failed(.panelClosed)]
    }
    var events: [Event] = []
    // The wait text appears only behind a lock, so it also proves one.
    if phase == .waitingForLock && (sample.screenLocked || sample.waitingForUnlock) {
      phase = .locked(touchIDView: sample.touchIDView)
      events.append(.locked(key: sample.panelIsKey))
    }
    if case .unlocked = phase, sample.screenLocked {
      // Locked again before the panel answered: judge the new lock alone.
      phase = .locked(touchIDView: sample.touchIDView)
      sawHold = false
      askedForKey = false
      madeKeyByProbe = false
      events.append(.locked(key: sample.panelIsKey))
    }
    if sample.waitingForUnlock && !sawHold {
      sawHold = true
      events.append(.heldForUnlock)
    }
    if case .locked(let lockedView) = phase {
      guard !sample.screenLocked else {
        phase = .locked(touchIDView: sample.touchIDView)
        return events
      }
      // Compared with the view seen while locked, not at this sample: a panel
      // that took key and renewed inside one poll interval still counts.
      phase = .unlocked(at: sample.at, touchIDView: lockedView)
      events.append(.unlocked)
    }
    guard case .unlocked(let unlockedAt, let lockedView) = phase else { return events }
    let fresh = sawHold || sample.touchIDView != lockedView
    if sample.panelIsKey && !sample.waitingForUnlock && !sample.clickToResume
      && sample.touchIDView != nil && fresh
    {
      phase = .finished
      events.append(.passed(sawHold ? .heldForUnlock : .renewedAfterPause))
      return events
    }
    if !sample.panelIsKey && !askedForKey && sample.at - unlockedAt >= Self.keyWait {
      askedForKey = true
      madeKeyByProbe = true
      events.append(.notKeyAfterUnlock)
    }
    return events
  }

  /// Why a run that ran out of time failed.
  public var timeoutFailure: Failure {
    switch phase {
    case .waitingForLock: return .neverLocked
    case .locked: return .neverUnlocked
    case .unlocked, .finished: return .noTouchIDAfterUnlock
    }
  }

  /// The probe's line for an event, after its prefix.
  public static func line(for event: Event, madeKeyByProbe: Bool) -> String {
    switch event {
    case .locked(let key):
      return "the Mac locked with the panel up (panel \(key ? "key" : "not key"))"
    case .heldForUnlock:
      return "the panel is held for unlock (macOS cancelled Touch ID behind the lock screen)"
    case .unlocked:
      return "the Mac unlocked; waiting for the panel to ask for Touch ID again"
    case .notKeyAfterUnlock:
      return "the panel is not key \(Int(keyWait)) s after unlock; making it key as a click on it would"
    case .passed(.heldForUnlock):
      return "PASS — the requester is alive; macOS cancelled Touch ID at the lock, the panel held for unlock, "
        + "stayed up and asked for Touch ID again"
        + (madeKeyByProbe ? " once made key" : " (key by itself)")
    case .passed(.renewedAfterPause):
      return "PASS — the requester is alive; macOS paused Touch ID across the lock without cancelling it, "
        + "and the panel stayed up and renewed it on a fresh context"
        + (madeKeyByProbe ? " once made key" : " once key by itself")
    case .failed(.panelClosed):
      return "FAIL — the panel closed although its requester is alive"
    case .failed(.neverLocked):
      return "FAIL — timed out (lock and unlock within three minutes): the Mac never locked"
    case .failed(.neverUnlocked):
      return "FAIL — timed out (lock and unlock within three minutes): the Mac is still locked"
    case .failed(.noTouchIDAfterUnlock):
      return "FAIL — timed out: after unlock the panel never asked for Touch ID again while key"
    }
  }
}

#if canImport(AppKit) && canImport(LocalAuthenticationEmbeddedUI)
  /// Dev-only, value-free on-device check that a real approval panel whose
  /// requester is alive survives a real screen lock and, once unlocked, asks
  /// for Touch ID again instead of closing or falling through, whichever way
  /// macOS took its Touch ID through the lock (`PromptUnlockRecheck`). Every
  /// approval surface shares it: `CSEC_PREVIEW_UNLOCK_RECHECK=1
  /// cs-review-preview <scenario>` covers the secret-access and SSH reviews,
  /// and `csec-sudo-review --unlock-probe` the sudo review.
  ///
  /// It needs a human: lock the Mac while the panel is up, then unlock it.
  /// It prints when it sees the lock, a hold for unlock if one comes, and the
  /// unlock, then `PASS` naming the way the panel took. If the panel is not
  /// key a few seconds after unlock, the probe makes it key as a click would
  /// and says so. A panel that closes, or no lock, unlock and fresh Touch ID
  /// within three minutes, fails the probe. Never touch the sensor while it
  /// runs (the caller fails the run if a touch approves the panel).
  public enum PromptUnlockRecheckProbe {
    public static func schedule(prefix: String) {
      // Each line as it happens: the human acts on them, and a run cut short
      // must still show how far it got.
      setlinebuf(stdout)
      Task { @MainActor in
        print("\(prefix): lock this Mac now, then unlock it (do not touch the sensor)")
        var recheck = PromptUnlockRecheck()
        let started = Date()
        for _ in 0..<(180 * 5) {
          try? await Task.sleep(nanoseconds: 200_000_000)
          let panel = NSApplication.shared.windows.first(where: { $0 is NSPanel && $0.isVisible })
          let content = panel?.contentView
          let sample = PromptUnlockRecheck.Sample(
            at: Date().timeIntervalSince(started),
            panelUp: content != nil,
            screenLocked: ScreenLockState.isScreenLocked,
            waitingForUnlock: content.map { showsText(ScreenLockState.waitingForUnlockText, in: $0) } ?? false,
            clickToResume: content.map { showsText(ReviewFocusRecovery.clickToResumeText, in: $0) } ?? false,
            panelIsKey: panel?.isKeyWindow ?? false,
            touchIDView: content.flatMap(touchIDViewNumber))
          for event in recheck.observe(sample) {
            print("\(prefix): \(PromptUnlockRecheck.line(for: event, madeKeyByProbe: recheck.madeKeyByProbe))")
            switch event {
            case .passed: exit(0)
            case .failed: exit(1)
            case .notKeyAfterUnlock:
              if let panel { PromptInteractionGrace.activateAndFocus(panel) }
            case .locked, .heldForUnlock, .unlocked: break
            }
          }
        }
        let failure = PromptUnlockRecheck.Event.failed(recheck.timeoutFailure)
        print("\(prefix): \(PromptUnlockRecheck.line(for: failure, madeKeyByProbe: recheck.madeKeyByProbe))")
        exit(1)
      }
    }

    /// Held strongly: a replaced view freed while the probe runs could hand
    /// its address to the next one and read as the same view.
    @MainActor private static var seenViews: [LAAuthenticationView] = []

    @MainActor
    private static func touchIDViewNumber(in content: NSView) -> Int? {
      guard let view = find(LAAuthenticationView.self, in: content), !view.isHidden else { return nil }
      if !seenViews.contains(where: { $0 === view }) { seenViews.append(view) }
      return seenViews.firstIndex(where: { $0 === view }).map { $0 + 1 }
    }

    @MainActor
    private static func find<T: NSView>(_ type: T.Type, in view: NSView) -> T? {
      if let match = view as? T { return match }
      for child in view.subviews {
        if let match = find(type, in: child) { return match }
      }
      return nil
    }

    @MainActor
    private static func showsText(_ text: String, in view: NSView) -> Bool {
      if let field = view as? NSTextField, !field.isHidden, field.stringValue == text { return true }
      return view.subviews.contains { showsText(text, in: $0) }
    }
  }
#endif
