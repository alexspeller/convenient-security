import Foundation

/// What an approval panel does with its armed Touch ID when its window loses
/// or regains key status. Every approval surface — the secret-access and SSH
/// reviews in csecd and the sudo review helper — runs its window's key changes
/// through this one rule.
///
/// Measured on macOS 26.2 with a probe built like these panels (an `NSPanel`
/// at `.modalPanel` level, an embedded `LAAuthenticationView`, the evaluation
/// started with the window), and in `coreauthd`'s and LocalAuthentication's
/// own log:
/// - An embedded evaluation is paused, and a touch goes nowhere, while its
///   process is not active, its window is not key, or its view is covered by
///   another window. It resumes when that ends: behind another app the
///   evaluation is still pending, and clicking the panel is enough.
/// - Whichever evaluation registers last, from any process — another approval
///   panel, or the macOS Touch ID sheet that `pam_tid` or another app raises —
///   owns the sensor. The earlier one is stashed and never retried: no
///   callback, no error, and nothing to recover even after the panel is
///   clicked. Only a fresh evaluation on a new context answers again.
///
/// So an evaluation that was armed while the panel could not take a touch may
/// have been stranded meanwhile, and the panel renews it when it becomes key:
/// - A panel that lost key while armed says to click it, and when the human
///   makes it key again it re-arms on a fresh context behind a typing guard
///   that never takes the focus back. Every competing prompt measured took key
///   status from the panel (a csec panel at the end of its grace,
///   the macOS sheet at once), so this is the case collisions produce.
/// - A panel armed before it was ever key — every first presentation, whose
///   grace holds the focus back, and an unlock re-present behind another app —
///   renews its evaluation, with no further guard, the first time it becomes
///   key: another panel may have registered after it in the meantime. The
///   paused first evaluation could not have taken a touch, so this costs
///   nothing.
/// A still pending evaluation renewed or re-armed only swaps the Touch ID
/// glyph, so the two cases are not told apart.
///
/// A screen lock is one of these key changes (measured on macOS 27.2): the
/// lock shield takes key status from an armed panel within about 0.1 s, the
/// evaluation is paused with no error, and the panel renews it once key after
/// unlock. macOS cancels (`LAError.systemCancel`, "System authentication is
/// running.") only an evaluation started while the screen is locked, which
/// `ScreenLockState` holds for unlock.
///
/// Not covered: a prompt that strands a panel which stays key — a csec panel
/// raised and dismissed inside its own grace, before it ever took key. The
/// stranded panel stays key and ignores touches until the human clicks
/// another window and then this one.
public enum ReviewFocusRecovery: Equatable, Sendable {
  /// Nothing to do.
  case none
  /// Key status left the panel while Touch ID was armed: touches no longer
  /// reach it, and another prompt may have taken the sensor. Say so.
  case showClickToResume
  /// The panel is key again after losing key while Touch ID was armed: start
  /// a fresh evaluation behind a fresh typing guard, because the pending one
  /// may be stranded and the human may still be typing elsewhere.
  case rearm
  /// The panel is key for the first time since Touch ID was armed: start a
  /// fresh evaluation, because another may have registered after it. The
  /// grace that just made it key already held the controls back.
  case renew

  /// The status line while the panel waits to be clicked. The panels float
  /// above other windows, so "in front" would not say which one Touch ID
  /// answers; the active one does.
  public static let clickToResumeText =
    "Touch ID answers only the active window. Click this window to use Touch ID."

  /// The window resigned key.
  public static func onResignKey(authenticating: Bool) -> ReviewFocusRecovery {
    authenticating ? .showClickToResume : .none
  }

  /// The window became key. `lostKeyWhileArmed` is whether it resigned key
  /// while the current evaluation was armed; `armedWhileNotKey` is whether
  /// that evaluation started while the window was not key and the window has
  /// not been key since. A panel key throughout keeps its evaluation.
  public static func onBecomeKey(
    authenticating: Bool, lostKeyWhileArmed: Bool, armedWhileNotKey: Bool
  ) -> ReviewFocusRecovery {
    guard authenticating else { return .none }
    if lostKeyWhileArmed { return .rearm }
    return armedWhileNotKey ? .renew : .none
  }

  /// macOS ended the armed evaluation itself (`LAError.systemCancel`) with the
  /// screen unlocked and Touch ID still here
  /// (`ReviewTouchIDUnavailable.AfterFailure.systemCancelled`), on a panel
  /// that stays up waiting on Touch ID. `renewedWhileKey` is whether the
  /// panel already renewed after a system cancel since it last became or
  /// resigned key.
  /// - Key, and not yet renewed: `.renew`, a fresh evaluation one run-loop
  ///   turn later. The focus did not move, so no new typing guard.
  /// - Otherwise: `.showClickToResume`. A panel that is not key renews when
  ///   it becomes key (`onBecomeKey`); one that is key and was cancelled again
  ///   waits for the human to click away and back, so something that keeps
  ///   cancelling cannot make the panel re-arm in a loop.
  public static func onSystemCancel(windowIsKey: Bool, renewedWhileKey: Bool) -> ReviewFocusRecovery {
    windowIsKey && !renewedWhileKey ? .renew : .showClickToResume
  }

  /// Whether an evaluation's result is the panel's answer. A re-arm
  /// invalidates the evaluation it replaces, which then reports a
  /// cancellation (or, if a touch raced the swap, a success) on a context the
  /// panel no longer uses; only the evaluation started last, while the panel
  /// is still waiting on Touch ID, decides.
  public static func isCurrent(
    generation: Int, currentGeneration: Int, authenticating: Bool
  ) -> Bool {
    authenticating && generation == currentGeneration
  }
}
