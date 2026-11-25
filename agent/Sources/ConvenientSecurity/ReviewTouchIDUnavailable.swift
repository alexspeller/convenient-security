#if canImport(LocalAuthentication)
  import Foundation
  @preconcurrency import LocalAuthentication

  /// What every approval panel says and does while this Mac cannot take a
  /// touch: no fingerprint enrolled, Touch ID locked out after failed attempts,
  /// or the lid closed with no Touch ID keyboard.
  ///
  /// The panel cannot approve then; only the paired phone can, when the review
  /// was mirrored to it and the phone leg has not given up
  /// (`ReviewPhoneStatus`). So the status line says whether the phone can
  /// still approve rather than flatly that nothing can, on all three surfaces
  /// from this one place. What the panel does about it differs: the sudo panel
  /// closes for the password prompt once nobody can approve
  /// (`SudoReviewWithoutTouchID`), while the secret-access and SSH panels, with
  /// no fallback prompt to hand over to, stay up and say why the request
  /// cannot be approved.
  ///
  /// Touch ID can come back while a panel is up (the lid opened, a Touch ID
  /// keyboard connected). Every panel then polls for it
  /// (`TouchIDAvailabilityWatch`) and arms Touch ID once it returns, so the
  /// person who opened the lid can touch the sensor instead of reaching for
  /// the phone.
  ///
  /// It can also go away under an armed panel (the lid closed with an
  /// external display, a lockout). The evaluation then ends with an error
  /// that is not the human refusing, and the panel finds Touch ID unavailable
  /// when it asks again (`afterFailure`): it goes on exactly as if it had
  /// opened without Touch ID, rather than ending a review the phone could
  /// still approve.
  public enum ReviewTouchIDUnavailable {
    /// The status line beside the (hidden) Touch ID view.
    public static func statusText(
      for surface: ReviewAuthenticationContext.Surface, phoneCanDecide: Bool
    ) -> String {
      switch (surface, phoneCanDecide) {
      case (.sudo, true):
        return "Touch ID is unavailable on this Mac. Approve on your iPhone, or use your password."
      case (.sudo, false):
        return "Touch ID is unavailable on this Mac. Use your password."
      case (.secretAccess, true), (.sshSigning, true):
        return "Touch ID is unavailable on this Mac. Approve on your iPhone."
      case (.secretAccess, false), (.sshSigning, false):
        return "Touch ID is unavailable on this Mac, so this request cannot be authorized."
      }
    }

    /// What a panel up with no Touch ID does on each poll.
    public enum Poll: Sendable, Equatable {
      /// Touch ID is still unavailable, or the screen is locked (Touch ID
      /// armed behind the lock screen would only be cancelled): keep waiting.
      case keepWaiting
      /// Touch ID is back with the requester still running: arm it.
      case arm
      /// Touch ID is back but the requester is gone: close as requesterGone
      /// rather than arm a prompt nothing is waiting for.
      case requesterGone
    }

    /// The re-arm rule, as one pure function every panel runs through.
    /// `requesterAlive` is read only when it decides anything, so a caller may
    /// pass `touchIDAvailable && !screenLocked && <requester check>`.
    public static func onPoll(
      touchIDAvailable: Bool, screenLocked: Bool, requesterAlive: Bool
    ) -> Poll {
      guard touchIDAvailable, !screenLocked else { return .keepWaiting }
      return requesterAlive ? .arm : .requesterGone
    }

    /// What a panel does when its armed evaluation ends without success,
    /// with the screen unlocked (a locked screen waits for unlock first).
    public enum AfterFailure: Sendable, Equatable {
      /// Touch ID went away under the evaluation: carry on as a panel opened
      /// without Touch ID does, so the phone can still approve and Touch ID
      /// re-arms when it comes back.
      case touchIDLost
      /// macOS ended the evaluation itself (`LAError.systemCancel`) with
      /// Touch ID still here: another app came forward, or another prompt
      /// took the sensor. The human decided nothing, so the panel stays up
      /// and renews Touch ID when it can take a touch
      /// (`ReviewFocusRecovery.onSystemCancel`).
      case systemCancelled
      /// Anything else: the surface's own failure handling (a denial on the
      /// secret-access and SSH panels, the password on the sudo panel).
      case failed
    }

    /// The rule, as one pure function every panel runs through. Apple's
    /// refusing button (`LAError.userCancel`) is the human deciding, whatever
    /// Touch ID says now. Any other error is the system's: which code a lid
    /// closing mid-evaluation produces is not documented, so the answer comes
    /// from asking again (`touchIDAvailable`, a fresh probe), not from the
    /// code. A probe that still finds Touch ID leaves the failure as it was,
    /// except a system cancel, which is never the human's answer.
    public static func afterFailure(errorCode: Int?, touchIDAvailable: Bool) -> AfterFailure {
      if errorCode == LAError.Code.userCancel.rawValue { return .failed }
      guard touchIDAvailable else { return .touchIDLost }
      return errorCode == LAError.Code.systemCancel.rawValue ? .systemCancelled : .failed
    }

    /// Whether Touch ID can be evaluated now for `surface`, on a fresh
    /// context, so no context's cached answer can hide a change, unless
    /// `override` (given to a panel built at `builtAt`) holds it unavailable.
    /// The availability watch and the after-failure probe both ask this.
    public static func isAvailableNow(
      for surface: ReviewAuthenticationContext.Surface,
      override: ReviewTouchIDOverride? = nil,
      builtAt: ContinuousClock.Instant
    ) -> Bool {
      if override?.holdsUnavailable(builtAt: builtAt) == true { return false }
      return isAvailable(ReviewAuthenticationContext.make(for: surface))
    }

    /// Whether `context` could evaluate Touch ID now. The panels' first probe
    /// and every poll ask the same question.
    public static func isAvailable(
      _ context: LAContext, error: UnsafeMutablePointer<NSError?>? = nil
    ) -> Bool {
      var evaluationError: NSError?
      let available = context.canEvaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics, error: &evaluationError)
      error?.pointee = evaluationError
      return available
    }
  }

  /// A dev-only stand-in for a Mac that cannot take a touch, for previews,
  /// probes and `ApprovalPanelInspection`. It can make Touch ID unavailable,
  /// never available: outside the interval it names, the panel asks this Mac
  /// as usual.
  public enum ReviewTouchIDOverride: Sendable, Equatable {
    /// Unavailable for the panel's whole life.
    case unavailable
    /// Unavailable until this long after the panel was built, as a lid opened
    /// while it is up; then whatever this Mac says.
    case returnsAfter(Duration)
    /// Whatever this Mac says until this long after the panel was built, then
    /// unavailable for good, as a lid closed while it is up. An evaluation
    /// armed then is ended the way the system ends one
    /// (`endsArmedEvaluation`).
    case lostAfter(Duration)

    /// Whether this override holds Touch ID unavailable at `now`, for a
    /// panel built at `builtAt`.
    public func holdsUnavailable(
      builtAt: ContinuousClock.Instant, now: ContinuousClock.Instant = .now
    ) -> Bool {
      switch self {
      case .unavailable: return true
      case let .returnsAfter(interval): return now - builtAt < interval
      case let .lostAfter(interval): return now - builtAt >= interval
      }
    }

    /// For `lostAfter`, how long after `now` Touch ID goes, which is when a
    /// panel ends the evaluation it has armed (at once, if it has gone
    /// already); nil for the others, which never end one.
    public func endsArmedEvaluation(
      builtAt: ContinuousClock.Instant, now: ContinuousClock.Instant = .now
    ) -> Duration? {
      guard case let .lostAfter(interval) = self else { return nil }
      return max(.zero, interval - (now - builtAt))
    }

    /// The override a preview tool's `CSEC_PREVIEW_NO_TOUCH_ID` names: `1`
    /// for `.unavailable`, a whole number of seconds above 1 for
    /// `.returnsAfter`. Nil for anything else.
    public init?(previewValue: String) {
      if previewValue == "1" {
        self = .unavailable
        return
      }
      guard let seconds = Int(previewValue), seconds > 1 else { return nil }
      self = .returnsAfter(.seconds(seconds))
    }
  }

  /// Polls whether Touch ID has become available while a panel is up without
  /// it, on the main run loop.
  ///
  /// Polling, not `LAEnvironment`'s observer: that is macOS 15 and later while
  /// csec supports 13, and the unlock wait polls for the same reason
  /// (`ScreenLockState.pollInterval`), so a dropped notification cannot leave a
  /// panel waiting on a phone after the lid has opened. A probe costs about a
  /// millisecond on a fresh context and runs only while a panel is up with no
  /// Touch ID.
  @MainActor
  public final class TouchIDAvailabilityWatch {
    public static let pollInterval: TimeInterval = 1

    public typealias Probe = @MainActor () -> Bool

    private let probe: Probe
    private var timer: Timer?

    /// `probe` answers whether Touch ID can be evaluated now.
    public init(probe: @escaping Probe) {
      self.probe = probe
    }

    /// A watch that asks this Mac on a fresh context for `surface` each time,
    /// so no context's cached answer can hide Touch ID coming back, unless
    /// `override` holds it unavailable.
    public convenience init(
      surface: ReviewAuthenticationContext.Surface,
      override: ReviewTouchIDOverride? = nil,
      builtAt: ContinuousClock.Instant = .now
    ) {
      self.init(probe: {
        ReviewTouchIDUnavailable.isAvailableNow(for: surface, override: override, builtAt: builtAt)
      })
    }

    public var isRunning: Bool { timer != nil }

    /// Calls `onPoll` with the probe's answer every `pollInterval` until
    /// `stop()`. Starting a running watch does nothing.
    public func start(_ onPoll: @escaping @MainActor (Bool) -> Void) {
      guard timer == nil else { return }
      let probe = self.probe
      let timer = Timer(timeInterval: Self.pollInterval, repeats: true) { _ in
        DispatchQueue.main.async { MainActor.assumeIsolated { onPoll(probe()) } }
      }
      // `.common` so the poll keeps firing even during window/menu tracking.
      RunLoop.main.add(timer, forMode: .common)
      self.timer = timer
    }

    public func stop() {
      timer?.invalidate()
      timer = nil
    }

    /// The probe's answer now, outside the timer, for the panel's first look
    /// and for tests.
    public func probeNow() -> Bool { probe() }
  }
#endif
