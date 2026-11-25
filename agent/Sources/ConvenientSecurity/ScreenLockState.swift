import Foundation
#if canImport(CoreGraphics)
  import CoreGraphics
#endif

/// Whether the login session's screen is locked, and the pure rule for what a
/// biometric cancellation means in that state.
///
/// The problem this solves: a Touch ID prompt that is cancelled while the user
/// is away — the Mac auto-locked or slept — arrives back as an
/// `LAError.systemCancel`, which the consent paths used to treat as a denial. So
/// a request the human *never saw* failed closed, and they returned to a "consent
/// denied" with no way to have approved it. While the screen is locked the
/// consent window (and its Deny button) is behind the lock screen, so such a
/// cancellation can only be system-initiated, never the user choosing Deny. The
/// safe response is therefore to hold the request open and re-present Touch ID
/// once the Mac is unlocked, not to deny.
public enum ScreenLockState {
    /// What to do after a biometric prompt is cancelled or fails.
    public enum PostFailureAction: Equatable {
        /// The screen is locked: the human could not have seen or dismissed the
        /// prompt, so this cancellation is not a real denial. Wait for unlock and
        /// re-present rather than failing the request.
        case waitForUnlock
        /// The screen is unlocked: the cancellation may be a genuine human
        /// decision (or an unrecoverable biometric error). Each caller then
        /// tells a system cancel the human did not make from the rest
        /// (`BiometricConsent.next`, `ReviewTouchIDUnavailable.afterFailure`).
        case deny
    }

    /// The whole safety argument, as one pure function: with the screen locked,
    /// never convert a cancellation into a denial; unlocked, it may be one.
    /// This is deterministic and unit-tested; the live lock/unlock cycle around
    /// it can only be exercised by a manual on-device test.
    public static func action(screenLocked: Bool) -> PostFailureAction {
        screenLocked ? .waitForUnlock : .deny
    }

    /// What every approval panel says while it is held for unlock. One string,
    /// so the panels cannot drift apart and `PromptUnlockRecheckProbe` can see
    /// the hold on any of them.
    public static let waitingForUnlockText =
        "Waiting for you to unlock this Mac — Touch ID will be requested again."

    #if canImport(CoreGraphics)
        /// The interval between polls while waiting for the screen to unlock.
        /// Human-scale: a sub-second re-check is imperceptible and avoids the
        /// missed-notification failure mode of `DistributedNotificationCenter`.
        public static let pollInterval: TimeInterval = 0.5

        /// Whether the current login session's screen is locked right now.
        ///
        /// `loginwindow` adds `CGSSessionScreenIsLocked` to the session
        /// dictionary with a true value only while the screen is locked, and
        /// omits the key entirely otherwise (verified live: the key is absent
        /// when unlocked). A missing dictionary — e.g. a headless session — reads
        /// as unlocked, which is the fail-safe default (deny rather than hang).
        public static var isScreenLocked: Bool {
            isScreenLocked(sessionInfo: CGSessionCopyCurrentDictionary() as? [String: Any])
        }
    #endif

    /// The session dictionary key `loginwindow` sets while the screen is locked.
    public static let screenIsLockedKey = "CGSSessionScreenIsLocked"

    /// Reads the lock flag out of a session dictionary, the shape both
    /// `CGSessionCopyCurrentDictionary` and the IORegistry's `IOConsoleUsers`
    /// entries have. A missing dictionary or key reads as unlocked.
    public static func isScreenLocked(sessionInfo: [String: Any]?) -> Bool {
        guard let info = sessionInfo else { return false }
        if let locked = info[screenIsLockedKey] as? Bool { return locked }
        if let locked = info[screenIsLockedKey] as? Int { return locked != 0 }
        return false
    }

    #if canImport(CoreGraphics)

        /// Suspends until the screen is unlocked, or the surrounding task is
        /// cancelled. Returns immediately if already unlocked. Polls rather than
        /// observing the `com.apple.screenIsUnlocked` distributed notification so
        /// a dropped notification can never strand a pending consent request.
        public static func waitForUnlock() async {
            while isScreenLocked {
                do {
                    try await Task.sleep(nanoseconds: UInt64(pollInterval * 1_000_000_000))
                } catch {
                    return  // Task cancelled; the caller re-checks and denies.
                }
            }
        }
    #endif
}
