import CSECRemoteApproval
import Foundation
#if canImport(CoreGraphics)
  import CoreGraphics
#endif

/// When the paired phone is alerted to a request csecd mirrored to it. The
/// request reaches the phone at once, so the app shows its card as soon as it
/// is opened; only the notification waits, for `macPromptGraceNanoseconds`, so
/// a prompt answered at the Mac never buzzes the phone as well. There is no
/// wait while nobody can answer the Mac's prompt with a touch — the session's
/// screen locked, its main display asleep, or Touch ID unavailable (nothing
/// enrolled, locked out, the lid closed with no Touch ID keyboard), when the
/// phone is the only approver and waiting would only delay it — and a wait
/// under way ends the moment that becomes true.
///
/// This delays a notification; it bounds nothing. The request has no lifetime,
/// and the phone may decide it before its alert as well as after.
public enum RemoteApprovalAlertTiming {
    public static let macPromptGraceNanoseconds: UInt64 = 30_000_000_000
    /// How often a wait re-reads whether the Mac is attended; the same
    /// human-scale interval `ScreenLockState.waitForUnlock` polls at.
    public static let pollNanoseconds: UInt64 = 500_000_000

    /// Suspends until the alert is due: `grace` has passed on `now`, or
    /// `macUnattended` reads true. Returns at once when cancelled.
    public static func waitUntilDue(
        grace: UInt64 = macPromptGraceNanoseconds,
        poll: UInt64 = pollNanoseconds,
        macUnattended: @Sendable () -> Bool,
        now: @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds },
        sleep: @Sendable (UInt64) async throws -> Void = { try await Task.sleep(nanoseconds: $0) }
    ) async {
        let start = now()
        while !Task.isCancelled {
            if macUnattended() { return }
            let elapsed = now() &- start
            if elapsed >= grace { return }
            do {
                try await sleep(min(poll, grace - elapsed))
            } catch {
                return
            }
        }
    }

    /// Whether nobody can answer the Mac's prompt with a touch. The Touch ID
    /// probe is read last, so a wait polls it only while the Mac is unlocked
    /// and awake; a probe costs about a millisecond on a fresh context
    /// (`TouchIDAvailabilityWatch`), at most 60 of them over one grace.
    public static func unattended(
        screenLocked: Bool, displayAsleep: Bool, canTakeTouch: @autoclosure () -> Bool
    ) -> Bool {
        screenLocked || displayAsleep || !canTakeTouch()
    }

    #if canImport(CoreGraphics) && canImport(LocalAuthentication)
      /// Whether nobody can answer the Mac's prompt with a touch now: the
      /// session's screen is locked, its main display is asleep, or this Mac
      /// cannot evaluate Touch ID. A surface's context differs only in the
      /// titles of Apple's sheet, so the secret-access one answers for all
      /// three.
      public static var macUnattended: Bool {
          unattended(
              screenLocked: ScreenLockState.isScreenLocked,
              displayAsleep: CGDisplayIsAsleep(CGMainDisplayID()) != 0,
              canTakeTouch: ReviewTouchIDUnavailable.isAvailable(
                  ReviewAuthenticationContext.make(for: .secretAccess)))
      }

      /// The gate csecd gives every requester.
      public static let live: RemoteApprovalAlertGate = {
          await waitUntilDue(macUnattended: { macUnattended })
      }
    #endif
}
