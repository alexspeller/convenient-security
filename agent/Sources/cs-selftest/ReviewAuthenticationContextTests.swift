import ConvenientSecurity
import Foundation
import LocalAuthentication

/// The `LAContext` invariants shared by csec's three approval dialogs, asserted
/// on each surface's own factory path rather than once on the helper.
///
/// The load-bearing one is Touch ID reuse. `LAContext.h` documents
/// `touchIDAuthenticationAllowableReuseDuration` as accepting a biometric match
/// the device lock screen already took, so a nonzero value on any of these
/// surfaces would let an approval panel raised shortly after the Mac is unlocked
/// with Touch ID succeed with no finger on the sensor and nothing read — an
/// authorization that is not a human decision. Nothing here evaluates a policy,
/// so no suite run ever puts a Touch ID sheet on screen.
func reviewAuthenticationContextTests() {
  let surfaces: [(ReviewAuthenticationContext.Surface, String, String)] = [
    (.secretAccess, "secret-access review", "Deny"),
    (.sshSigning, "SSH signing review", "Deny"),
    (.sudo, "sudo review", "Use Password…"),
  ]

  for (surface, label, cancelTitle) in surfaces {
    let context = ReviewAuthenticationContext.make(for: surface)
    check(
      context.touchIDAuthenticationAllowableReuseDuration == 0,
      "review context: the \(label) reuses no lock-screen Touch ID match")
    check(
      surface.cancelTitle == cancelTitle,
      "review context: the \(label) refuses with \"\(cancelTitle)\"")
    check(
      context.localizedCancelTitle == cancelTitle,
      "review context: the \(label) carries that title into Apple's sheet")
    check(
      context.localizedFallbackTitle == "",
      "review context: the \(label) offers no password fallback inside the sheet")
  }

  check(
    ReviewAuthenticationContext.Surface.allCases.count == surfaces.count,
    "review context: every approval surface is covered by these checks")

  // The rebuild an unlock retry performs is the same factory call, so a context
  // built for the second presentation of a prompt holds the same invariant.
  let rebuilt = ReviewAuthenticationContext.make(for: .secretAccess)
  check(
    rebuilt.touchIDAuthenticationAllowableReuseDuration == 0,
    "review context: a prompt re-presented after unlock reuses no match either")
}
