#if canImport(AppKit)
import AppKit
import Foundation
import LocalAuthentication

// The agent-owned Touch ID gate for batched host remediation. Fix *selection* now
// happens in the launcher's terminal checkbox picker; this class only authorizes
// applying the already-selected, value-free set with one biometric tap. It is a
// bare system biometric sheet — no custom window.
//
// Why the terminal is a sufficient review surface: every remediation is a
// reversible, security-positive change, so a tampered selection can only apply
// *more* hardening, never leak a credential (the opposite direction of harm from
// the access-review case, where the WYSIWYG-in-trusted-window property is
// load-bearing). Touch ID here is the physical-presence gate a compromised
// launcher cannot forge, and csecd still owns and re-derives the privileged apply.
@MainActor
final class HostRemediationReviewSession {
    private let items: [HostRemediationItem]
    private let context = LAContext()
    private var biometricsAvailable = false

    private init(items: [HostRemediationItem]) {
        self.items = items
        context.localizedCancelTitle = "Not now"
        context.localizedFallbackTitle = ""
        var error: NSError?
        biometricsAvailable = context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: &error)
        if !biometricsAvailable {
            FileHandle.standardError.write(Data(
                "csecd: biometrics unavailable, denying host remediation (\(error?.localizedDescription ?? "no Touch ID"))\n".utf8))
        }
    }

    static func present(_ review: HostRemediationReview) async -> HostRemediationOutcome {
        await HostRemediationReviewSession(items: review.items).run()
    }

    private func run() async -> HostRemediationOutcome {
        guard biometricsAvailable, !items.isEmpty else { return .denied }
        // Make csecd able to front the system biometric sheet and grab focus, even
        // though it is a background agent with no windows of its own.
        let application = NSApplication.shared
        application.setActivationPolicy(.accessory)
        application.activate(ignoringOtherApps: true)

        let reason = Self.reason(for: items.count)
        let approved: Bool = await withCheckedContinuation { continuation in
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics, localizedReason: reason
            ) { success, _ in
                continuation.resume(returning: success)
            }
        }
        // Selection was already fixed by the caller (the terminal picker); approval
        // authorizes exactly that set.
        return approved ? .approved(selectedKeys: items.map(\.key)) : .denied
    }

    /// Value-free, single-line reason naming only the count — the terminal picker
    /// already showed the itemized, deselectable list.
    static func reason(for count: Int) -> String {
        count == 1
            ? "Apply 1 reversible security fix selected in Terminal"
            : "Apply \(count) reversible security fixes selected in Terminal"
    }
}
#endif
