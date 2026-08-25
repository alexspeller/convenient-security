import Foundation
import LocalAuthentication

/// Standalone consent gated by Touch ID. Production access review normally uses
/// the same prompt format with an LAContext paired to its embedded authentication
/// view; injected/headless review and policy mutations use this provider. Every
/// evaluation creates a fresh context, so biometric state is never silently
/// reused to approve another request.
///
/// Fails closed: if biometrics are unavailable or locked out, or the user
/// cancels, consent is denied. This is the real per-secret human gate that
/// replaces `AutoApproveConsent`.
public struct BiometricConsent: ConsentProvider {
    private let policy: LAPolicy

    /// - Parameter allowPasswordFallback: when biometrics can't be evaluated,
    ///   allow the account password (`.deviceOwnerAuthentication`). Off by
    ///   default — Touch ID only.
    public init(allowPasswordFallback: Bool = false) {
        self.policy = allowPasswordFallback
            ? .deviceOwnerAuthentication
            : .deviceOwnerAuthenticationWithBiometrics
    }

    public func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval,
        policySummary: String?
    ) async -> ConsentOutcome {
        let localizedReason = Self.prompt(
            caller: caller,
            references: newReferences,
            reason: reason,
            ttl: ttl,
            policySummary: policySummary
        )
        return await evaluate(localizedReason: localizedReason)
    }

    public func authenticate(reason: String) async -> ConsentOutcome {
        await evaluate(localizedReason: Self.promptSafe(reason))
    }

    private func evaluate(localizedReason: String) async -> ConsentOutcome {
        let context = LAContext()
        context.localizedCancelTitle = "Deny"

        var evaluationError: NSError?
        guard context.canEvaluatePolicy(policy, error: &evaluationError) else {
            let detail = evaluationError.map { String(describing: $0) } ?? "unknown"
            FileHandle.standardError.write(Data(
                "csecd: biometrics unavailable, denying consent (\(detail))\n".utf8
            ))
            return .denied
        }

        let approved: Bool = await withCheckedContinuation { continuation in
            context.evaluatePolicy(policy, localizedReason: localizedReason) { success, _ in
                continuation.resume(returning: success)
            }
        }

        // Hand the just-evaluated context to the resolver so a cold cache or
        // native-store key read can fold into this touch. On a warm agent the
        // context may remain unused. See CacheUnlock / packaging/spike.
        return approved ? .approved(unlock: CacheUnlock(context)) : .denied
    }

    /// Bounded authentication reason. Standalone consent supplies the final
    /// policy-capped duration. Embedded review supplies the requested bound;
    /// its trusted window carries the live selection and the agent applies the
    /// final policy before releasing the evaluated context.
    public static func prompt(
        caller: CallerInfo,
        references: [SecretRef],
        reason: String,
        ttl: TimeInterval,
        policySummary: String? = nil
    ) -> String {
        let list = references.map { "• \($0.displayString)" }.joined(separator: "\n")
        let count = references.count
        let noun = count == 1 ? "secret" : "secrets"
        let policyLine = policySummary.map { "\npolicy: \(promptSafe($0))" } ?? ""
        return """
        grant \(promptSafe(caller.description)) access to \(count) \(noun):
        \(list)
        purpose: \(promptSafe(reason))
        duration: \(formatDuration(ttl))\(policyLine)
        """
    }

    private static func promptSafe(_ value: String) -> String {
        let bidiControls: Set<UInt32> = [
            0x061c, 0x200e, 0x200f,
            0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
            0x2066, 0x2067, 0x2068, 0x2069,
        ]
        return value.unicodeScalars.map { scalar in
            if CharacterSet.controlCharacters.contains(scalar)
                || CharacterSet.newlines.contains(scalar)
                || bidiControls.contains(scalar.value) {
                return "�"
            }
            return String(scalar)
        }.joined()
    }

    public static func formatDuration(_ ttl: TimeInterval) -> String {
        let total = Int(ttl.rounded())
        if total < 60 { return "\(total)s" }
        if total < 3600 { return "\(total / 60) min" }
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        return minutes == 0 ? "\(hours)h" : "\(hours)h \(minutes)m"
    }
}
