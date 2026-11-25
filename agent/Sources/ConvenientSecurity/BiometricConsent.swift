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
/// replaces `AutoApproveConsent`. A refusal keeps its `LAError`
/// (`ConsentRefusal`), and a sheet macOS dismissed unanswered is shown once
/// more before it counts as one.
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
        ttl: TimeInterval?,
        policySummary: String?
    ) async -> ConsentOutcome {
        let localizedReason = Self.prompt(
            caller: caller,
            references: newReferences,
            reason: reason,
            ttl: ttl,
            policySummary: policySummary
        )
        return await evaluate(localizedReason: localizedReason).outcome
    }

    public func authenticate(reason: String) async -> ConsentOutcome {
        await authenticateExplaining(reason: reason).outcome
    }

    public func authenticateExplaining(reason: String) async -> ConsentAnswer {
        await evaluate(localizedReason: ReviewDisplay.sanitized(reason))
    }

    /// What to do once a sheet has ended without approving.
    public enum Next: Sendable, Equatable {
        /// The screen is locked: the human could not have seen or dismissed
        /// the sheet (`ScreenLockState`). Wait for unlock and show it again.
        case waitForUnlock
        /// macOS took the sheet down unanswered while the human may well be
        /// at the Mac: show it again, once.
        case showAgain
        /// Fail closed with this refusal.
        case refuse
    }

    /// The rule, as one pure function. A locked screen always waits, as
    /// before. Unlocked, only a dismissal the human did not make
    /// (`systemCancel`, or `appCancel` while the request is still there) is
    /// shown again, and only once, so a sheet something keeps taking down
    /// ends rather than flickering back. Deny, a finger not recognised and
    /// every Touch ID failure refuse at once.
    public static func next(after cause: ConsentRefusal.Cause, screenLocked: Bool, shownAgain: Bool) -> Next {
        if ScreenLockState.action(screenLocked: screenLocked) == .waitForUnlock { return .waitForUnlock }
        switch cause {
        case .systemCancel, .appCancel: return shownAgain ? .refuse : .showAgain
        default: return .refuse
        }
    }

    private func evaluate(localizedReason: String) async -> ConsentAnswer {
        // Retry loop for the away-from-Mac case: a prompt cancelled while the
        // screen is locked is not a denial (the human never saw it), so wait for
        // unlock and re-present rather than failing closed. See ScreenLockState.
        // A sheet macOS dismissed with the screen unlocked is shown once more
        // (`next`). Every other end is a refusal that keeps its `LAError`, so
        // the caller can say which it was.
        var shownAgain = false
        while true {
            if Task.isCancelled { return .refused(ConsentRefusal(cause: .requesterGone, shownAgain: shownAgain)) }
            let context = LAContext()
            context.localizedCancelTitle = "Deny"

            var evaluationError: NSError?
            guard context.canEvaluatePolicy(policy, error: &evaluationError) else {
                let detail = evaluationError.map { String(describing: $0) } ?? "unknown"
                FileHandle.standardError.write(Data(
                    "csecd: biometrics unavailable, denying consent (\(detail))\n".utf8
                ))
                let code = evaluationError?.domain == LAErrorDomain ? evaluationError?.code : nil
                var refusal = ConsentRefusal(errorCode: code, shownAgain: shownAgain)
                if refusal.cause == .other { refusal.cause = .touchIDUnavailable }
                return .refused(refusal)
            }

            let shownAt = ContinuousClock.now
            let (approved, errorCode): (Bool, Int?) = await withTaskCancellationHandler {
                await withCheckedContinuation { continuation in
                    context.evaluatePolicy(policy, localizedReason: localizedReason) { success, error in
                        continuation.resume(returning: (success, (error as? LAError)?.code.rawValue))
                    }
                    if Task.isCancelled { context.invalidate() }
                }
            } onCancel: {
                context.invalidate()
            }
            let shownFor = ContinuousClock.now - shownAt

            if Task.isCancelled {
                return .refused(ConsentRefusal(
                    cause: .requesterGone, errorCode: errorCode, shownFor: shownFor, shownAgain: shownAgain
                ))
            }

            if approved {
                // Hand the just-evaluated context to the resolver so a cold cache
                // or native-store key read can fold into this touch. On a warm
                // agent the context may remain unused. See CacheUnlock.
                return .approved(unlock: CacheUnlock(context))
            }

            let refusal = ConsentRefusal(errorCode: errorCode, shownFor: shownFor, shownAgain: shownAgain)
            switch Self.next(after: refusal.cause, screenLocked: ScreenLockState.isScreenLocked, shownAgain: shownAgain) {
            case .waitForUnlock:
                FileHandle.standardError.write(Data(
                    ("csecd: biometric prompt cancelled while screen locked (\(refusal.logCause)); "
                        + "waiting for unlock to re-present\n").utf8
                ))
                context.invalidate()
                await ScreenLockState.waitForUnlock()
                if Task.isCancelled {
                    return .refused(ConsentRefusal(cause: .requesterGone, shownAgain: shownAgain))
                }
            case .showAgain:
                FileHandle.standardError.write(Data(
                    "csecd: Touch ID sheet ended unanswered (\(refusal.logCause)) with the screen unlocked; showing it again once\n".utf8
                ))
                context.invalidate()
                shownAgain = true
            case .refuse:
                FileHandle.standardError.write(Data(
                    "csecd: Touch ID sheet ended without approval (\(refusal.logCause)): \(refusal.summary)\n".utf8
                ))
                return .refused(refusal)
            }
        }
    }

    /// Bounded authentication reason. Standalone consent supplies the final
    /// policy-capped duration. Embedded review supplies the requested bound;
    /// its trusted window carries the live selection and the agent applies the
    /// final policy before releasing the evaluated context.
    public static func prompt(
        caller: CallerInfo,
        references: [SecretRef],
        reason: String,
        ttl: TimeInterval?,
        policySummary: String? = nil
    ) -> String {
        let list = references.map { "• \($0.displayString)" }.joined(separator: "\n")
        let count = references.count
        let noun = count == 1 ? "secret" : "secrets"
        let policyLine = policySummary.map { "\npolicy: \(ReviewDisplay.sanitized($0))" } ?? ""
        return """
        grant \(ReviewDisplay.sanitized(caller.description)) access to \(count) \(noun):
        \(list)
        purpose: \(ReviewDisplay.sanitized(reason))
        terminal: \(ReviewDisplay.sanitized(caller.terminalSummary))
        duration: \(formatDuration(ttl))\(policyLine)
        """
    }

    public static func formatDuration(_ ttl: TimeInterval?) -> String {
        guard let ttl else { return "no time limit" }
        let total = Int(ttl.rounded())
        if total < 60 { return "\(total)s" }
        if total < 3600 { return "\(total / 60) min" }
        let hours = total / 3600
        let minutes = (total % 3600) / 60
        return minutes == 0 ? "\(hours)h" : "\(hours)h \(minutes)m"
    }
}
