import Foundation
import LocalAuthentication

/// Why a bare Touch ID sheet (`BiometricConsent`) ended without approving,
/// value-free: the `LAError` code, how long the sheet was up, and whether
/// csecd had shown it again after macOS dismissed it. A session that sees
/// "Touch ID was not given" can then tell the human's Deny from a sheet
/// macOS took down and from a finger Touch ID did not recognise, and so
/// whether asking again is worth the human's time.
public struct ConsentRefusal: Sendable, Equatable {
    public enum Cause: String, Sendable, CaseIterable {
        /// The sheet's Deny button (`LAError.userCancel`): the human refusing.
        case userCancel = "user_cancel"
        /// macOS took the sheet down unanswered (`systemCancel`): another
        /// window or Touch ID prompt took over.
        case systemCancel = "system_cancel"
        /// The sheet's context was invalidated (`appCancel`) while its
        /// request was still there.
        case appCancel = "app_cancel"
        /// Touch ID did not recognise the finger, up to the system's limit of
        /// tries (`authenticationFailed`).
        case authenticationFailed = "auth_failed"
        /// "Use Password…" (`userFallback`); these sheets take Touch ID only.
        case userFallback = "user_fallback"
        /// Too many failed tries locked Touch ID (`biometryLockout`).
        case biometryLockout = "biometry_lockout"
        /// Touch ID could not be used at all: unavailable, not enrolled, no
        /// login password, or the sensor disconnected.
        case touchIDUnavailable = "no_touch_id"
        /// macOS would not show the sheet (`notInteractive`).
        case notInteractive = "not_interactive"
        /// The request went away (its connection closed) while its sheet
        /// waited or was up.
        case requesterGone = "requester_gone"
        /// No sheet was shown: csec's approval queue could not be taken.
        case notShown = "not_shown"
        /// csec's own panel (`SettingsChangeConsent`) ended without an
        /// approval and not by the human's Deny: Touch ID failed or was
        /// cancelled under it, or the panel could not be shown. csecd's log
        /// has the `LAError`.
        case panelFailed = "panel_failed"
        /// A consent provider that does not say why (an injected one).
        case unexplained
        /// Any other `LAError`; `errorCode` has it.
        case other = "la_error"
    }

    public var cause: Cause
    /// The `LAError` code the evaluation (or the availability check) ended
    /// with, when there was one.
    public var errorCode: Int?
    /// From the sheet's last presentation to its end; nil when no sheet was
    /// up.
    public var shownFor: Duration?
    /// macOS had dismissed the sheet once and csecd showed it again
    /// (`BiometricConsent.next`).
    public var shownAgain: Bool
    /// The prompt was csec's own panel, not Apple's bare sheet.
    public var onPanel: Bool
    /// The human's Deny came from the paired iPhone's copy of a mirrored
    /// review, not this Mac's panel.
    public var onPhone: Bool

    public init(
        cause: Cause, errorCode: Int? = nil, shownFor: Duration? = nil, shownAgain: Bool = false,
        onPanel: Bool = false, onPhone: Bool = false
    ) {
        self.cause = cause
        self.errorCode = errorCode
        self.shownFor = shownFor
        self.shownAgain = shownAgain
        self.onPanel = onPanel
        self.onPhone = onPhone
    }

    /// How csec's panel ended without an approval. Deny, Escape and closing
    /// the window are the human refusing; a request that went away, however
    /// it went, is `requesterGone`; everything else is the panel's failure.
    public init(panelDenial reason: AccessPolicyDenialReason) {
        switch reason {
        case let .human(decidedAt, surface, shownAt):
            self.init(
                cause: .userCancel, shownFor: shownAt.map { $0.duration(to: decidedAt) }, onPanel: true,
                onPhone: surface == .phone
            )
        case .requesterGone, .withdrawn, .timedOut:
            self.init(cause: .requesterGone, onPanel: true)
        case .authenticationFailed:
            self.init(cause: .panelFailed, onPanel: true)
        }
    }

    /// The refusal an `LAError` code means.
    public init(errorCode: Int?, shownFor: Duration? = nil, shownAgain: Bool = false) {
        self.init(cause: Self.cause(errorCode: errorCode), errorCode: errorCode, shownFor: shownFor, shownAgain: shownAgain)
    }

    public static let unexplained = ConsentRefusal(cause: .unexplained)

    /// What an `LAError` code says about how the sheet ended. A nil code (an
    /// evaluation that failed without an error) says nothing, so it is
    /// `other`.
    public static func cause(errorCode: Int?) -> Cause {
        guard let errorCode, let code = LAError.Code(rawValue: errorCode) else { return .other }
        switch code {
        case .userCancel: return .userCancel
        case .systemCancel: return .systemCancel
        case .appCancel: return .appCancel
        case .authenticationFailed: return .authenticationFailed
        case .userFallback: return .userFallback
        case .biometryLockout: return .biometryLockout
        case .biometryNotAvailable, .biometryNotEnrolled, .passcodeNotSet, .biometryDisconnected, .biometryNotPaired:
            return .touchIDUnavailable
        case .notInteractive: return .notInteractive
        default: return .other
        }
    }

    /// Only the sheet's Deny is the human refusing. Everything else is the
    /// system's, or the human's failed attempt, and says nothing about what
    /// they wanted.
    public var isHumanRefusal: Bool { cause == .userCancel }

    /// Why, in words, for `csec setup` and the log's detail.
    public var why: String {
        switch cause {
        case .userCancel: return onPhone ? "you pressed Deny on the iPhone" : "you pressed Deny"
        case .systemCancel: return "macOS dismissed the sheet before it was answered (another window or Touch ID prompt took over)"
        case .appCancel: return "the sheet was withdrawn before it was answered"
        case .authenticationFailed: return "Touch ID did not recognise the finger"
        case .userFallback: return "you chose the password, which this sheet does not take"
        case .biometryLockout: return "Touch ID is locked after too many tries; unlock this Mac with its password to reset it"
        case .touchIDUnavailable: return "Touch ID is not available"
        case .notInteractive: return "macOS would not show the sheet"
        case .requesterGone: return "the request went away"
        case .notShown: return "no sheet could be shown (csec's approval queue was unavailable)"
        case .panelFailed: return "Touch ID ended without approving, or the panel could not be shown (csecd's log says which)"
        case .unexplained: return "the consent provider gave no reason"
        case .other: return "Touch ID ended with error \(errorCode.map(String.init) ?? "unknown")"
        }
    }

    /// `why`, with how long the sheet was up and whether it was a second
    /// showing.
    public var summary: String {
        var parts = [why]
        if let shownFor {
            let seconds = Double(shownFor.components.seconds) + Double(shownFor.components.attoseconds) / 1e18
            parts.append("the \(onPanel ? "panel" : "sheet") was up " + String(format: "%.1fs", seconds))
        }
        if shownAgain {
            parts.append("it had been shown again after macOS dismissed it")
        }
        return parts.joined(separator: "; ")
    }

    // MARK: - The decision log

    /// The record's outcome. `denied` is kept for the human's own refusal.
    public var logOutcome: DecisionLogRecord.Outcome {
        switch cause {
        case .userCancel: return .denied
        case .requesterGone: return .requesterGone
        default: return .authenticationFailed
        }
    }

    public var logDecider: DecisionLogRecord.Decider? {
        guard isHumanRefusal else { return nil }
        return onPhone ? .humanPhone : .humanLocal
    }

    /// The record's cause; an unmapped `LAError` carries its code.
    public var logCause: String {
        if cause == .other, let errorCode { return "la_error_\(errorCode)" }
        return cause.rawValue
    }

    public var ttdMs: Int? {
        shownFor.map { Int($0.components.seconds) * 1_000 + Int($0.components.attoseconds / 1_000_000_000_000_000) }
    }
}

/// What a bare Touch ID sheet answered, with the reason when it did not
/// approve. `ConsentProvider.authenticateExplaining` returns it.
public enum ConsentAnswer: Sendable {
    case approved(unlock: CacheUnlock?)
    case refused(ConsentRefusal)

    public var outcome: ConsentOutcome {
        switch self {
        case let .approved(unlock): return .approved(unlock: unlock)
        case .refused: return .denied
        }
    }

    public var refusal: ConsentRefusal? {
        if case let .refused(refusal) = self { return refusal }
        return nil
    }
}
