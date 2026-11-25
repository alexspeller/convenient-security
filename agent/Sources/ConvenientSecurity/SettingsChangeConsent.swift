import Foundation

/// Consent that shows a change to csec's own settings in csecd's panel (the
/// secret-access surface's settings layout, `SettingsChangeReviewDetails`)
/// instead of Apple's bare Touch ID sheet, and leaves every other consent to
/// `underlying`.
///
/// The bare sheet is macOS's: csec cannot hold its Deny back or keep the
/// keyboard off it, so a sheet that came up mid-sentence took the next Space
/// as a refusal. The panel has the typing guard every csec approval has
/// (`PromptKeyboardSink`, `PromptInteractionGrace`), and the focus renewal,
/// unlock re-present and requester checks that come with it. Touch ID is
/// still the whole decision, and this Mac's alone for every settings change
/// but one: the rules- and hooks-changed acknowledgement csecd raises for a
/// request carries `phoneOperationDigest`, so through a mirroring reviewer
/// the paired phone's Face ID can decide it too (av-rcqg). Every other change
/// is `macOnly`, which the mirror keeps on this Mac.
public struct SettingsChangeConsent: ConsentProvider {
    private let underlying: any ConsentProvider
    private let review: any PolicyReviewProvider

    /// `review` is csecd's queued reviewer, so the panel takes its turn with
    /// every other approval; `underlying` is the queued bare sheet. Neither
    /// wraps the other, so neither waits on a turn the other holds. Only a
    /// mirroring `review` (`MirroredPolicyReview`) lets the phone decide.
    public init(underlying: any ConsentProvider, review: any PolicyReviewProvider) {
        self.underlying = underlying
        self.review = review
    }

    public func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String,
        ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        await underlying.requestConsent(
            caller: caller, newReferences: newReferences, reason: reason, ttl: ttl, policySummary: policySummary)
    }

    public func authenticate(reason: String) async -> ConsentOutcome {
        await underlying.authenticate(reason: reason)
    }

    public func authenticateExplaining(reason: String) async -> ConsentAnswer {
        await underlying.authenticateExplaining(reason: reason)
    }

    public func authenticateSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> ConsentAnswer {
        await decideSettingsChange(change, caller: caller, reason: reason).answer
    }

    public func decideSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> SettingsChangeDecision {
        let shown = AccessPolicyReview.settingsChange(caller: caller, change: change)
        let decision: SettingsChangeDecision
        switch await review.reviewAccess(shown) {
        case let .approved(approval):
            guard let session = approval.authenticationSession else {
                // A reviewer with no panel (an injected one) approved only
                // what it was shown; the touch is still asked for.
                return SettingsChangeDecision(answer: await underlying.authenticateExplaining(reason: reason))
            }
            switch await session.completeAfterPolicyApproval(policySummary: "settings change") {
            case let .approved(unlock):
                // A Mac approval's touch comes back as its unlock, for the
                // caller to use or invalidate; a phone approval brings none,
                // as a settings change needs no unlock.
                decision = SettingsChangeDecision(answer: .approved(unlock: unlock), decidedOn: approval.decidedOn)
            // The approval had succeeded: only the request going away, or the
            // other surface's decision winning, ends it here.
            case .denied:
                decision = SettingsChangeDecision(
                    answer: .refused(ConsentRefusal(cause: .requesterGone, onPanel: true)))
            }
        case let .denied(reason):
            decision = SettingsChangeDecision(answer: .refused(ConsentRefusal(panelDenial: reason)))
        }
        if let refusal = decision.answer.refusal {
            FileHandle.standardError.write(Data(
                "csecd: settings-change panel ended without approval (\(refusal.logCause)): \(refusal.summary)\n".utf8
            ))
        }
        return decision
    }

    public func settingsChangeReachesPhone(_ change: SettingsChangeReviewDetails, caller: CallerInfo) async -> Bool {
        guard change.phoneOperationDigest != nil else { return false }
        let shown = AccessPolicyReview.settingsChange(caller: caller, change: change)
        return await review.approvalReach(for: shown).place == .macOrPhone
    }
}

public extension ConsentProvider {
    /// The touch for a setup step csecd does at `caller`'s request — a
    /// backup, a restore, pairing a phone, a machine identity, removing an
    /// SSH key or an automation job, deleting stored files, the uninstall
    /// cleanup — in csecd's settings panel when this consent has one.
    /// `caller.terminal` is the tab the panel names; a provider with no panel
    /// shows the same change as one line naming it.
    func approveSettingsChange(_ change: SettingsChangeReviewDetails, caller: CallerInfo) async -> ConsentOutcome {
        let reason = ([change.title] + change.changes).joined(separator: " — ")
            + " — from \(ReviewDisplay.sanitized(caller.terminalSummary))"
        return await authenticateSettingsChange(change, caller: caller, reason: reason).outcome
    }
}
