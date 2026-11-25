import ConvenientSecurity
import Darwin
import Foundation
import OSLog

// The sudo review helper's diagnostic trail (csec-kua.11). Under PAM the
// helper's stderr is /dev/null, so its lines must reach the unified log, and
// every one must stay value-free: fixed labels and numbers only.

func sudoReviewLogTests() {
    print("\n# Sudo review trail: value-free lines that reach the unified log")
    let events: [SudoReviewLog.Event] =
        SudoReviewLog.Rejection.allCases.map { .rejected($0, exitStatus: 64) }
        + SudoReviewLog.TouchIDUnavailable.allCases.map { .touchIDUnavailable($0) }
        + SudoReviewLog.Pairing.allCases.map { .pairing($0) }
        + SudoReviewLog.EndReport.allCases.map { .endReport($0) }
        + SudoReviewLog.TerminalSource.allCases.flatMap { [.terminal($0, titled: true), .terminal($0, titled: false)] }
        + [SudoDelegationAnswer.Decision.approved, .declined, .notApplicable].map { .delegation($0) }
        + [
            .started(parent: 4242), .lockedCancel(errorCode: nil), .lockedCancel(errorCode: -4),
            .armedFailure(errorCode: -4, touchIDLost: true), .armedFailure(errorCode: nil, touchIDLost: false),
            .systemCancel(renewed: true), .systemCancel(renewed: false),
            .outcome(.approved(on: .mac)), .outcome(.approved(on: .phone)),
            .outcome(.usePassword(deniedOnPhone: false)), .outcome(.usePassword(deniedOnPhone: true)),
            .parentExited, .deadlinePassed, .exiting(status: 75),
        ]
    let shape = #/event=[a-z-]+( [a-z]+=[a-z0-9_-]+)*/#
    let lines = events.map(SudoReviewLog.line)
    check(lines.allSatisfy { $0.wholeMatch(of: shape) != nil },
          "sudo trail: every event is fixed lowercase labels and numbers")
    check(Set(lines).count == lines.count, "sudo trail: no two events share a line")

    check(SudoReviewLog.line(.outcome(.approved(on: .phone)))
            == "event=outcome result=approved surface=phone status=0"
            && SudoReviewLog.line(.outcome(.usePassword(deniedOnPhone: true)))
            == "event=outcome result=denied-on-phone status=69"
            && SudoReviewLog.line(.outcome(.usePassword(deniedOnPhone: false)))
            == "event=outcome result=use-password status=69",
          "sudo trail: an outcome names how it was decided and the status the module sees")
    check(SudoReviewLog.line(.rejected(.untrustedParent, exitStatus: 69))
            == "event=rejected reason=untrusted-parent status=69"
            && SudoReviewLog.line(.delegation(.notApplicable)) == "event=delegation decision=not_applicable"
            && SudoReviewLog.line(.lockedCancel(errorCode: -4)) == "event=locked-cancel error=-4"
            && SudoReviewLog.line(.lockedCancel(errorCode: nil)) == "event=locked-cancel error=none",
          "sudo trail: refusals, delegation and a locked cancel carry their label or code")
    check(SudoReviewLog.line(.endReport(.recorded)) == "event=end-report result=recorded"
            && SudoReviewLog.line(.endReport(.skippedNearDeadline)) == "event=end-report result=skipped-near-deadline",
          "sudo trail: the end report says whether csecd logged the review's end")
    check(SudoReviewLog.line(.terminal(.csecd, titled: true)) == "event=terminal source=csecd title=present"
            && SudoReviewLog.line(.terminal(.ttyOnly, titled: false)) == "event=terminal source=tty-only title=absent",
          "sudo trail: the terminal line names its source and whether a title came back, never the title")
    check(SudoReviewLog.line(.armedFailure(errorCode: -6, touchIDLost: true))
            == "event=armed-failure error=-6 touchid=lost"
            && SudoReviewLog.line(.armedFailure(errorCode: -1, touchIDLost: false))
            == "event=armed-failure error=-1 touchid=available",
          "sudo trail: a failed armed evaluation carries its code and whether Touch ID was then gone")
    check(SudoReviewLog.line(.systemCancel(renewed: true)) == "event=system-cancel action=renew"
            && SudoReviewLog.line(.systemCancel(renewed: false)) == "event=system-cancel action=wait-for-key",
          "sudo trail: a system cancel says whether the panel renewed Touch ID or waits to become key")

    // A unique parent PID marks this run's line among the process's entries.
    let marker = pid_t(Int32.random(in: 1_000_000...2_000_000))
    let since = Date().addingTimeInterval(-1)
    SudoReviewLog.record(.started(parent: marker))
    let expected = SudoReviewLog.line(.started(parent: marker))
    var found: [OSLogEntryLog] = []
    if let store = try? OSLogStore(scope: .currentProcessIdentifier),
        let entries = try? store.getEntries(at: store.position(date: since))
    {
        found = entries.compactMap { $0 as? OSLogEntryLog }.filter {
            $0.subsystem == SudoReviewLog.subsystem && $0.category == SudoReviewLog.category
        }
    }
    check(found.contains { $0.composedMessage == expected && $0.level == .notice },
          "sudo trail: a recorded event reaches the unified log whole, at notice level, unredacted")
}
