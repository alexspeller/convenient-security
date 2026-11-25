import Foundation
import os
import CSECBuildIdentity

/// The sudo review helper's diagnostic trail. The PAM module points the
/// helper's stderr at /dev/null, so a line written only there is lost under a
/// real sudo; each event here goes to the unified log as well (subsystem
/// `CSECBuildIdentity.identifier`, category `sudo-review`, notice level,
/// which macOS persists), beside the module's own `sudo stage=…` lines in
/// `process-liveness`. The module keeps /dev/null rather than relaying the
/// helper's stderr: a pipe root reads would carry unbounded child text into
/// sudo, and a file root opens in the user's directory invites a symlink.
///
/// Every line is value-free: fixed labels, exit statuses, error codes and the
/// parent's PID. Never the command, working directory, terminal, delegation
/// note or a localized error string. `line` builds only from the cases below,
/// so nothing else can reach the log.
public enum SudoReviewLog {
    /// Why the helper refused to review before anything was drawn.
    public enum Rejection: String, Sendable, CaseIterable {
        case unexpectedArguments = "unexpected-arguments"
        case untrustedParent = "untrusted-parent"
        case stdinNotPipe = "stdin-not-pipe"
        case invalidFrame = "invalid-frame"
        /// The sudo exited before the parent watch could be armed.
        case parentGone = "parent-gone"
    }

    /// Why a panel with no Touch ID to arm ends or waits.
    public enum TouchIDUnavailable: String, Sendable, CaseIterable {
        /// No phone can decide either: no panel, straight to the password.
        case noPhone = "no-phone"
        /// The panel stays up for the phone alone.
        case waitingForPhone = "waiting-for-phone"
        /// The phone turned out unable to decide: the panel closes.
        case phoneCannotDecide = "phone-cannot-decide"
        /// Touch ID came back while the panel was up (the lid opened): the
        /// panel armed it.
        case returned
    }

    /// What became of a pairing a Mac approval of a panel showing the line
    /// asked for.
    public enum Pairing: String, Sendable, CaseIterable {
        case recorded
        case notRecorded = "not-recorded"
        /// Approved too close to the module's deadline to wait on csecd.
        case skippedNearDeadline = "skipped-near-deadline"
    }

    /// Where the panel's terminal line came from (`sudo_terminal`).
    public enum TerminalSource: String, Sendable, CaseIterable {
        /// csecd named the terminal application.
        case csecd
        /// csecd answered without an application (tmux, or no terminal).
        case csecdUnnamed = "csecd-unnamed"
        /// No answer from csecd: the PAM tty alone.
        case ttyOnly = "tty-only"
    }

    /// What became of the helper's report of how its review ended
    /// (`sudo_review_end`).
    public enum EndReport: String, Sendable, CaseIterable {
        case recorded
        case notRecorded = "not-recorded"
        /// The call could outlast the module's deadline.
        case skippedNearDeadline = "skipped-near-deadline"
    }

    public enum Event: Sendable, Equatable {
        case rejected(Rejection, exitStatus: Int32)
        case started(parent: pid_t)
        case delegation(SudoDelegationAnswer.Decision)
        /// Whether the line has a tab title says the Automation lookup
        /// answered; the title itself is never logged.
        case terminal(TerminalSource, titled: Bool)
        case touchIDUnavailable(TouchIDUnavailable)
        /// Touch ID was cancelled while the screen was locked; the panel waits
        /// for unlock. `errorCode` is the `LAError` code, when there was one.
        case lockedCancel(errorCode: Int?)
        /// The armed Touch ID evaluation ended unsuccessfully with the screen
        /// unlocked, and Touch ID was (`touchIDLost`) or was not available
        /// when asked again (`ReviewTouchIDUnavailable.afterFailure`).
        case armedFailure(errorCode: Int?, touchIDLost: Bool)
        /// That failure was a system cancel with Touch ID still here, so the
        /// panel stayed up and renewed Touch ID at once (`renewed`) or waits
        /// to become key (`ReviewFocusRecovery.onSystemCancel`).
        case systemCancel(renewed: Bool)
        case outcome(SudoReviewOutcome)
        case pairing(Pairing)
        case endReport(EndReport)
        /// The sudo that spawned the helper exited during the review.
        case parentExited
        /// The review's deadline passed undecided.
        case deadlinePassed
        case exiting(status: Int32)
    }

    public static let subsystem = CSECBuildIdentity.identifier
    public static let category = "sudo-review"

    /// The one line `event` writes, after the `csec-sudo-review: ` prefix
    /// stderr adds.
    public static func line(_ event: Event) -> String {
        switch event {
        case let .rejected(reason, status):
            return "event=rejected reason=\(reason.rawValue) status=\(status)"
        case let .started(parent):
            return "event=started parent=\(parent)"
        case let .delegation(decision):
            return "event=delegation decision=\(decision.rawValue)"
        case let .terminal(source, titled):
            return "event=terminal source=\(source.rawValue) title=\(titled ? "present" : "absent")"
        case let .touchIDUnavailable(reason):
            return "event=touch-id-unavailable reason=\(reason.rawValue)"
        case let .lockedCancel(code):
            return "event=locked-cancel error=\(code.map(String.init) ?? "none")"
        case let .armedFailure(code, lost):
            return "event=armed-failure error=\(code.map(String.init) ?? "none") touchid=\(lost ? "lost" : "available")"
        case let .systemCancel(renewed):
            return "event=system-cancel action=\(renewed ? "renew" : "wait-for-key")"
        case let .outcome(outcome):
            switch outcome {
            case let .approved(surface):
                return "event=outcome result=approved surface=\(surface.rawValue) status=\(outcome.exitStatus)"
            case let .usePassword(deniedOnPhone):
                let result = deniedOnPhone ? "denied-on-phone" : "use-password"
                return "event=outcome result=\(result) status=\(outcome.exitStatus)"
            }
        case let .pairing(pairing):
            return "event=pairing result=\(pairing.rawValue)"
        case let .endReport(report):
            return "event=end-report result=\(report.rawValue)"
        case .parentExited:
            return "event=parent-exited"
        case .deadlinePassed:
            return "event=deadline-passed"
        case let .exiting(status):
            return "event=exit status=\(status)"
        }
    }

    public static func record(_ event: Event) {
        let line = line(event)
        logger.notice("\(line, privacy: .public)")
        FileHandle.standardError.write(Data("csec-sudo-review: \(line)\n".utf8))
    }

    private static let logger = Logger(subsystem: subsystem, category: category)
}
