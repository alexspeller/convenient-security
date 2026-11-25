import Foundation

/// How the phone tells a request a Mac is still waiting on from one a Mac left
/// behind and will not come back to.
///
/// A request has no lifetime: the Mac waits until one surface answers, and
/// withdraws the request when it stops waiting. The one case withdrawal cannot
/// cover is a Mac that stops for good — it crashed and never runs csecd again,
/// or it was wiped or lost — whose request record would otherwise stay in the
/// mailbox, and on the phone, with an Approve button nothing is listening for.
/// So a waiting Mac saves its request record again every
/// `refreshIntervalNanoseconds`, and the phone shows a request only while the
/// mailbox saved it within the last `quietAfterSeconds`.
///
/// This is liveness, not an expiry. Nothing about the request runs out, and a
/// quiet request is not answered, forgotten or deleted: the Mac's pending
/// table still decides what counts, and a Mac that wakes or reconnects saves
/// the record again, which brings its card back. The time compared is the
/// mailbox's own (CloudKit's record modification date) against the phone's
/// clock, so the Mac's clock plays no part, and the margin is wide enough for
/// the ordinary drift between two network-set clocks.
public enum RemoteApprovalLiveness {
    /// How often a waiting Mac saves its request record again. Far below
    /// `quietAfterSeconds`, so a save delayed by throttling (capped at 60 s,
    /// `RemoteApprovalRequester.maximumThrottleDelayNanoseconds`) or a few
    /// failed attempts never makes a waiting request look quiet.
    public static let refreshIntervalNanoseconds: UInt64 = 60_000_000_000

    /// How long a request record may go unsaved before the phone stops
    /// showing it: ten refresh intervals. A Mac asleep or offline for longer
    /// drops its card off the phone until it is back; an answer given
    /// meanwhile could only be read once it was anyway.
    public static let quietAfterSeconds: TimeInterval = 600

    /// Whether a record the mailbox last saved at `savedAt` has gone quiet by
    /// `now`. A mailbox that keeps no save time (nil) never makes a request
    /// quiet, and neither does a save time after `now`: a phone clock behind
    /// the mailbox's is no evidence the Mac stopped.
    public static func isQuiet(savedAt: Date?, now: Date) -> Bool {
        guard let savedAt else { return false }
        return now.timeIntervalSince(savedAt) > quietAfterSeconds
    }
}

/// A request record as the mailbox holds it: the signed envelope, still to be
/// verified, and when the mailbox last saved the record.
public struct RemoteApprovalMailboxRequest: Equatable, Sendable {
    public let envelope: SignedRemoteApprovalRequest
    /// By the mailbox's own clock (CloudKit's `modificationDate`); nil when
    /// the mailbox keeps none. It is not signed, and does not need to be: it
    /// only decides whether the phone shows a request, never whether an
    /// answer counts, and the Mac's signature still binds everything shown.
    public let savedAt: Date?

    public init(envelope: SignedRemoteApprovalRequest, savedAt: Date?) {
        self.envelope = envelope
        self.savedAt = savedAt
    }

    public var requestID: String { envelope.request.requestID }

    /// `RemoteApprovalLiveness.isQuiet` for this record.
    public func isQuiet(at now: Date) -> Bool {
        RemoteApprovalLiveness.isQuiet(savedAt: savedAt, now: now)
    }
}

/// What reading one request record by its ID found.
public enum RemoteApprovalRequestPresence: Equatable, Sendable {
    /// No record: the Mac stopped waiting and deleted it.
    case gone
    /// The record is there, last saved at `savedAt` (nil when the mailbox
    /// keeps no save time).
    case present(savedAt: Date?)

    /// Whether the phone should show the request: present and not quiet.
    public func isWaiting(at now: Date) -> Bool {
        guard case let .present(savedAt) = self else { return false }
        return !RemoteApprovalLiveness.isQuiet(savedAt: savedAt, now: now)
    }
}
