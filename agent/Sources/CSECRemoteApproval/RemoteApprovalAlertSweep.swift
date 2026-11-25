import Foundation

/// What the notification service extension tidies each time it handles an
/// alert, so a new alert never lands on top of stale ones even when iOS does
/// not wake the app for a settled request: the delivered csec alerts whose
/// request is gone come off, and the badge counts the requests still waiting.
/// Shared so every branch is tested where csec's tests run.
public enum RemoteApprovalAlertSweep {
    /// How many delivered alerts' requests one sweep reads by ID, newest
    /// first. The app follows as many alerted requests.
    public static let maximumReads = 16

    public struct Plan: Equatable, Sendable {
        /// Delivered notifications to remove, sorted.
        public let staleIdentifiers: [String]
        /// The badge to set, or nil to leave it as it is.
        public let badge: Int?

        public init(staleIdentifiers: [String], badge: Int?) {
            self.staleIdentifiers = staleIdentifiers
            self.badge = badge
        }
    }

    /// The requests to read by ID: `current`'s (the alert being handled),
    /// then each delivered csec alert's, newest first, without repeats, at
    /// most `maximumReads` in all. `delivered` is newest first.
    public static func requestIDsToRead(
        current: String?,
        delivered: [(identifier: String, requestID: String?)]
    ) -> [String] {
        var seen = Set<String>()
        var ordered: [String] = []
        for requestID in [current] + delivered.map(\.requestID) {
            guard let requestID, ordered.count < maximumReads,
                  seen.insert(requestID).inserted else { continue }
            ordered.append(requestID)
        }
        return ordered
    }

    /// `delivered`: each delivered notification's identifier and the request
    /// its alert is for (nil for one that is not a csec alert). `reads`: what
    /// reading each request by its ID gave
    /// (`RemoteApprovalAlertVerification.read(_:now:)`, so a quiet request
    /// reads as gone). `listed`: the mailbox query's records, nil when the
    /// query failed.
    ///
    /// An alert comes off only when its request read as gone: one whose read
    /// failed, or that was not read, stays. The badge is the number of
    /// distinct requests, listed or read, that verify against a pinned Mac in
    /// this container and whose Mac has not gone quiet
    /// (`RemoteApprovalLiveness`) — what the app's list would show — and is
    /// set only when the query answered, so a failed read never zeroes it.
    public static func plan(
        delivered: [(identifier: String, requestID: String?)],
        reads: [String: RemoteApprovalAlertVerification.Read],
        listed: [RemoteApprovalMailboxRequest]?,
        pinnedMacs: [RemoteApprovalAlertVerification.PinnedMac],
        containerIdentifier: String,
        nowMilliseconds: UInt64
    ) -> Plan {
        let stale = delivered.compactMap { alert -> String? in
            guard let requestID = alert.requestID,
                  case .gone? = reads[requestID] else { return nil }
            return alert.identifier
        }.sorted()
        guard let listed else { return Plan(staleIdentifiers: stale, badge: nil) }
        let now = Date(timeIntervalSince1970: TimeInterval(nowMilliseconds) / 1_000)
        var candidates = listed.filter { !$0.isQuiet(at: now) }.map(\.envelope)
        for read in reads.values {
            if case let .found(envelope) = read { candidates.append(envelope) }
        }
        var waiting = Set<String>()
        for envelope in candidates where reads[envelope.request.requestID].map(isGone) != true {
            let verified = RemoteApprovalAlertVerification.alert(
                for: .found(envelope),
                pinnedMacs: pinnedMacs,
                containerIdentifier: containerIdentifier,
                nowMilliseconds: nowMilliseconds
            ) != nil
            if verified { waiting.insert(envelope.request.requestID) }
        }
        return Plan(staleIdentifiers: stale, badge: waiting.count)
    }

    private static func isGone(_ read: RemoteApprovalAlertVerification.Read) -> Bool {
        if case .gone = read { return true }
        return false
    }
}
