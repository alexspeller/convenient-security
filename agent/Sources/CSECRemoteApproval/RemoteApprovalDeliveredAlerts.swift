import Foundation

/// Which of the phone's delivered alerts no longer stand for a request it can
/// answer. An alert left on the lock screen after the Mac decided, withdrew or
/// this phone already answered is an Approve that leads nowhere: the phone
/// clears it once a mailbox read has shown what is still waiting.
public enum RemoteApprovalDeliveredAlerts {
    /// `delivered`: each delivered notification's identifier and the request
    /// its alert is for (nil for one that is not a csec alert). Returns the
    /// identifiers of csec alerts whose request is not in `answerable`,
    /// sorted; anything else is left alone.
    public static func stale(
        _ delivered: [(identifier: String, requestID: String?)],
        answerable: Set<String>
    ) -> [String] {
        delivered.compactMap { alert in
            guard let requestID = alert.requestID, !answerable.contains(requestID) else { return nil }
            return alert.identifier
        }.sorted()
    }
}
