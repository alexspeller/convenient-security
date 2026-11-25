import Foundation

/// What the phone's notification service extension puts on the lock screen
/// for a request alert: the request's own words only once its Mac signature
/// verifies against a Mac this iPhone pinned in this container, "no longer
/// waiting" for a request that is gone, and the push's fixed text (nil) for
/// anything else. Shared so every branch is tested where csec's tests run.
public enum RemoteApprovalAlertVerification {
    /// What reading the alerted request by its ID gave.
    public enum Read: Sendable {
        case found(SignedRemoteApprovalRequest)
        case gone
        case unavailable
    }

    /// What reading `record` by its ID gives: gone when the mailbox no longer
    /// holds it, and gone too while its Mac has gone quiet
    /// (`RemoteApprovalLiveness`), so a quiet request's alerts come off and
    /// its own alert says it is not waiting. A Mac that comes back brings the
    /// card back in the app; the alert stays off.
    public static func read(_ record: RemoteApprovalMailboxRequest?, now: Date) -> Read {
        guard let record, !record.isQuiet(at: now) else { return .gone }
        return .found(record.envelope)
    }

    /// A Mac the iPhone pinned, as the extension reads it.
    public struct PinnedMac: Sendable {
        public let deviceID: String
        public let publicKeyX963: Data
        public let displayName: String
        public let cloudKitContainerIdentifier: String

        public init(deviceID: String, publicKeyX963: Data, displayName: String, cloudKitContainerIdentifier: String) {
            self.deviceID = deviceID
            self.publicKeyX963 = publicKeyX963
            self.displayName = displayName
            self.cloudKitContainerIdentifier = cloudKitContainerIdentifier
        }
    }

    public struct Alert: Equatable, Sendable {
        public let content: RemoteApprovalNotificationText.Content
        /// Groups a Mac's alerts together.
        public let threadIdentifier: String?
        /// Whether the alert may sound and light the screen. An alert for a
        /// request already over is delivered passive and silent: nothing is
        /// waiting, so nothing should buzz, and the next wake clears it.
        public let interrupts: Bool
    }

    /// The words for `read`, or nil to keep the push's fixed text. The Mac's
    /// name is the pinned one, never the one the request claims.
    public static func alert(
        for read: Read,
        pinnedMacs: [PinnedMac],
        containerIdentifier: String,
        nowMilliseconds: UInt64
    ) -> Alert? {
        switch read {
        case .unavailable:
            return nil
        case .gone:
            return Alert(
                content: RemoteApprovalNotificationText.noLongerWaiting,
                threadIdentifier: nil,
                interrupts: false
            )
        case let .found(envelope):
            guard let mac = pinnedMacs.first(where: {
                $0.deviceID == envelope.request.macDeviceID
                    && $0.cloudKitContainerIdentifier == containerIdentifier
            }) else { return nil }
            do {
                try envelope.verify(macPublicKeyX963: mac.publicKeyX963, at: nowMilliseconds)
            } catch {
                return nil
            }
            return Alert(
                content: RemoteApprovalNotificationText.content(for: envelope.request.review, macName: mac.displayName),
                threadIdentifier: mac.deviceID,
                interrupts: true
            )
        }
    }
}
