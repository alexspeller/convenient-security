import CSECRemoteApproval
import CSECRemoteApprovalCloudKit
import Foundation
import UserNotifications

/// Rewrites a request alert with that request's own words, once its Mac
/// signature has verified against a Mac this iPhone pinned. The push itself
/// carries no request field (`CloudKitRemoteApprovalRelay.makeAlertSubscription`):
/// the extension reads the request from the private database, the same record
/// the app verifies before it shows a card. Anything it cannot read or verify
/// in time leaves the push's fixed text, so nothing unverified reaches the
/// lock screen.
///
/// Each alert also tidies the ones before it (`RemoteApprovalAlertSweep`):
/// iOS runs this extension for every alert, but wakes the app for a settled
/// request only when it chooses to, so this is where a new alert is kept from
/// landing on top of stale ones. Delivered alerts whose request is gone, or
/// whose Mac has gone quiet (`RemoteApprovalLiveness`), come off, and the
/// badge counts the requests still waiting.
final class NotificationService: UNNotificationServiceExtension {
    /// How long the reads may take. iOS gives an extension about 30 seconds
    /// before `serviceExtensionTimeWillExpire`; this leaves room to deliver
    /// after it. The alert's own read and the sweep run side by side, each
    /// within it.
    static let readBoundNanoseconds: UInt64 = 20_000_000_000

    private let delivery = Delivery()
    private var work: Task<Void, Never>?

    override func didReceive(
        _ request: UNNotificationRequest,
        withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
    ) {
        delivery.start(fallback: request.content, handler: contentHandler)
        let requestID = CloudKitRemoteApprovalRelay.alertRequestID(
            fromRemoteNotification: request.content.userInfo
        )
        let delivery = self.delivery
        work = Task {
            let handled = await Self.handle(requestID: requestID)
            delivery.finish(with: handled.alert, badge: handled.badge)
        }
    }

    override func serviceExtensionTimeWillExpire() {
        work?.cancel()
        delivery.finish(with: nil, badge: nil)
    }

    /// The words for the request an alert names — nil to keep the fixed text:
    /// no request named, no pinned Mac, or a request that did not verify or
    /// could not be read in time (`RemoteApprovalAlertVerification`) — and the
    /// badge to set, nil to leave it. Stale delivered alerts are removed here.
    static func handle(requestID: String?) async -> (alert: VerifiedAlert?, badge: Int?) {
        guard let macs = try? PinnedMacRecords.load(), !macs.isEmpty else { return (nil, nil) }
        let pinnedMacs = macs.map {
            RemoteApprovalAlertVerification.PinnedMac(
                deviceID: $0.deviceID,
                publicKeyX963: $0.publicKeyX963,
                displayName: $0.displayName,
                cloudKitContainerIdentifier: $0.cloudKitContainerIdentifier
            )
        }
        let relay = CloudKitRemoteApprovalRelay()
        let center = UNUserNotificationCenter.current()
        let delivered = await center.deliveredNotifications()
            .sorted { $0.date > $1.date }
            .map {
                (
                    identifier: $0.request.identifier,
                    requestID: CloudKitRemoteApprovalRelay.alertRequestID(
                        fromRemoteNotification: $0.request.content.userInfo
                    )
                )
            }
        let others = RemoteApprovalAlertSweep.requestIDsToRead(current: nil, delivered: delivered)
            .filter { $0 != requestID }

        async let ownRead = read(requestID, from: relay)
        async let swept = sweepReads(others, from: relay)
        let read = await ownRead
        var sweep = await swept
        if let requestID { sweep.reads[requestID] = read }

        let now = currentTimeMilliseconds()
        let containerIdentifier = CloudKitRemoteApprovalRelay.defaultContainerIdentifier
        let alert = requestID == nil ? nil : RemoteApprovalAlertVerification.alert(
            for: read,
            pinnedMacs: pinnedMacs,
            containerIdentifier: containerIdentifier,
            nowMilliseconds: now
        )
        let plan = RemoteApprovalAlertSweep.plan(
            delivered: delivered,
            reads: sweep.reads,
            listed: sweep.listed,
            pinnedMacs: pinnedMacs,
            containerIdentifier: containerIdentifier,
            nowMilliseconds: now
        )
        if !plan.staleIdentifiers.isEmpty {
            center.removeDeliveredNotifications(withIdentifiers: plan.staleIdentifiers)
        }
        return (alert, plan.badge)
    }

    /// One request read by its ID, within the bound.
    private static func read(
        _ requestID: String?,
        from relay: CloudKitRemoteApprovalRelay
    ) async -> RemoteApprovalAlertVerification.Read {
        guard let requestID else { return .unavailable }
        return await RemoteApprovalBound.firstAnswer(
            within: readBoundNanoseconds,
            otherwise: RemoteApprovalAlertVerification.Read.unavailable
        ) {
            await readRequest(requestID, from: relay)
        }
    }

    private static func readRequest(
        _ requestID: String,
        from relay: CloudKitRemoteApprovalRelay
    ) async -> RemoteApprovalAlertVerification.Read {
        do {
            return RemoteApprovalAlertVerification.read(
                try await relay.requestRecord(requestID: requestID),
                now: Date()
            )
        } catch {
            return .unavailable
        }
    }

    /// The other alerts' requests, each read by its ID, and the mailbox
    /// query, side by side within the bound. Out of time, nothing is known:
    /// no alert is removed and the badge is left as it is.
    private static func sweepReads(
        _ requestIDs: [String],
        from relay: CloudKitRemoteApprovalRelay
    ) async -> SweepReads {
        await RemoteApprovalBound.firstAnswer(
            within: readBoundNanoseconds,
            otherwise: SweepReads(reads: [:], listed: nil)
        ) {
            async let listed = try? relay.pendingRequestRecords()
            let reads = await withTaskGroup(
                of: (String, RemoteApprovalAlertVerification.Read).self
            ) { group in
                for requestID in requestIDs {
                    group.addTask { (requestID, await readRequest(requestID, from: relay)) }
                }
                var reads: [String: RemoteApprovalAlertVerification.Read] = [:]
                for await (requestID, read) in group { reads[requestID] = read }
                return reads
            }
            return SweepReads(reads: reads, listed: await listed)
        }
    }
}

private struct SweepReads: Sendable {
    var reads: [String: RemoteApprovalAlertVerification.Read]
    var listed: [RemoteApprovalMailboxRequest]?
}

typealias VerifiedAlert = RemoteApprovalAlertVerification.Alert

/// Hands iOS exactly one content: the verified words and the badge if they
/// are ready, the push's own otherwise, whichever of the reads and the
/// extension's deadline comes first.
private final class Delivery: @unchecked Sendable {
    private let lock = NSLock()
    private var handler: ((UNNotificationContent) -> Void)?
    private var fallback: UNNotificationContent?

    func start(fallback: UNNotificationContent, handler: @escaping (UNNotificationContent) -> Void) {
        lock.lock()
        self.fallback = fallback
        self.handler = handler
        lock.unlock()
    }

    func finish(with alert: VerifiedAlert?, badge: Int?) {
        lock.lock()
        let handler = self.handler
        let fallback = self.fallback
        self.handler = nil
        lock.unlock()
        guard let handler, let fallback else { return }
        guard alert != nil || badge != nil,
              let content = fallback.mutableCopy() as? UNMutableNotificationContent else {
            handler(fallback)
            return
        }
        if let badge {
            content.badge = NSNumber(value: badge)
        }
        if let alert {
            content.title = alert.content.title
            content.subtitle = alert.content.subtitle
            content.body = alert.content.body
            if let threadIdentifier = alert.threadIdentifier {
                content.threadIdentifier = threadIdentifier
            }
            if !alert.interrupts {
                content.sound = nil
                content.interruptionLevel = .passive
            }
        }
        handler(content)
    }
}
