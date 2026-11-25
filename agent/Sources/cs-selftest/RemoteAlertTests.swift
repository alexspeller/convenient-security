import CloudKit
import CryptoKit
import CSECRemoteApproval
import CSECRemoteApprovalCloudKit
import ConvenientSecurity
import Foundation
import CSECBuildIdentity

/// The phone's alert: raised after the request is already on the phone, once
/// csecd's gate opens, and never for a request answered or withdrawn first;
/// the gate's timing; and the words the notification service extension shows.
func remoteAlertTests() async {
    print("\n# Remote approval alerts (timing, gate, notification text; synthetic keys only)")
    await alertWaitsForTheGate()
    await alertNeverRaisedForARequestDecidedFirst()
    await alertRetriesLikeTheRequest()
    await alertTimingGate()
    alertNotificationText()
    alertRecordNames()
    alertPushParsing()
    alertStaleDeliveredAlerts()
    alertExtensionVerification()
    alertExtensionSweep()
}

/// What the notification service extension puts on the lock screen: the
/// request's words only for a request whose signature verifies against the
/// pinned Mac it names, in this container.
private func alertExtensionVerification() {
    typealias Verification = RemoteApprovalAlertVerification
    let macKey = P256.Signing.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()
    let container = CSECBuildIdentity.cloudKitContainer
    let pinned = Verification.PinnedMac(
        deviceID: macDeviceID, publicKeyX963: macKey.publicKey.x963Representation,
        displayName: "Pinned Mac", cloudKitContainerIdentifier: container
    )
    let review = v3AccessReviewFixture(withRestore: false)
    let now = currentTimeMilliseconds()
    func signed(by key: P256.Signing.PrivateKey, macDeviceID: String, claimedName: String = "Claimed Name",
                createdAt: UInt64 = now) -> SignedRemoteApprovalRequest? {
        try? .signed(
            RemoteApprovalRequest(macDeviceID: macDeviceID, macDeviceName: claimedName,
                                  createdAtMilliseconds: createdAt, review: review),
            by: key
        )
    }
    guard let good = signed(by: macKey, macDeviceID: macDeviceID),
          let forged = signed(by: P256.Signing.PrivateKey(), macDeviceID: macDeviceID),
          let otherMac = signed(by: macKey, macDeviceID: UUID().uuidString.lowercased()),
          let future = signed(by: macKey, macDeviceID: macDeviceID, createdAt: now + 3_600_000) else {
        check(false, "alerts: the extension fixtures sign")
        return
    }
    func alert(_ read: Verification.Read, macs: [Verification.PinnedMac] = [pinned]) -> Verification.Alert? {
        Verification.alert(for: read, pinnedMacs: macs, containerIdentifier: container, nowMilliseconds: now)
    }
    let verified = alert(.found(good))
    check(verified?.content == RemoteApprovalNotificationText.content(for: review, macName: "Pinned Mac")
            && verified?.threadIdentifier == macDeviceID
            && verified?.interrupts == true,
          "alerts: a request the pinned Mac signed is shown in its own words, under the pinned Mac's name, not the claimed one")
    check(alert(.found(forged)) == nil,
          "alerts: a request in a pinned Mac's name signed by another key keeps the fixed text")
    check(alert(.found(otherMac)) == nil,
          "alerts: a request from a Mac this iPhone never pinned keeps the fixed text")
    check(alert(.found(future)) == nil,
          "alerts: a request that does not validate (created an hour ahead) keeps the fixed text")
    let elsewhere = Verification.PinnedMac(
        deviceID: macDeviceID, publicKeyX963: macKey.publicKey.x963Representation,
        displayName: "Pinned Mac", cloudKitContainerIdentifier: "iCloud.example.other"
    )
    check(alert(.found(good), macs: [elsewhere]) == nil,
          "alerts: a Mac pinned in another container does not vouch for a request in this one")
    check(alert(.gone)?.content == RemoteApprovalNotificationText.noLongerWaiting && alert(.unavailable) == nil,
          "alerts: a request already gone says it is no longer waiting; one that cannot be read keeps the fixed text")
    check(alert(.gone)?.interrupts == false,
          "alerts: an alert for a request already over arrives passive and silent")
}

/// What the extension tidies on each alert: delivered alerts whose request
/// read as gone come off, nothing else does, and the badge counts the
/// verified requests still waiting, only when the mailbox query answered.
private func alertExtensionSweep() {
    typealias Sweep = RemoteApprovalAlertSweep
    typealias Verification = RemoteApprovalAlertVerification
    let macKey = P256.Signing.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()
    let container = CSECBuildIdentity.cloudKitContainer
    let pinned = Verification.PinnedMac(
        deviceID: macDeviceID, publicKeyX963: macKey.publicKey.x963Representation,
        displayName: "Pinned Mac", cloudKitContainerIdentifier: container
    )
    let review = v3AccessReviewFixture(withRestore: false)
    let now = currentTimeMilliseconds()
    func signed(by key: P256.Signing.PrivateKey = macKey) -> SignedRemoteApprovalRequest? {
        try? .signed(
            RemoteApprovalRequest(macDeviceID: macDeviceID, macDeviceName: "Claimed",
                                  createdAtMilliseconds: now, review: review),
            by: key
        )
    }
    guard let current = signed(), let live = signed(), let listedOnly = signed(),
          let forged = signed(by: P256.Signing.PrivateKey()), let gone = signed(),
          let unread = signed() else {
        check(false, "alerts: the sweep fixtures sign")
        return
    }
    let delivered: [(identifier: String, requestID: String?)] = [
        (identifier: "n-live", requestID: live.request.requestID),
        (identifier: "n-gone", requestID: gone.request.requestID),
        (identifier: "n-unread", requestID: unread.request.requestID),
        (identifier: "n-other-app", requestID: nil),
    ]
    let reads: [String: Verification.Read] = [
        current.request.requestID: .found(current),
        live.request.requestID: .found(live),
        gone.request.requestID: .gone,
        unread.request.requestID: .unavailable,
    ]
    func plan(listed: [SignedRemoteApprovalRequest]?,
              reads: [String: Verification.Read] = reads) -> Sweep.Plan {
        Sweep.plan(delivered: delivered, reads: reads,
                   listed: listed?.map { RemoteApprovalMailboxRequest(envelope: $0, savedAt: nil) },
                   pinnedMacs: [pinned], containerIdentifier: container, nowMilliseconds: now)
    }
    let swept = plan(listed: [live, listedOnly, forged, gone])
    check(swept.staleIdentifiers == ["n-gone"],
          "alerts: only a delivered alert whose request read as gone comes off; an unreadable one and other apps' stay")
    check(swept.badge == 3,
          "alerts: the badge counts this alert's, a live alert's and a listed request, once each; not a forged or gone one")
    let offline = plan(listed: nil)
    check(offline.badge == nil && offline.staleIdentifiers == ["n-gone"],
          "alerts: with the mailbox query failed the badge is left alone, and gone alerts still come off")
    check(plan(listed: [], reads: [:]) == Sweep.Plan(staleIdentifiers: [], badge: 0),
          "alerts: an empty mailbox with nothing read clears the badge and removes nothing")
    check(plan(listed: [], reads: [current.request.requestID: .gone]).badge == 0,
          "alerts: an alert for a request already over does not count itself")

    // Which requests are read: this alert's first, then the delivered csec
    // alerts', newest first, once each, bounded.
    let many: [(identifier: String, requestID: String?)] = (0..<40).map {
        (identifier: "n\($0)", requestID: $0 % 2 == 0 ? "r\($0 / 2)" : nil)
    }
    let repeated = many + [(identifier: "dup", requestID: "r0")]
    let ids = Sweep.requestIDsToRead(current: "now", delivered: repeated)
    check(ids.first == "now" && ids.count == Sweep.maximumReads && Set(ids).count == ids.count
            && Array(ids.dropFirst().prefix(3)) == ["r0", "r1", "r2"],
          "alerts: the sweep reads this alert's request, then the newest delivered alerts', once each, at most \(Sweep.maximumReads)")
    check(Sweep.requestIDsToRead(current: nil, delivered: [(identifier: "x", requestID: nil)]).isEmpty,
          "alerts: no csec alert delivered and none named: nothing is read")
}

/// Delivered alerts the phone clears once a mailbox read shows what is still
/// waiting: csec alerts for requests it can no longer answer, nothing else.
private func alertStaleDeliveredAlerts() {
    let live = UUID().uuidString.lowercased()
    let decided = UUID().uuidString.lowercased()
    let gone = UUID().uuidString.lowercased()
    let stale = RemoteApprovalDeliveredAlerts.stale(
        [
            (identifier: "n-live", requestID: live),
            (identifier: "n-decided", requestID: decided),
            (identifier: "n-gone", requestID: gone),
            (identifier: "n-other-app", requestID: nil),
        ],
        answerable: [live]
    )
    check(stale == ["n-decided", "n-gone"],
          "alerts: delivered alerts for requests the phone can no longer answer are cleared; a live one and others stay")
    check(RemoteApprovalDeliveredAlerts.stale([(identifier: "n", requestID: nil)], answerable: []).isEmpty,
          "alerts: a notification that is not a csec alert is never cleared")
}

/// A gate the test opens by hand.
private actor AlertLatch {
    private var open = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        if open { return }
        await withCheckedContinuation { waiters.append($0) }
    }

    func release() {
        open = true
        waiters.forEach { $0.resume() }
        waiters = []
    }

    var isOpen: Bool { open }
}

private struct AlertFixture: Sendable {
    let phone = SyntheticPhone()
    let macKey = P256.Signing.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()
    let relay = V3MailboxRelay()

    func requester(gate: @escaping RemoteApprovalAlertGate) throws -> RemoteApprovalRequester {
        try RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: macDeviceID, macDeviceName: "Alex’s Mac",
                pinnedPhoneDeviceID: phone.deviceID,
                pinnedPhonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: V3SoftwareSigner(key: macKey),
            relay: relay,
            alertGate: gate
        )
    }

    func firstRequest() async -> SignedRemoteApprovalRequest? {
        for _ in 0..<500 {
            if let envelope = await relay.request(number: 0) { return envelope }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return nil
    }
}

/// Polls `condition` for up to five seconds.
private func eventually(_ condition: @Sendable () async -> Bool) async -> Bool {
    for _ in 0..<500 {
        if await condition() { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return false
}

private func alertWaitsForTheGate() async {
    let fixture = AlertFixture()
    let latch = AlertLatch()
    guard let requester = try? fixture.requester(gate: { await latch.wait() }) else {
        check(false, "alerts: the requester builds")
        return
    }
    let pending = Task { await requester.requestApproval(for: v3AccessReviewFixture(withRestore: false)) }
    guard let envelope = await fixture.firstRequest() else {
        pending.cancel()
        check(false, "alerts: the request reaches the mailbox")
        return
    }
    let requestID = envelope.request.requestID
    try? await Task.sleep(nanoseconds: 150_000_000)
    let earlyAlerts = await fixture.relay.alertsPublished
    check(earlyAlerts.isEmpty, "alerts: the request is on the phone before its alert, which waits for the gate")

    await latch.release()
    let alerted = await eventually { await fixture.relay.alerts.contains(requestID) }
    let alertCount = await fixture.relay.alertsPublished.count
    check(alerted && alertCount == 1, "alerts: once the gate opens the phone is alerted, once, for that request")

    do {
        let approval = try fixture.phone.respond(
            to: envelope, .approve,
            scopeID: envelope.request.review.defaultScopeID,
            durationIndex: envelope.request.review.defaultDurationIndex
        )
        try await fixture.relay.publishResponse(approval)
    } catch {
        check(false, "alerts: the phone answers (\(error))")
    }
    let result = await pending.value
    if case .approved = result {
        check(true, "alerts: the phone's answer after the alert decides the request")
    } else {
        check(false, "alerts: the phone's answer after the alert decides the request (\(result))")
    }
    let cleared = await eventually {
        let alerts = await fixture.relay.alerts
        let live = await fixture.relay.liveRequests()
        return alerts.isEmpty && live.isEmpty
    }
    check(cleared, "alerts: the answered request's alert record is deleted with it")
}

private func alertNeverRaisedForARequestDecidedFirst() async {
    // Answered at the Mac (withdrawn here) while the gate is shut.
    do {
        let fixture = AlertFixture()
        let gateReturned = AlertLatch()
        guard let requester = try? fixture.requester(gate: {
            try? await Task.sleep(nanoseconds: 60_000_000_000)
            await gateReturned.release()
        }) else {
            check(false, "alerts: the requester builds")
            return
        }
        let pending = Task { await requester.requestApproval(for: v3AccessReviewFixture(withRestore: false)) }
        guard let envelope = await fixture.firstRequest() else {
            pending.cancel()
            check(false, "alerts: the request reaches the mailbox")
            return
        }
        let started = ContinuousClock.now
        await requester.withdraw(requestID: envelope.request.requestID)
        _ = await pending.value
        let gateStopped = await eventually { await gateReturned.isOpen }
        let elapsed = ContinuousClock.now - started
        try? await Task.sleep(nanoseconds: 150_000_000)
        let attempts = await fixture.relay.alertAttempts
        check(gateStopped && elapsed < .seconds(5) && attempts == 0,
              "alerts: a request answered at the Mac before the gate opens stops the wait and never alerts the phone")
    }

    // Answered on the phone while the gate is shut.
    do {
        let fixture = AlertFixture()
        guard let requester = try? fixture.requester(gate: {
            try? await Task.sleep(nanoseconds: 60_000_000_000)
        }) else {
            check(false, "alerts: the requester builds")
            return
        }
        let pending = Task { await requester.requestApproval(for: v3AccessReviewFixture(withRestore: false)) }
        guard let envelope = await fixture.firstRequest() else {
            pending.cancel()
            check(false, "alerts: the request reaches the mailbox")
            return
        }
        do {
            try await fixture.relay.publishResponse(try fixture.phone.respond(to: envelope, .deny))
        } catch {
            check(false, "alerts: the phone denies (\(error))")
        }
        let result = await pending.value
        try? await Task.sleep(nanoseconds: 150_000_000)
        let attempts = await fixture.relay.alertAttempts
        if case .denied = result, attempts == 0 {
            check(true, "alerts: a request the phone decides from its card before the gate opens raises no alert")
        } else {
            check(false, "alerts: a request the phone decides from its card before the gate opens raises no alert (\(result), \(attempts) attempts)")
        }
    }
}

private func alertRetriesLikeTheRequest() async {
    // A delay is retried; the alert lands.
    do {
        let fixture = AlertFixture()
        await fixture.relay.failNextAlerts([
            RemoteApprovalRelayFailure.transient,
            RemoteApprovalRelayFailure.throttled(retryAfterNanoseconds: 0),
        ])
        guard let requester = try? fixture.requester(gate: {}) else {
            check(false, "alerts: the requester builds")
            return
        }
        let pending = Task { await requester.requestApproval(for: v3AccessReviewFixture(withRestore: false)) }
        guard let envelope = await fixture.firstRequest() else {
            pending.cancel()
            check(false, "alerts: the request reaches the mailbox")
            return
        }
        let alerted = await eventually { await fixture.relay.alerts.contains(envelope.request.requestID) }
        let attempts = await fixture.relay.alertAttempts
        check(alerted && attempts == 3, "alerts: a network or throttling delay is retried until the alert lands")
        await requester.withdraw(requestID: envelope.request.requestID)
        _ = await pending.value
    }

    // A relay that cannot take the alert leaves the request answerable.
    do {
        let fixture = AlertFixture()
        await fixture.relay.failNextAlerts([RemoteApprovalRelayFailure.permanentlyUnavailable])
        guard let requester = try? fixture.requester(gate: {}) else {
            check(false, "alerts: the requester builds")
            return
        }
        let pending = Task { await requester.requestApproval(for: v3AccessReviewFixture(withRestore: false)) }
        guard let envelope = await fixture.firstRequest() else {
            pending.cancel()
            check(false, "alerts: the request reaches the mailbox")
            return
        }
        let gaveUp = await eventually { await fixture.relay.alertAttempts == 1 }
        try? await Task.sleep(nanoseconds: 150_000_000)
        let attempts = await fixture.relay.alertAttempts
        let stillPending = await requester.isPending(requestID: envelope.request.requestID)
        check(gaveUp && attempts == 1 && stillPending,
              "alerts: an alert the relay refuses outright is not retried, and the request stays open")
        do {
            try await fixture.relay.publishResponse(try fixture.phone.respond(to: envelope, .deny))
        } catch {
            check(false, "alerts: the phone denies (\(error))")
        }
        if case .denied = await pending.value {
            check(true, "alerts: without its alert, the request is still decided from the phone's card")
        } else {
            check(false, "alerts: without its alert, the request is still decided from the phone's card")
        }
    }
}

/// A clock the gate's sleeps move, so the wait is measured without waiting.
private final class AlertClock: @unchecked Sendable {
    private let lock = NSLock()
    private var nanoseconds: UInt64 = 1_000_000_000
    private var unattendedAt: UInt64?
    private(set) var sleeps = 0

    init(unattendedAfter seconds: Double? = nil) {
        unattendedAt = seconds.map { 1_000_000_000 + UInt64($0 * 1_000_000_000) }
    }

    var now: UInt64 { lock.withLock { nanoseconds } }
    var elapsedSeconds: Double { Double(now - 1_000_000_000) / 1_000_000_000 }
    var unattended: Bool { lock.withLock { unattendedAt.map { nanoseconds >= $0 } ?? false } }

    func sleep(_ duration: UInt64) throws {
        try Task.checkCancellation()
        lock.withLock {
            nanoseconds += duration
            sleeps += 1
        }
    }
}

private func alertTimingGate() async {
    let grace = RemoteApprovalAlertTiming.macPromptGraceNanoseconds
    check(grace == 30_000_000_000, "alert gate: the Mac's prompt has 30 seconds before the phone is alerted")

    func run(_ clock: AlertClock) async {
        await RemoteApprovalAlertTiming.waitUntilDue(
            macUnattended: { clock.unattended },
            now: { clock.now },
            sleep: { try clock.sleep($0) }
        )
    }

    let attended = AlertClock()
    await run(attended)
    check(attended.elapsedSeconds == 30 && attended.sleeps == 60,
          "alert gate: while the Mac is attended the alert waits the full 30 s, re-checking every 0.5 s (\(attended.elapsedSeconds) s)")

    let locked = AlertClock(unattendedAfter: 0)
    await run(locked)
    check(locked.elapsedSeconds == 0 && locked.sleeps == 0,
          "alert gate: with the Mac locked or asleep the alert goes at once")

    let locksLater = AlertClock(unattendedAfter: 12.2)
    await run(locksLater)
    check(locksLater.elapsedSeconds == 12.5,
          "alert gate: a Mac that locks during the wait releases the alert at the next check (\(locksLater.elapsedSeconds) s)")

    let cancelled = AlertClock()
    await Task {
        withUnsafeCurrentTask { $0?.cancel() }
        await run(cancelled)
    }.value
    check(cancelled.elapsedSeconds == 0 && cancelled.sleeps == 0,
          "alert gate: a cancelled wait ends at once, without waiting out the grace")

    typealias Timing = RemoteApprovalAlertTiming
    check(!Timing.unattended(screenLocked: false, displayAsleep: false, canTakeTouch: true),
          "alert gate: an unlocked, awake Mac that can take a touch is attended")
    check(Timing.unattended(screenLocked: false, displayAsleep: false, canTakeTouch: false),
          "alert gate: a Mac that cannot take a touch (lid closed, lockout, nothing enrolled) alerts the phone at once")
    check(Timing.unattended(screenLocked: true, displayAsleep: false, canTakeTouch: true)
            && Timing.unattended(screenLocked: false, displayAsleep: true, canTakeTouch: true),
          "alert gate: a locked Mac or one with its display asleep alerts the phone at once")
    let probes = ProbeCounter()
    _ = Timing.unattended(screenLocked: true, displayAsleep: false, canTakeTouch: probes.probe())
    _ = Timing.unattended(screenLocked: false, displayAsleep: true, canTakeTouch: probes.probe())
    _ = Timing.unattended(screenLocked: false, displayAsleep: false, canTakeTouch: probes.probe())
    check(probes.count == 1,
          "alert gate: Touch ID is probed only once the Mac reads unlocked and awake (\(probes.count) probes)")
}

private final class ProbeCounter {
    private(set) var count = 0
    func probe() -> Bool {
        count += 1
        return true
    }
}

private func alertNotificationText() {
    typealias Text = RemoteApprovalNotificationText
    check(Text.kindTitle(.access) == "Secret access requested"
            && Text.kindTitle(.ssh) == "SSH sign-in requested"
            && Text.kindTitle(.sudo) == "sudo requested"
            && Text.kindTitle(.restore) == "Reopen approvals after csecd restarted",
          "notification: each kind has the card's heading")

    let access = v3AccessReviewFixture(withRestore: false)
    let content = Text.content(for: access, macName: "Alex M4")
    check(content.title == "Secret access requested" && content.subtitle == "From Alex M4"
            && content.body.hasPrefix("“\(access.headline)”")
            && content.body.contains(access.callerDescription),
          "notification: a verified request shows its kind, the pinned Mac, the command and the requester")
    let sudo = Text.content(for: v3SudoReviewFixture(), macName: "Alex M4")
    check(sudo.title == "sudo requested", "notification: a sudo request says so")

    let hostile = RemoteReviewParts.changing(access) {
        $0.headline = "ls\n\u{202E}evil " + String(repeating: "x", count: 400)
        $0.callerDescription = "Claude Code\u{0007}"
    }
    let shown = Text.content(for: hostile, macName: "Mac\u{2066}\nFake")
    let parts = [shown.title, shown.subtitle] + shown.body.split(separator: "\n").map(String.init)
    let controls: Set<UInt32> = [0x000A, 0x202E, 0x2066, 0x0007]
    check(shown.body.split(separator: "\n").count == 2
            && !parts.contains { $0.unicodeScalars.contains { controls.contains($0.value) } },
          "notification: newlines, bidi and control characters from the request cannot break or reorder the alert")
    check(parts.allSatisfy { $0.count <= 160 } && shown.body.contains("…"),
          "notification: a long command is cut to its line with an ellipsis")
}

private func alertRecordNames() {
    let id = UUID().uuidString.lowercased()
    check(RemoteApprovalMailboxName.alert(requestID: id) == "alert-\(id)"
            && RemoteApprovalMailboxName.requestID(fromAlertRecordName: "alert-\(id)") == id,
          "alert names: alert-<request ID> names a request's alert, and names it back")
    let refused = [
        RemoteApprovalMailboxName.alert(requestID: id.uppercased()),
        RemoteApprovalMailboxName.requestID(fromAlertRecordName: "alert-\(id.uppercased())"),
        RemoteApprovalMailboxName.requestID(fromAlertRecordName: "request-\(id)"),
        RemoteApprovalMailboxName.requestID(fromAlertRecordName: "alert-\(id)x"),
        RemoteApprovalMailboxName.requestID(fromAlertRecordName: "alert-"),
    ]
    check(refused.allSatisfy { $0 == nil },
          "alert names: only a canonical request ID makes or reads an alert name")
}

/// An alert push as CloudKit sends it, parsed by CloudKit's own parser.
private func alertPushParsing() {
    typealias Relay = CloudKitRemoteApprovalRelay
    let id = UUID().uuidString.lowercased()
    func push(subscription: String, record: String) -> [AnyHashable: Any] {
        [
            "aps": ["alert": ["title": "Convenient Security", "body": "A Mac is asking for your approval."],
                    "mutable-content": 1, "content-available": 1],
            "ck": [
                "ce": 2,
                "cid": Relay.defaultContainerIdentifier,
                "nid": UUID().uuidString,
                "qry": ["dbs": 1, "fo": 1, "rid": record, "sid": subscription,
                        "zid": "_defaultZone", "zoid": "_defaultOwner"],
            ],
        ]
    }
    check(Relay.alertRequestID(fromRemoteNotification: push(subscription: Relay.alertSubscriptionID,
                                                            record: "alert-\(id)")) == id,
          "alert push: CloudKit's notification names the request the alert is for")
    check(Relay.alertRequestID(fromRemoteNotification: push(subscription: Relay.requestSubscriptionID,
                                                            record: "request-\(id)")) == nil
            && Relay.alertRequestID(fromRemoteNotification: push(subscription: Relay.alertSubscriptionID,
                                                                 record: "request-\(id)")) == nil
            && Relay.alertRequestID(fromRemoteNotification: ["aps": ["alert": "hi"]]) == nil,
          "alert push: only the alert subscription's push for an alert record names a request")
}
