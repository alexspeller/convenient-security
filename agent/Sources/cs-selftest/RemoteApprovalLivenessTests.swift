import CryptoKit
import CSECRemoteApproval
import Foundation
import CSECBuildIdentity

/// A Mac that stops for good must not leave an approvable card on the phone:
/// a waiting Mac saves its request again on an interval, the phone shows a
/// request only while the mailbox saved it recently, and none of that is an
/// expiry — a quiet request comes back once its Mac saves it again.
func remoteApprovalLivenessTests() async {
    print("\n# Remote approval liveness (refresh while waiting, quiet requests; synthetic keys only)")
    livenessRule()
    livenessRequesterConfiguration()
    await livenessRefreshWhileWaiting()
    await livenessRefreshRetries()
    await livenessNoRefreshOutlivesWithdrawal()
    livenessAlertExtension()
}

private actor LivenessSigner: RemoteApprovalRequestSigner {
    let key: P256.Signing.PrivateKey

    init(key: P256.Signing.PrivateKey) {
        self.key = key
    }

    func publicKeyX963Representation() async throws -> Data {
        key.publicKey.x963Representation
    }

    func sign(_ data: Data) async throws -> Data {
        try key.signature(for: data).derRepresentation
    }
}

/// A mailbox that records every save and delete of a request record, in
/// order, and can fail the next refreshes.
private actor RefreshRecordingRelay: RemoteApprovalRelay {
    private(set) var events: [String] = []
    private(set) var refreshAttempts = 0
    private var requests: [String: SignedRemoteApprovalRequest] = [:]
    private var refreshFailures: [Error] = []
    /// How long each refresh takes to land, whatever happens to its caller.
    private var refreshDelayNanoseconds: UInt64 = 0

    func failNextRefreshes(_ failures: [Error]) {
        refreshFailures = failures
    }

    func delayRefreshes(by nanoseconds: UInt64) {
        refreshDelayNanoseconds = nanoseconds
    }

    func refreshes() -> Int {
        events.filter { $0.hasPrefix("refresh ") }.count
    }

    func publishedRequest() -> SignedRemoteApprovalRequest? {
        requests.values.first
    }

    func holds(_ requestID: String) -> Bool {
        requests[requestID] != nil
    }

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        requests[request.request.requestID] = request
        events.append("publish \(request.request.requestID)")
    }

    func refreshRequest(_ request: SignedRemoteApprovalRequest) async throws {
        refreshAttempts += 1
        if !refreshFailures.isEmpty {
            throw refreshFailures.removeFirst()
        }
        let delay = refreshDelayNanoseconds
        if delay > 0 {
            // A save already on the wire lands whether or not its caller was
            // cancelled.
            await Task.detached { try? await Task.sleep(nanoseconds: delay) }.value
        }
        requests[request.request.requestID] = request
        events.append("refresh \(request.request.requestID)")
    }

    func response(for requestID: String, phoneDeviceID: String) async throws -> SignedRemoteApprovalResponse? {
        nil
    }

    func discardResponse(for requestID: String, phoneDeviceID: String) async {}

    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] {
        Array(requests.values)
    }

    func requestIsPending(requestID: String) async throws -> Bool {
        requests[requestID] != nil
    }

    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {}
    func publishAlert(requestID: String, macDeviceID: String) async throws {}

    func deleteExchange(requestID: String, phoneDeviceID: String?) async throws {
        requests.removeValue(forKey: requestID)
        events.append("delete \(requestID)")
    }

    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation? { nil }
    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws {}
    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? { nil }
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {}
    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {}
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? { nil }
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async throws {}
}

private struct LivenessFixture {
    let macKey = P256.Signing.PrivateKey()
    let phoneKey = P256.Signing.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()
    let phoneDeviceID = UUID().uuidString.lowercased()

    func configuration(
        pollIntervalNanoseconds: UInt64 = 50_000_000,
        refreshIntervalNanoseconds: UInt64 = 100_000_000
    ) -> RemoteApprovalRequesterConfiguration {
        RemoteApprovalRequesterConfiguration(
            macDeviceID: macDeviceID,
            macDeviceName: "Alex’s Mac",
            pinnedPhoneDeviceID: phoneDeviceID,
            pinnedPhonePublicKeyX963: phoneKey.publicKey.x963Representation,
            pollIntervalNanoseconds: pollIntervalNanoseconds,
            refreshIntervalNanoseconds: refreshIntervalNanoseconds
        )
    }

    func requester(
        relay: any RemoteApprovalRelay,
        refreshIntervalNanoseconds: UInt64 = 100_000_000,
        exchangeDrainNanoseconds: UInt64 = RemoteApprovalBound.readNanoseconds
    ) throws -> RemoteApprovalRequester {
        try RemoteApprovalRequester(
            configuration: configuration(refreshIntervalNanoseconds: refreshIntervalNanoseconds),
            signer: LivenessSigner(key: macKey),
            relay: relay,
            exchangeDrainNanoseconds: exchangeDrainNanoseconds
        )
    }

    func signedRequest(createdAt: UInt64 = currentTimeMilliseconds()) -> SignedRemoteApprovalRequest? {
        try? .signed(
            RemoteApprovalRequest(
                macDeviceID: macDeviceID,
                macDeviceName: "Alex’s Mac",
                createdAtMilliseconds: createdAt,
                review: v3AccessReviewFixture(withRestore: false)
            ),
            by: macKey
        )
    }
}

private func livenessEventually(
    within nanoseconds: UInt64 = 4_000_000_000,
    _ condition: () async -> Bool
) async -> Bool {
    let deadline = ContinuousClock.now + .nanoseconds(Int64(nanoseconds))
    repeat {
        if await condition() { return true }
        try? await Task.sleep(nanoseconds: 5_000_000)
    } while ContinuousClock.now < deadline
    return await condition()
}

/// The phone's rule: quiet only once the mailbox has not saved a record for
/// longer than the threshold; never for a mailbox with no save time, or a
/// save time ahead of the phone's clock.
private func livenessRule() {
    typealias Liveness = RemoteApprovalLiveness
    let now = Date()
    let threshold = Liveness.quietAfterSeconds
    check(!Liveness.isQuiet(savedAt: now, now: now),
          "liveness: a record saved just now is waiting")
    check(!Liveness.isQuiet(savedAt: now.addingTimeInterval(-threshold), now: now),
          "liveness: a record saved exactly the threshold ago is still waiting")
    check(Liveness.isQuiet(savedAt: now.addingTimeInterval(-threshold - 1), now: now),
          "liveness: a record not saved for longer than the threshold is quiet")
    check(Liveness.isQuiet(savedAt: now.addingTimeInterval(-3 * 24 * 60 * 60), now: now),
          "liveness: the card a Mac that crashed days ago left is quiet")
    check(!Liveness.isQuiet(savedAt: nil, now: now),
          "liveness: a mailbox that keeps no save time never makes a request quiet")
    check(!Liveness.isQuiet(savedAt: now.addingTimeInterval(3_600), now: now),
          "liveness: a save time ahead of the phone's clock is no evidence the Mac stopped")
    check(Double(Liveness.refreshIntervalNanoseconds) / 1_000_000_000 * 5 <= threshold,
          "liveness: the threshold allows several missed refreshes before a waiting Mac looks quiet")
    check(Double(RemoteApprovalRequester.maximumThrottleDelayNanoseconds) / 1_000_000_000
            + Double(Liveness.refreshIntervalNanoseconds) / 1_000_000_000 < threshold,
          "liveness: a refresh delayed by the longest throttle still lands before the threshold")

    let presentNow = RemoteApprovalRequestPresence.present(savedAt: now)
    let presentLongAgo = RemoteApprovalRequestPresence.present(savedAt: now.addingTimeInterval(-threshold - 60))
    check(presentNow.isWaiting(at: now) && !presentLongAgo.isWaiting(at: now)
            && !RemoteApprovalRequestPresence.gone.isWaiting(at: now)
            && RemoteApprovalRequestPresence.present(savedAt: nil).isWaiting(at: now),
          "liveness: a present record is waiting unless quiet; a gone one never is")
    // Presentation only, and reversible: the same record saved again is
    // waiting once more.
    let quiet = now.addingTimeInterval(-threshold - 60)
    check(Liveness.isQuiet(savedAt: quiet, now: now) && !Liveness.isQuiet(savedAt: now, now: now),
          "liveness: a quiet request saved again is waiting again")
}

/// The refresh interval is the requester's to shorten, never to stretch past
/// the shared one the phone's threshold is set against.
private func livenessRequesterConfiguration() {
    let fixture = LivenessFixture()
    check((try? fixture.configuration(refreshIntervalNanoseconds: RemoteApprovalLiveness.refreshIntervalNanoseconds).validate()) != nil,
          "liveness: the shared refresh interval is a valid configuration")
    check((try? fixture.configuration(refreshIntervalNanoseconds: RemoteApprovalLiveness.refreshIntervalNanoseconds + 1).validate()) == nil,
          "liveness: a refresh interval longer than the shared one is refused")
    check((try? fixture.configuration(refreshIntervalNanoseconds: 1_000_000).validate()) == nil,
          "liveness: a refresh interval shorter than the poll floor is refused")
    let defaults = RemoteApprovalRequesterConfiguration(
        macDeviceID: fixture.macDeviceID,
        macDeviceName: "Alex’s Mac",
        pinnedPhoneDeviceID: fixture.phoneDeviceID,
        pinnedPhonePublicKeyX963: fixture.phoneKey.publicKey.x963Representation
    )
    check(defaults.refreshIntervalNanoseconds == RemoteApprovalLiveness.refreshIntervalNanoseconds,
          "liveness: csecd's requester refreshes on the shared interval by default")
}

/// While the Mac waits it saves the same signed request again, interval after
/// interval; once it stops waiting it saves nothing more.
private func livenessRefreshWhileWaiting() async {
    let fixture = LivenessFixture()
    let relay = RefreshRecordingRelay()
    guard let requester = try? fixture.requester(relay: relay) else {
        check(false, "liveness: the requester builds")
        return
    }
    let review = v3AccessReviewFixture(withRestore: false)
    let started = ContinuousClock.now
    let pending = Task { await requester.requestApproval(for: review) }
    let refreshed = await livenessEventually { await relay.refreshes() >= 3 }
    let elapsed = ContinuousClock.now - started
    check(refreshed, "liveness: a waiting Mac saves its request again on every interval")
    // Three refreshes on a 100 ms interval take at least 300 ms; on every
    // 50 ms poll they would take half that.
    check(elapsed >= .milliseconds(280),
          "liveness: refreshes come once an interval, not on every poll")
    let published = await relay.publishedRequest()
    let events = await relay.events
    if let published {
        check(events.first == "publish \(published.request.requestID)"
                && events.dropFirst().allSatisfy { $0 == "refresh \(published.request.requestID)" },
              "liveness: each refresh saves the one request it published, after publishing it")
    } else {
        check(false, "liveness: the request reaches the mailbox")
    }

    if let published {
        await requester.withdraw(requestID: published.request.requestID)
    }
    check(await pending.value == .unavailable, "liveness: a withdrawn wait is unavailable")
    let deleted = await livenessEventually {
        await relay.events.last?.hasPrefix("delete ") == true
    }
    check(deleted, "liveness: the withdrawn request is deleted")
    let afterDelete = await relay.refreshes()
    try? await Task.sleep(nanoseconds: 400_000_000)
    let laterRefreshes = await relay.refreshes()
    let lastEvent = await relay.events.last
    check(laterRefreshes == afterDelete && lastEvent?.hasPrefix("delete ") == true,
          "liveness: nothing saves the request again once the Mac stopped waiting")
    if let published {
        check(await relay.holds(published.request.requestID) == false,
              "liveness: the withdrawn request stays out of the mailbox")
    }
}

/// A refresh that fails is tried again soon, through throttling and blips,
/// without ending the wait; a relay this Mac cannot use stops only the
/// refreshes.
private func livenessRefreshRetries() async {
    let fixture = LivenessFixture()
    let relay = RefreshRecordingRelay()
    await relay.failNextRefreshes([
        RemoteApprovalRelayFailure.transient,
        RemoteApprovalRelayFailure.throttled(retryAfterNanoseconds: 1),
        URLError(.timedOut),
    ])
    guard let requester = try? fixture.requester(relay: relay, refreshIntervalNanoseconds: 1_000_000_000) else {
        check(false, "liveness: the requester builds")
        return
    }
    let review = v3AccessReviewFixture(withRestore: false)
    let pending = Task { await requester.requestApproval(for: review) }
    // Three failures, each retried on the poll interval or the throttle's
    // floor, then one that lands: well inside two intervals.
    let started = ContinuousClock.now
    let landed = await livenessEventually(within: 3_000_000_000) { await relay.refreshes() >= 1 }
    let elapsed = ContinuousClock.now - started
    let attempts = await relay.refreshAttempts
    check(landed && attempts == 4,
          "liveness: a refresh that failed (a blip, a throttle, an unclassified error) is tried again until it lands")
    check(elapsed < .milliseconds(1_900),
          "liveness: a failed refresh is retried soon, not a whole interval later")
    if let published = await relay.publishedRequest() {
        check(await requester.isPending(requestID: published.request.requestID),
              "liveness: failed refreshes do not end the wait")
    }
    pending.cancel()
    _ = await pending.value

    let unusable = RefreshRecordingRelay()
    await unusable.failNextRefreshes([RemoteApprovalRelayFailure.permanentlyUnavailable])
    guard let stopped = try? fixture.requester(relay: unusable) else {
        check(false, "liveness: the requester builds")
        return
    }
    let waiting = Task { await stopped.requestApproval(for: review) }
    _ = await livenessEventually { await unusable.refreshAttempts >= 1 }
    try? await Task.sleep(nanoseconds: 400_000_000)
    check(await unusable.refreshAttempts == 1,
          "liveness: a relay this Mac cannot use stops the refreshes")
    if let published = await unusable.publishedRequest() {
        check(await stopped.isPending(requestID: published.request.requestID),
              "liveness: and leaves the wait to the response poll")
    }
    waiting.cancel()
    _ = await waiting.value
}

/// A refresh already on the wire when the Mac stops waiting lands before the
/// withdrawal's delete, or is deleted after it, so it never puts the request
/// back on the phone for good.
private func livenessNoRefreshOutlivesWithdrawal() async {
    let fixture = LivenessFixture()
    for drain in [RemoteApprovalBound.readNanoseconds, 50_000_000] as [UInt64] {
        let relay = RefreshRecordingRelay()
        await relay.delayRefreshes(by: 300_000_000)
        guard let requester = try? fixture.requester(relay: relay, exchangeDrainNanoseconds: drain) else {
            check(false, "liveness: the requester builds")
            return
        }
        let review = v3AccessReviewFixture(withRestore: false)
        let pending = Task { await requester.requestApproval(for: review) }
        // The first refresh starts after one interval and takes 300 ms to land.
        _ = await livenessEventually { await relay.refreshAttempts >= 1 }
        try? await Task.sleep(nanoseconds: 50_000_000)
        pending.cancel()
        _ = await pending.value
        let settled = await livenessEventually {
            let events = await relay.events
            return events.contains { $0.hasPrefix("refresh ") } && events.last?.hasPrefix("delete ") == true
        }
        let requestID = await relay.events.first.map { String($0.dropFirst("publish ".count)) } ?? ""
        let held = await relay.holds(requestID)
        check(settled && !held,
              drain > 100_000_000
                ? "liveness: a refresh in flight at withdrawal lands before the delete"
                : "liveness: a refresh that lands after the drain bound is deleted again")
    }
}

/// The notification service extension's view of the same rule: a quiet
/// request's alert comes off, says it is not waiting, and is not counted.
private func livenessAlertExtension() {
    typealias Verification = RemoteApprovalAlertVerification
    let fixture = LivenessFixture()
    let container = CSECBuildIdentity.cloudKitContainer
    let pinned = Verification.PinnedMac(
        deviceID: fixture.macDeviceID, publicKeyX963: fixture.macKey.publicKey.x963Representation,
        displayName: "Pinned Mac", cloudKitContainerIdentifier: container
    )
    guard let live = fixture.signedRequest(), let quiet = fixture.signedRequest() else {
        check(false, "liveness: the extension fixtures sign")
        return
    }
    let now = Date()
    let nowMilliseconds = currentTimeMilliseconds(now)
    let longAgo = now.addingTimeInterval(-RemoteApprovalLiveness.quietAfterSeconds - 60)
    let liveRecord = RemoteApprovalMailboxRequest(envelope: live, savedAt: now)
    let quietRecord = RemoteApprovalMailboxRequest(envelope: quiet, savedAt: longAgo)

    if case .found = Verification.read(liveRecord, now: now) {
        check(true, "liveness: a recently saved request reads as found")
    } else {
        check(false, "liveness: a recently saved request reads as found")
    }
    if case .gone = Verification.read(quietRecord, now: now), case .gone = Verification.read(nil, now: now) {
        check(true, "liveness: a quiet request reads as gone to the extension, as a deleted one does")
    } else {
        check(false, "liveness: a quiet request reads as gone to the extension, as a deleted one does")
    }
    let ownAlert = Verification.alert(
        for: Verification.read(quietRecord, now: now),
        pinnedMacs: [pinned], containerIdentifier: container, nowMilliseconds: nowMilliseconds
    )
    check(ownAlert?.content == RemoteApprovalNotificationText.noLongerWaiting && ownAlert?.interrupts == false,
          "liveness: an alert for a quiet request says it is not waiting, passive and silent")

    let delivered: [(identifier: String, requestID: String?)] = [
        (identifier: "n-live", requestID: live.request.requestID),
        (identifier: "n-quiet", requestID: quiet.request.requestID),
    ]
    let plan = RemoteApprovalAlertSweep.plan(
        delivered: delivered,
        reads: [
            live.request.requestID: Verification.read(liveRecord, now: now),
            quiet.request.requestID: Verification.read(quietRecord, now: now),
        ],
        listed: [liveRecord, quietRecord],
        pinnedMacs: [pinned], containerIdentifier: container, nowMilliseconds: nowMilliseconds
    )
    check(plan.staleIdentifiers == ["n-quiet"],
          "liveness: a quiet request's delivered alert comes off; a waiting one's stays")
    check(plan.badge == 1,
          "liveness: the badge counts only the requests whose Mac is still in touch")
    let listedOnly = RemoteApprovalAlertSweep.plan(
        delivered: [], reads: [:], listed: [liveRecord, quietRecord],
        pinnedMacs: [pinned], containerIdentifier: container, nowMilliseconds: nowMilliseconds
    )
    check(listedOnly.badge == 1,
          "liveness: a quiet request the query lists is not counted either")
}
