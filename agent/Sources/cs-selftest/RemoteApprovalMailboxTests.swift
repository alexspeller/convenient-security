import CloudKit
import CryptoKit
import CSECRemoteApproval
import CSECRemoteApprovalCloudKit
import Foundation

// The mailbox is writable by anything signed into the same iCloud account, so
// nothing csecd does with it may trust a record before its signature binds it:
// not which record a sweep deletes, not which record ID is formed (CloudKit
// aborts the process on a bad one), and not which response a wait ends on.

/// A mailbox keyed by record name, as CloudKit is. It models what an
/// unauthenticated writer can do — put any payload under any name — and it
/// does *not* drop mismatched records itself, so these tests show the
/// requester's own checks rather than the CloudKit relay's.
actor HardenedMailboxRelay: RemoteApprovalRelay {
    private var requestRecords: [String: SignedRemoteApprovalRequest] = [:]
    private var responseRecords: [String: SignedRemoteApprovalResponse] = [:]
    private(set) var published: [String] = []
    /// Every request ID a delete was asked for, in order.
    private(set) var deleteRequests: [String] = []
    /// Response record names deleted by `deleteExchange` or `discardResponse`.
    private(set) var deletedResponseNames: [String] = []
    private(set) var discardedResponseNames: [String] = []
    private(set) var responseReads: [String] = []
    /// Set when a caller asked for an operation on a request ID the real relay
    /// could not name — the ID that used to abort csecd at every start.
    private(set) var unnameableIDRequested = false
    /// Failures still to come, as from a relay whose network is not back yet.
    private var deleteFailuresLeft = 0
    private var listingFailuresLeft = 0
    private var offerWithdrawalFailuresLeft = 0
    private(set) var listings = 0
    private(set) var offerWithdrawals = 0
    /// Response record names holding bytes that are no response.
    private var unreadableResponseNames: Set<String> = []

    func failNextDeletes(_ count: Int) { deleteFailuresLeft = count }
    func failNextListings(_ count: Int) { listingFailuresLeft = count }
    func failNextOfferWithdrawals(_ count: Int) { offerWithdrawalFailuresLeft = count }
    func plantUnreadableResponse(recordName: String) { unreadableResponseNames.insert(recordName) }

    func seed(_ envelope: SignedRemoteApprovalRequest, recordName: String) {
        requestRecords[recordName] = envelope
    }

    func plantResponse(_ envelope: SignedRemoteApprovalResponse, recordName: String) {
        responseRecords[recordName] = envelope
    }

    func requestRecordNames() -> Set<String> { Set(requestRecords.keys) }
    func responseRecord(_ name: String) -> SignedRemoteApprovalResponse? { responseRecords[name] }
    func responseRecordNames() -> Set<String> { Set(responseRecords.keys) }

    func publishedRequest(number index: Int) -> SignedRemoteApprovalRequest? {
        guard published.indices.contains(index),
              let name = RemoteApprovalMailboxName.request(requestID: published[index]) else { return nil }
        return requestRecords[name]
    }

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        guard let name = RemoteApprovalMailboxName.request(requestID: request.request.requestID) else {
            unnameableIDRequested = true
            throw RemoteApprovalRelayFailure.permanentlyUnavailable
        }
        requestRecords[name] = request
        published.append(request.request.requestID)
    }

    func response(for requestID: String, phoneDeviceID: String) async throws -> SignedRemoteApprovalResponse? {
        guard let name = RemoteApprovalMailboxName.response(requestID: requestID, phoneDeviceID: phoneDeviceID) else {
            unnameableIDRequested = true
            return nil
        }
        responseReads.append(name)
        if unreadableResponseNames.contains(name) { throw RemoteApprovalRelayFailure.unreadableRecord }
        return responseRecords[name]
    }

    func discardResponse(for requestID: String, phoneDeviceID: String) async {
        guard let name = RemoteApprovalMailboxName.response(requestID: requestID, phoneDeviceID: phoneDeviceID) else {
            unnameableIDRequested = true
            return
        }
        responseRecords[name] = nil
        unreadableResponseNames.remove(name)
        discardedResponseNames.append(name)
    }

    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] {
        listings += 1
        if listingFailuresLeft > 0 {
            listingFailuresLeft -= 1
            throw RemoteApprovalRelayFailure.transient
        }
        return Array(requestRecords.values)
    }

    func requestIsPending(requestID: String) async throws -> Bool {
        guard let name = RemoteApprovalMailboxName.request(requestID: requestID) else { return false }
        return requestRecords[name] != nil
    }

    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {
        guard let name = RemoteApprovalMailboxName.response(
            requestID: response.response.requestID,
            phoneDeviceID: response.response.phoneDeviceID
        ) else { throw RemoteApprovalRelayFailure.permanentlyUnavailable }
        responseRecords[name] = response
    }

    func publishAlert(requestID: String, macDeviceID: String) async throws {}

    func deleteExchange(requestID: String, phoneDeviceID: String?) async throws {
        deleteRequests.append(requestID)
        if deleteFailuresLeft > 0 {
            deleteFailuresLeft -= 1
            throw RemoteApprovalRelayFailure.transient
        }
        guard let name = RemoteApprovalMailboxName.request(requestID: requestID) else {
            unnameableIDRequested = true
            return
        }
        requestRecords[name] = nil
        if let phoneDeviceID,
           let responseName = RemoteApprovalMailboxName.response(
               requestID: requestID, phoneDeviceID: phoneDeviceID
           ) {
            responseRecords[responseName] = nil
            deletedResponseNames.append(responseName)
        }
    }

    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation? { nil }
    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws {}
    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? { nil }
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {}
    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {}
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? { nil }
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async throws {
        offerWithdrawals += 1
        if offerWithdrawalFailuresLeft > 0 {
            offerWithdrawalFailuresLeft -= 1
            throw RemoteApprovalRelayFailure.transient
        }
    }
}

/// `envelope` with its request ID replaced — what a JSON-editing writer can put
/// in the mailbox. The decoder does not normalize, so the ID survives as given.
private func rewritingRequestID(
    _ envelope: SignedRemoteApprovalRequest,
    to requestID: String
) throws -> SignedRemoteApprovalRequest {
    let data = try JSONEncoder().encode(envelope)
    guard var object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
          var request = object["request"] as? [String: Any] else {
        throw RemoteApprovalValidationError.invalidIdentifier
    }
    request["requestID"] = requestID
    object["request"] = request
    return try JSONDecoder().decode(
        SignedRemoteApprovalRequest.self,
        from: try JSONSerialization.data(withJSONObject: object)
    )
}

private struct MailboxWorld {
    let macKey = P256.Signing.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()
    let phone = SyntheticPhone()
    let review = v3AccessReviewFixture(withRestore: false)

    func requester(
        _ relay: HardenedMailboxRelay,
        cleanup: RemoteApprovalCleanupQueue = RemoteApprovalCleanupQueue()
    ) throws -> RemoteApprovalRequester {
        try RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: macDeviceID,
                macDeviceName: "Alex’s Mac",
                pinnedPhoneDeviceID: phone.deviceID,
                pinnedPhonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: V3SoftwareSigner(key: macKey),
            relay: relay,
            cleanup: cleanup
        )
    }

    func signedRequest(
        macDeviceID: String? = nil,
        by key: P256.Signing.PrivateKey? = nil
    ) throws -> SignedRemoteApprovalRequest {
        try .signed(
            RemoteApprovalRequest(
                macDeviceID: macDeviceID ?? self.macDeviceID,
                macDeviceName: "Alex’s Mac",
                createdAtMilliseconds: currentTimeMilliseconds() - 60_000,
                review: review
            ),
            by: key ?? macKey
        )
    }

    var approval: RemoteApprovalSelection {
        RemoteApprovalSelection(
            scopeOptionID: review.defaultScopeID,
            durationIndex: review.defaultDurationIndex.map(Int.init),
            unlockAnswer: nil
        )
    }
}

private func mailboxEventually(
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

/// `task`'s value, or nil if it has none within `nanoseconds` — then `task` is
/// cancelled — so a regression fails a check instead of hanging the suite.
private func boundedValue(
    _ task: Task<RemoteApprovalRequesterResult, Never>,
    within nanoseconds: UInt64 = 5_000_000_000
) async -> RemoteApprovalRequesterResult? {
    await withTaskGroup(of: RemoteApprovalRequesterResult?.self) { group in
        group.addTask { await task.value }
        group.addTask {
            try? await Task.sleep(nanoseconds: nanoseconds)
            return nil
        }
        let first = await group.next() ?? nil
        if first == nil { task.cancel() }
        group.cancelAll()
        return first
    }
}

private func waitForPublished(
    _ relay: HardenedMailboxRelay,
    number index: Int = 0
) async -> SignedRemoteApprovalRequest? {
    for _ in 0..<600 {
        if let envelope = await relay.publishedRequest(number: index) { return envelope }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return nil
}

// MARK: - Suite

func remoteApprovalMailboxTests() async {
    print("\n# Remote approval mailbox (record names, sweeps, the response slot, the subscription)")
    mailboxRecordNameTests()
    mailboxWithdrawableTests()
    await mailboxSweepTests()
    await mailboxCleanupRetryTests()
    await mailboxResponseSlotTests()
    mailboxSubscriptionTests()
    mailboxDisplayTextTests()
}

/// The guards that stand between a mailbox payload and `CKRecord.ID`, which
/// raises an Objective-C exception (uncatchable in Swift) for an empty name or
/// one over 255 bytes.
private func mailboxRecordNameTests() {
    let id = UUID().uuidString.lowercased()
    let phoneID = UUID().uuidString.lowercased()
    check(RemoteApprovalMailboxName.isCanonicalID(id), "a lowercase UUID is a canonical mailbox ID")
    for (bad, label) in [
        (id.uppercased(), "an upper-cased UUID"),
        ("", "an empty ID"),
        (String(repeating: "a", count: 300), "a 300-character ID"),
        ("{\(id)}", "a braced UUID"),
        (id + "\u{0}", "a UUID with a NUL"),
    ] {
        check(!RemoteApprovalMailboxName.isCanonicalID(bad), "\(label) is not a canonical mailbox ID")
        check(RemoteApprovalMailboxName.request(requestID: bad) == nil,
              "no request record name is formed from \(label)")
        check(RemoteApprovalMailboxName.response(requestID: bad, phoneDeviceID: phoneID) == nil
                && RemoteApprovalMailboxName.response(requestID: id, phoneDeviceID: bad) == nil,
              "no response record name is formed from \(label)")
    }
    check(RemoteApprovalMailboxName.request(requestID: id) == "request-\(id)",
          "a request record is named request-<requestID>")
    check(RemoteApprovalMailboxName.response(requestID: id, phoneDeviceID: phoneID)
            == "response-\(id)-\(phoneID)",
          "a response record is named per phone: response-<requestID>-<phoneDeviceID>")
    check(RemoteApprovalMailboxName.pairingConfirmation(macDeviceID: id.uppercased())
            == "pairing-confirmation-\(id)"
            && RemoteApprovalMailboxName.phoneStatus(phoneDeviceID: phoneID) == "phone-status-\(phoneID)",
          "device-scoped record names keep their lowercase form")
    check(RemoteApprovalMailboxName.pairingConfirmation(macDeviceID: String(repeating: "b", count: 400)) == nil,
          "no pairing-confirmation name is formed from a non-UUID device ID")

    check(RemoteApprovalMailboxName.requestRecord(named: "request-\(id)", holds: id),
          "a request record under its own name holds its request")
    check(!RemoteApprovalMailboxName.requestRecord(named: "request-\(UUID().uuidString.lowercased())", holds: id),
          "a signed request copied under another request's name is dropped")
    check(!RemoteApprovalMailboxName.requestRecord(named: "request-\(id)", holds: id.uppercased()),
          "a payload whose ID differs only in case from its record name is dropped")
    check(!RemoteApprovalMailboxName.requestRecord(named: "request-", holds: ""),
          "a record with an empty request ID is dropped")

    check(RemoteApprovalMailboxName.isUsableRecordName(String(repeating: "a", count: 255)),
          "a 255-byte ASCII record name is usable")
    for (bad, label) in [
        ("", "an empty record name"),
        (String(repeating: "a", count: 256), "a 256-byte record name"),
        ("request-" + String(repeating: "a", count: 100_000), "a 100 KB record name"),
        ("request-\u{0}x", "a record name with a NUL"),
        ("request-é", "a non-ASCII record name"),
        ("request- x", "a record name with a space"),
        ("_request", "a record name starting with an underscore"),
    ] {
        check(!RemoteApprovalMailboxName.isUsableRecordName(bad), "\(label) is not usable")
        do {
            _ = try CloudKitRemoteApprovalRelay.recordID(bad)
            check(false, "the CloudKit relay refuses \(label) with a Swift error instead of raising")
        } catch CloudKitRemoteApprovalError.invalidRecordName {
            check(true, "the CloudKit relay refuses \(label) with a Swift error instead of raising")
        } catch {
            check(false, "the CloudKit relay refuses \(label) with a Swift error instead of raising (\(error))")
        }
    }
    do {
        _ = try CloudKitRemoteApprovalRelay.recordID(nil)
        check(false, "the CloudKit relay refuses a name the builders could not form")
    } catch {
        check(error as? CloudKitRemoteApprovalError == .invalidRecordName,
              "the CloudKit relay refuses a name the builders could not form")
    }
    let name = RemoteApprovalMailboxName.response(requestID: id, phoneDeviceID: phoneID)
    check((try? CloudKitRemoteApprovalRelay.recordID(name))?.recordName == name,
          "the CloudKit relay makes a record ID from a name the builders formed")
}

private func mailboxWithdrawableTests() {
    let world = MailboxWorld()
    do {
        let ours = try world.signedRequest()
        let macKey = world.macKey.publicKey.x963Representation
        check(RemoteApprovalRequester.isWithdrawable(ours, macDeviceID: world.macDeviceID, macPublicKeyX963: macKey),
              "a sweep may withdraw a request this Mac's key signed")
        let forged = try world.signedRequest(by: P256.Signing.PrivateKey())
        check(!RemoteApprovalRequester.isWithdrawable(forged, macDeviceID: world.macDeviceID, macPublicKeyX963: macKey),
              "a sweep leaves a record another key signed in this Mac's name")
        let upper = try rewritingRequestID(ours, to: ours.request.requestID.uppercased())
        check(!RemoteApprovalRequester.isWithdrawable(upper, macDeviceID: world.macDeviceID, macPublicKeyX963: macKey)
                && !RemoteApprovalRequester.isWithdrawable(upper, macDeviceID: world.macDeviceID, macPublicKeyX963: nil),
              "a sweep leaves an upper-cased copy of a request alone, with or without the key")
        let long = try rewritingRequestID(ours, to: String(repeating: "a", count: 300))
        check(!RemoteApprovalRequester.isWithdrawable(long, macDeviceID: world.macDeviceID, macPublicKeyX963: nil),
              "a sweep leaves a record with an oversized request ID alone")
        let empty = try rewritingRequestID(ours, to: "")
        check(!RemoteApprovalRequester.isWithdrawable(empty, macDeviceID: world.macDeviceID, macPublicKeyX963: nil),
              "a sweep leaves a record with an empty request ID alone")
        let theirs = try world.signedRequest(macDeviceID: UUID().uuidString.lowercased())
        check(!RemoteApprovalRequester.isWithdrawable(theirs, macDeviceID: world.macDeviceID, macPublicKeyX963: macKey),
              "a sweep leaves another Mac's request alone")
        check(RemoteApprovalRequester.isWithdrawable(ours, macDeviceID: world.macDeviceID, macPublicKeyX963: nil),
              "without the retired key, a canonical request naming that Mac is withdrawn on its name")
    } catch {
        check(false, "withdrawable-record rules (\(error))")
    }
}

/// The startup sweep and the re-pair sweep, against a mailbox holding hostile
/// records next to a live request and a genuinely stale one.
private func mailboxSweepTests() async {
    let world = MailboxWorld()
    let relay = HardenedMailboxRelay()
    do {
        let requester = try world.requester(relay)
        let live = Task { await requester.requestApproval(for: world.review) }
        guard let liveEnvelope = await waitForPublished(relay) else {
            live.cancel()
            check(false, "the sweep test's live request reaches the mailbox")
            return
        }
        let liveID = liveEnvelope.request.requestID
        let stale = try world.signedRequest()
        let forged = try world.signedRequest(by: P256.Signing.PrivateKey())
        let otherMac = try world.signedRequest(macDeviceID: UUID().uuidString.lowercased())
        let upperLive = try rewritingRequestID(liveEnvelope, to: liveID.uppercased())
        let long = try rewritingRequestID(stale, to: String(repeating: "a", count: 300))
        let empty = try rewritingRequestID(stale, to: "")
        await relay.seed(stale, recordName: "request-\(stale.request.requestID)")
        await relay.seed(forged, recordName: "request-\(forged.request.requestID)")
        await relay.seed(otherMac, recordName: "request-\(otherMac.request.requestID)")
        await relay.seed(upperLive, recordName: "request-\(liveID.uppercased())")
        await relay.seed(long, recordName: "hostile-long")
        await relay.seed(empty, recordName: "hostile-empty")

        await requester.withdrawStaleRequests()
        let deleted = await relay.deleteRequests
        check(deleted == [stale.request.requestID],
              "the startup sweep withdraws exactly the stale request this Mac signed (asked: \(deleted.count))")
        check(await relay.unnameableIDRequested == false,
              "the startup sweep never asks the relay to name a hostile request ID")
        let remaining = await relay.requestRecordNames()
        check(remaining.contains("request-\(liveID)"),
              "an upper-cased copy of a live request does not get the live exchange deleted")
        check(remaining.contains("request-\(forged.request.requestID)")
                && remaining.contains("request-\(otherMac.request.requestID)"),
              "the startup sweep leaves forged and other Macs' records alone")
        check(await requester.isPending(requestID: liveID),
              "the live request is still pending after the sweep")

        // The re-pair sweep for a retired pairing: with its key, only what that
        // key signed; without it, only canonical records naming that Mac.
        let retired = MailboxWorld()
        let retiredRelay = HardenedMailboxRelay()
        let retiredStale = try retired.signedRequest()
        let retiredForged = try retired.signedRequest(by: P256.Signing.PrivateKey())
        await retiredRelay.seed(retiredStale, recordName: "request-\(retiredStale.request.requestID)")
        await retiredRelay.seed(retiredForged, recordName: "request-\(retiredForged.request.requestID)")
        await retiredRelay.seed(try rewritingRequestID(retiredStale, to: String(repeating: "c", count: 300)),
                                recordName: "hostile-long")
        await retiredRelay.seed(try rewritingRequestID(retiredStale, to: ""), recordName: "hostile-empty")
        await RemoteApprovalRequester.withdrawRequests(
            fromMacDeviceID: retired.macDeviceID,
            macPublicKeyX963: retired.macKey.publicKey.x963Representation,
            phoneDeviceID: retired.phone.deviceID,
            relay: retiredRelay
        )
        check(await retiredRelay.deleteRequests == [retiredStale.request.requestID],
              "the re-pair sweep withdraws only what the retired Mac key signed")
        check(await retiredRelay.deletedResponseNames
                == ["response-\(retiredStale.request.requestID)-\(retired.phone.deviceID)"],
              "the re-pair sweep deletes the retired phone's response record with the request")
        await RemoteApprovalRequester.withdrawRequests(
            fromMacDeviceID: retired.macDeviceID,
            macPublicKeyX963: nil,
            phoneDeviceID: nil,
            relay: retiredRelay
        )
        check(await retiredRelay.deleteRequests
                == [retiredStale.request.requestID, retiredForged.request.requestID],
              "without the retired key, the re-pair sweep withdraws canonical records naming that Mac only")
        check(await retiredRelay.unnameableIDRequested == false,
              "the re-pair sweep never asks the relay to name a hostile request ID")

        live.cancel()
        _ = await boundedValue(live)
    } catch {
        check(false, "sweeps against a hostile mailbox (\(error))")
    }
}

/// The response slot: per phone, bound to its request, cleared when refused.
/// A retry schedule fast enough for tests: 5 ms, doubling to 20 ms.
private let fastCleanup = RemoteApprovalRetrySchedule(initialNanoseconds: 5_000_000, maximumNanoseconds: 20_000_000)

/// Counts attempts of a cleanup job that fails a set number of times first.
private actor CleanupAttempts {
    private(set) var count = 0
    private let failures: Int
    init(failing failures: Int) { self.failures = failures }
    func attempt() -> Bool {
        count += 1
        return count > failures
    }
}

/// Mailbox cleanup that did not land is tried again until it does: a stale
/// Approve card on the phone is what the design ethos calls blind-approval
/// training, and a network blip at withdrawal must not leave one for days.
private func mailboxCleanupRetryTests() async {
    let schedule = RemoteApprovalRetrySchedule(initialNanoseconds: 2_000_000_000, maximumNanoseconds: 300_000_000_000)
    check(schedule.delay(beforeRound: 0) == 2_000_000_000 && schedule.delay(beforeRound: 1) == 4_000_000_000
            && schedule.delay(beforeRound: 7) == 256_000_000_000 && schedule.delay(beforeRound: 8) == 300_000_000_000
            && schedule.delay(beforeRound: 10_000) == 300_000_000_000,
          "cleanup retry delays double from their start and stop at their cap")

    // The queue on its own: a failing job is retried until it finishes.
    let queue = RemoteApprovalCleanupQueue(schedule: fastCleanup)
    let flaky = CleanupAttempts(failing: 3)
    await queue.run("flaky") { await flaky.attempt() }
    let retried = await mailboxEventually { await flaky.count == 4 }
    let drained = await mailboxEventually { await queue.pendingJobNames.isEmpty }
    try? await Task.sleep(nanoseconds: 60_000_000)
    let attemptsAfter = await flaky.count
    check(retried && drained && attemptsAfter == 4,
          "a cleanup job that fails is retried until it reports done, then never again (\(attemptsAfter) attempts)")

    // A newer job under the same name replaces the one still waiting.
    let older = CleanupAttempts(failing: 1_000)
    let newer = CleanupAttempts(failing: 0)
    let named = RemoteApprovalCleanupQueue(schedule: fastCleanup)
    await named.run("offer") { await older.attempt() }
    await named.run("offer") { await newer.attempt() }
    let replacedDrained = await mailboxEventually { await named.pendingJobNames.isEmpty }
    try? await Task.sleep(nanoseconds: 60_000_000)
    let olderAttempts = await older.count
    let newerAttempts = await newer.count
    check(replacedDrained && olderAttempts == 1 && newerAttempts == 1,
          "a cleanup queued under a waiting job's name replaces it")

    // retryNow skips a long wait: the relay is evidently back.
    let slow = RemoteApprovalCleanupQueue(schedule: RemoteApprovalRetrySchedule(
        initialNanoseconds: 60_000_000_000, maximumNanoseconds: 60_000_000_000
    ))
    let once = CleanupAttempts(failing: 1)
    await slow.run("sweep") { await once.attempt() }
    let waitingBefore = await slow.pendingJobNames
    await slow.retryNow()
    let retriedNow = await mailboxEventually { await once.count == 2 }
    let slowDrained = await mailboxEventually { await slow.pendingJobNames.isEmpty }
    check(waitingBefore == ["sweep"] && retriedNow && slowDrained,
          "retryNow tries a waiting cleanup at once instead of after its delay")

    // An exchange delete that fails is retried until the request record is gone.
    do {
        let world = MailboxWorld()
        let relay = HardenedMailboxRelay()
        let cleanup = RemoteApprovalCleanupQueue(schedule: fastCleanup)
        let requester = try world.requester(relay, cleanup: cleanup)
        let pending = Task { await requester.requestApproval(for: world.review) }
        guard let published = await waitForPublished(relay) else {
            pending.cancel()
            check(false, "a request reaches the mailbox for the delete-retry test")
            return
        }
        let requestID = published.request.requestID
        await relay.failNextDeletes(2)
        await requester.withdraw(requestID: requestID)
        _ = await boundedValue(pending)
        let gone = await mailboxEventually { await !relay.requestRecordNames().contains("request-\(requestID)") }
        let asks = await relay.deleteRequests.filter { $0 == requestID }.count
        let idle = await mailboxEventually { await cleanup.pendingJobNames.isEmpty }
        check(gone && asks == 3 && idle,
              "a withdrawal whose delete fails is retried until the request leaves the mailbox (\(asks) attempts)")
    } catch {
        check(false, "exchange delete retry (\(error))")
    }

    // The startup sweep runs again until one pass lists and clears the mailbox.
    do {
        let world = MailboxWorld()
        let relay = HardenedMailboxRelay()
        let requester = try world.requester(relay, cleanup: RemoteApprovalCleanupQueue(schedule: fastCleanup))
        let stale = try world.signedRequest()
        await relay.seed(stale, recordName: "request-\(stale.request.requestID)")
        await relay.failNextListings(1)
        await relay.failNextDeletes(1)
        await requester.withdrawStaleRequests()
        let cleared = await mailboxEventually { await relay.requestRecordNames().isEmpty }
        let listings = await relay.listings
        check(cleared && listings >= 3,
              "a startup sweep whose listing or delete fails runs again until the stale prompt is gone (\(listings) listings)")
    } catch {
        check(false, "startup sweep retry (\(error))")
    }

    // The re-pair sweep reports an incomplete pass, so its caller retries it.
    do {
        let retired = MailboxWorld()
        let relay = HardenedMailboxRelay()
        let stale = try retired.signedRequest()
        await relay.seed(stale, recordName: "request-\(stale.request.requestID)")
        await relay.failNextListings(1)
        let unlisted = await RemoteApprovalRequester.withdrawRequests(
            fromMacDeviceID: retired.macDeviceID, macPublicKeyX963: retired.macKey.publicKey.x963Representation,
            phoneDeviceID: retired.phone.deviceID, relay: relay
        )
        await relay.failNextDeletes(1)
        let undeleted = await RemoteApprovalRequester.withdrawRequests(
            fromMacDeviceID: retired.macDeviceID, macPublicKeyX963: retired.macKey.publicKey.x963Representation,
            phoneDeviceID: retired.phone.deviceID, relay: relay
        )
        let complete = await RemoteApprovalRequester.withdrawRequests(
            fromMacDeviceID: retired.macDeviceID, macPublicKeyX963: retired.macKey.publicKey.x963Representation,
            phoneDeviceID: retired.phone.deviceID, relay: relay
        )
        let cleared = await relay.requestRecordNames().isEmpty
        check(!unlisted && !undeleted && complete && cleared,
              "the re-pair sweep reports a pass that could not list or delete as incomplete, and a clean one as done")
    } catch {
        check(false, "re-pair sweep completeness (\(error))")
    }

    // Bytes in the pinned phone's slot that are no response are cleared, and
    // the phone's real answer still lands.
    do {
        let world = MailboxWorld()
        let relay = HardenedMailboxRelay()
        let requester = try world.requester(relay)
        let pending = Task { await requester.requestApproval(for: world.review) }
        guard let published = await waitForPublished(relay) else {
            pending.cancel()
            check(false, "a request reaches the mailbox for the unreadable-slot test")
            return
        }
        let slot = "response-\(published.request.requestID)-\(world.phone.deviceID)"
        await relay.plantUnreadableResponse(recordName: slot)
        check(await mailboxEventually { await relay.discardedResponseNames.contains(slot) },
              "a response record that does not decode is deleted, not read again on every poll")
        check(await requester.isPending(requestID: published.request.requestID),
              "an unreadable response record neither approves nor denies")
        try await relay.publishResponse(try world.phone.approve(published))
        check(await boundedValue(pending) == .approved(world.approval),
              "after the unreadable record is cleared, the phone's real answer is accepted")
    } catch {
        check(false, "unreadable response record (\(error))")
    }
}

private func mailboxResponseSlotTests() async {
    // Junk in the pinned phone's slot is refused, cleared, and does not stop
    // the phone's real answer.
    do {
        let world = MailboxWorld()
        let relay = HardenedMailboxRelay()
        let requester = try world.requester(relay)
        let pending = Task { await requester.requestApproval(for: world.review) }
        guard let published = await waitForPublished(relay) else {
            pending.cancel()
            check(false, "a request reaches the mailbox for the response-slot test")
            return
        }
        let requestID = published.request.requestID
        let slot = "response-\(requestID)-\(world.phone.deviceID)"
        let junk = try world.phone.approve(published).replacingSignature(with: P256.Signing.PrivateKey())
        await relay.plantResponse(junk, recordName: slot)
        check(await mailboxEventually { await relay.discardedResponseNames.contains(slot) },
              "a record in the pinned phone's slot that does not verify is deleted by the Mac")
        check(await requester.isPending(requestID: requestID),
              "a refused record in the slot neither approves nor denies")
        try await relay.publishResponse(try world.phone.approve(published))
        check(await boundedValue(pending) == .approved(world.approval),
              "the phone's real answer lands in the cleared slot and is accepted")
        check(await mailboxEventually { await relay.responseRecordNames().isEmpty },
              "withdrawing the answered exchange deletes the phone's response record")
        check(await relay.deletedResponseNames.contains(slot),
              "the exchange delete names the pinned phone's response record")
    } catch {
        check(false, "junk in the response slot (\(error))")
    }

    // Another phone's answer lives in its own slot, which the Mac never reads.
    do {
        let world = MailboxWorld()
        let relay = HardenedMailboxRelay()
        let requester = try world.requester(relay)
        let pending = Task { await requester.requestApproval(for: world.review) }
        guard let published = await waitForPublished(relay) else {
            pending.cancel()
            check(false, "a request reaches the mailbox for the other-phone test")
            return
        }
        let stranger = SyntheticPhone()
        try await relay.publishResponse(try stranger.approve(published))
        let strangerSlot = "response-\(published.request.requestID)-\(stranger.deviceID)"
        try? await Task.sleep(nanoseconds: 300_000_000)
        let reads = await relay.responseReads
        check(!reads.isEmpty && !reads.contains(strangerSlot),
              "the Mac polls only its pinned phone's response record")
        check(await relay.responseRecord(strangerSlot) != nil,
              "another phone's record does not occupy the pinned phone's slot")
        try await relay.publishResponse(try world.phone.respond(to: published, .deny))
        if case .denied? = await boundedValue(pending) {
            check(true, "the pinned phone still answers while another phone's record exists")
        } else {
            check(false, "the pinned phone still answers while another phone's record exists")
        }
    } catch {
        check(false, "another phone's response (\(error))")
    }

    // A valid answer to one request, copied into another request's slot, must
    // not end that other wait — and must not use up the first request's answer.
    do {
        let world = MailboxWorld()
        let relay = HardenedMailboxRelay()
        let requester = try world.requester(relay)
        let first = Task { await requester.requestApproval(for: world.review) }
        guard let firstEnvelope = await waitForPublished(relay, number: 0) else {
            first.cancel()
            check(false, "the first request reaches the mailbox for the cross-request test")
            return
        }
        let second = Task { await requester.requestApproval(for: world.review) }
        guard let secondEnvelope = await waitForPublished(relay, number: 1) else {
            first.cancel(); second.cancel()
            check(false, "the second request reaches the mailbox for the cross-request test")
            return
        }
        let firstApproval = try world.phone.approve(firstEnvelope)
        let secondSlot = "response-\(secondEnvelope.request.requestID)-\(world.phone.deviceID)"
        await relay.plantResponse(firstApproval, recordName: secondSlot)
        check(await mailboxEventually { await relay.discardedResponseNames.contains(secondSlot) },
              "an answer to another request found in a request's slot is refused and cleared")
        check(await requester.isPending(requestID: secondEnvelope.request.requestID),
              "an answer to another request does not approve the request whose slot it sits in")
        check(await requester.isPending(requestID: firstEnvelope.request.requestID),
              "the copied answer is not spent on the request it really answers")
        try await relay.publishResponse(firstApproval)
        check(await boundedValue(first) == .approved(world.approval),
              "the request the phone really approved is still approved by its own answer")
        second.cancel()
        check(await boundedValue(second) == .unavailable,
              "the other request ends only when its own wait ends")
    } catch {
        check(false, "an answer copied across requests (\(error))")
    }
}

/// `ensureSubscriptions` keeps an existing subscription only when it is
/// exactly the expected one; anything else under any of its IDs is replaced.
private func mailboxSubscriptionTests() {
    typealias Relay = CloudKitRemoteApprovalRelay
    let request = Relay.makeRequestSubscription()
    let alert = Relay.makeAlertSubscription()
    let settled = Relay.makeSettledSubscription()
    check(Relay.isExpectedSubscription(request) && Relay.isExpectedSubscription(alert)
            && Relay.isExpectedSubscription(settled),
          "all three subscriptions the phone saves are the ones it expects")
    check(settled.recordType == Relay.requestRecordType
            && settled.querySubscriptionOptions == [.firesOnRecordDeletion]
            && settled.notificationInfo?.shouldSendContentAvailable == true
            && settled.notificationInfo?.shouldSendMutableContent == false
            && settled.notificationInfo?.alertBody == nil
            && settled.notificationInfo?.title == nil
            && settled.notificationInfo?.soundName == nil
            && !(settled.notificationInfo?.shouldBadge ?? true),
          "a request record deleted only wakes the app: no alert, no sound, no badge of its own")
    check(Set([request, alert, settled].map(\.subscriptionID)).count == 3,
          "the three subscriptions have IDs of their own")
    check(request.notificationInfo?.shouldSendContentAvailable == true
            && request.notificationInfo?.alertBody == nil
            && request.notificationInfo?.title == nil
            && request.notificationInfo?.soundName == nil,
          "a new request only wakes the app: it shows no alert of its own")
    check(alert.recordType == Relay.alertRecordType
            && alert.notificationInfo?.shouldSendMutableContent == true
            && alert.notificationInfo?.title == RemoteApprovalNotificationText.unverified.title
            && alert.notificationInfo?.alertBody == RemoteApprovalNotificationText.unverified.body,
          "the alert fires on the alert record, with the fixed text the extension may replace")

    // Every other query subscription on a csec record type is stray: an older
    // version's, or one another client saved to copy fields into pushes.
    let planted = CKQuerySubscription(
        recordType: Relay.requestRecordType, predicate: NSPredicate(value: true),
        subscriptionID: "planted-request-copy", options: [.firesOnRecordCreation]
    )
    let leaky = CKSubscription.NotificationInfo()
    leaky.desiredKeys = ["payload"]
    planted.notificationInfo = leaky
    let older = CKQuerySubscription(
        recordType: "CSECApprovalRequestV2", predicate: NSPredicate(value: true),
        subscriptionID: "csec-approval-requests-v2", options: [.firesOnRecordCreation]
    )
    let unrelated = CKQuerySubscription(
        recordType: "Users", predicate: NSPredicate(value: true),
        subscriptionID: "someone-elses", options: [.firesOnRecordCreation]
    )
    check(Relay.straySubscriptionIDs([request, alert, settled, planted, older, unrelated])
            == ["csec-approval-requests-v2", "planted-request-copy"],
          "subscriptions on csec record types other than the three installed are deleted; those three and others are kept")

    func variant(
        of make: () -> CKQuerySubscription,
        _ change: (CKSubscription.NotificationInfo) -> Void
    ) -> CKQuerySubscription {
        let subscription = make()
        let info = subscription.notificationInfo ?? CKSubscription.NotificationInfo()
        change(info)
        subscription.notificationInfo = info
        return subscription
    }
    for (name, make, recordType, id) in [
        ("request", Relay.makeRequestSubscription, Relay.requestRecordType, Relay.requestSubscriptionID),
        ("alert", Relay.makeAlertSubscription, Relay.alertRecordType, Relay.alertSubscriptionID),
        ("settled", Relay.makeSettledSubscription, Relay.requestRecordType, Relay.settledSubscriptionID),
    ] as [(String, () -> CKQuerySubscription, String, String)] {
        let variants: [(String, CKSubscription)] = [
            ("copies the request payload into the push", variant(of: make) { $0.desiredKeys = ["payload"] }),
            ("shows other alert text", variant(of: make) { $0.alertBody = "Approve now: tap Approve." }),
            ("shows another title", variant(of: make) { $0.title = "Apple ID" }),
            ("adds a subtitle", variant(of: make) { $0.subtitle = "urgent" }),
            ("formats the alert from record fields", variant(of: make) {
                $0.alertLocalizationKey = "%@"
                $0.alertLocalizationArgs = ["payload"]
            }),
            ("badges the icon", variant(of: make) { $0.shouldBadge = true }),
            ("is not a content-available wake-up", variant(of: make) { $0.shouldSendContentAvailable = false }),
            ("has no notification at all", {
                let subscription = make()
                subscription.notificationInfo = nil
                return subscription
            }()),
            ("fires on other record changes", CKQuerySubscription(
                recordType: recordType,
                predicate: NSPredicate(value: true),
                subscriptionID: id,
                options: [.firesOnRecordCreation, .firesOnRecordUpdate]
            )),
            ("watches another record type", CKQuerySubscription(
                recordType: Relay.responseRecordType,
                predicate: NSPredicate(value: true),
                subscriptionID: id,
                options: [.firesOnRecordCreation]
            )),
            ("matches only some records", CKQuerySubscription(
                recordType: recordType,
                predicate: NSPredicate(format: "deviceID == %@", "x"),
                subscriptionID: id,
                options: [.firesOnRecordCreation]
            )),
            ("is a zone subscription", CKRecordZoneSubscription(
                zoneID: CKRecordZone.default().zoneID,
                subscriptionID: id
            )),
        ]
        for (label, subscription) in variants {
            check(!Relay.isExpectedSubscription(subscription),
                  "an existing \(name) subscription that \(label) is replaced")
        }
    }
    check(!Relay.isExpectedSubscription(variant(of: Relay.makeRequestSubscription) {
        $0.alertBody = RemoteApprovalNotificationText.unverified.body
    }), "a request subscription that alerts at once, ahead of the Mac's alert, is replaced")
    check(!Relay.isExpectedSubscription(variant(of: Relay.makeAlertSubscription) {
        $0.shouldSendMutableContent = false
    }), "an alert subscription the extension could not rewrite is replaced")
    check(!Relay.isExpectedSubscription(variant(of: Relay.makeSettledSubscription) {
        $0.alertBody = RemoteApprovalNotificationText.unverified.body
    }), "a settled subscription that raises an alert of its own is replaced")
    for options: CKQuerySubscription.Options in [
        [.firesOnRecordCreation], [.firesOnRecordCreation, .firesOnRecordDeletion],
    ] {
        let wrongFiring = CKQuerySubscription(
            recordType: Relay.requestRecordType,
            predicate: NSPredicate(value: true),
            subscriptionID: Relay.settledSubscriptionID,
            options: options
        )
        wrongFiring.notificationInfo = settled.notificationInfo
        check(!Relay.isExpectedSubscription(wrongFiring),
              "a settled subscription that fires on creation (\(options.rawValue)) is replaced")
    }
    let requestUnderSettledID = CKQuerySubscription(
        recordType: Relay.requestRecordType,
        predicate: NSPredicate(value: true),
        subscriptionID: Relay.settledSubscriptionID,
        options: [.firesOnRecordCreation]
    )
    requestUnderSettledID.notificationInfo = request.notificationInfo
    check(!Relay.isExpectedSubscription(requestUnderSettledID),
          "the request subscription saved under the settled subscription's ID is replaced")
    let alertUnderRequestID = CKQuerySubscription(
        recordType: Relay.alertRecordType,
        predicate: NSPredicate(value: true),
        subscriptionID: Relay.requestSubscriptionID,
        options: [.firesOnRecordCreation]
    )
    alertUnderRequestID.notificationInfo = alert.notificationInfo
    check(!Relay.isExpectedSubscription(alertUnderRequestID),
          "the alert subscription saved under the request subscription's ID is replaced")
    let other = CKQuerySubscription(
        recordType: Relay.requestRecordType, predicate: NSPredicate(value: true),
        subscriptionID: "some-other-subscription", options: [.firesOnRecordCreation]
    )
    other.notificationInfo = request.notificationInfo
    check(!Relay.isExpectedSubscription(other), "a subscription under an ID the app does not own is not its own")
}

private func mailboxDisplayTextTests() {
    check(RemoteApprovalDisplayText.sanitized("Alex’s MacBook Pro") == "Alex’s MacBook Pro",
          "an ordinary device name is shown as it is")
    let hostile = "Mac\u{202E}koob\u{2066}\nFake\u{0007}\u{200B}"
    let shown = RemoteApprovalDisplayText.sanitized(hostile)
    check(!shown.unicodeScalars.contains(where: {
        [0x202E, 0x2066, 0x000A, 0x0007, 0x200B].contains($0.value)
    }), "bidi, newline, control and format characters in a device name are neutralized")
    check(shown.unicodeScalars.filter { $0.value == 0xFFFD }.count == 5,
          "each neutralized character stays visible as a replacement character")
}

private extension SignedRemoteApprovalResponse {
    /// The same response, signed by a key that is not the pinned phone's.
    func replacingSignature(with key: P256.Signing.PrivateKey) throws -> SignedRemoteApprovalResponse {
        try .signed(response, by: key)
    }
}
