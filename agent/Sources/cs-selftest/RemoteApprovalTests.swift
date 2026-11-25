import CloudKit
import CryptoKit
import CSECRemoteApproval
import CSECRemoteApprovalCloudKit
import ConvenientSecurity
import Foundation
import CSECBuildIdentity

private actor SoftwareRemoteApprovalSigner: RemoteApprovalRequestSigner {
    let key: P256.Signing.PrivateKey

    init(key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
        self.key = key
    }

    func publicKeyX963Representation() async throws -> Data {
        key.publicKey.x963Representation
    }

    func sign(_ data: Data) async throws -> Data {
        try key.signature(for: data).derRepresentation
    }
}

private actor LoopbackRemoteApprovalRelay: RemoteApprovalRelay {
    let phoneDeviceID: String
    let phoneKey: P256.Signing.PrivateKey
    let decision: RemoteApprovalDecision
    private var storedResponse: SignedRemoteApprovalResponse?
    private var storedRequestID: String?
    private(set) var deleted = false

    init(
        phoneDeviceID: String,
        phoneKey: P256.Signing.PrivateKey,
        decision: RemoteApprovalDecision
    ) {
        self.phoneDeviceID = phoneDeviceID
        self.phoneKey = phoneKey
        self.decision = decision
    }

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        storedRequestID = request.request.requestID
        let review = request.request.review
        let response = RemoteApprovalResponse(
            requestID: request.request.requestID,
            requestDigest: try request.request.digest(),
            phoneDeviceID: phoneDeviceID,
            decision: decision,
            decidedAtMilliseconds: currentTimeMilliseconds(),
            selectedScopeID: decision == .approve ? review.defaultScopeID : nil,
            selectedDurationIndex: decision == .approve ? review.defaultDurationIndex : nil,
            phoneAppVersion: "synthetic"
        )
        storedResponse = try .signed(response, by: phoneKey)
    }

    func response(for requestID: String, phoneDeviceID: String) async throws -> SignedRemoteApprovalResponse? {
        guard storedResponse?.response.requestID == requestID,
              phoneDeviceID == self.phoneDeviceID else { return nil }
        return storedResponse
    }

    func discardResponse(for requestID: String, phoneDeviceID: String) async {}

    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] { [] }

    func requestIsPending(requestID: String) async throws -> Bool {
        storedRequestID == requestID
    }

    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {}

    func publishAlert(requestID: String, macDeviceID: String) async throws {}

    func deleteExchange(requestID: String, phoneDeviceID: String?) async {
        storedResponse = nil
        storedRequestID = nil
        deleted = true
    }

    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation? { nil }
    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws {}
    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? { nil }
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {}
    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {}
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? { nil }
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async {}
}

private enum SyntheticRemoteApprovalError: Error {
    case failed
}

private actor CommitThenFailRemoteApprovalRelay: RemoteApprovalRelay {
    private(set) var deleted = false

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        // Model a transport that commits the record and then reports the relay
        // unusable (the account signed out mid-save). A transient failure would
        // be retried instead; see the publish-retry tests.
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    func response(for requestID: String, phoneDeviceID: String) async throws -> SignedRemoteApprovalResponse? {
        nil
    }

    func discardResponse(for requestID: String, phoneDeviceID: String) async {}
    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] { [] }
    func requestIsPending(requestID: String) async throws -> Bool { false }
    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {}

    func publishAlert(requestID: String, macDeviceID: String) async throws {}

    func deleteExchange(requestID: String, phoneDeviceID: String?) async {
        deleted = true
    }

    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation? { nil }
    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws {}
    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? { nil }
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {}
    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {}
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? { nil }
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async {}
}

/// One in-memory mailbox with the same shape as the CloudKit relay: the Mac
/// saves a request record, each phone saves its response record under its own
/// name, and deleting the request record is the withdrawal marker. Nothing here
/// decides anything — the signed envelopes and the requester's pending table do.
private actor MailboxRemoteApprovalRelay: RemoteApprovalRelay {
    private var requests: [String: SignedRemoteApprovalRequest] = [:]
    /// Keyed by the per-phone record name, `response-<request>-<phone>`.
    private var responses: [String: SignedRemoteApprovalResponse] = [:]
    private(set) var publishedRequestIDs: [String] = []
    private(set) var deletedRequestIDs: [String] = []
    private(set) var discardedResponseNames: [String] = []
    private(set) var pollCount = 0
    private(set) var publishAttempts = 0
    private(set) var attemptedRequestIDs: Set<String> = []
    private var publishFailures: [InjectedRelayFailure] = []
    private var throttledPollsRemaining = 0
    private var throttleRetryAfterNanoseconds: UInt64 = 0
    private var pollsArePermanentlyUnavailable = false

    func throttleNextPolls(_ count: Int, retryAfterNanoseconds: UInt64) {
        throttledPollsRemaining = count
        throttleRetryAfterNanoseconds = retryAfterNanoseconds
    }

    func failPollsPermanently() {
        pollsArePermanentlyUnavailable = true
    }

    func seed(_ envelope: SignedRemoteApprovalRequest) {
        requests[envelope.request.requestID] = envelope
    }

    func storedRequest(_ requestID: String) -> SignedRemoteApprovalRequest? {
        requests[requestID]
    }

    func firstRequest() -> SignedRemoteApprovalRequest? {
        requests.values.first
    }

    func storedRequestIDs() -> Set<String> {
        Set(requests.keys)
    }

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        publishAttempts += 1
        attemptedRequestIDs.insert(request.request.requestID)
        if !publishFailures.isEmpty {
            throw publishFailures.removeFirst().error
        }
        requests[request.request.requestID] = request
        publishedRequestIDs.append(request.request.requestID)
    }

    /// Fail the next publishes, in order, before one is let through.
    func failNextPublishes(_ failures: [InjectedRelayFailure]) {
        publishFailures = failures
    }

    func response(for requestID: String, phoneDeviceID: String) async throws -> SignedRemoteApprovalResponse? {
        pollCount += 1
        if pollsArePermanentlyUnavailable {
            throw RemoteApprovalRelayFailure.permanentlyUnavailable
        }
        if throttledPollsRemaining > 0 {
            throttledPollsRemaining -= 1
            throw RemoteApprovalRelayFailure.throttled(
                retryAfterNanoseconds: throttleRetryAfterNanoseconds
            )
        }
        guard let name = RemoteApprovalMailboxName.response(
            requestID: requestID, phoneDeviceID: phoneDeviceID
        ) else { return nil }
        return responses[name]
    }

    func discardResponse(for requestID: String, phoneDeviceID: String) async {
        guard let name = RemoteApprovalMailboxName.response(
            requestID: requestID, phoneDeviceID: phoneDeviceID
        ) else { return }
        responses.removeValue(forKey: name)
        discardedResponseNames.append(name)
    }

    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] {
        Array(requests.values)
    }

    func requestIsPending(requestID: String) async throws -> Bool {
        requests[requestID] != nil
    }

    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {
        guard let name = RemoteApprovalMailboxName.response(
            requestID: response.response.requestID,
            phoneDeviceID: response.response.phoneDeviceID
        ) else { return }
        responses[name] = response
    }

    /// Put `response` in the slot of `requestID` and `phoneDeviceID`, whatever
    /// it says: what an unauthenticated mailbox writer can do.
    func plantResponse(
        _ response: SignedRemoteApprovalResponse,
        requestID: String,
        phoneDeviceID: String
    ) {
        guard let name = RemoteApprovalMailboxName.response(
            requestID: requestID, phoneDeviceID: phoneDeviceID
        ) else { return }
        responses[name] = response
    }

    func responseSlot(requestID: String, phoneDeviceID: String) -> SignedRemoteApprovalResponse? {
        RemoteApprovalMailboxName.response(requestID: requestID, phoneDeviceID: phoneDeviceID)
            .flatMap { responses[$0] }
    }

    func storedResponseCount() -> Int { responses.count }

    func publishAlert(requestID: String, macDeviceID: String) async throws {}

    func deleteExchange(requestID: String, phoneDeviceID: String?) async {
        requests.removeValue(forKey: requestID)
        if let phoneDeviceID,
           let name = RemoteApprovalMailboxName.response(
               requestID: requestID, phoneDeviceID: phoneDeviceID
           ) {
            responses.removeValue(forKey: name)
        }
        deletedRequestIDs.append(requestID)
    }

    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation? { nil }
    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws {}
    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? { nil }
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {}
    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {}
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? { nil }
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async {}
}

/// A relay failure a fake injects, as the classes the requester tells apart.
private enum InjectedRelayFailure: Sendable {
    case transient
    case unclassified
    case throttled(nanoseconds: UInt64)
    case permanent

    var error: Error {
        switch self {
        case .transient: return RemoteApprovalRelayFailure.transient
        case .unclassified: return SyntheticRemoteApprovalError.failed
        case let .throttled(nanoseconds):
            return RemoteApprovalRelayFailure.throttled(retryAfterNanoseconds: nanoseconds)
        case .permanent: return RemoteApprovalRelayFailure.permanentlyUnavailable
        }
    }
}

/// Polls `condition` until it holds or the deadline passes: for effects that
/// run in the background by design, such as the mailbox delete.
private func eventually(
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

/// A wait that, like a transport already on the wire, finishes whether or not
/// its caller was cancelled.
private func sleepIgnoringCancellation(_ nanoseconds: UInt64) async {
    guard nanoseconds > 0 else { return }
    await Task.detached { try? await Task.sleep(nanoseconds: nanoseconds) }.value
}

/// A mailbox as slow as a bad network, whose operations complete regardless of
/// cancellation. `events` records the order in which records land and leave.
private actor SlowMailboxRemoteApprovalRelay: RemoteApprovalRelay {
    let publishDelay: UInt64
    let responseDelay: UInt64
    let deleteDelay: UInt64
    private var requests: [String: SignedRemoteApprovalRequest] = [:]
    private var responses: [String: SignedRemoteApprovalResponse] = [:]
    private(set) var events: [String] = []

    init(publishDelay: UInt64 = 0, responseDelay: UInt64 = 0, deleteDelay: UInt64 = 0) {
        self.publishDelay = publishDelay
        self.responseDelay = responseDelay
        self.deleteDelay = deleteDelay
    }

    func firstRequest() -> SignedRemoteApprovalRequest? { requests.values.first }
    func storedRequestIDs() -> Set<String> { Set(requests.keys) }

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        await sleepIgnoringCancellation(publishDelay)
        requests[request.request.requestID] = request
        events.append("published")
    }

    func response(for requestID: String, phoneDeviceID: String) async throws -> SignedRemoteApprovalResponse? {
        await sleepIgnoringCancellation(responseDelay)
        guard let response = responses[requestID],
              response.response.phoneDeviceID == phoneDeviceID else { return nil }
        return response
    }

    func discardResponse(for requestID: String, phoneDeviceID: String) async {
        responses.removeValue(forKey: requestID)
    }

    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] {
        Array(requests.values)
    }

    func requestIsPending(requestID: String) async throws -> Bool {
        requests[requestID] != nil
    }

    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {
        responses[response.response.requestID] = response
    }

    func publishAlert(requestID: String, macDeviceID: String) async throws {}

    func deleteExchange(requestID: String, phoneDeviceID: String?) async {
        await sleepIgnoringCancellation(deleteDelay)
        requests.removeValue(forKey: requestID)
        responses.removeValue(forKey: requestID)
        events.append("deleted")
    }

    func pairingConfirmation(macDeviceID: String) async throws -> SignedRemoteApprovalPairingConfirmation? { nil }
    func publishPairingConfirmation(_ confirmation: SignedRemoteApprovalPairingConfirmation) async throws {}
    func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? { nil }
    func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {}
    func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {}
    func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? { nil }
    func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async {}
}

/// Records what the race does with a local approval's evaluated context.
private actor RecordingAuthenticationSession: AccessPolicyAuthenticationSession {
    private(set) var cancelled = false
    private(set) var completed = false

    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        completed = true
        return .approved(unlock: nil)
    }

    func cancel() async {
        cancelled = true
    }
}

/// A local panel whose Touch ID succeeded as the phone answered: it approves
/// after `delayNanoseconds` even though its task was cancelled meanwhile.
private struct LateApprovingLocalReviewer: PolicyReviewProvider {
    let session: RecordingAuthenticationSession
    let delayNanoseconds: UInt64

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        await sleepIgnoringCancellation(delayNanoseconds)
        return .approved(AccessPolicyApproval(authenticationSession: session, decidedOn: .mac))
    }
}

/// In-memory pairing record with the real store's contract: `store` validates,
/// and a failing read throws `.unreadable` like a refused Keychain query.
private actor MemoryRemoteApprovalStore: RemoteApprovalConfigurationStore {
    private var record: StoredRemoteApprovalConfiguration?
    private var unreadableLoadsRemaining = 0
    private var unreadableStatus: Int32 = 0
    private(set) var storeCount = 0
    private(set) var deleteCount = 0

    init(record: StoredRemoteApprovalConfiguration? = nil) {
        self.record = record
    }

    func failNextLoads(_ count: Int, status: Int32) {
        unreadableLoadsRemaining = count
        unreadableStatus = status
    }

    func current() -> StoredRemoteApprovalConfiguration? { record }

    func load() async throws -> StoredRemoteApprovalConfiguration? {
        if unreadableLoadsRemaining > 0 {
            unreadableLoadsRemaining -= 1
            throw RemoteApprovalConfigurationStoreError.unreadable(status: unreadableStatus)
        }
        return record
    }

    func store(_ configuration: StoredRemoteApprovalConfiguration) async throws {
        try configuration.validate()
        storeCount += 1
        record = configuration
    }

    func delete() async throws {
        deleteCount += 1
        record = nil
    }
}

/// The iCloud account as the manager's seam sees it.
private actor RemoteAccountSource {
    private var status: RemoteApprovalAccountStatus
    private(set) var checks = 0

    init(_ status: RemoteApprovalAccountStatus) {
        self.status = status
    }

    func set(_ status: RemoteApprovalAccountStatus) {
        self.status = status
    }

    func current() -> RemoteApprovalAccountStatus {
        checks += 1
        return status
    }
}

/// Counts the Touch IDs the manager spends.
private actor CountingRemoteConsent: ConsentProvider {
    private(set) var authentications = 0

    func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval?,
        policySummary: String?
    ) async -> ConsentOutcome {
        .approved(unlock: nil)
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        authentications += 1
        return .approved(unlock: nil)
    }
}

private final class RemoteLogCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: [String] = []

    func append(_ line: String) {
        lock.lock()
        storage.append(line)
        lock.unlock()
    }

    var lines: [String] {
        lock.lock()
        defer { lock.unlock() }
        return storage
    }
}

/// A signer whose key is present but cannot sign: a Secure Enclave handle that
/// decodes and no longer names a usable key.
private actor NonSigningRemoteApprovalSigner: RemoteApprovalRequestSigner {
    let publicKey: Data

    init(publicKey: Data) {
        self.publicKey = publicKey
    }

    func publicKeyX963Representation() async throws -> Data { publicKey }

    func sign(_ data: Data) async throws -> Data {
        throw SyntheticRemoteApprovalError.failed
    }
}

private let remoteTestContainer = CSECBuildIdentity.cloudKitContainer

/// Software stand-ins for the Secure Enclave pairing key. The handle is the raw
/// private key, which only a test may do.
private func softwareMacKeys() -> RemoteApprovalMacKeys {
    RemoteApprovalMacKeys(
        create: {
            let key = P256.Signing.PrivateKey()
            return (
                SoftwareRemoteApprovalSigner(key: key),
                key.rawRepresentation,
                key.publicKey.x963Representation
            )
        },
        load: { SoftwareRemoteApprovalSigner(key: try P256.Signing.PrivateKey(rawRepresentation: $0)) }
    )
}

private func storedRemoteConfiguration(
    macKey: P256.Signing.PrivateKey,
    phoneKey: P256.Signing.PrivateKey,
    phoneDeviceID: String,
    container: String = remoteTestContainer
) -> StoredRemoteApprovalConfiguration {
    StoredRemoteApprovalConfiguration(
        macDeviceID: UUID().uuidString.lowercased(),
        macDeviceName: "Alex’s Mac",
        macSigningKeyRepresentation: macKey.rawRepresentation,
        macPublicKeyX963: macKey.publicKey.x963Representation,
        phoneDeviceID: phoneDeviceID,
        phoneDeviceName: "Alex’s iPhone",
        phonePublicKeyX963: phoneKey.publicKey.x963Representation,
        phoneKeyAgreementPublicKeyX963: P256.KeyAgreement.PrivateKey().publicKey.x963Representation,
        cloudKitContainerIdentifier: container
    )
}

/// A pairing v2 phone code: the phone's signing key vouches for a fresh
/// key-agreement key.
private func v2PhonePairingCode(
    phoneDeviceID: String,
    phoneDeviceName: String = "Alex’s iPhone",
    phoneKey: P256.Signing.PrivateKey
) throws -> String {
    let keyAgreement = P256.KeyAgreement.PrivateKey().publicKey.x963Representation
    let binding = RemoteApprovalPhonePairing.keyAgreementBindingData(
        phoneDeviceID: phoneDeviceID, phoneKeyAgreementPublicKeyX963: keyAgreement
    )
    return try RemoteApprovalPairingCode.encodePhone(RemoteApprovalPhonePairing(
        phoneDeviceID: phoneDeviceID,
        phoneDeviceName: phoneDeviceName,
        phonePublicKeyX963: phoneKey.publicKey.x963Representation,
        phoneKeyAgreementPublicKeyX963: keyAgreement,
        keyAgreementSignatureDER: try phoneKey.signature(for: binding).derRepresentation,
        appVersion: "1.0 (1)"
    ))
}

/// What a phone that approves as offered selects for `review`.
private func offeredDefaults(_ review: RemoteApprovalReview) -> RemoteApprovalSelection {
    RemoteApprovalSelection(
        scopeOptionID: review.defaultScopeID,
        durationIndex: review.defaultDurationIndex.map(Int.init),
        unlockAnswer: nil
    )
}

private func isUnavailable(_ result: RemoteAccessReviewResult) -> Bool {
    if case .unavailable = result { return true }
    return false
}

private func makeRemoteManager(
    store: MemoryRemoteApprovalStore,
    relay: any RemoteApprovalRelay = MailboxRemoteApprovalRelay(),
    consent: CountingRemoteConsent = CountingRemoteConsent(),
    relayIsConfigured: Bool = true,
    account: RemoteAccountSource = RemoteAccountSource(.available),
    macKeys: RemoteApprovalMacKeys = softwareMacKeys(),
    log: RemoteLogCapture = RemoteLogCapture()
) -> RemoteApprovalManager {
    RemoteApprovalManager(
        store: store,
        relay: relay,
        consent: consent,
        cloudKitContainerIdentifier: remoteTestContainer,
        relayIsConfigured: relayIsConfigured,
        accountStatus: { await account.current() },
        macKeys: macKeys,
        log: { log.append($0) }
    )
}

/// Sign the decision the pinned phone would sign, at an arbitrary wall-clock
/// moment, so a test can answer minutes or hours after the prompt appeared.
private func phoneDecision(
    for envelope: SignedRemoteApprovalRequest,
    phoneDeviceID: String,
    phoneKey: P256.Signing.PrivateKey,
    decision: RemoteApprovalDecision,
    decidedAtMilliseconds: UInt64
) throws -> SignedRemoteApprovalResponse {
    try .signed(
        RemoteApprovalResponse(
            requestID: envelope.request.requestID,
            requestDigest: try envelope.request.digest(),
            phoneDeviceID: phoneDeviceID,
            decision: decision,
            decidedAtMilliseconds: decidedAtMilliseconds,
            selectedScopeID: decision == .approve ? envelope.request.review.defaultScopeID : nil,
            selectedDurationIndex: decision == .approve ? envelope.request.review.defaultDurationIndex : nil,
            phoneAppVersion: "synthetic"
        ),
        by: phoneKey
    )
}

private func waitForPublishedRequest(
    _ relay: MailboxRemoteApprovalRelay
) async -> SignedRemoteApprovalRequest? {
    for _ in 0..<400 {
        if let envelope = await relay.firstRequest() { return envelope }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return nil
}

private func waitForWithdrawal(
    _ relay: MailboxRemoteApprovalRelay,
    requestID: String
) async -> Bool {
    for _ in 0..<400 {
        if await relay.deletedRequestIDs.contains(requestID) { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return false
}

private actor FailingLoadRemoteApprovalStore: RemoteApprovalConfigurationStore {
    let deletionFails: Bool
    private(set) var deleteAttempts = 0

    init(deletionFails: Bool) {
        self.deletionFails = deletionFails
    }

    func load() async throws -> StoredRemoteApprovalConfiguration? {
        throw SyntheticRemoteApprovalError.failed
    }

    func store(_ configuration: StoredRemoteApprovalConfiguration) async throws {}

    func delete() async throws {
        deleteAttempts += 1
        if deletionFails { throw SyntheticRemoteApprovalError.failed }
    }
}

private actor StubRemotePolicyReviewer: RemoteAccessPolicyReviewProvider {
    let result: RemoteAccessReviewResult
    let readiness: RemoteReviewReadiness
    let delayNanoseconds: UInt64
    private(set) var reviewCount = 0
    private(set) var readinessCount = 0

    init(
        result: RemoteAccessReviewResult,
        readiness: RemoteReviewReadiness = .ready(unlock: .notNeeded),
        delayNanoseconds: UInt64 = 0
    ) {
        self.result = result
        self.readiness = readiness
        self.delayNanoseconds = delayNanoseconds
    }

    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        readinessCount += 1
        return readiness
    }

    func reviewRemoteAccess(
        _ review: RemoteApprovalReview,
        unlock: RemoteUnlockUse
    ) async -> RemoteAccessReviewResult {
        reviewCount += 1
        if delayNanoseconds > 0 {
            try? await Task.sleep(nanoseconds: delayNanoseconds)
        }
        return result
    }
}

private let phoneApproved = RemoteAccessReviewResult.approved(selection: remoteApprovalNoSelection, unlock: nil)

private struct DelayedLocalPolicyReviewer: PolicyReviewProvider {
    let outcome: AccessPolicyReviewOutcome
    let delayNanoseconds: UInt64

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        if delayNanoseconds > 0 {
            do {
                try await Task.sleep(nanoseconds: delayNanoseconds)
            } catch {
                return .denied(.requesterGone)
            }
        }
        return outcome
    }
}

private func remoteReviewFixture() -> RemoteApprovalReview {
    v3AccessReviewFixture(withRestore: false)
}

private func localReviewFixture(reference: String = "op://Development/Database/password") -> AccessPolicyReview {
    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(
            canonicalPath: "/usr/bin/ruby",
            assurance: .independentlyProtected
        ),
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 900,
        operationContext: "run migrations"
    )
    return AccessPolicyReview(
        caller: CallerInfo(pid: 42, startTime: 7, description: "ruby"),
        reason: "run migrations",
        plan: plan,
        credentials: [PolicyReviewCredential(references: [try! SecretRef(reference)])]
    )
}

func remoteApprovalTests() async {
    check(!CloudKitRemoteApprovalRelay.isEntitled(containerIdentifiers: []),
          "a build without CloudKit entitlements does not authorize relay construction")
    check(CloudKitRemoteApprovalRelay.isEntitled(containerIdentifiers: [
        CloudKitRemoteApprovalRelay.defaultContainerIdentifier
    ]), "the exact signed CloudKit container authorizes the optional relay")
    check(CloudKitRemoteApprovalRelay.makeIfEntitled(containerIdentifiers: []) == nil,
          "an ordinary build never calls CKContainer without its entitlement")

    // The account-status read is bounded so a wedged account service cannot
    // hang `csec remote status`, doctor, or pairing; the bound decides nothing.
    let fastAnswer = await CloudKitRemoteApprovalRelay.firstAnswer(
        within: 2_000_000_000, otherwise: RemoteApprovalAccountStatus.unavailable(.couldNotDetermine)
    ) { RemoteApprovalAccountStatus.available }
    check(fastAnswer == .available,
          "an account-status read that returns in time is reported as read")
    let slowStarted = ContinuousClock.now
    let slowAnswer = await CloudKitRemoteApprovalRelay.firstAnswer(
        within: 50_000_000, otherwise: RemoteApprovalAccountStatus.unavailable(.couldNotDetermine)
    ) {
        // A read that ignores cancellation and never comes back in time.
        let end = ContinuousClock.now + .seconds(3)
        while ContinuousClock.now < end { usleep(10_000) }
        return RemoteApprovalAccountStatus.available
    }
    let slowElapsed = ContinuousClock.now - slowStarted
    check(slowAnswer == .unavailable(.couldNotDetermine) && slowElapsed < .seconds(1),
          "a wedged account-status read becomes a transient could-not-determine within its bound (\(slowElapsed))")

    print("\n# Remote approval (signed, transaction-bound, waits; synthetic keys only)")

    let macKey = P256.Signing.PrivateKey()
    let phoneKey = P256.Signing.PrivateKey()
    let otherPhoneKey = P256.Signing.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()
    let phoneDeviceID = UUID().uuidString.lowercased()
    let now = currentTimeMilliseconds()
    let review = remoteReviewFixture()

    do {
        let restoredSoftwarePhoneKey = try P256.Signing.PrivateKey(
            rawRepresentation: phoneKey.rawRepresentation
        )
        check(
            restoredSoftwarePhoneKey.publicKey.x963Representation
                == phoneKey.publicKey.x963Representation,
            "the simulator-only software P-256 identity round-trips through its stored form"
        )
        try review.validate()
        let request = RemoteApprovalRequest(
            macDeviceID: macDeviceID,
            macDeviceName: "Alex’s Mac",
            createdAtMilliseconds: now,
            review: review
        )
        let signedRequest = try SignedRemoteApprovalRequest.signed(request, by: macKey)
        try signedRequest.verify(
            macPublicKeyX963: macKey.publicKey.x963Representation,
            at: now
        )
        check(true, "a Mac signature verifies the exact frozen remote review")

        let wrongReview = RemoteReviewParts.changing(remoteReviewFixture()) {
            $0.headline = "different operation"
        }
        let mutated = SignedRemoteApprovalRequest(
            request: RemoteApprovalRequest(
                requestID: request.requestID,
                macDeviceID: request.macDeviceID,
                macDeviceName: request.macDeviceName,
                createdAtMilliseconds: request.createdAtMilliseconds,
                review: wrongReview
            ),
            signatureDER: signedRequest.signatureDER
        )
        do {
            try mutated.verify(
                macPublicKeyX963: macKey.publicKey.x963Representation,
                at: now
            )
            check(false, "changing phone-visible review copy invalidates the Mac signature")
        } catch {
            check(true, "changing phone-visible review copy invalidates the Mac signature")
        }

        let response = RemoteApprovalResponse(
            requestID: request.requestID,
            requestDigest: try request.digest(),
            phoneDeviceID: phoneDeviceID,
            decision: .approve,
            decidedAtMilliseconds: now + 1_000,
            selectedScopeID: review.defaultScopeID,
            selectedDurationIndex: review.defaultDurationIndex,
            phoneAppVersion: "synthetic"
        )
        let signedResponse = try SignedRemoteApprovalResponse.signed(response, by: phoneKey)
        try signedResponse.verify(
            for: request,
            pinnedPhoneDeviceID: phoneDeviceID,
            phonePublicKeyX963: phoneKey.publicKey.x963Representation
        )
        check(true, "the pinned phone signature approves only its exact request digest")

        do {
            try signedResponse.verify(
                for: request,
                pinnedPhoneDeviceID: phoneDeviceID,
                phonePublicKeyX963: otherPhoneKey.publicKey.x963Representation
            )
            check(false, "an unpinned phone key cannot approve")
        } catch {
            check(true, "an unpinned phone key cannot approve")
        }

        // The prompt is the same prompt on a second screen and the local one
        // never auto-dismisses, so a decision taken after a long interruption is
        // still the user's decision.
        let lateResponse = try SignedRemoteApprovalResponse.signed(
            RemoteApprovalResponse(
                requestID: request.requestID,
                requestDigest: try request.digest(),
                phoneDeviceID: phoneDeviceID,
                decision: .approve,
                decidedAtMilliseconds: now + 3 * 60 * 60 * 1_000,
                selectedScopeID: review.defaultScopeID,
                selectedDurationIndex: review.defaultDurationIndex,
                phoneAppVersion: "synthetic"
            ),
            by: phoneKey
        )
        try lateResponse.verify(
            for: request,
            pinnedPhoneDeviceID: phoneDeviceID,
            phonePublicKeyX963: phoneKey.publicKey.x963Representation
        )
        check(true, "a phone decision hours after the prompt is still bound to its request")

        // The one timestamp bound that remains: a decision cannot predate the
        // request it claims to answer by more than the allowed clock skew.
        let prematureResponse = try SignedRemoteApprovalResponse.signed(
            RemoteApprovalResponse(
                requestID: request.requestID,
                requestDigest: try request.digest(),
                phoneDeviceID: phoneDeviceID,
                decision: .approve,
                decidedAtMilliseconds: now
                    - RemoteApprovalProtocolV3.allowedClockSkewMilliseconds - 1,
                selectedScopeID: review.defaultScopeID,
                selectedDurationIndex: review.defaultDurationIndex,
                phoneAppVersion: "synthetic"
            ),
            by: phoneKey
        )
        do {
            try prematureResponse.verify(
                for: request,
                pinnedPhoneDeviceID: phoneDeviceID,
                phonePublicKeyX963: phoneKey.publicKey.x963Representation
            )
            check(false, "a decision made before its request cannot approve")
        } catch RemoteApprovalValidationError.invalidTimestamp {
            check(true, "a decision made before its request cannot approve")
        }

        let phoneCode = try v2PhonePairingCode(phoneDeviceID: phoneDeviceID, phoneKey: phoneKey)
        let phonePairing = try RemoteApprovalPairingCode.decodePhone(phoneCode)
        check(try RemoteApprovalPairingCode.encodePhone(phonePairing) == phoneCode
                && phonePairing.phoneDeviceID == phoneDeviceID,
              "the value-free phone pairing code round-trips")
        check(RemoteApprovalPairingCode.publicKeyFingerprint(
            phoneKey.publicKey.x963Representation
        ).count == 16, "pairing shows a stable short public-key fingerprint")
    } catch {
        check(false, "signed remote approval protocol fixtures validate (\(error))")
    }

    do {
        let relay = LoopbackRemoteApprovalRelay(
            phoneDeviceID: phoneDeviceID,
            phoneKey: phoneKey,
            decision: .approve
        )
        let requester = try RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: macDeviceID,
                macDeviceName: "Alex’s Mac",
                pinnedPhoneDeviceID: phoneDeviceID,
                pinnedPhonePublicKeyX963: phoneKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: SoftwareRemoteApprovalSigner(key: macKey),
            relay: relay
        )
        check(await requester.requestApproval(for: review) == .approved(offeredDefaults(review)),
              "the requester accepts a valid loopback phone approval, with the selection the phone signed")
        // The delete runs in the background, after the caller has its answer.
        check(await eventually { await relay.deleted },
              "the requester removes the single-use relay exchange after a decision")
    } catch {
        check(false, "remote requester loopback succeeds (\(error))")
    }

    do {
        let relay = CommitThenFailRemoteApprovalRelay()
        let requester = try RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: macDeviceID,
                macDeviceName: "Alex’s Mac",
                pinnedPhoneDeviceID: phoneDeviceID,
                pinnedPhonePublicKeyX963: phoneKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: SoftwareRemoteApprovalSigner(key: macKey),
            relay: relay
        )
        check(await requester.requestApproval(for: review) == .unavailable,
              "a failed relay publish never becomes an approval")
        check(await eventually { await relay.deleted },
              "a possibly committed failed publish is cleaned up")
    } catch {
        check(false, "remote requester failed-publish cleanup succeeds (\(error))")
    }

    let remoteApproved = RemoteApprovedAuthenticationSession()
    check((await remoteApproved.completeAfterPolicyApproval(policySummary: "synthetic")).isApproved,
          "a verified remote decision completes the existing approval seam")
    check(!(await remoteApproved.completeAfterPolicyApproval(policySummary: "synthetic")).isApproved,
          "a verified remote decision can be consumed only once")

    let fastRemote = StubRemotePolicyReviewer(result: phoneApproved)
    let mirrored = MirroredPolicyReview(
        local: DelayedLocalPolicyReviewer(
            outcome: .denied(.human(decidedAt: .now)),
            delayNanoseconds: 2_000_000_000
        ),
        remote: fastRemote
    )
    if case let .approved(approval) = await mirrored.reviewAccess(localReviewFixture()),
       let session = approval.authenticationSession {
        check((await session.completeAfterPolicyApproval(policySummary: "synthetic")).isApproved,
              "a pinned phone can win the race against the ordinary local prompt")
    } else {
        check(false, "a pinned phone can win the race against the ordinary local prompt")
    }

    let unavailableRemote = StubRemotePolicyReviewer(result: .unavailable)
    let localFallback = MirroredPolicyReview(
        local: DelayedLocalPolicyReviewer(
            outcome: .approved(AccessPolicyApproval()),
            delayNanoseconds: 20_000_000
        ),
        remote: unavailableRemote
    )
    if case .approved = await localFallback.reviewAccess(localReviewFixture()) {
        check(true, "relay unavailability leaves the local approval path working")
    } else {
        check(false, "relay unavailability leaves the local approval path working")
    }

    // Which reviews reach the phone is the remote provider's readiness, never
    // a reference's scheme: the same native review stays local when the phone
    // could not carry it out and is mirrored when it could.
    let notReady = StubRemotePolicyReviewer(result: phoneApproved, readiness: .unavailable)
    let staysLocal = MirroredPolicyReview(
        local: DelayedLocalPolicyReviewer(outcome: .denied(.human(decidedAt: .now)), delayNanoseconds: 0),
        remote: notReady
    )
    if case .denied = await staysLocal.reviewAccess(
        localReviewFixture(reference: "csec://development/API_TOKEN")
    ) {
        let asked = await notReady.readinessCount
        check(await notReady.reviewCount == 0 && asked == 1,
              "a review the phone could not carry out (readiness unavailable) stays on the Mac")
    } else {
        check(false, "a review the phone could not carry out (readiness unavailable) stays on the Mac")
    }
    let readyNative = StubRemotePolicyReviewer(result: phoneApproved, readiness: .ready(unlock: .required))
    let nativeMirrored = MirroredPolicyReview(
        local: DelayedLocalPolicyReviewer(outcome: .denied(.human(decidedAt: .now)), delayNanoseconds: 2_000_000_000),
        remote: readyNative
    )
    if case let .approved(approval) = await nativeMirrored.reviewAccess(
        localReviewFixture(reference: "csec://development/API_TOKEN")
    ) {
        let mirroredCount = await readyNative.reviewCount
        check(approval.decidedOn == .phone && mirroredCount == 1,
              "a native-store review the phone can carry out is mirrored like any other")
    } else {
        check(false, "a native-store review the phone can carry out is mirrored like any other")
    }

    let recoverableStore = FailingLoadRemoteApprovalStore(deletionFails: false)
    let recoverableManager = RemoteApprovalManager(
        store: recoverableStore,
        relay: LoopbackRemoteApprovalRelay(
            phoneDeviceID: phoneDeviceID,
            phoneKey: phoneKey,
            decision: .approve
        ),
        consent: AutoApproveConsent(),
        cloudKitContainerIdentifier: CSECBuildIdentity.cloudKitContainer
    )
    await recoverableManager.prepare()
    check(await recoverableManager.status() == .pairingInvalid(.recordCorrupt),
          "an undecodable pin record is reported as an unusable pairing, not a generic failure")
    do {
        try await recoverableManager.disable(caller: setupCaller)
        check(await recoverableStore.deleteAttempts == 1,
              "opt-out deletes even a corrupt or unreadable pin record")
        check(await recoverableManager.status() == .disabled,
              "successful opt-out clears the unavailable state")
    } catch {
        check(false, "opt-out can recover an unreadable pin record (\(error))")
    }

    let undeletableStore = FailingLoadRemoteApprovalStore(deletionFails: true)
    let undeletableManager = RemoteApprovalManager(
        store: undeletableStore,
        relay: LoopbackRemoteApprovalRelay(
            phoneDeviceID: phoneDeviceID,
            phoneKey: phoneKey,
            decision: .approve
        ),
        consent: AutoApproveConsent(),
        cloudKitContainerIdentifier: CSECBuildIdentity.cloudKitContainer
    )
    await undeletableManager.prepare()
    do {
        try await undeletableManager.disable(caller: setupCaller)
        check(false, "a failed persistent opt-out is reported to the caller")
    } catch {
        check(await undeletableManager.status() == .pairingInvalid(.recordCorrupt),
              "a failed persistent opt-out stays fail-closed instead of appearing disabled")
    }

    do {
        let request = RemoteApprovalConfigurationRequest(
            action: .enable,
            phonePairingCode: "csec-phone-v1:synthetic"
        )
        let encoded = try JSONEncoder().encode(Request.configureRemoteApproval(request))
        let decoded = try JSONDecoder().decode(Request.self, from: encoded)
        if case let .configureRemoteApproval(roundTrip) = decoded {
            check(roundTrip.requestID == request.requestID
                  && roundTrip.action == .enable
                  && roundTrip.phonePairingCode == request.phonePairingCode,
                  "the authenticated local enrollment request round-trips on protocol v2")
        } else {
            check(false, "the authenticated local enrollment request round-trips on protocol v2")
        }
    } catch {
        check(false, "remote enrollment wire fixture round-trips (\(error))")
    }

    await remoteApprovalWaitTests(
        macKey: macKey,
        phoneKey: phoneKey,
        macDeviceID: macDeviceID,
        phoneDeviceID: phoneDeviceID,
        now: now,
        review: review
    )
    let fixture = RemoteRequesterFixture(
        macKey: macKey,
        phoneKey: phoneKey,
        macDeviceID: macDeviceID,
        phoneDeviceID: phoneDeviceID,
        review: review
    )
    await remoteApprovalRaceTests(fixture)
    await remoteApprovalRevocationTests(fixture)
    await remoteApprovalPublishRetryTests(fixture)
    await remoteApprovalReviewBoundsTests()
    await remoteApprovalReadinessTests(fixture)
    remoteApprovalStatusReportTests()
    remoteApprovalCloudKitClassificationTests()
    await remoteApprovalV3Tests()
    await remoteApprovalMailboxTests()
}

/// Keys and identities shared by the requester-level tests.
private struct RemoteRequesterFixture {
    let macKey: P256.Signing.PrivateKey
    let phoneKey: P256.Signing.PrivateKey
    let macDeviceID: String
    let phoneDeviceID: String
    let review: RemoteApprovalReview

    func requester(relay: any RemoteApprovalRelay) throws -> RemoteApprovalRequester {
        try RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: macDeviceID,
                macDeviceName: "Alex’s Mac",
                pinnedPhoneDeviceID: phoneDeviceID,
                pinnedPhonePublicKeyX963: phoneKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: SoftwareRemoteApprovalSigner(key: macKey),
            relay: relay
        )
    }

    func decision(
        for envelope: SignedRemoteApprovalRequest,
        _ decision: RemoteApprovalDecision
    ) throws -> SignedRemoteApprovalResponse {
        try phoneDecision(
            for: envelope,
            phoneDeviceID: phoneDeviceID,
            phoneKey: phoneKey,
            decision: decision,
            decidedAtMilliseconds: currentTimeMilliseconds()
        )
    }

    var phonePairingCode: String {
        get throws { try v2PhonePairingCode(phoneDeviceID: phoneDeviceID, phoneKey: phoneKey) }
    }
}

/// The mirrored request has no lifetime of its own: it is answered by the
/// laptop or the phone, or it is withdrawn (a deadline it carries is only
/// the Mac's own, shown on the card). These cover what replaced the request
/// lifetime — the pending table, single use, and the withdrawal triggers.
private func remoteApprovalWaitTests(
    macKey: P256.Signing.PrivateKey,
    phoneKey: P256.Signing.PrivateKey,
    macDeviceID: String,
    phoneDeviceID: String,
    now: UInt64,
    review: RemoteApprovalReview
) async {
    func makeRequester(
        relay: MailboxRemoteApprovalRelay
    ) throws -> RemoteApprovalRequester {
        try RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: macDeviceID,
                macDeviceName: "Alex’s Mac",
                pinnedPhoneDeviceID: phoneDeviceID,
                pinnedPhonePublicKeyX963: phoneKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: SoftwareRemoteApprovalSigner(key: macKey),
            relay: relay
        )
    }

    do {
        let relay = MailboxRemoteApprovalRelay()
        let requester = try makeRequester(relay: relay)
        let fourHoursAgo = now - 4 * 60 * 60 * 1_000
        let pending = Task {
            await requester.requestApproval(
                for: review,
                nowMilliseconds: fourHoursAgo
            )
        }
        if let published = await waitForPublishedRequest(relay) {
            let decision = try phoneDecision(
                for: published,
                phoneDeviceID: phoneDeviceID,
                phoneKey: phoneKey,
                decision: .approve,
                decidedAtMilliseconds: now
            )
            try await relay.publishResponse(decision)
            check(await pending.value == .approved(offeredDefaults(review)),
                  "a prompt opened hours ago is approved when the phone finally answers")
            check(await waitForWithdrawal(relay, requestID: published.request.requestID),
                  "an answered prompt is withdrawn from the phone")
            check(await requester.isPending(requestID: published.request.requestID) == false,
                  "an answered request stops being pending")
            check(await requester.accept(decision) == .rejected(.alreadyConsumed),
                  "replaying a consumed decision is refused")

            let stranger = try SignedRemoteApprovalRequest.signed(
                RemoteApprovalRequest(
                    macDeviceID: macDeviceID,
                    macDeviceName: "Alex’s Mac",
                    createdAtMilliseconds: now,
                    review: review
                ),
                by: macKey
            )
            let strangerDecision = try phoneDecision(
                for: stranger,
                phoneDeviceID: phoneDeviceID,
                phoneKey: phoneKey,
                decision: .approve,
                decidedAtMilliseconds: now
            )
            check(await requester.accept(strangerDecision) == .rejected(.notPending),
                  "a decision for a request csecd is not waiting on is refused")
        } else {
            pending.cancel()
            check(false, "a mirrored prompt reaches the mailbox for the phone to answer")
        }
    } catch {
        check(false, "a long wait ends in the phone's answer (\(error))")
    }

    do {
        let relay = MailboxRemoteApprovalRelay()
        let requester = try makeRequester(relay: relay)
        // The local window is authoritative and answers first. The task group
        // cancels the mirrored leg, which must take the prompt off the phone.
        let mirrored = MirroredPolicyReview(
            local: DelayedLocalPolicyReviewer(
                outcome: .denied(.human(decidedAt: .now)),
                delayNanoseconds: 300_000_000
            ),
            remote: RequesterRemoteAccessPolicyReviewProvider(requester: requester)
        )
        if case .denied = await mirrored.reviewAccess(localReviewFixture()) {
            let withdrawn = await eventually {
                let published = await relay.publishedRequestIDs
                let deleted = await relay.deletedRequestIDs
                let remaining = await relay.storedRequestIDs()
                return published.count == 1 && deleted == published && remaining.isEmpty
            }
            check(withdrawn,
                  "answering on the Mac withdraws the prompt it published to the phone")
        } else {
            check(false, "answering on the Mac withdraws the prompt it published to the phone")
        }
    } catch {
        check(false, "a local answer withdraws the mirrored prompt (\(error))")
    }

    do {
        let relay = MailboxRemoteApprovalRelay()
        let requester = try makeRequester(relay: relay)
        // Stands in for the requesting client going away: csecd cancels the
        // review, and nothing approvable may be left behind on the phone.
        let pending = Task { await requester.requestApproval(for: review) }
        if let published = await waitForPublishedRequest(relay) {
            pending.cancel()
            check(await pending.value == .unavailable,
                  "a cancelled mirrored leg is unavailable, never an approval")
            check(await waitForWithdrawal(relay, requestID: published.request.requestID),
                  "cancelling the request withdraws the prompt from the phone")
        } else {
            pending.cancel()
            check(false, "cancelling the request withdraws the prompt from the phone")
        }
    } catch {
        check(false, "a cancelled request withdraws its mirrored prompt (\(error))")
    }

    do {
        let relay = MailboxRemoteApprovalRelay()
        let requester = try makeRequester(relay: relay)
        let anHourAgo = now - 60 * 60 * 1_000
        let ours = try SignedRemoteApprovalRequest.signed(
            RemoteApprovalRequest(
                macDeviceID: macDeviceID,
                macDeviceName: "Alex’s Mac",
                createdAtMilliseconds: anHourAgo,
                review: review
            ),
            by: macKey
        )
        let theirs = try SignedRemoteApprovalRequest.signed(
            RemoteApprovalRequest(
                macDeviceID: UUID().uuidString.lowercased(),
                macDeviceName: "Another Mac",
                createdAtMilliseconds: anHourAgo,
                review: review
            ),
            by: macKey
        )
        await relay.seed(ours)
        await relay.seed(theirs)
        await requester.withdrawStaleRequests()
        let remaining = await relay.storedRequestIDs()
        check(!remaining.contains(ours.request.requestID),
              "startup withdraws a prompt this Mac left behind when it stopped waiting")
        check(remaining.contains(theirs.request.requestID),
              "the startup sweep leaves another Mac's live prompt alone")
    } catch {
        check(false, "the startup sweep withdraws this Mac's leftovers (\(error))")
    }

    do {
        let relay = MailboxRemoteApprovalRelay()
        let requester = try makeRequester(relay: relay)
        await relay.throttleNextPolls(3, retryAfterNanoseconds: 60_000_000)
        let pending = Task { await requester.requestApproval(for: review) }
        if let published = await waitForPublishedRequest(relay) {
            try await relay.publishResponse(try phoneDecision(
                for: published,
                phoneDeviceID: phoneDeviceID,
                phoneKey: phoneKey,
                decision: .approve,
                decidedAtMilliseconds: currentTimeMilliseconds()
            ))
            check(await pending.value == .approved(offeredDefaults(review)),
                  "a throttled relay keeps waiting and still accepts the phone's answer")
            check(await relay.pollCount > 3,
                  "throttled polls are retried after the relay's interval, not abandoned")
        } else {
            pending.cancel()
            check(false, "a throttled relay keeps waiting and still accepts the phone's answer")
        }
    } catch {
        check(false, "throttling delays the mirrored leg instead of ending it (\(error))")
    }

    do {
        let relay = MailboxRemoteApprovalRelay()
        let requester = try makeRequester(relay: relay)
        await relay.failPollsPermanently()
        check(await requester.requestApproval(for: review) == .unavailable,
              "a relay this Mac cannot use at all drops back to the local prompt")
        check(await eventually { await relay.deletedRequestIDs.count == 1 },
              "giving up on the relay still withdraws the published prompt")
    } catch {
        check(false, "an unusable relay falls back to local-only (\(error))")
    }

    do {
        let v3Request = RemoteApprovalRequest(
            macDeviceID: macDeviceID,
            macDeviceName: "Alex’s Mac",
            createdAtMilliseconds: now,
            review: review
        )
        let v2Envelope = try SignedRemoteApprovalRequest.signed(v3Request, by: macKey)
        let v1RequestData = try downgradedToV1(
            try JSONEncoder().encode(v2Envelope),
            envelopeKey: "request",
            extraFields: ["expiresAtMilliseconds": now + 90_000]
        )
        let v1Envelope = try JSONDecoder().decode(
            SignedRemoteApprovalRequest.self,
            from: v1RequestData
        )
        do {
            try v1Envelope.verify(
                macPublicKeyX963: macKey.publicKey.x963Representation,
                at: now
            )
            check(false, "a request of an older protocol version is refused rather than parsed")
        } catch RemoteApprovalValidationError.invalidVersion {
            check(true, "a request of an older protocol version is refused rather than parsed")
        }

        let v1ResponseData = try downgradedToV1(
            try JSONEncoder().encode(try phoneDecision(
                for: v2Envelope,
                phoneDeviceID: phoneDeviceID,
                phoneKey: phoneKey,
                decision: .approve,
                decidedAtMilliseconds: now
            )),
            envelopeKey: "response",
            extraFields: [:]
        )
        let v1Response = try JSONDecoder().decode(
            SignedRemoteApprovalResponse.self,
            from: v1ResponseData
        )
        do {
            _ = try v1Response.response.signingData()
            check(false, "a decision of an older protocol version is refused rather than parsed")
        } catch RemoteApprovalValidationError.invalidVersion {
            check(true, "a decision of an older protocol version is refused rather than parsed")
        }
    } catch {
        check(false, "an envelope from an un-upgraded phone app is refused (\(error))")
    }
}

/// Rewrite a signed v2 envelope into the v1 shape an un-upgraded iPhone app
/// would produce or accept, including the request lifetime field v2 removed.
private func downgradedToV1(
    _ encoded: Data,
    envelopeKey: String,
    extraFields: [String: Any]
) throws -> Data {
    guard var object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any],
          var inner = object[envelopeKey] as? [String: Any] else {
        throw SyntheticRemoteApprovalError.failed
    }
    inner["version"] = RemoteApprovalProtocolV3.version - 1
    for (key, value) in extraFields { inner[key] = value }
    object[envelopeKey] = inner
    return try JSONSerialization.data(withJSONObject: object)
}

private func mirroredReviewFixture(
    reason: String = "run migrations",
    commandLine: String? = nil,
    callerDescription: String = "ruby",
    references: [String] = ["op://Development/Database/password"],
    secrets: [ReviewSecret]? = nil
) -> AccessPolicyReview {
    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(
            canonicalPath: "/usr/bin/ruby",
            assurance: .independentlyProtected
        ),
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 900,
        operationContext: "run migrations"
    )
    return AccessPolicyReview(
        caller: CallerInfo(pid: 42, startTime: 7, description: callerDescription),
        reason: reason,
        plan: plan,
        commandLine: commandLine,
        credentials: [secrets.map { secrets in
            PolicyReviewCredential(described: zip(references, secrets).map { (try! SecretRef($0), $1) })
        } ?? PolicyReviewCredential(references: references.map { try! SecretRef($0) })]
    )
}

/// The local prompt and the phone race. The first decision wins; the loser is
/// ended promptly and never left holding anything.
private func remoteApprovalRaceTests(_ fixture: RemoteRequesterFixture) async {
    print("\n# Remote approval race (a local win is prompt; the losing leg is cancelled)")

    do {
        // Each poll and each delete takes seconds and ignores cancellation, as
        // a request already on the wire does. None of it may hold the Mac.
        let relay = SlowMailboxRemoteApprovalRelay(
            responseDelay: 1_500_000_000, deleteDelay: 2_000_000_000
        )
        let requester = try fixture.requester(relay: relay)
        let mirrored = MirroredPolicyReview(
            local: DelayedLocalPolicyReviewer(
                outcome: .approved(AccessPolicyApproval()), delayNanoseconds: 50_000_000
            ),
            remote: RequesterRemoteAccessPolicyReviewProvider(requester: requester)
        )
        let started = ContinuousClock.now
        let outcome = await mirrored.reviewAccess(localReviewFixture())
        let elapsed = started.duration(to: .now)
        var approved = false
        if case .approved = outcome { approved = true }
        check(approved && elapsed < .milliseconds(500),
              "a 50 ms local approval returns at once while the relay's poll and delete take seconds (\(elapsed))")
        if let published = await relay.firstRequest() {
            let requestID = published.request.requestID
            check(!(await requester.isPending(requestID: requestID)),
                  "the phone's request left the pending table before the local approval returned")
            check(await requester.accept(try fixture.decision(for: published, .approve))
                      == .rejected(.notPending),
                  "a phone Approve after the local win is refused as not pending")
            check(await eventually(within: 6_000_000_000) { await relay.storedRequestIDs().isEmpty },
                  "the losing phone prompt is still deleted, in the background")
        } else {
            check(false, "the mirrored prompt reached the slow mailbox")
        }
    } catch {
        check(false, "a local win is not held by relay IO (\(error))")
    }

    do {
        // The save is still on the wire when the local prompt wins.
        let relay = SlowMailboxRemoteApprovalRelay(publishDelay: 1_000_000_000)
        let requester = try fixture.requester(relay: relay)
        let mirrored = MirroredPolicyReview(
            local: DelayedLocalPolicyReviewer(
                outcome: .approved(AccessPolicyApproval()), delayNanoseconds: 50_000_000
            ),
            remote: RequesterRemoteAccessPolicyReviewProvider(requester: requester)
        )
        let started = ContinuousClock.now
        let outcome = await mirrored.reviewAccess(localReviewFixture())
        let elapsed = started.duration(to: .now)
        var approved = false
        if case .approved = outcome { approved = true }
        check(approved && elapsed < .milliseconds(500),
              "a local win does not wait for a save still on the wire (\(elapsed))")
        check(await eventually { await relay.events == ["published", "deleted"] },
              "the withdrawal deletes the prompt only after the late save lands, so none is left behind")
        check(await relay.storedRequestIDs().isEmpty,
              "no approvable prompt remains in the mailbox after a late save")
    } catch {
        check(false, "a late save is withdrawn after it lands (\(error))")
    }

    let lostApproval = RecordingAuthenticationSession()
    let phoneFirst = MirroredPolicyReview(
        local: LateApprovingLocalReviewer(session: lostApproval, delayNanoseconds: 100_000_000),
        remote: StubRemotePolicyReviewer(result: phoneApproved)
    )
    if case let .approved(approval) = await phoneFirst.reviewAccess(localReviewFixture()) {
        check(approval.decidedOn == .phone, "the phone's approval wins when it answers first")
        let lostCancelled = await lostApproval.cancelled
        let lostCompleted = await lostApproval.completed
        check(lostCancelled && !lostCompleted,
              "a local approval that lost the race is cancelled, invalidating its context, not dropped")
    } else {
        check(false, "the phone's approval wins when it answers first")
    }

    let receivedAt = ContinuousClock.now
    let lostToDeny = RecordingAuthenticationSession()
    let phoneDeny = MirroredPolicyReview(
        local: LateApprovingLocalReviewer(session: lostToDeny, delayNanoseconds: 100_000_000),
        remote: StubRemotePolicyReviewer(result: .denied(receivedAt: receivedAt))
    )
    if case let .denied(reason) = await phoneDeny.reviewAccess(localReviewFixture()) {
        check(reason == .human(decidedAt: receivedAt, on: .phone),
              "a verified phone Deny is terminal and ordered by when this Mac received it")
        check(await lostToDeny.cancelled,
              "a local approval that lost to a phone Deny is cancelled too")
    } else {
        check(false, "a verified phone Deny is terminal and ordered by when this Mac received it")
    }

    do {
        let relay = MailboxRemoteApprovalRelay()
        let requester = try fixture.requester(relay: relay)
        let mirrored = MirroredPolicyReview(
            local: DelayedLocalPolicyReviewer(
                outcome: .denied(.authenticationFailed), delayNanoseconds: 100_000_000
            ),
            remote: RequesterRemoteAccessPolicyReviewProvider(requester: requester)
        )
        if case let .denied(reason) = await mirrored.reviewAccess(localReviewFixture()) {
            check(reason == .authenticationFailed,
                  "a local Touch ID failure ends the request instead of leaving it pending on the phone alone")
            let withdrawn = await eventually {
                let published = await relay.publishedRequestIDs
                let deleted = await relay.deletedRequestIDs
                return published.count == 1 && deleted == published
            }
            check(withdrawn, "the phone's copy is withdrawn with the failed local prompt")
        } else {
            check(false, "a local Touch ID failure ends the request instead of leaving it pending on the phone alone")
        }
    } catch {
        check(false, "a local Touch ID failure ends the phone leg (\(error))")
    }
}

/// `csec remote disable` and pairing again end what the old pairing had open.
private func remoteApprovalRevocationTests(_ fixture: RemoteRequesterFixture) async {
    print("\n# Remote approval revocation (disable and re-pairing end in-flight requests)")

    do {
        let relay = MailboxRemoteApprovalRelay()
        let requester = try fixture.requester(relay: relay)
        let pending = Task { await requester.requestApproval(for: fixture.review) }
        if let published = await waitForPublishedRequest(relay) {
            let requestID = published.request.requestID
            let started = ContinuousClock.now
            await requester.revokeAll()
            let result = await pending.value
            check(result == .unavailable && started.duration(to: .now) < .milliseconds(500),
                  "revoking the pairing ends an in-flight mirrored request at once, as unavailable")
            check(!(await requester.isPending(requestID: requestID)),
                  "a revoked request leaves the pending table")
            check(await requester.accept(try fixture.decision(for: published, .approve))
                      == .rejected(.notPending),
                  "a phone Approve after revocation is refused as not pending")
            check(await waitForWithdrawal(relay, requestID: requestID),
                  "revocation deletes the revoked request's mailbox record")
            let again = await requester.requestApproval(for: fixture.review)
            let publishedCount = await relay.publishedRequestIDs.count
            check(again == .unavailable && publishedCount == 1,
                  "a revoked requester never publishes again")
        } else {
            pending.cancel()
            check(false, "revoking the pairing ends an in-flight mirrored request at once, as unavailable")
        }
    } catch {
        check(false, "requester revocation (\(error))")
    }

    do {
        // End to end through the manager. An earlier probe found that a phone
        // Approve after `csec remote disable` still approved this request.
        let store = MemoryRemoteApprovalStore()
        let relay = MailboxRemoteApprovalRelay()
        let manager = makeRemoteManager(store: store, relay: relay)
        _ = try await manager.enable(phonePairingCode: try fixture.phonePairingCode, caller: setupCaller)
        let inFlight = Task { await manager.reviewRemoteAccess(fixture.review, unlock: .notNeeded) }
        if let published = await waitForPublishedRequest(relay) {
            try await manager.disable(caller: setupCaller)
            try await relay.publishResponse(try fixture.decision(for: published, .approve))
            check(isUnavailable(await inFlight.value),
                  "after csec remote disable, a phone Approve no longer approves the request that was in flight")
            check(await waitForWithdrawal(relay, requestID: published.request.requestID),
                  "disable withdraws the in-flight prompt from the phone")
            check(await manager.status() == .disabled, "disable leaves remote approval off")
        } else {
            inFlight.cancel()
            check(false, "after csec remote disable, a phone Approve no longer approves the request that was in flight")
        }
    } catch {
        check(false, "disable revokes in-flight requests (\(error))")
    }

    do {
        let store = MemoryRemoteApprovalStore()
        let relay = MailboxRemoteApprovalRelay()
        let manager = makeRemoteManager(store: store, relay: relay)
        _ = try await manager.enable(phonePairingCode: try fixture.phonePairingCode, caller: setupCaller)
        guard let previous = await store.current() else {
            check(false, "enabling pins a record")
            return
        }
        let previousMacDeviceID = previous.macDeviceID
        // A prompt a crash left under the old Mac ID — signed by that
        // pairing's Mac key — one another key signed in that Mac's name, and
        // another Mac's live one.
        let leftover = try SignedRemoteApprovalRequest.signed(
            RemoteApprovalRequest(
                macDeviceID: previousMacDeviceID,
                macDeviceName: "Alex’s Mac",
                createdAtMilliseconds: currentTimeMilliseconds(),
                review: fixture.review
            ),
            by: try P256.Signing.PrivateKey(rawRepresentation: previous.macSigningKeyRepresentation)
        )
        let forged = try SignedRemoteApprovalRequest.signed(
            RemoteApprovalRequest(
                macDeviceID: previousMacDeviceID,
                macDeviceName: "Alex’s Mac",
                createdAtMilliseconds: currentTimeMilliseconds(),
                review: fixture.review
            ),
            by: fixture.macKey
        )
        await relay.seed(forged)
        let otherMac = try SignedRemoteApprovalRequest.signed(
            RemoteApprovalRequest(
                macDeviceID: UUID().uuidString.lowercased(),
                macDeviceName: "Another Mac",
                createdAtMilliseconds: currentTimeMilliseconds(),
                review: fixture.review
            ),
            by: fixture.macKey
        )
        await relay.seed(leftover)
        await relay.seed(otherMac)
        let inFlight = Task { await manager.reviewRemoteAccess(fixture.review, unlock: .notNeeded) }
        if await eventually({ await relay.publishedRequestIDs.count == 1 }) {
            let inFlightID = await relay.publishedRequestIDs[0]
            let newPhoneKey = P256.Signing.PrivateKey()
            _ = try await manager.enable(phonePairingCode: try v2PhonePairingCode(
                phoneDeviceID: UUID().uuidString.lowercased(),
                phoneDeviceName: "New iPhone",
                phoneKey: newPhoneKey
            ), caller: setupCaller)
            check(isUnavailable(await inFlight.value),
                  "pairing a new phone ends the replaced pairing's in-flight request")
            let swept = await eventually {
                let remaining = await relay.storedRequestIDs()
                return !remaining.contains(inFlightID)
                    && !remaining.contains(leftover.request.requestID)
            }
            check(swept, "re-pairing withdraws every prompt the previous pairing's Mac key signed")
            check(await relay.storedRequestIDs().contains(otherMac.request.requestID),
                  "re-pairing leaves another Mac's prompt alone")
            check(await relay.storedRequestIDs().contains(forged.request.requestID),
                  "re-pairing leaves a record another key signed in the previous Mac's name")
            let newMacDeviceID = await store.current()?.macDeviceID
            check(newMacDeviceID != nil && newMacDeviceID != previousMacDeviceID,
                  "re-pairing mints a new Mac device ID")
            if case let .enabled(phoneName, _) = await manager.status() {
                check(phoneName == "New iPhone", "the new phone is the one enabled")
            } else {
                check(false, "the new phone is the one enabled")
            }
        } else {
            inFlight.cancel()
            check(false, "pairing a new phone ends the replaced pairing's in-flight request")
        }
    } catch {
        check(false, "re-pairing revokes the old pairing (\(error))")
    }
}

/// A publish that fails for a reason polling would wait through is retried the
/// same way, instead of losing the phone for the whole wait.
private func remoteApprovalPublishRetryTests(_ fixture: RemoteRequesterFixture) async {
    print("\n# Remote approval publish retries (a network blip after wake is not a verdict)")

    do {
        let relay = MailboxRemoteApprovalRelay()
        await relay.failNextPublishes([
            .transient, .unclassified, .throttled(nanoseconds: 60_000_000), .transient,
        ])
        let requester = try fixture.requester(relay: relay)
        let pending = Task { await requester.requestApproval(for: fixture.review) }
        if let published = await waitForPublishedRequest(relay) {
            try await relay.publishResponse(try fixture.decision(for: published, .approve))
            check(await pending.value == .approved(offeredDefaults(fixture.review)),
                  "a publish that fails transiently four times still reaches the phone and is approved")
            check(await relay.publishAttempts == 5,
                  "transient, unclassified and throttled publish failures are each retried")
        } else {
            pending.cancel()
            check(false, "a publish that fails transiently four times still reaches the phone and is approved")
        }
    } catch {
        check(false, "transient publish failures are retried (\(error))")
    }

    do {
        let relay = MailboxRemoteApprovalRelay()
        await relay.failNextPublishes(Array(repeating: .transient, count: 1_000))
        let requester = try fixture.requester(relay: relay)
        let pending = Task { await requester.requestApproval(for: fixture.review) }
        let retrying = await eventually { await relay.publishAttempts >= 2 }
        pending.cancel()
        let ended = await pending.value
        check(retrying && ended == .unavailable,
              "a publish that keeps failing is retried until the wait ends, then is unavailable")
        let attempted = await relay.attemptedRequestIDs
        let cleaned = await eventually {
            let deleted = await relay.deletedRequestIDs
            return attempted.count == 1 && attempted.isSubset(of: Set(deleted))
        }
        check(cleaned, "a request whose failed saves may have committed is still withdrawn")
    } catch {
        check(false, "a failing publish ends with its wait (\(error))")
    }

    do {
        let relay = MailboxRemoteApprovalRelay()
        await relay.failNextPublishes([.transient, .permanent])
        let requester = try fixture.requester(relay: relay)
        check(await requester.requestApproval(for: fixture.review) == .unavailable,
              "a relay that turns out to be unusable ends publishing; the local prompt carries the request")
        check(await relay.publishAttempts == 2,
              "a permanent failure is not retried")
    } catch {
        check(false, "a permanent publish failure is final (\(error))")
    }
}

/// Every phone field is sanitized, then fitted with its ellipsis inside the
/// bound, so length and content can no longer keep a request off the phone.
private func remoteApprovalReviewBoundsTests() async {
    print("\n# Remote approval review bounds (long or multi-line requests still mirror)")
    typealias Limit = RemoteApprovalReview.FieldLimit

    func mirrors(_ review: AccessPolicyReview) async -> Bool {
        let remote = StubRemotePolicyReviewer(result: .unavailable)
        let mirrored = MirroredPolicyReview(
            local: DelayedLocalPolicyReviewer(
                outcome: .denied(.human(decidedAt: .now)), delayNanoseconds: 20_000_000
            ),
            remote: remote,
            log: { _ in }
        )
        _ = await mirrored.reviewAccess(review)
        return await remote.reviewCount == 1
    }

    let longArgv = "ruby -e " + String(repeating: "x", count: 2_600)
    let multiLine = "bash -c '" + String(repeating: "echo ok\n", count: 60) + "'"
    check(longArgv.utf8.count == 2_608 && multiLine.utf8.count == 490,
          "fixtures: a 2,608-byte command line and a 490-byte one with 60 newlines")
    do {
        let long = mirroredReviewFixture(commandLine: longArgv)
        let frozen = try RemoteApprovalReview(accessPolicyReview: long)
        check(frozen.headline.utf8.count <= Limit.headline && frozen.headline.hasSuffix("…")
                && frozen.headline.hasPrefix("ruby -e xxx"),
              "a 2,608-byte command line is cut to the 2 KiB headline on the phone, ellipsis included")
        check(await mirrors(long), "a 2,608-byte command line is still mirrored to the phone")

        let lines = mirroredReviewFixture(commandLine: multiLine)
        let frozenLines = try RemoteApprovalReview(accessPolicyReview: lines)
        check(frozenLines.headline == multiLine,
              "a multi-line command keeps its newlines on the phone, as the Mac panel shows it")
        check(await mirrors(lines), "a multi-line command is still mirrored to the phone")

        let hostile = mirroredReviewFixture(
            callerDescription: "evil\u{0000}tool\u{0007}\u{202E}"
                + String(repeating: "\u{0001}", count: 600)
        )
        let frozenHostile = try RemoteApprovalReview(accessPolicyReview: hostile)
        check(frozenHostile.callerDescription.utf8.count <= Limit.callerDescription
                && !frozenHostile.callerDescription.utf8.contains(0)
                && !frozenHostile.callerDescription.unicodeScalars.contains { $0.value == 0x202E },
              "control, NUL and bidi characters in the caller are neutralized before it is bounded")
        check(await mirrors(hostile), "a caller full of control characters is still mirrored")

        let hostileCommand = try RemoteApprovalReview(accessPolicyReview: mirroredReviewFixture(
            commandLine: "echo \u{202E}evil\u{0000}\n\u{0007}"
        ))
        check(!hostileCommand.headline.utf8.contains(0)
                && !hostileCommand.headline.unicodeScalars.contains { $0.value == 0x202E || $0.value == 7 }
                && hostileCommand.headline.contains("\n"),
              "a command's controls and bidi characters are neutralized even though its newlines are kept")

        let longCaller = try RemoteApprovalReview(accessPolicyReview: mirroredReviewFixture(
            callerDescription: String(repeating: "c", count: 2_000)
        ))
        check(longCaller.callerDescription.utf8.count <= Limit.callerDescription
                && longCaller.callerDescription.hasSuffix("…"),
              "a 2,000-byte caller is cut to the caller field's 1,024 bytes")

        let longReason = try RemoteApprovalReview(accessPolicyReview: mirroredReviewFixture(
            reason: String(repeating: "r", count: 5_000)
        ))
        check(longReason.headline.utf8.count <= Limit.headline && !longReason.headline.contains("\n"),
              "a long reason without argv is cut to the 2 KiB headline, on one line")

        let cjkArgv = try RemoteApprovalReview(accessPolicyReview: mirroredReviewFixture(
            commandLine: "echo " + String(repeating: "界", count: 800)
        ))
        check(cjkArgv.headline.utf8.count <= Limit.headline && cjkArgv.headline.hasSuffix("界…"),
              "a CJK command line is cut between characters on the phone")

        let vault = String(repeating: "V", count: 1_500)
        let noted = mirroredReviewFixture(
            references: ["op://\(vault)/Item/password"],
            secrets: [ReviewSecret(
                provider: "1Password", tint: .teal, account: String(repeating: "界", count: 400),
                container: vault, item: "Item", field: String(repeating: "f", count: 2_000),
                notes: [String(repeating: "n", count: 2_000)],
                warnings: [String(repeating: "é", count: 800)]
            )]
        )
        let frozenNoted = try RemoteApprovalReview(accessPolicyReview: noted)
        let secret = frozenNoted.secrets.first
        check((secret?.account?.utf8.count ?? .max) <= Limit.secretAccount
                && (secret?.container?.utf8.count ?? .max) <= Limit.secretContainer
                && (secret?.field?.utf8.count ?? .max) <= Limit.secretField
                && secret?.notes.count == 1 && secret?.warnings.count == 1
                && (secret?.notes.first?.utf8.count ?? .max) <= Limit.secretNote
                && (secret?.warnings.first?.utf8.count ?? .max) <= Limit.secretNote,
              "a long account, vault, field and provider note and warning each fit their own fields")
        check(await mirrors(noted), "a secret with long provider context is still mirrored")

        let longItem = try RemoteApprovalReview(accessPolicyReview: mirroredReviewFixture(
            references: ["op://Vault/" + String(repeating: "i", count: 5_000) + "/password"]
        ))
        check((longItem.secrets.first?.item.utf8.count ?? .max) <= Limit.secretItem,
              "a 5,000-byte whole reference fits the secret item's 4,096 bytes")
    } catch {
        check(false, "long and multi-line reviews build for the phone (\(error))")
    }

    let cjk = ReviewDisplay.fitted(String(repeating: "界", count: 200), maxBytes: 512)
    check(cjk == String(repeating: "界", count: 169) + "…" && cjk.utf8.count == 510,
          "a three-byte script is cut at a character boundary with the ellipsis inside the budget")
    let emoji = ReviewDisplay.fitted(String(repeating: "👍🏽", count: 100), maxBytes: 512)
    check(emoji == String(repeating: "👍🏽", count: 63) + "…" && emoji.utf8.count <= 512,
          "an emoji and its skin-tone modifier are never split")
    let exact = String(repeating: "a", count: 512)
    check(ReviewDisplay.fitted(exact, maxBytes: 512) == exact,
          "a value that already fits is left whole")
    check(ReviewDisplay.fitted("a\nb", maxBytes: 4) == "a…",
          "a newline's three-byte replacement counts against the budget")
    check(ReviewDisplay.fitted("para\n\nnext", maxBytes: 64, allowNewlines: true) == "para\n\nnext",
          "csec's own warning keeps its paragraph break on the phone")
    check(ReviewDisplay.bounded("abcdef", maxBytes: 4) == "abc…",
          "the Mac panel's bounded() keeps its existing semantics")

    let log = RemoteLogCapture()
    let crowdedRemote = StubRemotePolicyReviewer(result: phoneApproved)
    let crowded = MirroredPolicyReview(
        local: DelayedLocalPolicyReviewer(
            outcome: .denied(.human(decidedAt: .now)), delayNanoseconds: 0
        ),
        remote: crowdedRemote,
        log: { log.append($0) }
    )
    _ = await crowded.reviewAccess(mirroredReviewFixture(
        references: (0..<65).map { "op://Vault/Item/field\($0)" }
    ))
    check(await crowdedRemote.reviewCount == 0,
          "a review with more references than the phone format carries stays on the Mac")
    check(log.lines.count == 1 && log.lines[0].contains("65 references")
            && !log.lines[0].contains("op://"),
          "csecd logs why, value-free, instead of skipping the phone silently")
}

/// Readiness is specific, logged, re-checked where it can change, and never
/// costs a Touch ID for nothing.
private func remoteApprovalReadinessTests(_ fixture: RemoteRequesterFixture) async {
    print("\n# Remote approval readiness (specific causes, retried when transient)")
    let macKey = P256.Signing.PrivateKey()
    let fingerprint = RemoteApprovalPairingCode.publicKeyFingerprint(
        fixture.phoneKey.publicKey.x963Representation
    )
    let enabled = RemoteApprovalManagerStatus.enabled(
        phoneName: "Alex’s iPhone", phoneKeyFingerprint: fingerprint
    )
    func pinned(container: String = remoteTestContainer) -> StoredRemoteApprovalConfiguration {
        storedRemoteConfiguration(
            macKey: macKey,
            phoneKey: fixture.phoneKey,
            phoneDeviceID: fixture.phoneDeviceID,
            container: container
        )
    }

    do {
        let store = MemoryRemoteApprovalStore()
        let consent = CountingRemoteConsent()
        let account = RemoteAccountSource(.available)
        let log = RemoteLogCapture()
        let manager = makeRemoteManager(
            store: store, relay: UnavailableRemoteApprovalRelay(), consent: consent,
            relayIsConfigured: false, account: account, log: log
        )
        await manager.prepare()
        check(await manager.status() == .unsupportedBuild,
              "a build without the CloudKit entitlement reports unsupportedBuild")
        check(log.lines.count == 1 && log.lines[0].contains("CloudKit container entitlement"),
              "prepare logs the value-free cause")
        try await manager.disable(caller: setupCaller)
        let unpairedTouches = await consent.authentications
        let unpairedDeletes = await store.deleteCount
        check(unpairedTouches == 0 && unpairedDeletes == 0,
              "disable with nothing paired on an unsupported build spends no Touch ID")
        do {
            _ = try await manager.enable(phonePairingCode: try fixture.phonePairingCode, caller: setupCaller)
            check(false, "enabling on an unsupported build fails before the Touch ID")
        } catch RemoteApprovalManagerError.unsupportedBuild {
            check(await consent.authentications == 0,
                  "enabling on an unsupported build fails before the Touch ID")
        }
        check(await account.checks == 0, "an unsupported build never asks iCloud anything")
    } catch {
        check(false, "unsupported build readiness (\(error))")
    }

    do {
        let store = MemoryRemoteApprovalStore(record: pinned())
        let consent = CountingRemoteConsent()
        let manager = makeRemoteManager(
            store: store, relay: UnavailableRemoteApprovalRelay(), consent: consent,
            relayIsConfigured: false
        )
        await manager.prepare()
        try await manager.disable(caller: setupCaller)
        let leftoverTouches = await consent.authentications
        let leftoverDeletes = await store.deleteCount
        check(leftoverTouches == 1 && leftoverDeletes == 1,
              "a pairing record an earlier build left is removed on an unsupported build, behind one Touch ID")
    } catch {
        check(false, "an unsupported build can still remove an old pairing (\(error))")
    }

    do {
        let store = MemoryRemoteApprovalStore()
        let consent = CountingRemoteConsent()
        let account = RemoteAccountSource(.available)
        let manager = makeRemoteManager(store: store, consent: consent, account: account)
        await manager.prepare()
        check(await manager.status() == .disabled, "no pinned phone reads as disabled")
        try await manager.disable(caller: setupCaller)
        check(await consent.authentications == 0, "disable with nothing paired spends no Touch ID")
        check(await account.checks == 0, "with no pinned phone, csecd asks iCloud nothing")
    } catch {
        check(false, "unpaired readiness (\(error))")
    }

    do {
        let store = MemoryRemoteApprovalStore(record: pinned())
        let relay = MailboxRemoteApprovalRelay()
        let account = RemoteAccountSource(.available)
        let log = RemoteLogCapture()
        let manager = makeRemoteManager(store: store, relay: relay, account: account, log: log)
        await manager.prepare()
        check(await manager.status() == enabled,
              "a usable pairing with iCloud available is enabled")
        _ = await manager.status()
        check(log.lines.filter { $0.contains("on (phone key \(fingerprint))") }.count == 1,
              "readiness is logged once per change, not on every status check")
        await account.set(.unavailable(.noAccount))
        check(await manager.status() == .iCloudAccountUnavailable(
                .noAccount, phoneName: "Alex’s iPhone", phoneKeyFingerprint: fingerprint
              ),
              "enabled rechecks iCloud: a sign-out shows without waiting for a notification")
        let signedOutResult = await manager.reviewRemoteAccess(fixture.review, unlock: .notNeeded)
        let signedOutPublished = await relay.publishedRequestIDs
        check(isUnavailable(signedOutResult) && signedOutPublished.isEmpty,
              "a request while signed out stays local without publishing into an account that cannot take it")
        var eachClassReported = true
        for problem in RemoteApprovalAccountProblem.allCases {
            await account.set(.unavailable(problem))
            let reported = await manager.status()
            eachClassReported = eachClassReported && reported == .iCloudAccountUnavailable(
                problem, phoneName: "Alex’s iPhone", phoneKeyFingerprint: fingerprint
            )
        }
        check(eachClassReported, "each iCloud account class is reported as itself")
        await account.set(.available)
        await manager.accountDidChange()
        check(await manager.status() == enabled,
              "an account change back to available re-enables without re-pairing")
        let recheckStores = await store.storeCount
        let recheckDeletes = await store.deleteCount
        check(recheckStores == 0 && recheckDeletes == 0,
              "rechecking readiness never rewrites or deletes the pinned record")
    } catch {
        check(false, "iCloud account readiness (\(error))")
    }

    do {
        let stored = pinned()
        let store = MemoryRemoteApprovalStore(record: stored)
        let relay = MailboxRemoteApprovalRelay()
        let leftover = try SignedRemoteApprovalRequest.signed(
            RemoteApprovalRequest(
                macDeviceID: stored.macDeviceID,
                macDeviceName: "Alex’s Mac",
                createdAtMilliseconds: currentTimeMilliseconds(),
                review: fixture.review
            ),
            by: macKey
        )
        await relay.seed(leftover)
        let account = RemoteAccountSource(.unavailable(.noAccount))
        let manager = makeRemoteManager(store: store, relay: relay, account: account)
        await manager.prepare()
        _ = await manager.status()
        check(await relay.storedRequestIDs().contains(leftover.request.requestID),
              "the stale-prompt sweep waits for an iCloud account that can carry it")
        await account.set(.available)
        await manager.accountDidChange()
        check(await eventually {
                  !(await relay.storedRequestIDs().contains(leftover.request.requestID))
              },
              "signing in sweeps the prompts this Mac left behind")
    } catch {
        check(false, "the stale sweep follows the account (\(error))")
    }

    do {
        let store = MemoryRemoteApprovalStore(record: pinned())
        await store.failNextLoads(2, status: -25308)
        let log = RemoteLogCapture()
        let manager = makeRemoteManager(store: store, log: log)
        await manager.prepare()
        check(await manager.status() == .keychainUnavailable(status: -25308),
              "a refused Keychain read is reported with its OSStatus, not as a broken pairing")
        check(log.lines.contains { $0.contains("OSStatus -25308") },
              "the refused read is logged, value-free")
        check(await manager.status() == enabled,
              "the next status check reads the record again and recovers")
        let transientStores = await store.storeCount
        let transientDeletes = await store.deleteCount
        check(transientStores == 0 && transientDeletes == 0,
              "a transient read failure never deletes or replaces the pinned record")

        let changed = MemoryRemoteApprovalStore(record: pinned())
        await changed.failNextLoads(1, status: -25308)
        let afterChange = makeRemoteManager(store: changed)
        await afterChange.prepare()
        await afterChange.accountDidChange()
        check(await afterChange.status() == enabled,
              "an iCloud account change retries a refused Keychain read")

        let requested = MemoryRemoteApprovalStore(record: pinned())
        await requested.failNextLoads(1, status: -25308)
        let relay = MailboxRemoteApprovalRelay()
        let onRequest = makeRemoteManager(store: requested, relay: relay)
        await onRequest.prepare()
        let pending = Task { await onRequest.reviewRemoteAccess(fixture.review, unlock: .notNeeded) }
        check(await waitForPublishedRequest(relay) != nil,
              "a request retries a refused Keychain read and is mirrored")
        pending.cancel()
        _ = await pending.value

        let working = MemoryRemoteApprovalStore(record: pinned())
        let steady = makeRemoteManager(store: working)
        await steady.prepare()
        _ = await steady.status()
        await working.failNextLoads(1, status: -25308)
        await steady.prepare()
        check(await steady.status() == enabled,
              "a refused re-read never tears down a working pairing")
    }

    let otherKey = P256.Signing.PrivateKey()
    let invalidCases: [(RemoteApprovalPairingProblem, StoredRemoteApprovalConfiguration, RemoteApprovalMacKeys)] = [
        (.containerMismatch, pinned(container: "iCloud.com.example.other"), softwareMacKeys()),
        (.macKeyMissing, pinned(), RemoteApprovalMacKeys(
            create: { throw SyntheticRemoteApprovalError.failed },
            load: { _ in throw SyntheticRemoteApprovalError.failed }
        )),
        (.macKeyMismatch, pinned(), RemoteApprovalMacKeys(
            create: { throw SyntheticRemoteApprovalError.failed },
            load: { _ in SoftwareRemoteApprovalSigner(key: otherKey) }
        )),
        (.macKeyMissing, pinned(), RemoteApprovalMacKeys(
            create: { throw SyntheticRemoteApprovalError.failed },
            load: { _ in NonSigningRemoteApprovalSigner(publicKey: macKey.publicKey.x963Representation) }
        )),
    ]
    for (problem, record, keys) in invalidCases {
        do {
            let store = MemoryRemoteApprovalStore(record: record)
            let consent = CountingRemoteConsent()
            let account = RemoteAccountSource(.available)
            let log = RemoteLogCapture()
            let manager = makeRemoteManager(
                store: store, consent: consent, account: account, macKeys: keys, log: log
            )
            await manager.prepare()
            check(await manager.status() == .pairingInvalid(problem),
                  "an unusable pairing is reported as \(problem.rawValue)")
            check(log.lines.count == 1 && log.lines[0].contains(problem.rawValue)
                    && log.lines[0].contains("csec remote disable"),
                  "\(problem.rawValue) is logged with its fix")
            check(await account.checks == 0,
                  "\(problem.rawValue) is not retried against iCloud: waiting cannot fix it")
            try await manager.disable(caller: setupCaller)
            let invalidTouches = await consent.authentications
            let invalidDeletes = await store.deleteCount
            let afterDisable = await manager.status()
            check(invalidTouches == 1 && invalidDeletes == 1 && afterDisable == .disabled,
                  "disable removes a \(problem.rawValue) record behind one Touch ID")
        } catch {
            check(false, "\(problem.rawValue) readiness (\(error))")
        }
    }

    do {
        let store = MemoryRemoteApprovalStore()
        let controlName = String(repeating: "n", count: 200) + String(repeating: "\u{0007}", count: 20)
        let code = try v2PhonePairingCode(
            phoneDeviceID: fixture.phoneDeviceID, phoneDeviceName: controlName, phoneKey: fixture.phoneKey
        )
        let manager = makeRemoteManager(store: store)
        _ = try await manager.enable(phonePairingCode: code, caller: setupCaller)
        let name = await store.current()?.phoneDeviceName ?? ""
        check(controlName.utf8.count == 220 && !name.isEmpty && name.utf8.count <= 256
                && !name.unicodeScalars.contains { $0.value == 7 },
              "a phone name whose control characters sanitize past 256 bytes is bounded after sanitizing")
    } catch {
        check(false, "a phone name whose control characters sanitize past 256 bytes is bounded after sanitizing (\(error))")
    }

    do {
        let consent = CountingRemoteConsent()
        let manager = makeRemoteManager(
            store: MemoryRemoteApprovalStore(),
            consent: consent,
            account: RemoteAccountSource(.unavailable(.noAccount))
        )
        _ = try await manager.enable(phonePairingCode: try fixture.phonePairingCode, caller: setupCaller)
        check(false, "enabling while signed out of iCloud names the account problem, before the Touch ID")
    } catch RemoteApprovalManagerError.iCloudAccountUnavailable(.noAccount) {
        check(true, "enabling while signed out of iCloud names the account problem, before the Touch ID")
    } catch {
        check(false, "enabling while signed out of iCloud names the account problem (\(error))")
    }
}

/// The csecd wire, `csec remote status`, and the doctor row keep each cause.
private func remoteApprovalStatusReportTests() {
    print("\n# Remote approval status reporting (wire, csec remote status, doctor)")
    let fingerprint = "0011223344556677"
    var statuses: [RemoteApprovalManagerStatus] = [
        .disabled,
        .enabled(phoneName: "Alex’s iPhone", phoneKeyFingerprint: fingerprint),
        .unsupportedBuild,
        .keychainUnavailable(status: -25308),
    ]
    statuses += RemoteApprovalAccountProblem.allCases.map {
        .iCloudAccountUnavailable($0, phoneName: "Alex’s iPhone", phoneKeyFingerprint: fingerprint)
    }
    statuses += RemoteApprovalPairingProblem.allCases.map { .pairingInvalid($0) }
    do {
        var roundTrips = true
        var codes = Set<String>()
        for status in statuses {
            let wire = RemoteApprovalConfigurationStatus(status)
            let decoded = try JSONDecoder().decode(
                RemoteApprovalConfigurationStatus.self, from: JSONEncoder().encode(wire)
            )
            roundTrips = roundTrips && decoded == wire
            codes.insert("\(wire.state.rawValue)/\(wire.cause?.rawValue ?? "")/\(wire.detail?.rawValue ?? "")")
        }
        check(roundTrips && codes.count == statuses.count,
              "every readiness cause crosses the csecd wire as its own code")
        let future = try JSONDecoder().decode(
            RemoteApprovalConfigurationStatus.self,
            from: Data(#"{"state":"unavailable","cause":"future_cause","detail":"future_detail"}"#.utf8)
        )
        check(future.state == .unavailable && future.cause == nil && future.detail == nil,
              "a cause this csec does not know reads as absent instead of failing the response")
    } catch {
        check(false, "remote readiness wire round trip (\(error))")
    }

    typealias Report = RemoteApprovalStatusReport
    let unsupported = Report.summary(.init(.unsupportedBuild))
    check(!unsupported.succeeded && unsupported.lines.joined().contains("Convenient Security package"),
          "csec remote status fails an unsupported build and names the installer")
    let invalid = Report.summary(.init(.pairingInvalid(.macKeyMissing)))
    check(!invalid.succeeded && invalid.lines.joined().contains("csec remote disable")
            && invalid.lines.joined().contains("Secure Enclave pairing key is gone"),
          "csec remote status fails an unusable pairing, says why, and says to disable and pair again")
    let signedOut = Report.summary(.init(.iCloudAccountUnavailable(
        .noAccount, phoneName: "Alex’s iPhone", phoneKeyFingerprint: fingerprint
    )))
    check(signedOut.succeeded && signedOut.lines.joined().contains("sign into iCloud")
            && signedOut.lines.joined().contains("Alex’s iPhone"),
          "csec remote status tells a signed-out Mac to sign into iCloud, naming the paired phone")
    let keychain = Report.summary(.init(.keychainUnavailable(status: -25308)))
    check(keychain.succeeded && keychain.lines.joined().contains("transient")
            && keychain.lines.joined().contains("-25308"),
          "csec remote status calls a refused Keychain read transient and gives its OSStatus")
    check(Report.summary(.init(.disabled)).succeeded
            && Report.summary(.init(.enabled(phoneName: "P", phoneKeyFingerprint: fingerprint))).succeeded,
          "off and on both succeed")
    check(!Report.summary(RemoteApprovalConfigurationStatus(state: .unavailable)).succeeded,
          "an unavailable status with no cause, from an older csecd, is not reported as fine")

    check(Report.doctorRow(.init(.disabled), developmentEndpoint: false).state == .neutral,
          "doctor: not paired is neutral")
    check(Report.doctorRow(.init(.enabled(phoneName: "P", phoneKeyFingerprint: fingerprint)),
                           developmentEndpoint: false).state == .ok,
          "doctor: on is OK")
    check(Report.doctorRow(.init(.unsupportedBuild), developmentEndpoint: false).state == .bad
            && Report.failsDoctor(.init(.unsupportedBuild), developmentEndpoint: false)
            && Report.doctorRepair(.init(.unsupportedBuild))?.contains("Convenient Security package") == true,
          "doctor: a build without the CloudKit entitlement fails and names the installer")
    check(Report.doctorRow(.init(.unsupportedBuild), developmentEndpoint: true).state == .neutral
            && !Report.failsDoctor(.init(.unsupportedBuild), developmentEndpoint: true),
          "doctor: an unsigned development csecd is not failed for lacking the entitlement")
    check(Report.doctorRow(.init(.iCloudAccountUnavailable(
              .noAccount, phoneName: "P", phoneKeyFingerprint: fingerprint
          )), developmentEndpoint: false).state == .warn
            && !Report.failsDoctor(.init(.iCloudAccountUnavailable(
                .noAccount, phoneName: "P", phoneKeyFingerprint: fingerprint
            )), developmentEndpoint: false),
          "doctor: iCloud unavailable while paired warns")
    check(Report.doctorRow(.init(.pairingInvalid(.recordCorrupt)), developmentEndpoint: false).state == .bad
            && Report.failsDoctor(.init(.pairingInvalid(.recordCorrupt)), developmentEndpoint: false)
            && Report.doctorRepair(.init(.pairingInvalid(.recordCorrupt)))?
                .contains("csec remote disable") == true,
          "doctor: an unusable pairing fails and names the fix")
    check(Report.doctorRow(.init(.keychainUnavailable(status: -25308)), developmentEndpoint: false).state == .warn
            && !Report.failsDoctor(.init(.keychainUnavailable(status: -25308)), developmentEndpoint: false),
          "doctor: a refused Keychain read warns")
    check(Report.doctorRow(nil, developmentEndpoint: false).state == .neutral
            && !Report.failsDoctor(nil, developmentEndpoint: false),
          "doctor: an unreachable agent is left to its own row")
}

/// Which CloudKit failures the requester waits through, and each account class.
private func remoteApprovalCloudKitClassificationTests() {
    print("\n# CloudKit relay failure and account classification")
    func classified(_ code: CKError.Code, retryAfter: Double? = nil) -> RemoteApprovalRelayFailure? {
        var userInfo: [String: Any] = [:]
        if let retryAfter { userInfo[CKErrorRetryAfterKey] = NSNumber(value: retryAfter) }
        return CloudKitRemoteApprovalRelay.relayFailure(
            for: CKError(code, userInfo: userInfo)
        ) as? RemoteApprovalRelayFailure
    }
    let transientCodes: [CKError.Code] = [
        .networkUnavailable, .networkFailure, .serverResponseLost, .accountTemporarilyUnavailable,
    ]
    check(transientCodes.allSatisfy { classified($0) == .transient },
          "network loss and a not-yet-ready account are transient: retried on the poll interval")
    let throttledCodes: [CKError.Code] = [.requestRateLimited, .zoneBusy, .serviceUnavailable]
    check(throttledCodes.allSatisfy { classified($0) == .throttled(retryAfterNanoseconds: 0) },
          "server throttling without a hint waits one poll interval")
    check(classified(.serviceUnavailable, retryAfter: 5)
              == .throttled(retryAfterNanoseconds: 5_000_000_000),
          "a server retry-after hint is honoured")
    let permanentCodes: [CKError.Code] = [
        .notAuthenticated, .managedAccountRestricted, .permissionFailure, .badContainer,
        .badDatabase, .missingEntitlement, .incompatibleVersion, .invalidArguments, .quotaExceeded,
    ]
    check(permanentCodes.allSatisfy { classified($0) == .permanentlyUnavailable },
          "what no retry fixes, signed-out iCloud and an unindexed query field included, ends the phone leg")
    check(classified(.unknownItem) == nil,
          "an unrecognised CloudKit code passes through for the requester to treat as a blip")
    check(CloudKitRemoteApprovalRelay.relayFailure(for: SyntheticRemoteApprovalError.failed)
              is SyntheticRemoteApprovalError,
          "a non-CloudKit error passes through unchanged")

    let accounts: [(CKAccountStatus, RemoteApprovalAccountStatus)] = [
        (.available, .available),
        (.noAccount, .unavailable(.noAccount)),
        (.restricted, .unavailable(.restricted)),
        (.couldNotDetermine, .unavailable(.couldNotDetermine)),
        (.temporarilyUnavailable, .unavailable(.temporarilyUnavailable)),
    ]
    check(accounts.allSatisfy { CloudKitRemoteApprovalRelay.approvalAccountStatus(for: $0.0) == $0.1 },
          "each CloudKit account status keeps its own class")
}
