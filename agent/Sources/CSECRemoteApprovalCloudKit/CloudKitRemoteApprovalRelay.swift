import CloudKit
import CSECRemoteApproval
import Foundation
import CSECBuildIdentity

/// CloudKit private-database mailbox for value-free approval envelopes. Record
/// ownership and iCloud identity are useful transport isolation, but never an
/// authorization signal: callers must verify the P-256 envelopes themselves.
public actor CloudKitRemoteApprovalRelay: RemoteApprovalRelay {
    /// Record types and the subscription move with the protocol version. Builds
    /// of different versions therefore never read each other's mailbox at all,
    /// instead of one of them decoding a shape it does not understand.
    public static let requestRecordType = "CSECApprovalRequestV3"
    public static let responseRecordType = "CSECApprovalResponseV3"
    public static let pairingConfirmationRecordType = "CSECPairingConfirmationV3"
    public static let phoneStatusRecordType = "CSECPhoneStatusV3"
    /// `pairing-offer-<phoneDeviceID>`: the Mac's signed offer to the phone
    /// it pinned, read by that phone while its app is open.
    public static let pairingOfferRecordType = "CSECPairingOfferV3"
    /// `alert-<requestID>`: created once the phone should be alerted to a
    /// request already in the mailbox. It holds no request field.
    public static let alertRecordType = "CSECApprovalAlertV3"
    /// Silent: wakes the phone app to show a new request's card.
    public static let requestSubscriptionID = "csec-approval-requests-v3"
    /// Visible: the alert, which the notification service extension rewrites
    /// from the verified request.
    public static let alertSubscriptionID = "csec-approval-alerts-v3"
    /// Silent: a request record deleted — the Mac stopped waiting on it —
    /// wakes the phone app to take its card, alert and badge count off.
    public static let settledSubscriptionID = "csec-approval-settled-v3"
    public static let defaultContainerIdentifier =
        CSECBuildIdentity.cloudKitContainer

    private static let payloadField = "payload"
    private static let deviceIDField = "deviceID"
    private static let maximumEnvelopeBytes = 256 * 1_024

    private let container: CKContainer
    private let database: CKDatabase
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    /// `CKContainer(identifier:)` terminates the process when the signed binary
    /// does not carry the named iCloud-container entitlement. Callers must gate
    /// construction from their verified signing information; an unavailable
    /// optional transport must never crash the resident credential agent.
    public static func isEntitled(
        containerIdentifiers: [String],
        containerIdentifier: String = defaultContainerIdentifier
    ) -> Bool {
        containerIdentifiers.contains(containerIdentifier)
    }

    public static func makeIfEntitled(
        containerIdentifiers: [String],
        containerIdentifier: String = defaultContainerIdentifier
    ) -> CloudKitRemoteApprovalRelay? {
        guard isEntitled(
            containerIdentifiers: containerIdentifiers,
            containerIdentifier: containerIdentifier
        ) else { return nil }
        return CloudKitRemoteApprovalRelay(containerIdentifier: containerIdentifier)
    }

    public init(
        containerIdentifier: String = CloudKitRemoteApprovalRelay.defaultContainerIdentifier
    ) {
        let container = CKContainer(identifier: containerIdentifier)
        self.container = container
        self.database = container.privateCloudDatabase
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        self.encoder = encoder
        self.decoder = JSONDecoder()
    }

    public func accountStatus() async throws -> CKAccountStatus {
        try await container.accountStatus()
    }

    /// Posted when the signed-in iCloud account changes: a sign-in, a
    /// sign-out, or an account becoming ready. A paired Mac rechecks its
    /// readiness on it rather than trusting what it read at startup.
    public nonisolated static var accountChangedNotification: Notification.Name {
        .CKAccountChanged
    }

    /// How long an account-status read may take before it counts as "could
    /// not determine". `csec remote status`, `csec doctor` and pairing all wait
    /// on this read, and a wedged system account service would otherwise hang
    /// them. The bound decides nothing: "could not determine" is transient, and
    /// the next status check, request or account change asks again.
    public static let accountStatusBoundNanoseconds: UInt64 = 5_000_000_000

    /// The current account in the protocol module's vocabulary. A failure to
    /// read the status, or a read that does not return within
    /// `accountStatusBoundNanoseconds`, is itself "could not determine":
    /// asking again can work.
    public func approvalAccountStatus() async -> RemoteApprovalAccountStatus {
        let container = self.container
        return await Self.firstAnswer(
            within: Self.accountStatusBoundNanoseconds,
            otherwise: .unavailable(.couldNotDetermine)
        ) {
            do {
                return Self.approvalAccountStatus(for: try await container.accountStatus())
            } catch {
                return .unavailable(.couldNotDetermine)
            }
        }
    }

    /// `operation`'s result, or `fallback` once `bound` passes first
    /// (`RemoteApprovalBound.firstAnswer`).
    public static func firstAnswer<Value: Sendable>(
        within bound: UInt64,
        otherwise fallback: Value,
        _ operation: @escaping @Sendable () async -> Value
    ) async -> Value {
        await RemoteApprovalBound.firstAnswer(within: bound, otherwise: fallback, operation)
    }

    public static func approvalAccountStatus(
        for status: CKAccountStatus
    ) -> RemoteApprovalAccountStatus {
        switch status {
        case .available: return .available
        case .noAccount: return .unavailable(.noAccount)
        case .restricted: return .unavailable(.restricted)
        case .couldNotDetermine: return .unavailable(.couldNotDetermine)
        case .temporarilyUnavailable: return .unavailable(.temporarilyUnavailable)
        @unknown default: return .unavailable(.couldNotDetermine)
        }
    }

    public func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        let record = try requestRecord(for: request)
        do {
            _ = try await database.save(record)
        } catch let error as CKError where error.code == .serverRecordChanged {
            // The record name embeds a UUID this process just minted, so an
            // existing record under it can only be an earlier save of this same
            // request whose reply was lost. The prompt is already published.
            return
        } catch {
            throw Self.relayFailure(for: error)
        }
    }

    /// Overwrites the record with the same envelope. CloudKit stamps every
    /// save with the server's modification date, which is what the phone
    /// reads (`RemoteApprovalLiveness`); no field of the record changes, so
    /// the schema needs nothing new. The request subscription fires on
    /// creation only, so a refresh wakes no phone, unless something other
    /// than this Mac deleted the record, when it is put back as the request
    /// it still is.
    public func refreshRequest(_ request: SignedRemoteApprovalRequest) async throws {
        try await saveOverwriting(try requestRecord(for: request))
    }

    private func requestRecord(for request: SignedRemoteApprovalRequest) throws -> CKRecord {
        let data: Data
        let recordID: CKRecord.ID
        do {
            data = try encodeBounded(request)
            recordID = try Self.recordID(
                RemoteApprovalMailboxName.request(requestID: request.request.requestID)
            )
        } catch {
            // The same envelope encodes and names the same way on every
            // attempt, so a request that cannot be encoded, does not fit, or
            // has no usable record name is never going to publish. Retrying
            // it would only poll a failure.
            throw RemoteApprovalRelayFailure.permanentlyUnavailable
        }
        let record = CKRecord(recordType: Self.requestRecordType, recordID: recordID)
        record[Self.payloadField] = data as CKRecordValue
        record[Self.deviceIDField] = request.request.macDeviceID as CKRecordValue
        return record
    }

    public func response(
        for requestID: String,
        phoneDeviceID: String
    ) async throws -> SignedRemoteApprovalResponse? {
        let recordID: CKRecord.ID
        do {
            recordID = try Self.responseRecordID(requestID: requestID, phoneDeviceID: phoneDeviceID)
        } catch {
            // Polling cannot make an unusable name usable.
            throw RemoteApprovalRelayFailure.permanentlyUnavailable
        }
        let record: CKRecord
        do {
            record = try await database.record(for: recordID)
        } catch let error as CKError where error.code == .unknownItem {
            return nil
        } catch {
            throw Self.relayFailure(for: error)
        }
        do {
            return try decodeEnvelope(SignedRemoteApprovalResponse.self, from: record)
        } catch {
            // Bytes that are no response stay the same bytes on every poll.
            throw RemoteApprovalRelayFailure.unreadableRecord
        }
    }

    public func discardResponse(for requestID: String, phoneDeviceID: String) async {
        guard let recordID = try? Self.responseRecordID(
            requestID: requestID,
            phoneDeviceID: phoneDeviceID
        ) else { return }
        _ = try? await database.deleteRecord(withID: recordID)
    }

    public func pendingRequests() async throws -> [SignedRemoteApprovalRequest] {
        try await pendingRequestRecords().map(\.envelope)
    }

    /// The request records in the mailbox, each with when CloudKit last saved
    /// it, for the phone to tell a waiting Mac from one that has gone quiet.
    /// The Mac's own sweeps use `pendingRequests()`, which sees every record:
    /// a quiet one is exactly what a sweep is for.
    public func pendingRequestRecords() async throws -> [RemoteApprovalMailboxRequest] {
        let query = CKQuery(
            recordType: Self.requestRecordType,
            predicate: NSPredicate(value: true)
        )
        do {
            var page = try await database.records(
                matching: query,
                desiredKeys: [Self.payloadField],
                resultsLimit: 100
            )
            var results = page.matchResults
            var pageCount = 1
            // CloudKit does not promise that the first page contains the newest
            // record. Follow a bounded number of cursors so a small stale backlog
            // cannot hide a live approval indefinitely.
            while let cursor = page.queryCursor, pageCount < 10 {
                page = try await database.records(
                    continuingMatchFrom: cursor,
                    desiredKeys: [Self.payloadField],
                    resultsLimit: 100
                )
                results.append(contentsOf: page.matchResults)
                pageCount += 1
            }
            // Every record here is one a Mac published and has not withdrawn:
            // the Mac deletes its request as soon as it stops waiting, and
            // sweeps anything it left behind when it restarts. Nothing is
            // filtered out here, by age or by save time; the phone decides
            // what a quiet record means. A record is kept only under the one
            // name its payload's request ID gives it, so a caller that later
            // deletes or checks by that ID reaches exactly this record.
            return results.compactMap { _, result in
                guard let record = try? result.get(),
                      let envelope = try? decodeEnvelope(
                          SignedRemoteApprovalRequest.self,
                          from: record
                      ),
                      RemoteApprovalMailboxName.requestRecord(
                          named: record.recordID.recordName,
                          holds: envelope.request.requestID
                      ) else { return nil }
                return RemoteApprovalMailboxRequest(
                    envelope: envelope,
                    savedAt: record.modificationDate
                )
            }
        } catch {
            throw Self.relayFailure(for: error)
        }
    }

    public func requestIsPending(requestID: String) async throws -> Bool {
        try await requestPresence(requestID: requestID) != .gone
    }

    /// Whether the request record is there, and when CloudKit last saved it,
    /// read by its name without its payload.
    public func requestPresence(requestID: String) async throws -> RemoteApprovalRequestPresence {
        // A request ID with no usable record name was never published under
        // it, so nothing is waiting on it.
        guard let recordID = try? Self.recordID(
            RemoteApprovalMailboxName.request(requestID: requestID)
        ) else { return .gone }
        let results: [CKRecord.ID: Result<CKRecord, Error>]
        do {
            // No user field is fetched; system fields such as the
            // modification date always come back.
            results = try await database.records(for: [recordID], desiredKeys: [])
        } catch {
            throw Self.relayFailure(for: error)
        }
        guard let result = results[recordID] else { return .gone }
        switch result {
        case let .success(record):
            return .present(savedAt: record.modificationDate)
        case let .failure(error):
            if let ckError = error as? CKError, ckError.code == .unknownItem {
                return .gone
            }
            throw Self.relayFailure(for: error)
        }
    }

    /// Save a response only into an empty slot; a slot that already holds a
    /// record throws `CloudKitRemoteApprovalError.responseSlotTaken`. The
    /// phone uses `publishResponse(_:keepingEarlierAnswer:)`, which decides
    /// what to do about that record.
    public func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {
        let record = try responseRecord(for: response)
        do {
            _ = try await database.save(record)
        } catch let error as CKError where error.code == .serverRecordChanged {
            throw CloudKitRemoteApprovalError.responseSlotTaken
        } catch {
            throw Self.relayFailure(for: error)
        }
    }

    /// The phone's answer, saved to its own slot,
    /// `response-<requestID>-<phoneDeviceID>`. Returns nil once saved.
    ///
    /// When the slot already holds a record, `isEarlierAnswer` is shown what
    /// it decodes to. The phone's own earlier answer to the same request — a
    /// save that reached iCloud although its reply was lost — is kept and
    /// returned, because the Mac may already have acted on it; the caller
    /// reports that decision, not the new one. Anything else there — a record
    /// that does not decode, or that the phone did not sign for this request —
    /// is not an answer, so it is overwritten.
    public func publishResponse(
        _ response: SignedRemoteApprovalResponse,
        keepingEarlierAnswer isEarlierAnswer: @Sendable (SignedRemoteApprovalResponse) -> Bool
    ) async throws -> SignedRemoteApprovalResponse? {
        let record = try responseRecord(for: response)
        let existing: CKRecord?
        do {
            _ = try await database.save(record)
            return nil
        } catch let error as CKError where error.code == .serverRecordChanged {
            existing = error.serverRecord
        } catch {
            throw Self.relayFailure(for: error)
        }
        let current: CKRecord?
        if let existing {
            current = existing
        } else {
            do {
                current = try await database.record(for: record.recordID)
            } catch let error as CKError where error.code == .unknownItem {
                // Deleted meanwhile — the Mac cleared a record it refused.
                current = nil
            } catch {
                throw Self.relayFailure(for: error)
            }
        }
        if let current,
           let earlier = try? decodeEnvelope(SignedRemoteApprovalResponse.self, from: current),
           isEarlierAnswer(earlier) {
            return earlier
        }
        try await saveOverwriting(record)
        return nil
    }

    /// Save `record` whatever the server holds under its ID. The batch call
    /// reports a record's own failure in its results rather than by throwing,
    /// so that result is checked too: a save that did not land is an error.
    private func saveOverwriting(_ record: CKRecord) async throws {
        let saved: Result<CKRecord, Error>?
        do {
            saved = try await database.modifyRecords(
                saving: [record],
                deleting: [],
                savePolicy: .allKeys,
                atomically: true
            ).saveResults[record.recordID]
        } catch {
            throw Self.relayFailure(for: error)
        }
        switch saved {
        case .success?:
            return
        case let .failure(error)?:
            throw Self.relayFailure(for: error)
        case nil:
            throw RemoteApprovalRelayFailure.transient
        }
    }

    private func responseRecord(for response: SignedRemoteApprovalResponse) throws -> CKRecord {
        let data: Data
        let recordID: CKRecord.ID
        do {
            data = try encodeBounded(response)
            recordID = try Self.responseRecordID(
                requestID: response.response.requestID,
                phoneDeviceID: response.response.phoneDeviceID
            )
        } catch {
            throw RemoteApprovalRelayFailure.permanentlyUnavailable
        }
        let record = CKRecord(recordType: Self.responseRecordType, recordID: recordID)
        record[Self.payloadField] = data as CKRecordValue
        record[Self.deviceIDField] = response.response.phoneDeviceID as CKRecordValue
        return record
    }

    public func pairingConfirmation(
        macDeviceID: String
    ) async throws -> SignedRemoteApprovalPairingConfirmation? {
        try await fetchEnvelope(
            SignedRemoteApprovalPairingConfirmation.self,
            recordName: RemoteApprovalMailboxName.pairingConfirmation(macDeviceID: macDeviceID)
        )
    }

    public func publishPairingConfirmation(
        _ confirmation: SignedRemoteApprovalPairingConfirmation
    ) async throws {
        try await saveReplacing(
            confirmation,
            recordType: Self.pairingConfirmationRecordType,
            recordName: RemoteApprovalMailboxName.pairingConfirmation(
                macDeviceID: confirmation.confirmation.macDeviceID
            ),
            deviceID: confirmation.confirmation.phoneDeviceID
        )
    }

    public func phoneStatus(
        phoneDeviceID: String
    ) async throws -> SignedRemoteApprovalPhoneStatus? {
        try await fetchEnvelope(
            SignedRemoteApprovalPhoneStatus.self,
            recordName: RemoteApprovalMailboxName.phoneStatus(phoneDeviceID: phoneDeviceID)
        )
    }

    public func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {
        try await saveReplacing(
            status,
            recordType: Self.phoneStatusRecordType,
            recordName: RemoteApprovalMailboxName.phoneStatus(
                phoneDeviceID: status.status.phoneDeviceID
            ),
            deviceID: status.status.phoneDeviceID
        )
    }

    public func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {
        try await saveReplacing(
            offer,
            recordType: Self.pairingOfferRecordType,
            recordName: RemoteApprovalMailboxName.pairingOffer(
                phoneDeviceID: offer.offer.phoneDeviceID
            ),
            deviceID: offer.offer.mac.macDeviceID
        )
    }

    public func pairingOffer(
        phoneDeviceID: String
    ) async throws -> SignedRemoteApprovalPairingOffer? {
        try await fetchEnvelope(
            SignedRemoteApprovalPairingOffer.self,
            recordName: RemoteApprovalMailboxName.pairingOffer(phoneDeviceID: phoneDeviceID)
        )
    }

    /// Reads the offer first and deletes it only when `macDeviceID` made it.
    /// CloudKit has no conditional delete, so a newer offer saved between the
    /// read and the delete could still go; the phone then falls back to the
    /// pasted code, which `csec remote enable` always prints.
    public func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async throws {
        guard let recordID = try? Self.recordID(
            RemoteApprovalMailboxName.pairingOffer(phoneDeviceID: phoneDeviceID)
        ) else { return }
        let record: CKRecord
        do {
            record = try await database.record(for: recordID)
        } catch let error as CKError where error.code == .unknownItem {
            return
        } catch {
            throw Self.relayFailure(for: error)
        }
        // An offer that does not decode is no one's and goes too.
        if let offer = try? decodeEnvelope(SignedRemoteApprovalPairingOffer.self, from: record),
           offer.offer.mac.macDeviceID != macDeviceID.lowercased() {
            return
        }
        try await deleteIfPresent(recordID)
    }

    /// One record per ID that a later save replaces: a phone's latest status,
    /// its latest confirmation of a Mac pairing, or a Mac's latest offer.
    private func saveReplacing<T: Encodable>(
        _ value: T,
        recordType: String,
        recordName: String?,
        deviceID: String
    ) async throws {
        let data: Data
        let recordID: CKRecord.ID
        do {
            data = try encodeBounded(value)
            recordID = try Self.recordID(recordName)
        } catch {
            throw RemoteApprovalRelayFailure.permanentlyUnavailable
        }
        let record = CKRecord(recordType: recordType, recordID: recordID)
        record[Self.payloadField] = data as CKRecordValue
        record[Self.deviceIDField] = deviceID as CKRecordValue
        try await saveOverwriting(record)
    }

    private func fetchEnvelope<T: Decodable>(
        _ type: T.Type,
        recordName: String?
    ) async throws -> T? {
        // No record is ever saved under a name the builders refuse.
        guard let recordID = try? Self.recordID(recordName) else { return nil }
        do {
            let record = try await database.record(for: recordID)
            return try decodeEnvelope(type, from: record)
        } catch let error as CKError where error.code == .unknownItem {
            return nil
        } catch let error as CloudKitRemoteApprovalError {
            throw error
        } catch {
            throw Self.relayFailure(for: error)
        }
    }

    public func publishAlert(requestID: String, macDeviceID: String) async throws {
        let recordID: CKRecord.ID
        do {
            recordID = try Self.recordID(RemoteApprovalMailboxName.alert(requestID: requestID))
        } catch {
            throw RemoteApprovalRelayFailure.permanentlyUnavailable
        }
        let record = CKRecord(recordType: Self.alertRecordType, recordID: recordID)
        record[Self.deviceIDField] = macDeviceID.lowercased() as CKRecordValue
        do {
            _ = try await database.save(record)
        } catch let error as CKError where error.code == .serverRecordChanged {
            // An earlier save of this alert whose reply was lost.
            return
        } catch {
            throw Self.relayFailure(for: error)
        }
    }

    /// The request `requestID` names, read by its record name for the
    /// notification service extension; nil when the Mac has deleted it. The
    /// caller still verifies the Mac's signature.
    public func request(requestID: String) async throws -> SignedRemoteApprovalRequest? {
        try await requestRecord(requestID: requestID)?.envelope
    }

    /// `request(requestID:)` with when CloudKit last saved the record.
    public func requestRecord(requestID: String) async throws -> RemoteApprovalMailboxRequest? {
        guard let recordID = try? Self.recordID(
            RemoteApprovalMailboxName.request(requestID: requestID)
        ) else { return nil }
        do {
            let record = try await database.record(for: recordID)
            let envelope = try decodeEnvelope(SignedRemoteApprovalRequest.self, from: record)
            guard RemoteApprovalMailboxName.requestRecord(
                named: record.recordID.recordName,
                holds: envelope.request.requestID
            ) else { throw CloudKitRemoteApprovalError.invalidRecord }
            return RemoteApprovalMailboxRequest(envelope: envelope, savedAt: record.modificationDate)
        } catch let error as CKError where error.code == .unknownItem {
            return nil
        } catch let error as CKError {
            throw Self.relayFailure(for: error)
        }
    }

    /// The request an alert push is for: the record name of a notification
    /// from the alert subscription, when it is exactly `alert-<request ID>`.
    public static func alertRequestID(fromRemoteNotification userInfo: [AnyHashable: Any]) -> String? {
        guard let notification = CKNotification(fromRemoteNotificationDictionary: userInfo)
                as? CKQueryNotification,
              notification.subscriptionID == alertSubscriptionID,
              let recordName = notification.recordID?.recordName else { return nil }
        return RemoteApprovalMailboxName.requestID(fromAlertRecordName: recordName)
    }

    public func deleteExchange(requestID: String, phoneDeviceID: String?) async throws {
        var recordIDs: [CKRecord.ID] = []
        if let recordID = try? Self.recordID(RemoteApprovalMailboxName.alert(requestID: requestID)) {
            recordIDs.append(recordID)
        }
        if let recordID = try? Self.recordID(RemoteApprovalMailboxName.request(requestID: requestID)) {
            recordIDs.append(recordID)
        }
        if let phoneDeviceID,
           let recordID = try? Self.responseRecordID(requestID: requestID, phoneDeviceID: phoneDeviceID) {
            recordIDs.append(recordID)
        }
        var firstFailure: Error?
        for recordID in recordIDs {
            do {
                try await deleteIfPresent(recordID)
            } catch {
                firstFailure = firstFailure ?? error
            }
        }
        if let firstFailure { throw firstFailure }
    }

    /// Delete one record; a record already gone is deleted.
    private func deleteIfPresent(_ recordID: CKRecord.ID) async throws {
        do {
            _ = try await database.deleteRecord(withID: recordID)
        } catch let error as CKError where error.code == .unknownItem {
            return
        } catch {
            throw Self.relayFailure(for: error)
        }
    }

    public static let alertSound = "default"

    /// The companion installs these. Neither push carries a request field:
    /// every wake still calls `pendingRequests()` and verifies each Mac
    /// signature before anything is shown as actionable, and the alert's
    /// fixed text (`RemoteApprovalNotificationText.unverified`) is replaced
    /// only by the notification service extension, from a request whose
    /// signature it verified.
    ///
    /// A subscription already saved under either ID is kept only when it is
    /// exactly the one built here (`isExpectedSubscription`). Anything else
    /// under the ID — one that copies record fields into the push (and so
    /// through Apple's push service and onto the lock screen), shows other
    /// alert text, or fires on other records — is replaced. Any other query
    /// subscription on csec's record types (`straySubscriptionIDs`) is
    /// deleted: an older version's, or one another client saved that could
    /// copy record fields into its pushes.
    public func ensureSubscriptions() async throws {
        try await ensure(Self.makeAlertSubscription())
        try await ensure(Self.makeRequestSubscription())
        await removeStraySubscriptions()
    }

    /// The settled subscription, saved on its own after the other two: a
    /// Production container whose schema has not been given it yet refuses
    /// it, and that refusal must not cost the phone its alerts. Without it a
    /// settled request's alert and badge count stay until the app next runs
    /// or the extension handles the next alert.
    public func ensureSettledSubscription() async throws {
        try await ensure(Self.makeSettledSubscription())
    }

    /// Best effort: a failure here leaves the subscriptions this app needs
    /// in place, and the next refresh tries again.
    private func removeStraySubscriptions() async {
        guard let subscriptions = try? await database.allSubscriptions() else { return }
        for subscriptionID in Self.straySubscriptionIDs(subscriptions) {
            _ = try? await database.deleteSubscription(withID: subscriptionID)
        }
    }

    /// The query subscriptions on csec's record types (`CSEC…`) other than the
    /// three this app installs, sorted. The container is csec's alone, so any
    /// such subscription is stale or planted.
    public static func straySubscriptionIDs(_ subscriptions: [CKSubscription]) -> [CKSubscription.ID] {
        let installed: Set<CKSubscription.ID> = [
            requestSubscriptionID, alertSubscriptionID, settledSubscriptionID,
        ]
        return subscriptions.compactMap { subscription in
            guard let query = subscription as? CKQuerySubscription,
                  (query.recordType ?? "").hasPrefix("CSEC"),
                  !installed.contains(subscription.subscriptionID) else { return nil }
            return subscription.subscriptionID
        }.sorted()
    }

    private func ensure(_ expected: CKQuerySubscription) async throws {
        do {
            let existing = try await database.subscription(for: expected.subscriptionID)
            if Self.isExpectedSubscription(existing) { return }
            _ = try await database.deleteSubscription(withID: expected.subscriptionID)
        } catch let error as CKError where error.code == .unknownItem {
            // None yet: create below.
        }
        _ = try await database.save(expected)
    }

    /// Silent: a new request wakes the app so an open app shows its card at
    /// once. The alert waits for the alert record.
    public static func makeRequestSubscription() -> CKQuerySubscription {
        let subscription = CKQuerySubscription(
            recordType: requestRecordType,
            predicate: NSPredicate(value: true),
            subscriptionID: requestSubscriptionID,
            options: [.firesOnRecordCreation]
        )
        let notification = CKSubscription.NotificationInfo()
        notification.shouldSendContentAvailable = true
        subscription.notificationInfo = notification
        return subscription
    }

    /// Silent: a request record deleted wakes the app, which reads the
    /// mailbox and clears what is no longer waiting. CloudKit sends a
    /// deletion's push with the record ID alone; nothing is asked of it.
    public static func makeSettledSubscription() -> CKQuerySubscription {
        let subscription = CKQuerySubscription(
            recordType: requestRecordType,
            predicate: NSPredicate(value: true),
            subscriptionID: settledSubscriptionID,
            options: [.firesOnRecordDeletion]
        )
        let notification = CKSubscription.NotificationInfo()
        notification.shouldSendContentAvailable = true
        subscription.notificationInfo = notification
        return subscription
    }

    /// Visible: the fixed alert text, mutable so the notification service
    /// extension can put the verified request's words in its place, and a
    /// wake-up so the app refreshes too.
    public static func makeAlertSubscription() -> CKQuerySubscription {
        let subscription = CKQuerySubscription(
            recordType: alertRecordType,
            predicate: NSPredicate(value: true),
            subscriptionID: alertSubscriptionID,
            options: [.firesOnRecordCreation]
        )
        let notification = CKSubscription.NotificationInfo()
        notification.shouldSendContentAvailable = true
        notification.shouldSendMutableContent = true
        notification.title = RemoteApprovalNotificationText.unverified.title
        notification.alertBody = RemoteApprovalNotificationText.unverified.body
        notification.soundName = alertSound
        subscription.notificationInfo = notification
        return subscription
    }

    /// Whether `subscription` is exactly one of the three built above: a
    /// query subscription on its record type, matching every record, firing
    /// on creation only (deletion only for the settled subscription), in the
    /// default zone, carrying no record field, and with exactly that one's
    /// alert — none for the request and settled subscriptions, the fixed
    /// text for the alert subscription.
    public static func isExpectedSubscription(_ subscription: CKSubscription) -> Bool {
        let expected: CKQuerySubscription
        switch subscription.subscriptionID {
        case requestSubscriptionID: expected = makeRequestSubscription()
        case alertSubscriptionID: expected = makeAlertSubscription()
        case settledSubscriptionID: expected = makeSettledSubscription()
        default: return false
        }
        guard let query = subscription as? CKQuerySubscription,
              query.recordType == expected.recordType,
              query.predicate.predicateFormat == NSPredicate(value: true).predicateFormat,
              query.querySubscriptionOptions == expected.querySubscriptionOptions,
              query.zoneID == nil,
              let info = query.notificationInfo,
              let want = expected.notificationInfo else { return false }
        func isEmpty(_ keys: [String]?) -> Bool { keys?.isEmpty ?? true }
        return info.shouldSendContentAvailable == want.shouldSendContentAvailable
            && info.shouldSendMutableContent == want.shouldSendMutableContent
            && info.title == want.title
            && info.alertBody == want.alertBody
            && info.soundName == want.soundName
            && info.subtitle == nil
            && info.titleLocalizationKey == nil
            && info.subtitleLocalizationKey == nil
            && info.alertLocalizationKey == nil
            && info.alertActionLocalizationKey == nil
            && info.alertLaunchImage == nil
            && info.category == nil
            && info.collapseIDKey == nil
            && !info.shouldBadge
            && isEmpty(info.desiredKeys)
            && isEmpty(info.titleLocalizationArgs)
            && isEmpty(info.subtitleLocalizationArgs)
            && isEmpty(info.alertLocalizationArgs)
    }

    private func encodeBounded<T: Encodable>(_ value: T) throws -> Data {
        let data = try encoder.encode(value)
        guard data.count <= Self.maximumEnvelopeBytes else {
            throw CloudKitRemoteApprovalError.envelopeTooLarge
        }
        return data
    }

    private func decodeEnvelope<T: Decodable>(
        _ type: T.Type,
        from record: CKRecord
    ) throws -> T {
        guard let data = record[Self.payloadField] as? Data,
              data.count <= Self.maximumEnvelopeBytes else {
            throw CloudKitRemoteApprovalError.invalidRecord
        }
        return try decoder.decode(type, from: data)
    }

    /// The only place a record ID is made. `CKRecord.ID(recordName:)` raises
    /// an Objective-C exception — which aborts the process — for an empty name
    /// or one over 255 bytes, so a name is checked first and a bad one is a
    /// Swift error the caller handles.
    public static func recordID(_ recordName: String?) throws -> CKRecord.ID {
        guard let recordName,
              RemoteApprovalMailboxName.isUsableRecordName(recordName) else {
            throw CloudKitRemoteApprovalError.invalidRecordName
        }
        return CKRecord.ID(recordName: recordName)
    }

    private static func responseRecordID(
        requestID: String,
        phoneDeviceID: String
    ) throws -> CKRecord.ID {
        try recordID(RemoteApprovalMailboxName.response(
            requestID: requestID,
            phoneDeviceID: phoneDeviceID
        ))
    }

    /// Tell a caller that now waits indefinitely which failures are worth
    /// waiting through. Only conditions no amount of polling can fix become
    /// `permanentlyUnavailable` and drop csecd back to the local prompt alone;
    /// rate limiting, a busy server and a network that is not there yet are a
    /// delay, not an answer. Anything unrecognised is returned unchanged and
    /// treated by the requester as a transient blip too.
    public static func relayFailure(for error: Error) -> Error {
        guard let ckError = error as? CKError else { return error }
        if let retryAfterSeconds = ckError.retryAfterSeconds, retryAfterSeconds > 0 {
            return RemoteApprovalRelayFailure.throttled(
                retryAfterNanoseconds: nanoseconds(seconds: retryAfterSeconds)
            )
        }
        switch ckError.code {
        // `.invalidArguments` is also what CloudKit returns for a query on a
        // field the schema does not index — a Production container deployed
        // without the request type's indexes. That is a deployment defect no
        // retry fixes, so it stays permanent with the rest.
        case .notAuthenticated, .managedAccountRestricted, .permissionFailure,
             .badContainer, .badDatabase, .missingEntitlement, .incompatibleVersion,
             .invalidArguments, .quotaExceeded:
            return RemoteApprovalRelayFailure.permanentlyUnavailable
        case .requestRateLimited, .zoneBusy, .serviceUnavailable:
            // Throttled without a server hint: the requester falls back to its
            // ordinary poll interval.
            return RemoteApprovalRelayFailure.throttled(retryAfterNanoseconds: 0)
        case .networkUnavailable, .networkFailure, .serverResponseLost,
             .accountTemporarilyUnavailable:
            // The usual state for a few seconds after wake, or while the
            // account finishes signing in: retry on the poll interval.
            return RemoteApprovalRelayFailure.transient
        default:
            return error
        }
    }

    /// What a failed `ensureSubscriptions()` means for the phone's
    /// alerts. `.subscriptionRefused` for a failure no retry fixes — above all
    /// a Production container whose schema was never given the subscription,
    /// which CloudKit refuses with "attempting to create a subscription in a
    /// production container" (Invalid Arguments). `nil` for a delay worth
    /// retrying on the next refresh, which leaves the reported state as it was.
    public static func alertState(
        afterSubscriptionFailure error: Error
    ) -> RemoteApprovalPhoneAlertState? {
        guard let failure = relayFailure(for: subscriptionError(error)) as? RemoteApprovalRelayFailure,
              failure == .permanentlyUnavailable else { return nil }
        return .subscriptionRefused
    }

    /// A short reason to show for a CloudKit failure: its code and Apple's
    /// server message, sanitized for display and bounded. It holds no record
    /// field, so it is safe on screen.
    public static func failureSummary(_ error: Error) -> String {
        let underlying = subscriptionError(error)
        guard let ckError = underlying as? CKError else {
            return "error \(type(of: underlying))"
        }
        let message = RemoteApprovalDisplayText.sanitized(
            (ckError.userInfo[NSLocalizedDescriptionKey] as? String) ?? ""
        )
        let bounded = message.count > 200 ? String(message.prefix(199)) + "…" : message
        return "CloudKit error \(ckError.code.rawValue)" + (bounded.isEmpty ? "" : ": \(bounded)")
    }

    /// A save of one subscription can come back as a partial failure that
    /// holds the subscription's own error; that is the one to judge.
    private static func subscriptionError(_ error: Error) -> Error {
        guard let ckError = error as? CKError, ckError.code == .partialFailure,
              let errors = ckError.partialErrorsByItemID, errors.count == 1,
              let only = errors.values.first else { return error }
        return only
    }

    private static func nanoseconds(seconds: Double) -> UInt64 {
        let value = (seconds * 1_000_000_000).rounded(.up)
        guard value.isFinite, value > 0 else { return 0 }
        guard value < Double(UInt64.max) else { return UInt64.max }
        return UInt64(value)
    }
}

public enum CloudKitRemoteApprovalError: Error, Equatable, Sendable {
    case invalidRecord
    case envelopeTooLarge
    /// A record name CloudKit would refuse (by raising, not by returning an
    /// error), so no record ID was made from it.
    case invalidRecordName
    /// `publishResponse(_:)` found the phone's response slot already holding a
    /// record.
    case responseSlotTaken
}

