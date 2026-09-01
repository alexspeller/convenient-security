import CloudKit
import CSECRemoteApproval
import Foundation

/// CloudKit private-database mailbox for value-free approval envelopes. Record
/// ownership and iCloud identity are useful transport isolation, but never an
/// authorization signal: callers must verify the P-256 envelopes themselves.
public actor CloudKitRemoteApprovalRelay: RemoteApprovalRelay {
    public static let requestRecordType = "CSECApprovalRequestV1"
    public static let responseRecordType = "CSECApprovalResponseV1"
    public static let requestSubscriptionID = "csec-approval-requests-v1"
    public static let defaultContainerIdentifier =
        "iCloud.com.alexspeller.convenient-security"

    private static let payloadField = "payload"
    private static let expiresAtField = "expiresAt"
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

    public func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        let data = try encodeBounded(request)
        let record = CKRecord(
            recordType: Self.requestRecordType,
            recordID: requestRecordID(request.request.requestID)
        )
        record[Self.payloadField] = data as CKRecordValue
        record[Self.expiresAtField] = date(
            milliseconds: request.request.expiresAtMilliseconds
        ) as CKRecordValue
        record[Self.deviceIDField] = request.request.macDeviceID as CKRecordValue
        _ = try await database.save(record)
    }

    public func response(
        for requestID: String
    ) async throws -> SignedRemoteApprovalResponse? {
        do {
            let record = try await database.record(for: responseRecordID(requestID))
            return try decodeEnvelope(
                SignedRemoteApprovalResponse.self,
                from: record
            )
        } catch let error as CKError where error.code == .unknownItem {
            return nil
        }
    }

    public func pendingRequests() async throws -> [SignedRemoteApprovalRequest] {
        let query = CKQuery(
            recordType: Self.requestRecordType,
            predicate: NSPredicate(value: true)
        )
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
        let earliestAllowedExpiry = currentTimeMilliseconds().subtractingClamped(
            RemoteApprovalProtocolV1.allowedClockSkewMilliseconds
        )
        return results.compactMap { _, result in
            guard let record = try? result.get() else { return nil }
            guard let envelope = try? decodeEnvelope(
                SignedRemoteApprovalRequest.self,
                from: record
            ), envelope.request.expiresAtMilliseconds >= earliestAllowedExpiry else {
                return nil
            }
            return envelope
        }
    }

    public func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {
        let data = try encodeBounded(response)
        let record = CKRecord(
            recordType: Self.responseRecordType,
            recordID: responseRecordID(response.response.requestID)
        )
        record[Self.payloadField] = data as CKRecordValue
        record[Self.deviceIDField] = response.response.phoneDeviceID as CKRecordValue
        _ = try await database.save(record)
    }

    public func deleteExchange(requestID: String) async {
        _ = try? await database.deleteRecord(withID: requestRecordID(requestID))
        _ = try? await database.deleteRecord(withID: responseRecordID(requestID))
    }

    /// The companion installs this once. Silent pushes are wake-up hints only;
    /// every wake still calls `pendingRequests()` and verifies each Mac signature.
    public func ensureRequestSubscription() async throws {
        do {
            _ = try await database.subscription(for: Self.requestSubscriptionID)
            return
        } catch let error as CKError where error.code == .unknownItem {
            // Create below.
        }

        let subscription = CKQuerySubscription(
            recordType: Self.requestRecordType,
            predicate: NSPredicate(value: true),
            subscriptionID: Self.requestSubscriptionID,
            options: [.firesOnRecordCreation]
        )
        let notification = CKSubscription.NotificationInfo()
        notification.shouldSendContentAvailable = true
        subscription.notificationInfo = notification
        _ = try await database.save(subscription)
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

    private func requestRecordID(_ requestID: String) -> CKRecord.ID {
        CKRecord.ID(recordName: "request-\(requestID.lowercased())")
    }

    private func responseRecordID(_ requestID: String) -> CKRecord.ID {
        CKRecord.ID(recordName: "response-\(requestID.lowercased())")
    }

    private func date(milliseconds: UInt64) -> Date {
        Date(timeIntervalSince1970: TimeInterval(milliseconds) / 1_000)
    }
}

private extension UInt64 {
    func subtractingClamped(_ value: UInt64) -> UInt64 {
        self >= value ? self - value : 0
    }
}

public enum CloudKitRemoteApprovalError: Error, Equatable, Sendable {
    case invalidRecord
    case envelopeTooLarge
}
