import CryptoKit
import Foundation

/// Versioned, value-free remote approval protocol shared by the Mac agent and
/// the opt-in iPhone companion. CloudKit (or any future relay) is deliberately
/// outside this module: signatures, expiry, request binding, and replay state
/// are the authority.
public enum RemoteApprovalProtocolV1 {
    public static let version: UInt16 = 1
    public static let requestLifetimeMilliseconds: UInt64 = 90_000
    public static let maximumRequestLifetimeMilliseconds: UInt64 = 120_000
    public static let allowedClockSkewMilliseconds: UInt64 = 30_000
    public static let maximumCredentials = 64
    public static let maximumReferences = 64
}

public enum RemoteApprovalValidationError: Error, Equatable, Sendable {
    case invalidVersion
    case invalidIdentifier
    case invalidTimestamp
    case expired
    case fieldOutOfBounds
    case invalidDigest
    case invalidPublicKey
    case invalidSignature
    case wrongDevice
    case wrongRequest
    case alreadyConsumed
}

/// Exact display model rendered on the phone. These strings are generated from
/// the same bounded ReviewDisplay helpers as the local AppKit surface. The
/// separate reference-set and delivery-plan digests bind the display to the
/// agent's immutable authorization input without transmitting values.
public struct RemoteApprovalReview: Codable, Equatable, Sendable {
    public struct Credential: Codable, Equatable, Sendable {
        public let title: String?
        public let subtitle: String?
        public let fields: [String]
        public let rawReferences: [String]

        public init(
            title: String?,
            subtitle: String?,
            fields: [String],
            rawReferences: [String]
        ) {
            self.title = title
            self.subtitle = subtitle
            self.fields = fields
            self.rawReferences = rawReferences
        }
    }

    public let reason: String
    public let callerDescription: String
    public let credentials: [Credential]
    public let referenceSetDigest: Data
    public let emitterName: String
    public let emitterPath: String
    public let emitterAssurance: String
    public let recipientDescription: String
    public let deliveryDescription: String
    public let grantRootDescription: String
    public let destinationDescription: String
    public let requestedDurationDescription: String
    public let warning: String?
    public let deliveryPlanDigest: Data

    public init(
        reason: String,
        callerDescription: String,
        credentials: [Credential],
        referenceSetDigest: Data,
        emitterName: String,
        emitterPath: String,
        emitterAssurance: String,
        recipientDescription: String,
        deliveryDescription: String,
        grantRootDescription: String,
        destinationDescription: String,
        requestedDurationDescription: String,
        warning: String?,
        deliveryPlanDigest: Data
    ) {
        self.reason = reason
        self.callerDescription = callerDescription
        self.credentials = credentials
        self.referenceSetDigest = referenceSetDigest
        self.emitterName = emitterName
        self.emitterPath = emitterPath
        self.emitterAssurance = emitterAssurance
        self.recipientDescription = recipientDescription
        self.deliveryDescription = deliveryDescription
        self.grantRootDescription = grantRootDescription
        self.destinationDescription = destinationDescription
        self.requestedDurationDescription = requestedDurationDescription
        self.warning = warning
        self.deliveryPlanDigest = deliveryPlanDigest
    }

    public func validate() throws {
        guard !reason.isEmpty, reason.utf8.count <= 512,
              !callerDescription.isEmpty, callerDescription.utf8.count <= 1_024,
              !credentials.isEmpty,
              credentials.count <= RemoteApprovalProtocolV1.maximumCredentials,
              referenceSetDigest.count == SHA256.byteCount,
              deliveryPlanDigest.count == SHA256.byteCount,
              !emitterName.isEmpty, emitterName.utf8.count <= 512,
              !emitterPath.isEmpty, emitterPath.utf8.count <= 4_096,
              !emitterAssurance.isEmpty, emitterAssurance.utf8.count <= 128,
              !recipientDescription.isEmpty, recipientDescription.utf8.count <= 1_024,
              !deliveryDescription.isEmpty, deliveryDescription.utf8.count <= 512,
              !grantRootDescription.isEmpty, grantRootDescription.utf8.count <= 512,
              !destinationDescription.isEmpty, destinationDescription.utf8.count <= 512,
              !requestedDurationDescription.isEmpty,
              requestedDurationDescription.utf8.count <= 128,
              warning?.utf8.count ?? 0 <= 4_096 else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }

        var referenceCount = 0
        for credential in credentials {
            let displayCount = credential.fields.count + credential.rawReferences.count
            referenceCount += displayCount
            guard displayCount > 0,
                  credential.fields.count <= RemoteApprovalProtocolV1.maximumReferences,
                  credential.rawReferences.count <= RemoteApprovalProtocolV1.maximumReferences,
                  boundedOptional(credential.title, maximum: 1_024),
                  boundedOptional(credential.subtitle, maximum: 1_024),
                  credential.fields.allSatisfy({ bounded($0, maximum: 4_096) }),
                  credential.rawReferences.allSatisfy({ bounded($0, maximum: 4_096) }) else {
                throw RemoteApprovalValidationError.fieldOutOfBounds
            }
        }
        guard referenceCount <= RemoteApprovalProtocolV1.maximumReferences else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
    }

    fileprivate func appendCanonical(to encoder: inout CanonicalEncoder) throws {
        try validate()
        encoder.string(reason)
        encoder.string(callerDescription)
        encoder.array(credentials) { encoder, credential in
            encoder.optionalString(credential.title)
            encoder.optionalString(credential.subtitle)
            encoder.strings(credential.fields)
            encoder.strings(credential.rawReferences)
        }
        encoder.data(referenceSetDigest)
        encoder.string(emitterName)
        encoder.string(emitterPath)
        encoder.string(emitterAssurance)
        encoder.string(recipientDescription)
        encoder.string(deliveryDescription)
        encoder.string(grantRootDescription)
        encoder.string(destinationDescription)
        encoder.string(requestedDurationDescription)
        encoder.optionalString(warning)
        encoder.data(deliveryPlanDigest)
    }
}

public struct RemoteApprovalRequest: Codable, Equatable, Sendable {
    public let version: UInt16
    public let requestID: String
    public let macDeviceID: String
    public let macDeviceName: String
    public let createdAtMilliseconds: UInt64
    public let expiresAtMilliseconds: UInt64
    public let review: RemoteApprovalReview

    public init(
        requestID: String = UUID().uuidString.lowercased(),
        macDeviceID: String,
        macDeviceName: String,
        createdAtMilliseconds: UInt64,
        expiresAtMilliseconds: UInt64,
        review: RemoteApprovalReview
    ) {
        self.version = RemoteApprovalProtocolV1.version
        self.requestID = requestID.lowercased()
        self.macDeviceID = macDeviceID.lowercased()
        self.macDeviceName = macDeviceName
        self.createdAtMilliseconds = createdAtMilliseconds
        self.expiresAtMilliseconds = expiresAtMilliseconds
        self.review = review
    }

    public func validate(at nowMilliseconds: UInt64) throws {
        guard version == RemoteApprovalProtocolV1.version else {
            throw RemoteApprovalValidationError.invalidVersion
        }
        guard validUUID(requestID), validUUID(macDeviceID) else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard bounded(macDeviceName, maximum: 256) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        guard createdAtMilliseconds < expiresAtMilliseconds,
              expiresAtMilliseconds - createdAtMilliseconds
                <= RemoteApprovalProtocolV1.maximumRequestLifetimeMilliseconds,
              createdAtMilliseconds
                <= addingClamped(
                    nowMilliseconds,
                    RemoteApprovalProtocolV1.allowedClockSkewMilliseconds
                ) else {
            throw RemoteApprovalValidationError.invalidTimestamp
        }
        guard addingClamped(
            expiresAtMilliseconds,
            RemoteApprovalProtocolV1.allowedClockSkewMilliseconds
        ) >= nowMilliseconds else {
            throw RemoteApprovalValidationError.expired
        }
        try review.validate()
    }

    public func signingData() throws -> Data {
        var encoder = CanonicalEncoder(domain: "csec.remote-approval.request.v1")
        encoder.uint16(version)
        encoder.string(requestID)
        encoder.string(macDeviceID)
        encoder.string(macDeviceName)
        encoder.uint64(createdAtMilliseconds)
        encoder.uint64(expiresAtMilliseconds)
        try review.appendCanonical(to: &encoder)
        return encoder.data
    }

    public func digest() throws -> Data {
        Data(SHA256.hash(data: try signingData()))
    }
}

public struct SignedRemoteApprovalRequest: Codable, Equatable, Sendable {
    public let request: RemoteApprovalRequest
    /// ASN.1 DER representation of an ECDSA P-256 signature.
    public let signatureDER: Data

    public init(request: RemoteApprovalRequest, signatureDER: Data) {
        self.request = request
        self.signatureDER = signatureDER
    }

    public static func signed(
        _ request: RemoteApprovalRequest,
        by privateKey: P256.Signing.PrivateKey
    ) throws -> SignedRemoteApprovalRequest {
        let signature = try privateKey.signature(for: request.signingData())
        return SignedRemoteApprovalRequest(
            request: request,
            signatureDER: signature.derRepresentation
        )
    }

    public func verify(
        macPublicKeyX963: Data,
        at nowMilliseconds: UInt64
    ) throws {
        try request.validate(at: nowMilliseconds)
        try RemoteApprovalCrypto.verify(
            signatureDER: signatureDER,
            data: request.signingData(),
            publicKeyX963: macPublicKeyX963
        )
    }
}

public enum RemoteApprovalDecision: String, Codable, Equatable, Sendable {
    case approve
    case deny
}

public struct RemoteApprovalResponse: Codable, Equatable, Sendable {
    public let version: UInt16
    public let requestID: String
    public let requestDigest: Data
    public let phoneDeviceID: String
    public let decision: RemoteApprovalDecision
    public let decidedAtMilliseconds: UInt64

    public init(
        requestID: String,
        requestDigest: Data,
        phoneDeviceID: String,
        decision: RemoteApprovalDecision,
        decidedAtMilliseconds: UInt64
    ) {
        self.version = RemoteApprovalProtocolV1.version
        self.requestID = requestID.lowercased()
        self.requestDigest = requestDigest
        self.phoneDeviceID = phoneDeviceID.lowercased()
        self.decision = decision
        self.decidedAtMilliseconds = decidedAtMilliseconds
    }

    public func signingData() throws -> Data {
        guard version == RemoteApprovalProtocolV1.version else {
            throw RemoteApprovalValidationError.invalidVersion
        }
        guard validUUID(requestID), validUUID(phoneDeviceID) else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard requestDigest.count == SHA256.byteCount else {
            throw RemoteApprovalValidationError.invalidDigest
        }
        var encoder = CanonicalEncoder(domain: "csec.remote-approval.response.v1")
        encoder.uint16(version)
        encoder.string(requestID)
        encoder.data(requestDigest)
        encoder.string(phoneDeviceID)
        encoder.string(decision.rawValue)
        encoder.uint64(decidedAtMilliseconds)
        return encoder.data
    }
}

public struct SignedRemoteApprovalResponse: Codable, Equatable, Sendable {
    public let response: RemoteApprovalResponse
    /// ASN.1 DER representation of an ECDSA P-256 signature.
    public let signatureDER: Data

    public init(response: RemoteApprovalResponse, signatureDER: Data) {
        self.response = response
        self.signatureDER = signatureDER
    }

    public static func signed(
        _ response: RemoteApprovalResponse,
        by privateKey: P256.Signing.PrivateKey
    ) throws -> SignedRemoteApprovalResponse {
        let signature = try privateKey.signature(for: response.signingData())
        return SignedRemoteApprovalResponse(
            response: response,
            signatureDER: signature.derRepresentation
        )
    }

    public func verify(
        for request: RemoteApprovalRequest,
        pinnedPhoneDeviceID: String,
        phonePublicKeyX963: Data,
        at nowMilliseconds: UInt64
    ) throws {
        guard response.requestID == request.requestID,
              response.requestDigest == (try request.digest()) else {
            throw RemoteApprovalValidationError.wrongRequest
        }
        guard response.phoneDeviceID == pinnedPhoneDeviceID.lowercased() else {
            throw RemoteApprovalValidationError.wrongDevice
        }
        let lowerBound = subtractingClamped(
            request.createdAtMilliseconds,
            RemoteApprovalProtocolV1.allowedClockSkewMilliseconds
        )
        let upperBound = addingClamped(
            request.expiresAtMilliseconds,
            RemoteApprovalProtocolV1.allowedClockSkewMilliseconds
        )
        guard response.decidedAtMilliseconds >= lowerBound,
              response.decidedAtMilliseconds <= upperBound else {
            throw RemoteApprovalValidationError.invalidTimestamp
        }
        guard nowMilliseconds <= upperBound else {
            throw RemoteApprovalValidationError.expired
        }
        try RemoteApprovalCrypto.verify(
            signatureDER: signatureDER,
            data: response.signingData(),
            publicKeyX963: phonePublicKeyX963
        )
    }
}

public enum RemoteApprovalCrypto {
    public static func verify(
        signatureDER: Data,
        data: Data,
        publicKeyX963: Data
    ) throws {
        let publicKey: P256.Signing.PublicKey
        let signature: P256.Signing.ECDSASignature
        do {
            publicKey = try P256.Signing.PublicKey(x963Representation: publicKeyX963)
        } catch {
            throw RemoteApprovalValidationError.invalidPublicKey
        }
        do {
            signature = try P256.Signing.ECDSASignature(derRepresentation: signatureDER)
        } catch {
            throw RemoteApprovalValidationError.invalidSignature
        }
        guard publicKey.isValidSignature(signature, for: data) else {
            throw RemoteApprovalValidationError.invalidSignature
        }
    }
}

/// Request-side key seam. The shipping Mac implementation uses a persistent
/// Secure Enclave key; tests can use a software P-256 key without changing the
/// requester or weakening production selection.
public protocol RemoteApprovalRequestSigner: Sendable {
    func publicKeyX963Representation() async throws -> Data
    func sign(_ data: Data) async throws -> Data
}

/// Value-free mailbox seam. Implementations must not infer authorization from
/// storage ownership or successful delivery; only the signed protocol does so.
public protocol RemoteApprovalRelay: Sendable {
    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws
    func response(for requestID: String) async throws -> SignedRemoteApprovalResponse?
    func pendingRequests() async throws -> [SignedRemoteApprovalRequest]
    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws
    func deleteExchange(requestID: String) async
}

public struct RemoteApprovalRequesterConfiguration: Sendable, Equatable {
    public let macDeviceID: String
    public let macDeviceName: String
    public let pinnedPhoneDeviceID: String
    public let pinnedPhonePublicKeyX963: Data
    public let requestLifetimeMilliseconds: UInt64
    public let pollIntervalNanoseconds: UInt64

    public init(
        macDeviceID: String,
        macDeviceName: String,
        pinnedPhoneDeviceID: String,
        pinnedPhonePublicKeyX963: Data,
        requestLifetimeMilliseconds: UInt64 = RemoteApprovalProtocolV1.requestLifetimeMilliseconds,
        pollIntervalNanoseconds: UInt64 = 750_000_000
    ) {
        self.macDeviceID = macDeviceID.lowercased()
        self.macDeviceName = macDeviceName
        self.pinnedPhoneDeviceID = pinnedPhoneDeviceID.lowercased()
        self.pinnedPhonePublicKeyX963 = pinnedPhonePublicKeyX963
        self.requestLifetimeMilliseconds = requestLifetimeMilliseconds
        self.pollIntervalNanoseconds = pollIntervalNanoseconds
    }

    public func validate() throws {
        guard validUUID(macDeviceID), validUUID(pinnedPhoneDeviceID) else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard bounded(macDeviceName, maximum: 256),
              requestLifetimeMilliseconds > 0,
              requestLifetimeMilliseconds
                <= RemoteApprovalProtocolV1.maximumRequestLifetimeMilliseconds,
              pollIntervalNanoseconds >= 50_000_000,
              pollIntervalNanoseconds <= 5_000_000_000 else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        do {
            _ = try P256.Signing.PublicKey(x963Representation: pinnedPhonePublicKeyX963)
        } catch {
            throw RemoteApprovalValidationError.invalidPublicKey
        }
    }
}

public enum RemoteApprovalRequesterResult: Sendable, Equatable {
    /// Relay/configuration unavailable. The local prompt remains authoritative.
    case unavailable
    case denied
    case approved
}

/// Publishes one short-lived signed prompt and polls for a signed response from
/// the explicitly pinned phone. It holds no reusable approval capability and
/// consumes each request ID at most once in this process.
public actor RemoteApprovalRequester {
    private let configuration: RemoteApprovalRequesterConfiguration
    private let signer: any RemoteApprovalRequestSigner
    private let relay: any RemoteApprovalRelay
    private var consumedRequestIDs: Set<String> = []

    public init(
        configuration: RemoteApprovalRequesterConfiguration,
        signer: any RemoteApprovalRequestSigner,
        relay: any RemoteApprovalRelay
    ) throws {
        try configuration.validate()
        self.configuration = configuration
        self.signer = signer
        self.relay = relay
    }

    public func requestApproval(
        for review: RemoteApprovalReview,
        nowMilliseconds: UInt64 = currentTimeMilliseconds()
    ) async -> RemoteApprovalRequesterResult {
        var exchangeToDelete: String?
        do {
            try configuration.validate()
            try review.validate()
            let publicKey = try await signer.publicKeyX963Representation()
            _ = try P256.Signing.PublicKey(x963Representation: publicKey)

            let request = RemoteApprovalRequest(
                macDeviceID: configuration.macDeviceID,
                macDeviceName: configuration.macDeviceName,
                createdAtMilliseconds: nowMilliseconds,
                expiresAtMilliseconds: addingClamped(
                    nowMilliseconds,
                    configuration.requestLifetimeMilliseconds
                ),
                review: review
            )
            try request.validate(at: nowMilliseconds)
            let signature = try await signer.sign(request.signingData())
            // Catch a corrupted or mismatched persistent signer before putting
            // an unverifiable prompt in the relay.
            try RemoteApprovalCrypto.verify(
                signatureDER: signature,
                data: request.signingData(),
                publicKeyX963: publicKey
            )
            let envelope = SignedRemoteApprovalRequest(
                request: request,
                signatureDER: signature
            )
            // Mark it for cleanup before publishing: CloudKit may commit the
            // save and still return an error to this process.
            exchangeToDelete = request.requestID
            try await relay.publishRequest(envelope)

            let result = await waitForResponse(to: request)
            await deleteExchangeUncancelled(requestID: request.requestID)
            exchangeToDelete = nil
            return result
        } catch {
            if let exchangeToDelete {
                await deleteExchangeUncancelled(requestID: exchangeToDelete)
            }
            return .unavailable
        }
    }

    /// Local Touch ID commonly cancels this task. Run mailbox cleanup in a new
    /// cancellation domain so the losing phone prompt is still removed.
    private func deleteExchangeUncancelled(requestID: String) async {
        let relay = self.relay
        await Task.detached(priority: .utility) {
            await relay.deleteExchange(requestID: requestID)
        }.value
    }

    private func waitForResponse(
        to request: RemoteApprovalRequest
    ) async -> RemoteApprovalRequesterResult {
        while !Task.isCancelled {
            let now = currentTimeMilliseconds()
            if now > addingClamped(
                request.expiresAtMilliseconds,
                RemoteApprovalProtocolV1.allowedClockSkewMilliseconds
            ) {
                return .unavailable
            }
            if let envelope = try? await relay.response(for: request.requestID) {
                do {
                    try envelope.verify(
                        for: request,
                        pinnedPhoneDeviceID: configuration.pinnedPhoneDeviceID,
                        phonePublicKeyX963: configuration.pinnedPhonePublicKeyX963,
                        at: now
                    )
                    guard !consumedRequestIDs.contains(request.requestID) else {
                        return .unavailable
                    }
                    if consumedRequestIDs.count >= 4_096 {
                        consumedRequestIDs.removeAll(keepingCapacity: true)
                    }
                    consumedRequestIDs.insert(request.requestID)
                    return envelope.response.decision == .approve ? .approved : .denied
                } catch {
                    // An invalid mailbox record is not an authorization and not
                    // a denial. Keep the local prompt live and wait until expiry.
                }
            }
            do {
                try await Task.sleep(nanoseconds: configuration.pollIntervalNanoseconds)
            } catch {
                return .unavailable
            }
        }
        return .unavailable
    }
}

public func currentTimeMilliseconds(_ date: Date = Date()) -> UInt64 {
    let milliseconds = date.timeIntervalSince1970 * 1_000
    guard milliseconds.isFinite, milliseconds > 0 else { return 0 }
    return UInt64(milliseconds.rounded(.down))
}

private struct CanonicalEncoder {
    private(set) var data: Data

    init(domain: String) {
        data = Data()
        string(domain)
    }

    mutating func uint16(_ value: UInt16) {
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    mutating func uint32(_ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    mutating func uint64(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8((value >> UInt64(shift)) & 0xff))
        }
    }

    mutating func string(_ value: String) {
        let bytes = Data(value.utf8)
        uint32(UInt32(bytes.count))
        data.append(bytes)
    }

    mutating func optionalString(_ value: String?) {
        data.append(value == nil ? 0 : 1)
        if let value { string(value) }
    }

    mutating func data(_ value: Data) {
        uint32(UInt32(value.count))
        data.append(value)
    }

    mutating func strings(_ values: [String]) {
        array(values) { encoder, value in encoder.string(value) }
    }

    mutating func array<T>(
        _ values: [T],
        encode: (inout CanonicalEncoder, T) -> Void
    ) {
        uint32(UInt32(values.count))
        for value in values { encode(&self, value) }
    }
}

private func validUUID(_ value: String) -> Bool {
    UUID(uuidString: value) != nil && value.utf8.count == 36
}

private func bounded(_ value: String, maximum: Int) -> Bool {
    !value.isEmpty && value.utf8.count <= maximum && !value.utf8.contains(0)
}

private func boundedOptional(_ value: String?, maximum: Int) -> Bool {
    guard let value else { return true }
    return bounded(value, maximum: maximum)
}

private func addingClamped(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    let (value, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow ? UInt64.max : value
}

private func subtractingClamped(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    lhs >= rhs ? lhs - rhs : 0
}
