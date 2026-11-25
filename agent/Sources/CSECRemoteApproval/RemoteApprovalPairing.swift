import CryptoKit
import Foundation

/// Public, value-free identity exported by the phone during explicit pairing.
/// Possession of this text is not approval; the Mac still requires local Touch
/// ID before pinning it, and every later response needs this key's signature.
///
/// Pairing v2 adds the phone's key-agreement key, the one the cold-unlock
/// factor is wrapped to (`RemoteUnlockCrypto`). Both keys are Face-ID-gated
/// Secure Enclave keys; the signing key signs the key-agreement key, so the
/// Mac enrolls only a key the pinned identity vouches for.
public struct RemoteApprovalPhonePairing: Codable, Equatable, Sendable {
    public let version: UInt16
    public let phoneDeviceID: String
    public let phoneDeviceName: String
    public let phonePublicKeyX963: Data
    public let phoneKeyAgreementPublicKeyX963: Data
    /// The signing key's signature over `keyAgreementBindingData`.
    public let keyAgreementSignatureDER: Data
    public let appVersion: String

    public init(
        phoneDeviceID: String,
        phoneDeviceName: String,
        phonePublicKeyX963: Data,
        phoneKeyAgreementPublicKeyX963: Data,
        keyAgreementSignatureDER: Data,
        appVersion: String
    ) {
        self.version = RemoteApprovalProtocolV3.pairingVersion
        self.phoneDeviceID = phoneDeviceID.lowercased()
        self.phoneDeviceName = phoneDeviceName
        self.phonePublicKeyX963 = phonePublicKeyX963
        self.phoneKeyAgreementPublicKeyX963 = phoneKeyAgreementPublicKeyX963
        self.keyAgreementSignatureDER = keyAgreementSignatureDER
        self.appVersion = appVersion
    }

    /// What the phone's signing key signs to vouch for its key-agreement key.
    public static func keyAgreementBindingData(
        phoneDeviceID: String,
        phoneKeyAgreementPublicKeyX963: Data
    ) -> Data {
        var encoder = CanonicalEncoder(domain: "csec.remote-approval.phone-key-agreement.v1")
        encoder.string(phoneDeviceID.lowercased())
        encoder.data(phoneKeyAgreementPublicKeyX963)
        return encoder.data
    }

    public func validate() throws {
        guard version == RemoteApprovalProtocolV3.pairingVersion else {
            throw RemoteApprovalValidationError.invalidVersion
        }
        guard UUID(uuidString: phoneDeviceID) != nil, phoneDeviceID.utf8.count == 36 else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard !phoneDeviceName.isEmpty,
              phoneDeviceName.utf8.count <= 256,
              !phoneDeviceName.utf8.contains(0) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        guard bounded(appVersion, maximum: 64) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        do {
            _ = try P256.Signing.PublicKey(x963Representation: phonePublicKeyX963)
            _ = try P256.KeyAgreement.PublicKey(x963Representation: phoneKeyAgreementPublicKeyX963)
        } catch {
            throw RemoteApprovalValidationError.invalidPublicKey
        }
        try RemoteApprovalCrypto.verify(
            signatureDER: keyAgreementSignatureDER,
            data: Self.keyAgreementBindingData(
                phoneDeviceID: phoneDeviceID,
                phoneKeyAgreementPublicKeyX963: phoneKeyAgreementPublicKeyX963
            ),
            publicKeyX963: phonePublicKeyX963
        )
    }
}

/// Public, value-free identity returned by the Mac after local Touch ID pins a
/// phone. The companion imports it under iPhone biometrics, then can verify all
/// requests immediately; there is no second enrollment protocol or server key.
public struct RemoteApprovalMacPairing: Codable, Equatable, Sendable {
    public let version: UInt16
    public let macDeviceID: String
    public let macDeviceName: String
    public let macPublicKeyX963: Data
    public let cloudKitContainerIdentifier: String

    public init(
        macDeviceID: String,
        macDeviceName: String,
        macPublicKeyX963: Data,
        cloudKitContainerIdentifier: String
    ) {
        self.version = RemoteApprovalProtocolV3.pairingVersion
        self.macDeviceID = macDeviceID.lowercased()
        self.macDeviceName = macDeviceName
        self.macPublicKeyX963 = macPublicKeyX963
        self.cloudKitContainerIdentifier = cloudKitContainerIdentifier
    }

    public func validate() throws {
        guard version == RemoteApprovalProtocolV3.pairingVersion else {
            throw RemoteApprovalValidationError.invalidVersion
        }
        guard UUID(uuidString: macDeviceID) != nil, macDeviceID.utf8.count == 36 else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard !macDeviceName.isEmpty,
              macDeviceName.utf8.count <= 256,
              !macDeviceName.utf8.contains(0),
              !cloudKitContainerIdentifier.isEmpty,
              cloudKitContainerIdentifier.utf8.count <= 256,
              cloudKitContainerIdentifier.hasPrefix("iCloud."),
              !cloudKitContainerIdentifier.utf8.contains(0) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        do {
            _ = try P256.Signing.PublicKey(x963Representation: macPublicKeyX963)
        } catch {
            throw RemoteApprovalValidationError.invalidPublicKey
        }
    }
}

public enum RemoteApprovalPairingCode {
    public static let phonePrefix = "csec-phone-v2:"
    public static let macPrefix = "csec-mac-v2:"
    private static let maximumCodeBytes = 8 * 1_024

    public static func encodePhone(_ pairing: RemoteApprovalPhonePairing) throws -> String {
        try pairing.validate()
        return phonePrefix + (try encode(pairing))
    }

    public static func decodePhone(_ code: String) throws -> RemoteApprovalPhonePairing {
        let pairing: RemoteApprovalPhonePairing = try decode(code, prefix: phonePrefix)
        try pairing.validate()
        return pairing
    }

    public static func encodeMac(_ pairing: RemoteApprovalMacPairing) throws -> String {
        try pairing.validate()
        return macPrefix + (try encode(pairing))
    }

    public static func decodeMac(_ code: String) throws -> RemoteApprovalMacPairing {
        let pairing: RemoteApprovalMacPairing = try decode(code, prefix: macPrefix)
        try pairing.validate()
        return pairing
    }

    /// The command the phone offers to copy for the Mac. A code is only the
    /// prefix and base64url, so single quotes hold it intact in any shell.
    public static func enableCommand(phoneCode: String) -> String {
        "csec remote enable '\(phoneCode)'"
    }

    public static func publicKeyFingerprint(_ publicKeyX963: Data) -> String {
        SHA256.hash(data: publicKeyX963).prefix(8)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private static func encode<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value)
        guard data.count <= maximumCodeBytes else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        return base64URL(data)
    }

    private static func decode<T: Decodable>(_ code: String, prefix: String) throws -> T {
        guard code.hasPrefix(prefix), code.utf8.count <= maximumCodeBytes * 2 else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        let payload = String(code.dropFirst(prefix.count))
        guard let data = decodeBase64URL(payload), data.count <= maximumCodeBytes else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        guard value.utf8.allSatisfy({ byte in
            (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
                || (byte >= 48 && byte <= 57) || byte == 45 || byte == 95
        }) else { return nil }
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = (4 - base64.count % 4) % 4
        base64.append(String(repeating: "=", count: padding))
        return Data(base64Encoded: base64)
    }
}

/// The phone's signed statement that it pinned this Mac. The Mac reports a
/// pairing ready only once it has verified one, so a Mac code that was never
/// imported, or imported by another phone, is not mistaken for a working pairing.
public struct RemoteApprovalPairingConfirmation: Codable, Equatable, Sendable {
    public let version: UInt16
    public let macDeviceID: String
    /// SHA-256 of the Mac public key the phone pinned.
    public let macPublicKeyDigest: Data
    public let phoneDeviceID: String
    /// SHA-256 of the phone key-agreement key it paired with.
    public let phoneKeyAgreementDigest: Data
    public let phoneAppVersion: String
    public let createdAtMilliseconds: UInt64

    public init(
        macDeviceID: String,
        macPublicKeyX963: Data,
        phoneDeviceID: String,
        phoneKeyAgreementPublicKeyX963: Data,
        phoneAppVersion: String,
        createdAtMilliseconds: UInt64
    ) {
        self.version = RemoteApprovalProtocolV3.pairingVersion
        self.macDeviceID = macDeviceID.lowercased()
        self.macPublicKeyDigest = Data(SHA256.hash(data: macPublicKeyX963))
        self.phoneDeviceID = phoneDeviceID.lowercased()
        self.phoneKeyAgreementDigest = Data(SHA256.hash(data: phoneKeyAgreementPublicKeyX963))
        self.phoneAppVersion = phoneAppVersion
        self.createdAtMilliseconds = createdAtMilliseconds
    }

    public func signingData() throws -> Data {
        guard version == RemoteApprovalProtocolV3.pairingVersion else {
            throw RemoteApprovalValidationError.invalidVersion
        }
        guard validUUID(macDeviceID), validUUID(phoneDeviceID) else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard macPublicKeyDigest.count == SHA256.byteCount,
              phoneKeyAgreementDigest.count == SHA256.byteCount else {
            throw RemoteApprovalValidationError.invalidDigest
        }
        guard bounded(phoneAppVersion, maximum: 64) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        var encoder = CanonicalEncoder(domain: "csec.remote-approval.pairing-confirmation.v1")
        encoder.uint16(version)
        encoder.string(macDeviceID)
        encoder.data(macPublicKeyDigest)
        encoder.string(phoneDeviceID)
        encoder.data(phoneKeyAgreementDigest)
        encoder.string(phoneAppVersion)
        encoder.uint64(createdAtMilliseconds)
        return encoder.data
    }
}

public struct SignedRemoteApprovalPairingConfirmation: Codable, Equatable, Sendable {
    public let confirmation: RemoteApprovalPairingConfirmation
    public let signatureDER: Data

    public init(confirmation: RemoteApprovalPairingConfirmation, signatureDER: Data) {
        self.confirmation = confirmation
        self.signatureDER = signatureDER
    }

    /// Whether this confirms exactly the given pairing: this Mac's ID and key,
    /// the pinned phone, and the key-agreement key the Mac enrolled, signed by
    /// the pinned phone.
    public func verify(
        macDeviceID: String,
        macPublicKeyX963: Data,
        phoneDeviceID: String,
        phonePublicKeyX963: Data,
        phoneKeyAgreementPublicKeyX963: Data
    ) throws {
        guard confirmation.macDeviceID == macDeviceID.lowercased(),
              confirmation.macPublicKeyDigest == Data(SHA256.hash(data: macPublicKeyX963)),
              confirmation.phoneKeyAgreementDigest
                == Data(SHA256.hash(data: phoneKeyAgreementPublicKeyX963)) else {
            throw RemoteApprovalValidationError.wrongRequest
        }
        guard confirmation.phoneDeviceID == phoneDeviceID.lowercased() else {
            throw RemoteApprovalValidationError.wrongDevice
        }
        try RemoteApprovalCrypto.verify(
            signatureDER: signatureDER,
            data: confirmation.signingData(),
            publicKeyX963: phonePublicKeyX963
        )
    }
}

/// The Mac's offer of a pairing to the one phone whose code `csec remote
/// enable` pinned. The Mac leaves it in the private iCloud database so the
/// phone can show the Mac without its code being copied back by hand. It
/// carries what the Mac code carries plus the phone it is for, signed by the
/// offered Mac key, so it shows only that whoever holds that key made this
/// offer to this phone. Which Mac that is, the person still checks as for a
/// pasted code: by comparing the key fingerprint with the one `csec remote
/// enable` printed, before Face ID.
public struct RemoteApprovalPairingOffer: Codable, Equatable, Sendable {
    public let version: UInt16
    public let mac: RemoteApprovalMacPairing
    public let phoneDeviceID: String
    /// SHA-256 of the phone signing key the Mac pinned.
    public let phonePublicKeyDigest: Data
    /// SHA-256 of the phone key-agreement key the Mac enrolled.
    public let phoneKeyAgreementDigest: Data
    public let createdAtMilliseconds: UInt64

    public init(
        mac: RemoteApprovalMacPairing,
        phoneDeviceID: String,
        phonePublicKeyX963: Data,
        phoneKeyAgreementPublicKeyX963: Data,
        createdAtMilliseconds: UInt64
    ) {
        self.version = RemoteApprovalProtocolV3.pairingVersion
        self.mac = mac
        self.phoneDeviceID = phoneDeviceID.lowercased()
        self.phonePublicKeyDigest = Data(SHA256.hash(data: phonePublicKeyX963))
        self.phoneKeyAgreementDigest = Data(SHA256.hash(data: phoneKeyAgreementPublicKeyX963))
        self.createdAtMilliseconds = createdAtMilliseconds
    }

    public func signingData() throws -> Data {
        guard version == RemoteApprovalProtocolV3.pairingVersion else {
            throw RemoteApprovalValidationError.invalidVersion
        }
        try mac.validate()
        guard validUUID(phoneDeviceID) else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard phonePublicKeyDigest.count == SHA256.byteCount,
              phoneKeyAgreementDigest.count == SHA256.byteCount else {
            throw RemoteApprovalValidationError.invalidDigest
        }
        var encoder = CanonicalEncoder(domain: "csec.remote-approval.pairing-offer.v1")
        encoder.uint16(version)
        encoder.uint16(mac.version)
        encoder.string(mac.macDeviceID)
        encoder.string(mac.macDeviceName)
        encoder.data(mac.macPublicKeyX963)
        encoder.string(mac.cloudKitContainerIdentifier)
        encoder.string(phoneDeviceID)
        encoder.data(phonePublicKeyDigest)
        encoder.data(phoneKeyAgreementDigest)
        encoder.uint64(createdAtMilliseconds)
        return encoder.data
    }
}

public struct SignedRemoteApprovalPairingOffer: Codable, Equatable, Sendable {
    public let offer: RemoteApprovalPairingOffer
    public let signatureDER: Data

    public init(offer: RemoteApprovalPairingOffer, signatureDER: Data) {
        self.offer = offer
        self.signatureDER = signatureDER
    }

    /// `offer` signed by the Mac key it offers.
    public static func signed(
        _ offer: RemoteApprovalPairingOffer,
        by signer: any RemoteApprovalRequestSigner
    ) async throws -> SignedRemoteApprovalPairingOffer {
        guard try await signer.publicKeyX963Representation() == offer.mac.macPublicKeyX963 else {
            throw RemoteApprovalValidationError.invalidPublicKey
        }
        let signature = try await signer.sign(try offer.signingData())
        return SignedRemoteApprovalPairingOffer(offer: offer, signatureDER: signature)
    }

    /// The Mac pairing offered to exactly this phone identity — its device ID,
    /// its signing key and the key-agreement key the Mac enrolled — signed by
    /// the Mac key it offers. An offer that verifies is still only a
    /// candidate: the phone shows its name and key and pins it under Face ID,
    /// exactly as for a pasted code.
    public func verifiedMac(
        phoneDeviceID: String,
        phonePublicKeyX963: Data,
        phoneKeyAgreementPublicKeyX963: Data
    ) throws -> RemoteApprovalMacPairing {
        guard offer.phoneDeviceID == phoneDeviceID.lowercased(),
              offer.phonePublicKeyDigest == Data(SHA256.hash(data: phonePublicKeyX963)),
              offer.phoneKeyAgreementDigest
                == Data(SHA256.hash(data: phoneKeyAgreementPublicKeyX963)) else {
            throw RemoteApprovalValidationError.wrongDevice
        }
        try RemoteApprovalCrypto.verify(
            signatureDER: signatureDER,
            data: offer.signingData(),
            publicKeyX963: offer.mac.macPublicKeyX963
        )
        return offer.mac
    }
}

/// Whether a new request raises an alert on the phone. The alert comes from
/// the phone's CloudKit subscription and rides on its push registration;
/// notification permission is reported on its own
/// (`RemoteApprovalPhoneStatus.notificationsAuthorized`).
public enum RemoteApprovalPhoneAlertState: UInt16, Codable, Equatable, Sendable, CaseIterable {
    /// The subscription is saved and the phone is registered for pushes.
    case ready = 1
    /// iCloud refused the subscription with a failure retrying cannot fix,
    /// such as a Production container whose schema lacks the subscription.
    case subscriptionRefused = 2
    /// The phone could not register for push notifications.
    case pushRegistrationFailed = 3
}

/// The phone's signed report of what it can do: its app and protocol
/// versions, whether it may show notifications, whether a request alerts it
/// and which kinds of review it shows. Diagnostics, except that the Mac
/// offers a settings review only to a phone that lists it (`reviewKinds`).
public struct RemoteApprovalPhoneStatus: Codable, Equatable, Sendable {
    public static let maximumReviewKinds = 16
    public static let maximumReviewKindBytes = 32

    public let version: UInt16
    public let phoneDeviceID: String
    public let appVersion: String
    public let protocolVersion: UInt16
    public let notificationsAuthorized: Bool
    /// Absent until the phone has tried to set up its alerts, and in a record
    /// from an app that predates the field; the record is then signed in its
    /// original form, so both kinds verify.
    public let requestAlerts: RemoteApprovalPhoneAlertState?
    /// The `RemoteApprovalReview.Kind` raw values this app shows a card for.
    /// Absent from an app that predates the field, which shows access, SSH,
    /// sudo and restore reviews and drops a settings review unread. Strings,
    /// so a Mac still reads the status of a phone that knows a kind it does
    /// not.
    public let reviewKinds: [String]?
    public let updatedAtMilliseconds: UInt64

    public init(
        phoneDeviceID: String,
        appVersion: String,
        protocolVersion: UInt16 = RemoteApprovalProtocolV3.version,
        notificationsAuthorized: Bool,
        requestAlerts: RemoteApprovalPhoneAlertState? = nil,
        reviewKinds: [String]? = nil,
        updatedAtMilliseconds: UInt64
    ) {
        self.version = RemoteApprovalProtocolV3.pairingVersion
        self.phoneDeviceID = phoneDeviceID.lowercased()
        self.appVersion = appVersion
        self.protocolVersion = protocolVersion
        self.notificationsAuthorized = notificationsAuthorized
        self.requestAlerts = requestAlerts
        self.reviewKinds = reviewKinds
        self.updatedAtMilliseconds = updatedAtMilliseconds
    }

    /// Whether the phone said it shows `kind`'s card.
    public func shows(_ kind: RemoteApprovalReview.Kind) -> Bool {
        reviewKinds?.contains(kind.rawValue) == true
    }

    public func signingData() throws -> Data {
        guard version == RemoteApprovalProtocolV3.pairingVersion else {
            throw RemoteApprovalValidationError.invalidVersion
        }
        guard validUUID(phoneDeviceID) else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard bounded(appVersion, maximum: 64) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        if let reviewKinds {
            guard reviewKinds.count <= Self.maximumReviewKinds,
                  reviewKinds.allSatisfy({ bounded($0, maximum: Self.maximumReviewKindBytes) }) else {
                throw RemoteApprovalValidationError.fieldOutOfBounds
            }
        }
        // Each optional field adds a domain of its own: a record signed with
        // one cannot be passed off as one without it by dropping the field,
        // nor the other way round. A record with review kinds encodes the
        // alert state as present or absent, so neither can stand for the
        // other.
        let domain = reviewKinds != nil
            ? "csec.remote-approval.phone-status.v3"
            : requestAlerts == nil
            ? "csec.remote-approval.phone-status.v1"
            : "csec.remote-approval.phone-status.v2"
        var encoder = CanonicalEncoder(domain: domain)
        encoder.uint16(version)
        encoder.string(phoneDeviceID)
        encoder.string(appVersion)
        encoder.uint16(protocolVersion)
        encoder.bool(notificationsAuthorized)
        if let reviewKinds {
            encoder.optional(requestAlerts) { encoder, alerts in encoder.uint16(alerts.rawValue) }
            encoder.strings(reviewKinds)
        } else if let requestAlerts {
            encoder.uint16(requestAlerts.rawValue)
        }
        encoder.uint64(updatedAtMilliseconds)
        return encoder.data
    }
}

public struct SignedRemoteApprovalPhoneStatus: Codable, Equatable, Sendable {
    public let status: RemoteApprovalPhoneStatus
    public let signatureDER: Data

    public init(status: RemoteApprovalPhoneStatus, signatureDER: Data) {
        self.status = status
        self.signatureDER = signatureDER
    }

    public func verify(phoneDeviceID: String, phonePublicKeyX963: Data) throws {
        guard status.phoneDeviceID == phoneDeviceID.lowercased() else {
            throw RemoteApprovalValidationError.wrongDevice
        }
        try RemoteApprovalCrypto.verify(
            signatureDER: signatureDER,
            data: status.signingData(),
            publicKeyX963: phonePublicKeyX963
        )
    }
}
