import CryptoKit
import Foundation

/// Public, value-free identity exported by the phone during explicit pairing.
/// Possession of this text is not approval; the Mac still requires local Touch
/// ID before pinning it, and every later response needs this key's signature.
public struct RemoteApprovalPhonePairing: Codable, Equatable, Sendable {
    public let version: UInt16
    public let phoneDeviceID: String
    public let phoneDeviceName: String
    public let phonePublicKeyX963: Data

    public init(
        phoneDeviceID: String,
        phoneDeviceName: String,
        phonePublicKeyX963: Data
    ) {
        self.version = RemoteApprovalProtocolV1.version
        self.phoneDeviceID = phoneDeviceID.lowercased()
        self.phoneDeviceName = phoneDeviceName
        self.phonePublicKeyX963 = phonePublicKeyX963
    }

    public func validate() throws {
        guard version == RemoteApprovalProtocolV1.version else {
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
        do {
            _ = try P256.Signing.PublicKey(x963Representation: phonePublicKeyX963)
        } catch {
            throw RemoteApprovalValidationError.invalidPublicKey
        }
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
        self.version = RemoteApprovalProtocolV1.version
        self.macDeviceID = macDeviceID.lowercased()
        self.macDeviceName = macDeviceName
        self.macPublicKeyX963 = macPublicKeyX963
        self.cloudKitContainerIdentifier = cloudKitContainerIdentifier
    }

    public func validate() throws {
        guard version == RemoteApprovalProtocolV1.version else {
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
    public static let phonePrefix = "csec-phone-v1:"
    public static let macPrefix = "csec-mac-v1:"
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
