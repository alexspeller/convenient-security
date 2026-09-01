import CryptoKit
import Foundation
import Security

public enum SSHProtectionError: Error, Sendable, Equatable {
    case malformedMessage
    case unsupportedKeyType
    case encryptedPrivateKey
    case invalidPrivateKey
    case weakRSAKey
    case keyNotRegistered
    case destinationBindingRequired
    case forwardedAgentNotAllowed
    case destinationBindingInvalid
    case signingRequestInvalid
    case authorizationDenied
    case catalogUnavailable
    case providerResolutionFailed
}

extension SSHProtectionError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .malformedMessage:
            return "the SSH agent message is malformed"
        case .unsupportedKeyType:
            return "the SSH key type is not supported"
        case .encryptedPrivateKey:
            return "encrypted private-key files are not supported; import an unencrypted OpenSSH key"
        case .invalidPrivateKey:
            return "the reference did not resolve to a valid private SSH key"
        case .weakRSAKey:
            return "RSA keys must be at least 2048 bits"
        case .keyNotRegistered:
            return "the requested SSH key is not registered"
        case .destinationBindingRequired:
            return "SSH signing requires a verified OpenSSH destination binding"
        case .forwardedAgentNotAllowed:
            return "forwarded SSH-agent use is not supported"
        case .destinationBindingInvalid:
            return "the SSH destination binding could not be verified"
        case .signingRequestInvalid:
            return "the SSH signature request is not a bound user-authentication request"
        case .authorizationDenied:
            return "SSH signing authorization was denied"
        case .catalogUnavailable:
            return "the SSH key catalog is unavailable"
        case .providerResolutionFailed:
            return "the SSH key provider could not resolve the registered reference"
        }
    }
}

/// Bounded SSH wire reader. Every caller must finish with `isAtEnd`; trailing
/// fields are rejected so a validated prefix cannot hide a different request.
struct SSHWireReader {
    private let bytes: [UInt8]
    private(set) var offset = 0

    init(_ data: Data) {
        self.bytes = Array(data)
    }

    var isAtEnd: Bool { offset == bytes.count }
    var remainingCount: Int { bytes.count - offset }

    mutating func readByte() throws -> UInt8 {
        guard offset < bytes.count else { throw SSHProtectionError.malformedMessage }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func readUInt32() throws -> UInt32 {
        guard remainingCount >= 4 else { throw SSHProtectionError.malformedMessage }
        let value = (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
        offset += 4
        return value
    }

    mutating func readString(maximumBytes: Int = 256 * 1_024) throws -> Data {
        let length = Int(try readUInt32())
        guard length <= maximumBytes, length <= remainingCount else {
            throw SSHProtectionError.malformedMessage
        }
        defer { offset += length }
        return Data(bytes[offset..<(offset + length)])
    }

    mutating func readUTF8(maximumBytes: Int = 4_096) throws -> String {
        let data = try readString(maximumBytes: maximumBytes)
        guard let value = String(data: data, encoding: .utf8), !value.utf8.contains(0) else {
            throw SSHProtectionError.malformedMessage
        }
        return value
    }

    /// Read a canonical, non-negative SSH mpint and return its unsigned bytes.
    mutating func readPositiveMPInt(maximumBytes: Int = 2 * 1_024) throws -> Data {
        var value = [UInt8](try readString(maximumBytes: maximumBytes))
        if value.isEmpty { return Data() }
        guard value[0] & 0x80 == 0 else { throw SSHProtectionError.malformedMessage }
        if value.count > 1, value[0] == 0, value[1] & 0x80 == 0 {
            throw SSHProtectionError.malformedMessage
        }
        if value.first == 0 { value.removeFirst() }
        return Data(value)
    }
}

struct SSHWireWriter {
    private(set) var data = Data()

    mutating func appendByte(_ value: UInt8) { data.append(value) }

    mutating func appendUInt32(_ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    mutating func appendString(_ value: Data) {
        precondition(value.count <= Int(UInt32.max))
        appendUInt32(UInt32(value.count))
        data.append(value)
    }

    mutating func appendString(_ value: String) {
        appendString(Data(value.utf8))
    }

    mutating func appendPositiveMPInt(_ unsigned: Data) {
        var bytes = [UInt8](unsigned)
        while bytes.first == 0 { bytes.removeFirst() }
        if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
        appendString(Data(bytes))
    }
}

enum SSHCurve: String, Sendable {
    case nistp256
    case nistp384
    case nistp521

    var algorithm: String { "ecdsa-sha2-\(rawValue)" }
    var scalarBytes: Int {
        switch self {
        case .nistp256: return 32
        case .nistp384: return 48
        case .nistp521: return 66
        }
    }

    var pointBytes: Int { 1 + 2 * scalarBytes }
}

enum SSHPublicKey: Sendable {
    case ed25519(Data)
    case ecdsa(SSHCurve, Data)
    case rsa(exponent: Data, modulus: Data)

    var algorithm: String {
        switch self {
        case .ed25519: return "ssh-ed25519"
        case let .ecdsa(curve, _): return curve.algorithm
        case .rsa: return "ssh-rsa"
        }
    }

    var blob: Data {
        var writer = SSHWireWriter()
        writer.appendString(algorithm)
        switch self {
        case let .ed25519(publicKey):
            writer.appendString(publicKey)
        case let .ecdsa(curve, point):
            writer.appendString(curve.rawValue)
            writer.appendString(point)
        case let .rsa(exponent, modulus):
            writer.appendPositiveMPInt(exponent)
            writer.appendPositiveMPInt(modulus)
        }
        return writer.data
    }

    var fingerprint: String {
        let encoded = Data(SHA256.hash(data: blob)).base64EncodedString()
            .trimmingCharacters(in: CharacterSet(charactersIn: "="))
        return "SHA256:\(encoded)"
    }

    static func parse(_ blob: Data, requireStrongRSA: Bool = true) throws -> SSHPublicKey {
        var reader = SSHWireReader(blob)
        let algorithm = try reader.readUTF8(maximumBytes: 128)
        let key: SSHPublicKey
        switch algorithm {
        case "ssh-ed25519":
            let publicKey = try reader.readString(maximumBytes: 64)
            guard publicKey.count == 32 else { throw SSHProtectionError.malformedMessage }
            key = .ed25519(publicKey)
        case SSHCurve.nistp256.algorithm, SSHCurve.nistp384.algorithm,
             SSHCurve.nistp521.algorithm:
            guard let curve = SSHCurve(rawValue: try reader.readUTF8(maximumBytes: 32)),
                  curve.algorithm == algorithm else {
                throw SSHProtectionError.malformedMessage
            }
            let point = try reader.readString(maximumBytes: 256)
            guard point.count == curve.pointBytes, point.first == 4 else {
                throw SSHProtectionError.malformedMessage
            }
            key = .ecdsa(curve, point)
        case "ssh-rsa":
            let exponent = try reader.readPositiveMPInt(maximumBytes: 16)
            let modulus = try reader.readPositiveMPInt(maximumBytes: 2 * 1_024)
            guard !exponent.isEmpty, !modulus.isEmpty else {
                throw SSHProtectionError.malformedMessage
            }
            if requireStrongRSA, bitCount(modulus) < 2_048 {
                throw SSHProtectionError.weakRSAKey
            }
            key = .rsa(exponent: exponent, modulus: modulus)
        default:
            throw SSHProtectionError.unsupportedKeyType
        }
        guard reader.isAtEnd else { throw SSHProtectionError.malformedMessage }
        return key
    }

    func verify(signatureBlob: Data, message: Data) throws -> Bool {
        var signatureReader = SSHWireReader(signatureBlob)
        let signatureAlgorithm = try signatureReader.readUTF8(maximumBytes: 128)
        let signature = try signatureReader.readString(maximumBytes: 16 * 1_024)
        guard signatureReader.isAtEnd else { throw SSHProtectionError.malformedMessage }

        switch self {
        case let .ed25519(publicBytes):
            guard signatureAlgorithm == "ssh-ed25519", signature.count == 64 else { return false }
            return try Curve25519.Signing.PublicKey(rawRepresentation: publicBytes)
                .isValidSignature(signature, for: message)
        case let .ecdsa(curve, point):
            guard signatureAlgorithm == curve.algorithm else { return false }
            let raw = try Self.ecdsaRawSignature(signature, scalarBytes: curve.scalarBytes)
            switch curve {
            case .nistp256:
                let key = try P256.Signing.PublicKey(x963Representation: point)
                let value = try P256.Signing.ECDSASignature(rawRepresentation: raw)
                return key.isValidSignature(value, for: message)
            case .nistp384:
                let key = try P384.Signing.PublicKey(x963Representation: point)
                let value = try P384.Signing.ECDSASignature(rawRepresentation: raw)
                return key.isValidSignature(value, for: message)
            case .nistp521:
                let key = try P521.Signing.PublicKey(x963Representation: point)
                let value = try P521.Signing.ECDSASignature(rawRepresentation: raw)
                return key.isValidSignature(value, for: message)
            }
        case let .rsa(exponent, modulus):
            let algorithm: SecKeyAlgorithm
            switch signatureAlgorithm {
            case "rsa-sha2-256": algorithm = .rsaSignatureMessagePKCS1v15SHA256
            case "rsa-sha2-512": algorithm = .rsaSignatureMessagePKCS1v15SHA512
            default: return false // SHA-1 ssh-rsa signatures are deliberately refused.
            }
            guard let key = SSHSecurityKey.rsaPublic(exponent: exponent, modulus: modulus) else {
                return false
            }
            var error: Unmanaged<CFError>?
            return SecKeyVerifySignature(
                key, algorithm, message as CFData, signature as CFData, &error
            )
        }
    }

    private static func ecdsaRawSignature(_ encoded: Data, scalarBytes: Int) throws -> Data {
        var reader = SSHWireReader(encoded)
        let r = try reader.readPositiveMPInt(maximumBytes: scalarBytes + 1)
        let s = try reader.readPositiveMPInt(maximumBytes: scalarBytes + 1)
        guard reader.isAtEnd, r.count <= scalarBytes, s.count <= scalarBytes else {
            throw SSHProtectionError.malformedMessage
        }
        return Data(repeating: 0, count: scalarBytes - r.count) + r
            + Data(repeating: 0, count: scalarBytes - s.count) + s
    }
}

public struct SSHDestinationBinding: Sendable, Equatable {
    public let hostKeyBlob: Data
    public let sessionIdentifier: Data
    public let hostKeyFingerprint: String

    public init(
        hostKeyBlob: Data,
        sessionIdentifier: Data,
        signature: Data,
        isForwarding: Bool
    ) throws {
        guard !isForwarding else { throw SSHProtectionError.forwardedAgentNotAllowed }
        guard !sessionIdentifier.isEmpty, sessionIdentifier.count <= 1_024 else {
            throw SSHProtectionError.destinationBindingInvalid
        }
        let hostKey = try SSHPublicKey.parse(hostKeyBlob)
        guard try hostKey.verify(signatureBlob: signature, message: sessionIdentifier) else {
            throw SSHProtectionError.destinationBindingInvalid
        }
        self.hostKeyBlob = hostKeyBlob
        self.sessionIdentifier = sessionIdentifier
        self.hostKeyFingerprint = hostKey.fingerprint
    }
}

public struct SSHBoundUserAuthentication: Sendable, Equatable {
    public let remoteUser: String
    public let publicKeyBlob: Data
    public let publicKeyAlgorithm: String

    public static func parse(
        signedData: Data,
        binding: SSHDestinationBinding,
        requestedKeyBlob: Data,
        flags: UInt32
    ) throws -> SSHBoundUserAuthentication {
        var reader = SSHWireReader(signedData)
        let sessionIdentifier = try reader.readString(maximumBytes: 1_024)
        guard sessionIdentifier == binding.sessionIdentifier,
              try reader.readByte() == 50 else {
            throw SSHProtectionError.signingRequestInvalid
        }
        let remoteUser = try reader.readUTF8(maximumBytes: 256)
        let service = try reader.readUTF8(maximumBytes: 128)
        let method = try reader.readUTF8(maximumBytes: 128)
        let hasSignature = try reader.readByte()
        let algorithm = try reader.readUTF8(maximumBytes: 128)
        let publicKeyBlob = try reader.readString(maximumBytes: 16 * 1_024)
        guard !remoteUser.isEmpty,
              ReviewDisplay.sanitized(remoteUser) == remoteUser,
              service == "ssh-connection",
              hasSignature == 1,
              publicKeyBlob == requestedKeyBlob else {
            throw SSHProtectionError.signingRequestInvalid
        }

        let parsedKey = try SSHPublicKey.parse(publicKeyBlob)
        let algorithmAndFlagsMatch: Bool
        if parsedKey.algorithm == "ssh-rsa" {
            algorithmAndFlagsMatch = (algorithm == "rsa-sha2-256" && flags == 0x02)
                || (algorithm == "rsa-sha2-512" && flags == 0x04)
        } else {
            algorithmAndFlagsMatch = parsedKey.algorithm == algorithm && flags == 0
        }
        guard algorithmAndFlagsMatch else { throw SSHProtectionError.signingRequestInvalid }

        switch method {
        case "publickey":
            break
        case "publickey-hostbound-v00@openssh.com":
            let hostKey = try reader.readString(maximumBytes: 16 * 1_024)
            guard hostKey == binding.hostKeyBlob else {
                throw SSHProtectionError.signingRequestInvalid
            }
        default:
            throw SSHProtectionError.signingRequestInvalid
        }
        guard reader.isAtEnd else { throw SSHProtectionError.signingRequestInvalid }
        return SSHBoundUserAuthentication(
            remoteUser: remoteUser,
            publicKeyBlob: publicKeyBlob,
            publicKeyAlgorithm: algorithm
        )
    }
}

enum SSHSecurityKey {
    static func rsaPublic(exponent: Data, modulus: Data) -> SecKey? {
        let der = ASN1.sequence([ASN1.integer(modulus), ASN1.integer(exponent)])
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: bitCount(modulus),
        ]
        return SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil)
    }
}

enum ASN1 {
    static func sequence(_ values: [Data]) -> Data {
        tagged(0x30, values.reduce(into: Data()) { $0.append($1) })
    }

    static func integer(_ unsigned: Data) -> Data {
        var bytes = [UInt8](unsigned)
        while bytes.count > 1, bytes.first == 0 { bytes.removeFirst() }
        if bytes.isEmpty { bytes = [0] }
        if bytes[0] & 0x80 != 0 { bytes.insert(0, at: 0) }
        return tagged(0x02, Data(bytes))
    }

    static func tagged(_ tag: UInt8, _ contents: Data) -> Data {
        var result = Data([tag])
        if contents.count < 128 {
            result.append(UInt8(contents.count))
        } else {
            var length = contents.count
            var encoded: [UInt8] = []
            while length > 0 {
                encoded.insert(UInt8(length & 0xff), at: 0)
                length >>= 8
            }
            result.append(0x80 | UInt8(encoded.count))
            result.append(contentsOf: encoded)
        }
        result.append(contents)
        return result
    }
}

func bitCount(_ unsigned: Data) -> Int {
    guard let firstNonzero = unsigned.firstIndex(where: { $0 != 0 }) else { return 0 }
    let first = unsigned[firstNonzero]
    return (unsigned.count - firstNonzero - 1) * 8 + (8 - first.leadingZeroBitCount)
}
