import CryptoKit
import Foundation
import Security

/// Parsed only inside csecd's narrow signing/registration boundary. The private
/// representation is never returned to a protocol client or retained by the SSH
/// catalog; each signature operation resolves and parses through SecretResolver.
public struct SSHPrivateKey: @unchecked Sendable {
    private enum Storage {
        case ed25519(Curve25519.Signing.PrivateKey)
        case p256(P256.Signing.PrivateKey)
        case p384(P384.Signing.PrivateKey)
        case p521(P521.Signing.PrivateKey)
        case rsa(SecKey)
    }

    private let storage: Storage
    public let publicKeyBlob: Data
    public let algorithm: String
    public let comment: String

    private init(storage: Storage, publicKey: SSHPublicKey, comment: String) {
        self.storage = storage
        self.publicKeyBlob = publicKey.blob
        self.algorithm = publicKey.algorithm
        self.comment = ReviewDisplay.sanitized(comment)
    }

    public static func parse(_ data: Data) throws -> SSHPrivateKey {
        guard !data.isEmpty, data.count <= 4 * 1_024 * 1_024,
              let text = String(data: data, encoding: .utf8) else {
            throw SSHProtectionError.invalidPrivateKey
        }
        if text.contains("BEGIN ENCRYPTED PRIVATE KEY")
            || text.contains("Proc-Type: 4,ENCRYPTED") {
            throw SSHProtectionError.encryptedPrivateKey
        }
        if let body = pemBody(text, label: "OPENSSH PRIVATE KEY") {
            return try parseOpenSSH(body)
        }
        if let body = pemBody(text, label: "RSA PRIVATE KEY") {
            return try parseRSAPKCS1(body, comment: "")
        }
        if let body = pemBody(text, label: "EC PRIVATE KEY") {
            return try parseECSEC1(body, curveHint: nil, comment: "")
        }
        if let body = pemBody(text, label: "PRIVATE KEY") {
            return try parsePKCS8(body)
        }
        throw SSHProtectionError.invalidPrivateKey
    }

    /// Return the SSH signature blob (`string algorithm`, `string signature`).
    /// RSA/SHA-1 is intentionally unavailable: RSA callers must request SHA-256
    /// or SHA-512 using the standard agent flags.
    public func sign(_ message: Data, flags: UInt32) throws -> Data {
        let signatureAlgorithm: String
        let signature: Data
        switch storage {
        case let .ed25519(key):
            guard flags == 0 else { throw SSHProtectionError.signingRequestInvalid }
            signatureAlgorithm = "ssh-ed25519"
            signature = try key.signature(for: message)
        case let .p256(key):
            guard flags == 0 else { throw SSHProtectionError.signingRequestInvalid }
            signatureAlgorithm = SSHCurve.nistp256.algorithm
            signature = Self.encodeECDSASignature(
                try key.signature(for: message).rawRepresentation,
                scalarBytes: SSHCurve.nistp256.scalarBytes
            )
        case let .p384(key):
            guard flags == 0 else { throw SSHProtectionError.signingRequestInvalid }
            signatureAlgorithm = SSHCurve.nistp384.algorithm
            signature = Self.encodeECDSASignature(
                try key.signature(for: message).rawRepresentation,
                scalarBytes: SSHCurve.nistp384.scalarBytes
            )
        case let .p521(key):
            guard flags == 0 else { throw SSHProtectionError.signingRequestInvalid }
            signatureAlgorithm = SSHCurve.nistp521.algorithm
            signature = Self.encodeECDSASignature(
                try key.signature(for: message).rawRepresentation,
                scalarBytes: SSHCurve.nistp521.scalarBytes
            )
        case let .rsa(key):
            let secAlgorithm: SecKeyAlgorithm
            switch flags {
            case 0x02:
                signatureAlgorithm = "rsa-sha2-256"
                secAlgorithm = .rsaSignatureMessagePKCS1v15SHA256
            case 0x04:
                signatureAlgorithm = "rsa-sha2-512"
                secAlgorithm = .rsaSignatureMessagePKCS1v15SHA512
            default:
                throw SSHProtectionError.signingRequestInvalid
            }
            guard SecKeyIsAlgorithmSupported(key, .sign, secAlgorithm) else {
                throw SSHProtectionError.unsupportedKeyType
            }
            var error: Unmanaged<CFError>?
            guard let result = SecKeyCreateSignature(
                key, secAlgorithm, message as CFData, &error
            ) as Data? else {
                throw SSHProtectionError.invalidPrivateKey
            }
            signature = result
        }

        var writer = SSHWireWriter()
        writer.appendString(signatureAlgorithm)
        writer.appendString(signature)
        return writer.data
    }

    private static func parseOpenSSH(_ encoded: Data) throws -> SSHPrivateKey {
        let magic = Data("openssh-key-v1\0".utf8)
        guard encoded.count > magic.count, encoded.prefix(magic.count) == magic else {
            throw SSHProtectionError.invalidPrivateKey
        }
        var reader = SSHWireReader(encoded.dropFirst(magic.count))
        let cipher = try reader.readUTF8(maximumBytes: 128)
        let kdf = try reader.readUTF8(maximumBytes: 128)
        let kdfOptions = try reader.readString(maximumBytes: 1_024)
        guard cipher == "none", kdf == "none", kdfOptions.isEmpty else {
            throw SSHProtectionError.encryptedPrivateKey
        }
        guard try reader.readUInt32() == 1 else {
            throw SSHProtectionError.unsupportedKeyType
        }
        let outerPublicBlob = try reader.readString(maximumBytes: 16 * 1_024)
        _ = try SSHPublicKey.parse(outerPublicBlob)
        let privateBlock = try reader.readString(maximumBytes: 4 * 1_024 * 1_024)
        guard reader.isAtEnd else { throw SSHProtectionError.invalidPrivateKey }

        var privateReader = SSHWireReader(privateBlock)
        let check = try privateReader.readUInt32()
        guard try privateReader.readUInt32() == check else {
            throw SSHProtectionError.invalidPrivateKey
        }
        let keyType = try privateReader.readUTF8(maximumBytes: 128)
        let result: SSHPrivateKey
        switch keyType {
        case "ssh-ed25519":
            let publicBytes = try privateReader.readString(maximumBytes: 64)
            let privateBytes = try privateReader.readString(maximumBytes: 128)
            let comment = try privateReader.readUTF8(maximumBytes: 1_024)
            guard publicBytes.count == 32, privateBytes.count == 64,
                  privateBytes.suffix(32) == publicBytes else {
                throw SSHProtectionError.invalidPrivateKey
            }
            let key = try Curve25519.Signing.PrivateKey(
                rawRepresentation: privateBytes.prefix(32)
            )
            let publicKey = SSHPublicKey.ed25519(key.publicKey.rawRepresentation)
            guard publicKey.blob == outerPublicBlob else {
                throw SSHProtectionError.invalidPrivateKey
            }
            result = SSHPrivateKey(storage: .ed25519(key), publicKey: publicKey, comment: comment)
        case SSHCurve.nistp256.algorithm, SSHCurve.nistp384.algorithm,
             SSHCurve.nistp521.algorithm:
            guard let curve = SSHCurve(rawValue: try privateReader.readUTF8(maximumBytes: 32)),
                  curve.algorithm == keyType else {
                throw SSHProtectionError.invalidPrivateKey
            }
            let point = try privateReader.readString(maximumBytes: 256)
            let scalar = try privateReader.readPositiveMPInt(maximumBytes: curve.scalarBytes + 1)
            let comment = try privateReader.readUTF8(maximumBytes: 1_024)
            result = try makeEC(curve: curve, scalar: scalar, expectedPoint: point, comment: comment)
            guard result.publicKeyBlob == outerPublicBlob else {
                throw SSHProtectionError.invalidPrivateKey
            }
        case "ssh-rsa":
            let modulus = try privateReader.readPositiveMPInt(maximumBytes: 2 * 1_024)
            let exponent = try privateReader.readPositiveMPInt(maximumBytes: 16)
            let privateExponent = try privateReader.readPositiveMPInt(maximumBytes: 2 * 1_024)
            let coefficient = try privateReader.readPositiveMPInt(maximumBytes: 2 * 1_024)
            let primeP = try privateReader.readPositiveMPInt(maximumBytes: 2 * 1_024)
            let primeQ = try privateReader.readPositiveMPInt(maximumBytes: 2 * 1_024)
            let comment = try privateReader.readUTF8(maximumBytes: 1_024)
            result = try makeRSA(
                modulus: modulus,
                exponent: exponent,
                privateExponent: privateExponent,
                coefficient: coefficient,
                primeP: primeP,
                primeQ: primeQ,
                comment: comment
            )
            guard result.publicKeyBlob == outerPublicBlob else {
                throw SSHProtectionError.invalidPrivateKey
            }
        default:
            throw SSHProtectionError.unsupportedKeyType
        }
        try validatePadding(&privateReader)
        return result
    }

    private static func makeEC(
        curve: SSHCurve,
        scalar: Data,
        expectedPoint: Data?,
        comment: String
    ) throws -> SSHPrivateKey {
        guard !scalar.isEmpty, scalar.count <= curve.scalarBytes else {
            throw SSHProtectionError.invalidPrivateKey
        }
        let padded = Data(repeating: 0, count: curve.scalarBytes - scalar.count) + scalar
        switch curve {
        case .nistp256:
            let key = try P256.Signing.PrivateKey(rawRepresentation: padded)
            let point = key.publicKey.x963Representation
            guard expectedPoint == nil || expectedPoint == point else {
                throw SSHProtectionError.invalidPrivateKey
            }
            return SSHPrivateKey(
                storage: .p256(key), publicKey: .ecdsa(curve, point), comment: comment
            )
        case .nistp384:
            let key = try P384.Signing.PrivateKey(rawRepresentation: padded)
            let point = key.publicKey.x963Representation
            guard expectedPoint == nil || expectedPoint == point else {
                throw SSHProtectionError.invalidPrivateKey
            }
            return SSHPrivateKey(
                storage: .p384(key), publicKey: .ecdsa(curve, point), comment: comment
            )
        case .nistp521:
            let key = try P521.Signing.PrivateKey(rawRepresentation: padded)
            let point = key.publicKey.x963Representation
            guard expectedPoint == nil || expectedPoint == point else {
                throw SSHProtectionError.invalidPrivateKey
            }
            return SSHPrivateKey(
                storage: .p521(key), publicKey: .ecdsa(curve, point), comment: comment
            )
        }
    }

    private static func makeRSA(
        modulus: Data,
        exponent: Data,
        privateExponent: Data,
        coefficient: Data,
        primeP: Data,
        primeQ: Data,
        comment: String
    ) throws -> SSHPrivateKey {
        guard bitCount(modulus) >= 2_048,
              !exponent.isEmpty, !privateExponent.isEmpty,
              !primeP.isEmpty, !primeQ.isEmpty, !coefficient.isEmpty else {
            if bitCount(modulus) < 2_048 { throw SSHProtectionError.weakRSAKey }
            throw SSHProtectionError.invalidPrivateKey
        }
        let pMinusOne = try BigUnsigned.subtractOne(primeP)
        let qMinusOne = try BigUnsigned.subtractOne(primeQ)
        let exponentP = try BigUnsigned.mod(privateExponent, pMinusOne)
        let exponentQ = try BigUnsigned.mod(privateExponent, qMinusOne)
        let der = ASN1.sequence([
            ASN1.integer(Data()),
            ASN1.integer(modulus), ASN1.integer(exponent), ASN1.integer(privateExponent),
            ASN1.integer(primeP), ASN1.integer(primeQ),
            ASN1.integer(exponentP), ASN1.integer(exponentQ), ASN1.integer(coefficient),
        ])
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: bitCount(modulus),
        ]
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil) else {
            throw SSHProtectionError.invalidPrivateKey
        }
        return SSHPrivateKey(
            storage: .rsa(key),
            publicKey: .rsa(exponent: exponent, modulus: modulus),
            comment: comment
        )
    }

    private static func parseRSAPKCS1(_ der: Data, comment: String) throws -> SSHPrivateKey {
        var outer = DERReader(der)
        var sequence = DERReader(try outer.read(tag: 0x30))
        guard outer.isAtEnd,
              try sequence.readInteger() == Data(),
              !sequence.isAtEnd else {
            throw SSHProtectionError.invalidPrivateKey
        }
        let modulus = try sequence.readInteger()
        let exponent = try sequence.readInteger()
        let privateExponent = try sequence.readInteger()
        let primeP = try sequence.readInteger()
        let primeQ = try sequence.readInteger()
        let exponentP = try sequence.readInteger()
        let exponentQ = try sequence.readInteger()
        let coefficient = try sequence.readInteger()
        guard sequence.isAtEnd, bitCount(modulus) >= 2_048,
              !privateExponent.isEmpty, !primeP.isEmpty, !primeQ.isEmpty,
              !exponentP.isEmpty, !exponentQ.isEmpty, !coefficient.isEmpty else {
            if bitCount(modulus) < 2_048 { throw SSHProtectionError.weakRSAKey }
            throw SSHProtectionError.invalidPrivateKey
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: bitCount(modulus),
        ]
        guard let key = SecKeyCreateWithData(der as CFData, attributes as CFDictionary, nil) else {
            throw SSHProtectionError.invalidPrivateKey
        }
        return SSHPrivateKey(
            storage: .rsa(key),
            publicKey: .rsa(exponent: exponent, modulus: modulus),
            comment: comment
        )
    }

    private static func parseECSEC1(
        _ der: Data,
        curveHint: SSHCurve?,
        comment: String
    ) throws -> SSHPrivateKey {
        var outer = DERReader(der)
        var sequence = DERReader(try outer.read(tag: 0x30))
        guard outer.isAtEnd, try sequence.readInteger() == Data([1]) else {
            throw SSHProtectionError.invalidPrivateKey
        }
        let scalar = try sequence.read(tag: 0x04)
        var curve = curveHint
        var expectedPoint: Data?
        while !sequence.isAtEnd {
            let field = try sequence.readAny()
            switch field.tag {
            case 0xa0:
                var parameters = DERReader(field.contents)
                curve = try curveFromOID(parameters.read(tag: 0x06))
                guard parameters.isAtEnd else { throw SSHProtectionError.invalidPrivateKey }
            case 0xa1:
                var publicField = DERReader(field.contents)
                let bitString = try publicField.read(tag: 0x03)
                guard publicField.isAtEnd, bitString.first == 0 else {
                    throw SSHProtectionError.invalidPrivateKey
                }
                expectedPoint = bitString.dropFirst()
            default:
                throw SSHProtectionError.invalidPrivateKey
            }
        }
        guard let curve else { throw SSHProtectionError.invalidPrivateKey }
        return try makeEC(
            curve: curve, scalar: scalar, expectedPoint: expectedPoint, comment: comment
        )
    }

    private static func parsePKCS8(_ der: Data) throws -> SSHPrivateKey {
        var outer = DERReader(der)
        var sequence = DERReader(try outer.read(tag: 0x30))
        guard outer.isAtEnd, try sequence.readInteger() == Data() else {
            throw SSHProtectionError.invalidPrivateKey
        }
        var algorithm = DERReader(try sequence.read(tag: 0x30))
        let algorithmOID = try algorithm.read(tag: 0x06)
        var parameterOID: Data?
        if !algorithm.isAtEnd {
            let parameter = try algorithm.readAny()
            if parameter.tag == 0x06 { parameterOID = parameter.contents }
            else if parameter.tag != 0x05 || !parameter.contents.isEmpty {
                throw SSHProtectionError.invalidPrivateKey
            }
        }
        guard algorithm.isAtEnd else { throw SSHProtectionError.invalidPrivateKey }
        let privateBytes = try sequence.read(tag: 0x04)
        guard sequence.isAtEnd else { throw SSHProtectionError.invalidPrivateKey }

        switch algorithmOID {
        case OID.rsaEncryption:
            return try parseRSAPKCS1(privateBytes, comment: "")
        case OID.ecPublicKey:
            guard let parameterOID else { throw SSHProtectionError.invalidPrivateKey }
            return try parseECSEC1(
                privateBytes, curveHint: try curveFromOID(parameterOID), comment: ""
            )
        case OID.ed25519:
            var seed = privateBytes
            if seed.count != 32 {
                var nested = DERReader(seed)
                seed = try nested.read(tag: 0x04)
                guard nested.isAtEnd else { throw SSHProtectionError.invalidPrivateKey }
            }
            guard seed.count == 32 else { throw SSHProtectionError.invalidPrivateKey }
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            return SSHPrivateKey(
                storage: .ed25519(key),
                publicKey: .ed25519(key.publicKey.rawRepresentation),
                comment: ""
            )
        default:
            throw SSHProtectionError.unsupportedKeyType
        }
    }

    private static func curveFromOID(_ oid: Data) throws -> SSHCurve {
        switch oid {
        case OID.prime256v1: return .nistp256
        case OID.secp384r1: return .nistp384
        case OID.secp521r1: return .nistp521
        default: throw SSHProtectionError.unsupportedKeyType
        }
    }

    private static func validatePadding(_ reader: inout SSHWireReader) throws {
        // The OpenSSH format pads *until* the block length is aligned. A key
        // whose private section is already aligned legitimately has zero
        // padding bytes; otherwise the bytes must be the canonical 1, 2, … run.
        guard reader.remainingCount <= 255 else {
            throw SSHProtectionError.invalidPrivateKey
        }
        var expected: UInt8 = 1
        while !reader.isAtEnd {
            guard try reader.readByte() == expected else {
                throw SSHProtectionError.invalidPrivateKey
            }
            expected = expected == 255 ? 1 : expected + 1
        }
    }

    private static func encodeECDSASignature(_ raw: Data, scalarBytes: Int) -> Data {
        precondition(raw.count == scalarBytes * 2)
        var writer = SSHWireWriter()
        writer.appendPositiveMPInt(raw.prefix(scalarBytes))
        writer.appendPositiveMPInt(raw.suffix(scalarBytes))
        return writer.data
    }

    private static func pemBody(_ text: String, label: String) -> Data? {
        let begin = "-----BEGIN \(label)-----"
        let end = "-----END \(label)-----"
        guard let startRange = text.range(of: begin),
              text[..<startRange.lowerBound].allSatisfy(\.isWhitespace),
              let endRange = text.range(of: end, range: startRange.upperBound..<text.endIndex),
              text[endRange.upperBound...].allSatisfy(\.isWhitespace)
        else { return nil }
        let body = text[startRange.upperBound..<endRange.lowerBound]
            .filter { !$0.isWhitespace }
        guard !body.isEmpty, body.utf8.count <= 8 * 1_024 * 1_024 else { return nil }
        return Data(base64Encoded: String(body))
    }
}

private struct DERReader {
    struct Field { let tag: UInt8; let contents: Data }

    private let bytes: [UInt8]
    private var offset = 0
    var isAtEnd: Bool { offset == bytes.count }

    init(_ data: Data) { bytes = Array(data) }

    mutating func read(tag expected: UInt8) throws -> Data {
        let field = try readAny()
        guard field.tag == expected else { throw SSHProtectionError.invalidPrivateKey }
        return field.contents
    }

    mutating func readAny() throws -> Field {
        guard offset < bytes.count else { throw SSHProtectionError.invalidPrivateKey }
        let tag = bytes[offset]
        offset += 1
        guard offset < bytes.count else { throw SSHProtectionError.invalidPrivateKey }
        let firstLength = bytes[offset]
        offset += 1
        let length: Int
        if firstLength & 0x80 == 0 {
            length = Int(firstLength)
        } else {
            let count = Int(firstLength & 0x7f)
            guard count > 0, count <= 4, offset + count <= bytes.count,
                  bytes[offset] != 0 else {
                throw SSHProtectionError.invalidPrivateKey
            }
            var value = 0
            for _ in 0..<count {
                value = (value << 8) | Int(bytes[offset])
                offset += 1
            }
            guard value >= 128 else { throw SSHProtectionError.invalidPrivateKey }
            length = value
        }
        guard length <= bytes.count - offset else { throw SSHProtectionError.invalidPrivateKey }
        defer { offset += length }
        return Field(tag: tag, contents: Data(bytes[offset..<(offset + length)]))
    }

    mutating func readInteger() throws -> Data {
        var value = [UInt8](try read(tag: 0x02))
        guard !value.isEmpty, value[0] & 0x80 == 0 else {
            throw SSHProtectionError.invalidPrivateKey
        }
        if value.count > 1, value[0] == 0 {
            guard value[1] & 0x80 != 0 else { throw SSHProtectionError.invalidPrivateKey }
            value.removeFirst()
        }
        while value.first == 0 { value.removeFirst() }
        return Data(value)
    }
}

private enum OID {
    static let rsaEncryption = Data([0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
    static let ecPublicKey = Data([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01])
    static let prime256v1 = Data([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])
    static let secp384r1 = Data([0x2b, 0x81, 0x04, 0x00, 0x22])
    static let secp521r1 = Data([0x2b, 0x81, 0x04, 0x00, 0x23])
    static let ed25519 = Data([0x2b, 0x65, 0x70])
}

/// Minimal unsigned arithmetic used only to derive RSA CRT exponents from the
/// OpenSSH n/e/d/iqmp/p/q representation before importing it into Security.framework.
private enum BigUnsigned {
    private struct Value: Comparable {
        var words: [UInt32] // little-endian

        init(_ data: Data) {
            var result: [UInt32] = []
            var accumulator: UInt32 = 0
            var byteCount = 0
            for byte in data.reversed() {
                accumulator |= UInt32(byte) << (byteCount * 8)
                byteCount += 1
                if byteCount == 4 {
                    result.append(accumulator)
                    accumulator = 0
                    byteCount = 0
                }
            }
            if byteCount > 0 { result.append(accumulator) }
            words = result
            normalize()
        }

        static func < (lhs: Value, rhs: Value) -> Bool {
            if lhs.words.count != rhs.words.count { return lhs.words.count < rhs.words.count }
            for index in lhs.words.indices.reversed() where lhs.words[index] != rhs.words[index] {
                return lhs.words[index] < rhs.words[index]
            }
            return false
        }

        mutating func shiftLeft(addBit: Bool) {
            var carry: UInt64 = addBit ? 1 : 0
            for index in words.indices {
                let value = (UInt64(words[index]) << 1) | carry
                words[index] = UInt32(value & 0xffff_ffff)
                carry = value >> 32
            }
            if carry != 0 { words.append(UInt32(carry)) }
            if words.isEmpty, addBit { words = [1] }
        }

        mutating func subtract(_ other: Value) {
            precondition(self >= other)
            var borrow: UInt64 = 0
            for index in words.indices {
                let rhs = index < other.words.count ? UInt64(other.words[index]) : 0
                let lhs = UInt64(words[index])
                let required = rhs + borrow
                if lhs >= required {
                    words[index] = UInt32(lhs - required)
                    borrow = 0
                } else {
                    words[index] = UInt32((UInt64(1) << 32) + lhs - required)
                    borrow = 1
                }
            }
            normalize()
        }

        func encoded() -> Data {
            guard !words.isEmpty else { return Data() }
            var bytes: [UInt8] = []
            for word in words.reversed() {
                bytes.append(UInt8((word >> 24) & 0xff))
                bytes.append(UInt8((word >> 16) & 0xff))
                bytes.append(UInt8((word >> 8) & 0xff))
                bytes.append(UInt8(word & 0xff))
            }
            while bytes.first == 0 { bytes.removeFirst() }
            return Data(bytes)
        }

        private mutating func normalize() {
            while words.last == 0 { words.removeLast() }
        }
    }

    static func subtractOne(_ data: Data) throws -> Data {
        var bytes = [UInt8](data)
        guard bytes.contains(where: { $0 != 0 }) else {
            throw SSHProtectionError.invalidPrivateKey
        }
        var index = bytes.count - 1
        while bytes[index] == 0 {
            bytes[index] = 0xff
            guard index > 0 else { throw SSHProtectionError.invalidPrivateKey }
            index -= 1
        }
        bytes[index] -= 1
        while bytes.first == 0 { bytes.removeFirst() }
        guard !bytes.isEmpty else { throw SSHProtectionError.invalidPrivateKey }
        return Data(bytes)
    }

    static func mod(_ dividend: Data, _ divisor: Data) throws -> Data {
        let modulus = Value(divisor)
        guard !modulus.words.isEmpty else { throw SSHProtectionError.invalidPrivateKey }
        var remainder = Value(Data())
        for byte in dividend {
            for bit in stride(from: 7, through: 0, by: -1) {
                remainder.shiftLeft(addBit: (byte & (1 << bit)) != 0)
                if remainder >= modulus { remainder.subtract(modulus) }
            }
        }
        return remainder.encoded()
    }
}
