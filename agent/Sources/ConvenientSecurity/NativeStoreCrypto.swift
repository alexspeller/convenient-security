import Foundation
import CryptoKit
import Security

/// Shared AES-GCM envelope used by both the whole-document native store
/// (`NativeEncryptedFileProvider`) and the per-blob file store
/// (`NativeBlobStore`). The header is an authenticated, plaintext prefix that is
/// prepended verbatim to `box.combined` (nonce‖ciphertext‖tag) and *also* folded
/// into the additional-authenticated-data, so a truncated or swapped header
/// fails the tag check rather than merely mismatching a compare. Callers own the
/// meaning of `header`/`aad`; this type only guarantees confidentiality and
/// integrity of `plaintext` against exactly those bytes.
public enum NativeStoreEnvelope {
    public static func seal(plaintext: Data, key keyData: Data, header: Data, aad: Data) throws -> Data {
        guard keyData.count == 32 else { throw NativeStoreError.integrityFailure }
        let box: AES.GCM.SealedBox
        do {
            box = try AES.GCM.seal(
                plaintext,
                using: SymmetricKey(data: keyData),
                authenticating: aad
            )
        } catch {
            throw NativeStoreError.integrityFailure
        }
        guard let combined = box.combined else { throw NativeStoreError.integrityFailure }
        return header + combined
    }

    public static func open(ciphertext: Data, key keyData: Data, header: Data, aad: Data) throws -> Data {
        // 28 = 12-byte GCM nonce + 16-byte tag, the minimum `combined` overhead.
        guard keyData.count == 32, ciphertext.count >= header.count + 28 else {
            throw NativeStoreError.integrityFailure
        }
        guard Data(ciphertext.prefix(header.count)) == header else {
            throw NativeStoreError.integrityFailure
        }
        do {
            let box = try AES.GCM.SealedBox(combined: ciphertext.dropFirst(header.count))
            return try AES.GCM.open(
                box,
                using: SymmetricKey(data: keyData),
                authenticating: aad
            )
        } catch {
            throw NativeStoreError.integrityFailure
        }
    }

    public static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw NativeStoreError.randomGenerationFailed
        }
        return Data(bytes)
    }
}

extension Data {
    init?(lowerHex: String) {
        guard lowerHex.count.isMultiple(of: 2) else { return nil }
        var result = Data()
        result.reserveCapacity(lowerHex.count / 2)
        var index = lowerHex.startIndex
        while index < lowerHex.endIndex {
            let next = lowerHex.index(index, offsetBy: 2)
            guard let byte = UInt8(lowerHex[index..<next], radix: 16) else { return nil }
            result.append(byte)
            index = next
        }
        self = result
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    mutating func appendUInt64(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            append(UInt8((value >> UInt64(shift)) & 0xff))
        }
    }
}
