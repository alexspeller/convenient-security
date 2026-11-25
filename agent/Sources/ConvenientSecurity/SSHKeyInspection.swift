import Foundation

/// What a private-key file on disk is, as far as protecting it goes: whether
/// csec's signer can take it, and if not, why. Shared by `csec protect --ssh`,
/// bulk protect's discovery and the host audit's SSH key check, so all three
/// agree with what csecd's registration will accept.
///
/// The verdict is value-free: an algorithm name or a reason, never key bytes,
/// a fingerprint or anything else derived from the private material. The bytes
/// are parsed in the caller's process, which already holds them.
public enum SSHKeyFileVerdict: Equatable, Sendable {
    /// Unencrypted and of a type csecd signs with (`protect --ssh` imports it).
    case importable(algorithm: String)
    /// Encrypted with a passphrase. csec cannot import it without the
    /// passphrase being removed first, and it is not plaintext on disk.
    case passphraseProtected
    /// A FIDO security-key (`sk-`) handle: the private key lives on the token.
    case securityKey
    /// DSA or RSA under 2048 bits. OpenSSH 10 refuses DSA outright and csec
    /// refuses both, so the key is unusable and should be retired.
    case obsolete(reason: String)
    /// Another key type csecd does not sign with.
    case unsupportedType
    /// Has a private-key header but neither csec nor OpenSSH can read it as a
    /// key: wrapped in other text, truncated or corrupt.
    case unreadable

    public static func inspect(_ data: Data) -> SSHKeyFileVerdict {
        let text = String(decoding: data.prefix(64 * 1_024), as: UTF8.self)
        if text.contains("-----BEGIN DSA PRIVATE KEY-----") {
            return text.contains("Proc-Type: 4,ENCRYPTED") ? .passphraseProtected : .obsolete(reason: "DSA")
        }
        if let header = openSSHHeader(text) {
            if header.keyType == "ssh-dss" { return .obsolete(reason: "DSA") }
            if header.keyType.hasPrefix("sk-") { return .securityKey }
            if header.encrypted { return .passphraseProtected }
        }
        do {
            let key = try SSHPrivateKey.parse(data)
            return .importable(algorithm: key.algorithm)
        } catch SSHProtectionError.encryptedPrivateKey {
            return .passphraseProtected
        } catch SSHProtectionError.weakRSAKey {
            return .obsolete(reason: "RSA under 2048 bits")
        } catch SSHProtectionError.unsupportedKeyType {
            return .unsupportedType
        } catch {
            return .unreadable
        }
    }

    /// The public key of an importable private-key file, to tell two files
    /// holding the same key apart from two keys. It is public metadata (what
    /// csec writes to `.pub` and lists in its catalog); nil when csec cannot
    /// import the key.
    public static func publicKeyBlob(_ data: Data) -> Data? {
        try? SSHPrivateKey.parse(data).publicKeyBlob
    }

    /// Whether the file leaves usable private-key material readable by any
    /// process running as the user. A passphrase-encrypted key or a security-key
    /// handle does not.
    public var isPlaintextPrivateKey: Bool {
        switch self {
        case .importable, .obsolete, .unsupportedType, .unreadable: return true
        case .passphraseProtected, .securityKey: return false
        }
    }

    /// Why `protect --ssh` cannot import this file, or nil when it can.
    public var importRefusal: String? {
        switch self {
        case .importable:
            return nil
        case .passphraseProtected:
            return "is passphrase-protected; csec imports only unencrypted keys "
                + "(remove the passphrase with `ssh-keygen -p` first, or leave it as it is)"
        case .securityKey:
            return "is a security-key (sk-) handle; its private key stays on the token"
        case let .obsolete(reason):
            return "is a \(reason) key, which neither OpenSSH 10 nor csec will use; "
                + "retire it, or keep it encrypted with `csec protect --whole-file`"
        case .unsupportedType:
            return "is a key type csec does not sign with; "
                + "protect it with `csec protect --whole-file` instead"
        case .unreadable:
            return "has private-key content that is not a readable SSH key "
                + "(wrapped in other text, truncated or corrupt); "
                + "protect it with `csec protect --whole-file` instead"
        }
    }

    /// A short label for plan notes and audit evidence.
    public var label: String {
        switch self {
        case let .importable(algorithm): return algorithm
        case .passphraseProtected: return "passphrase-protected"
        case .securityKey: return "security key"
        case let .obsolete(reason): return "\(reason), obsolete"
        case .unsupportedType: return "unsupported key type"
        case .unreadable: return "not a readable SSH key"
        }
    }

    private struct OpenSSHHeader {
        let encrypted: Bool
        let keyType: String
    }

    /// The cleartext part of an `openssh-key-v1` file: cipher, KDF and the
    /// public key's type. Encryption shows only here, not in the PEM armour.
    private static func openSSHHeader(_ text: String) -> OpenSSHHeader? {
        let begin = "-----BEGIN OPENSSH PRIVATE KEY-----"
        let end = "-----END OPENSSH PRIVATE KEY-----"
        guard let start = text.range(of: begin),
              let stop = text.range(of: end, range: start.upperBound..<text.endIndex),
              let decoded = Data(
                base64Encoded: String(text[start.upperBound..<stop.lowerBound].filter { !$0.isWhitespace }))
        else { return nil }
        let magic = Data("openssh-key-v1\0".utf8)
        guard decoded.count > magic.count, decoded.prefix(magic.count) == magic else { return nil }
        var reader = SSHWireReader(decoded.dropFirst(magic.count))
        guard let cipher = try? reader.readUTF8(maximumBytes: 128),
              let kdf = try? reader.readUTF8(maximumBytes: 128),
              (try? reader.readString(maximumBytes: 1_024)) != nil,
              let count = try? reader.readUInt32(), count >= 1,
              let publicBlob = try? reader.readString(maximumBytes: 16 * 1_024)
        else { return nil }
        var publicReader = SSHWireReader(publicBlob)
        guard let keyType = try? publicReader.readUTF8(maximumBytes: 128) else { return nil }
        return OpenSSHHeader(encrypted: cipher != "none" || kdf != "none", keyType: keyType)
    }
}
