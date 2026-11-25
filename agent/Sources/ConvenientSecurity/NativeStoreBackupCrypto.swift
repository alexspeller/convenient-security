import CSECRemoteApproval
import CryptoKit
import Foundation
import Security

// Sealed backups of the native stores, for surviving the loss of this Mac.
//
// A native store's key record is a `.biometryAny`, `ThisDeviceOnly` Keychain
// item: Apple never migrates it to another Mac, even from a backup, so a
// secret kept only in the native store dies with the Mac (or its Touch ID).
// A backup bundle is a copy of one tier of one store — its key record and the
// ciphertext files the record pins — sealed to a recovery public key whose
// private half exists only in the recovery kit the human keeps off this Mac
// (in 1Password, or on paper). Sealing needs only the public half, so csecd
// keeps the bundles current on every store write with no prompt; opening one
// needs the kit, typed into csec's restore window on the Mac being restored.
//
// The kit is one 32-byte secret S. Everything else is derived from it:
// - a P-256 key-agreement key pair, the recipient every bundle is sealed to
//   (`RemoteUnlockCrypto.seal`, an ECIES box whose context names the bundle);
// - an authentication key, which csecd also keeps (in its restricted access
//   group, beside the public key) and MACs every bundle with. Sealing to a
//   public key alone authenticates nothing: anyone holding the public key
//   could plant a bundle of their own values for a restore to import. Only
//   csecd and the kit's holder hold this key;
// - the name key, which turns a tier and store into the bundle's file name, so
//   the folder (in iCloud Drive, readable by Apple) shows no store names.
//
// The backup's ID, which names its folder and binds every bundle to it, is
// random, not derived: it is shown and stored in the clear, and nothing csec
// shows may be derived from a secret (a derived ID would let anyone confirm a
// guessed kit offline).

/// One tier of a native store: the hand-editable document, or the per-file blobs.
public enum NativeStoreTier: String, Sendable, Hashable, Codable, CaseIterable {
    case documents = "doc"
    case blobs = "blob"
}

public enum NativeStoreBackupError: Error, Sendable, Equatable {
    /// A recovery kit that does not parse or whose check group does not match.
    case invalidRecoveryKit
    /// A bundle that is malformed, too large, or not this backup's.
    case invalidBundle
    /// A bundle whose MAC or sealed box does not authenticate under this kit.
    case bundleAuthenticationFailed
    /// A bundle that authenticates but names another tier, store or file than
    /// where it was found.
    case bundleMismatch
    /// Backups are not set up on this Mac.
    case notConfigured
    /// The backup folder is missing, not a directory, or could not be written.
    case destinationUnavailable
    /// A store's bundle would exceed `NativeStoreBackupBundle.maximumBytes`.
    case bundleTooLarge
    case randomGenerationFailed
    /// No backup folder holds bundles this recovery kit opens.
    case noMatchingBackup
    /// A restore found the store already on this Mac; nothing is overwritten.
    case storeExists
}

extension NativeStoreBackupError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidRecoveryKit:
            return "that is not a csec recovery key, or a character in it is wrong"
        case .invalidBundle:
            return "a backup bundle is malformed or belongs to another backup"
        case .bundleAuthenticationFailed:
            return "a backup bundle did not authenticate under this recovery key"
        case .bundleMismatch:
            return "a backup bundle names a different store than its file"
        case .notConfigured:
            return "native-store backups are not set up on this Mac (csec backup setup)"
        case .destinationUnavailable:
            return "the backup folder could not be used (is iCloud Drive on? --folder picks another folder)"
        case .bundleTooLarge:
            return "a native store is too large to back up in one bundle"
        case .randomGenerationFailed:
            return "secure random generation failed"
        case .noMatchingBackup:
            return "no backup folder holds bundles this recovery key opens"
        case .storeExists:
            return "this Mac already has a store by that name, so it was left as it is"
        }
    }
}

extension NativeStoreBackupError: ProviderDiagnosableError {
    public var boundedReason: String { errorDescription ?? "the native-store backup failed" }
}

/// The recovery kit: 32 random bytes, written as 14 groups of four Crockford
/// base32 characters after `CSEC`. Thirteen groups carry the secret; the last
/// is a check on it, so a mistyped character is caught before any bundle is
/// tried. Parsing ignores case, spaces and dashes, and reads O as 0 and I or
/// L as 1, the way Crockford's alphabet intends for something a human copies.
public struct BackupRecoveryKit: Sendable {
    static let secretBytes = 32
    static let groupLength = 4
    static let secretCharacters = 52 // ceil(256 / 5)
    static let checkCharacters = 4
    static let prefix = "CSEC"
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ".utf8)
    private static let checkDomain = Data("csec.backup.kit-check.v1".utf8)

    let secret: Data

    init(secret: Data) throws {
        guard secret.count == Self.secretBytes else { throw NativeStoreBackupError.invalidRecoveryKit }
        self.secret = secret
    }

    /// A fresh kit from the system's secure random source.
    public static func generate() throws -> BackupRecoveryKit {
        var bytes = [UInt8](repeating: 0, count: secretBytes)
        guard SecRandomCopyBytes(kSecRandomDefault, secretBytes, &bytes) == errSecSuccess else {
            throw NativeStoreBackupError.randomGenerationFailed
        }
        return try BackupRecoveryKit(secret: Data(bytes))
    }

    public init(parsing text: String) throws {
        var characters = Self.normalized(text)
        // The prefix's letters are base32 digits too, so it is told apart by
        // the length alone: a kit typed without it is four characters shorter.
        let prefix = Array(Self.prefix.utf8)
        let kitCharacters = Self.secretCharacters + Self.checkCharacters
        if characters.count == prefix.count + kitCharacters, characters.starts(with: prefix) {
            characters.removeFirst(prefix.count)
        }
        guard characters.count == kitCharacters else {
            throw NativeStoreBackupError.invalidRecoveryKit
        }
        let values = try characters.map { character -> UInt8 in
            guard let index = Self.alphabet.firstIndex(of: character) else {
                throw NativeStoreBackupError.invalidRecoveryKit
            }
            return UInt8(index)
        }
        let secret = try Self.decode(Array(values.prefix(Self.secretCharacters)))
        let check = Array(values.suffix(Self.checkCharacters))
        guard check == Self.checkValues(for: secret) else { throw NativeStoreBackupError.invalidRecoveryKit }
        try self.init(secret: secret)
    }

    /// The groups of four in a kit after `CSEC`, the check group included.
    public static let groupCount = (secretCharacters + checkCharacters) / groupLength

    /// How far typed or pasted text has got towards a whole kit, for the
    /// line under csec's masked key field: 74 identical dots can't show
    /// whether a paste brought every character. It counts characters and
    /// says whether the check group matches; it never repeats any of them.
    public enum EntryProgress: Equatable, Sendable {
        case empty
        /// `groups` whole groups and `characters` (one to three) of the next.
        case partial(groups: Int, characters: Int)
        /// Every group, and the check group matches.
        case complete
        /// Every group, but the check group doesn't match: a mistyped character.
        case mistyped
        case tooLong
        /// A character no kit has, such as U or punctuation.
        case unexpectedCharacter
    }

    public static func progress(of text: String) -> EntryProgress {
        if (try? BackupRecoveryKit(parsing: text)) != nil { return .complete }
        var characters = normalized(text)
        guard !characters.isEmpty else { return .empty }
        // While the key is still going in, its length can't yet tell the
        // prefix apart, so a leading CSEC (or the start of one) counts as it.
        // A whole kit that happens to begin CSEC without the prefix has
        // already parsed above.
        let prefix = Array(Self.prefix.utf8)
        if prefix.starts(with: characters) { return .partial(groups: 0, characters: 0) }
        if characters.starts(with: prefix) { characters.removeFirst(prefix.count) }
        guard characters.allSatisfy(alphabet.contains) else { return .unexpectedCharacter }
        let kitCharacters = secretCharacters + checkCharacters
        if characters.count > kitCharacters { return .tooLong }
        if characters.count == kitCharacters { return .mistyped }
        return .partial(groups: characters.count / groupLength, characters: characters.count % groupLength)
    }

    /// Upper case, without spaces, dashes or line breaks, and with O read as
    /// 0 and I or L as 1.
    private static func normalized(_ text: String) -> [UInt8] {
        var characters: [UInt8] = []
        for byte in text.uppercased().utf8 {
            switch byte {
            case 0x20, 0x2d, 0x09, 0x0a, 0x0d: continue // space, dash, tab, newlines
            case UInt8(ascii: "O"): characters.append(UInt8(ascii: "0"))
            case UInt8(ascii: "I"), UInt8(ascii: "L"): characters.append(UInt8(ascii: "1"))
            default: characters.append(byte)
            }
        }
        return characters
    }

    /// `CSEC-XXXX-…`, the form shown once in csec's setup window.
    public var formatted: String {
        let characters = (Self.encode(secret) + Self.checkValues(for: secret)).map { Self.alphabet[Int($0)] }
        var groups = [Self.prefix]
        var index = 0
        while index < characters.count {
            let end = min(index + Self.groupLength, characters.count)
            groups.append(String(decoding: characters[index..<end], as: UTF8.self))
            index = end
        }
        return groups.joined(separator: "-")
    }

    var keys: BackupKeys { BackupKeys(secret: secret) }

    /// What csecd keeps for a backup sealed to this kit.
    public func material(backupID: String) -> NativeStoreBackupPublicMaterial {
        keys.publicMaterial(backupID: backupID)
    }

    /// 5-bit values, most significant first; the final value is zero-padded.
    private static func encode(_ data: Data) -> [UInt8] {
        var values: [UInt8] = []
        var buffer: UInt32 = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                values.append(UInt8((buffer >> UInt32(bits - 5)) & 0x1f))
                bits -= 5
            }
        }
        if bits > 0 { values.append(UInt8((buffer << UInt32(5 - bits)) & 0x1f)) }
        return values
    }

    private static func decode(_ values: [UInt8]) throws -> Data {
        var bytes: [UInt8] = []
        var buffer: UInt32 = 0
        var bits = 0
        for value in values {
            buffer = (buffer << 5) | UInt32(value)
            bits += 5
            if bits >= 8 {
                bytes.append(UInt8((buffer >> UInt32(bits - 8)) & 0xff))
                bits -= 8
            }
        }
        // The padding bits must be zero, so each secret has exactly one spelling.
        guard bytes.count == secretBytes, buffer & ((1 << UInt32(bits)) - 1) == 0 else {
            throw NativeStoreBackupError.invalidRecoveryKit
        }
        return Data(bytes)
    }

    private static func checkValues(for secret: Data) -> [UInt8] {
        let digest = Array(SHA256.hash(data: checkDomain + secret))
        let bits = UInt32(digest[0]) << 16 | UInt32(digest[1]) << 8 | UInt32(digest[2])
        // The top 20 bits of the digest, as four 5-bit values.
        return (0..<checkCharacters).map { UInt8((bits >> UInt32(19 - 5 * $0)) & 0x1f) }
    }
}

/// What the kit's secret derives. csecd keeps `publicMaterial` only; the
/// agreement private key exists only while a restore opens bundles.
struct BackupKeys: Sendable {
    let recipientPublicKey: Data
    let authenticationKey: Data
    let nameKey: Data
    private let secret: Data

    init(secret: Data) {
        self.secret = secret
        self.authenticationKey = Self.derive(secret, "csec.backup.auth.v1", count: 32)
        self.nameKey = Self.derive(secret, "csec.backup.name.v1", count: 32)
        self.recipientPublicKey = Self.agreementKey(secret).publicKey.compressedRepresentation
    }

    func publicMaterial(backupID: String) -> NativeStoreBackupPublicMaterial {
        NativeStoreBackupPublicMaterial(
            backupID: backupID,
            recipientPublicKey: recipientPublicKey,
            authenticationKey: authenticationKey,
            nameKey: nameKey
        )
    }

    func agreementPrivateKey() -> P256.KeyAgreement.PrivateKey { Self.agreementKey(secret) }

    /// A P-256 scalar must lie in 1..<n; the counter retries the
    /// one-in-four-billion HKDF output that does not.
    private static func agreementKey(_ secret: Data) -> P256.KeyAgreement.PrivateKey {
        var counter: UInt8 = 0
        while true {
            let candidate = derive(secret, "csec.backup.agreement.v1", count: 32, counter: counter)
            if let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: candidate) { return key }
            counter &+= 1
        }
    }

    private static func derive(_ secret: Data, _ info: String, count: Int, counter: UInt8 = 0) -> Data {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: secret),
            salt: Data("csec.backup.v1".utf8),
            info: Data(info.utf8) + Data([counter]),
            outputByteCount: count
        ).withUnsafeBytes { Data($0) }
    }
}

/// What csecd keeps to write bundles: the backup's random ID, the recipient's
/// public key, and the authentication and name keys. None of it opens a bundle; the
/// authentication key would let its holder forge one, which is why it lives
/// only in csecd's restricted access group.
public struct NativeStoreBackupPublicMaterial: Codable, Sendable, Equatable {
    public let backupID: String
    public let recipientPublicKey: Data
    public let authenticationKey: Data
    public let nameKey: Data

    static func randomBackupID() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw NativeStoreBackupError.randomGenerationFailed
        }
        return Data(bytes).hexString
    }

    var isWellFormed: Bool {
        backupID.utf8.count == 32 && backupID.utf8.allSatisfy(NativeBlobIndex.isLowerHex)
            && recipientPublicKey.count == 33
            && (try? P256.KeyAgreement.PublicKey(compressedRepresentation: recipientPublicKey)) != nil
            && authenticationKey.count == 32
            && nameKey.count == 32
    }

    /// A keyed hash of a store's data key under the MAC key: it tells one
    /// lineage of a store name from another without revealing anything, and
    /// it never leaves csecd's protected item.
    func lineage(of keyData: Data) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: NativeStoreBackupBundle.canonical([Data("csec.backup.lineage.v1".utf8), keyData]),
            using: SymmetricKey(data: authenticationKey)
        )
        return Data(mac).prefix(16).hexString
    }

    /// The bundle file name for `item`: a keyed hash, so the folder names no
    /// store.
    public func bundleFileName(_ item: NativeStoreBackupItem) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: NativeStoreBackupBundle.canonical([Data(item.tag.utf8), Data(item.name.utf8)]),
            using: SymmetricKey(data: nameKey)
        )
        return Data(mac).prefix(16).hexString + NativeStoreBackupBundle.fileExtension
    }
}

/// What one bundle backs up: one tier of one native store, or the SSH key
/// catalog (public metadata only), which a restored `ssh-keys` store needs
/// to be offered to SSH again.
public enum NativeStoreBackupItem: Sendable, Hashable, CustomStringConvertible {
    case store(NativeStoreTier, NativeStoreName)
    case sshCatalog

    static let sshCatalogTag = "ssh-catalog"

    public var tag: String {
        switch self {
        case let .store(tier, _): return tier.rawValue
        case .sshCatalog: return Self.sshCatalogTag
        }
    }

    /// The store name; empty for the catalog.
    public var name: String {
        switch self {
        case let .store(_, store): return store.value
        case .sshCatalog: return ""
        }
    }

    public init?(tag: String, name: String) {
        if tag == Self.sshCatalogTag {
            guard name.isEmpty else { return nil }
            self = .sshCatalog
            return
        }
        guard let tier = NativeStoreTier(rawValue: tag), let store = try? NativeStoreName(name) else { return nil }
        self = .store(tier, store)
    }

    public var description: String {
        switch self {
        case let .store(tier, store): return "\(tier.rawValue) store \(store)"
        case .sshCatalog: return "SSH key catalog"
        }
    }
}

/// The plaintext inside one bundle.
public struct NativeStoreBackupContents: Sendable, Equatable {
    public enum Body: Sendable, Equatable {
        /// A tier's key record and the exact ciphertext files it pins, by
        /// file name, as csecd's store directories hold them.
        case store(record: NativeStoreKeyRecord, files: [String: Data])
        case sshCatalog([SSHKeyMetadata])
    }

    public let item: NativeStoreBackupItem
    public let body: Body
    public let createdAt: Date

    public init(item: NativeStoreBackupItem, body: Body, createdAt: Date) {
        self.item = item
        self.body = body
        self.createdAt = createdAt
    }

    public static func store(
        _ tier: NativeStoreTier,
        _ store: NativeStoreName,
        record: NativeStoreKeyRecord,
        files: [String: Data],
        createdAt: Date
    ) -> NativeStoreBackupContents {
        NativeStoreBackupContents(
            item: .store(tier, store), body: .store(record: record, files: files), createdAt: createdAt
        )
    }

    var record: NativeStoreKeyRecord? {
        if case let .store(record, _) = body { return record }
        return nil
    }
}

/// The bundle file: `CSECBAK1` ‖ backup ID ‖ sealed contents ‖ MAC.
///
/// The MAC covers everything before it and the bundle's file name, under the
/// authentication key; it is checked before the box is opened. The box's
/// context names the backup and the file, so a bundle copied to another name
/// or another backup's folder fails, and the opened contents must name the
/// item that file name derives from.
public enum NativeStoreBackupBundle {
    public static let fileExtension = ".csecbackup"
    /// The largest bundle written or read. A blob store's bundle holds every
    /// file it protects; far beyond any real store, and short of exhausting
    /// csecd's memory while one is assembled.
    public static let maximumBytes = 256 * 1024 * 1024
    static let magic = Data("CSECBAK1".utf8)
    static let domain = Data("csec.backup.bundle.v1".utf8)
    static let payloadDomain = Data("csec.backup.payload.v1".utf8)
    static let tagBytes = 32
    static let headerFields = 4
    static let maximumFiles = NativeBlobIndex.maximumBlobs + 2

    public static func seal(
        _ contents: NativeStoreBackupContents,
        material: NativeStoreBackupPublicMaterial,
        maximumBytes: Int = NativeStoreBackupBundle.maximumBytes
    ) throws -> Data {
        let fileName = material.bundleFileName(contents.item)
        guard let backupID = Data(lowerHex: material.backupID) else { throw NativeStoreBackupError.invalidBundle }
        var fields: [Data] = [
            payloadDomain,
            Data(contents.item.tag.utf8),
            Data(contents.item.name.utf8),
            Data(String(Int64((contents.createdAt.timeIntervalSince1970 * 1000).rounded())).utf8),
        ]
        switch contents.body {
        case let .store(record, files):
            guard files.count <= maximumFiles else { throw NativeStoreBackupError.bundleTooLarge }
            fields.append(try JSONEncoder().encode(record))
            var total = 0
            for name in files.keys.sorted() {
                let data = files[name]!
                total += data.count
                guard total <= maximumBytes else { throw NativeStoreBackupError.bundleTooLarge }
                fields.append(Data(name.utf8))
                fields.append(data)
            }
        case let .sshCatalog(keys):
            fields.append(try JSONEncoder().encode(keys))
        }
        let sealed: Data
        do {
            sealed = try RemoteUnlockCrypto.seal(
                canonical(fields),
                toRemotePublicKey: material.recipientPublicKey,
                context: context(backupID: backupID, fileName: fileName)
            )
        } catch {
            throw NativeStoreBackupError.invalidBundle
        }
        let body = magic + backupID + sealed
        guard body.count + tagBytes <= maximumBytes else { throw NativeStoreBackupError.bundleTooLarge }
        return body + tag(body, fileName: fileName, key: material.authenticationKey)
    }

    /// The backup ID a bundle claims, from its cleartext header alone.
    public static func backupID(of data: Data) -> String? {
        guard data.count > magic.count + 16 + tagBytes, data.prefix(magic.count) == magic else { return nil }
        return Data(data.dropFirst(magic.count).prefix(16)).hexString
    }

    /// Opens a bundle found under `fileName` in backup `backupID`'s folder
    /// with `kit`.
    public static func open(
        _ data: Data,
        fileName: String,
        backupID: String,
        kit: BackupRecoveryKit
    ) throws -> NativeStoreBackupContents {
        try open(data, fileName: fileName, backupID: backupID, keys: kit.keys)
    }

    static func open(
        _ data: Data,
        fileName: String,
        backupID expectedID: String,
        keys: BackupKeys
    ) throws -> NativeStoreBackupContents {
        guard data.count <= maximumBytes,
              let claimed = backupID(of: data),
              claimed == expectedID,
              let backupID = Data(lowerHex: claimed) else {
            throw NativeStoreBackupError.invalidBundle
        }
        let body = Data(data.dropLast(tagBytes))
        let mac = Data(data.suffix(tagBytes))
        guard HMAC<SHA256>.isValidAuthenticationCode(
            mac,
            authenticating: macInput(body, fileName: fileName),
            using: SymmetricKey(data: keys.authenticationKey)
        ) else {
            throw NativeStoreBackupError.bundleAuthenticationFailed
        }
        let payload: Data
        do {
            payload = try RemoteUnlockCrypto.open(
                Data(body.dropFirst(magic.count + 16)),
                remoteKey: keys.agreementPrivateKey(),
                context: context(backupID: backupID, fileName: fileName)
            )
        } catch {
            throw NativeStoreBackupError.bundleAuthenticationFailed
        }
        guard let fields = parseCanonical(payload),
              fields.count > headerFields,
              fields[0] == payloadDomain,
              let item = NativeStoreBackupItem(
                  tag: String(decoding: fields[1], as: UTF8.self),
                  name: String(decoding: fields[2], as: UTF8.self)
              ),
              let milliseconds = Int64(String(decoding: fields[3], as: UTF8.self)) else {
            throw NativeStoreBackupError.invalidBundle
        }
        guard keys.publicMaterial(backupID: expectedID).bundleFileName(item) == fileName else {
            throw NativeStoreBackupError.bundleMismatch
        }
        let contents: NativeStoreBackupContents.Body
        switch item {
        case .store:
            guard (fields.count - headerFields).isMultiple(of: 2) == false,
                  let record = try? JSONDecoder().decode(NativeStoreKeyRecord.self, from: fields[headerFields]),
                  record.isValid else {
                throw NativeStoreBackupError.invalidBundle
            }
            var files: [String: Data] = [:]
            var index = headerFields + 1
            while index < fields.count {
                let name = String(decoding: fields[index], as: UTF8.self)
                guard Data(name.utf8) == fields[index], SealedRecordDirectory.isSafeName(name), files[name] == nil else {
                    throw NativeStoreBackupError.invalidBundle
                }
                files[name] = fields[index + 1]
                index += 2
            }
            guard files.count <= maximumFiles else { throw NativeStoreBackupError.invalidBundle }
            contents = .store(record: record, files: files)
        case .sshCatalog:
            guard fields.count == headerFields + 1,
                  let keys = try? JSONDecoder().decode([SSHKeyMetadata].self, from: fields[headerFields]),
                  keys.count <= SSHKeyCatalog.maximumKeys else {
                throw NativeStoreBackupError.invalidBundle
            }
            contents = .sshCatalog(keys)
        }
        return NativeStoreBackupContents(
            item: item, body: contents, createdAt: Date(timeIntervalSince1970: TimeInterval(milliseconds) / 1000)
        )
    }

    private static func context(backupID: Data, fileName: String) -> Data {
        canonical([domain, backupID, Data(fileName.utf8)])
    }

    private static func macInput(_ body: Data, fileName: String) -> Data {
        canonical([domain, Data(fileName.utf8), body])
    }

    private static func tag(_ body: Data, fileName: String, key: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(
            for: macInput(body, fileName: fileName),
            using: SymmetricKey(data: key)
        ))
    }

    /// Length-prefixed fields: a 4-byte big-endian length before each.
    static func canonical(_ fields: [Data]) -> Data {
        var data = Data()
        for field in fields {
            let count = UInt32(field.count)
            data.append(contentsOf: [
                UInt8((count >> 24) & 0xff), UInt8((count >> 16) & 0xff),
                UInt8((count >> 8) & 0xff), UInt8(count & 0xff),
            ])
            data.append(field)
        }
        return data
    }

    static func parseCanonical(_ data: Data) -> [Data]? {
        let bytes = [UInt8](data)
        var fields: [Data] = []
        var offset = 0
        while offset < bytes.count {
            guard bytes.count - offset >= 4 else { return nil }
            let count = Int(bytes[offset]) << 24 | Int(bytes[offset + 1]) << 16
                | Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
            offset += 4
            guard bytes.count - offset >= count, fields.count < 2 * maximumFiles + 8 else { return nil }
            fields.append(Data(bytes[offset..<(offset + count)]))
            offset += count
        }
        return fields
    }
}
