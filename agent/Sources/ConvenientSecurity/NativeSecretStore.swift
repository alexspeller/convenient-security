import Foundation
import CryptoKit
import LocalAuthentication
import Security
#if canImport(Darwin)
import Darwin
#endif

/// A logical native-store file name. Restricting names to one conservative
/// ASCII component keeps references, keychain accounts, and openat(2) file
/// names unambiguous and prevents path traversal by construction.
public struct NativeStoreName: Hashable, Sendable, CustomStringConvertible {
    public let value: String

    public init(_ value: String) throws {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty,
              bytes.count <= 64,
              Self.isAlphaNumeric(bytes[0]),
              bytes.allSatisfy({ Self.isAlphaNumeric($0) || $0 == 45 || $0 == 95 }) else {
            throw NativeStoreError.invalidStoreName
        }
        self.value = value
    }

    public var description: String { value }

    private static func isAlphaNumeric(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57)
            || (byte >= 65 && byte <= 90)
            || (byte >= 97 && byte <= 122)
    }
}

/// Parsed `csec://<store>/<key>` reference — the single native value scheme,
/// resolving to bytes from whichever storage tier backs the key.
public struct NativeSecretReference: Hashable, Sendable, CustomStringConvertible {
    public let store: NativeStoreName
    public let key: String

    public init(_ reference: SecretRef) throws {
        guard reference.scheme == "csec",
              let slash = reference.path.firstIndex(of: "/"),
              !reference.path[reference.path.index(after: slash)...].contains("/") else {
            throw NativeStoreError.invalidReference
        }
        self.store = try NativeStoreName(String(reference.path[..<slash]))
        let key = String(reference.path[reference.path.index(after: slash)...])
        guard NativeStoreDocument.isValidKey(key) else {
            throw NativeStoreError.invalidReference
        }
        self.key = key
    }

    public init(store: NativeStoreName, key: String) throws {
        guard NativeStoreDocument.isValidKey(key) else {
            throw NativeStoreError.invalidReference
        }
        self.store = store
        self.key = key
    }

    public var uri: String { "csec://\(store.value)/\(key)" }
    public var description: String { uri }
    public var secretRef: SecretRef { try! SecretRef(uri) }

    public static func editConsentReference(for store: NativeStoreName) -> SecretRef {
        // Store names are already restricted to an RFC-3986-safe ASCII subset.
        try! SecretRef("csec://\(store.value)/*")
    }
}

public enum NativeStoreError: Error, Sendable, Equatable {
    case invalidStoreName
    case invalidReference
    case invalidDocument
    case documentTooLarge
    case tooManySecrets
    case authenticationRequired
    case keyUnavailable
    case storeNotFound
    case secretNotFound
    case integrityFailure
    case editSessionExpired
    case editConflict
    case tooManyEditSessions
    case filesystemFailure
    case randomGenerationFailed
    case blobTierUnavailable
    case crossTierKeyConflict
}

extension NativeStoreError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidStoreName:
            return "store names must be 1-64 ASCII letters, digits, '-' or '_', starting with a letter or digit"
        case .invalidReference:
            return "native references must use csec://<store>/<key> with a valid store and key"
        case .invalidDocument:
            return "the store must be a JSON object with unique valid keys and string values"
        case .documentTooLarge:
            return "the decrypted store exceeds the 1 MiB limit"
        case .tooManySecrets:
            return "the store exceeds the 1024-secret limit"
        case .authenticationRequired:
            return "a fresh biometric authorization is required"
        case .keyUnavailable:
            return "the device-bound native-store key is unavailable"
        case .storeNotFound:
            return "the native store does not exist"
        case .secretNotFound:
            return "the requested key does not exist in the native store"
        case .integrityFailure:
            return "the encrypted store failed authentication or rollback checks"
        case .editSessionExpired:
            return "the native-store edit session is invalid or expired"
        case .editConflict:
            return "the native store changed after this edit began"
        case .tooManyEditSessions:
            return "too many native-store edit sessions are active"
        case .filesystemFailure:
            return "the encrypted store could not be read or written safely"
        case .randomGenerationFailed:
            return "secure random generation failed"
        case .blobTierUnavailable:
            return "the native store's file/blob tier is not configured"
        case .crossTierKeyConflict:
            return "a key cannot exist in both the editable-document and file tiers of one store"
        }
    }
}

/// Strict, human-editable plaintext form. JSON is used instead of YAML or TOML
/// because Foundation supplies the encoder/decoder, the schema is deliberately
/// only a flat string-to-string object, and no tags, implicit typing, anchors,
/// includes, or third-party parser enter the trusted agent.
public struct NativeStoreDocument: Sendable, Equatable {
    public static let maximumBytes = 1024 * 1024
    public static let maximumSecrets = 1024

    public let values: [String: String]

    public init(values: [String: String]) throws {
        guard values.count <= Self.maximumSecrets else {
            throw NativeStoreError.tooManySecrets
        }
        guard values.keys.allSatisfy(Self.isValidKey) else {
            throw NativeStoreError.invalidDocument
        }
        self.values = values
        guard try encoded().count <= Self.maximumBytes else {
            throw NativeStoreError.documentTooLarge
        }
    }

    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes else {
            throw NativeStoreError.documentTooLarge
        }
        var parser = StrictStringObjectParser(data: data)
        let values = try parser.parse()
        guard values.count <= Self.maximumSecrets else {
            throw NativeStoreError.tooManySecrets
        }
        guard values.keys.allSatisfy(Self.isValidKey) else {
            throw NativeStoreError.invalidDocument
        }
        self.values = values
        guard try encoded().count <= Self.maximumBytes else {
            throw NativeStoreError.documentTooLarge
        }
    }

    public func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        var data = try encoder.encode(values)
        data.append(0x0a)
        return data
    }

    public static func isValidKey(_ key: String) -> Bool {
        let bytes = Array(key.utf8)
        guard !bytes.isEmpty, bytes.count <= 128 else { return false }
        let first = bytes[0]
        guard isAlphaNumeric(first) || first == 95 else { return false }
        return bytes.allSatisfy {
            isAlphaNumeric($0) || $0 == 45 || $0 == 46 || $0 == 95
        }
    }

    private static func isAlphaNumeric(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57)
            || (byte >= 65 && byte <= 90)
            || (byte >= 97 && byte <= 122)
    }
}

/// A small JSON parser for the intentionally narrow plaintext schema. It
/// rejects duplicate keys before a dictionary can collapse them and delegates
/// JSON string/unicode decoding to Foundation.
private struct StrictStringObjectParser {
    private let bytes: [UInt8]
    private var offset = 0

    init(data: Data) {
        self.bytes = Array(data)
    }

    mutating func parse() throws -> [String: String] {
        skipWhitespace()
        try consume(123) // {
        skipWhitespace()
        if consumeIf(125) { // }
            skipWhitespace()
            guard offset == bytes.count else { throw NativeStoreError.invalidDocument }
            return [:]
        }

        var result: [String: String] = [:]
        while true {
            skipWhitespace()
            let key = try parseString()
            guard result[key] == nil else { throw NativeStoreError.invalidDocument }
            skipWhitespace()
            try consume(58) // :
            skipWhitespace()
            let value = try parseString()
            result[key] = value
            skipWhitespace()
            if consumeIf(125) { break }
            try consume(44) // ,
        }
        skipWhitespace()
        guard offset == bytes.count else { throw NativeStoreError.invalidDocument }
        return result
    }

    private mutating func parseString() throws -> String {
        guard offset < bytes.count, bytes[offset] == 34 else {
            throw NativeStoreError.invalidDocument
        }
        let start = offset
        offset += 1
        while offset < bytes.count {
            let byte = bytes[offset]
            if byte == 34 {
                offset += 1
                let token = Data(bytes[start..<offset])
                guard let decoded = try? JSONDecoder().decode(String.self, from: token) else {
                    throw NativeStoreError.invalidDocument
                }
                return decoded
            }
            if byte < 0x20 { throw NativeStoreError.invalidDocument }
            if byte == 92 { // backslash
                offset += 1
                guard offset < bytes.count else { throw NativeStoreError.invalidDocument }
                let escaped = bytes[offset]
                if escaped == 117 { // u
                    guard offset + 4 < bytes.count else { throw NativeStoreError.invalidDocument }
                    for index in (offset + 1)...(offset + 4) {
                        guard Self.isHex(bytes[index]) else {
                            throw NativeStoreError.invalidDocument
                        }
                    }
                    offset += 5
                    continue
                }
                guard [34, 47, 92, 98, 102, 110, 114, 116].contains(escaped) else {
                    throw NativeStoreError.invalidDocument
                }
            }
            offset += 1
        }
        throw NativeStoreError.invalidDocument
    }

    private mutating func skipWhitespace() {
        while offset < bytes.count, [9, 10, 13, 32].contains(bytes[offset]) {
            offset += 1
        }
    }

    private mutating func consume(_ expected: UInt8) throws {
        guard consumeIf(expected) else { throw NativeStoreError.invalidDocument }
    }

    private mutating func consumeIf(_ expected: UInt8) -> Bool {
        guard offset < bytes.count, bytes[offset] == expected else { return false }
        offset += 1
        return true
    }

    private static func isHex(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57)
            || (byte >= 65 && byte <= 70)
            || (byte >= 97 && byte <= 102)
    }
}

/// The only native-store keychain item for one logical store. The data key and
/// active ciphertext pointer move together under one biometric ACL. Immutable,
/// random ciphertext file names plus this authenticated pointer prevent a
/// same-UID attacker from rolling a store back to an older valid ciphertext.
public struct NativeStoreKeyRecord: Codable, Sendable, Equatable {
    public static let version = 1

    public let formatVersion: Int
    public let keyData: Data
    public let generation: UInt64
    public let activeFileID: String?
    public let ciphertextDigest: String?

    public init(
        keyData: Data,
        generation: UInt64 = 0,
        activeFileID: String? = nil,
        ciphertextDigest: String? = nil
    ) {
        self.formatVersion = Self.version
        self.keyData = keyData
        self.generation = generation
        self.activeFileID = activeFileID
        self.ciphertextDigest = ciphertextDigest
    }

    public var isValid: Bool {
        guard formatVersion == Self.version, keyData.count == 32 else { return false }
        if generation == 0 {
            return activeFileID == nil && ciphertextDigest == nil
        }
        return activeFileID.map(Self.isFileID) == true
            && ciphertextDigest.map(Self.isDigest) == true
    }

    private static func isFileID(_ value: String) -> Bool {
        value.utf8.count == 32 && value.utf8.allSatisfy(isLowerHex)
    }

    private static func isDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy(isLowerHex)
    }

    private static func isLowerHex(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}

public protocol NativeStoreKeyBackend: Sendable {
    func load(store: String, unlock: CacheUnlock?) async throws -> NativeStoreKeyRecord?
    func create(store: String, record: NativeStoreKeyRecord) async throws
    func update(
        store: String,
        record: NativeStoreKeyRecord,
        unlock: CacheUnlock?
    ) async throws
}

/// The production per-store key backend. Keys are device-bound and require any
/// currently enrolled Touch ID biometric. `.biometryAny` deliberately survives
/// enrollment changes: unlike the refillable provider cache, this key may be
/// the only way to decrypt the native store.
public struct SecurityNativeStoreKeyBackend: NativeStoreKeyBackend {
    public static let service = "com.alexspeller.convenient-security.native-store-key"
    /// Distinct keychain service for the per-blob file store, so a blob store and
    /// a whole-document store may share a name without their key records colliding.
    public static let blobService = "com.alexspeller.convenient-security.native-blob-store-key"
    private let service: String
    private let queue = DispatchQueue(label: "com.alexspeller.convenient-security.native-store-key")

    public init(service: String = SecurityNativeStoreKeyBackend.service) {
        self.service = service
    }

    public func load(store: String, unlock: CacheUnlock?) async throws -> NativeStoreKeyRecord? {
        guard let unlock else { throw NativeStoreError.authenticationRequired }
        return try await blocking {
            var query = identity(store: store)
            query[kSecReturnData as String] = true
            query[kSecUseAuthenticationContext as String] = unlock.context
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess:
                guard let data = result as? Data,
                      let record = try? JSONDecoder().decode(NativeStoreKeyRecord.self, from: data),
                      record.isValid else { throw NativeStoreError.keyUnavailable }
                return record
            case errSecItemNotFound:
                return nil
            default:
                throw KeychainError(operation: "native-store key read", status: status)
            }
        }
    }

    public func create(store: String, record: NativeStoreKeyRecord) async throws {
        guard record.isValid else { throw NativeStoreError.keyUnavailable }
        let data = try JSONEncoder().encode(record)
        try await blocking {
            var accessError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .biometryAny,
                &accessError
            ) else {
                throw NativeStoreError.keyUnavailable
            }
            var query = identity(store: store)
            query[kSecAttrAccessControl as String] = access
            query[kSecValueData as String] = data
            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else {
                throw KeychainError(operation: "native-store key add", status: status)
            }
        }
    }

    public func update(
        store: String,
        record: NativeStoreKeyRecord,
        unlock: CacheUnlock?
    ) async throws {
        guard record.isValid, let unlock else { throw NativeStoreError.authenticationRequired }
        let data = try JSONEncoder().encode(record)
        try await blocking {
            var query = identity(store: store)
            query[kSecUseAuthenticationContext as String] = unlock.context
            let status = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            guard status == errSecSuccess else {
                throw KeychainError(operation: "native-store key update", status: status)
            }
        }
    }

    private func identity(store: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: service,
            kSecAttrAccount as String: store,
        ]
    }

    private func blocking<T: Sendable>(
        _ body: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result { try body() }) }
        }
    }
}

public protocol NativeStoreFileBackend: Sendable {
    var directoryPath: String { get }
    func read(named fileName: String) async throws -> Data?
    func writeAtomically(named fileName: String, data: Data) async throws
    func delete(named fileName: String) async
    func hasFiles(for store: String) async -> Bool
}

/// Ciphertext-only filesystem backend. The final directory is private, each
/// file is a regular 0600 non-symlink, and writes are fsync + rename atomic.
/// POSIX permissions are defense in depth here; confidentiality and integrity
/// come from AES-GCM and the biometric keychain record.
public struct SecureNativeStoreFileBackend: NativeStoreFileBackend {
    public static let defaultMaximumCiphertextBytes = NativeStoreDocument.maximumBytes + 1024
    private let maximumCiphertextBytes: Int
    public let directoryPath: String

    public init(
        directoryPath: String = Self.defaultDirectoryPath(),
        maximumCiphertextBytes: Int = Self.defaultMaximumCiphertextBytes
    ) throws {
        self.directoryPath = directoryPath
        self.maximumCiphertextBytes = maximumCiphertextBytes
        try Self.prepareDirectory(directoryPath)
    }

    public static func defaultDirectoryPath() -> String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("ConvenientSecurity", isDirectory: true)
            .appendingPathComponent("Secrets", isDirectory: true)
            .path
    }

    public func read(named fileName: String) async throws -> Data? {
        guard Self.isSafeFileName(fileName) else { throw NativeStoreError.filesystemFailure }
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        let fd = fileName.withCString {
            openat(directoryFD, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        if fd < 0, errno == ENOENT { return nil }
        guard fd >= 0 else { throw NativeStoreError.filesystemFailure }
        defer { close(fd) }

        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(),
              (info.st_mode & 0o077) == 0,
              info.st_size >= 0,
              info.st_size <= maximumCiphertextBytes else {
            throw NativeStoreError.filesystemFailure
        }

        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        var offset = 0
        let totalBytes = bytes.count
        while offset < totalBytes {
            let count = bytes.withUnsafeMutableBytes { raw in
                Darwin.read(fd, raw.baseAddress!.advanced(by: offset), totalBytes - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw NativeStoreError.filesystemFailure }
            offset += count
        }
        var extra: UInt8 = 0
        guard Darwin.read(fd, &extra, 1) == 0 else {
            throw NativeStoreError.filesystemFailure
        }
        return Data(bytes)
    }

    public func writeAtomically(named fileName: String, data: Data) async throws {
        guard Self.isSafeFileName(fileName),
              data.count <= maximumCiphertextBytes else {
            throw NativeStoreError.filesystemFailure
        }
        let directoryFD = try openDirectory()
        defer { close(directoryFD) }
        let temporaryName = ".csec-write-\(UUID().uuidString.lowercased())"
        let fd = temporaryName.withCString {
            openat(
                directoryFD,
                $0,
                O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                mode_t(0o600)
            )
        }
        guard fd >= 0 else { throw NativeStoreError.filesystemFailure }
        var keepTemporary = true
        defer {
            close(fd)
            if keepTemporary {
                temporaryName.withCString { _ = unlinkat(directoryFD, $0, 0) }
            }
        }

        var offset = 0
        try data.withUnsafeBytes { raw in
            while offset < raw.count {
                let count = Darwin.write(
                    fd,
                    raw.baseAddress!.advanced(by: offset),
                    raw.count - offset
                )
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { throw NativeStoreError.filesystemFailure }
                offset += count
            }
        }
        guard fchmod(fd, mode_t(0o600)) == 0,
              fsync(fd) == 0 else { throw NativeStoreError.filesystemFailure }
        let renamed = temporaryName.withCString { temporary in
            fileName.withCString { final in
                renameatx_np(
                    directoryFD,
                    temporary,
                    directoryFD,
                    final,
                    UInt32(RENAME_EXCL)
                )
            }
        }
        guard renamed == 0, fsync(directoryFD) == 0 else {
            throw NativeStoreError.filesystemFailure
        }
        keepTemporary = false
    }

    public func delete(named fileName: String) async {
        guard Self.isSafeFileName(fileName), let directoryFD = try? openDirectory() else { return }
        defer { close(directoryFD) }
        fileName.withCString { _ = unlinkat(directoryFD, $0, 0) }
        _ = fsync(directoryFD)
    }

    public func hasFiles(for store: String) async -> Bool {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: directoryPath) else {
            return false
        }
        return entries.contains { $0.hasPrefix("\(store).") && $0.hasSuffix(".csec") }
    }

    private static func prepareDirectory(_ path: String) throws {
        try FileManager.default.createDirectory(
            atPath: path,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: Int16(0o700))]
        )
        let fd = path.withCString {
            open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard fd >= 0 else { throw NativeStoreError.filesystemFailure }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == getuid(),
              fchmod(fd, mode_t(0o700)) == 0 else {
            throw NativeStoreError.filesystemFailure
        }
    }

    private func openDirectory() throws -> Int32 {
        let fd = directoryPath.withCString {
            open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard fd >= 0 else { throw NativeStoreError.filesystemFailure }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFDIR,
              info.st_uid == getuid(),
              (info.st_mode & 0o077) == 0 else {
            close(fd)
            throw NativeStoreError.filesystemFailure
        }
        return fd
    }

    private static func isSafeFileName(_ value: String) -> Bool {
        !value.isEmpty
            && value.utf8.count <= 256
            && !value.contains("/")
            && !value.contains("\0")
            && value != "."
            && value != ".."
    }
}

public actor InMemoryNativeStoreKeyBackend: NativeStoreKeyBackend {
    private var records: [String: NativeStoreKeyRecord] = [:]

    public init() {}

    public func load(store: String, unlock: CacheUnlock?) throws -> NativeStoreKeyRecord? {
        guard unlock != nil else { throw NativeStoreError.authenticationRequired }
        return records[store]
    }

    public func create(store: String, record: NativeStoreKeyRecord) throws {
        guard records[store] == nil else { throw NativeStoreError.editConflict }
        records[store] = record
    }

    public func update(
        store: String,
        record: NativeStoreKeyRecord,
        unlock: CacheUnlock?
    ) throws {
        guard unlock != nil, records[store] != nil else {
            throw NativeStoreError.authenticationRequired
        }
        records[store] = record
    }

    public func record(for store: String) -> NativeStoreKeyRecord? { records[store] }
}

public actor InMemoryNativeStoreFileBackend: NativeStoreFileBackend {
    public nonisolated let directoryPath = "memory://native-store"
    private var files: [String: Data] = [:]

    public init() {}

    public func read(named fileName: String) -> Data? { files[fileName] }
    public func writeAtomically(named fileName: String, data: Data) { files[fileName] = data }
    public func delete(named fileName: String) { files[fileName] = nil }
    public func hasFiles(for store: String) -> Bool {
        files.keys.contains { $0.hasPrefix("\(store).") && $0.hasSuffix(".csec") }
    }
    public func snapshot() -> [String: Data] { files }
    public func replace(named fileName: String, data: Data) { files[fileName] = data }
}

public struct NativeStoreEditStart: Sendable, Equatable {
    public let sessionID: String
    public let document: Data
}

public struct NativeStoreEditCommit: Sendable, Equatable {
    public let generation: UInt64
    public let secretCount: Int
}

/// Native encrypted provider and edit-session owner. The keychain record is
/// loaded only with a fresh biometric context, then kept in this actor's heap
/// for the daemon lifetime. Per-reference grants remain the authorization gate;
/// the provider never gives callers a way to decrypt a whole file directly.
public actor NativeEncryptedFileProvider: SecretProvider {
    private struct EditCaller: Sendable, Equatable {
        let pid: pid_t
        let startTime: UInt64
    }

    private struct EditSession: Sendable {
        let caller: EditCaller
        let store: NativeStoreName
        let baseline: NativeStoreKeyRecord
        let unlock: CacheUnlock
        let expiresAt: Date
    }

    private static let maximumEditSessions = 8
    private let keyBackend: NativeStoreKeyBackend
    private let fileBackend: NativeStoreFileBackend
    private let editTTL: TimeInterval
    /// The file/blob tier of the same `csec://` namespace. Small hand-editable
    /// secrets live in this provider's own document; large or binary whole-file
    /// values live in per-value envelopes here. Which tier backs a key is a pure
    /// storage decision — invisible at the reference. Optional so a provider with
    /// no blob tier (tests, doc-only deployments) resolves the document alone.
    private let blobStore: NativeBlobStore?
    private var records: [String: NativeStoreKeyRecord] = [:]
    private var editSessions: [String: EditSession] = [:]

    public init(
        keyBackend: NativeStoreKeyBackend,
        fileBackend: NativeStoreFileBackend,
        blobStore: NativeBlobStore? = nil,
        editTTL: TimeInterval = 30 * 60
    ) {
        self.keyBackend = keyBackend
        self.fileBackend = fileBackend
        self.blobStore = blobStore
        self.editTTL = editTTL
    }

    public nonisolated var schemes: Set<String> { ["csec"] }

    public nonisolated func authenticate() async throws {}
    public nonisolated func isAvailable() async -> Bool { true }

    public func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        let reference = try NativeSecretReference(ref)
        // A `csec://store/key` reference leads to a value; which tier stores that
        // value is invisible here. The editable-document tier is consulted first
        // (small hand-managed secrets take precedence), then the file/blob tier.
        var storeExists = false
        if let record = try await existingRecord(for: reference.store, unlock: unlock),
           record.generation > 0 {
            storeExists = true
            let document = try await loadDocument(store: reference.store, record: record)
            if let value = document.values[reference.key] {
                // The document holds UTF-8 text; the value primitive is bytes. The
                // encrypted file is the source of truth, so native values stay out
                // of the generic persistent cache (no stale value after an edit).
                return ResolvedSecret(value: Data(value.utf8), cacheHint: .noCache)
            }
        }
        if let blobStore {
            do {
                let blob = try await blobStore.loadBlob(
                    store: reference.store, key: reference.key, unlock: unlock
                )
                return ResolvedSecret(value: blob.data, cacheHint: .noCache)
            } catch NativeStoreError.storeNotFound {
                // No blob tier under this store name; fall through to not-found.
            } catch NativeStoreError.secretNotFound {
                storeExists = true // the store exists, only this key is absent
            }
        }
        throw storeExists ? NativeStoreError.secretNotFound : NativeStoreError.storeNotFound
    }

    /// The project-relative path a blob recorded at `csec protect` time, or nil if
    /// the value is not a blob (doc tier) or the store record is not already
    /// unlocked in this session. It passes `unlock: nil` on purpose: it reuses the
    /// store key record cached by a just-completed `resolve`, so binding a
    /// sidecar's location to its stored path costs no second authentication. A
    /// reference that was never resolved this session simply reads back nil and
    /// must be treated as unbound. Metadata only — the blob's value is never read.
    public func recordedBlobPath(store: NativeStoreName, key: String) async -> String? {
        guard let blobStore else { return nil }
        let entries = try? await blobStore.list(store: store, unlock: nil)
        return entries?[key]?.path
    }

    public func beginEdit(
        store: NativeStoreName,
        callerPID: pid_t,
        callerStartTime: UInt64,
        unlock: CacheUnlock?,
        authorizedTTL: TimeInterval? = nil,
        now: Date = Date()
    ) async throws -> NativeStoreEditStart {
        pruneSessions(now: now)
        guard editSessions.count < Self.maximumEditSessions else {
            throw NativeStoreError.tooManyEditSessions
        }
        guard let unlock else { throw NativeStoreError.authenticationRequired }

        let record: NativeStoreKeyRecord
        if let existing = try await existingRecord(for: store, unlock: unlock) {
            record = existing
        } else {
            // A ciphertext with no key record must never be silently adopted or
            // replaced: it may be a damaged/invalidated store or attacker DoS.
            guard !(await fileBackend.hasFiles(for: store.value)) else {
                throw NativeStoreError.keyUnavailable
            }
            let fresh = NativeStoreKeyRecord(keyData: try Self.randomBytes(count: 32))
            do {
                try await keyBackend.create(store: store.value, record: fresh)
            } catch {
                throw NativeStoreError.keyUnavailable
            }
            records[store.value] = fresh
            record = fresh
        }

        let document: NativeStoreDocument
        if record.generation == 0 {
            document = try NativeStoreDocument(values: [:])
        } else {
            document = try await loadDocument(store: store, record: record)
        }
        let sessionID = UUID().uuidString.lowercased()
        let sessionTTL = min(editTTL, authorizedTTL ?? editTTL)
        guard sessionTTL > 0 else { throw NativeStoreError.editSessionExpired }
        editSessions[sessionID] = EditSession(
            caller: EditCaller(pid: callerPID, startTime: callerStartTime),
            store: store,
            baseline: record,
            unlock: unlock,
            expiresAt: now.addingTimeInterval(sessionTTL)
        )
        return NativeStoreEditStart(sessionID: sessionID, document: try document.encoded())
    }

    public func commitEdit(
        sessionID: String,
        document data: Data,
        callerPID: pid_t,
        callerStartTime: UInt64,
        now: Date = Date()
    ) async throws -> NativeStoreEditCommit {
        pruneSessions(now: now)
        guard let session = editSessions[sessionID],
              session.caller == EditCaller(pid: callerPID, startTime: callerStartTime) else {
            throw NativeStoreError.editSessionExpired
        }
        let document = try NativeStoreDocument(data: data)
        guard records[session.store.value] == session.baseline else {
            throw NativeStoreError.editConflict
        }
        guard session.baseline.generation < UInt64.max else {
            throw NativeStoreError.integrityFailure
        }
        if session.baseline.generation > 0 {
            _ = try await loadDocument(store: session.store, record: session.baseline)
        }
        // Cross-tier uniqueness: a csec://store/key must resolve to exactly one
        // value, so an editable-document key may not shadow a file/blob key.
        if let blobStore, !document.values.isEmpty {
            let blobs = try await blobStore.list(store: session.store, unlock: session.unlock)
            for key in document.values.keys where blobs[key] != nil {
                throw NativeStoreError.crossTierKeyConflict
            }
        }

        let generation = session.baseline.generation + 1
        let fileID = try Self.randomBytes(count: 16).hexString
        let fileName = Self.fileName(store: session.store, fileID: fileID)
        let canonical = try document.encoded()
        let ciphertext = try Self.seal(
            plaintext: canonical,
            store: session.store,
            keyData: session.baseline.keyData,
            generation: generation,
            fileID: fileID
        )
        let updated = NativeStoreKeyRecord(
            keyData: session.baseline.keyData,
            generation: generation,
            activeFileID: fileID,
            ciphertextDigest: Self.digest(ciphertext)
        )
        guard updated.isValid else { throw NativeStoreError.integrityFailure }

        do {
            try await fileBackend.writeAtomically(named: fileName, data: ciphertext)
        } catch {
            throw NativeStoreError.filesystemFailure
        }
        do {
            try await keyBackend.update(
                store: session.store.value,
                record: updated,
                unlock: session.unlock
            )
        } catch {
            await fileBackend.delete(named: fileName)
            throw NativeStoreError.keyUnavailable
        }

        records[session.store.value] = updated
        editSessions[sessionID] = nil
        if let oldID = session.baseline.activeFileID {
            await fileBackend.delete(named: Self.fileName(store: session.store, fileID: oldID))
        }
        return NativeStoreEditCommit(generation: generation, secretCount: document.values.count)
    }

    /// Import whole-file values into the store's file/blob tier, reusing an
    /// already-authorized edit session's biometric unlock. One `beginEdit`
    /// consent covers this batch just as it would a document commit, and the
    /// session is consumed either way. Cross-tier uniqueness is enforced against
    /// the session's document baseline: a `csec://store/key` must resolve to
    /// exactly one value, so a blob key may not shadow an editable-document key.
    public func commitBlobs(
        sessionID: String,
        requests: [NativeBlobStore.PutRequest],
        callerPID: pid_t,
        callerStartTime: UInt64,
        now: Date = Date()
    ) async throws -> NativeStoreEditCommit {
        pruneSessions(now: now)
        guard let session = editSessions[sessionID],
              session.caller == EditCaller(pid: callerPID, startTime: callerStartTime) else {
            throw NativeStoreError.editSessionExpired
        }
        guard let blobStore else { throw NativeStoreError.blobTierUnavailable }
        guard !requests.isEmpty else { throw NativeStoreError.invalidDocument }
        if session.baseline.generation > 0 {
            let document = try await loadDocument(store: session.store, record: session.baseline)
            for request in requests where document.values[request.key] != nil {
                throw NativeStoreError.crossTierKeyConflict
            }
        }
        let generation = try await blobStore.putBlobs(
            store: session.store,
            requests: requests,
            unlock: session.unlock
        )
        editSessions[sessionID] = nil
        return NativeStoreEditCommit(generation: generation, secretCount: requests.count)
    }

    public func cancelEdit(
        sessionID: String,
        callerPID: pid_t,
        callerStartTime: UInt64
    ) {
        guard let session = editSessions[sessionID],
              session.caller == EditCaller(pid: callerPID, startTime: callerStartTime) else {
            return
        }
        editSessions[sessionID] = nil
    }

    public func encryptedDirectoryPath() -> String { fileBackend.directoryPath }

    private func existingRecord(
        for store: NativeStoreName,
        unlock: CacheUnlock?
    ) async throws -> NativeStoreKeyRecord? {
        if let record = records[store.value] { return record }
        guard let unlock else { throw NativeStoreError.authenticationRequired }
        do {
            guard let record = try await keyBackend.load(store: store.value, unlock: unlock) else {
                return nil
            }
            guard record.isValid else { throw NativeStoreError.keyUnavailable }
            records[store.value] = record
            return record
        } catch let error as NativeStoreError {
            throw error
        } catch {
            throw NativeStoreError.keyUnavailable
        }
    }

    private func loadDocument(
        store: NativeStoreName,
        record: NativeStoreKeyRecord
    ) async throws -> NativeStoreDocument {
        guard record.isValid,
              record.generation > 0,
              let fileID = record.activeFileID,
              let expectedDigest = record.ciphertextDigest else {
            throw NativeStoreError.integrityFailure
        }
        let fileName = Self.fileName(store: store, fileID: fileID)
        let ciphertext: Data
        do {
            guard let data = try await fileBackend.read(named: fileName) else {
                throw NativeStoreError.integrityFailure
            }
            ciphertext = data
        } catch let error as NativeStoreError {
            throw error
        } catch {
            throw NativeStoreError.filesystemFailure
        }
        guard Self.digest(ciphertext) == expectedDigest else {
            throw NativeStoreError.integrityFailure
        }
        let plaintext = try Self.open(
            ciphertext: ciphertext,
            store: store,
            keyData: record.keyData,
            generation: record.generation,
            fileID: fileID
        )
        do {
            return try NativeStoreDocument(data: plaintext)
        } catch {
            throw NativeStoreError.integrityFailure
        }
    }

    private func pruneSessions(now: Date) {
        editSessions = editSessions.filter { $0.value.expiresAt > now }
    }

    private static let envelopeMagic = Data("CSECSTR1".utf8)

    private static func seal(
        plaintext: Data,
        store: NativeStoreName,
        keyData: Data,
        generation: UInt64,
        fileID: String
    ) throws -> Data {
        guard let fileIDData = Data(lowerHex: fileID) else {
            throw NativeStoreError.integrityFailure
        }
        let header = envelopeHeader(generation: generation, fileID: fileIDData)
        return try NativeStoreEnvelope.seal(
            plaintext: plaintext,
            key: keyData,
            header: header,
            aad: authenticatedData(header: header, store: store)
        )
    }

    private static func open(
        ciphertext: Data,
        store: NativeStoreName,
        keyData: Data,
        generation: UInt64,
        fileID: String
    ) throws -> Data {
        guard let fileIDData = Data(lowerHex: fileID) else {
            throw NativeStoreError.integrityFailure
        }
        let header = envelopeHeader(generation: generation, fileID: fileIDData)
        return try NativeStoreEnvelope.open(
            ciphertext: ciphertext,
            key: keyData,
            header: header,
            aad: authenticatedData(header: header, store: store)
        )
    }

    private static func envelopeHeader(generation: UInt64, fileID: Data) -> Data {
        var header = envelopeMagic
        header.appendUInt64(generation)
        header.append(fileID)
        return header
    }

    private static func authenticatedData(header: Data, store: NativeStoreName) -> Data {
        var data = Data("csec-native-store\0".utf8)
        data.append(header)
        data.append(0)
        data.append(Data(store.value.utf8))
        return data
    }

    private static func fileName(store: NativeStoreName, fileID: String) -> String {
        "\(store.value).\(fileID).csec"
    }

    private static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func randomBytes(count: Int) throws -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
            throw NativeStoreError.randomGenerationFailed
        }
        return Data(bytes)
    }
}

// `Data(lowerHex:)`, `hexString`, and `appendUInt64` now live in
// NativeStoreCrypto.swift as internal helpers shared with the per-blob store.
