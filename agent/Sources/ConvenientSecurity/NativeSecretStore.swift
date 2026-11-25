import CSECRemoteApproval
import Foundation
import CryptoKit
import LocalAuthentication
import Security
import CSECBuildIdentity
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
    case editSessionNotFound
    case editConflict
    case tooManyEditSessions
    case filesystemFailure
    case randomGenerationFailed
    case blobTierUnavailable
    case crossTierKeyConflict
    case originConflict
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
        case .editSessionNotFound:
            return "no native-store edit session with that id belongs to this process"
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
        case .originConflict:
            return "the store name is claimed by a different project directory"
        }
    }
}

/// Every description above is a fixed, value-free sentence, so a release that
/// fails after its approval can tell the requester and the decision log why:
/// "the requested key does not exist in the native store" is something to fix,
/// where a bare "could not resolve" invites the requester to ask again.
extension NativeStoreError: ProviderDiagnosableError {
    public var boundedReason: String {
        errorDescription ?? "the native store failed"
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
    /// Reads the record; needs a local unlock (an evaluated `LAContext`).
    func load(store: String, unlock: CacheUnlock?) async throws -> NativeStoreKeyRecord?
    func create(store: String, record: NativeStoreKeyRecord) async throws
    /// Replaces the record; needs a local unlock.
    func update(
        store: String,
        record: NativeStoreKeyRecord,
        unlock: CacheUnlock?
    ) async throws
    /// Whether a record exists for `store`, from its attributes alone under a
    /// context that may not interact: never reads the record, never prompts.
    /// Throws when the Keychain cannot say.
    func recordExists(store: String) async throws -> Bool
    /// Every store with a record under this backend, listed with `unlock`'s
    /// evaluated local context.
    func storeNames(unlock: CacheUnlock) async throws -> [String]
}

/// The production per-store key backend. Keys are device-bound and require any
/// currently enrolled Touch ID biometric. `.biometryAny` deliberately survives
/// enrollment changes: unlike the refillable provider cache, this key may be
/// the only way to decrypt the native store.
public struct SecurityNativeStoreKeyBackend: NativeStoreKeyBackend {
    public static let service = CSECBuildIdentity.named("native-store-key")
    /// Distinct keychain service for the per-blob file store, so a blob store and
    /// a whole-document store may share a name without their key records colliding.
    public static let blobService = CSECBuildIdentity.named("native-blob-store-key")
    private let service: String
    private let queue = DispatchQueue(label: CSECBuildIdentity.named("native-store-key"))

    public init(service: String = SecurityNativeStoreKeyBackend.service) {
        self.service = service
    }

    public func load(store: String, unlock: CacheUnlock?) async throws -> NativeStoreKeyRecord? {
        // A remote unlock has no context; a query without one would raise its
        // own Touch ID sheet.
        guard let unlock, unlock.isLocal else { throw NativeStoreError.authenticationRequired }
        return try await blocking {
            guard let context = unlock.context else { throw NativeStoreError.authenticationRequired }
            var query = identity(store: store)
            query[kSecReturnData as String] = true
            query[kSecUseAuthenticationContext as String] = context
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
        guard record.isValid, let unlock, unlock.isLocal else {
            throw NativeStoreError.authenticationRequired
        }
        let data = try JSONEncoder().encode(record)
        try await blocking {
            guard let context = unlock.context else { throw NativeStoreError.authenticationRequired }
            var query = identity(store: store)
            query[kSecUseAuthenticationContext as String] = context
            let status = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            guard status == errSecSuccess else {
                throw KeychainError(operation: "native-store key update", status: status)
            }
        }
    }

    public func recordExists(store: String) async throws -> Bool {
        try await blocking {
            var query = identity(store: store)
            query[kSecReturnAttributes as String] = true
            query[kSecMatchLimit as String] = kSecMatchLimitOne
            let context = LAContext()
            context.interactionNotAllowed = true
            query[kSecUseAuthenticationContext as String] = context
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess, errSecInteractionNotAllowed:
                return true
            case errSecItemNotFound:
                return false
            default:
                throw KeychainError(operation: "native-store key lookup", status: status)
            }
        }
    }

    public func storeNames(unlock: CacheUnlock) async throws -> [String] {
        guard unlock.isLocal else { throw NativeStoreError.authenticationRequired }
        let service = self.service
        return try await blocking {
            guard let context = unlock.context else { throw NativeStoreError.authenticationRequired }
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecUseDataProtectionKeychain as String: true,
                kSecAttrService as String: service,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
                kSecUseAuthenticationContext as String: context,
            ]
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess:
                guard let rows = result as? [[String: Any]] else {
                    throw KeychainError(operation: "native-store key list", status: errSecDecode)
                }
                return rows.compactMap { $0[kSecAttrAccount as String] as? String }
            case errSecItemNotFound:
                return []
            default:
                throw KeychainError(operation: "native-store key list", status: status)
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
    /// `hasFiles`, or nil when the directory cannot be listed: an answer a
    /// refusal may rest on, so a listing failure is not "no files".
    func filePresence(for store: String) async -> Bool?
    /// Every file under `store`'s name (`<store>.…`, its origin marker
    /// included), or nil when the directory cannot be listed.
    func fileNames(for store: String) async -> [String]?
}

public extension NativeStoreFileBackend {
    func filePresence(for store: String) async -> Bool? { await hasFiles(for: store) }
    func fileNames(for store: String) async -> [String]? { nil }
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
        await filePresence(for: store) ?? false
    }

    public func filePresence(for store: String) async -> Bool? {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: directoryPath) else {
            return nil
        }
        return entries.contains { $0.hasPrefix("\(store).") && $0.hasSuffix(".csec") }
    }

    public func fileNames(for store: String) async -> [String]? {
        guard let entries = try? FileManager.default.contentsOfDirectory(atPath: directoryPath) else {
            return nil
        }
        return entries.filter { $0.hasPrefix("\(store).") }.sorted()
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

    /// Like the biometric item, a record opens only with a local unlock: a
    /// remote one has no context to present.
    public func load(store: String, unlock: CacheUnlock?) throws -> NativeStoreKeyRecord? {
        guard unlock?.isLocal == true else { throw NativeStoreError.authenticationRequired }
        loadCount += 1
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
        guard unlock?.isLocal == true, records[store] != nil else {
            throw NativeStoreError.authenticationRequired
        }
        records[store] = record
    }

    public func recordExists(store: String) -> Bool { records[store] != nil }

    public func storeNames(unlock: CacheUnlock) throws -> [String] {
        guard unlock.isLocal else { throw NativeStoreError.authenticationRequired }
        return records.keys.sorted()
    }

    public func record(for store: String) -> NativeStoreKeyRecord? { records[store] }

    /// How many record reads a local unlock made.
    public private(set) var loadCount = 0
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
    public func fileNames(for store: String) -> [String]? {
        files.keys.filter { $0.hasPrefix("\(store).") }.sorted()
    }
    public func snapshot() -> [String: Data] { files }
    public func replace(named fileName: String, data: Data) { files[fileName] = data }
}

/// What one tier of a native store can say about a key before any unlock:
/// see `NativeEncryptedFileProvider.presence(of:)`.
enum NativeTierPresence: Sendable, Equatable {
    /// The tier holds the key.
    case present
    /// The tier holds the store, and the store has no such key.
    case keyAbsent
    /// The tier has no such store.
    case storeAbsent
    /// Only an unlock could tell.
    case unknown

    /// A tier whose key record this daemon has neither opened nor found
    /// absent. Its store certainly does not exist when the Keychain has no
    /// record for it (an attributes-only lookup that never prompts) and the
    /// tier's directory holds no file under its name either: a record the
    /// lookup failed to see while files remain, or a directory that cannot be
    /// listed, is a question for an unlock, never a reason to refuse.
    static func cold(
        store: NativeStoreName,
        keyBackend: NativeStoreKeyBackend,
        fileBackend: NativeStoreFileBackend
    ) async -> NativeTierPresence {
        guard (try? await keyBackend.recordExists(store: store.value)) == false,
              await fileBackend.filePresence(for: store.value) == false else { return .unknown }
        return .storeAbsent
    }
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

    /// An open edit and the unlock it decrypts with. It carries no deadline: the
    /// session belongs to one exact process incarnation and ends when that
    /// process saves, cancels, or exits. This actor cannot see processes — the
    /// agent owns that check and cancels the sessions of callers that are gone.
    private struct EditSession: Sendable {
        let caller: EditCaller
        let store: NativeStoreName
        let baseline: NativeStoreKeyRecord
        let unlock: CacheUnlock
    }

    private static let maximumEditSessions = 8
    private let keyBackend: NativeStoreKeyBackend
    private let fileBackend: NativeStoreFileBackend
    /// The file/blob tier of the same `csec://` namespace. Small hand-editable
    /// secrets live in this provider's own document; large or binary whole-file
    /// values live in per-value envelopes here. Which tier backs a key is a pure
    /// storage decision — invisible at the reference. Optional so a provider with
    /// no blob tier (tests, doc-only deployments) resolves the document alone.
    private let blobStore: NativeBlobStore?
    private var records: [String: NativeStoreKeyRecord] = [:]
    /// Stores an authenticated read found to have no document-tier key record.
    /// Only this actor creates that record (`beginEdit`, which clears the mark),
    /// so for the rest of the daemon lifetime such a store has no document to
    /// open and a lookup needs no unlock to say so. Without this, a store kept
    /// only in the blob tier (what `csec protect` writes) would fail every
    /// grant reuse after its first release: the document tier would demand an
    /// unlock before the blob tier was ever consulted.
    private var absentRecords: Set<String> = []
    private var editSessions: [String: EditSession] = [:]
    /// Keeps each store's remote-unlock mirror (a copy of its key record
    /// sealed to the enrollment's remote key) current, and serves nothing
    /// without an enrollment. Nil: remote unlock is off for this provider.
    private let remoteUnlock: RemoteUnlockStore?
    /// Stores whose warm record was opened from a remote-unlock mirror. Reads
    /// use it like any warm record; a write starts over from the Keychain
    /// record itself, read with the local context every write holds.
    private var remotelyOpened: Set<String> = []
    /// Stores whose Keychain record is being moved: their mirror was removed
    /// and is sealed again once the record has moved. No other seal may land
    /// in between, or it could restore the record being replaced.
    private var mirrorWritesInFlight: [String: Int] = [:]
    /// Keeps each store's sealed backup bundle current; nil, or not set up,
    /// writes none. See NativeStoreBackup.swift.
    private let backup: NativeStoreBackup?

    public init(
        keyBackend: NativeStoreKeyBackend,
        fileBackend: NativeStoreFileBackend,
        blobStore: NativeBlobStore? = nil,
        remoteUnlock: RemoteUnlockStore? = nil,
        backup: NativeStoreBackup? = nil
    ) {
        self.keyBackend = keyBackend
        self.fileBackend = fileBackend
        self.blobStore = blobStore
        self.remoteUnlock = remoteUnlock
        self.backup = backup
    }

    public nonisolated var schemes: Set<String> { ["csec"] }

    public nonisolated func authenticate() async throws {}
    public nonisolated func isAvailable() async -> Bool { true }

    /// this Mac › store › key. A key is itself the secret, so it has no field.
    /// The edit-consent reference (`csec://store/*`) names every key of the
    /// store.
    public nonisolated func reviewDescription(for ref: SecretRef) async -> ReviewSecret? {
        let store: NativeStoreName
        let item: String
        let isKey: Bool
        if let reference = try? NativeSecretReference(ref) {
            store = reference.store
            item = reference.key
            isKey = true
        } else if ref.scheme == "csec",
                  let slash = ref.path.firstIndex(of: "/"),
                  ref.path[ref.path.index(after: slash)...] == "*",
                  let named = try? NativeStoreName(String(ref.path[..<slash])) {
            store = named
            item = "all keys (edit access)"
            isKey = false
        } else {
            return nil
        }
        return ReviewSecret(
            provider: "csec", tint: .purple, account: "this Mac",
            container: store.value, item: item, field: nil, itemIsIdentifier: isKey
        )
    }

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

    /// Whether `resolve(ref, unlock: nil)` would stop at a sealed key record
    /// this daemon has not opened yet: the document tier's, or, when the
    /// document does not hold the key, the blob tier's. Reads no Keychain item
    /// and never prompts; decrypting an already-opened document is local.
    public func requiresUnlockToResolve(_ ref: SecretRef) async -> Bool {
        // A reference this provider cannot parse fails the same either way.
        guard let reference = try? NativeSecretReference(ref) else { return false }
        let store = reference.store.value
        if let record = records[store] {
            if record.generation > 0 {
                // An integrity failure here fails resolution with or without
                // an unlock, so it is not a reason to ask for one.
                guard let document = try? await loadDocument(
                    store: reference.store, record: record
                ) else { return false }
                if document.values[reference.key] != nil { return false }
            }
        } else if !absentRecords.contains(store) {
            return true
        }
        guard let blobStore else { return false }
        return await blobStore.requiresUnlock(store: reference.store)
    }

    /// Whether `ref` exists, from what this daemon already holds: a warm
    /// document is decrypted inside this actor and only whether it holds the
    /// key leaves it, as in `requiresUnlockToResolve`; a cold tier is settled
    /// only when its store does not exist at all (`NativeTierPresence.cold`).
    /// The answer follows `resolve`: present in either tier is present, and
    /// absent from both is absent, as "no such key" when either tier holds the
    /// store and "no such store" otherwise. Anything else, an integrity
    /// failure included, is unknown and goes to a review as before. Opens no
    /// Keychain record, never prompts, and changes no warm state.
    public func presence(of ref: SecretRef) async -> ReferencePresence {
        guard let reference = try? NativeSecretReference(ref) else {
            return .absent(reason: NativeStoreError.invalidReference.boundedReason)
        }
        let document = await documentPresence(store: reference.store, key: reference.key)
        if document == .present { return .present }
        let blob = await blobStore?.presence(store: reference.store, key: reference.key) ?? .storeAbsent
        switch (document, blob) {
        case (_, .present):
            return .present
        case (.unknown, _), (_, .unknown):
            return .unknown
        case (.storeAbsent, .storeAbsent):
            return .absent(reason: NativeStoreError.storeNotFound.boundedReason)
        default:
            return .absent(reason: NativeStoreError.secretNotFound.boundedReason)
        }
    }

    private func documentPresence(store: NativeStoreName, key: String) async -> NativeTierPresence {
        if let record = records[store.value] {
            guard record.generation > 0 else { return .storeAbsent }
            guard let document = try? await loadDocument(store: store, record: record) else {
                return .unknown
            }
            return document.values[key] != nil ? .present : .keyAbsent
        }
        if absentRecords.contains(store.value) { return .storeAbsent }
        return await NativeTierPresence.cold(store: store, keyBackend: keyBackend, fileBackend: fileBackend)
    }

    /// Whether a remote unlock opens what `resolve(ref, unlock:)` would need:
    /// each tier's key record is warm, known absent, mirrored, or found (by
    /// its attributes, with no prompt) not to exist. When the document tier
    /// is still cold its content is unknown, so the blob tier must be covered
    /// too. Never opens a mirror or a record.
    public func canResolveWithRemoteUnlock(_ ref: SecretRef) async -> Bool {
        guard let remoteUnlock, let reference = try? NativeSecretReference(ref) else { return false }
        let store = reference.store.value
        if let record = records[store] {
            if record.generation > 0,
               let document = try? await loadDocument(store: reference.store, record: record),
               document.values[reference.key] != nil {
                return true
            }
        } else if !absentRecords.contains(store) {
            guard await remoteUnlock.isEnrolled() else { return false }
            let covered = await remoteUnlock.exists(.nativeDocuments(store: store))
            if !covered, (try? await keyBackend.recordExists(store: store)) != false {
                return false
            }
        }
        guard let blobStore else { return true }
        return await blobStore.canOpenWithRemoteUnlock(store: reference.store)
    }

    /// Mirror both tiers' key records for every store, reading each with the
    /// one context enrollment spent. The records are read, not kept: warm
    /// state is left exactly as it was.
    public func backfillRemoteUnlockMirrors(localUnlock: CacheUnlock) async -> RemoteUnlockBackfillReport {
        var report = RemoteUnlockBackfillReport()
        guard let remoteUnlock, localUnlock.isLocal, await remoteUnlock.isEnrolled() else { return report }
        do {
            for name in Set(try await keyBackend.storeNames(unlock: localUnlock)).sorted() {
                do {
                    guard let store = try? NativeStoreName(name),
                          let record = try await keyBackend.load(store: store.value, unlock: localUnlock),
                          record.isValid else {
                        report.failed += 1
                        continue
                    }
                    if await sealMirror(store, record) { report.mirrored += 1 } else { report.failed += 1 }
                } catch {
                    report.failed += 1
                }
            }
        } catch {
            Self.logMirror("native stores could not be listed for remote unlock (\(error))")
            report.failed += 1
        }
        if let blobStore {
            report.add(await blobStore.backfillRemoteUnlockMirrors(localUnlock: localUnlock))
        }
        return report
    }

    /// Open both tiers' key records for every store `refs` name with one
    /// evaluated context. Only the Keychain records are read; no document or
    /// blob is decrypted here.
    public func warm(_ refs: [SecretRef], unlock: CacheUnlock) async {
        var stores: [NativeStoreName] = []
        var seen = Set<String>()
        for ref in refs {
            guard let reference = try? NativeSecretReference(ref),
                  seen.insert(reference.store.value).inserted else { continue }
            stores.append(reference.store)
        }
        for store in stores {
            _ = try? await existingRecord(for: store, unlock: unlock)
            await blobStore?.warm(store: store, unlock: unlock)
        }
    }

    /// A value from a store this daemon already opened, with no unlock. Both
    /// tiers stop at a sealed key record without an unlock
    /// (`authenticationRequired`) rather than reading the Keychain, so this
    /// never prompts; any failure is nil.
    public func resolveWithoutInteraction(_ ref: SecretRef) async -> ResolvedSecret? {
        try? await resolve(ref, unlock: nil)
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
        origin: String? = nil
    ) async throws -> NativeStoreEditStart {
        guard editSessions.count < Self.maximumEditSessions else {
            throw NativeStoreError.tooManyEditSessions
        }
        // An edit writes the Keychain record, which only a local context
        // opens; a remote unlock reads mirrors and never writes.
        guard let unlock, unlock.isLocal else { throw NativeStoreError.authenticationRequired }
        if let origin {
            guard NativeStoreOriginMarker.isValidOrigin(origin) else {
                throw NativeStoreError.invalidDocument
            }
        }

        let record: NativeStoreKeyRecord
        var freshlyCreated = false
        if let existing = try await recordForLocalWrite(for: store, unlock: unlock) {
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
            absentRecords.remove(store.value)
            await sealMirror(store, fresh)
            record = fresh
            freshlyCreated = true
        }
        if let origin {
            try await enforceOrigin(
                origin,
                store: store,
                keyData: record.keyData,
                freshlyCreated: freshlyCreated
            )
        }

        let document: NativeStoreDocument
        if record.generation == 0 {
            document = try NativeStoreDocument(values: [:])
        } else {
            document = try await loadDocument(store: store, record: record)
        }
        let sessionID = UUID().uuidString.lowercased()
        editSessions[sessionID] = EditSession(
            caller: EditCaller(pid: callerPID, startTime: callerStartTime),
            store: store,
            baseline: record,
            unlock: unlock
        )
        return NativeStoreEditStart(sessionID: sessionID, document: try document.encoded())
    }

    public func commitEdit(
        sessionID: String,
        document data: Data,
        callerPID: pid_t,
        callerStartTime: UInt64
    ) async throws -> NativeStoreEditCommit {
        guard let session = editSessions[sessionID],
              session.caller == EditCaller(pid: callerPID, startTime: callerStartTime) else {
            throw NativeStoreError.editSessionNotFound
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
        mirrorWritesInFlight[session.store.value, default: 0] += 1
        do {
            try await removeMirrorBeforeWrite(session.store)
            try await keyBackend.update(
                store: session.store.value,
                record: updated,
                unlock: session.unlock
            )
        } catch {
            endMirrorWrite(session.store)
            await fileBackend.delete(named: fileName)
            throw NativeStoreError.keyUnavailable
        }

        records[session.store.value] = updated
        remotelyOpened.remove(session.store.value)
        endMirrorWrite(session.store)
        await sealMirror(session.store, updated)
        editSessions[sessionID] = nil
        if let oldID = session.baseline.activeFileID {
            await fileBackend.delete(named: Self.fileName(store: session.store, fileID: oldID))
        }
        await backUp(session.store, updated)
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
        callerStartTime: UInt64
    ) async throws -> NativeStoreEditCommit {
        guard let session = editSessions[sessionID],
              session.caller == EditCaller(pid: callerPID, startTime: callerStartTime) else {
            throw NativeStoreError.editSessionNotFound
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

    /// Bind a default-resolved store name to the project root that claimed it.
    /// Called only when the launcher derived the name from a project directory
    /// (never for explicit `--store` overrides or direct references):
    /// - a fresh store (or one with no marker — legacy, or a stale/unreadable
    ///   leftover) is stamped with this origin;
    /// - an existing marker must verify under the store key *and* name this
    ///   exact root, otherwise the launcher's resolution was stale or the
    ///   cleartext header was forged, and the edit is refused so it can
    ///   re-resolve onto the deterministic suffixed name.
    private func enforceOrigin(
        _ origin: String,
        store: NativeStoreName,
        keyData: Data,
        freshlyCreated: Bool
    ) async throws {
        let markerName = NativeStoreOriginMarker.fileName(store: store)
        let existingMarker = freshlyCreated ? nil : try? await fileBackend.read(named: markerName)
        if let existingMarker {
            guard let verified = NativeStoreOriginMarker.verifiedOrigin(
                data: existingMarker, store: store, keyData: keyData
            ), verified == origin else {
                throw NativeStoreError.originConflict
            }
            return
        }
        let sealed = try NativeStoreOriginMarker.sealed(
            origin: origin, store: store, keyData: keyData)
        await fileBackend.delete(named: markerName)
        do {
            try await fileBackend.writeAtomically(named: markerName, data: sealed)
        } catch {
            throw NativeStoreError.filesystemFailure
        }
    }

    private func existingRecord(
        for store: NativeStoreName,
        unlock: CacheUnlock?
    ) async throws -> NativeStoreKeyRecord? {
        if let record = records[store.value] { return record }
        if absentRecords.contains(store.value) { return nil }
        guard let unlock else { throw NativeStoreError.authenticationRequired }
        if let remote = unlock.remote {
            return try await remotelyOpenedRecord(for: store, remote: remote)
        }
        return try await locallyLoadedRecord(for: store, unlock: unlock)
    }

    /// The Keychain record itself, read with a local context, made warm, and
    /// sealed to its remote-unlock mirror when remote unlock is enrolled.
    private func locallyLoadedRecord(
        for store: NativeStoreName,
        unlock: CacheUnlock
    ) async throws -> NativeStoreKeyRecord? {
        do {
            guard let record = try await keyBackend.load(store: store.value, unlock: unlock) else {
                absentRecords.insert(store.value)
                return nil
            }
            guard record.isValid else { throw NativeStoreError.keyUnavailable }
            records[store.value] = record
            remotelyOpened.remove(store.value)
            await sealMirror(store, record)
            await backUp(store, record)
            return record
        } catch let error as NativeStoreError {
            throw error
        } catch {
            throw NativeStoreError.keyUnavailable
        }
    }

    /// The record opened from its remote-unlock mirror. It passes exactly the
    /// checks the Keychain record does (`isValid`, then the pointer and
    /// ciphertext checks of `loadDocument`), and all of them before it is made
    /// warm, so a stale or foreign mirror fails closed instead of leaving a
    /// record behind that would fail every later read. With no mirror, a store
    /// whose record does not exist at all needs nothing opened; any other
    /// store still needs a local touch. Nothing here ever creates or replaces
    /// a store.
    private func remotelyOpenedRecord(
        for store: NativeStoreName,
        remote: RemoteUnlockKey
    ) async throws -> NativeStoreKeyRecord? {
        let payload: Data?
        do {
            payload = try await remote.open(.nativeDocuments(store: store.value))
        } catch RemoteUnlockStoreError.unlockInvalidated {
            throw NativeStoreError.authenticationRequired
        } catch {
            throw NativeStoreError.keyUnavailable
        }
        guard let payload else {
            if (try? await keyBackend.recordExists(store: store.value)) == false {
                absentRecords.insert(store.value)
                return nil
            }
            throw NativeStoreError.authenticationRequired
        }
        guard let record = try? JSONDecoder().decode(NativeStoreKeyRecord.self, from: payload),
              record.isValid else {
            throw NativeStoreError.keyUnavailable
        }
        if record.generation > 0 {
            _ = try await loadDocument(store: store, record: record)
        }
        // A local read or a commit that finished meanwhile holds the
        // Keychain's own record: keep it.
        if let current = records[store.value] { return current }
        records[store.value] = record
        remotelyOpened.insert(store.value)
        return record
    }

    /// The record a write starts from. One opened from a mirror is re-read
    /// from the Keychain with the write's local context first, so a write
    /// never builds on anything but the Keychain record.
    private func recordForLocalWrite(
        for store: NativeStoreName,
        unlock: CacheUnlock
    ) async throws -> NativeStoreKeyRecord? {
        guard remotelyOpened.contains(store.value) else {
            return try await existingRecord(for: store, unlock: unlock)
        }
        let reloaded = try await locallyLoadedRecord(for: store, unlock: unlock)
        if reloaded == nil {
            records[store.value] = nil
            remotelyOpened.remove(store.value)
        }
        return reloaded
    }

    /// Seal `record` to its remote-unlock mirror. A no-op (false) without an
    /// enrollment, and while the store's record is being moved (that write
    /// seals its own record when it lands). If the warm record changed while
    /// this seal was in flight, the current one is sealed over it. A failure
    /// is logged value-free, and the mirror store has then removed or
    /// neutralized the older mirror.
    @discardableResult
    private func sealMirror(_ store: NativeStoreName, _ record: NativeStoreKeyRecord) async -> Bool {
        guard let remoteUnlock, mirrorWritesInFlight[store.value, default: 0] == 0 else { return false }
        do {
            var sealed = record
            var stored = try await remoteUnlock.sealAndStore(
                .nativeDocuments(store: store.value), payload: try JSONEncoder().encode(sealed)
            )
            while stored, mirrorWritesInFlight[store.value, default: 0] == 0,
                  !remotelyOpened.contains(store.value),
                  let current = records[store.value], current != sealed {
                sealed = current
                stored = try await remoteUnlock.sealAndStore(
                    .nativeDocuments(store: store.value), payload: try JSONEncoder().encode(sealed)
                )
            }
            return stored
        } catch {
            Self.logMirror("native store \(store) not mirrored for remote unlock (\(error))")
            return false
        }
    }

    private func endMirrorWrite(_ store: NativeStoreName) {
        let remaining = mirrorWritesInFlight[store.value, default: 1] - 1
        mirrorWritesInFlight[store.value] = remaining > 0 ? remaining : nil
    }

    /// Before the Keychain record moves, its mirror goes: a mirror must never
    /// name a pointer the record no longer holds, or a crash between the
    /// update and the re-seal would leave one that still opens the previous
    /// generation while that file lingers. It is sealed again after the
    /// update. No Keychain call without an enrollment.
    private func removeMirrorBeforeWrite(_ store: NativeStoreName) async throws {
        guard let remoteUnlock else { return }
        try await remoteUnlock.remove(.nativeDocuments(store: store.value))
    }

    private static func logMirror(_ message: String) {
        FileHandle.standardError.write(Data("csecd: native store: \(message)\n".utf8))
    }

    // MARK: - Backup

    /// Hand the backup a bundle of `record` and the files it pins (the
    /// document's ciphertext and the store's origin marker) when the last
    /// bundle for this store is older. The files are read as they are, never
    /// decrypted; the digest check keeps a damaged file from replacing a good
    /// bundle. A failure is recorded by the backup and never fails the read or
    /// write that led here.
    @discardableResult
    private func backUp(_ store: NativeStoreName, _ record: NativeStoreKeyRecord) async -> NativeStoreBackupOutcome {
        guard let backup else { return .off }
        guard await backup.needsBundle(tier: .documents, store: store, record: record) else { return .current }
        do {
            guard let fileID = record.activeFileID else { throw NativeStoreError.integrityFailure }
            let name = Self.fileName(store: store, fileID: fileID)
            guard let ciphertext = try await fileBackend.read(named: name),
                  Self.digest(ciphertext) == record.ciphertextDigest else {
                throw NativeStoreError.integrityFailure
            }
            var files = [name: ciphertext]
            let marker = NativeStoreOriginMarker.fileName(store: store)
            if let origin = try? await fileBackend.read(named: marker),
               NativeStoreOriginMarker.verifiedOrigin(data: origin, store: store, keyData: record.keyData) != nil {
                files[marker] = origin
            }
            return await backup.write(.store(
                .documents, store, record: record, files: files, createdAt: Date()
            ))
        } catch {
            await backup.recordFailure(
                .store(.documents, store), generation: record.generation,
                reason: (error as? NativeStoreError)?.boundedReason ?? "the store's files could not be read"
            )
            return .failed
        }
    }

    /// Bring every store's bundle up to date, in both tiers, reading each key
    /// record with the one context `csec backup setup` or `sync` spent. Warm
    /// state is left exactly as it was.
    public func backfillBackups(localUnlock: CacheUnlock) async -> NativeStoreBackupReport {
        var report = NativeStoreBackupReport()
        guard backup != nil, localUnlock.isLocal else { return report }
        do {
            for name in Set(try await keyBackend.storeNames(unlock: localUnlock)).sorted() {
                guard let store = try? NativeStoreName(name),
                      let record = try? await keyBackend.load(store: store.value, unlock: localUnlock),
                      record.isValid else {
                    report.failed += 1
                    continue
                }
                guard record.generation > 0 else { continue }
                report.add(await backUp(store, record))
            }
        } catch {
            report.failed += 1
        }
        if let blobStore {
            report.add(await blobStore.backfillBackups(localUnlock: localUnlock))
        }
        return report
    }

    /// Whether this tier holds `store`: an open record, or a Keychain record
    /// found by its attributes alone (no prompt). A lookup that cannot say
    /// counts as holding it, so a restore never writes over what it could not
    /// rule out. Files with no record (an interrupted restore) do not count.
    public func holdsStore(_ store: NativeStoreName) async -> Bool {
        if records[store.value] != nil { return true }
        return (try? await keyBackend.recordExists(store: store.value)) != false
    }

    /// Validate one document-tier store from a backup bundle without
    /// changing anything: the record must pin exactly the files the bundle
    /// holds, and the document must open under the record's key. Returns how
    /// many keys it holds, for the value-free restore listing.
    public nonisolated func inspectBackup(
        store: NativeStoreName,
        record: NativeStoreKeyRecord,
        files: [String: Data]
    ) throws -> Int {
        guard record.isValid, record.generation > 0, let fileID = record.activeFileID else {
            throw NativeStoreError.integrityFailure
        }
        let name = Self.fileName(store: store, fileID: fileID)
        let marker = NativeStoreOriginMarker.fileName(store: store)
        guard let ciphertext = files[name],
              Self.digest(ciphertext) == record.ciphertextDigest,
              Set(files.keys).isSubset(of: [name, marker]) else {
            throw NativeStoreError.integrityFailure
        }
        let plaintext = try Self.open(
            ciphertext: ciphertext, store: store, keyData: record.keyData,
            generation: record.generation, fileID: fileID
        )
        guard let document = try? NativeStoreDocument(data: plaintext) else {
            throw NativeStoreError.integrityFailure
        }
        return document.values.count
    }

    /// Put one document-tier store back from a backup bundle, under a new
    /// device-bound Keychain item holding the same record: the files are
    /// written first, the record only after, so a failure leaves no record
    /// pointing at nothing. Only a store this Mac does not have at all is
    /// restored; nothing is ever overwritten.
    public func restoreFromBackup(
        store: NativeStoreName,
        record: NativeStoreKeyRecord,
        files: [String: Data]
    ) async throws -> Int {
        let keys = try inspectBackup(store: store, record: record, files: files)
        let marker = NativeStoreOriginMarker.fileName(store: store)
        var restorable = files
        if let origin = files[marker],
           NativeStoreOriginMarker.verifiedOrigin(data: origin, store: store, keyData: record.keyData) == nil {
            restorable[marker] = nil
        }
        let written = try await NativeStoreBackupRestoration.writeFiles(
            restorable, store: store, keyBackend: keyBackend, fileBackend: fileBackend,
            alreadyOpen: records[store.value] != nil
        )
        // A store created here while the files were being written wins.
        guard records[store.value] == nil else {
            for name in written { await fileBackend.delete(named: name) }
            throw NativeStoreBackupError.storeExists
        }
        do {
            try await keyBackend.create(store: store.value, record: record)
        } catch {
            for name in written { await fileBackend.delete(named: name) }
            throw (try? await keyBackend.recordExists(store: store.value)) == true
                ? NativeStoreBackupError.storeExists : NativeStoreError.filesystemFailure
        }
        records[store.value] = record
        absentRecords.remove(store.value)
        await sealMirror(store, record)
        await backUp(store, record)
        return keys
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
