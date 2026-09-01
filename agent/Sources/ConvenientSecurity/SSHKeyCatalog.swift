import Foundation
import Security

public struct SSHKeyRegistrationIntent: Codable, Sendable, Equatable {
    public let reference: String
    public let label: String?

    public init(reference: String, label: String? = nil) {
        self.reference = reference
        self.label = label
    }
}

/// Persisted SSH catalog row. It contains a canonical provider-neutral
/// reference and public key metadata only; private bytes and provider-private
/// identifiers are never stored here.
public struct SSHKeyMetadata: Codable, Sendable, Equatable {
    public let reference: String
    public let fingerprint: String
    public let algorithm: String
    public let publicKeyBlob: Data
    public let label: String

    public init(
        reference: String,
        fingerprint: String,
        algorithm: String,
        publicKeyBlob: Data,
        label: String
    ) {
        self.reference = reference
        self.fingerprint = fingerprint
        self.algorithm = algorithm
        self.publicKeyBlob = publicKeyBlob
        self.label = label
    }

    public var publicKeyLine: String {
        let suffix = label.isEmpty ? "" : " \(label)"
        return "\(algorithm) \(publicKeyBlob.base64EncodedString())\(suffix)\n"
    }

    fileprivate var isValid: Bool {
        guard let reference = try? SecretRef(reference),
              self.reference == reference.uri,
              fingerprint.utf8.count <= 128,
              label.utf8.count <= 256,
              !label.utf8.contains(0),
              publicKeyBlob.count <= 16 * 1_024,
              let key = try? SSHPublicKey.parse(publicKeyBlob),
              key.algorithm == algorithm,
              key.fingerprint == fingerprint else { return false }
        return true
    }
}

public enum SSHKeyCatalogAction: String, Codable, Sendable {
    case list
    case register
    case remove
}

public struct SSHKeyCatalogRequest: Codable, Sendable {
    public let requestID: String
    public let action: SSHKeyCatalogAction
    public let registrations: [SSHKeyRegistrationIntent]
    public let fingerprint: String?

    public init(
        action: SSHKeyCatalogAction,
        registrations: [SSHKeyRegistrationIntent] = [],
        fingerprint: String? = nil,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.action = action
        self.registrations = registrations
        self.fingerprint = fingerprint
    }
}

public protocol SSHKeyCatalogStore: Sendable {
    func load() async throws -> [SSHKeyMetadata]
    func store(_ keys: [SSHKeyMetadata]) async throws
}

public actor InMemorySSHKeyCatalogStore: SSHKeyCatalogStore {
    private var keys: [SSHKeyMetadata]

    public init(keys: [SSHKeyMetadata] = []) { self.keys = keys }

    public func load() -> [SSHKeyMetadata] { keys }
    public func store(_ keys: [SSHKeyMetadata]) { self.keys = keys }
}

/// Public-metadata catalog in the data-protection Keychain. It is intentionally
/// not biometric-gated on reads: the signing service needs identities at SSH
/// connection time, while every mutation and every private operation has its
/// own authenticated policy gate. Code identity still limits the item to csecd.
public struct SecuritySSHKeyCatalogStore: SSHKeyCatalogStore {
    public static let service = "com.alexspeller.convenient-security.ssh-catalog"
    private static let account = "catalog-v1"
    private static let maximumBytes = 256 * 1_024

    private let queue = DispatchQueue(
        label: "com.alexspeller.convenient-security.ssh-catalog-keychain"
    )

    public init() {}

    public func load() async throws -> [SSHKeyMetadata] {
        try await blocking {
            var query = identity()
            query[kSecReturnData as String] = true
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess:
                guard let data = result as? Data, data.count <= Self.maximumBytes else {
                    throw SSHProtectionError.catalogUnavailable
                }
                return try decode(data)
            case errSecItemNotFound:
                return []
            default:
                throw KeychainError(operation: "SSH catalog read", status: status)
            }
        }
    }

    public func store(_ keys: [SSHKeyMetadata]) async throws {
        let data = try encode(keys)
        try await blocking {
            var query = identity()
            let status = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            if status == errSecSuccess { return }
            guard status == errSecItemNotFound else {
                throw KeychainError(operation: "SSH catalog update", status: status)
            }
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            query[kSecValueData as String] = data
            let addStatus = SecItemAdd(query as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainError(operation: "SSH catalog add", status: addStatus)
            }
        }
    }

    private func identity() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
        ]
    }

    private func encode(_ keys: [SSHKeyMetadata]) throws -> Data {
        guard keys.count <= SSHKeyCatalog.maximumKeys,
              keys.allSatisfy(\.isValid) else {
            throw SSHProtectionError.catalogUnavailable
        }
        let document = SSHKeyCatalogDocument(keys: keys)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(document)
        guard data.count <= Self.maximumBytes else { throw SSHProtectionError.catalogUnavailable }
        return data
    }

    private func decode(_ data: Data) throws -> [SSHKeyMetadata] {
        let document = try JSONDecoder().decode(SSHKeyCatalogDocument.self, from: data)
        guard document.version == 1,
              document.keys.count <= SSHKeyCatalog.maximumKeys,
              document.keys.allSatisfy(\.isValid),
              Set(document.keys.map(\.fingerprint)).count == document.keys.count else {
            throw SSHProtectionError.catalogUnavailable
        }
        return document.keys
    }

    private func blocking<T: Sendable>(
        _ body: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result { try body() }) }
        }
    }
}

private struct SSHKeyCatalogDocument: Codable {
    let version: UInt16
    let keys: [SSHKeyMetadata]

    init(keys: [SSHKeyMetadata]) {
        version = 1
        self.keys = keys
    }
}

public actor SSHKeyCatalog {
    public static let maximumKeys = 64

    private let store: any SSHKeyCatalogStore
    private var loaded: [SSHKeyMetadata]?

    public init(store: any SSHKeyCatalogStore) { self.store = store }

    public func list() async throws -> [SSHKeyMetadata] {
        try await current().sorted { $0.fingerprint < $1.fingerprint }
    }

    public func key(publicKeyBlob: Data) async throws -> SSHKeyMetadata? {
        try await current().first { $0.publicKeyBlob == publicKeyBlob }
    }

    @discardableResult
    public func register(_ additions: [SSHKeyMetadata]) async throws -> [SSHKeyMetadata] {
        guard !additions.isEmpty,
              additions.count <= Self.maximumKeys,
              additions.allSatisfy(\.isValid),
              Set(additions.map(\.fingerprint)).count == additions.count else {
            throw SSHProtectionError.invalidPrivateKey
        }
        var byFingerprint = Dictionary(
            uniqueKeysWithValues: try await current().map { ($0.fingerprint, $0) }
        )
        for key in additions { byFingerprint[key.fingerprint] = key }
        let next = byFingerprint.values.sorted { $0.fingerprint < $1.fingerprint }
        guard next.count <= Self.maximumKeys else { throw SSHProtectionError.catalogUnavailable }
        try await store.store(next)
        loaded = next
        return additions
    }

    public func remove(fingerprint: String) async throws -> Bool {
        let existing = try await current()
        let next = existing.filter { $0.fingerprint != fingerprint }
        guard next.count != existing.count else { return false }
        try await store.store(next)
        loaded = next
        return true
    }

    private func current() async throws -> [SSHKeyMetadata] {
        if let loaded { return loaded }
        let values = try await store.load()
        guard values.count <= Self.maximumKeys,
              values.allSatisfy(\.isValid),
              Set(values.map(\.fingerprint)).count == values.count else {
            throw SSHProtectionError.catalogUnavailable
        }
        loaded = values
        return values
    }
}
