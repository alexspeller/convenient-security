import CryptoKit
import CSECRemoteApproval
import Foundation
import Security

public struct StoredRemoteApprovalConfiguration: Codable, Equatable, Sendable {
    public let version: UInt16
    public let macDeviceID: String
    public let macDeviceName: String
    public let macSigningKeyRepresentation: Data
    public let macPublicKeyX963: Data
    public let phoneDeviceID: String
    public let phoneDeviceName: String
    public let phonePublicKeyX963: Data
    public let cloudKitContainerIdentifier: String

    public init(
        macDeviceID: String,
        macDeviceName: String,
        macSigningKeyRepresentation: Data,
        macPublicKeyX963: Data,
        phoneDeviceID: String,
        phoneDeviceName: String,
        phonePublicKeyX963: Data,
        cloudKitContainerIdentifier: String
    ) {
        self.version = RemoteApprovalProtocolV1.version
        self.macDeviceID = macDeviceID.lowercased()
        self.macDeviceName = macDeviceName
        self.macSigningKeyRepresentation = macSigningKeyRepresentation
        self.macPublicKeyX963 = macPublicKeyX963
        self.phoneDeviceID = phoneDeviceID.lowercased()
        self.phoneDeviceName = phoneDeviceName
        self.phonePublicKeyX963 = phonePublicKeyX963
        self.cloudKitContainerIdentifier = cloudKitContainerIdentifier
    }

    public func validate() throws {
        guard version == RemoteApprovalProtocolV1.version,
              !macSigningKeyRepresentation.isEmpty,
              macSigningKeyRepresentation.count <= 4_096 else {
            throw RemoteApprovalManagerError.invalidConfiguration
        }
        try RemoteApprovalMacPairing(
            macDeviceID: macDeviceID,
            macDeviceName: macDeviceName,
            macPublicKeyX963: macPublicKeyX963,
            cloudKitContainerIdentifier: cloudKitContainerIdentifier
        ).validate()
        try RemoteApprovalPhonePairing(
            phoneDeviceID: phoneDeviceID,
            phoneDeviceName: phoneDeviceName,
            phonePublicKeyX963: phonePublicKeyX963
        ).validate()
    }
}

public protocol RemoteApprovalConfigurationStore: Sendable {
    func load() async throws -> StoredRemoteApprovalConfiguration?
    func store(_ configuration: StoredRemoteApprovalConfiguration) async throws
    func delete() async throws
}

/// Code-identity-gated, non-interactive configuration storage. Public keys and
/// device names are not secrets; the Secure Enclave dataRepresentation is an
/// opaque handle, not private-key material. Local Touch ID is required by the
/// manager before this record is created, replaced, or deleted.
public struct SecurityRemoteApprovalConfigurationStore: RemoteApprovalConfigurationStore {
    public static let service = "com.alexspeller.convenient-security.remote-approval"
    private static let account = "pinned-phone-v1"

    private let queue = DispatchQueue(
        label: "com.alexspeller.convenient-security.remote-approval-keychain"
    )

    public init() {}

    public func load() async throws -> StoredRemoteApprovalConfiguration? {
        try await blocking {
            var query = identity()
            query[kSecReturnData as String] = true
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess:
                guard let data = result as? Data,
                      data.count <= 32 * 1_024 else {
                    throw RemoteApprovalManagerError.invalidConfiguration
                }
                let configuration = try JSONDecoder().decode(
                    StoredRemoteApprovalConfiguration.self,
                    from: data
                )
                try configuration.validate()
                return configuration
            case errSecItemNotFound:
                return nil
            default:
                throw KeychainError(
                    operation: "remote approval read",
                    status: status
                )
            }
        }
    }

    public func store(_ configuration: StoredRemoteApprovalConfiguration) async throws {
        try configuration.validate()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(configuration)
        guard data.count <= 32 * 1_024 else {
            throw RemoteApprovalManagerError.invalidConfiguration
        }
        try await blocking {
            var query = identity()
            let update = [kSecValueData as String: data]
            let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
            if status == errSecSuccess { return }
            guard status == errSecItemNotFound else {
                throw KeychainError(
                    operation: "remote approval update",
                    status: status
                )
            }
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            query[kSecValueData as String] = data
            let addStatus = SecItemAdd(query as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainError(
                    operation: "remote approval add",
                    status: addStatus
                )
            }
        }
    }

    public func delete() async throws {
        try await blocking {
            let status = SecItemDelete(identity() as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeychainError(
                    operation: "remote approval delete",
                    status: status
                )
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

    private func blocking<T: Sendable>(
        _ body: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result { try body() }) }
        }
    }
}

public actor SecureEnclaveRemoteApprovalSigner: RemoteApprovalRequestSigner {
    private let key: SecureEnclave.P256.Signing.PrivateKey

    public init(dataRepresentation: Data) throws {
        guard SecureEnclave.isAvailable else {
            throw RemoteApprovalManagerError.secureEnclaveUnavailable
        }
        self.key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: dataRepresentation
        )
    }

    public static func create() throws -> (
        signer: SecureEnclaveRemoteApprovalSigner,
        dataRepresentation: Data,
        publicKeyX963: Data
    ) {
        guard SecureEnclave.isAvailable else {
            throw RemoteApprovalManagerError.secureEnclaveUnavailable
        }
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            .privateKeyUsage,
            &accessError
        ) else {
            throw RemoteApprovalManagerError.secureEnclaveUnavailable
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        return (
            SecureEnclaveRemoteApprovalSigner(key: key),
            key.dataRepresentation,
            key.publicKey.x963Representation
        )
    }

    private init(key: SecureEnclave.P256.Signing.PrivateKey) {
        self.key = key
    }

    public func publicKeyX963Representation() async throws -> Data {
        key.publicKey.x963Representation
    }

    public func sign(_ data: Data) async throws -> Data {
        try key.signature(for: data).derRepresentation
    }
}

public enum RemoteApprovalManagerStatus: Equatable, Sendable {
    case disabled
    case enabled(phoneName: String, phoneKeyFingerprint: String)
    case unavailable
}

/// Owns the dynamic opt-in state. The mirrored policy reviewer can be installed
/// unconditionally: before a valid pinned record exists this provider returns
/// `.unavailable` immediately and the unchanged local Touch ID path continues.
public actor RemoteApprovalManager: RemoteAccessPolicyReviewProvider {
    private let store: any RemoteApprovalConfigurationStore
    private let relay: any RemoteApprovalRelay
    private let consent: any ConsentProvider
    private let cloudKitContainerIdentifier: String
    private let relayIsConfigured: Bool
    private let relayIsAvailable: @Sendable () async -> Bool

    private var configuration: StoredRemoteApprovalConfiguration?
    private var requester: RemoteApprovalRequester?
    private var loadFailed = false

    public init(
        store: any RemoteApprovalConfigurationStore,
        relay: any RemoteApprovalRelay,
        consent: any ConsentProvider,
        cloudKitContainerIdentifier: String,
        relayIsConfigured: Bool = true,
        relayIsAvailable: @escaping @Sendable () async -> Bool = { true }
    ) {
        self.store = store
        self.relay = relay
        self.consent = consent
        self.cloudKitContainerIdentifier = cloudKitContainerIdentifier
        self.relayIsConfigured = relayIsConfigured
        self.relayIsAvailable = relayIsAvailable
    }

    public func prepare() async {
        guard relayIsConfigured else {
            configuration = nil
            requester = nil
            loadFailed = true
            return
        }
        do {
            guard let stored = try await store.load() else {
                configuration = nil
                requester = nil
                loadFailed = false
                return
            }
            let preparedRequester = try await makeRequester(for: stored)
            configuration = stored
            requester = preparedRequester
            loadFailed = false
        } catch {
            configuration = nil
            requester = nil
            loadFailed = true
        }
    }

    public func status() -> RemoteApprovalManagerStatus {
        if loadFailed { return .unavailable }
        guard let configuration else { return .disabled }
        return .enabled(
            phoneName: ReviewDisplay.sanitized(configuration.phoneDeviceName),
            phoneKeyFingerprint: RemoteApprovalPairingCode.publicKeyFingerprint(
                configuration.phonePublicKeyX963
            )
        )
    }

    /// Pin or replace one phone after a fresh local biometric. Returns the Mac's
    /// public pairing code for biometric-gated import by the phone app.
    public func enable(phonePairingCode: String) async throws -> String {
        let phone = try RemoteApprovalPairingCode.decodePhone(phonePairingCode)
        guard relayIsConfigured, await relayIsAvailable() else {
            throw RemoteApprovalManagerError.relayUnavailable
        }
        let safeName = ReviewDisplay.sanitized(phone.phoneDeviceName)
        let fingerprint = RemoteApprovalPairingCode.publicKeyFingerprint(
            phone.phonePublicKeyX963
        )
        let auth = await consent.authenticate(
            reason: "Enable remote approval from \(safeName) (key \(fingerprint))"
        )
        guard auth.isApproved else { throw RemoteApprovalManagerError.denied }

        let material = try SecureEnclaveRemoteApprovalSigner.create()
        let macName = ReviewDisplay.sanitized(
            Host.current().localizedName ?? "Mac"
        )
        let stored = StoredRemoteApprovalConfiguration(
            macDeviceID: UUID().uuidString.lowercased(),
            macDeviceName: macName,
            macSigningKeyRepresentation: material.dataRepresentation,
            macPublicKeyX963: material.publicKeyX963,
            phoneDeviceID: phone.phoneDeviceID,
            phoneDeviceName: safeName,
            phonePublicKeyX963: phone.phonePublicKeyX963,
            cloudKitContainerIdentifier: cloudKitContainerIdentifier
        )
        let preparedRequester = try await makeRequester(
            for: stored,
            signer: material.signer
        )
        try await store.store(stored)
        configuration = stored
        requester = preparedRequester
        loadFailed = false

        return try RemoteApprovalPairingCode.encodeMac(
            RemoteApprovalMacPairing(
                macDeviceID: stored.macDeviceID,
                macDeviceName: stored.macDeviceName,
                macPublicKeyX963: stored.macPublicKeyX963,
                cloudKitContainerIdentifier: stored.cloudKitContainerIdentifier
            )
        )
    }

    public func disable() async throws {
        guard configuration != nil || loadFailed else { return }
        let auth = await consent.authenticate(reason: "Disable iPhone remote approval")
        guard auth.isApproved else { throw RemoteApprovalManagerError.denied }
        try await store.delete()
        configuration = nil
        requester = nil
        loadFailed = false
    }

    public func reviewRemoteAccess(
        _ review: RemoteApprovalReview
    ) async -> RemoteApprovalRequesterResult {
        guard let requester else { return .unavailable }
        return await requester.requestApproval(for: review)
    }

    private func makeRequester(
        for stored: StoredRemoteApprovalConfiguration,
        signer suppliedSigner: SecureEnclaveRemoteApprovalSigner? = nil
    ) async throws -> RemoteApprovalRequester {
        try stored.validate()
        guard stored.cloudKitContainerIdentifier == cloudKitContainerIdentifier else {
            throw RemoteApprovalManagerError.invalidConfiguration
        }
        let signer = try suppliedSigner ?? SecureEnclaveRemoteApprovalSigner(
            dataRepresentation: stored.macSigningKeyRepresentation
        )
        guard try await signer.publicKeyX963Representation() == stored.macPublicKeyX963 else {
            throw RemoteApprovalManagerError.invalidConfiguration
        }
        let config = RemoteApprovalRequesterConfiguration(
            macDeviceID: stored.macDeviceID,
            macDeviceName: stored.macDeviceName,
            pinnedPhoneDeviceID: stored.phoneDeviceID,
            pinnedPhonePublicKeyX963: stored.phonePublicKeyX963
        )
        return try RemoteApprovalRequester(
            configuration: config,
            signer: signer,
            relay: relay
        )
    }
}

/// Safe stand-in for a build without CloudKit entitlements. The protocol stays
/// present so local policy review and opt-out recovery retain one code path, but
/// every attempted transport operation is explicitly unavailable.
public actor UnavailableRemoteApprovalRelay: RemoteApprovalRelay {
    public init() {}

    public func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        throw RemoteApprovalManagerError.relayUnavailable
    }

    public func response(
        for requestID: String
    ) async throws -> SignedRemoteApprovalResponse? {
        throw RemoteApprovalManagerError.relayUnavailable
    }

    public func pendingRequests() async throws -> [SignedRemoteApprovalRequest] {
        throw RemoteApprovalManagerError.relayUnavailable
    }

    public func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {
        throw RemoteApprovalManagerError.relayUnavailable
    }

    public func deleteExchange(requestID: String) async {}
}

public enum RemoteApprovalManagerError: Error, Equatable, Sendable {
    case invalidConfiguration
    case secureEnclaveUnavailable
    case relayUnavailable
    case denied
}
