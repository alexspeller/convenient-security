import Foundation
import CryptoKit
import Security

public protocol RiskJudgmentBackend: Sendable {
    func load(service: String, account: String) async throws -> Data?
    func store(service: String, account: String, data: Data) async throws
    func delete(service: String, account: String) async
}

/// Integrity-protected judgment store. It stores no raw provider reference:
/// account names and member identities are HMACs under an agent-only device key.
public actor RiskJudgmentStore {
    public static let policyService = "com.alexspeller.convenient-security.judgments"
    public static let acceptanceService = "com.alexspeller.convenient-security.delivery-acceptance"
    public static let keyService = "com.alexspeller.convenient-security.judgment-key"
    private static let keyAccount = "device-hmac-key-v1"

    private let backend: RiskJudgmentBackend
    private var loadedKey: SymmetricKey?

    public init(backend: RiskJudgmentBackend = SecurityRiskJudgmentBackend()) {
        self.backend = backend
    }

    /// Derive the opaque logical bundle identity used by judgments. `group` is
    /// provider-specific (for 1Password, initially vault/item); members may be
    /// individual fields. Raw strings exist only transiently in this call.
    public func credentialIdentity(
        provider: String,
        providerAccount: String,
        group: String,
        memberReferences: [String]
    ) async throws -> CredentialIdentity {
        let key = try await deviceKey()
        return CredentialIdentity(
            provider: provider,
            providerAccountKey: opaqueID(
                components: ["account", provider, providerAccount],
                key: key
            ),
            credentialKey: opaqueID(
                components: ["credential", provider, providerAccount, group],
                key: key
            ),
            memberReferenceKeys: memberReferences.map {
                opaqueID(
                    components: ["member", provider, providerAccount, $0],
                    key: key
                )
            }
        )
    }

    public func save(_ judgment: RiskJudgment) async throws {
        guard judgment.level != .unknown else {
            throw RiskJudgmentStoreError.unknownCannotBePersisted
        }
        guard Self.hasValidOpaqueMetadata(judgment) else {
            throw RiskJudgmentStoreError.invalidOpaqueMetadata
        }
        guard judgment.decidedAt < judgment.reviewAfter else {
            throw RiskJudgmentStoreError.invalidReviewWindow
        }
        let data = try JSONEncoder().encode(judgment)
        try await backend.store(
            service: Self.policyService,
            account: judgment.credential.credentialKey,
            data: data
        )
    }

    /// Returns only a current judgment. Stale policy/review records are deleted
    /// so they cannot be accidentally reused as a downgrade.
    public func load(
        credentialKey: String,
        policyVersion: Int,
        at date: Date = Date()
    ) async throws -> RiskJudgment? {
        guard Self.isOpaqueDigest(credentialKey) else { return nil }
        guard let data = try await backend.load(
            service: Self.policyService,
            account: credentialKey
        ) else { return nil }

        guard let judgment = try? JSONDecoder().decode(RiskJudgment.self, from: data),
              judgment.credential.credentialKey == credentialKey,
              judgment.level != .unknown,
              judgment.decidedAt < judgment.reviewAfter,
              Self.hasValidOpaqueMetadata(judgment) else {
            await forget(credentialKey: credentialKey)
            return nil
        }

        guard judgment.isCurrent(at: date, policyVersion: policyVersion) else {
            await forget(credentialKey: credentialKey)
            return nil
        }
        return judgment
    }

    public func forget(credentialKey: String) async {
        await backend.delete(service: Self.policyService, account: credentialKey)
    }

    public func save(_ acceptance: DeliveryAcceptance) async throws {
        guard Self.isOpaqueDigest(acceptance.credentialKey) else {
            throw RiskJudgmentStoreError.invalidOpaqueMetadata
        }
        guard acceptance.acceptedAt < acceptance.reviewAfter else {
            throw RiskJudgmentStoreError.invalidReviewWindow
        }
        let account = "\(acceptance.credentialKey).\(acceptance.mechanism.rawValue).\(acceptance.consumerAssurance.rawValue)"
        try await backend.store(
            service: Self.acceptanceService,
            account: account,
            data: try JSONEncoder().encode(acceptance)
        )
    }

    public func loadAcceptance(
        credentialKey: String,
        mechanism: DeliveryMechanism,
        assurance: ConsumerAssurance,
        policyVersion: Int,
        at date: Date = Date()
    ) async throws -> DeliveryAcceptance? {
        guard Self.isOpaqueDigest(credentialKey) else { return nil }
        let account = "\(credentialKey).\(mechanism.rawValue).\(assurance.rawValue)"
        guard let data = try await backend.load(
            service: Self.acceptanceService,
            account: account
        ) else { return nil }
        guard let acceptance = try? JSONDecoder().decode(DeliveryAcceptance.self, from: data),
              acceptance.credentialKey == credentialKey,
              acceptance.mechanism == mechanism,
              acceptance.consumerAssurance == assurance,
              acceptance.acceptedAt < acceptance.reviewAfter,
              acceptance.policyVersion == policyVersion,
              date < acceptance.reviewAfter else {
            await backend.delete(service: Self.acceptanceService, account: account)
            return nil
        }
        return acceptance
    }

    public func forgetAcceptance(
        credentialKey: String,
        mechanism: DeliveryMechanism,
        assurance: ConsumerAssurance
    ) async {
        let account = "\(credentialKey).\(mechanism.rawValue).\(assurance.rawValue)"
        await backend.delete(service: Self.acceptanceService, account: account)
    }

    private func deviceKey() async throws -> SymmetricKey {
        if let loadedKey { return loadedKey }
        if let existing = try await backend.load(
            service: Self.keyService,
            account: Self.keyAccount
        ), existing.count == 32 {
            let key = SymmetricKey(data: existing)
            loadedKey = key
            return key
        }

        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw RiskJudgmentStoreError.randomGenerationFailed
        }
        let data = Data(bytes)
        try await backend.store(service: Self.keyService, account: Self.keyAccount, data: data)
        let key = SymmetricKey(data: data)
        loadedKey = key
        return key
    }

    private func opaqueID(components: [String], key: SymmetricKey) -> String {
        var input = Data()
        for component in components {
            let bytes = Data(component.utf8)
            var length = UInt32(bytes.count).bigEndian
            withUnsafeBytes(of: &length) { input.append(contentsOf: $0) }
            input.append(bytes)
        }
        return HMAC<SHA256>.authenticationCode(for: input, using: key).map {
            String(format: "%02x", $0)
        }.joined()
    }

    private static func isOpaqueDigest(_ value: String) -> Bool {
        value.count == 64 && value.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
    }

    private static func hasValidOpaqueMetadata(_ judgment: RiskJudgment) -> Bool {
        let opaqueFields = [
            judgment.credential.providerAccountKey,
            judgment.credential.credentialKey,
        ] + judgment.credential.memberReferenceKeys
            + judgment.evidence.map(\.evidenceDigest)
            + [judgment.providerRevision, judgment.observedScopeDigest].compactMap { $0 }
        return opaqueFields.allSatisfy(isOpaqueDigest)
    }
}

public enum RiskJudgmentStoreError: Error {
    case unknownCannotBePersisted
    case invalidOpaqueMetadata
    case invalidReviewWindow
    case randomGenerationFailed
}

/// Data-protection-keychain backend with ThisDeviceOnly protection and no
/// biometric read ACL. Confidentiality and integrity come from the provisioned
/// agent-only access group; judgments are metadata, never grants or values.
public struct SecurityRiskJudgmentBackend: RiskJudgmentBackend {
    private let queue = DispatchQueue(label: "com.alexspeller.convenient-security.judgments")

    public init() {}

    public func load(service: String, account: String) async throws -> Data? {
        try await blocking {
            var query = identity(service: service, account: account)
            query[kSecReturnData as String] = true
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess: return result as? Data
            case errSecItemNotFound: return nil
            default: throw KeychainError(operation: "judgment read", status: status)
            }
        }
    }

    public func store(service: String, account: String, data: Data) async throws {
        try await blocking {
            let base = identity(service: service, account: account)
            let updateStatus = SecItemUpdate(
                base as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            if updateStatus == errSecSuccess { return }
            guard updateStatus == errSecItemNotFound else {
                throw KeychainError(operation: "judgment update", status: updateStatus)
            }
            var add = base
            add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            add[kSecValueData as String] = data
            let addStatus = SecItemAdd(add as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainError(operation: "judgment add", status: addStatus)
            }
        }
    }

    public func delete(service: String, account: String) async {
        _ = try? await blocking {
            SecItemDelete(identity(service: service, account: account) as CFDictionary)
        }
    }

    private func identity(service: String, account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
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

/// Initial provider-specific grouping rule. It is pure and returns metadata
/// only; the store HMACs the result before persistence.
public enum CredentialGrouping {
    public static func onePasswordGroup(for reference: SecretRef) -> String? {
        guard reference.scheme == "op" else { return nil }
        let components = reference.path.split(separator: "/", omittingEmptySubsequences: false)
        guard components.count >= 2,
              !components[0].isEmpty,
              !components[1].isEmpty else { return nil }
        return components.prefix(2).joined(separator: "/")
    }
}
