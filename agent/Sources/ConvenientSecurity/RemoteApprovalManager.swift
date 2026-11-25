import CryptoKit
import CSECRemoteApproval
import Foundation
import Security
import CSECBuildIdentity

public struct StoredRemoteApprovalConfiguration: Codable, Equatable, Sendable {
    /// The pairing version this build writes and reads. Pairing v2 pins the
    /// phone's key-agreement key as well as its signing key; a record an
    /// older build wrote reads as `RemoteApprovalPairingProblem.outdated`.
    public static let currentVersion = RemoteApprovalProtocolV3.pairingVersion

    public let version: UInt16
    public let macDeviceID: String
    public let macDeviceName: String
    public let macSigningKeyRepresentation: Data
    public let macPublicKeyX963: Data
    public let phoneDeviceID: String
    public let phoneDeviceName: String
    public let phonePublicKeyX963: Data
    /// The phone's Face-ID-gated key-agreement key, which its signing key
    /// vouched for in the pairing code. The remote-unlock factor is wrapped
    /// to it.
    public let phoneKeyAgreementPublicKeyX963: Data
    public let cloudKitContainerIdentifier: String

    public init(
        macDeviceID: String,
        macDeviceName: String,
        macSigningKeyRepresentation: Data,
        macPublicKeyX963: Data,
        phoneDeviceID: String,
        phoneDeviceName: String,
        phonePublicKeyX963: Data,
        phoneKeyAgreementPublicKeyX963: Data,
        cloudKitContainerIdentifier: String
    ) {
        self.version = Self.currentVersion
        self.macDeviceID = macDeviceID.lowercased()
        self.macDeviceName = macDeviceName
        self.macSigningKeyRepresentation = macSigningKeyRepresentation
        self.macPublicKeyX963 = macPublicKeyX963
        self.phoneDeviceID = phoneDeviceID.lowercased()
        self.phoneDeviceName = phoneDeviceName
        self.phonePublicKeyX963 = phonePublicKeyX963
        self.phoneKeyAgreementPublicKeyX963 = phoneKeyAgreementPublicKeyX963
        self.cloudKitContainerIdentifier = cloudKitContainerIdentifier
    }

    public func validate() throws {
        guard version == Self.currentVersion,
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
        guard UUID(uuidString: phoneDeviceID) != nil, phoneDeviceID.utf8.count == 36 else {
            throw RemoteApprovalValidationError.invalidIdentifier
        }
        guard !phoneDeviceName.isEmpty,
              phoneDeviceName.utf8.count <= 256,
              !phoneDeviceName.utf8.contains(0) else {
            throw RemoteApprovalValidationError.fieldOutOfBounds
        }
        do {
            _ = try P256.Signing.PublicKey(x963Representation: phonePublicKeyX963)
            _ = try P256.KeyAgreement.PublicKey(x963Representation: phoneKeyAgreementPublicKeyX963)
        } catch {
            throw RemoteApprovalValidationError.invalidPublicKey
        }
    }

    /// Decode a stored record. One an older build wrote, which pinned no
    /// key-agreement key, throws `RemoteApprovalConfigurationStoreError
    /// .outdated` with the Mac device ID it names, so the pairing that
    /// replaces it can still withdraw its prompts; anything else that does not
    /// decode or validate throws as it is.
    public static func decodeStored(_ data: Data) throws -> StoredRemoteApprovalConfiguration {
        struct VersionProbe: Decodable {
            let version: UInt16?
            let macDeviceID: String?
        }
        if let probe = try? JSONDecoder().decode(VersionProbe.self, from: data),
           let version = probe.version, version < currentVersion {
            throw RemoteApprovalConfigurationStoreError.outdated(macDeviceID: probe.macDeviceID?.lowercased())
        }
        let configuration = try JSONDecoder().decode(StoredRemoteApprovalConfiguration.self, from: data)
        try configuration.validate()
        return configuration
    }
}

/// How a configuration store reports that it could not be read at all, as
/// opposed to holding a record that cannot be used.
public enum RemoteApprovalConfigurationStoreError: Error, Equatable, Sendable {
    /// The backing store refused the read (a Keychain `OSStatus`). Nothing is
    /// known about the record; reading again later can succeed.
    case unreadable(status: Int32)
    /// The record is a pairing an older build made, before the phone's
    /// key-agreement key was pinned. It is kept until `disable` or a new
    /// pairing replaces it; `macDeviceID` is the Mac ID it names, if any.
    case outdated(macDeviceID: String?)
}

public protocol RemoteApprovalConfigurationStore: Sendable {
    /// The pinned record, or nil when none exists. Throws
    /// `RemoteApprovalConfigurationStoreError.unreadable` when the store cannot
    /// be read right now; any other error means a record exists but cannot be
    /// decoded or validated.
    func load() async throws -> StoredRemoteApprovalConfiguration?
    func store(_ configuration: StoredRemoteApprovalConfiguration) async throws
    func delete() async throws
}

/// Code-identity-gated, non-interactive configuration storage. Public keys and
/// device names are not secrets; the Secure Enclave dataRepresentation is an
/// opaque handle, not private-key material. Local Touch ID is required by the
/// manager before this record is created, replaced, or deleted.
public struct SecurityRemoteApprovalConfigurationStore: RemoteApprovalConfigurationStore {
    public static let service = CSECBuildIdentity.named("remote-approval")
    private static let account = "pinned-phone-v1"

    private let queue = DispatchQueue(
        label: CSECBuildIdentity.named("remote-approval-keychain")
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
                return try StoredRemoteApprovalConfiguration.decodeStored(data)
            case errSecItemNotFound:
                return nil
            default:
                throw RemoteApprovalConfigurationStoreError.unreadable(status: status)
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

/// What is wrong with a pairing record that exists but cannot be used. None of
/// these clears by waiting: the fix is `csec remote disable`, then pairing
/// again.
public enum RemoteApprovalPairingProblem: String, Equatable, Sendable, CaseIterable {
    /// The record could not be decoded or failed validation.
    case recordCorrupt = "record_corrupt"
    /// The record names a CloudKit container other than the one this build uses.
    case containerMismatch = "container_mismatch"
    /// The Secure Enclave key the record points at cannot sign on this Mac:
    /// erased, never on this Mac, or no Secure Enclave at all.
    case macKeyMissing = "mac_key_missing"
    /// The Secure Enclave key signs, but it is not the key the phone pinned.
    case macKeyMismatch = "mac_key_mismatch"
    /// An older csec made this pairing, before the phone's key-agreement key
    /// was pinned: the phone must be paired again.
    case outdated
}

/// Whether iPhone remote approval can run, and if not, exactly why. Every case
/// is a bounded, value-free code that `csec remote status` and `csec doctor`
/// turn into advice specific to it.
public enum RemoteApprovalManagerStatus: Equatable, Sendable {
    /// No phone is paired.
    case disabled
    /// A phone is paired, the record and this Mac's key are usable, and this
    /// Mac's iCloud account is available.
    case enabled(phoneName: String, phoneKeyFingerprint: String)
    /// This csecd was signed without the CloudKit container entitlement, so it
    /// cannot reach the relay at all.
    case unsupportedBuild
    /// A phone is paired but this Mac's iCloud account cannot carry requests.
    case iCloudAccountUnavailable(
        RemoteApprovalAccountProblem,
        phoneName: String,
        phoneKeyFingerprint: String
    )
    /// A pairing record exists but cannot be used.
    case pairingInvalid(RemoteApprovalPairingProblem)
    /// The Keychain refused to read the pairing record just now. csecd reads
    /// it again on the next status check, request, or account change.
    case keychainUnavailable(status: Int32)
}

/// What `RemoteApprovalManager.enable` hands back to the person pairing.
public struct RemoteApprovalEnableResult: Equatable, Sendable {
    /// The public `csec-mac-v2:` code, always printed: the way to pair when
    /// the offer did not reach the phone.
    public let macPairingCode: String
    /// The same pairing was left in the mailbox for the pinned phone, whose
    /// app shows it on its own.
    public let pairingOfferPublished: Bool

    public init(macPairingCode: String, pairingOfferPublished: Bool) {
        self.macPairingCode = macPairingCode
        self.pairingOfferPublished = pairingOfferPublished
    }
}

/// What csecd knows about the paired phone beyond the pairing record: whether
/// the phone confirmed this pairing, what it last reported about itself, and
/// whether the phone-held unlock factor is enrolled. Diagnostics, except that
/// a settings review is offered only to a phone that shows it; a request is
/// verified on its own whatever these say.
public struct RemoteApprovalPairingHealth: Equatable, Sendable {
    /// The phone published a signed confirmation of exactly this pairing.
    public let confirmed: Bool
    /// From the phone's latest signed status record, when there is one.
    public let phoneAppVersion: String?
    public let notificationsAuthorized: Bool?
    /// Whether a request raises an alert on the phone; nil until the phone
    /// has reported it.
    public let requestAlerts: RemoteApprovalPhoneAlertState?
    /// A remote-unlock enrollment for this pairing exists.
    public let remoteUnlockEnrolled: Bool
    /// The protocol the phone app speaks, and when it wrote that status
    /// record (milliseconds since 1970, by the phone's clock).
    public let phoneProtocolVersion: UInt16?
    public let phoneStatusUpdatedAtMilliseconds: UInt64?
    /// Whether that record says the app shows settings reviews, which only
    /// then reach the phone (`remoteSettingsReadiness`).
    public let phoneShowsSettingsReviews: Bool?

    public init(
        confirmed: Bool,
        phoneAppVersion: String?,
        notificationsAuthorized: Bool?,
        requestAlerts: RemoteApprovalPhoneAlertState? = nil,
        remoteUnlockEnrolled: Bool,
        phoneProtocolVersion: UInt16? = nil,
        phoneStatusUpdatedAtMilliseconds: UInt64? = nil,
        phoneShowsSettingsReviews: Bool? = nil
    ) {
        self.confirmed = confirmed
        self.phoneAppVersion = phoneAppVersion
        self.notificationsAuthorized = notificationsAuthorized
        self.requestAlerts = requestAlerts
        self.remoteUnlockEnrolled = remoteUnlockEnrolled
        self.phoneProtocolVersion = phoneProtocolVersion
        self.phoneStatusUpdatedAtMilliseconds = phoneStatusUpdatedAtMilliseconds
        self.phoneShowsSettingsReviews = phoneShowsSettingsReviews
    }
}

/// Where the Mac's pairing key comes from. Shipping code uses the Secure
/// Enclave. The seam exists so the manager can be exercised with software keys;
/// it is constructor-injected only and never selectable at runtime.
public struct RemoteApprovalMacKeys: Sendable {
    public typealias Created = (
        signer: any RemoteApprovalRequestSigner,
        dataRepresentation: Data,
        publicKeyX963: Data
    )

    public let create: @Sendable () throws -> Created
    public let load: @Sendable (Data) throws -> any RemoteApprovalRequestSigner

    public init(
        create: @escaping @Sendable () throws -> Created,
        load: @escaping @Sendable (Data) throws -> any RemoteApprovalRequestSigner
    ) {
        self.create = create
        self.load = load
    }

    public static let secureEnclave = RemoteApprovalMacKeys(
        create: {
            let material = try SecureEnclaveRemoteApprovalSigner.create()
            return (material.signer, material.dataRepresentation, material.publicKeyX963)
        },
        load: { try SecureEnclaveRemoteApprovalSigner(dataRepresentation: $0) }
    )
}

/// Owns the dynamic opt-in state. The mirrored policy reviewer can be installed
/// unconditionally: until a usable pinned record exists this provider returns
/// `.unavailable` immediately and the unchanged local Touch ID path continues.
///
/// Readiness is honest and specific (`RemoteApprovalManagerStatus`), logged
/// once per change, and re-checked where it can change: a Keychain that refused
/// a read and the iCloud account are read again on a status check, on a
/// request, and when the account changes. Nothing here ever deletes or replaces
/// the pinned record except `enable` and `disable`, each behind Touch ID.
public actor RemoteApprovalManager: RemoteAccessPolicyReviewProvider {
    private enum Readiness {
        /// `prepare()` has not run yet.
        case unprepared
        case unsupportedBuild
        case disabled
        case keychainUnavailable(status: Int32)
        /// `macDeviceID` is known when the record decoded, so a replacement
        /// pairing can still withdraw that Mac ID's prompts.
        case pairingInvalid(RemoteApprovalPairingProblem, macDeviceID: String?, diagnostic: String?)
        case paired(Pairing)
    }

    private struct Pairing {
        let configuration: StoredRemoteApprovalConfiguration
        let requester: RemoteApprovalRequester
        /// Nil until the first account check after the pairing loaded.
        var account: RemoteApprovalAccountStatus?
        /// Set once the phone's signed confirmation of this pairing verified.
        var confirmed = false
        /// The phone's latest verified status record.
        var phoneStatus: RemoteApprovalPhoneStatus?
    }

    private struct PairingFailure: Error {
        let problem: RemoteApprovalPairingProblem
        var diagnostic: String?
    }

    /// Signed with the pairing key to prove it still works. A raw ASCII string
    /// can never equal a canonical request encoding, which starts with a
    /// four-byte length prefix, and the signature is discarded on the spot.
    private static let macKeyProbe = Data("csec.remote-approval.mac-key-probe.v1".utf8)

    private let store: any RemoteApprovalConfigurationStore
    private let relay: any RemoteApprovalRelay
    private let consent: any ConsentProvider
    private let cloudKitContainerIdentifier: String
    private let relayIsConfigured: Bool
    private let accountStatus: @Sendable () async -> RemoteApprovalAccountStatus
    private let macKeys: RemoteApprovalMacKeys
    private let log: @Sendable (String) -> Void
    /// The phone-held unlock factor's storage: the enrollment a request's
    /// blinded challenge comes from, and what opens the remote unlock an
    /// approval's answer carries. Nil where csecd keeps no remote-unlock items.
    private let remoteUnlock: RemoteUnlockStore?
    /// Which references need an unlock and which of those a remote unlock
    /// covers, from the owning providers, with a review's restore references
    /// judged as a restore reopens them (`SecretResolver.remoteUnlockCoverage`).
    /// Nil makes every review Mac-only: readiness cannot be judged without it.
    private let coverage: (@Sendable (RemoteUnlockCoverageRequest) async -> RemoteUnlockCoverage)?
    /// Seals a copy of every existing native key record and cache entry to a
    /// new enrollment, reading them with the one local context `enable`
    /// spent (`SecretResolver.backfillRemoteUnlockMirrors`).
    private let backfill: (@Sendable (CacheUnlock) async -> RemoteUnlockBackfillReport)?
    /// When a mirrored request alerts the phone; csecd passes
    /// `RemoteApprovalAlertTiming.live`.
    private let alertGate: RemoteApprovalAlertGate
    /// Mailbox cleanup that has not landed yet — exchange deletes, sweeps,
    /// offer withdrawals — retried until it does, across every requester this
    /// manager makes, so a replaced pairing's cleanup outlives its requester.
    private let cleanup: RemoteApprovalCleanupQueue

    private var readiness: Readiness = .unprepared
    /// Bumped whenever `readiness` is replaced, so a read that was in flight
    /// while `enable` or `disable` changed the pairing does not overwrite it.
    private var generation: UInt64 = 0
    private var preparation: Task<Void, Never>?
    private var loggedStatus: RemoteApprovalManagerStatus?
    /// A background read of the phone's facts started by a settings review
    /// the phone's status did not cover (`remoteSettingsReadiness`).
    private var phoneFactsRefresh: Task<Void, Never>?

    public init(
        store: any RemoteApprovalConfigurationStore,
        relay: any RemoteApprovalRelay,
        consent: any ConsentProvider,
        cloudKitContainerIdentifier: String,
        relayIsConfigured: Bool = true,
        accountStatus: @escaping @Sendable () async -> RemoteApprovalAccountStatus = { .available },
        macKeys: RemoteApprovalMacKeys = .secureEnclave,
        remoteUnlock: RemoteUnlockStore? = nil,
        coverage: (@Sendable (RemoteUnlockCoverageRequest) async -> RemoteUnlockCoverage)? = nil,
        backfill: (@Sendable (CacheUnlock) async -> RemoteUnlockBackfillReport)? = nil,
        alertGate: @escaping RemoteApprovalAlertGate = {},
        cleanup: RemoteApprovalCleanupQueue = RemoteApprovalCleanupQueue(),
        log: @escaping @Sendable (String) -> Void = { line in
            FileHandle.standardError.write(Data("\(line)\n".utf8))
        }
    ) {
        self.store = store
        self.relay = relay
        self.consent = consent
        self.cloudKitContainerIdentifier = cloudKitContainerIdentifier
        self.relayIsConfigured = relayIsConfigured
        self.accountStatus = accountStatus
        self.macKeys = macKeys
        self.remoteUnlock = remoteUnlock
        self.coverage = coverage
        self.backfill = backfill
        self.alertGate = alertGate
        self.cleanup = cleanup
        self.log = log
    }

    /// Read the pinned record and make it usable. Local only (the Keychain and
    /// the Secure Enclave): csecd awaits this before it serves, so the iCloud
    /// account check and the stale-prompt sweep run in the background.
    public func prepare() async {
        if let preparation {
            await preparation.value
            return
        }
        let task = Task { await self.loadAndApply() }
        preparation = task
        await task.value
        preparation = nil
    }

    public func status() async -> RemoteApprovalManagerStatus {
        await refresh()
        return currentStatus()
    }

    /// The paired phone's confirmation, its latest status and the unlock
    /// enrollment, read from the relay (each read bounded) and the Keychain.
    /// Nil when no usable pairing exists. The CLI polls this after `enable`
    /// until the phone confirms, so it is also what notices the confirmation.
    public func pairingHealth() async -> RemoteApprovalPairingHealth? {
        await refresh()
        guard case let .paired(pairing) = readiness else { return nil }
        if pairing.account == .available {
            await refreshPhoneFacts()
        }
        guard case let .paired(current) = readiness else { return nil }
        return RemoteApprovalPairingHealth(
            confirmed: current.confirmed,
            phoneAppVersion: current.phoneStatus.map { ReviewDisplay.sanitized($0.appVersion) },
            notificationsAuthorized: current.phoneStatus?.notificationsAuthorized,
            requestAlerts: current.phoneStatus?.requestAlerts,
            remoteUnlockEnrolled: await enrollment(matching: current.configuration) != nil,
            phoneProtocolVersion: current.phoneStatus?.protocolVersion,
            phoneStatusUpdatedAtMilliseconds: current.phoneStatus?.updatedAtMilliseconds,
            phoneShowsSettingsReviews: current.phoneStatus?.shows(.settings)
        )
    }

    /// The iCloud account changed (`CKAccountChanged`): a sign-in or sign-out
    /// changes readiness, and a Keychain read or mailbox cleanup that failed
    /// is worth retrying.
    public func accountDidChange() async {
        await cleanup.retryNow()
        await refresh()
    }

    /// Pin or replace one phone after a fresh local biometric, in csecd's
    /// settings panel naming the tab `caller` runs in. Returns the Mac's
    /// public pairing code for biometric-gated import by the phone app, and
    /// whether the same pairing was also offered to that phone through the
    /// mailbox, where its app finds it without the code being pasted.
    /// Replacing a pairing revokes every request the old one has in flight.
    public func enable(
        phonePairingCode: String,
        caller: CallerInfo
    ) async throws -> RemoteApprovalEnableResult {
        let phone = try RemoteApprovalPairingCode.decodePhone(phonePairingCode)
        guard relayIsConfigured else { throw RemoteApprovalManagerError.unsupportedBuild }
        if case let .unavailable(problem) = await accountStatus() {
            throw RemoteApprovalManagerError.iCloudAccountUnavailable(problem)
        }
        // Sanitizing can only grow a name (a control byte becomes a three-byte
        // U+FFFD), so the pinned name is bounded after it: a name that passed
        // the code's own 256-byte check could otherwise fail the record's,
        // after the Touch ID.
        let safeName = ReviewDisplay.fitted(
            phone.phoneDeviceName, maxBytes: Self.maximumDeviceNameBytes
        )
        let fingerprint = RemoteApprovalPairingCode.publicKeyFingerprint(
            phone.phonePublicKeyX963
        )
        let auth = await consent.approveSettingsChange(
            SettingsChangeReviewDetails(
                title: "Pair an iPhone for Remote Approval",
                changes: [
                    "Pair \(safeName) (key \(fingerprint)) for remote approval",
                    "Its Face ID will approve requests and open csec's stored secrets on this Mac",
                ]
            ),
            caller: caller
        )
        guard auth.isApproved else { throw RemoteApprovalManagerError.denied }
        // The one Touch ID also reads every existing key record and cache
        // entry to seal their remote-unlock copies; it authorizes nothing
        // after this call.
        defer { auth.unlock?.invalidate() }

        let material = try macKeys.create()
        let hostName = ReviewDisplay.fitted(
            Host.current().localizedName ?? "", maxBytes: Self.maximumDeviceNameBytes
        )
        let stored = StoredRemoteApprovalConfiguration(
            macDeviceID: UUID().uuidString.lowercased(),
            macDeviceName: hostName.isEmpty ? "Mac" : hostName,
            macSigningKeyRepresentation: material.dataRepresentation,
            macPublicKeyX963: material.publicKeyX963,
            phoneDeviceID: phone.phoneDeviceID,
            phoneDeviceName: safeName,
            phonePublicKeyX963: phone.phonePublicKeyX963,
            phoneKeyAgreementPublicKeyX963: phone.phoneKeyAgreementPublicKeyX963,
            cloudKitContainerIdentifier: cloudKitContainerIdentifier
        )
        let preparedRequester: RemoteApprovalRequester
        do {
            preparedRequester = try await makeRequester(for: stored, signer: material.signer)
        } catch {
            throw RemoteApprovalManagerError.invalidConfiguration
        }
        // Enroll the phone-held unlock factor before the pairing is stored, so
        // a pairing never exists half-enrolled: either both land or neither.
        // Enrolling replaces any earlier enrollment and its copies.
        if let remoteUnlock {
            do {
                _ = try await remoteUnlock.enroll(
                    phoneKeyAgreementPublicKeyX963: stored.phoneKeyAgreementPublicKeyX963,
                    macDeviceID: stored.macDeviceID,
                    phoneDeviceID: stored.phoneDeviceID
                )
            } catch {
                log("csecd: remote approval was not paired: the remote-unlock factor could not be "
                    + "enrolled (\(Self.unlockFailureCode(error))).")
                throw RemoteApprovalManagerError.remoteUnlockUnavailable
            }
            if let backfill, let local = auth.unlock, local.isLocal {
                let report = await backfill(local)
                log("csecd: remote unlock: sealed \(report.mirrored) stored item(s) for the phone"
                    + (report.failed > 0 ? "; \(report.failed) could not be sealed now and will be when next opened here." : "."))
            }
        }
        do {
            try await store.store(stored)
        } catch {
            await restoreUnlock(afterFailedPairing: error, local: auth.unlock)
            throw error
        }
        let previous = readiness
        replaceReadiness(with: .paired(Pairing(
            configuration: stored, requester: preparedRequester, account: .available
        )))
        await retire(previous, replacedBy: stored)

        let macPairing = RemoteApprovalMacPairing(
            macDeviceID: stored.macDeviceID,
            macDeviceName: stored.macDeviceName,
            macPublicKeyX963: stored.macPublicKeyX963,
            cloudKitContainerIdentifier: stored.cloudKitContainerIdentifier
        )
        let code = try RemoteApprovalPairingCode.encodeMac(macPairing)
        let offered = await offerPairing(
            macPairing, to: stored, signer: material.signer, replacing: previous
        )
        return RemoteApprovalEnableResult(macPairingCode: code, pairingOfferPublished: offered)
    }

    /// The new pairing could not be saved after its unlock factor was
    /// enrolled, which replaced any earlier enrollment and its copies. A
    /// pairing kept from before gets its factor back: it is enrolled again for
    /// that pairing's phone (the phone takes no part: its key-agreement key is
    /// all enrolling needs) and its copies sealed again, with the same Touch
    /// ID, which is still valid here. Otherwise, or when that fails, what this
    /// attempt enrolled goes too, and the kept pairing reads as not enrolled
    /// (`pairingHealth`) until the phone is paired again.
    private func restoreUnlock(afterFailedPairing error: Error, local: CacheUnlock?) async {
        guard let remoteUnlock else { return }
        guard case let .paired(kept) = readiness else {
            try? await remoteUnlock.removeAllRemoteUnlockState()
            return
        }
        let cause = "the new pairing could not be saved (\(type(of: error)))"
        do {
            _ = try await remoteUnlock.enroll(
                phoneKeyAgreementPublicKeyX963: kept.configuration.phoneKeyAgreementPublicKeyX963,
                macDeviceID: kept.configuration.macDeviceID,
                phoneDeviceID: kept.configuration.phoneDeviceID
            )
        } catch let enrollError {
            try? await remoteUnlock.removeAllRemoteUnlockState()
            log("csecd: remote approval was not re-paired: \(cause). The phone paired before stays paired, "
                + "but enrolling the new one replaced its phone-held unlock, which could not be enrolled again "
                + "(\(Self.unlockFailureCode(enrollError))): pair again to enroll it.")
            return
        }
        if let backfill, let local, local.isLocal {
            _ = await backfill(local)
        }
        log("csecd: remote approval was not re-paired: \(cause). The phone paired before stays paired, "
            + "with its phone-held unlock enrolled again.")
    }

    /// Leave the Mac code for the pinned phone in the mailbox, so its app shows
    /// this Mac without the code being copied back by hand. Bounded and
    /// best-effort: the printed code remains the way to pair when this fails.
    /// The offer replaces an earlier pairing's offer to the same phone; when it
    /// cannot be published, that earlier offer is withdrawn instead, so the
    /// phone never offers a Mac key csecd no longer signs with.
    private func offerPairing(
        _ macPairing: RemoteApprovalMacPairing,
        to stored: StoredRemoteApprovalConfiguration,
        signer: any RemoteApprovalRequestSigner,
        replacing previous: Readiness
    ) async -> Bool {
        let offer = RemoteApprovalPairingOffer(
            mac: macPairing,
            phoneDeviceID: stored.phoneDeviceID,
            phonePublicKeyX963: stored.phonePublicKeyX963,
            phoneKeyAgreementPublicKeyX963: stored.phoneKeyAgreementPublicKeyX963,
            createdAtMilliseconds: currentTimeMilliseconds()
        )
        let relay = self.relay
        let published = await RemoteApprovalBound.firstAnswer(
            within: RemoteApprovalBound.readNanoseconds,
            otherwise: false
        ) {
            do {
                try await relay.publishPairingOffer(
                    try await SignedRemoteApprovalPairingOffer.signed(offer, by: signer)
                )
                return true
            } catch {
                return false
            }
        }
        guard !published else { return true }
        log("csecd: the pairing was not offered to the iPhone through iCloud; "
            + "pair with the printed Mac code instead.")
        if case let .paired(old) = previous,
           old.configuration.phoneDeviceID == stored.phoneDeviceID {
            withdrawOffer(phoneDeviceID: stored.phoneDeviceID, macDeviceID: old.configuration.macDeviceID)
        }
        return false
    }

    /// Remove the pinned phone after a fresh local biometric, in csecd's
    /// settings panel naming the tab `caller` runs in, revoking every request
    /// in flight so a later phone decision is refused. The Touch ID is asked
    /// for only when there is a record to remove.
    public func disable(caller: CallerInfo) async throws {
        await retryIfTransient()
        switch readiness {
        case .unprepared, .disabled:
            return
        case .unsupportedBuild:
            // This build never reads the record for itself, so look now: one
            // left by an earlier build is worth a Touch ID to remove, an empty
            // Keychain is not.
            guard await pairingRecordMayExist() else { return }
        case .keychainUnavailable, .pairingInvalid, .paired:
            break
        }
        let auth = await consent.approveSettingsChange(
            SettingsChangeReviewDetails(
                title: "Turn Off iPhone Remote Approval",
                changes: ["Unpair \(Self.pairedPhoneName(readiness) ?? "the paired iPhone"): it will no longer approve requests "
                    + "or open csec's stored secrets"]
            ),
            caller: caller
        )
        guard auth.isApproved else { throw RemoteApprovalManagerError.denied }
        auth.unlock?.invalidate()
        try await store.delete()
        let previous = readiness
        replaceReadiness(with: relayIsConfigured ? .disabled : .unsupportedBuild)
        await retire(previous, replacedBy: nil)
        await removeRemoteUnlockState(reason: "the pairing was removed")
    }

    /// Delete the phone-held unlock factor's enrollment, its epoch and every
    /// sealed copy. Without a pairing nothing requests them, but they should
    /// not outlive it. This runs whether or not an enrollment is found: a
    /// removal that deleted the enrollment but not every copy leaves copies
    /// no enrollment names (they can never open again), and every start with
    /// no phone paired sweeps them. A failure is logged and retried then.
    private func removeRemoteUnlockState(reason: String) async {
        guard let remoteUnlock else { return }
        do {
            try await remoteUnlock.removeAllRemoteUnlockState()
        } catch {
            log("csecd: remote unlock: \(reason), but its sealed copies could not all be deleted "
                + "(\(Self.unlockFailureCode(error))); csecd tries again at its next start.")
        }
    }

    /// Ready only with a usable pairing whose iCloud account can carry a
    /// request, and then exactly when a phone approval could carry out the
    /// review: no reference needs an unlock, or every one that does is covered
    /// by the phone-held unlock factor enrolled for this pairing, and no value
    /// would wait on its provider's own prompt at the Mac (one whose cached
    /// copy the unlock opens makes that unlock required). `restoring`
    /// (a restore section's references) is judged as the restore reopens it,
    /// from local sealed state only. Local reads only (the Keychain record,
    /// the providers' and the cache's state, remote-unlock item attributes);
    /// never relay IO, never a prompt, never a value out.
    public func remoteReadiness(
        for references: [SecretRef],
        restoring: [SecretRef]
    ) async -> RemoteReviewReadiness {
        guard let pairing = await usablePairing() else { return .unavailable }
        // A review that names no reference (one sudo authentication) releases
        // nothing and opens nothing.
        if references.isEmpty, restoring.isEmpty { return .ready(unlock: .notNeeded) }
        guard let coverage else { return .unavailable }
        let covered = await coverage(RemoteUnlockCoverageRequest(references: references, restoring: restoring))
        let enrolled = await enrollment(matching: pairing.configuration) != nil
        // A value whose provider would prompt at the Mac waits on that
        // prompt, so a phone approval could only time out: the phone is not
        // offered one, unless the unlock opens a cached copy of every such
        // value, which the approval then must carry.
        if !covered.unattendable.isEmpty
            || (!covered.needsAttendance.isEmpty && !enrolled) {
            log("csecd: this request stays on the Mac; a provider would first have to authorize "
                + "at the Mac for \(covered.needsAttendance.count) of its references, which a phone "
                + "approval cannot answer.")
            return .unavailable
        }
        if covered.needsUnlock.isEmpty {
            if !covered.needsAttendance.isEmpty { return .ready(unlock: .required) }
            // Every value can be fetched without the unlock; a cached copy it
            // opens is read first when this pairing has the factor enrolled.
            return .ready(unlock: enrolled && !covered.cachedRemotely.isEmpty ? .preferred : .notNeeded)
        }
        guard covered.isComplete, enrolled else { return .unavailable }
        return .ready(unlock: .required)
    }

    /// Ready, needing no unlock, when the paired phone's latest verified
    /// status says it shows settings reviews. An app that predates them drops
    /// one unread, so a request this Mac's locked screen hid would wait on
    /// nobody; until the status lists them the change stays on this Mac. A
    /// status that does not is read again in the background, so the next
    /// request sees an updated app once it has signed its status. Never waits
    /// on the relay.
    public func remoteSettingsReadiness() async -> RemoteReviewReadiness {
        guard let pairing = await usablePairing() else { return .unavailable }
        guard pairing.phoneStatus?.shows(.settings) == true else {
            if phoneFactsRefresh == nil {
                phoneFactsRefresh = Task {
                    await self.refreshPhoneFacts()
                    self.phoneFactsRefresh = nil
                }
            }
            return .unavailable
        }
        return .ready(unlock: .notNeeded)
    }

    public func reviewRemoteAccess(
        _ review: RemoteApprovalReview,
        unlock use: RemoteUnlockUse
    ) async -> RemoteAccessReviewResult {
        guard let pairing = await usablePairing() else { return .unavailable }
        let required = use == .required
        let withoutUnlock = { RemoteAccessReviewResult(await pairing.requester.requestApproval(for: review)) }
        guard use != .notNeeded else { return await withoutUnlock() }
        // A fresh blinding of the enrollment for this request alone: the
        // scalar stays here, the blinded point goes into the signed request.
        guard let remoteUnlock,
              await enrollment(matching: pairing.configuration) != nil else {
            return required ? .unavailable : await withoutUnlock()
        }
        let blinded: (challenge: RemoteUnlockCrypto.Challenge, enrollmentID: String)
        do {
            blinded = try await remoteUnlock.challenge()
        } catch {
            guard required else {
                log("csecd: the remote-unlock challenge could not be made "
                    + "(\(Self.unlockFailureCode(error))); a phone approval asks the provider for the values.")
                return await withoutUnlock()
            }
            log("csecd: this request stays on the Mac; the remote-unlock challenge could not be "
                + "made (\(Self.unlockFailureCode(error))).")
            return .unavailable
        }
        let result = await pairing.requester.requestApproval(
            for: review,
            unlockChallenge: RemoteApprovalUnlockChallenge(
                enrollmentID: blinded.enrollmentID, blindedPoint: blinded.challenge.blindedPoint
            )
        )
        guard case let .approved(selection) = result else { return RemoteAccessReviewResult(result) }
        // The pinned phone signed this approval; the unlock only reaches
        // cached copies. With `.preferred` every value can still come from its
        // provider, so an approval whose unlock does not open stands.
        let withoutOpening = RemoteAccessReviewResult.approved(selection: selection.withoutUnlockAnswer, unlock: nil)
        // The requester accepted this approval only with a well-formed answer
        // to this request's challenge; whether it opens is the unwrap's to say.
        guard let answer = selection.unlockAnswer else { return required ? .unavailable : withoutOpening }
        do {
            let unlock = try await remoteUnlock.openRemoteUnlock(
                challenge: blinded.challenge, answer: answer, enrollmentID: blinded.enrollmentID
            )
            if Task.isCancelled {
                // The local prompt won meanwhile: nobody will use this unlock.
                unlock.invalidate()
                return .unavailable
            }
            return .approved(selection: selection.withoutUnlockAnswer, unlock: unlock)
        } catch {
            guard required else {
                log("csecd: a phone approval's unlock answer did not open the remote-unlock key "
                    + "(\(Self.unlockFailureCode(error))); the approval stands and the provider is asked "
                    + "for the values.")
                return withoutOpening
            }
            // An answer from another key or a replaced enrollment: no phone
            // decision the Mac can act on. The phone's request is already
            // withdrawn; the local prompt still carries this one.
            log("csecd: a phone approval's unlock answer did not open the remote-unlock key "
                + "(\(Self.unlockFailureCode(error))); the request stays on the Mac.")
            return .unavailable
        }
    }

    /// The pairing a request may use now, or nil: not paired, or this Mac's
    /// iCloud account was unusable when last checked. A request is when remote
    /// approval is wanted, so a Keychain that refused the record earlier is
    /// asked again here. That read is local, never relay IO.
    private func usablePairing() async -> Pairing? {
        await retryIfTransient()
        guard case let .paired(pairing) = readiness else { return nil }
        if case let .unavailable(problem)? = pairing.account, !problem.isTransient {
            // Signed out or restricted when last checked: publishing would only
            // fail. Check again in the background so a sign-in is seen by the
            // next request without holding this one on relay IO.
            Task { await self.refreshAccount() }
            return nil
        }
        return pairing
    }

    /// The remote-unlock enrollment, when it belongs to exactly this pairing:
    /// this Mac ID, the pinned phone, and the key-agreement key it pinned. An
    /// enrollment left by an earlier pairing could never open, so it would
    /// only spend the phone's Face ID on nothing.
    private func enrollment(
        matching configuration: StoredRemoteApprovalConfiguration
    ) async -> RemoteUnlockEnrollmentRecord? {
        guard let record = await remoteUnlock?.enrollment(),
              record.macDeviceID == configuration.macDeviceID,
              record.phoneDeviceID == configuration.phoneDeviceID,
              record.enrollment.phoneKeyAgreementPublicKey == configuration.phoneKeyAgreementPublicKeyX963
        else { return nil }
        return record
    }

    /// A value-free code for why a remote unlock did not open.
    private static func unlockFailureCode(_ error: Error) -> String {
        if let failure = error as? RemoteUnlockCrypto.Failure { return "\(failure)" }
        if let failure = error as? RemoteUnlockStoreError {
            switch failure {
            case .notEnrolled: return "not_enrolled"
            case .enrollmentUnreadable: return "enrollment_unreadable"
            case .invalidEnrollment: return "invalid_enrollment"
            case .enrollmentMismatch: return "enrollment_replaced"
            case .unlockInvalidated: return "unlock_invalidated"
            case .mirrorUnreadable: return "mirror_unreadable"
            case .staleMirrorMayRemain: return "stale_mirror"
            case .removalIncomplete: return "removal_incomplete"
            case .keychain: return "keychain"
            }
        }
        return "\(type(of: error))"
    }

    // MARK: - Readiness

    private static let maximumDeviceNameBytes = 256

    private func refresh() async {
        await retryIfTransient()
        if case .paired = readiness { await refreshAccount() }
    }

    /// Re-read the record when the last read failed for a reason that can
    /// clear by itself. A usable or unusable record is never re-read: nothing
    /// but `enable` or `disable` changes it.
    private func retryIfTransient() async {
        switch readiness {
        case .unprepared, .keychainUnavailable: await prepare()
        default: break
        }
    }

    private func loadAndApply() async {
        let started = generation
        let loaded = await loadReadiness()
        // `enable` or `disable` replaced the pairing while this read was in
        // flight: theirs is newer than what this read saw.
        guard generation == started else { return }
        if case let .paired(current) = readiness {
            switch loaded {
            case let .paired(next) where current.configuration == next.configuration:
                // Same pinning: keep the requester, and with it every request
                // in flight and the account already checked.
                return
            case .keychainUnavailable:
                // A refused read is no evidence the record changed; a working
                // pairing is not torn down, nor its requests revoked, for it.
                return
            default:
                break
            }
        }
        let previous = readiness
        replaceReadiness(with: loaded)
        if case .disabled = loaded {
            await removeRemoteUnlockState(reason: "no phone is paired")
        }
        if case let .paired(next) = loaded {
            await retire(previous, replacedBy: next.configuration)
            Task { await self.refreshAccount() }
        } else {
            await retire(previous, replacedBy: nil)
        }
    }

    private func loadReadiness() async -> Readiness {
        guard relayIsConfigured else { return .unsupportedBuild }
        let stored: StoredRemoteApprovalConfiguration?
        do {
            stored = try await store.load()
        } catch let RemoteApprovalConfigurationStoreError.unreadable(status) {
            return .keychainUnavailable(status: status)
        } catch let RemoteApprovalConfigurationStoreError.outdated(macDeviceID) {
            return .pairingInvalid(.outdated, macDeviceID: macDeviceID, diagnostic: nil)
        } catch {
            return .pairingInvalid(
                .recordCorrupt, macDeviceID: nil, diagnostic: "\(type(of: error))"
            )
        }
        guard let stored else { return .disabled }
        do {
            let requester = try await makeRequester(for: stored)
            return .paired(Pairing(configuration: stored, requester: requester, account: nil))
        } catch let failure as PairingFailure {
            return .pairingInvalid(
                failure.problem, macDeviceID: stored.macDeviceID, diagnostic: failure.diagnostic
            )
        } catch {
            return .pairingInvalid(
                .recordCorrupt, macDeviceID: stored.macDeviceID, diagnostic: "\(type(of: error))"
            )
        }
    }

    /// Check the iCloud account for the current pairing. The first time it is
    /// available — at startup, or after a sign-in — the prompts this Mac left
    /// behind are swept, detached: a crash or restart is the one way a prompt
    /// can be left on the phone with nobody waiting for the answer.
    private func refreshAccount() async {
        guard case let .paired(checked) = readiness else { return }
        let account = await accountStatus()
        guard case var .paired(current) = readiness,
              current.requester === checked.requester else { return }
        let previous = current.account
        current.account = account
        readiness = .paired(current)
        logIfChanged()
        if account == .available, previous != .available {
            let requester = current.requester
            Task.detached(priority: .utility) {
                await requester.withdrawStaleRequests()
            }
            Task { await self.refreshPhoneFacts() }
        }
    }

    /// Read the phone's confirmation of this pairing (until one verifies) and
    /// its latest status record from the relay, each bounded, and keep what
    /// verifies against the pinned phone. Relay trouble leaves both as they
    /// were. They are never authorization: the status decides only whether a
    /// settings review is offered to the phone, and every answer is verified
    /// on its own. Refreshes can overlap, so a slower one never replaces a
    /// newer status or a confirmation another one kept.
    private func refreshPhoneFacts() async {
        guard case let .paired(checked) = readiness else { return }
        let configuration = checked.configuration
        let relay = self.relay
        var confirmed = checked.confirmed
        if !confirmed {
            let confirmation = await RemoteApprovalBound.firstAnswer(
                within: RemoteApprovalBound.readNanoseconds,
                otherwise: SignedRemoteApprovalPairingConfirmation?.none
            ) {
                try? await relay.pairingConfirmation(macDeviceID: configuration.macDeviceID)
            }
            if let confirmation {
                do {
                    try confirmation.verify(
                        macDeviceID: configuration.macDeviceID,
                        macPublicKeyX963: configuration.macPublicKeyX963,
                        phoneDeviceID: configuration.phoneDeviceID,
                        phonePublicKeyX963: configuration.phonePublicKeyX963,
                        phoneKeyAgreementPublicKeyX963: configuration.phoneKeyAgreementPublicKeyX963
                    )
                    confirmed = true
                    // The phone has pinned this Mac, so its offer has done
                    // its job. This also runs once per csecd start, which
                    // sweeps an offer an earlier withdrawal left behind.
                    withdrawOffer(phoneDeviceID: configuration.phoneDeviceID, macDeviceID: configuration.macDeviceID)
                } catch {
                    log("csecd: a pairing confirmation in the relay does not match this pairing; "
                        + "ignored.")
                }
            }
        }
        let status = await RemoteApprovalBound.firstAnswer(
            within: RemoteApprovalBound.readNanoseconds,
            otherwise: SignedRemoteApprovalPhoneStatus?.none
        ) {
            try? await relay.phoneStatus(phoneDeviceID: configuration.phoneDeviceID)
        }
        guard case var .paired(current) = readiness,
              current.requester === checked.requester else { return }
        current.confirmed = current.confirmed || confirmed
        if let status,
           (try? status.verify(
                phoneDeviceID: configuration.phoneDeviceID,
                phonePublicKeyX963: configuration.phonePublicKeyX963
           )) != nil,
           status.status.updatedAtMilliseconds >= (current.phoneStatus?.updatedAtMilliseconds ?? 0) {
            current.phoneStatus = status.status
        }
        readiness = .paired(current)
    }

    private func replaceReadiness(with next: Readiness) {
        generation &+= 1
        readiness = next
        logIfChanged()
    }

    /// End what a replaced or removed pairing still has open. Its requests in
    /// flight are revoked before this returns, so a phone decision for them is
    /// refused from here on; its prompts, and any a crash left behind under
    /// that Mac ID, are withdrawn from the mailbox in the background.
    /// The retired pairing's offer to its phone is withdrawn too, unless the
    /// new pairing is with the same phone: its own offer replaces that one
    /// (`offerPairing`).
    private func retire(
        _ previous: Readiness,
        replacedBy next: StoredRemoteApprovalConfiguration?
    ) async {
        let retiredMacDeviceID: String?
        // The retired pairing's Mac key and phone, when its record was read:
        // the sweep then withdraws only prompts that key signed, and the
        // phone's response records with them.
        var retiredMacPublicKey: Data?
        var retiredPhoneDeviceID: String?
        switch previous {
        case let .paired(pairing):
            await pairing.requester.revokeAll()
            retiredMacDeviceID = pairing.configuration.macDeviceID
            retiredMacPublicKey = pairing.configuration.macPublicKeyX963
            retiredPhoneDeviceID = pairing.configuration.phoneDeviceID
        case let .pairingInvalid(_, identifier, _):
            retiredMacDeviceID = identifier
        case .unprepared, .unsupportedBuild, .disabled, .keychainUnavailable:
            retiredMacDeviceID = nil
        }
        guard relayIsConfigured, let retiredMacDeviceID,
              retiredMacDeviceID != next?.macDeviceID.lowercased() else { return }
        let relay = self.relay
        let cleanup = self.cleanup
        let macPublicKey = retiredMacPublicKey
        let phoneDeviceID = retiredPhoneDeviceID
        Task.detached(priority: .utility) {
            await cleanup.run("retired-requests-\(retiredMacDeviceID)") {
                await RemoteApprovalRequester.withdrawRequests(
                    fromMacDeviceID: retiredMacDeviceID,
                    macPublicKeyX963: macPublicKey,
                    phoneDeviceID: phoneDeviceID,
                    relay: relay
                )
            }
        }
        if let phoneDeviceID, phoneDeviceID != next?.phoneDeviceID {
            withdrawOffer(phoneDeviceID: phoneDeviceID, macDeviceID: retiredMacDeviceID)
        }
    }

    /// Withdraw `macDeviceID`'s pairing offer to `phoneDeviceID`, in the
    /// background, retried until it lands: an offer left behind keeps showing
    /// on the phone as a Mac asking to pair.
    private func withdrawOffer(phoneDeviceID: String, macDeviceID: String) {
        let relay = self.relay
        let cleanup = self.cleanup
        Task.detached(priority: .utility) {
            await cleanup.run("pairing-offer-\(phoneDeviceID)-\(macDeviceID)") {
                (try? await relay.withdrawPairingOffer(phoneDeviceID: phoneDeviceID, macDeviceID: macDeviceID)) != nil
            }
        }
    }

    private func pairingRecordMayExist() async -> Bool {
        do {
            return try await store.load() != nil
        } catch {
            // Unreadable or undecodable: a failed read is no evidence that
            // nothing is there.
            return true
        }
    }

    private func currentStatus() -> RemoteApprovalManagerStatus {
        switch readiness {
        case .unprepared, .disabled:
            // `.unprepared` is never returned by `status()`, which prepares
            // first.
            return .disabled
        case .unsupportedBuild:
            return .unsupportedBuild
        case let .keychainUnavailable(status):
            return .keychainUnavailable(status: status)
        case let .pairingInvalid(problem, _, _):
            return .pairingInvalid(problem)
        case let .paired(pairing):
            let name = ReviewDisplay.sanitized(pairing.configuration.phoneDeviceName)
            let fingerprint = RemoteApprovalPairingCode.publicKeyFingerprint(
                pairing.configuration.phonePublicKeyX963
            )
            if case let .unavailable(problem)? = pairing.account {
                return .iCloudAccountUnavailable(
                    problem, phoneName: name, phoneKeyFingerprint: fingerprint
                )
            }
            return .enabled(phoneName: name, phoneKeyFingerprint: fingerprint)
        }
    }

    /// One line per change of readiness, value-free: codes, an `OSStatus`, an
    /// error's type, and the phone key's public fingerprint.
    private func logIfChanged() {
        // A freshly loaded pairing is reported once its account is checked.
        if case let .paired(pairing) = readiness, pairing.account == nil { return }
        let status = currentStatus()
        guard status != loggedStatus else { return }
        loggedStatus = status
        var diagnostic: String?
        if case let .pairingInvalid(_, _, detail) = readiness { diagnostic = detail }
        log(Self.logLine(for: status, diagnostic: diagnostic))
    }

    static func logLine(for status: RemoteApprovalManagerStatus, diagnostic: String?) -> String {
        let prefix = "csecd: iPhone remote approval"
        switch status {
        case .disabled:
            return "\(prefix) off (no phone paired)."
        case let .enabled(_, fingerprint):
            return "\(prefix) on (phone key \(fingerprint))."
        case .unsupportedBuild:
            return "\(prefix) unavailable: this build lacks the CloudKit container entitlement; "
                + "requests are approved on this Mac only."
        case let .iCloudAccountUnavailable(problem, _, fingerprint):
            return "\(prefix) unavailable: this Mac's iCloud account is \(problem.rawValue); "
                + "phone key \(fingerprint) stays paired and requests are approved on this Mac "
                + "until the account is available."
        case let .pairingInvalid(problem):
            let detail = diagnostic.map { ", \($0)" } ?? ""
            return "\(prefix) unavailable: the pairing record is unusable (\(problem.rawValue)\(detail)); "
                + "run `csec remote disable`, then pair again."
        case let .keychainUnavailable(status):
            return "\(prefix) unavailable: the Keychain did not return the pairing record "
                + "(OSStatus \(status)); csecd reads it again on the next request or status check."
        }
    }

    /// The pinned phone's name, for the unpair panel; nil when no pairing
    /// could be read.
    private static func pairedPhoneName(_ readiness: Readiness) -> String? {
        guard case let .paired(pairing) = readiness else { return nil }
        return pairing.configuration.phoneDeviceName
    }

    private func makeRequester(
        for stored: StoredRemoteApprovalConfiguration,
        signer suppliedSigner: (any RemoteApprovalRequestSigner)? = nil
    ) async throws -> RemoteApprovalRequester {
        do {
            try stored.validate()
        } catch {
            throw PairingFailure(problem: .recordCorrupt, diagnostic: "\(type(of: error))")
        }
        guard stored.cloudKitContainerIdentifier == cloudKitContainerIdentifier else {
            throw PairingFailure(problem: .containerMismatch)
        }
        let signer: any RemoteApprovalRequestSigner
        if let suppliedSigner {
            signer = suppliedSigner
        } else {
            do {
                signer = try macKeys.load(stored.macSigningKeyRepresentation)
            } catch {
                throw PairingFailure(problem: .macKeyMissing, diagnostic: "\(type(of: error))")
            }
        }
        let publicKey: Data
        do {
            publicKey = try await signer.publicKeyX963Representation()
        } catch {
            throw PairingFailure(problem: .macKeyMissing, diagnostic: "\(type(of: error))")
        }
        guard publicKey == stored.macPublicKeyX963 else {
            throw PairingFailure(problem: .macKeyMismatch)
        }
        // A handle can decode and still name no usable key. Sign once now, so
        // that shows up as this status instead of every request failing while
        // the status reads "on".
        do {
            let signature = try await signer.sign(Self.macKeyProbe)
            try RemoteApprovalCrypto.verify(
                signatureDER: signature, data: Self.macKeyProbe, publicKeyX963: publicKey
            )
        } catch {
            throw PairingFailure(problem: .macKeyMissing, diagnostic: "\(type(of: error))")
        }
        let config = RemoteApprovalRequesterConfiguration(
            macDeviceID: stored.macDeviceID,
            macDeviceName: stored.macDeviceName,
            pinnedPhoneDeviceID: stored.phoneDeviceID,
            pinnedPhonePublicKeyX963: stored.phonePublicKeyX963
        )
        do {
            return try RemoteApprovalRequester(
                configuration: config, signer: signer, relay: relay, alertGate: alertGate, cleanup: cleanup
            )
        } catch {
            throw PairingFailure(problem: .recordCorrupt, diagnostic: "\(type(of: error))")
        }
    }
}

/// Safe stand-in for a build without CloudKit entitlements. The protocol stays
/// present so local policy review and opt-out recovery retain one code path, but
/// every attempted transport operation is explicitly unavailable.
public actor UnavailableRemoteApprovalRelay: RemoteApprovalRelay {
    public init() {}

    public func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func response(
        for requestID: String,
        phoneDeviceID: String
    ) async throws -> SignedRemoteApprovalResponse? {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func discardResponse(for requestID: String, phoneDeviceID: String) async {}

    public func pendingRequests() async throws -> [SignedRemoteApprovalRequest] {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func requestIsPending(requestID: String) async throws -> Bool {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func publishAlert(requestID: String, macDeviceID: String) async throws {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func deleteExchange(requestID: String, phoneDeviceID: String?) async {}

    public func pairingConfirmation(
        macDeviceID: String
    ) async throws -> SignedRemoteApprovalPairingConfirmation? {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func publishPairingConfirmation(
        _ confirmation: SignedRemoteApprovalPairingConfirmation
    ) async throws {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func phoneStatus(phoneDeviceID: String) async throws -> SignedRemoteApprovalPhoneStatus? {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func publishPhoneStatus(_ status: SignedRemoteApprovalPhoneStatus) async throws {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func publishPairingOffer(_ offer: SignedRemoteApprovalPairingOffer) async throws {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func pairingOffer(phoneDeviceID: String) async throws -> SignedRemoteApprovalPairingOffer? {
        throw RemoteApprovalRelayFailure.permanentlyUnavailable
    }

    public func withdrawPairingOffer(phoneDeviceID: String, macDeviceID: String) async {}
}

public enum RemoteApprovalManagerError: Error, Equatable, Sendable {
    case invalidConfiguration
    case secureEnclaveUnavailable
    /// This csecd lacks the CloudKit container entitlement.
    case unsupportedBuild
    /// This Mac's iCloud account cannot carry requests, so pairing now would
    /// pin a phone that can never answer.
    case iCloudAccountUnavailable(RemoteApprovalAccountProblem)
    /// The phone-held unlock factor could not be enrolled, so nothing was
    /// paired.
    case remoteUnlockUnavailable
    case denied
}
