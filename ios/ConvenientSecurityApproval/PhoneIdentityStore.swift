import CSECRemoteApproval
import CryptoKit
import CryptoTokenKit
import Foundation
import LocalAuthentication
import Security
import UIKit
import CSECBuildIdentity

/// This iPhone's approval identity, format 2: a signing key that signs every
/// decision, a key-agreement key that answers the Mac's cold-unlock challenge,
/// and the signing key's signature vouching for the key-agreement key. Both
/// keys are Face-ID-gated; on a device they live in the Secure Enclave and the
/// stored representations are only opaque handles to them.
struct PhoneApprovalIdentity: Codable, Equatable {
    static let currentFormatVersion = 2

    let formatVersion: Int
    let deviceID: String
    let deviceName: String
    let signingKeyRepresentation: Data
    let publicKeyX963: Data
    let keyAgreementKeyRepresentation: Data
    let keyAgreementPublicKeyX963: Data
    /// The signing key's signature over
    /// `RemoteApprovalPhonePairing.keyAgreementBindingData`.
    let keyAgreementSignatureDER: Data

    func pairing(appVersion: String) -> RemoteApprovalPhonePairing {
        RemoteApprovalPhonePairing(
            phoneDeviceID: deviceID,
            phoneDeviceName: deviceName,
            phonePublicKeyX963: publicKeyX963,
            phoneKeyAgreementPublicKeyX963: keyAgreementPublicKeyX963,
            keyAgreementSignatureDER: keyAgreementSignatureDER,
            appVersion: appVersion
        )
    }

    var fingerprint: String {
        RemoteApprovalPairingCode.publicKeyFingerprint(publicKeyX963)
    }
}

/// `PinnedMac` and its Keychain record's names live in `Shared/PinnedMacRecords.swift`,
/// which the notification service extension compiles too.

/// The facts the phone status record reports.
struct PhoneStatusFacts: Codable, Equatable {
    let appVersion: String
    let protocolVersion: UInt16
    let notificationsAuthorized: Bool
    /// Absent in facts saved by an app that predates it.
    let requestAlerts: RemoteApprovalPhoneAlertState?
    /// The review kinds this app shows a card for; absent in facts saved by
    /// an app that predates it, so the change is signed and reported.
    let reviewKinds: [String]?

    init(
        appVersion: String,
        protocolVersion: UInt16,
        notificationsAuthorized: Bool,
        requestAlerts: RemoteApprovalPhoneAlertState?,
        reviewKinds: [String]?
    ) {
        self.appVersion = appVersion
        self.protocolVersion = protocolVersion
        self.notificationsAuthorized = notificationsAuthorized
        self.requestAlerts = requestAlerts
        self.reviewKinds = reviewKinds
    }

    init(_ status: RemoteApprovalPhoneStatus) {
        self.init(
            appVersion: status.appVersion,
            protocolVersion: status.protocolVersion,
            notificationsAuthorized: status.notificationsAuthorized,
            requestAlerts: status.requestAlerts,
            reviewKinds: status.reviewKinds
        )
    }
}

/// What the phone last told its Macs about itself, and a signed status still
/// waiting for iCloud. Signing needs Face ID, so a status is signed only with a
/// Face ID the reader gave for something else and then kept until delivered.
struct PhoneStatusPublication: Codable, Equatable {
    var published: PhoneStatusFacts?
    var unpublished: SignedRemoteApprovalPhoneStatus?
}

enum PhoneIdentityState: Equatable {
    case notSetUp
    case ready(PhoneApprovalIdentity)
    /// A format-1 identity: a signing key and no key-agreement key, so it
    /// cannot answer a cold-unlock challenge. Setting up again replaces it.
    case outdated
    /// The records could not be read just now — most often because this
    /// iPhone has not been unlocked since it restarted (the Keychain answers
    /// `errSecInteractionNotAllowed`). Nothing is wrong with what is stored,
    /// so this is never a reason to set up again: reading later works.
    case temporarilyUnavailable(OSStatus)
    /// Stored identity state that cannot be used: it does not decode, or its
    /// keys no longer match what was stored.
    case unusable
}

enum PhoneIdentityError: Error, Equatable {
    case invalidState
    case secureEnclaveUnavailable
    /// Face ID did not complete: cancelled, not recognized, locked out, or not
    /// available.
    case biometrics(LAError.Code)
    /// Face ID succeeded but a Secure Enclave key could not be used — most
    /// often because Face ID enrollment changed, which invalidates both keys.
    case keyUnusable
    case keychain(OSStatus)
}

enum AppVersion {
    /// "<CFBundleShortVersionString> (<CFBundleVersion>)", bounded to the
    /// protocol's 64 bytes.
    static let current: String = {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "0"
        let build = info?["CFBundleVersion"] as? String ?? "0"
        var text = "\(short) (\(build))"
        while text.utf8.count > 64 { text.removeLast() }
        return text.isEmpty ? "0" : text
    }()
}

/// Phone-private state: the approval identity, the pinned Macs, and the status
/// publication. On a physical device the private keys never leave the Secure
/// Enclave. A DEBUG Simulator build deliberately substitutes software P-256
/// keys so the approval flow can be exercised without pretending the Simulator
/// is secure. The stored records stay readable after first unlock so a silent
/// CloudKit push can be vetted while the phone is locked.
final class PhoneIdentityStore {
    /// The one CloudKit container a pinned Mac may name.
    static let containerIdentifier = CSECBuildIdentity.cloudKitContainer
    static let maximumPinnedMacs = PinnedMacRecords.maximumCount

    private static let service = PinnedMacRecords.keychainService
    private static let identityAccount = "phone-identity-v2"
    private static let macsAccount = PinnedMacRecords.keychainAccount
    private static let statusAccount = "phone-status-v1"
    private static let decidedRequestsAccount = "decided-requests-v1"
    /// The most request IDs `decided-requests-v1` keeps; the oldest go first.
    /// 1,024 canonical IDs are about 40 KB of JSON, inside a record's 64 KB.
    static let maximumDecidedRequestIDs = 1_024
    /// Format 1 (protocol v2): a signing key only. Its Macs were pinned with
    /// v1 pairing codes and must pair again, so both records are only ever
    /// detected and then deleted by a new setup.
    private static let legacyIdentityAccount = "phone-identity-v1"
    private static let legacyMacsAccount = "pinned-macs-v1"

    /// What is stored, told apart from what could not be read just now.
    /// Only a record that was read and does not decode, or whose keys do not
    /// match it, is `.unusable` — the one state that offers a destructive
    /// "set up again". A Keychain refusal is `.temporarilyUnavailable`, and so
    /// is any failure while protected data is unavailable (the phone is
    /// locked), since a locked phone is no evidence the keys are gone.
    func loadState(protectedDataAvailable: Bool) -> PhoneIdentityState {
        do {
            if let data = try load(account: Self.identityAccount) {
                do {
                    return .ready(try decodeIdentity(data))
                } catch {
                    return protectedDataAvailable
                        ? .unusable
                        : .temporarilyUnavailable(errSecInteractionNotAllowed)
                }
            }
            if try load(account: Self.legacyIdentityAccount) != nil {
                return .outdated
            }
            return .notSetUp
        } catch let PhoneIdentityError.keychain(status) {
            return .temporarilyUnavailable(status)
        } catch {
            return protectedDataAvailable
                ? .unusable
                : .temporarilyUnavailable(errSecInteractionNotAllowed)
        }
    }

    /// Create both keys and the signature binding them, for one Face ID. The
    /// evaluated context is handed to both key creations and both key uses:
    /// the binding signature, and one throwaway key agreement that proves the
    /// key-agreement key works before a Mac ever relies on it. A new identity
    /// replaces any earlier one, and with it every pinned Mac, since those Macs
    /// pinned the old keys.
    func createIdentity(
        deviceName: String,
        reason: String
    ) async throws -> PhoneApprovalIdentity {
        let context = try await Self.evaluatedContext(reason: reason)
        defer { context.invalidate() }
        let deviceID = UUID().uuidString.lowercased()
        #if DEBUG && targetEnvironment(simulator)
        let signing = P256.Signing.PrivateKey()
        let agreement = P256.KeyAgreement.PrivateKey()
        let signingRepresentation = signing.rawRepresentation
        let agreementRepresentation = agreement.rawRepresentation
        #else
        guard SecureEnclave.isAvailable else {
            throw PhoneIdentityError.secureEnclaveUnavailable
        }
        let signing = try Self.keyOperation {
            try SecureEnclave.P256.Signing.PrivateKey(
                accessControl: try Self.keyAccessControl(),
                authenticationContext: context
            )
        }
        let agreement = try Self.keyOperation {
            try SecureEnclave.P256.KeyAgreement.PrivateKey(
                accessControl: try Self.keyAccessControl(),
                authenticationContext: context
            )
        }
        let signingRepresentation = signing.dataRepresentation
        let agreementRepresentation = agreement.dataRepresentation
        #endif
        let binding = RemoteApprovalPhonePairing.keyAgreementBindingData(
            phoneDeviceID: deviceID,
            phoneKeyAgreementPublicKeyX963: agreement.publicKey.x963Representation
        )
        let bindingSignature = try Self.keyOperation {
            try signing.signature(for: binding).derRepresentation
        }
        try Self.keyOperation {
            _ = try agreement.sharedSecretFromKeyAgreement(
                with: P256.KeyAgreement.PrivateKey().publicKey
            )
        }
        let identity = PhoneApprovalIdentity(
            formatVersion: PhoneApprovalIdentity.currentFormatVersion,
            deviceID: deviceID,
            deviceName: Self.sanitizedDeviceName(deviceName),
            signingKeyRepresentation: signingRepresentation,
            publicKeyX963: signing.publicKey.x963Representation,
            keyAgreementKeyRepresentation: agreementRepresentation,
            keyAgreementPublicKeyX963: agreement.publicKey.x963Representation,
            keyAgreementSignatureDER: bindingSignature
        )
        // Verifies the binding signature as the Mac will.
        try identity.pairing(appVersion: AppVersion.current).validate()
        try save(try JSONEncoder().encode(identity), account: Self.identityAccount)
        try save(try JSONEncoder().encode([PinnedMac]()), account: Self.macsAccount)
        delete(account: Self.statusAccount)
        delete(account: Self.decidedRequestsAccount)
        delete(account: Self.legacyIdentityAccount)
        delete(account: Self.legacyMacsAccount)
        return identity
    }

    /// One Face ID for one user action. Everything that action signs or
    /// agrees on uses the returned authorization's single evaluated context.
    func authorize(
        _ identity: PhoneApprovalIdentity,
        reason: String
    ) async throws -> PhoneAuthorization {
        PhoneAuthorization(
            identity: identity,
            context: try await Self.evaluatedContext(reason: reason)
        )
    }

    func loadPinnedMacs() throws -> [PinnedMac] {
        guard let data = try load(account: Self.macsAccount) else { return [] }
        do {
            return try PinnedMacRecords.decode(data)
        } catch is PinnedMacRecords.Invalid {
            throw PhoneIdentityError.invalidState
        }
    }

    func savePinnedMacs(_ macs: [PinnedMac]) throws {
        guard macs.count <= Self.maximumPinnedMacs else {
            throw PhoneIdentityError.invalidState
        }
        try save(try JSONEncoder().encode(macs), account: Self.macsAccount)
    }

    func loadStatusPublication() -> PhoneStatusPublication {
        guard let data = try? load(account: Self.statusAccount),
              let publication = try? JSONDecoder().decode(
                  PhoneStatusPublication.self,
                  from: data
              ) else {
            return PhoneStatusPublication()
        }
        return publication
    }

    func saveStatusPublication(_ publication: PhoneStatusPublication) {
        guard let data = try? JSONEncoder().encode(publication) else { return }
        try? save(data, account: Self.statusAccount)
    }

    /// The requests this iPhone answered, or found withdrawn while answering,
    /// oldest first. They are random request IDs and nothing else, kept in the
    /// Keychain beside the identity and the pinned Macs so the list lives as
    /// long as the pairings it guards: the app's own defaults go when the app
    /// is deleted, while Keychain records can outlive it and bring those
    /// pairings back on a reinstall. A Keychain refusal is thrown, like any
    /// other record's; a list that does not decode is a list of nothing, since
    /// the Mac's pending table, not this list, decides whether an answer
    /// counts.
    func loadDecidedRequestIDs() throws -> [String] {
        guard let data = try load(account: Self.decidedRequestsAccount),
              let stored = try? JSONDecoder().decode([String].self, from: data) else {
            return []
        }
        var seen = Set<String>()
        let ids = stored.filter {
            RemoteApprovalMailboxName.isCanonicalID($0) && seen.insert($0).inserted
        }
        return Array(ids.suffix(Self.maximumDecidedRequestIDs))
    }

    /// Best effort: a list that could not be saved leaves this run's memory
    /// of it, and the next answer saves the whole list again.
    func saveDecidedRequestIDs(_ ids: [String]) {
        let bounded = Array(ids.suffix(Self.maximumDecidedRequestIDs))
        guard let data = try? JSONEncoder().encode(bounded) else { return }
        try? save(data, account: Self.decidedRequestsAccount)
    }

    // MARK: - Keys and Face ID

    private func decodeIdentity(_ data: Data) throws -> PhoneApprovalIdentity {
        let identity = try JSONDecoder().decode(PhoneApprovalIdentity.self, from: data)
        guard identity.formatVersion == PhoneApprovalIdentity.currentFormatVersion,
              UUID(uuidString: identity.deviceID) != nil,
              identity.signingKeyRepresentation.count <= 4_096,
              identity.keyAgreementKeyRepresentation.count <= 4_096 else {
            throw PhoneIdentityError.invalidState
        }
        // Loading a key handle and reading its public half needs no Face ID.
        #if DEBUG && targetEnvironment(simulator)
        let signing = try P256.Signing.PrivateKey(
            rawRepresentation: identity.signingKeyRepresentation
        )
        let agreement = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: identity.keyAgreementKeyRepresentation
        )
        #else
        let signing = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: identity.signingKeyRepresentation
        )
        let agreement = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: identity.keyAgreementKeyRepresentation
        )
        #endif
        guard signing.publicKey.x963Representation == identity.publicKeyX963,
              agreement.publicKey.x963Representation
                == identity.keyAgreementPublicKeyX963 else {
            throw PhoneIdentityError.invalidState
        }
        try identity.pairing(appVersion: AppVersion.current).validate()
        return identity
    }

    #if !(DEBUG && targetEnvironment(simulator))
    /// Both keys: usable only while this iPhone is unlocked, only on this
    /// device, and only after Face ID with the currently enrolled faces, so a
    /// change to Face ID enrollment invalidates them.
    private static func keyAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet, .privateKeyUsage],
            &error
        ) else {
            throw PhoneIdentityError.secureEnclaveUnavailable
        }
        return access
    }
    #endif

    /// A context that has already passed Face ID. The caller passes it to
    /// every key use for the same action; it is deliberately not set to
    /// `interactionNotAllowed`, so if iOS wants a second Face ID for a second
    /// key it can ask for one rather than fail.
    static func evaluatedContext(reason: String) async throws -> LAContext {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        // Face ID only: no passcode fallback button.
        context.localizedFallbackTitle = ""
        context.localizedReason = reason
        var availability: NSError?
        guard context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &availability
        ) else {
            throw PhoneIdentityError.biometrics(
                availability.flatMap { LAError.Code(rawValue: $0.code) }
                    ?? .biometryNotAvailable
            )
        }
        #if DEBUG && targetEnvironment(simulator)
        await SimulatorInstrumentation.shared.recordFaceIDPrompt()
        #endif
        do {
            _ = try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            )
        } catch {
            throw classify(error)
        }
        #if DEBUG && targetEnvironment(simulator)
        await SimulatorInstrumentation.shared.recordFaceIDMatch()
        #endif
        return context
    }

    static func keyOperation<Value>(_ body: () throws -> Value) throws -> Value {
        do {
            return try body()
        } catch {
            throw classify(error)
        }
    }

    /// Face ID's own outcomes keep their meaning (a cancelled second sheet is
    /// a cancellation); any other key failure means the key is not usable.
    private static func classify(_ error: Error) -> PhoneIdentityError {
        if let error = error as? PhoneIdentityError { return error }
        let nsError = error as NSError
        if nsError.domain == LAErrorDomain,
           let code = LAError.Code(rawValue: nsError.code) {
            return .biometrics(code)
        }
        if nsError.domain == TKErrorDomain,
           nsError.code == TKError.Code.canceledByUser.rawValue {
            return .biometrics(.userCancel)
        }
        return .keyUnusable
    }

    private static func sanitizedDeviceName(_ value: String) -> String {
        let cleaned = value.unicodeScalars.map { scalar -> String in
            CharacterSet.controlCharacters.contains(scalar)
                || CharacterSet.newlines.contains(scalar) ? "�" : String(scalar)
        }.joined()
        var bounded = String(cleaned.prefix(128))
        while bounded.utf8.count > 256 { bounded.removeLast() }
        return bounded.isEmpty ? "iPhone" : bounded
    }

    // MARK: - Keychain records

    private func item(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private func load(account: String) throws -> Data? {
        #if DEBUG && targetEnvironment(simulator)
        if SimulatorKeychainRefusal.shared.isOn {
            throw PhoneIdentityError.keychain(errSecInteractionNotAllowed)
        }
        #endif
        var query = item(account: account)
        query[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data, data.count <= 64 * 1_024 else {
                throw PhoneIdentityError.invalidState
            }
            return data
        case errSecItemNotFound:
            return nil
        default:
            throw PhoneIdentityError.keychain(status)
        }
    }

    private func save(_ data: Data, account: String) throws {
        guard data.count <= 64 * 1_024 else { throw PhoneIdentityError.invalidState }
        var query = item(account: account)
        let update = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if updateStatus == errSecSuccess { return }
        guard updateStatus == errSecItemNotFound else {
            throw PhoneIdentityError.keychain(updateStatus)
        }
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        query[kSecValueData as String] = data
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw PhoneIdentityError.keychain(addStatus)
        }
    }

    private func delete(account: String) {
        SecItemDelete(item(account: account) as CFDictionary)
    }

    #if DEBUG && targetEnvironment(simulator)
    // MARK: - Simulator UI-test state

    /// Every record this app keeps, gone: the next read finds no setup.
    func eraseForSimulatorTests() {
        for account in [
            Self.identityAccount, Self.macsAccount, Self.statusAccount,
            Self.decidedRequestsAccount,
            Self.legacyIdentityAccount, Self.legacyMacsAccount,
        ] {
            delete(account: account)
        }
    }

    /// An identity record that was read and does not decode: what damaged
    /// storage looks like. The app must offer to set up again.
    func seedUndecodableIdentityForSimulatorTests() {
        try? save(Data(#"{"formatVersion":2,"deviceID":"#.utf8), account: Self.identityAccount)
    }

    /// A format-2 identity that decodes but whose signing key does not match
    /// the public key stored beside it: keys that no longer match what was
    /// stored. The app must offer to set up again.
    func seedMismatchedIdentityForSimulatorTests() {
        let signing = P256.Signing.PrivateKey()
        let agreement = P256.KeyAgreement.PrivateKey()
        let identity = PhoneApprovalIdentity(
            formatVersion: PhoneApprovalIdentity.currentFormatVersion,
            deviceID: UUID().uuidString.lowercased(),
            deviceName: "iPhone whose stored keys do not match",
            signingKeyRepresentation: signing.rawRepresentation,
            publicKeyX963: P256.Signing.PrivateKey().publicKey.x963Representation,
            keyAgreementKeyRepresentation: agreement.rawRepresentation,
            keyAgreementPublicKeyX963: agreement.publicKey.x963Representation,
            keyAgreementSignatureDER: Data()
        )
        guard let data = try? JSONEncoder().encode(identity) else { return }
        try? save(data, account: Self.identityAccount)
    }

    /// A format-1 record in the place a protocol v2 build kept it. Only its
    /// presence matters: the app never decodes a format-1 identity, it
    /// reports it as outdated and replaces it at the next setup.
    func seedLegacyIdentityForSimulatorTests() {
        let legacy: [String: Any] = [
            "formatVersion": 1,
            "deviceID": UUID().uuidString.lowercased(),
            "deviceName": "iPhone set up by a protocol v2 build",
        ]
        guard let data = try? JSONSerialization.data(withJSONObject: legacy) else { return }
        try? save(data, account: Self.legacyIdentityAccount)
    }
    #endif
}

/// One Face ID, spent on everything a single user action needs: a decision's
/// signature and, for an approval that carries a cold-unlock challenge, its key
/// agreement; a pairing confirmation; a status piggybacked on any of them.
/// Every key use goes through the one evaluated context, and the context is
/// invalidated as soon as the action has what it needs.
///
/// The operations are `async` so they run off the main actor: if iOS does ask
/// for a second Face ID for the second key, the blocking Secure Enclave call
/// does not freeze the interface under the sheet.
final class PhoneAuthorization: PhoneDecisionKeys {
    let identity: PhoneApprovalIdentity
    private let context: LAContext

    init(identity: PhoneApprovalIdentity, context: LAContext) {
        self.identity = identity
        self.context = context
    }

    func sign(_ data: Data) async throws -> Data {
        #if DEBUG && targetEnvironment(simulator)
        let key = try P256.Signing.PrivateKey(
            rawRepresentation: identity.signingKeyRepresentation
        )
        #else
        let context = self.context
        let identity = self.identity
        let key = try PhoneIdentityStore.keyOperation {
            try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: identity.signingKeyRepresentation,
                authenticationContext: context
            )
        }
        #endif
        guard key.publicKey.x963Representation == identity.publicKeyX963 else {
            throw PhoneIdentityError.keyUnusable
        }
        #if DEBUG && targetEnvironment(simulator)
        await SimulatorInstrumentation.shared.recordPhoneKeySignature()
        #endif
        return try PhoneIdentityStore.keyOperation {
            try key.signature(for: data).derRepresentation
        }
    }

    func unlockAnswer(blindedPoint: Data) async throws -> Data {
        #if DEBUG && targetEnvironment(simulator)
        let key = try P256.KeyAgreement.PrivateKey(
            rawRepresentation: identity.keyAgreementKeyRepresentation
        )
        #else
        let context = self.context
        let identity = self.identity
        let key = try PhoneIdentityStore.keyOperation {
            try SecureEnclave.P256.KeyAgreement.PrivateKey(
                dataRepresentation: identity.keyAgreementKeyRepresentation,
                authenticationContext: context
            )
        }
        #endif
        guard key.publicKey.x963Representation == identity.keyAgreementPublicKeyX963 else {
            throw PhoneIdentityError.keyUnusable
        }
        #if DEBUG && targetEnvironment(simulator)
        await SimulatorInstrumentation.shared.recordUnlockKeyAgreement()
        #endif
        return try PhoneIdentityStore.keyOperation {
            try RemoteUnlockCrypto.answer(blindedPoint: blindedPoint) { point in
                try key.sharedSecretFromKeyAgreement(with: point)
            }
        }
    }

    func invalidate() {
        context.invalidate()
    }
}
