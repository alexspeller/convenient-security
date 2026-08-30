import CSECRemoteApproval
import CryptoKit
import Foundation
import LocalAuthentication
import Security
import UIKit

struct PhoneApprovalIdentity: Codable, Equatable {
    let deviceID: String
    let deviceName: String
    let signingKeyRepresentation: Data
    let publicKeyX963: Data

    private enum CodingKeys: String, CodingKey {
        case deviceID
        case deviceName
        // Keep the v1 on-disk field stable for any already-enrolled test build.
        case signingKeyRepresentation = "secureEnclaveKeyRepresentation"
        case publicKeyX963
    }

    var pairing: RemoteApprovalPhonePairing {
        RemoteApprovalPhonePairing(
            phoneDeviceID: deviceID,
            phoneDeviceName: deviceName,
            phonePublicKeyX963: publicKeyX963
        )
    }
}

struct PinnedMac: Codable, Equatable, Identifiable {
    let deviceID: String
    let deviceName: String
    let publicKeyX963: Data
    let cloudKitContainerIdentifier: String

    var id: String { deviceID }

    init(_ pairing: RemoteApprovalMacPairing) {
        self.deviceID = pairing.macDeviceID
        self.deviceName = pairing.macDeviceName
        self.publicKeyX963 = pairing.macPublicKeyX963
        self.cloudKitContainerIdentifier = pairing.cloudKitContainerIdentifier
    }
}

/// Phone-private state. On a physical device the P-256 private key never leaves
/// the Secure Enclave; its stored dataRepresentation is only an opaque handle.
/// A DEBUG simulator build deliberately substitutes a software P-256 key so the
/// approval flow can be exercised without pretending the simulator is secure.
/// Public pairing state remains available after first unlock so silent CloudKit
/// pushes can be vetted.
final class PhoneIdentityStore {
    #if DEBUG && targetEnvironment(simulator)
    private static let service = "com.alexspeller.convenient-security.approval.simulator"
    #else
    private static let service = "com.alexspeller.convenient-security.approval"
    #endif
    private static let identityAccount = "phone-identity-v1"
    private static let macsAccount = "pinned-macs-v1"

    func loadIdentity() throws -> PhoneApprovalIdentity? {
        guard let data = try load(account: Self.identityAccount) else { return nil }
        let identity = try JSONDecoder().decode(PhoneApprovalIdentity.self, from: data)
        guard UUID(uuidString: identity.deviceID) != nil,
              identity.signingKeyRepresentation.count <= 4_096 else {
            throw PhoneIdentityError.invalidState
        }
        #if DEBUG && targetEnvironment(simulator)
        let key = try P256.Signing.PrivateKey(
            rawRepresentation: identity.signingKeyRepresentation
        )
        #else
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: identity.signingKeyRepresentation
        )
        #endif
        guard key.publicKey.x963Representation == identity.publicKeyX963 else {
            throw PhoneIdentityError.invalidState
        }
        try identity.pairing.validate()
        return identity
    }

    func createIdentity() throws -> PhoneApprovalIdentity {
        #if DEBUG && targetEnvironment(simulator)
        let key = P256.Signing.PrivateKey()
        let keyRepresentation = key.rawRepresentation
        #else
        guard SecureEnclave.isAvailable else {
            throw PhoneIdentityError.secureEnclaveUnavailable
        }
        var accessError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.biometryCurrentSet, .privateKeyUsage],
            &accessError
        ) else {
            throw PhoneIdentityError.secureEnclaveUnavailable
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
        let keyRepresentation = key.dataRepresentation
        #endif
        let identity = PhoneApprovalIdentity(
            deviceID: UUID().uuidString.lowercased(),
            deviceName: sanitizedDeviceName(UIDevice.current.name),
            signingKeyRepresentation: keyRepresentation,
            publicKeyX963: key.publicKey.x963Representation
        )
        try identity.pairing.validate()
        try save(try JSONEncoder().encode(identity), account: Self.identityAccount)
        try save(try JSONEncoder().encode([PinnedMac]()), account: Self.macsAccount)
        return identity
    }

    func loadPinnedMacs() throws -> [PinnedMac] {
        guard let data = try load(account: Self.macsAccount) else { return [] }
        let macs = try JSONDecoder().decode([PinnedMac].self, from: data)
        guard macs.count <= 16, Set(macs.map(\.deviceID)).count == macs.count else {
            throw PhoneIdentityError.invalidState
        }
        for mac in macs {
            try RemoteApprovalMacPairing(
                macDeviceID: mac.deviceID,
                macDeviceName: mac.deviceName,
                macPublicKeyX963: mac.publicKeyX963,
                cloudKitContainerIdentifier: mac.cloudKitContainerIdentifier
            ).validate()
        }
        return macs
    }

    func pinMac(_ pairing: RemoteApprovalMacPairing) async throws -> [PinnedMac] {
        try pairing.validate()
        guard pairing.cloudKitContainerIdentifier
                == "iCloud.com.alexspeller.convenient-security" else {
            throw PhoneIdentityError.invalidPairingCode
        }
        try await authenticate(
            reason: "Pair with \(pairing.macDeviceName) for remote approvals"
        )
        var macs = try loadPinnedMacs()
        macs.removeAll { $0.deviceID == pairing.macDeviceID }
        macs.append(PinnedMac(pairing))
        macs.sort { $0.deviceName.localizedStandardCompare($1.deviceName) == .orderedAscending }
        guard macs.count <= 16 else { throw PhoneIdentityError.invalidState }
        try save(try JSONEncoder().encode(macs), account: Self.macsAccount)
        return macs
    }

    func sign(
        _ data: Data,
        identity: PhoneApprovalIdentity,
        reason: String
    ) async throws -> Data {
        #if DEBUG && targetEnvironment(simulator)
        try await authenticate(reason: reason)
        let key = try P256.Signing.PrivateKey(
            rawRepresentation: identity.signingKeyRepresentation
        )
        #else
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        context.localizedReason = reason
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: identity.signingKeyRepresentation,
            authenticationContext: context
        )
        #endif
        guard key.publicKey.x963Representation == identity.publicKeyX963 else {
            throw PhoneIdentityError.invalidState
        }
        return try key.signature(for: data).derRepresentation
    }

    func resetInvalidState() {
        SecItemDelete(identity(account: Self.identityAccount) as CFDictionary)
        SecItemDelete(identity(account: Self.macsAccount) as CFDictionary)
    }

    private func authenticate(reason: String) async throws {
        let context = LAContext()
        context.localizedCancelTitle = "Cancel"
        var error: NSError?
        guard context.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            error: &error
        ) else {
            throw PhoneIdentityError.biometricsUnavailable
        }
        try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            ) { success, error in
                if success {
                    continuation.resume()
                } else {
                    continuation.resume(
                        throwing: error ?? PhoneIdentityError.authenticationDenied
                    )
                }
            }
        }
    }

    private func sanitizedDeviceName(_ value: String) -> String {
        let cleaned = value.unicodeScalars.map { scalar -> String in
            CharacterSet.controlCharacters.contains(scalar)
                || CharacterSet.newlines.contains(scalar) ? "�" : String(scalar)
        }.joined()
        return String(cleaned.prefix(128)).isEmpty ? "iPhone" : String(cleaned.prefix(128))
    }

    private func identity(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }

    private func load(account: String) throws -> Data? {
        var query = identity(account: account)
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
        var query = identity(account: account)
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
}

enum PhoneIdentityError: Error {
    case invalidState
    case invalidPairingCode
    case secureEnclaveUnavailable
    case biometricsUnavailable
    case authenticationDenied
    case keychain(OSStatus)
}
