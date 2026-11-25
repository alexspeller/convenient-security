import CSECRemoteApproval
import Foundation
import Security
import CSECBuildIdentity

/// A Mac this iPhone accepted under Face ID, and the signed confirmation it
/// published for that Mac. The confirmation is public and value-free, so it is
/// kept: a publish that failed is retried without asking for Face ID again.
struct PinnedMac: Codable, Equatable, Identifiable {
    let deviceID: String
    let deviceName: String
    let publicKeyX963: Data
    let cloudKitContainerIdentifier: String
    let pairedAtMilliseconds: UInt64
    let confirmation: SignedRemoteApprovalPairingConfirmation?
    var confirmationDelivered: Bool

    var id: String { deviceID }

    var fingerprint: String {
        RemoteApprovalPairingCode.publicKeyFingerprint(publicKeyX963)
    }

    /// The Mac's name as this iPhone shows it. The name comes from a pairing
    /// code, so control, format and bidirectional characters are neutralized
    /// before it reaches the screen or a Face ID prompt; two Macs with the
    /// same name are told apart by `fingerprint`.
    var displayName: String {
        RemoteApprovalDisplayText.sanitized(deviceName)
    }

    init(
        _ pairing: RemoteApprovalMacPairing,
        confirmation: SignedRemoteApprovalPairingConfirmation?,
        pairedAtMilliseconds: UInt64
    ) {
        self.deviceID = pairing.macDeviceID
        self.deviceName = pairing.macDeviceName
        self.publicKeyX963 = pairing.macPublicKeyX963
        self.cloudKitContainerIdentifier = pairing.cloudKitContainerIdentifier
        self.pairedAtMilliseconds = pairedAtMilliseconds
        self.confirmation = confirmation
        self.confirmationDelivered = confirmation == nil
    }
}

/// The pinned Macs' Keychain record: its names, and how it is decoded and
/// checked. The app writes it (`PhoneIdentityStore`); the notification
/// service extension only reads it, through the app's own access group,
/// which the extension's `keychain-access-groups` names. It is
/// `AfterFirstUnlockThisDeviceOnly`, so the extension can read it while the
/// iPhone is locked, as it is when most alerts arrive.
enum PinnedMacRecords {
    #if DEBUG && targetEnvironment(simulator)
    static let keychainService = CSECBuildIdentity.named("approval.simulator")
    #else
    static let keychainService = CSECBuildIdentity.named("approval")
    #endif
    static let keychainAccount = "pinned-macs-v2"
    static let maximumCount = 16
    static let maximumRecordBytes = 64 * 1_024

    struct Invalid: Error {}

    /// The pinned Macs in a record's bytes, refusing a record with too many
    /// Macs, a Mac twice, or a Mac whose pairing does not validate.
    static func decode(_ data: Data) throws -> [PinnedMac] {
        guard data.count <= maximumRecordBytes else { throw Invalid() }
        let macs = try JSONDecoder().decode([PinnedMac].self, from: data)
        guard macs.count <= maximumCount,
              Set(macs.map(\.deviceID)).count == macs.count else { throw Invalid() }
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

    /// Read-only: the pinned Macs, or none when there is no record.
    static func load() throws -> [PinnedMac] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw Invalid() }
            return try decode(data)
        case errSecItemNotFound:
            return []
        default:
            throw Invalid()
        }
    }
}
