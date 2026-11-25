import Foundation

/// The record names the mailbox uses, and the rule every name must pass before
/// a relay hands it to its transport.
///
/// A record's name decides what a delete removes, so it is computed here from
/// canonical identifiers only, never taken from a mailbox payload as-is: a
/// payload is attacker-writable data until its signature verifies, and CloudKit
/// raises an Objective-C exception — which Swift cannot catch, so it aborts the
/// process — for an empty record name or one longer than 255 bytes. Every
/// builder returns nil rather than a name the transport could refuse.
public enum RemoteApprovalMailboxName {
    /// CloudKit's limit on a record name, in bytes.
    public static let maximumRecordNameBytes = 255

    /// Whether `value` is a UUID in its one canonical spelling: 36 characters,
    /// lowercase. `RemoteApprovalRequest` and `RemoteApprovalResponse` lowercase
    /// the IDs they are built with, but a decoded payload is whatever its
    /// writer put there — `UUID(uuidString:)` alone accepts upper case too.
    public static func isCanonicalID(_ value: String) -> Bool {
        guard value.utf8.count == 36, let uuid = UUID(uuidString: value) else { return false }
        return uuid.uuidString.lowercased() == value
    }

    /// `request-<requestID>`: the Mac's prompt. Deleting it is the withdrawal
    /// marker the phone watches for.
    public static func request(requestID: String) -> String? {
        guard isCanonicalID(requestID) else { return nil }
        return "request-" + requestID
    }

    /// `response-<requestID>-<phoneDeviceID>`: one phone's answer to one
    /// request. The name is per phone so that a record anyone else writes for
    /// the same request lands somewhere the Mac never reads, instead of taking
    /// the one slot the pinned phone's answer needs.
    public static func response(requestID: String, phoneDeviceID: String) -> String? {
        guard isCanonicalID(requestID), isCanonicalID(phoneDeviceID) else { return nil }
        return "response-\(requestID)-\(phoneDeviceID)"
    }

    /// `alert-<requestID>`: what raises the phone's notification for a request
    /// already in the mailbox. The Mac creates it once the phone should be
    /// alerted, which can be after the request itself.
    public static func alert(requestID: String) -> String? {
        guard isCanonicalID(requestID) else { return nil }
        return "alert-" + requestID
    }

    /// The request an alert record named `recordName` is for, or nil when the
    /// name is not exactly `alert-<canonical request ID>`.
    public static func requestID(fromAlertRecordName recordName: String) -> String? {
        guard recordName.hasPrefix("alert-") else { return nil }
        let requestID = String(recordName.dropFirst("alert-".count))
        return isCanonicalID(requestID) ? requestID : nil
    }

    /// `pairing-confirmation-<macDeviceID>`.
    public static func pairingConfirmation(macDeviceID: String) -> String? {
        let id = macDeviceID.lowercased()
        guard isCanonicalID(id) else { return nil }
        return "pairing-confirmation-" + id
    }

    /// `pairing-offer-<phoneDeviceID>`: the Mac's offer to the phone it
    /// pinned. Named by the phone, the one thing that phone knows before it
    /// knows the Mac.
    public static func pairingOffer(phoneDeviceID: String) -> String? {
        let id = phoneDeviceID.lowercased()
        guard isCanonicalID(id) else { return nil }
        return "pairing-offer-" + id
    }

    /// `phone-status-<phoneDeviceID>`.
    public static func phoneStatus(phoneDeviceID: String) -> String? {
        let id = phoneDeviceID.lowercased()
        guard isCanonicalID(id) else { return nil }
        return "phone-status-" + id
    }

    /// Whether a request record called `recordName` holds the request its
    /// payload names. The mailbox drops every record for which this is false:
    /// a signed request copied under another name is a replay, and a record
    /// whose payload names some other request must not decide what a delete
    /// by that request's ID removes.
    public static func requestRecord(named recordName: String, holds requestID: String) -> Bool {
        guard let expected = request(requestID: requestID) else { return false }
        return recordName == expected
    }

    /// Whether `name` is one a record ID can be made from without the
    /// transport raising: not empty, at most 255 bytes, printable ASCII, and
    /// not starting with `_` (CloudKit reserves those). Every name the builders
    /// above return passes; a relay checks again anyway before constructing an
    /// ID, so no future caller can hand it an unchecked string.
    public static func isUsableRecordName(_ name: String) -> Bool {
        let bytes = name.utf8
        guard !bytes.isEmpty, bytes.count <= maximumRecordNameBytes,
              bytes.first != UInt8(ascii: "_") else { return false }
        return bytes.allSatisfy { $0 >= 0x21 && $0 <= 0x7e }
    }
}

/// Makes a device name or other untrusted label safe to show on either device.
///
/// It is the phone's twin of the Mac's `ReviewDisplay.sanitized`: bidirectional
/// formatting characters, newlines and other control or format characters each
/// become U+FFFD, so a name cannot reorder or break the line it is shown in, and
/// the substitution stays visible. It is display-only — wire validation of a
/// name is unchanged, and a name made of ordinary characters comes back as it
/// went in.
public enum RemoteApprovalDisplayText {
    private static let bidiControls: Set<UInt32> = [
        0x061c, 0x200e, 0x200f,
        0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
        0x2066, 0x2067, 0x2068, 0x2069,
    ]

    public static func sanitized(_ value: String) -> String {
        var result = String.UnicodeScalarView()
        for scalar in value.unicodeScalars {
            if bidiControls.contains(scalar.value)
                || CharacterSet.newlines.contains(scalar)
                || CharacterSet.controlCharacters.contains(scalar) {
                result.append("\u{FFFD}")
            } else {
                result.append(scalar)
            }
        }
        return String(result)
    }
}
