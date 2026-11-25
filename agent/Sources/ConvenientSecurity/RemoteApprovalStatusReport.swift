import CSECRemoteApproval
import Foundation

public extension RemoteApprovalConfigurationStatus {
    /// The wire form of csecd's readiness. Every cause keeps its own code, so
    /// the launcher can say what to do instead of one generic "unavailable".
    /// Whether the phone shows settings reviews is said in every state, from
    /// the phone's signed status only while the pairing is usable.
    init(_ status: RemoteApprovalManagerStatus, health: RemoteApprovalPairingHealth? = nil) {
        let mac = Int(RemoteApprovalProtocolV3.version)
        switch status {
        case .disabled:
            self.init(state: .disabled, phoneSettingsReviews: .noPhoneStatus, macProtocolVersion: mac)
        case let .enabled(phoneName, fingerprint):
            self.init(
                state: .enabled,
                phoneName: phoneName,
                phoneKeyFingerprint: fingerprint,
                phoneConfirmed: health?.confirmed,
                phoneAppVersion: health?.phoneAppVersion,
                phoneNotificationsAuthorized: health?.notificationsAuthorized,
                phoneRequestAlerts: health?.requestAlerts.map(RemoteApprovalPhoneAlertCondition.init),
                remoteUnlockEnrolled: health?.remoteUnlockEnrolled,
                phoneProtocolVersion: health?.phoneProtocolVersion.map(Int.init),
                phoneStatusUpdatedAtMilliseconds: health?.phoneStatusUpdatedAtMilliseconds,
                phoneShowsSettingsReviews: health?.phoneShowsSettingsReviews,
                phoneSettingsReviews: RemoteApprovalPhoneSettingsReviews(phoneShows: health?.phoneShowsSettingsReviews),
                macProtocolVersion: mac
            )
        case .unsupportedBuild:
            self.init(
                state: .unavailable, cause: .unsupportedBuild,
                phoneSettingsReviews: .noPhoneStatus, macProtocolVersion: mac
            )
        case let .iCloudAccountUnavailable(problem, phoneName, fingerprint):
            self.init(
                state: .unavailable,
                phoneName: phoneName,
                phoneKeyFingerprint: fingerprint,
                cause: .iCloudAccountUnavailable,
                detail: RemoteApprovalUnavailableDetail(problem),
                phoneSettingsReviews: .noPhoneStatus,
                macProtocolVersion: mac
            )
        case let .pairingInvalid(problem):
            self.init(
                state: .unavailable,
                cause: .pairingInvalid,
                detail: RemoteApprovalUnavailableDetail(problem),
                phoneSettingsReviews: .noPhoneStatus,
                macProtocolVersion: mac
            )
        case let .keychainUnavailable(status):
            self.init(
                state: .unavailable, cause: .keychainUnavailable, keychainStatus: status,
                phoneSettingsReviews: .noPhoneStatus, macProtocolVersion: mac
            )
        }
    }
}

extension RemoteApprovalPhoneAlertCondition {
    init(_ state: RemoteApprovalPhoneAlertState) {
        switch state {
        case .ready: self = .ready
        case .subscriptionRefused: self = .subscriptionRefused
        case .pushRegistrationFailed: self = .pushRegistrationFailed
        }
    }
}

extension RemoteApprovalUnavailableDetail {
    init(_ problem: RemoteApprovalAccountProblem) {
        switch problem {
        case .noAccount: self = .noAccount
        case .restricted: self = .restricted
        case .couldNotDetermine: self = .couldNotDetermine
        case .temporarilyUnavailable: self = .temporarilyUnavailable
        }
    }

    init(_ problem: RemoteApprovalPairingProblem) {
        switch problem {
        case .recordCorrupt: self = .recordCorrupt
        case .containerMismatch: self = .containerMismatch
        case .macKeyMissing: self = .macKeyMissing
        case .macKeyMismatch: self = .macKeyMismatch
        case .outdated: self = .outdated
        }
    }
}

/// What `csec remote status` and `csec doctor` say about remote approval. Kept
/// beside the status model so the advice for each cause is tested with it.
public enum RemoteApprovalStatusReport {
    public struct Summary: Equatable, Sendable {
        /// Printed to standard output, one per line.
        public let lines: [String]
        /// False for the causes that need a rebuild or a new pairing; a
        /// temporary account or Keychain condition is not a failure.
        public let succeeded: Bool
    }

    /// The installer for people building from a source checkout.
    public static let installerCommand = PackagePayload.sourceInstallCommand

    /// What `csec remote enable` prints once csecd has pinned the phone. The
    /// key is what the person compares on the phone before Face ID, whichever
    /// way the Mac reaches it; the code is printed either way, as the way to
    /// pair when the offer did not get through.
    public static func enableInstructions(
        macPairingCode: String,
        macPublicKeyX963: Data,
        pairingOfferPublished: Bool
    ) -> [String] {
        let key = RemoteApprovalPairingCode.publicKeyFingerprint(macPublicKeyX963)
        if pairingOfferPublished {
            return [
                "Open Convenient Security on the iPhone: it now shows this Mac to accept.",
                "This Mac's key: \(key). Accept with Face ID only if the iPhone shows the same key.",
                "If the iPhone does not show this Mac, paste this public Mac pairing code there instead:",
                macPairingCode,
            ]
        }
        return [
            "Import this public Mac pairing code in Convenient Security on the iPhone:",
            macPairingCode,
            "This Mac's key: \(key) (the iPhone shows it before you accept)",
        ]
    }

    public static func summary(_ status: RemoteApprovalConfigurationStatus, now: Date = Date()) -> Summary {
        switch status.state {
        case .disabled:
            return Summary(lines: ["csec: iPhone remote approval is off"], succeeded: true)
        case .enabled:
            return Summary(lines: enabledLines(status, now: now), succeeded: true)
        case .unavailable:
            break
        }
        switch status.cause {
        case .unsupportedBuild?:
            return Summary(lines: [
                "csec: iPhone remote approval is unavailable: this csecd build lacks the "
                    + "CloudKit container entitlement, so it cannot reach the iCloud relay",
                "csec: \(PackagePayload.installAdvice)",
            ], succeeded: false)
        case .iCloudAccountUnavailable?:
            return Summary(lines: [
                "csec: iPhone remote approval is paired with \(phone(status)) but unavailable: "
                    + accountCondition(status.detail),
                "csec: \(accountAdvice(status.detail)); until then requests are approved on this Mac only",
            ], succeeded: true)
        case .pairingInvalid?:
            return Summary(lines: [
                "csec: iPhone remote approval is unavailable: the pairing record is unusable ("
                    + pairingCondition(status.detail) + ")",
                "csec: run `csec remote disable`, then pair again with "
                    + "`csec remote enable '<csec-phone-v2:…>'`",
            ], succeeded: false)
        case .keychainUnavailable?:
            return Summary(lines: [
                "csec: iPhone remote approval is unavailable right now: csecd could not read its "
                    + "pairing record from the Keychain" + keychainStatus(status),
                "csec: this is usually transient; run `csec remote status` again "
                    + "(csecd also retries on the next request)",
            ], succeeded: true)
        case nil:
            return Summary(lines: [
                "csec: iPhone remote approval is unavailable (csecd did not say why; "
                    + "it may be older than this csec)",
                "csec: Install the current Convenient Security package so csec and csecd match.",
            ], succeeded: false)
        }
    }

    /// The `csec status` / `csec doctor` row. A development endpoint runs an
    /// unsigned csecd that can never carry the entitlement, so its missing
    /// relay is neutral there rather than a failure.
    public static func doctorRow(
        _ status: RemoteApprovalConfigurationStatus?,
        developmentEndpoint: Bool
    ) -> StatusRow {
        let label = "Remote approval"
        guard let status else {
            return StatusRow(label: label, value: "unavailable", state: .neutral)
        }
        switch status.state {
        case .disabled:
            return StatusRow(label: label, value: "off", state: .neutral)
        case .enabled:
            return enabledRow(status, label: label)
        case .unavailable:
            break
        }
        switch status.cause {
        case .unsupportedBuild?:
            return developmentEndpoint
                ? StatusRow(label: label, value: "unavailable in a development build", state: .neutral)
                : StatusRow(
                    label: label,
                    value: "this csecd build lacks the CloudKit entitlement",
                    state: .bad
                )
        case .iCloudAccountUnavailable?:
            return StatusRow(
                label: label,
                value: "paired, but this Mac's iCloud account is unavailable ("
                    + (status.detail?.rawValue ?? "unknown") + ")",
                state: .warn
            )
        case .pairingInvalid?:
            return StatusRow(
                label: label,
                value: "pairing record unusable (" + (status.detail?.rawValue ?? "unknown") + ")",
                state: .bad
            )
        case .keychainUnavailable?:
            return StatusRow(
                label: label,
                value: "pairing record unreadable right now" + keychainStatus(status),
                state: .warn
            )
        case nil:
            return StatusRow(label: label, value: "unavailable (csecd did not say why)", state: .warn)
        }
    }

    /// Whether the row fails `csec doctor`: every shipped build carries the
    /// CloudKit entitlement, and an unusable pairing silently keeps every
    /// request off the phone until someone pairs again.
    public static func failsDoctor(
        _ status: RemoteApprovalConfigurationStatus?,
        developmentEndpoint: Bool
    ) -> Bool {
        switch status?.cause {
        case .unsupportedBuild?: return !developmentEndpoint
        case .pairingInvalid?: return true
        default: return false
        }
    }

    /// The repair `csec doctor` names for a failing row.
    public static func doctorRepair(_ status: RemoteApprovalConfigurationStatus?) -> String? {
        switch status?.cause {
        case .unsupportedBuild?:
            return "this csecd build lacks the CloudKit container entitlement, so iPhone remote "
                + "approval cannot run. \(PackagePayload.installAdvice)"
        case .pairingInvalid?:
            return "the iPhone remote approval pairing record is unusable ("
                + pairingCondition(status?.detail)
                + "); run `csec remote disable`, then pair the iPhone again"
        default:
            return nil
        }
    }

    /// The enabled state, and what csecd knows about the phone: whether it
    /// confirmed the pairing, its app, and whether it may show alerts.
    static func enabledLines(_ status: RemoteApprovalConfigurationStatus, now: Date = Date()) -> [String] {
        var lines = ["csec: iPhone remote approval is on for \(phone(status))"]
        if status.phoneConfirmed == false {
            lines.append(
                "csec: waiting for the iPhone to confirm the pairing: open Convenient Security on the "
                    + "phone and accept this Mac with Face ID (or paste the Mac pairing code csec remote "
                    + "enable printed). A phone app from another csec version never confirms. \(phoneUpdateAdvice)"
            )
        }
        if let version = status.phoneAppVersion {
            lines.append("csec: iPhone app \(version)")
        }
        if let line = protocolMismatch(status)?.line {
            lines.append("csec: \(line)")
        }
        if let updated = status.phoneStatusUpdatedAtMilliseconds {
            lines.append("csec: the iPhone last reported \(Self.age(sinceMilliseconds: updated, now: now))")
        }
        lines.append(settingsReviewsLine(status))
        if status.phoneNotificationsAuthorized == false {
            lines.append(
                "csec: notifications are off for Convenient Security on the iPhone, so requests "
                    + "appear only when the app is opened; turn them on in the phone's Settings"
            )
        }
        if let problem = alertProblem(status) {
            lines.append("csec: \(problem.line)")
        }
        if status.remoteUnlockEnrolled == false {
            lines.append(
                "csec: the phone-held unlock is not enrolled, so requests that need csec's "
                    + "stored secrets opened stay on this Mac; pair again to enroll it"
            )
        }
        return lines
    }

    static func enabledRow(_ status: RemoteApprovalConfigurationStatus, label: String) -> StatusRow {
        var parts = ["on for \(phone(status))"]
        if let version = status.phoneAppVersion { parts.append("app \(version)") }
        if let row = protocolMismatch(status)?.row {
            parts.append(row)
            return StatusRow(label: label, value: parts.joined(separator: "; "), state: .warn)
        }
        if status.phoneConfirmed == false {
            parts.append("waiting for the iPhone to confirm the pairing")
            return StatusRow(label: label, value: parts.joined(separator: "; "), state: .warn)
        }
        if status.phoneNotificationsAuthorized == false {
            parts.append("notifications off on the iPhone")
            return StatusRow(label: label, value: parts.joined(separator: "; "), state: .warn)
        }
        if let problem = alertProblem(status) {
            parts.append(problem.row)
            return StatusRow(label: label, value: parts.joined(separator: "; "), state: .warn)
        }
        if status.remoteUnlockEnrolled == false {
            parts.append("phone-held unlock not enrolled")
            return StatusRow(label: label, value: parts.joined(separator: "; "), state: .warn)
        }
        // Said either way, but never a warning: every request still reaches
        // this Mac, and `csec remote status` says why and what to do.
        parts.append(settingsReviewsPart(status))
        return StatusRow(label: label, value: parts.joined(separator: "; "), state: .ok)
    }

    private static func settingsReviewsPart(_ status: RemoteApprovalConfigurationStatus) -> String {
        switch status.phoneSettingsReviews {
        case .shown: return "hook acknowledgements reach the iPhone"
        case .notShown, .noPhoneStatus: return "hook acknowledgements stay on this Mac"
        case .notReported: return "csecd did not say whether hook acknowledgements reach the iPhone"
        }
    }

    /// Whether Claude Code hook and rule acknowledgements reach the phone,
    /// said in every case so that a missing answer never reads as a yes.
    private static func settingsReviewsLine(_ status: RemoteApprovalConfigurationStatus) -> String {
        switch status.phoneSettingsReviews {
        case .shown:
            return "csec: the iPhone app reported that it shows Claude Code hook and rule acknowledgements, "
                + "so they reach it as well as this Mac"
        case .notShown:
            return "csec: the iPhone app has not reported that it shows Claude Code hook and rule "
                + "acknowledgements, so they stay on this Mac. An app that shows them reports it with "
                + "its next Face ID approval. \(phoneUpdateAdvice)"
        case .noPhoneStatus:
            return "csec: csecd has no signed status from the iPhone app, so Claude Code hook and rule "
                + "acknowledgements stay on this Mac; the app reports its status with its next Face ID approval"
        case .notReported:
            return "csec: csecd did not say whether the iPhone app shows Claude Code hook and rule "
                + "acknowledgements (it may be older than this csec). Install the current Convenient "
                + "Security package so csec and csecd match."
        }
    }

    /// `csec remote status --json`: csecd's answer as one value-free object
    /// for a program to check, every field present and null where csecd did
    /// not say. It names no phone, key or device (docs/remote-approval.md).
    public struct Document: Encodable, Equatable, Sendable {
        /// A new number means a field changed meaning or went away.
        public static let currentSchema = 1

        public let schema: Int
        public let state: RemoteApprovalConfigurationState
        public let cause: RemoteApprovalUnavailableCause?
        public let phoneConfirmed: Bool?
        public let macProtocolVersion: Int?
        public let phoneProtocolVersion: Int?
        public let phoneStatusUpdatedAtMilliseconds: UInt64?
        public let phoneSettingsReviews: RemoteApprovalPhoneSettingsReviews

        public init(_ status: RemoteApprovalConfigurationStatus) {
            schema = Self.currentSchema
            state = status.state
            cause = status.cause
            phoneConfirmed = status.phoneConfirmed
            macProtocolVersion = status.macProtocolVersion
            phoneProtocolVersion = status.phoneProtocolVersion
            phoneStatusUpdatedAtMilliseconds = status.phoneStatusUpdatedAtMilliseconds
            phoneSettingsReviews = status.phoneSettingsReviews
        }

        private enum CodingKeys: String, CodingKey {
            case schema, state, cause, phoneConfirmed, macProtocolVersion, phoneProtocolVersion
            case phoneStatusUpdatedAtMilliseconds, phoneSettingsReviews
        }

        /// Optionals are written as null rather than left out, so a reader
        /// never has to tell a missing field from a missing answer.
        public func encode(to encoder: Encoder) throws {
            var container = encoder.container(keyedBy: CodingKeys.self)
            try container.encode(schema, forKey: .schema)
            try container.encode(state, forKey: .state)
            try container.encode(cause, forKey: .cause)
            try container.encode(phoneConfirmed, forKey: .phoneConfirmed)
            try container.encode(macProtocolVersion, forKey: .macProtocolVersion)
            try container.encode(phoneProtocolVersion, forKey: .phoneProtocolVersion)
            try container.encode(phoneStatusUpdatedAtMilliseconds, forKey: .phoneStatusUpdatedAtMilliseconds)
            try container.encode(phoneSettingsReviews, forKey: .phoneSettingsReviews)
        }
    }

    /// The document as `csec remote status --json` prints it: one line,
    /// sorted keys.
    public static func json(_ status: RemoteApprovalConfigurationStatus) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return String(decoding: try encoder.encode(Document(status)), as: UTF8.self)
    }

    private static let phoneUpdateAdvice = "For an App Store or TestFlight install, check for a phone app update there. "
        + "For a source build, run \(installerCommand) --only-iphone from the matching checkout."

    /// The phone app reported a protocol other than this Mac's, so its
    /// requests are not ones the phone reads: a warning, never a failure, as
    /// the Mac panel still decides every request.
    private static func protocolMismatch(
        _ status: RemoteApprovalConfigurationStatus
    ) -> (line: String, row: String)? {
        // csecd's own protocol when it said, since csecd is what talks to the
        // phone; this launcher's otherwise.
        let mine = status.macProtocolVersion ?? Int(RemoteApprovalProtocolV3.version)
        guard let theirs = status.phoneProtocolVersion, theirs != mine else { return nil }
        let advice = theirs > mine ? PackagePayload.installAdvice : phoneUpdateAdvice
        return (
            "the iPhone app speaks remote-approval protocol v\(theirs) and this Mac v\(mine), so requests "
                + "stay on this Mac. \(advice)",
            "iPhone app on protocol v\(theirs), this Mac v\(mine)"
        )
    }

    /// "just now", "5 minutes ago", "3 hours ago", "2 days ago": how long
    /// ago the phone's clock said it reported. Information only.
    public static func age(sinceMilliseconds milliseconds: UInt64, now: Date) -> String {
        let seconds = now.timeIntervalSince1970 - Double(milliseconds) / 1_000
        func plural(_ count: Int, _ unit: String) -> String { "\(count) \(unit)\(count == 1 ? "" : "s") ago" }
        switch seconds {
        case ..<120: return "just now"
        case ..<7_200: return plural(Int(seconds / 60), "minute")
        case ..<172_800: return plural(Int(seconds / 3_600), "hour")
        default: return plural(Int(seconds / 86_400), "day")
        }
    }

    /// Why a request would not alert the phone, when it reported it cannot be
    /// alerted: a longer line for `csec remote status`, a short one for the row.
    private static func alertProblem(
        _ status: RemoteApprovalConfigurationStatus
    ) -> (line: String, row: String)? {
        switch status.phoneRequestAlerts {
        case .subscriptionRefused?:
            return (
                "the iPhone is not alerted to requests: iCloud refused its notification "
                    + "subscription, so requests appear only when the app is opened. The iCloud "
                    + "container's Production schema lacks the subscription; see "
                    + "docs/remote-approval.md (CloudKit schema)",
                "iPhone not alerted to requests (iCloud refused its subscription)"
            )
        case .pushRegistrationFailed?:
            return (
                "the iPhone is not alerted to requests: it could not register for push "
                    + "notifications, so requests appear only when the app is opened",
                "iPhone not alerted to requests (push registration failed)"
            )
        case .ready?, nil:
            return nil
        }
    }

    private static func phone(_ status: RemoteApprovalConfigurationStatus) -> String {
        let name = ReviewDisplay.fitted(status.phoneName ?? "paired iPhone", maxBytes: 256)
        let fingerprint = ReviewDisplay.fitted(status.phoneKeyFingerprint ?? "unknown", maxBytes: 64)
        return "\(name.isEmpty ? "paired iPhone" : name) (key \(fingerprint))"
    }

    private static func keychainStatus(_ status: RemoteApprovalConfigurationStatus) -> String {
        status.keychainStatus.map { " (OSStatus \($0))" } ?? ""
    }

    private static func accountCondition(_ detail: RemoteApprovalUnavailableDetail?) -> String {
        switch detail {
        case .noAccount?: return "this Mac is not signed into iCloud"
        case .restricted?: return "iCloud is restricted on this Mac (Screen Time or device management)"
        case .couldNotDetermine?: return "csecd could not determine this Mac's iCloud account status"
        case .temporarilyUnavailable?: return "this Mac's iCloud account is signed in but not ready"
        default: return "this Mac's iCloud account is unavailable"
        }
    }

    private static func accountAdvice(_ detail: RemoteApprovalUnavailableDetail?) -> String {
        switch detail {
        case .restricted?:
            return "allow iCloud for this account in Screen Time, or ask the Mac's administrator"
        case .couldNotDetermine?:
            return "this is usually transient; run `csec remote status` again shortly"
        case .temporarilyUnavailable?:
            return "open System Settings › Apple Account on this Mac and finish any verification it asks for"
        default:
            return "sign into iCloud on this Mac (System Settings › Apple Account) "
                + "with the same Apple Account as the iPhone"
        }
    }

    private static func pairingCondition(_ detail: RemoteApprovalUnavailableDetail?) -> String {
        switch detail {
        case .recordCorrupt?: return "it could not be decoded"
        case .containerMismatch?: return "it names a different iCloud container than this build uses"
        case .macKeyMissing?: return "this Mac's Secure Enclave pairing key is gone"
        case .macKeyMismatch?: return "this Mac's Secure Enclave key is not the one the iPhone pinned"
        case .outdated?: return "an older csec made it, before the iPhone's unlock key was pinned"
        default: return "reason not reported"
        }
    }
}
