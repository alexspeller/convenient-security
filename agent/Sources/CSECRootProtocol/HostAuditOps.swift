import Foundation
import CryptoKit

// Wire types for the host-posture audit's privileged surface. These live in
// CSECRootProtocol so the minimal root helper (csec-rootd) can decode them
// without linking the full agent module. They are a **closed allow-list**: the
// only privileged reads and mutations the audit can ask the root helper to
// perform. There is deliberately no "run this command as root" — every case
// maps, inside CSECRootServer, to one fixed, audited command/syscall.
//
// Value-free discipline: a read returns bounded command output that the *agent*
// (never this protocol layer, never a log) parses into a value-free finding.

/// A privileged, read-only host query. Each case maps to exactly one fixed
/// root-run command in `HostOpsExecutor`.
public enum HostRootRead: String, Codable, Sendable, CaseIterable, Equatable {
    /// Sharing services enabled/disabled state (Remote Login, ARD, SMB, …).
    case sharingServices
    /// `firmwarepasswd -check` (Intel) / owner-passcode note (Apple Silicon).
    case firmwarePassword
    /// System-scope configuration profiles (`profiles show -all`).
    case configurationProfiles
    /// Root account enable/disable authority (`dscl . -read /Users/root …`).
    case rootAccount
    /// `sudo` posture: tty_tickets, timestamp_timeout, NOPASSWD, sudoers.d.
    case sudoers
    /// Account password policy (`pwpolicy -getaccountpolicies`).
    case passwordPolicy
    /// Network-time on + configured server (`systemsetup -getusingnetworktime`).
    case networkTime
    /// Time Machine destinations + per-destination encryption.
    case timeMachineDestinations
    /// Location Services master enable flag (owned by `locationd`).
    case locationServices
    /// launchd overrides that could re-enable an OS-disabled service.
    case launchdOverrides
    /// Crash/diagnostic auto-submission to Apple.
    case crashReporterSubmission
    /// Background Task Management login/daemon items (`sfltool dumpbtm`).
    case backgroundTaskManagement
}

/// A sharing daemon whose state a `.setSharingService` change can toggle.
public enum HostSharingService: String, Codable, Sendable, CaseIterable, Equatable {
    case remoteLogin            // SSH
    case remoteManagement       // ARD
    case screenSharing
    case fileSharing            // SMB/AFP
    case printerSharing
    case remoteAppleEvents
    case internetSharing
    case contentCaching
    case mediaSharing
}

/// A `com.apple.SoftwareUpdate` auto-delivery flag (gates XProtect/Gatekeeper
/// signature + Rapid Security Response delivery).
public enum HostSoftwareUpdateFlag: String, Codable, Sendable, CaseIterable, Equatable {
    case configDataInstall          // ConfigDataInstall — XProtect/Gatekeeper data
    case criticalUpdateInstall      // CriticalUpdateInstall — Rapid Security Responses
    case automaticCheckEnabled
    case automaticDownload
}

/// A specific known-dangerous `boot-args` token the guarded HA-A03 remediation
/// may clear. Only these exact tokens are ever removed; anything unrecognized is
/// surfaced but never auto-cleared.
public enum HostDangerousBootArg: String, Codable, Sendable, CaseIterable, Equatable {
    case amfiGetOutOfMyWay          // amfi_get_out_of_my_way=…
    case amfiDisable                // amfi=0x…
    case csEnforcementDisable       // cs_enforcement_disable
    case libraryValidationDisable   // amfi_allow_any_signature / -library validation off
    case arm64ePreviewABI           // -arm64e_preview_abi

    /// The literal token prefix as it appears in `nvram boot-args`.
    public var tokenPrefix: String {
        switch self {
        case .amfiGetOutOfMyWay: return "amfi_get_out_of_my_way"
        case .amfiDisable: return "amfi"
        case .csEnforcementDisable: return "cs_enforcement_disable"
        case .libraryValidationDisable: return "amfi_allow_any_signature"
        case .arm64ePreviewABI: return "-arm64e_preview_abi"
        }
    }
}

/// A reversible, allow-listed privileged mutation. Every case is safe and
/// reversible; the batched review (one Touch ID) authorizes a selected subset,
/// and each applied change is digest-bound to its own value-free representation.
public enum HostRootChange: Codable, Sendable, Equatable, Hashable {
    /// HA-C01 — turn the inbound Application Firewall global state on.
    case enableApplicationFirewall
    /// HA-C02 — firewall stealth mode.
    case setFirewallStealthMode(Bool)
    /// HA-C02 — firewall connection logging.
    case setFirewallLogging(Bool)
    /// HA-C02 — stop auto-allowing signed/downloaded software through the firewall.
    case setFirewallAllowSigned(Bool)
    /// HA-C05 — enable/disable one sharing service.
    case setSharingService(HostSharingService, enabled: Bool)
    /// HA-B04 — one software-update auto-delivery flag.
    case setSoftwareUpdateFlag(HostSoftwareUpdateFlag, enabled: Bool)
    /// HA-G01 — remove the `autoLoginUser` key.
    case removeAutoLoginUser
    /// HA-G01 — set `DisableFDEAutoLogin`.
    case setDisableFDEAutoLogin(Bool)
    /// HA-G04 — disable the root account.
    case disableRootAccount
    /// HA-G05 — disable the guest account.
    case disableGuestAccount
    /// HA-G08 — install Touch ID for `sudo` via `/etc/pam.d/sudo_local`.
    case installSudoTouchID
    /// HA-I01 — enable network time.
    case enableNetworkTime
    /// HA-A03 — clear one known-dangerous boot-args token (guarded).
    case clearBootArgsToken(HostDangerousBootArg)

    /// Stable digest binding this exact change, using the same encoding the rest
    /// of the protocol uses for plan/decision binding (sorted keys, no slash
    /// escaping, SHA-256 hex). The root helper independently recomputes this and
    /// requires equality before applying — it never trusts the caller's pre-image.
    public func digest() throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(self)
        return SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }

    /// A short, value-free label for the change (report + review display).
    public var summary: String {
        switch self {
        case .enableApplicationFirewall: return "Enable the inbound application firewall"
        case let .setFirewallStealthMode(on): return on ? "Enable firewall stealth mode" : "Disable firewall stealth mode"
        case let .setFirewallLogging(on): return on ? "Enable firewall logging" : "Disable firewall logging"
        case let .setFirewallAllowSigned(on): return on ? "Auto-allow signed software through the firewall" : "Stop auto-allowing signed software through the firewall"
        case let .setSharingService(service, enabled): return "\(enabled ? "Enable" : "Disable") sharing service: \(service.rawValue)"
        case let .setSoftwareUpdateFlag(flag, enabled): return "\(enabled ? "Enable" : "Disable") software-update flag: \(flag.rawValue)"
        case .removeAutoLoginUser: return "Remove automatic login"
        case let .setDisableFDEAutoLogin(on): return on ? "Disable FileVault auto-login" : "Allow FileVault auto-login"
        case .disableRootAccount: return "Disable the root account"
        case .disableGuestAccount: return "Disable the guest account"
        case .installSudoTouchID: return "Enable Touch ID for sudo (/etc/pam.d/sudo_local)"
        case .enableNetworkTime: return "Enable network time synchronization"
        case let .clearBootArgsToken(token): return "Clear boot-args token: \(token.tokenPrefix)"
        }
    }
}

/// The value-free result of a privileged read or apply. `output` is bounded
/// command stdout intended for the verified agent to parse; `applied` reports a
/// mutation outcome.
public struct HostHelperResult: Codable, Sendable, Equatable {
    public let exitCode: Int32
    /// Bounded stdout (UTF-8, lossy). For reads only; empty for applies.
    public let output: String
    /// True when a `hostApply` mutation completed successfully.
    public let applied: Bool

    public init(exitCode: Int32, output: String = "", applied: Bool = false) {
        self.exitCode = exitCode
        self.output = output
        self.applied = applied
    }
}
