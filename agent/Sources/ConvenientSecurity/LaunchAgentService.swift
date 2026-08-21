import Foundation
import ServiceManagement

/// Where the agent stands with launchd, in terms the CLI can print without
/// importing ServiceManagement.
public enum LaunchAgentStatus: Sendable, Equatable {
    /// Not registered — `csec install` will register it.
    case notRegistered
    /// Registered and allowed to run; launchd starts it at login.
    case enabled
    /// Registered but the user must approve it in System Settings before it runs.
    case requiresApproval
    /// launchd reports no such job. In practice this is also the state *before the
    /// first* `register()` — so it usually just means "not installed yet". It also
    /// appears if `csec` isn't running from inside the installed `.app` (then the
    /// bundled LaunchAgent plist can't be found).
    case notFound
    /// A status this build doesn't recognise.
    case unknown

    public var description: String {
        switch self {
        case .notRegistered: return "not registered"
        case .enabled: return "enabled — starts at login"
        case .requiresApproval: return "registered, awaiting your approval in System Settings › General › Login Items"
        case .notFound: return "not installed (run: csec install) — or csec isn't running from inside the installed .app bundle"
        case .unknown: return "unknown"
        }
    }

    public var needsApproval: Bool { self == .requiresApproval }
}

/// Registers / unregisters `csecd` as a per-user launchd **LaunchAgent** (never a
/// daemon — the Secure Enclave, the data-protection keychain, and Touch ID are all
/// login-session-only). Uses `SMAppService.agent`, whose plist SMAppService
/// resolves relative to the **calling process's** `Bundle.main` — so `csec` must
/// run from inside the signed `.app` for install/uninstall to see the plist.
public enum LaunchAgentService {
    /// Must match the filename shipped at `Contents/Library/LaunchAgents/`.
    public static let plistName = "com.alexspeller.convenient-security.plist"

    private static var service: SMAppService {
        SMAppService.agent(plistName: plistName)
    }

    /// Register the LaunchAgent, returning the resulting status (often
    /// `.requiresApproval` on first install — that's normal on modern macOS).
    @discardableResult
    public static func install() throws -> LaunchAgentStatus {
        try service.register()
        return status()
    }

    /// Unregister the LaunchAgent; a running instance is terminated by launchd.
    public static func uninstall() throws {
        try service.unregister()
    }

    public static func status() -> LaunchAgentStatus {
        switch service.status {
        case .notRegistered: return .notRegistered
        case .enabled: return .enabled
        case .requiresApproval: return .requiresApproval
        case .notFound: return .notFound
        @unknown default: return .unknown
        }
    }
}
