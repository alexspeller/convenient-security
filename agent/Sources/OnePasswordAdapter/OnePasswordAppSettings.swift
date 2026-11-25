import Foundation

/// Reads value-free 1Password application preferences that affect how csec holds
/// its desktop-integration session. This only ever reads booleans and paths from
/// 1Password's own settings file — never a vault, item, or secret value.
public enum OnePasswordAppSettings {
    /// 1Password's settings file inside its group container. Value-free JSON with
    /// flat, dotted top-level keys (e.g. `security.autolock.onDeviceLock`).
    public static var defaultSettingsPath: String {
        (NSHomeDirectory() as NSString).appendingPathComponent(
            "Library/Group Containers/2BUA8C4S2C.com.1password/Library/Application Support/1Password/Data/settings/settings.json"
        )
    }

    /// Whether 1Password locks itself when the Mac's screen locks
    /// (`security.autolock.onDeviceLock`).
    ///
    /// When true, a screen lock revokes every desktop-integration authorization,
    /// so csec must suspend its keepalive — a ping against a locked app could only
    /// re-authorize, which is a prompt. When false, the session survives the lock
    /// and csec keeps it warm instead of dropping it and re-authorizing (a prompt)
    /// on the next request.
    ///
    /// Defaults to **true** whenever the setting cannot be read (file missing,
    /// unreadable, malformed, or key absent): the safe assumption is that
    /// 1Password does lock with the device — that is its own default, and it
    /// matches csec's prior unconditional suspend, so an unreadable setting never
    /// makes csec *less* cautious than before.
    public static func locksOnDeviceLock(settingsPath: String = defaultSettingsPath) -> Bool {
        guard let data = FileManager.default.contents(atPath: settingsPath),
              let object = try? JSONSerialization.jsonObject(with: data),
              let settings = object as? [String: Any],
              let value = settings["security.autolock.onDeviceLock"] as? Bool
        else { return true }
        return value
    }

    /// Whether 1Password locks itself once the Mac has been idle for a while
    /// (`security.autolock.minutes`).
    public enum IdleLock: Sendable, Equatable {
        /// 1Password stores -1 for its "Never" choice.
        case never
        case after(minutes: Int)
        /// The setting could not be read as one of the above.
        case unknown
    }

    /// Reads 1Password's idle auto-lock (`security.autolock.minutes`).
    ///
    /// An idle lock revokes every desktop-integration authorization while the
    /// screen stays unlocked, so a keepalive ping after one re-authorizes,
    /// which is a prompt. `unknown` whenever the value is not a definite
    /// answer (file missing, unreadable, malformed, key absent, not an
    /// integer, or zero, which 1Password does not document): callers treat it
    /// as idle-locking, the cautious reading.
    public static func idleLock(settingsPath: String = defaultSettingsPath) -> IdleLock {
        guard let data = FileManager.default.contents(atPath: settingsPath),
              let object = try? JSONSerialization.jsonObject(with: data),
              let settings = object as? [String: Any],
              let number = settings["security.autolock.minutes"] as? NSNumber,
              // JSON true would otherwise bridge to 1.
              CFGetTypeID(number) != CFBooleanGetTypeID(),
              let minutes = Int(exactly: number.doubleValue)
        else { return .unknown }
        if minutes == -1 { return .never }
        if minutes > 0 { return .after(minutes: minutes) }
        return .unknown
    }
}
