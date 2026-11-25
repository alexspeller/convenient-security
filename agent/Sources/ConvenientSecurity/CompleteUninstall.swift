import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// `csec uninstall --all`: where the package's own uninstaller lives, the
/// checks before sudo runs it as root, and what stays afterwards.
///
/// The uninstaller is a script the package installs beside the language
/// bridge, under directories only root can write, so what sudo runs as root is
/// what the signed package put there. `/Applications` is admin-group writable,
/// which is why it does not live in the app bundle.
public enum CompleteUninstall {
    public static let bridgeDirectory = "/Library/Application Support/ConvenientSecurity"
    public static let scriptPath = bridgeDirectory + "/libexec/uninstall-csec.sh"
    /// The app carries the same script, sealed by its signature, so doctor can
    /// tell a stale or altered installed copy from the one this build shipped.
    public static let bundledCopyPath =
        "/Applications/ConvenientSecurity.app/Contents/Resources/uninstall/uninstall-csec.sh"

    /// Whether the package's uninstaller is in place, for `csec status` and
    /// `csec doctor`.
    public enum InstalledState: Sendable, Equatable {
        case installed
        /// Missing, unprotected or unreadable: the reason.
        case unusable(String)
        /// In place, but not the copy the installed app carries.
        case stale
    }

    public static func installedState(
        path: String = scriptPath,
        bundledCopy: String = bundledCopyPath,
        owner: uid_t = 0
    ) -> InstalledState {
        if let problem = scriptProblem(path: path, owner: owner) { return .unusable(problem) }
        guard let installed = FileManager.default.contents(atPath: path) else {
            return .unusable("\(path) cannot be read")
        }
        guard let bundled = FileManager.default.contents(atPath: bundledCopy) else {
            return .unusable("the app's copy \(bundledCopy) cannot be read")
        }
        return installed == bundled ? .installed : .stale
    }

    /// Why the uninstaller at `path` must not be run as root, or nil when it
    /// may: it must be a regular file (never a symlink) with one link, and it
    /// and every directory above it must belong to root (or `owner`, which
    /// only tests set) and be writable by no one else.
    public static func scriptProblem(path: String = scriptPath, owner: uid_t = 0) -> String? {
        guard path.hasPrefix("/") else { return "\(path) is not an absolute path" }
        var info = stat()
        guard lstat(path, &info) == 0 else {
            return "\(path) is missing, so this csec was not installed from the package"
        }
        guard (info.st_mode & S_IFMT) == S_IFREG, info.st_nlink == 1 else {
            return "\(path) is not a regular file"
        }
        if let problem = protectionProblem(path, info, owner: owner) { return problem }
        var directory = (path as NSString).deletingLastPathComponent
        while true {
            var parent = stat()
            guard lstat(directory, &parent) == 0, (parent.st_mode & S_IFMT) == S_IFDIR else {
                return "\(directory) is not a directory"
            }
            if let problem = protectionProblem(directory, parent, owner: owner) { return problem }
            if directory == "/" { return nil }
            directory = (directory as NSString).deletingLastPathComponent
        }
    }

    private static func protectionProblem(_ path: String, _ info: stat, owner: uid_t) -> String? {
        guard info.st_uid == 0 || info.st_uid == owner else { return "\(path) does not belong to root" }
        guard info.st_mode & 0o022 == 0 else { return "\(path) can be changed by other users" }
        return nil
    }

    public struct UpdateCacheError: Error, LocalizedError {
        public let path: String
        public var errorDescription: String? { "\(path) is not a directory" }
    }

    /// `--all`, once csecd has stopped: delete the signed release manifest and
    /// check state csecd keeps for update notices (`ReleaseManifestStore`), and
    /// its parent folder when nothing else is left there. Nothing in it is a
    /// secret, and a reinstall fetches it again. A symlink in its place is
    /// refused, so nothing outside the cache is deleted through it. True when
    /// the cache was there and is gone.
    public static func removeUpdateCache(
        directory: URL = ReleaseManifestStore.defaultDirectory()
    ) throws -> Bool {
        var info = stat()
        guard lstat(directory.path, &info) == 0 else { return false }
        guard (info.st_mode & S_IFMT) == S_IFDIR else { throw UpdateCacheError(path: directory.path) }
        try FileManager.default.removeItem(at: directory)
        // rmdir removes only an empty directory.
        _ = rmdir(directory.deletingLastPathComponent().path)
        return true
    }

    /// What `csec uninstall --all` leaves in place, one line each, for its
    /// closing list. Secrets and where they are kept stay unless the user
    /// removes them; the rest is either outside this Mac or harmless.
    public static let keptAfterCompleteUninstall: [String] = [
        "your secrets and where they are kept: \(CsecdUninstaller.keptSummary). Files you protected "
            + "still hold csec references, and values in csec's native stores can be read only through "
            + "csec, so a reinstall picks them all up again",
        "the backup folder in iCloud Drive, which its recovery key still restores",
        "Google credential files and the gcloud shell function",
        "Codex's csec permission profile in ~/.codex/config.toml, which keeps working without csec",
        "the approval app on your iPhone: delete it there",
        "csec's settings in other accounts on this Mac: csec uninstall in each removes them, "
            + "before --all removes the app",
    ]
}
