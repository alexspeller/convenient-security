import Foundation

// What the signed package installs beyond the app, so that `csec setup` can
// finish an install on a Mac with no checkout: the guarded installers it runs
// through sudo, the sudo review's module and helper they install, and `csec` on
// PATH. `packaging/bin/build-pkg.sh` stages these paths and
// `packaging/pkg-scripts/postinstall` verifies them; `bin/ci` holds the three
// to the same strings.
//
// Value-free: everything here is a path, a link target or a byte comparison
// whose only output is equal or not.

public enum PackagePayload {
    static let sourceInstallCommand = "./packaging/bin/build-and-install.sh"
    public static let installAdvice = "Install the current Convenient Security package. "
        + "For a source build, run \(sourceInstallCommand) from your checkout."

    /// Root-owned, beside the language bridge, below parents the login user
    /// cannot replace: root runs these installers.
    public static let supportDirectory = "/Library/Application Support/ConvenientSecurity"
    public static let codexHookInstaller = supportDirectory + "/libexec/install-codex-hook.sh"
    public static let sudoReviewInstaller = supportDirectory + "/libexec/install-sudo-review.sh"
    public static let sudoModule = supportDirectory + "/sudo-review/pam_csec_sudo.so"
    public static let sudoHelper = supportDirectory + "/sudo-review/csec-sudo-review"
    /// `/usr/local/bin` is in the default `/etc/paths`.
    public static let commandLinkPath = "/usr/local/bin/csec"

    /// Whether `path` is a regular file (not a link) owned by root and writable
    /// by no one else, as the package installs it. Setup runs only such an
    /// installer through sudo.
    public static func isRootOwnedFile(_ path: String) -> Bool {
        var info = stat()
        guard path.withCString({ lstat($0, &info) }) == 0 else { return false }
        return (info.st_mode & S_IFMT) == S_IFREG && info.st_uid == 0 && (info.st_mode & 0o022) == 0
    }
}

/// Whether `csec` on PATH is the package's link to the installed launcher.
public enum CommandLinkState: Sendable, Equatable {
    /// A symlink naming the installed launcher.
    case linked
    /// Nothing there: the package was not installed, or the link was removed.
    case missing
    /// A symlink naming something else; the package leaves it alone.
    case linksElsewhere(String)
    /// Another file holds the name; the package leaves it alone.
    case otherFile

    public static func inspect(
        linkPath: String = PackagePayload.commandLinkPath,
        launcherPath: String = CodingAgentSetup.installedLauncherPath
    ) -> CommandLinkState {
        var info = stat()
        guard linkPath.withCString({ lstat($0, &info) }) == 0 else { return .missing }
        guard (info.st_mode & S_IFMT) == S_IFLNK else { return .otherFile }
        guard let target = try? FileManager.default.destinationOfSymbolicLink(atPath: linkPath) else {
            return .otherFile
        }
        return target == launcherPath ? .linked : .linksElsewhere(target)
    }

    /// Only a missing link is the install's own defect; a name something else
    /// holds was left alone on purpose.
    public var failsDoctor: Bool { self == .missing }

    public var rowValue: String {
        switch self {
        case .linked: return "\(PackagePayload.commandLinkPath) runs the installed csec"
        case .missing: return "\(PackagePayload.commandLinkPath) missing; reinstall the package"
        case let .linksElsewhere(target):
            return "\(PackagePayload.commandLinkPath) links to \(target), not the installed csec"
        case .otherFile: return "\(PackagePayload.commandLinkPath) is another program, not csec"
        }
    }
}

/// Whether the installed sudo review is the build the package carries. A
/// package upgrade replaces the payload but not the installed integration,
/// which only the guarded installer replaces (after its live check).
public enum SudoReviewPayloadMatch: Sendable, Equatable {
    case matches
    /// The installed module or helper is not the package's build.
    case differs
    /// No package payload to compare against (a development build).
    case noPackagePayload

    public static func compare(
        installedModule: String = SudoIntegrationInspection.modulePath,
        installedHelper: String = SudoIntegrationInspection.helperPath,
        packageModule: String = PackagePayload.sudoModule,
        packageHelper: String = PackagePayload.sudoHelper
    ) -> SudoReviewPayloadMatch {
        let files = FileManager.default
        guard files.fileExists(atPath: packageModule), files.fileExists(atPath: packageHelper) else {
            return .noPackagePayload
        }
        return files.contentsEqual(atPath: installedModule, andPath: packageModule)
            && files.contentsEqual(atPath: installedHelper, andPath: packageHelper) ? .matches : .differs
    }
}

/// What `csec setup` offers for the sudo review: the guarded installer in the
/// package, run through sudo, installs or replaces the module and helper and
/// keeps them only after a live sudo the new helper approved. That approval
/// needs a touch, so nothing is offered while Touch ID cannot take one.
public enum SetupSudoReviewOffer: Sendable, Equatable {
    /// Installed, sound and (when there is a package to compare with) the
    /// package's build: nothing to do.
    case current
    /// Not installed; the package can install it.
    case install
    /// Installed and sound, but not the package's build.
    case update
    /// Installed but will not hand off as it should; reinstalling repairs it.
    case repair(SudoIntegrationState)
    /// Something to install or replace, but the live check could not be
    /// approved without Touch ID.
    case needsTouchID(TouchIDReadiness)
    /// Something to install or replace, and no package payload to do it with:
    /// a development build, installed from a checkout.
    case noPackage(SudoIntegrationState)

    public static func decide(
        state: SudoIntegrationState,
        payload: SudoReviewPayloadMatch,
        packageInstallerPresent: Bool,
        touchID: TouchIDReadiness
    ) -> SetupSudoReviewOffer {
        let wanted: SetupSudoReviewOffer
        switch state {
        case .healthy:
            guard payload == .differs else { return .current }
            wanted = .update
        case .notInstalled:
            wanted = .install
        case .helperSignatureUnreadable:
            // Undetermined, not a defect: reinstalling on a guess would ask
            // for a touch with nothing known to be wrong.
            return .current
        default:
            wanted = .repair(state)
        }
        guard packageInstallerPresent, payload != .noPackagePayload else { return .noPackage(state) }
        guard touchID.canApprove else { return .needsTouchID(touchID) }
        return wanted
    }
}
