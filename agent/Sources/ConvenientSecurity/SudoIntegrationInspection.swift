import Foundation
import CSECBuildIdentity

// Read-only inspection of the *installed* sudo authorization-review integration.
//
// The PAM module (`packaging/sudo/pam_csec_sudo.c`) is installed into
// /etc/pam.d/sudo_local and, before it will hand a sudo prompt to csec's review
// dialog, it requires the helper at /usr/local/libexec/csec-sudo-review to be a
// root-owned, non-group/other-writable regular file below a root-owned path, and
// requires the spawned process to sign as the product's sudo-review identifier
// (`ProductCodeIdentity.sudoReviewHelperIdentifier`) with the hardened runtime.
// This type re-checks those same properties from the outside, so "healthy" means
// "the module will actually hand off to csec's dialog" rather than merely "a PAM
// line exists".
//
// It exists because nothing noticed a *stale* install: reinstalling the app does
// not touch the sudo helper, so a pre-release helper kept drawing this Mac's sudo
// dialog for two weeks while the sudo PAM check (HA-G08) passed throughout.
//
// The inspection is pure and injectable — it reads only through `FileInspecting`
// and `CommandRunning` — so the host audit (HA-G11) and `csec doctor` share one
// implementation and both can be exercised against fakes.
//
// Value-free discipline: the module image is read only to test it for two fixed,
// NUL-terminated literals; no byte of it is ever echoed. Every string this type
// produces carries paths, code-signing identifiers, and CDHashes — state, never
// a credential value.

/// What an inspection of the installed sudo review integration found.
public enum SudoIntegrationState: Sendable, Equatable {
    /// No active csec line in /etc/pam.d/sudo_local — the integration is not
    /// installed, and nothing below it is checked or reported.
    case notInstalled
    /// The module and helper are installed, protected, and current.
    case healthy(codeDirectoryHash: String)

    case moduleMissing
    case moduleUnsafe(reason: String)
    case moduleUnreadable
    case deadlineGuardMissing
    /// The installed module was built against a different helper path/identifier
    /// than this source tree's; `spike` marks the known pre-release build.
    case moduleNamesAnotherHelper(spike: Bool)

    case helperMissing
    case helperUnsafePath(reason: String)
    case helperSignatureInvalid
    /// codesign could not be run or produced nothing recognizable — undetermined,
    /// not a defect.
    case helperSignatureUnreadable
    case helperIdentifierMismatch(found: String)
    case helperNotHardened
    /// Hardened and correctly identified, but not signed by csec's team: an
    /// install older than the phone-capable helper. The PAM module still runs
    /// it, but csecd admits only the team-signed helper, so its sudo reviews
    /// never reach the paired iPhone.
    case helperNotTeamSigned

    public var isHealthy: Bool {
        if case .healthy = self { return true }
        return false
    }

    /// True when the integration is active but will not hand off to csec's
    /// review dialog (or will hand off to something other than this source tree).
    /// `notInstalled`, `healthy`, and the undetermined signature read are not
    /// defects.
    public var isDefect: Bool {
        switch self {
        case .notInstalled, .healthy, .helperSignatureUnreadable: return false
        default: return true
        }
    }

    /// A compact value-free phrase for the `csec doctor` / `csec status` row.
    /// `StatusRenderer` gives a row value about 53 columns on an 80-column
    /// terminal, so the row names the defect and the full `summary` carries the
    /// paths and identifiers into the audit evidence.
    public var rowValue: String {
        switch self {
        case .notInstalled: return "not installed"
        case let .healthy(hash): return "installed and hardened (CDHash \(hash.prefix(16))…)"
        case .moduleMissing: return "PAM module missing"
        case .moduleUnsafe: return "PAM module path not protected"
        case .moduleUnreadable: return "PAM module unreadable"
        case .deadlineGuardMissing: return "PAM deadline guard missing or misordered"
        case let .moduleNamesAnotherHelper(spike):
            return spike
                ? "PAM module names the pre-release spike helper"
                : "PAM module names another helper build"
        case .helperMissing: return "review helper missing"
        case .helperUnsafePath: return "review helper path not protected"
        case .helperSignatureInvalid: return "review helper signature invalid"
        case .helperSignatureUnreadable: return "review helper signature unreadable"
        case .helperIdentifierMismatch: return "review helper signs as another identifier"
        case .helperNotHardened: return "review helper not hardened"
        case .helperNotTeamSigned: return "review helper not team-signed (no iPhone approval)"
        }
    }

    /// The full value-free description: the paths, identifiers, and CDHash that
    /// say exactly what is installed and what was expected. Used in the HA-G11
    /// evidence sentence; the status row uses `rowValue` instead.
    public var summary: String {
        let helper = SudoIntegrationInspection.helperPath
        let identifier = SudoIntegrationInspection.helperIdentifier
        let module = SudoIntegrationInspection.modulePath
        switch self {
        case .notInstalled:
            return "the csec sudo integration is not active in \(SudoIntegrationInspection.pamConfigurationPath)"
        case let .healthy(hash):
            return "helper installed, hardened, identifier \(identifier) (CDHash \(hash))"
        case .moduleMissing:
            return "the active sudo_local line names \(module) but no module is installed there"
        case let .moduleUnsafe(reason):
            return "the installed PAM module is not protected — \(reason)"
        case .moduleUnreadable:
            return "the installed PAM module at \(module) could not be read"
        case .deadlineGuardMissing:
            return "sudo_local must place the requisite csec review_guard immediately after its sufficient review "
                + "and before pam_tid, using a module with guard support. Run csec setup and accept the sudo review step."
        case let .moduleNamesAnotherHelper(spike):
            return spike
                ? "the installed PAM module names the pre-release spike review helper, not \(helper) (identifier \(identifier))"
                : "the installed PAM module does not name \(helper) and identifier \(identifier), so it was built from other sources"
        case .helperMissing:
            return "no review helper is installed at \(helper), so sudo falls back to the stock prompt"
        case let .helperUnsafePath(reason):
            return "the review helper path is not protected — \(reason); the PAM module refuses to spawn it"
        case .helperSignatureInvalid:
            return "the review helper at \(helper) fails codesign --verify --strict"
        case .helperSignatureUnreadable:
            return "the code signature of \(helper) could not be read"
        case let .helperIdentifierMismatch(found):
            return "the review helper signs as \(found), not \(identifier)"
        case .helperNotHardened:
            return "the review helper at \(helper) is signed without the hardened runtime"
        case .helperNotTeamSigned:
            return "the review helper at \(helper) is not signed by team \(SudoIntegrationInspection.teamIdentifier), "
                + "so csecd will not relay its sudo reviews to the paired iPhone. Run csec setup and accept the sudo review step."
        }
    }
}

public enum SudoIntegrationInspection {
    /// The team the installed helper must be signed by (`ProductCodeIdentity`).
    public static let teamIdentifier = CSECBuildIdentity.teamIdentifier
    /// The canonical constants, mirroring `packaging/sudo/pam_csec_sudo.c`.
    public static let pamConfigurationPath = "/etc/pam.d/sudo_local"
    public static let modulePath = "/usr/local/lib/pam/pam_csec_sudo.so"
    public static let helperPath = "/usr/local/libexec/csec-sudo-review"
    public static let helperIdentifier = CSECBuildIdentity.named("sudo-review")
    /// The token an active sudo_local line must contain for the integration to be
    /// in play at all (the line may name the module by any path).
    public static let moduleToken = "pam_csec_sudo.so"

    /// The Aug 2026 pre-release build, named explicitly so a stale install says
    /// so rather than reporting a generic mismatch.
    public static let spikeHelperPath = helperPath + "-spike"
    public static let spikeIdentifier = helperIdentifier + "-spike"

    /// Directory chains the PAM module itself requires to be root-owned and not
    /// group/other-writable before it will spawn the helper, plus the equivalent
    /// chain guarding the module image PAM loads as root.
    public static let helperDirectories = ["/", "/usr", "/usr/local", "/usr/local/libexec"]
    public static let moduleDirectories = ["/", "/usr", "/usr/local", "/usr/local/lib", "/usr/local/lib/pam"]

    /// The module is ~190 KB; the bound is generous enough that a larger build
    /// still gets read whole and small enough to stay a bounded read.
    static let moduleReadLimit = 8 * 1_024 * 1_024
    static let configurationReadLimit = 65_536

    public static let verifyCommandLabel = "codesign.verify.sudoReviewHelper"
    public static let displayCommandLabel = "codesign.display.sudoReviewHelper"

    /// Inspect the installed integration. Returns `.notInstalled` — and reads
    /// nothing further — when no active csec line is present in sudo_local.
    public static func inspect(
        files: any FileInspecting,
        commands: any CommandRunning
    ) async -> SudoIntegrationState {
        guard isActive(files: files) else { return .notInstalled }

        guard hasDeadlineGuard(files: files) else { return .deadlineGuardMissing }

        if let state = inspectModule(files: files) { return state }
        if let state = inspectHelperPath(files: files) { return state }
        return await inspectHelperSignature(commands: commands)
    }

    /// Whether /etc/pam.d/sudo_local holds a non-comment line naming the csec
    /// module. Same tolerant parse as HA-G08 uses for `pam_tid.so`.
    public static func isActive(files: any FileInspecting) -> Bool {
        guard let configuration = files.readText(
            pamConfigurationPath, maxBytes: configurationReadLimit) else { return false }
        return configuration
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .contains { !$0.hasPrefix("#") && $0.contains(moduleToken) }
    }

    /// An expired sufficient factor cannot stop OpenPAM on its own. The
    /// requisite guard must be its next active factor, before stock recovery.
    private static func hasDeadlineGuard(files: any FileInspecting) -> Bool {
        guard let text = files.readText(pamConfigurationPath, maxBytes: configurationReadLimit) else {
            return false
        }
        let entries = text.split(separator: "\n").map { line in
            line.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false)[0]
                .split(whereSeparator: { $0.isWhitespace }).map(String.init)
        }.filter { !$0.isEmpty }
        let review = ["auth", "sufficient", modulePath]
        let guardEntry = ["auth", "requisite", modulePath, "review_guard"]
        let csecEntries = entries.indices.filter { entries[$0].contains(modulePath) }
        guard csecEntries.count == 2, let index = csecEntries.first,
              index + 1 < entries.count, entries[index] == review,
              entries[index + 1] == guardEntry else { return false }
        let touchID = entries.indices.first { position in
            let entry = entries[position]
            return entry.count >= 3 && entry[0] == "auth" && entry[1] == "sufficient"
                && (entry[2] as NSString).lastPathComponent == "pam_tid.so"
        }
        return touchID.map { $0 > index + 1 } ?? false
    }

    // MARK: module

    private static func inspectModule(files: any FileInspecting) -> SudoIntegrationState? {
        guard files.fileExists(modulePath) else { return .moduleMissing }
        for directory in moduleDirectories {
            if let reason = unsafeDirectory(directory, files: files) {
                return .moduleUnsafe(reason: reason)
            }
        }
        if let reason = unsafeFile(modulePath, files: files, requireOwnerExecute: false) {
            return .moduleUnsafe(reason: reason)
        }
        guard let image = files.readText(modulePath, maxBytes: moduleReadLimit) else {
            return .moduleUnreadable
        }
        // Compare over UTF-8 bytes, not graphemes: the image is binary, so the
        // decoded string holds replacement characters whose cluster boundaries
        // must not be allowed to affect a literal match. The trailing NUL is
        // what makes "…/csec-sudo-review" fail to match "…/csec-sudo-review-spike".
        let bytes = Array(image.utf8)
        let namesHelper = contains(bytes, Array((helperPath + "\0").utf8))
        let namesIdentifier = contains(bytes, Array((helperIdentifier + "\0").utf8))
        guard namesHelper, namesIdentifier else {
            let spike = contains(bytes, Array((spikeHelperPath + "\0").utf8))
                || contains(bytes, Array((spikeIdentifier + "\0").utf8))
            return .moduleNamesAnotherHelper(spike: spike)
        }
        guard contains(bytes, Array("review_guard\0".utf8)) else {
            return .deadlineGuardMissing
        }
        return nil
    }

    // MARK: helper

    private static func inspectHelperPath(files: any FileInspecting) -> SudoIntegrationState? {
        guard files.fileExists(helperPath) else { return .helperMissing }
        for directory in helperDirectories {
            if let reason = unsafeDirectory(directory, files: files) {
                return .helperUnsafePath(reason: reason)
            }
        }
        if let reason = unsafeFile(helperPath, files: files, requireOwnerExecute: true) {
            return .helperUnsafePath(reason: reason)
        }
        return nil
    }

    private static func inspectHelperSignature(
        commands: any CommandRunning
    ) async -> SudoIntegrationState {
        let verify = await commands.run(HostCommand(
            executable: "/usr/bin/codesign",
            arguments: ["--verify", "--strict", helperPath],
            label: verifyCommandLabel))
        if verify.launchFailed { return .helperSignatureUnreadable }
        guard verify.exitCode == 0 else { return .helperSignatureInvalid }

        // `-dvvv` (not `-dvv`) is the verbosity that prints the CDHash line.
        let display = await commands.run(HostCommand(
            executable: "/usr/bin/codesign",
            arguments: ["-dvvv", helperPath],
            label: displayCommandLabel))
        if display.launchFailed { return .helperSignatureUnreadable }
        // codesign writes its display to stderr.
        let lines = (display.standardError + "\n" + display.standardOutput)
            .split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }

        guard let identifier = value(after: "Identifier=", in: lines) else {
            return .helperSignatureUnreadable
        }
        guard identifier == helperIdentifier else {
            return .helperIdentifierMismatch(found: String(identifier.prefix(128)))
        }
        guard let flags = token(after: "flags=", in: lines), flags.contains("runtime") else {
            return .helperNotHardened
        }
        guard let hash = value(after: "CDHash=", in: lines), !hash.isEmpty else {
            return .helperSignatureUnreadable
        }
        // csecd admits the helper (for mirroring sudo to the phone) only when
        // it satisfies the team's Developer ID requirement, which
        // build-sudo-review.sh signs it for in the install pipeline.
        guard value(after: "TeamIdentifier=", in: lines) == teamIdentifier else {
            return .helperNotTeamSigned
        }
        return .healthy(codeDirectoryHash: String(hash.prefix(128)))
    }

    // MARK: parsing helpers

    /// The remainder of the first line that starts with `prefix` (a whole-line
    /// key such as `Identifier=` or `CDHash=`, so `CandidateCDHash …` never
    /// matches).
    private static func value(after prefix: String, in lines: [String]) -> String? {
        for line in lines where line.hasPrefix(prefix) {
            return String(line.dropFirst(prefix.count)).trimmingCharacters(in: .whitespaces)
        }
        return nil
    }

    /// The whitespace-delimited token following `flags=` anywhere on a line —
    /// e.g. `0x10002(adhoc,runtime)` from the CodeDirectory line. Scoped to that
    /// token so an unrelated "Runtime Version=" line cannot satisfy it.
    private static func token(after prefix: String, in lines: [String]) -> String? {
        for line in lines {
            guard let range = line.range(of: prefix) else { continue }
            let rest = line[range.upperBound...]
            return String(rest.prefix { !$0.isWhitespace })
        }
        return nil
    }

    // MARK: filesystem predicates (mirroring csec_review_helper_is_protected)

    private static func unsafeDirectory(_ path: String, files: any FileInspecting) -> String? {
        guard files.isDirectory(path) else { return "\(path) is not a directory" }
        return unsafeOwnership(path, files: files)
    }

    private static func unsafeFile(
        _ path: String, files: any FileInspecting, requireOwnerExecute: Bool
    ) -> String? {
        guard files.isRegularFile(path) else {
            return "\(path) is a symlink or other non-regular node"
        }
        if let reason = unsafeOwnership(path, files: files) { return reason }
        if requireOwnerExecute, let permissions = files.permissions(path),
           permissions.mode & 0o100 == 0 {
            return "\(path) is not executable by its owner"
        }
        return nil
    }

    private static func unsafeOwnership(_ path: String, files: any FileInspecting) -> String? {
        guard let permissions = files.permissions(path) else {
            return "\(path) could not be inspected"
        }
        guard permissions.ownerUID == 0 else { return "\(path) is not root-owned" }
        guard !permissions.isGroupWritable, !permissions.isOtherWritable else {
            return "\(path) is group- or other-writable"
        }
        return nil
    }

    /// Literal byte-sequence search (no grapheme or canonical-equivalence rules).
    private static func contains(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        let last = haystack.count - needle.count
        var start = 0
        while start <= last {
            var offset = 0
            while offset < needle.count, haystack[start + offset] == needle[offset] {
                offset += 1
            }
            if offset == needle.count { return true }
            start += 1
        }
        return false
    }
}
