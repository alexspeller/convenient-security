import Darwin
import Foundation

// The delegated-approval settings and project pairings csecd keeps, each in
// its own protected item (`ProtectedStores`): csecd-only, never synced, no
// biometric ACL, strict JSON, and read fail-safe. Nothing here is a runtime
// switch: no environment variable, argument or file can enable delegation;
// only `configure_delegation enable` behind csecd's own Touch ID sheet writes
// the settings, and only a human approval on this Mac adds a pairing.

/// Compiled delegation policy bounds.
public enum DelegationPolicy {
    /// The version of what delegation auto-approves. A build that widens it
    /// bumps this, and delegation stays off (`reconfirmation_required`) until
    /// `csec setup` confirms it again under one Touch ID sheet.
    public static let currentVersion = 2

    public static let maximumTrustedBuilds = DelegationGrantsListing.maximumTrustedBuilds
    public static let maximumAcknowledgedHooks = DelegationGrantsListing.maximumAcknowledgedHooks
    /// Rule digests kept across every acknowledged source's classifier rules.
    /// They are display only (`csec setup`'s diff), so past this bound the
    /// oldest sources' are dropped, never an acknowledgement.
    public static let maximumAcknowledgedRuleDigests = 2_048
    public static let maximumPairedProjects = DelegationGrantsListing.maximumPairings
    public static let maximumPairedReferences = ProjectPairingSummary.maximumReferences
    public static let maximumPairedSSHUses = ProjectPairingSummary.maximumSSHPairings
    public static let maximumPinnedLaunchers = ProjectPairingSummary.maximumLaunchers
}

/// A Claude Code build the human trusted by cdhash. The cdhash is the only
/// authority; the rest is display, and `trustedAt` is never an expiry.
public struct TrustedClaudeBuild: Codable, Sendable, Equatable {
    public let cdHash: String
    public let versionLabel: String
    public let path: String
    public let trustedAt: Date

    public init(cdHash: String, versionLabel: String, path: String, trustedAt: Date) {
        self.cdHash = cdHash
        self.versionLabel = versionLabel
        self.path = path
        self.trustedAt = trustedAt
    }

    public var summary: ClaudeBuildSummary {
        ClaudeBuildSummary(cdHash: cdHash, versionLabel: versionLabel, path: path, trustedAt: trustedAt)
    }

    public var isWellFormed: Bool { summary.isWellFormed }
}

/// A hook other than csec's own that can approve a Bash call, or a settings
/// source's auto-mode classifier rules, acknowledged once with Touch ID. Any
/// change gives a new digest, which is not acknowledged.
public struct AcknowledgedClaudeHook: Codable, Sendable, Equatable {
    public let digest: String
    public let display: String
    public let acknowledgedAt: Date
    /// Classifier rules only: which source, and its rules' digests.
    public var classifierRules: AcknowledgedClassifierRules?

    public init(digest: String, display: String, acknowledgedAt: Date, classifierRules: AcknowledgedClassifierRules? = nil) {
        self.digest = digest
        self.display = display
        self.acknowledgedAt = acknowledgedAt
        self.classifierRules = classifierRules
    }

    public var summary: AcknowledgedHookSummary {
        AcknowledgedHookSummary(
            digest: digest, display: display, acknowledgedAt: acknowledgedAt, classifierRules: classifierRules)
    }

    public var isWellFormed: Bool { summary.isWellFormed }
}

/// The source and rule digests of acknowledged classifier rules
/// (`ClaudeHookSource.ruleDigests`), so `csec setup` can show which rules are
/// new since. Display only: the acknowledgement is the source's digest.
public struct AcknowledgedClassifierRules: Codable, Sendable, Equatable {
    /// The settings file, as `ClaudeHookSource.sourceID` names it.
    public let sourceID: String
    public var ruleDigests: [String]

    public init(sourceID: String, ruleDigests: [String]) {
        self.sourceID = sourceID
        self.ruleDigests = ruleDigests
    }

    public var isWellFormed: Bool {
        WireField.isBoundedText(sourceID, maximumBytes: ClaudeHookSource.maximumSourceIDBytes)
            && ClaudeClassifierRules.areWellFormed(ruleDigests)
    }
}

/// The `delegation`/`settings-v1` document. Its presence with Claude Code in
/// `clients` is the opt-in; `disable` deletes it.
public struct DelegationSettingsDocument: ProtectedDocument, Equatable {
    public static let protectedItem: ProtectedItem = .delegationSettings
    /// 2 added `classifierRules` to acknowledged hooks.
    public static let formatVersion = 2

    /// Format 1 is format 2 with no acknowledged classifier rules, which
    /// decodes as this type.
    public static func migrate(from legacy: ProtectedLegacyDocument) -> DelegationSettingsDocument? {
        guard legacy.formatVersion == 1, let old = legacy.decode(DelegationSettingsDocument.self),
              old.acknowledgedHooks.allSatisfy({ $0.classifierRules == nil }) else { return nil }
        return old
    }

    /// `hooks`, newest last, within the document's bounds: at most
    /// `maximumAcknowledgedHooks` entries, and the oldest sources' rule
    /// digests dropped past `maximumAcknowledgedRuleDigests`.
    public static func bounded(_ hooks: [AcknowledgedClaudeHook]) -> [AcknowledgedClaudeHook] {
        var kept = Array(hooks.suffix(DelegationPolicy.maximumAcknowledgedHooks))
        var budget = DelegationPolicy.maximumAcknowledgedRuleDigests
        for index in kept.indices.reversed() {
            guard let count = kept[index].classifierRules?.ruleDigests.count else { continue }
            if count <= budget {
                budget -= count
            } else {
                kept[index].classifierRules?.ruleDigests = []
            }
        }
        return kept
    }

    /// The coding agents whose classifier may stand in for a panel. Only
    /// Claude Code: Codex's approvals cannot be attested.
    public var clients: [AICommandHookClient]
    /// The policy version the human confirmed.
    public var consentedPolicyVersion: Int
    /// Whether `csec setup` added `autoMode.classifyAllShell` to
    /// `claudeSettingsPath`, so disable and uninstall remove it only then.
    public var setClassifyAllShell: Bool
    /// The Claude Code settings file `csec setup` edited.
    public var claudeSettingsPath: String?
    /// Oldest first; at most `DelegationPolicy.maximumTrustedBuilds`.
    public var trustedBuilds: [TrustedClaudeBuild]
    /// Oldest first; at most `DelegationPolicy.maximumAcknowledgedHooks`.
    public var acknowledgedHooks: [AcknowledgedClaudeHook]

    public init(
        clients: [AICommandHookClient] = [.claude],
        consentedPolicyVersion: Int = DelegationPolicy.currentVersion,
        setClassifyAllShell: Bool = false,
        claudeSettingsPath: String? = nil,
        trustedBuilds: [TrustedClaudeBuild] = [],
        acknowledgedHooks: [AcknowledgedClaudeHook] = []
    ) {
        self.clients = clients
        self.consentedPolicyVersion = consentedPolicyVersion
        self.setClassifyAllShell = setClassifyAllShell
        self.claudeSettingsPath = claudeSettingsPath
        self.trustedBuilds = trustedBuilds
        self.acknowledgedHooks = acknowledgedHooks
    }

    public var trustedCDHashes: Set<String> { Set(trustedBuilds.map(\.cdHash)) }
    public var acknowledgedDigests: Set<String> { Set(acknowledgedHooks.map(\.digest)) }

    public var isWellFormed: Bool {
        clients.allSatisfy { $0 == .claude }
            && Set(clients).count == clients.count
            && consentedPolicyVersion > 0
            && (claudeSettingsPath.map(WireField.isClaudeSettingsPath) ?? true)
            && (!setClassifyAllShell || claudeSettingsPath != nil)
            && trustedBuilds.count <= DelegationPolicy.maximumTrustedBuilds
            && trustedBuilds.allSatisfy(\.isWellFormed)
            && Set(trustedBuilds.map(\.cdHash)).count == trustedBuilds.count
            && acknowledgedHooks.count <= DelegationPolicy.maximumAcknowledgedHooks
            && acknowledgedHooks.allSatisfy(\.isWellFormed)
            && Set(acknowledgedHooks.map(\.digest)).count == acknowledgedHooks.count
            && acknowledgedHooks.reduce(0) { $0 + ($1.classifierRules?.ruleDigests.count ?? 0) }
                <= DelegationPolicy.maximumAcknowledgedRuleDigests
    }
}

/// What a pairing is keyed on: the shared git directory of the repository a
/// Claude Code session runs in (`ProjectRepository`), or the session's
/// directory when it is in none; the kernel's canonical path, the volume's
/// UUID and the directory's inode. The volume UUID, not `st_dev`: APFS
/// numbers devices per mount, so a pairing kept until it is revoked must
/// survive a remount.
public struct ProjectKey: Codable, Sendable, Hashable {
    public let path: String
    /// Uppercase, as `UUID.uuidString` spells it.
    public let volumeUUID: String
    public let inode: UInt64

    public init(path: String, volumeUUID: String, inode: UInt64) {
        self.path = path
        self.volumeUUID = volumeUUID
        self.inode = inode
    }

    /// The project's name, for the panel and the decline note: the last
    /// component of `displayPath`.
    public var displayName: String {
        let name = (displayPath as NSString).lastPathComponent
        return ReviewDisplay.bounded(ReviewDisplay.sanitized(name.isEmpty ? path : name), maxBytes: 128)
    }

    /// The path a person knows the project by: a repository's checkout
    /// (`…/app` for `…/app/.git`), or the directory itself.
    public var displayPath: String { Self.displayPath(forPath: path) }

    /// The project as `csec grants`, the restore panel and the log name it:
    /// "…/app (git repository)" for a repository, or the directory's path.
    public var displayDescription: String { Self.displayDescription(forPath: path) }

    public static func displayPath(forPath path: String) -> String {
        guard (path as NSString).lastPathComponent == ".git" else { return path }
        let checkout = (path as NSString).deletingLastPathComponent
        return checkout.isEmpty ? path : checkout
    }

    public static func displayDescription(forPath path: String) -> String {
        let shown = displayPath(forPath: path)
        return shown == path ? path : shown + " (git repository)"
    }

    public var isWellFormed: Bool {
        WireField.isAbsolutePath(path) && UUID(uuidString: volumeUUID)?.uuidString == volumeUUID && inode > 0
    }
}

/// One SSH use a human approved for a project: the tuple an SSH grant binds,
/// without its root.
public struct PairedSSHUse: Codable, Sendable, Hashable {
    public let keyFingerprint: String
    public let hostKeyFingerprint: String
    public let remoteUser: String

    public init(keyFingerprint: String, hostKeyFingerprint: String, remoteUser: String) {
        self.keyFingerprint = keyFingerprint
        self.hostKeyFingerprint = hostKeyFingerprint
        self.remoteUser = remoteUser
    }

    public var isWellFormed: Bool {
        !keyFingerprint.isEmpty && keyFingerprint.utf8.count <= 128 && !keyFingerprint.utf8.contains(0)
            && !hostKeyFingerprint.isEmpty && hostKeyFingerprint.utf8.count <= 128
            && !hostKeyFingerprint.utf8.contains(0)
            && !remoteUser.isEmpty && remoteUser.utf8.count <= 256 && !remoteUser.utf8.contains(0)
    }
}

/// One file a pinned launcher script reads: its path relative to the checkout
/// it was pinned in, and the SHA-256 of its bytes, or nil for a sourced file
/// that was absent when it was pinned (its later appearance is a change).
///
/// The digest is kept only in csecd's sealed pairing item. It is never
/// printed, logged, shown or sent to the phone: a pinned file may hold a
/// secret, and a digest of one would let a reader confirm a guess.
public struct PinnedFile: Codable, Sendable, Hashable {
    public static let maximumPathBytes = 1_024

    public let path: String
    public let digest: String?

    public init(path: String, digest: String?) {
        self.path = path
        self.digest = digest
    }

    public var isWellFormed: Bool {
        Self.isCheckoutRelativePath(path) && (digest.map { WireField.isLowercaseHex($0, length: 64) } ?? true)
    }

    /// A path relative to a checkout's root: non-empty, bounded, no NUL, no
    /// leading `/`, no empty, `.` or `..` component, and no `.git` component
    /// (nothing inside a repository's own directory is ever pinned).
    public static func isCheckoutRelativePath(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= maximumPathBytes, !value.utf8.contains(0),
              !value.hasPrefix("/") else { return false }
        // `.git` in any case: APFS is case insensitive by default.
        return value.split(separator: "/", omittingEmptySubsequences: false).allSatisfy { component in
            !component.isEmpty && component != "." && component != ".." && component.lowercased() != ".git"
        }
    }
}

/// A script a human trusted to start SSH for Claude Code auto mode in one
/// project: the script's checkout-relative path and digest, and every file its
/// `source`/`.` lines read, exactly as they were when the human approved.
/// Nothing pins one or checks one any more: since csec-0.11 an SSH signing
/// auto mode approved signs with no pin. A pairing written before that still
/// carries its pins, which are decoded so `csec grants` lists them and
/// `csec revoke` removes them.
public struct PinnedLauncher: Codable, Sendable, Equatable {
    /// With the script itself, at most 16 files: the bound the pinning check
    /// read up to.
    public static let maximumSources = 15

    public let path: String
    public let digest: String
    public let sources: [PinnedFile]

    public init(path: String, digest: String, sources: [PinnedFile]) {
        self.path = path
        self.digest = digest
        self.sources = sources
    }

    public var isWellFormed: Bool {
        PinnedFile.isCheckoutRelativePath(path)
            && WireField.isLowercaseHex(digest, length: 64)
            && sources.count <= Self.maximumSources
            && sources.allSatisfy(\.isWellFormed)
            && Set(sources.map(\.path)).count == sources.count
            && !sources.contains { $0.path == path }
    }
}

/// What a human approved for one project, which Claude Code auto mode may
/// then use there until it is revoked. References, SSH uses and launcher
/// scripts are kept in the order they were first approved; `sudo` says a
/// human let auto mode run sudo there.
public struct ProjectPairing: Codable, Sendable, Equatable {
    /// Lowercase UUID: the `pair-` id.
    public let id: String
    public let project: ProjectKey
    /// References auto mode may have released into its commands.
    public var references: [String]
    /// References auto mode may have csecd use on its behalf and never
    /// release (`daemon_proxy`, the GitHub socket). A human who approved only
    /// that use approved nothing that hands the value's bytes to a process, so
    /// these never cover a release; a reference in `references` covers both.
    public var usedReferences: [String]
    /// SSH destinations a human approved before csec-0.11, which no longer
    /// decide anything; kept so they list and revoke. A signing to one still
    /// counts the pairing as used.
    public var ssh: [PairedSSHUse]
    /// Scripts pinned to start SSH before csec-0.11, likewise kept only to
    /// list and revoke.
    public var launchers: [PinnedLauncher]
    /// Auto mode may run sudo in this project: a sudo the classifier approved,
    /// started directly by the approved text (`SudoChainRule`).
    public var sudo: Bool

    public init(
        id: String = UUID().uuidString.lowercased(), project: ProjectKey, references: [String],
        usedReferences: [String] = [], ssh: [PairedSSHUse], launchers: [PinnedLauncher] = [], sudo: Bool = false
    ) {
        self.id = id
        self.project = project
        self.references = references
        self.usedReferences = usedReferences
        self.ssh = ssh
        self.launchers = launchers
        self.sudo = sudo
    }

    /// Launchers alone do not keep a pairing: they only let a script start SSH
    /// to destinations the pairing already holds.
    public var isEmpty: Bool { references.isEmpty && usedReferences.isEmpty && ssh.isEmpty && !sudo }

    /// Whether auto mode may have `reference` released (`daemonUse` false) or
    /// used inside csecd (`daemonUse` true) in this project.
    public func covers(_ reference: String, daemonUse: Bool) -> Bool {
        references.contains(reference) || (daemonUse && usedReferences.contains(reference))
    }

    public var isWellFormed: Bool {
        UUID(uuidString: id)?.uuidString.lowercased() == id
            && project.isWellFormed
            && references.count <= DelegationPolicy.maximumPairedReferences
            && references.allSatisfy { WireField.isReference($0) && (try? SecretRef($0))?.uri == $0 }
            && Set(references).count == references.count
            && usedReferences.count <= DelegationPolicy.maximumPairedReferences
            && usedReferences.allSatisfy { WireField.isReference($0) && (try? SecretRef($0))?.uri == $0 }
            && Set(usedReferences).count == usedReferences.count
            && Set(usedReferences).isDisjoint(with: references)
            && ssh.count <= DelegationPolicy.maximumPairedSSHUses
            && ssh.allSatisfy(\.isWellFormed)
            && Set(ssh).count == ssh.count
            && launchers.count <= DelegationPolicy.maximumPinnedLaunchers
            && launchers.allSatisfy(\.isWellFormed)
            && Set(launchers.map(\.path)).count == launchers.count
    }
}

/// The `pairing`/`v1` item's document: every project pairing, oldest first.
/// Recency is kept in memory only, so the item is rewritten only when a
/// pairing is added or removed.
///
/// Format 2 added `launchers`, format 3 `sudo`, format 4 `usedReferences`.
/// Older items migrate with none and no sudo. A build that predates a format reads its items as
/// unreadable and starts with no pairings; the store then holds the item, so
/// what that build pairs lasts only for its run and the newer build finds
/// every pairing it wrote.
public struct PairingDocument: ProtectedDocument, Equatable {
    public static let protectedItem: ProtectedItem = .pairing
    public static let formatVersion = 4

    public var projects: [ProjectPairing]

    public init(projects: [ProjectPairing] = []) {
        self.projects = projects
    }

    public var isWellFormed: Bool {
        projects.count <= DelegationPolicy.maximumPairedProjects
            && projects.allSatisfy(\.isWellFormed)
            && Set(projects.map(\.id)).count == projects.count
            && Set(projects.map(\.project)).count == projects.count
    }

    /// Format 1: the same document without `launchers` or `sudo`.
    private struct Version1: Decodable {
        struct Pairing: Decodable {
            let id: String
            let project: ProjectKey
            let references: [String]
            let ssh: [PairedSSHUse]
        }

        let projects: [Pairing]
    }

    /// Format 2: without `sudo`.
    private struct Version2: Decodable {
        struct Pairing: Decodable {
            let id: String
            let project: ProjectKey
            let references: [String]
            let ssh: [PairedSSHUse]
            let launchers: [PinnedLauncher]
        }

        let projects: [Pairing]
    }

    /// Format 3: without `usedReferences`.
    private struct Version3: Decodable {
        struct Pairing: Decodable {
            let id: String
            let project: ProjectKey
            let references: [String]
            let ssh: [PairedSSHUse]
            let launchers: [PinnedLauncher]
            let sudo: Bool
        }

        let projects: [Pairing]
    }

    public static func migrate(from legacy: ProtectedLegacyDocument) -> PairingDocument? {
        switch legacy.formatVersion {
        case 1:
            guard let old = legacy.decode(Version1.self) else { return nil }
            return PairingDocument(projects: old.projects.map {
                ProjectPairing(id: $0.id, project: $0.project, references: $0.references, ssh: $0.ssh)
            })
        case 2:
            guard let old = legacy.decode(Version2.self) else { return nil }
            return PairingDocument(projects: old.projects.map {
                ProjectPairing(
                    id: $0.id, project: $0.project, references: $0.references, ssh: $0.ssh, launchers: $0.launchers
                )
            })
        case 3:
            guard let old = legacy.decode(Version3.self) else { return nil }
            return PairingDocument(projects: old.projects.map {
                ProjectPairing(
                    id: $0.id, project: $0.project, references: $0.references, ssh: $0.ssh,
                    launchers: $0.launchers, sudo: $0.sudo
                )
            })
        default:
            return nil
        }
    }
}

/// The volume a mount point belongs to, by its UUID (`getattrlist`
/// `ATTR_VOL_UUID`). Measured on this Mac to equal `diskutil`'s Volume UUID
/// for the sealed system volume and the Data volume, and to answer for any
/// path on the volume. It asks the file system, so a caller uses it only for a
/// mount the kernel's cached table says is local.
public enum VolumeIdentity {
    public static func uuid(ofMountPoint path: String) -> String? {
        var request = attrlist()
        request.bitmapcount = u_short(ATTR_BIT_MAP_COUNT)
        request.volattr = attrgroup_t(ATTR_VOL_INFO) | attrgroup_t(ATTR_VOL_UUID)
        // The reply is a u_int32_t length followed by the uuid_t.
        var buffer = [UInt8](repeating: 0, count: 64)
        let status = buffer.withUnsafeMutableBytes { raw in
            getattrlist(path, &request, raw.baseAddress, raw.count, UInt32(FSOPT_NOFOLLOW))
        }
        guard status == 0 else { return nil }
        let length = buffer.withUnsafeBytes { $0.load(as: UInt32.self) }
        guard length >= 20 else { return nil }
        let bytes = Array(buffer[4..<20])
        guard bytes.contains(where: { $0 != 0 }) else { return nil }
        let uuid = UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
        ))
        return uuid.uuidString
    }
}
