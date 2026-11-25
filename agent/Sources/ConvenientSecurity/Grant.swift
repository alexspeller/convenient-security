import Foundation

/// A consented capability: a set of references granted to a process subtree.
/// Held only in the agent's memory-protected heap. Reuse is
/// bound to the live process subtree plus either the originating delivery-plan
/// digest (a requesting-command root) or the release-shape digest (a root the
/// human deliberately widened); after the risk-level collapse there is no
/// per-credential policy binding.
///
/// A grant lives for the lifetime of the process subtree it is rooted at — the
/// authority is the `rootPID`/`rootStartTime` liveness the table sweeps on, not
/// a clock. `expiresAt` is nil for that default, and carries a wall-clock cap
/// only when the human deliberately chose a shorter opt-in lifetime (`--for`, or
/// the review's 1h/12h options). A nil expiry never lets a grant outlive its
/// process: `GrantTable.sweep` drops it the moment the root incarnation is gone.
public struct Grant: Sendable, Identifiable {
    public let id: UUID
    /// Root of the granted process subtree (the process that consented).
    public let rootPID: pid_t
    /// Start time of `rootPID` (epoch microseconds), to defeat PID reuse.
    public let rootStartTime: UInt64
    public var references: Set<String>
    public let reason: String
    /// Wall-clock cap, or nil for a grant that lives as long as its root process
    /// subtree (the default). Never a substitute for the liveness sweep.
    public var expiresAt: Date?
    /// Originating v2 request and delivery context. The nonce is audit/binding
    /// metadata, not a bearer token; plan-digest equality controls reuse.
    public let requestID: String?
    public let deliveryPlanDigest: String?
    public let peerPIDVersion: Int32?
    public let peerCDHash: String?
    public let plannedExecutable: PlannedExecutable?
    /// Which selectable root the human approved. Display and diagnostics only —
    /// `rootPID`/`rootStartTime` remain the authority.
    public let scopeKind: GrantScopeKind
    /// Set only for a widened root: the release-shape digest that a *different*
    /// command in this subtree must match to reuse the grant. Nil keeps the
    /// original exact delivery-plan-digest binding.
    public let scopeReuseDigest: String?
    /// Audit session of the approving caller. Enforced alongside ancestry for a
    /// widened grant, mirroring the binding `SSHSigningService` applies to its
    /// reused grants.
    public let auditSessionID: UInt32?
    /// Human label for the root process, captured at approval time.
    public let rootProcessLabel: String?
    /// Who approved it. Recorded with the grant; nothing is decided on it.
    public let origin: GrantOrigin
    /// When it was minted, which orders the oldest-first trim of the persisted
    /// grants item. Never compared with the present.
    public let mintedAt: Date
    /// The csecd build that minted it, for diagnostics only. Nil until the
    /// grant is first persisted, which stamps the running build.
    public let mintedByBuild: String?
    /// Loaded from the persisted grants item when csecd started, rather than
    /// minted in this daemon lifetime.
    public var restored: Bool
    /// Whether this grant is past the restore: true for a grant minted in this
    /// lifetime (its own panel unlocked what it needs), and for a restored one
    /// once the restore panel reopened its stores or found nothing to reopen.
    public var warm: Bool

    /// A restored grant whose stores the restore panel has not reopened yet.
    public var awaitingRestore: Bool { restored && !warm }

    public init(
        id: UUID = UUID(),
        rootPID: pid_t,
        rootStartTime: UInt64,
        references: Set<String>,
        reason: String,
        expiresAt: Date? = nil,
        requestID: String? = nil,
        deliveryPlanDigest: String? = nil,
        peerPIDVersion: Int32? = nil,
        peerCDHash: String? = nil,
        plannedExecutable: PlannedExecutable? = nil,
        scopeKind: GrantScopeKind = .requestingCommand,
        scopeReuseDigest: String? = nil,
        auditSessionID: UInt32? = nil,
        rootProcessLabel: String? = nil,
        origin: GrantOrigin = .humanLocal,
        mintedAt: Date = Date(),
        mintedByBuild: String? = nil,
        restored: Bool = false,
        warm: Bool = true
    ) {
        self.id = id
        self.rootPID = rootPID
        self.rootStartTime = rootStartTime
        self.references = references
        self.reason = reason
        self.expiresAt = expiresAt
        self.requestID = requestID
        self.deliveryPlanDigest = deliveryPlanDigest
        self.peerPIDVersion = peerPIDVersion
        self.peerCDHash = peerCDHash
        self.plannedExecutable = plannedExecutable
        self.scopeKind = scopeKind
        self.scopeReuseDigest = scopeReuseDigest
        self.auditSessionID = auditSessionID
        self.rootProcessLabel = rootProcessLabel
        self.origin = origin
        self.mintedAt = mintedAt
        self.mintedByBuild = mintedByBuild
        self.restored = restored
        self.warm = warm
    }

    /// Whether the grant's own clock still permits it. A nil `expiresAt` never
    /// expires by clock — the process-liveness sweep is the sole authority then.
    public func isLive(now: Date) -> Bool {
        guard let expiresAt else { return true }
        return now < expiresAt
    }
}

/// Who approved a grant.
public enum GrantOrigin: String, Codable, Sendable, CaseIterable {
    /// A human on this Mac: the trusted panel, or the consent sheet an
    /// injected reviewer falls back to.
    case humanLocal = "human_local"
    /// The paired iPhone.
    case phone
    /// Claude Code auto mode through delegation. Nothing mints a delegated
    /// grant today; the value exists so the persisted format does not change
    /// when something does.
    case delegated
}

/// The kinds of grant `csec grants` lists and `csec revoke` drops.
public enum GrantKind: String, Codable, Sendable, CaseIterable {
    /// Secret references released to a process subtree.
    case secret
    /// SSH signatures for one key, server identity and remote user.
    case ssh
}

/// Everything `csec grants` lists and `csec revoke` removes, each with its own
/// typed id: `grant-…` secret grants, `ssh-…` SSH grants, and — only while
/// delegated approvals are on — `pair-…` project pairings, `build-…` trusted
/// Claude Code builds and `hook-…` acknowledged hooks. An id within its kind is
/// lowercase hex (and dashes): a grant's or pairing's UUID, a build's cdhash, a
/// hook's digest.
public enum GrantIDKind: String, Codable, Sendable, CaseIterable {
    case secret
    case ssh
    case pairing
    case build
    case hook

    /// What `csec grants` prints before the id.
    public var typedPrefix: String {
        switch self {
        case .secret: return "grant-"
        case .ssh: return "ssh-"
        case .pairing: return "pair-"
        case .build: return "build-"
        case .hook: return "hook-"
        }
    }

    public init(_ kind: GrantKind) {
        switch kind {
        case .secret: self = .secret
        case .ssh: self = .ssh
        }
    }

    /// The grant kind, for the two kinds that are grants.
    public var grantKind: GrantKind? {
        switch self {
        case .secret: return .secret
        case .ssh: return .ssh
        case .pairing, .build, .hook: return nil
        }
    }
}

/// A `csec revoke` argument: a kind and an id prefix within it. A typed id
/// (`grant-`, `ssh-`, `pair-`, `build-`, `hook-`) names its kind; a bare id (hex
/// and dashes) still names secret grants, as it always has. A prefix matches
/// only entries of its own kind. Parsing and `displayID` are the one place ids
/// are spelled.
public struct GrantIDSelector: Sendable, Equatable {
    public static let sshPrefix = GrantIDKind.ssh.typedPrefix
    /// The longest id within a kind: a hook's SHA-256 digest.
    public static let maximumPrefixLength = 64

    public let kind: GrantIDKind
    /// Lowercase hex digits and dashes: the start of the entry's id.
    public let prefix: String

    public init?(_ raw: String) {
        guard raw.utf8.count <= Self.maximumPrefixLength + 8 else { return nil }
        let lowered = raw.lowercased()
        let typed = GrantIDKind.allCases.first { lowered.hasPrefix($0.typedPrefix) }
        let kind = typed ?? .secret
        let prefix = typed.map { String(lowered.dropFirst($0.typedPrefix.count)) } ?? lowered
        // ASCII only: `Character.isHexDigit` also accepts fullwidth forms.
        guard WireField.isTypedIDBody(prefix) else { return nil }
        self.kind = kind
        self.prefix = prefix
    }

    /// Whether `id` (an entry of this selector's kind) starts with the prefix.
    public func matches(id: String) -> Bool {
        id.lowercased().hasPrefix(prefix)
    }

    /// The short id `csec grants` prints for an entry of this kind.
    public static func displayID(kind: GrantIDKind, id: String) -> String {
        kind.typedPrefix + String(id.lowercased().prefix(8))
    }
}

public enum GrantsAction: String, Codable, Sendable {
    case list
    case revoke
}

/// Inspect or drop live grants. Listing returns value-free metadata and
/// revocation only removes access, so neither needs Touch ID; both still
/// require an authenticated signed launcher like every other verb.
public struct GrantsRequest: Codable, Sendable {
    public let requestID: String
    public let action: GrantsAction
    /// For `revoke`: a typed id or a prefix of one (`grant-`, `ssh-`, `pair-`,
    /// `build-`, `hook-`; a bare hex id names a secret grant), parsed by
    /// `GrantIDSelector`. A prefix matching more than one entry of its kind
    /// removes nothing and fails, listing the matches.
    public let grantID: String?
    /// Revoke every secret grant, SSH grant and project pairing. Trusted
    /// builds and acknowledged hooks stay: they are delegation settings, which
    /// `csec setup` (or revoking their own ids) changes.
    public let all: Bool

    public init(
        action: GrantsAction,
        grantID: String? = nil,
        all: Bool = false,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.action = action
        self.grantID = grantID
        self.all = all
    }
}

/// Value-free description of a live grant for `csec grants`. It carries
/// reference URIs and process metadata, never a resolved value.
public struct GrantSummary: Codable, Sendable, Equatable {
    public let id: String
    /// Nil from a csecd that predates SSH grant listing, which listed only
    /// secret grants.
    public let kind: GrantKind?
    public let rootPID: pid_t
    public let rootProcessLabel: String
    public let scopeKind: GrantScopeKind
    public let references: [String]
    public let reason: String
    /// Wall-clock cap, or nil for a grant that lives as long as its root process.
    public let expiresAt: Date?
    /// Present exactly for an SSH grant: what it signs for.
    public let ssh: SSHGrantSummary?
    /// Restored after a csecd restart rather than approved in this run.
    public let restored: Bool?

    public init(
        id: String,
        kind: GrantKind = .secret,
        rootPID: pid_t,
        rootProcessLabel: String,
        scopeKind: GrantScopeKind,
        references: [String],
        reason: String,
        expiresAt: Date?,
        ssh: SSHGrantSummary? = nil,
        restored: Bool = false
    ) {
        self.id = id
        self.kind = kind
        self.rootPID = rootPID
        self.rootProcessLabel = rootProcessLabel
        self.scopeKind = scopeKind
        self.references = references
        self.reason = reason
        self.expiresAt = expiresAt
        self.ssh = ssh
        self.restored = restored
    }

    public var grantKind: GrantKind { kind ?? .secret }

    /// The id `csec grants` prints and `csec revoke` accepts.
    public var displayID: String { GrantIDSelector.displayID(kind: GrantIDKind(grantKind), id: id) }

    public var reusesAcrossCommands: Bool { scopeKind.reusesAcrossCommands }

    /// Bounds for a summary crossing the socket, checked by the client.
    public var isWellFormed: Bool {
        !id.isEmpty && id.utf8.count <= 64
            && rootPID > 0
            && !rootProcessLabel.isEmpty && rootProcessLabel.utf8.count <= 256
            && references.count <= 64
            && references.allSatisfy { !$0.isEmpty && $0.utf8.count <= 4_096 }
            && reason.utf8.count <= 512
            && (ssh?.isWellFormed ?? true)
            && (grantKind == .ssh) == (ssh != nil)
    }
}

/// What an SSH grant signs for: one key, one verified server identity, one
/// remote user. Public metadata only.
public struct SSHGrantSummary: Codable, Sendable, Equatable {
    public let keyFingerprint: String
    public let keyLabel: String?
    public let hostKeyFingerprint: String
    /// known_hosts names for the server identity; empty when none matched.
    public let hostNames: [String]
    public let remoteUser: String

    public init(
        keyFingerprint: String,
        keyLabel: String?,
        hostKeyFingerprint: String,
        hostNames: [String],
        remoteUser: String
    ) {
        self.keyFingerprint = keyFingerprint
        self.keyLabel = keyLabel
        self.hostKeyFingerprint = hostKeyFingerprint
        self.hostNames = hostNames
        self.remoteUser = remoteUser
    }

    public var isWellFormed: Bool {
        !keyFingerprint.isEmpty && keyFingerprint.utf8.count <= 128
            && (keyLabel?.utf8.count ?? 0) <= 256
            && !hostKeyFingerprint.isEmpty && hostKeyFingerprint.utf8.count <= 128
            && hostNames.count <= 16
            && hostNames.allSatisfy { !$0.isEmpty && $0.utf8.count <= 256 }
            && !remoteUser.isEmpty && remoteUser.utf8.count <= 256
    }
}

// MARK: - Typed-id listing and revocation beyond grants

/// One entry a `revoke` removed, or matched ambiguously: its kind, its full id
/// within that kind, and a value-free line saying what it is (csecd-authored;
/// a renderer still sanitizes it).
public struct RevocableEntry: Codable, Sendable, Equatable {
    public static let maximumLabelBytes = 512

    public let kind: GrantIDKind
    /// Lowercase hex and dashes: a grant's or pairing's UUID, a build's
    /// cdhash, a hook's digest.
    public let id: String
    public let label: String

    public init(kind: GrantIDKind, id: String, label: String) {
        self.kind = kind
        self.id = id
        self.label = label
    }

    public var displayID: String { GrantIDSelector.displayID(kind: kind, id: id) }

    public var isWellFormed: Bool {
        WireField.isTypedIDBody(id)
            && WireField.isBoundedText(label, maximumBytes: Self.maximumLabelBytes)
    }
}

/// What a `revoke` (of `grants`) or an `untrust_build` / `forget_hook` (of
/// `configure_delegation`) did. A successful reply lists every removed entry,
/// possibly none. A prefix that matched more than one entry of its kind
/// removes nothing: the reply is an `invalid_request` failure that also
/// carries this value, with `ambiguousMatches` listing every match.
public struct GrantRevocation: Codable, Sendable, Equatable {
    /// Room for every secret grant, SSH grant and pairing csecd can hold, so
    /// `revoke --all` lists everything it removed.
    public static let maximumEntries = 2_048

    public let removed: [RevocableEntry]
    public let ambiguousMatches: [RevocableEntry]

    public init(removed: [RevocableEntry] = [], ambiguousMatches: [RevocableEntry] = []) {
        self.removed = removed
        self.ambiguousMatches = ambiguousMatches
    }

    public var isAmbiguous: Bool { !ambiguousMatches.isEmpty }

    public var isWellFormed: Bool {
        removed.count <= Self.maximumEntries
            && ambiguousMatches.count <= Self.maximumEntries
            && removed.allSatisfy(\.isWellFormed)
            && ambiguousMatches.allSatisfy(\.isWellFormed)
            // An ambiguity removes nothing and names at least two matches, all
            // of the one kind the id named.
            && (ambiguousMatches.isEmpty || (removed.isEmpty && ambiguousMatches.count >= 2))
            && Set(ambiguousMatches.map(\.kind)).count <= 1
    }
}

/// The delegated-approval entries of `csec grants`. csecd sends it only while
/// delegated approvals are on; with them off, pairings are never listed,
/// warmed or used, and there is nothing else to list.
public struct DelegationGrantsListing: Codable, Sendable, Equatable {
    public static let maximumPairings = 256
    public static let maximumTrustedBuilds = 32
    public static let maximumAcknowledgedHooks = 128

    public let pairings: [ProjectPairingSummary]
    public let trustedBuilds: [ClaudeBuildSummary]
    public let acknowledgedHooks: [AcknowledgedHookSummary]

    public init(
        pairings: [ProjectPairingSummary],
        trustedBuilds: [ClaudeBuildSummary],
        acknowledgedHooks: [AcknowledgedHookSummary]
    ) {
        self.pairings = pairings
        self.trustedBuilds = trustedBuilds
        self.acknowledgedHooks = acknowledgedHooks
    }

    public var isWellFormed: Bool {
        pairings.count <= Self.maximumPairings
            && trustedBuilds.count <= Self.maximumTrustedBuilds
            && acknowledgedHooks.count <= Self.maximumAcknowledgedHooks
            && pairings.allSatisfy(\.isWellFormed)
            && trustedBuilds.allSatisfy(\.isWellFormed)
            && acknowledgedHooks.allSatisfy(\.isWellFormed)
    }
}

/// A project pairing: the references, SSH key, server and user tuples, and
/// launcher scripts a human approved for one project, which Claude Code auto
/// mode may then use there until they are revoked. Value-free: a launcher is
/// listed by its paths, never its digests.
public struct ProjectPairingSummary: Codable, Sendable, Equatable {
    public static let maximumReferences = 256
    public static let maximumSSHPairings = 256
    public static let maximumLaunchers = 64

    /// Stable for the pairing's lifetime: lowercase hex and dashes.
    public let id: String
    /// The path the pairing is keyed on, for display: a repository's shared
    /// git directory (`ProjectKey.displayDescription(forPath:)` names its
    /// checkout) or a directory.
    public let projectPath: String
    /// Canonical reference URIs auto mode may have released.
    public let references: [String]
    /// Canonical reference URIs auto mode may have csecd use, never released.
    public let usedReferences: [String]
    public let ssh: [SSHPairingSummary]
    public let launchers: [LauncherPairingSummary]
    /// Auto mode may run sudo in the project.
    public let sudo: Bool

    public init(
        id: String, projectPath: String, references: [String], usedReferences: [String] = [],
        ssh: [SSHPairingSummary], launchers: [LauncherPairingSummary] = [], sudo: Bool = false
    ) {
        self.id = id
        self.projectPath = projectPath
        self.references = references
        self.usedReferences = usedReferences
        self.ssh = ssh
        self.launchers = launchers
        self.sudo = sudo
    }

    private enum CodingKeys: String, CodingKey {
        case id, projectPath, references, usedReferences, ssh, launchers, sudo
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        projectPath = try container.decode(String.self, forKey: .projectPath)
        references = try container.decode([String].self, forKey: .references)
        // A csecd that predates daemon-proxy pairing never pairs a use.
        usedReferences = try container.decodeIfPresent([String].self, forKey: .usedReferences) ?? []
        ssh = try container.decode([SSHPairingSummary].self, forKey: .ssh)
        // A csecd that predates launchers sends none, and one that predates
        // sudo pairing never pairs it.
        launchers = try container.decodeIfPresent([LauncherPairingSummary].self, forKey: .launchers) ?? []
        sudo = try container.decodeIfPresent(Bool.self, forKey: .sudo) ?? false
    }

    public var displayID: String { GrantIDSelector.displayID(kind: .pairing, id: id) }

    public var isWellFormed: Bool {
        WireField.isTypedIDBody(id)
            && WireField.isAbsolutePath(projectPath)
            && references.count <= Self.maximumReferences
            && references.allSatisfy(WireField.isReference)
            && usedReferences.count <= Self.maximumReferences
            && usedReferences.allSatisfy(WireField.isReference)
            && ssh.count <= Self.maximumSSHPairings
            && ssh.allSatisfy(\.isWellFormed)
            && launchers.count <= Self.maximumLaunchers
            && launchers.allSatisfy(\.isWellFormed)
    }
}

/// A pinned launcher script, by its checkout-relative path and the paths of
/// the files it sources. Never its digests.
public struct LauncherPairingSummary: Codable, Sendable, Equatable {
    public let path: String
    public let sources: [String]

    public init(path: String, sources: [String]) {
        self.path = path
        self.sources = sources
    }

    public var isWellFormed: Bool {
        PinnedFile.isCheckoutRelativePath(path)
            && sources.count <= PinnedLauncher.maximumSources
            && sources.allSatisfy(PinnedFile.isCheckoutRelativePath)
    }
}

/// One paired SSH use: a key, a verified server identity and a remote user,
/// exactly the tuple an SSH grant binds, without its root. Public metadata.
public struct SSHPairingSummary: Codable, Sendable, Equatable {
    /// The key's canonical reference, when the catalog still has the key.
    public let keyReference: String?
    public let keyFingerprint: String
    public let keyLabel: String?
    public let hostKeyFingerprint: String
    /// known_hosts names for the server identity; empty when none matched.
    public let hostNames: [String]
    public let remoteUser: String

    public init(
        keyReference: String?,
        keyFingerprint: String,
        keyLabel: String?,
        hostKeyFingerprint: String,
        hostNames: [String],
        remoteUser: String
    ) {
        self.keyReference = keyReference
        self.keyFingerprint = keyFingerprint
        self.keyLabel = keyLabel
        self.hostKeyFingerprint = hostKeyFingerprint
        self.hostNames = hostNames
        self.remoteUser = remoteUser
    }

    public var isWellFormed: Bool {
        (keyReference.map(WireField.isReference) ?? true)
            && SSHGrantSummary(
                keyFingerprint: keyFingerprint,
                keyLabel: keyLabel,
                hostKeyFingerprint: hostKeyFingerprint,
                hostNames: hostNames,
                remoteUser: remoteUser
            ).isWellFormed
    }
}

/// A Claude Code build csecd trusts by cdhash (`trustedAt` set), or one it
/// found that is neither signed by Anthropic nor trusted (`trustedAt` nil, in
/// the delegation status's `discoveredUntrustedBuilds`).
public struct ClaudeBuildSummary: Codable, Sendable, Equatable {
    public static let maximumVersionLabelBytes = 64
    public static let maximumPathBytes = 1_024

    /// 40 lowercase hex: the only authority. Everything else is display.
    public let cdHash: String
    public let versionLabel: String
    public let path: String
    /// When it was trusted. Display only, never an expiry.
    public let trustedAt: Date?

    public init(cdHash: String, versionLabel: String, path: String, trustedAt: Date? = nil) {
        self.cdHash = cdHash
        self.versionLabel = versionLabel
        self.path = path
        self.trustedAt = trustedAt
    }

    public var displayID: String { GrantIDSelector.displayID(kind: .build, id: cdHash) }

    public var isWellFormed: Bool {
        WireField.isLowercaseHex(cdHash, length: 40)
            && WireField.isBoundedText(versionLabel, maximumBytes: Self.maximumVersionLabelBytes)
            && WireField.isAbsolutePath(path, maximumBytes: Self.maximumPathBytes)
    }
}

/// A hook other than csec's own that can approve a Bash call, which the human
/// acknowledged with Touch ID. Any change to it gives a new digest, which is
/// not acknowledged.
public struct AcknowledgedHookSummary: Codable, Sendable, Equatable {
    public static let maximumDisplayBytes = 256

    /// 64 lowercase hex: the hook's canonical digest (`ClaudeHookSource.digest`).
    public let digest: String
    /// For example "cc-caffeine@samber · PreToolUse *".
    public let display: String
    /// Display only, never an expiry.
    public let acknowledgedAt: Date?
    /// Acknowledged classifier rules only: their source and rule digests,
    /// which `csec setup` diffs the rules there now against. `csec grants`
    /// lists them without the digests.
    public let classifierRules: AcknowledgedClassifierRules?

    public init(
        digest: String, display: String, acknowledgedAt: Date? = nil,
        classifierRules: AcknowledgedClassifierRules? = nil
    ) {
        self.digest = digest
        self.display = display
        self.acknowledgedAt = acknowledgedAt
        self.classifierRules = classifierRules
    }

    public var displayID: String { GrantIDSelector.displayID(kind: .hook, id: digest) }

    /// This summary with no rule digests, for a listing.
    public var listed: AcknowledgedHookSummary {
        AcknowledgedHookSummary(
            digest: digest, display: display, acknowledgedAt: acknowledgedAt,
            classifierRules: classifierRules.map { AcknowledgedClassifierRules(sourceID: $0.sourceID, ruleDigests: []) })
    }

    public var isWellFormed: Bool {
        WireField.isLowercaseHex(digest, length: 64)
            && WireField.isBoundedText(display, maximumBytes: Self.maximumDisplayBytes)
            && (classifierRules?.isWellFormed ?? true)
    }
}
