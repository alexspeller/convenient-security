import CryptoKit
import Foundation
import Security
#if canImport(Darwin)
import Darwin
#endif

// The Claude Code settings gate: what csecd must know about a Claude Code
// session's configuration before it may accept the auto-mode classifier's
// verdict in place of a human panel, and what `csec setup` changes (and later
// puts back) to make that verdict the only approver.
//
// - G1: `autoMode.classifyAllShell` is true in user or policy settings. With it,
//   auto mode drops every Bash allow rule from every source, including the
//   session and command rules no file shows. Project settings cannot set it.
// - G2: no other hook can approve a Bash call (PreToolUse `allow`,
//   PermissionRequest `allow`, a plugin hooks module) or keep Claude Code
//   from reloading its settings (ConfigChange), and no settings source carries
//   auto-mode classifier rules (`autoMode.allow`, `soft_deny`, `hard_deny`,
//   `environment`), unless the human acknowledged that exact hook or that
//   source's exact rules. A rule list steers the classifier as strongly as an
//   approving hook: one without `"$defaults"` replaces the built-in section,
//   so it can tell the classifier to approve, or delete its blocks.
// - G5 (settings half): no settings `env` block sets a name on the injected-
//   environment list, since Claude Code applies those to its own environment.
// - G6: no sandbox auto-allow, no reachable bypass, no disabled hooks.
//
// `processWrapper` (`CLAUDE_CODE_PROCESS_WRAPPER`), honoured from user, flag
// and policy settings, needs no check: 2.1.280 puts it in front of Claude
// Code's own re-spawns of the claude binary (the background daemon and its
// workers, agent-team teammates, the relaunch after login, the remote-control
// bridge, the update restart), never in front of a Bash tool command, so it
// cannot sit between `csec ai` and its command or replace `csec ai`. A wrapped
// process is a fresh Claude Code process that csecd checks on its own terms,
// and the wrapper itself is same-user code started by the session, which the
// threat model already accepts for MCP servers and SessionStart hooks.
//
// csecd evaluates the gate on every delegated request (so it must stay cheap:
// reads are cached by file identity and re-`stat`ed per call, with no clock),
// and csec evaluates it for `csec setup`, `csec status` and `csec doctor`. It
// takes every root explicitly and reads files only through
// `ClaudeSettingsFileAccess`, never the environment, so a test drives it with a
// fixture home.

// MARK: - The gate

public protocol ClaudeSettingsGate: Sendable {
    /// G1, G2, G5 on settings and G6 for `scope`, with every file that could
    /// not be read. Synchronous and read-only; it may block on a slow file
    /// system, so csecd calls it off its actor with a bounded wait.
    func evaluate(_ scope: ClaudeSettingsScope) -> ClaudeSettingsGateEvaluation

    /// The Claude Code builds installed for `scope` (native and mise standalone
    /// npm versions), with their code identity. Not per request: only
    /// status, setup and `enable` need it.
    func discoverBuilds(_ scope: ClaudeSettingsScope) -> ClaudeBuildDiscovery

    /// The user settings file setup edits and `enable` records for `scope`:
    /// `scope.sharedUserSettingsPath`, so a `CLAUDE_CONFIG_DIR` whose
    /// `settings.json` links to `~/.claude/settings.json` edits and records
    /// that file.
    func userSettingsPath(_ scope: ClaudeSettingsScope) -> String

    /// What enabling delegation changes in the user settings file
    /// (`userSettingsPath`): add
    /// `autoMode.classifyAllShell: true` if it is not already true (recording
    /// that csec added it), and replace csec's `autoMode.environment` entry with
    /// its delegation-aware text. One atomic write; nothing is written here.
    func planEnable(_ scope: ClaudeSettingsScope) -> ClaudeSettingsEditPlan

    /// What disabling delegation, or uninstalling csec, puts back in
    /// `recordedSettingsPath` — the file `enable` recorded
    /// (`DelegationStatus.claudeSettingsPath`), whatever `CLAUDE_CONFIG_DIR`
    /// says now; `userSettingsPath(scope)` only when there is no record: remove
    /// `autoMode.classifyAllShell` only when `csecAddedClassifyAllShell` (the
    /// record csecd keeps from `enable`), and restore csec's non-delegation
    /// `autoMode.environment` entry. Disable and uninstall share this one plan,
    /// whose `settingsPath` is the file it reverts.
    func planRevert(
        _ scope: ClaudeSettingsScope,
        recordedSettingsPath: String?,
        csecAddedClassifyAllShell: Bool
    ) -> ClaudeSettingsEditPlan
}

/// The gate csecd and csec use. `fileAccess` nil means the live file system; a
/// test passes a fixture. `evaluate` and `discoverBuilds` read only through
/// `fileAccess`; the edit plans always read the real settings file, because
/// the atomic write they feed re-checks that file's bytes and metadata.
///
/// Keep one gate for as long as it is useful: it caches what each file says by
/// the file's identity, which is what makes a repeated evaluation cost one
/// `stat` per file.
public func makeClaudeSettingsGate(
    fileAccess: (any ClaudeSettingsFileAccess)? = nil
) -> any ClaudeSettingsGate {
    FileSystemClaudeSettingsGate(files: fileAccess ?? LiveClaudeSettingsFileAccess())
}

// MARK: - Roots

/// Every root the gate reads from, supplied by the caller. csecd builds it from
/// kernel facts about the Claude Code process P; csec from its own
/// environment and working directory.
public struct ClaudeSettingsScope: Sendable, Equatable {
    public static let defaultManagedSettingsDirectory = "/Library/Application Support/ClaudeCode"
    public static let defaultManagedPreferencesDirectory = "/Library/Managed Preferences"

    /// Claude Code's home directory: `os.homedir()` in the Claude process P,
    /// which is P's `HOME` (Node and Bun return `$HOME` as given). It roots
    /// `~/.claude`, the global config file and the project walk. csec passes
    /// its own home. csecd must not assume P's home is the account's: it reads
    /// P's exec-time `HOME` (value-readable, `ClaudeSessionFacts
    /// .valueReadableEnvironmentKeys`) and declines unless
    /// `ClaudeDelegationGateLists.processHomeMatches(_:accountHome:)` holds,
    /// and only then passes the account home here.
    public var homeDirectory: String
    /// `CLAUDE_CONFIG_DIR` as P sees it (csecd reads it from P's environment)
    /// or as csec sees it; nil when unset. Always absolute: a caller that finds
    /// it empty or relative cannot say which files Claude Code reads, and
    /// treats that as unreadable settings rather than building a scope.
    public var claudeConfigDirectory: String?
    /// Directories whose project and local settings apply, each walked up to
    /// its git root or the home directory: P's kernel working directory and the
    /// hook's `cwd` (csecd), or the working directory (csec).
    public var workingDirectories: [String]
    /// P's `--add-dir` directories, scanned for skill, agent and command hooks
    /// like the working directories. csec passes none.
    public var additionalDirectories: [String]
    /// Policy (managed) settings: `managed-settings.json` and
    /// `managed-settings.d/*.json` under this directory.
    public var managedSettingsDirectory: String
    /// The MDM preference domain `com.anthropic.claudecode`, directly under
    /// this directory and under its `<userName>/` subdirectory.
    public var managedPreferencesDirectory: String
    /// The login name, for the per-user managed preferences.
    public var userName: String
    /// The csec launcher whose own Claude Code hook is excluded from G2, as
    /// is the installed launcher's, and only when the configured handler is
    /// byte-equal to
    /// `AICommandHook.hookConfiguration(client: .claude, csecExecutablePath:)`
    /// for one of them (`FileSystemClaudeSettingsGate.csecHandlers(for:)`).
    public var csecExecutablePath: String
    /// P's inline `--settings` JSON texts
    /// (`ClaudeDelegationGateLists.launchSettings(inArgv:)`), read as one more
    /// settings layer that can only decline. csec passes none.
    public var launchSettings: [String]
    /// Prefixed to the system-wide install paths build discovery reads
    /// (Homebrew's cask, global npm); empty for the real ones. Tests point it
    /// at a fixture so a Mac's own installs do not leak in.
    public var systemRoot: String

    /// Where the gate's findings name a `--settings` layer: no file is there,
    /// and none can be (`/dev/null` is not a directory). The service shows it
    /// as `launchSettingsDisplay`.
    public static let launchSettingsPath = "/dev/null/claude --settings"
    public static let launchSettingsDisplay = "Claude Code's --settings"

    public init(
        homeDirectory: String,
        claudeConfigDirectory: String? = nil,
        workingDirectories: [String] = [],
        additionalDirectories: [String] = [],
        managedSettingsDirectory: String = Self.defaultManagedSettingsDirectory,
        managedPreferencesDirectory: String = Self.defaultManagedPreferencesDirectory,
        userName: String,
        csecExecutablePath: String,
        launchSettings: [String] = [],
        systemRoot: String = ""
    ) {
        self.homeDirectory = homeDirectory
        self.claudeConfigDirectory = claudeConfigDirectory
        self.workingDirectories = workingDirectories
        self.additionalDirectories = additionalDirectories
        self.managedSettingsDirectory = managedSettingsDirectory
        self.managedPreferencesDirectory = managedPreferencesDirectory
        self.userName = userName
        self.csecExecutablePath = csecExecutablePath
        self.launchSettings = launchSettings
        self.systemRoot = systemRoot
    }

    /// How a `CLAUDE_CONFIG_DIR` value decides Claude Code's configuration home.
    public enum ConfigDirectory: Sendable, Equatable {
        /// Unset: `~/.claude`.
        case unset
        /// An absolute directory.
        case directory(String)
        /// Empty or relative: Claude Code resolves it against its own working
        /// directory, so the files it reads cannot be named from outside.
        case unusable

        public init(environmentValue value: String?) {
            guard let value else { self = .unset; return }
            self = WireField.isAbsolutePath(value)
                ? .directory(ClaudeSettingsScope.normalizedPath(value)) : .unusable
        }
    }

    /// An absolute path with empty, `.` and `..` components resolved
    /// lexically, as Node's `path.join` does for the paths Claude Code builds;
    /// symlinks are not followed. A relative path is returned unchanged.
    public static func normalizedPath(_ path: String) -> String {
        guard path.hasPrefix("/") else { return path }
        var components: [Substring] = []
        for component in path.split(separator: "/", omittingEmptySubsequences: true) {
            switch component {
            case ".": continue
            case "..": if !components.isEmpty { components.removeLast() }
            default: components.append(component)
            }
        }
        return "/" + components.joined(separator: "/")
    }

    /// Claude Code's configuration home: `CLAUDE_CONFIG_DIR`, else `~/.claude`,
    /// normalized and in Unicode NFC as Claude Code builds it (2.1.88
    /// `envUtils.ts` `getClaudeConfigHomeDir`).
    public var claudeConfigurationHome: String {
        Self.normalizedPath(claudeConfigDirectory ?? homeDirectory + "/.claude")
            .precomposedStringWithCanonicalMapping
    }

    /// The user settings file, which `csec setup` edits and G1 reads first. A
    /// revert uses the path `enable` recorded instead, when there is one. It
    /// never has an empty, `.` or `..` component, so it is always a valid
    /// `claudeSettingsPath` when within the wire's length bound.
    public var userSettingsPath: String {
        Self.normalizedPath(claudeConfigurationHome + "/settings.json")
    }

    /// The configuration home with no `CLAUDE_CONFIG_DIR`: `~/.claude`, built
    /// as `claudeConfigurationHome` builds it.
    public var defaultConfigurationHome: String {
        Self.normalizedPath(homeDirectory + "/.claude").precomposedStringWithCanonicalMapping
    }

    /// For `path` under a configuration home that is not the default one, the
    /// same relative path under `~/.claude`; nil for the default home, and for
    /// a path outside the configuration home. Lexical only: whether the two
    /// name the same file is for the caller to check, every time.
    public func defaultHomeCounterpart(of path: String) -> String? {
        let home = claudeConfigurationHome
        let defaultHome = defaultConfigurationHome
        guard home != defaultHome, path.hasPrefix(home + "/") else { return nil }
        return Self.normalizedPath(defaultHome + "/" + path.dropFirst(home.count + 1))
    }

    /// The user settings file `csec setup` edits and records: `~/.claude/
    /// settings.json` when `CLAUDE_CONFIG_DIR`'s `settings.json` is that same
    /// regular file (a symlink to it, as each extra Claude account's config
    /// directory has), else `userSettingsPath`. Setup then edits the file the
    /// link points to, never the link, and one record serves every account.
    public func sharedUserSettingsPath(files: any ClaudeSettingsFileAccess) -> String {
        let path = userSettingsPath
        guard let counterpart = defaultHomeCounterpart(of: path),
              case let .regularFile(identity) = files.status(of: path),
              case let .regularFile(shared) = files.status(of: counterpart),
              identity.location == shared.location else { return path }
        return counterpart
    }

    /// The legacy global config file. When it exists Claude Code reads it and
    /// no other global config (2.1.88 `env.ts` `getGlobalClaudeFile`).
    public var legacyGlobalConfigPath: String {
        Self.normalizedPath(claudeConfigurationHome + "/.config.json")
    }

    /// The global config files Claude Code may read when the legacy one does
    /// not exist: `.claude<suffix>.json` in `CLAUDE_CONFIG_DIR` (else the home
    /// directory), where the suffix is `-custom-oauth` when
    /// `CLAUDE_CODE_CUSTOM_OAUTH_URL` is set, `-local-oauth` / `-staging-oauth`
    /// for Anthropic-internal OAuth configs, and empty otherwise (2.1.88
    /// `constants/oauth.ts` `fileSuffixForOauthConfig`). Which one applies
    /// depends on P's environment, so the gate applies G5 to every one of
    /// these that exists, and to the legacy file when it exists: an extra file
    /// can only decline. Each file's `env` block is applied to Claude Code's
    /// environment (`managedEnv.ts`).
    public var globalConfigPaths: [String] {
        let base = claudeConfigDirectory ?? homeDirectory
        return ["", "-custom-oauth", "-local-oauth", "-staging-oauth"].map {
            Self.normalizedPath(base + "/.claude\($0).json")
        }
    }

    /// The native installer's versions directory, where builds are discovered.
    public var claudeVersionsDirectory: String {
        Self.normalizedPath(homeDirectory + "/.local/share/claude/versions")
    }

    /// mise's standalone npm tool installation, separate from the native updater.
    public var claudeMiseVersionsDirectory: String {
        Self.normalizedPath(homeDirectory + "/.local/share/mise/installs/npm-anthropic-ai-claude-code")
    }

    /// Homebrew's cask versions directory, one `VERSION/claude` per install.
    public var claudeHomebrewVersionsDirectory: String {
        systemRoot + ClaudeInstallLayout.homebrewVersionsDirectory
    }

    /// The global npm installs build discovery checks.
    public var claudeNpmExecutables: [String] {
        ClaudeInstallLayout.npmGlobalExecutables.map { systemRoot + $0 }
    }

    /// Whether every path is absolute and within bounds.
    public var isWellFormed: Bool {
        (systemRoot.isEmpty || WireField.isAbsolutePath(systemRoot))
            && ([homeDirectory, managedSettingsDirectory, managedPreferencesDirectory, csecExecutablePath]
            + workingDirectories + additionalDirectories + (claudeConfigDirectory.map { [$0] } ?? []))
            .allSatisfy { WireField.isAbsolutePath($0) }
            && !userName.isEmpty && !userName.contains("/") && !userName.utf8.contains(0)
    }
}

// MARK: - File access seam

/// A file's identity as the gate caches it: a read is reused only while the
/// path still stats to the same device, inode, size, modification time and
/// status-change time. The status-change time is what a same-user writer
/// cannot put back: `utimensat` restores the modification time of a
/// same-size rewrite, but the kernel sets the change time to now.
public struct ClaudeSettingsFileIdentity: Sendable, Hashable {
    public let device: UInt64
    public let inode: UInt64
    public let size: UInt64
    public let modificationSeconds: Int64
    public let modificationNanoseconds: Int64
    public let statusChangeSeconds: Int64
    public let statusChangeNanoseconds: Int64

    public init(
        device: UInt64,
        inode: UInt64,
        size: UInt64,
        modificationSeconds: Int64,
        modificationNanoseconds: Int64,
        statusChangeSeconds: Int64 = 0,
        statusChangeNanoseconds: Int64 = 0
    ) {
        self.device = device
        self.inode = inode
        self.size = size
        self.modificationSeconds = modificationSeconds
        self.modificationNanoseconds = modificationNanoseconds
        self.statusChangeSeconds = statusChangeSeconds
        self.statusChangeNanoseconds = statusChangeNanoseconds
    }
}

/// What a path is, following symlinks as Claude Code does.
public enum ClaudeSettingsPathStatus: Sendable, Equatable {
    case missing
    case regularFile(ClaudeSettingsFileIdentity)
    case directory(ClaudeSettingsFileIdentity)
    /// A socket, FIFO or device: never read.
    case other
    /// It exists but could not be examined (permissions, privacy protection, a
    /// symlink loop).
    case unreadable
}

public enum ClaudeSettingsFileContents: Sendable, Equatable {
    case missing
    case contents(Data, ClaudeSettingsFileIdentity)
    /// Larger than the caller's bound; nothing was returned.
    case oversized
    /// Not a regular file, or it could not be opened or read.
    case unreadable
}

public enum ClaudeSettingsDirectoryListing: Sendable, Equatable {
    case missing
    /// Entry names (not paths), in no particular order.
    case entries([String])
    /// More entries than the caller's bound; nothing was returned.
    case tooMany
    case unreadable
}

/// How the gate reads the file system. The live implementation follows
/// symlinks (Claude Code does) and never writes.
public protocol ClaudeSettingsFileAccess: Sendable {
    func status(of path: String) -> ClaudeSettingsPathStatus
    func contents(of path: String, maximumBytes: Int) -> ClaudeSettingsFileContents
    func entries(of directory: String, maximumCount: Int) -> ClaudeSettingsDirectoryListing
}

// MARK: - The evaluation

/// Everything the gate found for one scope. Value-free: paths, fixed names and
/// digests, never a setting's value. It crosses the socket inside
/// `DelegationStatus`, so every list is bounded; a gate that finds more than
/// fits reports the excess as unreadable (`.tooMany`) rather than dropping it.
public struct ClaudeSettingsGateEvaluation: Codable, Sendable, Equatable {
    public static let maximumPaths = 64
    public static let maximumHooks = 256

    /// G1.
    public let classifyAllShell: ClaudeClassifyAllShellFinding
    /// G2: every hook other than csec's own that can approve a Bash call or
    /// block a settings reload (`ConfigChange`), from user, project, local and
    /// policy settings, every plugin Claude Code loads (enabled plugins of
    /// recorded marketplaces and of local marketplaces declared in settings,
    /// claude.ai-synced and skills-directory plugins, with their hooks
    /// modules), and skill, agent and command frontmatter.
    /// Acknowledged or not.
    public let hooks: [ClaudeHookSource]
    /// G5 on settings: injected-environment names set by the `env` block of any
    /// settings layer or of Claude Code's global config file, and a
    /// code-loading `NODE_OPTIONS` there. The global config file is
    /// `<configHome>/.config.json` when it exists, else
    /// `<CLAUDE_CONFIG_DIR or home>/.claude<suffix>.json` with the suffix
    /// `-custom-oauth`, `-local-oauth`, `-staging-oauth` or none; the gate reads
    /// every existing one of `ClaudeSettingsScope.legacyGlobalConfigPath` and
    /// `.globalConfigPaths`.
    public let environment: [ClaudeSettingsEnvironmentFinding]
    /// G6: settings files with `sandbox.enabled: true`.
    public let sandboxEnabled: [String]
    /// G6: settings files with `permissions.defaultMode: "bypassPermissions"`.
    public let bypassPermissionsDefault: [String]
    /// G6: `disableAllHooks` or `allowManagedHooksOnly` set.
    public let hooksDisabled: [ClaudeHooksDisabledFinding]
    /// Files (and directories) that exist but could not be read, parsed, or
    /// read within bounds. Any entry declines.
    public let unreadable: [ClaudeUnreadableSetting]

    public init(
        classifyAllShell: ClaudeClassifyAllShellFinding,
        hooks: [ClaudeHookSource],
        environment: [ClaudeSettingsEnvironmentFinding],
        sandboxEnabled: [String],
        bypassPermissionsDefault: [String],
        hooksDisabled: [ClaudeHooksDisabledFinding],
        unreadable: [ClaudeUnreadableSetting]
    ) {
        self.classifyAllShell = classifyAllShell
        self.hooks = hooks
        self.environment = environment
        self.sandboxEnabled = sandboxEnabled
        self.bypassPermissionsDefault = bypassPermissionsDefault
        self.hooksDisabled = hooksDisabled
        self.unreadable = unreadable
    }

    /// The approving hooks whose digest is not acknowledged.
    public func unacknowledgedHooks(acknowledgedDigests: Set<String>) -> [ClaudeHookSource] {
        hooks.filter { !acknowledgedDigests.contains($0.digest) }
    }

    /// The first reason these settings stop delegation, or nil when they
    /// allow it. The order is fixed, so csecd's decline and csec's status row
    /// name the same reason: unreadable, then G5 on settings, G1, G2, and G6
    /// (sandbox, bypass, disabled hooks).
    ///
    /// `ignoringClassifierRules` leaves auto-mode classifier rules out of G2,
    /// as an SSH signing does: rules steer the classifier, but what they
    /// steer is still auto mode's own approval, and that is all an SSH
    /// signing asks for. A hook that can approve a Bash command still
    /// declines, since then auto mode may not have approved it at all.
    public func firstFailure(
        acknowledgedDigests: Set<String>, ignoringClassifierRules: Bool = false
    ) -> ClaudeSettingsGateFailure? {
        if let unreadable = unreadable.first { return .unreadable(unreadable) }
        if let finding = environment.first { return .injectedEnvironment(finding) }
        if !classifyAllShell.isSet { return .classifyAllShellNotSet(ignoredIn: classifyAllShell.ignoredIn) }
        if let hook = unacknowledgedHooks(acknowledgedDigests: acknowledgedDigests).first(where: {
            !(ignoringClassifierRules && $0.kind == .classifierRules)
        }) {
            return .unacknowledgedHook(hook)
        }
        if let path = sandboxEnabled.first { return .sandboxEnabled(path: path) }
        if let path = bypassPermissionsDefault.first { return .bypassPermissionsDefault(path: path) }
        if let finding = hooksDisabled.first { return .hooksDisabled(finding) }
        return nil
    }

    public var isWellFormed: Bool {
        classifyAllShell.isWellFormed
            && hooks.count <= Self.maximumHooks && hooks.allSatisfy(\.isWellFormed)
            && environment.count <= Self.maximumPaths && environment.allSatisfy(\.isWellFormed)
            && sandboxEnabled.count <= Self.maximumPaths
            && sandboxEnabled.allSatisfy { WireField.isAbsolutePath($0) }
            && bypassPermissionsDefault.count <= Self.maximumPaths
            && bypassPermissionsDefault.allSatisfy { WireField.isAbsolutePath($0) }
            && hooksDisabled.count <= Self.maximumPaths && hooksDisabled.allSatisfy(\.isWellFormed)
            && unreadable.count <= Self.maximumPaths && unreadable.allSatisfy(\.isWellFormed)
    }
}

/// The first failing gate, in `firstFailure`'s order.
public enum ClaudeSettingsGateFailure: Sendable, Equatable {
    case unreadable(ClaudeUnreadableSetting)
    case injectedEnvironment(ClaudeSettingsEnvironmentFinding)
    /// `ignoredIn` names project or local settings that set it, where it does
    /// not count.
    case classifyAllShellNotSet(ignoredIn: [String])
    case unacknowledgedHook(ClaudeHookSource)
    case sandboxEnabled(path: String)
    case bypassPermissionsDefault(path: String)
    case hooksDisabled(ClaudeHooksDisabledFinding)
}

/// G1: where `autoMode.classifyAllShell` is `true`.
public struct ClaudeClassifyAllShellFinding: Codable, Sendable, Equatable {
    /// User or policy settings files (or the managed preferences plist) that
    /// set it to `true`. Any one suffices: a policy `false` cannot undo a user
    /// `true`.
    public let setIn: [String]
    /// Project or local settings files that set it, which Claude Code ignores.
    public let ignoredIn: [String]

    public init(setIn: [String], ignoredIn: [String]) {
        self.setIn = setIn
        self.ignoredIn = ignoredIn
    }

    public var isSet: Bool { !setIn.isEmpty }

    public var isWellFormed: Bool {
        setIn.count <= ClaudeSettingsGateEvaluation.maximumPaths
            && ignoredIn.count <= ClaudeSettingsGateEvaluation.maximumPaths
            && (setIn + ignoredIn).allSatisfy { WireField.isAbsolutePath($0) }
    }
}

/// G2: one hook, other than csec's own, that can approve a Bash call.
public struct ClaudeHookSource: Codable, Sendable, Hashable {
    public static let maximumSourceIDBytes = 4_096
    public static let maximumEventBytes = 64
    public static let maximumMatcherBytes = 1_024
    public static let maximumHandlerSummaryBytes = 512

    public enum Kind: String, Codable, Sendable, CaseIterable {
        /// A `hooks` entry in a settings file.
        case settings
        /// A plugin's `hooks/hooks.json`, `plugin.json` or marketplace-entry
        /// `hooks`, or its hooks module.
        case plugin
        /// A skill, agent or command file whose frontmatter has `hooks:`.
        case frontmatter
        /// A settings source's auto-mode classifier rules, as one source.
        case classifierRules = "classifier_rules"
    }

    public let kind: Kind
    /// The settings path, the plugin's `id@version`, or the frontmatter file.
    public let sourceID: String
    /// `PreToolUse`, `PermissionRequest` or `ConfigChange`; nil for
    /// frontmatter, which is not parsed, for a plugin's hooks module, and for
    /// classifier rules.
    public let event: String?
    /// The matcher as written; nil when absent (which matches everything).
    public let matcher: String?
    /// 64 lowercase hex: SHA-256 of the canonical JSON of
    /// `{sourceKind, sourceID, event, matcher, handlers}`. It is what the human
    /// acknowledges; any change to the hook changes it. For classifier rules
    /// the one handler is the source's non-default rule lists, in order, with
    /// `"$defaults"` where it is written.
    public let digest: String
    /// Sanitized, for the Touch ID sheet, status and setup: for example
    /// "cc-caffeine@samber · PreToolUse *".
    public let display: String
    /// The hook runs code fetched at run time with no pinned version (`npx
    /// pkg`, `bunx`, `pnpm dlx`, `yarn dlx`, …): acknowledging it trusts
    /// whatever that fetches. A pinned local invocation is not flagged.
    public let fetchesUnpinnedCode: Bool
    /// Classifier rules only: one `ClaudeClassifierRules.ruleDigest` per
    /// distinct rule (`"$defaults"` included), in file order. Display only:
    /// `csec setup` diffs them against the acknowledged source's to show what
    /// is new; `digest` is the authority.
    public let ruleDigests: [String]?
    /// Classifier rules only, as the gate read them: each distinct rule, in
    /// file order, for the panel csecd raises when they change
    /// (csec-0.64). Display only, like `ruleDigests`, and covered by
    /// `digest`, so it is never on the wire and never compared.
    public private(set) var rules: [ClaudeClassifierRules.Rule]?
    /// A settings or plugin hook group only: what each handler runs (a
    /// command and its arguments, or the handler as written), for the panel
    /// csecd raises when a hook is added (csec-0.64.7). Display only, like
    /// `rules`: covered by `digest`, never on the wire, never compared.
    public private(set) var handlerSummaries: [String]?
    /// A plugin's hooks module only: each module file as the gate read it,
    /// its path as the hooks file names it and its SHA-256 (or that it is
    /// missing or unreadable), so the panel can say exactly which file the
    /// acknowledgement trusts. Display only, like `handlerSummaries`.
    public private(set) var moduleFiles: [String]?
    /// Whether the gate cut none of `display`, `handlerSummaries` and
    /// `moduleFiles` short, and no summary leaves out a handler setting that
    /// might change what runs, so a panel listing them shows all the source
    /// says. Display only, like them. False unless the gate says so (only it
    /// does, which `bin/ci` guards), and for a decoded source, so only what
    /// csecd read whole can reach the phone.
    public private(set) var shownWhole = false

    private enum CodingKeys: String, CodingKey {
        case kind, sourceID, event, matcher, digest, display, fetchesUnpinnedCode, ruleDigests
    }

    public init(
        kind: Kind,
        sourceID: String,
        event: String?,
        matcher: String?,
        digest: String,
        display: String,
        fetchesUnpinnedCode: Bool,
        ruleDigests: [String]? = nil,
        rules: [ClaudeClassifierRules.Rule]? = nil,
        handlerSummaries: [String]? = nil,
        moduleFiles: [String]? = nil,
        shownWhole: Bool = false
    ) {
        self.kind = kind
        self.sourceID = sourceID
        self.event = event
        self.matcher = matcher
        self.digest = digest
        self.display = display
        self.fetchesUnpinnedCode = fetchesUnpinnedCode
        self.ruleDigests = ruleDigests
        self.rules = rules
        self.handlerSummaries = handlerSummaries
        self.moduleFiles = moduleFiles
        self.shownWhole = shownWhole
    }

    public static func == (left: Self, right: Self) -> Bool {
        left.kind == right.kind && left.sourceID == right.sourceID && left.event == right.event
            && left.matcher == right.matcher && left.digest == right.digest && left.display == right.display
            && left.fetchesUnpinnedCode == right.fetchesUnpinnedCode && left.ruleDigests == right.ruleDigests
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(kind)
        hasher.combine(sourceID)
        hasher.combine(event)
        hasher.combine(matcher)
        hasher.combine(digest)
        hasher.combine(display)
        hasher.combine(fetchesUnpinnedCode)
        hasher.combine(ruleDigests)
    }

    public var displayID: String { GrantIDSelector.displayID(kind: .hook, id: digest) }

    public var isWellFormed: Bool {
        WireField.isBoundedText(sourceID, maximumBytes: Self.maximumSourceIDBytes)
            && (event.map { WireField.isBoundedText($0, maximumBytes: Self.maximumEventBytes) } ?? true)
            && (matcher.map { $0.utf8.count <= Self.maximumMatcherBytes && !$0.utf8.contains(0) } ?? true)
            && WireField.isLowercaseHex(digest, length: 64)
            && WireField.isBoundedText(display, maximumBytes: AcknowledgedHookSummary.maximumDisplayBytes)
            && (ruleDigests == nil) == (kind != .classifierRules)
            && (ruleDigests.map(ClaudeClassifierRules.areWellFormed) ?? true)
    }
}

/// G2 on auto-mode classifier rules: how a settings source's rules are read,
/// digested and shown. Claude Code 2.1.280 (`aH`) concatenates `allow`,
/// `soft_deny`, `hard_deny` and `environment` from user, `--settings` and
/// policy settings, ignoring project and local settings; a layer's list
/// replaces the built-in section unless it holds the literal `"$defaults"`.
/// The schema's `deny` key is never read.
public enum ClaudeClassifierRules {
    /// The rule lists, in the order a source's digest and display take them.
    public static let sections = ["allow", "soft_deny", "hard_deny", "environment"]
    /// The marker that keeps Claude Code's built-in rules in a section.
    public static let defaultsMarker = "$defaults"
    /// More rules than this in one source (`"$defaults"` included) declines
    /// as too many to acknowledge.
    public static let maximumRulesPerSource = 512
    /// Hex characters in a rule digest: 128 bits, enough that no second rule
    /// can be made to look like an acknowledged one.
    public static let ruleDigestLength = 32

    /// One rule as `csec setup` shows it.
    public struct Rule: Sendable, Equatable {
        public let section: String
        public let text: String
        public let digest: String

        public init(section: String, text: String) {
            self.init(section: section, text: text, digest: ClaudeClassifierRules.ruleDigest(section: section, text: text))
        }

        init(section: String, text: String, digest: String) {
            self.section = section
            self.text = text
            self.digest = digest
        }
    }

    /// A settings object's rule lists: section name to its list, only the
    /// sections present. Nil when `autoMode` or a list is not the shape Claude
    /// Code reads (an object; arrays of strings).
    public static func lists(inSettings settings: [String: Any]) -> [String: [String]]? {
        guard let value = settings["autoMode"] else { return [:] }
        guard let autoMode = value as? [String: Any] else { return nil }
        var lists: [String: [String]] = [:]
        for section in sections {
            guard let listed = autoMode[section] else { continue }
            guard let items = listed as? [Any] else { return nil }
            var texts: [String] = []
            for item in items {
                guard let text = item as? String else { return nil }
                texts.append(text)
            }
            lists[section] = texts
        }
        return lists
    }

    /// `lists` as the gate counts them: csec's own `autoMode.environment`
    /// entries removed by exact text (only where `csec setup` writes them, the
    /// user settings), then every section that is absent or exactly
    /// `["$defaults"]` dropped, since it leaves the built-in rules as they are.
    /// An empty list stays: it deletes the built-in section.
    public static func counted(_ lists: [String: [String]], excludingCsecEntries: Bool) -> [String: [String]] {
        var counted: [String: [String]] = [:]
        for (section, list) in lists {
            var texts = list
            if excludingCsecEntries, section == "environment" {
                let csec = CodingAgentSetup.ClaudeAutoModeEntry.standard.texts
                    + CodingAgentSetup.ClaudeAutoModeEntry.delegationAware.texts
                texts.removeAll { text in csec.contains { bytesEqual($0, text) } }
            }
            if texts.count == 1, bytesEqual(texts[0], defaultsMarker) { continue }
            counted[section] = texts
        }
        return counted
    }

    /// The counted rules of one settings file's bytes (JSON, or a property
    /// list), for `csec setup` to show; nil when they cannot be read.
    public static func rules(inSettingsData data: Data, excludingCsecEntries: Bool) -> [Rule]? {
        let object = strictJSONValue(data)
            ?? (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil))
        guard let settings = object as? [String: Any], let lists = lists(inSettings: settings) else { return nil }
        let counted = counted(lists, excludingCsecEntries: excludingCsecEntries)
        return sections.flatMap { section in
            (counted[section] ?? []).map { Rule(section: section, text: $0, digest: ruleDigest(section: section, text: $0)) }
        }
    }

    /// 32 lowercase hex: the first 128 bits of SHA-256 of `[section, text]` as
    /// JSON.
    public static func ruleDigest(section: String, text: String) -> String {
        let json = Data("[".utf8) + GateRun.jsonString(section) + Data(",".utf8) + GateRun.jsonString(text) + Data("]".utf8)
        return SHA256.hash(data: json).prefix(ruleDigestLength / 2).map { String(format: "%02x", $0) }.joined()
    }

    static func areWellFormed(_ digests: [String]) -> Bool {
        digests.count <= maximumRulesPerSource
            && digests.allSatisfy { WireField.isLowercaseHex($0, length: ruleDigestLength) }
    }

    /// The rule count a source's display names, `"$defaults"` excluded.
    static func ruleCount(_ counted: [String: [String]]) -> Int {
        counted.values.reduce(0) { $0 + $1.filter { !bytesEqual($0, defaultsMarker) }.count }
    }

    static func bytesEqual(_ left: String, _ right: String) -> Bool { Array(left.utf8) == Array(right.utf8) }
}

/// G5 on settings: an `env` block sets a listed name.
public struct ClaudeSettingsEnvironmentFinding: Codable, Sendable, Equatable {
    /// The entry of `ClaudeDelegationGateLists` that matched: an exact name, a
    /// prefix followed by `*`, or `NODE_OPTIONS` when its value loads code.
    /// Never the raw key.
    public let name: String
    public let path: String

    public init(name: String, path: String) {
        self.name = name
        self.path = path
    }

    public var isWellFormed: Bool {
        WireField.isBoundedText(name, maximumBytes: 128) && WireField.isAbsolutePath(path)
    }
}

/// G6: hooks switched off, so csec's own never registers.
public struct ClaudeHooksDisabledFinding: Codable, Sendable, Equatable {
    public enum Setting: String, Codable, Sendable, CaseIterable {
        case disableAllHooks
        case allowManagedHooksOnly
    }

    public let setting: Setting
    public let path: String

    public init(setting: Setting, path: String) {
        self.setting = setting
        self.path = path
    }

    public var isWellFormed: Bool { WireField.isAbsolutePath(path) }
}

public struct ClaudeUnreadableSetting: Codable, Sendable, Equatable {
    public enum Reason: String, Codable, Sendable, CaseIterable {
        /// It exists but could not be opened or read.
        case unreadable
        /// Larger than `CodingAgentSetup.maximumConfigurationBytes`.
        case oversized
        /// Not the JSON (or property list) shape Claude Code reads.
        case unparseable
        /// A directory with more entries than the gate scans.
        case tooMany
        /// This build has no settings gate.
        case gateUnavailable = "gate_unavailable"
        /// A managed source can replace or extend policy with helper output
        /// or a nested fallback payload that this gate cannot inspect.
        case generatedPolicy = "generated_policy"
    }

    public let path: String
    public let reason: Reason

    public init(path: String, reason: Reason) {
        self.path = path
        self.reason = reason
    }

    public var isWellFormed: Bool { WireField.isAbsolutePath(path) }
}

// MARK: - Builds

/// A Claude Code build the gate found on disk.
public struct DiscoveredClaudeBuild: Codable, Sendable, Equatable {
    public let path: String
    public let versionLabel: String
    /// The host-architecture slice's cdhash, lowercase; nil when the
    /// signature could not be read.
    public let cdHash: String?
    /// Satisfies `ForeignCodeIdentity.anthropicClaudeCodeRequirement`.
    public let signedByAnthropic: Bool

    public init(path: String, versionLabel: String, cdHash: String?, signedByAnthropic: Bool) {
        self.path = path
        self.versionLabel = versionLabel
        self.cdHash = cdHash
        self.signedByAnthropic = signedByAnthropic
    }
}

public struct ClaudeBuildDiscovery: Sendable, Equatable {
    public let builds: [DiscoveredClaudeBuild]
    public let unreadable: [ClaudeUnreadableSetting]

    public init(builds: [DiscoveredClaudeBuild], unreadable: [ClaudeUnreadableSetting]) {
        self.builds = builds
        self.unreadable = unreadable
    }

    /// Builds neither signed by Anthropic nor trusted by cdhash.
    public func untrusted(trustedCDHashes: Set<String>) -> [DiscoveredClaudeBuild] {
        builds.filter { build in
            !build.signedByAnthropic && !(build.cdHash.map(trustedCDHashes.contains) ?? false)
        }
    }
}

// MARK: - Planned settings edits

/// One planned change to the user settings file, for `enable`, disable and
/// uninstall. Applying it is `CodingAgentSetup.apply(_:)` on `outcome`'s plan,
/// which re-reads the file and refuses if it changed since planning.
public struct ClaudeSettingsEditPlan: Sendable {
    public enum ClassifyAllShellEdit: String, Sendable, Codable, CaseIterable {
        /// Enable: it was absent or false; csec sets it to true and records
        /// that it did.
        case add
        /// Enable: already true; csec leaves it and records nothing.
        case alreadySet
        /// Revert: csec added it, so csec removes it.
        case remove
        /// Revert: csec did not add it, so it stays.
        case leave
        /// Nothing to do with it (a blocked or unavailable plan).
        case unchanged
    }

    public enum EnvironmentEntryEdit: String, Sendable, Codable, CaseIterable {
        /// Enable: csec's entry becomes the delegation-aware text.
        case delegationAware
        /// Revert: csec's entry goes back to the non-delegation text, or is
        /// removed where csec added it.
        case standard
        /// Already in the planned state, or csec has no entry to change.
        case unchanged
    }

    public enum Outcome: Sendable {
        /// Write this plan (one atomic write of the settings file).
        case write(CodingAgentConfigurationPlan)
        /// The file already says what the plan wants.
        case nothingToChange
        /// The file cannot be changed safely; the reason is value-free.
        case blocked(String)
    }

    /// The file the plan edits. For `planEnable`, what the `enable` request
    /// sends as `claudeSettingsPath`.
    public let settingsPath: String
    public let classifyAllShell: ClassifyAllShellEdit
    public let environmentEntry: EnvironmentEntryEdit
    public let outcome: Outcome

    public init(
        settingsPath: String,
        classifyAllShell: ClassifyAllShellEdit,
        environmentEntry: EnvironmentEntryEdit,
        outcome: Outcome
    ) {
        self.settingsPath = settingsPath
        self.classifyAllShell = classifyAllShell
        self.environmentEntry = environmentEntry
        self.outcome = outcome
    }

    /// What `configure_delegation enable` records as `setClassifyAllShell`.
    public var csecAddsClassifyAllShell: Bool { classifyAllShell == .add }

    /// What the user must remove by hand when a revert cannot be written
    /// (blocked, or the write failed), before csecd's record of what csec
    /// changed is gone: the file, `autoMode.classifyAllShell` when csec added
    /// it (nil: csecd could not say), and csec's `autoMode.environment` entry.
    /// Value-free; the path is sanitized for a terminal.
    public static func manualRevertInstructions(settingsPath: String, csecAddedClassifyAllShell: Bool?) -> String {
        let entry = "the autoMode.environment entry that begins \""
            + CodingAgentSetup.claudeAutoModeEnvironmentEntryPrefix + "\""
        let keys: String
        switch csecAddedClassifyAllShell {
        case true?:
            keys = "autoMode.classifyAllShell (csec added it) and " + entry
        case false?:
            keys = entry + " (leave autoMode.classifyAllShell: csec did not add it)"
        case nil:
            keys = entry + ", and autoMode.classifyAllShell unless you set it yourself "
                + "(csecd could not say whether csec added it)"
        }
        return "remove " + keys + " from " + ReviewDisplay.sanitized(settingsPath)
    }
}

// MARK: - The launch-time lists (G4 and G5)

/// The Claude Code launch options (G4) and environment names (G5) that decline
/// delegation, from the Claude Code 2.1.280 bundle. csecd checks P's argv and
/// exec-time environment against them; `csec setup` and the settings gate
/// check settings `env` blocks against the environment names. Every match
/// reports the list entry, never the raw argument or variable.
public enum ClaudeDelegationGateLists {
    /// Long options that decline on presence, as `--name` or `--name=value`:
    /// a headless, SDK or remote driver; reachable bypass; a non-human
    /// answering permission prompts; settings csecd cannot see or that drop
    /// user settings (`--restricted` drops user, project and local settings,
    /// csec's own hook with them); hook sources csecd cannot see; external
    /// message drivers.
    public static let launchOptions: [String] = [
        "--print", "--output-format", "--input-format", "--sdk-url", "--await-initialize",
        "--attach-serve", "--remote",
        "--dangerously-skip-permissions", "--allow-dangerously-skip-permissions",
        "--permission-prompt-tool", "--permission-prompts",
        "--settings", "--managed-settings", "--setting-sources", "--project-config-root",
        "--forward-home-settings", "--restricted",
        "--plugin-dir", "--plugin-dir-no-mcp", "--plugin-url", "--trust-plugin", "--agents",
        "--channels", "--dangerously-load-development-channels",
    ]

    /// Short options that decline anywhere in a `-abc` cluster (`-p`, print).
    public static let shortLaunchOptions: Set<Character> = ["p"]

    /// `--permission-mode bypassPermissions` (or `=bypassPermissions`)
    /// declines; other modes are the registration's business.
    public static let permissionModeOption = "--permission-mode"
    public static let bypassPermissionMode = "bypassPermissions"

    /// Environment names that decline on presence.
    public static let environmentNames: [String] = [
        "BUN_OPTIONS", "BUN_BE_BUN", "BUN_INSPECT_PRELOAD", "BUN_CONFIG_FILE", "BUN_TCC_OPTIONS",
        "BUN_RUNTIME_TRANSPILER_CACHE_PATH",
        "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE", "SSL_CERT_DIR",
        "ANTHROPIC_BASE_URL", "ANTHROPIC_BEDROCK_BASE_URL", "ANTHROPIC_VERTEX_BASE_URL",
        "ANTHROPIC_FOUNDRY_BASE_URL",
        // 2.1.280's provider resolver (`SW`) also honours these three.
        "ANTHROPIC_BEDROCK_MANTLE_BASE_URL", "ANTHROPIC_AWS_BASE_URL", "ANTHROPIC_GOOGLE_CLOUD_BASE_URL",
        // The auto-mode classifier's verdict is what delegation trusts, and
        // these hand it to someone else (csec-6h2q, 2.1.280). Claude Code
        // JSON-parses `CLAUDE_CODE_EXTRA_BODY` (`cG`) and spreads it last
        // into every API request body (`_0`), the classifier's included, so
        // it can replace the classifier's prompt, transcript or model. The
        // provider selectors (`Oe`) send the classifier's calls to a
        // third-party endpoint built from environment: Foundry's host is
        // `https://${ANTHROPIC_FOUNDRY_RESOURCE}.services.ai.azure.com`,
        // unvalidated, and the gateway takes `ANTHROPIC_BASE_URL`; declining
        // the selectors covers every companion that only acts under one.
        // `ANTHROPIC_UNIX_SOCKET` routes every API fetch through a local
        // socket (`wi`). `CLAUDE_CODE_AUTO_MODE_PRIOR_ASSISTANT_CONTEXT`
        // (`eCr`) feeds the agent's own prose to the classifier, so an
        // injected agent can argue its case. The other `CLAUDE_CODE_AUTO_MODE_*`
        // knobs only add real context or change format, temperature or
        // concurrency. 2.1.302 reads `_MODEL` under server-config precedence,
        // organization policy and the API's escalated-check safeguard; like
        // main-model selection, it changes quality within the same prompt
        // and provider policy. `_EXTERNAL_PERMISSIONS`,
        // `CLAUDE_CODE_BG_CLASSIFIER_MODEL` and `CLAUDE_CODE_TWO_STAGE_CLASSIFIER`
        // still have no reader. None of those names declines.
        "CLAUDE_CODE_EXTRA_BODY", "ANTHROPIC_UNIX_SOCKET", "CLAUDE_CODE_AUTO_MODE_PRIOR_ASSISTANT_CONTEXT",
        "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
        "CLAUDE_CODE_USE_ANTHROPIC_AWS", "CLAUDE_CODE_USE_ANTHROPIC_GOOGLE_CLOUD", "CLAUDE_CODE_USE_MANTLE",
        "CLAUDE_CODE_USE_GATEWAY",
        "CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_CODE_SHELL_LAUNCHER_SCRIPT",
        "CLAUDE_CODE_MANAGED_SETTINGS_PATH", "CLAUDE_CODE_REMOTE_SETTINGS_PATH",
        "CLAUDE_CODE_MOCK_REMOTE_SETTINGS", "CLAUDE_CODE_BRIDGE_CHILD_MACHINE_SETTINGS",
        "CLAUDE_CODE_SANDBOXED", "CLAUDE_CODE_FORCE_SANDBOX",
        "CLAUDE_CODE_ADOPT_UNDERIVABLE_PARKED_PERMISSION",
        "CLAUDE_CODE_ENTRYPOINT", "CLAUDECODE",
        // Remote sessions can materialize a separate tool relay's proxy/CA
        // environment after launch (2.1.280 and 2.1.295). Like the remote
        // argv drivers, this is outside the local session the gate attests.
        "CLAUDE_CODE_REMOTE",
        // 2.1.302's standalone relay starts separately, without REMOTE,
        // and applies its selected proxy to subsequent runtime traffic.
        "CCR_AGENT_PROXY_RELAY_MODE",
        // Restricted mode, as `--restricted`: user, project and local
        // settings are dropped.
        "CLAUDE_CODE_RESTRICTED",
        // Plugins, their hooks and (cowork) the user settings file load from
        // somewhere the gate does not read (2.1.88 `pluginDirectories.ts`,
        // `settings.ts`, `zipCache.ts`; 2.1.280 loads `CLAUDE_CODE_PLUGIN_DIRS`
        // as inline plugins, enabled by default, like `--plugin-dir`).
        "CLAUDE_CODE_PLUGIN_CACHE_DIR", "CLAUDE_CODE_PLUGIN_SEED_DIR", "CLAUDE_CODE_USE_COWORK_PLUGINS",
        "CLAUDE_CODE_PLUGIN_DIRS", "CLAUDE_CODE_PLUGIN_USE_ZIP_CACHE",
        // A user-delegated session (2.1.325) picks the auto-mode classifier's
        // model itself, ahead of the server-config and organization-policy
        // precedence that keeps `CLAUDE_CODE_AUTO_MODE_MODEL` acceptable:
        // the session's own default wins outright, `_ALLOWED_CHECK_MODELS`
        // replaces the allowed checkers, `_ANY_CHECK_MODEL` lets the main
        // model check its own actions, and `_DIRECT_API` changes the check's
        // routing, MCP policy and what happens when no checker is available.
        // The classifier's verdict is what delegation trusts. Nothing reads
        // `_ALLOWED_PROVIDERS` yet beyond the lists that pass the family to
        // child sessions; it declines with the rest so a later reader is
        // covered.
        "CLAUDE_CODE_USER_DELEGATED_SESSION", "CLAUDE_CODE_USER_DELEGATED_SESSION_DIRECT_API",
        "CLAUDE_CODE_USER_DELEGATED_SESSION_ALLOWED_CHECK_MODELS",
        "CLAUDE_CODE_USER_DELEGATED_SESSION_ANY_CHECK_MODEL",
        "CLAUDE_CODE_USER_DELEGATED_SESSION_ALLOWED_PROVIDERS",
    ]

    /// Environment name prefixes that decline on presence.
    public static let environmentPrefixes: [String] = [
        "BUN_INSPECT", "BUN_INTERNAL_", "BUN_JSC_", "JSC_", "DYLD_",
    ]

    /// Names that decline when a settings `env` block sets them (any layer,
    /// and Claude Code's global config file), on top of `environmentNames`.
    /// Claude Code applies those blocks to its own environment after launch,
    /// and each of these then moves every later read of the user settings,
    /// hooks, plugins and global config somewhere the gate never looked
    /// (2.1.88 `envUtils.ts` memoizes the configuration home on
    /// `CLAUDE_CONFIG_DIR`'s value; `xdg.ts` roots the home at `HOME`). In P's
    /// exec-time environment the two are read for their value instead, and
    /// root the scope. `ZDOTDIR` moves the startup files of every Bash tool
    /// shell, which inherits the block, and the kernel withholds the tool
    /// shell's own environment, so a block that sets it declines here.
    /// `CLAUDE_SECURESTORAGE_CONFIG_DIR` moves Claude Code's stored sign-ins,
    /// which csecd checks for a Cloud-gateway one (`secureStorageDirectoryName`).
    public static let settingsEnvironmentNames: [String] = [
        "CLAUDE_CONFIG_DIR", "HOME", "ZDOTDIR", "CLAUDE_SECURESTORAGE_CONFIG_DIR",
    ]

    /// The list entry a settings `env` block's name matches: an injected-
    /// environment entry (`environmentEntry(matching:)`), or a name from
    /// `settingsEnvironmentNames`. Case-sensitive.
    public static func settingsEnvironmentEntry(matching name: String) -> String? {
        environmentEntry(matching: name) ?? (settingsEnvironmentNames.contains(name) ? name : nil)
    }

    /// P's `HOME`, read for its value: Claude Code roots `~/.claude`, its
    /// global config and the project walk at it, so a session started with
    /// another `HOME` reads settings the gate would not.
    public static let homeName = "HOME"

    /// Read for its value: a non-empty one moves the plaintext record of
    /// Claude Code's sign-ins out of its configuration home (2.1.316 `_F`),
    /// where csecd looks for a stored Cloud-gateway sign-in
    /// (`ClaudeGatewaySignIn`), so it declines. An empty one keeps the
    /// default record and passes. Launchers that switch accounts unset it.
    public static let secureStorageDirectoryName = "CLAUDE_SECURESTORAGE_CONFIG_DIR"

    /// Whether P's exec-time `HOME` names the account's home directory
    /// (both lexically normalized, as Claude Code joins paths). An absent,
    /// empty or relative `HOME` does not: csecd declines, rather than guess
    /// which files that Claude Code reads.
    public static func processHomeMatches(_ processHome: String?, accountHome: String) -> Bool {
        guard let processHome, WireField.isAbsolutePath(processHome),
              WireField.isAbsolutePath(accountHome) else { return false }
        return ClaudeSettingsScope.normalizedPath(processHome) == ClaudeSettingsScope.normalizedPath(accountHome)
    }

    /// Read for its value, never declined on presence: users commonly set
    /// `--max-old-space-size`, so only code-loading flags decline.
    public static let nodeOptionsName = "NODE_OPTIONS"
    public static let nodeOptionsCodeLoadingFlags: [String] = [
        "--require", "-r", "--import", "--loader", "--experimental-loader", "--inspect", "--preload",
    ]

    /// Declines like every listed name unless its value is exactly csec's own
    /// prefix script (`ClaudeCodeShellPrefix.isCsecPrefix`).
    public static let shellPrefixName = "CLAUDE_CODE_SHELL_PREFIX"

    /// Whether a settings `env` entry is csec's own shell prefix: its prefix
    /// script runs every Bash command under `csec ai` after auto mode reviewed
    /// it (csec-0.83.1). Any other value of the name still declines.
    public static func isAcceptedShellPrefix(name: String, value: Any?, accepted: String?) -> Bool {
        name == shellPrefixName && ClaudeCodeShellPrefix.isCsecPrefix(value as? String, accepted: accepted)
    }

    /// The list entry an environment name matches: the exact name, or
    /// `PREFIX*`. Case-sensitive, as the runtime reads them.
    public static func environmentEntry(matching name: String) -> String? {
        if environmentNames.contains(name) { return name }
        return environmentPrefixes.first { name.hasPrefix($0) }.map { $0 + "*" }
    }

    /// The code-loading flag `NODE_OPTIONS` carries, or nil. Conservative on
    /// every ambiguity: quotes and backslashes are dropped before splitting on
    /// whitespace, `_` reads as `-` (Node accepts both), and a flag matches as
    /// a prefix (`--inspect-brk`, `--require=x`, `-rx`).
    public static func nodeOptionsCodeLoadingFlag(in value: String) -> String? {
        let unquoted = String(value.unicodeScalars.filter { $0 != "\"" && $0 != "'" && $0 != "\\" })
        for token in unquoted.split(whereSeparator: { $0.isWhitespace }) {
            let normalized = token.lowercased().replacingOccurrences(of: "_", with: "-")
            if let flag = nodeOptionsCodeLoadingFlags.first(where: { normalized.hasPrefix($0) }) {
                return flag
            }
        }
        return nil
    }

    /// The first declining launch option in `argv` (argv[0] included, and
    /// skipped), as its list entry. Claude Code parses options with commander,
    /// which matches long names exactly (no abbreviations), accepts
    /// `--name=value`, and splits `-abc` clusters; this reads every token
    /// that way, including after `--` and in option values, which can only
    /// decline more. Tokens are read as commander and Claude Code's own argv
    /// scan read them, by code unit (`ArgvToken`), never by Swift Character:
    /// a combining mark after `=` would otherwise join it into one Character
    /// and hide `--settings=<mark>file` from this scan.
    ///
    /// `--settings` is the one listed option that declines only for some
    /// values: inline JSON (`isInlineSettings`) does not, since the settings
    /// gate reads it from argv as a settings layer of its own
    /// (`launchSettings(inArgv:)`); a file path, or no value, does.
    public static func launchOption(inArgv argv: [String]) -> String? {
        var index = 1
        while index < argv.count {
            let token = ArgvToken(argv[index])
            index += 1
            if token.hasPrefix("--") {
                let name = token.name
                if name == settingsOption {
                    guard let value = optionValue(token, argv: argv, next: index), isInlineSettings(value) else {
                        return name
                    }
                    continue
                }
                if launchOptions.contains(name) { return name }
                if name == permissionModeOption {
                    let value = optionValue(token, argv: argv, next: index)
                    if value?.lowercased() == bypassPermissionMode.lowercased() {
                        return "\(permissionModeOption) \(bypassPermissionMode)"
                    }
                }
            } else if token.hasPrefix("-") {
                let cluster = token.text.unicodeScalars.dropFirst().prefix { $0.isASCII && $0.properties.isAlphabetic }
                if let short = cluster.first(where: { shortLaunchOptions.contains(Character($0)) }) {
                    return "-\(short)"
                }
            }
        }
        return nil
    }

    /// The option whose inline-JSON value the settings gate reads.
    public static let settingsOption = "--settings"

    /// Whether Claude Code reads a `--settings` value as inline JSON rather
    /// than a file, and csecd can read it as Claude Code did. 2.1.280
    /// (`A_o`, run from raw argv before commander parses it) trims the value
    /// and takes it as JSON when it starts with `{` and ends with `}`; any
    /// other value is a file path, read once at startup and pinned, so csecd
    /// reading the file later could see bytes Claude Code never loaded.
    /// Exactly `{`…`}`, untrimmed: JavaScript's trim and Swift's whitespace
    /// differ (U+0085 is whitespace only to Swift), so a value with anything
    /// around the braces declines as a file would, and csecd never reads a
    /// value as inline that Claude Code reads as a path.
    public static func isInlineSettings(_ value: String) -> Bool {
        value.unicodeScalars.first == "{" && value.unicodeScalars.last == "}"
    }

    /// Every `--settings` value in `argv` (argv[0] skipped), in order, read
    /// as `launchOption(inArgv:)` reads them: `--settings value` and
    /// `--settings=value`, after `--` too. Claude Code applies only the last
    /// one before `--`; the gate reads them all, which can only decline more.
    /// Meaningful only once `launchOption(inArgv:)` found none declining, so
    /// that every value here is inline JSON.
    public static func launchSettings(inArgv argv: [String]) -> [String] {
        var values: [String] = []
        var index = 1
        while index < argv.count {
            let token = ArgvToken(argv[index])
            index += 1
            if token.name == settingsOption, let value = optionValue(token, argv: argv, next: index) {
                values.append(value)
            }
        }
        return values
    }

    /// A long option's value: after `=`, or the next token.
    private static func optionValue(_ token: ArgvToken, argv: [String], next index: Int) -> String? {
        if let value = token.inlineValue { return value }
        return index < argv.count ? argv[index] : nil
    }
}

/// One argv token read the way commander and Claude Code's raw argv scan
/// (2.1.280 `fIr`) read it: by code unit, splitting at the first `=`. Swift's
/// `String.split`, `firstIndex(of:)` and `hasPrefix` work on Characters, and
/// a combining mark (U+0301, U+200D, U+FE0F, …) after `=` or `-` joins it into
/// one Character, so `"--settings=\u{301}x.json"` would neither split nor
/// match while Claude Code loads `\u{301}x.json` as a settings file. `=` and
/// `-` are ASCII, so a UTF-8 byte split falls exactly where a UTF-16 one does.
/// Names still compare as Strings, whose canonical equivalence can only make
/// a name match more options, never fewer.
public struct ArgvToken {
    public let text: String

    public init(_ text: String) { self.text = text }

    /// Whether the token's bytes start with `prefix`'s.
    public func hasPrefix(_ prefix: String) -> Bool { text.utf8.starts(with: prefix.utf8) }

    /// Everything before the first `=`, or the whole token.
    public var name: String {
        let bytes = Array(text.utf8)
        guard let equals = bytes.firstIndex(of: UInt8(ascii: "=")) else { return text }
        return String(decoding: bytes[..<equals], as: UTF8.self)
    }

    /// Everything after the first `=`, or nil when there is none.
    public var inlineValue: String? {
        let bytes = Array(text.utf8)
        guard let equals = bytes.firstIndex(of: UInt8(ascii: "=")) else { return nil }
        return String(decoding: bytes[(equals + 1)...], as: UTF8.self)
    }
}

// MARK: - Which hooks can approve a shell command

extension ClaudeHookSource {
    /// Whether a hook group's matcher can select a tool that runs a shell
    /// command (`AICommandHook.shellTools(for: .claude)`: Bash, and Monitor,
    /// which runs its command in the same Bash tool shell), exactly as Claude
    /// Code 2.1.88 matches (`utils/hooks.ts` `matchesPattern`): absent, empty
    /// and `*` match everything; `[A-Za-z0-9_|]+` is an exact name or a `|`
    /// list of them; anything else is a JavaScript regular expression, which
    /// csec cannot run and so counts as matching. Neither tool has a legacy
    /// alias for a name to normalize from.
    public static func matcherCanMatchShellTool(_ matcher: String?) -> Bool {
        guard let matcher, !matcher.isEmpty, matcher != "*" else { return true }
        let isNameList = matcher.unicodeScalars.allSatisfy { scalar in
            (scalar >= "a" && scalar <= "z") || (scalar >= "A" && scalar <= "Z")
                || (scalar >= "0" && scalar <= "9") || scalar == "_" || scalar == "|"
        }
        guard isNameList else { return true }
        let tools = AICommandHook.shellTools(for: .claude)
        return matcher.split(separator: "|", omittingEmptySubsequences: false).contains {
            tools.contains(String($0))
        }
    }
}

// MARK: - Hooks that run code fetched at run time

/// Whether a hook's command runs code it fetches when it runs, with no
/// version pinned (`npx pkg`, `bunx`, `pnpm dlx`, `yarn dlx`, `npm exec`,
/// `npm init`/`create`, `uvx`, `pipx run`, `deno run <url>`, `go run
/// mod@latest`, `gem exec`, `docker run` without a digest, a download piped
/// into a shell): acknowledging such a hook trusts whatever that fetch
/// returns, every time. A pinned exact version, or a local path (for example
/// `node ~/.local/share/tool/1.2.3/…/tool.js`), is not flagged. The reading is
/// conservative: quoting is dropped and shell operators split words, so a
/// runner inside `sh -c "…"` is still found.
public enum ClaudeHookFetchCheck {
    public static func fetchesUnpinnedCode(command: String) -> Bool {
        fetchesUnpinnedCode(words: words(in: command))
    }

    /// Programs that download, and interpreters a download can be fed to.
    static let downloaders: Set<String> = ["curl", "wget", "fetch", "aria2c", "http", "xh"]
    static let interpreters: Set<String> = [
        "sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "node", "ruby", "perl", "php", "source",
        "eval", "bun", "deno", "osascript",
    ]
    static let containerRunners: Set<String> = ["docker", "podman", "nerdctl"]

    /// The words of a hook command, with quotes, backslashes and backticks
    /// dropped and shell operators read as word breaks.
    public static func words(in command: String) -> [String] {
        var text = String.UnicodeScalarView()
        for scalar in command.unicodeScalars {
            switch scalar {
            case "\"", "'", "`", "\\":
                continue
            case ";", "&", "|", "(", ")", "<", ">", "{", "}", "$", "\n", "\r", "\t":
                text.append(" ")
            default:
                text.append(scalar)
            }
        }
        return String(text).split(whereSeparator: { $0 == " " }).map(String.init)
    }

    public static func fetchesUnpinnedCode(words: [String]) -> Bool {
        let programs = words.map { ($0 as NSString).lastPathComponent }
        // A download and an interpreter in one command: `curl … | sh`,
        // `bash <(curl …)`, `sh -c "$(wget -O- …)"`.
        if programs.contains(where: downloaders.contains), programs.contains(where: interpreters.contains) {
            return true
        }
        for index in words.indices {
            let name = programs[index]
            let next = index + 1 < words.count ? words[index + 1] : nil
            let rest = Array(words[(index + 1)...])
            switch (name, next) {
            case ("go", "run"?):
                if rest.dropFirst().contains(where: { word in
                    guard !word.hasPrefix("-"), let at = word.lastIndex(of: "@") else { return false }
                    return !isPinnedGoVersion(String(word[word.index(after: at)...]))
                }) { return true }
            case ("gem", "exec"?):
                if !hasExactVersionOption(Array(rest.dropFirst())) { return true }
            case let (runner, "run"?) where containerRunners.contains(runner):
                if !rest.contains(where: { $0.contains("@sha256:") }) { return true }
            default:
                break
            }
            let skipped: Int
            let style: Style
            switch (name, next) {
            case ("npx", _), ("bunx", _), ("pnpx", _):
                skipped = 1
                style = .node
            case ("npm", "exec"?), ("npm", "x"?), ("bun", "x"?), ("pnpm", "dlx"?), ("yarn", "dlx"?),
                 ("npm", "init"?), ("npm", "create"?), ("yarn", "create"?), ("pnpm", "create"?), ("bun", "create"?):
                skipped = 2
                style = .node
            case ("uvx", _):
                skipped = 1
                style = .python
            case ("pipx", "run"?):
                skipped = 2
                style = .python
            case ("uv", "tool"?) where index + 2 < words.count && words[index + 2] == "run":
                skipped = 3
                style = .python
            case ("deno", "run"?), ("deno", "x"?):
                skipped = 2
                style = .deno
            default:
                continue
            }
            if invocationFetchesUnpinned(Array(words[(index + skipped)...]), style: style) { return true }
        }
        return false
    }

    private enum Style { case node, python, deno }

    /// The words after the runner: its options, then the package it runs.
    /// `--package`/`-p` (node) and `--from`/`--spec` (python) name the package
    /// instead of the first word; `--with` adds packages it also fetches.
    private static func invocationFetchesUnpinned(_ words: [String], style: Style) -> Bool {
        let packageOptions: Set<String>
        let extraOptions: Set<String>
        switch style {
        case .node:
            packageOptions = ["-p", "--package"]
            extraOptions = []
        case .python:
            packageOptions = ["--from", "--spec"]
            extraOptions = ["--with"]
        case .deno:
            packageOptions = []
            extraOptions = []
        }
        var packages: [String] = []
        var extras: [String] = []
        var positional: String?
        var index = 0
        while index < words.count {
            let word = words[index]
            index += 1
            if word == "--" {
                positional = index < words.count ? words[index] : nil
                break
            }
            // `npx -c '<command>'` runs a command string: read as fetching.
            if style == .node, word == "-c" || word == "--call" { return true }
            var option = word
            var value: String?
            if word.hasPrefix("-"), let equals = word.firstIndex(of: "=") {
                option = String(word[..<equals])
                value = String(word[word.index(after: equals)...])
            }
            if packageOptions.contains(option) || extraOptions.contains(option) {
                if value == nil {
                    value = index < words.count ? words[index] : nil
                    index += 1
                }
                if let value {
                    if packageOptions.contains(option) { packages.append(value) } else { extras.append(value) }
                }
                continue
            }
            if word.hasPrefix("-") { continue }
            positional = word
            break
        }
        if style == .deno { return positional.map(isUnpinnedRemoteModule) ?? false }
        let pinned: (String) -> Bool = style == .python ? isPinnedPythonPackage : isPinnedNodePackage
        if !extras.allSatisfy(pinned) { return true }
        if !packages.isEmpty { return !packages.allSatisfy(pinned) }
        return positional.map { !pinned($0) } ?? false
    }

    private static func isLocalPath(_ spec: String) -> Bool {
        spec.hasPrefix(".") || spec.hasPrefix("/") || spec.hasPrefix("~") || spec.hasPrefix("file:")
    }

    /// `name@1.2.3` (a scoped `@scope/name@1.2.3` too) with an exact version,
    /// a git spec pinned to a full commit, or a local path.
    static func isPinnedNodePackage(_ spec: String) -> Bool {
        if isLocalPath(spec) { return true }
        if let hash = spec.range(of: "#", options: .backwards) {
            let commit = spec[hash.upperBound...]
            return commit.count == 40 && commit.allSatisfy(\.isHexDigit) && commit.allSatisfy(\.isASCII)
        }
        let body = spec.hasPrefix("@") ? String(spec.dropFirst()) : spec
        guard let at = body.firstIndex(of: "@") else { return false }
        return isExactVersion(String(body[body.index(after: at)...]))
    }

    /// `name==1.2.3` or `name@1.2.3`, or a local path.
    static func isPinnedPythonPackage(_ spec: String) -> Bool {
        if isLocalPath(spec) { return true }
        if let equals = spec.range(of: "==") {
            let version = spec[equals.upperBound...]
            return !version.isEmpty && !version.contains("*") && !version.contains(",")
                && version.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "+") }
        }
        guard let at = spec.firstIndex(of: "@") else { return false }
        return isExactVersion(String(spec[spec.index(after: at)...]))
    }

    private static func isUnpinnedRemoteModule(_ specifier: String) -> Bool {
        if specifier.hasPrefix("npm:") || specifier.hasPrefix("jsr:") {
            return !isPinnedNodePackage(String(specifier.dropFirst(4)))
        }
        guard specifier.hasPrefix("http://") || specifier.hasPrefix("https://") else { return false }
        return !specifier.split(separator: "/").contains { segment in
            segment.firstIndex(of: "@").map { isExactVersion(String(segment[segment.index(after: $0)...])) } ?? false
        }
    }

    /// `go run mod@v1.2.3` (a pseudo-version included) or `@<commit>` pins;
    /// `@latest`, a branch or a query does not.
    static func isPinnedGoVersion(_ version: String) -> Bool {
        if version.hasPrefix("v"), isExactVersion(String(version.dropFirst())) { return true }
        return version.count >= 12 && version.count <= 40 && version.allSatisfy { $0.isASCII && $0.isHexDigit }
    }

    /// `gem exec -v 1.2.3 tool` or `--version=1.2.3`.
    static func hasExactVersionOption(_ words: [String]) -> Bool {
        for (index, word) in words.enumerated() {
            if word == "-v" || word == "--version", index + 1 < words.count, isExactVersion(words[index + 1]) {
                return true
            }
            if word.hasPrefix("--version="), isExactVersion(String(word.dropFirst("--version=".count))) { return true }
        }
        return false
    }

    /// Semantic version `MAJOR.MINOR.PATCH`, with an optional pre-release and
    /// build suffix, and nothing that makes it a range.
    private static func isExactVersion(_ version: String) -> Bool {
        let core = version.split(separator: "+", maxSplits: 1).first.map(String.init) ?? ""
        let release = core.split(separator: "-", maxSplits: 1).first.map(String.init) ?? ""
        let parts = release.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 3 && parts.allSatisfy { !$0.isEmpty && $0.allSatisfy { $0.isASCII && $0.isNumber } }
            && version.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "+") }
    }
}

// MARK: - The live file system

/// The file system as Claude Code reads it: symlinks followed, nothing
/// written. A FIFO or device is never read: it is opened non-blocking and only
/// a regular file's bytes are taken.
public struct LiveClaudeSettingsFileAccess: ClaudeSettingsFileAccess {
    public init() {}

    public func status(of path: String) -> ClaudeSettingsPathStatus {
        var info = stat()
        guard path.withCString({ stat($0, &info) }) == 0 else {
            return Self.isAbsent(errno) ? .missing : .unreadable
        }
        switch info.st_mode & S_IFMT {
        case S_IFREG: return .regularFile(Self.identity(info))
        case S_IFDIR: return .directory(Self.identity(info))
        default: return .other
        }
    }

    public func contents(of path: String, maximumBytes: Int) -> ClaudeSettingsFileContents {
        // Claude Code rewrites some of these files often; a read that saw the
        // file change under it is taken again, and a third change reads as
        // unreadable rather than as a mix of two versions.
        for _ in 0..<3 {
            let descriptor = path.withCString { open($0, O_RDONLY | O_CLOEXEC | O_NONBLOCK) }
            guard descriptor >= 0 else { return Self.isAbsent(errno) ? .missing : .unreadable }
            defer { close(descriptor) }
            var before = stat()
            guard fstat(descriptor, &before) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_size >= 0 else {
                return .unreadable
            }
            guard before.st_size <= Int64(maximumBytes) else { return .oversized }
            var bytes = [UInt8](repeating: 0, count: Int(before.st_size))
            var offset = 0
            var complete = true
            while offset < bytes.count {
                let count = bytes.withUnsafeMutableBytes { raw in
                    Darwin.read(descriptor, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                }
                if count < 0, errno == EINTR { continue }
                guard count > 0 else { complete = false; break }
                offset += count
            }
            var extra: UInt8 = 0
            if complete, Darwin.read(descriptor, &extra, 1) != 0 { complete = false }
            var after = stat()
            guard fstat(descriptor, &after) == 0 else { return .unreadable }
            guard complete, Self.identity(after) == Self.identity(before) else { continue }
            return .contents(Data(bytes), Self.identity(before))
        }
        return .unreadable
    }

    public func entries(of directory: String, maximumCount: Int) -> ClaudeSettingsDirectoryListing {
        guard let stream = directory.withCString({ opendir($0) }) else {
            return Self.isAbsent(errno) ? .missing : .unreadable
        }
        defer { closedir(stream) }
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(stream) else { return errno == 0 ? .entries(names) : .unreadable }
            let length = Int(entry.pointee.d_namlen)
            var rawName = entry.pointee.d_name
            let name: String? = withUnsafeBytes(of: &rawName) { raw in
                let bytes = raw.prefix(length)
                let text = String(decoding: bytes, as: UTF8.self)
                return text.utf8.elementsEqual(bytes) ? text : nil
            }
            // A name that is not UTF-8 cannot be put into a path to read it.
            guard let name else { return .unreadable }
            if name == "." || name == ".." { continue }
            guard names.count < maximumCount else { return .tooMany }
            names.append(name)
        }
    }

    static func identity(_ info: stat) -> ClaudeSettingsFileIdentity {
        ClaudeSettingsFileIdentity(
            device: UInt64(UInt32(bitPattern: info.st_dev)),
            inode: UInt64(info.st_ino),
            size: UInt64(max(info.st_size, 0)),
            modificationSeconds: Int64(info.st_mtimespec.tv_sec),
            modificationNanoseconds: Int64(info.st_mtimespec.tv_nsec),
            statusChangeSeconds: Int64(info.st_ctimespec.tv_sec),
            statusChangeNanoseconds: Int64(info.st_ctimespec.tv_nsec)
        )
    }

    private static func isAbsent(_ code: Int32) -> Bool { code == ENOENT || code == ENOTDIR }
}

// MARK: - The gate over a file system

/// The settings gate, reading through a `ClaudeSettingsFileAccess`. It never
/// reads the environment: every root comes from the scope.
///
/// Every file is cached by path and identity (device, inode, size,
/// modification and status-change time, `ClaudeSettingsFileIdentity`) as the
/// facts the gate needs from it, and re-`stat`ed on every evaluation: an
/// unchanged file costs one `stat`, a changed one is read again. Directory
/// listings are cached the same way. There is no clock. The facts are not
/// the file's bytes, but a hook's handler JSON (its command) and a
/// frontmatter block stay cached as the digest's input.
final class FileSystemClaudeSettingsGate: ClaudeSettingsGate, @unchecked Sendable {
    /// Settings files, plugin manifests and hook files: the bound `csec
    /// setup` holds a settings file to.
    static let maximumSettingsBytes = CodingAgentSetup.maximumConfigurationBytes
    /// Claude Code's global config file keeps per-project history and grows
    /// with use; only its `env` block is read.
    static let maximumGlobalConfigBytes = 16 * 1024 * 1024
    static let maximumMarkdownBytes = CodingAgentSetup.maximumConfigurationBytes
    static let maximumDirectoryEntries = 4_096
    /// Across every skill, agent and command tree one evaluation walks.
    static let maximumScannedEntries = 20_000
    static let maximumScanDepth = 16
    static let componentDirectories = ["skills", "agents", "commands"]

    /// Where a directory's skills, agents and commands load from: skills one
    /// level deep (`<skills>/<name>/SKILL.md`), agents and commands as every
    /// markdown file below.
    static func componentRoots(under directory: String) -> [ComponentRoot] {
        [ComponentRoot(path: path(directory, "skills"), kind: .skills),
         ComponentRoot(path: path(directory, "agents"), kind: .markdownTree),
         ComponentRoot(path: path(directory, "commands"), kind: .markdownTree)]
    }

    private let files: any ClaudeSettingsFileAccess
    private let cache = ClaudeSettingsReadCache()

    init(files: any ClaudeSettingsFileAccess) {
        self.files = files
    }

    // MARK: Evaluation

    func evaluate(_ scope: ClaudeSettingsScope) -> ClaudeSettingsGateEvaluation {
        var run = GateRun(scope: scope, csecHandlers: Self.csecHandlers(for: scope))
        guard scope.isWellFormed else {
            run.addUnreadable(scope.homeDirectory, .unreadable)
            return run.evaluation()
        }
        let configurationHome = scope.claudeConfigurationHome

        // User settings: the one file whose classifyAllShell counts, and the
        // cowork variant Claude Code reads instead in cowork mode, whose other
        // settings can only decline.
        readSettings(scope.userSettingsPath, role: .user, sharedWithDefaultHome: true, &run)
        readSettings(Self.path(configurationHome, "cowork_settings.json"), role: .declinesOnly,
                     sharedWithDefaultHome: true, &run)

        // `--settings` JSON from P's argv: Claude Code merges it over the
        // user, project and local layers with the user layer's reach (hooks,
        // `disableAllHooks`, `env` applied before trust, `defaultMode`,
        // plugins), so it is read as they are, but its `classifyAllShell`
        // is never credited.
        for json in scope.launchSettings {
            readLaunchSettings(json, &run)
        }

        // Policy (managed) settings.
        let managed = scope.managedSettingsDirectory
        readSettings(Self.path(managed, "managed-settings.json"), role: .policy, &run)
        for name in jsonDropIns(in: Self.path(managed, "managed-settings.d"), &run) {
            readSettings(Self.path(managed, "managed-settings.d/" + name), role: .policy, &run)
        }
        // Claude Code reads only the first managed preferences plist that
        // exists, even an empty one (2.1.88 `mdm/rawRead.ts`): a per-user
        // plist shadows the device-level one, which then only declines.
        let preferences = "com.anthropic.claudecode.plist"
        let perUserPreferences = Self.path(scope.managedPreferencesDirectory, scope.userName + "/" + preferences)
        let perUserExists: Bool
        if case .missing = files.status(of: perUserPreferences) { perUserExists = false } else { perUserExists = true }
        readSettings(perUserPreferences, role: .policy, format: .propertyList, &run)
        readSettings(
            Self.path(scope.managedPreferencesDirectory, preferences),
            role: perUserExists ? .shadowedPolicy : .policy, format: .propertyList, &run)
        // Server-managed settings: the file is user-writable and Claude Code
        // applies it only for some accounts, so it never credits
        // classifyAllShell, but while it holds anything it may be the policy
        // that applies, and so withholds the other policy sources' credit.
        readSettings(Self.path(configurationHome, "remote-settings.json"), role: .policyNeverCredits,
                     sharedWithDefaultHome: true, &run)

        // Project and local settings, from each working directory up to its
        // git root or the home directory, and a worktree's main checkout,
        // whose local settings 2.1.280 applies to the worktree.
        let projectDirectories = projectDirectories(scope)
        for directory in projectDirectories.directories + projectDirectories.worktreeMainRoots {
            readSettings(Self.path(directory, ".claude/settings.json"), role: .project, &run)
            readSettings(Self.path(directory, ".claude/settings.local.json"), role: .project, &run)
        }

        // G5 on the global config file, whichever one applies.
        for path in [scope.legacyGlobalConfigPath] + scope.globalConfigPaths {
            readGlobalConfiguration(path, &run)
        }

        // `--add-dir` directories enable plugins and declare marketplaces
        // through their settings files (2.1.88 `addDirPluginSettings.ts`);
        // nothing else is read from them. `permissions.additionalDirectories`
        // is treated the same way, which can only find more plugins.
        let additionalDirectories = scope.additionalDirectories + run.additionalDirectories
        for directory in additionalDirectories {
            readSettings(Self.path(directory, ".claude/settings.json"), role: .pluginEnablement, &run)
            readSettings(Self.path(directory, ".claude/settings.local.json"), role: .pluginEnablement, &run)
        }
        // A project's own files are never acknowledged as `~/.claude`'s, even
        // inside a configuration home.
        run.projectTrees = (projectDirectories.directories + projectDirectories.worktreeMainRoots
            + additionalDirectories).map { Self.path($0, ".claude") + "/" }

        // Plugins' hooks, and the directories their skills, agents and
        // commands load from.
        var claudeDirectories = [configurationHome, Self.path(managed, ".claude")]
        claudeDirectories += projectDirectories.directories.map { Self.path($0, ".claude") }
        claudeDirectories += projectDirectories.worktreeMainRoots.map { Self.path($0, ".claude") }
        claudeDirectories += additionalDirectories.map { Self.path($0, ".claude") }
        var componentRoots: [ComponentRoot] = []
        let skillsDirectories = [Self.path(configurationHome, "skills")]
            + claudeDirectories.dropFirst().map { Self.path($0, "skills") }
        var relativeBases: [String] = []
        for directory in scope.workingDirectories.map(ClaudeSettingsScope.normalizedPath)
            + projectDirectories.directories + projectDirectories.worktreeMainRoots + additionalDirectories
        where !relativeBases.contains(directory) {
            relativeBases.append(directory)
        }
        readPlugins(scope, skillsDirectories: skillsDirectories, relativeBases: relativeBases,
                    into: &componentRoots, &run)

        // Skill, agent and command frontmatter.
        var seenRoots = Set<ComponentRoot>()
        for root in claudeDirectories.flatMap(Self.componentRoots(under:)) + componentRoots
        where seenRoots.insert(root).inserted {
            scanComponents(root, &run)
        }
        // Disk-backed synced skills retain frontmatter hooks (2.1.282
        // P$o -> FP -> b$o -> Oe); they are not the memory/remote factories
        // that erase executable capabilities. Inspect every account bucket
        // without reading login state or guessing which account is active.
        scanSyncedSkills(Self.path(configurationHome, "skills/synced"), &run)
        return run.evaluation()
    }

    /// `relative` under `directory`, normalized (the root directory included).
    static func path(_ directory: String, _ relative: String) -> String {
        ClaudeSettingsScope.normalizedPath(directory + "/" + relative)
    }

    private enum SettingsFormat { case json, propertyList }

    /// `sharedWithDefaultHome` marks a file of the configuration home, which
    /// is acknowledged as `~/.claude`'s same file when it is that file
    /// (`sharedSourcePath`).
    private func readSettings(
        _ path: String,
        role: GateRun.SettingsRole,
        format: SettingsFormat = .json,
        sharedWithDefaultHome: Bool = false,
        _ run: inout GateRun
    ) {
        guard run.readPaths.insert(path).inserted else { return }
        let kind: ClaudeSettingsReadCache.Kind = format == .json ? .settings : .propertyList
        var identity: ClaudeSettingsFileIdentity?
        let result = read(path, kind: kind, maximumBytes: Self.maximumSettingsBytes, identity: &identity) { data in
            let object: Any?
            switch format {
            case .json:
                object = strictJSONValue(data)
            case .propertyList:
                object = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
            }
            return object.flatMap(ClaudeSettingsFacts.init).map(CachedFacts.settings)
        }
        switch result {
        case .missing:
            return
        case let .unreadable(reason):
            run.addUnreadable(path, reason)
        case let .facts(.settings(facts)):
            let sourcePath = sharedWithDefaultHome
                ? sharedSourcePath(path, readAs: identity, sameTree: false, run) : path
            // Read as `~/.claude`'s file, it is read at that path too: a
            // working directory with no git root walks up to the home, whose
            // `.claude/settings.json` this is, and a default session reads it
            // only once there.
            if sourcePath != path { run.readPaths.insert(sourcePath) }
            run.apply(facts, path: path, sourcePath: sourcePath, role: role)
        case .facts:
            run.addUnreadable(path, .unparseable)
        }
    }

    // MARK: Files shared with the default configuration home

    /// The path a source read at `path` is acknowledged under: with a
    /// `CLAUDE_CONFIG_DIR` that is not `~/.claude`, a file `<configHome>/<rel>`
    /// that is the same file as `~/.claude/<rel>` (an extra Claude account's
    /// config directory links its settings, skills and plugins to the default
    /// ones) is that file, so one acknowledgement covers every account and a
    /// default session's digests are unchanged. Anything else keeps its own
    /// path, and so needs its own acknowledgement.
    ///
    /// Same file means the device and inode `identity` was read from equal
    /// the counterpart's, stat'ed now, on every evaluation: nothing about it
    /// is cached, so a link retargeted elsewhere is its own source again on
    /// the next request. The digest is still over the bytes read at `path`.
    /// Only the relative path within the home is kept, so a file keeps its
    /// role, and a project's `.claude` is never shared even inside a
    /// configuration home.
    ///
    /// `sameTree` is for a file whose hooks can name where it sits: a skill's
    /// folder (`${CLAUDE_SKILL_DIR}`, and paths above it) or a plugin's root
    /// (`${CLAUDE_PLUGIN_ROOT}`). It also requires the home's top-level entry
    /// holding the file (`skills`, `plugins`, `agents`, …) to be the same
    /// directory as the counterpart's, so that everything around the file is
    /// the same too. A settings file's hooks run in the project, wherever the
    /// file is.
    private func sharedSourcePath(
        _ path: String, readAs identity: ClaudeSettingsFileIdentity?, sameTree: Bool, _ run: GateRun
    ) -> String {
        guard let identity, let counterpart = sharedCounterpart(of: path, run),
              case let .regularFile(shared) = files.status(of: counterpart),
              shared.location == identity.location,
              !sameTree || isSameTree(path, run) else { return path }
        return counterpart
    }

    /// `sharedSourcePath` for a skills-directory plugin's root, a directory
    /// whose hooks name it (`${CLAUDE_PLUGIN_ROOT}`).
    private func sharedDirectoryPath(_ path: String, _ run: GateRun) -> String {
        guard let counterpart = sharedCounterpart(of: path, run), isSameTree(path, run),
              case let .directory(identity) = files.status(of: path),
              case let .directory(shared) = files.status(of: counterpart),
              identity.location == shared.location else { return path }
        return counterpart
    }

    private func sharedCounterpart(of path: String, _ run: GateRun) -> String? {
        guard !run.projectTrees.contains(where: { path.hasPrefix($0) }) else { return nil }
        return run.scope.defaultHomeCounterpart(of: path)
    }

    /// Whether the configuration home's top-level entry holding `path` is the
    /// same directory as `~/.claude`'s entry of that name (the home itself
    /// for a file directly in it).
    private func isSameTree(_ path: String, _ run: GateRun) -> Bool {
        let home = run.scope.claudeConfigurationHome
        guard path.hasPrefix(home + "/") else { return false }
        let components = path.dropFirst(home.count + 1).split(separator: "/", omittingEmptySubsequences: true)
        let top = components.count > 1 ? Self.path(home, String(components[0])) : home
        guard let counterpart = top == home ? run.scope.defaultConfigurationHome
                : run.scope.defaultHomeCounterpart(of: top),
              case let .directory(one) = files.status(of: top),
              case let .directory(other) = files.status(of: counterpart) else { return false }
        return one.location == other.location
    }

    /// One inline `--settings` value, parsed as strictly as a settings file
    /// (duplicate keys decline). Claude Code parses it with `JSON.parse`, so
    /// any text both accept is the same object to both.
    private func readLaunchSettings(_ json: String, _ run: inout GateRun) {
        let path = ClaudeSettingsScope.launchSettingsPath
        let data = Data(json.utf8)
        guard data.count <= Self.maximumSettingsBytes else {
            run.addUnreadable(path, .oversized)
            return
        }
        guard let facts = strictJSONValue(data).flatMap(ClaudeSettingsFacts.init) else {
            run.addUnreadable(path, .unparseable)
            return
        }
        run.apply(facts, path: path, role: .declinesOnly)
    }

    private func readGlobalConfiguration(_ path: String, _ run: inout GateRun) {
        guard run.readPaths.insert(path).inserted else { return }
        let result = read(path, kind: .globalConfiguration, maximumBytes: Self.maximumGlobalConfigBytes) { data in
            guard let object = strictJSONValue(data) as? [String: Any] else { return nil }
            guard let environment = object["env"] else { return .environment([]) }
            guard let names = environment as? [String: Any] else { return nil }
            return .environment(ClaudeSettingsFacts.environmentEntries(names))
        }
        switch result {
        case .missing:
            return
        case let .unreadable(reason):
            run.addUnreadable(path, reason)
        case let .facts(.environment(entries)):
            run.addEnvironment(entries, path: path)
        case .facts:
            run.addUnreadable(path, .unparseable)
        }
    }

    /// `managed-settings.d/*.json` as Claude Code loads them: names ending in
    /// `.json`, not starting with `.`, in sorted order.
    private func jsonDropIns(in directory: String, _ run: inout GateRun) -> [String] {
        switch listing(directory) {
        case .missing:
            return []
        case let .unreadable(reason):
            run.addUnreadable(directory, reason)
            return []
        case let .entries(names):
            return names.filter { $0.hasSuffix(".json") && !$0.hasPrefix(".") }.sorted()
        }
    }

    /// The names of the directories (symlinks followed) directly inside
    /// `directory`, sorted; a listing that fails declines.
    private func subdirectories(of directory: String, _ run: inout GateRun) -> [String] {
        let names: [String]
        switch listing(directory) {
        case .missing:
            return []
        case let .unreadable(reason):
            run.addUnreadable(directory, reason)
            return []
        case let .entries(found):
            names = found.sorted()
        }
        return names.filter { name in
            switch files.status(of: Self.path(directory, name)) {
            case .directory:
                return true
            case .unreadable:
                run.addUnreadable(Self.path(directory, name), .unreadable)
                return false
            case .missing, .regularFile, .other:
                return false
            }
        }
    }

    // MARK: Project directories

    private struct ProjectDirectories {
        var directories: [String] = []
        /// Main checkouts of git worktrees (the `.git` file's `gitdir`, then
        /// its `commondir`): 2.1.280 applies their `.claude/settings.local.json`
        /// to the worktree, and Claude Code loads their skills, agents and
        /// commands when the worktree has none.
        var worktreeMainRoots: [String] = []
    }

    /// Every directory from each working directory up to its git root (the
    /// nearest directory holding `.git`, a directory or a worktree's file),
    /// else up to and including the home directory, else the root.
    /// Over-approximates Claude Code, which reads project settings at its
    /// working directory (and local settings at the canonical git root): an
    /// extra file can only decline.
    ///
    /// A repository nested inside another working directory's repository (a
    /// submodule or vendored clone inside the session's project) walks on to
    /// that outer root, as Claude Code's skill, agent and command walk does
    /// (2.1.88 `markdownConfigLoader.ts` `resolveStopBoundary`).
    private func projectDirectories(_ scope: ClaudeSettingsScope) -> ProjectDirectories {
        var result = ProjectDirectories()
        let home = ClaudeSettingsScope.normalizedPath(scope.homeDirectory)
        var starts: [String] = []
        for start in scope.workingDirectories.map(ClaudeSettingsScope.normalizedPath) where !starts.contains(start) {
            starts.append(start)
        }
        let gitRoots = starts.compactMap { nearestGitRoot(from: $0, home: home) }
        var seen = Set<String>()
        for start in starts {
            var stop = nearestGitRoot(from: start, home: home)
            if let own = stop {
                stop = gitRoots.filter { Self.isAncestor($0, of: own) }.min { $0.utf8.count < $1.utf8.count } ?? own
            }
            var directory = start
            while true {
                if seen.insert(directory).inserted {
                    result.directories.append(directory)
                    if case .regularFile = files.status(of: Self.path(directory, ".git")),
                       let main = worktreeMainRoot(of: directory), main != directory,
                       !result.worktreeMainRoots.contains(main) {
                        result.worktreeMainRoots.append(main)
                    }
                }
                if let stop {
                    if directory == stop { break }
                } else if directory == home {
                    break
                }
                if directory == "/" { break }
                directory = ClaudeSettingsScope.normalizedPath(directory + "/..")
            }
        }
        return result
    }

    /// The nearest directory at or above `start` holding `.git`, stopping at
    /// the home directory and the root; nil when there is none.
    private func nearestGitRoot(from start: String, home: String) -> String? {
        var directory = start
        while true {
            switch files.status(of: Self.path(directory, ".git")) {
            case .directory, .regularFile:
                return directory
            case .missing, .other, .unreadable:
                break
            }
            if directory == home || directory == "/" { return nil }
            directory = ClaudeSettingsScope.normalizedPath(directory + "/..")
        }
    }

    /// Whether `ancestor` is a strict ancestor of `path`.
    static func isAncestor(_ ancestor: String, of path: String) -> Bool {
        ancestor != path && (ancestor == "/" || path.hasPrefix(ancestor + "/"))
    }

    /// The main checkout of the worktree rooted at `directory`, as Claude
    /// Code resolves it (2.1.88 `utils/git.ts` `resolveCanonicalRoot`): the
    /// `.git` file's `gitdir`, then that directory's `commondir`; the main
    /// checkout is the common directory's parent (a bare repository's common
    /// directory itself). Claude Code also checks the back-links; skipping
    /// that can only read more files. Without a `commondir` (a submodule) a
    /// `…/.git/worktrees/<name>` gitdir still names its main checkout.
    private func worktreeMainRoot(of directory: String) -> String? {
        guard case let .facts(.text(target?)) = read(
            Self.path(directory, ".git"), kind: .gitFile, maximumBytes: 4_096, parse: { data in
                let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                guard text.hasPrefix("gitdir:") else { return .text(nil) }
                return .text(String(text.dropFirst("gitdir:".count)).trimmingCharacters(in: .whitespaces))
            }) else { return nil }
        let gitDirectory = target.hasPrefix("/")
            ? ClaudeSettingsScope.normalizedPath(target) : Self.path(directory, target)
        if case let .facts(.text(common?)) = read(
            Self.path(gitDirectory, "commondir"), kind: .gitFile, maximumBytes: 4_096, parse: { data in
                let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
                return .text(text.isEmpty ? nil : text)
            }) {
            let commonDirectory = common.hasPrefix("/")
                ? ClaudeSettingsScope.normalizedPath(common) : Self.path(gitDirectory, common)
            return (commonDirectory as NSString).lastPathComponent == ".git"
                ? (commonDirectory as NSString).deletingLastPathComponent : commonDirectory
        }
        guard let range = gitDirectory.range(of: "/.git/worktrees/") else { return nil }
        let main = String(gitDirectory[..<range.lowerBound])
        return main.isEmpty ? nil : main
    }

    // MARK: Plugins

    /// Every plugin Claude Code can load hooks from, and the directories its
    /// skills, agents and commands load from. Where Claude Code's choice of
    /// root cannot be reproduced exactly, every candidate is read, which can
    /// only find more hooks; a root that exists but is not a directory (a zip
    /// Claude Code would extract) declines.
    ///
    /// - claude.ai-synced plugins (2.1.280): every plugin folder of every
    ///   account under `plugins/synced`, enabled unless turned off there;
    /// - skills-directory plugins (2.1.280): any folder of a `skills`
    ///   directory can be adopted as `<name>@skills-dir`;
    /// - enabled marketplace plugins (any settings layer, `--add-dir`): each
    ///   `installed_plugins.json` `installPath`; for a marketplace entry whose
    ///   source is a relative path, that path under the marketplace directory
    ///   (the cache-only loader reads it there with no install record, 2.1.88
    ///   `pluginLoader.ts`; 2.1.280 for `directory`/`file` marketplaces); and
    ///   every version directory of the plugin in the plugin cache (2.1.280
    ///   loads the versioned cache copy with no install record, and 2.1.88
    ///   recomputes a version-1 record's path there);
    /// - the marketplaces are those `known_marketplaces.json` records and,
    ///   whatever it records, every `directory` or `file` marketplace a
    ///   settings file the gate reads declares under `extraKnownMarketplaces`
    ///   (`declaredMarketplaceLocations`).
    ///
    /// An enabled plugin found nowhere is not loaded: `installed_plugins.json`,
    /// the marketplaces and the cache are re-read by identity on every
    /// evaluation, so the request after it is installed evaluates its hooks.
    private func readPlugins(
        _ scope: ClaudeSettingsScope,
        skillsDirectories: [String],
        relativeBases: [String],
        into componentRoots: inout [ComponentRoot],
        _ run: inout GateRun
    ) {
        let pluginsDirectory = Self.path(scope.claudeConfigurationHome, "plugins")
        var probed = Set<String>()
        func probe(_ root: String, _ source: GateRun.PluginSource, _ run: inout GateRun) {
            guard probed.insert(root + "\u{0}" + source.sourceID).inserted else { return }
            probePluginRoot(root, source: source, into: &componentRoots, &run)
        }

        let synced = Self.path(pluginsDirectory, "synced")
        for bucket in subdirectories(of: synced, &run) where !bucket.hasPrefix(".") {
            let bucketPath = Self.path(synced, bucket)
            for name in subdirectories(of: bucketPath, &run) where !name.hasPrefix(".") {
                probe(Self.path(bucketPath, name),
                      GateRun.PluginSource(sourceID: "synced:" + bucket + "/" + name, display: name + " (claude.ai)"), &run)
            }
        }

        var seenSkills = Set<String>()
        for skills in skillsDirectories where seenSkills.insert(skills).inserted {
            for name in subdirectories(of: skills, &run) where !name.hasPrefix(".") {
                let root = Self.path(skills, name)
                probe(root, GateRun.PluginSource(sourceID: sharedDirectoryPath(root, run), display: name + "@skills-dir"),
                      &run)
            }
        }

        guard !run.enabledPlugins.isEmpty else { return }
        let installedPath = Self.path(pluginsDirectory, "installed_plugins.json")
        var installed: [String: [InstalledPlugin]] = [:]
        switch read(installedPath, kind: .installedPlugins, maximumBytes: Self.maximumSettingsBytes, parse: {
            strictJSONValue($0).flatMap(InstalledPlugin.parse).map(CachedFacts.installedPlugins)
        }) {
        case .missing:
            break
        case let .unreadable(reason):
            run.addUnreadable(installedPath, reason)
            return
        case let .facts(.installedPlugins(plugins)):
            installed = plugins
        case .facts:
            run.addUnreadable(installedPath, .unparseable)
            return
        }
        let knownPath = Self.path(pluginsDirectory, "known_marketplaces.json")
        var known: [String: KnownMarketplace] = [:]
        switch read(knownPath, kind: .knownMarketplaces, maximumBytes: Self.maximumSettingsBytes, parse: {
            strictJSONValue($0).flatMap(KnownMarketplace.parse).map(CachedFacts.knownMarketplaces)
        }) {
        case .missing:
            break
        case let .unreadable(reason):
            run.addUnreadable(knownPath, reason)
            return
        case let .facts(.knownMarketplaces(found)):
            known = found
        case .facts:
            run.addUnreadable(knownPath, .unparseable)
            return
        }
        var declared: [String: [KnownMarketplace]] = [:]
        for marketplace in run.declaredMarketplaces {
            declared[marketplace.name, default: []] += declaredMarketplaceLocations(
                marketplace, homeDirectory: scope.homeDirectory, relativeBases: relativeBases)
        }

        for id in run.enabledPlugins {
            guard let at = id.lastIndex(of: "@"), at != id.startIndex else { continue }
            let name = String(id[..<at])
            let marketplaceName = String(id[id.index(after: at)...])
            var roots: [(root: String, version: String)] = []
            var entries: [MarketplaceEntry] = []
            for marketplace in (known[marketplaceName].map { [$0] } ?? []) + (declared[marketplaceName] ?? []) {
                guard let entry = marketplaceEntry(named: name, in: marketplace, &run) else { continue }
                if !entries.contains(where: { $0.catalogPath == entry.catalogPath }) { entries.append(entry) }
                if let source = entry.stringSource {
                    roots += marketplaceDirectories(marketplace).map { (Self.path($0, source), entry.version ?? "marketplace") }
                }
            }
            // Marketplace renames resolve the enabled name before Claude
            // chooses a recorded installation or versioned cache directory.
            // Also inspect the old name conservatively across snapshots.
            let names = Set([name] + entries.map(\.name))
            for candidate in names.sorted() {
                for plugin in installed[candidate + "@" + marketplaceName] ?? [] {
                    guard WireField.isAbsolutePath(plugin.installPath) else {
                        run.addUnreadable(installedPath, .unparseable)
                        continue
                    }
                    roots.append((ClaudeSettingsScope.normalizedPath(plugin.installPath), plugin.version ?? "unknown"))
                }
            }
            let cache = Self.path(pluginsDirectory, "cache/" + PluginCacheNames.sanitized(marketplaceName))
            let pluginNames = names.reduce(into: Set<String>()) {
                $0.formUnion(PluginCacheNames.candidates(forPlugin: $1))
            }
            for folder in subdirectories(of: cache, &run) where pluginNames.contains(folder.lowercased()) {
                let versions = Self.path(cache, folder)
                for version in subdirectories(of: versions, &run) where !version.hasPrefix(".") {
                    roots.append((Self.path(versions, version), version))
                }
            }
            let entrySource = GateRun.PluginSource(sourceID: id, display: id)
            for entry in entries {
                if let manifest = entry.manifest {
                    run.addHooks(manifest.hooks.inline, source: entrySource, path: entry.catalogPath)
                    for block in manifest.inlineCommandFrontmatter {
                        run.addFrontmatterHooks(block, path: entry.catalogPath, sourcePath: entry.catalogSourcePath)
                    }
                } else {
                    run.addUnreadable(entry.catalogPath, .unparseable)
                }
            }
            var seenRoots = Set<String>()
            for (root, version) in roots where seenRoots.insert(root + "\u{0}" + version).inserted {
                let source = GateRun.PluginSource(sourceID: id + "@" + version, display: id)
                probe(root, source, &run)
                // Whichever catalog Claude Code reads the entry from, its
                // hooks files and component paths apply to the root it loads.
                for manifest in entries.compactMap(\.manifest) {
                    for file in manifest.hooks.files {
                        readPluginHooks(Self.path(root, file), source: source, &run)
                    }
                    componentRoots += manifest.componentPaths.map {
                        ComponentRoot(path: Self.path(root, $0.path), kind: $0.kind)
                    }
                }
            }
        }
    }

    /// Where a marketplace declared under `extraKnownMarketplaces` may load
    /// plugins from, before `known_marketplaces.json` records it. 2.1.280
    /// adds a declared `directory` or `file` marketplace for the load when the
    /// registry lacks it ("its plugins load in place from the declared path,
    /// and the background reconcile records it", `Gjt`), from user, policy and
    /// `--settings` declarations and, in a trusted workspace, project, local
    /// and `--add-dir` ones (`yO`); 2.1.88 records the declaration first
    /// (`reconciler.ts`). The gate reads every declaration in a file it reads,
    /// whatever the registry holds, trust or admission rules:
    /// - the path as declared when absolute, and `~`/`~/…` under the home
    ///   directory (2.1.280 `Ujt`); a relative path, which the reconcile
    ///   anchors at the project's canonical root or the working directory
    ///   (2.1.88 `normalizeSource`), under every project and working
    ///   directory;
    /// - a `file` marketplace is that file, and when it sits in a
    ///   `.claude-plugin` folder, also the folder's parent (2.1.280 `tpe`),
    ///   whose standard catalog Claude Code reads.
    private func declaredMarketplaceLocations(
        _ declared: DeclaredMarketplace, homeDirectory: String, relativeBases: [String]
    ) -> [KnownMarketplace] {
        var paths: [String] = []
        if declared.path.hasPrefix("/") {
            paths.append(ClaudeSettingsScope.normalizedPath(declared.path))
        } else {
            if declared.path == "~" {
                paths.append(ClaudeSettingsScope.normalizedPath(homeDirectory))
            } else if declared.path.hasPrefix("~/") {
                paths.append(Self.path(homeDirectory, String(declared.path.dropFirst(2))))
            }
            paths += relativeBases.map { Self.path($0, declared.path) }
        }
        var locations: [KnownMarketplace] = []
        for path in paths {
            locations.append(KnownMarketplace(installLocation: path, sourceType: declared.sourceType, sourcePath: path))
            let parent = (path as NSString).deletingLastPathComponent
            if declared.sourceType == "file", (parent as NSString).lastPathComponent.lowercased() == ".claude-plugin" {
                locations.append(KnownMarketplace(
                    installLocation: (parent as NSString).deletingLastPathComponent,
                    sourceType: declared.sourceType, sourcePath: path))
            }
        }
        return locations
    }

    /// Read one plugin root: `hooks/hooks.json`, `.claude-plugin/plugin.json`
    /// (its hooks, component paths and inline commands), and its standard
    /// component directories. A root that is missing has nothing to load; one
    /// that is not a directory cannot be read the way Claude Code would.
    private func probePluginRoot(
        _ root: String,
        source: GateRun.PluginSource,
        into componentRoots: inout [ComponentRoot],
        _ run: inout GateRun
    ) {
        switch files.status(of: root) {
        case .missing:
            return
        case .directory:
            break
        case .regularFile, .other, .unreadable:
            run.addUnreadable(root, .unreadable)
            return
        }
        readPluginHooks(Self.path(root, "hooks/hooks.json"), source: source, &run)
        // With no skills/ directory or manifest skills path, Claude Code
        // also adopts a plugin's root SKILL.md (2.1.267 `_Te`). As with
        // shadowed standard directories, inspecting it always is conservative.
        readSkillFile(Self.path(root, "SKILL.md"), &run)
        componentRoots += Self.componentRoots(under: root)
        let manifestPath = Self.path(root, ".claude-plugin/plugin.json")
        var identity: ClaudeSettingsFileIdentity?
        switch read(manifestPath, kind: .pluginManifest, maximumBytes: Self.maximumSettingsBytes, identity: &identity,
                    parse: { strictJSONValue($0).flatMap(PluginManifest.parse).map(CachedFacts.pluginManifest) }) {
        case .missing:
            break
        case let .unreadable(reason):
            run.addUnreadable(manifestPath, reason)
        case let .facts(.pluginManifest(manifest)):
            run.addHooks(manifest.hooks.inline, source: source, path: manifestPath)
            for file in manifest.hooks.files {
                readPluginHooks(Self.path(root, file), source: source, &run)
            }
            let sourcePath = sharedSourcePath(manifestPath, readAs: identity, sameTree: true, run)
            for block in manifest.inlineCommandFrontmatter {
                run.addFrontmatterHooks(block, path: manifestPath, sourcePath: sourcePath)
            }
            componentRoots += manifest.componentPaths.map { ComponentRoot(path: Self.path(root, $0.path), kind: $0.kind) }
        case .facts:
            run.addUnreadable(manifestPath, .unparseable)
        }
    }

    /// A plugin hooks file: `{description?, hooks?, modules?}` (2.1.280; 2.1.88
    /// requires `hooks`). Its hook groups count like settings hooks. A hooks
    /// module (`modules`, a script exporting `register(on)` whose handlers can
    /// allow a tool call) and any key Claude Code does not document count as
    /// one source to acknowledge, digested with the module file's bytes.
    private func readPluginHooks(_ path: String, source: GateRun.PluginSource, _ run: inout GateRun) {
        switch read(path, kind: .pluginHooks, maximumBytes: Self.maximumSettingsBytes, parse: {
            strictJSONValue($0).flatMap(PluginHooksFile.parse).map(CachedFacts.pluginHooks)
        }) {
        case .missing:
            return
        case let .unreadable(reason):
            run.addUnreadable(path, reason)
        case let .facts(.pluginHooks(file)):
            run.addHooks(file.groups, source: source, path: path)
            guard !file.modules.isEmpty || file.otherKeys != nil else { return }
            let directory = (path as NSString).deletingLastPathComponent
            var modules: [String] = []
            for module in file.modules {
                let modulePath = Self.path(directory, module)
                switch read(modulePath, kind: .moduleSource, maximumBytes: Self.maximumSettingsBytes, parse: { data in
                    .text(SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
                }) {
                case .missing:
                    modules.append(module + " (missing)")
                case let .unreadable(reason):
                    run.addUnreadable(modulePath, reason)
                    modules.append(module + " (unreadable)")
                case let .facts(.text(digest?)):
                    modules.append(module + " sha256:" + digest)
                case .facts:
                    modules.append(module)
                }
            }
            run.addHooksModule(modules: modules, otherKeys: file.otherKeys, source: source, path: path)
        case .facts:
            run.addUnreadable(path, .unparseable)
        }
    }

    /// Where a marketplace's plugins with a relative `source` load from:
    /// its install location when that is a directory, else the directory
    /// holding it (2.1.88 cache-only loader), and for a `directory` or `file`
    /// marketplace also the directory it was added from.
    private func marketplaceDirectories(_ marketplace: KnownMarketplace) -> [String] {
        var directories: [String] = []
        if let location = marketplace.installLocation {
            switch files.status(of: location) {
            case .directory: directories.append(location)
            case .regularFile: directories.append((location as NSString).deletingLastPathComponent)
            case .missing, .other, .unreadable: break
            }
        }
        if let path = marketplace.sourcePath {
            switch marketplace.sourceType {
            case "directory"?:
                directories.append(path)
            case "file"?:
                let parent = (path as NSString).deletingLastPathComponent
                directories += [parent, (parent as NSString).deletingLastPathComponent]
            default:
                break
            }
        }
        var unique: [String] = []
        for directory in directories where !unique.contains(directory) { unique.append(directory) }
        return unique
    }

    /// The marketplace catalog's entry for `name`: the catalog is
    /// `<install location>/.claude-plugin/marketplace.json`, else the install
    /// location itself when it is a file (2.1.88 `readCachedMarketplace`).
    private func marketplaceEntry(
        named name: String, in marketplace: KnownMarketplace, _ run: inout GateRun
    ) -> MarketplaceEntry? {
        guard let location = marketplace.installLocation else { return nil }
        var catalogPath = Self.path(location, ".claude-plugin/marketplace.json")
        if case .missing = files.status(of: catalogPath), case .regularFile = files.status(of: location) {
            catalogPath = location
        }
        var identity: ClaudeSettingsFileIdentity?
        switch read(catalogPath, kind: .marketplace, maximumBytes: Self.maximumGlobalConfigBytes, identity: &identity,
                    parse: { strictJSONValue($0).flatMap(MarketplaceEntry.parseCatalog).map(CachedFacts.marketplace) }) {
        case .missing:
            return nil
        case let .unreadable(reason):
            run.addUnreadable(catalogPath, reason)
            return nil
        case let .facts(.marketplace(entries)):
            guard var entry = entries[name] else { return nil }
            entry.catalogPath = catalogPath
            entry.catalogSourcePath = sharedSourcePath(catalogPath, readAs: identity, sameTree: true, run)
            return entry
        case .facts:
            run.addUnreadable(catalogPath, .unparseable)
            return nil
        }
    }

    // MARK: Skill, agent and command frontmatter

    /// The skill, agent and command files below `root` whose frontmatter may
    /// register hooks. A skills directory is read as Claude Code reads it
    /// (2.1.88 `loadSkillsFromSkillsDir`, `loadPluginCommands.ts`; 2.1.280
    /// the same): `<root>/SKILL.md` (a plugin's skill path may be the skill
    /// itself) and `<root>/<entry>/SKILL.md` for every entry that is a
    /// directory, opened by that exact name so the volume folds case as it
    /// does for Claude Code. An agents or commands directory is every
    /// markdown file below it (hidden entries included, symlinks followed, as
    /// ripgrep `--hidden --follow --no-ignore` finds them), and `root` itself
    /// when a plugin names a single file.
    private func scanComponents(_ root: ComponentRoot, _ run: inout GateRun) {
        guard !run.scanBudgetSpent else { return }
        switch files.status(of: root.path) {
        case let .directory(identity):
            switch root.kind {
            case .skills:
                scanSkills(root.path, &run)
            case .markdownTree:
                var visited = Set<ClaudeSettingsFileIdentity.Location>()
                scanDirectory(root.path, identity: identity, depth: 0, root: root.path, visited: &visited, &run)
            }
        case .regularFile where root.kind == .markdownTree && Self.isMarkdownName((root.path as NSString).lastPathComponent):
            readFrontmatter(root.path, &run)
        case .unreadable:
            run.addUnreadable(root.path, .unreadable)
        case .missing, .other, .regularFile:
            return
        }
    }

    private func scanSyncedSkills(_ directory: String, _ run: inout GateRun) {
        guard !run.scanBudgetSpent else { return }
        for account in subdirectories(of: directory, &run) {
            run.scannedEntries += 1
            guard run.scannedEntries <= Self.maximumScannedEntries else {
                run.scanBudgetSpent = true
                run.addUnreadable(directory, .tooMany)
                return
            }
            scanSkills(Self.path(directory, account), includeRoot: false, &run)
            if run.scanBudgetSpent { return }
        }
    }

    private func scanSkills(_ directory: String, includeRoot: Bool = true, _ run: inout GateRun) {
        if includeRoot { readSkillFile(Self.path(directory, "SKILL.md"), &run) }
        for name in subdirectories(of: directory, &run) {
            run.scannedEntries += 1
            guard run.scannedEntries <= Self.maximumScannedEntries else {
                run.scanBudgetSpent = true
                run.addUnreadable(directory, .tooMany)
                return
            }
            readSkillFile(Self.path(directory, name + "/SKILL.md"), &run)
        }
    }

    private func readSkillFile(_ path: String, _ run: inout GateRun) {
        switch files.status(of: path) {
        case .regularFile:
            readFrontmatter(path, &run)
        case .unreadable, .other:
            run.addUnreadable(path, .unreadable)
        case .missing, .directory:
            return
        }
    }

    /// A markdown file name, in any case: a skill's `SKILL.md` is opened by
    /// that name, which the default case-insensitive volume also resolves
    /// to `SKILL.MD` or `skill.md`.
    static func isMarkdownName(_ name: String) -> Bool {
        name.lowercased().hasSuffix(".md")
    }

    private func scanDirectory(
        _ path: String,
        identity: ClaudeSettingsFileIdentity,
        depth: Int,
        root: String,
        visited: inout Set<ClaudeSettingsFileIdentity.Location>,
        _ run: inout GateRun
    ) {
        guard visited.insert(identity.location).inserted else { return }
        guard depth <= Self.maximumScanDepth else {
            run.addUnreadable(path, .tooMany)
            return
        }
        let names: [String]
        switch listing(path, identity: identity) {
        case .missing:
            return
        case let .unreadable(reason):
            run.addUnreadable(path, reason)
            return
        case let .entries(found):
            names = found.sorted()
        }
        for name in names {
            run.scannedEntries += 1
            guard run.scannedEntries <= Self.maximumScannedEntries else {
                run.scanBudgetSpent = true
                run.addUnreadable(root, .tooMany)
                return
            }
            let child = path + "/" + name
            switch files.status(of: child) {
            case let .directory(childIdentity):
                scanDirectory(child, identity: childIdentity, depth: depth + 1, root: root, visited: &visited, &run)
                if run.scanBudgetSpent { return }
            case .regularFile where Self.isMarkdownName(name):
                readFrontmatter(child, &run)
            case .unreadable:
                run.addUnreadable(child, .unreadable)
            case .regularFile, .missing, .other:
                continue
            }
        }
    }

    private func readFrontmatter(_ path: String, _ run: inout GateRun) {
        var identity: ClaudeSettingsFileIdentity?
        switch read(path, kind: .frontmatter, maximumBytes: Self.maximumMarkdownBytes, identity: &identity, parse: { data in
            .text(ClaudeSettingsFacts.frontmatterHooksBlock(String(decoding: data, as: UTF8.self)))
        }) {
        case .missing:
            return
        case let .unreadable(reason):
            run.addUnreadable(path, reason)
        case let .facts(.text(block?)):
            run.addFrontmatterHooks(
                block, path: path, sourcePath: sharedSourcePath(path, readAs: identity, sameTree: true, run))
        case .facts:
            return
        }
    }

    // MARK: Builds

    func discoverBuilds(_ scope: ClaudeSettingsScope) -> ClaudeBuildDiscovery {
        guard scope.isWellFormed else {
            return ClaudeBuildDiscovery(builds: [], unreadable: [ClaudeUnreadableSetting(path: "/", reason: .unreadable)])
        }
        var builds: [DiscoveredClaudeBuild] = []
        var unreadable: [ClaudeUnreadableSetting] = []
        var seen = Set<ClaudeSettingsFileIdentity>()
        // Version-named directories, then the fixed npm paths, whose label
        // names the route instead of a version. `root` is what a full
        // inventory reports as cut short.
        var candidates: [(path: String, label: String, root: String)] = []
        for (directory, suffix) in [
            (scope.claudeVersionsDirectory, ""), (scope.claudeMiseVersionsDirectory, "/bin/claude"),
            (scope.claudeHomebrewVersionsDirectory, "/claude"),
        ] {
            switch listing(directory) {
            case .missing: continue
            case let .unreadable(reason):
                unreadable.append(ClaudeUnreadableSetting(path: directory, reason: reason))
                continue
            case let .entries(found):
                candidates += found.filter { !$0.hasPrefix(".") }.sorted().map {
                    (directory + "/" + $0 + suffix, $0, directory)
                }
            }
        }
        candidates += scope.claudeNpmExecutables.map { ($0, ClaudeInstallLayout.npmLabel, $0) }
        for (path, name, root) in candidates {
            switch files.status(of: path) {
            case let .regularFile(identity):
                guard seen.insert(identity).inserted else { continue }
                guard builds.count < DelegationStatus.maximumDiscoveredBuilds else {
                    unreadable.append(ClaudeUnreadableSetting(path: root, reason: .tooMany))
                    return ClaudeBuildDiscovery(builds: builds, unreadable: unreadable)
                }
                let code = codeIdentity(path, identity: identity)
                builds.append(DiscoveredClaudeBuild(
                    path: path,
                    versionLabel: ClaudeDelegationDisplay.bounded(
                        ReviewDisplay.sanitized(name), maximumBytes: ClaudeBuildSummary.maximumVersionLabelBytes),
                    cdHash: code.cdHash,
                    signedByAnthropic: code.signedByAnthropic))
            case .unreadable:
                unreadable.append(ClaudeUnreadableSetting(path: path, reason: .unreadable))
            case .missing, .directory, .other:
                continue
            }
        }
        return ClaudeBuildDiscovery(builds: builds, unreadable: unreadable)
    }

    private func codeIdentity(_ path: String, identity: ClaudeSettingsFileIdentity) -> StaticCodeIdentity {
        if case let .code(cached)? = cache.facts(path, identity: identity, kind: .codeIdentity) { return cached }
        let code = StaticCodeIdentity(path: path)
        cache.store(path, identity: identity, kind: .codeIdentity, facts: .code(code))
        return code
    }

    // MARK: Settings edits

    func userSettingsPath(_ scope: ClaudeSettingsScope) -> String {
        scope.sharedUserSettingsPath(files: files)
    }

    func planEnable(_ scope: ClaudeSettingsScope) -> ClaudeSettingsEditPlan {
        CodingAgentSetup.planClaudeDelegationEnable(settingsPath: userSettingsPath(scope))
    }

    func planRevert(
        _ scope: ClaudeSettingsScope,
        recordedSettingsPath: String?,
        csecAddedClassifyAllShell: Bool
    ) -> ClaudeSettingsEditPlan {
        CodingAgentSetup.planClaudeDelegationRevert(
            settingsPath: recordedSettingsPath ?? userSettingsPath(scope),
            csecAddedClassifyAllShell: csecAddedClassifyAllShell)
    }

    // MARK: Reading through the cache

    private enum ReadResult {
        case missing
        case unreadable(ClaudeUnreadableSetting.Reason)
        case facts(CachedFacts)
    }

    private func read(
        _ path: String,
        kind: ClaudeSettingsReadCache.Kind,
        maximumBytes: Int,
        parse: (Data) -> CachedFacts?
    ) -> ReadResult {
        var identity: ClaudeSettingsFileIdentity?
        return read(path, kind: kind, maximumBytes: maximumBytes, identity: &identity, parse: parse)
    }

    /// `read`, also giving the identity the facts came from: the file read
    /// (its descriptor's), or on a cache hit the path's stat that matched.
    private func read(
        _ path: String,
        kind: ClaudeSettingsReadCache.Kind,
        maximumBytes: Int,
        identity factsIdentity: inout ClaudeSettingsFileIdentity?,
        parse: (Data) -> CachedFacts?
    ) -> ReadResult {
        factsIdentity = nil
        switch files.status(of: path) {
        case .missing:
            return .missing
        case .unreadable, .other, .directory:
            return .unreadable(.unreadable)
        case let .regularFile(identity):
            if let cached = cache.facts(path, identity: identity, kind: kind) {
                factsIdentity = identity
                return Self.result(cached)
            }
            guard identity.size <= UInt64(maximumBytes) else { return .unreadable(.oversized) }
            switch files.contents(of: path, maximumBytes: maximumBytes) {
            case .missing:
                return .missing
            case .oversized:
                return .unreadable(.oversized)
            case .unreadable:
                return .unreadable(.unreadable)
            case let .contents(data, readIdentity):
                let facts = parse(data) ?? .unparseable
                cache.store(path, identity: readIdentity, kind: kind, facts: facts)
                factsIdentity = readIdentity
                return Self.result(facts)
            }
        }
    }

    private static func result(_ facts: CachedFacts) -> ReadResult {
        if case .unparseable = facts { return .unreadable(.unparseable) }
        return .facts(facts)
    }

    private enum ListingResult {
        case missing
        case unreadable(ClaudeUnreadableSetting.Reason)
        case entries([String])
    }

    private func listing(_ path: String) -> ListingResult {
        switch files.status(of: path) {
        case .missing:
            return .missing
        case let .directory(identity):
            return listing(path, identity: identity)
        case .unreadable, .other, .regularFile:
            return .unreadable(.unreadable)
        }
    }

    private func listing(_ path: String, identity: ClaudeSettingsFileIdentity) -> ListingResult {
        if let names = cache.names(path, identity: identity) { return .entries(names) }
        switch files.entries(of: path, maximumCount: Self.maximumDirectoryEntries) {
        case .missing:
            return .missing
        case .tooMany:
            return .unreadable(.tooMany)
        case .unreadable:
            return .unreadable(.unreadable)
        case let .entries(names):
            cache.store(path, identity: identity, names: names)
            return .entries(names)
        }
    }

    /// csec's own handler as `csec setup` installs it, in the canonical form
    /// hooks are compared in: excluded from G2 only when a configured handler
    /// is byte-equal to one of these, the comparison `CodingAgentSetup.plan`
    /// makes. One is for the scope's launcher (a development build's own
    /// hook), the other for the installed launcher every generated hook
    /// invokes, whatever process the request named: a surface whose
    /// requesting path was not the installed launcher (csec-0.47's PR lookup,
    /// SSH signings in csec-0.64) otherwise read csec's own hook as another
    /// hook and declined. Both run csec's signed launcher, so neither is
    /// code csec did not write.
    static func csecHandlers(for scope: ClaudeSettingsScope) -> Set<Data> {
        Set([scope.csecExecutablePath, CodingAgentSetup.installedLauncherPath].compactMap { path in
            guard let configuration = try? AICommandHook.hookConfiguration(client: .claude, csecExecutablePath: path),
                  let object = try? JSONSerialization.jsonObject(with: configuration) as? [String: Any],
                  let hooks = object["hooks"] as? [String: Any],
                  let groups = hooks["PreToolUse"] as? [[String: Any]],
                  let handler = (groups.first?["hooks"] as? [[String: Any]])?.first else { return nil }
            return ClaudeSettingsFacts.canonicalJSON(handler)
        })
    }
}

// MARK: - What a file says

enum ComponentKind: Hashable {
    /// A skills directory: `<name>/SKILL.md` one level down.
    case skills
    /// An agents or commands directory: every markdown file below.
    case markdownTree
}

struct ComponentRoot: Hashable {
    let path: String
    let kind: ComponentKind
}

extension ClaudeSettingsFileIdentity {
    /// Which file (device and inode), whatever its size and time: a directory
    /// seen again through a symlink is not walked twice.
    struct Location: Hashable {
        let device: UInt64
        let inode: UInt64
    }

    var location: Location { Location(device: device, inode: inode) }
}

/// The facts the gate keeps about one file: never the file's bytes, and no
/// setting's value except a hook's handler JSON and a frontmatter block, the
/// digest's input (a `NODE_OPTIONS` value is read only for its flags).
private enum CachedFacts {
    case settings(ClaudeSettingsFacts)
    case environment([String])
    case installedPlugins([String: [InstalledPlugin]])
    case pluginManifest(PluginManifest)
    case pluginHooks(PluginHooksFile)
    case knownMarketplaces([String: KnownMarketplace])
    case marketplace([String: MarketplaceEntry])
    case text(String?)
    case code(StaticCodeIdentity)
    case unparseable
}

private final class ClaudeSettingsReadCache: @unchecked Sendable {
    enum Kind: Equatable {
        case settings, propertyList, globalConfiguration, installedPlugins, pluginManifest, pluginHooks
        case knownMarketplaces, marketplace, frontmatter, gitFile, codeIdentity, moduleSource
    }

    /// Bounds memory in a long-lived csecd; past it the cache starts over.
    static let maximumEntries = 16_384

    private let lock = NSLock()
    private var reads: [String: (identity: ClaudeSettingsFileIdentity, kind: Kind, facts: CachedFacts)] = [:]
    private var listings: [String: (identity: ClaudeSettingsFileIdentity, names: [String])] = [:]

    func facts(_ path: String, identity: ClaudeSettingsFileIdentity, kind: Kind) -> CachedFacts? {
        lock.lock()
        defer { lock.unlock() }
        guard let entry = reads[path], entry.identity == identity, entry.kind == kind else { return nil }
        return entry.facts
    }

    func store(_ path: String, identity: ClaudeSettingsFileIdentity, kind: Kind, facts: CachedFacts) {
        lock.lock()
        defer { lock.unlock() }
        if reads.count >= Self.maximumEntries { reads.removeAll(keepingCapacity: true) }
        reads[path] = (identity, kind, facts)
    }

    func names(_ path: String, identity: ClaudeSettingsFileIdentity) -> [String]? {
        lock.lock()
        defer { lock.unlock() }
        guard let entry = listings[path], entry.identity == identity else { return nil }
        return entry.names
    }

    func store(_ path: String, identity: ClaudeSettingsFileIdentity, names: [String]) {
        lock.lock()
        defer { lock.unlock() }
        if listings.count >= Self.maximumEntries { listings.removeAll(keepingCapacity: true) }
        listings[path] = (identity, names)
    }
}

/// One hook group that can select Bash, from an event that can approve, or
/// a `ConfigChange` group.
private struct ClaudeHookGroup {
    let event: String
    let matcher: String?
    let handlers: [ClaudeHookHandler]
}

private struct ClaudeHookHandler {
    /// The handler object as sorted-key JSON: what it is compared and
    /// digested as.
    let canonical: Data
    let fetchesUnpinnedCode: Bool
    /// What it runs, for display (`ClaudeHookSource.handlerSummaries`).
    let summary: String
    /// `summary` is all of it: not cut to its bound, and leaving out nothing
    /// that might change what runs.
    let summaryIsWhole: Bool
}

/// What one settings file (or managed preferences plist) says about the gate.
private struct ClaudeSettingsFacts {
    /// No keys at all: an empty policy source is not the one Claude Code uses.
    var isEmpty = true
    /// `autoMode.classifyAllShell` is exactly `true`.
    var classifyAllShell = false
    /// `autoMode`'s classifier rule lists, as written.
    var classifierRules: [String: [String]] = [:]
    var hookGroups: [ClaudeHookGroup] = []
    var environment: [String] = []
    var sandboxEnabled = false
    var bypassPermissionsDefault = false
    var disableAllHooks = false
    var allowManagedHooksOnly = false
    var enabledPlugins: [String] = []
    var additionalDirectories: [String] = []
    var declaredMarketplaces: [DeclaredMarketplace] = []
    var generatedPolicy = false

    /// Nil when the file is not the shape Claude Code reads: then it declines
    /// as unparseable rather than being read as having nothing in it.
    init?(_ value: Any) {
        guard let settings = value as? [String: Any] else { return nil }
        isEmpty = settings.isEmpty
        if let value = settings["autoMode"] {
            guard let autoMode = value as? [String: Any],
                  let rules = ClaudeClassifierRules.lists(inSettings: settings) else { return nil }
            classifyAllShell = autoMode["classifyAllShell"].flatMap(Self.strictBoolean) == true
            classifierRules = rules
        }
        if let value = settings["hooks"] {
            guard let groups = Self.hookGroups(value) else { return nil }
            hookGroups = groups
        }
        if let value = settings["env"] {
            guard let names = value as? [String: Any] else { return nil }
            environment = Self.environmentEntries(names)
        }
        if let value = settings["sandbox"] {
            guard let sandbox = value as? [String: Any] else { return nil }
            sandboxEnabled = Self.isSet(sandbox["enabled"])
        }
        if let value = settings["permissions"] {
            guard let permissions = value as? [String: Any] else { return nil }
            bypassPermissionsDefault = permissions["defaultMode"] as? String == ClaudeDelegationGateLists.bypassPermissionMode
            additionalDirectories = (permissions["additionalDirectories"] as? [Any])?.compactMap { $0 as? String } ?? []
        }
        disableAllHooks = Self.isSet(settings["disableAllHooks"])
        allowManagedHooksOnly = Self.isSet(settings["allowManagedHooksOnly"])
        generatedPolicy = settings["policyHelper"] != nil || settings["policyHelpers"] != nil
        if let value = settings["enabledPlugins"] {
            guard let plugins = value as? [String: Any] else { return nil }
            // `true`, or a list of version constraints; `false` disables.
            enabledPlugins = plugins.keys.sorted().filter { id in
                Self.strictBoolean(plugins[id] as Any) == true || plugins[id] is [Any]
            }
        }
        // Claude Code normalizes this alias before validating the settings.
        // A non-null canonical value wins, including an empty dictionary.
        let marketplaces = settings["extraKnownMarketplaces"].flatMap { $0 is NSNull ? nil : $0 }
            ?? settings["additionalMarketplaces"]
        if let value = marketplaces {
            guard let declared = value as? [String: Any] else { return nil }
            declaredMarketplaces = DeclaredMarketplace.parse(declared)
        }
    }

    /// Present and not exactly `false`: a value Claude Code would not accept
    /// as a boolean still counts, which can only decline.
    static func isSet(_ value: Any?) -> Bool {
        guard let value else { return false }
        return strictBoolean(value) != false
    }

    static func strictBoolean(_ value: Any) -> Bool? {
        guard let number = value as? NSNumber, CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
        return number.boolValue
    }

    /// The injected-environment entries a settings `env` block matches, in
    /// name order: `ClaudeDelegationGateLists.settingsEnvironmentEntry`, and
    /// `NODE_OPTIONS` when its value loads code (or is not text).
    static func environmentEntries(
        _ names: [String: Any], acceptedShellPrefix: String? = ClaudeCodeShellPrefix.installedPrefixPath
    ) -> [String] {
        var entries: [String] = []
        for name in names.keys.sorted() {
            let entry: String?
            if ClaudeDelegationGateLists.isAcceptedShellPrefix(
                name: name, value: names[name], accepted: acceptedShellPrefix) {
                entry = nil
            } else if let listed = ClaudeDelegationGateLists.settingsEnvironmentEntry(matching: name) {
                entry = listed
            } else if name == ClaudeDelegationGateLists.nodeOptionsName {
                let loadsCode = (names[name] as? String).map {
                    ClaudeDelegationGateLists.nodeOptionsCodeLoadingFlag(in: $0) != nil
                } ?? true
                entry = loadsCode ? name : nil
            } else {
                entry = nil
            }
            if let entry, !entries.contains(entry) { entries.append(entry) }
        }
        return entries
    }

    /// The `PreToolUse` and `PermissionRequest` groups (the events whose
    /// `allow` approves a tool call) that can select Bash or Monitor, and every
    /// `ConfigChange` group: a `ConfigChange` hook that blocks stops Claude
    /// Code from reloading settings, skills and plugins (2.1.88
    /// `changeDetector.ts`, `skillChangeDetector.ts`; 2.1.280 also plugin
    /// reloads), so an approving hook since deleted from disk, where the gate
    /// looks, stays live in the session. Every group of those events must be
    /// well formed, shell tool or not.
    static let hookEvents = ["PreToolUse", "PermissionRequest", "ConfigChange"]

    static func hookGroups(_ value: Any) -> [ClaudeHookGroup]? {
        guard let events = value as? [String: Any] else { return nil }
        var groups: [ClaudeHookGroup] = []
        for event in hookEvents {
            guard let listed = events[event] else { continue }
            guard let list = listed as? [Any] else { return nil }
            for item in list {
                guard let group = item as? [String: Any], let handlerList = group["hooks"] as? [Any] else { return nil }
                var matcher: String?
                if let raw = group["matcher"] {
                    guard let text = raw as? String else { return nil }
                    matcher = text
                }
                var handlers: [ClaudeHookHandler] = []
                for entry in handlerList {
                    guard let handler = entry as? [String: Any], let canonical = canonicalJSON(handler) else { return nil }
                    let runs = summary(of: handler, canonical: canonical)
                    handlers.append(ClaudeHookHandler(
                        canonical: canonical, fetchesUnpinnedCode: fetchesUnpinnedCode(handler),
                        summary: ClaudeDelegationDisplay.bounded(
                            runs.text, maximumBytes: ClaudeHookSource.maximumHandlerSummaryBytes),
                        summaryIsWhole: runs.complete
                            && runs.text.utf8.count <= ClaudeHookSource.maximumHandlerSummaryBytes))
                }
                if event == "ConfigChange" || ClaudeHookSource.matcherCanMatchShellTool(matcher) {
                    groups.append(ClaudeHookGroup(event: event, matcher: matcher, handlers: handlers))
                }
            }
        }
        return groups
    }

    /// A command handler's keys that its summary may leave out: none of them
    /// changes what it runs.
    private static let commandHandlerUnshownKeys: Set<String> = ["type", "command", "args", "timeout", "statusMessage"]

    /// A command handler's command and arguments, as Claude Code runs them;
    /// any other handler as written. Whole: the caller bounds it, and the
    /// panel sanitizes it. Not `complete` when a command handler has a key it
    /// leaves out that might change what runs, or an argument it cannot show.
    private static func summary(of handler: [String: Any], canonical: Data) -> (text: String, complete: Bool) {
        if handler["type"] as? String == "command", let command = handler["command"] as? String {
            let listed = handler["args"] == nil ? [] : handler["args"] as? [Any]
            let arguments = (listed ?? []).compactMap { $0 as? String }
            let complete = Set(handler.keys).isSubset(of: commandHandlerUnshownKeys) && listed?.count == arguments.count
            return (([command] + arguments).joined(separator: " "), complete)
        }
        return (String(decoding: canonical, as: UTF8.self), true)
    }

    private static func fetchesUnpinnedCode(_ handler: [String: Any]) -> Bool {
        guard handler["type"] as? String == "command" else { return false }
        var words = (handler["command"] as? String).map(ClaudeHookFetchCheck.words(in:)) ?? []
        for argument in handler["args"] as? [Any] ?? [] {
            if let text = argument as? String { words += ClaudeHookFetchCheck.words(in: text) }
        }
        return ClaudeHookFetchCheck.fetchesUnpinnedCode(words: words)
    }

    static func canonicalJSON(_ object: Any) -> Data? {
        guard JSONSerialization.isValidJSONObject(object) else { return nil }
        return try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
    }

    /// The frontmatter of a skill, agent or command file when it may register
    /// hooks, else nil. Frontmatter is the text after an opening `---` line up
    /// to the next `---` anywhere (2.1.88 `FRONTMATTER_REGEX`; 2.1.280 strips
    /// a leading BOM). Claude Code parses it with Bun's YAML parser, which
    /// decodes escapes and resolves aliases, tags and merge keys; the gate
    /// does not parse YAML, so every block it cannot read with certainty
    /// counts, digested whole (`frontmatterMayRegisterHooks`).
    static func frontmatterHooksBlock(_ text: String) -> String? {
        var body = Substring(text)
        if body.hasPrefix("\u{FEFF}") { body = body.dropFirst() }
        // `\r\n` is one Character, so a line ends at any newline Character.
        guard body.hasPrefix("---"), let firstLineEnd = body.firstIndex(where: \.isNewline) else { return nil }
        let rest = body[body.index(after: firstLineEnd)...]
        guard let close = rest.range(of: "---") else { return nil }
        let block = rest[..<close.lowerBound]
        return frontmatterMayRegisterHooks(block) ? String(block) : nil
    }

    /// Whether a frontmatter block may yield a `hooks` key:
    /// - a line names `hooks` where YAML can make it a key: at any
    ///   indentation, after `- ` or `? ` indicators, inside flow-sequence
    ///   brackets (`[hooks]:`), quoted or not, followed by `:`, a comment or
    ///   the end of the line (an explicit key, or a block scalar's content),
    ///   in any case (`lineNamesHooksKey`);
    /// - a line has a backslash anywhere but inside a double-quoted value
    ///   that YAML decodes as the value's text (an escape such as
    ///   `"\x68ooks"` can spell the key; `quotedValueHoldsEveryBackslash`),
    ///   or the block has an invisible format character (a byte-order mark
    ///   inside a key);
    /// - it uses YAML that makes a key depend on more than its own line: an
    ///   anchor (`&`), alias (`*`) or tag (`!`) at the start of a token, a
    ///   flow mapping (`{`), a merge key (`<<`), a directive (`%`) or a
    ///   document marker (`...`).
    /// With those forms counted, every other way YAML can spell the key puts
    /// its letters at such a place, so `hooks` elsewhere in a line (a
    /// description mentioning webhooks) does not count.
    static func frontmatterMayRegisterHooks<Block: StringProtocol>(_ block: Block) -> Bool {
        if block.unicodeScalars.contains(where: { $0.properties.generalCategory == .format }) {
            return true
        }
        let lines = block.split(whereSeparator: \.isNewline)
        // A backslash is exempt only where every quoted scalar opens and
        // closes on its own line, so that no line is the rest of a scalar the
        // line before it opened.
        let quotesCloseOnTheirLines = !lines.contains { lineMayLeaveQuoteOpen(Array($0)) }
        return lines.contains { line in
            (line.contains("\\") && !(quotesCloseOnTheirLines && quotedValueHoldsEveryBackslash(line)))
                || lineNamesHooksKey(line) || lineHasUncertainYAML(Array(line))
        }
    }

    /// Whether `line`, read from outside any scalar, may leave a quoted scalar
    /// open for the next line: a quote that opens where YAML starts a token
    /// and does not close on the line, or a quote after a closed quoted
    /// scalar on the same line (which YAML rejects, and a lenient parser might
    /// open). Double-quoted backslash escapes and single-quoted `''` are
    /// honoured, and a quote inside a plain scalar or a comment is text.
    private static func lineMayLeaveQuoteOpen(_ line: [Character]) -> Bool {
        var atTokenStart = true
        var quote: Character?
        var afterQuoted = false
        var previous: Character = " "
        var index = line.startIndex
        while index < line.endIndex {
            let character = line[index]
            let next: Character? = index + 1 < line.endIndex ? line[index + 1] : nil
            defer {
                previous = character
                index += 1
            }
            if let open = quote {
                if open == "\"", character == "\\" {
                    index += 1
                } else if character == open {
                    if open == "'", next == "'" {
                        index += 1
                    } else {
                        quote = nil
                        afterQuoted = true
                    }
                }
                continue
            }
            if character == " " || character == "\t" { continue }
            if character == "#", previous == " " || previous == "\t" || index == line.startIndex { return false }
            if character == "\"" || character == "'" {
                if afterQuoted { return true }
                if atTokenStart {
                    quote = character
                    atTokenStart = false
                }
                continue
            }
            if atTokenStart {
                if character == "-" || character == "?", next == nil || next == " " || next == "\t" { continue }
                atTokenStart = false
            }
            if character == ":", next == nil || next == " " || next == "\t" {
                atTokenStart = true
                afterQuoted = false
            } else if character == "," || character == "[" || character == "{" {
                atTokenStart = true
            }
        }
        return quote != nil
    }

    /// Whether every backslash in `line` is an escape inside one double-quoted
    /// scalar that is the whole value of a plain key other than `hooks`
    /// (`description: "Set up a plugin.\n"`, also after `- `) or of a
    /// sequence entry (`- "a\tb"`), closed on the line and followed only by
    /// blanks or a comment. Only asked when no line of the block leaves a
    /// quoted scalar open (`lineMayLeaveQuoteOpen`). Either form is a value
    /// unless an explicit key (`? `) holds it, and an explicit key counts on
    /// its own (`lineHasUncertainYAML`). YAML decodes those
    /// escapes into the value's text, where they cannot spell a key. A quoted
    /// scalar followed by `:` is a key, one ending in an escaped line break
    /// continues on the next line, and a backslash anywhere else may be part
    /// of a key, so each of those still counts.
    private static func quotedValueHoldsEveryBackslash<Line: StringProtocol>(_ line: Line) -> Bool {
        let blank: (Character) -> Bool = { $0 == " " || $0 == "\t" }
        var rest = Substring(line).drop(while: blank)
        var entry = false
        while rest.first == "-", rest.dropFirst().first.map(blank) ?? false {
            rest = rest.dropFirst().drop(while: blank)
            entry = true
        }
        // A quoted scalar alone on a line is a value only as a sequence entry;
        // anywhere else it needs its plain key in front of it.
        if !(entry && rest.first == "\"") {
            let key = rest.prefix { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == ".") }
            guard let initial = key.first, initial != "-", key.lowercased() != "hooks" else { return false }
            rest = rest.dropFirst(key.count)
            guard rest.first == ":", rest.dropFirst().first.map(blank) ?? false else { return false }
            rest = rest.dropFirst().drop(while: blank)
            guard rest.first == "\"" else { return false }
        }
        rest = rest.dropFirst()
        var closed = false
        while let character = rest.popFirst() {
            if character == "\\" {
                // An escaped line break continues the scalar on the next line.
                guard rest.popFirst() != nil else { return false }
            } else if character == "\"" {
                closed = true
                break
            }
        }
        guard closed else { return false }
        let after = rest.drop(while: blank)
        return after.isEmpty || (after.first == "#" && after.count < rest.count)
    }

    /// A line whose first token can spell the key `hooks`: past indentation,
    /// `- `/`? ` indicators and flow-sequence brackets (Bun makes a sequence
    /// key the text of its entries joined by commas, so `[hooks]:`,
    /// `[ "hooks", ]:` and `[[hooks]]:` are all the key `hooks`), an optional
    /// quote, `hooks` in any case, an optional quote, then only blanks,
    /// closing brackets and commas before `:`, a comment or the line's end.
    private static func lineNamesHooksKey<Line: StringProtocol>(_ line: Line) -> Bool {
        var rest = Substring(line)
        while true {
            rest = rest.drop { $0 == " " || $0 == "\t" }
            guard let first = rest.first else { break }
            if first == "[" {
                rest = rest.dropFirst()
            } else if first == "-" || first == "?", rest.dropFirst().first.map({ $0 == " " || $0 == "\t" }) ?? true {
                rest = rest.dropFirst()
            } else {
                break
            }
        }
        if let quote = rest.first, quote == "\"" || quote == "'" { rest = rest.dropFirst() }
        guard rest.lowercased().hasPrefix("hooks") else { return false }
        rest = rest.dropFirst(5)
        if let quote = rest.first, quote == "\"" || quote == "'" { rest = rest.dropFirst() }
        rest = rest.drop { $0 == " " || $0 == "\t" || $0 == "]" || $0 == "," }
        return rest.isEmpty || rest.first == ":" || rest.first == "#"
    }

    private static func lineHasUncertainYAML(_ line: [Character]) -> Bool {
        let first = line.firstIndex { $0 != " " && $0 != "\t" } ?? line.endIndex
        let trimmed = line[first...]
        if trimmed.starts(with: "%") || trimmed.starts(with: "...") { return true }
        var atTokenStart = true
        var quote: Character?
        var previous: Character = " "
        var index = first
        while index < line.endIndex {
            let character = line[index]
            let next: Character? = index + 1 < line.endIndex ? line[index + 1] : nil
            defer {
                previous = character
                index += 1
            }
            if let open = quote {
                // In a double-quoted scalar a backslash escapes the next
                // character, so an escaped quote does not close it.
                if open == "\"", character == "\\" {
                    index += 1
                } else if character == open {
                    quote = nil
                }
                continue
            }
            if character == " " || character == "\t" { continue }
            // A comment runs to the end of the line.
            if character == "#", previous == " " || previous == "\t" || index == first { return false }
            if character == "{" { return true }
            if atTokenStart {
                if character == "&" || character == "*" || character == "!" { return true }
                if character == "<", next == "<" { return true }
                if character == "\"" || character == "'" {
                    quote = character
                    atTokenStart = false
                    continue
                }
                // An explicit key: Bun turns a sequence or flow sequence held
                // by one into its entries' text, so a quoted entry with an
                // escape could be the key, on this line or a later one.
                if character == "?", next == nil || next.map({ " \t,[]{}".contains($0) }) == true { return true }
                // A sequence entry: the next token starts after it.
                if character == "-", next == nil || next == " " || next == "\t" { continue }
                atTokenStart = false
            }
            if character == ":", next == nil || next == " " || next == "\t" {
                atTokenStart = true
            } else if character == "," || character == "[" {
                atTokenStart = true
            }
        }
        return false
    }
}

/// `installed_plugins.json`: every installation of each plugin id (version 2
/// lists them per scope; version 1 held one).
private struct InstalledPlugin {
    let installPath: String
    let version: String?

    static func parse(_ value: Any) -> [String: [InstalledPlugin]]? {
        guard let object = value as? [String: Any] else { return nil }
        guard let pluginsValue = object["plugins"] else { return [:] }
        guard let plugins = pluginsValue as? [String: Any] else { return nil }
        var result: [String: [InstalledPlugin]] = [:]
        for (id, entry) in plugins {
            let entries: [Any]
            if let list = entry as? [Any] {
                entries = list
            } else {
                entries = [entry]
            }
            var installations: [InstalledPlugin] = []
            for item in entries {
                guard let fields = item as? [String: Any], let installPath = fields["installPath"] as? String else {
                    return nil
                }
                installations.append(InstalledPlugin(installPath: installPath, version: fields["version"] as? String))
            }
            result[id] = installations
        }
        return result
    }
}

/// A `hooks` value in a plugin manifest or marketplace entry: a path to a
/// hooks file, inline hooks, or an array of both (2.1.88 `schemas.ts`).
private struct PluginHookSpec {
    var files: [String] = []
    var inline: [ClaudeHookGroup] = []
    /// A marketplace entry whose `hooks` could not be read.
    var malformed = false

    static func parse(_ value: Any) -> PluginHookSpec? {
        var spec = PluginHookSpec()
        for item in (value as? [Any]) ?? [value] {
            if let path = item as? String {
                spec.files.append(path)
            } else if let groups = ClaudeSettingsFacts.hookGroups(item) {
                spec.inline += groups
            } else {
                return nil
            }
        }
        return spec
    }
}

/// `.claude-plugin/plugin.json`, or a marketplace entry (the same fields):
/// its hooks, where its skills, agents and commands load from besides the
/// standard directories (a path, a list of paths, or for commands a map of
/// `{source}` paths and `{content}` inline markdown, 2.1.88 `schemas.ts`), and
/// the frontmatter of inline commands that may register hooks.
private struct PluginManifest {
    let hooks: PluginHookSpec
    let componentPaths: [(path: String, kind: ComponentKind)]
    let inlineCommandFrontmatter: [String]

    static func parse(_ value: Any) -> PluginManifest? {
        guard let object = value as? [String: Any] else { return nil }
        var hooks = PluginHookSpec()
        if let value = object["hooks"] {
            guard let spec = PluginHookSpec.parse(value) else { return nil }
            hooks = spec
        }
        var paths: [(path: String, kind: ComponentKind)] = []
        var inline: [String] = []
        for key in FileSystemClaudeSettingsGate.componentDirectories {
            let kind: ComponentKind = key == "skills" ? .skills : .markdownTree
            if let path = object[key] as? String { paths.append((path, kind)) }
            paths += ((object[key] as? [Any])?.compactMap { $0 as? String } ?? []).map { ($0, kind) }
            for case let command as [String: Any] in (object[key] as? [String: Any])?.values.map({ $0 }) ?? [] {
                if let path = command["source"] as? String { paths.append((path, .markdownTree)) }
                if let content = command["content"] as? String,
                   let block = ClaudeSettingsFacts.frontmatterHooksBlock(content) {
                    inline.append(block)
                }
            }
        }
        return PluginManifest(hooks: hooks, componentPaths: paths, inlineCommandFrontmatter: inline)
    }
}

/// A plugin hooks file (`hooks/hooks.json` or one a manifest names):
/// `{description?, hooks?, modules?}` in 2.1.280.
private struct PluginHooksFile {
    let groups: [ClaudeHookGroup]
    /// Hooks-module paths, relative to the hooks file.
    let modules: [String]
    /// Keys Claude Code does not document, as sorted-key JSON; nil when none.
    let otherKeys: Data?

    static func parse(_ value: Any) -> PluginHooksFile? {
        guard let object = value as? [String: Any] else { return nil }
        var groups: [ClaudeHookGroup] = []
        if let hooks = object["hooks"] {
            guard let parsed = ClaudeSettingsFacts.hookGroups(hooks) else { return nil }
            groups = parsed
        }
        var modules: [String] = []
        if let value = object["modules"] {
            guard let list = value as? [Any] else { return nil }
            for item in list {
                guard let path = item as? String else { return nil }
                modules.append(path)
            }
        }
        let other = object.filter { !["description", "hooks", "modules"].contains($0.key) }
        return PluginHooksFile(
            groups: groups, modules: modules,
            otherKeys: other.isEmpty ? nil : ClaudeSettingsFacts.canonicalJSON(other) ?? Data("{}".utf8))
    }
}

/// One `known_marketplaces.json` entry.
private struct KnownMarketplace {
    let installLocation: String?
    /// `source.source`: `github`, `git`, `url`, `file`, `directory`, …
    let sourceType: String?
    /// `source.path` of a `file` or `directory` marketplace.
    let sourcePath: String?

    static func parse(_ value: Any) -> [String: KnownMarketplace]? {
        guard let object = value as? [String: Any] else { return nil }
        var result: [String: KnownMarketplace] = [:]
        for (name, entry) in object {
            guard let fields = entry as? [String: Any] else { continue }
            let source = fields["source"] as? [String: Any]
            result[name] = KnownMarketplace(
                installLocation: (fields["installLocation"] as? String).flatMap(Self.absolute),
                sourceType: source?["source"] as? String,
                sourcePath: (source?["path"] as? String).flatMap(Self.absolute))
        }
        return result
    }

    private static func absolute(_ path: String) -> String? {
        WireField.isAbsolutePath(path) ? ClaudeSettingsScope.normalizedPath(path) : nil
    }
}

/// A settings file's `extraKnownMarketplaces` entry with a `directory` or
/// `file` source: the ones 2.1.280 loads in place before the registry
/// records them (`Gjt` admits only those, `ym`). Other sources load once the
/// background reconcile has fetched and recorded them, which the gate then
/// reads from `known_marketplaces.json`; a settings-sourced one's catalog is
/// written under `plugins/marketplaces` and recorded the same way (2.1.88
/// `marketplaceManager.ts`), and its entries carry no hooks.
private struct DeclaredMarketplace: Hashable {
    let name: String
    let sourceType: String
    /// As declared: absolute, `~`-relative or relative.
    let path: String

    static func parse(_ declared: [String: Any]) -> [DeclaredMarketplace] {
        declared.keys.sorted().compactMap { name in
            guard let entry = declared[name] as? [String: Any],
                  let source = entry["source"] as? [String: Any],
                  let type = source["source"] as? String, type == "directory" || type == "file",
                  let path = source["path"] as? String, !path.isEmpty else { return nil }
            return DeclaredMarketplace(name: name, sourceType: type, path: path)
        }
    }
}

/// One plugin's entry in a marketplace catalog.
private struct MarketplaceEntry {
    /// The actual catalog name, including when reached through `renames`.
    let name: String
    /// The entry's `source` when it is a path relative to the marketplace.
    let stringSource: String?
    let version: String?
    /// The entry's manifest fields; nil when they cannot be read.
    let manifest: PluginManifest?
    var catalogPath = ""
    /// What the catalog's inline command frontmatter is acknowledged under
    /// (`sharedSourcePath`).
    var catalogSourcePath = ""

    /// Every entry of a catalog, by name. Another plugin's malformed entry
    /// does not decline this one's.
    static func parseCatalog(_ value: Any) -> [String: MarketplaceEntry]? {
        guard let object = value as? [String: Any] else { return nil }
        guard let plugins = object["plugins"] else { return [:] }
        guard let entries = plugins as? [Any] else { return nil }
        var result: [String: MarketplaceEntry] = [:]
        for case let entry as [String: Any] in entries {
            guard let name = entry["name"] as? String else { continue }
            result[name] = MarketplaceEntry(
                name: name,
                stringSource: entry["source"] as? String,
                version: entry["version"] as? String,
                manifest: PluginManifest.parse(entry))
        }
        if let value = object["renames"] {
            guard let renames = value as? [String: Any],
                  renames.values.allSatisfy({ $0 is String || $0 is NSNull }) else { return nil }
            let original = result
            for alias in renames.keys.sorted() where original[alias] == nil {
                var target = alias
                var visited = Set<String>()
                // Both audited images use 16 iterations (2.1.267 `l$e`,
                // 2.1.280 `WXe`). Removed, cyclic, missing and deeper chains
                // never load a replacement. An existing name wins outright.
                for _ in 0..<16 {
                    guard visited.insert(target).inserted else { break }
                    guard let next = renames[target] else {
                        if let entry = original[target] { result[alias] = entry }
                        break
                    }
                    guard let name = next as? String else { break }
                    target = name
                }
            }
        }
        return result
    }
}

/// How Claude Code names a plugin's folders in its plugin cache
/// (`cache/<marketplace>/<plugin>/<version>`, 2.1.88 `getVersionedCachePathIn`,
/// 2.1.280 `z1t`).
private enum PluginCacheNames {
    static func sanitized(_ name: String) -> String {
        String(name.unicodeScalars.map { scalar -> Character in
            let allowed = (scalar >= "a" && scalar <= "z") || (scalar >= "A" && scalar <= "Z")
                || (scalar >= "0" && scalar <= "9") || scalar == "-" || scalar == "_"
            return allowed ? Character(scalar) : "-"
        })
    }

    /// 2.1.280's spelling for `@npm` plugins: other characters as `_hh` or
    /// `__hex_`.
    static func escaped(_ name: String) -> String {
        name.unicodeScalars.map { scalar -> String in
            if (scalar >= "a" && scalar <= "z") || (scalar >= "0" && scalar <= "9") || scalar == "-" {
                return String(scalar)
            }
            return scalar.value <= 255
                ? "_" + String(format: "%02x", scalar.value) : "__" + String(scalar.value, radix: 16) + "_"
        }.joined()
    }

    /// Lowercased: the default volume folds case.
    static func candidates(forPlugin name: String) -> Set<String> {
        [sanitized(name).lowercased(), escaped(name).lowercased()]
    }
}

/// A build's on-disk code identity: the host-architecture slice's cdhash (the
/// one the kernel runs, and so the one csecd sees live), and whether its
/// signature satisfies Anthropic's designated requirement. The executable's
/// pages are not hashed: this names a build for the inventory, and csecd
/// checks the running code itself.
private struct StaticCodeIdentity {
    let cdHash: String?
    let signedByAnthropic: Bool

    init(path: String) {
        var staticCode: SecStaticCode?
        var information: CFDictionary?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &staticCode) == errSecSuccess,
              let staticCode,
              SecCodeCopySigningInformation(
                staticCode, SecCSFlags(rawValue: UInt32(kSecCSSigningInformation)), &information) == errSecSuccess,
              let dictionary = information as? [String: Any] else {
            cdHash = nil
            signedByAnthropic = false
            return
        }
        let hash = (dictionary[kSecCodeInfoUnique as String] as? Data)?.map { String(format: "%02x", $0) }.joined()
        // Compatibility inventory must not call a corrupted image checked just
        // because its signing header still contains a known cdhash. Dynamic
        // authorization independently validates the actual live image.
        let valid = SecStaticCodeCheckValidity(
            staticCode, SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)), nil) == errSecSuccess
        cdHash = valid ? hash.flatMap { ForeignCodeIdentity.isWellFormedCDHash($0) ? $0 : nil } : nil
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
                ForeignCodeIdentity.anthropicClaudeCodeRequirement as CFString, [], &requirement) == errSecSuccess,
              let requirement else {
            signedByAnthropic = false
            return
        }
        signedByAnthropic = valid && SecStaticCodeCheckValidity(
            staticCode, SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)), requirement) == errSecSuccess
    }
}

// MARK: - One evaluation's findings

/// The findings of one `evaluate`, bounded as `ClaudeSettingsGateEvaluation`
/// requires: whatever does not fit is reported as unreadable (`.tooMany`),
/// never dropped silently.
private struct GateRun {
    enum SettingsRole {
        /// The user settings file: its `classifyAllShell` counts, and it is
        /// the one place csec's own hook is csec's.
        case user
        /// A file Claude Code reads only in some modes or cases (the cowork
        /// user settings): it can only decline.
        case declinesOnly
        /// A shadowed managed preferences plist: it can only decline, but
        /// unlike user settings it can configure a policy helper.
        case shadowedPolicy
        /// A policy source: its `classifyAllShell` counts only when every
        /// non-empty policy source sets it, since only one of them applies.
        case policy
        /// A policy source that never credits `classifyAllShell` (the
        /// user-writable server-managed settings), but that may be the one
        /// that applies, so while non-empty it withholds the others' credit.
        case policyNeverCredits
        /// Project or local settings: `classifyAllShell` there is ignored.
        case project
        /// An `--add-dir` directory's settings: only `enabledPlugins` and
        /// `extraKnownMarketplaces` count.
        case pluginEnablement
    }

    struct PluginSource {
        let sourceID: String
        let display: String
    }

    let scope: ClaudeSettingsScope
    let csecHandlers: Set<Data>
    var readPaths = Set<String>()
    /// `<directory>/.claude/` of every project, worktree main checkout and
    /// `--add-dir` directory, once known: their files are never shared with
    /// the default configuration home.
    var projectTrees: [String] = []
    var enabledPlugins: [String] = []
    var additionalDirectories: [String] = []
    /// Every settings file's local marketplace declarations, whatever its role.
    var declaredMarketplaces: [DeclaredMarketplace] = []
    var scannedEntries = 0
    var scanBudgetSpent = false

    private var userSetIn: [String] = []
    private var policySources: [(path: String, setsClassifyAllShell: Bool)] = []
    private var ignoredIn: [String] = []
    private var hooks: [ClaudeHookSource] = []
    private var hookDigests = Set<String>()
    private var environment: [ClaudeSettingsEnvironmentFinding] = []
    private var sandboxEnabled: [String] = []
    private var bypassPermissionsDefault: [String] = []
    private var hooksDisabled: [ClaudeHooksDisabledFinding] = []
    private var unreadable: [ClaudeUnreadableSetting] = []

    init(scope: ClaudeSettingsScope, csecHandlers: Set<Data>) {
        self.scope = scope
        self.csecHandlers = csecHandlers
    }

    /// `sourcePath` is what the file's hooks and classifier rules are
    /// digested and shown under (`sharedSourcePath`); every other finding
    /// names `path`, the file read.
    mutating func apply(_ facts: ClaudeSettingsFacts, path: String, sourcePath: String? = nil, role: SettingsRole) {
        for marketplace in facts.declaredMarketplaces where !declaredMarketplaces.contains(marketplace) {
            declaredMarketplaces.append(marketplace)
        }
        switch role {
        case .user:
            if facts.classifyAllShell { userSetIn.append(path) }
        case .declinesOnly, .shadowedPolicy:
            break
        case .policy:
            if !facts.isEmpty { policySources.append((path, facts.classifyAllShell)) }
        case .policyNeverCredits:
            if !facts.isEmpty { policySources.append((path, false)) }
        case .project:
            if facts.classifyAllShell { ignoredIn.append(path) }
        case .pluginEnablement:
            for id in facts.enabledPlugins where !enabledPlugins.contains(id) { enabledPlugins.append(id) }
            return
        }
        if facts.generatedPolicy && (role == .policy || role == .policyNeverCredits || role == .shadowedPolicy) {
            // Never execute a policy helper or acknowledge its configuration
            // as evidence of the hooks, rules or env its output will contain.
            addUnreadable(path, .generatedPolicy)
        }
        let sourcePath = sourcePath ?? path
        let display = ClaudeDelegationDisplay.path(sourcePath, homeDirectory: scope.homeDirectory)
        // Claude Code ignores project and local rules; csec's own entry is
        // csec's only where `csec setup` writes it.
        if role != .project {
            addClassifierRules(facts.classifierRules, path: path, sourceID: sourcePath, display: display,
                               excludingCsecEntries: role == .user)
        }
        for group in facts.hookGroups {
            // csec's own hook is excluded only where `csec setup` installs
            // it: anywhere else a copy of it is another hook.
            addHook(group, kind: .settings, sourceID: sourcePath, display: display, path: path,
                    excludingCsecHandler: role == .user && group.event == "PreToolUse")
        }
        addEnvironment(facts.environment, path: path)
        if facts.sandboxEnabled { addPath(path, to: \.sandboxEnabled) }
        if facts.bypassPermissionsDefault { addPath(path, to: \.bypassPermissionsDefault) }
        if facts.disableAllHooks { addDisabled(.disableAllHooks, path: path) }
        if facts.allowManagedHooksOnly { addDisabled(.allowManagedHooksOnly, path: path) }
        for id in facts.enabledPlugins where !enabledPlugins.contains(id) { enabledPlugins.append(id) }
        for directory in facts.additionalDirectories {
            additionalDirectories += resolvedDirectories(directory)
        }
    }

    /// `permissions.additionalDirectories` as written: absolute, `~/…`, or
    /// relative (resolved against every working directory, which can only
    /// add directories to scan).
    private func resolvedDirectories(_ directory: String) -> [String] {
        if directory.hasPrefix("/") { return [directory] }
        if directory == "~" { return [scope.homeDirectory] }
        if directory.hasPrefix("~/") { return [scope.homeDirectory + "/" + directory.dropFirst(2)] }
        return scope.workingDirectories.map { $0 + "/" + directory }
    }

    mutating func addHooks(_ groups: [ClaudeHookGroup], source: PluginSource, path: String) {
        for group in groups {
            addHook(group, kind: .plugin, sourceID: source.sourceID, display: ReviewDisplay.sanitized(source.display),
                    path: path, excludingCsecHandler: false)
        }
    }

    /// A plugin's hooks module (and any undocumented hooks-file key): one
    /// source, digested with each module's path and file digest.
    mutating func addHooksModule(modules: [String], otherKeys: Data?, source: PluginSource, path: String) {
        var handlers = modules.map { Self.jsonString($0) }
        if let otherKeys { handlers.append(otherKeys) }
        let digest = Self.digest(kind: .plugin, sourceID: source.sourceID, event: nil, matcher: nil, handlers: handlers)
        let shown = ReviewDisplay.sanitized(source.display)
        let detail = modules.isEmpty ? "hooks file with unknown keys" : "hooks module"
        append(ClaudeHookSource(
            kind: .plugin,
            sourceID: ClaudeDelegationDisplay.bounded(source.sourceID, maximumBytes: ClaudeHookSource.maximumSourceIDBytes),
            event: nil,
            matcher: nil,
            digest: digest,
            display: ClaudeDelegationDisplay.hook(source: shown, detail: detail),
            fetchesUnpinnedCode: false,
            moduleFiles: modules.isEmpty ? nil : modules.map {
                ClaudeDelegationDisplay.bounded($0, maximumBytes: ClaudeHookSource.maximumHandlerSummaryBytes)
            },
            shownWhole: ClaudeDelegationDisplay.hookIsWhole(source: shown, detail: detail)
                && modules.allSatisfy { $0.utf8.count <= ClaudeHookSource.maximumHandlerSummaryBytes }), path: path)
    }

    private mutating func addHook(
        _ group: ClaudeHookGroup, kind: ClaudeHookSource.Kind, sourceID: String, display: String, path: String,
        excludingCsecHandler: Bool
    ) {
        let handlers = excludingCsecHandler
            ? group.handlers.filter { !csecHandlers.contains($0.canonical) } : group.handlers
        guard !handlers.isEmpty else { return }
        let digest = Self.digest(
            kind: kind, sourceID: sourceID, event: group.event, matcher: group.matcher,
            handlers: handlers.map(\.canonical))
        let detail = group.event + " " + ClaudeDelegationDisplay.matcher(group.matcher)
        append(ClaudeHookSource(
            kind: kind,
            sourceID: ClaudeDelegationDisplay.bounded(sourceID, maximumBytes: ClaudeHookSource.maximumSourceIDBytes),
            event: group.event,
            matcher: group.matcher.map {
                ClaudeDelegationDisplay.bounded(
                    $0.replacingOccurrences(of: "\u{0}", with: "\u{FFFD}"),
                    maximumBytes: ClaudeHookSource.maximumMatcherBytes)
            },
            digest: digest,
            display: ClaudeDelegationDisplay.hook(source: display, detail: detail),
            fetchesUnpinnedCode: handlers.contains(where: \.fetchesUnpinnedCode),
            handlerSummaries: handlers.map(\.summary),
            shownWhole: ClaudeDelegationDisplay.matcherIsWhole(group.matcher)
                && ClaudeDelegationDisplay.hookIsWhole(source: display, detail: detail)
                && handlers.allSatisfy(\.summaryIsWhole)), path: path)
    }

    /// One settings source's classifier rules, when any section is not
    /// Claude Code's default.
    private mutating func addClassifierRules(
        _ lists: [String: [String]], path: String, sourceID: String, display: String, excludingCsecEntries: Bool
    ) {
        let counted = ClaudeClassifierRules.counted(lists, excludingCsecEntries: excludingCsecEntries)
        guard !counted.isEmpty else { return }
        var ruleDigests: [String] = []
        var rules: [ClaudeClassifierRules.Rule] = []
        var ruleTotal = 0
        for section in ClaudeClassifierRules.sections {
            for text in counted[section] ?? [] {
                ruleTotal += 1
                let digest = ClaudeClassifierRules.ruleDigest(section: section, text: text)
                if !ruleDigests.contains(digest) {
                    ruleDigests.append(digest)
                    rules.append(ClaudeClassifierRules.Rule(section: section, text: text, digest: digest))
                }
            }
        }
        guard ruleTotal <= ClaudeClassifierRules.maximumRulesPerSource,
              let sections = ClaudeSettingsFacts.canonicalJSON(counted) else {
            addUnreadable(path, .tooMany)
            return
        }
        let digest = Self.digest(kind: .classifierRules, sourceID: sourceID, event: nil, matcher: nil, handlers: [sections])
        let count = ClaudeClassifierRules.ruleCount(counted)
        let detail = "\(count) auto-mode classifier rule\(count == 1 ? "" : "s")"
        append(ClaudeHookSource(
            kind: .classifierRules,
            sourceID: ClaudeDelegationDisplay.bounded(sourceID, maximumBytes: ClaudeHookSource.maximumSourceIDBytes),
            event: nil,
            matcher: nil,
            digest: digest,
            display: ClaudeDelegationDisplay.hook(source: display, detail: detail),
            fetchesUnpinnedCode: false,
            ruleDigests: ruleDigests,
            rules: rules,
            shownWhole: ClaudeDelegationDisplay.hookIsWhole(source: display, detail: detail)), path: path)
    }

    /// `sourcePath` as for `apply`.
    mutating func addFrontmatterHooks(_ block: String, path: String, sourcePath: String? = nil) {
        let sourcePath = sourcePath ?? path
        let digest = Self.digest(
            kind: .frontmatter, sourceID: sourcePath, event: nil, matcher: nil,
            handlers: [Self.jsonString(block)])
        let shown = ClaudeDelegationDisplay.path(sourcePath, homeDirectory: scope.homeDirectory)
        let detail = "hooks in its frontmatter"
        append(ClaudeHookSource(
            kind: .frontmatter,
            sourceID: ClaudeDelegationDisplay.bounded(sourcePath, maximumBytes: ClaudeHookSource.maximumSourceIDBytes),
            event: nil,
            matcher: nil,
            digest: digest,
            display: ClaudeDelegationDisplay.hook(source: shown, detail: detail),
            fetchesUnpinnedCode: ClaudeHookFetchCheck.fetchesUnpinnedCode(command: block),
            shownWhole: ClaudeDelegationDisplay.hookIsWhole(source: shown, detail: detail)), path: path)
    }

    private mutating func append(_ hook: ClaudeHookSource, path: String) {
        guard hookDigests.insert(hook.digest).inserted else { return }
        guard hooks.count < ClaudeSettingsGateEvaluation.maximumHooks else {
            addUnreadable(path, .tooMany)
            return
        }
        hooks.append(hook)
    }

    mutating func addEnvironment(_ entries: [String], path: String) {
        for name in entries {
            let finding = ClaudeSettingsEnvironmentFinding(name: name, path: Self.wirePath(path))
            guard !environment.contains(finding) else { continue }
            guard environment.count < ClaudeSettingsGateEvaluation.maximumPaths else {
                addUnreadable(path, .tooMany)
                return
            }
            environment.append(finding)
        }
    }

    private mutating func addPath(_ path: String, to list: WritableKeyPath<GateRun, [String]>) {
        let wire = Self.wirePath(path)
        guard !self[keyPath: list].contains(wire) else { return }
        guard self[keyPath: list].count < ClaudeSettingsGateEvaluation.maximumPaths else {
            addUnreadable(path, .tooMany)
            return
        }
        self[keyPath: list].append(wire)
    }

    private mutating func addDisabled(_ setting: ClaudeHooksDisabledFinding.Setting, path: String) {
        let finding = ClaudeHooksDisabledFinding(setting: setting, path: Self.wirePath(path))
        guard !hooksDisabled.contains(finding) else { return }
        guard hooksDisabled.count < ClaudeSettingsGateEvaluation.maximumPaths else {
            addUnreadable(path, .tooMany)
            return
        }
        hooksDisabled.append(finding)
    }

    mutating func addUnreadable(_ path: String, _ reason: ClaudeUnreadableSetting.Reason) {
        let finding = ClaudeUnreadableSetting(path: Self.wirePath(path), reason: reason)
        guard !unreadable.contains(finding), unreadable.count < ClaudeSettingsGateEvaluation.maximumPaths else { return }
        unreadable.append(finding)
    }

    func evaluation() -> ClaudeSettingsGateEvaluation {
        var setIn = userSetIn
        if !policySources.isEmpty, policySources.allSatisfy(\.setsClassifyAllShell) {
            setIn += policySources.map(\.path)
        }
        return ClaudeSettingsGateEvaluation(
            classifyAllShell: ClaudeClassifyAllShellFinding(
                setIn: Array(setIn.map(Self.wirePath).prefix(ClaudeSettingsGateEvaluation.maximumPaths)),
                ignoredIn: Array(ignoredIn.map(Self.wirePath).prefix(ClaudeSettingsGateEvaluation.maximumPaths))),
            hooks: hooks,
            environment: environment,
            sandboxEnabled: sandboxEnabled,
            bypassPermissionsDefault: bypassPermissionsDefault,
            hooksDisabled: hooksDisabled,
            unreadable: unreadable)
    }

    /// A path as the evaluation carries it: absolute and within the wire's
    /// bound. One too long to carry keeps its end.
    static func wirePath(_ path: String) -> String {
        guard path.hasPrefix("/") else { return "/" }
        guard !WireField.isAbsolutePath(path) else { return path }
        return "/…" + ClaudeDelegationDisplay.tail(
            path.replacingOccurrences(of: "\u{0}", with: "\u{FFFD}"), maximumBytes: WireField.maximumPathBytes - 8)
    }

    /// 64 lowercase hex: SHA-256 of `{"event","handlers","matcher","sourceID",
    /// "sourceKind"}` as sorted-key JSON, each handler in its canonical form.
    static func digest(
        kind: ClaudeHookSource.Kind, sourceID: String, event: String?, matcher: String?, handlers: [Data]
    ) -> String {
        var json = Data("{\"event\":".utf8) + jsonString(event)
        json += Data(",\"handlers\":[".utf8)
        for (index, handler) in handlers.enumerated() {
            if index > 0 { json += Data(",".utf8) }
            json += handler
        }
        json += Data("],\"matcher\":".utf8) + jsonString(matcher)
        json += Data(",\"sourceID\":".utf8) + jsonString(sourceID)
        json += Data(",\"sourceKind\":".utf8) + jsonString(kind.rawValue) + Data("}".utf8)
        return SHA256.hash(data: json).map { String(format: "%02x", $0) }.joined()
    }

    static func jsonString(_ value: String?) -> Data {
        guard let value,
              let data = try? JSONSerialization.data(
                withJSONObject: value, options: [.fragmentsAllowed, .withoutEscapingSlashes]) else {
            return Data("null".utf8)
        }
        return data
    }
}

// MARK: - Display

/// How gate findings read in a terminal, a status row or csecd's Touch ID
/// sheet: sanitized, bounded, the home directory shown as `~`.
public enum ClaudeDelegationDisplay {
    /// `path` with the home directory as `~`, sanitized.
    public static func path(_ path: String, homeDirectory: String) -> String {
        if path == ClaudeSettingsScope.launchSettingsPath { return ClaudeSettingsScope.launchSettingsDisplay }
        let home = ClaudeSettingsScope.normalizedPath(homeDirectory)
        let shown: String
        if path == home {
            shown = "~"
        } else if home != "/", path.hasPrefix(home + "/") {
            shown = "~" + path.dropFirst(home.count)
        } else {
            shown = path
        }
        return ReviewDisplay.sanitized(shown)
    }

    /// "<source> · <detail>" within `AcknowledgedHookSummary.maximumDisplayBytes`,
    /// the source shortened from the front when it has to be.
    static func hook(source: String, detail: String) -> String {
        let suffix = " · " + bounded(ReviewDisplay.sanitized(detail), maximumBytes: 96)
        let budget = AcknowledgedHookSummary.maximumDisplayBytes - suffix.utf8.count
        let head = source.utf8.count <= budget ? source : "…" + tail(source, maximumBytes: budget - 3)
        let text = head + suffix
        return text.isEmpty ? "hook" : text
    }

    /// Whether `hook(source:detail:)` shows both whole.
    static func hookIsWhole(source: String, detail: String) -> Bool {
        hook(source: source, detail: detail) == source + " · " + ReviewDisplay.sanitized(detail)
    }

    static func matcher(_ matcher: String?) -> String {
        guard let matcher, !matcher.isEmpty else { return "*" }
        return bounded(ReviewDisplay.sanitized(matcher), maximumBytes: 48)
    }

    /// Whether `matcher(_:)` shows it whole: an absent or empty one is "*",
    /// which is what it matches.
    static func matcherIsWhole(_ matcher: String?) -> Bool {
        guard let matcher, !matcher.isEmpty else { return true }
        return self.matcher(matcher) == ReviewDisplay.sanitized(matcher)
    }

    /// At most `maximumBytes` of UTF-8, cut on a character boundary, with "…"
    /// marking a cut.
    public static func bounded(_ value: String, maximumBytes: Int) -> String {
        guard value.utf8.count > maximumBytes else { return value }
        var kept = ""
        var used = 0
        for character in value {
            let size = String(character).utf8.count
            if used + size > maximumBytes - 3 { break }
            kept.append(character)
            used += size
        }
        return kept + "…"
    }

    /// The last characters of `value` within `maximumBytes` of UTF-8.
    static func tail(_ value: String, maximumBytes: Int) -> String {
        var kept: [Character] = []
        var used = 0
        for character in value.reversed() {
            let size = String(character).utf8.count
            if used + size > maximumBytes { break }
            kept.append(character)
            used += size
        }
        return String(kept.reversed())
    }
}

// MARK: - Status rows

/// The `csec status` / `csec doctor` rows for delegated approvals. Only `.bad`
/// fails `csec doctor`: a delegation settings item csecd cannot read. The
/// "Agent allow rules" row stays beside these as defense-in-depth advice.
public enum ClaudeDelegationStatusRows {
    public static let label = "Claude auto-mode approvals"
    public static let buildsLabel = "Claude Code builds"
    public static let lastDeclineLabel = "Claude auto-mode last decline"
    public static let identityLookupLabel = "Claude Code identity check"
    public static let verificationLabel = "Claude Code release verification"

    /// What csec learned from csecd.
    public enum Report: Sendable, Equatable {
        case csecdUnavailable
        /// csecd does not advertise `delegated_approvals`.
        case unsupported
        case failed(String)
        case status(DelegationStatus)
    }

    /// `evaluation` stands in for the status's own settings evaluation when
    /// csecd sent none. `delegationEntryRemainsIn` names a user settings file
    /// still holding csec's delegation-aware auto-mode entry while delegation
    /// is off (a revert that could not be written).
    public static func rows(
        _ report: Report,
        evaluation fallback: ClaudeSettingsGateEvaluation? = nil,
        delegationEntryRemainsIn: String? = nil,
        displayPath: (String) -> String
    ) -> [StatusRow] {
        let status: DelegationStatus
        switch report {
        case .csecdUnavailable:
            return [StatusRow(label: label, value: "unknown — csecd is unavailable", state: .neutral)]
        case .unsupported:
            return [StatusRow(label: label, value: "not available in this csecd", state: .neutral)]
        case let .failed(reason):
            let shown = ClaudeDelegationDisplay.bounded(ReviewDisplay.sanitized(reason), maximumBytes: 120)
            return [StatusRow(label: label, value: "csecd could not report them (\(shown))", state: .warn)]
        case let .status(reported):
            status = reported
        }
        switch status.state {
        case .off:
            if let path = delegationEntryRemainsIn {
                return [StatusRow(
                    label: label,
                    value: "off, but csec's auto-mode entry in \(displayPath(path)) still says approvals release "
                        + "secrets — run csec setup",
                    state: .warn)]
            }
            return [StatusRow(label: label, value: "off — csec setup can let auto mode approve secret use",
                              state: .neutral)]
        case .unavailable:
            return [StatusRow(label: label, value: "unavailable — this csecd has no protected store for the setting",
                              state: .neutral)]
        case .unreadable:
            return [StatusRow(label: label, value: "delegation settings unreadable", state: .bad)]
        case .reconfirmationRequired:
            return [StatusRow(
                label: label,
                value: "paused: this csec delegates more than you agreed to — run csec setup to confirm again",
                state: .warn)]
        case .on:
            break
        }
        var rows: [StatusRow] = []
        let acknowledged = Set(status.acknowledgedHooks.map(\.digest))
        if let failure = (status.settings ?? fallback)?.firstFailure(acknowledgedDigests: acknowledged) {
            rows.append(StatusRow(label: label, value: "on, inactive: " + describe(failure, displayPath: displayPath),
                                  state: .warn))
        } else {
            rows.append(StatusRow(
                label: label,
                value: "on — \(status.counters.approved) approved / \(status.counters.declined) sent to Touch ID "
                    + "since csecd started",
                state: .ok))
        }
        if let verification = status.buildVerification {
            let unchecked = verification.uncheckedBuilds
            if let build = unchecked.first {
                rows.append(StatusRow(
                    label: verificationLabel,
                    value: "\(ReviewDisplay.sanitized(build.versionLabel)) (\(displayPath(build.path))) unchecked — "
                        + "delegation paused for this image until csec's list of checked releases includes it; "
                        + "Touch ID remains available"
                        + (unchecked.count > 1 ? " (+\(unchecked.count - 1) more)" : ""),
                    state: .warn))
            } else if !verification.unreadablePaths.isEmpty {
                rows.append(StatusRow(label: verificationLabel, value: "build inventory incomplete", state: .warn))
            } else {
                let versions = Set(verification.builds.compactMap(\.checkedVersion)).sorted().joined(separator: ", ")
                rows.append(StatusRow(
                    label: verificationLabel,
                    value: versions.isEmpty ? "no Claude Code images found" : "checked images: \(versions)", state: .neutral))
            }
        } else {
            rows.append(StatusRow(label: verificationLabel, value: "unavailable — update csec", state: .warn))
        }
        // Why the last request went to Touch ID, as its panel said it, and how
        // csecd located Claude Code's code: both value-free and csecd-authored,
        // re-sanitized here because a status is printed to a terminal.
        if let lastDecline = status.lastDecline {
            let reason = lastDecline.hasPrefix(DelegationDecline.panelPrefix)
                ? String(lastDecline.dropFirst(DelegationDecline.panelPrefix.count)) : lastDecline
            rows.append(StatusRow(
                label: lastDeclineLabel,
                value: ClaudeDelegationDisplay.bounded(ReviewDisplay.sanitized(reason), maximumBytes: 240),
                state: .neutral))
        }
        if let lookup = status.identityLookup {
            rows.append(StatusRow(
                label: identityLookupLabel,
                value: ClaudeDelegationDisplay.bounded(ReviewDisplay.sanitized(lookup), maximumBytes: 128),
                state: .neutral))
        }
        if let build = status.discoveredUntrustedBuilds.first {
            let more = status.discoveredUntrustedBuilds.count > 1
                ? " (+\(status.discoveredUntrustedBuilds.count - 1) more)" : ""
            let directory = displayPath((build.path as NSString).deletingLastPathComponent)
            rows.append(StatusRow(
                label: buildsLabel,
                value: "\(ReviewDisplay.sanitized(build.versionLabel)) (\(directory)) isn't signed by Anthropic or "
                    + "trusted — its sessions use Touch ID; \(DelegationDecline.setupCommand) can trust it\(more)",
                state: .warn))
        }
        return rows
    }

    /// Why settings keep delegation inactive, in one line.
    public static func describe(_ failure: ClaudeSettingsGateFailure, displayPath: (String) -> String) -> String {
        switch failure {
        case let .unreadable(setting):
            let what: String
            switch setting.reason {
            case .unreadable, .gateUnavailable: what = "unreadable"
            case .oversized: what = "too large to read"
            case .unparseable: what = "not valid settings"
            case .tooMany: what = "has too many entries to check"
            case .generatedPolicy: what = "loads generated policy the gate cannot inspect"
            }
            return "\(displayPath(setting.path)) \(what)"
        case let .injectedEnvironment(finding):
            return "\(ReviewDisplay.sanitized(finding.name)) set in \(displayPath(finding.path))"
        case let .classifyAllShellNotSet(ignoredIn):
            let ignored = ignoredIn.first.map {
                " (\(displayPath($0)) sets it, but Claude Code reads it only from user or managed settings)"
            } ?? ""
            return "autoMode.classifyAllShell not set\(ignored) — run \(DelegationDecline.setupCommand)"
        case let .unacknowledgedHook(hook) where hook.kind == .classifierRules:
            return "\(ReviewDisplay.sanitized(hook.display)) steer the classifier and aren't acknowledged as they "
                + "are now — run \(DelegationDecline.setupCommand) to review them"
        case let .unacknowledgedHook(hook):
            return "\(ReviewDisplay.sanitized(hook.display)) can approve shell commands — run "
                + "\(DelegationDecline.setupCommand) to review it"
        case let .sandboxEnabled(path):
            return "sandbox.enabled in \(displayPath(path))"
        case let .bypassPermissionsDefault(path):
            return "permissions.defaultMode bypassPermissions in \(displayPath(path))"
        case let .hooksDisabled(finding):
            return "\(finding.setting.rawValue) in \(displayPath(finding.path))"
        }
    }
}
