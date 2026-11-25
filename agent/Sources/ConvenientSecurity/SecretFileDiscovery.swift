import Foundation
import CoreFoundation

#if canImport(Darwin)
import Darwin
#endif

/// Structural classes discovery distinguishes by name and content. Tool
/// specificity deliberately lives in the credential catalog (`catalogID` on
/// the record), so covering another tool is a data change, not a new case.
public enum SecretFileKind: String, Sendable, Equatable, Codable {
    case dotenv
    case envrc
    case shellRc = "shell_rc"
    case sshPrivateKey = "ssh_private_key"
    case keyMaterial = "key_material"
    case toolCredential = "tool_credential"
    case other
}

public enum SecretFileSizeClass: String, Sendable, Equatable, Codable {
    /// ≤ 4 KiB.
    case small
    /// ≤ 1 MiB.
    case medium
    /// ≤ the 4 MiB blob bound.
    case large
    /// Beyond what `csec protect` can import.
    case overLimit = "over_limit"

    init(byteSize: Int) {
        if byteSize <= 4096 {
            self = .small
        } else if byteSize <= 1024 * 1024 {
            self = .medium
        } else if byteSize <= NativeBlobStore.maximumBlobBytes {
            self = .large
        } else {
            self = .overLimit
        }
    }
}

/// One protectable file. Metadata only — detection may read bytes transiently
/// to classify, but the record never retains a value.
public struct DiscoveredSecretFile: Sendable, Equatable {
    /// Fully resolved path every alias collapses onto (dev/ino-deduped).
    public let canonicalPath: String
    /// Other discovered hardlink paths to the same file (never symlinks).
    /// Whole-file protection writes a sidecar at each.
    public internal(set) var aliasPaths: [String]
    public internal(set) var kind: SecretFileKind
    /// The `KnownCredentialFile.id` when a catalog probe identified this file.
    public let catalogID: String?
    public let displayName: String?
    public let mode: UInt16
    public let byteSize: Int
    public let sizeClass: SecretFileSizeClass
    /// The scan root this file was found under (`~`, a `--scan-root`, or
    /// `catalog`/`ssh` for structural probes).
    public let rootLabel: String
    public let suggestedApproach: CredentialDelivery
    /// True when the owning tool normally keeps this secret in the macOS
    /// Keychain — the file's presence is itself a degraded-posture finding.
    public let keychainFallback: Bool
    /// True when the catalog says the owning tool saves this file during
    /// ordinary commands, so whole-file protection would break it or put the
    /// plaintext back (`KnownCredentialFile.toolRewritesFile`).
    public let toolRewritesFile: Bool
    /// Value-free annotations (posture, fallback reasons, bounds).
    public internal(set) var notes: [String]

    public init(
        canonicalPath: String,
        aliasPaths: [String],
        kind: SecretFileKind,
        catalogID: String?,
        displayName: String?,
        mode: UInt16,
        byteSize: Int,
        sizeClass: SecretFileSizeClass,
        rootLabel: String,
        suggestedApproach: CredentialDelivery,
        keychainFallback: Bool,
        toolRewritesFile: Bool = false,
        notes: [String]
    ) {
        self.canonicalPath = canonicalPath
        self.aliasPaths = aliasPaths
        self.kind = kind
        self.catalogID = catalogID
        self.displayName = displayName
        self.mode = mode
        self.byteSize = byteSize
        self.sizeClass = sizeClass
        self.rootLabel = rootLabel
        self.suggestedApproach = suggestedApproach
        self.keychainFallback = keychainFallback
        self.toolRewritesFile = toolRewritesFile
        self.notes = notes
    }
}

public struct SecretFileDiscoveryProgress: Sendable, Equatable {
    public enum Phase: Sendable, Equatable {
        /// Probing the catalog's known credential paths, `~/.ssh` and the
        /// shell startup files.
        case knownLocations
        /// Walking a scan root.
        case sweep
    }

    /// Where the walk is within one level of a root: on folder `index` of
    /// `total` (1-based). The walk is depth-first, so every folder before
    /// `index` at this level is finished; `total` is the number of folders
    /// that level's listing held, which is what makes this a measured
    /// remaining indication rather than a guess.
    public struct FolderPosition: Sendable, Equatable {
        public let name: String
        public let index: Int
        public let total: Int

        public init(name: String, index: Int, total: Int) {
            self.name = name
            self.index = index
            self.total = total
        }
    }

    public let visitedEntries: Int
    public let discoveredFiles: Int
    public let currentLocation: String
    public let phase: Phase
    /// The root being walked (`~`, a `--scan-root`), and its place among them.
    public let rootLabel: String?
    public let rootIndex: Int
    public let rootCount: Int
    /// The position in the root's top-level folders, then in the current
    /// top-level folder's own folders; empty before the first is entered.
    public let folders: [FolderPosition]

    public init(
        visitedEntries: Int,
        discoveredFiles: Int,
        currentLocation: String,
        phase: Phase = .sweep,
        rootLabel: String? = nil,
        rootIndex: Int = 0,
        rootCount: Int = 0,
        folders: [FolderPosition] = []
    ) {
        self.visitedEntries = visitedEntries
        self.discoveredFiles = discoveredFiles
        self.currentLocation = currentLocation
        self.phase = phase
        self.rootLabel = rootLabel
        self.rootIndex = rootIndex
        self.rootCount = rootCount
        self.folders = folders
    }
}

public struct SecretFileDiscoveryReport: Sendable {
    public let files: [DiscoveredSecretFile]
    public let warnings: [String]
    public let scannedRootLabels: [String]
    public let visitedEntryCount: Int
    /// Candidate symlinks resolved to destinations, never separate plan rows.
    public let symlinkCount: Int
    /// Default exclusions, grouped by reason; counts are paths (files or trees).
    public let exclusionCounts: [String: Int]
    /// Env-style files that parsed cleanly but held nothing secret-like:
    /// suppressed from `files`, counted so the summary can say so.
    public let suppressedSecretFreeEnvFiles: Int
}

/// File-level discovery for the bulk-protect flow: sweeps the scan roots
/// (default: the whole home directory) for project-level secret files, probes
/// the credential catalog's absolute paths directly — bypassing the walk's
/// exclusions, which is the only reliable way to reach
/// credentials inside excluded trees — and resolves/dedupes symlinks and
/// hardlinks so each file is imported once. Symlinks remain pointed at the
/// destination; only hardlinks need additional protection paths.
public enum SecretFileDiscoveryEngine {
    /// Classify only the explicitly selected, already safely read file. Unlike
    /// discovery this never sweeps siblings or silently drops unknown files.
    public static func explicitFile(
        path: String, data: Data, mode: UInt16, homeDirectory: String,
        environment: [String: String] = [:]
    ) -> DiscoveredSecretFile {
        let name = (path as NSString).lastPathComponent
        let catalogEntry = CredentialCatalog.entries.first { entry in
            let overrides = entry.environmentOverrides.compactMap { override -> String? in
                guard let value = environment[override.variable], !value.isEmpty else { return nil }
                return override.template.replacingOccurrences(of: "$VALUE", with: value)
            }
            return (entry.pathTemplates + overrides).contains {
                let expanded = expandHome($0, home: homeDirectory)
                // Match literal catalog paths in the same realpath namespace as
                // the safe reader (/var vs /private/var, or a linked .aws parent).
                if !expanded.contains("*"), !expanded.contains("?"), resolvePath(expanded) == path {
                    return true
                }
                return GlobMatcher.matches(expanded, path: path, homeDirectory: homeDirectory)
            }
        }
        let match = walkPathMatch(path)
        var kind = catalogEntry?.kind ?? match?.kind ?? .other
        var approach = catalogEntry?.delivery ?? match?.approach ?? .wholeFile
        if path.hasPrefix(homeDirectory + "/.ssh/")
            || ((path as NSString).deletingLastPathComponent as NSString).lastPathComponent == ".ssh",
           case .privateKey = classifyKeyContent(data, name: name) {
            kind = .sshPrivateKey
            switch SSHKeyFileVerdict.inspect(data) {
            case .obsolete, .unsupportedType, .unreadable:
                // csec's SSH agent cannot use it; encrypting it whole still
                // takes the plaintext off disk, as bulk protect does.
                approach = .wholeFile
            case .importable, .passphraseProtected, .securityKey:
                // The SSH path explains its refusal of the last two.
                approach = .sshKey
            }
        }
        if [.dotenv, .envrc, .shellRc].contains(kind) {
            switch classifyEnvContent(data) {
            case .wholeFileFallback, .unparseable: approach = .wholeFile
            case .perVar, .secretFree: approach = .perVar
            }
        }
        return DiscoveredSecretFile(
            canonicalPath: path, aliasPaths: [], kind: kind,
            catalogID: catalogEntry?.id ?? match?.catalogID,
            displayName: catalogEntry?.displayName ?? match?.displayName,
            mode: mode, byteSize: data.count, sizeClass: SecretFileSizeClass(byteSize: data.count),
            rootLabel: "explicit", suggestedApproach: approach,
            keychainFallback: catalogEntry?.keychainDefaultOnMacOS ?? false,
            toolRewritesFile: catalogEntry?.toolRewritesFile ?? false, notes: [])
    }

    public static let maximumContentSniffBytes = EnvFileDocument.maximumBytes
    public static let shellStartupPreservationNote = "shell startup file preserved by default; "
        + "per-variable rewriting cannot handle it, so migrate manually or choose whole-file explicitly"
    /// Why a file the tool rewrites is skipped by default, shown in the plan.
    public static let toolRewritesFileNote = "its tool rewrites this file during ordinary "
        + "commands, so whole-file protection would break it or put the plaintext back; "
        + "skipped unless whole-file is chosen"
    /// Fly rewrites its config too, but its token comes out of the file.
    public static let flyTokenNote = "fly rewrites this file during ordinary commands, so csec "
        + "takes the token out of it for `csec fly` and keeps every other setting"
    static let progressInterval = 256

    /// Directory names the general walk skips as build/vendor/home noise.
    /// Credential-bearing dotdirs (`.aws`, `.config`, `.ssh`, `.gnupg`,
    /// `.kube`, `.docker`, `.fly`, `.codex`, …) are deliberately absent; the
    /// excluded trees that do hold credentials (`~/.cache`, `~/Library`,
    /// `~/.cargo`, `~/.m2`, `~/.gradle`) are reached by catalog probes.
    public static let excludedDirectoryNames: Set<String> = [
        ".git", ".build", ".swiftpm", "node_modules", "vendor", "Pods",
        "DerivedData", "build", "dist", "coverage", "tmp",
        "Library", ".Trash", ".cache", "Caches", ".cargo", ".rustup", ".npm",
        ".gradle", ".m2", "Applications", ".venv", "venv", ".virtualenvs",
        ".tox", ".mypy_cache", ".pytest_cache", "__pycache__", "target",
        ".terraform",
    ]
    /// Root-relative paths excluded even though the leaf name alone is too
    /// common to blanket-ban (a Go workspace's module cache, not every `pkg`).
    public static let excludedRelativePaths: Set<String> = ["go/pkg"]

    /// Only these app-owned subtrees are excluded, never their account config.
    /// Keep this list location-specific: a project named `extensions` is valid.
    public static let excludedHomeTrees: [String] = [
        ".vscode/extensions", ".vscode-insiders/extensions", ".cursor/extensions",
        ".local/share/mise/installs", ".local/share/uv/python", ".pyenv/versions",
        ".rbenv/versions", ".asdf/installs", ".nvm/versions", ".platformio/packages",
    ]
    private static let fixtureDirectoryNames: Set<String> = [
        "test", "tests", "spec", "fixtures", "__fixtures__", "testdata",
        "regress", "integration-tests",
    ]

    /// Whether a sweep of `roots` (none: home) covers the home directory, and
    /// so also probes the home-global known credential locations.
    public static func scanCoversHome(roots: [String], homeDirectory: String) -> Bool {
        guard !roots.isEmpty else { return true }
        let home = resolvePath(homeDirectory)
        return roots.map(resolvePath).contains {
            $0 == home || home.hasPrefix($0 == "/" ? "/" : $0 + "/")
        }
    }

    public static func discover(
        roots: [String],
        homeDirectory: String,
        environment: [String: String] = [:],
        catalog: [KnownCredentialFile] = CredentialCatalog.entries,
        includeExcluded: Bool = false,
        progress: ((SecretFileDiscoveryProgress) -> Void)? = nil
    ) -> SecretFileDiscoveryReport {
        // Canonicalize home once so template expansion, prefix stripping, and
        // labels all live in the same namespace as resolved paths (macOS's
        // /var -> /private/var firmlink would otherwise break the prefixes).
        var state = DiscoveryState(
            homeDirectory: resolvePath(homeDirectory), includeExcluded: includeExcluded, progress: progress)

        let scanRoots = roots.isEmpty ? [homeDirectory] : roots

        // Resolve the roots up front: the home-global probes below only run
        // when the sweep actually covers the home directory. An explicit
        // narrow --scan-root must stay inside its roots — probing (and later
        // protecting) home-global credentials from a scan the user pointed
        // elsewhere is exactly the blast-radius surprise this guards against.
        var resolvedRoots: [(resolved: String, label: String)] = []
        var seenRootIdentities: Set<FileIdentity> = []
        for root in scanRoots {
            let resolved = resolvePath(root)
            guard let identity = directoryIdentity(resolved) else {
                state.warnings.append(
                    "scan root \(displayPath(root, home: state.homeDirectory)) "
                        + "is not a readable directory")
                continue
            }
            guard seenRootIdentities.insert(identity).inserted else { continue }
            let label = resolved == state.homeDirectory
                ? "~"
                : displayPath(resolved, home: state.homeDirectory)
            resolvedRoots.append((resolved, label))
            state.scannedRootLabels.append(label)
        }
        state.scanRoots = resolvedRoots.map(\.resolved)
        let sweepCoversHome = resolvedRoots.contains {
            $0.resolved == state.homeDirectory
                || state.homeDirectory.hasPrefix($0.resolved == "/" ? "/" : $0.resolved + "/")
        }

        // Catalog + structural probes first: their classification is richer
        // than the walk's, and the dev/ino dedupe then treats walk hits on the
        // same files as aliases.
        if sweepCoversHome {
            state.report(location: "known credential locations")
            probeMacBitcoinWallets(state: &state)
            probeCatalog(catalog, environment: environment, state: &state)
            probeSSHDirectory(environment: environment, state: &state)
            probeShellRcFiles(environment: environment, state: &state)
        }

        state.phase = .sweep
        state.rootCount = resolvedRoots.count
        for (offset, root) in resolvedRoots.enumerated() {
            state.rootIndex = offset + 1
            state.rootLabel = root.label
            state.folderLevels = []
            state.report(location: root.label)
            walk(root: root.resolved, label: root.label, state: &state)
        }

        // A catalog path or hardlink may have been visited before its live
        // store. No spelling of that inode belongs in the bulk picker.
        let withheld = Set(state.reportOnlyIdentities.compactMap { state.indexByIdentity[$0] })
        let files = state.files.enumerated().compactMap { index, file in
            withheld.contains(index) ? nil : file
        }.sorted {
            ($0.rootLabel, $0.canonicalPath) < ($1.rootLabel, $1.canonicalPath)
        }
        return SecretFileDiscoveryReport(
            files: files,
            warnings: state.warnings + state.advisories.sorted(),
            scannedRootLabels: state.scannedRootLabels,
            visitedEntryCount: state.visited,
            symlinkCount: state.symlinkPaths.count,
            exclusionCounts: state.excludedPaths.values.reduce(into: [:]) { $0[$1, default: 0] += 1 },
            suppressedSecretFreeEnvFiles: state.suppressedSecretFree
        )
    }

    // MARK: - shared state

    private struct FileIdentity: Hashable {
        let device: UInt64
        let inode: UInt64

        init(_ info: stat) {
            device = UInt64(info.st_dev)
            inode = UInt64(info.st_ino)
        }
    }

    private struct DiscoveryState {
        let homeDirectory: String
        let includeExcluded: Bool
        let progress: ((SecretFileDiscoveryProgress) -> Void)?
        var files: [DiscoveredSecretFile] = []
        var indexByIdentity: [FileIdentity: Int] = [:]
        var warnings: [String] = []
        var reportOnlyIdentities: Set<FileIdentity> = []
        var advisories: Set<String> = []
        var scannedRootLabels: [String] = []
        var visited = 0
        var scanRoots: [String] = []
        var excludedPaths: [String: String] = [:]
        var symlinkPaths: Set<String> = []
        var visitedDirectories: Set<FileIdentity> = []
        var suppressedSecretFreeIdentities: Set<FileIdentity> = []
        var suppressedSecretFree = 0
        var phase: SecretFileDiscoveryProgress.Phase = .knownLocations
        var rootLabel: String?
        var rootIndex = 0
        var rootCount = 0
        /// The walk's position in the top two levels of the current root.
        var folderLevels: [(name: String, index: Int, total: Int)] = []

        mutating func tick(location: String) {
            visited += 1
            if visited % SecretFileDiscoveryEngine.progressInterval == 0 {
                report(location: location)
            }
        }

        func report(location: String) {
            progress?(SecretFileDiscoveryProgress(
                visitedEntries: visited,
                discoveredFiles: files.count,
                currentLocation: location,
                phase: phase,
                rootLabel: rootLabel,
                rootIndex: rootIndex,
                rootCount: rootCount,
                folders: folderLevels.filter { $0.total > 0 }.map {
                    SecretFileDiscoveryProgress.FolderPosition(
                        name: $0.name, index: $0.index, total: $0.total)
                }
            ))
        }

        /// A directory at `depth` (1 = a root's child) leaves the walk's
        /// stack. Depth-first order means its predecessors at that level are
        /// done, and a new top-level folder starts its own second level.
        mutating func enterFolder(name: String, depth: Int, location: String) {
            guard depth == 1 || depth == 2, folderLevels.count >= depth else { return }
            folderLevels[depth - 1].name = name
            folderLevels[depth - 1].index += 1
            if depth == 1 { folderLevels.removeSubrange(1...) }
            report(location: location)
        }

        /// A directory at `depth` 0 or 1 was listed and pushed `count` folders.
        mutating func listedFolders(_ count: Int, depth: Int) {
            guard depth == 0 || depth == 1, folderLevels.count == depth else { return }
            folderLevels.append((name: "", index: 0, total: count))
        }
    }

    // MARK: - catalog probes

    private static func probeCatalog(
        _ catalog: [KnownCredentialFile],
        environment: [String: String],
        state: inout DiscoveryState
    ) {
        for entry in catalog {
            var templates: [String] = []
            for override in entry.environmentOverrides {
                guard let value = environment[override.variable],
                      !value.isEmpty, !value.utf8.contains(0) else { continue }
                templates.append(override.template.replacingOccurrences(
                    of: "$VALUE", with: value))
            }
            templates.append(contentsOf: entry.pathTemplates)

            var probed: Set<String> = []
            for template in templates {
                let expanded = expandHome(template, home: state.homeDirectory)
                for path in expandGlob(expanded) where probed.insert(path).inserted {
                    state.tick(location: entry.id)
                    admitCandidate(
                        path: path,
                        kind: entry.kind,
                        catalogID: entry.id,
                        displayName: entry.displayName,
                        rootLabel: "catalog",
                        approach: entry.delivery,
                        keychainFallback: entry.keychainDefaultOnMacOS,
                        contentGate: entry.contentGate,
                        toolRewritesFile: entry.toolRewritesFile,
                        state: &state
                    )
                }
            }
        }
    }

    /// `~/.ssh` is probed structurally: key files carry arbitrary names, so
    /// membership is decided by content (a private-key header), and delivery
    /// belongs to the existing `protect --ssh` flow.
    private static func probeSSHDirectory(
        environment: [String: String],
        state: inout DiscoveryState
    ) {
        let directory = expandHome(CredentialCatalog.sshDirectory, home: state.homeDirectory)
        let entries = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
        for name in entries.sorted() {
            guard isSSHDirectoryKeyCandidateName(name) else { continue }
            state.tick(location: "~/.ssh")
            let path = directory + "/" + name
            admitCandidate(
                path: path,
                kind: .sshPrivateKey,
                catalogID: nil,
                displayName: "SSH private key",
                rootLabel: "ssh",
                approach: .sshKey,
                keychainFallback: false,
                contentGate: .always,
                requirePrivateKeyContent: true,
                state: &state
            )
        }
    }

    /// Whether a file in an SSH directory may be a private key, before its
    /// content is checked: everything except OpenSSH's own non-key files.
    private static func isSSHDirectoryKeyCandidateName(_ name: String) -> Bool {
        let skipNames: Set<String> = [
            "config", "authorized_keys", "authorized_keys2", "environment",
            "agent-socket",
        ]
        return !skipNames.contains(name)
            && !name.hasPrefix("known_host")
            && !name.hasSuffix(".pub")
    }

    /// Shell rc files are probed at their canonical locations (and `$ZDOTDIR`
    /// for the zsh trio) when the scan covers home. They ride the per-var env path.
    private static func probeShellRcFiles(
        environment: [String: String],
        state: inout DiscoveryState
    ) {
        var paths = [
            "~/.zshrc", "~/.zshenv", "~/.zprofile",
            "~/.bashrc", "~/.bash_profile", "~/.profile",
        ].map { expandHome($0, home: state.homeDirectory) }
        if let zdotdir = environment["ZDOTDIR"], zdotdir.hasPrefix("/") {
            paths.append(contentsOf: [".zshrc", ".zshenv", ".zprofile"].map {
                zdotdir + "/" + $0
            })
        }
        for path in paths {
            state.tick(location: "shell rc")
            admitCandidate(
                path: path,
                kind: .shellRc,
                catalogID: nil,
                displayName: "shell rc",
                rootLabel: "shell",
                approach: .perVar,
                keychainFallback: false,
                contentGate: .always,
                state: &state
            )
        }
    }

    // MARK: - the general walk

    private static func walk(root: String, label: String, state: inout DiscoveryState) {
        let rootURL = URL(fileURLWithPath: root, isDirectory: true)
        let keys: [URLResourceKey] = [.isDirectoryKey, .isRegularFileKey, .isSymbolicLinkKey]
        var pending: [(url: URL, relativePath: String)] = [(rootURL, "")]
        while let directory = pending.popLast() {
            // Each listing autoreleases its URLs and their prefetched
            // resource values, and a command-line run has no run loop to
            // drain them: without a pool per directory a walk over ~ kept
            // every entry it had seen, about 4 KB each, and reached 19 GB.
            autoreleasepool {
                walkDirectory(
                    directory, label: label, keys: keys, pending: &pending, state: &state)
            }
        }
    }

    private static func walkDirectory(
        _ directory: (url: URL, relativePath: String),
        label: String,
        keys: [URLResourceKey],
        pending: inout [(url: URL, relativePath: String)],
        state: inout DiscoveryState
    ) {
        let depth = directory.relativePath.isEmpty
            ? 0 : directory.relativePath.reduce(1) { $0 + ($1 == "/" ? 1 : 0) }
        if depth > 0 {
            state.enterFolder(
                name: directory.url.lastPathComponent, depth: depth,
                location: label + "/" + directory.relativePath)
        }
        let pendingBefore = pending.count
        defer { state.listedFolders(pending.count - pendingBefore, depth: depth) }
        let directoryPath = directory.url.path
        if excludeTree(directoryPath, state: &state) { return }
        guard let identity = directoryIdentity(directoryPath),
              state.visitedDirectories.insert(identity).inserted else { return }
        let entries: [URL]
        do {
            entries = try FileManager.default.contentsOfDirectory(
                at: directory.url, includingPropertiesForKeys: keys, options: []
            ).sorted { $0.lastPathComponent < $1.lastPathComponent }
        } catch {
            state.warnings.append("could not read directory \(display(directory.url.path, state))")
            return
        }
        for url in entries {
            state.tick(location: label + (directory.relativePath.isEmpty
                ? "" : "/" + directory.relativePath))
            let name = url.lastPathComponent
            let relative = directory.relativePath.isEmpty
                ? name
                : directory.relativePath + "/" + name
            let values = try? url.resourceValues(forKeys: Set(keys))
            if values?.isDirectory == true {
                // Symlinked directories are never traversed: real roots
                // plus inode dedupe already give full coverage without
                // loops, root escapes, or double counting.
                if values?.isSymbolicLink != true,
                   !excludedDirectoryNames.contains(name),
                   !excludedRelativePaths.contains(relative) {
                    pending.append((url, relative))
                }
                continue
            }

            if let store = MutableStore(name: name, directory: directoryPath, home: state.homeDirectory) {
                recordMutableStore(store, path: url.path, state: &state)
                continue
            }

            // A `.ssh` directory reached by the walk (a moved `~/.ssh`
            // target, a backup copy) is classified like `~/.ssh` itself:
            // key files carry arbitrary names, so content decides.
            let match = directory.url.lastPathComponent == ".ssh"
                && isSSHDirectoryKeyCandidateName(name)
                ? WalkMatch(
                    kind: .sshPrivateKey, approach: .sshKey,
                    displayName: "SSH private key", requirePrivateKeyContent: true)
                : walkPathMatch(url.path)
            guard let match else { continue }
            admitCandidate(
                path: url.path,
                kind: match.kind,
                catalogID: match.catalogID,
                displayName: match.displayName,
                rootLabel: label,
                approach: match.approach,
                keychainFallback: false,
                contentGate: match.contentGate,
                requirePrivateKeyContent: match.requirePrivateKeyContent,
                state: &state
            )
        }
    }

    /// Match fixture/dependency names beneath home or the explicit scan root,
    /// never against unrelated ancestors (e.g. a user whose login is `test`).
    private static func relativeComponents(_ path: String, state: DiscoveryState) -> [String] {
        let bases = [state.homeDirectory] + state.scanRoots.sorted { $0.count > $1.count }
        for base in bases {
            if path == base { return [] }
            let prefix = base == "/" ? "/" : base + "/"
            if path.hasPrefix(prefix) { return path.dropFirst(prefix.count).split(separator: "/").map(String.init) }
        }
        return []
    }

    private static func excludeTree(_ path: String, state: inout DiscoveryState) -> Bool {
        guard !state.includeExcluded else { return false }
        for relative in excludedHomeTrees {
            let tree = state.homeDirectory + "/" + relative
            if path == tree || path.hasPrefix(tree + "/") {
                state.excludedPaths[tree] = "installed tools/extensions"
                return true
            }
        }
        // Mix/Elixir dependencies, analogous to node_modules/vendor.
        if let index = relativeComponents(path, state: state).firstIndex(of: "deps") {
            let relative = relativeComponents(path, state: state)
            let suffix = relative.dropFirst(index + 1).joined(separator: "/")
            let tree = suffix.isEmpty ? path : String(path.dropLast(suffix.count + 1))
            state.excludedPaths[tree] = "dependency trees"
            return true
        }
        return false
    }

    private static func excludeCandidate(
        _ path: String, kind: SecretFileKind, state: inout DiscoveryState
    ) -> Bool {
        guard !state.includeExcluded else { return false }
        if excludeTree(path, state: &state) { return true }
        let name = (path as NSString).lastPathComponent.lowercased()
        let reason: String?
        if path == state.homeDirectory + "/.claude/daemon/control.key" {
            reason = "app runtime keys"
        } else if kind == .dotenv,
                  [".enc", ".encrypted", ".gpg", ".age", ".csec", ".erb", ".j2", ".jinja", ".jinja2"]
                    .contains(where: name.hasSuffix) {
            reason = "env templates/encrypted files"
        } else if (kind == .keyMaterial || kind == .sshPrivateKey),
                  relativeComponents(path, state: state).dropLast().contains(where: { fixtureDirectoryNames.contains($0) }) {
            reason = "test fixture keys"
        } else {
            reason = nil
        }
        guard let reason else { return false }
        state.excludedPaths[path] = reason
        return true
    }

    private struct WalkMatch {
        let kind: SecretFileKind
        let approach: CredentialDelivery
        let contentGate: CredentialContentGate
        let catalogID: String?
        let displayName: String?
        let requirePrivateKeyContent: Bool

        init(
            kind: SecretFileKind,
            approach: CredentialDelivery,
            contentGate: CredentialContentGate = .always,
            catalogID: String? = nil,
            displayName: String? = nil,
            requirePrivateKeyContent: Bool = false
        ) {
            self.kind = kind
            self.approach = approach
            self.contentGate = contentGate
            self.catalogID = catalogID
            self.displayName = displayName
            self.requirePrivateKeyContent = requirePrivateKeyContent
        }
    }

    private static func walkPathMatch(_ path: String) -> WalkMatch? {
        let name = (path as NSString).lastPathComponent
        let parent = ((path as NSString).deletingLastPathComponent as NSString).lastPathComponent
        if name == "id.json", parent == "solana" {
            return WalkMatch(
                kind: .keyMaterial, approach: .wholeFile, contentGate: .solanaKeypair,
                catalogID: "solana", displayName: "Solana keypair")
        }
        return walkNameMatch(name)
    }

    private static func walkNameMatch(_ name: String) -> WalkMatch? {
        if name.hasPrefix("UTC--") {
            return WalkMatch(
                kind: .keyMaterial, approach: .wholeFile, contentGate: .ethereumKeystore,
                catalogID: "ethereum-keystore", displayName: "Ethereum key store")
        }
        if isLiveDotenvName(name) {
            return WalkMatch(kind: .dotenv, approach: .perVar)
        }
        if name == ".envrc" {
            return WalkMatch(kind: .envrc, approach: .perVar)
        }
        if isLiveShellRcName(name) {
            return WalkMatch(kind: .shellRc, approach: .perVar)
        }
        if name == ".git-credentials" {
            return WalkMatch(
                kind: .toolCredential, approach: .wholeFile,
                catalogID: "git-credentials", displayName: "git credential store")
        }
        if name == ".netrc" {
            return WalkMatch(
                kind: .toolCredential, approach: .wholeFile,
                contentGate: .containsAny(["password"]),
                catalogID: "netrc", displayName: "netrc")
        }
        if name == ".npmrc" {
            return WalkMatch(
                kind: .toolCredential,
                approach: .filePreset(preset: "npm", pathEnvironmentVariable: "NPM_CONFIG_USERCONFIG"),
                contentGate: .npmAuth,
                catalogID: "npm", displayName: "npm config")
        }
        if name == ".gcx.yaml" {
            // gcx's repository config layer; `gcx login --config .gcx.yaml`
            // writes there, in plaintext when its keychain is off.
            return WalkMatch(
                kind: .toolCredential,
                approach: .envToken(variables: ["GRAFANA_TOKEN", "GRAFANA_CLOUD_TOKEN"]),
                contentGate: CredentialCatalog.grafanaConfigGate,
                catalogID: "gcx", displayName: "Grafana CLI (gcx) repository config")
        }
        if looksLikePrivateKeyName(name) {
            let sshName = name.hasPrefix("id_")
            return WalkMatch(
                kind: sshName ? .sshPrivateKey : .keyMaterial,
                approach: sshName ? .sshKey : .wholeFile,
                requirePrivateKeyContent: true
            )
        }
        return nil
    }

    /// `.env`, `.env.<environment>` and Docker Compose's `<name>.env`, minus
    /// their templates. Shared with setup's project walk so the two agree.
    static func isLiveDotenvName(_ name: String) -> Bool {
        let lowered = name.lowercased()
        let templateMarkers = ["example", "sample", "template", "dist"]
        if name == ".env" || name.hasPrefix(".env.") {
            return !templateMarkers.contains { lowered.hasSuffix("." + $0) }
        }
        guard name.hasSuffix(".env"), name.count > ".env".count else { return false }
        // `example.env`, `secrets.example.env`; `<name>.env.example` already
        // fails the suffix test.
        return !lowered.dropLast(".env".count).split(separator: ".")
            .contains { templateMarkers.contains(String($0)) }
    }

    static func isLiveShellRcName(_ name: String) -> Bool {
        [".zshrc", ".zshenv", ".zprofile", ".bashrc", ".bash_profile", ".profile"]
            .contains(name)
    }

    private static func looksLikePrivateKeyName(_ name: String) -> Bool {
        guard !name.hasSuffix(".pub") else { return false }
        if name.hasPrefix("id_") { return true }
        if name == "master.key" { return true }
        let lowered = name.lowercased()
        return lowered.hasSuffix(".pem")
            || lowered.hasSuffix(".key")
            || lowered.hasSuffix(".p12")
            || lowered.hasSuffix(".pfx")
            || lowered.hasSuffix(".jks")
            || lowered.hasSuffix(".keystore")
            || lowered.hasSuffix(".asc")
    }

    // MARK: - candidate admission (stat, content gates, dedupe)

    private enum MutableStore {
        case claude, gemini, bitcoin, electrum, gnupg

        init?(name: String, directory: String, home: String) {
            if directory.hasSuffix("/.electrum/wallets") {
                self = .electrum
            } else if name == "wallet.dat" {
                self = .bitcoin
            } else if name.hasSuffix(".key"), directory.hasSuffix("/private-keys-v1.d") {
                self = .gnupg
            } else if name == ".claude.json", directory == home {
                self = .claude
            } else if name == "settings.json", directory == home + "/.gemini" {
                self = .gemini
            } else {
                return nil
            }
        }
    }

    // Library is deliberately excluded from a home walk. Probe just Bitcoin
    // Core's default wallet and named wallet locations under its data directory.
    private static func probeMacBitcoinWallets(state: inout DiscoveryState) {
        let base = state.homeDirectory + "/Library/Application Support/Bitcoin"
        guard realpathString(base) == base else { return }
        recordMutableStore(.bitcoin, path: base + "/wallet.dat", state: &state)
        let wallets = base + "/wallets"
        guard realpathString(wallets) == wallets,
              let entries = try? FileManager.default.contentsOfDirectory(atPath: wallets) else { return }
        recordMutableStore(.bitcoin, path: wallets + "/wallet.dat", state: &state)
        for name in entries {
            let directory = wallets + "/" + name
            guard realpathString(directory) == directory else { continue }
            recordMutableStore(.bitcoin, path: directory + "/wallet.dat", state: &state)
        }
    }

    private static func recordMutableStore(_ store: MutableStore, path: String, state: inout DiscoveryState) {
        guard let canonical = realpathString(path),
              state.scanRoots.contains(where: { canonical.hasPrefix($0 == "/" ? "/" : $0 + "/") }) else { return }
        var info = stat()
        guard lstat(canonical, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid()
        else { return }
        state.reportOnlyIdentities.insert(FileIdentity(info))
        switch store {
        case .bitcoin:
            state.advisories.insert("Possible Bitcoin Core wallet left in place. Use backupwallet for a consistent copy.")
        case .electrum:
            state.advisories.insert("Electrum wallet file left in place. Use File → Save backup in Electrum.")
        case .gnupg:
            state.advisories.insert("GnuPG agent key files left in place. For exportable keys, see “Backing up a GnuPG key” in the everyday guide.")
        case .claude, .gemini:
            let client = store == .claude ? "Claude" : "Gemini"
            let limit = store == .claude ? FileSystemClaudeSettingsGate.maximumGlobalConfigBytes : maximumContentSniffBytes
            guard let data = try? boundedRead(path: canonical, maximumBytes: limit),
                  let config = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
                state.advisories.insert("\(client) MCP settings could not be checked. Review server environments in the client.")
                return
            }
            let projects = store == .claude ? config["projects"] as? [String: Any] : nil
            if hasMCPEnvironmentCredential(config) || projects?.values.contains(where: hasMCPEnvironmentCredential) == true {
                state.advisories.insert("\(client) rewrites its MCP settings. Review the credential-shaped "
                    + "server environment fields and use the server’s supported sign-in method where available.")
            }
        }
    }

    private static func hasMCPEnvironmentCredential(_ object: Any) -> Bool {
        guard let config = object as? [String: Any], let servers = config["mcpServers"] as? [String: Any]
        else { return false }
        return servers.values.contains {
            guard let server = $0 as? [String: Any], let env = server["env"] as? [String: Any] else { return false }
            return env.contains { name, value in value is String && SecretHeuristics.nameLooksSecretLike(name) }
        }
    }

    private static func admitCandidate(
        path: String,
        kind: SecretFileKind,
        catalogID: String?,
        displayName: String?,
        rootLabel: String,
        approach: CredentialDelivery,
        keychainFallback: Bool,
        contentGate: CredentialContentGate,
        requirePrivateKeyContent: Bool = false,
        toolRewritesFile: Bool = false,
        state: inout DiscoveryState
    ) {
        var info = stat()
        guard lstat(path, &info) == 0 else { return }

        var canonical = path
        if (info.st_mode & S_IFMT) == S_IFLNK {
            // Protect the destination once. Leave the symlink in place; it
            // will follow that destination when it is materialized again.
            state.symlinkPaths.insert(path)
            guard let resolved = realpathString(path) else {
                state.warnings.append(
                    "skipped \(display(path, state)): broken symlink")
                return
            }
            canonical = resolved
            guard lstat(canonical, &info) == 0 else { return }
        }

        guard (info.st_mode & S_IFMT) == S_IFREG else {
            state.warnings.append(
                "skipped \(display(path, state)): not a regular file")
            return
        }
        guard info.st_uid == getuid() else {
            state.warnings.append(
                "skipped \(display(path, state)): owned by another user")
            return
        }
        guard info.st_size > 0 else { return }

        canonical = resolvePath(canonical)
        if !["catalog", "ssh", "shell"].contains(rootLabel),
           !state.scanRoots.contains(where: { canonical.hasPrefix($0 == "/" ? "/" : $0 + "/") }) {
            state.warnings.append("skipped \(display(path, state)): symlink destination is outside the scan roots; scan its destination explicitly")
            return
        }
        if excludeCandidate(canonical, kind: kind, state: &state) { return }
        if canonical != path {
            let target = canonical as NSString
            if let store = MutableStore(name: target.lastPathComponent, directory: target.deletingLastPathComponent,
                                        home: state.homeDirectory) {
                recordMutableStore(store, path: canonical, state: &state)
                return
            }
        }
        let identity = FileIdentity(info)
        if state.reportOnlyIdentities.contains(identity) { return }
        if let index = state.indexByIdentity[identity] {
            // An rc path can be a symlink or hardlink to a file already found
            // as dotenv/catalog data. Preserve its startup role regardless of
            // which path was visited first.
            if kind == .shellRc, state.files[index].kind != .shellRc {
                state.files[index].kind = .shellRc
                if state.files[index].suggestedApproach != .perVar {
                    state.files[index].notes.removeAll {
                        $0 == "per-var cannot rewrite its secrets; whole-file fallback"
                            || $0 == "not parseable as an env file"
                    }
                    state.files[index].notes.append(shellStartupPreservationNote)
                }
            }
            // Only a distinct hardlink needs its own protection path.
            if state.files[index].canonicalPath != canonical,
               !state.files[index].aliasPaths.contains(canonical) {
                state.files[index].aliasPaths.append(canonical)
            }
            return
        }

        let byteSize = Int(info.st_size)
        var notes: [String] = []
        let effectiveKind = kind
        var effectiveApproach = approach

        // Content classification. Reading the bytes to classify is fine —
        // nothing is displayed or retained; only membership and routing are
        // decided here.
        let sniff: Data?
        if byteSize <= maximumContentSniffBytes {
            sniff = try? boundedRead(path: canonical, maximumBytes: maximumContentSniffBytes)
        } else {
            sniff = nil
            notes.append("content not inspected (over 1 MiB)")
        }

        if requirePrivateKeyContent {
            guard let data = sniff else {
                if byteSize <= maximumContentSniffBytes { return }
                // Over the sniff bound, only a true keystore extension is
                // admissible on name alone: a giant `.key` is a Keynote
                // presentation and a giant `known_hosts.bak` is not a key.
                let lowered = (canonical as NSString).lastPathComponent.lowercased()
                guard [".p12", ".pfx", ".jks", ".keystore"]
                    .contains(where: lowered.hasSuffix) else { return }
                notes.append("binary key store")
                appendFile(
                    canonicalPath: canonical, kind: effectiveKind,
                    catalogID: catalogID, displayName: displayName, info: info,
                    byteSize: byteSize, rootLabel: rootLabel,
                    approach: effectiveApproach, keychainFallback: keychainFallback,
                    toolRewritesFile: toolRewritesFile,
                    notes: notes, identity: identity, state: &state)
                return
            }
            switch classifyKeyContent(data, name: (canonical as NSString).lastPathComponent) {
            case .privateKey(let encrypted):
                if encrypted { notes.append("already passphrase-protected") }
            case .binaryKeyStore:
                notes.append("binary key store")
            case .certificateOnly, .notKeyMaterial:
                return
            }
            if effectiveApproach == .sshKey {
                // csecd registers an SSH batch only if every key parses, so a
                // key it would refuse never rides the `ssh` approach.
                let verdict = SSHKeyFileVerdict.inspect(data)
                switch verdict {
                case .importable:
                    break
                case .passphraseProtected:
                    state.warnings.append(
                        "left \(display(canonical, state)) alone: a passphrase-protected SSH key "
                            + "is not plaintext, and csec imports only unencrypted keys")
                    return
                case .securityKey:
                    return
                case .obsolete, .unsupportedType, .unreadable:
                    effectiveApproach = .wholeFile
                    notes.append(verdict.label + "; csec's SSH agent cannot use it, so whole-file")
                }
            }
        }

        switch effectiveKind {
        case .dotenv, .envrc, .shellRc:
            guard let data = sniff else {
                notes.append("could not read for classification")
                return
            }
            switch classifyEnvContent(data) {
            case .perVar:
                effectiveApproach = .perVar
            case .wholeFileFallback:
                // Shell startup cannot load a whole-file sidecar. Keep the
                // candidate visible for an explicit choice, but the planner
                // defaults it to skip rather than removing startup config.
                effectiveApproach = .wholeFile
                notes.append(effectiveKind == .shellRc ? shellStartupPreservationNote
                    : "per-var cannot rewrite its secrets; whole-file fallback")
            case .secretFree:
                if state.suppressedSecretFreeIdentities.insert(identity).inserted {
                    state.suppressedSecretFree += 1
                }
                return
            case .unparseable:
                effectiveApproach = .wholeFile
                notes.append(effectiveKind == .shellRc ? shellStartupPreservationNote
                    : "not parseable as an env file")
            }
        case .sshPrivateKey, .keyMaterial, .toolCredential, .other:
            if let data = sniff, !evaluateGate(contentGate, data: data) { return }
            if sniff == nil, contentGate != .always {
                notes.append("assumed credential-bearing (content gate skipped)")
            }
        }
        if contentGate == .ethereumKeystore {
            notes.append("password-encrypted key store; csec adds access gating")
        }

        if keychainFallback {
            notes.append("tool normally keeps this in the Keychain; "
                + "a plaintext fallback file is present")
        }
        if toolRewritesFile {
            notes.append(approach == .flyToken ? flyTokenNote : toolRewritesFileNote)
        }
        if permissionsAreLoose(info) {
            notes.append("group/other readable")
        }
        if byteSize > NativeBlobStore.maximumBlobBytes {
            notes.append("exceeds the 4 MiB protect bound")
        }

        appendFile(
            canonicalPath: canonical, kind: effectiveKind,
            catalogID: catalogID, displayName: displayName, info: info,
            byteSize: byteSize, rootLabel: rootLabel, approach: effectiveApproach,
            keychainFallback: keychainFallback, toolRewritesFile: toolRewritesFile,
            notes: notes, identity: identity, state: &state)
    }

    private static func appendFile(
        canonicalPath: String,
        kind: SecretFileKind,
        catalogID: String?,
        displayName: String?,
        info: stat,
        byteSize: Int,
        rootLabel: String,
        approach: CredentialDelivery,
        keychainFallback: Bool,
        toolRewritesFile: Bool,
        notes: [String],
        identity: FileIdentity,
        state: inout DiscoveryState
    ) {
        state.indexByIdentity[identity] = state.files.count
        state.files.append(DiscoveredSecretFile(
            canonicalPath: canonicalPath,
            aliasPaths: [],
            kind: kind,
            catalogID: catalogID,
            displayName: displayName,
            mode: UInt16(info.st_mode & 0o7777),
            byteSize: byteSize,
            sizeClass: SecretFileSizeClass(byteSize: byteSize),
            rootLabel: rootLabel,
            suggestedApproach: approach,
            keychainFallback: keychainFallback,
            toolRewritesFile: toolRewritesFile,
            notes: notes
        ))
    }

    // MARK: - content classification

    enum EnvContentClass {
        case perVar
        case wholeFileFallback
        case secretFree
        case unparseable
    }

    /// The deterministic per-var / whole-file / no-op branch from the plan:
    /// ≥1 importable secret-like candidate → per-var; else ≥1 secret-like
    /// (necessarily unsupported) → whole-file candidate; else nothing to
    /// protect. Startup files are preserved by the bulk planner/apply guard.
    static func classifyEnvContent(_ data: Data) -> EnvContentClass {
        guard let document = try? EnvFileDocument(data: data) else { return .unparseable }
        let candidates = document.candidates
        if candidates.contains(where: { $0.kind == .importable && $0.secretLike }) {
            return .perVar
        }
        if candidates.contains(where: { $0.kind == .unsupported && $0.secretLike }) {
            return .wholeFileFallback
        }
        if !document.referenceNamesToPrefix.isEmpty { return .perVar }
        return .secretFree
    }

    enum KeyContentClass {
        case privateKey(encrypted: Bool)
        case binaryKeyStore
        case certificateOnly
        case notKeyMaterial
    }

    static func classifyKeyContent(_ data: Data, name: String) -> KeyContentClass {
        let prefix = String(decoding: data.prefix(4096), as: UTF8.self)
        if prefix.contains("PRIVATE KEY-----") || prefix.contains("PRIVATE KEY BLOCK-----") {
            // An OpenSSH-format key names its cipher inside the base64 body,
            // not in the PEM armour.
            let encrypted = prefix.contains("ENCRYPTED")
                || (prefix.contains("BEGIN OPENSSH PRIVATE KEY")
                    && SSHKeyFileVerdict.inspect(data) == .passphraseProtected)
            return .privateKey(encrypted: encrypted)
        }
        if prefix.contains("-----BEGIN CERTIFICATE-----")
            || prefix.contains("-----BEGIN PUBLIC KEY-----") {
            return .certificateOnly
        }
        let lowered = name.lowercased()
        let binaryExtensions = [".p12", ".pfx", ".jks", ".keystore"]
        if binaryExtensions.contains(where: lowered.hasSuffix) {
            return .binaryKeyStore
        }
        // A `.key` without a PEM header can still be a raw key string —
        // Rails `master.key` is a bare hex line. Admit it when the first line
        // itself looks like secret material.
        if lowered.hasSuffix(".key") {
            let firstLine = String(
                decoding: data.prefix(while: { $0 != 0x0A }), as: UTF8.self
            ).trimmingCharacters(in: .whitespaces)
            if !firstLine.isEmpty, SecretHeuristics.valueLooksSecretLike(firstLine) {
                return .privateKey(encrypted: false)
            }
        }
        // Anything else without recognizable key content is a look-alike
        // (a TLS chain, a lockfile, cover art named `folder.key`).
        return .notKeyMaterial
    }

    static func evaluateGate(_ gate: CredentialContentGate, data: Data) -> Bool {
        switch gate {
        case .always:
            return true
        case .nonEmptyFirstLine:
            let firstLine = data.prefix(while: { $0 != 0x0A })
            return firstLine.contains { $0 != 0x20 && $0 != 0x09 && $0 != 0x0D }
        case .containsAny(let needles):
            let haystack = String(decoding: data, as: UTF8.self).lowercased()
            return needles.contains { haystack.contains($0.lowercased()) }
        case .populatedDockerAuths:
            guard let object = try? JSONSerialization.jsonObject(with: data),
                  let root = object as? [String: Any],
                  let auths = root["auths"] as? [String: Any], !auths.isEmpty else {
                return false
            }
            return auths.values.contains { entry in
                guard let fields = entry as? [String: Any] else { return false }
                let auth = fields["auth"] as? String ?? ""
                let identity = fields["identitytoken"] as? String ?? ""
                return !auth.isEmpty || !identity.isEmpty
            }
        case .npmAuth:
            return NpmUserConfig.containsLiteralAuth(data)
        case .propertiesWithSecretKey:
            let text = String(decoding: data, as: UTF8.self)
            for line in text.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                guard !trimmed.hasPrefix("#"), !trimmed.hasPrefix("!"),
                      let equals = trimmed.firstIndex(of: "=") else { continue }
                let key = trimmed[..<equals].lowercased()
                let value = trimmed[trimmed.index(after: equals)...]
                    .trimmingCharacters(in: .whitespaces)
                guard !value.isEmpty else { continue }
                if ["password", "passphrase", "token", "secret", "apikey", "api_key"]
                    .contains(where: key.contains) {
                    return true
                }
            }
            return false
        case .literalCredentialAssignments:
            return containsLiteralCredential(data)
        case .solanaKeypair:
            guard let numbers = (try? JSONSerialization.jsonObject(with: data)) as? [NSNumber],
                  numbers.count == 64 else { return false }
            return numbers.allSatisfy {
                CFGetTypeID($0) != CFBooleanGetTypeID()
                    && $0.doubleValue >= 0 && $0.doubleValue <= 255
                    && $0.doubleValue.rounded() == $0.doubleValue
            }
        case .ethereumKeystore:
            guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
                  let crypto = (root["crypto"] ?? root["Crypto"]) as? [String: Any],
                  let ciphertext = crypto["ciphertext"] as? String,
                  !ciphertext.isEmpty,
                  let cipher = crypto["cipher"] as? String, !cipher.isEmpty else { return false }
            if let version = root["version"] as? NSNumber,
               CFGetTypeID(version) != CFBooleanGetTypeID(), version.doubleValue == 3 { return true }
            return root["version"] as? String == "1"
        case .literalYAMLValues(let keys, let ignoredPrefixes):
            let wanted = Set(keys.map { $0.lowercased() })
            let text = String(decoding: data, as: UTF8.self)
            for line in text.split(whereSeparator: \.isNewline) {
                var trimmed = line.trimmingCharacters(in: .whitespaces)
                while trimmed.hasPrefix("- ") {
                    trimmed = String(trimmed.dropFirst(2)).trimmingCharacters(in: .whitespaces)
                }
                guard !trimmed.hasPrefix("#"), let colon = trimmed.firstIndex(of: ":") else {
                    continue
                }
                var key = trimmed[..<colon].trimmingCharacters(in: .whitespaces)
                if key.count >= 2, let first = key.first, first == "\"" || first == "'",
                   key.last == first {
                    key = String(key.dropFirst().dropLast())
                }
                guard wanted.contains(key.lowercased()) else { continue }
                // `key:value` with no space is a plain scalar, not a mapping.
                let rest = trimmed[trimmed.index(after: colon)...]
                guard rest.isEmpty || rest.first == " " || rest.first == "\t" else { continue }
                var value = rest.trimmingCharacters(in: .whitespaces)
                if let first = value.first, first == "\"" || first == "'" {
                    if let close = value.dropFirst().firstIndex(of: first) {
                        value = String(value[value.index(after: value.startIndex)..<close])
                    }
                } else if let comment = value.range(of: " #") {
                    value = value[..<comment.lowerBound].trimmingCharacters(in: .whitespaces)
                }
                // An empty value opens a nested mapping or is unset.
                guard !value.isEmpty, value != "~", value.lowercased() != "null" else { continue }
                if ignoredPrefixes.contains(where: { value.hasPrefix($0) }) { continue }
                if value.hasPrefix("${"), value.hasSuffix("}"),
                   SecretHeuristics.isEnvironmentName(String(value.dropFirst(2).dropLast())) {
                    continue
                }
                return true
            }
            return false
        }
    }

    private static func containsLiteralCredential(_ data: Data) -> Bool {
        func literal(_ key: String, _ value: String) -> Bool {
            let normalized = key.replacingOccurrences(of: "-", with: "_").lowercased()
            guard !value.isEmpty else { return false }
            if let ref = try? SecretRef(value), EnvFileDocument.referenceSchemes.contains(ref.scheme) { return false }
            if value.hasPrefix("${"), value.hasSuffix("}"),
               SecretHeuristics.isEnvironmentName(String(value.dropFirst(2).dropLast())) { return false }
            if normalized.hasSuffix("_env"), SecretHeuristics.isEnvironmentName(value) { return false }
            return normalized == "key" || normalized.contains("apikey")
                || normalized.contains("passphrase")
                || SecretHeuristics.nameLooksSecretLike(key)
        }
        func jsonContains(_ object: Any) -> Bool {
            if let fields = object as? [String: Any] {
                return fields.contains { key, value in
                    if let value = value as? String { return literal(key, value) }
                    return jsonContains(value)
                }
            }
            if let array = object as? [Any] { return array.contains(where: jsonContains) }
            return false
        }
        if let object = try? JSONSerialization.jsonObject(with: data) { return jsonContains(object) }
        // These catalog files use simple single-line YAML/TOML scalars. Reuse
        // the env parser's quoting/comment rules instead of executing a shell
        // or guessing at interpolation. Unsupported shapes stay out of this gate.
        for line in String(decoding: data, as: UTF8.self).split(separator: "\n") {
            let text = line.trimmingCharacters(in: .whitespaces)
            guard !text.hasPrefix("#"), !text.hasPrefix(";"),
                  let separator = text.firstIndex(where: { $0 == ":" || $0 == "=" }) else { continue }
            let key = text[..<separator].trimmingCharacters(in: .whitespaces)
                .trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
            let rhs = text[text.index(after: separator)...]
            guard let document = try? EnvFileDocument(data: Data("VALUE=\(rhs)\n".utf8)),
                  let value = document.assignments.first?.value else { continue }
            if literal(key, value) { return true }
        }
        return false
    }

    // MARK: - path helpers

    static func expandHome(_ template: String, home: String) -> String {
        guard template.hasPrefix("~/") else { return template }
        let trimmedHome = home.hasSuffix("/") ? String(home.dropLast()) : home
        return trimmedHome + String(template.dropFirst(1))
    }

    /// Expands at most one `*` glob per path component, matching the
    /// seed catalog's needs (`legacy_credentials/*/adc.json`, `*.pem`).
    static func expandGlob(_ path: String) -> [String] {
        guard path.contains("*") else { return [path] }
        let components = path.split(separator: "/", omittingEmptySubsequences: true)
            .map(String.init)
        guard let globIndex = components.firstIndex(where: { $0.contains("*") }) else {
            return [path]
        }
        let parent = "/" + components[..<globIndex].joined(separator: "/")
        let pattern = components[globIndex]
        let remainder = components[(globIndex + 1)...].joined(separator: "/")
        let entries = ((try? FileManager.default.contentsOfDirectory(atPath: parent)) ?? [])
            .sorted()
        var results: [String] = []
        for entry in entries where matchesSingleStar(entry, pattern: pattern) {
            let expanded = parent + "/" + entry + (remainder.isEmpty ? "" : "/" + remainder)
            results.append(contentsOf: expandGlob(expanded))
        }
        return results
    }

    static func matchesSingleStar(_ name: String, pattern: String) -> Bool {
        guard let star = pattern.firstIndex(of: "*") else { return name == pattern }
        let prefix = pattern[..<star]
        let suffix = pattern[pattern.index(after: star)...]
        return name.hasPrefix(prefix) && name.hasSuffix(suffix)
            && name.count >= prefix.count + suffix.count
    }

    private static func resolvePath(_ path: String) -> String {
        realpathString(path) ?? path
    }

    private static func realpathString(_ path: String) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX) + 1)
        guard realpath(path, &buffer) != nil else { return nil }
        return String(cString: buffer)
    }

    private static func directoryIdentity(_ path: String) -> FileIdentity? {
        var info = stat()
        guard stat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR else { return nil }
        return FileIdentity(info)
    }

    private static func permissionsAreLoose(_ info: stat) -> Bool {
        (info.st_mode & 0o044) != 0
    }

    private static func displayPath(_ path: String, home: String) -> String {
        let trimmedHome = home.hasSuffix("/") ? String(home.dropLast()) : home
        if path == trimmedHome { return "~" }
        if path.hasPrefix(trimmedHome + "/") {
            return "~" + path.dropFirst(trimmedHome.count)
        }
        return path
    }

    private static func display(_ path: String, _ state: DiscoveryState) -> String {
        displayPath(path, home: state.homeDirectory)
    }

    /// Bounded O_NOFOLLOW read for classification. Ownership was already
    /// checked on the lstat; the fstat re-check keeps the read bound to the
    /// same inode the stat decision was made on.
    private static func boundedRead(path: String, maximumBytes: Int) throws -> Data {
        let fd = path.withCString { open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK) }
        guard fd >= 0 else { throw SetupOnboardingError.unsafeRegularFile(path) }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(),
              info.st_size >= 0,
              info.st_size <= maximumBytes else {
            throw SetupOnboardingError.unsafeRegularFile(path)
        }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        var offset = 0
        let totalBytes = bytes.count
        while offset < totalBytes {
            let count = bytes.withUnsafeMutableBytes { raw in
                read(fd, raw.baseAddress!.advanced(by: offset), totalBytes - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { throw SetupOnboardingError.unsafeRegularFile(path) }
            offset += count
        }
        return Data(bytes)
    }
}
