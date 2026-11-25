import Foundation
import CSECRootProtocol
#if canImport(Darwin)
import Darwin
#endif

public enum HomeTokenFileRestoreError: Error, LocalizedError, Equatable {
    case noSidecar(String)
    case unusableSidecar(path: String, reason: String)
    case outsideHome(String)
    case notHomeRooted(path: String, projectRoot: String)
    case tooManyFiles(limit: Int)

    public var errorDescription: String? {
        switch self {
        case let .noSidecar(path):
            return "--with-file \(path): there is no protected copy (\(path)\(ProtectedFileSidecar.suffix))"
        case let .unusableSidecar(path, reason):
            return "--with-file \(path): its sidecar \(reason)"
        case let .outsideHome(path):
            return "--with-file \(path): only files protected under your home directory can be named; "
                + "run csec exec from the file's project instead"
        case let .notHomeRooted(path, projectRoot):
            return "--with-file \(path): it was protected as part of the project at \(projectRoot); "
                + "run csec exec from there instead"
        case let .tooManyFiles(limit):
            return "this launch would restore more than \(limit) protected files, the per-launch maximum"
        }
    }
}

/// Which protected home token files a `csec exec` launch restores at their home
/// paths, whatever directory it runs from.
///
/// The working-directory sidecar scan only reaches files below it, and a home
/// store records home-relative paths, so `~/.vault-token` would otherwise be
/// restored only when `csec exec` runs from `~` itself. Restoring every home
/// token on every launch would hand each command every tool's token; instead
/// the command's own name selects its catalog entries (`vault` gets the Vault
/// token, nothing else), and `--with-file` names a file for a tool started
/// through a wrapper or library. Every file still rides the one launch review,
/// which lists each reference.
///
/// Filesystem-only and value-free, like the sidecar scan: it reads sidecars as
/// untrusted metadata and decides nothing about release, which csecd does after
/// the review, binding each value to the path its blob was protected at.
public enum HomeTokenFileRestore {
    public struct Plan: Equatable, Sendable {
        /// Working-directory discoveries, less any that name a home file below.
        public let projectFiles: [DiscoveredProtectedFile]
        /// Home files, with home-relative target and sidecar paths.
        public let homeFiles: [DiscoveredProtectedFile]
        /// Catalog sidecars that exist but cannot be used, home-relative.
        public let issues: [ProtectedSidecarIssue]
    }

    /// Catalog entries whose ordinary runs read their file, for a command line.
    /// Matching is by `argv[0]`'s base name only: an interpreter or wrapper
    /// (`python -m …`, `npx …`) names no tool, and `--with-file` covers it.
    public static func entries(
        forCommand command: String,
        catalog: [KnownCredentialFile] = CredentialCatalog.entries
    ) -> [KnownCredentialFile] {
        let name = (command as NSString).lastPathComponent
        guard !name.isEmpty else { return [] }
        return catalog.filter { $0.commands.contains(name) }
    }

    /// - Parameters:
    ///   - homeDirectory: canonical home, in the namespace bulk protect used.
    ///   - currentDirectory: canonical working directory the scan ran from.
    ///   - withFiles: `--with-file` paths, absolute, a target or its sidecar.
    ///   - projectRootBelowHome: the protect root of a canonical path when it is
    ///     a project below home (a `.git` ancestor), nil when it is home itself,
    ///     whose blob records the home-relative path a home link is bound to.
    public static func plan(
        command: String,
        withFiles: [String],
        homeDirectory: String,
        currentDirectory: String,
        environment: [String: String],
        projectFiles: [DiscoveredProtectedFile],
        catalog: [KnownCredentialFile] = CredentialCatalog.entries,
        projectRootBelowHome: (String) -> String?
    ) throws -> Plan {
        let home = trimmed(homeDirectory)
        let cwd = trimmed(currentDirectory)
        var homeFiles: [DiscoveredProtectedFile] = []
        var issues: [ProtectedSidecarIssue] = []
        var seen = Set<String>()

        func admit(homeRelative: String, sidecar: ProtectedFileSidecar) {
            guard seen.insert(homeRelative).inserted else { return }
            homeFiles.append(DiscoveredProtectedFile(
                targetRelativePath: homeRelative,
                sidecarRelativePath: homeRelative + ProtectedFileSidecar.suffix,
                reference: sidecar.reference
            ))
        }

        for entry in entries(forCommand: command, catalog: catalog) {
            for path in candidatePaths(entry, home: home, environment: environment) {
                guard let canonical = canonicalTarget(path),
                      let homeRelative = relative(canonical, to: home),
                      projectRootBelowHome(canonical) == nil,
                      let result = ProtectedSidecarScanner.sidecar(
                          atPath: canonical + ProtectedFileSidecar.suffix) else { continue }
                switch result {
                case let .success(sidecar):
                    admit(homeRelative: homeRelative, sidecar: sidecar)
                case let .failure(failure):
                    issues.append(ProtectedSidecarIssue(
                        sidecarRelativePath: "~/" + homeRelative + ProtectedFileSidecar.suffix,
                        reason: failure.reason
                    ))
                }
            }
        }

        let projectTargets = Set(projectFiles.map { cwd + "/" + $0.targetRelativePath })
        for given in withFiles {
            let target = given.hasSuffix(ProtectedFileSidecar.suffix)
                && given.utf8.count > ProtectedFileSidecar.suffix.utf8.count
                ? String(given.dropLast(ProtectedFileSidecar.suffix.count)) : given
            let canonical = canonicalTarget(target) ?? target
            // The working-directory scan already restores a file below it.
            if projectTargets.contains(canonical) { continue }
            guard let homeRelative = relative(canonical, to: home) else {
                throw HomeTokenFileRestoreError.outsideHome(target)
            }
            if let root = projectRootBelowHome(canonical) {
                throw HomeTokenFileRestoreError.notHomeRooted(path: target, projectRoot: root)
            }
            switch ProtectedSidecarScanner.sidecar(atPath: canonical + ProtectedFileSidecar.suffix) {
            case nil:
                throw HomeTokenFileRestoreError.noSidecar(target)
            case let .failure(failure)?:
                throw HomeTokenFileRestoreError.unusableSidecar(path: target, reason: failure.reason)
            case let .success(sidecar)?:
                admit(homeRelative: homeRelative, sidecar: sidecar)
            }
        }

        // A home file the working-directory scan also found (run from `~`, or
        // from `~/.cargo`) is restored once, home-rooted: that is the path its
        // blob records, so the project-relative copy would fail csecd's check.
        let homeTargets = Set(homeFiles.map { home + "/" + $0.targetRelativePath })
        let remaining = projectFiles.filter {
            !homeTargets.contains(cwd + "/" + $0.targetRelativePath)
        }
        guard remaining.count + homeFiles.count <= ProtectedLaunchPlan.maximumFiles else {
            throw HomeTokenFileRestoreError.tooManyFiles(limit: ProtectedLaunchPlan.maximumFiles)
        }
        return Plan(
            projectFiles: remaining,
            homeFiles: homeFiles.sorted { $0.targetRelativePath < $1.targetRelativePath },
            issues: issues
        )
    }

    /// The catalog's literal locations for an entry, environment overrides first,
    /// as bulk protect probes them. Glob templates name no single file to
    /// restore and are skipped.
    static func candidatePaths(
        _ entry: KnownCredentialFile,
        home: String,
        environment: [String: String]
    ) -> [String] {
        var templates: [String] = []
        for override in entry.environmentOverrides {
            guard let value = environment[override.variable],
                  !value.isEmpty, !value.utf8.contains(0) else { continue }
            templates.append(override.template.replacingOccurrences(of: "$VALUE", with: value))
        }
        templates.append(contentsOf: entry.pathTemplates)
        var seen = Set<String>()
        return templates
            .map { SecretFileDiscoveryEngine.expandHome($0, home: home) }
            .filter { $0.hasPrefix("/") && !$0.contains("*") && seen.insert($0).inserted }
    }

    /// The target's canonical path: its parent through realpath(3), its leaf
    /// as named, since the leaf is usually absent (only the sidecar remains) or
    /// a dangling link from an interrupted launch.
    public static func canonicalTarget(_ path: String) -> String? {
        let parent = (path as NSString).deletingLastPathComponent
        let leaf = (path as NSString).lastPathComponent
        guard !leaf.isEmpty, leaf != ".", leaf != "..",
              let resolved = parent.withCString({ realpath($0, nil) }) else { return nil }
        defer { free(resolved) }
        let directory = String(cString: resolved)
        return (directory == "/" ? "" : directory) + "/" + leaf
    }

    private static func relative(_ path: String, to home: String) -> String? {
        guard home.hasPrefix("/"), path.hasPrefix(home + "/") else { return nil }
        let relative = String(path.dropFirst(home.count + 1))
        return ProtectedLaunchPlan.validProjectRelativePath(relative) ? relative : nil
    }

    private static func trimmed(_ path: String) -> String {
        path.count > 1 && path.hasSuffix("/") ? String(path.dropLast()) : path
    }
}
