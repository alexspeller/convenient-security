import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum ProtectedSymlinkError: Error, LocalizedError, Equatable {
    case projectDirectoryUnavailable
    case targetOccupied(String)
    case linkCreationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .projectDirectoryUnavailable:
            return "the project directory could not be opened for materialization"
        case let .targetOccupied(path):
            // The usual occupant is plaintext a tool wrote back beside its
            // sidecar (a save by rename during a launch, or a fresh login
            // outside one), so say what to do about it, not just that it blocks.
            return "a file already exists at \(path); refusing to replace it with a protected link. "
                + "If a tool wrote it back it may hold the secret in plaintext: check it, then "
                + "run `csec protect` on it to store it again, or move it aside"
        case let .linkCreationFailed(path):
            return "the protected link for \(path) could not be created"
        }
    }
}

/// Launcher-side installer for the symlinks that surface sidecar-materialized
/// files at their original project paths.
///
/// This runs entirely at ordinary user privilege — `csec-rootd` never writes
/// outside its own mount, so surfacing the file at a caller-chosen project path
/// is the launcher's job, not the root helper's. Every link is created
/// descriptor-relative to the project root with no symlink following, and the
/// installer refuses to clobber an existing name (a same-uid attacker can still
/// race the link afterwards — that is an accepted integrity limitation, not a
/// confidentiality one, since the tmpfs target stays `root:<gid>`). It records
/// exactly what it created so teardown removes only its own links, never a real
/// file that later took the same name.
public final class ProtectedSymlinkMaterialization {
    public struct Link: Equatable, Sendable {
        /// Where the file must appear for the tool, relative to the project root.
        public let projectRelativePath: String
        /// The absolute tmpfs path the link points at (`<mount>/<nonce>/<rel>`).
        public let tmpfsPath: String

        public init(projectRelativePath: String, tmpfsPath: String) {
            self.projectRelativePath = projectRelativePath
            self.tmpfsPath = tmpfsPath
        }
    }

    private let directoryFD: Int32
    /// Absolute tmpfs mount root (`<mount>`). A blocking name is only ever
    /// reclaimed when it is a dangling symlink pointing inside this directory, so
    /// nothing outside csec's own mount can be mistaken for a stale link.
    private let mountRoot: String
    private var installed: [(path: String, tmpfsPath: String)] = []
    /// Prepended to a relative path wherever one is shown to the user, so a
    /// home-rooted session's paths read `~/.vault-token`.
    public let displayPrefix: String

    public init(projectDirectory: String, mountRoot: String, displayPrefix: String = "") throws {
        self.mountRoot = mountRoot
        self.displayPrefix = displayPrefix
        directoryFD = projectDirectory.withCString {
            open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard directoryFD >= 0 else { throw ProtectedSymlinkError.projectDirectoryUnavailable }
    }

    deinit {
        removeAll()
        close(directoryFD)
    }

    /// Install every link, undoing any it already created if one fails, so a
    /// partially materialized project never launches.
    public func install(_ links: [Link]) throws {
        do {
            for link in links { try installOne(link) }
        } catch {
            removeAll()
            throw error
        }
    }

    private func installOne(_ link: Link) throws {
        let parentFD = try openParent(of: link.projectRelativePath)
        defer { close(parentFD) }
        let leaf = leafComponent(of: link.projectRelativePath)
        if symlinkat(link.tmpfsPath, parentFD, leaf) != 0 {
            let firstErrno = errno
            guard firstErrno == EEXIST else {
                throw ProtectedSymlinkError.linkCreationFailed(displayPrefix + link.projectRelativePath)
            }
            // A hard-killed prior launch skips teardown (it exits without running
            // `removeAll`), so a dangling protected link can survive and block a
            // fresh launch at the same path. Reclaim it — but only when it is
            // provably a dead csec link — then retry once.
            guard reclaimStaleLink(parentFD: parentFD, leaf: leaf) else {
                throw ProtectedSymlinkError.targetOccupied(displayPrefix + link.projectRelativePath)
            }
            guard symlinkat(link.tmpfsPath, parentFD, leaf) == 0 else {
                throw ProtectedSymlinkError.linkCreationFailed(displayPrefix + link.projectRelativePath)
            }
        }
        installed.append((path: link.projectRelativePath, tmpfsPath: link.tmpfsPath))
    }

    /// Decide whether the leaf currently occupying a target is a *stale* protected
    /// link that may be reclaimed, and if so, remove it. All three conditions must
    /// hold, so nothing else is ever touched:
    ///   1. it is a symlink — `readlinkat` succeeds (it returns `EINVAL` on a real
    ///      file or directory), so a genuine file that took the name is never
    ///      removed;
    ///   2. its target points inside our own tmpfs mount — a user's symlink to any
    ///      other location is left untouched; and
    ///   3. it is dangling — following it fails with `ENOENT`, so a *live* link
    ///      belonging to a concurrently running launch (whose session still exists)
    ///      is never removed. A fresh launch always uses a new nonce, so a dangling
    ///      old-nonce link can never come back to life.
    /// Returns true only when it unlinked such a link.
    private func reclaimStaleLink(parentFD: Int32, leaf: String) -> Bool {
        // An empty or root mount root would make the prefix test match anything;
        // require a real absolute path before trusting the ownership check.
        guard mountRoot.hasPrefix("/"), mountRoot.utf8.count > 1 else { return false }

        var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
        let count = readlinkat(parentFD, leaf, &buffer, buffer.count - 1)
        guard count > 0, count < Int(PATH_MAX) - 1 else { return false }
        buffer[Int(count)] = 0
        let target = String(cString: buffer)
        guard target == mountRoot || target.hasPrefix(mountRoot + "/") else { return false }

        // Follow the link: a live target resolves (leave it), a dangling one is
        // `ENOENT` (reclaim it). Any other error is treated as "do not touch".
        guard faccessat(parentFD, leaf, F_OK, 0) != 0, errno == ENOENT else { return false }
        return unlinkat(parentFD, leaf, 0) == 0
    }

    /// Remove every link this instance created, but only where the name is still
    /// the exact symlink it installed — never a real file that replaced it.
    ///
    /// Returns the project-relative paths where something other than that link
    /// now sits. The tmpfs file is read-only to the child, so a tool that saves
    /// its file does so by writing a new one and renaming it over the path, which
    /// replaces the link with an ordinary file that may hold the secret in
    /// plaintext. The caller warns about each, since teardown deliberately leaves
    /// them alone. A name that is simply gone (the tool deleted it) holds nothing
    /// and is not reported.
    @discardableResult
    public func removeAll() -> [String] {
        var replaced: [String] = []
        for entry in installed.reversed() {
            guard let parentFD = try? openParent(of: entry.path) else { continue }
            defer { close(parentFD) }
            let leaf = leafComponent(of: entry.path)
            var info = stat()
            guard fstatat(parentFD, leaf, &info, AT_SYMLINK_NOFOLLOW) == 0 else { continue }
            if info.st_mode & S_IFMT == S_IFLNK {
                var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
                let count = readlinkat(parentFD, leaf, &buffer, buffer.count - 1)
                if count > 0 {
                    buffer[Int(count)] = 0
                    if String(cString: buffer) == entry.tmpfsPath {
                        _ = unlinkat(parentFD, leaf, 0)
                        continue
                    }
                }
            }
            replaced.append(entry.path)
        }
        installed.removeAll()
        return replaced.reversed()
    }

    /// Open the directory that will hold the link's leaf, walking each parent
    /// component descriptor-relative with no symlink following.
    private func openParent(of projectRelativePath: String) throws -> Int32 {
        let components = projectRelativePath.split(separator: "/").map(String.init)
        guard !components.isEmpty else {
            throw ProtectedSymlinkError.linkCreationFailed(displayPrefix + projectRelativePath)
        }
        var currentFD = dup(directoryFD)
        guard currentFD >= 0 else {
            throw ProtectedSymlinkError.linkCreationFailed(displayPrefix + projectRelativePath)
        }
        for component in components.dropLast() {
            let nextFD = openat(currentFD, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            close(currentFD)
            guard nextFD >= 0 else {
                throw ProtectedSymlinkError.linkCreationFailed(displayPrefix + projectRelativePath)
            }
            currentFD = nextFD
        }
        return currentFD
    }

    private func leafComponent(of projectRelativePath: String) -> String {
        String(projectRelativePath.split(separator: "/").last ?? "")
    }
}
