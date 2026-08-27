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
            return "a file already exists at \(path); refusing to replace it with a protected link"
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
    private var installed: [(path: String, tmpfsPath: String)] = []

    public init(projectDirectory: String) throws {
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
        guard symlinkat(link.tmpfsPath, parentFD, leaf) == 0 else {
            if errno == EEXIST { throw ProtectedSymlinkError.targetOccupied(link.projectRelativePath) }
            throw ProtectedSymlinkError.linkCreationFailed(link.projectRelativePath)
        }
        installed.append((path: link.projectRelativePath, tmpfsPath: link.tmpfsPath))
    }

    /// Remove every link this instance created, but only where the name is still
    /// the exact symlink it installed — never a real file that replaced it.
    public func removeAll() {
        for entry in installed.reversed() {
            guard let parentFD = try? openParent(of: entry.path) else { continue }
            defer { close(parentFD) }
            let leaf = leafComponent(of: entry.path)
            var buffer = [CChar](repeating: 0, count: Int(PATH_MAX))
            let count = readlinkat(parentFD, leaf, &buffer, buffer.count - 1)
            if count > 0 {
                buffer[Int(count)] = 0
                if String(cString: buffer) == entry.tmpfsPath {
                    _ = unlinkat(parentFD, leaf, 0)
                }
            }
        }
        installed.removeAll()
    }

    /// Open the directory that will hold the link's leaf, walking each parent
    /// component descriptor-relative with no symlink following.
    private func openParent(of projectRelativePath: String) throws -> Int32 {
        let components = projectRelativePath.split(separator: "/").map(String.init)
        guard !components.isEmpty else {
            throw ProtectedSymlinkError.linkCreationFailed(projectRelativePath)
        }
        var currentFD = dup(directoryFD)
        guard currentFD >= 0 else {
            throw ProtectedSymlinkError.linkCreationFailed(projectRelativePath)
        }
        for component in components.dropLast() {
            let nextFD = openat(currentFD, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            close(currentFD)
            guard nextFD >= 0 else {
                throw ProtectedSymlinkError.linkCreationFailed(projectRelativePath)
            }
            currentFD = nextFD
        }
        return currentFD
    }

    private func leafComponent(of projectRelativePath: String) -> String {
        String(projectRelativePath.split(separator: "/").last ?? "")
    }
}
