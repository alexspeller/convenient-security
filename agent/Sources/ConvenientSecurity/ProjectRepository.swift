import Darwin
import Foundation

/// The git repository a Claude Code session's directory belongs to, which a
/// project pairing is keyed on: one approval covers the repository's main
/// checkout, every linked worktree and any subdirectory, the way a person
/// thinks of "this project".
///
/// From the directory up to the nearest `.git`, on one file system (git's own
/// discovery stops at a file-system boundary too):
/// - a `.git` directory is the repository's own git directory;
/// - a `.git` file is followed only when it is a linked worktree's: its
///   `gitdir:` names `<common>/worktrees/<id>`, that directory's `commondir`
///   names `<common>`, and its `gitdir` file names this checkout's `.git`
///   back. A downloaded archive can carry any `.git` file, so a pointer the
///   repository did not write, and cannot link back, borrows nothing
///   (Claude Code checks its project identity the same way).
/// The repository's identity is its shared git directory, so every worktree
/// resolves to the same one, and a repository nested in another is its own.
///
/// No repository is found, and the caller keys the pairing on the directory
/// itself, when anything is not laid out as git writes it for a checkout or
/// a linked worktree:
/// - a submodule, or a checkout with a separate git directory: a `.git` file
///   whose target has no `commondir`;
/// - a `.git` that is a symlink, unreadable, or a directory holding a
///   `commondir`;
/// - a pointer that does not parse or exceeds `maximumPointerBytes`, or a
///   worktree that does not link back;
/// - a git directory without `HEAD`, `objects` and `refs`;
/// - a working tree, `.git` or git directory not owned by the user (git's
///   own ownership rule);
/// - a path that is not on a local mount;
/// - a repository whose working tree is `/` or the home directory or above
///   it, which would take in every directory beneath it, or an unknown home
///   directory.
/// Every file read is bounded. Pointer targets are normalized before the
/// local-mount check; one that reaches a network mount through a symlink is
/// read inside the caller's bounded fact queue.
public enum ProjectRepository {
    /// A directory as the kernel identifies it once opened.
    public struct Directory: Sendable, Equatable {
        /// The canonical path (`F_GETPATH`).
        public let path: String
        public let mountPoint: String
        public let inode: UInt64
        public let owner: uid_t
        /// The directory's own mount is local (`MNT_LOCAL`).
        public let isLocal: Bool

        public init(path: String, mountPoint: String, inode: UInt64, owner: uid_t, isLocal: Bool) {
            self.path = path
            self.mountPoint = mountPoint
            self.inode = inode
            self.owner = owner
            self.isLocal = isLocal
        }
    }

    /// What `lstat` says about an entry.
    public struct Status: Sendable, Equatable {
        public enum Kind: Sendable, Equatable {
            case directory
            case regularFile
            /// A symlink, a special file, or an entry that could not be read.
            case other
        }

        public let kind: Kind
        public let owner: uid_t
        public let device: Int32

        public init(kind: Kind, owner: uid_t, device: Int32) {
            self.kind = kind
            self.owner = owner
            self.device = device
        }
    }

    /// The file-system reads the lookup makes; injectable so tests can stage
    /// layouts a real repository cannot (another owner, a mount boundary, a
    /// network mount).
    public struct FileSystem: Sendable {
        /// `lstat`: nil when the entry is absent.
        let status: @Sendable (String) -> Status?
        /// A regular file's contents when it is at most `limit` bytes of
        /// UTF-8 with no NUL; nil otherwise, or for a symlink.
        let smallFile: @Sendable (_ path: String, _ limit: Int) -> String?
        /// The directory at `path`, following symlinks, or nil.
        let directory: @Sendable (String) -> Directory?
        /// `path` and every mount at or above it are local.
        let isOnLocalMounts: @Sendable (String) -> Bool
        /// The user whose repositories count.
        let userID: uid_t

        public init(
            status: @escaping @Sendable (String) -> Status?,
            smallFile: @escaping @Sendable (String, Int) -> String?,
            directory: @escaping @Sendable (String) -> Directory?,
            isOnLocalMounts: @escaping @Sendable (String) -> Bool,
            userID: uid_t
        ) {
            self.status = status
            self.smallFile = smallFile
            self.directory = directory
            self.isOnLocalMounts = isOnLocalMounts
            self.userID = userID
        }

        public static let live = FileSystem(
            status: { liveStatus($0) },
            smallFile: { liveSmallFile($0, limit: $1) },
            directory: { liveDirectory($0) },
            isOnLocalMounts: { ProcessAncestry.pathIsOnLocalMounts($0) == true },
            userID: getuid()
        )

        /// Nothing exists: every directory keys its own pairing.
        public static let empty = FileSystem(
            status: { _ in nil }, smallFile: { _, _ in nil }, directory: { _ in nil },
            isOnLocalMounts: { _ in true }, userID: getuid()
        )
    }

    /// Git writes a `gitdir:`, `commondir` or `gitdir` pointer as one path and
    /// a newline; anything longer is not one.
    public static let maximumPointerBytes = 4_096
    /// Deeper than any real path's components: the walk to `/` ends first.
    static let maximumLevels = 512

    /// The shared git directory of the repository `directory` is in, or nil
    /// when there is none to key a pairing on (see the type's documentation).
    /// `directory` is an absolute, canonical path the kernel reported and a
    /// caller has checked is on local mounts.
    public static func commonDirectory(
        of directory: String, homeDirectory: String, fileSystem: FileSystem
    ) -> Directory? {
        checkout(containing: directory, homeDirectory: homeDirectory, fileSystem: fileSystem)?.common
    }

    /// The checkout `directory` is in: its working-tree root (the directory
    /// holding its `.git`) and the repository's shared git directory, under
    /// the same rules as `commonDirectory`.
    public static func checkout(
        containing directory: String, homeDirectory: String, fileSystem: FileSystem
    ) -> (root: String, common: Directory)? {
        let user = fileSystem.userID
        guard directory.hasPrefix("/"), !homeDirectory.isEmpty,
              let start = fileSystem.status(directory), start.kind == .directory else { return nil }
        // The home directory's canonical path, read only on a local disk.
        let home = fileSystem.isOnLocalMounts(homeDirectory)
            ? fileSystem.directory(homeDirectory)?.path ?? homeDirectory : homeDirectory

        // Up to the nearest `.git`, without leaving the directory's file system.
        var current = directory
        var found: (root: String, dotGit: String, entry: Status)?
        for _ in 0..<maximumLevels {
            guard let here = fileSystem.status(current), here.kind == .directory,
                  here.device == start.device else { return nil }
            let dotGit = join(current, ".git")
            if let entry = fileSystem.status(dotGit) {
                found = (current, dotGit, entry)
                break
            }
            guard current != "/" else { return nil }
            current = parent(of: current)
        }
        guard let found, !covers(found.root, homeDirectory: home),
              fileSystem.status(found.root)?.owner == user, found.entry.owner == user else { return nil }

        let common: String
        switch found.entry.kind {
        case .directory:
            // A checkout's own git directory never has a `commondir`.
            guard fileSystem.status(join(found.dotGit, "commondir")) == nil else { return nil }
            common = found.dotGit
        case .regularFile:
            guard let linked = linkedWorktreeCommonDirectory(
                root: found.root, dotGit: found.dotGit, fileSystem: fileSystem
            ) else { return nil }
            common = linked
        case .other:
            return nil
        }

        // Git's own test for a git directory: HEAD, objects and refs.
        guard fileSystem.status(join(common, "HEAD"))?.kind == .regularFile,
              fileSystem.status(join(common, "objects"))?.kind == .directory,
              fileSystem.status(join(common, "refs"))?.kind == .directory,
              let identified = fileSystem.directory(common),
              identified.isLocal, identified.owner == user, identified.inode > 0,
              identified.path.hasPrefix("/") else { return nil }
        return (found.root, identified)
    }

    /// The common git directory of the linked worktree whose `.git` file is
    /// `dotGit` at `root`, when the repository itself vouches for it: the
    /// file names `<common>/worktrees/<id>`, whose `commondir` names
    /// `<common>` and whose `gitdir` names `root/.git` back.
    static func linkedWorktreeCommonDirectory(root: String, dotGit: String, fileSystem: FileSystem) -> String? {
        let user = fileSystem.userID
        guard let target = pointer(fileSystem.smallFile(dotGit, maximumPointerBytes), prefix: "gitdir: ") else {
            return nil
        }
        let worktreeGitDirectory = normalized(resolve(target, against: root))
        guard fileSystem.isOnLocalMounts(worktreeGitDirectory),
              let commonPointer = fileSystem.status(join(worktreeGitDirectory, "commondir")),
              commonPointer.kind == .regularFile, commonPointer.owner == user,
              let commonTarget = pointer(
                  fileSystem.smallFile(join(worktreeGitDirectory, "commondir"), maximumPointerBytes), prefix: ""
              ) else { return nil }
        let common = normalized(resolve(commonTarget, against: worktreeGitDirectory))
        guard fileSystem.isOnLocalMounts(common),
              let worktree = fileSystem.directory(worktreeGitDirectory), worktree.owner == user,
              let repository = fileSystem.directory(common),
              parent(of: worktree.path) == join(repository.path, "worktrees") else { return nil }

        // The back-link git keeps in the worktree's git directory: absolute,
        // or relative to that directory (`worktree add --relative-paths`).
        let backLink = join(worktreeGitDirectory, "gitdir")
        guard fileSystem.status(backLink)?.kind == .regularFile,
              let linkTarget = pointer(fileSystem.smallFile(backLink, maximumPointerBytes), prefix: "") else {
            return nil
        }
        let linked = normalized(resolve(linkTarget, against: worktree.path))
        guard (linked as NSString).lastPathComponent == ".git",
              fileSystem.isOnLocalMounts(linked),
              fileSystem.directory(parent(of: linked))?.path == root else { return nil }
        return repository.path
    }

    /// A working tree at `/`, at the home directory or above it would take in
    /// every directory beneath it that is not in a repository of its own.
    static func covers(_ root: String, homeDirectory: String) -> Bool {
        if root == "/" { return true }
        let home = homeDirectory.count > 1 && homeDirectory.hasSuffix("/")
            ? String(homeDirectory.dropLast()) : homeDirectory
        return home == root || home.hasPrefix(root + "/")
    }

    /// The path a pointer file names: what follows `prefix`, with trailing
    /// `\n` and `\r` removed as git removes them; nil when anything else
    /// holds a line break.
    static func pointer(_ contents: String?, prefix: String) -> String? {
        guard let contents, contents.hasPrefix(prefix) else { return nil }
        var scalars = Array(contents.unicodeScalars.dropFirst(prefix.unicodeScalars.count))
        while let last = scalars.last, last == "\n" || last == "\r" { scalars.removeLast() }
        guard !scalars.isEmpty, !scalars.contains("\n"), !scalars.contains("\r") else { return nil }
        var value = String.UnicodeScalarView()
        value.append(contentsOf: scalars)
        return String(value)
    }

    static func resolve(_ path: String, against base: String) -> String {
        path.hasPrefix("/") ? path : join(base, path)
    }

    /// `path` with `.`, `..` and repeated slashes resolved lexically.
    static func normalized(_ path: String) -> String {
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

    static func join(_ directory: String, _ name: String) -> String {
        directory == "/" ? "/" + name : directory + "/" + name
    }

    static func parent(of path: String) -> String {
        guard let slash = path.lastIndex(of: "/"), slash != path.startIndex else { return "/" }
        return String(path[..<slash])
    }

    // MARK: - Live reads

    static func liveStatus(_ path: String) -> Status? {
        var info = stat()
        guard lstat(path, &info) == 0 else {
            return errno == ENOENT || errno == ENOTDIR ? nil : Status(kind: .other, owner: uid_t.max, device: -1)
        }
        let kind: Status.Kind
        switch info.st_mode & S_IFMT {
        case S_IFDIR: kind = .directory
        case S_IFREG: kind = .regularFile
        default: kind = .other
        }
        return Status(kind: kind, owner: info.st_uid, device: info.st_dev)
    }

    static func liveSmallFile(_ path: String, limit: Int) -> String? {
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_size >= 0, info.st_size <= limit else { return nil }
        var bytes = [UInt8](repeating: 0, count: limit + 1)
        var count = 0
        while count < bytes.count {
            let read = bytes.withUnsafeMutableBytes { raw in
                Darwin.read(descriptor, raw.baseAddress! + count, raw.count - count)
            }
            if read < 0, errno == EINTR { continue }
            guard read >= 0 else { return nil }
            if read == 0 { break }
            count += read
        }
        guard count <= limit else { return nil }
        let data = bytes.prefix(count)
        guard !data.contains(0) else { return nil }
        return String(bytes: data, encoding: .utf8)
    }

    static func liveDirectory(_ path: String) -> Directory? {
        let descriptor = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(descriptor, F_GETPATH, &buffer) == 0 else { return nil }
        var info = stat()
        var fileSystem = statfs()
        guard fstat(descriptor, &info) == 0, fstatfs(descriptor, &fileSystem) == 0 else { return nil }
        let mountPoint = withUnsafeBytes(of: fileSystem.f_mntonname) { raw in
            String(cString: raw.bindMemory(to: CChar.self).baseAddress!)
        }
        return Directory(
            path: String(cString: buffer),
            mountPoint: mountPoint,
            inode: UInt64(info.st_ino),
            owner: info.st_uid,
            isLocal: fileSystem.f_flags & UInt32(MNT_LOCAL) != 0
        )
    }
}
