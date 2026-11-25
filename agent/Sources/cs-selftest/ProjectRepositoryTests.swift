import ConvenientSecurity
import Darwin
import Foundation

// The git repository a pairing is keyed on (`ProjectRepository`), found in
// real layouts `git` itself writes, plus the few it cannot (another owner, a
// mount boundary, a network mount) through an injected file system.

/// A real git layout in a fresh temporary directory, every path canonical:
/// - `main`, a checkout with one commit, and `main/src/deep` inside it;
/// - `worktree` (and `worktree/sub`) and `relativeWorktree`, linked
///   worktrees of `main`, the second with relative pointers, as
///   `worktree add --relative-paths` (git 2.48) writes them;
/// - `nested`, a separate repository inside `main`;
/// - `submodule`, a submodule of `main`;
/// - `separateWork`, a checkout whose git directory is `separateGit`;
/// - `plain`, a directory in no repository.
final class GitRepositoryFixture: @unchecked Sendable {
    let root: String
    let home: String
    let main: String
    let mainDeep: String
    let worktree: String
    let worktreeSub: String
    let relativeWorktree: String
    let nested: String
    let submodule: String
    let separateWork: String
    let separateGit: String
    let plain: String

    var mainGit: String { main + "/.git" }

    init?() {
        let template = (NSTemporaryDirectory() as NSString).appendingPathComponent("csec-repo-XXXXXX")
        var buffer = Array(template.utf8CString)
        guard mkdtemp(&buffer) != nil,
              let canonical = realpath(buffer, nil) else { return nil }
        root = String(cString: canonical)
        free(canonical)
        home = root + "/home"
        main = root + "/main"
        mainDeep = main + "/src/deep"
        worktree = root + "/worktree"
        worktreeSub = worktree + "/sub"
        relativeWorktree = root + "/relative-worktree"
        nested = main + "/vendor/nested"
        submodule = main + "/module"
        separateWork = root + "/separate"
        separateGit = root + "/separate.git"
        plain = root + "/plain"
        let moduleSource = root + "/module-source"
        guard Self.makeDirectory(home), Self.makeDirectory(plain),
              git(["init", "-q", "-b", "main", main]),
              git(["-C", main, "commit", "-q", "--allow-empty", "-m", "init"]),
              git(["-C", main, "worktree", "add", "-q", "-b", "side", worktree]),
              git(["-C", main, "worktree", "add", "-q", "-b", "relative", relativeWorktree]),
              write("gitdir: ../main/.git/worktrees/relative-worktree\n", to: relativeWorktree + "/.git"),
              write("../../../../relative-worktree/.git\n", to: main + "/.git/worktrees/relative-worktree/gitdir"),
              git(["init", "-q", "-b", "main", nested]),
              git(["init", "-q", "-b", "main", moduleSource]),
              git(["-C", moduleSource, "commit", "-q", "--allow-empty", "-m", "module"]),
              git(["-C", main, "submodule", "add", "-q", moduleSource, "module"]),
              git(["init", "-q", "-b", "main", "--separate-git-dir", separateGit, separateWork]),
              Self.makeDirectory(mainDeep), Self.makeDirectory(worktreeSub) else {
            remove()
            return nil
        }
    }

    /// Git with no system, global or user configuration of this Mac.
    @discardableResult
    func git(_ arguments: [String]) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        process.arguments = [
            "-c", "user.name=csec", "-c", "user.email=csec@example.invalid",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=always",
        ] + arguments
        process.environment = [
            "HOME": home, "PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
        ]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch { return false }
        process.waitUntilExit()
        return process.terminationStatus == 0
    }

    static func makeDirectory(_ path: String) -> Bool {
        (try? FileManager.default.createDirectory(atPath: path, withIntermediateDirectories: true)) != nil
    }

    func write(_ contents: String, to path: String) -> Bool {
        Self.makeDirectory((path as NSString).deletingLastPathComponent)
            && FileManager.default.createFile(atPath: path, contents: Data(contents.utf8))
    }

    func read(_ path: String) -> String? {
        FileManager.default.contents(atPath: path).flatMap { String(data: $0, encoding: .utf8) }
    }

    func inode(_ path: String) -> UInt64 {
        var info = stat()
        return stat(path, &info) == 0 ? UInt64(info.st_ino) : 0
    }

    func remove() {
        try? FileManager.default.removeItem(atPath: root)
    }
}

func projectRepositoryTests() {
    print("\n# Project pairing: the git repository a directory is in")
    guard let fixture = GitRepositoryFixture() else {
        check(false, "project repository: the git fixture builds (checkout, worktrees, nested repo, submodule)")
        return
    }
    defer { fixture.remove() }
    func common(_ directory: String, home: String? = nil, fileSystem: ProjectRepository.FileSystem = .live) -> String? {
        ProjectRepository.commonDirectory(of: directory, homeDirectory: home ?? fixture.home, fileSystem: fileSystem)?.path
    }
    let mainGit = fixture.mainGit

    check(common(fixture.main) == mainGit, "project repository: a checkout's key is its .git directory")
    check(common(fixture.mainDeep) == mainGit, "project repository: a subdirectory shares its checkout's repository")
    check(common(fixture.worktree) == mainGit && common(fixture.worktreeSub) == mainGit,
          "project repository: a linked worktree and its subdirectories share the main checkout's repository")
    check(common(fixture.relativeWorktree) == mainGit,
          "project repository: a worktree with relative pointers (--relative-paths) links back too")
    check(ProjectRepository.commonDirectory(of: fixture.worktree, homeDirectory: fixture.home, fileSystem: .live)?.inode
            == fixture.inode(mainGit),
          "project repository: the key carries the shared git directory's inode")
    check(common(fixture.nested) == fixture.nested + "/.git",
          "project repository: a repository nested in another is its own")
    check(common(fixture.submodule) == nil && common(fixture.separateWork) == nil,
          "project repository: a submodule and a separate git directory keep their own directory's key")
    check(common(fixture.plain) == nil, "project repository: a directory in no repository has none")
    let bare = fixture.root + "/bare.git"
    let bareWorktree = fixture.root + "/bare-worktree"
    check(fixture.git(["clone", "-q", "--bare", fixture.main, bare])
            && fixture.git(["-C", bare, "worktree", "add", "-q", "-b", "bare-side", bareWorktree])
            && common(bareWorktree) == bare,
          "project repository: a bare repository's worktree is keyed on the bare repository")

    // A working tree at or above the home directory would take in every
    // directory beneath it that is in no repository of its own.
    check(common(fixture.mainDeep, home: fixture.main) == nil,
          "project repository: a repository whose working tree is the home directory is not used")
    check(common(fixture.main, home: fixture.mainDeep) == nil,
          "project repository: nor one whose working tree is above the home directory")
    check(common(fixture.main, home: "") == nil, "project repository: an unknown home directory finds none")

    // Pointers git would not have written, or that the repository does not
    // link back, borrow nothing: the directory keys itself.
    func planted(_ name: String, _ files: [String: String]) -> String {
        let directory = fixture.root + "/" + name
        for (relative, contents) in files { _ = fixture.write(contents, to: directory + "/" + relative) }
        return directory
    }
    let worktreeGitDirectory = mainGit + "/worktrees/worktree"
    let borrowing: [(String, [String: String], String)] = [
        ("direct", [".git": "gitdir: ../main/.git\n"], "a .git file naming another checkout's git directory"),
        ("absolute", [".git": "gitdir: \(mainGit)\n"], "an absolute pointer to another checkout's git directory"),
        ("hijack", [".git": "gitdir: \(worktreeGitDirectory)\n"],
         "a .git file naming another worktree's git directory, which does not link back"),
        ("via-commondir", [".git": "gitdir: ./fake\n", "fake/commondir": "../../main/.git\n", "fake/gitdir": "../.git\n"],
         "a pointer to a planted git directory whose commondir names the repository"),
        ("garbage", [".git": "not a pointer\n"], "a .git file that is not a gitdir pointer"),
        ("oversized", [".git": "gitdir: " + String(repeating: "a", count: ProjectRepository.maximumPointerBytes) + "\n"],
         "a .git file larger than a pointer"),
        ("two-lines", [".git": "gitdir: \(worktreeGitDirectory)\nextra\n"], "a .git file with more than one line"),
    ]
    for (name, files, label) in borrowing {
        check(common(planted(name, files)) == nil, "project repository: \(label) finds no repository")
    }
    let commonInDirectory = planted("dir-commondir", ["x": ""])
    check(fixture.git(["init", "-q", "-b", "main", commonInDirectory])
            && fixture.write("../main/.git\n", to: commonInDirectory + "/.git/commondir")
            && common(commonInDirectory) == nil,
          "project repository: a .git directory holding a commondir finds no repository")
    let linked = fixture.root + "/linked"
    check(GitRepositoryFixture.makeDirectory(linked)
            && symlink(mainGit, linked + "/.git") == 0 && common(linked) == nil,
          "project repository: a symlinked .git finds no repository")
    let pruned = fixture.root + "/pruned"
    check(fixture.git(["-C", fixture.main, "worktree", "add", "-q", "-b", "pruned", pruned])
            && (try? FileManager.default.removeItem(atPath: mainGit + "/worktrees/pruned")) != nil
            && common(pruned) == nil,
          "project repository: a worktree the repository no longer lists finds none")

    // Line endings, as git reads them.
    for (label, ending) in [("CRLF", "\r\n"), ("\\n\\r\\n", "\n\r\n")] {
        let directory = fixture.root + "/crlf-\(label.count)"
        let written = fixture.git(["-C", fixture.main, "worktree", "add", "-q", "-b", "crlf\(label.count)", directory])
        let pointer = fixture.read(directory + "/.git")?.trimmingCharacters(in: .newlines)
        check(written && pointer != nil && fixture.write(pointer! + ending, to: directory + "/.git")
                && common(directory) == mainGit,
              "project repository: a pointer ending in \(label) resolves as git reads it")
    }

    // Layouts a real repository cannot stage.
    let user: uid_t = 501
    func staged(
        _ statuses: [String: ProjectRepository.Status], files: [String: String] = [:],
        local: @escaping @Sendable (String) -> Bool = { _ in true },
        directories: [String: ProjectRepository.Directory] = [:]
    ) -> ProjectRepository.FileSystem {
        ProjectRepository.FileSystem(
            status: { statuses[$0] },
            smallFile: { path, limit in files[path].flatMap { $0.utf8.count <= limit ? $0 : nil } },
            directory: { path in
                directories[path] ?? ProjectRepository.Directory(path: path, mountPoint: "/", inode: 7, owner: user, isLocal: true)
            },
            isOnLocalMounts: local,
            userID: user
        )
    }
    func directory(_ owner: uid_t = user, device: Int32 = 1) -> ProjectRepository.Status {
        ProjectRepository.Status(kind: .directory, owner: owner, device: device)
    }
    func file(_ owner: uid_t = user) -> ProjectRepository.Status {
        ProjectRepository.Status(kind: .regularFile, owner: owner, device: 1)
    }
    // /w is a linked worktree of the repository whose git directory is /r/.git.
    let layout: [String: ProjectRepository.Status] = [
        "/": directory(), "/w": directory(), "/w/a": directory(), "/w/.git": file(),
        "/r/.git/worktrees/w/commondir": file(), "/r/.git/worktrees/w/gitdir": file(),
        "/r/.git/HEAD": file(), "/r/.git/objects": directory(), "/r/.git/refs": directory(),
    ]
    let pointers = [
        "/w/.git": "gitdir: /r/.git/worktrees/w\n",
        "/r/.git/worktrees/w/commondir": "../..\n",
        "/r/.git/worktrees/w/gitdir": "/w/.git\n",
    ]
    check(common("/w/a", home: "/home", fileSystem: staged(layout, files: pointers)) == "/r/.git",
          "project repository: the staged worktree resolves (control)")
    check(common("/w/a", home: "/home", fileSystem: staged(layout, files: pointers, local: { !$0.hasPrefix("/r") })) == nil,
          "project repository: a git directory on a network mount is not read")
    check(common("/w/a", home: "/home", fileSystem: staged(
        layout, files: pointers,
        directories: ["/r/.git": ProjectRepository.Directory(path: "/r/.git", mountPoint: "/", inode: 7, owner: user, isLocal: false)]
    )) == nil, "project repository: a git directory whose mount is not local is not used")
    for (label, path, status) in [
        ("working tree", "/w", directory(0)), (".git file", "/w/.git", file(0)),
        ("commondir", "/r/.git/worktrees/w/commondir", file(0)),
    ] {
        var owned = layout
        owned[path] = status
        check(common("/w/a", home: "/home", fileSystem: staged(owned, files: pointers)) == nil,
              "project repository: a \(label) owned by another user finds no repository")
    }
    check(common("/w/a", home: "/home", fileSystem: staged(
        layout, files: pointers,
        directories: ["/r/.git": ProjectRepository.Directory(path: "/r/.git", mountPoint: "/", inode: 7, owner: 0, isLocal: true)]
    )) == nil, "project repository: a git directory owned by another user finds no repository")
    var mounted = layout
    mounted["/w/a"] = directory(device: 2)
    check(common("/w/a", home: "/home", fileSystem: staged(mounted, files: pointers)) == nil,
          "project repository: the walk stops at a file-system boundary, as git's does")
    var commonIsDirectory = layout
    commonIsDirectory["/r/.git/worktrees/w/commondir"] = directory()
    check(common("/w/a", home: "/home", fileSystem: staged(commonIsDirectory, files: pointers)) == nil,
          "project repository: a commondir that is not a file finds no repository")
    var unreadable = layout
    unreadable["/w/.git"] = ProjectRepository.Status(kind: .other, owner: user, device: 1)
    check(common("/w/a", home: "/home", fileSystem: staged(unreadable, files: pointers)) == nil,
          "project repository: an unreadable .git finds no repository")
    check(common("/w/a", home: "/home-link", fileSystem: staged(
        layout, files: pointers,
        directories: ["/home-link": ProjectRepository.Directory(path: "/w", mountPoint: "/", inode: 9, owner: user, isLocal: true)]
    )) == nil, "project repository: the home directory is compared by its canonical path")
    check(common("/w/a", home: "/home-net", fileSystem: staged(
        layout, files: pointers, local: { $0 != "/home-net" },
        directories: ["/home-net": ProjectRepository.Directory(path: "/w", mountPoint: "/", inode: 9, owner: user, isLocal: false)]
    )) == "/r/.git", "project repository: a home directory on a network mount is compared as written, never opened")
    check(common("/", fileSystem: .empty) == nil && common("relative/path") == nil,
          "project repository: / and a relative path find none")

    // What a person sees for a repository's key.
    let repositoryKey = ProjectKey(path: "/x/app/.git", volumeUUID: UUID().uuidString, inode: 1)
    let directoryKey = ProjectKey(path: "/x/app", volumeUUID: UUID().uuidString, inode: 1)
    let dotGitName = ProjectKey(path: "/x/app.git", volumeUUID: UUID().uuidString, inode: 1)
    check(repositoryKey.displayPath == "/x/app" && repositoryKey.displayName == "app"
            && repositoryKey.displayDescription == "/x/app (git repository)"
            && directoryKey.displayPath == "/x/app" && directoryKey.displayDescription == "/x/app"
            && dotGitName.displayPath == "/x/app.git" && dotGitName.displayName == "app.git",
          "project repository: a repository shows as its checkout, marked as a repository; any other path as itself")
}
