import Foundation

/// One process incarnation. A PID is reusable; the pair of PID and start time
/// (epoch microseconds) names exactly one process for its whole life.
public struct ProcessIncarnation: Hashable, Sendable, CustomStringConvertible {
    public let pid: pid_t
    public let startTime: UInt64

    public init(pid: pid_t, startTime: UInt64) {
        self.pid = pid
        self.startTime = startTime
    }

    public var description: String { "pid \(pid) started \(startTime)" }
}

/// A directory named by its canonical path and by the device and inode of the
/// directory itself, so a path later bound to a different directory (renamed,
/// replaced, remounted) is a different identity.
public struct DirectoryIdentity: Hashable, Sendable, Codable {
    /// The kernel's canonical path: symlinks and the system firmlinks
    /// resolved, the on-disk case. Measured to equal `realpath` for symlinked
    /// and case-variant entries, and to be more canonical than it for a
    /// directory entered through /System/Volumes/Data, which the kernel
    /// reports by its firmlinked /Users path.
    public let path: String
    public let device: UInt64
    public let inode: UInt64

    public init(path: String, device: UInt64, inode: UInt64) {
        self.path = path
        self.device = device
        self.inode = inode
    }
}

/// A process's working directory as the kernel reports it: its identity, and
/// the mount it is on, all from kernel state that no file system is asked for.
public struct ProcessWorkingDirectory: Sendable, Equatable {
    public let directory: DirectoryIdentity
    /// The directory's own mount, from the kernel's cached mount table.
    public let mount: MountFacts
    /// The directory's mount and every mount at or above its path are local.
    /// Only then has the path been checked to still name this directory (a
    /// directory removed after the process entered it keeps its last path in
    /// the kernel), and only then may a caller read files under it or look up
    /// its volume: on a network mount either can block on an unresponsive
    /// server.
    public let isOnLocalMounts: Bool

    public init(directory: DirectoryIdentity, mount: MountFacts, isOnLocalMounts: Bool) {
        self.directory = directory
        self.mount = mount
        self.isOnLocalMounts = isOnLocalMounts
    }
}

/// A regular file another process holds open (a shell's script, for one), as
/// the kernel records it, with the mount it lives on.
public struct ProcessOpenFile: Sendable, Equatable {
    public let vnode: ProcessFileDescriptorVnode
    /// The file's own mount, from the kernel's cached mount table.
    public let mount: MountFacts
    /// The file's mount and every mount at or above its path are local. Only
    /// then has the path been checked to still name this file, and only then
    /// may a caller open it: on a network mount either can block.
    public let isOnLocalMounts: Bool

    public init(vnode: ProcessFileDescriptorVnode, mount: MountFacts, isOnLocalMounts: Bool) {
        self.vnode = vnode
        self.mount = mount
        self.isOnLocalMounts = isOnLocalMounts
    }
}

/// Whether a process is the interactive foreground job of its terminal, and if
/// not, the first fact that says otherwise.
public enum ClaudeInteractivity: Sendable, Equatable {
    case interactive
    case notInteractive(Reason)

    public enum Reason: String, Sendable, Equatable {
        /// The job facts or the stdin descriptor could not be read.
        case factsUnavailable
        /// No controlling terminal (`PROC_FLAG_CONTROLT` clear, or NODEV).
        case noControllingTerminal
        /// Not the leader of its own process group (`pgid != pid`).
        case notProcessGroupLeader
        /// Its group is not the terminal's foreground group (`tpgid != pid`).
        case notForegroundProcessGroup
        /// fd 0 is not a character device, or is one other than the terminal.
        case standardInputNotTerminal
    }

    public var isInteractive: Bool { self == .interactive }
}

/// Kernel facts about a coding-agent process and its ancestry. Every method
/// that takes an incarnation answers only while that incarnation is live
/// across the read, and returns nil otherwise, so a fact never comes from a
/// process that reused the PID. The protocol is a seam: production uses
/// `.live`, and tests inject a synthetic process tree.
///
/// argv and environment are untrusted metadata the process's launcher chose.
/// Callers may compare them against fixed lists; they must never log or
/// display an argv value, and environment values are readable only for the
/// non-secret keys in `ClaudeSessionFacts.valueReadableEnvironmentKeys`.
public protocol ClaudeSessionFactProvider: Sendable {
    /// The live incarnation currently holding `pid`, or nil.
    func incarnation(of pid: pid_t) -> ProcessIncarnation?
    /// The raw parent PID of `pid`. Unbound to an incarnation on purpose: the
    /// ancestry walk binds it with re-reads (`ClaudeSessionFacts.verifiedAncestry`).
    func parent(of pid: pid_t) -> pid_t?
    func executablePath(of process: ProcessIncarnation) -> String?
    func argv(of process: ProcessIncarnation) -> [String]?
    func jobFacts(of process: ProcessIncarnation) -> ProcessJobFacts?
    /// What `fd` refers to. The kernel stats the descriptor's object to answer,
    /// which a network file system may do over the network.
    func fdCharDevice(of process: ProcessIncarnation, fd: Int32) -> ProcessFileDescriptorKind?
    /// The working directory, or nil when the kernel has no path for it, its
    /// mount is unknown, or (on local mounts) its path no longer names it. The
    /// kernel read makes one getattr call on the directory, which a network
    /// file system may answer over the network; no other file-system call is
    /// made unless `isOnLocalMounts`.
    func cwd(of process: ProcessIncarnation) -> ProcessWorkingDirectory?
    /// The regular file open on `fd`, or nil when the descriptor is not an
    /// open regular file, its path is incomplete or its mount is unknown, or
    /// (on local mounts) its path no longer names that file. Like `cwd`, the
    /// kernel read makes one getattr call on the file, and no other
    /// file-system call is made unless `isOnLocalMounts`.
    func openFile(of process: ProcessIncarnation, fd: Int32) -> ProcessOpenFile?
    /// Presence of exact environment names and name prefixes; no value read.
    func envPresence(
        of process: ProcessIncarnation, names: [String], prefixes: [String]
    ) -> EnvironmentNamePresence?
    /// Values of `allowlistedKeys`, which must all be in
    /// `ClaudeSessionFacts.valueReadableEnvironmentKeys`. Nil when any key is
    /// outside that list, when a requested key occurs more than once (which
    /// occurrence the process honours is not knowable from outside), or when
    /// the environment is unreadable. A key that is not set is simply absent.
    func envValues(of process: ProcessIncarnation, allowlistedKeys: [String]) -> [String: String]?
    /// The live code identity; see `ForeignCodeIdentity.resolve`. When `child`
    /// is given, `ppid(child) == process.pid` is re-read around the checks.
    func codeIdentity(
        of process: ProcessIncarnation, parentOf child: pid_t?, trustedCDHashes: Set<String>
    ) -> ForeignCodeIdentity?
    /// The audit-token PID version, which exec changes: a cheap key for
    /// caching a resolved identity per image. Nil when the kernel refuses the
    /// task name port, in which case nothing exec-exact is available.
    func pidVersion(of process: ProcessIncarnation) -> Int32?
    /// Every live process of this user, as incarnations. Candidates only: the
    /// caller applies the identity and gate checks.
    func liveProcesses() -> [ProcessIncarnation]?
    /// What the kernel tells any user about `pid` (`KernelProcessRecord`):
    /// all csecd can read of a set-id root process such as sudo.
    func kernelRecord(of pid: pid_t) -> KernelProcessRecord?
}

public extension ClaudeSessionFactProvider where Self == LiveClaudeSessionFactProvider {
    static var live: LiveClaudeSessionFactProvider { LiveClaudeSessionFactProvider() }
}

public extension ClaudeSessionFactProvider {
    /// A provider that models no set-id process has nothing to say.
    func kernelRecord(of pid: pid_t) -> KernelProcessRecord? { nil }

    /// G3's facts for `process`: its job facts, and only when they qualify, its
    /// fd 0. Reading a descriptor makes the kernel stat what it refers to, so
    /// the sweep over every process reads fd 0 only of terminal foreground jobs.
    func interactivity(of process: ProcessIncarnation) -> ClaudeInteractivity {
        let job = jobFacts(of: process)
        if let reason = ClaudeSessionFacts.jobControlDisqualifier(job) {
            return .notInteractive(reason)
        }
        return ClaudeSessionFacts.interactivity(job: job, standardInput: fdCharDevice(of: process, fd: 0))
    }
}

/// Pure helpers over process facts. They state what the kernel says; which
/// argv flags and environment names are disqualifying is policy, and lives
/// with the delegation service.
public enum ClaudeSessionFacts {
    /// The only environment keys whose values may be read from another
    /// process: paths (the configuration directory, the home directory Claude
    /// Code roots its settings at, and the `cd` search path and logical
    /// working directory a shell script's `cd` and `pwd` start from) and a
    /// runtime option string, none of which is a secret. Every other key is
    /// presence-only. `CDPATH` needs its value because an empty one is common
    /// and harmless (it is set empty in Alex's sessions) while any other value
    /// steers a script's `cd`; `PWD` because bash starts its logical `cd ..`
    /// from it; `CLAUDE_SECURESTORAGE_CONFIG_DIR` because an empty one keeps
    /// Claude Code's own sign-in (csec's Claude Code end-to-end check sets it
    /// so) while any other value moves where it keeps them.
    public static let valueReadableEnvironmentKeys: Set<String> = [
        "CDPATH",
        // A path: csec's own shell prefix script is the one value the gate
        // accepts (`ClaudeCodeShellPrefix`).
        "CLAUDE_CODE_SHELL_PREFIX",
        "CLAUDE_CONFIG_DIR",
        "CLAUDE_SECURESTORAGE_CONFIG_DIR",
        "HOME",
        "NODE_OPTIONS",
        "PWD",
    ]

    /// Whether the process is the interactive foreground job of its terminal:
    /// it has a controlling terminal, leads its own process group, that group
    /// is the terminal's foreground group, and fd 0 is that terminal.
    ///
    /// Session leadership is deliberately not required: an interactive shell's
    /// job is the leader of its process group, while the session leader is the
    /// login process above the shell.
    public static func interactivity(
        job: ProcessJobFacts?,
        standardInput: ProcessFileDescriptorKind?
    ) -> ClaudeInteractivity {
        if let reason = jobControlDisqualifier(job) { return .notInteractive(reason) }
        guard let terminal = job?.terminalDevice, let standardInput else {
            return .notInteractive(.factsUnavailable)
        }
        guard case let .characterDevice(device) = standardInput, device == terminal else {
            return .notInteractive(.standardInputNotTerminal)
        }
        return .interactive
    }

    /// The first job-control fact that rules out interactivity, or nil when
    /// the job facts alone allow it (fd 0 is then still to be checked).
    public static func jobControlDisqualifier(_ job: ProcessJobFacts?) -> ClaudeInteractivity.Reason? {
        guard let job else { return .factsUnavailable }
        guard job.hasControllingTerminal, job.terminalDevice != nil else { return .noControllingTerminal }
        guard job.processGroup == job.pid else { return .notProcessGroupLeader }
        guard job.terminalProcessGroup == job.pid else { return .notForegroundProcessGroup }
        return nil
    }

    /// `start` followed by its `hops` nearest ancestors, or nil unless every
    /// link still held after every member was read.
    ///
    /// The race rule: each parent's start time is read after its PID, and then
    /// every child's parent PID is read again. The kernel reparents a child to
    /// launchd when its parent exits, and never back, so a re-read that still
    /// names the same parent proves that parent stayed alive from the first
    /// read to the re-read, and the start time read in between is its own
    /// rather than that of a process that later reused the PID. Finally every
    /// member's start time is read again. A chain that reaches launchd (an
    /// orphan) or loops is refused.
    public static func verifiedAncestry(
        of start: ProcessIncarnation,
        hops: Int,
        provider: some ClaudeSessionFactProvider
    ) -> [ProcessIncarnation]? {
        guard hops >= 0, start.pid > 1,
              provider.incarnation(of: start.pid) == start else { return nil }
        var chain = [start]
        for _ in 0..<hops {
            let child = chain[chain.count - 1]
            guard let parentPID = provider.parent(of: child.pid), parentPID > 1,
                  !chain.contains(where: { $0.pid == parentPID }),
                  let parent = provider.incarnation(of: parentPID) else { return nil }
            chain.append(parent)
        }
        for (child, parent) in zip(chain, chain.dropFirst())
        where provider.parent(of: child.pid) != parent.pid {
            return nil
        }
        for member in chain where provider.incarnation(of: member.pid) != member {
            return nil
        }
        return chain
    }

    /// The chain a coding agent's tool call forms: `command` (the verified csec
    /// peer), its parent `shell`, and the shell's parent `agent`, each bound by
    /// `verifiedAncestry`'s race rule.
    public static func commandChain(
        from command: ProcessIncarnation,
        provider: some ClaudeSessionFactProvider
    ) -> AgentCommandChain? {
        guard let chain = verifiedAncestry(of: command, hops: 2, provider: provider),
              chain.count == 3 else { return nil }
        return AgentCommandChain(command: chain[0], shell: chain[1], agent: chain[2])
    }

    /// `command → agent` for csec as Claude Code's shell prefix: zsh runs the
    /// prefix, its one command, by exec, so the `csec ai` keeps the Bash tool
    /// shell's pid and start time and stands where that shell stood, directly
    /// under P (`ClaudeCodeShellPrefix`). The command is its own shell.
    public static func shellPrefixChain(
        from command: ProcessIncarnation,
        provider: some ClaudeSessionFactProvider
    ) -> AgentCommandChain? {
        guard let chain = verifiedAncestry(of: command, hops: 1, provider: provider),
              chain.count == 2 else { return nil }
        return AgentCommandChain(command: chain[0], shell: chain[0], agent: chain[1])
    }
}

/// `command → shell → agent`, each an incarnation whose parent link was
/// verified by re-reads.
public struct AgentCommandChain: Hashable, Sendable {
    public let command: ProcessIncarnation
    public let shell: ProcessIncarnation
    public let agent: ProcessIncarnation

    public init(command: ProcessIncarnation, shell: ProcessIncarnation, agent: ProcessIncarnation) {
        self.command = command
        self.shell = shell
        self.agent = agent
    }
}

/// The kernel-backed provider.
public struct LiveClaudeSessionFactProvider: ClaudeSessionFactProvider {
    public init() {}

    public func incarnation(of pid: pid_t) -> ProcessIncarnation? {
        guard pid > 0, let startTime = ProcessAncestry.startTime(of: pid) else { return nil }
        return ProcessIncarnation(pid: pid, startTime: startTime)
    }

    public func parent(of pid: pid_t) -> pid_t? {
        ProcessAncestry.parent(of: pid)
    }

    public func executablePath(of process: ProcessIncarnation) -> String? {
        whileLive(process) { ProcessAncestry.executablePath(of: process.pid) }
    }

    public func argv(of process: ProcessIncarnation) -> [String]? {
        whileLive(process) { ProcessAncestry.arguments(of: process.pid) }
    }

    public func jobFacts(of process: ProcessIncarnation) -> ProcessJobFacts? {
        // One kernel read carries its own start time; no second read needed.
        guard let facts = ProcessAncestry.jobFacts(of: process.pid),
              facts.startTime == process.startTime else { return nil }
        return facts
    }

    public func fdCharDevice(of process: ProcessIncarnation, fd: Int32) -> ProcessFileDescriptorKind? {
        whileLive(process) { ProcessAncestry.fileDescriptorKind(of: process.pid, fd: fd) }
    }

    public func cwd(of process: ProcessIncarnation) -> ProcessWorkingDirectory? {
        // Path, device, inode and mount all come from kernel state. The only
        // file-system call is the presence check below, made only when every
        // mount the path passes through is local.
        guard let vnode = whileLive(process, { ProcessAncestry.workingDirectoryVnode(of: process.pid) }),
              let mount = ProcessAncestry.mount(of: vnode.fileSystemID) else { return nil }
        let isOnLocalMounts = mount.isLocal && ProcessAncestry.pathIsOnLocalMounts(vnode.path) == true
        if isOnLocalMounts {
            var info = stat()
            guard lstat(vnode.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
                  UInt64(UInt32(bitPattern: info.st_dev)) == vnode.device,
                  UInt64(info.st_ino) == vnode.inode else { return nil }
        }
        return ProcessWorkingDirectory(
            directory: DirectoryIdentity(path: vnode.path, device: vnode.device, inode: vnode.inode),
            mount: mount,
            isOnLocalMounts: isOnLocalMounts
        )
    }

    public func openFile(of process: ProcessIncarnation, fd: Int32) -> ProcessOpenFile? {
        // As `cwd`: everything from kernel state, plus one lstat confirming
        // the path still names the same regular file, made only when every
        // mount on the path is local.
        guard let vnode = whileLive(process, { ProcessAncestry.fileDescriptorVnode(of: process.pid, fd: fd) }),
              let mount = ProcessAncestry.mount(of: vnode.fileSystemID) else { return nil }
        let isOnLocalMounts = mount.isLocal && ProcessAncestry.pathIsOnLocalMounts(vnode.path) == true
        if isOnLocalMounts {
            var info = stat()
            guard lstat(vnode.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
                  UInt64(UInt32(bitPattern: info.st_dev)) == vnode.device,
                  UInt64(info.st_ino) == vnode.inode else { return nil }
        }
        return ProcessOpenFile(vnode: vnode, mount: mount, isOnLocalMounts: isOnLocalMounts)
    }

    public func envPresence(
        of process: ProcessIncarnation, names: [String], prefixes: [String]
    ) -> EnvironmentNamePresence? {
        whileLive(process) {
            ProcessAncestry.environmentNamePresence(of: process.pid, names: names, prefixes: prefixes)
        }
    }

    public func envValues(of process: ProcessIncarnation, allowlistedKeys: [String]) -> [String: String]? {
        guard allowlistedKeys.allSatisfy(ClaudeSessionFacts.valueReadableEnvironmentKeys.contains) else {
            return nil
        }
        guard !allowlistedKeys.isEmpty else { return [:] }
        return whileLive(process) {
            guard let presence = ProcessAncestry.environmentNamePresence(
                of: process.pid, names: allowlistedKeys, prefixes: []
            ), !presence.names.values.contains(where: { $0 > 1 }) else { return nil }
            return ProcessAncestry.environmentSubset(of: process.pid, keys: allowlistedKeys)
        }
    }

    public func codeIdentity(
        of process: ProcessIncarnation, parentOf child: pid_t?, trustedCDHashes: Set<String>
    ) -> ForeignCodeIdentity? {
        ForeignCodeIdentity.resolve(
            pid: process.pid,
            startTime: process.startTime,
            parentOf: child,
            trustedCDHashes: trustedCDHashes
        )
    }

    public func pidVersion(of process: ProcessIncarnation) -> Int32? {
        guard case let .token(audit) = AuditIdentity.task(pid: process.pid),
              audit.startTime == process.startTime else { return nil }
        return audit.pidVersion
    }

    public func liveProcesses() -> [ProcessIncarnation]? {
        ProcessAncestry.processIDs(ofUser: getuid())?.compactMap { incarnation(of: $0) }
    }

    public func kernelRecord(of pid: pid_t) -> KernelProcessRecord? {
        KernelProcessRecord.live(pid)
    }

    /// Run `read` only while `process` is the live holder of its PID on both
    /// sides of the read.
    private func whileLive<T>(_ process: ProcessIncarnation, _ read: () -> T?) -> T? {
        guard process.pid > 0, ProcessAncestry.startTime(of: process.pid) == process.startTime,
              let value = read(),
              ProcessAncestry.startTime(of: process.pid) == process.startTime else { return nil }
        return value
    }
}
