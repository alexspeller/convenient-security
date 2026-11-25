import Foundation
import CSecuritySupport

/// Kernel process facts for subtree-scoped grants.
///
/// `descends` walks `pid → ppid → …` to a root with a matching start time.
/// `ppid` is kernel-assigned at `fork` and cannot be self-reparented onto an
/// arbitrary process, so malware cannot graft itself into a granted subtree.
/// csecd's grant checks walk `ProcessInspection.descends` instead, which also
/// links a detached job back through its session (`SessionLineage`, from
/// `lineageFacts`). See DESIGN.md (Grant model, Detached jobs).
public enum ProcessAncestry {
    /// Start time of `pid` (epoch microseconds), or nil if the process is gone.
    public static func startTime(of pid: pid_t) -> UInt64? {
        let t = cs_proc_start_time(pid)
        return t == 0 ? nil : t
    }

    /// Advisory lifecycle state used by supervisor diagnostics/tests. A stopped
    /// state is never sufficient for an authorization decision.
    public static func isStopped(_ pid: pid_t) -> Bool {
        cs_proc_status(pid) == 4 // SSTOP from <sys/proc.h>
    }

    /// Parent PID of `pid`, or nil if unavailable.
    public static func parent(of pid: pid_t) -> pid_t? {
        let p = cs_proc_ppid(pid)
        return p < 0 ? nil : p
    }

    /// Short process name (e.g. "ruby"), or nil. Advisory only — shown to the
    /// human in the consent prompt, never trusted as an identity gate.
    public static func name(of pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 256)
        let written = cs_proc_name(pid, &buffer, Int32(buffer.count))
        guard written > 0 else { return nil }
        let name = String(cString: buffer)
        return name.isEmpty ? nil : name
    }

    /// Whether `pid` has a controlling terminal. True for a login/terminal shell
    /// and its ordinary children; false for the pipe-wired shell a coding agent
    /// spawns per tool call, and for daemons. Advisory grant-scope input only.
    public static func hasControllingTerminal(_ pid: pid_t) -> Bool {
        cs_proc_controlling_terminal(pid) >= 0
    }

    /// Name of the controlling terminal device of `pid` (e.g. "ttys012"), or
    /// nil when it has none or the lookup failed. Display-only.
    public static func controllingTerminalName(of pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 64)
        let result = cs_proc_controlling_terminal_name(pid, &buffer, Int32(buffer.count))
        guard result == 1 else { return nil }
        let name = String(cString: buffer)
        return name.isEmpty ? nil : name
    }

    /// The exec-time values of an allow-listed set of environment variables of
    /// `pid`, or nil when its environment is unreadable (gone, another user's,
    /// or withheld by the kernel). Only the named keys are copied out of the
    /// kernel's block; see `cs_proc_env_subset`. Callers name only keys whose
    /// values are never secrets: the terminal a request came from, and the
    /// non-secret settings `ClaudeSessionFactProvider` allow-lists.
    public static func environmentSubset(of pid: pid_t, keys: [String]) -> [String: String]? {
        guard !keys.isEmpty else { return [:] }
        var buffer = [CChar](repeating: 0, count: 16 * 1_024)
        let keyStrings = keys.map { strdup($0) }
        defer { keyStrings.forEach { free($0) } }
        let count = keyStrings.withUnsafeBufferPointer { pointer -> Int32 in
            pointer.withMemoryRebound(to: UnsafePointer<CChar>?.self) { rebound in
                cs_proc_env_subset(
                    pid, rebound.baseAddress, Int32(keys.count), &buffer, Int32(buffer.count)
                )
            }
        }
        guard count >= 0 else { return nil }
        guard let entries = buffer.withUnsafeBufferPointer({
            nulTerminatedStrings(in: $0, count: Int(count))?.strings
        }) else { return nil }
        var values: [String: String] = [:]
        for entry in entries {
            guard let separator = entry.firstIndex(of: "=") else { continue }
            values[String(entry[..<separator])] = String(entry[entry.index(after: separator)...])
        }
        return values
    }

    /// Job-control facts of `pid` from one kernel read, or nil when it is gone.
    /// The snapshot carries its own start time, so a caller binds it to an
    /// incarnation by comparing that field rather than by a second read.
    public static func jobFacts(of pid: pid_t) -> ProcessJobFacts? {
        var facts = cs_job_facts()
        guard cs_proc_job_facts(pid, &facts) == 0, facts.pid == pid, facts.start_time > 0 else {
            return nil
        }
        return ProcessJobFacts(
            pid: facts.pid,
            parent: facts.parent,
            processGroup: facts.process_group,
            terminalProcessGroup: facts.terminal_process_group,
            // NODEV is the kernel's "no terminal" sentinel, never a device.
            terminalDevice: facts.terminal_device == UInt32.max ? nil : facts.terminal_device,
            hasControllingTerminal: facts.has_controlling_terminal != 0,
            isSessionLeader: facts.is_session_leader != 0,
            isTraced: facts.is_traced != 0,
            effectiveUID: facts.effective_uid,
            startTime: facts.start_time
        )
    }

    /// The facts that tie `pid` to the session it was forked in, all of one
    /// process incarnation, or nil when it is gone, another user's, or was
    /// replaced during the read.
    public static func lineageFacts(of pid: pid_t) -> ProcessLineageFacts? {
        var facts = cs_lineage_facts()
        guard cs_proc_lineage_facts(pid, &facts) == 0, facts.pid == pid, facts.start_time > 0 else {
            return nil
        }
        return ProcessLineageFacts(
            pid: facts.pid,
            parent: facts.parent,
            session: facts.session,
            uniqueID: facts.unique_id,
            startTime: facts.start_time
        )
    }

    /// kern.maxproc, or nil when unreadable.
    public static func maximumProcesses() -> Int? {
        let value = cs_max_processes()
        return value > 0 ? Int(value) : nil
    }

    /// What descriptor `fd` of `pid` is, or nil when the process is gone or the
    /// descriptor is not open.
    public static func fileDescriptorKind(of pid: pid_t, fd: Int32) -> ProcessFileDescriptorKind? {
        var device: UInt64 = 0
        switch cs_proc_fd_char_device(pid, fd, &device) {
        case 1: return .characterDevice(UInt32(truncatingIfNeeded: device))
        case 0: return .other
        default: return nil
        }
    }

    /// The kernel's path for the working directory of `pid`, with the device,
    /// inode and file-system ID of that directory from the same read, or nil.
    /// See `cs_proc_cwd`: the path is canonical but not re-checked, and the
    /// read makes one getattr call on the directory's file system.
    public static func workingDirectoryVnode(of pid: pid_t) -> ProcessWorkingDirectoryVnode? {
        var buffer = [CChar](repeating: 0, count: 4 * 1_024)
        var device: UInt64 = 0
        var inode: UInt64 = 0
        var fileSystemID: [Int32] = [0, 0]
        let written = cs_proc_cwd(pid, &buffer, Int32(buffer.count), &device, &inode, &fileSystemID)
        guard written > 0 else { return nil }
        let path = String(cString: buffer)
        guard path.hasPrefix("/") else { return nil }
        return ProcessWorkingDirectoryVnode(
            path: path,
            device: device,
            inode: inode,
            fileSystemID: FileSystemID(fileSystemID[0], fileSystemID[1])
        )
    }

    /// The regular file open on descriptor `fd` of `pid`: the kernel's path for
    /// it and the device, inode, file-system ID, size and status-change time
    /// from the same read, or nil when the descriptor is not an open regular
    /// file or its path is incomplete. See `cs_proc_fd_vnode`: the path is
    /// canonical but not re-checked, and the read makes one getattr call on the
    /// file's file system.
    public static func fileDescriptorVnode(of pid: pid_t, fd: Int32) -> ProcessFileDescriptorVnode? {
        var buffer = [CChar](repeating: 0, count: 4 * 1_024)
        var device: UInt64 = 0
        var inode: UInt64 = 0
        var fileSystemID: [Int32] = [0, 0]
        var size: Int64 = 0
        var ctimeSeconds: Int64 = 0
        var ctimeNanoseconds: Int64 = 0
        let written = cs_proc_fd_vnode(
            pid, fd, &buffer, Int32(buffer.count), &device, &inode, &fileSystemID,
            &size, &ctimeSeconds, &ctimeNanoseconds
        )
        guard written > 0 else { return nil }
        let path = String(cString: buffer)
        guard path.hasPrefix("/") else { return nil }
        return ProcessFileDescriptorVnode(
            path: path,
            device: device,
            inode: inode,
            fileSystemID: FileSystemID(fileSystemID[0], fileSystemID[1]),
            size: size,
            statusChange: FileTimestamp(seconds: ctimeSeconds, nanoseconds: ctimeNanoseconds)
        )
    }

    /// The mount with `fileSystemID`, from the kernel's cached mount table, or
    /// nil when no mount has that ID. Never calls into a file system, so an
    /// unresponsive network mount cannot block it.
    public static func mount(of fileSystemID: FileSystemID) -> MountFacts? {
        var isLocal: Int32 = 0
        var mountPoint = [CChar](repeating: 0, count: 1_024)
        var typeName = [CChar](repeating: 0, count: 64)
        let found = cs_mount_lookup(
            fileSystemID.first, fileSystemID.second, &isLocal,
            &mountPoint, Int32(mountPoint.count), &typeName, Int32(typeName.count)
        )
        guard found == 1 else { return nil }
        return MountFacts(
            fileSystemID: fileSystemID,
            mountPoint: String(cString: mountPoint),
            fileSystemType: String(cString: typeName),
            isLocal: isLocal != 0
        )
    }

    /// Whether every mount at or above the canonical `path` is local, from the
    /// cached mount table and without touching any file system; nil on error.
    public static func pathIsOnLocalMounts(_ path: String) -> Bool? {
        switch cs_path_mounts_local(path) {
        case 1: return true
        case 0: return false
        default: return nil
        }
    }

    /// The exec-time argv of `pid`, never its environment, or nil when it is
    /// unreadable. argv is attacker-chosen metadata: callers may compare its
    /// tokens against fixed lists, but must never log or display a value
    /// except through csecd's redacting review display (a direct-parent
    /// requester's command line on its panel and in its decision record).
    public static func arguments(of pid: pid_t) -> [String]? {
        // kern.argmax is 1 MiB on macOS and argv is a subset of that block; a
        // larger block reads as unreadable rather than truncated. The buffer
        // is left uninitialized: the shim writes exactly the strings it
        // reports, and only that prefix is read and then wiped.
        let capacity = 1_024 * 1_024
        let buffer = UnsafeMutableBufferPointer<CChar>.allocate(capacity: capacity)
        defer { buffer.deallocate() }
        let count = cs_proc_argv(pid, buffer.baseAddress, Int32(capacity))
        guard count >= 0 else { return nil }
        let decoded = nulTerminatedStrings(in: UnsafeBufferPointer(buffer), count: Int(count))
        _ = memset_s(buffer.baseAddress, capacity, 0, decoded?.byteCount ?? capacity)
        return decoded?.strings
    }

    /// Which of `names`, and which of `prefixes`, occur in the exec-time
    /// environment of `pid`, and how often, without reading a value. Nil when
    /// the environment is unreadable, including when the kernel withheld it.
    public static func environmentNamePresence(
        of pid: pid_t,
        names: [String],
        prefixes: [String]
    ) -> EnvironmentNamePresence? {
        guard !names.contains(where: \.isEmpty), !prefixes.contains(where: \.isEmpty) else {
            return nil
        }
        let nameStrings = names.map { strdup($0) }
        let prefixStrings = prefixes.map { strdup($0) }
        defer {
            nameStrings.forEach { free($0) }
            prefixStrings.forEach { free($0) }
        }
        var nameCounts = [UInt8](repeating: 0, count: max(names.count, 1))
        var prefixCounts = [UInt8](repeating: 0, count: max(prefixes.count, 1))
        let status = nameStrings.withUnsafeBufferPointer { namePointer -> Int32 in
            prefixStrings.withUnsafeBufferPointer { prefixPointer -> Int32 in
                namePointer.withMemoryRebound(to: UnsafePointer<CChar>?.self) { reboundNames in
                    prefixPointer.withMemoryRebound(to: UnsafePointer<CChar>?.self) { reboundPrefixes in
                        cs_proc_env_names_present(
                            pid,
                            reboundNames.baseAddress, Int32(names.count),
                            reboundPrefixes.baseAddress, Int32(prefixes.count),
                            &nameCounts, &prefixCounts
                        )
                    }
                }
            }
        }
        guard status == 0 else { return nil }
        var nameOccurrences: [String: Int] = [:]
        for (index, name) in names.enumerated() where nameCounts[index] > 0 {
            nameOccurrences[name] = Int(nameCounts[index])
        }
        var prefixOccurrences: [String: Int] = [:]
        for (index, prefix) in prefixes.enumerated() where prefixCounts[index] > 0 {
            prefixOccurrences[prefix] = Int(prefixCounts[index])
        }
        return EnvironmentNamePresence(names: nameOccurrences, prefixes: prefixOccurrences)
    }

    /// PIDs of every process whose effective UID is `uid`, or nil. A PID is
    /// only a candidate: callers bind each one to its start time before use.
    public static func processIDs(ofUser uid: uid_t) -> [pid_t]? {
        var capacity = 2_048
        for _ in 0..<4 {
            var pids = [Int32](repeating: 0, count: capacity)
            let total = cs_list_user_pids(uid, &pids, Int32(capacity))
            guard total >= 0 else { return nil }
            if Int(total) <= capacity { return Array(pids.prefix(Int(total))) }
            capacity = Int(total) + 256
        }
        return nil
    }

    /// Executable path guarded against PID reuse during the lookup.
    public static func executablePath(of pid: pid_t) -> String? {
        guard let before = startTime(of: pid) else { return nil }
        var buffer = [CChar](repeating: 0, count: 4 * 1_024)
        let written = cs_proc_path(pid, &buffer, Int32(buffer.count))
        guard written > 0, startTime(of: pid) == before else { return nil }
        let path = String(cString: buffer)
        return path.isEmpty ? nil : path
    }

    /// The first `count` consecutive NUL-terminated strings in `buffer` and the
    /// bytes they occupy, or nil if they overrun it. Each string is measured in
    /// bytes before it is decoded: invalid UTF-8 decodes with replacement
    /// characters, which have a different length, so a decoded string's length
    /// cannot locate the next.
    private static func nulTerminatedStrings(
        in buffer: UnsafeBufferPointer<CChar>,
        count: Int
    ) -> (strings: [String], byteCount: Int)? {
        guard let base = buffer.baseAddress else { return count == 0 ? ([], 0) : nil }
        var strings: [String] = []
        strings.reserveCapacity(count)
        var offset = 0
        for _ in 0..<count {
            guard offset < buffer.count else { return nil }
            let length = strnlen(base + offset, buffer.count - offset)
            guard length < buffer.count - offset else { return nil }
            let bytes = UnsafeRawBufferPointer(start: base + offset, count: length)
            strings.append(String(decoding: bytes, as: UTF8.self))
            offset += length + 1
        }
        return (strings, offset)
    }

    /// Whether `pid` is `root` or descends from it, with `root`'s start time
    /// matching `rootStartTime` (the PID-reuse guard).
    public static func descends(_ pid: pid_t, from root: pid_t, rootStartTime: UInt64) -> Bool {
        // The root must still be the same process that was granted.
        guard startTime(of: root) == rootStartTime else { return false }

        var current = pid
        var hops = 0
        while hops < 128 {
            if current == root { return true }
            // pid 1 is launchd; reaching it means we never hit `root`.
            if current <= 1 { return false }
            guard let next = parent(of: current), next != current else { return false }
            current = next
            hops += 1
        }
        return false
    }
}

/// One kernel snapshot of a process's job-control facts (`cs_proc_job_facts`).
/// Advisory kernel metadata: it states what the kernel reports about job
/// control, not who the process is.
public struct ProcessJobFacts: Sendable, Equatable {
    public let pid: pid_t
    public let parent: pid_t
    public let processGroup: pid_t
    /// The foreground process group of the controlling terminal; 0 without one.
    public let terminalProcessGroup: pid_t
    /// The controlling terminal's device number, or nil when there is none.
    public let terminalDevice: UInt32?
    public let hasControllingTerminal: Bool
    public let isSessionLeader: Bool
    public let isTraced: Bool
    public let effectiveUID: uid_t
    /// Epoch microseconds, from the same read as every other field.
    public let startTime: UInt64

    public init(
        pid: pid_t,
        parent: pid_t,
        processGroup: pid_t,
        terminalProcessGroup: pid_t,
        terminalDevice: UInt32?,
        hasControllingTerminal: Bool,
        isSessionLeader: Bool = false,
        isTraced: Bool = false,
        effectiveUID: uid_t,
        startTime: UInt64
    ) {
        self.pid = pid
        self.parent = parent
        self.processGroup = processGroup
        self.terminalProcessGroup = terminalProcessGroup
        self.terminalDevice = terminalDevice
        self.hasControllingTerminal = hasControllingTerminal
        self.isSessionLeader = isSessionLeader
        self.isTraced = isTraced
        self.effectiveUID = effectiveUID
        self.startTime = startTime
    }
}

/// One guarded read of the facts that tie a process to its session
/// (`cs_proc_lineage_facts`). `uniqueID` is the kernel's p_uniqueid: one per
/// pid allocation, in allocation order, never reused within a boot, and kept
/// across exec.
public struct ProcessLineageFacts: Sendable, Equatable {
    public let pid: pid_t
    /// The kernel parent now: launchd (1) once the original parent has exited.
    public let parent: pid_t
    /// getsid(pid): the pid of the process that started this session.
    public let session: pid_t
    public let uniqueID: UInt64
    /// Epoch microseconds.
    public let startTime: UInt64

    public init(pid: pid_t, parent: pid_t, session: pid_t, uniqueID: UInt64, startTime: UInt64) {
        self.pid = pid
        self.parent = parent
        self.session = session
        self.uniqueID = uniqueID
        self.startTime = startTime
    }

    /// Whether this process started its own session.
    public var leadsSession: Bool { session == pid }
}

/// What an open descriptor of another process refers to.
public enum ProcessFileDescriptorKind: Sendable, Equatable {
    /// A character device, with its device number (`/dev/null` is one too).
    case characterDevice(UInt32)
    /// A pipe, socket, regular file, directory or any other object.
    case other
}

/// The kernel's record of a process's working directory: the path it
/// reports and the device, inode and file-system ID of the directory vnode.
public struct ProcessWorkingDirectoryVnode: Sendable, Equatable {
    public let path: String
    public let device: UInt64
    public let inode: UInt64
    public let fileSystemID: FileSystemID

    public init(path: String, device: UInt64, inode: UInt64, fileSystemID: FileSystemID) {
        self.path = path
        self.device = device
        self.inode = inode
        self.fileSystemID = fileSystemID
    }
}

/// A file timestamp as the kernel keeps it: whole seconds since the epoch and
/// the nanoseconds within that second.
public struct FileTimestamp: Sendable, Equatable, Comparable {
    public let seconds: Int64
    public let nanoseconds: Int64

    public init(seconds: Int64, nanoseconds: Int64) {
        self.seconds = seconds
        self.nanoseconds = nanoseconds
    }

    public static func < (lhs: FileTimestamp, rhs: FileTimestamp) -> Bool {
        (lhs.seconds, lhs.nanoseconds) < (rhs.seconds, rhs.nanoseconds)
    }
}

/// The kernel's record of a regular file another process holds open: the path
/// it reports and the identity, size and status-change time of the vnode.
public struct ProcessFileDescriptorVnode: Sendable, Equatable {
    public let path: String
    public let device: UInt64
    public let inode: UInt64
    public let fileSystemID: FileSystemID
    public let size: Int64
    /// `st_ctime`: every write, rename, link or attribute change moves it, and
    /// no user-space call can set it.
    public let statusChange: FileTimestamp

    public init(
        path: String, device: UInt64, inode: UInt64, fileSystemID: FileSystemID,
        size: Int64, statusChange: FileTimestamp
    ) {
        self.path = path
        self.device = device
        self.inode = inode
        self.fileSystemID = fileSystemID
        self.size = size
        self.statusChange = statusChange
    }
}

/// A mounted file system's `f_fsid`. It names the mount, not a device: the
/// root directory's `st_dev` can differ from its mount's `f_fsid` (measured on
/// the sealed system volume), so mounts are matched by this, never by st_dev.
public struct FileSystemID: Hashable, Sendable, Codable {
    public let first: Int32
    public let second: Int32

    public init(_ first: Int32, _ second: Int32) {
        self.first = first
        self.second = second
    }
}

/// One entry of the kernel's cached mount table.
public struct MountFacts: Hashable, Sendable, Codable {
    public let fileSystemID: FileSystemID
    public let mountPoint: String
    public let fileSystemType: String
    /// MNT_LOCAL: the file system is not reached over a network.
    public let isLocal: Bool

    public init(fileSystemID: FileSystemID, mountPoint: String, fileSystemType: String, isLocal: Bool) {
        self.fileSystemID = fileSystemID
        self.mountPoint = mountPoint
        self.fileSystemType = fileSystemType
        self.isLocal = isLocal
    }
}

/// Which environment names and name prefixes occur in a process's exec-time
/// environment, and how many entries matched each. No value is ever read.
public struct EnvironmentNamePresence: Sendable, Equatable {
    /// Exact names that occur, with their occurrence counts (saturating at 255).
    public let names: [String: Int]
    /// Prefixes that some name starts with, with how many names matched.
    public let prefixes: [String: Int]

    public init(names: [String: Int] = [:], prefixes: [String: Int] = [:]) {
        self.names = names.filter { $0.value > 0 }
        self.prefixes = prefixes.filter { $0.value > 0 }
    }

    public var isEmpty: Bool { names.isEmpty && prefixes.isEmpty }
}
