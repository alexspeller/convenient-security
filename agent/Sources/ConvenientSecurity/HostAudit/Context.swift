import Foundation
import CSECRootProtocol

// Dependency-injected surface the host audit reads through. Every side effect
// the checks can reach — unprivileged command output, privileged root-helper
// reads/applies, TCC.db enumeration, filesystem inspection, and the accepted
// baseline — is behind a `Sendable` protocol so checks are pure functions of a
// `HostAuditContext` and can be exercised against fakes with captured fixtures.
//
// Value-free discipline: these types move *configuration state*, never a
// credential value. Command output is captured verbatim for a check to parse
// and reduce to a value-free `HostFinding`; nothing here logs or interprets it.

// MARK: - Unprivileged command execution

/// One allow-listed unprivileged command the audit may run. `executable` is
/// either an absolute path or a bare tool name resolved *only* from a fixed safe
/// PATH — never the user's `PATH`, which is itself an audit target (HA-F01).
public struct HostCommand: Sendable, Equatable {
    public let executable: String
    public let arguments: [String]
    /// Stable, value-free key: matches fakes in tests and names the read in logs.
    public let label: String
    public let standardInput: String?

    public init(
        executable: String,
        arguments: [String] = [],
        label: String,
        standardInput: String? = nil
    ) {
        self.executable = executable
        self.arguments = arguments
        self.label = label
        self.standardInput = standardInput
    }
}

public struct HostCommandResult: Sendable, Equatable {
    public let exitCode: Int32
    public let standardOutput: String
    public let standardError: String
    /// No trustworthy command result was obtained. Existing checks treat this
    /// as unknown, including commands interrupted after a successful launch.
    public var launchFailed: Bool { failure != nil }
    public let failure: HostCommandFailure?

    public init(
        exitCode: Int32,
        standardOutput: String = "",
        standardError: String = "",
        launchFailed: Bool = false,
        failure: HostCommandFailure? = nil
    ) {
        self.exitCode = exitCode
        self.standardOutput = standardOutput
        self.standardError = standardError
        self.failure = failure ?? (launchFailed ? .launch : nil)
    }

    public var succeeded: Bool { !launchFailed && exitCode == 0 }

    /// Convenience for the common "command missing → cannot determine" branch.
    public static let unavailable = HostCommandResult(exitCode: 127, launchFailed: true)
}

public protocol CommandRunning: Sendable {
    func run(_ command: HostCommand) async -> HostCommandResult

    /// Wall-clock cap this runner enforces on a single command, in whole
    /// seconds, or `nil` when it enforces none. A bounded scan quotes this in
    /// its logged coverage note, so the bound the user reads is the one this
    /// run actually enforces rather than a literal that can drift out of step
    /// with the runner.
    var perCommandTimeoutSeconds: Int? { get }
}

extension CommandRunning {
    /// Runners that impose no wall-clock cap (test doubles) inherit "no bound",
    /// so a coverage note never claims a timeout that is not enforced.
    public var perCommandTimeoutSeconds: Int? { nil }
}

/// Production runner: a fresh child per command with a minimal fixed
/// environment (so nothing the audit spawns inherits an attacker-influenced
/// `PATH`/`DYLD_*`), a hard timeout, and bounded output capture.
public struct SystemCommandRunner: CommandRunning {
    /// The per-command wall-clock cap every audit command runs under unless a
    /// caller overrides it. Single source of truth: a check that logs its time
    /// bound reads it from `perCommandTimeoutSeconds` rather than repeating it,
    /// and `HostAuditEngine.streamingCeilingSeconds` derives the whole-audit
    /// ceiling from it.
    public static let defaultTimeout: TimeInterval = 25

    private let timeout: TimeInterval
    private let maximumOutputBytes: Int
    private let executor: any HostCommandExecuting
    private let capacity: HostCommandCapacity
    private let diagnostics: @Sendable (HostCommandDiagnostic) -> Void

    public init(
        timeout: TimeInterval = SystemCommandRunner.defaultTimeout,
        maximumOutputBytes: Int = 1_048_576,
        executor: any HostCommandExecuting = POSIXHostCommandExecutor(),
        capacity: HostCommandCapacity = .shared,
        diagnostics: @escaping @Sendable (HostCommandDiagnostic) -> Void = { $0.log() }
    ) {
        self.timeout = max(0.01, timeout)
        self.maximumOutputBytes = max(1, maximumOutputBytes)
        self.executor = executor
        self.capacity = capacity
        self.diagnostics = diagnostics
    }

    public var perCommandTimeoutSeconds: Int? { Int(timeout.rounded()) }

    public func run(_ command: HostCommand) async -> HostCommandResult {
        await withCheckedContinuation { continuation in
            guard capacity.acquire(label: command.label) else {
                diagnostics(HostCommandDiagnostic(label: command.label, event: "capacity", phase: .launch, elapsed: 0))
                continuation.resume(returning: HostCommandResult(exitCode: 125, failure: .capacity))
                return
            }
            let control = HostCommandControl(
                label: command.label, timeout: timeout, capacity: capacity,
                diagnostics: diagnostics, continuation: continuation)
            // Arm the deadline BEFORE filesystem lookups or spawn. A kernel
            // stall may keep this worker alive, but cannot hold its caller or
            // create unlimited replacement workers: it retains a capacity slot.
            control.start()
            DispatchQueue.global(qos: .userInitiated).async {
                let result = control.expired
                    ? HostCommandResult(exitCode: 124, failure: .timeout)
                    : executor.execute(command, control: control, maximumOutputBytes: maximumOutputBytes)
                control.workerFinished()
                control.finish(result)
            }
        }
    }
}

/// Test double: matches a captured fixture by command `label` (falling back to a
/// closure), so per-check unit tests feed synthetic output.
public struct FakeCommandRunner: CommandRunning {
    public var byLabel: [String: HostCommandResult]
    public var fallback: @Sendable (HostCommand) -> HostCommandResult
    /// Nothing is really spawned, so the fake enforces no cap by default; a test
    /// that exercises a bound-logging check declares one to stand in for the
    /// production runner.
    public var perCommandTimeoutSeconds: Int?

    public init(
        _ byLabel: [String: HostCommandResult] = [:],
        fallback: @escaping @Sendable (HostCommand) -> HostCommandResult = { _ in .unavailable },
        perCommandTimeoutSeconds: Int? = nil
    ) {
        self.byLabel = byLabel
        self.fallback = fallback
        self.perCommandTimeoutSeconds = perCommandTimeoutSeconds
    }

    public func run(_ command: HostCommand) async -> HostCommandResult {
        byLabel[command.label] ?? fallback(command)
    }
}

// MARK: - Privileged host operations (via csec-rootd, agent role only)

public enum HostPrivilegedRead: Sendable, Equatable {
    /// Bounded, value-free command output for the agent to parse.
    case output(HostHelperResult)
    /// The signed root helper was not reachable → the check reports `unknown`.
    case unavailable
}

public enum HostPrivilegedApply: Sendable, Equatable {
    case applied
    case failed(String)     // value-free reason
    case unavailable
}

public protocol PrivilegedHostOps: Sendable {
    func read(_ query: HostRootRead) async -> HostPrivilegedRead
    func apply(_ change: HostRootChange) async -> HostPrivilegedApply
}

/// Production implementation wrapping `RootHelperClient`. Privileged reads and
/// reversible applies cross to `csec-rootd`, which admits only the agent's code
/// identity for these ops. Each apply is digest-bound to its exact change.
public struct RootHelperPrivilegedOps: PrivilegedHostOps {
    private let client: RootHelperClient

    public init(client: RootHelperClient) {
        self.client = client
    }

    public func read(_ query: HostRootRead) async -> HostPrivilegedRead {
        do {
            return .output(try client.hostRead(query))
        } catch {
            return .unavailable
        }
    }

    public func apply(_ change: HostRootChange) async -> HostPrivilegedApply {
        do {
            let digest = try change.digest()
            let result = try client.hostApply(change, digest: digest)
            return result.applied ? .applied : .failed("root helper did not apply the change")
        } catch {
            return .unavailable
        }
    }
}

/// Test double for privileged ops. `reads` maps a query to its outcome; `applies`
/// optionally overrides the outcome for specific changes (so a test can make one
/// change fail while others succeed — exercising atomic-per-target semantics).
public struct StubPrivilegedHostOps: PrivilegedHostOps {
    public var reads: [HostRootRead: HostPrivilegedRead]
    public var applies: [HostRootChange: HostPrivilegedApply]
    public var available: Bool
    public init(
        reads: [HostRootRead: HostPrivilegedRead] = [:],
        applies: [HostRootChange: HostPrivilegedApply] = [:],
        available: Bool = true
    ) {
        self.reads = reads
        self.applies = applies
        self.available = available
    }
    public func read(_ query: HostRootRead) async -> HostPrivilegedRead {
        reads[query] ?? (available ? .output(HostHelperResult(exitCode: 0)) : .unavailable)
    }
    public func apply(_ change: HostRootChange) async -> HostPrivilegedApply {
        applies[change] ?? (available ? .applied : .unavailable)
    }
}

// MARK: - TCC reading (Full Disk Access gated, via `sqlite3 -readonly`)

public enum TCCService: String, Sendable, CaseIterable {
    case allFiles = "kTCCServiceSystemPolicyAllFiles"
    case accessibility = "kTCCServiceAccessibility"
    case screenCapture = "kTCCServiceScreenCapture"
    case listenEvent = "kTCCServiceListenEvent"
    case appleEvents = "kTCCServiceAppleEvents"
    case developerTool = "kTCCServiceDeveloperTool"
    case camera = "kTCCServiceCamera"
    case microphone = "kTCCServiceMicrophone"
}

public enum TCCDatabase: String, Sendable, Equatable { case system, user }

/// One TCC grant row — the grantee identifier is app metadata (bundle id or
/// path), never a credential value.
public struct TCCGrant: Sendable, Equatable {
    public let client: String
    /// 0 = bundle identifier, 1 = absolute path (TCC `client_type`).
    public let clientType: Int
    public let allowed: Bool
    public let database: TCCDatabase
    public init(client: String, clientType: Int, allowed: Bool, database: TCCDatabase) {
        self.client = client
        self.clientType = clientType
        self.allowed = allowed
        self.database = database
    }
}

public enum TCCReadOutcome: Sendable, Equatable {
    case grants([TCCGrant])
    /// TCC.db could not be opened → csec lacks Full Disk Access. The check
    /// reports `unknown` with a Settings deep-link, never a pass.
    case noFullDiskAccess
}

public protocol TCCReading: Sendable {
    func grantees(_ service: TCCService) async -> TCCReadOutcome
}

/// Production reader over the system + per-user TCC.db via `sqlite3 -readonly`.
/// Both databases are SIP-protected, so a successful open proves csec holds FDA.
public struct SystemTCCReader: TCCReading {
    private let commands: CommandRunning
    private let systemDB = "/Library/Application Support/com.apple.TCC/TCC.db"
    private let userDB: String

    public init(commands: CommandRunning, homeDirectory: String = NSHomeDirectory()) {
        self.commands = commands
        self.userDB = "\(homeDirectory)/Library/Application Support/com.apple.TCC/TCC.db"
    }

    public func grantees(_ service: TCCService) async -> TCCReadOutcome {
        var all: [TCCGrant] = []
        var openedAny = false
        for (db, label) in [(systemDB, TCCDatabase.system), (userDB, .user)] {
            switch await query(db, service: service, database: label) {
            case .noFullDiskAccess:
                continue
            case let .grants(rows):
                openedAny = true
                all.append(contentsOf: rows)
            }
        }
        return openedAny ? .grants(all) : .noFullDiskAccess
    }

    private func query(_ db: String, service: TCCService, database: TCCDatabase) async -> TCCReadOutcome {
        guard FileManager.default.fileExists(atPath: db) else { return .noFullDiskAccess }
        // Tolerate schema drift: modern rows use `auth_value` (0/2/3), older ones
        // an `allowed` (0/1) column. Select both defensively via COALESCE.
        let sql = """
        SELECT client, client_type, \
        COALESCE((SELECT auth_value FROM access a2 WHERE a2.client=access.client AND a2.service=access.service LIMIT 1), 0) \
        FROM access WHERE service='\(service.rawValue)';
        """
        let result = await commands.run(HostCommand(
            executable: "/usr/bin/sqlite3",
            arguments: ["-readonly", "-separator", "|", db, sql],
            label: "sqlite3.tcc.\(database.rawValue).\(service.rawValue)"
        ))
        if result.launchFailed { return .noFullDiskAccess }
        // Permission-denied / unable-to-open ⇒ no FDA. sqlite3 exits 1 and prints
        // "Error: ... unable to open database" to stderr.
        if result.exitCode != 0 {
            let combined = (result.standardError + result.standardOutput).lowercased()
            if combined.contains("unable to open") || combined.contains("authorization denied")
                || combined.contains("not authorized") || combined.contains("permission denied") {
                return .noFullDiskAccess
            }
            // Some schema variance may still exit non-zero; treat empty as no rows.
            if result.standardOutput.isEmpty { return .grants([]) }
        }
        var grants: [TCCGrant] = []
        for line in result.standardOutput.split(separator: "\n") {
            let fields = line.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            guard fields.count >= 3 else { continue }
            let authValue = Int(fields[2]) ?? 0
            grants.append(TCCGrant(
                client: fields[0],
                clientType: Int(fields[1]) ?? 0,
                allowed: authValue >= 2,     // 2 = allowed, 3 = limited; both are grants
                database: database
            ))
        }
        return .grants(grants)
    }
}

public struct FakeTCCReader: TCCReading {
    public var byService: [TCCService: TCCReadOutcome]
    public init(_ byService: [TCCService: TCCReadOutcome] = [:]) { self.byService = byService }
    public func grantees(_ service: TCCService) async -> TCCReadOutcome {
        byService[service] ?? .noFullDiskAccess
    }
}

// MARK: - Filesystem inspection (value-free)

public protocol FileInspecting: Sendable {
    func fileExists(_ path: String) -> Bool
    func isExecutableFile(_ path: String) -> Bool
    func isDirectory(_ path: String) -> Bool
    /// Follows no symlinks: true only when the node at `path` is itself a regular
    /// file. `permissions` masks the type bits away, so a check that must reject a
    /// symlink standing in for a trusted binary asks here.
    func isRegularFile(_ path: String) -> Bool
    /// True only when the node at `path` is itself a symbolic link.
    func isSymbolicLink(_ path: String) -> Bool
    /// Bounded regular-file read; follows no final symlink; nil if unreadable.
    func readText(_ path: String, maxBytes: Int) -> String?
    func readPropertyList(_ path: String) -> Any?
    func permissions(_ path: String) -> HostFilePermissions?
    func directoryEntries(_ path: String) -> [String]
    var homeDirectory: String { get }
}

public struct HostFilePermissions: Sendable, Equatable {
    public let mode: UInt16
    public let ownerUID: UInt32
    public let groupGID: UInt32
    public init(mode: UInt16, ownerUID: UInt32, groupGID: UInt32) {
        self.mode = mode
        self.ownerUID = ownerUID
        self.groupGID = groupGID
    }
    public var isGroupWritable: Bool { mode & 0o020 != 0 }
    public var isOtherWritable: Bool { mode & 0o002 != 0 }
    public var isOwnedByCurrentUser: Bool { ownerUID == UInt32(getuid()) }
}

public struct SystemFileInspector: FileInspecting {
    public init() {}
    public var homeDirectory: String { NSHomeDirectory() }
    public func fileExists(_ path: String) -> Bool { FileManager.default.fileExists(atPath: path) }
    public func isExecutableFile(_ path: String) -> Bool { FileManager.default.isExecutableFile(atPath: path) }
    public func isDirectory(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }
    public func isRegularFile(_ path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFREG
    }
    public func isSymbolicLink(_ path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0 && (info.st_mode & S_IFMT) == S_IFLNK
    }
    public func readText(_ path: String, maxBytes: Int = 1_048_576) -> String? {
        guard maxBytes > 0 else { return nil }
        // O_NONBLOCK plus a descriptor type check closes the stat/open race:
        // a history path replaced by a FIFO must never hang the audit.
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }
        var buffer = [UInt8](repeating: 0, count: maxBytes)
        let n = buffer.withUnsafeMutableBytes { bytes -> Int in
            var count = 0
            while count < maxBytes {
                let next = read(fd, bytes.baseAddress!.advanced(by: count), maxBytes - count)
                if next < 0 {
                    if errno == EINTR { continue }
                    return -1
                }
                if next == 0 { break }
                count += next
            }
            return count
        }
        guard n >= 0 else { return nil }
        return String(decoding: buffer.prefix(n), as: UTF8.self)
    }
    public func readPropertyList(_ path: String) -> Any? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    }
    public func permissions(_ path: String) -> HostFilePermissions? {
        var s = stat()
        guard lstat(path, &s) == 0 else { return nil }
        return HostFilePermissions(
            mode: UInt16(s.st_mode & 0o7777),
            ownerUID: UInt32(s.st_uid),
            groupGID: UInt32(s.st_gid)
        )
    }
    public func directoryEntries(_ path: String) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? []
    }
}

public final class FakeFileInspector: FileInspecting, @unchecked Sendable {
    // A test double populated once at construction; `plists` holds Foundation
    // plist objects (`Any`), so this is an intentionally `@unchecked Sendable`
    // class rather than a struct.
    public var texts: [String: String]
    public var plists: [String: Any]
    public var perms: [String: HostFilePermissions]
    public var entries: [String: [String]]
    public var executables: Set<String>
    public var directories: Set<String>
    /// Paths a test wants `isRegularFile` to reject: anything else that exists
    /// and is not a directory reads as a regular file.
    public var symlinks: Set<String>
    public var homeDirectory: String

    public init(
        texts: [String: String] = [:],
        plists: [String: Any] = [:],
        perms: [String: HostFilePermissions] = [:],
        entries: [String: [String]] = [:],
        executables: Set<String> = [],
        directories: Set<String> = [],
        symlinks: Set<String> = [],
        homeDirectory: String = "/Users/tester"
    ) {
        self.texts = texts
        self.plists = plists
        self.perms = perms
        self.entries = entries
        self.executables = executables
        self.directories = directories
        self.symlinks = symlinks
        self.homeDirectory = homeDirectory
    }
    public func fileExists(_ path: String) -> Bool {
        texts[path] != nil || plists[path] != nil || perms[path] != nil
            || executables.contains(path) || directories.contains(path) || entries[path] != nil
    }
    public func isExecutableFile(_ path: String) -> Bool { executables.contains(path) }
    public func isDirectory(_ path: String) -> Bool { directories.contains(path) }
    public func isRegularFile(_ path: String) -> Bool {
        fileExists(path) && !directories.contains(path) && !symlinks.contains(path)
    }
    public func isSymbolicLink(_ path: String) -> Bool { symlinks.contains(path) }
    public func readText(_ path: String, maxBytes: Int) -> String? { texts[path] }
    public func readPropertyList(_ path: String) -> Any? { plists[path] }
    public func permissions(_ path: String) -> HostFilePermissions? { perms[path] }
    public func directoryEntries(_ path: String) -> [String] { entries[path] ?? [] }
}

// MARK: - Accepted baseline (periodic re-audit)

public struct BaselineEntry: Codable, Sendable, Equatable {
    public let status: String            // FindingStatus rawValue
    public let acceptedAtHint: String?
    public init(status: String, acceptedAtHint: String?) {
        self.status = status
        self.acceptedAtHint = acceptedAtHint
    }
}

/// One triaged finding: an accepted risk (exemption) or a deferred fix (TODO).
/// Value-free — `note` is the user's own local reason text, never a credential.
public struct TriageRecord: Codable, Sendable, Equatable {
    /// User reason for an exemption (nil for a TODO).
    public var note: String?
    /// When the user recorded this triage decision (opaque ISO hint).
    public var recordedAtHint: String?
    /// When a TODO reminder was last posted (weekly rate-limit); nil = never.
    public var lastRemindedAtHint: String?
    public init(note: String? = nil, recordedAtHint: String? = nil, lastRemindedAtHint: String? = nil) {
        self.note = note
        self.recordedAtHint = recordedAtHint
        self.lastRemindedAtHint = lastRemindedAtHint
    }
}

public struct HostAuditBaseline: Codable, Sendable, Equatable {
    public var entries: [String: BaselineEntry]
    /// Findings the user accepted as documented risks (suppress re-nagging).
    public var exemptions: [String: TriageRecord]
    /// Findings the user deferred as TODOs (weekly notification reminders).
    public var todos: [String: TriageRecord]

    public init(
        entries: [String: BaselineEntry] = [:],
        exemptions: [String: TriageRecord] = [:],
        todos: [String: TriageRecord] = [:]
    ) {
        self.entries = entries
        self.exemptions = exemptions
        self.todos = todos
    }

    private enum CodingKeys: String, CodingKey {
        case entries, exemptions, todos
    }

    // Custom decode so an existing baseline file predating the triage maps still
    // loads (missing dictionaries default to empty). A key this version no longer
    // knows — a `lastVersionCheckHint` written by an older build — is simply not
    // asked for, and a keyed container ignores what it is not asked for.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        entries = try c.decodeIfPresent([String: BaselineEntry].self, forKey: .entries) ?? [:]
        exemptions = try c.decodeIfPresent([String: TriageRecord].self, forKey: .exemptions) ?? [:]
        todos = try c.decodeIfPresent([String: TriageRecord].self, forKey: .todos) ?? [:]
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(entries, forKey: .entries)
        try c.encode(exemptions, forKey: .exemptions)
        try c.encode(todos, forKey: .todos)
    }
}

/// Where the accepted baseline lives. csecd's is `SealedBaselineStore`; a run
/// without protected stores, and every test, uses `InMemoryBaselineStore`.
/// Nothing reads or writes a plaintext baseline: an older csecd's plaintext
/// file is only ever imported, once, by the sealed store.
public protocol BaselineStoring: Sendable {
    func load() async -> HostAuditBaseline
    /// Replaces the baseline. Returns whether it was stored.
    @discardableResult
    func save(_ baseline: HostAuditBaseline, for change: BaselineChange) async -> Bool
    /// Reads, transforms and writes back as one step, so concurrent updates
    /// (an interactive audit, a triage, a reminder stamp) never lose one
    /// another. Returns whether the result was stored.
    @discardableResult
    func update(
        for change: BaselineChange,
        _ transform: @escaping @Sendable (HostAuditBaseline) -> HostAuditBaseline
    ) async -> Bool
}

/// What a write to the accepted baseline is for, so one that does not take
/// can say which action it was.
public enum BaselineChange: String, Sendable, Equatable, CaseIterable {
    /// An interactive `csec audit` accepting what it found.
    case audit
    /// Exemptions and deferred fixes recorded from `csec audit`'s triage.
    case triage
    /// The daily scan noting that a deferred-fix reminder was posted.
    case reminderStamp = "reminder_stamp"
}

public final class InMemoryBaselineStore: BaselineStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var baseline: HostAuditBaseline
    public init(_ baseline: HostAuditBaseline = HostAuditBaseline()) { self.baseline = baseline }
    public func load() async -> HostAuditBaseline { current() }
    @discardableResult
    public func save(_ baseline: HostAuditBaseline, for change: BaselineChange) async -> Bool {
        replace { _ in baseline }
        return true
    }
    @discardableResult
    public func update(
        for change: BaselineChange,
        _ transform: @escaping @Sendable (HostAuditBaseline) -> HostAuditBaseline
    ) async -> Bool {
        replace(transform)
        return true
    }
    private func current() -> HostAuditBaseline { lock.lock(); defer { lock.unlock() }; return baseline }
    private func replace(_ transform: (HostAuditBaseline) -> HostAuditBaseline) {
        lock.lock(); baseline = transform(baseline); lock.unlock()
    }
}

// MARK: - Per-run memoization (coalesce duplicate + concurrent reads)

/// Wraps a command runner so identical invocations within one audit run execute
/// once. The engine runs checks concurrently, and a few slow system commands
/// (notably `sfltool dumpbtm`, ~25s) are issued by more than one check; caching
/// the in-flight `Task` means concurrent duplicate calls await a single execution
/// rather than spawning the slow command twice. Scoped to one run (built fresh in
/// `production()`), so nothing is cached across audits. Read-only commands only —
/// the audit never mutates through this path.
public actor MemoizingCommandRunner: CommandRunning {
    private let base: CommandRunning
    private var inFlight: [String: Task<HostCommandResult, Never>] = [:]

    public init(_ base: CommandRunning) { self.base = base }

    /// Memoization changes only how often a command runs, never its bound, so
    /// the wrapped runner's cap is reported verbatim.
    public nonisolated var perCommandTimeoutSeconds: Int? { base.perCommandTimeoutSeconds }

    public func run(_ command: HostCommand) async -> HostCommandResult {
        let key = command.executable + "\u{0}"
            + command.arguments.joined(separator: "\u{1}") + "\u{0}"
            + (command.standardInput ?? "")
        if let existing = inFlight[key] { return await existing.value }
        let base = self.base
        // Detached so the real command runs off the actor — distinct commands stay
        // concurrent; only identical ones coalesce onto this shared Task.
        let task = Task<HostCommandResult, Never>.detached { await base.run(command) }
        inFlight[key] = task
        return await task.value
    }
}

/// Wraps the privileged host ops so identical reads within one run coalesce (e.g.
/// two checks both read `.sharingServices`). Applies are never cached.
public actor MemoizingPrivilegedHostOps: PrivilegedHostOps {
    private let base: PrivilegedHostOps
    private var inFlight: [HostRootRead: Task<HostPrivilegedRead, Never>] = [:]

    public init(_ base: PrivilegedHostOps) { self.base = base }

    public func read(_ query: HostRootRead) async -> HostPrivilegedRead {
        if let existing = inFlight[query] { return await existing.value }
        let base = self.base
        let task = Task<HostPrivilegedRead, Never>.detached { await base.read(query) }
        inFlight[query] = task
        return await task.value
    }

    public func apply(_ change: HostRootChange) async -> HostPrivilegedApply {
        await base.apply(change)
    }
}

// MARK: - Self identity + options + context

/// csec's own code identities, used to mark HA-D01 (csec's Full Disk Access) as
/// `expectedSelf` rather than a finding (Decision 8).
public struct HostSelfIdentity: Sendable {
    public let bundleIdentifiers: Set<String>
    public let executablePaths: Set<String>
    public init(bundleIdentifiers: Set<String>, executablePaths: Set<String> = []) {
        self.bundleIdentifiers = bundleIdentifiers
        self.executablePaths = executablePaths
    }

    /// The shipping csec/csecd/root-helper identifiers.
    public static let product = HostSelfIdentity(bundleIdentifiers: [
        ProductCodeIdentity.agentIdentifier,
        ProductCodeIdentity.launcherIdentifier,
        ProductCodeIdentity.rootHelperIdentifier,
    ])

    /// Whether a TCC grantee identifier is one of csec's own components.
    public func matches(_ client: String) -> Bool {
        if bundleIdentifiers.contains(client) || executablePaths.contains(client) { return true }
        // A path grantee under the installed csec app bundle also counts.
        return bundleIdentifiers.contains { client.contains($0) }
    }
}

public struct HostAuditOptions: Sendable {
    /// Opt into the bounded HA-F10 SUID/world-writable filesystem sweep.
    public var scanFilesystem: Bool
    /// Report only; never propose or apply remediation.
    public var reportOnly: Bool
    public init(scanFilesystem: Bool = false, reportOnly: Bool = false) {
        self.scanFilesystem = scanFilesystem
        self.reportOnly = reportOnly
    }
}

/// Everything a check reads through. Assembled with production impls in csecd and
/// with fakes in tests.
public struct HostAuditContext: Sendable {
    public let commands: CommandRunning
    public let privileged: PrivilegedHostOps
    public let tcc: TCCReading
    public let files: FileInspecting
    public let environment: [String: String]
    public let baseline: BaselineStoring
    public let selfIdentity: HostSelfIdentity
    public let options: HostAuditOptions
    /// Where coding-agent detection (HA-K01/HA-K02) looks for each client's
    /// executable after `PATH`: the standard install locations unless a test
    /// confines detection to its fixtures.
    public let codingAgentExecutableDirectories: @Sendable (AICommandHookClient) -> [String]
    /// Where HA-F13's fixes write a package manager's user-level config file.
    public let userConfig: UserConfigWriting

    public init(
        commands: CommandRunning,
        privileged: PrivilegedHostOps,
        tcc: TCCReading,
        files: FileInspecting,
        environment: [String: String],
        baseline: BaselineStoring,
        selfIdentity: HostSelfIdentity = .product,
        options: HostAuditOptions = HostAuditOptions(),
        codingAgentExecutableDirectories: @escaping @Sendable (AICommandHookClient) -> [String]
            = { CodingAgentSetup.standardExecutableDirectories(for: $0) },
        userConfig: UserConfigWriting = SystemUserConfigWriter()
    ) {
        self.commands = commands
        self.privileged = privileged
        self.tcc = tcc
        self.files = files
        self.environment = environment
        self.baseline = baseline
        self.selfIdentity = selfIdentity
        self.options = options
        self.codingAgentExecutableDirectories = codingAgentExecutableDirectories
        self.userConfig = userConfig
    }

    /// The production context csecd assembles: real command runner, root-helper
    /// privileged ops, FDA-gated TCC reader, real filesystem, and the baseline
    /// store csecd installed (sealed when it has protected stores).
    public static func production(
        rootHelper: RootHelperClient,
        options: HostAuditOptions = HostAuditOptions(),
        baseline: any BaselineStoring = HostAuditService.baselineStore
    ) -> HostAuditContext {
        // One memoizing runner shared by the checks and the TCC reader, so any
        // command issued by more than one check (or concurrently) runs once.
        let commands = MemoizingCommandRunner(SystemCommandRunner())
        return HostAuditContext(
            commands: commands,
            privileged: MemoizingPrivilegedHostOps(RootHelperPrivilegedOps(client: rootHelper)),
            tcc: SystemTCCReader(commands: commands),
            files: SystemFileInspector(),
            environment: ProcessInfo.processInfo.environment,
            baseline: baseline,
            options: options
        )
    }
}
