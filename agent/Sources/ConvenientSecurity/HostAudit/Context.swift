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
    /// The tool could not be launched at all (missing binary, resolution failed).
    public let launchFailed: Bool

    public init(
        exitCode: Int32,
        standardOutput: String = "",
        standardError: String = "",
        launchFailed: Bool = false
    ) {
        self.exitCode = exitCode
        self.standardOutput = standardOutput
        self.standardError = standardError
        self.launchFailed = launchFailed
    }

    public var succeeded: Bool { !launchFailed && exitCode == 0 }

    /// Convenience for the common "command missing → cannot determine" branch.
    public static let unavailable = HostCommandResult(exitCode: 127, launchFailed: true)
}

public protocol CommandRunning: Sendable {
    func run(_ command: HostCommand) async -> HostCommandResult
}

/// Production runner: a fresh `Process` per command with a minimal fixed
/// environment (so nothing the audit spawns inherits an attacker-influenced
/// `PATH`/`DYLD_*`), a hard timeout, and bounded output capture.
public struct SystemCommandRunner: CommandRunning {
    private let timeout: TimeInterval
    private let maximumOutputBytes: Int
    /// Fixed resolution path for bare tool names. Ordered so Homebrew dev tools
    /// (npm/brew/code) resolve, but system binaries win where both exist.
    private static let safePath = [
        "/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec",
        "/opt/homebrew/bin", "/usr/local/bin",
    ]

    public init(timeout: TimeInterval = 25, maximumOutputBytes: Int = 1_048_576) {
        self.timeout = timeout
        self.maximumOutputBytes = maximumOutputBytes
    }

    public func run(_ command: HostCommand) async -> HostCommandResult {
        await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(returning: self.runBlocking(command))
            }
        }
    }

    private func resolve(_ executable: String) -> String? {
        if executable.hasPrefix("/") {
            return FileManager.default.isExecutableFile(atPath: executable) ? executable : nil
        }
        guard !executable.contains("/") else { return nil }
        for dir in Self.safePath {
            let candidate = "\(dir)/\(executable)"
            if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
        }
        return nil
    }

    private func runBlocking(_ command: HostCommand) -> HostCommandResult {
        guard let path = resolve(command.executable) else { return .unavailable }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = command.arguments
        process.environment = ["PATH": Self.safePath.joined(separator: ":"), "LC_ALL": "C"]

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        if let input = command.standardInput {
            let inPipe = Pipe()
            process.standardInput = inPipe
            inPipe.fileHandleForWriting.write(Data(input.utf8))
            try? inPipe.fileHandleForWriting.close()
        }

        var outData = Data(), errData = Data()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            outData = outPipe.fileHandleForReading.readDataToEndOfFile(); group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .utility).async {
            errData = errPipe.fileHandleForReading.readDataToEndOfFile(); group.leave()
        }
        do {
            try process.run()
        } catch {
            return .unavailable
        }
        if group.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            _ = group.wait(timeout: .now() + 2)
        }
        process.waitUntilExit()
        return HostCommandResult(
            exitCode: process.terminationStatus,
            standardOutput: bounded(outData),
            standardError: bounded(errData)
        )
    }

    private func bounded(_ data: Data) -> String {
        String(decoding: data.prefix(maximumOutputBytes), as: UTF8.self)
    }
}

/// Test double: matches a captured fixture by command `label` (falling back to a
/// closure), so per-check unit tests feed synthetic output.
public struct FakeCommandRunner: CommandRunning {
    public var byLabel: [String: HostCommandResult]
    public var fallback: @Sendable (HostCommand) -> HostCommandResult

    public init(
        _ byLabel: [String: HostCommandResult] = [:],
        fallback: @escaping @Sendable (HostCommand) -> HostCommandResult = { _ in .unavailable }
    ) {
        self.byLabel = byLabel
        self.fallback = fallback
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
    /// Follows no symlinks; bounded read; nil if unreadable.
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
    public func readText(_ path: String, maxBytes: Int = 1_048_576) -> String? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var buffer = [UInt8](repeating: 0, count: maxBytes)
        let n = read(fd, &buffer, maxBytes)
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
    public var homeDirectory: String

    public init(
        texts: [String: String] = [:],
        plists: [String: Any] = [:],
        perms: [String: HostFilePermissions] = [:],
        entries: [String: [String]] = [:],
        executables: Set<String> = [],
        directories: Set<String> = [],
        homeDirectory: String = "/Users/tester"
    ) {
        self.texts = texts
        self.plists = plists
        self.perms = perms
        self.entries = entries
        self.executables = executables
        self.directories = directories
        self.homeDirectory = homeDirectory
    }
    public func fileExists(_ path: String) -> Bool {
        texts[path] != nil || plists[path] != nil || perms[path] != nil
            || executables.contains(path) || directories.contains(path) || entries[path] != nil
    }
    public func isExecutableFile(_ path: String) -> Bool { executables.contains(path) }
    public func isDirectory(_ path: String) -> Bool { directories.contains(path) }
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
    /// Last time the online version catalog was reachable (offline-currency).
    public var lastVersionCheckHint: String?
    /// Findings the user accepted as documented risks (suppress re-nagging).
    public var exemptions: [String: TriageRecord]
    /// Findings the user deferred as TODOs (weekly notification reminders).
    public var todos: [String: TriageRecord]

    public init(
        entries: [String: BaselineEntry] = [:],
        lastVersionCheckHint: String? = nil,
        exemptions: [String: TriageRecord] = [:],
        todos: [String: TriageRecord] = [:]
    ) {
        self.entries = entries
        self.lastVersionCheckHint = lastVersionCheckHint
        self.exemptions = exemptions
        self.todos = todos
    }

    private enum CodingKeys: String, CodingKey {
        case entries, lastVersionCheckHint, exemptions, todos
    }

    // Custom decode so an existing baseline file predating the triage maps still
    // loads (missing dictionaries default to empty).
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        entries = try c.decodeIfPresent([String: BaselineEntry].self, forKey: .entries) ?? [:]
        lastVersionCheckHint = try c.decodeIfPresent(String.self, forKey: .lastVersionCheckHint)
        exemptions = try c.decodeIfPresent([String: TriageRecord].self, forKey: .exemptions) ?? [:]
        todos = try c.decodeIfPresent([String: TriageRecord].self, forKey: .todos) ?? [:]
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(entries, forKey: .entries)
        try c.encodeIfPresent(lastVersionCheckHint, forKey: .lastVersionCheckHint)
        try c.encode(exemptions, forKey: .exemptions)
        try c.encode(todos, forKey: .todos)
    }
}

public protocol BaselineStoring: Sendable {
    func load() -> HostAuditBaseline
    func save(_ baseline: HostAuditBaseline)
}

/// Durable, value-free baseline at
/// `~/Library/Application Support/ConvenientSecurity/host-audit-baseline.json`,
/// written atomically with owner-only permissions.
public struct FileBaselineStore: BaselineStoring {
    private let path: String
    public init(homeDirectory: String = NSHomeDirectory()) {
        self.path = "\(homeDirectory)/Library/Application Support/ConvenientSecurity/host-audit-baseline.json"
    }
    public func load() -> HostAuditBaseline {
        guard let data = FileManager.default.contents(atPath: path),
              let baseline = try? JSONDecoder().decode(HostAuditBaseline.self, from: data) else {
            return HostAuditBaseline()
        }
        return baseline
    }
    public func save(_ baseline: HostAuditBaseline) {
        let dir = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        guard let data = try? encoder.encode(baseline) else { return }
        let tmp = "\(path).\(UUID().uuidString)"
        guard FileManager.default.createFile(atPath: tmp, contents: data, attributes: [.posixPermissions: 0o600]) else { return }
        _ = try? FileManager.default.replaceItemAt(URL(fileURLWithPath: path), withItemAt: URL(fileURLWithPath: tmp))
    }
}

public final class InMemoryBaselineStore: BaselineStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var baseline: HostAuditBaseline
    public init(_ baseline: HostAuditBaseline = HostAuditBaseline()) { self.baseline = baseline }
    public func load() -> HostAuditBaseline { lock.lock(); defer { lock.unlock() }; return baseline }
    public func save(_ baseline: HostAuditBaseline) { lock.lock(); self.baseline = baseline; lock.unlock() }
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

    public init(
        commands: CommandRunning,
        privileged: PrivilegedHostOps,
        tcc: TCCReading,
        files: FileInspecting,
        environment: [String: String],
        baseline: BaselineStoring,
        selfIdentity: HostSelfIdentity = .product,
        options: HostAuditOptions = HostAuditOptions()
    ) {
        self.commands = commands
        self.privileged = privileged
        self.tcc = tcc
        self.files = files
        self.environment = environment
        self.baseline = baseline
        self.selfIdentity = selfIdentity
        self.options = options
    }

    /// The production context csecd assembles: real command runner, root-helper
    /// privileged ops, FDA-gated TCC reader, real filesystem, durable baseline.
    public static func production(
        rootHelper: RootHelperClient,
        options: HostAuditOptions = HostAuditOptions()
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
            baseline: FileBaselineStore(),
            options: options
        )
    }
}
