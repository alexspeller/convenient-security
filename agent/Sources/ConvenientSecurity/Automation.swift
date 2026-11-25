import Foundation
import Security
import CSECBuildIdentity

/// The deliberately weaker consumer boundary for unattended scripts. The
/// interpreter is still path/signature bound where possible, but the script,
/// modules, native add-ons, and ordinary inputs below `workingDirectory` remain
/// mutable. This is never inferred from an ordinary access request: one attended
/// enrollment must opt into it for an exact command and exact references.
public enum AutomationConsumerTrust: String, Codable, Sendable {
    case mutableInterpreted = "mutable_interpreted"
}

/// Automation inherits the trigger process's useful non-secret environment only
/// after removing loader/injection controls. Environment contents are explicitly
/// not an integrity boundary for a mutable interpreted job.
public enum AutomationEnvironmentMode: String, Codable, Sendable {
    case sanitizedTrigger = "sanitized_trigger"
}

public struct AutomationCommand: Codable, Sendable, Equatable {
    public static let maximumArgumentCount = 64
    public static let maximumArgumentBytes = 1_024
    public static let maximumCommandBytes = 8 * 1_024

    public let executable: PlannedExecutable
    /// A framework Python first executes this launcher, then replaces its image
    /// with `executable` (Python.app) in the same PID. Both identities are pinned.
    /// Absent on older jobs and commands that do not re-exec.
    public let launcherExecutable: PlannedExecutable?
    /// The stored argv. argv[0] is the absolute path the job was enrolled
    /// with, symlinks kept, so an interpreter that locates itself from
    /// argv[0] (a Python virtual environment's `bin/python`) still does; the
    /// runner uses `executionPath`, and a run is refused unless argv[0] still
    /// resolves to exactly the enrolled launcher or interpreter.
    public let commandLine: [String]
    public let workingDirectory: String
    public let commandDigest: String
    public let environmentMode: AutomationEnvironmentMode

    public init(
        executable: PlannedExecutable,
        commandLine: [String],
        workingDirectory: String,
        commandDigest: String,
        environmentMode: AutomationEnvironmentMode = .sanitizedTrigger,
        launcherExecutable: PlannedExecutable? = nil
    ) {
        self.executable = executable
        self.launcherExecutable = launcherExecutable
        self.commandLine = commandLine
        self.workingDirectory = workingDirectory
        self.commandDigest = commandDigest
        self.environmentMode = environmentMode
    }

    public var displayCommand: String {
        ReviewDisplay.commandLine(commandLine)
    }

    /// Framework Python uses _NSGetExecutablePath, rather than argv[0], to find
    /// a venv. Execute its invoked symlink, whose resolved identity csecd checks.
    public var executionPath: String {
        launcherExecutable == nil ? executable.canonicalPath : commandLine[0]
    }

    public var isWellFormed: Bool {
        guard Self.validExecutable(executable),
              commandLine.count > 0,
              commandLine.count <= Self.maximumArgumentCount,
              commandLine[0].hasPrefix("/"),
              commandLine.allSatisfy({
                  $0.utf8.count <= Self.maximumArgumentBytes
                      && !$0.utf8.contains(0)
                      && ReviewDisplay.sanitized($0) == $0
              }),
              commandLine.reduce(0, { $0 + $1.utf8.count }) <= Self.maximumCommandBytes,
              workingDirectory.hasPrefix("/"),
              workingDirectory.utf8.count <= 4_096,
              ReviewDisplay.sanitized(workingDirectory) == workingDirectory,
              Self.isSHA256(commandDigest),
              (try? ExecutableInspection.commandDigest(commandLine)) == commandDigest,
              validLauncher else { return false }
        return true
    }

    /// Preserve ordinary cron configuration while removing environment controls
    /// that can replace the selected interpreter image or preload executable code.
    /// Secret values must continue to travel through the language client, never
    /// through this environment.
    public static func sanitizedEnvironment(
        _ environment: [String: String]
    ) -> [String: String] {
        let denied: Set<String> = [
            "NODE_OPTIONS", "NODE_PATH",
            "BUN_OPTIONS",
            "PYTHONHOME", "PYTHONPATH", "PYTHONINSPECT", "PYTHONSTARTUP",
            "RUBYOPT", "RUBYLIB",
            "PERL5OPT", "PERL5LIB",
        ]
        return ProtectedLaunchPlan.sanitizedEnvironment(environment).filter {
            !denied.contains($0.key)
        }
    }

    private var validLauncher: Bool {
        guard let launcherExecutable else { return true }
        return Self.validExecutable(launcherExecutable)
            && launcherExecutable.cdHash != nil && executable.cdHash != nil
            && ExecutableInspection.pythonFrameworkConsumerPath(
                forLauncherPath: launcherExecutable.canonicalPath
            ) == executable.canonicalPath
    }

    private static func validExecutable(_ executable: PlannedExecutable) -> Bool {
        executable.assurance == .unverified
            && executable.canonicalPath.hasPrefix("/")
            && executable.canonicalPath.utf8.count <= 4_096
            && ReviewDisplay.sanitized(executable.canonicalPath) == executable.canonicalPath
            && (executable.signingIdentifier.map {
                !$0.isEmpty && $0.utf8.count <= 512 && !$0.utf8.contains(0)
            } ?? true)
            && (executable.teamIdentifier.map {
                !$0.isEmpty && $0.utf8.count <= 128 && !$0.utf8.contains(0)
            } ?? true)
            && (executable.cdHash.map {
                !$0.isEmpty && $0.utf8.count <= 128
                    && $0.utf8.allSatisfy(Self.isLowerHex)
            } ?? true)
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy(isLowerHex)
    }

    private static func isLowerHex(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}

public struct AutomationEnrollment: Codable, Sendable, Equatable {
    public let name: String
    public let reason: String
    public let references: [String]
    public let command: AutomationCommand
    /// Zero permits every trigger. A positive value rate-limits cron/launchd
    /// retries in daemon memory without turning the job name into a bearer token.
    public let minimumIntervalSeconds: Int
    /// Wall-clock (awake-time) cap on a single run, or nil for a daemon that runs
    /// process-lifetime — auth once at enrollment, secrets stay available for as
    /// long as the daemon process lives, no runtime kill. A bounded cap remains
    /// justified for an unattended cron run (a hung run with no human present).
    public let maximumRuntimeSeconds: Int?
    public let consumerTrust: AutomationConsumerTrust

    public init(
        name: String,
        reason: String,
        references: [String],
        command: AutomationCommand,
        minimumIntervalSeconds: Int = 0,
        maximumRuntimeSeconds: Int? = 12 * 60 * 60,
        consumerTrust: AutomationConsumerTrust = .mutableInterpreted
    ) {
        self.name = name
        self.reason = reason
        self.references = references
        self.command = command
        self.minimumIntervalSeconds = minimumIntervalSeconds
        self.maximumRuntimeSeconds = maximumRuntimeSeconds
        self.consumerTrust = consumerTrust
    }
}

/// Persistent, value-free authorization metadata. This records only canonical
/// SecretRefs and the exact job recipe; provider-private identifiers and resolved
/// values live in neither this type nor its store.
public struct AutomationJob: Codable, Sendable, Equatable, Identifiable {
    public let id: String
    public let revision: String
    public let name: String
    public let reason: String
    public let references: [String]
    public let command: AutomationCommand
    public let minimumIntervalSeconds: Int
    /// Awake-time cap on a single run, or nil for a process-lifetime daemon job
    /// (see `AutomationEnrollment.maximumRuntimeSeconds`).
    public let maximumRuntimeSeconds: Int?
    public let consumerTrust: AutomationConsumerTrust
    public let createdAt: Date
    public let updatedAt: Date

    public init(
        id: String,
        revision: String,
        name: String,
        reason: String,
        references: [String],
        command: AutomationCommand,
        minimumIntervalSeconds: Int,
        maximumRuntimeSeconds: Int?,
        consumerTrust: AutomationConsumerTrust,
        createdAt: Date,
        updatedAt: Date
    ) {
        self.id = id
        self.revision = revision
        self.name = name
        self.reason = reason
        self.references = references
        self.command = command
        self.minimumIntervalSeconds = minimumIntervalSeconds
        self.maximumRuntimeSeconds = maximumRuntimeSeconds
        self.consumerTrust = consumerTrust
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    public var isWellFormed: Bool {
        guard let canonicalID = UUID(uuidString: id)?.uuidString.lowercased(),
              canonicalID == id,
              let canonicalRevision = UUID(uuidString: revision)?.uuidString.lowercased(),
              canonicalRevision == revision,
              Self.validName(name),
              !reason.isEmpty,
              reason.utf8.count <= 512,
              !reason.utf8.contains(0),
              ReviewDisplay.sanitized(reason) == reason,
              !references.isEmpty,
              references.count <= 64,
              Set(references).count == references.count,
              references == references.sorted(),
              references.allSatisfy({ raw in
                  guard let ref = try? SecretRef(raw) else { return false }
                  return ref.uri == raw
              }),
              command.isWellFormed,
              minimumIntervalSeconds >= 0,
              minimumIntervalSeconds <= 30 * 24 * 60 * 60,
              // nil ⇒ process-lifetime daemon; a bounded cap is positive and ≤ 24h.
              (maximumRuntimeSeconds.map { $0 > 0 && $0 <= 24 * 60 * 60 } ?? true),
              consumerTrust == .mutableInterpreted,
              createdAt <= updatedAt else { return false }
        return true
    }

    public static func validName(_ value: String) -> Bool {
        let bytes = Array(value.utf8)
        guard !bytes.isEmpty, bytes.count <= 64 else { return false }
        return bytes.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122) || $0 == 45 || $0 == 46 || $0 == 95
        }
    }
}

public enum AutomationAction: String, Codable, Sendable {
    case enroll
    case list
    case beginRun = "begin_run"
    case finishRun = "finish_run"
    /// A launcher asks a restarted csecd whether its run's lease came back,
    /// before it scans output with that csecd again.
    case resumeRun = "resume_run"
    case revoke
}

public struct AutomationRequest: Codable, Sendable {
    public let requestID: String
    public let action: AutomationAction
    public let enrollment: AutomationEnrollment?
    public let name: String?
    public let runID: String?

    public init(
        action: AutomationAction,
        enrollment: AutomationEnrollment? = nil,
        name: String? = nil,
        runID: String? = nil,
        requestID: UUID = UUID()
    ) {
        self.requestID = requestID.uuidString.lowercased()
        self.action = action
        self.enrollment = enrollment
        self.name = name
        self.runID = runID
    }
}

public struct AutomationRunAuthorization: Codable, Sendable, Equatable {
    public let runID: String
    public let job: AutomationJob
    /// Awake seconds the lease stays releasable, on the clock the runner caps
    /// the command with (`AutomationClock.awake`). A wall-clock deadline would
    /// expire during sleep while the capped command lived on, and its late
    /// bridge would then look like an ordinary attended caller. nil for a
    /// process-lifetime daemon run: the lease stays releasable for as long as the
    /// launcher process lives, and the runner applies no runtime kill.
    public let remainingRuntimeSeconds: TimeInterval?

    public init(runID: String, job: AutomationJob, remainingRuntimeSeconds: TimeInterval?) {
        self.runID = runID
        self.job = job
        self.remainingRuntimeSeconds = remainingRuntimeSeconds
    }
}

/// Extra value-free material shown in the trusted csecd-owned review window.
public struct AutomationReviewDetails: Sendable {
    public let job: AutomationJob

    public init(job: AutomationJob) { self.job = job }
}

public enum AutomationServiceError: Error, LocalizedError, Sendable {
    case invalidRequest
    case unavailable
    case notFound
    case consentDenied
    case resolutionFailed
    /// A reference that cannot resolve, refused before the enrollment's
    /// review; carries `KnownAbsentReference.summary`.
    case referenceNotFound(String)
    /// References whose values are made per use and expire within the hour
    /// (a machine identity sign-in), which a stored materialization cannot
    /// keep fresh; refused before the review.
    case expiringValues([String])
    /// One-time codes, which need a person to approve each one, so no
    /// unattended job may hold them; refused before the review.
    case oneTimeCodes([String])
    case alreadyRunning
    case materializationUnavailable
    case executableChanged
    case runExpired
    case runInvalidated

    public var errorDescription: String? {
        switch self {
        case .invalidRequest: return "the automation request is invalid"
        case .unavailable: return "unattended automation storage is unavailable"
        case .notFound: return "the automation job was not found"
        case .consentDenied: return "automation enrollment was denied"
        case .resolutionFailed: return "one or more references could not be materialized"
        case let .referenceNotFound(summary): return "\(summary); nothing was asked"
        case let .expiringValues(references):
            return "\(references.joined(separator: ", ")) \(references.count == 1 ? "makes a value" : "make values") "
                + "per use that expire within the hour, which an unattended job's stored copy cannot keep fresh; "
                + "nothing was asked"
        case let .oneTimeCodes(references):
            return "\(references.joined(separator: ", ")) \(references.count == 1 ? "is a one-time code" : "are one-time codes"), "
                + "which a person approves each time, so no unattended job can hold "
                + "\(references.count == 1 ? "it" : "them"); nothing was asked"
        case .alreadyRunning: return "the automation job already has a live run"
        case .materializationUnavailable:
            return "the automation materialization is unavailable; unlock the Mac or refresh the job"
        case .executableChanged:
            return "the registered interpreter changed; enroll the job again"
        case .runExpired:
            return "the automation run exceeded its registered maximum runtime before this request"
        case .runInvalidated:
            return "the automation job was revoked or re-enrolled during this run"
        }
    }
}

public protocol AutomationGrantStore: Sendable {
    func load() async throws -> [AutomationJob]
    func store(_ jobs: [AutomationJob]) async throws
}

/// Resolved values are deliberately isolated behind a second store. The grant
/// catalog remains value-free and backend-neutral; a run can load this document
/// only after its complete job authorization has matched.
public struct AutomationMaterialization: Sendable {
    public static let maximumTotalValueBytes = 1024 * 1024

    public let jobID: String
    public let revision: String
    public let valuesByReference: [String: Data]

    public init(jobID: String, revision: String, valuesByReference: [String: Data]) {
        self.jobID = jobID
        self.revision = revision
        self.valuesByReference = valuesByReference
    }

    public func matches(_ job: AutomationJob) -> Bool {
        jobID == job.id
            && revision == job.revision
            && Set(valuesByReference.keys) == Set(job.references)
            && valuesByReference.values.reduce(0, { $0 + $1.count })
                <= Self.maximumTotalValueBytes
    }
}

public protocol AutomationMaterializationStore: Sendable {
    func store(_ materialization: AutomationMaterialization) async throws
    func load(jobID: String, revision: String) async throws -> AutomationMaterialization?
    func delete(jobID: String, revision: String) async throws
}

public actor InMemoryAutomationGrantStore: AutomationGrantStore {
    private var jobs: [AutomationJob]

    public init(jobs: [AutomationJob] = []) { self.jobs = jobs }
    public func load() -> [AutomationJob] { jobs }
    public func store(_ jobs: [AutomationJob]) { self.jobs = jobs }
}

public actor InMemoryAutomationMaterializationStore: AutomationMaterializationStore {
    private var values: [String: AutomationMaterialization] = [:]

    public init() {}

    public func store(_ materialization: AutomationMaterialization) {
        values[Self.key(materialization.jobID, materialization.revision)] = materialization
    }

    public func load(jobID: String, revision: String) -> AutomationMaterialization? {
        values[Self.key(jobID, revision)]
    }

    public func delete(jobID: String, revision: String) {
        values[Self.key(jobID, revision)] = nil
    }

    private static func key(_ jobID: String, _ revision: String) -> String {
        "\(jobID):\(revision)"
    }
}

/// Value-free job catalog in csecd's data-protection Keychain group. It is
/// device-only and readable after the first unlock so launchd/cron can operate
/// while the screen is locked.
public struct SecurityAutomationGrantStore: AutomationGrantStore {
    public static let service = CSECBuildIdentity.named("automation-grants")
    private static let account = "catalog-v1"
    private static let maximumBytes = 512 * 1_024
    private let queue = DispatchQueue(
        label: CSECBuildIdentity.named("automation-grants-keychain")
    )

    public init() {}

    public func load() async throws -> [AutomationJob] {
        try await blocking {
            var query = identity()
            query[kSecReturnData as String] = true
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess:
                guard let data = result as? Data, data.count <= Self.maximumBytes else {
                    throw AutomationServiceError.unavailable
                }
                let document = try JSONDecoder().decode(AutomationGrantDocument.self, from: data)
                guard document.version == 1,
                      document.jobs.count <= 128,
                      document.jobs.allSatisfy(\.isWellFormed),
                      Set(document.jobs.map(\.name)).count == document.jobs.count else {
                    throw AutomationServiceError.unavailable
                }
                return document.jobs
            case errSecItemNotFound:
                return []
            default:
                throw KeychainError(operation: "automation grant read", status: status)
            }
        }
    }

    public func store(_ jobs: [AutomationJob]) async throws {
        guard jobs.count <= 128,
              jobs.allSatisfy(\.isWellFormed),
              Set(jobs.map(\.name)).count == jobs.count else {
            throw AutomationServiceError.invalidRequest
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(AutomationGrantDocument(jobs: jobs))
        guard data.count <= Self.maximumBytes else { throw AutomationServiceError.unavailable }
        try await blocking {
            var query = identity()
            let updated = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            if updated == errSecSuccess { return }
            guard updated == errSecItemNotFound else {
                throw KeychainError(operation: "automation grant update", status: updated)
            }
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            query[kSecValueData as String] = data
            let added = SecItemAdd(query as CFDictionary, nil)
            guard added == errSecSuccess else {
                throw KeychainError(operation: "automation grant add", status: added)
            }
        }
    }

    private func identity() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: Self.account,
        ]
    }

    private func blocking<T: Sendable>(
        _ body: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result { try body() }) }
        }
    }
}

/// Automation-only value copies. They use a separate service/account namespace
/// from grants, never synchronize or migrate, and are inaccessible before the
/// first device unlock after boot. Revocation invalidates its live lease before
/// deleting this item, so catalog cleanup can be retried without an orphaned
/// value copy if the operation is interrupted.
public struct SecurityAutomationMaterializationStore: AutomationMaterializationStore {
    public static let service = CSECBuildIdentity.named("automation-materializations")
    private static let maximumEncodedBytes = 2 * 1_024 * 1_024
    private let queue = DispatchQueue(
        label: CSECBuildIdentity.named("automation-materialization-keychain")
    )

    public init() {}

    public func store(_ materialization: AutomationMaterialization) async throws {
        guard validUUID(materialization.jobID), validUUID(materialization.revision),
              materialization.valuesByReference.count <= 64,
              materialization.valuesByReference.keys.allSatisfy({
                  (try? SecretRef($0))?.uri == $0
              }),
              materialization.valuesByReference.values.reduce(0, { $0 + $1.count })
                <= AutomationMaterialization.maximumTotalValueBytes else {
            throw AutomationServiceError.invalidRequest
        }
        let document = AutomationMaterializationDocument(materialization)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(document)
        guard data.count <= Self.maximumEncodedBytes else {
            throw AutomationServiceError.unavailable
        }
        let account = Self.account(materialization.jobID, materialization.revision)
        try await blocking {
            var query = identity(account)
            let updated = SecItemUpdate(
                query as CFDictionary,
                [kSecValueData as String: data] as CFDictionary
            )
            if updated == errSecSuccess { return }
            guard updated == errSecItemNotFound else {
                throw KeychainError(operation: "automation materialization update", status: updated)
            }
            query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            query[kSecValueData as String] = data
            let added = SecItemAdd(query as CFDictionary, nil)
            guard added == errSecSuccess else {
                throw KeychainError(operation: "automation materialization add", status: added)
            }
        }
    }

    public func load(
        jobID: String,
        revision: String
    ) async throws -> AutomationMaterialization? {
        guard validUUID(jobID), validUUID(revision) else {
            throw AutomationServiceError.invalidRequest
        }
        return try await blocking {
            var query = identity(Self.account(jobID, revision))
            query[kSecReturnData as String] = true
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            switch status {
            case errSecSuccess:
                guard let data = result as? Data, data.count <= Self.maximumEncodedBytes else {
                    throw AutomationServiceError.materializationUnavailable
                }
                let document = try JSONDecoder().decode(
                    AutomationMaterializationDocument.self, from: data
                )
                guard document.version == 1,
                      document.jobID == jobID,
                      document.revision == revision else {
                    throw AutomationServiceError.materializationUnavailable
                }
                return AutomationMaterialization(
                    jobID: document.jobID,
                    revision: document.revision,
                    valuesByReference: document.valuesByReference
                )
            case errSecItemNotFound:
                return nil
            default:
                throw KeychainError(operation: "automation materialization read", status: status)
            }
        }
    }

    public func delete(jobID: String, revision: String) async throws {
        guard validUUID(jobID), validUUID(revision) else { return }
        try await blocking {
            let status = SecItemDelete(
                identity(Self.account(jobID, revision)) as CFDictionary
            )
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw KeychainError(
                    operation: "automation materialization delete", status: status
                )
            }
        }
    }

    private func identity(_ account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrSynchronizable as String: false,
            kSecAttrService as String: Self.service,
            kSecAttrAccount as String: account,
        ]
    }

    private static func account(_ jobID: String, _ revision: String) -> String {
        "\(jobID):\(revision)"
    }

    private func validUUID(_ value: String) -> Bool {
        UUID(uuidString: value)?.uuidString.lowercased() == value
    }

    private func blocking<T: Sendable>(
        _ body: @escaping @Sendable () throws -> T
    ) async throws -> T {
        try await withCheckedThrowingContinuation { continuation in
            queue.async { continuation.resume(with: Result { try body() }) }
        }
    }
}

public protocol AutomationProcessInspecting: Sendable {
    func startTime(of pid: pid_t) async -> UInt64?
    func parent(of pid: pid_t) async -> pid_t?
    func executablePath(of pid: pid_t) async -> String?
    func inspectedExecutable(path: String) async -> PlannedExecutable?
}

public struct SystemAutomationProcessInspector: AutomationProcessInspecting {
    public init() {}

    public func startTime(of pid: pid_t) async -> UInt64? {
        ProcessAncestry.startTime(of: pid)
    }

    public func parent(of pid: pid_t) async -> pid_t? {
        ProcessAncestry.parent(of: pid)
    }

    public func executablePath(of pid: pid_t) async -> String? {
        ProcessAncestry.executablePath(of: pid)
    }

    public func inspectedExecutable(path: String) async -> PlannedExecutable? {
        guard let inspected = try? ExecutableInspection.plannedExecutable(
            command: path, mutableInterpreter: true
        ) else {
            return nil
        }
        return PlannedExecutable(
            canonicalPath: inspected.canonicalPath,
            signingIdentifier: inspected.signingIdentifier,
            teamIdentifier: inspected.teamIdentifier,
            cdHash: inspected.cdHash,
            assurance: .unverified
        )
    }
}

/// One reading of both clocks the automation service consults. Wall time
/// orders enrollments and rate-limits triggers, which is how cron thinks about
/// an interval. Awake time bounds a run lease: it is the clock the signed
/// runner caps the command with, so a Mac that sleeps mid-run neither expires
/// a lease the runner still honours nor extends one through a wall-clock
/// correction.
public struct AutomationClock: Sendable, Equatable {
    public let wall: Date
    /// Seconds the system has been awake since boot (`ProcessInfo.systemUptime`).
    /// It does not advance while the Mac sleeps.
    public let awake: TimeInterval

    public init(wall: Date, awake: TimeInterval) {
        self.wall = wall
        self.awake = awake
    }

    public static func now() -> AutomationClock {
        AutomationClock(wall: Date(), awake: ProcessInfo.processInfo.systemUptime)
    }
}

public enum AutomationRunDecision: Sendable {
    case started(AutomationRunAuthorization)
    case skipped(nextEligibleAt: Date)
}

public enum AutomationAccessDecision: Sendable {
    case notApplicable
    /// `expiresAt` is nil for a process-lifetime daemon run: the release stays
    /// valid for as long as the launcher process lives, with no clock expiry.
    case allowed(values: [String: Data], expiresAt: Date?)
    case denied(AutomationServiceError)
}

/// Owns persistent until-revoked automation grants and the run leases, which
/// are written behind (value-free) so a restarted csecd can restore them.
/// A job name/run UUID is a lookup hint, never a bearer capability: release is
/// authorized by the live signed launcher's PID/start-time, exact direct child,
/// exact stored interpreter identity, and exact canonical references.
public actor AutomationService {
    private struct LauncherIncarnation: Hashable, Sendable {
        let pid: pid_t
        let startTime: UInt64
    }

    /// One trigger's lease. Once it stops being releasable while its launcher
    /// may still be alive — expired, revoked, or re-enrolled — the entry stays
    /// as a value-free tombstone until that launcher exits, so a late bridge
    /// from its child is still recognised as automation and gets the typed
    /// reason instead of falling through to the attended review. Its
    /// value-free half is persisted (`PersistedAutomationRun`), so a csecd
    /// restart does not strand a launcher that outlives it.
    private struct RunLease: Sendable {
        let runID: String
        let jobName: String
        let jobID: String
        let revision: String
        /// nil only for a tombstone restored after its job was revoked.
        let job: AutomationJob?
        let launcherPID: pid_t
        let launcherStartTime: UInt64
        let auditSessionID: UInt32?
        /// Awake-time deadline (`AutomationClock.awake`), shared with the
        /// runner's runtime cap. nil for a process-lifetime daemon run: no clock
        /// deadline — the launcher-liveness prune is the sole bound.
        let expiresAtAwake: TimeInterval?
        private(set) var invalidation: AutomationServiceError?
        private(set) var valuesByReference: [String: Data]
        /// The record a tombstone was restored from when restoring it live
        /// failed only for want of the Keychain (the catalog or the
        /// materialization could not be read). It is written back unchanged,
        /// so a later csecd that can read them re-checks it rather than
        /// finding it already invalidated.
        private(set) var retainedRecord: PersistedAutomationRun?

        init(
            runID: String,
            job: AutomationJob,
            launcherPID: pid_t,
            launcherStartTime: UInt64,
            auditSessionID: UInt32?,
            expiresAtAwake: TimeInterval?,
            valuesByReference: [String: Data]
        ) {
            self.runID = runID
            self.jobName = job.name
            self.jobID = job.id
            self.revision = job.revision
            self.job = job
            self.launcherPID = launcherPID
            self.launcherStartTime = launcherStartTime
            self.auditSessionID = auditSessionID
            self.expiresAtAwake = expiresAtAwake
            self.invalidation = nil
            self.valuesByReference = valuesByReference
            self.retainedRecord = nil
        }

        /// A tombstone for a persisted run whose job no longer releases it,
        /// or, when `retained`, whose job could not be read this time.
        init(
            tombstone record: PersistedAutomationRun,
            reason: AutomationServiceError,
            retained: Bool = false
        ) {
            self.runID = record.runID
            self.jobName = record.jobName
            self.jobID = record.jobID
            self.revision = record.revision
            self.job = nil
            self.launcherPID = record.launcherPID
            self.launcherStartTime = record.launcherStartTime
            self.auditSessionID = record.auditSessionID
            self.expiresAtAwake = record.expiresAtAwake
            self.invalidation = reason
            self.valuesByReference = [:]
            self.retainedRecord = retained ? record : nil
        }

        var isLive: Bool { invalidation == nil }

        mutating func invalidate(_ reason: AutomationServiceError) {
            invalidation = reason
            valuesByReference = [:]
            retainedRecord = nil
        }

        func persisted(bootSessionUUID: String?) -> PersistedAutomationRun {
            if let retainedRecord { return retainedRecord }
            let recorded: PersistedAutomationRun.Invalidation?
            switch invalidation {
            case nil: recorded = nil
            case .runExpired?: recorded = .expired
            default: recorded = .invalidated
            }
            return PersistedAutomationRun(
                runID: runID,
                jobName: jobName,
                jobID: jobID,
                revision: revision,
                launcherPID: launcherPID,
                launcherStartTime: launcherStartTime,
                auditSessionID: auditSessionID,
                expiresAtAwake: expiresAtAwake,
                invalidation: recorded,
                bootSessionUUID: bootSessionUUID
            )
        }
    }

    private let resolver: SecretResolver
    private let grantStore: any AutomationGrantStore
    private let materializationStore: any AutomationMaterializationStore
    private let consent: any ConsentProvider
    private let policyReview: any PolicyReviewProvider
    private let processInspector: any AutomationProcessInspecting
    private let requestProcessInspection: ProcessInspection
    private let terminalInspection: TerminalSessionInspector
    private let clock: @Sendable () -> AutomationClock
    private var loadedJobs: [String: AutomationJob]?
    private var runLeases: [String: RunLease] = [:]
    private var lastStartedAt: [String: Date] = [:]
    /// Actor methods are reentrant while awaiting Keychain, policy, or process
    /// inspection. These reservations make each catalog mutation and each run
    /// start atomic without serializing independent jobs for their full run.
    private var catalogMutationInProgress = false
    private var jobMutationsInProgress: Set<String> = []
    private var runStartsInProgress: Set<String> = []
    private var launcherStartsInProgress: Set<LauncherIncarnation> = []
    /// Where enrollment panels are recorded (the `automation` surface).
    private let decisionLog: DecisionLog?
    /// Which refusals before a panel this run has recorded.
    private var absentReferenceRecords = AbsentReferenceRecords()
    /// Where run leases persist across a csecd restart; nil keeps them in
    /// memory only. Nothing is written until `restoreRuns` has read the item,
    /// so a fresh csecd never overwrites the leases it is about to restore.
    private let runStore: ProtectedStore<AutomationRunsDocument>?
    private let bootSessionUUID: String?
    private var runsRestored = false
    private var pendingRunWrite: Task<Void, Never>?

    public init(
        resolver: SecretResolver,
        grantStore: any AutomationGrantStore,
        materializationStore: any AutomationMaterializationStore,
        consent: any ConsentProvider,
        policyReview: any PolicyReviewProvider,
        processInspector: any AutomationProcessInspecting = SystemAutomationProcessInspector(),
        terminalInspection: TerminalSessionInspector,
        // An explicit @Sendable closure literal, not a bare `AutomationClock.now`
        // reference: an unapplied static-func value is not @Sendable, which warns
        // under strict concurrency. The literal captures nothing, so it is safe.
        clock: @escaping @Sendable () -> AutomationClock = { AutomationClock.now() },
        decisionLog: DecisionLog? = nil,
        runStore: ProtectedStore<AutomationRunsDocument>? = nil,
        bootSessionUUID: String? = CsecdRunFacts.bootSessionUUID(),
        requestProcessInspection: ProcessInspection = .live
    ) {
        self.decisionLog = decisionLog
        self.runStore = runStore
        self.bootSessionUUID = bootSessionUUID
        self.resolver = resolver
        self.grantStore = grantStore
        self.materializationStore = materializationStore
        self.consent = consent
        self.policyReview = policyReview
        self.processInspector = processInspector
        self.requestProcessInspection = requestProcessInspection
        self.terminalInspection = terminalInspection
        self.clock = clock
    }

    public func enroll(
        _ enrollment: AutomationEnrollment,
        caller: CallerInfo
    ) async throws -> AutomationJob {
        let result: Result<AutomationJob, Error> = await HumanWait.tracking(
            caller: caller, inspection: requestProcessInspection
        ) { caller in
            do { return .success(try await self.enrollPending(enrollment, caller: caller)) }
            catch { return .failure(error) }
        }
        return try result.get()
    }

    private func enrollPending(
        _ enrollment: AutomationEnrollment, caller: CallerInfo
    ) async throws -> AutomationJob {
        let normalized = try normalizedEnrollment(enrollment)
        guard await callerIsLive(caller) else {
            throw AutomationServiceError.executableChanged
        }
        guard !catalogMutationInProgress,
              !jobMutationsInProgress.contains(normalized.name),
              !runStartsInProgress.contains(normalized.name) else {
            throw AutomationServiceError.alreadyRunning
        }
        catalogMutationInProgress = true
        jobMutationsInProgress.insert(normalized.name)
        defer {
            catalogMutationInProgress = false
            jobMutationsInProgress.remove(normalized.name)
        }

        guard await commandIdentityMatches(normalized.command),
              directoryExists(normalized.command.workingDirectory) else {
            throw AutomationServiceError.executableChanged
        }

        let now = clock().wall
        let current = try await jobs()
        let previous = current[normalized.name]
        let candidate = AutomationJob(
            id: previous?.id ?? UUID().uuidString.lowercased(),
            revision: UUID().uuidString.lowercased(),
            name: normalized.name,
            reason: normalized.reason,
            references: normalized.references,
            command: normalized.command,
            minimumIntervalSeconds: normalized.minimumIntervalSeconds,
            maximumRuntimeSeconds: normalized.maximumRuntimeSeconds,
            consumerTrust: normalized.consumerTrust,
            createdAt: previous?.createdAt ?? now,
            updatedAt: max(previous?.createdAt ?? now, now)
        )
        guard candidate.isWellFormed else { throw AutomationServiceError.invalidRequest }

        let refs = candidate.references.compactMap { try? SecretRef($0) }
        guard refs.count == candidate.references.count else {
            throw AutomationServiceError.invalidRequest
        }
        let plan = DeliveryPlan(
            mechanism: .directHeap,
            executable: candidate.command.executable,
            root: .caller,
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: candidate.maximumRuntimeSeconds,
            operationContext: candidate.reason,
            commandDigest: candidate.command.commandDigest
        )
        // A job keeps the values it was enrolled with, so a sign-in made per
        // use would be expired by its next run: refused before any panel.
        let expiring = await resolver.referencesWithExpiringValues(refs)
        if !expiring.isEmpty { throw AutomationServiceError.expiringValues(expiring) }
        let codes = refs.filter(\.isOneTimeCode).map(\.uri)
        if !codes.isEmpty { throw AutomationServiceError.oneTimeCodes(codes) }
        // A job with a reference that cannot resolve could never be
        // materialized: say so before the panel rather than after its touch.
        if let summary = Agent.absentSummary(await resolver.referencesKnownAbsent(refs)) {
            if let decisionLog, let record = absentReferenceRecords.admit(DecisionLogRecord(
                kind: .absentReference, surface: .automation,
                requester: DecisionLogRecord.Requester(class: "automation", rootPID: caller.pid),
                refs: candidate.references.sorted(),
                mechanism: plan.mechanism.rawValue,
                commandDigest: candidate.command.commandDigest,
                detail: "enroll unattended job \(candidate.name): \(summary); refused before a panel"
            )) {
                await decisionLog.record(record)
            }
            throw AutomationServiceError.referenceNotFound(summary)
        }
        var reviewedCaller = caller
        reviewedCaller.terminal = await terminalInspection.context(forCallerPID: caller.pid)
        let review = AccessPolicyReview(
            caller: reviewedCaller,
            reason: candidate.reason,
            plan: plan,
            credentials: await resolver.reviewCredentials(
                for: CredentialGrouping.groups(for: refs).map(\.references)
            ),
            automation: AutomationReviewDetails(job: candidate)
        )
        let reviewOutcome = await policyReview.reviewAccess(review)
        guard case let .approved(approval) = reviewOutcome else {
            if case let .denied(reason) = reviewOutcome {
                let reason = HumanWait.current?.effectiveReason(reason) ?? reason
                let ended = DecisionLogRecord.outcome(for: reason)
                await decisionLog?.record(enrollmentRecord(
                    kind: DecisionLogRecord.kind(for: reason),
                    review: review, job: candidate, outcome: ended.outcome,
                    decider: ended.decider, ttdMs: ended.ttdMs,
                    failure: HumanWait.current?.abandonment != nil ? HumanWait.current?.withdrawnDetail() : nil
                ))
            }
            throw AutomationServiceError.consentDenied
        }

        let outcome: ConsentOutcome
        if let session = approval.authenticationSession {
            outcome = await session.completeAfterPolicyApproval(
                policySummary: "unattended mutable automation until revoked"
            )
        } else {
            outcome = await consent.requestConsent(
                caller: reviewedCaller,
                newReferences: refs,
                reason: candidate.reason,
                ttl: candidate.maximumRuntimeSeconds.map(TimeInterval.init),
                policySummary: "unattended mutable automation; persistent until revoked"
            )
        }
        guard case let .approved(unlock) = outcome else {
            await decisionLog?.record(enrollmentRecord(
                review: review, job: candidate, outcome: .authenticationFailed, decider: nil
            ))
            throw AutomationServiceError.consentDenied
        }
        // The approval is recorded once the enrollment it approved has
        // passed its identity checks and been stored, or with why it was not.
        let approved = DecisionLogRecord.outcome(for: approval)
        do {
            let job = try await completeApprovedEnrollment(
                candidate: candidate, refs: refs, unlock: unlock, caller: caller,
                current: current, previous: previous
            )
            await decisionLog?.record(enrollmentRecord(
                review: review, job: candidate, outcome: approved.outcome,
                decider: approved.decider, ttdMs: approved.ttdMs
            ))
            return job
        } catch {
            let why: String
            switch error as? AutomationServiceError {
            case .executableChanged?: why = "the caller or the job's command changed after approval"
            case .resolutionFailed?: why = "a reference could not be resolved"
            case .materializationUnavailable?: why = "the resolved values did not match the job"
            default: why = "the job could not be stored"
            }
            await decisionLog?.record(enrollmentRecord(
                review: review, job: candidate, outcome: approved.outcome,
                decider: approved.decider, ttdMs: approved.ttdMs,
                failure: "\(why); nothing was enrolled"
            ))
            throw error
        }
    }

    /// Everything an enrollment does after its approval: the identity checks
    /// on both sides of resolution, the materialization, and the catalog.
    private func completeApprovedEnrollment(
        candidate: AutomationJob,
        refs: [SecretRef],
        unlock: CacheUnlock?,
        caller: CallerInfo,
        current: [String: AutomationJob],
        previous: AutomationJob?
    ) async throws -> AutomationJob {
        guard await callerIsLive(caller),
              await commandIdentityMatches(candidate.command) else {
            throw AutomationServiceError.executableChanged
        }

        var values: [String: Data] = [:]
        for ref in refs {
            do {
                values[ref.uri] = try await resolver.resolve(ref, unlock: unlock)
            } catch {
                throw AutomationServiceError.resolutionFailed
            }
        }
        let materialization = AutomationMaterialization(
            jobID: candidate.id,
            revision: candidate.revision,
            valuesByReference: values
        )
        guard materialization.matches(candidate) else {
            throw AutomationServiceError.materializationUnavailable
        }
        guard await callerIsLive(caller),
              await commandIdentityMatches(candidate.command) else {
            throw AutomationServiceError.executableChanged
        }

        do {
            try await materializationStore.store(materialization)
            var next = current
            next[candidate.name] = candidate
            try await persist(next)
        } catch {
            try? await materializationStore.delete(
                jobID: candidate.id, revision: candidate.revision
            )
            throw AutomationServiceError.unavailable
        }
        if let previous, previous.revision != candidate.revision {
            try? await materializationStore.delete(
                jobID: previous.id, revision: previous.revision
            )
        }
        invalidateLeases(forJob: candidate.name)
        lastStartedAt[candidate.name] = nil
        return candidate
    }

    /// A value-free record of one enrollment panel: the job's name and
    /// references, never its environment or values.
    private func enrollmentRecord(
        kind: DecisionLogRecord.Kind = .panel,
        review: AccessPolicyReview,
        job: AutomationJob,
        outcome: DecisionLogRecord.Outcome,
        decider: DecisionLogRecord.Decider?,
        ttdMs: Int? = nil,
        failure: String? = nil
    ) -> DecisionLogRecord {
        DecisionLogRecord(
            kind: kind,
            surface: .automation,
            requester: DecisionLogRecord.Requester(
                class: "automation",
                rootPID: review.caller.pid,
                terminal: review.caller.terminal?.summary
            ),
            refs: job.references.sorted(),
            mechanism: review.plan.mechanism.rawValue,
            commandDigest: job.command.commandDigest,
            duration: "until_revoked",
            outcome: outcome,
            decider: decider,
            ttdMs: ttdMs,
            detail: "enroll unattended job \(job.name)" + (failure.map { ": \($0)" } ?? "")
        )
    }

    public func list() async throws -> [AutomationJob] {
        try await jobs().values.sorted { $0.name < $1.name }
    }

    public func revoke(
        name: String,
        caller: CallerInfo
    ) async throws -> AutomationJob {
        guard AutomationJob.validName(name), await callerIsLive(caller) else {
            throw AutomationServiceError.invalidRequest
        }
        guard !catalogMutationInProgress,
              !jobMutationsInProgress.contains(name),
              !runStartsInProgress.contains(name) else {
            throw AutomationServiceError.alreadyRunning
        }
        catalogMutationInProgress = true
        jobMutationsInProgress.insert(name)
        defer {
            catalogMutationInProgress = false
            jobMutationsInProgress.remove(name)
        }

        let current = try await jobs()
        guard let job = current[name] else { throw AutomationServiceError.notFound }
        var shown = caller
        shown.terminal = await terminalInspection.context(forCallerPID: caller.pid)
        let outcome = await consent.approveSettingsChange(
            SettingsChangeReviewDetails(
                title: "Revoke an Unattended Automation Job",
                changes: ["Revoke unattended automation job \(name): it can no longer start or use its references"]
            ),
            caller: shown
        )
        outcome.unlock?.invalidate()
        guard outcome.isApproved, await callerIsLive(caller) else {
            throw AutomationServiceError.consentDenied
        }

        var next = current
        next[name] = nil
        // Stop in-memory release first, then remove the value copy. If catalog
        // persistence is interrupted afterwards, the remaining metadata is
        // inert and a retry can complete the idempotent revoke.
        invalidateLeases(forJob: name)
        lastStartedAt[name] = nil
        // The tombstone is durable before the values go: a crash after a
        // failed delete must not restore the revoked run live. If it cannot
        // be written the values stay and the revoke fails, so a retry writes
        // it again; the leases are already dead in memory either way.
        do {
            try await commitPersistedRuns()
            try await materializationStore.delete(jobID: job.id, revision: job.revision)
            try await persist(next)
        } catch {
            throw AutomationServiceError.unavailable
        }
        return job
    }

    public func beginRun(
        name: String,
        caller: CallerInfo
    ) async throws -> AutomationRunDecision {
        guard AutomationJob.validName(name), await callerIsLive(caller) else {
            throw AutomationServiceError.invalidRequest
        }
        let launcher = LauncherIncarnation(pid: caller.pid, startTime: caller.startTime)
        guard !jobMutationsInProgress.contains(name),
              !runStartsInProgress.contains(name),
              !launcherStartsInProgress.contains(launcher) else {
            throw AutomationServiceError.alreadyRunning
        }
        runStartsInProgress.insert(name)
        launcherStartsInProgress.insert(launcher)
        defer {
            runStartsInProgress.remove(name)
            launcherStartsInProgress.remove(launcher)
        }

        await pruneRunLeases(awake: clock().awake)
        let current = try await jobs()
        guard let job = current[name] else { throw AutomationServiceError.notFound }
        guard await commandIdentityMatches(job.command),
              directoryExists(job.command.workingDirectory) else {
            throw AutomationServiceError.executableChanged
        }
        // Only a live lease is an overlapping run. A tombstone left by an
        // earlier trigger whose launcher is still winding down must not hold
        // the job's next trigger hostage.
        guard !runLeases.values.contains(where: { $0.isLive && $0.jobName == name }) else {
            throw AutomationServiceError.alreadyRunning
        }
        // One lease per launcher incarnation, tombstones included, so the
        // table is bounded by live launcher processes.
        guard !runLeases.values.contains(where: {
            $0.launcherPID == caller.pid && $0.launcherStartTime == caller.startTime
        }) else {
            throw AutomationServiceError.alreadyRunning
        }
        if job.minimumIntervalSeconds > 0,
           let last = lastStartedAt[name] {
            let next = last.addingTimeInterval(TimeInterval(job.minimumIntervalSeconds))
            if clock().wall < next { return .skipped(nextEligibleAt: next) }
        }

        let materialization: AutomationMaterialization
        do {
            guard let loaded = try await materializationStore.load(
                jobID: job.id, revision: job.revision
            ), loaded.matches(job) else {
                throw AutomationServiceError.materializationUnavailable
            }
            materialization = loaded
        } catch let error as AutomationServiceError {
            throw error
        } catch {
            throw AutomationServiceError.materializationUnavailable
        }
        guard await callerIsLive(caller) else {
            throw AutomationServiceError.executableChanged
        }

        // The lease clock starts only now. The interpreter check and Keychain
        // read above are csecd's cost, not the job's runtime, and the signed
        // bridge re-inspects the live interpreter at access time, so a second
        // identity check here would only shorten the lease.
        let started = clock()
        let runID = UUID().uuidString.lowercased()
        // nil ⇒ a process-lifetime daemon run: no awake deadline, no runner cap.
        let runtime = job.maximumRuntimeSeconds.map(TimeInterval.init)
        runLeases[runID] = RunLease(
            runID: runID,
            job: job,
            launcherPID: caller.pid,
            launcherStartTime: caller.startTime,
            auditSessionID: caller.peerIdentity?.audit.auditSessionID,
            expiresAtAwake: runtime.map { started.awake + $0 },
            valuesByReference: materialization.valuesByReference
        )
        persistRuns()
        lastStartedAt[name] = started.wall
        return .started(AutomationRunAuthorization(
            runID: runID, job: job, remainingRuntimeSeconds: runtime
        ))
    }

    /// The values a launcher's own live lease releases, for csecd's output
    /// redactor, or nil when this csecd holds no live lease for that run and
    /// launcher incarnation. A launcher that reopens its scanner after a csecd
    /// restart asks this first, so it never scans its command's output with a
    /// csecd that does not know the values the command may hold.
    public func resumeRun(
        runID: String,
        caller: CallerInfo
    ) async -> AutomationRunRestoration.Release? {
        let now = clock()
        await pruneRunLeases(awake: now.awake)
        guard UUID(uuidString: runID)?.uuidString.lowercased() == runID,
              await callerIsLive(caller),
              let lease = runLeases[runID],
              lease.isLive,
              lease.launcherPID == caller.pid,
              lease.launcherStartTime == caller.startTime else { return nil }
        return AutomationRunRestoration.Release(
            valuesByReference: lease.valuesByReference,
            expiresAt: lease.expiresAtAwake.map {
                now.wall.addingTimeInterval($0 - now.awake)
            }
        )
    }

    @discardableResult
    public func finishRun(runID: String, caller: CallerInfo) async -> Bool {
        guard UUID(uuidString: runID)?.uuidString.lowercased() == runID,
              let lease = runLeases[runID],
              lease.launcherPID == caller.pid,
              lease.launcherStartTime == caller.startTime else { return false }
        runLeases[runID] = nil
        persistRuns()
        return true
    }

    public func authorizeAccess(
        references: [SecretRef],
        plan: DeliveryPlan,
        caller: CallerInfo
    ) async -> AutomationAccessDecision {
        let clock = self.clock()
        await pruneRunLeases(awake: clock.awake)
        guard plan.mechanism == .directHeap,
              plan.descendantScope == .subtree,
              plan.destination == .localDevelopment,
              plan.executable.assurance == .unverified,
              case let .directParent(consumerPID, consumerStartTime) = plan.root else {
            return .notApplicable
        }

        guard await processInspector.startTime(of: consumerPID) == consumerStartTime,
              let consumerParent = await processInspector.parent(of: consumerPID) else {
            return .notApplicable
        }
        var matchedLease: RunLease?
        for lease in runLeases.values {
            let auditSessionMatches = lease.auditSessionID == nil
                || caller.peerIdentity?.audit.auditSessionID == lease.auditSessionID
            if auditSessionMatches && consumerParent == lease.launcherPID {
                matchedLease = lease
                break
            }
        }
        guard let lease = matchedLease else { return .notApplicable }

        // From here the consumer's parent is a leased automation launcher, so
        // every outcome is an automation decision and a typed denial is the
        // only failure. Falling through to the attended review would raise an
        // interactive prompt for a job enrolled precisely because nobody is
        // there to answer one.
        if let invalidation = lease.invalidation { return .denied(invalidation) }
        guard let job = lease.job else { return .denied(.runInvalidated) }
        // A bounded run must still be within its awake deadline; a process-
        // lifetime daemon run (nil) has no clock to check — launcher liveness,
        // rechecked below, is the sole bound.
        if let deadline = lease.expiresAtAwake, clock.awake >= deadline {
            return .denied(.runExpired)
        }
        guard await processInspector.startTime(of: lease.launcherPID)
                == lease.launcherStartTime,
              await processInspector.executablePath(of: consumerPID)
                == job.command.executable.canonicalPath,
              plan.executable == job.command.executable else {
            return .denied(.executableChanged)
        }
        let requested = Set(references.map(\.uri))
        guard !requested.isEmpty,
              requested.isSubset(of: Set(job.references)) else {
            return .denied(.invalidRequest)
        }
        let values = lease.valuesByReference.filter { requested.contains($0.key) }
        guard Set(values.keys) == requested,
              await processInspector.parent(of: consumerPID) == lease.launcherPID,
              await processInspector.startTime(of: consumerPID) == consumerStartTime,
              await processInspector.startTime(of: lease.launcherPID)
                == lease.launcherStartTime else {
            return .denied(.materializationUnavailable)
        }
        // Every process inspection above suspends this actor. Recheck the
        // memory lease without another await so a concurrent finish, revoke, or
        // re-enrollment cannot release a stale local copy after invalidation.
        guard let activeLease = runLeases[lease.runID] else {
            return .denied(.materializationUnavailable)
        }
        if let invalidation = activeLease.invalidation { return .denied(invalidation) }
        guard activeLease.revision == lease.revision,
              activeLease.launcherPID == lease.launcherPID,
              activeLease.launcherStartTime == lease.launcherStartTime else {
            return .denied(.materializationUnavailable)
        }
        return .allowed(
            values: values,
            // nil deadline ⇒ a process-lifetime daemon run: no wall-clock expiry.
            expiresAt: lease.expiresAtAwake.map {
                clock.wall.addingTimeInterval($0 - clock.awake)
            }
        )
    }

    private func normalizedEnrollment(
        _ enrollment: AutomationEnrollment
    ) throws -> AutomationEnrollment {
        guard AutomationJob.validName(enrollment.name),
              !enrollment.reason.isEmpty,
              enrollment.reason.utf8.count <= 512,
              !enrollment.reason.utf8.contains(0),
              ReviewDisplay.sanitized(enrollment.reason) == enrollment.reason,
              enrollment.command.isWellFormed,
              !enrollment.references.isEmpty,
              enrollment.references.count <= 64,
              enrollment.minimumIntervalSeconds >= 0,
              enrollment.minimumIntervalSeconds <= 30 * 24 * 60 * 60,
              // nil ⇒ process-lifetime daemon; a bounded cap is positive and ≤ 24h.
              (enrollment.maximumRuntimeSeconds.map { $0 > 0 && $0 <= 24 * 60 * 60 } ?? true),
              enrollment.consumerTrust == .mutableInterpreted else {
            throw AutomationServiceError.invalidRequest
        }
        let references = try enrollment.references.map { try SecretRef($0).uri }
        guard Set(references).count == references.count else {
            throw AutomationServiceError.invalidRequest
        }
        return AutomationEnrollment(
            name: enrollment.name,
            reason: enrollment.reason,
            references: references.sorted(),
            command: enrollment.command,
            minimumIntervalSeconds: enrollment.minimumIntervalSeconds,
            maximumRuntimeSeconds: enrollment.maximumRuntimeSeconds,
            consumerTrust: enrollment.consumerTrust
        )
    }

    private func jobs() async throws -> [String: AutomationJob] {
        if let loadedJobs { return loadedJobs }
        let loaded: [AutomationJob]
        do {
            loaded = try await grantStore.load()
        } catch {
            throw AutomationServiceError.unavailable
        }
        // Another reentrant call may have durably mutated and published the
        // catalog while this initial Keychain read was suspended. Never replace
        // that newer snapshot with the stale read result.
        if let loadedJobs { return loadedJobs }
        guard loaded.count <= 128,
              loaded.allSatisfy(\.isWellFormed),
              Set(loaded.map(\.name)).count == loaded.count else {
            throw AutomationServiceError.unavailable
        }
        let byName = Dictionary(uniqueKeysWithValues: loaded.map { ($0.name, $0) })
        loadedJobs = byName
        return byName
    }

    private func persist(_ jobs: [String: AutomationJob]) async throws {
        let ordered = jobs.values.sorted { $0.name < $1.name }
        try await grantStore.store(ordered)
        loadedJobs = jobs
    }

    private func callerIsLive(_ caller: CallerInfo) async -> Bool {
        guard caller.pid > 1, caller.startTime > 0,
              caller.requestAnchor?.abandonment(using: requestProcessInspection) == nil else { return false }
        return await processInspector.startTime(of: caller.pid) == caller.startTime
    }

    /// Inspects the job's argv[0], not its stored canonical path, so a run is
    /// refused both when the interpreter image changed and when argv[0] (a
    /// virtual environment's symlink) now leads to a different interpreter.
    private func commandIdentityMatches(_ command: AutomationCommand) async -> Bool {
        guard command.isWellFormed,
              let inspected = await processInspector.inspectedExecutable(
                path: command.commandLine[0]
              ) else { return false }
        guard inspected == (command.launcherExecutable ?? command.executable) else { return false }
        guard let launcher = command.launcherExecutable else { return true }
        guard let consumerPath = ExecutableInspection.pythonFrameworkConsumerPath(
                forLauncherPath: launcher.canonicalPath
              ), let consumer = await processInspector.inspectedExecutable(path: consumerPath) else {
            return false
        }
        return consumer == command.executable
    }

    private func directoryExists(_ path: String) -> Bool {
        var isDirectory = ObjCBool(false)
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
            && isDirectory.boolValue
    }

    /// A revoked or re-enrolled job's in-flight leases become tombstones: the
    /// launcher may still be supervising its child, and that child's late
    /// bridge must be told why rather than treated as an attended caller.
    private func invalidateLeases(forJob name: String) {
        var changed = false
        for (id, lease) in runLeases where lease.jobName == name && lease.isLive {
            runLeases[id]?.invalidate(.runInvalidated)
            changed = true
        }
        if changed { persistRuns() }
    }

    /// Drops leases whose launcher incarnation has exited and turns leases past
    /// their awake-time deadline into value-free tombstones. The table is
    /// mutated entry by entry: the process inspections suspend this actor, and
    /// a concurrent finish or start must be neither resurrected nor dropped by
    /// a wholesale replacement.
    private func pruneRunLeases(awake: TimeInterval) async {
        var changed = false
        for (id, lease) in runLeases {
            if await processInspector.startTime(of: lease.launcherPID)
                != lease.launcherStartTime, runLeases[id] != nil {
                runLeases[id] = nil
                changed = true
            }
        }
        // A process-lifetime daemon lease (nil deadline) never expires by clock;
        // the launcher-exit drop above is its only bound.
        for (id, lease) in runLeases
        where lease.isLive && (lease.expiresAtAwake.map { awake >= $0 } ?? false) {
            runLeases[id]?.invalidate(.runExpired)
            changed = true
        }
        if changed { persistRuns() }
    }

    /// Writes the leases behind, prepared in this synchronous section so a
    /// later change always supersedes an earlier one. A lost write only means
    /// a lease is not restored after a restart (its child then meets the
    /// attended review); it can never widen access, because `restoreRuns`
    /// re-checks every record against the launcher and the catalog.
    private func persistRuns() {
        guard let runStore, runsRestored,
              let change = try? runStore.prepare(runsDocument()) else { return }
        let previous = pendingRunWrite
        pendingRunWrite = Task {
            await previous?.value
            _ = try? await change.commit()
        }
    }

    /// Writes the leases as they are now, after every write prepared before,
    /// and throws unless this write, a later one, or the item's deletion
    /// landed: each leaves nothing that restores live a lease invalidated
    /// in memory.
    private func commitPersistedRuns() async throws {
        guard let runStore, runsRestored else { return }
        let change = try runStore.prepare(runsDocument())
        let previous = pendingRunWrite
        let write = Task {
            await previous?.value
            do {
                try await change.commit()
            } catch ProtectedStoreError.writeFailedItemDeleted {
                return
            }
        }
        pendingRunWrite = Task { _ = try? await write.value }
        try await write.value
    }

    private func runsDocument() -> AutomationRunsDocument {
        let ordered = runLeases.values.sorted {
            $0.isLive != $1.isLive ? $0.isLive : $0.runID < $1.runID
        }
        return AutomationRunsDocument(runs: ordered
            .prefix(AutomationRunsDocument.maximumRuns)
            .map { $0.persisted(bootSessionUUID: bootSessionUUID) })
    }

    /// Waits for every lease write prepared so far.
    public func flushPersistedRuns() async {
        await pendingRunWrite?.value
    }

    /// Puts back the leases the previous csecd persisted, once, before csecd
    /// serves anything. A record is restored only within the same boot and
    /// while its launcher incarnation (pid and start time) still runs; it is
    /// restored live only while its job still has that id and revision and
    /// its materialization still matches. Anything else whose launcher still
    /// runs comes back as a tombstone, so its child gets a typed automation
    /// denial rather than an attended panel nobody is there to answer. The
    /// values a live lease releases are returned for csecd's output redactor.
    public func restoreRuns() async -> AutomationRunRestoration {
        guard let runStore, !runsRestored else { return AutomationRunRestoration() }
        var rewrite = false
        defer {
            runsRestored = true
            if rewrite { persistRuns() }
        }
        let document: AutomationRunsDocument
        switch await runStore.load() {
        case .absent:
            return AutomationRunRestoration()
        case let .unreadable(reason):
            // Left as found for now; it is not held (see
            // `AutomationRunsDocument`), so the next lease change replaces it
            // with this csecd's own leases.
            return AutomationRunRestoration(unreadable: reason.description)
        case let .document(stored):
            document = stored
            rewrite = true
        }

        let catalog = try? await jobs()
        var result = AutomationRunRestoration()
        for record in document.runs {
            // An unknown boot session, on either side, restores nothing.
            guard let bootSessionUUID, record.bootSessionUUID == bootSessionUUID,
                  await processInspector.startTime(of: record.launcherPID)
                    == record.launcherStartTime,
                  runLeases[record.runID] == nil,
                  !runLeases.values.contains(where: {
                      $0.launcherPID == record.launcherPID
                          && $0.launcherStartTime == record.launcherStartTime
                  }) else {
                result.dropped += 1
                continue
            }
            guard let catalog else {
                // The Keychain could not be read just now: deny the child,
                // but keep the record as it was for the next csecd to check.
                runLeases[record.runID] = RunLease(
                    tombstone: record, reason: .materializationUnavailable, retained: true
                )
                result.tombstones += 1
                continue
            }
            guard record.invalidation == nil,
                  let job = catalog[record.jobName],
                  job.id == record.jobID,
                  job.revision == record.revision else {
                runLeases[record.runID] = RunLease(
                    tombstone: record,
                    reason: record.invalidation == .expired ? .runExpired : .runInvalidated
                )
                result.tombstones += 1
                continue
            }
            let loaded: AutomationMaterialization?
            do {
                loaded = try await materializationStore.load(jobID: job.id, revision: job.revision)
            } catch {
                runLeases[record.runID] = RunLease(
                    tombstone: record, reason: .materializationUnavailable, retained: true
                )
                result.tombstones += 1
                continue
            }
            guard let materialization = loaded, materialization.matches(job) else {
                runLeases[record.runID] = RunLease(
                    tombstone: record, reason: .materializationUnavailable
                )
                result.tombstones += 1
                continue
            }
            let now = clock()
            if let deadline = record.expiresAtAwake, now.awake >= deadline {
                runLeases[record.runID] = RunLease(tombstone: record, reason: .runExpired)
                result.tombstones += 1
                continue
            }
            runLeases[record.runID] = RunLease(
                runID: record.runID,
                job: job,
                launcherPID: record.launcherPID,
                launcherStartTime: record.launcherStartTime,
                auditSessionID: record.auditSessionID,
                expiresAtAwake: record.expiresAtAwake,
                valuesByReference: materialization.valuesByReference
            )
            result.live += 1
            result.releases.append(AutomationRunRestoration.Release(
                valuesByReference: materialization.valuesByReference,
                expiresAt: record.expiresAtAwake.map {
                    now.wall.addingTimeInterval($0 - now.awake)
                }
            ))
        }
        return result
    }
}

private struct AutomationGrantDocument: Codable {
    let version: UInt16
    let jobs: [AutomationJob]

    init(jobs: [AutomationJob]) {
        version = 1
        self.jobs = jobs
    }
}

private struct AutomationMaterializationDocument: Codable {
    let version: UInt16
    let jobID: String
    let revision: String
    let valuesByReference: [String: Data]

    init(_ materialization: AutomationMaterialization) {
        version = 1
        jobID = materialization.jobID
        revision = materialization.revision
        valuesByReference = materialization.valuesByReference
    }
}
