import Foundation
import Security

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
    /// Canonical argv, including the canonical executable path as argv[0].
    public let commandLine: [String]
    public let workingDirectory: String
    public let commandDigest: String
    public let environmentMode: AutomationEnvironmentMode

    public init(
        executable: PlannedExecutable,
        commandLine: [String],
        workingDirectory: String,
        commandDigest: String,
        environmentMode: AutomationEnvironmentMode = .sanitizedTrigger
    ) {
        self.executable = executable
        self.commandLine = commandLine
        self.workingDirectory = workingDirectory
        self.commandDigest = commandDigest
        self.environmentMode = environmentMode
    }

    public var displayCommand: String {
        commandLine.map(Self.displayArgument).joined(separator: " ")
    }

    public var isWellFormed: Bool {
        guard executable.assurance == .unverified,
              executable.canonicalPath.hasPrefix("/"),
              executable.canonicalPath.utf8.count <= 4_096,
              ReviewDisplay.sanitized(executable.canonicalPath) == executable.canonicalPath,
              commandLine.count > 0,
              commandLine.count <= Self.maximumArgumentCount,
              commandLine[0] == executable.canonicalPath,
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
              validSigningMetadata else { return false }
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

    private var validSigningMetadata: Bool {
        (executable.signingIdentifier.map {
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

    private static func displayArgument(_ value: String) -> String {
        let safe = ReviewDisplay.sanitized(value)
        guard !safe.isEmpty else { return "''" }
        let unquoted = safe.utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 65 && $0 <= 90)
                || ($0 >= 97 && $0 <= 122)
                || [43, 44, 45, 46, 47, 58, 61, 64, 95].contains($0)
        }
        if unquoted { return safe }
        return "'" + safe.replacingOccurrences(of: "'", with: "'\\''") + "'"
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
    public let maximumRuntimeSeconds: Int
    public let consumerTrust: AutomationConsumerTrust

    public init(
        name: String,
        reason: String,
        references: [String],
        command: AutomationCommand,
        minimumIntervalSeconds: Int = 0,
        maximumRuntimeSeconds: Int = 60 * 60,
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
    public let maximumRuntimeSeconds: Int
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
        maximumRuntimeSeconds: Int,
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
              maximumRuntimeSeconds > 0,
              maximumRuntimeSeconds <= 24 * 60 * 60,
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
    public let expiresAt: Date

    public init(runID: String, job: AutomationJob, expiresAt: Date) {
        self.runID = runID
        self.job = job
        self.expiresAt = expiresAt
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
    case alreadyRunning
    case materializationUnavailable
    case executableChanged

    public var errorDescription: String? {
        switch self {
        case .invalidRequest: return "the automation request is invalid"
        case .unavailable: return "unattended automation storage is unavailable"
        case .notFound: return "the automation job was not found"
        case .consentDenied: return "automation enrollment was denied"
        case .resolutionFailed: return "one or more references could not be materialized"
        case .alreadyRunning: return "the automation job already has a live run"
        case .materializationUnavailable:
            return "the automation materialization is unavailable; unlock the Mac or refresh the job"
        case .executableChanged:
            return "the registered interpreter changed; enroll the job again"
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
    public static let service = "com.alexspeller.convenient-security.automation-grants"
    private static let account = "catalog-v1"
    private static let maximumBytes = 512 * 1_024
    private let queue = DispatchQueue(
        label: "com.alexspeller.convenient-security.automation-grants-keychain"
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
    public static let service = "com.alexspeller.convenient-security.automation-materializations"
    private static let maximumEncodedBytes = 2 * 1_024 * 1_024
    private let queue = DispatchQueue(
        label: "com.alexspeller.convenient-security.automation-materialization-keychain"
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
        guard let inspected = try? ExecutableInspection.plannedExecutable(command: path) else {
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

public enum AutomationRunDecision: Sendable {
    case started(AutomationRunAuthorization)
    case skipped(nextEligibleAt: Date)
}

public enum AutomationAccessDecision: Sendable {
    case notApplicable
    case allowed(values: [String: Data], expiresAt: Date)
    case denied(AutomationServiceError)
}

/// Owns persistent until-revoked automation grants and memory-only run leases.
/// A job name/run UUID is a lookup hint, never a bearer capability: release is
/// authorized by the live signed launcher's PID/start-time, exact direct child,
/// exact stored interpreter identity, and exact canonical references.
public actor AutomationService {
    private struct LauncherIncarnation: Hashable, Sendable {
        let pid: pid_t
        let startTime: UInt64
    }

    private struct RunLease: Sendable {
        let runID: String
        let job: AutomationJob
        let launcherPID: pid_t
        let launcherStartTime: UInt64
        let auditSessionID: UInt32?
        let expiresAt: Date
        let valuesByReference: [String: Data]
    }

    private let resolver: SecretResolver
    private let grantStore: any AutomationGrantStore
    private let materializationStore: any AutomationMaterializationStore
    private let consent: any ConsentProvider
    private let policyReview: any PolicyReviewProvider
    private let processInspector: any AutomationProcessInspecting
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

    public init(
        resolver: SecretResolver,
        grantStore: any AutomationGrantStore,
        materializationStore: any AutomationMaterializationStore,
        consent: any ConsentProvider,
        policyReview: any PolicyReviewProvider,
        processInspector: any AutomationProcessInspecting = SystemAutomationProcessInspector()
    ) {
        self.resolver = resolver
        self.grantStore = grantStore
        self.materializationStore = materializationStore
        self.consent = consent
        self.policyReview = policyReview
        self.processInspector = processInspector
    }

    public func enroll(
        _ enrollment: AutomationEnrollment,
        caller: CallerInfo,
        now: Date = Date()
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
        let review = AccessPolicyReview(
            caller: caller,
            reason: candidate.reason,
            plan: plan,
            credentials: await resolver.reviewCredentials(
                for: CredentialGrouping.groups(for: refs).map(\.references)
            ),
            automation: AutomationReviewDetails(job: candidate)
        )
        guard case let .approved(approval) = await policyReview.reviewAccess(review) else {
            throw AutomationServiceError.consentDenied
        }

        let outcome: ConsentOutcome
        if let session = approval.authenticationSession {
            outcome = await session.completeAfterPolicyApproval(
                policySummary: "unattended mutable automation until revoked"
            )
        } else {
            outcome = await consent.requestConsent(
                caller: caller,
                newReferences: refs,
                reason: candidate.reason,
                ttl: TimeInterval(candidate.maximumRuntimeSeconds),
                policySummary: "unattended mutable automation; persistent until revoked"
            )
        }
        guard case let .approved(unlock) = outcome else {
            throw AutomationServiceError.consentDenied
        }
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
        runLeases = runLeases.filter { $0.value.job.name != candidate.name }
        lastStartedAt[candidate.name] = nil
        return candidate
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
        guard case .approved = await consent.authenticate(
            reason: "Revoke unattended automation job \(ReviewDisplay.sanitized(name))"
        ), await callerIsLive(caller) else {
            throw AutomationServiceError.consentDenied
        }

        var next = current
        next[name] = nil
        // Stop in-memory release first, then remove the value copy. If catalog
        // persistence is interrupted afterwards, the remaining metadata is
        // inert and a retry can complete the idempotent revoke.
        runLeases = runLeases.filter { $0.value.job.name != name }
        lastStartedAt[name] = nil
        do {
            try await materializationStore.delete(jobID: job.id, revision: job.revision)
            try await persist(next)
        } catch {
            throw AutomationServiceError.unavailable
        }
        return job
    }

    public func beginRun(
        name: String,
        caller: CallerInfo,
        now: Date = Date()
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

        await pruneRunLeases(now: now)
        let current = try await jobs()
        guard let job = current[name] else { throw AutomationServiceError.notFound }
        guard await commandIdentityMatches(job.command),
              directoryExists(job.command.workingDirectory) else {
            throw AutomationServiceError.executableChanged
        }
        guard !runLeases.values.contains(where: { $0.job.name == name }) else {
            throw AutomationServiceError.alreadyRunning
        }
        guard !runLeases.values.contains(where: {
            $0.launcherPID == caller.pid && $0.launcherStartTime == caller.startTime
        }) else {
            throw AutomationServiceError.alreadyRunning
        }
        if job.minimumIntervalSeconds > 0,
           let last = lastStartedAt[name] {
            let next = last.addingTimeInterval(TimeInterval(job.minimumIntervalSeconds))
            if now < next { return .skipped(nextEligibleAt: next) }
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
        guard await callerIsLive(caller),
              await commandIdentityMatches(job.command) else {
            throw AutomationServiceError.executableChanged
        }

        let runID = UUID().uuidString.lowercased()
        let expiresAt = now.addingTimeInterval(TimeInterval(job.maximumRuntimeSeconds))
        runLeases[runID] = RunLease(
            runID: runID,
            job: job,
            launcherPID: caller.pid,
            launcherStartTime: caller.startTime,
            auditSessionID: caller.peerIdentity?.audit.auditSessionID,
            expiresAt: expiresAt,
            valuesByReference: materialization.valuesByReference
        )
        lastStartedAt[name] = now
        return .started(AutomationRunAuthorization(
            runID: runID, job: job, expiresAt: expiresAt
        ))
    }

    @discardableResult
    public func finishRun(runID: String, caller: CallerInfo) async -> Bool {
        guard UUID(uuidString: runID)?.uuidString.lowercased() == runID,
              let lease = runLeases[runID],
              lease.launcherPID == caller.pid,
              lease.launcherStartTime == caller.startTime else { return false }
        runLeases[runID] = nil
        return true
    }

    public func authorizeAccess(
        references: [SecretRef],
        plan: DeliveryPlan,
        caller: CallerInfo,
        now: Date = Date()
    ) async -> AutomationAccessDecision {
        await pruneRunLeases(now: now)
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

        guard now < lease.expiresAt,
              await processInspector.startTime(of: lease.launcherPID)
                == lease.launcherStartTime,
              await processInspector.executablePath(of: consumerPID)
                == lease.job.command.executable.canonicalPath,
              plan.executable == lease.job.command.executable else {
            return .denied(.executableChanged)
        }
        let requested = Set(references.map(\.uri))
        guard !requested.isEmpty,
              requested.isSubset(of: Set(lease.job.references)) else {
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
        guard let activeLease = runLeases[lease.runID],
              activeLease.job.revision == lease.job.revision,
              activeLease.launcherPID == lease.launcherPID,
              activeLease.launcherStartTime == lease.launcherStartTime,
              now < activeLease.expiresAt else {
            return .denied(.materializationUnavailable)
        }
        return .allowed(values: values, expiresAt: lease.expiresAt)
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
              enrollment.maximumRuntimeSeconds > 0,
              enrollment.maximumRuntimeSeconds <= 24 * 60 * 60,
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
        guard caller.pid > 1, caller.startTime > 0 else { return false }
        return await processInspector.startTime(of: caller.pid) == caller.startTime
    }

    private func commandIdentityMatches(_ command: AutomationCommand) async -> Bool {
        guard command.isWellFormed,
              let inspected = await processInspector.inspectedExecutable(
                path: command.executable.canonicalPath
              ) else { return false }
        return inspected == command.executable
    }

    private func directoryExists(_ path: String) -> Bool {
        var isDirectory = ObjCBool(false)
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDirectory)
            && isDirectory.boolValue
    }

    private func pruneRunLeases(now: Date) async {
        var retained: [String: RunLease] = [:]
        for (id, lease) in runLeases where now < lease.expiresAt {
            if await processInspector.startTime(of: lease.launcherPID)
                == lease.launcherStartTime {
                retained[id] = lease
            }
        }
        runLeases = retained
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
