import Foundation
import ConvenientSecurity

public enum OnePasswordConnectionStatus: String, Sendable, Equatable {
    case notStarted
    case cliUnavailable
    case connecting
    case connected
    case disconnected
}

public struct OnePasswordConnectionConfiguration: Sendable, Equatable {
    /// 1Password CLI desktop-app authorization expires after ten minutes of
    /// inactivity. Eight minutes leaves room for scheduling delay and wake-up.
    public var heartbeatInterval: TimeInterval
    public var connectionFreshness: TimeInterval
    public var initialRetryDelay: TimeInterval
    public var maximumRetryDelay: TimeInterval
    public var authenticationTimeout: TimeInterval
    public var resolutionTimeout: TimeInterval

    public init(
        heartbeatInterval: TimeInterval = 8 * 60,
        connectionFreshness: TimeInterval = 10 * 60,
        initialRetryDelay: TimeInterval = 5 * 60,
        maximumRetryDelay: TimeInterval = 30 * 60,
        authenticationTimeout: TimeInterval = 60,
        resolutionTimeout: TimeInterval = OnePasswordCLI.defaultTimeout
    ) {
        self.heartbeatInterval = max(0.001, heartbeatInterval)
        self.connectionFreshness = max(0.001, connectionFreshness)
        self.initialRetryDelay = max(0.001, initialRetryDelay)
        self.maximumRetryDelay = max(self.initialRetryDelay, maximumRetryDelay)
        self.authenticationTimeout = max(0.001, authenticationTimeout)
        self.resolutionTimeout = max(0.001, resolutionTimeout)
    }
}

/// 1Password provider backed by the official `op` CLI. The actor owns the CLI
/// authorization lifecycle as well as resolution: it attempts a metadata-only
/// connection at daemon launch, keeps that connection active, coalesces
/// simultaneous reconnects, and serializes commands so background maintenance
/// can never race a real read into a second authorization prompt.
public actor OnePasswordProvider: SecretProvider {
    public typealias CommandRunner = @Sendable (
        _ path: String,
        _ arguments: [String],
        _ timeout: TimeInterval
    ) async throws -> OnePasswordCLI.Result
    public typealias CLILocator = @Sendable () -> String?
    public typealias DateProvider = @Sendable () -> Date
    public typealias Sleeper = @Sendable (_ seconds: TimeInterval) async throws -> Void
    public typealias StatusObserver = @Sendable (_ status: OnePasswordConnectionStatus) -> Void

    public nonisolated let schemes: Set<String> = ["op"]

    private let configuredCLIPath: String?
    private let cacheMaxAge: TimeInterval
    private let configuration: OnePasswordConnectionConfiguration
    private let locateCLI: CLILocator
    private let runCommand: CommandRunner
    private let currentDate: DateProvider
    private let sleep: Sleeper
    private let statusObserver: StatusObserver

    private var status: OnePasswordConnectionStatus = .notStarted
    private var lastConfirmedAt: Date?
    private var connectionAttempt: (id: UInt64, task: Task<Void, Error>)?
    private var nextConnectionAttemptID: UInt64 = 0
    private var commandRunning = false
    private var commandWaiters: [CheckedContinuation<Void, Never>] = []
    private var maintenanceRunning = false

    public init(
        cliPath: String? = nil,
        cacheMaxAge: TimeInterval = 24 * 3600,
        configuration: OnePasswordConnectionConfiguration = .init(),
        locateCLI: @escaping CLILocator = { OnePasswordCLI.locate() },
        runCommand: @escaping CommandRunner = { path, arguments, timeout in
            try await OnePasswordCLI.run(path, arguments, timeout: timeout)
        },
        currentDate: @escaping DateProvider = { Date() },
        sleep: @escaping Sleeper = { seconds in
            let nanoseconds = UInt64(min(seconds * 1_000_000_000, Double(UInt64.max)))
            try await Task.sleep(nanoseconds: nanoseconds)
        },
        statusObserver: @escaping StatusObserver = { _ in }
    ) {
        self.configuredCLIPath = cliPath
        self.cacheMaxAge = cacheMaxAge
        self.configuration = configuration
        self.locateCLI = locateCLI
        self.runCommand = runCommand
        self.currentDate = currentDate
        self.sleep = sleep
        self.statusObserver = statusObserver
    }

    /// Starts one resident maintenance loop. The first authentication attempt is
    /// immediate; subsequent successful probes stay inside 1Password's ten-minute
    /// inactivity window. Failed probes back off, while a real request can still
    /// trigger an immediate coalesced reconnect.
    public func maintainConnection() async {
        guard !maintenanceRunning else { return }
        maintenanceRunning = true
        defer { maintenanceRunning = false }

        var retryDelay = configuration.initialRetryDelay
        while !Task.isCancelled {
            do {
                try await establishConnection(forceProbe: true)
                retryDelay = configuration.initialRetryDelay
                try await sleep(configuration.heartbeatInterval)
            } catch is CancellationError {
                return
            } catch {
                if Task.isCancelled { return }
                do {
                    try await sleep(retryDelay)
                } catch {
                    return
                }
                retryDelay = min(configuration.maximumRetryDelay, retryDelay * 3)
            }
        }
    }

    public func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        try await authenticate()

        let result: OnePasswordCLI.Result
        do {
            result = try await execute(
                arguments: ["read", "--no-newline", ref.uri],
                timeout: configuration.resolutionTimeout
            )
        } catch {
            markConnectionFailure(error)
            throw error
        }

        guard result.status == 0 else {
            let stderr = String(data: result.stderr, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines)
            let message = (stderr?.isEmpty == false) ? stderr! : "op exited \(result.status)"
            let error = OnePasswordError.readFailed(
                reference: ref.uri,
                status: result.status,
                message: message
            )
            markConnectionFailure(error)
            throw error
        }
        markConnected()

        // `op read` addresses a single field, which is text; a non-UTF-8 result
        // signals a wrong reference (e.g. a document) rather than a real value.
        // The validated bytes are sealed verbatim — a value is bytes.
        guard String(data: result.stdout, encoding: .utf8) != nil else {
            throw OnePasswordError.notUTF8(ref.uri)
        }
        return ResolvedSecret(value: result.stdout, cacheHint: .cacheable(maxAge: cacheMaxAge))
    }

    /// Establish or refresh the desktop-app authorization. Idempotent and
    /// single-flight: concurrent callers share one metadata-only `op whoami`.
    public func authenticate() async throws {
        try await establishConnection(forceProbe: false)
    }

    /// True only while a recent authenticated command proves the provider can
    /// serve without beginning another interactive authorization ceremony.
    public func isAvailable() async -> Bool {
        guard connectionIsFresh else {
            if status == .connected { setStatus(.disconnected) }
            return false
        }
        return true
    }

    public func connectionStatus() -> OnePasswordConnectionStatus {
        status
    }

    private var connectionIsFresh: Bool {
        guard status == .connected, let lastConfirmedAt else { return false }
        let age = max(0, currentDate().timeIntervalSince(lastConfirmedAt))
        return age < configuration.connectionFreshness
    }

    private func establishConnection(forceProbe: Bool) async throws {
        if !forceProbe, connectionIsFresh { return }

        if let attempt = connectionAttempt {
            try await attempt.task.value
            return
        }

        nextConnectionAttemptID &+= 1
        let attemptID = nextConnectionAttemptID
        if status != .connected { setStatus(.connecting) }
        let task = Task { try await self.performAuthenticationProbe() }
        connectionAttempt = (attemptID, task)

        do {
            try await task.value
            if connectionAttempt?.id == attemptID {
                connectionAttempt = nil
            }
        } catch {
            if connectionAttempt?.id == attemptID {
                connectionAttempt = nil
            }
            throw error
        }
    }

    private func performAuthenticationProbe() async throws {
        do {
            // `whoami` touches no credential value. Its account metadata is
            // captured only to EOF and discarded; logs contain fixed state only.
            let result = try await execute(
                arguments: ["whoami", "--format=json"],
                timeout: configuration.authenticationTimeout
            )
            guard result.status == 0 else {
                throw OnePasswordError.authenticationFailed(status: result.status)
            }
            markConnected()
        } catch {
            markConnectionFailure(error)
            throw error
        }
    }

    private func execute(
        arguments: [String],
        timeout: TimeInterval
    ) async throws -> OnePasswordCLI.Result {
        await acquireCommandSlot()
        defer { releaseCommandSlot() }
        try Task.checkCancellation()

        guard let cliPath = configuredCLIPath ?? locateCLI() else {
            throw OnePasswordError.cliNotFound
        }
        return try await runCommand(cliPath, arguments, timeout)
    }

    private func acquireCommandSlot() async {
        if !commandRunning {
            commandRunning = true
            return
        }
        await withCheckedContinuation { continuation in
            commandWaiters.append(continuation)
        }
    }

    private func releaseCommandSlot() {
        if commandWaiters.isEmpty {
            commandRunning = false
            return
        }
        commandWaiters.removeFirst().resume()
    }

    private func markConnected() {
        lastConfirmedAt = currentDate()
        setStatus(.connected)
    }

    private func markConnectionFailure(_ error: Error) {
        if let onePasswordError = error as? OnePasswordError,
           case .cliNotFound = onePasswordError {
            setStatus(.cliUnavailable)
        } else {
            setStatus(.disconnected)
        }
    }

    private func setStatus(_ next: OnePasswordConnectionStatus) {
        guard status != next else { return }
        status = next
        statusObserver(next)
    }
}

public enum OnePasswordError: Error, CustomStringConvertible {
    case cliNotFound
    case authenticationFailed(status: Int32)
    case readFailed(reference: String, status: Int32, message: String)
    case notUTF8(String)

    public var description: String {
        switch self {
        case .cliNotFound:
            return "the verified official 1Password CLI (op) was not found"
        case .authenticationFailed(let status):
            return "1Password desktop authorization failed (exit \(status))"
        case let .readFailed(reference, status, message):
            return "op read \(reference) failed (exit \(status)): \(message)"
        case let .notUTF8(reference):
            return "op returned non-UTF-8 data for \(reference)"
        }
    }
}
