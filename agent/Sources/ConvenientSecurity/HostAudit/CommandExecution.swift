import CSecuritySupport
import Darwin
import Foundation
import OSLog
import CSECBuildIdentity

public enum HostCommandFailure: String, Sendable {
    case launch, timeout, capacity, outputLimit, io
}

public enum HostCommandPhase: String, Sendable { case launch, running, cleanup }

/// Only a static operation label, phase and duration cross the logging seam.
/// Never include argv, environment, input, output, or an executable/app path.
public struct HostCommandDiagnostic: Sendable {
    public let label: String
    public let event: String
    public let phase: HostCommandPhase
    public let elapsed: TimeInterval

    public func log() {
        let logger = Logger(subsystem: CSECBuildIdentity.identifier, category: "process-liveness")
        logger.notice("audit command=\(label, privacy: .public) event=\(event, privacy: .public) phase=\(phase.rawValue, privacy: .public) elapsed=\(elapsed, privacy: .public)s")
    }

    init(label: String, event: String, phase: HostCommandPhase, elapsed: TimeInterval) {
        // Labels are source-defined identifiers; reject accidentally supplied
        // paths/control characters instead of passing them through the log.
        self.label = !label.isEmpty && label.utf8.count <= 80 && label.utf8.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || "._-".utf8.contains($0)
        } ? label : "invalid-label"
        self.event = event
        self.phase = phase
        self.elapsed = elapsed
    }
}

/// Shared across scans and runner instances. A launch stuck inside macOS keeps
/// its slot after the caller's deadline; retries cannot grow threads/processes
/// without bound. Twelve audit checks plus their small nested scans fit here.
public final class HostCommandCapacity: @unchecked Sendable {
    public static let shared = HostCommandCapacity(limit: 16)
    private let lock = NSLock()
    private let limit: Int
    private var active = 0
    private var gatekeeperActive = 0

    public init(limit: Int) { self.limit = max(1, limit) }
    func acquire(label: String = "") -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard active < limit, label != "spctl.assess.app" || gatekeeperActive < 2 else { return false }
        active += 1
        if label == "spctl.assess.app" { gatekeeperActive += 1 }
        return true
    }
    func release(label: String = "") {
        lock.lock(); defer { lock.unlock() }
        active -= 1
        if label == "spctl.assess.app" { gatekeeperActive -= 1 }
    }
}

/// Executor injection lets tests stall a launch without wedging the host OS.
public protocol HostCommandExecuting: Sendable {
    func execute(_ command: HostCommand, control: HostCommandControl, maximumOutputBytes: Int) -> HostCommandResult
}

public final class HostCommandControl: @unchecked Sendable {
    private static let watchdog = DispatchQueue(label: "csec.audit.command-deadlines", qos: .utility)
    private let lock = NSLock()
    private let started = ProcessInfo.processInfo.systemUptime
    private let timeout: TimeInterval
    private let label: String
    private let capacity: HostCommandCapacity
    private let diagnostics: @Sendable (HostCommandDiagnostic) -> Void
    private var continuation: CheckedContinuation<HostCommandResult, Never>?
    private var timer: DispatchSourceTimer?
    private var timedOut = false
    private var phase: HostCommandPhase = .launch
    private var workerDone = false
    private var pendingReap = false

    init(label: String, timeout: TimeInterval, capacity: HostCommandCapacity,
         diagnostics: @escaping @Sendable (HostCommandDiagnostic) -> Void,
         continuation: CheckedContinuation<HostCommandResult, Never>) {
        self.label = label; self.timeout = timeout; self.capacity = capacity
        self.diagnostics = diagnostics; self.continuation = continuation
    }

    public var expired: Bool {
        lock.lock(); defer { lock.unlock() }
        return timedOut || ProcessInfo.processInfo.systemUptime - started >= timeout
    }

    public func setPhase(_ phase: HostCommandPhase) {
        lock.lock(); defer { lock.unlock() }
        self.phase = phase
    }

    func start() {
        let source = DispatchSource.makeTimerSource(queue: Self.watchdog)
        timer = source
        // One early warning, then the hard deadline. No subprocess is needed
        // to produce diagnostics when process creation itself has stalled.
        let warning = min(5, timeout / 2)
        source.schedule(deadline: .now() + warning)
        source.setEventHandler { [weak self] in
            self?.watchdogFired()
        }
        source.resume()
    }

    private func watchdogFired() {
        lock.lock()
        guard continuation != nil else { lock.unlock(); return }
        let remaining = timeout - (ProcessInfo.processInfo.systemUptime - started)
        if remaining <= 0 {
            lock.unlock()
            finish(HostCommandResult(exitCode: 124, failure: .timeout))
        } else {
            timer?.schedule(deadline: .now() + remaining)
            lock.unlock()
            record("slow")
        }
    }

    private func record(_ event: String) {
        lock.lock()
        let diagnostic = HostCommandDiagnostic(label: label, event: event, phase: phase,
            elapsed: ProcessInfo.processInfo.systemUptime - started)
        lock.unlock()
        diagnostics(diagnostic)
    }

    func finish(_ proposed: HostCommandResult) {
        lock.lock()
        guard let continuation else { lock.unlock(); return }
        // A completion racing a delayed watchdog must not turn an expired
        // assessment (even exit 0) into a trusted success.
        let result = ProcessInfo.processInfo.systemUptime - started >= timeout
            ? HostCommandResult(exitCode: 124, failure: .timeout) : proposed
        timedOut = result.failure == .timeout
        self.continuation = nil
        timer?.cancel(); timer = nil
        lock.unlock()
        continuation.resume(returning: result)
        if let failure = result.failure { record(failure.rawValue) }
    }

    func workerFinished() {
        lock.lock()
        workerDone = true
        let release = !pendingReap
        lock.unlock()
        if release { capacity.release(label: label) }
    }

    /// Ownership of an unreaped child transfers here. No blocking wait and no
    /// signal after reaping: retaining the zombie until cleanup prevents PID
    /// reuse from turning a late timeout into a signal to an unrelated process.
    func reapLater(_ pid: pid_t) {
        lock.lock(); pendingReap = true; lock.unlock()
        let source = DispatchSource.makeTimerSource(queue: Self.watchdog)
        source.schedule(deadline: .now(), repeating: .milliseconds(100))
        source.setEventHandler { [self] in
            var status: Int32 = 0
            let result = waitpid(pid, &status, WNOHANG)
            guard result == pid || (result < 0 && errno == ECHILD) else { return }
            source.cancel()
            source.setEventHandler {}
            lock.lock()
            pendingReap = false
            let release = workerDone
            lock.unlock()
            if release { capacity.release(label: label) }
        }
        source.resume()
    }
}

public struct POSIXHostCommandExecutor: HostCommandExecuting {
    private static let safePath = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec", "/opt/homebrew/bin", "/usr/local/bin"]
    public init() {}

    public func execute(_ command: HostCommand, control: HostCommandControl,
                        maximumOutputBytes: Int) -> HostCommandResult {
        guard !([command.executable] + command.arguments).contains(where: { $0.utf8.contains(0) }),
              (command.standardInput?.utf8.count ?? 0) <= 1_048_576 else { return .unavailable }
        let candidates = command.executable.hasPrefix("/") ? [command.executable]
            : (command.executable.contains("/") ? [] : Self.safePath.map { $0 + "/" + command.executable })
        guard let path = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }),
              !control.expired else { return .unavailable }

        var descriptors = [Int32](repeating: -1, count: 6)
        func closeAt(_ index: Int) {
            if descriptors[index] >= 0 { close(descriptors[index]); descriptors[index] = -1 }
        }
        defer { for i in descriptors.indices { closeAt(i) } }
        for offset in stride(from: 0, to: 6, by: 2) {
            var pair: [Int32] = [-1, -1]
            guard pipe(&pair) == 0 else { return .unavailable }
            descriptors[offset] = pair[0]; descriptors[offset + 1] = pair[1]
            for index in offset...(offset + 1) {
                // Even a daemon with a closed standard descriptor must not
                // accidentally close a dup2 target in the child actions.
                if descriptors[index] < 3 {
                    let duplicate = fcntl(descriptors[index], F_DUPFD_CLOEXEC, 3)
                    guard duplicate >= 0 else { return .unavailable }
                    closeAt(index)
                    descriptors[index] = duplicate
                }
                guard fcntl(descriptors[index], F_SETFD, FD_CLOEXEC) == 0 else { return .unavailable }
            }
        }
        // Parent ends only. Child endpoints retain blocking semantics.
        for i in [1, 2, 4] {
            let flags = fcntl(descriptors[i], F_GETFL)
            guard flags >= 0, fcntl(descriptors[i], F_SETFL, flags | O_NONBLOCK) == 0 else { return .unavailable }
        }
        guard fcntl(descriptors[1], F_SETNOSIGPIPE, 1) == 0 else { return .unavailable }
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { return .unavailable }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { return .unavailable }
        defer { posix_spawnattr_destroy(&attributes) }
        for (index, target) in [(0, STDIN_FILENO), (3, STDOUT_FILENO), (5, STDERR_FILENO)] {
            guard posix_spawn_file_actions_adddup2(&actions, descriptors[index], target) == 0 else { return .unavailable }
        }
        for fd in descriptors {
            guard posix_spawn_file_actions_addclose(&actions, fd) == 0 else { return .unavailable }
        }
        // A child starts the way a shell would start it: the signals csecd
        // catches or ignores (SIGTERM, for its shutdown; SIGPIPE) at their
        // default action, and nothing blocked. Without this, a command started
        // from a dispatch or Swift-concurrency thread inherits that thread's
        // blocked mask and can never receive SIGTERM.
        var defaults = sigset_t()
        sigemptyset(&defaults)
        for signal in [SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGPIPE, SIGALRM, SIGUSR1, SIGUSR2] {
            sigaddset(&defaults, signal)
        }
        var unblocked = sigset_t()
        sigemptyset(&unblocked)
        guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK)) == 0,
              posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
              posix_spawnattr_setsigmask(&attributes, &unblocked) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0 else { return .unavailable }
        let argv = ([path] + command.arguments).map { text in text.withCString { strdup($0) } } + [nil]
        let environmentStrings = ["PATH=" + Self.safePath.joined(separator: ":"), "LC_ALL=C"]
        let env = environmentStrings.map { text in text.withCString { strdup($0) } } + [nil]
        defer { for pointer in argv + env { free(pointer) } }
        guard argv.dropLast().allSatisfy({ $0 != nil }), env.dropLast().allSatisfy({ $0 != nil }) else { return .unavailable }
        var pid: pid_t = -1
        guard !control.expired else { return HostCommandResult(exitCode: 124, failure: .timeout) }
        let spawned = argv.withUnsafeBufferPointer { args in env.withUnsafeBufferPointer { environment in
            posix_spawn(&pid, path, &actions, &attributes, args.baseAddress!, environment.baseAddress!)
        } }
        guard spawned == 0 else { return .unavailable }
        // This defer also handles a spawn that completed AFTER the deadline.
        defer {
            if pid > 0 {
                control.setPhase(.cleanup)
                kill(-pid, SIGKILL); kill(pid, SIGKILL)
                control.reapLater(pid)
            }
        }
        // Kernel validation can return long after our caller's deadline. Keep
        // the child suspended until we know this request is still current.
        guard !control.expired else { return HostCommandResult(exitCode: 124, failure: .timeout) }
        guard kill(pid, SIGCONT) == 0 else { return .unavailable }
        control.setPhase(.running)
        for i in [0, 3, 5] { closeAt(i) }
        let input = Data((command.standardInput ?? "").utf8)
        var inputOffset = 0
        var output = [Data(), Data()]
        var bytes = [UInt8](repeating: 0, count: 8192)
        while !control.expired {
            if descriptors[1] >= 0 {
                if inputOffset == input.count { closeAt(1) }
                else {
                    let count = input.withUnsafeBytes {
                        write(descriptors[1], $0.baseAddress!.advanced(by: inputOffset), min(8192, input.count - inputOffset))
                    }
                    if count > 0 { inputOffset += count }
                    else if count < 0 && errno == EPIPE { closeAt(1) }
                    else if count < 0 && errno != EINTR && errno != EAGAIN { return HostCommandResult(exitCode: 125, failure: .io) }
                }
            }
            // One bounded read per stream per turn: a noisy child cannot starve
            // the deadline, stderr, input delivery, or process-exit detection.
            for (stream, index) in [2, 4].enumerated() where descriptors[index] >= 0 {
                let count = read(descriptors[index], &bytes, bytes.count)
                if count > 0 {
                    guard count <= maximumOutputBytes - output[stream].count else {
                        return HostCommandResult(exitCode: 125, failure: .outputLimit)
                    }
                    output[stream].append(contentsOf: bytes.prefix(count))
                } else if count == 0 { closeAt(index) }
                else if errno != EINTR && errno != EAGAIN { return HostCommandResult(exitCode: 125, failure: .io) }
            }
            var status: Int32 = 0
            let exited = cs_peek_child_exit(pid, &status)
            if exited < 0 {
                // If another child handler reaped it, PID ownership is gone.
                // Do not send a late signal to a potentially reused PID/group.
                if errno == ECHILD { pid = -1 }
                return HostCommandResult(exitCode: 125, failure: .io)
            }
            if exited > 0 && descriptors[2] < 0 && descriptors[4] < 0 {
                // Retain PID ownership through the final group cleanup; a
                // descendant may have closed its output but still be running.
                kill(-pid, SIGKILL)
                var reapedStatus: Int32 = 0
                let reaped = waitpid(pid, &reapedStatus, WNOHANG)
                if reaped == pid || (reaped < 0 && errno == ECHILD) { pid = -1 }
                return HostCommandResult(exitCode: status,
                    standardOutput: String(decoding: output[0], as: UTF8.self),
                    standardError: String(decoding: output[1], as: UTF8.self))
            }
            var polls = [pollfd(fd: descriptors[2], events: Int16(POLLIN), revents: 0),
                         pollfd(fd: descriptors[4], events: Int16(POLLIN), revents: 0),
                         pollfd(fd: descriptors[1], events: Int16(POLLOUT), revents: 0)]
            _ = poll(&polls, nfds_t(polls.count), 10)
        }
        return HostCommandResult(exitCode: 124, failure: .timeout)
    }
}
