import Foundation
import ConvenientSecurity
import CSecuritySupport
import Darwin

struct OutputGuardConfiguration {
    var mode: OutputGuardMode = .always
    // Default: name the redacted reference in-band as `[redacted: <ref>]`. The
    // reference is value-free metadata the user already holds in the sidecar or
    // environment. `--redact-output-label=opaque` restores `[csec:secret-N]`.
    var labelStyle: OutputRedactionLabelStyle = .reference
    var includeShortValues = false
    // Per-match "protected output detected and redacted" stderr warnings are
    // opt-in; the in-band label already shows what was redacted. Enable with
    // `--redact-output-warn` for scripted/auditable visibility.
    var emitWarnings = false

    var plan: OutputGuardPlan {
        OutputGuardPlan(
            mode: mode,
            labelStyle: labelStyle,
            includeShortValues: includeShortValues
        )
    }
}

enum ProcessSupervisorError: Error, CustomStringConvertible {
    case allocationFailed
    case spawnFailed(String)
    case setupFailed(String)
    case deliveryFailed
    /// The agent-side output scanner failed; the error is what its session
    /// threw.
    case redactionFailed(Error)
    case timedOut

    var description: String {
        switch self {
        case .allocationFailed:
            return "could not prepare the child process"
        case let .spawnFailed(message):
            return "could not launch the child: \(message)"
        case let .setupFailed(message):
            return "could not secure the child output channels: \(message)"
        case .deliveryFailed:
            return "the target closed an inherited secret channel before delivery completed"
        case let .redactionFailed(error):
            return "the trusted output scanner became unavailable: \(String(describing: error))"
        case .timedOut:
            return "the command exceeded its registered maximum runtime"
        }
    }
}

/// One anonymous file-shaped secret channel. The descriptor number/path is
/// non-secret; bytes are retained only until the supervised child consumes the
/// pipe, then overwritten best-effort and released.
final class InheritedSecretFile {
    private(set) var readFD: Int32
    private(set) var writeFD: Int32
    private var bytes: [UInt8]
    private var offset = 0

    var path: String { "/dev/fd/\(readFD)" }
    var isWriting: Bool { writeFD >= 0 }

    init(data: Data) throws {
        var descriptors: [Int32] = [-1, -1]
        guard pipe(&descriptors) == 0 else {
            throw ProcessSupervisorError.setupFailed("could not create an inherited secret pipe")
        }
        for descriptor in descriptors {
            let flags = fcntl(descriptor, F_GETFD)
            guard flags >= 0, fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) == 0 else {
                close(descriptors[0])
                close(descriptors[1])
                throw ProcessSupervisorError.setupFailed("could not protect an inherited secret pipe")
            }
        }
        // Keep advertised descriptor paths away from the low numbers commonly
        // occupied by unrelated launch plumbing. F_DUPFD_CLOEXEC also ensures
        // only our child-side clear operation can carry this copy through exec.
        let elevatedRead = fcntl(descriptors[0], F_DUPFD_CLOEXEC, 64)
        guard elevatedRead >= 64 else {
            close(descriptors[0])
            close(descriptors[1])
            throw ProcessSupervisorError.setupFailed("could not reserve an inherited secret descriptor")
        }
        close(descriptors[0])
        readFD = elevatedRead
        writeFD = descriptors[1]
        bytes = Array(data)
    }

    deinit { closeAndWipe() }

    func childDidExec() throws {
        if readFD >= 0 {
            close(readFD)
            readFD = -1
        }
        guard writeFD >= 0, cs_fd_set_nonblocking(writeFD) == 0 else {
            throw ProcessSupervisorError.setupFailed("could not prepare an inherited secret pipe")
        }
        if bytes.isEmpty { closeWriterAndWipe() }
    }

    func writeAvailable() throws {
        guard writeFD >= 0 else { return }
        let written = bytes.withUnsafeBytes { rawBuffer -> Int in
            guard let base = rawBuffer.baseAddress else { return 0 }
            return write(writeFD, base.advanced(by: offset), bytes.count - offset)
        }
        if written > 0 {
            offset += written
            if offset == bytes.count { closeWriterAndWipe() }
        } else if written < 0, errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK {
            return
        } else {
            closeWriterAndWipe()
            throw ProcessSupervisorError.deliveryFailed
        }
    }

    func closeAndWipe() {
        if readFD >= 0 { close(readFD); readFD = -1 }
        closeWriterAndWipe()
    }

    private func closeWriterAndWipe() {
        if writeFD >= 0 { close(writeFD); writeFD = -1 }
        _ = bytes.withUnsafeMutableBytes { buffer in
            buffer.initializeMemory(as: UInt8.self, repeating: 0)
        }
        bytes.removeAll(keepingCapacity: false)
        offset = 0
    }
}

private enum GuardedStream: String, Hashable {
    case stdout
    case stderr
    case terminal
}

private extension GuardedStream {
    var protocolStream: OutputRedactionStream {
        switch self {
        case .stdout: return .stdout
        case .stderr: return .stderr
        case .terminal: return .terminal
        }
    }
}

private enum CaptureRedactor {
    case local(StreamingOutputRedactor)
    case agent(AgentOutputRedactionSession, OutputRedactionStream)

    mutating func process(_ data: Data) throws -> OutputRedactionResult {
        switch self {
        case var .local(redactor):
            let result = redactor.process(data)
            self = .local(redactor)
            return result
        case let .agent(session, stream):
            return try session.process(data, stream: stream)
        }
    }

    mutating func finish() throws -> OutputRedactionResult {
        switch self {
        case var .local(redactor):
            let result = redactor.finish()
            self = .local(redactor)
            return result
        case let .agent(session, stream):
            return try session.finish(stream: stream)
        }
    }
}

private struct IncidentKey: Hashable {
    let stream: GuardedStream
    let match: OutputRedactionMatch
}

private final class IncidentReporter {
    private let emitWarnings: Bool
    private var reported = Set<IncidentKey>()
    private var pending: [GuardedStream: [OutputRedactionMatch]] = [:]

    init(emitWarnings: Bool) {
        self.emitWarnings = emitWarnings
    }

    func record(_ matches: [OutputRedactionMatch], stream: GuardedStream) {
        guard emitWarnings else { return }
        for match in matches {
            let key = IncidentKey(stream: stream, match: match)
            guard reported.insert(key).inserted else { continue }
            pending[stream, default: []].append(match)
        }
    }

    /// Write warnings only at a child-output line boundary. Without this, a
    /// warning generated after withholding a possible prefix can be inserted in
    /// the middle of an otherwise unrelated terminal line.
    func flush(stream: GuardedStream, addLeadingNewline: Bool = false) {
        guard emitWarnings else { return }
        guard let matches = pending.removeValue(forKey: stream), !matches.isEmpty else { return }
        if addLeadingNewline {
            _ = writeAll(fd: STDERR_FILENO, data: Data("\n".utf8))
        }
        for match in matches {
            let message = "csec: warning: protected output detected and redacted "
                + "(\(match.reference ?? match.opaqueID), \(stream.rawValue), \(match.representation.rawValue))\n"
            _ = writeAll(fd: STDERR_FILENO, data: Data(message.utf8))
        }
    }
}

private final class Capture {
    let fd: Int32
    let targetFD: Int32
    let stream: GuardedStream
    var redactor: CaptureRedactor
    /// Output read while no scanner answered, to scan once one reopens.
    var awaitingScan = OutputTail(limit: ScannerLossHandling.awaitingScanLimit)
    /// The last scanned output, to prime a reopened scanner with.
    var scannedTail = OutputTail(limit: ScannerLossHandling.primeBytes)
    var isOpen = true
    var downstreamIsOpen = true
    var atLineBoundary = true

    init(
        fd: Int32,
        targetFD: Int32,
        stream: GuardedStream,
        patterns: [OutputRedactionPattern],
        agentSession: AgentOutputRedactionSession?
    ) {
        self.fd = fd
        self.targetFD = targetFD
        self.stream = stream
        if let agentSession {
            redactor = .agent(agentSession, stream.protocolStream)
        } else {
            redactor = .local(StreamingOutputRedactor(
                patterns: patterns,
                interpretsTerminalControls: stream == .terminal
            ))
        }
    }
}

private final class CStringVector {
    var pointers: [UnsafeMutablePointer<CChar>?]

    init(_ strings: [String]) throws {
        var allocated: [UnsafeMutablePointer<CChar>?] = []
        allocated.reserveCapacity(strings.count + 1)
        for string in strings {
            guard let pointer = strdup(string) else {
                for case let pointer? in allocated { free(pointer) }
                throw ProcessSupervisorError.allocationFailed
            }
            allocated.append(pointer)
        }
        allocated.append(nil)
        pointers = allocated
    }

    deinit {
        for case let pointer? in pointers { free(pointer) }
    }
}

private final class OptionalCString {
    let pointer: UnsafeMutablePointer<CChar>?

    init(_ string: String?) throws {
        if let string {
            guard let pointer = strdup(string) else {
                throw ProcessSupervisorError.allocationFailed
            }
            self.pointer = pointer
        } else {
            pointer = nil
        }
    }

    deinit {
        if let pointer { free(pointer) }
    }
}

/// What `ProcessSupervisor.run` does when its agent-side output scanner fails
/// mid-command, and what it withheld when it carried on.
///
/// Without it the supervisor stops the command: nothing after the failure is
/// forwarded and the child is terminated. A caller whose command csecd
/// released nothing to may instead withhold the rest of the output and let
/// the command finish: nothing unscanned is forwarded either way, and killing
/// a command that holds no delivered value protects nothing. An automation
/// run, whose csecd keeps its lease across a restart, withholds only until a
/// scanner opens on the restarted csecd, and then scans again.
final class ScannerLossHandling {
    enum Action {
        case terminate
        case withholdRemaining
        /// Withhold the output, and keep trying `reopen`, at most once a
        /// second, until a scanner opens; then scan the rest with it.
        case withholdUntilReopened
    }

    enum Reopen {
        case opened(AgentOutputRedactionSession)
        /// No csecd answers yet: withhold, and try again.
        case unavailable
        /// A csecd answered and will not scan for this command: stop it.
        case refused(Error)
    }

    fileprivate let decide: (Error) -> Action
    /// Asked on every turn of the supervisor's loop, whether or not the
    /// command printed anything: the error the scanner's csecd is gone with,
    /// or nil while it still runs. A quiet command learns of a restart from
    /// this, not only from its next output.
    fileprivate let scannerGone: (() -> Error?)?
    /// Opens a scanner on a restarted csecd.
    fileprivate let reopen: (() -> Reopen)?
    /// Called once a scanner reopens, with the bytes withheld while there was
    /// none.
    fileprivate let reopened: ((AgentOutputRedactionSession, Int) -> Void)?
    fileprivate var reopensWhenAvailable = false
    /// How much scanned output primes a reopened scanner: a value split
    /// across the loss is matched whole while the part the old matcher held
    /// back is within this. csecd matches a value in forms up to six times
    /// its length (JSON `\\u` escapes), so this covers any value up to 40 KiB.
    fileprivate static let primeBytes = 256 * 1_024
    /// How much output is held per stream while no scanner answers.
    fileprivate static let awaitingScanLimit = 1_024 * 1_024
    /// How long a stream that ends while no scanner answers waits for one to
    /// reopen, at most, across the whole command: an update restarts csecd
    /// within seconds, and the command's last output is often what says why
    /// it ended.
    fileprivate static let endOfOutputWait: TimeInterval = 15
    /// Set once the scanner was lost and the rest of the output is being
    /// withheld: how many bytes were read from the command and dropped since.
    /// Output the scanner was still holding back when it was lost (the start
    /// of a possible secret) is dropped too, uncounted. While a scanner may
    /// reopen, output is held to scan instead, and only what the hold could
    /// not keep is counted here.
    fileprivate(set) var withheldBytes: Int?
    /// The error the scanner failed with, once it has.
    fileprivate(set) var loss: Error?
    /// Set when a csecd refused to scan after the command had already
    /// exited: there was nothing left to stop, so the command's own status
    /// stands, and the output still unscanned was withheld.
    fileprivate(set) var refusedAfterExit: Error?

    init(
        decide: @escaping (Error) -> Action,
        scannerGone: (() -> Error?)? = nil,
        reopen: (() -> Reopen)? = nil,
        reopened: ((AgentOutputRedactionSession, Int) -> Void)? = nil
    ) {
        self.decide = decide
        self.scannerGone = scannerGone
        self.reopen = reopen
        self.reopened = reopened
    }
}

enum ProcessSupervisor {
    /// Supervise one command and return its raw wait status. The caller uses
    /// `cs_terminate_like_wait_status` so a signalled child remains signalled to
    /// its invoking shell rather than being flattened into an arbitrary code.
    static func run(
        executablePath: String,
        commandLine: [String],
        environment: [String: String],
        workingDirectory: String? = nil,
        timeoutSeconds: TimeInterval? = nil,
        catalog: OutputRedactionCatalog? = nil,
        agentSession: AgentOutputRedactionSession? = nil,
        mode: OutputGuardMode,
        emitWarnings: Bool = false,
        inheritedFiles: [InheritedSecretFile] = [],
        scannerLoss: ScannerLossHandling? = nil,
        onTick: (() -> Void)? = nil
    ) throws -> Int32 {
        precondition(inheritedFiles.count <= 32)
        precondition(timeoutSeconds == nil || (timeoutSeconds!.isFinite && timeoutSeconds! > 0))
        let patterns = mode == .never ? [] : (catalog?.patterns ?? [])
        let stdinIsTTY = isatty(STDIN_FILENO) == 1
        let stdoutIsTTY = isatty(STDOUT_FILENO) == 1
        let stderrIsTTY = isatty(STDERR_FILENO) == 1

        let captureStdout: Bool
        let captureStderr: Bool
        switch mode {
        case .tty:
            captureStdout = stdoutIsTTY
            captureStderr = stderrIsTTY
        case .always:
            captureStdout = true
            captureStderr = true
        case .never:
            // FD delivery still needs a parent to feed and close the anonymous
            // pipes. Preserve terminal behavior through the existing PTY relay,
            // but use an empty matcher for the explicit byte-exact bypass.
            captureStdout = stdoutIsTTY
            captureStderr = stderrIsTTY
        }

        let stdinUsesPTY = stdinIsTTY
        let stdoutMode: cs_output_mode = captureStdout
            ? (stdoutIsTTY ? CS_OUTPUT_PTY : CS_OUTPUT_PIPE)
            : CS_OUTPUT_INHERIT
        let stderrMode: cs_output_mode = captureStderr
            ? (stderrIsTTY ? CS_OUTPUT_PTY : CS_OUTPUT_PIPE)
            : CS_OUTPUT_INHERIT

        let argv = try CStringVector(commandLine)
        let environmentEntries = environment.keys.sorted().compactMap { key -> String? in
            guard let value = environment[key] else { return nil }
            return "\(key)=\(value)"
        }
        let envp = try CStringVector(environmentEntries)
        let workingDirectoryCString = try OptionalCString(workingDirectory)

        var childPID: Int32 = -1
        var ptyMaster: Int32 = -1
        var stdoutRead: Int32 = -1
        var stderrRead: Int32 = -1
        var failedStep = CS_SPAWN_STEP_NONE
        let inheritedFDs = inheritedFiles.map(\.readFD)
        let spawnResult = argv.pointers.withUnsafeMutableBufferPointer { argvBuffer in
            envp.pointers.withUnsafeMutableBufferPointer { envBuffer in
                inheritedFDs.withUnsafeBufferPointer { inheritedBuffer in
                    executablePath.withCString { path in
                        cs_spawn_supervised(
                            path,
                            argvBuffer.baseAddress,
                            envBuffer.baseAddress,
                            workingDirectoryCString.pointer,
                            stdinUsesPTY ? 1 : 0,
                            stdoutMode,
                            stderrMode,
                            inheritedBuffer.baseAddress,
                            Int32(inheritedBuffer.count),
                            &childPID,
                            &ptyMaster,
                            &stdoutRead,
                            &stderrRead,
                            &failedStep
                        )
                    }
                }
            }
        }
        guard spawnResult == 0, childPID > 0 else {
            // Read errno before closing the inherited files can change it.
            let reason = "\(spawnStepName(failedStep)) failed: \(errnoMessage())"
            inheritedFiles.forEach { $0.closeAndWipe() }
            throw ProcessSupervisorError.spawnFailed(reason)
        }

        do {
            for file in inheritedFiles { try file.childDidExec() }
        } catch {
            inheritedFiles.forEach { $0.closeAndWipe() }
            _ = kill(-childPID, SIGKILL)
            _ = kill(childPID, SIGKILL)
            var status: Int32 = 0
            while waitpid(childPID, &status, 0) < 0, errno == EINTR {}
            if ptyMaster >= 0 { close(ptyMaster) }
            if stdoutRead >= 0 { close(stdoutRead) }
            if stderrRead >= 0 { close(stderrRead) }
            throw error
        }

        var signalPipe: [Int32] = [-1, -1]
        var openedTerminalOutput: Int32 = -1
        var handlersInstalled = false
        var terminalIsRaw = false
        var captures: [Capture] = []

        func abortChild() {
            _ = kill(-childPID, SIGKILL)
            _ = kill(childPID, SIGKILL)
            var status: Int32 = 0
            while waitpid(childPID, &status, 0) < 0, errno == EINTR {}
        }

        defer {
            if terminalIsRaw { cs_terminal_restore() }
            if handlersInstalled { cs_supervisor_restore_signal_handlers() }
            for capture in captures where capture.isOpen { close(capture.fd) }
            if ptyMaster >= 0 && !captures.contains(where: { $0.fd == ptyMaster }) {
                close(ptyMaster)
            }
            if signalPipe[0] >= 0 { close(signalPipe[0]) }
            if signalPipe[1] >= 0 { close(signalPipe[1]) }
            if openedTerminalOutput >= 0 { close(openedTerminalOutput) }
            inheritedFiles.forEach { $0.closeAndWipe() }
        }

        guard cs_supervisor_signal_pipe(&signalPipe) == 0 else {
            abortChild()
            throw ProcessSupervisorError.setupFailed("signal relay unavailable")
        }
        guard cs_supervisor_install_signal_handlers(signalPipe[1]) == 0 else {
            abortChild()
            throw ProcessSupervisorError.setupFailed("signal relay unavailable")
        }
        handlersInstalled = true

        if stdinUsesPTY {
            guard cs_terminal_enter_raw(STDIN_FILENO) == 0 else {
                abortChild()
                throw ProcessSupervisorError.setupFailed("terminal relay unavailable")
            }
            terminalIsRaw = true
        }
        if ptyMaster >= 0 {
            _ = cs_resize_pty_from_standard_terminal(ptyMaster)
        }

        let ptyTarget: Int32
        if stdoutMode == CS_OUTPUT_PTY {
            ptyTarget = STDOUT_FILENO
        } else if stderrMode == CS_OUTPUT_PTY {
            ptyTarget = STDERR_FILENO
        } else if ptyMaster >= 0 {
            openedTerminalOutput = open("/dev/tty", O_WRONLY | O_CLOEXEC)
            guard openedTerminalOutput >= 0 else {
                abortChild()
                throw ProcessSupervisorError.setupFailed("terminal output relay unavailable")
            }
            ptyTarget = openedTerminalOutput
        } else {
            ptyTarget = -1
        }

        if ptyMaster >= 0 {
            captures.append(Capture(
                fd: ptyMaster,
                targetFD: ptyTarget,
                stream: .terminal,
                patterns: patterns,
                agentSession: agentSession
            ))
        }
        if stdoutRead >= 0 {
            captures.append(Capture(
                fd: stdoutRead,
                targetFD: STDOUT_FILENO,
                stream: .stdout,
                patterns: patterns,
                agentSession: agentSession
            ))
        }
        if stderrRead >= 0 {
            captures.append(Capture(
                fd: stderrRead,
                targetFD: STDERR_FILENO,
                stream: .stderr,
                patterns: patterns,
                agentSession: agentSession
            ))
        }

        let reporter = IncidentReporter(emitWarnings: emitWarnings)
        var relayInput = stdinUsesPTY
        var terminalStatus: Int32?
        // Runtime limits use the awake-time clock csecd's automation lease is
        // measured on: a sleeping Mac pauses both together, and a wall-clock
        // correction cannot extend an unattended process lifetime.
        let timeoutDeadline = timeoutSeconds.map { AutomationClock.now().awake + $0 }
        var timeoutTerminationSentAt: TimeInterval?

        func forward(_ result: OutputRedactionResult, through capture: Capture) {
            reporter.record(result.matches, stream: capture.stream)
            guard capture.downstreamIsOpen else { return }
            if !result.data.isEmpty, !writeAll(fd: capture.targetFD, data: result.data) {
                capture.downstreamIsOpen = false
                // The child writes to our pipe/PTY rather than the now-closed
                // downstream channel, so recreate ordinary pipeline SIGPIPE.
                if terminalStatus == nil { _ = kill(-childPID, SIGPIPE) }
                close(capture.fd)
                capture.isOpen = false
                reporter.flush(stream: capture.stream)
                return
            }
            if let last = result.data.last {
                capture.atLineBoundary = last == 10 || last == 13
            }
            if capture.atLineBoundary {
                reporter.flush(stream: capture.stream)
            }
        }

        var withholding: Bool { scannerLoss?.withheldBytes != nil }

        var lastReopenAttempt: TimeInterval?
        /// Set when a csecd refused to scan for this command after a loss:
        /// the command has been sent SIGTERM and is reported with this error.
        var scannerStop: Error?
        var scannerStopSentAt: TimeInterval?

        /// Scanned output, kept (the last `primeBytes` of it) only while a lost
        /// scanner may be reopened, to prime the reopened one.
        func remember(_ data: Data, in capture: Capture) {
            guard scannerLoss?.reopen != nil else { return }
            capture.scannedTail.append(data)
        }

        /// Output read while no scanner answers, kept to scan once one
        /// reopens. Past the bound the oldest is dropped, counted as withheld,
        /// and becomes priming context, since nothing of it was forwarded.
        func hold(_ data: Data, in capture: Capture) {
            let dropped = capture.awaitingScan.append(data)
            guard !dropped.isEmpty else { return }
            remember(dropped, in: capture)
            scannerLoss?.withheldBytes = (scannerLoss?.withheldBytes ?? 0) + dropped.count
        }

        /// After a scanner loss the caller's policy lets the command outlive:
        /// try, at most once a second unless `immediately`, to open a scanner
        /// on the restarted csecd. On success every open stream is primed with
        /// the output just before the loss, so a value split across it is
        /// still matched whole, and the output held meanwhile is scanned and
        /// forwarded. A csecd that refuses gets the command stopped.
        func reopenScanner(immediately: Bool = false) throws {
            guard let scannerLoss, scannerLoss.reopensWhenAvailable,
                  let dropped = scannerLoss.withheldBytes,
                  let reopen = scannerLoss.reopen else { return }
            let now = AutomationClock.now().awake
            if !immediately, let last = lastReopenAttempt, now - last < 1 { return }
            lastReopenAttempt = now
            let session: AgentOutputRedactionSession
            switch reopen() {
            case let .opened(opened):
                session = opened
            case .unavailable:
                return
            case let .refused(error):
                scannerLoss.reopensWhenAvailable = false
                if terminalStatus == nil {
                    scannerStop = error
                    scannerStopSentAt = now
                    _ = kill(-childPID, SIGTERM)
                } else {
                    scannerLoss.refusedAfterExit = error
                }
                return
            }
            do {
                for capture in captures where capture.isOpen && !capture.scannedTail.isEmpty {
                    try session.prime(capture.scannedTail.bytes, stream: capture.stream.protocolStream)
                }
            } catch {
                // Lost again before it was usable; keep holding and retry.
                session.close()
                return
            }
            for capture in captures where capture.isOpen {
                capture.redactor = .agent(session, capture.stream.protocolStream)
            }
            scannerLoss.withheldBytes = nil
            scannerLoss.loss = nil
            scannerLoss.reopensWhenAvailable = false
            scannerLoss.reopened?(session, dropped)
            for capture in captures where capture.isOpen && !capture.awaitingScan.isEmpty {
                let held = capture.awaitingScan.bytes
                capture.awaitingScan.removeAll()
                var offset = held.startIndex
                while offset < held.endIndex {
                    let end = min(offset + 16 * 1_024, held.endIndex)
                    try process(held.subdata(in: offset..<end), through: capture)
                    offset = end
                }
            }
        }

        /// The scanner failed: stop the command, or withhold everything from
        /// here on (or hold it until a scanner reopens) when the caller's
        /// policy allows it. `capture` is nil when the loss was noticed with
        /// no output in hand.
        func scannerFailed(_ error: Error, input data: Data, in capture: Capture?) throws {
            guard let scannerLoss else { throw ProcessSupervisorError.redactionFailed(error) }
            switch scannerLoss.decide(error) {
            case .terminate:
                throw ProcessSupervisorError.redactionFailed(error)
            case .withholdRemaining:
                scannerLoss.loss = error
                scannerLoss.withheldBytes = data.count
            case .withholdUntilReopened:
                scannerLoss.loss = error
                scannerLoss.withheldBytes = 0
                scannerLoss.reopensWhenAvailable = true
                if let capture { hold(data, in: capture) }
                try reopenScanner(immediately: true)
            }
        }

        /// While the command is quiet, a csecd that went away is noticed here
        /// rather than at the next output: an automation run whose csecd
        /// restarted resumes its lease (or is stopped, when csecd no longer
        /// holds it or csec was replaced) within about a second.
        func checkScannerWhileQuiet() throws {
            guard let scannerLoss, scannerLoss.withheldBytes == nil,
                  let error = scannerLoss.scannerGone?() else { return }
            try scannerFailed(error, input: Data(), in: nil)
        }

        func process(_ data: Data, through capture: Capture) throws {
            try reopenScanner()
            if let scannerLoss, let withheld = scannerLoss.withheldBytes {
                if scannerLoss.reopensWhenAvailable {
                    hold(data, in: capture)
                } else {
                    scannerLoss.withheldBytes = withheld + data.count
                }
                return
            }
            do {
                forward(try capture.redactor.process(data), through: capture)
                remember(data, in: capture)
            } catch {
                try scannerFailed(error, input: data, in: capture)
            }
        }

        var endOfOutputDeadline: TimeInterval?

        /// A stream is ending while no scanner answers: wait, within the
        /// command's one bounded budget, for a scanner to reopen, so the
        /// held output and whatever the old matcher was holding back are
        /// scanned rather than dropped.
        func awaitScannerBeforeEnd() throws {
            guard let scannerLoss, scannerLoss.reopensWhenAvailable else { return }
            let deadline = endOfOutputDeadline
                ?? AutomationClock.now().awake + ScannerLossHandling.endOfOutputWait
            endOfOutputDeadline = deadline
            while scannerLoss.reopensWhenAvailable, AutomationClock.now().awake < deadline {
                usleep(250_000)
                try reopenScanner()
            }
        }

        func closeCapture(_ capture: Capture) throws {
            guard capture.isOpen else { return }
            try reopenScanner()
            try awaitScannerBeforeEnd()
            // Forwarding what a reopened scanner released can close the
            // capture (its downstream went away).
            guard capture.isOpen else { return }
            if !withholding {
                var result: OutputRedactionResult?
                do {
                    result = try capture.redactor.finish()
                } catch {
                    try scannerFailed(error, input: Data(), in: capture)
                    // The loss showed first at the end: wait for a scanner
                    // here too, so what the old matcher held back is
                    // rebuilt from the prime and released through the new one.
                    try awaitScannerBeforeEnd()
                    guard capture.isOpen else { return }
                    if !withholding { result = try capture.redactor.finish() }
                }
                if let result {
                    forward(result, through: capture)
                    reporter.flush(
                        stream: capture.stream,
                        addLeadingNewline: capture.downstreamIsOpen && !capture.atLineBoundary
                    )
                }
            }
            if let withheld = scannerLoss?.withheldBytes, !capture.awaitingScan.isEmpty {
                // No scanner came back before this stream ended.
                scannerLoss?.withheldBytes = withheld + capture.awaitingScan.count
                capture.awaitingScan.removeAll()
            }
            close(capture.fd)
            capture.isOpen = false
        }

        func suspendWithChild(_ stopSignal: Int32) throws {
            if terminalIsRaw {
                cs_terminal_restore()
                terminalIsRaw = false
            }
            if handlersInstalled {
                cs_supervisor_restore_signal_handlers()
                handlersInstalled = false
            }
            _ = cs_supervisor_suspend_self(stopSignal == SIGSTOP ? SIGTSTP : stopSignal)
            guard cs_supervisor_install_signal_handlers(signalPipe[1]) == 0 else {
                throw ProcessSupervisorError.setupFailed("could not restore signal relay after continue")
            }
            handlersInstalled = true
            if stdinUsesPTY {
                guard cs_terminal_enter_raw(STDIN_FILENO) == 0 else {
                    throw ProcessSupervisorError.setupFailed("could not restore terminal relay after continue")
                }
                terminalIsRaw = true
            }
            if ptyMaster >= 0 { _ = cs_resize_pty_from_standard_terminal(ptyMaster) }
            _ = kill(-childPID, SIGCONT)
        }

        do {
            while terminalStatus == nil || captures.contains(where: \.isOpen) {
                let loopNow = AutomationClock.now().awake
                if terminalStatus == nil,
                   timeoutTerminationSentAt == nil,
                   let timeoutDeadline,
                   loopNow >= timeoutDeadline {
                    timeoutTerminationSentAt = loopNow
                    _ = kill(-childPID, SIGTERM)
                } else if terminalStatus == nil,
                          let sentAt = timeoutTerminationSentAt,
                          loopNow - sentAt >= 5 {
                    _ = kill(-childPID, SIGKILL)
                }
                if terminalStatus == nil, let sentAt = scannerStopSentAt, loopNow - sentAt >= 5 {
                    _ = kill(-childPID, SIGKILL)
                }
                // A lost scanner is noticed and retried on the clock too,
                // not only when output arrives, so a quiet command learns of
                // a restart and held output is released soon after csecd is
                // back.
                try checkScannerWhileQuiet()
                try reopenScanner()
                // Called on every turn (at least every 250 ms) whether or not
                // the command printed anything; `csec ai` asks csecd here for
                // the approvals its command waits on.
                onTick?()
                enum PollSource {
                    case signal
                    case input
                    case capture(Capture)
                    case inheritedFile(InheritedSecretFile)
                }
                var sources: [PollSource] = [.signal]
                var descriptors = [pollfd(
                    fd: signalPipe[0],
                    events: Int16(POLLIN | POLLHUP | POLLERR),
                    revents: 0
                )]
                if relayInput, ptyMaster >= 0 {
                    sources.append(.input)
                    descriptors.append(pollfd(
                        fd: STDIN_FILENO,
                        events: Int16(POLLIN | POLLHUP | POLLERR),
                        revents: 0
                    ))
                }
                for capture in captures where capture.isOpen {
                    sources.append(.capture(capture))
                    descriptors.append(pollfd(
                        fd: capture.fd,
                        events: Int16(POLLIN | POLLHUP | POLLERR),
                        revents: 0
                    ))
                }
                for file in inheritedFiles where file.isWriting {
                    sources.append(.inheritedFile(file))
                    descriptors.append(pollfd(
                        fd: file.writeFD,
                        events: Int16(POLLOUT | POLLHUP | POLLERR),
                        revents: 0
                    ))
                }

                let pollResult = descriptors.withUnsafeMutableBufferPointer { buffer in
                    poll(buffer.baseAddress, nfds_t(buffer.count), 250)
                }
                if pollResult < 0, errno != EINTR {
                    if terminalStatus == nil { _ = kill(-childPID, SIGTERM) }
                }

                if pollResult > 0 {
                    for index in descriptors.indices where descriptors[index].revents != 0 {
                        switch sources[index] {
                        case .signal:
                            var signalBytes = [UInt8](repeating: 0, count: 64)
                            let count = read(signalPipe[0], &signalBytes, signalBytes.count)
                            if count > 0 {
                                for byte in signalBytes.prefix(count) {
                                    let signalNumber = Int32(byte)
                                    switch signalNumber {
                                    case SIGCHLD:
                                        break
                                    case SIGWINCH:
                                        if ptyMaster >= 0 {
                                            _ = cs_resize_pty_from_standard_terminal(ptyMaster)
                                        }
                                        if terminalStatus == nil { _ = kill(-childPID, signalNumber) }
                                    case SIGCONT:
                                        if terminalStatus == nil { _ = kill(-childPID, signalNumber) }
                                    default:
                                        if terminalStatus == nil { _ = kill(-childPID, signalNumber) }
                                    }
                                }
                            }
                        case .input:
                            var input = [UInt8](repeating: 0, count: 16 * 1024)
                            let count = read(STDIN_FILENO, &input, input.count)
                            if count > 0 {
                                let data = Data(input.prefix(count))
                                if !writeAll(fd: ptyMaster, data: data) { relayInput = false }
                            } else if count == 0 {
                                relayInput = false
                            } else if errno != EINTR && errno != EAGAIN {
                                relayInput = false
                            }
                        case let .capture(capture):
                            var bytes = [UInt8](repeating: 0, count: 16 * 1024)
                            let count = read(capture.fd, &bytes, bytes.count)
                            if count > 0 {
                                try process(Data(bytes.prefix(count)), through: capture)
                            } else if count == 0 || (errno != EINTR && errno != EAGAIN) {
                                try closeCapture(capture)
                            }
                        case let .inheritedFile(file):
                            try file.writeAvailable()
                        }
                    }
                }

                if terminalStatus == nil {
                    while true {
                        var status: Int32 = 0
                        let waited = waitpid(childPID, &status, WNOHANG | WUNTRACED | WCONTINUED)
                        if waited == 0 { break }
                        if waited < 0 {
                            if errno == EINTR { continue }
                            break
                        }
                        if cs_wait_status_stopped(status) == 1 {
                            try suspendWithChild(cs_wait_status_stop_signal(status))
                        } else if cs_wait_status_continued(status) == 1 {
                            continue
                        } else if cs_wait_status_exited(status) == 1
                                    || cs_wait_status_signaled(status) == 1 {
                            terminalStatus = status
                            relayInput = false
                            let incompleteDelivery = inheritedFiles.contains(where: \.isWriting)
                            inheritedFiles.forEach { $0.closeAndWipe() }

                            // The root's writes are complete before waitpid reports
                            // exit. Drain everything already queued, then close the
                            // relays rather than hanging on a daemonized descendant
                            // that inherited stdout/stderr. Closing also avoids
                            // signalling a numerically reused process group later.
                            for capture in captures where capture.isOpen {
                                while capture.isOpen {
                                    var descriptor = pollfd(
                                        fd: capture.fd,
                                        events: Int16(POLLIN | POLLHUP | POLLERR),
                                        revents: 0
                                    )
                                    let ready = poll(&descriptor, 1, 0)
                                    guard ready > 0 else {
                                        try closeCapture(capture)
                                        break
                                    }
                                    var bytes = [UInt8](repeating: 0, count: 16 * 1024)
                                    let count = read(capture.fd, &bytes, bytes.count)
                                    if count > 0 {
                                        try process(Data(bytes.prefix(count)), through: capture)
                                    } else {
                                        try closeCapture(capture)
                                    }
                                }
                            }
                            if incompleteDelivery {
                                throw ProcessSupervisorError.deliveryFailed
                            }
                            break
                        }
                    }
                }
            }
        } catch {
            // No unscanned bytes are forwarded after a daemon/protocol failure.
            // If the root is still live, terminate and reap its whole process
            // group before reporting the value-free scanner error.
            if terminalStatus == nil { abortChild() }
            throw error
        }

        guard let terminalStatus else {
            throw ProcessSupervisorError.setupFailed("child status unavailable")
        }
        if let scannerStop {
            throw ProcessSupervisorError.redactionFailed(scannerStop)
        }
        if timeoutTerminationSentAt != nil {
            throw ProcessSupervisorError.timedOut
        }
        return terminalStatus
    }
}

private func errnoMessage() -> String {
    String(cString: strerror(errno))
}

/// The call behind a `cs_spawn_supervised` failure, as a launch error names it.
private func spawnStepName(_ step: cs_spawn_step) -> String {
    switch step {
    case CS_SPAWN_STEP_FORK: return "fork"
    case CS_SPAWN_STEP_CHDIR: return "chdir"
    case CS_SPAWN_STEP_SETSID: return "setsid"
    case CS_SPAWN_STEP_CONTROLLING_TERMINAL: return "TIOCSCTTY"
    case CS_SPAWN_STEP_FOREGROUND_GROUP: return "tcsetpgrp"
    case CS_SPAWN_STEP_PROCESS_GROUP: return "setpgid"
    case CS_SPAWN_STEP_STANDARD_STREAMS: return "dup2"
    case CS_SPAWN_STEP_INHERITED_FDS: return "fd inheritance"
    case CS_SPAWN_STEP_EXEC: return "execve"
    case CS_SPAWN_STEP_EXEC_STATUS: return "exec status"
    default: return "setup"
    }
}

@discardableResult
private func writeAll(fd: Int32, data: Data) -> Bool {
    var offset = 0
    while offset < data.count {
        let written = data.withUnsafeBytes { rawBuffer -> Int in
            guard let base = rawBuffer.baseAddress else { return 0 }
            return write(fd, base.advanced(by: offset), data.count - offset)
        }
        if written > 0 {
            offset += written
        } else if written < 0, errno == EINTR {
            continue
        } else {
            return false
        }
    }
    return true
}
