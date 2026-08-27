import Foundation
import ConvenientSecurity
import CSecuritySupport
import Darwin

private struct ProtectedFileDeclaration {
    let environmentName: String
    let reference: String
}

private enum ProtectedFileCommandError: Error, LocalizedError {
    case setupFailed
    case ambientGitHubAuthority
    case invalidGitHubCommand
    case unsupportedGitHubCLI
    case supervisionFailed

    var errorDescription: String? {
        switch self {
        case .setupFailed:
            return "could not prepare protected launch descriptors"
        case .ambientGitHubAuthority:
            return "refusing protected GH_CONFIG_DIR while ambient GitHub authentication remains; remove it first"
        case .invalidGitHubCommand:
            return "the GH_CONFIG_DIR profile requires a direct non-auth gh command"
        case .unsupportedGitHubCLI:
            return "the installed gh cannot prove that ambient authentication is absent"
        case .supervisionFailed:
            return "the protected child could not be supervised safely"
        }
    }
}

func runExecFile(_ arguments: [String]) -> Never {
    var declarations: [ProtectedFileDeclaration] = []
    var githubReference: String?
    var githubHost = "github.com"
    var githubUser: String?
    var githubGitProtocol = "https"
    var reason: String?
    var ttlSeconds = 3600
    var hardTTL = false
    var outputGuard = OutputGuardConfiguration()
    var commandLine: [String] = []
    var index = 0

    parse: while index < arguments.count {
        switch arguments[index] {
        case "--":
            commandLine = Array(arguments[(index + 1)...])
            break parse
        case "--file":
            index += 1
            guard index < arguments.count,
                  let equals = arguments[index].firstIndex(of: "=") else { usage() }
            declarations.append(ProtectedFileDeclaration(
                environmentName: String(arguments[index][..<equals]),
                reference: String(arguments[index][arguments[index].index(after: equals)...])
            ))
        case "--gh-config":
            index += 1
            guard index < arguments.count, githubReference == nil else { usage() }
            githubReference = arguments[index]
        case "--github-host":
            index += 1
            guard index < arguments.count else { usage() }
            githubHost = arguments[index]
        case "--github-user":
            index += 1
            guard index < arguments.count else { usage() }
            githubUser = arguments[index]
        case "--github-git-protocol":
            index += 1
            guard index < arguments.count else { usage() }
            githubGitProtocol = arguments[index]
        case "--reason":
            index += 1
            guard index < arguments.count else { usage() }
            reason = arguments[index]
        case "--for":
            index += 1
            guard index < arguments.count, let seconds = Int(arguments[index]) else { usage() }
            ttlSeconds = seconds
        case "--hard-ttl":
            hardTTL = true
        case "--redact-output":
            index += 1
            guard index < arguments.count,
                  let mode = OutputGuardMode(rawValue: arguments[index]) else { usage() }
            outputGuard.mode = mode
        case let option where option.hasPrefix("--redact-output="):
            guard let mode = OutputGuardMode(
                rawValue: String(option.dropFirst("--redact-output=".count))
            ) else { usage() }
            outputGuard.mode = mode
        case "--redact-output-label":
            index += 1
            guard index < arguments.count,
                  let style = OutputRedactionLabelStyle(rawValue: arguments[index]) else { usage() }
            outputGuard.labelStyle = style
        case let option where option.hasPrefix("--redact-output-label="):
            guard let style = OutputRedactionLabelStyle(
                rawValue: String(option.dropFirst("--redact-output-label=".count))
            ) else { usage() }
            outputGuard.labelStyle = style
        case "--redact-short-values":
            outputGuard.includeShortValues = true
        default:
            usage()
        }
        index += 1
    }

    guard !commandLine.isEmpty,
          (!declarations.isEmpty || githubReference != nil),
          declarations.count + (githubReference == nil ? 0 : 1) <= ProtectedLaunchPlan.maximumFiles,
          declarations.allSatisfy({
              ProtectedLaunchPlan.validEnvironmentName($0.environmentName)
                  && !$0.environmentName.hasPrefix("CSEC_")
                  && !$0.reference.isEmpty
                  && (try? SecretRef($0.reference)) != nil
          }),
          Set(declarations.map(\.environmentName)).count == declarations.count,
          !declarations.contains(where: { $0.environmentName == "GH_CONFIG_DIR" }),
          githubReference.map({ (try? SecretRef($0)) != nil }) ?? true,
          ttlSeconds > 0, ttlSeconds <= 24 * 60 * 60,
          reason?.utf8.count ?? 0 <= 256 else { usage() }

    do {
        let executable = try conservativeExecutable(command: commandLine[0])
        if githubReference != nil {
            guard URL(fileURLWithPath: executable.canonicalPath).lastPathComponent == "gh",
                  !commandLine.dropFirst().contains(where: { $0 == "auth" || $0 == "extension" }) else {
                throw ProtectedFileCommandError.invalidGitHubCommand
            }
        }

        let bindings = declarations.enumerated().map { offset, declaration in
            ProtectedFileBinding.raw(
                environmentName: declaration.environmentName,
                reference: declaration.reference,
                index: offset
            )
        } + (githubReference.map {
            [ProtectedFileBinding.github(
                reference: $0,
                host: githubHost,
                user: githubUser,
                gitProtocol: githubGitProtocol
            )]
        } ?? [])

        var environment = ProtectedLaunchPlan.sanitizedEnvironment(
            ProcessInfo.processInfo.environment
        )
        for binding in bindings {
            if let name = binding.environmentName { environment.removeValue(forKey: name) }
        }
        if githubReference != nil {
            for name in [
                "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
            ] { environment.removeValue(forKey: name) }
        }

        let io = try ProtectedLaunchIO(outputMode: outputGuard.mode)
        let operation = reason
            ?? "csec exec-file \((executable.canonicalPath as NSString).lastPathComponent)"
        let deliveryPlan = DeliveryPlan(
            mechanism: .capabilityGIDFile,
            executable: executable,
            root: .caller,
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: ttlSeconds,
            operationContext: operation,
            commandDigest: try ExecutableInspection.commandDigest(commandLine),
            outputGuard: outputGuard.plan
        )
        guard let startTime = ProcessAncestry.startTime(of: getpid()) else {
            throw ProtectedFileCommandError.setupFailed
        }
        let auditSessionID = cs_self_audit_session_id()
        guard auditSessionID != UInt32.max else { throw ProtectedFileCommandError.setupFailed }
        let launchPlan = ProtectedLaunchPlan(
            launcherPID: getpid(),
            launcherStartTime: startTime,
            uid: getuid(),
            auditSessionID: auditSessionID,
            executable: executable,
            commandLine: commandLine,
            environment: environment,
            files: bindings,
            deliveryPlan: deliveryPlan,
            hardTTL: hardTTL,
            usesPTY: io.usesPTY
        )
        try launchPlan.validate()
        if githubReference != nil {
            try requireNoAmbientGitHubAuthority(
                ghPath: executable.canonicalPath,
                host: githubHost
            )
        }

        #if DEBUG
        let rootTrust: RootHelperServerTrustPolicy = .allowUnverifiedForTesting
        #else
        let rootTrust: RootHelperServerTrustPolicy = .requireProductRootHelper
        #endif
        let rootClient = RootHelperClient(trustPolicy: rootTrust)
        let prepared = try rootClient.prepare(
            plan: launchPlan,
            cwdFD: io.cwdFD,
            stdinFD: io.childStdinFD,
            stdoutFD: io.childStdoutFD,
            stderrFD: io.childStderrFD
        )
        io.didPrepare()
        var launched = false
        defer {
            if !launched {
                rootClient.cancel(nonce: prepared.nonce, planDigest: prepared.planDigest)
            }
        }

        try makeAgentClient().approveProtectedLaunch(
            rendezvousNonce: prepared.nonce,
            launchPlan: launchPlan,
            launchPlanDigest: prepared.planDigest
        )

        let scanner: AgentOutputRedactionSession?
        if outputGuard.mode != .never, !io.streams.isEmpty {
            scanner = try makeAgentClient().beginOutputRedaction(
                destination: .localDevelopment,
                streams: io.streams,
                includeShortValues: outputGuard.includeShortValues
            )
        } else {
            scanner = nil
        }
        defer { scanner?.close() }

        if outputGuard.mode == .tty, io.streams.isEmpty {
            writeProtectedFileError(
                "csec exec-file: warning: tty output masking is inactive for redirected output; "
                    + "use --redact-output=always to alter captured logs\n"
            )
        } else if outputGuard.mode == .never {
            writeProtectedFileError(
                "csec exec-file: warning: output detection and masking explicitly disabled\n"
            )
        }
        if outputGuard.labelStyle == .reference {
            writeProtectedFileError(
                "csec exec-file: reference-shaped labels are unavailable because plaintext stays in csecd/rootd; using opaque labels\n"
            )
        }

        let child = try rootClient.start(
            nonce: prepared.nonce,
            planDigest: prepared.planDigest
        )
        launched = true
        let status = try RemoteRootProcessSupervisor.run(
            io: io,
            rootClient: rootClient,
            prepared: prepared,
            childPID: child.pid,
            childStartTime: child.startTime,
            scanner: scanner
        )
        cs_terminate_like_wait_status(status)
    } catch {
        writeProtectedFileError("csec exec-file: \(error.localizedDescription)\n")
        exit(1)
    }
}

/// `csec exec` in a project holding `*.csec` sidecars: materialize every
/// protected file back at its original project path for the wrapped process tree,
/// then run the command. The tmpfs bytes and their `root:<gid>` isolation come
/// from the same rootd path `csec exec-file` uses; the launcher additionally
/// installs — and always tears down — the symlinks that surface each file where a
/// tool expects it. csecd independently binds each value to the path its blob was
/// protected at, so a planted or moved sidecar fails closed before any launch.
func runSidecarExec(
    commandLine: [String],
    discoveries: [DiscoveredProtectedFile],
    environmentAssignments: [(name: String, reference: String)],
    reason: String?,
    ttlSeconds: Int,
    outputGuard: OutputGuardConfiguration
) -> Never {
    // Symlink teardown must survive `cs_terminate_like_wait_status` (which exits
    // and skips `defer`), so it is done explicitly at every exit path rather than
    // in a `defer`; a hard-killed launcher leaves only dangling links over an
    // already-unlinked tmpfs node.
    var materialization: ProtectedSymlinkMaterialization?
    do {
        let executable = try conservativeExecutable(command: commandLine[0])
        // Sidecar files surface via launcher-installed symlinks; folded-in
        // environment injection (`--set` and env-scanned references) surfaces as
        // values rootd places directly in the child environment. Both ride the
        // same approval, so plaintext is resolved once by csecd and never touches
        // the launcher.
        let symlinkBindings = discoveries.enumerated().map { offset, discovery in
            ProtectedFileBinding.symlink(
                projectRelativePath: discovery.targetRelativePath,
                reference: discovery.reference.uri,
                index: offset
            )
        }
        let valueBindings = environmentAssignments.enumerated().map { offset, assignment in
            ProtectedFileBinding.value(
                environmentName: assignment.name,
                reference: assignment.reference,
                index: offset
            )
        }
        let bindings = symlinkBindings + valueBindings
        var environment = ProtectedLaunchPlan.sanitizedEnvironment(
            ProcessInfo.processInfo.environment
        )
        // A value-in-environment binding owns its variable; drop any inherited
        // entry (e.g. the literal `DATABASE_URL=csec://…` an env-scan matched) so
        // the plan validator's "name not already in the base environment" rule
        // holds and the resolved value is what the child sees.
        for binding in bindings {
            if let name = binding.environmentName { environment.removeValue(forKey: name) }
        }
        let io = try ProtectedLaunchIO(outputMode: outputGuard.mode)
        let operation = reason
            ?? "csec exec (\(discoveries.count) protected file(s)) "
                + "\((executable.canonicalPath as NSString).lastPathComponent)"
        let deliveryPlan = DeliveryPlan(
            mechanism: .capabilityGIDFile,
            executable: executable,
            root: .caller,
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: ttlSeconds,
            operationContext: operation,
            commandDigest: try ExecutableInspection.commandDigest(commandLine),
            outputGuard: outputGuard.plan
        )
        guard let startTime = ProcessAncestry.startTime(of: getpid()) else {
            throw ProtectedFileCommandError.setupFailed
        }
        let auditSessionID = cs_self_audit_session_id()
        guard auditSessionID != UInt32.max else { throw ProtectedFileCommandError.setupFailed }
        let launchPlan = ProtectedLaunchPlan(
            launcherPID: getpid(),
            launcherStartTime: startTime,
            uid: getuid(),
            auditSessionID: auditSessionID,
            executable: executable,
            commandLine: commandLine,
            environment: environment,
            files: bindings,
            deliveryPlan: deliveryPlan,
            usesPTY: io.usesPTY
        )
        try launchPlan.validate()

        #if DEBUG
        let rootTrust: RootHelperServerTrustPolicy = .allowUnverifiedForTesting
        #else
        let rootTrust: RootHelperServerTrustPolicy = .requireProductRootHelper
        #endif
        let rootClient = RootHelperClient(trustPolicy: rootTrust)
        let prepared = try rootClient.prepare(
            plan: launchPlan,
            cwdFD: io.cwdFD,
            stdinFD: io.childStdinFD,
            stdoutFD: io.childStdoutFD,
            stderrFD: io.childStderrFD
        )
        io.didPrepare()

        do {
            // After approval the tmpfs files exist; resolution also lets csecd bind
            // each value to its stored path before it returns success here.
            try makeAgentClient().approveProtectedLaunch(
                rendezvousNonce: prepared.nonce,
                launchPlan: launchPlan,
                launchPlanDigest: prepared.planDigest
            )

            let session = try ProtectedSymlinkMaterialization(
                projectDirectory: FileManager.default.currentDirectoryPath,
                mountRoot: RootHelperSocket.defaultMountPath())
            materialization = session
            let sessionPrefix = (RootHelperSocket.defaultMountPath() as NSString)
                .appendingPathComponent(prepared.nonce)
            // Only sidecar bindings carry a symlink target; value-in-environment
            // bindings surface no file, so they install no link.
            try session.install(bindings.compactMap { binding in
                binding.symlinkTarget.map { target in
                    ProtectedSymlinkMaterialization.Link(
                        projectRelativePath: target,
                        tmpfsPath: (sessionPrefix as NSString)
                            .appendingPathComponent(binding.relativePath)
                    )
                }
            })

            let scanner: AgentOutputRedactionSession?
            if outputGuard.mode != .never, !io.streams.isEmpty {
                scanner = try makeAgentClient().beginOutputRedaction(
                    destination: .localDevelopment,
                    streams: io.streams,
                    includeShortValues: outputGuard.includeShortValues
                )
            } else {
                scanner = nil
            }
            defer { scanner?.close() }

            let child = try rootClient.start(
                nonce: prepared.nonce,
                planDigest: prepared.planDigest
            )
            let status = try RemoteRootProcessSupervisor.run(
                io: io,
                rootClient: rootClient,
                prepared: prepared,
                childPID: child.pid,
                childStartTime: child.startTime,
                scanner: scanner
            )
            materialization?.removeAll()
            cs_terminate_like_wait_status(status)
        } catch {
            materialization?.removeAll()
            rootClient.cancel(nonce: prepared.nonce, planDigest: prepared.planDigest)
            throw error
        }
    } catch {
        materialization?.removeAll()
        writeProtectedFileError("csec exec: \(error.localizedDescription)\n")
        exit(1)
    }
}

private func requireNoAmbientGitHubAuthority(ghPath: String, host: String) throws {
    let ambientNames = [
        "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
        "GH_CONFIG_DIR",
    ]
    guard ambientNames.allSatisfy({ ProcessInfo.processInfo.environment[$0] == nil }) else {
        throw ProtectedFileCommandError.ambientGitHubAuthority
    }
    var environment = ProtectedLaunchPlan.sanitizedEnvironment(ProcessInfo.processInfo.environment)
    for name in ambientNames { environment.removeValue(forKey: name) }
    // `auth status` may contact the network and report failure while a local
    // credential still exists. `auth token` is the local config/keyring probe;
    // its stdout goes straight to /dev/null so csec never receives those bytes.
    // Requiring both probes to report no usable authority makes an offline
    // status check unable to hide a locally retrievable token.
    let capabilityProbe = Process()
    capabilityProbe.executableURL = URL(fileURLWithPath: ghPath)
    capabilityProbe.arguments = ["auth", "token", "--help"]
    capabilityProbe.environment = environment
    capabilityProbe.standardInput = FileHandle.nullDevice
    capabilityProbe.standardOutput = FileHandle.nullDevice
    capabilityProbe.standardError = FileHandle.nullDevice
    try capabilityProbe.run()
    capabilityProbe.waitUntilExit()
    guard capabilityProbe.terminationReason == .exit,
          capabilityProbe.terminationStatus == 0 else {
        throw ProtectedFileCommandError.unsupportedGitHubCLI
    }

    for arguments in [
        ["auth", "status", "--hostname", host],
        ["auth", "token", "--hostname", host],
    ] {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: ghPath)
        process.arguments = arguments
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        guard process.terminationReason == .exit, process.terminationStatus != 0 else {
            throw ProtectedFileCommandError.ambientGitHubAuthority
        }
    }
}

private final class ProtectedLaunchIO {
    let cwdFD: Int32
    let usesPTY: Bool
    private(set) var childStdinFD: Int32
    private(set) var childStdoutFD: Int32
    private(set) var childStderrFD: Int32
    private(set) var ptyMasterFD: Int32 = -1
    private(set) var stdoutReadFD: Int32 = -1
    private(set) var stderrReadFD: Int32 = -1
    private var ownedChildFDs: [Int32] = []
    private var didSend = false

    var streams: [OutputRedactionStream] {
        if ptyMasterFD >= 0 { return [.terminal] }
        var result: [OutputRedactionStream] = []
        if stdoutReadFD >= 0 { result.append(.stdout) }
        if stderrReadFD >= 0 { result.append(.stderr) }
        return result
    }

    init(outputMode: OutputGuardMode) throws {
        cwdFD = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard cwdFD >= 0 else { throw ProtectedFileCommandError.setupFailed }
        childStdinFD = STDIN_FILENO
        childStdoutFD = STDOUT_FILENO
        childStderrFD = STDERR_FILENO

        let allTTY = isatty(STDIN_FILENO) == 1
            && isatty(STDOUT_FILENO) == 1
            && isatty(STDERR_FILENO) == 1
        usesPTY = allTTY
        if allTTY {
            var master: Int32 = -1
            var slave: Int32 = -1
            guard cs_open_standard_pty(&master, &slave) == 0 else {
                close(cwdFD)
                throw ProtectedFileCommandError.setupFailed
            }
            ptyMasterFD = master
            childStdinFD = slave
            childStdoutFD = slave
            childStderrFD = slave
            ownedChildFDs = [slave]
        } else if outputMode == .always {
            let stdoutPipe = try Self.makePipe()
            let stderrPipe = try Self.makePipe()
            stdoutReadFD = stdoutPipe.read
            stderrReadFD = stderrPipe.read
            childStdoutFD = stdoutPipe.write
            childStderrFD = stderrPipe.write
            ownedChildFDs = [stdoutPipe.write, stderrPipe.write]
        }
    }

    deinit {
        if !didSend { close(cwdFD) }
        for fd in ownedChildFDs where fd >= 0 { close(fd) }
        if ptyMasterFD >= 0 { close(ptyMasterFD) }
        if stdoutReadFD >= 0 { close(stdoutReadFD) }
        if stderrReadFD >= 0 { close(stderrReadFD) }
    }

    func didPrepare() {
        guard !didSend else { return }
        didSend = true
        close(cwdFD)
        for fd in ownedChildFDs where fd >= 0 { close(fd) }
        ownedChildFDs.removeAll()
    }

    func relinquishCapture(_ fd: Int32) {
        if ptyMasterFD == fd { ptyMasterFD = -1 }
        if stdoutReadFD == fd { stdoutReadFD = -1 }
        if stderrReadFD == fd { stderrReadFD = -1 }
    }

    private static func makePipe() throws -> (read: Int32, write: Int32) {
        var descriptors: [Int32] = [-1, -1]
        guard pipe(&descriptors) == 0 else { throw ProtectedFileCommandError.setupFailed }
        for fd in descriptors {
            let flags = fcntl(fd, F_GETFD)
            guard flags >= 0, fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0 else {
                close(descriptors[0]); close(descriptors[1])
                throw ProtectedFileCommandError.setupFailed
            }
        }
        return (descriptors[0], descriptors[1])
    }
}

private final class RemoteCapture {
    let fd: Int32
    let targetFD: Int32
    let stream: OutputRedactionStream
    var isOpen = true

    init(fd: Int32, targetFD: Int32, stream: OutputRedactionStream) {
        self.fd = fd
        self.targetFD = targetFD
        self.stream = stream
    }
}

private enum RemoteRootProcessSupervisor {
    static func run(
        io: ProtectedLaunchIO,
        rootClient: RootHelperClient,
        prepared: PreparedRootLaunch,
        childPID: pid_t,
        childStartTime: UInt64,
        scanner: AgentOutputRedactionSession?
    ) throws -> Int32 {
        guard childPID > 1, childStartTime > 0 else {
            throw ProtectedFileCommandError.supervisionFailed
        }
        var captures: [RemoteCapture] = []
        if io.ptyMasterFD >= 0 {
            captures.append(RemoteCapture(
                fd: io.ptyMasterFD,
                targetFD: STDOUT_FILENO,
                stream: .terminal
            ))
        }
        if io.stdoutReadFD >= 0 {
            captures.append(RemoteCapture(
                fd: io.stdoutReadFD,
                targetFD: STDOUT_FILENO,
                stream: .stdout
            ))
        }
        if io.stderrReadFD >= 0 {
            captures.append(RemoteCapture(
                fd: io.stderrReadFD,
                targetFD: STDERR_FILENO,
                stream: .stderr
            ))
        }
        for capture in captures { io.relinquishCapture(capture.fd) }

        var signalPipe: [Int32] = [-1, -1]
        var handlersInstalled = false
        var terminalRaw = false
        var relayInput = io.usesPTY
        defer {
            if terminalRaw { cs_terminal_restore() }
            if handlersInstalled { cs_supervisor_restore_signal_handlers() }
            if signalPipe[0] >= 0 { close(signalPipe[0]) }
            if signalPipe[1] >= 0 { close(signalPipe[1]) }
            for capture in captures where capture.isOpen { close(capture.fd) }
        }

        guard cs_supervisor_signal_pipe(&signalPipe) == 0,
              cs_supervisor_install_signal_handlers(signalPipe[1]) == 0 else {
            rootClient.cancel(nonce: prepared.nonce, planDigest: prepared.planDigest)
            throw ProtectedFileCommandError.supervisionFailed
        }
        handlersInstalled = true
        if io.usesPTY {
            guard cs_terminal_enter_raw(STDIN_FILENO) == 0 else {
                rootClient.cancel(nonce: prepared.nonce, planDigest: prepared.planDigest)
                throw ProtectedFileCommandError.supervisionFailed
            }
            terminalRaw = true
            _ = cs_resize_pty_from_standard_terminal(captures[0].fd)
        }

        var waitStatus: Int32?
        var lastStatusCheck = Date.distantPast

        func sendSignal(_ signal: Int32) {
            try? rootClient.signal(
                signal,
                nonce: prepared.nonce,
                planDigest: prepared.planDigest
            )
        }

        func forward(_ data: Data, capture: RemoteCapture) throws {
            let output: Data
            if let scanner {
                let result = try scanner.process(data, stream: capture.stream)
                output = result.data
                for match in result.matches {
                    writeProtectedFileError(
                        "csec: warning: protected output detected and redacted "
                            + "(\(match.opaqueID), \(capture.stream.rawValue), \(match.representation.rawValue))\n"
                    )
                }
            } else {
                output = data
            }
            guard writeProtectedFileAll(fd: capture.targetFD, data: output) else {
                sendSignal(SIGPIPE)
                close(capture.fd)
                capture.isOpen = false
                return
            }
        }

        func finish(_ capture: RemoteCapture) throws {
            guard capture.isOpen else { return }
            if let scanner {
                let result = try scanner.finish(stream: capture.stream)
                guard writeProtectedFileAll(fd: capture.targetFD, data: result.data) else {
                    sendSignal(SIGPIPE)
                    close(capture.fd)
                    capture.isOpen = false
                    return
                }
                for match in result.matches {
                    writeProtectedFileError(
                        "csec: warning: protected output detected and redacted "
                            + "(\(match.opaqueID), \(capture.stream.rawValue), \(match.representation.rawValue))\n"
                    )
                }
            }
            close(capture.fd)
            capture.isOpen = false
        }

        do {
            while waitStatus == nil || captures.contains(where: \.isOpen) {
                enum Source { case signal, input, capture(RemoteCapture) }
                var sources: [Source] = [.signal]
                var descriptors = [pollfd(
                    fd: signalPipe[0],
                    events: Int16(POLLIN | POLLHUP | POLLERR),
                    revents: 0
                )]
                if relayInput, let terminal = captures.first(where: { $0.stream == .terminal }) {
                    sources.append(.input)
                    descriptors.append(pollfd(
                        fd: STDIN_FILENO,
                        events: Int16(POLLIN | POLLHUP | POLLERR),
                        revents: 0
                    ))
                    _ = terminal
                }
                for capture in captures where capture.isOpen {
                    sources.append(.capture(capture))
                    descriptors.append(pollfd(
                        fd: capture.fd,
                        events: Int16(POLLIN | POLLHUP | POLLERR),
                        revents: 0
                    ))
                }
                let result = descriptors.withUnsafeMutableBufferPointer {
                    poll($0.baseAddress, nfds_t($0.count), 100)
                }
                if result < 0, errno != EINTR { throw ProtectedFileCommandError.supervisionFailed }
                if result > 0 {
                    for offset in descriptors.indices where descriptors[offset].revents != 0 {
                        switch sources[offset] {
                        case .signal:
                            var bytes = [UInt8](repeating: 0, count: 64)
                            let count = read(signalPipe[0], &bytes, bytes.count)
                            if count > 0 {
                                for byte in bytes.prefix(count) {
                                    let signal = Int32(byte)
                                    switch signal {
                                    case SIGCHLD:
                                        break
                                    case SIGWINCH:
                                        if let terminal = captures.first(where: { $0.stream == .terminal }) {
                                            _ = cs_resize_pty_from_standard_terminal(terminal.fd)
                                        }
                                        sendSignal(signal)
                                    case SIGTSTP, SIGSTOP:
                                        sendSignal(signal)
                                        if terminalRaw { cs_terminal_restore(); terminalRaw = false }
                                        cs_supervisor_restore_signal_handlers(); handlersInstalled = false
                                        _ = cs_supervisor_suspend_self(signal == SIGSTOP ? SIGTSTP : signal)
                                        guard cs_supervisor_install_signal_handlers(signalPipe[1]) == 0 else {
                                            throw ProtectedFileCommandError.supervisionFailed
                                        }
                                        handlersInstalled = true
                                        if io.usesPTY {
                                            guard cs_terminal_enter_raw(STDIN_FILENO) == 0 else {
                                                throw ProtectedFileCommandError.supervisionFailed
                                            }
                                            terminalRaw = true
                                        }
                                        sendSignal(SIGCONT)
                                    default:
                                        sendSignal(signal)
                                    }
                                }
                            }
                        case .input:
                            guard let terminal = captures.first(where: { $0.stream == .terminal }) else {
                                relayInput = false
                                continue
                            }
                            var bytes = [UInt8](repeating: 0, count: 16 * 1024)
                            let count = read(STDIN_FILENO, &bytes, bytes.count)
                            if count > 0 {
                                if !writeProtectedFileAll(
                                    fd: terminal.fd,
                                    data: Data(bytes.prefix(count))
                                ) { relayInput = false }
                            } else if count == 0 || (errno != EINTR && errno != EAGAIN) {
                                relayInput = false
                            }
                        case let .capture(capture):
                            var bytes = [UInt8](repeating: 0, count: 16 * 1024)
                            let count = read(capture.fd, &bytes, bytes.count)
                            if count > 0 {
                                try forward(Data(bytes.prefix(count)), capture: capture)
                            } else if count == 0 || (errno != EINTR && errno != EAGAIN) {
                                try finish(capture)
                            }
                        }
                    }
                }

                if waitStatus == nil,
                   Date().timeIntervalSince(lastStatusCheck) >= 0.2 {
                    lastStatusCheck = Date()
                    let status = try rootClient.status(
                        nonce: prepared.nonce,
                        planDigest: prepared.planDigest
                    )
                    if status.state == .finished, let raw = status.waitStatus {
                        waitStatus = raw
                        relayInput = false
                        // Drain only bytes already queued. A surviving descendant
                        // may retain an output fd, but must not keep csec alive.
                        for capture in captures where capture.isOpen {
                            while capture.isOpen {
                                var descriptor = pollfd(
                                    fd: capture.fd,
                                    events: Int16(POLLIN | POLLHUP | POLLERR),
                                    revents: 0
                                )
                                guard poll(&descriptor, 1, 0) > 0 else {
                                    try finish(capture)
                                    break
                                }
                                var bytes = [UInt8](repeating: 0, count: 16 * 1024)
                                let count = read(capture.fd, &bytes, bytes.count)
                                if count > 0 {
                                    try forward(Data(bytes.prefix(count)), capture: capture)
                                } else {
                                    try finish(capture)
                                }
                            }
                        }
                    } else if status.state == .cancelled {
                        throw ProtectedFileCommandError.supervisionFailed
                    }
                }
            }
        } catch {
            rootClient.cancel(nonce: prepared.nonce, planDigest: prepared.planDigest)
            throw error
        }
        guard let waitStatus else { throw ProtectedFileCommandError.supervisionFailed }
        return waitStatus
    }
}

private func writeProtectedFileError(_ message: String) {
    FileHandle.standardError.write(Data(message.utf8))
}

@discardableResult
private func writeProtectedFileAll(fd: Int32, data: Data) -> Bool {
    var offset = 0
    while offset < data.count {
        let count = data.withUnsafeBytes { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            return write(fd, base.advanced(by: offset), data.count - offset)
        }
        if count > 0 { offset += count }
        else if count < 0, errno == EINTR { continue }
        else { return false }
    }
    return true
}
