import ConvenientSecurity
import Darwin
import Foundation

private enum FixtureError: Error, LocalizedError {
    case commandFailed(String, Int32, String)
    case couldNotAllocatePort
    case serverDidNotStart(String)
    case registrationFailed
    case invalidCertificateAuthority
    case unsupportedHostMode(String)
    case authenticationFailed(String)
    case grantReuseFailed(Int)
    case unsupportedScenario(String)
    case concurrentReviewFailed(Int)
    case interruptedReviewFailed(String)
    case orphanedReviewFailed(String)

    var errorDescription: String? {
        switch self {
        case let .commandFailed(command, exitCode, detail):
            return "\(command) failed with status \(exitCode): \(detail)"
        case .couldNotAllocatePort:
            return "could not allocate an isolated localhost port"
        case let .serverDidNotStart(detail):
            return "the isolated sshd did not start: \(detail)"
        case .registrationFailed:
            return "the synthetic RSA identity was not registered"
        case .invalidCertificateAuthority:
            return "the synthetic host certificate authority public key is malformed"
        case let .unsupportedHostMode(mode):
            return "unsupported synthetic host-key mode: \(mode)"
        case let .authenticationFailed(detail):
            return "real OpenSSH authentication failed: \(detail)"
        case let .grantReuseFailed(reviewCount):
            return "two sibling OpenSSH connections required \(reviewCount) policy reviews"
        case let .unsupportedScenario(scenario):
            return "unsupported SSH scenario: \(scenario)"
        case let .concurrentReviewFailed(reviewCount):
            return "three concurrent OpenSSH connections required \(reviewCount) policy reviews"
        case let .interruptedReviewFailed(detail):
            return "an interrupted OpenSSH connection's review was not cancelled: \(detail)"
        case let .orphanedReviewFailed(detail):
            return "an orphaned OpenSSH connection's review was not cancelled: \(detail)"
        }
    }
}

private enum HostFixtureMode: String {
    case ed25519Certificate = "ed25519-certificate"
    case ed25519
    case ecdsa
    case rsa
    case rsaSHA1 = "rsa-sha1"

    var keygenArguments: [String] {
        switch self {
        case .ed25519Certificate, .ed25519:
            return ["-t", "ed25519"]
        case .ecdsa:
            return ["-t", "ecdsa", "-b", "256"]
        case .rsa, .rsaSHA1:
            return ["-t", "rsa", "-b", "2048"]
        }
    }

    var hostKeyAlgorithm: String {
        switch self {
        case .ed25519Certificate: return "ssh-ed25519-cert-v01@openssh.com"
        case .ed25519: return "ssh-ed25519"
        case .ecdsa: return "ecdsa-sha2-nistp256"
        case .rsa: return "rsa-sha2-512"
        case .rsaSHA1: return "ssh-rsa"
        }
    }

    var usesCertificate: Bool { self == .ed25519Certificate }

    var sshdAlgorithmArguments: [String] {
        self == .rsaSHA1 ? ["-o", "HostKeyAlgorithms=ssh-rsa"] : []
    }
}

/// Which real-OpenSSH behavior this run proves (CSEC_SSH_E2E_SCENARIO).
private enum Scenario: String {
    /// Two sibling connections, one after the other, reuse one review.
    case siblings
    /// Three connections started at once wait behind one review.
    case concurrent
    /// An ssh interrupted while its review is on screen cancels that review,
    /// and nothing was approved for the next one.
    case interrupted
    /// The ssh survives SIGKILL of its waiting parent shell.
    case orphaned
}

private struct FixtureProvider: SecretProvider {
    let reference: String
    let value: Data

    var schemes: Set<String> { ["fixture"] }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard ref.uri == reference else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

/// Counts reviews and approves them. While `held`, each review waits for
/// `release()`, like a window waiting on a human; a held review cancelled
/// underneath it is counted as cancelled, as the real window's requester-gone
/// close would be.
private actor CountingGatedPolicyReview: PolicyReviewProvider {
    private var reviewCount = 0
    private var cancelledCount = 0
    private var held: Bool
    private var waiting: [(UUID, CheckedContinuation<Bool, Never>)] = []

    init(held: Bool) {
        self.held = held
    }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviewCount += 1
        guard held else { return .approved(AccessPolicyApproval()) }
        let id = UUID()
        let approved = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                if Task.isCancelled {
                    continuation.resume(returning: false)
                } else {
                    waiting.append((id, continuation))
                }
            }
        } onCancel: {
            Task { await self.cancel(id) }
        }
        return approved ? .approved(AccessPolicyApproval()) : .denied(.requesterGone)
    }

    private func cancel(_ id: UUID) {
        guard let index = waiting.firstIndex(where: { $0.0 == id }) else { return }
        cancelledCount += 1
        waiting.remove(at: index).1.resume(returning: false)
    }

    /// Stop holding: approve every held review and every later one.
    func release() {
        held = false
        let pending = waiting
        waiting = []
        for (_, continuation) in pending { continuation.resume(returning: true) }
    }

    func calls() -> Int { reviewCount }
    func cancellations() -> Int { cancelledCount }
    func pending() -> Int { waiting.count }
}

private func runCommand(_ executable: String, _ arguments: [String]) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardInput = FileHandle.nullDevice
    let output = Pipe()
    process.standardOutput = output
    process.standardError = output
    try process.run()
    let data = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationReason == .exit, process.terminationStatus == 0 else {
        let detail = String(data: data, encoding: .utf8) ?? "no diagnostic"
        throw FixtureError.commandFailed(
            URL(fileURLWithPath: executable).lastPathComponent,
            process.terminationStatus,
            detail.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }
}

private func allocateLoopbackPort() throws -> UInt16 {
    let descriptor = socket(AF_INET, SOCK_STREAM, 0)
    guard descriptor >= 0 else { throw FixtureError.couldNotAllocatePort }
    defer { close(descriptor) }

    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = in_port_t(0)
    address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

    let bound = withUnsafePointer(to: &address) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard bound == 0 else { throw FixtureError.couldNotAllocatePort }

    var selected = sockaddr_in()
    var length = socklen_t(MemoryLayout<sockaddr_in>.size)
    let inspected = withUnsafeMutablePointer(to: &selected) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            getsockname(descriptor, $0, &length)
        }
    }
    guard inspected == 0, selected.sin_port != 0 else {
        throw FixtureError.couldNotAllocatePort
    }
    return UInt16(bigEndian: selected.sin_port)
}

private func readLog(_ url: URL) -> String {
    guard let data = try? Data(contentsOf: url),
          let text = String(data: data, encoding: .utf8) else { return "no diagnostic" }
    return text.trimmingCharacters(in: .whitespacesAndNewlines)
}

private func makeLogHandle(_ url: URL) throws -> FileHandle {
    FileManager.default.createFile(atPath: url.path, contents: nil)
    return try FileHandle(forWritingTo: url)
}

/// Set in the environment of the run inside the fixture terminal session.
private let terminalSessionMarker = "CSEC_SSH_E2E_TERMINAL_SESSION"

private func failAndExit(_ detail: String) -> Never {
    FileHandle.standardError.write(Data("FAIL - \(detail)\n".utf8))
    exit(1)
}

/// Run this binary again under a shell that owns a fresh pty as its
/// controlling terminal, and exit with that run's status.
///
/// Sibling and concurrent connections share one review only under a shared
/// grant root: a coding agent, or a shell with a controlling terminal
/// (`GrantScopeInspector`). Run detached (nohup, launchd, headless CI) the
/// e2e has neither above it, so each `ssh` would rightly be its own root.
/// The fixture session gives every run the same real shape: a terminal shell
/// above the e2e and its `ssh`.
///
/// The shell takes the pty itself: xnu applies `POSIX_SPAWN_SETSID` after the
/// spawn's file actions, so only an open made by the new session leader (the
/// shell's `exec 3<>`) makes the pty its controlling terminal. Output passes
/// straight through; nothing is read from the pty. Closing the master when
/// this process ends hangs the session up, which ends the run inside it.
private func runInsideFixtureTerminalSession() -> Never {
    guard let executablePath = Bundle.main.executablePath else {
        failAndExit("cannot locate cs-ssh-e2e to run it in a fixture terminal session")
    }
    var master: Int32 = -1
    var slave: Int32 = -1
    guard openpty(&master, &slave, nil, nil, nil) == 0, let slaveName = ttyname(slave) else {
        failAndExit("cannot open a pty for the fixture terminal session")
    }
    let slavePath = String(cString: slaveName)
    _ = fcntl(master, F_SETFD, FD_CLOEXEC)
    _ = fcntl(slave, F_SETFD, FD_CLOEXEC)

    var attributes: posix_spawnattr_t?
    posix_spawnattr_init(&attributes)
    defer { posix_spawnattr_destroy(&attributes) }
    posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSID))
    var actions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&actions)
    defer { posix_spawn_file_actions_destroy(&actions) }
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)

    let arguments = [
        "/bin/sh", "-c", #"exec 3<>"$1" || exit 70; "$2"; exit $?"#,
        "sh", slavePath, executablePath,
    ]
    var environment = ProcessInfo.processInfo.environment
    environment[terminalSessionMarker] = "1"
    let environmentEntries = environment.map { "\($0.key)=\($0.value)" }
    let argv = arguments.map { strdup($0) } + [nil]
    let envp = environmentEntries.map { strdup($0) } + [nil]
    defer { (argv + envp).forEach { free($0) } }

    var shell: pid_t = 0
    let spawned = posix_spawn(&shell, "/bin/sh", &actions, &attributes, argv, envp)
    guard spawned == 0 else {
        failAndExit("cannot start the fixture terminal session shell: \(String(cString: strerror(spawned)))")
    }
    var status: Int32 = 0
    while waitpid(shell, &status, 0) < 0 {
        guard errno == EINTR else { failAndExit("lost the fixture terminal session shell") }
    }
    close(slave)
    close(master)
    // A normal exit carries its status in the second byte; otherwise the low
    // seven bits name the signal that ended it.
    let signal = status & 0x7f
    exit(signal == 0 ? (status >> 8) & 0xff : 128 + signal)
}

/// Stops the fixture sshd and removes the fixture directory when the run is
/// ended by a signal, which skips every `defer`. Hanging up the fixture
/// terminal session (its outer run killed by a timeout or Ctrl-C) sends
/// SIGHUP, which `sshd -D` takes as a restart, so without this it would keep
/// listening after the run is gone.
private final class SignalTeardown: @unchecked Sendable {
    private let lock = NSLock()
    private var sshdPID: pid_t = 0
    private var sources: [DispatchSourceSignal] = []
    private let queue = DispatchQueue(label: "cs-ssh-e2e.signal-teardown")

    func install(removing directory: URL) {
        for signalNumber in [SIGHUP, SIGINT, SIGTERM] {
            // Caught, not ignored: an ignored signal stays ignored in the
            // ssh this run spawns, and the interrupted scenario needs SIGINT.
            signal(signalNumber) { _ in }
            let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: queue)
            source.setEventHandler { [self] in
                lock.lock()
                let pid = sshdPID
                lock.unlock()
                if pid > 0 { kill(pid, SIGTERM) }
                try? FileManager.default.removeItem(at: directory)
                FileHandle.standardError.write(Data("FAIL - ended by signal \(signalNumber)\n".utf8))
                exit(128 + signalNumber)
            }
            source.resume()
            sources.append(source)
        }
    }

    func sshdStarted(_ pid: pid_t) {
        lock.lock()
        sshdPID = pid
        lock.unlock()
    }
}

private let signalTeardown = SignalTeardown()

private func waitForFile(_ url: URL, process: Process, timeout: TimeInterval) -> Bool {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if FileManager.default.fileExists(atPath: url.path) { return true }
        if !process.isRunning { return false }
        usleep(20_000)
    }
    return FileManager.default.fileExists(atPath: url.path)
}

let fixtureDirectory = URL(fileURLWithPath: "/private/tmp", isDirectory: true)
    .appendingPathComponent("csec-real-ssh-e2e-\(UUID().uuidString.lowercased())")
let requestedHostMode = ProcessInfo.processInfo.environment["CSEC_SSH_E2E_HOST_MODE"]
    ?? HostFixtureMode.ed25519Certificate.rawValue
guard let hostMode = HostFixtureMode(rawValue: requestedHostMode) else {
    FileHandle.standardError.write(
        Data("FAIL - \(FixtureError.unsupportedHostMode(requestedHostMode).localizedDescription)\n".utf8)
    )
    exit(1)
}
let requestedScenario = ProcessInfo.processInfo.environment["CSEC_SSH_E2E_SCENARIO"]
    ?? Scenario.siblings.rawValue
guard let scenario = Scenario(rawValue: requestedScenario) else {
    FileHandle.standardError.write(
        Data("FAIL - \(FixtureError.unsupportedScenario(requestedScenario).localizedDescription)\n".utf8)
    )
    exit(1)
}

guard ProcessInfo.processInfo.environment[terminalSessionMarker] == "1" else {
    runInsideFixtureTerminalSession()
}
// The connections below must have a shared grant root, the fixture shell or
// one further out; without one this run would prove nothing about reuse.
guard ProcessAncestry.hasControllingTerminal(getpid()) else {
    failAndExit("the fixture terminal session has no controlling terminal")
}
guard let startTime = ProcessAncestry.startTime(of: getpid()),
      GrantScopeInspector.choices(
          planRootPID: getpid(), planRootStartTime: startTime, requestingLabel: "cs-ssh-e2e"
      ).defaultOption.kind != .requestingCommand else {
    failAndExit("the fixture terminal session offers no shared grant root above ssh")
}
signalTeardown.install(removing: fixtureDirectory)

do {
    try FileManager.default.createDirectory(
        at: fixtureDirectory,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
} catch {
    FileHandle.standardError.write(Data("FAIL - cannot create SSH fixture directory\n".utf8))
    exit(1)
}
defer { try? FileManager.default.removeItem(at: fixtureDirectory) }

let clientKey = fixtureDirectory.appendingPathComponent("synthetic-client-rsa")
let clientPublicKey = fixtureDirectory.appendingPathComponent("synthetic-client-rsa.pub")
let hostKey = fixtureDirectory.appendingPathComponent("synthetic-host")
let hostPublicKey = fixtureDirectory.appendingPathComponent("synthetic-host.pub")
let hostCertificate = fixtureDirectory.appendingPathComponent("synthetic-host-cert.pub")
let hostCertificateAuthority = fixtureDirectory.appendingPathComponent("synthetic-host-ca-ed25519")
let hostCertificateAuthorityPublic = fixtureDirectory
    .appendingPathComponent("synthetic-host-ca-ed25519.pub")
let authorizedKeys = fixtureDirectory.appendingPathComponent("authorized_keys")
let knownHosts = fixtureDirectory.appendingPathComponent("known_hosts")
let socketPath = fixtureDirectory.appendingPathComponent("agent.sock").path
let sshdPID = fixtureDirectory.appendingPathComponent("sshd.pid")
let sshdLog = fixtureDirectory.appendingPathComponent("sshd.log")

do {
    try runCommand("/usr/bin/ssh-keygen", [
        "-q", "-t", "rsa", "-b", "2048", "-N", "",
        "-C", "csec-synthetic-real-ssh", "-f", clientKey.path,
    ])
    try runCommand(
        "/usr/bin/ssh-keygen",
        ["-q"] + hostMode.keygenArguments + [
            "-N", "", "-C", "csec-synthetic-host", "-f", hostKey.path,
        ]
    )
    if hostMode.usesCertificate {
        try runCommand("/usr/bin/ssh-keygen", [
            "-q", "-t", "ed25519", "-N", "",
            "-C", "csec-synthetic-host-ca", "-f", hostCertificateAuthority.path,
        ])
        try runCommand("/usr/bin/ssh-keygen", [
            "-q", "-s", hostCertificateAuthority.path,
            "-I", "csec-synthetic-host", "-h", "-n", "127.0.0.1",
            "-V", "-1m:+5m", hostPublicKey.path,
        ])
    }
    try FileManager.default.copyItem(at: clientPublicKey, to: authorizedKeys)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o600], ofItemAtPath: authorizedKeys.path
    )

    // Resolve from memory, then remove the synthetic plaintext private-key file.
    // The real ssh process can succeed only by using the custom agent socket.
    let privateKey = try Data(contentsOf: clientKey)
    try FileManager.default.removeItem(at: clientKey)

    let reference = "fixture://real-open-ssh/rsa-private-key"
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(FixtureProvider(reference: reference, value: privateKey))
    let policyReview = CountingGatedPolicyReview(held: scenario != .siblings)
    // The SSH review turn is observable so the concurrent run can wait until
    // every connection is queued behind the first review.
    let reviewTurns = ConsentQueue()
    let signingService = SSHSigningService(
        resolver: resolver,
        catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore()),
        consent: AutoApproveConsent(),
        policyReview: QueuedPolicyReview(underlying: policyReview, queue: ConsentQueue()),
        allowUnverifiedCallersForTesting: true,
        terminalInspection: .unavailable,
        reviewTurns: reviewTurns
    )
    let registered = try await signingService.registerAlreadyAuthorized(
        [SSHKeyRegistrationIntent(reference: reference, label: "synthetic RSA")],
        caller: CallerInfo(
            pid: getpid(), startTime: 1, description: "synthetic real-SSH fixture"
        )
    )
    guard registered.count == 1, registered[0].algorithm == "ssh-rsa" else {
        throw FixtureError.registrationFailed
    }

    let agentServer = SSHAgentServer(
        path: socketPath,
        trustPolicy: .allowUnverifiedForTesting,
        provider: signingService
    )
    Thread.detachNewThread { try? agentServer.run() }
    let socketDeadline = Date().addingTimeInterval(2)
    while !FileManager.default.fileExists(atPath: socketPath), Date() < socketDeadline {
        usleep(20_000)
    }
    guard FileManager.default.fileExists(atPath: socketPath) else {
        throw FixtureError.serverDidNotStart("SSH-agent socket is absent")
    }

    let port = try allocateLoopbackPort()
    if hostMode.usesCertificate {
        let authorityText = try String(
            contentsOf: hostCertificateAuthorityPublic,
            encoding: .utf8
        )
        let authorityFields = authorityText.split(whereSeparator: { $0.isWhitespace })
        guard authorityFields.count >= 2 else { throw FixtureError.invalidCertificateAuthority }
        try Data(
            "@cert-authority [127.0.0.1]:\(port) \(authorityFields[0]) \(authorityFields[1])\n".utf8
        ).write(to: knownHosts, options: .atomic)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: knownHosts.path
        )
    }

    let sshdOutput = try makeLogHandle(sshdLog)
    let sshd = Process()
    sshd.executableURL = URL(fileURLWithPath: "/usr/sbin/sshd")
    var sshdArguments = [
        "-D", "-e", "-f", "/dev/null",
        "-o", "Port=\(port)",
        "-o", "ListenAddress=127.0.0.1",
        "-o", "HostKey=\(hostKey.path)",
        "-o", "PidFile=\(sshdPID.path)",
        "-o", "UsePAM=no",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "PubkeyAuthentication=yes",
        "-o", "AuthorizedKeysFile=\(authorizedKeys.path)",
        "-o", "StrictModes=no",
        "-o", "UseDNS=no",
        "-o", "LogLevel=DEBUG3",
    ]
    if hostMode.usesCertificate {
        sshdArguments += ["-o", "HostCertificate=\(hostCertificate.path)"]
    }
    sshdArguments += hostMode.sshdAlgorithmArguments
    sshd.arguments = sshdArguments
    sshd.standardInput = FileHandle.nullDevice
    sshd.standardOutput = sshdOutput
    sshd.standardError = sshdOutput
    try sshd.run()
    signalTeardown.sshdStarted(sshd.processIdentifier)
    defer {
        if sshd.isRunning { sshd.terminate() }
        sshd.waitUntilExit()
        try? sshdOutput.close()
    }
    guard waitForFile(sshdPID, process: sshd, timeout: 2) else {
        throw FixtureError.serverDidNotStart(readLog(sshdLog))
    }

    func launchSSH(_ label: String, underParent: Bool = false) throws -> (Process, FileHandle, URL) {
        let sshLog = fixtureDirectory.appendingPathComponent("ssh-\(label).log")
        let sshOutput = try makeLogHandle(sshLog)
        let ssh = Process()
        ssh.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
        let knownHostsPath = hostMode.usesCertificate ? knownHosts.path : "/dev/null"
        let strictHostKeyChecking = hostMode.usesCertificate ? "yes" : "no"
        ssh.arguments = [
            "-F", "/dev/null", "-vvv", "-p", String(port),
            "-o", "UserKnownHostsFile=\(knownHostsPath)",
            "-o", "StrictHostKeyChecking=\(strictHostKeyChecking)",
            "-o", "HostKeyAlgorithms=\(hostMode.hostKeyAlgorithm)",
            "-o", "BatchMode=yes",
            "-o", "PreferredAuthentications=publickey",
            "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no",
            "-o", "IdentitiesOnly=yes",
            "-o", "IdentityFile=\(clientPublicKey.path)",
            "127.0.0.1", "/usr/bin/true",
        ]
        if underParent {
            let arguments = ssh.arguments!
            ssh.executableURL = URL(fileURLWithPath: "/bin/sh")
            ssh.arguments = ["-c", "\"$@\" & child=$!; wait \"$child\"", "orphan-parent", "/usr/bin/ssh"] + arguments
        }
        var environment = ProcessInfo.processInfo.environment
        environment["SSH_AUTH_SOCK"] = socketPath
        ssh.environment = environment
        ssh.standardInput = FileHandle.nullDevice
        ssh.standardOutput = sshOutput
        ssh.standardError = sshOutput
        try ssh.run()
        return (ssh, sshOutput, sshLog)
    }

    func finish(_ launched: (Process, FileHandle, URL)) throws {
        let (ssh, sshOutput, sshLog) = launched
        ssh.waitUntilExit()
        try sshOutput.close()
        guard ssh.terminationReason == .exit, ssh.terminationStatus == 0 else {
            throw FixtureError.authenticationFailed(readLog(sshLog))
        }
    }

    /// Wait for an observable condition, never an assumed sleep order.
    func waitFor(seconds: TimeInterval, _ condition: () async -> Bool) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if await condition() { return true }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        return await condition()
    }

    switch scenario {
    case .siblings:
        for attempt in 1...2 {
            try finish(try launchSSH(String(attempt)))
        }
        let signingReviewCount = await policyReview.calls()
        guard signingReviewCount == 1 else {
            throw FixtureError.grantReuseFailed(signingReviewCount)
        }
        print(
            "ok   - two sibling Apple OpenSSH connections reuse one csec review with "
                + "a synthetic RSA key and \(hostMode.rawValue) host binding"
        )
    case .concurrent:
        let launched = try (1...3).map { try launchSSH("concurrent-\($0)") }
        let queued = await waitFor(seconds: 20) {
            let pending = await policyReview.pending()
            let waiting = await reviewTurns.waitingCount
            return pending == 1 && waiting == 2
        }
        await policyReview.release()
        for connection in launched { try finish(connection) }
        let signingReviewCount = await policyReview.calls()
        guard queued, signingReviewCount == 1 else {
            throw FixtureError.concurrentReviewFailed(signingReviewCount)
        }
        print(
            "ok   - three concurrent Apple OpenSSH connections wait behind one csec review "
                + "and all authenticate (\(hostMode.rawValue) host binding)"
        )
    case .orphaned:
        let (parent, output, _) = try launchSSH("orphaned", underParent: true)
        defer {
            if parent.isRunning { kill(parent.processIdentifier, SIGKILL) }
            parent.waitUntilExit()
            try? output.close()
        }
        guard await waitFor(seconds: 20, { await policyReview.pending() == 1 }) else {
            throw FixtureError.orphanedReviewFailed("the review never appeared")
        }
        kill(parent.processIdentifier, SIGKILL)
        parent.waitUntilExit()
        guard await waitFor(seconds: 10, { await policyReview.cancellations() == 1 }),
              await policyReview.calls() == 1 else {
            throw FixtureError.orphanedReviewFailed("the orphan's review stayed pending or appeared again")
        }
        await policyReview.release()
        try finish(try launchSSH("after-orphan"))
        guard await policyReview.calls() == 2 else {
            throw FixtureError.orphanedReviewFailed("the next live connection was not reviewed afresh")
        }
        print("ok   - killing a waiting ssh's parent withdraws its csec review; the next connection is reviewed afresh")
    case .interrupted:
        let (ssh, sshOutput, _) = try launchSSH("interrupted")
        guard await waitFor(seconds: 20, { await policyReview.pending() == 1 }) else {
            throw FixtureError.interruptedReviewFailed("the review never appeared")
        }
        // What Ctrl-C does to a foreground ssh.
        ssh.interrupt()
        ssh.waitUntilExit()
        try sshOutput.close()
        guard await waitFor(seconds: 10, { await policyReview.cancellations() == 1 }) else {
            throw FixtureError.interruptedReviewFailed("the review stayed on screen after ssh exited")
        }
        guard await policyReview.calls() == 1 else {
            throw FixtureError.interruptedReviewFailed("the interrupted ssh raised more than one review")
        }
        // Nothing was approved, so a fresh ssh is a new question.
        await policyReview.release()
        try finish(try launchSSH("after-interrupt"))
        let signingReviewCount = await policyReview.calls()
        guard signingReviewCount == 2 else {
            throw FixtureError.interruptedReviewFailed(
                "the next ssh raised \(signingReviewCount - 1) reviews instead of 1"
            )
        }
        print(
            "ok   - an interrupted Apple OpenSSH connection cancels its csec review, and the "
                + "next connection is reviewed afresh (\(hostMode.rawValue) host binding)"
        )
    }
} catch {
    FileHandle.standardError.write(Data("FAIL - \(error.localizedDescription)\n".utf8))
    try? FileManager.default.removeItem(at: fixtureDirectory)
    exit(1)
}
