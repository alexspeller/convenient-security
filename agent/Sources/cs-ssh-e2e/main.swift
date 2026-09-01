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
let sshLog = fixtureDirectory.appendingPathComponent("ssh.log")

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
    let signingService = SSHSigningService(
        resolver: resolver,
        catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore()),
        consent: AutoApproveConsent(),
        policyReview: AutoApprovePolicyReview(),
        allowUnverifiedCallersForTesting: true
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
    defer {
        if sshd.isRunning { sshd.terminate() }
        sshd.waitUntilExit()
        try? sshdOutput.close()
    }
    guard waitForFile(sshdPID, process: sshd, timeout: 2) else {
        throw FixtureError.serverDidNotStart(readLog(sshdLog))
    }

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
    var environment = ProcessInfo.processInfo.environment
    environment["SSH_AUTH_SOCK"] = socketPath
    ssh.environment = environment
    ssh.standardInput = FileHandle.nullDevice
    ssh.standardOutput = sshOutput
    ssh.standardError = sshOutput
    try ssh.run()
    ssh.waitUntilExit()
    try sshOutput.close()

    guard ssh.terminationReason == .exit, ssh.terminationStatus == 0 else {
        throw FixtureError.authenticationFailed(readLog(sshLog))
    }
    print(
        "ok   - Apple OpenSSH authenticates through csec with a synthetic RSA key "
            + "and \(hostMode.rawValue) host binding"
    )
} catch {
    FileHandle.standardError.write(Data("FAIL - \(error.localizedDescription)\n".utf8))
    try? FileManager.default.removeItem(at: fixtureDirectory)
    exit(1)
}
