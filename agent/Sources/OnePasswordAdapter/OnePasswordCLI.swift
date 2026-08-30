import Foundation
import Security
import ConvenientSecurity
import Darwin

/// Locates and runs the 1Password CLI (`op`). Encapsulates all subprocess
/// handling so `OnePasswordProvider` stays declarative.
public enum OnePasswordCLI {
    public static let defaultTimeout: TimeInterval = 120

    /// Absolute path to `op`, using common installation locations. Debug builds
    /// accept `OP_CLI_PATH` for isolated tests; a shipping signed agent must not
    /// select security-critical provider code from attacker-controlled process
    /// environment.
    public static func locate() -> String? {
        let fileManager = FileManager.default
        #if DEBUG
        if let override = ProcessInfo.processInfo.environment["OP_CLI_PATH"],
           !override.isEmpty, fileManager.isExecutableFile(atPath: override) {
            return override
        }
        #endif
        let candidates = ["/opt/homebrew/bin/op", "/usr/local/bin/op", "/usr/bin/op"]
        return candidates.first {
            fileManager.isExecutableFile(atPath: $0) && trustReport(for: $0).trusted
        }
    }

    public struct TrustReport: Sendable {
        public let canonicalPath: String
        public let identifier: String?
        public let teamIdentifier: String?
        public let signatureValid: Bool
        public let hardenedRuntime: Bool
        public let dangerousEntitlements: [String]
        public let requirementMatches: Bool

        public var trusted: Bool {
            signatureValid
                && hardenedRuntime
                && dangerousEntitlements.isEmpty
                && requirementMatches
        }
    }

    /// Validate the exact official 1Password CLI requirement. This is repeated
    /// immediately before each spawn. A root-owned installation removes the
    /// remaining user-writable-path TOCTOU concern; Homebrew installations are
    /// still protected by 1Password desktop integration refusing an unsigned
    /// impostor, but should be treated as a compatibility installation.
    public static func trustReport(for path: String) -> TrustReport {
        let canonicalPath = URL(fileURLWithPath: path)
            .standardizedFileURL
            .resolvingSymlinksInPath()
            .path
        var code: SecStaticCode?
        let creationStatus = SecStaticCodeCreateWithPath(
            URL(fileURLWithPath: canonicalPath) as CFURL,
            SecCSFlags(rawValue: 0),
            &code
        )
        guard creationStatus == errSecSuccess, let code else {
            return TrustReport(
                canonicalPath: canonicalPath,
                identifier: nil,
                teamIdentifier: nil,
                signatureValid: false,
                hardenedRuntime: false,
                dangerousEntitlements: [],
                requirementMatches: false
            )
        }

        let signatureValid = SecStaticCodeCheckValidity(
            code,
            SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)),
            nil
        ) == errSecSuccess
        var information: CFDictionary?
        _ = SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: UInt32(kSecCSSigningInformation)),
            &information
        )
        let dictionary = information as? [String: Any]
        let identifier = dictionary?[kSecCodeInfoIdentifier as String] as? String
        let teamIdentifier = dictionary?[kSecCodeInfoTeamIdentifier as String] as? String
        let flags = (dictionary?[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let entitlements = dictionary?[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        let dangerousEntitlements = ProductCodeIdentity.forbiddenEntitlements.filter {
            (entitlements[$0] as? Bool) == true
        }

        var requirement: SecRequirement?
        let requirementText = "identifier \"com.1password.op\" and anchor apple generic and certificate leaf[subject.OU] = \"2BUA8C4S2C\""
        let requirementStatus = SecRequirementCreateWithString(
            requirementText as CFString,
            SecCSFlags(rawValue: 0),
            &requirement
        )
        let requirementMatches = requirementStatus == errSecSuccess
            && requirement.map {
                SecStaticCodeCheckValidity(
                    code,
                    SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)),
                    $0
                ) == errSecSuccess
            } == true

        return TrustReport(
            canonicalPath: canonicalPath,
            identifier: identifier,
            teamIdentifier: teamIdentifier,
            signatureValid: signatureValid,
            hardenedRuntime: flags & 0x0001_0000 != 0, // CS_RUNTIME
            dangerousEntitlements: dangerousEntitlements,
            requirementMatches: requirementMatches
        )
    }

    public struct Result: Sendable {
        public let status: Int32
        public let stdout: Data
        public let stderr: Data

        public init(status: Int32, stdout: Data, stderr: Data) {
            self.status = status
            self.stdout = stdout
            self.stderr = stderr
        }
    }

    /// Do not copy csecd's ambient environment into `op`: even a short-lived
    /// child can be exposed through KERN_PROCARGS2/pgrep process-title bugs.
    /// `op` needs its account home and standard locale/path, not arbitrary
    /// shell credentials such as GITHUB_TOKEN or database URLs.
    public static func sanitizedEnvironment() -> [String: String] {
        var environment = [
            "HOME": NSHomeDirectory(),
            "USER": NSUserName(),
            "LOGNAME": NSUserName(),
            "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        ]
        if let lang = ProcessInfo.processInfo.environment["LANG"], !lang.isEmpty {
            environment["LANG"] = lang
        }
        return environment
    }

    /// Run `op` with `arguments`, capturing stdout/stderr. Executed off the
    /// cooperative pool so it never blocks an actor. Arguments are passed as an
    /// array (no shell), so a reference can't cause shell injection. `stdin`
    /// carries anything sensitive (e.g. an item JSON template with field
    /// values) — argv is visible to every process on the machine, a pipe is
    /// not.
    public static func run(
        _ path: String,
        _ arguments: [String],
        stdin input: Data? = nil,
        timeout: TimeInterval = defaultTimeout
    ) async throws -> Result {
        try verifyTrusted(path)
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                continuation.resume(with: Swift.Result {
                    try execute(path, arguments, stdin: input, timeout: timeout)
                })
            }
        }
    }

    /// Synchronous variant for the CLI's sequential command flows (e.g.
    /// `csec protect --env` writing to 1Password). Same trust re-check and
    /// sanitized environment; blocks the calling thread until `op` exits.
    public static func runSync(
        _ path: String,
        _ arguments: [String],
        stdin input: Data? = nil,
        timeout: TimeInterval = defaultTimeout
    ) throws -> Result {
        try verifyTrusted(path)
        return try execute(path, arguments, stdin: input, timeout: timeout)
    }

    private static func verifyTrusted(_ path: String) throws {
        #if DEBUG
        let isExplicitTestOverride = ProcessInfo.processInfo.environment["OP_CLI_PATH"] == path
        #else
        let isExplicitTestOverride = false
        #endif
        guard isExplicitTestOverride || trustReport(for: path).trusted else {
            throw OnePasswordCLIError.untrustedExecutable
        }
    }

    private static func execute(
        _ path: String,
        _ arguments: [String],
        stdin input: Data?,
        timeout: TimeInterval
    ) throws -> Result {
        guard timeout > 0, timeout.isFinite else {
            throw OnePasswordCLIError.invalidTimeout
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = sanitizedEnvironment()

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        let inPipe: Pipe?
        if input != nil {
            let pipe = Pipe()
            process.standardInput = pipe
            inPipe = pipe
        } else {
            inPipe = nil
        }

        let terminated = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in terminated.signal() }

        try process.run()

        let output = CapturedProcessOutput()
        let readers = DispatchGroup()
        readers.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            output.setStdout(outPipe.fileHandleForReading.readDataToEndOfFile())
            readers.leave()
        }
        readers.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            output.setStderr(errPipe.fileHandleForReading.readDataToEndOfFile())
            readers.leave()
        }

        if let input, let inPipe {
            // Feed stdin from another queue while this one drains the outputs,
            // so a template larger than the pipe buffer can't deadlock. If op
            // exits without reading, the write must fail with EPIPE, not raise
            // SIGPIPE.
            let writeHandle = inPipe.fileHandleForWriting
            _ = fcntl(writeHandle.fileDescriptor, F_SETNOSIGPIPE, 1)
            DispatchQueue.global(qos: .userInitiated).async {
                try? writeHandle.write(contentsOf: input)
                try? writeHandle.close()
            }
        }

        let timeoutMilliseconds = min(
            timeout * 1_000,
            Double(Int.max)
        )
        let deadline = DispatchTime.now()
            + .milliseconds(Int(timeoutMilliseconds.rounded(.up)))
        if terminated.wait(timeout: deadline) == .timedOut {
            if process.isRunning {
                process.terminate()
            }
            if terminated.wait(timeout: .now() + .seconds(2)) == .timedOut {
                if process.isRunning {
                    _ = Darwin.kill(process.processIdentifier, SIGKILL)
                }
                terminated.wait()
            }
            readers.wait()
            throw OnePasswordCLIError.timedOut
        }

        readers.wait()
        let captured = output.snapshot()

        return Result(
            status: process.terminationStatus,
            stdout: captured.stdout,
            stderr: captured.stderr
        )
    }
}

private final class CapturedProcessOutput: @unchecked Sendable {
    private let lock = NSLock()
    private var stdout = Data()
    private var stderr = Data()

    func setStdout(_ data: Data) {
        lock.lock()
        stdout = data
        lock.unlock()
    }

    func setStderr(_ data: Data) {
        lock.lock()
        stderr = data
        lock.unlock()
    }

    func snapshot() -> (stdout: Data, stderr: Data) {
        lock.lock()
        defer { lock.unlock() }
        return (stdout, stderr)
    }
}

public enum OnePasswordCLIError: Error, LocalizedError {
    case untrustedExecutable
    case invalidTimeout
    case timedOut

    public var errorDescription: String? {
        switch self {
        case .untrustedExecutable:
            return "the configured 1Password CLI does not satisfy the official signing requirement"
        case .invalidTimeout:
            return "the configured 1Password CLI timeout is invalid"
        case .timedOut:
            return "the 1Password CLI did not respond before the operation deadline"
        }
    }
}
