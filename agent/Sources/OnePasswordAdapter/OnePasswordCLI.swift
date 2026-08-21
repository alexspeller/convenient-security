import Foundation
import Security
import ConvenientSecurity

/// Locates and runs the 1Password CLI (`op`). Encapsulates all subprocess
/// handling so `OnePasswordProvider` stays declarative.
public enum OnePasswordCLI {
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
    /// array (no shell), so a reference can't cause shell injection.
    public static func run(_ path: String, _ arguments: [String]) async throws -> Result {
        #if DEBUG
        let isExplicitTestOverride = ProcessInfo.processInfo.environment["OP_CLI_PATH"] == path
        #else
        let isExplicitTestOverride = false
        #endif
        guard isExplicitTestOverride || trustReport(for: path).trusted else {
            throw OnePasswordCLIError.untrustedExecutable
        }
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let process = Process()
                process.executableURL = URL(fileURLWithPath: path)
                process.arguments = arguments
                process.environment = sanitizedEnvironment()

                let outPipe = Pipe()
                let errPipe = Pipe()
                process.standardOutput = outPipe
                process.standardError = errPipe

                do {
                    try process.run()
                } catch {
                    continuation.resume(throwing: error)
                    return
                }

                // op's output (a secret value, or a short error) is small, so
                // draining stdout then stderr to EOF cannot fill the pipe buffers.
                let out = outPipe.fileHandleForReading.readDataToEndOfFile()
                let err = errPipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()

                continuation.resume(returning: Result(
                    status: process.terminationStatus, stdout: out, stderr: err
                ))
            }
        }
    }
}

public enum OnePasswordCLIError: Error, LocalizedError {
    case untrustedExecutable

    public var errorDescription: String? {
        "the configured 1Password CLI does not satisfy the official signing requirement"
    }
}
