import Foundation
import CryptoKit
import Security
import Darwin

public enum ExecutableInspectionError: Error, LocalizedError {
    case notFound(String)
    case notFoundLooksLikeShellCommand(String)
    case notExecutable(String)

    public var errorDescription: String? {
        switch self {
        case let .notFound(command): return "executable not found: \(command)"
        case let .notFoundLooksLikeShellCommand(command):
            return "executable not found: \(command)\n"
                + "The quoted string was used as one program name: csec takes a command "
                + "and its arguments separately, like env, without shell parsing. "
                + "Pass the arguments individually (… -- /bin/echo \"$NAME\") or name a "
                + "shell explicitly to expand variables inside the guarded environment "
                + "(… -- /bin/sh -c 'echo \"$NAME\"')."
        case let .notExecutable(path): return "not an executable file: \(path)"
        }
    }
}

/// Conservative, pre-resolution inspection used by the signed launcher when it
/// constructs a delivery plan. A user-writable executable remains user-writable
/// even if it happens to carry a valid signature at inspection time.
public enum ExecutableInspection {
    public static func plannedExecutable(
        command: String,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        workingDirectory: String? = nil,
        mutableInterpreter: Bool = false
    ) throws -> PlannedExecutable {
        let path = try resolve(
            command: command,
            environment: environment,
            workingDirectory: workingDirectory
        )
        // Framework Python's packages/resources are mutable interpreted inputs.
        // Homebrew omits the app resource seal, but the executable itself still
        // has a valid signature. Only this explicit, unverified consumer mode
        // may skip resources; executable pages are always validated.
        let staticIdentity = signingIdentity(
            path: path,
            validateResources: !mutableInterpreter || !isPythonFrameworkConsumer(path)
        )
        return PlannedExecutable(
            canonicalPath: path,
            signingIdentifier: staticIdentity.identifier,
            teamIdentifier: staticIdentity.teamIdentifier,
            cdHash: staticIdentity.cdHash,
            assurance: mutableInterpreter ? .unverified
                : (independentlyProtected(path: path) ? .independentlyProtected : .userWritable)
        )
    }

    /// CPython's conventional macOS framework launcher replaces itself with
    /// this app executable, retaining its PID and parent. This is a layout rule,
    /// never a probe that executes a user-supplied interpreter before consent.
    public static func pythonFrameworkConsumerPath(forLauncherPath path: String) -> String? {
        let launcher = URL(fileURLWithPath: path).standardizedFileURL
        let bin = launcher.deletingLastPathComponent()
        let version = bin.deletingLastPathComponent()
        let versions = version.deletingLastPathComponent()
        let framework = versions.deletingLastPathComponent()
        guard path.hasPrefix("/"), launcher.path == path,
              bin.lastPathComponent == "bin", versions.lastPathComponent == "Versions",
              ["Python.framework", "Python3.framework"].contains(framework.lastPathComponent),
              launcher.lastPathComponent.range(
                of: "^python(?:[23](?:\\.[0-9]+)?)?[dt]?$", options: .regularExpression
              ) != nil else { return nil }
        return version.appendingPathComponent("Resources/Python.app/Contents/MacOS/Python").path
    }

    private static func isPythonFrameworkConsumer(_ path: String) -> Bool {
        let suffix = "/Resources/Python.app/Contents/MacOS/Python"
        guard path.hasSuffix(suffix) else { return false }
        return pythonFrameworkConsumerPath(
            forLauncherPath: String(path.dropLast(suffix.count)) + "/bin/python3"
        ) == path
    }

    public static func commandDigest(_ commandLine: [String]) throws -> String {
        let data = try JSONEncoder().encode(commandLine)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func resolve(
        command: String,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        workingDirectory: String? = nil
    ) throws -> String {
        try locate(command: command, environment: environment, workingDirectory: workingDirectory)
            .resolvingSymlinksInPath()
            .path
    }

    /// The absolute path `command` names, found the way `resolve` finds it but
    /// with its symlinks left in place: the path a launcher passes as argv[0].
    /// An interpreter can read its own argv[0] to find where it was installed
    /// (Python finds a virtual environment's `pyvenv.cfg` from it), so a
    /// launcher that runs the resolved image still names it by this path.
    public static func invokedPath(
        command: String,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        workingDirectory: String? = nil
    ) throws -> String {
        try locate(command: command, environment: environment, workingDirectory: workingDirectory).path
    }

    private static func locate(
        command: String,
        environment: [String: String],
        workingDirectory: String?
    ) throws -> URL {
        let fm = FileManager.default
        let baseDirectory = workingDirectory ?? fm.currentDirectoryPath
        let candidates: [String]
        if command.contains("/") {
            let expanded = (command as NSString).expandingTildeInPath
            if expanded.hasPrefix("/") {
                candidates = [expanded]
            } else {
                candidates = [(baseDirectory as NSString).appendingPathComponent(expanded)]
            }
        } else {
            let path = environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"
            candidates = path.split(separator: ":", omittingEmptySubsequences: false).map { component in
                let directory = component.isEmpty ? baseDirectory : String(component)
                return (directory as NSString).appendingPathComponent(command)
            }
        }

        for candidate in candidates where fm.fileExists(atPath: candidate) {
            guard fm.isExecutableFile(atPath: candidate) else {
                if command.contains("/") { throw ExecutableInspectionError.notExecutable(candidate) }
                continue
            }
            return URL(fileURLWithPath: candidate).standardizedFileURL
        }
        // `csec exec '/bin/echo $VAR'` reads as one program name with a space in
        // it. A path that exists under that literal name resolved above; a
        // missing one is far more likely a shell command line quoted into a
        // single argument, so explain the argv model instead of just "not found".
        if command.contains(where: \.isWhitespace) {
            throw ExecutableInspectionError.notFoundLooksLikeShellCommand(command)
        }
        throw ExecutableInspectionError.notFound(command)
    }

    /// Every controlling component must be root-owned and not writable by group
    /// or others. This is intentionally conservative and does not claim that a
    /// valid signature makes a login-user-writable checkout immutable.
    public static func independentlyProtected(path: String) -> Bool {
        let fm = FileManager.default
        var current = URL(fileURLWithPath: path).standardizedFileURL
        while true {
            guard let attributes = try? fm.attributesOfItem(atPath: current.path),
                  let owner = attributes[.ownerAccountID] as? NSNumber,
                  let permissions = attributes[.posixPermissions] as? NSNumber,
                  owner.uint32Value == 0,
                  permissions.intValue & 0o022 == 0,
                  access(current.path, W_OK) != 0 else { return false }

            let parent = current.deletingLastPathComponent()
            if parent.path == current.path { return true }
            current = parent
        }
    }

    private static func signingIdentity(
        path: String, validateResources: Bool
    ) -> (identifier: String?, teamIdentifier: String?, cdHash: String?) {
        var code: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(
            URL(fileURLWithPath: path) as CFURL,
            SecCSFlags(rawValue: 0),
            &code
        )
        guard createStatus == errSecSuccess, let code,
              SecStaticCodeCheckValidity(
                code,
                SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)
                    | (validateResources ? 0 : UInt32(kSecCSDoNotValidateResources))),
                nil
              ) == errSecSuccess else { return (nil, nil, nil) }

        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: UInt32(kSecCSSigningInformation)),
            &information
        ) == errSecSuccess,
        let dictionary = information as? [String: Any] else { return (nil, nil, nil) }

        return (
            dictionary[kSecCodeInfoIdentifier as String] as? String,
            dictionary[kSecCodeInfoTeamIdentifier as String] as? String,
            (dictionary[kSecCodeInfoUnique as String] as? Data)?.map {
                String(format: "%02x", $0)
            }.joined()
        )
    }
}
