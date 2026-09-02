import ConvenientSecurity
import Foundation
#if canImport(Darwin)
import Darwin
#endif

private let sshActivationExport = "export SSH_AUTH_SOCK=\"$(csec ssh socket)\""

/// Registration and import run in a child process, so they cannot configure the
/// caller's shell themselves. Only show the activation guidance when the shell
/// that launched csec is not already pointing at the canonical csec socket.
func sshActivationGuidanceIfNeeded() -> String {
    guard ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"]
        != SSHAgentSocket.defaultPath() else { return "" }
    return "SSH is not configured to use csec in this shell.\n"
        + "Add this line to your shell profile, or run it before SSH commands:\n"
        + "  \(sshActivationExport)\n"
}

func runSSH(_ arguments: [String]) -> Never {
    guard let action = arguments.first else { usage("ssh") }
    switch action {
    case "socket":
        guard arguments.count == 1 else { usage("ssh") }
        FileHandle.standardOutput.write(Data("\(SSHAgentSocket.defaultPath())\n".utf8))
        exit(0)
    case "env":
        guard arguments.count == 1 else { usage("ssh") }
        let path = SSHAgentSocket.defaultPath().replacingOccurrences(of: "'", with: "'\\''")
        FileHandle.standardOutput.write(Data("export SSH_AUTH_SOCK='\(path)'\n".utf8))
        exit(0)
    case "list":
        guard arguments.count == 1 else { usage("ssh") }
        do {
            let keys = try makeAgentClient().listSSHKeys()
            if keys.isEmpty {
                FileHandle.standardOutput.write(Data("No protected SSH keys registered.\n".utf8))
            } else {
                for key in keys {
                    let reference = (try? SecretRef(key.reference))?.safeInlineURI ?? "invalid-reference"
                    let label = ReviewDisplay.sanitized(key.label)
                    FileHandle.standardOutput.write(Data(
                        "\(key.fingerprint)  \(key.algorithm)  \(label)  \(reference)\n".utf8
                    ))
                }
            }
            exit(0)
        } catch {
            sshFail(error.localizedDescription)
        }
    case "register":
        var label: String?
        var referenceArgument: String?
        var index = 1
        while index < arguments.count {
            switch arguments[index] {
            case "--label":
                index += 1
                guard index < arguments.count, label == nil else { usage("ssh") }
                label = arguments[index]
            case let token where token.hasPrefix("-"):
                usage("ssh")
            default:
                guard referenceArgument == nil else { usage("ssh") }
                referenceArgument = arguments[index]
            }
            index += 1
        }
        guard let referenceArgument else { usage("ssh") }
        do {
            let reference = try sshRegistrationReference(referenceArgument)
            let keys = try makeAgentClient().registerSSHKeys([
                SSHKeyRegistrationIntent(reference: reference.uri, label: label)
            ])
            guard let key = keys.first, keys.count == 1 else {
                throw AgentClient.ClientError.transportFailed
            }
            FileHandle.standardOutput.write(Data(
                "Registered \(key.fingerprint) (\(key.algorithm)) from \(reference.safeInlineURI)\n".utf8
            ))
            FileHandle.standardOutput.write(Data(sshActivationGuidanceIfNeeded().utf8))
            exit(0)
        } catch {
            sshFail(error.localizedDescription)
        }
    case "remove":
        guard arguments.count == 2 else { usage("ssh") }
        let fingerprint = arguments[1]
        do {
            let before = try makeAgentClient().listSSHKeys()
            guard before.contains(where: { $0.fingerprint == fingerprint }) else {
                sshFail("no registered key has that fingerprint")
            }
            _ = try makeAgentClient().removeSSHKey(fingerprint: fingerprint)
            FileHandle.standardOutput.write(Data("Removed \(fingerprint)\n".utf8))
            exit(0)
        } catch {
            sshFail(error.localizedDescription)
        }
    case "status":
        guard arguments.count == 1 else { usage("ssh") }
        FileHandle.standardError.write(Data(
            "csec ssh status: status is consolidated under `csec status`\n".utf8
        ))
        runStatus()
    default:
        usage("ssh")
    }
}

private func sshRegistrationReference(_ argument: String) throws -> SecretRef {
    if argument.contains("://") { return try SecretRef(argument) }
    guard argument.hasSuffix(ProtectedFileSidecar.suffix) else {
        throw ProtectedFileSidecarError.notASidecar
    }
    let fd = argument.withCString { open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) }
    guard fd >= 0 else { throw ProtectedFileSidecarError.notASidecar }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0,
          (info.st_mode & S_IFMT) == S_IFREG,
          info.st_uid == getuid(),
          info.st_size >= 0,
          info.st_size <= ProtectedFileSidecar.maximumBytes else {
        throw ProtectedFileSidecarError.malformed
    }
    var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
    var offset = 0
    while offset < bytes.count {
        let total = bytes.count
        let count = bytes.withUnsafeMutableBytes {
            Darwin.read(fd, $0.baseAddress!.advanced(by: offset), total - offset)
        }
        if count < 0, errno == EINTR { continue }
        guard count > 0 else { throw ProtectedFileSidecarError.malformed }
        offset += count
    }
    return try ProtectedFileSidecar(data: Data(bytes)).reference
}

private func sshFail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("csec ssh: \(message)\n".utf8))
    exit(1)
}
