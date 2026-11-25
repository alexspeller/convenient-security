import Foundation
import ConvenientSecurity
import CSecuritySupport
import Darwin

private struct CredentialConsumer {
    let pid: pid_t
    let startTime: UInt64
    let executable: PlannedExecutable

    func isStillCurrent() -> Bool {
        getppid() == pid
            && ProcessAncestry.startTime(of: pid) == startTime
            && ProcessAncestry.executablePath(of: pid) == executable.canonicalPath
    }
}

private struct FDDeclaration {
    let environmentName: String
    let reference: String
    let preset: InheritedFilePreset?
}

func runSession(_ arguments: [String]) -> Never {
    guard arguments.count >= 2, arguments[0] == "--" else { usage("session") }
    let commandLine = Array(arguments.dropFirst())

    do {
        let sessionID = try makeAgentClient().beginSession()
        guard setenv(RegisteredSessionHint.environmentKey, sessionID, 1) == 0 else {
            throw SecureDeliveryError.invalidSessionHint
        }
        execCommand(commandLine, label: "csec session")
    } catch {
        fail("csec session", error)
    }
}

func runCredentials(_ arguments: [String]) -> Never {
    guard let kind = arguments.first else { usage("creds") }
    switch kind {
    case "aws":
        runAWSCredentials(Array(arguments.dropFirst()))
    case "git":
        runGitCredentials(Array(arguments.dropFirst()))
    case "google":
        runGoogleCredentials(Array(arguments.dropFirst()))
    default:
        usage("creds")
    }
}

private func runAWSCredentials(_ arguments: [String]) -> Never {
    var itemReference: String?
    var roleReferences: [String: String] = [:]
    var reason = "AWS credential_process"
    var ttlSeconds: Int? = nil
    var index = 0

    while index < arguments.count {
        let token = arguments[index]
        let role: String?
        switch token {
        case "--item": role = "item"
        case "--access-key-id-ref": role = AWSCredentialProcess.accessKeyID
        case "--secret-access-key-ref": role = AWSCredentialProcess.secretAccessKey
        case "--session-token-ref": role = AWSCredentialProcess.sessionToken
        case "--expiration-ref": role = AWSCredentialProcess.expiration
        case "--reason":
            index += 1
            guard index < arguments.count else { usage("creds") }
            reason = arguments[index]
            role = nil
        case "--for":
            index += 1
            guard index < arguments.count, let seconds = Int(arguments[index]) else { usage("creds") }
            ttlSeconds = seconds
            role = nil
        default:
            usage("creds")
        }

        if let role {
            index += 1
            guard index < arguments.count else { usage("creds") }
            if role == "item" {
                guard itemReference == nil else { usage("creds") }
                itemReference = arguments[index]
            } else {
                guard roleReferences[role] == nil else { usage("creds") }
                roleReferences[role] = arguments[index]
            }
        }
        index += 1
    }

    guard (ttlSeconds.map({ $0 > 0 }) ?? true),
          !reason.isEmpty, reason.utf8.count <= 256,
          (itemReference != nil) != (!roleReferences.isEmpty),
          itemReference != nil || (
            roleReferences[AWSCredentialProcess.accessKeyID] != nil
                && roleReferences[AWSCredentialProcess.secretAccessKey] != nil
          ) else { usage("creds") }

    let references = stableUnique(itemReference.map { [$0] } ?? Array(roleReferences.values))
    guard references.allSatisfy({ (try? SecretRef($0)) != nil }),
          cs_fd_is_pipe_or_socket(STDOUT_FILENO) == 1 else {
        csecError("creds aws", "stdout must be a private pipe and all references must be valid")
        exit(2)
    }

    do {
        let consumer = try credentialConsumer()
        let commandDigest = try ExecutableInspection.commandDigest(
            ["aws-credential-process"] + roleReferences.keys.sorted().map {
                "\($0)=\(roleReferences[$0]!)"
            } + (itemReference.map { ["item=\($0)"] } ?? [])
        )
        let values = try accessWithSecureDeliveryRoot(
            references: references,
            reason: reason,
            ttlSeconds: ttlSeconds,
            defaultScope: .exactProcess
        ) { root, scope in
            DeliveryPlan(
                mechanism: .credentialProtocol,
                executable: consumer.executable,
                root: root,
                descendantScope: scope,
                destination: .credentialConsumer,
                requestedTTLSeconds: ttlSeconds,
                operationContext: reason,
                commandDigest: commandDigest
            )
        }

        // AWS credential material is text — a JSON bundle or per-role string
        // values — so each value is decoded as UTF-8 at this boundary.
        let fields: [String: String]
        if let itemReference, let bundleBytes = values[itemReference] {
            guard let bundle = String(data: bundleBytes, encoding: .utf8) else {
                throw AgentClient.ClientError.transportFailed
            }
            fields = try AWSCredentialProcess.fields(fromBundle: bundle)
        } else {
            fields = try Dictionary(uniqueKeysWithValues: roleReferences.map { role, reference in
                guard let bytes = values[reference],
                      let value = String(data: bytes, encoding: .utf8) else {
                    throw AgentClient.ClientError.transportFailed
                }
                return (role, value)
            })
        }
        let output = try AWSCredentialProcess.render(fields: fields)
        guard consumer.isStillCurrent(), writeCredentialOutput(output) else {
            throw AgentClient.ClientError.transportFailed
        }
        exit(0)
    } catch {
        fail("csec creds aws", error)
    }
}

/// A Google external-account credential's executable source: gcloud and the
/// client libraries run this and exchange the OIDC token it prints with
/// Google's STS themselves. Any reference that resolves to such a token will
/// do, a minted `csec-identity://` sign-in or a stored one. google-auth reads
/// the reply from stdout with stderr merged into it, so nothing but the reply
/// is printed while a review waits.
private func runGoogleCredentials(_ arguments: [String]) -> Never {
    var itemReference: String?
    var reason = "Google Cloud sign-in"
    var ttlSeconds: Int? = nil
    var index = 0
    while index < arguments.count {
        switch arguments[index] {
        case "--item":
            index += 1
            guard index < arguments.count, itemReference == nil else { usage("creds") }
            itemReference = arguments[index]
        case "--reason":
            index += 1
            guard index < arguments.count else { usage("creds") }
            reason = arguments[index]
        case "--for":
            index += 1
            guard index < arguments.count, let seconds = Int(arguments[index]), seconds > 0 else { usage("creds") }
            ttlSeconds = seconds
        default:
            usage("creds")
        }
        index += 1
    }
    guard let itemReference, !reason.isEmpty, reason.utf8.count <= 256 else { usage("creds") }
    guard (try? SecretRef(itemReference)) != nil, cs_fd_is_pipe_or_socket(STDOUT_FILENO) == 1 else {
        csecError("creds google", "stdout must be a private pipe and the reference must be valid")
        exit(2)
    }
    do {
        let consumer = try credentialConsumer()
        let commandDigest = try ExecutableInspection.commandDigest(["google-executable-credential", "item=\(itemReference)"])
        let values = try accessWithSecureDeliveryRoot(
            references: [itemReference],
            reason: reason,
            ttlSeconds: ttlSeconds,
            defaultScope: .exactProcess,
            waitingNotice: { _ in }
        ) { root, scope in
            DeliveryPlan(
                mechanism: .credentialProtocol,
                executable: consumer.executable,
                root: root,
                descendantScope: scope,
                destination: .credentialConsumer,
                requestedTTLSeconds: ttlSeconds,
                operationContext: reason,
                commandDigest: commandDigest
            )
        }
        guard let bytes = values[itemReference], let token = String(data: bytes, encoding: .utf8) else {
            throw AgentClient.ClientError.transportFailed
        }
        let output = try GoogleExecutableCredential.render(token: token)
        guard consumer.isStillCurrent(), writeCredentialOutput(output) else {
            throw AgentClient.ClientError.transportFailed
        }
        exit(0)
    } catch {
        fail("csec creds google", error)
    }
}

private func runGitCredentials(_ arguments: [String]) -> Never {
    var expectedProtocol = "https"
    var expectedHost: String?
    var expectedPath: String?
    var usernameReference: String?
    var passwordReference: String?
    var reason = "Git credential helper"
    var ttlSeconds: Int? = nil
    var operation: String?
    var index = 0

    while index < arguments.count {
        let token = arguments[index]
        let destination: ((String) -> Void)?
        switch token {
        case "--protocol": destination = { expectedProtocol = $0 }
        case "--host": destination = { expectedHost = $0 }
        case "--path": destination = { expectedPath = $0 }
        case "--username-ref": destination = { usernameReference = $0 }
        case "--password-ref": destination = { passwordReference = $0 }
        case "--reason": destination = { reason = $0 }
        case "--for":
            index += 1
            guard index < arguments.count, let seconds = Int(arguments[index]) else { usage("creds") }
            ttlSeconds = seconds
            destination = nil
        default:
            guard !token.hasPrefix("-"), operation == nil else { usage("creds") }
            operation = token
            destination = nil
        }
        if let destination {
            index += 1
            guard index < arguments.count else { usage("creds") }
            destination(arguments[index])
        }
        index += 1
    }

    guard let operation else { usage("creds") }
    if operation == "capability" {
        _ = writeCredentialOutput(Data("version 0\n\n".utf8))
        exit(0)
    }

    // A read-only helper deliberately ignores store, erase, and future verbs.
    // Consume a bounded request so Git can finish its write without persisting
    // or resolving anything.
    let input = FileHandle.standardInput.readData(ofLength: GitCredentialRequest.maximumBytes + 1)
    guard operation == "get" else { exit(0) }

    guard (ttlSeconds.map({ $0 > 0 }) ?? true),
          let expectedHost,
          validConstraint(expectedProtocol, maximumBytes: 32),
          validConstraint(expectedHost, maximumBytes: 255),
          expectedPath.map({ validConstraint($0, maximumBytes: 256) }) ?? true,
          !reason.isEmpty, reason.utf8.count <= 128,
          let passwordReference,
          (try? SecretRef(passwordReference)) != nil,
          usernameReference.map({ (try? SecretRef($0)) != nil }) ?? true else { usage("creds") }

    do {
        let request = try GitCredentialRequest(data: input)
        guard request.matches(
            protocol: expectedProtocol,
            host: expectedHost,
            path: expectedPath
        ) else { exit(0) }
        guard cs_fd_is_pipe_or_socket(STDOUT_FILENO) == 1 else {
            csecError("creds git", "refusing credential output without a private pipe")
            exit(2)
        }

        let references = stableUnique([usernameReference, passwordReference].compactMap { $0 })
        let consumer = try credentialConsumer()
        let target = expectedProtocol.lowercased() + "://" + expectedHost.lowercased()
            + (expectedPath.map { "/\($0)" } ?? "")
        let operationContext = "\(reason) for \(target)"
        guard operationContext.utf8.count <= 512 else { usage("creds") }
        let commandDigest = try ExecutableInspection.commandDigest([
            "git-credential", expectedProtocol.lowercased(), expectedHost.lowercased(),
            expectedPath ?? "", usernameReference ?? "", passwordReference,
        ])
        let values = try accessWithSecureDeliveryRoot(
            references: references,
            reason: operationContext,
            ttlSeconds: ttlSeconds,
            defaultScope: .exactProcess
        ) { root, scope in
            DeliveryPlan(
                mechanism: .credentialProtocol,
                executable: consumer.executable,
                root: root,
                descendantScope: scope,
                destination: .credentialConsumer,
                requestedTTLSeconds: ttlSeconds,
                operationContext: operationContext,
                commandDigest: commandDigest
            )
        }
        // Git credentials are text fields in the git credential protocol.
        guard let passwordBytes = values[passwordReference],
              let password = String(data: passwordBytes, encoding: .utf8) else {
            throw AgentClient.ClientError.transportFailed
        }
        let username = try usernameReference.map { reference -> String in
            guard let bytes = values[reference],
                  let value = String(data: bytes, encoding: .utf8) else {
                throw AgentClient.ClientError.transportFailed
            }
            return value
        }
        let output = try GitCredentialRequest.render(username: username, password: password)
        guard consumer.isStillCurrent(), writeCredentialOutput(output) else {
            throw AgentClient.ClientError.transportFailed
        }
        exit(0)
    } catch {
        fail("csec creds git", error)
    }
}

func runExecFD(_ arguments: [String]) -> Never {
    var declarations: [FDDeclaration] = []
    var reason: String?
    var ttlSeconds: Int? = nil
    var outputGuard = OutputGuardConfiguration()
    var commandLine: [String] = []
    var index = 0

    parse: while index < arguments.count {
        let token = arguments[index]
        switch token {
        case "--":
            commandLine = Array(arguments[(index + 1)...])
            break parse
        case "--fd", "--preset":
            index += 1
            guard index < arguments.count,
                  let equals = arguments[index].firstIndex(of: "=") else { usage("exec-fd") }
            let name = String(arguments[index][..<equals])
            let reference = String(arguments[index][arguments[index].index(after: equals)...])
            guard !name.isEmpty, !reference.isEmpty else { usage("exec-fd") }
            if token == "--preset" {
                guard let preset = InheritedFilePreset(rawValue: name) else { usage("exec-fd") }
                declarations.append(FDDeclaration(
                    environmentName: preset.environmentName,
                    reference: reference,
                    preset: preset
                ))
            } else {
                guard validEnvironmentName(name), !name.hasPrefix("CSEC_") else { usage("exec-fd") }
                declarations.append(FDDeclaration(
                    environmentName: name,
                    reference: reference,
                    preset: nil
                ))
            }
        case "--reason":
            index += 1
            guard index < arguments.count else { usage("exec-fd") }
            reason = arguments[index]
        case "--for":
            index += 1
            guard index < arguments.count, let seconds = Int(arguments[index]) else { usage("exec-fd") }
            ttlSeconds = seconds
        case "--redact-output":
            index += 1
            guard index < arguments.count,
                  let mode = OutputGuardMode(rawValue: arguments[index]) else { usage("exec-fd") }
            outputGuard.mode = mode
        case let option where option.hasPrefix("--redact-output="):
            guard let mode = OutputGuardMode(
                rawValue: String(option.dropFirst("--redact-output=".count))
            ) else { usage("exec-fd") }
            outputGuard.mode = mode
        case "--redact-output-label":
            index += 1
            guard index < arguments.count,
                  let style = OutputRedactionLabelStyle(rawValue: arguments[index]) else { usage("exec-fd") }
            outputGuard.labelStyle = style
        case let option where option.hasPrefix("--redact-output-label="):
            guard let style = OutputRedactionLabelStyle(
                rawValue: String(option.dropFirst("--redact-output-label=".count))
            ) else { usage("exec-fd") }
            outputGuard.labelStyle = style
        case "--redact-short-values":
            outputGuard.includeShortValues = true
        case "--redact-output-warn":
            outputGuard.emitWarnings = true
        default:
            usage("exec-fd")
        }
        index += 1
    }

    guard !commandLine.isEmpty,
          !declarations.isEmpty, declarations.count <= 16,
          Set(declarations.map(\.environmentName)).count == declarations.count,
          declarations.allSatisfy({ (try? SecretRef($0.reference)) != nil }),
          (ttlSeconds.map({ $0 > 0 }) ?? true),
          reason?.utf8.count ?? 0 <= 256 else { usage("exec-fd") }

    do {
        let executable = try conservativeExecutable(command: commandLine[0])
        let operation = reason ?? "csec exec-fd \((executable.canonicalPath as NSString).lastPathComponent)"
        let references = stableUnique(declarations.map(\.reference))
        let bindingDigest = declarations.map {
            "\($0.environmentName)=\($0.preset?.rawValue ?? "raw"):\($0.reference)"
        }.sorted()
        let commandDigest = try ExecutableInspection.commandDigest(
            commandLine + ["--csec-inherited-files--"] + bindingDigest
        )
        // Read before asking, so an unusable config fails before any panel.
        let liveNpmConfig = declarations.contains(where: { $0.preset == .npm })
            ? try readLiveNpmUserConfig() : nil
        let values = try accessWithSecureDeliveryRoot(
            references: references,
            reason: operation,
            ttlSeconds: ttlSeconds,
            defaultScope: .exactProcess
        ) { root, scope in
            DeliveryPlan(
                mechanism: .inheritedFileDescriptor,
                executable: executable,
                root: root,
                descendantScope: scope,
                destination: .localDevelopment,
                requestedTTLSeconds: ttlSeconds,
                operationContext: operation,
                commandDigest: commandDigest,
                outputGuard: outputGuard.plan
            )
        }

        var files: [InheritedSecretFile] = []
        var totalBytes = 0
        var extraRedactions: [Data: String] = [:]
        for declaration in declarations {
            guard let value = values[declaration.reference] else {
                throw AgentClient.ClientError.transportFailed
            }
            let data: Data
            if declaration.preset == .npm {
                // The stored value is the auth lines csec split out of the
                // userconfig; npm reads its other settings from the live file.
                data = try InheritedFilePreset.npm.render(String(decoding: try NpmUserConfig.merged(
                    liveConfig: liveNpmConfig, authLines: value), as: UTF8.self))
                for credential in NpmUserConfig.credentialValues(in: value) {
                    extraRedactions[Data(credential.utf8)] = declaration.reference
                }
            } else if let preset = declaration.preset {
                // A preset weaves the value into a text template (netrc, git
                // credentials …), so the value must be a text secret.
                guard let text = String(data: value, encoding: .utf8) else {
                    throw SecureDeliveryError.invalidInheritedFile
                }
                data = try preset.render(text)
            } else {
                data = try renderGenericInheritedFile(value)
            }
            totalBytes += data.count
            guard totalBytes <= 4 * InheritedFilePreset.maximumFileBytes else {
                throw SecureDeliveryError.invalidInheritedFile
            }
            files.append(try InheritedSecretFile(data: data))
        }

        var childEnvironment = ProcessInfo.processInfo.environment
        if declarations.contains(where: { $0.preset == .npm }) {
            // npm matches npm_config_* case-insensitively; leave it only the
            // descriptor, never a second spelling naming the plain file.
            for name in childEnvironment.keys where name.lowercased() == "npm_config_userconfig" {
                childEnvironment.removeValue(forKey: name)
            }
        }
        for (declaration, file) in zip(declarations, files) {
            childEnvironment[declaration.environmentName] = file.path
        }

        // Several references may resolve to one value: the lexically first
        // names it, as the by-reference catalog does.
        var referenceByValue = extraRedactions
        for reference in values.keys.sorted().reversed() {
            if let value = values[reference] { referenceByValue[value] = reference }
        }
        let catalog = OutputRedactionCatalog(
            referenceByValue: referenceByValue,
            labelStyle: outputGuard.labelStyle,
            includeShortValues: outputGuard.includeShortValues
        )
        warnForOutputGuard(outputGuard, catalog: catalog)
        let status = try ProcessSupervisor.run(
            executablePath: executable.canonicalPath,
            commandLine: commandLine,
            environment: childEnvironment,
            catalog: catalog,
            mode: outputGuard.mode,
            emitWarnings: outputGuard.emitWarnings,
            inheritedFiles: files
        )
        cs_terminate_like_wait_status(status)
    } catch {
        fail("csec exec-fd", error)
    }
}

private func credentialConsumer() throws -> CredentialConsumer {
    let pid = getppid()
    guard pid > 1,
          let startTime = ProcessAncestry.startTime(of: pid),
          let path = ProcessAncestry.executablePath(of: pid) else {
        throw AgentClient.ClientError.transportFailed
    }
    let executable = try conservativeExecutable(command: path)
    guard getppid() == pid,
          ProcessAncestry.startTime(of: pid) == startTime,
          ProcessAncestry.executablePath(of: pid) == executable.canonicalPath else {
        throw AgentClient.ClientError.transportFailed
    }
    return CredentialConsumer(pid: pid, startTime: startTime, executable: executable)
}

/// A protected interpreter image does not make a mutable script, module graph,
/// or shell program independently protected. Keep those consumer contexts at
/// unverified assurance while retaining code-signing metadata for review.
func conservativeExecutable(command: String) throws -> PlannedExecutable {
    let inspected = try ExecutableInspection.plannedExecutable(command: command)
    let interpreterNames: Set<String> = [
        "bash", "dash", "node", "perl", "python", "python3", "ruby", "sh", "zsh",
    ]
    guard interpreterNames.contains(
        URL(fileURLWithPath: inspected.canonicalPath).lastPathComponent.lowercased()
    ) else { return inspected }
    return PlannedExecutable(
        canonicalPath: inspected.canonicalPath,
        signingIdentifier: inspected.signingIdentifier,
        teamIdentifier: inspected.teamIdentifier,
        cdHash: inspected.cdHash,
        assurance: .unverified
    )
}

private func secureDeliveryRoot(
    defaultScope: DescendantScope
) throws -> (root: DeliveryRoot, scope: DescendantScope) {
    if let sessionID = try RegisteredSessionHint.sessionID() {
        return (.registeredSession(id: sessionID), .broadSession)
    }
    return (.caller, defaultScope)
}

/// A session is a convenience root, never a way around a narrower risk rule.
/// If policy alone rejects its broad scope, repeat the still-value-free access
/// with the command's normal root. Invalid/stale session registrations and all
/// other failures remain fatal instead of silently changing authorization.
private func accessWithSecureDeliveryRoot(
    references: [String],
    reason: String,
    ttlSeconds: Int?,
    defaultScope: DescendantScope,
    waitingNotice: @escaping (String) -> Void = approvalWaitNotice("exec"),
    plan: (DeliveryRoot, DescendantScope) throws -> DeliveryPlan
) throws -> [String: Data] {
    let client = makeAgentClient()
    let selected = try secureDeliveryRoot(defaultScope: defaultScope)
    do {
        return try client.access(
            references: references,
            reason: reason,
            ttlSeconds: ttlSeconds,
            deliveryPlan: try plan(selected.root, selected.scope),
            waitingNotice: waitingNotice
        )
    } catch AgentClient.ClientError.protocolFailure(.policyDenied, _)
            where selected.scope == .broadSession {
        return try client.access(
            references: references,
            reason: reason,
            ttlSeconds: ttlSeconds,
            deliveryPlan: try plan(.caller, defaultScope),
            waitingNotice: waitingNotice
        )
    }
}

/// The userconfig npm would read without the preset. Missing is empty: the
/// stored lines then stand alone, as a value an earlier csec stored whole does.
/// It is the caller's own settings file, so a symlink to it is followed as npm
/// follows it; only its size and type are bounded.
private func readLiveNpmUserConfig() throws -> Data? {
    let environment = ProcessInfo.processInfo.environment
    let home = environment["HOME"].flatMap { $0.isEmpty ? nil : $0 }
        ?? FileManager.default.homeDirectoryForCurrentUser.path
    let path = NpmUserConfig.liveConfigPath(environment: environment, homeDirectory: home)
    var info = stat()
    guard stat(path, &info) == 0 else {
        if errno == ENOENT { return nil }
        throw SecureDeliveryError.invalidInheritedFile
    }
    guard info.st_mode & S_IFMT == S_IFREG,
          info.st_size <= Int64(InheritedFilePreset.maximumFileBytes),
          let data = FileManager.default.contents(atPath: path),
          data.count <= InheritedFilePreset.maximumFileBytes else {
        throw SecureDeliveryError.invalidInheritedFile
    }
    try NpmUserConfig.validateLiveConfig(data)
    return data
}

private func renderGenericInheritedFile(_ value: Data) throws -> Data {
    // A generic inherited file is the value's own bytes. NUL is still rejected:
    // the descriptor is read as a text token here, and a binary blob belongs on
    // the capability-GID file path, not stitched into a `/dev/fd` token.
    guard !value.isEmpty,
          value.count <= InheritedFilePreset.maximumFileBytes,
          !value.contains(0) else {
        throw SecureDeliveryError.invalidInheritedFile
    }
    return value
}

private func validEnvironmentName(_ value: String) -> Bool {
    let bytes = Array(value.utf8)
    guard !bytes.isEmpty, bytes.count <= 128,
          isASCIIAlpha(bytes[0]) || bytes[0] == 95 else { return false }
    return bytes.allSatisfy { isASCIIAlpha($0) || ($0 >= 48 && $0 <= 57) || $0 == 95 }
}

private func isASCIIAlpha(_ byte: UInt8) -> Bool {
    (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
}

private func validConstraint(_ value: String, maximumBytes: Int) -> Bool {
    !value.isEmpty
        && value.utf8.count <= maximumBytes
        && !value.unicodeScalars.contains(where: {
            $0.value == 0 || CharacterSet.controlCharacters.contains($0)
        })
}

private func stableUnique(_ values: [String]) -> [String] {
    var seen = Set<String>()
    return values.filter { seen.insert($0).inserted }
}

private func warnForOutputGuard(
    _ guardConfiguration: OutputGuardConfiguration,
    catalog: OutputRedactionCatalog
) {
    if guardConfiguration.mode == .tty {
        var unguarded: [String] = []
        if isatty(STDOUT_FILENO) != 1 { unguarded.append("stdout") }
        if isatty(STDERR_FILENO) != 1 { unguarded.append("stderr") }
        if !unguarded.isEmpty {
            writeError(
                "csec exec-fd: warning: tty output masking is inactive for "
                    + unguarded.joined(separator: " and ")
                    + "; use --redact-output=always to alter non-terminal output\n"
            )
        }
    } else if guardConfiguration.mode == .never {
        writeError("csec exec-fd: warning: output detection and masking explicitly disabled\n")
    }
    if guardConfiguration.mode != .never, catalog.skippedShortValueCount > 0 {
        writeError(
            "csec exec-fd: warning: \(catalog.skippedShortValueCount) protected value(s) shorter than "
                + "\(OutputRedactionCatalog.minimumAutomaticSecretBytes) bytes are not matched; "
                + "use --redact-short-values to accept possible false positives\n"
        )
    }
}

private func execCommand(_ commandLine: [String], label: String) -> Never {
    let argv: [UnsafeMutablePointer<CChar>?] = commandLine.map { strdup($0) } + [nil]
    execvp(commandLine[0], argv)
    let execError = errno
    writeError("\(label): target exec failed: \(String(cString: strerror(execError)))\n")
    exit(execError == ENOENT ? 127 : 126)
}

private func writeCredentialOutput(_ data: Data) -> Bool {
    signal(SIGPIPE, SIG_IGN)
    var offset = 0
    while offset < data.count {
        let written = data.withUnsafeBytes { buffer -> Int in
            guard let base = buffer.baseAddress else { return 0 }
            return write(STDOUT_FILENO, base.advanced(by: offset), data.count - offset)
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

private func writeError(_ message: String) {
    FileHandle.standardError.write(Data(message.utf8))
}

private func fail(_ label: String, _ error: Error) -> Never {
    let command = label.hasPrefix("csec ") ? String(label.dropFirst("csec ".count)) : label
    csecError(command, ReviewDisplay.sanitized(error.localizedDescription))
    exit(1)
}
