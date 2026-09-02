import Foundation
import ConvenientSecurity
import CSecuritySupport
#if canImport(Darwin)
import Darwin
#endif


/// Report a usage error for `command` (bad/missing args): print that command's
/// help to stderr and exit 2, or the global help when no command is given.
func usage(_ command: String? = nil) -> Never {
    if let command {
        printCommandHelp(command, explicit: false)
    }
    printGlobalHelp(exitCode: 2)
}

let arguments = Array(CommandLine.arguments.dropFirst())

// Help is intercepted before dispatch: `csec`, `csec help [cmd]`, `csec --help`,
// and `csec <cmd> --help` print help to stdout and exit 0; an unknown command or
// bad args print help to stderr and exit 2.
guard let command = arguments.first else { printGlobalHelp(exitCode: 0) }
let commandArguments = Array(arguments.dropFirst())

switch command {
case "--help", "-h":
    printGlobalHelp(exitCode: 0)
case "help":
    if let requested = commandArguments.first {
        if CLICatalog.command(named: requested) != nil {
            printCommandHelp(requested, explicit: true)
        }
        printUnknownCommand(requested)
    }
    printGlobalHelp(exitCode: 0)
default:
    break
}

// A per-command `-h`/`--help` before any `--` prints that command's help, so
// `csec exec --help` documents exec while `csec exec -- rails --help` forwards.
if CLICatalog.command(named: command) != nil, wantsHelp(commandArguments) {
    printCommandHelp(command, explicit: true)
}

switch command {
case "get":
    runGet(Array(arguments.dropFirst()))
case "exec":
    runExec(Array(arguments.dropFirst()))
case "session":
    runSession(Array(arguments.dropFirst()))
case "creds":
    runCredentials(Array(arguments.dropFirst()))
case "exec-fd":
    runExecFD(Array(arguments.dropFirst()))
case "exec-file":
    runExecFile(Array(arguments.dropFirst()))
case "bridge":
    guard arguments.count == 1 else { usage("bridge") }
    runBridge()
case "tool-exec":
    runToolExec(Array(arguments.dropFirst()))
case "hook":
    runHook(Array(arguments.dropFirst()))
case "hook-config":
    runHookConfig(Array(arguments.dropFirst()))
case "edit":
    runEdit(Array(arguments.dropFirst()))
case "protect":
    runProtect(Array(arguments.dropFirst()))
case "setup":
    runSetup(Array(arguments.dropFirst()))
case "audit":
    runAudit(Array(arguments.dropFirst()))
case "remote":
    runRemote(Array(arguments.dropFirst()))
case "ssh":
    runSSH(Array(arguments.dropFirst()))
case "automation":
    runAutomation(Array(arguments.dropFirst()))
case "grants":
    runGrants(Array(arguments.dropFirst()))
case "revoke":
    runRevoke(Array(arguments.dropFirst()))
case "install":
    runInstall()
case "uninstall":
    runUninstall()
case "status":
    runStatus()
case "doctor":
    runDoctor(Array(arguments.dropFirst()))
case "root-status":
    guard arguments.count == 1 else { usage("root-status") }
    runRootStatus()
default:
    printUnknownCommand(command)
}

// MARK: - AI command hooks and fail-closed tool execution

func runHook(_ arguments: [String]) -> Never {
    guard arguments.count == 1,
          let client = AICommandHookClient(rawValue: arguments[0]) else { usage("hook") }
    do {
        let input = FileHandle.standardInput.readDataToEndOfFile()
        let output = try AICommandHook.rewrite(
            input: input,
            client: client,
            csecExecutablePath: currentExecutablePath()
        )
        FileHandle.standardOutput.write(output)
        FileHandle.standardOutput.write(Data("\n".utf8))
        exit(0)
    } catch {
        // PreToolUse treats status 2 as a denial. Keep this diagnostic generic:
        // malformed hook input can contain a sensitive proposed command.
        FileHandle.standardError.write(Data(
            "csec hook: refusing an invalid shell-tool request\n".utf8
        ))
        exit(2)
    }
}

func runHookConfig(_ arguments: [String]) -> Never {
    guard arguments.count == 1,
          let client = AICommandHookClient(rawValue: arguments[0]) else { usage("hook-config") }
    do {
        FileHandle.standardOutput.write(try AICommandHook.hookConfiguration(
            client: client,
            csecExecutablePath: currentExecutablePath()
        ))
        exit(0)
    } catch {
        csecError("hook-config", "could not build configuration")
        exit(1)
    }
}

func runToolExec(_ arguments: [String]) -> Never {
    var destination: String?
    var encodedShellCommand: String?
    var commandLine: [String] = []
    var index = 0
    parse: while index < arguments.count {
        switch arguments[index] {
        case "--destination":
            index += 1
            guard index < arguments.count else { usage("tool-exec") }
            destination = arguments[index]
        case "--encoded-shell-command":
            index += 1
            guard index < arguments.count else { usage("tool-exec") }
            encodedShellCommand = arguments[index]
        case "--":
            commandLine = Array(arguments[(index + 1)...])
            break parse
        default:
            usage("tool-exec")
        }
        index += 1
    }
    guard destination == "ai",
          encodedShellCommand == nil || commandLine.isEmpty else { usage("tool-exec") }

    let executablePath: String
    if let encodedShellCommand {
        do {
            let command = try AICommandHook.decodeShellCommand(encodedShellCommand)
            // Claude Code and Codex both submit a shell program, not an argv
            // vector. zsh is the native macOS user-shell superset used by the
            // local integration. Base64url makes the transport unambiguous and
            // avoids a second quoting interpretation; it is encoding, not a
            // confidentiality boundary, and remains visible in process argv.
            executablePath = "/bin/zsh"
            commandLine = [executablePath, "-lc", command]
        } catch {
            csecError("tool-exec", "invalid encoded command")
            exit(2)
        }
    } else {
        guard !commandLine.isEmpty else { usage("tool-exec") }
        do {
            executablePath = try ExecutableInspection.plannedExecutable(
                command: commandLine[0]
            ).canonicalPath
        } catch {
            csecError("tool-exec", "command is not executable")
            exit(127)
        }
    }

    let session: AgentOutputRedactionSession
    do {
        session = try makeAgentClient().beginOutputRedaction(
            destination: .aiTool,
            streams: OutputRedactionStream.allCases,
            // The AI tool is the output recipient here, not the operator's own
            // terminal. Keep opaque `[csec:secret-N]` labels so a redaction does
            // not hand the AI the reference metadata a `csec exec` user would see.
            labelStyle: .opaque
        )
    } catch {
        // The original command has not run. This is the ordinary fail-closed
        // path when csecd is absent, outdated, or cannot authenticate csec.
        FileHandle.standardError.write(Data(
            "csec tool-exec: protected output scanner unavailable; command not run\n".utf8
        ))
        exit(1)
    }
    defer { session.close() }

    if session.skippedShortValueCount > 0 {
        FileHandle.standardError.write(Data(
            ("csec tool-exec: warning: \(session.skippedShortValueCount) active value(s) shorter than "
             + "\(OutputRedactionCatalog.minimumAutomaticSecretBytes) bytes are not matched\n").utf8
        ))
    }

    do {
        let status = try ProcessSupervisor.run(
            executablePath: executablePath,
            commandLine: commandLine,
            environment: ProcessInfo.processInfo.environment,
            agentSession: session,
            mode: .always
        )
        session.close()
        cs_terminate_like_wait_status(status)
    } catch {
        session.close()
        FileHandle.standardError.write(Data(
            "csec tool-exec: trusted output scanning failed; command terminated (\(error))\n".utf8
        ))
        exit(1)
    }
}

func currentExecutablePath() -> String {
    (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0]))
        .standardizedFileURL.resolvingSymlinksInPath().path
}

// MARK: - native encrypted store editor

func runEdit(_ arguments: [String]) -> Never {
    // A full reference selects the single-secret editor; a bare store name
    // opens the whole-document editor. Store names can never contain "://",
    // so the two forms are unambiguous. --editor applies only to the
    // document editor.
    if arguments.contains(where: { $0.contains("://") }) {
        guard arguments.count == 1 else { usage("edit") }
        runEditReference(arguments[0])
    }
    var useExternalEditor = false
    var storeArgument: String?
    for argument in arguments {
        if argument == "--editor" {
            guard !useExternalEditor else { usage("edit") }
            useExternalEditor = true
        } else {
            guard storeArgument == nil, !argument.hasPrefix("-") else { usage("edit") }
            storeArgument = argument
        }
    }
    guard let storeArgument else { usage("edit") }

    let externalEditor: ExternalEditorCommand?
    if useExternalEditor {
        do {
            externalEditor = try ExternalEditorCommand()
        } catch {
            csecError("edit", "\(error.localizedDescription)")
            exit(2)
        }
        FileHandle.standardError.write(Data("""
        csec edit: warning: --editor writes decrypted secrets to a named temporary file.
        Same-UID processes, the selected editor and its plugins can read it; swap,
        autosave, backup, recovery, or filesystem snapshots may retain copies. csec
        does not mask the editor's display or output. It removes its private
        temporary workspace after a normal editor exit, but cannot securely erase
        storage or remove copies made elsewhere. A crash or forced termination can
        leave the temporary workspace behind.

        """.utf8))
    } else {
        externalEditor = nil
    }

    let store: NativeStoreName
    do {
        store = try NativeStoreName(storeArgument)
    } catch {
        csecError("edit", "\(error.localizedDescription)")
        exit(2)
    }

    let client = makeAgentClient()
    do {
        guard try client.capabilities().features.contains(.nativeEncryptedStore) else {
            FileHandle.standardError.write(Data(
                "csec edit: the running agent does not provide the native encrypted store\n".utf8
            ))
            exit(1)
        }
    } catch {
        csecError("edit", "cannot reach the trusted agent")
        exit(1)
    }

    let edit: NativeStoreEditStart
    do {
        edit = try client.beginNativeStoreEdit(
            store: store.value,
            mode: useExternalEditor ? .externalTemporaryFile : .builtInMemory,
            externalEditorPath: externalEditor?.executablePath
        )
    } catch {
        csecError("edit", "\(error.localizedDescription)")
        exit(1)
    }

    var currentDocument = edit.document
    while true {
        let edited: Data
        if let externalEditor {
            do {
                edited = try ExternalNativeStoreEditor.edit(
                    command: externalEditor,
                    document: currentDocument
                )
            } catch {
                client.cancelNativeStoreEdit(sessionID: edit.sessionID)
                FileHandle.standardError.write(Data(
                    "csec edit: \(error.localizedDescription); store unchanged\n".utf8
                ))
                exit(1)
            }
        } else {
            do {
                guard let result = try NativeStoreEditor.edit(
                    store: store.value,
                    document: currentDocument
                ) else {
                    client.cancelNativeStoreEdit(sessionID: edit.sessionID)
                    print("csec: native store unchanged")
                    exit(0)
                }
                edited = result
            } catch {
                NativeStoreEditor.showValidationError(error.localizedDescription)
                continue
            }
        }
        currentDocument = edited

        let canonical: Data
        do {
            canonical = try NativeStoreDocument(data: edited).encoded()
        } catch {
            showEditValidationError(error.localizedDescription, external: useExternalEditor)
            continue
        }
        if canonical == edit.document {
            client.cancelNativeStoreEdit(sessionID: edit.sessionID)
            print("csec: native store unchanged")
            exit(0)
        }

        do {
            let result = try client.commitNativeStoreEdit(
                sessionID: edit.sessionID,
                document: canonical
            )
            print(
                "csec: saved encrypted store '\(store.value)' "
                    + "(generation \(result.generation), \(result.secretCount) secrets)"
            )
            exit(0)
        } catch AgentClient.ClientError.protocolFailure(.invalidStoreDocument, let message) {
            showEditValidationError(message, external: useExternalEditor)
        } catch {
            client.cancelNativeStoreEdit(sessionID: edit.sessionID)
            csecError("edit", "\(error.localizedDescription)")
            exit(1)
        }
    }
}

func showEditValidationError(_ message: String, external: Bool) {
    if external {
        FileHandle.standardError.write(Data(
            "csec edit: invalid store: \(message); reopening $EDITOR\n".utf8
        ))
    } else {
        NativeStoreEditor.showValidationError(message)
    }
}

// MARK: - get

func runGet(_ arguments: [String]) -> Never {
    var references: [String] = []
    var reason = "csec get"
    var ttlSeconds = 3600
    var reveal = false
    var allowPlaintextFile = false
    var index = 0
    while index < arguments.count {
        switch arguments[index] {
        case "--reason":
            index += 1
            guard index < arguments.count else { usage("get") }
            reason = arguments[index]
        case "--for":
            index += 1
            guard index < arguments.count, let seconds = Int(arguments[index]) else { usage("get") }
            ttlSeconds = seconds
        case "--reveal":
            reveal = true
        case "--allow-plaintext-file":
            allowPlaintextFile = true
        default:
            references.append(arguments[index])
        }
        index += 1
    }
    guard !references.isEmpty else { usage("get") }
    guard ttlSeconds > 0, ttlSeconds <= 24 * 60 * 60 else {
        csecError("get", "--for must be between 1 and 86400 seconds")
        exit(2)
    }

    let client = makeAgentClient()
    do {
        let parentPID = getppid()
        guard parentPID > 1,
              let parentStartTime = ProcessAncestry.startTime(of: parentPID),
              let parentPath = ProcessAncestry.executablePath(of: parentPID),
              let parentExecutable = try? ExecutableInspection.plannedExecutable(
                command: parentPath
              ) else {
            FileHandle.standardError.write(Data(
                "csec get: requesting parent identity is unavailable\n".utf8
            ))
            exit(1)
        }
        let requestingParent = (
            pid: parentPID,
            startTime: parentStartTime,
            executablePath: parentExecutable.canonicalPath
        )
        // A human is interactively present if any std descriptor is a tty. This
        // distinguishes a person piping `csec get x | cmd` (allowed) from an
        // agent/script capturing the output (refused, steered to injection).
        let interactive = isatty(STDIN_FILENO) == 1
            || isatty(STDOUT_FILENO) == 1
            || isatty(STDERR_FILENO) == 1
        let mechanism: DeliveryMechanism
        let destination: DestinationClass
        let recipient: RecipientAssurance
        // Whether the user supplied the override flag this stdout shape requires.
        // One flag never unlocks the other; csecd independently re-derives whether
        // an acknowledgment is required, so the launcher check is a fast, specific
        // first line, not the security boundary.
        let ackGiven: Bool
        if isatty(STDOUT_FILENO) == 1 {
            // Echoing to the terminal lands in scrollback.
            mechanism = .rawStandardOutput
            destination = .humanOutput
            recipient = .interactiveTerminal
            ackGiven = reveal
        } else if cs_fd_is_regular_file(STDOUT_FILENO) == 1 {
            // Durable plaintext on disk.
            mechanism = .namedPlaintextFile
            destination = .persistentPlaintextFile
            recipient = .ordinaryPersistentFile
            ackGiven = allowPlaintextFile
        } else {
            // A pipe/socket or any other non-tty, non-file sink: bytes go to a
            // reader csec cannot authenticate. Interactive → allowed; a
            // non-interactive capture is refused with --reveal as the override.
            mechanism = .rawStandardOutput
            destination = .shellDelegatedPipe
            recipient = .unverifiedPipeReader
            ackGiven = reveal
        }
        let ackRequired: Bool
        switch (mechanism, recipient) {
        case (.namedPlaintextFile, _),
             (.rawStandardOutput, .interactiveTerminal):
            ackRequired = true
        case (.rawStandardOutput, .unverifiedPipeReader):
            ackRequired = !interactive
        default:
            ackRequired = false
        }
        if ackRequired && !ackGiven {
            let hint: String
            if recipient == .ordinaryPersistentFile {
                hint = "csec get: refusing to write a secret to a persistent plaintext file — it "
                    + "would remain on disk, readable by other processes running as you and possibly "
                    + "synced or backed up. Prefer `csec exec-file`, or pass --allow-plaintext-file to "
                    + "write it anyway."
            } else if recipient == .interactiveTerminal {
                hint = "csec get: refusing to print a secret to the terminal — it would remain in "
                    + "scrollback and could be captured by a coding-agent session, logger, or screen "
                    + "capture. Pipe it into the consuming command, or pass --reveal to echo it "
                    + "deliberately."
            } else {
                hint = "csec get: no interactive terminal is attached — a coding agent, script, or "
                    + "logger appears to be capturing this output and would receive the value. Prefer "
                    + "`csec exec`, `csec exec-file`, or a credential helper, which hand the value to "
                    + "the consuming tool without returning it here. Pass --reveal to output the raw "
                    + "value anyway."
            }
            FileHandle.standardError.write(Data((hint + "\n").utf8))
            exit(2)
        }
        let plaintextExposureAcknowledged = ackRequired && ackGiven
        let plan = DeliveryPlan(
            mechanism: mechanism,
            executable: PlannedExecutable(
                canonicalPath: URL(fileURLWithPath: CommandLine.arguments[0])
                    .standardizedFileURL.resolvingSymlinksInPath().path,
                signingIdentifier: ProductCodeIdentity.launcherIdentifier,
                teamIdentifier: ProductCodeIdentity.teamIdentifier,
                assurance: .verifiedProduct
            ),
            requestingExecutable: parentExecutable,
            root: .directParent(pid: parentPID, startTime: parentStartTime),
            descendantScope: .subtree,
            destination: destination,
            recipientAssurance: recipient,
            requestedTTLSeconds: ttlSeconds,
            operationContext: reason,
            interactive: interactive,
            plaintextExposureAcknowledged: plaintextExposureAcknowledged
        )
        if isatty(STDERR_FILENO) == 1 {
            FileHandle.standardError.write(Data(
                "csec: waiting for the Convenient Security review window and Touch ID…\n".utf8
            ))
        }
        let values = try client.access(
            references: references,
            reason: reason,
            ttlSeconds: ttlSeconds,
            deliveryPlan: plan
        )
        // The response is already in csec's heap at this point, but it must not
        // cross stdout if the shell exited, was replaced, or csec was
        // reparented while review/Touch ID was in progress.
        guard getppid() == requestingParent.pid,
              ProcessAncestry.startTime(of: requestingParent.pid)
                == requestingParent.startTime,
              ProcessAncestry.executablePath(of: requestingParent.pid)
                == requestingParent.executablePath else {
            FileHandle.standardError.write(Data(
                "csec get: requesting parent changed during access; refusing output\n".utf8
            ))
            exit(1)
        }
        for reference in references {
            guard let value = values[reference] else {
                FileHandle.standardError.write(Data("csec: no value returned for \(reference)\n".utf8))
                exit(1)
            }
            // A value is bytes: stream them verbatim, then a trailing newline to
            // match a shell-friendly `get`. A text value is byte-identical to the
            // previous line-printed form; a binary value keeps full fidelity.
            FileHandle.standardOutput.write(value)
            FileHandle.standardOutput.write(Data("\n".utf8))
        }
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("csec: \(error.localizedDescription)\n".utf8))
        exit(1)
    }
}

// MARK: - exec

func runExec(_ arguments: [String]) -> Never {
    var reason: String?
    var ttlSeconds = 3600
    var explicit: [(name: String, reference: String)] = []
    var commandLine: [String] = []
    var outputGuard = OutputGuardConfiguration()

    var index = 0
    parse: while index < arguments.count {
        let token = arguments[index]
        switch token {
        case "--":
            commandLine = Array(arguments[(index + 1)...])
            break parse
        case "--reason":
            index += 1
            guard index < arguments.count else { usage("exec") }
            reason = arguments[index]
        case "--for":
            index += 1
            guard index < arguments.count, let seconds = Int(arguments[index]) else { usage("exec") }
            ttlSeconds = seconds
        case "--set":
            index += 1
            guard index < arguments.count, let equals = arguments[index].firstIndex(of: "=") else { usage("exec") }
            let name = String(arguments[index][..<equals])
            let reference = String(arguments[index][arguments[index].index(after: equals)...])
            guard !name.isEmpty, !reference.isEmpty else { usage("exec") }
            explicit.append((name: name, reference: reference))
        case "--redact-output":
            index += 1
            guard index < arguments.count,
                  let mode = OutputGuardMode(rawValue: arguments[index]) else { usage("exec") }
            outputGuard.mode = mode
        case let option where option.hasPrefix("--redact-output="):
            let value = String(option.dropFirst("--redact-output=".count))
            guard let mode = OutputGuardMode(rawValue: value) else { usage("exec") }
            outputGuard.mode = mode
        case "--redact-output-label":
            index += 1
            guard index < arguments.count,
                  let style = OutputRedactionLabelStyle(rawValue: arguments[index]) else { usage("exec") }
            outputGuard.labelStyle = style
        case let option where option.hasPrefix("--redact-output-label="):
            let value = String(option.dropFirst("--redact-output-label=".count))
            guard let style = OutputRedactionLabelStyle(rawValue: value) else { usage("exec") }
            outputGuard.labelStyle = style
        case "--redact-short-values":
            outputGuard.includeShortValues = true
        case "--redact-output-warn":
            outputGuard.emitWarnings = true
        default:
            // First non-flag token starts the command (`--` optional, like `env`).
            commandLine = Array(arguments[index...])
            break parse
        }
        index += 1
    }

    guard !commandLine.isEmpty else { usage("exec") }
    guard ttlSeconds > 0, ttlSeconds <= 24 * 60 * 60 else {
        csecError("exec", "--for must be between 1 and 86400 seconds")
        exit(2)
    }

    // A project holding `*.csec` sidecars needs its protected files back at their
    // original paths for the wrapped tree, which only the rootd launch can do.
    // Route there when any are present; overflow past the per-launch bound is a
    // hard error, never a silent fallback to environment injection. `csec exec`'s
    // ordinary environment injection (`--set` and env-scanned references) is folded
    // into the same launch as value-in-environment bindings, so one approval
    // delivers both files and values.
    do {
        let scan = try ProtectedSidecarScanner.scan(
            projectDirectory: FileManager.default.currentDirectoryPath)
        // A file that looks like a sidecar but cannot be parsed is warned about, not
        // silently skipped — otherwise a broken `*.csec` looks identical to the
        // secret simply not being there.
        for issue in scan.issues {
            warnProtectedSidecarIssue(path: issue.sidecarRelativePath, reason: issue.reason)
        }
        if !scan.discoveries.isEmpty {
            let assignments: [(name: String, reference: String)]
            do {
                let knownSchemes = Set(try makeAgentClient().schemes())
                let plan = try ExecPlanner.plan(
                    environment: ProcessInfo.processInfo.environment,
                    explicit: explicit,
                    knownSchemes: knownSchemes
                )
                // Sort for a deterministic plan (dictionaries are unordered) so the
                // digest and binding order are stable across identical invocations.
                assignments = plan.assignments
                    .map { (name: $0.key, reference: $0.value) }
                    .sorted { $0.name < $1.name }
            } catch {
                csecError("exec", "\(error)")
                exit(1)
            }
            runSidecarExec(
                commandLine: commandLine,
                discoveries: scan.discoveries,
                environmentAssignments: assignments,
                reason: reason,
                ttlSeconds: ttlSeconds,
                outputGuard: outputGuard
            )
        }
    } catch {
        csecError("exec", "\(error.localizedDescription)")
        exit(1)
    }

    let client = makeAgentClient()

    let knownSchemes: Set<String>
    do {
        knownSchemes = Set(try client.schemes())
    } catch {
        csecError("exec", "cannot reach agent: \(error)")
        exit(1)
    }

    let plan: ExecPlanner.Plan
    do {
        plan = try ExecPlanner.plan(
            environment: ProcessInfo.processInfo.environment,
            explicit: explicit,
            knownSchemes: knownSchemes
        )
    } catch {
        csecError("exec", "\(error)")
        exit(1)
    }

    var injected: [String: String] = [:]
    var resolvedValues: [String: Data] = [:]
    var resolvedExecutablePath: String?
    if !plan.references.isEmpty {
        do {
            let inspectedExecutable = try ExecutableInspection.plannedExecutable(command: commandLine[0])
            // An arbitrary command can load a user-writable script, checkout,
            // config, plugin, gem, or shared module. A protected interpreter
            // binary alone is not protected *consumer context*.
            let executable = PlannedExecutable(
                canonicalPath: inspectedExecutable.canonicalPath,
                signingIdentifier: inspectedExecutable.signingIdentifier,
                teamIdentifier: inspectedExecutable.teamIdentifier,
                cdHash: inspectedExecutable.cdHash,
                assurance: .unverified
            )
            let operation = reason ?? "csec exec \((executable.canonicalPath as NSString).lastPathComponent)"
            let deliveryPlan = DeliveryPlan(
                mechanism: .unrestrictedInitialEnvironment,
                executable: executable,
                root: .caller,
                descendantScope: .subtree,
                destination: .localDevelopment,
                requestedTTLSeconds: ttlSeconds,
                operationContext: operation,
                commandDigest: try ExecutableInspection.commandDigest(commandLine),
                outputGuard: outputGuard.plan
            )
            let values = try client.access(
                references: plan.references,
                reason: operation,
                ttlSeconds: ttlSeconds,
                deliveryPlan: deliveryPlan
            )
            resolvedValues = values
            resolvedExecutablePath = executable.canonicalPath
            injected = try ExecPlanner.resolvedEnvironment(base: [:], plan: plan, values: values)
        } catch {
            csecError("exec", "\(error.localizedDescription)")
            // A failed resolution names the reference; say which environment
            // name carries each one so the user knows what to fix or unset.
            if case AgentClient.ClientError.protocolFailure(.resolutionFailed, _) = error {
                FileHandle.standardError.write(Data("csec exec: this launch requested:\n".utf8))
                for (name, reference) in plan.assignments.sorted(by: { $0.key < $1.key }) {
                    let safe = (try? SecretRef(reference))?.safeInlineURI ?? "<invalid reference>"
                    FileHandle.standardError.write(Data("  \(safe)  —  environment \(name)\n".utf8))
                }
                FileHandle.standardError.write(Data(
                    "Fix or unset the source of the unresolvable reference and retry.\n".utf8
                ))
            }
            exit(1)
        }
    }

    let catalog = OutputRedactionCatalog(
        valuesByReference: resolvedValues,
        labelStyle: outputGuard.labelStyle,
        includeShortValues: outputGuard.includeShortValues
    )
    let stdoutIsTTY = isatty(STDOUT_FILENO) == 1
    let stderrIsTTY = isatty(STDERR_FILENO) == 1
    let guardOwnsOutput: Bool
    switch outputGuard.mode {
    case .tty:
        guardOwnsOutput = stdoutIsTTY || stderrIsTTY
        var unguarded: [String] = []
        if !stdoutIsTTY { unguarded.append("stdout") }
        if !stderrIsTTY { unguarded.append("stderr") }
        if !resolvedValues.isEmpty, !unguarded.isEmpty {
            FileHandle.standardError.write(Data(
                ("csec exec: warning: tty output masking is inactive for "
                 + unguarded.joined(separator: " and ")
                 + "; use --redact-output=always to alter non-terminal output\n").utf8
            ))
        }
    case .always:
        guardOwnsOutput = true
    case .never:
        guardOwnsOutput = false
        if !resolvedValues.isEmpty {
            FileHandle.standardError.write(Data(
                "csec exec: warning: output detection and masking explicitly disabled\n".utf8
            ))
        }
    }

    if guardOwnsOutput, catalog.skippedShortValueCount > 0 {
        FileHandle.standardError.write(Data(
            ("csec exec: warning: \(catalog.skippedShortValueCount) protected value(s) shorter than "
             + "\(OutputRedactionCatalog.minimumAutomaticSecretBytes) bytes are not matched; "
             + "use --redact-short-values to accept possible false positives\n").utf8
        ))
    }
    if guardOwnsOutput, !catalog.patterns.isEmpty, let executablePath = resolvedExecutablePath {
        var childEnvironment = ProcessInfo.processInfo.environment
        for (name, value) in injected { childEnvironment[name] = value }
        do {
            let status = try ProcessSupervisor.run(
                executablePath: executablePath,
                commandLine: commandLine,
                environment: childEnvironment,
                catalog: catalog,
                mode: outputGuard.mode,
                emitWarnings: outputGuard.emitWarnings
            )
            cs_terminate_like_wait_status(status)
        } catch {
            csecError("exec", "\(error)")
            exit(1)
        }
    }

    // With no owned output channel, no matchable value, or an explicit bypass,
    // retain exec-replacement behavior. csec disappears and the target directly
    // inherits the augmented environment, signals, and standard descriptors.
    for (name, value) in injected {
        guard setenv(name, value, 1) == 0 else {
            FileHandle.standardError.write(Data(
                "csec exec: could not construct the protected child environment\n".utf8
            ))
            exit(1)
        }
    }
    let argv: [UnsafeMutablePointer<CChar>?] = commandLine.map { strdup($0) } + [nil]
    execvp(commandLine[0], argv)

    // Secret-free launches never went through ExecutableInspection, so give the
    // quoted-shell-command mistake the same explanation it produces there.
    if errno == ENOENT, commandLine[0].contains(where: \.isWhitespace) {
        let guidance = ExecutableInspectionError
            .notFoundLooksLikeShellCommand(commandLine[0]).localizedDescription
        csecError("exec", "\(guidance)")
        exit(127)
    }
    let message = String(cString: strerror(errno))
    csecError("exec", "\(commandLine[0]): \(message)")
    exit(127)
}

// MARK: - signed language-client bridge

func runBridge() -> Never {
    // A bridge value is intentionally written to stdout, but only when stdout
    // and stdin are private pipes/socketpairs. Never permit a typo such as
    // `csec bridge > response.json` to persist plaintext in a regular file.
    guard cs_fd_is_pipe_or_socket(STDIN_FILENO) == 1,
          cs_fd_is_pipe_or_socket(STDOUT_FILENO) == 1 else {
        FileHandle.standardError.write(Data(
            "csec bridge: stdin and stdout must be private pipes (use a language client)\n".utf8
        ))
        exit(2)
    }
    signal(SIGPIPE, SIG_IGN)

    guard let input = readFrame(STDIN_FILENO),
          let request = try? JSONDecoder().decode(BridgeRequest.self, from: input),
          request.version == 1,
          !request.references.isEmpty,
          request.references.count <= 64,
          !request.reason.isEmpty,
          request.reason.utf8.count <= 512,
          request.ttlSeconds > 0,
          request.ttlSeconds <= 24 * 60 * 60 else {
        writeBridgeFailure(.invalidRequest, "invalid bridge request", status: 2)
    }

    let parentPID = getppid()
    guard parentPID > 1,
          let parentStartTime = ProcessAncestry.startTime(of: parentPID),
          let parentPath = ProcessAncestry.executablePath(of: parentPID),
          let inspectedExecutable = try? ExecutableInspection.plannedExecutable(command: parentPath) else {
        writeBridgeFailure(.invalidRequest, "requesting parent identity is unavailable", status: 1)
    }

    // The Ruby executable may be root-owned, but the application, gems, native
    // extensions, and checkout are ordinarily user-writable. Never let the
    // signed bridge upgrade that whole interpreted consumer to protected.
    let executable = PlannedExecutable(
        canonicalPath: inspectedExecutable.canonicalPath,
        signingIdentifier: inspectedExecutable.signingIdentifier,
        teamIdentifier: inspectedExecutable.teamIdentifier,
        cdHash: inspectedExecutable.cdHash,
        assurance: .unverified
    )

    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: executable,
        root: .directParent(pid: parentPID, startTime: parentStartTime),
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: request.ttlSeconds,
        operationContext: request.reason
    )

    do {
        let values = try makeAgentClient().access(
            references: request.references,
            reason: request.reason,
            ttlSeconds: request.ttlSeconds,
            deliveryPlan: plan
        )
        // The pipe must still lead to the same live parent that was shown in the
        // consent decision; reject reparenting, PID reuse, or an exec/image
        // change before writing values.
        guard getppid() == parentPID,
              ProcessAncestry.startTime(of: parentPID) == parentStartTime,
              ProcessAncestry.executablePath(of: parentPID) == inspectedExecutable.canonicalPath else {
            writeBridgeFailure(.unverifiedPeer, "requesting parent changed during access", status: 1)
        }
        // The bridge delivers env-style secrets into a language runtime, which are
        // NUL-free UTF-8 strings. A value that is not representable as one (a
        // binary file) has no place in a process environment.
        var textValues: [String: String] = [:]
        for (reference, bytes) in values {
            guard let text = String(data: bytes, encoding: .utf8), !text.utf8.contains(0) else {
                writeBridgeFailure(
                    .deliveryNotSupported,
                    "a referenced value is not a text secret and cannot be delivered to a language runtime",
                    status: 1
                )
            }
            textValues[reference] = text
        }
        let response = BridgeResponse(values: textValues)
        guard let data = try? JSONEncoder().encode(response),
              writeFrame(STDOUT_FILENO, data) else { exit(1) }
        exit(0)
    } catch AgentClient.ClientError.denied {
        writeBridgeFailure(.consentDenied, "consent denied", status: 1)
    } catch AgentClient.ClientError.protocolFailure(let code, let message) {
        writeBridgeFailure(code, message, status: 1)
    } catch {
        writeBridgeFailure(.internalError, "bridge could not reach the trusted agent", status: 1)
    }
}

func writeBridgeFailure(_ code: WireErrorCode, _ message: String, status: Int32) -> Never {
    let response = BridgeResponse(failure: ProtocolFailure(code, message: message))
    if let data = try? JSONEncoder().encode(response) {
        _ = writeFrame(STDOUT_FILENO, data)
    }
    exit(status)
}

// MARK: - install / uninstall / status

func runInstall() -> Never {
    do {
        let status = try LaunchAgentService.install()
        print("csec: agent registered — \(status.description)")
        if status.needsApproval {
            print("→ Approve “ConvenientSecurity” in System Settings › General › Login Items to let it start.")
        }
        exit(0)
    } catch {
        csecError("install", "\(error)")
        FileHandle.standardError.write(Data(
            "  csec must run from inside the installed .app bundle so SMAppService can find the LaunchAgent plist.\n".utf8
        ))
        exit(1)
    }
}

func runUninstall() -> Never {
    do {
        try LaunchAgentService.uninstall()
        print("csec: agent unregistered.")
        exit(0)
    } catch {
        csecError("uninstall", "\(error)")
        exit(1)
    }
}

func runRootStatus() -> Never {
    #if DEBUG
    let trustPolicy: RootHelperServerTrustPolicy = .allowUnverifiedForTesting
    #else
    let trustPolicy: RootHelperServerTrustPolicy = .requireProductRootHelper
    #endif
    do {
        try RootHelperClient(trustPolicy: trustPolicy).health()
        print("csec: authenticated root helper reachable")
        exit(0)
    } catch {
        FileHandle.standardError.write(Data(
            "csec root-status: authenticated root helper unavailable\n".utf8
        ))
        exit(1)
    }
}

func runRemote(_ arguments: [String]) -> Never {
    guard let action = arguments.first else { usage("remote") }
    let client = makeAgentClient()
    do {
        switch action {
        case "status":
            guard arguments.count == 1 else { usage("remote") }
            printRemoteApprovalStatus(try client.remoteApprovalStatus())
        case "enable":
            guard arguments.count == 2 else { usage("remote") }
            let result = try client.enableRemoteApproval(
                phonePairingCode: arguments[1]
            )
            printRemoteApprovalStatus(result.status)
            print("Import this public Mac pairing code in Convenient Security on the iPhone:")
            print(result.macPairingCode)
            print("Remote approval starts immediately after the phone accepts that code.")
        case "disable":
            guard arguments.count == 1 else { usage("remote") }
            printRemoteApprovalStatus(try client.disableRemoteApproval())
        default:
            usage("remote")
        }
        exit(0)
    } catch {
        FileHandle.standardError.write(Data(
            "csec remote: remote approval could not be configured (\(error.localizedDescription))\n".utf8
        ))
        exit(1)
    }
}

private func printRemoteApprovalStatus(_ status: RemoteApprovalConfigurationStatus) {
    switch status.state {
    case .disabled:
        print("csec: iPhone remote approval is off")
    case .unavailable:
        print("csec: iPhone remote approval configuration is unavailable; disable and enroll again")
    case .enabled:
        let phone = status.phoneName ?? "paired iPhone"
        let fingerprint = status.phoneKeyFingerprint ?? "unknown"
        print("csec: iPhone remote approval is on for \(phone) (key \(fingerprint))")
    }
}

/// Release clients always authenticate the product agent. Debug integration
/// tests may explicitly select their synthetic server via `CSEC_SOCKET`; both
/// the alternate path and relaxed trust are compiled out of release builds.
func makeAgentClient() -> AgentClient {
    #if DEBUG
    // SwiftPM development binaries are ad-hoc signed and cannot satisfy the
    // Developer ID requirement. This branch does not exist in a release build.
    let trustPolicy: AgentServerTrustPolicy = .allowUnverifiedForTesting
    #else
    let trustPolicy: AgentServerTrustPolicy = .requireProductAgent
    #endif
    return AgentClient(path: AgentSocket.defaultPath(), serverTrustPolicy: trustPolicy)
}
