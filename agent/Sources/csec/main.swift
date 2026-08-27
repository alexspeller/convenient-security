import Foundation
import ConvenientSecurity
import CSecuritySupport
#if canImport(Darwin)
import Darwin
#endif

// The launcher / CLI.
//
//   csec get <reference> [--reason <text>] [--for <seconds>]
//       Fetch a secret from the running agent after reviewing the exact stdout
//       shape: terminal, shell-delegated pipe, or ordinary persistent file.
//
//   csec exec [options] [--set NAME=<reference>]… -- <cmd> [args…]
//       Resolve secret references (from the environment and any --set flags) and
//       run <cmd> with those values injected into its environment. Environment
//       values that are themselves references (e.g. DATABASE_URL=csec://…) are
//       resolved in place, so unmodified tools like `rails`/`psql` just work.
//
//   csec session -- <cmd> [args…]
//       Register this PID/start-time as an explicit broad session root, then
//       replace csec with the requested command.
//
//   csec creds aws|git ...
//       Serve a tool-native credential protocol over a private stdout pipe.
//
//   csec exec-fd (--fd ENV=<reference>|--preset NAME=<reference>)… -- <cmd>
//       Stream file-shaped secrets into inherited anonymous descriptors.
//
//   csec exec-file (--file ENV=<reference>|--gh-config <reference>)… -- <cmd>
//       Ask the root helper to launch a process tree with regular files protected
//       by a fresh primary-GID capability on bounded tmpfs.

//   csec root-status
//       Verify that the authenticated root helper is reachable.
//
//   csec tool-exec --destination ai -- <cmd> [args…]
//       Run a command whose output is scanned against every active value in the
//       resident agent before any bytes are returned to an AI command runner.
//
//   csec edit [--editor] <store>
//       Open the native csec:// store as strict JSON. The built-in fileless
//       editor is the default; --editor opts into a named plaintext file for
//       compatibility with the command in $EDITOR.
//
//   csec risk inspect|forget <reference>
//   csec risk classify|raise <level> <reference>
//       Inspect or change value-free risk metadata without resolving a value.

//   csec setup [--apply] [options]
//       Dry-run-first onboarding for coding-agent hooks, value-free local source
//       discovery, selected native-store import, and a bounded audit prompt.

func usage() -> Never {
    FileHandle.standardError.write(Data("""
    usage:
      csec get <reference> [--reason <text>] [--for <seconds>]
      csec exec [--reason <text>] [--for <seconds>] [--set NAME=<reference>]…
                [--redact-output=tty|always|never]
                [--redact-output-label=opaque|reference] [--redact-short-values]
                -- <cmd> [args…]
      csec session -- <cmd> [args…]
      csec creds aws (--item <reference> |
                     --access-key-id-ref <reference> --secret-access-key-ref <reference>
                     [--session-token-ref <reference>] [--expiration-ref <reference>])
                     [--reason <text>] [--for <seconds>]
      csec creds git --host <host> [--protocol <scheme>] [--path <repository>]
                     [--username-ref <reference>] --password-ref <reference>
                     [--reason <text>] [--for <seconds>] get|store|erase
      csec exec-fd [--reason <text>] [--for <seconds>]
                   (--fd ENV_NAME=<reference> |
                    --preset {pgpass|kubeconfig|aws-shared-credentials|google-service-account}=<reference>)…
                   [--redact-output=tty|always|never]
                   [--redact-output-label=opaque|reference] [--redact-short-values]
                   -- <cmd> [args…]
      csec exec-file [--reason <text>] [--for <seconds>] [--hard-ttl]
                     (--file ENV_NAME=<reference> | --gh-config <reference>)…
                     [--github-host <host>] [--github-user <login>]
                     [--github-git-protocol https|ssh]
                     [--redact-output=tty|always|never]
                     [--redact-output-label=opaque|reference] [--redact-short-values]
                     -- <cmd> [args…]
      csec bridge
      csec tool-exec --destination ai -- <cmd> [args…]
      csec hook claude|codex
      csec hook-config claude|codex
      csec edit [--editor] <store>
      csec protect [--store <store>] [--keep-plaintext] [--dry-run] <path>…
      csec risk inspect <reference>
      csec risk classify low|standard|high|critical <reference>
      csec risk raise low|standard|high|critical <reference>
      csec risk forget <reference>
      csec setup [--apply] [--agent claude|codex]… [--skip-agents]
                 [--project <directory>] [--replace-csec-hook]
                 [--store <store>
                  --import DEST=env:NAME|DEST=dotenv:PATH:NAME]…
                 [--replace-secret] [--no-audit-prompt]
      csec audit [--report-only] [--json] [--attest] [--scan-filesystem]
      csec install | uninstall | status
      csec root-status

    get        Fetch a secret from csecd and write it to the selected stdout shape:
                 csec get REF                    interactive terminal output
                 csec get REF | command          shell-delegated pipeline
                 value=$(csec get REF)           shell-delegated command substitution
                 csec get REF > file             ordinary persistent plaintext file
               The verified direct-parent shell owns the PID/start-time-bound subtree
               grant; signed csec is the emitter. A generic Unix pipe does not reveal
               its sibling reader, so the review labels that recipient unverified.
               File redirection persists plaintext and may expose it to same-user
               processes, copies, backups, and later access. Each delivery shape is
               approved separately. Prefer csec exec for environment injection,
               csec exec-fd for anonymous file-shaped input, csec exec-file for
               protected regular files, or csec creds for supported tool-native
               credential protocols.
    exec       Run <cmd> with secret references resolved into its environment. Any env
               value that is a secret reference (DATABASE_URL=csec://…) is resolved in
               place; --set NAME=<ref> injects additional ones. Terminal output is
               masked by default; use 'always' for captured logs and pipes.
    session    Register a kernel-verified broad grant root, then run <cmd> at the same PID.
    creds      Serve AWS credential_process or Git credential-helper output via a private pipe.
    exec-fd    Give a child anonymous single-open secret files at /dev/fd/N. Presets set
               PGPASSFILE, KUBECONFIG, AWS_SHARED_CREDENTIALS_FILE, or
               GOOGLE_APPLICATION_CREDENTIALS to the non-secret descriptor path.
    exec-file  Give a launched process tree seekable/reopenable root-owned regular files
               on bounded tmpfs. A fresh primary GID is the per-launch capability;
               csec never receives file bytes. --gh-config creates protected hosts.yml
               only after ambient GitHub authentication has been removed.
    bridge     Private framed stdin/stdout protocol for language clients; not for terminals.
    tool-exec  Fail-closed AI command broker using csecd's active-value scanner.
    hook       PreToolUse stdin/stdout adapter for Claude Code or Codex.
    hook-config  Print a hook JSON fragment using this exact csec executable.
    edit       Edit a csec:// store as strict JSON. The default built-in editor is
               fileless; --editor uses $EDITOR with a temporary plaintext file.
    risk       Inspect or change a logical credential's value-free risk policy.
               classify may set any level; raise cannot lower one; forget resets
               it to fail-safe unknown. Downgrades and forget require Touch ID.
    setup      Detect supported coding agents and local secret sources without
               displaying values. The default is a dry run. --apply safely merges
               fail-closed hooks and may import only explicitly selected plaintext
               candidates into one native encrypted store; existing hooks/keys are
               never replaced without their separate explicit replacement flags.
    audit      Run the value-free host posture audit through csecd and render the
               findings (severity-ordered, ★ marks controls that shrink same-user
               malware blast radius). On a terminal the scan animates live progress;
               piped or --json output stays plain. By default it then offers the
               reversible fixes as an in-terminal checkbox picker (one bare Touch ID
               in csecd applies the selected set), triages whatever is still failing
               (accept as an exemption, or keep as a TODO with weekly reminders), and
               prints a copy-paste attestation of the final posture. --report-only
               just prints the report, --attest prints only the pasteable
               attestation, --json emits the machine-readable report, and
               --scan-filesystem adds the bounded SUID/world-writable sweep.
    install    Register csecd as a login-item LaunchAgent so it runs in the background.
    uninstall  Unregister the csecd LaunchAgent.
    status     Show whether the csecd LaunchAgent is registered/enabled.
    root-status  Verify that the authenticated regular-file root helper is reachable.

    """.utf8))
    exit(2)
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard let command = arguments.first else { usage() }

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
    guard arguments.count == 1 else { usage() }
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
case "risk":
    runRisk(Array(arguments.dropFirst()))
case "setup":
    runSetup(Array(arguments.dropFirst()))
case "audit":
    runAudit(Array(arguments.dropFirst()))
case "install":
    runInstall()
case "uninstall":
    runUninstall()
case "status":
    runStatus()
case "root-status":
    guard arguments.count == 1 else { usage() }
    runRootStatus()
default:
    usage()
}

// MARK: - AI command hooks and fail-closed tool execution

func runHook(_ arguments: [String]) -> Never {
    guard arguments.count == 1,
          let client = AICommandHookClient(rawValue: arguments[0]) else { usage() }
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
          let client = AICommandHookClient(rawValue: arguments[0]) else { usage() }
    do {
        FileHandle.standardOutput.write(try AICommandHook.hookConfiguration(
            client: client,
            csecExecutablePath: currentExecutablePath()
        ))
        exit(0)
    } catch {
        FileHandle.standardError.write(Data("csec hook-config: could not build configuration\n".utf8))
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
            guard index < arguments.count else { usage() }
            destination = arguments[index]
        case "--encoded-shell-command":
            index += 1
            guard index < arguments.count else { usage() }
            encodedShellCommand = arguments[index]
        case "--":
            commandLine = Array(arguments[(index + 1)...])
            break parse
        default:
            usage()
        }
        index += 1
    }
    guard destination == "ai",
          encodedShellCommand == nil || commandLine.isEmpty else { usage() }

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
            FileHandle.standardError.write(Data("csec tool-exec: invalid encoded command\n".utf8))
            exit(2)
        }
    } else {
        guard !commandLine.isEmpty else { usage() }
        do {
            executablePath = try ExecutableInspection.plannedExecutable(
                command: commandLine[0]
            ).canonicalPath
        } catch {
            FileHandle.standardError.write(Data("csec tool-exec: command is not executable\n".utf8))
            exit(127)
        }
    }

    let session: AgentOutputRedactionSession
    do {
        session = try makeAgentClient().beginOutputRedaction(
            destination: .aiTool,
            streams: OutputRedactionStream.allCases
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

// MARK: - value-free risk management

func runRisk(_ arguments: [String]) -> Never {
    guard let operationText = arguments.first,
          let operation = RiskOperation(rawValue: operationText) else { usage() }

    let referenceText: String
    let level: RiskLevel?
    switch operation {
    case .inspect, .forget:
        guard arguments.count == 2 else { usage() }
        referenceText = arguments[1]
        level = nil
    case .classify, .raise:
        guard arguments.count == 3,
              let parsed = RiskLevel(rawValue: arguments[1]),
              parsed != .unknown else { usage() }
        level = parsed
        referenceText = arguments[2]
    }
    guard let reference = try? SecretRef(referenceText) else {
        FileHandle.standardError.write(Data("csec risk: invalid secret reference\n".utf8))
        exit(2)
    }

    do {
        let inspection = try makeAgentClient().risk(
            operation,
            reference: reference.uri,
            level: level
        )
        let formatter = ISO8601DateFormatter()
        print("reference: \(reference.safeInlineURI)")
        print("provider: \(inspection.provider)")
        print("classification: \(inspection.level.rawValue)")
        print("effective-risk: \(inspection.effectiveLevel.rawValue)")
        print("policy-version: \(inspection.policyVersion)")
        print("known-members: \(inspection.knownMemberCount)")
        print("reference-in-known-scope: \(inspection.referenceInKnownScope ? "yes" : "no")")
        if let decidedAt = inspection.decidedAt {
            print("decided-at: \(formatter.string(from: decidedAt))")
        }
        if let reviewAfter = inspection.reviewAfter {
            print("review-after: \(formatter.string(from: reviewAfter))")
        }
        if inspection.acceptances.isEmpty {
            print("compatibility-acceptances: none")
        } else {
            for acceptance in inspection.acceptances {
                print(
                    "compatibility-acceptance: \(acceptance.mechanism.rawValue) "
                        + "\(acceptance.destination.rawValue) "
                        + "scope=\(acceptance.descendantScope.rawValue) "
                        + "emitter=\(acceptance.emitterAssurance.rawValue) "
                        + "requester=\(acceptance.requesterAssurance?.rawValue ?? "none") "
                        + "recipient=\(acceptance.recipientAssurance?.rawValue ?? "planned_consumer") until "
                        + formatter.string(from: acceptance.reviewAfter)
                )
            }
        }
        exit(0)
    } catch {
        FileHandle.standardError.write(Data(
            "csec risk: \(error.localizedDescription)\n".utf8
        ))
        exit(1)
    }
}

// MARK: - native encrypted store editor

func runEdit(_ arguments: [String]) -> Never {
    var useExternalEditor = false
    var storeArgument: String?
    for argument in arguments {
        if argument == "--editor" {
            guard !useExternalEditor else { usage() }
            useExternalEditor = true
        } else {
            guard storeArgument == nil, !argument.hasPrefix("-") else { usage() }
            storeArgument = argument
        }
    }
    guard let storeArgument else { usage() }

    let externalEditor: ExternalEditorCommand?
    if useExternalEditor {
        do {
            externalEditor = try ExternalEditorCommand()
        } catch {
            FileHandle.standardError.write(Data("csec edit: \(error.localizedDescription)\n".utf8))
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
        FileHandle.standardError.write(Data("csec edit: \(error.localizedDescription)\n".utf8))
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
        FileHandle.standardError.write(Data("csec edit: cannot reach the trusted agent\n".utf8))
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
        FileHandle.standardError.write(Data("csec edit: \(error.localizedDescription)\n".utf8))
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
            FileHandle.standardError.write(Data("csec edit: \(error.localizedDescription)\n".utf8))
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
    var index = 0
    while index < arguments.count {
        switch arguments[index] {
        case "--reason":
            index += 1
            guard index < arguments.count else { usage() }
            reason = arguments[index]
        case "--for":
            index += 1
            guard index < arguments.count, let seconds = Int(arguments[index]) else { usage() }
            ttlSeconds = seconds
        default:
            references.append(arguments[index])
        }
        index += 1
    }
    guard !references.isEmpty else { usage() }
    guard ttlSeconds > 0, ttlSeconds <= 24 * 60 * 60 else {
        FileHandle.standardError.write(Data("csec get: --for must be between 1 and 86400 seconds\n".utf8))
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
        let mechanism: DeliveryMechanism
        let destination: DestinationClass
        let recipient: RecipientAssurance
        if isatty(STDOUT_FILENO) == 1 {
            mechanism = .rawStandardOutput
            destination = .humanOutput
            recipient = .interactiveTerminal
        } else if cs_fd_is_pipe_or_socket(STDOUT_FILENO) == 1 {
            mechanism = .rawStandardOutput
            destination = .shellDelegatedPipe
            recipient = .unverifiedPipeReader
            FileHandle.standardError.write(Data(
                "csec get: stdout is a shell-delegated pipe with an unverified reader; review required\n".utf8
            ))
        } else if cs_fd_is_regular_file(STDOUT_FILENO) == 1 {
            mechanism = .namedPlaintextFile
            destination = .persistentPlaintextFile
            recipient = .ordinaryPersistentFile
            FileHandle.standardError.write(Data(
                "csec get: stdout is an ordinary persistent plaintext file; review required; prefer csec exec-file\n".utf8
            ))
        } else {
            FileHandle.standardError.write(Data(
                "csec get: unsupported stdout destination\n".utf8
            ))
            exit(2)
        }
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
            operationContext: reason
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
            guard index < arguments.count else { usage() }
            reason = arguments[index]
        case "--for":
            index += 1
            guard index < arguments.count, let seconds = Int(arguments[index]) else { usage() }
            ttlSeconds = seconds
        case "--set":
            index += 1
            guard index < arguments.count, let equals = arguments[index].firstIndex(of: "=") else { usage() }
            let name = String(arguments[index][..<equals])
            let reference = String(arguments[index][arguments[index].index(after: equals)...])
            guard !name.isEmpty, !reference.isEmpty else { usage() }
            explicit.append((name: name, reference: reference))
        case "--redact-output":
            index += 1
            guard index < arguments.count,
                  let mode = OutputGuardMode(rawValue: arguments[index]) else { usage() }
            outputGuard.mode = mode
        case let option where option.hasPrefix("--redact-output="):
            let value = String(option.dropFirst("--redact-output=".count))
            guard let mode = OutputGuardMode(rawValue: value) else { usage() }
            outputGuard.mode = mode
        case "--redact-output-label":
            index += 1
            guard index < arguments.count,
                  let style = OutputRedactionLabelStyle(rawValue: arguments[index]) else { usage() }
            outputGuard.labelStyle = style
        case let option where option.hasPrefix("--redact-output-label="):
            let value = String(option.dropFirst("--redact-output-label=".count))
            guard let style = OutputRedactionLabelStyle(rawValue: value) else { usage() }
            outputGuard.labelStyle = style
        case "--redact-short-values":
            outputGuard.includeShortValues = true
        default:
            // First non-flag token starts the command (`--` optional, like `env`).
            commandLine = Array(arguments[index...])
            break parse
        }
        index += 1
    }

    guard !commandLine.isEmpty else { usage() }
    guard ttlSeconds > 0, ttlSeconds <= 24 * 60 * 60 else {
        FileHandle.standardError.write(Data("csec exec: --for must be between 1 and 86400 seconds\n".utf8))
        exit(2)
    }

    // A project holding `*.csec` sidecars needs its protected files back at their
    // original paths for the wrapped tree, which only the rootd launch can do.
    // Route there when any are present; overflow past the per-launch bound is a
    // hard error, never a silent fallback to environment injection.
    do {
        let discoveries = try ProtectedSidecarScanner.scan(
            projectDirectory: FileManager.default.currentDirectoryPath)
        if !discoveries.isEmpty {
            if !explicit.isEmpty {
                FileHandle.standardError.write(Data(
                    "csec exec: warning: --set is ignored when protected-file sidecars are present\n".utf8))
            }
            runSidecarExec(
                commandLine: commandLine,
                discoveries: discoveries,
                reason: reason,
                ttlSeconds: ttlSeconds,
                outputGuard: outputGuard
            )
        }
    } catch {
        FileHandle.standardError.write(Data("csec exec: \(error.localizedDescription)\n".utf8))
        exit(1)
    }

    let client = makeAgentClient()

    let knownSchemes: Set<String>
    do {
        knownSchemes = Set(try client.schemes())
    } catch {
        FileHandle.standardError.write(Data("csec exec: cannot reach agent: \(error)\n".utf8))
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
        FileHandle.standardError.write(Data("csec exec: \(error)\n".utf8))
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
            FileHandle.standardError.write(Data("csec exec: \(error.localizedDescription)\n".utf8))
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
    if guardOwnsOutput, outputGuard.labelStyle == .reference, !catalog.patterns.isEmpty {
        FileHandle.standardError.write(Data(
            "csec exec: warning: redaction labels will expose secret-reference metadata\n".utf8
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
                mode: outputGuard.mode
            )
            cs_terminate_like_wait_status(status)
        } catch {
            FileHandle.standardError.write(Data("csec exec: \(error)\n".utf8))
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

    let message = String(cString: strerror(errno))
    FileHandle.standardError.write(Data("csec exec: \(commandLine[0]): \(message)\n".utf8))
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
        FileHandle.standardError.write(Data("csec install: \(error)\n".utf8))
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
        FileHandle.standardError.write(Data("csec uninstall: \(error)\n".utf8))
        exit(1)
    }
}

func runStatus() -> Never {
    print("csec: LaunchAgent \(LaunchAgentService.status().description)")
    exit(0)
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
