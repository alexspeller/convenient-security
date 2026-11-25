import Foundation
import ConvenientSecurity
import CSECRemoteApproval
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
case "--version":
    // This binary's own release stamp, so the bridge copy outside the app
    // reports what it is, not what the app beside it says.
    guard commandArguments.isEmpty else { printGlobalHelp(exitCode: 2) }
    print(ReleaseStamp.versionLine(program: CLICatalog.program))
    exit(0)
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
// `csec fly` forwards everything to fly, help included (`csec help fly` is csec's).
if CLICatalog.command(named: command) != nil, command != "fly", wantsHelp(commandArguments) {
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
case "gcloud":
    runGcloud(commandArguments)
case "fly":
    runFly(commandArguments)
case "exec-file":
    runExecFile(Array(arguments.dropFirst()))
case "bridge":
    guard arguments.count == 1 else { usage("bridge") }
    runBridge()
case "ai":
    runAI(Array(arguments.dropFirst()))
case "tool-exec":
    // Hidden deprecated alias: already-emitted hook rewrites still say
    // `tool-exec`. It routes to the same broker as `ai` (which also decodes the
    // legacy `--encoded-shell-command` transport those rewrites use).
    runAI(Array(arguments.dropFirst()), invokedAs: "tool-exec")
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
case "backup":
    runBackup(Array(arguments.dropFirst()))
case "ssh":
    runSSH(Array(arguments.dropFirst()))
case "github":
    runGitHub(Array(arguments.dropFirst()))
case "identity":
    runIdentity(Array(arguments.dropFirst()))
case "automation":
    runAutomation(Array(arguments.dropFirst()))
case "grants":
    runGrants(Array(arguments.dropFirst()))
case "restore":
    runRestore(Array(arguments.dropFirst()))
case "revoke":
    runRevoke(Array(arguments.dropFirst()))
case "refresh":
    runRefresh(Array(arguments.dropFirst()))
case "log":
    runLog(Array(arguments.dropFirst()))
case "install":
    runInstall()
case "uninstall":
    runUninstall(Array(arguments.dropFirst()))
case "status":
    runStatus(Array(arguments.dropFirst()))
case "doctor":
    runDoctor(Array(arguments.dropFirst()))
case "root-status":
    guard arguments.count == 1 else { usage("root-status") }
    runRootStatus()
default:
    printUnknownCommand(command)
}

// MARK: - AI command hooks and fail-closed tool execution

func runRestore(_ arguments: [String]) -> Never {
    guard arguments.isEmpty else { usage("restore") }
    do {
        let result = try makeAgentClient().restoreApprovals(waitingNotice: approvalWaitNotice("restore"))
        switch result.status {
        case .reopened: print("Approvals reopened after csecd restarted.")
        case .forgotten: print("Restored approvals forgotten as requested.")
        case .notNeeded: print("No approvals need reopening.")
        case .alreadyRestored: print("Approval restoration already completed for this csecd.")
        }
        if let fetched = result.fetchedAhead {
            printFetchAhead(fetched)
        }
        // A value that could not be fetched now is fetched on first use, as
        // before; it is reported, never a reason to fail the install.
        exit(0)
    } catch {
        csecError("restore", error.localizedDescription)
        exit(1)
    }
}

func printFetchAhead(_ summary: FetchAheadSummary) {
    print("Paired values fetched ahead for Claude Code auto mode: \(summary.fetched) fetched, "
        + "\(summary.alreadyHeld) already held, \(summary.failureCount) not fetched.")
    for failure in summary.failures {
        let reference = (try? SecretRef(failure.reference))?.safeInlineURI ?? "a reference"
        print("  not fetched: \(reference): \(ReviewDisplay.sanitized(failure.reason))")
    }
    if summary.failureCount > summary.failures.count {
        print("  … and \(summary.failureCount - summary.failures.count) more; see csec log --kind fetch_ahead.")
    }
    if summary.failureCount > 0 {
        print("  Each is fetched on first use instead, and its provider's own app may then need someone at the Mac.")
    }
}

func runHook(_ arguments: [String]) -> Never {
    guard arguments.count == 1,
          let client = AICommandHookClient(rawValue: arguments[0]) else { usage("hook") }
    do {
        let input = FileHandle.standardInput.readDataToEndOfFile()
        // Claude Code runs nothing until the hook exits, so registering before
        // the rewrite is printed puts the registration ahead of the `csec ai`
        // it describes. It is bounded, never retried and silent: a csecd that
        // is down, stale or slow only means the command is not delegated.
        let output = try AICommandHook.output(
            input: input,
            client: client,
            csecExecutablePath: currentExecutablePath(),
            codexPolicy: { workingDirectory in
                CodexCommandGate.loadPolicy(
                    homeDirectory: FileManager.default.homeDirectoryForCurrentUser.path,
                    codexHome: ProcessInfo.processInfo.environment["CODEX_HOME"],
                    workingDirectory: workingDirectory)
            },
            shellPrefix: ProcessInfo.processInfo.environment["CLAUDE_CODE_SHELL_PREFIX"],
            register: { registration in
                _ = makeAgentClient().registerAgentCommand(registration)
            }
        )
        // Empty output leaves the command to the client's own gates.
        guard !output.isEmpty else { exit(0) }
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
    guard let first = arguments.first,
          let client = AICommandHookClient(rawValue: first) else { usage("hook-config") }
    let options = Array(arguments.dropFirst())
    let system = options.first == "--system"
    if client == .codex, options == ["--system", "--remove"] { runCodexSystemHookRemoval() }
    // `--launcher <path>` names the csec the document should invoke, so the root
    // installer can run a verified private copy that still embeds the installed path.
    var launcher = currentExecutablePath()
    switch options.count {
    case 0: break
    case 1 where system: break
    case 3 where system && options[1] == "--launcher" && options[2].hasPrefix("/"): launcher = options[2]
    default: usage("hook-config")
    }
    guard !system || client == .codex else { usage("hook-config") }
    do {
        // `--system` prints the complete managed document for Codex's System
        // layer: the current csec handler merged into the installed file, with
        // every other hook kept. The guarded installer stage runs this as root
        // and build-and-install compares the result byte for byte.
        FileHandle.standardOutput.write(system
            ? try CodingAgentSetup.codexSystemHookDocument(csecExecutablePath: launcher)
            : try AICommandHook.hookConfiguration(
                client: client,
                csecExecutablePath: launcher
            ))
        exit(0)
    } catch {
        csecError("hook-config", system
            ? "could not build the managed Codex hook document from \(CodingAgentSetup.codexSystemHookPath) "
                + "(it must be a root-owned JSON file in a root-owned directory): "
                + ReviewDisplay.sanitized(error.localizedDescription)
            : "could not build configuration")
        exit(1)
    }
}

/// `csec hook-config codex --system --remove`, for the complete uninstall's
/// root script: prints `/etc/codex/hooks.json` with csec's hook taken out and
/// every other hook and key kept, or nothing when no file should remain (csec's
/// hook was all it held, or there is no file). A valid document is never
/// empty, so empty output cannot be mistaken for one. Read-only: the script
/// writes the result itself, as root, and compares it with the file to tell
/// whether anything of csec's was there.
func runCodexSystemHookRemoval() -> Never {
    do {
        switch try CodingAgentSetup.codexSystemHookRemoval() {
        case .absent, .delete:
            break
        case let .rewrite(data), let .unchanged(data):
            FileHandle.standardOutput.write(data)
        }
        exit(0)
    } catch {
        csecError("hook-config", "could not read the managed Codex hook document "
            + "\(CodingAgentSetup.codexSystemHookPath) (it must be a root-owned JSON file in a root-owned directory): "
            + ReviewDisplay.sanitized(error.localizedDescription))
        exit(1)
    }
}

/// The coding-agent command broker. It does both halves of protected execution
/// through the one shared injection engine `csec exec` uses:
///
/// 1. **Inject** — resolve any secret references in the environment (the direnv
///    ergonomic: `.envrc` exports `op://…`/`csec://…`, `ai` resolves them) and
///    hand the values to the child, so an agent under the hook can actually *use*
///    secrets rather than fall back to a plaintext `.env`. A secret-free program
///    (`AICommandSecretFree`) skips this half: no access request, and no
///    reference variable reaches the child.
/// 2. **Redact** — scan the child's output against csecd's active values before a
///    byte reaches the AI, with always-on opaque `[csec:secret-N]` labels.
///
/// Both halves need csecd. A transient outage (e.g. mid `csec install` restart)
/// is retried briefly; a durable one fails closed with an actionable message —
/// the command never runs unscanned.
///
/// `invokedAs` is only the label in diagnostics/usage, so the hidden `tool-exec`
/// alias reports itself faithfully.
func runAI(_ arguments: [String], invokedAs command: String = "ai") -> Never {
    // Exactly one program source: the visible `-- <program>` form or the legacy
    // base64 transport (the Codex fail-safe and the `tool-exec` alias). The
    // hook single-quotes a shell program into one word and emits a bare-safe
    // one as words the client's shell splits; either way the words are rejoined
    // exactly as the hook's registration digested them. `--destination` is
    // accepted only for the legacy alias, and only as `ai`.
    let program: String
    do {
        program = try AICommandExec.program(fromArguments: arguments)
    } catch AICommandExec.ArgumentError.invalidEncodedCommand {
        csecError(command, "invalid encoded command")
        exit(2)
    } catch {
        usage(command)
    }

    // As Claude Code's shell prefix (`ClaudeCodeShellPrefix`), a hook or MCP
    // command line runs unwrapped, exactly as it ran before the prefix; a Bash
    // or Monitor framing runs under csec ai, judged by the command inside its
    // `eval`, which is the command auto mode reviewed.
    let shellPrefix = AICommandExec.isShellPrefix(arguments: arguments)
    if shellPrefix, ClaudeCodeShellPrefix.runsUnwrapped(program) {
        execUnwrappedShellPrefixCommand(program)
    }
    let framing = shellPrefix ? ClaudeCodeShellPrefix.framing(program) : nil
    let judgedProgram = framing?.command ?? program

    let executablePath = AICommandExec.shellPath
    // Policy and delegation bind the exact requested program. The child launch
    // adds only the fixed credential-guard setup after its login startup, or,
    // for a framing, just before its `eval`, after the snapshot it sources.
    let commandLine = AICommandExec.commandLine(forProgram: program)
    if AICommandCredentialGuard.invokesOPDirectly(judgedProgram) {
        csecError(command, AICommandCredentialGuard.refusal)
        exit(126)
    }
    let credentialGuard: AICommandCredentialGuard
    do {
        credentialGuard = try AICommandCredentialGuard(executablePath: currentExecutablePath())
    } catch {
        csecError(command, "could not prepare the direct op guard; command refused")
        exit(126)
    }
    let executionCommandLine = framing.map {
        AICommandExec.commandLine(forProgram: ClaudeCodeShellPrefix.guarded(
            program, evalStart: $0.evalStart, setup: credentialGuard.framingSetup))
    } ?? credentialGuard.commandLine(forProgram: program)
    let notices = AISetupNotices(command: command)

    // Process-lifetime grant, matching `csec exec`: the hook does not request a
    // wall-clock lifetime, so a whole agent session of the same shape costs one
    // Touch ID and never re-prompts on a clock. nil ⇒ the grant lives for the
    // agent process subtree.
    let ttlSeconds: Int? = nil

    let client = makeAgentClient()

    // Detect which environment values are resolvable references. This is the
    // first csecd touch; a down daemon means fail closed, exactly like the
    // scanner being unavailable below.
    let knownSchemes: Set<String>
    do {
        knownSchemes = Set(try withCsecdReconnect { try client.schemes() })
    } catch {
        // csec ai never blocks: warn and run without injection rather than
        // bricking the shell when csecd is unreachable/untrusted/stale.
        runAICommandUnprotected(
            command, executablePath: executablePath, commandLine: executionCommandLine,
            credentialGuard: credentialGuard,
            cause: aiDegradeCause(error)
        )
    }

    let plan: ExecPlanner.Plan
    do {
        plan = try ExecPlanner.plan(
            environment: ProcessInfo.processInfo.environment,
            explicit: [],
            knownSchemes: knownSchemes
        )
    } catch {
        runAICommandUnprotected(
            command, executablePath: executablePath, commandLine: executionCommandLine,
            credentialGuard: credentialGuard,
            cause: "the environment could not be analyzed for secret references (\(error))."
        )
    }

    // A program that runs only listed read-only tools and expands no reference
    // variable needs no secret: ask csecd for none (no panel) and hand the child
    // none of the references. Its output is still scanned below, against every
    // value csecd has already released. A local list that fails its checks adds
    // nothing, so its commands ask for the secrets as before.
    var secretFree = false
    if !plan.references.isEmpty {
        let localCommands: AICommandSecretFree.LocalCommands
        do {
            localCommands = try AICommandSecretFree.LocalCommands.load()
        } catch {
            FileHandle.standardError.write(Data("csec: ignoring local secret-free commands: \(error)\n".utf8))
            localCommands = .none
        }
        secretFree = AICommandSecretFree.classify(
            judgedProgram, referenceVariables: AICommandSecretFree.referenceVariables(of: plan),
            localCommands: localCommands
        ).isSecretFree
    }

    var injected: [String: String] = [:]
    if !plan.references.isEmpty && !secretFree {
        // The plan binds the argv csecd shows (and a delegated approval checks)
        // by digest. A stable release shape is load-bearing here: the digest is
        // outside it, so the coding-agent scope csecd offers by default reuses
        // this grant for every later `ai` command of the same shape, and a
        // whole agent session costs one Touch ID.
        let commandDigest: String
        do {
            commandDigest = try ExecutableInspection.commandDigest(commandLine)
        } catch {
            runAICommandUnprotected(
                command, executablePath: executablePath, commandLine: executionCommandLine,
                credentialGuard: credentialGuard,
                cause: "the command could not be bound to its access request (\(error))."
            )
        }
        let deliveryPlan = AICommandExec.deliveryPlan(
            executablePath: executablePath,
            ttlSeconds: ttlSeconds,
            commandDigest: commandDigest
        )
        do {
            injected = try withCsecdReconnect {
                try resolveAndInject(
                    client: client,
                    plan: plan,
                    deliveryPlan: deliveryPlan,
                    reason: AICommandExec.operationContext,
                    ttlSeconds: ttlSeconds,
                    commandLine: commandLine,
                    delegationNotice: notices.print,
                    waitingNotice: approvalWaitNotice(command)
                ).injected
            }
        } catch {
            // Never block: warn and run without injection. A daemon/trust failure
            // points at `csec doctor`; a resolution failure (a reference that no
            // longer resolves) names the reference(s) so the user can fix it.
            let cause: String
            switch error {
            case AgentClient.ClientError.connectFailed,
                 AgentClient.ClientError.connectPermissionDenied,
                 AgentClient.ClientError.untrustedServer,
                 AgentClient.ClientError.transportFailed,
                 AgentClient.ClientError.daemonUnresponsive,
                 AgentClient.ClientError.connectionLost:
                cause = aiDegradeCause(error)
            default:
                var lines = "a secret reference could not be resolved (\(error.localizedDescription)):"
                for (name, reference) in plan.assignments.sorted(by: { $0.key < $1.key }) {
                    let safe = (try? SecretRef(reference))?.safeInlineURI ?? "<invalid reference>"
                    lines += "\n  \(safe)  —  environment \(name)"
                }
                cause = lines
            }
            runAICommandUnprotected(
                command, executablePath: executablePath, commandLine: executionCommandLine,
                credentialGuard: credentialGuard, cause: cause
            )
        }
    }

    // Output redaction snapshots csecd's active values, which now include the
    // ones just injected. Order matters: inject (register), then begin the scan.
    let session: AgentOutputRedactionSession
    do {
        session = try withCsecdReconnect {
            try client.beginOutputRedaction(
                destination: .aiTool,
                streams: OutputRedactionStream.allCases,
                // The AI tool is the output recipient here, not the operator's own
                // terminal. Keep opaque `[csec:secret-N]` labels so a redaction
                // does not hand the AI the reference metadata a `csec exec` user
                // would see.
                labelStyle: .opaque
            )
        }
    } catch {
        // Never block. Run without csec — with our ORIGINAL environment, so any
        // values just injected above are discarded (the child sees unresolved
        // references) and nothing is left unredacted.
        runAICommandUnprotected(
            command, executablePath: executablePath, commandLine: executionCommandLine,
            credentialGuard: credentialGuard,
            cause: aiDegradeCause(error)
        )
    }
    defer { session.close() }

    if session.skippedShortValueCount > 0 {
        FileHandle.standardError.write(Data(
            ("csec \(command): warning: \(session.skippedShortValueCount) active value(s) shorter than "
             + "\(OutputRedactionCatalog.minimumAutomaticSecretBytes) bytes are not matched\n").utf8
        ))
    }

    var childEnvironment = secretFree
        ? AICommandSecretFree.environmentWithoutReferences(ProcessInfo.processInfo.environment, plan: plan)
        : plan.removingReferenceNames(from: ProcessInfo.processInfo.environment)
    for (name, value) in injected { childEnvironment[name] = value }
    if !injected.isEmpty { warnEnvironmentInjection(command) }

    // The scanner lives in csecd and masks every value csecd has released,
    // not only this command's. When csecd stops mid-command (an update
    // restarts it), a command csecd released nothing to runs on with the rest
    // of its output withheld: nothing unscanned is forwarded, and stopping a
    // command that holds no delivered value would protect nothing. A command
    // holding delivered values, and any other scanner failure, is stopped.
    let releasedToThisCommand = !injected.isEmpty
    let scannerLoss = ScannerLossHandling { error in
        guard !releasedToThisCommand,
              case AgentClient.ClientError.connectionLost = error,
              session.agentHasExited() else { return .terminate }
        // Report the one-way transition before waiting for the child's exit.
        // Only wrapper-authored text crosses stderr after the scanner is lost.
        FileHandle.standardError.write(Data(
            ("\ncsec \(command): csecd stopped while this command ran (an update restarts it); "
             + "output is now being withheld unscanned. Waiting for the command to finish; "
             + "its own exit status will be reported.\n").utf8
        ))
        return .withholdRemaining
    }
    do {
        let status = try ProcessSupervisor.run(
            executablePath: executablePath,
            commandLine: executionCommandLine,
            environment: childEnvironment,
            agentSession: session,
            mode: .always,
            scannerLoss: scannerLoss,
            onTick: approvalNoticePoller(client: client, session: session, command: command)
        )
        if let notice = session.close() { notices.print(notice) }
        if let withheld = scannerLoss.withheldBytes {
            FileHandle.standardError.write(Data(
                ("\ncsec \(command): csecd stopped while this command ran (an update restarts it); "
                 + "the command's output after that was withheld unscanned (\(withheld) bytes). "
                 + "The exit status is the command's own.\n").utf8
            ))
        }
        credentialGuard.cleanup()
        cs_terminate_like_wait_status(status)
    } catch {
        credentialGuard.cleanup()
        if let notice = session.close() { notices.print(notice) }
        let message: String
        if case let ProcessSupervisorError.redactionFailed(cause) = error,
           case AgentClient.ClientError.connectionLost = cause,
           session.agentHasExited(within: 0) {
            message = releasedToThisCommand
                ? "csecd stopped while this command held values it had delivered; command terminated"
                : "csecd stopped while this command ran; command terminated"
        } else {
            message = "trusted output scanning failed; command terminated (\(error))"
        }
        FileHandle.standardError.write(Data("csec \(command): \(message)\n".utf8))
        exit(1)
    }
}

/// Prints csecd's notice that a request waits on a human (`HumanWait`), one
/// line on stderr. csecd sends it only for a coding agent's request, whose
/// session reads stderr; a terminal's request hears nothing new.
func approvalWaitNotice(_ command: String) -> (String) -> Void {
    { message in
        FileHandle.standardError.write(Data("csec \(command): \(message)\n".utf8))
    }
}

/// Asks csecd, about once a second while the command runs, whether a request
/// started under this `csec ai` waits on a human and could not say so itself
/// (an `ssh` signing for `git push`, a bridge client), and prints each one
/// once. It asks on a connection of its own (`ApprovalNoticeChannel`), so a
/// csecd that cannot answer (an older build, one that went away or stalled)
/// only stops the notices; the command's output scanner is untouched.
func approvalNoticePoller(
    client: AgentClient, session: AgentOutputRedactionSession, command: String
) -> () -> Void {
    var channel: ApprovalNoticeChannel?
    var lastAsked: TimeInterval?
    var stopped = false
    let print = approvalWaitNotice(command)
    return {
        guard !stopped else { return }
        let now = ProcessInfo.processInfo.systemUptime
        if let lastAsked, now - lastAsked < 1 { return }
        lastAsked = now
        do {
            if channel == nil { channel = try client.approvalNoticeChannel(for: session) }
            try channel?.take().forEach(print)
        } catch {
            stopped = true
            channel = nil
        }
    }
}

/// csecd's setup notices for one `csec ai` (`Response.delegationNotice`),
/// each printed once on stderr, where the agent session reads it: delegated
/// approvals wait on `csec setup auto-mode`, so its approvals go to Touch ID.
final class AISetupNotices {
    private let command: String
    private var printed: Set<String> = []

    init(command: String) { self.command = command }

    func print(_ notice: String) {
        guard printed.insert(notice).inserted else { return }
        FileHandle.standardError.write(Data("csec \(command): warning: \(notice)\n".utf8))
    }
}

/// Retry a csecd call across a brief bounded window so a transient daemon restart
/// (e.g. mid `csec install`, which the daemon log confirmed can make even `ls`
/// fail) does not brick an AI command that would otherwise succeed. Only a
/// connect failure is retried; a real protocol/consent error returns at once.
/// Permission denials have their own error case and are never retried: restarting
/// csecd cannot repair a sandbox's denied Unix-socket access.
/// Mirrors `SetupCommand`'s `waitForAgentReachable` bounded 250 ms poll.
func withCsecdReconnect<T>(_ body: () throws -> T) throws -> T {
    let deadline = Date().addingTimeInterval(2)
    while true {
        do {
            return try body()
        } catch AgentClient.ClientError.connectFailed(let path) {
            guard Date() < deadline else {
                throw AgentClient.ClientError.connectFailed(path)
            }
            usleep(250_000)
        }
    }
}

/// A value-free, actionable cause line for why `csec ai` is degrading to an
/// unprotected run. `csec ai` NEVER refuses to run the command — a hard gate on
/// the shell hook bricks every command and trains the user to work around csec —
/// so instead of failing closed it warns with this cause plus fix guidance and
/// runs the command with secret references left unresolved (see
/// `runAICommandUnprotected`). Never reflects attacker-controlled code-signing
/// metadata; only a fixed, human-authored string per error class.
func aiDegradeCause(_ error: Error) -> String {
    switch error {
    case AgentClient.ClientError.connectPermissionDenied(let path):
        return CodexSandboxConfiguration.recoveryMessage(socketPath: path)
    case AgentClient.ClientError.connectFailed:
        return "the Convenient Security agent (csecd) is not reachable. Fix: run `csec doctor` "
            + "to repair the service (or `csec status` to check it)."
    case AgentClient.ClientError.untrustedServer:
        return "the csec agent's code identity could not be verified — csecd may be running a "
            + "stale build after an update. Fix: run `csec doctor` to restart it."
    case AgentClient.ClientError.transportFailed, AgentClient.ClientError.connectionLost:
        return "the connection to csecd failed mid-request. Fix: run `csec doctor`."
    case AgentClient.ClientError.daemonUnresponsive(let seconds):
        return "the Convenient Security agent (csecd) stopped responding for \(seconds) seconds "
            + "and may be wedged — it accepted the connection and then went silent. "
            + "Fix: run `csec doctor` to restart it."
    default:
        return "protected execution could not be initialized (\(error.localizedDescription))."
    }
}

/// A hook or MCP command line Claude Code handed its shell prefix: replace
/// this process with `/bin/sh -c <command>`, keeping its pid, stdio and
/// environment, which is how it ran before csec became the prefix. Nothing
/// is resolved or scanned; csec never wrapped these.
func execUnwrappedShellPrefixCommand(_ commandLine: String) -> Never {
    let argv = ["sh", "-c", commandLine]
    var pointers: [UnsafeMutablePointer<CChar>?] = argv.map { strdup($0) } + [nil]
    execv("/bin/sh", &pointers)
    let failure = errno
    csecError("ai", "could not run the command with /bin/sh: \(String(cString: strerror(failure)))")
    exit(126)
}

/// `csec ai`'s failure mode: warn on stderr (naming the cause and the fix) and
/// run the command anyway, WITHOUT csec. The command inherits our own, unmodified
/// environment, so any `op://…`/`csec://…` references stay unresolved — nothing is
/// resolved on this path. The direct op guard remains active in the child.
/// `.never` mode gives a byte-exact passthrough (no matcher) while still relaying
/// the PTY, signals, and exit status exactly as the protected path does.
func runAICommandUnprotected(
    _ command: String,
    executablePath: String,
    commandLine: [String],
    credentialGuard: AICommandCredentialGuard,
    cause: String
) -> Never {
    FileHandle.standardError.write(Data(
        ("csec \(command): warning: \(cause)\n"
            + "  Running the command WITHOUT csec: op:// / csec:// references are left "
            + "unresolved, so no secrets are injected or revealed.\n").utf8
    ))
    do {
        let status = try ProcessSupervisor.run(
            executablePath: executablePath,
            commandLine: commandLine,
            environment: ProcessInfo.processInfo.environment,
            mode: .never
        )
        credentialGuard.cleanup()
        cs_terminate_like_wait_status(status)
    } catch {
        credentialGuard.cleanup()
        csecError(command, "could not run the command: \(error)")
        exit(126)
    }
}

/// A CLI notice independent of output masking and cached approval state. Keep
/// its content fixed: values, references and caller-controlled metadata never
/// belong in this warning. Sidecar launches use it for their environment values
/// too, even though the root helper performs that injection.
func warnEnvironmentInjection(_ command: String) {
    FileHandle.standardError.write(Data((
        "csec \(command): warning: secrets in the child's initial environment can be read by "
        + "other processes running as your user. Output masking does not hide the environment.\n"
        + "csec \(command): prefer credential adapters (csec creds aws / csec creds git), "
        + "csec exec-fd or csec exec-file when the tool supports them.\n"
    ).utf8))
}

/// Shared inject core for `csec exec` and `csec ai`: resolve a plan's references
/// under one delivery plan, then fold the resolved values into a fresh child
/// environment (base empty — the caller merges onto the ambient environment).
/// The two callers differ only in the delivery plan they present and their
/// output posture; the resolution and rebuild are identical. The raw `values`
/// are returned as well so `csec exec` can build its client-side redaction
/// catalog; `csec ai` ignores them (its scan runs in csecd's registry).
func resolveAndInject(
    client: AgentClient,
    plan: ExecPlanner.Plan,
    deliveryPlan: DeliveryPlan,
    reason: String,
    ttlSeconds: Int?,
    commandLine: [String],
    delegationNotice: ((String) -> Void)? = nil,
    waitingNotice: ((String) -> Void)? = nil
) throws -> (injected: [String: String], values: [String: Data]) {
    let values = try client.access(
        references: plan.references,
        reason: reason,
        ttlSeconds: ttlSeconds,
        deliveryPlan: deliveryPlan,
        commandLine: commandLine,
        delegationNotice: delegationNotice,
        waitingNotice: waitingNotice
    )
    let injected = try ExecPlanner.resolvedEnvironment(base: [:], plan: plan, values: values)
    return (injected, values)
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
    // document editor; --remove takes references and nothing else.
    if arguments.contains("--remove") {
        guard arguments.filter({ $0 == "--remove" }).count == 1 else { usage("edit") }
        runEditRemove(arguments.filter { $0 != "--remove" })
    }
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
    // nil ⇒ a process-lifetime grant (the default); `--for` sets a bounded one.
    var ttlSeconds: Int? = nil
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
    if let ttlSeconds, ttlSeconds <= 0 {
        csecError("get", "--for must be a positive number of seconds")
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
            deliveryPlan: plan,
            waitingNotice: approvalWaitNotice("get")
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

/// `warnsAboutEnvironment` is false only for a wrapper whose environment
/// delivery is its documented design and is stated once at setup (`csec fly`):
/// repeating the warning on every run would teach users to skip csec's output.
func runExec(_ arguments: [String], warnsAboutEnvironment: Bool = true) -> Never {
    var reason: String?
    // nil ⇒ a process-lifetime grant (the default); `--for` sets a bounded one.
    var ttlSeconds: Int? = nil
    var explicit: [(name: String, reference: String)] = []
    var withFiles: [String] = []
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
        case "--with-file":
            index += 1
            guard index < arguments.count, !arguments[index].isEmpty else { usage("exec") }
            // `~` follows `$HOME`, as `csec protect` resolves home; NSString's
            // expansion reads the account database instead.
            let given = arguments[index]
            let expanded = given == "~" || given.hasPrefix("~/")
                ? canonicalHomeDirectory() + String(given.dropFirst()) : given
            withFiles.append((expanded as NSString).isAbsolutePath ? expanded
                : (FileManager.default.currentDirectoryPath as NSString)
                    .appendingPathComponent(expanded))
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
    if let ttlSeconds, ttlSeconds <= 0 {
        csecError("exec", "--for must be a positive number of seconds")
        exit(2)
    }

    // A project holding `*.csec` sidecars needs its protected files back at their
    // original paths for the wrapped tree, which only the rootd launch can do.
    // Route there when any are present; overflow past the per-launch bound is a
    // hard error, never a silent fallback to environment injection. `csec exec`'s
    // ordinary environment injection (`--set` and env-scanned references) is folded
    // into the same launch as value-in-environment bindings, so one approval
    // delivers both files and values.
    // A home token file (`~/.vault-token`) is restored for the command that reads
    // it from any directory, beside the project's own sidecars.
    do {
        let currentDirectory = FileManager.default.currentDirectoryPath
        let scan = try ProtectedSidecarScanner.scan(projectDirectory: currentDirectory)
        let home = canonicalHomeDirectory()
        let files = try HomeTokenFileRestore.plan(
            command: commandLine[0],
            withFiles: withFiles,
            homeDirectory: home,
            currentDirectory: canonicalPath(currentDirectory) ?? currentDirectory,
            environment: ProcessInfo.processInfo.environment,
            projectFiles: scan.discoveries,
            projectRootBelowHome: { path in
                let root = bulkProjectRoot(for: path, homeDirectory: home)
                return root == home ? nil : root
            }
        )
        // A file that looks like a sidecar but cannot be parsed is warned about, not
        // silently skipped — otherwise a broken `*.csec` looks identical to the
        // secret simply not being there.
        for issue in scan.issues + files.issues {
            warnProtectedSidecarIssue(path: issue.sidecarRelativePath, reason: issue.reason)
        }
        if !files.projectFiles.isEmpty || !files.homeFiles.isEmpty {
            let environmentPlan: ExecPlanner.Plan
            do {
                let knownSchemes = Set(try makeAgentClient().schemes())
                environmentPlan = try ExecPlanner.plan(
                    environment: ProcessInfo.processInfo.environment,
                    explicit: explicit,
                    knownSchemes: knownSchemes
                )
            } catch {
                csecError("exec", "\(error)")
                exit(1)
            }
            runSidecarExec(
                commandLine: commandLine,
                discoveries: files.projectFiles,
                homeFiles: files.homeFiles,
                homeDirectory: home,
                environmentPlan: environmentPlan,
                reason: reason,
                ttlSeconds: ttlSeconds,
                outputGuard: outputGuard,
                warnsAboutEnvironment: warnsAboutEnvironment
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
            let resolved = try resolveAndInject(
                client: client,
                plan: plan,
                deliveryPlan: deliveryPlan,
                reason: operation,
                ttlSeconds: ttlSeconds,
                commandLine: commandLine,
                waitingNotice: approvalWaitNotice("exec")
            )
            resolvedValues = resolved.values
            resolvedExecutablePath = executable.canonicalPath
            injected = resolved.injected
        } catch {
            csecError("exec", "\(error.localizedDescription)")
            // A failed resolution names the reference; say which environment
            // name carries each one so the user knows what to fix or unset.
            if case let AgentClient.ClientError.protocolFailure(code, _) = error,
               code == .resolutionFailed || code == .referenceNotFound {
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

    if warnsAboutEnvironment, !injected.isEmpty { warnEnvironmentInjection("exec") }

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
        var childEnvironment = plan.removingReferenceNames(from: ProcessInfo.processInfo.environment)
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
    for name in plan.referenceNames { unsetenv(name) }
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
          request.isWellFormed else {
        writeBridgeFailure(.invalidRequest, "invalid bridge request", status: 2)
    }

    let parentPID = getppid()
    guard parentPID > 1,
          let parentStartTime = ProcessAncestry.startTime(of: parentPID),
          let parentPath = ProcessAncestry.executablePath(of: parentPID),
          let inspectedExecutable = try? ExecutableInspection.plannedExecutable(
            command: parentPath, mutableInterpreter: true
          ) else {
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

    // A request without a TTL asks for no clock: the grant lives as long as the
    // root the human approves, exactly as for `csec exec`.
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

/// `csec uninstall`, in order: revert what `csec setup` changed in the Claude
/// settings; have csecd delete its protected Keychain items, decision log and
/// sealed host-audit baseline under one Touch ID (after which csecd writes
/// nothing); then unregister the LaunchAgent, whose SIGTERM finds nothing left
/// to write. A refused Touch ID stops before anything is deleted, and puts
/// back what step one reverted, so a refused uninstall changes nothing.
///
/// `--all` goes on to remove everything else csec installed: after the Touch
/// ID it takes csec's hook out of Claude Code's and Codex's user settings
/// (Claude Code's fails closed, so once the app is gone a hook left behind
/// would block every Bash command), unregisters the agent, and then runs the
/// package's uninstaller through sudo for the system-wide parts. Its checks
/// run first, so a Mac that cannot finish is told before anything changes.
func runUninstall(_ arguments: [String]) -> Never {
    let all: Bool
    switch arguments {
    case []: all = false
    case ["--all"]: all = true
    default: usage("uninstall")
    }
    if all {
        guard isatty(STDIN_FILENO) == 1, isatty(STDERR_FILENO) == 1 else {
            csecError("uninstall", "csec uninstall --all asks for sudo; run it in a terminal.")
            exit(2)
        }
        if let problem = CompleteUninstall.scriptProblem() {
            csecError("uninstall", "the package's uninstaller cannot be run (\(ReviewDisplay.sanitized(problem))); "
                + "nothing was changed.")
            exit(1)
        }
        print("csec: removing csec from this Mac. Your secrets stay where they are. "
            + "Other accounts that use csec should run csec uninstall first, while the app is still here.")
    }

    // The prefix script goes with the bundle; a prefix left naming it would
    // stop every Claude Code Bash command. Without it the hook rewrites
    // again, so a refused uninstall leaves every command wrapped.
    switch editClaudeShellPrefix(remove: true) {
    case let .changed(path, _):
        print("csec: removed csec's shell prefix from \(ReviewDisplay.sanitized(path))")
    case .unchanged, .notBundled:
        break
    case let .failed(reason):
        FileHandle.standardError.write(Data((
            "csec uninstall: could not remove env.\(ClaudeDelegationGateLists.shellPrefixName) from Claude Code's "
            + "settings (\(reason)); remove it by hand, or Claude Code's Bash commands will fail once csec is gone.\n"
        ).utf8))
    }
    let settingsRevert = revertClaudeSettingsBeforeUninstall()

    do {
        let result = try makeAgentClient().uninstallCleanup()
        if result.isComplete {
            print("csec: csecd deleted its \(CsecdUninstaller.deletedSummary).")
            if !all {
                print("csec: left in place, and used again by a reinstall: \(CsecdUninstaller.keptSummary).")
            }
        } else {
            FileHandle.standardError.write(Data(
                "csec uninstall: csecd could not delete everything; these remain:\n".utf8
            ))
            if !result.logDirectoryRemoved {
                FileHandle.standardError.write(Data("  the decision log directory\n".utf8))
            }
            for item in result.remainingItems + result.remainingFiles {
                FileHandle.standardError.write(Data("  \(ReviewDisplay.sanitized(item))\n".utf8))
            }
        }
    } catch AgentClient.ClientError.denied {
        // Nothing is uninstalled, so what step one reverted goes back.
        let reapply = settingsRevert.map(ClaudeDelegationSetup.reapplyReverted)
        if let reapply, reapply.result == .restored {
            print("csec: put back csec's auto-mode settings in \(ReviewDisplay.sanitized(reapply.settingsPath))")
        }
        csecError("uninstall", ClaudeDelegationSetup.refusedUninstallMessage(reapply))
        exit(1)
    } catch {
        // Only csecd can delete its items. Unregistering still stops it, and a
        // reinstall picks the items and the log back up.
        FileHandle.standardError.write(Data((
            "csec uninstall: csecd could not clean up "
            + "(\(ReviewDisplay.sanitized(error.localizedDescription))); "
            + "its protected Keychain items, encrypted decision log and sealed host-audit baseline "
            + "remain. Only csecd can remove them, and a reinstall reuses them.\n"
        ).utf8))
    }

    // After the Touch ID, so a refusal above leaves the hooks working.
    let hooksRemoved = all ? removeCodingAgentHooksForUninstall() : true

    do {
        try LaunchAgentService.uninstall()
        print("csec: agent unregistered.")
    } catch {
        csecError("uninstall", "\(error)")
        if all {
            FileHandle.standardError.write(Data(
                "csec uninstall: the app and system parts were left in place; run csec uninstall --all again.\n".utf8
            ))
        }
        exit(1)
    }
    guard all else {
        print("csec: the app, root helper, sudo review and Codex hook remain for every account; "
            + "csec uninstall --all removes them.")
        exit(0)
    }
    // csecd has stopped, so it cannot write the cache again.
    do {
        if try CompleteUninstall.removeUpdateCache() {
            print("csec: removed csec's update-check cache.")
        }
    } catch {
        FileHandle.standardError.write(Data((
            "csec uninstall: left csec's update-check cache in place "
            + "(\(ReviewDisplay.sanitized(error.localizedDescription))); it holds no secrets.\n"
        ).utf8))
    }
    guard hooksRemoved else {
        // The app must outlive a hook that would otherwise block every command.
        csecError("uninstall", "the app and system parts were left in place so the hooks above keep working; "
            + "remove csec's hook from those files, then run csec uninstall --all again.")
        exit(1)
    }
    exit(runSystemUninstaller())
}

/// `--all`: take csec's hook out of each coding agent's user-level hook file,
/// keeping every other hook and setting. True when none is left behind.
func removeCodingAgentHooksForUninstall() -> Bool {
    let environment = ProcessInfo.processInfo.environment
    let detections: [CodingAgentDetection]
    do {
        detections = try CodingAgentSetup.detect(
            homeDirectory: FileManager.default.homeDirectoryForCurrentUser.path,
            pathEnvironment: environment["PATH"],
            claudeConfigDirectory: environment["CLAUDE_CONFIG_DIR"])
    } catch {
        csecError("uninstall", "could not find Claude Code's and Codex's settings "
            + "(\(ReviewDisplay.sanitized(error.localizedDescription))).")
        return false
    }
    var removedAll = true
    for detection in detections {
        let path = ReviewDisplay.sanitized(detection.configurationPath)
        do {
            let plan = try CodingAgentSetup.planUserHookRemoval(detection: detection)
            guard plan.action != .unchanged else { continue }
            try CodingAgentSetup.apply(plan)
            print("csec: removed csec's \(detection.client.rawValue) hook from \(path)")
        } catch {
            removedAll = false
            FileHandle.standardError.write(Data((
                "csec uninstall: could not remove csec's \(detection.client.rawValue) hook from \(path) "
                + "(\(ReviewDisplay.sanitized(error.localizedDescription))).\n"
            ).utf8))
        }
    }
    return removedAll
}

/// `--all`'s system part: sudo runs the package's uninstaller, which removes
/// the sudo review (guarded), the managed Codex hook, the root helper, the
/// app, the bridge and the package receipt for every account. csecd is gone
/// by now, so the sudo review shows its own panel without the phone. Returns
/// the exit status for `csec uninstall --all`.
func runSystemUninstaller() -> Int32 {
    print("csec: sudo now runs the package's uninstaller for the parts every account shares.")
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
    process.arguments = ["--", CompleteUninstall.scriptPath]
    do {
        try process.run()
    } catch {
        csecError("uninstall", "could not start sudo (\(ReviewDisplay.sanitized(error.localizedDescription))).")
        return 1
    }
    process.waitUntilExit()
    guard process.terminationReason == .exit, process.terminationStatus == 0 else {
        FileHandle.standardError.write(Data((
            "csec uninstall: the package's uninstaller did not finish; what it printed above says what "
            + "stayed. This account's part is done; to finish, run:\n"
            + "  sudo '\(CompleteUninstall.scriptPath)'\n"
        ).utf8))
        return 1
    }
    print("csec: csec is removed from this Mac. Left in place:")
    for line in CompleteUninstall.keptAfterCompleteUninstall {
        print("  - \(line)")
    }
    return 0
}

/// Step one of `csec uninstall`: put back the Claude Code settings `csec setup`
/// changed (the delegation-aware auto-mode text and `classifyAllShell` when
/// csec added it) with the one revert disabling delegation uses,
/// `ClaudeDelegationSetup.revertRecordedSettings`, on the settings file csecd
/// recorded when delegation was enabled, whatever `CLAUDE_CONFIG_DIR` says
/// now. It must run before the cleanup, which deletes that record. Without it
/// (csecd unreachable, or delegation never enabled) the current user settings
/// file is reverted and `classifyAllShell` stays: Claude Code then classifies
/// more, never less. Nothing here stops the uninstall. Returns the revert
/// when it was written, so a refused Touch ID can put it back.
func revertClaudeSettingsBeforeUninstall() -> ClaudeDelegationSetup.SettingsRevert? {
    let context = ClaudeSettingsContext.current(csecExecutablePath: currentExecutablePath())
    let outcome = try? makeAgentClient().configureDelegation(.status(
        claudeConfigDirectory: context.scope?.claudeConfigDirectory,
        projectDirectory: context.workingDirectory
    ))
    // Nil when csecd could not say.
    var status: DelegationStatus?
    if case let .configured(reported, _)? = outcome { status = reported }
    // With no record, the file to revert is the one CLAUDE_CONFIG_DIR names,
    // which an empty or relative value does not.
    if status?.claudeSettingsPath == nil, context.scope == nil {
        FileHandle.standardError.write(Data((
            "csec uninstall: CLAUDE_CONFIG_DIR is not an absolute path, so Claude Code's settings were "
            + "left as they are; run csec uninstall again with it unset or absolute to revert them.\n"
        ).utf8))
        return nil
    }
    let revert = ClaudeDelegationSetup.revertRecordedSettings(
        status: status, gate: makeClaudeSettingsGate(), scope: context.scope ?? context.anyScope)
    switch revert.result {
    case .nothingToChange:
        break
    case .reverted:
        print("csec: reverted csec's auto-mode settings in \(ReviewDisplay.sanitized(revert.settingsPath))")
    case let .notWritten(reason):
        // Once the cleanup runs, csecd's record of what csec changed is gone,
        // so a revert that cannot be written says exactly what to undo by hand.
        FileHandle.standardError.write(Data((
            "csec uninstall: Claude Code's settings were left as they are "
            + "(\(ReviewDisplay.sanitized(reason))); \(revert.manualInstructions ?? "").\n"
        ).utf8))
        return nil
    }
    if status == nil, revert.classifyAllShell == .leave {
        FileHandle.standardError.write(Data((
            "csec uninstall: csecd could not say whether csec setup added autoMode.classifyAllShell, "
            + "so it stays in \(ReviewDisplay.sanitized(revert.settingsPath)).\n"
        ).utf8))
    }
    return revert.result == .reverted ? revert : nil
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
            let json = arguments == ["status", "--json"]
            guard arguments.count == 1 || json else { usage("remote") }
            // A build without the relay, or a pairing that must be redone,
            // fails the command; a temporary iCloud or Keychain condition does
            // not. `--json` exits the same way.
            let status = try client.remoteApprovalStatus()
            if json {
                print(try RemoteApprovalStatusReport.json(status))
                exit(RemoteApprovalStatusReport.summary(status).succeeded ? 0 : 1)
            }
            let succeeded = printRemoteApprovalStatus(status)
            exit(succeeded ? 0 : 1)
        case "enable":
            guard arguments.count == 2 else { usage("remote") }
            let result = try client.enableRemoteApproval(
                phonePairingCode: arguments[1]
            )
            for line in RemoteApprovalStatusReport.enableInstructions(
                macPairingCode: result.macPairingCode,
                macPublicKeyX963: result.macPairing.macPublicKeyX963,
                pairingOfferPublished: result.pairingOfferPublished
            ) {
                print(line)
            }
            waitForPhoneConfirmation(client: client, initial: result.status)
        case "disable":
            guard arguments.count == 1 else { usage("remote") }
            // Removing the pairing succeeded even where this build could not
            // use one anyway; the status lines still say so.
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

/// After `csec remote enable`: wait for the phone to import the Mac code and
/// publish its signed confirmation. There is no deadline — the person may be
/// fetching the phone — and Ctrl-C only stops the waiting: the pairing stays,
/// and `csec remote status` says when the phone has confirmed it.
private func waitForPhoneConfirmation(
    client: AgentClient,
    initial: RemoteApprovalConfigurationStatus
) {
    var status = initial
    if status.state == .enabled, status.phoneConfirmed == false {
        print("Waiting for the iPhone to confirm the pairing (Ctrl-C stops waiting; the pairing stays)…")
        while status.state == .enabled, status.phoneConfirmed == false {
            Thread.sleep(forTimeInterval: 2)
            guard let next = try? client.remoteApprovalStatus() else { continue }
            status = next
        }
    }
    printRemoteApprovalStatus(status)
}

@discardableResult
private func printRemoteApprovalStatus(_ status: RemoteApprovalConfigurationStatus) -> Bool {
    let summary = RemoteApprovalStatusReport.summary(status)
    for line in summary.lines { print(line) }
    return summary.succeeded
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
