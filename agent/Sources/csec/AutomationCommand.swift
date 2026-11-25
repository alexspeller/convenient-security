import ConvenientSecurity
import CSecuritySupport
import Foundation
import Security

/// A restarted csecd answered the launcher's `resume_run` without the run's
/// live lease, so it would not mask the values the command already holds.
private struct AutomationLeaseNotRestored: Error {}

/// An update replaced this launcher's binary while it ran: csecd admits only a
/// peer whose code still matches its file, so it will never scan for this
/// launcher again. Stopping the command lets launchd or cron start it under
/// the new launcher, which gets a fresh lease with no panel.
private struct AutomationLauncherReplaced: Error {}

/// Whether this process's code no longer matches the file it was loaded from.
private func launcherImageReplaced() -> Bool {
    var code: SecCode?
    guard SecCodeCopySelf(SecCSFlags(rawValue: 0), &code) == errSecSuccess, let code else {
        return false
    }
    let status = SecCodeCheckValidity(code, SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)), nil)
    return status != errSecSuccess
}

private enum AutomationCLIError: Error, CustomStringConvertible {
    case invalidArguments
    case invalidNumber(String)
    case invalidWorkingDirectory

    var description: String {
        switch self {
        case .invalidArguments:
            return "invalid automation arguments"
        case let .invalidNumber(option):
            return "\(option) must be a whole number in its supported range"
        case .invalidWorkingDirectory:
            return "the automation working directory does not exist"
        }
    }
}

func runAutomation(_ arguments: [String]) -> Never {
    guard let action = arguments.first else { usage("automation") }
    do {
        switch action {
        case "add":
            try addAutomation(Array(arguments.dropFirst()))
        case "list":
            guard arguments.count == 1 else { throw AutomationCLIError.invalidArguments }
            try listAutomation()
        case "run":
            guard arguments.count == 2 else { throw AutomationCLIError.invalidArguments }
            try runAutomationJob(name: arguments[1])
        case "revoke":
            guard arguments.count == 2 else { throw AutomationCLIError.invalidArguments }
            try revokeAutomation(name: arguments[1])
        default:
            throw AutomationCLIError.invalidArguments
        }
        exit(0)
    } catch AutomationCLIError.invalidArguments {
        usage("automation")
    } catch AgentClient.ClientError.denied {
        FileHandle.standardError.write(Data("csec automation: consent denied\n".utf8))
        exit(1)
    } catch AgentClient.ClientError.protocolFailure(let code, let message) {
        FileHandle.standardError.write(Data(
            "csec automation: \(code.rawValue): \(message)\n".utf8
        ))
        exit(1)
    } catch ProcessSupervisorError.redactionFailed(let cause) where cause is AutomationLeaseNotRestored {
        FileHandle.standardError.write(Data(
            "csec automation: csecd restarted and holds no live lease for this run; command terminated\n".utf8
        ))
        exit(1)
    } catch ProcessSupervisorError.redactionFailed(let cause) where cause is AutomationLauncherReplaced {
        FileHandle.standardError.write(Data(
            ("csec automation: csec was updated while this job ran, and csecd does not accept the "
             + "replaced launcher; command stopped so it can start again under the new csec\n").utf8
        ))
        exit(1)
    } catch ProcessSupervisorError.timedOut {
        FileHandle.standardError.write(Data(
            "csec automation: command exceeded its registered maximum runtime\n".utf8
        ))
        exit(124)
    } catch {
        FileHandle.standardError.write(Data("csec automation: \(error)\n".utf8))
        exit(1)
    }
}

private func addAutomation(_ arguments: [String]) throws {
    guard let name = arguments.first, AutomationJob.validName(name) else {
        throw AutomationCLIError.invalidArguments
    }
    var references: [String] = []
    var reason = "Unattended automation job \(name)"
    var minimumIntervalSeconds = 0
    // Bounded by default (a hung unattended run still needs a backstop with no
    // human present); `--max-runtime none` enrolls a process-lifetime daemon.
    var maximumRuntimeSeconds: Int? = 12 * 60 * 60
    var workingDirectory = FileManager.default.currentDirectoryPath
    var commandLine: [String] = []
    var index = 1

    parse: while index < arguments.count {
        switch arguments[index] {
        case "--ref":
            index += 1
            guard index < arguments.count else { throw AutomationCLIError.invalidArguments }
            references.append(arguments[index])
        case "--reason":
            index += 1
            guard index < arguments.count else { throw AutomationCLIError.invalidArguments }
            reason = arguments[index]
        case "--every":
            index += 1
            guard index < arguments.count,
                  let value = Int(arguments[index]),
                  value >= 0,
                  value <= 30 * 24 * 60 * 60 else {
                throw AutomationCLIError.invalidNumber("--every")
            }
            minimumIntervalSeconds = value
        case "--max-runtime":
            index += 1
            guard index < arguments.count else {
                throw AutomationCLIError.invalidNumber("--max-runtime")
            }
            // `none` enrolls a process-lifetime daemon: no runtime kill, secrets
            // stay available for as long as the daemon process runs.
            if arguments[index] == "none" {
                maximumRuntimeSeconds = nil
            } else {
                guard let value = Int(arguments[index]),
                      value > 0,
                      value <= 24 * 60 * 60 else {
                    throw AutomationCLIError.invalidNumber("--max-runtime")
                }
                maximumRuntimeSeconds = value
            }
        case "--cwd":
            index += 1
            guard index < arguments.count else { throw AutomationCLIError.invalidArguments }
            workingDirectory = arguments[index]
        case "--":
            commandLine = Array(arguments[(index + 1)...])
            break parse
        default:
            throw AutomationCLIError.invalidArguments
        }
        index += 1
    }

    guard !references.isEmpty,
          references.count <= 64,
          !commandLine.isEmpty,
          commandLine.count <= AutomationCommand.maximumArgumentCount else {
        throw AutomationCLIError.invalidArguments
    }

    let canonicalWorkingDirectory = canonicalDirectory(workingDirectory)
    guard let canonicalWorkingDirectory else {
        throw AutomationCLIError.invalidWorkingDirectory
    }
    let inspected = try ExecutableInspection.plannedExecutable(
        command: commandLine[0],
        environment: ProcessInfo.processInfo.environment,
        workingDirectory: canonicalWorkingDirectory,
        mutableInterpreter: true
    )
    let launcher = PlannedExecutable(
        canonicalPath: inspected.canonicalPath,
        signingIdentifier: inspected.signingIdentifier,
        teamIdentifier: inspected.teamIdentifier,
        cdHash: inspected.cdHash,
        assurance: .unverified
    )
    let consumer: PlannedExecutable?
    if let path = ExecutableInspection.pythonFrameworkConsumerPath(forLauncherPath: launcher.canonicalPath) {
        consumer = try ExecutableInspection.plannedExecutable(command: path, mutableInterpreter: true)
    } else {
        consumer = nil
    }
    // Keep the invoked path for venv discovery. Non-framework Python reads
    // argv[0]; framework launchers also need this path passed to exec itself.
    commandLine[0] = try ExecutableInspection.invokedPath(
        command: commandLine[0],
        environment: ProcessInfo.processInfo.environment,
        workingDirectory: canonicalWorkingDirectory
    )
    let command = AutomationCommand(
        executable: consumer ?? launcher,
        commandLine: commandLine,
        workingDirectory: canonicalWorkingDirectory,
        commandDigest: try ExecutableInspection.commandDigest(commandLine),
        launcherExecutable: consumer == nil ? nil : launcher
    )
    let enrollment = AutomationEnrollment(
        name: name,
        reason: reason,
        references: references,
        command: command,
        minimumIntervalSeconds: minimumIntervalSeconds,
        maximumRuntimeSeconds: maximumRuntimeSeconds
    )
    let job = try makeAgentClient().enrollAutomation(enrollment)
    print("csec: enrolled unattended automation job \(job.name) until revoked")
    print("csec: warning: its mutable script, dependencies, inputs, and ordinary environment are trusted with every registered reference")
}

private func listAutomation() throws {
    let jobs = try makeAgentClient().listAutomation()
    if jobs.isEmpty {
        print("csec: no unattended automation jobs are registered")
        return
    }
    let formatter = ISO8601DateFormatter()
    for job in jobs {
        print("\(job.name)")
        print("  command: \(job.command.displayCommand)")
        print("  cwd: \(job.command.workingDirectory)")
        print("  references: \(job.references.joined(separator: ", "))")
        print("  minimum interval: \(job.minimumIntervalSeconds)s")
        let runtime = job.maximumRuntimeSeconds.map { "\($0)s" } ?? "process lifetime (daemon)"
        print("  maximum runtime: \(runtime)")
        print("  authorization: until revoked (updated \(formatter.string(from: job.updatedAt)))")
        print("  trust: mutable interpreted script")
    }
}

private func runAutomationJob(name: String) throws {
    let client = makeAgentClient()
    switch try client.beginAutomationRun(name: name) {
    case let .skipped(nextEligibleAt):
        let formatted = ISO8601DateFormatter().string(from: nextEligibleAt)
        print("csec: automation job \(name) skipped; next eligible at \(formatted)")
    case let .started(run):
        var finished = false
        func finish() {
            guard !finished else { return }
            finished = true
            _ = try? client.finishAutomationRun(runID: run.runID)
        }

        let session: AgentOutputRedactionSession
        do {
            session = try client.beginOutputRedaction(
                destination: .localDevelopment,
                streams: OutputRedactionStream.allCases,
                labelStyle: .reference
            )
        } catch {
            finish()
            throw error
        }

        // csecd keeps this run's lease across a restart (an update restarts
        // it), so the job outlives one: while csecd is away its output is
        // withheld unscanned, and once the restarted csecd confirms it holds
        // the lease, and so knows every value the command may hold, a scanner
        // opened there scans the rest. Any other scanner failure stops it.
        var scanner = session
        let scannerLoss = ScannerLossHandling(
            decide: { error in
                guard case AgentClient.ClientError.connectionLost = error,
                      scanner.agentHasExited() else { return .terminate }
                FileHandle.standardError.write(Data(
                    ("csec automation: csecd went away while \(name) ran; holding its output "
                     + "until csecd is back\n").utf8
                ))
                return .withholdUntilReopened
            },
            scannerGone: { () -> Error? in
                guard scanner.agentHasExited(within: 0) else { return nil }
                return AgentClient.ClientError.connectionLost("csecd exited while the command was quiet")
            },
            reopen: {
                do {
                    try client.resumeAutomationRun(runID: run.runID)
                } catch let error as AgentClient.ClientError {
                    // A csecd that answers and refuses no longer holds this
                    // run's lease, and would not mask what the command holds.
                    if case .protocolFailure = error { return .refused(AutomationLeaseNotRestored()) }
                    return launcherImageReplaced() ? .refused(AutomationLauncherReplaced()) : .unavailable
                } catch {
                    return launcherImageReplaced() ? .refused(AutomationLauncherReplaced()) : .unavailable
                }
                // The lease is confirmed; a scanner csecd can't open yet (it
                // holds its most sessions, say) is tried again, and resuming
                // again only re-registers the same values.
                guard let opened = try? client.beginOutputRedaction(
                    destination: .localDevelopment,
                    streams: OutputRedactionStream.allCases,
                    labelStyle: .reference
                ) else { return .unavailable }
                return .opened(opened)
            },
            reopened: { reopened, withheld in
                scanner.close()
                scanner = reopened
                let withheldNote = withheld == 0
                    ? ""
                    : "; \(withheld) bytes of output, past the 1 MiB per stream it keeps while csecd is away, "
                        + "were withheld unscanned"
                FileHandle.standardError.write(Data(
                    "csec automation: csecd restarted while \(name) ran; scanning resumed\(withheldNote)\n".utf8
                ))
            }
        )

        do {
            // csecd's lease and this cap share the awake-time clock, so they
            // expire together whether or not the Mac sleeps in between.
            let status = try ProcessSupervisor.run(
                executablePath: run.job.command.executionPath,
                commandLine: run.job.command.commandLine,
                environment: AutomationCommand.sanitizedEnvironment(
                    ProcessInfo.processInfo.environment
                ),
                workingDirectory: run.job.command.workingDirectory,
                timeoutSeconds: run.remainingRuntimeSeconds,
                agentSession: session,
                mode: .always,
                scannerLoss: scannerLoss
            )
            scanner.close()
            finish()
            if let withheld = scannerLoss.withheldBytes, withheld > 0 {
                let why = scannerLoss.refusedAfterExit == nil
                    ? "csecd was away when \(name) ended"
                    : "the restarted csecd no longer held \(name)'s run when it ended"
                FileHandle.standardError.write(Data(
                    ("csec automation: \(why); its last \(withheld) bytes "
                     + "of output were withheld unscanned\n").utf8
                ))
            }
            cs_terminate_like_wait_status(status)
        } catch {
            scanner.close()
            finish()
            throw error
        }
    }
}

private func revokeAutomation(name: String) throws {
    let job = try makeAgentClient().revokeAutomation(name: name)
    print("csec: revoked unattended automation job \(job.name)")
}

private func canonicalDirectory(_ rawPath: String) -> String? {
    let expanded = (rawPath as NSString).expandingTildeInPath
    let absolute: String
    if expanded.hasPrefix("/") {
        absolute = expanded
    } else {
        absolute = (FileManager.default.currentDirectoryPath as NSString)
            .appendingPathComponent(expanded)
    }
    let canonical = URL(fileURLWithPath: absolute)
        .standardizedFileURL
        .resolvingSymlinksInPath()
        .path
    var isDirectory = ObjCBool(false)
    guard FileManager.default.fileExists(atPath: canonical, isDirectory: &isDirectory),
          isDirectory.boolValue else { return nil }
    return canonical
}
