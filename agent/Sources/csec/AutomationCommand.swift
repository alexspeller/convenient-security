import ConvenientSecurity
import CSecuritySupport
import Foundation

private enum AutomationCLIError: Error, CustomStringConvertible {
    case invalidArguments
    case invalidNumber(String)
    case invalidWorkingDirectory
    case runAuthorizationExpired

    var description: String {
        switch self {
        case .invalidArguments:
            return "invalid automation arguments"
        case let .invalidNumber(option):
            return "\(option) must be a whole number in its supported range"
        case .invalidWorkingDirectory:
            return "the automation working directory does not exist"
        case .runAuthorizationExpired:
            return "the automation run authorization expired before the command started"
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
    var maximumRuntimeSeconds = 60 * 60
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
            guard index < arguments.count,
                  let value = Int(arguments[index]),
                  value > 0,
                  value <= 24 * 60 * 60 else {
                throw AutomationCLIError.invalidNumber("--max-runtime")
            }
            maximumRuntimeSeconds = value
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
        workingDirectory: canonicalWorkingDirectory
    )
    let executable = PlannedExecutable(
        canonicalPath: inspected.canonicalPath,
        signingIdentifier: inspected.signingIdentifier,
        teamIdentifier: inspected.teamIdentifier,
        cdHash: inspected.cdHash,
        assurance: .unverified
    )
    commandLine[0] = executable.canonicalPath
    let command = AutomationCommand(
        executable: executable,
        commandLine: commandLine,
        workingDirectory: canonicalWorkingDirectory,
        commandDigest: try ExecutableInspection.commandDigest(commandLine)
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
        print("  maximum runtime: \(job.maximumRuntimeSeconds)s")
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

        do {
            let remainingRuntime = min(
                TimeInterval(run.job.maximumRuntimeSeconds),
                run.expiresAt.timeIntervalSinceNow
            )
            guard remainingRuntime > 0 else {
                finish()
                throw AutomationCLIError.runAuthorizationExpired
            }
            let status = try ProcessSupervisor.run(
                executablePath: run.job.command.executable.canonicalPath,
                commandLine: run.job.command.commandLine,
                environment: AutomationCommand.sanitizedEnvironment(
                    ProcessInfo.processInfo.environment
                ),
                workingDirectory: run.job.command.workingDirectory,
                timeoutSeconds: remainingRuntime,
                agentSession: session,
                mode: .always
            )
            session.close()
            finish()
            cs_terminate_like_wait_status(status)
        } catch {
            session.close()
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
