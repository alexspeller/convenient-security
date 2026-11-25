import Foundation
import ConvenientSecurity

/// The `/bin/sh` wrapper both clients' hook configurations enter through,
/// run as the clients run it. An install replaces the app bundle with a gap
/// in which the launcher path does not exist (PackageKit's bundle "shove",
/// about 25 ms), so the wrapper waits a bounded time for the launcher instead
/// of denying every command that lands in it, and still denies a launcher
/// that stays unavailable.
func hookWrapperTests() {
    print("\n# Hook wrapper")

    struct Wrapper {
        let label: String
        /// The `/bin/sh` arguments for a launcher at the given path.
        let arguments: (String) -> [String]
    }
    struct Run {
        let status: Int32
        let stdout: String
        let stderr: String
        let seconds: TimeInterval
    }

    let configuredPath = "/opt/Convenient Security/csec"
    let wrappers: [Wrapper]
    do {
        let claudeData = try AICommandHook.hookConfiguration(client: .claude, csecExecutablePath: configuredPath)
        let codexData = try AICommandHook.hookConfiguration(client: .codex, csecExecutablePath: configuredPath)
        func handler(_ data: Data) -> [String: Any]? {
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            let hooks = object?["hooks"] as? [String: Any]
            let groups = hooks?["PreToolUse"] as? [[String: Any]]
            return (groups?.first?["hooks"] as? [[String: Any]])?.first
        }
        guard let claudeArguments = handler(claudeData)?["args"] as? [String],
              claudeArguments.suffix(2) == [configuredPath, "claude"],
              let codexCommand = handler(codexData)?["command"] as? String,
              codexCommand.contains("'\(configuredPath)'") else {
            check(false, "both hook configurations carry the launcher path through the wrapper")
            return
        }
        wrappers = [
            Wrapper(label: "Claude") { Array(claudeArguments.dropLast(2)) + [$0, "claude"] },
            Wrapper(label: "Codex") {
                ["-c", codexCommand.replacingOccurrences(of: "'\(configuredPath)'", with: "'\($0)'")]
            },
        ]
    } catch {
        check(false, "hook configurations serialize (\(error))")
        return
    }

    let fm = FileManager.default
    let root = fm.temporaryDirectory.appendingPathComponent("csec-hook-wrapper-\(UUID().uuidString)", isDirectory: true)
    do {
        try fm.createDirectory(at: root, withIntermediateDirectories: true)
    } catch {
        check(false, "hook wrapper scratch directory is created (\(error))")
        return
    }
    defer { try? fm.removeItem(at: root) }

    let input = #"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo kept"}}"#

    /// Installs `body` at `path` the way an install leaves it: complete before
    /// it becomes executable.
    func install(_ body: String, at path: URL) throws {
        try body.write(to: path, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path.path)
    }

    /// Starts the wrapper; `wait` returns once it has exited.
    func start(_ wrapper: Wrapper, launcher: URL) throws -> () -> Run {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = wrapper.arguments(launcher.path)
        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        let started = Date()
        try process.run()
        stdin.fileHandleForWriting.write(Data(input.utf8))
        try? stdin.fileHandleForWriting.close()
        // Drain both pipes on their own threads so a full pipe never stalls the wrapper.
        var outData = Data()
        var errData = Data()
        let group = DispatchGroup()
        DispatchQueue.global().async(group: group) { outData = stdout.fileHandleForReading.readDataToEndOfFile() }
        DispatchQueue.global().async(group: group) { errData = stderr.fileHandleForReading.readDataToEndOfFile() }
        return {
            process.waitUntilExit()
            group.wait()
            return Run(
                status: process.terminationStatus,
                stdout: String(decoding: outData, as: UTF8.self),
                stderr: String(decoding: errData, as: UTF8.self),
                seconds: Date().timeIntervalSince(started))
        }
    }

    // A working launcher: it echoes the whole hook input, so a pass proves the
    // wrapper handed csec stdin untouched.
    let echoing = "#!/bin/sh\nprintf 'launcher saw: '\ncat\n"

    do {
        // Missing for the whole wait: denied with a reason on stderr (Codex
        // runs the command unwrapped on a silent status 2), after the bounded
        // wait and well inside the clients' 30 s hook timeout. Every wrapper
        // runs at once so the wait is paid once.
        let missing = root.appendingPathComponent("missing/csec")
        let waits = try wrappers.map { ($0.label, try start($0, launcher: missing)) }
        for (label, wait) in waits {
            let run = wait()
            check(run.status == 2
                  && run.stderr.contains("csec hook: protected output scanner unavailable for 5 s; command denied")
                  && run.stdout.isEmpty,
                  "\(label) hook wrapper denies, with its reason, a launcher that stays unavailable")
            check(run.seconds >= 4.5 && run.seconds < 15,
                  "\(label) hook wrapper waits about 5 s for the launcher before it denies (\(run.seconds) s)")
        }

        for wrapper in wrappers {
            // Missing when the hook starts, installed during the wait: run.
            let directory = root.appendingPathComponent("appears-\(wrapper.label)", isDirectory: true)
            try fm.createDirectory(at: directory, withIntermediateDirectories: true)
            let launcher = directory.appendingPathComponent("csec")
            let wait = try start(wrapper, launcher: launcher)
            Thread.sleep(forTimeInterval: 0.4)
            try install(echoing, at: launcher)
            let run = wait()
            check(run.status == 0 && run.stdout == "launcher saw: \(input)",
                  "\(wrapper.label) hook wrapper runs a launcher that an install puts back during its wait")

            // Executable but not runnable (the shell's exec fails, status 126,
            // as when the bundle goes between the test and the exec), then
            // replaced: run, with stdin still whole.
            let swapping = root.appendingPathComponent("swap-\(wrapper.label)", isDirectory: true)
            try fm.createDirectory(at: swapping, withIntermediateDirectories: true)
            let swapped = swapping.appendingPathComponent("csec")
            try install("#!/definitely/missing/interpreter\n", at: swapped)
            let swapWait = try start(wrapper, launcher: swapped)
            Thread.sleep(forTimeInterval: 0.4)
            try install(echoing, at: swapped)
            let swapRun = swapWait()
            check(swapRun.status == 0 && swapRun.stdout == "launcher saw: \(input)",
                  "\(wrapper.label) hook wrapper retries a launcher the shell could not exec, then runs it with stdin whole")

            // A launcher that ran and refused is never retried: one run, denied at once.
            // Every retry runs the launcher again, so the run count proves there was
            // none however loaded the Mac is. The time bound catches only a wrapper
            // that waits out its retry loop before denying, which sleeps at least
            // 4.9 s; process starts on a loaded Mac can take seconds, so it allows
            // anything under the 4.5 s the bounded-wait check holds as the floor.
            let refusing = root.appendingPathComponent("refuse-\(wrapper.label)", isDirectory: true)
            try fm.createDirectory(at: refusing, withIntermediateDirectories: true)
            let counter = refusing.appendingPathComponent("runs")
            let refuser = refusing.appendingPathComponent("csec")
            try install("#!/bin/sh\ncat >/dev/null\necho run >> '\(counter.path)'\nexit 3\n", at: refuser)
            let refuseRun = try start(wrapper, launcher: refuser)()
            let runs = (try? String(contentsOf: counter, encoding: .utf8))?.split(separator: "\n").count ?? 0
            check(refuseRun.status == 2
                  && refuseRun.stderr.contains("csec hook: exited with status 3; command denied")
                  && runs == 1,
                  "\(wrapper.label) hook wrapper denies a launcher's own failure, without a retry (status \(refuseRun.status), \(runs) run(s))")
            check(refuseRun.seconds < 4.5,
                  "\(wrapper.label) hook wrapper denies a launcher's own failure without waiting out its retry loop (\(refuseRun.seconds) s)")
        }
    } catch {
        check(false, "hook wrapper scenarios run (\(error))")
    }
}
