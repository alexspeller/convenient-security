import ConvenientSecurity
import Darwin
import Foundation
#if canImport(AppKit)
    import AppKit
#endif

// The sudo review helper closes when the sudo that spawned it dies. The PAM
// module handles every exit it controls (approval, timeout, a pending Ctrl-C
// or Ctrl-\, a terminal hangup — packaging/tests/test-pam-cleanup.c); this is
// the one it cannot: sudo itself SIGKILLed or crashed. The check runs the real
// built helper as the child of a throwaway shell, kills the shell, and waits
// for the helper to go. `--parent-watch-probe` arms the same watch the review
// path arms, on its real parent, without a window or Touch ID.

private final class ProbeOutput: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes = Data()
    private var finished = false

    func append(_ data: Data) { lock.lock(); bytes.append(data); lock.unlock() }
    func finish() { lock.lock(); finished = true; lock.unlock() }
    var isFinished: Bool { lock.lock(); defer { lock.unlock() }; return finished }
    var text: String {
        lock.lock(); defer { lock.unlock() }
        return String(decoding: bytes, as: UTF8.self)
    }
}

/// Start `/bin/sh -c <script> <helper>` with its stdout collected until every
/// writer — the shell and the helper it started — has exited.
private func startProbeShell(_ script: String, helper: String) throws -> (Process, ProbeOutput) {
    let shell = Process()
    shell.executableURL = URL(fileURLWithPath: "/bin/sh")
    shell.arguments = ["-c", script, helper]
    let pipe = Pipe()
    shell.standardOutput = pipe
    shell.standardError = FileHandle.nullDevice
    shell.standardInput = FileHandle.nullDevice
    try shell.run()
    try? pipe.fileHandleForWriting.close()
    let output = ProbeOutput()
    let reader = pipe.fileHandleForReading
    Thread.detachNewThread {
        while true {
            let chunk = reader.availableData
            if chunk.isEmpty { break }
            output.append(chunk)
        }
        output.finish()
    }
    return (shell, output)
}

private func waitUntil(seconds: Double, _ condition: () -> Bool) -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        if condition() { return true }
        usleep(10_000)
    }
    return condition()
}

func sudoParentWatchTests() {
    print("\n# sudo review helper: closes when its sudo dies")
    let helper = (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0]))
        .deletingLastPathComponent().appendingPathComponent("csec-sudo-review").path
    guard FileManager.default.isExecutableFile(atPath: helper) else {
        check(false, "the csec-sudo-review helper is built next to cs-selftest (\(helper))")
        return
    }

    // A live parent SIGKILLed while the review is open: the helper exits.
    do {
        let (shell, output) = try startProbeShell(#""$0" --parent-watch-probe & wait"#, helper: helper)
        let armed = waitUntil(seconds: 10) { output.text.contains("armed parent=") }
        check(armed && output.text.contains("armed parent=\(shell.processIdentifier)"),
              "sudo parent watch: the helper arms its watch on the process that spawned it")
        kill(shell.processIdentifier, SIGKILL)
        let exited = waitUntil(seconds: 10) { output.isFinished }
        check(exited && output.text.contains("parent exited; review closed unsuccessful"),
              "sudo parent watch: the helper closes unsuccessful when its sudo is SIGKILLed")
        if !exited {
            // Never leave a stranded probe behind a failed check.
            _ = try? startProbeShell(#"/usr/bin/pkill -KILL -f -- "^$0 --parent-watch-probe$""#, helper: helper)
        }
    } catch {
        check(false, "sudo parent watch: the killed-parent probe runs (\(error))")
    }

    // A parent that is already gone, or goes while the watch is being armed:
    // the helper still exits rather than waiting for an exit it cannot see.
    do {
        let (_, output) = try startProbeShell(#""$0" --parent-watch-probe &"#, helper: helper)
        let exited = waitUntil(seconds: 10) { output.isFinished }
        check(exited,
              "sudo parent watch: a helper whose sudo exited before or while the watch armed still exits")
    } catch {
        check(false, "sudo parent watch: the exited-parent probe runs (\(error))")
    }
}

#if canImport(AppKit)
    // Exit zero is the PAM module's only approval signal, and AppKit ends a
    // process that agrees to quit with exit(0). Any process of the same user
    // can ask the helper to quit (`NSRunningApplication.terminate()`, a quit
    // Apple Event, logout), so a helper that let AppKit quit would hand sudo an
    // approval nobody gave. The check quits the real built helper's
    // `--parent-watch-probe`, which runs AppKit through the review path's own
    // `runWatchingParent`, and requires the unsuccessful status.
    func sudoReviewTerminationTests() {
        print("\n# sudo review helper: a quit request never approves")
        let helper = (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0]))
            .deletingLastPathComponent().appendingPathComponent("csec-sudo-review").path
        guard FileManager.default.isExecutableFile(atPath: helper) else {
            check(false, "the csec-sudo-review helper is built next to cs-selftest (\(helper))")
            return
        }
        do {
            let (_, output) = try startProbeShell(
                #""$0" --parent-watch-probe & echo "helper=$!"; wait "$!"; echo "status=$?""#, helper: helper)
            var helperPID: pid_t = 0
            let armed = waitUntil(seconds: 10) {
                let text = output.text
                guard text.contains("armed parent="),
                    let line = text.split(separator: "\n").first(where: { $0.hasPrefix("helper=") }),
                    let pid = pid_t(line.dropFirst("helper=".count))
                else { return false }
                helperPID = pid
                return true
            }
            check(armed, "sudo review quit: the helper's AppKit loop is up")
            // LaunchServices learns of the helper as AppKit finishes launching;
            // ask again until it answers, as logout or a quitting process would.
            let asked = armed && waitUntil(seconds: 10) {
                NSRunningApplication(processIdentifier: helperPID)?.terminate() ?? false
            }
            check(asked, "sudo review quit: the helper is asked to quit as a running application")
            let exited = waitUntil(seconds: 10) { output.isFinished }
            check(exited && output.text.contains("status=69\n"),
                  "sudo review quit: the helper exits unsuccessful (69), never with AppKit's exit(0)")
            if !exited, helperPID > 0 {
                kill(helperPID, SIGKILL)
            }
        } catch {
            check(false, "sudo review quit: the probe runs (\(error))")
        }
    }
#endif
