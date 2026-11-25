import ConvenientSecurity
import Foundation

private final class CommandDiagnosticRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var events: [HostCommandDiagnostic] = []
    func record(_ event: HostCommandDiagnostic) {
        lock.lock(); defer { lock.unlock() }; events.append(event)
    }
    func snapshot() -> [HostCommandDiagnostic] {
        lock.lock(); defer { lock.unlock() }; return events
    }
}

private final class StalledCommandExecutor: HostCommandExecuting, @unchecked Sendable {
    let unblock = DispatchSemaphore(value: 0)
    let returned = DispatchSemaphore(value: 0)
    func waitForReturn() async -> Bool {
        await withCheckedContinuation { continuation in
            DispatchQueue.global().async { [self] in
                continuation.resume(returning: returned.wait(timeout: .now() + 2) == .success)
            }
        }
    }
    func execute(_ command: HostCommand, control: HostCommandControl, maximumOutputBytes: Int) -> HostCommandResult {
        unblock.wait()
        defer { returned.signal() }
        // A launch preparation which eventually comes back must not start the
        // expired request, even though its caller has already moved on.
        return POSIXHostCommandExecutor().execute(command, control: control, maximumOutputBytes: maximumOutputBytes)
    }
}

func hostCommandExecutionTests() async {
    let silent: @Sendable (HostCommandDiagnostic) -> Void = { _ in }
    let runner = SystemCommandRunner(timeout: 2, diagnostics: silent)
    let result = await runner.run(HostCommand(executable: "/bin/sh",
        arguments: ["-c", "printf fixture-out; printf fixture-err >&2; exit 7"], label: "fixture.output"))
    check(!result.launchFailed && result.exitCode == 7 && result.standardOutput == "fixture-out"
        && result.standardError == "fixture-err", "audit runner captures both streams and actual exit status")
    let missing = await runner.run(HostCommand(executable: "/csec-fixture-missing", label: "fixture.missing"))
    check(missing.failure == .launch, "audit runner reports missing executable as unavailable")
    let input = String(repeating: "synthetic-input\n", count: 10000)
    let echoed = await runner.run(HostCommand(executable: "/bin/cat", label: "fixture.input", standardInput: input))
    check(echoed.succeeded && echoed.standardOutput == input, "audit runner streams input larger than a pipe without deadlock")
    let eof = await runner.run(HostCommand(executable: "/bin/cat", label: "fixture.stdin"))
    check(eof.succeeded && eof.standardOutput.isEmpty, "audit runner supplies EOF instead of inheriting interactive stdin")

    let diagnostics = CommandDiagnosticRecorder()
    let short = SystemCommandRunner(timeout: 0.25, diagnostics: { diagnostics.record($0) })
    for (name, script) in [
        ("term-resistant", "trap '' TERM; while :; do :; done"),
        ("closed-output", "exec 1>&- 2>&-; /bin/sleep 10"),
        ("inherited-pipe", "/bin/sleep 10 & exit 0"),
    ] {
        let started = ProcessInfo.processInfo.systemUptime
        let stalled = await short.run(HostCommand(executable: "/bin/sh", arguments: ["-c", script], label: "fixture.\(name)"))
        check(stalled.failure == .timeout && stalled.launchFailed && !stalled.succeeded,
            "audit \(name) returns an explicit unknown/timeout result")
        check(ProcessInfo.processInfo.systemUptime - started < 2,
            "audit \(name) deadline includes child exit and inherited pipes")
        check(stalled.standardOutput.isEmpty && stalled.standardError.isEmpty,
            "audit timeout cannot expose a partial result as evidence")
    }
    let noisy = await SystemCommandRunner(timeout: 2, maximumOutputBytes: 1024, diagnostics: silent)
        .run(HostCommand(executable: "/usr/bin/yes", arguments: ["fixture"], label: "fixture.noisy"))
    check(noisy.failure == .outputLimit && noisy.standardOutput.isEmpty,
        "audit output limit is enforced during capture, not after unbounded allocation")
    let events = diagnostics.snapshot()
    check(events.contains { $0.event == "slow" } && events.contains { $0.event == "timeout" },
        "audit records an early slow event and timeout using only stable metadata")

    let stalledExecutor = StalledCommandExecutor()
    let capacity = HostCommandCapacity(limit: 1)
    let launchEvents = CommandDiagnosticRecorder()
    let delayed = SystemCommandRunner(timeout: 0.15, executor: stalledExecutor,
        capacity: capacity, diagnostics: { launchEvents.record($0) })
    let marker = FileManager.default.temporaryDirectory.appendingPathComponent("csec-expired-launch-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: marker) }
    let expired = await delayed.run(HostCommand(executable: "/usr/bin/touch", arguments: [marker.path], label: "fixture.delayed"))
    check(expired.failure == .timeout, "audit deadline covers an executor stalled before spawn")
    let probe = SystemCommandRunner(timeout: 1, capacity: capacity, diagnostics: silent)
    let saturated = await probe.run(HostCommand(executable: "/usr/bin/true", label: "fixture.capacity"))
    check(saturated.failure == .capacity, "timed-out launch retains admission slot until the worker really finishes")
    stalledExecutor.unblock.signal()
    let returned = await stalledExecutor.waitForReturn()
    check(returned, "late launch worker completes safely")
    try? await Task.sleep(nanoseconds: 100_000_000)
    let recovered = await probe.run(HostCommand(executable: "/usr/bin/true", label: "fixture.recovered"))
    check(recovered.succeeded && !FileManager.default.fileExists(atPath: marker.path),
        "expired launch never runs later and admission capacity is recovered")
    check(launchEvents.snapshot().contains { $0.event == "timeout" && $0.phase == .launch },
        "launch-stall diagnostic distinguishes launch from running/cleanup")

    // Two scans sharing a process pool cannot each fan out two more stalled
    // assessments; the reservation survives a timeout across runner instances.
    let sharedExecutor = StalledCommandExecutor()
    let sharedCapacity = HostCommandCapacity(limit: 4)
    let assessments = SystemCommandRunner(timeout: 0.15, executor: sharedExecutor,
        capacity: sharedCapacity, diagnostics: silent)
    let results = await withTaskGroup(of: HostCommandResult.self, returning: [HostCommandResult].self) { group in
        for _ in 0..<3 {
            group.addTask {
                await assessments.run(HostCommand(executable: "/usr/bin/true", label: "spctl.assess.app"))
            }
        }
        var results: [HostCommandResult] = []
        for await result in group { results.append(result) }
        return results
    }
    check(results.filter { $0.failure == .timeout }.count == 2 && results.filter { $0.failure == .capacity }.count == 1,
        "Gatekeeper admission cap is shared across simultaneous scans and stalled launches")
    let otherWork = await SystemCommandRunner(timeout: 1, capacity: sharedCapacity, diagnostics: silent)
        .run(HostCommand(executable: "/usr/bin/true", label: "fixture.unrelated"))
    check(otherWork.succeeded, "stalled Gatekeeper assessments leave capacity for unrelated diagnostics")
    sharedExecutor.unblock.signal(); sharedExecutor.unblock.signal()
    let firstReturned = await sharedExecutor.waitForReturn()
    let secondReturned = await sharedExecutor.waitForReturn()
    check(firstReturned && secondReturned, "both synthetic stalled assessment workers are released")

    let serial = SystemCommandRunner(timeout: 1, capacity: HostCommandCapacity(limit: 1), diagnostics: silent)
    var serialSucceeded = true
    for _ in 0..<20 {
        let command = await serial.run(HostCommand(executable: "/usr/bin/true", label: "fixture.serial"))
        serialSucceeded = serialSucceeded && command.succeeded
    }
    check(serialSucceeded, "completed commands release admission before their caller starts the next command")
}
