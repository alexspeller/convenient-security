import Foundation

/// A child process's exit, awaited without blocking a thread.
///
/// `Process.waitUntilExit()` spins the calling thread's run loop until the
/// child's exit wakes it. In an async test, an `await` between `run()` and
/// the wait can move the task to another cooperative thread, and there the
/// wakeup can be lost for good: measured 3–5 of 30 hung, and one hung the
/// whole selftest in `RestorePanelTests`. Plain threads, the main actor, and
/// a wait with no suspension since `run()` measured 0 hung. The
/// `terminationHandler` always runs, so an async test installs one through
/// this type before `run()` and awaits it, bounded: a child still running
/// at the bound makes the wait return false, a check fails, and the run
/// goes on.
final class ChildProcessExit: @unchecked Sendable {
    private let lock = NSLock()
    private var exited = false
    private var waiters: [UUID: CheckedContinuation<Bool, Never>] = [:]

    /// Installs `process`'s termination handler. Call it before `run()`: a
    /// handler set after the child has exited is never called.
    init(_ process: Process) {
        process.terminationHandler = { [self] _ in finish() }
    }

    /// Whether the child exited within `seconds`.
    func wait(within seconds: Double) async -> Bool {
        let id = UUID()
        return await withCheckedContinuation { continuation in
            lock.lock()
            if exited {
                lock.unlock()
                continuation.resume(returning: true)
                return
            }
            waiters[id] = continuation
            lock.unlock()
            DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { [self] in
                lock.lock()
                let pending = waiters.removeValue(forKey: id)
                lock.unlock()
                pending?.resume(returning: false)
            }
        }
    }

    private func finish() {
        lock.lock()
        exited = true
        let pending = waiters
        waiters = [:]
        lock.unlock()
        for continuation in pending.values { continuation.resume(returning: true) }
    }
}

func childProcessExitTests() async {
    print("\n# awaiting a child's exit without blocking a thread")
    func sleeper(_ seconds: String) -> Process {
        let child = Process()
        child.executableURL = URL(fileURLWithPath: "/bin/sleep")
        child.arguments = [seconds]
        return child
    }

    // The shape that hung RestorePanelTests: launch, a suspension that can
    // move the task to another thread, terminate, wait.
    var returned = 0
    for _ in 0..<20 {
        let child = sleeper("30")
        let exit = ChildProcessExit(child)
        guard (try? child.run()) != nil else { continue }
        try? await Task.sleep(nanoseconds: 20_000_000)
        child.terminate()
        if await exit.wait(within: 5) { returned += 1 }
    }
    check(returned == 20, "child exit: after a suspension, terminate and wait always returns (\(returned) of 20)")

    // Bounded: a child still running at the bound is reported, not waited on.
    let long = sleeper("30")
    let longExit = ChildProcessExit(long)
    if (try? long.run()) != nil {
        let started = Date()
        let early = await longExit.wait(within: 0.3)
        let elapsed = Date().timeIntervalSince(started)
        long.terminate()
        let late = await longExit.wait(within: 5)
        check(!early && elapsed < 3 && late,
              "child exit: a child still running at the bound returns false promptly, then true once it exits")
    } else {
        check(false, "child exit: the long-running fixture starts")
    }

    // A child that exited before the wait began, and a second wait.
    let quick = Process()
    quick.executableURL = URL(fileURLWithPath: "/usr/bin/true")
    let quickExit = ChildProcessExit(quick)
    if (try? quick.run()) != nil {
        _ = await quickExit.wait(within: 5)
        let again = await quickExit.wait(within: 0.1)
        check(again, "child exit: waiting again after the exit returns true at once")
    } else {
        check(false, "child exit: the short fixture starts")
    }
}
