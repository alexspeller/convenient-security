import CoreFoundation
import Foundation

/// AppKit's event thread pulls each WindowServer event and wakes the main
/// thread by performing a block on the main run loop that stops it (HIToolbox
/// `PushToCGEventQueue`). Once a panel test has connected this process to the
/// WindowServer, that can happen at any moment, including while the suite is
/// waiting with the main thread idle in its run loop. These checks send that
/// exact stop from another thread while the suite waits, and pass only if the
/// run carries on past it: a stop that ends the run leaves the suite short of
/// its last check, which fails it.
func mainRunLoopStopTests() async {
    print("\n# Main run loop: a stop from AppKit's event thread does not end the run")
    for round in 1...3 {
        let delivery = MainRunLoopStopDelivery()
        Thread.detachNewThread {
            CFRunLoopPerformBlock(CFRunLoopGetMain(), CFRunLoopMode.commonModes.rawValue) {
                delivery.markDelivered()
                CFRunLoopStop(CFRunLoopGetMain())
            }
            CFRunLoopWakeUp(CFRunLoopGetMain())
        }
        // Wait without holding the main thread, so the stop lands in the run
        // loop the suite itself is waiting in. Starting the thread and running
        // the block can take seconds on a heavily loaded Mac; the wait ends as
        // soon as it lands.
        for _ in 0..<6_000 where !delivery.delivered {
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        try? await Task.sleep(nanoseconds: 50_000_000)
        check(delivery.delivered,
              "stop \(round): a main-run-loop stop sent the way AppKit's event thread sends it lands while the suite waits, and the suite carries on")
    }
}

/// The standalone `--main-run-loop-only` run. Its first statement spins the
/// main run loop the way the panel tests do, with no suspension before it, as
/// a standalone `--*-only` run of a panel suite does. The keeper must already
/// be running as the outermost loop by then; had it been left to start in the
/// first run of the loop, it would start inside this spin, which would then
/// never return.
@MainActor
func mainRunLoopKeeperTests() async {
    print("\n# Main run loop: the keeper is running before the suite's first statement")
    let spinStarted = Date()
    spinMainRunLoop(seconds: 0.2)
    check(Date().timeIntervalSince(spinStarted) < 30,
          "a spin of the main run loop before the suite's first suspension returns")
    await mainRunLoopStopTests()
}

@MainActor
private func spinMainRunLoop(seconds: TimeInterval) {
    RunLoop.main.run(until: Date().addingTimeInterval(seconds))
}

private final class MainRunLoopStopDelivery: @unchecked Sendable {
    private let lock = NSLock()
    private var wasDelivered = false

    var delivered: Bool {
        lock.lock()
        defer { lock.unlock() }
        return wasDelivered
    }

    func markDelivered() {
        lock.lock()
        wasDelivered = true
        lock.unlock()
    }
}
