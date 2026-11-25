import CoreFoundation

/// Keeps cs-selftest's run going when something stops the main run loop.
///
/// A Swift async `main` drains the main actor by running the main run loop
/// once (`CFRunLoopRun`) and calls `exit(0)` when that returns. AppKit's event
/// thread stops the main run loop to wake the main thread for every
/// WindowServer event it pulls (HIToolbox `PushToCGEventQueue` performs a
/// block that calls `CFRunLoopStop`). After a panel test has connected this
/// process to the WindowServer, an event that arrives while the suite is
/// waiting would end the run there with status 0. A busy Mac sends more of
/// them, and later.
///
/// `install()` performs one block on the main run loop and waits for it to
/// start. The block never returns: it runs the main run loop again after
/// every stop, and main-queue jobs (the main actor), timers and sources all
/// run inside it as they would in the runtime's. A stop now ends one pass of
/// this loop, never the runtime's. The suite still ends only through its own
/// `exit`.
///
/// The block has to start in the runtime's own run of the loop, the
/// outermost one. Any run of the main run loop performs pending blocks, so a
/// test that spun the loop before the runtime reached the block would run the
/// keeper inside its spin, and the spin would never return. `install()`
/// therefore suspends the caller until the keeper is running: with the
/// suite's code suspended, only the runtime's run loop is left to start it.
enum MainRunLoopKeeper {
    static func install() async {
        await withCheckedContinuation { (started: CheckedContinuation<Void, Never>) in
            let mainRunLoop = CFRunLoopGetMain()
            CFRunLoopPerformBlock(mainRunLoop, CFRunLoopMode.defaultMode.rawValue) {
                // Resuming only queues the suite's next main-actor job; the
                // loop below runs it.
                started.resume()
                while true {
                    _ = CFRunLoopRunInMode(.defaultMode, .greatestFiniteMagnitude, false)
                }
            }
            CFRunLoopWakeUp(mainRunLoop)
        }
    }
}
