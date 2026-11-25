import Foundation

/// A serial dispatch queue for one connection's blocking calls (its socket
/// reads and writes, and the code-signature checks of its peer), so that none
/// of them ever runs on Swift's cooperative thread pool.
///
/// That pool has one thread per CPU, and a thread blocked in read(2) is lost to
/// every other task until the call returns. The AI output broker and `ssh` each
/// hold a connection open, often quietly, for as long as their command runs, so
/// a blocking read on the pool let as many quiet clients as the Mac has CPUs
/// stop csecd from serving anything: it accepted connections and never answered
/// them. A serial queue with no target runs on the overcommit root queue
/// (libdispatch: "Serial queues default to overcommit!"), which brings up
/// another thread when its work blocks, so a quiet connection parks one thread
/// of its own and nothing else waits for it.
struct ConnectionLane: Sendable {
    private let queue: DispatchQueue

    init(_ label: String) {
        queue = DispatchQueue(label: label)
    }

    /// Runs `body` on the lane and waits for it without holding a pool thread.
    /// Calls on one lane run one at a time.
    func run<T: Sendable>(_ body: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { continuation in
            queue.async { continuation.resume(returning: body()) }
        }
    }
}
