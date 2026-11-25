import Foundation

/// How long mailbox cleanup waits before trying again: a delay that doubles
/// each round, from `initialNanoseconds` up to `maximumNanoseconds`.
public struct RemoteApprovalRetrySchedule: Sendable, Equatable {
    public let initialNanoseconds: UInt64
    public let maximumNanoseconds: UInt64

    /// Two seconds, doubling to five minutes: quick enough that a delete a
    /// network blip refused is retried before anyone looks at the phone, slow
    /// enough that a Mac offline for hours costs a request every five minutes.
    public static let standard = RemoteApprovalRetrySchedule(
        initialNanoseconds: 2_000_000_000,
        maximumNanoseconds: 300_000_000_000
    )

    public init(initialNanoseconds: UInt64, maximumNanoseconds: UInt64) {
        self.initialNanoseconds = max(initialNanoseconds, 1)
        self.maximumNanoseconds = max(maximumNanoseconds, self.initialNanoseconds)
    }

    /// The wait before retry round `round` (0 for the first retry).
    public func delay(beforeRound round: Int) -> UInt64 {
        var delay = initialNanoseconds
        for _ in 0..<max(round, 0) {
            guard delay < maximumNanoseconds / 2 else { return maximumNanoseconds }
            delay *= 2
        }
        return min(delay, maximumNanoseconds)
    }
}

/// Mailbox cleanup that must eventually happen: deleting an exchange the Mac
/// stopped waiting on, sweeping the prompts a restart or a replaced pairing
/// left behind, withdrawing a pairing offer. Each leaves a phone showing
/// something nobody is waiting on — above all an Approve card for a request
/// already decided — so a job that did not finish (a network not yet back
/// after wake, a throttled relay) is kept and tried again on a doubling delay
/// for as long as this process runs. There is no deadline: giving up would
/// leave the stale card. `retryNow()` skips the wait when something says the
/// relay is back (the iCloud account became available, a publish succeeded).
///
/// Jobs are named so the same cleanup is never queued twice: a job queued
/// under a name already waiting replaces it, and one already running is tried
/// again afterwards.
public actor RemoteApprovalCleanupQueue {
    /// One attempt; true when the cleanup is complete.
    public typealias Job = @Sendable () async -> Bool

    private let schedule: RemoteApprovalRetrySchedule
    private var waiting: [String: Job] = [:]
    private var running: Set<String> = []
    private var loop: Task<Void, Never>?
    private var pause: Task<Void, Never>?
    private var round = 0
    /// Set by `retryNow()`: the next round starts without waiting, even when
    /// the retry loop has not reached its wait yet.
    private var skipWait = false

    public init(schedule: RemoteApprovalRetrySchedule = .standard) {
        self.schedule = schedule
    }

    /// Try `job` now, and keep trying it until it reports done.
    public func run(_ name: String, _ job: @escaping Job) async {
        guard !running.contains(name) else {
            waiting[name] = job
            startRetrying()
            return
        }
        waiting[name] = nil
        await attempt(name, job)
        if !waiting.isEmpty { startRetrying() }
    }

    /// Retry every waiting job without finishing the current wait.
    public func retryNow() {
        guard !waiting.isEmpty || !running.isEmpty else { return }
        round = 0
        skipWait = true
        pause?.cancel()
    }

    /// The names of the jobs still to finish (value-free: request and device
    /// identifiers).
    public var pendingJobNames: [String] {
        Array(Set(waiting.keys).union(running)).sorted()
    }

    private func attempt(_ name: String, _ job: @escaping Job) async {
        running.insert(name)
        let done = await job()
        running.remove(name)
        // A job queued under this name while this one ran is the newer intent.
        if !done, waiting[name] == nil { waiting[name] = job }
    }

    private func startRetrying() {
        guard loop == nil else { return }
        loop = Task { await self.retryUntilDone() }
    }

    private func retryUntilDone() async {
        while !waiting.isEmpty {
            if !skipWait {
                let delay = schedule.delay(beforeRound: round)
                round += 1
                let sleeping = Task { _ = try? await Task.sleep(nanoseconds: delay) }
                pause = sleeping
                await sleeping.value
                pause = nil
            }
            skipWait = false
            for name in waiting.keys.sorted() where !running.contains(name) {
                guard let job = waiting.removeValue(forKey: name) else { continue }
                await attempt(name, job)
            }
        }
        round = 0
        skipWait = false
        loop = nil
    }
}
