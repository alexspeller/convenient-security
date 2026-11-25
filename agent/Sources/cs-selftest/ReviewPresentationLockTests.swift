import ConvenientSecurity
import Darwin
import Foundation

private actor PresentationEvents {
    private(set) var values: [String] = []
    func record(_ event: String) { values.append(event) }
}

private func presentationEventually(_ condition: () async -> Bool) async -> Bool {
    for _ in 0..<500 {
        if await condition() { return true }
        try? await Task.sleep(nanoseconds: 10_000_000)
    }
    return false
}

private final class PresentationProbeOutput: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes = Data()
    func append(_ data: Data) { lock.lock(); bytes.append(data); lock.unlock() }
    var text: String {
        lock.lock(); defer { lock.unlock() }
        return String(decoding: bytes, as: UTF8.self)
    }
}

private struct PresentationProbe {
    let process: Process
    let input: FileHandle
    let output: PresentationProbeOutput

    init(directory: String) throws {
        let helper = (Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0]))
            .deletingLastPathComponent().appendingPathComponent("csec-sudo-review")
        process = Process()
        process.executableURL = helper
        process.arguments = ["--presentation-lock-probe", directory]
        // PAM's environment has no TMPDIR; inherited shell values must not
        // be needed by the shared presentation mechanism or its helper.
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "C"]
        let stdin = Pipe(), stdout = Pipe()
        input = stdin.fileHandleForWriting
        output = PresentationProbeOutput()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        try process.run()
        try? stdin.fileHandleForReading.close()
        try? stdout.fileHandleForWriting.close()
        let collected = output, reader = stdout.fileHandleForReading
        Thread.detachNewThread {
            while true {
                let bytes = reader.availableData
                if bytes.isEmpty { break }
                collected.append(bytes)
            }
            try? reader.close()
        }
    }

    func stop() {
        try? input.close()
        if process.isRunning { kill(process.processIdentifier, SIGKILL) }
    }
}

func reviewPresentationLockTests() async {
    print("\n# Cross-process approval presentation (sudo, access, SSH and cancellation)")
    let directory = NSTemporaryDirectory() + "csec-review-presentation-\(UUID().uuidString)"
    defer { try? FileManager.default.removeItem(atPath: directory) }
    let gate = ReviewPresentationLock(directory: directory)
    do {
        let held = try await gate.acquire()
        let events = PresentationEvents()
        let waiting = Task {
            await events.record("waiting")
            return try await gate.acquire()
        }
        check(await presentationEventually { await events.values == ["waiting"] },
              "a competing review starts waiting for its presentation turn")
        waiting.cancel()
        do {
            _ = try await waiting.value
            check(false, "a cancelled presentation waiter must never own a turn")
        } catch { check(error is CancellationError, "a queued requester cancels without waiting for the owner") }
        held.release()
        let next = try await gate.acquire()
        held.release()
        let stillBlocked = Task { try await gate.acquire() }
        stillBlocked.cancel()
        do {
            _ = try await stillBlocked.value
            check(false, "a repeated old release must not release a later review")
        } catch { check(error is CancellationError, "a repeated release leaves the next owner's turn intact") }
        next.release()

        // Neither copy starts while a different process/surface owns the
        // turn. Cancellation withdraws both before any panel or phone copy.
        let owner = try await gate.acquire()
        let race = Task {
            await events.record("sudo-waiting")
            return await SudoReviewRace.run(
                presentationLock: gate,
                local: { await events.record("mac"); return .approved },
                phone: { await events.record("phone"); return .approved }
            )
        }
        check(await presentationEventually { await events.values.contains("sudo-waiting") },
              "sudo joins the shared presentation wait")
        race.cancel()
        check(await race.value.exitStatus != 0, "a queued cancelled sudo cannot approve")
        check(await events.values == ["waiting", "sudo-waiting"],
              "queued sudo starts neither its Mac panel nor its phone review")
        owner.release()

        let outcome = await SudoReviewRace.run(
            presentationLock: gate, local: { .approved }, phone: { .unavailable }
        )
        check(outcome == .approved(on: .mac), "sudo starts normally once the presentation turn is free")
        let after = try await gate.acquire()
        after.release()
        check(true, "the sudo race releases its turn after both legs finish")

        // The daemon's FIFO head can be cancelled while it owns the FIFO but
        // is still waiting for a sudo helper's cross-process turn.
        let blocking = try await gate.acquire()
        let queue = ConsentQueue(presentationLock: gate)
        let head = Task { try await queue.acquire() }
        let follower = Task { try await queue.acquire() }
        check(await presentationEventually { await queue.waitingCount == 1 },
              "the daemon preserves its FIFO behind the shared turn")
        head.cancel(); follower.cancel()
        _ = try? await head.value
        _ = try? await follower.value
        blocking.release()
        let recovered = try await queue.acquire()
        await recovered.release()
        check(await queue.waitingCount == 0, "cancelling the blocked FIFO head leaves no stuck owner")
    } catch { check(false, "presentation turn lifecycle runs (\(error))") }

    // File validation must refuse unsafe rendezvous objects without writing
    // through them or starting either review leg.
    let path = directory + "/review.lock"
    do {
        try FileManager.default.removeItem(atPath: path)
        let target = directory + "/target"
        try Data().write(to: URL(fileURLWithPath: target))
        try FileManager.default.createSymbolicLink(atPath: path, withDestinationPath: target)
        do {
            _ = try await gate.acquire()
            check(false, "a symlink cannot be a presentation lock")
        } catch { check(true, "presentation locking refuses symlinks") }
        try FileManager.default.removeItem(atPath: path)
        try FileManager.default.linkItem(atPath: target, toPath: path)
        chmod(target, 0o600)
        let events = PresentationEvents()
        let refused = await SudoReviewRace.run(
            presentationLock: gate,
            local: { await events.record("mac"); return .approved },
            phone: { await events.record("phone"); return .approved }
        )
        check(refused.exitStatus != 0, "an unsafe presentation lock cannot approve sudo")
        check(await events.values.isEmpty, "lock failure starts neither review copy")
        try FileManager.default.removeItem(atPath: path)
        try FileManager.default.removeItem(atPath: target)
        chmod(directory, 0o755)
        do {
            _ = try await gate.acquire()
            check(false, "a shared directory cannot host the private presentation lock")
        } catch { check(true, "presentation locking refuses a non-private directory") }
        chmod(directory, 0o700)
    } catch { check(false, "unsafe presentation path fixtures run (\(error))") }

    // Real helper processes use the production sudo race. EOF is a normal
    // finish; SIGKILL proves that no persistent stale owner survives a crash.
    do {
        let first = try PresentationProbe(directory: directory)
        defer { first.stop() }
        check(await presentationEventually { first.output.text.contains("acquired") },
              "the real first sudo helper owns its presentation turn")
        let second = try PresentationProbe(directory: directory)
        defer { second.stop() }
        check(await presentationEventually { second.output.text.contains("waiting") },
              "a concurrent real sudo helper joins the presentation wait")
        check(!second.output.text.contains("acquired"), "concurrent real sudo helpers never both present")
        try first.input.close()
        check(await presentationEventually { !first.process.isRunning }, "the first helper exits normally on EOF")
        check(first.process.terminationStatus == 69, "the probe never authorizes a real command")
        check(await presentationEventually { second.output.text.contains("acquired") },
              "a normal sudo helper exit admits the waiting helper")
        let third = try PresentationProbe(directory: directory)
        defer { third.stop() }
        check(await presentationEventually { third.output.text.contains("waiting") },
              "a third helper waits behind the second")
        check(!third.output.text.contains("acquired"), "the second helper retains the turn until it ends")
        kill(second.process.processIdentifier, SIGKILL)
        check(await presentationEventually { !second.process.isRunning }, "the owner helper can crash")
        check(await presentationEventually { third.output.text.contains("acquired") },
              "a helper crash releases its turn without deleting the rendezvous file")

        // The daemon and a real helper contend in both directions. Its FIFO
        // head waits with no presentation while the helper owns the turn.
        let queue = ConsentQueue(presentationLock: gate)
        let events = PresentationEvents()
        let queued = Task {
            await events.record("waiting")
            let permit = try await queue.acquire()
            await events.record("acquired")
            return permit
        }
        let cancelled = Task { try await queue.acquire() }
        check(await presentationEventually { await queue.waitingCount == 1 },
              "a real sudo helper holds the daemon's presentation FIFO")
        cancelled.cancel()
        _ = try? await cancelled.value
        check(await events.values == ["waiting"], "the daemon cannot present over a real sudo helper")
        try third.input.close()
        check(await presentationEventually { !third.process.isRunning }, "the last helper exits normally")
        let daemon = try await queued.value
        check(await events.values == ["waiting", "acquired"], "the waiting daemon presents after the real helper exits")
        let fourth = try PresentationProbe(directory: directory)
        defer { fourth.stop() }
        check(await presentationEventually { fourth.output.text.contains("waiting") },
              "a real sudo helper waits for the daemon's turn")
        check(!fourth.output.text.contains("acquired"), "a real sudo helper cannot present over a daemon review")
        await daemon.release()
        check(await presentationEventually { fourth.output.text.contains("acquired") },
              "closing the daemon review admits the real sudo helper")
        try fourth.input.close()
        check(await presentationEventually { !fourth.process.isRunning }, "every helper probe is finished")
    } catch { check(false, "cross-process sudo presentation probes run (\(error))") }
}
