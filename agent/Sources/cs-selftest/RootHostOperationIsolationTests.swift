import ConvenientSecurity
import CSECRootProtocol
import CSECRootServer
import Darwin
import Foundation

// A host-audit request runs fixed system tools for up to 25 s each, and csecd's
// periodic audit sends a dozen. rootd used to run them inside its launch
// coordinator actor, so while an audit ran no launch could prepare and the
// maintenance sweeps that enforce soft and hard TTLs and launcher death waited
// behind it (csec-0.39.23). A host read held open here must hold up neither.
func rootHostOperationIsolationTests() async {
    let base = URL(fileURLWithPath: "/tmp")
        .appendingPathComponent("cs-hostiso-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: base) }
    let socketPath = base.appendingPathComponent("rootd.sock").path

    // The synthetic read signals that it is running, then blocks until the test
    // releases it, or for at most 15 s so a regression fails rather than hangs.
    let readStarted = DispatchSemaphore(value: 0)
    let releaseRead = DispatchSemaphore(value: 0)
    let hostOperations = RootHostOperations(mode: .syntheticTesting, syntheticRead: { query in
        readStarted.signal()
        _ = releaseRead.wait(timeout: .now() + 15)
        return HostHelperResult(exitCode: 0, output: "### synthetic held \(query.rawValue)\n")
    })

    let coordinator: RootLaunchCoordinator
    do {
        try FileManager.default.createDirectory(
            atPath: base.path, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let mountPath = base.appendingPathComponent("files").path
        try ProtectedTmpFS(mode: .syntheticTesting, basePath: base.path, mountPath: mountPath).prepare()
        coordinator = RootLaunchCoordinator(
            mode: .syntheticTesting,
            allocator: CapabilityGIDAllocator(mode: .syntheticTesting, basePath: base.path),
            files: try ProtectedFileStore(mountPath: mountPath, mode: .syntheticTesting))
        let server = RootHelperServer(
            path: socketPath, peerTrustPolicy: .allowUnverifiedForTesting, coordinator: coordinator,
            hostOperations: hostOperations)
        Thread.detachNewThread { try? server.run() }
    } catch {
        check(false, "root host operation isolation: synthetic root helper setup threw (\(error))")
        return
    }
    var waited = 0
    while !FileManager.default.fileExists(atPath: socketPath) && waited < 200 {
        usleep(10_000); waited += 1
    }
    let client = RootHelperClient(path: socketPath, trustPolicy: .allowUnverifiedForTesting)

    let heldRead = HeldHostRead()
    let readFinished = DispatchSemaphore(value: 0)
    Thread.detachNewThread {
        heldRead.result = try? client.hostRead(.sharingServices)
        readFinished.signal()
    }
    guard await signalled(readStarted, within: 5) else {
        check(false, "root host operation isolation: the held host read reached the synthetic tool")
        releaseRead.signal()
        return
    }

    // While the host read is still running, a maintenance pass and a socket
    // prepare run side by side, so neither can pass by waiting for the read to
    // be released after the other.
    let plan = try? preparationPlan()
    async let maintenanceSeconds: TimeInterval = {
        let start = Date()
        await coordinator.maintenance()
        return Date().timeIntervalSince(start)
    }()
    async let prepareOutcome: (PreparedRootLaunch?, TimeInterval) = withCheckedContinuation { continuation in
        DispatchQueue.global().async {
            let start = Date()
            var prepared: PreparedRootLaunch?
            let fds = preparationDescriptors()
            if let plan, fds.allSatisfy({ $0 >= 0 }) {
                prepared = try? client.prepare(
                    plan: plan, cwdFD: fds[0], stdinFD: fds[1], stdoutFD: fds[2], stderrFD: fds[3])
            }
            fds.forEach { if $0 >= 0 { close($0) } }
            continuation.resume(returning: (prepared, Date().timeIntervalSince(start)))
        }
    }
    let (maintained, (prepared, prepareSeconds)) = await (maintenanceSeconds, prepareOutcome)
    check(maintained < 2,
          "root host operation isolation: a maintenance pass does not wait for a running host read"
          + " (took \(String(format: "%.2f", maintained)) s)")
    check(prepared != nil && prepareSeconds < 2,
          "root host operation isolation: a launch prepares over the socket while a host read runs"
          + " (\(prepared == nil ? "failed" : "prepared") in \(String(format: "%.2f", prepareSeconds)) s)")
    if let prepared {
        client.cancel(nonce: prepared.nonce, planDigest: prepared.planDigest)
    }

    // The held read itself still completes with its own output once released.
    releaseRead.signal()
    let finished = await signalled(readFinished, within: 10)
    check(finished && heldRead.result?.output.contains("synthetic held sharingServices") == true,
          "root host operation isolation: the held host read returns its output once its tool finishes")
}

/// Waits for `semaphore` on a dispatch thread, never on the cooperative pool.
private func signalled(_ semaphore: DispatchSemaphore, within seconds: Int) async -> Bool {
    await withCheckedContinuation { continuation in
        DispatchQueue.global().async {
            continuation.resume(returning: semaphore.wait(timeout: .now() + .seconds(seconds)) == .success)
        }
    }
}

/// Carries the held read's result from its thread; the semaphore orders the
/// write before the read.
private final class HeldHostRead: @unchecked Sendable {
    var result: HostHelperResult?
}
