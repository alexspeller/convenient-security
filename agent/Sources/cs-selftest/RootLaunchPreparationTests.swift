import ConvenientSecurity
import CSecuritySupport
import CSECRootProtocol
import CSECRootServer
import Darwin
import Foundation

// csec exec prepares its root rendezvous before csecd raises the approval
// panel, and a human may answer that panel many minutes later: a coding
// agent's request waits up to ApprovalWaitLimit, a terminal's indefinitely.
// rootd used to forget a preparation after a fixed 60 s, so an approval given
// later resolved the value and then failed with "the authenticated root helper
// could not accept this launch" (csec-ejxq). A prepared launch now lives while
// its launcher does, and a launch that is gone is reported as such.
func rootLaunchPreparationTests() async {
    let base = URL(fileURLWithPath: "/tmp")
        .appendingPathComponent("cs-rootprep-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: base) }
    let socketPath = base.appendingPathComponent("rootd.sock").path
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
            path: socketPath, peerTrustPolicy: .allowUnverifiedForTesting, coordinator: coordinator)
        Thread.detachNewThread { try? server.run() }
    } catch {
        check(false, "root launch preparation: synthetic root helper setup threw (\(error))")
        return
    }
    var waited = 0
    while !FileManager.default.fileExists(atPath: socketPath) && waited < 200 {
        usleep(10_000); waited += 1
    }
    let client = RootHelperClient(path: socketPath, trustPolicy: .allowUnverifiedForTesting)

    // This process is the launcher: it prepares through the socket, and the
    // same audit identity stands in for csecd's approve.
    var sockets: [Int32] = [-1, -1]
    guard sockets.withUnsafeMutableBufferPointer({
        socketpair(AF_UNIX, SOCK_STREAM, 0, $0.baseAddress)
    }) == 0 else {
        check(false, "root launch preparation: socketpair failed")
        return
    }
    defer { close(sockets[0]); close(sockets[1]) }
    guard let peer = PeerIdentity.socketPeer(fd: sockets[0]),
          let plan = try? preparationPlan(),
          let payloads = try? ProtectedFilePayloadRenderer.render(
              bindings: plan.files,
              values: [plan.files[0].reference: Data("synthetic-preparation-value".utf8)]
          ) else {
        check(false, "root launch preparation: fixture plan or peer unavailable")
        return
    }

    func prepare() -> PreparedRootLaunch? {
        let fds = preparationDescriptors()
        defer { fds.forEach { if $0 >= 0 { close($0) } } }
        guard fds.allSatisfy({ $0 >= 0 }) else { return nil }
        return try? client.prepare(
            plan: plan, cwdFD: fds[0], stdinFD: fds[1], stdoutFD: fds[2], stderrFD: fds[3])
    }

    func approve(_ launch: PreparedRootLaunch, at now: Date, payloads: [ProtectedFilePayload]) async -> Error? {
        do {
            _ = try await coordinator.approve(
                nonce: launch.nonce, planDigest: launch.planDigest, payloads: payloads,
                expiresAt: nil, peer: peer, now: now)
            return nil
        } catch {
            return error
        }
    }

    // The regression: an approval half an hour after the preparation, with
    // rootd's maintenance sweeping in between, is accepted while the launcher
    // is still running.
    guard let slow = prepare() else {
        check(false, "root launch preparation: the synthetic root helper prepares a launch")
        return
    }
    let later = Date().addingTimeInterval(30 * 60)
    await coordinator.maintenance(now: Date().addingTimeInterval(61))
    await coordinator.maintenance(now: later)
    let slowError = await approve(slow, at: later, payloads: payloads)
    check(slowError == nil,
          "root launch preparation: an approval 30 minutes after prepare is accepted while the launcher lives"
          + (slowError.map { " (threw \($0))" } ?? ""))
    client.cancel(nonce: slow.nonce, planDigest: slow.planDigest)

    // A launch that is gone reaches csecd as launchExpired, which csecd turns
    // into "run the command again", not a refusal.
    if let cancelled = prepare() {
        client.cancel(nonce: cancelled.nonce, planDigest: cancelled.planDigest)
        var thrown: Error?
        do {
            try client.approve(
                nonce: cancelled.nonce, planDigest: cancelled.planDigest,
                payloads: payloads, expiresAt: nil)
        } catch {
            thrown = error
        }
        check((thrown as? ProtectedFileDeliveryError) == .launchExpired,
              "root launch preparation: approving a cancelled launch reports launchExpired"
              + " (got \(thrown.map { "\($0)" } ?? "success"))")
    } else {
        check(false, "root launch preparation: a second launch prepares")
    }

    // A launcher holds at most one unapproved preparation; a new one replaces
    // the last, so abandoned preparations cannot fill rootd's record table.
    if let first = prepare(), let second = prepare() {
        let firstError = await approve(first, at: Date(), payloads: payloads)
        check((firstError as? RootHelperRuntimeError) == .invalidRendezvous,
              "root launch preparation: a launcher's newer preparation replaces its older one")
        let secondError = await approve(second, at: Date(), payloads: payloads)
        check(secondError == nil,
              "root launch preparation: the replacing preparation is still approvable")
        client.cancel(nonce: second.nonce, planDigest: second.planDigest)
    } else {
        check(false, "root launch preparation: two consecutive preparations succeed")
    }

    // An approval whose files do not match the plan is a refusal, not a gone
    // launch, so it is never mistaken for "run it again".
    if let mismatched = prepare() {
        let wrong = [ProtectedFilePayload(relativePath: "files/other-0", data: Data("x".utf8))]
        let error = await approve(mismatched, at: Date(), payloads: wrong)
        check((error as? RootHelperRuntimeError) == .invalidApproval,
              "root launch preparation: mismatched payloads are refused as an invalid approval")
        client.cancel(nonce: mismatched.nonce, planDigest: mismatched.planDigest)
    } else {
        check(false, "root launch preparation: a mismatch fixture prepares")
    }

    // csecd's answer for each.
    if let request = try? ProtectedLaunchApprovalRequest(
        rendezvousNonce: UUID().uuidString, launchPlan: plan, launchPlanDigest: (try? plan.digest()) ?? ""
    ) {
        let gone = request.rootHelperRefusal(ProtectedFileDeliveryError.launchExpired)
        check(gone.failure?.code == .invalidRequest
              && gone.failure?.message.contains("run the command again") == true
              && gone.failure?.message.contains("nothing was delivered") == true,
              "root launch preparation: csecd tells the user a gone launch delivered nothing and to run it again")
        let refused = request.rootHelperRefusal(ProtectedFileDeliveryError.rootHelperFailure("x"))
        check(refused.failure?.code == .deliveryNotSupported
              && refused.failure?.message == "the authenticated root helper could not accept this launch",
              "root launch preparation: any other root-helper failure stays a refusal")
    } else {
        check(false, "root launch preparation: approval request fixture builds")
    }
}

func preparationPlan() throws -> ProtectedLaunchPlan {
    let commandLine = ["/bin/sh", "-c", "exit 0"]
    let executable = try ExecutableInspection.plannedExecutable(
        command: "/bin/sh", environment: ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"])
    let delivery = DeliveryPlan(
        mechanism: .capabilityGIDFile,
        executable: executable,
        root: .caller,
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: nil,
        operationContext: "synthetic root launch preparation self-test",
        commandDigest: try ExecutableInspection.commandDigest(commandLine),
        outputGuard: OutputGuardPlan(mode: .always)
    )
    return ProtectedLaunchPlan(
        launcherPID: getpid(),
        launcherStartTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
        uid: getuid(),
        auditSessionID: cs_self_audit_session_id(),
        executable: executable,
        commandLine: commandLine,
        environment: ["PATH": "/usr/bin:/bin"],
        files: [.raw(environmentName: "SYNTHETIC_PREPARATION_FILE", reference: "op://vault/item/field", index: 0)],
        deliveryPlan: delivery
    )
}

/// cwd, stdin, stdout, stderr: the four descriptors a launcher hands rootd.
func preparationDescriptors() -> [Int32] {
    [
        open("/", O_RDONLY | O_DIRECTORY),
        open("/dev/null", O_RDONLY),
        open("/dev/null", O_WRONLY),
        open("/dev/null", O_WRONLY),
    ]
}
