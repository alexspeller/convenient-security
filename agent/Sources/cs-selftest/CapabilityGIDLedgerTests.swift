import ConvenientSecurity
import CSecuritySupport
import CSECRootProtocol
import CSECRootServer
import Darwin
import Foundation

// csec-rootd keeps its launch records in memory and spawns each child in its
// own session, so a restart (every package upgrade, a crash, `csec doctor`'s
// kickstart) used to leave every running protected tree alive with nobody
// left to enforce launcher death or a hard TTL on it (csec-0.39.24). rootd now
// records the GIDs it still manages beside the boot-scoped cursor and kills
// their holders on start. These checks drive that ledger with fake kernel
// probes, so they run unprivileged and never signal a real process.

private final class FakeCapabilityKernel: @unchecked Sendable {
    private let lock = NSLock()
    private var bootTimeValue: UInt64 = 1_000
    private var assigned: Set<UInt32> = []
    private var live: Set<UInt32> = []
    private var unkillable: Set<UInt32> = []
    private var killed: [UInt32] = []

    func set(bootTime: UInt64) { lock.withLock { bootTimeValue = bootTime } }
    func assign(_ gid: UInt32) { lock.withLock { _ = assigned.insert(gid) } }
    func hold(_ gid: UInt32) { lock.withLock { _ = live.insert(gid) } }
    func resistKill(_ gid: UInt32, _ resist: Bool) {
        lock.withLock { if resist { unkillable.insert(gid) } else { unkillable.remove(gid) } }
    }
    func takeKills() -> [UInt32] { lock.withLock { defer { killed = [] }; return killed } }
    func isLive(_ gid: UInt32) -> Bool { lock.withLock { live.contains(gid) } }

    var host: CapabilityGIDHost {
        CapabilityGIDHost(
            bootTime: { [self] in lock.withLock { bootTimeValue } },
            isAssigned: { [self] gid in lock.withLock { assigned.contains(gid) ? 1 : 0 } },
            hasLiveHolder: { [self] gid in lock.withLock { live.contains(gid) ? 1 : 0 } },
            terminateHolders: { [self] gid in
                lock.withLock {
                    killed.append(gid)
                    if unkillable.contains(gid) { return false }
                    live.remove(gid)
                    return true
                }
            }
        )
    }
}

func capabilityGIDLedgerTests() async {
    print("\n# csec-rootd restart recovery: managed capability GIDs")
    let base = URL(fileURLWithPath: "/tmp")
        .appendingPathComponent("cs-gidledger-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: base) }
    do {
        try FileManager.default.createDirectory(
            atPath: base.path, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
    } catch {
        check(false, "gid ledger: fixture directory could not be created (\(error))")
        return
    }
    let statePath = base.appendingPathComponent("gid-state.json").path
    let kernel = FakeCapabilityKernel()
    let low = CapabilityGIDAllocator.range.lowerBound

    func freshLedger() -> CapabilityGIDAllocator {
        CapabilityGIDAllocator(ledgerAt: statePath, host: kernel.host)
    }

    do {
        // The allocator skips an assigned group and an unrelated live holder;
        // neither may ever be recorded, or a restart would kill their holders.
        kernel.assign(low)
        kernel.hold(low + 1)
        let ledger = freshLedger()
        let first = try ledger.allocate()
        let second = try ledger.allocate()
        check(first == gid_t(low + 2) && second == gid_t(low + 3),
              "gid ledger: allocation skips assigned and live GIDs")
        check(try ledger.managedGIDs() == [low + 2, low + 3],
              "gid ledger: exactly the issued GIDs are recorded as managed, never the skipped ones")

        // A retired launch record stops being managed.
        try ledger.release(first)
        check(try ledger.managedGIDs() == [low + 3],
              "gid ledger: releasing a retired record's GID removes only that GID")

        // A restart: a new allocator over the same file, same boot. The still
        // managed tree is killed; the unrelated live holder and the released
        // GID are left alone.
        kernel.hold(low + 2)  // e.g. a soft-TTL survivor whose record was retired
        kernel.hold(low + 3)
        _ = kernel.takeKills()
        let restarted = freshLedger()
        try restarted.terminateTreesFromBeforeRestart()
        check(kernel.takeKills() == [low + 3],
              "gid ledger: restart recovery kills only the trees rootd still managed")
        check(!kernel.isLive(low + 3) && kernel.isLive(low + 1) && kernel.isLive(low + 2),
              "gid ledger: unrelated and released holders survive restart recovery")
        check(try restarted.managedGIDs().isEmpty,
              "gid ledger: a killed tree is no longer recorded after recovery")
        check(try restarted.allocate() == gid_t(low + 4),
              "gid ledger: restart recovery preserves the boot-scoped cursor (no GID reuse)")

        // A holder that survives the bounded rescans fails startup and stays
        // recorded, so launchd's retry tries again rather than serving launches
        // beside an unmanaged tree.
        kernel.hold(low + 4)
        kernel.resistKill(low + 4, true)
        checkThrows("gid ledger: a surviving holder fails restart recovery") {
            try freshLedger().terminateTreesFromBeforeRestart()
        }
        check(try freshLedger().managedGIDs() == [low + 4],
              "gid ledger: a surviving tree stays recorded for the next start")
        kernel.resistKill(low + 4, false)
        try freshLedger().terminateTreesFromBeforeRestart()
        check(try freshLedger().managedGIDs().isEmpty && !kernel.isLive(low + 4),
              "gid ledger: the retried start kills the survivor and clears it")

        // A reboot ends every process: a ledger from an earlier boot kills
        // nothing and restarts the cursor.
        _ = try freshLedger().allocate()
        kernel.set(bootTime: 2_000)
        _ = kernel.takeKills()
        try freshLedger().terminateTreesFromBeforeRestart()
        check(kernel.takeKills().isEmpty,
              "gid ledger: a cursor from an earlier boot kills nothing")
        // low is assigned and low+1 and low+2 are still held by live processes.
        check(try freshLedger().allocate() == gid_t(low + 3),
              "gid ledger: a new boot restarts the cursor at the range's low end, skipping held GIDs")
    } catch {
        check(false, "gid ledger: ledger checks threw (\(error))")
    }

    do {
        // A cursor written before managed GIDs were recorded still decodes.
        let legacy = #"{"bootTime":2000,"nextGID":50010}"#
        try Data(legacy.utf8).write(to: URL(fileURLWithPath: statePath))
        chmod(statePath, 0o600)
        _ = kernel.takeKills()
        try freshLedger().terminateTreesFromBeforeRestart()
        check(kernel.takeKills().isEmpty,
              "gid ledger: a cursor with no managed list recovers without killing anything")
        check(try freshLedger().allocate() == gid_t(50_010),
              "gid ledger: a cursor with no managed list keeps its position")

        try Data("not json".utf8).write(to: URL(fileURLWithPath: statePath))
        chmod(statePath, 0o600)
        checkThrows("gid ledger: an unreadable cursor fails restart recovery closed") {
            try freshLedger().terminateTreesFromBeforeRestart()
        }
        try FileManager.default.removeItem(atPath: statePath)
    } catch {
        check(false, "gid ledger: legacy and corrupt cursor checks threw (\(error))")
    }

    await coordinatorReleasesRetiredGIDs(base: base, kernel: kernel)
}

/// The coordinator must release a launch record's GID when it retires the
/// record, or a later restart would kill a tree rootd had already let go.
private func coordinatorReleasesRetiredGIDs(base: URL, kernel: FakeCapabilityKernel) async {
    let statePath = base.appendingPathComponent("coordinator-gid-state.json").path
    let mountPath = base.appendingPathComponent("files").path
    var sockets: [Int32] = [-1, -1]
    guard sockets.withUnsafeMutableBufferPointer({
        socketpair(AF_UNIX, SOCK_STREAM, 0, $0.baseAddress)
    }) == 0 else {
        check(false, "gid ledger: socketpair failed")
        return
    }
    defer { close(sockets[0]); close(sockets[1]) }
    do {
        try ProtectedTmpFS(mode: .syntheticTesting, basePath: base.path, mountPath: mountPath).prepare()
        let ledger = CapabilityGIDAllocator(ledgerAt: statePath, host: kernel.host)
        let coordinator = RootLaunchCoordinator(
            mode: .syntheticTesting,
            allocator: ledger,
            files: try ProtectedFileStore(mountPath: mountPath, mode: .syntheticTesting))
        guard let peer = PeerIdentity.socketPeer(fd: sockets[0]) else {
            check(false, "gid ledger: peer identity unavailable")
            return
        }
        let plan = try ledgerPlan()
        let digest = try plan.digest()
        let payloads = try ProtectedFilePayloadRenderer.render(
            bindings: plan.files,
            values: [plan.files[0].reference: Data("synthetic-ledger-value".utf8)])
        let descriptors = [
            open("/", O_RDONLY | O_DIRECTORY),
            open("/dev/null", O_RDONLY),
            open("/dev/null", O_WRONLY),
            open("/dev/null", O_WRONLY),
        ]
        let prepared = try await coordinator.prepare(
            plan: plan, planDigest: digest, peer: peer, descriptors: descriptors)
        guard let nonce = prepared.nonce else {
            check(false, "gid ledger: preparation returned no nonce")
            return
        }
        _ = try await coordinator.approve(
            nonce: nonce, planDigest: digest, payloads: payloads,
            expiresAt: nil, peer: peer)
        let issued = try ledger.managedGIDs()
        check(issued.count == 1, "gid ledger: an approved launch records its GID as managed")
        _ = try await coordinator.cancel(nonce: nonce, planDigest: digest, peer: peer)
        await coordinator.maintenance()
        check(try ledger.managedGIDs().isEmpty,
              "gid ledger: retiring a launch record releases its GID")
    } catch {
        check(false, "gid ledger: coordinator release checks threw (\(error))")
    }
}

private func ledgerPlan() throws -> ProtectedLaunchPlan {
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
        operationContext: "synthetic capability GID ledger self-test",
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
        files: [.raw(environmentName: "SYNTHETIC_LEDGER_FILE", reference: "op://vault/item/field", index: 0)],
        deliveryPlan: delivery
    )
}
