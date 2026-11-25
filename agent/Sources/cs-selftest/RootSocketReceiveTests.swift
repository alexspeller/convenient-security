import ConvenientSecurity
import CSecuritySupport
import CSECRootServer
import Darwin
import Foundation

// rootd's socket must survive clients that are slow, silent or malformed
// (csec-0.24). A silent client once pinned a rootd thread at 100% for good:
// after SO_RCVTIMEO expired, cs_receive_frame_header_with_fds walked the
// untouched control buffer, whose zeroed header Darwin's CMSG_NXTHDR returns
// forever. And each connection's blocking reads sat on Swift's fixed-width
// cooperative pool, so enough silent clients stalled every async task in rootd.
func rootSocketReceiveTests() {
    silentPeerReturnsPromptly()
    truncatedRightsAreRejected()
    silentClientsDoNotStallTheServer()
    descriptorBudgetCoversTheLaunchCap()
    // cs-fake-rootd follows CSEC_ROOT_SOCKET only in a debug build; a release
    // one would aim at the installed rootd's own socket.
    #if DEBUG
    descriptorLimitCoversTheConnectionSlots()
    descriptorExhaustionDoesNotSpin()
    #endif
}

/// Run `body` on its own thread and wait at most `seconds` for it. A body that
/// never returns is left running (the selftest exits at the end anyway), and
/// the caller gets nil.
private final class FinishBox<T>: @unchecked Sendable {
    var value: T?
}

private func finishes<T>(within seconds: TimeInterval, _ body: @escaping () -> T) -> T? {
    let box = FinishBox<T>()
    let done = DispatchSemaphore(value: 0)
    Thread.detachNewThread {
        box.value = body()
        done.signal()
    }
    guard done.wait(timeout: .now() + seconds) == .success else { return nil }
    return box.value
}

private func setReceiveTimeout(_ fd: Int32, milliseconds: Int) {
    var timeout = timeval(tv_sec: 0, tv_usec: Int32(milliseconds * 1000))
    _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
}

private func silentPeerReturnsPromptly() {
    var pair: [Int32] = [-1, -1]
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
        check(false, "root socket receive: socketpair failed (errno \(errno))")
        return
    }
    defer { close(pair[0]); close(pair[1]) }
    setReceiveTimeout(pair[0], milliseconds: 200)
    let receiver = pair[0]
    let outcome = finishes(within: 3) { () -> (Int32, Int32) in
        var bodyLength: UInt32 = 0
        var fds = [Int32](repeating: -1, count: 8)
        let result = cs_receive_frame_header_with_fds(receiver, &bodyLength, &fds, 8)
        return (result, errno)
    }
    check(outcome != nil,
          "root socket receive: a silent peer returns once SO_RCVTIMEO expires, rather than spinning")
    if let (result, error) = outcome {
        check(result == -1 && error == EAGAIN,
              "root socket receive: a silent peer fails with EAGAIN (got \(result), errno \(error))")
    }
}

/// More rights than the receive buffer holds: the kernel truncates the control
/// message (MSG_CTRUNC) but keeps the sender's cmsg_len, so the receiver must
/// bound the descriptors it reads by what was actually copied out.
private func truncatedRightsAreRejected() {
    var pair: [Int32] = [-1, -1]
    guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
        check(false, "root socket receive: socketpair failed (errno \(errno))")
        return
    }
    defer { close(pair[0]); close(pair[1]) }
    setReceiveTimeout(pair[0], milliseconds: 1000)

    let sentCount = 12
    var sent: [Int32] = []
    for _ in 0..<sentCount {
        let fd = open("/dev/null", O_RDONLY)
        guard fd >= 0 else {
            check(false, "root socket receive: could not open /dev/null")
            sent.forEach { close($0) }
            return
        }
        sent.append(fd)
    }
    defer { sent.forEach { close($0) } }
    // Descriptors the receiver must leave alone, whatever it reads.
    let bystanders = (0..<16).map { _ in open("/dev/null", O_RDONLY) }
    defer { bystanders.forEach { if $0 >= 0 { close($0) } } }

    var header: [UInt8] = [0, 0, 0, 2]
    let rightsBytes = sentCount * MemoryLayout<Int32>.size
    let headerSize = MemoryLayout<cmsghdr>.size
    let controlLength = headerSize + rightsBytes
    var control = [UInt8](repeating: 0, count: controlLength)
    control.withUnsafeMutableBytes { raw in
        var cmsg = cmsghdr(
            cmsg_len: socklen_t(controlLength),
            cmsg_level: SOL_SOCKET,
            cmsg_type: SCM_RIGHTS)
        withUnsafeBytes(of: &cmsg) { raw.copyMemory(from: $0) }
        sent.withUnsafeBytes { rights in
            UnsafeMutableRawBufferPointer(rebasing: raw[headerSize...]).copyMemory(from: rights)
        }
    }
    let sendResult = header.withUnsafeMutableBytes { headerBytes in
        control.withUnsafeMutableBytes { controlBytes -> Int in
            var iov = iovec(iov_base: headerBytes.baseAddress, iov_len: headerBytes.count)
            return withUnsafeMutablePointer(to: &iov) { iovPointer in
                var message = msghdr(
                    msg_name: nil, msg_namelen: 0,
                    msg_iov: iovPointer, msg_iovlen: 1,
                    msg_control: controlBytes.baseAddress,
                    msg_controllen: socklen_t(controlBytes.count),
                    msg_flags: 0)
                return sendmsg(pair[1], &message, 0)
            }
        }
    }
    guard sendResult == header.count else {
        check(false, "root socket receive: sendmsg of \(sentCount) rights failed (errno \(errno))")
        return
    }

    let receiver = pair[0]
    let outcome = finishes(within: 3) { () -> (Int32, Int32, [Int32]) in
        var bodyLength: UInt32 = 0
        var fds = [Int32](repeating: -1, count: 8)
        let result = cs_receive_frame_header_with_fds(receiver, &bodyLength, &fds, 8)
        return (result, errno, fds)
    }
    guard let (result, error, fds) = outcome else {
        check(false, "root socket receive: truncated rights return promptly")
        return
    }
    check(result == -1 && error == EPROTO,
          "root socket receive: truncated rights are rejected with EPROTO (got \(result), errno \(error))")
    check(fds.allSatisfy { $0 == -1 },
          "root socket receive: a rejected frame hands back no descriptors")
    check(bystanders.allSatisfy { $0 >= 0 && fcntl($0, F_GETFD) != -1 },
          "root socket receive: a truncated control message closes none of the receiver's other descriptors")
}

/// More silent clients than the cooperative pool has threads must not delay an
/// unrelated request until their receive timeouts fire.
private func silentClientsDoNotStallTheServer() {
    let base = URL(fileURLWithPath: "/tmp")
        .appendingPathComponent("cs-rootrx-\(UUID().uuidString)", isDirectory: true)
    let socketPath = base.appendingPathComponent("rootd.sock").path
    let mountPath = base.appendingPathComponent("files").path
    do {
        try FileManager.default.createDirectory(
            atPath: base.path, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        let mount = ProtectedTmpFS(mode: .syntheticTesting, basePath: base.path, mountPath: mountPath)
        try mount.prepare()
        let files = try ProtectedFileStore(mountPath: mountPath, mode: .syntheticTesting)
        let coordinator = RootLaunchCoordinator(
            mode: .syntheticTesting,
            allocator: CapabilityGIDAllocator(mode: .syntheticTesting, basePath: base.path),
            files: files)
        let server = RootHelperServer(
            path: socketPath, peerTrustPolicy: .allowUnverifiedForTesting, coordinator: coordinator)
        Thread.detachNewThread { try? server.run() }
    } catch {
        check(false, "root socket receive: synthetic server setup threw (\(error))")
        return
    }
    defer { try? FileManager.default.removeItem(at: base) }

    var waited = 0
    while !FileManager.default.fileExists(atPath: socketPath) && waited < 200 {
        usleep(10_000); waited += 1
    }
    let client = RootHelperClient(path: socketPath, trustPolicy: .allowUnverifiedForTesting)
    check((try? client.health()) != nil, "root socket receive: the synthetic server answers health")

    // rootd allows 32 connections; stay below that so the probe gets a slot.
    let silentCount = min(ProcessInfo.processInfo.activeProcessorCount + 8, 30)
    // The listen backlog is 16, so connect one at a time and let the accept
    // loop catch up rather than overflow it.
    let silent = (0..<silentCount).map { _ -> Int32 in
        for _ in 0..<100 {
            let fd = socketPath.withCString { cs_connect_unix($0) }
            if fd >= 0 { return fd }
            usleep(10_000)
        }
        return -1
    }
    defer { silent.forEach { if $0 >= 0 { close($0) } } }
    check(silent.allSatisfy { $0 >= 0 },
          "root socket receive: \(silentCount) silent clients connect")
    // Let the server accept them and start blocking on their headers.
    usleep(300_000)

    let started = DispatchTime.now()
    let answered = finishes(within: 3) { (try? client.health()) != nil }
    let elapsed = Double(DispatchTime.now().uptimeNanoseconds - started.uptimeNanoseconds) / 1e9
    check(answered == true,
          "root socket receive: health answers within 3 s while \(silentCount) silent clients hold connections"
          + " (took \(String(format: "%.2f", elapsed)) s)")
}

/// CPU time a process has used so far, in seconds, or nil once it has gone.
/// `ri_user_time` and `ri_system_time` count `mach_absolute_time` ticks.
private func cpuSeconds(of pid: pid_t) -> Double? {
    var usage = rusage_info_v0()
    let result = withUnsafeMutablePointer(to: &usage) { pointer in
        pointer.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) {
            proc_pid_rusage(pid, RUSAGE_INFO_V0, $0)
        }
    }
    var timebase = mach_timebase_info_data_t()
    guard result == 0, mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.denom > 0 else {
        return nil
    }
    let ticks = Double(usage.ri_user_time + usage.ri_system_time)
    return ticks * Double(timebase.numer) / Double(timebase.denom) / 1e9
}

/// A synthetic rootd started under `ulimit` limits, reachable at its socket.
private final class LimitedFakeRoot {
    let process = Process()
    let socketPath: String
    let client: RootHelperClient
    private let base: URL

    init?(limits: String, purpose: String) {
        guard let executable = Bundle.main.executableURL else {
            check(false, "\(purpose): cs-selftest knows its own path")
            return nil
        }
        let fakeRoot = executable.deletingLastPathComponent().appendingPathComponent("cs-fake-rootd")
        guard FileManager.default.isExecutableFile(atPath: fakeRoot.path) else {
            check(false, "\(purpose): the debug cs-fake-rootd sits beside cs-selftest")
            return nil
        }
        base = URL(fileURLWithPath: "/tmp")
            .appendingPathComponent("cs-rootfd-\(UUID().uuidString.prefix(8))", isDirectory: true)
        socketPath = base.appendingPathComponent("rootd.sock").path
        client = RootHelperClient(path: socketPath, trustPolicy: .allowUnverifiedForTesting)
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", "ulimit \(limits) && exec \"$0\"", fakeRoot.path]
        process.environment = ["PATH": "/usr/bin:/bin", "CSEC_ROOT_SOCKET": socketPath]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch {
            check(false, "\(purpose): cs-fake-rootd starts (\(error))")
            return nil
        }
        var waited = 0
        while !FileManager.default.fileExists(atPath: socketPath) && waited < 300 && process.isRunning {
            usleep(10_000); waited += 1
        }
    }

    func answersHealth(within seconds: TimeInterval) -> Bool {
        let client = self.client
        return finishes(within: seconds) { (try? client.health()) != nil } == true
    }

    /// Up to `count` connections that never send a byte. rootd closes each
    /// after its 5 s receive timeout, so a caller's checks stay well inside it.
    func idleClients(_ count: Int) -> [Int32] {
        var idle: [Int32] = []
        var refusals = 0
        while idle.count < count && refusals < 3 {
            let fd = socketPath.withCString { cs_connect_unix($0) }
            if fd >= 0 { idle.append(fd); refusals = 0 } else { refusals += 1 }
            usleep(5_000)
        }
        usleep(200_000)
        return idle
    }

    deinit {
        if process.isRunning { process.terminate() }
        process.waitUntilExit()
        try? FileManager.default.removeItem(at: base)
    }
}

/// rootd retains four descriptors per prepared launch, up to 128 launches,
/// but launchd starts a daemon at a 256-file soft limit (csec-0.39.22). Below
/// rootd's own caps, the kernel dropped every new connection once descriptors
/// ran out. Started at a 24-file soft limit, the synthetic rootd must lift
/// itself clear and keep serving with a connection in every slot but one.
private func descriptorLimitCoversTheConnectionSlots() {
    let purpose = "root descriptor budget"
    guard let root = LimitedFakeRoot(limits: "-S -n 24", purpose: purpose) else { return }
    guard root.answersHealth(within: 3) else {
        check(false, "\(purpose): the synthetic rootd answers health")
        return
    }
    let idle = root.idleClients(RootHelperDescriptorBudget.connectionSlots - 1)
    defer { idle.forEach { close($0) } }
    check(idle.count == RootHelperDescriptorBudget.connectionSlots - 1,
          "\(purpose): \(idle.count) idle clients connect")
    check(root.answersHealth(within: 3),
          "\(purpose): a rootd started at a 24-file soft limit still serves beside \(idle.count) idle connections")
}

/// The descriptor budget the server raises to covers what its own caps let it
/// hold, and an ordinary process can reach it from launchd's default soft limit.
private func descriptorBudgetCoversTheLaunchCap() {
    let purpose = "root descriptor budget"
    check(RootHelperDescriptorBudget.required
          >= rlim_t(RootLaunchCoordinator.maximumLaunchRecords * 4
                    + (RootHelperDescriptorBudget.connectionSlots + 1) * 9),
          "\(purpose): \(RootHelperDescriptorBudget.required) covers every retained launch's descriptors"
          + " and every connection's socket and rights")
    var original = rlimit()
    guard getrlimit(RLIMIT_NOFILE, &original) == 0 else {
        check(false, "\(purpose): getrlimit works")
        return
    }
    guard original.rlim_max >= RootHelperDescriptorBudget.required else {
        check(false, "\(purpose): this process's hard limit \(original.rlim_max) allows the budget")
        return
    }
    defer { var restore = original; _ = setrlimit(RLIMIT_NOFILE, &restore) }
    var lowered = original
    lowered.rlim_cur = 256
    guard setrlimit(RLIMIT_NOFILE, &lowered) == 0 else {
        check(false, "\(purpose): the soft limit lowers to launchd's 256")
        return
    }
    let raised = RootHelperDescriptorBudget.raiseLimit()
    var now = rlimit()
    check(getrlimit(RLIMIT_NOFILE, &now) == 0
          && raised == RootHelperDescriptorBudget.required
          && now.rlim_cur == RootHelperDescriptorBudget.required,
          "\(purpose): a 256 soft limit rises to the budget (reported \(raised), now \(now.rlim_cur))")
}

/// When the descriptors do run out, the kernel's accept() drops the pending
/// connection and fails with EMFILE (xnu's accept, rdar://8554930), so the
/// loop's immediate retry cannot spin on it. A synthetic rootd held at a hard
/// 32-file limit, which it cannot lift, flooded with idle clients past it, must
/// stay near idle and serve again once they leave.
private func descriptorExhaustionDoesNotSpin() {
    let purpose = "root socket pressure"
    guard let root = LimitedFakeRoot(limits: "-n 32", purpose: purpose) else { return }
    guard root.answersHealth(within: 3) else {
        check(false, "\(purpose): the synthetic rootd answers health under a 32-file limit")
        return
    }
    // Fewer clients than connection slots, so only a missing descriptor can
    // keep the probe out.
    var idle = root.idleClients(RootHelperDescriptorBudget.connectionSlots - 1)
    defer { idle.forEach { close($0) } }
    check(!root.answersHealth(within: 1),
          "\(purpose): \(idle.count) idle clients exhaust the synthetic rootd's descriptors")

    let pid = root.process.processIdentifier
    guard let before = cpuSeconds(of: pid) else {
        check(false, "\(purpose): the synthetic rootd is still running while flooded")
        return
    }
    // More connects while it is exhausted: each is dropped, never retried.
    let dropped = root.idleClients(16)
    dropped.forEach { close($0) }
    usleep(800_000)
    guard let after = cpuSeconds(of: pid) else {
        check(false, "\(purpose): the synthetic rootd survives descriptor exhaustion")
        return
    }
    let used = after - before
    check(used < 0.25,
          "\(purpose): an exhausted rootd does not spin (\(String(format: "%.2f", used)) s CPU in about 1 s)")

    idle.forEach { close($0) }
    idle.removeAll()
    check(root.answersHealth(within: 3),
          "\(purpose): rootd serves again once the idle clients leave")
}
