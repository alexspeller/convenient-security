import ConvenientSecurity
import CSECRootProtocol
import CSECRootServer
import Foundation

// Wire-level test of the two new privileged host-audit operations over the real
// framed root socket + RootHelperServer + RootLaunchCoordinator (synthetic mode).
// Proves: hostRead round-trips value-free output; hostApply with the correct
// digest applies; and hostApply with a mismatched digest is rejected — the
// fail-closed gate that keeps a tampered/unreviewed change from ever applying.
func hostAuditRootProtocolTests() {
    // Short base under /tmp: the socket path must fit in sun_path (~104 bytes),
    // which the long per-user /var/folders temp dir would overflow.
    let base = URL(fileURLWithPath: "/tmp")
        .appendingPathComponent("cs-hostops-\(UUID().uuidString)", isDirectory: true)
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
        check(false, "host-ops root protocol: synthetic server setup threw (\(error))")
        return
    }
    defer { try? FileManager.default.removeItem(at: base) }

    // Wait for the server to bind the socket.
    var waited = 0
    while !FileManager.default.fileExists(atPath: socketPath) && waited < 200 {
        usleep(10_000); waited += 1
    }
    let client = RootHelperClient(path: socketPath, trustPolicy: .allowUnverifiedForTesting)

    // hostRead: value-free synthetic output crosses the wire.
    if let result = try? client.hostRead(.sharingServices) {
        check(result.output.contains("synthetic"),
              "hostRead round-trips value-free output over the framed socket")
    } else {
        check(false, "hostRead did not return a result over the socket")
    }

    // hostApply with the correct digest applies (synthetic).
    let change = HostRootChange.enableApplicationFirewall
    guard let digest = try? change.digest() else {
        check(false, "hostApply: change digest failed to compute")
        return
    }
    if let applied = try? client.hostApply(change, digest: digest) {
        check(applied.applied, "hostApply with the correct digest applies (synthetic)")
    } else {
        check(false, "hostApply with the correct digest threw unexpectedly")
    }

    // hostApply with a mismatched digest is rejected — fails closed.
    checkThrows("hostApply with a mismatched digest is rejected (fails closed)") {
        _ = try client.hostApply(change, digest: "0000000000000000000000000000000000000000000000000000000000000000")
    }
}
