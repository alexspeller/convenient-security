import Foundation
import CSECRootProtocol
import CSECRootServer
import Darwin

// The root helper deliberately contains no provider, Keychain, biometric, UI,
// shell, or arbitrary-write surface. csec supplies only a bounded launch plan
// plus cwd/stdio descriptors; csecd separately supplies digest-bound bytes.
guard geteuid() == 0 else {
    FileHandle.standardError.write(Data("csec-rootd: refusing to run without root privileges\n".utf8))
    exit(1)
}

do {
    let mount = ProtectedTmpFS(mode: .production)
    try mount.prepare()
    let files = try ProtectedFileStore(mountPath: mount.mountPath, mode: .production)
    // A daemon restart invalidates prepared/ready launches. Existing open fds
    // remain valid, but unlinking every stale session prevents any new open;
    // the boot-scoped allocator still refuses every previously issued GID.
    try files.recoverAfterDaemonRestart()
    let allocator = CapabilityGIDAllocator(mode: .production, basePath: mount.basePath)
    let coordinator = RootLaunchCoordinator(
        mode: .production,
        allocator: allocator,
        files: files
    )
    let server = RootHelperServer(
        path: RootHelperSocket.canonicalPath,
        peerTrustPolicy: .requireProductPeers,
        coordinator: coordinator
    )
    FileHandle.standardError.write(Data("csec-rootd: protected launch service ready\n".utf8))
    try server.run()
} catch {
    FileHandle.standardError.write(Data("csec-rootd: startup security checks failed\n".utf8))
    exit(1)
}
