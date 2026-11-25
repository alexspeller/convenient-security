import Foundation
import CSECRootProtocol
import CSECRootServer
import Darwin

// The root helper deliberately contains no provider, Keychain, biometric, UI or
// shell surface, and no write a caller can aim. csec supplies only a bounded
// launch plan plus cwd/stdio descriptors; csecd separately supplies
// digest-bound bytes. csecd's host-audit requests name entries in a closed
// list that HostOpsExecutor maps to fixed system tools; its digest-bound
// changes to system configuration (preferences, launchd services, the root and
// guest accounts, /etc/kcpassword, /etc/pam.d/sudo_local, NVRAM boot-args) are
// the only writes outside the helper's own runtime directory.
guard geteuid() == 0 else {
    FileHandle.standardError.write(Data("csec-rootd: refusing to run without root privileges\n".utf8))
    exit(1)
}

do {
    let mount = ProtectedTmpFS(mode: .production)
    try mount.prepare()
    let files = try ProtectedFileStore(mountPath: mount.mountPath, mode: .production)
    // A daemon restart loses every launch record. Unlinking every stale session
    // prevents any new open; the boot-scoped allocator still refuses every
    // previously issued GID; and every tree rootd still managed is killed,
    // since its launcher has already given up and nothing else would enforce
    // launcher death or a hard TTL on it. Both run before any work is accepted.
    try files.recoverAfterDaemonRestart()
    let allocator = CapabilityGIDAllocator(mode: .production, basePath: mount.basePath)
    try allocator.terminateTreesFromBeforeRestart()
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
