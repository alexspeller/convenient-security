import Foundation
import CSECRootProtocol
import CSECRootServer

// Synthetic protocol/CLI fixture only. Unlike csec-rootd it does not mount,
// chown, or change credentials, so it proves rendezvous behavior but is not a
// same-UID security boundary.
let socketPath = RootHelperSocket.defaultPath()
let basePath = (socketPath as NSString).deletingLastPathComponent
let mountPath = (basePath as NSString).appendingPathComponent("files")

do {
    try FileManager.default.createDirectory(
        atPath: basePath,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    let mount = ProtectedTmpFS(
        mode: .syntheticTesting,
        basePath: basePath,
        mountPath: mountPath
    )
    try mount.prepare()
    let files = try ProtectedFileStore(mountPath: mountPath, mode: .syntheticTesting)
    try files.recoverAfterDaemonRestart()
    let coordinator = RootLaunchCoordinator(
        mode: .syntheticTesting,
        allocator: CapabilityGIDAllocator(mode: .syntheticTesting, basePath: basePath),
        files: files
    )
    let server = RootHelperServer(
        path: socketPath,
        peerTrustPolicy: .allowUnverifiedForTesting,
        coordinator: coordinator
    )
    try server.run()
} catch {
    FileHandle.standardError.write(Data("cs-fake-rootd: synthetic service failed\n".utf8))
    exit(1)
}
