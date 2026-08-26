import Foundation
import CSecuritySupport
import CSECRootProtocol
import Darwin

public enum RootHelperRuntimeMode: Sendable, Equatable {
    case production
    case syntheticTesting
}

public enum RootHelperRuntimeError: Error, LocalizedError {
    case rootRequired
    case unsafeRuntimePath
    case mountFailed
    case mountVerificationFailed
    case gidStateUnavailable
    case gidPoolExhausted
    case invalidDescriptors
    case invalidPeer
    case invalidRendezvous
    case invalidTransition
    case fileCreationFailed
    case spawnFailed

    public var errorDescription: String? {
        switch self {
        case .rootRequired: return "root privileges are required"
        case .unsafeRuntimePath: return "a root-helper runtime path is unsafe"
        case .mountFailed: return "the bounded tmpfs could not be mounted"
        case .mountVerificationFailed: return "the protected-file mount is missing required bounds or flags"
        case .gidStateUnavailable: return "the boot-scoped GID allocation state is unavailable"
        case .gidPoolExhausted: return "the boot-scoped capability GID pool is exhausted"
        case .invalidDescriptors: return "the launch descriptors are invalid"
        case .invalidPeer: return "the authenticated peer does not match the launch"
        case .invalidRendezvous: return "the launch rendezvous is invalid or expired"
        case .invalidTransition: return "the launch rendezvous is in the wrong state"
        case .fileCreationFailed: return "protected files could not be created"
        case .spawnFailed: return "the protected child could not be launched"
        }
    }
}

/// Root-owned mount preparation. Production never accepts a caller-selected
/// path or mount option; the fixed constants are also re-verified with statfs
/// after mount_tmpfs returns.
public final class ProtectedTmpFS: @unchecked Sendable {
    public static let maximumBytes: UInt64 = 32 * 1024 * 1024
    public static let maximumNodes: UInt64 = 2_048

    public let basePath: String
    public let mountPath: String
    private let mode: RootHelperRuntimeMode

    public init(
        mode: RootHelperRuntimeMode,
        basePath: String = RootHelperSocket.canonicalDirectory,
        mountPath: String = RootHelperSocket.canonicalMountPath
    ) {
        self.mode = mode
        self.basePath = basePath
        self.mountPath = mountPath
    }

    public func prepare() throws {
        switch mode {
        case .production:
            guard geteuid() == 0 else { throw RootHelperRuntimeError.rootRequired }
            try ensureDirectory(basePath, owner: 0, mode: 0o755)
            try ensureDirectory(mountPath, owner: 0, mode: 0o711)

            let existing = mountPath.withCString {
                cs_secure_tmpfs_status($0, Self.maximumBytes, Self.maximumNodes)
            }
            if existing != 1 {
                guard existing == 0 else { throw RootHelperRuntimeError.mountVerificationFailed }
                let process = Process()
                process.executableURL = URL(fileURLWithPath: "/sbin/mount_tmpfs")
                process.arguments = [
                    "-o", "nodev,nosuid,noexec,nobrowse",
                    "-n", String(Self.maximumNodes),
                    "-s", String(Self.maximumBytes),
                    mountPath,
                ]
                process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
                process.standardInput = FileHandle.nullDevice
                process.standardOutput = FileHandle.nullDevice
                process.standardError = FileHandle.nullDevice
                do {
                    try process.run()
                    process.waitUntilExit()
                } catch {
                    throw RootHelperRuntimeError.mountFailed
                }
                guard process.terminationReason == .exit, process.terminationStatus == 0 else {
                    throw RootHelperRuntimeError.mountFailed
                }
            }
            guard mountPath.withCString({
                cs_secure_tmpfs_status($0, Self.maximumBytes, Self.maximumNodes)
            }) == 1 else {
                throw RootHelperRuntimeError.mountVerificationFailed
            }
            guard chmod(mountPath, 0o711) == 0, chown(mountPath, 0, 0) == 0 else {
                throw RootHelperRuntimeError.unsafeRuntimePath
            }
        case .syntheticTesting:
            try FileManager.default.createDirectory(
                atPath: mountPath,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
    }

    private func ensureDirectory(_ path: String, owner: uid_t, mode: mode_t) throws {
        var info = stat()
        if lstat(path, &info) != 0 {
            guard errno == ENOENT, mkdir(path, mode) == 0 else {
                throw RootHelperRuntimeError.unsafeRuntimePath
            }
            guard lstat(path, &info) == 0 else {
                throw RootHelperRuntimeError.unsafeRuntimePath
            }
        }
        guard info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == owner,
              info.st_nlink >= 1,
              info.st_mode & 0o022 == 0,
              chown(path, owner, 0) == 0,
              chmod(path, mode) == 0 else {
            throw RootHelperRuntimeError.unsafeRuntimePath
        }
    }
}

/// A monotonic cursor is persisted outside the tmpfs with the current boot
/// timestamp. Advancing and fsyncing it happens before a GID is returned, so a
/// daemon crash cannot make an allocated capability available for reuse.
public final class CapabilityGIDAllocator: @unchecked Sendable {
    private struct State: Codable {
        let bootTime: UInt64
        var nextGID: UInt32
    }

    public static let range: ClosedRange<UInt32> = 50_000...59_999

    private let mode: RootHelperRuntimeMode
    private let statePath: String

    public init(mode: RootHelperRuntimeMode, basePath: String) {
        self.mode = mode
        self.statePath = (basePath as NSString).appendingPathComponent("gid-state.json")
    }

    public func allocate() throws -> gid_t {
        if case .syntheticTesting = mode { return getgid() }
        guard geteuid() == 0 else { throw RootHelperRuntimeError.rootRequired }
        let bootTime = cs_boot_time()
        guard bootTime > 0 else { throw RootHelperRuntimeError.gidStateUnavailable }

        let fd = open(statePath, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw RootHelperRuntimeError.gidStateUnavailable }
        defer {
            _ = flock(fd, LOCK_UN)
            close(fd)
        }
        guard flock(fd, LOCK_EX) == 0 else {
            throw RootHelperRuntimeError.gidStateUnavailable
        }
        var info = stat()
        guard fchown(fd, 0, 0) == 0,
              fchmod(fd, 0o600) == 0,
              fstat(fd, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == 0,
              info.st_nlink == 1,
              info.st_mode & 0o777 == 0o600 else {
            throw RootHelperRuntimeError.gidStateUnavailable
        }

        guard let bytes = readBounded(fd: fd, maximum: 4_096) else {
            throw RootHelperRuntimeError.gidStateUnavailable
        }
        var state: State
        if bytes.isEmpty {
            state = State(bootTime: bootTime, nextGID: Self.range.lowerBound)
        } else {
            guard let decoded = try? JSONDecoder().decode(State.self, from: Data(bytes)) else {
                // Corruption fails closed. Resetting an unreadable cursor could
                // reuse a credential still held by an orphaned descendant.
                throw RootHelperRuntimeError.gidStateUnavailable
            }
            state = decoded.bootTime == bootTime
                ? decoded
                : State(bootTime: bootTime, nextGID: Self.range.lowerBound)
        }

        var candidate = max(state.nextGID, Self.range.lowerBound)
        while Self.range.contains(candidate) {
            let assigned = cs_gid_is_assigned(candidate)
            let live = cs_gid_has_live_holder(candidate)
            guard assigned >= 0, live >= 0 else {
                throw RootHelperRuntimeError.gidStateUnavailable
            }
            let next = candidate == UInt32.max ? candidate : candidate + 1
            state.nextGID = next
            try persist(state, fd: fd)
            if assigned == 0, live == 0 { return gid_t(candidate) }
            candidate = next
        }
        throw RootHelperRuntimeError.gidPoolExhausted
    }

    private func persist(_ state: State, fd: Int32) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let data = try? encoder.encode(state), data.count <= 4_096,
              ftruncate(fd, 0) == 0 else {
            throw RootHelperRuntimeError.gidStateUnavailable
        }
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return 0 }
                return pwrite(fd, base.advanced(by: offset), data.count - offset, off_t(offset))
            }
            if written > 0 { offset += written }
            else if written < 0, errno == EINTR { continue }
            else { throw RootHelperRuntimeError.gidStateUnavailable }
        }
        guard fsync(fd) == 0 else { throw RootHelperRuntimeError.gidStateUnavailable }
    }

    private func readBounded(fd: Int32, maximum: Int) -> [UInt8]? {
        var bytes = [UInt8](repeating: 0, count: maximum + 1)
        let count = bytes.withUnsafeMutableBytes { buffer in
            pread(fd, buffer.baseAddress, buffer.count, 0)
        }
        guard count >= 0, count <= maximum else { return nil }
        return Array(bytes.prefix(count))
    }
}

public struct ProtectedFileSession: Sendable {
    public let nonce: String
    public let gid: gid_t
    public let environment: [String: String]
    fileprivate let relativeFiles: [String]
}

/// Descriptor-relative creator for the only writable privileged namespace.
/// Every directory and file is opened with O_NOFOLLOW and checked after open.
public final class ProtectedFileStore: @unchecked Sendable {
    private let mountPath: String
    private let mode: RootHelperRuntimeMode
    private let mountFD: Int32

    public init(mountPath: String, mode: RootHelperRuntimeMode) throws {
        self.mountPath = mountPath
        self.mode = mode
        mountFD = open(mountPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard mountFD >= 0 else { throw RootHelperRuntimeError.unsafeRuntimePath }
    }

    deinit { close(mountFD) }

    public func recoverAfterDaemonRestart() throws {
        let entries = try FileManager.default.contentsOfDirectory(atPath: mountPath)
        for entry in entries {
            guard UUID(uuidString: entry) != nil else {
                throw RootHelperRuntimeError.unsafeRuntimePath
            }
            // No untrusted process can write the mount root or a 0050 session.
            // Removing the UUID entry unlinks rather than follows any symlink,
            // while creation itself remains entirely descriptor-relative.
            try FileManager.default.removeItem(
                atPath: (mountPath as NSString).appendingPathComponent(entry)
            )
        }
    }

    public func create(
        nonce: String,
        gid: gid_t,
        bindings: [ProtectedFileBinding],
        payloads: [ProtectedFilePayload]
    ) throws -> ProtectedFileSession {
        guard UUID(uuidString: nonce) != nil,
              !bindings.isEmpty,
              bindings.count <= ProtectedLaunchPlan.maximumFiles,
              payloads.map(\.relativePath) == bindings.map(\.relativePath),
              Set(payloads.map(\.relativePath)).count == payloads.count,
              Set(bindings.map(\.environmentName)).count == bindings.count,
              bindings.allSatisfy({ binding in
                  ProtectedLaunchPlan.validRelativePath(
                      binding.relativePath,
                      allowDirectory: false
                  )
                      && ProtectedLaunchPlan.validRelativePath(
                          binding.environmentRelativePath,
                          allowDirectory: true
                      )
                      && (binding.relativePath == binding.environmentRelativePath
                          || binding.relativePath.hasPrefix(
                              binding.environmentRelativePath + "/"
                      ))
                      && ProtectedLaunchPlan.validEnvironmentName(binding.environmentName)
                      && !binding.environmentName.hasPrefix("CSEC_")
              }),
              payloads.allSatisfy({
                  !$0.data.isEmpty
                      && $0.data.count <= ProtectedFilePayloadRenderer.maximumFileBytes
              }),
              payloads.reduce(0, { $0 + $1.data.count })
                <= ProtectedFilePayloadRenderer.maximumTotalBytes else {
            throw RootHelperRuntimeError.fileCreationFailed
        }
        let directoryMode: mode_t = mode == .production ? 0o050 : 0o700
        let fileMode: mode_t = mode == .production ? 0o040 : 0o400
        let owner: uid_t = mode == .production ? 0 : getuid()
        let group: gid_t = mode == .production ? gid : getgid()
        let sessionName = nonce.lowercased()

        guard mkdirat(mountFD, sessionName, directoryMode) == 0 else {
            throw RootHelperRuntimeError.fileCreationFailed
        }
        var sessionFD: Int32 = -1
        do {
            guard fchownat(
                mountFD,
                sessionName,
                owner,
                group,
                AT_SYMLINK_NOFOLLOW
            ) == 0 else {
                throw RootHelperRuntimeError.fileCreationFailed
            }
            sessionFD = try openCheckedDirectory(
                parentFD: mountFD,
                component: sessionName,
                owner: owner,
                group: group,
                mode: directoryMode
            )
            for payload in payloads {
                try createFile(
                    sessionFD: sessionFD,
                    relativePath: payload.relativePath,
                    data: payload.data,
                    owner: owner,
                    group: group,
                    directoryMode: directoryMode,
                    fileMode: fileMode
                )
            }
            close(sessionFD)
            sessionFD = -1
            let prefix = (mountPath as NSString).appendingPathComponent(sessionName)
            let environment = Dictionary(uniqueKeysWithValues: bindings.map {
                ($0.environmentName, (prefix as NSString).appendingPathComponent($0.environmentRelativePath))
            })
            return ProtectedFileSession(
                nonce: sessionName,
                gid: gid,
                environment: environment,
                relativeFiles: payloads.map(\.relativePath)
            )
        } catch {
            if sessionFD >= 0 { close(sessionFD) }
            try? cleanup(nonce: sessionName)
            throw error
        }
    }

    public func cleanup(nonce: String) throws {
        guard UUID(uuidString: nonce) != nil else {
            throw RootHelperRuntimeError.unsafeRuntimePath
        }
        let path = (mountPath as NSString).appendingPathComponent(nonce.lowercased())
        var info = stat()
        if lstat(path, &info) != 0 {
            if errno == ENOENT { return }
            throw RootHelperRuntimeError.fileCreationFailed
        }
        guard info.st_mode & S_IFMT == S_IFDIR else {
            throw RootHelperRuntimeError.unsafeRuntimePath
        }
        try FileManager.default.removeItem(atPath: path)
    }

    private func createFile(
        sessionFD: Int32,
        relativePath: String,
        data: Data,
        owner: uid_t,
        group: gid_t,
        directoryMode: mode_t,
        fileMode: mode_t
    ) throws {
        let components = relativePath.split(separator: "/").map(String.init)
        guard ProtectedLaunchPlan.validRelativePath(relativePath, allowDirectory: false),
              components.count >= 2 else {
            throw RootHelperRuntimeError.fileCreationFailed
        }
        var currentFD = dup(sessionFD)
        guard currentFD >= 0 else { throw RootHelperRuntimeError.fileCreationFailed }
        defer { if currentFD >= 0 { close(currentFD) } }

        for component in components.dropLast() {
            let created: Bool
            if mkdirat(currentFD, component, directoryMode) == 0 {
                created = true
            } else if errno == EEXIST {
                created = false
            } else {
                throw RootHelperRuntimeError.fileCreationFailed
            }
            if created {
                guard fchownat(currentFD, component, owner, group, AT_SYMLINK_NOFOLLOW) == 0 else {
                    throw RootHelperRuntimeError.fileCreationFailed
                }
            }
            let nextFD = try openCheckedDirectory(
                parentFD: currentFD,
                component: component,
                owner: owner,
                group: group,
                mode: directoryMode
            )
            close(currentFD)
            currentFD = nextFD
        }

        let name = components.last!
        let fd = openat(
            currentFD,
            name,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            fileMode
        )
        guard fd >= 0 else { throw RootHelperRuntimeError.fileCreationFailed }
        defer { close(fd) }
        guard fchown(fd, owner, group) == 0,
              fchmod(fd, fileMode) == 0 else {
            throw RootHelperRuntimeError.fileCreationFailed
        }
        var offset = 0
        while offset < data.count {
            let written = data.withUnsafeBytes { buffer -> Int in
                guard let base = buffer.baseAddress else { return 0 }
                return Darwin.write(fd, base.advanced(by: offset), data.count - offset)
            }
            if written > 0 { offset += written }
            else if written < 0, errno == EINTR { continue }
            else { throw RootHelperRuntimeError.fileCreationFailed }
        }
        var info = stat()
        guard fstat(fd, &info) == 0,
              info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == owner,
              info.st_gid == group,
              info.st_nlink == 1,
              info.st_mode & 0o777 == fileMode else {
            throw RootHelperRuntimeError.fileCreationFailed
        }
    }

    private func openCheckedDirectory(
        parentFD: Int32,
        component: String,
        owner: uid_t,
        group: gid_t,
        mode: mode_t
    ) throws -> Int32 {
        let fd = openat(parentFD, component, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard fd >= 0 else { throw RootHelperRuntimeError.fileCreationFailed }
        guard fchown(fd, owner, group) == 0, fchmod(fd, mode) == 0 else {
            close(fd)
            throw RootHelperRuntimeError.fileCreationFailed
        }
        var info = stat()
        guard fstat(fd, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == owner,
              info.st_gid == group,
              info.st_mode & 0o777 == mode else {
            close(fd)
            throw RootHelperRuntimeError.fileCreationFailed
        }
        return fd
    }
}

private final class RootLaunchRecord: @unchecked Sendable {
    let nonce: String
    let plan: ProtectedLaunchPlan
    let planDigest: String
    let launcherAuditToken: Data
    let launcherUID: uid_t
    let launcherAuditSessionID: UInt32
    let supplementaryGroups: [UInt32]
    let preparedAt: Date
    var descriptors: [Int32]
    var state: RootLaunchState = .prepared
    var gid: gid_t?
    var fileSession: ProtectedFileSession?
    var expiresAt: Date?
    var childPID: pid_t?
    var childStartTime: UInt64?
    var waitStatus: Int32?
    var filesWereRemoved = false
    var statusWasObserved = false
    var requiresTreeTermination = false

    init(
        nonce: String,
        plan: ProtectedLaunchPlan,
        planDigest: String,
        launcher: PeerIdentity,
        supplementaryGroups: [UInt32],
        descriptors: [Int32],
        preparedAt: Date
    ) {
        self.nonce = nonce
        self.plan = plan
        self.planDigest = planDigest
        self.launcherAuditToken = launcher.audit.rawAuditToken
        self.launcherUID = launcher.audit.effectiveUID
        self.launcherAuditSessionID = launcher.audit.auditSessionID
        self.supplementaryGroups = supplementaryGroups
        self.descriptors = descriptors
        self.preparedAt = preparedAt
    }

    deinit { closeDescriptors() }

    func closeDescriptors() {
        for fd in descriptors where fd >= 0 { close(fd) }
        descriptors.removeAll()
    }
}

private final class CStringList {
    let pointers: [UnsafeMutablePointer<CChar>?]

    init(_ strings: [String]) throws {
        var result: [UnsafeMutablePointer<CChar>?] = []
        for string in strings {
            guard let pointer = strdup(string) else {
                for case let existing? in result { free(existing) }
                throw RootHelperRuntimeError.spawnFailed
            }
            result.append(pointer)
        }
        result.append(nil)
        pointers = result
    }

    deinit { for case let pointer? in pointers { free(pointer) } }
}

/// Serialized rendezvous and lifecycle owner. GID membership is the process-tree
/// marker, so daemonized descendants remain visible after ordinary ancestry is
/// lost and a GID is never recycled from this boot-scoped allocator.
public actor RootLaunchCoordinator {
    private static let preparationLifetime: TimeInterval = 60
    private static let finishedRecordLifetime: TimeInterval = 5 * 60
    private static let maximumLaunchRecords = 128

    private let mode: RootHelperRuntimeMode
    private let allocator: CapabilityGIDAllocator
    private let files: ProtectedFileStore
    private var records: [String: RootLaunchRecord] = [:]
    private var finishedAt: [String: Date] = [:]

    public init(
        mode: RootHelperRuntimeMode,
        allocator: CapabilityGIDAllocator,
        files: ProtectedFileStore
    ) {
        self.mode = mode
        self.allocator = allocator
        self.files = files
    }

    public func prepare(
        plan: ProtectedLaunchPlan,
        planDigest: String,
        peer: PeerIdentity,
        descriptors: [Int32],
        now: Date = Date()
    ) throws -> RootHelperResponse {
        maintenance(now: now)
        do {
            try plan.validate()
            guard (try plan.digest()) == planDigest,
                  records.count < Self.maximumLaunchRecords,
                  peer.audit.pid == plan.launcherPID,
                  peer.audit.startTime == plan.launcherStartTime,
                  peer.audit.effectiveUID == plan.uid,
                  peer.audit.auditSessionID == plan.auditSessionID,
                  ProcessAncestry.startTime(of: plan.launcherPID) == plan.launcherStartTime,
                  descriptors.count == 4,
                  Self.validDescriptors(descriptors, usesPTY: plan.usesPTY),
                  Self.executableClaimIsConservative(plan.executable) else {
                throw RootHelperRuntimeError.invalidPeer
            }
            var groups = [UInt32](repeating: 0, count: 16)
            let count = groups.withUnsafeMutableBufferPointer {
                cs_proc_groups(plan.launcherPID, $0.baseAddress, Int32($0.count))
            }
            guard count > 0, count <= groups.count else {
                throw RootHelperRuntimeError.invalidPeer
            }
            groups.removeSubrange(Int(count)..<groups.count)

            let nonce = UUID().uuidString.lowercased()
            records[nonce] = RootLaunchRecord(
                nonce: nonce,
                plan: plan,
                planDigest: planDigest,
                launcher: peer,
                supplementaryGroups: groups,
                descriptors: descriptors,
                preparedAt: now
            )
            return RootHelperResponse(
                requestID: "",
                nonce: nonce,
                planDigest: planDigest,
                state: .prepared
            )
        } catch {
            for fd in descriptors where fd >= 0 { close(fd) }
            throw error
        }
    }

    // MARK: Host posture audit — value-free privileged reads + reversible applies

    /// Run one allow-listed, read-only host query as root and return its bounded
    /// output for the verified agent to parse value-free. `query` selects a fixed
    /// command in `HostOpsExecutor`; no caller string is ever executed.
    public func hostRead(query: HostRootRead, peer: PeerIdentity) throws -> RootHelperResponse {
        let result: HostHelperResult
        switch mode {
        case .production:
            guard geteuid() == 0 else { throw RootHelperRuntimeError.rootRequired }
            result = HostOpsExecutor.read(query)
        case .syntheticTesting:
            result = HostOpsExecutor.syntheticRead(query)
        }
        return RootHelperResponse(requestID: "", hostResult: result)
    }

    /// Apply one reversible, allow-listed privileged change. The caller-supplied
    /// digest must equal this exact change's independently-recomputed digest, so
    /// a tampered or unreviewed change fails closed before any mutation.
    public func hostApply(
        change: HostRootChange,
        digest: String,
        peer: PeerIdentity
    ) throws -> RootHelperResponse {
        guard let expected = try? change.digest(), expected == digest else {
            throw RootHelperRuntimeError.invalidTransition
        }
        let result: HostHelperResult
        switch mode {
        case .production:
            guard geteuid() == 0 else { throw RootHelperRuntimeError.rootRequired }
            result = HostOpsExecutor.apply(change)
        case .syntheticTesting:
            result = HostHelperResult(exitCode: 0, applied: true)
        }
        return RootHelperResponse(requestID: "", hostResult: result)
    }

    public func approve(
        nonce: String,
        planDigest: String,
        payloads: [ProtectedFilePayload],
        expiresAt: Date,
        peer: PeerIdentity,
        now: Date = Date()
    ) throws -> RootHelperResponse {
        guard let record = matching(nonce: nonce, digest: planDigest),
              record.state == .prepared,
              now.timeIntervalSince(record.preparedAt) <= Self.preparationLifetime,
              peer.audit.effectiveUID == record.launcherUID,
              peer.audit.auditSessionID == record.launcherAuditSessionID,
              expiresAt > now,
              expiresAt.timeIntervalSince(now)
                <= TimeInterval(record.plan.deliveryPlan.requestedTTLSeconds),
              payloads.count == record.plan.files.count,
              payloads.map(\.relativePath) == record.plan.files.map(\.relativePath),
              payloads.allSatisfy({
                  !$0.data.isEmpty && $0.data.count <= ProtectedFilePayloadRenderer.maximumFileBytes
              }),
              payloads.reduce(0, { $0 + $1.data.count })
                <= ProtectedFilePayloadRenderer.maximumTotalBytes else {
            throw RootHelperRuntimeError.invalidRendezvous
        }
        let gid = try allocator.allocate()
        record.gid = gid
        let session: ProtectedFileSession
        do {
            session = try files.create(
                nonce: record.nonce,
                gid: gid,
                bindings: record.plan.files,
                payloads: payloads
            )
        } catch {
            // Retain a cancelled record when cleanup itself fails so periodic
            // maintenance keeps retrying the exact UUID instead of orphaning a
            // partially written plaintext tree.
            record.closeDescriptors()
            record.state = .cancelled
            finishedAt[nonce] = now
            removeFiles(record)
            throw error
        }
        record.fileSession = session
        record.expiresAt = expiresAt
        record.state = .ready
        return RootHelperResponse(
            requestID: "",
            nonce: nonce,
            planDigest: planDigest,
            state: .ready
        )
    }

    public func start(
        nonce: String,
        planDigest: String,
        peer: PeerIdentity,
        now: Date = Date()
    ) throws -> RootHelperResponse {
        guard let record = matching(nonce: nonce, digest: planDigest),
              record.state == .ready,
              sameLauncher(peer, record: record),
              let expiresAt = record.expiresAt, expiresAt > now,
              let gid = record.gid,
              let session = record.fileSession,
              record.descriptors.count == 4 else {
            throw RootHelperRuntimeError.invalidTransition
        }
        var environment = record.plan.environment
        for (name, path) in session.environment { environment[name] = path }
        let environmentEntries = environment.keys.sorted().compactMap { key in
            environment[key].map { "\(key)=\($0)" }
        }
        let argv = try CStringList(record.plan.commandLine)
        let envp = try CStringList(environmentEntries)
        var childPID: Int32 = -1
        var childStartTime: UInt64 = 0
        let groups = record.supplementaryGroups
        let spawnResult = argv.pointers.withUnsafeBufferPointer { argvBuffer in
            envp.pointers.withUnsafeBufferPointer { environmentBuffer in
                groups.withUnsafeBufferPointer { groupBuffer in
                    record.plan.executable.canonicalPath.withCString { executablePath in
                        cs_spawn_with_capability_gid(
                            executablePath,
                            UnsafeMutablePointer(mutating: argvBuffer.baseAddress),
                            UnsafeMutablePointer(mutating: environmentBuffer.baseAddress),
                            record.descriptors[0],
                            record.descriptors[1],
                            record.descriptors[2],
                            record.descriptors[3],
                            record.plan.uid,
                            gid,
                            groupBuffer.baseAddress,
                            Int32(groupBuffer.count),
                            mode == .production ? record.plan.auditSessionID : 0,
                            record.plan.usesPTY ? 1 : 0,
                            mode == .production ? 1 : 0,
                            &childPID,
                            &childStartTime
                        )
                    }
                }
            }
        }
        guard spawnResult == 0, childPID > 1, childStartTime > 0 else {
            removeFiles(record)
            record.closeDescriptors()
            record.state = .cancelled
            finishedAt[nonce] = now
            throw RootHelperRuntimeError.spawnFailed
        }
        record.closeDescriptors()
        record.childPID = childPID
        record.childStartTime = childStartTime
        record.state = .running

        let coordinator = self
        let launchedPID = childPID
        DispatchQueue.global(qos: .utility).async {
            var status: Int32 = 0
            var result: pid_t
            repeat { result = waitpid(launchedPID, &status, 0) } while result < 0 && errno == EINTR
            Task { await coordinator.childFinished(nonce: nonce, pid: launchedPID, status: status) }
        }
        return RootHelperResponse(
            requestID: "",
            nonce: nonce,
            planDigest: planDigest,
            state: .running,
            childPID: childPID,
            childStartTime: childStartTime
        )
    }

    public func status(
        nonce: String,
        planDigest: String,
        peer: PeerIdentity
    ) throws -> RootHelperResponse {
        guard let record = matching(nonce: nonce, digest: planDigest),
              sameLauncher(peer, record: record) else {
            throw RootHelperRuntimeError.invalidRendezvous
        }
        record.statusWasObserved = record.state == .finished
        return RootHelperResponse(
            requestID: "",
            nonce: nonce,
            planDigest: planDigest,
            state: record.state,
            childPID: record.childPID,
            childStartTime: record.childStartTime,
            waitStatus: record.waitStatus
        )
    }

    public func sendSignal(
        nonce: String,
        planDigest: String,
        signal: Int32,
        peer: PeerIdentity
    ) throws -> RootHelperResponse {
        let allowed: Set<Int32> = [
            SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGTERM, SIGKILL,
            SIGTSTP, SIGSTOP, SIGCONT, SIGWINCH,
        ]
        guard allowed.contains(signal),
              let record = matching(nonce: nonce, digest: planDigest),
              record.state == .running,
              sameLauncher(peer, record: record),
              let pid = record.childPID,
              let startTime = record.childStartTime,
              startTime > 0,
              ProcessAncestry.startTime(of: pid) == startTime,
              kill(-pid, signal) == 0 else {
            throw RootHelperRuntimeError.invalidRendezvous
        }
        return RootHelperResponse(
            requestID: "",
            nonce: nonce,
            planDigest: planDigest,
            state: .running,
            childPID: pid,
            childStartTime: startTime
        )
    }

    public func cancel(
        nonce: String,
        planDigest: String,
        peer: PeerIdentity
    ) throws -> RootHelperResponse {
        guard let record = matching(nonce: nonce, digest: planDigest),
              sameLauncher(peer, record: record) else {
            throw RootHelperRuntimeError.invalidRendezvous
        }
        if mode == .production,
           record.gid != nil,
           (record.state == .running || record.state == .finished) {
            requestTreeTermination(record)
        } else if record.state == .running,
                  let pid = record.childPID,
                  let start = record.childStartTime,
                  ProcessAncestry.startTime(of: pid) == start {
            _ = kill(-pid, SIGKILL)
            _ = kill(pid, SIGKILL)
        }
        removeFiles(record)
        record.closeDescriptors()
        record.state = .cancelled
        finishedAt[nonce] = Date()
        return RootHelperResponse(
            requestID: "",
            nonce: nonce,
            planDigest: planDigest,
            state: .cancelled
        )
    }

    public func maintenance(now: Date = Date()) {
        for (nonce, record) in records {
            if record.requiresTreeTermination, let gid = record.gid {
                _ = killAllHolders(of: gid)
            }
            switch record.state {
            case .prepared:
                if now.timeIntervalSince(record.preparedAt) > Self.preparationLifetime
                    || !launcherIsLive(record) {
                    removeFiles(record)
                    record.closeDescriptors()
                    record.state = .cancelled
                    finishedAt[nonce] = now
                }
            case .ready:
                if record.expiresAt.map({ now >= $0 }) == true || !launcherIsLive(record) {
                    removeFiles(record)
                    record.closeDescriptors()
                    record.state = .cancelled
                    finishedAt[nonce] = now
                }
            case .running:
                if !launcherIsLive(record) {
                    if mode == .production,
                       record.gid != nil,
                       !record.requiresTreeTermination {
                        requestTreeTermination(record)
                    } else if let pid = record.childPID,
                              record.childStartTime == ProcessAncestry.startTime(of: pid) {
                        removeFiles(record)
                        _ = kill(-pid, SIGKILL)
                        _ = kill(pid, SIGKILL)
                    }
                }
                if record.expiresAt.map({ now >= $0 }) == true {
                    removeFiles(record)
                    if record.plan.hardTTL,
                       mode == .production,
                       record.gid != nil,
                       !record.requiresTreeTermination {
                        requestTreeTermination(record)
                    } else if record.plan.hardTTL,
                              let pid = record.childPID,
                              record.childStartTime == ProcessAncestry.startTime(of: pid) {
                        _ = kill(-pid, SIGKILL)
                        _ = kill(pid, SIGKILL)
                    }
                }
            case .finished:
                if mode == .syntheticTesting {
                    removeFiles(record)
                } else if !record.statusWasObserved,
                          !launcherIsLive(record),
                          record.gid != nil {
                    // The launcher vanished before collecting its child's wait
                    // status. Treat that as an abandoned launch even if the
                    // direct child happened to exit first; daemonized holders
                    // must not turn the race into an unattended capability.
                    if !record.requiresTreeTermination {
                        requestTreeTermination(record)
                    }
                } else if let gid = record.gid, cs_gid_has_live_holder(gid) == 0 {
                    removeFiles(record)
                } else if record.expiresAt.map({ now >= $0 }) == true {
                    removeFiles(record)
                    if record.plan.hardTTL,
                       mode == .production,
                       record.gid != nil,
                       !record.requiresTreeTermination {
                        requestTreeTermination(record)
                    }
                }
            case .cancelled:
                removeFiles(record)
            }
        }
        for (nonce, date) in finishedAt {
            guard let record = records[nonce],
                  record.state == .cancelled
                    || (record.state == .finished
                        && (record.statusWasObserved
                            || (!launcherIsLive(record) && record.requiresTreeTermination)))
                    || now.timeIntervalSince(date) > Self.finishedRecordLifetime,
                  record.filesWereRemoved,
                  !record.requiresTreeTermination || treeIsGone(record) else {
                // A direct child can exit while a daemonized descendant still
                // holds the capability GID. Retain the record until that tree
                // disappears or TTL unlinks the files; otherwise a five-minute
                // bookkeeping timeout would orphan live plaintext in tmpfs.
                continue
            }
            records.removeValue(forKey: nonce)
            finishedAt.removeValue(forKey: nonce)
        }
    }

    private func childFinished(nonce: String, pid: pid_t, status: Int32) {
        guard let record = records[nonce], record.childPID == pid else { return }
        record.waitStatus = status
        if record.state == .running { record.state = .finished }
        finishedAt[nonce] = Date()
        if mode == .syntheticTesting {
            removeFiles(record)
        } else if let gid = record.gid, cs_gid_has_live_holder(gid) == 0 {
            removeFiles(record)
        }
    }

    private func matching(nonce: String, digest: String) -> RootLaunchRecord? {
        guard UUID(uuidString: nonce) != nil,
              digest.count == 64,
              let record = records[nonce.lowercased()],
              record.planDigest == digest else { return nil }
        return record
    }

    private func sameLauncher(_ peer: PeerIdentity, record: RootLaunchRecord) -> Bool {
        peer.audit.rawAuditToken == record.launcherAuditToken
            && peer.audit.pid == record.plan.launcherPID
            && peer.audit.startTime == record.plan.launcherStartTime
            && peer.audit.effectiveUID == record.launcherUID
            && peer.audit.auditSessionID == record.launcherAuditSessionID
    }

    private func launcherIsLive(_ record: RootLaunchRecord) -> Bool {
        ProcessAncestry.startTime(of: record.plan.launcherPID) == record.plan.launcherStartTime
    }

    @discardableResult
    private func removeFiles(_ record: RootLaunchRecord) -> Bool {
        guard !record.filesWereRemoved else { return true }
        do {
            try files.cleanup(nonce: record.nonce)
            record.filesWereRemoved = true
            return true
        } catch {
            return false
        }
    }

    private func requestTreeTermination(_ record: RootLaunchRecord) {
        removeFiles(record)
        record.requiresTreeTermination = true
        if let gid = record.gid { _ = killAllHolders(of: gid) }
    }

    private func treeIsGone(_ record: RootLaunchRecord) -> Bool {
        guard let gid = record.gid else { return true }
        return cs_gid_has_live_holder(gid) == 0
    }

    @discardableResult
    private func killAllHolders(of gid: gid_t) -> Bool {
        // A holder can fork between enumeration and SIGKILL delivery. Re-scan
        // until the kernel reports no holder rather than returning merely
        // because one snapshot fit in the output buffer.
        for _ in 0..<8 {
            var pids = [Int32](repeating: 0, count: 4_096)
            let count = pids.withUnsafeMutableBufferPointer {
                cs_pids_with_gid(gid, $0.baseAddress, Int32($0.count))
            }
            if count == 0 { return true }
            guard count > 0 else { return false }
            for pid in pids.prefix(min(Int(count), pids.count)) where pid > 1 {
                // Freeze the enumerated incarnation before the credential
                // recheck. If that PID was reused by a process without the
                // capability, resume it instead of delivering root's SIGKILL.
                guard kill(pid, SIGSTOP) == 0 else { continue }
                if cs_pid_has_gid(pid, gid) == 1 {
                    _ = kill(pid, SIGKILL)
                } else {
                    _ = kill(pid, SIGCONT)
                }
            }
            usleep(10_000)
        }
        return cs_gid_has_live_holder(gid) == 0
    }

    private static func executableClaimIsConservative(_ claimed: PlannedExecutable) -> Bool {
        guard let actual = try? ExecutableInspection.plannedExecutable(
            command: claimed.canonicalPath,
            environment: ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        ),
        actual.canonicalPath == claimed.canonicalPath,
        actual.signingIdentifier == claimed.signingIdentifier,
        actual.teamIdentifier == claimed.teamIdentifier,
        actual.cdHash == claimed.cdHash else { return false }
        return claimed.assurance == actual.assurance || claimed.assurance == .unverified
    }

    private static func validDescriptors(_ fds: [Int32], usesPTY: Bool) -> Bool {
        for (index, fd) in fds.enumerated() {
            var info = stat()
            let flags = fcntl(fd, F_GETFL)
            guard fd >= 0, fstat(fd, &info) == 0, flags >= 0 else { return false }
            if index == 0 {
                guard info.st_mode & S_IFMT == S_IFDIR,
                      flags & O_ACCMODE != O_WRONLY else { return false }
            } else {
                guard info.st_mode & S_IFMT != S_IFDIR else { return false }
                if index == 1, flags & O_ACCMODE == O_WRONLY { return false }
                if index >= 2, flags & O_ACCMODE == O_RDONLY { return false }
            }
        }
        if usesPTY {
            guard isatty(fds[1]) == 1, isatty(fds[2]) == 1, isatty(fds[3]) == 1 else {
                return false
            }
        }
        return true
    }
}
