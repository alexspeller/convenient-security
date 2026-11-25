import Foundation
import CSecuritySupport
import CSECRootProtocol
import Darwin

public enum RootHelperPeerTrustPolicy: Sendable {
    case requireProductPeers
    case allowUnverifiedForTesting

    fileprivate func accepts(_ peer: PeerIdentity, role: ProductCodeRole) -> Bool {
        switch self {
        case .requireProductPeers:
            return peer.audit.effectiveUID != 0
                && peer.code.signatureValid
                && peer.code.role == role
        case .allowUnverifiedForTesting:
            return true
        }
    }

    fileprivate func acceptsAnyRequestPeer(_ peer: PeerIdentity) -> Bool {
        accepts(peer, role: .launcher) || accepts(peer, role: .agent)
    }
}

/// The descriptors rootd may hold at once, derived from its own caps, and the
/// RLIMIT_NOFILE it asks for. launchd starts a daemon at a 256-file soft limit,
/// below the 512 that the launch cap alone retains, and once the descriptors
/// run out the kernel drops every new connection: protected-file delivery then
/// fails for every user until a same-UID process's parked launchers exit.
public enum RootHelperDescriptorBudget {
    /// Concurrent connection threads; one more accepted socket waits for a slot.
    public static let connectionSlots = 32
    /// Each prepared or approved launch keeps its cwd and stdio descriptors.
    static let descriptorsPerLaunch = 4
    /// A connection's socket, the up to 8 rights a frame may carry before it is
    /// validated, and a host operation's pipes, with room to spare.
    static let descriptorsPerConnection = 16
    /// stdio, the listen socket, the mount directory, the GID cursor file, a
    /// file creation's directory chain and the runtime's own descriptors.
    static let fixedDescriptors = 64

    public static let required = rlim_t(
        RootLaunchCoordinator.maximumLaunchRecords * descriptorsPerLaunch
            + (connectionSlots + 1) * descriptorsPerConnection
            + fixedDescriptors
    )

    /// Raises the soft limit to `required`, and the hard limit too when it is
    /// lower and the caller is root. An unprivileged caller held by its hard
    /// limit gets as close as that allows. Returns the soft limit now in force.
    @discardableResult
    public static func raiseLimit() -> rlim_t {
        var current = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &current) == 0 else { return 0 }
        guard current.rlim_cur < required else { return current.rlim_cur }
        var wanted = current
        wanted.rlim_cur = required
        wanted.rlim_max = max(current.rlim_max, required)
        if setrlimit(RLIMIT_NOFILE, &wanted) != 0 {
            wanted = current
            wanted.rlim_cur = min(required, current.rlim_max)
            _ = setrlimit(RLIMIT_NOFILE, &wanted)
        }
        var now = rlimit()
        guard getrlimit(RLIMIT_NOFILE, &now) == 0 else { return 0 }
        return now.rlim_cur
    }
}

/// Narrow root socket server. It authenticates the complete live audit token
/// before decoding a request, authorizes the product role per operation, and
/// revalidates the same token/code image before replying.
public final class RootHelperServer: @unchecked Sendable {
    private let path: String
    private let peerTrustPolicy: RootHelperPeerTrustPolicy
    private let coordinator: RootLaunchCoordinator
    private let hostOperations: RootHostOperations

    /// `hostOperations` defaults to the coordinator's mode; tests pass their own
    /// to stand in a slow or failing host tool.
    public init(
        path: String,
        peerTrustPolicy: RootHelperPeerTrustPolicy,
        coordinator: RootLaunchCoordinator,
        hostOperations: RootHostOperations? = nil
    ) {
        self.path = path
        self.peerTrustPolicy = peerTrustPolicy
        self.coordinator = coordinator
        self.hostOperations = hostOperations ?? RootHostOperations(mode: coordinator.mode)
    }

    public func run() throws {
        let descriptorLimit = RootHelperDescriptorBudget.raiseLimit()
        if descriptorLimit < RootHelperDescriptorBudget.required {
            FileHandle.standardError.write(Data(
                ("root helper: descriptor limit \(descriptorLimit) is below the "
                 + "\(RootHelperDescriptorBudget.required) its launch and connection caps need\n").utf8))
        }
        let listenFD = path.withCString { cs_listen_unix($0) }
        var socketInfo = stat()
        guard listenFD >= 0,
              chmod(path, 0o666) == 0,
              lstat(path, &socketInfo) == 0,
              socketInfo.st_mode & S_IFMT == S_IFSOCK,
              socketInfo.st_uid == geteuid(),
              socketInfo.st_mode & 0o777 == 0o666 else {
            if listenFD >= 0 { close(listenFD) }
            throw RootHelperRuntimeError.unsafeRuntimePath
        }

        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + .milliseconds(250), repeating: .milliseconds(250))
        let coordinator = self.coordinator
        timer.setEventHandler { Task { await coordinator.maintenance() } }
        timer.resume()
        let connectionSlots = DispatchSemaphore(value: RootHelperDescriptorBudget.connectionSlots)
        defer {
            timer.cancel()
            close(listenFD)
        }

        while true {
            let fd = cs_accept(listenFD)
            // Retrying at once cannot spin on a queued connection: a failed
            // accept was either interrupted or has consumed its connection.
            // Even out of descriptors (EMFILE), xnu's accept takes the pending
            // connection off the queue and closes it rather than leaving it to
            // fail again (rdar://8554930), and cs_accept closes any it accepted.
            if fd < 0 { continue }
            connectionSlots.wait()
            guard Self.setFiniteIOTimeout(fd) else {
                close(fd)
                connectionSlots.signal()
                continue
            }
            let policy = peerTrustPolicy
            let hostOperations = self.hostOperations
            // Each connection gets its own thread, never a Swift concurrency
            // task: its socket reads and writes block for up to the 5 s
            // timeout, and the cooperative pool has only one thread per CPU,
            // so enough slow or silent clients there would stall every actor
            // in rootd. The connection slots bound these threads.
            let thread = Thread {
                defer { connectionSlots.signal() }
                Self.serve(
                    fd: fd,
                    policy: policy,
                    coordinator: coordinator,
                    hostOperations: hostOperations
                )
            }
            thread.name = "rootd connection"
            thread.start()
        }
    }

    private static func serve(
        fd: Int32,
        policy: RootHelperPeerTrustPolicy,
        coordinator: RootLaunchCoordinator,
        hostOperations: RootHostOperations
    ) {
        defer { close(fd) }
        guard let originalPeer = PeerIdentity.socketPeer(fd: fd),
              policy.acceptsAnyRequestPeer(originalPeer) else { return }

        var descriptors = [Int32](repeating: -1, count: 8)
        var bodyLength: UInt32 = 0
        let descriptorCount = descriptors.withUnsafeMutableBufferPointer {
            cs_receive_frame_header_with_fds(
                fd,
                &bodyLength,
                $0.baseAddress,
                Int32($0.count)
            )
        }
        guard descriptorCount >= 0,
              let body = readExactly(fd, Int(bodyLength)),
              let request = try? JSONDecoder().decode(
                RootHelperRequest.self,
                from: Data(body)
              ) else {
            for descriptor in descriptors where descriptor >= 0 { close(descriptor) }
            return
        }
        descriptors.removeSubrange(Int(descriptorCount)..<descriptors.count)

        let requestID = request.requestID
        guard UUID(uuidString: requestID) != nil,
              expectedDescriptorCount(for: request) == descriptorCount,
              policy.accepts(originalPeer, role: requiredRole(for: request)) else {
            for descriptor in descriptors where descriptor >= 0 { close(descriptor) }
            return
        }

        let receivedDescriptors = descriptors
        let response: RootHelperResponse
        switch request {
        case .hostRead, .hostApply:
            // Host-audit tools block for seconds each, so they run here on this
            // connection's own thread, never in the coordinator or on the
            // cooperative pool, where they would hold up launches and the
            // maintenance sweeps (RootHostOperations). They carry no descriptors.
            response = handleHost(request, hostOperations: hostOperations)
        default:
            response = waitFor {
                let response = await handle(
                    request,
                    peer: originalPeer,
                    descriptors: receivedDescriptors,
                    coordinator: coordinator
                )
                await coordinator.maintenance()
                return response
            }
        }

        guard let currentPeer = PeerIdentity.socketPeer(fd: fd),
              currentPeer.audit.rawAuditToken == originalPeer.audit.rawAuditToken,
              policy.accepts(currentPeer, role: requiredRole(for: request)),
              let encoded = try? JSONEncoder().encode(response) else { return }
        _ = writeFrame(fd, encoded)
    }

    /// Run `operation` on the concurrency pool and block this connection
    /// thread until it finishes. Only ever called from a connection thread,
    /// never from a task, so the wait cannot hold a cooperative thread.
    private static func waitFor<T: Sendable>(
        _ operation: @escaping @Sendable () async -> T
    ) -> T {
        let result = ConnectionResult<T>()
        let finished = DispatchSemaphore(value: 0)
        Task.detached {
            result.value = await operation()
            finished.signal()
        }
        finished.wait()
        return result.value!
    }

    private static func handle(
        _ request: RootHelperRequest,
        peer originalPeer: PeerIdentity,
        descriptors: [Int32],
        coordinator: RootLaunchCoordinator
    ) async -> RootHelperResponse {
        var descriptors = descriptors
        let requestID = request.requestID
        let response: RootHelperResponse
        do {
            let partial: RootHelperResponse
            switch request {
            case let .prepare(_, plan, digest):
                let transferredDescriptors = descriptors
                descriptors.removeAll()
                partial = try await coordinator.prepare(
                    plan: plan,
                    planDigest: digest,
                    peer: originalPeer,
                    descriptors: transferredDescriptors
                )
            case let .approve(_, nonce, digest, payloads, expiresAt):
                partial = try await coordinator.approve(
                    nonce: nonce,
                    planDigest: digest,
                    payloads: payloads,
                    expiresAt: expiresAt,
                    peer: originalPeer
                )
            case let .start(_, nonce, digest):
                partial = try await coordinator.start(
                    nonce: nonce,
                    planDigest: digest,
                    peer: originalPeer
                )
            case let .status(_, nonce, digest):
                partial = try await coordinator.status(
                    nonce: nonce,
                    planDigest: digest,
                    peer: originalPeer
                )
            case let .signal(_, nonce, digest, signal):
                partial = try await coordinator.sendSignal(
                    nonce: nonce,
                    planDigest: digest,
                    signal: signal,
                    peer: originalPeer
                )
            case let .cancel(_, nonce, digest):
                partial = try await coordinator.cancel(
                    nonce: nonce,
                    planDigest: digest,
                    peer: originalPeer
                )
            case .health:
                partial = RootHelperResponse(requestID: "", state: .prepared)
            case .hostRead, .hostApply:
                // serve answers these on the connection thread (handleHost).
                throw RootHelperRuntimeError.invalidTransition
            }
            response = partial.withRequestID(requestID)
        } catch {
            for descriptor in descriptors where descriptor >= 0 { close(descriptor) }
            response = rejection(requestID: requestID, error)
        }
        return response
    }

    /// Blocks the calling connection thread for as long as the host tools run.
    private static func handleHost(
        _ request: RootHelperRequest,
        hostOperations: RootHostOperations
    ) -> RootHelperResponse {
        let requestID = request.requestID
        do {
            let partial: RootHelperResponse
            switch request {
            case let .hostRead(_, query):
                partial = try hostOperations.read(query: query)
            case let .hostApply(_, change, digest):
                partial = try hostOperations.apply(change: change, digest: digest)
            default:
                throw RootHelperRuntimeError.invalidTransition
            }
            return partial.withRequestID(requestID)
        } catch {
            return rejection(requestID: requestID, error)
        }
    }

    private static func rejection(requestID: String, _ error: Error) -> RootHelperResponse {
        let message: String
        if let runtime = error as? RootHelperRuntimeError,
           runtime == .invalidRendezvous {
            message = "launch rendezvous expired"
        } else {
            message = "root-helper request was rejected"
        }
        return .failed(requestID: requestID, .invalidRequest, message)
    }

    private static func expectedDescriptorCount(for request: RootHelperRequest) -> Int32 {
        if case .prepare = request { return 4 }
        return 0
    }

    private static func setFiniteIOTimeout(_ fd: Int32) -> Bool {
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        let size = socklen_t(MemoryLayout<timeval>.size)
        let receive = withUnsafePointer(to: &timeout) {
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, $0, size)
        }
        let send = withUnsafePointer(to: &timeout) {
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, $0, size)
        }
        return receive == 0 && send == 0
    }

    private static func requiredRole(for request: RootHelperRequest) -> ProductCodeRole {
        switch request {
        case .approve, .hostRead, .hostApply:
            // The audit's privileged reads and reversible applies are driven only
            // by the resident agent (csecd), never the launcher.
            return .agent
        default:
            return .launcher
        }
    }
}

private extension RootHelperRequest {
    var requestID: String {
        switch self {
        case let .prepare(id, _, _), let .approve(id, _, _, _, _),
             let .start(id, _, _), let .status(id, _, _),
             let .signal(id, _, _, _), let .cancel(id, _, _), let .health(id),
             let .hostRead(id, _), let .hostApply(id, _, _):
            return id
        }
    }
}

private extension RootHelperResponse {
    func withRequestID(_ requestID: String) -> RootHelperResponse {
        RootHelperResponse(
            requestID: requestID,
            nonce: nonce,
            planDigest: planDigest,
            state: state,
            childPID: childPID,
            childStartTime: childStartTime,
            waitStatus: waitStatus,
            failure: failure,
            hostResult: hostResult
        )
    }
}

/// Carries a request's response from its task back to the connection thread
/// waiting on it; the semaphore orders the write before the read.
private final class ConnectionResult<T>: @unchecked Sendable {
    var value: T?
}

extension RootHelperRuntimeError: Equatable {}
