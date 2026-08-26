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

/// Narrow root socket server. It authenticates the complete live audit token
/// before decoding a request, authorizes the product role per operation, and
/// revalidates the same token/code image before replying.
public final class RootHelperServer: @unchecked Sendable {
    private let path: String
    private let peerTrustPolicy: RootHelperPeerTrustPolicy
    private let coordinator: RootLaunchCoordinator

    public init(
        path: String,
        peerTrustPolicy: RootHelperPeerTrustPolicy,
        coordinator: RootLaunchCoordinator
    ) {
        self.path = path
        self.peerTrustPolicy = peerTrustPolicy
        self.coordinator = coordinator
    }

    public func run() throws {
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
        let connectionSlots = DispatchSemaphore(value: 32)
        defer {
            timer.cancel()
            close(listenFD)
        }

        while true {
            let fd = cs_accept(listenFD)
            if fd < 0 {
                if errno == EINTR { continue }
                continue
            }
            connectionSlots.wait()
            guard Self.setFiniteIOTimeout(fd) else {
                close(fd)
                connectionSlots.signal()
                continue
            }
            let policy = peerTrustPolicy
            Task.detached { [coordinator] in
                defer { connectionSlots.signal() }
                await Self.serve(
                    fd: fd,
                    policy: policy,
                    coordinator: coordinator
                )
            }
        }
    }

    private static func serve(
        fd: Int32,
        policy: RootHelperPeerTrustPolicy,
        coordinator: RootLaunchCoordinator
    ) async {
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
            case let .hostRead(_, query):
                partial = try await coordinator.hostRead(query: query, peer: originalPeer)
            case let .hostApply(_, change, digest):
                partial = try await coordinator.hostApply(
                    change: change,
                    digest: digest,
                    peer: originalPeer
                )
            }
            response = partial.withRequestID(requestID)
        } catch {
            for descriptor in descriptors where descriptor >= 0 { close(descriptor) }
            let message: String
            if let runtime = error as? RootHelperRuntimeError,
               runtime == .invalidRendezvous {
                message = "launch rendezvous expired"
            } else {
                message = "root-helper request was rejected"
            }
            response = .failed(requestID: requestID, .invalidRequest, message)
        }

        await coordinator.maintenance()
        guard let currentPeer = PeerIdentity.socketPeer(fd: fd),
              currentPeer.audit.rawAuditToken == originalPeer.audit.rawAuditToken,
              policy.accepts(currentPeer, role: requiredRole(for: request)),
              let encoded = try? JSONEncoder().encode(response) else { return }
        _ = writeFrame(fd, encoded)
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

extension RootHelperRuntimeError: Equatable {}
