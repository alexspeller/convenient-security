import Foundation
import CSecuritySupport
#if canImport(Darwin)
import Darwin
#endif

/// Listens on a unix socket, authenticates each peer via the kernel audit token
/// (`LOCAL_PEERTOKEN`), reads one framed `Request`, and replies with a framed
/// `Response` from the supplied handler.
public final class SocketServer: @unchecked Sendable {
    public typealias Handler = @Sendable (Request, CallerInfo) async -> Response

    private let path: String
    private let clientTrustPolicy: SocketPeerTrustPolicy
    private let handler: Handler

    public init(
        path: String,
        clientTrustPolicy: SocketPeerTrustPolicy = .requireProductLauncher,
        handler: @escaping Handler
    ) {
        self.path = path
        self.clientTrustPolicy = clientTrustPolicy
        self.handler = handler
    }

    public enum ServerError: Error { case bindFailed(String) }

    /// Bind + listen, then accept connections forever. Blocking — run on a
    /// dedicated thread.
    public func run() throws {
        let listenFD = path.withCString { cs_listen_unix($0) }
        guard listenFD >= 0 else { throw ServerError.bindFailed(path) }

        while true {
            let fd = cs_accept(listenFD)
            if fd < 0 { continue }
            let handler = self.handler
            let clientTrustPolicy = self.clientTrustPolicy
            // Detached so connection handling never inherits the caller's actor
            // isolation — `run()` may itself be invoked from the main actor.
            Task.detached {
                await SocketServer.serve(
                    fd: fd,
                    clientTrustPolicy: clientTrustPolicy,
                    handler: handler
                )
            }
        }
    }

    private static func serve(
        fd: Int32,
        clientTrustPolicy: SocketPeerTrustPolicy,
        handler: Handler
    ) async {
        defer { close(fd) }

        guard let peer = PeerIdentity.socketPeer(fd: fd),
              peer.isCurrentUser,
              clientTrustPolicy.accepts(peer) else {
            // Reject before reading protocol bytes. This prevents an untrusted
            // peer from sending even reference metadata to the real agent.
            return
        }
        let caller = CallerInfo(
            pid: peer.audit.pid,
            startTime: peer.audit.startTime,
            description: peer.displayDescription,
            peerIdentity: peer
        )

        // Ordinary clients send one frame and close. The AI output broker keeps
        // this same authenticated connection open for bounded streaming chunks,
        // avoiding a code-signature lookup and socket handshake per 16 KiB.
        while let data = readFrame(fd) {
            guard let request = try? JSONDecoder().decode(Request.self, from: data) else {
                if let encoded = try? JSONEncoder().encode(
                    Response.failed(.invalidRequest, message: "malformed request")
                ) {
                    _ = writeFrame(fd, encoded)
                }
                return
            }
            let response = await handler(request, caller)

            // Bind every release to the same live, trusted code image checked
            // before the first request. This also catches an exec/image change
            // between chunks before any response bytes leave the agent.
            guard let revalidatedPeer = PeerIdentity.socketPeer(fd: fd),
                  revalidatedPeer.audit.rawAuditToken == peer.audit.rawAuditToken,
                  revalidatedPeer.isCurrentUser,
                  clientTrustPolicy.accepts(revalidatedPeer) else { return }
            guard let encoded = try? JSONEncoder().encode(response),
                  writeFrame(fd, encoded) else { return }
        }
    }
}

/// Trust applied by a socket server before it reads a request. The testing case
/// is constructor-only and must never be selected by a shipping environment
/// variable or command-line option.
public enum SocketPeerTrustPolicy: Sendable {
    case requireProductLauncher
    case allowUnverifiedForTesting

    fileprivate func accepts(_ peer: PeerIdentity) -> Bool {
        switch self {
        case .requireProductLauncher:
            return peer.code.signatureValid && peer.code.role == .launcher
        case .allowUnverifiedForTesting:
            return true
        }
    }
}
