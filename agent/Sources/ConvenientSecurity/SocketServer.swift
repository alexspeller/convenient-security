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
    private let liveness: AgentLiveness

    public init(
        path: String,
        clientTrustPolicy: SocketPeerTrustPolicy = .requireProductLauncher,
        liveness: AgentLiveness = .default,
        handler: @escaping Handler
    ) {
        self.path = path
        self.clientTrustPolicy = clientTrustPolicy
        self.liveness = liveness
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
            let acceptedAt = mach_absolute_time()
            let handler = self.handler
            let clientTrustPolicy = self.clientTrustPolicy
            let liveness = self.liveness
            // Detached so connection handling never inherits the caller's actor
            // isolation — `run()` may itself be invoked from the main actor.
            Task.detached {
                await SocketServer.serve(
                    fd: fd,
                    acceptedAt: acceptedAt,
                    clientTrustPolicy: clientTrustPolicy,
                    liveness: liveness,
                    handler: handler
                )
            }
        }
    }

    private static func serve(
        fd: Int32,
        acceptedAt: UInt64,
        clientTrustPolicy: SocketPeerTrustPolicy,
        liveness: AgentLiveness,
        handler: @escaping Handler
    ) async {
        defer { close(fd) }

        // Everything below that blocks on the socket or on a code-signature
        // check runs on this connection's own queues, never on the
        // cooperative pool (`ConnectionLane`).
        let reads = ConnectionLane("com.alexspeller.csecd.connection.reads")
        guard let peer = await reads.run({ PeerIdentity.socketPeer(fd: fd) }),
              peer.isCurrentUser,
              clientTrustPolicy.accepts(peer) else {
            // Reject before reading protocol bytes. This prevents an untrusted
            // peer from sending even reference metadata to the real agent.
            return
        }
        let identifiedAt = mach_absolute_time()
        let caller = CallerInfo(
            pid: peer.audit.pid,
            startTime: peer.audit.startTime,
            description: peer.displayDescription,
            peerIdentity: peer,
            acceptedAt: acceptedAt,
            identifiedAt: identifiedAt
        )
        let writer = ConnectionWriter(fd: fd, liveness: liveness)

        // Ordinary clients send one frame and close. The AI output broker keeps
        // this same authenticated connection open for bounded streaming chunks,
        // avoiding a code-signature lookup and socket handshake per 16 KiB.
        var isFirstFrame = true
        while true {
            let readingFirstFrame = isFirstFrame
            // Bound ONLY the wait for the very first frame. A peer that
            // connects and then says nothing would otherwise park this handler
            // for the life of the daemon. The gap BETWEEN frames on an
            // established connection is deliberately left unbounded: the AI
            // output broker holds one connection open for streaming chunks, and
            // a long-running child may legitimately produce no output for many
            // minutes without that meaning anything is wrong.
            let incoming: FrameReadOutcome
            if isFirstFrame {
                let firstFrameDeadline = liveness.firstFrameDeadline
                incoming = await reads.run { readFrame(fd, silence: firstFrameDeadline) }
                isFirstFrame = false
            } else {
                incoming = await reads.run { readFrame(fd).map { FrameReadOutcome.frame($0) } ?? .closed }
            }
            guard case let .frame(data) = incoming else {
                if readingFirstFrame {
                    noteSilentClose(peer: peer, acceptedAt: acceptedAt, identifiedAt: identifiedAt)
                }
                return
            }
            var stamped = caller
            stamped.requestReadAt = mach_absolute_time()
            let requestCaller = stamped

            guard let request = try? JSONDecoder().decode(Request.self, from: data) else {
                if let encoded = try? JSONEncoder().encode(
                    Response.failed(.invalidRequest, message: "malformed request")
                ) {
                    _ = await writer.writeResponse(encoded)
                }
                return
            }
            // Each verified role sends only its own requests: the sudo review
            // helper nothing but `sudo_remote_review`, `sudo_delegation`,
            // `sudo_terminal` and `sudo_review_end`, the launcher everything
            // but those. Refused
            // before the handler runs, so a refused request never reaches the
            // phone or any other csecd state.
            guard clientTrustPolicy.permits(request, from: peer) else {
                if let encoded = try? JSONEncoder().encode(
                    Response.failed(.unverifiedPeer, message: "this client may not send this request")
                ) {
                    _ = await writer.writeResponse(encoded)
                }
                return
            }

            let epoch = await writer.beginRequest()
            // The handler runs as its own task so that the loss of the
            // requesting client can cancel it. This is the cancellation source
            // the remote-approval withdrawal (csec-1xv.11) builds on.
            // A client that reads notices hears, mid-request, that its request
            // waits on a human (`HumanWait`); the epoch drops a notice that
            // would land after the response.
            let notices: RequestNoticeSink? = WireTransport.requestSupportsNotices(data)
                ? RequestNoticeSink { message in
                    Task { _ = await writer.writeNotice(message, epoch: epoch) }
                }
                : nil
            let work = Task {
                await RequestNotices.$sink.withValue(notices) { await handler(request, requestCaller) }
            }
            let requesterGone = RequesterGoneFlag()

            // Peer-exit watch. It applies to EVERY client, heartbeat opt-in or
            // not, because it reads nothing of the protocol: `peerHasClosed`
            // peeks without consuming, so a streaming client whose next frame
            // is already queued is correctly seen as alive.
            let watch = Task.detached {
                while !Task.isCancelled {
                    if peerHasClosed(fd) {
                        await requesterGone.set()
                        work.cancel()
                        return
                    }
                    try? await Task.sleep(
                        nanoseconds: UInt64(AgentLiveness.peerExitPollInterval * 1_000_000_000)
                    )
                }
            }

            // Opt-in only: a client that did not say it understands heartbeats
            // never receives one, so a foreign or older client sees a
            // byte-identical exchange to before.
            let beat: Task<Void, Never>? = WireTransport.requestSupportsHeartbeats(data)
                ? Task.detached {
                    await emitHeartbeats(
                        interval: liveness.heartbeatInterval,
                        epoch: epoch,
                        writer: writer,
                        onRequesterGone: {
                            await requesterGone.set()
                            work.cancel()
                        }
                    )
                }
                : nil

            let response = await work.value
            beat?.cancel()
            watch.cancel()
            // Nothing more belongs to this request but its response: retire
            // its heartbeats and notices now, so one still queued is dropped
            // rather than written after the response, or after the paths below
            // that return without one and close the descriptor.
            await writer.retire(epoch)
            if await requesterGone.isSet { return }

            // Bind every release to the same live, trusted code image checked
            // before the first request. This also catches an exec/image change
            // between chunks before any response bytes leave the agent.
            guard let revalidatedPeer = await reads.run({ PeerIdentity.socketPeer(fd: fd) }),
                  revalidatedPeer.audit.rawAuditToken == peer.audit.rawAuditToken,
                  revalidatedPeer.isCurrentUser,
                  clientTrustPolicy.accepts(revalidatedPeer) else { return }
            guard let encoded = try? JSONEncoder().encode(response),
                  await writer.writeResponse(encoded) else { return }
        }
    }

    /// Logs a verified csec client that connected and closed without sending
    /// a request at least `ClaudeDelegationService.slowRegistrationMilliseconds`
    /// after csecd accepted it. `csec hook claude` checks csecd's signature
    /// before it sends its registration and gives up silently at its deadline,
    /// so a registration it never sent leaves only this line. Value-free.
    private static func noteSilentClose(peer: PeerIdentity, acceptedAt: UInt64, identifiedAt: UInt64) {
        guard peer.code.role == .launcher else { return }
        let clock = DelegationProcessClock.live
        guard let note = silentCloseNote(
            acceptedAt: acceptedAt, identifiedAt: identifiedAt, now: mach_absolute_time(),
            milliseconds: clock.milliseconds
        ) else { return }
        FileHandle.standardError.write(Data("csecd: \(ClaudeDelegationService.logTimestamp(Date())) \(note)\n".utf8))
    }

    /// The line for a client that closed without a request, or nil when it
    /// went within `ClaudeDelegationService.slowRegistrationMilliseconds`.
    public static func silentCloseNote(
        acceptedAt: UInt64, identifiedAt: UInt64, now: UInt64, milliseconds: (UInt64) -> UInt64
    ) -> String? {
        guard now > acceptedAt,
              milliseconds(now - acceptedAt) >= ClaudeDelegationService.slowRegistrationMilliseconds
        else { return nil }
        let check = identifiedAt >= acceptedAt ? "\(milliseconds(identifiedAt - acceptedAt)) ms" : "unknown"
        return "a verified csec client closed without sending a request \(milliseconds(now - acceptedAt)) ms "
            + "after it connected (csecd's identity check took \(check)); "
            + "a csec hook that gives up before sending its registration ends like this"
    }

    /// Emit one heartbeat frame per interval until the request's response is
    /// written (the epoch retires), the task is cancelled, or the write fails.
    ///
    /// Every tick round-trips through the **main actor** on purpose. Every
    /// human-blocking path — the access, SSH and automation reviews, and the
    /// re-present after a screen unlock — presents its window on the main actor.
    /// A tick emitted from a detached background task alone would keep flowing
    /// while a deadlocked main actor held that prompt hostage, masking exactly
    /// the wedge the client's silence deadline exists to catch. Hopping here
    /// means a wedged main actor stops the ticks and the client gives up; a
    /// SIGSTOPped or fully deadlocked daemon stops them for free.
    private static func emitHeartbeats(
        interval: TimeInterval,
        epoch: Int,
        writer: ConnectionWriter,
        onRequesterGone: @Sendable @escaping () async -> Void
    ) async {
        while !Task.isCancelled {
            do {
                try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            } catch {
                return
            }
            await MainActor.run {}
            switch await writer.writeHeartbeat(epoch: epoch) {
            case .written:
                continue
            case .retired, .timedOut:
                return
            case .failed:
                // A write error on a live request is the second, opt-in-only
                // signal that the requester has gone: treat it exactly like the
                // peer-exit watch's EOF.
                await onRequesterGone()
                return
            }
        }
    }
}

/// Set once when the requesting client is known to be gone, so the response
/// write is skipped and the connection closed rather than writing into a socket
/// nobody is reading.
private actor RequesterGoneFlag {
    private(set) var isSet = false
    func set() { isSet = true }
}

/// Serializes every frame written on one connection, so a heartbeat can never
/// interleave with a response, and writes them on a queue of the connection's
/// own: a client that stops reading parks that queue's thread, never one of the
/// cooperative pool's (`ConnectionLane`).
///
/// `epoch` retires the heartbeats belonging to a request whose response has
/// already been written: a tick that loses the race is dropped rather than
/// written after the response. Without that, a streaming client would see a
/// stray frame between two responses. The epoch is read and changed only on
/// `queue`, in the same block as the write it guards, so that holds however
/// the callers' tasks interleave.
private final class ConnectionWriter: @unchecked Sendable {
    enum HeartbeatOutcome {
        case written
        case retired
        case timedOut
        case failed
    }

    private let fd: Int32
    private let liveness: AgentLiveness
    private let queue = DispatchQueue(label: "com.alexspeller.csecd.connection.writes")
    /// Read and written only on `queue`.
    private var epoch = 0

    init(fd: Int32, liveness: AgentLiveness) {
        self.fd = fd
        self.liveness = liveness
    }

    func beginRequest() async -> Int {
        await withCheckedContinuation { continuation in
            queue.async {
                self.epoch += 1
                continuation.resume(returning: self.epoch)
            }
        }
    }

    func writeHeartbeat(epoch: Int) async -> HeartbeatOutcome {
        let fd = self.fd
        let deadline = liveness.writeDeadline
        return await withCheckedContinuation { continuation in
            queue.async {
                guard epoch == self.epoch else {
                    continuation.resume(returning: .retired)
                    return
                }
                // Bounded: a client that has stopped reading must not be able
                // to park this queue (and with it the response) on a full
                // socket buffer.
                switch writeFrame(fd, WireTransport.heartbeatFrame(), silence: deadline) {
                case .written: continuation.resume(returning: .written)
                case .timedOut: continuation.resume(returning: .timedOut)
                case .failed: continuation.resume(returning: .failed)
                }
            }
        }
    }

    /// Retires `epoch`'s heartbeats and notices, if it is still current.
    func retire(_ epoch: Int) async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            queue.async {
                if epoch == self.epoch { self.epoch += 1 }
                continuation.resume()
            }
        }
    }

    func writeNotice(_ message: String, epoch: Int) async -> Bool {
        let fd = self.fd
        let deadline = liveness.writeDeadline
        let frame = WireTransport.noticeFrame(message)
        return await withCheckedContinuation { continuation in
            queue.async {
                guard epoch == self.epoch, !frame.isEmpty else {
                    continuation.resume(returning: false)
                    return
                }
                // Bounded like a heartbeat: a client that stopped reading
                // must not park the response behind a notice.
                switch writeFrame(fd, frame, silence: deadline) {
                case .written: continuation.resume(returning: true)
                case .timedOut, .failed: continuation.resume(returning: false)
                }
            }
        }
    }

    func writeResponse(_ data: Data) async -> Bool {
        let fd = self.fd
        return await withCheckedContinuation { continuation in
            queue.async {
                // Retire any heartbeat still in flight for the request being
                // answered.
                self.epoch += 1
                continuation.resume(returning: writeFrame(fd, data))
            }
        }
    }
}

/// Trust applied by a socket server before it reads a request, and to each
/// request it reads. The testing cases are constructor-only and must never be
/// selected by a shipping environment variable or command-line option.
public enum SocketPeerTrustPolicy: Sendable {
    /// The product launcher (`csec`) alone.
    case requireProductLauncher
    /// csecd's shipping policy: the product launcher, and the sudo review
    /// helper (`csec-sudo-review`), each for its own requests only
    /// (`permits(_:role:)`). The helper's one request mirrors a sudo review
    /// to the paired phone, whose answer ends a root authentication, so its
    /// live code identity is checked like the launcher's: team, identifier,
    /// hardened runtime, no weakening entitlement, and the Developer ID
    /// requirement evaluated against the kernel-selected code object.
    case requireProductClients
    case allowUnverifiedForTesting
    /// Tests only: every peer is accepted, and each request is gated as if
    /// the peer's verified role were `role`, so the per-role gate can be
    /// driven end to end by an ad-hoc-signed test binary.
    case assumeRoleForTesting(ProductCodeRole)
    /// Tests only: any peer whose live code still validates against its file
    /// (ad-hoc signing is enough), every request permitted. It turns away a
    /// process whose binary was replaced while it ran, as the shipping
    /// policies do, so an ad-hoc test build can drive that case.
    case requireValidSignatureForTesting

    fileprivate func accepts(_ peer: PeerIdentity) -> Bool {
        switch self {
        case .requireProductLauncher:
            return peer.code.signatureValid && peer.code.role == .launcher
        case .requireProductClients:
            return peer.code.signatureValid && Self.admits(role: peer.code.role)
        case .allowUnverifiedForTesting, .assumeRoleForTesting:
            return true
        case .requireValidSignatureForTesting:
            return peer.code.signatureValid
        }
    }

    fileprivate func permits(_ request: Request, from peer: PeerIdentity) -> Bool {
        switch self {
        case .requireProductLauncher, .requireProductClients:
            return Self.permits(request, role: peer.code.role)
        case .allowUnverifiedForTesting, .requireValidSignatureForTesting:
            return true
        case let .assumeRoleForTesting(role):
            return Self.permits(request, role: role)
        }
    }

    /// The verified roles `requireProductClients` lets connect at all.
    public static func admits(role: ProductCodeRole) -> Bool {
        switch role {
        case .launcher, .sudoReviewHelper: return true
        case .agent, .rootHelper, .other: return false
        }
    }

    /// Whether a peer whose verified role is `role` may send `request`. The
    /// sudo review helper may send only `sudo_remote_review`,
    /// `sudo_delegation` (with `sudo_pairing`), `sudo_terminal` and
    /// `sudo_review_end`; the launcher may send anything else, never those.
    /// No other role sends anything.
    public static func permits(_ request: Request, role: ProductCodeRole) -> Bool {
        let sudoHelperRequest = request.isSudoRemoteReview || request.isSudoDelegation
            || request.isSudoTerminal || request.isSudoReviewEnd
        switch role {
        case .launcher: return !sudoHelperRequest
        case .sudoReviewHelper: return sudoHelperRequest
        case .agent, .rootHelper, .other: return false
        }
    }
}
