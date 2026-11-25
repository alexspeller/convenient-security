import CSecuritySupport
import Foundation
#if canImport(Darwin)
import Darwin
#endif

public enum SSHAgentSocket {
    public static let maximumFrameBytes = 256 * 1_024

    public static func defaultPath() -> String {
        #if DEBUG
        // Isolated integration tests need a socket that cannot collide with a
        // developer's installed agent. Release builds compile out this lookup.
        if let override = ProcessInfo.processInfo.environment["CSEC_SSH_SOCKET"],
           !override.isEmpty {
            return override
        }
        #endif
        return (AgentSocket.directory() as NSString).appendingPathComponent("ssh-agent.sock")
    }
}

/// Exact live-code requirement for the only process allowed to issue SSH wire
/// requests. A matching filename or self-signed `com.apple.ssh` identifier is
/// insufficient; Apple's requirement is checked against the kernel-selected
/// audit-token guest on every connection/revalidation. The kernel's facts for
/// the token (CS_VALID, cdhash, identifier) are read every time, and the
/// requirement's static half is evaluated by Security.framework once per
/// `ssh` cdhash (`LiveCodeRequirement`).
public enum SSHClientCodeIdentity {
    public static let requirement = "anchor apple and identifier \"com.apple.ssh\""

    public static func accepts(_ peer: PeerIdentity) -> Bool {
        guard peer.isCurrentUser,
              peer.audit.executablePath == "/usr/bin/ssh",
              peer.code.executablePath == "/usr/bin/ssh",
              peer.code.identifier == "com.apple.ssh",
              peer.code.signatureValid,
              peer.code.hardenedRuntime,
              peer.code.dangerousEntitlements.isEmpty else { return false }
        return LiveCodeRequirement.isSatisfied(by: peer.audit, requirement: requirement)
    }
}

public enum SSHSocketPeerTrustPolicy: Sendable {
    case requireAppleSSH
    case allowUnverifiedForTesting

    fileprivate func accepts(_ peer: PeerIdentity) -> Bool {
        switch self {
        case .requireAppleSSH: return SSHClientCodeIdentity.accepts(peer)
        case .allowUnverifiedForTesting: return peer.isCurrentUser
        }
    }
}

/// Stateful handler for one authenticated SSH-agent connection. The verified
/// session-bind lives only for this connection and is mandatory before signing.
public actor SSHAgentConnection {
    private enum Message {
        static let failure: UInt8 = 5
        static let success: UInt8 = 6
        static let requestIdentities: UInt8 = 11
        static let identitiesAnswer: UInt8 = 12
        static let signRequest: UInt8 = 13
        static let signResponse: UInt8 = 14
        static let extensionRequest: UInt8 = 27
        static let extensionFailure: UInt8 = 28
        static let extensionResponse: UInt8 = 29
    }

    private let provider: any SSHAgentKeyProvider
    private let caller: CallerInfo
    private let failureReporter: (@Sendable (String) -> Void)?
    private var binding: SSHDestinationBinding?

    public init(
        provider: any SSHAgentKeyProvider,
        caller: CallerInfo,
        failureReporter: (@Sendable (String) -> Void)? = nil
    ) {
        self.provider = provider
        self.caller = caller
        self.failureReporter = failureReporter
    }

    public func handle(_ message: Data) async -> Data {
        var requestType: UInt8?
        var diagnosticDetail = ""
        do {
            var reader = SSHWireReader(message)
            let type = try reader.readByte()
            requestType = type
            switch type {
            case Message.requestIdentities:
                guard reader.isAtEnd else { throw SSHProtectionError.malformedMessage }
                let keys = try await provider.listedSSHKeys()
                guard keys.count <= SSHKeyCatalog.maximumKeys else {
                    throw SSHProtectionError.catalogUnavailable
                }
                var response = SSHWireWriter()
                response.appendByte(Message.identitiesAnswer)
                response.appendUInt32(UInt32(keys.count))
                for key in keys {
                    response.appendString(key.publicKeyBlob)
                    response.appendString(key.label)
                }
                return response.data
            case Message.extensionRequest:
                let name = try reader.readUTF8(maximumBytes: 128)
                if name == "query" {
                    guard reader.isAtEnd else { throw SSHProtectionError.malformedMessage }
                    var response = SSHWireWriter()
                    response.appendByte(Message.extensionResponse)
                    response.appendString("query")
                    response.appendString("session-bind@openssh.com")
                    return response.data
                }
                guard name == "session-bind@openssh.com" else {
                    return Data([Message.extensionFailure])
                }
                let hostKey = try reader.readString(maximumBytes: 16 * 1_024)
                let sessionIdentifier = try reader.readString(maximumBytes: 1_024)
                let signature = try reader.readString(maximumBytes: 16 * 1_024)
                let forwarding = try reader.readByte()
                diagnosticDetail = " host_key_algorithm="
                    + SSHPublicKey.diagnosticAlgorithm(in: hostKey)
                    + " host_signature_algorithm="
                    + SSHPublicKey.diagnosticAlgorithm(in: signature)
                    + " forwarding=\(forwarding == 1) already_bound=\(binding != nil)"
                guard reader.isAtEnd, forwarding == 0 || forwarding == 1,
                      binding == nil else {
                    throw SSHProtectionError.destinationBindingInvalid
                }
                binding = try SSHDestinationBinding(
                    hostKeyBlob: hostKey,
                    sessionIdentifier: sessionIdentifier,
                    signature: signature,
                    isForwarding: forwarding == 1
                )
                return Data([Message.success])
            case Message.signRequest:
                guard let binding else {
                    throw SSHProtectionError.destinationBindingRequired
                }
                let keyBlob = try reader.readString(maximumBytes: 16 * 1_024)
                let signedData = try reader.readString(maximumBytes: SSHAgentSocket.maximumFrameBytes)
                let flags = try reader.readUInt32()
                guard reader.isAtEnd else { throw SSHProtectionError.malformedMessage }
                let signature = try await provider.signSSHAuthentication(
                    publicKeyBlob: keyBlob,
                    signedData: signedData,
                    flags: flags,
                    binding: binding,
                    caller: caller
                )
                var response = SSHWireWriter()
                response.appendByte(Message.signResponse)
                response.appendString(signature)
                return response.data
            default:
                // SSH wire add/remove/lock operations cannot mutate csec. The
                // authenticated JSON management protocol owns catalog changes.
                return Data([Message.failure])
            }
        } catch {
            // The serve loop cancels a request only when its peer has closed
            // the connection, so a cancelled request failed because its `ssh`
            // went away, whatever error the cancellation surfaced as.
            let reason = Task.isCancelled
                ? "requester_gone"
                : (error as? SSHProtectionError)?.diagnosticCode ?? "internal_error"
            failureReporter?(
                "message=\(requestType.map(String.init) ?? "unparsed") "
                    + "reason=\(reason)\(diagnosticDetail)"
            )
            return Data([Message.failure])
        }
    }
}

public final class SSHAgentServer: @unchecked Sendable {
    public enum ServerError: Error { case bindFailed(String) }

    private let path: String
    private let trustPolicy: SSHSocketPeerTrustPolicy
    private let provider: any SSHAgentKeyProvider
    private let firstFrameDeadline: TimeInterval
    private let diagnostics: @Sendable (String) -> Void

    /// `diagnostics` receives each value-free refusal line; production writes
    /// it to csecd's log (stderr).
    public init(
        path: String = SSHAgentSocket.defaultPath(),
        trustPolicy: SSHSocketPeerTrustPolicy = .requireAppleSSH,
        provider: any SSHAgentKeyProvider,
        firstFrameDeadline: TimeInterval = AgentLiveness.defaultFirstFrameDeadline,
        diagnostics: @escaping @Sendable (String) -> Void = { line in
            FileHandle.standardError.write(Data((line + "\n").utf8))
        }
    ) {
        self.path = path
        self.trustPolicy = trustPolicy
        self.provider = provider
        self.firstFrameDeadline = firstFrameDeadline
        self.diagnostics = diagnostics
    }

    public func run() throws {
        let listenFD = path.withCString { cs_listen_unix($0) }
        guard listenFD >= 0 else { throw ServerError.bindFailed(path) }
        _ = path.withCString { chmod($0, 0o600) }

        while true {
            let fd = cs_accept(listenFD)
            if fd < 0 { continue }
            let trustPolicy = self.trustPolicy
            let provider = self.provider
            let firstFrameDeadline = self.firstFrameDeadline
            let diagnostics = self.diagnostics
            Task.detached {
                await Self.serve(
                    fd: fd, trustPolicy: trustPolicy, provider: provider,
                    firstFrameDeadline: firstFrameDeadline, diagnostics: diagnostics
                )
            }
        }
    }

    private static func serve(
        fd: Int32,
        trustPolicy: SSHSocketPeerTrustPolicy,
        provider: any SSHAgentKeyProvider,
        firstFrameDeadline: TimeInterval,
        diagnostics: @escaping @Sendable (String) -> Void
    ) async {
        defer { close(fd) }
        // Every socket read and write and every code-signature check of the
        // peer runs on this connection's own queue, never on the cooperative
        // pool: each `ssh` holds its connection open for its whole session
        // (`ConnectionLane`).
        let lane = ConnectionLane("com.alexspeller.csecd.ssh-agent.connection")
        guard let peer = await lane.run({ PeerIdentity.socketPeer(fd: fd).flatMap { trustPolicy.accepts($0) ? $0 : nil } })
        else { return }
        let caller = CallerInfo(
            pid: peer.audit.pid,
            startTime: peer.audit.startTime,
            description: "Apple SSH [verified] (pid \(peer.audit.pid))",
            peerIdentity: peer
        )
        let connection = SSHAgentConnection(
            provider: provider,
            caller: caller,
            failureReporter: { diagnostic in
                diagnostics("csecd: SSH agent refused request (\(diagnostic))")
            }
        )

        // Bound ONLY the wait for the first frame: `ssh` connects to the agent
        // and immediately asks for identities, so a connection that says
        // nothing at all is stuck or abandoned and would otherwise park this
        // handler for the life of the daemon. The gap BETWEEN frames on an
        // established connection stays unbounded — one `ssh` session holds the
        // agent connection open across a long transfer and may go quiet for
        // many minutes between signatures.
        var isFirstFrame = true
        while true {
            let request: Data?
            if isFirstFrame {
                request = await lane.run { readSSHFrame(fd, silence: firstFrameDeadline) }
                isFirstFrame = false
            } else {
                request = await lane.run { readSSHFrame(fd) }
            }
            guard let request else { return }

            // The request runs as its own task so that the loss of its `ssh`
            // can cancel it — the same peer-exit watch `SocketServer.serve`
            // gives every csec client. Without it a signing review stays on
            // screen for an `ssh` that was interrupted, timed out, or lost its
            // tab, and a request still queued behind another review is later
            // presented for nobody. `peerHasClosed` peeks without consuming,
            // and `ssh` never pipelines behind a pending signature, so a live
            // client is never mistaken for a gone one.
            let work = Task { await connection.handle(request) }
            let requesterGone = SSHRequesterGoneFlag()
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
            let response = await work.value
            watch.cancel()
            // Nobody is reading: write nothing and close.
            if await requesterGone.isSet { return }
            guard let revalidated = await lane.run({ PeerIdentity.socketPeer(fd: fd).flatMap { trustPolicy.accepts($0) ? $0 : nil } }),
                  revalidated.audit.rawAuditToken == peer.audit.rawAuditToken,
                  await lane.run({ writeSSHFrame(fd, response) }) else { return }
        }
    }

    private static func readSSHFrame(_ fd: Int32) -> Data? {
        guard let header = readExactly(fd, 4) else { return nil }
        let length = (UInt32(header[0]) << 24) | (UInt32(header[1]) << 16)
            | (UInt32(header[2]) << 8) | UInt32(header[3])
        guard length > 0, length <= UInt32(SSHAgentSocket.maximumFrameBytes),
              let bytes = readExactly(fd, Int(length)) else { return nil }
        return Data(bytes)
    }

    private static func readSSHFrame(_ fd: Int32, silence: TimeInterval) -> Data? {
        guard case let .frame(header) = readExactly(fd, 4, silence: silence) else { return nil }
        let bytes = [UInt8](header)
        let length = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16)
            | (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        guard length > 0, length <= UInt32(SSHAgentSocket.maximumFrameBytes),
              case let .frame(body) = readExactly(fd, Int(length), silence: silence) else {
            return nil
        }
        return body
    }

    private static func writeSSHFrame(_ fd: Int32, _ data: Data) -> Bool {
        guard !data.isEmpty, data.count <= SSHAgentSocket.maximumFrameBytes else { return false }
        let length = UInt32(data.count)
        let header: [UInt8] = [
            UInt8((length >> 24) & 0xff), UInt8((length >> 16) & 0xff),
            UInt8((length >> 8) & 0xff), UInt8(length & 0xff),
        ]
        return writeExactly(fd, header + [UInt8](data))
    }
}

/// Set once when the requesting `ssh` has closed its connection, so the
/// response write is skipped and the connection closed.
private actor SSHRequesterGoneFlag {
    private(set) var isSet = false
    func set() { isSet = true }
}
