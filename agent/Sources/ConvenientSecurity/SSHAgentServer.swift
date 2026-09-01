import CSecuritySupport
import Foundation
import Security
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
/// insufficient; Security.framework evaluates Apple's requirement against the
/// kernel-selected audit-token guest on every connection/revalidation.
public enum SSHClientCodeIdentity {
    public static func accepts(_ peer: PeerIdentity) -> Bool {
        guard peer.isCurrentUser,
              peer.audit.executablePath == "/usr/bin/ssh",
              peer.code.executablePath == "/usr/bin/ssh",
              peer.code.identifier == "com.apple.ssh",
              peer.code.signatureValid,
              peer.code.hardenedRuntime,
              peer.code.dangerousEntitlements.isEmpty else { return false }

        let attributes = [
            kSecGuestAttributeAudit: peer.audit.rawAuditToken as CFData
        ] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(
            nil, attributes, SecCSFlags(rawValue: 0), &code
        ) == errSecSuccess, let code else { return false }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(
            "anchor apple and identifier \"com.apple.ssh\"" as CFString,
            SecCSFlags(rawValue: 0),
            &requirement
        ) == errSecSuccess, let requirement else { return false }
        return SecCodeCheckValidity(
            code,
            SecCSFlags(rawValue: UInt32(kSecCSStrictValidate)),
            requirement
        ) == errSecSuccess
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
    private var binding: SSHDestinationBinding?

    public init(provider: any SSHAgentKeyProvider, caller: CallerInfo) {
        self.provider = provider
        self.caller = caller
    }

    public func handle(_ message: Data) async -> Data {
        do {
            var reader = SSHWireReader(message)
            let type = try reader.readByte()
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
            return Data([Message.failure])
        }
    }
}

public final class SSHAgentServer: @unchecked Sendable {
    public enum ServerError: Error { case bindFailed(String) }

    private let path: String
    private let trustPolicy: SSHSocketPeerTrustPolicy
    private let provider: any SSHAgentKeyProvider

    public init(
        path: String = SSHAgentSocket.defaultPath(),
        trustPolicy: SSHSocketPeerTrustPolicy = .requireAppleSSH,
        provider: any SSHAgentKeyProvider
    ) {
        self.path = path
        self.trustPolicy = trustPolicy
        self.provider = provider
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
            Task.detached {
                await Self.serve(fd: fd, trustPolicy: trustPolicy, provider: provider)
            }
        }
    }

    private static func serve(
        fd: Int32,
        trustPolicy: SSHSocketPeerTrustPolicy,
        provider: any SSHAgentKeyProvider
    ) async {
        defer { close(fd) }
        guard let peer = PeerIdentity.socketPeer(fd: fd),
              trustPolicy.accepts(peer) else { return }
        let caller = CallerInfo(
            pid: peer.audit.pid,
            startTime: peer.audit.startTime,
            description: "Apple SSH [verified] (pid \(peer.audit.pid))",
            peerIdentity: peer
        )
        let connection = SSHAgentConnection(provider: provider, caller: caller)

        while let request = readSSHFrame(fd) {
            let response = await connection.handle(request)
            guard let revalidated = PeerIdentity.socketPeer(fd: fd),
                  revalidated.audit.rawAuditToken == peer.audit.rawAuditToken,
                  trustPolicy.accepts(revalidated),
                  writeSSHFrame(fd, response) else { return }
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
