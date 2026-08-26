import Foundation
import CSecuritySupport
import Darwin

public enum RootHelperServerTrustPolicy: Sendable {
    case requireProductRootHelper
    case allowUnverifiedForTesting

    fileprivate func accepts(_ peer: PeerIdentity) -> Bool {
        switch self {
        case .requireProductRootHelper:
            return peer.audit.effectiveUID == 0
                && peer.code.signatureValid
                && peer.code.role == .rootHelper
        case .allowUnverifiedForTesting:
            return true
        }
    }
}

public struct PreparedRootLaunch: Sendable {
    public let nonce: String
    public let planDigest: String

    public init(nonce: String, planDigest: String) {
        self.nonce = nonce
        self.planDigest = planDigest
    }
}

/// Authenticated client used by two different product roles: csec prepares,
/// starts, supervises, and cancels; csecd alone submits approved file bytes.
/// Every call opens a fresh socket so a waiting status request cannot prevent
/// the other party from completing the rendezvous.
public struct RootHelperClient: Sendable {
    private let path: String
    private let trustPolicy: RootHelperServerTrustPolicy

    public init(
        path: String = RootHelperSocket.defaultPath(),
        trustPolicy: RootHelperServerTrustPolicy = .requireProductRootHelper
    ) {
        self.path = path
        self.trustPolicy = trustPolicy
    }

    public func health() throws {
        let requestID = UUID().uuidString.lowercased()
        let response = try send(.health(requestID: requestID), requestID: requestID)
        guard response.state == .prepared,
              response.nonce == nil,
              response.planDigest == nil else {
            throw ProtectedFileDeliveryError.unavailableRootHelper
        }
    }

    public func prepare(
        plan: ProtectedLaunchPlan,
        cwdFD: Int32,
        stdinFD: Int32,
        stdoutFD: Int32,
        stderrFD: Int32
    ) throws -> PreparedRootLaunch {
        try plan.validate()
        let digest = try plan.digest()
        let requestID = UUID().uuidString.lowercased()
        let response = try sendWithDescriptors(
            .prepare(requestID: requestID, plan: plan, planDigest: digest),
            requestID: requestID,
            descriptors: [cwdFD, stdinFD, stdoutFD, stderrFD]
        )
        guard response.state == .prepared,
              let nonce = response.nonce,
              UUID(uuidString: nonce) != nil,
              response.planDigest == digest else {
            throw ProtectedFileDeliveryError.unavailableRootHelper
        }
        return PreparedRootLaunch(nonce: nonce.lowercased(), planDigest: digest)
    }

    public func approve(
        nonce: String,
        planDigest: String,
        payloads: [ProtectedFilePayload],
        expiresAt: Date
    ) throws {
        let requestID = UUID().uuidString.lowercased()
        let response = try send(
            .approve(
                requestID: requestID,
                nonce: nonce,
                planDigest: planDigest,
                payloads: payloads,
                expiresAt: expiresAt
            ),
            requestID: requestID
        )
        guard response.state == .ready,
              response.nonce == nonce,
              response.planDigest == planDigest else {
            throw ProtectedFileDeliveryError.unavailableRootHelper
        }
    }

    public func start(
        nonce: String,
        planDigest: String
    ) throws -> (pid: pid_t, startTime: UInt64) {
        let requestID = UUID().uuidString.lowercased()
        let response = try send(
            .start(requestID: requestID, nonce: nonce, planDigest: planDigest),
            requestID: requestID
        )
        guard response.state == .running,
              response.nonce == nonce,
              response.planDigest == planDigest,
              let pid = response.childPID, pid > 1,
              let startTime = response.childStartTime, startTime > 0 else {
            throw ProtectedFileDeliveryError.unavailableRootHelper
        }
        return (pid, startTime)
    }

    public func status(
        nonce: String,
        planDigest: String
    ) throws -> RootHelperResponse {
        let requestID = UUID().uuidString.lowercased()
        let response = try send(
            .status(requestID: requestID, nonce: nonce, planDigest: planDigest),
            requestID: requestID
        )
        guard response.state != nil,
              response.nonce == nonce,
              response.planDigest == planDigest else {
            throw ProtectedFileDeliveryError.unavailableRootHelper
        }
        return response
    }

    public func signal(
        _ signal: Int32,
        nonce: String,
        planDigest: String
    ) throws {
        let requestID = UUID().uuidString.lowercased()
        let response = try send(
            .signal(
                requestID: requestID,
                nonce: nonce,
                planDigest: planDigest,
                signal: signal
            ),
            requestID: requestID
        )
        guard response.state == .running,
              response.nonce == nonce,
              response.planDigest == planDigest else {
            throw ProtectedFileDeliveryError.unavailableRootHelper
        }
    }

    public func cancel(nonce: String, planDigest: String) {
        let requestID = UUID().uuidString.lowercased()
        _ = try? send(
            .cancel(requestID: requestID, nonce: nonce, planDigest: planDigest),
            requestID: requestID
        )
    }

    /// Run one allow-listed, value-free privileged host read (posture audit).
    /// Only the resident agent's code identity is accepted by the helper.
    public func hostRead(_ query: HostRootRead) throws -> HostHelperResult {
        let requestID = UUID().uuidString.lowercased()
        let response = try send(
            .hostRead(requestID: requestID, query: query),
            requestID: requestID
        )
        guard let result = response.hostResult else {
            throw ProtectedFileDeliveryError.unavailableRootHelper
        }
        return result
    }

    /// Apply one reversible, allow-listed privileged change, digest-bound to the
    /// exact change (which the helper independently recomputes and verifies).
    public func hostApply(_ change: HostRootChange, digest: String) throws -> HostHelperResult {
        let requestID = UUID().uuidString.lowercased()
        let response = try send(
            .hostApply(requestID: requestID, change: change, digest: digest),
            requestID: requestID
        )
        guard let result = response.hostResult else {
            throw ProtectedFileDeliveryError.unavailableRootHelper
        }
        return result
    }

    private func connect() throws -> Int32 {
        let fd = path.withCString { cs_connect_unix($0) }
        guard fd >= 0 else { throw ProtectedFileDeliveryError.unavailableRootHelper }
        guard let peer = PeerIdentity.socketPeer(fd: fd), trustPolicy.accepts(peer) else {
            close(fd)
            throw ProtectedFileDeliveryError.untrustedRootHelper
        }
        return fd
    }

    private func send(
        _ request: RootHelperRequest,
        requestID: String
    ) throws -> RootHelperResponse {
        let fd = try connect()
        defer { close(fd) }
        let encoded = try JSONEncoder().encode(request)
        guard writeFrame(fd, encoded), let data = readFrame(fd) else {
            throw ProtectedFileDeliveryError.unavailableRootHelper
        }
        return try validate(
            JSONDecoder().decode(RootHelperResponse.self, from: data),
            requestID: requestID
        )
    }

    private func sendWithDescriptors(
        _ request: RootHelperRequest,
        requestID: String,
        descriptors: [Int32]
    ) throws -> RootHelperResponse {
        guard descriptors.count == 4 else {
            throw ProtectedFileDeliveryError.invalidLaunchPlan
        }
        let fd = try connect()
        defer { close(fd) }
        let encoded = try JSONEncoder().encode(request)
        let headerResult = descriptors.withUnsafeBufferPointer { buffer in
            cs_send_frame_header_with_fds(
                fd,
                UInt32(encoded.count),
                buffer.baseAddress,
                Int32(buffer.count)
            )
        }
        guard headerResult == 0,
              writeExactly(fd, [UInt8](encoded)),
              let data = readFrame(fd) else {
            throw ProtectedFileDeliveryError.unavailableRootHelper
        }
        return try validate(
            JSONDecoder().decode(RootHelperResponse.self, from: data),
            requestID: requestID
        )
    }

    private func validate(
        _ response: RootHelperResponse,
        requestID: String
    ) throws -> RootHelperResponse {
        guard response.version == RootHelperWireProtocol.version,
              response.requestID == requestID else {
            throw ProtectedFileDeliveryError.unavailableRootHelper
        }
        if let failure = response.failure {
            if failure.code == .invalidRequest, failure.message == "launch rendezvous expired" {
                throw ProtectedFileDeliveryError.launchExpired
            }
            throw ProtectedFileDeliveryError.rootHelperFailure(failure.message)
        }
        return response
    }
}
