import Foundation
import CSECRootProtocol

/// Agent-side half of the two-party root rendezvous. It embeds the ordinary
/// access request so policy and biometric consent are evaluated against the
/// exact same delivery plan that the launcher prepared with csec-rootd.
public struct ProtectedLaunchApprovalRequest: Codable, Sendable {
    public let requestID: String
    public let rendezvousNonce: String
    public let launchPlan: ProtectedLaunchPlan
    public let launchPlanDigest: String
    public let accessRequest: AccessRequest

    public init(
        rendezvousNonce: String,
        launchPlan: ProtectedLaunchPlan,
        launchPlanDigest: String,
        requestID: UUID = UUID()
    ) throws {
        self.requestID = requestID.uuidString.lowercased()
        self.rendezvousNonce = rendezvousNonce.lowercased()
        self.launchPlan = launchPlan
        self.launchPlanDigest = launchPlanDigest
        self.accessRequest = try AccessRequest(
            references: launchPlan.references,
            reason: launchPlan.deliveryPlan.operationContext,
            ttlSeconds: launchPlan.deliveryPlan.requestedTTLSeconds,
            deliveryPlan: launchPlan.deliveryPlan,
            commandLine: launchPlan.commandLine
        )
    }

    public func validate(caller: CallerInfo) -> Bool {
        guard UUID(uuidString: requestID) != nil,
              UUID(uuidString: rendezvousNonce) != nil,
              launchPlanDigest.count == 64,
              (try? launchPlan.digest()) == launchPlanDigest,
              (try? launchPlan.validate()) != nil,
              launchPlan.launcherPID == caller.pid,
              launchPlan.launcherStartTime == caller.startTime,
              launchPlan.uid == caller.peerIdentity?.audit.effectiveUID,
              launchPlan.auditSessionID == caller.peerIdentity?.audit.auditSessionID,
              accessRequest.references == launchPlan.references,
              accessRequest.reason == launchPlan.deliveryPlan.operationContext,
              accessRequest.ttlSeconds == launchPlan.deliveryPlan.requestedTTLSeconds,
              accessRequest.deliveryPlan == launchPlan.deliveryPlan,
              accessRequest.commandLine == launchPlan.commandLine,
              accessRequest.deliveryPlanDigest == (try? launchPlan.deliveryPlan.digest()) else {
            return false
        }
        return true
    }
}

extension ProtectedLaunchApprovalRequest {
    /// csecd's answer when the root helper will not take this approved launch's
    /// files. A launch that is no longer prepared (its launcher exited or
    /// cancelled it, or the root helper restarted and forgot it) is told apart
    /// from a refusal, so the human whose approval was spent learns that running
    /// the command again is the fix rather than suspecting the helper.
    public func rootHelperRefusal(_ error: Error) -> Response {
        if case .launchExpired? = error as? ProtectedFileDeliveryError {
            return .failed(
                .invalidRequest,
                message: "the launch this approval was for is no longer waiting (its command exited "
                    + "or csec's root helper restarted), so nothing was delivered; run the command again",
                requestID: requestID
            )
        }
        return .failed(
            .deliveryNotSupported,
            message: "the authenticated root helper could not accept this launch",
            requestID: requestID
        )
    }
}
