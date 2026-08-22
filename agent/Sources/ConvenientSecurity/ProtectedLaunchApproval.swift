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
            deliveryPlan: launchPlan.deliveryPlan
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
              accessRequest.deliveryPlanDigest == (try? launchPlan.deliveryPlan.digest()) else {
            return false
        }
        return true
    }
}
