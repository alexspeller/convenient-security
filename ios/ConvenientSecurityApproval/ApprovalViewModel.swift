import CSECRemoteApproval
import CSECRemoteApprovalCloudKit
import CryptoKit
import Foundation
import SwiftUI

struct PendingRemoteApproval: Identifiable, Equatable {
    let envelope: SignedRemoteApprovalRequest
    let mac: PinnedMac

    var id: String { envelope.request.requestID }
    var review: RemoteApprovalReview { envelope.request.review }
    var expiresAt: Date {
        Date(
            timeIntervalSince1970:
                TimeInterval(envelope.request.expiresAtMilliseconds) / 1_000
        )
    }
}

@MainActor
final class ApprovalViewModel: ObservableObject {
    @Published private(set) var phonePairingCode: String?
    @Published private(set) var pinnedMacs: [PinnedMac] = []
    @Published private(set) var pending: [PendingRemoteApproval] = []
    @Published private(set) var isRefreshing = false
    @Published var macPairingCode = ""
    @Published var message: String?

    private let identityStore = PhoneIdentityStore()
    private let relay = CloudKitRemoteApprovalRelay()
    private var identity: PhoneApprovalIdentity?
    private var completedRequestIDs: Set<String> = []
    private var started = false
    #if DEBUG && targetEnvironment(simulator)
    private var simulatorPending: [String: PendingRemoteApproval] = [:]
    private let simulatorMacKey = P256.Signing.PrivateKey()
    private let simulatorMacDeviceID = UUID().uuidString.lowercased()
    #endif

    func start() async {
        guard !started else { return }
        started = true
        do {
            identity = try identityStore.loadIdentity()
            pinnedMacs = try identityStore.loadPinnedMacs()
            try updatePhonePairingCode()
        } catch {
            identity = nil
            pinnedMacs = []
            phonePairingCode = nil
            message = "This iPhone’s approval identity must be set up again."
        }
        if identity != nil { _ = await refresh() }
    }

    func setUpPhone() {
        do {
            let created = try identityStore.createIdentity()
            identity = created
            pinnedMacs = []
            try updatePhonePairingCode()
            message = "Phone identity ready. Copy its pairing code to the Mac."
        } catch {
            #if DEBUG && targetEnvironment(simulator)
            message = "The simulator test identity could not be created."
            #else
            message = "Face ID and the Secure Enclave are required to set up this iPhone."
            #endif
        }
    }

    func pairMac() async {
        guard identity != nil else {
            message = "Set up this iPhone first."
            return
        }
        let code = macPairingCode.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            let pairing = try RemoteApprovalPairingCode.decodeMac(code)
            pinnedMacs = try await identityStore.pinMac(pairing)
            macPairingCode = ""
            message = "Paired with \(pairing.macDeviceName). Remote approvals are ready."
            _ = await refresh()
        } catch {
            message = "The Mac pairing code was not accepted."
        }
    }

    @discardableResult
    func refresh() async -> Bool {
        guard !isRefreshing, identity != nil, !pinnedMacs.isEmpty else { return false }
        isRefreshing = true
        defer { isRefreshing = false }
        do {
            try await relay.ensureRequestSubscription()
            let envelopes = try await relay.pendingRequests()
            let now = currentTimeMilliseconds()
            var verified: [PendingRemoteApproval] = []
            for envelope in envelopes {
                let request = envelope.request
                guard !completedRequestIDs.contains(request.requestID),
                      let mac = pinnedMacs.first(where: {
                          $0.deviceID == request.macDeviceID
                            && $0.cloudKitContainerIdentifier
                              == CloudKitRemoteApprovalRelay.defaultContainerIdentifier
                      }) else { continue }
                do {
                    try envelope.verify(
                        macPublicKeyX963: mac.publicKeyX963,
                        at: now
                    )
                    verified.append(PendingRemoteApproval(envelope: envelope, mac: mac))
                } catch {
                    // An invalid or expired mailbox record is never rendered as
                    // actionable and never converted into a decision.
                }
            }
            verified.sort {
                $0.envelope.request.expiresAtMilliseconds
                    < $1.envelope.request.expiresAtMilliseconds
            }
            #if DEBUG && targetEnvironment(simulator)
            appendValidSimulatorRequests(to: &verified, at: now)
            #endif
            let changed = verified != pending
            pending = verified
            if verified.isEmpty { message = nil }
            return changed
        } catch {
            #if DEBUG && targetEnvironment(simulator)
            var verified: [PendingRemoteApproval] = []
            appendValidSimulatorRequests(
                to: &verified,
                at: currentTimeMilliseconds()
            )
            let changed = verified != pending
            pending = verified
            message = verified.isEmpty
                ? "Remote approvals could not be refreshed from private iCloud."
                : "Private iCloud is unavailable; the local simulator request is still testable."
            return changed
            #else
            message = "Remote approvals could not be refreshed from private iCloud."
            return false
            #endif
        }
    }

    func decide(
        _ item: PendingRemoteApproval,
        decision: RemoteApprovalDecision
    ) async {
        guard let identity,
              pending.contains(where: { $0.id == item.id }) else { return }
        do {
            let frozenAt = currentTimeMilliseconds()
            // Re-verify the exact immutable request immediately before creating
            // the response that Face ID will sign.
            try item.envelope.verify(
                macPublicKeyX963: item.mac.publicKeyX963,
                at: frozenAt
            )
            let response = RemoteApprovalResponse(
                requestID: item.envelope.request.requestID,
                requestDigest: try item.envelope.request.digest(),
                phoneDeviceID: identity.deviceID,
                decision: decision,
                decidedAtMilliseconds: frozenAt
            )
            let signingData = try response.signingData()
            let verb = decision == .approve ? "Approve" : "Deny"
            let signature = try await identityStore.sign(
                signingData,
                identity: identity,
                reason: "\(verb) this request from \(item.mac.deviceName)"
            )
            let envelope = SignedRemoteApprovalResponse(
                response: response,
                signatureDER: signature
            )
            // Face ID may have remained open until the request expired. Verify
            // the signed response at publish time and fail closed if so.
            try envelope.verify(
                for: item.envelope.request,
                pinnedPhoneDeviceID: identity.deviceID,
                phonePublicKeyX963: identity.publicKeyX963,
                at: currentTimeMilliseconds()
            )
            #if DEBUG && targetEnvironment(simulator)
            if simulatorPending[item.id] != nil {
                simulatorPending.removeValue(forKey: item.id)
            } else {
                try await relay.publishResponse(envelope)
            }
            #else
            try await relay.publishResponse(envelope)
            #endif
            if completedRequestIDs.count >= 4_096 {
                completedRequestIDs.removeAll(keepingCapacity: true)
            }
            completedRequestIDs.insert(item.id)
            pending.removeAll { $0.id == item.id }
            message = decision == .approve ? "Approved." : "Denied."
        } catch {
            message = "No decision was sent. The request may have expired or Face ID was cancelled."
            #if !DEBUG || !targetEnvironment(simulator)
            _ = await refresh()
            #endif
        }
    }

    private func updatePhonePairingCode() throws {
        guard let identity else {
            phonePairingCode = nil
            return
        }
        phonePairingCode = try RemoteApprovalPairingCode.encodePhone(identity.pairing)
    }

    #if DEBUG && targetEnvironment(simulator)
    func injectSimulatorRequest() {
        guard identity != nil else {
            message = "Set up the simulator identity first."
            return
        }
        do {
            let macPairing = RemoteApprovalMacPairing(
                macDeviceID: simulatorMacDeviceID,
                macDeviceName: "Simulated Mac",
                macPublicKeyX963: simulatorMacKey.publicKey.x963Representation,
                cloudKitContainerIdentifier: CloudKitRemoteApprovalRelay
                    .defaultContainerIdentifier
            )
            try macPairing.validate()
            let mac = PinnedMac(macPairing)
            let now = currentTimeMilliseconds()
            let review = RemoteApprovalReview(
                reason: "run the simulator approval test",
                callerDescription: "simulated shell (grant root pid 4242)",
                credentials: [
                    .init(
                        title: "Example account",
                        subtitle: "1Password · vault “Development”",
                        fields: ["password"],
                        rawReferences: []
                    ),
                ],
                referenceSetDigest: Data(SHA256.hash(
                    data: Data("op://Development/Example/password".utf8)
                )),
                emitterName: "simulated-tool",
                emitterPath: "/usr/bin/simulated-tool",
                emitterAssurance: "Simulator fixture",
                recipientDescription: "simulated executable consumer",
                deliveryDescription: "Direct to process memory · simulated",
                grantRootDescription: "Simulated requesting launcher",
                destinationDescription: "Simulator test only",
                requestedDurationDescription: "90 seconds",
                warning: "Synthetic request: no credential will be resolved.",
                deliveryPlanDigest: Data(SHA256.hash(
                    data: Data("csec.simulator.delivery-plan.v1".utf8)
                ))
            )
            let request = RemoteApprovalRequest(
                macDeviceID: mac.deviceID,
                macDeviceName: mac.deviceName,
                createdAtMilliseconds: now,
                expiresAtMilliseconds: now
                    + RemoteApprovalProtocolV1.requestLifetimeMilliseconds,
                review: review
            )
            let envelope = try SignedRemoteApprovalRequest.signed(
                request,
                by: simulatorMacKey
            )
            try envelope.verify(macPublicKeyX963: mac.publicKeyX963, at: now)
            let item = PendingRemoteApproval(envelope: envelope, mac: mac)
            simulatorPending[item.id] = item
            if !pinnedMacs.contains(where: { $0.id == mac.id }) {
                pinnedMacs.append(mac)
            }
            pending.removeAll { $0.id == item.id }
            pending.append(item)
            pending.sort { $0.expiresAt < $1.expiresAt }
            message = "Signed simulator request injected. Approve or deny it with simulated Face ID."
        } catch {
            message = "The signed simulator request could not be created."
        }
    }

    private func appendValidSimulatorRequests(
        to requests: inout [PendingRemoteApproval],
        at now: UInt64
    ) {
        var invalidRequestIDs: [String] = []
        for (requestID, item) in simulatorPending {
            do {
                try item.envelope.verify(
                    macPublicKeyX963: item.mac.publicKeyX963,
                    at: now
                )
                if !completedRequestIDs.contains(requestID) {
                    requests.append(item)
                }
            } catch {
                invalidRequestIDs.append(requestID)
            }
        }
        for requestID in invalidRequestIDs {
            simulatorPending.removeValue(forKey: requestID)
        }
        requests.sort { $0.expiresAt < $1.expiresAt }
    }
    #endif
}
