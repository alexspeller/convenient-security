import CryptoKit
import CSECRemoteApproval
import CSECRemoteApprovalCloudKit
import ConvenientSecurity
import Foundation

private actor SoftwareRemoteApprovalSigner: RemoteApprovalRequestSigner {
    let key: P256.Signing.PrivateKey

    init(key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) {
        self.key = key
    }

    func publicKeyX963Representation() async throws -> Data {
        key.publicKey.x963Representation
    }

    func sign(_ data: Data) async throws -> Data {
        try key.signature(for: data).derRepresentation
    }
}

private actor LoopbackRemoteApprovalRelay: RemoteApprovalRelay {
    let phoneDeviceID: String
    let phoneKey: P256.Signing.PrivateKey
    let decision: RemoteApprovalDecision
    private var storedResponse: SignedRemoteApprovalResponse?
    private(set) var deleted = false

    init(
        phoneDeviceID: String,
        phoneKey: P256.Signing.PrivateKey,
        decision: RemoteApprovalDecision
    ) {
        self.phoneDeviceID = phoneDeviceID
        self.phoneKey = phoneKey
        self.decision = decision
    }

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        let response = RemoteApprovalResponse(
            requestID: request.request.requestID,
            requestDigest: try request.request.digest(),
            phoneDeviceID: phoneDeviceID,
            decision: decision,
            decidedAtMilliseconds: currentTimeMilliseconds()
        )
        storedResponse = try .signed(response, by: phoneKey)
    }

    func response(for requestID: String) async throws -> SignedRemoteApprovalResponse? {
        guard storedResponse?.response.requestID == requestID else { return nil }
        return storedResponse
    }

    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] { [] }
    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {}

    func deleteExchange(requestID: String) async {
        storedResponse = nil
        deleted = true
    }
}

private enum SyntheticRemoteApprovalError: Error {
    case failed
}

private actor CommitThenFailRemoteApprovalRelay: RemoteApprovalRelay {
    private(set) var deleted = false

    func publishRequest(_ request: SignedRemoteApprovalRequest) async throws {
        // Model a transport that commits the record but loses the save reply.
        throw SyntheticRemoteApprovalError.failed
    }

    func response(for requestID: String) async throws -> SignedRemoteApprovalResponse? {
        nil
    }

    func pendingRequests() async throws -> [SignedRemoteApprovalRequest] { [] }
    func publishResponse(_ response: SignedRemoteApprovalResponse) async throws {}

    func deleteExchange(requestID: String) async {
        deleted = true
    }
}

private actor FailingLoadRemoteApprovalStore: RemoteApprovalConfigurationStore {
    let deletionFails: Bool
    private(set) var deleteAttempts = 0

    init(deletionFails: Bool) {
        self.deletionFails = deletionFails
    }

    func load() async throws -> StoredRemoteApprovalConfiguration? {
        throw SyntheticRemoteApprovalError.failed
    }

    func store(_ configuration: StoredRemoteApprovalConfiguration) async throws {}

    func delete() async throws {
        deleteAttempts += 1
        if deletionFails { throw SyntheticRemoteApprovalError.failed }
    }
}

private actor StubRemotePolicyReviewer: RemoteAccessPolicyReviewProvider {
    let result: RemoteApprovalRequesterResult
    let delayNanoseconds: UInt64
    private(set) var reviewCount = 0

    init(
        result: RemoteApprovalRequesterResult,
        delayNanoseconds: UInt64 = 0
    ) {
        self.result = result
        self.delayNanoseconds = delayNanoseconds
    }

    func reviewRemoteAccess(
        _ review: RemoteApprovalReview
    ) async -> RemoteApprovalRequesterResult {
        reviewCount += 1
        if delayNanoseconds > 0 {
            try? await Task.sleep(nanoseconds: delayNanoseconds)
        }
        return result
    }
}

private struct DelayedLocalPolicyReviewer: PolicyReviewProvider {
    let outcome: AccessPolicyReviewOutcome
    let delayNanoseconds: UInt64

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        if delayNanoseconds > 0 {
            do {
                try await Task.sleep(nanoseconds: delayNanoseconds)
            } catch {
                return .denied
            }
        }
        return outcome
    }
}

private func remoteReviewFixture() -> RemoteApprovalReview {
    RemoteApprovalReview(
        reason: "run migrations",
        callerDescription: "ruby for rails [protected] (grant root pid 42)",
        credentials: [
            .init(
                title: "Database",
                subtitle: "1Password · vault “Development”",
                fields: ["password"],
                rawReferences: []
            ),
        ],
        referenceSetDigest: Data(repeating: 0x11, count: SHA256.byteCount),
        emitterName: "ruby",
        emitterPath: "/usr/bin/ruby",
        emitterAssurance: "Protected path",
        recipientDescription: "planned executable consumer",
        deliveryDescription: "Direct to process memory · process and its descendants",
        grantRootDescription: "Requesting launcher",
        destinationDescription: "Local development",
        requestedDurationDescription: "15 minutes",
        warning: nil,
        deliveryPlanDigest: Data(repeating: 0x22, count: SHA256.byteCount)
    )
}

private func localReviewFixture(reference: String = "op://Development/Database/password") -> AccessPolicyReview {
    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(
            canonicalPath: "/usr/bin/ruby",
            assurance: .independentlyProtected
        ),
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 900,
        operationContext: "run migrations"
    )
    return AccessPolicyReview(
        caller: CallerInfo(pid: 42, startTime: 7, description: "ruby"),
        reason: "run migrations",
        plan: plan,
        credentials: [PolicyReviewCredential(references: [try! SecretRef(reference)])]
    )
}

func remoteApprovalTests() async {
    check(!CloudKitRemoteApprovalRelay.isEntitled(containerIdentifiers: []),
          "a build without CloudKit entitlements does not authorize relay construction")
    check(CloudKitRemoteApprovalRelay.isEntitled(containerIdentifiers: [
        CloudKitRemoteApprovalRelay.defaultContainerIdentifier
    ]), "the exact signed CloudKit container authorizes the optional relay")
    check(CloudKitRemoteApprovalRelay.makeIfEntitled(containerIdentifiers: []) == nil,
          "an ordinary build never calls CKContainer without its entitlement")

    print("\n# Remote approval (signed, expiring, transaction-bound; synthetic keys only)")

    let macKey = P256.Signing.PrivateKey()
    let phoneKey = P256.Signing.PrivateKey()
    let otherPhoneKey = P256.Signing.PrivateKey()
    let macDeviceID = UUID().uuidString.lowercased()
    let phoneDeviceID = UUID().uuidString.lowercased()
    let now = currentTimeMilliseconds()
    let review = remoteReviewFixture()

    do {
        let restoredSoftwarePhoneKey = try P256.Signing.PrivateKey(
            rawRepresentation: phoneKey.rawRepresentation
        )
        check(
            restoredSoftwarePhoneKey.publicKey.x963Representation
                == phoneKey.publicKey.x963Representation,
            "the simulator-only software P-256 identity round-trips through its stored form"
        )
        try review.validate()
        let request = RemoteApprovalRequest(
            macDeviceID: macDeviceID,
            macDeviceName: "Alex’s Mac",
            createdAtMilliseconds: now,
            expiresAtMilliseconds: now + 90_000,
            review: review
        )
        let signedRequest = try SignedRemoteApprovalRequest.signed(request, by: macKey)
        try signedRequest.verify(
            macPublicKeyX963: macKey.publicKey.x963Representation,
            at: now
        )
        check(true, "a Mac signature verifies the exact frozen remote review")

        var wrongReview = remoteReviewFixture()
        wrongReview = RemoteApprovalReview(
            reason: "different operation",
            callerDescription: wrongReview.callerDescription,
            credentials: wrongReview.credentials,
            referenceSetDigest: wrongReview.referenceSetDigest,
            emitterName: wrongReview.emitterName,
            emitterPath: wrongReview.emitterPath,
            emitterAssurance: wrongReview.emitterAssurance,
            recipientDescription: wrongReview.recipientDescription,
            deliveryDescription: wrongReview.deliveryDescription,
            grantRootDescription: wrongReview.grantRootDescription,
            destinationDescription: wrongReview.destinationDescription,
            requestedDurationDescription: wrongReview.requestedDurationDescription,
            warning: wrongReview.warning,
            deliveryPlanDigest: wrongReview.deliveryPlanDigest
        )
        let mutated = SignedRemoteApprovalRequest(
            request: RemoteApprovalRequest(
                requestID: request.requestID,
                macDeviceID: request.macDeviceID,
                macDeviceName: request.macDeviceName,
                createdAtMilliseconds: request.createdAtMilliseconds,
                expiresAtMilliseconds: request.expiresAtMilliseconds,
                review: wrongReview
            ),
            signatureDER: signedRequest.signatureDER
        )
        do {
            try mutated.verify(
                macPublicKeyX963: macKey.publicKey.x963Representation,
                at: now
            )
            check(false, "changing phone-visible review copy invalidates the Mac signature")
        } catch {
            check(true, "changing phone-visible review copy invalidates the Mac signature")
        }

        let response = RemoteApprovalResponse(
            requestID: request.requestID,
            requestDigest: try request.digest(),
            phoneDeviceID: phoneDeviceID,
            decision: .approve,
            decidedAtMilliseconds: now + 1_000
        )
        let signedResponse = try SignedRemoteApprovalResponse.signed(response, by: phoneKey)
        try signedResponse.verify(
            for: request,
            pinnedPhoneDeviceID: phoneDeviceID,
            phonePublicKeyX963: phoneKey.publicKey.x963Representation,
            at: now + 2_000
        )
        check(true, "the pinned phone signature approves only its exact request digest")

        do {
            try signedResponse.verify(
                for: request,
                pinnedPhoneDeviceID: phoneDeviceID,
                phonePublicKeyX963: otherPhoneKey.publicKey.x963Representation,
                at: now + 2_000
            )
            check(false, "an unpinned phone key cannot approve")
        } catch {
            check(true, "an unpinned phone key cannot approve")
        }

        do {
            try signedResponse.verify(
                for: request,
                pinnedPhoneDeviceID: phoneDeviceID,
                phonePublicKeyX963: phoneKey.publicKey.x963Representation,
                at: now + 200_000
            )
            check(false, "an expired phone response cannot approve")
        } catch {
            check(true, "an expired phone response cannot approve")
        }

        let phonePairing = RemoteApprovalPhonePairing(
            phoneDeviceID: phoneDeviceID,
            phoneDeviceName: "Alex’s iPhone",
            phonePublicKeyX963: phoneKey.publicKey.x963Representation
        )
        let phoneCode = try RemoteApprovalPairingCode.encodePhone(phonePairing)
        check(try RemoteApprovalPairingCode.decodePhone(phoneCode) == phonePairing,
              "the value-free phone pairing code round-trips")
        check(RemoteApprovalPairingCode.publicKeyFingerprint(
            phoneKey.publicKey.x963Representation
        ).count == 16, "pairing shows a stable short public-key fingerprint")
    } catch {
        check(false, "signed remote approval protocol fixtures validate (\(error))")
    }

    do {
        let relay = LoopbackRemoteApprovalRelay(
            phoneDeviceID: phoneDeviceID,
            phoneKey: phoneKey,
            decision: .approve
        )
        let requester = try RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: macDeviceID,
                macDeviceName: "Alex’s Mac",
                pinnedPhoneDeviceID: phoneDeviceID,
                pinnedPhonePublicKeyX963: phoneKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: SoftwareRemoteApprovalSigner(key: macKey),
            relay: relay
        )
        check(await requester.requestApproval(for: review) == .approved,
              "the requester accepts a valid loopback phone approval")
        check(await relay.deleted,
              "the requester removes the single-use relay exchange after a decision")
    } catch {
        check(false, "remote requester loopback succeeds (\(error))")
    }

    do {
        let relay = CommitThenFailRemoteApprovalRelay()
        let requester = try RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: macDeviceID,
                macDeviceName: "Alex’s Mac",
                pinnedPhoneDeviceID: phoneDeviceID,
                pinnedPhonePublicKeyX963: phoneKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: SoftwareRemoteApprovalSigner(key: macKey),
            relay: relay
        )
        check(await requester.requestApproval(for: review) == .unavailable,
              "a failed relay publish never becomes an approval")
        check(await relay.deleted,
              "a possibly committed failed publish is cleaned up")
    } catch {
        check(false, "remote requester failed-publish cleanup succeeds (\(error))")
    }

    let remoteApproved = RemoteApprovedAuthenticationSession()
    check((await remoteApproved.completeAfterPolicyApproval(policySummary: "synthetic")).isApproved,
          "a verified remote decision completes the existing approval seam")
    check(!(await remoteApproved.completeAfterPolicyApproval(policySummary: "synthetic")).isApproved,
          "a verified remote decision can be consumed only once")

    let fastRemote = StubRemotePolicyReviewer(result: .approved)
    let mirrored = MirroredPolicyReview(
        local: DelayedLocalPolicyReviewer(
            outcome: .denied,
            delayNanoseconds: 2_000_000_000
        ),
        remote: fastRemote
    )
    if case let .approved(approval) = await mirrored.reviewAccess(localReviewFixture()),
       let session = approval.authenticationSession {
        check((await session.completeAfterPolicyApproval(policySummary: "synthetic")).isApproved,
              "a pinned phone can win the race against the ordinary local prompt")
    } else {
        check(false, "a pinned phone can win the race against the ordinary local prompt")
    }

    let unavailableRemote = StubRemotePolicyReviewer(result: .unavailable)
    let localFallback = MirroredPolicyReview(
        local: DelayedLocalPolicyReviewer(
            outcome: .approved(AccessPolicyApproval()),
            delayNanoseconds: 20_000_000
        ),
        remote: unavailableRemote
    )
    if case .approved = await localFallback.reviewAccess(localReviewFixture()) {
        check(true, "relay unavailability leaves the local approval path working")
    } else {
        check(false, "relay unavailability leaves the local approval path working")
    }

    let nativeRemote = StubRemotePolicyReviewer(result: .approved)
    let nativeOnly = MirroredPolicyReview(
        local: DelayedLocalPolicyReviewer(outcome: .denied, delayNanoseconds: 0),
        remote: nativeRemote
    )
    if case .denied = await nativeOnly.reviewAccess(
        localReviewFixture(reference: "csec://development/API_TOKEN")
    ) {
        check(await nativeRemote.reviewCount == 0,
              "cold native-store requests remain local because a phone has no Mac LAContext")
    } else {
        check(false, "cold native-store requests remain local because a phone has no Mac LAContext")
    }

    let recoverableStore = FailingLoadRemoteApprovalStore(deletionFails: false)
    let recoverableManager = RemoteApprovalManager(
        store: recoverableStore,
        relay: LoopbackRemoteApprovalRelay(
            phoneDeviceID: phoneDeviceID,
            phoneKey: phoneKey,
            decision: .approve
        ),
        consent: AutoApproveConsent(),
        cloudKitContainerIdentifier: "iCloud.com.alexspeller.convenient-security"
    )
    await recoverableManager.prepare()
    check(await recoverableManager.status() == .unavailable,
          "a failed pin load is reported as unavailable")
    do {
        try await recoverableManager.disable()
        check(await recoverableStore.deleteAttempts == 1,
              "opt-out deletes even a corrupt or unreadable pin record")
        check(await recoverableManager.status() == .disabled,
              "successful opt-out clears the unavailable state")
    } catch {
        check(false, "opt-out can recover an unreadable pin record (\(error))")
    }

    let undeletableStore = FailingLoadRemoteApprovalStore(deletionFails: true)
    let undeletableManager = RemoteApprovalManager(
        store: undeletableStore,
        relay: LoopbackRemoteApprovalRelay(
            phoneDeviceID: phoneDeviceID,
            phoneKey: phoneKey,
            decision: .approve
        ),
        consent: AutoApproveConsent(),
        cloudKitContainerIdentifier: "iCloud.com.alexspeller.convenient-security"
    )
    await undeletableManager.prepare()
    do {
        try await undeletableManager.disable()
        check(false, "a failed persistent opt-out is reported to the caller")
    } catch {
        check(await undeletableManager.status() == .unavailable,
              "a failed persistent opt-out stays fail-closed instead of appearing disabled")
    }

    do {
        let request = RemoteApprovalConfigurationRequest(
            action: .enable,
            phonePairingCode: "csec-phone-v1:synthetic"
        )
        let encoded = try JSONEncoder().encode(Request.configureRemoteApproval(request))
        let decoded = try JSONDecoder().decode(Request.self, from: encoded)
        if case let .configureRemoteApproval(roundTrip) = decoded {
            check(roundTrip.requestID == request.requestID
                  && roundTrip.action == .enable
                  && roundTrip.phonePairingCode == request.phonePairingCode,
                  "the authenticated local enrollment request round-trips on protocol v2")
        } else {
            check(false, "the authenticated local enrollment request round-trips on protocol v2")
        }
    } catch {
        check(false, "remote enrollment wire fixture round-trips (\(error))")
    }
}
