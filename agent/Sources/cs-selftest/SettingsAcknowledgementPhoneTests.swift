import CryptoKit
import CSECRemoteApproval
import ConvenientSecurity
import Foundation

// The rules- and hooks-changed acknowledgement csecd raises for a Claude Code
// request reaches the paired phone as well as this Mac (av-rcqg: a biometric
// approval is answerable from whichever surface Alex is on). It stays his
// alone, single-use and bound to exactly the hooks and rules it lists; every
// other change to csec's settings stays at this Mac.

/// The hooks-changed panel's change for a launch-only hooks module, as csecd
/// builds it for a request that declined on it.
func settingsAcknowledgementFixture(
    digest: String = String(repeating: "a", count: 64)
) -> (hook: ClaudeHookSource, change: SettingsChangeReviewDetails) {
    let hook = settingsAcknowledgementHook(digest: digest)
    return (hook, ClaudeDelegationService.changedRulesReview([hook], acknowledged: []))
}

private func settingsAcknowledgementHook(digest: String) -> ClaudeHookSource {
    ClaudeHookSource(
        kind: .plugin, sourceID: "harbor-artifact-defer@harbor", event: nil, matcher: nil, digest: digest,
        display: "harbor-artifact-defer@harbor · hooks module", fetchesUnpinnedCode: false,
        moduleFiles: ["register.mjs sha256:" + settingsAcknowledgementModuleDigest], shownWhole: true
    )
}

/// The file digest of the hooks module the Artifact deferral plans to load.
let settingsAcknowledgementModuleDigest = "5d701a15f102bea3419d82442e5a3d446435116ff98375a7741898c8db82fe3a"

/// The settings review the phone renders, as the wire carries it.
func v3SettingsReviewFixture() -> RemoteApprovalReview {
    RemoteApprovalReview(
        kind: .settings,
        headline: "New Claude Code Hook",
        callerDescription: "claude (pid 51)",
        terminalDescription: "iTerm2 · window 1, tab 3",
        secrets: [],
        referenceSetDigest: Data(SHA256.hash(data: Data())),
        delivery: nil,
        warnings: [],
        footnote: ClaudeDelegationService.changedHooksFootnote,
        settings: .init(changes: [
            "New hook: harbor-artifact-defer@harbor · hooks module, which can approve shell commands",
            "Its module \u{201C}register.mjs sha256:5d701a15f102bea3419d82442e5a3d446435116ff98375a7741898c8db82fe3a\u{201D}",
            "csec can't show what it runs: acknowledge it only if you have reviewed it where it is defined",
        ]),
        operationDigest: Data(repeating: 0x77, count: SHA256.byteCount)
    )
}

/// The Mac panel left up, answering only by being cancelled, or failing
/// after `patience` so a run where nothing cancels it still ends.
private actor SettingsLocalPanel: PolicyReviewProvider {
    private(set) var reviews: [AccessPolicyReview] = []
    private(set) var cancelled = false
    let patience: Duration

    init(patience: Duration = .seconds(3)) { self.patience = patience }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews.append(review)
        let start = ContinuousClock.now
        while !Task.isCancelled, ContinuousClock.now - start < patience {
            try? await Task.sleep(for: .milliseconds(10))
        }
        cancelled = Task.isCancelled
        return .denied(.authenticationFailed)
    }
}

func settingsAcknowledgementPhoneTests() async {
    print("\n# The hooks-changed acknowledgement on the paired phone (av-rcqg)")
    settingsAcknowledgementWireTests()
    settingsAcknowledgementStatusTests()
    await settingsAcknowledgementSingleUseTests()
    settingsAcknowledgementReviewTests()
    await settingsAcknowledgementMirrorTests()
}

/// The paired phone's signed status, listing the review kinds it shows
/// (nil: an app that predates the field).
func settingsPhoneStatus(
    _ phone: SyntheticPhone, kinds: [String]?, at milliseconds: UInt64 = currentTimeMilliseconds()
) throws -> SignedRemoteApprovalPhoneStatus {
    let status = RemoteApprovalPhoneStatus(
        phoneDeviceID: phone.deviceID, appVersion: "1.0 (8)", notificationsAuthorized: true,
        requestAlerts: .ready, reviewKinds: kinds, updatedAtMilliseconds: milliseconds
    )
    return SignedRemoteApprovalPhoneStatus(
        status: status, signatureDER: try phone.signingKey.signature(for: status.signingData()).derRepresentation
    )
}

/// Every kind this build's phone app shows.
let settingsPhoneKinds = RemoteApprovalReview.Kind.allCases.map(\.rawValue)

// MARK: - Wire

private func settingsAcknowledgementWireTests() {
    let review = v3SettingsReviewFixture()
    func request(_ review: RemoteApprovalReview) -> RemoteApprovalRequest {
        RemoteApprovalRequest(
            requestID: "0b8f5f1e-1111-4222-8333-944455556666", macDeviceID: "1c9f5f1e-1111-4222-8333-944455556666",
            macDeviceName: "Alex’s Mac", createdAtMilliseconds: 1_700_000_000_000, review: review
        )
    }
    func error(_ review: RemoteApprovalReview) -> RemoteApprovalValidationError? {
        do {
            try review.validate()
            return nil
        } catch let error as RemoteApprovalValidationError {
            return error
        } catch {
            return nil
        }
    }

    let digest = try? request(review).digest()
    check(digest != nil && error(review) == nil
            && RemoteApprovalRequest.signingDomain(for: review) == "csec.remote-approval.request.v3+settings",
          "settings wire: a settings review validates and signs under its own domain, so an older phone app "
            + "cannot verify it")
    let closing = RemoteReviewParts.changing(review) { $0.closesAtMilliseconds = 1_700_000_060_000 }
    check(RemoteApprovalRequest.signingDomain(for: closing) == "csec.remote-approval.request.v3+settings+deadline"
            && error(closing) == nil,
          "settings wire: one the Mac closes unanswered carries its deadline, after the settings suffix")

    let mutations: [(String, (inout RemoteReviewParts) -> Void)] = [
        ("a line", { $0.settings = .init(changes: ["New hook: something else, which can approve shell commands"]) }),
        ("the lines' order", { $0.settings = .init(changes: ($0.settings?.changes ?? []).reversed()) }),
        ("the operation", { $0.operationDigest = Data(repeating: 0x78, count: SHA256.byteCount) }),
        ("the headline", { $0.headline = "New Claude Code Hooks" }),
        ("the footnote", { $0.footnote = "Other." }),
    ]
    for (label, mutation) in mutations {
        let changed = RemoteReviewParts.changing(review, mutation)
        check((try? request(changed).digest()) != digest, "settings wire: changing \(label) changes what is signed")
    }

    let inconsistent: [(String, (inout RemoteReviewParts) -> Void)] = [
        ("no settings block", { $0.settings = nil }),
        ("a secret", { $0.secrets = [v3NativeSecret("app", "TOKEN")] }),
        ("a delivery", { $0.delivery = v3AccessReviewFixture().delivery }),
        ("a warning", { $0.warnings = ["WARNING"] }),
        ("a scope choice", {
            $0.scopeOptions = [.init(id: "s", title: "t", detail: "d")]
            $0.defaultScopeID = "s"
        }),
        ("a lifetime choice", {
            $0.durationOptions = ["Until it exits"]
            $0.defaultDurationIndex = 0
        }),
        ("a delegation block", { $0.delegation = .init(note: "Auto mode didn't approve this: x", pairing: nil) }),
        ("a requester command", { $0.requesterCommand = "bin/deploy" }),
        ("an SSH block", { $0.ssh = v3SSHReviewFixture().ssh }),
        ("a sudo block", { $0.sudo = v3SudoReviewFixture().sudo }),
    ]
    for (label, mutation) in inconsistent {
        check(error(RemoteReviewParts.changing(review, mutation)) == .inconsistentKind,
              "settings wire: a settings review with \(label) is refused")
    }
    check(error(RemoteReviewParts.changing(v3SudoReviewFixture()) { $0.settings = review.settings })
            == .inconsistentKind,
          "settings wire: only a settings review carries settings lines")
    let bounds: [(String, [String])] = [
        ("no line", []),
        ("too many lines", Array(repeating: "x", count: RemoteApprovalProtocolV3.maximumSettingsChanges + 1)),
        ("a line too long", [String(repeating: "x", count: RemoteApprovalReview.FieldLimit.settingsChange + 1)]),
    ]
    for (label, changes) in bounds {
        check(error(RemoteReviewParts.changing(review) { $0.settings = .init(changes: changes) }) == .fieldOutOfBounds,
              "settings wire: a settings review with \(label) is refused")
    }

    // Its answer selects nothing: the phone signs a bare Approve or Deny.
    let phone = SyntheticPhone()
    let macKey = P256.Signing.PrivateKey()
    guard let envelope = try? SignedRemoteApprovalRequest.signed(request(review), by: macKey) else {
        check(false, "settings wire: the fixture signs")
        return
    }
    func verified(_ response: SignedRemoteApprovalResponse?) -> Result<RemoteApprovalSelection?, Error>? {
        guard let response else { return nil }
        return Result {
            try response.verify(
                for: envelope.request, pinnedPhoneDeviceID: phone.deviceID,
                phonePublicKeyX963: phone.signingKey.publicKey.x963Representation
            )
        }
    }
    let approval = verified(try? phone.approve(envelope))
    let scoped = verified(try? phone.respond(to: envelope, .approve, scopeID: "requesting_command-51-9"))
    let paired = verified(try? phone.respond(to: envelope, .approve, pairingLineShown: true))
    let approvedSelection = try? approval?.get()
    check(approvedSelection != nil && approvedSelection?.scopeOptionID == nil
            && approvedSelection?.durationIndex == nil && approvedSelection?.pairingLineShown == false,
          "settings wire: the phone's approval selects nothing and pairs nothing")
    check((try? scoped?.get()) == nil && (try? paired?.get()) == nil,
          "settings wire: an approval that selects a scope or claims a pairing line is refused")

    let challenged = RemoteApprovalRequest(
        requestID: "0b8f5f1e-1111-4222-8333-944455556666", macDeviceID: "1c9f5f1e-1111-4222-8333-944455556666",
        macDeviceName: "Alex’s Mac", createdAtMilliseconds: 1_700_000_000_000, review: review,
        unlockChallenge: RemoteApprovalUnlockChallenge(
            enrollmentID: UUID().uuidString,
            blindedPoint: P256.KeyAgreement.PrivateKey().publicKey.compressedRepresentation
        )
    )
    var refusal: RemoteApprovalValidationError?
    do { try challenged.validate(at: 1_700_000_000_000) } catch { refusal = error as? RemoteApprovalValidationError }
    check(refusal == .inconsistentKind && (try? request(review).validate(at: 1_700_000_000_000)) != nil,
          "settings wire: a settings request never asks the phone to open its unlock factor")
}

// MARK: - The phone's status

/// The phone says which kinds of review it shows, signed, so a Mac offers a
/// settings review only to an app that shows one. The golden bytes come from
/// an encoder written independently of `CanonicalEncoder`.
private func settingsAcknowledgementStatusTests() {
    let deviceID = "0b7c3a52-1111-4222-8333-444455556666"
    func status(_ alerts: RemoteApprovalPhoneAlertState?, _ kinds: [String]?) -> RemoteApprovalPhoneStatus {
        RemoteApprovalPhoneStatus(
            phoneDeviceID: deviceID, appVersion: "1.0 (7)", notificationsAuthorized: true,
            requestAlerts: alerts, reviewKinds: kinds, updatedAtMilliseconds: 1_790_000_000_000
        )
    }
    func hex(_ data: Data?) -> String? { data.map { $0.map { String(format: "%02x", $0) }.joined() } }
    let header = "00000024637365632e72656d6f74652d617070726f76616c2e70686f6e652d7374617475732e7633"
        + "00020000002430623763336135322d313131312d343232322d383333332d343434343535353536363636"
        + "00000007312e3020283729000301"
    check(hex(try? status(nil, ["access", "settings"]).signingData())
            == header + "00" + "00000002" + "00000006616363657373" + "0000000873657474696e6773" + "000001a0c4506c00",
          "phone status: with review kinds it signs under its own v3 domain, no alert state marked absent")
    check(hex(try? status(.subscriptionRefused, ["settings"]).signingData())
            == header + "010002" + "00000001" + "0000000873657474696e6773" + "000001a0c4506c00",
          "phone status: with review kinds and an alert state, the state is marked present before the kinds")

    let key = P256.Signing.PrivateKey()
    let publicKey = key.publicKey.x963Representation
    guard let data = try? status(.ready, ["access", "settings"]).signingData(),
          let signature = try? key.signature(for: data).derRepresentation else {
        check(false, "phone status: the v3 record signs")
        return
    }
    func verifies(_ candidate: RemoteApprovalPhoneStatus) -> Bool {
        (try? SignedRemoteApprovalPhoneStatus(status: candidate, signatureDER: signature)
            .verify(phoneDeviceID: deviceID, phonePublicKeyX963: publicKey)) != nil
    }
    check(verifies(status(.ready, ["access", "settings"])), "phone status: signed review kinds verify")
    check(!verifies(status(.ready, nil)) && !verifies(status(.ready, ["access"]))
            && !verifies(status(.ready, ["access", "settings", "restore"])) && !verifies(status(nil, ["access", "settings"])),
          "phone status: dropping, removing or adding a kind, or dropping the alert state, breaks the signature")
    let tooMany = Array(repeating: "access", count: RemoteApprovalPhoneStatus.maximumReviewKinds + 1)
    let tooLong = [String(repeating: "k", count: RemoteApprovalPhoneStatus.maximumReviewKindBytes + 1)]
    for (label, kinds) in [("too many kinds", tooMany), ("a kind too long", tooLong)] {
        var refusal: RemoteApprovalValidationError?
        do { _ = try status(nil, kinds).signingData() } catch { refusal = error as? RemoteApprovalValidationError }
        check(refusal == .fieldOutOfBounds, "phone status: one with \(label) is refused")
    }
    check(status(nil, settingsPhoneKinds).shows(.settings) && !status(nil, ["access", "sudo"]).shows(.settings)
            && !status(.ready, nil).shows(.settings) && status(nil, ["access", "future"]).shows(.access),
          "phone status: a phone shows a settings review only if it lists the kind; a kind this Mac does not "
            + "know is no obstacle")
    do {
        let older = try JSONDecoder().decode(RemoteApprovalPhoneStatus.self, from: Data("""
            {"version":2,"phoneDeviceID":"\(deviceID)","appVersion":"1.0 (7)","protocolVersion":3,
             "notificationsAuthorized":true,"requestAlerts":1,"updatedAtMilliseconds":1790000000000}
            """.utf8))
        let roundTrip = try JSONDecoder().decode(
            RemoteApprovalPhoneStatus.self, from: JSONEncoder().encode(status(.ready, settingsPhoneKinds)))
        check(older.reviewKinds == nil && roundTrip == status(.ready, settingsPhoneKinds),
              "phone status: an older app's record has no review kinds, and a new one's cross the relay intact")
    } catch {
        check(false, "phone status: records decode (\(error))")
    }

    typealias Report = RemoteApprovalStatusReport
    func lines(_ shows: Bool?) -> [String] {
        Report.summary(RemoteApprovalConfigurationStatus(
            state: .enabled, phoneName: "P", phoneKeyFingerprint: "0011223344556677", phoneConfirmed: true,
            phoneAppVersion: "1.0 (7)", phoneNotificationsAuthorized: true, remoteUnlockEnrolled: true,
            phoneProtocolVersion: Int(RemoteApprovalProtocolV3.version), phoneShowsSettingsReviews: shows,
            phoneSettingsReviews: RemoteApprovalPhoneSettingsReviews(phoneShows: shows),
            macProtocolVersion: Int(RemoteApprovalProtocolV3.version)
        )).lines
    }
    let hidden = lines(false).filter { $0.contains("hook and rule acknowledgements") }
    check(hidden.count == 1 && hidden[0].contains("stay on this Mac") && hidden[0].contains("App Store") && hidden[0].contains("--only-iphone")
            && !lines(true).joined().contains("stay on this Mac"),
          "phone status: csec remote status says when the phone has not reported showing hook acknowledgements")
}

// MARK: - Single use

/// One phone approval answers one request: once taken it is refused, and it
/// never answers the next request, which has its own ID.
private func settingsAcknowledgementSingleUseTests() async {
    let phone = SyntheticPhone()
    let relay = V3MailboxRelay()
    do {
        let requester = try RemoteApprovalRequester(
            configuration: RemoteApprovalRequesterConfiguration(
                macDeviceID: UUID().uuidString.lowercased(), macDeviceName: "Alex’s Mac",
                pinnedPhoneDeviceID: phone.deviceID,
                pinnedPhonePublicKeyX963: phone.signingKey.publicKey.x963Representation,
                pollIntervalNanoseconds: 50_000_000
            ),
            signer: V3SoftwareSigner(key: P256.Signing.PrivateKey()),
            relay: relay
        )
        let first = Task { await requester.requestApproval(for: v3SettingsReviewFixture()) }
        guard let envelope = await v3WaitForRequest(relay) else {
            first.cancel()
            check(false, "settings single use: the request reaches the mailbox")
            return
        }
        let answer = try phone.approve(envelope)
        try await relay.publishResponse(answer)
        let approved = await first.value
        guard case let .approved(selection) = approved else {
            check(false, "settings single use: the phone's approval answers its request (\(approved))")
            return
        }
        check(selection.scopeOptionID == nil && selection.durationIndex == nil && selection.unlockAnswer == nil,
              "settings single use: the approval selects and opens nothing")
        let replayed = await requester.accept(answer)
        check(replayed == .rejected(.alreadyConsumed), "settings single use: the same approval again is refused")

        let second = Task { await requester.requestApproval(for: v3SettingsReviewFixture()) }
        guard let next = await v3WaitForRequest(relay, number: 1) else {
            second.cancel()
            check(false, "settings single use: the next request reaches the mailbox")
            return
        }
        let stale = await requester.accept(answer)
        check(next.request.requestID != envelope.request.requestID && stale == .rejected(.alreadyConsumed),
              "settings single use: the next request has its own ID, and the old approval does not answer it")
        try await relay.publishResponse(try phone.respond(to: next, .deny))
        let denied = await second.value
        if case .denied = denied {
            check(true, "settings single use: the next request waits for its own answer")
        } else {
            check(false, "settings single use: the next request waits for its own answer (\(denied))")
        }
    } catch {
        check(false, "settings single use: \(error)")
    }
}

// MARK: - The Mac's review

private func settingsAcknowledgementReviewTests() {
    let caller = CallerInfo(pid: 51, startTime: 9, description: "claude (pid 51)")
    let (hook, change) = settingsAcknowledgementFixture()
    let review = AccessPolicyReview.settingsChange(caller: caller, change: change)
    check(!review.macOnly && change.phoneOperationDigest == ClaudeDelegationService.acknowledgementDigest([hook]),
          "settings review: the hooks-changed acknowledgement is not Mac-only, and names exactly what it acknowledges")
    let setup = AccessPolicyReview.settingsChange(caller: caller, change: SettingsChangeReviewDetails(
        title: "Turn On Claude Code Auto-Mode Approvals", changes: ["Let Claude Code auto mode approve csec secrets"]
    ))
    check(setup.macOnly && (try? RemoteApprovalReview(accessPolicyReview: setup)) == nil,
          "settings review: every other change to csec's settings stays at this Mac and never freezes for the phone")

    let other = settingsAcknowledgementHook(digest: String(repeating: "b", count: 64))
    typealias Service = ClaudeDelegationService
    check(Service.acknowledgementDigest([hook, other]) == Service.acknowledgementDigest([other, hook])
            && Service.acknowledgementDigest([hook, hook]) == Service.acknowledgementDigest([hook])
            && Service.acknowledgementDigest([hook]) != Service.acknowledgementDigest([other])
            && Service.acknowledgementDigest([hook]) != Service.acknowledgementDigest([hook, other])
            && Service.acknowledgementDigest([hook]).count == SHA256.byteCount,
          "settings review: the operation digest is the set of sources acknowledged, in no particular order")

    guard let frozen = try? RemoteApprovalReview(accessPolicyReview: review) else {
        check(false, "settings review: the hooks-changed acknowledgement freezes for the phone")
        return
    }
    check(frozen.kind == .settings && frozen.headline == change.title && frozen.settings?.changes == change.changes
            && frozen.footnote == change.footnote && frozen.secrets.isEmpty && frozen.delivery == nil
            && frozen.warnings.isEmpty && frozen.scopeOptions.isEmpty && frozen.durationOptions.isEmpty
            && frozen.delegation == nil && frozen.requesterCommand == nil
            && frozen.operationDigest == change.phoneOperationDigest
            && frozen.callerDescription == "claude (pid 51)",
          "settings review: the phone's copy is the panel's title, lines and footnote, bound to the acknowledgement")
    check(!change.footnote.contains("Touch ID"),
          "settings review: its footnote reads true on either surface")

    let operation = Data(repeating: 0x42, count: SHA256.byteCount)
    func kept(_ changes: [String], title: String = "T", digest: Data? = nil) -> Bool {
        SettingsChangeReviewDetails(
            title: title, changes: changes, footnote: "F", phoneOperationDigest: digest ?? operation
        ).phoneOperationDigest != nil
    }
    let full = String(repeating: "x", count: SettingsChangeReviewDetails.maximumChangeBytes)
    check(kept(["a", full]), "settings review: a change shown whole keeps its phone operation")
    check(!kept(["a", full + "y"]) && !kept(Array(repeating: "a", count: SettingsChangeReviewDetails.maximumChanges + 1))
            && !kept(["a"], title: String(repeating: "t", count: 129))
            && !kept(["a"], digest: Data(repeating: 0x42, count: SHA256.byteCount - 1)),
          "settings review: a line cut short, lines left out, a title cut short or a digest of the wrong length "
            + "keeps the change at this Mac")
    check(AccessPolicyReview.settingsChange(caller: caller, change: SettingsChangeReviewDetails(
        title: "T", changes: ["a", full + "y"], footnote: "F", phoneOperationDigest: operation)).macOnly,
          "settings review: such a change is Mac-only")
}

// MARK: - The mirror, end to end

private func settingsAcknowledgementMirrorTests() async {
    let caller = CallerInfo(pid: 51, startTime: 9, description: "claude (pid 51)")
    let (hook, change) = settingsAcknowledgementFixture()
    let review = AccessPolicyReview.settingsChange(caller: caller, change: change)
    let setupChange = SettingsChangeReviewDetails(
        title: "Turn On Claude Code Auto-Mode Approvals", changes: ["Let Claude Code auto mode approve csec secrets"]
    )
    let setup = AccessPolicyReview.settingsChange(caller: caller, change: setupChange)
    let phone = SyntheticPhone()
    let pairing = v3StoredPairing(phone: phone, macKey: P256.Signing.PrivateKey())

    // The mirror judges the phone ready for it: it releases and opens
    // nothing, and the phone said it shows settings reviews.
    do {
        let relay = V3MailboxRelay()
        try await relay.publishPhoneStatus(settingsPhoneStatus(phone, kinds: settingsPhoneKinds))
        let manager = v3Manager(store: V3MemoryConfigurationStore(record: pairing), relay: relay)
        await manager.prepare()
        let health = await manager.pairingHealth()
        check(health?.phoneShowsSettingsReviews == true,
              "settings mirror: csecd reads that the phone shows settings reviews from its signed status")
        let spy = V3SpyRemote(manager)
        let local = SettingsLocalPanel(patience: .milliseconds(50))
        let mirror = MirroredPolicyReview(local: local, remote: spy, log: { _ in })
        let reach = await mirror.approvalReach(for: review)
        let setupReach = await mirror.approvalReach(for: setup)
        check(reach == .judged(.ready(unlock: .notNeeded)) && setupReach == .judged(.unavailable),
              "settings mirror: the paired phone can decide the acknowledgement and no other setting "
                + "(\(reach), \(setupReach))")
        _ = await mirror.reviewAccess(setup)
        let mirrored = await spy.reviews
        let localReviews = await local.reviews.count
        check(mirrored == 0 && localReviews == 1,
              "settings mirror: a Mac-only settings change is shown at this Mac and never published")
        let consent = SettingsChangeConsent(underlying: V3CountingConsent(), review: mirror)
        let reaches = await consent.settingsChangeReachesPhone(change, caller: caller)
        let setupReaches = await consent.settingsChangeReachesPhone(setupChange, caller: caller)
        check(reaches && !setupReaches,
              "settings mirror: the settings consent says the phone can decide only the acknowledgement")

        let unpaired = v3Manager(store: V3MemoryConfigurationStore(record: nil), relay: V3MailboxRelay())
        await unpaired.prepare()
        let lone = SettingsChangeConsent(
            underlying: V3CountingConsent(),
            review: MirroredPolicyReview(local: SettingsLocalPanel(), remote: unpaired, log: { _ in })
        )
        let loneReaches = await lone.settingsChangeReachesPhone(change, caller: caller)
        check(!loneReaches, "settings mirror: with no phone paired only this Mac can decide it")
    } catch {
        check(false, "settings mirror: readiness (\(error))")
    }

    // An app that predates settings reviews would drop the request unread,
    // so the change stays at this Mac until the phone's status lists them;
    // the next request after it does sees it without a restart.
    do {
        let relay = V3MailboxRelay()
        let reported = currentTimeMilliseconds()
        try await relay.publishPhoneStatus(settingsPhoneStatus(phone, kinds: nil, at: reported))
        let manager = v3Manager(store: V3MemoryConfigurationStore(record: pairing), relay: relay)
        await manager.prepare()
        let health = await manager.pairingHealth()
        let mirror = MirroredPolicyReview(local: SettingsLocalPanel(), remote: manager, log: { _ in })
        let consent = SettingsChangeConsent(underlying: V3CountingConsent(), review: mirror)
        let oldReach = await mirror.approvalReach(for: review)
        let oldReaches = await consent.settingsChangeReachesPhone(change, caller: caller)
        let access = await manager.remoteReadiness(for: [])
        check(health?.phoneShowsSettingsReviews == false && oldReach == .judged(.unavailable) && !oldReaches
                && access == .ready(unlock: .notNeeded),
              "settings mirror: a phone app that has not said it shows settings reviews is not offered one, "
                + "and still decides everything else")
        try await relay.publishPhoneStatus(settingsPhoneStatus(phone, kinds: settingsPhoneKinds, at: reported + 1))
        check(await eventuallyTrue { await manager.remoteSettingsReadiness() == .ready(unlock: .notNeeded) },
              "settings mirror: once the updated app's status lists them, csecd offers it the next one")

        let silent = v3Manager(store: V3MemoryConfigurationStore(record: pairing), relay: V3MailboxRelay())
        await silent.prepare()
        let silentReadiness = await silent.remoteSettingsReadiness()
        check(silentReadiness == .unavailable,
              "settings mirror: a phone that has reported nothing is not offered one either")
    } catch {
        check(false, "settings mirror: an older phone app (\(error))")
    }

    // The Mac signs the request, the phone approves it, the Mac panel is
    // closed, and the decision says it was the phone's.
    do {
        let relay = V3MailboxRelay()
        try await relay.publishPhoneStatus(settingsPhoneStatus(phone, kinds: settingsPhoneKinds))
        let manager = v3Manager(store: V3MemoryConfigurationStore(record: pairing), relay: relay)
        await manager.prepare()
        _ = await manager.pairingHealth()
        let local = SettingsLocalPanel()
        let consent = SettingsChangeConsent(
            underlying: V3CountingConsent(), review: MirroredPolicyReview(local: local, remote: manager, log: { _ in })
        )
        let asked = Task { await consent.decideSettingsChange(change, caller: caller, reason: change.title) }
        if let envelope = await v3WaitForRequest(relay) {
            try envelope.verify(macPublicKeyX963: pairing.macPublicKeyX963, at: currentTimeMilliseconds())
            let offered = envelope.request.review
            check(offered.kind == .settings && offered.headline == change.title
                    && offered.settings?.changes == change.changes && offered.footnote == change.footnote
                    && offered.secrets.isEmpty && offered.delivery == nil && offered.scopeOptions.isEmpty
                    && offered.durationOptions.isEmpty && offered.delegation == nil
                    && envelope.request.unlockChallenge == nil,
                  "settings mirror: the signed request carries the panel's title, lines and footnote, and "
                    + "releases, opens and offers nothing")
            check(offered.operationDigest == ClaudeDelegationService.acknowledgementDigest([hook]),
                  "settings mirror: the signed request is bound to exactly the hooks it acknowledges")
            try await relay.publishResponse(try phone.approve(envelope))
            let decision = await asked.value
            let localCancelled = await local.cancelled
            check(decision.answer.refusal == nil && decision.decidedOn == .phone && localCancelled,
                  "settings mirror: the phone's approval approves, says so, and closes the Mac panel")
            check(await eventuallyTrue { await relay.deleted.contains(envelope.request.requestID) },
                  "settings mirror: the answered request is withdrawn from the mailbox")
            // The next panel is a new request with a new ID, decided on its
            // own (single use itself: settingsAcknowledgementSingleUseTests).
            let again = Task { await consent.decideSettingsChange(change, caller: caller, reason: change.title) }
            if let second = await v3WaitForRequest(relay, number: 1) {
                check(second.request.requestID != envelope.request.requestID,
                      "settings mirror: each panel is its own single-use request")
                try await relay.publishResponse(try phone.respond(to: second, .deny))
            } else {
                check(false, "settings mirror: each panel is its own single-use request")
            }
            let denied = await again.value
            check(denied.answer.refusal?.isHumanRefusal == true && denied.answer.refusal?.onPhone == true
                    && denied.answer.refusal?.logDecider == .humanPhone
                    && denied.answer.refusal?.why == "you pressed Deny on the iPhone",
                  "settings mirror: the next panel waits for its own answer, and the phone's Deny is the "
                    + "human's refusal, logged as made on the phone")
        } else {
            asked.cancel()
            _ = await asked.value
            check(false, "settings mirror: the acknowledgement reaches the phone")
        }
    } catch {
        check(false, "settings mirror: phone-decided acknowledgement (\(error))")
    }

    let phoneDeny = ConsentRefusal(panelDenial: .human(decidedAt: .now, on: .phone))
    let macDeny = ConsentRefusal(panelDenial: .human(decidedAt: .now, on: .mac))
    check(phoneDeny.isHumanRefusal && phoneDeny.logDecider == .humanPhone && macDeny.logDecider == .humanLocal
            && macDeny == ConsentRefusal(cause: .userCancel, onPanel: true),
          "settings mirror: a phone Deny is logged as the human's on the phone, a Mac Deny as at the Mac")
}
