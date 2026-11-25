import CryptoKit
import CSECRemoteApproval
import ConvenientSecurity
import Foundation

// The phone's copy of a review with a deadline (csec-0.69): the moment the Mac
// panel closes unanswered travels in the signed request, and the card shows
// the Mac panel's own line (`ReviewDeadlineText`). The sudo leg's half is in
// SudoRemoteReviewTests.swift (`sudoPhoneDeadlineTests`).

func phoneDeadlineTests() async {
    print("\n# Phone deadline: the card shows when the Mac closes the request, in the panel's words")
    phoneDeadlineTextTests()
    phoneDeadlineProtocolTests()
    await phoneDeadlineMirrorTests()
    await sudoPhoneDeadlineTests()
}

private func phoneDeadlineTextTests() {
    let utc = TimeZone(identifier: "UTC")!
    let now = Date(timeIntervalSince1970: 1_792_000_000)
    let closesAt = now.addingTimeInterval(300)
    let mac = ReviewDeadline(remaining: .seconds(300), now: .now, nowDate: now)
    var same = true
    for remaining: Duration in [.seconds(300), .milliseconds(30_001), .seconds(30), .milliseconds(400), .zero, .seconds(-2)] {
        let panel = mac.line(remaining: remaining, now: now, timeZone: utc)
        let card = ReviewDeadlineText.line(closesAt: closesAt, remaining: remaining, now: now, timeZone: utc)
        same = same && panel.text == card.text && panel.isCountdown == card.isCountdown
    }
    check(same, "phone deadline: the card's line is the Mac panel's, word for word, at every stage")
    check(ReviewDeadlineText.line(closesAt: closesAt, now: now, timeZone: utc).text
            == "If nobody answers by 17:51, this closes without approving anything."
            && ReviewDeadlineText.line(closesAt: closesAt, now: closesAt.addingTimeInterval(-12.5), timeZone: utc).text
            == "Closes in 13 seconds if nobody answers, without approving anything.",
          "phone deadline: measured on the wall clock, the quiet line names the time and the countdown rounds up")

    let changes = ReviewDeadlineText.changes(closesAt: closesAt, from: now)
    check(changes.count == 31
            && abs(changes[0].timeIntervalSince(closesAt.addingTimeInterval(-30))) < 0.01
            && abs(changes[30].timeIntervalSince(closesAt)) < 0.01
            && changes.allSatisfy({ $0 > now }),
          "phone deadline: the card redraws when the countdown starts, at each second, and at the close")
    var previous = ReviewDeadlineText.line(closesAt: closesAt, now: now, timeZone: utc).text
    var eachChanges = true
    for date in changes {
        let text = ReviewDeadlineText.line(closesAt: closesAt, now: date, timeZone: utc).text
        eachChanges = eachChanges && text != previous
        previous = text
    }
    check(eachChanges, "phone deadline: each redraw shows a new number, never the same one twice")
    check(previous == "Closing: nobody answered in time. Nothing was approved.",
          "phone deadline: at the close the card says why, until the Mac's withdrawal takes it away")
    check(ReviewDeadlineText.changes(closesAt: now.addingTimeInterval(-1), from: now).isEmpty
            && ReviewDeadlineText.changes(closesAt: now.addingTimeInterval(10), from: now).count == 10,
          "phone deadline: a passed deadline schedules nothing; one inside the countdown only its seconds")
    check(mac.unixMilliseconds == 1_792_000_300_000,
          "phone deadline: the Mac sends the panel's closing moment in Unix milliseconds")
}

private func phoneDeadlineProtocolTests() {
    let createdAt: UInt64 = 1_760_000_000_000
    let closesAt = createdAt + 1_200_000
    func request(_ review: RemoteApprovalReview, created: UInt64 = createdAt) -> RemoteApprovalRequest {
        RemoteApprovalRequest(
            requestID: "00000000-0000-4000-8000-0000000000d1", macDeviceID: "00000000-0000-4000-8000-0000000000d2",
            macDeviceName: "Alex’s Mac", createdAtMilliseconds: created, review: review
        )
    }
    func error(_ body: () throws -> Void) -> RemoteApprovalValidationError? {
        do { try body() } catch let error as RemoteApprovalValidationError { return error } catch {}
        return nil
    }
    let access = v3AccessReviewFixture()
    let withDeadline = RemoteReviewParts.changing(access) { $0.closesAtMilliseconds = closesAt }

    check(RemoteApprovalRequest.signingDomain(for: access) == "csec.remote-approval.request.v3"
            && RemoteApprovalRequest.signingDomain(for: withDeadline) == "csec.remote-approval.request.v3+deadline",
          "phone deadline: a review without one signs exactly as before, one with it under its own domain")
    let every = RemoteReviewParts.changing(withDeadline) {
        $0.delegation = .init(note: "Auto mode didn't approve this: x", pairing: nil)
        $0.requesterCommand = "/usr/bin/python3 -m pytest"
    }
    check(RemoteApprovalRequest.signingDomain(for: every)
            == "csec.remote-approval.request.v3+delegation+command+deadline",
          "phone deadline: with a delegation block and a command line too, the domain names all three")
    let digest = try? request(withDeadline).digest()
    check(digest != nil && digest != (try? request(access).digest())
            && digest != (try? request(RemoteReviewParts.changing(access) { $0.closesAtMilliseconds = closesAt + 1 }).digest()),
          "phone deadline: the deadline is bound by the request signature, to the millisecond")

    let mac = P256.Signing.PrivateKey()
    if let signed = try? SignedRemoteApprovalRequest.signed(request(withDeadline), by: mac) {
        let key = mac.publicKey.x963Representation
        check((try? signed.verify(macPublicKeyX963: key, at: createdAt)) != nil,
              "phone deadline: the signed request with it verifies")
        let stripped = SignedRemoteApprovalRequest(request: request(access), signatureDER: signed.signatureDER)
        let moved = SignedRemoteApprovalRequest(
            request: request(RemoteReviewParts.changing(access) { $0.closesAtMilliseconds = closesAt + 600_000 }),
            signatureDER: signed.signatureDER)
        check((try? stripped.verify(macPublicKeyX963: key, at: createdAt)) == nil
                && (try? moved.verify(macPublicKeyX963: key, at: createdAt)) == nil,
              "phone deadline: dropping or moving the deadline in the mailbox breaks the signature")
        if let data = try? JSONEncoder().encode(signed),
           let decoded = try? JSONDecoder().decode(SignedRemoteApprovalRequest.self, from: data) {
            check(decoded.request.review.closesAtMilliseconds == closesAt
                    && (try? decoded.verify(macPublicKeyX963: key, at: createdAt)) != nil,
                  "phone deadline: it survives the mailbox's JSON and still verifies")
        } else {
            check(false, "phone deadline: the signed request round-trips through JSON")
        }
    } else {
        check(false, "phone deadline: a request with a deadline signs")
    }
    if let data = try? JSONEncoder().encode(request(access)),
       let decoded = try? JSONDecoder().decode(RemoteApprovalRequest.self, from: data) {
        check(decoded.review.closesAtMilliseconds == nil && decoded == request(access),
              "phone deadline: a request with none decodes with none")
    } else {
        check(false, "phone deadline: a request without one round-trips through JSON")
    }

    let limit = RemoteApprovalProtocolV3.maximumDeadlineMilliseconds
    check(error { try request(RemoteReviewParts.changing(access) { $0.closesAtMilliseconds = createdAt + limit }).validate(at: createdAt) } == nil,
          "phone deadline: a day after the request, the longest wait csecd allows, is accepted")
    check(error { try request(RemoteReviewParts.changing(access) { $0.closesAtMilliseconds = createdAt + limit + 1 }).validate(at: createdAt) }
            == .fieldOutOfBounds,
          "phone deadline: one further ahead than any wait is refused")
    check(error { try request(RemoteReviewParts.changing(access) { $0.closesAtMilliseconds = createdAt - 500 }).validate(at: createdAt) } == nil
            && error { try request(RemoteReviewParts.changing(access) { $0.closesAtMilliseconds = .max }, created: .max - 10).validate(at: .max) } == nil,
          "phone deadline: one already passed when the request was signed is shown as closing, not refused; no overflow")
    for (label, review) in [
        ("an SSH review", v3SSHReviewFixture()), ("a sudo review", v3SudoReviewFixture()),
    ] {
        check(error { try RemoteReviewParts.changing(review) { $0.closesAtMilliseconds = closesAt }.validate() } == nil,
              "phone deadline: \(label) may carry one")
    }
    let restoreOnly = RemoteApprovalReview(
        kind: .restore, headline: "csecd restarted", callerDescription: "fish (pid 20)", terminalDescription: nil,
        secrets: [], referenceSetDigest: Data(repeating: 1, count: 32), delivery: nil, warnings: [], footnote: nil,
        restore: .init(header: "csecd restarted", footnote: "Reopen?", storeCount: 1,
                       rows: [.init(kind: "secret", title: "fish", detail: "pid 20", secrets: [], ssh: nil)]),
        closesAtMilliseconds: closesAt, operationDigest: Data(repeating: 2, count: 32))
    check(error { try restoreOnly.validate() } == .inconsistentKind,
          "phone deadline: a restore-only review, which has no deadline, cannot carry one")

    let alert = RemoteApprovalNotificationText.content(for: withDeadline, macName: "Alex’s Mac")
    let plainAlert = RemoteApprovalNotificationText.content(for: access, macName: "Alex’s Mac")
    check(alert.title == plainAlert.title && alert.body == plainAlert.body,
          "phone deadline: the alert's words are unchanged; the card carries the line")
}

/// Records the review the phone leg was asked to publish, and denies it, so
/// the race ends without a panel.
private actor DeadlineCapturingPhone: RemoteAccessPolicyReviewProvider {
    private(set) var published: [RemoteApprovalReview] = []

    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        .ready(unlock: .notNeeded)
    }

    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        published.append(review)
        return .denied(receivedAt: .now)
    }
}

private func phoneDeadlineMirrorTests() async {
    let caller = CallerInfo(pid: 51, startTime: 9, description: "claude (pid 51)")
    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/python3", assurance: .unverified),
        root: .directParent(pid: 51, startTime: 9), descendantScope: .subtree,
        destination: .localDevelopment, requestedTTLSeconds: nil, operationContext: "deadline fixture"
    )
    let review = AccessPolicyReview(
        caller: caller, reason: "deadline fixture", plan: plan,
        credentials: [PolicyReviewCredential(references: [try! SecretRef("csec://harbor/RELAY_TOKEN")])]
    )
    func published(under wait: HumanWait?) async -> RemoteApprovalReview? {
        let phone = DeadlineCapturingPhone()
        let mirror = MirroredPolicyReview(local: V3UnansweredLocal(), remote: phone, log: { _ in })
        _ = await HumanWait.$current.withValue(wait) { await mirror.reviewAccess(review) }
        return await phone.published.first
    }
    let requester = HumanWait.Requester(pid: 51, startTime: 9)
    let arrived = Date(timeIntervalSince1970: 1_792_000_000)
    let agent = HumanWait(
        requester: requester, summary: "fixture", limit: .seconds(1_200),
        arrivedAt: .now, arrivedAtDate: arrived)
    let agentCopy = await published(under: agent)
    check(agentCopy?.closesAtMilliseconds == 1_792_001_200_000,
          "phone deadline: a coding agent's request reaches the phone with the moment csecd withdraws it")
    check(agentCopy?.closesAtMilliseconds == ReviewDeadline(agent)?.unixMilliseconds,
          "phone deadline: the phone's moment is the one the Mac panel counts down to")
    check(UInt64(ApprovalWaitLimit.allowedMinutes.upperBound) * 60_000
            == RemoteApprovalProtocolV3.maximumDeadlineMilliseconds,
          "phone deadline: the protocol's bound is the longest wait a coding agent's request can be given")
    let longest = await published(under: HumanWait(
        requester: requester, summary: "fixture", limit: .seconds(86_400), arrivedAt: .now, arrivedAtDate: Date()))
    check(longest?.closesAtMilliseconds != nil,
          "phone deadline: the longest wait a request can be given reaches the phone with its deadline")
    let beyond = await published(under: HumanWait(
        requester: requester, summary: "fixture", limit: .seconds(86_401), arrivedAt: .now, arrivedAtDate: Date()))
    check(beyond != nil && beyond?.closesAtMilliseconds == nil,
          "phone deadline: a deadline the request would refuse is dropped, and the review still reaches the phone")
    let terminal = await published(under: HumanWait(requester: requester, summary: "fixture", limit: nil))
    let none = await published(under: nil)
    check(terminal != nil && terminal?.closesAtMilliseconds == nil && none != nil && none?.closesAtMilliseconds == nil,
          "phone deadline: a terminal's request, and a review with no request wait, carry none")
    let restore = AccessPolicyReview(
        caller: caller, reason: "restore", plan: plan, credentials: [],
        restore: RestoreReviewDetails(
            cause: .restart,
            rows: [RestoreReviewRow(kind: .secretGrant, title: "fish", detail: "This terminal session · pid 20",
                                    references: ["csec://harbor/RELAY_TOKEN"])],
            storeCount: 1))
    let frozenRestore = try? RemoteApprovalReview(
        accessPolicyReview: restore, deadline: ReviewDeadline(remaining: .seconds(60)))
    check(frozenRestore?.kind == .restore && frozenRestore?.closesAtMilliseconds == nil,
          "phone deadline: a restore-only review never carries one")
}
