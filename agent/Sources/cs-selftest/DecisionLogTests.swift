import ConvenientSecurity
import CSECRemoteApproval
import CSecuritySupport
import Foundation
import LocalAuthentication
import Security

// The decision log (persistence §2.3), restart causes, the SIGTERM flush, and
// `csec uninstall`'s cleanup. Hermetic: every log lives in its own temporary
// directory over process-local protected items; nothing touches the
// installed csecd's log or the real Keychain.

/// A synthetic secret value the record-point tests release. It must never
/// appear in any record.
private let decisionLogSyntheticValue = "decision-log-synthetic-value-7f3a9c"

private final class IntegrityNotices: @unchecked Sendable {
    private let lock = NSLock()
    private var received: [DecisionLogVerification] = []
    func append(_ verification: DecisionLogVerification) {
        lock.lock(); received.append(verification); lock.unlock()
    }
    var count: Int { lock.lock(); defer { lock.unlock() }; return received.count }
}

/// One log's directory and protected items. `open()` builds a fresh
/// `DecisionLog` over them, which is how a csecd restart looks to the log.
private struct LogFixture {
    let directory: String
    let backend: InMemoryProtectedItemBackend
    let stores: ProtectedStores
    let limits: DecisionLogLimits
    let notices = IntegrityNotices()

    init(_ name: String, limits: DecisionLogLimits = smallLogLimits) {
        directory = NSTemporaryDirectory()
            + "cs-selftest-decision-log-\(name)-\(UUID().uuidString.lowercased())"
        backend = InMemoryProtectedItemBackend()
        stores = .processLocal(backend)
        self.limits = limits
    }

    func open() async -> (DecisionLog, DecisionLogVerification) {
        let notices = self.notices
        let log = DecisionLog(
            directory: SealedRecordDirectory(path: directory),
            stores: stores,
            limits: limits,
            bootSessionUUID: "00000000-0000-0000-0000-00000000b007",
            onIntegrityEvent: { notices.append($0) }
        )
        return (log, await log.open())
    }

    func checkpoint() async -> DecisionLogCheckpoint? {
        if case let .document(document) = await stores.store(for: DecisionLogCheckpoint.self).load() {
            return document
        }
        return nil
    }

    func liveSegments(_ stream: DecisionLogStream) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? [])
            .filter { $0.hasPrefix("\(stream.rawValue)-") && $0.hasSuffix(".clog") }
            .sorted()
    }

    func quarantined(_ stream: DecisionLogStream) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? [])
            .filter { $0.hasPrefix("\(stream.rawValue)-") && $0.hasSuffix(".quarantined") }
    }

    func path(_ name: String) -> String { (directory as NSString).appendingPathComponent(name) }

    func bytes(_ name: String) -> Data { FileManager.default.contents(atPath: path(name)) ?? Data() }

    func write(_ name: String, _ data: Data) {
        FileManager.default.createFile(
            atPath: path(name), contents: data, attributes: [.posixPermissions: 0o600]
        )
    }

    func remove() { try? FileManager.default.removeItem(atPath: directory) }
}

/// About three frames per segment, and a checkpoint delay long enough that a
/// test decides when usage is flushed.
private let smallLogLimits = DecisionLogLimits(
    segmentBytes: 1_200,
    decisionsCapBytes: 1 << 20,
    usageCapBytes: 1 << 20,
    usageCheckpointDelay: .seconds(3_600),
    maximumRecordBytes: 64 * 1_024
)

private func decisionEntry(_ index: Int) -> DecisionLogRecord {
    DecisionLogRecord(
        kind: .panel, surface: .secretAccess,
        requester: DecisionLogRecord.Requester(class: "exec", rootPID: 4_000 + Int32(index)),
        refs: ["op://decision-log/item-\(index)/password"],
        outcome: .approved, decider: .humanLocal, ttdMs: 1_000 + index,
        detail: "synthetic decision \(index)"
    )
}

private func usageEntry(_ index: Int) -> DecisionLogRecord {
    DecisionLogRecord(
        kind: .reuse, surface: .secretAccess,
        requester: DecisionLogRecord.Requester(class: "coding_agent", rootPID: 5_000),
        refs: ["op://decision-log/usage/password"],
        command: "synthetic reuse \(index)",
        outcome: .approved, decider: .grant
    )
}

private func allRecords(
    _ log: DecisionLog,
    streams: [DecisionLogStream] = [.decisions, .usage],
    kinds: [DecisionLogRecord.Kind]? = nil
) async -> [DecisionLogRecord] {
    var query = DecisionLogQuery(streams: streams, kinds: kinds)
    var records: [DecisionLogRecord] = []
    for _ in 0..<1_000 {
        let page = await log.read(query)
        records += page.records
        guard let next = page.next, !page.records.isEmpty else { break }
        query.after = next
    }
    return records
}

/// Byte ranges of the frames in a segment, from their cleartext headers.
private func frameRanges(_ data: Data) -> [Range<Int>] {
    let bytes = [UInt8](data)
    var ranges: [Range<Int>] = []
    var offset = 0
    while offset + 28 <= bytes.count {
        let length = bytes[(offset + 4)..<(offset + 8)].reduce(0) { $0 << 8 | Int($1) }
        let end = offset + 28 + length + 16
        guard end <= bytes.count else { break }
        ranges.append(offset..<end)
        offset = end
    }
    return ranges
}

func decisionLogTests() async {
    print("\n# Where a human decided, and the time to decision")
    await decisionSurfaceTests()
    print("\n# Decision log (sealed chain, checkpoint, integrity, caps)")
    await decisionLogRoundTripTests()
    await decisionLogTamperTests()
    await decisionLogTornTailTests()
    await decisionLogMissingAnchorTests()
    await decisionLogCapTests()
    await decisionLogUsageCheckpointTests()
    await decisionLogReadTests()
    print("\n# Restart causes, last-run, and the SIGTERM flush")
    restartCauseClassificationTests()
    await lifecycleTests()
    print("\n# csec uninstall cleanup and the uninstalled state")
    await protectedStoreUninstalledTests()
    await uninstallCleanupTests()
    startupProbeShapeTests()
    print("\n# Decision log record points")
    await accessRecordPointTests()
    await sshRecordPointTests()
}

// MARK: - Decision surface

private struct FixedPhone: RemoteAccessPolicyReviewProvider {
    let result: RemoteAccessReviewResult
    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        .ready(unlock: .notNeeded)
    }
    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        result
    }
}

private func surfaceReview() -> AccessPolicyReview {
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    return AccessPolicyReview(
        caller: CallerInfo(pid: me, startTime: ProcessAncestry.startTime(of: me) ?? 1, description: "surface"),
        reason: "surface", plan: recordPlan("surface"),
        credentials: [PolicyReviewCredential(references: [try! SecretRef("op://surface/item/password")])]
    )
}

private func decisionSurfaceTests() async {
    let review = surfaceReview()
    func approval(_ outcome: AccessPolicyReviewOutcome) -> AccessPolicyApproval? {
        if case let .approved(approval) = outcome { return approval }
        return nil
    }
    func reason(_ outcome: AccessPolicyReviewOutcome) -> AccessPolicyDenialReason? {
        if case let .denied(reason) = outcome { return reason }
        return nil
    }

    // The Touch ID sheet's own Deny is the human refusing on the Mac, stamped
    // with the panel's presentation.
    let shown = ContinuousClock.now
    if case let .human(decidedAt, surface, shownAt) = AccessPolicyDenialReason.afterAuthenticationFailure(
        LAError(.userCancel), shownAt: shown
    ) {
        check(surface == .mac && shownAt == shown && decidedAt >= shown,
              "surface: the Touch ID sheet's Deny is a Mac decision carrying when the panel was shown")
    } else {
        check(false, "surface: the Touch ID sheet's Deny is a human refusal")
    }

    // The phone's verified decisions say so, through the mirror and the queue.
    let received = ContinuousClock.now
    let phoneDeny = reason(await QueuedPolicyReview(
        underlying: MirroredPolicyReview(local: GatedPolicyReview(), remote: FixedPhone(result: .denied(receivedAt: received))),
        queue: ConsentQueue()
    ).reviewAccess(review))
    check(phoneDeny == .human(decidedAt: received, on: .phone, shownAt: nil),
          "surface: a phone Deny is a human refusal on the phone, with no panel time")
    let phoneApproval = approval(await QueuedPolicyReview(
        underlying: MirroredPolicyReview(local: GatedPolicyReview(), remote: FixedPhone(result: .approved(selection: remoteApprovalNoSelection, unlock: nil))),
        queue: ConsentQueue()
    ).reviewAccess(review))
    check(phoneApproval?.decidedOn == .phone && phoneApproval?.pairingLineShown == false,
          "surface: a phone approval reports the phone after the queue rewraps its session, and no pairing line")

    // A Mac approval keeps its surface and time to decision through both.
    let macApproval = approval(await QueuedPolicyReview(
        underlying: MirroredPolicyReview(
            local: MacPanelReview(answer: .approve(latency: .milliseconds(900))),
            remote: FixedPhone(result: .unavailable)
        ),
        queue: ConsentQueue()
    ).reviewAccess(review))
    check(macApproval?.decidedOn == .mac && macApproval?.decisionLatency == .milliseconds(900),
          "surface: a Mac approval stays decided on the Mac, with its time to decision, through mirror and queue")
    check(macApproval?.pairingLineShown == true,
          "surface: a Mac panel that showed the pairing line still says so after mirror and queue")
    await macApproval?.authenticationSession?.cancel()

    // A reviewer that reports nothing is never the Mac.
    check(AccessPolicyApproval().decidedOn == nil && AccessPolicyApproval().pairingLineShown == false,
          "surface: an approval that reports no surface is not decided on the Mac and showed no pairing line")

    // The log's mapping.
    let decided = ContinuousClock.now
    let mac = DecisionLogRecord.outcome(
        for: .human(decidedAt: decided, on: .mac, shownAt: decided.advanced(by: .milliseconds(-1_250)))
    )
    let phone = DecisionLogRecord.outcome(for: .human(decidedAt: decided, on: .phone))
    let unreported = DecisionLogRecord.outcome(for: .human(decidedAt: decided))
    check(mac.outcome == .denied && mac.decider == .humanLocal && mac.ttdMs == 1_250,
          "surface: a Mac Deny maps to human_local with its time to decision")
    check(phone.decider == .humanPhone && phone.ttdMs == nil,
          "surface: a phone Deny maps to human_phone with no time to decision")
    check(unreported.decider == .human && unreported.ttdMs == nil,
          "surface: a Deny that reports no surface maps to human")
    check(DecisionLogRecord.outcome(for: .requesterGone).decider == nil
          && DecisionLogRecord.outcome(for: .authenticationFailed).ttdMs == nil,
          "surface: a requester that left or a Touch ID failure has no decider and no time")
}

// MARK: - Round trip

private func decisionLogRoundTripTests() async {
    let fixture = LogFixture("roundtrip")
    defer { fixture.remove() }
    let (log, first) = await fixture.open()
    check(first.status == .firstRun, "log: no key, no checkpoint and no segments is a first run")
    check(!FileManager.default.fileExists(atPath: fixture.directory),
          "log: a first run creates no directory until something is recorded")
    for index in 1...7 { _ = await log.record(decisionEntry(index)) }
    for index in 1...4 { _ = await log.record(usageEntry(index)) }
    await log.flushUsageCheckpoint()

    let records = await allRecords(log)
    let decisions = records.filter { $0.kind == .panel }
    let usage = records.filter { $0.kind == .reuse }
    check(decisions.map(\.seq) == Array(1...7) && usage.map(\.seq) == Array(1...4),
          "log: each stream numbers its records from 1 without a gap")
    check(decisions.map { $0.refs ?? [] } == (1...7).map { ["op://decision-log/item-\($0)/password"] }
          && decisions.allSatisfy {
              $0.bootSessionUUID == "00000000-0000-0000-0000-00000000b007" && $0.v == 1
          },
          "log: records round-trip with the fields the log assigns")
    check(fixture.liveSegments(.decisions).count >= 2,
          "log: small segments roll over (\(fixture.liveSegments(.decisions).count) decision segments)")
    let raw = fixture.liveSegments(.decisions).map(fixture.bytes).reduce(Data(), +)
    check(raw.prefix(4) == Data("CSL1".utf8)
          && raw.range(of: Data("decision-log/item".utf8)) == nil
          && raw.range(of: Data("synthetic decision".utf8)) == nil,
          "log: segment files are sealed frames; no record text is readable on disk")
    let mode = (try? FileManager.default.attributesOfItem(atPath: fixture.directory))?[.posixPermissions] as? Int
    check(mode == 0o700, "log: the log directory is private (0700)")

    let checkpoint = await fixture.checkpoint()
    check(checkpoint?.decisions?.seq == 7 && checkpoint?.usage?.seq == 4,
          "log: the checkpoint names both streams' durable heads")
    let verified = await log.verify()
    check(verified.status == .clean && verified.findings.isEmpty, "log: a verification of an untouched log is clean")

    let filesBefore = fixture.liveSegments(.decisions)
    let (restarted, reopened) = await fixture.open()
    check(reopened.status == .clean && fixture.notices.count == 0,
          "log: reopening an untouched log verifies clean with no notification")
    _ = await restarted.record(decisionEntry(8))
    let afterRestart = await allRecords(restarted, streams: [.decisions])
    check(afterRestart.map(\.seq) == Array(1...8),
          "log: after a restart the chain continues at the next sequence number")
    check(fixture.liveSegments(.decisions).count <= filesBefore.count + 1,
          "log: a restart keeps appending to the last segment instead of opening a new one each time")
    check(await restarted.verify().status == .clean, "log: the continued chain verifies clean")
}

// MARK: - Tampering

private func decisionLogTamperTests() async {
    enum Setup { case twelve, rollback }

    func run(
        _ label: String,
        expecting finding: DecisionLogRecord.IntegrityFinding.Kind,
        alongside junk: Bool = false,
        setup: Setup = .twelve,
        tamper: (LogFixture, inout [String: Data]) -> Void
    ) async {
        let fixture = LogFixture("tamper-\(label)")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        var snapshot: [String: Data] = [:]
        for index in 1...12 {
            _ = await log.record(decisionEntry(index))
            if setup == .rollback, index == 6 {
                for name in fixture.liveSegments(.decisions) { snapshot[name] = fixture.bytes(name) }
            }
        }
        // Awaited on its own: Swift 6.4 (Xcode 27.1) reports an `await` over
        // the optional chain as covering no async call.
        let checkpoint = await fixture.checkpoint()
        guard let before = checkpoint?.decisions else {
            check(false, "tamper \(label): the log wrote a checkpoint")
            return
        }
        tamper(fixture, &snapshot)

        let (restarted, result) = await fixture.open()
        let expected: [DecisionLogRecord.IntegrityFinding.Kind] = junk ? [.splicedSegment, finding] : [finding]
        check(result.status == .discrepancy && result.findings.map(\.finding) == expected
              && result.findings.allSatisfy { $0.stream == .decisions },
              "tamper \(label): detected as \(finding.rawValue) (got \(result.status.rawValue): "
                  + "\(result.findings.map(\.finding.rawValue)))")
        let integrity = await allRecords(restarted, kinds: [.logIntegrity])
        check(integrity.count == 1, "tamper \(label): exactly one log_integrity record (\(integrity.count))")
        if let record = integrity.first {
            check(record.resume != nil && record.chain == before.link && record.seq > before.seq,
                  "tamper \(label): a fresh segment starts with the finding, chained to the checkpoint")
        }
        check(fixture.notices.count == 1, "tamper \(label): one user notification")
        check(await restarted.status().integrityEvents == 1,
              "tamper \(label): csec status reports the finding for this run")

        let (again, second) = await fixture.open()
        let integrityAfter = await allRecords(again, kinds: [.logIntegrity])
        check(second.status == .clean
              && integrityAfter.count == 1
              && fixture.notices.count == 1,
              "tamper \(label): the next start verifies clean and raises nothing again")
        _ = await again.record(decisionEntry(100))
        check(await again.verify().status == .clean, "tamper \(label): the resumed chain keeps verifying")
    }

    await run("flipped byte", expecting: .modifiedRecord) { fixture, _ in
        let segments = fixture.liveSegments(.decisions)
        var data = fixture.bytes(segments[1])
        let frames = frameRanges(data)
        data[frames[1].lowerBound + 40] ^= 0x01
        fixture.write(segments[1], data)
    }
    await run("reordered pair", expecting: .modifiedRecord) { fixture, _ in
        guard let name = fixture.liveSegments(.decisions).dropLast().first(where: {
            frameRanges(fixture.bytes($0)).count >= 3
        }) else { return }
        let data = fixture.bytes(name)
        let frames = frameRanges(data)
        var swapped = data.subdata(in: 0..<frames[1].lowerBound)
        swapped.append(data.subdata(in: frames[2]))
        swapped.append(data.subdata(in: frames[1]))
        swapped.append(data.subdata(in: frames[2].upperBound..<data.count))
        fixture.write(name, swapped)
    }
    // A segment from another log (another key), put in the place of a middle
    // one: the foreign file is set aside as junk, and the real segment it
    // replaced is missing from the chain.
    let other = LogFixture("tamper-foreign")
    let (foreign, _) = await other.open()
    for index in 1...12 { _ = await foreign.record(decisionEntry(index)) }
    let foreignSegment = other.bytes(other.liveSegments(.decisions)[1])
    await run("spliced segment", expecting: .missingSegment, alongside: true) { fixture, _ in
        fixture.write(fixture.liveSegments(.decisions)[1], foreignSegment)
    }
    other.remove()
    await run("deleted middle segment", expecting: .missingSegment) { fixture, _ in
        try? FileManager.default.removeItem(atPath: fixture.path(fixture.liveSegments(.decisions)[1]))
    }
    await run("truncated tail", expecting: .behindCheckpoint) { fixture, _ in
        guard let last = fixture.liveSegments(.decisions).last else { return }
        let data = fixture.bytes(last)
        fixture.write(last, data.prefix(data.count - 10))
    }
    await run("rolled-back segment set", expecting: .behindCheckpoint, setup: .rollback) { fixture, snapshot in
        for name in fixture.liveSegments(.decisions) {
            try? FileManager.default.removeItem(atPath: fixture.path(name))
        }
        for (name, data) in snapshot { fixture.write(name, data) }
    }

    // The usage stream: the finding is recorded in decisions, and usage resumes
    // in a fresh segment of its own.
    do {
        let fixture = LogFixture("tamper-usage")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        _ = await log.record(decisionEntry(1))
        for index in 1...12 { _ = await log.record(usageEntry(index)) }
        await log.flushUsageCheckpoint()
        let before = await fixture.checkpoint()?.usage
        let segments = fixture.liveSegments(.usage)
        var data = fixture.bytes(segments[1])
        data[frameRanges(data)[1].lowerBound + 40] ^= 0x80
        fixture.write(segments[1], data)
        let (restarted, result) = await fixture.open()
        check(result.findings.map(\.finding) == [.modifiedRecord] && result.findings.first?.stream == .usage,
              "tamper usage: a changed usage record is detected")
        let integrity = await allRecords(restarted, kinds: [.logIntegrity])
        let resumes = await allRecords(restarted, streams: [.usage], kinds: [.chainResume])
        check(integrity.count == 1 && integrity.first?.resume == nil,
              "tamper usage: one log_integrity record, appended to the decisions stream")
        check(resumes.count == 1 && resumes.first?.chain == before?.link && resumes.first?.resume != nil,
              "tamper usage: usage resumes in a fresh segment chained to its checkpoint")
        check(fixture.quarantined(.usage).count == segments.count - 1,
              "tamper usage: the altered segment and those after it are set aside")
        check(await fixture.open().1.status == .clean, "tamper usage: the next start is clean")
    }

    // A change made while csecd runs is found by `csec log --verify`.
    do {
        let fixture = LogFixture("tamper-runtime")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...6 { _ = await log.record(decisionEntry(index)) }
        let first = fixture.liveSegments(.decisions)[0]
        var data = fixture.bytes(first)
        data[frameRanges(data)[0].lowerBound + 40] ^= 0x01
        fixture.write(first, data)
        let result = await log.verify()
        check(result.status == .discrepancy && fixture.notices.count == 1,
              "tamper runtime: csec log --verify finds a change made while csecd runs")
        _ = await log.record(decisionEntry(7))
        check(await log.verify().status == .clean, "tamper runtime: the log verifies clean after resuming")
    }
}

// MARK: - Torn final frames

private func decisionLogTornTailTests() async {
    // A crash in the middle of the last write: uncommitted bytes after the
    // durable head are cut and recorded, never reported as tampering.
    do {
        let fixture = LogFixture("torn-decisions")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...5 { _ = await log.record(decisionEntry(index)) }
        guard let last = fixture.liveSegments(.decisions).last else { return }
        let intact = fixture.bytes(last)
        var torn = intact
        torn.append(Data("CSL1".utf8) + Data([0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 6]) + Data(repeating: 7, count: 40))
        fixture.write(last, torn)
        let (restarted, result) = await fixture.open()
        check(result.status == .repaired && result.tornTails == [.decisions] && result.findings.isEmpty,
              "torn: a partly written final frame is repaired, not a finding")
        let tornRecords = await allRecords(restarted, kinds: [.tornTail])
        let integrityRecords = await allRecords(restarted, kinds: [.logIntegrity])
        check(fixture.bytes(last).prefix(intact.count) == intact
              && tornRecords.count == 1
              && integrityRecords.isEmpty
              && fixture.notices.count == 0,
              "torn: the tail is cut, recorded once as torn_tail, and nothing is notified")
        check(await fixture.open().1.status == .clean, "torn: the next start is clean")
    }
    // Usage frames written after the last debounced checkpoint survive a crash;
    // a torn frame after them is cut.
    do {
        let fixture = LogFixture("torn-usage")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        _ = await log.record(decisionEntry(1))
        for index in 1...5 { _ = await log.record(usageEntry(index)) }
        guard let last = fixture.liveSegments(.usage).last else { return }
        var torn = fixture.bytes(last)
        torn.append(Data(repeating: 0, count: 64))
        fixture.write(last, torn)
        let (restarted, result) = await fixture.open()
        check(result.status == .repaired && result.tornTails == [.usage],
              "torn: zero-filled bytes after the usage chain are a torn tail")
        check((await allRecords(restarted, streams: [.usage], kinds: [.reuse])).count == 5,
              "torn: usage frames past the lagging checkpoint are kept")
        check(await fixture.checkpoint()?.usage?.seq == 5,
              "torn: the checkpoint catches up to the verified usage chain")
    }
    // A segment created just before a crash, with nothing in it.
    do {
        let fixture = LogFixture("torn-empty-segment")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...2 { _ = await log.record(decisionEntry(index)) }
        let empty = "decisions-99999999-0123456789abcdef.clog"
        fixture.write(empty, Data())
        let (_, result) = await fixture.open()
        check(result.status == .repaired && !fixture.liveSegments(.decisions).contains(empty),
              "torn: an empty last segment is removed as a torn write")
    }
}

// MARK: - Missing key, checkpoint or files

private func decisionLogMissingAnchorTests() async {
    do {
        let fixture = LogFixture("key-missing")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...5 { _ = await log.record(decisionEntry(index)) }
        let segments = fixture.liveSegments(.decisions)
        await fixture.backend.setRawBytes(nil, for: .decisionLogKey)
        let (restarted, result) = await fixture.open()
        check(result.status == .discrepancy && result.findings.map(\.finding) == [.keyMissing],
              "anchor: a missing key while segments exist is a finding, never a fresh start")
        let newKey = await fixture.backend.rawBytes(for: .decisionLogKey)
        check(fixture.quarantined(.decisions).count == segments.count && newKey != nil,
              "anchor: the unreadable segments are set aside and a new key is stored")
        check((await allRecords(restarted, kinds: [.logIntegrity])).count == 1 && fixture.notices.count == 1,
              "anchor: a missing key is recorded and notified once")
        check(await fixture.open().1.status == .clean, "anchor: the next start after a missing key is clean")
    }
    do {
        let fixture = LogFixture("checkpoint-missing")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...5 { _ = await log.record(decisionEntry(index)) }
        await fixture.backend.setRawBytes(nil, for: .decisionLogCheckpoint)
        let (restarted, result) = await fixture.open()
        check(result.status == .discrepancy && result.findings.map(\.finding) == [.checkpointMissing],
              "anchor: a missing checkpoint while segments exist is a finding")
        check((await allRecords(restarted, kinds: [.panel])).count == 5 && fixture.quarantined(.decisions).isEmpty,
              "anchor: the verified segments are kept when only the checkpoint is gone")
        check(await fixture.open().1.status == .clean, "anchor: the next start after a missing checkpoint is clean")
    }
    do {
        let fixture = LogFixture("directory-missing")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...5 { _ = await log.record(decisionEntry(index)) }
        fixture.remove()
        let (_, result) = await fixture.open()
        check(result.findings.map(\.finding) == [.behindCheckpoint],
              "anchor: a deleted log directory is detected against the checkpoint")
    }
    do {
        let fixture = LogFixture("key-only")
        defer { fixture.remove() }
        _ = await fixture.open()
        let (_, result) = await fixture.open()
        check(result.status == .clean && fixture.notices.count == 0,
              "anchor: a key with no checkpoint and no segments (nothing recorded yet) is not a finding")
    }
    do {
        let fixture = LogFixture("key-unreadable")
        defer { fixture.remove() }
        _ = await fixture.open()
        await fixture.backend.inject(.init(read: errSecInteractionNotAllowed), for: .decisionLogKey)
        let (log, result) = await fixture.open()
        let recorded = await log.record(decisionEntry(1))
        let keptKey = await fixture.backend.rawBytes(for: .decisionLogKey)
        check(result.status == .unavailable && !recorded
              && !FileManager.default.fileExists(atPath: fixture.directory)
              && keptKey != nil,
              "anchor: an unreadable key leaves the log off for this run and never replaces the key")
    }
}

// MARK: - Caps and pruning

private func decisionLogCapTests() async {
    do {
        let limits = DecisionLogLimits(
            segmentBytes: 1_200, decisionsCapBytes: 64 * 1_024, usageCapBytes: 4_000,
            usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
        )
        let fixture = LogFixture("cap-usage", limits: limits)
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...3 { _ = await log.record(decisionEntry(index)) }
        let decisionsBefore = fixture.liveSegments(.decisions)
        for index in 1...120 { _ = await log.record(usageEntry(index)) }
        let usageBytes = fixture.liveSegments(.usage).reduce(0) { $0 + fixture.bytes($1).count }
        check(usageBytes <= 4_000 + 1_200, "cap: the usage stream stays within its cap (\(usageBytes) bytes)")
        let decisions = await allRecords(log, streams: [.decisions])
        check(decisions.map(\.seq) == [1, 2, 3] && fixture.liveSegments(.decisions) == decisionsBefore,
              "cap: usage spam never evicts or adds to the decisions stream")
        let prunes = await allRecords(log, streams: [.usage], kinds: [.prune])
        check(!prunes.isEmpty && prunes.allSatisfy { $0.prune?.stream == .usage },
              "cap: each usage prune is recorded in the usage stream before its segment goes")
        let checkpoint = await fixture.checkpoint()
        let oldest = (await allRecords(log, streams: [.usage])).first?.seq ?? 0
        check((checkpoint?.usage?.prunedThroughSeq ?? 0) > 0 && oldest == (checkpoint?.usage?.prunedThroughSeq ?? 0) + 1,
              "cap: prunedThroughSeq in the checkpoint marks exactly what was pruned")
        check(await fixture.open().1.status == .clean, "cap: a pruned log verifies clean at the next start")
    }
    do {
        let limits = DecisionLogLimits(
            segmentBytes: 1_200, decisionsCapBytes: 4_000, usageCapBytes: 64 * 1_024,
            usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
        )
        let fixture = LogFixture("cap-decisions", limits: limits)
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...4 { _ = await log.record(decisionEntry(index)) }
        let oldestName = fixture.liveSegments(.decisions)[0]
        let oldestBytes = fixture.bytes(oldestName)
        for index in 5...40 { _ = await log.record(decisionEntry(index)) }
        let bytes = fixture.liveSegments(.decisions).reduce(0) { $0 + fixture.bytes($1).count }
        let kept = await allRecords(log, streams: [.decisions], kinds: [.panel])
        check(bytes <= 4_000 + 1_200 && kept.last?.seq != nil && kept.first.map { $0.seq > 1 } == true,
              "cap: the decisions stream drops its oldest segments to stay within its cap")
        check(await log.verify().status == .clean, "cap: a pruned decisions stream verifies clean")
        check(!fixture.liveSegments(.decisions).contains(oldestName),
              "cap: the oldest decisions segment was pruned")
        // A pruned segment that reappears (an interrupted prune, or a copy put
        // back) is a leftover to delete, not a finding.
        fixture.write(oldestName, oldestBytes)
        let (_, result) = await fixture.open()
        check(result.status == .clean && fixture.notices.count == 0
              && !fixture.liveSegments(.decisions).contains(oldestName),
              "cap: a pruned segment that reappears is deleted as a leftover, not reported")
    }
}

// MARK: - Usage checkpoint debounce and flush

private func decisionLogUsageCheckpointTests() async {
    do {
        let limits = DecisionLogLimits(
            segmentBytes: 1 << 20, decisionsCapBytes: 1 << 22, usageCapBytes: 1 << 22,
            usageCheckpointDelay: .milliseconds(150), maximumRecordBytes: 64 * 1_024
        )
        let fixture = LogFixture("debounce", limits: limits)
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        _ = await log.record(decisionEntry(1))
        await fixture.backend.clearOperations()
        for index in 1...10 { _ = await log.record(usageEntry(index)) }
        check(await fixture.checkpoint()?.usage == nil,
              "usage: a reuse does not rewrite the checkpoint item on every append")
        check(await eventuallyTrue { await fixture.checkpoint()?.usage?.seq == 10 },
              "usage: the checkpoint catches up within the write-coalescing delay")
        let writes = await fixture.backend.operations(on: .decisionLogCheckpoint).filter { $0 == .update || $0 == .add }
        check(writes.count <= 2, "usage: ten reuses cost at most two checkpoint writes (\(writes.count))")
    }
    do {
        let fixture = LogFixture("flush")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        _ = await log.record(decisionEntry(1))
        for index in 1...3 { _ = await log.record(usageEntry(index)) }
        let lifecycle = CsecdLifecycle(stores: fixture.stores, log: log, current: syntheticRun(cdHash: "aa"))
        _ = await lifecycle.start()
        let result = await CsecdShutdown.flush(stores: fixture.stores, log: log, lifecycle: lifecycle)
        let flushedUsage = await fixture.checkpoint()?.usage?.seq
        check(result == CsecdShutdown.Result(usageFlushed: true, cleanShutdownMarked: true)
              && flushedUsage == 3,
              "shutdown: the SIGTERM flush checkpoints usage at once and marks the run clean")
        let lastRun = await fixture.stores.store(for: CsecdLastRun.self).load()
        if case let .document(run) = lastRun {
            check(run.cleanShutdown, "shutdown: last-run records the clean shutdown")
        } else {
            check(false, "shutdown: last-run is readable after the flush")
        }
    }
}

// MARK: - Reading

private func decisionLogReadTests() async {
    let fixture = LogFixture("read", limits: DecisionLogLimits(
        segmentBytes: 64 * 1_024, decisionsCapBytes: 1 << 22, usageCapBytes: 1 << 22,
        usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
    ))
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    for index in 1...230 { _ = await log.record(decisionEntry(index)) }
    _ = await log.record(DecisionLogRecord(kind: .revoke, detail: "synthetic revoke"))
    let first = await log.read(DecisionLogQuery(streams: [.decisions]))
    check(first.records.count == DecisionLogQuery.maximumLimit && first.next != nil,
          "read: a page is bounded and says where the next one starts")
    var second = DecisionLogQuery(streams: [.decisions])
    second.after = first.next ?? DecisionLogCursor()
    let rest = await log.read(second)
    check(rest.records.count == 31 && rest.next == nil && rest.records.first?.seq == 201,
          "read: the next page continues after the cursor and ends the listing")
    let revokes = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.revoke]))
    check(revokes.records.count == 1 && revokes.records.first?.kind == .revoke,
          "read: --kind filters records")
    let future = await log.read(DecisionLogQuery(
        streams: [.decisions], since: DecisionLogTime(Date().addingTimeInterval(3_600))
    ))
    check(future.records.isEmpty, "read: --since filters by wall time")
    check(!DecisionLogQuery(streams: [.decisions], limit: 0).isWellFormed
          && !DecisionLogQuery(streams: [.decisions], limit: 201).isWellFormed
          && !DecisionLogQuery(streams: [], limit: 10).isWellFormed,
          "read: out-of-bounds queries are refused")
    let now = Date(timeIntervalSince1970: 1_790_000_000)
    check(DecisionLogTime.parseSince("30m", now: now) == now.addingTimeInterval(-1_800)
          && DecisionLogTime.parseSince("2d", now: now) == now.addingTimeInterval(-172_800)
          && DecisionLogTime.parseSince("2026-09-25T12:00:00Z") != nil
          && DecisionLogTime.parseSince("2026-09-25") != nil
          && DecisionLogTime.parseSince("yesterday") == nil,
          "read: --since accepts ISO 8601 times, dates and ages")
    let line = decisionEntry(3).displayLine()
    let header = DecisionLogRecord.displayHeader()
    check(line.contains("panel") && line.contains("approved") && line.contains("human_local")
          && line.contains("op://decision-log/item-3/password") && !line.contains("\n")
          && header.hasPrefix("TIME") && line.firstIndex(of: "p").map { line.distance(from: line.startIndex, to: $0) } == 20,
          "read: a record renders as one aligned table row under the header")
}

// MARK: - Restart causes

private func syntheticRun(
    boot: String = "boot-a", cdHash: String?, pid: Int32 = 400, clean: Bool = false
) -> CsecdLastRun {
    CsecdLastRun(
        bootSessionUUID: boot, pid: pid, startTimeMicros: 1_000, cdHash: cdHash,
        version: "1.0 (1)", cleanShutdown: clean
    )
}

private func restartCauseClassificationTests() {
    let current = syntheticRun(cdHash: "aa", pid: 500)
    check(CsecdRestartCause.classify(previous: nil, current: current) == .firstStart,
          "restart: no previous run is a first start")
    check(CsecdRestartCause.classify(previous: syntheticRun(boot: "boot-b", cdHash: "aa", clean: true), current: current) == .reboot,
          "restart: a different boot session is a reboot")
    check(CsecdRestartCause.classify(previous: syntheticRun(cdHash: "bb", clean: true), current: current) == .upgrade,
          "restart: a different cdhash on the same boot is an upgrade (or downgrade)")
    check(CsecdRestartCause.classify(previous: syntheticRun(cdHash: "aa", clean: true), current: current) == .restart,
          "restart: the same build after a clean SIGTERM is a restart")
    check(CsecdRestartCause.classify(previous: syntheticRun(cdHash: "aa", clean: false), current: current) == .crash,
          "restart: the same build with no clean shutdown is a crash")
    check(CsecdRestartCause.classify(previous: syntheticRun(boot: "boot-b", cdHash: "bb", clean: false), current: current) == .reboot,
          "restart: a reboot outranks a changed build and a missing shutdown mark")
    let facts = CsecdLastRun.current()
    check(facts.pid == getpid() && facts.startTimeMicros > 0 && facts.bootSessionUUID?.isEmpty == false,
          "restart: this process's boot session, pid and start time are readable")
}

private func lifecycleTests() async {
    let fixture = LogFixture("lifecycle")
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    let first = CsecdLifecycle(stores: fixture.stores, log: log, current: syntheticRun(cdHash: "aa", pid: 401))
    check(await first.start() == .firstStart, "lifecycle: the first start has no previous run")
    _ = await first.markCleanShutdown()
    let second = CsecdLifecycle(stores: fixture.stores, log: log, current: syntheticRun(cdHash: "aa", pid: 402))
    check(await second.start() == .restart, "lifecycle: after a clean shutdown the same build restarts")
    let third = CsecdLifecycle(stores: fixture.stores, log: log, current: syntheticRun(cdHash: "aa", pid: 403))
    check(await third.start() == .crash, "lifecycle: without the SIGTERM mark it was a crash")
    let fourth = CsecdLifecycle(stores: fixture.stores, log: log, current: syntheticRun(cdHash: "bb", pid: 404))
    check(await fourth.start() == .upgrade, "lifecycle: a new cdhash is an upgrade")
    let fifth = CsecdLifecycle(stores: fixture.stores, log: log, current: syntheticRun(boot: "boot-z", cdHash: "bb", pid: 405))
    check(await fifth.start() == .reboot, "lifecycle: a new boot session is a reboot")
    let restarts = await allRecords(log, kinds: [.restart])
    check(restarts.compactMap(\.cause) == ["first_start", "restart", "crash", "upgrade", "reboot"],
          "lifecycle: every start logs a restart record with its cause")
    await fixture.backend.setRawBytes(Data("not json".utf8), for: .lastRun)
    let sixth = CsecdLifecycle(stores: fixture.stores, log: log, current: syntheticRun(cdHash: "bb", pid: 406))
    check(await sixth.start() == .unknown, "lifecycle: an unreadable last-run is an unknown cause, not a first start")
}

// MARK: - The uninstalled state

private struct UninstallProbeDocument: ProtectedDocument, Equatable {
    static let protectedItem = ProtectedItem.grants
    static let formatVersion = 1
    var generation: Int
    var isWellFormed: Bool { generation >= 0 }
}

private func protectedStoreUninstalledTests() async {
    let backend = InMemoryProtectedItemBackend()
    let stores = ProtectedStores.processLocal(backend)
    let store = stores.store(for: UninstallProbeDocument.self)
    _ = try? await store.prepare(UninstallProbeDocument(generation: 1)).commit()
    let early = try? store.prepare(UninstallProbeDocument(generation: 2))
    stores.enterUninstalledState()
    check(stores.isUninstalled, "uninstalled: the state is visible to every consumer of the stores")
    var refused = false
    do { _ = try store.prepare(UninstallProbeDocument(generation: 3)) } catch ProtectedStoreError.uninstalled {
        refused = true
    } catch {}
    check(refused, "uninstalled: a write prepared after cleanup began is refused at prepare")
    await backend.clearOperations()
    var lateRefused = false
    do { _ = try await early?.commit() } catch ProtectedStoreError.uninstalled { lateRefused = true } catch {}
    let operations = await backend.operations(on: .grants)
    check(lateRefused && !operations.contains(.update) && !operations.contains(.add) && !operations.contains(.delete),
          "uninstalled: a write prepared earlier and committed later touches nothing")
    let remaining = await stores.deleteAll()
    let grantsAfter = await backend.rawBytes(for: .grants)
    check(remaining.isEmpty && grantsAfter == nil,
          "uninstalled: deletions still run")

    // The log consults the same switch: once the stores are uninstalled it
    // writes no frame and no checkpoint, even before its own directory goes.
    let fixture = LogFixture("uninstalled-switch")
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    _ = await log.record(decisionEntry(1))
    let segmentsBefore = fixture.liveSegments(.decisions).map(fixture.bytes)
    fixture.stores.enterUninstalledState()
    await fixture.backend.clearOperations()
    let decisionWritten = await log.record(decisionEntry(2))
    let usageWritten = await log.record(usageEntry(1))
    await log.flushUsageCheckpoint()
    let checkpointOperations = await fixture.backend.operations(on: .decisionLogCheckpoint)
    check(!decisionWritten && !usageWritten && checkpointOperations.isEmpty
          && fixture.liveSegments(.decisions).map(fixture.bytes) == segmentsBefore
          && fixture.liveSegments(.usage).isEmpty,
          "uninstalled: the log writes no frame and no checkpoint once the stores are uninstalled")
}

private actor ScriptedConsent: ConsentProvider {
    private let approve: Bool
    private(set) var reasons: [String] = []
    init(approve: Bool) { self.approve = approve }

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String,
        ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        approve ? .approved(unlock: nil) : .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        reasons.append(reason)
        return approve ? .approved(unlock: nil) : .denied
    }
}

private func uninstallCleanupTests() async {
    func populated(_ name: String) async -> (LogFixture, DecisionLog, CsecdLifecycle) {
        let fixture = LogFixture(name)
        let (log, _) = await fixture.open()
        let lifecycle = CsecdLifecycle(stores: fixture.stores, log: log, current: syntheticRun(cdHash: "aa"))
        _ = await lifecycle.start()
        _ = await log.record(decisionEntry(1))
        _ = await log.record(usageEntry(1))
        await log.flushUsageCheckpoint()
        // Documents later items own; only their presence matters here.
        for item in [ProtectedItem.delegationSettings, .delegationRegistrations, .grants, .pairing, .baselinePointer, .automationRuns, .githubProxy, .nativeStoreBackup, .machineIdentity] {
            await fixture.backend.setRawBytes(Data("{\"formatVersion\":1}".utf8), for: item)
        }
        return (fixture, log, lifecycle)
    }

    // Refused: nothing changes.
    do {
        let (fixture, log, _) = await populated("uninstall-denied")
        defer { fixture.remove() }
        let consent = ScriptedConsent(approve: false)
        let outcome = await CsecdUninstaller(
            consent: consent, stores: fixture.stores, log: log,
            logDirectory: SealedRecordDirectory(path: fixture.directory)
        )
            .run(caller: setupCaller)
        var present = true
        for item in ProtectedItem.all where await fixture.backend.rawBytes(for: item) == nil { present = false }
        check(outcome == .denied && present && !fixture.stores.isUninstalled
              && FileManager.default.fileExists(atPath: fixture.directory),
              "uninstall: without an approving Touch ID nothing is deleted and nothing enters the uninstalled state")
        let stillRecords = await log.record(decisionEntry(2))
        let stillVerifies = await log.verify().status
        check(stillRecords && stillVerifies == .clean,
              "uninstall: a refused cleanup leaves the log writing and verifying")
        let reasons = await consent.reasons
        check(reasons.count == 1 && reasons[0].hasPrefix("Uninstall Convenient Security")
              && reasons[0].contains(" — from "),
              "uninstall: one bare Touch ID sheet whose reason names the terminal")
        check(reasons.count == 1 && reasons[0].contains("Keychain items")
              && reasons[0].contains("decision log") && reasons[0].contains("sealed host-audit baseline"),
              "uninstall: the Touch ID reason names everything the cleanup deletes")
        check(reasons.count == 1 && reasons[0].hasPrefix(
                "Uninstall Convenient Security and delete its protected Keychain items (grants, project pairings "
                    + "and delegation settings), decision log and sealed host-audit baseline — from "),
              "uninstall: the Touch ID reason says the protected items, never all of csec's Keychain items")
        check(CsecdUninstaller.keptSummary.contains("cached secret values")
              && CsecdUninstaller.keptSummary.contains("native stores")
              && CsecdUninstaller.keptSummary.contains("iPhone pairing"),
              "uninstall: what the cleanup leaves in place is named for the success message")
    }

    // Approved: every item and the directory are gone, and nothing is written
    // again through any path.
    do {
        let (fixture, log, lifecycle) = await populated("uninstall-approved")
        defer { fixture.remove() }
        let outcome = await CsecdUninstaller(
            consent: ScriptedConsent(approve: true), stores: fixture.stores, log: log,
            logDirectory: SealedRecordDirectory(path: fixture.directory)
        ).run(caller: setupCaller)
        var anyLeft = false
        for item in ProtectedItem.all where await fixture.backend.rawBytes(for: item) != nil { anyLeft = true }
        check(outcome == .completed(UninstallCleanupResult(remainingItems: [], logDirectoryRemoved: true))
              && !anyLeft && !FileManager.default.fileExists(atPath: fixture.directory),
              "uninstall: every protected item and the log directory are deleted")
        await fixture.backend.clearOperations()
        let appended = await log.record(decisionEntry(3))
        let usageAppended = await log.record(usageEntry(3))
        await log.flushUsageCheckpoint()
        let marked = await lifecycle.markCleanShutdown()
        let flushed = await CsecdShutdown.flush(stores: fixture.stores, log: log, lifecycle: lifecycle)
        var protectedWriteRefused = false
        do {
            _ = try fixture.stores.store(for: UninstallProbeDocument.self).prepare(UninstallProbeDocument(generation: 9))
        } catch ProtectedStoreError.uninstalled { protectedWriteRefused = true } catch {}
        var writes: [ProtectedKeychainOperation] = []
        for item in ProtectedItem.all { writes += await fixture.backend.operations(on: item) }
        check(!appended && !usageAppended && !marked && flushed == CsecdShutdown.Result(usageFlushed: false, cleanShutdownMarked: false)
              && protectedWriteRefused
              && !writes.contains(.update) && !writes.contains(.add)
              && !FileManager.default.fileExists(atPath: fixture.directory),
              "uninstall: after cleanup no log append, checkpoint, last-run, protected write or SIGTERM flush writes anything")
        let verifiedAfter = await log.verify().status
        let stateAfter = await log.status().state
        check(verifiedAfter == .unavailable && stateAfter == .uninstalled,
              "uninstall: the log reports itself uninstalled")

        // A reinstall is a new csecd over empty items: it starts clean, with a
        // fresh key and no false finding.
        let reinstalled = LogFixture("uninstall-reinstall")
        defer { reinstalled.remove() }
        let fresh = DecisionLog(
            directory: SealedRecordDirectory(path: fixture.directory),
            stores: reinstalled.stores, limits: smallLogLimits
        )
        let result = await fresh.open()
        check(result.status == .firstRun && result.findings.isEmpty,
              "uninstall: a reinstall after a completed uninstall starts clean with no integrity finding")
    }
}

private func startupProbeShapeTests() {
    let add = SecurityKeychainBackend.probeQuery(adding: true)
    let match = SecurityKeychainBackend.probeQuery(adding: false)
    check(add[kSecAttrAccessGroup as String] as? String == ProtectedItem.accessGroup
          && match[kSecAttrAccessGroup as String] as? String == ProtectedItem.accessGroup,
          "probe: the startup probe names the protected items' explicit access group")
    check((add[kSecAttrAccessible as String] as? String) == (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String),
          "probe: the probe item is AfterFirstUnlockThisDeviceOnly, so a restart behind a locked screen passes it")
    check(match[kSecAttrAccessible as String] == nil && match[kSecValueData as String] == nil,
          "probe: the delete query matches a leftover probe item of any class")
    check(add[kSecUseDataProtectionKeychain as String] as? Bool == true
          && add[kSecAttrSynchronizable as String] as? Bool == false
          && add[kSecAttrAccessControl as String] == nil,
          "probe: data-protection keychain, not synchronizable, no biometric ACL")
}

// MARK: - Record points

private actor DecisionLogFixtureProvider: SecretProvider {
    nonisolated let schemes: Set<String> = ["op", "csec"]
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        ResolvedSecret(value: Data(decisionLogSyntheticValue.utf8), cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

/// Answers the way `TrustedAccessReviewSession` does: an approval carries a
/// live authentication session, the measured time to decision and `.mac`; a
/// Deny carries `.mac` and when the panel was shown. Each review is presented
/// once, as a panel is.
private struct MacPanelReview: PolicyReviewProvider {
    enum Answer: Sendable {
        case approve(latency: Duration)
        case deny(after: Duration)
    }
    let answer: Answer

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        switch answer {
        case let .approve(latency):
            return .approved(AccessPolicyApproval(
                authenticationSession: MacPanelSession(),
                decisionLatency: latency,
                pairingLineShown: true,
                decidedOn: .mac
            ))
        case let .deny(after):
            let shownAt = ContinuousClock.now
            return .denied(.human(decidedAt: shownAt.advanced(by: after), on: .mac, shownAt: shownAt))
        }
    }
}

private actor MacPanelSession: AccessPolicyAuthenticationSession {
    private var used = false
    /// Whether the touch yields a local context, as the real panel's does,
    /// so an approval can open a store csecd has not opened yet.
    private let unlocks: Bool
    init(unlocks: Bool = false) { self.unlocks = unlocks }
    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        guard !used else { return .denied }
        used = true
        return .approved(unlock: unlocks ? CacheUnlock(LAContext()) : nil)
    }
    func cancel() async { used = true }
}

/// The phone leg when no phone answers: the Mac panel decides alone.
private struct SilentPhone: RemoteAccessPolicyReviewProvider {
    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        .ready(unlock: .notNeeded)
    }
    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        .unavailable
    }
}

private struct DenyingPhone: RemoteAccessPolicyReviewProvider {
    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        .ready(unlock: .notNeeded)
    }
    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        .denied(receivedAt: .now)
    }
}

/// The Mac panel, left up until the phone's decision wins and cancels it.
private struct UnansweredLocalReview: PolicyReviewProvider {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        try? await Task.sleep(for: .seconds(5))
        return .denied(.requesterGone)
    }
}

private struct ApprovingPhone: RemoteAccessPolicyReviewProvider {
    func remoteReadiness(for references: [SecretRef], restoring: [SecretRef]) async -> RemoteReviewReadiness {
        .ready(unlock: .notNeeded)
    }
    func reviewRemoteAccess(_ review: RemoteApprovalReview, unlock: RemoteUnlockUse) async -> RemoteAccessReviewResult {
        .approved(selection: remoteApprovalNoSelection, unlock: nil)
    }
}

/// A provider whose resolution fails until it is healed, as a locked
/// provider or a missing item would.
private actor FlakyRecordProvider: SecretProvider {
    nonisolated let schemes: Set<String> = ["flaky"]
    private var failing = true
    func heal() { failing = false }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        if failing { throw ProviderError.notAuthenticated }
        return ResolvedSecret(value: Data(decisionLogSyntheticValue.utf8), cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

/// The Mac panel approving every review it is shown, counting them.
private actor CountingMacPanel: PolicyReviewProvider {
    private(set) var reviews = 0
    private let unlocks: Bool
    init(unlocks: Bool = false) { self.unlocks = unlocks }
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews += 1
        return .approved(AccessPolicyApproval(
            authenticationSession: MacPanelSession(unlocks: unlocks), decisionLatency: .milliseconds(500), decidedOn: .mac
        ))
    }
}

private func recordPlan(_ command: String) -> DeliveryPlan {
    DeliveryPlan(
        mechanism: .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/\(command)", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: nil, operationContext: "synthetic \(command)",
        outputGuard: OutputGuardPlan(mode: .tty)
    )
}

private func accessRecordPointTests() async {
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let start = ProcessAncestry.startTime(of: me) else {
        check(false, "record points: the fixture reads its own start time")
        return
    }
    let caller = CallerInfo(pid: me, startTime: start, description: "synthetic record-point caller")
    let silentTerminal = TerminalSessionInspector(
        environment: { _ in nil }, parent: { _ in nil }, terminalName: { _ in nil }, titleQuery: { _ in nil }
    )

    func harness(_ name: String, review: any PolicyReviewProvider) async -> (Agent, DecisionLog, LogFixture) {
        let fixture = LogFixture("records-\(name)")
        let (log, _) = await fixture.open()
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(DecisionLogFixtureProvider())
        let agent = Agent(
            resolver: resolver, grants: GrantTable(), consent: AutoApproveConsent(),
            policyReview: review, allowUnverifiedPlansForTesting: true,
            terminalInspection: silentTerminal, decisionLog: log
        )
        return (agent, log, fixture)
    }
    func ask(_ agent: Agent, _ refs: [String], _ command: String, argv: [String]? = nil) async -> Response {
        let request = try! AccessRequest(
            references: refs, reason: command, deliveryPlan: recordPlan(command), commandLine: argv
        )
        return await agent.handle(request: request, caller: caller)
    }
    func sealedText(_ fixture: LogFixture) -> Data {
        (fixture.liveSegments(.decisions) + fixture.liveSegments(.usage)).map(fixture.bytes).reduce(Data(), +)
    }
    let refs = ["op://record-points/item/password"]

    /// The production composition: the Mac panel mirrored to a phone, behind
    /// the UI queue, which rewraps an approval's session.
    func production(
        local: any PolicyReviewProvider,
        phone: any RemoteAccessPolicyReviewProvider = SilentPhone()
    ) -> any PolicyReviewProvider {
        QueuedPolicyReview(
            underlying: MirroredPolicyReview(local: local, remote: phone), queue: ConsentQueue()
        )
    }

    // A panel approval, then a reuse of the grant it minted.
    do {
        let panel = production(local: MacPanelReview(answer: .approve(latency: .milliseconds(1_830))))
        let (agent, log, fixture) = await harness("approve", review: panel)
        defer { fixture.remove() }
        let approved = await ask(agent, refs, "first")
        let reused = await ask(agent, refs, "first",
                               argv: ["/usr/bin/first", "--token", decisionLogSyntheticValue])
        let panels = await allRecords(log, streams: [.decisions], kinds: [.panel])
        let reuses = await allRecords(log, streams: [.usage], kinds: [.reuse])
        let grantIDs = await agent.handleGrants(request: GrantsRequest(action: .list), caller: caller)
            .grants?.map(\.id) ?? []
        check(approved.failure == nil && reused.failure == nil && panels.count == 1
              && panels[0].outcome == .approved && panels[0].decider == .humanLocal
              && panels[0].surface == .secretAccess && panels[0].refs == refs
              && panels[0].grantIDs == grantIDs && !grantIDs.isEmpty,
              "record points: an approved panel records its outcome, decider, refs and minted grants")
        check(reuses.count == 1 && reuses[0].decider == .grant && reuses[0].outcome == .approved
              && reuses[0].refs == refs,
              "record points: a reuse of that grant is recorded in the usage stream with decider grant")
        let encoded = try! JSONEncoder().encode(panels + reuses)
        check(String(decoding: encoded, as: UTF8.self).contains(decisionLogSyntheticValue) == false
              && reuses[0].command?.contains("--token") == true,
              "record points: a released value in a later command line is redacted in the record")
        check(sealedText(fixture).range(of: Data(decisionLogSyntheticValue.utf8)) == nil,
              "record points: no synthetic value reaches the log files")
    }

    // A human Deny from a reviewer that reports no surface, a requester that
    // went away, and a Touch ID failure.
    let endings: [(AccessPolicyDenialReason, DecisionLogRecord.Outcome, DecisionLogRecord.Decider?)] = [
        (.human(decidedAt: .now), .denied, .human),
        (.requesterGone, .requesterGone, nil),
        (.authenticationFailed, .authenticationFailed, nil),
    ]
    for (reason, outcome, decider) in endings {
        let gate = GatedPolicyReview(automatic: .deny(reason))
        let (agent, log, fixture) = await harness("deny-\(outcome.rawValue)", review: gate)
        defer { fixture.remove() }
        let response = await ask(agent, refs, "denied")
        let panels = await allRecords(log, streams: [.decisions], kinds: [.panel])
        check(response.failure?.code == .consentDenied && panels.count == 1
              && panels[0].outcome == outcome && panels[0].decider == decider
              && panels[0].grantIDs == nil && panels[0].ttdMs == nil,
              "record points: a \(outcome.rawValue) panel is recorded as such, with no grant")
    }

    // The time to decision the panel measured survives the UI queue's rewrap.
    do {
        let panel = production(local: MacPanelReview(answer: .approve(latency: .milliseconds(2_140))))
        let (agent, log, fixture) = await harness("ttd", review: panel)
        defer { fixture.remove() }
        _ = await ask(agent, refs, "measured")
        let panels = await allRecords(log, streams: [.decisions], kinds: [.panel])
        check(panels.first?.ttdMs == 2_140 && panels.first?.decider == .humanLocal,
              "record points: the Mac panel's time to decision is recorded in ms, through the queue")
    }

    // A human Deny on the Mac panel: human_local, with the time from the
    // panel's presentation to the Deny.
    do {
        let panel = production(local: MacPanelReview(answer: .deny(after: .milliseconds(2_400))))
        let (agent, log, fixture) = await harness("mac-deny", review: panel)
        defer { fixture.remove() }
        let response = await ask(agent, refs, "mac-deny")
        let panels = await allRecords(log, streams: [.decisions], kinds: [.panel])
        check(response.failure?.code == .consentDenied && panels.count == 1
              && panels[0].outcome == .denied && panels[0].decider == .humanLocal
              && panels[0].ttdMs == 2_400 && panels[0].grantIDs == nil,
              "record points: a Mac Deny is recorded by human_local with its time to decision")

        // It names the root of the scope the window offered by default, as an
        // approval of that default scope does, not the requesting command.
        // The same command is asked: with no coding agent or terminal shell
        // above this process (a detached run whose session leader exited),
        // the default scope is the requesting command, labelled by its name.
        let approving = production(local: MacPanelReview(answer: .approve(latency: .milliseconds(10))))
        let (approver, approvalLog, approvalFixture) = await harness("mac-deny-root", review: approving)
        defer { approvalFixture.remove() }
        _ = await ask(approver, refs, "mac-deny")
        let approved = await allRecords(approvalLog, streams: [.decisions], kinds: [.panel]).first
        check(approved != nil && panels.first?.requester?.rootPID == approved?.requester?.rootPID
              && panels.first?.requester?.rootLabel == approved?.requester?.rootLabel,
              "record points: a denied panel records the default scope's root and label, as an approval of it does")
    }

    // A phone Deny, through the production composition: human_phone, and no
    // time to decision, since this Mac cannot see when the phone showed it.
    do {
        let panel = production(local: UnansweredLocalReview(), phone: DenyingPhone())
        let (agent, log, fixture) = await harness("phone-deny", review: panel)
        defer { fixture.remove() }
        let response = await ask(agent, refs, "phone-deny")
        let panels = await allRecords(log, streams: [.decisions], kinds: [.panel])
        check(response.failure?.code == .consentDenied && panels.count == 1
              && panels[0].outcome == .denied && panels[0].decider == .humanPhone
              && panels[0].ttdMs == nil,
              "record points: a phone Deny is recorded by human_phone")
    }

    // A phone approval, through the production composition: the UI queue
    // rewraps the phone's session, so the surface must travel explicitly.
    do {
        let panel = production(local: UnansweredLocalReview(), phone: ApprovingPhone())
        let (agent, log, fixture) = await harness("phone", review: panel)
        defer { fixture.remove() }
        _ = await ask(agent, refs, "phone")
        let panels = await allRecords(log, streams: [.decisions], kinds: [.panel])
        check(panels.first?.outcome == .phoneApproved && panels.first?.decider == .humanPhone,
              "record points: a phone approval is recorded as phone_approved by human_phone, through the queue")
    }

    // An approval from a reviewer that reports no surface is never taken as
    // the Mac.
    do {
        let (agent, log, fixture) = await harness("no-surface", review: GatedPolicyReview(automatic: .approve(nil)))
        defer { fixture.remove() }
        _ = await ask(agent, refs, "no-surface")
        let panels = await allRecords(log, streams: [.decisions], kinds: [.panel])
        check(panels.first?.outcome == .approved && panels.first?.decider == .human,
              "record points: an approval that reports no surface is recorded by human, not human_local")
    }

    // A release that fails after the human approved mints nothing: the log
    // keeps the approval, then the value-free failure, and the next identical
    // request is reviewed again instead of riding a grant for a release that
    // never happened.
    do {
        let fixture = LogFixture("records-undelivered")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        let flaky = FlakyRecordProvider()
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(flaky)
        let panel = CountingMacPanel()
        let grants = GrantTable()
        let agent = Agent(
            resolver: resolver, grants: grants, consent: AutoApproveConsent(),
            policyReview: panel, allowUnverifiedPlansForTesting: true,
            terminalInspection: silentTerminal, decisionLog: log
        )
        let flakyRefs = ["flaky://record-points/item"]
        let failed = await ask(agent, flakyRefs, "undelivered")
        let minted = await grants.summaries(now: Date())
        let records = await allRecords(log, streams: [.decisions], kinds: [.panel, .deliveryFailed])
        check(failed.failure?.code == .resolutionFailed && failed.values == nil && minted.isEmpty,
              "grant after resolve: a release whose resolution failed mints no grant")
        check(records.map(\.kind) == [.panel, .deliveryFailed]
                && records.first?.outcome == .approved && records.first?.decider == .humanLocal
                && records.first?.grantIDs == nil
                && records.last?.refs == flakyRefs && records.last?.outcome == nil
                && records.last?.detail?.contains("could not resolve") == true
                && records.last?.detail?.contains("no grant was minted") == true,
              "grant after resolve: the log records the human's approval, then the value-free failure")
        await flaky.heal()
        let retried = await ask(agent, flakyRefs, "undelivered")
        let reviewsAfterRetry = await panel.reviews
        let mintedAfterRetry = await grants.summaries(now: Date())
        check(reviewsAfterRetry == 2 && retried.values != nil && mintedAfterRetry.count == 1,
              "grant after resolve: the next identical request is reviewed again, and its release mints the grant")
        let reused = await ask(agent, flakyRefs, "undelivered")
        let reviewsAfterReuse = await panel.reviews
        check(reused.values != nil && reviewsAfterReuse == 2,
              "grant after resolve: a grant minted for a delivered release covers the next request")
        let everything = await allRecords(log)
        check(!everything.isEmpty && !everything.contains {
                  ($0.detail ?? "").contains(decisionLogSyntheticValue)
                      || ($0.command ?? "").contains(decisionLogSyntheticValue)
              },
              "grant after resolve: no record holds a value")
    }

    // A native reference whose store exists but whose key does not, asked
    // after a restart, before csecd has opened the store (when csecd already
    // holds the store open it refuses such a request before any panel; see
    // AbsentReferenceTests): the approval delivers nothing, and the requester
    // and the log both say why, so the requester can stop asking instead of
    // retrying a bare failure. The panel's touch is a local context here, as
    // the real panel's is, so resolution reaches the store's own answer.
    do {
        let fixture = LogFixture("records-absent-native-key")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        let keys = InMemoryNativeStoreKeyBackend()
        let files = InMemoryNativeStoreFileBackend()
        let writer = NativeEncryptedFileProvider(keyBackend: keys, fileBackend: files)
        let store = try! NativeStoreName("records")
        let session = try! await writer.beginEdit(
            store: store, callerPID: me, callerStartTime: start, unlock: CacheUnlock(LAContext()))
        _ = try! await writer.commitEdit(
            sessionID: session.sessionID, document: Data(#"{"PRESENT":"x"}"#.utf8),
            callerPID: me, callerStartTime: start)
        let native = NativeEncryptedFileProvider(keyBackend: keys, fileBackend: files)
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(native)
        let agent = Agent(
            resolver: resolver, grants: GrantTable(), consent: AutoApproveConsent(),
            policyReview: CountingMacPanel(unlocks: true), allowUnverifiedPlansForTesting: true,
            terminalInspection: silentTerminal, decisionLog: log
        )
        let reason = NativeStoreError.secretNotFound.boundedReason
        let absent = await ask(agent, ["csec://records/ABSENT"], "absent-key")
        let records = await allRecords(log, streams: [.decisions], kinds: [.deliveryFailed])
        check(absent.failure?.code == .resolutionFailed
                && absent.failure?.message.contains("csec://records/ABSENT") == true
                && absent.failure?.message.contains(reason) == true,
              "native store: a missing key's failure tells the requester the key does not exist (\(absent.failure?.message ?? "none"))")
        check(records.count == 1 && records[0].detail?.contains(reason) == true,
              "native store: the delivery_failed record says the key does not exist")
    }

    // Revocation is a recorded settings mutation.
    do {
        let gate = GatedPolicyReview(automatic: .approve(nil))
        let (agent, log, fixture) = await harness("revoke", review: gate)
        defer { fixture.remove() }
        _ = await ask(agent, refs, "revoked")
        _ = await agent.handleGrants(request: GrantsRequest(action: .revoke, all: true), caller: caller)
        let revokes = await allRecords(log, streams: [.decisions], kinds: [.revoke])
        check(revokes.count == 1 && revokes[0].detail?.contains("1 grant dropped") == true,
              "record points: csec revoke is recorded")
    }

    // The log verb: listing needs no Touch ID and status reports the log.
    do {
        let gate = GatedPolicyReview(automatic: .approve(nil))
        let (agent, _, fixture) = await harness("verb", review: gate)
        defer { fixture.remove() }
        _ = await ask(agent, refs, "listed")
        let page = await agent.handleDecisionLog(
            request: DecisionLogRequest(action: .read, query: DecisionLogQuery(streams: [.decisions])),
            caller: caller
        )
        let status = await agent.handleDecisionLog(request: DecisionLogRequest(action: .status), caller: caller)
        let verify = await agent.handleDecisionLog(request: DecisionLogRequest(action: .verify), caller: caller)
        check(page.decisionLogPage?.records.contains { $0.kind == .panel } == true
              && status.decisionLogStatus?.state == .active
              && verify.decisionLogVerification?.status == .clean,
              "log verb: read, status and verify answer over the agent")
        let request = DecisionLogRequest(action: .read, query: DecisionLogQuery(streams: [.usage], limit: 5))
        let wire = try? JSONEncoder().encode(Request.decisionLog(request))
        let decoded = wire.flatMap { try? JSONDecoder().decode(Request.self, from: $0) }
        if case let .decisionLog(roundTrip) = decoded {
            check(roundTrip.action == .read && roundTrip.query == request.query && roundTrip.requestID == request.requestID,
                  "log verb: the request round-trips on the wire")
        } else {
            check(false, "log verb: the request round-trips on the wire")
        }
        let uninstallWire = try? JSONEncoder().encode(Request.uninstallCleanup(UninstallCleanupRequest()))
        if case .uninstallCleanup = uninstallWire.flatMap({ try? JSONDecoder().decode(Request.self, from: $0) }) {
            check(true, "uninstall verb: the request round-trips on the wire")
        } else {
            check(false, "uninstall verb: the request round-trips on the wire")
        }
        let malformed = Data(#"{"type":"decision_log","version":2,"requestID":"\#(UUID().uuidString)","action":"read"}"#.utf8)
        check((try? JSONDecoder().decode(Request.self, from: malformed)) == nil,
              "log verb: a read without a query is refused at decode")
    }
}

private func sshRecordPointTests() async {
    let gate = MacPanelReview(answer: .approve(latency: .milliseconds(1_320)))
    let fixture = LogFixture("records-ssh")
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    let signing: SSHSocketSigningFixture
    do {
        signing = try await SSHSocketSigningFixture.make(
            policyReview: QueuedPolicyReview(underlying: gate, queue: ConsentQueue()),
            decisionLog: log
        )
    } catch {
        check(false, "record points: the SSH signing fixture builds (\(error))")
        return
    }
    let socketDirectory = URL(fileURLWithPath: "/tmp", isDirectory: true)
        .appendingPathComponent("cs-dlog-\(UUID().uuidString.prefix(8))", isDirectory: true)
    try? FileManager.default.createDirectory(
        atPath: socketDirectory.path, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
    defer { try? FileManager.default.removeItem(at: socketDirectory) }
    let socketPath = socketDirectory.appendingPathComponent("ssh.sock").path
    let server = SSHAgentServer(
        path: socketPath, trustPolicy: .allowUnverifiedForTesting, provider: signing.service,
        diagnostics: { _ in }
    )
    Thread.detachNewThread { try? server.run() }
    guard await eventuallyTrue({ FileManager.default.fileExists(atPath: socketPath) }) else {
        check(false, "record points: the SSH agent socket binds")
        return
    }
    func signOnce() async -> Bool {
        await Task.detached { () -> Bool in
            let fd = socketPath.withCString { cs_connect_unix($0) }
            guard fd >= 0 else { return false }
            defer { close(fd) }
            guard writeFrame(fd, signing.bindMessage),
                  case let .frame(bound) = readFrame(fd, silence: 8), bound == Data([6]),
                  writeFrame(fd, signing.signMessage),
                  case let .frame(answer) = readFrame(fd, silence: 8) else { return false }
            return answer.first == 14
        }.value
    }
    let first = await signOnce()
    let second = await signOnce()
    let panels = await allRecords(log, streams: [.decisions], kinds: [.panel])
    let reuses = await allRecords(log, streams: [.usage], kinds: [.reuse])
    check(first && second && panels.count == 1 && panels[0].surface == .sshSigning
          && panels[0].outcome == .approved && panels[0].decider == .humanLocal
          && panels[0].ttdMs == 1_320
          && panels[0].refs == ["csec://ssh-liveness/key"]
          && panels[0].detail?.contains("SSH as deploy") == true,
          "record points: an approved SSH panel records the key reference, user and host")
    check(reuses.count == 1 && reuses[0].surface == .sshSigning && reuses[0].decider == .grant,
          "record points: a signature covered by the SSH grant is recorded as a reuse")
}
