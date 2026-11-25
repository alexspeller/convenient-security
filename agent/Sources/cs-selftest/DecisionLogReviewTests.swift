import ConvenientSecurity
import CryptoKit
import CSECRemoteApproval
import Foundation
import LocalAuthentication
import Security
#if canImport(Darwin)
import Darwin
#endif

// Adversarial cases for the decision log: recovery that cannot be written,
// planted names, an unusable directory, clock steps, newer formats, bounded
// reads, and the record points and prompt causes the first cut left out. Each
// log is hermetic (a temporary directory over process-local protected items).

func decisionLogReviewTests() async {
    print("\n# Decision log: recovery, planted names, directory modes")
    await unrecordableFindingTests()
    await plantedNameTests()
    await checkpointFailureStatusTests()
    await lostCheckpointAfterResumeTests()
    await directoryModeTests()
    print("\n# Decision log: reading (budget, clock steps, newer formats)")
    await readBudgetTests()
    await clockStepPagingTests()
    await newerFormatTests()
    logTimeFormatTests()
    print("\n# Decision log: shutdown, signals, uninstall without stores, durability")
    await shutdownFlushTests()
    terminationSignalInheritanceTests()
    await hostAuditChildSignalTests()
    await uninstallWithoutStoresTests()
    durableAppendTests()
    print("\n# Decision log: native-edit, SSH registration, automation, prompt causes")
    await nativeEditRecordTests()
    await sshRegistrationRecordTests()
    await automationRecordTests()
    await orphanedSetupReviewTests()
    await promptCauseTests()
}

// MARK: - Fixtures

private final class Notices: @unchecked Sendable {
    private let lock = NSLock()
    private var received: [DecisionLogVerification] = []
    func append(_ verification: DecisionLogVerification) { lock.lock(); received.append(verification); lock.unlock() }
    var all: [DecisionLogVerification] { lock.lock(); defer { lock.unlock() }; return received }
}

private final class StepClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: Date
    init(_ start: Date) { current = start }
    func now() -> Date { lock.lock(); defer { lock.unlock() }; return current }
    func set(_ date: Date) { lock.lock(); current = date; lock.unlock() }
}

private struct ReviewLog {
    let directory: String
    let backend = InMemoryProtectedItemBackend()
    let stores: ProtectedStores
    let limits: DecisionLogLimits
    let notices = Notices()
    let clock: StepClock?

    init(_ name: String, limits: DecisionLogLimits = ReviewLog.smallLimits, clock: StepClock? = nil) {
        directory = NSTemporaryDirectory() + "cs-selftest-dlreview-\(name)-\(UUID().uuidString.lowercased())"
        stores = .processLocal(backend)
        self.limits = limits
        self.clock = clock
    }

    static let smallLimits = DecisionLogLimits(
        segmentBytes: 1_200, decisionsCapBytes: 1 << 20, usageCapBytes: 1 << 20,
        usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
    )

    func open() async -> (DecisionLog, DecisionLogVerification) {
        let notices = self.notices
        let clock = self.clock
        let log = DecisionLog(
            directory: SealedRecordDirectory(path: directory), stores: stores, limits: limits,
            bootSessionUUID: "boot-review",
            clock: { clock?.now() ?? Date() },
            onIntegrityEvent: { notices.append($0) }
        )
        return (log, await log.open())
    }

    func checkpoint() async -> DecisionLogCheckpoint? {
        if case let .document(document) = await stores.store(for: DecisionLogCheckpoint.self).load() { return document }
        return nil
    }

    func names() -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []).sorted()
    }

    func live(_ stream: DecisionLogStream) -> [String] {
        names().filter { $0.hasPrefix("\(stream.rawValue)-") && $0.hasSuffix(".clog") }
    }

    func path(_ name: String) -> String { (directory as NSString).appendingPathComponent(name) }
    func bytes(_ name: String) -> Data { FileManager.default.contents(atPath: path(name)) ?? Data() }
    func write(_ name: String, _ data: Data) {
        FileManager.default.createFile(atPath: path(name), contents: data, attributes: [.posixPermissions: 0o600])
    }

    func setImmutable(_ on: Bool) { _ = chflags(directory, on ? UInt32(UF_IMMUTABLE) : 0) }

    func remove() {
        setImmutable(false)
        _ = chmod(directory, 0o700)
        try? FileManager.default.removeItem(atPath: directory)
    }
}

private func panel(_ index: Int) -> DecisionLogRecord {
    DecisionLogRecord(
        kind: .panel, surface: .secretAccess, refs: ["op://review/item-\(index)/password"],
        outcome: .approved, decider: .humanLocal, detail: "review decision \(index)"
    )
}

private func reuse(_ index: Int) -> DecisionLogRecord {
    DecisionLogRecord(kind: .reuse, surface: .secretAccess, refs: ["op://review/usage/password"],
                      outcome: .approved, decider: .grant, detail: "review reuse \(index)")
}

private func everything(
    _ log: DecisionLog, streams: [DecisionLogStream] = [.decisions, .usage],
    kinds: [DecisionLogRecord.Kind]? = nil, limit: Int = DecisionLogQuery.maximumLimit
) async -> (records: [DecisionLogRecord], pages: Int) {
    var query = DecisionLogQuery(streams: streams, kinds: kinds, limit: limit)
    var records: [DecisionLogRecord] = []
    var pages = 0
    while pages < 10_000 {
        let page = await log.read(query)
        pages += 1
        records += page.records
        guard let next = page.next, next != query.after else { break }
        query.after = next
    }
    return (records, pages)
}

// MARK: - H1: a finding that cannot be recorded

private func unrecordableFindingTests() async {
    // The recovery write fails (an immutable directory stands in for a full
    // disk): the checkpoint must not move back to the truncated files, the
    // log must stop, and the finding must come back until it is recorded.
    do {
        let fixture = ReviewLog("unrecordable")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...12 { _ = await log.record(panel(index)) }
        let before = await fixture.checkpoint()?.decisions?.seq
        guard let last = fixture.live(.decisions).last else { return }
        let data = fixture.bytes(last)
        fixture.write(last, data.prefix(data.count - 10))
        fixture.setImmutable(true)

        let (held, first) = await fixture.open()
        let afterFirst = await fixture.checkpoint()?.decisions?.seq
        let status = await held.status()
        let recordedWhileHeld = await held.record(panel(13))
        check(first.status == .discrepancy && !first.recorded && fixture.notices.all.count == 1,
              "H1: a finding whose recovery cannot be written is reported unrecorded and notified")
        check(before == 12 && afterFirst == 12,
              "H1: the checkpoint does not move back to the truncated files (\(before ?? 0) → \(afterFirst ?? 0))")
        check(status.unrecordedFinding && status.state == .unavailable && !recordedWhileHeld,
              "H1: the log is held: status shows the unrecorded finding and nothing chains onto the tail")
        let again = await held.verify()
        check(again.status == .discrepancy && !again.recorded && fixture.notices.all.count == 2,
              "H1: csec log --verify keeps reporting the finding while it cannot be recorded")

        fixture.setImmutable(false)
        let recovered = await held.verify()
        let afterRecovery = await fixture.checkpoint()?.decisions?.seq ?? 0
        let integrity = await everything(held, kinds: [.logIntegrity]).records
        check(recovered.status == .discrepancy && recovered.recorded && integrity.count == 1
              && afterRecovery > 12,
              "H1: once writable again, verify records the finding and only then moves the checkpoint forward")
        let (_, next) = await fixture.open()
        check(next.status == .clean, "H1: after the finding is recorded, the next start is clean")
    }

    // Thousands of planted segment files: the finding lists a bounded number
    // of names and still fits in one record, so it is recorded.
    do {
        let fixture = ReviewLog("planted-many")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...12 { _ = await log.record(panel(index)) }
        guard let last = fixture.live(.decisions).last else { return }
        let data = fixture.bytes(last)
        fixture.write(last, data.prefix(data.count - 10))
        for index in 0..<2_000 {
            fixture.write(String(format: "decisions-5%07d-%016x.clog", index, index), Data("junk".utf8))
        }
        let (reopened, result) = await fixture.open()
        let integrity = await everything(reopened, kinds: [.logIntegrity]).records
        let finding = integrity.first?.integrity?.first
        let seq = await fixture.checkpoint()?.decisions?.seq ?? 0
        check(result.status == .discrepancy && result.recorded && integrity.count == 1,
              "H1: a finding over 2,000 planted files is recorded")
        check((finding?.quarantined.count ?? 99) <= DecisionLogRecord.IntegrityFinding.maximumListedNames
              && (finding?.quarantinedCount ?? 0) >= 2_000,
              "H1: the finding lists at most 16 names and counts them all (\(finding?.quarantinedCount ?? 0))")
        check(seq > 12, "H1: the checkpoint only moves forward (\(seq))")
        check(await fixture.open().1.status == .clean, "H1: the next start is clean")
    }

    // A directory made read-only is simply repaired: csecd owns it.
    do {
        let fixture = ReviewLog("mode-0500")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...6 { _ = await log.record(panel(index)) }
        _ = chmod(fixture.directory, 0o500)
        guard let last = fixture.live(.decisions).last else { return }
        let data = fixture.bytes(last)
        _ = chmod(fixture.directory, 0o700)
        fixture.write(last, data.prefix(data.count - 10))
        _ = chmod(fixture.directory, 0o500)
        let (_, result) = await fixture.open()
        var info = stat()
        _ = stat(fixture.directory, &info)
        check(result.recorded && result.status == .discrepancy && (info.st_mode & 0o777) == 0o700,
              "H1: a directory set to 0500 is restored to 0700 and the finding is recorded")
    }
}

// MARK: - H2: planted names never set numbering or hide records

private func plantedNameTests() async {
    // A planted high-numbered quarantined name.
    do {
        let fixture = ReviewLog("planted-quarantined")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...2 { _ = await log.record(panel(index)) }
        fixture.write("decisions-99999999-0000000000000000.clog.quarantined", Data())
        fixture.write("usage-99999999-0000000000000000.clog.quarantined", Data())
        let (reopened, result) = await fixture.open()
        for index in 3...10 { _ = await reopened.record(panel(index)) }
        for index in 1...8 { _ = await reopened.record(reuse(index)) }
        await reopened.flushUsageCheckpoint()
        let status = await reopened.status()
        let numbers = fixture.live(.decisions).compactMap { Int($0.split(separator: "-")[1]) }
        check(result.status == .clean && status.checkpointWriteFailures == 0,
              "H2: a planted quarantined name is no finding and never blocks the checkpoint")
        check(numbers.allSatisfy { $0 < 100 } && fixture.live(.decisions).allSatisfy { $0.split(separator: "-")[1].count == 8 },
              "H2: segment numbers come only from verified segments (\(numbers))")
        let (restarted, next) = await fixture.open()
        let decisions = await everything(restarted, streams: [.decisions], kinds: [.panel]).records.map(\.seq)
        let usage = await everything(restarted, streams: [.usage], kinds: [.reuse]).records.count
        check(next.status == .clean && decisions == Array(1...10) && usage == 8,
              "H2: after a restart every record is still there")
    }

    // A planted nine-digit (unparseable) live name is foreign: a finding, set
    // aside, with no effect on numbering.
    do {
        let fixture = ReviewLog("planted-foreign")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...3 { _ = await log.record(panel(index)) }
        fixture.write("decisions-100000000-0000000000000000.clog", Data("junk".utf8))
        fixture.write("usage-1-ABC.clog", Data())
        let (reopened, result) = await fixture.open()
        for index in 4...8 { _ = await reopened.record(panel(index)) }
        let kinds = Set(result.findings.map(\.finding))
        let (restarted, next) = await fixture.open()
        let panels = await everything(restarted, streams: [.decisions], kinds: [.panel]).records
        check(kinds == [.foreignFile] && result.recorded && result.findings.count == 2,
              "H2: unparseable segment-shaped names are foreign files, recorded as a finding")
        check(!fixture.names().contains("decisions-100000000-0000000000000000.clog")
              && fixture.live(.decisions).allSatisfy { $0.split(separator: "-")[1].count == 8 },
              "H2: a foreign file is set aside and never becomes a segment name")
        check(next.status == .clean && panels.compactMap(\.detail) == (1...8).map { "review decision \($0)" },
              "H2: records written after a foreign file survive the next start")
    }

    // A planted high number in the exact format is junk: it fails to
    // authenticate, is set aside, and the next segment is numbered from the
    // verified ones.
    do {
        let fixture = ReviewLog("planted-high")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...3 { _ = await log.record(panel(index)) }
        fixture.write("decisions-99999998-0123456789abcdef.clog", Data("junk".utf8))
        let (reopened, result) = await fixture.open()
        for index in 4...9 { _ = await reopened.record(panel(index)) }
        let numbers = fixture.live(.decisions).compactMap { Int($0.split(separator: "-")[1]) }
        check(result.status == .discrepancy && result.recorded && numbers.allSatisfy { $0 < 100 },
              "H2: a planted high-numbered segment is set aside and numbering stays with verified segments")
        let (restarted, next) = await fixture.open()
        let panels = await everything(restarted, streams: [.decisions], kinds: [.panel]).records
        check(next.status == .clean && panels.compactMap(\.detail) == (1...9).map { "review decision \($0)" },
              "H2: no record disappears at the next start")
    }
}

private func checkpointFailureStatusTests() async {
    let fixture = ReviewLog("checkpoint-failure")
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    _ = await log.record(panel(1))
    await fixture.backend.inject(.failingWrites(errSecIO, delete: errSecIO), for: .decisionLogCheckpoint)
    _ = await log.record(panel(2))
    let status = await log.status()
    check(status.checkpointWriteFailures > 0,
          "H2: a checkpoint that cannot be written is counted for csec status (\(status.checkpointWriteFailures))")
    await fixture.backend.inject(.init(), for: .decisionLogCheckpoint)
}

// MARK: - L1: the checkpoint commit after a resume is lost

private func lostCheckpointAfterResumeTests() async {
    let fixture = ReviewLog("lost-commit")
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    for index in 1...9 { _ = await log.record(panel(index)) }
    let preRecovery = await fixture.backend.rawBytes(for: .decisionLogCheckpoint)
    let segments = fixture.live(.decisions)
    var data = fixture.bytes(segments[1])
    data[60] ^= 0x01
    fixture.write(segments[1], data)
    let (_, first) = await fixture.open()
    await fixture.backend.setRawBytes(preRecovery, for: .decisionLogCheckpoint)
    let (_, second) = await fixture.open()
    check(first.status == .discrepancy && second.status == .clean && fixture.notices.all.count == 1,
          "L1: a crash between the recorded resume and its checkpoint raises no second finding")
}

// MARK: - L3: directory and file modes

private func directoryModeTests() async {
    do {
        let fixture = ReviewLog("mode-000")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...4 { _ = await log.record(panel(index)) }
        if let first = fixture.live(.decisions).first { _ = chmod(fixture.path(first), 0o000) }
        _ = chmod(fixture.directory, 0o000)
        let (reopened, result) = await fixture.open()
        let recorded = await reopened.record(panel(5))
        check(result.status == .clean && recorded && fixture.notices.all.isEmpty,
              "L3: a directory and segment set to 000 are restored and the log carries on")
    }
    do {
        let fixture = ReviewLog("dir-unusable")
        defer {
            try? FileManager.default.removeItem(atPath: fixture.directory)
            fixture.remove()
        }
        let (log, _) = await fixture.open()
        for index in 1...3 { _ = await log.record(panel(index)) }
        try? FileManager.default.removeItem(atPath: fixture.directory)
        FileManager.default.createFile(atPath: fixture.directory, contents: Data("not a directory".utf8))
        let (reopened, result) = await fixture.open()
        let status = await reopened.status()
        check(result.status == .discrepancy && !result.recorded
              && result.findings.map(\.finding) == [.directoryUnusable]
              && fixture.notices.all.count == 1 && status.unrecordedFinding,
              "L3: an unusable log directory with a checkpoint is a notified, unrecorded finding, not silence")
    }
}

// MARK: - M1: bounded reads off the actor

private func readBudgetTests() async {
    let limits = DecisionLogLimits(
        segmentBytes: 64 * 1_024, decisionsCapBytes: 1 << 22, usageCapBytes: 1 << 22,
        usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024, readScanFrames: 7
    )
    let fixture = ReviewLog("budget", limits: limits)
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    for index in 1...30 { _ = await log.record(reuse(index)) }
    let firstPage = await log.read(DecisionLogQuery(streams: [.usage], kinds: [.prune]))
    check(firstPage.records.isEmpty && firstPage.next != nil,
          "M1: a filter that matches nothing returns an empty page with a cursor once its budget is spent")
    let none = await everything(log, streams: [.usage], kinds: [.prune])
    check(none.records.isEmpty && none.pages >= 5 && none.pages < 20,
          "M1: paging through a non-matching scan ends (\(none.pages) pages)")
    let all = await everything(log, streams: [.usage], kinds: [.reuse], limit: 4)
    check(all.records.map(\.seq) == Array(1...30),
          "M1: a budgeted scan returns every match exactly once, in order")
}

// MARK: - L2: paging across streams after the clock steps back

private func clockStepPagingTests() async {
    let clock = StepClock(Date(timeIntervalSince1970: 1_790_000_000))
    let fixture = ReviewLog("clock-step", clock: clock)
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    clock.set(Date(timeIntervalSince1970: 1_790_000_100)); _ = await log.record(panel(1))
    clock.set(Date(timeIntervalSince1970: 1_790_000_100)); _ = await log.record(reuse(1))
    clock.set(Date(timeIntervalSince1970: 1_790_000_050)); _ = await log.record(reuse(2))
    clock.set(Date(timeIntervalSince1970: 1_790_000_060)); _ = await log.record(panel(2))
    clock.set(Date(timeIntervalSince1970: 1_790_000_010)); _ = await log.record(panel(3))
    clock.set(Date(timeIntervalSince1970: 1_790_000_200)); _ = await log.record(reuse(3))
    for limit in 1...3 {
        let listed = await everything(log, kinds: [.panel, .reuse], limit: limit).records
        let keys = listed.map { "\($0.kind.rawValue)#\($0.seq)" }
        let expected = ["panel#1", "panel#2", "panel#3", "reuse#1", "reuse#2", "reuse#3"]
        check(keys.sorted() == expected && Set(keys).count == keys.count,
              "L2: after a backward clock step, two-stream paging (limit \(limit)) lists every record once (\(keys))")
    }
}

// MARK: - L5: records from a newer csecd

/// Seals a frame exactly as the format is specified, from the key item's
/// bytes: the check that an older build reads a newer build's frame is only
/// honest if the frame is not produced by this build's own writer.
private func sealForeignFormatFrame(
    fixture: ReviewLog, segment: String, seq: UInt64, plaintext: Data, firstInSegment: Bool = false
) async -> Bool {
    guard let envelope = await fixture.backend.rawBytes(for: .decisionLogKey),
          let object = try? JSONSerialization.jsonObject(with: envelope) as? [String: Any],
          let document = object["document"] as? [String: Any],
          let keyText = document["key"] as? String, let master = Data(base64Encoded: keyText) else { return false }
    let key = HKDF<SHA256>.deriveKey(
        inputKeyMaterial: SymmetricKey(data: master), info: Data("csec-decision-log-v1 frames".utf8),
        outputByteCount: 32
    )
    let existing = fixture.bytes(segment)
    guard firstInSegment || existing.count >= 16 else { return false }
    let previousTag = firstInSegment ? Data(repeating: 0, count: 16) : existing.suffix(16)
    let segmentID = String(segment.dropFirst("decisions-".count).dropLast(".clog".count))
    var aad = Data("csec-decision-log-v1\0".utf8)
    aad.append(Data("decisions".utf8)); aad.append(0)
    aad.append(Data(segmentID.utf8)); aad.append(0)
    withUnsafeBytes(of: seq.bigEndian) { aad.append(contentsOf: $0) }
    aad.append(previousTag)
    guard let box = try? AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(), authenticating: aad) else {
        return false
    }
    var frame = Data("CSL1".utf8)
    withUnsafeBytes(of: UInt32(box.ciphertext.count).bigEndian) { frame.append(contentsOf: $0) }
    withUnsafeBytes(of: seq.bigEndian) { frame.append(contentsOf: $0) }
    frame.append(contentsOf: box.nonce)
    frame.append(box.ciphertext)
    frame.append(box.tag)
    fixture.write(segment, existing + frame)
    return true
}

private func newerFormatTests() async {
    let limits = DecisionLogLimits(
        segmentBytes: 64 * 1_024, decisionsCapBytes: 1 << 22, usageCapBytes: 1 << 22,
        usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
    )
    let fixture = ReviewLog("newer", limits: limits)
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    for index in 1...2 { _ = await log.record(panel(index)) }
    guard let segment = fixture.live(.decisions).last else { return }
    let unknownValues = Data(#"{"v":2,"seq":3,"kind":"future_kind","wallTime":"2026-09-25T00:00:00.000Z","outcome":"future_outcome","decider":"future_decider","surface":"future_surface","newField":{"x":1}}"#.utf8)
    let newShape = Data(#"{"v":3,"seq":4,"kind":"panel","wallTime":"2026-09-25T00:00:01.000Z","refs":"a string now"}"#.utf8)
    let sealed = await sealForeignFormatFrame(fixture: fixture, segment: segment, seq: 3, plaintext: unknownValues)
    let sealedSecond = await sealForeignFormatFrame(fixture: fixture, segment: segment, seq: 4, plaintext: newShape)
    // A newer build's segment whose very first record (the one the chain
    // walk decodes) carries an unknown kind and a field this build lacks.
    let lastTag = fixture.bytes(segment).suffix(16)
    let previousID = String(segment.dropFirst("decisions-".count).dropLast(".clog".count))
    let nextSegment = "decisions-00000002-00000000000000aa.clog"
    fixture.write(nextSegment, Data())
    let firstOfSegment = Data(("{\"v\":2,\"seq\":5,\"kind\":\"future_kind\",\"wallTime\":\"2026-09-25T00:00:02.000Z\","
        + "\"futureOnly\":true,\"refs\":\"a string now\",\"chain\":{\"segmentID\":\"\(previousID)\",\"seq\":4,"
        + "\"tag\":\"\(lastTag.base64EncodedString())\"}}").utf8)
    let sealedThird = await sealForeignFormatFrame(
        fixture: fixture, segment: nextSegment, seq: 5, plaintext: firstOfSegment, firstInSegment: true
    )
    let (reopened, result) = await fixture.open()
    let records = await everything(reopened, streams: [.decisions]).records
    let third = records.first { $0.seq == 3 }
    let fourth = records.first { $0.seq == 4 }
    check(sealed && sealedSecond && sealedThird && result.status == .clean && fixture.notices.all.isEmpty
          && records.contains { $0.seq == 5 && $0.kind == .unrecognized },
          "L5: records a newer csecd wrote, even a segment's first, verify clean in an older one")
    check(third?.kind == .unrecognized && third?.outcome == .unrecognized && third?.decider == .unrecognized
          && third?.surface == .unrecognized,
          "L5: unknown kinds, outcomes, deciders and surfaces read as unrecognized")
    check(fourth?.kind == .unrecognized && fourth?.v == 3 && fourth?.detail?.contains("newer csecd") == true,
          "L5: a record this build cannot decode is shown as unrecognized, not reported as corrupt")
    let projection = try? JSONDecoder().decode(
        DecisionLogRecord.self,
        from: Data(#"{"v":1,"seq":1,"kind":"panel","wallTime":"2026-09-25T00:00:00.000Z","integrity":[{"stream":"decisions","finding":"a_future_finding","quarantined":[],"quarantinedCount":0}]}"#.utf8)
    )
    check(projection?.integrity?.first?.finding == .unrecognized,
          "L5: an unknown integrity finding kind decodes as unrecognized")
}

private func logTimeFormatTests() {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let samples: [TimeInterval] = [0, 1_790_000_000.123, 1_790_000_000.999, 951_782_400.5, 4_102_444_799.001]
    let agree = samples.allSatisfy { seconds in
        let date = Date(timeIntervalSince1970: seconds)
        let text = DecisionLogTime(date).text
        return text == formatter.string(from: date)
            && DecisionLogTime.parse(text).map { abs($0.timeIntervalSince1970 - formatter.date(from: text)!.timeIntervalSince1970) < 0.0005 } == true
    }
    check(agree, "M1: the log's hand-built time format matches ISO 8601 with milliseconds, both ways")
    check(DecisionLogTime.parse("2026-09-25T12:00:00Z") != nil && DecisionLogTime.parse("2026-13-25T12:00:00.000Z") == nil,
          "M1: other ISO 8601 spellings still parse, and an impossible month does not")
}

// MARK: - Shutdown, signals, uninstall, durability

private func shutdownFlushTests() async {
    let fixture = ReviewLog("flush-concurrent")
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    _ = await log.record(reuse(1))
    let lifecycle = CsecdLifecycle(
        stores: fixture.stores, log: log,
        current: CsecdLastRun(bootSessionUUID: "b", pid: 900, startTimeMicros: 1, cdHash: "aa", version: nil)
    )
    _ = await lifecycle.start()
    let result = await CsecdShutdown.flush(stores: fixture.stores, log: log, lifecycle: lifecycle)
    check(result == CsecdShutdown.Result(usageFlushed: true, cleanShutdownMarked: true),
          "M1: the SIGTERM flush and the clean mark both complete (run concurrently)")
}

/// Spawns a shell that sends itself SIGTERM, with nothing blocked (this test
/// runs on a Swift-concurrency thread, whose mask blocks SIGTERM), so only the
/// inherited disposition decides whether the signal ends it.
private func spawnSelfTerminatingShell() -> (signaled: Bool, status: Int32) {
    var pid: pid_t = 0
    let arguments = ["/bin/sh", "-c", "kill -TERM $$; exit 3"]
    var argv: [UnsafeMutablePointer<CChar>?] = arguments.map { strdup($0) } + [nil]
    defer { argv.forEach { free($0) } }
    var attributes: posix_spawnattr_t?
    guard posix_spawnattr_init(&attributes) == 0 else { return (false, -1) }
    defer { posix_spawnattr_destroy(&attributes) }
    var unblocked = sigset_t()
    sigemptyset(&unblocked)
    guard posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETSIGMASK)) == 0,
          posix_spawnattr_setsigmask(&attributes, &unblocked) == 0,
          posix_spawn(&pid, "/bin/sh", nil, &attributes, &argv, environ) == 0 else { return (false, -1) }
    var status: Int32 = 0
    while waitpid(pid, &status, 0) < 0, errno == EINTR {}
    let signaled = (status & 0x7f) != 0 && (status & 0x7f) != 0x7f
    return (signaled && (status & 0x7f) == SIGTERM, (status >> 8) & 0xff)
}

private func terminationSignalInheritanceTests() {
    signal(SIGTERM, SIG_IGN)
    let ignored = spawnSelfTerminatingShell()
    CsecdShutdown.catchTerminationSignal()
    let caught = spawnSelfTerminatingShell()
    CsecdShutdown.restoreDefaultTerminationSignal()
    check(!ignored.signaled && ignored.status == 3,
          "L6: with SIGTERM ignored, a spawned child cannot receive it (the old disposition)")
    check(caught.signaled,
          "L6: with SIGTERM caught, a child spawned by posix_spawn gets the default action back")
}

private func hostAuditChildSignalTests() async {
    // csecd's own disposition while it runs, and a Swift-concurrency caller:
    // the host-audit runner must still start its child able to receive SIGTERM.
    CsecdShutdown.catchTerminationSignal()
    let result = await SystemCommandRunner(timeout: 5, diagnostics: { _ in }).run(
        HostCommand(executable: "/bin/sh", arguments: ["-c", "kill -TERM $$; exit 3"], label: "fixture.sigterm")
    )
    CsecdShutdown.restoreDefaultTerminationSignal()
    check(result.exitCode == 128 + SIGTERM,
          "L6: a host-audit command starts with SIGTERM at its default action and unblocked (exit \(result.exitCode))")
}

private actor ApprovingConsent: ConsentProvider {
    func requestConsent(caller: CallerInfo, newReferences: [SecretRef], reason: String,
                        ttl: TimeInterval?, policySummary: String?) async -> ConsentOutcome {
        .approved(unlock: nil)
    }
    func authenticate(reason: String) async -> ConsentOutcome { .approved(unlock: nil) }
}

private func uninstallWithoutStoresTests() async {
    let directory = NSTemporaryDirectory() + "cs-selftest-dlreview-uninstall-\(UUID().uuidString.lowercased())"
    try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
    FileManager.default.createFile(atPath: directory + "/decisions-00000001-0000000000000000.clog", contents: Data())
    let outcome = await CsecdUninstaller(
        consent: ApprovingConsent(), stores: nil, log: nil,
        logDirectory: SealedRecordDirectory(path: directory)
    ).run(caller: setupCaller)
    guard case let .completed(result) = outcome else {
        check(false, "L4: an approved uninstall without protected stores completes")
        return
    }
    check(!result.isComplete && result.remainingItems.count == ProtectedItem.all.count
          && result.remainingItems.allSatisfy { $0.contains("not deleted") },
          "L4: without protected stores, uninstall reports every Keychain item as not deleted")
    check(result.logDirectoryRemoved && !FileManager.default.fileExists(atPath: directory),
          "L4: without a log this run, uninstall still deletes the log directory an earlier run wrote")
}

private func durableAppendTests() {
    let directory = SealedRecordDirectory(
        path: NSTemporaryDirectory() + "cs-selftest-dlreview-sync-\(UUID().uuidString.lowercased())"
    )
    defer { try? directory.removeDirectory() }
    do {
        try directory.prepare()
        let handle = try directory.createExclusive("decisions-00000001-0000000000000000.clog")
        try handle.append(Data("one".utf8), sync: .full)
        try handle.append(Data("two".utf8), sync: .fsync)
        try handle.synchronize(.full)
        try directory.fullSynchronize()
        handle.close()
        let read = try directory.read("decisions-00000001-0000000000000000.clog", maximumBytes: 64)
        check(read == Data("onetwo".utf8), "L7: full-sync appends and the directory flush succeed")
    } catch {
        check(false, "L7: full-sync appends and the directory flush succeed (\(error))")
    }
}

// MARK: - G1: native edit, SSH registration, automation

private actor UnlockingConsent: ConsentProvider {
    func requestConsent(caller: CallerInfo, newReferences: [SecretRef], reason: String,
                        ttl: TimeInterval?, policySummary: String?) async -> ConsentOutcome {
        .approved(unlock: CacheUnlock(LAContext()))
    }
    func authenticate(reason: String) async -> ConsentOutcome { .approved(unlock: CacheUnlock(LAContext())) }
}

private struct FixedOutcomeReview: PolicyReviewProvider {
    let outcome: AccessPolicyReviewOutcome
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome { outcome }
}

private func nativeEditRecordTests() async {
    let editor = CallerInfo(pid: 41_110, startTime: 4_111, description: "synthetic editor")
    let inspection = ProcessInspection(
        startTime: { $0 == editor.pid ? editor.startTime : nil }, parent: { _ in 1 },
        name: { _ in "synthetic" }, executablePath: { _ in "/synthetic/csec" }
    )
    for (label, outcome, expected) in [
        ("approved", AccessPolicyReviewOutcome.approved(AccessPolicyApproval(decidedOn: .mac)),
         DecisionLogRecord.Outcome.approved),
        ("denied", .denied(.human(decidedAt: .now, on: .mac)), .denied),
    ] {
        let fixture = ReviewLog("native-\(label)")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        let store = NativeEncryptedFileProvider(
            keyBackend: InMemoryNativeStoreKeyBackend(), fileBackend: InMemoryNativeStoreFileBackend()
        )
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(store)
        let agent = Agent(
            resolver: resolver, grants: GrantTable(), consent: UnlockingConsent(),
            policyReview: FixedOutcomeReview(outcome: outcome), nativeStore: store,
            allowUnverifiedPlansForTesting: true, processInspection: inspection,
            terminalInspection: .unavailable, decisionLog: log
        )
        _ = await agent.beginNativeStoreEdit(
            request: BeginNativeStoreEditRequest(
                store: "reviewedit", mode: .externalTemporaryFile, externalEditorPath: "/usr/bin/true"
            ),
            caller: editor
        )
        let panels = await everything(log, streams: [.decisions], kinds: [.panel]).records
        check(panels.count == 1 && panels[0].surface == .nativeEdit && panels[0].outcome == expected
              && (panels[0].refs?.first?.contains("reviewedit") ?? false)
              && panels[0].decider == .humanLocal,
              "G1: a native-store edit panel (\(label)) is recorded on the native_edit surface")
    }
}

private func sshRegistrationRecordTests() async {
    let fixture = ReviewLog("ssh-register")
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    do {
        let signing = try await SSHSocketSigningFixture.make(
            policyReview: FixedOutcomeReview(outcome: .denied(.human(decidedAt: .now, on: .mac))),
            decisionLog: log
        )
        _ = try? await signing.service.register(
            [SSHKeyRegistrationIntent(reference: "csec://ssh-liveness/other")],
            caller: CallerInfo(pid: getpid(), startTime: 1, description: "synthetic launcher")
        )
        let panels = await everything(log, streams: [.decisions], kinds: [.panel]).records
        check(panels.count == 1 && panels[0].surface == .sshSigning && panels[0].outcome == .denied
              && panels[0].decider == .humanLocal && panels[0].detail?.contains("register") == true,
              "G1: a denied SSH key-registration panel is recorded")
    } catch {
        check(false, "G1: the SSH registration fixture builds (\(error))")
    }
}

private actor EnrollmentInspector: AutomationProcessInspecting {
    private let executable: PlannedExecutable
    private var allowedInspections: Int
    init(executable: PlannedExecutable, allowedInspections: Int) {
        self.executable = executable
        self.allowedInspections = allowedInspections
    }
    func startTime(of pid: pid_t) async -> UInt64? { pid == 42_000 ? 420 : nil }
    func parent(of pid: pid_t) async -> pid_t? { nil }
    func executablePath(of pid: pid_t) async -> String? { "/synthetic/csec" }
    func inspectedExecutable(path: String) async -> PlannedExecutable? {
        guard path == executable.canonicalPath, allowedInspections > 0 else { return nil }
        allowedInspections -= 1
        return executable
    }
}

private struct EnrollmentProvider: SecretProvider {
    var schemes: Set<String> { ["op"] }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        ResolvedSecret(value: Data("synthetic-enrollment-value".utf8), cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private func automationRecordTests() async {
    let executable = PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified)
    let commandLine = ["/bin/sh", "-c", "synthetic enrolled script"]
    guard let digest = try? ExecutableInspection.commandDigest(commandLine) else {
        check(false, "G1: the enrollment fixture command digest is constructible")
        return
    }
    let command = AutomationCommand(
        executable: executable, commandLine: commandLine, workingDirectory: "/tmp", commandDigest: digest
    )
    let caller = CallerInfo(pid: 42_000, startTime: 420, description: "synthetic csec")
    for (label, inspections, enrolls) in [("changed", 1, false), ("enrolled", 99, true)] {
        let fixture = ReviewLog("automation-\(label)")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(EnrollmentProvider())
        let service = AutomationService(
            resolver: resolver, grantStore: InMemoryAutomationGrantStore(),
            materializationStore: InMemoryAutomationMaterializationStore(),
            consent: ApprovingConsent(),
            policyReview: FixedOutcomeReview(outcome: .approved(AccessPolicyApproval(decidedOn: .mac))),
            processInspector: EnrollmentInspector(executable: executable, allowedInspections: inspections),
            terminalInspection: .unavailable, decisionLog: log
        )
        let job = try? await service.enroll(AutomationEnrollment(
            name: "review-\(label)", reason: "Synthetic enrollment", references: ["op://review/enroll/token"],
            command: command, minimumIntervalSeconds: 60, maximumRuntimeSeconds: 300
        ), caller: caller)
        let panels = await everything(log, streams: [.decisions], kinds: [.panel]).records
        let detail = panels.first?.detail ?? ""
        check((job != nil) == enrolls && panels.count == 1 && panels[0].surface == .automation
              && panels[0].outcome == .approved
              && detail.contains("nothing was enrolled") == !enrolls,
              "L8: an automation approval is recorded after its identity checks (\(label): \(detail))")
    }
}

// MARK: - G2: why a panel appeared

private func orphanedSetupReviewTests() async {
    let me = getpid()
    guard let start = ProcessAncestry.startTime(of: me) else {
        check(false, "orphan setup: the test process has an incarnation")
        return
    }
    let caller = CallerInfo(pid: me, startTime: start, description: "synthetic setup caller")
    func tree(for caller: CallerInfo) -> AnchorFixtureTree {
        AnchorFixtureTree(starts: [caller.pid: caller.startTime, 96_001: 960],
                          parents: [caller.pid: 96_001, 96_001: 1], terminal: 0)
    }
    for mode in NativeStoreEditorMode.allCases {
        let fixture = ReviewLog("orphan-edit-\(mode.rawValue)")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        let tree = tree(for: caller), queue = ConsentQueue(), gate = GatedPolicyReview()
        let permit = try! await queue.acquire()
        let store = NativeEncryptedFileProvider(
            keyBackend: InMemoryNativeStoreKeyBackend(), fileBackend: InMemoryNativeStoreFileBackend()
        )
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(store)
        let agent = Agent(
            resolver: resolver, grants: GrantTable(), consent: UnlockingConsent(),
            policyReview: QueuedPolicyReview(underlying: gate, queue: queue), nativeStore: store,
            allowUnverifiedPlansForTesting: true, processInspection: tree.inspection,
            terminalInspection: .unavailable, decisionLog: log
        )
        let pending = Task {
            await agent.beginNativeStoreEdit(
                request: BeginNativeStoreEditRequest(
                    store: "orphanedit", mode: mode,
                    externalEditorPath: mode == .externalTemporaryFile ? "/usr/bin/true" : nil
                ), caller: caller
            )
        }
        check(await eventuallyTrue { await queue.waitingCount == 1 },
              "orphan setup: \(mode.rawValue) waits for its review")
        tree.reparent(caller.pid)
        let result = await pending.value
        let records = await everything(log, streams: [.decisions], kinds: [.withdrawn]).records
        check(result.editSessionID == nil && result.failure?.code == .consentDenied
              && records.count == 1 && records[0].detail?.contains("never shown; abandoned:") == true,
              "orphan setup: \(mode.rawValue) withdraws and logs without opening a store")
        check(await gate.reviews == 0, "orphan setup: \(mode.rawValue) is never presented")
        await permit.release()
    }
    do {
        let fixture = ReviewLog("orphan-register")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        let tree = tree(for: caller), queue = ConsentQueue(), gate = GatedPolicyReview()
        let permit = try! await queue.acquire()
        let catalog = SSHKeyCatalog(store: InMemorySSHKeyCatalogStore())
        // op:// needs a provider: a reference of a scheme no provider claims
        // is refused before any review, and this request must reach one.
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(EnrollmentProvider())
        let service = SSHSigningService(
            resolver: resolver, catalog: catalog,
            consent: UnlockingConsent(), policyReview: QueuedPolicyReview(underlying: gate, queue: queue),
            allowUnverifiedCallersForTesting: true, processInspection: tree.inspection,
            terminalInspection: .unavailable, decisionLog: log
        )
        let pending = Task {
            try? await service.register([SSHKeyRegistrationIntent(reference: "op://orphan/key/private key")], caller: caller)
        }
        check(await eventuallyTrue { await queue.waitingCount == 1 }, "orphan setup: key registration waits for review")
        tree.reparent(caller.pid)
        let result = await pending.value
        let records = await everything(log, streams: [.decisions], kinds: [.withdrawn]).records
        check(result == nil && records.count == 1 && records[0].detail?.contains("abandoned:") == true,
              "orphan setup: key registration withdraws and logs without resolving a key")
        check(await gate.reviews == 0, "orphan setup: key registration is never presented")
        await permit.release()
    }
    do {
        let fixture = ReviewLog("orphan-enroll")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        let caller = CallerInfo(pid: 42_000, startTime: 420, description: "synthetic enrollment caller")
        let tree = tree(for: caller), queue = ConsentQueue(), gate = GatedPolicyReview()
        let permit = try! await queue.acquire()
        let executable = PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified)
        let argv = ["/bin/sh", "-c", "synthetic orphan enrollment"]
        let command = AutomationCommand(
            executable: executable, commandLine: argv, workingDirectory: "/tmp",
            commandDigest: try! ExecutableInspection.commandDigest(argv)
        )
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(EnrollmentProvider())
        let service = AutomationService(
            resolver: resolver, grantStore: InMemoryAutomationGrantStore(),
            materializationStore: InMemoryAutomationMaterializationStore(), consent: ApprovingConsent(),
            policyReview: QueuedPolicyReview(underlying: gate, queue: queue),
            processInspector: EnrollmentInspector(executable: executable, allowedInspections: 99),
            terminalInspection: .unavailable, decisionLog: log, requestProcessInspection: tree.inspection
        )
        let pending = Task {
            try? await service.enroll(AutomationEnrollment(
                name: "orphan-enroll", reason: "Synthetic orphan enrollment", references: ["op://orphan/enroll/token"],
                command: command, minimumIntervalSeconds: 60, maximumRuntimeSeconds: 300
            ), caller: caller)
        }
        check(await eventuallyTrue { await queue.waitingCount == 1 }, "orphan setup: automation enrollment waits for review")
        tree.reparent(caller.pid)
        let result = await pending.value
        let records = await everything(log, streams: [.decisions], kinds: [.withdrawn]).records
        check(result == nil && records.count == 1 && records[0].detail?.contains("abandoned:") == true,
              "orphan setup: automation enrollment withdraws and logs without enrolling a job")
        check(await gate.reviews == 0, "orphan setup: automation enrollment is never presented")
        await permit.release()
    }
}

private final class MutableProcesses: @unchecked Sendable {
    private let lock = NSLock()
    private var parents: [pid_t: pid_t] = [:]
    func setParent(_ pid: pid_t, _ parent: pid_t) { lock.lock(); parents[pid] = parent; lock.unlock() }
    func parent(_ pid: pid_t) -> pid_t? {
        lock.lock(); defer { lock.unlock() }
        return parents[pid] ?? ProcessAncestry.parent(of: pid)
    }
}

private func promptCauseTests() async {
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let start = ProcessAncestry.startTime(of: me) else {
        check(false, "G2: the fixture reads its own start time")
        return
    }
    let outsider = Process()
    outsider.executableURL = URL(fileURLWithPath: "/bin/sleep")
    outsider.arguments = ["30"]
    guard (try? outsider.run()) != nil, let outsiderStart = ProcessAncestry.startTime(of: outsider.processIdentifier) else {
        check(false, "G2: the outsider requester starts")
        return
    }
    defer { if outsider.isRunning { outsider.terminate() } }
    let processes = MutableProcesses()
    processes.setParent(outsider.processIdentifier, 1)
    let inspection = ProcessInspection(
        startTime: { ProcessAncestry.startTime(of: $0) },
        parent: { processes.parent($0) },
        name: { ProcessAncestry.name(of: $0) },
        executablePath: { ProcessAncestry.executablePath(of: $0) },
        hasControllingTerminal: { _ in false }
    )
    let caller = CallerInfo(pid: me, startTime: start, description: "synthetic cause caller")
    let outsiderCaller = CallerInfo(pid: outsider.processIdentifier, startTime: outsiderStart, description: "outsider")
    let fixture = ReviewLog("causes")
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(EnrollmentProvider())
    let agent = Agent(
        resolver: resolver, grants: GrantTable(), consent: ApprovingConsent(),
        policyReview: FixedOutcomeReview(outcome: .approved(AccessPolicyApproval(decidedOn: .mac))),
        allowUnverifiedPlansForTesting: true, processInspection: inspection,
        terminalInspection: .unavailable, decisionLog: log
    )
    func plan(_ command: String, heap: Bool = false, ttl: Int? = nil) -> DeliveryPlan {
        DeliveryPlan(
            mechanism: heap ? .directHeap : .unrestrictedInitialEnvironment,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/\(command)", assurance: .unverified),
            root: .caller, descendantScope: .subtree, destination: .localDevelopment,
            requestedTTLSeconds: ttl, operationContext: "synthetic \(command)",
            outputGuard: heap ? nil : OutputGuardPlan(mode: .tty)
        )
    }
    func ask(_ refs: [String], _ plan: DeliveryPlan, as who: CallerInfo) async {
        let request = try! AccessRequest(
            references: refs, reason: plan.operationContext, ttlSeconds: plan.requestedTTLSeconds, deliveryPlan: plan
        )
        _ = await agent.handle(request: request, caller: who)
    }
    func lastCause() async -> String? {
        await everything(log, streams: [.decisions], kinds: [.panel]).records.last?.cause
    }

    await ask(["op://cause/a/password"], plan("one"), as: caller)
    check(await lastCause() == "new_refs", "G2: references never approved this run are new_refs")
    await ask(["op://cause/a/password"], plan("two", heap: true), as: caller)
    check(await lastCause() == "new_release_shape",
          "G2: approved for this process tree but another release shape is new_release_shape")
    await ask(["op://cause/b/password"], plan("three", ttl: 1), as: caller)
    try? await Task.sleep(for: .milliseconds(1_200))
    await ask(["op://cause/b/password"], plan("three", ttl: 1), as: caller)
    check(await lastCause() == "grant_expired", "G2: an approval past its chosen lifetime is grant_expired")
    await ask(["op://cause/c/password"], plan("four"), as: caller)
    _ = await agent.handleGrants(request: GrantsRequest(action: .revoke, all: true), caller: caller)
    await ask(["op://cause/c/password"], plan("four"), as: caller)
    check(await lastCause() == "grant_revoked", "G2: an approval revoked with csec revoke is grant_revoked")
    await ask(["op://cause/d/password"], plan("five"), as: outsiderCaller)
    await ask(["op://cause/d/password"], plan("five"), as: caller)
    check(await lastCause() == "new_process",
          "G2: approved for another process tree this request is not in is new_process")
}
