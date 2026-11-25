import ConvenientSecurity
import Foundation
#if canImport(Darwin)
import Darwin
#endif

// The fourth review of the decision log: planted files must never push one of
// csecd's own damaged segments off the list of segments left out of the
// chain. Walked again, such a segment breaks the chain and sets aside
// everything written since the previous start, at every start. Hermetic, like
// the other log suites.

func decisionLogRoundFourTests() async {
    print("\n# Decision log: damaged segments stay excluded whatever is planted")
    excludedSegmentBoundTests()
    await plantedLowDigestTests()
    await plantedLiveNamedJunkTests()
    await excludedSegmentsNeverEvictedTests()
}

private final class RoundFourNotices: @unchecked Sendable {
    private let lock = NSLock()
    private var received = 0
    func append() { lock.lock(); received += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return received }
}

private struct RoundFourLog {
    let directory: String
    let backend = InMemoryProtectedItemBackend()
    let stores: ProtectedStores
    let limits: DecisionLogLimits
    let notices = RoundFourNotices()

    init(_ name: String, segmentBytes: UInt64) {
        directory = NSTemporaryDirectory() + "cs-selftest-dlround4-\(name)-\(UUID().uuidString.lowercased())"
        stores = .processLocal(backend)
        limits = DecisionLogLimits(
            segmentBytes: segmentBytes, decisionsCapBytes: 1 << 20, usageCapBytes: 1 << 20,
            usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
        )
    }

    func open() async -> (DecisionLog, DecisionLogVerification) {
        let notices = self.notices
        let log = DecisionLog(
            directory: SealedRecordDirectory(path: directory), stores: stores, limits: limits,
            bootSessionUUID: "boot-round-four", onIntegrityEvent: { _ in notices.append() }
        )
        return (log, await log.open())
    }

    func checkpoint() async -> DecisionLogCheckpoint? {
        if case let .document(document) = await stores.store(for: DecisionLogCheckpoint.self).load() {
            return document
        }
        return nil
    }

    func names() -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []).sorted()
    }

    func live() -> [String] {
        names().filter { $0.hasPrefix("decisions-") && $0.hasSuffix(".clog") && !$0.contains("-x") }
    }

    func path(_ name: String) -> String { (directory as NSString).appendingPathComponent(name) }

    func setImmutable(_ name: String, _ on: Bool) {
        _ = chflags(path(name), on ? UInt32(UF_IMMUTABLE) : 0)
    }

    /// A planted file that stays where it is: csecd can neither move nor
    /// remove it.
    func plantImmutable(_ name: String) {
        FileManager.default.createFile(atPath: path(name), contents: Data("planted junk, not a frame".utf8))
        setImmutable(name, true)
    }

    /// Flips one byte inside the segment's second frame: its first frame
    /// still authenticates, so it is damage to csecd's own history, not junk.
    func damageSecondFrame(_ name: String) -> Bool {
        guard var data = FileManager.default.contents(atPath: path(name)), data.count > 8 else { return false }
        let firstLength = data[4..<8].reduce(0) { $0 << 8 | Int($1) }
        let target = 28 + firstLength + 16 + 30
        guard target < data.count else { return false }
        data[target] ^= 0x01
        return FileManager.default.createFile(atPath: path(name), contents: data)
    }

    func quarantinedCount() -> Int {
        names().filter { $0.hasSuffix(".quarantined") }.count
    }

    func remove() {
        for name in names() { setImmutable(name, false) }
        try? FileManager.default.removeItem(atPath: directory)
    }
}

private func digest(_ name: String) -> String { DecisionLogCheckpoint.unmovableDigest(name) }

private func roundFourDecision(_ index: Int) -> DecisionLogRecord {
    DecisionLogRecord(
        kind: .panel, surface: .secretAccess, refs: ["csec://round-four/item-\(index)"],
        outcome: .approved, decider: .humanLocal, detail: "round four decision \(index)"
    )
}

private func roundFourPanels(_ log: DecisionLog) async -> [String] {
    var query = DecisionLogQuery(streams: [.decisions], kinds: [.panel])
    var details: [String] = []
    for _ in 0..<1_000 {
        let page = await log.read(query)
        details += page.records.compactMap(\.detail)
        guard let next = page.next, next != query.after else { break }
        query.after = next
    }
    return details
}

// MARK: - The checkpoint's two lists

private func excludedSegmentBoundTests() {
    let hex = (0..<97).map { String(format: "%016x", $0) }
    let full = DecisionLogCheckpoint(
        unmovable: Array(hex.prefix(DecisionLogCheckpoint.maximumUnmovable)),
        excludedSegments: Array(hex.prefix(DecisionLogCheckpoint.maximumExcludedSegments))
    )
    check(full.isWellFormed && !DecisionLogCheckpoint(excludedSegments: hex).isWellFormed
          && !DecisionLogCheckpoint(excludedSegments: ["not-a-digest"]).isWellFormed,
          "RL8: the checkpoint bounds and checks csecd's own excluded segments apart from planted files")
}

// MARK: - RL8: the reviewer's scenario (R3-cap)

private func plantedLowDigestTests() async {
    let fixture = RoundFourLog("low-digest", segmentBytes: 1_200)
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    for index in 1...20 { _ = await log.record(roundFourDecision(index)) }
    let segments = fixture.live()
    // The middle segment with the highest digest, so 32 planted names whose
    // digests sort below it are cheap to find.
    guard segments.count >= 4,
          let damaged = segments[1..<(segments.count - 1)].max(by: { digest($0) < digest($1) }),
          fixture.damageSecondFrame(damaged) else {
        check(false, "RL8: the fixture has a middle segment to damage")
        return
    }
    fixture.setImmutable(damaged, true)
    let target = digest(damaged)
    var planted: [String] = []
    var trial = 0
    while planted.count < DecisionLogCheckpoint.maximumUnmovable, trial < 4_000_000 {
        let name = "decisions-x\(trial).clog"
        if digest(name) < target { planted.append(name) }
        trial += 1
    }
    guard planted.count == DecisionLogCheckpoint.maximumUnmovable else {
        check(false, "RL8: the fixture finds 32 planted names with lower digests")
        return
    }
    planted.forEach(fixture.plantImmutable)

    var written = 20
    var starts: [DecisionLogVerification] = []
    var setAsideCounts: [Int] = []
    var latest: DecisionLog = log
    for _ in 1...3 {
        let (started, verification) = await fixture.open()
        starts.append(verification)
        for _ in 1...3 {
            written += 1
            _ = await started.record(roundFourDecision(written))
        }
        setAsideCounts.append(fixture.quarantinedCount())
        latest = started
    }
    let readable = await roundFourPanels(latest)
    let sinceFinding = (21...written).map { "round four decision \($0)" }
    let checkpoint = await fixture.checkpoint()
    check(starts[0].status == .discrepancy && starts[0].recorded
          && Set(starts[0].findings.map(\.finding)) == [.modifiedRecord, .foreignFile],
          "RL8: the first start records the damaged segment and the 32 planted files")
    check(starts[1].status == .clean && starts[2].status == .clean && fixture.notices.count == 1,
          "RL8: 32 planted low-digest files do not bring the damaged segment back: later starts are clean, one notification in all")
    check(sinceFinding.allSatisfy(readable.contains) && setAsideCounts[0] == setAsideCounts[2],
          "RL8: every decision written since the finding stays readable, and nothing more is set aside")
    check(checkpoint?.excludedSegments == [target] && checkpoint?.unmovable?.count == 32
          && checkpoint?.unmovable?.contains(target) == false,
          "RL8: the damaged segment is on the checkpoint's own-segment list; the planted files fill only theirs")
}

// MARK: - RL8: planted segment names in a finding's range are not csecd's own

private func plantedLiveNamedJunkTests() async {
    let fixture = RoundFourLog("live-named-junk", segmentBytes: 1_200)
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    for index in 1...12 { _ = await log.record(roundFourDecision(index)) }
    let segments = fixture.live()
    guard segments.count >= 3, fixture.damageSecondFrame(segments[1]) else {
        check(false, "RL8: the fixture has a middle segment to damage")
        return
    }
    fixture.setImmutable(segments[1], true)
    // Segment-shaped names after every real segment, so they fall inside the
    // range the finding sets aside.
    let junk = (0..<40).map { String(format: "decisions-%08d-%016x.clog", 50 + $0, 0xabc0 + $0) }
    junk.forEach(fixture.plantImmutable)

    let (_, first) = await fixture.open()
    let afterFirst = await fixture.checkpoint()
    let junkDigests = Set(junk.map(digest))
    check(first.status == .discrepancy && first.recorded
          && afterFirst?.excludedSegments == [digest(segments[1])]
          && Set(afterFirst?.unmovable ?? []).isSubset(of: junkDigests)
          && afterFirst?.unmovable?.count == DecisionLogCheckpoint.maximumUnmovable,
          "RL8: of the files in a finding's range, only csecd's own segment goes on the never-evicted list; planted names go on the capped one")

    let (second, again) = await fixture.open()
    _ = await second.record(roundFourDecision(13))
    let readable = await roundFourPanels(second)
    let afterSecond = await fixture.checkpoint()
    check(again.recorded && Set(again.findings.map(\.finding)).isSubset(of: [.splicedSegment])
          && readable.contains("round four decision 13")
          && afterSecond?.excludedSegments == [digest(segments[1])],
          "RL8: planted names past the cap are only found again as junk; the damaged segment stays excluded")
}

// MARK: - RL8: never evicted, even past the bound

private func excludedSegmentsNeverEvictedTests() async {
    // One record per segment: 100 segments.
    let fixture = RoundFourLog("never-evicted", segmentBytes: 1)
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    for index in 1...100 { _ = await log.record(roundFourDecision(index)) }
    let segments = fixture.live()
    guard segments.count == 100, unlink(fixture.path(segments[1])) == 0 else {
        check(false, "RL8: the fixture has 100 segments and removes the second")
        return
    }
    // Everything after the gap is csecd's own history that cannot be moved:
    // 98 segments, two more than the list holds. The 32 planted files fill
    // the other list, so the checkpoint is at its largest.
    for name in segments[2...] { fixture.setImmutable(name, true) }
    (0..<DecisionLogCheckpoint.maximumUnmovable).map { "decisions-x\($0).clog" }.forEach(fixture.plantImmutable)

    let (first, found) = await fixture.open()
    let firstStatus = await first.status()
    let firstCheckpoint = await fixture.checkpoint()
    let afterFirst = firstCheckpoint?.excludedSegments ?? []
    let expected = segments[2..<(2 + DecisionLogCheckpoint.maximumExcludedSegments)].map(digest)
    check(found.status == .discrepancy && found.recorded && afterFirst == expected
          && firstCheckpoint?.unmovable?.count == DecisionLogCheckpoint.maximumUnmovable
          && firstStatus.checkpointWriteFailures == 0,
          "RL8: 96 excluded segments and 32 planted digests fit the checkpoint item")

    let (second, _) = await fixture.open()
    let secondStatus = await second.status()
    let afterSecond = await fixture.checkpoint()?.excludedSegments ?? []
    check(afterSecond == afterFirst && secondStatus.checkpointWriteFailures == 0
          && !afterSecond.contains(digest(segments[98])) && !afterSecond.contains(digest(segments[99])),
          "RL8: past the bound, the segments already excluded stay excluded; none is evicted for a later one")
}
