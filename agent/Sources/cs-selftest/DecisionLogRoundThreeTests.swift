import ConvenientSecurity
import Foundation
#if canImport(Darwin)
import Darwin
#endif

// The third review of the decision log: a damaged segment csecd cannot move
// must be recorded once and left out, never hold the log at every start; an
// oldest segment that cannot be unlinked must be pruned once, not on every
// append; and a FIFO planted where csecd opens a file must never hold csecd
// on the open. Hermetic, like the other log suites.

func decisionLogRoundThreeTests() async {
    print("\n# Decision log: unmovable damaged segments, unlinkable pruned segments, planted FIFOs")
    await unmovableDamagedSegmentTests()
    await unlinkablePrunedSegmentTests()
    plantedFIFOSealedDirectoryTests()
    await plantedFIFOSegmentTests()
}

private final class RoundThreeNotices: @unchecked Sendable {
    private let lock = NSLock()
    private var received = 0
    func append() { lock.lock(); received += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return received }
}

private struct RoundThreeLog {
    let directory: String
    let backend = InMemoryProtectedItemBackend()
    let stores: ProtectedStores
    let limits: DecisionLogLimits
    let notices = RoundThreeNotices()

    init(_ name: String, limits: DecisionLogLimits) {
        directory = NSTemporaryDirectory() + "cs-selftest-dlround3-\(name)-\(UUID().uuidString.lowercased())"
        stores = .processLocal(backend)
        self.limits = limits
    }

    func open() async -> (DecisionLog, DecisionLogVerification) {
        let notices = self.notices
        let log = DecisionLog(
            directory: SealedRecordDirectory(path: directory), stores: stores, limits: limits,
            bootSessionUUID: "boot-round-three", onIntegrityEvent: { _ in notices.append() }
        )
        return (log, await log.open())
    }

    func checkpointSeq() async -> UInt64 {
        if case let .document(document) = await stores.store(for: DecisionLogCheckpoint.self).load() {
            return document.decisions?.seq ?? 0
        }
        return 0
    }

    func names() -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []).sorted()
    }

    func live() -> [String] {
        names().filter { $0.hasPrefix("decisions-") && $0.hasSuffix(".clog") }
    }

    func path(_ name: String) -> String { (directory as NSString).appendingPathComponent(name) }

    func setImmutable(_ name: String, _ on: Bool) {
        _ = chflags(path(name), on ? UInt32(UF_IMMUTABLE) : 0)
    }

    func remove() {
        for name in names() { setImmutable(name, false) }
        try? FileManager.default.removeItem(atPath: directory)
    }
}

private let roundThreeLimits = DecisionLogLimits(
    segmentBytes: 1_200, decisionsCapBytes: 6_000, usageCapBytes: 6_000,
    usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
)

private func roundThreeDecision(_ index: Int) -> DecisionLogRecord {
    DecisionLogRecord(
        kind: .panel, surface: .secretAccess, refs: ["op://round-three/item-\(index)/password"],
        outcome: .approved, decider: .humanLocal, detail: "round three decision \(index)"
    )
}

private func roundThreeRecords(_ log: DecisionLog, kinds: [DecisionLogRecord.Kind]) async -> [DecisionLogRecord] {
    var query = DecisionLogQuery(streams: [.decisions], kinds: kinds)
    var records: [DecisionLogRecord] = []
    for _ in 0..<1_000 {
        let page = await log.read(query)
        records += page.records
        guard let next = page.next, next != query.after else { break }
        query.after = next
    }
    return records
}

// MARK: - RL5: a damaged segment csecd cannot move

private func unmovableDamagedSegmentTests() async {
    let limits = DecisionLogLimits(
        segmentBytes: 1_200, decisionsCapBytes: 1 << 20, usageCapBytes: 1 << 20,
        usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
    )
    let fixture = RoundThreeLog("damaged-immutable", limits: limits)
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    for index in 1...12 { _ = await log.record(roundThreeDecision(index)) }
    let segments = fixture.live()
    guard segments.count >= 3, var data = FileManager.default.contents(atPath: fixture.path(segments[1])) else {
        check(false, "RL5: the fixture has a middle segment")
        return
    }
    // Flip a byte inside the segment's second frame: its first frame still
    // authenticates, so this is damage to real history, not junk.
    let firstLength = data[4..<8].reduce(0) { $0 << 8 | Int($1) }
    let secondFrame = 28 + firstLength + 16
    data[secondFrame + 30] ^= 0x01
    FileManager.default.createFile(atPath: fixture.path(segments[1]), contents: data)
    fixture.setImmutable(segments[1], true)
    let seqBefore = await fixture.checkpointSeq()

    let (first, found) = await fixture.open()
    let written = await first.record(roundThreeDecision(13))
    let status = await first.status()
    let seqAfterFirst = await fixture.checkpointSeq()
    check(found.status == .discrepancy && found.recorded && found.findings.map(\.finding) == [.modifiedRecord]
          && found.findings.first?.quarantined.contains(segments[1]) == true
          && written && fixture.names().contains(segments[1]) && status.stuckFiles.contains(segments[1]),
          "RL5: a damaged segment that cannot be moved is recorded once, left in place and named, and the log carries on")
    let reverified = await first.verify()
    let reverifiedStatus = await first.status()
    check(reverified.status == .clean && fixture.notices.count == 1 && reverifiedStatus.state == .active
          && reverifiedStatus.stuckFiles.filter { $0 == segments[1] }.count == 1,
          "RL5: a re-verification in the same run leaves it out too")
    let (second, again) = await fixture.open()
    let secondStatus = await second.status()
    let integrity = await roundThreeRecords(second, kinds: [.logIntegrity])
    let latest = await roundThreeRecords(second, kinds: [.panel]).compactMap(\.detail).last
    check(again.status == .clean && fixture.notices.count == 1 && integrity.count == 1
          && secondStatus.stuckFiles.contains(segments[1]) && latest == "round three decision 13",
          "RL5: the next start leaves it out of the chain quietly: no second finding, and later records stay readable")
    let seqAfterSecond = await fixture.checkpointSeq()
    check(seqAfterFirst > seqBefore && seqAfterSecond >= seqAfterFirst,
          "RL5: the checkpoint only moves forward")
    fixture.setImmutable(segments[1], false)
    let (_, freed) = await fixture.open()
    check(freed.status == .clean && !fixture.names().contains(segments[1]) && fixture.notices.count == 1,
          "RL5: once it can be moved, it is set aside with no second finding")
}

// MARK: - RL6: an oldest segment that cannot be unlinked

private func unlinkablePrunedSegmentTests() async {
    let fixture = RoundThreeLog("prune-immutable", limits: roundThreeLimits)
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    for index in 1...12 { _ = await log.record(roundThreeDecision(index)) }
    guard let oldest = fixture.live().first else {
        check(false, "RL6: the fixture has segments")
        return
    }
    let oldestID = String(oldest.dropFirst("decisions-".count).dropLast(".clog".count))
    fixture.setImmutable(oldest, true)
    // Append until the oldest segment's prune is recorded, then a few more:
    // those land in the newest segment, so every prune record written after
    // it is still readable.
    var appended = 12
    var prunedAt: Int?
    while prunedAt == nil, appended < 64 {
        appended += 1
        _ = await log.record(roundThreeDecision(appended))
        if await roundThreeRecords(log, kinds: [.prune]).contains(where: { $0.prune?.segmentID == oldestID }) {
            prunedAt = appended
        }
    }
    for _ in 1...5 {
        appended += 1
        _ = await log.record(roundThreeDecision(appended))
    }
    let prunes = await roundThreeRecords(log, kinds: [.prune]).compactMap(\.prune?.segmentID)
    check(prunedAt != nil && prunes.filter { $0 == oldestID }.count == 1 && Set(prunes).count == prunes.count,
          "RL6: an oldest segment that cannot be unlinked is pruned once, not again on every append")
    while appended < 32 {
        appended += 1
        _ = await log.record(roundThreeDecision(appended))
    }
    let status = await log.status()
    let kept = await roundThreeRecords(log, kinds: [.panel]).compactMap(\.detail)

    // The same appends into a log whose files can all be unlinked keep exactly
    // the same history: the stuck file costs no live history.
    let baseline = RoundThreeLog("prune-baseline", limits: roundThreeLimits)
    defer { baseline.remove() }
    let (plain, _) = await baseline.open()
    for index in 1...appended { _ = await plain.record(roundThreeDecision(index)) }
    let baselineKept = await roundThreeRecords(plain, kinds: [.panel]).compactMap(\.detail)
    check(fixture.names().contains(oldest) && status.stuckFiles.contains(oldest)
          && !kept.isEmpty && kept == baselineKept,
          "RL6: it is listed in csec status, and the log keeps exactly the history it keeps when the file can be unlinked")
    let verified = await log.verify()
    let verifiedStatus = await log.status()
    let (restarted, next) = await fixture.open()
    let nextStatus = await restarted.status()
    check(verified.status == .clean && next.status == .clean && fixture.notices.count == 0
          && verifiedStatus.stuckFiles.filter { $0 == oldest }.count == 1
          && nextStatus.stuckFiles.contains(oldest),
          "RL6: a re-verification and the next start treat it as a prune leftover: clean, no finding, still listed")
    fixture.setImmutable(oldest, false)
    let (_, freed) = await fixture.open()
    check(freed.status == .clean && !fixture.names().contains(oldest),
          "RL6: once it can be unlinked, the leftover is removed")
}

// MARK: - A FIFO planted where csecd opens a file

private final class PromptResult: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: String?
    func set(_ value: String) { lock.lock(); stored = value; lock.unlock() }
    var value: String? { lock.lock(); defer { lock.unlock() }; return stored }
}

/// Opens both ends of `fifo` without blocking, which releases an open that is
/// waiting on it, so a regression fails its check instead of hanging the run.
private func releaseFIFO(_ fifo: String) {
    let reader = open(fifo, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
    let writer = open(fifo, O_WRONLY | O_NONBLOCK | O_CLOEXEC)
    usleep(200_000)
    if reader >= 0 { close(reader) }
    if writer >= 0 { close(writer) }
}

/// Runs `body` on its own thread and returns its result, or nil when it is
/// still running after five seconds (then releasing whatever waits on `fifo`).
private func promptly(_ fifo: String, _ body: @escaping @Sendable () -> String) -> String? {
    let result = PromptResult()
    let done = DispatchSemaphore(value: 0)
    Thread.detachNewThread {
        result.set(body())
        done.signal()
    }
    guard done.wait(timeout: .now() + 5) == .timedOut else { return result.value }
    releaseFIFO(fifo)
    _ = done.wait(timeout: .now() + 5)
    return nil
}

private func sealedOutcome(_ body: () throws -> Void) -> String {
    do {
        try body()
        return "opened"
    } catch SealedRecordError.notPrivate {
        return "notPrivate"
    } catch {
        return "other: \(error)"
    }
}

private func plantedFIFOSealedDirectoryTests() {
    let root = NSTemporaryDirectory() + "cs-selftest-dlround3-fifo-\(UUID().uuidString.lowercased())"
    let directory = SealedRecordDirectory(path: root)
    defer { try? FileManager.default.removeItem(atPath: root) }
    let name = "baseline.sealed"
    let fifo = (root as NSString).appendingPathComponent(name)
    guard (try? directory.prepare()) != nil, mkfifo(fifo, 0o600) == 0 else {
        check(false, "FIFO: the fixture plants a FIFO")
        return
    }
    let read = promptly(fifo) { sealedOutcome { _ = try directory.read(name, maximumBytes: 1 << 20) } }
    let append = promptly(fifo) { sealedOutcome { _ = try directory.openForAppend(name) } }
    let truncate = promptly(fifo) { sealedOutcome { try directory.truncate(name, to: 0) } }
    check(read == "notPrivate" && append == "notPrivate" && truncate == "notPrivate",
          "FIFO: reading, appending to or truncating a planted FIFO returns at once and is refused "
          + "(read \(read ?? "blocked"), append \(append ?? "blocked"), truncate \(truncate ?? "blocked"))")

    // With a reader holding its other end, an open for writing succeeds at
    // once; the type check still refuses it.
    let reader = open(fifo, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
    let appendWithReader = promptly(fifo) { sealedOutcome { _ = try directory.openForAppend(name) } }
    if reader >= 0 { close(reader) }
    check(reader >= 0 && appendWithReader == "notPrivate",
          "FIFO: with a reader on the other end, an append open is still refused as not a regular file")

    // A FIFO where the directory belongs.
    let planted = SealedRecordDirectory(path: fifo)
    let asDirectory = promptly(fifo) { sealedOutcome { _ = try planted.read("x", maximumBytes: 16) } }
    let listed = promptly(fifo) { sealedOutcome { _ = try planted.entries() } }
    check(asDirectory == "notPrivate" && listed == "notPrivate",
          "FIFO: a FIFO in place of the directory is refused at once")

    // A regular file still reads.
    let regular = "regular.sealed"
    try? directory.writeAtomically(regular, data: Data("synthetic".utf8))
    let readBack = try? directory.read(regular, maximumBytes: 64)
    check(readBack == Data("synthetic".utf8), "FIFO: a regular file still reads in full")
}

private func plantedFIFOSegmentTests() async {
    let limits = DecisionLogLimits(
        segmentBytes: 1_200, decisionsCapBytes: 1 << 20, usageCapBytes: 1 << 20,
        usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
    )
    let fixture = RoundThreeLog("fifo-segment", limits: limits)
    defer { fixture.remove() }
    let (log, _) = await fixture.open()
    for index in 1...12 { _ = await log.record(roundThreeDecision(index)) }
    let segments = fixture.live()
    guard segments.count >= 3 else {
        check(false, "FIFO: the fixture has a middle segment")
        return
    }
    // Swap a live segment for a FIFO under the same name, after csecd has
    // listed it: its reads and its next verification open that name.
    let fifo = fixture.path(segments[1])
    guard unlink(fifo) == 0, mkfifo(fifo, 0o600) == 0 else {
        check(false, "FIFO: the fixture swaps a segment for a FIFO")
        return
    }
    let page = PromptResult()
    let reading = Task.detached {
        let result = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.panel]))
        page.set(result.incomplete ? "incomplete" : "complete \(result.records.count)")
    }
    for _ in 0..<50 where page.value == nil { try? await Task.sleep(nanoseconds: 100_000_000) }
    let readOutcome = page.value
    if readOutcome == nil { releaseFIFO(fifo) }
    await reading.value
    check(readOutcome == "incomplete",
          "FIFO: a read that reaches a segment swapped for a FIFO returns at once, marked incomplete (\(readOutcome ?? "blocked"))")

    let verified = await log.verify()
    let written = await log.record(roundThreeDecision(13))
    let kinds = Set(verified.findings.map(\.finding))
    check(verified.status == .discrepancy && verified.recorded && kinds.contains(.foreignFile)
          && written && !fixture.names().contains(segments[1]),
          "FIFO: the next verification records it as foreign, sets it aside, and the log carries on")
}
