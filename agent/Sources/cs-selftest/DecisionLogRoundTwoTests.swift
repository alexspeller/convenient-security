import ConvenientSecurity
import Foundation
#if canImport(Darwin)
import Darwin
#endif

// The second review of the decision log: planted set-aside files must never
// cost verified history, a foreign finding must survive until it is recorded,
// an entry csecd cannot move must never hold the log, and junk must never set
// authentic history aside. Hermetic, like the other log suites.

func decisionLogRoundTwoTests() async {
    print("\n# Decision log: planted set-aside files, deferred and stuck set-asides, junk")
    await plantedSetAsideTests()
    await deferredForeignTests()
    await unmovableEntryTests()
    await junkSegmentTests()
}

private final class RoundTwoNotices: @unchecked Sendable {
    private let lock = NSLock()
    private var received = 0
    func append() { lock.lock(); received += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return received }
}

private struct RoundTwoLog {
    let directory: String
    let backend = InMemoryProtectedItemBackend()
    let stores: ProtectedStores
    let limits: DecisionLogLimits
    let notices = RoundTwoNotices()

    init(_ name: String, limits: DecisionLogLimits = RoundTwoLog.smallLimits) {
        directory = NSTemporaryDirectory() + "cs-selftest-dlround2-\(name)-\(UUID().uuidString.lowercased())"
        stores = .processLocal(backend)
        self.limits = limits
    }

    static let smallLimits = DecisionLogLimits(
        segmentBytes: 1_200, decisionsCapBytes: 1 << 20, usageCapBytes: 1 << 20,
        usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
    )

    func open() async -> (DecisionLog, DecisionLogVerification) {
        let notices = self.notices
        let log = DecisionLog(
            directory: SealedRecordDirectory(path: directory), stores: stores, limits: limits,
            bootSessionUUID: "boot-round-two", onIntegrityEvent: { _ in notices.append() }
        )
        return (log, await log.open())
    }

    func names() -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []).sorted()
    }

    func live() -> [String] {
        names().filter { $0.hasPrefix("decisions-") && $0.hasSuffix(".clog") }
    }

    func path(_ name: String) -> String { (directory as NSString).appendingPathComponent(name) }

    func write(_ name: String, _ data: Data) {
        FileManager.default.createFile(atPath: path(name), contents: data, attributes: [.posixPermissions: 0o600])
    }

    func setImmutable(_ name: String?, _ on: Bool) {
        _ = chflags(name.map(path) ?? directory, on ? UInt32(UF_IMMUTABLE) : 0)
    }

    func remove() {
        for name in names() { setImmutable(name, false) }
        setImmutable(nil, false)
        try? FileManager.default.removeItem(atPath: directory)
    }
}

private func decision(_ index: Int) -> DecisionLogRecord {
    DecisionLogRecord(
        kind: .panel, surface: .secretAccess, refs: ["op://round-two/item-\(index)/password"],
        outcome: .approved, decider: .humanLocal, detail: "round two decision \(index)"
    )
}

private func details(_ log: DecisionLog, kinds: [DecisionLogRecord.Kind]) async -> [DecisionLogRecord] {
    var query = DecisionLogQuery(streams: [.decisions, .usage], kinds: kinds)
    var records: [DecisionLogRecord] = []
    for _ in 0..<1_000 {
        let page = await log.read(query)
        records += page.records
        guard let next = page.next, next != query.after else { break }
        query.after = next
    }
    return records
}

private func panelDetails(_ log: DecisionLog) async -> [String] {
    await details(log, kinds: [.panel]).compactMap(\.detail)
}

// MARK: - RH1: planted set-aside files never cost verified history

private func plantedSetAsideTests() async {
    // The reviewer's scenario: 1,200-byte segments, a 6,000-byte cap, and a
    // large sparse set-aside file that cannot be removed.
    let limits = DecisionLogLimits(
        segmentBytes: 1_200, decisionsCapBytes: 6_000, usageCapBytes: 6_000,
        usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: 64 * 1_024
    )
    do {
        let fixture = RoundTwoLog("setaside-stuck", limits: limits)
        defer { fixture.remove() }
        let planted = "decisions-00000042-0000000000000abc.clog.quarantined"
        let (log, _) = await fixture.open()
        for index in 1...9 { _ = await log.record(decision(index)) }
        let liveBefore = fixture.live()
        fixture.write(planted, Data())
        _ = truncate(fixture.path(planted), 1 << 20)
        fixture.setImmutable(planted, true)
        let (reopened, opened) = await fixture.open()
        _ = await reopened.record(decision(10))
        let liveAfter = fixture.live()
        let panels = await panelDetails(reopened)
        let status = await reopened.status()
        check(liveBefore.count >= 3 && opened.status == .clean && fixture.notices.count == 0,
              "RH1: a planted set-aside file is no finding")
        check(liveBefore.allSatisfy { liveAfter.contains($0) }
              && panels == (1...10).map { "round two decision \($0)" },
              "RH1: an unremovable planted set-aside file never costs a verified segment "
                  + "(\(liveBefore.count) → \(liveAfter.count) live)")
        check(fixture.names().contains(planted) && status.stuckFiles.contains(planted),
              "RH1: the unremovable file stays where it is and csec status names it")
        let (_, next) = await fixture.open()
        check(next.status == .clean && fixture.notices.count == 0, "RH1: the next start is clean")
    }
    // A removable planted set-aside file is trimmed on its own budget.
    do {
        let fixture = RoundTwoLog("setaside-removable", limits: limits)
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...6 { _ = await log.record(decision(index)) }
        let planted = "decisions-00000042-0000000000000abc.clog.quarantined"
        fixture.write(planted, Data(repeating: 0x41, count: 7_000))
        let liveBefore = fixture.live()
        let (reopened, _) = await fixture.open()
        _ = await reopened.record(decision(7))
        let prunes = await details(reopened, kinds: [.prune])
        let panels = await panelDetails(reopened)
        check(!fixture.names().contains(planted) && prunes.contains { $0.prune?.quarantinedFiles == 1 }
              && liveBefore.allSatisfy { fixture.live().contains($0) }
              && panels == (1...7).map { "round two decision \($0)" },
              "RH1: set-aside files are trimmed on their own budget, and no verified segment goes with them")
    }
}

// MARK: - RL1: a foreign finding is kept until it is recorded

private func deferredForeignTests() async {
    let fixture = RoundTwoLog("foreign-deferred")
    defer { fixture.remove() }
    let planted = "decisions-123-planted.clog"
    let (log, _) = await fixture.open()
    for index in 1...3 { _ = await log.record(decision(index)) }
    fixture.write(planted, Data("junk".utf8))
    // A file-size limit stands in for a full disk: no frame can be written,
    // while a rename (which writes no data) still could be.
    var limit = rlimit()
    getrlimit(RLIMIT_FSIZE, &limit)
    var tight = limit
    tight.rlim_cur = 64
    let previousHandler = signal(SIGXFSZ, SIG_IGN)
    setrlimit(RLIMIT_FSIZE, &tight)
    let (_, held) = await fixture.open()
    setrlimit(RLIMIT_FSIZE, &limit)
    signal(SIGXFSZ, previousHandler)
    check(!held.recorded && held.findings.map(\.finding) == [.foreignFile] && fixture.names().contains(planted),
          "RL1: a foreign file whose finding cannot be recorded is left where it was")
    let (reopened, again) = await fixture.open()
    let integrity = await details(reopened, kinds: [.logIntegrity])
    check(again.recorded && again.findings.map(\.finding) == [.foreignFile] && integrity.count == 1
          && !fixture.names().contains(planted),
          "RL1: once writable, the same foreign file is found again, recorded, and only then set aside")
}

// MARK: - RL2: an entry csecd cannot move never holds the log

private func unmovableEntryTests() async {
    // A name too long to extend with `.quarantined` is set aside under a
    // short generated name.
    do {
        let fixture = RoundTwoLog("long-name")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        _ = await log.record(decision(1))
        let longName = "decisions-" + String(repeating: "a", count: 240) + ".clog"
        fixture.write(longName, Data("junk".utf8))
        let (reopened, result) = await fixture.open()
        let recordedAfter = await reopened.record(decision(2))
        let (_, next) = await fixture.open()
        check(longName.utf8.count == 255 && result.recorded && result.findings.map(\.finding) == [.foreignFile]
              && !fixture.names().contains(longName) && recordedAfter && next.status == .clean,
              "RL2: a 255-byte foreign name is set aside under a short name and the log carries on")
    }
    // An immutable foreign file: recorded once, skipped afterwards, listed.
    do {
        let fixture = RoundTwoLog("immutable-foreign")
        defer { fixture.remove() }
        let stuck = "decisions-777-stuck.clog"
        let (log, _) = await fixture.open()
        _ = await log.record(decision(1))
        fixture.write(stuck, Data("junk".utf8))
        fixture.setImmutable(stuck, true)
        let (first, found) = await fixture.open()
        let written = await first.record(decision(2))
        let status = await first.status()
        let (second, secondResult) = await fixture.open()
        let secondStatus = await second.status()
        let integrity = await details(second, kinds: [.logIntegrity])
        let (_, third) = await fixture.open()
        check(found.recorded && found.findings.map(\.finding) == [.foreignFile] && written
              && status.stuckFiles.contains(stuck),
              "RL2: an immutable foreign file is recorded, the log carries on, and csec status names it")
        check(secondResult.status == .clean && third.status == .clean && fixture.notices.count == 1
              && integrity.count == 1 && secondStatus.stuckFiles.contains(stuck),
              "RL2: it is recorded once: later starts skip it quietly and keep naming it")
        fixture.setImmutable(stuck, false)
        let (_, freed) = await fixture.open()
        check(freed.status == .clean && !fixture.names().contains(stuck) && fixture.notices.count == 1,
              "RL2: once it can be moved, it is set aside with no second finding")
    }
}

// MARK: - RL3: junk never costs authentic history

private func junkSegmentTests() async {
    for (label, planted) in [
        ("number-zero", "decisions-00000000-0123456789abcdef.clog"),
        ("sorts-first", "decisions-00000001-0000000000000000.clog"),
        ("middle", "decisions-00000002-0000000000000000.clog"),
    ] {
        let fixture = RoundTwoLog("junk-\(label)")
        defer { fixture.remove() }
        let (log, _) = await fixture.open()
        for index in 1...9 { _ = await log.record(decision(index)) }
        let authentic = fixture.live()
        fixture.write(planted, Data("junk bytes that are not a frame".utf8))
        let (reopened, result) = await fixture.open()
        _ = await reopened.record(decision(10))
        let panels = await panelDetails(reopened)
        let (_, next) = await fixture.open()
        check(result.status == .discrepancy && result.recorded && result.findings.count == 1
              && [.foreignFile, .splicedSegment].contains(result.findings[0].finding),
              "RL3 \(label): one planted junk file is one finding (\(result.findings.map(\.finding.rawValue)))")
        check(authentic.count >= 3 && authentic.allSatisfy { fixture.live().contains($0) }
              && panels == (1...10).map { "round two decision \($0)" } && next.status == .clean,
              "RL3 \(label): no authentic segment is set aside and all history stays readable")
    }
}
