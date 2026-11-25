import ConvenientSecurity
import CryptoKit
import Darwin
import Foundation
import Security

// The sealed host-audit baseline (persistence §1.4, §2.3): migration once,
// the concurrent-save race, crash ordering, tamper, and uninstall. Hermetic:
// every fixture keeps its sealed directory, plaintext file and decision log in
// its own temporary directory over process-local protected items; nothing
// touches the installed csecd's baseline or the real Keychain.

private final class TamperNotices: @unchecked Sendable {
    private let lock = NSLock()
    private var received: [SealedBaselineNotice] = []
    func append(_ notice: SealedBaselineNotice) {
        lock.lock(); received.append(notice); lock.unlock()
    }
    var all: [SealedBaselineNotice] { lock.lock(); defer { lock.unlock() }; return received }
    /// The altered-baseline notices, in order.
    var altered: [SealedBaselineTamper] {
        all.compactMap { if case let .altered(tamper) = $0 { return tamper } else { return nil } }
    }
}

private func altered(
    _ finding: SealedBaselineFinding, recorded: Bool = true, treatedAsAbsent: Bool = true
) -> SealedBaselineNotice {
    .altered(SealedBaselineTamper(finding: finding, recorded: recorded, treatedAsAbsent: treatedAsAbsent))
}

/// The store tests write as an interactive audit, unless where a write comes
/// from is what they test.
extension BaselineStoring {
    @discardableResult
    func save(_ baseline: HostAuditBaseline) async -> Bool {
        await save(baseline, for: .audit)
    }

    @discardableResult
    func update(_ transform: @escaping @Sendable (HostAuditBaseline) -> HostAuditBaseline) async -> Bool {
        await update(for: .audit, transform)
    }
}

/// One csecd's baseline files and protected items. `start()` builds a fresh
/// decision log and store over them, which is how a csecd restart looks.
private struct BaselineFixture {
    let root: String
    let backend: InMemoryProtectedItemBackend
    let stores: ProtectedStores
    let notices = TamperNotices()

    /// `stores` replaces the process-local items, for a test that needs a
    /// substitute Keychain.
    init(_ name: String, stores: ProtectedStores? = nil) {
        root = NSTemporaryDirectory()
            + "cs-selftest-sealed-baseline-\(name)-\(UUID().uuidString.lowercased())"
        backend = InMemoryProtectedItemBackend()
        self.stores = stores ?? .processLocal(backend)
        try? FileManager.default.createDirectory(
            atPath: supportPath, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
    }

    /// Stands in for Application Support/ConvenientSecurity: the sealed
    /// directory and the plaintext file live here, the log beside it.
    var supportPath: String { (root as NSString).appendingPathComponent("Support") }
    var directoryPath: String { (supportPath as NSString).appendingPathComponent("HostAuditBaseline") }
    var plaintextPath: String { (supportPath as NSString).appendingPathComponent("host-audit-baseline.json") }
    var logPath: String { (root as NSString).appendingPathComponent("DecisionLog") }

    /// A log refuses every record when its records may be at most a few
    /// bytes, while its key (and so the baseline's) stays available.
    func start(recordable: Bool = true) async -> (SealedBaselineStore, DecisionLog) {
        let log = DecisionLog(
            directory: SealedRecordDirectory(path: logPath),
            stores: stores,
            limits: DecisionLogLimits(
                segmentBytes: 1 << 20, decisionsCapBytes: 1 << 22, usageCapBytes: 1 << 22,
                usageCheckpointDelay: .seconds(3_600), maximumRecordBytes: recordable ? 64 * 1_024 : 16
            ),
            bootSessionUUID: "00000000-0000-0000-0000-0000000ba5e1"
        )
        _ = await log.open()
        return (store(log: log), log)
    }

    func store(log: DecisionLog) -> SealedBaselineStore {
        let notices = self.notices
        return SealedBaselineStore(
            stores: stores,
            log: log,
            directory: SealedRecordDirectory(path: directoryPath),
            plaintextPath: plaintextPath,
            onNotice: { notices.append($0) }
        )
    }

    func pointer() async -> SealedBaselinePointer? {
        if case let .document(pointer) = await stores.store(for: SealedBaselinePointer.self).load() {
            return pointer
        }
        return nil
    }

    func setPointer(_ pointer: SealedBaselinePointer) async {
        _ = try? await stores.store(for: SealedBaselinePointer.self).prepare(pointer).commit()
    }

    func names() -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: directoryPath)) ?? []).sorted()
    }

    func path(_ name: String) -> String { (directoryPath as NSString).appendingPathComponent(name) }
    func bytes(_ name: String) -> Data { FileManager.default.contents(atPath: path(name)) ?? Data() }
    func write(_ name: String, _ data: Data) {
        FileManager.default.createFile(atPath: path(name), contents: data, attributes: [.posixPermissions: 0o600])
    }

    func writePlaintext(_ baseline: HostAuditBaseline) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted]
        FileManager.default.createFile(
            atPath: plaintextPath, contents: (try? encoder.encode(baseline)) ?? Data(),
            attributes: [.posixPermissions: 0o600]
        )
    }

    var plaintextExists: Bool {
        var info = stat()
        return lstat(plaintextPath, &info) == 0
    }

    func remove() {
        _ = chmod(supportPath, 0o700)
        for path in [directoryPath] + names().map(path) { _ = stripACL(path) }
        try? FileManager.default.removeItem(atPath: root)
    }
}

/// Adds an extended ACL entry the way a same-UID process would (`chmod +a`).
@discardableResult
private func addACL(_ entry: String, to path: String) -> Bool {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/chmod")
    process.arguments = ["+a", entry, path]
    do { try process.run() } catch { return false }
    process.waitUntilExit()
    return process.terminationStatus == 0
}

/// Whether `path` carries an extended ACL. Only "no ACL" reads as ENOENT;
/// an ACL that denies reading itself fails otherwise, and counts as present.
private func hasACL(_ path: String) -> Bool {
    guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else { return errno != ENOENT }
    acl_free(UnsafeMutableRawPointer(acl))
    return true
}

@discardableResult
private func stripACL(_ path: String) -> Bool {
    guard let empty = acl_init(0) else { return false }
    defer { acl_free(UnsafeMutableRawPointer(empty)) }
    return acl_set_link_np(path, ACL_TYPE_EXTENDED, empty) == 0
}

private func records(_ log: DecisionLog, _ kind: DecisionLogRecord.Kind) async -> [DecisionLogRecord] {
    await log.read(DecisionLogQuery(streams: [.decisions], kinds: [kind])).records
}

private func committedName(_ pointer: SealedBaselinePointer?) -> String {
    "baseline-\(pointer?.fileID ?? "none").sealed"
}

private func pendingName(_ pointer: SealedBaselinePointer?) -> String {
    "pending-\(pointer?.fileID ?? "none").sealed"
}

private func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func sampleBaseline(_ tag: String) -> HostAuditBaseline {
    HostAuditBaseline(
        entries: ["HA-A01": BaselineEntry(status: "pass", acceptedAtHint: "hint-\(tag)")],
        exemptions: ["HA-B08": TriageRecord(note: "synthetic accepted reason \(tag)")],
        todos: ["HA-C02": TriageRecord(recordedAtHint: "todo-\(tag)")]
    )
}

private func passingReport(_ ids: [String]) -> HostAuditReport {
    HostAuditReport(
        findings: ids.map {
            HostFinding(
                id: $0, title: "synthetic control", severity: .medium, tier: .runtimeReadable,
                status: .pass, onThesis: false, evidence: "", anchor: "", remediation: .advise
            )
        },
        verdict: "synthetic"
    )
}

func sealedBaselineTests() async {
    print("\n# sealed host-audit baseline")
    await sealedBaselineRoundTripTests()
    await sealedBaselineMigrationTests()
    await sealedBaselineLaterPlaintextTests()
    await sealedBaselineConcurrencyTests()
    await sealedBaselineCrashOrderingTests()
    await sealedBaselineTamperTests()
    await sealedBaselineUnrecordedTamperTests()
    await sealedBaselineUnavailableTests()
    await sealedBaselineUninstallTests()
    await sealedBaselineWiringTests()
    await sealedBaselineReviewTests()
    await sealedBaselineReviewRound2Tests()
    sealedBaselineNotificationTests()
}

// MARK: - Notification copy

/// The tamper notification says what happened: the altered baseline was
/// discarded for an empty one, so regressions go unreported until `csec
/// audit` re-accepts a baseline. It never suggests detection carries on.
private func sealedBaselineNotificationTests() {
    let recorded = SealedBaselineNotice.altered(SealedBaselineTamper(finding: .digestMismatch, recorded: true))
        .notification
    check(recorded.title == "Security baseline altered"
            && recorded.body == "csec's accepted host-audit baseline was changed outside csecd (its sealed file was "
                + "modified or rolled back); recorded, see `csec log --kind baseline_integrity`. csecd discarded it and "
                + "starts again from an empty baseline, so regressions are not reported again until you run "
                + "`csec audit` and re-accept.",
          "baseline notice: a recorded tamper says the baseline was reset and regressions wait for csec audit")
    let unrecorded = SealedBaselineNotice.altered(SealedBaselineTamper(finding: .fileMissing, recorded: false))
        .notification.body
    check(unrecorded.contains("could not be recorded yet") && unrecorded.contains("keeps the altered files as evidence")
            && unrecorded.contains("regressions are not reported until the finding is recorded and you run `csec audit`"),
          "baseline notice: an unrecorded tamper says the files are kept and regressions wait")
    let restored = SealedBaselineNotice.altered(SealedBaselineTamper(
        finding: .fileUnreadable, recorded: true, treatedAsAbsent: false)).notification.body
    check(restored.contains("csecd restored its access and the baseline verified unchanged")
            && restored.hasSuffix("Run `csec audit` to review.") && !restored.contains("regressions are not reported"),
          "baseline notice: a restored, verified baseline is not reported as reset")
    check(!recorded.body.contains("no exemption hides a regression") && !unrecorded.contains("treated as absent"),
          "baseline notice: no wording implies regressions are still being detected")
}

// MARK: - Round trip

private func sealedBaselineRoundTripTests() async {
    let fixture = BaselineFixture("round-trip")
    defer { fixture.remove() }
    let (store, log) = await fixture.start()

    let opened = await store.open()
    let first = await fixture.pointer()
    check(opened == .sealed(generation: 1) && first?.generation == 1
          && fixture.names() == [committedName(first)],
          "sealed baseline: a first start with no plaintext seals an empty baseline under generation 1")
    let emptyLoad = await store.load()
    let firstRecords = await records(log, .baselineMigration)
    check(emptyLoad == HostAuditBaseline() && firstRecords.isEmpty,
          "sealed baseline: with nothing to import it is empty and nothing is recorded")

    let sample = sampleBaseline("round-trip")
    let saved = await store.save(sample)
    let pointer = await fixture.pointer()
    let loaded = await store.load()
    let name = committedName(pointer)
    let sealed = fixture.bytes(name)
    check(saved && loaded == sample && pointer?.generation == 2 && fixture.names() == [name],
          "sealed baseline: a save round-trips and leaves exactly the current sealed file")
    check(pointer?.digest == sha256Hex(sealed),
          "sealed baseline: the pointer's digest is the sealed file's SHA-256")
    check(sealed.prefix(4) == Data("CSR1".utf8)
          && sealed.range(of: Data("synthetic accepted reason".utf8)) == nil
          && sealed.range(of: Data("exemptions".utf8)) == nil,
          "sealed baseline: the file is an AEAD record with no baseline text in it")
    var directoryInfo = stat(), fileInfo = stat()
    _ = lstat(fixture.directoryPath, &directoryInfo)
    _ = lstat(fixture.path(name), &fileInfo)
    check(directoryInfo.st_mode & 0o777 == 0o700 && fileInfo.st_mode & 0o777 == 0o600,
          "sealed baseline: the directory is 0700 and the file 0600")

    let (restarted, restartedLog) = await fixture.start()
    let afterRestart = await restarted.load()
    let integrity = await records(restartedLog, .baselineIntegrity)
    check(afterRestart == sample && fixture.notices.all.isEmpty && integrity.isEmpty,
          "sealed baseline: a restart loads the same baseline with no finding")

    let uppercase = SealedBaselinePointer(
        generation: 1, fileID: String(repeating: "A", count: 32), digest: String(repeating: "0", count: 64)
    )
    let zeroGeneration = SealedBaselinePointer(
        generation: 0, fileID: String(repeating: "a", count: 32), digest: String(repeating: "0", count: 64)
    )
    check(!uppercase.isWellFormed && !zeroGeneration.isWellFormed && pointer?.isWellFormed == true,
          "sealed baseline: a pointer is well formed only with lowercase hex IDs and a positive generation")
}

// MARK: - Migration

private func sealedBaselineMigrationTests() async {
    // Plaintext and no pointer: imported once, deleted, recorded once.
    do {
        let fixture = BaselineFixture("migrate")
        defer { fixture.remove() }
        let legacy = sampleBaseline("legacy")
        fixture.writePlaintext(legacy)
        let (store, log) = await fixture.start()
        let state = await store.open()
        let loaded = await store.load()
        let migrations = await records(log, .baselineMigration)
        check(state == .sealed(generation: 1) && loaded == legacy && !fixture.plaintextExists,
              "migrate: a plaintext baseline with no pointer is imported, and the plaintext deleted")
        check(migrations.count == 1
              && migrations.first?.detail?.contains("imported the plaintext host-audit baseline (1 accepted statuses, 1 exemptions, 1 deferred fixes)") == true
              && migrations.first?.detail?.contains("synthetic accepted reason") == false,
              "migrate: one value-free baseline_migration record (counts, never the notes)")
        check(fixture.notices.all.isEmpty, "migrate: a migration is not a finding and notifies nothing")

        let (restarted, restartedLog) = await fixture.start()
        let again = await restarted.load()
        let migrationsAfter = await records(restartedLog, .baselineMigration)
        let generation = await fixture.pointer()?.generation
        check(again == legacy && migrationsAfter.count == 1 && generation == 1,
              "migrate: a second start imports nothing and records nothing more")
    }

    // A plaintext file that is not a baseline, a symbolic link, or a FIFO is
    // never imported: the sealed baseline starts empty and the path is removed.
    for (label, plant) in [
        ("undecodable", { (fixture: BaselineFixture) in
            FileManager.default.createFile(atPath: fixture.plaintextPath, contents: Data("not json".utf8))
        }),
        ("symlink", { (fixture: BaselineFixture) in
            let target = (fixture.root as NSString).appendingPathComponent("elsewhere.json")
            fixture.writePlaintext(sampleBaseline("elsewhere"))
            _ = rename(fixture.plaintextPath, target)
            _ = symlink(target, fixture.plaintextPath)
        }),
        ("fifo", { (fixture: BaselineFixture) in
            _ = mkfifo(fixture.plaintextPath, 0o600)
        }),
    ] as [(String, (BaselineFixture) -> Void)] {
        let fixture = BaselineFixture("migrate-\(label)")
        defer { fixture.remove() }
        plant(fixture)
        let (store, log) = await fixture.start()
        let loaded = await store.load()
        let migrations = await records(log, .baselineMigration)
        let target = (fixture.root as NSString).appendingPathComponent("elsewhere.json")
        let targetIntact = label != "symlink"
            || (try? JSONDecoder().decode(
                HostAuditBaseline.self, from: FileManager.default.contents(atPath: target) ?? Data()
            )) == sampleBaseline("elsewhere")
        check(loaded == HostAuditBaseline() && !fixture.plaintextExists && targetIntact
              && migrations.count == 1 && migrations.first?.detail?.contains("did not import") == true,
              "migrate: a \(label) plaintext is not imported, is removed without following it, and is recorded")
    }

    // A failed pointer write during the import changes nothing: the plaintext
    // stays and is imported once the pointer can be written.
    do {
        let fixture = BaselineFixture("migrate-pointer-failure")
        defer { fixture.remove() }
        let legacy = sampleBaseline("retry")
        fixture.writePlaintext(legacy)
        await fixture.backend.inject(.failingWrites(errSecIO), for: .baselinePointer)
        let (store, log) = await fixture.start()
        let failed = await store.open()
        let loadedWhileFailing = await store.load()
        let pointerWhileFailing = await fixture.pointer()
        let migrationsWhileFailing = await records(log, .baselineMigration)
        var unavailable = false
        if case .unavailable = failed { unavailable = true }
        check(unavailable && loadedWhileFailing == HostAuditBaseline() && pointerWhileFailing == nil
              && fixture.plaintextExists && fixture.names().isEmpty && migrationsWhileFailing.isEmpty
              && fixture.notices.all.isEmpty,
              "migrate: a failed pointer write keeps the plaintext, leaves no sealed file, and is no finding")
        await fixture.backend.inject(.init(), for: .baselinePointer)
        let retried = await store.load()
        let migrations = await records(log, .baselineMigration)
        check(retried == legacy && !fixture.plaintextExists && migrations.count == 1,
              "migrate: once the pointer can be written the import happens, once")
    }
}

// MARK: - A plaintext file that appears later

private func sealedBaselineLaterPlaintextTests() async {
    let fixture = BaselineFixture("later-plaintext")
    defer { fixture.remove() }
    let (store, log) = await fixture.start()
    let sample = sampleBaseline("sealed")
    _ = await store.save(sample)

    var planted = sampleBaseline("planted")
    planted.exemptions["HA-Z99"] = TriageRecord(note: "planted exemption")
    fixture.writePlaintext(planted)
    let loaded = await store.load()
    let ignored = await records(log, .baselineIntegrity)
    check(loaded == sample && loaded.exemptions["HA-Z99"] == nil && !fixture.plaintextExists,
          "later plaintext: with a pointer present a plaintext baseline is never imported, and is deleted")
    check(ignored.count == 1 && ignored.first?.cause == "plaintext_ignored" && fixture.notices.all.isEmpty,
          "later plaintext: it is recorded once as baseline_integrity plaintext_ignored, without a notification")
    _ = await store.load()
    let ignoredAgain = await records(log, .baselineIntegrity)
    check(ignoredAgain.count == 1, "later plaintext: a later scan with no new plaintext records nothing")

    // One that cannot be deleted (a directory) is recorded once a run.
    try? FileManager.default.createDirectory(atPath: fixture.plaintextPath, withIntermediateDirectories: false)
    _ = await store.load()
    _ = await store.load()
    let unremovable = await records(log, .baselineIntegrity)
    let stillSealed = await store.load()
    check(unremovable.count == 2 && unremovable.last?.detail?.contains("could not be deleted") == true
          && stillSealed == sample,
          "later plaintext: one that cannot be deleted is recorded once, and the sealed baseline stays current")
}

// MARK: - Concurrency

private func sealedBaselineConcurrencyTests() async {
    // Two call paths (triage and the interactive baseline advance) update
    // concurrently: no update is lost.
    do {
        let fixture = BaselineFixture("race-updates")
        defer { fixture.remove() }
        let (store, _) = await fixture.start()
        await store.open()
        let count = 40
        await withTaskGroup(of: Void.self) { group in
            for index in 0..<count {
                group.addTask {
                    await HostAuditService.recordTriage(
                        HostTriageRequest(exemptions: [HostTriageDecision(id: "HA-E\(index)", note: "n\(index)")]),
                        recordedAtHint: "t\(index)", store: store
                    )
                }
                group.addTask {
                    await HostAuditService.recordBaseline(
                        passingReport(["HA-P\(index)"]), acceptedAtHint: "b\(index)", store: store
                    )
                }
            }
        }
        let final = await store.load()
        let pointer = await fixture.pointer()
        let name = committedName(pointer)
        check(final.exemptions.count == count && final.entries.count == count
              && (0..<count).allSatisfy { final.exemptions["HA-E\($0)"] != nil && final.entries["HA-P\($0)"] != nil },
              "race: \(count * 2) concurrent updates from two call paths lose none")
        check(pointer?.generation == UInt64(1 + count * 2) && fixture.names() == [name]
              && pointer?.digest == sha256Hex(fixture.bytes(name)),
              "race: every update is one generation, and the pointer and the only file agree")
        let (restarted, _) = await fixture.start()
        let reloaded = await restarted.load()
        check(reloaded == final && fixture.notices.all.isEmpty,
              "race: a restart reads the final baseline with no finding")
    }

    // Whole-baseline saves racing from two paths: the result is one of them.
    do {
        let fixture = BaselineFixture("race-saves")
        defer { fixture.remove() }
        let (store, _) = await fixture.start()
        let count = 30
        let left = (0..<count).map { sampleBaseline("left-\($0)") }
        let right = (0..<count).map { sampleBaseline("right-\($0)") }
        await withTaskGroup(of: Void.self) { group in
            for index in 0..<count {
                group.addTask { await store.save(left[index]) }
                group.addTask { await store.save(right[index]) }
                group.addTask { await HostAuditService.stampTodoReminders(["HA-C02"], atHint: "s\(index)", store: store) }
            }
        }
        let final = await store.load()
        var unstamped = final
        unstamped.todos["HA-C02"]?.lastRemindedAtHint = nil
        let pointer = await fixture.pointer()
        let name = committedName(pointer)
        check((left + right).contains(unstamped),
              "race: after concurrent saves the baseline is one of the saved values")
        check(fixture.names() == [name] && pointer?.digest == sha256Hex(fixture.bytes(name)),
              "race: the pointer names the only file left and its digest matches: no orphan, no dangling pointer")
    }
}

// MARK: - Crash ordering

private func sealedBaselineCrashOrderingTests() async {
    // Build A then B, keeping what a crash would have left behind.
    func twoGenerations(_ name: String) async -> (BaselineFixture, Data, SealedBaselinePointer?, String, Data, SealedBaselinePointer?) {
        let fixture = BaselineFixture(name)
        let (store, _) = await fixture.start()
        _ = await store.save(sampleBaseline("A"))
        let pointerA = await fixture.pointer()
        let pointerBytesA = await fixture.backend.rawBytes(for: .baselinePointer) ?? Data()
        let fileA = fixture.bytes(committedName(pointerA))
        _ = await store.save(sampleBaseline("B"))
        let pointerB = await fixture.pointer()
        return (fixture, pointerBytesA, pointerA, committedName(pointerA), fileA, pointerB)
    }

    // A crash after the new file was written, before the pointer bump: the
    // old baseline is current and the new file is an orphan.
    do {
        let (fixture, pointerBytesA, pointerA, nameA, fileA, pointerB) = await twoGenerations("crash-before-bump")
        defer { fixture.remove() }
        _ = rename(fixture.path(committedName(pointerB)), fixture.path(pendingName(pointerB)))
        fixture.write(nameA, fileA)
        fixture.write(".csec-write-leftover", Data("partial".utf8))
        await fixture.backend.setRawBytes(pointerBytesA, for: .baselinePointer)
        let (store, log) = await fixture.start()
        let loaded = await store.load()
        let integrity = await records(log, .baselineIntegrity)
        check(loaded == sampleBaseline("A") && fixture.names() == [nameA] && pointerA != nil
              && fixture.notices.all.isEmpty && integrity.isEmpty,
              "crash before the pointer bump: the old baseline loads, the orphan and temp file are removed, no finding")
    }

    // A crash after the pointer bump, before the rename and the old file's
    // deletion: the pending file the pointer names is verified and renamed.
    do {
        let (fixture, _, _, nameA, fileA, pointerB) = await twoGenerations("crash-after-bump")
        defer { fixture.remove() }
        _ = rename(fixture.path(committedName(pointerB)), fixture.path(pendingName(pointerB)))
        fixture.write(nameA, fileA)
        let (store, log) = await fixture.start()
        let loaded = await store.load()
        let integrity = await records(log, .baselineIntegrity)
        check(loaded == sampleBaseline("B") && fixture.names() == [committedName(pointerB)]
              && fixture.notices.all.isEmpty && integrity.isEmpty,
              "crash after the pointer bump: the new baseline loads, is renamed, the old file removed, no finding")
    }

    // A crash after the rename, before the old file's deletion.
    do {
        let (fixture, _, _, nameA, fileA, pointerB) = await twoGenerations("crash-before-delete")
        defer { fixture.remove() }
        fixture.write(nameA, fileA)
        let (store, _) = await fixture.start()
        let loaded = await store.load()
        check(loaded == sampleBaseline("B") && fixture.names() == [committedName(pointerB)]
              && fixture.notices.all.isEmpty,
              "crash before deleting the old file: the new baseline loads and the old file is removed")
    }

    // A pointer write that fails and leaves the previous pointer (the
    // fallback delete failed too): the save reports failure, the old baseline
    // stays current, and its file is still there because the old file is
    // deleted only after the bump.
    do {
        let fixture = BaselineFixture("failed-save")
        defer { fixture.remove() }
        let (store, log) = await fixture.start()
        _ = await store.save(sampleBaseline("A"))
        let pointerA = await fixture.pointer()
        await fixture.backend.inject(.failingWrites(errSecIO, delete: errSecIO), for: .baselinePointer)
        let saved = await store.save(sampleBaseline("B"))
        await fixture.backend.inject(.init(), for: .baselinePointer)
        let loaded = await store.load()
        let pointer = await fixture.pointer()
        let integrity = await records(log, .baselineIntegrity)
        check(!saved && loaded == sampleBaseline("A") && pointer == pointerA
              && fixture.names() == [committedName(pointerA)] && integrity.isEmpty
              && fixture.notices.all == [.notSaved(.audit, nil)],
              "failed save: the old baseline stays current and whole, the new file is removed, and the "
                + "save is reported as not saved, not as a finding")
    }

    // A pointer write that fails and deletes the item (the protected store's
    // write-or-delete): an absent pointer beside a committed file is a
    // finding, never a migration, even with a plaintext file waiting.
    do {
        let fixture = BaselineFixture("failed-save-pointer-deleted")
        defer { fixture.remove() }
        let (store, log) = await fixture.start()
        _ = await store.save(sampleBaseline("A"))
        await fixture.backend.inject(.failingWrites(errSecIO), for: .baselinePointer)
        let saved = await store.save(sampleBaseline("B"))
        let pointerGone = await fixture.pointer() == nil
        await fixture.backend.inject(.init(), for: .baselinePointer)
        fixture.writePlaintext(sampleBaseline("planted"))
        let loaded = await store.load()
        let integrity = await records(log, .baselineIntegrity)
        let migrations = await records(log, .baselineMigration)
        check(!saved && pointerGone && loaded == HostAuditBaseline()
              && fixture.notices.all == [.notSaved(.audit, nil), altered(.pointerMissing)]
              && integrity.contains { $0.cause == "pointer_missing" } && migrations.isEmpty
              && !fixture.plaintextExists,
              "failed save that deleted the pointer: pointer_missing, treated as absent, and the plaintext is not imported")
    }

    // A crash during the import, after the sealed file and before the
    // pointer: that is not a committed file, so the import simply runs again.
    do {
        let fixture = BaselineFixture("crash-migration")
        defer { fixture.remove() }
        let legacy = sampleBaseline("legacy-crash")
        fixture.writePlaintext(legacy)
        try? FileManager.default.createDirectory(
            atPath: fixture.directoryPath, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
        )
        fixture.write("pending-\(String(repeating: "c", count: 32)).sealed", Data("CSR1-leftover".utf8))
        let (store, log) = await fixture.start()
        let loaded = await store.load()
        let pointer = await fixture.pointer()
        let migrations = await records(log, .baselineMigration)
        check(loaded == legacy && fixture.names() == [committedName(pointer)] && migrations.count == 1
              && fixture.notices.all.isEmpty,
              "crash during the import: a pending file with no pointer is removed and the import completes")
    }
}

// MARK: - Tamper

private func sealedBaselineTamperTests() async {
    struct Case {
        let label: String
        let finding: SealedBaselineFinding
        let alter: (BaselineFixture, SealedBaselinePointer, [String: Data]) async -> Void
    }
    let cases: [Case] = [
        Case(label: "a flipped byte", finding: .digestMismatch) { fixture, pointer, _ in
            var bytes = fixture.bytes(committedName(pointer))
            bytes[bytes.count - 20] ^= 0x01
            fixture.write(committedName(pointer), bytes)
        },
        Case(label: "an older sealed file swapped in (rollback)", finding: .digestMismatch) { fixture, pointer, earlier in
            fixture.write(committedName(pointer), earlier["A"] ?? Data())
        },
        Case(label: "an older sealed file restored beside a deleted current one", finding: .fileMissing) { fixture, pointer, earlier in
            try? FileManager.default.removeItem(atPath: fixture.path(committedName(pointer)))
            fixture.write(earlier.keys.first { $0.hasPrefix("baseline-") } ?? "baseline-x.sealed", earlier["A"] ?? Data())
        },
        Case(label: "a deleted file", finding: .fileMissing) { fixture, pointer, _ in
            try? FileManager.default.removeItem(atPath: fixture.path(committedName(pointer)))
        },
        Case(label: "a deleted directory", finding: .fileMissing) { fixture, _, _ in
            try? FileManager.default.removeItem(atPath: fixture.directoryPath)
        },
        Case(label: "a file renamed to another ID", finding: .fileMissing) { fixture, pointer, _ in
            _ = rename(fixture.path(committedName(pointer)),
                       fixture.path("baseline-\(String(repeating: "d", count: 32)).sealed"))
        },
        Case(label: "a pointer whose generation does not match the file", finding: .authenticationFailed) { fixture, pointer, _ in
            await fixture.setPointer(SealedBaselinePointer(
                generation: pointer.generation + 1, fileID: pointer.fileID, digest: pointer.digest
            ))
        },
        Case(label: "a pointer whose file ID does not match the file", finding: .authenticationFailed) { fixture, pointer, _ in
            let otherID = String(repeating: "e", count: 32)
            _ = rename(fixture.path(committedName(pointer)), fixture.path("baseline-\(otherID).sealed"))
            await fixture.setPointer(SealedBaselinePointer(
                generation: pointer.generation, fileID: otherID, digest: pointer.digest
            ))
        },
        Case(label: "a missing pointer beside a sealed file", finding: .pointerMissing) { fixture, _, _ in
            await fixture.backend.setRawBytes(nil, for: .baselinePointer)
        },
        Case(label: "a symbolic link in place of the file", finding: .fileReplaced) { fixture, pointer, _ in
            let decoy = (fixture.root as NSString).appendingPathComponent("decoy.sealed")
            _ = rename(fixture.path(committedName(pointer)), decoy)
            _ = symlink(decoy, fixture.path(committedName(pointer)))
        },
        Case(label: "a symbolic link in place of the directory", finding: .fileReplaced) { fixture, _, _ in
            let moved = (fixture.root as NSString).appendingPathComponent("moved-directory")
            _ = rename(fixture.directoryPath, moved)
            _ = symlink(moved, fixture.directoryPath)
        },
    ]

    for testCase in cases {
        let fixture = BaselineFixture("tamper")
        defer { fixture.remove() }
        let (store, log) = await fixture.start()
        _ = await store.save(sampleBaseline("A"))
        let pointerA = await fixture.pointer()
        let earlier = [
            "A": fixture.bytes(committedName(pointerA)),
            committedName(pointerA): fixture.bytes(committedName(pointerA)),
        ]
        var exempted = sampleBaseline("B")
        exempted.exemptions["HA-G01"] = TriageRecord(note: "user exemption")
        _ = await store.save(exempted)
        guard let pointer = await fixture.pointer() else {
            check(false, "tamper \(testCase.label): no pointer after a save")
            continue
        }
        await testCase.alter(fixture, pointer, earlier)

        let loaded = await store.load()
        let notices = fixture.notices.all
        let integrity = await records(log, .baselineIntegrity)
        check(loaded == HostAuditBaseline(),
              "tamper \(testCase.label): the baseline is treated as absent (no exemption survives)")
        check(notices == [altered(testCase.finding)],
              "tamper \(testCase.label): one notification, \(testCase.finding.rawValue) (\(fixture.notices.altered.map(\.finding.rawValue)))")
        check(integrity.count == 1 && integrity.first?.cause == testCase.finding.rawValue,
              "tamper \(testCase.label): one baseline_integrity record naming the finding")

        let rescan = await store.load()
        let resealed = await fixture.pointer()
        let integrityAfter = await records(log, .baselineIntegrity)
        check(rescan == HostAuditBaseline() && fixture.notices.all.count == 1 && integrityAfter.count == 1
              && (resealed?.generation ?? 0) > 0 && resealed?.fileID != pointer.fileID
              && fixture.names() == [committedName(resealed)],
              "tamper \(testCase.label): resealed empty, so a second scan neither notifies nor records again")

        let (restarted, restartedLog) = await fixture.start()
        let afterRestart = await restarted.load()
        let restartIntegrity = await records(restartedLog, .baselineIntegrity)
        check(afterRestart == HostAuditBaseline() && fixture.notices.all.count == 1 && restartIntegrity.count == 1,
              "tamper \(testCase.label): the next start is clean")
    }

    // The symbolic-link directory case must not have written through the link.
    do {
        let fixture = BaselineFixture("tamper-directory-link")
        defer { fixture.remove() }
        let (store, _) = await fixture.start()
        _ = await store.save(sampleBaseline("A"))
        let moved = (fixture.root as NSString).appendingPathComponent("moved-directory")
        _ = rename(fixture.directoryPath, moved)
        _ = symlink(moved, fixture.directoryPath)
        let before = ((try? FileManager.default.contentsOfDirectory(atPath: moved)) ?? []).sorted()
        _ = await store.load()
        let after = ((try? FileManager.default.contentsOfDirectory(atPath: moved)) ?? []).sorted()
        var info = stat()
        _ = lstat(fixture.directoryPath, &info)
        check(before == after && (info.st_mode & S_IFMT) == S_IFDIR,
              "tamper: a linked-away directory is replaced by a real one, and nothing is written through the link")
    }
}

/// A finding the log cannot record is still reported once, the files are
/// left as they are, and the same state is not reported again on the next
/// scan; the next start (with a working log) records it and reseals.
private func sealedBaselineUnrecordedTamperTests() async {
    let fixture = BaselineFixture("tamper-unrecorded")
    defer { fixture.remove() }
    do {
        let (store, _) = await fixture.start()
        _ = await store.save(sampleBaseline("A"))
    }
    guard let pointer = await fixture.pointer() else {
        check(false, "unrecorded tamper: no pointer after a save")
        return
    }
    var bytes = fixture.bytes(committedName(pointer))
    bytes[bytes.count - 1] ^= 0x80
    fixture.write(committedName(pointer), bytes)

    let (store, log) = await fixture.start(recordable: false)
    let first = await store.load()
    let second = await store.load()
    let state = await store.state
    let stillPointer = await fixture.pointer()
    let integrity = await records(log, .baselineIntegrity)
    check(first == HostAuditBaseline() && second == HostAuditBaseline()
          && fixture.notices.all == [altered(.digestMismatch, recorded: false)]
          && state == .tampered(.digestMismatch) && stillPointer == pointer
          && fixture.bytes(committedName(pointer)) == bytes && integrity.isEmpty,
          "unrecorded tamper: absent, notified once, not re-notified by the next scan, and the evidence is left")

    // P5: the next `csec audit` or triage must not seal over the evidence
    // before the finding is recorded; the refusal is reported.
    let saved = await store.update { _ in sampleBaseline("after-audit") }
    let stamped = await store.save(sampleBaseline("another"))
    let pointerAfterSaves = await fixture.pointer()
    check(!saved && !stamped && pointerAfterSaves == pointer
          && fixture.names() == [committedName(pointer)] && fixture.bytes(committedName(pointer)) == bytes
          && fixture.notices.all == [
              altered(.digestMismatch, recorded: false), .notSaved(.audit, .digestMismatch), .notSaved(.audit, .digestMismatch),
          ],
          "unrecorded tamper: a save is refused while the finding is unrecorded, keeps the evidence, "
            + "and each refusal is reported")

    let (restarted, restartedLog) = await fixture.start()
    let afterRestart = await restarted.load()
    let recorded = await records(restartedLog, .baselineIntegrity)
    let resealed = await fixture.pointer()
    check(afterRestart == HostAuditBaseline() && recorded.count == 1
          && fixture.notices.all.count == 4 && fixture.notices.altered.last?.recorded == true
          && resealed?.fileID != pointer.fileID,
          "unrecorded tamper: the next start with a working log records it once and reseals")
    let savedAfter = await restarted.update { _ in sampleBaseline("after-audit") }
    let loadedAfter = await restarted.load()
    check(savedAfter && loadedAfter == sampleBaseline("after-audit") && fixture.notices.all.count == 4,
          "unrecorded tamper: once recorded, the next save is stored")
}

// MARK: - Unavailable

private func sealedBaselineUnavailableTests() async {
    // No log key: nothing is sealed, migrated or deleted.
    do {
        let fixture = BaselineFixture("unavailable-key")
        defer { fixture.remove() }
        fixture.writePlaintext(sampleBaseline("legacy"))
        await fixture.backend.inject(
            InMemoryProtectedItemBackend.Failures(read: errSecInteractionNotAllowed), for: .decisionLogKey
        )
        let (store, _) = await fixture.start()
        let state = await store.open()
        let loaded = await store.load()
        let saved = await store.save(sampleBaseline("new"))
        let pointerOperations = await fixture.backend.operations(on: .baselinePointer)
        var unavailable = false
        if case .unavailable = state { unavailable = true }
        check(unavailable && loaded == HostAuditBaseline() && !saved && fixture.plaintextExists
              && !FileManager.default.fileExists(atPath: fixture.directoryPath)
              && !pointerOperations.contains(.update) && !pointerOperations.contains(.add)
              && fixture.notices.all == [.notSaved(.audit, nil)],
              "unavailable: without the log's key nothing is read, sealed, imported or deleted; the refused "
                + "save is reported and nothing is a finding")
    }

    // A pointer this build cannot read (a newer format) is left alone.
    do {
        let fixture = BaselineFixture("unavailable-pointer")
        defer { fixture.remove() }
        let (store, _) = await fixture.start()
        _ = await store.save(sampleBaseline("A"))
        let names = fixture.names()
        let newer = Data("{\"document\":{},\"formatVersion\":99}".utf8)
        await fixture.backend.setRawBytes(newer, for: .baselinePointer)
        fixture.writePlaintext(sampleBaseline("planted"))
        let (restarted, _) = await fixture.start()
        let state = await restarted.open()
        let loaded = await restarted.load()
        let saved = await restarted.save(sampleBaseline("new"))
        let pointerBytes = await fixture.backend.rawBytes(for: .baselinePointer)
        var unavailable = false
        if case .unavailable = state { unavailable = true }
        check(unavailable && loaded == HostAuditBaseline() && !saved && pointerBytes == newer
              && fixture.names() == names && fixture.plaintextExists && fixture.notices.all == [.notSaved(.audit, nil)],
              "unavailable: a newer pointer is left for the build that wrote it; nothing is imported or "
                + "rewritten, and the refused save is reported")
    }
}

// MARK: - Uninstall

private actor BaselineUninstallConsent: ConsentProvider {
    private let approve: Bool
    init(approve: Bool) { self.approve = approve }
    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String,
        ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        approve ? .approved(unlock: nil) : .denied
    }
    func authenticate(reason: String) async -> ConsentOutcome {
        approve ? .approved(unlock: nil) : .denied
    }
}

private func sealedBaselineUninstallTests() async {
    // Refused: nothing is deleted.
    do {
        let fixture = BaselineFixture("uninstall-denied")
        defer { fixture.remove() }
        let (store, log) = await fixture.start()
        _ = await store.save(sampleBaseline("A"))
        let outcome = await CsecdUninstaller(
            consent: BaselineUninstallConsent(approve: false), stores: fixture.stores, log: log,
            logDirectory: SealedRecordDirectory(path: fixture.logPath),
            fileCleanups: [{ await store.eraseForUninstall() }]
        ).run(caller: setupCaller)
        let loaded = await store.load()
        check(outcome == .denied && loaded == sampleBaseline("A") && fixture.names().count == 1,
              "uninstall: a refused cleanup leaves the sealed baseline")
    }

    // Approved: the sealed file, its directory, a plaintext file and the
    // pointer are gone, and nothing is written again.
    do {
        let fixture = BaselineFixture("uninstall-approved")
        defer { fixture.remove() }
        let (store, log) = await fixture.start()
        _ = await store.save(sampleBaseline("A"))
        fixture.writePlaintext(sampleBaseline("leftover"))
        let outcome = await CsecdUninstaller(
            consent: BaselineUninstallConsent(approve: true), stores: fixture.stores, log: log,
            logDirectory: SealedRecordDirectory(path: fixture.logPath),
            fileCleanups: [{ await store.eraseForUninstall() }]
        ).run(caller: setupCaller)
        let pointerBytes = await fixture.backend.rawBytes(for: .baselinePointer)
        var complete = false
        if case let .completed(result) = outcome { complete = result.isComplete && result.remainingFiles.isEmpty }
        check(complete && pointerBytes == nil && !FileManager.default.fileExists(atPath: fixture.directoryPath)
              && !fixture.plaintextExists,
              "uninstall: the sealed directory, the plaintext file and the pointer are deleted")

        await fixture.backend.clearOperations()
        fixture.writePlaintext(sampleBaseline("after"))
        let saved = await store.save(sampleBaseline("B"))
        let updated = await store.update { _ in sampleBaseline("C") }
        await HostAuditService.stampTodoReminders(["HA-C02"], atHint: "later", store: store)
        let loaded = await store.load()
        let state = await store.state
        let operations = await fixture.backend.operations(on: .baselinePointer)
        check(!saved && !updated && loaded == HostAuditBaseline() && state == .uninstalled
              && operations.isEmpty && !FileManager.default.fileExists(atPath: fixture.directoryPath)
              && fixture.plaintextExists && fixture.notices.all.isEmpty,
              "uninstall: afterwards no save, update or load reads or writes anything, or imports a plaintext file")
    }

    // Saves racing the cleanup: the cleanup runs after every queued save,
    // and none lands behind it.
    do {
        let fixture = BaselineFixture("uninstall-race")
        defer { fixture.remove() }
        let (store, log) = await fixture.start()
        await store.open()
        let uninstaller = CsecdUninstaller(
            consent: BaselineUninstallConsent(approve: true), stores: fixture.stores, log: log,
            logDirectory: SealedRecordDirectory(path: fixture.logPath),
            fileCleanups: [{ await store.eraseForUninstall() }]
        )
        await withTaskGroup(of: Void.self) { group in
            for index in 0..<30 {
                group.addTask { await store.update { _ in sampleBaseline("race-\(index)") } }
            }
            group.addTask { _ = await uninstaller.run(caller: setupCaller) }
            for index in 30..<60 {
                group.addTask { await store.update { _ in sampleBaseline("race-\(index)") } }
            }
        }
        let pointerBytes = await fixture.backend.rawBytes(for: .baselinePointer)
        check(pointerBytes == nil && !FileManager.default.fileExists(atPath: fixture.directoryPath),
              "uninstall: saves racing the cleanup leave neither a sealed file nor a pointer")
    }

    // Without a store (no protected stores this run) the files still go.
    do {
        let fixture = BaselineFixture("uninstall-no-store")
        defer { fixture.remove() }
        let (store, _) = await fixture.start()
        _ = await store.save(sampleBaseline("A"))
        fixture.writePlaintext(sampleBaseline("leftover"))
        let remaining = SealedBaselineStore.eraseFiles(
            directory: SealedRecordDirectory(path: fixture.directoryPath), plaintextPath: fixture.plaintextPath
        )
        check(remaining == nil && !FileManager.default.fileExists(atPath: fixture.directoryPath)
              && !fixture.plaintextExists,
              "uninstall: eraseFiles removes the sealed directory and the plaintext file without a store")
    }
}

// MARK: - Wiring

private func sealedBaselineWiringTests() async {
    check(HostAuditService.baselineStore is InMemoryBaselineStore,
          "wiring: a process that installs no store keeps an in-memory baseline, never a plaintext file")
    let fixture = BaselineFixture("wiring")
    defer { fixture.remove() }
    let (store, _) = await fixture.start()
    let previous = HostAuditService.baselineStore
    HostAuditService.installBaselineStore(store)
    let context = HostAuditService.productionContext(scanFilesystem: false)
    let installed = HostAuditService.baselineStore
    check((context.baseline as? SealedBaselineStore) === store && (installed as? SealedBaselineStore) === store,
          "wiring: the production context and every HostAuditService path use the installed sealed store")
    await HostAuditService.recordTriage(HostTriageRequest(todos: ["HA-W01"]), recordedAtHint: "w")
    let viaDefault = await store.load()
    check(viaDefault.todos["HA-W01"] != nil,
          "wiring: a HostAuditService write with no explicit store lands in the installed store")
    HostAuditService.installBaselineStore(previous)
}

// MARK: - Review regressions (B2-review.md probes P1–P7)

private func failingReport(_ ids: [String]) -> HostAuditReport {
    HostAuditReport(
        findings: ids.map {
            HostFinding(
                id: $0, title: "synthetic control", severity: .medium, tier: .runtimeReadable,
                status: .fail, onThesis: false, evidence: "", anchor: "", remediation: .advise
            )
        },
        verdict: "synthetic"
    )
}

private final class Flag: @unchecked Sendable {
    private let lock = NSLock()
    private var raised = false
    private var text: String?
    func raise(_ detail: String = "") { lock.lock(); raised = true; text = detail; lock.unlock() }
    var isRaised: Bool { lock.lock(); defer { lock.unlock() }; return raised }
    var detail: String? { lock.lock(); defer { lock.unlock() }; return text }
}

/// A substitute Keychain that behaves like the real one (an update misses on
/// an absent item, an add creates it) and can fail the next writes of one
/// item, as a real Keychain write occasionally does.
private final class FlakyKeychain: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    private var failing: [String: Int] = [:]

    func failNextWrites(_ count: Int, of item: ProtectedItem) {
        lock.lock(); failing[item.description] = count; lock.unlock()
    }

    private static func key(_ query: [String: Any]) -> String {
        "\(query[kSecAttrService as String] as? String ?? "")/\(query[kSecAttrAccount as String] as? String ?? "")"
    }

    /// Consumes one planned failure; call with the lock held.
    private func failsNow(_ key: String) -> Bool {
        guard let remaining = failing[key], remaining > 0 else { return false }
        failing[key] = remaining - 1
        return true
    }

    var functions: ProtectedKeychainFunctions {
        ProtectedKeychainFunctions(
            copyMatching: { [self] query in
                lock.lock(); defer { lock.unlock() }
                return items[Self.key(query)].map { (errSecSuccess, $0) } ?? (errSecItemNotFound, nil)
            },
            update: { [self] query, attributes in
                lock.lock(); defer { lock.unlock() }
                let key = Self.key(query)
                if failsNow(key) { return errSecIO }
                guard items[key] != nil else { return errSecItemNotFound }
                items[key] = attributes[kSecValueData as String] as? Data
                return errSecSuccess
            },
            add: { [self] attributes in
                lock.lock(); defer { lock.unlock() }
                let key = Self.key(attributes)
                if failsNow(key) { return errSecIO }
                guard items[key] == nil else { return errSecDuplicateItem }
                items[key] = attributes[kSecValueData as String] as? Data
                return errSecSuccess
            },
            delete: { [self] query in
                lock.lock(); defer { lock.unlock() }
                return items.removeValue(forKey: Self.key(query)) == nil ? errSecItemNotFound : errSecSuccess
            }
        )
    }
}

/// Alternately renames a hard link of the real sealed file and a fresh FIFO
/// over the name the store reads, as the reviewer's race did.
private final class FifoFlipLoop: @unchecked Sendable {
    private let lock = NSLock()
    private var target: String
    private var real: String
    private var running = true
    let root: String

    init(root: String, target: String, real: String) {
        self.root = root
        self.target = target
        self.real = real
    }

    func retarget(_ path: String, real: String) { lock.lock(); target = path; self.real = real; lock.unlock() }
    func stop() { lock.lock(); running = false; lock.unlock() }

    func run() {
        let regular = (root as NSString).appendingPathComponent("flip.regular")
        let fifo = (root as NSString).appendingPathComponent("flip.fifo")
        while true {
            lock.lock(); let go = running; let path = target; let source = real; lock.unlock()
            if !go { return }
            _ = unlink(regular)
            if link(source, regular) == 0 { _ = rename(regular, path) }
            _ = unlink(fifo)
            if mkfifo(fifo, 0o600) == 0 { _ = rename(fifo, path) }
        }
    }
}

private func sealedBaselineReviewTests() async {
    let accepted = HostAuditBaseline(entries: ["HA-A01": BaselineEntry(status: "pass", acceptedAtHint: "h")])
    let failing = failingReport(["HA-A01"])

    // P1, P2: an ACL denying csecd its own file or directory survives B1's
    // mode repair. It is a finding, not "unavailable"; csecd strips the ACL
    // from its own object, and the authentic baseline goes on reporting the
    // regression the denial was meant to hide.
    for (label, onFile, entry) in [
        ("a deny-read ACL on the sealed file", true, "everyone deny read"),
        ("a deny-list ACL on the directory", false, "everyone deny list,search"),
    ] {
        let fixture = BaselineFixture("acl")
        defer { fixture.remove() }
        let (store, log) = await fixture.start()
        _ = await store.save(accepted)
        guard let pointer = await fixture.pointer() else {
            check(false, "access denied (\(label)): no pointer after a save")
            continue
        }
        let path = onFile ? fixture.path(committedName(pointer)) : fixture.directoryPath
        let applied = addACL(entry, to: path)
        let loaded = await store.load()
        let integrity = await records(log, .baselineIntegrity)
        check(applied && loaded == accepted
              && HostAuditService.baselineRegressions(report: failing, baseline: loaded).map(\.id) == ["HA-A01"],
              "access denied (\(label)): csecd restores its own access, and the authentic baseline still reports the regression")
        check(fixture.notices.all == [altered(.fileUnreadable, treatedAsAbsent: false)]
              && integrity.count == 1 && integrity.first?.cause == "file_unreadable" && !hasACL(path),
              "access denied (\(label)): one notification and one baseline_integrity record; the ACL is gone")
        _ = await store.load()
        let saved = await store.save(sampleBaseline("after"))
        let integrityAfter = await records(log, .baselineIntegrity)
        check(saved && fixture.notices.all.count == 1 && integrityAfter.count == 1,
              "access denied (\(label)): the next scan is silent and a save is stored")
        let (restarted, restartedLog) = await fixture.start()
        let afterRestart = await restarted.load()
        let restartIntegrity = await records(restartedLog, .baselineIntegrity)
        check(afterRestart == sampleBaseline("after") && fixture.notices.all.count == 1 && restartIntegrity.count == 1,
              "access denied (\(label)): the next start is clean")
    }

    // P3: a locked parent directory is not csecd's to repair. The baseline is
    // absent and the finding recorded and notified once a run; a save that
    // cannot be stored is reported every time; the authentic file, never
    // sealed over, verifies again once the parent is unlocked.
    do {
        let fixture = BaselineFixture("parent-locked")
        defer { fixture.remove() }
        let (store, log) = await fixture.start()
        _ = await store.save(accepted)
        let pointer = await fixture.pointer()
        _ = chmod(fixture.supportPath, 0)
        let loaded = await store.load()
        let rescan = await store.load()
        let state = await store.state
        let integrity = await records(log, .baselineIntegrity)
        check(loaded == HostAuditBaseline() && rescan == HostAuditBaseline() && state == .tampered(.fileUnreadable)
              && fixture.notices.all == [altered(.fileUnreadable)]
              && integrity.count == 1 && integrity.first?.cause == "file_unreadable",
              "access denied (a locked parent): absent, one notification, one record, and the next scan is silent")
        let saved = await store.update { _ in accepted }
        let savedAgain = await store.save(accepted)
        check(!saved && !savedAgain
              && fixture.notices.all == [altered(.fileUnreadable), .notSaved(.audit, .fileUnreadable), .notSaved(.audit, .fileUnreadable)],
              "access denied (a locked parent): every save that cannot be stored is reported, none is dropped silently")
        let (restarted, restartedLog) = await fixture.start()
        let afterRestart = await restarted.load()
        let restartState = await restarted.state
        let restartIntegrity = await records(restartedLog, .baselineIntegrity)
        check(afterRestart == HostAuditBaseline() && restartState == .tampered(.fileUnreadable)
              && fixture.notices.all.count == 4 && fixture.notices.all.last == altered(.fileUnreadable)
              && restartIntegrity.count == 2,
              "access denied (a locked parent): a restart with the parent still locked finds it again, once")
        _ = chmod(fixture.supportPath, 0o700)
        let (unlocked, _) = await fixture.start()
        let afterUnlock = await unlocked.load()
        let pointerAfter = await fixture.pointer()
        check(afterUnlock == accepted && pointerAfter == pointer && fixture.notices.all.count == 4,
              "access denied (a locked parent): once unlocked, the authentic baseline verifies again")
    }

    // A directory that refuses only writes (the baseline still reads and
    // verifies) has csecd's access restored by the save itself.
    do {
        let fixture = BaselineFixture("acl-write")
        defer { fixture.remove() }
        let (store, _) = await fixture.start()
        _ = await store.save(accepted)
        let applied = addACL("everyone deny add_file,delete_child", to: fixture.directoryPath)
        let saved = await store.save(sampleBaseline("B"))
        let loaded = await store.load()
        let pointer = await fixture.pointer()
        check(applied && saved && loaded == sampleBaseline("B") && !hasACL(fixture.directoryPath)
              && fixture.names() == [committedName(pointer)] && fixture.notices.all.isEmpty,
              "access denied (a write-only denial on the directory): the save restores csecd's access and is stored")
    }

    // P4: a crash after the import sealed generation 1 and before the
    // plaintext was deleted and the import recorded. Recovery finishes the
    // import and records it as one, not as a plaintext that appeared later.
    do {
        let fixture = BaselineFixture("migration-crash")
        defer { fixture.remove() }
        let legacy = sampleBaseline("legacy")
        fixture.writePlaintext(legacy)
        do {
            let (first, _) = await fixture.start(recordable: false)
            _ = await first.open()
        }
        fixture.writePlaintext(legacy)
        let (store, log) = await fixture.start()
        let loaded = await store.load()
        let migrations = await records(log, .baselineMigration)
        let integrity = await records(log, .baselineIntegrity)
        check(loaded == legacy && !fixture.plaintextExists && integrity.isEmpty && fixture.notices.all.isEmpty
              && migrations.count == 1 && migrations.first?.detail?.contains("completed the import") == true,
              "migration crash: recovery finishes the import and records baseline_migration, not plaintext_ignored")
    }
    do {
        let fixture = BaselineFixture("migration-crash-other")
        defer { fixture.remove() }
        fixture.writePlaintext(sampleBaseline("legacy"))
        let (store, log) = await fixture.start()
        _ = await store.open()
        fixture.writePlaintext(sampleBaseline("other"))
        let loaded = await store.load()
        let migrations = await records(log, .baselineMigration)
        let integrity = await records(log, .baselineIntegrity)
        check(loaded == sampleBaseline("legacy") && migrations.count == 1
              && integrity.map { $0.cause ?? "" } == ["plaintext_ignored"] && !fixture.plaintextExists,
              "migration crash: a different plaintext at generation 1 is not the import's leftover and is ignored")
    }

    // P6: csecd's own failed pointer write deletes the pointer; the previous
    // one goes straight back, so there is neither a false alarm nor a window
    // in which deleted sealed files and a planted plaintext would be imported.
    do {
        let keychain = FlakyKeychain()
        let fixture = BaselineFixture("pointer-restored", stores: .dataProtectionKeychain(calling: keychain.functions))
        defer { fixture.remove() }
        let (store, log) = await fixture.start()
        _ = await store.save(sampleBaseline("A"))
        let pointerA = await fixture.pointer()
        keychain.failNextWrites(1, of: .baselinePointer)
        let saved = await store.save(sampleBaseline("B"))
        let pointer = await fixture.pointer()
        let loaded = await store.load()
        let integrity = await records(log, .baselineIntegrity)
        check(!saved && pointerA != nil && pointer == pointerA && loaded == sampleBaseline("A")
              && fixture.names() == [committedName(pointerA)] && integrity.isEmpty
              && fixture.notices.all == [.notSaved(.audit, nil)],
              "pointer write failure: the previous pointer is restored at once; the save is reported, not a finding")
        for name in fixture.names() where name.hasPrefix("baseline-") {
            _ = rename(fixture.path(name), fixture.path("pending-" + name.dropFirst("baseline-".count)))
        }
        var planted = sampleBaseline("planted")
        planted.exemptions["HA-Z99"] = TriageRecord(note: "planted exemption")
        fixture.writePlaintext(planted)
        let attacked = await store.load()
        let migrations = await records(log, .baselineMigration)
        check(attacked == sampleBaseline("A") && attacked.exemptions["HA-Z99"] == nil && migrations.isEmpty
              && !fixture.plaintextExists && fixture.names() == [committedName(pointerA)],
              "pointer write failure: with the pointer back, renamed sealed files and a planted plaintext import nothing")
    }

    // P7a: a FIFO where a sealed file belongs never holds a reader: the open
    // is non-blocking and the type check refuses it.
    do {
        let fixture = BaselineFixture("fifo-read")
        defer { fixture.remove() }
        let directory = SealedRecordDirectory(path: fixture.directoryPath)
        try? directory.prepare()
        let fifo = fixture.path("planted.sealed")
        _ = mkfifo(fifo, 0o600)
        let outcome = Flag()
        let reader = Thread {
            do {
                _ = try SealedRecordDirectory(path: (fifo as NSString).deletingLastPathComponent)
                    .read("planted.sealed", maximumBytes: 1 << 20)
                outcome.raise("returned data")
            } catch {
                outcome.raise("\(error)")
            }
        }
        reader.start()
        var waited = 0
        while !outcome.isRaised, waited < 200 {
            try? await Task.sleep(nanoseconds: 10_000_000)
            waited += 1
        }
        let returned = outcome.isRaised
        if !returned {
            // Release a blocked reader so the rest of the run is unaffected.
            let fd = open(fifo, O_WRONLY | O_NONBLOCK)
            if fd >= 0 { close(fd) }
        }
        check(returned && outcome.detail == "\(SealedRecordError.notPrivate)",
              "FIFO: reading a FIFO planted as a sealed file returns at once, refused (\(outcome.detail ?? "blocked"))")
    }

    // P7b: loads racing a FIFO renamed over the sealed file after the listing
    // saw a regular file. Before the non-blocking open this hung the store,
    // the periodic scan and uninstall for the rest of csecd's life.
    do {
        let fixture = BaselineFixture("fifo-race")
        defer { fixture.remove() }
        let (store, _) = await fixture.start()
        _ = await store.save(accepted)
        guard let first = await fixture.pointer() else {
            check(false, "FIFO race: no pointer after a save")
            return
        }
        func keepReal(_ pointer: SealedBaselinePointer) -> String {
            let real = (fixture.root as NSString).appendingPathComponent("real-\(pointer.fileID)")
            _ = link(fixture.path(committedName(pointer)), real)
            return real
        }
        let loop = FifoFlipLoop(root: fixture.root, target: fixture.path(committedName(first)), real: keepReal(first))
        let flipper = Thread { loop.run() }
        flipper.start()
        var hung = false
        var attempts = 0
        for _ in 0..<80 {
            attempts += 1
            let before = fixture.notices.all.count
            let done = Flag()
            Task { _ = await store.load(); done.raise() }
            var waited = 0
            while !done.isRaised, waited < 300 {
                try? await Task.sleep(nanoseconds: 10_000_000)
                waited += 1
            }
            if !done.isRaised {
                hung = true
                break
            }
            if let current = await fixture.pointer(),
               current.fileID != first.fileID || fixture.notices.all.count != before {
                loop.retarget(fixture.path(committedName(current)), real: keepReal(current))
            }
        }
        loop.stop()
        try? await Task.sleep(nanoseconds: 50_000_000)
        check(!hung, "FIFO race: \(attempts) loads racing a FIFO swapped over the sealed file all return")
    }
}

// MARK: - Review regressions, round 2 (B2-review.md, "Re-review of 99c8453")

private func modeBits(_ path: String) -> mode_t? {
    var info = stat()
    return lstat(path, &info) == 0 ? info.st_mode & 0o777 : nil
}

private func sealedBaselineReviewRound2Tests() async {
    let accepted = HostAuditBaseline(entries: ["HA-A01": BaselineEntry(status: "pass", acceptedAtHint: "h")])
    let failing = failingReport(["HA-A01"])

    // N1 (P1b, P2b): an ACL that also denies reading csecd's own attributes
    // or ACL. csecd strips it without reading it first, identifies its own
    // object another way (the descriptor's attributes, or the directory's
    // attributes by path), and keeps the authentic baseline.
    for (label, onFile, entry) in [
        ("deny read,readsecurity on the sealed file", true, "everyone deny read,readsecurity"),
        ("deny list,search,readsecurity on the directory", false, "everyone deny list,search,readsecurity"),
    ] {
        let fixture = BaselineFixture("acl-hidden")
        defer { fixture.remove() }
        let (store, log) = await fixture.start()
        _ = await store.save(accepted)
        guard let pointer = await fixture.pointer() else {
            check(false, "access denied (\(label)): no pointer after a save")
            continue
        }
        let path = onFile ? fixture.path(committedName(pointer)) : fixture.directoryPath
        let applied = addACL(entry, to: path)
        let loaded = await store.load()
        let integrity = await records(log, .baselineIntegrity)
        check(applied && loaded == accepted
              && HostAuditService.baselineRegressions(report: failing, baseline: loaded).map(\.id) == ["HA-A01"]
              && fixture.notices.all == [altered(.fileUnreadable, treatedAsAbsent: false)]
              && integrity.map { $0.cause ?? "" } == ["file_unreadable"] && !hasACL(path),
              "access denied (\(label)): the ACL is stripped unread, the authentic baseline kept, one notice")
    }

    // N1: an ACL csecd cannot see past at all (it also denies the
    // attributes and writing) leaves the file unidentifiable, so csecd does
    // not touch it. It is reported as unreadable, never as missing; the
    // baseline is treated as absent and resealed, and the old name goes.
    do {
        let fixture = BaselineFixture("acl-opaque")
        defer { fixture.remove() }
        let (store, log) = await fixture.start()
        _ = await store.save(accepted)
        guard let pointer = await fixture.pointer() else {
            check(false, "access denied (opaque ACL): no pointer after a save")
            return
        }
        let applied = addACL(
            "everyone deny read,write,append,readattr,readextattr,readsecurity", to: fixture.path(committedName(pointer))
        )
        let loaded = await store.load()
        let integrity = await records(log, .baselineIntegrity)
        let resealed = await fixture.pointer()
        check(applied && loaded == HostAuditBaseline()
              && fixture.notices.all == [altered(.fileUnreadable)]
              && integrity.map { $0.cause ?? "" } == ["file_unreadable"]
              && resealed?.fileID != pointer.fileID && fixture.names() == [committedName(resealed)],
              "access denied (opaque ACL): unreadable, not missing; absent, resealed, and the old name removed")
    }

    // N2 (P8): a hard link to someone else's file planted under csecd's
    // pending name. The directory is repaired (it is csecd's own), the
    // linked file is not: its ACL and mode stay exactly as they were.
    do {
        let fixture = BaselineFixture("hardlink-pending")
        defer { fixture.remove() }
        let (store, _) = await fixture.start()
        _ = await store.save(accepted)
        guard let pointer = await fixture.pointer() else {
            check(false, "hard link (pending name): no pointer after a save")
            return
        }
        let victim = (fixture.root as NSString).appendingPathComponent("victim-user-file")
        FileManager.default.createFile(
            atPath: victim, contents: Data("user data".utf8), attributes: [.posixPermissions: 0o644]
        )
        let protected = addACL("everyone deny delete", to: victim)
        let linked = link(victim, fixture.path(pendingName(pointer))) == 0
        let denied = addACL("everyone deny list,search", to: fixture.directoryPath)
        let loaded = await store.load()
        check(protected && linked && denied && loaded == accepted
              && hasACL(victim) && modeBits(victim) == 0o644
              && FileManager.default.contents(atPath: victim) == Data("user data".utf8),
              "hard link (pending name): csecd repairs its directory but leaves a hard-linked file's ACL and mode alone")
        _ = stripACL(victim)
    }

    // N2 (P8b): the same under the committed name, with a deny-read ACL on
    // the linked file. csecd cannot read it and will not repair it: the
    // baseline is treated as absent and resealed, the victim is untouched,
    // and only csecd's name for it goes.
    do {
        let fixture = BaselineFixture("hardlink-committed")
        defer { fixture.remove() }
        let (store, _) = await fixture.start()
        _ = await store.save(accepted)
        guard let pointer = await fixture.pointer() else {
            check(false, "hard link (committed name): no pointer after a save")
            return
        }
        let victim = (fixture.root as NSString).appendingPathComponent("victim-user-file")
        FileManager.default.createFile(
            atPath: victim, contents: Data("user data".utf8), attributes: [.posixPermissions: 0o644]
        )
        let protected = addACL("everyone deny read", to: victim)
        _ = unlink(fixture.path(committedName(pointer)))
        let linked = link(victim, fixture.path(committedName(pointer))) == 0
        let loaded = await store.load()
        let victimACL = hasACL(victim)
        let victimMode = modeBits(victim)
        _ = stripACL(victim)
        check(protected && linked && loaded == HostAuditBaseline()
              && victimACL && victimMode == 0o644
              && FileManager.default.contents(atPath: victim) == Data("user data".utf8)
              && fixture.notices.all == [altered(.fileUnreadable)]
              && !fixture.names().contains(committedName(pointer)),
              "hard link (committed name): the linked file keeps its ACL, mode and content; only csecd's name goes")
    }

    // N2: the identity check on its own. csecd's single-link file passes; a
    // second link fails; a directory is identified without a link count.
    do {
        let fixture = BaselineFixture("identity")
        defer { fixture.remove() }
        let (store, _) = await fixture.start()
        _ = await store.save(accepted)
        let pointer = await fixture.pointer()
        let path = fixture.path(committedName(pointer))
        let single = SealedBaselineStore.identity(atPath: path, file: true)
        _ = link(path, (fixture.root as NSString).appendingPathComponent("second-link"))
        let double = SealedBaselineStore.identity(atPath: path, file: true)
        let directory = SealedBaselineStore.identity(atPath: fixture.directoryPath, file: false)
        check(single?.type == .regular && single?.links == 1 && single?.owner == getuid()
              && double?.links == 2 && directory?.type == .directory && directory?.owner == getuid(),
              "identity: a sealed file has one link, a hard-linked one two, and the directory reads as a directory")
        _ = addACL("everyone deny read,readsecurity", to: path)
        let hidden = SealedBaselineStore.identity(atPath: path, file: true)
        _ = stripACL(path)
        check(hidden?.type == .regular && hidden?.links == 2 && hidden?.owner == getuid(),
              "identity: with stat denied, the attributes still give type, owner and link count")
    }

    // N3: a change that does not take names itself. An audit and a triage
    // are reported every time; the daily reminder stamp once a run.
    do {
        let fixture = BaselineFixture("not-saved-origin")
        defer { fixture.remove() }
        let (store, _) = await fixture.start()
        _ = await store.save(HostAuditBaseline(todos: ["HA-C02": TriageRecord()]))
        await fixture.backend.inject(.failingWrites(errSecIO, delete: errSecIO), for: .baselinePointer)
        await HostAuditService.stampTodoReminders(["HA-C02"], atHint: "day-1", store: store)
        await HostAuditService.stampTodoReminders(["HA-C02"], atHint: "day-2", store: store)
        await HostAuditService.recordTriage(HostTriageRequest(todos: ["HA-C03"]), recordedAtHint: "t", store: store)
        await HostAuditService.recordBaseline(passingReport(["HA-A01"]), acceptedAtHint: "a", store: store)
        await HostAuditService.recordBaseline(passingReport(["HA-A01"]), acceptedAtHint: "b", store: store)
        check(fixture.notices.all == [
            .notSaved(.reminderStamp, nil), .notSaved(.triage, nil), .notSaved(.audit, nil), .notSaved(.audit, nil),
        ], "not saved: each notice names what failed; the reminder stamp once a run, an audit or triage every time")
        await fixture.backend.inject(.init(), for: .baselinePointer)
        await HostAuditService.stampTodoReminders(["HA-C02"], atHint: "day-3", store: store)
        await fixture.backend.inject(.failingWrites(errSecIO, delete: errSecIO), for: .baselinePointer)
        await HostAuditService.stampTodoReminders(["HA-C02"], atHint: "day-4", store: store)
        check(fixture.notices.all.last == .notSaved(.reminderStamp, nil) && fixture.notices.all.count == 5,
              "not saved: after a reminder stamp succeeds, the next failed one is reported again")
    }
}
