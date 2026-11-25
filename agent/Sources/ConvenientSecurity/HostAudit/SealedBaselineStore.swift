import CryptoKit
import Foundation
#if canImport(Darwin)
import Darwin
#endif

// The accepted host-audit baseline, sealed (persistence §1.4). The periodic
// re-audit notifies on a `pass → fail` regression of an accepted control unless
// the user exempted it. A same-UID process that could edit the baseline could
// add an exemption, or rewrite an entry, before disabling a control, and so
// silence the one notification that would have reported it. The baseline
// therefore lives in a file sealed with AES-GCM under a key derived from the
// decision log's (which only csecd can read), and a protected Keychain item
// names the one current file and the exact bytes it must hold.

/// The `baseline`/`pointer-v1` protected item: which sealed file holds the
/// accepted baseline, and exactly what its bytes are.
public struct SealedBaselinePointer: ProtectedDocument, Equatable {
    public static let protectedItem: ProtectedItem = .baselinePointer
    public static let formatVersion = 1

    /// Raised by every write, and bound into the sealed file's associated data.
    public var generation: UInt64
    /// Sixteen random bytes as lowercase hex. It names the file and is bound
    /// into its associated data, so a sealed file renamed to another ID does
    /// not open.
    public var fileID: String
    /// SHA-256 of the whole sealed file, lowercase hex. An older sealed file put
    /// back (a rollback) still authenticates under the key, but not against
    /// this digest.
    public var digest: String

    public init(generation: UInt64, fileID: String, digest: String) {
        self.generation = generation
        self.fileID = fileID
        self.digest = digest
    }

    public var isWellFormed: Bool {
        generation > 0
            && Self.isLowercaseHex(fileID, length: 32)
            && Self.isLowercaseHex(digest, length: 64)
    }

    static func isLowercaseHex(_ value: String, length: Int) -> Bool {
        value.utf8.count == length
            && value.utf8.allSatisfy { (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }
    }
}

/// Why the sealed baseline cannot be trusted. Only something outside csecd
/// produces these, except `pointerMissing`, which csecd's own failed pointer
/// write leaves behind when restoring the previous pointer fails as well (the
/// protected store deletes an item it could not write).
public enum SealedBaselineFinding: String, Codable, Sendable, CaseIterable {
    /// Sealed files exist but the pointer item does not.
    case pointerMissing = "pointer_missing"
    /// The pointer names a file, or a directory, that is not there.
    case fileMissing = "file_missing"
    /// Something other than csecd's own regular file (a symbolic link, a
    /// directory, an oversized file) is where the sealed file or its
    /// directory belongs.
    case fileReplaced = "file_replaced"
    /// The file's bytes are not the ones the pointer names: it was modified,
    /// or an older sealed file was put back.
    case digestMismatch = "digest_mismatch"
    /// The bytes are the ones the pointer names but do not authenticate under
    /// the key with the pointer's generation and file ID.
    case authenticationFailed = "authentication_failed"
    /// The sealed file or its directory exists but csecd cannot list or read
    /// it: an ACL, a mode or a parent directory denies csecd its own file.
    /// Unlike a missing name, nothing csecd wrote leaves this behind.
    case fileUnreadable = "file_unreadable"

    /// Value-free, for a log line and the notification.
    public var summary: String {
        switch self {
        case .pointerMissing: return "its Keychain pointer is missing"
        case .fileMissing: return "its sealed file is missing"
        case .fileReplaced: return "its sealed file was replaced"
        case .digestMismatch: return "its sealed file was modified or rolled back"
        case .authenticationFailed: return "its sealed file does not authenticate"
        case .fileUnreadable: return "its sealed file or directory was made unreadable"
        }
    }
}

/// One tamper finding, reported once per altered state.
public struct SealedBaselineTamper: Sendable, Equatable {
    public let finding: SealedBaselineFinding
    /// Whether the finding reached the decision log.
    public let recorded: Bool
    /// False only for a `fileUnreadable` finding where csecd restored its own
    /// access and the baseline then verified unchanged.
    public let treatedAsAbsent: Bool

    public init(finding: SealedBaselineFinding, recorded: Bool, treatedAsAbsent: Bool = true) {
        self.finding = finding
        self.recorded = recorded
        self.treatedAsAbsent = treatedAsAbsent
    }
}

/// What the store tells the user, through csecd's notification path.
public enum SealedBaselineNotice: Sendable, Equatable {
    /// Found altered, unreadable or without its pointer; once per state.
    case altered(SealedBaselineTamper)
    /// A change to the baseline was not stored: which one (an audit, a
    /// triage, the daily reminder stamp), with the live finding that blocked
    /// it, if any. An audit or triage that does not take is reported every
    /// time: the user just asked for it. The reminder stamp, which the daily
    /// scan retries, is reported once a run.
    case notSaved(BaselineChange, SealedBaselineFinding?)
}

public extension SealedBaselineNotice {
    /// The notification csecd posts for this notice, value-free. An altered
    /// baseline is discarded (sealed again empty once the finding is
    /// recorded), and regressions are compared against the accepted baseline
    /// only, so none is reported until `csec audit` re-accepts one: the words
    /// say that, rather than suggest detection carries on meanwhile.
    var notification: (title: String, body: String) {
        switch self {
        case let .altered(tamper):
            let altered = "csec's accepted host-audit baseline was changed outside csecd (\(tamper.finding.summary))"
            let recorded = "recorded, see `csec log --kind baseline_integrity`"
            guard tamper.treatedAsAbsent else {
                return ("Security baseline altered", altered
                    + ". csecd restored its access and the baseline verified unchanged"
                    + (tamper.recorded ? "; \(recorded)" : "") + ". Run `csec audit` to review.")
            }
            guard tamper.recorded else {
                return ("Security baseline altered", altered
                    + ". The finding could not be recorded yet, so csecd keeps the altered files as evidence and "
                    + "treats the baseline as empty: regressions are not reported until the finding is recorded "
                    + "and you run `csec audit` and re-accept.")
            }
            return ("Security baseline altered", altered + "; \(recorded). csecd discarded it and starts again "
                + "from an empty baseline, so regressions are not reported again until you run `csec audit` "
                + "and re-accept.")
        case let .notSaved(change, finding):
            let what: String
            switch change {
            case .audit: what = "Your latest `csec audit` was not saved to the accepted baseline"
            case .triage: what = "Your latest triage (exemptions and deferred fixes) was not saved to the accepted baseline"
            case .reminderStamp:
                what = "csec could not note today's deferred-fix reminder in the accepted baseline, "
                    + "so the reminder will come again"
            }
            return ("Security baseline not saved", what
                + (finding.map {
                    " because \($0.summary). Until it can be saved, regressions of accepted controls "
                        + "are not reported; see `csec log --kind baseline_integrity`."
                } ?? ". csecd.log says why; run `csec audit` if it keeps happening."))
        }
    }
}

public enum SealedBaselineState: Sendable, Equatable, CustomStringConvertible {
    case notOpened
    /// A verified sealed baseline of this generation is current.
    case sealed(generation: UInt64)
    /// A tamper finding this run that could not yet be resealed over: the
    /// baseline is treated as absent.
    case tampered(SealedBaselineFinding)
    /// The store cannot verify or seal this run (the log's key or the pointer
    /// is unreadable, or the directory failed); the baseline is treated as
    /// absent and nothing is written.
    case unavailable(String)
    /// `csec uninstall` began: nothing is read or written again.
    case uninstalled

    public var description: String {
        switch self {
        case .notOpened: return "not opened"
        case let .sealed(generation): return "sealed (generation \(generation))"
        case let .tampered(finding): return "altered outside csecd (\(finding.rawValue)); treated as absent"
        case let .unavailable(reason): return "unavailable (\(reason))"
        case .uninstalled: return "uninstalled"
        }
    }
}

/// csecd's accepted host-audit baseline: the JSON sealed with AES-GCM under a
/// key the decision log derives for this purpose alone, in a private
/// directory, with the `baseline`/`pointer-v1` protected item naming the
/// current file's generation, ID and digest.
///
/// - **Serialized.** Every operation runs to completion before the next one
///   starts, suspension points included, so an interactive `csec audit`, a
///   triage and the periodic scan's reminder stamp never lose one another's
///   update or leave a pointer to a deleted file. `update` reads, transforms
///   and writes as one step.
/// - **Crash-safe writes.** A write seals a new file under a pending name,
///   bumps the pointer, renames the file to its committed name, then deletes
///   the old one. A crash before the bump leaves the old baseline current and
///   an orphan the next load deletes; a crash after it leaves a pending file
///   the pointer names, which the next load verifies and renames.
/// - **Migration, once.** The plaintext file an older csecd kept is imported
///   only when the pointer is absent and no committed sealed file exists,
///   then deleted and recorded. An absent pointer beside a committed sealed
///   file is a finding, never a migration, because a failed pointer write
///   deletes the pointer. A plaintext file that appears while the sealed
///   baseline exists is never imported: it is deleted and recorded.
/// - **Tamper.** A missing, replaced or unreadable file, a digest mismatch
///   (modification or rollback) or an authentication failure is recorded as
///   `baseline_integrity`, reported once per state, and the baseline is
///   treated as absent, so no altered exemption can hide a regression. An
///   unreadable file is a finding, never "unavailable": a denial (an ACL, a
///   mode, a locked parent) is how a same-UID process would otherwise silence
///   the baseline. csecd first restores its own access (it strips an ACL from
///   its directory and file); a baseline that then verifies is kept, and the
///   denial is still reported. Once a finding is recorded an empty baseline
///   is sealed under a fresh pointer, so the next scan and the next start are
///   clean. Until then the files are evidence: no save seals over them, and
///   every refused save is reported.
/// - **Uninstall.** After the protected stores enter their uninstalled state
///   nothing is read, sealed, migrated or deleted, except by
///   `eraseForUninstall`, which removes the directory and any plaintext file.
public actor SealedBaselineStore: BaselineStoring {
    /// The purpose the decision log derives this store's key for.
    public static let keyPurpose = "host-audit-baseline"
    static let sealingDomain = "host-audit-baseline-v1"
    /// The largest sealed file read or written. A real baseline is a few KiB.
    public static let maximumSealedBytes = 4 * 1_024 * 1_024
    static let plaintextIgnoredCause = "plaintext_ignored"

    public static func defaultDirectoryPath() -> String {
        applicationSupportPath().appendingPathComponent("HostAuditBaseline", isDirectory: true).path
    }

    /// Where csecd kept the plaintext baseline before it was sealed.
    public static func defaultPlaintextPath() -> String {
        applicationSupportPath().appendingPathComponent("host-audit-baseline.json").path
    }

    private static func applicationSupportPath() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library", isDirectory: true)
            .appendingPathComponent("Application Support", isDirectory: true)
            .appendingPathComponent("ConvenientSecurity", isDirectory: true)
    }

    /// The baseline as the store found it, with the key it found it under.
    private enum Current {
        case verified(HostAuditBaseline, SealedBaselinePointer, SymmetricKey)
        /// Treated as absent after a finding. `pointer` is the one in place,
        /// if any, so the next write follows its generation.
        case absent(SealedBaselinePointer?, SymmetricKey)
        case unavailable
    }

    private struct Listing {
        var regular: Set<String> = []
        var foreign: Set<String> = []
        var names: [String] { (regular.union(foreign)).sorted() }
    }

    private enum ListingResult {
        case missing
        case notDirectory
        case failed(String)
        case listed(Listing)
    }

    /// What reading the file the pointer names found, without changing
    /// anything.
    private enum Inspection {
        case verified(HostAuditBaseline, name: String, listing: Listing)
        case finding(SealedBaselineFinding, evidence: String)
        case unavailable(String)
    }

    private struct ReportedTamper {
        let fingerprint: String
        var recorded: Bool
    }

    private let stores: ProtectedStores
    private let pointerStore: ProtectedStore<SealedBaselinePointer>
    private let log: DecisionLog
    private let directory: SealedRecordDirectory
    private let plaintextPath: String
    private let onNotice: @Sendable (SealedBaselineNotice) -> Void

    private var tail: Task<Void, Never>?
    public private(set) var state = SealedBaselineState.notOpened
    /// The tamper state last reported. The same state found again (the
    /// periodic scan, the next audit) is neither notified nor, once recorded,
    /// recorded again.
    private var reportedTamper: ReportedTamper?
    /// A plaintext file that could not be deleted is recorded once a run.
    private var unremovablePlaintextRecorded = false
    /// A reminder stamp that did not take is reported once a run.
    private var reminderStampFailureReported = false
    private var lastUnavailableReason: String?

    public init(
        stores: ProtectedStores,
        log: DecisionLog,
        directory: SealedRecordDirectory = SealedRecordDirectory(path: SealedBaselineStore.defaultDirectoryPath()),
        plaintextPath: String = SealedBaselineStore.defaultPlaintextPath(),
        onNotice: @escaping @Sendable (SealedBaselineNotice) -> Void = { _ in }
    ) {
        self.stores = stores
        self.pointerStore = stores.store(for: SealedBaselinePointer.self)
        self.log = log
        self.directory = directory
        self.plaintextPath = plaintextPath
        self.onNotice = onNotice
    }

    // MARK: - Operations

    /// Verifies (or migrates to) the sealed baseline at startup, so a finding
    /// is reported and the plaintext file removed before anything is served.
    @discardableResult
    public func open() async -> SealedBaselineState {
        await serialized { store in await store.resolvedState() }
    }

    /// The verified baseline, or an empty one when it is absent, altered or
    /// unavailable.
    public func load() async -> HostAuditBaseline {
        await serialized { store in await store.currentBaseline() }
    }

    @discardableResult
    public func save(_ baseline: HostAuditBaseline, for change: BaselineChange) async -> Bool {
        await serialized { store in await store.write(change) { _ in baseline } }
    }

    @discardableResult
    public func update(
        for change: BaselineChange,
        _ transform: @escaping @Sendable (HostAuditBaseline) -> HostAuditBaseline
    ) async -> Bool {
        await serialized { store in await store.write(change, transform) }
    }

    /// `csec uninstall`: deletes the sealed directory and any plaintext file,
    /// after every operation already queued. Call it once the protected
    /// stores are in their uninstalled state, which refuses every later
    /// write. The pointer item goes with the other protected items. Returns a
    /// value-free description of what remains, or nil.
    public func eraseForUninstall() async -> String? {
        await serialized { store in await store.erase() }
    }

    /// Runs `operation` after every operation started before it has finished.
    /// Actor isolation alone would let a second operation run while the first
    /// awaits the Keychain, and interleave a read-modify-write. An operation
    /// calls the private steps, never a public entry point: that would wait
    /// behind itself.
    private func serialized<T: Sendable>(
        _ operation: @escaping @Sendable (SealedBaselineStore) async -> T
    ) async -> T {
        let previous = tail
        let task = Task { () async -> T in
            await previous?.value
            return await operation(self)
        }
        tail = Task { _ = await task.value }
        return await task.value
    }

    private func resolvedState() async -> SealedBaselineState {
        _ = await resolve()
        return state
    }

    private func currentBaseline() async -> HostAuditBaseline {
        if case let .verified(baseline, _, _) = await resolve() { return baseline }
        return HostAuditBaseline()
    }

    private func write(
        _ change: BaselineChange,
        _ transform: @Sendable (HostAuditBaseline) -> HostAuditBaseline
    ) async -> Bool {
        let base: HostAuditBaseline
        let previous: SealedBaselinePointer?
        let key: SymmetricKey
        switch await resolve() {
        case let .verified(baseline, pointer, sealingKey):
            (base, previous, key) = (baseline, pointer, sealingKey)
        case let .absent(pointer, sealingKey):
            // Sealing over an altered baseline whose finding the log could
            // not record yet would delete the only evidence of it.
            guard reportedTamper?.recorded == true else { return notSaved(change) }
            (base, previous, key) = (HostAuditBaseline(), pointer, sealingKey)
        case .unavailable:
            return notSaved(change)
        }
        guard let pointer = await seal(transform(base), key: key, after: previous) else { return notSaved(change) }
        state = .sealed(generation: pointer.generation)
        if change == .reminderStamp { reminderStampFailureReported = false }
        return true
    }

    /// Reports a change that did not take, naming it. Nothing is reported
    /// once uninstall began: refusing then is the point.
    private func notSaved(_ change: BaselineChange) -> Bool {
        guard state != .uninstalled, !stores.isUninstalled else { return false }
        FileHandle.standardError.write(Data(
            "csecd: host-audit baseline \(change.rawValue) not saved (\(state)).\n".utf8
        ))
        if change == .reminderStamp {
            guard !reminderStampFailureReported else { return false }
            reminderStampFailureReported = true
        }
        let finding: SealedBaselineFinding?
        if case let .tampered(live) = state { finding = live } else { finding = nil }
        onNotice(.notSaved(change, finding))
        return false
    }

    private func erase() -> String? {
        state = .uninstalled
        return Self.eraseFiles(directory: directory, plaintextPath: plaintextPath)
    }

    // MARK: - Reading and verification

    private func resolve() async -> Current {
        guard !stores.isUninstalled else {
            state = .uninstalled
            return .unavailable
        }
        guard let key = await log.sealingKey(purpose: Self.keyPurpose) else {
            return becomeUnavailable("the decision log's key is unavailable")
        }
        switch await pointerStore.load() {
        case let .unreadable(reason):
            // A newer csecd's pointer, or a Keychain read error: leave the
            // item and the files for a build that can read them.
            return becomeUnavailable("the baseline pointer is unreadable: \(reason)")
        case .absent:
            return await resolveWithoutPointer(key: key)
        case let .document(pointer):
            return await resolve(pointer: pointer, key: key)
        }
    }

    private func resolve(pointer: SealedBaselinePointer, key: SymmetricKey) async -> Current {
        var inspection = inspect(pointer: pointer, key: key)
        if case let .finding(.fileUnreadable, evidence) = inspection {
            // Something denied csecd its own directory or file. csecd restores
            // its access and looks once more: a baseline that then verifies is
            // authentic and is kept, and the denial is still reported.
            if restoreOwnAccess(fileID: pointer.fileID) {
                inspection = inspect(pointer: pointer, key: key)
            }
            if case .verified = inspection {
                _ = await report(.fileUnreadable, pointer: pointer, evidence: evidence, treatedAsAbsent: false)
            }
        }
        switch inspection {
        case let .verified(baseline, name, listing):
            var keep = name
            if name == Self.pendingName(pointer.fileID),
               (try? directory.rename(name, to: Self.fileName(pointer.fileID))) != nil {
                keep = Self.fileName(pointer.fileID)
            }
            removeEntries(of: listing, except: keep)
            state = .sealed(generation: pointer.generation)
            await settlePlaintext(sealed: (pointer, baseline))
            return .verified(baseline, pointer, key)
        case let .finding(finding, evidence):
            return await tampered(finding, pointer: pointer, key: key, evidence: evidence)
        case let .unavailable(reason):
            return becomeUnavailable(reason)
        }
    }

    /// Lists the directory and reads, checks and opens the file the pointer
    /// names, changing nothing. With a pointer in place every failure but a
    /// missing name is a finding; only an authenticated file that does not
    /// decode (a format this build cannot read) is left alone as unavailable.
    private func inspect(pointer: SealedBaselinePointer, key: SymmetricKey) -> Inspection {
        let listing: Listing
        switch list() {
        case .missing:
            return .finding(.fileMissing, evidence: "no directory")
        case .notDirectory:
            return .finding(.fileReplaced, evidence: "not a directory")
        case let .failed(reason):
            return .finding(.fileUnreadable, evidence: reason)
        case let .listed(found):
            listing = found
        }
        let committed = Self.fileName(pointer.fileID)
        let pending = Self.pendingName(pointer.fileID)
        let evidence = listing.names.joined(separator: ",")
        let name: String
        if listing.regular.contains(committed) {
            name = committed
        } else if listing.foreign.contains(committed) {
            return .finding(.fileReplaced, evidence: evidence)
        } else if listing.regular.contains(pending) {
            // A crash between the pointer bump and the rename.
            name = pending
        } else if [committed, pending].contains(where: exists(butCannotExamine:)) {
            // The listing leaves out a name it cannot examine: an ACL denying
            // csecd its attributes hides the file, it does not remove it.
            return .finding(.fileUnreadable, evidence: evidence)
        } else {
            return .finding(.fileMissing, evidence: evidence)
        }

        let sealed: Data
        do {
            // The open is non-blocking, so a FIFO swapped in after the listing
            // fails the type check instead of holding the store.
            guard let data = try directory.read(name, maximumBytes: Self.maximumSealedBytes) else {
                return .finding(.fileMissing, evidence: evidence)
            }
            sealed = data
        } catch SealedRecordError.tooLarge, SealedRecordError.notPrivate, SealedRecordError.system(ELOOP) {
            return .finding(.fileReplaced, evidence: evidence)
        } catch SealedRecordError.system(ENOENT) {
            return .finding(.fileMissing, evidence: evidence)
        } catch {
            return .finding(.fileUnreadable, evidence: "\(evidence)|\(error)")
        }
        let digest = Self.digest(sealed)
        guard digest == pointer.digest else {
            return .finding(.digestMismatch, evidence: "\(evidence)|\(digest)")
        }
        guard let plaintext = try? SealedRecordFile.open(
            sealed, key: key, domain: Self.sealingDomain,
            associatedData: Self.associatedData(generation: pointer.generation, fileID: pointer.fileID)
        ) else {
            return .finding(.authenticationFailed, evidence: evidence)
        }
        guard let baseline = try? JSONDecoder().decode(HostAuditBaseline.self, from: plaintext) else {
            // It authenticates, so csecd sealed it: a format this build
            // cannot read, never tampering. Leave it for the build that can.
            return .unavailable("the sealed baseline does not decode")
        }
        return .verified(baseline, name: name, listing: listing)
    }

    /// No pointer. A committed sealed file beside it is a finding: the
    /// pointer is gone, not never written. Otherwise this is the first start
    /// of a csecd that seals the baseline, and the plaintext is imported.
    private func resolveWithoutPointer(key: SymmetricKey) async -> Current {
        switch list() {
        case .missing:
            break
        case .notDirectory:
            return await tampered(.fileReplaced, pointer: nil, key: key, evidence: "not a directory")
        case let .failed(reason):
            // Nothing is anchored yet (the decision log treats its own
            // unanchored directory the same way). Whether a committed file
            // hides there cannot be told, so nothing is imported, and the
            // import is retried.
            return becomeUnavailable("the baseline directory could not be listed: \(reason)")
        case let .listed(listing):
            let committed = listing.names.filter { Self.committedFileID($0) != nil }
            if !committed.isEmpty {
                return await tampered(
                    .pointerMissing, pointer: nil, key: key, evidence: committed.joined(separator: ",")
                )
            }
            // Pending and temporary files of a migration that never
            // committed its pointer.
            removeEntries(of: listing, except: nil)
        }
        return await migrate(key: key)
    }

    private func migrate(key: SymmetricKey) async -> Current {
        let legacy = Self.readPlaintext(at: plaintextPath)
        let imported: HostAuditBaseline
        let detail: String?
        switch legacy {
        case .absent:
            imported = HostAuditBaseline()
            detail = nil
        case let .baseline(baseline):
            imported = baseline
            detail = "imported the plaintext host-audit baseline (\(baseline.entries.count) accepted "
                + "statuses, \(baseline.exemptions.count) exemptions, \(baseline.todos.count) deferred fixes) "
                + "into the sealed baseline"
        case let .notImportable(reason):
            imported = HostAuditBaseline()
            detail = "did not import the plaintext host-audit baseline (\(reason)); the sealed baseline starts empty"
        case let .unreadable(code):
            return becomeUnavailable("the plaintext baseline could not be read (errno \(code)); import retried later")
        }
        guard let pointer = await seal(imported, key: key, after: nil) else {
            return state == .uninstalled ? .unavailable : becomeUnavailable("the baseline could not be sealed")
        }
        state = .sealed(generation: pointer.generation)
        if let detail {
            let removed = Self.removePlaintext(at: plaintextPath)
            await log.record(DecisionLogRecord(
                kind: .baselineMigration,
                detail: detail + (removed ? "; deleted the plaintext file" : "; the plaintext file could not be deleted")
            ))
            FileHandle.standardError.write(Data("csecd: host-audit baseline sealed; \(detail).\n".utf8))
        }
        return .verified(imported, pointer, key)
    }

    /// Records and reports a finding once per state, and treats the baseline
    /// as absent. Once the finding is durably recorded, an empty baseline is
    /// sealed under a fresh pointer: the altered state is gone, so it is not
    /// found again. A finding that could not be recorded leaves the files as
    /// they are (no save seals over them), and the next start finds it again.
    private func tampered(
        _ finding: SealedBaselineFinding,
        pointer: SealedBaselinePointer?,
        key: SymmetricKey,
        evidence: String
    ) async -> Current {
        let recorded = await report(finding, pointer: pointer, evidence: evidence, treatedAsAbsent: true)
        state = .tampered(finding)
        guard recorded, let fresh = await seal(HostAuditBaseline(), key: key, after: pointer) else {
            return .absent(pointer, key)
        }
        state = .sealed(generation: fresh.generation)
        await settlePlaintext(sealed: nil)
        return .verified(HostAuditBaseline(), fresh, key)
    }

    /// Records a finding (retrying until the log takes it) and notifies it
    /// once per state: the same state found again by the next scan or audit
    /// is not notified again. A new csecd run notifies a state that is still
    /// there once more. Returns whether the finding is recorded.
    private func report(
        _ finding: SealedBaselineFinding,
        pointer: SealedBaselinePointer?,
        evidence: String,
        treatedAsAbsent: Bool
    ) async -> Bool {
        let fingerprint = [
            finding.rawValue,
            pointer.map { "\($0.generation)/\($0.fileID)/\($0.digest)" } ?? "no pointer",
            evidence,
        ].joined(separator: "|")
        let isNew = reportedTamper?.fingerprint != fingerprint
        var report = reportedTamper.flatMap { $0.fingerprint == fingerprint ? $0 : nil }
            ?? ReportedTamper(fingerprint: fingerprint, recorded: false)
        if !report.recorded {
            report.recorded = await log.record(DecisionLogRecord(
                kind: .baselineIntegrity,
                cause: finding.rawValue,
                detail: "the sealed host-audit baseline was altered outside csecd: \(finding.summary); "
                    + (treatedAsAbsent
                        ? "treated as absent until it is resealed"
                        : "csecd restored its own access and the baseline verified unchanged")
            ))
        }
        reportedTamper = report
        if isNew {
            FileHandle.standardError.write(Data(
                ("csecd: host-audit baseline altered outside csecd (\(finding.rawValue)); "
                    + (treatedAsAbsent ? "treated as absent" : "access restored, baseline verified")
                    + (report.recorded ? "; recorded as baseline_integrity.\n" : "; the finding could not be recorded.\n")).utf8
            ))
            onNotice(.altered(SealedBaselineTamper(
                finding: finding, recorded: report.recorded, treatedAsAbsent: treatedAsAbsent
            )))
        }
        return report.recorded
    }

    // MARK: - Writing

    /// Seals `baseline` as the next generation after `previous`: write the new
    /// file under its pending name, bump the pointer, rename the file, delete
    /// everything else. Returns the new pointer, or nil when nothing changed
    /// (the old baseline, if any, is still current).
    private func seal(
        _ baseline: HostAuditBaseline,
        key: SymmetricKey,
        after previous: SealedBaselinePointer?
    ) async -> SealedBaselinePointer? {
        guard !stores.isUninstalled else {
            state = .uninstalled
            return nil
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let plaintext = try? encoder.encode(baseline),
              plaintext.count + SealedRecordFile.overhead <= Self.maximumSealedBytes else {
            FileHandle.standardError.write(Data(
                "csecd: host-audit baseline not saved: it does not encode within \(Self.maximumSealedBytes) bytes.\n".utf8
            ))
            return nil
        }
        let generation = (previous?.generation ?? 0) &+ 1
        let fileID = Self.randomFileID()
        guard generation > 0,
              let sealed = try? SealedRecordFile.seal(
                  plaintext, key: key, domain: Self.sealingDomain,
                  associatedData: Self.associatedData(generation: generation, fileID: fileID)
              ) else { return nil }
        let pointer = SealedBaselinePointer(generation: generation, fileID: fileID, digest: Self.digest(sealed))
        let pending = Self.pendingName(fileID)
        guard writeSealed(pending, sealed) else { return nil }

        if await !commitPointer(pointer) {
            // What the Keychain holds now decides, whatever the error said.
            // Unless it is this pointer, nothing names the new file, and the
            // old baseline (its file is deleted only after a bump) stays
            // current.
            let stored: SealedBaselinePointer?
            if case let .document(document) = await pointerStore.load() { stored = document } else { stored = nil }
            if stored != pointer {
                try? directory.remove(pending)
                // A failed write deletes the item. Left that way it would read
                // as `pointer_missing` (an alarm for csecd's own failure), and
                // until then deleting the sealed files and planting a
                // plaintext one would import it silently. So the previous
                // pointer goes straight back; only if that fails too does the
                // next load report the missing pointer.
                if stored == nil, let previous, await commitPointer(previous) {
                    FileHandle.standardError.write(Data(
                        "csecd: host-audit baseline pointer restored after a failed write.\n".utf8
                    ))
                }
                return nil
            }
        }
        let committed = Self.fileName(fileID)
        let keep = (try? directory.rename(pending, to: committed)) != nil ? committed : pending
        if case let .listed(listing) = list() {
            removeEntries(of: listing, except: keep)
        }
        // The names the previous pointer used, even ones the listing could
        // not see (a file hidden by an ACL): unlinking a name in csecd's own
        // directory changes nothing about the object it named.
        if let previous, previous.fileID != fileID {
            for name in [Self.fileName(previous.fileID), Self.pendingName(previous.fileID)] {
                try? directory.remove(name)
            }
        }
        return pointer
    }

    /// The only place a sealed file is written. Something other than a
    /// directory planted where the directory belongs was already reported;
    /// it is removed so the directory can be made again. A directory that
    /// refuses the write (an ACL or a mode on csecd's own directory) has
    /// csecd's access restored once.
    private func writeSealed(_ name: String, _ data: Data) -> Bool {
        guard !stores.isUninstalled else { return false }
        if case .notDirectory = list() {
            _ = unlink(directory.path)
        }
        var restored = false
        while true {
            do {
                try directory.prepare()
                try directory.writeAtomically(name, data: data)
                return true
            } catch {
                guard !restored, restoreOwnAccess(fileID: nil) else {
                    FileHandle.standardError.write(Data("csecd: host-audit baseline not saved: \(error).\n".utf8))
                    return false
                }
                restored = true
            }
        }
    }

    /// The only place the pointer is written. True only when this change is
    /// the item's current document.
    private func commitPointer(_ pointer: SealedBaselinePointer) async -> Bool {
        guard !stores.isUninstalled else { return false }
        do {
            return try await pointerStore.prepare(pointer).commit() == .applied
        } catch {
            FileHandle.standardError.write(Data(
                "csecd: host-audit baseline pointer not written: \(error).\n".utf8
            ))
            return false
        }
    }

    // MARK: - The plaintext file

    /// A plaintext baseline found while a sealed one exists is never imported
    /// (only a start with no pointer and no sealed file imports): it is
    /// deleted, and recorded so its appearance is on record. The one
    /// exception is the import's own leftover: a crash after the first
    /// pointer and before the plaintext was deleted leaves generation 1
    /// holding exactly what the file holds. That finishes the import and is
    /// recorded as one, not as something that appeared later.
    private func settlePlaintext(sealed: (pointer: SealedBaselinePointer, baseline: HostAuditBaseline)?) async {
        var info = stat()
        guard lstat(plaintextPath, &info) == 0 else {
            unremovablePlaintextRecorded = false
            return
        }
        let importLeftover = sealed.map {
            $0.pointer.generation == 1 && Self.isImportLeftover(Self.readPlaintext(at: plaintextPath), of: $0.baseline)
        } ?? false
        let removed = Self.removePlaintext(at: plaintextPath)
        if !removed {
            guard !unremovablePlaintextRecorded else { return }
            unremovablePlaintextRecorded = true
        }
        let deletion = removed ? "deleted it" : "it could not be deleted"
        if importLeftover {
            await log.record(DecisionLogRecord(
                kind: .baselineMigration,
                detail: "completed the import of the plaintext host-audit baseline after a restart: "
                    + "it was sealed before csecd stopped; \(deletion)"
            ))
            FileHandle.standardError.write(Data(
                "csecd: completed the host-audit baseline import after a restart; \(deletion).\n".utf8
            ))
            return
        }
        await log.record(DecisionLogRecord(
            kind: .baselineIntegrity,
            cause: Self.plaintextIgnoredCause,
            detail: "a plaintext host-audit baseline appeared after the sealed baseline existed; ignored; \(deletion)"
        ))
        FileHandle.standardError.write(Data(
            "csecd: ignored a plaintext host-audit baseline that appeared after sealing; \(deletion).\n".utf8
        ))
    }

    /// Whether a plaintext file is what the first import sealed: the same
    /// baseline, or one it could not import beside the empty baseline it
    /// sealed instead.
    static func isImportLeftover(_ plaintext: PlaintextBaseline, of sealed: HostAuditBaseline) -> Bool {
        switch plaintext {
        case let .baseline(baseline): return baseline == sealed
        case .notImportable: return sealed == HostAuditBaseline()
        case .absent, .unreadable: return false
        }
    }

    enum PlaintextBaseline: Equatable {
        case absent
        case baseline(HostAuditBaseline)
        /// Present but never importable: nothing to retry.
        case notImportable(String)
        /// A read error that may pass: import is retried later.
        case unreadable(Int32)
    }

    /// Reads the plaintext file without following a symbolic link and without
    /// blocking on a planted FIFO, bounded like a sealed file.
    static func readPlaintext(at path: String) -> PlaintextBaseline {
        let fd = Darwin.open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            switch errno {
            case ENOENT: return .absent
            case ELOOP: return .notImportable("it is a symbolic link")
            case EACCES: return .notImportable("csecd may not read it")
            case let code: return .unreadable(code)
            }
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0 else { return .unreadable(errno) }
        guard (info.st_mode & S_IFMT) == S_IFREG else { return .notImportable("it is not a regular file") }
        guard info.st_uid == getuid() else { return .notImportable("another user owns it") }
        guard info.st_size >= 0, info.st_size <= off_t(maximumSealedBytes) else {
            return .notImportable("it is larger than \(maximumSealedBytes) bytes")
        }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size) + 1)
        var count = 0
        while count < bytes.count {
            let read = bytes.withUnsafeMutableBytes { raw in
                Darwin.read(fd, raw.baseAddress!.advanced(by: count), raw.count - count)
            }
            if read < 0, errno == EINTR { continue }
            guard read >= 0 else { return .unreadable(errno) }
            if read == 0 { break }
            count += read
        }
        guard count <= Int(info.st_size) else { return .notImportable("it changed while being read") }
        guard let baseline = try? JSONDecoder().decode(HostAuditBaseline.self, from: Data(bytes[0..<count])) else {
            return .notImportable("it is not a host-audit baseline")
        }
        return .baseline(baseline)
    }

    static func removePlaintext(at path: String) -> Bool {
        unlink(path) == 0 || errno == ENOENT
    }

    /// Deletes the sealed directory and the plaintext file, whichever exist.
    /// csecd's uninstall calls it through the store (or directly when this
    /// run has no store). Returns a value-free description of what remains.
    public static func eraseFiles(
        directory: SealedRecordDirectory = SealedRecordDirectory(path: defaultDirectoryPath()),
        plaintextPath: String = defaultPlaintextPath()
    ) -> String? {
        var remaining: [String] = []
        var info = stat()
        if lstat(directory.path, &info) == 0 {
            if (info.st_mode & S_IFMT) == S_IFDIR {
                do {
                    try directory.removeDirectory()
                } catch {
                    if directory.exists() { remaining.append("the sealed host-audit baseline directory (\(error))") }
                }
            } else if unlink(directory.path) != 0, errno != ENOENT {
                remaining.append("the sealed host-audit baseline path (errno \(errno))")
            }
        }
        if !removePlaintext(at: plaintextPath) {
            remaining.append("the plaintext host-audit baseline (errno \(errno))")
        }
        return remaining.isEmpty ? nil : remaining.joined(separator: "; ")
    }

    // MARK: - Helpers

    /// Restores csecd's access to its own directory and to the pointer's
    /// sealed files: strips an extended ACL (without reading it first: an ACL
    /// can deny reading itself) and puts back 0700/0600. Nothing is changed
    /// until the object is proven csecd's own: its directory, or a regular
    /// file of this user with exactly one link, examined through a descriptor
    /// opened without following a symbolic link. csecd's sealed files are
    /// made by renaming a fresh file, so they have one link; a hard link
    /// planted under csecd's name, to a file csecd never wrote, has two, and
    /// is left exactly as it is. True when a repair was applied.
    private func restoreOwnAccess(fileID: String?) -> Bool {
        guard !stores.isUninstalled else { return false }
        var changed = Self.restoreOwnDirectory(at: directory.path)
        if let fileID {
            // The files are opened relative to the directory's own verified
            // descriptor, so a directory swapped for a link to somewhere else
            // after the listing redirects nothing.
            let flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
            let directoryFD = directory.path.withCString { Darwin.open($0, flags) }
            if directoryFD >= 0 {
                defer { close(directoryFD) }
                if let owned = Self.identity(of: directoryFD, file: false),
                   owned.type == .directory, owned.owner == getuid() {
                    for name in [Self.fileName(fileID), Self.pendingName(fileID)] {
                        changed = Self.restoreOwnFile(named: name, in: directoryFD) || changed
                    }
                }
            }
        }
        if changed {
            FileHandle.standardError.write(Data(
                "csecd: restored csecd's own access to the host-audit baseline directory.\n".utf8
            ))
        }
        return changed
    }

    /// The directory: through its descriptor when one opens, otherwise (an
    /// ACL denying csecd the listing refuses every open) by its attributes,
    /// read without following a symbolic link. A directory cannot be
    /// hard-linked, so its type and owner identify it.
    static func restoreOwnDirectory(at path: String) -> Bool {
        let flags = O_EVTONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        let fd = path.withCString { Darwin.open($0, flags) }
        if fd >= 0 {
            defer { close(fd) }
            guard let owned = identity(of: fd, file: false), owned.type == .directory,
                  owned.owner == getuid() else { return false }
            return stripAccessControl(fd: fd, mode: 0o700)
        }
        guard let owned = identity(atPath: path, file: false), owned.type == .directory,
              owned.owner == getuid(), let empty = acl_init(0) else { return false }
        defer { acl_free(UnsafeMutableRawPointer(empty)) }
        var stripped = acl_set_link_np(path, ACL_TYPE_EXTENDED, empty) == 0
        if !stripped, identity(atPath: path, file: false) == owned {
            // acl_set_link_np needs rights an ACL denying csecd its own
            // security refuses; acl_set_file does not, but follows a symbolic
            // link. It runs only on a path just seen, without following, to be
            // this user's directory. A directory cannot be hard-linked, so
            // only a link swapped in between the two calls could redirect it.
            stripped = acl_set_file(path, ACL_TYPE_EXTENDED, empty) == 0
        }
        let restored = fchmodat(AT_FDCWD, path, mode_t(0o700), AT_SYMLINK_NOFOLLOW) == 0
        return stripped && restored
    }

    /// A sealed file, only through a descriptor on exactly this inode: the
    /// first of an event-only, read or write open that csecd's own ACL still
    /// allows (never creating or truncating), then its identity, then the
    /// repair on that descriptor.
    static func restoreOwnFile(named name: String, in directoryFD: Int32) -> Bool {
        let base = O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC
        var fd: Int32 = -1
        for mode in [O_EVTONLY, O_RDONLY, O_WRONLY] {
            fd = name.withCString { openat(directoryFD, $0, mode | base) }
            if fd >= 0 || errno == ENOENT || errno == ELOOP { break }
        }
        guard fd >= 0 else { return false }
        defer { close(fd) }
        guard let owned = identity(of: fd, file: true), owned.type == .regular,
              owned.owner == getuid(), owned.links == 1 else { return false }
        return stripAccessControl(fd: fd, mode: 0o600)
    }

    private static func stripAccessControl(fd: Int32, mode: mode_t) -> Bool {
        guard let empty = acl_init(0) else { return false }
        defer { acl_free(UnsafeMutableRawPointer(empty)) }
        let stripped = acl_set_fd_np(fd, empty, ACL_TYPE_EXTENDED) == 0
        let restored = fchmod(fd, mode) == 0
        return stripped && restored
    }

    public struct Identity: Equatable, Sendable {
        public enum Kind: Equatable, Sendable { case regular, directory, other }
        public let type: Kind
        public let owner: uid_t
        public let links: UInt32

        init(type: Kind, owner: uid_t, links: UInt32) {
            self.type = type
            self.owner = owner
            self.links = links
        }

        init(_ info: stat) {
            switch info.st_mode & S_IFMT {
            case S_IFREG: type = .regular
            case S_IFDIR: type = .directory
            default: type = .other
            }
            owner = info.st_uid
            links = UInt32(info.st_nlink)
        }
    }

    /// An object's type, owner and link count: `fstat` when it may, or its
    /// attributes when an ACL denies csecd `fstat` (reading the attributes is
    /// a separate right). Nil when neither is allowed.
    static func identity(of fd: Int32, file: Bool) -> Identity? {
        var info = stat()
        if fstat(fd, &info) == 0 { return Identity(info) }
        return attributes(file: file) { list, buffer, size in fgetattrlist(fd, list, buffer, size, 0) }
    }

    public static func identity(atPath path: String, file: Bool) -> Identity? {
        var info = stat()
        if lstat(path, &info) == 0 { return Identity(info) }
        return attributes(file: file) { list, buffer, size in
            getattrlist(path, list, buffer, size, UInt32(FSOPT_NOFOLLOW))
        }
    }

    private static func attributes(
        file: Bool,
        _ read: (UnsafeMutableRawPointer, UnsafeMutableRawPointer, Int) -> Int32
    ) -> Identity? {
        var list = attrlist()
        list.bitmapcount = u_short(ATTR_BIT_MAP_COUNT)
        list.commonattr = attrgroup_t(ATTR_CMN_OBJTYPE) | attrgroup_t(ATTR_CMN_OWNERID)
        list.fileattr = file ? attrgroup_t(ATTR_FILE_LINKCOUNT) : 0
        // length, object type, owner, link count: four 32-bit values.
        var words = [UInt32](repeating: 0, count: 4)
        let status = withUnsafeMutablePointer(to: &list) { listPointer in
            words.withUnsafeMutableBytes { raw in
                read(UnsafeMutableRawPointer(listPointer), raw.baseAddress!, raw.count)
            }
        }
        guard status == 0 else { return nil }
        let kind: Identity.Kind
        switch words[1] {
        case VREG.rawValue: kind = .regular
        case VDIR.rawValue: kind = .directory
        default: kind = .other
        }
        // A directory returns no file attributes, so its reply is shorter.
        let links = kind == .regular && words[0] >= 16 ? words[3] : 0
        return Identity(type: kind, owner: uid_t(words[2]), links: links)
    }

    /// Whether `name` exists in the directory although csecd may not examine
    /// it (a listing leaves such a name out).
    private func exists(butCannotExamine name: String) -> Bool {
        var info = stat()
        let path = (directory.path as NSString).appendingPathComponent(name)
        return lstat(path, &info) != 0 && (errno == EACCES || errno == EPERM)
    }

    private func list() -> ListingResult {
        var info = stat()
        guard lstat(directory.path, &info) == 0 else {
            return errno == ENOENT ? .missing : .failed("errno \(errno)")
        }
        guard (info.st_mode & S_IFMT) == S_IFDIR else { return .notDirectory }
        do {
            let entries = try directory.entries()
            return .listed(Listing(regular: Set(entries.files.map(\.name)), foreign: Set(entries.foreignNames)))
        } catch SealedRecordError.notPrivate {
            return .notDirectory
        } catch {
            return .failed("\(error)")
        }
    }

    /// Deletes every entry but `keep`: superseded and orphaned sealed files,
    /// pending and temporary files, anything else placed here. csecd owns the
    /// directory; nothing in it but the current file is ever read.
    private func removeEntries(of listing: Listing, except keep: String?) {
        guard !stores.isUninstalled else { return }
        for name in listing.names where name != keep {
            try? directory.remove(name)
        }
    }

    private func becomeUnavailable(_ reason: String) -> Current {
        state = .unavailable(reason)
        if lastUnavailableReason != reason {
            lastUnavailableReason = reason
            FileHandle.standardError.write(Data(
                "csecd: host-audit baseline unavailable (\(reason)); treated as absent.\n".utf8
            ))
        }
        return .unavailable
    }

    static func fileName(_ fileID: String) -> String { "baseline-\(fileID).sealed" }
    static func pendingName(_ fileID: String) -> String { "pending-\(fileID).sealed" }

    /// The file ID of a committed sealed file's name, or nil.
    static func committedFileID(_ name: String) -> String? {
        let prefix = "baseline-", suffix = ".sealed"
        guard name.hasPrefix(prefix), name.hasSuffix(suffix) else { return nil }
        let fileID = String(name.dropFirst(prefix.count).dropLast(suffix.count))
        return SealedBaselinePointer.isLowercaseHex(fileID, length: 32) ? fileID : nil
    }

    static func associatedData(generation: UInt64, fileID: String) -> Data {
        var data = Data()
        data.appendUInt64(generation)
        data.append(Data(lowerHex: fileID) ?? Data())
        return data
    }

    static func digest(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    static func randomFileID() -> String {
        var generator = SystemRandomNumberGenerator()
        return Data((0..<16).map { _ in UInt8.random(in: .min ... .max, using: &generator) }).hexString
    }
}
