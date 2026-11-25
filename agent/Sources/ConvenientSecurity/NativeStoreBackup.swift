import CryptoKit
import Foundation
#if canImport(Darwin)
import Darwin
#endif

// The native-store backup's state and writer. See NativeStoreBackupCrypto.swift
// for what a bundle is and why it is safe to keep in iCloud Drive.
//
// The providers call `needsBundle` whenever a tier's key record is current in
// their hands — after every write, and after every local open — and, when it
// says so, hand over the record and its files. So a store changed while a
// write failed, or created before backups were turned on, is backed up the
// next time it is opened with Touch ID, and `csec backup sync` opens every
// store with one touch. A failed bundle never fails the store write it follows.
//
// A backup folder is only ever written by the one Mac whose settings name it:
// setup makes a new one, and a restore that carries the backup on makes a new
// one under the same kit. So no Mac ever replaces a bundle another Mac wrote,
// and a restore reads every folder its kit opens, taking each store's newest
// bundle. Nothing deletes a bundle except retiring a folder after a new kit
// (rotation), and then only the files this Mac's own manifest named there,
// once every store has a bundle in the new folder that iCloud has uploaded.

/// One bundle csecd wrote, as the manifest remembers it.
public struct NativeStoreBackupEntry: Codable, Sendable, Equatable {
    /// `NativeStoreBackupItem.tag` and `.name`.
    public let kind: String
    public let store: String
    /// The store record's generation and active file; zero and nil for the
    /// SSH catalog, whose bundle is rewritten on each change.
    public let generation: UInt64
    public let activeFileID: String?
    /// A keyed hash of the store's data key (`NativeStoreBackupPublicMaterial.lineage`),
    /// so a store recreated under the same name, whose generations start
    /// again at one, is still seen as changed. Never shown.
    public let lineage: String?
    public let fileName: String
    public let bytes: Int
    /// The bundle file's inode and modification time when csecd wrote it:
    /// with `bytes`, one `stat` tells whether it is still the file csecd
    /// wrote (an older genuine bundle put back is usually the same size).
    public let inode: UInt64
    public let modifiedNanoseconds: Int64
    /// SHA-256 of the bundle file, which is ciphertext throughout.
    public let digest: String
    public let writtenAt: Date

    var item: NativeStoreBackupItem? { NativeStoreBackupItem(tag: kind, name: store) }

    var isWellFormed: Bool {
        let pinsRecord: Bool
        switch item {
        case .store:
            pinsRecord = generation > 0
                && activeFileID.map(Self.isHex32) == true
                && lineage.map(Self.isHex32) == true
        case .sshCatalog:
            pinsRecord = generation == 0 && activeFileID == nil && lineage == nil
        case nil:
            return false
        }
        return pinsRecord
            && SealedRecordDirectory.isSafeName(fileName) && fileName.hasSuffix(NativeStoreBackupBundle.fileExtension)
            && bytes > 0 && bytes <= NativeStoreBackupBundle.maximumBytes
            && digest.utf8.count == 64 && digest.utf8.allSatisfy(NativeBlobIndex.isLowerHex)
    }

    private static func isHex32(_ value: String) -> Bool {
        value.utf8.count == 32 && value.utf8.allSatisfy(NativeBlobIndex.isLowerHex)
    }
}

/// A store change whose bundle could not be written. Cleared when a later
/// bundle for the same tier and store lands.
public struct NativeStoreBackupFailure: Codable, Sendable, Equatable {
    public static let maximumReasonBytes = 200

    public let kind: String
    public let store: String
    public let generation: UInt64
    public let reason: String
    /// A failure no retry of this generation can mend (the store is too
    /// large for one bundle): not attempted again until the store changes.
    public let permanent: Bool
    public let at: Date

    var item: NativeStoreBackupItem? { NativeStoreBackupItem(tag: kind, name: store) }

    var isWellFormed: Bool {
        item != nil && reason.utf8.count <= Self.maximumReasonBytes
    }
}

/// An earlier backup's folder waiting to be cleared after a new kit: the
/// bundle files this Mac wrote there, and nothing else.
public struct NativeStoreBackupRetiringFolder: Codable, Sendable, Equatable {
    public let folder: String
    public let fileNames: [String]

    var isWellFormed: Bool {
        folder.hasPrefix("/") && folder.utf8.count <= 1024 && !folder.utf8.contains(0)
            && fileNames.count <= NativeStoreBackupDocument.maximumEntries
            && fileNames.allSatisfy {
                SealedRecordDirectory.isSafeName($0) && $0.hasSuffix(NativeStoreBackupBundle.fileExtension)
            }
    }
}

/// The `native-store-backup`/`v1` protected item: what csecd needs to write
/// bundles, where they go, and what it last wrote. Because the item is
/// csecd-only, a same-UID process cannot swap in a recipient key of its own
/// and harvest every later bundle, nor learn the authentication key.
public struct NativeStoreBackupDocument: ProtectedDocument, Equatable {
    public static let protectedItem: ProtectedItem = .nativeStoreBackup
    public static let formatVersion = 1
    public static let maximumEntries = 4096
    public static let maximumRetiring = 8

    public var material: NativeStoreBackupPublicMaterial
    /// The backup's own folder (the root's `<backup ID>` subfolder).
    public var folder: String
    public var configuredAt: Date
    public var entries: [NativeStoreBackupEntry]
    public var failures: [NativeStoreBackupFailure]
    public var retiring: [NativeStoreBackupRetiringFolder]

    public init(
        material: NativeStoreBackupPublicMaterial,
        folder: String,
        configuredAt: Date,
        entries: [NativeStoreBackupEntry] = [],
        failures: [NativeStoreBackupFailure] = [],
        retiring: [NativeStoreBackupRetiringFolder] = []
    ) {
        self.material = material
        self.folder = folder
        self.configuredAt = configuredAt
        self.entries = entries
        self.failures = failures
        self.retiring = retiring
    }

    func entry(for item: NativeStoreBackupItem) -> NativeStoreBackupEntry? {
        entries.first { $0.item == item }
    }

    public var isWellFormed: Bool {
        material.isWellFormed
            && folder.hasPrefix("/") && folder.utf8.count <= 1024 && !folder.utf8.contains(0)
            && entries.count <= Self.maximumEntries
            && failures.count <= Self.maximumEntries
            && retiring.count <= Self.maximumRetiring
            && entries.allSatisfy(\.isWellFormed)
            && failures.allSatisfy(\.isWellFormed)
            && retiring.allSatisfy(\.isWellFormed)
            && Set(entries.map { "\($0.kind)/\($0.store)" }).count == entries.count
            && Set(failures.map { "\($0.kind)/\($0.store)" }).count == failures.count
    }
}

/// Value-free status for `csec backup status` and `csec doctor`.
public struct NativeStoreBackupStatus: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable {
        case off
        case on
        /// The settings item exists but this build cannot read it.
        case unreadable
    }

    public enum BundleState: String, Codable, Sendable {
        /// The bundle csecd last wrote is in the folder, unchanged.
        case current
        /// The store changed and its bundle could not be written.
        case failed
        /// The bundle csecd last wrote is gone, or is not the file it wrote.
        case missingOrChanged = "missing_or_changed"
        /// The store is on this Mac and no bundle has been written for it.
        case notBackedUp = "not_backed_up"
    }

    public struct Store: Codable, Sendable, Equatable {
        /// `doc`, `blob` or `ssh-catalog`; `store` is empty for the catalog.
        public let kind: String
        public let store: String
        public let state: BundleState
        public let generation: UInt64?
        public let writtenAt: Date?
        /// iCloud Drive's own answer for the bundle; nil outside iCloud Drive.
        public let uploaded: Bool?
        public let failureReason: String?
    }

    public let state: State
    public let unreadableReason: String?
    public let folder: String?
    public let configuredAt: Date?
    public let stores: [Store]
    /// Earlier backups' folders still waiting to be cleared after a new kit.
    public let retiringFolders: Int

    public static let off = NativeStoreBackupStatus(
        state: .off, unreadableReason: nil, folder: nil, configuredAt: nil, stores: [], retiringFolders: 0
    )

    public var problems: [Store] { stores.filter { $0.state != .current } }
}

/// Where the bundles go, and what lists the stores this Mac holds.
public struct NativeStoreBackupLocations: Sendable {
    /// The folder that holds one subfolder per backup.
    public let root: String
    /// The document tier's and the blob tier's ciphertext directories.
    public let documentDirectory: String
    public let blobDirectory: String

    public init(root: String, documentDirectory: String, blobDirectory: String) {
        self.root = root
        self.documentDirectory = documentDirectory
        self.blobDirectory = blobDirectory
    }

    /// iCloud Drive's own folder: what Finder shows as iCloud Drive.
    public static func iCloudDrivePath() -> String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Mobile Documents/com~apple~CloudDocs", isDirectory: true)
            .path
    }

    public static func defaultRoot() -> String {
        (iCloudDrivePath() as NSString).appendingPathComponent("Convenient Security Backups")
    }

    public static func production(root: String? = nil) -> NativeStoreBackupLocations {
        NativeStoreBackupLocations(
            root: root ?? defaultRoot(),
            documentDirectory: SecureNativeStoreFileBackend.defaultDirectoryPath(),
            blobDirectory: NativeBlobStore.defaultBlobDirectoryPath()
        )
    }
}

/// What one attempt to bring a store's bundle up to date did.
public enum NativeStoreBackupOutcome: Sendable, Equatable {
    /// No backup is attached to the provider, or it is not set up.
    case off
    /// The last bundle already holds this record, or a newer one landed.
    case current
    case written
    case failed
}

/// Value-free counts from `backfillBackups`.
public struct NativeStoreBackupReport: Codable, Sendable, Equatable {
    public var written: Int
    public var current: Int
    public var failed: Int

    public init(written: Int = 0, current: Int = 0, failed: Int = 0) {
        self.written = written
        self.current = current
        self.failed = failed
    }

    public mutating func add(_ outcome: NativeStoreBackupOutcome) {
        switch outcome {
        case .written: written += 1
        case .current: current += 1
        case .failed: failed += 1
        case .off: break
        }
    }

    public mutating func add(_ other: NativeStoreBackupReport) {
        written += other.written
        current += other.current
        failed += other.failed
    }
}

/// What a restore found: every bundle the kit opens, the newest per item
/// across all the folders it opens, and what it could not read.
public struct NativeStoreBackupFound: Sendable {
    public struct Bundle: Sendable {
        public let contents: NativeStoreBackupContents
        public let folder: String
    }

    public let bundles: [Bundle]
    /// The root that holds the folders, where a carried-on backup goes.
    public let root: String
    /// The folder of the newest bundle.
    public let newestFolder: String
    /// Bundles in those folders that did not open under the kit.
    public let unreadable: Int
    /// Bundles iCloud Drive has not downloaded to this Mac yet; asked to.
    public let notDownloaded: Int
}

/// The file half of a restore, shared by both tiers.
enum NativeStoreBackupRestoration {
    /// Write a restored store's files, before its Keychain record is made.
    /// Only a store this Mac does not have is restored: no open or stored
    /// record, and no file under its name except this very bundle's own, byte
    /// for byte, which a restore that stopped before making the record left
    /// behind; those are kept and the rest written. Returns the names it
    /// wrote, for the caller to remove if the record cannot be made.
    static func writeFiles(
        _ files: [String: Data],
        store: NativeStoreName,
        keyBackend: NativeStoreKeyBackend,
        fileBackend: NativeStoreFileBackend,
        alreadyOpen: Bool
    ) async throws -> [String] {
        guard !alreadyOpen, (try? await keyBackend.recordExists(store: store.value)) == false else {
            throw NativeStoreBackupError.storeExists
        }
        let present: [String]
        if let listed = await fileBackend.fileNames(for: store.value) {
            present = listed
        } else if await fileBackend.filePresence(for: store.value) == false {
            present = []
        } else {
            throw NativeStoreBackupError.storeExists
        }
        for name in present {
            guard let expected = files[name], (try? await fileBackend.read(named: name)) == expected else {
                throw NativeStoreBackupError.storeExists
            }
        }
        var written: [String] = []
        do {
            for (name, data) in files.sorted(by: { $0.key < $1.key }) where !present.contains(name) {
                try await fileBackend.writeAtomically(named: name, data: data)
                written.append(name)
            }
        } catch {
            for name in written { await fileBackend.delete(named: name) }
            throw NativeStoreError.filesystemFailure
        }
        return written
    }
}

public actor NativeStoreBackup {
    private enum State {
        case unloaded
        case off
        case on(NativeStoreBackupDocument)
        case unreadable(ProtectedUnreadableReason)
    }

    public static let readmeName = "README.txt"
    static let readme = """
    Convenient Security (csec) native-store backups.

    Each subfolder is one backup: its .csecbackup files are csec's native
    stores and SSH key catalog, sealed to a recovery key that exists only in
    the recovery kit shown once by `csec backup setup`. Without that kit
    these files open nothing; with it, `csec backup restore` puts the stores
    back on a Mac.

    To remove a backup, turn it off first (`csec backup off`, or a new
    `csec backup setup`), then delete its subfolder. csec never reads
    anything else in this folder.

    """

    private let store: ProtectedStore<NativeStoreBackupDocument>
    public nonisolated let locations: NativeStoreBackupLocations
    /// The largest bundle written; `NativeStoreBackupBundle.maximumBytes`
    /// outside tests.
    public nonisolated let maximumBundleBytes: Int
    private let now: @Sendable () -> Date
    private var state: State = .unloaded
    /// The newest SSH catalog revision handed over this run: the catalog
    /// passes its changes in order, but they can arrive here out of it.
    private var catalogRevision: UInt64 = 0

    public init(
        stores: ProtectedStores,
        locations: NativeStoreBackupLocations,
        maximumBundleBytes: Int = NativeStoreBackupBundle.maximumBytes,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.store = stores.store(for: NativeStoreBackupDocument.self)
        self.locations = locations
        self.maximumBundleBytes = min(maximumBundleBytes, NativeStoreBackupBundle.maximumBytes)
        self.now = now
    }

    // MARK: - Writing bundles

    /// Whether `record` needs a new bundle: it is newer than (or of another
    /// lineage than) the bundle csecd last wrote for this tier and store, or
    /// that bundle is no longer the file csecd wrote. Never true when backups
    /// are off, for a store with nothing in it yet, or for a generation whose
    /// last attempt failed in a way no retry mends. One `stat`; nothing read.
    public func needsBundle(tier: NativeStoreTier, store: NativeStoreName, record: NativeStoreKeyRecord) async -> Bool {
        guard record.generation > 0, case let .on(document) = await loadedState() else { return false }
        let item = NativeStoreBackupItem.store(tier, store)
        if let failure = document.failures.first(where: { $0.item == item }),
           failure.permanent, failure.generation == record.generation {
            return false
        }
        guard let entry = document.entry(for: item) else { return true }
        return Self.isNewer(record, than: entry, material: document.material)
            || !Self.isPresent(entry, in: document.folder)
    }

    /// Seal `contents` and write its bundle, unless the bundle csecd last
    /// wrote is newer and still in place. A failure is recorded for status
    /// and logged value-free; it never reaches the store write that led here.
    @discardableResult
    public func write(_ contents: NativeStoreBackupContents) async -> NativeStoreBackupOutcome {
        guard case let .on(document) = await loadedState() else { return .off }
        let record = contents.record
        if let record, let entry = document.entry(for: contents.item),
           !Self.shouldReplace(entry, with: record, document: document) {
            return .current
        }
        let fileName = document.material.bundleFileName(contents.item)
        // Stamped by this clock: a restore takes each store's newest bundle.
        let stamped = NativeStoreBackupContents(item: contents.item, body: contents.body, createdAt: now())
        let bundle: Data
        let identity: (inode: UInt64, modified: Int64)
        do {
            bundle = try NativeStoreBackupBundle.seal(stamped, material: document.material, maximumBytes: maximumBundleBytes)
            try Self.ensureFolder(document.folder)
            try SealedRecordDirectory(path: document.folder).writeAtomically(fileName, data: bundle)
            guard let written = Self.fileIdentity((document.folder as NSString).appendingPathComponent(fileName)) else {
                throw NativeStoreBackupError.destinationUnavailable
            }
            identity = (written.inode, written.modified)
        } catch {
            await recordFailure(
                contents.item, generation: record?.generation ?? 0, reason: Self.reason(error),
                permanent: (error as? NativeStoreBackupError) == .bundleTooLarge
            )
            return .failed
        }
        let entry = NativeStoreBackupEntry(
            kind: contents.item.tag, store: contents.item.name,
            generation: record?.generation ?? 0, activeFileID: record?.activeFileID,
            lineage: record.map { document.material.lineage(of: $0.keyData) },
            fileName: fileName, bytes: bundle.count,
            inode: identity.inode, modifiedNanoseconds: identity.modified,
            digest: NativeStoreEnvelope.digest(bundle), writtenAt: now()
        )
        var current = document
        if let index = current.entries.firstIndex(where: { $0.item == contents.item }) {
            current.entries[index] = entry
        } else {
            guard current.entries.count < NativeStoreBackupDocument.maximumEntries else { return .failed }
            current.entries.append(entry)
        }
        current.failures.removeAll { $0.item == contents.item }
        await persist(current)
        if !current.retiring.isEmpty { await retireIfSafe() }
        return .written
    }

    /// Write the SSH key catalog's bundle. `revision` orders the catalog's
    /// changes within this run; an older one than the last handed over is
    /// dropped.
    @discardableResult
    public func writeSSHCatalog(_ keys: [SSHKeyMetadata], revision: UInt64) async -> NativeStoreBackupOutcome {
        guard revision >= catalogRevision else { return .current }
        catalogRevision = revision
        guard await isOn() else { return .off }
        // Another change may have been handed over while the settings loaded.
        guard revision == catalogRevision else { return .current }
        return await write(NativeStoreBackupContents(
            item: .sshCatalog,
            body: .sshCatalog(keys.sorted { $0.fingerprint < $1.fingerprint }),
            createdAt: now()
        ))
    }

    /// Remember that a change has no bundle, for status, until a later
    /// bundle for it lands. A failure for a generation the manifest already
    /// holds a newer bundle of is dropped: a newer write overtook it.
    public func recordFailure(
        _ item: NativeStoreBackupItem,
        generation: UInt64,
        reason: String,
        permanent: Bool = false
    ) async {
        guard case var .on(document) = await loadedState() else { return }
        if case .store = item, let entry = document.entry(for: item),
           entry.generation >= generation, Self.isPresent(entry, in: document.folder) {
            return
        }
        Self.log("\(item) generation \(generation) not backed up (\(reason))")
        let failure = NativeStoreBackupFailure(
            kind: item.tag, store: item.name, generation: generation,
            reason: String(decoding: Data(reason.utf8).prefix(NativeStoreBackupFailure.maximumReasonBytes), as: UTF8.self),
            permanent: permanent, at: now()
        )
        document.failures.removeAll { $0.item == item }
        guard document.failures.count < NativeStoreBackupDocument.maximumEntries else { return }
        document.failures.append(failure)
        await persist(document)
    }

    // MARK: - Setup

    public func isOn() async -> Bool {
        if case .on = await loadedState() { return true }
        return false
    }

    public func isOff() async -> Bool {
        if case .off = await loadedState() { return true }
        return false
    }

    /// Why the settings item cannot be read, or nil.
    public func unreadableReason() async -> ProtectedUnreadableReason? {
        if case let .unreadable(reason) = await loadedState() { return reason }
        return nil
    }

    /// Start a backup sealed to `kit` in a new folder under `root` (iCloud
    /// Drive's by default), replacing this Mac's earlier one. The earlier
    /// folder is kept for its kit until every store has an uploaded bundle in
    /// the new one (`retireIfSafe`), and then only csecd's own bundles go.
    public func configure(kit: BackupRecoveryKit, root: String? = nil) async throws {
        var retiring: [NativeStoreBackupRetiringFolder] = []
        if case let .on(previous) = await loadedState() {
            retiring = previous.retiring
            if !previous.entries.isEmpty, retiring.count < NativeStoreBackupDocument.maximumRetiring {
                retiring.append(NativeStoreBackupRetiringFolder(
                    folder: previous.folder, fileNames: previous.entries.map(\.fileName)
                ))
            }
        }
        let root = root ?? locations.root
        let backupID = try NativeStoreBackupPublicMaterial.randomBackupID()
        let folder = (root as NSString).appendingPathComponent(backupID)
        try Self.prepareRoot(root)
        try Self.ensureFolder(folder)
        try await replace(with: NativeStoreBackupDocument(
            material: kit.material(backupID: backupID),
            folder: folder,
            configuredAt: now(),
            retiring: retiring
        ))
    }

    /// Stop writing bundles. The folder is left as it is: its kit still
    /// restores what it holds.
    public func turnOff() async throws {
        let previous = state
        // Off before the await, so no write that lands meanwhile can take a
        // later place in the item's order and bring the settings back.
        state = .off
        do {
            try await store.prepareDiscard().commit()
        } catch {
            state = previous
            throw NativeStoreBackupError.destinationUnavailable
        }
    }

    /// Clear the folders an earlier kit left, once that loses nothing: every
    /// store this Mac holds has a current bundle in the new folder, iCloud
    /// Drive has uploaded each one, and no write is failing. Only the files
    /// this Mac's own manifest named there are removed, and the folder only
    /// when nothing else is left in it. Returns how many folders remain.
    @discardableResult
    public func retireIfSafe() async -> Int {
        guard case var .on(document) = await loadedState() else { return 0 }
        guard !document.retiring.isEmpty else { return 0 }
        let status = await status()
        guard status.problems.isEmpty, status.stores.allSatisfy({ $0.uploaded != false }) else {
            return document.retiring.count
        }
        for retired in document.retiring {
            let folder = SealedRecordDirectory(path: retired.folder)
            guard folder.exists() else { continue }
            for name in retired.fileNames { try? folder.remove(name) }
            _ = Darwin.rmdir(retired.folder)
        }
        document.retiring = []
        await persist(document)
        return 0
    }

    /// A human asked for this backup, so whatever the item held, even one
    /// this build cannot read, is replaced rather than kept.
    private func replace(with document: NativeStoreBackupDocument) async throws {
        guard document.isWellFormed else { throw NativeStoreBackupError.invalidBundle }
        catalogRevision = 0
        let previous = state
        state = .on(document)
        do {
            try await store.prepareDiscard().commit()
            try await store.prepare(document).commit()
        } catch {
            state = previous
            throw NativeStoreBackupError.destinationUnavailable
        }
    }

    // MARK: - Status

    public func status() async -> NativeStoreBackupStatus {
        let document: NativeStoreBackupDocument
        switch await loadedState() {
        case .off, .unloaded:
            return NativeStoreBackupStatus(
                state: .off, unreadableReason: nil, folder: nil, configuredAt: nil,
                stores: Self.storesOnDisk(locations).map {
                    .init(kind: $0.0.rawValue, store: $0.1, state: .notBackedUp,
                          generation: nil, writtenAt: nil, uploaded: nil, failureReason: nil)
                },
                retiringFolders: 0
            )
        case let .unreadable(reason):
            return NativeStoreBackupStatus(
                state: .unreadable, unreadableReason: reason.description,
                folder: nil, configuredAt: nil, stores: [], retiringFolders: 0
            )
        case let .on(loaded):
            document = loaded
        }
        var stores: [NativeStoreBackupStatus.Store] = []
        var seen = Set<String>()
        for failure in document.failures {
            seen.insert("\(failure.kind)/\(failure.store)")
            let entry = document.entries.first { $0.kind == failure.kind && $0.store == failure.store }
            stores.append(.init(
                kind: failure.kind, store: failure.store, state: .failed,
                generation: entry?.generation, writtenAt: entry?.writtenAt,
                uploaded: nil, failureReason: failure.reason
            ))
        }
        for entry in document.entries where !seen.contains("\(entry.kind)/\(entry.store)") {
            seen.insert("\(entry.kind)/\(entry.store)")
            let path = (document.folder as NSString).appendingPathComponent(entry.fileName)
            let present = Self.isPresent(entry, in: document.folder)
            stores.append(.init(
                kind: entry.kind, store: entry.store,
                state: present ? .current : .missingOrChanged,
                generation: entry.generation, writtenAt: entry.writtenAt,
                uploaded: present ? Self.uploaded(path) : nil, failureReason: nil
            ))
        }
        for (tier, name) in Self.storesOnDisk(locations) where !seen.contains("\(tier.rawValue)/\(name)") {
            stores.append(.init(
                kind: tier.rawValue, store: name, state: .notBackedUp,
                generation: nil, writtenAt: nil, uploaded: nil, failureReason: nil
            ))
        }
        stores.sort { ($0.store, $0.kind) < ($1.store, $1.kind) }
        return NativeStoreBackupStatus(
            state: .on, unreadableReason: nil, folder: document.folder,
            configuredAt: document.configuredAt, stores: stores,
            retiringFolders: document.retiring.count
        )
    }

    // MARK: - Restore

    /// Every bundle `kit` opens in the backup folders under `root` (or in
    /// `root` itself, when it is one), the newest per item. A folder of
    /// another kit is passed over without a sign of what it holds. Read only:
    /// nothing in the folders is created, repaired or removed, and a bundle
    /// iCloud Drive has not downloaded yet is asked for and counted rather
    /// than waited on.
    public static func find(kit: BackupRecoveryKit, root: String) throws -> NativeStoreBackupFound {
        let keys = kit.keys
        var candidates: [String] = []
        var parent = root
        if isBackupID((root as NSString).lastPathComponent) {
            candidates.append(root)
            parent = (root as NSString).deletingLastPathComponent
        }
        if let names = try? FileManager.default.contentsOfDirectory(atPath: root) {
            candidates += names.filter(isBackupID).sorted().map { (root as NSString).appendingPathComponent($0) }
        }
        var newest: [NativeStoreBackupItem: NativeStoreBackupFound.Bundle] = [:]
        var unreadable = 0
        var notDownloaded = 0
        for folderPath in candidates {
            let backupID = (folderPath as NSString).lastPathComponent
            let names = (try? FileManager.default.contentsOfDirectory(atPath: folderPath)) ?? []
            var opened: [NativeStoreBackupContents] = []
            var failed = 0
            for name in names {
                // An iCloud placeholder for a bundle not downloaded yet.
                if name.hasPrefix("."), name.hasSuffix(NativeStoreBackupBundle.fileExtension + ".icloud") {
                    let real = String(name.dropFirst().dropLast(".icloud".count))
                    requestDownload((folderPath as NSString).appendingPathComponent(real))
                    notDownloaded += 1
                    continue
                }
                guard name.hasSuffix(NativeStoreBackupBundle.fileExtension) else { continue }
                let path = (folderPath as NSString).appendingPathComponent(name)
                if !isDownloaded(path) {
                    requestDownload(path)
                    notDownloaded += 1
                    continue
                }
                guard let data = readBundle(path),
                      let contents = try? NativeStoreBackupBundle.open(
                          data, fileName: name, backupID: backupID, keys: keys
                      ) else {
                    failed += 1
                    continue
                }
                opened.append(contents)
            }
            // A folder none of whose bundles opens belongs to another kit:
            // its unreadable files are not this backup's to count.
            guard !opened.isEmpty else { continue }
            unreadable += failed
            for contents in opened where newest[contents.item].map({ contents.createdAt > $0.contents.createdAt }) ?? true {
                newest[contents.item] = .init(contents: contents, folder: folderPath)
            }
        }
        guard let latest = newest.values.max(by: { $0.contents.createdAt < $1.contents.createdAt }) else {
            throw NativeStoreBackupError.noMatchingBackup
        }
        let bundles = newest.values.sorted {
            ($0.contents.item.name, $0.contents.item.tag) < ($1.contents.item.name, $1.contents.item.tag)
        }
        return NativeStoreBackupFound(
            bundles: bundles, root: parent, newestFolder: latest.folder,
            unreadable: unreadable, notDownloaded: notDownloaded
        )
    }

    // MARK: - Internals

    private func loadedState() async -> State {
        if case .unloaded = state {
            let loaded = await store.load()
            // Another call may have settled the state while this one loaded.
            guard case .unloaded = state else { return state }
            switch loaded {
            case .absent: state = .off
            case let .document(document): state = .on(document)
            case let .unreadable(reason): state = .unreadable(reason)
            }
        }
        return state
    }

    private func persist(_ document: NativeStoreBackupDocument) async {
        state = .on(document)
        do {
            try await store.prepare(document).commit()
        } catch {
            Self.log("the backup manifest could not be saved (\(error))")
        }
    }

    static func isNewer(
        _ record: NativeStoreKeyRecord,
        than entry: NativeStoreBackupEntry,
        material: NativeStoreBackupPublicMaterial
    ) -> Bool {
        if entry.lineage != material.lineage(of: record.keyData) { return true }
        if record.generation != entry.generation { return record.generation > entry.generation }
        return record.activeFileID != entry.activeFileID
    }

    /// A newer record always replaces the bundle; an older one only when
    /// the newer bundle is gone, and never one of the same lineage that is
    /// older than what the manifest holds.
    private static func shouldReplace(
        _ entry: NativeStoreBackupEntry,
        with record: NativeStoreKeyRecord,
        document: NativeStoreBackupDocument
    ) -> Bool {
        if isNewer(record, than: entry, material: document.material) { return true }
        let sameLineage = entry.lineage == document.material.lineage(of: record.keyData)
        return sameLineage && record.generation == entry.generation && !isPresent(entry, in: document.folder)
    }

    private static func isBackupID(_ name: String) -> Bool {
        name.utf8.count == 32 && name.utf8.allSatisfy(NativeBlobIndex.isLowerHex)
    }

    /// The root that holds backup folders: created (0700, with a README)
    /// when it does not exist and its parent does. An existing root, perhaps
    /// a folder the human chose, is left exactly as it is.
    private static func prepareRoot(_ root: String) throws {
        var info = stat()
        if lstat(root, &info) == 0 {
            guard (info.st_mode & S_IFMT) == S_IFDIR else { throw NativeStoreBackupError.destinationUnavailable }
            return
        }
        let parent = (root as NSString).deletingLastPathComponent
        guard lstat(parent, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              mkdir(root, mode_t(0o700)) == 0 else {
            throw NativeStoreBackupError.destinationUnavailable
        }
        try? SealedRecordDirectory(path: root).writeAtomically(readmeName, data: Data(readme.utf8))
    }

    /// The backup's own folder, created as one 0700 directory when it is
    /// missing and the root still exists. A missing root (iCloud Drive
    /// turned off, or the folder deleted) is not recreated.
    private static func ensureFolder(_ folder: String) throws {
        var info = stat()
        if lstat(folder, &info) == 0 {
            guard (info.st_mode & S_IFMT) == S_IFDIR else { throw NativeStoreBackupError.destinationUnavailable }
            return
        }
        let root = (folder as NSString).deletingLastPathComponent
        guard lstat(root, &info) == 0, (info.st_mode & S_IFMT) == S_IFDIR,
              mkdir(folder, mode_t(0o700)) == 0 else {
            throw NativeStoreBackupError.destinationUnavailable
        }
    }

    /// The stores this Mac holds, by tier, from their ciphertext file names
    /// alone: no Keychain item is read and nothing prompts.
    static func storesOnDisk(_ locations: NativeStoreBackupLocations) -> [(NativeStoreTier, String)] {
        func names(in directory: String, suffix: String) -> Set<String> {
            let files = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
            var stores = Set<String>()
            for file in files where file.hasSuffix(suffix) {
                let stem = file.dropLast(suffix.count)
                guard let dot = stem.lastIndex(of: ".") else { continue }
                let id = stem[stem.index(after: dot)...]
                guard id.utf8.count == 32, id.utf8.allSatisfy(NativeBlobIndex.isLowerHex),
                      let name = try? NativeStoreName(String(stem[..<dot])) else { continue }
                stores.insert(name.value)
            }
            return stores
        }
        let documents = names(in: locations.documentDirectory, suffix: ".csec")
        let blobs = names(in: locations.blobDirectory, suffix: ".index.csec")
        return documents.sorted().map { (.documents, $0) } + blobs.sorted().map { (.blobs, $0) }
    }

    private static func isPresent(_ entry: NativeStoreBackupEntry, in folder: String) -> Bool {
        guard let identity = fileIdentity((folder as NSString).appendingPathComponent(entry.fileName)) else {
            return false
        }
        return identity.size == entry.bytes && identity.inode == entry.inode
            && identity.modified == entry.modifiedNanoseconds
    }

    private static func fileIdentity(_ path: String) -> (size: Int, inode: UInt64, modified: Int64)? {
        var info = stat()
        guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }
        let modified = Int64(info.st_mtimespec.tv_sec) * 1_000_000_000 + Int64(info.st_mtimespec.tv_nsec)
        return (Int(info.st_size), UInt64(info.st_ino), modified)
    }

    private static func uploaded(_ path: String) -> Bool? {
        let url = URL(fileURLWithPath: path)
        guard let values = try? url.resourceValues(forKeys: [.isUbiquitousItemKey, .ubiquitousItemIsUploadedKey]),
              values.isUbiquitousItem == true else { return nil }
        return values.ubiquitousItemIsUploaded
    }

    private static func isDownloaded(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        guard let values = try? url.resourceValues(forKeys: [.isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey]),
              values.isUbiquitousItem == true,
              let status = values.ubiquitousItemDownloadingStatus else { return true }
        return status != .notDownloaded
    }

    private static func requestDownload(_ path: String) {
        try? FileManager.default.startDownloadingUbiquitousItem(at: URL(fileURLWithPath: path))
    }

    /// A bundle's bytes: a regular file, never through a symlink, within the
    /// size limit. Nothing about it is changed.
    private static func readBundle(_ path: String) -> Data? {
        let fd = path.withCString { open($0, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) }
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size >= 0, info.st_size <= off_t(NativeStoreBackupBundle.maximumBytes) else { return nil }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeMutableBytes { raw in
                Darwin.read(fd, raw.baseAddress!.advanced(by: offset), raw.count - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { return nil }
            offset += count
        }
        return Data(bytes)
    }

    private static func reason(_ error: Error) -> String {
        if let error = error as? ProviderDiagnosableError { return error.boundedReason }
        if let error = error as? SealedRecordError { return error.description }
        return "the bundle could not be written"
    }

    static func log(_ message: String) {
        FileHandle.standardError.write(Data("csecd: native-store backup: \(message)\n".utf8))
    }
}
