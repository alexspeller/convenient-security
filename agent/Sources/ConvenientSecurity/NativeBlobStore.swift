import Foundation

/// The file/blob tier of the unified `csec://` native store. A blob is opaque
/// file *bytes* — an `.envrc`, a service-account JSON, a `master.key`, a cert,
/// or arbitrary binary — addressed by the same `csec://<store>/<key>` reference
/// as a small editable-document secret. Which tier backs a given key is a pure
/// storage decision the provider makes; the reference never encodes it. A blob
/// is decrypted from its own sealed ciphertext file, so a single value is served
/// without touching the others and hundreds of files never inflate one decrypt.

/// One index row. `digest` pins the blob ciphertext (rollback/integrity), `mode`
/// is the intended POSIX permission of the materialized file, `size` is the
/// plaintext length (a cheap post-decrypt sanity check), and `path` is the
/// original project-relative location the importer recorded. Metadata only —
/// never a value.
public struct NativeBlobEntry: Codable, Equatable, Sendable {
    public let blobId: String
    public let digest: String
    public let mode: UInt16
    public let size: Int
    public let path: String

    public init(blobId: String, digest: String, mode: UInt16, size: Int, path: String) {
        self.blobId = blobId
        self.digest = digest
        self.mode = mode
        self.size = size
        self.path = path
    }

    var isWellFormed: Bool {
        blobId.utf8.count == 32 && blobId.utf8.allSatisfy(NativeBlobIndex.isLowerHex)
            && digest.utf8.count == 64 && digest.utf8.allSatisfy(NativeBlobIndex.isLowerHex)
            && size >= 0 && size <= NativeBlobStore.maximumBlobBytes
            && mode <= 0o7777
            && NativeBlobIndex.isSafeRelativePath(path)
    }
}

/// The encrypted per-store index: `key -> NativeBlobEntry`. It holds only
/// metadata, so it stays small even with thousands of protected files, and is
/// itself sealed and pinned by the store's keychain record for rollback safety.
public struct NativeBlobIndex: Sendable, Equatable {
    public static let maximumBlobs = 8192
    public static let maximumIndexBytes = 8 * 1024 * 1024

    public private(set) var entries: [String: NativeBlobEntry]

    public init(entries: [String: NativeBlobEntry] = [:]) throws {
        guard entries.count <= Self.maximumBlobs,
              entries.keys.allSatisfy(NativeStoreDocument.isValidKey),
              entries.allSatisfy({ $0.value.isWellFormed }) else {
            throw NativeStoreError.invalidDocument
        }
        self.entries = entries
    }

    public init(data: Data) throws {
        guard data.count <= Self.maximumIndexBytes else {
            throw NativeStoreError.documentTooLarge
        }
        let decoded: [String: NativeBlobEntry]
        do {
            decoded = try JSONDecoder().decode([String: NativeBlobEntry].self, from: data)
        } catch {
            throw NativeStoreError.invalidDocument
        }
        try self.init(entries: decoded)
    }

    public func encoded() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(entries)
        guard data.count <= Self.maximumIndexBytes else {
            throw NativeStoreError.documentTooLarge
        }
        return data
    }

    mutating func set(_ key: String, _ entry: NativeBlobEntry) throws {
        guard NativeStoreDocument.isValidKey(key), entry.isWellFormed else {
            throw NativeStoreError.invalidDocument
        }
        var next = entries
        next[key] = entry
        guard next.count <= Self.maximumBlobs else { throw NativeStoreError.tooManySecrets }
        entries = next
    }

    static func isLowerHex(_ byte: UInt8) -> Bool {
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }

    static func isSafeRelativePath(_ value: String) -> Bool {
        guard !value.isEmpty,
              !value.hasPrefix("/"),
              !value.utf8.contains(0),
              value.utf8.count <= 1024 else { return false }
        return value.split(separator: "/", omittingEmptySubsequences: false).allSatisfy {
            !$0.isEmpty && $0 != "." && $0 != ".."
        }
    }
}

public struct NativeBlobRecord: Sendable, Equatable {
    public let data: Data
    public let mode: UInt16
    public let path: String
}

/// The per-blob encrypted file provider. Structurally parallel to
/// `NativeEncryptedFileProvider`, but the keychain-pinned document is a small
/// *index* and each blob's bytes live in their own sealed ciphertext file, so a
/// single blob is decrypted without touching the others and hundreds of files
/// never inflate one monolithic decrypt. Rollback safety chains
/// keychain record -> index (fileID + digest) -> each blob (digest in index).
public actor NativeBlobStore {
    public static let maximumBlobBytes = 4 * 1024 * 1024

    private let keyBackend: NativeStoreKeyBackend
    private let fileBackend: NativeStoreFileBackend
    private var records: [String: NativeStoreKeyRecord] = [:]
    /// Stores an authenticated read found to have no blob-tier key record. Only
    /// this actor creates one (`recordForWrite`, which clears the mark), so a
    /// later lookup can answer "no such store" without an unlock.
    private var absentRecords: Set<String> = []
    /// Keeps each store's remote-unlock mirror current; nil turns remote
    /// unlock off for this tier. See `NativeEncryptedFileProvider`.
    private let remoteUnlock: RemoteUnlockStore?
    /// Stores whose warm record was opened from a remote-unlock mirror; a
    /// write re-reads the Keychain record with its local context first.
    private var remotelyOpened: Set<String> = []
    /// Stores whose Keychain record is being moved; no other seal may land
    /// until that write seals its own record.
    private var mirrorWritesInFlight: [String: Int] = [:]
    /// Keeps each store's sealed backup bundle current; see
    /// `NativeEncryptedFileProvider`.
    private let backup: NativeStoreBackup?

    public init(
        keyBackend: NativeStoreKeyBackend,
        fileBackend: NativeStoreFileBackend,
        remoteUnlock: RemoteUnlockStore? = nil,
        backup: NativeStoreBackup? = nil
    ) {
        self.keyBackend = keyBackend
        self.fileBackend = fileBackend
        self.remoteUnlock = remoteUnlock
        self.backup = backup
    }

    /// Whether reading `store` now would need an unlock: its key record has
    /// neither been opened nor found absent in this daemon lifetime.
    public func requiresUnlock(store: NativeStoreName) -> Bool {
        records[store.value] == nil && !absentRecords.contains(store.value)
    }

    /// Whether a remote unlock opens `store`'s key record: it is warm, known
    /// absent, mirrored, or found (by its attributes, with no prompt) not to
    /// exist. Never opens a mirror or a record.
    public func canOpenWithRemoteUnlock(store: NativeStoreName) async -> Bool {
        if records[store.value] != nil || absentRecords.contains(store.value) { return true }
        guard let remoteUnlock, await remoteUnlock.isEnrolled() else { return false }
        if await remoteUnlock.exists(.nativeBlobs(store: store.value)) { return true }
        return (try? await keyBackend.recordExists(store: store.value)) == false
    }

    /// What this tier can say about `key` with no unlock: its warm index
    /// (metadata only; no blob is read) or, cold, whether the store exists at
    /// all. Pure: it opens no record and changes no warm state. See
    /// `NativeEncryptedFileProvider.presence(of:)`.
    func presence(store: NativeStoreName, key: String) async -> NativeTierPresence {
        if let record = records[store.value] {
            guard record.generation > 0 else { return .storeAbsent }
            guard let index = try? await loadIndex(store: store, record: record) else { return .unknown }
            return index.entries[key] != nil ? .present : .keyAbsent
        }
        if absentRecords.contains(store.value) { return .storeAbsent }
        return await NativeTierPresence.cold(store: store, keyBackend: keyBackend, fileBackend: fileBackend)
    }

    /// Mirror every blob store's key record, read with the one context
    /// enrollment spent. Warm state is left exactly as it was.
    public func backfillRemoteUnlockMirrors(localUnlock: CacheUnlock) async -> RemoteUnlockBackfillReport {
        var report = RemoteUnlockBackfillReport()
        guard let remoteUnlock, localUnlock.isLocal, await remoteUnlock.isEnrolled() else { return report }
        do {
            for name in Set(try await keyBackend.storeNames(unlock: localUnlock)).sorted() {
                do {
                    guard let store = try? NativeStoreName(name),
                          let record = try await keyBackend.load(store: store.value, unlock: localUnlock),
                          record.isValid else {
                        report.failed += 1
                        continue
                    }
                    if await sealMirror(store, record) { report.mirrored += 1 } else { report.failed += 1 }
                } catch {
                    report.failed += 1
                }
            }
        } catch {
            Self.logMirror("blob stores could not be listed for remote unlock (\(error))")
            report.failed += 1
        }
        return report
    }

    /// Open `store`'s key record with an evaluated context, or learn that it
    /// has none. A failure leaves the store cold.
    public func warm(store: NativeStoreName, unlock: CacheUnlock) async {
        _ = try? await existingRecord(for: store, unlock: unlock)
    }

    public func encryptedDirectoryPath() -> String { fileBackend.directoryPath }

    public struct PutRequest: Sendable {
        public let key: String
        public let data: Data
        public let mode: UInt16
        public let path: String
        public init(key: String, data: Data, mode: UInt16, path: String) {
            self.key = key
            self.data = data
            self.mode = mode
            self.path = path
        }
    }

    /// Import (or replace) a batch of blobs under one keychain bump. One Touch ID
    /// covers the whole batch, one index rewrite records them all, and the old
    /// index plus any replaced blob files are unlinked only after the new index
    /// and keychain pointer are durable.
    @discardableResult
    public func putBlobs(
        store: NativeStoreName,
        requests: [PutRequest],
        unlock: CacheUnlock?
    ) async throws -> UInt64 {
        // Writes move the Keychain record, which only a local context opens.
        guard let unlock, unlock.isLocal else { throw NativeStoreError.authenticationRequired }
        guard !requests.isEmpty else { throw NativeStoreError.invalidDocument }
        for request in requests {
            guard NativeStoreDocument.isValidKey(request.key),
                  !request.data.isEmpty,
                  request.data.count <= Self.maximumBlobBytes,
                  NativeBlobIndex.isSafeRelativePath(request.path) else {
                throw NativeStoreError.invalidDocument
            }
        }
        guard Set(requests.map(\.key)).count == requests.count else {
            throw NativeStoreError.invalidDocument
        }

        let record = try await recordForWrite(store: store, unlock: unlock)
        var index = record.generation > 0
            ? try await loadIndex(store: store, record: record)
            : (try NativeBlobIndex())

        guard record.generation < UInt64.max else { throw NativeStoreError.integrityFailure }

        var writtenBlobFiles: [String] = []
        var replacedBlobFiles: [String] = []
        do {
            for request in requests {
                if let existing = index.entries[request.key] {
                    replacedBlobFiles.append(Self.blobFileName(store: store, blobId: existing.blobId))
                }
                let blobId = try NativeStoreEnvelope.randomBytes(count: 16).hexString
                let ciphertext = try Self.sealBlob(
                    plaintext: request.data,
                    store: store,
                    keyData: record.keyData,
                    key: request.key,
                    blobId: blobId
                )
                let fileName = Self.blobFileName(store: store, blobId: blobId)
                try await fileBackend.writeAtomically(named: fileName, data: ciphertext)
                writtenBlobFiles.append(fileName)
                try index.set(request.key, NativeBlobEntry(
                    blobId: blobId,
                    digest: NativeStoreEnvelope.digest(ciphertext),
                    mode: request.mode,
                    size: request.data.count,
                    path: request.path
                ))
            }

            let generation = record.generation + 1
            let indexId = try NativeStoreEnvelope.randomBytes(count: 16).hexString
            let indexName = Self.indexFileName(store: store, fileID: indexId)
            let indexCiphertext = try Self.sealIndex(
                plaintext: try index.encoded(),
                store: store,
                keyData: record.keyData,
                generation: generation,
                fileID: indexId
            )
            let updated = NativeStoreKeyRecord(
                keyData: record.keyData,
                generation: generation,
                activeFileID: indexId,
                ciphertextDigest: NativeStoreEnvelope.digest(indexCiphertext)
            )
            guard updated.isValid else { throw NativeStoreError.integrityFailure }

            try await fileBackend.writeAtomically(named: indexName, data: indexCiphertext)
            mirrorWritesInFlight[store.value, default: 0] += 1
            do {
                try await removeMirrorBeforeWrite(store)
                try await keyBackend.update(store: store.value, record: updated, unlock: unlock)
            } catch {
                endMirrorWrite(store)
                await fileBackend.delete(named: indexName)
                throw NativeStoreError.keyUnavailable
            }

            records[store.value] = updated
            remotelyOpened.remove(store.value)
            endMirrorWrite(store)
            await sealMirror(store, updated)
            if let oldIndexID = record.activeFileID {
                await fileBackend.delete(named: Self.indexFileName(store: store, fileID: oldIndexID))
            }
            for replaced in replacedBlobFiles {
                await fileBackend.delete(named: replaced)
            }
            await backUp(store, updated, index: index)
            return generation
        } catch {
            // A failure before the keychain pointer moved leaves the old index
            // authoritative; unlink the now-unreferenced new blob files.
            for orphan in writtenBlobFiles { await fileBackend.delete(named: orphan) }
            throw error
        }
    }

    public func loadBlob(
        store: NativeStoreName,
        key: String,
        unlock: CacheUnlock?
    ) async throws -> NativeBlobRecord {
        guard let record = try await existingRecord(for: store, unlock: unlock),
              record.generation > 0 else {
            throw NativeStoreError.storeNotFound
        }
        let index = try await loadIndex(store: store, record: record)
        guard let entry = index.entries[key] else {
            throw NativeStoreError.secretNotFound
        }
        let fileName = Self.blobFileName(store: store, blobId: entry.blobId)
        let ciphertext: Data
        do {
            guard let data = try await fileBackend.read(named: fileName) else {
                throw NativeStoreError.integrityFailure
            }
            ciphertext = data
        } catch let error as NativeStoreError {
            throw error
        } catch {
            throw NativeStoreError.filesystemFailure
        }
        guard NativeStoreEnvelope.digest(ciphertext) == entry.digest else {
            throw NativeStoreError.integrityFailure
        }
        let plaintext = try Self.openBlob(
            ciphertext: ciphertext,
            store: store,
            keyData: record.keyData,
            key: key,
            blobId: entry.blobId
        )
        guard plaintext.count == entry.size else { throw NativeStoreError.integrityFailure }
        return NativeBlobRecord(data: plaintext, mode: entry.mode, path: entry.path)
    }

    /// Metadata-only listing (no plaintext), for `csec` status/inspection.
    public func list(store: NativeStoreName, unlock: CacheUnlock?) async throws -> [String: NativeBlobEntry] {
        guard let record = try await existingRecord(for: store, unlock: unlock),
              record.generation > 0 else {
            return [:]
        }
        return try await loadIndex(store: store, record: record).entries
    }

    public func removeBlobs(
        store: NativeStoreName,
        keys: [String],
        unlock: CacheUnlock?
    ) async throws -> UInt64 {
        guard let unlock, unlock.isLocal else { throw NativeStoreError.authenticationRequired }
        guard let record = try await recordForLocalWrite(for: store, unlock: unlock),
              record.generation > 0 else {
            throw NativeStoreError.storeNotFound
        }
        var index = try await loadIndex(store: store, record: record)
        var removedBlobFiles: [String] = []
        var mutated = false
        for key in Set(keys) {
            if let entry = index.entries[key] {
                removedBlobFiles.append(Self.blobFileName(store: store, blobId: entry.blobId))
                var next = index.entries
                next.removeValue(forKey: key)
                index = try NativeBlobIndex(entries: next)
                mutated = true
            }
        }
        guard mutated else { return record.generation }
        guard record.generation < UInt64.max else { throw NativeStoreError.integrityFailure }

        let generation = record.generation + 1
        let indexId = try NativeStoreEnvelope.randomBytes(count: 16).hexString
        let indexName = Self.indexFileName(store: store, fileID: indexId)
        let indexCiphertext = try Self.sealIndex(
            plaintext: try index.encoded(),
            store: store,
            keyData: record.keyData,
            generation: generation,
            fileID: indexId
        )
        let updated = NativeStoreKeyRecord(
            keyData: record.keyData,
            generation: generation,
            activeFileID: indexId,
            ciphertextDigest: NativeStoreEnvelope.digest(indexCiphertext)
        )
        guard updated.isValid else { throw NativeStoreError.integrityFailure }
        try await fileBackend.writeAtomically(named: indexName, data: indexCiphertext)
        mirrorWritesInFlight[store.value, default: 0] += 1
        do {
            try await removeMirrorBeforeWrite(store)
            try await keyBackend.update(store: store.value, record: updated, unlock: unlock)
        } catch {
            endMirrorWrite(store)
            await fileBackend.delete(named: indexName)
            throw NativeStoreError.keyUnavailable
        }
        records[store.value] = updated
        remotelyOpened.remove(store.value)
        endMirrorWrite(store)
        await sealMirror(store, updated)
        if let oldIndexID = record.activeFileID {
            await fileBackend.delete(named: Self.indexFileName(store: store, fileID: oldIndexID))
        }
        for removed in removedBlobFiles { await fileBackend.delete(named: removed) }
        await backUp(store, updated, index: index)
        return generation
    }

    // MARK: - record + index

    private func recordForWrite(
        store: NativeStoreName,
        unlock: CacheUnlock
    ) async throws -> NativeStoreKeyRecord {
        if let existing = try await recordForLocalWrite(for: store, unlock: unlock) {
            return existing
        }
        // No key record: only adopt the name if no ciphertext files linger, so a
        // damaged/invalidated store or a same-UID attacker's planted files can
        // never be silently reinitialized under a fresh key.
        guard !(await fileBackend.hasFiles(for: store.value)) else {
            throw NativeStoreError.keyUnavailable
        }
        let fresh = NativeStoreKeyRecord(keyData: try NativeStoreEnvelope.randomBytes(count: 32))
        do {
            try await keyBackend.create(store: store.value, record: fresh)
        } catch {
            throw NativeStoreError.keyUnavailable
        }
        records[store.value] = fresh
        absentRecords.remove(store.value)
        await sealMirror(store, fresh)
        return fresh
    }

    private func existingRecord(
        for store: NativeStoreName,
        unlock: CacheUnlock?
    ) async throws -> NativeStoreKeyRecord? {
        if let record = records[store.value] { return record }
        if absentRecords.contains(store.value) { return nil }
        guard let unlock else { throw NativeStoreError.authenticationRequired }
        if let remote = unlock.remote {
            return try await remotelyOpenedRecord(for: store, remote: remote)
        }
        return try await locallyLoadedRecord(for: store, unlock: unlock)
    }

    /// The Keychain record itself, read with a local context, made warm, and
    /// sealed to its remote-unlock mirror when remote unlock is enrolled.
    private func locallyLoadedRecord(
        for store: NativeStoreName,
        unlock: CacheUnlock
    ) async throws -> NativeStoreKeyRecord? {
        do {
            guard let record = try await keyBackend.load(store: store.value, unlock: unlock) else {
                absentRecords.insert(store.value)
                return nil
            }
            guard record.isValid else { throw NativeStoreError.keyUnavailable }
            records[store.value] = record
            remotelyOpened.remove(store.value)
            await sealMirror(store, record)
            await backUp(store, record)
            return record
        } catch let error as NativeStoreError {
            throw error
        } catch {
            throw NativeStoreError.keyUnavailable
        }
    }

    /// The record opened from its remote-unlock mirror, held to exactly the
    /// Keychain record's checks (`isValid`, then `loadIndex`'s pointer and
    /// ciphertext checks) before it is made warm. With no mirror, a store
    /// whose record does not exist needs nothing opened; any other store
    /// still needs a local touch. Never creates or replaces a store.
    private func remotelyOpenedRecord(
        for store: NativeStoreName,
        remote: RemoteUnlockKey
    ) async throws -> NativeStoreKeyRecord? {
        let payload: Data?
        do {
            payload = try await remote.open(.nativeBlobs(store: store.value))
        } catch RemoteUnlockStoreError.unlockInvalidated {
            throw NativeStoreError.authenticationRequired
        } catch {
            throw NativeStoreError.keyUnavailable
        }
        guard let payload else {
            if (try? await keyBackend.recordExists(store: store.value)) == false {
                absentRecords.insert(store.value)
                return nil
            }
            throw NativeStoreError.authenticationRequired
        }
        guard let record = try? JSONDecoder().decode(NativeStoreKeyRecord.self, from: payload),
              record.isValid else {
            throw NativeStoreError.keyUnavailable
        }
        if record.generation > 0 {
            _ = try await loadIndex(store: store, record: record)
        }
        if let current = records[store.value] { return current }
        records[store.value] = record
        remotelyOpened.insert(store.value)
        return record
    }

    /// The record a write starts from: one opened from a mirror is re-read
    /// from the Keychain with the write's local context first.
    private func recordForLocalWrite(
        for store: NativeStoreName,
        unlock: CacheUnlock
    ) async throws -> NativeStoreKeyRecord? {
        guard remotelyOpened.contains(store.value) else {
            return try await existingRecord(for: store, unlock: unlock)
        }
        let reloaded = try await locallyLoadedRecord(for: store, unlock: unlock)
        if reloaded == nil {
            records[store.value] = nil
            remotelyOpened.remove(store.value)
        }
        return reloaded
    }

    /// See `NativeEncryptedFileProvider.sealMirror`: skipped while the record
    /// is being moved, and re-sealed if the warm record changed meanwhile.
    @discardableResult
    private func sealMirror(_ store: NativeStoreName, _ record: NativeStoreKeyRecord) async -> Bool {
        guard let remoteUnlock, mirrorWritesInFlight[store.value, default: 0] == 0 else { return false }
        do {
            var sealed = record
            var stored = try await remoteUnlock.sealAndStore(
                .nativeBlobs(store: store.value), payload: try JSONEncoder().encode(sealed)
            )
            while stored, mirrorWritesInFlight[store.value, default: 0] == 0,
                  !remotelyOpened.contains(store.value),
                  let current = records[store.value], current != sealed {
                sealed = current
                stored = try await remoteUnlock.sealAndStore(
                    .nativeBlobs(store: store.value), payload: try JSONEncoder().encode(sealed)
                )
            }
            return stored
        } catch {
            Self.logMirror("blob store \(store) not mirrored for remote unlock (\(error))")
            return false
        }
    }

    private func endMirrorWrite(_ store: NativeStoreName) {
        let remaining = mirrorWritesInFlight[store.value, default: 1] - 1
        mirrorWritesInFlight[store.value] = remaining > 0 ? remaining : nil
    }

    /// The mirror goes before the Keychain record moves, and is sealed again
    /// after (see `NativeEncryptedFileProvider.removeMirrorBeforeWrite`).
    private func removeMirrorBeforeWrite(_ store: NativeStoreName) async throws {
        guard let remoteUnlock else { return }
        try await remoteUnlock.remove(.nativeBlobs(store: store.value))
    }

    private static func logMirror(_ message: String) {
        FileHandle.standardError.write(Data("csecd: native store: \(message)\n".utf8))
    }

    // MARK: - Backup

    /// Hand the backup a bundle of `record`, its index and every blob the
    /// index pins, when the last bundle for this store is older. The files
    /// are read as they are and only checked against their digests; the
    /// index is opened (with the record's key, already in hand) to learn
    /// which blobs it names. See `NativeEncryptedFileProvider.backUp`.
    @discardableResult
    private func backUp(
        _ store: NativeStoreName,
        _ record: NativeStoreKeyRecord,
        index knownIndex: NativeBlobIndex? = nil
    ) async -> NativeStoreBackupOutcome {
        guard let backup else { return .off }
        guard await backup.needsBundle(tier: .blobs, store: store, record: record) else { return .current }
        do {
            guard let fileID = record.activeFileID else { throw NativeStoreError.integrityFailure }
            let indexName = Self.indexFileName(store: store, fileID: fileID)
            guard let indexCiphertext = try await fileBackend.read(named: indexName),
                  NativeStoreEnvelope.digest(indexCiphertext) == record.ciphertextDigest else {
                throw NativeStoreError.integrityFailure
            }
            let index: NativeBlobIndex
            if let knownIndex { index = knownIndex } else { index = try await loadIndex(store: store, record: record) }
            // Sized from the index before any blob is read: a store too large
            // for one bundle is refused without loading it into memory, and is
            // not tried again until it changes.
            let estimated = index.entries.values.reduce(indexCiphertext.count) { total, entry in
                total + entry.size + Self.backupOverheadPerBlob
            }
            guard estimated <= backup.maximumBundleBytes else {
                await backup.recordFailure(
                    .store(.blobs, store), generation: record.generation,
                    reason: NativeStoreBackupError.bundleTooLarge.boundedReason, permanent: true
                )
                return .failed
            }
            var files = [indexName: indexCiphertext]
            for entry in index.entries.values {
                let name = Self.blobFileName(store: store, blobId: entry.blobId)
                guard let ciphertext = try await fileBackend.read(named: name),
                      NativeStoreEnvelope.digest(ciphertext) == entry.digest else {
                    throw NativeStoreError.integrityFailure
                }
                files[name] = ciphertext
            }
            return await backup.write(.store(
                .blobs, store, record: record, files: files, createdAt: Date()
            ))
        } catch {
            await backup.recordFailure(
                .store(.blobs, store), generation: record.generation,
                reason: (error as? NativeStoreError)?.boundedReason ?? "the store's files could not be read"
            )
            return .failed
        }
    }

    /// A blob's envelope (magic, ID, nonce, tag) and its bundle framing.
    static let backupOverheadPerBlob = 8 + 16 + 28 + 64

    /// Every blob store's bundle brought up to date with the one context
    /// spent; warm state is left exactly as it was.
    public func backfillBackups(localUnlock: CacheUnlock) async -> NativeStoreBackupReport {
        var report = NativeStoreBackupReport()
        guard backup != nil, localUnlock.isLocal else { return report }
        do {
            for name in Set(try await keyBackend.storeNames(unlock: localUnlock)).sorted() {
                guard let store = try? NativeStoreName(name),
                      let record = try? await keyBackend.load(store: store.value, unlock: localUnlock),
                      record.isValid else {
                    report.failed += 1
                    continue
                }
                guard record.generation > 0 else { continue }
                report.add(await backUp(store, record))
            }
        } catch {
            report.failed += 1
        }
        return report
    }

    /// Whether this tier holds `store`: an open record, or a Keychain record
    /// found by its attributes alone (no prompt). A lookup that cannot say
    /// counts as holding it, so a restore never writes over what it could not
    /// rule out. Files with no record (an interrupted restore) do not count.
    public func holdsStore(_ store: NativeStoreName) async -> Bool {
        if records[store.value] != nil { return true }
        return (try? await keyBackend.recordExists(store: store.value)) != false
    }

    /// Validate one blob store from a backup bundle without changing
    /// anything: the record must pin the index, the index must open under the
    /// record's key, and the bundle must hold exactly the blobs it names, each
    /// matching its digest. Returns how many blobs it holds.
    public nonisolated func inspectBackup(
        store: NativeStoreName,
        record: NativeStoreKeyRecord,
        files: [String: Data]
    ) throws -> Int {
        guard record.isValid, record.generation > 0, let fileID = record.activeFileID else {
            throw NativeStoreError.integrityFailure
        }
        let indexName = Self.indexFileName(store: store, fileID: fileID)
        guard let indexCiphertext = files[indexName],
              NativeStoreEnvelope.digest(indexCiphertext) == record.ciphertextDigest else {
            throw NativeStoreError.integrityFailure
        }
        let plaintext = try Self.openIndex(
            ciphertext: indexCiphertext, store: store, keyData: record.keyData,
            generation: record.generation, fileID: fileID
        )
        guard let index = try? NativeBlobIndex(data: plaintext) else { throw NativeStoreError.integrityFailure }
        var expected: Set<String> = [indexName]
        for entry in index.entries.values {
            let name = Self.blobFileName(store: store, blobId: entry.blobId)
            guard let ciphertext = files[name], NativeStoreEnvelope.digest(ciphertext) == entry.digest else {
                throw NativeStoreError.integrityFailure
            }
            expected.insert(name)
        }
        guard Set(files.keys) == expected else { throw NativeStoreError.integrityFailure }
        return index.entries.count
    }

    /// Put one blob store back from a backup bundle; see
    /// `NativeEncryptedFileProvider.restoreFromBackup`.
    public func restoreFromBackup(
        store: NativeStoreName,
        record: NativeStoreKeyRecord,
        files: [String: Data]
    ) async throws -> Int {
        let blobs = try inspectBackup(store: store, record: record, files: files)
        let written = try await NativeStoreBackupRestoration.writeFiles(
            files, store: store, keyBackend: keyBackend, fileBackend: fileBackend,
            alreadyOpen: records[store.value] != nil
        )
        // A store created here while the files were being written wins.
        guard records[store.value] == nil else {
            for name in written { await fileBackend.delete(named: name) }
            throw NativeStoreBackupError.storeExists
        }
        do {
            try await keyBackend.create(store: store.value, record: record)
        } catch {
            for name in written { await fileBackend.delete(named: name) }
            throw (try? await keyBackend.recordExists(store: store.value)) == true
                ? NativeStoreBackupError.storeExists : NativeStoreError.filesystemFailure
        }
        records[store.value] = record
        absentRecords.remove(store.value)
        await sealMirror(store, record)
        await backUp(store, record)
        return blobs
    }

    private func loadIndex(
        store: NativeStoreName,
        record: NativeStoreKeyRecord
    ) async throws -> NativeBlobIndex {
        guard record.isValid,
              record.generation > 0,
              let fileID = record.activeFileID,
              let expectedDigest = record.ciphertextDigest else {
            throw NativeStoreError.integrityFailure
        }
        let indexName = Self.indexFileName(store: store, fileID: fileID)
        let ciphertext: Data
        do {
            guard let data = try await fileBackend.read(named: indexName) else {
                throw NativeStoreError.integrityFailure
            }
            ciphertext = data
        } catch let error as NativeStoreError {
            throw error
        } catch {
            throw NativeStoreError.filesystemFailure
        }
        guard NativeStoreEnvelope.digest(ciphertext) == expectedDigest else {
            throw NativeStoreError.integrityFailure
        }
        let plaintext = try Self.openIndex(
            ciphertext: ciphertext,
            store: store,
            keyData: record.keyData,
            generation: record.generation,
            fileID: fileID
        )
        do {
            return try NativeBlobIndex(data: plaintext)
        } catch {
            throw NativeStoreError.integrityFailure
        }
    }

    // MARK: - envelopes

    private static let indexMagic = Data("CSECBIX1".utf8)
    private static let blobMagic = Data("CSECBLB1".utf8)

    private static func sealIndex(
        plaintext: Data,
        store: NativeStoreName,
        keyData: Data,
        generation: UInt64,
        fileID: String
    ) throws -> Data {
        guard let fileIDData = Data(lowerHex: fileID) else { throw NativeStoreError.integrityFailure }
        let header = indexHeader(generation: generation, fileID: fileIDData)
        return try NativeStoreEnvelope.seal(
            plaintext: plaintext, key: keyData, header: header,
            aad: indexAAD(header: header, store: store)
        )
    }

    private static func openIndex(
        ciphertext: Data,
        store: NativeStoreName,
        keyData: Data,
        generation: UInt64,
        fileID: String
    ) throws -> Data {
        guard let fileIDData = Data(lowerHex: fileID) else { throw NativeStoreError.integrityFailure }
        let header = indexHeader(generation: generation, fileID: fileIDData)
        return try NativeStoreEnvelope.open(
            ciphertext: ciphertext, key: keyData, header: header,
            aad: indexAAD(header: header, store: store)
        )
    }

    private static func sealBlob(
        plaintext: Data,
        store: NativeStoreName,
        keyData: Data,
        key: String,
        blobId: String
    ) throws -> Data {
        guard let blobIdData = Data(lowerHex: blobId) else { throw NativeStoreError.integrityFailure }
        let header = blobMagic + blobIdData
        return try NativeStoreEnvelope.seal(
            plaintext: plaintext, key: keyData, header: header,
            aad: blobAAD(header: header, store: store, key: key)
        )
    }

    private static func openBlob(
        ciphertext: Data,
        store: NativeStoreName,
        keyData: Data,
        key: String,
        blobId: String
    ) throws -> Data {
        guard let blobIdData = Data(lowerHex: blobId) else { throw NativeStoreError.integrityFailure }
        let header = blobMagic + blobIdData
        return try NativeStoreEnvelope.open(
            ciphertext: ciphertext, key: keyData, header: header,
            aad: blobAAD(header: header, store: store, key: key)
        )
    }

    private static func indexHeader(generation: UInt64, fileID: Data) -> Data {
        var header = indexMagic
        header.appendUInt64(generation)
        header.append(fileID)
        return header
    }

    private static func indexAAD(header: Data, store: NativeStoreName) -> Data {
        var data = Data("csec-blob-index\0".utf8)
        data.append(header)
        data.append(0)
        data.append(Data(store.value.utf8))
        return data
    }

    private static func blobAAD(header: Data, store: NativeStoreName, key: String) -> Data {
        var data = Data("csec-blob\0".utf8)
        data.append(header)
        data.append(0)
        data.append(Data(store.value.utf8))
        data.append(0)
        data.append(Data(key.utf8))
        return data
    }

    private static func indexFileName(store: NativeStoreName, fileID: String) -> String {
        "\(store.value).\(fileID).index.csec"
    }

    private static func blobFileName(store: NativeStoreName, blobId: String) -> String {
        "\(store.value).\(blobId).blob.csec"
    }

    public static func defaultBlobDirectoryPath() -> String {
        (SecureNativeStoreFileBackend.defaultDirectoryPath() as NSString)
            .appendingPathComponent("Blobs")
    }
}
