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

    public init(keyBackend: NativeStoreKeyBackend, fileBackend: NativeStoreFileBackend) {
        self.keyBackend = keyBackend
        self.fileBackend = fileBackend
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
        guard let unlock else { throw NativeStoreError.authenticationRequired }
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
            do {
                try await keyBackend.update(store: store.value, record: updated, unlock: unlock)
            } catch {
                await fileBackend.delete(named: indexName)
                throw NativeStoreError.keyUnavailable
            }

            records[store.value] = updated
            if let oldIndexID = record.activeFileID {
                await fileBackend.delete(named: Self.indexFileName(store: store, fileID: oldIndexID))
            }
            for replaced in replacedBlobFiles {
                await fileBackend.delete(named: replaced)
            }
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
        guard let unlock else { throw NativeStoreError.authenticationRequired }
        guard let record = try await existingRecord(for: store, unlock: unlock),
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
        do {
            try await keyBackend.update(store: store.value, record: updated, unlock: unlock)
        } catch {
            await fileBackend.delete(named: indexName)
            throw NativeStoreError.keyUnavailable
        }
        records[store.value] = updated
        if let oldIndexID = record.activeFileID {
            await fileBackend.delete(named: Self.indexFileName(store: store, fileID: oldIndexID))
        }
        for removed in removedBlobFiles { await fileBackend.delete(named: removed) }
        return generation
    }

    // MARK: - record + index

    private func recordForWrite(
        store: NativeStoreName,
        unlock: CacheUnlock
    ) async throws -> NativeStoreKeyRecord {
        if let existing = try await existingRecord(for: store, unlock: unlock) {
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
        return fresh
    }

    private func existingRecord(
        for store: NativeStoreName,
        unlock: CacheUnlock?
    ) async throws -> NativeStoreKeyRecord? {
        if let record = records[store.value] { return record }
        guard let unlock else { throw NativeStoreError.authenticationRequired }
        do {
            guard let record = try await keyBackend.load(store: store.value, unlock: unlock) else {
                return nil
            }
            guard record.isValid else { throw NativeStoreError.keyUnavailable }
            records[store.value] = record
            return record
        } catch let error as NativeStoreError {
            throw error
        } catch {
            throw NativeStoreError.keyUnavailable
        }
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
