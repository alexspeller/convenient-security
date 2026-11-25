import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// The store-origin marker: a `<store>.origin` file beside the store's
/// ciphertext, recording the canonical project root that claimed the store
/// name. The path sits in the envelope's *cleartext header* so default-name
/// resolution can read it with no unlock and no Touch ID, and the same bytes
/// are folded into the AEAD tag under the store's key, so the daemon detects
/// any tamper the next time it opens the store for an edit. A path is
/// metadata, never a secret value. The marker deliberately does not end in
/// `.csec`: it must not make `hasFiles(for:)` treat a name as holding
/// ciphertext.
public enum NativeStoreOriginMarker {
    public static let maximumOriginBytes = 1024
    /// Header magic + 2-byte length + path, followed by the sealed empty
    /// plaintext (12-byte nonce + 16-byte tag).
    private static let magic = Data("CSECORG1".utf8)
    private static let sealedOverhead = 28

    public static func fileName(store: NativeStoreName) -> String {
        "\(store.value).origin"
    }

    /// An origin is a canonical absolute directory path, bounded and NUL-free.
    public static func isValidOrigin(_ origin: String) -> Bool {
        origin.hasPrefix("/")
            && origin.utf8.count <= maximumOriginBytes
            && !origin.utf8.contains(0)
    }

    public static func sealed(
        origin: String,
        store: NativeStoreName,
        keyData: Data
    ) throws -> Data {
        guard let header = header(origin: origin) else {
            throw NativeStoreError.invalidDocument
        }
        return try NativeStoreEnvelope.seal(
            plaintext: Data(),
            key: keyData,
            header: header,
            aad: aad(header: header, store: store)
        )
    }

    /// Parse the cleartext origin path without any key. The result is
    /// *unverified* — callers may only use it to propose a default name the
    /// user reviews. `verifiedOrigin` is the authenticated read.
    public static func parseOrigin(fromCleartext data: Data) -> String? {
        let bytes = [UInt8](data)
        let lengthOffset = magic.count
        guard bytes.count >= lengthOffset + 2,
              Data(bytes.prefix(magic.count)) == magic else { return nil }
        let length = Int(bytes[lengthOffset]) << 8 | Int(bytes[lengthOffset + 1])
        let pathOffset = lengthOffset + 2
        guard length > 0,
              length <= maximumOriginBytes,
              bytes.count >= pathOffset + length + sealedOverhead else { return nil }
        let origin = String(decoding: bytes[pathOffset..<(pathOffset + length)], as: UTF8.self)
        guard isValidOrigin(origin), Data(origin.utf8).count == length else { return nil }
        return origin
    }

    /// The authenticated read: reconstruct the header from the parsed cleartext
    /// and require the AEAD tag to verify under the store's key. Nil means the
    /// marker is absent in meaning — unparseable, sealed for another store, or
    /// tampered with since it was stamped.
    public static func verifiedOrigin(
        data: Data,
        store: NativeStoreName,
        keyData: Data
    ) -> String? {
        guard let origin = parseOrigin(fromCleartext: data),
              let header = header(origin: origin),
              let plaintext = try? NativeStoreEnvelope.open(
                  ciphertext: data,
                  key: keyData,
                  header: header,
                  aad: aad(header: header, store: store)
              ),
              plaintext.isEmpty else { return nil }
        return origin
    }

    private static func header(origin: String) -> Data? {
        guard isValidOrigin(origin) else { return nil }
        let pathBytes = Data(origin.utf8)
        var header = magic
        header.append(UInt8(pathBytes.count >> 8))
        header.append(UInt8(pathBytes.count & 0xff))
        header.append(pathBytes)
        return header
    }

    private static func aad(header: Data, store: NativeStoreName) -> Data {
        var data = Data("csec-store-origin\0".utf8)
        data.append(header)
        data.append(0)
        data.append(Data(store.value.utf8))
        return data
    }
}

/// Production `NativeStoreNameIndexing`: a point-in-time snapshot of the store
/// names present in the document- and blob-tier ciphertext directories, plus
/// each name's cleartext origin marker. Runs in the launcher with no daemon
/// round-trip, no unlock, and no Touch ID — both processes are the same user
/// and the directories are 0700 ciphertext-only. Snapshot semantics are
/// intentional: resolution is advisory, and the daemon re-verifies the marker
/// under the store key before any mutation.
public struct NativeStoreDirectoryIndex: NativeStoreNameIndexing {
    private let names: Set<String>
    private let origins: [String: String]

    public init(
        documentDirectory: String = SecureNativeStoreFileBackend.defaultDirectoryPath(),
        blobDirectory: String = NativeBlobStore.defaultBlobDirectoryPath()
    ) {
        var names: Set<String> = []
        var origins: [String: String] = [:]
        for directory in [documentDirectory, blobDirectory] {
            let entries = (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []
            for entry in entries {
                guard let separator = entry.firstIndex(of: ".") else { continue }
                let name = String(entry[entry.startIndex..<separator])
                guard !name.isEmpty else { continue }
                let rest = String(entry[entry.index(after: separator)...])
                if rest == "origin" {
                    names.insert(name)
                    if origins[name] == nil,
                       let data = Self.readMarker(
                           directory: directory, fileName: entry),
                       let origin = NativeStoreOriginMarker.parseOrigin(fromCleartext: data) {
                        origins[name] = origin
                    }
                } else if rest.hasSuffix("csec") {
                    names.insert(name)
                }
            }
        }
        self.names = names
        self.origins = origins
    }

    public func storeExists(_ name: String) -> Bool { names.contains(name) }
    public func origin(forStore name: String) -> String? { origins[name] }

    /// Bounded, symlink-refusing, owner-checked read of one marker file. The
    /// content is ciphertext-plus-cleartext-header either way; the hardening
    /// only keeps this read from being redirected or fed a giant file.
    private static func readMarker(directory: String, fileName: String) -> Data? {
        let maximumMarkerBytes = 4096
        let path = (directory as NSString).appendingPathComponent(fileName)
        let fd = path.withCString {
            open($0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        }
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0,
              (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == getuid(),
              info.st_size > 0,
              info.st_size <= maximumMarkerBytes else { return nil }
        var bytes = [UInt8](repeating: 0, count: Int(info.st_size))
        var offset = 0
        let totalBytes = bytes.count
        while offset < totalBytes {
            let count = bytes.withUnsafeMutableBytes { raw in
                read(fd, raw.baseAddress!.advanced(by: offset), totalBytes - offset)
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else { return nil }
            offset += count
        }
        return Data(bytes)
    }
}
