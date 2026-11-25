import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Display-only names from public OpenSSH host-key metadata. Reverse matching a
/// verified key can give the human useful context, but it cannot prove which
/// name was used for this connection when keys are shared. Names never enter a
/// grant, a policy decision, or provider resolution.
public struct SSHKnownHostsLookup: Sendable {
    // Long-lived known_hosts files readily exceed 2 MiB. Keep reads bounded
    // without discarding ordinary host catalogs before looking for a match.
    private static let maximumFileBytes = 16 * 1_024 * 1_024
    private static let maximumNames = 8
    private static let maximumNameBytes = 160

    private let lookup: @Sendable (String) -> [String]

    public init(lookup: @escaping @Sendable (String) -> [String]) {
        self.lookup = lookup
    }

    public func names(matchingHostKeyFingerprint fingerprint: String) -> [String] {
        Self.safeNames(lookup(fingerprint))
    }

    public static let live = SSHKnownHostsLookup { fingerprint in
        #if os(macOS)
        return matchingNames(inFiles: standardPaths(), hostKeyFingerprint: fingerprint)
        #else
        return []
        #endif
    }

    /// The same bounded public-metadata lookup used by `live`, with explicit
    /// file paths for synthetic checks. No SSH configuration is executed.
    public static func matchingNames(
        inFiles paths: [String], hostKeyFingerprint fingerprint: String
    ) -> [String] {
        #if os(macOS)
        var names: [String] = []
        for path in paths.prefix(4) {
            guard let document = readBoundedRegularFile(at: path) else { continue }
            names.append(contentsOf: matchingNames(
                in: document, hostKeyFingerprint: fingerprint
            ))
        }
        return safeNames(names)
        #else
        return []
        #endif
    }

    /// Public for the framework-free synthetic security checks. Marked,
    /// negated, hashed, and wildcard host patterns are deliberately omitted:
    /// none supplies a concrete name that is safe to present as connection
    /// context during a one-tap approval.
    public static func matchingNames(
        in document: Data,
        hostKeyFingerprint fingerprint: String
    ) -> [String] {
        let text = String(decoding: document, as: UTF8.self)
        var names: [String] = []
        for line in text.split(whereSeparator: \.isNewline) {
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count >= 3,
                  !fields[0].hasPrefix("#"),
                  !fields[0].hasPrefix("@"),
                  fields[1].utf8.count <= 128,
                  fields[2].utf8.count <= 24 * 1_024,
                  let keyBlob = Data(base64Encoded: String(fields[2])),
                  keyBlob.count <= 16 * 1_024 else { continue }

            var keyReader = SSHWireReader(keyBlob)
            guard let embeddedAlgorithm = try? keyReader.readUTF8(maximumBytes: 128),
                  embeddedAlgorithm == fields[1],
                  let key = try? SSHPublicKey.parseHostKey(keyBlob),
                  key.fingerprint == fingerprint else { continue }

            for field in fields[0].split(separator: ",") {
                names.append(String(field))
            }
        }
        return safeNames(names)
    }

    static func safeNames(_ candidates: [String]) -> [String] {
        var result: [String] = []
        var seen = Set<String>()
        for candidate in candidates {
            guard !candidate.isEmpty,
                  !candidate.hasPrefix("|"),
                  !candidate.hasPrefix("!"),
                  !candidate.contains("*"),
                  !candidate.contains("?"),
                  !candidate.contains("/"),
                  candidate.utf8.count <= maximumNameBytes,
                  ReviewDisplay.sanitized(candidate) == candidate,
                  seen.insert(candidate).inserted else { continue }
            result.append(candidate)
            if result.count == maximumNames { break }
        }
        return result
    }

    #if os(macOS)
    private static func standardPaths() -> [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return [
            home.appendingPathComponent(".ssh/known_hosts").path,
            home.appendingPathComponent(".ssh/known_hosts2").path,
            "/etc/ssh/ssh_known_hosts",
            "/etc/ssh/ssh_known_hosts2",
        ]
    }

    private static func readBoundedRegularFile(at path: String) -> Data? {
        let descriptor = Darwin.open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK)
        guard descriptor >= 0 else { return nil }
        defer { Darwin.close(descriptor) }

        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_size >= 0,
              metadata.st_size <= maximumFileBytes else { return nil }

        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: false)
        guard let data = try? handle.read(upToCount: maximumFileBytes + 1),
              data.count <= maximumFileBytes else { return nil }
        return data
    }
    #endif
}
