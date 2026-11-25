import CryptoKit
import Foundation

/// The release signing keys this build trusts, as OpenSSH public-key lines
/// (`ssh-ed25519 AAAA… comment`). A manifest counts only when one of these
/// signed it. Each key is the public half of a key that never leaves its
/// signing service (docs/release-manifest.md, "Signing"); a new key reaches
/// buyers only inside a release signed by one they already trust.
///
/// Empty means this build has no release key yet: csecd then checks for
/// nothing, and `csec doctor` says the update check is off.
public enum ReleaseSigningKeys {
    public static let pinned: [String] = []
}

/// SSH signatures (`ssh-keygen -Y sign`, OpenSSH's PROTOCOL.sshsig) over a
/// whole file, Ed25519 keys only. csec uses OpenSSH's format, not one of its
/// own, so anyone can check a manifest with stock tools:
///
///     ssh-keygen -Y verify -f allowed_signers -I csec-release \
///       -n release-manifest@convenientsecurity.app -s manifest.json.sig < manifest.json
public enum SSHFileSignature {
    public enum Failure: Error, Equatable, Sendable {
        case malformed
        case unsupportedVersion
        case unsupportedKey
        case wrongNamespace
        case unsupportedHash
        case untrustedKey
        case badSignature
        case noTrustedKeys

        /// Short, value-free text for logs and `csec doctor`.
        public var summary: String {
            switch self {
            case .malformed: return "the signature is not an SSH signature"
            case .unsupportedVersion: return "the SSH signature version is not supported"
            case .unsupportedKey: return "the signature's key is not Ed25519"
            case .wrongNamespace: return "the signature is for a different purpose (namespace)"
            case .unsupportedHash: return "the signature's hash algorithm is not supported"
            case .untrustedKey: return "the signature's key is not a pinned release key"
            case .badSignature: return "the signature does not match the manifest"
            case .noTrustedKeys: return "this build pins no release signing key"
            }
        }
    }

    private static let magic = Data("SSHSIG".utf8)
    private static let armorBegin = "-----BEGIN SSH SIGNATURE-----"
    private static let armorEnd = "-----END SSH SIGNATURE-----"

    /// Verifies `armored` over `message` for `namespace`, accepting only a key
    /// whose public blob equals one of `trustedKeys`' blobs. Returns the
    /// trusted key line that signed it.
    public static func verify(
        message: Data,
        armored: String,
        namespace: String,
        trustedKeys: [String]
    ) -> Result<String, Failure> {
        let trusted = trustedKeys.compactMap { line in publicKeyBlob(line).map { (line, $0) } }
        guard !trusted.isEmpty else { return .failure(.noTrustedKeys) }
        guard let blob = dearmor(armored) else { return .failure(.malformed) }
        var reader = Reader(blob)
        guard reader.bytes(magic.count) == magic,
              let version = reader.uint32() else { return .failure(.malformed) }
        guard version == 1 else { return .failure(.unsupportedVersion) }
        guard let keyBlob = reader.string(),
              let signedNamespace = reader.string(),
              let reserved = reader.string(),
              let hashName = reader.string(),
              let signatureBlob = reader.string(),
              reader.isAtEnd else { return .failure(.malformed) }

        var keyReader = Reader(keyBlob)
        guard keyReader.string() == Data("ssh-ed25519".utf8),
              let rawKey = keyReader.string(), rawKey.count == 32, keyReader.isAtEnd
        else { return .failure(.unsupportedKey) }
        guard signedNamespace == Data(namespace.utf8) else { return .failure(.wrongNamespace) }

        let digest: Data
        switch String(decoding: hashName, as: UTF8.self) {
        case "sha512": digest = Data(SHA512.hash(data: message))
        case "sha256": digest = Data(SHA256.hash(data: message))
        default: return .failure(.unsupportedHash)
        }
        guard let signer = trusted.first(where: { $0.1 == keyBlob }) else { return .failure(.untrustedKey) }

        var signatureReader = Reader(signatureBlob)
        guard signatureReader.string() == Data("ssh-ed25519".utf8),
              let rawSignature = signatureReader.string(), rawSignature.count == 64,
              signatureReader.isAtEnd,
              let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: rawKey)
        else { return .failure(.badSignature) }

        var signed = magic
        appendString(&signed, signedNamespace)
        appendString(&signed, reserved)
        appendString(&signed, hashName)
        appendString(&signed, digest)
        guard publicKey.isValidSignature(rawSignature, for: signed) else { return .failure(.badSignature) }
        return .success(signer.0)
    }

    /// The wire blob of an `ssh-ed25519 BASE64 [comment]` line; nil for any
    /// other key type or a blob whose type does not match its label.
    public static func publicKeyBlob(_ line: String) -> Data? {
        let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
        guard fields.count >= 2, fields[0] == "ssh-ed25519",
              let blob = Data(base64Encoded: String(fields[1])) else { return nil }
        var reader = Reader(blob)
        guard reader.string() == Data("ssh-ed25519".utf8),
              let raw = reader.string(), raw.count == 32, reader.isAtEnd else { return nil }
        return blob
    }

    private static func dearmor(_ text: String) -> Data? {
        let lines = text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard lines.count >= 3, lines.first == armorBegin, lines.last == armorEnd else { return nil }
        return Data(base64Encoded: lines.dropFirst().dropLast().joined())
    }

    private static func appendString(_ data: inout Data, _ value: Data) {
        var length = UInt32(value.count).bigEndian
        withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
        data.append(value)
    }

    private struct Reader {
        private let data: Data
        private var offset: Int

        init(_ data: Data) {
            self.data = Data(data)
            offset = 0
        }

        var isAtEnd: Bool { offset == data.count }

        mutating func bytes(_ count: Int) -> Data? {
            guard count >= 0, data.count - offset >= count else { return nil }
            defer { offset += count }
            return data.subdata(in: offset..<(offset + count))
        }

        mutating func uint32() -> UInt32? {
            guard let raw = bytes(4) else { return nil }
            return raw.reduce(0) { ($0 << 8) | UInt32($1) }
        }

        mutating func string() -> Data? {
            guard let length = uint32(), length <= 1_048_576 else { return nil }
            return bytes(Int(length))
        }
    }
}

/// The signed release manifest: one small JSON document csec fetches from a
/// fixed address, signed as a whole by a pinned release key
/// (`SSHFileSignature`). It announces the newest package; sections other
/// releases add (the audited Claude Code list) sit beside `release` and are
/// ignored by a build that does not know them.
public struct ReleaseManifest: Sendable, Equatable {
    public static let namespace = "release-manifest@convenientsecurity.app"
    public static let manifestURL = URL(string: "https://convenientsecurity.app/releases/manifest.json")!
    public static let signatureURL = URL(string: "https://convenientsecurity.app/releases/manifest.json.sig")!
    /// Both files are a few hundred bytes; anything larger is not a manifest.
    public static let maximumBytes = 256 * 1024

    public struct Release: Sendable, Equatable {
        public let build: ReleaseBuild
        /// Where a person downloads the package: an https page, never fetched
        /// by csec, only shown.
        public let download: URL

        public init(build: ReleaseBuild, download: URL) {
            self.build = build
            self.download = download
        }
    }

    /// Claude Code images whose settings loader has been checked against
    /// csec's gate since this build was compiled (`claude_code.checked`).
    /// They only add to `ClaudeBuildVerification.shipped`: a manifest can
    /// never withdraw a compiled record. Each is an exact host-slice code
    /// directory hash; the version is a label for people.
    public struct ClaudeCodeBuild: Sendable, Equatable {
        public let cdHash: String
        public let version: String

        public init(cdHash: String, version: String) {
            self.cdHash = cdHash
            self.version = version
        }

        /// A version label is short printable ASCII: it reaches panels and
        /// `csec doctor`, so nothing else is accepted from the manifest.
        static func isVersionLabel(_ text: String) -> Bool {
            !text.isEmpty && text.utf8.count <= ClaudeBuildSummary.maximumVersionLabelBytes
                && text.unicodeScalars.allSatisfy {
                    $0.isASCII && (CharacterSet.alphanumerics.contains($0) || ".-+_".unicodeScalars.contains($0))
                }
        }
    }

    /// Grows with every manifest published. csec refuses one numbered below
    /// the copy it holds, so an old signed manifest replayed later cannot
    /// hide a newer release.
    public let sequence: Int
    public let release: Release?
    public let claudeCode: [ClaudeCodeBuild]

    public init(sequence: Int, release: Release?, claudeCode: [ClaudeCodeBuild] = []) {
        self.sequence = sequence
        self.release = release
        self.claudeCode = claudeCode
    }

    public enum ParseFailure: Error, Equatable, Sendable {
        case notJSON
        case unsupportedSchema
        case invalid(String)

        public var summary: String {
            switch self {
            case .notJSON: return "the manifest is not a JSON object"
            case .unsupportedSchema: return "the manifest's schema is newer than this csec"
            case let .invalid(field): return "the manifest's \(field) is invalid"
            }
        }
    }

    private struct Wire: Decodable {
        struct Release: Decodable {
            let version: String
            let build: Int
            let download: String
        }
        struct ClaudeCode: Decodable {
            struct Build: Decodable {
                let cdhash: String
                let version: String
            }
            let checked: [Build]
        }
        let schema: Int
        let sequence: Int
        let release: Release?
        let claudeCode: ClaudeCode?

        enum CodingKeys: String, CodingKey {
            case schema, sequence, release
            case claudeCode = "claude_code"
        }
    }

    /// Parses schema 1 with strict types. Unknown keys are ignored so later
    /// sections can be added without breaking earlier builds.
    public static func parse(_ data: Data) -> Result<ReleaseManifest, ParseFailure> {
        guard (try? JSONSerialization.jsonObject(with: data)) is [String: Any] else {
            return .failure(.notJSON)
        }
        struct Schema: Decodable { let schema: Int }
        guard let schema = try? JSONDecoder().decode(Schema.self, from: data).schema else {
            return .failure(.invalid("schema"))
        }
        guard schema == 1 else { return .failure(.unsupportedSchema) }
        let wire: Wire
        do {
            wire = try JSONDecoder().decode(Wire.self, from: data)
        } catch let DecodingError.keyNotFound(key, context) {
            return .failure(.invalid(Self.field(context.codingPath + [key])))
        } catch let DecodingError.valueNotFound(_, context) {
            return .failure(.invalid(Self.field(context.codingPath)))
        } catch let DecodingError.typeMismatch(_, context) {
            return .failure(.invalid(Self.field(context.codingPath)))
        } catch let DecodingError.dataCorrupted(context) {
            return .failure(.invalid(Self.field(context.codingPath)))
        } catch {
            return .failure(.notJSON)
        }
        guard wire.sequence > 0 else { return .failure(.invalid("sequence")) }
        let claudeCode: [ClaudeCodeBuild]
        switch Self.claudeCode(wire.claudeCode) {
        case let .failure(failure): return .failure(failure)
        case let .success(builds): claudeCode = builds
        }
        guard let release = wire.release else {
            return .success(ReleaseManifest(sequence: wire.sequence, release: nil, claudeCode: claudeCode))
        }
        guard let version = ReleaseVersion(release.version) else { return .failure(.invalid("release version")) }
        guard release.build > 0 else { return .failure(.invalid("release build")) }
        guard release.download.count <= 200,
              release.download.unicodeScalars.allSatisfy({ $0.isASCII && $0.value > 0x20 && $0.value < 0x7F }),
              let download = URL(string: release.download),
              download.scheme == "https", download.host?.isEmpty == false
        else { return .failure(.invalid("release download address")) }
        return .success(ReleaseManifest(
            sequence: wire.sequence,
            release: Release(build: ReleaseBuild(version: version, build: release.build), download: download),
            claudeCode: claudeCode))
    }

    /// The whole section is refused for one bad entry, so a mistake in the
    /// list can never admit a partial or reinterpreted identity.
    private static func claudeCode(_ section: Wire.ClaudeCode?) -> Result<[ClaudeCodeBuild], ParseFailure> {
        guard let section else { return .success([]) }
        guard section.checked.count <= ClaudeBuildVerificationReport.maximumCheckedReleases else {
            return .failure(.invalid("claude_code checked"))
        }
        var seen = Set<String>()
        var builds: [ClaudeCodeBuild] = []
        for build in section.checked {
            guard WireField.isLowercaseHex(build.cdhash, length: 40), seen.insert(build.cdhash).inserted else {
                return .failure(.invalid("claude_code cdhash"))
            }
            guard ClaudeCodeBuild.isVersionLabel(build.version) else {
                return .failure(.invalid("claude_code version"))
            }
            builds.append(ClaudeCodeBuild(cdHash: build.cdhash, version: build.version))
        }
        return .success(builds)
    }

    private static func field(_ path: [CodingKey]) -> String {
        let names = path.map(\.stringValue).filter { !$0.isEmpty }
        return names.isEmpty ? "contents" : names.joined(separator: " ")
    }
}

/// A manifest whose signature verified against a pinned key, with the exact
/// bytes that were signed (so a later reader can verify them again).
public struct VerifiedReleaseManifest: Sendable, Equatable {
    public let manifest: ReleaseManifest
    public let bytes: Data
    public let signature: String

    public static func verify(
        bytes: Data, signature: String, trustedKeys: [String] = ReleaseSigningKeys.pinned
    ) -> Result<VerifiedReleaseManifest, ReleaseManifestFailure> {
        guard bytes.count <= ReleaseManifest.maximumBytes,
              signature.utf8.count <= ReleaseManifest.maximumBytes else { return .failure(.tooLarge) }
        switch SSHFileSignature.verify(
            message: bytes, armored: signature, namespace: ReleaseManifest.namespace, trustedKeys: trustedKeys) {
        case let .failure(failure): return .failure(.signature(failure))
        case .success: break
        }
        switch ReleaseManifest.parse(bytes) {
        case let .failure(failure): return .failure(.parse(failure))
        case let .success(manifest):
            return .success(VerifiedReleaseManifest(manifest: manifest, bytes: bytes, signature: signature))
        }
    }
}

public enum ReleaseManifestFailure: Error, Equatable, Sendable {
    case tooLarge
    case signature(SSHFileSignature.Failure)
    case parse(ReleaseManifest.ParseFailure)
    /// Signed, but numbered below the copy csec holds.
    case rollback(held: Int, offered: Int)
    /// Signed with the same number as the held copy but different contents.
    case conflictingSequence(Int)

    public var summary: String {
        switch self {
        case .tooLarge: return "the manifest is too large"
        case let .signature(failure): return failure.summary
        case let .parse(failure): return failure.summary
        case let .rollback(held, offered):
            return "the manifest offered (number \(offered)) is older than the one csec holds (number \(held))"
        case let .conflictingSequence(sequence):
            return "two different manifests are both numbered \(sequence)"
        }
    }
}

/// The last verified manifest and what the update check last did, kept as
/// plain files under `~/Library/Application Support/ConvenientSecurity/Updates`.
/// Nothing here is trusted as written: the manifest is verified again on every
/// read, so a file someone replaced only reads as absent. The check's state
/// file (times, last failure, the version already announced) is bookkeeping;
/// altering it can at worst repeat or suppress one notification.
public struct ReleaseManifestStore: Sendable {
    public let directory: URL
    public let trustedKeys: [String]

    public init(directory: URL = ReleaseManifestStore.defaultDirectory(),
                trustedKeys: [String] = ReleaseSigningKeys.pinned) {
        self.directory = directory
        self.trustedKeys = trustedKeys
    }

    public static func defaultDirectory() -> URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/ConvenientSecurity/Updates", isDirectory: true)
    }

    private var manifestPath: URL { directory.appendingPathComponent("manifest.json") }
    private var signaturePath: URL { directory.appendingPathComponent("manifest.json.sig") }
    private var statePath: URL { directory.appendingPathComponent("state.json") }

    /// The held manifest, verified again now; nil when there is none or it
    /// no longer verifies.
    public func load() -> VerifiedReleaseManifest? {
        guard let bytes = Self.readBounded(manifestPath),
              let signatureBytes = Self.readBounded(signaturePath),
              let signature = String(data: signatureBytes, encoding: .utf8),
              case let .success(verified) = VerifiedReleaseManifest.verify(
                bytes: bytes, signature: signature, trustedKeys: trustedKeys)
        else { return nil }
        return verified
    }

    public enum Acceptance: Equatable, Sendable {
        /// Newer than the held copy (or the first), and now held.
        case accepted(VerifiedReleaseManifest)
        /// Byte-for-byte the held copy.
        case unchanged(VerifiedReleaseManifest)
    }

    /// Verifies a fetched manifest and keeps it when it is new. A lower
    /// number than the held copy, or the same number with other contents, is
    /// refused and the held copy stays.
    public func accept(bytes: Data, signature: String) throws -> Result<Acceptance, ReleaseManifestFailure> {
        let offered: VerifiedReleaseManifest
        switch VerifiedReleaseManifest.verify(bytes: bytes, signature: signature, trustedKeys: trustedKeys) {
        case let .failure(failure): return .failure(failure)
        case let .success(verified): offered = verified
        }
        if let held = load() {
            if offered.manifest.sequence < held.manifest.sequence {
                return .failure(.rollback(held: held.manifest.sequence, offered: offered.manifest.sequence))
            }
            if offered.manifest.sequence == held.manifest.sequence {
                return held.bytes == offered.bytes
                    ? .success(.unchanged(held))
                    : .failure(.conflictingSequence(held.manifest.sequence))
            }
        }
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        // The signature first: a reader between the two writes sees a
        // mismatched pair, which fails verification and reads as absent
        // until the manifest lands.
        try Data(offered.signature.utf8).write(to: signaturePath, options: .atomic)
        try offered.bytes.write(to: manifestPath, options: .atomic)
        return .success(.accepted(offered))
    }

    public func loadState() -> ReleaseUpdateCheckState {
        guard let data = Self.readBounded(statePath),
              let state = try? JSONDecoder().decode(ReleaseUpdateCheckState.self, from: data) else {
            return ReleaseUpdateCheckState()
        }
        return state
    }

    public func saveState(_ state: ReleaseUpdateCheckState) throws {
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(state).write(to: statePath, options: .atomic)
    }

    private static func readBounded(_ url: URL) -> Data? {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              attributes[.type] as? FileAttributeType == .typeRegular,
              let size = attributes[.size] as? Int, size <= ReleaseManifest.maximumBytes
        else { return nil }
        return try? Data(contentsOf: url)
    }
}

/// What the update check last did. Reported by `csec doctor`; never a
/// reason for csec to change anything.
public struct ReleaseUpdateCheckState: Codable, Equatable, Sendable {
    public var lastAttempt: Date?
    public var lastSuccess: Date?
    /// Value-free summary of the last failed attempt; cleared by a success.
    public var lastFailure: String?
    /// The release already announced in a notification, `VERSION (build N)`.
    public var announced: String?

    public init(lastAttempt: Date? = nil, lastSuccess: Date? = nil,
                lastFailure: String? = nil, announced: String? = nil) {
        self.lastAttempt = lastAttempt
        self.lastSuccess = lastSuccess
        self.lastFailure = lastFailure
        self.announced = announced
    }

    private enum CodingKeys: String, CodingKey {
        case lastAttempt, lastSuccess, lastFailure, announced
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        lastAttempt = Self.date(container, .lastAttempt)
        lastSuccess = Self.date(container, .lastSuccess)
        lastFailure = try? container.decodeIfPresent(String.self, forKey: .lastFailure)
        announced = try? container.decodeIfPresent(String.self, forKey: .announced)
    }

    private static func date(_ container: KeyedDecodingContainer<CodingKeys>, _ key: CodingKeys) -> Date? {
        guard let text = try? container.decodeIfPresent(String.self, forKey: key) else { return nil }
        return ISO8601DateFormatter().date(from: text)
    }
}

/// What `csec doctor` and csecd make of the running build against the held
/// manifest.
public enum ReleaseUpdateStatus: Equatable, Sendable {
    case off(reason: String)
    case notChecked(lastFailure: String?)
    case upToDate(latest: ReleaseBuild?, checked: Date?, lastFailure: String?)
    case available(ReleaseManifest.Release, running: ReleaseBuild)

    public static func evaluate(
        running: ReleaseStamp?,
        trustedKeys: [String] = ReleaseSigningKeys.pinned,
        held: VerifiedReleaseManifest?,
        state: ReleaseUpdateCheckState
    ) -> ReleaseUpdateStatus {
        guard let running, let runningBuild = ReleaseBuild(running) else {
            return .off(reason: "development build")
        }
        guard !trustedKeys.isEmpty else { return .off(reason: "this build pins no release signing key") }
        guard let held else { return .notChecked(lastFailure: state.lastFailure) }
        if let release = held.manifest.release, runningBuild < release.build {
            return .available(release, running: runningBuild)
        }
        return .upToDate(latest: held.manifest.release?.build, checked: state.lastSuccess,
                         lastFailure: state.lastFailure)
    }

    /// The doctor row. An available update or a failing check warns; none
    /// of them makes the installation unhealthy.
    public var doctorRow: StatusRow {
        switch self {
        case let .off(reason):
            return StatusRow(label: "Updates", value: "check off: \(reason)", state: .neutral)
        case let .notChecked(lastFailure):
            return StatusRow(
                label: "Updates",
                value: lastFailure.map { "not checked yet; last attempt: \(ReviewDisplay.sanitized($0))" }
                    ?? "not checked yet",
                state: lastFailure == nil ? .neutral : .warn)
        case let .upToDate(latest, checked, lastFailure):
            var value = latest.map { "up to date (newest release \($0))" } ?? "up to date"
            if let checked { value += ", checked \(Self.day(checked))" }
            if let lastFailure { value += "; last attempt: \(ReviewDisplay.sanitized(lastFailure))" }
            return StatusRow(label: "Updates", value: value, state: lastFailure == nil ? .ok : .warn)
        case let .available(release, running):
            return StatusRow(
                label: "Updates",
                value: "csec \(release.build) is available (this is \(running)): \(release.download.absoluteString)",
                state: .warn)
        }
    }

    private static func day(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_GB")
        formatter.dateFormat = "d MMM yyyy HH:mm"
        return formatter.string(from: date)
    }
}
