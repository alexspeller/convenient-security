import Darwin
import Foundation
import Security

// A stored Cloud-gateway sign-in (csec-kpep). Claude Code keeps its sign-ins
// in one JSON record in its secure storage: on macOS a generic-password
// Keychain item, or `.credentials.json` in its configuration home when the
// Keychain holds no item. At startup it restores an `enterpriseGateway`
// sign-in from that record with no environment variable (2.1.316 `IRn`,
// checking only the record's own TLS pin, expiry and allowlist entry), and
// then sends every API request, the auto-mode classifier's included, to the
// gateway's URL. `CLAUDE_CODE_USE_GATEWAY` and `ANTHROPIC_BASE_URL` already
// decline in G5; this is the same route without either.
//
// The record also holds Claude Code's OAuth tokens. csecd reads it inside its
// own process only to find whether the key is there, keeps nothing derived
// from any value, and reports only the fixed decline reason.

/// Whether Claude Code's credential records hold a Cloud-gateway sign-in.
public enum ClaudeGatewaySignIn {
    public enum Finding: Sendable, Equatable {
        /// No record holds one.
        case notSignedIn
        case signedIn
        /// A record could not be listed, read or parsed, so csecd cannot say.
        case unchecked
    }

    /// The record's key for the sign-in.
    public static let recordKey = "enterpriseGateway"
    /// The plaintext record's name in Claude Code's configuration home.
    public static let plaintextName = ".credentials.json"
    /// Larger plaintext or Keychain records read as unchecked.
    public static let maximumRecordBytes = 4 * 1_024 * 1_024

    /// Claude Code's own Keychain service names: `Claude Code`, its OAuth
    /// configuration's suffix (`-custom-oauth` and others), `-credentials`,
    /// and a hash of the configuration directory when one is set (2.1.316
    /// `K2`). Matching the shape rather than rebuilding one name covers every
    /// account's configuration directory and suffix: a record for another
    /// configuration can only decline.
    public static func isCredentialService(_ service: String) -> Bool {
        service.hasPrefix("Claude Code") && service.contains("-credentials")
    }

    /// Claude Code reads its item under `$USER` (else the login name), and
    /// only when that is `[A-Za-z0-9._-]+` (else `claude-code-user`), so an
    /// item under any other account is one it never reads.
    public static func isCredentialAccount(_ account: String) -> Bool {
        !account.isEmpty && account.utf8.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || "._-".utf8.contains($0)
        }
    }

    /// The plaintext record Claude Code falls back to: `.credentials.json` in
    /// its configuration home (`ClaudeSettingsScope.claudeConfigurationHome`;
    /// G5 declines a non-empty `CLAUDE_SECURESTORAGE_CONFIG_DIR`, which would
    /// move it).
    public static func plaintextPath(homeDirectory: String, configDirectory: String?) -> String {
        let home = ClaudeSettingsScope.normalizedPath(configDirectory ?? homeDirectory + "/.claude")
            .precomposedStringWithCanonicalMapping
        return ClaudeSettingsScope.normalizedPath(home + "/" + plaintextName)
    }

    /// Whether a record's top-level object has `enterpriseGateway` set to
    /// anything but null; nil when it is not JSON this check can read, which
    /// the caller treats as unchecked.
    ///
    /// Claude Code parses the record with `JSON.parse`, which keeps the last
    /// of duplicate keys, while `JSONSerialization` keeps the first. So the
    /// top-level keys are scanned here, each decoded as JSON decodes it and
    /// compared byte for byte, and any occurrence that is not null counts.
    /// JSON whitespace around the record is ignored (Claude Code trims the
    /// Keychain's output); anything else unusual reads as nil.
    public static func recordHoldsSignIn(_ data: Data) -> Bool? {
        guard data.count <= maximumRecordBytes,
              let parsed = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        else { return nil }
        guard parsed is [String: Any] else { return false }
        var scanner = TopLevelKeyScanner(bytes: Array(data))
        return scanner.holdsNonNull(key: Array(recordKey.utf8))
    }

    /// Reads a top-level JSON object's keys and whether each value is the
    /// literal `null`. Every failure is nil.
    private struct TopLevelKeyScanner {
        let bytes: [UInt8]
        var index = 0

        mutating func holdsNonNull(key wanted: [UInt8]) -> Bool? {
            skipWhitespace()
            guard take(UInt8(ascii: "{")) else { return nil }
            var found = false
            skipWhitespace()
            if take(UInt8(ascii: "}")) { return finished() ? false : nil }
            while true {
                skipWhitespace()
                guard let key = string() else { return nil }
                skipWhitespace()
                guard take(UInt8(ascii: ":")) else { return nil }
                skipWhitespace()
                let isNull = bytes[index...].starts(with: Array("null".utf8))
                guard skipValue() else { return nil }
                if key == wanted, !isNull { found = true }
                skipWhitespace()
                if take(UInt8(ascii: ",")) { continue }
                guard take(UInt8(ascii: "}")) else { return nil }
                return finished() ? found : nil
            }
        }

        /// A string token, decoded by `JSONSerialization`, as UTF-8 bytes.
        private mutating func string() -> [UInt8]? {
            let start = index
            guard skipString() else { return nil }
            let literal = Data([UInt8(ascii: "[")] + bytes[start..<index] + [UInt8(ascii: "]")])
            guard let decoded = (try? JSONSerialization.jsonObject(with: literal)) as? [String],
                  decoded.count == 1 else { return nil }
            return Array(decoded[0].utf8)
        }

        private mutating func skipString() -> Bool {
            guard take(UInt8(ascii: "\"")) else { return false }
            while index < bytes.count {
                let byte = bytes[index]
                index += 1
                if byte == UInt8(ascii: "\\") {
                    index += 1
                } else if byte == UInt8(ascii: "\"") {
                    return index <= bytes.count
                }
            }
            return false
        }

        /// Skips one value, nested or not; the document already parsed, so
        /// only strings and brackets need tracking.
        private mutating func skipValue() -> Bool {
            var depth = 0
            while index < bytes.count {
                let byte = bytes[index]
                switch byte {
                case UInt8(ascii: "\""):
                    guard skipString() else { return false }
                    if depth == 0 { return true }
                    continue
                case UInt8(ascii: "{"), UInt8(ascii: "["):
                    depth += 1
                case UInt8(ascii: "}"), UInt8(ascii: "]"):
                    if depth == 0 { return true }
                    depth -= 1
                    if depth == 0 { index += 1; return true }
                case UInt8(ascii: ","):
                    if depth == 0 { return true }
                default:
                    break
                }
                index += 1
            }
            return depth == 0
        }

        private mutating func take(_ byte: UInt8) -> Bool {
            guard index < bytes.count, bytes[index] == byte else { return false }
            index += 1
            return true
        }

        private mutating func skipWhitespace() {
            while index < bytes.count, [0x20, 0x09, 0x0A, 0x0D].contains(bytes[index]) { index += 1 }
        }

        private mutating func finished() -> Bool {
            skipWhitespace()
            return index == bytes.count
        }
    }
}

/// Where csecd looks for Claude Code's stored sign-ins.
public protocol ClaudeCredentialStore: Sendable {
    /// Every Claude Code Keychain record of this account, and the plaintext
    /// record at `plaintextPath`.
    func gatewaySignIn(plaintextPath: String) -> ClaudeGatewaySignIn.Finding
}

/// The live store: the user's Keychain search list and the plaintext file.
///
/// Listing items reads attributes only, which needs no access to any item
/// and raises no prompt. Each Claude Code item's record is then read the way
/// Claude Code reads it, through `/usr/bin/security find-generic-password
/// -w`: Claude Code writes the item with that tool, so the item's access
/// list already trusts it and no prompt appears. A record is read again only
/// when its item's creation or modification date changes; securityd sets
/// both and ignores a written date, at one-second resolution, so a date
/// within `settledInterval` of the listing is never cached.
public final class KeychainClaudeCredentialStore: ClaudeCredentialStore, @unchecked Sendable {
    public struct Item: Sendable, Hashable {
        public let service: String
        public let account: String
        public let created: Date?
        public let modified: Date?

        public init(service: String, account: String, created: Date?, modified: Date?) {
            self.service = service
            self.account = account
            self.created = created
            self.modified = modified
        }
    }

    public enum Record: Sendable, Equatable {
        case data(Data)
        /// The item went between the listing and the read.
        case absent
        case unreadable
    }

    public static let shared = KeychainClaudeCredentialStore()
    /// How long `security` may take for one record. Claude Code gives it two
    /// seconds; the request's own bound is `ClaudeDelegationService
    /// .credentialBound`.
    public static let readTimeout: TimeInterval = 1.5
    public static let settledInterval: TimeInterval = 2

    private let list: @Sendable () -> [Item]?
    private let read: @Sendable (Item) -> Record
    private let files: any ClaudeSettingsFileAccess
    private let clock: @Sendable () -> Date
    private let lock = NSLock()
    private var verdicts: [Item: Bool] = [:]

    public init(
        list: @escaping @Sendable () -> [Item]? = { KeychainClaudeCredentialStore.liveItems() },
        read: @escaping @Sendable (Item) -> Record = { KeychainClaudeCredentialStore.liveRecord($0) },
        files: any ClaudeSettingsFileAccess = LiveClaudeSettingsFileAccess(),
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.list = list
        self.read = read
        self.files = files
        self.clock = clock
    }

    public func gatewaySignIn(plaintextPath: String) -> ClaudeGatewaySignIn.Finding {
        let listedAt = clock()
        guard let items = list() else { return .unchecked }
        var unchecked = false
        var signedIn = false
        var kept: [Item: Bool] = [:]
        for item in items
        where ClaudeGatewaySignIn.isCredentialService(item.service)
            && ClaudeGatewaySignIn.isCredentialAccount(item.account) {
            if let known = cachedVerdict(item) {
                kept[item] = known
                signedIn = signedIn || known
                continue
            }
            let holds: Bool?
            switch read(item) {
            case let .data(data): holds = ClaudeGatewaySignIn.recordHoldsSignIn(data)
            case .absent: holds = false
            case .unreadable: holds = nil
            }
            guard let holds else { unchecked = true; continue }
            signedIn = signedIn || holds
            if let created = item.created, let modified = item.modified,
               listedAt.timeIntervalSince(max(created, modified)) >= Self.settledInterval {
                kept[item] = holds
            }
        }
        lock.lock()
        verdicts = kept
        lock.unlock()
        switch files.contents(of: plaintextPath, maximumBytes: ClaudeGatewaySignIn.maximumRecordBytes) {
        case .missing:
            break
        case let .contents(data, _):
            switch ClaudeGatewaySignIn.recordHoldsSignIn(data) {
            case true?: signedIn = true
            case false?: break
            case nil: unchecked = true
            }
        case .oversized, .unreadable:
            unchecked = true
        }
        if signedIn { return .signedIn }
        return unchecked ? .unchecked : .notSignedIn
    }

    private func cachedVerdict(_ item: Item) -> Bool? {
        lock.lock()
        defer { lock.unlock() }
        return verdicts[item]
    }

    /// Every generic-password item's service, account and dates in the
    /// user's search list; nil when the Keychain cannot be listed.
    public static func liveItems() -> [Item]? {
        var result: CFTypeRef?
        // Claude Code's items are in the file-based keychains its
        // `security` calls search, not the data-protection keychain.
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecUseDataProtectionKeychain as String: false,
            kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true,
        ] as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess, let attributes = result as? [[String: Any]] else { return nil }
        return attributes.compactMap { item in
            guard let service = item[kSecAttrService as String] as? String,
                  let account = item[kSecAttrAccount as String] as? String else { return nil }
            return Item(
                service: service, account: account,
                created: item[kSecAttrCreationDate as String] as? Date,
                modified: item[kSecAttrModificationDate as String] as? Date
            )
        }
    }

    /// One item's record, as `security find-generic-password -w` prints it
    /// (exit 44: not found). The value stays in this process.
    public static func liveRecord(_ item: Item) -> Record {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        process.arguments = ["find-generic-password", "-a", item.account, "-s", item.service, "-w"]
        process.environment = ["PATH": "/usr/bin:/bin", "LC_ALL": "C"]
        let output = Pipe()
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return .unreadable
        }
        let watchdog = DispatchWorkItem {
            if process.isRunning { process.terminate() }
            DispatchQueue.global().asyncAfter(deadline: .now() + 0.5) {
                if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            }
        }
        DispatchQueue.global().asyncAfter(deadline: .now() + readTimeout, execute: watchdog)
        var data = Data()
        var oversized = false
        while let chunk = try? output.fileHandleForReading.read(upToCount: 64 * 1_024), !chunk.isEmpty {
            if data.count + chunk.count > ClaudeGatewaySignIn.maximumRecordBytes {
                oversized = true
                if process.isRunning { process.terminate() }
                break
            }
            data.append(chunk)
        }
        process.waitUntilExit()
        watchdog.cancel()
        guard !oversized, process.terminationReason == .exit else { return .unreadable }
        switch process.terminationStatus {
        case 0: return .data(data)
        case 44: return .absent
        default: return .unreadable
        }
    }
}
