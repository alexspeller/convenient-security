import ConvenientSecurity
import Foundation

/// A credential store that answers `finding` and records each plaintext
/// path it was asked about. `delay` holds the answer back, for the bound.
final class FakeCredentialStore: ClaudeCredentialStore, @unchecked Sendable {
    private let lock = NSLock()
    private var answer: ClaudeGatewaySignIn.Finding
    private var asked: [String] = []
    private let delay: TimeInterval

    init(_ finding: ClaudeGatewaySignIn.Finding = .notSignedIn, delay: TimeInterval = 0) {
        answer = finding
        self.delay = delay
    }

    var paths: [String] {
        lock.lock()
        defer { lock.unlock() }
        return asked
    }

    func gatewaySignIn(plaintextPath: String) -> ClaudeGatewaySignIn.Finding {
        if delay > 0 { Thread.sleep(forTimeInterval: delay) }
        lock.lock()
        defer { lock.unlock() }
        asked.append(plaintextPath)
        return answer
    }
}

/// Synthetic Keychain items and plaintext files for `KeychainClaudeCredentialStore`.
private final class SyntheticCredentialWorld: @unchecked Sendable {
    private let lock = NSLock()
    var items: [KeychainClaudeCredentialStore.Item]? = []
    var records: [String: KeychainClaudeCredentialStore.Record] = [:]
    var files: [String: ClaudeSettingsFileContents] = [:]
    var now = Date(timeIntervalSince1970: 2_000_000_000)
    private(set) var reads: [String] = []

    func read(_ item: KeychainClaudeCredentialStore.Item) -> KeychainClaudeCredentialStore.Record {
        lock.lock()
        defer { lock.unlock() }
        reads.append(item.service + "/" + item.account)
        return records[item.service + "/" + item.account] ?? .absent
    }

    func store() -> KeychainClaudeCredentialStore {
        KeychainClaudeCredentialStore(
            list: { self.items },
            read: { self.read($0) },
            files: SyntheticCredentialFiles(world: self),
            clock: { self.now }
        )
    }
}

private struct SyntheticCredentialFiles: ClaudeSettingsFileAccess {
    let world: SyntheticCredentialWorld

    func status(of path: String) -> ClaudeSettingsPathStatus { .missing }
    func contents(of path: String, maximumBytes: Int) -> ClaudeSettingsFileContents {
        world.files[path] ?? .missing
    }
    func entries(of directory: String, maximumCount: Int) -> ClaudeSettingsDirectoryListing { .missing }
}

private let syntheticIdentity = ClaudeSettingsFileIdentity(
    device: 1, inode: 2, size: 3, modificationSeconds: 4, modificationNanoseconds: 0
)

func claudeGatewaySignInTests() {
    print("\n# Delegated approvals: Claude Code's stored Cloud-gateway sign-in")
    gatewayRecordTests()
    gatewayCredentialStoreTests()
}

private func gatewayRecordTests() {
    func holds(_ text: String) -> Bool? { ClaudeGatewaySignIn.recordHoldsSignIn(Data(text.utf8)) }
    let signedIn = #"{"claudeAiOauth":{"accessToken":"synthetic"},"enterpriseGateway":{"url":"https://gw.invalid","jwt":"x"}}"#
    check(holds(signedIn) == true, "gateway record: a top-level enterpriseGateway object is a sign-in")
    check(holds(#"{"claudeAiOauth":{"accessToken":"synthetic"}}"#) == false,
          "gateway record: a record with only a Claude sign-in holds none")
    check(holds(#"{"enterpriseGateway":null}"#) == false, "gateway record: an explicit null is no sign-in")
    check(holds("{}") == false && holds(" \n{ }\n") == false, "gateway record: an empty record holds none")
    check(holds(#"{"mcpOAuth":{"enterpriseGateway":{"url":"x"}},"list":[{"enterpriseGateway":1}]}"#) == false,
          "gateway record: the key nested below the top level is not Claude Code's sign-in")
    check(holds(#"{"note":"\"enterpriseGateway\":{}"}"#) == false,
          "gateway record: the key's text inside a string value is not a key")
    // JSON.parse keeps the last duplicate and JSONSerialization the first,
    // so a non-null occurrence anywhere counts whichever comes last.
    check(holds(#"{"enterpriseGateway":null,"enterpriseGateway":{"url":"x"}}"#) == true,
          "gateway record: a sign-in after a null duplicate counts (JSON.parse keeps the last)")
    check(holds(#"{"enterpriseGateway":{"url":"x"},"enterpriseGateway":null}"#) == true,
          "gateway record: a sign-in before a null duplicate still counts")
    check(holds(#"{"enterpriseGateway":{"url":"x"}}"#) == true,
          "gateway record: a key spelled with an escape is decoded before it is compared")
    check(holds(#"{"enterpriseGateway":"x","a":[1,{"b":"]}"}],"c":true}"#) == true,
          "gateway record: a string value counts, and brackets inside strings do not end a value")
    check(holds(#"{"enterpriseGateway":false}"#) == true && holds(#"{"enterpriseGateway":0}"#) == true,
          "gateway record: any value but null counts, over-approximating JavaScript's truthiness")
    check(holds(#"{"enterpriseGatewayX":{}, "EnterpriseGateway":{}}"#) == false,
          "gateway record: only the exact key counts")
    check(holds("[1,2]") == false && holds("\"text\"") == false && holds("42") == false,
          "gateway record: a record that is not an object holds none, as Claude Code reads it")
    check(holds("{\"enterpriseGateway\":") == nil && holds("not json") == nil && holds("") == nil,
          "gateway record: a record that is not JSON cannot be checked")
    check(holds(#"{"a":"\ud800"}"#) == nil, "gateway record: JSON Foundation's parser refuses reads as unchecked, never as none")
    check(ClaudeGatewaySignIn.recordHoldsSignIn(Data([0xEF, 0xBB, 0xBF] + Array(signedIn.utf8))) != false,
          "gateway record: a byte-order mark never reads as no sign-in")

    check(ClaudeGatewaySignIn.isCredentialService("Claude Code-credentials")
            && ClaudeGatewaySignIn.isCredentialService("Claude Code-credentials-1a2b3c4d")
            && ClaudeGatewaySignIn.isCredentialService("Claude Code-custom-oauth-credentials")
            && !ClaudeGatewaySignIn.isCredentialService("Claude Code")
            && !ClaudeGatewaySignIn.isCredentialService("Claude Safe Storage")
            && !ClaudeGatewaySignIn.isCredentialService("csec Claude Code-credentials"),
          "gateway store: every Claude Code credentials service matches, and nothing else")
    check(ClaudeGatewaySignIn.isCredentialAccount("tester") && ClaudeGatewaySignIn.isCredentialAccount("claude-code-user")
            && ClaudeGatewaySignIn.isCredentialAccount("a.b_c-1")
            && !ClaudeGatewaySignIn.isCredentialAccount("") && !ClaudeGatewaySignIn.isCredentialAccount("me@example.invalid")
            && !ClaudeGatewaySignIn.isCredentialAccount("two words"),
          "gateway store: only an account Claude Code can read its item under matches")
    check(ClaudeGatewaySignIn.plaintextPath(homeDirectory: "/Users/tester", configDirectory: nil)
            == "/Users/tester/.claude/.credentials.json"
            && ClaudeGatewaySignIn.plaintextPath(homeDirectory: "/Users/tester", configDirectory: "/synthetic/config/./")
            == "/synthetic/config/.credentials.json",
          "gateway store: the plaintext record is .credentials.json in Claude Code's configuration home")
}

private func gatewayCredentialStoreTests() {
    typealias Item = KeychainClaudeCredentialStore.Item
    let old = Date(timeIntervalSince1970: 1_900_000_000)
    let plaintext = "/Users/tester/.claude/.credentials.json"
    let signedIn = Data(#"{"enterpriseGateway":{"url":"https://gw.invalid"}}"#.utf8)
    let claudeOnly = Data(#"{"claudeAiOauth":{"accessToken":"synthetic"}}"#.utf8)

    do {
        let world = SyntheticCredentialWorld()
        world.items = [
            Item(service: "Claude Code-credentials", account: "tester", created: old, modified: old),
            Item(service: "Chrome Safe Storage", account: "Chrome", created: old, modified: old),
            Item(service: "Claude Code-credentials", account: "not an account", created: old, modified: old),
        ]
        world.records["Claude Code-credentials/tester"] = .data(claudeOnly)
        world.records["Chrome Safe Storage/Chrome"] = .data(signedIn)
        world.records["Claude Code-credentials/not an account"] = .data(signedIn)
        let store = world.store()
        check(store.gatewaySignIn(plaintextPath: plaintext) == .notSignedIn,
              "gateway store: a Claude-only Keychain record and no plaintext file hold no sign-in")
        check(world.reads == ["Claude Code-credentials/tester"],
              "gateway store: only Claude Code's own items, under an account it can read, are read")
        _ = store.gatewaySignIn(plaintextPath: plaintext)
        check(world.reads.count == 1, "gateway store: an unchanged, settled item is not read again")
        world.items?[0] = Item(service: "Claude Code-credentials", account: "tester", created: old,
                               modified: old.addingTimeInterval(60))
        world.records["Claude Code-credentials/tester"] = .data(signedIn)
        check(store.gatewaySignIn(plaintextPath: plaintext) == .signedIn && world.reads.count == 2,
              "gateway store: a modified item is read again, and its new sign-in found")
    }
    do {
        // securityd dates items to the second, so a record written within a
        // second of the read could change again under the same date.
        let world = SyntheticCredentialWorld()
        let fresh = world.now.addingTimeInterval(-0.5)
        world.items = [Item(service: "Claude Code-credentials-1a2b3c4d", account: "tester", created: old, modified: fresh)]
        world.records["Claude Code-credentials-1a2b3c4d/tester"] = .data(claudeOnly)
        let store = world.store()
        _ = store.gatewaySignIn(plaintextPath: plaintext)
        world.records["Claude Code-credentials-1a2b3c4d/tester"] = .data(signedIn)
        check(store.gatewaySignIn(plaintextPath: plaintext) == .signedIn && world.reads.count == 2,
              "gateway store: an item modified within the settled interval is never cached")
        let undated = SyntheticCredentialWorld()
        undated.items = [Item(service: "Claude Code-credentials", account: "tester", created: nil, modified: nil)]
        undated.records["Claude Code-credentials/tester"] = .data(claudeOnly)
        let undatedStore = undated.store()
        _ = undatedStore.gatewaySignIn(plaintextPath: plaintext)
        _ = undatedStore.gatewaySignIn(plaintextPath: plaintext)
        check(undated.reads.count == 2, "gateway store: an item with no dates is read every time")
    }
    do {
        let world = SyntheticCredentialWorld()
        world.items = [
            Item(service: "Claude Code-credentials", account: "tester", created: old, modified: old),
            Item(service: "Claude Code-credentials-1a2b3c4d", account: "tester", created: old, modified: old),
        ]
        world.records["Claude Code-credentials/tester"] = .data(claudeOnly)
        world.records["Claude Code-credentials-1a2b3c4d/tester"] = .data(signedIn)
        check(world.store().gatewaySignIn(plaintextPath: plaintext) == .signedIn,
              "gateway store: another configuration directory's item with a sign-in declines too")
    }
    do {
        let world = SyntheticCredentialWorld()
        world.files[plaintext] = .contents(signedIn, syntheticIdentity)
        check(world.store().gatewaySignIn(plaintextPath: plaintext) == .signedIn,
              "gateway store: a plaintext record with a sign-in is found with no Keychain item")
        world.files[plaintext] = .contents(claudeOnly, syntheticIdentity)
        check(world.store().gatewaySignIn(plaintextPath: plaintext) == .notSignedIn,
              "gateway store: a Claude-only plaintext record holds none")
        for contents in [ClaudeSettingsFileContents.unreadable, .oversized, .contents(Data("{".utf8), syntheticIdentity)] {
            world.files[plaintext] = contents
            check(world.store().gatewaySignIn(plaintextPath: plaintext) == .unchecked,
                  "gateway store: an unreadable, oversized or unparsable plaintext record is unchecked (\(contents))")
        }
        world.files[plaintext] = .unreadable
        world.items = [Item(service: "Claude Code-credentials", account: "tester", created: old, modified: old)]
        world.records["Claude Code-credentials/tester"] = .data(signedIn)
        check(world.store().gatewaySignIn(plaintextPath: plaintext) == .signedIn,
              "gateway store: a sign-in found anywhere wins over a record that cannot be checked")
    }
    do {
        let world = SyntheticCredentialWorld()
        world.items = nil
        check(world.store().gatewaySignIn(plaintextPath: plaintext) == .unchecked,
              "gateway store: a Keychain that cannot be listed is unchecked")
        world.items = [Item(service: "Claude Code-credentials", account: "tester", created: old, modified: old)]
        world.records["Claude Code-credentials/tester"] = .unreadable
        let store = world.store()
        check(store.gatewaySignIn(plaintextPath: plaintext) == .unchecked,
              "gateway store: a record security cannot read is unchecked")
        _ = store.gatewaySignIn(plaintextPath: plaintext)
        check(world.reads.count == 2, "gateway store: an unreadable record is never cached")
        world.records["Claude Code-credentials/tester"] = .data(Data("plain text".utf8))
        check(world.store().gatewaySignIn(plaintextPath: plaintext) == .unchecked,
              "gateway store: a record that is not JSON is unchecked")
        world.records["Claude Code-credentials/tester"] = .absent
        check(world.store().gatewaySignIn(plaintextPath: plaintext) == .notSignedIn,
              "gateway store: an item gone between the listing and the read holds none")
    }
}

/// `cs-selftest --claude-gateway-sign-in-timing`: the live store against this
/// Mac's Keychain and Claude Code's default configuration home.
func claudeGatewaySignInTiming(homeDirectory: String) {
    func time<T>(_ body: () -> T) -> (T, Double) {
        let start = DispatchTime.now().uptimeNanoseconds
        let value = body()
        return (value, Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000)
    }
    let (items, listing) = time { KeychainClaudeCredentialStore.liveItems() }
    let claude = items?.filter {
        ClaudeGatewaySignIn.isCredentialService($0.service) && ClaudeGatewaySignIn.isCredentialAccount($0.account)
    }
    print("listing: \(items.map { "\($0.count) items" } ?? "failed"), \(claude?.count ?? 0) Claude Code records, "
        + String(format: "%.2f ms", listing))
    let store = KeychainClaudeCredentialStore()
    let path = ClaudeGatewaySignIn.plaintextPath(homeDirectory: homeDirectory, configDirectory: nil)
    let (cold, coldTime) = time { store.gatewaySignIn(plaintextPath: path) }
    var warm: [Double] = []
    for _ in 0..<20 { warm.append(time { store.gatewaySignIn(plaintextPath: path) }.1) }
    warm.sort()
    print("cold check: \(cold), " + String(format: "%.2f ms", coldTime))
    print("warm check x20: median " + String(format: "%.2f", warm[10]) + " ms, max " + String(format: "%.2f", warm[19]) + " ms")
}
