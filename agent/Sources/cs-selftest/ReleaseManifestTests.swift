import ConvenientSecurity
import CryptoKit
import Foundation

// csec's release version, its build stamp and the signed update manifest
// (csec-0.39.11). The signature vectors below were made by stock OpenSSH
// (`ssh-keygen -Y sign`, throwaway keys whose private halves were deleted), so
// csec's verifier is checked against OpenSSH's own format, not against itself.

func releaseManifestTests() async {
    releaseVersionTests()
    releaseStampTests()
    sshFileSignatureTests()
    releaseManifestParseTests()
    releaseManifestStoreTests()
    releaseManifestClaudeCodeTests()
    releaseUpdateStatusTests()
    await releaseUpdateCheckerTests()
    releaseManifestRequestTests()
}

private enum OpenSSHVectors {
    static let releaseKey =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICa2tayU+P8U1sQQjiXSYF2/0Cj4QmotanvBPpdgqgzy csec-test-release"
    static let otherKey =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPknwEcBYvO69LjYWulYij0Tz8aX918NNlf250R5vXQi csec-test-other"
    static let manifest = Data((
        #"{"schema": 1, "sequence": 3, "published": "2026-11-16T00:00:00Z", "release": {"version": "1.2.0", "#
        + #""build": 4200, "download": "https://convenientsecurity.app/download"}, "claudeCode": {"future": true}}"#
        + "\n").utf8)
    static let sha512Signature = """
        -----BEGIN SSH SIGNATURE-----
        U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgJra1rJT4/xTWxBCOJdJgXb/QKP
        hCai1qe8E+l2CqDPIAAAAncmVsZWFzZS1tYW5pZmVzdEBjb252ZW5pZW50c2VjdXJpdHku
        YXBwAAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQBiSGHM2Q/qC7NAgOM
        ogYCtyt2MNT5S4hhqQb7qFwax19NuJDoTZ4vYFwFZHpfL1Z3arD+sFmLhSUWn89MytPwI=
        -----END SSH SIGNATURE-----
        """
    static let sha256Signature = """
        -----BEGIN SSH SIGNATURE-----
        U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgJra1rJT4/xTWxBCOJdJgXb/QKP
        hCai1qe8E+l2CqDPIAAAAncmVsZWFzZS1tYW5pZmVzdEBjb252ZW5pZW50c2VjdXJpdHku
        YXBwAAAAAAAAAAZzaGEyNTYAAABTAAAAC3NzaC1lZDI1NTE5AAAAQAhhhcomwp/JhLPZ6s
        kKm0TUA9o6+eqOQOgduDZHE6wfZJAyf3gclAfeMOhSjsF/p2BZE4qyOb5PK3AIExJXewM=
        -----END SSH SIGNATURE-----
        """
    /// The release key, signing the same bytes for OpenSSH's `file` namespace.
    static let fileNamespaceSignature = """
        -----BEGIN SSH SIGNATURE-----
        U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAgJra1rJT4/xTWxBCOJdJgXb/QKP
        hCai1qe8E+l2CqDPIAAAAEZmlsZQAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx
        OQAAAECKa/pZokk5wzOov4Om3YfnRLI8eUxXg9lj9UnpeLUZjl18prICWgqopMnFLugmsE
        YRVKRmvzGE3MIWmIkC0zAD
        -----END SSH SIGNATURE-----
        """
    /// The other key, signing the same bytes for the manifest namespace.
    static let otherKeySignature = """
        -----BEGIN SSH SIGNATURE-----
        U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg+SfARwFi87r0uNha6ViKPRPPxp
        f3Xw02V/bnRHm9dCIAAAAncmVsZWFzZS1tYW5pZmVzdEBjb252ZW5pZW50c2VjdXJpdHku
        YXBwAAAAAAAAAAZzaGE1MTIAAABTAAAAC3NzaC1lZDI1NTE5AAAAQNL3RI0wytFy2NC5pw
        QbYjM0PFrM+3KExOxcIxRRHqp2vsAzzWhPKPRqhOuYba5V2AYwR8iUcQnFMUMaw3LmYAg=
        -----END SSH SIGNATURE-----
        """
}

/// Signs like `ssh-keygen -Y sign` (sha512), for the cases the fixed vectors
/// cannot cover: several manifests under one key. Its output is checked
/// against OpenSSH's own signature over the same bytes first.
struct TestReleaseSigner {
    let key: Curve25519.Signing.PrivateKey

    var publicLine: String {
        var blob = Data()
        Self.appendString(&blob, Data("ssh-ed25519".utf8))
        Self.appendString(&blob, key.publicKey.rawRepresentation)
        return "ssh-ed25519 \(blob.base64EncodedString()) csec-test-signer"
    }

    func sign(_ message: Data, namespace: String = ReleaseManifest.namespace) -> String {
        var signed = Data("SSHSIG".utf8)
        Self.appendString(&signed, Data(namespace.utf8))
        Self.appendString(&signed, Data())
        Self.appendString(&signed, Data("sha512".utf8))
        Self.appendString(&signed, Data(SHA512.hash(data: message)))
        // Ed25519 is deterministic in OpenSSH; CryptoKit's is randomized, and
        // both verify the same way.
        let signature = try! key.signature(for: signed)

        var keyBlob = Data()
        Self.appendString(&keyBlob, Data("ssh-ed25519".utf8))
        Self.appendString(&keyBlob, key.publicKey.rawRepresentation)
        var signatureBlob = Data()
        Self.appendString(&signatureBlob, Data("ssh-ed25519".utf8))
        Self.appendString(&signatureBlob, signature)

        var blob = Data("SSHSIG".utf8)
        blob.append(contentsOf: [0, 0, 0, 1])
        Self.appendString(&blob, keyBlob)
        Self.appendString(&blob, Data(namespace.utf8))
        Self.appendString(&blob, Data())
        Self.appendString(&blob, Data("sha512".utf8))
        Self.appendString(&blob, signatureBlob)
        let encoded = blob.base64EncodedString()
        let lines = stride(from: 0, to: encoded.count, by: 70).map { start -> String in
            let from = encoded.index(encoded.startIndex, offsetBy: start)
            let to = encoded.index(from, offsetBy: min(70, encoded.count - start))
            return String(encoded[from..<to])
        }
        return (["-----BEGIN SSH SIGNATURE-----"] + lines + ["-----END SSH SIGNATURE-----"]).joined(separator: "\n")
            + "\n"
    }

    static func appendString(_ data: inout Data, _ value: Data) {
        var length = UInt32(value.count).bigEndian
        withUnsafeBytes(of: &length) { data.append(contentsOf: $0) }
        data.append(value)
    }
}

private func manifestBytes(sequence: Int, version: String = "1.2.0", build: Int = 4200,
                           download: String = "https://convenientsecurity.app/download") -> Data {
    Data(#"{"schema": 1, "sequence": \#(sequence), "release": {"version": "\#(version)", "build": \#(build), "download": "\#(download)"}}"#.utf8)
}

private func releaseVersionTests() {
    check(ReleaseVersion("0.9.0") == ReleaseVersion(major: 0, minor: 9, patch: 0),
          "release version: 0.9.0 parses")
    check(ReleaseVersion("12.0.10")?.description == "12.0.10", "release version: round-trips its text")
    for bad in ["1.0", "1.0.0.0", "01.0.0", "1.0.0-beta", "1..0", "v1.0.0", " 1.0.0", "1.0.x", "", "1.0.٣"] {
        check(ReleaseVersion(bad) == nil, "release version: \(bad.debugDescription) is refused")
    }
    check(ReleaseVersion("1.10.0")! > ReleaseVersion("1.9.9")!, "release version: compares numerically, not as text")
    check(ReleaseVersion("2.0.0")! > ReleaseVersion("1.99.99")!, "release version: the major number decides first")
    let older = ReleaseBuild(version: ReleaseVersion("1.0.0")!, build: 9000)
    let newer = ReleaseBuild(version: ReleaseVersion("1.0.1")!, build: 10)
    check(older < newer, "release build: a higher version wins over a higher build number")
    check(ReleaseBuild(version: ReleaseVersion("1.0.0")!, build: 41)
            < ReleaseBuild(version: ReleaseVersion("1.0.0")!, build: 42),
          "release build: the same version is ordered by build")
}

private func releaseStampTests() {
    let commit = String(repeating: "a", count: 40)
    let good = Data(#"{"version":"0.9.0","build":4567,"commit":"\#(commit)"}"#.utf8)
    let stamp = ReleaseStamp.decode(good)
    check(stamp == ReleaseStamp(version: "0.9.0", build: 4567, commit: commit), "release stamp: decodes a whole stamp")
    check(stamp?.display == "0.9.0 (build 4567, commit aaaaaaa)", "release stamp: displays version, build and short commit")
    check(ReleaseStamp.versionLine(program: "csec", stamp: stamp) == "csec 0.9.0 (build 4567, commit aaaaaaa)",
          "release stamp: csec --version names the stamp")
    check(ReleaseStamp.versionLine(program: "csec", stamp: nil) == "csec development build (no release stamp)",
          "release stamp: an unstamped build says it is a development build")
    for bad in [
        #"{"version":"0.9","build":4567,"commit":"\#(commit)"}"#,
        #"{"version":"0.9.0","build":0,"commit":"\#(commit)"}"#,
        #"{"version":"0.9.0","build":4567,"commit":"abc"}"#,
        #"{"version":"0.9.0","build":4567,"commit":"\#(String(repeating: "A", count: 40))"}"#,
        #"{"version":"0.9.0","commit":"\#(commit)"}"#,
        "not json",
    ] {
        check(ReleaseStamp.decode(Data(bad.utf8)) == nil, "release stamp: refuses \(bad.prefix(40))")
    }
    // A binary build-agent.sh linked carries a stamp; `swift build` leaves none.
    // Either way, what the running binary reports must be a whole stamp.
    check(ReleaseStamp.current.map { ReleaseStamp.decode(try! JSONEncoder().encode($0)) == $0 } ?? true,
          "release stamp: the running binary's stamp, if any, is well formed")
}

private func sshFileSignatureTests() {
    let namespace = ReleaseManifest.namespace
    let trusted = [OpenSSHVectors.releaseKey]
    func verify(_ message: Data, _ signature: String, keys: [String] = trusted,
                namespace: String = namespace) -> Result<String, SSHFileSignature.Failure> {
        SSHFileSignature.verify(message: message, armored: signature, namespace: namespace, trustedKeys: keys)
    }

    check(verify(OpenSSHVectors.manifest, OpenSSHVectors.sha512Signature) == .success(OpenSSHVectors.releaseKey),
          "ssh signature: OpenSSH's sha512 signature verifies against the pinned key")
    check(verify(OpenSSHVectors.manifest, OpenSSHVectors.sha256Signature) == .success(OpenSSHVectors.releaseKey),
          "ssh signature: OpenSSH's sha256 signature verifies too")
    check(verify(OpenSSHVectors.manifest, OpenSSHVectors.sha512Signature,
                 keys: [OpenSSHVectors.otherKey, OpenSSHVectors.releaseKey]) == .success(OpenSSHVectors.releaseKey),
          "ssh signature: any one of several pinned keys may sign")

    var tampered = OpenSSHVectors.manifest
    tampered[tampered.index(tampered.startIndex, offsetBy: 30)] ^= 0x01
    check(verify(tampered, OpenSSHVectors.sha512Signature) == .failure(.badSignature),
          "ssh signature: one changed byte of the manifest fails")
    check(verify(OpenSSHVectors.manifest + Data("\n".utf8), OpenSSHVectors.sha512Signature) == .failure(.badSignature),
          "ssh signature: an appended byte fails")
    check(verify(OpenSSHVectors.manifest, OpenSSHVectors.fileNamespaceSignature) == .failure(.wrongNamespace),
          "ssh signature: the release key's signature for another namespace is refused")
    check(verify(OpenSSHVectors.manifest, OpenSSHVectors.otherKeySignature) == .failure(.untrustedKey),
          "ssh signature: a valid signature by a key that is not pinned is refused")
    check(verify(OpenSSHVectors.manifest, OpenSSHVectors.sha512Signature, keys: []) == .failure(.noTrustedKeys),
          "ssh signature: with no pinned key nothing verifies")
    check(verify(OpenSSHVectors.manifest, OpenSSHVectors.sha512Signature,
                 keys: ["ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ csec-test"]) == .failure(.noTrustedKeys),
          "ssh signature: a pinned line that is not an Ed25519 key is ignored")
    check(verify(OpenSSHVectors.manifest, "not a signature") == .failure(.malformed),
          "ssh signature: text without the armour is refused")
    check(verify(OpenSSHVectors.manifest, "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----")
            == .failure(.malformed),
          "ssh signature: a truncated blob is refused")

    // Corrupt the signature's last byte inside its base64 (the signature
    // bytes themselves, not the framing).
    var lines = OpenSSHVectors.sha512Signature.split(separator: "\n").map(String.init)
    var blob = Data(base64Encoded: lines[1..<(lines.count - 1)].joined())!
    blob[blob.count - 1] ^= 0x01
    let encoded = blob.base64EncodedString()
    lines = ["-----BEGIN SSH SIGNATURE-----", encoded, "-----END SSH SIGNATURE-----"]
    check(verify(OpenSSHVectors.manifest, lines.joined(separator: "\n")) == .failure(.badSignature),
          "ssh signature: a changed signature byte fails")

    // The test signer agrees with OpenSSH's format: its signature over the
    // vector verifies, and its key line round-trips as a pinned key.
    let signer = TestReleaseSigner(key: Curve25519.Signing.PrivateKey())
    check(verify(OpenSSHVectors.manifest, signer.sign(OpenSSHVectors.manifest), keys: [signer.publicLine])
            == .success(signer.publicLine),
          "ssh signature: the test signer's SSHSIG verifies like OpenSSH's")
    check(SSHFileSignature.publicKeyBlob(OpenSSHVectors.releaseKey) != nil,
          "ssh signature: an OpenSSH public key line parses")
    check(SSHFileSignature.publicKeyBlob("ssh-ed25519 AAAAC3NzaC1yc2E= x") == nil,
          "ssh signature: a key line whose blob does not match its type is refused")
}

private func releaseManifestParseTests() {
    let parsed = ReleaseManifest.parse(OpenSSHVectors.manifest)
    check(parsed == .success(ReleaseManifest(
        sequence: 3,
        release: ReleaseManifest.Release(
            build: ReleaseBuild(version: ReleaseVersion("1.2.0")!, build: 4200),
            download: URL(string: "https://convenientsecurity.app/download")!))),
          "release manifest: schema 1 parses and ignores sections it does not know")
    check(ReleaseManifest.parse(Data(#"{"schema": 1, "sequence": 7}"#.utf8))
            == .success(ReleaseManifest(sequence: 7, release: nil)),
          "release manifest: a manifest may announce no release")
    check(ReleaseManifest.parse(Data(#"{"schema": 2, "sequence": 7}"#.utf8)) == .failure(.unsupportedSchema),
          "release manifest: a newer schema is refused, not guessed at")
    check(ReleaseManifest.parse(Data(#"{"schema": true, "sequence": 7}"#.utf8)) == .failure(.invalid("schema")),
          "release manifest: a boolean is not a schema number")
    check(ReleaseManifest.parse(Data(#"{"schema": 1, "sequence": 0}"#.utf8)) == .failure(.invalid("sequence")),
          "release manifest: the sequence must be positive")
    check(ReleaseManifest.parse(Data(#"{"schema": 1, "sequence": "7"}"#.utf8)) == .failure(.invalid("sequence")),
          "release manifest: a string sequence is refused")
    check(ReleaseManifest.parse(manifestBytes(sequence: 1, version: "1.2")) == .failure(.invalid("release version")),
          "release manifest: a release version must be MAJOR.MINOR.PATCH")
    check(ReleaseManifest.parse(manifestBytes(sequence: 1, build: 0)) == .failure(.invalid("release build")),
          "release manifest: a release build must be positive")
    check(ReleaseManifest.parse(manifestBytes(sequence: 1, download: "http://convenientsecurity.app/download"))
            == .failure(.invalid("release download address")),
          "release manifest: the download address must be https")
    check(ReleaseManifest.parse(manifestBytes(sequence: 1, download: "https://example.com/a b"))
            == .failure(.invalid("release download address")),
          "release manifest: a download address with spaces is refused")
    check(ReleaseManifest.parse(Data("[1]".utf8)) == .failure(.notJSON), "release manifest: an array is refused")
}

private func releaseManifestStoreTests() {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("csec-release-manifest-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let signer = TestReleaseSigner(key: Curve25519.Signing.PrivateKey())
    let store = ReleaseManifestStore(directory: directory, trustedKeys: [signer.publicLine])

    check(store.load() == nil, "manifest store: holds nothing at first")
    let first = manifestBytes(sequence: 5)
    guard case let .success(.accepted(accepted))? = try? store.accept(bytes: first, signature: signer.sign(first)) else {
        check(false, "manifest store: accepts the first signed manifest")
        return
    }
    check(accepted.manifest.sequence == 5, "manifest store: accepts the first signed manifest")
    check(store.load()?.bytes == first, "manifest store: the accepted manifest reads back verified")

    let again = try? store.accept(bytes: first, signature: signer.sign(first))
    if case .success(.unchanged)? = again {
        check(true, "manifest store: the same manifest again is unchanged")
    } else {
        check(false, "manifest store: the same manifest again is unchanged")
    }

    let older = manifestBytes(sequence: 4, version: "9.9.9")
    check((try? store.accept(bytes: older, signature: signer.sign(older))) == .failure(.rollback(held: 5, offered: 4)),
          "manifest store: a signed manifest numbered below the held one is refused (no rollback)")
    let sameNumber = manifestBytes(sequence: 5, version: "9.9.9")
    check((try? store.accept(bytes: sameNumber, signature: signer.sign(sameNumber))) == .failure(.conflictingSequence(5)),
          "manifest store: different contents under the held number are refused")
    check(store.load()?.bytes == first, "manifest store: a refused manifest leaves the held one in place")

    let unsigned = manifestBytes(sequence: 6)
    check((try? store.accept(bytes: unsigned, signature: OpenSSHVectors.sha512Signature)) == .failure(.signature(.untrustedKey)),
          "manifest store: a manifest not signed by a pinned key is refused")
    let newer = manifestBytes(sequence: 6, version: "1.3.0", build: 4300)
    if case .success(.accepted)? = try? store.accept(bytes: newer, signature: signer.sign(newer)) {
        check(store.load()?.manifest.release?.build.version == ReleaseVersion("1.3.0"),
              "manifest store: a higher number replaces the held manifest")
    } else {
        check(false, "manifest store: a higher number replaces the held manifest")
    }

    // A replaced file on disk only reads as absent, never as trusted.
    try? Data(#"{"schema": 1, "sequence": 99, "release": {"version": "99.0.0", "build": 1, "download": "https://evil.example/x"}}"#.utf8)
        .write(to: directory.appendingPathComponent("manifest.json"))
    check(store.load() == nil, "manifest store: a manifest edited on disk no longer verifies and reads as absent")
    let otherKeyStore = ReleaseManifestStore(directory: directory, trustedKeys: [OpenSSHVectors.releaseKey])
    check(otherKeyStore.load() == nil, "manifest store: a held manifest is checked against this build's keys")

    var state = ReleaseUpdateCheckState(lastAttempt: Date(timeIntervalSince1970: 1_800_000_000),
                                        lastSuccess: Date(timeIntervalSince1970: 1_800_000_000),
                                        lastFailure: nil, announced: "1.3.0 (build 4300)")
    try? store.saveState(state)
    check(store.loadState() == state, "manifest store: the check's state round-trips")
    state.lastFailure = "timed out"
    try? store.saveState(state)
    check(store.loadState().lastFailure == "timed out", "manifest store: the last failure is kept")
    try? Data("garbage".utf8).write(to: directory.appendingPathComponent("state.json"))
    check(store.loadState() == ReleaseUpdateCheckState(), "manifest store: an unreadable state file reads as empty")
}

/// The audited Claude Code list the manifest carries (csec-0.39.14): it can
/// only add exact identities to the compiled catalog, and only while the held
/// copy verifies.
private func releaseManifestClaudeCodeTests() {
    let compiledHash = "cb0b92a2ee6314aeadf4303ca2b503a181ad9f7f"
    let added = String(repeating: "d", count: 40)
    func manifest(_ sequence: Int, _ builds: String) -> Data {
        Data(#"{"schema": 1, "sequence": \#(sequence), "claude_code": {"checked": [\#(builds)]}}"#.utf8)
    }
    func build(_ cdHash: String, _ version: String) -> String { #"{"cdhash": "\#(cdHash)", "version": "\#(version)"}"# }

    check(ReleaseManifest.parse(manifest(2, build(added, "2.1.330") + "," + build(compiledHash, "relabelled")))
            == .success(ReleaseManifest(sequence: 2, release: nil, claudeCode: [
                .init(cdHash: added, version: "2.1.330"), .init(cdHash: compiledHash, version: "relabelled")])),
          "release manifest: the claude_code section parses into exact identities")
    check(ReleaseManifest.parse(Data(#"{"schema": 1, "sequence": 2, "claude_code": {"checked": []}}"#.utf8))
            == .success(ReleaseManifest(sequence: 2, release: nil)),
          "release manifest: an empty claude_code list adds nothing")
    for (bad, field, why) in [
        (build(String(repeating: "D", count: 40), "2.1.330"), "claude_code cdhash", "an uppercase hash"),
        (build(String(repeating: "d", count: 39), "2.1.330"), "claude_code cdhash", "a short hash"),
        (build(added, "1") + "," + build(added, "2"), "claude_code cdhash", "a repeated hash"),
        (build(added, ""), "claude_code version", "an empty version"),
        (build(added, "2.1 330"), "claude_code version", "a version with a space"),
        (build(added, "2.1.330\\n"), "claude_code version", "a version with a newline"),
        (build(added, String(repeating: "9", count: 65)), "claude_code version", "a version over 64 bytes"),
    ] {
        check(ReleaseManifest.parse(manifest(2, bad)) == .failure(.invalid(field)),
              "release manifest: \(why) in claude_code refuses the whole manifest")
    }
    if case .failure(.invalid) = ReleaseManifest.parse(Data(#"{"schema": 1, "sequence": 2, "claude_code": {"checked": "all"}}"#.utf8)) {
        check(true, "release manifest: a claude_code list of the wrong type is refused")
    } else {
        check(false, "release manifest: a claude_code list of the wrong type is refused")
    }
    let tooMany = (0...ClaudeBuildVerificationReport.maximumCheckedReleases).map {
        build(String(format: "%040x", $0), "v\($0)")
    }.joined(separator: ",")
    check(ReleaseManifest.parse(manifest(2, tooMany)) == .failure(.invalid("claude_code checked")),
          "release manifest: a claude_code list over its bound is refused")

    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("csec-release-claude-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let signer = TestReleaseSigner(key: Curve25519.Signing.PrivateKey())
    let store = ReleaseManifestStore(directory: directory, trustedKeys: [signer.publicLine])
    let compiled = ClaudeBuildVerification.shipped
    check(ClaudeBuildVerification.current(compiled: compiled, store: store).records.map(\.cdHash)
            == compiled.records.map(\.cdHash),
          "signed Claude list: with no manifest held, only the compiled catalog counts")
    let first = manifest(3, build(added, "2.1.330") + "," + build(compiledHash, "relabelled"))
    _ = try? store.accept(bytes: first, signature: signer.sign(first))
    let current = ClaudeBuildVerification.current(compiled: compiled, store: store)
    check(current.checkedVersion(cdHash: added) == "2.1.330"
            && current.checkedVersion(cdHash: compiledHash) == "2.1.325"
            && current.records.count == compiled.records.count + 1
            && current.records.last?.evidence == "signed release manifest, number 3",
          "signed Claude list: a verified manifest adds its new image; a compiled record keeps its own label")
    check(current.checkedVersion(cdHash: String(repeating: "d", count: 39) + "0") == nil,
          "signed Claude list: a neighbouring hash of an added image stays unchecked")
    let empty = manifest(4, "")
    _ = try? store.accept(bytes: empty, signature: signer.sign(empty))
    let after = ClaudeBuildVerification.current(compiled: compiled, store: store)
    check(after.checkedVersion(cdHash: compiledHash) == "2.1.325" && after.checkedVersion(cdHash: added) == nil,
          "signed Claude list: a later manifest cannot withdraw a compiled image, and drops only its own")
    _ = try? store.accept(bytes: first, signature: signer.sign(first))
    check(ClaudeBuildVerification.current(compiled: compiled, store: store).checkedVersion(cdHash: added) == nil,
          "signed Claude list: an older signed list replayed later is refused, so a dropped image stays dropped")
    let forged = manifest(9, build(String(repeating: "e", count: 40), "2.1.999"))
    try? forged.write(to: directory.appendingPathComponent("manifest.json"))
    check(ClaudeBuildVerification.current(compiled: compiled, store: store).records.map(\.cdHash)
            == compiled.records.map(\.cdHash),
          "signed Claude list: a manifest edited on disk adds nothing")
    let unpinned = ReleaseManifestStore(directory: directory, trustedKeys: [])
    check(ClaudeBuildVerification.current(compiled: compiled, store: unpinned).records.count == compiled.records.count,
          "signed Claude list: a build that pins no release key reads the compiled catalog alone")
}

private func releaseUpdateStatusTests() {
    let signer = TestReleaseSigner(key: Curve25519.Signing.PrivateKey())
    let bytes = manifestBytes(sequence: 2, version: "1.2.0", build: 4200)
    guard case let .success(held) = VerifiedReleaseManifest.verify(
        bytes: bytes, signature: signer.sign(bytes), trustedKeys: [signer.publicLine]) else {
        check(false, "update status: test manifest verifies")
        return
    }
    let commit = String(repeating: "b", count: 40)
    let keys = [signer.publicLine]
    let state = ReleaseUpdateCheckState()

    check(ReleaseUpdateStatus.evaluate(running: nil, trustedKeys: keys, held: held, state: state)
            == .off(reason: "development build"),
          "update status: a development build does not check")
    let running = ReleaseStamp(version: "1.1.0", build: 4000, commit: commit)
    check(ReleaseUpdateStatus.evaluate(running: running, trustedKeys: [], held: nil, state: state)
            == .off(reason: "this build pins no release signing key"),
          "update status: a build with no pinned key says the check is off")
    check(ReleaseUpdateStatus.evaluate(running: running, trustedKeys: keys, held: nil, state: state)
            == .notChecked(lastFailure: nil),
          "update status: nothing held yet is 'not checked'")
    let available = ReleaseUpdateStatus.evaluate(running: running, trustedKeys: keys, held: held, state: state)
    check(available == .available(held.manifest.release!, running: ReleaseBuild(running)!),
          "update status: a newer release is available")
    check(available.doctorRow.state == .warn
            && available.doctorRow.value.contains("1.2.0 (build 4200) is available")
            && available.doctorRow.value.contains("https://convenientsecurity.app/download"),
          "update status: the doctor row warns and names the release and where to get it")
    let same = ReleaseStamp(version: "1.2.0", build: 4200, commit: commit)
    check(ReleaseUpdateStatus.evaluate(running: same, trustedKeys: keys, held: held, state: state).doctorRow.state == .ok,
          "update status: running the announced build is up to date")
    let newerDevelopment = ReleaseStamp(version: "1.2.0", build: 4250, commit: commit)
    check(ReleaseUpdateStatus.evaluate(running: newerDevelopment, trustedKeys: keys, held: held, state: state)
            .doctorRow.state == .ok,
          "update status: a later build of the same version is not offered the older release")
    let failing = ReleaseUpdateCheckState(lastFailure: "the server answered 404")
    check(ReleaseUpdateStatus.evaluate(running: same, trustedKeys: keys, held: held, state: failing).doctorRow.state == .warn,
          "update status: a failing check warns even while up to date")
}

/// Serves fixed bytes per URL, or fails, and counts the requests.
private final class FakeManifestServer: @unchecked Sendable {
    private let lock = NSLock()
    private var files: [URL: Data] = [:]
    private var failure: Error?
    private(set) var requests = 0

    func serve(manifest: Data, signature: String) {
        lock.lock(); defer { lock.unlock() }
        files = [ReleaseManifest.manifestURL: manifest, ReleaseManifest.signatureURL: Data(signature.utf8)]
        failure = nil
    }

    func fail(_ error: Error) {
        lock.lock(); defer { lock.unlock() }
        failure = error
    }

    func fetch(_ url: URL) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        requests += 1
        if let failure { throw failure }
        guard let data = files[url] else { throw ReleaseManifestFetcher.Failure.status(404) }
        return data
    }
}

private func releaseUpdateCheckerTests() async {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("csec-release-check-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let signer = TestReleaseSigner(key: Curve25519.Signing.PrivateKey())
    let store = ReleaseManifestStore(directory: directory, trustedKeys: [signer.publicLine])
    let server = FakeManifestServer()
    let running = ReleaseStamp(version: "1.1.0", build: 4000, commit: String(repeating: "c", count: 40))
    let checker = ReleaseUpdateChecker(store: store, running: running, fetch: { try server.fetch($0) })
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    let offDevelopment = ReleaseUpdateChecker(store: store, running: nil, fetch: { try server.fetch($0) })
    check(await offDevelopment.check(now: now) == .off("development build") && server.requests == 0,
          "update check: a development build fetches nothing")
    let offNoKey = ReleaseUpdateChecker(store: ReleaseManifestStore(directory: directory, trustedKeys: []),
                                        running: running, fetch: { try server.fetch($0) })
    check(await offNoKey.check(now: now) == .off("this build pins no release signing key") && server.requests == 0,
          "update check: a build with no pinned key fetches nothing")

    check(await checker.check(now: now) == .failed("the release server answered 404"),
          "update check: an unpublished manifest is a failure, not an update")
    check(store.loadState().lastFailure == "the release server answered 404" && store.loadState().lastAttempt == now,
          "update check: the failure and its time are recorded for csec doctor")

    let newer = manifestBytes(sequence: 2, version: "1.2.0", build: 4200)
    server.serve(manifest: newer, signature: signer.sign(newer))
    let first = await checker.check(now: now)
    let expected = ReleaseManifest.Release(build: ReleaseBuild(version: ReleaseVersion("1.2.0")!, build: 4200),
                                           download: URL(string: "https://convenientsecurity.app/download")!)
    check(first == .announce(expected, running: ReleaseBuild(running)!),
          "update check: a newer signed release is announced")
    check(store.loadState().lastFailure == nil && store.loadState().lastSuccess == now,
          "update check: a success clears the last failure")
    if case .checked(.available)? = Optional(await checker.check(now: now)) {
        check(true, "update check: the same release is announced only once")
    } else {
        check(false, "update check: the same release is announced only once")
    }

    let forged = manifestBytes(sequence: 3, version: "9.0.0", build: 1)
    server.serve(manifest: forged, signature: OpenSSHVectors.sha512Signature)
    check(await checker.check(now: now) == .failed("the signature's key is not a pinned release key"),
          "update check: a manifest signed by another key is refused")
    let replayed = manifestBytes(sequence: 1, version: "1.1.5", build: 4100)
    server.serve(manifest: replayed, signature: signer.sign(replayed))
    if case let .failed(summary) = await checker.check(now: now) {
        check(summary.contains("older than the one csec holds"), "update check: a replayed older manifest is refused")
    } else {
        check(false, "update check: a replayed older manifest is refused")
    }
    check(store.load()?.bytes == newer, "update check: refusals keep the held manifest")

    let later = manifestBytes(sequence: 4, version: "1.3.0", build: 4300)
    server.serve(manifest: later, signature: signer.sign(later))
    if case let .announce(release, _) = await checker.check(now: now) {
        check(release.build.version == ReleaseVersion("1.3.0"), "update check: a later release is announced again")
    } else {
        check(false, "update check: a later release is announced again")
    }
    server.fail(ReleaseManifestFetcher.Failure.unreachable(-1009))
    check(await checker.check(now: now) == .failed("could not reach the release server (error -1009)"),
          "update check: an offline Mac records the failure")
    check(store.load()?.manifest.release?.build.version == ReleaseVersion("1.3.0"),
          "update check: offline, the last verified manifest still answers csec doctor")

    let words = ReleaseUpdateNotice.words(release: expected, running: ReleaseBuild(running)!)
    check(words.title == "csec 1.2.0 is available"
            && words.body == "This Mac runs csec 1.1.0. Download the new package from convenientsecurity.app; "
                + "`csec doctor` shows the link.",
          "update notice: names the new and running versions and where to download")
    let rebuilt = ReleaseUpdateNotice.words(
        release: expected, running: ReleaseBuild(version: ReleaseVersion("1.2.0")!, build: 4100))
    check(rebuilt.title == "csec 1.2.0 (build 4200) is available" && rebuilt.body.contains("runs csec 1.2.0 (build 4100)"),
          "update notice: a rebuild of the same version names both builds")
}

private func releaseManifestRequestTests() {
    let request = ReleaseManifestFetcher.request(for: ReleaseManifest.manifestURL)
    check(request.url == URL(string: "https://convenientsecurity.app/releases/manifest.json")
            && request.httpMethod == "GET" && request.httpBody == nil,
          "update request: a plain GET of the fixed address")
    check(request.allHTTPHeaderFields == [
        "User-Agent": "ConvenientSecurity", "Accept": "*/*", "Accept-Language": "en"],
          "update request: only a fixed User-Agent (no version) and generic Accept headers")
    check(!request.httpShouldHandleCookies, "update request: no cookies")
    check(ReleaseManifest.manifestURL.query == nil && ReleaseManifest.signatureURL.query == nil,
          "update request: no query string")
    let configuration = ReleaseManifestFetcher.sessionConfiguration()
    check(configuration.httpCookieStorage == nil && configuration.urlCache == nil
            && configuration.urlCredentialStorage == nil && configuration.httpCookieAcceptPolicy == .never,
          "update request: an ephemeral session keeps no cookies, cache or credentials")
}
