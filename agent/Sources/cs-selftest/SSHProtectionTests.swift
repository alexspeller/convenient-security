import ConvenientSecurity
import CryptoKit
import Darwin
import Foundation
import Security

private enum SSHFixtureError: Error {
    case malformed
    case rsaKeyGeneration
    case rsaPublicKey
    case signatureAlgorithm(expected: String, actual: String)
    case signatureTrailingData
}

private struct SSHFixtureWriter {
    private(set) var data = Data()

    mutating func byte(_ value: UInt8) {
        data.append(value)
    }

    mutating func uint32(_ value: UInt32) {
        data.append(UInt8((value >> 24) & 0xff))
        data.append(UInt8((value >> 16) & 0xff))
        data.append(UInt8((value >> 8) & 0xff))
        data.append(UInt8(value & 0xff))
    }

    mutating func uint64(_ value: UInt64) {
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8((value >> UInt64(shift)) & 0xff))
        }
    }

    mutating func string(_ value: Data) {
        uint32(UInt32(value.count))
        data.append(value)
    }

    mutating func string(_ value: String) {
        string(Data(value.utf8))
    }

    mutating func positiveMPInt(_ value: Data) {
        var bytes = [UInt8](value)
        while bytes.first == 0 { bytes.removeFirst() }
        if let first = bytes.first, first & 0x80 != 0 { bytes.insert(0, at: 0) }
        string(Data(bytes))
    }
}

private struct SSHFixtureReader {
    private let bytes: [UInt8]
    private var offset = 0

    init(_ data: Data) {
        bytes = Array(data)
    }

    var isAtEnd: Bool { offset == bytes.count }

    mutating func byte() throws -> UInt8 {
        guard offset < bytes.count else { throw SSHFixtureError.malformed }
        defer { offset += 1 }
        return bytes[offset]
    }

    mutating func uint32() throws -> UInt32 {
        guard bytes.count - offset >= 4 else { throw SSHFixtureError.malformed }
        let value = (UInt32(bytes[offset]) << 24)
            | (UInt32(bytes[offset + 1]) << 16)
            | (UInt32(bytes[offset + 2]) << 8)
            | UInt32(bytes[offset + 3])
        offset += 4
        return value
    }

    mutating func string() throws -> Data {
        let count = Int(try uint32())
        guard count <= bytes.count - offset else { throw SSHFixtureError.malformed }
        defer { offset += count }
        return Data(bytes[offset..<(offset + count)])
    }

    mutating func text() throws -> String {
        let value = try string()
        guard let text = String(data: value, encoding: .utf8) else {
            throw SSHFixtureError.malformed
        }
        return text
    }

    mutating func positiveMPInt() throws -> Data {
        var value = [UInt8](try string())
        guard value.first.map({ $0 & 0x80 == 0 }) ?? true else {
            throw SSHFixtureError.malformed
        }
        if value.count > 1, value[0] == 0, value[1] & 0x80 == 0 {
            throw SSHFixtureError.malformed
        }
        if value.first == 0 { value.removeFirst() }
        return Data(value)
    }
}

private func openSSHPrivateKeyPEM(
    publicKeyBlob: Data,
    mismatchedCheckints: Bool = false,
    cipher: String = "none",
    kdf: String = "none",
    kdfOptions: Data = Data(),
    fields: (inout SSHFixtureWriter) -> Void
) -> Data {
    var privateWriter = SSHFixtureWriter()
    privateWriter.uint32(0x4353_4543)
    privateWriter.uint32(mismatchedCheckints ? 0x4353_4544 : 0x4353_4543)
    fields(&privateWriter)
    var padding: UInt8 = 1
    while privateWriter.data.count % 8 != 0 {
        privateWriter.byte(padding)
        padding &+= 1
    }

    var document = Data("openssh-key-v1\0".utf8)
    var outerWriter = SSHFixtureWriter()
    outerWriter.string(cipher)
    outerWriter.string(kdf)
    outerWriter.string(kdfOptions)
    outerWriter.uint32(1)
    outerWriter.string(publicKeyBlob)
    outerWriter.string(privateWriter.data)
    document.append(outerWriter.data)
    return pem(label: "OPENSSH PRIVATE KEY", body: document)
}

private func pem(label: String, body: Data) -> Data {
    Data(
        "-----BEGIN \(label)-----\n\(body.base64EncodedString())\n"
            .appending("-----END \(label)-----\n").utf8
    )
}

private func der(_ tag: UInt8, _ contents: Data) -> Data {
    var result = Data([tag])
    if contents.count < 128 {
        result.append(UInt8(contents.count))
    } else {
        var count = contents.count
        var encoded: [UInt8] = []
        while count > 0 {
            encoded.insert(UInt8(count & 0xff), at: 0)
            count >>= 8
        }
        result.append(0x80 | UInt8(encoded.count))
        result.append(contentsOf: encoded)
    }
    result.append(contents)
    return result
}

private func ed25519PKCS8(seed: Data) -> Data {
    let version = der(0x02, Data([0]))
    let algorithm = der(0x30, der(0x06, Data([0x2b, 0x65, 0x70])))
    let privateKey = der(0x04, der(0x04, seed))
    return pem(label: "PRIVATE KEY", body: der(0x30, version + algorithm + privateKey))
}

private func ecSEC1P256(scalar: Data, publicPoint: Data) -> Data {
    let version = der(0x02, Data([1]))
    let privateKey = der(0x04, scalar)
    let curve = der(0xa0, der(0x06, Data([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])))
    let publicKey = der(0xa1, der(0x03, Data([0]) + publicPoint))
    return pem(label: "EC PRIVATE KEY", body: der(0x30, version + privateKey + curve + publicKey))
}

struct Ed25519SSHFixture {
    let key: Curve25519.Signing.PrivateKey
    let publicKeyBlob: Data
    let privateKeyPEM: Data

    init(seed: UInt8, mismatchedCheckints: Bool = false) throws {
        let seedBytes = Data((0..<32).map { seed &+ UInt8($0) })
        let generatedKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seedBytes)
        key = generatedKey

        var publicWriter = SSHFixtureWriter()
        publicWriter.string("ssh-ed25519")
        publicWriter.string(generatedKey.publicKey.rawRepresentation)
        publicKeyBlob = publicWriter.data
        privateKeyPEM = openSSHPrivateKeyPEM(
            publicKeyBlob: publicWriter.data,
            mismatchedCheckints: mismatchedCheckints
        ) { privateWriter in
            privateWriter.string("ssh-ed25519")
            privateWriter.string(generatedKey.publicKey.rawRepresentation)
            privateWriter.string(seedBytes + generatedKey.publicKey.rawRepresentation)
            privateWriter.string("synthetic-csec-selftest")
        }
    }

    func signatureBlob(for message: Data) throws -> Data {
        var writer = SSHFixtureWriter()
        writer.string("ssh-ed25519")
        writer.string(try key.signature(for: message))
        return writer.data
    }

    func verifies(signatureBlob: Data, message: Data) -> Bool {
        do {
            var reader = SSHFixtureReader(signatureBlob)
            let algorithm = try reader.text()
            let signature = try reader.string()
            return algorithm == "ssh-ed25519"
                && reader.isAtEnd
                && key.publicKey.isValidSignature(signature, for: message)
        } catch {
            return false
        }
    }
}

/// A fixed, full-magnitude ECDSA private scalar of `length` bytes with exactly
/// one leading 0x00 followed by a byte below 0x80, so the minimal-mpint
/// stripping the fixtures exercise is still covered. Tiny scalars (7, 9, 11)
/// are avoided: CryptoKit's own verify of its own signature fails for some of
/// them a few percent of the time (csec-ad9), which made these checks flaky.
private func ecdsaFixtureScalar(length: Int) -> Data {
    Data([0x00]) + Data((1..<length).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 11) })
}

private func ecdsaOpenSSHFixture(
    curve: String,
    scalar: Data,
    publicPoint: Data
) -> (pem: Data, publicKeyBlob: Data) {
    let algorithm = "ecdsa-sha2-\(curve)"
    var publicWriter = SSHFixtureWriter()
    publicWriter.string(algorithm)
    publicWriter.string(curve)
    publicWriter.string(publicPoint)
    let publicKeyBlob = publicWriter.data
    let privateKeyPEM = openSSHPrivateKeyPEM(publicKeyBlob: publicKeyBlob) { writer in
        writer.string(algorithm)
        writer.string(curve)
        writer.string(publicPoint)
        writer.positiveMPInt(scalar)
        writer.string("synthetic-csec-selftest")
    }
    return (privateKeyPEM, publicKeyBlob)
}

private func rawECDSASignature(
    _ signatureBlob: Data,
    algorithm: String,
    scalarBytes: Int
) throws -> Data {
    var outer = SSHFixtureReader(signatureBlob)
    guard try outer.text() == algorithm else { throw SSHFixtureError.malformed }
    let encoded = try outer.string()
    guard outer.isAtEnd else { throw SSHFixtureError.malformed }
    var inner = SSHFixtureReader(encoded)
    let r = try inner.positiveMPInt()
    let s = try inner.positiveMPInt()
    guard inner.isAtEnd, r.count <= scalarBytes, s.count <= scalarBytes else {
        throw SSHFixtureError.malformed
    }
    return Data(repeating: 0, count: scalarBytes - r.count) + r
        + Data(repeating: 0, count: scalarBytes - s.count) + s
}

private func rawSSHSignature(_ signatureBlob: Data, algorithm: String) throws -> Data {
    var reader = SSHFixtureReader(signatureBlob)
    let actualAlgorithm = try reader.text()
    guard actualAlgorithm == algorithm else {
        throw SSHFixtureError.signatureAlgorithm(expected: algorithm, actual: actualAlgorithm)
    }
    let signature = try reader.string()
    guard reader.isAtEnd else { throw SSHFixtureError.signatureTrailingData }
    return signature
}

func generatedRSAPEM(bits: Int) throws -> (privateKey: SecKey, pem: Data) {
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits as String: bits,
    ]
    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
          let representation = SecKeyCopyExternalRepresentation(privateKey, &error) as Data?
    else { throw SSHFixtureError.rsaKeyGeneration }
    return (privateKey, pem(label: "RSA PRIVATE KEY", body: representation))
}

private actor SSHFixtureCounter {
    private var value = 0

    func record() { value += 1 }
    func count() -> Int { value }
}

private final class SSHDiagnosticCapture: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?

    func record(_ diagnostic: String) {
        lock.lock()
        value = diagnostic
        lock.unlock()
    }

    func latest() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private struct SSHFixtureProvider: SecretProvider {
    let scheme: String
    let values: [String: Data]
    let counter: SSHFixtureCounter
    var onResolve: (@Sendable () -> Void)? = nil

    var schemes: Set<String> { [scheme] }

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        await counter.record()
        guard let value = values[ref.uri] else {
            throw ProviderError.referenceNotFound(ref.uri)
        }
        onResolve?()
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }

    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

private actor SSHFixtureConsent: ConsentProvider {
    private var count = 0

    func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval?,
        policySummary: String?
    ) async -> ConsentOutcome {
        count += 1
        return .approved(unlock: nil)
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        count += 1
        return .approved(unlock: nil)
    }

    func calls() -> Int { count }
}

private actor SSHFixtureReview: PolicyReviewProvider {
    private var count = 0
    private var latestReason: String?
    private var latestSSH: SSHAccessReviewDetails?
    private var latestScopes: GrantScopeChoices?
    private var latestDurations: GrantDurationChoices?
    /// What the real window would put in its banner for this review, recorded so
    /// the service-level tests can assert on the copy a human would actually see.
    private var latestWarning: String?
    private let selectedKind: GrantScopeKind?
    private let selectedID: String?
    private let selectedDuration: GrantDuration?
    private let onReview: (@Sendable () -> Void)?

    init(
        selecting kind: GrantScopeKind? = nil,
        selectedID: String? = nil,
        selectedDuration: GrantDuration? = nil,
        onReview: (@Sendable () -> Void)? = nil
    ) {
        self.selectedKind = kind
        self.selectedID = selectedID
        self.selectedDuration = selectedDuration
        self.onReview = onReview
    }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        count += 1
        latestReason = review.reason
        latestSSH = review.ssh
        latestScopes = review.scopeChoices
        latestDurations = review.durationChoices
        latestWarning = DeliveryReviewCopy.warning(for: review)
        if review.ssh != nil { onReview?() }
        let selected = selectedID ?? review.scopeChoices?.options.first {
            $0.kind == selectedKind
        }?.id
        // Resolve the desired lifetime to a menu index; an unoffered lifetime is
        // out of range, so the service falls back to the displayed default.
        let durationIndex = selectedDuration
            .flatMap { review.durationChoices?.options.firstIndex(of: $0) }
        return .approved(AccessPolicyApproval(
            selectedScopeOptionID: selected,
            selectedDurationIndex: durationIndex
        ))
    }

    func calls() -> Int { count }
    func reason() -> String? { latestReason }
    func ssh() -> SSHAccessReviewDetails? { latestSSH }
    func scopes() -> GrantScopeChoices? { latestScopes }
    func durations() -> GrantDurationChoices? { latestDurations }
    func warning() -> String? { latestWarning }
}

/// A movable clock for grant-expiry checks, so a 12-hour lifetime is testable
/// without waiting for one.
private final class SSHFixtureClock: @unchecked Sendable {
    private let lock = NSLock()
    private var instant = Date(timeIntervalSince1970: 1_700_000_000)

    func now() -> Date {
        lock.lock()
        defer { lock.unlock() }
        return instant
    }

    func advance(seconds: TimeInterval) {
        lock.lock()
        instant = instant.addingTimeInterval(seconds)
        lock.unlock()
    }
}

private final class SSHFixtureProcessChanges: @unchecked Sendable {
    private let lock = NSLock()
    private var starts: [pid_t: UInt64] = [:]
    private var parents: [pid_t: pid_t] = [:]

    func startTime(_ pid: pid_t, fallback: UInt64?) -> UInt64? {
        lock.lock()
        defer { lock.unlock() }
        return starts[pid] ?? fallback
    }

    func parent(_ pid: pid_t, fallback: pid_t?) -> pid_t? {
        lock.lock()
        defer { lock.unlock() }
        return parents[pid] ?? fallback
    }

    func recycle(_ pid: pid_t) {
        lock.lock()
        starts[pid] = 99_999
        lock.unlock()
    }

    func detach(_ pid: pid_t) {
        lock.lock()
        parents[pid] = 1
        lock.unlock()
    }
}

private struct SSHDenyFixtureReview: PolicyReviewProvider {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        .denied(.human(decidedAt: .now))
    }
}

func sshFingerprint(_ publicKeyBlob: Data) -> String {
    let digest = Data(SHA256.hash(data: publicKeyBlob)).base64EncodedString()
        .trimmingCharacters(in: CharacterSet(charactersIn: "="))
    return "SHA256:\(digest)"
}

private func ed25519HostCertificate(
    host: Ed25519SSHFixture,
    certificationAuthority: Ed25519SSHFixture,
    certificateType: UInt32 = 2
) throws -> Data {
    var principals = SSHFixtureWriter()
    principals.string("synthetic.example")

    var certificate = SSHFixtureWriter()
    certificate.string("ssh-ed25519-cert-v01@openssh.com")
    certificate.string(Data(repeating: 0x43, count: 32))
    certificate.string(host.key.publicKey.rawRepresentation)
    certificate.uint64(7)
    certificate.uint32(certificateType)
    certificate.string("synthetic-host-certificate")
    certificate.string(principals.data)
    certificate.uint64(0)
    certificate.uint64(UInt64.max)
    certificate.string(Data()) // critical options
    certificate.string(Data()) // extensions
    certificate.string(Data()) // reserved
    certificate.string(certificationAuthority.publicKeyBlob)

    let signature = try certificationAuthority.signatureBlob(for: certificate.data)
    certificate.string(signature)
    return certificate.data
}

func userAuthenticationRequest(
    sessionIdentifier: Data,
    remoteUser: String,
    publicKeyBlob: Data,
    hostKeyBlob: Data,
    algorithm: String = "ssh-ed25519",
    hostbound: Bool = true
) -> Data {
    var writer = SSHFixtureWriter()
    writer.string(sessionIdentifier)
    writer.byte(50) // SSH2_MSG_USERAUTH_REQUEST
    writer.string(remoteUser)
    writer.string("ssh-connection")
    writer.string(hostbound ? "publickey-hostbound-v00@openssh.com" : "publickey")
    writer.byte(1)
    writer.string(algorithm)
    writer.string(publicKeyBlob)
    if hostbound { writer.string(hostKeyBlob) }
    return writer.data
}

private func sessionBindMessage(
    host: Ed25519SSHFixture,
    sessionIdentifier: Data,
    forwarding: Bool = false
) throws -> Data {
    var writer = SSHFixtureWriter()
    writer.byte(27) // SSH_AGENTC_EXTENSION
    writer.string("session-bind@openssh.com")
    writer.string(host.publicKeyBlob)
    writer.string(sessionIdentifier)
    writer.string(try host.signatureBlob(for: sessionIdentifier))
    writer.byte(forwarding ? 1 : 0)
    return writer.data
}

private func signRequest(publicKeyBlob: Data, signedData: Data, flags: UInt32 = 0) -> Data {
    var writer = SSHFixtureWriter()
    writer.byte(13) // SSH2_AGENTC_SIGN_REQUEST
    writer.string(publicKeyBlob)
    writer.string(signedData)
    writer.uint32(flags)
    return writer.data
}

private func sshScopeSelectionTests() async throws {
    let nativeKey = try Ed25519SSHFixture(seed: 17)
    let providerKey = try Ed25519SSHFixture(seed: 43)
    let hostKey = try Ed25519SSHFixture(seed: 83)
    let session = Data(repeating: 0x31, count: 32)
    let binding = try SSHDestinationBinding(
        hostKeyBlob: hostKey.publicKeyBlob, sessionIdentifier: session,
        signature: hostKey.signatureBlob(for: session), isForwarding: false
    )
    let fish: pid_t = 71_000
    let claude: pid_t = 71_010
    let firstSSH: pid_t = 71_021
    let siblingSSH: pid_t = 71_031
    let codexSSH: pid_t = 71_041
    let directSSH: pid_t = 71_050
    let secondDirectSSH: pid_t = 71_051
    let otherTerminalSSH: pid_t = 72_001
    let parents: [pid_t: pid_t] = [
        fish: 1, claude: fish, 71_020: claude, firstSSH: 71_020,
        71_030: claude, siblingSSH: 71_030, 71_040: fish, codexSSH: 71_040,
        directSSH: fish, secondDirectSSH: fish, 72_000: 1, otherTerminalSSH: 72_000,
    ]
    let starts = Dictionary(uniqueKeysWithValues: parents.keys.map { ($0, UInt64($0) + 100) })
    let names: [pid_t: String] = [
        fish: "fish", 72_000: "fish", claude: "2.1.252", 71_040: "codex",
        71_020: "zsh", 71_030: "zsh",
    ]
    let fixtures = [
        ("csec://ssh-scope/native", nativeKey),
        ("op://SSH Scope/Provider/private key", providerKey),
    ]

    func makeService(
        review: SSHFixtureReview,
        changes: SSHFixtureProcessChanges = SSHFixtureProcessChanges(),
        onResolve: (@Sendable () -> Void)? = nil
    ) async throws -> (SSHSigningService, SSHFixtureCounter) {
        let counter = SSHFixtureCounter()
        let resolver = SecretResolver(cache: NullSecretCache())
        var keys: [SSHKeyMetadata] = []
        for (uri, fixture) in fixtures {
            let reference = try SecretRef(uri)
            await resolver.register(SSHFixtureProvider(
                scheme: reference.scheme, values: [uri: fixture.privateKeyPEM],
                counter: counter, onResolve: onResolve
            ))
            keys.append(SSHKeyMetadata(
                reference: uri, fingerprint: sshFingerprint(fixture.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: fixture.publicKeyBlob, label: "scope key"
            ))
        }
        let inspection = ProcessInspection(
            startTime: { changes.startTime($0, fallback: starts[$0]) },
            parent: { changes.parent($0, fallback: parents[$0]) },
            name: { names[$0] ?? "ssh" },
            executablePath: {
                $0 == claude ? "/Users/test/.local/share/claude/versions/2.1.252" : "/usr/bin/ssh"
            },
            hasControllingTerminal: { $0 == fish || $0 == 72_000 }
        )
        return (SSHSigningService(
            resolver: resolver,
            catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: keys)),
            consent: SSHFixtureConsent(), policyReview: review,
            allowUnverifiedCallersForTesting: true, processInspection: inspection,
            knownHostsLookup: SSHKnownHostsLookup { _ in ["scope.example.test"] },
            terminalInspection: .unavailable
        ), counter)
    }

    func sign(
        _ service: SSHSigningService, pid: pid_t,
        key: Ed25519SSHFixture? = nil,
        destination: SSHDestinationBinding? = nil, user: String = "deploy"
    ) async throws {
        let key = key ?? nativeKey
        let destination = destination ?? binding
        _ = try await service.signSSHAuthentication(
            publicKeyBlob: key.publicKeyBlob,
            signedData: userAuthenticationRequest(
                sessionIdentifier: destination.sessionIdentifier, remoteUser: user,
                publicKeyBlob: key.publicKeyBlob, hostKeyBlob: destination.hostKeyBlob
            ),
            flags: 0, binding: destination,
            caller: CallerInfo(pid: pid, startTime: starts[pid]!, description: "synthetic SSH")
        )
    }

    let directReview = SSHFixtureReview()
    let (directService, _) = try await makeService(review: directReview)
    try await sign(directService, pid: directSSH)
    let directChoices = await directReview.scopes()
    check(directChoices?.options.map(\.kind) == [.requestingCommand, .terminalSession]
          && directChoices?.defaultOption.pid == fish,
          "SSH typed in fish offers command or fish, with fish as the visible default")
    try await sign(directService, pid: secondDirectSSH)
    try await sign(directService, pid: firstSSH)
    check(await directReview.calls() == 1,
          "a fish approval covers later direct SSH and coding agents started under that fish")
    try await sign(directService, pid: otherTerminalSSH)
    check(await directReview.calls() == 2, "a fish approval does not cover another terminal")

    for (_, key) in fixtures {
        let narrowReview = SSHFixtureReview(selecting: .requestingCommand)
        let (narrowService, _) = try await makeService(review: narrowReview)
        try await sign(narrowService, pid: firstSSH, key: key)
        try await sign(narrowService, pid: siblingSSH, key: key)
        check(await narrowReview.calls() == 2,
              "command-only SSH approval excludes a later command for either storage backend")
    }

    let agentReview = SSHFixtureReview()
    let (agentService, _) = try await makeService(review: agentReview)
    try await sign(agentService, pid: firstSSH)
    let agentChoices = await agentReview.scopes()
    check(agentChoices?.options.map(\.kind) == [.requestingCommand, .codingAgent, .terminalSession]
          && agentChoices?.defaultOption.pid == claude,
          "SSH under Claude offers command, Claude, and fish, defaulting to Claude")
    try await sign(agentService, pid: siblingSSH)
    check(await agentReview.calls() == 1, "a Claude SSH approval covers sibling tool calls")
    try await sign(agentService, pid: codexSSH)
    check(await agentReview.calls() == 2, "a Claude SSH approval excludes a sibling coding agent")

    let terminalReview = SSHFixtureReview(selecting: .terminalSession)
    let (terminalService, _) = try await makeService(review: terminalReview)
    try await sign(terminalService, pid: firstSSH)
    try await sign(terminalService, pid: codexSSH)
    try await sign(terminalService, pid: directSSH)
    check(await terminalReview.calls() == 1,
          "explicitly choosing fish under Claude grants the selected terminal, not the default agent")
    let otherHost = try Ed25519SSHFixture(seed: 107)
    let otherBinding = try SSHDestinationBinding(
        hostKeyBlob: otherHost.publicKeyBlob, sessionIdentifier: session,
        signature: otherHost.signatureBlob(for: session), isForwarding: false
    )
    try await sign(terminalService, pid: directSSH, key: providerKey)
    try await sign(terminalService, pid: directSSH, destination: otherBinding)
    try await sign(terminalService, pid: directSSH, user: "other-user")
    check(await terminalReview.calls() == 4,
          "even a terminal SSH approval cannot cross key, server identity, or username boundaries")

    let forgedReview = SSHFixtureReview(selectedID: "terminal_session-999-999")
    let (forgedService, _) = try await makeService(review: forgedReview)
    try await sign(forgedService, pid: firstSSH)
    try await sign(forgedService, pid: codexSSH)
    check(await forgedReview.calls() == 2,
          "an unoffered SSH scope ID falls back to the visible Claude default without widening")

    for changedPID in [fish, firstSSH] {
        let changes = SSHFixtureProcessChanges()
        let review = SSHFixtureReview(selecting: .terminalSession, onReview: {
            changes.recycle(changedPID)
        })
        let (service, counter) = try await makeService(review: review, changes: changes)
        do {
            try await sign(service, pid: firstSSH)
            check(false, "a recycled caller or selected scope must invalidate SSH approval")
        } catch SSHProtectionError.authorizationDenied {
            check(await counter.count() == 0,
                  "a recycled caller or selected scope denies SSH before provider resolution")
        }
    }

    let reparenting = SSHFixtureProcessChanges()
    let reparentedReview = SSHFixtureReview(selecting: .terminalSession)
    let (reparentedService, _) = try await makeService(
        review: reparentedReview, changes: reparenting,
        onResolve: { reparenting.detach(firstSSH) }
    )
    do {
        try await sign(reparentedService, pid: firstSSH)
        check(false, "SSH cannot return a signature after leaving its selected scope")
    } catch SSHProtectionError.authorizationDenied {
        check(true, "SSH revalidates selected-root containment before returning a signature")
    }

    let recycled = SSHFixtureProcessChanges()
    let recycledReview = SSHFixtureReview(selecting: .terminalSession)
    let (recycledService, _) = try await makeService(review: recycledReview, changes: recycled)
    try await sign(recycledService, pid: firstSSH)
    recycled.recycle(fish)
    try await sign(recycledService, pid: siblingSSH)
    check(await recycledReview.calls() == 2,
          "a recycled terminal PID cannot inherit an earlier SSH grant")
}

/// The SSH review's one warning channel: a server identity no `known_hosts`
/// entry names. The plan carries no `recipientAssurance`, so without the SSH
/// branch in `DeliveryReviewCopy.warning(for:)` an unknown host would render
/// exactly like a recognized one.
private func sshUnknownHostReviewTests() async throws {
    let signingKey = try Ed25519SSHFixture(seed: 211)
    let hostKey = try Ed25519SSHFixture(seed: 223)
    let session = Data(repeating: 0x57, count: 32)
    let binding = try SSHDestinationBinding(
        hostKeyBlob: hostKey.publicKeyBlob, sessionIdentifier: session,
        signature: hostKey.signatureBlob(for: session), isForwarding: false
    )
    let shell: pid_t = 74_000
    let sshPID: pid_t = 74_010
    let starts: [pid_t: UInt64] = [shell: 74_100, sshPID: 74_110]
    let inspection = ProcessInspection(
        startTime: { starts[$0] },
        parent: { $0 == sshPID ? shell : 1 },
        name: { $0 == shell ? "fish" : "ssh" },
        executablePath: { _ in "/usr/bin/ssh" },
        hasControllingTerminal: { $0 == shell }
    )
    let reference = "csec://ssh-unknown-host/key"
    let plan = DeliveryPlan(
        mechanism: .credentialProtocol,
        executable: PlannedExecutable(
            canonicalPath: "/usr/bin/ssh", signingIdentifier: "com.apple.ssh",
            assurance: .independentlyProtected
        ),
        root: .caller,
        descendantScope: .subtree,
        destination: .credentialConsumer,
        requestedTTLSeconds: nil,
        operationContext: "SSH authentication"
    )

    func copyReview(hostNames: [String]) -> AccessPolicyReview {
        let ssh = SSHAccessReviewDetails(
            hostNames: hostNames, remoteUser: "deploy",
            keyLabel: "copy fixture", keyAlgorithm: "ssh-ed25519"
        )
        return AccessPolicyReview(
            caller: CallerInfo(pid: sshPID, startTime: starts[sshPID]!, description: "synthetic SSH"),
            reason: ssh.reason, plan: plan, credentials: [], ssh: ssh
        )
    }

    check(DeliveryReviewCopy.warning(for: copyReview(hostNames: []))?
            .hasPrefix("UNKNOWN HOST:") == true,
          "an SSH review with no matching known_hosts name yields an unknown-host warning")
    check(DeliveryReviewCopy.warning(for: copyReview(hostNames: ["known.example.test"])) == nil,
          "an SSH review for a recognized server identity yields no warning")

    func sign(names: [String], review: SSHFixtureReview) async throws {
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(SSHFixtureProvider(
            scheme: "csec", values: [reference: signingKey.privateKeyPEM],
            counter: SSHFixtureCounter()
        ))
        let service = SSHSigningService(
            resolver: resolver,
            catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [SSHKeyMetadata(
                reference: reference, fingerprint: sshFingerprint(signingKey.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: signingKey.publicKeyBlob,
                label: "unknown host fixture"
            )])),
            consent: SSHFixtureConsent(), policyReview: review,
            allowUnverifiedCallersForTesting: true, processInspection: inspection,
            knownHostsLookup: SSHKnownHostsLookup { _ in names },
            terminalInspection: .unavailable
        )
        _ = try await service.signSSHAuthentication(
            publicKeyBlob: signingKey.publicKeyBlob,
            signedData: userAuthenticationRequest(
                sessionIdentifier: session, remoteUser: "deploy",
                publicKeyBlob: signingKey.publicKeyBlob, hostKeyBlob: hostKey.publicKeyBlob
            ),
            flags: 0, binding: binding,
            caller: CallerInfo(pid: sshPID, startTime: starts[sshPID]!, description: "synthetic SSH")
        )
    }

    let unknownReview = SSHFixtureReview()
    try await sign(names: [], review: unknownReview)
    let unknownWarning = await unknownReview.warning()
    check(unknownWarning?.contains("UNKNOWN HOST") == true,
          "an SSH signing request for an unrecognized server identity warns the reviewer")
    check(unknownWarning?.contains("SHA256:") == false
          && unknownWarning?.contains(reference) == false,
          "the unknown-host warning names the condition without a fingerprint or reference")
    check(await unknownReview.ssh()?.hostTitle == "Unknown host",
          "the unknown-host review still leads with the unknown-host headline")

    let knownReview = SSHFixtureReview()
    try await sign(names: ["known.example.test"], review: knownReview)
    check(await knownReview.warning() == nil,
          "a known_hosts-recognized server identity shows no warning banner")
}

/// The SSH review offers the same 1/12/48-hour lifetime choice as a secret
/// release, and the chosen lifetime — never an unoffered one — bounds the grant.
private func sshGrantDurationTests() async throws {
    let signingKey = try Ed25519SSHFixture(seed: 227)
    let hostKey = try Ed25519SSHFixture(seed: 229)
    let session = Data(repeating: 0x61, count: 32)
    let binding = try SSHDestinationBinding(
        hostKeyBlob: hostKey.publicKeyBlob, sessionIdentifier: session,
        signature: hostKey.signatureBlob(for: session), isForwarding: false
    )
    let fish: pid_t = 75_000
    let claude: pid_t = 75_010
    let firstWrapper: pid_t = 75_020
    let firstSSH: pid_t = 75_021
    let siblingWrapper: pid_t = 75_030
    let siblingSSH: pid_t = 75_031
    let parents: [pid_t: pid_t] = [
        fish: 1, claude: fish, firstWrapper: claude, firstSSH: firstWrapper,
        siblingWrapper: claude, siblingSSH: siblingWrapper,
    ]
    let starts = Dictionary(uniqueKeysWithValues: parents.keys.map { ($0, UInt64($0) + 100) })
    let names: [pid_t: String] = [
        fish: "fish", claude: "2.1.252", firstWrapper: "zsh", siblingWrapper: "zsh",
    ]
    let inspection = ProcessInspection(
        startTime: { starts[$0] },
        parent: { parents[$0] },
        name: { names[$0] ?? "ssh" },
        executablePath: {
            $0 == claude ? "/Users/test/.local/share/claude/versions/2.1.252" : "/usr/bin/ssh"
        },
        hasControllingTerminal: { $0 == fish }
    )
    let reference = "csec://ssh-duration/key"

    func makeService(
        review: SSHFixtureReview, clock: SSHFixtureClock
    ) async throws -> SSHSigningService {
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(SSHFixtureProvider(
            scheme: "csec", values: [reference: signingKey.privateKeyPEM],
            counter: SSHFixtureCounter()
        ))
        return SSHSigningService(
            resolver: resolver,
            catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [SSHKeyMetadata(
                reference: reference, fingerprint: sshFingerprint(signingKey.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: signingKey.publicKeyBlob,
                label: "duration fixture"
            )])),
            consent: SSHFixtureConsent(), policyReview: review,
            allowUnverifiedCallersForTesting: true, processInspection: inspection,
            knownHostsLookup: SSHKnownHostsLookup { _ in ["duration.example.test"] },
            terminalInspection: .unavailable,
            now: { clock.now() }
        )
    }

    func sign(_ service: SSHSigningService, pid: pid_t) async throws {
        _ = try await service.signSSHAuthentication(
            publicKeyBlob: signingKey.publicKeyBlob,
            signedData: userAuthenticationRequest(
                sessionIdentifier: session, remoteUser: "deploy",
                publicKeyBlob: signingKey.publicKeyBlob, hostKeyBlob: hostKey.publicKeyBlob
            ),
            flags: 0, binding: binding,
            caller: CallerInfo(pid: pid, startTime: starts[pid]!, description: "synthetic SSH")
        )
    }

    // An explicit opt-in bound (1 hour) still works: a sibling reuses it inside
    // the hour, and a new review is required once the hour has passed.
    let hourClock = SSHFixtureClock()
    let hourReview = SSHFixtureReview(selectedDuration: .bounded(seconds: 60 * 60))
    let hourService = try await makeService(review: hourReview, clock: hourClock)
    try await sign(hourService, pid: firstSSH)
    let offered = await hourReview.durations()
    check(offered?.defaultOption == .processLifetime
          && offered?.options == [.processLifetime, .bounded(seconds: 60 * 60),
                                  .bounded(seconds: 12 * 60 * 60)],
          "an SSH review defaults to session lifetime, with opt-in 1h/12h beside it (no 48h, no cap)")
    hourClock.advance(seconds: 3_540)
    try await sign(hourService, pid: siblingSSH)
    check(await hourReview.calls() == 1,
          "a one-hour SSH approval still covers a sibling command inside that hour")
    hourClock.advance(seconds: 120)
    try await sign(hourService, pid: siblingSSH)
    check(await hourReview.calls() == 2,
          "an explicit one-hour SSH approval requires a new review once the hour has passed")

    // The default (session lifetime): the signing grant never lapses by clock —
    // only the process-subtree liveness sweep can drop it — so a sibling reuses
    // it no matter how much wall-clock passes.
    let sessionClock = SSHFixtureClock()
    let sessionReview = SSHFixtureReview()  // no selection ⇒ the displayed session-lifetime default
    let sessionService = try await makeService(review: sessionReview, clock: sessionClock)
    try await sign(sessionService, pid: firstSSH)
    sessionClock.advance(seconds: TimeInterval(30 * 24 * 60 * 60))
    try await sign(sessionService, pid: siblingSSH)
    check(await sessionReview.calls() == 1,
          "a session-lifetime SSH grant covers a sibling a month later without re-review")

    // An unoffered lifetime falls back to the displayed default (session
    // lifetime), never lengthening — and never re-prompting on a clock.
    let unofferedClock = SSHFixtureClock()
    let unofferedReview = SSHFixtureReview(selectedDuration: .bounded(seconds: 7 * 24 * 60 * 60))
    let unofferedService = try await makeService(review: unofferedReview, clock: unofferedClock)
    try await sign(unofferedService, pid: firstSSH)
    unofferedClock.advance(seconds: TimeInterval(30 * 24 * 60 * 60))
    try await sign(unofferedService, pid: siblingSSH)
    check(await unofferedReview.calls() == 1,
          "an unoffered SSH lifetime falls back to the session-lifetime default, not a clock")
}

/// An SSH approval for a Claude session also covers the `ssh` a job that
/// session detached runs after its tool call has ended, through the recorded
/// session (`SessionLineage`). Without the record the job's `ssh` is reviewed
/// again, and can only be approved for itself.
private func sshDetachedJobGrantTests() async throws {
    let signingKey = try Ed25519SSHFixture(seed: 233)
    let hostKey = try Ed25519SSHFixture(seed: 239)
    let session = Data(repeating: 0x63, count: 32)
    let binding = try SSHDestinationBinding(
        hostKeyBlob: hostKey.publicKeyBlob, sessionIdentifier: session,
        signature: hostKey.signatureBlob(for: session), isForwarding: false
    )
    let reference = "csec://ssh-detached/key"

    func makeService(
        review: SSHFixtureReview, inspection: ProcessInspection
    ) async throws -> SSHSigningService {
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(SSHFixtureProvider(
            scheme: "csec", values: [reference: signingKey.privateKeyPEM],
            counter: SSHFixtureCounter()
        ))
        return SSHSigningService(
            resolver: resolver,
            catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [SSHKeyMetadata(
                reference: reference, fingerprint: sshFingerprint(signingKey.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: signingKey.publicKeyBlob,
                label: "detached job fixture"
            )])),
            consent: SSHFixtureConsent(), policyReview: review,
            allowUnverifiedCallersForTesting: true, processInspection: inspection,
            knownHostsLookup: SSHKnownHostsLookup { _ in ["nimbus.example.test"] },
            terminalInspection: .unavailable
        )
    }

    func sign(_ service: SSHSigningService, pid: pid_t, kernel: FakeLineageKernel) async throws {
        _ = try await service.signSSHAuthentication(
            publicKeyBlob: signingKey.publicKeyBlob,
            signedData: userAuthenticationRequest(
                sessionIdentifier: session, remoteUser: "root",
                publicKeyBlob: signingKey.publicKeyBlob, hostKeyBlob: hostKey.publicKeyBlob
            ),
            flags: 0, binding: binding,
            caller: CallerInfo(pid: pid, startTime: kernel.startTime(pid)!, description: "synthetic SSH")
        )
    }

    for recorded in [true, false] {
        let fixture = FakeClaudeSession()
        let lineage = SessionLineage(facts: fixture.kernel.facts)
        if recorded { lineage.record(from: FakeClaudeSession.csecAI) }
        fixture.kernel.spawn(FakeClaudeSession.inTreeSSH, parent: FakeClaudeSession.command)
        let review = SSHFixtureReview()
        let service = try await makeService(review: review, inspection: fixture.inspection(lineage))

        try await sign(service, pid: FakeClaudeSession.inTreeSSH, kernel: fixture.kernel)
        let first = await review.scopes()?.defaultOption
        check(first?.kind == .codingAgent && first?.pid == FakeClaudeSession.claude,
              "fixture: the tool call's own ssh is approved for the Claude session")

        fixture.kernel.exit(FakeClaudeSession.inTreeSSH)
        fixture.endToolCall()
        fixture.kernel.spawn(FakeClaudeSession.ssh, parent: FakeClaudeSession.job)
        try await sign(service, pid: FakeClaudeSession.ssh, kernel: fixture.kernel)
        if recorded {
            check(await review.calls() == 1,
                  "an ssh run by a job the Claude session detached reuses that session's SSH approval")
        } else {
            let calls = await review.calls()
            let offered = await review.scopes()?.options.map(\.kind)
            check(calls == 2 && offered == [.requestingCommand],
                  "without the session record, the detached job's ssh is reviewed again, for itself only")
        }
    }
}

// MARK: - Concurrent reviews, Deny propagation, and requester liveness
//
// `GatedPolicyReview` (DenialPropagationTests) holds each review until the
// test answers it.

/// One registered synthetic key and a verified session binding, for tests that
/// drive a real `SSHAgentServer` socket. Synthetic keys only.
struct SSHSocketSigningFixture {
    let service: SSHSigningService
    let reviewTurns: ConsentQueue
    let bindMessage: Data
    let signMessage: Data
    let resolutions: SSHResolutionCount

    static func make(
        policyReview: any PolicyReviewProvider,
        reviewTurns: ConsentQueue = ConsentQueue(),
        decisionLog: DecisionLog? = nil
    ) async throws -> SSHSocketSigningFixture {
        let signingKey = try Ed25519SSHFixture(seed: 151)
        let hostKey = try Ed25519SSHFixture(seed: 157)
        let session = Data(repeating: 0x73, count: 32)
        let reference = "csec://ssh-liveness/key"
        let counter = SSHFixtureCounter()
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(SSHFixtureProvider(
            scheme: "csec", values: [reference: signingKey.privateKeyPEM], counter: counter
        ))
        let service = SSHSigningService(
            resolver: resolver,
            catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [SSHKeyMetadata(
                reference: reference, fingerprint: sshFingerprint(signingKey.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: signingKey.publicKeyBlob,
                label: "liveness fixture"
            )])),
            consent: SSHFixtureConsent(), policyReview: policyReview,
            allowUnverifiedCallersForTesting: true,
            knownHostsLookup: SSHKnownHostsLookup { _ in ["liveness.example.test"] },
            terminalInspection: .unavailable,
            reviewTurns: reviewTurns,
            decisionLog: decisionLog
        )
        return SSHSocketSigningFixture(
            service: service,
            reviewTurns: reviewTurns,
            bindMessage: try sessionBindMessage(host: hostKey, sessionIdentifier: session),
            signMessage: signRequest(
                publicKeyBlob: signingKey.publicKeyBlob,
                signedData: userAuthenticationRequest(
                    sessionIdentifier: session, remoteUser: "deploy",
                    publicKeyBlob: signingKey.publicKeyBlob, hostKeyBlob: hostKey.publicKeyBlob
                )
            ),
            resolutions: SSHResolutionCount(counter: counter)
        )
    }
}

/// How many times the fixture's provider resolved its key.
struct SSHResolutionCount: Sendable {
    fileprivate let counter: SSHFixtureCounter
    func value() async -> Int { await counter.count() }
}

private final class SSHFixtureCallCount: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func bump() { lock.lock(); value += 1; lock.unlock() }
    var count: Int { lock.lock(); defer { lock.unlock() }; return value }
}

/// Concurrent same-shape connections share one review; a human Deny answers the
/// identical requests already waiting and ends the denied connection's signing;
/// a requester that has exited is never shown. ssh-duplicates.md §9, T1–T6.
private func sshConcurrentReviewTests() async throws {
    let nativeKey = try Ed25519SSHFixture(seed: 171)
    let providerKey = try Ed25519SSHFixture(seed: 173)
    let hostKey = try Ed25519SSHFixture(seed: 179)
    let otherHostKey = try Ed25519SSHFixture(seed: 181)
    let session = Data(repeating: 0x5a, count: 32)
    let binding = try SSHDestinationBinding(
        hostKeyBlob: hostKey.publicKeyBlob, sessionIdentifier: session,
        signature: hostKey.signatureBlob(for: session), isForwarding: false
    )
    let otherBinding = try SSHDestinationBinding(
        hostKeyBlob: otherHostKey.publicKeyBlob, sessionIdentifier: session,
        signature: otherHostKey.signatureBlob(for: session), isForwarding: false
    )
    // Two interactive terminals; ssh processes directly under each, and one
    // under a Claude Code session inside the first terminal.
    let fish: pid_t = 76_000
    let otherFish: pid_t = 77_000
    let sshA: pid_t = 76_001, sshB: pid_t = 76_002, sshC: pid_t = 76_003
    let sshD: pid_t = 76_004, sshE: pid_t = 76_005
    let claude: pid_t = 76_010, claudeShell: pid_t = 76_020, claudeSSH: pid_t = 76_021
    let otherSSH: pid_t = 77_001
    let parents: [pid_t: pid_t] = [
        fish: 1, otherFish: 1, sshA: fish, sshB: fish, sshC: fish, sshD: fish, sshE: fish,
        claude: fish, claudeShell: claude, claudeSSH: claudeShell,
        otherSSH: otherFish,
    ]
    let starts = Dictionary(uniqueKeysWithValues: parents.keys.map { ($0, UInt64($0) + 300) })
    let fixtures = [
        ("csec://ssh-concurrent/native", nativeKey),
        ("op://SSH Concurrent/Provider/private key", providerKey),
    ]

    struct Harness {
        let service: SSHSigningService
        let gate: GatedPolicyReview
        let turns: ConsentQueue
        let resolutions: SSHFixtureCounter
    }

    func makeHarness(
        gate: GatedPolicyReview = GatedPolicyReview(),
        changes: SSHFixtureProcessChanges = SSHFixtureProcessChanges(),
        knownHosts: SSHKnownHostsLookup = SSHKnownHostsLookup { _ in ["concurrent.example.test"] },
        terminal: TerminalSessionInspector = .unavailable,
        approvalWaitLimit: Duration = .seconds(1_200),
        decisionLog: DecisionLog? = nil,
        preserveLineage: Bool = false
    ) async throws -> Harness {
        let counter = SSHFixtureCounter()
        let resolver = SecretResolver(cache: NullSecretCache())
        var keys: [SSHKeyMetadata] = []
        for (uri, fixture) in fixtures {
            let reference = try SecretRef(uri)
            await resolver.register(SSHFixtureProvider(
                scheme: reference.scheme, values: [uri: fixture.privateKeyPEM], counter: counter
            ))
            keys.append(SSHKeyMetadata(
                reference: uri, fingerprint: sshFingerprint(fixture.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: fixture.publicKeyBlob,
                label: "concurrent key"
            ))
        }
        let names: [pid_t: String] = [
            fish: "fish", otherFish: "fish", claude: "2.1.252", claudeShell: "zsh",
        ]
        let inspection = ProcessInspection(
            startTime: { changes.startTime($0, fallback: starts[$0]) },
            parent: { changes.parent($0, fallback: parents[$0]) },
            name: { names[$0] ?? "ssh" },
            executablePath: {
                $0 == claude ? "/Users/test/.local/share/claude/versions/2.1.252" : "/usr/bin/ssh"
            },
            hasControllingTerminal: { $0 == fish || $0 == otherFish },
            lineageParent: { preserveLineage ? parents[$0] : changes.parent($0, fallback: parents[$0]) }
        )
        let turns = ConsentQueue()
        let service = SSHSigningService(
            resolver: resolver,
            catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: keys)),
            consent: SSHFixtureConsent(),
            policyReview: QueuedPolicyReview(underlying: gate, queue: ConsentQueue()),
            allowUnverifiedCallersForTesting: true, processInspection: inspection,
            knownHostsLookup: knownHosts, terminalInspection: terminal,
            reviewTurns: turns, decisionLog: decisionLog,
            approvalWaitLimit: { approvalWaitLimit }
        )
        return Harness(service: service, gate: gate, turns: turns, resolutions: counter)
    }

    func signedData(key: Ed25519SSHFixture, destination: SSHDestinationBinding, user: String) -> Data {
        userAuthenticationRequest(
            sessionIdentifier: destination.sessionIdentifier, remoteUser: user,
            publicKeyBlob: key.publicKeyBlob, hostKeyBlob: destination.hostKeyBlob
        )
    }

    /// Start one signing request; its result is whether a valid signature came back.
    func start(
        _ harness: Harness, pid: pid_t, key: Ed25519SSHFixture? = nil,
        destination: SSHDestinationBinding? = nil, user: String = "deploy", startTime: UInt64? = nil
    ) -> Task<Bool, Never> {
        let key = key ?? nativeKey
        let destination = destination ?? binding
        let message = signedData(key: key, destination: destination, user: user)
        let service = harness.service
        let caller = CallerInfo(pid: pid, startTime: startTime ?? starts[pid]!, description: "synthetic SSH")
        return Task {
            guard let signature = try? await service.signSSHAuthentication(
                publicKeyBlob: key.publicKeyBlob, signedData: message, flags: 0,
                binding: destination, caller: caller
            ) else { return false }
            return key.verifies(signatureBlob: signature, message: message)
        }
    }

    func results(_ tasks: [Task<Bool, Never>]) async -> [Bool] {
        var values: [Bool] = []
        for task in tasks { values.append(await task.value) }
        return values
    }

    /// Start requests one at a time, each only once the previous one holds
    /// its place — the first on screen, the rest queued on the SSH review turn
    /// — so which request the first decision answers is fixed.
    func startInOrder(
        _ harness: Harness, _ requests: [() -> Task<Bool, Never>]
    ) async -> [Task<Bool, Never>] {
        var tasks: [Task<Bool, Never>] = []
        for request in requests {
            let waiters = tasks.count
            tasks.append(request())
            _ = await eventuallyTrue {
                let pending = await harness.gate.pendingCount
                let waiting = await harness.turns.waitingCount
                return pending == 1 && waiting == waiters
            }
        }
        return tasks
    }

    /// Wait until one review is on screen and `waiters` more requests queue
    /// behind it on the SSH review turn.
    func queued(_ harness: Harness, waiters: Int) async -> Bool {
        await eventuallyTrue {
            let pending = await harness.gate.pendingCount
            let waiting = await harness.turns.waitingCount
            return pending == 1 && waiting == waiters
        }
    }

    // T1: three concurrent same-shape connections from one terminal → one
    // review and three valid signatures, for either storage backend.
    for (uri, key) in fixtures {
        let scheme = uri.hasPrefix("op:") ? "op" : "csec"
        let harness = try await makeHarness()
        let tasks = await startInOrder(harness, [sshA, sshB, sshC].map { pid in
            { start(harness, pid: pid, key: key) }
        })
        check(await queued(harness, waiters: 2),
              "T1: concurrent same-shape SSH requests wait behind one review (\(scheme))")
        await harness.gate.decide(.approve(nil))
        // Any further panel is a regression: answer it so the check fails
        // rather than the suite waiting on a review nobody answers.
        await harness.gate.decideAll(.deny(.authenticationFailed))
        let signed = await results(tasks)
        let reviews = await harness.gate.reviews
        check(signed == [true, true, true] && reviews == 1,
              "T1: three concurrent same-shape SSH connections get one review and three valid signatures (\(scheme))")
    }

    // T2: "this command only" still reviews each connection: the waiters pass
    // the unchanged grant check, which a command-rooted grant does not satisfy.
    do {
        let harness = try await makeHarness()
        let tasks = await startInOrder(harness, [sshA, sshB, sshC].map { pid in
            { start(harness, pid: pid) }
        })
        _ = await queued(harness, waiters: 2)
        await harness.gate.decideAll(.approve(.requestingCommand))
        let signed = await results(tasks)
        let reviews = await harness.gate.reviews
        check(signed == [true, true, true] && reviews == 3,
              "T2: a command-only SSH approval still gives each concurrent connection its own review")
    }

    // T3: two terminals are two questions.
    do {
        let harness = try await makeHarness()
        let tasks = await startInOrder(harness, [
            { start(harness, pid: sshA) }, { start(harness, pid: otherSSH) },
        ])
        _ = await queued(harness, waiters: 1)
        await harness.gate.decideAll(.approve(nil))
        let signed = await results(tasks)
        let reviews = await harness.gate.reviews
        check(signed == [true, true] && reviews == 2,
              "T3: concurrent SSH requests from two terminals get two reviews")
    }

    // T4: a different server identity, or a different remote user, is a
    // different question.
    for (label, second) in [
        ("host key", { start($0, pid: sshB, destination: otherBinding) }),
        ("remote user", { start($0, pid: sshB, user: "other-user") }),
    ] as [(String, (Harness) -> Task<Bool, Never>)] {
        let harness = try await makeHarness()
        let tasks = await startInOrder(harness, [
            { start(harness, pid: sshA) }, { second(harness) },
        ])
        _ = await queued(harness, waiters: 1)
        await harness.gate.decideAll(.approve(nil))
        let signed = await results(tasks)
        let reviews = await harness.gate.reviews
        check(signed == [true, true] && reviews == 2,
              "T4: concurrent SSH requests for two \(label)s get two reviews")
    }

    // T5: a human Deny answers the identical requests already waiting behind
    // it: one review, no signatures. A request that arrives afterwards is a new
    // question and gets its own panel — this is not a cooldown.
    do {
        let harness = try await makeHarness()
        let tasks = await startInOrder(harness, [sshA, sshB, sshC].map { pid in
            { start(harness, pid: pid) }
        })
        _ = await queued(harness, waiters: 2)
        await harness.gate.decide(.deny(.human(decidedAt: .now)))
        await harness.gate.decideAll(.deny(.authenticationFailed))
        let signed = await results(tasks)
        let reviews = await harness.gate.reviews
        let resolved = await harness.resolutions.count()
        check(signed == [false, false, false] && reviews == 1 && resolved == 0,
              "T5: a human SSH Deny refuses the identical waiting requests without another panel or key resolution")
        await harness.gate.decideAll(.approve(nil))
        let later = await start(harness, pid: sshD).value
        let reviewsAfterLater = await harness.gate.reviews
        check(later && reviewsAfterLater == 2,
              "a later identical SSH request after a human Deny gets its own review")
        // A connection refused by that Deny is itself a denied connection: its
        // next catalog key gets no signature and no panel.
        let nextKey = await start(harness, pid: sshB, key: providerKey).value
        let reviewsAfterNextKey = await harness.gate.reviews
        check(!nextKey && reviewsAfterNextKey == 2,
              "a connection refused by a human Deny gets no further signature and no panel")
    }

    // The Deny is ordered by when the human decided, not by when its outcome
    // reaches the service: an identical ssh that arrived after the decision
    // instant, while the outcome was still on its way back, gets its own
    // panel and keeps its signing; one that was waiting before is refused.
    do {
        let harness = try await makeHarness()
        let tasks = await startInOrder(harness, [
            { start(harness, pid: sshA) }, { start(harness, pid: sshB) },
        ])
        let decidedAt = ContinuousClock.now
        let afterDecision = start(harness, pid: sshD)
        check(await queued(harness, waiters: 2),
              "an SSH request arrives after the human decided, before the outcome returns")
        await harness.gate.decide(.deny(.human(decidedAt: decidedAt)))
        await harness.gate.decideAll(.approve(nil))
        let signed = await results(tasks + [afterDecision])
        let reviews = await harness.gate.reviews
        check(signed == [false, false, true] && reviews == 2,
              "an SSH request that arrived after the decision instant gets its own panel; one waiting before is refused")
    }

    // The SSH rule is "the same default root", not "inside it": an ssh under a
    // Claude session in the denied terminal defaults to that session, so it is
    // a different question even though it runs inside the denied root.
    do {
        let harness = try await makeHarness()
        let tasks = await startInOrder(harness, [
            { start(harness, pid: sshA) }, { start(harness, pid: claudeSSH) },
        ])
        await harness.gate.decide(.deny(.human(decidedAt: .now)))
        check(await eventuallyTrue { await harness.gate.reviews == 2 },
              "an identical SSH request inside the denied root but with its own default root is reviewed")
        await harness.gate.decideAll(.approve(nil))
        let reviewedPIDs = await harness.gate.reviewedPIDs
        check(await results(tasks) == [false, true] && reviewedPIDs == [sshA, claudeSSH],
              "a human SSH Deny refuses only waiters offered the same default root")
    }

    // Only the human's Deny propagates: a requester that went away, or a Touch
    // ID error, leaves the waiting requests to be reviewed on their own.
    for reason in [AccessPolicyDenialReason.requesterGone, .authenticationFailed] {
        let harness = try await makeHarness()
        let tasks = await startInOrder(harness, [sshA, sshB, sshC].map { pid in
            { start(harness, pid: pid) }
        })
        _ = await queued(harness, waiters: 2)
        await harness.gate.decide(.deny(reason))
        check(await eventuallyTrue { await harness.gate.reviews == 2 },
              "T5: after a \(reason) SSH denial the next identical request is reviewed")
        await harness.gate.decideAll(.approve(nil))
        let signed = await results(tasks)
        let reviews = await harness.gate.reviews
        check(signed == [false, true, true] && reviews == 2,
              "T5: a \(reason) SSH denial does not propagate: 2 reviews, 2 signatures")
        let sameConnection = start(harness, pid: sshA, key: providerKey)
        check(await eventuallyTrue { await harness.gate.reviews == 3 },
              "a \(reason) SSH denial does not end that connection's signing")
        await harness.gate.decideAll(.approve(nil))
        check(await sameConnection.value, "the connection signs after its next approval (\(reason))")
    }

    // A human Deny does not reach a request from another terminal.
    do {
        let harness = try await makeHarness()
        let tasks = await startInOrder(harness, [
            { start(harness, pid: sshA) }, { start(harness, pid: otherSSH) },
        ])
        _ = await queued(harness, waiters: 1)
        await harness.gate.decide(.deny(.human(decidedAt: .now)))
        check(await eventuallyTrue { await harness.gate.reviews == 2 },
              "an identical SSH request from another terminal is reviewed after a human Deny")
        await harness.gate.decideAll(.approve(nil))
        check(await results(tasks) == [false, true],
              "a human SSH Deny refuses only waiters inside its terminal")
    }

    // T6: a requester that exits while its review is being built is never
    // shown, its terminal is never looked up, and no key is resolved.
    do {
        let changes = SSHFixtureProcessChanges()
        let terminalLookups = SSHFixtureCallCount()
        let harness = try await makeHarness(
            changes: changes,
            knownHosts: SSHKnownHostsLookup { _ in
                changes.recycle(sshE)
                return ["concurrent.example.test"]
            },
            terminal: TerminalSessionInspector(
                environment: { _ in nil }, parent: { _ in nil },
                terminalName: { _ in terminalLookups.bump(); return nil },
                titleQuery: { _ in nil }
            )
        )
        let signed = await start(harness, pid: sshE).value
        let reviews = await harness.gate.reviews
        let resolved = await harness.resolutions.count()
        check(!signed && reviews == 0 && resolved == 0 && terminalLookups.count == 0,
              "T6: an SSH requester that exits before its review is shown gets no review, no terminal lookup, and no key")
    }
    do {
        let changes = SSHFixtureProcessChanges()
        let harness = try await makeHarness(
            changes: changes,
            terminal: TerminalSessionInspector(
                environment: { _ in nil }, parent: { _ in nil },
                terminalName: { _ in changes.recycle(sshE); return nil },
                titleQuery: { _ in nil }
            )
        )
        let signed = await start(harness, pid: sshE).value
        let reviews = await harness.gate.reviews
        check(!signed && reviews == 0,
              "an SSH requester that exits during its terminal lookup is not reviewed")
    }

    // D: after a human Deny on a connection, ssh offers the next catalog key on
    // that same connection; it gets no signature and no second panel.
    do {
        let harness = try await makeHarness(gate: GatedPolicyReview(automatic: .deny(.human(decidedAt: .now))))
        let connection = SSHAgentConnection(
            provider: harness.service,
            caller: CallerInfo(pid: sshA, startTime: starts[sshA]!, description: "synthetic SSH")
        )
        _ = await connection.handle(try sessionBindMessage(host: hostKey, sessionIdentifier: session))
        let first = await connection.handle(signRequest(
            publicKeyBlob: nativeKey.publicKeyBlob,
            signedData: signedData(key: nativeKey, destination: binding, user: "deploy")
        ))
        let next = await connection.handle(signRequest(
            publicKeyBlob: providerKey.publicKeyBlob,
            signedData: signedData(key: providerKey, destination: binding, user: "deploy")
        ))
        let reviews = await harness.gate.reviews
        check(first == Data([5]) && next == Data([5]) && reviews == 1,
              "a human-denied SSH connection's next key is refused with no review")
        check(await harness.resolutions.count() == 0,
              "a human-denied SSH connection never reaches a key provider")
        await harness.gate.decideAll(.approve(nil))
        let otherConnection = await start(harness, pid: sshB, key: providerKey).value
        let reviewsAfterOther = await harness.gate.reviews
        check(otherConnection && reviewsAfterOther == 2,
              "another connection after a human SSH Deny is reviewed as usual")
    }

    // W: a coding agent's signing request nobody answers (csec-ia3q).
    func scratchLog() async -> (DecisionLog, String) {
        let directory = NSTemporaryDirectory() + "cs-selftest-ssh-wait-\(UUID().uuidString.lowercased())"
        let log = DecisionLog(
            directory: SealedRecordDirectory(path: directory),
            stores: .processLocal(InMemoryProtectedItemBackend()),
            bootSessionUUID: "boot-ssh-wait"
        )
        _ = await log.open()
        return (log, directory)
    }
    func records(_ log: DecisionLog, _ kind: DecisionLogRecord.Kind) async -> [DecisionLogRecord] {
        let page = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [kind]))
        return page.records
    }

    // A: parent loss, including a lineage-retained orphan, before and after
    // presentation. Another live requester is not a propagated Deny.
    for shown in [true, false] {
        let (log, directory) = await scratchLog()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let changes = SSHFixtureProcessChanges()
        let harness = try await makeHarness(changes: changes, decisionLog: log, preserveLineage: true)
        let first = start(harness, pid: sshA)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let second = start(harness, pid: sshB, key: shown ? nativeKey : providerKey)
        _ = await queued(harness, waiters: 1)
        changes.detach(shown ? sshA : sshB)
        let orphanSigned = shown ? await first.value : await second.value
        let kind: DecisionLogRecord.Kind = shown ? .panel : .withdrawn
        let ended = await records(log, kind)
        check(!orphanSigned && ended.count == 1 && ended[0].outcome == .requesterGone
              && ended[0].detail?.contains("abandoned:") == true
              && ended[0].detail?.contains("waited ") == true
              && ended[0].requester?.rootPID == fish,
              "orphan SSH: \(shown ? "shown" : "queued") request logs its original root, parent loss and wait")
        if !shown {
            check(await harness.gate.reviews == 1, "orphan SSH: a queued orphan is never presented")
        }
        let next = await start(harness, pid: shown ? sshA : sshB, key: providerKey).value
        let refusals = await records(log, .refusal)
        check(!next && refusals.last?.outcome == .requesterGone,
              "orphan SSH: the same live ssh's next key is refused without another review")
        await harness.gate.decideAll(.approve(nil))
        let survivor = shown ? await second.value : await first.value
        check(survivor, "orphan SSH: the other live request is reviewed and signs normally")
        // A new process at the same pid is not the abandoned connection.
        let recycledPID = shown ? sshA : sshB
        changes.recycle(recycledPID)
        check(await start(harness, pid: recycledPID, key: providerKey, startTime: 99_999).value,
              "orphan SSH: a recycled pid is not poisoned by the abandoned-requester list")
    }
    do {
        let (log, directory) = await scratchLog()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let changes = SSHFixtureProcessChanges()
        let gate = GatedPolicyReview(onApproval: { changes.recycle(fish) })
        let harness = try await makeHarness(gate: gate, changes: changes, decisionLog: log)
        let pending = start(harness, pid: sshA)
        _ = await eventuallyTrue { await gate.pendingCount == 1 }
        await gate.decide(.approve(nil))
        let signed = await pending.value, resolutions = await harness.resolutions.count()
        check(!signed && resolutions == 0,
              "orphan SSH: a scope lost at approval is refused before key resolution")
        let panels = await records(log, .panel), failures = await records(log, .deliveryFailed)
        check(panels.count == 1 && panels[0].outcome == .approved && failures.count == 1,
              "orphan SSH: that approval and delivery_failed are each recorded once")
    }

    // W1: on screen, an ssh under Claude Code is withdrawn at its deadline,
    // logged as withdrawn and timed out; its next key gets no fresh wait.
    do {
        let (log, directory) = await scratchLog()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let harness = try await makeHarness(approvalWaitLimit: .milliseconds(1_500), decisionLog: log)
        let started = ContinuousClock.now
        let signed = await start(harness, pid: claudeSSH).value
        let elapsed = started.duration(to: .now)
        let cancelled = await harness.gate.cancelledReviews
        check(!signed && cancelled == 1 && elapsed >= .milliseconds(1_450) && elapsed < .seconds(6),
              "an unanswered SSH review from Claude Code is withdrawn at its deadline (\(elapsed))")
        let withdrawn = await records(log, .withdrawn)
        check(withdrawn.count == 1 && withdrawn.first?.outcome == .timedOut
              && withdrawn.first?.detail?.contains("shown, not answered") == true
              && withdrawn.first?.decider == nil,
              "the withdrawn SSH review is logged as withdrawn, timed out, never as a Deny")
        let nextStarted = ContinuousClock.now
        let next = await start(harness, pid: claudeSSH, key: providerKey).value
        let reviews = await harness.gate.reviews
        check(!next && reviews == 1 && nextStarted.duration(to: .now) < .seconds(1),
              "the withdrawn ssh's next key is refused at once, with no second wait")
        let refusals = await records(log, .refusal)
        check(refusals.count == 1 && refusals.first?.outcome == .timedOut,
              "that refusal is logged as timed out")
        check(await harness.resolutions.count() == 0, "a withdrawn SSH request never reaches a key provider")
    }

    // W2: an ssh from a terminal keeps waiting past the coding-agent limit.
    do {
        let harness = try await makeHarness(approvalWaitLimit: .milliseconds(300))
        let pending = start(harness, pid: sshA)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        try? await Task.sleep(for: .milliseconds(900))
        let stillPending = await harness.gate.pendingCount
        check(stillPending == 1, "a terminal's SSH review keeps waiting past the coding-agent limit")
        await harness.gate.decide(.approve(nil))
        check(await pending.value, "and signs when the human approves")
    }

    // W3: queued on the SSH review turn behind a terminal's panel, a Claude
    // Code ssh lapses on its own clock and is never shown.
    do {
        let (log, directory) = await scratchLog()
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let harness = try await makeHarness(approvalWaitLimit: .milliseconds(1_000), decisionLog: log)
        let terminalSSH = start(harness, pid: sshA)
        _ = await eventuallyTrue { await harness.gate.pendingCount == 1 }
        let agentSSH = start(harness, pid: claudeSSH)
        check(await queued(harness, waiters: 1), "a Claude Code ssh queues behind a terminal's SSH panel")
        let agentSigned = await agentSSH.value
        let reviews = await harness.gate.reviews
        check(!agentSigned && reviews == 1, "the queued Claude Code ssh lapses without ever being shown")
        let withdrawn = await records(log, .withdrawn)
        check(withdrawn.count == 1 && withdrawn.first?.outcome == .timedOut
              && withdrawn.first?.detail?.contains("; never shown; nobody answered within") == true,
              "the queued ssh is logged as withdrawn, timed out, never shown (\(withdrawn.map { "\($0.outcome?.rawValue ?? "-") \($0.detail ?? "")" }))")
        await harness.gate.decide(.approve(nil))
        check(await terminalSSH.value, "the terminal's SSH review it waited behind is unaffected")
    }
}

func sshProtectionTests() async {
    sshKeyFileVerdictTests()
    print("\n# SSH protection (synthetic keys only)")

    do {
        let nativeKey = try Ed25519SSHFixture(seed: 1)
        let providerKey = try Ed25519SSHFixture(seed: 65)
        let hostKey = try Ed25519SSHFixture(seed: 129)
        let parsed = try SSHPrivateKey.parse(nativeKey.privateKeyPEM)

        check(parsed.algorithm == "ssh-ed25519"
              && parsed.publicKeyBlob == nativeKey.publicKeyBlob
              && parsed.comment == "synthetic-csec-selftest",
              "an unencrypted OpenSSH Ed25519 key parses with matching public metadata")

        let probe = Data("synthetic SSH signing probe".utf8)
        let parsedSignature = try parsed.sign(probe, flags: 0)
        check(nativeKey.verifies(signatureBlob: parsedSignature, message: probe),
              "the parsed private key returns a valid SSH signature blob")
        do {
            _ = try parsed.sign(probe, flags: 0x02)
            check(false, "Ed25519 signing rejects RSA agent flags")
        } catch {
            check(true, "Ed25519 signing rejects RSA agent flags")
        }

        let edPKCS8 = try SSHPrivateKey.parse(
            ed25519PKCS8(seed: nativeKey.key.rawRepresentation)
        )
        check(edPKCS8.publicKeyBlob == nativeKey.publicKeyBlob,
              "an Ed25519 PKCS#8 key derives the same public identity")

        let p256Scalar = ecdsaFixtureScalar(length: 32)
        let p256Key = try P256.Signing.PrivateKey(rawRepresentation: p256Scalar)
        let p256Fixture = ecdsaOpenSSHFixture(
            curve: "nistp256",
            scalar: p256Scalar,
            publicPoint: p256Key.publicKey.x963Representation
        )
        let parsedP256 = try SSHPrivateKey.parse(p256Fixture.pem)
        let p256Signature = try P256.Signing.ECDSASignature(rawRepresentation:
            rawECDSASignature(
                try parsedP256.sign(probe, flags: 0),
                algorithm: "ecdsa-sha2-nistp256",
                scalarBytes: 32
            )
        )
        check(parsedP256.publicKeyBlob == p256Fixture.publicKeyBlob
              && p256Key.publicKey.isValidSignature(p256Signature, for: probe),
              "OpenSSH ECDSA P-256 keys parse and sign with canonical SSH mpints")
        let parsedSEC1 = try SSHPrivateKey.parse(ecSEC1P256(
            scalar: p256Scalar,
            publicPoint: p256Key.publicKey.x963Representation
        ))
        check(parsedSEC1.publicKeyBlob == p256Fixture.publicKeyBlob,
              "legacy SEC1 P-256 keys derive the expected SSH public identity")

        let p384Scalar = ecdsaFixtureScalar(length: 48)
        let p384Key = try P384.Signing.PrivateKey(rawRepresentation: p384Scalar)
        let p384Fixture = ecdsaOpenSSHFixture(
            curve: "nistp384",
            scalar: p384Scalar,
            publicPoint: p384Key.publicKey.x963Representation
        )
        let parsedP384 = try SSHPrivateKey.parse(p384Fixture.pem)
        let p384Signature = try P384.Signing.ECDSASignature(rawRepresentation:
            rawECDSASignature(
                try parsedP384.sign(probe, flags: 0),
                algorithm: "ecdsa-sha2-nistp384",
                scalarBytes: 48
            )
        )
        check(parsedP384.publicKeyBlob == p384Fixture.publicKeyBlob
              && p384Key.publicKey.isValidSignature(p384Signature, for: probe),
              "OpenSSH ECDSA P-384 keys parse and sign")

        let p521Scalar = ecdsaFixtureScalar(length: 66)
        let p521Key = try P521.Signing.PrivateKey(rawRepresentation: p521Scalar)
        let p521Fixture = ecdsaOpenSSHFixture(
            curve: "nistp521",
            scalar: p521Scalar,
            publicPoint: p521Key.publicKey.x963Representation
        )
        let parsedP521 = try SSHPrivateKey.parse(p521Fixture.pem)
        let p521Signature = try P521.Signing.ECDSASignature(rawRepresentation:
            rawECDSASignature(
                try parsedP521.sign(probe, flags: 0),
                algorithm: "ecdsa-sha2-nistp521",
                scalarBytes: 66
            )
        )
        check(parsedP521.publicKeyBlob == p521Fixture.publicKeyBlob
              && p521Key.publicKey.isValidSignature(p521Signature, for: probe),
              "OpenSSH ECDSA P-521 keys parse and sign")

        let rsaFixture = try generatedRSAPEM(bits: 2_048)
        let parsedRSA = try SSHPrivateKey.parse(rsaFixture.pem)
        let rsaPublicKey = try SecKeyCopyPublicKey(rsaFixture.privateKey).unwrap(
            or: SSHFixtureError.rsaPublicKey
        )
        let rsaSHA256 = try rawSSHSignature(
            try parsedRSA.sign(probe, flags: 0x02), algorithm: "rsa-sha2-256"
        )
        let rsaSHA512 = try rawSSHSignature(
            try parsedRSA.sign(probe, flags: 0x04), algorithm: "rsa-sha2-512"
        )
        var rsaError: Unmanaged<CFError>?
        let rsa256Valid = SecKeyVerifySignature(
            rsaPublicKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            probe as CFData,
            rsaSHA256 as CFData,
            &rsaError
        )
        rsaError = nil
        let rsa512Valid = SecKeyVerifySignature(
            rsaPublicKey,
            .rsaSignatureMessagePKCS1v15SHA512,
            probe as CFData,
            rsaSHA512 as CFData,
            &rsaError
        )
        check(parsedRSA.algorithm == "ssh-rsa" && rsa256Valid && rsa512Valid,
              "legacy PEM RSA-2048 keys sign only with RSA-SHA2-256/512")
        do {
            _ = try parsedRSA.sign(probe, flags: 0)
            check(false, "RSA/SHA-1 signing is unavailable")
        } catch {
            check(true, "RSA/SHA-1 signing is unavailable")
        }
        let weakRSA = try generatedRSAPEM(bits: 1_024)
        do {
            _ = try SSHPrivateKey.parse(weakRSA.pem)
            check(false, "RSA keys below 2048 bits are rejected")
        } catch let error as SSHProtectionError {
            check(error == .weakRSAKey, "RSA keys below 2048 bits are rejected")
        }

        let badCheckints = try Ed25519SSHFixture(seed: 2, mismatchedCheckints: true)
        do {
            _ = try SSHPrivateKey.parse(badCheckints.privateKeyPEM)
            check(false, "OpenSSH private-key checkint mismatch is rejected")
        } catch {
            check(true, "OpenSSH private-key checkint mismatch is rejected")
        }
        do {
            _ = try SSHPrivateKey.parse(Data(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAA==\n"
                    .appending("-----END ENCRYPTED PRIVATE KEY-----\n").utf8
            ))
            check(false, "encrypted private keys are rejected explicitly")
        } catch let error as SSHProtectionError {
            check(error == .encryptedPrivateKey, "encrypted private keys are rejected explicitly")
        }
        do {
            _ = try SSHPrivateKey.parse(Data("not a private-key file\n".utf8) + nativeKey.privateKeyPEM)
            check(false, "a PEM key embedded in unrelated content is rejected")
        } catch {
            check(true, "a PEM key embedded in unrelated content is rejected")
        }

        let sessionIdentifier = Data((0..<32).map { UInt8(200 &+ $0) })
        let hostSignature = try hostKey.signatureBlob(for: sessionIdentifier)
        let binding = try SSHDestinationBinding(
            hostKeyBlob: hostKey.publicKeyBlob,
            sessionIdentifier: sessionIdentifier,
            signature: hostSignature,
            isForwarding: false
        )
        check(binding.hostKeyFingerprint == sshFingerprint(hostKey.publicKeyBlob),
              "the destination binding verifies the host signature over the session identifier")

        let encodedHostKey = hostKey.publicKeyBlob.base64EncodedString()
        let knownHostsDocument = Data("""
        # ignored comment
        production.example.test,[production.example.test]:2222 ssh-ed25519 \(encodedHostKey) label
        |1|hashed-name|hash ssh-ed25519 \(encodedHostKey)
        *.example.test ssh-ed25519 \(encodedHostKey)
        @revoked revoked.example.test ssh-ed25519 \(encodedHostKey)
        misleading\u{202e}.example.test ssh-ed25519 \(encodedHostKey)
        unrelated.example.test ssh-ed25519 \(nativeKey.publicKeyBlob.base64EncodedString())
        """.utf8)
        check(SSHKnownHostsLookup.matchingNames(
            in: knownHostsDocument,
            hostKeyFingerprint: binding.hostKeyFingerprint
        ) == ["production.example.test", "[production.example.test]:2222"],
        "the SSH review reverse-matches only concrete safe names for the verified host key")
        check(SSHKnownHostsLookup { _ in [
            "safe.example.test\nmisleading review", "*.example.test", "safe.example.test",
        ] }.names(matchingHostKeyFingerprint: binding.hostKeyFingerprint)
            == ["safe.example.test"],
        "injected known-host context is sanitized and bounded before trusted display")

        let knownHostsDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent("csec-ssh-known-hosts-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: knownHostsDirectory, withIntermediateDirectories: true
        )
        defer { try? FileManager.default.removeItem(at: knownHostsDirectory) }
        let largeKnownHosts = knownHostsDirectory.appendingPathComponent("known_hosts")
        let padding = Data(repeating: 0x23, count: 2 * 1_024 * 1_024)
        try (padding + Data("\n".utf8) + knownHostsDocument).write(to: largeKnownHosts)
        check(SSHKnownHostsLookup.matchingNames(
            inFiles: [largeKnownHosts.path], hostKeyFingerprint: binding.hostKeyFingerprint
        ) == ["production.example.test", "[production.example.test]:2222"],
        "hostnames after the first 2 MiB of a real known_hosts file remain visible")
        let oversizedKnownHosts = try FileHandle(forWritingTo: largeKnownHosts)
        try oversizedKnownHosts.truncate(atOffset: 16 * 1_024 * 1_024 + 1)
        try oversizedKnownHosts.close()
        check(SSHKnownHostsLookup.matchingNames(
            inFiles: [largeKnownHosts.path, knownHostsDirectory.path],
            hostKeyFingerprint: binding.hostKeyFingerprint
        ).isEmpty, "known-host lookup still rejects oversized files and non-regular files")

        let unknownHostReview = SSHAccessReviewDetails(
            hostNames: ["|1|hashed|name", "*.example.test", "bad\nname"],
            remoteUser: "deploy", keyLabel: "id_ecdsa", keyAlgorithm: "ecdsa-sha2-nistp256"
        )
        check(unknownHostReview.hostTitle == "Unknown host"
              && unknownHostReview.hostContext == "No hostname found in known_hosts."
              && unknownHostReview.keyLabel == "id_ecdsa"
              && unknownHostReview.keyAlgorithm == "ECDSA P-256"
              && !unknownHostReview.reason.contains("SHA256:"),
              "an unavailable hostname stays explicit without replacing it with an opaque hash")
        let sharedHostReview = SSHAccessReviewDetails(
            hostNames: ["production.example.test", "staging.example.test", "third.example.test"],
            remoteUser: "deploy\nmisleading", keyLabel: "key\u{202e}label",
            keyAlgorithm: "untrusted\nalgorithm"
        )
        check(sharedHostReview.hostTitle
                == "production.example.test, staging.example.test (+1 more)"
              && sharedHostReview.hostContext.contains("share the same server identity")
              && sharedHostReview.hostNames.count == 3
              && !sharedHostReview.reason.contains("\n")
              && !sharedHostReview.keyLabel.contains("\u{202e}")
              && sharedHostReview.keyAlgorithm == "SSH",
              "shared host identities remain explicit and SSH display metadata is sanitized")

        var rsaSHA1Error: Unmanaged<CFError>?
        guard let rsaSHA1Signature = SecKeyCreateSignature(
            rsaFixture.privateKey,
            .rsaSignatureMessagePKCS1v15SHA1,
            sessionIdentifier as CFData,
            &rsaSHA1Error
        ) as Data? else {
            throw rsaSHA1Error?.takeRetainedValue() ?? SSHFixtureError.rsaKeyGeneration
        }
        var rsaSHA1SignatureWriter = SSHFixtureWriter()
        rsaSHA1SignatureWriter.string("ssh-rsa")
        rsaSHA1SignatureWriter.string(rsaSHA1Signature)
        let legacyRSAHostBinding = try SSHDestinationBinding(
            hostKeyBlob: parsedRSA.publicKeyBlob,
            sessionIdentifier: sessionIdentifier,
            signature: rsaSHA1SignatureWriter.data,
            isForwarding: false
        )
        check(legacyRSAHostBinding.hostKeyFingerprint == sshFingerprint(parsedRSA.publicKeyBlob),
              "destination binding verifies an RSA/SHA-1 host signature already accepted by SSH")

        let hostCertificateAuthority = try Ed25519SSHFixture(seed: 177)
        let hostCertificate = try ed25519HostCertificate(
            host: hostKey,
            certificationAuthority: hostCertificateAuthority
        )
        let certificateBinding = try SSHDestinationBinding(
            hostKeyBlob: hostCertificate,
            sessionIdentifier: sessionIdentifier,
            signature: hostSignature,
            isForwarding: false
        )
        check(certificateBinding.hostKeyBlob == hostCertificate
              && certificateBinding.hostKeyFingerprint == sshFingerprint(hostKey.publicKeyBlob),
              "a CA-verified OpenSSH host certificate binds the exact certificate and underlying key")

        do {
            var invalidCertificate = hostCertificate
            invalidCertificate[invalidCertificate.index(before: invalidCertificate.endIndex)] ^= 1
            _ = try SSHDestinationBinding(
                hostKeyBlob: invalidCertificate,
                sessionIdentifier: sessionIdentifier,
                signature: hostSignature,
                isForwarding: false
            )
            check(false, "a host certificate with an invalid CA signature is rejected")
        } catch {
            check(true, "a host certificate with an invalid CA signature is rejected")
        }
        do {
            _ = try SSHDestinationBinding(
                hostKeyBlob: ed25519HostCertificate(
                    host: hostKey,
                    certificationAuthority: hostCertificateAuthority,
                    certificateType: 1
                ),
                sessionIdentifier: sessionIdentifier,
                signature: hostSignature,
                isForwarding: false
            )
            check(false, "a user certificate cannot be used as a destination host binding")
        } catch let error as SSHProtectionError {
            check(error == .destinationBindingInvalid,
                  "a user certificate cannot be used as a destination host binding")
        }
        do {
            _ = try SSHDestinationBinding(
                hostKeyBlob: hostKey.publicKeyBlob,
                sessionIdentifier: sessionIdentifier,
                signature: hostSignature,
                isForwarding: true
            )
            check(false, "forwarded agent bindings are rejected")
        } catch let error as SSHProtectionError {
            check(error == .forwardedAgentNotAllowed, "forwarded agent bindings are rejected")
        }
        do {
            var invalidSignature = hostSignature
            invalidSignature[invalidSignature.index(before: invalidSignature.endIndex)] ^= 1
            _ = try SSHDestinationBinding(
                hostKeyBlob: hostKey.publicKeyBlob,
                sessionIdentifier: sessionIdentifier,
                signature: invalidSignature,
                isForwarding: false
            )
            check(false, "a destination binding with an invalid host signature is rejected")
        } catch {
            check(true, "a destination binding with an invalid host signature is rejected")
        }

        let rsaAuthentication = userAuthenticationRequest(
            sessionIdentifier: sessionIdentifier,
            remoteUser: "deploy",
            publicKeyBlob: parsedRSA.publicKeyBlob,
            hostKeyBlob: hostKey.publicKeyBlob,
            algorithm: "rsa-sha2-256"
        )
        let parsedRSAAuthentication = try SSHBoundUserAuthentication.parse(
            signedData: rsaAuthentication,
            binding: binding,
            requestedKeyBlob: parsedRSA.publicKeyBlob,
            flags: 0x02
        )
        check(parsedRSAAuthentication.publicKeyAlgorithm == "rsa-sha2-256",
              "RSA user authentication binds the SHA-2 algorithm to its agent flag")
        do {
            _ = try SSHBoundUserAuthentication.parse(
                signedData: rsaAuthentication,
                binding: binding,
                requestedKeyBlob: parsedRSA.publicKeyBlob,
                flags: 0x04
            )
            check(false, "mismatched RSA algorithm and agent flags are rejected")
        } catch {
            check(true, "mismatched RSA algorithm and agent flags are rejected")
        }
        do {
            _ = try SSHBoundUserAuthentication.parse(
                signedData: userAuthenticationRequest(
                    sessionIdentifier: sessionIdentifier,
                    remoteUser: "deploy",
                    publicKeyBlob: parsedRSA.publicKeyBlob,
                    hostKeyBlob: hostKey.publicKeyBlob,
                    algorithm: "ssh-rsa"
                ),
                binding: binding,
                requestedKeyBlob: parsedRSA.publicKeyBlob,
                flags: 0x02
            )
            check(false, "RSA/SHA-1 user-auth algorithm requests are rejected")
        } catch {
            check(true, "RSA/SHA-1 user-auth algorithm requests are rejected")
        }

        let signedData = userAuthenticationRequest(
            sessionIdentifier: sessionIdentifier,
            remoteUser: "deploy",
            publicKeyBlob: nativeKey.publicKeyBlob,
            hostKeyBlob: hostKey.publicKeyBlob
        )
        let authentication = try SSHBoundUserAuthentication.parse(
            signedData: signedData,
            binding: binding,
            requestedKeyBlob: nativeKey.publicKeyBlob,
            flags: 0
        )
        check(authentication.remoteUser == "deploy",
              "only an exact destination-bound SSH user-authentication packet is accepted")
        do {
            var trailing = signedData
            trailing.append(0)
            _ = try SSHBoundUserAuthentication.parse(
                signedData: trailing,
                binding: binding,
                requestedKeyBlob: nativeKey.publicKeyBlob,
                flags: 0
            )
            check(false, "trailing fields cannot hide a different signing request")
        } catch {
            check(true, "trailing fields cannot hide a different signing request")
        }
        do {
            _ = try SSHBoundUserAuthentication.parse(
                signedData: userAuthenticationRequest(
                    sessionIdentifier: sessionIdentifier,
                    remoteUser: "deploy\nmisleading review",
                    publicKeyBlob: nativeKey.publicKeyBlob,
                    hostKeyBlob: hostKey.publicKeyBlob
                ),
                binding: binding,
                requestedKeyBlob: nativeKey.publicKeyBlob,
                flags: 0
            )
            check(false, "SSH usernames cannot inject or reorder trusted review text")
        } catch {
            check(true, "SSH usernames cannot inject or reorder trusted review text")
        }

        let nativeReference = "csec://synthetic-ssh/key-one"
        let providerReference = "op://Synthetic SSH/Key Two/private key"
        let nativeCounter = SSHFixtureCounter()
        let providerCounter = SSHFixtureCounter()
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(SSHFixtureProvider(
            scheme: "csec",
            values: [nativeReference: nativeKey.privateKeyPEM],
            counter: nativeCounter
        ))
        await resolver.register(SSHFixtureProvider(
            scheme: "op",
            values: [providerReference: providerKey.privateKeyPEM],
            counter: providerCounter
        ))
        let catalog = SSHKeyCatalog(store: InMemorySSHKeyCatalogStore())
        let consent = SSHFixtureConsent()
        let review = SSHFixtureReview()
        let claudePID: pid_t = 91_000
        let firstWrapperPID: pid_t = 91_010
        let firstSSHPID: pid_t = 91_011
        let secondWrapperPID: pid_t = 91_020
        let secondSSHPID: pid_t = 91_021
        let codexPID: pid_t = 92_000
        let otherWrapperPID: pid_t = 92_010
        let otherSSHPID: pid_t = 92_011
        let processStartTimes: [pid_t: UInt64] = [
            claudePID: 1_001,
            firstWrapperPID: 1_002,
            firstSSHPID: 1_003,
            secondWrapperPID: 1_004,
            secondSSHPID: 1_005,
            codexPID: 2_001,
            otherWrapperPID: 2_002,
            otherSSHPID: 2_003,
        ]
        let processParents: [pid_t: pid_t] = [
            firstWrapperPID: claudePID,
            firstSSHPID: firstWrapperPID,
            secondWrapperPID: claudePID,
            secondSSHPID: secondWrapperPID,
            otherWrapperPID: codexPID,
            otherSSHPID: otherWrapperPID,
        ]
        let processNames: [pid_t: String] = [
            claudePID: "2.1.252",
            firstWrapperPID: "zsh",
            firstSSHPID: "ssh",
            secondWrapperPID: "nimbusssh",
            secondSSHPID: "ssh",
            codexPID: "codex",
            otherWrapperPID: "zsh",
            otherSSHPID: "ssh",
        ]
        let processPaths: [pid_t: String] = [
            claudePID: "/Users/test/.local/share/claude/versions/2.1.252",
            firstWrapperPID: "/bin/zsh",
            firstSSHPID: "/usr/bin/ssh",
            secondWrapperPID: "/Users/test/project/bin/nimbusssh",
            secondSSHPID: "/usr/bin/ssh",
            codexPID: "/opt/codex/bin/codex",
            otherWrapperPID: "/bin/zsh",
            otherSSHPID: "/usr/bin/ssh",
        ]
        let processInspection = ProcessInspection(
            startTime: { processStartTimes[$0] },
            parent: { processParents[$0] },
            name: { processNames[$0] },
            executablePath: { processPaths[$0] }
        )
        let service = SSHSigningService(
            resolver: resolver,
            catalog: catalog,
            consent: consent,
            policyReview: review,
            allowUnverifiedCallersForTesting: true,
            processInspection: processInspection,
            knownHostsLookup: SSHKnownHostsLookup { _ in
                ["production.example.test"]
            },
            terminalInspection: .unavailable
        )
        let caller = CallerInfo(
            pid: firstSSHPID,
            startTime: processStartTimes[firstSSHPID] ?? 0,
            description: "first synthetic Claude SSH client"
        )
        let siblingCaller = CallerInfo(
            pid: secondSSHPID,
            startTime: processStartTimes[secondSSHPID] ?? 0,
            description: "sibling synthetic Claude SSH client"
        )
        let otherSessionCaller = CallerInfo(
            pid: otherSSHPID,
            startTime: processStartTimes[otherSSHPID] ?? 0,
            description: "synthetic Codex SSH client"
        )
        let registrations = try await service.register([
            SSHKeyRegistrationIntent(reference: nativeReference, label: "native fixture"),
            SSHKeyRegistrationIntent(reference: providerReference, label: "provider fixture"),
        ], caller: caller)
        check(Set(registrations.map { (try? SecretRef($0.reference).scheme) ?? "" })
              == Set(["csec", "op"]),
              "the SSH catalog registers canonical references from multiple backend schemes")
        let nativeRegistrationResolutions = await nativeCounter.count()
        let providerRegistrationResolutions = await providerCounter.count()
        check(nativeRegistrationResolutions == 1 && providerRegistrationResolutions == 1,
              "registration resolves each backend through SecretResolver exactly once")
        let listed = try await service.listedSSHKeys()
        check(listed.count == 2
              && listed.allSatisfy { !$0.publicKeyBlob.isEmpty && !$0.fingerprint.isEmpty },
              "the catalog retains public metadata for both backends")

        let nativeMetadata = try registrations.first { $0.reference == nativeReference }
            .unwrap(or: SSHFixtureError.malformed)
        let beforeMalformed = await nativeCounter.count()
        do {
            _ = try await service.signSSHAuthentication(
                publicKeyBlob: nativeMetadata.publicKeyBlob,
                signedData: Data("arbitrary payload".utf8),
                flags: 0,
                binding: binding,
                caller: caller
            )
            check(false, "arbitrary signing input is rejected")
        } catch {
            check(true, "arbitrary signing input is rejected")
        }
        check(await nativeCounter.count() == beforeMalformed,
              "an invalid signing request is rejected before its provider is resolved")

        let serviceSignature = try await service.signSSHAuthentication(
            publicKeyBlob: nativeMetadata.publicKeyBlob,
            signedData: signedData,
            flags: 0,
            binding: binding,
            caller: caller
        )
        check(nativeKey.verifies(signatureBlob: serviceSignature, message: signedData),
              "the provider-neutral signing service returns only a valid signature")
        let sshReview = await review.ssh()
        let sshReviewReason = await review.reason()
        check(sshReview?.hostTitle == "production.example.test"
              && sshReview?.keyLabel == "native fixture"
              && sshReview?.remoteUser == "deploy"
              && sshReview?.keyAlgorithm == "Ed25519"
              && sshReviewReason == sshReview?.reason
              && sshReview?.reason.contains("SHA256:") == false,
              "SSH approvals carry the readable host and key as primary facts without fingerprints")
        let reviewsAfterFirstSignature = await review.calls()
        _ = try await service.signSSHAuthentication(
            publicKeyBlob: nativeMetadata.publicKeyBlob,
            signedData: signedData,
            flags: 0,
            binding: binding,
            caller: siblingCaller
        )
        check(await review.calls() == reviewsAfterFirstSignature,
              "sibling SSH wrappers in one coding-agent subtree reuse one review")
        _ = try await service.signSSHAuthentication(
            publicKeyBlob: nativeMetadata.publicKeyBlob,
            signedData: signedData,
            flags: 0,
            binding: binding,
            caller: otherSessionCaller
        )
        check(await review.calls() == reviewsAfterFirstSignature + 1,
              "a different coding-agent process root requires another SSH review")

        try await sshScopeSelectionTests()
        try await sshUnknownHostReviewTests()
        try await sshGrantDurationTests()
        try await sshDetachedJobGrantTests()
        try await sshConcurrentReviewTests()

        let deniedCounter = SSHFixtureCounter()
        let deniedResolver = SecretResolver(cache: NullSecretCache())
        await deniedResolver.register(SSHFixtureProvider(
            scheme: "csec",
            values: [nativeReference: nativeKey.privateKeyPEM],
            counter: deniedCounter
        ))
        let deniedMetadata = SSHKeyMetadata(
            reference: nativeReference,
            fingerprint: sshFingerprint(nativeKey.publicKeyBlob),
            algorithm: "ssh-ed25519",
            publicKeyBlob: nativeKey.publicKeyBlob,
            label: "denied fixture"
        )
        let deniedService = SSHSigningService(
            resolver: deniedResolver,
            catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [deniedMetadata])),
            consent: consent,
            policyReview: SSHDenyFixtureReview(),
            allowUnverifiedCallersForTesting: true,
            processInspection: processInspection,
            terminalInspection: .unavailable
        )
        do {
            _ = try await deniedService.signSSHAuthentication(
                publicKeyBlob: nativeKey.publicKeyBlob,
                signedData: signedData,
                flags: 0,
                binding: binding,
                caller: caller
            )
            check(false, "a denied SSH policy review stops signing")
        } catch {
            check(true, "a denied SSH policy review stops signing")
        }
        check(await deniedCounter.count() == 0,
              "policy denial occurs before private key resolution")

        let connection = SSHAgentConnection(provider: service, caller: caller)
        let identities = await connection.handle(Data([11]))
        var identitiesReader = SSHFixtureReader(identities)
        check(try identitiesReader.byte() == 12
              && identitiesReader.uint32() == 2,
              "the SSH agent lists only catalog public identities")

        var query = SSHFixtureWriter()
        query.byte(27)
        query.string("query")
        let queryResponse = await connection.handle(query.data)
        var queryReader = SSHFixtureReader(queryResponse)
        check(try queryReader.byte() == 29
              && queryReader.text() == "query"
              && queryReader.text() == "session-bind@openssh.com"
              && queryReader.isAtEnd,
              "the SSH agent advertises only the session-binding extension")

        let unboundConnection = SSHAgentConnection(provider: service, caller: caller)
        check(await unboundConnection.handle(signRequest(
            publicKeyBlob: nativeKey.publicKeyBlob, signedData: signedData
        )) == Data([5]),
        "the SSH wire refuses signing before a verified session binding")

        let diagnosticCapture = SSHDiagnosticCapture()
        let diagnosticConnection = SSHAgentConnection(
            provider: service,
            caller: caller,
            failureReporter: { diagnosticCapture.record($0) }
        )
        var invalidHostSignature = hostSignature
        invalidHostSignature[invalidHostSignature.index(before: invalidHostSignature.endIndex)] ^= 1
        var invalidBinding = SSHFixtureWriter()
        invalidBinding.byte(27)
        invalidBinding.string("session-bind@openssh.com")
        invalidBinding.string(hostKey.publicKeyBlob)
        invalidBinding.string(sessionIdentifier)
        invalidBinding.string(invalidHostSignature)
        invalidBinding.byte(0)
        check(await diagnosticConnection.handle(invalidBinding.data) == Data([5])
              && diagnosticCapture.latest()
                == "message=27 reason=destination_binding_invalid "
                    + "host_key_algorithm=ed25519 host_signature_algorithm=ed25519 "
                    + "forwarding=false already_bound=false",
              "session-binding diagnostics contain only fixed algorithm categories and booleans")

        var untrustedHostKey = SSHFixtureWriter()
        untrustedHostKey.string("unknown\nforged-host-metadata")
        let untrustedDiagnosticConnection = SSHAgentConnection(
            provider: service,
            caller: caller,
            failureReporter: { diagnosticCapture.record($0) }
        )
        var unsupportedBinding = SSHFixtureWriter()
        unsupportedBinding.byte(27)
        unsupportedBinding.string("session-bind@openssh.com")
        unsupportedBinding.string(untrustedHostKey.data)
        unsupportedBinding.string(sessionIdentifier)
        unsupportedBinding.string(hostSignature)
        unsupportedBinding.byte(0)
        _ = await untrustedDiagnosticConnection.handle(unsupportedBinding.data)
        check(diagnosticCapture.latest()?.contains("host_key_algorithm=unsupported") == true
              && diagnosticCapture.latest()?.contains("forged-host-metadata") == false,
              "session-binding diagnostics never echo an untrusted wire algorithm")

        check(await connection.handle(try sessionBindMessage(
            host: hostKey, sessionIdentifier: sessionIdentifier
        )) == Data([6]),
        "the SSH wire accepts one verified, non-forwarded session binding")
        let wireResponse = await connection.handle(signRequest(
            publicKeyBlob: nativeKey.publicKeyBlob, signedData: signedData
        ))
        var wireReader = SSHFixtureReader(wireResponse)
        let wireType = try wireReader.byte()
        let wireSignature = try wireReader.string()
        check(wireType == 14 && wireReader.isAtEnd
              && nativeKey.verifies(signatureBlob: wireSignature, message: signedData),
              "the bound SSH wire request returns a valid signature response")
        check(await connection.handle(try sessionBindMessage(
            host: hostKey, sessionIdentifier: sessionIdentifier
        )) == Data([5]),
        "a connection cannot replace or duplicate its destination binding")

        let forwardedConnection = SSHAgentConnection(provider: service, caller: caller)
        check(await forwardedConnection.handle(try sessionBindMessage(
            host: hostKey, sessionIdentifier: sessionIdentifier, forwarding: true
        )) == Data([5]),
        "the SSH wire fails closed for agent forwarding")
        check(await forwardedConnection.handle(Data([17])) == Data([5]),
              "SSH wire mutation operations cannot change the csec catalog")
    } catch {
        check(false, "SSH protection checks succeed (\(error))")
    }
}

private extension Optional {
    func unwrap(or error: @autoclosure () -> Error) throws -> Wrapped {
        guard let value = self else { throw error() }
        return value
    }
}

/// What `protect --ssh`, bulk protect and HA-F11 decide about a key file must
/// match what csecd's registration accepts.
private func sshKeyFileVerdictTests() {
    print("\n# SSH key file verdicts (synthetic keys only)")
    do {
        let edKey = try Ed25519SSHFixture(seed: 9)
        check(SSHKeyFileVerdict.inspect(edKey.privateKeyPEM) == .importable(algorithm: "ssh-ed25519"),
              "an unencrypted OpenSSH ed25519 key is importable")
        let rsa = try generatedRSAPEM(bits: 2_048)
        check(SSHKeyFileVerdict.inspect(rsa.pem) == .importable(algorithm: "ssh-rsa"),
              "a PEM RSA-2048 key is importable as ssh-rsa")

        var bcryptOptions = SSHFixtureWriter()
        bcryptOptions.string(Data(repeating: 7, count: 16))
        bcryptOptions.uint32(16)
        let encrypted = openSSHPrivateKeyPEM(
            publicKeyBlob: edKey.publicKeyBlob, cipher: "aes256-ctr", kdf: "bcrypt",
            kdfOptions: bcryptOptions.data
        ) { writer in
            writer.string(Data(repeating: 0xa5, count: 48))
        }
        let encryptedVerdict = SSHKeyFileVerdict.inspect(encrypted)
        check(encryptedVerdict == .passphraseProtected && !encryptedVerdict.isPlaintextPrivateKey
              && encryptedVerdict.importRefusal != nil,
              "an OpenSSH key encrypted in its binary header is passphrase-protected, not plaintext")
        let encryptedPEM = Data(
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n"
                .appending("-----END RSA PRIVATE KEY-----\n").utf8)
        check(SSHKeyFileVerdict.inspect(encryptedPEM) == .passphraseProtected,
              "a PEM key with an ENCRYPTED Proc-Type is passphrase-protected")

        let dsaPEM = Data(
            "-----BEGIN DSA PRIVATE KEY-----\nMIIBuwIBAAKBgQ==\n-----END DSA PRIVATE KEY-----\n".utf8)
        let dsaVerdict = SSHKeyFileVerdict.inspect(dsaPEM)
        check(dsaVerdict == .obsolete(reason: "DSA") && dsaVerdict.isPlaintextPrivateKey
              && dsaVerdict.importRefusal?.contains("DSA") == true,
              "a PEM DSA key is obsolete plaintext, refused for import with its reason")
        var dssPublic = SSHFixtureWriter()
        dssPublic.string("ssh-dss")
        dssPublic.string(Data(repeating: 1, count: 20))
        let dssOpenSSH = openSSHPrivateKeyPEM(publicKeyBlob: dssPublic.data) { writer in
            writer.string("ssh-dss")
        }
        check(SSHKeyFileVerdict.inspect(dssOpenSSH) == .obsolete(reason: "DSA"),
              "an OpenSSH-format DSA key is obsolete")
        let weakRSA = try generatedRSAPEM(bits: 1_024)
        check(SSHKeyFileVerdict.inspect(weakRSA.pem) == .obsolete(reason: "RSA under 2048 bits"),
              "an RSA key under 2048 bits is obsolete")

        var skPublic = SSHFixtureWriter()
        skPublic.string("sk-ssh-ed25519@openssh.com")
        skPublic.string(Data(repeating: 2, count: 32))
        skPublic.string("ssh:")
        let skKey = openSSHPrivateKeyPEM(publicKeyBlob: skPublic.data) { writer in
            writer.string("sk-ssh-ed25519@openssh.com")
        }
        let skVerdict = SSHKeyFileVerdict.inspect(skKey)
        check(skVerdict == .securityKey && !skVerdict.isPlaintextPrivateKey,
              "a security-key handle is not a plaintext private key")

        let wrapped = Data("<<EOT\n".utf8) + rsa.pem + Data("EOT\n".utf8)
        let wrappedVerdict = SSHKeyFileVerdict.inspect(wrapped)
        check(wrappedVerdict == .unreadable && wrappedVerdict.isPlaintextPrivateKey,
              "a key wrapped in other text (terraform heredoc output) is unreadable plaintext")
        let mismatched = try Ed25519SSHFixture(seed: 3, mismatchedCheckints: true)
        check(SSHKeyFileVerdict.inspect(mismatched.privateKeyPEM) == .unreadable,
              "a corrupt OpenSSH key is unreadable")
        for verdict in [SSHKeyFileVerdict.importable(algorithm: "ssh-ed25519"), dsaVerdict, wrappedVerdict,
                        encryptedVerdict, skVerdict] {
            check(!verdict.label.isEmpty && !(verdict.importRefusal ?? "").contains("-----"),
                  "a verdict's label and refusal are value-free text (\(verdict.label))")
        }
    } catch {
        check(false, "SSH key file verdict fixtures: \(error)")
    }
}
