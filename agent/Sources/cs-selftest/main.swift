import Foundation
import ConvenientSecurity
import OnePasswordAdapter
import LocalAuthentication

// Framework-free self-checks for the provider-agnostic core, runnable anywhere
// (`swift run cs-selftest`) without XCTest or full Xcode. Exits non-zero on any
// failure. Richer suites can move to swift-testing once a full toolchain is
// standard across dev + CI.

var failures = 0

func check(_ condition: Bool, _ label: String) {
    if condition {
        print("ok   - \(label)")
    } else {
        print("FAIL - \(label)")
        failures += 1
    }
}

func checkThrows(_ label: String, _ body: () throws -> Void) {
    do {
        try body()
        print("FAIL - \(label) (expected a throw)")
        failures += 1
    } catch {
        print("ok   - \(label) (threw \(error))")
    }
}

/// In-memory stand-in for the data-protection keychain. Shared between two
/// `KeychainSecretCache` instances it models the keychain surviving an agent
/// restart (persistent store, empty warm tier). Counts backend touches so a test
/// can assert the cache never consults it — i.e. never raises a biometric —
/// without a consent context.
actor FakeKeychainBackend: KeychainBackend {
    private var items: [String: Data] = [:]
    private(set) var loadCount = 0

    func store(account: String, data: Data) async throws {
        items[account] = data
    }

    func load(account: String, unlock: CacheUnlock?) async throws -> Data? {
        loadCount += 1
        return items[account]
    }

    func delete(account: String) async {
        items[account] = nil
    }

    func has(_ account: String) -> Bool {
        items[account] != nil
    }
}

actor FakeRiskJudgmentBackend: RiskJudgmentBackend {
    private var items: [String: Data] = [:]

    func load(service: String, account: String) async throws -> Data? {
        items["\(service)|\(account)"]
    }

    func store(service: String, account: String, data: Data) async throws {
        items["\(service)|\(account)"] = data
    }

    func delete(service: String, account: String) async {
        items["\(service)|\(account)"] = nil
    }

    func snapshot() -> [String: Data] { items }
}

print("# SecretRef")

// SecretRef: canonical URI parsing + scheme dispatch.
if let ref = try? SecretRef("op://Private/Database Server/credential") {
    check(ref.scheme == "op", "op scheme parsed")
    check(ref.path == "Private/Database Server/credential", "path is the opaque remainder")
    check(ref.uri == "op://Private/Database Server/credential", "canonical uri preserved")
} else {
    check(false, "a valid op:// reference parses")
}

check((try? SecretRef("OP://vault/item/field"))?.scheme == "op", "scheme is lowercased")
check((try? SecretRef("op://vault/item/section/field"))?.path == "vault/item/section/field",
      "multi-segment path stays opaque to the core")

checkThrows("missing :// is rejected") { _ = try SecretRef("op:/vault/item") }
checkThrows("empty scheme is rejected") { _ = try SecretRef("://vault/item") }
checkThrows("empty path is rejected") { _ = try SecretRef("op://") }
checkThrows("scheme starting with a digit is rejected") { _ = try SecretRef("1password://vault/item") }
if let spoofed = try? SecretRef("op://vault/item/field\nforged prompt\u{202e}") {
    let display = spoofed.displayString
    check(display.filter { $0 == "\n" }.count == 2
          && display.contains("field�forged prompt�"),
          "reference control and bidi characters cannot add or reorder consent lines")
} else {
    check(false, "synthetic control-character reference parses for display sanitization test")
}

print("\n# ProcessAncestry (against the live process tree)")

let me = getpid()
let myParent = getppid()

if let myStart = ProcessAncestry.startTime(of: me) {
    check(myStart > 0, "own start time is readable")
    check(ProcessAncestry.descends(me, from: me, rootStartTime: myStart),
          "a process descends from itself")
    check(!ProcessAncestry.descends(me, from: me, rootStartTime: myStart &+ 1),
          "a mismatched root start time is rejected (PID-reuse guard)")
} else {
    check(false, "own start time is readable")
}

check(ProcessAncestry.parent(of: me) == myParent, "ppid matches getppid()")

if let parentStart = ProcessAncestry.startTime(of: myParent) {
    check(ProcessAncestry.descends(me, from: myParent, rootStartTime: parentStart),
          "a process descends from its parent")
    if let myStart = ProcessAncestry.startTime(of: me) {
        check(!ProcessAncestry.descends(myParent, from: me, rootStartTime: myStart),
              "a parent does NOT descend from its child")
    }
} else {
    check(false, "parent start time is readable")
}

print("\n# AgentSocket")

let socketDir = AgentSocket.directory()
check(socketDir.contains("convenient-security-"), "socket directory is namespaced by uid")
check(AgentSocket.defaultPath().hasSuffix("/agent.sock"), "default socket path ends in agent.sock")

do {
    try AgentSocket.ensureDirectory()
    var isDirectory: ObjCBool = false
    let exists = FileManager.default.fileExists(atPath: socketDir, isDirectory: &isDirectory)
    check(exists && isDirectory.boolValue, "ensureDirectory creates the directory")
    if let attributes = try? FileManager.default.attributesOfItem(atPath: socketDir),
       let permissions = attributes[.posixPermissions] as? NSNumber {
        check(permissions.intValue == 0o700, "socket directory is private (0700)")
    } else {
        check(false, "socket directory permissions are readable")
    }
} catch {
    check(false, "ensureDirectory succeeds (\(error))")
}

#if DEBUG
check(true, "debug build permits only compile-time test endpoint/provider seams")
#else
let releaseSocketOverride = "/tmp/csec-release-must-ignore.sock"
let originalSocketOverride = ProcessInfo.processInfo.environment["CSEC_SOCKET"]
setenv("CSEC_SOCKET", releaseSocketOverride, 1)
check(!AgentSocket.isUsingDebugOverride && AgentSocket.defaultPath() != releaseSocketOverride,
      "release build ignores CSEC_SOCKET")
if let originalSocketOverride {
    setenv("CSEC_SOCKET", originalSocketOverride, 1)
} else {
    unsetenv("CSEC_SOCKET")
}

let originalProviderOverride = ProcessInfo.processInfo.environment["OP_CLI_PATH"]
setenv("OP_CLI_PATH", "/bin/false", 1)
check(OnePasswordCLI.locate() != "/bin/false", "release build ignores OP_CLI_PATH")
if let originalProviderOverride {
    setenv("OP_CLI_PATH", originalProviderOverride, 1)
} else {
    unsetenv("OP_CLI_PATH")
}
#endif

print("\n# ProductCodeIdentity (pure trust classification)")

check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.agentIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true
) == .agent, "exact valid agent identity is classified as agent")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.launcherIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true
) == .launcher, "exact valid launcher identity is classified as launcher")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.launcherIdentifier,
    teamIdentifier: "ATTACKERTEAM",
    signatureValid: true
) == .other, "matching identifier signed by another team is rejected")
check(ProductCodeIdentity.metadataRole(
    identifier: "com.example.unrelated",
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true
) == .other, "another binary from the product team is rejected")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.agentIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: false
) == .other, "invalid or unsigned code is rejected even with matching metadata")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.agentIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true,
    hardenedRuntime: false
) == .other, "matching product code without hardened runtime is rejected")
check(ProductCodeIdentity.metadataRole(
    identifier: ProductCodeIdentity.agentIdentifier,
    teamIdentifier: ProductCodeIdentity.teamIdentifier,
    signatureValid: true,
    dangerousEntitlements: ["com.apple.security.get-task-allow"]
) == .other, "matching product code with a dangerous entitlement is rejected")

let selfStartupReport = StartupSecurityReport.currentAgent()
check(selfStartupReport.sipStatus != .unknown,
      "startup self-audit obtains a definite SIP status")
check(!selfStartupReport.productionReady,
      "an ad-hoc self-test binary cannot pass the production agent startup gate")

print("\n# DeliveryPlan + protocol v2")

let baseExecutable = PlannedExecutable(
    canonicalPath: "/usr/bin/ruby",
    assurance: .userWritable
)
let basePlan = DeliveryPlan(
    mechanism: .directHeap,
    executable: baseExecutable,
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 3600,
    operationContext: "boot application",
    commandDigest: String(repeating: "a", count: 64)
)
check((try? basePlan.digest()) == (try? basePlan.digest()),
      "delivery plan digest is deterministic")
let envPlan = DeliveryPlan(
    mechanism: .unrestrictedInitialEnvironment,
    executable: baseExecutable,
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 3600,
    operationContext: "boot application",
    commandDigest: String(repeating: "a", count: 64)
)
check((try? basePlan.digest()) != (try? envPlan.digest()),
      "delivery mechanism changes the bound plan digest")
let guardedEnvPlan = DeliveryPlan(
    mechanism: .unrestrictedInitialEnvironment,
    executable: baseExecutable,
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 3600,
    operationContext: "boot application",
    commandDigest: String(repeating: "a", count: 64),
    outputGuard: OutputGuardPlan(mode: .always)
)
let unguardedEnvPlan = DeliveryPlan(
    mechanism: .unrestrictedInitialEnvironment,
    executable: baseExecutable,
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 3600,
    operationContext: "boot application",
    commandDigest: String(repeating: "a", count: 64),
    outputGuard: OutputGuardPlan(mode: .never)
)
check((try? guardedEnvPlan.digest()) != (try? unguardedEnvPlan.digest()),
      "output masking versus byte-exact bypass changes the bound plan digest")
let guardedOutputDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-output-binding",
    storedLevel: .low,
    evidence: [],
    plan: guardedEnvPlan,
    now: Date(timeIntervalSince1970: 2_000_000_000)
))
let unguardedOutputDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-output-binding",
    storedLevel: .low,
    evidence: [],
    plan: unguardedEnvPlan,
    now: Date(timeIntervalSince1970: 2_000_000_000)
))
check(guardedOutputDecision.policyDigest != unguardedOutputDecision.policyDigest,
      "output-guard configuration changes the policy decision digest")

do {
    let access = try AccessRequest(
        references: ["op://demo/db/url"],
        reason: "self-test",
        ttlSeconds: 3600,
        deliveryPlan: basePlan,
        requestID: UUID(uuidString: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")!
    )
    let data = try JSONEncoder().encode(Request.access(access))
    let decoded = try JSONDecoder().decode(Request.self, from: data)
    if case let .access(roundTrip) = decoded {
        check(roundTrip.protocolVersion == 2, "v2 access version round-trips")
        check(roundTrip.requestID == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
              "v2 request nonce round-trips")
        check(roundTrip.deliveryPlanDigest == (try? basePlan.digest()),
              "v2 plan digest round-trips")
    } else {
        check(false, "v2 access request decodes as access")
    }
} catch {
    check(false, "v2 access request round-trip succeeds (\(error))")
}

let legacyJSON = Data(#"{"type":"access","references":["op://demo/key"],"reason":"old","ttlSeconds":60}"#.utf8)
if let legacy = try? JSONDecoder().decode(Request.self, from: legacyJSON),
   case let .access(access) = legacy {
    check(access.isLegacy && access.deliveryPlan == nil,
          "v1 access is recognized explicitly and never gains an inferred plan")
} else {
    check(false, "v1 access remains decodable for a typed upgrade failure")
}

check((try? ExecutableInspection.resolve(command: "sh"))?.hasPrefix("/") == true,
      "launcher resolves PATH commands to an absolute executable")
check(ExecutableInspection.independentlyProtected(path: "/bin/sh"),
      "root-owned system executable is independently protected")
check(!ExecutableInspection.independentlyProtected(
    path: Bundle.main.executableURL?.path ?? CommandLine.arguments[0]
), "a user-owned development binary is not mislabeled independently protected")

print("\n# RiskPolicyV1 (preview, pure decisions)")

let policyNow = Date(timeIntervalSince1970: 2_000_000_000)
let unknownDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-credential",
    storedLevel: .unknown,
    evidence: [],
    plan: basePlan,
    now: policyNow
))
check(unknownDecision.effectiveLevel == .high,
      "unknown credentials are enforced at the high floor")
check(!unknownDecision.allowed && unknownDecision.denialReason == .classificationRequired,
      "unknown credentials fail closed pending classification")

let lowEnvDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-low",
    storedLevel: .low,
    evidence: [],
    plan: envPlan,
    now: policyNow
))
check(lowEnvDecision.allowed, "low-risk policy permits labeled compatibility env delivery")
check(lowEnvDecision.ttlCapSeconds == 12 * 3600,
      "low-risk TTL cap comes from the centralized table")

let standardWithoutAcceptance = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-standard",
    storedLevel: .standard,
    evidence: [],
    plan: envPlan,
    now: policyNow
))
check(!standardWithoutAcceptance.allowed
      && standardWithoutAcceptance.denialReason == .compatibilityAcceptanceRequired,
      "standard-risk env delivery requires a separate cached acceptance")

let acceptance = DeliveryAcceptance(
    credentialKey: "opaque-standard",
    mechanism: .unrestrictedInitialEnvironment,
    consumerAssurance: .userWritable,
    policyVersion: RiskPolicyV1.version,
    acceptedAt: policyNow.addingTimeInterval(-60),
    reviewAfter: policyNow.addingTimeInterval(3600)
)
let standardWithAcceptance = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-standard",
    storedLevel: .standard,
    evidence: [],
    plan: envPlan,
    acceptance: acceptance,
    now: policyNow
))
check(standardWithAcceptance.allowed,
      "matching unexpired delivery acceptance permits standard compatibility env")

let aiSubtreePlan = DeliveryPlan(
    mechanism: .directHeap,
    executable: baseExecutable,
    root: .caller,
    descendantScope: .subtree,
    destination: .aiTool,
    requestedTTLSeconds: 300,
    operationContext: "AI-assisted development"
)
let aiSubtreeDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-standard",
    storedLevel: .standard,
    evidence: [],
    plan: aiSubtreePlan,
    now: policyNow
))
check(!aiSubtreeDecision.allowed
      && aiSubtreeDecision.denialReason == .descendantScopeTooBroad,
      "standard-risk access does not implicitly grant an AI process subtree")

let criticalEvidence = RiskEvidence(
    category: .authority,
    floor: .critical,
    source: .providerMetadata,
    evidenceDigest: "opaque-evidence",
    observedAt: policyNow
)
let raisedDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-low",
    storedLevel: .low,
    evidence: [criticalEvidence],
    plan: basePlan,
    now: policyNow
))
check(raisedDecision.effectiveLevel == .critical,
      "provider evidence raises a cached low judgment")
check(!raisedDecision.allowed && raisedDecision.denialReason == .consumerAssuranceInsufficient,
      "critical policy rejects a user-writable consumer")

let protectedHighPlan = DeliveryPlan(
    mechanism: .directHeap,
    executable: PlannedExecutable(
        canonicalPath: "/usr/bin/security",
        assurance: .independentlyProtected
    ),
    root: .caller,
    descendantScope: .exactProcess,
    destination: .production,
    requestedTTLSeconds: 3600,
    operationContext: "bounded production read"
)
let highDecision = RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-high",
    storedLevel: .high,
    evidence: [],
    plan: protectedHighPlan,
    now: policyNow
))
check(highDecision.allowed && highDecision.grantedTTLSeconds == 15 * 60,
      "high-risk protected exact-process delivery is allowed with a 15-minute cap")
check(highDecision.outputPolicy == .stopAndSuppressOnMatch,
      "high-risk output matches fail closed")
check(highDecision.policyDigest == RiskPolicyV1.evaluate(RiskPolicyInput(
    credentialKey: "opaque-high",
    storedLevel: .high,
    evidence: [],
    plan: protectedHighPlan,
    now: policyNow
)).policyDigest, "identical policy inputs yield a stable policy digest")

print("\n# RiskJudgmentStore (opaque metadata, in-memory backend)")

do {
    let backend = FakeRiskJudgmentBackend()
    let store = RiskJudgmentStore(backend: backend)
    let rawAccount = "synthetic-account-name"
    let rawGroup = "Synthetic Vault/Synthetic Item"
    let rawMember = "op://Synthetic Vault/Synthetic Item/password"
    let identity = try await store.credentialIdentity(
        provider: "op",
        providerAccount: rawAccount,
        group: rawGroup,
        memberReferences: [rawMember]
    )
    check(identity.credentialKey.count == 64 && identity.memberReferenceKeys.first?.count == 64,
          "credential and member identities are keyed opaque hashes")
    check(identity.credentialKey != identity.memberReferenceKeys.first,
          "logical credential and member use domain-separated opaque IDs")

    let sameIdentity = try await RiskJudgmentStore(backend: backend).credentialIdentity(
        provider: "op",
        providerAccount: rawAccount,
        group: rawGroup,
        memberReferences: [rawMember]
    )
    check(sameIdentity == identity, "device-key identity remains stable across store restarts")

    let judgment = RiskJudgment(
        credential: identity,
        level: .standard,
        evidence: [],
        source: .explicitUser,
        decidedAt: policyNow,
        reviewAfter: policyNow.addingTimeInterval(3600),
        policyVersion: RiskPolicyV1.version
    )
    try await store.save(judgment)
    check(try await store.load(
        credentialKey: identity.credentialKey,
        policyVersion: RiskPolicyV1.version,
        at: policyNow
    ) == judgment, "current judgment round-trips separately from grants and values")

    let storedAcceptance = DeliveryAcceptance(
        credentialKey: identity.credentialKey,
        mechanism: .unrestrictedInitialEnvironment,
        consumerAssurance: .unverified,
        policyVersion: RiskPolicyV1.version,
        acceptedAt: policyNow,
        reviewAfter: policyNow.addingTimeInterval(3600)
    )
    try await store.save(storedAcceptance)
    check(try await store.loadAcceptance(
        credentialKey: identity.credentialKey,
        mechanism: .unrestrictedInitialEnvironment,
        assurance: .unverified,
        policyVersion: RiskPolicyV1.version,
        at: policyNow
    ) == storedAcceptance, "weaker-delivery acceptance is stored separately from risk judgment")

    let storedText = await backend.snapshot().reduce(into: "") { partial, item in
        partial += item.key
        partial += String(data: item.value, encoding: .utf8) ?? ""
    }
    check(!storedText.contains(rawAccount)
          && !storedText.contains(rawGroup)
          && !storedText.contains(rawMember),
          "persisted judgment records contain no raw account, item, or reference")

    check(try await store.load(
        credentialKey: identity.credentialKey,
        policyVersion: RiskPolicyV1.version + 1,
        at: policyNow
    ) == nil, "policy-version change invalidates and removes a cached judgment")
} catch {
    check(false, "risk judgment store checks succeed (\(error))")
}

check(CredentialGrouping.onePasswordGroup(
    for: try! SecretRef("op://Vault Name/Item Name/section/password")
) == "Vault Name/Item Name", "1Password fields group initially by vault/item capability")

print("\n# OnePasswordProvider (op CLI plumbing, no account access)")

check(OnePasswordCLI.sanitizedEnvironment()["GITHUB_TOKEN"] == nil
      && OnePasswordCLI.sanitizedEnvironment()["DATABASE_URL"] == nil,
      "provider child receives a minimal allowlisted environment")

if let opPath = OnePasswordCLI.locate() {
    check(FileManager.default.isExecutableFile(atPath: opPath), "op CLI located at \(opPath)")
    if let result = try? await OnePasswordCLI.run(opPath, ["--version"]) {
        check(result.status == 0, "op --version exits 0 via the runner")
        let version = String(data: result.stdout, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        check(!version.isEmpty, "op --version prints a version (\(version))")
    } else {
        check(false, "op --version runs via the runner")
    }
} else {
    print("skip - op CLI not installed; skipping live op checks")
}

// A provider pointed at a missing binary must fail fast, never hang.
let brokenProvider = OnePasswordProvider(cliPath: "/nonexistent/op")
do {
    _ = try await brokenProvider.resolve(try! SecretRef("op://demo/db/url"))
    check(false, "resolve with a missing CLI should throw")
} catch {
    check(true, "resolve with a missing CLI throws (\(error))")
}

print("\n# ExecPlanner (env-injection planning, no agent)")

// Env-scan resolves references in place; ordinary values pass through untouched.
if let scan = try? ExecPlanner.plan(
    environment: ["DATABASE_URL": "op://vault/db/url", "PATH": "/usr/bin", "HOME": "/Users/x"],
    explicit: [],
    knownSchemes: ["op"]
) {
    check(scan.assignments == ["DATABASE_URL": "op://vault/db/url"],
          "env value that is an op:// reference is detected; plain values are not")
    check(scan.references == ["op://vault/db/url"], "references list is just the detected ref")
} else {
    check(false, "env-scan plan builds")
}

// An ordinary URL must not be mistaken for a secret: https isn't a known scheme.
check((try? ExecPlanner.plan(
    environment: ["SITE": "https://example.com"], explicit: [], knownSchemes: ["op"]
))?.assignments.isEmpty == true, "https:// is left untouched (scheme not resolvable)")

// A reference whose scheme the agent doesn't handle is ignored in env-scan.
check((try? ExecPlanner.plan(
    environment: ["X": "vault://a/b"], explicit: [], knownSchemes: ["op"]
))?.assignments.isEmpty == true, "unknown resolvable-looking scheme is skipped in env-scan")

// Explicit --set overrides an env-scan match for the same variable.
if let overridden = try? ExecPlanner.plan(
    environment: ["DATABASE_URL": "op://vault/db/url"],
    explicit: [(name: "DATABASE_URL", reference: "op://vault/other/url")],
    knownSchemes: ["op"]
) {
    check(overridden.assignments["DATABASE_URL"] == "op://vault/other/url",
          "explicit --set wins over an env-scan match")
} else {
    check(false, "explicit-override plan builds")
}

// references are deduped and sorted for a stable single access() call.
if let many = try? ExecPlanner.plan(
    environment: ["A": "op://x", "B": "op://x", "C": "op://y"],
    explicit: [],
    knownSchemes: ["op"]
) {
    check(many.references == ["op://x", "op://y"], "references are deduped and sorted")
} else {
    check(false, "multi-ref plan builds")
}

checkThrows("--set with a non-reference value throws") {
    _ = try ExecPlanner.plan(
        environment: [:], explicit: [(name: "X", reference: "not a uri")], knownSchemes: ["op"]
    )
}
checkThrows("--set with an unresolvable scheme throws") {
    _ = try ExecPlanner.plan(
        environment: [:], explicit: [(name: "X", reference: "vault://a/b")], knownSchemes: ["op"]
    )
}

// resolvedEnvironment injects values and preserves everything else.
let injectPlan = ExecPlanner.Plan(assignments: ["DATABASE_URL": "op://vault/db/url"])
if let env = try? ExecPlanner.resolvedEnvironment(
    base: ["PATH": "/usr/bin", "DATABASE_URL": "placeholder"],
    plan: injectPlan,
    values: ["op://vault/db/url": "postgres://resolved"]
) {
    check(env["DATABASE_URL"] == "postgres://resolved", "resolved value replaces the placeholder")
    check(env["PATH"] == "/usr/bin", "unrelated variables are preserved")
} else {
    check(false, "resolvedEnvironment succeeds")
}

// With an empty base it yields exactly the injected subset (the exec code path).
check((try? ExecPlanner.resolvedEnvironment(
    base: [:], plan: injectPlan, values: ["op://vault/db/url": "postgres://resolved"]
)) == ["DATABASE_URL": "postgres://resolved"], "empty base yields only the injected variables")

checkThrows("resolvedEnvironment throws when the agent returned no value") {
    _ = try ExecPlanner.resolvedEnvironment(base: [:], plan: injectPlan, values: [:])
}

checkThrows("--set rejects an ambiguous environment name") {
    _ = try ExecPlanner.plan(
        environment: [:],
        explicit: [(name: "BAD=NAME", reference: "op://vault/db/url")],
        knownSchemes: ["op"]
    )
}
checkThrows("environment delivery rejects a protected value containing NUL") {
    _ = try ExecPlanner.resolvedEnvironment(
        base: [:],
        plan: injectPlan,
        values: ["op://vault/db/url": "synthetic\0value"]
    )
}

print("\n# OutputGuard (binary-safe streaming redaction)")

func redact(
    patterns: [OutputRedactionPattern],
    chunks: [Data]
) -> (data: Data, matches: [OutputRedactionMatch], firstChunk: Data) {
    var redactor = StreamingOutputRedactor(patterns: patterns)
    var output = Data()
    var matches: [OutputRedactionMatch] = []
    var firstChunk = Data()
    for (index, chunk) in chunks.enumerated() {
        let result = redactor.process(chunk)
        if index == 0 { firstChunk = result.data }
        output.append(result.data)
        matches.append(contentsOf: result.matches)
    }
    let final = redactor.finish()
    output.append(final.data)
    matches.append(contentsOf: final.matches)
    return (output, matches, firstChunk)
}

let prefixPattern = OutputRedactionPattern(
    opaqueID: "secret-prefix",
    representation: .exact,
    bytes: Data("abcdefgh".utf8),
    replacement: Data("[prefix]".utf8)
)
let longestPattern = OutputRedactionPattern(
    opaqueID: "secret-long",
    representation: .exact,
    bytes: Data("abcdefghijk".utf8),
    replacement: Data("[long]".utf8)
)
let splitRedaction = redact(
    patterns: [prefixPattern, longestPattern],
    chunks: [Data("before:abc".utf8), Data("def".utf8), Data("ghijk:after".utf8)]
)
check(splitRedaction.firstChunk.range(of: Data("abc".utf8)) == nil,
      "a possible secret prefix is withheld rather than forwarded")
check(splitRedaction.data == Data("before:[long]:after".utf8),
      "a secret split across writes is replaced using longest-match semantics")
check(splitRedaction.matches == [OutputRedactionMatch(opaqueID: "secret-long", representation: .exact)],
      "redaction emits only value-free match metadata")

let splitFixture = Data("prefix-abcdefghijk-suffix".utf8)
let splitExpected = Data("prefix-[long]-suffix".utf8)
let everyTwoChunkBoundaryIsSafe = (0...splitFixture.count).allSatisfy { boundary in
    let result = redact(
        patterns: [prefixPattern, longestPattern],
        chunks: [
            splitFixture.subdata(in: 0..<boundary),
            splitFixture.subdata(in: boundary..<splitFixture.count),
        ]
    )
    return result.data == splitExpected
}
let byteAtATime = redact(
    patterns: [prefixPattern, longestPattern],
    chunks: splitFixture.map { Data([$0]) }
)
check(everyTwoChunkBoundaryIsSafe && byteAtATime.data == splitExpected,
      "every split boundary, including byte-at-a-time writes, produces the same safe output")

let binaryRedaction = redact(
    patterns: [longestPattern],
    chunks: [Data([0x00, 0xff, 0x61, 0x62]), Data("cdefghijk".utf8) + Data([0x80])]
)
check(binaryRedaction.data == Data([0x00, 0xff]) + Data("[long]".utf8) + Data([0x80]),
      "matching and replacement preserve unrelated non-UTF8 bytes")

let unmatchedFlush = redact(
    patterns: [longestPattern],
    chunks: [Data("trailing-abcd".utf8)]
)
check(unmatchedFlush.data == Data("trailing-abcd".utf8) && unmatchedFlush.matches.isEmpty,
      "an unmatched trailing prefix is forwarded intact at EOF")

let encodedCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/Output/token": "alpha:/\"beta-token"]
)
let base64Text = Data("alpha:/\"beta-token".utf8).base64EncodedData()
let encodedRedaction = redact(patterns: encodedCatalog.patterns, chunks: [base64Text])
check(encodedRedaction.data == Data("[csec:secret-1]".utf8)
      && encodedRedaction.matches.first?.representation == .base64,
      "canonical base64 output is detected without exposing its source value")

let percentText = Data("alpha%3A%2F%22beta-token".utf8)
let percentRedaction = redact(patterns: encodedCatalog.patterns, chunks: [percentText])
check(percentRedaction.data == Data("[csec:secret-1]".utf8)
      && percentRedaction.matches.first?.representation == .percentEncoded,
      "canonical percent-encoded output is detected")

let encodedJSONText = try! JSONEncoder().encode("alpha:/\"beta-token")
let jsonText = encodedJSONText.subdata(in: 1..<(encodedJSONText.count - 1))
let jsonRedaction = redact(patterns: encodedCatalog.patterns, chunks: [jsonText])
check(jsonRedaction.data == Data("[csec:secret-1]".utf8)
      && jsonRedaction.matches.first?.representation == .jsonEscaped,
      "JSON-escaped output is detected")

let shortCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/short": "tiny"]
)
check(shortCatalog.patterns.isEmpty && shortCatalog.skippedShortValueCount == 1,
      "short common values are excluded from automatic destructive matching")
let optedInShortCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/short": "tiny"],
    includeShortValues: true
)
check(!optedInShortCatalog.patterns.isEmpty,
      "short-value matching requires an explicit opt-in")

let referenceCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/Output/token": "synthetic-output-token"],
    labelStyle: .reference
)
let referenceRedaction = redact(
    patterns: referenceCatalog.patterns,
    chunks: [Data("synthetic-output-token".utf8)]
)
check(referenceRedaction.data == Data("op://Synthetic/Output/token".utf8),
      "reference-shaped replacement is available only through the opt-in catalog style")

let unsafeReferenceCatalog = OutputRedactionCatalog(
    valuesByReference: ["op://Synthetic/item/field\nforged\u{202e}": "synthetic-control-token"],
    labelStyle: .reference
)
let unsafeReferenceRedaction = redact(
    patterns: unsafeReferenceCatalog.patterns,
    chunks: [Data("synthetic-control-token".utf8)]
)
check(unsafeReferenceRedaction.data == Data("op://Synthetic/item/field�forged�".utf8),
      "reference-shaped output cannot inject lines or bidirectional controls")

let collisionSource = "synthetic-collision-source"
let collisionExact = Data(collisionSource.utf8).base64EncodedString()
let collisionCatalog = OutputRedactionCatalog(
    valuesByReference: [
        "op://Synthetic/a-derived": collisionSource,
        "op://Synthetic/b-exact": collisionExact,
    ],
    labelStyle: .reference
)
let collisionRedaction = redact(
    patterns: collisionCatalog.patterns,
    chunks: [Data(collisionExact.utf8)]
)
check(collisionRedaction.data == Data("op://Synthetic/b-exact".utf8)
      && collisionRedaction.matches.first?.representation == .exact,
      "an exact credential wins over another credential's colliding encoded form")

print("\n# AICommandHook (Claude Code / Codex PreToolUse rewriting)")

let complexHookCommand = "printf '%s\\n' \"a b\"; echo `uname` && printf '$HOME'\ntrue"
let hookInputObject: [String: Any] = [
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": [
        "command": complexHookCommand,
        "description": "synthetic quoting test",
        "timeout": 12_345,
        "run_in_background": true,
    ],
]
let hookInputData = try! JSONSerialization.data(withJSONObject: hookInputObject)
for client in AICommandHookClient.allCases {
    do {
        let outputData = try AICommandHook.rewrite(
            input: hookInputData,
            client: client,
            csecExecutablePath: "/opt/Convenient Security/it's/csec"
        )
        let output = try JSONSerialization.jsonObject(with: outputData) as? [String: Any]
        let specific = output?["hookSpecificOutput"] as? [String: Any]
        let updated = specific?["updatedInput"] as? [String: Any]
        let rewritten = updated?["command"] as? String ?? ""
        let encoded = rewritten.split(separator: " ").last.map(String.init) ?? ""
        let decoded = try AICommandHook.decodeShellCommand(encoded)
        check(specific?["hookEventName"] as? String == "PreToolUse"
              && specific?["permissionDecision"] as? String == "allow"
              && decoded == complexHookCommand,
              "\(client.rawValue) hook rewrites the exact multiline shell program through tool-exec")
        check(updated?["description"] as? String == "synthetic quoting test"
              && updated?["timeout"] as? Int == 12_345
              && updated?["run_in_background"] as? Bool == true,
              "\(client.rawValue) hook preserves every unchanged Bash input field")
    } catch {
        check(false, "\(client.rawValue) hook rewrite succeeds")
    }
}

do {
    let claudeData = try AICommandHook.hookConfiguration(
        client: .claude,
        csecExecutablePath: "/opt/Convenient Security/csec"
    )
    let codexData = try AICommandHook.hookConfiguration(
        client: .codex,
        csecExecutablePath: "/opt/Convenient Security/csec"
    )
    let claudeText = String(data: claudeData, encoding: .utf8) ?? ""
    let codexObject = try JSONSerialization.jsonObject(with: codexData) as? [String: Any]
    let codexHooks = codexObject?["hooks"] as? [String: Any]
    let codexGroups = codexHooks?["PreToolUse"] as? [[String: Any]]
    let codexHandlers = codexGroups?.first?["hooks"] as? [[String: Any]]
    let codexCommand = codexHandlers?.first?["command"] as? String
    check(claudeText.contains("\"args\"") && claudeText.contains("\"claude\""),
          "Claude hook configuration uses shell-free exec-form arguments")
    check(codexCommand == "'/opt/Convenient Security/csec' hook codex",
          "Codex hook configuration safely quotes the absolute csec path")
} catch {
    check(false, "hook configurations serialize")
}

checkThrows("hook adapter rejects a non-Bash tool instead of silently passing it through") {
    let invalid = try JSONSerialization.data(withJSONObject: [
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": ["command": "true"],
    ])
    _ = try AICommandHook.rewrite(
        input: invalid,
        client: .claude,
        csecExecutablePath: "/usr/local/bin/csec"
    )
}
checkThrows("encoded hook command rejects malformed base64url") {
    _ = try AICommandHook.decodeShellCommand("not+base64")
}

print("\n# BiometricConsent (prompt formatting + availability, no actual prompt)")

// The consent prompt must state exactly what is granted, to whom, and for how long.
let promptRef = try! SecretRef("op://vault/db/url")
let promptText = BiometricConsent.prompt(
    caller: CallerInfo(pid: 4242, startTime: 1, description: "ruby (pid 4242)"),
    references: [promptRef],
    reason: "run migrations",
    ttl: 8 * 3600
)
check(promptText.contains("vault: vault"), "prompt identifies the vault")
check(promptText.contains("item: db"), "prompt identifies the item")
check(promptText.contains("field: url"), "prompt identifies the field")
check(promptText.contains("ruby (pid 4242)"), "prompt names the requesting process")
check(promptText.contains("run migrations"), "prompt states the caller's reason")
check(promptText.contains("8h"), "prompt states the grant duration")

let spoofedPrompt = BiometricConsent.prompt(
    caller: CallerInfo(pid: 4242, startTime: 1, description: "ruby\nverified launcher"),
    references: [promptRef],
    reason: "run tests\ncritical approved",
    ttl: 60
)
check(!spoofedPrompt.contains("ruby\nverified launcher")
      && !spoofedPrompt.contains("run tests\ncritical approved"),
      "caller and reason cannot inject consent-prompt lines")

check(BiometricConsent.formatDuration(45) == "45s", "duration under a minute renders as seconds")
check(BiometricConsent.formatDuration(600) == "10 min", "duration under an hour renders as minutes")
check(BiometricConsent.formatDuration(8 * 3600) == "8h", "whole-hour duration renders as hours")
check(BiometricConsent.formatDuration(3 * 3600 + 30 * 60) == "3h 30m", "mixed duration renders hours and minutes")

// canEvaluatePolicy is a non-interactive capability probe — it never prompts, so
// it's safe to call here. Availability varies by machine; just report it.
let laContext = LAContext()
var laError: NSError?
let biometricsAvailable = laContext.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laError)
print("info - Touch ID available on this machine: \(biometricsAvailable)" +
      (laError.map { " (\($0.localizedDescription))" } ?? ""))
check(true, "LocalAuthentication links and canEvaluatePolicy runs without prompting")

// The advisory process name should resolve for the running self-test process.
check(ProcessAncestry.name(of: getpid()) != nil, "own process name resolves (advisory consent label)")

print("\n# KeychainSecretCache (warm/cold tiers, in-memory backend — no keychain, no biometrics)")

// A CacheUnlock just needs a context object; constructing one never prompts.
let unlock = CacheUnlock(LAContext())

do {
    let backend = FakeKeychainBackend()
    let cache = KeychainSecretCache(backend: backend)

    try await cache.put("op://vault/db/url", value: "postgres://s3cr3t", maxAge: 3600)
    check(try await cache.get("op://vault/db/url", unlock: nil) == "postgres://s3cr3t",
          "warm hit serves an in-grant fetch with no unlock (zero touches)")
    check(await backend.loadCount == 0, "a warm hit never consults the keychain backend")

    // A fresh cache over the same backend = the keychain surviving a restart.
    let afterRestart = KeychainSecretCache(backend: backend)
    check(try await afterRestart.get("op://vault/db/url", unlock: unlock) == "postgres://s3cr3t",
          "cold keychain read serves after a restart when the consent context is supplied")
    check(await backend.loadCount == 1, "the cold read consults the backend exactly once")
    check(try await afterRestart.get("op://vault/db/url", unlock: nil) == "postgres://s3cr3t",
          "a cold hit is promoted to the warm tier and served free thereafter")
    check(await backend.loadCount == 1, "the promoted value is not re-read from the backend")

    // The security-critical invariant: no consent context ⇒ the cache never
    // reaches for the keychain, so it can't raise a prompt nobody consented to.
    let unconsented = KeychainSecretCache(backend: backend)
    check(try await unconsented.get("op://vault/db/url", unlock: nil) == nil,
          "a cold value is NOT served without a consent context")
    check(await backend.loadCount == 1, "no consent context ⇒ the backend/biometric is never consulted")

    // An expired warm entry with no unlock is a plain miss (falls through to the
    // provider), not a surprise biometric.
    let warmExpiry = FakeKeychainBackend()
    let warmExpiryCache = KeychainSecretCache(backend: warmExpiry)
    try await warmExpiryCache.put("op://vault/short/lived", value: "STALE", maxAge: -1)
    check(try await warmExpiryCache.get("op://vault/short/lived", unlock: nil) == nil,
          "an expired warm entry with no unlock is a miss, not a prompt")
    check(await warmExpiry.loadCount == 0, "expired warm + no unlock never consults the backend")

    // A cold entry past its maxAge is dropped on read, not served.
    let coldExpiry = FakeKeychainBackend()
    let coldWriter = KeychainSecretCache(backend: coldExpiry)
    try await coldWriter.put("op://vault/expired", value: "OLD", maxAge: -1)
    let coldReader = KeychainSecretCache(backend: coldExpiry)
    check(try await coldReader.get("op://vault/expired", unlock: unlock) == nil,
          "an expired cold entry is not served")
    check(!(await coldExpiry.has("op://vault/expired")), "an expired cold entry is deleted on read")

    // invalidate clears both tiers.
    let invBackend = FakeKeychainBackend()
    let invCache = KeychainSecretCache(backend: invBackend)
    try await invCache.put("op://vault/rotated", value: "V", maxAge: 3600)
    await invCache.invalidate("op://vault/rotated")
    check(try await invCache.get("op://vault/rotated", unlock: unlock) == nil,
          "invalidate removes the value from the warm tier")
    check(!(await invBackend.has("op://vault/rotated")), "invalidate deletes the keychain item")
} catch {
    check(false, "KeychainSecretCache checks threw unexpectedly: \(error)")
}

if failures == 0 {
    print("\nAll checks passed.")
    exit(0)
} else {
    FileHandle.standardError.write(Data("\n\(failures) check(s) failed.\n".utf8))
    exit(1)
}
