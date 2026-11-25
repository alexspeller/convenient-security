import Foundation
import ConvenientSecurity
import CryptoKit
import Darwin

// A long-running FAKE agent for cross-language client integration tests. It
// serves a fixed set of demo references from memory with auto-approved consent —
// no 1Password, no real secrets, no biometrics. NOT a production surface; it
// exists so the Ruby and Node.js clients can be tested against a real agent
// speaking the real wire protocol without a provisioned build or a live vault.
//
// Listens on AgentSocket.defaultPath() (honouring CSEC_SOCKET), so a test points
// it at a private temp socket and runs the client against that.

struct StaticProvider: SecretProvider {
    let values: [String: String]
    var schemes: Set<String> { Set(values.keys.compactMap { (try? SecretRef($0))?.scheme }) }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: Data(value.utf8), cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

let demoValues = ["op://demo/db/url": "postgres://s3cr3t",
                  "op://demo/google/token": "FIXTURE-STORED-ACCESS-TOKEN",
                  "csec://demo/GOOGLE_TOKEN": "FIXTURE-STORED-ACCESS-TOKEN"]

/// Approves an automation enrollment and refuses every other attended review.
struct EnrollmentOnlyPolicyReview: PolicyReviewProvider {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        guard review.automation != nil else { return .denied(.authenticationFailed) }
        return await AutoApprovePolicyReview().reviewAccess(review)
    }
}

/// The automation catalog as one JSON file in the fake agent's state directory.
struct FileAutomationGrantStore: AutomationGrantStore {
    let directory: String
    private var file: URL { URL(fileURLWithPath: directory).appendingPathComponent("jobs.json") }

    func load() async throws -> [AutomationJob] {
        guard let data = try? Data(contentsOf: file) else { return [] }
        return try JSONDecoder().decode([AutomationJob].self, from: data)
    }

    func store(_ jobs: [AutomationJob]) async throws {
        try JSONEncoder().encode(jobs).write(to: file, options: .atomic)
    }
}

/// Synthetic materializations, one JSON file per job revision.
struct FileAutomationMaterializationStore: AutomationMaterializationStore {
    let directory: String
    private func file(_ jobID: String, _ revision: String) -> URL {
        URL(fileURLWithPath: directory).appendingPathComponent("materialization-\(jobID)-\(revision).json")
    }

    func store(_ materialization: AutomationMaterialization) async throws {
        try JSONEncoder().encode(materialization.valuesByReference)
            .write(to: file(materialization.jobID, materialization.revision), options: .atomic)
    }

    func load(jobID: String, revision: String) async throws -> AutomationMaterialization? {
        guard let data = try? Data(contentsOf: file(jobID, revision)) else { return nil }
        return AutomationMaterialization(
            jobID: jobID,
            revision: revision,
            valuesByReference: try JSONDecoder().decode([String: Data].self, from: data)
        )
    }

    func delete(jobID: String, revision: String) async throws {
        try? FileManager.default.removeItem(at: file(jobID, revision))
    }
}

// This standalone test fixture can simulate days of silence between output
// chunks. It changes neither the system clock nor grant/authorization timing;
// the shipping daemon has no environment-controlled clock.
actor RedactionFixtureClock {
    private let advance = Double(ProcessInfo.processInfo.environment[
        "CSEC_FAKE_REDACTION_ADVANCE_SECONDS"] ?? "0") ?? 0
    private var seen = Set<String>()

    func now(sessionID: String) -> Date {
        guard advance.isFinite && advance > 0 else { return Date() }
        return Date().addingTimeInterval(seen.insert(sessionID).inserted ? 0 : advance)
    }

    func end(sessionID: String) { seen.remove(sessionID) }
}
let redactionClock = RedactionFixtureClock()

let socketPath = AgentSocket.defaultPath()
try? AgentSocket.ensureDirectory()

let resolver = SecretResolver(cache: NullSecretCache())
await resolver.register(StaticProvider(values: demoValues))
let grants = GrantTable()

// Machine identities with software keys in memory and a scripted STS, so
// `csec identity` and `csec creds aws|google` can be driven end to end over
// the real socket with no Secure Enclave key, no cloud account and no touch.
let fakeIdentityKeys = MachineIdentityKeyFactory(
    create: {
        let key = P256.Signing.PrivateKey()
        return (SoftwareIdentitySigner(key: key), key.rawRepresentation)
    },
    open: { SoftwareIdentitySigner(key: try P256.Signing.PrivateKey(rawRepresentation: $0)) }
)
let identityCatalog = MachineIdentityCatalog(store: nil, keys: fakeIdentityKeys)
// Opt-in metadata-only tracing for the offline Google consumer regression.
actor GoogleFixtureControl {
    let directory = ProcessInfo.processInfo.environment["CSEC_FAKE_GOOGLE_STATE"]
    func record(_ event: String) {
        guard let directory else { return }
        let path = (directory as NSString).appendingPathComponent("events")
        let fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0o600)
        precondition(fd >= 0, "Google fixture trace could not be opened")
        defer { close(fd) }
        let data = Data((event + "\n").utf8)
        let written = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
        precondition(written == data.count, "Google fixture trace could not be written")
    }
    func denied() -> Bool {
        directory.map { FileManager.default.fileExists(atPath: ($0 as NSString).appendingPathComponent("deny")) } ?? false
    }
}
let googleFixture = GoogleFixtureControl()
struct GoogleFixturePolicyReview: PolicyReviewProvider {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        await googleFixture.record("review \(review.caller.pid)")
        if await googleFixture.denied() { return .denied(.human(decidedAt: .now)) }
        return .approved(AccessPolicyApproval(
            selectedScopeOptionID: review.scopeChoices?.options.first(where: { $0.kind == .requestingCommand })?.id
        ))
    }
}
await resolver.register(MachineIdentityProvider(catalog: identityCatalog, exchange: { request in
    let expiry = ISO8601DateFormatter().string(from: Date().addingTimeInterval(3_600))
    let role = String(data: request.httpBody ?? Data(), encoding: .utf8)?.contains("RoleArn=") == true
    let reply = """
    <AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>\
    <AccessKeyId>ASIAFAKEAGENT0000001</AccessKeyId><SecretAccessKey>fake-agent-secret</SecretAccessKey>\
    <SessionToken>fake-agent-session</SessionToken><Expiration>\(expiry)</Expiration>\
    </Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>
    """
    return (Data(reply.utf8), role ? 200 : 400)
}, googleExchange: { request in
    let impersonated = request.url?.host == "iamcredentials.googleapis.com"
    await googleFixture.record(impersonated ? "impersonation" : "sts")
    let reply: [String: Any]
    if impersonated {
        reply = ["accessToken": "FIXTURE-CSECD-IMPERSONATED", "expireTime": ISO8601DateFormatter().string(from: Date().addingTimeInterval(3_600))]
    } else {
        reply = ["access_token": "FIXTURE-CSECD-FEDERATED", "expires_in": 3_600, "token_type": "Bearer",
                 "issued_token_type": GoogleWebIdentity.accessTokenType]
    }
    return (try JSONSerialization.data(withJSONObject: reply), 200)
}))
let identityService = MachineIdentityService(
    catalog: identityCatalog, consent: AutoApproveConsent(), hardwareKeys: false, persistent: false,
    revokeReferences: { await grants.revoke(references: $0) },
    terminalInspection: .unavailable
)

// With CSEC_FAKE_AUTOMATION_STATE set, the fake agent also runs unattended
// automation, keeping its job catalog, materializations and run leases in that
// directory, so a test can kill it and start another over the same state the
// way csecd restarts over its Keychain items. In this mode every attended
// review except an enrollment is refused, so a bridge request is served only
// as automation: a request that fell through to the attended path would fail.
let automationStateDirectory = ProcessInfo.processInfo.environment["CSEC_FAKE_AUTOMATION_STATE"]
let automationRunsBackend = InMemoryProtectedItemBackend()
let automationService: AutomationService?
if let automationStateDirectory {
    let runsFile = URL(fileURLWithPath: automationStateDirectory).appendingPathComponent("runs.json")
    if let stored = try? Data(contentsOf: runsFile) {
        await automationRunsBackend.setRawBytes(stored, for: .automationRuns)
    }
    automationService = AutomationService(
        resolver: resolver,
        grantStore: FileAutomationGrantStore(directory: automationStateDirectory),
        materializationStore: FileAutomationMaterializationStore(directory: automationStateDirectory),
        consent: AutoApproveConsent(),
        policyReview: EnrollmentOnlyPolicyReview(),
        terminalInspection: .unavailable,
        runStore: ProtectedStores.processLocal(automationRunsBackend)
            .store(for: AutomationRunsDocument.self)
    )
} else {
    automationService = nil
}

/// Writes the run leases back to the state directory after each request, so a
/// SIGKILLed fake agent leaves them as csecd's write-behind would.
func saveAutomationRuns() async {
    guard let automationStateDirectory, let automationService else { return }
    await automationService.flushPersistedRuns()
    let runsFile = URL(fileURLWithPath: automationStateDirectory).appendingPathComponent("runs.json")
    if let bytes = await automationRunsBackend.rawBytes(for: .automationRuns) {
        try? bytes.write(to: runsFile, options: .atomic)
    }
}

let fixtureReview: any PolicyReviewProvider
if automationService != nil {
    fixtureReview = EnrollmentOnlyPolicyReview()
} else if ProcessInfo.processInfo.environment["CSEC_FAKE_GOOGLE_STATE"] != nil {
    fixtureReview = GoogleFixturePolicyReview()
} else {
    fixtureReview = AutoApprovePolicyReview()
}
let agent = Agent(
    resolver: resolver,
    grants: grants,
    consent: AutoApproveConsent(),
    policyReview: fixtureReview,
    automationService: automationService,
    allowLegacyAccessForTesting: true,
    allowUnverifiedPlansForTesting: true,
    allowUnverifiedAutomationCallersForTesting: automationService != nil,
    terminalInspection: .unavailable
)
if automationService != nil {
    _ = await agent.restoreAutomationRuns()
    await saveAutomationRuns()
}

// CSEC_FAKE_REQUIRE_VALID_SIGNATURE=1 turns away a peer whose binary was
// replaced while it ran, as csecd does after an update.
let fakeTrustPolicy: SocketPeerTrustPolicy =
    ProcessInfo.processInfo.environment["CSEC_FAKE_REQUIRE_VALID_SIGNATURE"] == "1"
        ? .requireValidSignatureForTesting
        : .allowUnverifiedForTesting
// CSEC_FAKE_RESPONSE_DELAY_SECONDS holds every response back that long, so a
// test can watch a slow but live agent keep a client waiting on heartbeats.
let fixtureResponseDelay = Double(ProcessInfo.processInfo.environment[
    "CSEC_FAKE_RESPONSE_DELAY_SECONDS"] ?? "0") ?? 0

let server = SocketServer(path: socketPath, clientTrustPolicy: fakeTrustPolicy) { request, caller in
    if fixtureResponseDelay.isFinite && fixtureResponseDelay > 0 {
        try? await Task.sleep(nanoseconds: UInt64(fixtureResponseDelay * 1_000_000_000))
    }
    switch request {
    case let .access(access):
        let response = await agent.handle(request: access, caller: caller)
        await saveAutomationRuns()
        return response
    case .schemes:
        return await agent.schemes()
    case .capabilities:
        return await agent.capabilities()
    case let .restoreApprovals(request):
        return await agent.restoreApprovals(request: request, caller: caller)
    case let .configureRemoteApproval(request):
        return Response(
            requestID: request.requestID,
            remoteApprovalStatus: RemoteApprovalConfigurationStatus(state: .disabled)
        )
    case let .configureSSH(request):
        return await agent.configureSSH(request: request, caller: caller)
    case let .configureGitHub(request):
        return await agent.configureGitHub(request: request, caller: caller)
    case let .configureAutomation(request):
        let response = await agent.configureAutomation(request: request, caller: caller)
        await saveAutomationRuns()
        return response
    case let .grants(request):
      return await agent.handleGrants(request: request, caller: caller)
    case let .beginSession(begin):
        return await agent.beginSession(request: begin, caller: caller)
    case let .beginOutputRedaction(begin):
        return await agent.beginOutputRedaction(request: begin, caller: caller)
    case let .redactOutputChunk(chunk):
        let now = await redactionClock.now(sessionID: chunk.sessionID)
        return await agent.redactOutputChunk(request: chunk, caller: caller, now: now)
    case let .endOutputRedaction(end):
        await redactionClock.end(sessionID: end.sessionID)
        return await agent.endOutputRedaction(request: end, caller: caller)
    case let .takeApprovalNotices(take):
        return await agent.takeApprovalNotices(request: take, caller: caller)
    case let .beginNativeStoreEdit(begin):
        return await agent.beginNativeStoreEdit(request: begin, caller: caller)
    case let .commitNativeStoreEdit(commit):
        return await agent.commitNativeStoreEdit(request: commit, caller: caller)
    case let .commitNativeStoreBlobs(commit):
        return await agent.commitNativeStoreBlobs(request: commit, caller: caller)
    case let .cancelNativeStoreEdit(cancel):
        return await agent.cancelNativeStoreEdit(request: cancel, caller: caller)
    case let .approveProtectedLaunch(approval):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent has no root-helper rendezvous",
            requestID: approval.requestID
        )
    case let .hostAudit(request):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent does not run the host posture audit",
            requestID: request.requestID
        )
    case let .hostAuditStart(request):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent does not run the host posture audit",
            requestID: request.requestID
        )
    case let .hostAuditPoll(request):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent does not run the host posture audit",
            requestID: request.requestID
        )
    case let .hostRemediate(request):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent does not run host remediation",
            requestID: request.requestID
        )
    case let .hostRecordTriage(request):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent does not persist host triage",
            requestID: request.requestID
        )
    case let .invalidateCachedReferences(request):
        return await agent.invalidateCachedReferences(request: request, caller: caller)
    case let .decisionLog(request):
        return await agent.handleDecisionLog(request: request, caller: caller)
    case let .uninstallCleanup(request):
        return .failed(
            .deliveryNotSupported,
            message: "the standalone fake agent has nothing to uninstall",
            requestID: request.requestID
        )
    case let .registerAgentCommand(registration):
        return Response(requestID: registration.requestID, agentCommandRegistered: false)
    case let .configureDelegation(request):
        guard request.action == .status else {
            return .failed(
                .deliveryNotSupported,
                message: "the standalone fake agent has no delegated approvals",
                requestID: request.requestID
            )
        }
        return Response(
            requestID: request.requestID,
            delegationStatus: DelegationStatus(state: .unavailable, policyVersion: 1)
        )
    case let .sudoRemoteReview(request):
        // No paired phone here: the sudo review's own panel decides.
        return Response(requestID: request.requestID, sudoRemoteReview: .unavailable)
    case let .sudoDelegation(request):
        // No Claude Code session here: the panel as ever.
        return Response(requestID: request.requestID, sudoDelegation: .notApplicable)
    case let .sudoPairing(request):
        return Response(requestID: request.requestID, sudoPaired: false)
    case let .sudoTerminal(request):
        // Never an Apple event from a test double: the panel names the tty.
        return Response(requestID: request.requestID)
    case let .sudoReviewEnd(request):
        // No decision log here.
        return Response(requestID: request.requestID, sudoReviewEnded: false)
    case let .nativeStoreBackup(request):
        return .failed(.providerUnavailable, message: "native-store backups are not available in the fake agent", requestID: request.requestID)
    case let .configureMachineIdentity(request):
        return await identityService.handle(request, caller: caller)
    case let .removeNativeValues(request):
        return .failed(.nativeStoreUnavailable, message: "the fake agent has no native store", requestID: request.requestID)
    }
}

FileHandle.standardError.write(Data(
    "cs-fake-agent: listening on \(socketPath) (in-memory demo values, auto-approve)\n".utf8
))

// The accept loop runs on a thread of its own, as in csecd, and the main actor
// stays free. Every heartbeat tick hops through the main actor
// (SocketServer.emitHeartbeats), so a main thread blocked in accept() would
// starve the ticks and a slow request would look like a wedged agent.
Thread.detachNewThread {
    do {
        try server.run()
    } catch {
        FileHandle.standardError.write(Data("cs-fake-agent: \(error)\n".utf8))
        exit(1)
    }
}
// This top-level code is an async main running on the main actor, where
// dispatchMain() traps; suspending for good keeps the process alive and hands
// the main actor back to the heartbeat hops.
await withUnsafeContinuation { (_: UnsafeContinuation<Never, Never>) in }
