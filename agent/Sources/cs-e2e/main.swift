import Foundation
import ConvenientSecurity
import LocalAuthentication

// End-to-end check: start the agent on a temp socket, connect a client, and
// prove the full path — socket, LOCAL_PEERTOKEN peer identity, subtree grant,
// resolution — round-trips a value. Runs locally with no entitlements, using a
// fake in-memory provider and a counting consent stub.

var failures = 0
let forcedScannerFailureMarker = "csec-synthetic-scanner-failure-trigger"
func check(_ condition: Bool, _ label: String) {
    print(condition ? "ok   - \(label)" : "FAIL - \(label)")
    if !condition { failures += 1 }
}

let environmentInjectionWarning = "warning: secrets in the child's initial environment"
func checkEnvironmentInjectionWarning(_ stderr: String, command: String, label: String) {
    check(stderr.components(separatedBy: "csec \(command): \(environmentInjectionWarning)").count == 2
          && stderr.contains("other processes running as your user")
          && stderr.contains("Output masking does not hide the environment")
          && stderr.contains("csec creds aws") && stderr.contains("csec creds git")
          && stderr.contains("csec exec-fd") && stderr.contains("csec exec-file")
          && !stderr.contains("postgres://s3cr3t") && !stderr.contains("native-synthetic-token")
          && !stderr.contains("op://demo/db/url") && !stderr.contains("csec://development/NATIVE_TOKEN"),
          "\(label) warns once about environment exposure with value-free adapter guidance")
}

// Sidecar discovery intentionally scans the launcher's working tree. Keep the
// harness in its own empty tree so a developer's real/untracked *.csec files
// cannot become test inputs or make CI depend on local provider state.
let e2eWorkingDirectory = NSTemporaryDirectory()
    + "csec-e2e-cwd-\(UUID().uuidString.lowercased())"
do {
    try FileManager.default.createDirectory(
        atPath: e2eWorkingDirectory, withIntermediateDirectories: true
    )
    guard FileManager.default.changeCurrentDirectoryPath(e2eWorkingDirectory) else {
        throw CocoaError(.fileNoSuchFile)
    }
} catch {
    FileHandle.standardError.write(Data("cs-e2e: cannot create isolated working directory\n".utf8))
    exit(1)
}

actor ResolutionCounter {
    private var count = 0
    func record() { count += 1 }
    func calls() -> Int { count }
}

/// Every `access` request the main socket server receives, whatever its outcome,
/// so a check can prove a launch asked for nothing.
actor AccessRequestCounter {
    private var count = 0
    func record() { count += 1 }
    func calls() -> Int { count }
}

/// What the harness's csecd answers `csec remote status` with. It starts as
/// a status built without csecd's facts, which encodes as an older csecd's
/// answer does; a scenario swaps in the one csecd builds from its manager.
actor RemoteStatusFixture {
    private(set) var status = RemoteApprovalConfigurationStatus(state: .disabled)
    func serve(_ next: RemoteApprovalConfigurationStatus) { status = next }
}

struct StaticProvider: SecretProvider {
    let values: [String: String]
    let counter: ResolutionCounter?
    let requiresUnlock: Bool

    init(
        values: [String: String],
        counter: ResolutionCounter? = nil,
        requiresUnlock: Bool = false
    ) {
        self.values = values
        self.counter = counter
        self.requiresUnlock = requiresUnlock
    }

    var schemes: Set<String> { ["op"] }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        await counter?.record()
        guard !requiresUnlock || unlock != nil else {
            throw ProviderError.notAuthenticated
        }
        guard let value = values[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: Data(value.utf8), cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

/// A `.cacheable` provider for the post-rotation freshness e2e: its value is
/// fixed to the rotated ("AFTER") value, so a resolve after cache invalidation
/// must return it.
struct RotatingProvider: SecretProvider {
    let reference: String
    let value: String
    var schemes: Set<String> { ["op"] }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard ref.uri == reference else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: Data(value.utf8), cacheHint: .cacheable)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

/// In-memory keychain backend so the e2e can drive a real `KeychainSecretCache`
/// (warm + cold tiers) without touching the data-protection keychain, and can
/// assert whether an entry survives an invalidation.
actor InMemoryKeychain: KeychainBackend {
    private var items: [String: Data] = [:]
    func store(account: String, data: Data) async throws { items[account] = data }
    func load(account: String, unlock: CacheUnlock?) async throws -> Data? { items[account] }
    func delete(account: String) async { items[account] = nil }
    func contains(account: String) async -> Bool { items[account] != nil }
    func has(_ account: String) -> Bool { items[account] != nil }
}

/// A minimal server exposing only `.access` and `.invalidateCachedReferences`,
/// used to drive the cache-invalidation verb over a real socket.
func startInvalidatingServer(path: String, agent: Agent) -> Bool {
    let server = SocketServer(path: path, clientTrustPolicy: .allowUnverifiedForTesting) {
        request, caller in
        switch request {
        case let .access(access):
            return await agent.handle(request: access, caller: caller)
        case let .invalidateCachedReferences(request):
            return await agent.invalidateCachedReferences(request: request, caller: caller)
        default:
            return .failed(.invalidRequest, message: "synthetic invalidation server")
        }
    }
    Thread.detachNewThread { try? server.run() }
    var attempts = 0
    while !FileManager.default.fileExists(atPath: path) && attempts < 100 {
        usleep(20_000)
        attempts += 1
    }
    return FileManager.default.fileExists(atPath: path)
}

actor ConsentCounter: ConsentProvider {
    private(set) var count = 0
    private(set) var authenticationCount = 0
    private(set) var lastTTL: TimeInterval?
    func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval?,
        policySummary: String?
    ) async -> ConsentOutcome {
        count += 1
        lastTTL = ttl
        return .approved(unlock: CacheUnlock(LAContext()))
    }
    func calls() -> Int { count }
    func latestTTL() -> TimeInterval? { lastTTL }
    func authenticate(reason: String) async -> ConsentOutcome {
        authenticationCount += 1
        return .approved(unlock: CacheUnlock(LAContext()))
    }
    func authentications() -> Int { authenticationCount }
}

actor DenyPolicyReview: PolicyReviewProvider {
    private var count = 0
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        count += 1
        return .denied(.human(decidedAt: .now))
    }
    func calls() -> Int { count }
}

actor SignalingDelayedPolicyReview: PolicyReviewProvider {
    private var markerPaths: [String]

    init(markerPaths: [String]) {
        self.markerPaths = markerPaths
    }

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        if !markerPaths.isEmpty {
            let marker = markerPaths.removeFirst()
            FileManager.default.createFile(atPath: marker, contents: Data())
        }
        try? await Task.sleep(nanoseconds: 300_000_000)
        return .approved(AccessPolicyApproval())
    }
}

actor AccessReviewCapture {
    private var reviews: [AccessPolicyReview] = []

    func record(_ review: AccessPolicyReview) {
        reviews.append(review)
    }

    func latest() -> AccessPolicyReview? { reviews.last }
    func snapshot() -> [AccessPolicyReview] { reviews }
}

struct CapturingAutoApprovePolicyReview: PolicyReviewProvider {
    let capture: AccessReviewCapture
    private let delegate = AutoApprovePolicyReview()

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        await capture.record(review)
        await bulkProtectionReviewMutation.run()
        return await delegate.reviewAccess(review)
    }
}

actor EmbeddedAuthenticationCounter: AccessPolicyAuthenticationSession {
    private var preauthenticationCount = 0
    private var authenticationCount = 0
    private var cancellationCount = 0

    func recordPreauthentication() {
        preauthenticationCount += 1
    }

    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        authenticationCount += 1
        return .approved(unlock: CacheUnlock(LAContext()))
    }

    func cancel() async {
        cancellationCount += 1
    }

    func preauthentications() -> Int { preauthenticationCount }
    func authentications() -> Int { authenticationCount }
    func cancellations() -> Int { cancellationCount }
}

struct EmbeddedAuthenticationPolicyReview: PolicyReviewProvider {
    let session: EmbeddedAuthenticationCounter

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        // Model the production UI: its biometric succeeds and freezes the
        // visible selection before the agent receives the value-free snapshot.
        await session.recordPreauthentication()
        return .approved(AccessPolicyApproval(authenticationSession: session))
    }
}

actor RequestCapture {
    private(set) var calls = 0
    private(set) var lastCaller: CallerInfo?

    func record(_ caller: CallerInfo) {
        calls += 1
        lastCaller = caller
    }

    func snapshot() -> (calls: Int, caller: CallerInfo?) { (calls, lastCaller) }
}

let socketPath = NSTemporaryDirectory() + "cs-e2e-\(getpid()).sock"
let sshSocketPath = NSTemporaryDirectory() + "cs-e2e-ssh-\(getpid()).sock"
let githubSocketPath = NSTemporaryDirectory() + "cs-e2e-gh-\(getpid()).sock"
let rootFixtureDirectory = NSTemporaryDirectory() + "cs-root-e2e-\(getpid())"
let rootSocketPath = rootFixtureDirectory + "/rootd.sock"
setenv("CSEC_ROOT_SOCKET", rootSocketPath, 1)
setenv("CSEC_SSH_SOCKET", sshSocketPath, 1)
setenv("CSEC_GITHUB_SOCKET", githubSocketPath, 1)

let resolver = SecretResolver(cache: NullSecretCache())
let resolutionCounter = ResolutionCounter()
await resolver.register(StaticProvider(values: [
    "op://demo/db/url": "postgres://s3cr3t",
    "op://demo/db/url-extended": "postgres://s3cr3t/extended",
    "op://demo/api/key": "sk-demo-123",
    "op://demo/github/token": gitHubE2EToken,
    "op://demo/github/not-a-token": "two words",
    "op://grant-policy/credential/token": "grant-policy-synthetic-token",
    "op://session-tests/credential/token": "session-root-synthetic-token",
    "op://secure-delivery/aws/access-key-id": "AKIA-CSEC-SYNTHETIC",
    "op://secure-delivery/aws/secret-access-key": "aws-csec-synthetic-secret",
    "op://secure-delivery/aws/session-token": "aws-csec-synthetic-session",
    "op://secure-delivery/aws/bundle": "{\"AccessKeyId\":\"AKIA-CSEC-BUNDLE\",\"SecretAccessKey\":\"aws-csec-bundle-secret\"}",
    "op://secure-delivery/git/username": "csec-synthetic-user",
    "op://secure-delivery/git/password": "git-csec-synthetic-password",
    "op://fd-presets/pgpass/content": "db.test:5432:*:csec:pgpass-synthetic-secret",
    "op://fd-presets/kubeconfig/content": "apiVersion: v1\nkind: Config\nsynthetic: kube-secret",
    "op://fd-presets/aws/content": "[default]\naws_access_key_id=AKIAFD\naws_secret_access_key=aws-fd-secret",
    "op://fd-presets/google/content": "{\"type\":\"service_account\",\"private_key\":\"google-fd-secret\"}",
    "op://fd-presets/npm/content": "//registry.npmjs.org/:_authToken=npm-fd-secret",
    "op://fd-high/pgpass/content": "high-fd-synthetic-secret",
    "op://file-delivery/config/content": "regular-file-synthetic-secret",
    "op://github/profile/token": "github-regular-file-synthetic-token",
    "op://get-tests/credential/token": "interactive-get-synthetic-token",
    "op://get-pipe/credential/token": "pipe-delivery-synthetic-token",
    "op://get-substitution/credential/token": "command-substitution-synthetic-token",
    "op://get-shapes/credential/token": "delivery-shape-synthetic-token",
], counter: resolutionCounter))
let nativeKeyBackend = InMemoryNativeStoreKeyBackend()
let nativeFileBackend = InMemoryNativeStoreFileBackend()
let nativeBlobStore = NativeBlobStore(
    keyBackend: InMemoryNativeStoreKeyBackend(),
    fileBackend: InMemoryNativeStoreFileBackend()
)
let nativeProvider = NativeEncryptedFileProvider(
    keyBackend: nativeKeyBackend,
    fileBackend: nativeFileBackend,
    blobStore: nativeBlobStore
)
await resolver.register(nativeProvider)
let grants = GrantTable()
let consent = ConsentCounter()
let capture = RequestCapture()
let accessReviewCapture = AccessReviewCapture()
let policyReview = CapturingAutoApprovePolicyReview(capture: accessReviewCapture)
let sshSigningService = SSHSigningService(
    resolver: resolver,
    catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore()),
    consent: consent,
    policyReview: policyReview,
    allowUnverifiedCallersForTesting: true,
    terminalInspection: .unavailable
)
let automationService = AutomationService(
    resolver: resolver,
    grantStore: InMemoryAutomationGrantStore(),
    materializationStore: InMemoryAutomationMaterializationStore(),
    consent: consent,
    policyReview: policyReview,
    terminalInspection: .unavailable
)
/// This suite asserts how *plan roots* behave — per-invocation roots, verified
/// direct parents, registered sessions — so grant-scope discovery is pinned to
/// "offer nothing wider". Otherwise the results would depend on whatever tree the
/// suite happens to run under: launched from a coding agent or an interactive
/// terminal, csecd would legitimately default to a wider root and those
/// per-invocation assertions would describe the harness, not the code. Ancestry
/// and start times stay live, so every kernel check remains real; only the two
/// signals that *nominate* a wider root are suppressed. The widened path has its
/// own coverage in cs-selftest (`grantScopeAgentWiringTests`).
let narrowScopeInspection = ProcessInspection(
    startTime: { ProcessAncestry.startTime(of: $0) },
    parent: { ProcessAncestry.parent(of: $0) },
    name: { _ in nil },
    executablePath: { _ in nil },
    hasControllingTerminal: { _ in false }
)
// A hermetic decision log: process-local protected items and a private
// directory, so `csec log` runs over the real socket without touching the
// installed csecd's log.
let e2eDecisionLogDirectory = NSTemporaryDirectory() + "cs-e2e-decision-log-\(getpid())"
let e2eDecisionLog = DecisionLog(
    directory: SealedRecordDirectory(path: e2eDecisionLogDirectory),
    stores: .processLocal()
)
await e2eDecisionLog.open()
let githubProxy = GitHubProxyService(store: nil, socketPath: githubSocketPath)
let agent = Agent(
    resolver: resolver,
    grants: grants,
    consent: consent,
    policyReview: policyReview,
    nativeStore: nativeProvider,
    sshSigningService: sshSigningService,
    githubProxy: githubProxy,
    automationService: automationService,
    allowUnverifiedPlansForTesting: true,
    allowUnverifiedAutomationCallersForTesting: true,
    processInspection: narrowScopeInspection,
    terminalInspection: .unavailable,
    decisionLog: e2eDecisionLog
)
// `csec edit --remove` against the same stores and registrations, wired as
// csecd wires it (AgentRuntime.swift). Its scenario protects files from one
// directory, which stands in for the home directory and the project roots.
let removalProjectDirectory = NSTemporaryDirectory() + "csec-remove-e2e-\(UUID().uuidString.lowercased())"
let nativeStoreRemovalService = NativeStoreRemovalService(
    blobStore: nativeBlobStore,
    consent: consent,
    terminalInspection: .unavailable,
    uses: {
        var uses: [String: String] = [:]
        for job in try await automationService.list() {
            for reference in job.references { uses[reference] = "used by the automation job \(job.name)" }
        }
        if let token = await githubProxy.tokenReference { uses[token.uri] = "csec's GitHub token" }
        for key in try await sshSigningService.listedSSHKeys() {
            uses[key.reference] = "the SSH key \(key.fingerprint)"
        }
        return uses
    },
    protectedFrom: { _ in [removalProjectDirectory] },
    forget: { references in
        let revoked = await grants.revoke(references: references)
        await resolver.invalidate(references: references)
        return revoked
    }
)

let accessRequests = AccessRequestCounter()
let remoteStatusFixture = RemoteStatusFixture()
let server = SocketServer(path: socketPath, clientTrustPolicy: .allowUnverifiedForTesting) { request, caller in
    await capture.record(caller)
    if case let .redactOutputChunk(chunk) = request,
       chunk.data.range(of: Data(forcedScannerFailureMarker.utf8)) != nil {
        return .failed(
            .internalError,
            message: "synthetic scanner failure",
            requestID: chunk.requestID
        )
    }
    switch request {
    case let .access(access):
        await accessRequests.record()
        return await agent.handle(request: access, caller: caller)
    case .schemes:
        return await agent.schemes()
    case .capabilities:
        return await agent.capabilities()
    case let .restoreApprovals(request):
        return await agent.restoreApprovals(request: request, caller: caller)
    case let .configureRemoteApproval(request):
        return Response(
            requestID: request.requestID,
            remoteApprovalStatus: await remoteStatusFixture.status
        )
    case let .configureSSH(request):
        return await agent.configureSSH(request: request, caller: caller)
    case let .configureGitHub(request):
        return await agent.configureGitHub(request: request, caller: caller)
    case let .configureAutomation(request):
        return await agent.configureAutomation(request: request, caller: caller)
    case let .grants(request):
        return await agent.handleGrants(request: request, caller: caller)
    case let .beginSession(begin):
        return await agent.beginSession(request: begin, caller: caller)
    case let .beginOutputRedaction(begin):
        return await agent.beginOutputRedaction(request: begin, caller: caller)
    case let .redactOutputChunk(chunk):
        return await agent.redactOutputChunk(request: chunk, caller: caller)
    case let .endOutputRedaction(end):
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
    case let .hostAudit(request):
        return Response(requestID: request.requestID, hostAuditReport: nil)
    case let .hostAuditStart(request):
        return .failed(
            .deliveryNotSupported,
            message: "the e2e harness does not run the host posture audit",
            requestID: request.requestID
        )
    case let .hostAuditPoll(request):
        return .failed(
            .deliveryNotSupported,
            message: "the e2e harness does not run the host posture audit",
            requestID: request.requestID
        )
    case let .hostRemediate(request):
        return await agent.runHostRemediation(request: request, caller: caller)
    case let .hostRecordTriage(request):
        return .failed(
            .deliveryNotSupported,
            message: "the e2e harness does not persist host triage",
            requestID: request.requestID
        )
    case let .invalidateCachedReferences(request):
        return await agent.invalidateCachedReferences(request: request, caller: caller)
    case let .decisionLog(request):
        return await agent.handleDecisionLog(request: request, caller: caller)
    case let .uninstallCleanup(request):
        return .failed(
            .deliveryNotSupported,
            message: "the e2e harness does not uninstall",
            requestID: request.requestID
        )
    case let .registerAgentCommand(registration):
        return Response(requestID: registration.requestID, agentCommandRegistered: false)
    case let .configureDelegation(request):
        guard request.action == .status else {
            return .failed(
                .deliveryNotSupported,
                message: "the e2e harness has no delegated approvals",
                requestID: request.requestID
            )
        }
        return Response(
            requestID: request.requestID,
            delegationStatus: DelegationStatus(state: .off, policyVersion: 1)
        )
    case let .sudoRemoteReview(request):
        return Response(requestID: request.requestID, sudoRemoteReview: .unavailable)
    case let .sudoDelegation(request):
        return Response(requestID: request.requestID, sudoDelegation: .notApplicable)
    case let .sudoPairing(request):
        return Response(requestID: request.requestID, sudoPaired: false)
    case let .sudoTerminal(request):
        return Response(requestID: request.requestID)
    case let .sudoReviewEnd(request):
        return Response(requestID: request.requestID, sudoReviewEnded: false)
    case let .nativeStoreBackup(request):
        return .failed(.providerUnavailable, message: "native-store backups are not available here", requestID: request.requestID)
    case let .configureMachineIdentity(request):
        return .failed(.providerUnavailable, message: "machine identities are not available here", requestID: request.requestID)
    case let .removeNativeValues(request):
        return await nativeStoreRemovalService.handle(request, caller: caller)
    case let .approveProtectedLaunch(approval):
        guard approval.validate(caller: caller) else {
            return .failed(
                .invalidRequest,
                message: "invalid synthetic protected launch",
                requestID: approval.requestID
            )
        }
        let access = await agent.handle(request: approval.accessRequest, caller: caller)
        if let failure = access.failure {
            return Response(requestID: approval.requestID, failure: failure)
        }
        guard let values = access.values else {
            return .failed(
                .internalError,
                message: "synthetic protected launch produced no values",
                requestID: approval.requestID
            )
        }
        // nil ⇒ a process-lifetime delivery (rootd tears down on process exit).
        let expiresAt = access.accessExpiresAt
        guard await agent.protectedFilePathsAreBound(approval.launchPlan.files) else {
            return .failed(
                .invalidRequest,
                message: "a protected-file sidecar does not match its stored path",
                requestID: approval.requestID
            )
        }
        do {
            try RootHelperClient(
                path: rootSocketPath,
                trustPolicy: .allowUnverifiedForTesting
            ).approve(
                nonce: approval.rendezvousNonce,
                planDigest: approval.launchPlanDigest,
                payloads: try ProtectedFilePayloadRenderer.render(
                    bindings: approval.launchPlan.files,
                    values: values
                ),
                expiresAt: expiresAt
            )
            return Response(
                requestID: approval.requestID,
                protectedLaunchApproved: true
            )
        } catch {
            return approval.rootHelperRefusal(error)
        }
    }
}
Thread.detachNewThread { try? server.run() }
let sshServer = SSHAgentServer(
    path: sshSocketPath,
    trustPolicy: .allowUnverifiedForTesting,
    provider: sshSigningService
)
Thread.detachNewThread { try? sshServer.run() }
let githubUpstream = E2EGitHubUpstream()
let githubServer = GitHubProxyServer(
    path: githubSocketPath, service: githubProxy, authorizer: agent, connector: githubUpstream,
    diagnostics: { _ in }
)
Thread.detachNewThread { try? githubServer.run() }

// Wait (up to ~2s) for both protocol sockets to appear.
var waited = 0
while (!FileManager.default.fileExists(atPath: socketPath)
       || !FileManager.default.fileExists(atPath: sshSocketPath)
       || !FileManager.default.fileExists(atPath: githubSocketPath)) && waited < 100 {
    usleep(20_000)
    waited += 1
}
check(FileManager.default.fileExists(atPath: socketPath), "agent socket is listening")
check(FileManager.default.fileExists(atPath: sshSocketPath), "SSH agent socket is listening")
check(FileManager.default.fileExists(atPath: githubSocketPath), "GitHub token proxy socket is listening")

func startAccessOnlyServer(path: String, agent: Agent) -> Bool {
    let server = SocketServer(path: path, clientTrustPolicy: .allowUnverifiedForTesting) {
        request, caller in
        guard case let .access(access) = request else {
            return .failed(.invalidRequest, message: "synthetic access-only server")
        }
        return await agent.handle(request: access, caller: caller)
    }
    Thread.detachNewThread { try? server.run() }
    var attempts = 0
    while !FileManager.default.fileExists(atPath: path) && attempts < 100 {
        usleep(20_000)
        attempts += 1
    }
    return FileManager.default.fileExists(atPath: path)
}

let client = AgentClient(path: socketPath, serverTrustPolicy: .allowUnverifiedForTesting)

// A production client must authenticate the connected process before sending
// even a capability query. This server is the unsigned cs-e2e process.
do {
    _ = try AgentClient(path: socketPath).schemes()
    check(false, "production client rejects an unsigned replacement server")
} catch AgentClient.ClientError.untrustedServer {
    check(true, "production client rejects an unsigned replacement server before request write")
} catch {
    check(false, "replacement server rejection is a typed trust failure (got \(error))")
}
check((await capture.snapshot()).calls == 0,
      "replacement server receives no request metadata before client rejection")

// Blob-path binding: a *.csec sidecar (symlink binding) may only materialize its
// value at the project path the blob was protected at, so a planted or moved
// sidecar pointing the same value elsewhere is rejected before the launch.
do {
    let store = try NativeStoreName("e2ebind")
    let bindUnlock = CacheUnlock(LAContext())
    let bindPID: pid_t = 5150
    let bindStart: UInt64 = 42
    let edit = try await nativeProvider.beginEdit(
        store: store, callerPID: bindPID, callerStartTime: bindStart, unlock: bindUnlock)
    _ = try await nativeProvider.commitBlobs(
        sessionID: edit.sessionID,
        requests: [.init(key: "envrc", data: Data("X=1\n".utf8), mode: 0o600, path: ".envrc")],
        callerPID: bindPID, callerStartTime: bindStart)
    // Resolving unlocks and caches the store record that the check reuses.
    _ = try await nativeProvider.resolve(try SecretRef("csec://e2ebind/envrc"), unlock: bindUnlock)

    let matched = ProtectedFileBinding.symlink(
        projectRelativePath: ".envrc", reference: "csec://e2ebind/envrc", index: 0)
    let redirected = ProtectedFileBinding.symlink(
        projectRelativePath: "config/other.key", reference: "csec://e2ebind/envrc", index: 0)
    let envDelivered = ProtectedFileBinding.raw(
        environmentName: "X", reference: "csec://e2ebind/envrc", index: 0)
    check(await agent.protectedFilePathsAreBound([matched]),
          "a sidecar at its stored protect path is accepted")
    check(!(await agent.protectedFilePathsAreBound([redirected])),
          "a sidecar redirected to a different path is rejected (planted-sidecar defense)")
    check(await agent.protectedFilePathsAreBound([envDelivered]),
          "environment-delivered bindings are not path-bound")
    // A home token file restored for its tool from another directory is bound
    // to its home-relative path, which is what a home store records.
    check(await agent.protectedFilePathsAreBound([ProtectedFileBinding.homeSymlink(
        homeRelativePath: ".envrc", reference: "csec://e2ebind/envrc", index: 0)]),
          "a home link at its stored protect path is accepted")
    check(!(await agent.protectedFilePathsAreBound([ProtectedFileBinding.homeSymlink(
        homeRelativePath: ".config/other", reference: "csec://e2ebind/envrc", index: 0)])),
          "a home link redirected to a different path is rejected")
    // Source-neutral: a non-native (op://) sidecar has no recorded protect-path, so
    // it is not path-bound here and instead relies on the review that shows it.
    let nonNative = ProtectedFileBinding.symlink(
        projectRelativePath: "secrets/token", reference: "op://vault/item/field", index: 0)
    check(await agent.protectedFilePathsAreBound([nonNative]),
          "a source-neutral (op://) sidecar is not path-bound; it relies on the review")
} catch {
    check(false, "blob-path binding e2e checks succeed (\(error))")
}

do {
    let capabilities = try client.capabilities()
    check(capabilities.supportedVersions == [2], "client negotiates protocol v2")
    check(capabilities.features.contains(.deliveryPlans)
          && capabilities.features.contains(.typedFailures)
          && capabilities.features.contains(.outputGuardBinding)
          && capabilities.features.contains(.activeOutputRedaction)
          && capabilities.features.contains(.nativeEncryptedStore)
          && capabilities.features.contains(.nativeEditorPolicy)
          && capabilities.features.contains(.registeredSessionRoots)
          && capabilities.features.contains(.credentialProtocols)
          && capabilities.features.contains(.inheritedFileDescriptors)
          && capabilities.features.contains(.protectedRegularFiles)
          && capabilities.features.contains(.unattendedAutomation),
          "agent advertises delivery, redaction, storage, and automation capabilities")
} catch {
    check(false, "protocol capability negotiation succeeds (\(error))")
}

// Old access JSON remains recognizable solely so the production agent can fail
// with an explicit upgrade code; it never infers a secure delivery plan.
let legacyData = Data(#"{"type":"access","references":["op://demo/db/url"],"reason":"legacy","ttlSeconds":60}"#.utf8)
if let legacyWire = try? JSONDecoder().decode(Request.self, from: legacyData),
   case let .access(legacyAccess) = legacyWire {
    let legacyResponse = await agent.handle(
        request: legacyAccess,
        caller: CallerInfo(
            pid: getpid(),
            startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
            description: "legacy test"
        )
    )
    check(legacyResponse.failure?.code == .upgradeRequired,
          "production agent fails closed on v1 access with upgrade_required")
} else {
    check(false, "legacy access JSON decodes for migration failure")
}

let invalidMetadataPlan = DeliveryPlan(
    mechanism: .directHeap,
    executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .unverified),
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 60,
    operationContext: "metadata bounds test",
    commandDigest: "not-a-sha256-digest"
)
if let invalidMetadataRequest = try? AccessRequest(
    references: ["op://demo/db/url"],
    reason: "invalid metadata must fail before consent",
    ttlSeconds: 60,
    deliveryPlan: invalidMetadataPlan
) {
    let invalidMetadataResponse = await agent.handle(
        request: invalidMetadataRequest,
        caller: CallerInfo(
            pid: getpid(),
            startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
            description: "metadata test"
        )
    )
    check(invalidMetadataResponse.failure?.code == .invalidRequest,
          "malformed delivery metadata fails before consent or resolution")
} else {
    check(false, "malformed-metadata request can be constructed for rejection testing")
}

let misplacedRequesterPlan = DeliveryPlan(
    mechanism: .directHeap,
    executable: PlannedExecutable(canonicalPath: "/usr/bin/ruby", assurance: .unverified),
    requestingExecutable: PlannedExecutable(
        canonicalPath: "/bin/sh",
        assurance: .independentlyProtected
    ),
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 60,
    operationContext: "misplaced requester metadata test"
)
if let misplacedRequesterRequest = try? AccessRequest(
    references: ["op://demo/db/url"],
    reason: "requester identity is valid only for a direct parent",
    ttlSeconds: 60,
    deliveryPlan: misplacedRequesterPlan
) {
    let consentBefore = await consent.calls()
    let response = await agent.handle(
        request: misplacedRequesterRequest,
        caller: CallerInfo(
            pid: getpid(),
            startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
            description: "misplaced requester test"
        )
    )
    let consentAfter = await consent.calls()
    check(response.failure?.code == .invalidRequest
          && consentAfter == consentBefore,
          "requester executable metadata is rejected outside a direct-parent root")
} else {
    check(false, "misplaced-requester request can be constructed for rejection testing")
}

let malformedPipePlan = DeliveryPlan(
    mechanism: .rawStandardOutput,
    executable: PlannedExecutable(
        canonicalPath: "/Applications/ConvenientSecurity.app/Contents/MacOS/csec",
        signingIdentifier: ProductCodeIdentity.launcherIdentifier,
        teamIdentifier: ProductCodeIdentity.teamIdentifier,
        assurance: .verifiedProduct
    ),
    // A pipe cannot omit its separate direct-parent requester and then claim
    // that the authenticated launcher itself owns the grant.
    root: .caller,
    descendantScope: .subtree,
    destination: .shellDelegatedPipe,
    recipientAssurance: .unverifiedPipeReader,
    requestedTTLSeconds: 60,
    operationContext: "malformed shell-delegated pipe metadata"
)
if let malformedPipeRequest = try? AccessRequest(
    references: ["op://demo/db/url"],
    reason: "malformed pipe roles must fail before consent",
    ttlSeconds: 60,
    deliveryPlan: malformedPipePlan
) {
    let consentBefore = await consent.calls()
    let resolutionsBefore = await resolutionCounter.calls()
    let response = await agent.handle(
        request: malformedPipeRequest,
        caller: CallerInfo(
            pid: getpid(),
            startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
            description: "malformed pipe test"
        )
    )
    let consentAfter = await consent.calls()
    let resolutionsAfter = await resolutionCounter.calls()
    check(response.failure?.code == .invalidRequest
          && consentAfter == consentBefore
          && resolutionsAfter == resolutionsBefore,
          "malformed pipe requester metadata fails closed before consent or resolution")
} else {
    check(false, "malformed-pipe request can be constructed for rejection testing")
}

let unsupportedMatcherPlan = DeliveryPlan(
    mechanism: .unrestrictedInitialEnvironment,
    executable: PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified),
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 60,
    operationContext: "unsupported matcher test",
    outputGuard: OutputGuardPlan(mode: .always, matcherVersion: 999)
)
if let unsupportedMatcherRequest = try? AccessRequest(
    references: ["op://demo/db/url"],
    reason: "unsupported output matcher must fail before consent",
    ttlSeconds: 60,
    deliveryPlan: unsupportedMatcherPlan
) {
    let consentBefore = await consent.calls()
    let response = await agent.handle(
        request: unsupportedMatcherRequest,
        caller: CallerInfo(
            pid: getpid(),
            startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
            description: "matcher-version test"
        )
    )
    let consentAfter = await consent.calls()
    check(response.failure?.code == .invalidRequest
          && consentAfter == consentBefore,
          "unsupported output-matcher semantics fail before consent or resolution")
} else {
    check(false, "unsupported-matcher request can be constructed for rejection testing")
}

let unboundOutputPlan = DeliveryPlan(
    mechanism: .unrestrictedInitialEnvironment,
    executable: PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified),
    root: .caller,
    descendantScope: .subtree,
    destination: .localDevelopment,
    requestedTTLSeconds: 60,
    operationContext: "missing output binding test"
)
if let unboundOutputRequest = try? AccessRequest(
    references: ["op://demo/db/url"],
    reason: "unbound output policy must fail before consent",
    ttlSeconds: 60,
    deliveryPlan: unboundOutputPlan
) {
    let consentBefore = await consent.calls()
    let response = await agent.handle(
        request: unboundOutputRequest,
        caller: CallerInfo(
            pid: getpid(),
            startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
            description: "missing-output-binding test"
        )
    )
    let consentAfter = await consent.calls()
    check(response.failure?.code == .invalidRequest
          && consentAfter == consentBefore,
          "unrestricted env delivery without an output-policy binding fails before consent")
} else {
    check(false, "unbound-output request can be constructed for rejection testing")
}

// A denied trusted review must stop before the resolver/cache boundary and
// without falling back to the ConsentProvider, even for a syntactically valid
// request constructed directly rather than through csec's normal planner.
do {
    let guardedCounter = ResolutionCounter()
    let guardedResolver = SecretResolver(cache: NullSecretCache())
    await guardedResolver.register(StaticProvider(
        values: ["op://production/admin/token": "never-resolve-this"],
        counter: guardedCounter
    ))
    let denyingReview = DenyPolicyReview()
    let guardedConsent = ConsentCounter()
    let guardedAgent = Agent(
        resolver: guardedResolver,
        grants: GrantTable(),
        consent: guardedConsent,
        policyReview: denyingReview,
        allowUnverifiedPlansForTesting: true,
        terminalInspection: .unavailable
    )
    let directCaller = CallerInfo(
        pid: getpid(),
        startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
        description: "direct policy test"
    )
    let heapPlan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified),
        root: .caller,
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 3600,
        operationContext: "denied review test"
    )
    let deniedRequest = try AccessRequest(
        references: ["op://production/admin/token"],
        reason: "a new reference must pass the trusted review",
        ttlSeconds: 3600,
        deliveryPlan: heapPlan
    )
    let deniedResponse = await guardedAgent.handle(
        request: deniedRequest,
        caller: directCaller
    )
    let deniedResolutionCalls = await guardedCounter.calls()
    let deniedConsentCalls = await guardedConsent.calls()
    let deniedReviewCalls = await denyingReview.calls()
    check(deniedResponse.failure?.code == .consentDenied
          && deniedResolutionCalls == 0
          && deniedConsentCalls == 0
          && deniedReviewCalls == 1,
          "a denied trusted review blocks fallback consent and provider resolution")
} catch {
    check(false, "direct pre-resolution policy checks succeed (\(error))")
}

// A trusted access reviewer can preauthenticate, freeze its visible choices,
// and keep one UI session open while the agent validates that value-free
// snapshot, carrying the same biometric to the resolver's cold-cache unlock.
do {
    let caller = CallerInfo(
        pid: getpid(),
        startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
        description: "embedded authentication test"
    )
    let plan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified),
        root: .caller,
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 3600,
        operationContext: "embedded authentication test"
    )

    let allowedReference = "op://embedded-review/allowed/token"
    let allowedResolution = ResolutionCounter()
    let allowedResolver = SecretResolver(cache: NullSecretCache())
    await allowedResolver.register(StaticProvider(
        values: [allowedReference: "embedded-review-synthetic-token"],
        counter: allowedResolution,
        requiresUnlock: true
    ))
    let embeddedAuthentication = EmbeddedAuthenticationCounter()
    let separateConsent = ConsentCounter()
    let allowedAgent = Agent(
        resolver: allowedResolver,
        grants: GrantTable(),
        consent: separateConsent,
        policyReview: EmbeddedAuthenticationPolicyReview(
            session: embeddedAuthentication
        ),
        allowUnverifiedPlansForTesting: true,
        terminalInspection: .unavailable
    )
    let allowedRequest = try AccessRequest(
        references: [allowedReference],
        reason: "use the combined policy and biometric window",
        ttlSeconds: 3600,
        deliveryPlan: plan
    )
    let allowedResponse = await allowedAgent.handle(request: allowedRequest, caller: caller)
    let embeddedPreauthenticationCalls = await embeddedAuthentication.preauthentications()
    let embeddedAuthenticationCalls = await embeddedAuthentication.authentications()
    let embeddedCancellationCalls = await embeddedAuthentication.cancellations()
    let separateConsentCalls = await separateConsent.calls()
    let allowedResolutionCalls = await allowedResolution.calls()
    check(allowedResponse.values?[allowedReference] == Data("embedded-review-synthetic-token".utf8)
          && embeddedPreauthenticationCalls == 1
          && embeddedAuthenticationCalls == 1
          && embeddedCancellationCalls == 0
          && separateConsentCalls == 0
          && allowedResolutionCalls == 1,
          "an allowed preauthenticated review carries its policy-bound unlock to resolution")
} catch {
    check(false, "embedded policy authentication checks succeed (\(error))")
}

do {
    let first = try client.access(references: ["op://demo/db/url"], reason: "e2e first", ttlSeconds: 3600)
    check(first["op://demo/db/url"] == Data("postgres://s3cr3t".utf8), "value resolves end-to-end over the socket")

    let second = try client.access(references: ["op://demo/db/url"], reason: "e2e second", ttlSeconds: 3600)
    check(second["op://demo/db/url"] == Data("postgres://s3cr3t".utf8), "second fetch succeeds")

    let consentCalls = await consent.calls()
    check(consentCalls == 1, "consent asked once; the subtree grant covered the second fetch")

    let capturedCaller = (await capture.snapshot()).caller
    check(capturedCaller?.peerIdentity?.audit.pid == getpid(),
          "server caller PID comes from the complete kernel audit token")
    check(capturedCaller?.peerIdentity?.audit.effectiveUID == getuid(),
          "server caller effective uid comes from the kernel audit token")
    check(capturedCaller?.peerIdentity?.audit.pidVersion ?? -1 >= 0,
          "server retains the audit-token PID version")
    check(capturedCaller?.peerIdentity?.audit.rawAuditToken.isEmpty == false,
          "server retains the complete opaque audit token")
    check(capturedCaller?.peerIdentity?.code.role == .other,
          "unsigned/ad-hoc test code is explicitly unverified, not product code")
} catch {
    check(false, "client access failed: \(error)")
}

do {
    let sessionID = try client.beginSession()
    let sessionPlan = DeliveryPlan(
        mechanism: .directHeap,
        executable: PlannedExecutable(
            canonicalPath: URL(fileURLWithPath: CommandLine.arguments[0])
                .standardizedFileURL.resolvingSymlinksInPath().path,
            assurance: .userWritable
        ),
        root: .registeredSession(id: sessionID),
        descendantScope: .broadSession,
        destination: .localDevelopment,
        requestedTTLSeconds: 300,
        operationContext: "registered session ancestry test"
    )
    let values = try client.access(
        references: ["op://session-tests/credential/token"],
        reason: "registered session ancestry test",
        ttlSeconds: 300,
        deliveryPlan: sessionPlan
    )
    check(values["op://session-tests/credential/token"] == Data("session-root-synthetic-token".utf8),
          "a live registered session roots access at its exact process incarnation")

    let outsiderRequest = try AccessRequest(
        references: ["op://session-tests/credential/token"],
        reason: "copied session hint",
        ttlSeconds: 300,
        deliveryPlan: sessionPlan
    )
    let parentPID = getppid()
    let outsiderResponse = await agent.handle(
        request: outsiderRequest,
        caller: CallerInfo(
            pid: parentPID,
            startTime: ProcessAncestry.startTime(of: parentPID) ?? 0,
            description: "process outside registered subtree"
        )
    )
    check(outsiderResponse.failure?.code == .invalidRequest,
          "copying a session ID outside its kernel ancestry grants no authority")

    let forgedPlan = DeliveryPlan(
        mechanism: .directHeap,
        executable: sessionPlan.executable,
        root: .registeredSession(id: UUID().uuidString.lowercased()),
        descendantScope: .broadSession,
        destination: .localDevelopment,
        requestedTTLSeconds: 300,
        operationContext: "forged registered session"
    )
    let forgedRequest = try AccessRequest(
        references: ["op://session-tests/credential/token"],
        reason: "forged registered session",
        ttlSeconds: 300,
        deliveryPlan: forgedPlan
    )
    let forgedResponse = await agent.handle(
        request: forgedRequest,
        caller: CallerInfo(
            pid: getpid(),
            startTime: ProcessAncestry.startTime(of: getpid()) ?? 0,
            description: "forged session caller"
        )
    )
    check(forgedResponse.failure?.code == .invalidRequest,
          "an unregistered opaque session ID is rejected before policy or resolution")
} catch {
    check(false, "registered-session ancestry checks succeed (\(error))")
}

// Reciprocal gate: a production server rejects this unsigned client before its
// access request reaches the handler. The client relaxes only server checking
// here so the test exercises the daemon-side decision.
let strictSocketPath = NSTemporaryDirectory() + "cs-e2e-strict-\(getpid()).sock"
let strictCapture = RequestCapture()
let strictServer = SocketServer(path: strictSocketPath) { _, caller in
    await strictCapture.record(caller)
    return Response(error: "should not be reached")
}
Thread.detachNewThread { try? strictServer.run() }
waited = 0
while !FileManager.default.fileExists(atPath: strictSocketPath) && waited < 100 {
    usleep(20_000)
    waited += 1
}
do {
    _ = try AgentClient(
        path: strictSocketPath,
        serverTrustPolicy: .allowUnverifiedForTesting
    ).access(references: ["op://demo/db/url"], reason: "must be rejected", ttlSeconds: 60)
    check(false, "production server rejects an unsigned client")
} catch {
    check(true, "production server rejects an unsigned client")
}
usleep(20_000)
check((await strictCapture.snapshot()).calls == 0,
      "unsigned client's access request never reaches the production handler")
unlink(strictSocketPath)

// An unknown reference must surface as an error, not a silent empty result.
do {
    _ = try client.access(references: ["op://demo/missing"], reason: "e2e missing", ttlSeconds: 60)
    check(false, "a missing reference should raise")
} catch {
    check(true, "a missing reference raises (\(error))")
}

// Consent delta: requesting an already-granted reference plus a new one prompts
// only for the new one, and both resolve. This is the core grant-expansion rule.
do {
    let before = await consent.calls()
    let both = try client.access(
        references: ["op://demo/db/url", "op://demo/api/key"],
        reason: "e2e delta", ttlSeconds: 3600
    )
    let after = await consent.calls()
    check(after - before == 1, "adding one new reference consents only for the delta (\(after - before))")
    check(both["op://demo/db/url"] == Data("postgres://s3cr3t".utf8) && both["op://demo/api/key"] == Data("sk-demo-123".utf8),
          "both the already-granted and the newly-granted reference resolve")
} catch {
    check(false, "consent-delta access failed: \(error)")
}

// Native provider management stays on the same mutually authenticated socket,
// but uses a separate exact-caller edit session rather than a secret grant.
do {
    let consentBeforeUnboundEditor = await consent.calls()
    do {
        _ = try client.beginNativeStoreEdit(
            store: "unbound_editor",
            mode: .externalTemporaryFile
        )
        check(false, "external editor mode requires its actual executable path")
    } catch AgentClient.ClientError.protocolFailure(.invalidRequest, _) {
        check(await consent.calls() == consentBeforeUnboundEditor,
              "external editor mode is bound to its executable before policy or biometric")
    }

    let edit = try client.beginNativeStoreEdit(store: "development")
    check((try? NativeStoreDocument(data: edit.document).values.isEmpty) == true,
          "native-store edit begins with a decrypted empty JSON document")
    do {
        _ = try client.commitNativeStoreEdit(
            sessionID: edit.sessionID,
            document: Data(#"{"NATIVE_TOKEN":"one","NATIVE_TOKEN":"two"}"#.utf8)
        )
        check(false, "invalid native-store JSON returns a typed failure")
    } catch AgentClient.ClientError.protocolFailure(.invalidStoreDocument, _) {
        check(true, "invalid native-store JSON returns a typed failure without consuming the edit session")
    }
    let commit = try client.commitNativeStoreEdit(
        sessionID: edit.sessionID,
        document: Data(#"{"NATIVE_TOKEN":"native-synthetic-token"}"#.utf8)
    )
    check(commit.generation == 1 && commit.secretCount == 1,
          "native-store edit validates, encrypts, and commits over the authenticated protocol")

    let nativeValues = try client.access(
        references: ["csec://development/NATIVE_TOKEN"],
        reason: "native provider e2e",
        ttlSeconds: 3600
    )
    check(nativeValues["csec://development/NATIVE_TOKEN"] == Data("native-synthetic-token".utf8),
          "csec:// value resolves end-to-end through the native encrypted provider")

    let mixed = try client.access(
        references: ["op://demo/db/url", "csec://development/NATIVE_TOKEN"],
        reason: "mixed provider e2e",
        ttlSeconds: 3600
    )
    check(mixed["op://demo/db/url"] == Data("postgres://s3cr3t".utf8)
          && mixed["csec://development/NATIVE_TOKEN"] == Data("native-synthetic-token".utf8),
          "one request resolves 1Password and native-store references together")

    // Whole-file import over the wire: begin an onboarding-import session, commit a
    // blob batch (including binary), then resolve them back as csec:// values.
    let importEdit = try client.beginNativeStoreEdit(
        store: "development", mode: .onboardingImport)
    let importCommit = try client.commitNativeStoreBlobs(
        sessionID: importEdit.sessionID,
        blobs: [
            ProtectedBlobImport(
                key: "ENVRC_FILE", data: Data("export A=1\nuse_flake\n".utf8),
                mode: 0o600, path: ".envrc"),
            ProtectedBlobImport(
                key: "KEYFILE", data: Data([0x00, 0x01, 0xff, 0xfe]),
                mode: 0o400, path: "config/master.key"),
        ]
    )
    check(importCommit.generation >= 1 && importCommit.secretCount == 2,
          "a whole-file import commits its blob batch over the authenticated protocol")
    let importedValues = try client.access(
        references: ["csec://development/ENVRC_FILE", "csec://development/KEYFILE"],
        reason: "imported blob e2e",
        ttlSeconds: 3600
    )
    check(importedValues["csec://development/ENVRC_FILE"] == Data("export A=1\nuse_flake\n".utf8)
          && importedValues["csec://development/KEYFILE"] == Data([0x00, 0x01, 0xff, 0xfe]),
          "imported whole-file (incl. binary) values resolve via csec:// with full fidelity")

    // Cross-tier uniqueness holds over the wire (NATIVE_TOKEN is a document key).
    let clashEdit = try client.beginNativeStoreEdit(
        store: "development", mode: .onboardingImport)
    do {
        _ = try client.commitNativeStoreBlobs(
            sessionID: clashEdit.sessionID,
            blobs: [ProtectedBlobImport(
                key: "NATIVE_TOKEN", data: Data("x".utf8), mode: 0o600, path: "t")]
        )
        check(false, "a blob import cannot shadow an existing document key over the wire")
    } catch AgentClient.ClientError.protocolFailure(.invalidStoreDocument, _) {
        check(true, "a blob import cannot shadow an existing document key over the wire")
    }
} catch {
    check(false, "native-store protocol checks succeed (\(error))")
}

// Full `csec exec` path: run the actual built binary against this agent and
// confirm the (fake) secret lands in the child's environment. CSEC_SOCKET points
// csec at our temp agent; the fake value is safe to print.
let selfURL = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
let csecURL = selfURL.deletingLastPathComponent().appendingPathComponent("csec")
let fileProbeURL = selfURL.deletingLastPathComponent().appendingPathComponent("cs-file-probe")
let ghFixtureURL = selfURL.deletingLastPathComponent().appendingPathComponent("cs-gh-fixture")
let fakeRootURL = selfURL.deletingLastPathComponent().appendingPathComponent("cs-fake-rootd")
let processTitleFixtureURL = selfURL.deletingLastPathComponent()
    .appendingPathComponent("cs-process-title-fixture")

let fakeRoot = Process()
fakeRoot.executableURL = fakeRootURL
var fakeRootEnvironment = ProcessInfo.processInfo.environment
fakeRootEnvironment["CSEC_ROOT_SOCKET"] = rootSocketPath
fakeRoot.environment = fakeRootEnvironment
fakeRoot.standardInput = FileHandle.nullDevice
fakeRoot.standardOutput = FileHandle.nullDevice
fakeRoot.standardError = FileHandle.nullDevice
try? FileManager.default.removeItem(atPath: rootFixtureDirectory)
try? fakeRoot.run()
var rootWaited = 0
while !FileManager.default.fileExists(atPath: rootSocketPath) && rootWaited < 100 {
    usleep(20_000)
    rootWaited += 1
}
check(FileManager.default.fileExists(atPath: rootSocketPath), "synthetic root-helper socket is listening")

let completeStatus = runCsec(
    ["status"], extraEnv: ["SSH_AUTH_SOCK": sshSocketPath]
)
// The status block renders as a colored, glyphed report (StatusRenderer): each
// row is `● <label>:  <value>` with an overall verdict badge. Assert on the
// value substrings and the healthy badge; exit 0 already proves every component
// (agent, provider, SSH, root) is healthy via CompleteStatus.healthy.
check(completeStatus.status == 0
      && completeStatus.out.contains("healthy")
      && completeStatus.out.contains("Agent control channel:")
      && completeStatus.out.contains("reachable and authenticated")
      && completeStatus.out.contains("csec, op")
      && completeStatus.out.contains("SSH agent:")
      && completeStatus.out.contains("ready")
      && completeStatus.out.contains("Root helper:")
      && completeStatus.out.contains("GitHub token proxy:"),
      "csec status consolidates authenticated agent, provider, SSH, GitHub proxy, and root health")

let doctorCheck = runCsec(
    ["doctor", "--check"], extraEnv: ["SSH_AUTH_SOCK": sshSocketPath]
)
// The doctor narrative is now a styled note on stderr; the status block (with the
// healthy badge) is the stdout report.
check(doctorCheck.status == 0
      && doctorCheck.err.contains("checking the complete installation")
      && doctorCheck.out.contains("healthy")
      && doctorCheck.out.contains("ready"),
      "csec doctor --check performs a healthy read-only diagnosis")

for arguments in [["doctor", "--runtime"], ["doctor", "--check", "--runtime"],
                  ["doctor", "--runtime", "--check"]] {
    let runtimeCheck = runCsec(arguments, extraEnv: ["SSH_AUTH_SOCK": sshSocketPath])
    check(runtimeCheck.status == 0
          && runtimeCheck.err.contains("checking the installed runtime")
          && runtimeCheck.out.contains("Convenient Security runtime status")
          && runtimeCheck.out.contains("not checked (runtime-only mode)")
          && !runtimeCheck.err.contains("checking the complete installation"),
          "csec doctor runtime gate identifies its limited scope: \(arguments.joined(separator: " "))")
}
let runtimeWithoutRoot = runCsec(
    ["doctor", "--runtime", "--check"],
    extraEnv: ["CSEC_ROOT_SOCKET": rootSocketPath + ".missing"])
check(runtimeWithoutRoot.status != 0 && runtimeWithoutRoot.out.contains("Root helper:"),
      "the runtime gate still fails when the root-helper endpoint is unavailable")
let runtimeWithoutAgent = runCsec(
    ["doctor", "--runtime", "--check"],
    extraEnv: ["CSEC_SOCKET": socketPath + ".missing"])
check(runtimeWithoutAgent.status != 0 && runtimeWithoutAgent.out.contains("Agent control channel:"),
      "the runtime gate still fails when the agent endpoint is unavailable")

gitHubProxyE2ETests(socketPath: githubSocketPath, upstream: githubUpstream)
flyE2ETests()

let legacySSHStatus = runCsec(
    ["ssh", "status"], extraEnv: ["SSH_AUTH_SOCK": sshSocketPath]
)
check(legacySSHStatus.status == 0
      && legacySSHStatus.err.contains("status is consolidated under `csec status`")
      && legacySSHStatus.out.contains("Convenient Security status"),
      "csec ssh status redirects users to the complete status report")

let fakeGHURL = URL(fileURLWithPath: rootFixtureDirectory).appendingPathComponent("gh")
try? FileManager.default.removeItem(at: fakeGHURL)
do {
    try FileManager.default.copyItem(at: ghFixtureURL, to: fakeGHURL)
    try FileManager.default.setAttributes(
        [.posixPermissions: 0o755],
        ofItemAtPath: fakeGHURL.path
    )
} catch {
    check(false, "synthetic gh fixture can be installed (\(error))")
}

func runCsec(
    _ arguments: [String],
    extraEnv: [String: String]
) -> (status: Int32, reason: Process.TerminationReason, out: String, err: String) {
    let process = Process()
    process.executableURL = csecURL
    process.arguments = arguments
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    for name in [
        "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
        "GH_CONFIG_DIR",
    ] { environment.removeValue(forKey: name) }
    for (key, value) in extraEnv { environment[key] = value }
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, .exit, "", "spawn failed: \(error)")
    }
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        process.terminationReason,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func jsonStringLiteral(_ value: String) -> String {
    guard let encoded = try? JSONEncoder().encode(value) else { return "\"\"" }
    return String(decoding: encoded, as: UTF8.self)
}

let rootStatus = runCsec(["root-status"], extraEnv: [:])
check(rootStatus.status == 0
      && rootStatus.out == "csec: authenticated root helper reachable\n"
      && rootStatus.err.isEmpty,
      "root-status verifies the authenticated root-helper protocol endpoint")

// Persistent automation end to end: enroll through the authenticated control
// protocol, launch Node as the runner's exact child, fetch through the real
// private bridge, and prove revocation removes the registration. Every value is
// synthetic and the materialization stores are process-local test doubles.
do {
    let emptyAutomation = runCsec(["automation", "list"], extraEnv: [:])
    check(emptyAutomation.status == 0
          && emptyAutomation.out.contains("no unattended automation jobs"),
          "automation control protocol lists an empty catalog")

    let node = try ExecutableInspection.plannedExecutable(command: "node").canonicalPath
    var repositoryURL = URL(fileURLWithPath: #filePath)
    for _ in 0..<4 { repositoryURL.deleteLastPathComponent() }
    let moduleURL = repositoryURL
        .appendingPathComponent("clients/node/dist/esm/index.js")
        .absoluteURL.absoluteString
    let scriptURL = URL(fileURLWithPath: e2eWorkingDirectory)
        .appendingPathComponent("automation-node-e2e.mjs")
    let automationReference = "op://demo/api/key"
    let script = """
    import { access } from \(jsonStringLiteral(moduleURL));
    const reference = \(jsonStringLiteral(automationReference));
    const values = await access([reference], {
      reason: 'Synthetic unattended Node e2e',
      ttl: 30,
      bridgePath: \(jsonStringLiteral(csecURL.path)),
      testSocketPath: \(jsonStringLiteral(socketPath)),
    });
    if (values[reference] !== 'sk-demo-123') process.exit(3);
    process.stdout.write('automation-node-ok\\n');
    """
    try Data(script.utf8).write(to: scriptURL, options: .atomic)

    let jobName = "node-e2e"
    let enrolled = runCsec([
        "automation", "add", jobName,
        "--ref", automationReference,
        "--reason", "Synthetic unattended Node e2e",
        "--max-runtime", "30",
        "--cwd", e2eWorkingDirectory,
        "--", node, scriptURL.path,
    ], extraEnv: [:])
    check(enrolled.status == 0
          && enrolled.out.contains("enrolled unattended automation job \(jobName)"),
          "automation enrollment materializes a synthetic reference over the real socket")

    let listedAutomation = runCsec(["automation", "list"], extraEnv: [:])
    check(listedAutomation.status == 0
          && listedAutomation.out.contains(jobName)
          && listedAutomation.out.contains(node)
          && listedAutomation.out.contains(automationReference),
          "automation list returns the persistent value-free command recipe")

    let automationRun = runCsec(["automation", "run", jobName], extraEnv: [:])
    check(automationRun.status == 0
          && automationRun.out == "automation-node-ok\n"
          && automationRun.err.isEmpty,
          "automation runs Node as the exact child and authorizes its real language bridge "
            + "(status \(automationRun.status), out \(automationRun.out.debugDescription), "
            + "err \(automationRun.err.debugDescription))")

    let revoked = runCsec(["automation", "revoke", jobName], extraEnv: [:])
    let afterRevoke = runCsec(["automation", "list"], extraEnv: [:])
    check(revoked.status == 0
          && afterRevoke.status == 0
          && afterRevoke.out.contains("no unattended automation jobs"),
          "automation revoke removes the persistent grant and materialization")

    let timeoutJobName = "timeout-e2e"
    let enrolledTimeout = runCsec([
        "automation", "add", timeoutJobName,
        "--ref", automationReference,
        "--max-runtime", "2",
        "--cwd", e2eWorkingDirectory,
        "--", "/bin/sleep", "10",
    ], extraEnv: [:])
    let timedOut = runCsec(["automation", "run", timeoutJobName], extraEnv: [:])
    let revokedTimeout = runCsec(
        ["automation", "revoke", timeoutJobName], extraEnv: [:]
    )
    check(enrolledTimeout.status == 0
          && timedOut.status == 124
          && timedOut.err.contains("exceeded its registered maximum runtime")
          && revokedTimeout.status == 0,
          "automation enforces its registered runtime and reports timeout status 124")

    // A child that outlives its runtime and only then asks for its secrets —
    // here from its SIGTERM handler, inside the runner's five-second grace —
    // is still an automation caller. csecd must answer its real bridge with
    // the typed expiry, never open the attended review that would prompt for
    // an unattended job.
    let lateScriptURL = URL(fileURLWithPath: e2eWorkingDirectory)
        .appendingPathComponent("automation-late-bridge-e2e.mjs")
    let lateReason = "Late bridge after the runtime cap"
    let lateScript = """
    import { access } from \(jsonStringLiteral(moduleURL));
    const reference = \(jsonStringLiteral(automationReference));
    process.on('SIGTERM', async () => {
      try {
        await access([reference], {
          reason: \(jsonStringLiteral(lateReason)),
          ttl: 30,
          bridgePath: \(jsonStringLiteral(csecURL.path)),
          testSocketPath: \(jsonStringLiteral(socketPath)),
        });
        process.stdout.write('late-bridge-released\\n');
      } catch (error) {
        process.stdout.write('late-bridge: ' + String(error.message) + '\\n');
      }
      process.exit(0);
    });
    setInterval(() => {}, 1000);
    """
    try Data(lateScript.utf8).write(to: lateScriptURL, options: .atomic)
    let lateJobName = "late-bridge-e2e"
    let enrolledLate = runCsec([
        "automation", "add", lateJobName,
        "--ref", automationReference,
        "--reason", lateReason,
        "--max-runtime", "2",
        "--cwd", e2eWorkingDirectory,
        "--", node, lateScriptURL.path,
    ], extraEnv: [:])
    let reviewsBeforeLate = (await accessReviewCapture.snapshot()).count
    let lateRun = runCsec(["automation", "run", lateJobName], extraEnv: [:])
    let lateReviews = (await accessReviewCapture.snapshot()).dropFirst(reviewsBeforeLate)
    let revokedLate = runCsec(["automation", "revoke", lateJobName], extraEnv: [:])
    check(enrolledLate.status == 0
          && lateRun.status == 124
          && lateRun.out.contains("late-bridge: automation_run_expired")
          && !lateRun.out.contains("late-bridge-released")
          && !lateReviews.contains(where: { $0.reason == lateReason })
          && revokedLate.status == 0,
          "a bridge after the runtime cap gets the typed automation expiry, not an attended review "
            + "(status \(lateRun.status), out \(lateRun.out.debugDescription), "
            + "err \(lateRun.err.debugDescription), late reviews \(lateReviews.count))")
} catch {
    check(false, "unattended Node automation end-to-end checks run (\(error))")
}

// The language bridge's TTL is optional. The Node client omits ttlSeconds, the
// real bridge accepts the request, and csecd mints a grant rooted at the Node
// process with no clock, exactly as for `csec exec`. The same Node process then
// frames a request by hand with a lifetime beyond the clients' own 48-hour
// bound: the bridge passes an explicit TTL through as csecd honours it. Both
// grants die with the Node process, which stays alive until its stdin closes
// so they can be read while it is live.
do {
    let node = try ExecutableInspection.plannedExecutable(command: "node").canonicalPath
    var repositoryURL = URL(fileURLWithPath: #filePath)
    for _ in 0..<4 { repositoryURL.deleteLastPathComponent() }
    let moduleURL = repositoryURL
        .appendingPathComponent("clients/node/dist/esm/index.js")
        .absoluteURL.absoluteString
    let reason = "Synthetic TTL-free bridge e2e"
    let longReason = "Synthetic long-TTL bridge e2e"
    let longTTL = 172_801
    let reference = "op://demo/api/key"
    let scriptURL = URL(fileURLWithPath: e2eWorkingDirectory)
        .appendingPathComponent("bridge-ttl-free-e2e.mjs")
    let script = """
    import { spawn } from 'node:child_process';
    import { access } from \(jsonStringLiteral(moduleURL));
    const reference = \(jsonStringLiteral(reference));
    const values = await access([reference], {
      reason: \(jsonStringLiteral(reason)),
      bridgePath: \(jsonStringLiteral(csecURL.path)),
      testSocketPath: \(jsonStringLiteral(socketPath)),
    });
    if (values[reference] !== 'sk-demo-123') process.exit(3);
    const bridge = spawn(\(jsonStringLiteral(csecURL.path)), ['bridge'], {
      env: { PATH: '/usr/bin:/bin', CSEC_SOCKET: \(jsonStringLiteral(socketPath)) },
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    const payload = Buffer.from(JSON.stringify({
      version: 1, references: [reference], reason: \(jsonStringLiteral(longReason)), ttlSeconds: \(longTTL),
    }));
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length);
    bridge.stdin.end(Buffer.concat([header, payload]));
    const chunks = [];
    for await (const chunk of bridge.stdout) chunks.push(chunk);
    const frame = Buffer.concat(chunks);
    const response = JSON.parse(frame.subarray(4, 4 + frame.readUInt32BE(0)).toString('utf8'));
    if (response.values?.[reference] !== 'sk-demo-123') process.exit(4);
    process.stdout.write('bridge-ttl-free-ok\\n');
    process.stdin.resume();
    process.stdin.on('end', () => process.exit(0));
    """
    try Data(script.utf8).write(to: scriptURL, options: .atomic)

    let consumer = Process()
    consumer.executableURL = URL(fileURLWithPath: node)
    consumer.arguments = [scriptURL.path]
    let consumerInput = Pipe(), consumerOutput = Pipe()
    consumer.standardInput = consumerInput
    consumer.standardOutput = consumerOutput
    consumer.standardError = FileHandle.nullDevice
    try consumer.run()
    var received = Data()
    while received.range(of: Data("bridge-ttl-free-ok\n".utf8)) == nil {
        let chunk = consumerOutput.fileHandleForReading.availableData
        if chunk.isEmpty { break }
        received.append(chunk)
    }
    let observedAt = Date()
    let liveGrants = await grants.summaries(now: observedAt)
    let grant = liveGrants.first { $0.reason == reason }
    let longGrant = liveGrants.first { $0.reason == longReason }
    let review = await accessReviewCapture.snapshot().last { $0.reason == reason }
    let longReview = await accessReviewCapture.snapshot().last { $0.reason == longReason }
    consumerInput.fileHandleForWriting.closeFile()
    consumer.waitUntilExit()
    let ran = String(decoding: received, as: UTF8.self) == "bridge-ttl-free-ok\n"
        && consumer.terminationStatus == 0
    check(ran
          && grant?.rootPID == consumer.processIdentifier
          && grant != nil && grant?.expiresAt == nil
          && review != nil && review?.plan.requestedTTLSeconds == nil
          && review?.durationChoices?.defaultOption == .processLifetime,
          "a TTL-free bridge request is accepted and mints a no-clock grant rooted at its Node caller "
              + "(status \(consumer.terminationStatus), grant \(grant != nil), "
              + "expiry \(String(describing: grant?.expiresAt)), "
              + "requested TTL \(String(describing: review?.plan.requestedTTLSeconds)))")
    let longRemaining = longGrant?.expiresAt.map { $0.timeIntervalSince(observedAt) }
    check(ran
          && longGrant?.rootPID == consumer.processIdentifier
          && longRemaining.map { abs($0 - Double(longTTL)) < 120 } == true
          && longReview?.plan.requestedTTLSeconds == longTTL
          && longReview?.durationChoices?.defaultOption == .bounded(seconds: longTTL),
          "the bridge passes an explicit ttlSeconds of \(longTTL), beyond the clients' bound, through to "
              + "csecd, which honours it (status \(consumer.terminationStatus), grant \(longGrant != nil), "
              + "remaining \(String(describing: longRemaining)), "
              + "requested TTL \(String(describing: longReview?.plan.requestedTTLSeconds)))")
} catch {
    check(false, "the TTL-free bridge end-to-end check runs (\(error))")
}

// An explicit bridge TTL must still be positive: the real bridge refuses zero or
// a negative lifetime before it identifies its parent or asks csecd for anything.
do {
    func bridgeFailure(_ json: String) -> (status: Int32, code: WireErrorCode?) {
        let bridge = Process()
        bridge.executableURL = csecURL
        bridge.arguments = ["bridge"]
        var environment = ProcessInfo.processInfo.environment
        environment["CSEC_SOCKET"] = socketPath
        bridge.environment = environment
        let input = Pipe(), output = Pipe()
        bridge.standardInput = input
        bridge.standardOutput = output
        bridge.standardError = FileHandle.nullDevice
        do { try bridge.run() } catch { return (-1, nil) }
        _ = writeFrame(input.fileHandleForWriting.fileDescriptor, Data(json.utf8))
        input.fileHandleForWriting.closeFile()
        let response = readFrame(output.fileHandleForReading.fileDescriptor)
            .flatMap { try? JSONDecoder().decode(BridgeResponse.self, from: $0) }
        bridge.waitUntilExit()
        return (bridge.terminationStatus, response?.failure?.code)
    }
    let before = await accessRequests.calls()
    for ttl in ["0", "-60"] {
        let refused = bridgeFailure(
            #"{"version":1,"references":["op://demo/api/key"],"reason":"positive ttl e2e","ttlSeconds":\#(ttl)}"#
        )
        check(refused.status == 2 && refused.code == .invalidRequest,
              "the bridge refuses an explicit ttlSeconds of \(ttl) as an invalid request "
                  + "(status \(refused.status), code \(String(describing: refused.code)))")
    }
    let after = await accessRequests.calls()
    check(after == before, "a refused bridge TTL never reaches csecd (access requests \(after - before))")
}

// `csec protect` end to end: run the real launcher in a throwaway project dir and
// confirm it imports the plaintext into the encrypted store, writes a valid
// sidecar in its place, removes the plaintext, and that the imported value
// resolves back byte-for-byte through csec://.
do {
    let projectDir = NSTemporaryDirectory()
        + "csec-protect-e2e-\(UUID().uuidString.lowercased())"
    try FileManager.default.createDirectory(
        atPath: projectDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: projectDir) }
    let envrcPath = projectDir + "/.envrc"
    let envrcBytes = Data("export SECRET_TOKEN=protect-e2e-synthetic\nuse_flake\n".utf8)
    try envrcBytes.write(to: URL(fileURLWithPath: envrcPath))

    let process = Process()
    process.executableURL = csecURL
    process.arguments = ["protect", "--whole-file", ".envrc"]
    process.currentDirectoryURL = URL(fileURLWithPath: projectDir)
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    try process.run()
    _ = outPipe.fileHandleForReading.readDataToEndOfFile()
    let protectErr = String(
        data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    process.waitUntilExit()

    check(process.terminationStatus == 0,
          "csec protect exits cleanly (stderr: \(protectErr))")
    check(!FileManager.default.fileExists(atPath: envrcPath),
          "csec protect removes the plaintext file")
    let sidecarPath = envrcPath + ".csec"
    check(FileManager.default.fileExists(atPath: sidecarPath),
          "csec protect writes a .csec sidecar in the plaintext's place")

    let sidecar = try ProtectedFileSidecar(
        data: Data(contentsOf: URL(fileURLWithPath: sidecarPath)))
    let resolved = try client.access(
        references: [sidecar.reference.uri],
        reason: "protect e2e resolve",
        ttlSeconds: 3600
    )
    check(resolved[sidecar.reference.uri] == envrcBytes,
          "the protected .envrc resolves back through csec:// with full fidelity")
} catch {
    check(false, "csec protect end-to-end succeeds (\(error))")
}

// `csec edit --remove` end to end: the real launcher deletes a protected file's
// stored value after one touch, but not while its sidecar is still in place,
// and turns away what it could never delete before asking csecd.
do {
    try FileManager.default.createDirectory(atPath: removalProjectDirectory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: removalProjectDirectory) }
    let filePath = removalProjectDirectory + "/service.json"
    try Data("{\"synthetic\":\"remove-e2e\"}".utf8).write(to: URL(fileURLWithPath: filePath))
    let protected = runCsecPipedAt(
        cwd: removalProjectDirectory, ["protect", "--whole-file", "--store", "remove-e2e", "service.json"], input: Data())
    let sidecarPath = filePath + ProtectedFileSidecar.suffix
    check(protected.status == 0 && FileManager.default.fileExists(atPath: sidecarPath),
          "edit --remove: csec protect stores the fixture file (err: \(protected.err.suffix(200)))")
    let reference = try ProtectedFileSidecar(data: Data(contentsOf: URL(fileURLWithPath: sidecarPath))).reference.uri
    _ = try client.access(references: [reference], reason: "edit --remove e2e grant", ttlSeconds: 3600)
    let granted = await grants.summaries(now: Date()).contains { $0.references.contains(reference) }

    let touchesBefore = await consent.authentications()
    let inPlace = runCsecPipedAt(cwd: removalProjectDirectory, ["edit", "--remove", reference], input: Data())
    let touchesAfterInPlace = await consent.authentications()
    check(inPlace.status == 1 && inPlace.err.contains("still used by the sidecar")
          && touchesAfterInPlace == touchesBefore,
          "edit --remove refuses a value whose sidecar is still in place, before any touch "
              + "(status \(inPlace.status), err: \(inPlace.err.suffix(200)))")

    try FileManager.default.removeItem(atPath: sidecarPath)
    let removed = runCsecPipedAt(cwd: removalProjectDirectory, ["edit", reference, "--remove"], input: Data())
    let touchesAfterRemoval = await consent.authentications()
    let stillGranted = await grants.summaries(now: Date()).contains { $0.references.contains(reference) }
    check(removed.status == 0
          && removed.out.contains("csec edit: deleted \(reference) (protected from service.json)")
          && touchesAfterRemoval == touchesBefore + 1,
          "edit --remove deletes the value after one touch and names where it was protected from "
              + "(status \(removed.status), out: \(removed.out.suffix(200)), err: \(removed.err.suffix(200)))")
    check(granted && !stillGranted && removed.out.contains("revoked 1 grant that covered it"),
          "edit --remove takes the value's grant with it")
    do {
        _ = try client.access(references: [reference], reason: "edit --remove e2e after", ttlSeconds: 3600)
        check(false, "a deleted value no longer resolves")
    } catch {
        check(true, "a deleted value no longer resolves")
    }
    let twice = runCsecPipedAt(cwd: removalProjectDirectory, ["edit", "--remove", reference], input: Data())
    check(twice.status == 1 && twice.err.contains("not a whole-file value"),
          "edit --remove refuses a value that is not there (err: \(twice.err.suffix(200)))")

    let touchesBeforeRefusals = await consent.authentications()
    let foreign = runCsecPipedAt(cwd: removalProjectDirectory, ["edit", "--remove", "op://vault/item/field"], input: Data())
    let twoStores = runCsecPipedAt(
        cwd: removalProjectDirectory, ["edit", "--remove", "csec://remove-e2e/a", "csec://other/b"], input: Data())
    let tooMany = runCsecPipedAt(
        cwd: removalProjectDirectory,
        ["edit", "--remove"] + (0...NativeStoreRemovalRequest.maximumReferences).map { "csec://remove-e2e/k\($0)" },
        input: Data())
    let touchesAfterRefusals = await consent.authentications()
    check(foreign.status == 1 && foreign.err.contains("deletes only values csec stores itself")
          && twoStores.status == 1 && twoStores.err.contains("one store at a time")
          && tooMany.status == 1 && tooMany.err.contains("so the Touch ID panel can name each one")
          && touchesAfterRefusals == touchesBeforeRefusals,
          "edit --remove turns away another provider's reference, two stores and an unnameable batch, with no touch")
} catch {
    check(false, "csec edit --remove end-to-end succeeds (\(error))")
}

// Manual SSH protection end to end: generate a throwaway key, import it through
// the real CLI, prove the original is removed only after registration without
// leaving a redundant sidecar, and separately exercise re-registration through
// the ordinary backend-neutral sidecar format accepted by `csec ssh register`.
do {
    let fixtureDirectory = NSTemporaryDirectory()
        + "csec-protect-ssh-e2e-\(UUID().uuidString.lowercased())"
    try FileManager.default.createDirectory(
        atPath: fixtureDirectory, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: fixtureDirectory) }
    let privateKeyPath = fixtureDirectory + "/id_ed25519"
    let publicKeyPath = privateKeyPath + ".pub"

    let keygen = Process()
    keygen.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    keygen.arguments = [
        "-q", "-t", "ed25519", "-N", "", "-C", "csec-synthetic-e2e",
        "-f", privateKeyPath,
    ]
    keygen.standardInput = FileHandle.nullDevice
    keygen.standardOutput = FileHandle.nullDevice
    keygen.standardError = FileHandle.nullDevice
    try keygen.run()
    keygen.waitUntilExit()
    guard keygen.terminationStatus == 0 else { throw SSHProtectionError.invalidPrivateKey }
    let originalPublicKey = try Data(contentsOf: URL(fileURLWithPath: publicKeyPath))
    let activationExport = "export SSH_AUTH_SOCK=\"$(csec ssh socket)\""
    let otherAgentPath = fixtureDirectory + "/not-csec-agent.sock"

    let protected = runCsec(
        ["protect", "--ssh", privateKeyPath],
        extraEnv: ["SSH_AUTH_SOCK": otherAgentPath]
    )
    check(protected.status == 0,
          "csec protect --ssh imports and registers a synthetic key (err: \(protected.err))")
    check(!FileManager.default.fileExists(atPath: privateKeyPath),
          "protect --ssh removes the unchanged private-key plaintext")
    let sidecarPath = privateKeyPath + ProtectedFileSidecar.suffix
    check(!FileManager.default.fileExists(atPath: sidecarPath),
          "protect --ssh does not leave a redundant .csec sidecar")
    check(try Data(contentsOf: URL(fileURLWithPath: publicKeyPath)) == originalPublicKey,
          "protect --ssh preserves an existing public-key file byte-for-byte")

    let protectedKeys = try client.listSSHKeys()
    guard protectedKeys.count == 1, let protectedKey = protectedKeys.first else {
        throw SSHProtectionError.keyNotRegistered
    }
    check(protectedKey.algorithm == "ssh-ed25519"
          && protected.out.contains(protectedKey.fingerprint),
          "protect --ssh reports the registered public fingerprint without key bytes")
    check(protected.out.contains("Add this line to your shell profile")
          && protected.out.contains(activationExport),
          "protect --ssh explains how to activate csec when SSH_AUTH_SOCK points elsewhere")

    let listed = runCsec(["ssh", "list"], extraEnv: [:])
    check(listed.status == 0
          && listed.out.contains(protectedKey.fingerprint)
          && listed.out.contains(protectedKey.reference),
          "csec ssh list reads backend-neutral public catalog metadata")

    let removed = runCsec(
        ["ssh", "remove", protectedKey.fingerprint], extraEnv: [:]
    )
    let keysAfterRemoval = try client.listSSHKeys()
    check(removed.status == 0 && keysAfterRemoval.isEmpty,
          "csec ssh remove deletes only the catalog registration")

    // Sidecar registration remains useful for a private key protected through
    // the generic file workflow or another backend-neutral reference file. It
    // is deliberately independent from `protect --ssh`.
    let sidecar = try ProtectedFileSidecar(
        reference: SecretRef(protectedKey.reference)
    )
    try sidecar.encoded().write(
        to: URL(fileURLWithPath: sidecarPath), options: .atomic
    )
    let registered = runCsec(
        ["ssh", "register", "--label", "sidecar fixture", sidecarPath],
        extraEnv: ["SSH_AUTH_SOCK": otherAgentPath]
    )
    let restoredKeys = try client.listSSHKeys()
    check(registered.status == 0
          && restoredKeys.count == 1
          && restoredKeys[0].reference == sidecar.reference.uri
          && restoredKeys[0].label == "sidecar fixture",
          "csec ssh register accepts an ordinary sidecar without backend-specific handling")
    check(registered.out.contains("Add this line to your shell profile")
          && registered.out.contains(activationExport),
          "csec ssh register explains how to activate csec when SSH_AUTH_SOCK points elsewhere")

    let registeredFromConfiguredShell = runCsec(
        ["ssh", "register", "--label", "sidecar fixture", sidecarPath],
        extraEnv: ["SSH_AUTH_SOCK": SSHAgentSocket.defaultPath()]
    )
    check(registeredFromConfiguredShell.status == 0
          && !registeredFromConfiguredShell.out.contains(activationExport)
          && !registeredFromConfiguredShell.out.contains("shell profile"),
          "csec ssh register stays quiet when the shell already uses the csec socket")

    // ssh-keygen's OpenSSH RSA document exercises the parser path that derives
    // CRT exponents before importing the private key into Security.framework.
    let rsaPrivateKeyPath = fixtureDirectory + "/id_rsa"
    let rsaPublicKeyPath = rsaPrivateKeyPath + ".pub"
    let rsaKeygen = Process()
    rsaKeygen.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
    rsaKeygen.arguments = [
        "-q", "-t", "rsa", "-b", "2048", "-N", "", "-C", "csec-synthetic-rsa-e2e",
        "-f", rsaPrivateKeyPath,
    ]
    rsaKeygen.standardInput = FileHandle.nullDevice
    rsaKeygen.standardOutput = FileHandle.nullDevice
    rsaKeygen.standardError = FileHandle.nullDevice
    try rsaKeygen.run()
    rsaKeygen.waitUntilExit()
    guard rsaKeygen.terminationStatus == 0 else { throw SSHProtectionError.invalidPrivateKey }
    let rsaPublicKey = try Data(contentsOf: URL(fileURLWithPath: rsaPublicKeyPath))

    let protectedRSA = runCsec(
        ["protect", "--ssh", rsaPrivateKeyPath],
        extraEnv: ["SSH_AUTH_SOCK": SSHAgentSocket.defaultPath()]
    )
    let keysWithRSA = try client.listSSHKeys()
    let rsaPublicPreserved = try Data(
        contentsOf: URL(fileURLWithPath: rsaPublicKeyPath)
    ) == rsaPublicKey
    check(protectedRSA.status == 0
          && !FileManager.default.fileExists(atPath: rsaPrivateKeyPath)
          && !FileManager.default.fileExists(
            atPath: rsaPrivateKeyPath + ProtectedFileSidecar.suffix
          )
          && rsaPublicPreserved
          && keysWithRSA.contains(where: { $0.algorithm == "ssh-rsa" })
          && !protectedRSA.out.contains(activationExport)
          && !protectedRSA.out.contains("shell profile"),
          "protect --ssh supports a generated OpenSSH RSA-2048 key end to end")

    if let rsaKey = keysWithRSA.first(where: { $0.algorithm == "ssh-rsa" }) {
        let inUse = runCsec(["edit", "--remove", rsaKey.reference], extraEnv: [:])
        let keysAfterRefusal = try client.listSSHKeys()
        check(inUse.status == 1 && inUse.err.contains("is the SSH key \(rsaKey.fingerprint)")
              && keysAfterRefusal.contains(rsaKey),
              "edit --remove refuses a registered SSH key's value (err: \(inUse.err.suffix(200)))")
    }
} catch {
    check(false, "csec protect --ssh end-to-end succeeds (\(error))")
}

// `csec protect --env` end to end: drive the real picker through a PTY with
// scripted keystrokes, and prove the safety ordering — values durable in the
// store, then an in-place rewrite that leaves every untouched byte identical.
func runCsecPipedAt(
    cwd: String, _ arguments: [String], input: Data, extraEnv: [String: String] = [:],
    baseEnvironment: [String: String] = ProcessInfo.processInfo.environment
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = csecURL
    process.arguments = arguments
    process.currentDirectoryURL = URL(fileURLWithPath: cwd)
    var environment = baseEnvironment
    environment["CSEC_SOCKET"] = socketPath
    for (key, value) in extraEnv { environment[key] = value }
    process.environment = environment
    let inputPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
    process.standardInput = inputPipe
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed: \(error)")
    }
    inputPipe.fileHandleForWriting.write(input)
    inputPipe.fileHandleForWriting.closeFile()
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

/// Like `runCsecInPTY` but with a working directory and scripted keystrokes:
/// the bytes land in the PTY input queue, so the raw-mode picker, the cooked
/// destination prompt, and the y/N confirmation all consume them in turn.
/// stdout and stderr are merged by the PTY.
func runCsecInPTYAt(
    cwd: String, _ arguments: [String], keystrokes: String
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/script")
    process.arguments = [
        "-q", "/dev/null", "/bin/sh", "-c",
        "stty rows 37 cols 113; exec \"$@\"", "csec-pty", csecURL.path,
    ] + arguments
    process.currentDirectoryURL = URL(fileURLWithPath: cwd)
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    process.environment = environment
    let inputPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
    process.standardInput = inputPipe
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed: \(error)")
    }
    inputPipe.fileHandleForWriting.write(Data(keystrokes.utf8))
    inputPipe.fileHandleForWriting.closeFile()
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

/// Expect-style PTY driver for prompts that must never echo: each step's
/// `send` bytes are written only after its `expect` marker has appeared in the
/// merged PTY output — by which point the command has already turned echo off.
/// stdin stays open until the process exits, so script(1) never relays an
/// early EOF (^D) into the input queue mid-flow.
func runCsecExpectInPTY(
    cwd: String, _ arguments: [String], steps: [(expect: String, send: String)]
) -> (status: Int32, out: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/script")
    process.arguments = [
        "-q", "/dev/null", "/bin/sh", "-c",
        "stty rows 37 cols 113; exec \"$@\"", "csec-pty", csecURL.path,
    ] + arguments
    process.currentDirectoryURL = URL(fileURLWithPath: cwd)
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    process.environment = environment
    let inputPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
    process.standardInput = inputPipe
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "spawn failed: \(error)")
    }
    let watchdog = DispatchWorkItem { process.terminate() }
    DispatchQueue.global().asyncAfter(deadline: .now() + 30, execute: watchdog)
    var collected = Data()
    var remaining = steps
    while true {
        let chunk = outPipe.fileHandleForReading.availableData
        if chunk.isEmpty { break }
        collected.append(chunk)
        while let step = remaining.first,
              String(decoding: collected, as: UTF8.self).contains(step.expect) {
            remaining.removeFirst()
            inputPipe.fileHandleForWriting.write(Data(step.send.utf8))
        }
    }
    inputPipe.fileHandleForWriting.closeFile()
    process.waitUntilExit()
    watchdog.cancel()
    return (process.terminationStatus, String(decoding: collected, as: UTF8.self))
}

do {
    let projectDir = NSTemporaryDirectory()
        + "csec-protect-env-e2e-\(UUID().uuidString.lowercased())"
    try FileManager.default.createDirectory(
        atPath: projectDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: projectDir) }
    let envPath = projectDir + "/.envrc"
    let fixture = """
    # Service configuration
    PORT=3000
    export SLACK_TOKEN=xoxb-e2e-1234567890abcdef
    # DB_PASSWORD=commented-out-password
    API_KEY="quoted-secret-value" # trailing note
    EXISTING_REF=csec://somestore/EXISTING_REF
    BAD_INTERP="$HOME/creds"
    use_flake
    """
    let fixtureData = Data(fixture.utf8)
    try fixtureData.write(to: URL(fileURLWithPath: envPath))
    let store = "protect-env-e2e"

    // Dry run: metadata only, nothing touched, no value ever printed.
    let dryRun = runCsecPipedAt(
        cwd: projectDir, ["protect", "--env", "--store", store, "--dry-run", ".envrc"],
        input: Data())
    check(dryRun.status == 0
          && dryRun.out.contains("[x] SLACK_TOKEN")
          && dryRun.out.contains("[x] API_KEY")
          && dryRun.out.contains("[ ] PORT")
          && dryRun.out.contains("[x] DB_PASSWORD_commented_1")
          && dryRun.out.contains("commented")
          && dryRun.out.contains("already csec://")
          && dryRun.out.contains("unsupported value")
          && !dryRun.out.contains("xoxb-e2e")
          && !dryRun.out.contains("quoted-secret-value")
          && !dryRun.out.contains("commented-out-password"),
          "protect --env --dry-run lists metadata only; a commented secret is preselected")
    check((try? Data(contentsOf: URL(fileURLWithPath: envPath))) == fixtureData,
          "protect --env --dry-run leaves the file byte-identical")

    // Without a terminal the picker refuses rather than guessing.
    let nonTTY = runCsecPipedAt(
        cwd: projectDir, ["protect", "--env", "--store", store, ".envrc"], input: Data())
    check(nonTTY.status == 1 && nonTTY.err.contains("interactive terminal"),
          "protect --env without a TTY fails with a clear message")
    check((try? Data(contentsOf: URL(fileURLWithPath: envPath))) == fixtureData,
          "protect --env without a TTY leaves the file byte-identical")

    // Values stay hidden by default but an explicit `v` reveals every
    // importable candidate long enough to compare before another key action.
    let revealed = runCsecInPTYAt(
        cwd: projectDir, ["protect", "--env", "--store", store, ".envrc"],
        keystrokes: "vq"
    )
    check(revealed.status == 1
          && revealed.out.contains("xoxb-e2e-1234567890abcdef")
          && revealed.out.contains("quoted-secret-value")
          && revealed.out.contains("commented-out-password")
          && revealed.out.contains("Values visible"),
          "protect --env reveals candidate values only after the picker shortcut")
    check((try? Data(contentsOf: URL(fileURLWithPath: envPath))) == fixtureData,
          "revealing then cancelling leaves the env file byte-identical")

    // Cancelling the picker changes nothing.
    let cancelled = runCsecInPTYAt(
        cwd: projectDir, ["protect", "--env", "--store", store, ".envrc"], keystrokes: "q")
    check(cancelled.status == 1 && cancelled.out.contains("cancelled"),
          "protect --env picker cancel exits nonzero and reports it")
    check((try? Data(contentsOf: URL(fileURLWithPath: envPath))) == fixtureData,
          "protect --env picker cancel leaves the file byte-identical")

    // Happy path: accept the preselection (enter), confirm (y). --store is
    // preset so there is no destination prompt. The commented DB_PASSWORD is
    // preselected too — a commented credential is still a credential on disk.
    let imported = runCsecInPTYAt(
        cwd: projectDir, ["protect", "--env", "--store", store, ".envrc"],
        keystrokes: "\ry\n")
    check(imported.status == 0 && imported.out.contains("imported 3 variable(s)"),
          "protect --env imports the preselected variables (out: \(imported.out.suffix(200)))")

    let expected = """
    # Service configuration
    PORT=3000
    export csec_SLACK_TOKEN="csec://\(store)/SLACK_TOKEN"
    # csec_DB_PASSWORD="csec://\(store)/DB_PASSWORD_commented_1"
    csec_API_KEY="csec://\(store)/API_KEY" # trailing note
    csec_EXISTING_REF=csec://somestore/EXISTING_REF
    BAD_INTERP="$HOME/creds"
    use_flake
    """
    let rewritten = try Data(contentsOf: URL(fileURLWithPath: envPath))
    check(rewritten == Data(expected.utf8),
          "protect --env rewrites each selected value — the commented secret under its own "
              + "key, still commented; every other byte is identical")

    let resolved = try client.access(
        references: [
            "csec://\(store)/SLACK_TOKEN", "csec://\(store)/API_KEY",
            "csec://\(store)/DB_PASSWORD_commented_1",
        ],
        reason: "protect --env e2e resolve",
        ttlSeconds: 3600)
    check(resolved["csec://\(store)/SLACK_TOKEN"] == Data("xoxb-e2e-1234567890abcdef".utf8)
          && resolved["csec://\(store)/API_KEY"] == Data("quoted-secret-value".utf8)
          && resolved["csec://\(store)/DB_PASSWORD_commented_1"]
              == Data("commented-out-password".utf8),
          "the imported env values resolve back through csec:// with full fidelity")

    // The rewritten reference composes with `csec exec` (as direnv would
    // export it): the child sees the real value in its environment.
    let execRoundTrip = runCsecPipedAt(
        cwd: projectDir,
        ["exec", "--", "/bin/sh", "-c",
         "test \"$SLACK_TOKEN\" = xoxb-e2e-1234567890abcdef && echo ENV-RESOLVED"],
        input: Data(),
        extraEnv: ["csec_SLACK_TOKEN": "csec://\(store)/SLACK_TOKEN"])
    check(execRoundTrip.status == 0 && execRoundTrip.out.contains("ENV-RESOLVED"),
          "csec exec resolves the rewritten reference into the child environment "
              + "(err: \(execRoundTrip.err.suffix(200)))")

    // Re-running now shows the vars as already-references; nothing importable
    // is preselected.
    let rerun = runCsecPipedAt(
        cwd: projectDir, ["protect", "--env", "--store", store, "--dry-run", ".envrc"],
        input: Data())
    check(rerun.status == 0
          && rerun.out.contains("csec_SLACK_TOKEN  (line 3 · already csec://")
          && !rerun.out.contains("[x]"),
          "a re-run treats rewritten variables as references, not candidates")

    // The interactive destination prompt: default declined, explicit
    // csec://STORE typed in.
    let promptDir = NSTemporaryDirectory()
        + "csec-protect-env-prompt-\(UUID().uuidString.lowercased())"
    try FileManager.default.createDirectory(
        atPath: promptDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: promptDir) }
    let promptEnvPath = promptDir + "/.env"
    try Data("SECRET_TOKEN=prompt-e2e-value-123\n".utf8)
        .write(to: URL(fileURLWithPath: promptEnvPath))
    let promptStore = "protect-env-e2e-prompt"
    let prompted = runCsecInPTYAt(
        cwd: promptDir, ["protect", "--env", ".env"],
        keystrokes: "\rcsec://\(promptStore)\ny\n")
    let promptedRewrite = try Data(contentsOf: URL(fileURLWithPath: promptEnvPath))
    check(prompted.status == 0
          && promptedRewrite == Data("csec_SECRET_TOKEN=\"csec://\(promptStore)/SECRET_TOKEN\"\n".utf8),
          "the destination prompt accepts a typed csec:// store "
              + "(out: \(prompted.out.suffix(200)))")

    let referenceOnly = Data("export TOKEN='op://synthetic/item/token' # keep\n".utf8)
    try referenceOnly.write(to: URL(fileURLWithPath: promptEnvPath))
    let renamedOnly = runCsecInPTYAt(
        cwd: promptDir, ["protect", "--env", "--dest", "op://synthetic", ".env"],
        keystrokes: "\ry\n")
    check(try renamedOnly.status == 0
          && Data(contentsOf: URL(fileURLWithPath: promptEnvPath))
              == Data("export csec_TOKEN='op://synthetic/item/token' # keep\n".utf8),
          "interactive reference-only protection renames without contacting the destination")

    // `csec edit <reference>` — stdin pipe: rotate an imported value, create a
    // brand-new key, and refuse an empty value.
    let rotated = runCsecPipedAt(
        cwd: projectDir, ["edit", "csec://\(store)/SLACK_TOKEN"],
        input: Data("rotated-e2e-value\n".utf8))
    check(rotated.status == 0 && rotated.out.contains("csec://\(store)/SLACK_TOKEN"),
          "csec edit <reference> accepts a piped value (err: \(rotated.err.suffix(200)))")
    let created = runCsecPipedAt(
        cwd: projectDir, ["edit", "csec://\(store)/BRAND_NEW"],
        input: Data("fresh-secret-value\n".utf8))
    check(created.status == 0, "csec edit <reference> creates a missing key")
    let emptied = runCsecPipedAt(
        cwd: projectDir, ["edit", "csec://\(store)/SLACK_TOKEN"], input: Data("\n".utf8))
    check(emptied.status == 1 && emptied.err.contains("empty"),
          "csec edit <reference> refuses an empty value")

    // `csec edit <reference>` — hidden terminal prompt: typed twice, never
    // echoed, wrong confirmation refused. Expect-driven so each line is sent
    // only once its prompt (and therefore echo-off) is in effect.
    let hidden = runCsecExpectInPTY(
        cwd: projectDir, ["edit", "csec://\(store)/SLACK_TOKEN"],
        steps: [
            (expect: "New value", send: "pty-hidden-value\r"),
            (expect: "Confirm value", send: "pty-hidden-value\r"),
        ])
    check(hidden.status == 0 && !hidden.out.contains("pty-hidden-value"),
          "the hidden prompt never echoes the value "
              + "(status \(hidden.status), out: \(hidden.out.suffix(300)))")
    let mismatch = runCsecExpectInPTY(
        cwd: projectDir, ["edit", "csec://\(store)/SLACK_TOKEN"],
        steps: [
            (expect: "New value", send: "first-attempt\r"),
            (expect: "Confirm value", send: "second-attempt\r"),
        ])
    check(mismatch.status == 1 && mismatch.out.contains("did not match"),
          "the hidden prompt refuses a mismatched confirmation "
              + "(status \(mismatch.status), out: \(mismatch.out.suffix(300)))")

    let afterEdits = try client.access(
        references: ["csec://\(store)/SLACK_TOKEN", "csec://\(store)/BRAND_NEW"],
        reason: "edit reference e2e resolve",
        ttlSeconds: 3600)
    check(afterEdits["csec://\(store)/SLACK_TOKEN"] == Data("pty-hidden-value".utf8)
          && afterEdits["csec://\(store)/BRAND_NEW"] == Data("fresh-secret-value".utf8),
          "edited values resolve back with full fidelity")
} catch {
    check(false, "csec protect --env end-to-end succeeds (\(error))")
}

// Explicit paths and AWS migration use only this synthetic home and fake agent.
do {
    let root = NSTemporaryDirectory() + "csec-explicit-e2e-\(UUID().uuidString.lowercased())"
    let home = root + "/home"
    let project = root + "/unrelated-project"
    let fm = FileManager.default
    defer { try? fm.removeItem(atPath: root) }
    try fm.createDirectory(atPath: home + "/.aws", withIntermediateDirectories: true)
    try fm.createDirectory(atPath: project, withIntermediateDirectories: true)
    let credentials = home + "/.aws/credentials"
    let config = home + "/.aws/config"
    let credentialBytes = Data(("# keep credentials comment\n[default]\n"
        + "aws_access_key_id = SYNTHETIC_ACCESS\naws_secret_access_key = aws-migrate-synthetic-secret\n"
        + "region = eu-west-1\n[role]\nrole_arn = arn:synthetic\nsource_profile = default\n").utf8)
    let configBytes = Data("# keep config comment\n[default]\nregion = eu-west-1\n".utf8)
    try credentialBytes.write(to: URL(fileURLWithPath: credentials))
    try configBytes.write(to: URL(fileURLWithPath: config))
    let environment = ["HOME": home, "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "TMPDIR": root + "/"]
    func run(_ arguments: [String], extra: [String: String] = [:]) -> (status: Int32, out: String, err: String) {
        runCsecPipedAt(cwd: project, arguments, input: Data(), extraEnv: extra, baseEnvironment: environment)
    }
    let store = "aws-explicit-e2e"
    let dry = run(["protect", "--store", store, "--dry-run", credentials])
    check(dry.status == 0 && dry.out.contains("creds-aws") && dry.out.contains("1 static profile(s)"),
          "protect from an unrelated cwd recognizes the standard AWS file (\(dry.err))")
    check(try (Data(contentsOf: URL(fileURLWithPath: credentials))) == credentialBytes
          && (Data(contentsOf: URL(fileURLWithPath: config))) == configBytes,
          "AWS dry-run leaves both inputs unchanged")
    check(!dry.out.contains("aws-migrate-synthetic-secret") && !dry.err.contains("aws-migrate-synthetic-secret"),
          "AWS dry-run output is value-free")
    let applied = run(["protect", "--store", store, credentials])
    check(applied.status == 0 && applied.out.contains("credential_process configured"),
          "single-file protect completes AWS configuration (\(applied.err))")
    let migrated = try Data(contentsOf: URL(fileURLWithPath: credentials))
    let configured = try Data(contentsOf: URL(fileURLWithPath: config))
    guard let resolvedSource = realpath(credentials, nil) else { throw NSError(domain: "AWSFixture", code: 1) }
    let sourcePath = String(cString: resolvedSource)
    free(resolvedSource)
    let key = AWSCredentialMigration.bundleKey(sourcePath: sourcePath, profile: "default")
    let ref = try NativeSecretReference(store: NativeStoreName(store), key: key).uri
    let command = try AWSCredentialMigration.command(executable: csecURL.resolvingSymlinksInPath().path, reference: ref)
    check(String(decoding: configured, as: UTF8.self).contains("credential_process = " + command)
          && !String(decoding: migrated, as: UTF8.self).contains("aws_secret_access_key")
          && String(decoding: migrated, as: UTF8.self).contains("role_arn = arn:synthetic"),
          "AWS config names the imported reference and cleanup preserves the derived profile")
    let imported = try client.access(references: [ref], reason: "synthetic AWS migration", ttlSeconds: 60)
    let bundle = try AWSCredentialProcess.fields(fromBundle: String(decoding: imported[ref]!, as: UTF8.self))
    check(bundle["SecretAccessKey"] == "aws-migrate-synthetic-secret",
          "the configured AWS reference resolves to the durably imported synthetic profile")
    let repeated = run(["protect", "--store", store, credentials])
    check(try repeated.status == 0 && (Data(contentsOf: URL(fileURLWithPath: config))) == configured
          && (Data(contentsOf: URL(fileURLWithPath: credentials))) == migrated,
          "a completed AWS migration is idempotent")

    // Repeat via setup, with an interrupted/configured-but-not-cleaned state.
    try credentialBytes.write(to: URL(fileURLWithPath: credentials))
    let bulk = run(["setup", "--protect-files", "--scan-root", home,
                    "--glob", "**=skip", "--glob", "~/.aws/credentials=creds-aws:csec://" + store, "--apply"])
    check(try bulk.status == 0 && (Data(contentsOf: URL(fileURLWithPath: credentials))) == migrated,
          "bulk setup shares AWS migration and resumes after config installation (\(bulk.err))")

    try credentialBytes.write(to: URL(fileURLWithPath: credentials))
    let kept = run(["protect", "--store", store, "--keep-plaintext", credentials])
    check(try kept.status == 0 && (Data(contentsOf: URL(fileURLWithPath: credentials))) == credentialBytes,
          "AWS keep-plaintext retains original credentials")
    let conflict = Data("[default]\ncredential_process = /different/helper\n".utf8)
    try conflict.write(to: URL(fileURLWithPath: config))
    let refused = run(["protect", "--store", store, credentials])
    check(try refused.status != 0 && (Data(contentsOf: URL(fileURLWithPath: config))) == conflict
          && (Data(contentsOf: URL(fileURLWithPath: credentials))) == credentialBytes,
          "conflicting credential process preserves both files")

    // Leaf links and hardlinks cannot turn a selected path into another write.
    try fm.removeItem(atPath: config)
    try fm.createSymbolicLink(atPath: config, withDestinationPath: credentials)
    let symlink = run(["protect", "--store", store, credentials])
    check(try symlink.status != 0 && (Data(contentsOf: URL(fileURLWithPath: credentials))) == credentialBytes,
          "AWS migration refuses a symlinked config before import or cleanup")
    try fm.removeItem(atPath: config)
    try fm.linkItem(atPath: credentials, toPath: home + "/credentials-alias")
    let hardlink = run(["protect", "--store", store, credentials])
    check(hardlink.status != 0 && hardlink.err.contains("hardlinks"),
          "explicit protection refuses aliases it cannot safely clean up")
    try fm.removeItem(atPath: home + "/credentials-alias")
    let newConfig = run(["protect", "--store", store, credentials])
    check(newConfig.status == 0 && fm.fileExists(atPath: config),
          "AWS migration creates an absent config before cleanup")

    let customCredentials = root + "/custom-aws-credentials"
    let customConfig = root + "/custom-aws-config"
    try credentialBytes.write(to: URL(fileURLWithPath: customCredentials))
    let custom = run(["protect", "--aws", "--aws-config", customConfig,
                      "--store", "aws-custom-e2e", customCredentials])
    check(custom.status == 0 && fm.fileExists(atPath: customConfig),
          "--aws and --aws-config migrate custom filenames outside home")
    let overrideCredentials = root + "/override-aws-credentials"
    let overrideConfig = root + "/override-aws-config"
    try credentialBytes.write(to: URL(fileURLWithPath: overrideCredentials))
    let overrideResult = run(["protect", "--store", "aws-override-e2e", overrideCredentials],
        extra: ["AWS_SHARED_CREDENTIALS_FILE": overrideCredentials, "AWS_CONFIG_FILE": overrideConfig])
    check(overrideResult.status == 0 && fm.fileExists(atPath: overrideConfig),
          "AWS environment overrides select both the handler and config destination")

    let opaque = root + "/outside-home.secret"
    let opaqueData = Data("opaque-synthetic-file".utf8)
    try opaqueData.write(to: URL(fileURLWithPath: opaque))
    let whole = run(["protect", "--store", "explicit-opaque-e2e", opaque])
    check(whole.status == 0 && !fm.fileExists(atPath: opaque) && fm.fileExists(atPath: opaque + ".csec"),
          "an arbitrary file outside home and cwd is protected (\(whole.err))")
    let env = root + "/.env"
    try Data("EXPLICIT_SECRET_TOKEN=synthetic-env-token\n".utf8).write(to: URL(fileURLWithPath: env))
    let envDry = run(["protect", "--env", "--store", "explicit-env-e2e", "--dry-run", env])
    check(envDry.status == 0 && envDry.out.contains("EXPLICIT_SECRET_TOKEN"),
          "explicit --env accepts an outside-cwd path")
    let autoEnv = run(["protect", "--store", "explicit-env-e2e", env])
    check(try autoEnv.status == 0 && String(decoding: Data(contentsOf: URL(fileURLWithPath: env)), as: UTF8.self).contains("csec_EXPLICIT_SECRET_TOKEN=\"csec://"),
          "automatic env protection rewrites per-variable outside cwd (\(autoEnv.err))")

    let legacy = Data("export TOKEN='op://synthetic/item/token' # keep\r\n".utf8)
    let prefixed = Data("export csec_TOKEN='op://synthetic/item/token' # keep\r\n".utf8)
    try legacy.write(to: URL(fileURLWithPath: env))
    let rename = run(["protect", "--store", "explicit-env-e2e", env],
                     extra: ["CSEC_SOCKET": root + "/absent-agent.sock"])
    check(try rename.status == 0 && Data(contentsOf: URL(fileURLWithPath: env)) == prefixed,
          "reference-only protect renames without an agent or provider CLI (\(rename.err))")
    let again = run(["protect", "--store", "explicit-env-e2e", env])
    check(try again.status == 0 && Data(contentsOf: URL(fileURLWithPath: env)) == prefixed,
          "reference-only protection is idempotent")

    let collision = Data("TOKEN=synthetic\ncsec_TOKEN=op://synthetic/item/token\n".utf8)
    try collision.write(to: URL(fileURLWithPath: env))
    let refusedEnv = run(["protect", "--store", "explicit-env-e2e", env])
    check(try refusedEnv.status != 0 && refusedEnv.err.contains("both TOKEN and csec_TOKEN")
          && Data(contentsOf: URL(fileURLWithPath: env)) == collision,
          "env protection refuses name collisions without changing the file")
} catch { check(false, "explicit path/AWS migration end-to-end succeeds (\(error))") }

await importDirectoryTests()
await bulkProtectionHardlinkTests()
await npmSplitTests()
shellStartupProtectionE2ETests()

// Bulk protection end to end (`csec setup --protect-files`): a synthetic home
// tree drives the non-interactive glob apply against the fake agent. Per-var
// files rewrite in place, a command-substituted env file falls back to
// whole-file, key material becomes a blob with a sidecar at each hardlink
// while symlinks stay pointed at their destination. Cross-file key collisions
// inside one store resolve to distinct keys, and no secret value ever crosses
// stdout or stderr.
do {
    let bulkFixtureRoot = NSTemporaryDirectory()
        + "csec-bulk-e2e-\(UUID().uuidString.lowercased())"
    let bulkHome = bulkFixtureRoot + "/home"
    let fm = FileManager.default
    defer { try? fm.removeItem(atPath: bulkFixtureRoot) }
    func writeBulk(_ relative: String, _ content: String) throws {
        let path = bulkHome + "/" + relative
        try fm.createDirectory(
            atPath: (path as NSString).deletingLastPathComponent,
            withIntermediateDirectories: true)
        try Data(content.utf8).write(to: URL(fileURLWithPath: path))
    }
    try writeBulk("proj/.envrc",
                  "export E2E_BULK_TOKEN=bulk-envrc-secret-value\n"
                      + "export SHARED_KEY=bulk-shared-first-9999\nuse_flake\n")
    try writeBulk("proj/.env", "BULK_SUB_TOKEN=\"$(op read op://v/i/f)\"\n")
    try writeBulk("real2/.env", "SHARED_KEY=bulk-shared-second-8888\n")
    let keyBody = "-----BEGIN OPENSSH PRIVATE KEY-----\nYnVsay1rZXk=\n"
        + "-----END OPENSSH PRIVATE KEY-----\n"
    try writeBulk("keys/server.key", keyBody)
    try fm.createDirectory(atPath: bulkHome + "/alias2", withIntermediateDirectories: true)
    try fm.createSymbolicLink(
        atPath: bulkHome + "/alias2/backup.key",
        withDestinationPath: bulkHome + "/keys/server.key")

    try fm.linkItem(atPath: bulkHome + "/keys/server.key",
                    toPath: bulkHome + "/alias2/hardlink.key")

    let bulkStore = "bulk-e2e"

    // HOME alone is insufficient: inherited CODEX_HOME, ZDOTDIR and catalog
    // overrides can point outside the fixture. Every bulk invocation starts
    // from this explicit environment; the helper adds only the fake socket.
    let bulkEnvironment = [
        "HOME": bulkHome,
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "TMPDIR": bulkFixtureRoot + "/",
    ]
    func runBulk(
        _ arguments: [String], extraEnv: [String: String] = [:]
    ) -> (status: Int32, out: String, err: String) {
        runCsecPipedAt(
            cwd: bulkHome,
            ["setup", "--protect-files", "--scan-root", bulkHome] + arguments,
            input: Data(), extraEnv: extraEnv, baseEnvironment: bulkEnvironment)
    }

    // Isolation interlock: require a successful dry run naming exactly the
    // fixture's files AND aliases. A matching count alone cannot prove that
    // all files are synthetic (an unexpected file could replace a missing one).
    func matchesBulkFixture(_ result: (status: Int32, out: String, err: String)) -> Bool {
        let lines = result.out.split(separator: "\n").map(String.init)
        let rows = lines.filter { $0.hasPrefix("| ") }.map {
            $0.split(separator: "|", omittingEmptySubsequences: false)
                .dropFirst().dropLast().map { $0.trimmingCharacters(in: .whitespaces) }
        }
        let paths = rows.filter { $0.count >= 3 && $0[0].hasPrefix("~/") && $0[1] != "Hardlink" }
            .map { $0[0] }
        let aliases = rows.filter { $0.count >= 3 && $0[1] == "Hardlink" }.map { $0[0] }
        let expectedPaths: Set<String> = [
            "~/keys/server.key", "~/proj/.env", "~/proj/.envrc", "~/real2/.env",
        ]
        return result.status == 0
            && lines.first == "plan: 4 unique file(s) to protect"
            && paths.count == expectedPaths.count && Set(paths) == expectedPaths
            && aliases == ["~/alias2/hardlink.key"]
            && rows.filter { $0.count >= 3 && !$0[1].isEmpty && $0[1] != "TYPE" }.count == 5
            && !rows.contains { $0.count >= 3 && $0[2] == "skip" }
    }

    // Reproduce the original fifth candidate using only a synthetic outside
    // credential file. This deliberately contaminated plan is never applied.
    let outsideCodex = bulkFixtureRoot + "/outside-codex"
    try fm.createDirectory(atPath: outsideCodex, withIntermediateDirectories: true)
    try Data("{\"synthetic\":\"bulk-fixture-only\"}\n".utf8)
        .write(to: URL(fileURLWithPath: outsideCodex + "/auth.json"))
    let contaminated = runBulk(["--dry-run"], extraEnv: ["CODEX_HOME": outsideCodex])
    check(contaminated.status == 0
          && contaminated.out.contains("plan: 5 unique file(s) to protect")
          && contaminated.out.contains("/outside-codex/auth.json")
          && !matchesBulkFixture(contaminated),
          "the bulk interlock rejects a synthetic credential-location override outside home")

    let bulkDryRun = runBulk(["--dry-run"])
    check(matchesBulkFixture(bulkDryRun),
          "the isolated dry run plans exactly the synthetic files and alias "
              + "(err: \(bulkDryRun.err.suffix(300)))")
    check(!matchesBulkFixture((1, bulkDryRun.out, "synthetic failure")),
          "the bulk interlock rejects a failed dry run even with the expected plan")
    check(!matchesBulkFixture((0, bulkDryRun.out.replacingOccurrences(
        of: "~/real2/.env", with: outsideCodex + "/auth.json"), "")),
          "the bulk interlock rejects an outside path even when the file count matches")
    check(!matchesBulkFixture((0, bulkDryRun.out.replacingOccurrences(
        of: "~/alias2/hardlink.key", with: outsideCodex + "/backup.key"), "")),
          "the bulk interlock rejects an outside alias even when the file count matches")
    guard matchesBulkFixture(bulkDryRun) else {
        check(false, "REFUSING bulk --apply: the plan does not match the isolated fixture")
        throw SetupOnboardingError.unsafeRegularFile("bulk-e2e isolation interlock")
    }

    let applied = runBulk(["--glob", "**=csec://\(bulkStore)", "--apply"])
    check(applied.status == 0,
          "bulk apply exits cleanly (out: \(applied.out.suffix(300)), "
              + "err: \(applied.err.suffix(300)))")
    check(!applied.out.contains("bulk-envrc-secret-value")
          && !applied.out.contains("bulk-shared-")
          && !applied.err.contains("bulk-envrc-secret-value")
          && !applied.err.contains("bulk-shared-"),
          "no secret value crosses the bulk apply's stdout or stderr")

    let rewrittenEnvrc = String(
        decoding: (try? Data(contentsOf: URL(fileURLWithPath: bulkHome + "/proj/.envrc")))
            ?? Data(),
        as: UTF8.self)
    check(rewrittenEnvrc.contains("csec_E2E_BULK_TOKEN=\"csec://\(bulkStore)/E2E_BULK_TOKEN")
          && rewrittenEnvrc.contains("use_flake")
          && !rewrittenEnvrc.contains("bulk-envrc-secret-value"),
          "the per-var .envrc is rewritten in place with references")

    check(!fm.fileExists(atPath: bulkHome + "/proj/.env")
          && fm.fileExists(atPath: bulkHome + "/proj/.env.csec"),
          "a command-substituted env file falls back to whole-file (blob + sidecar)")
    check(!fm.fileExists(atPath: bulkHome + "/keys/server.key")
          && fm.fileExists(atPath: bulkHome + "/keys/server.key.csec"),
          "key material becomes a blob with a sidecar in the plaintext's place")
    check(!fm.fileExists(atPath: bulkHome + "/alias2/backup.key.csec"),
          "the symlink gets no redundant sidecar")
    check((try? fm.destinationOfSymbolicLink(atPath: bulkHome + "/alias2/backup.key"))
              == bulkHome + "/keys/server.key",
          "the symlink remains pointed at its protected destination")
    check(fm.fileExists(atPath: bulkHome + "/alias2/hardlink.key.csec")
          && !fm.fileExists(atPath: bulkHome + "/alias2/hardlink.key"),
          "the additional hardlink gets a sidecar and loses its plaintext")

    // Cross-file collision: both files exported SHARED_KEY with different
    // values, so they must reference two distinct keys that resolve to their
    // own values.
    let rewrittenReal2 = String(
        decoding: (try? Data(contentsOf: URL(fileURLWithPath: bulkHome + "/real2/.env")))
            ?? Data(),
        as: UTF8.self)
    let envrcSharedRef = rewrittenEnvrc.split(separator: "\n")
        .first { $0.contains("SHARED_KEY") }?
        .split(separator: "\"").dropFirst().first.map(String.init) ?? ""
    let real2SharedRef = rewrittenReal2.split(separator: "\n")
        .first { $0.contains("SHARED_KEY") }?
        .split(separator: "\"").dropFirst().first.map(String.init) ?? ""
    check(envrcSharedRef.hasPrefix("csec://\(bulkStore)/")
          && real2SharedRef.hasPrefix("csec://\(bulkStore)/")
          && envrcSharedRef != real2SharedRef,
          "colliding keys across files resolve to distinct store keys "
              + "(\(envrcSharedRef) vs \(real2SharedRef))")
    let bulkResolved = try client.access(
        references: [
            "csec://\(bulkStore)/E2E_BULK_TOKEN", envrcSharedRef, real2SharedRef,
        ],
        reason: "bulk protect e2e resolve",
        ttlSeconds: 3600)
    check(bulkResolved["csec://\(bulkStore)/E2E_BULK_TOKEN"]
              == Data("bulk-envrc-secret-value".utf8)
          && bulkResolved[envrcSharedRef] == Data("bulk-shared-first-9999".utf8)
          && bulkResolved[real2SharedRef] == Data("bulk-shared-second-8888".utf8),
          "bulk-imported env values resolve back with full fidelity")

    // The whole-file blobs resolve byte-for-byte through their sidecars.
    let envSidecar = try ProtectedFileSidecar(
        data: Data(contentsOf: URL(fileURLWithPath: bulkHome + "/proj/.env.csec")))
    let keySidecar = try ProtectedFileSidecar(
        data: Data(contentsOf: URL(fileURLWithPath: bulkHome + "/keys/server.key.csec")))
    let aliasSidecar = try ProtectedFileSidecar(
        data: Data(contentsOf: URL(fileURLWithPath: bulkHome + "/alias2/hardlink.key.csec")))
    check(aliasSidecar.reference == keySidecar.reference,
          "the hardlink sidecar points at the same reference as the canonical one")
    let blobResolved = try client.access(
        references: [envSidecar.reference.uri, keySidecar.reference.uri],
        reason: "bulk blob e2e resolve",
        ttlSeconds: 3600)
    check(blobResolved[envSidecar.reference.uri]
              == Data("BULK_SUB_TOKEN=\"$(op read op://v/i/f)\"\n".utf8)
          && blobResolved[keySidecar.reference.uri] == Data(keyBody.utf8),
          "bulk whole-file blobs resolve byte-for-byte")
    check(fm.fileExists(atPath: outsideCodex + "/auth.json")
          && !fm.fileExists(atPath: outsideCodex + "/auth.json.csec"),
          "bulk apply leaves the synthetic outside credential file unprotected")

    // Dry run over the same (already protected) tree changes nothing and
    // reports the references as already handled.
    let dryRunAfter = runBulk(["--dry-run"])
    check(dryRunAfter.status == 0,
          "a post-apply dry run exits cleanly (err: \(dryRunAfter.err.suffix(200)))")
} catch {
    check(false, "bulk protect end-to-end succeeds (\(error))")
}

// Full sidecar materialization: protect a file, then `csec exec` in the same
// project must surface it at its original path so the wrapped child reads the
// protected bytes — and must tear the link down afterwards.
do {
    let projectDir = NSTemporaryDirectory()
        + "csec-exec-sidecar-e2e-\(UUID().uuidString.lowercased())"
    try FileManager.default.createDirectory(atPath: projectDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: projectDir) }
    let envrcPath = projectDir + "/.envrc"
    let secret = "export SECRET_TOKEN=exec-sidecar-synthetic\nuse_flake\n"
    try Data(secret.utf8).write(to: URL(fileURLWithPath: envrcPath))

    func runInProject(
        _ arguments: [String],
        extraEnv: [String: String] = [:]
    ) -> (status: Int32, out: String, err: String) {
        let process = Process()
        process.executableURL = csecURL
        process.arguments = arguments
        process.currentDirectoryURL = URL(fileURLWithPath: projectDir)
        var environment = ProcessInfo.processInfo.environment
        environment["CSEC_SOCKET"] = socketPath
        for (key, value) in extraEnv { environment[key] = value }
        process.environment = environment
        let outPipe = Pipe(), errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe
        do { try process.run() } catch { return (-1, "", "spawn failed: \(error)") }
        let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
        let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus,
                String(data: outData, encoding: .utf8) ?? "",
                String(data: errData, encoding: .utf8) ?? "")
    }

    let existingAlias = projectDir + "/linked-envrc"
    try FileManager.default.createSymbolicLink(atPath: existingAlias, withDestinationPath: ".envrc")

    let protectResult = runInProject(["protect", "--whole-file", ".envrc"])
    check(protectResult.status == 0
          && !FileManager.default.fileExists(atPath: envrcPath)
          && FileManager.default.fileExists(atPath: envrcPath + ".csec"),
          "sidecar exec setup: protect replaces .envrc with a sidecar (err: \(protectResult.err))")

    let execResult = runInProject([
        "exec", "--", "/bin/sh", "-c",
        "test \"$(cat .envrc)\" = 'export SECRET_TOKEN=exec-sidecar-synthetic\nuse_flake' "
            + "&& cmp .envrc linked-envrc && printf sidecar-ok",
    ])
    check(execResult.status == 0 && execResult.out == "sidecar-ok",
          "csec exec materializes a *.csec destination reachable through an existing symlink "
            + "(status \(execResult.status), out \"\(execResult.out)\", err \"\(execResult.err)\")")
    check(!execResult.err.contains(environmentInjectionWarning),
          "a sidecar-only launch does not warn about environment injection")
    check((try? FileManager.default.destinationOfSymbolicLink(atPath: envrcPath)) == nil,
          "csec exec tears down the materialized symlink after the child exits")

    check((try? FileManager.default.destinationOfSymbolicLink(atPath: existingAlias)) == ".envrc",
          "materializing and tearing down the destination preserves the user's symlink")

    // The default guard covers pipes: a materialized file printed straight to a
    // captured stdout must come back as a label, never plaintext.
    let pipedDefault = runInProject(["exec", "/bin/cat", ".envrc"])
    check(pipedDefault.status == 0
          && pipedDefault.out.contains("[redacted: csec://")
          && !pipedDefault.out.contains("exec-sidecar-synthetic")
          && !pipedDefault.err.contains("exec-sidecar-synthetic"),
          "the default output guard redacts a materialized file printed to a pipe, "
            + "naming its csec:// reference in-band "
            + "(status \(pipedDefault.status), out \"\(pipedDefault.out)\", "
            + "err \"\(pipedDefault.err)\")")

    // Combined path: with a sidecar present, `csec exec` must ALSO fold in ordinary
    // environment injection — both an explicit `--set` and an env-scanned reference
    // exported into the launcher's shell — resolving each into the child's
    // environment through the same one-approval root launch. The value is placed by
    // rootd, never by the launcher. (The comparison happens inside the child, so
    // the default output guard has nothing to redact.)
    let combined = runInProject(
        ["exec", "--set", "INJECTED_URL=op://demo/db/url", "--",
         "/bin/sh", "-c",
         "test \"$INJECTED_URL\" = 'postgres://s3cr3t' "
            + "&& test \"$SCANNED_TOKEN\" = 'native-synthetic-token' && test -z \"${csec_SCANNED_TOKEN+x}\" && printf combined-ok"],
        extraEnv: ["csec_SCANNED_TOKEN": "csec://development/NATIVE_TOKEN"]
    )
    check(combined.status == 0
          && combined.out == "combined-ok",
          "csec exec folds --set and env-scanned references into the sidecar launch "
            + "as value-in-environment (status \(combined.status), out \"\(combined.out)\", "
            + "err \"\(combined.err)\")")
    checkEnvironmentInjectionWarning(combined.err, command: "exec", label: "combined sidecar/environment exec")
    check((try? FileManager.default.destinationOfSymbolicLink(atPath: envrcPath)) == nil,
          "the combined launch still tears the sidecar symlink down afterwards")

    // Stale-link reclamation (F3) through the real launcher: simulate a hard-killed
    // prior run by planting a dangling protected link where .envrc must reappear,
    // pointing at a vanished session inside the real mount. The next exec must
    // reclaim it and still surface the file, not fail with EEXIST.
    let mountRoot = (rootFixtureDirectory as NSString).appendingPathComponent("files")
    let deadTarget = (mountRoot as NSString)
        .appendingPathComponent("00000000-0000-0000-0000-000000000000/files/protected-0")
    try? FileManager.default.removeItem(atPath: envrcPath)
    try FileManager.default.createSymbolicLink(atPath: envrcPath, withDestinationPath: deadTarget)
    check(!FileManager.default.fileExists(atPath: envrcPath),
          "stale-link fixture: the planted link dangles into a vanished session")
    let reclaimed = runInProject([
        "exec", "--", "/bin/sh", "-c",
        "test \"$(cat .envrc)\" = 'export SECRET_TOKEN=exec-sidecar-synthetic\nuse_flake' "
            + "&& printf reclaimed-ok",
    ])
    check(reclaimed.status == 0 && reclaimed.out == "reclaimed-ok",
          "csec exec reclaims a dangling protected link from a hard-killed run and still "
            + "materializes the file (status \(reclaimed.status), out \"\(reclaimed.out)\", "
            + "err \"\(reclaimed.err)\")")
    check((try? FileManager.default.destinationOfSymbolicLink(atPath: envrcPath)) == nil,
          "the reclaimed launch tears its own materialized link down afterwards")

    // Source-neutral: a hand-written BARE sidecar naming an op:// reference (no JSON
    // envelope, no csec:// requirement) materializes end-to-end through the real
    // launch. The value is compared inside the child so the default guard has
    // nothing to redact.
    try Data("op://demo/db/url\n".utf8).write(
        to: URL(fileURLWithPath: projectDir + "/db.url.csec"))
    let bareOp = runInProject([
        "exec", "--", "/bin/sh", "-c",
        "test \"$(cat db.url)\" = 'postgres://s3cr3t' && printf bare-op-ok",
    ])
    check(bareOp.status == 0 && bareOp.out == "bare-op-ok",
          "a bare op:// sidecar materializes source-neutrally through the real launch "
            + "(status \(bareOp.status), out \"\(bareOp.out)\", err \"\(bareOp.err)\")")

    // A *.csec file that cannot be parsed WARNS on stderr instead of being silently
    // skipped — otherwise a broken sidecar is indistinguishable from the secret
    // simply not being there.
    try Data("this is not a reference\n".utf8).write(
        to: URL(fileURLWithPath: projectDir + "/broken.env.csec"))
    let warned = runInProject(["exec", "--", "/bin/sh", "-c", "printf ran"])
    check(warned.status == 0
          && warned.out == "ran"
          && warned.err.contains("broken.env.csec")
          && warned.err.contains("warning"),
          "csec exec warns about an unparseable *.csec instead of silently skipping "
            + "(err \"\(warned.err)\")")

    // A sidecar naming a reference no provider can resolve fails closed — and the
    // error names both the failing reference and each requested reference's
    // source, because "one or more references" gives the user nothing to fix.
    let ghostPath = projectDir + "/ghost.env.csec"
    try Data("op://demo/missing/value\n".utf8).write(to: URL(fileURLWithPath: ghostPath))
    let unresolvable = runInProject(["exec", "--", "/bin/sh", "-c", "printf unreachable"])
    try? FileManager.default.removeItem(atPath: ghostPath)
    check(unresolvable.status == 1
          && unresolvable.out.isEmpty
          && unresolvable.err.contains("op://demo/missing/value")
          && unresolvable.err.contains("ghost.env.csec"),
          "an unresolvable sidecar reference is named together with its source file "
            + "(status \(unresolvable.status), err \"\(unresolvable.err)\")")
} catch {
    check(false, "csec exec sidecar materialization end-to-end succeeds (\(error))")
}

// Home token files: a file protected under home is restored for the command
// that reads it when `csec exec` runs from a project, and only for that command
// (or one named with --with-file). The synthetic home is HOME for every run.
do {
    let fm = FileManager.default
    let base = NSTemporaryDirectory() + "csec-exec-home-e2e-\(UUID().uuidString.lowercased())"
    try fm.createDirectory(atPath: base, withIntermediateDirectories: true)
    defer { try? fm.removeItem(atPath: base) }
    let home = (base as NSString).resolvingSymlinksInPath + "/home"
    let project = home + "/projects/app"
    let bin = base + "/bin"
    for directory in [project, bin] {
        try fm.createDirectory(atPath: directory, withIntermediateDirectories: true)
    }
    let tokenPath = home + "/.vault-token"
    try Data("synthetic-vault-token\n".utf8).write(to: URL(fileURLWithPath: tokenPath))
    // A stand-in `vault` that checks its token inside the child, so the
    // output guard has nothing to redact.
    let vault = bin + "/vault"
    try Data("#!/bin/sh\ntest \"$(cat \"$HOME/.vault-token\")\" = synthetic-vault-token && printf home-ok\n".utf8)
        .write(to: URL(fileURLWithPath: vault))
    try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: vault)
    let env = ["HOME": home]

    let protected = runCsecPipedAt(cwd: home, ["protect", "--whole-file", "--store", "e2ehome\(UUID().uuidString.prefix(8).lowercased())", tokenPath],
                                   input: Data(), extraEnv: env)
    check(protected.status == 0 && !fm.fileExists(atPath: tokenPath)
          && fm.fileExists(atPath: tokenPath + ".csec"),
          "home exec setup: protect replaces ~/.vault-token with a sidecar (err: \(protected.err))")

    guard fm.fileExists(atPath: tokenPath + ".csec") else { throw CocoaError(.fileNoSuchFile) }
    let fromProject = runCsecPipedAt(cwd: project, ["exec", "--", vault], input: Data(), extraEnv: env)
    check(fromProject.status == 0 && fromProject.out == "home-ok",
          "csec exec -- vault from a project restores the protected ~/.vault-token "
            + "(status \(fromProject.status), out \"\(fromProject.out)\", err \"\(fromProject.err)\")")
    check((try? fm.destinationOfSymbolicLink(atPath: tokenPath)) == nil
          && fm.fileExists(atPath: tokenPath + ".csec"),
          "the home link is torn down after the child exits and the sidecar stays")

    let fromHome = runCsecPipedAt(cwd: home, ["exec", "--", vault], input: Data(), extraEnv: env)
    check(fromHome.status == 0 && fromHome.out == "home-ok",
          "run from home itself, the same file is restored once, home-rooted "
            + "(status \(fromHome.status), err \"\(fromHome.err)\")")

    let readsToken = "test \"$(cat \"$HOME/.vault-token\")\" = synthetic-vault-token && printf named-ok"
    let named = runCsecPipedAt(cwd: project, ["exec", "--with-file", "~/.vault-token", "--",
                                              "/bin/sh", "-c", readsToken], input: Data(), extraEnv: env)
    check(named.status == 0 && named.out == "named-ok",
          "--with-file restores a named home file for a wrapper "
            + "(status \(named.status), err \"\(named.err)\")")
    let unnamed = runCsecPipedAt(cwd: project, ["exec", "--", "/bin/sh", "-c",
                                                "test -e \"$HOME/.vault-token\" || printf absent"],
                                 input: Data(), extraEnv: env)
    check(unnamed.status == 0 && unnamed.out == "absent",
          "a command that does not read the file gets no home token")
    let missing = runCsecPipedAt(cwd: project, ["exec", "--with-file", "~/.netrc", "--", "/usr/bin/true"],
                                 input: Data(), extraEnv: env)
    check(missing.status == 1 && missing.err.contains("no protected copy"),
          "--with-file of an unprotected file fails before any launch (err \"\(missing.err)\")")

    // A tool that saved plaintext beside the sidecar blocks the next restore
    // and is named from home, so the user knows which file to check.
    try Data("plaintext".utf8).write(to: URL(fileURLWithPath: tokenPath))
    let occupied = runCsecPipedAt(cwd: project, ["exec", "--", vault], input: Data(), extraEnv: env)
    check(occupied.status == 1 && occupied.err.contains("~/.vault-token")
          && (try? Data(contentsOf: URL(fileURLWithPath: tokenPath))) == Data("plaintext".utf8),
          "plaintext at a home path blocks its restore, is named and left alone "
            + "(err \"\(occupied.err)\")")
} catch {
    check(false, "csec exec home token restore end-to-end succeeds (\(error))")
}

/// `baseEnvironment` replaces the harness's own environment, for a launch that
/// must see exactly what a real caller passes (the sudo PAM module's redactor).
func runCsecWithInput(
    _ arguments: [String],
    input: Data,
    extraEnv: [String: String] = [:],
    baseEnvironment: [String: String]? = nil
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = csecURL
    process.arguments = arguments
    var environment = baseEnvironment ?? ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    for (key, value) in extraEnv { environment[key] = value }
    process.environment = environment
    let inputPipe = Pipe(), outPipe = Pipe(), errPipe = Pipe()
    process.standardInput = inputPipe
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed: \(error)")
    }
    inputPipe.fileHandleForReading.closeFile()
    inputPipe.fileHandleForWriting.write(input)
    inputPipe.fileHandleForWriting.closeFile()
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func externalEditorWorkspaceNames() -> Set<String> {
    let entries = (try? FileManager.default.contentsOfDirectory(
        atPath: AgentSocket.directory()
    )) ?? []
    return Set(entries.filter { $0.hasPrefix(".csec-edit-") })
}

func runProgram(
    executable: String,
    arguments: [String]
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed")
    }
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func runCsecInPTY(
    _ arguments: [String],
    extraEnv: [String: String]
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/script")
    process.arguments = [
        "-q", "/dev/null", "/bin/sh", "-c",
        "stty rows 37 cols 113; exec \"$@\"", "csec-pty", csecURL.path,
    ] + arguments
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    for (key, value) in extraEnv { environment[key] = value }
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed: \(error)")
    }
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

/// `csec` in a pseudo-terminal whose input closes at once (script(1) relays
/// one ^D, and later reads block), stopped after `timeout` seconds so a
/// question that waits on input fails its check instead of hanging the suite.
func runCsecInPTYWithClosedInput(
    _ arguments: [String], extraEnv: [String: String], timeout: TimeInterval
) -> (status: Int32, out: String, timedOut: Bool) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/script")
    process.arguments = [
        "-q", "/dev/null", "/bin/sh", "-c",
        "stty rows 37 cols 113; exec \"$@\"", "csec-pty", csecURL.path,
    ] + arguments
    var environment = ProcessInfo.processInfo.environment
    for (key, value) in extraEnv { environment[key] = value }
    process.environment = environment
    let inputPipe = Pipe(), outPipe = Pipe()
    process.standardInput = inputPipe
    process.standardOutput = outPipe
    process.standardError = outPipe
    do {
        try process.run()
    } catch {
        return (-1, "spawn failed: \(error)", false)
    }
    inputPipe.fileHandleForWriting.closeFile()
    let output = OutputCollector()
    let reader = Thread { output.set(outPipe.fileHandleForReading.readDataToEndOfFile()) }
    reader.start()
    let deadline = Date().addingTimeInterval(timeout)
    while process.isRunning && Date() < deadline { usleep(50_000) }
    let timedOut = process.isRunning
    if timedOut { process.terminate() }
    process.waitUntilExit()
    let collected = output.wait(seconds: 5)
    return (process.terminationStatus, String(data: collected, encoding: .utf8) ?? "", timedOut)
}

/// The bytes a reader thread collected, handed back once it has them.
final class OutputCollector: @unchecked Sendable {
    private let done = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var data = Data()

    func set(_ collected: Data) {
        lock.withLock { data = collected }
        done.signal()
    }

    func wait(seconds: TimeInterval) -> Data {
        _ = done.wait(timeout: .now() + seconds)
        return lock.withLock { data }
    }
}

/// Counts every Touch ID sheet and approves each one, so a sheet that should
/// never have been raised would also have changed csecd's record.
final class SetupEOFConsent: ConsentProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var sheets = 0

    var count: Int { lock.withLock { sheets } }

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        lock.withLock { sheets += 1 }
        return .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        lock.withLock { sheets += 1 }
        return .approved(unlock: nil)
    }
}

/// Run two sibling interactive `csec get` processes beneath one long-lived
/// shell. The trailing `:` prevents the shell from replacing itself with the
/// second csec, so both requests have the exact same direct parent incarnation.
func runRepeatedInteractiveGet(
    reference: String
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/script")
    process.arguments = [
        "-q", "/dev/null", "/bin/sh", "-c",
        "\"$1\" get --reveal --for 60 \"$2\"; \"$1\" get --reveal --for 60 \"$2\"; :",
        "csec-get-parent-e2e", csecURL.path, reference,
    ]
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed: \(error)")
    }
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func runShellGetCommand(
    _ command: String,
    arguments: [String],
    agentSocket: String = socketPath
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["-c", command, "csec-get-shell-e2e"] + arguments
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = agentSocket
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed: \(error)")
    }
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func runTerminalPipeAndFileGet(
    reference: String,
    filePath: String
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/script")
    process.arguments = [
        "-q", "/dev/null", "/bin/sh", "-c",
        "\"$1\" get --reveal --reason shape-isolation --for 60 \"$2\"; "
            + "\"$1\" get --reason shape-isolation --for 60 \"$2\" | /bin/cat; "
            + "\"$1\" get --allow-plaintext-file --reason shape-isolation --for 60 \"$2\" > \"$3\"; :",
        "csec-get-shapes-e2e", csecURL.path, reference, filePath,
    ]
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed: \(error)")
    }
    let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: outData, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func runCsecThroughStopAndContinue() -> (
    status: Int32,
    observedStop: Bool,
    out: String,
    err: String
) {
    let process = Process()
    process.executableURL = csecURL
    process.arguments = [
        "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
        "/bin/sh", "-c",
        "printf '%080d' 0; kill -STOP $$; printf %s \"$TESTVAR\"",
    ]
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, false, "", "spawn failed: \(error)")
    }

    let first = outPipe.fileHandleForReading.readData(ofLength: 1)
    var observedStop = false
    for _ in 0..<200 {
        if ProcessAncestry.isStopped(process.processIdentifier) {
            observedStop = true
            break
        }
        usleep(10_000)
    }
    _ = kill(process.processIdentifier, SIGCONT)
    if !observedStop {
        process.terminate()
        _ = kill(process.processIdentifier, SIGCONT)
    }

    let rest = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        observedStop,
        String(data: first + rest, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

func runCsecWithExternalTermination() -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = csecURL
    process.arguments = [
        "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
        "/bin/sh", "-c",
        "trap 'exit 42' TERM; printf '%080d' 0; while :; do :; done",
    ]
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = socketPath
    process.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    process.standardOutput = outPipe
    process.standardError = errPipe
    do {
        try process.run()
    } catch {
        return (-1, "", "spawn failed: \(error)")
    }

    // The guard withholds at most its longest-pattern tail. Reading one byte
    // proves the supervisor and child signal handlers are fully established.
    let first = outPipe.fileHandleForReading.readData(ofLength: 1)
    process.terminate()
    let rest = outPipe.fileHandleForReading.readDataToEndOfFile()
    let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    return (
        process.terminationStatus,
        String(data: first + rest, encoding: .utf8) ?? "",
        String(data: errData, encoding: .utf8) ?? ""
    )
}

if FileManager.default.isExecutableFile(atPath: csecURL.path) {
    let interactiveGetReference = "op://get-tests/credential/token"
    let interactiveGetValue = "interactive-get-synthetic-token"
    let consentBeforeInteractiveGets = await consent.calls()
    let repeatedInteractiveGets = runRepeatedInteractiveGet(
        reference: interactiveGetReference
    )
    let consentAfterInteractiveGets = await consent.calls()
    let repeatedValueCount = repeatedInteractiveGets.out
        .components(separatedBy: interactiveGetValue).count - 1
    let interactiveReview = await accessReviewCapture.latest()
    var directParentReviewIsBound = false
    if let interactiveReview,
       case .directParent = interactiveReview.plan.root,
       let requester = interactiveReview.plan.requestingExecutable {
        let requesterName = URL(fileURLWithPath: requester.canonicalPath).lastPathComponent
        directParentReviewIsBound = interactiveReview.plan.descendantScope == .subtree
            && interactiveReview.plan.destination == .humanOutput
            && URL(fileURLWithPath: interactiveReview.plan.executable.canonicalPath)
                .lastPathComponent == "csec"
            && requesterName != "csec"
            && interactiveReview.caller.description.contains("\(requesterName) [")
            && interactiveReview.caller.description.contains(" via ")
    }
    check(repeatedInteractiveGets.status == 0
          && repeatedValueCount == 2
          && consentAfterInteractiveGets == consentBeforeInteractiveGets + 1
          && directParentReviewIsBound,
          "interactive get identifies its direct parent and sibling gets reuse one grant")

    let pipeReference = "op://get-pipe/credential/token"
    let pipeValue = "pipe-delivery-synthetic-token"
    let reviewsBeforePipedGets = await accessReviewCapture.snapshot().count
    let consentBeforePipedGets = await consent.calls()
    let repeatedPipedGets = runShellGetCommand(
        "\"$1\" get --reveal --for 60 \"$2\" | /bin/cat; "
            + "\"$1\" get --reveal --for 60 \"$2\" | /bin/cat; :",
        arguments: [csecURL.path, pipeReference]
    )
    let consentAfterPipedGets = await consent.calls()
    let pipedReviews = Array(
        (await accessReviewCapture.snapshot()).dropFirst(reviewsBeforePipedGets)
    )
    let pipeReviewIsExplicit = pipedReviews.count == 1
        && pipedReviews[0].plan.destination == .shellDelegatedPipe
        && pipedReviews[0].plan.recipientAssurance == .unverifiedPipeReader
        && pipedReviews[0].plan.executable.assurance == .verifiedProduct
        && pipedReviews[0].plan.requestingExecutable != nil
        && pipedReviews[0].plan.descendantScope == .subtree
        && pipedReviews[0].caller.description.contains(" via ")
    check(repeatedPipedGets.status == 0
          && repeatedPipedGets.out.components(separatedBy: pipeValue).count - 1 == 2
          && consentAfterPipedGets == consentBeforePipedGets + 1
          && pipeReviewIsExplicit,
          "reviewed shell-delegated pipe receives values and sibling gets reuse one grant")

    let consentBeforeOtherShell = await consent.calls()
    let otherShellGet = runShellGetCommand(
        "\"$1\" get --reveal --for 60 \"$2\" | /bin/cat",
        arguments: [csecURL.path, pipeReference]
    )
    let consentAfterOtherShell = await consent.calls()
    check(otherShellGet.status == 0
          && otherShellGet.out.contains(pipeValue)
          && consentAfterOtherShell == consentBeforeOtherShell + 1,
          "a different shell process cannot reuse the first shell's pipe grant")

    let substitutionReference = "op://get-substitution/credential/token"
    let substitutionValue = "command-substitution-synthetic-token"
    let commandSubstitution = runShellGetCommand(
        "value=$(\"$1\" get --reveal --for 60 \"$2\") || exit $?; /usr/bin/printf '%s\\n' \"$value\"",
        arguments: [csecURL.path, substitutionReference]
    )
    check(commandSubstitution.status == 0
          && commandSubstitution.out == "\(substitutionValue)\n"
          && !commandSubstitution.err.contains(substitutionValue),
          "command substitution succeeds through revealed shell-delegated pipe delivery")

    let shapeReference = "op://get-shapes/credential/token"
    let shapeValue = "delivery-shape-synthetic-token"
    let shapeFile = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("csec-get-shape-\(UUID().uuidString)")
    defer { try? FileManager.default.removeItem(at: shapeFile) }
    let reviewsBeforeShapes = await accessReviewCapture.snapshot().count
    let consentBeforeShapes = await consent.calls()
    let shapeGet = runTerminalPipeAndFileGet(
        reference: shapeReference,
        filePath: shapeFile.path
    )
    let consentAfterShapes = await consent.calls()
    let shapeReviews = Array(
        (await accessReviewCapture.snapshot()).dropFirst(reviewsBeforeShapes)
    )
    let shapeDestinations = Set(shapeReviews.map(\.plan.destination))
    let persistedShapeValue = (try? String(contentsOf: shapeFile, encoding: .utf8)) ?? ""
    let persistentReview = shapeReviews.first {
        $0.plan.destination == .persistentPlaintextFile
    }
    let persistentWarning = persistentReview.flatMap(DeliveryReviewCopy.warning(for:)) ?? ""
    check(shapeGet.status == 0
          && shapeGet.out.components(separatedBy: shapeValue).count - 1 == 2
          && persistedShapeValue == "\(shapeValue)\n"
          && consentAfterShapes == consentBeforeShapes + 3
          && shapeDestinations == [.humanOutput, .shellDelegatedPipe, .persistentPlaintextFile]
          && persistentReview?.plan.mechanism == .namedPlaintextFile
          && persistentReview?.plan.recipientAssurance == .ordinaryPersistentFile
          && persistentReview?.plan.operationContext == "shape-isolation"
          && !persistentWarning.contains(shapeFile.lastPathComponent)
          && !persistentWarning.contains(shapeValue),
          "terminal, pipe, and persistent-file shapes require separate review without filename or value metadata")

    // Force the exact direct parent to change after review begins. The agent
    // revalidates before resolution and csec independently rechecks before
    // stdout, so neither an exec replacement nor reparenting releases bytes.
    let mutationReference = "op://parent-mutation/credential/token"
    let mutationValue = "parent-mutation-synthetic-token"
    let mutationResolution = ResolutionCounter()
    let mutationResolver = SecretResolver(cache: NullSecretCache())
    await mutationResolver.register(StaticProvider(
        values: [mutationReference: mutationValue],
        counter: mutationResolution
    ))
    let markerDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
        .appendingPathComponent("csec-parent-mutation-\(UUID().uuidString)", isDirectory: true)
    try! FileManager.default.createDirectory(at: markerDirectory, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: markerDirectory) }
    let replacementMarker = markerDirectory.appendingPathComponent("replace").path
    let exitMarker = markerDirectory.appendingPathComponent("exit").path
    let mutationAgent = Agent(
        resolver: mutationResolver,
        grants: GrantTable(),
        consent: ConsentCounter(),
        policyReview: SignalingDelayedPolicyReview(
            markerPaths: [replacementMarker, exitMarker]
        ),
        allowUnverifiedPlansForTesting: true,
        terminalInspection: .unavailable
    )
    let mutationSocket = NSTemporaryDirectory() + "cs-parent-mutation-\(getpid()).sock"
    check(startAccessOnlyServer(path: mutationSocket, agent: mutationAgent),
          "parent-mutation test agent is listening")
    let replacedParentGet = runShellGetCommand(
        "\"$1\" get --reveal --reason parent-replaced --for 60 \"$2\" & "
            + "while [ ! -e \"$3\" ]; do /bin/sleep 0.01; done; exec /bin/sleep 1",
        arguments: [csecURL.path, mutationReference, replacementMarker],
        agentSocket: mutationSocket
    )
    let exitedParentGet = runShellGetCommand(
        "\"$1\" get --reveal --reason parent-exited --for 60 \"$2\" & "
            + "while [ ! -e \"$3\" ]; do /bin/sleep 0.01; done; exit 0",
        arguments: [csecURL.path, mutationReference, exitMarker],
        agentSocket: mutationSocket
    )
    let mutationResolutions = await mutationResolution.calls()
    check(replacedParentGet.out.isEmpty
          && exitedParentGet.out.isEmpty
          && mutationResolutions == 0
          && (replacedParentGet.err.contains("requester changed")
              || replacedParentGet.err.contains("invalid_request"))
          && (exitedParentGet.err.contains("requester changed")
              || exitedParentGet.err.contains("invalid_request")
              || (exitedParentGet.err.contains("approval was not given")
                  && exitedParentGet.err.contains("process that started this request exited")))
          && !replacedParentGet.err.contains(mutationValue)
          && !exitedParentGet.err.contains(mutationValue),
          "replaced or exited parent fails closed before resolution or plaintext output")

    // `csec setup` is now a guided, interactive-only flow. The former flag-driven
    // batch/import surface (--skip-agents/--store/--import/--dry-run/--apply/
    // --replace-secret/--no-audit-prompt) was removed by design; the import engine
    // it used is still covered by cs-selftest (EnvImportTests + the SetupOnboarding
    // block). Here we prove the guided fail-closed gate: run under a piped stderr
    // (not a terminal), setup must refuse with exit 2 and change nothing.
    let guidedSetup = runCsec(
        ["setup", "--project", NSTemporaryDirectory()], extraEnv: [:])
    check(guidedSetup.status == 2
          && guidedSetup.err.contains("interactive guided flow")
          && guidedSetup.out.isEmpty,
          "csec setup refuses to run without an interactive terminal")

    // `csec setup auto-mode` with no csecd answering (csec-0.23): it waits
    // while launchd may still be starting one, then names the cause and exits
    // non-zero, so a script can tell the step was skipped. csec's hook sits
    // in a scratch CLAUDE_CONFIG_DIR, so the step gets as far as csecd.
    do {
        let claudeDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("cs-e2e-claude-\(getpid())", isDirectory: true)
        try FileManager.default.createDirectory(at: claudeDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: claudeDirectory) }
        let hookConfig = runCsec(["hook-config", "claude"], extraEnv: [:])
        try Data(hookConfig.out.utf8).write(to: claudeDirectory.appendingPathComponent("settings.json"))
        let unreachable = runCsecInPTY(
            ["setup", "auto-mode", "--project", NSTemporaryDirectory()],
            extraEnv: ["CSEC_SOCKET": socketPath + ".missing", "CLAUDE_CONFIG_DIR": claudeDirectory.path])
        check(hookConfig.status == 0
              && unreachable.status == 1
              && unreachable.out.contains("3c. Auto-mode approvals (Claude Code)")
              && unreachable.out.contains("Skipped: csecd is not reachable (nothing answers at"),
              "csec setup auto-mode names why csecd did not answer and exits 1 when it skips the step")
    } catch {
        check(false, "csec setup auto-mode fixture failed: \(error)")
    }

    // `csec setup auto-mode` whose terminal input closes (csec-tp8y). On 22
    // Oct a check run with no input and a scratch CLAUDE_CONFIG_DIR answered
    // the default Yes to "Restore them" on EOF: two Touch ID sheets moved
    // delegation off ~/.claude/settings.json. Here a real delegation service
    // holds delegation on for file A, setup runs with CLAUDE_CONFIG_DIR at B,
    // and every sheet it raised would be approved: closed input must stop at
    // the move question, name both files, and change nothing.
    do {
        let base = NSTemporaryDirectory() + "cs-e2e-setup-eof-\(getpid())"
        let recordedDirectory = base + "/recorded", scratchDirectory = base + "/scratch"
        for directory in [recordedDirectory, scratchDirectory] {
            try FileManager.default.createDirectory(
                atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        defer { try? FileManager.default.removeItem(atPath: base) }
        let recordedSettings = recordedDirectory + "/settings.json"
        let scratchSettings = scratchDirectory + "/settings.json"
        let hookConfig = runCsec(["hook-config", "claude"], extraEnv: [:])
        for path in [recordedSettings, scratchSettings] {
            try Data(hookConfig.out.utf8).write(to: URL(fileURLWithPath: path))
        }
        if case let .write(plan) = CodingAgentSetup.planClaudeDelegationEnable(settingsPath: recordedSettings).outcome {
            try CodingAgentSetup.apply(plan)
        }
        let recordedBefore = FileManager.default.contents(atPath: recordedSettings)
        let scratchBefore = FileManager.default.contents(atPath: scratchSettings)
        let stores = ProtectedStores.processLocal()
        _ = try await stores.store(for: DelegationSettingsDocument.self)
            .prepare(DelegationSettingsDocument(setClassifyAllShell: true, claudeSettingsPath: recordedSettings))
            .commit()
        let log = DecisionLog(directory: SealedRecordDirectory(path: base + "/log"), stores: stores)
        _ = await log.open()
        let sheets = SetupEOFConsent()
        let delegation = ClaudeDelegationService(
            stores: stores, gate: makeClaudeSettingsGate(), consent: sheets,
            decisionLog: log, terminalInspection: .unavailable, credentialStore: SignedOutClaudeCredentials(),
            allowUnverifiedCallersForTesting: true
        )
        let delegationAgent = Agent(
            resolver: SecretResolver(cache: NullSecretCache()), grants: GrantTable(), consent: sheets,
            policyReview: DenyPolicyReview(), allowUnverifiedPlansForTesting: true,
            terminalInspection: .unavailable, decisionLog: log, delegation: delegation
        )
        let setupSocket = base + "/csecd.sock"
        let setupServer = SocketServer(path: setupSocket, clientTrustPolicy: .allowUnverifiedForTesting) {
            request, caller in
            switch request {
            case .capabilities:
                return await delegationAgent.capabilities()
            case .schemes:
                return await delegationAgent.schemes()
            case let .configureDelegation(request):
                return await delegationAgent.configureDelegation(request: request, caller: caller)
            default:
                return .failed(.deliveryNotSupported, message: "not part of the setup EOF check")
            }
        }
        Thread.detachNewThread { try? setupServer.run() }
        for _ in 0..<40 where !FileManager.default.fileExists(atPath: setupSocket) {
            try? await Task.sleep(nanoseconds: 50_000_000)
        }
        let closed = runCsecInPTYWithClosedInput(
            ["setup", "auto-mode", "--project", base],
            extraEnv: ["CSEC_SOCKET": setupSocket, "CLAUDE_CONFIG_DIR": scratchDirectory], timeout: 60)
        var recordedPath: String?
        if case let .document(document) = await stores.store(for: DelegationSettingsDocument.self).load() {
            recordedPath = document.claudeSettingsPath
        }
        check(hookConfig.status == 0 && !closed.timedOut && closed.status == 1
              // Prompt.warn wraps at the terminal width, so a long path may
              // start the next line.
              && closed.out.contains("Delegated approvals are set up in") && closed.out.contains(recordedSettings)
              && closed.out.contains("Move delegated approvals to \(scratchSettings) (asks for Touch ID)?")
              && closed.out.contains("[y/N]")
              && closed.out.contains("No answer: the terminal's input closed")
              && !closed.out.contains("Restore them")
              && !closed.out.contains("Keep delegated approvals on?"),
              "csec setup auto-mode under a moved CLAUDE_CONFIG_DIR names both files, defaults the move to No, "
                + "and stops with exit 1 when its input closes (status \(closed.status), timed out "
                + "\(closed.timedOut), out \(String(closed.out.suffix(1200)).debugDescription))")
        check(sheets.count == 0
              && FileManager.default.contents(atPath: recordedSettings) == recordedBefore
              && FileManager.default.contents(atPath: scratchSettings) == scratchBefore
              && recordedPath == recordedSettings,
              "closed input raises no Touch ID sheet and changes neither settings file nor csecd's record")
        unlink(setupSocket)
    } catch {
        check(false, "csec setup closed-input fixture failed: \(error)")
    }

    do {
        let fixtureDirectory = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("csec editor fixture \(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: fixtureDirectory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: fixtureDirectory) }
        let templateURL = fixtureDirectory.appendingPathComponent("template with spaces.json")
        try Data(#"{"EDITOR_TOKEN":"external-editor-synthetic-token"}"#.utf8)
            .write(to: templateURL)

        let workspacesBefore = externalEditorWorkspaceNames()
        let externallyEdited = runCsec(
            ["edit", "--editor", "external_editor"],
            extraEnv: ["EDITOR": "/bin/cp '\(templateURL.path)'"]
        )
        let workspacesAfter = externalEditorWorkspaceNames()
        check(externallyEdited.status == 0
              && externallyEdited.out.contains("saved encrypted store")
              && externallyEdited.err.contains("Same-UID processes")
              && !externallyEdited.out.contains("external-editor-synthetic-token")
              && !externallyEdited.err.contains("external-editor-synthetic-token"),
              "--editor warns, invokes a quoted $EDITOR argv, and saves without printing values")

        let externalValues = try client.access(
            references: ["csec://external_editor/EDITOR_TOKEN"],
            reason: "external editor e2e",
            ttlSeconds: 60
        )
        check(externalValues["csec://external_editor/EDITOR_TOKEN"]
              == Data("external-editor-synthetic-token".utf8),
              "--editor commits the validated document through the native provider")
        check(workspacesAfter == workspacesBefore,
              "--editor removes its randomized plaintext workspace after success")

        let failedWorkspacesBefore = externalEditorWorkspaceNames()
        let failedEdit = runCsec(
            ["edit", "external_editor_failure", "--editor"],
            extraEnv: ["EDITOR": "/usr/bin/false"]
        )
        check(failedEdit.status == 1
              && failedEdit.err.contains("did not exit successfully")
              && externalEditorWorkspaceNames() == failedWorkspacesBefore,
              "--editor cancels and removes its plaintext workspace when the editor fails")
    } catch {
        check(false, "external-editor end-to-end checks run (\(error))")
    }

    let awsArguments = [
        "creds", "aws",
        "--access-key-id-ref", "op://secure-delivery/aws/access-key-id",
        "--secret-access-key-ref", "op://secure-delivery/aws/secret-access-key",
        "--session-token-ref", "op://secure-delivery/aws/session-token",
        "--for", "60",
    ]
    let awsCredentials = runCsec(awsArguments, extraEnv: [:])
    let awsObject = awsCredentials.out.data(using: .utf8).flatMap {
        try? JSONSerialization.jsonObject(with: $0) as? [String: Any]
    }
    check(awsCredentials.status == 0
          && awsObject?["Version"] as? Int == 1
          && awsObject?["AccessKeyId"] as? String == "AKIA-CSEC-SYNTHETIC"
          && awsObject?["SecretAccessKey"] as? String == "aws-csec-synthetic-secret"
          && awsObject?["SessionToken"] as? String == "aws-csec-synthetic-session"
          && !awsCredentials.err.contains("aws-csec-synthetic-secret"),
          "csec creds aws emits only valid credential_process JSON over its private pipe")

    let awsBundle = runCsec(
        ["creds", "aws", "--item", "op://secure-delivery/aws/bundle", "--for", "60"],
        extraEnv: [:]
    )
    let awsBundleObject = awsBundle.out.data(using: .utf8).flatMap {
        try? JSONSerialization.jsonObject(with: $0) as? [String: Any]
    }
    check(awsBundle.status == 0
          && awsBundleObject?["AccessKeyId"] as? String == "AKIA-CSEC-BUNDLE"
          && awsBundleObject?["SecretAccessKey"] as? String == "aws-csec-bundle-secret",
          "csec creds aws accepts one strict JSON bundle reference")

    let consentBeforePerInvocationHelpers = await consent.calls()
    let independentAWSA = runCsec(awsArguments, extraEnv: [:])
    let independentAWSB = runCsec(awsArguments, extraEnv: [:])
    let consentAfterPerInvocationHelpers = await consent.calls()
    check(independentAWSA.status == 0 && independentAWSB.status == 0
          && consentAfterPerInvocationHelpers == consentBeforePerInvocationHelpers + 2,
          "credential helpers use exact per-invocation roots when no session is registered")

    let innerAWSCommand = "\"$1\" creds aws "
        + "--access-key-id-ref op://secure-delivery/aws/access-key-id "
        + "--secret-access-key-ref op://secure-delivery/aws/secret-access-key "
        + "--session-token-ref op://secure-delivery/aws/session-token --for 60; "
        + "\"$1\" creds aws "
        + "--access-key-id-ref op://secure-delivery/aws/access-key-id "
        + "--secret-access-key-ref op://secure-delivery/aws/secret-access-key "
        + "--session-token-ref op://secure-delivery/aws/session-token --for 60"
    let consentBeforeSessionHelpers = await consent.calls()
    let sessionAWS = runCsec(
        ["session", "--", "/bin/sh", "-c", innerAWSCommand, "csec-session-e2e", csecURL.path],
        extraEnv: [:]
    )
    let consentAfterSessionHelpers = await consent.calls()
    let sessionDocuments = sessionAWS.out.split(separator: "\n").compactMap {
        try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any]
    }
    check(sessionAWS.status == 0
          && sessionDocuments.count == 2
          && consentAfterSessionHelpers == consentBeforeSessionHelpers + 1,
          "csec session prompts once while repeated descendant helpers reuse its kernel-verified root")

    let staleSession = runCsec(
        awsArguments,
        extraEnv: [RegisteredSessionHint.environmentKey: UUID().uuidString.lowercased()]
    )
    check(staleSession.status == 1
          && staleSession.out.isEmpty
          && staleSession.err.contains("requested grant root does not match process ancestry"),
          "a stale or copied session hint fails closed instead of falling back to a wider grant")

    let gitArguments = [
        "creds", "git", "--protocol", "https", "--host", "git.example.test",
        "--path", "team/repository.git",
        "--username-ref", "op://secure-delivery/git/username",
        "--password-ref", "op://secure-delivery/git/password",
        "--for", "60", "get",
    ]
    let gitInput = Data(
        "protocol=https\nhost=git.example.test\npath=team/repository.git\n\n".utf8
    )
    let gitCredentials = runCsecWithInput(gitArguments, input: gitInput)
    check(gitCredentials.status == 0
          && gitCredentials.out
            == "username=csec-synthetic-user\npassword=git-csec-synthetic-password\n\n"
          && !gitCredentials.err.contains("git-csec-synthetic-password"),
          "csec creds git implements the bounded get response for an exact host/repository")

    let resolutionsBeforeGitMismatch = await resolutionCounter.calls()
    let mismatchedGit = runCsecWithInput(
        gitArguments,
        input: Data("protocol=https\nhost=other.example.test\npath=team/repository.git\n\n".utf8)
    )
    let resolutionsAfterGitMismatch = await resolutionCounter.calls()
    check(mismatchedGit.status == 0 && mismatchedGit.out.isEmpty
          && resolutionsAfterGitMismatch == resolutionsBeforeGitMismatch,
          "Git host mismatch returns no credential and performs no secret resolution")

    let resolutionsBeforeGitStore = await resolutionCounter.calls()
    let ignoredGitStore = runCsecWithInput(
        Array(gitArguments.dropLast()) + ["store"],
        input: Data(
            "protocol=https\nhost=git.example.test\nusername=synthetic\npassword=do-not-store\n\n".utf8
        )
    )
    let resolutionsAfterGitStore = await resolutionCounter.calls()
    check(ignoredGitStore.status == 0 && ignoredGitStore.out.isEmpty
          && resolutionsAfterGitStore == resolutionsBeforeGitStore,
          "the read-only Git helper ignores store without persisting or resolving a value")

    let presetArguments = [
        "exec-fd", "--redact-output=never",
        "--preset", "pgpass=op://fd-presets/pgpass/content",
        "--preset", "kubeconfig=op://fd-presets/kubeconfig/content",
        "--preset", "aws-shared-credentials=op://fd-presets/aws/content",
        "--preset", "google-service-account=op://fd-presets/google/content",
        "--preset", "npm=op://fd-presets/npm/content",
        "--", "/bin/sh", "-c",
        "case \"$PGPASSFILE:$KUBECONFIG:$AWS_SHARED_CREDENTIALS_FILE:$GOOGLE_APPLICATION_CREDENTIALS:$NPM_CONFIG_USERCONFIG\" in "
            + "*:/dev/fd/6[4-9]:/dev/fd/6[4-9]:/dev/fd/6[4-9]:/dev/fd/6[4-9]) ;; *) exit 81;; esac; "
            + "test \"$PGPASSFILE\" != \"$KUBECONFIG\" && "
            + "test \"$KUBECONFIG\" != \"$AWS_SHARED_CREDENTIALS_FILE\" && "
            + "test \"$AWS_SHARED_CREDENTIALS_FILE\" != \"$GOOGLE_APPLICATION_CREDENTIALS\" && "
            + "test \"$GOOGLE_APPLICATION_CREDENTIALS\" != \"$NPM_CONFIG_USERCONFIG\" || exit 82; "
            + "p=$(cat \"$PGPASSFILE\") && k=$(cat \"$KUBECONFIG\") && "
            + "a=$(cat \"$AWS_SHARED_CREDENTIALS_FILE\") && g=$(cat \"$GOOGLE_APPLICATION_CREDENTIALS\") && "
            + "n=$(cat \"$NPM_CONFIG_USERCONFIG\") || exit 83; "
            + "metadata=$(/bin/ps eww -p $$; /usr/bin/env); "
            + "case \"$metadata\" in *\"$p\"*|*\"$k\"*|*\"$a\"*|*\"$g\"*|*\"$n\"*) exit 84;; esac; "
            + "printf '%s\\n--\\n%s\\n--\\n%s\\n--\\n%s\\n--\\n%s' \"$p\" \"$k\" \"$a\" \"$g\" \"$n\"",
    ]
    let directoryBeforeFD = Set(
        (try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.currentDirectoryPath)) ?? []
    )
    // The npm preset merges the live userconfig: point it at an empty
    // synthetic home so the host's own ~/.npmrc is never read.
    let presetHome = NSTemporaryDirectory() + "csec-fd-presets-\(UUID().uuidString.lowercased())"
    try FileManager.default.createDirectory(atPath: presetHome, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: presetHome) }
    let presetDelivery = runCsec(presetArguments, extraEnv: [
        "HOME": presetHome, "NPM_CONFIG_USERCONFIG": "", "npm_config_userconfig": "",
    ])
    check(!presetDelivery.err.contains(environmentInjectionWarning),
          "inherited-fd delivery does not warn about environment injection")
    let directoryAfterFD = Set(
        (try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.currentDirectoryPath)) ?? []
    )
    check(presetDelivery.status == 0
          && presetDelivery.out.contains("pgpass-synthetic-secret")
          && presetDelivery.out.contains("synthetic: kube-secret")
          && presetDelivery.out.contains("aws_secret_access_key=aws-fd-secret")
          && presetDelivery.out.contains("google-fd-secret")
          && presetDelivery.out.contains("_authToken=npm-fd-secret")
          && !presetDelivery.err.contains("pgpass-synthetic-secret")
          && !presetDelivery.err.contains("npm-fd-secret")
          && directoryAfterFD == directoryBeforeFD,
          "all fd presets deliver exact bytes through distinct /dev/fd paths without argv, env, or files")

    let genericFD = runCsec(
        [
            "exec-fd", "--redact-output=never",
            "--fd", "TOOL_CONFIG=op://fd-presets/google/content",
            "--", "/bin/sh", "-c", "/bin/cat \"$TOOL_CONFIG\"",
        ],
        extraEnv: [:]
    )
    check(genericFD.status == 0
          && genericFD.out == "{\"type\":\"service_account\",\"private_key\":\"google-fd-secret\"}"
          && !genericFD.err.contains("google-fd-secret"),
          "generic --fd maps an exact reference payload to a caller-selected path variable")

    let consentBeforeRegularFiles = await consent.calls()
    let resolutionsBeforeRegularFiles = await resolutionCounter.calls()
    let regularFileProbe = runCsec(
        [
            "exec-file", "--redact-output=always", "--for", "60",
            "--file", "PROTECTED_FILE=op://file-delivery/config/content",
            "--", fileProbeURL.path, "--parent", "400",
        ],
        extraEnv: [:]
    )
    check(regularFileProbe.status == 0
          && regularFileProbe.out == "file-probe-ok\n"
          && !regularFileProbe.err.contains("regular-file-synthetic-secret"),
          "exec-file supports stat, open, reopen, seek, mmap, and fork/exec inheritance "
            + "(status=\(regularFileProbe.status), out=\(regularFileProbe.out.debugDescription), "
            + "err=\(regularFileProbe.err.debugDescription))")

    let regularFileLeak = runCsec(
        [
            "exec-file", "--redact-output=always", "--for", "60",
            "--file", "TOOL_CONFIG=op://file-delivery/config/content",
            "--", "/bin/sh", "-c", "/bin/cat \"$TOOL_CONFIG\"",
        ],
        extraEnv: [:]
    )
    let consentAfterRegularFiles = await consent.calls()
    let resolutionsAfterRegularFiles = await resolutionCounter.calls()
    check(regularFileLeak.status == 0
          && regularFileLeak.out.contains("[redacted: op://file-delivery/config/content]")
          && !regularFileLeak.out.contains("regular-file-synthetic-secret")
          && !regularFileLeak.err.contains("regular-file-synthetic-secret"),
          "exec-file output scanning redacts a protected file deliberately printed by its target, "
            + "naming the reference in-band "
            + "(status=\(regularFileLeak.status), out=\(regularFileLeak.out.debugDescription), "
            + "err=\(regularFileLeak.err.debugDescription))")
    check(consentAfterRegularFiles == consentBeforeRegularFiles + 2
          && resolutionsAfterRegularFiles == resolutionsBeforeRegularFiles + 2,
          "every protected-file launch repeats consent and resolution for its one-time rendezvous")

    let regularFilePTY = runCsecInPTY(
        [
            "exec-file", "--for", "60",
            "--file", "PROTECTED_FILE=op://file-delivery/config/content",
            "--", "/bin/sh", "-c",
            "test -t 0 && test -t 1 && test -t 2 && stty size && /bin/cat \"$PROTECTED_FILE\"",
        ],
        extraEnv: [:]
    )
    check(regularFilePTY.status == 0
          && regularFilePTY.out.contains("37 113")
          && regularFilePTY.out.contains("[redacted: op://file-delivery/config/content]")
          && !regularFilePTY.out.contains("regular-file-synthetic-secret")
          && !regularFilePTY.err.contains("regular-file-synthetic-secret"),
          "exec-file preserves a controlling PTY, terminal size, and guarded output")

    let githubArguments = [
        "exec-file", "--redact-output=always", "--for", "60",
        "--gh-config", "op://github/profile/token",
        "--github-host", "github.example.test",
        "--github-user", "synthetic-user",
        "--github-git-protocol", "https",
        "--", fakeGHURL.path, "api", "user",
    ]
    let resolutionsBeforeAmbientGitHub = await resolutionCounter.calls()
    let ambientGitHub = runCsec(
        githubArguments,
        extraEnv: ["GH_TOKEN": "synthetic-ambient-authority"]
    )
    let resolutionsAfterAmbientGitHub = await resolutionCounter.calls()
    check(ambientGitHub.status == 1
          && ambientGitHub.out.isEmpty
          && ambientGitHub.err.contains("ambient GitHub authentication remains")
          && resolutionsAfterAmbientGitHub == resolutionsBeforeAmbientGitHub,
          "GH_CONFIG_DIR mode refuses ambient token authority before resolving its profile")

    let protectedGitHub = runCsec(githubArguments, extraEnv: [:])
    check(protectedGitHub.status == 0
          && protectedGitHub.out == "gh-profile-ok\n"
          && !protectedGitHub.err.contains("github-regular-file-synthetic-token"),
          "GH_CONFIG_DIR mode gives only direct gh a protected hosts.yml profile "
            + "(status=\(protectedGitHub.status), out=\(protectedGitHub.out.debugDescription), "
            + "err=\(protectedGitHub.err.debugDescription))")

    let sessionsAfterRegularFile = (try? FileManager.default.contentsOfDirectory(
        atPath: rootFixtureDirectory + "/files"
    )) ?? []
    check(sessionsAfterRegularFile.isEmpty,
          "the root helper removes the protected session after the complete launch tree exits")

    let redactedFD = runCsec(
        [
            "exec-fd", "--redact-output=always",
            "--preset", "pgpass=op://fd-presets/pgpass/content",
            "--", "/bin/cat", "$PGPASSFILE",
        ],
        extraEnv: [:]
    )
    // There is intentionally no shell expansion in exec-fd. Use a shell only
    // in the positive check so the target reads the non-secret environment path.
    let redactedFDViaShell = runCsec(
        [
            "exec-fd", "--redact-output=always",
            "--preset", "pgpass=op://fd-presets/pgpass/content",
            "--", "/bin/sh", "-c", "/bin/cat \"$PGPASSFILE\"",
        ],
        extraEnv: [:]
    )
    check(redactedFD.status != 0
          && redactedFDViaShell.status == 0
          && redactedFDViaShell.out == "[redacted: op://fd-presets/pgpass/content]"
          && !redactedFDViaShell.out.contains("pgpass-synthetic-secret")
          && !redactedFDViaShell.err.contains("pgpass-synthetic-secret"),
          "exec-fd keeps argv literal and masks a child that deliberately prints the delivered file")

    let fdProbe = Process()
    fdProbe.executableURL = csecURL
    fdProbe.arguments = [
        "exec-fd", "--redact-output=never",
        "--preset", "pgpass=op://fd-presets/pgpass/content",
        "--", "/bin/sh", "-c",
        "printf '%s\\n' \"$PGPASSFILE\"; /bin/sleep 1; /bin/cat \"$PGPASSFILE\" >/dev/null",
    ]
    var fdProbeEnvironment = ProcessInfo.processInfo.environment
    fdProbeEnvironment["CSEC_SOCKET"] = socketPath
    fdProbe.environment = fdProbeEnvironment
    let fdProbeOut = Pipe(), fdProbeErr = Pipe()
    fdProbe.standardOutput = fdProbeOut
    fdProbe.standardError = fdProbeErr
    do {
        try fdProbe.run()
        var pathData = Data()
        while pathData.count < 128 {
            let byte = fdProbeOut.fileHandleForReading.readData(ofLength: 1)
            if byte.isEmpty || byte.first == 0x0a { break }
            pathData.append(byte)
        }
        let inheritedPath = String(data: pathData, encoding: .utf8) ?? ""
        let unrelated = runProgram(executable: "/usr/bin/stat", arguments: [inheritedPath])
        _ = fdProbeOut.fileHandleForReading.readDataToEndOfFile()
        let fdProbeError = fdProbeErr.fileHandleForReading.readDataToEndOfFile()
        fdProbe.waitUntilExit()
        check(inheritedPath.hasPrefix("/dev/fd/6")
              && unrelated.status != 0
              && unrelated.out.isEmpty
              && fdProbe.terminationStatus == 0
              && !String(data: fdProbeError, encoding: .utf8)!.contains("pgpass-synthetic-secret"),
              "an unrelated same-UID process cannot address or inspect the child's inherited fd")
    } catch {
        check(false, "unrelated-process inherited-fd probe runs (\(error))")
    }

    // Explicit --set injects a named reference into the child. The comparison
    // happens inside the child so the default output guard has nothing to redact.
    let explicit = runCsec(
        ["exec", "--set", "TESTVAR=op://demo/db/url", "--", "/bin/sh", "-c",
         "test \"$TESTVAR\" = 'postgres://s3cr3t' && printf explicit-ok"],
        extraEnv: [:]
    )
    check(explicit.status == 0 && explicit.out == "explicit-ok",
          "csec exec --set injects the resolved value (got status \(explicit.status), out \"\(explicit.out)\", err \"\(explicit.err)\")")
    checkEnvironmentInjectionWarning(explicit.err, command: "exec", label: "explicit exec")

    // Without any --redact-output flag, a resolved value printed to a captured
    // stdout must come back as a label: `always` is the default, not `tty`.
    let defaultGuarded = runCsec(
        ["exec", "--set", "TESTVAR=op://demo/db/url", "--", "/bin/sh", "-c", "printf %s \"$TESTVAR\""],
        extraEnv: [:]
    )
    check(defaultGuarded.status == 0
          && defaultGuarded.out == "[redacted: op://demo/db/url]"
          && !defaultGuarded.err.contains("protected output detected and redacted")
          && !defaultGuarded.out.contains("postgres://s3cr3t")
          && !defaultGuarded.err.contains("postgres://s3cr3t"),
          "the default output guard names the redacted reference in-band and stays silent on stderr "
            + "(status \(defaultGuarded.status), out \"\(defaultGuarded.out)\", err \"\(defaultGuarded.err)\")")

    // Opting in restores the per-match stderr warning, which now names the
    // reference rather than an opaque ordinal.
    let warnedGuarded = runCsec(
        ["exec", "--redact-output-warn", "--set", "TESTVAR=op://demo/db/url", "--",
         "/bin/sh", "-c", "printf %s \"$TESTVAR\""],
        extraEnv: [:]
    )
    check(warnedGuarded.status == 0
          && warnedGuarded.out == "[redacted: op://demo/db/url]"
          && warnedGuarded.err.contains("protected output detected and redacted")
          && warnedGuarded.err.contains("op://demo/db/url")
          && !warnedGuarded.err.contains("postgres://s3cr3t"),
          "--redact-output-warn emits a stderr warning naming the redacted reference "
            + "(status \(warnedGuarded.status), out \"\(warnedGuarded.out)\", err \"\(warnedGuarded.err)\")")

    let mixedProviders = runCsec(
        [
            "exec", "--redact-output=always",
            "--set", "REMOTE=op://demo/db/url",
            "--set", "LOCAL=csec://development/NATIVE_TOKEN",
            "--", "/bin/sh", "-c",
            "test \"$REMOTE\" = 'postgres://s3cr3t' && "
                + "test \"$LOCAL\" = 'native-synthetic-token' && printf mixed-ok",
        ],
        extraEnv: [:]
    )
    check(mixedProviders.status == 0 && mixedProviders.out == "mixed-ok",
          "csec exec resolves 1Password and native-store assignments in one launch")
    checkEnvironmentInjectionWarning(mixedProviders.err, command: "exec", label: "mixed-provider exec")

    let guarded = runCsec(
        [
            "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c",
            "printf %s 'postgres://'; printf %s 's3cr3t'; "
                + "printf %s 'postgres://' >&2; printf %s 's3cr3t' >&2",
        ],
        extraEnv: [:]
    )
    check(guarded.status == 0
          && guarded.out == "[redacted: op://demo/db/url]"
          && guarded.err.contains("[redacted: op://demo/db/url]")
          && !guarded.err.contains("protected output detected and redacted")
          && !guarded.out.contains("postgres://s3cr3t")
          && !guarded.err.contains("postgres://s3cr3t"),
          "always mode redacts split matches on stdout and stderr before forwarding")

    // This launch resolves no values. Its matcher comes from csecd's registry,
    // populated by the earlier independent access/exec launches, which is the
    // property needed when pgrep exposes a RuboCop daemon from another worktree.
    // The visible `ai -- '<program>'` form is what the Claude hook now emits.
    let crossLaunch = runCsec(
        ["ai", "--", "printf %s 'postgres://'; printf %s 's3cr3t'"],
        extraEnv: [:]
    )
    check(crossLaunch.status == 0
          && crossLaunch.out.hasPrefix("[csec:secret-")
          && !crossLaunch.err.contains(environmentInjectionWarning)
          && !crossLaunch.err.contains("protected output detected and redacted")
          && !crossLaunch.out.contains("postgres://s3cr3t")
          && !crossLaunch.err.contains("postgres://s3cr3t"),
          "csec ai redacts another launch's active value with opaque labels and no warning "
              + "(status=\(crossLaunch.status), label=\(crossLaunch.out.hasPrefix("[csec:secret-")), "
              + "raw=\(crossLaunch.out.contains("postgres://s3cr3t") || crossLaunch.err.contains("postgres://s3cr3t")), "
              + "err=\(crossLaunch.err.contains("postgres://s3cr3t") ? "<contained synthetic marker>" : crossLaunch.err))")

    // csec ai injects a reference-valued environment variable (the direnv
    // ergonomic) and then redacts that same value from the child's AI-facing
    // output. Injection: the child compares $INJECTED to the known plaintext and
    // prints a non-secret marker only on a match.
    let aiInjected = runCsec(
        ["ai", "--", "test \"$INJECTED\" = 'postgres://s3cr3t' && printf inject-ok"],
        extraEnv: ["INJECTED": "op://demo/db/url"]
    )
    check(aiInjected.status == 0 && aiInjected.out == "inject-ok",
          "csec ai resolves an op:// environment reference and injects it into the child "
              + "(status \(aiInjected.status), out \"\(aiInjected.out)\", err \"\(aiInjected.err)\")")
    checkEnvironmentInjectionWarning(aiInjected.err, command: "ai", label: "AI environment injection")

    for wrapper in ["ai", "tool-exec"] {
        let prefixed = runCsec(
            [wrapper, "--", "test \"$INJECTED\" = 'postgres://s3cr3t' && test -z \"${csec_INJECTED+x}\" && printf alias-ok"],
            extraEnv: ["csec_INJECTED": "op://demo/db/url"])
        check(prefixed.status == 0 && prefixed.out == "alias-ok",
              "\(wrapper) resolves a prefixed reference and removes its alias")
        checkEnvironmentInjectionWarning(prefixed.err, command: wrapper, label: "prefixed \(wrapper)")
    }

    // Redaction of the injected value: printing it straight to the AI stream comes
    // back as an opaque label, never plaintext.
    let aiInjectedRedacted = runCsec(
        ["ai", "--", "printf %s \"$INJECTED\""],
        extraEnv: ["INJECTED": "op://demo/db/url"]
    )
    check(aiInjectedRedacted.status == 0
          && aiInjectedRedacted.out.hasPrefix("[csec:secret-")
          && !aiInjectedRedacted.out.contains("postgres://s3cr3t")
          && !aiInjectedRedacted.err.contains("postgres://s3cr3t"),
          "csec ai redacts its own injected value from the AI-facing output "
              + "(status \(aiInjectedRedacted.status), out \"\(aiInjectedRedacted.out)\")")

    // csec as Claude Code's shell prefix (csec-0.83.1, av-e2sa, av-pivm): every
    // Bash call now reaches csec ai as `--claude-code-shell <framing>`, so this
    // path carries the masking every agent command relies on. Claude Code's
    // shell snapshot is sourced inside the framing, under csec ai, so a function
    // it defines runs with the injected value too and its output must be masked
    // just the same. A hook or MCP line (no framing markers) runs unwrapped and
    // must get no value at all.
    do {
        let prefixDirectory = NSTemporaryDirectory() + "csec-e2e-prefix-\(UUID().uuidString.lowercased())"
        try? FileManager.default.createDirectory(atPath: prefixDirectory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: prefixDirectory) }
        let snapshot = prefixDirectory + "/snapshot-zsh-e2e.sh"
        try? Data("print_injected() { printf %s \"$INJECTED\"; }\n".utf8).write(to: URL(fileURLWithPath: snapshot))
        let cwdFile = prefixDirectory + "/claude-e2e-cwd"
        func framing(_ command: String) -> String {
            "source '\(snapshot)' 2>/dev/null || true"
                + " && { shopt -u extglob || setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL; } >/dev/null 2>&1 || true"
                + " && eval '" + command.replacingOccurrences(of: "'", with: "'\"'\"'") + "' < /dev/null"
                + " && pwd -P >| " + cwdFile
        }
        let leaked = { (run: (status: Int32, reason: Process.TerminationReason, out: String, err: String)) in
            run.out.contains("postgres://s3cr3t") || run.err.contains("postgres://s3cr3t")
        }

        let stdout = runCsec(["ai", "--claude-code-shell", framing("printf %s \"$INJECTED\"")],
                             extraEnv: ["INJECTED": "op://demo/db/url"])
        let cwd = (try? String(contentsOfFile: cwdFile, encoding: .utf8)) ?? ""
        check(stdout.status == 0 && stdout.out.hasPrefix("[csec:secret-") && !leaked(stdout) && !cwd.isEmpty,
              "shell prefix: a Claude Code framing's injected value comes back masked on stdout and the framing "
                  + "still records its cwd (status \(stdout.status), label \(stdout.out.hasPrefix("[csec:secret-")), "
                  + "raw \(leaked(stdout)), cwd recorded \(!cwd.isEmpty))")

        let stderr = runCsec(["ai", "--claude-code-shell", framing("printf %s \"$INJECTED\" >&2")],
                             extraEnv: ["INJECTED": "op://demo/db/url"])
        check(stderr.status == 0 && stderr.err.contains("[csec:secret-") && !leaked(stderr),
              "shell prefix: a framing's injected value comes back masked on stderr "
                  + "(status \(stderr.status), label \(stderr.err.contains("[csec:secret-")), raw \(leaked(stderr)))")

        let snapshotFunction = runCsec(["ai", "--claude-code-shell", framing("print_injected")],
                                       extraEnv: ["INJECTED": "op://demo/db/url"])
        check(snapshotFunction.status == 0 && snapshotFunction.out.hasPrefix("[csec:secret-")
              && !leaked(snapshotFunction),
              "shell prefix: a shell-snapshot function that prints the injected value is masked too "
                  + "(status \(snapshotFunction.status), label \(snapshotFunction.out.hasPrefix("[csec:secret-")), "
                  + "raw \(leaked(snapshotFunction)))")

        let hookLine = runCsec(["ai", "--claude-code-shell", "printf %s \"$INJECTED\""],
                               extraEnv: ["INJECTED": "op://demo/db/url"])
        check(hookLine.status == 0 && hookLine.out == "op://demo/db/url" && !leaked(hookLine),
              "shell prefix: a hook-style line runs unwrapped with its reference unresolved, never a value "
                  + "(status \(hookLine.status), reference kept \(hookLine.out == "op://demo/db/url"), "
                  + "raw \(leaked(hookLine)))")
    }

// Secret-free programs (AICommandSecretFree). The references here resolve to
// nothing, so any access request would degrade the launch with a warning and
// hand the child its original environment: the checks see both.
do {
    let secretFreeEnvironment = [
        "CSEC_E2E_SECRET_FREE_REF": "op://secret-free/never/requested",
        "csec_CSEC_E2E_SECRET_FREE_ALIAS": "op://secret-free/alias/never-requested",
        "CSEC_E2E_SECRET_FREE_PLAIN": "plain-marker-not-a-reference",
    ]
    // `ps -E` prints the child's own environment without expanding a variable,
    // which would itself make the program need secrets.
    let accessBefore = await accessRequests.calls()
    let reviewsBefore = await accessReviewCapture.snapshot().count
    let readOnly = runCsec(["ai", "--", "/bin/ps -Eww -o command= -p \"$$\""], extraEnv: secretFreeEnvironment)
    let accessAfter = await accessRequests.calls()
    let reviewsAfter = await accessReviewCapture.snapshot().count
    check(readOnly.status == 0
          && accessAfter == accessBefore
          && reviewsAfter == reviewsBefore
          && readOnly.out.contains("CSEC_E2E_SECRET_FREE_PLAIN=plain-marker-not-a-reference")
          && !readOnly.out.contains("CSEC_E2E_SECRET_FREE_REF")
          && !readOnly.out.contains("CSEC_E2E_SECRET_FREE_ALIAS")
          && !readOnly.out.contains("op://secret-free/")
          && !readOnly.err.contains(environmentInjectionWarning)
          && !readOnly.err.contains("WITHOUT csec"),
          "csec ai runs a secret-free first command with no access request or review, and its child "
              + "sees none of the reference variables (status \(readOnly.status), access requests "
              + "\(accessAfter - accessBefore), reviews \(reviewsAfter - reviewsBefore), plain marker "
              + "\(readOnly.out.contains("CSEC_E2E_SECRET_FREE_PLAIN=")), reference names "
              + "\(readOnly.out.contains("CSEC_E2E_SECRET_FREE_REF") || readOnly.out.contains("CSEC_E2E_SECRET_FREE_ALIAS")))")

    // Not secret-free: expanding a reference, or running an unlisted program
    // that expands nothing, still asks csecd and injects as before.
    for (program, expected, label) in [
        ("test -n \"$CSEC_E2E_SECRET_FREE_INJECT\" && printf requested", "requested",
         "a program that expands a reference variable"),
        ("/usr/bin/awk 'BEGIN { printf \"requested\" }'", "requested", "an unlisted program"),
    ] {
        let before = await accessRequests.calls()
        let requesting = runCsec(
            ["ai", "--", program],
            extraEnv: ["CSEC_E2E_SECRET_FREE_INJECT": "op://demo/api/key"]
        )
        let after = await accessRequests.calls()
        check(requesting.status == 0 && requesting.out == expected && after == before + 1
              && !requesting.err.contains("WITHOUT csec"),
              "csec ai still requests access for \(label) (status \(requesting.status), access requests "
                  + "\(after - before), out \(requesting.out.debugDescription))")
    }

    // The sudo PAM module's redactor runs `tool-exec --destination ai -- /bin/cat`
    // over NUL-delimited argv with only PATH and LANG. `/bin/cat` is secret-free,
    // so with a reference in the environment it now asks for nothing, and the
    // value released earlier in this run is still redacted either way.
    let sudoArgv = Data("/usr/bin/psql\u{0}postgres://s3cr3t\u{0}--echo\u{0}".utf8)
    for (label, extra) in [
        ("the PAM module's environment", [String: String]()),
        ("a reference in the environment", ["CSEC_E2E_SECRET_FREE_REF": "op://secret-free/never/requested"]),
    ] {
        let before = await accessRequests.calls()
        let redacted = runCsecWithInput(
            ["tool-exec", "--destination", "ai", "--", "/bin/cat"],
            input: sudoArgv,
            extraEnv: extra,
            baseEnvironment: ["PATH": "/usr/bin:/bin", "LANG": "C"]
        )
        let after = await accessRequests.calls()
        check(redacted.status == 0
              && after == before
              && redacted.out.hasPrefix("/usr/bin/psql\u{0}[csec:secret-")
              && redacted.out.hasSuffix("\u{0}--echo\u{0}")
              && !redacted.out.contains("postgres://s3cr3t")
              && !redacted.err.contains("postgres://s3cr3t")
              && !redacted.err.contains("WITHOUT csec"),
              "sudo's tool-exec /bin/cat redactor still redacts an active value with \(label) "
                  + "(status \(redacted.status), access requests \(after - before), "
                  + "label \(redacted.out.contains("[csec:secret-")), "
                  + "raw \(redacted.out.contains("postgres://s3cr3t")))")
    }
}

    let quotedShellOutput = "spaces $HOME `uname` \"quotes\"\nsecond line"
    let quotedShellProgram = "printf '%s' '" + quotedShellOutput + "'"
    // The legacy base64 transport still round-trips through the hidden `tool-exec`
    // alias, so already-emitted rewrites keep working.
    let encodedShell = runCsec(
        [
            "tool-exec", "--destination", "ai", "--encoded-shell-command",
            AICommandHook.encodeShellCommand(quotedShellProgram),
        ],
        extraEnv: [:]
    )
    check(encodedShell.status == 0 && encodedShell.out == quotedShellOutput,
          "the tool-exec alias base64 transport preserves spaces, metacharacters, quotes, and newlines")

    // Faithful regression for the reported incident: a tiny synthetic daemon
    // rewrites its original argv string area the way modern Ruby does while one
    // already-registered fake value is in its initial environment. First prove
    // raw pgrep exposes the marker, then run the same command through tool-exec.
    let rubocopToken = "csec-rubocop-fixture-\(getpid())"
    let rubocopFixture = Process()
    rubocopFixture.executableURL = processTitleFixtureURL
    rubocopFixture.arguments = [rubocopToken, "padding-one", "padding-two"]
    rubocopFixture.environment = ["CSEC_SYNTHETIC_RUBOCOP_SECRET": "postgres://s3cr3t"]
    let readyPipe = Pipe()
    rubocopFixture.standardOutput = readyPipe
    rubocopFixture.standardError = FileHandle.nullDevice
    do {
        try rubocopFixture.run()
        let ready = readyPipe.fileHandleForReading.readData(ofLength: 6)
        let rawPgrep = runProgram(executable: "/usr/bin/pgrep", arguments: ["-fl", rubocopToken])
        let rawFixtureReproduced = ready == Data("ready\n".utf8)
            && rawPgrep.status == 0
            && rawPgrep.out.contains("postgres://s3cr3t")
        check(rawFixtureReproduced,
              "synthetic RuboCop-title fixture reproduces the raw pgrep environment disclosure "
                  + "(ready=\(ready == Data("ready\n".utf8)), status=\(rawPgrep.status), "
                  + "marker=\(rawPgrep.out.contains("postgres://s3cr3t")))")

        let guardedPgrep = runCsec(
            ["ai", "--", "/usr/bin/pgrep -fl \(rubocopToken)"],
            extraEnv: [:]
        )
        check(rawFixtureReproduced
              && guardedPgrep.status == 0
              && guardedPgrep.out.contains("[csec:secret-")
              && !guardedPgrep.out.contains("postgres://s3cr3t")
              && !guardedPgrep.err.contains("postgres://s3cr3t"),
              "synthetic RuboCop/pgrep leak is redacted before the simulated AI recipient "
                  + "(status=\(guardedPgrep.status), label=\(guardedPgrep.out.contains("[csec:secret-")), "
                  + "raw=\(guardedPgrep.out.contains("postgres://s3cr3t") || guardedPgrep.err.contains("postgres://s3cr3t")))")
        rubocopFixture.terminate()
        rubocopFixture.waitUntilExit()
    } catch {
        check(false, "synthetic RuboCop-title fixture starts")
    }

    // csec ai NEVER blocks: when csecd is unreachable it exhausts the reconnect
    // window, then warns (naming csecd and the `csec doctor` fix) and runs the
    // command WITHOUT csec — references left unresolved, no secret revealed —
    // rather than refusing and bricking the shell.
    let unavailableMarker = NSTemporaryDirectory() + "csec-ai-degraded-\(getpid())"
    try? FileManager.default.removeItem(atPath: unavailableMarker)
    let unavailable = runCsec(
        ["ai", "--", "/usr/bin/touch \(unavailableMarker)"],
        extraEnv: ["CSEC_SOCKET": NSTemporaryDirectory() + "csec-missing-\(getpid()).sock"]
    )
    check(unavailable.status == 0
          && FileManager.default.fileExists(atPath: unavailableMarker)
          && unavailable.err.contains("csecd")
          && unavailable.err.contains("not reachable")
          && unavailable.err.contains("csec doctor")
          && unavailable.err.contains("WITHOUT csec")
          && !unavailable.err.contains(environmentInjectionWarning),
          "csec ai warns (naming csecd and doctor) and still runs the command when csecd is unreachable "
              + "(status \(unavailable.status), err \"\(unavailable.err)\")")
    try? FileManager.default.removeItem(atPath: unavailableMarker)

    let interruptedMarker = NSTemporaryDirectory() + "csec-ai-terminated-\(getpid())"
    try? FileManager.default.removeItem(atPath: interruptedMarker)
    let interrupted = runCsec(
        [
            "ai", "--",
            "printf %s \(forcedScannerFailureMarker); sleep 2; /usr/bin/touch \(interruptedMarker)",
        ],
        extraEnv: [:]
    )
    check(interrupted.status == 1
          && interrupted.out.isEmpty
          && !FileManager.default.fileExists(atPath: interruptedMarker)
          && interrupted.err.contains("command terminated"),
          "csec ai forwards no unscanned chunk and terminates the child if scanning fails")

    let longest = runCsec(
        [
            "exec", "--redact-output=always",
            "--set", "SHORT=op://demo/db/url",
            "--set", "LONG=op://demo/db/url-extended", "--",
            "/bin/sh", "-c", "printf %s \"$LONG\"",
        ],
        extraEnv: [:]
    )
    check(longest.status == 0 && longest.out == "[redacted: op://demo/db/url-extended]"
          && !longest.out.contains("postgres://s3cr3t"),
          "supervised output uses the longest matching protected value and names its reference")

    let encoded = runCsec(
        [
            "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "printf %s \"$TESTVAR\" | /usr/bin/base64",
        ],
        extraEnv: [:]
    )
    check(encoded.status == 0 && encoded.out == "[redacted: op://demo/db/url]\n"
          && !encoded.out.contains("cG9zdGdyZXM"),
          "supervised output recognizes canonical base64 secret output")

    // Opting out with `--redact-output-label=opaque` restores the ordinal label
    // and keeps the reference out of the output stream entirely.
    let opaqueLabel = runCsec(
        [
            "exec", "--redact-output=always", "--redact-output-label=opaque",
            "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "printf %s \"$TESTVAR\"",
        ],
        extraEnv: [:]
    )
    check(opaqueLabel.status == 0 && opaqueLabel.out == "[csec:secret-1]"
          && !opaqueLabel.out.contains("op://demo/db/url")
          && !opaqueLabel.out.contains("postgres://s3cr3t"),
          "--redact-output-label=opaque restores an ordinal label with no reference in output "
            + "(status \(opaqueLabel.status), out \"\(opaqueLabel.out)\")")

    let byteExact = runCsec(
        [
            "exec", "--redact-output=never", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "printf %s \"$TESTVAR\"",
        ],
        extraEnv: [:]
    )
    check(byteExact.status == 0 && byteExact.out == "postgres://s3cr3t"
          && byteExact.err.contains("explicitly disabled"),
          "never mode is an explicit byte-exact bypass with a warning")
    checkEnvironmentInjectionWarning(byteExact.err, command: "exec", label: "exec replacement")

    let childExit = runCsec(
        [
            "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "exit 23",
        ],
        extraEnv: [:]
    )
    check(childExit.status == 23, "the output supervisor preserves the child's exit code")
    checkEnvironmentInjectionWarning(childExit.err, command: "exec", label: "nonzero exec exit")

    let childSignal = runCsec(
        [
            "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "kill -TERM $$",
        ],
        extraEnv: [:]
    )
    check(childSignal.reason == .uncaughtSignal && childSignal.status == SIGTERM,
          "the output supervisor preserves a child's terminating signal")

    let externallyTerminated = runCsecWithExternalTermination()
    check(externallyTerminated.status == 42 && externallyTerminated.out.count == 80,
          "signals sent to csec are forwarded to the supervised child process group")

    let stopAndContinue = runCsecThroughStopAndContinue()
    check(stopAndContinue.observedStop
          && stopAndContinue.status == 0
          && stopAndContinue.out.hasSuffix("[redacted: op://demo/db/url]")
          && !stopAndContinue.out.contains("postgres://s3cr3t"),
          "the supervisor mirrors child stop/continue and resumes guarded output")

    let automaticTTY = runCsecInPTY(
        [
            "exec", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c",
            "test -t 0 && test -t 1 && test -t 2 && stty size && "
                + "printf %s 'postgres://' && printf %s 's3cr3t'",
        ],
        extraEnv: [:]
    )
    let ptyNumbers = automaticTTY.out
        .split(whereSeparator: { !$0.isNumber })
        .compactMap { Int($0) }
    let automaticTTYPassed = automaticTTY.status == 0
        && automaticTTY.out.contains("[redacted: op://demo/db/url]")
        && automaticTTY.out.contains("37 113")
        && !automaticTTY.out.contains("protected output detected and redacted")
        && !automaticTTY.out.contains("postgres://s3cr3t")
    let automaticTTYDiagnostics = automaticTTYPassed ? "" : " "
        + "(status=\(automaticTTY.status), label=\(automaticTTY.out.contains("[redacted: op://demo/db/url]")), "
        + "size=\(automaticTTY.out.contains("37 113")), numbers=\(ptyNumbers), "
        + "event=\(automaticTTY.out.contains("protected output detected and redacted")), "
        + "raw=\(automaticTTY.out.contains("postgres://s3cr3t")))"
    check(automaticTTYPassed,
          "the default guard allocates a child PTY and automatically redacts terminal output"
              + automaticTTYDiagnostics)

    // fish 4 asks the terminal for its Primary Device Attributes at startup and
    // waits for the reply. The demo value's base64 form begins with DA1's final
    // `c`, so the query reaches the terminal (here, the test answering it) only
    // if the guarded PTY relay forwards the whole sequence at once (csec-bpc).
    let terminalQuery = runCsecExpectInPTY(
        cwd: NSTemporaryDirectory(),
        [
            "exec", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c",
            "stty -echo; printf '\\033[0c'; IFS= read -r reply; printf 'reply=%s\\n' \"$reply\"",
        ],
        steps: [(expect: "\u{1b}[0c", send: "da1-answer\n")]
    )
    check(terminalQuery.status == 0 && terminalQuery.out.contains("reply=da1-answer"),
          "a terminal query from the supervised child reaches the terminal whole, so its reply arrives"
              + (terminalQuery.status == 0 ? "" : " (status=\(terminalQuery.status))"))

    // Env-scan: a reference already in the environment is resolved in place.
    let scanned = runCsec(
        ["exec", "--", "/bin/sh", "-c",
         "test \"$TESTVAR\" = 'postgres://s3cr3t' && printf scanned-ok"],
        extraEnv: ["TESTVAR": "op://demo/db/url"]
    )
    check(scanned.status == 0 && scanned.out == "scanned-ok",
          "csec exec env-scan resolves an op:// value already in the environment (got status \(scanned.status), out \"\(scanned.out)\", err \"\(scanned.err)\")")

    // A plain URL in the environment must be passed through untouched.
    for mode in ["always", "never"] {
        let prefixed = runCsec(
            ["exec", "--redact-output=\(mode)", "--", "/bin/sh", "-c",
             "test \"$TESTVAR\" = 'postgres://s3cr3t' && test -z \"${csec_TESTVAR+x}\" && printf alias-ok"],
            extraEnv: ["csec_TESTVAR": "op://demo/db/url"])
        check(prefixed.status == 0 && prefixed.out == "alias-ok",
              "exec \(mode) resolves prefixed references and removes aliases")
        checkEnvironmentInjectionWarning(prefixed.err, command: "exec", label: "env-scanned exec \(mode)")
    }
    let conflicting = runCsec(
        ["exec", "--", "/bin/sh", "-c", "printf should-not-launch"],
        extraEnv: ["TESTVAR": "ordinary", "csec_TESTVAR": "op://demo/db/url"])
    check(conflicting.status != 0 && conflicting.out.isEmpty && conflicting.err.contains("both TESTVAR and csec_TESTVAR"),
          "conflicting ambient names fail before launching the command")

    let untouched = runCsec(
        ["exec", "--", "/bin/sh", "-c", "printf %s \"$SITE_URL\""],
        extraEnv: ["SITE_URL": "https://example.com"]
    )
    check(untouched.status == 0 && untouched.out == "https://example.com",
          "csec exec leaves a non-secret URL untouched (got status \(untouched.status), out \"\(untouched.out)\", err \"\(untouched.err)\")")
    check(!untouched.err.contains(environmentInjectionWarning),
          "exec without resolved references does not warn about environment injection")
} else {
    check(false, "built csec binary is present at \(csecURL.path)")
}

// Cache invalidation over the socket: a rotation performed outside csecd (an
// `op` edit) leaves csecd's cached resolution stale; the launcher's invalidate
// verb must evict it so the next resolve returns the rotated value.
do {
    let cacheBackend = InMemoryKeychain()
    let cache = KeychainSecretCache(backend: cacheBackend)
    let rotResolver = SecretResolver(cache: cache)
    let uri = "op://rotate/item/field"
    await rotResolver.register(RotatingProvider(reference: uri, value: "AFTER"))
    // Seed the cache with the pre-rotation value, as an earlier resolve would.
    try await cache.put(uri, value: Data("BEFORE".utf8))
    check(await cacheBackend.has(uri), "precondition: the stale value is cached")

    let rotAgent = Agent(
        resolver: rotResolver,
        grants: GrantTable(),
        consent: ConsentCounter(),
        policyReview: CapturingAutoApprovePolicyReview(capture: AccessReviewCapture()),
        allowUnverifiedPlansForTesting: true,
        terminalInspection: .unavailable
    )
    let rotSocket = NSTemporaryDirectory() + "cs-e2e-invalidate-\(getpid()).sock"
    check(startInvalidatingServer(path: rotSocket, agent: rotAgent),
          "cache-invalidation server is listening")
    let rotClient = AgentClient(path: rotSocket, serverTrustPolicy: .allowUnverifiedForTesting)

    try rotClient.invalidateCachedReferences([uri])
    check(!(await cacheBackend.has(uri)),
          "invalidate over the socket evicts the cached entry")
    let fresh = try await rotResolver.resolve(try SecretRef(uri), unlock: CacheUnlock(LAContext()))
    check(fresh == Data("AFTER".utf8),
          "after socket invalidation the resolver serves the rotated value")
    unlink(rotSocket)
} catch {
    check(false, "socket cache invalidation threw: \(error)")
}

// `csec grants` / `csec revoke` over the real socket. Everything runs inside
// one registered session so the grant's root process is still alive while it
// is listed and revoked.
let grantsScript = "\"$1\" creds aws "
    + "--access-key-id-ref op://secure-delivery/aws/access-key-id "
    + "--secret-access-key-ref op://secure-delivery/aws/secret-access-key "
    + "--session-token-ref op://secure-delivery/aws/session-token --for 60 | /bin/cat >/dev/null; "
    + "\"$1\" creds aws "
    + "--access-key-id-ref op://secure-delivery/aws/access-key-id "
    + "--secret-access-key-ref op://secure-delivery/aws/secret-access-key "
    + "--session-token-ref op://secure-delivery/aws/session-token --for 60 | /bin/cat >/dev/null; "
    + "/usr/bin/printf 'LISTED\\n'; \"$1\" grants; "
    + "\"$1\" revoke --all; "
    + "/usr/bin/printf 'AFTER\\n'; \"$1\" grants; "
    + "\"$1\" creds aws "
    + "--access-key-id-ref op://secure-delivery/aws/access-key-id "
    + "--secret-access-key-ref op://secure-delivery/aws/secret-access-key "
    + "--session-token-ref op://secure-delivery/aws/session-token --for 60 | /bin/cat >/dev/null"
let consentBeforeGrantsCLI = await consent.calls()
let grantsCLI = runCsec(
    ["session", "--", "/bin/sh", "-c", grantsScript, "csec-grants-e2e", csecURL.path],
    extraEnv: [:]
)
let consentAfterGrantsCLI = await consent.calls()
let listedSection = grantsCLI.out
    .components(separatedBy: "LISTED\n").last?
    .components(separatedBy: "AFTER\n").first ?? ""
let afterSection = grantsCLI.out.components(separatedBy: "AFTER\n").last ?? ""
check(grantsCLI.status == 0
      && listedSection.contains("op://secure-delivery/aws/access-key-id")
      && listedSection.contains("root:")
      && listedSection.contains("expires:")
      && !grantsCLI.out.contains("aws-csec-synthetic-secret")
      && !grantsCLI.out.contains("aws-csec-synthetic-session"),
      "csec grants lists a live grant's references, root, and expiry but never a value")
check(grantsCLI.out.contains("csec: revoked ")
      && afterSection.contains("no live grants")
      && consentAfterGrantsCLI == consentBeforeGrantsCLI + 2,
      "csec revoke --all drops the live grant so the next access prompts again")

// `csec remote status --json` over the real socket (csec-0.93): the launcher
// prints csecd's readiness as one value-free object, an older csecd's silence
// as not_reported, and nothing at all when there is no csecd to ask.
let remoteDocumentKeys: Set<String> = [
    "schema", "state", "cause", "phoneConfirmed", "macProtocolVersion", "phoneProtocolVersion",
    "phoneStatusUpdatedAtMilliseconds", "phoneSettingsReviews",
]
func remoteDocument(_ text: String) -> [String: Any]? {
    let lines = text.split(separator: "\n")
    guard lines.count == 1 else { return nil }
    return (try? JSONSerialization.jsonObject(with: Data(lines[0].utf8))) as? [String: Any]
}
let olderRemote = runCsec(["remote", "status", "--json"], extraEnv: [:])
let olderDocument = remoteDocument(olderRemote.out)
check(olderRemote.status == 0 && olderDocument.map { Set($0.keys) } == remoteDocumentKeys
      && olderDocument?["phoneSettingsReviews"] as? String == "not_reported"
      && olderDocument?["macProtocolVersion"] is NSNull && olderDocument?["state"] as? String == "disabled"
      && olderDocument?["schema"] as? Int == 1,
      "csec remote status --json reads an older csecd's answer as not_reported, with what it did not say as null")
let phoneStatusAt: UInt64 = 1_790_000_000_000
// The protocol csecd says it speaks, from csecd's own wire derivation.
let macProtocol = RemoteApprovalConfigurationStatus(.disabled).macProtocolVersion ?? 0
check(macProtocol > 0, "csecd reports the remote-approval protocol it speaks")
await remoteStatusFixture.serve(RemoteApprovalConfigurationStatus(
    .enabled(phoneName: "Synthetic iPhone", phoneKeyFingerprint: "a1b2c3d4e5f60718"),
    health: RemoteApprovalPairingHealth(
        confirmed: true, phoneAppVersion: "9.9 (99)", notificationsAuthorized: true, requestAlerts: .ready,
        remoteUnlockEnrolled: true, phoneProtocolVersion: UInt16(macProtocol),
        phoneStatusUpdatedAtMilliseconds: phoneStatusAt, phoneShowsSettingsReviews: true
    )
))
let shownRemote = runCsec(["remote", "status", "--json"], extraEnv: [:])
let shownDocument = remoteDocument(shownRemote.out)
check(shownRemote.status == 0 && shownDocument.map { Set($0.keys) } == remoteDocumentKeys
      && shownDocument?["phoneSettingsReviews"] as? String == "shown" && shownDocument?["state"] as? String == "enabled"
      && shownDocument?["phoneConfirmed"] as? Bool == true && shownDocument?["cause"] is NSNull
      && shownDocument?["macProtocolVersion"] as? Int == macProtocol
      && shownDocument?["phoneProtocolVersion"] as? Int == macProtocol
      && (shownDocument?["phoneStatusUpdatedAtMilliseconds"] as? NSNumber)?.uint64Value == phoneStatusAt,
      "csec remote status --json says a confirmed phone on this protocol shows settings reviews")
check(!shownRemote.out.contains("Synthetic iPhone") && !shownRemote.out.contains("a1b2c3d4e5f60718")
      && !shownRemote.out.contains("9.9 (99)") && shownRemote.err.isEmpty,
      "csec remote status --json names no phone, key or app")
let shownText = runCsec(["remote", "status"], extraEnv: [:])
check(shownText.status == 0 && shownText.out.hasPrefix("csec: iPhone remote approval is on for Synthetic iPhone")
      && shownText.out.contains("reported that it shows Claude Code hook and rule acknowledgements"),
      "csec remote status keeps its text and says the acknowledgements reach the phone")
await remoteStatusFixture.serve(RemoteApprovalConfigurationStatus(.unsupportedBuild))
let unsupportedRemote = runCsec(["remote", "status", "--json"], extraEnv: [:])
let unsupportedDocument = remoteDocument(unsupportedRemote.out)
check(unsupportedRemote.status == 1 && unsupportedDocument?["state"] as? String == "unavailable"
      && unsupportedDocument?["cause"] as? String == "unsupported_build"
      && unsupportedDocument?["phoneSettingsReviews"] as? String == "no_phone_status",
      "csec remote status --json exits as the text command does for a build without the relay")
await remoteStatusFixture.serve(RemoteApprovalConfigurationStatus(state: .disabled))
for extra in [["status", "--json", "--json"], ["status", "--jsn"], ["status", "json"]] {
    let refused = runCsec(["remote"] + extra, extraEnv: [:])
    check(refused.status == 2 && remoteDocument(refused.out) == nil,
          "csec remote \(extra.joined(separator: " ")) is a usage error")
}
let noDaemon = runCsec(
    ["remote", "status", "--json"],
    extraEnv: ["CSEC_SOCKET": NSTemporaryDirectory() + "cs-e2e-absent-\(getpid()).sock"]
)
check(noDaemon.status == 1 && noDaemon.out.isEmpty && noDaemon.err.contains("csec remote:"),
      "csec remote status --json prints nothing on standard output when there is no csecd to ask")

// `csec log` over the real socket: the panels and the revocation just made are
// listed value-free, the grant reuse is in the usage stream, and the chain
// verifies clean.
let logJSON = runCsec(["log", "--json"], extraEnv: [:])
let logLines = logJSON.out.split(separator: "\n").compactMap {
    try? JSONDecoder().decode(DecisionLogRecord.self, from: Data($0.utf8))
}
check(logJSON.status == 0
      // The harness reviewer is no human surface, so the record does not
      // claim the Mac panel.
      && logLines.contains { $0.kind == .panel && $0.outcome == .approved && $0.decider == .human
          && ($0.refs ?? []).contains("op://secure-delivery/aws/access-key-id") }
      && logLines.contains { $0.kind == .revoke }
      && !logJSON.out.contains("aws-csec-synthetic-secret")
      && !logJSON.out.contains("aws-csec-synthetic-session"),
      "csec log --json lists the approved panels and the revocation, never a value")
let reuseLog = runCsec(["log", "--kind", "reuse", "--json"], extraEnv: [:])
let reuseLines = reuseLog.out.split(separator: "\n").compactMap {
    try? JSONDecoder().decode(DecisionLogRecord.self, from: Data($0.utf8))
}
check(reuseLog.status == 0
      && !reuseLines.isEmpty
      && reuseLines.allSatisfy { $0.kind == .reuse && $0.decider == .grant },
      "csec log --kind reuse lists grant reuses from the usage stream")
let logTable = runCsec(["log", "--since", "1h"], extraEnv: [:])
check(logTable.status == 0 && logTable.out.contains("panel") && logTable.out.contains("approved"),
      "csec log prints a readable line per record")
let logVerify = runCsec(["log", "--verify"], extraEnv: [:])
check(logVerify.status == 0 && logVerify.out.contains("decision log verified"),
      "csec log --verify reports a clean chain and exits 0")
let logBadKind = runCsec(["log", "--kind", "nonsense"], extraEnv: [:])
check(logBadKind.status == 2, "csec log rejects an unknown record kind")

let revokeUnknown = runCsec(["revoke", "deadbeef"], extraEnv: [:])
check(revokeUnknown.status == 1 && revokeUnknown.err.contains("no live grant matches"),
      "revoking an unknown grant id fails rather than silently succeeding")
let revokeEmptyAll = runCsec(["revoke", "--all"], extraEnv: [:])
check(revokeEmptyAll.status == 0,
      "revoke --all is idempotent when nothing is left to revoke")
let revokeUsage = runCsec(["revoke"], extraEnv: [:])
check(revokeUsage.status != 0,
      "csec revoke requires either a grant id or --all")

// --- A wedged daemon must fail fast; `csec ai` must still run the command.
//
// SIGSTOP a real agent process. Its listening socket survives (the kernel still
// completes connections into the accept backlog), but it never executes another
// line of its request loop — the closest reachable stand-in for a deadlocked
// main actor or an actor that never resumes. Before csec-1xv.8 a client blocked
// in read() until the user pressed Ctrl-C.
//
// The shortened deadline is a debug-only knob (CSEC_LIVENESS_DEADLINE_SECONDS,
// compiled out of release exactly like CSEC_SOCKET) and is passed only to these
// child processes; the shipping default is 20 s of silence.
let wedgeBase = "/tmp/csec-e2e-wedge-\(UUID().uuidString.prefix(8))"
let wedgeSocket = wedgeBase + "/agent.sock"
let fakeAgentURL = selfURL.deletingLastPathComponent().appendingPathComponent("cs-fake-agent")
do {
    try FileManager.default.createDirectory(
        atPath: wedgeBase, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
} catch {
    check(false, "wedged agent: temp dir setup threw (\(error))")
}
let wedgedAgent = Process()
wedgedAgent.executableURL = fakeAgentURL
var wedgedEnvironment = ProcessInfo.processInfo.environment
wedgedEnvironment["CSEC_SOCKET"] = wedgeSocket
wedgedAgent.environment = wedgedEnvironment
wedgedAgent.standardInput = FileHandle.nullDevice
wedgedAgent.standardOutput = FileHandle.nullDevice
wedgedAgent.standardError = FileHandle.nullDevice
try? wedgedAgent.run()
var wedgeWaited = 0
while !FileManager.default.fileExists(atPath: wedgeSocket) && wedgeWaited < 250 {
    usleep(20_000)
    wedgeWaited += 1
}
let wedgeEnvironment = [
    "CSEC_SOCKET": wedgeSocket,
    "CSEC_LIVENESS_DEADLINE_SECONDS": "2",
]
let liveGrants = runCsec(["grants"], extraEnv: wedgeEnvironment)
check(wedgedAgent.isRunning && liveGrants.status == 0,
      "a running agent answers before it is wedged")

kill(wedgedAgent.processIdentifier, SIGSTOP)
let wedgeStarted = Date()
let wedgedGrants = runCsec(["grants"], extraEnv: wedgeEnvironment)
let wedgeElapsed = Date().timeIntervalSince(wedgeStarted)
check(wedgedGrants.status != 0
      && wedgedGrants.err.contains("stopped responding")
      && wedgedGrants.err.contains("csec doctor"),
      "a wedged agent fails the command naming the wedge and `csec doctor`")
check(wedgeElapsed < 20,
      "the wedged-agent failure arrives on the deadline instead of hanging")

// `csec ai` never hard-gates: it warns, names the fix, and runs the command
// with the reference left unresolved so nothing is injected or revealed.
let wedgedAI = runCsec(
    ["ai", "--", "printf %s \"$CSEC_E2E_WEDGE_REF\""],
    extraEnv: wedgeEnvironment.merging(
        ["CSEC_E2E_WEDGE_REF": "op://demo/db/url"], uniquingKeysWith: { _, new in new })
)
check(wedgedAI.status == 0
      && wedgedAI.out.contains("op://demo/db/url")
      && wedgedAI.err.contains("stopped responding")
      && wedgedAI.err.contains("csec doctor")
      && wedgedAI.err.contains("WITHOUT csec"),
      "csec ai degrades on a wedged agent: warns, names the fix, leaves the reference unresolved")

kill(wedgedAgent.processIdentifier, SIGCONT)
let recoveredGrants = runCsec(["grants"], extraEnv: wedgeEnvironment)
check(recoveredGrants.status == 0,
      "the next command succeeds once the agent is running again")
if wedgedAgent.isRunning {
    wedgedAgent.terminate()
    wedgedAgent.waitUntilExit()
}

// The converse: an agent that is slow but alive keeps the client waiting on
// heartbeats instead of being taken for a wedge. Each tick hops through the
// agent's main actor, so this fails if the fake agent's main thread is busy
// in its accept loop.
let slowSocket = wedgeBase + "/slow.sock"
let slowEnvironment = [
    "CSEC_SOCKET": slowSocket,
    "CSEC_LIVENESS_DEADLINE_SECONDS": "1",
]
let slowAgent = Process()
slowAgent.executableURL = fakeAgentURL
slowAgent.environment = ProcessInfo.processInfo.environment
    .merging(slowEnvironment, uniquingKeysWith: { _, new in new })
    .merging(["CSEC_FAKE_RESPONSE_DELAY_SECONDS": "2"], uniquingKeysWith: { _, new in new })
slowAgent.standardInput = FileHandle.nullDevice
slowAgent.standardOutput = FileHandle.nullDevice
slowAgent.standardError = FileHandle.nullDevice
try? slowAgent.run()
var slowWaited = 0
while !FileManager.default.fileExists(atPath: slowSocket) && slowWaited < 250 {
    usleep(20_000)
    slowWaited += 1
}
let slowStarted = Date()
let slowGrants = runCsec(["grants"], extraEnv: slowEnvironment)
let slowElapsed = Date().timeIntervalSince(slowStarted)
check(slowAgent.isRunning && slowGrants.status == 0 && slowElapsed >= 2,
      "a slow but live agent answers past the silence deadline instead of failing as wedged")
if slowAgent.isRunning {
    slowAgent.terminate()
    slowAgent.waitUntilExit()
}
try? FileManager.default.removeItem(atPath: wedgeBase)

// --- csecd stops while `csec ai` runs a command (an update restarts it).
//
// The scanner lives in csecd, so its matcher dies with it. A command csecd
// released nothing to runs on with the rest of its output withheld and exits
// with its own status; a command holding delivered values is stopped. Either
// way nothing unscanned is forwarded, including the tail of a secret whose
// start the old scanner was still holding back. Each scenario kills a
// `cs-fake-agent` mid-command and starts a new one on the same socket.
let restartBase = "/tmp/csec-e2e-restart-\(UUID().uuidString.prefix(8))"
let restartSocket = restartBase + "/agent.sock"
let restartEnvironment = ["CSEC_SOCKET": restartSocket]
do {
    try FileManager.default.createDirectory(
        atPath: restartBase, withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700])
} catch {
    check(false, "csecd restart: temp dir setup threw (\(error))")
}

func startRestartAgent() -> Process? {
    let agent = Process()
    agent.executableURL = fakeAgentURL
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = restartSocket
    agent.environment = environment
    agent.standardInput = FileHandle.nullDevice
    agent.standardOutput = FileHandle.nullDevice
    agent.standardError = FileHandle.nullDevice
    guard (try? agent.run()) != nil else { return nil }
    // Ready once it answers: a socket file a killed agent left behind does
    // not count.
    for _ in 0..<250 {
        if runCsec(["grants"], extraEnv: restartEnvironment).status == 0 { return agent }
        usleep(20_000)
    }
    agent.terminate()
    return nil
}

/// Run `csec ai -- program` against a running fake agent; once the program
/// creates `READY`, kill that agent, start another, and create `GO`. A live
/// notice check keeps the child behind `GO.finish` until stderr is observed.
func runAIAcrossRestart(
    _ program: (_ ready: String, _ go: String, _ done: String) -> String,
    extraEnv: [String: String] = [:],
    verb: String = "ai",
    waitForWithholdingNotice: Bool = false,
    seed: (() -> Void)? = nil
) -> (status: Int32, out: String, err: String, finished: Bool, noticedWhileRunning: Bool)? {
    guard let first = startRestartAgent() else {
        check(false, "csecd restart: the first fake agent starts")
        return nil
    }
    seed?()
    let marker = restartBase + "/\(UUID().uuidString.prefix(8))"
    let ready = marker + ".ready", go = marker + ".go", done = marker + ".done"
    let ai = Process()
    ai.executableURL = csecURL
    ai.arguments = [verb, "--", program(ready, go, done)]
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = restartSocket
    for (key, value) in extraEnv { environment[key] = value }
    ai.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    ai.standardOutput = outPipe
    ai.standardError = errPipe
    guard (try? ai.run()) != nil else {
        first.terminate()
        check(false, "csecd restart: csec ai starts")
        return nil
    }
    var waited = 0
    while !FileManager.default.fileExists(atPath: ready) && waited < 1_000 {
        usleep(20_000)
        waited += 1
    }
    kill(first.processIdentifier, SIGKILL)
    first.waitUntilExit()
    let second = startRestartAgent()
    FileManager.default.createFile(atPath: go, contents: Data())
    var err = Data()
    var noticedWhileRunning = false
    if waitForWithholdingNotice {
        let notice = "output is now being withheld unscanned"
        let deadline = ProcessInfo.processInfo.systemUptime + 10
        while ai.isRunning && ProcessInfo.processInfo.systemUptime < deadline {
            var descriptor = pollfd(
                fd: errPipe.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0
            )
            guard poll(&descriptor, 1, 100) > 0 else { continue }
            let chunk = errPipe.fileHandleForReading.availableData
            if chunk.isEmpty { break }
            err.append(chunk)
            if String(decoding: err, as: UTF8.self).contains(notice) {
                noticedWhileRunning = ai.isRunning && !FileManager.default.fileExists(atPath: done)
                break
            }
        }
        FileManager.default.createFile(atPath: go + ".finish", contents: Data())
    }
    let out = outPipe.fileHandleForReading.readDataToEndOfFile()
    err.append(errPipe.fileHandleForReading.readDataToEndOfFile())
    ai.waitUntilExit()
    second?.terminate()
    second?.waitUntilExit()
    return (
        ai.terminationStatus,
        String(decoding: out, as: UTF8.self),
        String(decoding: err, as: UTF8.self),
        FileManager.default.fileExists(atPath: done),
        noticedWhileRunning
    )
}

for verb in ["ai", "tool-exec"] {
    if let withheld = runAIAcrossRestart({ ready, go, done in
        "printf 'before\\n'; /usr/bin/touch \(ready); while [ ! -e \(go) ]; do sleep 0.05; done; "
            + "printf 'after\\n'; printf 'after-stderr\\n' >&2; "
            + "while [ ! -e \(go).finish ]; do sleep 0.05; done; /usr/bin/touch \(done); exit 7"
    }, verb: verb, waitForWithholdingNotice: true) {
        check(withheld.noticedWhileRunning,
              "csecd restart: \(verb) explains withholding on stderr before the child can exit")
        check(withheld.err.components(separatedBy: "output is now being withheld unscanned").count == 2,
              "csecd restart: \(verb) emits the in-flight notice exactly once across both streams")
        check(withheld.status == 7 && withheld.finished,
              "csecd restart: a command csecd released nothing to runs to the end and exits with its own status "
                  + "(status \(withheld.status))")
        check(withheld.out == "before\n" && !withheld.err.contains("after-stderr"),
              "csecd restart: stdout and stderr after csecd stopped stay withheld")
        check(withheld.err.contains("csec \(verb): csecd stopped while this command ran")
                && withheld.err.contains("was withheld unscanned (19 bytes)")
                && withheld.err.contains("The exit status is the command's own.")
                && !withheld.err.contains("trusted output scanning failed"),
              "csecd restart: csec \(verb) keeps the final withheld-byte summary and exit-status notice")
    }
}

if let stopped = runAIAcrossRestart({ ready, go, done in
    "/usr/bin/touch \(ready); while [ ! -e \(go) ]; do sleep 0.05; done; "
        + "printf '%s\\n' \"$CSEC_E2E_RESTART_REF\"; sleep 2; /usr/bin/touch \(done)"
}, extraEnv: ["CSEC_E2E_RESTART_REF": "op://demo/db/url"]) {
    check(stopped.status == 1 && !stopped.finished,
          "csecd restart: a command holding a value csecd delivered is terminated (status \(stopped.status))")
    check(!stopped.out.contains("postgres://s3cr3t") && !stopped.err.contains("postgres://s3cr3t"),
          "csecd restart: the delivered value never reaches the output")
    check(stopped.err.contains("csecd stopped while this command held values it had delivered"),
          "csecd restart: the termination names csecd stopping (err \"\(stopped.err)\")")
    check(!stopped.err.contains("output is now being withheld unscanned"),
          "csecd restart: a terminated command does not claim to be waiting for completion")
}

if let split = runAIAcrossRestart({ ready, go, done in
    "printf %s 'postgres:/'; /usr/bin/touch \(ready); while [ ! -e \(go) ]; do sleep 0.05; done; "
        + "printf '%s\\n' '/s3cr3t'; /usr/bin/touch \(done)"
}, seed: {
    let released = runCsec(
        ["exec", "--set", "CSEC_E2E_SEEDED=op://demo/db/url", "--", "/usr/bin/true"],
        extraEnv: restartEnvironment
    )
    check(released.status == 0, "csecd restart: the first agent releases the value the split command prints")
}) {
    check(split.status == 0 && split.finished
            && !split.out.contains("postgres") && !split.out.contains("s3cr3t"),
          "csecd restart: neither the held-back start of a released value nor its tail is forwarded "
              + "(out \"\(split.out)\")")
}

// --- csecd restarts while an unattended automation daemon runs.
//
// A Python daemon in a real virtual environment (its `bin/python` a symlink,
// which Python resolves its environment from) runs under `csec automation
// run`, fetches through the real bridge, and keeps running while the fake
// agent is killed and another starts over the same state. The restarted agent
// restores the run lease, so the daemon's next fetch is served as automation
// (this fake refuses every attended review), and the launcher reopens its
// scanner there, so a value the daemon prints is still redacted. When the
// restarted agent holds no lease for the run, the launcher stops the daemon
// rather than scan its output with an agent that does not know its values.
func startAutomationAgent(state: String, requireValidSignature: Bool) -> Process? {
    let agent = Process()
    agent.executableURL = fakeAgentURL
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = restartSocket
    environment["CSEC_FAKE_AUTOMATION_STATE"] = state
    if requireValidSignature { environment["CSEC_FAKE_REQUIRE_VALID_SIGNATURE"] = "1" }
    agent.environment = environment
    agent.standardInput = FileHandle.nullDevice
    agent.standardOutput = FileHandle.nullDevice
    agent.standardError = FileHandle.nullDevice
    guard (try? agent.run()) != nil else { return nil }
    for _ in 0..<250 {
        if runCsec(["grants"], extraEnv: restartEnvironment).status == 0 { return agent }
        usleep(20_000)
    }
    agent.terminate()
    return nil
}

/// A real, non-framework Python to build the virtual environment from: a
/// framework build re-executes itself from inside its `.app`, so the process
/// csec sees is never the interpreter the job enrolled. `CSEC_E2E_PYTHON` if
/// set, else `python3` on PATH, else the first Python mise, uv or pyenv
/// installed.
func automationBasePython() -> String? {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    var candidates: [[String]] = []
    if let chosen = ProcessInfo.processInfo.environment["CSEC_E2E_PYTHON"] { candidates.append([chosen]) }
    candidates.append(["/usr/bin/env", "python3"])
    for root in [".local/share/mise/installs/python", ".local/share/uv/python", ".pyenv/versions"] {
        let directory = home + "/" + root
        for version in ((try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? []).sorted() {
            let python = directory + "/" + version + "/bin/python3"
            if FileManager.default.isExecutableFile(atPath: python) { candidates.append([python]) }
        }
    }
    for candidate in candidates {
        let probe = Process()
        probe.executableURL = URL(fileURLWithPath: candidate[0])
        probe.arguments = Array(candidate.dropFirst())
            + ["-c", "import os, sys; print(os.path.realpath(sys._base_executable))"]
        let out = Pipe()
        probe.standardOutput = out
        probe.standardError = FileHandle.nullDevice
        guard (try? probe.run()) != nil else { continue }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        probe.waitUntilExit()
        let path = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        if probe.terminationStatus == 0, path.hasPrefix("/"), !path.contains(".framework/") { return path }
    }
    return nil
}

/// How one automation-restart scenario varies.
/// What a running launcher has forwarded so far, read on its own thread as it
/// arrives, so a case can wait for a line to have come through the scanner.
final class ForwardedOutput: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes = Data()
    private let closed = DispatchSemaphore(value: 0)

    init(_ handle: FileHandle) {
        Thread.detachNewThread { [self] in
            while true {
                let chunk = handle.availableData
                if chunk.isEmpty { break }
                lock.withLock { bytes.append(chunk) }
            }
            closed.signal()
        }
    }

    var text: String { lock.withLock { String(decoding: bytes, as: UTF8.self) } }

    /// Everything, once the launcher has closed its end.
    func untilClosed() -> String {
        closed.wait()
        return text
    }
}

struct AutomationRestartCase {
    var name: String
    /// Override to exercise a framework-backed venv as well as the ordinary
    /// non-framework runtime used by the restart regressions.
    var basePython: String? = nil
    /// The second fake agent starts over the first one's state (its leases).
    var keepState = true
    /// Both fake agents turn away a peer whose binary changed, as csecd does.
    var requireValidSignature = false
    /// The launcher runs from its own copy, which is replaced while the
    /// fake agent is down, as an update replaces `csec`.
    var replaceLauncher = false
    /// The daemon prints its value in two halves, one each side of the restart.
    var splitValue = false
    /// After the restart the daemon prints nothing and fetches nothing for a
    /// while, as a daemon waiting on its next job does.
    var quietAfterRestart = false
}

func runAutomationDaemonAcrossRestart(
    _ scenario: AutomationRestartCase
) -> (status: Int32, out: String, err: String, finished: Bool)? {
    guard let basePython = scenario.basePython ?? automationBasePython() else {
        check(false, "automation restart: a non-framework Python (CSEC_E2E_PYTHON, PATH, mise, uv or pyenv) builds the venv")
        return nil
    }
    let name = scenario.name
    let base = restartBase + "/\(name)"
    let firstState = base + "/state-a"
    let secondState = scenario.keepState ? firstState : base + "/state-b"
    let venv = base + "/venv"
    for directory in [firstState, secondState] {
        try? FileManager.default.createDirectory(
            atPath: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
    let makeVenv = Process()
    makeVenv.executableURL = URL(fileURLWithPath: basePython)
    makeVenv.arguments = ["-m", "venv", "--without-pip", venv]
    guard (try? makeVenv.run()) != nil else {
        check(false, "automation restart: the virtual environment is created")
        return nil
    }
    makeVenv.waitUntilExit()
    let venvPython = venv + "/bin/python"
    guard makeVenv.terminationStatus == 0,
          (try? FileManager.default.destinationOfSymbolicLink(atPath: venvPython)) != nil else {
        check(false, "automation restart: the venv's bin/python is a symlink")
        return nil
    }
    var launcherURL = csecURL
    if scenario.replaceLauncher {
        launcherURL = URL(fileURLWithPath: base + "/csec")
        guard (try? FileManager.default.copyItem(at: csecURL, to: launcherURL)) != nil else {
            check(false, "automation restart: the launcher is copied")
            return nil
        }
    }
    let ready = base + "/ready", go = base + "/go", done = base + "/done"
    let script = base + "/daemon.py"
    let source = """
    import json, os, struct, subprocess, sys, time
    bridge, sock, ready, go, done, mode = sys.argv[1:7]
    ref = "op://demo/db/url"
    def access():
        payload = json.dumps({"version": 1, "references": [ref],
                              "reason": "Synthetic venv daemon e2e"}).encode()
        p = subprocess.run([bridge, "bridge"], input=struct.pack(">I", len(payload)) + payload,
                           capture_output=True, env={"PATH": "/usr/bin:/bin", "CSEC_SOCKET": sock})
        if len(p.stdout) < 4:
            return None
        (n,) = struct.unpack(">I", p.stdout[:4])
        return (json.loads(p.stdout[4:4 + n]).get("values") or {}).get(ref)
    print("venv-ok" if sys.prefix != sys.base_prefix else "venv-missing", flush=True)
    first = access()
    print("first-ok" if first == "postgres://s3cr3t" else "first-failed", flush=True)
    if mode == "split":
        sys.stdout.write((first or "")[:10])
        sys.stdout.flush()
        time.sleep(0.5)
    open(ready, "w").close()
    while not os.path.exists(go):
        time.sleep(0.05)
    if mode == "quiet":
        time.sleep(20)
        open(done, "w").close()
        sys.exit(0)
    if mode == "split":
        sys.stdout.write((first or "")[10:] + "\\n")
        sys.stdout.flush()
        print("after-split", flush=True)
    else:
        second = access()
        print("after-ok" if second == "postgres://s3cr3t" else "after-failed", flush=True)
        print("value: " + (second or ""), flush=True)
    time.sleep(2)
    open(done, "w").close()
    """
    guard (try? Data(source.utf8).write(to: URL(fileURLWithPath: script))) != nil,
          let first = startAutomationAgent(state: firstState, requireValidSignature: scenario.requireValidSignature)
    else {
        check(false, "automation restart: the script is written and the first fake agent starts")
        return nil
    }
    let enrolled = runCsec([
        "automation", "add", name,
        "--ref", "op://demo/db/url",
        "--reason", "Synthetic venv daemon e2e",
        "--max-runtime", "none",
        "--cwd", base,
        "--", venvPython, script, csecURL.path, restartSocket, ready, go, done,
        scenario.splitValue ? "split" : scenario.quietAfterRestart ? "quiet" : "fetch",
    ], extraEnv: restartEnvironment)
    check(enrolled.status == 0,
          "automation restart: the venv daemon enrolls (status \(enrolled.status), err \(enrolled.err.debugDescription))")
    let listed = runCsec(["automation", "list"], extraEnv: restartEnvironment)
    check(listed.out.contains("command: \(venvPython) \(script)"),
          "automation restart: the job keeps the venv's bin/python as argv[0] (\(listed.out.debugDescription))")

    let run = Process()
    run.executableURL = launcherURL
    run.arguments = ["automation", "run", name]
    var environment = ProcessInfo.processInfo.environment
    environment["CSEC_SOCKET"] = restartSocket
    run.environment = environment
    let outPipe = Pipe(), errPipe = Pipe()
    run.standardOutput = outPipe
    run.standardError = errPipe
    guard (try? run.run()) != nil else {
        first.terminate()
        check(false, "automation restart: csec automation run starts")
        return nil
    }
    let forwarded = ForwardedOutput(outPipe.fileHandleForReading)
    // The agent goes away once the daemon's first fetch has been reported
    // through the launcher, not merely written: until the launcher has read
    // and scanned it, the line is held, and a launcher the restarted agent
    // turns away never forwards what it holds unscanned. On a loaded Mac
    // that would lose the line by timing alone.
    var waited = 0
    while !(FileManager.default.fileExists(atPath: ready)
                && (forwarded.text.contains("first-ok\n") || forwarded.text.contains("first-failed\n")))
            && waited < 1_500 {
        usleep(20_000)
        waited += 1
    }
    kill(first.processIdentifier, SIGKILL)
    first.waitUntilExit()
    if scenario.replaceLauncher {
        // An update renames a new binary over the old one; the running
        // launcher keeps the old image, which no longer matches the file.
        let replacement = base + "/csec.new"
        try? FileManager.default.copyItem(at: fakeAgentURL, to: URL(fileURLWithPath: replacement))
        _ = rename(replacement, launcherURL.path)
    }
    let second = startAutomationAgent(state: secondState, requireValidSignature: scenario.requireValidSignature)
    check(second != nil, "automation restart: the second fake agent starts")
    FileManager.default.createFile(atPath: go, contents: Data())
    let err = errPipe.fileHandleForReading.readDataToEndOfFile()
    let out = forwarded.untilClosed()
    run.waitUntilExit()
    second?.terminate()
    second?.waitUntilExit()
    return (
        run.terminationStatus,
        out,
        String(decoding: err, as: UTF8.self),
        FileManager.default.fileExists(atPath: done)
    )
}

if let survived = runAutomationDaemonAcrossRestart(
    AutomationRestartCase(name: "venv-daemon", requireValidSignature: true)
) {
    check(survived.status == 0 && survived.finished,
          "automation restart: the daemon outlives the restart and exits with its own status "
              + "(status \(survived.status), err \(survived.err.debugDescription))")
    check(survived.out.contains("venv-ok\n"),
          "automation restart: Python finds its virtual environment from argv[0] (out \(survived.out.debugDescription))")
    check(survived.out.contains("first-ok\n") && survived.out.contains("after-ok\n"),
          "automation restart: the restarted agent serves the daemon's fetch as automation, with no panel, "
              + "and no output is lost (out \(survived.out.debugDescription))")
    check(survived.out.contains("value: [redacted: op://demo/db/url]")
            && !survived.out.contains("s3cr3t") && !survived.err.contains("s3cr3t"),
          "automation restart: the reopened scanner still redacts the daemon's value (out \(survived.out.debugDescription))")
    check(survived.err.contains("csecd went away while venv-daemon ran; holding its output until csecd is back\n")
            && survived.err.contains("csecd restarted while venv-daemon ran; scanning resumed\n"),
          "automation restart: the launcher says it resumed scanning, with nothing withheld "
              + "(err \(survived.err.debugDescription))")
}

if let split = runAutomationDaemonAcrossRestart(
    AutomationRestartCase(name: "venv-daemon-split", splitValue: true)
) {
    check(split.status == 0 && split.finished,
          "automation restart: the split-value daemon runs to the end (status \(split.status), err \(split.err.debugDescription))")
    check(split.out.contains("[redacted: op://demo/db/url]\n") && split.out.contains("after-split\n")
            && !split.out.contains("postgres") && !split.out.contains("s3cr3t"),
          "automation restart: a value printed half before and half after the restart is redacted whole "
              + "(out \(split.out.debugDescription))")
}

if let replaced = runAutomationDaemonAcrossRestart(
    AutomationRestartCase(name: "venv-daemon-updated", requireValidSignature: true, replaceLauncher: true)
) {
    check(replaced.status != 0 && !replaced.finished,
          "automation restart: a launcher whose binary an update replaced stops its daemon "
              + "(status \(replaced.status), err \(replaced.err.debugDescription))")
    check(replaced.err.contains("csec was updated while this job ran"),
          "automation restart: the launcher says the update is why (err \(replaced.err.debugDescription))")
    // The old scanner can still hold the pre-update tail when the launcher
    // stops. It must not flush that tail through an unscanned channel merely
    // to make this test observe a marker. Only a prefix of pre-update output
    // is allowed; the stopped-daemon and no-post-update checks stay strict.
    check("venv-ok\nfirst-ok\n".hasPrefix(replaced.out) && !replaced.out.contains("after-")
            && !replaced.out.contains("s3cr3t") && !replaced.err.contains("s3cr3t"),
          "automation restart: nothing the daemon writes after the update is forwarded unscanned "
              + "(out \(replaced.out.debugDescription))")
}

if let stopped = runAutomationDaemonAcrossRestart(
    AutomationRestartCase(name: "venv-daemon-lost", keepState: false)
) {
    check(stopped.status != 0 && !stopped.finished,
          "automation restart: a restarted agent without the run's lease stops the daemon "
              + "(status \(stopped.status), err \(stopped.err.debugDescription))")
    check(stopped.err.contains("holds no live lease for this run; command terminated"),
          "automation restart: the launcher says why it stopped the daemon (err \(stopped.err.debugDescription))")
    check(stopped.out.contains("first-ok\n") && !stopped.out.contains("after-")
            && !stopped.out.contains("s3cr3t") && !stopped.err.contains("s3cr3t"),
          "automation restart: nothing it writes after the restart is forwarded unscanned "
              + "(out \(stopped.out.debugDescription))")
}
// A quiet daemon learns of the restart from the launcher's clock, not from
// its next output: without that, it would run on unscanned under a lease the
// restarted agent does not hold, or under a replaced csec, until it printed.
if let quietLost = runAutomationDaemonAcrossRestart(
    AutomationRestartCase(name: "venv-daemon-quiet-lost", keepState: false, quietAfterRestart: true)
) {
    check(quietLost.status != 0 && !quietLost.finished
            && quietLost.err.contains("holds no live lease for this run; command terminated"),
          "automation restart: a quiet daemon is stopped when the restarted agent lacks its lease, "
              + "without waiting for it to print (status \(quietLost.status), err \(quietLost.err.debugDescription))")
}
if let quietUpdated = runAutomationDaemonAcrossRestart(
    AutomationRestartCase(
        name: "venv-daemon-quiet-updated", requireValidSignature: true, replaceLauncher: true,
        quietAfterRestart: true
    )
) {
    check(quietUpdated.status != 0 && !quietUpdated.finished
            && quietUpdated.err.contains("csec was updated while this job ran"),
          "automation restart: a quiet daemon is stopped once an update replaced csec, "
              + "without waiting for it to print (status \(quietUpdated.status), err \(quietUpdated.err.debugDescription))")
}
await frameworkPythonAutomationTests()
try? FileManager.default.removeItem(atPath: restartBase)

unlink(socketPath)
unlink(sshSocketPath)
if fakeRoot.isRunning {
    fakeRoot.terminate()
    fakeRoot.waitUntilExit()
}
try? FileManager.default.removeItem(atPath: rootFixtureDirectory)
_ = FileManager.default.changeCurrentDirectoryPath(NSTemporaryDirectory())
try? FileManager.default.removeItem(atPath: e2eWorkingDirectory)

// claude-delegation: a real Claude Code against a delegation service. It needs
// a logged-in Claude Code and makes model calls, so it runs only when asked
// for.
if ProcessInfo.processInfo.environment["CSEC_E2E_CLAUDE"] == "1" {
    await claudeDelegationE2E()
}

if failures == 0 {
    print("\nAll end-to-end checks passed.")
    exit(0)
} else {
    FileHandle.standardError.write(Data("\n\(failures) check(s) failed.\n".utf8))
    exit(1)
}

// MARK: - claude-delegation (opt-in: CSEC_E2E_CLAUDE=1)

/// A reference only this scenario's provider serves, held unlocked, as a
/// value a human approved earlier in the session would be.
actor ClaudeDelegationE2EProvider: SecretProvider {
    nonisolated let schemes: Set<String> = ["csec-e2e-claude"]

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        ResolvedSecret(value: Data("synthetic-claude-delegation-value".utf8), cacheHint: .noCache)
    }

    func resolveWithoutInteraction(_ ref: SecretRef) async -> ResolvedSecret? {
        ResolvedSecret(value: Data("synthetic-claude-delegation-value".utf8), cacheHint: .noCache)
    }

    nonisolated func authenticate() async throws {}
    nonisolated func isAvailable() async -> Bool { true }
}

/// The e2e runs judge synthetic sessions, so the stored-sign-in gate sees a
/// fixed signed-out store rather than this Mac's own Claude Code sign-ins,
/// which would make the result depend on the host.
struct SignedOutClaudeCredentials: ClaudeCredentialStore {
    func gatewaySignIn(plaintextPath: String) -> ClaudeGatewaySignIn.Finding { .notSignedIn }
}

struct ClaudeDelegationE2EConsent: ConsentProvider {
    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome { .denied }
    func authenticate(reason: String) async -> ConsentOutcome { .denied }
}

/// Waits for a record the delegation path writes: a `delegated_release` in
/// usage, or a `decline` with a given reason in decisions.
func waitForDelegationRecord(
    _ log: DecisionLog, kind: DecisionLogRecord.Kind, within seconds: Double,
    matching predicate: @escaping (DecisionLogRecord) -> Bool
) async -> Bool {
    let deadline = Date().addingTimeInterval(seconds)
    while Date() < deadline {
        let page = await log.read(DecisionLogQuery(streams: [kind.stream], kinds: [kind]))
        if page.records.contains(where: predicate) { return true }
        try? await Task.sleep(nanoseconds: 500_000_000)
    }
    return false
}

/// Every decline reason the scenario's log holds so far, as `code: text`, so a
/// check that waited in vain says what was decided instead.
func recordedDeclines(_ log: DecisionLog) async -> String {
    let page = await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.decline]))
    let reasons = page.records.map { "\($0.delegation?.reason ?? "?"): \($0.detail ?? "")" }
    return reasons.isEmpty ? "none" : reasons.joined(separator: " | ")
}

/// The on-device delegation check (plumbing §7.2), against a real Claude Code
/// in a scratch `CLAUDE_CONFIG_DIR` whose settings hold this build's `csec
/// hook claude`, `autoMode.classifyAllShell` and auto mode by default:
///
/// - `claude -p` (headless, fd 0 not a terminal, `-p` on the G4 list) runs a
///   command that uses a paired reference: csecd declines `.notInteractive`.
/// - An interactive `claude --permission-mode auto` in a pty (the foreground
///   job of its own terminal) runs the same kind of command: delegated, no
///   panel, a `delegated_release` in the log. Then Shift+Tab leaves auto mode
///   and the next command declines `.notAutoMode`.
///
/// The agent here is csecd's shape: `register_agent_command` goes straight to
/// the delegation service, over in-memory protected stores with delegation on
/// and the scratch project paired with the reference; the settings gate is the
/// shipping one; any panel is refused. Every reason is read from this agent's
/// own decision log.
///
/// What it takes to reach this in-process agent rather than an installed one:
/// - The hook is this build's `csec` by absolute path, and this build's
///   directory leads the session's `PATH`: the rewritten command names `csec`
///   bare, and Claude Code's shell exports the session's own `PATH`. Only a
///   debug `csec` honours `CSEC_SOCKET`; the installed one would ask the
///   installed csecd, which knows nothing of the scenario's reference, and
///   the command would run secret-free with nothing recorded here.
/// - Claude Code keys its login on `CLAUDE_CONFIG_DIR`; an empty
///   `CLAUDE_SECURESTORAGE_CONFIG_DIR` makes the scratch session use the
///   user's own login (its default Keychain entry, which may ask once for
///   Keychain access). `ANTHROPIC_API_KEY` and `ANTHROPIC_AUTH_TOKEN` are not
///   passed: an interactive session asks whether to use a key, with "No"
///   focused, and the harness does not read a credential to pre-approve it.
///   `CLAUDE_CODE_OAUTH_TOKEN` is passed for a login made that way.
/// - Nothing that marks a nested or child session reaches it (`CLAUDECODE`,
///   `CLAUDE_CODE_*`, `CLAUDE_PID`, …), so it may run from a terminal or
///   inside a Claude Code session.
/// - The scratch settings accept the auto-mode opt-in, and after Shift+Tab
///   the default-mode "Do you want to proceed?" dialog is answered Yes, read
///   off the session's screen, so the `csec ai` runs and can be declined.
/// A step that cannot start prints the end of the session's screen and ends
/// the scenario rather than waiting out every later timeout. The model must
/// choose to run the command it is asked to run.
func claudeDelegationE2E() async {
    print("\n# claude-delegation (opt-in)")
    let environment = ProcessInfo.processInfo.environment
    let claudePath = environment["CSEC_E2E_CLAUDE_PATH"] ?? (NSHomeDirectory() + "/.local/bin/claude")
    guard FileManager.default.isExecutableFile(atPath: claudePath) else {
        check(false, "claude-delegation: Claude Code is at \(claudePath) (set CSEC_E2E_CLAUDE_PATH)")
        return
    }
    // The build's own csec, as the kernel names it: the settings gate
    // recognises csec's hook only byte for byte against the launcher that
    // asks, whose path is the resolved one.
    let debugCsec = csecURL.resolvingSymlinksInPath()
    let scratch = NSTemporaryDirectory() + "csec-e2e-claude-\(getpid())"
    try? FileManager.default.createDirectory(atPath: scratch + "/config", withIntermediateDirectories: true)
    try? FileManager.default.createDirectory(atPath: scratch + "/project", withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: scratch) }
    guard let base = realpath(scratch, nil).map({ pointer -> String in
        defer { free(pointer) }
        return String(cString: pointer)
    }) else {
        check(false, "claude-delegation: the scratch directory resolves")
        return
    }
    let configDirectory = base + "/config"
    let projectDirectory = base + "/project"

    // Claude Code's settings: this build's hook, classifyAllShell, auto mode,
    // and the auto-mode opt-in already accepted (2.1.280 reads
    // `skipAutoPermissionPrompt` as "the user has accepted the auto mode
    // opt-in dialog"; the global flag stops a migration clearing it).
    guard let hook = try? AICommandHook.hookConfiguration(client: .claude, csecExecutablePath: debugCsec.path),
          var settings = (try? JSONSerialization.jsonObject(with: hook)) as? [String: Any] else {
        check(false, "claude-delegation: csec's Claude Code hook configuration builds")
        return
    }
    settings["autoMode"] = ["classifyAllShell": true]
    settings["permissions"] = ["defaultMode": "auto"]
    settings["skipAutoPermissionPrompt"] = true
    let global: [String: Any] = [
        "hasCompletedOnboarding": true,
        "hasResetAutoModeOptInForDefaultOffer": true,
        "hasSeenAutoModeOutsideReadPrompt": true,
        "projects": [projectDirectory: ["hasTrustDialogAccepted": true, "hasCompletedProjectOnboarding": true]],
    ]
    do {
        try JSONSerialization.data(withJSONObject: settings, options: [.sortedKeys])
            .write(to: URL(fileURLWithPath: configDirectory + "/settings.json"))
        try JSONSerialization.data(withJSONObject: global, options: [.sortedKeys])
            .write(to: URL(fileURLWithPath: configDirectory + "/.claude.json"))
    } catch {
        check(false, "claude-delegation: the scratch Claude Code configuration is written (\(error))")
        return
    }

    // Delegation on, the scratch project paired with the reference.
    let reference = "csec-e2e-claude://delegation/token"
    var projectStat = stat()
    guard lstat(projectDirectory, &projectStat) == 0,
          let volume = VolumeIdentity.uuid(ofMountPoint: projectDirectory) else {
        check(false, "claude-delegation: the scratch project's inode and volume are readable")
        return
    }
    let stores = ProtectedStores.processLocal()
    _ = try? await stores.store(for: DelegationSettingsDocument.self)
        .prepare(DelegationSettingsDocument(setClassifyAllShell: true, claudeSettingsPath: configDirectory + "/settings.json"))
        .commit()
    _ = try? await stores.store(for: PairingDocument.self).prepare(PairingDocument(projects: [ProjectPairing(
        project: ProjectKey(path: projectDirectory, volumeUUID: volume, inode: UInt64(projectStat.st_ino)),
        references: [reference], ssh: []
    )])).commit()
    let log = DecisionLog(directory: SealedRecordDirectory(path: base + "/log"), stores: stores)
    _ = await log.open()
    let delegationResolver = SecretResolver(cache: NullSecretCache())
    await delegationResolver.register(ClaudeDelegationE2EProvider())
    let delegation = ClaudeDelegationService(
        stores: stores, gate: makeClaudeSettingsGate(), consent: ClaudeDelegationE2EConsent(),
        decisionLog: log, terminalInspection: .unavailable, credentialStore: SignedOutClaudeCredentials(),
        allowUnverifiedCallersForTesting: true
    )
    let delegationAgent = Agent(
        resolver: delegationResolver, grants: GrantTable(), consent: ClaudeDelegationE2EConsent(),
        policyReview: DenyPolicyReview(), allowUnverifiedPlansForTesting: true,
        terminalInspection: .unavailable, decisionLog: log, delegation: delegation
    )
    let delegationSocket = NSTemporaryDirectory() + "cs-e2e-claude-\(getpid()).sock"
    let traffic = ClaudeDelegationE2ETraffic()
    let delegationServer = SocketServer(path: delegationSocket, clientTrustPolicy: .allowUnverifiedForTesting) {
        request, caller in
        switch request {
        case let .access(access):
            traffic.noteAccess(from: caller.peerIdentity?.audit.executablePath)
            return await delegationAgent.handle(request: access, caller: caller)
        case .schemes:
            return await delegationAgent.schemes()
        case .capabilities:
            return await delegationAgent.capabilities()
        case let .beginOutputRedaction(begin):
            return await delegationAgent.beginOutputRedaction(request: begin, caller: caller)
        case let .redactOutputChunk(chunk):
            return await delegationAgent.redactOutputChunk(request: chunk, caller: caller)
        case let .endOutputRedaction(end):
            return await delegationAgent.endOutputRedaction(request: end, caller: caller)
        case let .takeApprovalNotices(take):
            return await delegationAgent.takeApprovalNotices(request: take, caller: caller)
        case let .registerAgentCommand(registration):
            let accepted = await delegation.register(registration, caller: caller)
            traffic.noteRegistration(accepted: accepted)
            return Response(requestID: registration.requestID, agentCommandRegistered: accepted)
        case let .configureDelegation(request):
            return await delegationAgent.configureDelegation(request: request, caller: caller)
        default:
            return .failed(.deliveryNotSupported, message: "not part of the claude-delegation check")
        }
    }
    Thread.detachNewThread { try? delegationServer.run() }
    defer { unlink(delegationSocket) }
    for _ in 0..<40 where !FileManager.default.fileExists(atPath: delegationSocket) {
        try? await Task.sleep(nanoseconds: 50_000_000)
    }

    // Claude Code's environment: this harness's, without anything on the G5
    // list, anything that marks a nested or child Claude Code session, or an
    // API key; this build first on PATH; pointed at the scratch configuration,
    // the user's own login and this socket, with the reference in it.
    var claudeEnvironment = environment.filter { name, value in
        ClaudeDelegationGateLists.environmentEntry(matching: name) == nil
            && !(name == ClaudeDelegationGateLists.nodeOptionsName
                && ClaudeDelegationGateLists.nodeOptionsCodeLoadingFlag(in: value) != nil)
            && !ClaudeDelegationE2ETraffic.isWithheld(name)
    }
    claudeEnvironment["PATH"] = debugCsec.deletingLastPathComponent().path + ":"
        + (environment["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin")
    claudeEnvironment["CLAUDE_CONFIG_DIR"] = configDirectory
    claudeEnvironment["CLAUDE_SECURESTORAGE_CONFIG_DIR"] = ""
    claudeEnvironment["CSEC_SOCKET"] = delegationSocket
    claudeEnvironment["CSEC_E2E_CLAUDE_REF"] = reference
    let prompt = "Run exactly this Bash command once, and nothing else: printf '%s' \"$CSEC_E2E_CLAUDE_REF\" | wc -c"

    // Headless: declined as not interactive.
    let headless = Process()
    headless.executableURL = URL(fileURLWithPath: claudePath)
    headless.arguments = ["-p", "--permission-mode", "auto", prompt]
    headless.currentDirectoryURL = URL(fileURLWithPath: projectDirectory)
    headless.environment = claudeEnvironment
    headless.standardInput = FileHandle.nullDevice
    let headlessOutput = Pipe()
    let headlessScreen = ClaudeDelegationE2EScreen(headlessOutput)
    headless.standardOutput = headlessOutput
    headless.standardError = headlessOutput
    let headlessExit = ChildExitWatch(headless)
    if (try? headless.run()) != nil {
        _ = await headlessExit.wait(within: 240)
        if headless.isRunning { headless.terminate() }
    }
    // Fail fast, with the reason, when nothing reached this agent: every later
    // step would only wait out its timeout.
    guard traffic.registrations > 0 else {
        check(false, "claude-delegation: csec's hook registered claude -p's Bash call with this agent "
            + "(none arrived; claude -p printed: \(headlessScreen.tail()))")
        return
    }
    let foreignLaunchers = traffic.accessExecutables.filter {
        URL(fileURLWithPath: $0).resolvingSymlinksInPath().path != debugCsec.path
    }
    guard !traffic.accessExecutables.isEmpty, foreignLaunchers.isEmpty else {
        check(false, "claude-delegation: claude -p's `csec ai` is this build's and asked this agent for the reference "
            + "(access requests from \(traffic.accessExecutables.isEmpty ? "no process" : foreignLaunchers.joined(separator: ", ")); "
            + "claude -p printed: \(headlessScreen.tail()))")
        return
    }
    check(await waitForDelegationRecord(log, kind: .decline, within: 20) {
        $0.delegation?.reason == DelegationDecline.notInteractive.code
    }, "claude-delegation: claude -p is declined .notInteractive (recorded in the decision log; "
        + "declines recorded: \(await recordedDeclines(log)))")

    // Interactive, in a pty: delegated; then Shift+Tab leaves auto mode.
    let interactive = Process()
    interactive.executableURL = URL(fileURLWithPath: "/usr/bin/script")
    interactive.arguments = [
        "-q", "/dev/null", "/bin/sh", "-c", "stty rows 40 cols 120; exec \"$@\"", "claude-pty",
        claudePath, "--permission-mode", "auto",
    ]
    interactive.currentDirectoryURL = URL(fileURLWithPath: projectDirectory)
    interactive.environment = claudeEnvironment
    let input = Pipe()
    let output = Pipe()
    let screen = ClaudeDelegationE2EScreen(output)
    interactive.standardInput = input
    interactive.standardOutput = output
    interactive.standardError = output
    let interactiveExit = ChildExitWatch(interactive)
    guard (try? interactive.run()) != nil else {
        check(false, "claude-delegation: an interactive Claude Code starts in a pty")
        return
    }
    defer {
        if interactive.isRunning { interactive.terminate() }
    }
    // Its status line reads "auto mode on" once the prompt is up in auto mode.
    guard await screen.wait(for: "auto mode on", within: 90, while: { interactive.isRunning }) else {
        check(false, "claude-delegation: the interactive session reached its prompt in auto mode "
            + "(its screen ended: \(screen.tail()))")
        return
    }
    // Typed, then submitted: Claude Code reads a burst that arrives in one
    // write as a paste, whose trailing Return is a newline, not a submit.
    func submit(_ text: String) async {
        input.fileHandleForWriting.write(Data(text.utf8))
        try? await Task.sleep(nanoseconds: 700_000_000)
        input.fileHandleForWriting.write(Data("\r".utf8))
    }
    await submit(prompt)
    check(await waitForDelegationRecord(log, kind: .delegatedRelease, within: 180) {
        $0.decider == .delegated && $0.refs == [reference]
    }, "claude-delegation: an interactive auto-mode session's command is delegated, with no panel "
        + "(declines recorded: \(await recordedDeclines(log)); its screen ended: \(screen.tail()))")
    // One Shift+Tab from auto is default mode, where Claude Code asks before
    // running the command; answering Yes lets its `csec ai` run and ask.
    // Claude Code shows default mode as "manual mode" (its hook input still
    // says "default"), and so does the decline note.
    let beforeShiftTab = screen.mark
    input.fileHandleForWriting.write(Data("\u{1b}[Z".utf8))
    _ = await screen.wait(
        for: "manual mode on", within: 10, after: beforeShiftTab, while: { interactive.isRunning })
    try? await Task.sleep(nanoseconds: 1_000_000_000)
    let beforeSecondPrompt = screen.mark
    await submit(prompt)
    guard await screen.wait(
        for: "Do you want to proceed?", within: 180, after: beforeSecondPrompt, while: { interactive.isRunning }
    ) else {
        check(false, "claude-delegation: in default mode Claude Code asks before running the command "
            + "(its screen ended: \(screen.tail()))")
        return
    }
    try? await Task.sleep(nanoseconds: 500_000_000)
    input.fileHandleForWriting.write(Data("\r".utf8))
    check(await waitForDelegationRecord(log, kind: .decline, within: 60) {
        $0.delegation?.reason == DelegationDecline.notAutoMode("default").code
            && $0.detail?.contains(DelegationDecline.notAutoMode("default").reason) == true
    }, "claude-delegation: after Shift+Tab leaves auto mode, the next command is declined .notAutoMode(default) "
        + "(declines recorded: \(await recordedDeclines(log)))")
    await submit("/exit")
    if !(await interactiveExit.wait(within: 10)) { interactive.terminate() }
}

/// What reached the scenario's agent, so a step that got nothing fails at
/// once with the reason.
final class ClaudeDelegationE2ETraffic: @unchecked Sendable {
    private let lock = NSLock()
    private var registered = 0
    private var executables: [String] = []

    /// Names the scratch session must not inherit: the markers of a nested or
    /// child Claude Code session and its host's plumbing (`CLAUDECODE`,
    /// `CLAUDE_CODE_*` such as the entry point, child-session and attended
    /// flags, `CLAUDE_PID`, `CLAUDE_*`), except a login token; and an API key,
    /// which an interactive session would ask about with "No" focused.
    static func isWithheld(_ name: String) -> Bool {
        if name == "CLAUDE_CODE_OAUTH_TOKEN" { return false }
        return name.hasPrefix("CLAUDE") || name == "ANTHROPIC_API_KEY" || name == "ANTHROPIC_AUTH_TOKEN"
    }

    func noteRegistration(accepted: Bool) {
        guard accepted else { return }
        lock.lock()
        registered += 1
        lock.unlock()
    }

    func noteAccess(from executable: String?) {
        lock.lock()
        executables.append(executable ?? "an unknown executable")
        lock.unlock()
    }

    var registrations: Int {
        lock.lock()
        defer { lock.unlock() }
        return registered
    }

    var accessExecutables: [String] {
        lock.lock()
        defer { lock.unlock() }
        return executables
    }
}

/// A Claude Code session's screen as one searchable string: everything it
/// printed, with terminal escape sequences, whitespace and control characters
/// removed, so a phrase matches however the screen was painted. The model's
/// replies and the commands it runs print only the value-free reference and a
/// byte count.
final class ClaudeDelegationE2EScreen: @unchecked Sendable {
    private let lock = NSLock()
    private var bytes = Data()
    /// Bytes dropped from the front to honour the cap, so a mark taken before
    /// the drop still names the same point in the session.
    private var droppedBytes = 0
    private static let maximumBytes = 4 * 1_024 * 1_024

    init(_ pipe: Pipe) {
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let chunk = handle.availableData
            guard !chunk.isEmpty else {
                handle.readabilityHandler = nil
                return
            }
            self?.append(chunk)
        }
    }

    private func append(_ chunk: Data) {
        lock.lock()
        bytes.append(chunk)
        if bytes.count > Self.maximumBytes {
            let excess = bytes.count - Self.maximumBytes
            bytes.removeFirst(excess)
            droppedBytes += excess
        }
        lock.unlock()
    }

    /// The text after byte offset `mark` of the whole session (or all of it).
    private func text(after mark: Int) -> String {
        lock.lock()
        defer { lock.unlock() }
        let start = min(max(0, mark - droppedBytes), bytes.count)
        return String(decoding: bytes.dropFirst(start), as: UTF8.self)
    }

    private var raw: String {
        lock.lock()
        defer { lock.unlock() }
        return String(decoding: bytes, as: UTF8.self)
    }

    /// Escape sequences (CSI, OSC, two-byte) and control characters removed.
    private static func readable(_ text: String) -> String {
        text.replacingOccurrences(
            of: "\u{1B}(\\[[0-?]*[ -/]*[@-~]|\\][^\u{07}\u{1B}]*(\u{07}|\u{1B}\\\\)|[@-_])",
            with: " ", options: .regularExpression
        ).unicodeScalars.map { CharacterSet.controlCharacters.contains($0) ? " " : String($0) }.joined()
    }

    private static func squeezed(_ text: String) -> String {
        String(readable(text).unicodeScalars.filter { !CharacterSet.whitespaces.contains($0) }).lowercased()
    }

    /// Where the session is now (a byte offset that the cap does not move),
    /// for `wait(for:after:)`.
    var mark: Int {
        lock.lock()
        defer { lock.unlock() }
        return droppedBytes + bytes.count
    }

    func contains(_ phrase: String, after mark: Int = 0) -> Bool {
        Self.squeezed(text(after: mark)).contains(Self.squeezed(phrase))
    }

    /// Waits for `phrase` to appear after `mark`, until `seconds` pass or the
    /// session ends (`running` turns false).
    func wait(
        for phrase: String, within seconds: Double, after mark: Int = 0, while running: () -> Bool = { true }
    ) async -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline, running() {
            if contains(phrase, after: mark) { return true }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        try? await Task.sleep(nanoseconds: 250_000_000)
        return contains(phrase, after: mark)
    }

    /// The last few hundred readable characters, for a failure message.
    func tail(_ count: Int = 600) -> String {
        let text = Self.readable(raw).split(whereSeparator: \.isWhitespace).joined(separator: " ")
        return text.isEmpty ? "nothing" : "…" + String(text.suffix(count))
    }
}

/// A child's exit, awaited without `waitUntilExit()` (which can lose its
/// wakeup in async code): the termination handler is installed before
/// `run()`.
final class ChildExitWatch: @unchecked Sendable {
    private let lock = NSLock()
    private var exited = false
    private var waiting: CheckedContinuation<Bool, Never>?

    init(_ process: Process) {
        process.terminationHandler = { [self] _ in finish() }
    }

    func wait(within seconds: Double) async -> Bool {
        await withCheckedContinuation { continuation in
            lock.lock()
            if exited {
                lock.unlock()
                continuation.resume(returning: true)
                return
            }
            waiting = continuation
            lock.unlock()
            DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { [self] in
                lock.lock()
                let pending = waiting
                waiting = nil
                lock.unlock()
                pending?.resume(returning: false)
            }
        }
    }

    private func finish() {
        lock.lock()
        exited = true
        let pending = waiting
        waiting = nil
        lock.unlock()
        pending?.resume(returning: true)
    }
}
