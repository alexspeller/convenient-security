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

actor ResolutionCounter {
    private var count = 0
    func record() { count += 1 }
    func calls() -> Int { count }
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

actor ConsentCounter: ConsentProvider {
    private(set) var count = 0
    private(set) var authenticationCount = 0
    private(set) var lastTTL: TimeInterval?
    func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval,
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
        return .denied
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
let rootFixtureDirectory = NSTemporaryDirectory() + "cs-root-e2e-\(getpid())"
let rootSocketPath = rootFixtureDirectory + "/rootd.sock"
setenv("CSEC_ROOT_SOCKET", rootSocketPath, 1)

let resolver = SecretResolver(cache: NullSecretCache())
let resolutionCounter = ResolutionCounter()
await resolver.register(StaticProvider(values: [
    "op://demo/db/url": "postgres://s3cr3t",
    "op://demo/db/url-extended": "postgres://s3cr3t/extended",
    "op://demo/api/key": "sk-demo-123",
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
let agent = Agent(
    resolver: resolver,
    grants: grants,
    consent: consent,
    policyReview: CapturingAutoApprovePolicyReview(capture: accessReviewCapture),
    nativeStore: nativeProvider,
    allowUnverifiedPlansForTesting: true
)

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
        return await agent.handle(request: access, caller: caller)
    case .schemes:
        return await agent.schemes()
    case .capabilities:
        return await agent.capabilities()
    case let .configureRemoteApproval(request):
        return Response(
            requestID: request.requestID,
            remoteApprovalStatus: RemoteApprovalConfigurationStatus(state: .disabled)
        )
    case let .beginSession(begin):
        return await agent.beginSession(request: begin, caller: caller)
    case let .beginOutputRedaction(begin):
        return await agent.beginOutputRedaction(request: begin, caller: caller)
    case let .redactOutputChunk(chunk):
        return await agent.redactOutputChunk(request: chunk, caller: caller)
    case let .endOutputRedaction(end):
        return await agent.endOutputRedaction(request: end, caller: caller)
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
        guard let values = access.values, let expiresAt = access.accessExpiresAt else {
            return .failed(
                .internalError,
                message: "synthetic protected launch was not bounded",
                requestID: approval.requestID
            )
        }
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
            return .failed(
                .deliveryNotSupported,
                message: "synthetic root helper rejected the launch",
                requestID: approval.requestID
            )
        }
    }
}
Thread.detachNewThread { try? server.run() }

// Wait (up to ~2s) for the socket to appear.
var waited = 0
while !FileManager.default.fileExists(atPath: socketPath) && waited < 100 {
    usleep(20_000)
    waited += 1
}
check(FileManager.default.fileExists(atPath: socketPath), "agent socket is listening")

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
          && capabilities.features.contains(.protectedRegularFiles),
          "agent advertises delivery, redaction, native-store, and secure-file capabilities")
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
        allowUnverifiedPlansForTesting: true
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
        allowUnverifiedPlansForTesting: true
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

let rootStatus = runCsec(["root-status"], extraEnv: [:])
check(rootStatus.status == 0
      && rootStatus.out == "csec: authenticated root helper reachable\n"
      && rootStatus.err.isEmpty,
      "root-status verifies the authenticated root-helper protocol endpoint")

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
    process.arguments = ["protect", ".envrc"]
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

// `csec protect --env` end to end: drive the real picker through a PTY with
// scripted keystrokes, and prove the safety ordering — values durable in the
// store, then an in-place rewrite that leaves every untouched byte identical.
func runCsecPipedAt(
    cwd: String, _ arguments: [String], input: Data, extraEnv: [String: String] = [:]
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = csecURL
    process.arguments = arguments
    process.currentDirectoryURL = URL(fileURLWithPath: cwd)
    var environment = ProcessInfo.processInfo.environment
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
          && dryRun.out.contains("[ ] DB_PASSWORD")
          && dryRun.out.contains("commented")
          && dryRun.out.contains("already csec://")
          && dryRun.out.contains("unsupported value")
          && !dryRun.out.contains("xoxb-e2e")
          && !dryRun.out.contains("quoted-secret-value")
          && !dryRun.out.contains("commented-out-password"),
          "protect --env --dry-run lists metadata only, with heuristic preselection")
    check((try? Data(contentsOf: URL(fileURLWithPath: envPath))) == fixtureData,
          "protect --env --dry-run leaves the file byte-identical")

    // Without a terminal the picker refuses rather than guessing.
    let nonTTY = runCsecPipedAt(
        cwd: projectDir, ["protect", "--env", "--store", store, ".envrc"], input: Data())
    check(nonTTY.status == 1 && nonTTY.err.contains("interactive terminal"),
          "protect --env without a TTY fails with a clear message")
    check((try? Data(contentsOf: URL(fileURLWithPath: envPath))) == fixtureData,
          "protect --env without a TTY leaves the file byte-identical")

    // Cancelling the picker changes nothing.
    let cancelled = runCsecInPTYAt(
        cwd: projectDir, ["protect", "--env", "--store", store, ".envrc"], keystrokes: "q")
    check(cancelled.status == 1 && cancelled.out.contains("cancelled"),
          "protect --env picker cancel exits nonzero and reports it")
    check((try? Data(contentsOf: URL(fileURLWithPath: envPath))) == fixtureData,
          "protect --env picker cancel leaves the file byte-identical")

    // Happy path: accept the preselection (enter), confirm (y). --store is
    // preset so there is no destination prompt.
    let imported = runCsecInPTYAt(
        cwd: projectDir, ["protect", "--env", "--store", store, ".envrc"],
        keystrokes: "\ry\n")
    check(imported.status == 0 && imported.out.contains("imported 2 variable(s)"),
          "protect --env imports the preselected variables (out: \(imported.out.suffix(200)))")

    let expected = """
    # Service configuration
    PORT=3000
    export SLACK_TOKEN="csec://\(store)/SLACK_TOKEN"
    # DB_PASSWORD=commented-out-password
    API_KEY="csec://\(store)/API_KEY" # trailing note
    EXISTING_REF=csec://somestore/EXISTING_REF
    BAD_INTERP="$HOME/creds"
    use_flake
    """
    let rewritten = try Data(contentsOf: URL(fileURLWithPath: envPath))
    check(rewritten == Data(expected.utf8),
          "protect --env rewrites only the selected values; every other byte is identical")

    let resolved = try client.access(
        references: ["csec://\(store)/SLACK_TOKEN", "csec://\(store)/API_KEY"],
        reason: "protect --env e2e resolve",
        ttlSeconds: 3600)
    check(resolved["csec://\(store)/SLACK_TOKEN"] == Data("xoxb-e2e-1234567890abcdef".utf8)
          && resolved["csec://\(store)/API_KEY"] == Data("quoted-secret-value".utf8),
          "the imported env values resolve back through csec:// with full fidelity")

    // The rewritten reference composes with `csec exec` (as direnv would
    // export it): the child sees the real value in its environment.
    let execRoundTrip = runCsecPipedAt(
        cwd: projectDir,
        ["exec", "--", "/bin/sh", "-c",
         "test \"$SLACK_TOKEN\" = xoxb-e2e-1234567890abcdef && echo ENV-RESOLVED"],
        input: Data(),
        extraEnv: ["SLACK_TOKEN": "csec://\(store)/SLACK_TOKEN"])
    check(execRoundTrip.status == 0 && execRoundTrip.out.contains("ENV-RESOLVED"),
          "csec exec resolves the rewritten reference into the child environment "
              + "(err: \(execRoundTrip.err.suffix(200)))")

    // Re-running now shows the vars as already-references; nothing importable
    // is preselected.
    let rerun = runCsecPipedAt(
        cwd: projectDir, ["protect", "--env", "--store", store, "--dry-run", ".envrc"],
        input: Data())
    check(rerun.status == 0
          && rerun.out.contains("SLACK_TOKEN  (line 3 · already csec://")
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
          && promptedRewrite == Data("SECRET_TOKEN=\"csec://\(promptStore)/SECRET_TOKEN\"\n".utf8),
          "the destination prompt accepts a typed csec:// store "
              + "(out: \(prompted.out.suffix(200)))")

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

    let protectResult = runInProject(["protect", ".envrc"])
    check(protectResult.status == 0
          && !FileManager.default.fileExists(atPath: envrcPath)
          && FileManager.default.fileExists(atPath: envrcPath + ".csec"),
          "sidecar exec setup: protect replaces .envrc with a sidecar (err: \(protectResult.err))")

    let execResult = runInProject([
        "exec", "--", "/bin/sh", "-c",
        "test \"$(cat .envrc)\" = 'export SECRET_TOKEN=exec-sidecar-synthetic\nuse_flake' "
            + "&& printf sidecar-ok",
    ])
    check(execResult.status == 0 && execResult.out == "sidecar-ok",
          "csec exec materializes a *.csec file at its project path for the child "
            + "(status \(execResult.status), out \"\(execResult.out)\", err \"\(execResult.err)\")")
    check((try? FileManager.default.destinationOfSymbolicLink(atPath: envrcPath)) == nil,
          "csec exec tears down the materialized symlink after the child exits")

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
            + "&& test \"$SCANNED_TOKEN\" = 'native-synthetic-token' && printf combined-ok"],
        extraEnv: ["SCANNED_TOKEN": "csec://development/NATIVE_TOKEN"]
    )
    check(combined.status == 0
          && combined.out == "combined-ok",
          "csec exec folds --set and env-scanned references into the sidecar launch "
            + "as value-in-environment (status \(combined.status), out \"\(combined.out)\", "
            + "err \"\(combined.err)\")")
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

func runCsecWithInput(
    _ arguments: [String],
    input: Data,
    extraEnv: [String: String] = [:]
) -> (status: Int32, out: String, err: String) {
    let process = Process()
    process.executableURL = csecURL
    process.arguments = arguments
    var environment = ProcessInfo.processInfo.environment
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
        allowUnverifiedPlansForTesting: true
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
              || exitedParentGet.err.contains("invalid_request"))
          && !replacedParentGet.err.contains(mutationValue)
          && !exitedParentGet.err.contains(mutationValue),
          "replaced or exited parent fails closed before resolution or plaintext output")

    do {
        let setupFixture = URL(fileURLWithPath: NSTemporaryDirectory(), isDirectory: true)
            .appendingPathComponent("csec setup fixture \(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(
            at: setupFixture,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        defer { try? FileManager.default.removeItem(at: setupFixture) }
        let dotenvURL = setupFixture.appendingPathComponent(".env.local")
        let firstMarker = "onboarding-import-synthetic-value"
        try Data("LEGACY_TOKEN='\(firstMarker)'\n".utf8).write(to: dotenvURL)
        let setupArguments = [
            "setup", "--skip-agents", "--project", setupFixture.path,
            "--store", "onboarding_e2e",
            "--import", "IMPORTED_TOKEN=dotenv:.env.local:LEGACY_TOKEN",
            "--no-audit-prompt",
        ]

        let dryRun = runCsec(setupArguments, extraEnv: [:])
        let dryRunStoreRecord = await nativeKeyBackend.record(for: "onboarding_e2e")
        check(dryRun.status == 0
              && dryRun.out.contains("DRY RUN")
              && dryRun.out.contains("plaintext-candidate: dotenv:.env.local:LEGACY_TOKEN")
              && dryRun.out.contains("no files, stores, grants, or providers were changed")
              && !dryRun.out.contains(firstMarker)
              && !dryRun.err.contains(firstMarker)
              && dryRunStoreRecord == nil,
              "setup dry run reviews the selected dotenv credential without values or mutations")

        let applied = runCsec(setupArguments + ["--apply"], extraEnv: [:])
        let importedValues = try client.access(
            references: ["csec://onboarding_e2e/IMPORTED_TOKEN"],
            reason: "onboarding import e2e",
            ttlSeconds: 300
        )
        let originalSource = try Data(contentsOf: dotenvURL)
        check(applied.status == 0
              && applied.out.contains("csec setup: apply complete")
              && applied.out.contains("original environment/dotenv sources were not modified")
              && !applied.out.contains(firstMarker)
              && !applied.err.contains(firstMarker)
              && importedValues["csec://onboarding_e2e/IMPORTED_TOKEN"] == Data(firstMarker.utf8)
              && String(data: originalSource, encoding: .utf8)?.contains(firstMarker) == true,
              "setup imports only the explicitly selected value through the authenticated native-store protocol")

        let protectedExisting = runCsec(setupArguments + ["--apply"], extraEnv: [:])
        check(protectedExisting.status == 1
              && protectedExisting.err.contains("would overwrite existing native-store key")
              && !protectedExisting.out.contains(firstMarker)
              && !protectedExisting.err.contains(firstMarker),
              "repeated setup protects an existing native-store key unless replacement is explicit")

        let secondMarker = "onboarding-import-replacement-value"
        try Data("LEGACY_TOKEN='\(secondMarker)'\n".utf8).write(to: dotenvURL)
        let replaced = runCsec(
            setupArguments + ["--replace-secret", "--apply"],
            extraEnv: [:]
        )
        let replacedValues = try client.access(
            references: ["csec://onboarding_e2e/IMPORTED_TOKEN"],
            reason: "onboarding replacement e2e",
            ttlSeconds: 300
        )
        check(replaced.status == 0
              && !replaced.out.contains(secondMarker)
              && !replaced.err.contains(secondMarker)
              && replacedValues["csec://onboarding_e2e/IMPORTED_TOKEN"] == Data(secondMarker.utf8),
              "--replace-secret explicitly updates only the selected native-store key")
    } catch {
        check(false, "setup CLI import checks succeed (\(error))")
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
        "--", "/bin/sh", "-c",
        "case \"$PGPASSFILE:$KUBECONFIG:$AWS_SHARED_CREDENTIALS_FILE:$GOOGLE_APPLICATION_CREDENTIALS\" in "
            + "*:/dev/fd/6[4-9]:/dev/fd/6[4-9]:/dev/fd/6[4-9]) ;; *) exit 81;; esac; "
            + "test \"$PGPASSFILE\" != \"$KUBECONFIG\" && "
            + "test \"$KUBECONFIG\" != \"$AWS_SHARED_CREDENTIALS_FILE\" && "
            + "test \"$AWS_SHARED_CREDENTIALS_FILE\" != \"$GOOGLE_APPLICATION_CREDENTIALS\" || exit 82; "
            + "p=$(cat \"$PGPASSFILE\") && k=$(cat \"$KUBECONFIG\") && "
            + "a=$(cat \"$AWS_SHARED_CREDENTIALS_FILE\") && g=$(cat \"$GOOGLE_APPLICATION_CREDENTIALS\") || exit 83; "
            + "metadata=$(/bin/ps eww -p $$; /usr/bin/env); "
            + "case \"$metadata\" in *\"$p\"*|*\"$k\"*|*\"$a\"*|*\"$g\"*) exit 84;; esac; "
            + "printf '%s\\n--\\n%s\\n--\\n%s\\n--\\n%s' \"$p\" \"$k\" \"$a\" \"$g\"",
    ]
    let directoryBeforeFD = Set(
        (try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.currentDirectoryPath)) ?? []
    )
    let presetDelivery = runCsec(presetArguments, extraEnv: [:])
    let directoryAfterFD = Set(
        (try? FileManager.default.contentsOfDirectory(atPath: FileManager.default.currentDirectoryPath)) ?? []
    )
    check(presetDelivery.status == 0
          && presetDelivery.out.contains("pgpass-synthetic-secret")
          && presetDelivery.out.contains("synthetic: kube-secret")
          && presetDelivery.out.contains("aws_secret_access_key=aws-fd-secret")
          && presetDelivery.out.contains("google-fd-secret")
          && !presetDelivery.err.contains("pgpass-synthetic-secret")
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
    let crossLaunch = runCsec(
        [
            "tool-exec", "--destination", "ai", "--", "/bin/sh", "-c",
            "printf %s 'postgres://'; printf %s 's3cr3t'",
        ],
        extraEnv: [:]
    )
    check(crossLaunch.status == 0
          && crossLaunch.out.hasPrefix("[csec:secret-")
          && !crossLaunch.err.contains("protected output detected and redacted")
          && !crossLaunch.out.contains("postgres://s3cr3t")
          && !crossLaunch.err.contains("postgres://s3cr3t"),
          "AI tool broker redacts another launch's active value with opaque labels and no warning "
              + "(status=\(crossLaunch.status), label=\(crossLaunch.out.hasPrefix("[csec:secret-")), "
              + "raw=\(crossLaunch.out.contains("postgres://s3cr3t") || crossLaunch.err.contains("postgres://s3cr3t")), "
              + "err=\(crossLaunch.err.contains("postgres://s3cr3t") ? "<contained synthetic marker>" : crossLaunch.err))")

    let quotedShellOutput = "spaces $HOME `uname` \"quotes\"\nsecond line"
    let quotedShellProgram = "printf '%s' '" + quotedShellOutput + "'"
    let encodedShell = runCsec(
        [
            "tool-exec", "--destination", "ai", "--encoded-shell-command",
            AICommandHook.encodeShellCommand(quotedShellProgram),
        ],
        extraEnv: [:]
    )
    check(encodedShell.status == 0 && encodedShell.out == quotedShellOutput,
          "hook transport preserves spaces, metacharacters, quotes, and newlines exactly")

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
            ["tool-exec", "--destination", "ai", "--", "/usr/bin/pgrep", "-fl", rubocopToken],
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

    let unavailableMarker = NSTemporaryDirectory() + "csec-tool-exec-not-run-\(getpid())"
    try? FileManager.default.removeItem(atPath: unavailableMarker)
    let unavailable = runCsec(
        ["tool-exec", "--destination", "ai", "--", "/usr/bin/touch", unavailableMarker],
        extraEnv: ["CSEC_SOCKET": NSTemporaryDirectory() + "csec-missing-\(getpid()).sock"]
    )
    check(unavailable.status == 1
          && !FileManager.default.fileExists(atPath: unavailableMarker)
          && unavailable.err.contains("command not run"),
          "AI tool broker fails closed before launch when the scanner is unavailable")

    let interruptedMarker = NSTemporaryDirectory() + "csec-tool-exec-terminated-\(getpid())"
    try? FileManager.default.removeItem(atPath: interruptedMarker)
    let interrupted = runCsec(
        [
            "tool-exec", "--destination", "ai", "--", "/bin/sh", "-c",
            "printf %s \(forcedScannerFailureMarker); sleep 2; /usr/bin/touch \(interruptedMarker)",
        ],
        extraEnv: [:]
    )
    check(interrupted.status == 1
          && interrupted.out.isEmpty
          && !FileManager.default.fileExists(atPath: interruptedMarker)
          && interrupted.err.contains("command terminated"),
          "AI tool broker forwards no unscanned chunk and terminates the child if scanning fails")

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

    let childExit = runCsec(
        [
            "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "exit 23",
        ],
        extraEnv: [:]
    )
    check(childExit.status == 23, "the output supervisor preserves the child's exit code")

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

    // Env-scan: a reference already in the environment is resolved in place.
    let scanned = runCsec(
        ["exec", "--", "/bin/sh", "-c",
         "test \"$TESTVAR\" = 'postgres://s3cr3t' && printf scanned-ok"],
        extraEnv: ["TESTVAR": "op://demo/db/url"]
    )
    check(scanned.status == 0 && scanned.out == "scanned-ok",
          "csec exec env-scan resolves an op:// value already in the environment (got status \(scanned.status), out \"\(scanned.out)\", err \"\(scanned.err)\")")

    // A plain URL in the environment must be passed through untouched.
    let untouched = runCsec(
        ["exec", "--", "/bin/sh", "-c", "printf %s \"$SITE_URL\""],
        extraEnv: ["SITE_URL": "https://example.com"]
    )
    check(untouched.status == 0 && untouched.out == "https://example.com",
          "csec exec leaves a non-secret URL untouched (got status \(untouched.status), out \"\(untouched.out)\", err \"\(untouched.err)\")")
} else {
    check(false, "built csec binary is present at \(csecURL.path)")
}

unlink(socketPath)
if fakeRoot.isRunning {
    fakeRoot.terminate()
    fakeRoot.waitUntilExit()
}
try? FileManager.default.removeItem(atPath: rootFixtureDirectory)

if failures == 0 {
    print("\nAll end-to-end checks passed.")
    exit(0)
} else {
    FileHandle.standardError.write(Data("\n\(failures) check(s) failed.\n".utf8))
    exit(1)
}
