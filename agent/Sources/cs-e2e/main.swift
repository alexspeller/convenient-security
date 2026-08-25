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
        return ResolvedSecret(value: value, cacheHint: .noCache)
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
    func reviewRiskChange(_ review: RiskChangeReview) async -> Bool { false }
    func calls() -> Int { count }
}

actor EmbeddedAuthenticationCounter: AccessPolicyAuthenticationSession {
    private var authenticationCount = 0
    private var cancellationCount = 0

    func authenticate(localizedReason: String, policySummary: String) async -> ConsentOutcome {
        authenticationCount += 1
        return .approved(unlock: CacheUnlock(LAContext()))
    }

    func cancel() async {
        cancellationCount += 1
    }

    func authentications() -> Int { authenticationCount }
    func cancellations() -> Int { cancellationCount }
}

struct EmbeddedAuthenticationPolicyReview: PolicyReviewProvider {
    let level: RiskLevel
    let session: EmbeddedAuthenticationCounter

    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        let classifications = Dictionary(uniqueKeysWithValues: review.credentials.compactMap {
            $0.storedLevel == .unknown ? ($0.identity.credentialKey, level) : nil
        })
        return .approved(AccessPolicyApproval(
            classifications: classifications,
            acceptedCompatibilityCredentialKeys: [],
            authenticationSession: session
        ))
    }

    func reviewRiskChange(_ review: RiskChangeReview) async -> Bool { false }
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
], counter: resolutionCounter))
let nativeKeyBackend = InMemoryNativeStoreKeyBackend()
let nativeFileBackend = InMemoryNativeStoreFileBackend()
let nativeProvider = NativeEncryptedFileProvider(
    keyBackend: nativeKeyBackend,
    fileBackend: nativeFileBackend
)
await resolver.register(nativeProvider)
let grants = GrantTable()
let consent = ConsentCounter()
let capture = RequestCapture()
let agent = Agent(
    resolver: resolver,
    grants: grants,
    consent: consent,
    riskJudgments: RiskJudgmentStore(backend: InMemoryRiskJudgmentBackend()),
    policyReview: AutoApprovePolicyReview(),
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
    case let .cancelNativeStoreEdit(cancel):
        return await agent.cancelNativeStoreEdit(request: cancel, caller: caller)
    case let .risk(risk):
        return await agent.handleRiskOperation(request: risk, caller: caller)
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

do {
    let capabilities = try client.capabilities()
    check(capabilities.supportedVersions == [2], "client negotiates protocol v2")
    check(capabilities.features.contains(.deliveryPlans)
          && capabilities.features.contains(.typedFailures)
          && capabilities.features.contains(.outputGuardBinding)
          && capabilities.features.contains(.activeOutputRedaction)
          && capabilities.features.contains(.nativeEncryptedStore)
          && capabilities.features.contains(.riskPolicyV1)
          && capabilities.features.contains(.riskManagement)
          && capabilities.features.contains(.nativeEditorPolicy)
          && capabilities.features.contains(.registeredSessionRoots)
          && capabilities.features.contains(.credentialProtocols)
          && capabilities.features.contains(.inheritedFileDescriptors)
          && capabilities.features.contains(.protectedRegularFiles),
          "agent advertises delivery, redaction, native-store, risk-policy, and secure-file capabilities")
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

// Unknown classification and a preclassified incompatible mechanism both stop
// before the resolver/cache boundary, even for a syntactically valid request
// constructed directly rather than through csec's normal command planner.
do {
    let guardedCounter = ResolutionCounter()
    let guardedResolver = SecretResolver(cache: NullSecretCache())
    await guardedResolver.register(StaticProvider(
        values: ["op://production/admin/token": "never-resolve-this"],
        counter: guardedCounter
    ))
    let guardedStore = RiskJudgmentStore(backend: InMemoryRiskJudgmentBackend())
    let denyingReview = DenyPolicyReview()
    let guardedConsent = ConsentCounter()
    let guardedAgent = Agent(
        resolver: guardedResolver,
        grants: GrantTable(),
        consent: guardedConsent,
        riskJudgments: guardedStore,
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
        operationContext: "unknown classification test"
    )
    let unknownRequest = try AccessRequest(
        references: ["op://production/admin/token"],
        reason: "unknown must be reviewed",
        ttlSeconds: 3600,
        deliveryPlan: heapPlan
    )
    let unknownResponse = await guardedAgent.handle(
        request: unknownRequest,
        caller: directCaller
    )
    let unknownResolutionCalls = await guardedCounter.calls()
    let unknownConsentCalls = await guardedConsent.calls()
    let unknownReviewCalls = await denyingReview.calls()
    check(unknownResponse.failure?.code == .consentDenied
          && unknownResolutionCalls == 0
          && unknownConsentCalls == 0
          && unknownReviewCalls == 1,
          "unknown risk requires trusted review before biometric or provider resolution")

    let highReference = try SecretRef("op://production/admin/token")
    let descriptor = CredentialGrouping.groups(for: [highReference])[0]
    let identity = try await guardedStore.credentialIdentity(
        provider: descriptor.provider,
        providerAccount: descriptor.providerAccount,
        group: descriptor.group,
        memberReferences: descriptor.references.map(\.uri)
    )
    try await guardedStore.save(RiskJudgment(
        credential: identity,
        level: .high,
        evidence: [],
        source: .explicitUser,
        decidedAt: Date(),
        reviewAfter: Date().addingTimeInterval(3600),
        policyVersion: RiskPolicyV1.version
    ))
    let envPlan = DeliveryPlan(
        mechanism: .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/bin/sh", assurance: .unverified),
        root: .caller,
        descendantScope: .subtree,
        destination: .localDevelopment,
        requestedTTLSeconds: 3600,
        operationContext: "hand-written incompatible delivery",
        outputGuard: OutputGuardPlan(mode: .always)
    )
    let highRequest = try AccessRequest(
        references: [highReference.uri],
        reason: "must fail before resolution",
        ttlSeconds: 3600,
        deliveryPlan: envPlan
    )
    let highResponse = await guardedAgent.handle(request: highRequest, caller: directCaller)
    let highResolutionCalls = await guardedCounter.calls()
    let highConsentCalls = await guardedConsent.calls()
    let highReviewCalls = await denyingReview.calls()
    check(highResponse.failure?.code == .policyDenied
          && highResolutionCalls == 0
          && highConsentCalls == 0
          && highReviewCalls == 1,
          "a hand-written high-risk environment request is denied before review, biometric, cache, or provider")
} catch {
    check(false, "direct pre-resolution policy checks succeed (\(error))")
}

// A trusted access reviewer can keep one UI session open across the value-free
// policy decision and biometric gate. The agent must validate the selection
// before invoking that session, and must not also invoke ConsentProvider.
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
        riskJudgments: RiskJudgmentStore(backend: InMemoryRiskJudgmentBackend()),
        policyReview: EmbeddedAuthenticationPolicyReview(
            level: .low,
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
    let embeddedAuthenticationCalls = await embeddedAuthentication.authentications()
    let embeddedCancellationCalls = await embeddedAuthentication.cancellations()
    let separateConsentCalls = await separateConsent.calls()
    let allowedResolutionCalls = await allowedResolution.calls()
    check(allowedResponse.values?[allowedReference] == "embedded-review-synthetic-token"
          && embeddedAuthenticationCalls == 1
          && embeddedCancellationCalls == 0
          && separateConsentCalls == 0
          && allowedResolutionCalls == 1,
          "an allowed reviewed policy authenticates once and carries its unlock to resolution")

    let deniedReference = "op://embedded-review/denied/token"
    let deniedResolution = ResolutionCounter()
    let deniedResolver = SecretResolver(cache: NullSecretCache())
    await deniedResolver.register(StaticProvider(
        values: [deniedReference: "must-not-resolve"],
        counter: deniedResolution
    ))
    let deniedAuthentication = EmbeddedAuthenticationCounter()
    let deniedConsent = ConsentCounter()
    let deniedAgent = Agent(
        resolver: deniedResolver,
        grants: GrantTable(),
        consent: deniedConsent,
        riskJudgments: RiskJudgmentStore(backend: InMemoryRiskJudgmentBackend()),
        policyReview: EmbeddedAuthenticationPolicyReview(
            level: .high,
            session: deniedAuthentication
        ),
        allowUnverifiedPlansForTesting: true
    )
    let deniedRequest = try AccessRequest(
        references: [deniedReference],
        reason: "deny before embedded authentication",
        ttlSeconds: 3600,
        deliveryPlan: plan
    )
    let deniedResponse = await deniedAgent.handle(request: deniedRequest, caller: caller)
    let deniedAuthenticationCalls = await deniedAuthentication.authentications()
    let deniedCancellationCalls = await deniedAuthentication.cancellations()
    let deniedConsentCalls = await deniedConsent.calls()
    let deniedResolutionCalls = await deniedResolution.calls()
    check(deniedResponse.failure?.code == .policyDenied
          && deniedAuthenticationCalls == 0
          && deniedCancellationCalls == 1
          && deniedConsentCalls == 0
          && deniedResolutionCalls == 0,
          "a rejected policy closes its embedded session before biometric or resolution")
} catch {
    check(false, "embedded policy authentication checks succeed (\(error))")
}

do {
    let first = try client.access(references: ["op://demo/db/url"], reason: "e2e first", ttlSeconds: 3600)
    check(first["op://demo/db/url"] == "postgres://s3cr3t", "value resolves end-to-end over the socket")

    let second = try client.access(references: ["op://demo/db/url"], reason: "e2e second", ttlSeconds: 3600)
    check(second["op://demo/db/url"] == "postgres://s3cr3t", "second fetch succeeds")

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
    check(values["op://session-tests/credential/token"] == "session-root-synthetic-token",
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
    check(both["op://demo/db/url"] == "postgres://s3cr3t" && both["op://demo/api/key"] == "sk-demo-123",
          "both the already-granted and the newly-granted reference resolve")
} catch {
    check(false, "consent-delta access failed: \(error)")
}

// A risk change must take effect against a grant that is already live. The
// second request uses the identical reference and delivery plan; it may not
// reuse the earlier low-risk grant after the logical credential is raised.
do {
    let reference = "op://grant-policy/credential/token"
    let initial = try client.access(
        references: [reference],
        reason: "create a low-risk live grant",
        ttlSeconds: 3600
    )
    check(initial[reference] == "grant-policy-synthetic-token",
          "a low-risk reference receives an initial live grant")

    _ = try client.risk(.raise, reference: reference, level: .high)
    let resolutionsBeforeRetry = await resolutionCounter.calls()
    let consentBeforeRetry = await consent.calls()
    do {
        _ = try client.access(
            references: [reference],
            reason: "stale grant must not bypass raised risk",
            ttlSeconds: 3600
        )
        check(false, "a stale low-risk grant cannot survive a risk raise")
    } catch AgentClient.ClientError.protocolFailure(.policyDenied, _) {
        let resolutionsAfterRetry = await resolutionCounter.calls()
        let consentAfterRetry = await consent.calls()
        check(resolutionsAfterRetry == resolutionsBeforeRetry
              && consentAfterRetry == consentBeforeRetry,
              "a raised risk level invalidates a live grant before biometric or resolution")
    }
} catch {
    check(false, "live-grant risk-raise checks succeed (\(error))")
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

    _ = try client.risk(
        .classify,
        reference: "csec://high_editor/*",
        level: .high
    )
    let consentBeforeForbiddenEditor = await consent.calls()
    do {
        _ = try client.beginNativeStoreEdit(
            store: "high_editor",
            mode: .externalTemporaryFile,
            externalEditorPath: "/usr/bin/false"
        )
        check(false, "high-risk native stores reject the named-plaintext editor")
    } catch AgentClient.ClientError.protocolFailure(.policyDenied, _) {
        let consentAfterForbiddenEditor = await consent.calls()
        let forbiddenEditorKey = await nativeKeyBackend.record(for: "high_editor")
        check(consentAfterForbiddenEditor == consentBeforeForbiddenEditor
              && forbiddenEditorKey == nil,
              "high-risk named-plaintext editing is denied before biometric or decryption")
    }
    let protectedHighEdit = try client.beginNativeStoreEdit(
        store: "high_editor",
        mode: .builtInMemory
    )
    check(await consent.latestTTL() == 15 * 60,
          "high-risk built-in editing applies the 15-minute policy cap")
    client.cancelNativeStoreEdit(sessionID: protectedHighEdit.sessionID)

    _ = try client.risk(
        .classify,
        reference: "csec://standard_editor/*",
        level: .standard
    )
    let standardEdit = try client.beginNativeStoreEdit(
        store: "standard_editor",
        mode: .externalTemporaryFile,
        externalEditorPath: "/usr/bin/false"
    )
    client.cancelNativeStoreEdit(sessionID: standardEdit.sessionID)
    let standardInspection = try client.risk(
        .inspect,
        reference: "csec://standard_editor/*"
    )
    check(standardInspection.acceptances.contains {
        $0.mechanism == .namedPlaintextFile
            && $0.consumerAssurance == .unverified
    }, "standard-risk external editing records separate named-file acceptance")

    _ = try client.risk(
        .classify,
        reference: "csec://revoked_editor/*",
        level: .low
    )
    let revokedEdit = try client.beginNativeStoreEdit(store: "revoked_editor")
    _ = try client.risk(
        .raise,
        reference: "csec://revoked_editor/*",
        level: .high
    )
    do {
        _ = try client.commitNativeStoreEdit(
            sessionID: revokedEdit.sessionID,
            document: Data(#"{"TOKEN":"must-not-commit"}"#.utf8)
        )
        check(false, "a risk change revokes an open native edit session")
    } catch AgentClient.ClientError.protocolFailure(.invalidRequest, _) {
        check(true, "a risk change revokes an open native edit session")
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
    check(nativeValues["csec://development/NATIVE_TOKEN"] == "native-synthetic-token",
          "csec:// value resolves end-to-end through the native encrypted provider")

    let mixed = try client.access(
        references: ["op://demo/db/url", "csec://development/NATIVE_TOKEN"],
        reason: "mixed provider e2e",
        ttlSeconds: 3600
    )
    check(mixed["op://demo/db/url"] == "postgres://s3cr3t"
          && mixed["csec://development/NATIVE_TOKEN"] == "native-synthetic-token",
          "one request resolves 1Password and native-store references together")
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
              && importedValues["csec://onboarding_e2e/IMPORTED_TOKEN"] == firstMarker
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
              && replacedValues["csec://onboarding_e2e/IMPORTED_TOKEN"] == secondMarker,
              "--replace-secret explicitly updates only the selected native-store key")
    } catch {
        check(false, "setup CLI import checks succeed (\(error))")
    }

    let policyReference = "op://policy-tests/credential/token"
    let resolutionsBeforeRiskCLI = await resolutionCounter.calls()
    let initialRisk = runCsec(["risk", "inspect", policyReference], extraEnv: [:])
    let authenticationBeforeRiskCLI = await consent.authentications()
    let classifiedLow = runCsec(
        ["risk", "classify", "low", policyReference],
        extraEnv: [:]
    )
    let authenticationAfterLow = await consent.authentications()
    let raisedHigh = runCsec(
        ["risk", "raise", "high", policyReference],
        extraEnv: [:]
    )
    let authenticationAfterRaise = await consent.authentications()
    let rejectedLowerRaise = runCsec(
        ["risk", "raise", "low", policyReference],
        extraEnv: [:]
    )
    let classifiedBackToLow = runCsec(
        ["risk", "classify", "low", policyReference],
        extraEnv: [:]
    )
    let authenticationAfterDowngrade = await consent.authentications()
    let forgottenRisk = runCsec(["risk", "forget", policyReference], extraEnv: [:])
    let authenticationAfterForget = await consent.authentications()
    let resolutionsAfterRiskCLI = await resolutionCounter.calls()
    check(initialRisk.status == 0
          && initialRisk.out.contains("classification: unknown")
          && initialRisk.out.contains("effective-risk: high"),
          "risk inspect reports fail-safe unknown without resolving a value")
    check(classifiedLow.status == 0
          && classifiedLow.out.contains("classification: low")
          && authenticationAfterLow == authenticationBeforeRiskCLI + 1,
          "classifying below the unknown high floor requires authentication")
    check(raisedHigh.status == 0
          && raisedHigh.out.contains("classification: high")
          && authenticationAfterRaise == authenticationAfterLow,
          "risk raise increases enforcement without an unnecessary biometric")
    check(rejectedLowerRaise.status == 1
          && rejectedLowerRaise.err.contains("policy_denied"),
          "risk raise cannot be used to lower a classification")
    check(classifiedBackToLow.status == 0
          && authenticationAfterDowngrade == authenticationAfterRaise + 1,
          "an explicit high-to-low reclassification requires authentication")
    check(forgottenRisk.status == 0
          && forgottenRisk.out.contains("classification: unknown")
          && authenticationAfterForget == authenticationAfterDowngrade + 1,
          "risk forget resets to fail-safe unknown behind authentication")
    check(resolutionsAfterRiskCLI == resolutionsBeforeRiskCLI,
          "risk management reads and writes no provider value")

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
              == "external-editor-synthetic-token",
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
          && regularFileLeak.out.hasPrefix("[csec:secret-")
          && regularFileLeak.out.hasSuffix("]")
          && !regularFileLeak.out.contains("regular-file-synthetic-secret")
          && !regularFileLeak.err.contains("regular-file-synthetic-secret"),
          "exec-file output scanning redacts a protected file deliberately printed by its target "
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
          && regularFilePTY.out.contains("[csec:secret-")
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

    do {
        _ = try client.risk(
            .classify,
            reference: "op://fd-high/pgpass/content",
            level: .high
        )
        let consentBeforeHighFD = await consent.calls()
        let highSessionFD = runCsec(
            [
                "session", "--", csecURL.path,
                "exec-fd", "--redact-output=never",
                "--preset", "pgpass=op://fd-high/pgpass/content",
                "--", "/bin/cat", "/dev/fd/64",
            ],
            extraEnv: [:]
        )
        let consentAfterHighFD = await consent.calls()
        check(highSessionFD.status == 0
              && highSessionFD.out == "high-fd-synthetic-secret"
              && consentAfterHighFD == consentBeforeHighFD + 1,
              "high-risk delivery inside a session falls back to an exact per-command root")
    } catch {
        check(false, "high-risk session fallback can be prepared (\(error))")
    }

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
          && redactedFDViaShell.out == "[csec:secret-1]"
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

    let resolutionsBeforePipedGet = await resolutionCounter.calls()
    let fetched = runCsec(
        ["get", "op://demo/db/url", "--reason", "synthetic pipe test", "--for", "60"],
        extraEnv: [:]
    )
    let resolutionsAfterPipedGet = await resolutionCounter.calls()
    check(fetched.status == 1
          && fetched.out.isEmpty
          && fetched.err.contains("policy_denied")
          && resolutionsAfterPipedGet == resolutionsBeforePipedGet,
          "unknown-destination piped output is denied before provider resolution "
            + "(status \(fetched.status), out \(fetched.out.debugDescription), "
            + "err \(fetched.err.debugDescription), resolutions "
            + "\(resolutionsBeforePipedGet)->\(resolutionsAfterPipedGet))")

    // Explicit --set injects a named reference into the child.
    let explicit = runCsec(
        ["exec", "--set", "TESTVAR=op://demo/db/url", "--", "/bin/sh", "-c", "printf %s \"$TESTVAR\""],
        extraEnv: [:]
    )
    check(explicit.status == 0 && explicit.out == "postgres://s3cr3t",
          "csec exec --set injects the resolved value (got status \(explicit.status), out \"\(explicit.out)\", err \"\(explicit.err)\")")

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
          && guarded.out == "[csec:secret-1]"
          && guarded.err.contains("[csec:secret-1]")
          && guarded.err.contains("protected output detected and redacted")
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
          && crossLaunch.err.contains("protected output detected and redacted")
          && !crossLaunch.out.contains("postgres://s3cr3t")
          && !crossLaunch.err.contains("postgres://s3cr3t"),
          "AI tool broker redacts another launch's active value before returning output "
              + "(status=\(crossLaunch.status), label=\(crossLaunch.out.hasPrefix("[csec:secret-")), "
              + "event=\(crossLaunch.err.contains("protected output detected and redacted")), "
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
    check(longest.status == 0 && longest.out == "[csec:secret-2]"
          && !longest.out.contains("postgres://s3cr3t"),
          "supervised output uses the longest matching protected value")

    let encoded = runCsec(
        [
            "exec", "--redact-output=always", "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "printf %s \"$TESTVAR\" | /usr/bin/base64",
        ],
        extraEnv: [:]
    )
    check(encoded.status == 0 && encoded.out == "[csec:secret-1]\n"
          && !encoded.out.contains("cG9zdGdyZXM"),
          "supervised output recognizes canonical base64 secret output")

    let referenceLabel = runCsec(
        [
            "exec", "--redact-output=always", "--redact-output-label=reference",
            "--set", "TESTVAR=op://demo/db/url", "--",
            "/bin/sh", "-c", "printf %s \"$TESTVAR\"",
        ],
        extraEnv: [:]
    )
    check(referenceLabel.status == 0 && referenceLabel.out == "op://demo/db/url"
          && referenceLabel.err.contains("reference metadata"),
          "reference-shaped redaction is explicit and warns about metadata exposure")

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
          && stopAndContinue.out.hasSuffix("[csec:secret-1]")
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
        && automaticTTY.out.contains("[csec:secret-1]")
        && automaticTTY.out.contains("37 113")
        && automaticTTY.out.contains("protected output detected and redacted")
        && !automaticTTY.out.contains("postgres://s3cr3t")
    let automaticTTYDiagnostics = automaticTTYPassed ? "" : " "
        + "(status=\(automaticTTY.status), label=\(automaticTTY.out.contains("[csec:secret-1]")), "
        + "size=\(automaticTTY.out.contains("37 113")), numbers=\(ptyNumbers), "
        + "event=\(automaticTTY.out.contains("protected output detected and redacted")), "
        + "raw=\(automaticTTY.out.contains("postgres://s3cr3t")))"
    check(automaticTTYPassed,
          "default tty mode allocates a child PTY and automatically redacts terminal output"
              + automaticTTYDiagnostics)

    // Env-scan: a reference already in the environment is resolved in place.
    let scanned = runCsec(
        ["exec", "--", "/bin/sh", "-c", "printf %s \"$TESTVAR\""],
        extraEnv: ["TESTVAR": "op://demo/db/url"]
    )
    check(scanned.status == 0 && scanned.out == "postgres://s3cr3t",
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
