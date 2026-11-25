import ConvenientSecurity
import CSECRemoteApproval
import Foundation
import LocalAuthentication

// A request for a reference csecd already knows cannot resolve is refused
// before any panel (csec-233n): no such native key in a store csecd holds
// open, no such store at all, or no provider for the scheme. Hermetic: native
// stores live in in-memory backends, every log in its own temporary
// directory, and the panel is a counting fake.

/// A synthetic secret value. It must never appear in any record or message.
private let absentSyntheticValue = "absent-reference-synthetic-value-41c2"

func absentReferenceTests() async {
    print("\n# A reference csecd already knows cannot resolve is refused before any panel")
    await nativePresenceTests()
    await resolverAbsenceTests()
    await absentAccessTests()
    absentRecordBoundTests()
    await absentSSHTests()
}

// MARK: - Fakes

/// The Mac panel approving every review it is shown, counting them. Its
/// touch yields a local context, so an approval opens a cold native store.
private actor AbsentCountingPanel: PolicyReviewProvider {
    private(set) var reviews = 0
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews += 1
        return .approved(AccessPolicyApproval(
            authenticationSession: AbsentPanelSession(), decisionLatency: .milliseconds(400), decidedOn: .mac
        ))
    }
}

private actor AbsentPanelSession: AccessPolicyAuthenticationSession {
    private var used = false
    func completeAfterPolicyApproval(policySummary: String) async -> ConsentOutcome {
        guard !used else { return .denied }
        used = true
        return .approved(unlock: CacheUnlock(LAContext()))
    }
    func cancel() async { used = true }
}

/// The Mac panel holding reviews until the test releases it, so a second
/// request can be made to wait for its turn behind the first. Once released
/// it approves every later review at once, so a panel the second request
/// should never have raised shows in `reviews` rather than hanging the test.
private actor AbsentGatedPanel: PolicyReviewProvider {
    private var waiting: [CheckedContinuation<Void, Never>] = []
    private var released = false
    private(set) var reviews = 0
    var pendingCount: Int { waiting.count }
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        reviews += 1
        if !released { await withCheckedContinuation { waiting.append($0) } }
        return .approved(AccessPolicyApproval(
            authenticationSession: AbsentPanelSession(), decisionLatency: .milliseconds(400), decidedOn: .mac
        ))
    }
    func releaseAll() {
        released = true
        let held = waiting
        waiting = []
        for continuation in held { continuation.resume() }
    }
}

/// A non-native provider that says which of its references are absent, so
/// the refusal is shown to work for any backend, not only `csec://`.
private struct AbsentFixtureProvider: SecretProvider {
    let scheme: String
    let present: [String: Data]
    let absent: Set<String>
    var schemes: Set<String> { [scheme] }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        guard let value = present[ref.uri] else { throw ProviderError.referenceNotFound(ref.uri) }
        return ResolvedSecret(value: value, cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
    func presence(of ref: SecretRef) async -> ReferencePresence {
        if present[ref.uri] != nil { return .present }
        if absent.contains(ref.uri) { return .absent(reason: "the fixture has no such item") }
        return .unknown
    }
}

/// A provider that keeps the default presence, `unknown`.
private struct UnknownPresenceProvider: SecretProvider {
    let scheme: String
    var schemes: Set<String> { [scheme] }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        ResolvedSecret(value: Data(absentSyntheticValue.utf8), cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

/// A cache that holds exactly `held`, as a value cached before its provider
/// was unregistered would be.
private struct HoldingCache: SecretCache {
    let held: Set<String>
    func get(_ uri: String, unlock: CacheUnlock?) async throws -> Data? {
        held.contains(uri) ? Data(absentSyntheticValue.utf8) : nil
    }
    func put(_ uri: String, value: Data) async throws {}
    func invalidate(_ uri: String) async -> Bool { true }
    func holds(_ uri: String) async -> Bool { held.contains(uri) }
}

/// The in-memory key backend, counting record reads and lookups, whose
/// attributes-only lookup can be made to miss a record that exists (as a
/// Keychain that cannot answer might).
private actor CountingKeyBackend: NativeStoreKeyBackend {
    let inner = InMemoryNativeStoreKeyBackend()
    private(set) var loads = 0
    private(set) var lookups = 0
    var lookupMisses = false

    func missLookups() { lookupMisses = true }

    func load(store: String, unlock: CacheUnlock?) async throws -> NativeStoreKeyRecord? {
        loads += 1
        return try await inner.load(store: store, unlock: unlock)
    }
    func create(store: String, record: NativeStoreKeyRecord) async throws {
        try await inner.create(store: store, record: record)
    }
    func update(store: String, record: NativeStoreKeyRecord, unlock: CacheUnlock?) async throws {
        try await inner.update(store: store, record: record, unlock: unlock)
    }
    func recordExists(store: String) async throws -> Bool {
        lookups += 1
        if lookupMisses { return false }
        return await inner.recordExists(store: store)
    }
    func storeNames(unlock: CacheUnlock) async throws -> [String] {
        try await inner.storeNames(unlock: unlock)
    }
}

private func absentPlan(_ command: String) -> DeliveryPlan {
    DeliveryPlan(
        mechanism: .unrestrictedInitialEnvironment,
        executable: PlannedExecutable(canonicalPath: "/usr/bin/\(command)", assurance: .unverified),
        root: .caller, descendantScope: .subtree, destination: .localDevelopment,
        requestedTTLSeconds: nil, operationContext: "synthetic \(command)",
        outputGuard: OutputGuardPlan(mode: .tty)
    )
}

private struct AbsentLog {
    let directory: String
    let log: DecisionLog

    static func open(_ name: String) async -> AbsentLog {
        let directory = NSTemporaryDirectory()
            + "cs-selftest-absent-\(name)-\(UUID().uuidString.lowercased())"
        let log = DecisionLog(
            directory: SealedRecordDirectory(path: directory),
            stores: .processLocal(InMemoryProtectedItemBackend()),
            limits: .standard,
            bootSessionUUID: "00000000-0000-0000-0000-0000000ab5e7",
            onIntegrityEvent: { _ in }
        )
        _ = await log.open()
        return AbsentLog(directory: directory, log: log)
    }

    func records(_ kinds: [DecisionLogRecord.Kind]? = nil) async -> [DecisionLogRecord] {
        var query = DecisionLogQuery(streams: [.decisions, .usage], kinds: kinds)
        var records: [DecisionLogRecord] = []
        for _ in 0..<1_000 {
            let page = await log.read(query)
            records += page.records
            guard let next = page.next, !page.records.isEmpty else { break }
            query.after = next
        }
        return records
    }

    func remove() { try? FileManager.default.removeItem(atPath: directory) }
}

private struct AbsentCaller {
    let pid: pid_t
    let start: UInt64
    var info: CallerInfo { CallerInfo(pid: pid, startTime: start, description: "synthetic absent-reference caller") }

    static func current() -> AbsentCaller? {
        let me = pid_t(ProcessInfo.processInfo.processIdentifier)
        guard let start = ProcessAncestry.startTime(of: me) else { return nil }
        return AbsentCaller(pid: me, start: start)
    }
}

/// A native store `name` holding `document`, written through the provider's
/// own edit path so its document-tier record is warm afterwards.
private func writeNativeStore(
    _ native: NativeEncryptedFileProvider, _ name: String, _ document: String, caller: AbsentCaller
) async throws {
    let store = try NativeStoreName(name)
    let session = try await native.beginEdit(
        store: store, callerPID: caller.pid, callerStartTime: caller.start, unlock: CacheUnlock(LAContext())
    )
    _ = try await native.commitEdit(
        sessionID: session.sessionID, document: Data(document.utf8),
        callerPID: caller.pid, callerStartTime: caller.start
    )
}

// MARK: - Native presence, tier by tier

private func nativePresenceTests() async {
    guard let caller = AbsentCaller.current() else {
        check(false, "native presence: the fixture reads its own start time")
        return
    }
    func ref(_ uri: String) -> SecretRef { try! SecretRef(uri) }
    let keyNotFound = NativeStoreError.secretNotFound.boundedReason
    let storeNotFound = NativeStoreError.storeNotFound.boundedReason

    // The document tier, warm, then cold in a fresh provider (a csecd restart).
    let keys = CountingKeyBackend()
    let files = InMemoryNativeStoreFileBackend()
    let blobKeys = CountingKeyBackend()
    let blobFiles = InMemoryNativeStoreFileBackend()
    let warm = NativeEncryptedFileProvider(
        keyBackend: keys, fileBackend: files,
        blobStore: NativeBlobStore(keyBackend: blobKeys, fileBackend: blobFiles)
    )
    do {
        try await writeNativeStore(warm, "presence", #"{"PRESENT":"\#(absentSyntheticValue)"}"#, caller: caller)
    } catch {
        check(false, "native presence: the fixture store is written (\(error))")
        return
    }
    let loadsBefore = await keys.loads
    let blobLoadsBefore = await blobKeys.loads
    check(await warm.presence(of: ref("csec://presence/PRESENT")) == .present,
          "native presence: a key in a warm document is present")
    check(await warm.presence(of: ref("csec://presence/ABSENT")) == .absent(reason: keyNotFound),
          "native presence: a key missing from a warm document, in a store with no blob tier, is absent as no such key")
    check(await warm.presence(of: ref("csec://nowhere/KEY")) == .absent(reason: storeNotFound),
          "native presence: a store neither tier has, with no record or file, is absent as no such store")
    check(await warm.presence(of: ref("csec://presence/*")) == .absent(
              reason: NativeStoreError.invalidReference.boundedReason),
          "native presence: a reference the native provider cannot parse is absent")
    let loadsAfter = await keys.loads
    let blobLoads = await blobKeys.loads
    check(loadsAfter == loadsBefore && blobLoads == blobLoadsBefore,
          "native presence: answering reads no Keychain record in either tier")

    let cold = NativeEncryptedFileProvider(
        keyBackend: keys, fileBackend: files,
        blobStore: NativeBlobStore(keyBackend: blobKeys, fileBackend: blobFiles)
    )
    check(await cold.presence(of: ref("csec://presence/ABSENT")) == .unknown,
          "native presence: a key in a store csecd has not opened since it started is unknown")
    check(await cold.presence(of: ref("csec://nowhere/KEY")) == .absent(reason: storeNotFound),
          "native presence: a store that does not exist is absent even before csecd opened anything")
    check(await cold.requiresUnlockToResolve(ref("csec://presence/ABSENT")),
          "native presence: answering leaves a cold store cold")
    await keys.missLookups()
    check(await cold.presence(of: ref("csec://presence/ABSENT")) == .unknown,
          "native presence: a record lookup that misses while the store's files remain is unknown, never absent")

    // A corrupt document is a question for the review, not a refusal.
    let corruptFiles = InMemoryNativeStoreFileBackend()
    let corrupt = NativeEncryptedFileProvider(keyBackend: InMemoryNativeStoreKeyBackend(), fileBackend: corruptFiles)
    do {
        try await writeNativeStore(corrupt, "corrupt", #"{"KEY":"x"}"#, caller: caller)
        for name in await corruptFiles.snapshot().keys {
            await corruptFiles.replace(named: name, data: Data("not a sealed document".utf8))
        }
        check(await corrupt.presence(of: ref("csec://corrupt/OTHER")) == .unknown,
              "native presence: a warm document that fails its integrity check is unknown")
    } catch {
        check(false, "native presence: the corrupt fixture store is written (\(error))")
    }

    // The blob tier: a store kept only there, warm, then cold.
    let tierKeys = CountingKeyBackend()
    let tierFiles = InMemoryNativeStoreFileBackend()
    let tierBlobKeys = InMemoryNativeStoreKeyBackend()
    let tierBlobFiles = InMemoryNativeStoreFileBackend()
    let blobs = NativeBlobStore(keyBackend: tierBlobKeys, fileBackend: tierBlobFiles)
    do {
        try await blobs.putBlobs(
            store: try NativeStoreName("files"),
            requests: [NativeBlobStore.PutRequest(
                key: "CONFIG", data: Data(absentSyntheticValue.utf8), mode: 0o600, path: "config/app.yml"
            )],
            unlock: CacheUnlock(LAContext())
        )
    } catch {
        check(false, "native presence: the blob fixture store is written (\(error))")
        return
    }
    let blobProvider = NativeEncryptedFileProvider(keyBackend: tierKeys, fileBackend: tierFiles, blobStore: blobs)
    check(await blobProvider.presence(of: ref("csec://files/CONFIG")) == .present,
          "native presence: a key in a warm blob index is present")
    check(await blobProvider.presence(of: ref("csec://files/OTHER")) == .absent(reason: keyNotFound),
          "native presence: a key missing from a warm blob index, with no document tier, is absent as no such key")
    let coldBlobs = NativeEncryptedFileProvider(
        keyBackend: tierKeys, fileBackend: tierFiles,
        blobStore: NativeBlobStore(keyBackend: tierBlobKeys, fileBackend: tierBlobFiles)
    )
    check(await coldBlobs.presence(of: ref("csec://files/OTHER")) == .unknown,
          "native presence: a key in a blob store csecd has not opened is unknown")
}

// MARK: - The resolver

/// A provider whose absence reason carries terminal controls, as a future
/// provider's own text might.
private struct UnrulyReasonProvider: SecretProvider {
    var schemes: Set<String> { ["unruly"] }
    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        throw ProviderError.referenceNotFound(ref.uri)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
    func presence(of ref: SecretRef) async -> ReferencePresence {
        .absent(reason: "no such item\u{1b}[2J\n" + String(repeating: "x", count: 2_000))
    }
}

private func resolverAbsenceTests() async {
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.registerUnavailable(scheme: "csec")
    await resolver.register(UnrulyReasonProvider())
    let absent = await resolver.referencesKnownAbsent([
        try! SecretRef("csec://store/KEY"), try! SecretRef("nope://x"), try! SecretRef("unruly://item"),
        try! SecretRef("nope://x"),
    ])
    check(absent.map(\.reference.uri) == ["nope://x", "unruly://item"],
          "absent resolver: a csec:// reference is not refused while the native store could not start, and each absent reference is listed once, in request order")
    let reason = absent.last?.reason ?? ""
    check(!reason.contains("\u{1b}") && !reason.contains("\n") && reason.utf8.count <= 512 && reason.hasPrefix("no such item"),
          "absent resolver: a provider's reason is made display-safe and bounded before it reaches a requester")
}

// MARK: - The access path

private func absentAccessTests() async {
    guard let caller = AbsentCaller.current() else {
        check(false, "absent access: the fixture reads its own start time")
        return
    }
    let silentTerminal = TerminalSessionInspector(
        environment: { _ in nil }, parent: { _ in nil }, terminalName: { _ in nil }, titleQuery: { _ in nil }
    )
    struct Harness {
        let agent: Agent
        let panel: AbsentCountingPanel
        let grants: GrantTable
        let log: AbsentLog
    }
    func harness(
        _ name: String, resolver: SecretResolver
    ) async -> Harness {
        let log = await AbsentLog.open(name)
        let panel = AbsentCountingPanel()
        let grants = GrantTable()
        let agent = Agent(
            resolver: resolver, grants: grants, consent: AutoApproveConsent(),
            policyReview: panel, allowUnverifiedPlansForTesting: true,
            terminalInspection: silentTerminal, decisionLog: log.log
        )
        return Harness(agent: agent, panel: panel, grants: grants, log: log)
    }
    func ask(_ harness: Harness, _ refs: [String], _ command: String) async -> Response {
        let request = try! AccessRequest(references: refs, reason: command, deliveryPlan: absentPlan(command))
        return await harness.agent.handle(request: request, caller: caller.info)
    }
    func valueFree(_ records: [DecisionLogRecord], _ response: Response) -> Bool {
        !(response.failure?.message ?? "").contains(absentSyntheticValue) && !records.contains {
            ($0.detail ?? "").contains(absentSyntheticValue) || ($0.command ?? "").contains(absentSyntheticValue)
        }
    }
    let keyNotFound = NativeStoreError.secretNotFound.boundedReason

    // The incident: a store csecd holds open, asked for a key it lacks.
    do {
        let keys = InMemoryNativeStoreKeyBackend()
        let files = InMemoryNativeStoreFileBackend()
        let native = NativeEncryptedFileProvider(keyBackend: keys, fileBackend: files)
        try! await writeNativeStore(native, "harbor", #"{"OPENROUTER_API_KEY":"\#(absentSyntheticValue)"}"#, caller: caller)
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(native)
        let h = await harness("warm", resolver: resolver)
        defer { h.log.remove() }
        let refused = await ask(h, ["csec://harbor/RELAY_TOKEN"], "relay")
        let again = await ask(h, ["csec://harbor/RELAY_TOKEN"], "relay")
        let reviews = await h.panel.reviews
        let minted = await h.grants.summaries(now: Date())
        let records = await h.log.records()
        let absent = records.filter { $0.kind == .absentReference }
        check(refused.values == nil && refused.failure?.code == .referenceNotFound
                && refused.failure?.message.contains("csec://harbor/RELAY_TOKEN") == true
                && refused.failure?.message.contains(keyNotFound) == true,
              "absent access: a key missing from a store csecd holds open is refused with reference_not_found, naming it and why (\(refused.failure?.message ?? "none"))")
        check(again.failure?.code == .referenceNotFound && reviews == 0 && minted.isEmpty,
              "absent access: no panel is raised and nothing is minted, however often it is asked")
        check(absent.count == 1 && absent[0].surface == .secretAccess && absent[0].outcome == nil
                && absent[0].decider == nil && absent[0].refs == ["csec://harbor/RELAY_TOKEN"]
                && absent[0].detail?.contains(keyNotFound) == true
                && absent[0].stream == .decisions,
              "absent access: one absent_reference record, with no outcome, for the repeated refusal")
        check(!records.contains { $0.kind == .panel || $0.kind == .deliveryFailed },
              "absent access: no panel or delivery_failed record")
        check(valueFree(records, refused), "absent access: no record or message holds a value")

        // A mixed request fails whole, and a present key still gets its panel.
        let mixed = await ask(h, ["csec://harbor/OPENROUTER_API_KEY", "csec://harbor/RELAY_TOKEN"], "mixed")
        let afterMixed = await h.panel.reviews
        check(mixed.failure?.code == .referenceNotFound && afterMixed == 0,
              "absent access: a request with one absent reference among present ones is refused whole")
        let present = await ask(h, ["csec://harbor/OPENROUTER_API_KEY"], "present")
        let afterPresent = await h.panel.reviews
        check(present.values?["csec://harbor/OPENROUTER_API_KEY"] == Data(absentSyntheticValue.utf8) && afterPresent == 1,
              "absent access: a key the store holds is reviewed and released as before")
    }

    // A store csecd has not opened since it started: the panel shows, the
    // failure after approval says why, and the store is then open, so the
    // next request is refused before any panel.
    do {
        let keys = InMemoryNativeStoreKeyBackend()
        let files = InMemoryNativeStoreFileBackend()
        let writer = NativeEncryptedFileProvider(keyBackend: keys, fileBackend: files)
        try! await writeNativeStore(writer, "records", #"{"PRESENT":"x"}"#, caller: caller)
        let restarted = NativeEncryptedFileProvider(keyBackend: keys, fileBackend: files)
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(restarted)
        let h = await harness("cold", resolver: resolver)
        defer { h.log.remove() }
        let first = await ask(h, ["csec://records/ABSENT"], "absent-key")
        let firstReviews = await h.panel.reviews
        let failed = await h.log.records([.deliveryFailed])
        check(first.failure?.code == .resolutionFailed && firstReviews == 1
                && first.failure?.message.contains("csec://records/ABSENT") == true
                && first.failure?.message.contains(keyNotFound) == true,
              "absent access: a cold store's missing key is reviewed, and its failure says the key does not exist (\(first.failure?.message ?? "none"))")
        check(failed.count == 1 && failed[0].detail?.contains(keyNotFound) == true,
              "absent access: the delivery_failed record says the key does not exist")
        let second = await ask(h, ["csec://records/ABSENT"], "absent-key")
        let secondReviews = await h.panel.reviews
        check(second.failure?.code == .referenceNotFound && secondReviews == 1,
              "absent access: once the approval opened the store, the next request is refused before any panel")
    }

    // Two requests for that missing key race a restart: both find the store
    // cold, the second waits for its turn behind the first's panel, and the
    // first's touch opens the store, so the second is refused on its turn
    // instead of raising a panel of its own.
    do {
        let keys = InMemoryNativeStoreKeyBackend()
        let files = InMemoryNativeStoreFileBackend()
        let writer = NativeEncryptedFileProvider(keyBackend: keys, fileBackend: files)
        try! await writeNativeStore(writer, "racing", #"{"PRESENT":"x"}"#, caller: caller)
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(NativeEncryptedFileProvider(keyBackend: keys, fileBackend: files))
        let log = await AbsentLog.open("queued")
        defer { log.remove() }
        let panel = AbsentGatedPanel()
        let queue = ConsentQueue()
        let agent = Agent(
            resolver: resolver, grants: GrantTable(), consent: AutoApproveConsent(),
            policyReview: panel, allowUnverifiedPlansForTesting: true,
            terminalInspection: silentTerminal, accessConsentQueue: queue, decisionLog: log.log
        )
        func request() -> AccessRequest {
            try! AccessRequest(references: ["csec://racing/ABSENT"], reason: "racing", deliveryPlan: absentPlan("racing"))
        }
        let first = Task { await agent.handle(request: request(), caller: caller.info) }
        let firstShown = await eventuallyTrue { await panel.pendingCount == 1 }
        let second = Task { await agent.handle(request: request(), caller: caller.info) }
        let secondQueued = await eventuallyTrue { await queue.waitingCount == 1 }
        await panel.releaseAll()
        let firstResponse = await first.value
        let secondResponse = await second.value
        let reviews = await panel.reviews
        check(firstShown && secondQueued && firstResponse.failure?.code == .resolutionFailed
                && secondResponse.failure?.code == .referenceNotFound && reviews == 1,
              "absent access: a request that waited for its turn behind the panel that opened the store is refused on its turn, with no panel of its own")
    }

    // A store that does not exist, before csecd opened anything.
    do {
        let keys = CountingKeyBackend()
        let native = NativeEncryptedFileProvider(
            keyBackend: keys, fileBackend: InMemoryNativeStoreFileBackend(),
            blobStore: NativeBlobStore(keyBackend: InMemoryNativeStoreKeyBackend(), fileBackend: InMemoryNativeStoreFileBackend())
        )
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(native)
        let h = await harness("no-store", resolver: resolver)
        defer { h.log.remove() }
        let refused = await ask(h, ["csec://typo/KEY"], "typo")
        let reviews = await h.panel.reviews
        let loads = await keys.loads
        let lookups = await keys.lookups
        check(refused.failure?.code == .referenceNotFound
                && refused.failure?.message.contains(NativeStoreError.storeNotFound.boundedReason) == true
                && reviews == 0 && loads == 0 && lookups > 0,
              "absent access: a store that does not exist is refused from an attributes-only lookup, with no record read")
    }

    // Any backend: a provider that knows an item is absent is refused, one
    // that cannot tell keeps its panel, and a scheme nobody claims is
    // refused unless the cache holds the reference.
    do {
        let resolver = SecretResolver(cache: HoldingCache(held: ["gone://cached/item"]))
        await resolver.register(AbsentFixtureProvider(
            scheme: "fake", present: ["fake://vault/present": Data(absentSyntheticValue.utf8)],
            absent: ["fake://vault/absent"]
        ))
        await resolver.register(UnknownPresenceProvider(scheme: "vague"))
        let h = await harness("schemes", resolver: resolver)
        defer { h.log.remove() }
        let fake = await ask(h, ["fake://vault/absent"], "fake")
        let unclaimed = await ask(h, ["nope://anything"], "nope")
        let afterRefusals = await h.panel.reviews
        check(fake.failure?.code == .referenceNotFound
                && fake.failure?.message.contains("the fixture has no such item") == true
                && unclaimed.failure?.code == .referenceNotFound
                && unclaimed.failure?.message.contains("no provider is registered for its scheme") == true
                && afterRefusals == 0,
              "absent access: a fake:// item its provider knows is absent, and an unclaimed scheme, are refused before any panel")
        let vague = await ask(h, ["vague://vault/item"], "vague")
        let cached = await ask(h, ["gone://cached/item"], "cached")
        let afterReviews = await h.panel.reviews
        check(vague.values != nil && cached.values != nil && afterReviews == 2,
              "absent access: a provider that cannot tell, and a cached value of an unclaimed scheme, are reviewed as before")
        let absent = await h.log.records([.absentReference])
        check(absent.count == 2, "absent access: each distinct refusal is recorded once")
    }

    // A covered reference whose key was deleted after its grant: a release
    // that also needs a new reference is refused before its panel, while one
    // covered entirely shows no panel and fails as before, saying why.
    do {
        let native = NativeEncryptedFileProvider(
            keyBackend: InMemoryNativeStoreKeyBackend(), fileBackend: InMemoryNativeStoreFileBackend()
        )
        try! await writeNativeStore(native, "rotating", #"{"OLD":"\#(absentSyntheticValue)","NEW":"x"}"#, caller: caller)
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(native)
        let h = await harness("covered", resolver: resolver)
        defer { h.log.remove() }
        let granted = await ask(h, ["csec://rotating/OLD"], "rotating")
        try! await writeNativeStore(native, "rotating", #"{"NEW":"x"}"#, caller: caller)
        let mixed = await ask(h, ["csec://rotating/OLD", "csec://rotating/NEW"], "rotating")
        let reviews = await h.panel.reviews
        check(granted.values != nil && mixed.failure?.code == .referenceNotFound && reviews == 1,
              "absent access: a covered reference that no longer exists refuses a release that needs a panel for another")
        let covered = await ask(h, ["csec://rotating/OLD"], "rotating")
        let coveredReviews = await h.panel.reviews
        check(covered.failure?.code == .resolutionFailed
                && covered.failure?.message.contains(keyNotFound) == true && coveredReviews == 1,
              "absent access: a release its grant covers entirely shows no panel and fails as before, saying why")
    }
}

// MARK: - The record bound

private func absentRecordBoundTests() {
    func record(_ index: Int, surface: DecisionLogRecord.Surface = .secretAccess) -> DecisionLogRecord {
        DecisionLogRecord(
            kind: .absentReference, surface: surface,
            requester: DecisionLogRecord.Requester(class: "bridge:python3.12", rootPID: 900),
            refs: ["csec://bound/KEY_\(index)"], detail: "refusal \(index)"
        )
    }
    var bound = AbsentReferenceRecords()
    let first = bound.admit(record(0))
    let repeated = bound.admit(record(0))
    let otherSurface = bound.admit(record(0, surface: .sshSigning))
    check(first?.detail == "refusal 0" && repeated == nil && otherSurface != nil,
          "absent records: a refusal is recorded once per run, and the same references on another surface are another refusal")
    var admitted = 2
    var last: DecisionLogRecord?
    for index in 1..<(AbsentReferenceRecords.maximumPerRun + 10) {
        if let written = bound.admit(record(index)) {
            admitted += 1
            last = written
        }
    }
    check(admitted == AbsentReferenceRecords.maximumPerRun
            && last?.detail?.hasPrefix("the last refusal like this csecd records until it restarts") == true,
          "absent records: at most \(AbsentReferenceRecords.maximumPerRun) are recorded per run, and the last says so")
}

// MARK: - SSH

private actor AbsentSSHConsent: ConsentProvider {
    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String,
        ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome { .approved(unlock: nil) }
    func authenticate(reason: String) async -> ConsentOutcome { .approved(unlock: nil) }
}

private func absentSSHTests() async {
    guard let caller = AbsentCaller.current() else {
        check(false, "absent SSH: the fixture reads its own start time")
        return
    }
    let signingKey: Ed25519SSHFixture
    let hostKey: Ed25519SSHFixture
    let binding: SSHDestinationBinding
    do {
        signingKey = try Ed25519SSHFixture(seed: 191)
        hostKey = try Ed25519SSHFixture(seed: 193)
        let session = Data(repeating: 0x2b, count: 32)
        binding = try SSHDestinationBinding(
            hostKeyBlob: hostKey.publicKeyBlob, sessionIdentifier: session,
            signature: hostKey.signatureBlob(for: session), isForwarding: false
        )
    } catch {
        check(false, "absent SSH: the synthetic keys build (\(error))")
        return
    }
    let reference = "fake://ssh/deleted-key"
    let nextReference = "fake://ssh/next-key"
    let nextKey: Ed25519SSHFixture
    do { nextKey = try Ed25519SSHFixture(seed: 197) } catch {
        check(false, "absent SSH: the next synthetic key builds (\(error))")
        return
    }
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(AbsentFixtureProvider(
        scheme: "fake", present: [nextReference: nextKey.privateKeyPEM],
        absent: [reference, "fake://ssh/new-key"]
    ))
    let panel = AbsentCountingPanel()
    let log = await AbsentLog.open("ssh")
    defer { log.remove() }
    let service = SSHSigningService(
        resolver: resolver,
        catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [
            SSHKeyMetadata(
                reference: reference, fingerprint: sshFingerprint(signingKey.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: signingKey.publicKeyBlob, label: "deleted key"
            ),
            SSHKeyMetadata(
                reference: nextReference, fingerprint: sshFingerprint(nextKey.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: nextKey.publicKeyBlob, label: "next key"
            ),
        ])),
        consent: AbsentSSHConsent(), policyReview: panel,
        allowUnverifiedCallersForTesting: true,
        knownHostsLookup: SSHKnownHostsLookup { _ in ["absent.example.test"] },
        terminalInspection: .unavailable,
        decisionLog: log.log
    )
    func sign(_ key: Ed25519SSHFixture) async -> Result<Data, SSHProtectionError> {
        do {
            return .success(try await service.signSSHAuthentication(
                publicKeyBlob: key.publicKeyBlob,
                signedData: userAuthenticationRequest(
                    sessionIdentifier: binding.sessionIdentifier, remoteUser: "deploy",
                    publicKeyBlob: key.publicKeyBlob, hostKeyBlob: hostKey.publicKeyBlob
                ),
                flags: 0, binding: binding, caller: caller.info
            ))
        } catch {
            return .failure(error as? SSHProtectionError ?? .catalogUnavailable)
        }
    }
    let refused = await sign(signingKey)
    let signReviews = await panel.reviews
    if case let .failure(.referenceNotFound(summary)) = refused {
        check(summary.contains(reference) && SSHProtectionError.referenceNotFound(summary).diagnosticCode == "reference_not_found"
                && signReviews == 0,
              "absent SSH: a catalog key whose reference cannot resolve is refused before any panel")
    } else {
        check(false, "absent SSH: a catalog key whose reference cannot resolve is refused before any panel (\(refused))")
    }
    let next = await sign(nextKey)
    let nextReviews = await panel.reviews
    if case .success = next {
        check(nextReviews == 1, "absent SSH: the same connection's next identity is reviewed and signs, as ssh offers it")
    } else {
        check(false, "absent SSH: the same connection's next identity is reviewed and signs, as ssh offers it (\(next))")
    }

    var registerError: SSHProtectionError?
    do {
        _ = try await service.register(
            [SSHKeyRegistrationIntent(reference: "fake://ssh/new-key", label: "new key")], caller: caller.info
        )
    } catch {
        registerError = error as? SSHProtectionError
    }
    let registerReviews = await panel.reviews
    if case let .referenceNotFound(summary)? = registerError {
        check(summary.contains("fake://ssh/new-key") && registerReviews == 1,
              "absent SSH: registering a key whose reference cannot resolve is refused before its panel")
    } else {
        check(false, "absent SSH: registering a key whose reference cannot resolve is refused before its panel (\(String(describing: registerError)))")
    }
    let absent = await log.records([.absentReference])
    check(absent.count == 2 && absent.allSatisfy { $0.surface == .sshSigning && $0.outcome == nil },
          "absent SSH: both refusals are recorded as absent_reference on the SSH surface")

    // Two ssh offer a key whose native store is cold after a restart: the
    // second waits for its review turn behind the first's panel, whose touch
    // opens the store, and is refused on its turn with no panel of its own.
    do {
        let keys = InMemoryNativeStoreKeyBackend()
        let files = InMemoryNativeStoreFileBackend()
        let writer = NativeEncryptedFileProvider(keyBackend: keys, fileBackend: files)
        try await writeNativeStore(writer, "sshcold", #"{"OTHER":"x"}"#, caller: caller)
        let coldResolver = SecretResolver(cache: NullSecretCache())
        await coldResolver.register(NativeEncryptedFileProvider(keyBackend: keys, fileBackend: files))
        let gated = AbsentGatedPanel()
        let turns = ConsentQueue()
        let coldService = SSHSigningService(
            resolver: coldResolver,
            catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [SSHKeyMetadata(
                reference: "csec://sshcold/MISSING", fingerprint: sshFingerprint(signingKey.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: signingKey.publicKeyBlob, label: "missing key"
            )])),
            consent: AbsentSSHConsent(), policyReview: gated,
            allowUnverifiedCallersForTesting: true,
            knownHostsLookup: SSHKnownHostsLookup { _ in ["absent.example.test"] },
            terminalInspection: .unavailable,
            reviewTurns: turns
        )
        func coldSign() async -> SSHProtectionError? {
            do {
                _ = try await coldService.signSSHAuthentication(
                    publicKeyBlob: signingKey.publicKeyBlob,
                    signedData: userAuthenticationRequest(
                        sessionIdentifier: binding.sessionIdentifier, remoteUser: "deploy",
                        publicKeyBlob: signingKey.publicKeyBlob, hostKeyBlob: hostKey.publicKeyBlob
                    ),
                    flags: 0, binding: binding, caller: caller.info
                )
                return nil
            } catch {
                return error as? SSHProtectionError ?? .catalogUnavailable
            }
        }
        let first = Task { await coldSign() }
        let firstShown = await eventuallyTrue { await gated.pendingCount == 1 }
        let second = Task { await coldSign() }
        let secondQueued = await eventuallyTrue { await turns.waitingCount == 1 }
        await gated.releaseAll()
        let firstError = await first.value
        let secondError = await second.value
        let reviews = await gated.reviews
        var secondRefused = false
        if case .referenceNotFound? = secondError { secondRefused = true }
        check(firstShown && secondQueued && firstError == .providerResolutionFailed && secondRefused && reviews == 1,
              "absent SSH: an ssh that waited for its turn behind the panel that opened the store is refused on its turn, with no panel of its own (\(String(describing: firstError)), \(String(describing: secondError)))")
    } catch {
        check(false, "absent SSH: the cold-store fixture builds (\(error))")
    }
}
