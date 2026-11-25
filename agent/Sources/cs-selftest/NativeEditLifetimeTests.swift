import Foundation
import ConvenientSecurity
import LocalAuthentication

/// What ends a `csec edit` session, and what does not.
///
/// The rule under test: an open edit is bound to the editor process that opened
/// it and to nothing else. No wall clock retires it, however long the human
/// spends typing; the editor's death does, because csecd holds a decryption
/// context and one of eight session slots for it. In-memory backends only — no
/// files, no host state, no real Touch ID.
func nativeEditLifetimeTests() async {
    print("\n# Native-store edit session lifetime")
    let nativeStore = NativeEncryptedFileProvider(
        keyBackend: InMemoryNativeStoreKeyBackend(),
        fileBackend: InMemoryNativeStoreFileBackend()
    )
    let resolver = SecretResolver(cache: NullSecretCache())
    await resolver.register(nativeStore)
    let editor = CallerInfo(pid: 40_110, startTime: 4_011, description: "synthetic editor")
    let other = CallerInfo(pid: 40_120, startTime: 4_012, description: "synthetic second editor")
    let processes = NativeEditFixtureProcesses([
        editor.pid: editor.startTime,
        other.pid: other.startTime,
    ])
    let consent = NativeEditConsent()
    let agent = Agent(
        resolver: resolver,
        grants: GrantTable(),
        consent: consent,
        policyReview: AutoApprovePolicyReview(),
        nativeStore: nativeStore,
        allowUnverifiedPlansForTesting: true,
        processInspection: processes.inspection,
        terminalInspection: .unavailable
    )

    // External-editor mode keeps every caller in this suite synthetic: it binds
    // the named editor path from the request instead of reading the caller's own
    // executable out of the kernel, so a PID that never existed can hold a
    // session. The lifetime rules under test are identical in both modes.
    func beginRequest(store: String = "editlifetime") -> BeginNativeStoreEditRequest {
        BeginNativeStoreEditRequest(
            store: store,
            mode: .externalTemporaryFile,
            externalEditorPath: "/usr/bin/true"
        )
    }
    func housekeeping(_ caller: CallerInfo) async {
        _ = await agent.handleGrants(request: GrantsRequest(action: .list), caller: caller)
    }

    let opened = await agent.beginNativeStoreEdit(request: beginRequest(), caller: editor)
    guard let session = opened.editSessionID else {
        check(false, "a native-store edit begins for a verified editor")
        return
    }
    check(opened.failure == nil && opened.document != nil,
          "a native-store edit begins and hands back the decrypted document")
    let authorizedTTL = await consent.authorizedTTL()
    let consentCalls = await consent.callCount()
    check(authorizedTTL == nil && consentCalls == 1,
          "the edit asks for no wall-clock lifetime: it is authorized for the editor's lifetime")

    // A long editing session. Nothing in the edit path reads a clock any more, so
    // elapsed time is simulated by running everything that *could* retire a
    // session — the daemon housekeeping sweep, other editors coming and going —
    // while this editor stays alive, and then saving.
    for _ in 0..<3 {
        await housekeeping(editor)
        let transient = await agent.beginNativeStoreEdit(request: beginRequest(), caller: other)
        _ = await agent.cancelNativeStoreEdit(
            request: CancelNativeStoreEditRequest(editSessionID: transient.editSessionID ?? ""),
            caller: other
        )
    }
    let reused = CallerInfo(pid: editor.pid, startTime: editor.startTime + 1,
                            description: "synthetic reused PID")
    let impostor = await agent.commitNativeStoreEdit(
        request: CommitNativeStoreEditRequest(
            editSessionID: session, document: Data(#"{"STOLEN":"no"}"#.utf8)),
        caller: reused
    )
    check(impostor.failure?.code == .invalidRequest && impostor.generation == nil,
          "another process incarnation cannot save someone else's open edit")
    let saved = await agent.commitNativeStoreEdit(
        request: CommitNativeStoreEditRequest(
            editSessionID: session, document: Data(#"{"SLOW_EDIT":"still-saves"}"#.utf8)),
        caller: editor
    )
    check(saved.failure == nil && saved.generation == 1 && saved.secretCount == 1,
          "an edit still saves after its editor has held it open indefinitely")

    // Capacity: the store caps concurrent sessions, so a dead editor must give
    // its slot back. Fill the table from one editor, then kill it.
    var held: [String] = []
    for _ in 0..<8 {
        if let id = await agent.beginNativeStoreEdit(
            request: beginRequest(), caller: editor).editSessionID {
            held.append(id)
        }
    }
    let full = await agent.beginNativeStoreEdit(request: beginRequest(), caller: other)
    check(held.count == 8 && full.editSessionID == nil && full.failure?.code == .policyDenied,
          "live editors hold every session slot: the table is not evicted to make room")

    processes.set(editor.pid, start: nil)
    let reclaimed = await agent.beginNativeStoreEdit(request: beginRequest(), caller: other)
    guard let reclaimedSession = reclaimed.editSessionID else {
        check(false, "a dead editor's sessions free capacity for the next edit")
        return
    }
    check(reclaimed.failure == nil, "a dead editor's sessions free capacity for the next edit")
    let ghost = await agent.commitNativeStoreEdit(
        request: CommitNativeStoreEditRequest(
            editSessionID: held.first ?? "", document: Data(#"{"GHOST":"no"}"#.utf8)),
        caller: editor
    )
    check(ghost.failure?.code == .invalidRequest && ghost.generation == nil,
          "a swept session cannot be saved afterwards")

    // The surviving editor is not collateral damage: its session outlives both
    // the sweep that reclaimed its neighbour and any amount of further idling.
    for _ in 0..<3 { await housekeeping(other) }
    let survivorSave = await agent.commitNativeStoreEdit(
        request: CommitNativeStoreEditRequest(
            editSessionID: reclaimedSession, document: Data(#"{"LIVE_EDITOR":"kept"}"#.utf8)),
        caller: other
    )
    check(survivorSave.failure == nil && survivorSave.generation == 2,
          "sweeping a dead editor leaves a live editor's open session untouched")

    // A cancel naming someone else's session must not strand it: the store
    // ignores the mismatched caller, and so must the agent's own record — the
    // liveness sweep walks those records, so one dropped early would hold a slot
    // until csecd restarted.
    processes.set(editor.pid, start: editor.startTime)
    let guarded = await agent.beginNativeStoreEdit(request: beginRequest(), caller: editor)
    guard let guardedSession = guarded.editSessionID else {
        check(false, "a fresh edit begins for the cancel-ownership check")
        return
    }
    _ = await agent.cancelNativeStoreEdit(
        request: CancelNativeStoreEditRequest(editSessionID: guardedSession),
        caller: other
    )
    let stillOwned = await agent.commitNativeStoreEdit(
        request: CommitNativeStoreEditRequest(
            editSessionID: guardedSession, document: Data(#"{"OWNED":"yes"}"#.utf8)),
        caller: editor
    )
    check(stillOwned.failure == nil && stillOwned.generation == 3,
          "another process cannot cancel an edit it does not own")
}

private final class NativeEditFixtureProcesses: @unchecked Sendable {
    private let lock = NSLock()
    private var starts: [pid_t: UInt64]
    init(_ starts: [pid_t: UInt64]) { self.starts = starts }
    func set(_ pid: pid_t, start: UInt64?) {
        lock.lock(); defer { lock.unlock() }
        starts[pid] = start
    }
    private func start(_ pid: pid_t) -> UInt64? {
        lock.lock(); defer { lock.unlock() }
        return starts[pid]
    }
    var inspection: ProcessInspection {
        ProcessInspection(startTime: { self.start($0) }, parent: { _ in 1 },
                          name: { _ in "synthetic" }, executablePath: { _ in "/synthetic/csec" })
    }
}

/// Approves without a human and records the lifetime it was asked to authorize.
/// It returns a real unlock so the in-memory store can decrypt; with in-memory
/// backends the context is never evaluated, so nothing prompts.
private actor NativeEditConsent: ConsentProvider {
    private var calls = 0
    private var ttl: TimeInterval?

    func requestConsent(
        caller: CallerInfo,
        newReferences: [SecretRef],
        reason: String,
        ttl: TimeInterval?,
        policySummary: String?
    ) async -> ConsentOutcome {
        calls += 1
        self.ttl = ttl
        return .approved(unlock: CacheUnlock(LAContext()))
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        .approved(unlock: CacheUnlock(LAContext()))
    }

    func callCount() -> Int { calls }
    func authorizedTTL() -> TimeInterval? { ttl }
}
