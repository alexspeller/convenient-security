import ConvenientSecurity
import Foundation
import LocalAuthentication

// Persisted grants: the `grants`/`live-v1` protected item. Every secret and
// SSH grant is written through one owner (`GrantPersistence`), restored at the
// next start only if it passes every load check, and a revocation is written
// before csecd replies, so a restart can never bring a revoked grant back.
// Everything runs over process-local protected items; nothing touches the
// real Keychain.

let grantTestFacts = GrantPersistenceFacts(bootSessionUUID: "boot-session-a", build: "build-under-test")

func grantPersistenceTests() async {
    print("\n# Persisted grants (grants/live-v1)")
    let me = pid_t(ProcessInfo.processInfo.processIdentifier)
    guard let myStart = ProcessAncestry.startTime(of: me) else {
        check(false, "persisted-grant tests can read their own start time")
        return
    }
    grantIDSelectorTests()
    await nativeRestoreReadinessTests()
    await persistedRoundTripTests(me: me, myStart: myStart)
    await loadCheckTests(me: me, myStart: myStart)
    await unreadableDocumentTests(me: me, myStart: myStart)
    await synchronousRevokeTests(me: me, myStart: myStart)
    await sshGrantListingTests(me: me, myStart: myStart)
    await uninstalledGrantWriteTests(me: me, myStart: myStart)
    await grantCapTests(me: me, myStart: myStart)
    await singleOwnerOrderTests(me: me, myStart: myStart)
    await droppedGrantQueryTests(me: me, myStart: myStart)
    await restartCauseWiringTests(me: me, myStart: myStart)
    await evictionRecordTests(me: me, myStart: myStart)
    await settleWaitsForCommitTests(me: me, myStart: myStart)
}

// MARK: - settle() waits for a commit already under way (review F3)

/// Substitute Keychain calls whose writes take a while, counting writes that
/// started and that finished.
private final class SlowKeychainCalls: @unchecked Sendable {
    private let lock = NSLock()
    private var started = 0
    private var finished = 0
    private var stored: Data?

    var writesStarted: Int { lock.lock(); defer { lock.unlock() }; return started }
    var writesFinished: Int { lock.lock(); defer { lock.unlock() }; return finished }

    var functions: ProtectedKeychainFunctions {
        ProtectedKeychainFunctions(
            copyMatching: { [self] _ in
                lock.lock(); defer { lock.unlock() }
                return stored.map { (errSecSuccess, $0) } ?? (errSecItemNotFound, nil)
            },
            update: { [self] _, attributes in write(attributes) },
            add: { [self] attributes in write(attributes) },
            delete: { [self] _ in
                lock.lock(); defer { lock.unlock() }
                stored = nil
                return errSecSuccess
            }
        )
    }

    private func write(_ attributes: [String: Any]) -> OSStatus {
        lock.lock(); started += 1; lock.unlock()
        usleep(600_000)
        lock.lock(); defer { lock.unlock() }
        stored = attributes[kSecValueData as String] as? Data
        finished += 1
        return errSecSuccess
    }
}

private func settleWaitsForCommitTests(me: pid_t, myStart: UInt64) async {
    let calls = SlowKeychainCalls()
    let persistence = GrantPersistence(
        stores: .dataProtectionKeychain(calling: calls.functions), facts: grantTestFacts
    )
    let grant = Grant(rootPID: me, rootStartTime: myStart, references: ["csec://settle/A"], reason: "settle")
    await persistence.update(secret: [grant], generation: 1)
    let underWay = await eventuallyTrue { calls.writesStarted >= 1 }
    await persistence.settle()
    let finishedAtReturn = calls.writesFinished
    check(underWay && finishedAtReturn >= 1 && finishedAtReturn == calls.writesStarted,
          "settle() returns only after a write-behind commit already under way has finished")
}

// MARK: - Fixtures

func persistedSecretGrant(
    id: UUID = UUID(),
    root: pid_t,
    start: UInt64,
    references: [String],
    bootSessionUUID: String? = "boot-session-a",
    epoch: Int = GrantPersistence.grantPolicyEpoch,
    expiresAt: Date? = nil,
    mintedAt: Date = Date(),
    deliveryPlanDigest: String? = "plan-digest",
    scopeKind: GrantScopeKind = .requestingCommand,
    scopeReuseDigest: String? = nil,
    auditSessionID: UInt32? = nil
) -> PersistedSecretGrant {
    PersistedSecretGrant(
        id: id, rootPID: root, rootStartTime: start, references: references,
        reason: "synthetic persisted grant", expiresAt: expiresAt, requestID: nil,
        deliveryPlanDigest: deliveryPlanDigest, peerPIDVersion: nil, peerCDHash: nil,
        plannedExecutable: nil, scopeKind: scopeKind, scopeReuseDigest: scopeReuseDigest,
        auditSessionID: auditSessionID, rootProcessLabel: "fish",
        bootSessionUUID: bootSessionUUID, mintedAt: mintedAt, origin: .humanLocal,
        mintedByBuild: "build-under-test", grantPolicyEpoch: epoch
    )
}

func persistedSSHGrant(
    id: UUID = UUID(),
    root: pid_t,
    start: UInt64,
    fingerprint: String,
    hostKeyFingerprint: String = "SHA256:synthetic-host",
    remoteUser: String = "deploy",
    bootSessionUUID: String? = "boot-session-a",
    epoch: Int = GrantPersistence.grantPolicyEpoch,
    expiresAt: Date? = nil,
    mintedAt: Date = Date()
) -> PersistedSSHGrant {
    PersistedSSHGrant(
        id: id, keyFingerprint: fingerprint, hostKeyFingerprint: hostKeyFingerprint,
        remoteUser: remoteUser, rootPID: root, rootStartTime: start, auditSessionID: nil,
        clientCDHash: nil, expiresAt: expiresAt, scopeKind: .terminalSession,
        rootProcessLabel: "fish", mintedAt: mintedAt, origin: .humanLocal,
        mintedByBuild: "build-under-test", bootSessionUUID: bootSessionUUID,
        grantPolicyEpoch: epoch
    )
}

/// What the grants item holds right now, read through a fresh store value
/// over the same backend (what the next csecd would read).
func storedGrantsDocument(_ backend: InMemoryProtectedItemBackend) async -> GrantsDocument? {
    guard case let .document(document) = await ProtectedStores.processLocal(backend)
        .store(for: GrantsDocument.self).load() else { return nil }
    return document
}

func writeGrantsDocument(_ document: GrantsDocument, to backend: InMemoryProtectedItemBackend) async {
    do {
        try await ProtectedStores.processLocal(backend).store(for: GrantsDocument.self)
            .prepare(document).commit()
    } catch {
        check(false, "the synthetic grants document is written (\(error))")
    }
}

/// A process that exits: its pid and start time name an incarnation that is gone.
func exitedProcess() -> (pid: pid_t, start: UInt64)? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sleep")
    process.arguments = ["30"]
    guard (try? process.run()) != nil else { return nil }
    let pid = process.processIdentifier
    guard let start = ProcessAncestry.startTime(of: pid) else { return nil }
    process.terminate()
    process.waitUntilExit()
    return (pid, start)
}

private struct PlainFixtureProvider: SecretProvider {
    let schemes: Set<String>
    let value: Data

    func resolve(_ ref: SecretRef, unlock: CacheUnlock?) async throws -> ResolvedSecret {
        ResolvedSecret(value: value, cacheHint: .noCache)
    }
    func authenticate() async throws {}
    func isAvailable() async -> Bool { true }
}

// MARK: - Ids

private func grantIDSelectorTests() {
    let bare = GrantIDSelector("1A2B3C4D")
    check(bare?.kind == .secret && bare?.prefix == "1a2b3c4d",
          "a bare hex id still names secret grants")
    let ssh = GrantIDSelector("ssh-0f0e")
    check(ssh?.kind == .ssh && ssh?.prefix == "0f0e", "an ssh- id names SSH grants")
    check(GrantIDSelector("ssh-") == nil && GrantIDSelector("") == nil
            && GrantIDSelector("grant-zz") == nil && GrantIDSelector("xyz") == nil
            && GrantIDSelector(String(repeating: "a", count: 65)) == nil,
          "an empty, non-hex, unknown-kind or over-long id is refused")
    check(GrantIDSelector.displayID(kind: .secret, id: "ABCDEF01-2345") == "grant-abcdef01"
            && GrantIDSelector.displayID(kind: .ssh, id: "abcdef01-2345") == "ssh-abcdef01",
          "grants are listed with their kind's typed short id")
}

// MARK: - Native readiness (backend side of the restore)

private func nativeRestoreReadinessTests() async {
    let unlock = CacheUnlock(LAContext())
    let documentKeys = InMemoryNativeStoreKeyBackend()
    let documentFiles = InMemoryNativeStoreFileBackend()
    let blobKeys = InMemoryNativeStoreKeyBackend()
    let blobFiles = InMemoryNativeStoreFileBackend()
    do {
        let blobs = NativeBlobStore(keyBackend: blobKeys, fileBackend: blobFiles)
        let provider = NativeEncryptedFileProvider(
            keyBackend: documentKeys, fileBackend: documentFiles, blobStore: blobs
        )
        let documentStore = try NativeStoreName("restoredoc")
        let edit = try await provider.beginEdit(
            store: documentStore, callerPID: 4_000, callerStartTime: 9, unlock: unlock
        )
        _ = try await provider.commitEdit(
            sessionID: edit.sessionID, document: Data(#"{"TOKEN":"synthetic-document-value"}"#.utf8),
            callerPID: 4_000, callerStartTime: 9
        )
        _ = try await blobs.putBlobs(
            store: try NativeStoreName("restoreblob"),
            requests: [.init(key: "envrc", data: Data("synthetic-blob-value".utf8), mode: 0o600, path: ".envrc")],
            unlock: unlock
        )
        let documentRef = try SecretRef("csec://restoredoc/TOKEN")
        let blobRef = try SecretRef("csec://restoreblob/envrc")
        let absentRef = try SecretRef("csec://restorenone/KEY")

        // The pre-existing reuse path: a blob-only store opened by one release
        // serves the next (covered) one with no unlock.
        _ = try await provider.resolve(blobRef, unlock: unlock)
        let reused = try await provider.resolve(blobRef, unlock: nil)
        check(reused.value == Data("synthetic-blob-value".utf8),
              "a blob-only store serves a covered reuse with no unlock after its first release")

        // After a restart every sealed tier is cold again.
        let restarted = NativeEncryptedFileProvider(
            keyBackend: documentKeys, fileBackend: documentFiles,
            blobStore: NativeBlobStore(keyBackend: blobKeys, fileBackend: blobFiles)
        )
        let coldDocument = await restarted.requiresUnlockToResolve(documentRef)
        let coldBlob = await restarted.requiresUnlockToResolve(blobRef)
        let coldAbsent = await restarted.requiresUnlockToResolve(absentRef)
        check(coldDocument && coldBlob && coldAbsent,
              "a restarted native provider reports every reference as needing an unlock")
        do {
            _ = try await restarted.resolve(blobRef, unlock: nil)
            check(false, "a cold native reference cannot resolve without an unlock")
        } catch NativeStoreError.authenticationRequired {
            check(true, "a cold native reference cannot resolve without an unlock")
        }

        await restarted.warm([documentRef, blobRef, absentRef], unlock: unlock)
        let warmDocument = await restarted.requiresUnlockToResolve(documentRef)
        let warmBlob = await restarted.requiresUnlockToResolve(blobRef)
        let warmAbsent = await restarted.requiresUnlockToResolve(absentRef)
        check(!warmDocument && !warmBlob && !warmAbsent,
              "one warm with one context opens the document tier, the blob tier, and learns an absent store")
        let warmedDocument = try await restarted.resolve(documentRef, unlock: nil).value
        let warmedBlob = try await restarted.resolve(blobRef, unlock: nil).value
        check(warmedDocument == Data("synthetic-document-value".utf8)
                && warmedBlob == Data("synthetic-blob-value".utf8),
              "after the warm, document and blob values resolve with no unlock")
        do {
            _ = try await restarted.resolve(absentRef, unlock: nil)
            check(false, "a store known to be absent is reported as not found, not as needing an unlock")
        } catch NativeStoreError.storeNotFound {
            check(true, "a store known to be absent is reported as not found, not as needing an unlock")
        }

        // Creating the document store later clears its absence.
        let created = try NativeStoreName("restorenone")
        let createEdit = try await restarted.beginEdit(
            store: created, callerPID: 4_000, callerStartTime: 9, unlock: unlock
        )
        _ = try await restarted.commitEdit(
            sessionID: createEdit.sessionID, document: Data(#"{"KEY":"synthetic-created"}"#.utf8),
            callerPID: 4_000, callerStartTime: 9
        )
        check(try await restarted.resolve(absentRef, unlock: nil).value == Data("synthetic-created".utf8),
              "a document store created after it was found absent resolves")

        // Through the resolver, backend-neutrally.
        let resolver = SecretResolver(cache: NullSecretCache())
        let cold = NativeEncryptedFileProvider(
            keyBackend: documentKeys, fileBackend: documentFiles,
            blobStore: NativeBlobStore(keyBackend: blobKeys, fileBackend: blobFiles)
        )
        await resolver.register(cold)
        await resolver.register(PlainFixtureProvider(schemes: ["op"], value: Data("x".utf8)))
        let opRef = try SecretRef("op://Vault/Item/field")
        let unknownScheme = try SecretRef("nowhere://x/y")
        let needing = await resolver.referencesRequiringUnlock([documentRef, opRef, unknownScheme])
        check(needing == [documentRef.uri],
              "the resolver asks each provider: native needs an unlock, op:// and unregistered schemes do not")
        await resolver.warm([documentRef, opRef], unlock: unlock)
        check(!(await resolver.requiresUnlock([documentRef, opRef])),
              "the resolver's warm opens what its providers need")
    } catch {
        check(false, "native restore-readiness checks run (\(error))")
    }
}

// MARK: - Round trip

private func persistedRoundTripTests(me: pid_t, myStart: UInt64) async {
    let backend = InMemoryProtectedItemBackend()
    let persistence = GrantPersistence(stores: .processLocal(backend), facts: grantTestFacts)
    let table = GrantTable(persistence: persistence)
    let grant = Grant(
        rootPID: me, rootStartTime: myStart,
        references: ["op://Vault/Item/field", "csec://persist/A"],
        reason: "synthetic persisted", deliveryPlanDigest: "digest-1",
        scopeKind: .terminalSession, scopeReuseDigest: "shape-1", auditSessionID: 77,
        rootProcessLabel: "fish", origin: .phone
    )
    await table.add(grant)
    await persistence.settle()
    let stored = await storedGrantsDocument(backend)
    let record = stored?.secret.first
    check(stored?.secret.count == 1 && stored?.ssh.isEmpty == true
            && record?.id == grant.id
            && record?.references == ["csec://persist/A", "op://Vault/Item/field"]
            && record?.rootStartTime == myStart
            && record?.scopeReuseDigest == "shape-1" && record?.auditSessionID == 77
            && record?.bootSessionUUID == "boot-session-a"
            && record?.grantPolicyEpoch == GrantPersistence.grantPolicyEpoch
            && record?.mintedByBuild == "build-under-test"
            && record?.origin == .phone && record?.scopeKind == .terminalSession,
          "a minted grant is persisted with every field, its boot, epoch, build and origin")

    // The next csecd over the same items.
    let restarted = GrantPersistence(stores: .processLocal(backend), facts: grantTestFacts)
    let load = await restarted.load(registeredSchemes: ["csec", "op"], sshKeyFingerprints: [])
    let restored = load.secret.first
    check(load.secret.count == 1 && restored?.id == grant.id
            && restored?.references == grant.references
            && restored?.restored == true && restored?.warm == false
            && restored?.awaitingRestore == true
            && restored?.mintedByBuild == "build-under-test"
            && load.counts.secret == 1 && load.counts.dropped == nil,
          "a restart restores the grant, restored and not yet warm")

    let restoredTable = GrantTable(persistence: restarted)
    await backend.clearOperations()
    await restoredTable.restore(load.secret)
    let coverage = await restoredTable.coverage(
        for: me, now: Date(), deliveryPlanDigest: "another-plan",
        releaseShapeDigest: "shape-1", callerAuditSessionID: 77
    )
    check(coverage.references == grant.references
            && coverage.awaitingRestore == grant.references
            && coverage.coveredOnlyByRestored == grant.references,
          "a restored grant covers exactly as before, and says it waits for the restore")
    let otherSession = await restoredTable.coverage(
        for: me, now: Date(), deliveryPlanDigest: "another-plan",
        releaseShapeDigest: "shape-1", callerAuditSessionID: 78
    )
    check(otherSession.references.isEmpty,
          "a restored grant keeps its audit-session binding")
    _ = await restoredTable.accessibleReferences(
        for: me, now: Date(), releaseShapeDigest: "shape-1", callerAuditSessionID: 77
    )
    await restarted.settle()
    let operations = await backend.operations(on: .grants)
    check(!operations.contains(.update) && !operations.contains(.add),
          "restoring and reusing a grant writes nothing")

    // A second load in the same process restores nothing more.
    let again = await restarted.load(registeredSchemes: ["csec", "op"], sshKeyFingerprints: [])
    check(again.secret.isEmpty, "the grants item is loaded once per daemon lifetime")
}

// MARK: - Load checks

private func loadCheckTests(me: pid_t, myStart: UInt64) async {
    guard let exited = exitedProcess() else {
        check(false, "the exited-root fixture runs")
        return
    }
    let now = Date()
    let survivor = persistedSecretGrant(root: me, start: myStart, references: ["csec://keep/A"])
    let partial = persistedSecretGrant(
        root: me, start: myStart, references: ["csec://keep/B", "zzz://gone/x"]
    )
    let epochAndBoot = persistedSecretGrant(
        root: me, start: myStart, references: ["csec://keep/C"],
        bootSessionUUID: "boot-session-b", epoch: GrantPersistence.grantPolicyEpoch + 1
    )
    let otherBoot = persistedSecretGrant(
        root: me, start: myStart, references: ["csec://keep/D"], bootSessionUUID: "boot-session-b"
    )
    let recycled = persistedSecretGrant(root: me, start: myStart + 1, references: ["csec://keep/E"])
    let exitedRoot = persistedSecretGrant(root: exited.pid, start: exited.start, references: ["csec://keep/F"])
    let expired = persistedSecretGrant(
        root: me, start: myStart, references: ["csec://keep/G"], expiresAt: now.addingTimeInterval(-60)
    )
    let unknown = persistedSecretGrant(root: me, start: myStart, references: ["zzz://gone/y"])
    let sshSurvivor = persistedSSHGrant(root: me, start: myStart, fingerprint: "SHA256:known")
    let sshRemoved = persistedSSHGrant(root: me, start: myStart, fingerprint: "SHA256:removed")
    let sshExpired = persistedSSHGrant(
        root: me, start: myStart, fingerprint: "SHA256:known", expiresAt: now.addingTimeInterval(-1)
    )
    let backend = InMemoryProtectedItemBackend()
    await writeGrantsDocument(GrantsDocument(
        secret: [survivor, partial, epochAndBoot, otherBoot, recycled, exitedRoot, expired, unknown],
        ssh: [sshSurvivor, sshRemoved, sshExpired]
    ), to: backend)

    let persistence = GrantPersistence(stores: .processLocal(backend), facts: grantTestFacts)
    let load = await persistence.load(
        now: now, registeredSchemes: ["csec", "op"], sshKeyFingerprints: ["SHA256:known"]
    )
    check(Set(load.secret.map(\.id)) == [survivor.id, partial.id]
            && load.secret.allSatisfy { $0.restored && !$0.warm },
          "only grants passing every load check are restored, restored and not warm")
    check(load.secret.first { $0.id == partial.id }?.references == ["csec://keep/B"],
          "a reference of an unregistered scheme is dropped from a grant that keeps others")
    check(load.ssh.map(\.id) == [sshSurvivor.id], "an SSH grant whose key is still catalogued is restored")
    check(load.counts.secret == 2 && load.counts.ssh == 1, "the restart counts what was restored")
    check(load.counts.dropped == [
        "policy_epoch": 1, "boot_session": 1, "root_exited": 2, "expired": 2,
        "unknown_reference": 1, "ssh_key_removed": 1,
    ], "each dropped grant is counted under the first check it fails (\(load.counts.dropped ?? [:]))")
    let reasons = await persistence.droppedAtLoad.map(\.reason)
    check(reasons.count == 8 && reasons.filter { $0 == .rootExited }.count == 2,
          "the dropped grants are remembered for the rest of the run")

    await persistence.settle()
    let rewritten = await storedGrantsDocument(backend)
    check(Set(rewritten?.secret.map(\.id) ?? []) == [survivor.id, partial.id]
            && rewritten?.secret.first { $0.id == partial.id }?.references == ["csec://keep/B"]
            && rewritten?.ssh.map(\.id) == [sshSurvivor.id],
          "after dropping, the item is rewritten with the survivors only")

    // An SSH catalog that cannot be read restores no SSH grant.
    let catalogless = InMemoryProtectedItemBackend()
    await writeGrantsDocument(GrantsDocument(ssh: [sshSurvivor]), to: catalogless)
    let noCatalog = await GrantPersistence(stores: .processLocal(catalogless), facts: grantTestFacts)
        .load(registeredSchemes: ["csec"], sshKeyFingerprints: nil)
    check(noCatalog.ssh.isEmpty && noCatalog.counts.dropped == ["ssh_key_removed": 1],
          "with no readable SSH catalog, no SSH grant is restored")

    // A boot csecd cannot name cannot be shown to be the same boot.
    let unnamed = InMemoryProtectedItemBackend()
    await writeGrantsDocument(GrantsDocument(secret: [survivor]), to: unnamed)
    let noBoot = await GrantPersistence(
        stores: .processLocal(unnamed),
        facts: GrantPersistenceFacts(bootSessionUUID: nil, build: "build-under-test")
    ).load(registeredSchemes: ["csec"], sshKeyFingerprints: [])
    check(noBoot.secret.isEmpty && noBoot.counts.dropped == ["boot_session": 1],
          "with no readable boot session, nothing is restored")
}

private func unreadableDocumentTests(me: pid_t, myStart: UInt64) async {
    let backend = InMemoryProtectedItemBackend()
    let future = Data(#"{"document":{"future":true},"formatVersion":99}"#.utf8)
    await backend.setRawBytes(future, for: .grants)
    let persistence = GrantPersistence(stores: .processLocal(backend), facts: grantTestFacts)
    let load = await persistence.load(registeredSchemes: ["csec"], sshKeyFingerprints: [])
    await persistence.settle()
    let untouched = await backend.rawBytes(for: .grants)
    check(load.secret.isEmpty && load.ssh.isEmpty && load.counts.unreadable != nil
            && untouched == future,
          "an item this build cannot read restores nothing and is left as it is")
    let table = GrantTable(persistence: persistence)
    let grant = Grant(rootPID: me, rootStartTime: myStart, references: ["csec://after/A"], reason: "new")
    await table.add(grant)
    await persistence.settle()
    let afterMint = await backend.rawBytes(for: .grants)
    let listed = await table.summaries(now: Date()).map(\.id)
    check(afterMint == future && listed.count == 1,
          "a grant minted over an item this build cannot read holds for the run and leaves the item as found")
    _ = await table.revoke(idPrefix: String(grant.id.uuidString.prefix(8)))
    let revokeFailure = await persistence.persistNow()
    let afterRevoke = await backend.rawBytes(for: .grants)
    check(revokeFailure == nil && afterRevoke == future,
          "revoking that grant is complete without touching the item, which never held it")
    await table.add(Grant(rootPID: me, rootStartTime: myStart, references: ["csec://after/B"], reason: "new"))
    _ = await table.revokeAll()
    let allFailure = await persistence.persistNow(discardingUnreadable: true)
    let afterAll = await storedGrantsDocument(backend)
    check(allFailure == nil && afterAll?.secret.isEmpty == true && afterAll?.ssh.isEmpty == true,
          "revoke --all discards an item this build cannot read and saves the empty state")
    let later = Grant(rootPID: me, rootStartTime: myStart, references: ["csec://after/C"], reason: "new")
    await table.add(later)
    await persistence.settle()
    check(await storedGrantsDocument(backend)?.secret.map(\.id) == [later.id],
          "after the discard, grants are saved again")
}

// MARK: - Synchronous revoke

private func synchronousRevokeTests(me: pid_t, myStart: UInt64) async {
    let backend = InMemoryProtectedItemBackend()
    let persistence = GrantPersistence(stores: .processLocal(backend), facts: grantTestFacts)
    let table = GrantTable(persistence: persistence)
    let agent = Agent(
        resolver: SecretResolver(cache: NullSecretCache()), grants: table,
        consent: AutoApproveConsent(), policyReview: AutoApprovePolicyReview(),
        allowUnverifiedPlansForTesting: true, terminalInspection: .unavailable, grantPersistence: persistence
    )
    let caller = CallerInfo(pid: me, startTime: myStart, description: "synthetic revoker")
    func grant(_ key: String) -> Grant {
        Grant(rootPID: me, rootStartTime: myStart, references: ["csec://revoke/\(key)"], reason: "revoke fixture")
    }
    func revoke(_ id: String? = nil, all: Bool = false) async -> Response {
        await agent.handleGrants(request: GrantsRequest(action: .revoke, grantID: id, all: all), caller: caller)
    }
    let first = grant("A"), second = grant("B")
    await table.add(first)
    await table.add(second)
    await persistence.settle()
    check(Set(await storedGrantsDocument(backend)?.secret.map(\.id) ?? []) == [first.id, second.id],
          "revoke fixture: both grants are persisted")

    let revoked = await revoke(String(first.id.uuidString.prefix(8)))
    // No settle: the reply comes only after the write.
    let afterRevoke = await storedGrantsDocument(backend)
    check(revoked.revokedGrantCount == 1 && afterRevoke?.secret.map(\.id) == [second.id],
          "a revocation is persisted before csec revoke gets its reply")

    // A write that fails deletes the whole item: every persisted grant is
    // forgotten, which cannot resurrect anything.
    await backend.inject(.failingWrites(-25_308), for: .grants)
    let failedWrite = await revoke(String(second.id.uuidString.prefix(8)))
    let deleted = await backend.rawBytes(for: .grants)
    check(failedWrite.revokedGrantCount == 1 && failedWrite.failure == nil && deleted == nil,
          "a revocation whose write fails deletes the item instead and succeeds")

    // A write and a delete that both fail are reported: the earlier item,
    // with the revoked grant, may still be there.
    await backend.inject(.init(), for: .grants)
    let third = grant("C")
    await table.add(third)
    await persistence.settle()
    check(await storedGrantsDocument(backend)?.secret.map(\.id) == [third.id],
          "revoke fixture: the third grant is persisted")
    await backend.inject(.failingWrites(-25_308, delete: -25_244), for: .grants)
    let unpersisted = await revoke(String(third.id.uuidString.prefix(8)))
    let listed = await agent.handleGrants(request: GrantsRequest(action: .list), caller: caller)
    check(unpersisted.failure?.code == .internalError
            && unpersisted.failure?.message.contains("could not be written") == true
            && unpersisted.failure?.message.contains("revoked 1 grant") == true
            && listed.grants?.isEmpty == true,
          "a revocation that could be neither written nor deleted is reported, and still holds in memory")
    await backend.inject(.init(), for: .grants)

    // revoke --all writes even when nothing is live, so nothing can come back.
    await writeGrantsDocument(GrantsDocument(secret: [
        persistedSecretGrant(root: me, start: myStart, references: ["csec://revoke/stale"]),
    ]), to: backend)
    let all = await revoke(all: true)
    let emptied = await storedGrantsDocument(backend)
    check(all.revokedGrantCount == 0 && all.failure == nil
            && emptied.map { $0.secret.isEmpty && $0.ssh.isEmpty } == true,
          "revoke --all leaves the persisted item empty")
}

// MARK: - SSH grants in csec grants / csec revoke

private func sshGrantListingTests(me: pid_t, myStart: UInt64) async {
    let backend = InMemoryProtectedItemBackend()
    let persistence = GrantPersistence(stores: .processLocal(backend), facts: grantTestFacts)
    let table = GrantTable(persistence: persistence)
    let resolver = SecretResolver(cache: NullSecretCache())
    guard let listingKey = try? Ed25519SSHFixture(seed: 199) else {
        check(false, "the SSH listing key fixture builds")
        return
    }
    let key = SSHKeyMetadata(
        reference: "csec://ssh-listing/key", fingerprint: sshFingerprint(listingKey.publicKeyBlob),
        algorithm: "ssh-ed25519", publicKeyBlob: listingKey.publicKeyBlob, label: "listing key"
    )
    let ssh = SSHSigningService(
        resolver: resolver,
        catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [key])),
        consent: AutoApproveConsent(), policyReview: AutoApprovePolicyReview(),
        allowUnverifiedCallersForTesting: true,
        knownHostsLookup: SSHKnownHostsLookup { _ in ["listing.example.test"] },
        terminalInspection: .unavailable,
        persistence: persistence
    )
    let agent = Agent(
        resolver: resolver, grants: table, consent: AutoApproveConsent(),
        policyReview: AutoApprovePolicyReview(), sshSigningService: ssh,
        allowUnverifiedPlansForTesting: true, terminalInspection: .unavailable, grantPersistence: persistence
    )
    let caller = CallerInfo(pid: me, startTime: myStart, description: "synthetic lister")
    let sshGrant = persistedSSHGrant(root: me, start: myStart, fingerprint: key.fingerprint)
    let secret = Grant(rootPID: me, rootStartTime: myStart, references: ["csec://listing/A"], reason: "listed")
    await ssh.restore([sshGrant])
    await table.add(secret)
    await persistence.settle()
    check(await storedGrantsDocument(backend)?.ssh.map(\.id) == [sshGrant.id],
          "an SSH grant is persisted in the same item as secret grants")

    let listed = await agent.handleGrants(request: GrantsRequest(action: .list), caller: caller)
    let sshSummary = listed.grants?.first { $0.grantKind == .ssh }
    check(listed.grants?.count == 2 && listed.grants?.allSatisfy(\.isWellFormed) == true
            && sshSummary?.displayID == "ssh-" + String(sshGrant.id.uuidString.lowercased().prefix(8))
            && sshSummary?.ssh?.remoteUser == "deploy"
            && sshSummary?.ssh?.hostNames == ["listing.example.test"]
            && sshSummary?.ssh?.keyLabel == "listing key"
            && sshSummary?.references == [key.reference]
            && sshSummary?.rootProcessLabel == "fish" && sshSummary?.restored == true,
          "csec grants lists SSH grants with key, host, user, root and an ssh- id")

    let shortID = String(sshGrant.id.uuidString.lowercased().prefix(8))
    let bare = await agent.handleGrants(
        request: GrantsRequest(action: .revoke, grantID: shortID), caller: caller
    )
    check(bare.revokedGrantCount == 0, "a bare id never matches an SSH grant")
    let typed = await agent.handleGrants(
        request: GrantsRequest(action: .revoke, grantID: "ssh-" + shortID), caller: caller
    )
    let afterTyped = await storedGrantsDocument(backend)
    check(typed.revokedGrantCount == 1 && afterTyped?.ssh.isEmpty == true,
          "csec revoke ssh-<id> drops the SSH grant and persists it before replying")

    await ssh.restore([persistedSSHGrant(root: me, start: myStart, fingerprint: key.fingerprint)])
    let all = await agent.handleGrants(request: GrantsRequest(action: .revoke, all: true), caller: caller)
    let emptied = await storedGrantsDocument(backend)
    let remaining = await agent.handleGrants(request: GrantsRequest(action: .list), caller: caller)
    check(all.revokedGrantCount == 2 && emptied?.secret.isEmpty == true && emptied?.ssh.isEmpty == true
            && remaining.grants?.isEmpty == true,
          "csec revoke --all drops secret and SSH grants and persists both")
}

// MARK: - Uninstalled

private func uninstalledGrantWriteTests(me: pid_t, myStart: UInt64) async {
    let backend = InMemoryProtectedItemBackend()
    let stores = ProtectedStores.processLocal(backend)
    let persistence = GrantPersistence(stores: stores, facts: grantTestFacts)
    let table = GrantTable(persistence: persistence)
    let grant = Grant(rootPID: me, rootStartTime: myStart, references: ["csec://gone/A"], reason: "x")
    await table.add(grant)
    await persistence.settle()
    stores.enterUninstalledState()
    await backend.clearOperations()
    await table.add(Grant(rootPID: me, rootStartTime: myStart, references: ["csec://gone/B"], reason: "y"))
    _ = await table.revoke(idPrefix: String(grant.id.uuidString.prefix(8)))
    let failure = await persistence.persistNow()
    await persistence.settle()
    let operations = await backend.operations(on: .grants)
    check(failure == nil && !operations.contains(.update) && !operations.contains(.add),
          "once uninstall began, no mint or revocation writes the grants item")
}

// MARK: - Caps

private func grantCapTests(me: pid_t, myStart: UInt64) async {
    let backend = InMemoryProtectedItemBackend()
    let persistence = GrantPersistence(stores: .processLocal(backend), facts: grantTestFacts)
    let base = Date(timeIntervalSince1970: 1_800_000_000)
    let secret = (0..<(GrantPersistence.maximumSecretGrants + 6)).map { index in
        Grant(
            rootPID: me, rootStartTime: myStart, references: ["csec://cap/K\(index)"],
            reason: "cap", mintedAt: base.addingTimeInterval(TimeInterval(index))
        )
    }
    let ssh = (0..<(GrantPersistence.maximumSSHGrants + 3)).map { index in
        persistedSSHGrant(
            root: me, start: myStart, fingerprint: "SHA256:cap-\(index)",
            mintedAt: base.addingTimeInterval(TimeInterval(index))
        )
    }
    await persistence.update(secret: secret, generation: 1)
    await persistence.update(ssh: ssh, generation: 1)
    await persistence.settle()
    let stored = await storedGrantsDocument(backend)
    check(stored?.secret.count == GrantPersistence.maximumSecretGrants
            && Set(stored?.secret.map(\.id) ?? []) == Set(secret.suffix(GrantPersistence.maximumSecretGrants).map(\.id))
            && stored?.ssh.count == GrantPersistence.maximumSSHGrants
            && Set(stored?.ssh.map(\.id) ?? []) == Set(ssh.suffix(GrantPersistence.maximumSSHGrants).map(\.id)),
          "over the count caps, the oldest grants are left out of the item")

    // Over the byte cap: the oldest go until the document fits.
    let sizeBackend = InMemoryProtectedItemBackend()
    let sized = GrantPersistence(stores: .processLocal(sizeBackend), facts: grantTestFacts)
    let padding = String(repeating: "p", count: 3_900)
    let large = (0..<6).map { index in
        Grant(
            rootPID: me, rootStartTime: myStart,
            references: Set((0..<64).map { "op://Cap/Item\(index)-\($0)/\(padding)" }),
            reason: "large", mintedAt: base.addingTimeInterval(TimeInterval(index))
        )
    }
    await sized.update(secret: large, generation: 1)
    await sized.settle()
    let bytes = await sizeBackend.rawBytes(for: .grants)
    let fitted = await storedGrantsDocument(sizeBackend)
    let kept = fitted?.secret.map(\.id) ?? []
    check((bytes?.count ?? .max) <= ProtectedItem.grants.maximumBytes
            && !kept.isEmpty && kept.count < large.count
            && kept.contains(large[5].id) && !kept.contains(large[0].id),
          "over the byte cap, the oldest grants go until the item fits (kept \(kept.count))")
}

// MARK: - One owner, ordered

private func singleOwnerOrderTests(me: pid_t, myStart: UInt64) async {
    // A snapshot that arrives after a newer one never replaces it.
    let backend = InMemoryProtectedItemBackend()
    let persistence = GrantPersistence(stores: .processLocal(backend), facts: grantTestFacts)
    let a = Grant(rootPID: me, rootStartTime: myStart, references: ["csec://order/A"], reason: "a")
    let b = Grant(rootPID: me, rootStartTime: myStart, references: ["csec://order/B"], reason: "b")
    await persistence.update(secret: [a, b], generation: 2)
    await persistence.update(secret: [a], generation: 1)
    let sshNew = persistedSSHGrant(root: me, start: myStart, fingerprint: "SHA256:order-new")
    await persistence.update(ssh: [], generation: 5)
    await persistence.update(ssh: [sshNew], generation: 4)
    await persistence.settle()
    let stored = await storedGrantsDocument(backend)
    check(Set(stored?.secret.map(\.id) ?? []) == [a.id, b.id] && stored?.ssh.isEmpty == true,
          "a late, older snapshot of either table never replaces a newer one")

    // Interleaved mints and revocations from both services: a revocation is
    // persisted when its reply would go out and never comes back, and what
    // is persisted at the end is exactly what both tables hold.
    let resolver = SecretResolver(cache: NullSecretCache())
    guard let signingKey = try? Ed25519SSHFixture(seed: 211),
          let hostKey = try? Ed25519SSHFixture(seed: 223),
          let hostSignature = try? hostKey.signatureBlob(for: Data(repeating: 0x5b, count: 32)),
          let binding = try? SSHDestinationBinding(
              hostKeyBlob: hostKey.publicKeyBlob, sessionIdentifier: Data(repeating: 0x5b, count: 32),
              signature: hostSignature, isForwarding: false
          ) else {
        check(false, "the SSH ordering fixture builds")
        return
    }
    await resolver.register(PlainFixtureProvider(schemes: ["csec"], value: signingKey.privateKeyPEM))
    var failures: [String] = []
    for trial in 0..<12 {
        let trialBackend = InMemoryProtectedItemBackend()
        let owner = GrantPersistence(stores: .processLocal(trialBackend), facts: grantTestFacts)
        let table = GrantTable(persistence: owner)
        let ssh = SSHSigningService(
            resolver: resolver,
            catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [SSHKeyMetadata(
                reference: "csec://ssh-order/key", fingerprint: sshFingerprint(signingKey.publicKeyBlob),
                algorithm: "ssh-ed25519", publicKeyBlob: signingKey.publicKeyBlob, label: "order key"
            )])),
            consent: SilentApprovingConsent(), policyReview: SilentApprovingReview(),
            allowUnverifiedCallersForTesting: true,
            knownHostsLookup: SSHKnownHostsLookup { _ in ["order.example.test"] },
            terminalInspection: .unavailable,
            persistence: owner
        )
        let caller = CallerInfo(pid: me, startTime: myStart, description: "synthetic ordering")
        let revoked = await withTaskGroup(of: [String].self) { group -> [String] in
            for index in 0..<16 {
                group.addTask {
                    let grant = Grant(
                        rootPID: me, rootStartTime: myStart,
                        references: ["csec://order/T\(trial)-\(index)"], reason: "order"
                    )
                    await table.add(grant)
                    guard index % 3 == 0 else { return [] }
                    let id = grant.id.uuidString.lowercased()
                    _ = await table.revoke(idPrefix: id)
                    let failure = await owner.persistNow()
                    let now = await storedGrantsDocument(trialBackend)
                    if failure != nil || now?.secret.contains(where: { $0.id == grant.id }) == true {
                        return ["secret revoke \(id) not persisted at reply"]
                    }
                    return ["id:" + id]
                }
            }
            for index in 0..<6 {
                group.addTask {
                    let signed = try? await ssh.signSSHAuthentication(
                        publicKeyBlob: signingKey.publicKeyBlob,
                        signedData: userAuthenticationRequest(
                            sessionIdentifier: binding.sessionIdentifier, remoteUser: "user\(index)",
                            publicKeyBlob: signingKey.publicKeyBlob, hostKeyBlob: hostKey.publicKeyBlob
                        ),
                        flags: 0, binding: binding, caller: caller
                    )
                    guard signed != nil else { return ["ssh mint \(index) failed"] }
                    guard index % 2 == 0 else { return [] }
                    let listed = await ssh.grantSummaries()
                    guard let mine = listed.first(where: { $0.ssh?.remoteUser == "user\(index)" }) else {
                        return ["ssh grant \(index) not listed"]
                    }
                    _ = await ssh.revokeGrants(idPrefix: mine.id)
                    let failure = await owner.persistNow()
                    let now = await storedGrantsDocument(trialBackend)
                    if failure != nil || now?.ssh.contains(where: { $0.id.uuidString.lowercased() == mine.id }) == true {
                        return ["ssh revoke \(mine.id) not persisted at reply"]
                    }
                    return ["id:" + mine.id]
                }
            }
            var results: [String] = []
            for await result in group { results += result }
            return results
        }
        failures += revoked.filter { !$0.hasPrefix("id:") }
        await owner.settle()
        let final = await storedGrantsDocument(trialBackend)
        let revokedIDs = Set(revoked.filter { $0.hasPrefix("id:") }.map { String($0.dropFirst(3)) })
        let liveSecret = Set(await table.summaries(now: Date()).map(\.id))
        let liveSSH = Set(await ssh.grantSummaries().map(\.id))
        let storedSecret = Set(final?.secret.map { $0.id.uuidString.lowercased() } ?? [])
        let storedSSH = Set(final?.ssh.map { $0.id.uuidString.lowercased() } ?? [])
        if storedSecret != liveSecret || storedSSH != liveSSH {
            failures.append("trial \(trial): persisted state differs from the tables")
        }
        if !revokedIDs.isDisjoint(with: storedSecret.union(storedSSH)) {
            failures.append("trial \(trial): a revoked grant came back")
        }
    }
    check(failures.isEmpty,
          "interleaved secret and SSH mints and revocations persist the newest state and never resurrect a revocation (\(failures.prefix(3)))")
}

/// Approves every review with no session and says nothing (the dev-only
/// reviewer announces itself on stderr for every approval).
struct SilentApprovingReview: PolicyReviewProvider {
    func reviewAccess(_ review: AccessPolicyReview) async -> AccessPolicyReviewOutcome {
        .approved(AccessPolicyApproval(decidedOn: .mac))
    }
}

/// The consent a session-less approval falls back to, approving silently.
struct SilentApprovingConsent: ConsentProvider {
    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String,
        ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        .approved(unlock: nil)
    }

    func authenticate(reason: String) async -> ConsentOutcome { .approved(unlock: nil) }
}

// MARK: - Grants dropped at load (restart_not_restored)

private func droppedGrantQueryTests(me: pid_t, myStart: UInt64) async {
    guard let exited = exitedProcess() else {
        check(false, "the exited-root fixture runs")
        return
    }
    let backend = InMemoryProtectedItemBackend()
    let epochDropped = persistedSecretGrant(
        root: me, start: myStart, references: ["csec://dropped/A", "csec://dropped/B"],
        epoch: GrantPersistence.grantPolicyEpoch + 1, deliveryPlanDigest: "digest-1"
    )
    let expiredWidened = persistedSecretGrant(
        root: me, start: myStart, references: ["csec://dropped/W"],
        expiresAt: Date().addingTimeInterval(-10), deliveryPlanDigest: "digest-9",
        scopeKind: .terminalSession, scopeReuseDigest: "shape-1", auditSessionID: 5
    )
    let deadRoot = persistedSecretGrant(
        root: exited.pid, start: exited.start, references: ["csec://dropped/Z"], deliveryPlanDigest: "digest-1"
    )
    let survivor = persistedSecretGrant(root: me, start: myStart, references: ["csec://dropped/S"])
    let removedKey = persistedSSHGrant(root: me, start: myStart, fingerprint: "SHA256:gone-key")
    await writeGrantsDocument(GrantsDocument(
        secret: [epochDropped, expiredWidened, deadRoot, survivor], ssh: [removedKey]
    ), to: backend)
    let persistence = GrantPersistence(stores: .processLocal(backend), facts: grantTestFacts)
    _ = await persistence.load(registeredSchemes: ["csec"], sshKeyFingerprints: [])

    func covering(_ refs: Set<String>, digest: String? = "digest-1", shape: String? = nil,
                  session: UInt32? = nil, pid: pid_t? = nil, widenedOnly: Bool = false) async -> GrantDropReason? {
        await persistence.droppedGrantCovering(
            references: refs, callerPID: pid ?? me, deliveryPlanDigest: digest,
            releaseShapeDigest: shape, callerAuditSessionID: session, widenedScopeOnly: widenedOnly
        )
    }
    let single = await covering(["csec://dropped/A"])
    let both = await covering(["csec://dropped/A", "csec://dropped/B"])
    check(single == .policyEpoch && both == .policyEpoch,
          "a request a grant dropped at load would have covered names its drop reason")
    check(await covering(["csec://dropped/A", "csec://dropped/new"]) == nil,
          "a request the dropped grant covers only in part is not a re-ask")
    let otherDigest = await covering(["csec://dropped/A"], digest: "digest-2")
    let widenedOnly = await covering(["csec://dropped/A"], widenedOnly: true)
    check(otherDigest == nil && widenedOnly == nil,
          "a dropped grant keeps its reuse binding in the query")
    let sameSession = await covering(["csec://dropped/W"], digest: "other", shape: "shape-1", session: 5)
    let otherSession = await covering(["csec://dropped/W"], digest: "other", shape: "shape-1", session: 6)
    check(sameSession == .expired && otherSession == nil,
          "a dropped widened grant matches by release shape and audit session")
    check(await covering(["csec://dropped/A"], pid: 1) == nil,
          "a caller outside the dropped grant's root is not covered by it")
    check(await covering(["csec://dropped/Z"]) == nil,
          "a grant dropped because its root exited cannot cover anything")
    check(await covering(["csec://dropped/S"]) == nil,
          "a restored grant is not a dropped one")
    let sshReason = await persistence.droppedSSHGrantCovering(
        keyFingerprint: "SHA256:gone-key", hostKeyFingerprint: "SHA256:synthetic-host",
        remoteUser: "deploy", callerPID: me, callerAuditSessionID: nil, clientCDHash: nil
    )
    let otherUser = await persistence.droppedSSHGrantCovering(
        keyFingerprint: "SHA256:gone-key", hostKeyFingerprint: "SHA256:synthetic-host",
        remoteUser: "root", callerPID: me, callerAuditSessionID: nil, clientCDHash: nil
    )
    check(sshReason == .sshKeyRemoved && otherUser == nil,
          "a dropped SSH grant matches only its key, server identity and user")

    // A grant dropped for another reason whose chosen lifetime has passed
    // since would not have covered the request either.
    let lapsedBackend = InMemoryProtectedItemBackend()
    await writeGrantsDocument(GrantsDocument(secret: [
        persistedSecretGrant(
            root: me, start: myStart, references: ["csec://dropped/L"],
            epoch: GrantPersistence.grantPolicyEpoch + 1,
            expiresAt: Date().addingTimeInterval(3_600), deliveryPlanDigest: "digest-1"
        ),
    ]), to: lapsedBackend)
    let lapsed = GrantPersistence(stores: .processLocal(lapsedBackend), facts: grantTestFacts)
    _ = await lapsed.load(registeredSchemes: ["csec"], sshKeyFingerprints: [])
    let beforeLapse = await lapsed.droppedGrantCovering(
        references: ["csec://dropped/L"], callerPID: me, deliveryPlanDigest: "digest-1",
        releaseShapeDigest: nil, callerAuditSessionID: nil
    )
    let afterLapse = await lapsed.droppedGrantCovering(
        references: ["csec://dropped/L"], callerPID: me, deliveryPlanDigest: "digest-1",
        releaseShapeDigest: nil, callerAuditSessionID: nil, now: Date().addingTimeInterval(7_200)
    )
    check(beforeLapse == .policyEpoch && afterLapse == .expired,
          "a dropped grant whose chosen lifetime has since passed counts as expired, not as the restart's")

    // The precedence between this run's causes and the restart's.
    typealias Cause = DecisionLogPromptCause
    let table: [(Cause, GrantDropReason?, Cause)] = [
        (.newRefs, nil, .newRefs),
        (.newRefs, .policyEpoch, .restartNotRestored),
        (.newRefs, .unknownReference, .restartNotRestored),
        (.newProcess, .policyEpoch, .restartNotRestored),
        (.newRefs, .expired, .grantExpired),
        (.newProcess, .expired, .grantExpired),
        (.newProcess, nil, .newProcess),
        (.newReleaseShape, .policyEpoch, .newReleaseShape),
        (.grantExpired, .policyEpoch, .grantExpired),
        (.grantRevoked, .policyEpoch, .grantRevoked),
        (.grantRevoked, nil, .grantRevoked),
    ]
    let mismatches = table.filter { Cause.accountingForRestart(inRun: $0.0, droppedAtLoad: $0.1) != $0.2 }
    check(mismatches.isEmpty,
          "a restart re-ask is restart_not_restored unless this run already decided about the tree (\(mismatches.map { "\($0.0.rawValue)+\($0.1?.rawValue ?? "nil")" }))")
    check(Cause.restartNotRestored.rawValue == "restart_not_restored"
            && Cause.restartRestore.rawValue == "restart_restore",
          "the restart causes are spelled as the decision log records them")
}

// MARK: - The panel cause, wired (restart_not_restored)

private func restartCauseWiringTests(me: pid_t, myStart: UInt64) async {
    guard let outsider = exitedProcess() else {
        check(false, "the restart-cause fixtures run")
        return
    }
    func makeLog(_ stores: ProtectedStores) async -> DecisionLog {
        let log = DecisionLog(
            directory: SealedRecordDirectory(path: (NSTemporaryDirectory() as NSString)
                .appendingPathComponent("csec-restart-cause-\(UUID().uuidString)")),
            stores: stores
        )
        _ = await log.open()
        return log
    }
    func panelCauses(_ log: DecisionLog) async -> [String] {
        await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.panel])).records.compactMap(\.cause)
    }
    func plan(_ name: String) -> DeliveryPlan {
        DeliveryPlan(
            mechanism: .directHeap,
            executable: PlannedExecutable(canonicalPath: "/usr/bin/\(name)", assurance: .unverified),
            root: .caller, descendantScope: .subtree, destination: .localDevelopment,
            requestedTTLSeconds: 600, operationContext: "synthetic \(name)"
        )
    }

    // Secret access: a request the dropped grant covered, one no grant ever
    // covered, one a dropped expired grant covered, one whose dropped grant is
    // rooted outside this process tree; then a revocation this run.
    do {
        let first = plan("restartcause")
        let firstDigest = try first.digest()
        let backend = InMemoryProtectedItemBackend()
        let stores = ProtectedStores.processLocal(backend)
        await writeGrantsDocument(GrantsDocument(secret: [
            persistedSecretGrant(
                root: me, start: myStart, references: ["csec://cause/A"],
                epoch: GrantPersistence.grantPolicyEpoch + 1, deliveryPlanDigest: firstDigest
            ),
            persistedSecretGrant(
                root: me, start: myStart, references: ["csec://cause/E"],
                expiresAt: Date().addingTimeInterval(-60), deliveryPlanDigest: firstDigest
            ),
            persistedSecretGrant(
                root: outsider.pid, start: outsider.start, references: ["csec://cause/O"],
                epoch: GrantPersistence.grantPolicyEpoch + 1, deliveryPlanDigest: firstDigest
            ),
        ]), to: backend)
        let log = await makeLog(stores)
        let persistence = GrantPersistence(stores: stores, facts: grantTestFacts, decisionLog: log)
        _ = await persistence.load(registeredSchemes: ["csec"], sshKeyFingerprints: [])
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(PlainFixtureProvider(schemes: ["csec"], value: Data("synthetic-cause".utf8)))
        let agent = Agent(
            resolver: resolver, grants: GrantTable(persistence: persistence),
            consent: SilentApprovingConsent(), policyReview: SilentApprovingReview(),
            allowUnverifiedPlansForTesting: true, terminalInspection: .unavailable,
            decisionLog: log, grantPersistence: persistence
        )
        let caller = CallerInfo(pid: me, startTime: myStart, description: "synthetic cause caller")
        func ask(_ refs: [String], _ plan: DeliveryPlan) async -> Response {
            let request = try! AccessRequest(
                references: refs, reason: plan.operationContext, ttlSeconds: 600, deliveryPlan: plan
            )
            return await agent.handle(request: request, caller: caller)
        }
        let released = await ask(["csec://cause/A"], first)
        _ = await ask(["csec://cause/N"], first)
        _ = await ask(["csec://cause/E"], first)
        _ = await ask(["csec://cause/O"], first)
        let causes = await panelCauses(log)
        check(released.values != nil && causes == [
            "restart_not_restored", "new_refs", "grant_expired", "new_refs",
        ], "a panel a dropped grant would have spared records restart_not_restored (\(causes))")

        // Revoked this run: this run's decision explains the next panel.
        _ = await agent.handleGrants(request: GrantsRequest(action: .revoke, all: true), caller: caller)
        _ = await ask(["csec://cause/A"], first)
        let afterRevoke = await panelCauses(log)
        check(afterRevoke.last == "grant_revoked",
              "after a revocation this run, the next panel is grant_revoked, not the restart's")
    } catch {
        check(false, "the secret restart-cause fixture runs (\(error))")
    }

    // SSH: the same, for a dropped signing grant of this key, server and user.
    do {
        let signingKey = try Ed25519SSHFixture(seed: 227)
        let hostKey = try Ed25519SSHFixture(seed: 229)
        let session = Data(repeating: 0x61, count: 32)
        let binding = try SSHDestinationBinding(
            hostKeyBlob: hostKey.publicKeyBlob, sessionIdentifier: session,
            signature: hostKey.signatureBlob(for: session), isForwarding: false
        )
        let fingerprint = sshFingerprint(signingKey.publicKeyBlob)
        let backend = InMemoryProtectedItemBackend()
        let stores = ProtectedStores.processLocal(backend)
        await writeGrantsDocument(GrantsDocument(ssh: [
            persistedSSHGrant(
                root: me, start: myStart, fingerprint: fingerprint,
                hostKeyFingerprint: binding.hostKeyFingerprint, remoteUser: "deploy",
                epoch: GrantPersistence.grantPolicyEpoch + 1
            ),
        ]), to: backend)
        let log = await makeLog(stores)
        let persistence = GrantPersistence(stores: stores, facts: grantTestFacts, decisionLog: log)
        _ = await persistence.load(registeredSchemes: ["csec"], sshKeyFingerprints: [fingerprint])
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(PlainFixtureProvider(schemes: ["csec"], value: signingKey.privateKeyPEM))
        let ssh = SSHSigningService(
            resolver: resolver,
            catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore(keys: [SSHKeyMetadata(
                reference: "csec://ssh-cause/key", fingerprint: fingerprint,
                algorithm: "ssh-ed25519", publicKeyBlob: signingKey.publicKeyBlob, label: "cause key"
            )])),
            consent: SilentApprovingConsent(), policyReview: SilentApprovingReview(),
            allowUnverifiedCallersForTesting: true,
            knownHostsLookup: SSHKnownHostsLookup { _ in ["cause.example.test"] },
            terminalInspection: .unavailable,
            decisionLog: log,
            persistence: persistence
        )
        let caller = CallerInfo(pid: me, startTime: myStart, description: "synthetic SSH cause")
        func sign(_ user: String) async -> Bool {
            (try? await ssh.signSSHAuthentication(
                publicKeyBlob: signingKey.publicKeyBlob,
                signedData: userAuthenticationRequest(
                    sessionIdentifier: session, remoteUser: user,
                    publicKeyBlob: signingKey.publicKeyBlob, hostKeyBlob: hostKey.publicKeyBlob
                ),
                flags: 0, binding: binding, caller: caller
            )) != nil
        }
        let signed = await sign("deploy")
        _ = await sign("other")
        _ = await ssh.revokeAllGrants()
        _ = await sign("deploy")
        let causes = await panelCauses(log)
        check(signed && causes == ["restart_not_restored", "new_release_shape", "grant_revoked"],
              "an SSH panel a dropped signing grant would have spared is restart_not_restored; a revocation this run wins (\(causes))")
    } catch {
        check(false, "the SSH restart-cause fixture runs (\(error))")
    }

    // `csec revoke ssh-<id>` marks only SSH approvals: a secret approval whose
    // grant id shares the prefix keeps its own cause.
    do {
        let first = plan("revokekind")
        let resolver = SecretResolver(cache: NullSecretCache())
        await resolver.register(PlainFixtureProvider(schemes: ["csec"], value: Data("synthetic-kind".utf8)))
        let stores = ProtectedStores.processLocal()
        let log = await makeLog(stores)
        let persistence = GrantPersistence(stores: stores, facts: grantTestFacts, decisionLog: log)
        let ssh = SSHSigningService(
            resolver: resolver, catalog: SSHKeyCatalog(store: InMemorySSHKeyCatalogStore()),
            consent: SilentApprovingConsent(), policyReview: SilentApprovingReview(),
            allowUnverifiedCallersForTesting: true, terminalInspection: .unavailable,
            persistence: persistence
        )
        let grants = GrantTable(persistence: persistence)
        let agent = Agent(
            resolver: resolver, grants: grants, consent: SilentApprovingConsent(),
            policyReview: SilentApprovingReview(), sshSigningService: ssh,
            allowUnverifiedPlansForTesting: true, terminalInspection: .unavailable,
            decisionLog: log, grantPersistence: persistence
        )
        let caller = CallerInfo(pid: me, startTime: myStart, description: "synthetic kind caller")
        _ = await agent.handle(
            request: try AccessRequest(references: ["csec://kind/Z"], reason: "z", ttlSeconds: 600, deliveryPlan: first),
            caller: caller
        )
        guard let secretID = await grants.summaries(now: Date()).first?.id,
              let initial = secretID.first,
              let sshID = UUID(uuidString: "\(initial)0000000-0000-4000-8000-000000000000") else {
            check(false, "the revoke-kind fixture mints a secret grant")
            return
        }
        await ssh.restore([persistedSSHGrant(id: sshID, root: me, start: myStart, fingerprint: "SHA256:kind")])
        let revoked = await agent.handleGrants(
            request: GrantsRequest(action: .revoke, grantID: "ssh-\(initial)"), caller: caller
        )
        _ = await agent.handle(
            request: try AccessRequest(
                // Another delivery mechanism is another release shape, so the
                // live approval does not cover it and a panel follows.
                references: ["csec://kind/Z"], reason: "z", ttlSeconds: 600,
                deliveryPlan: DeliveryPlan(
                    mechanism: .unrestrictedInitialEnvironment,
                    executable: PlannedExecutable(canonicalPath: "/usr/bin/revokekind", assurance: .unverified),
                    root: .caller, descendantScope: .subtree, destination: .localDevelopment,
                    requestedTTLSeconds: 600, operationContext: "synthetic revokekind env",
                    outputGuard: OutputGuardPlan(mode: .tty)
                )
            ),
            caller: caller
        )
        let causes = await panelCauses(log)
        check(revoked.revokedGrantCount == 1 && causes == ["new_refs", "new_release_shape"],
              "revoking an SSH grant never marks a secret approval that shares its id prefix (\(causes))")
    } catch {
        check(false, "the revoke-kind fixture runs (\(error))")
    }
}

// MARK: - Cap evictions, recorded

private func evictionRecordTests(me: pid_t, myStart: UInt64) async {
    let stores = ProtectedStores.processLocal()
    let log = DecisionLog(
        directory: SealedRecordDirectory(path: (NSTemporaryDirectory() as NSString)
            .appendingPathComponent("csec-grant-eviction-\(UUID().uuidString)")),
        stores: stores
    )
    _ = await log.open()
    let persistence = GrantPersistence(stores: stores, facts: grantTestFacts, decisionLog: log)
    let base = Date(timeIntervalSince1970: 1_800_000_000)
    func secret(_ index: Int) -> Grant {
        Grant(
            rootPID: me, rootStartTime: myStart, references: ["csec://evict/K\(index)"],
            reason: "evict", mintedAt: base.addingTimeInterval(TimeInterval(index))
        )
    }
    let limit = GrantPersistence.maximumSecretGrants
    var grants = (0..<(limit + 6)).map(secret)
    let sshGrants = (0..<(GrantPersistence.maximumSSHGrants + 2)).map { index in
        persistedSSHGrant(
            root: me, start: myStart, fingerprint: "SHA256:evict-\(index)",
            mintedAt: base.addingTimeInterval(TimeInterval(index))
        )
    }
    func evictions() async -> [DecisionLogRecord] {
        await log.read(DecisionLogQuery(streams: [.decisions], kinds: [.grantEviction])).records
    }
    await persistence.update(secret: grants, generation: 1)
    await persistence.update(ssh: sshGrants, generation: 1)
    await persistence.settle()
    let recorded = await evictions()
    let evictedIDs = Set(recorded.flatMap { $0.grantIDs ?? [] })
    let expectedSecret = Set(grants.prefix(6).map { $0.id.uuidString.lowercased() })
    let expectedSSH = Set(sshGrants.prefix(2).map { "ssh-" + $0.id.uuidString.lowercased() })
    check(evictedIDs == expectedSecret.union(expectedSSH)
            && recorded.reduce(0) { $0 + ($1.grants?.secret ?? 0) } == 6
            && recorded.reduce(0) { $0 + ($1.grants?.ssh ?? 0) } == 2
            && recorded.allSatisfy { $0.stream == .decisions },
          "the oldest grants left out over the caps are recorded in the decisions stream (\(recorded.count) records)")

    // One more mint evicts one more grant, recorded once; a write that evicts
    // nothing new records nothing.
    grants.append(secret(limit + 6))
    await persistence.update(secret: grants, generation: 2)
    await persistence.settle()
    let afterMint = await evictions()
    let newest = afterMint.last?.grantIDs
    check(afterMint.count == recorded.count + 1
            && newest == [grants[6].id.uuidString.lowercased()],
          "a mint over the cap records exactly the one grant it newly leaves out")
    grants.removeLast()
    await persistence.update(secret: grants, generation: 3)
    await persistence.settle()
    _ = await persistence.persistNow()
    let afterNothingNew = await evictions()
    check(afterNothingNew.count == afterMint.count,
          "writes that leave out nothing new record nothing")
}
