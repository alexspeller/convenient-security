import ConvenientSecurity
import Foundation
import LocalAuthentication

// `csec edit --remove` (csec-0ls6): csecd deletes whole-file values from one
// native store behind one settings panel naming each of them, and refuses
// what its own registrations or a sidecar in place still use, before the
// touch whenever it can tell. In-memory Keychain and file backends; a real
// temporary directory stands in for where files were protected from.

func nativeStoreRemovalTests() async {
    print("\n# Deleting whole-file values from the native store (csec edit --remove)")
    removalWireTests()
    await removalServiceTests()
}

private func removalWireTests() {
    let request = NativeStoreRemovalRequest(references: ["csec://files/service_json", "csec://files/old_key"])
    do {
        let data = try JSONEncoder().encode(Request.removeNativeValues(request))
        guard case let .removeNativeValues(decoded) = try JSONDecoder().decode(Request.self, from: data) else {
            check(false, "removal: the request decodes as a removal")
            return
        }
        check(decoded.references == request.references && decoded.requestID == request.requestID,
              "removal: the request round-trips on the wire")
    } catch {
        check(false, "removal: the request round-trips on the wire (\(error))")
    }
    let malformed: [(String, [String])] = [
        ("no references", []),
        ("a reference to another provider", ["op://vault/item/field"]),
        ("references to two stores", ["csec://files/a", "csec://other/a"]),
        ("the same reference twice", ["csec://files/a", "csec://files/a"]),
        ("a reference not in canonical form (an upper-case scheme would miss the in-use checks)", ["CSEC://files/a"]),
        ("more references than the panel can name",
         (0...NativeStoreRemovalRequest.maximumReferences).map { "csec://files/k\($0)" }),
    ]
    for (label, references) in malformed {
        let refused = NativeStoreRemovalRequest(references: references)
        let decoded = (try? JSONEncoder().encode(Request.removeNativeValues(refused)))
            .flatMap { try? JSONDecoder().decode(Request.self, from: $0) }
        check(!refused.isWellFormed && decoded == nil, "removal: the decoder refuses \(label)")
    }
    check(NativeStoreRemovalRequest.maximumReferences == SettingsChangeReviewDetails.maximumChanges,
          "removal: one request names no more values than the settings panel shows lines")
}

/// The settings panel as the removal sees it: each touch it was shown, and a
/// local unlock when approved (in-memory backends only; it never prompts).
private actor RemovalPanel: ConsentProvider {
    private(set) var panels: [(change: SettingsChangeReviewDetails, caller: CallerInfo)] = []
    private(set) var bareSheets = 0
    private var approve = true

    func set(approve: Bool) { self.approve = approve }

    func requestConsent(
        caller: CallerInfo, newReferences: [SecretRef], reason: String, ttl: TimeInterval?, policySummary: String?
    ) async -> ConsentOutcome {
        .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        bareSheets += 1
        return .denied
    }

    func authenticateSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> ConsentAnswer {
        panels.append((change, caller))
        return approve ? .approved(unlock: CacheUnlock(LAContext())) : .refused(.unexplained)
    }
}

/// What csecd's registrations use, changeable mid-test, and everything the
/// service told csecd to forget or record.
private actor RemovalWorld {
    var uses: [String: String] = [:]
    /// Uses that appear only from the next check on, as a registration made
    /// while the panel is up would.
    var usesAfterNextCheck: [String: String]?
    var failChecks = false
    private(set) var checks = 0
    private(set) var forgotten: [Set<String>] = []
    private(set) var records: [(detail: String, references: [String])] = []

    func set(uses: [String: String], afterNextCheck: [String: String]? = nil, failing: Bool = false) {
        self.uses = uses
        usesAfterNextCheck = afterNextCheck
        failChecks = failing
    }

    func currentUses() throws -> [String: String] {
        checks += 1
        if failChecks { throw CocoaError(.fileReadUnknown) }
        defer {
            if let next = usesAfterNextCheck {
                uses = next
                usesAfterNextCheck = nil
            }
        }
        return uses
    }

    func forget(_ references: Set<String>) -> Int {
        forgotten.append(references)
        return 2
    }

    func record(_ detail: String, _ references: [String]) {
        records.append((detail, references))
    }
}

private func removalServiceTests() async {
    let base = FileManager.default.temporaryDirectory
        .appendingPathComponent("csec-removal-selftest-\(UUID().uuidString.lowercased())", isDirectory: true)
    let project = base.appendingPathComponent("project").path
    defer { try? FileManager.default.removeItem(at: base) }
    do {
        try FileManager.default.createDirectory(atPath: project + "/config", withIntermediateDirectories: true)
    } catch {
        check(false, "removal: the fixture directory is created (\(error))")
        return
    }
    let local = CacheUnlock(LAContext()) // in-memory backends only; never prompts
    let files = try! NativeStoreName("files")
    let keys = InMemoryNativeStoreKeyBackend()
    let ciphertext = InMemoryNativeStoreFileBackend()
    let blobs = NativeBlobStore(keyBackend: keys, fileBackend: ciphertext)
    do {
        _ = try await blobs.putBlobs(store: files, requests: [
            .init(key: "service_json", data: Data("{\"synthetic\":1}".utf8), mode: 0o600, path: "config/service.json"),
            .init(key: "old_key", data: Data("synthetic-old-key".utf8), mode: 0o600, path: "ssh-keys/id_rsa.old"),
            .init(key: "envrc", data: Data("export SYNTHETIC=1\n".utf8), mode: 0o600, path: ".envrc"),
            .init(key: "kept", data: Data("synthetic-kept".utf8), mode: 0o600, path: "kept.txt"),
        ], unlock: local)
    } catch {
        check(false, "removal: the fixture values are stored (\(error))")
        return
    }
    let service = "csec://files/service_json", oldKey = "csec://files/old_key"
    let envrc = "csec://files/envrc", kept = "csec://files/kept"

    let panel = RemovalPanel()
    let world = RemovalWorld()
    func makeService(_ store: NativeBlobStore) -> NativeStoreRemovalService {
        NativeStoreRemovalService(
            blobStore: store, consent: panel, terminalInspection: .unavailable,
            uses: { try await world.currentUses() },
            protectedFrom: { _ in [project] },
            forget: { await world.forget($0) },
            record: { await world.record($0, $1) }
        )
    }
    let removal = makeService(blobs)
    func remove(_ references: [String], with removal: NativeStoreRemovalService? = nil) async -> Response {
        await (removal ?? makeService(blobs)).handle(NativeStoreRemovalRequest(references: references), caller: setupCaller)
    }
    // Read through a store of its own: a removal by another instance leaves
    // an instance's warm record behind its index.
    func stored() async -> Set<String> {
        let reader = NativeBlobStore(keyBackend: keys, fileBackend: ciphertext)
        return Set(((try? await reader.list(store: files, unlock: local)) ?? [:]).keys)
    }
    let everything: Set<String> = ["service_json", "old_key", "envrc", "kept"]

    // MARK: Refused before the touch.
    await world.set(uses: [oldKey: "the SSH key SHA256:synthetic (csec ssh remove SHA256:synthetic removes it)"])
    let registered = await removal.handle(NativeStoreRemovalRequest(references: [oldKey]), caller: setupCaller)
    check(registered.failure?.code == .policyDenied
            && registered.failure?.message.contains("\(oldKey) is the SSH key SHA256:synthetic") == true
            && registered.failure?.message.hasSuffix("nothing was removed") == true,
          "removal: a value a registration uses is refused, naming the registration")
    var panels = await panel.panels.count
    let storedAfterRegistered = await stored()
    check(panels == 0 && storedAfterRegistered == everything, "removal: a registered value costs no touch and stays")

    await world.set(uses: [:], failing: true)
    let unknownUses = await remove([oldKey])
    panels = await panel.panels.count
    let storedAfterUnknownUses = await stored()
    check(unknownUses.failure?.code == .internalError && panels == 0 && storedAfterUnknownUses == everything,
          "removal: when csecd cannot tell what uses a value, nothing is asked or removed")
    await world.set(uses: [:])

    let missing = await remove(["csec://files/never_stored"])
    panels = await panel.panels.count
    check(missing.failure?.code == .referenceNotFound
            && missing.failure?.message.contains("not a whole-file value") == true
            && missing.failure?.message.contains("csec edit files") == true
            && panels == 0,
          "removal: a key the warm index lacks is refused before the touch, pointing at the document editor")
    let mixed = await remove([service, "csec://files/never_stored"])
    let storedAfterMixed = await stored()
    check(mixed.failure?.code == .referenceNotFound && storedAfterMixed == everything,
          "removal: one missing value fails the whole request, so nothing is half done")
    let noStore = await remove(["csec://no-such-store/a"])
    panels = await panel.panels.count
    check(noStore.failure?.code == .referenceNotFound && panels == 0,
          "removal: a store with no whole-file tier is refused before the touch")

    // The value's own sidecar, still where the file was protected from.
    let sidecarPath = project + "/config/service.json" + ProtectedFileSidecar.suffix
    do {
        try ProtectedFileSidecar(reference: SecretRef(service)).encoded()
            .write(to: URL(fileURLWithPath: sidecarPath))
        try ProtectedFileSidecar(reference: SecretRef("csec://elsewhere/envrc")).encoded()
            .write(to: URL(fileURLWithPath: project + "/.envrc" + ProtectedFileSidecar.suffix))
    } catch {
        check(false, "removal: the fixture sidecars are written (\(error))")
    }
    let inPlace = await remove([service])
    panels = await panel.panels.count
    let storedAfterSidecar = await stored()
    check(inPlace.failure?.code == .policyDenied
            && inPlace.failure?.message.contains("still used by the sidecar") == true
            && inPlace.failure?.message.contains("config/service.json.csec") == true
            && panels == 0 && storedAfterSidecar == everything,
          "removal: a value whose sidecar is still in place is refused, naming the sidecar")

    // MARK: The panel.
    await panel.set(approve: false)
    let denied = await remove([envrc])
    let forgottenAfterDenial = await world.forgotten.count
    let storedAfterDenial = await stored()
    check(denied.failure?.code == .consentDenied && storedAfterDenial == everything && forgottenAfterDenial == 0,
          "removal: a refused panel removes and forgets nothing")
    await panel.set(approve: true)

    let removed = await remove([envrc, oldKey])
    let shown = await panel.panels.last
    let bareSheets = await panel.bareSheets
    check(removed.failure == nil
            && removed.nativeStoreRemoval?.removed == [
                .init(reference: envrc, path: ".envrc"), .init(reference: oldKey, path: "ssh-keys/id_rsa.old"),
            ]
            && removed.nativeStoreRemoval?.revokedGrants == 2,
          "removal: an approved panel deletes the named values and reports their recorded paths "
              + "(a sidecar naming another value does not block one)")
    let storedAfterRemoval = await stored()
    check(storedAfterRemoval == ["service_json", "kept"],
          "removal: exactly the named values are gone and the store's others stay")
    let keptValue = try? await blobs.loadBlob(store: files, key: "kept", unlock: nil)
    check(keptValue?.data == Data("synthetic-kept".utf8), "removal: a value left in the store still reads back")
    check(shown?.change.title == "Delete 2 Stored Files"
            && shown?.change.changes == [
                "Delete \(envrc) from csec's native store, with every grant for it",
                "Delete \(oldKey) from csec's native store, with every grant for it",
            ]
            && shown?.change.footnote == "Touch ID deletes exactly these values from Convenient Security's "
                + "native store. No secret is released."
            && shown?.caller.pid == setupCaller.pid && shown?.caller.terminal != nil
            && bareSheets == 0,
          "removal: the one touch is csecd's settings panel for the csec that asked, naming every value")
    let forgotten = await world.forgotten
    let records = await world.records
    check(forgotten == [[envrc, oldKey]], "removal: the deleted values' grants, pairings and cached copies are dropped")
    check(records.count == 1 && records[0].references == [envrc, oldKey]
            && records[0].detail == "deleted 2 whole-file values from native store files; 2 grants revoked",
          "removal: the deletion goes in the decision log with its references")
    let again = await remove([envrc])
    check(again.failure?.code == .referenceNotFound, "removal: a deleted value cannot be deleted twice")

    // MARK: A cold store: only the touch can tell, and the checks run again.
    try? FileManager.default.removeItem(atPath: sidecarPath)
    let coldPanelsBefore = await panel.panels.count
    let coldMissing = await remove(["csec://files/never_stored"], with: makeService(
        NativeBlobStore(keyBackend: keys, fileBackend: ciphertext)
    ))
    var coldPanels = await panel.panels.count - coldPanelsBefore
    check(coldMissing.failure?.code == .referenceNotFound && coldPanels == 1,
          "removal: a cold store is opened by the touch, and a missing value is still refused after it")
    await world.set(uses: [:], afterNextCheck: [kept: "used by the automation job nightly"])
    let raced = await remove([kept], with: makeService(NativeBlobStore(keyBackend: keys, fileBackend: ciphertext)))
    coldPanels = await panel.panels.count - coldPanelsBefore
    let storedAfterRace = await stored()
    check(raced.failure?.code == .policyDenied && coldPanels == 2 && storedAfterRace.contains("kept"),
          "removal: a registration made while the panel was up still stops the deletion")
    await world.set(uses: [:])
    let coldRemoved = await remove([service], with: makeService(NativeBlobStore(keyBackend: keys, fileBackend: ciphertext)))
    let storedAfterColdRemoval = await stored()
    check(coldRemoved.nativeStoreRemoval?.removed == [.init(reference: service, path: "config/service.json")]
            && storedAfterColdRemoval == ["kept"],
          "removal: once its sidecar is gone, a value in a cold store is deleted after one touch")
}
