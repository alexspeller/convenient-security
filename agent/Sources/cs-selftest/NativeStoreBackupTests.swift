import ConvenientSecurity
import CryptoKit
import Foundation
import LocalAuthentication

// Native-store backups: the recovery kit, sealed bundles, the providers'
// write-path hooks, and a restore onto a second, empty Mac. Each "Mac" is its
// own pair of real ciphertext directories (so the on-disk store listing is
// exercised) over in-memory Keychain backends; the backup folder is a
// temporary directory standing in for iCloud Drive.

func nativeStoreBackupTests() async {
    print("\n# Native-store backups (sealed bundles for surviving the loss of this Mac)")
    backupKitTests()
    backupBundleTests()
    backupProtocolTests()
    await backupProviderAndRestoreTests()
}

// MARK: - Recovery kit

private func backupKitTests() {
    do {
        let kit = try BackupRecoveryKit.generate()
        let text = kit.formatted
        let groups = text.split(separator: "-")
        check(groups.first == "CSEC" && groups.count == 15 && groups.dropFirst().allSatisfy { $0.count == 4 },
              "a recovery kit reads CSEC then 14 groups of four characters")
        check((try? BackupRecoveryKit(parsing: text))?.formatted == text, "a kit parses back to itself")
        check((try? BackupRecoveryKit(parsing: text.lowercased()))?.formatted == text,
              "a kit typed in lower case parses")
        check((try? BackupRecoveryKit(parsing: text.replacingOccurrences(of: "-", with: " ")))?.formatted == text,
              "a kit with spaces for dashes parses")
        check((try? BackupRecoveryKit(parsing: String(text.dropFirst(5))))?.formatted == text,
              "a kit typed without its CSEC prefix parses")
        let confusable = String(text.dropFirst(5))
            .replacingOccurrences(of: "0", with: "O").replacingOccurrences(of: "1", with: "l")
        check((try? BackupRecoveryKit(parsing: confusable))?.formatted == text,
              "O for 0 and l for 1 read as Crockford intends")
        var characters = Array(text)
        let index = 7 // inside the first secret group
        characters[index] = characters[index] == "A" ? "B" : "A"
        checkThrows("a kit with one wrong character is refused by its check group") {
            _ = try BackupRecoveryKit(parsing: String(characters))
        }
        checkThrows("a truncated kit is refused") { _ = try BackupRecoveryKit(parsing: String(text.dropLast(5))) }
        checkThrows("text that is not a kit is refused") { _ = try BackupRecoveryKit(parsing: "CSEC-not-a-key") }
        check((try BackupRecoveryKit.generate()).formatted != text, "two generated kits differ")
        // The 52nd character carries 1 bit of the secret and 4 of padding:
        // setting a padding bit spells the same secret another way.
        let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        var padded = Array(text.dropFirst(5).replacingOccurrences(of: "-", with: ""))
        let last = alphabet.firstIndex(of: padded[51])!
        padded[51] = alphabet[last | 1 == last ? last ^ 2 : last | 1]
        checkThrows("a kit whose padding bits are set is refused, so each secret has one spelling") {
            _ = try BackupRecoveryKit(parsing: String(padded))
        }
    } catch {
        check(false, "recovery kit tests ran (\(error))")
    }
}

// MARK: - Bundles

private func backupBundleTests() {
    do {
        let kit = try BackupRecoveryKit.generate()
        let backupID = "00112233445566778899aabbccddeeff"
        let material = kit.material(backupID: backupID)
        let store = try NativeStoreName("bundle-a")
        let fileID = String(repeating: "ab", count: 16)
        let record = NativeStoreKeyRecord(
            keyData: Data(repeating: 7, count: 32), generation: 3,
            activeFileID: fileID, ciphertextDigest: String(repeating: "cd", count: 32)
        )
        let contents = NativeStoreBackupContents.store(
            .documents, store, record: record,
            files: ["bundle-a.\(fileID).csec": Data("synthetic-ciphertext".utf8)],
            createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let item = NativeStoreBackupItem.store(.documents, store)
        let name = material.bundleFileName(item)
        let sealed = try NativeStoreBackupBundle.seal(contents, material: material)
        let opened = try NativeStoreBackupBundle.open(sealed, fileName: name, backupID: backupID, kit: kit)
        check(opened == contents, "a bundle opens under its kit to exactly what was sealed")
        check(!name.contains("bundle-a") && name.hasSuffix(NativeStoreBackupBundle.fileExtension),
              "a bundle's file name does not name its store")
        check(name != material.bundleFileName(.store(.blobs, store)) && name != material.bundleFileName(.sshCatalog),
              "each tier and the SSH catalog get their own bundle name")
        check(sealed.range(of: Data("bundle-a".utf8)) == nil && sealed.range(of: Data("synthetic-ciphertext".utf8)) == nil,
              "nothing of the store shows in the bundle's bytes")
        check(NativeStoreBackupBundle.backupID(of: sealed) == backupID, "the cleartext header names only the backup")

        let otherKit = try BackupRecoveryKit.generate()
        checkThrows("another kit cannot open the bundle") {
            _ = try NativeStoreBackupBundle.open(sealed, fileName: name, backupID: backupID, kit: otherKit)
        }
        var flipped = sealed
        flipped[flipped.count / 2] ^= 0x01
        checkThrows("a bundle with one byte changed is refused") {
            _ = try NativeStoreBackupBundle.open(flipped, fileName: name, backupID: backupID, kit: kit)
        }
        checkThrows("a bundle moved to another store's file name is refused") {
            _ = try NativeStoreBackupBundle.open(
                sealed, fileName: material.bundleFileName(.store(.blobs, store)), backupID: backupID, kit: kit
            )
        }
        checkThrows("a bundle found in another backup's folder is refused") {
            _ = try NativeStoreBackupBundle.open(
                sealed, fileName: name, backupID: "ffeeddccbbaa99887766554433221100", kit: kit
            )
        }

        // Someone with the public key and file-name key but not the MAC key
        // (anyone who saw csecd's material without its access group) cannot
        // plant a bundle a restore would import.
        var forged = try JSONSerialization.jsonObject(with: JSONEncoder().encode(material)) as! [String: Any]
        forged["authenticationKey"] = Data((0..<32).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
        let forgedMaterial = try JSONDecoder().decode(
            NativeStoreBackupPublicMaterial.self, from: JSONSerialization.data(withJSONObject: forged)
        )
        let planted = try NativeStoreBackupBundle.seal(contents, material: forgedMaterial)
        checkThrows("a bundle sealed to the right key without csecd's MAC key is refused") {
            _ = try NativeStoreBackupBundle.open(planted, fileName: name, backupID: backupID, kit: kit)
        }

        let fixture = try Ed25519SSHFixture(seed: 41)
        let key = SSHKeyMetadata(
            reference: "csec://ssh-keys/id_ed25519", fingerprint: sshFingerprint(fixture.publicKeyBlob),
            algorithm: "ssh-ed25519", publicKeyBlob: fixture.publicKeyBlob, label: "synthetic"
        )
        let catalog = NativeStoreBackupContents(
            item: .sshCatalog, body: .sshCatalog([key]), createdAt: Date(timeIntervalSince1970: 1_700_000_000)
        )
        let catalogName = material.bundleFileName(.sshCatalog)
        let catalogOpened = try NativeStoreBackupBundle.open(
            try NativeStoreBackupBundle.seal(catalog, material: material),
            fileName: catalogName, backupID: backupID, kit: kit
        )
        check(catalogOpened == catalog, "the SSH catalog's bundle round-trips its public metadata")
    } catch {
        check(false, "bundle tests ran (\(error))")
    }
}

// MARK: - Protocol

private func backupProtocolTests() {
    do {
        let request = NativeStoreBackupRequest(action: .restore, recoveryKit: "CSEC-SYNTHETIC", folder: "/tmp/x")
        let data = try JSONEncoder().encode(Request.nativeStoreBackup(request))
        guard case let .nativeStoreBackup(decoded) = try JSONDecoder().decode(Request.self, from: data) else {
            check(false, "a backup request decodes as one")
            return
        }
        check(decoded.action == .restore && decoded.recoveryKit == "CSEC-SYNTHETIC" && decoded.folder == "/tmp/x"
              && decoded.requestID == request.requestID,
              "a backup request round-trips on the wire")
        let kitOnStatus = NativeStoreBackupRequest(action: .status, recoveryKit: "CSEC-SYNTHETIC")
        let refused = try JSONEncoder().encode(Request.nativeStoreBackup(kitOnStatus))
        checkThrows("a recovery kit is accepted only by the restore actions") {
            _ = try JSONDecoder().decode(Request.self, from: refused)
        }
        check(!NativeStoreBackupRequest(action: .completeSetup).isWellFormed,
              "completing setup needs the session begin_setup returned")
        check(!NativeStoreBackupRequest(action: .sync, folder: "/tmp/x").isWellFormed,
              "only setup and restore take a folder")
    } catch {
        check(false, "protocol tests ran (\(error))")
    }
}

// MARK: - Providers, setup, sync and restore

/// One Mac's storage: what survives a csecd restart.
private struct BackupTestMac {
    let docKeys = InMemoryNativeStoreKeyBackend()
    let blobKeys = InMemoryNativeStoreKeyBackend()
    let items = InMemoryProtectedItemBackend()
    let catalogStore = InMemorySSHKeyCatalogStore()
    let docDirectory: String
    let blobDirectory: String
    let clock: BackupTestClock

    init(_ base: URL, clockStart: TimeInterval) {
        docDirectory = base.appendingPathComponent("Secrets").path
        blobDirectory = base.appendingPathComponent("Secrets/Blobs").path
        clock = BackupTestClock(start: clockStart)
    }
}

/// Each Mac's own clock, a millisecond further on at every read, so which
/// bundle is newest never depends on how fast the test runs.
private final class BackupTestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var current: TimeInterval

    init(start: TimeInterval) { current = start }

    func now() -> Date {
        lock.lock()
        defer { lock.unlock() }
        current += 0.001
        return Date(timeIntervalSince1970: current)
    }
}

private struct BackupTestRun {
    let backup: NativeStoreBackup
    let blobs: NativeBlobStore
    let provider: NativeEncryptedFileProvider
    let catalog: SSHKeyCatalog
    let service: NativeStoreBackupService
}

private actor CountingBackupConsent: ConsentProvider {
    private(set) var authentications = 0
    /// Each touch as csecd's settings panel would show it, and for whom.
    private(set) var panels: [(change: SettingsChangeReviewDetails, caller: CallerInfo)] = []
    /// Bare sheets asked for: never, now that every step takes the panel.
    private(set) var bareSheets = 0
    let approve: Bool

    init(approve: Bool = true) { self.approve = approve }

    func requestConsent(caller: CallerInfo, newReferences: [SecretRef], reason: String,
                        ttl: TimeInterval?, policySummary: String?) async -> ConsentOutcome {
        .denied
    }

    func authenticate(reason: String) async -> ConsentOutcome {
        bareSheets += 1
        authentications += 1
        // In-memory backends only; this context never prompts.
        return approve ? .approved(unlock: CacheUnlock(LAContext())) : .denied
    }

    func authenticateSettingsChange(
        _ change: SettingsChangeReviewDetails, caller: CallerInfo, reason: String
    ) async -> ConsentAnswer {
        panels.append((change, caller))
        authentications += 1
        return approve ? .approved(unlock: CacheUnlock(LAContext())) : .refused(.unexplained)
    }
}

private func bootBackupRun(
    _ mac: BackupTestMac,
    root: String,
    consent: ConsentProvider,
    maximumBundleBytes: Int = NativeStoreBackupBundle.maximumBytes
) throws -> BackupTestRun {
    let clock = mac.clock
    let backup = NativeStoreBackup(
        stores: .processLocal(mac.items),
        locations: NativeStoreBackupLocations(
            root: root, documentDirectory: mac.docDirectory, blobDirectory: mac.blobDirectory
        ),
        maximumBundleBytes: maximumBundleBytes,
        now: { clock.now() }
    )
    let blobs = NativeBlobStore(
        keyBackend: mac.blobKeys,
        fileBackend: try SecureNativeStoreFileBackend(directoryPath: mac.blobDirectory),
        backup: backup
    )
    let provider = NativeEncryptedFileProvider(
        keyBackend: mac.docKeys,
        fileBackend: try SecureNativeStoreFileBackend(directoryPath: mac.docDirectory),
        blobStore: blobs,
        backup: backup
    )
    let catalog = SSHKeyCatalog(store: mac.catalogStore, backup: backup)
    let service = NativeStoreBackupService(
        backup: backup, nativeStore: provider, blobStore: blobs, catalog: catalog, consent: consent,
        terminalInspection: .unavailable
    )
    return BackupTestRun(backup: backup, blobs: blobs, provider: provider, catalog: catalog, service: service)
}

/// Name, size, inode and modification time of every file in a folder.
private func folderSnapshot(_ path: String) -> [String: [Int64]] {
    var snapshot: [String: [Int64]] = [:]
    for name in (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? [] {
        var info = stat()
        guard lstat((path as NSString).appendingPathComponent(name), &info) == 0 else { continue }
        snapshot[name] = [Int64(info.st_size), Int64(info.st_ino),
                          Int64(info.st_mtimespec.tv_sec), Int64(info.st_mtimespec.tv_nsec)]
    }
    return snapshot
}

private func backupFolders(_ root: String) -> [String] {
    ((try? FileManager.default.contentsOfDirectory(atPath: root)) ?? [])
        .filter { $0.count == 32 }.sorted().map { (root as NSString).appendingPathComponent($0) }
}

private func backupProviderAndRestoreTests() async {
    let base = FileManager.default.temporaryDirectory
        .appendingPathComponent("csec-backup-selftest-\(UUID().uuidString.lowercased())", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: base) }
    let root = base.appendingPathComponent("Backups").path
    let local = CacheUnlock(LAContext()) // in-memory backends only; never prompts
    let caller = CallerInfo(pid: getpid(), startTime: 1, description: "synthetic csec")
    let otherCaller = CallerInfo(pid: getpid(), startTime: 2, description: "another csec")
    let alpha = try! NativeStoreName("alpha")
    let beta = try! NativeStoreName("beta")
    let sshKeys = try! NativeStoreName("ssh-keys")
    let tokenRef = try! SecretRef("csec://alpha/API_TOKEN")
    let fileRef = try! SecretRef("csec://alpha/service_json")
    let betaRef = try! SecretRef("csec://beta/API_TOKEN")
    let sshRef = try! SecretRef("csec://ssh-keys/id_ed25519")
    var kitText = ""

    func commit(_ run: BackupTestRun, _ store: NativeStoreName, _ values: [String: String]) async throws {
        let session = try await run.provider.beginEdit(store: store, callerPID: 4_242, callerStartTime: 1, unlock: local)
        _ = try await run.provider.commitEdit(
            sessionID: session.sessionID, document: try NativeStoreDocument(values: values).encoded(),
            callerPID: 4_242, callerStartTime: 1
        )
    }
    func value(_ run: BackupTestRun, _ ref: SecretRef, unlock: CacheUnlock? = nil) async -> String? {
        guard let resolved = try? await run.provider.resolve(ref, unlock: unlock) else { return nil }
        return String(decoding: resolved.value, as: UTF8.self)
    }
    func entry(_ status: NativeStoreBackupStatus, _ kind: String, _ store: String) -> NativeStoreBackupStatus.Store? {
        status.stores.first { $0.kind == kind && $0.store == store }
    }
    func restore(_ run: BackupTestRun, preview: Bool = false) async -> Response {
        await run.service.handle(
            NativeStoreBackupRequest(action: preview ? .previewRestore : .restore, recoveryKit: kitText, folder: root),
            caller: caller
        )
    }

    do {
        let consentA = CountingBackupConsent()
        let macA = BackupTestMac(base.appendingPathComponent("mac-a"), clockStart: 1_700_000_000)
        let runA = try bootBackupRun(macA, root: root, consent: consentA)
        let fixture = try Ed25519SSHFixture(seed: 9)

        // MARK: Before setup: stores exist only on this Mac.
        try await commit(runA, alpha, ["API_TOKEN": "synthetic-alpha-1"])
        try await commit(runA, beta, ["API_TOKEN": "synthetic-beta-a"])
        _ = try await runA.blobs.putBlobs(
            store: alpha,
            requests: [.init(key: "service_json", data: Data("{\"synthetic\":1}".utf8), mode: 0o600, path: "config/service.json")],
            unlock: local
        )
        _ = try await runA.blobs.putBlobs(
            store: sshKeys,
            requests: [.init(key: "id_ed25519", data: fixture.privateKeyPEM, mode: 0o600, path: ".ssh/id_ed25519")],
            unlock: local
        )
        try await runA.catalog.register([SSHKeyMetadata(
            reference: sshRef.uri, fingerprint: sshFingerprint(fixture.publicKeyBlob),
            algorithm: "ssh-ed25519", publicKeyBlob: fixture.publicKeyBlob, label: "synthetic"
        )])
        let off = await runA.backup.status()
        check(off.state == .off && off.stores.count == 4 && off.stores.allSatisfy { $0.state == .notBackedUp },
              "with backups off, status lists the four store tiers on this Mac, none backed up")
        check(NativeStoreBackupStatusReport.doctorRow(off).state == .warn,
              "doctor warns while native stores exist and backups are off")
        check(!FileManager.default.fileExists(atPath: root), "nothing is written anywhere before setup")

        // MARK: Setup: a kit only csecd made, one Touch ID, every store backed up.
        let begun = await runA.service.handle(NativeStoreBackupRequest(action: .beginSetup, folder: root), caller: caller)
        guard let sessionID = begun.nativeStoreBackup?.setupSessionID,
              let generated = begun.nativeStoreBackup?.recoveryKit else {
            check(false, "begin_setup returns a session and a kit")
            return
        }
        kitText = generated
        let touchesAfterKit = await consentA.authentications
        check(touchesAfterKit == 0, "showing the kit needs no Touch ID and changes nothing")
        let stolen = await runA.service.handle(
            NativeStoreBackupRequest(action: .completeSetup, sessionID: sessionID), caller: otherCaller
        )
        check(stolen.failure?.code == .invalidRequest, "another csec cannot complete this csec's setup")
        let completed = await runA.service.handle(
            NativeStoreBackupRequest(action: .completeSetup, sessionID: sessionID), caller: caller
        )
        let touchesAfterSetup = await consentA.authentications
        check(completed.failure == nil && touchesAfterSetup == 1, "completing setup takes exactly one Touch ID")
        let setupPanel = await consentA.panels.last
        check(setupPanel?.change.title == "Turn On Native-Store Backups"
              && setupPanel?.change.changes.last == "Folder: \(root)"
              && setupPanel?.change.footnote == "Touch ID lets Convenient Security read its native stores to seal them "
                  + "into the backup. No secret is released."
              && setupPanel?.caller.pid == caller.pid && setupPanel?.caller.startTime == caller.startTime
              && setupPanel?.caller.terminal != nil,
              "setup's Touch ID is csecd's settings panel, for the csec that asked, naming its tab and the folder (csec-0.60)")
        let report = completed.nativeStoreBackup?.report
        check(report?.written == 5 && report?.failed == 0, "setup backs up all four store tiers and the SSH catalog")
        let on = await runA.backup.status()
        check(on.state == .on && on.stores.count == 5 && on.problems.isEmpty,
              "after setup every store tier and the catalog is current")
        check(NativeStoreBackupStatusReport.doctorRow(on).state == .ok, "doctor is content once everything is backed up")
        let again = await runA.service.handle(
            NativeStoreBackupRequest(action: .completeSetup, sessionID: sessionID), caller: caller
        )
        check(again.failure?.code == .invalidRequest, "a setup session completes once")
        guard let folderA = on.folder else {
            check(false, "status names the backup folder")
            return
        }
        let bundleNames = (try? FileManager.default.contentsOfDirectory(atPath: folderA)) ?? []
        check(bundleNames.filter { $0.hasSuffix(NativeStoreBackupBundle.fileExtension) }.count == 5
              && !bundleNames.contains { $0.contains("alpha") || $0.contains("beta") || $0.contains("ssh") },
              "the folder holds five bundles whose names say nothing about the stores")
        check(FileManager.default.fileExists(atPath: (root as NSString).appendingPathComponent(NativeStoreBackup.readmeName)),
              "a backup root csec made explains itself in a README")

        // MARK: Steady state: every write refreshes its bundle, no prompt.
        let before = entry(on, "doc", "alpha")?.generation
        try await commit(runA, alpha, ["API_TOKEN": "synthetic-alpha-2"])
        let afterEdit = await runA.backup.status()
        check(entry(afterEdit, "doc", "alpha")?.generation == (before ?? 0) + 1 && afterEdit.problems.isEmpty,
              "an edit refreshes its store's bundle")
        let blobBefore = entry(afterEdit, "blob", "alpha")?.generation
        _ = try await runA.blobs.putBlobs(
            store: alpha,
            requests: [.init(key: "service_json", data: Data("{\"synthetic\":2}".utf8), mode: 0o600, path: "config/service.json")],
            unlock: local
        )
        let afterBlob = await runA.backup.status()
        check(entry(afterBlob, "blob", "alpha")?.generation == (blobBefore ?? 0) + 1,
              "a blob import refreshes the blob tier's bundle")
        let touchesSteady = await consentA.authentications
        check(touchesSteady == 1, "keeping bundles current asks for nothing")

        // MARK: An older record never replaces a newer bundle.
        let stale = NativeStoreBackupContents.store(
            .documents, alpha,
            record: NativeStoreKeyRecord(
                keyData: Data(repeating: 1, count: 32), generation: 1,
                activeFileID: String(repeating: "0", count: 32), ciphertextDigest: String(repeating: "0", count: 64)
            ),
            files: [:], createdAt: Date()
        )
        let staleOutcome = await runA.backup.write(stale)
        check(staleOutcome == .written, "a record of another lineage (a recreated store) is written")
        let afterStale = await runA.backup.status()
        try await commit(runA, alpha, ["API_TOKEN": "synthetic-alpha-3"])
        let afterRecommit = await runA.backup.status()
        check(entry(afterStale, "doc", "alpha")?.generation == 1
              && entry(afterRecommit, "doc", "alpha")?.generation == (before ?? 0) + 2,
              "the real store's next change takes its bundle back")

        // MARK: A bundle put back from earlier is noticed, though it is the same size.
        let alphaDocName = on.stores.isEmpty ? "" : ((try? FileManager.default.contentsOfDirectory(atPath: folderA)) ?? [])
            .filter { $0.hasSuffix(NativeStoreBackupBundle.fileExtension) }.sorted().first ?? ""
        let alphaDocPath = (folderA as NSString).appendingPathComponent(alphaDocName)
        let savedBytes = try Data(contentsOf: URL(fileURLWithPath: alphaDocPath))
        let saved = base.appendingPathComponent("saved-bundle")
        try savedBytes.write(to: saved)
        try FileManager.default.removeItem(atPath: alphaDocPath)
        try FileManager.default.moveItem(at: saved, to: URL(fileURLWithPath: alphaDocPath))
        let swapped = await runA.backup.status()
        check(swapped.stores.contains { $0.state == .missingOrChanged },
              "a bundle replaced by an identical-size copy reads as changed")
        let resynced = await runA.service.handle(NativeStoreBackupRequest(action: .sync), caller: caller)
        let afterResync = await runA.backup.status()
        check(resynced.failure == nil && afterResync.problems.isEmpty, "sync rewrites the replaced bundle")

        // MARK: A failed bundle never fails the write, and heals.
        try FileManager.default.removeItem(atPath: folderA)
        FileManager.default.createFile(atPath: folderA, contents: Data("not a folder".utf8))
        try await commit(runA, alpha, ["API_TOKEN": "synthetic-alpha-4"])
        let writtenWhileBroken = await value(runA, tokenRef)
        check(writtenWhileBroken == "synthetic-alpha-4", "a store write succeeds while its bundle cannot be written")
        let broken = await runA.backup.status()
        check(entry(broken, "doc", "alpha")?.state == .failed
              && NativeStoreBackupStatusReport.doctorRow(broken).state == .warn,
              "the failed bundle shows in status and as a doctor warning")
        try FileManager.default.removeItem(atPath: folderA)
        let synced = await runA.service.handle(NativeStoreBackupRequest(action: .sync), caller: caller)
        let afterSync = await runA.backup.status()
        let touchesAfterSync = await consentA.authentications
        check(synced.nativeStoreBackup?.report?.failed == 0 && afterSync.problems.isEmpty && touchesAfterSync == 3,
              "csec backup sync rewrites what was lost with one Touch ID")
        let syncPanel = await consentA.panels.last
        let bareSheetsA = await consentA.bareSheets
        check(syncPanel?.change.title == "Back Up Native Stores" && syncPanel?.caller.pid == caller.pid
              && bareSheetsA == 0,
              "sync's Touch ID is csecd's settings panel, never the bare sheet (csec-0.60)")

        // MARK: A damaged bundle is reported, never imported.
        let victim = ((try? FileManager.default.contentsOfDirectory(atPath: folderA)) ?? [])
            .filter { $0.hasSuffix(NativeStoreBackupBundle.fileExtension) }.sorted().first!
        let victimPath = (folderA as NSString).appendingPathComponent(victim)
        let intact = try Data(contentsOf: URL(fileURLWithPath: victimPath))
        var damagedBytes = intact
        damagedBytes[damagedBytes.count - 1] ^= 0x01
        try damagedBytes.write(to: URL(fileURLWithPath: victimPath))
        let macC = BackupTestMac(base.appendingPathComponent("mac-c"), clockStart: 1_750_000_000)
        let runC = try bootBackupRun(macC, root: root, consent: CountingBackupConsent())
        let damaged = await restore(runC, preview: true)
        check(damaged.nativeStoreBackup?.restore?.unreadableBundles == 1
              && damaged.nativeStoreBackup?.restore?.items.count == 4,
              "a bundle changed in the folder is counted as unreadable and left out")
        try intact.write(to: URL(fileURLWithPath: victimPath))

        // MARK: Restore onto a Mac that already has a store of that name.
        let consentB = CountingBackupConsent()
        let macB = BackupTestMac(base.appendingPathComponent("mac-b"), clockStart: 1_800_000_000)
        let runB = try bootBackupRun(macB, root: root, consent: consentB)
        try await commit(runB, beta, ["API_TOKEN": "synthetic-beta-b"])
        let wrong = await runB.service.handle(
            NativeStoreBackupRequest(action: .previewRestore, recoveryKit: try BackupRecoveryKit.generate().formatted,
                                     folder: root),
            caller: caller
        )
        check(wrong.failure != nil, "another kit finds no backup")
        let preview = await restore(runB, preview: true)
        let previewItems = preview.nativeStoreBackup?.restore?.items ?? []
        let touchesAfterPreview = await consentB.authentications
        check(previewItems.count == 5 && touchesAfterPreview == 0, "a preview lists every bundle and asks for nothing")
        check(previewItems.first { $0.kind == "doc" && $0.store == "beta" }?.outcome == .exists
              && previewItems.first { $0.kind == "doc" && $0.store == "alpha" }?.outcome == .willRestore
              && previewItems.first { $0.kind == "doc" && $0.store == "alpha" }?.count == 1,
              "the preview says what would be restored and what this Mac already has")
        let beforeRestore = await value(runB, tokenRef)
        check(beforeRestore == nil, "a preview restores nothing")

        let denied = try bootBackupRun(macB, root: root, consent: CountingBackupConsent(approve: false))
        let refused = await denied.service.handle(
            NativeStoreBackupRequest(action: .restore, recoveryKit: kitText, folder: root), caller: caller
        )
        let afterRefusal = await denied.backup.status()
        check(refused.failure?.code == .consentDenied && afterRefusal.state == .off,
              "a declined Touch ID restores nothing and sets nothing up")

        let snapshotA = folderSnapshot(folderA)
        let restored = await restore(runB)
        let outcomes = restored.nativeStoreBackup?.restore?.items ?? []
        let touchesAfterRestore = await consentB.authentications
        check(outcomes.filter { $0.outcome == .restored }.count == 3
              && outcomes.first { $0.store == "beta" }?.outcome == .exists
              && outcomes.first { $0.kind == "ssh-catalog" }?.outcome == .merged
              && touchesAfterRestore == 1,
              "one Touch ID restores the three missing tiers, merges the catalog and skips beta")
        let restorePanel = await consentB.panels.last
        let bareSheetsB = await consentB.bareSheets
        check(restorePanel?.change.title == "Restore Native Stores from a Backup"
              && restorePanel?.change.changes.first == "Restore 5 backed-up items into this Mac's native stores"
              && restorePanel?.change.changes.last == "Carry the backup on from this Mac, under the same recovery kit"
              && restorePanel?.change.footnote.hasPrefix("Touch ID restores exactly these items") == true
              && restorePanel?.caller.pid == caller.pid && bareSheetsB == 0,
              "a restore's Touch ID is csecd's settings panel, saying what it restores and that backups carry on (csec-0.60)")
        let restoredToken = await value(runB, tokenRef)
        let restoredFile = await value(runB, fileRef)
        check(restoredToken == "synthetic-alpha-4" && restoredFile == "{\"synthetic\":2}",
              "the restored stores hold the latest values")
        let keptBeta = await value(runB, betaRef)
        check(keptBeta == "synthetic-beta-b", "a store the Mac already had is left as it was")
        let restoredKeys = (try? await runB.catalog.list()) ?? []
        check(restoredKeys.map(\.fingerprint) == [sshFingerprint(fixture.publicKeyBlob)],
              "the SSH key is back in the catalog, so the agent offers it again")
        let rebooted = try bootBackupRun(macB, root: root, consent: consentB)
        let reopened = try? await rebooted.provider.resolve(sshRef, unlock: local)
        check(reopened?.value == fixture.privateKeyPEM, "after a restart the restored store opens from its new Keychain record")
        let carriedOn = await runB.backup.status()
        check(restored.nativeStoreBackup?.restore?.continuesBackup == true
              && carriedOn.state == .on && carriedOn.folder != folderA && carriedOn.problems.isEmpty,
              "a Mac with no backup of its own carries it on in a new folder, everything current, beta included")
        check(folderSnapshot(folderA) == snapshotA,
              "the folder restored from is left exactly as it was: not one bundle replaced")

        // MARK: A third Mac takes each store's newest bundle across both folders.
        let macD = BackupTestMac(base.appendingPathComponent("mac-d"), clockStart: 1_900_000_000)
        let runD = try bootBackupRun(macD, root: root, consent: CountingBackupConsent())
        _ = await restore(runD)
        let betaOnD = await value(runD, betaRef)
        let alphaOnD = await value(runD, tokenRef)
        check(betaOnD == "synthetic-beta-b" && alphaOnD == "synthetic-alpha-4",
              "a restore reads every folder its kit opens and takes the newest bundle of each store")

        // MARK: Either tier of a name already here keeps the whole name.
        let macE = BackupTestMac(base.appendingPathComponent("mac-e"), clockStart: 1_950_000_000)
        let runE = try bootBackupRun(macE, root: root, consent: CountingBackupConsent())
        try await commit(runE, alpha, ["OTHER": "synthetic-e"])
        let crossTier = await restore(runE, preview: true)
        check(crossTier.nativeStoreBackup?.restore?.items.first { $0.kind == "blob" && $0.store == "alpha" }?.outcome
              == .exists,
              "a blob tier is not restored beside a document store of the same name")

        // MARK: An interrupted restore resumes; a stranger's file does not.
        let found = try NativeStoreBackup.find(kit: try BackupRecoveryKit(parsing: kitText), root: root)
        guard let alphaBundle = found.bundles.first(where: { $0.contents.item == .store(.documents, alpha) }),
              case let .store(_, alphaFiles) = alphaBundle.contents.body else {
            check(false, "the alpha bundle is found")
            return
        }
        let macF = BackupTestMac(base.appendingPathComponent("mac-f"), clockStart: 1_960_000_000)
        let runF = try bootBackupRun(macF, root: root, consent: CountingBackupConsent())
        let leftBehind = try SecureNativeStoreFileBackend(directoryPath: macF.docDirectory)
        for (name, data) in alphaFiles { try await leftBehind.writeAtomically(named: name, data: data) }
        _ = await restore(runF)
        let resumed = await value(runF, tokenRef)
        check(resumed == "synthetic-alpha-4", "a restore that stopped before its Keychain record is finished")
        let macG = BackupTestMac(base.appendingPathComponent("mac-g"), clockStart: 1_970_000_000)
        let runG = try bootBackupRun(macG, root: root, consent: CountingBackupConsent())
        let stranger = try SecureNativeStoreFileBackend(directoryPath: macG.docDirectory)
        try await stranger.writeAtomically(named: "alpha.\(String(repeating: "e", count: 32)).csec", data: Data("x".utf8))
        let blocked = await restore(runG)
        let blockedOutcome = blocked.nativeStoreBackup?.restore?.items
            .first { $0.kind == "doc" && $0.store == "alpha" }?.outcome
        let notRestored = await value(runG, tokenRef)
        check(blockedOutcome == .exists && notRestored == nil,
              "a store name with someone else's file is not restored over it")

        // MARK: A store too large for one bundle is refused before it is read.
        let macH = BackupTestMac(base.appendingPathComponent("mac-h"), clockStart: 1_980_000_000)
        let runH = try bootBackupRun(macH, root: root, consent: CountingBackupConsent(), maximumBundleBytes: 4_096)
        let beganH = await runH.service.handle(NativeStoreBackupRequest(action: .beginSetup, folder: root), caller: caller)
        _ = await runH.service.handle(
            NativeStoreBackupRequest(action: .completeSetup, sessionID: beganH.nativeStoreBackup?.setupSessionID),
            caller: caller
        )
        let big = try NativeStoreName("big")
        _ = try await runH.blobs.putBlobs(
            store: big,
            requests: [.init(key: "blob", data: Data(repeating: 7, count: 8_192), mode: 0o600, path: "big.bin")],
            unlock: local
        )
        let tooLarge = await runH.backup.status()
        let needsAgain = await runH.backup.needsBundle(
            tier: .blobs, store: big,
            record: NativeStoreKeyRecord(keyData: Data(repeating: 9, count: 32), generation: 1,
                                         activeFileID: String(repeating: "1", count: 32),
                                         ciphertextDigest: String(repeating: "2", count: 64))
        )
        check(entry(tooLarge, "blob", "big")?.state == .failed && !needsAgain,
              "an oversized store is reported and not read again until it changes")

        // MARK: A new kit retires only this Mac's own bundles, once all is safe.
        let note = (folderA as NSString).appendingPathComponent("notes.txt")
        FileManager.default.createFile(atPath: note, contents: Data("kept".utf8))
        let rotate = await runA.service.handle(NativeStoreBackupRequest(action: .beginSetup, folder: root), caller: caller)
        _ = await runA.service.handle(
            NativeStoreBackupRequest(action: .completeSetup, sessionID: rotate.nativeStoreBackup?.setupSessionID),
            caller: caller
        )
        let rotated = await runA.backup.status()
        let leftInA = (try? FileManager.default.contentsOfDirectory(atPath: folderA)) ?? []
        check(rotated.folder != folderA && rotated.problems.isEmpty && rotated.retiringFolders == 0,
              "a new kit backs up everything into a new folder")
        check(leftInA == ["notes.txt"], "the old folder loses only the bundles this Mac wrote there")
        check(backupFolders(root).contains(carriedOn.folder ?? ""),
              "another Mac's folder is never touched by this Mac's rotation")

        // MARK: Off.
        let turnedOff = await runA.service.handle(NativeStoreBackupRequest(action: .off), caller: caller)
        let afterOff = await runA.backup.status()
        check(turnedOff.failure == nil && afterOff.state == .off && FileManager.default.fileExists(atPath: rotated.folder ?? ""),
              "off stops backups under Touch ID and leaves the folder for its kit")
        let offPanel = await consentA.panels.last
        check(offPanel?.change.title == "Turn Off Native-Store Backups"
              && offPanel?.change.footnote == SettingsChangeReviewDetails.settingsFootnote
              && offPanel?.caller.pid == caller.pid,
              "off's Touch ID is csecd's settings panel (csec-0.60)")
        try await commit(runA, alpha, ["API_TOKEN": "synthetic-alpha-5"])
        let rebootedA = try bootBackupRun(macA, root: root, consent: consentA)
        let stillOff = await rebootedA.backup.status()
        check(stillOff.state == .off, "a write after off does not bring backups back at the next start")
    } catch {
        check(false, "provider and restore tests ran (\(error))")
    }
}
