import Foundation

/// csecd's side of `csec backup`. Every action that changes anything costs
/// one Touch ID on this Mac, in csecd's settings panel: turning backups on
/// (or onto a new kit), syncing, restoring, and turning them off. The kit
/// itself never reaches a terminal: `begin_setup` hands it to the signed
/// launcher, which shows it in its own window, and a restore's kit comes from
/// the launcher's window too.
public actor NativeStoreBackupService {
    /// A kit csecd made and handed to one launcher, waiting for that launcher
    /// to finish setup. Only csecd's own kits ever become a backup, so a
    /// caller cannot choose the key future bundles are sealed to.
    private struct PendingSetup {
        let kit: BackupRecoveryKit
        let folderRoot: String?
        let pid: pid_t
        let startTime: UInt64
    }

    static let maximumPendingSetups = 4

    private let backup: NativeStoreBackup
    private let nativeStore: NativeEncryptedFileProvider
    private let blobStore: NativeBlobStore?
    private let catalog: SSHKeyCatalog?
    private let consent: ConsentProvider
    private let terminalInspection: TerminalSessionInspector
    private let record: @Sendable (String) async -> Void
    private var pending: [String: PendingSetup] = [:]
    private var pendingOrder: [String] = []

    public init(
        backup: NativeStoreBackup,
        nativeStore: NativeEncryptedFileProvider,
        blobStore: NativeBlobStore?,
        catalog: SSHKeyCatalog?,
        consent: ConsentProvider,
        terminalInspection: TerminalSessionInspector,
        record: @escaping @Sendable (String) async -> Void = { _ in }
    ) {
        self.backup = backup
        self.nativeStore = nativeStore
        self.blobStore = blobStore
        self.catalog = catalog
        self.consent = consent
        self.terminalInspection = terminalInspection
        self.record = record
    }

    public func handle(_ request: NativeStoreBackupRequest, caller: CallerInfo) async -> Response {
        let id = request.requestID
        switch request.action {
        case .status:
            return reply(id, NativeStoreBackupReply(status: await backup.status()))
        case .beginSetup:
            // A launcher that exited without finishing leaves its kit behind
            // only until the next setup begins.
            for (sessionID, setup) in pending where kill(setup.pid, 0) != 0 && errno == ESRCH {
                drop(sessionID)
            }
            do {
                let kit = try BackupRecoveryKit.generate()
                let sessionID = UUID().uuidString.lowercased()
                pending[sessionID] = PendingSetup(
                    kit: kit, folderRoot: request.folder, pid: caller.pid, startTime: caller.startTime
                )
                pendingOrder.append(sessionID)
                while pendingOrder.count > Self.maximumPendingSetups {
                    pending[pendingOrder.removeFirst()] = nil
                }
                return reply(id, NativeStoreBackupReply(setupSessionID: sessionID, recoveryKit: kit.formatted))
            } catch {
                return failed(id, .internalError, error)
            }
        case .cancelSetup:
            if let sessionID = request.sessionID, owned(sessionID, by: caller) {
                drop(sessionID)
            }
            return reply(id, NativeStoreBackupReply())
        case .completeSetup:
            guard let sessionID = request.sessionID, owned(sessionID, by: caller),
                  let setup = pending[sessionID] else {
                return .failed(.invalidRequest, message: "no backup setup is waiting for this csec", requestID: id)
            }
            drop(sessionID)
            return await completeSetup(setup, caller: caller, requestID: id)
        case .sync:
            guard await backup.isOn() else {
                return failed(id, .invalidRequest, NativeStoreBackupError.notConfigured)
            }
            let auth = await approve(Self.syncChange(folder: await backup.status().folder), caller: caller)
            guard auth.isApproved, let unlock = auth.unlock, unlock.isLocal else {
                return .failed(.consentDenied, message: "backup sync denied", requestID: id)
            }
            defer { unlock.invalidate() }
            let report = await backfill(unlock)
            await backup.retireIfSafe()
            return reply(id, NativeStoreBackupReply(status: await backup.status(), report: report))
        case .previewRestore, .restore:
            return await restore(request, apply: request.action == .restore, caller: caller)
        case .off:
            let isOn = await backup.isOn()
            let unreadable = await backup.unreadableReason()
            guard isOn || unreadable != nil else {
                return reply(id, NativeStoreBackupReply(status: .off))
            }
            let auth = await approve(Self.offChange, caller: caller)
            guard auth.isApproved else {
                return .failed(.consentDenied, message: "turning backups off was denied", requestID: id)
            }
            auth.unlock?.invalidate()
            do {
                try await backup.turnOff()
            } catch {
                return failed(id, .internalError, error)
            }
            await record("native-store backups turned off")
            return reply(id, NativeStoreBackupReply(status: .off))
        }
    }

    // MARK: - Setup

    private func completeSetup(_ setup: PendingSetup, caller: CallerInfo, requestID id: String) async -> Response {
        let auth = await approve(Self.onChange(folder: setup.folderRoot ?? backup.locations.root), caller: caller)
        guard auth.isApproved, let unlock = auth.unlock, unlock.isLocal else {
            return .failed(.consentDenied, message: "backup setup denied", requestID: id)
        }
        defer { unlock.invalidate() }
        do {
            try await backup.configure(kit: setup.kit, root: setup.folderRoot)
        } catch {
            return failed(id, .providerUnavailable, error)
        }
        let report = await backfill(unlock)
        // An earlier kit's folder goes only once everything is safely in the
        // new one; until then the earlier kit still restores it.
        await backup.retireIfSafe()
        await record("native-store backups turned on")
        return reply(id, NativeStoreBackupReply(status: await backup.status(), report: report))
    }

    private func backfill(_ unlock: CacheUnlock) async -> NativeStoreBackupReport {
        var report = await nativeStore.backfillBackups(localUnlock: unlock)
        if let catalog {
            switch (try? await catalog.backUp()) ?? .failed {
            case .written: report.written += 1
            case .current, .off: report.current += 1
            case .failed: report.failed += 1
            }
        }
        return report
    }

    // MARK: - Touch ID

    /// The one touch an action costs, in csecd's settings panel naming the
    /// tab `caller` runs in.
    private func approve(_ change: SettingsChangeReviewDetails, caller: CallerInfo) async -> ConsentOutcome {
        var shown = caller
        shown.terminal = await terminalInspection.context(forCallerPID: caller.pid)
        return await consent.approveSettingsChange(change, caller: shown)
    }

    /// Sync and setup read every native-store item with the touch, to seal
    /// each into the backup; nothing leaves csecd unsealed.
    static let backupFootnote =
        "Touch ID lets Convenient Security read its native stores to seal them into the backup. No secret is released."

    static func onChange(folder: String) -> SettingsChangeReviewDetails {
        SettingsChangeReviewDetails(
            title: "Turn On Native-Store Backups",
            changes: [
                "Back up csec's native stores and SSH key catalog, sealed to the recovery kit csec showed",
                "Folder: \(folder)",
            ],
            footnote: backupFootnote
        )
    }

    static func syncChange(folder: String?) -> SettingsChangeReviewDetails {
        SettingsChangeReviewDetails(
            title: "Back Up Native Stores",
            changes: ["Write a current backup of every native store and the SSH key catalog"]
                + (folder.map { ["Folder: \($0)"] } ?? []),
            footnote: backupFootnote
        )
    }

    static let offChange = SettingsChangeReviewDetails(
        title: "Turn Off Native-Store Backups",
        changes: ["Stop backing up csec's native stores; the backups already written stay in their folder"]
    )

    static func restoreChange(items: Int, folder: String, continues: Bool) -> SettingsChangeReviewDetails {
        SettingsChangeReviewDetails(
            title: "Restore Native Stores from a Backup",
            changes: ["Restore \(items) backed-up item\(items == 1 ? "" : "s") into this Mac's native stores",
                      "From: \(folder)"]
                + (continues ? ["Carry the backup on from this Mac, under the same recovery kit"] : []),
            footnote: "Touch ID restores exactly these items into Convenient Security's native stores. "
                + "No secret is released."
        )
    }

    private func owned(_ sessionID: String, by caller: CallerInfo) -> Bool {
        guard let setup = pending[sessionID] else { return false }
        return setup.pid == caller.pid && setup.startTime == caller.startTime
    }

    private func drop(_ sessionID: String) {
        pending[sessionID] = nil
        pendingOrder.removeAll { $0 == sessionID }
    }

    // MARK: - Restore

    private func restore(_ request: NativeStoreBackupRequest, apply: Bool, caller: CallerInfo) async -> Response {
        let id = request.requestID
        let kit: BackupRecoveryKit
        let found: NativeStoreBackupFound
        do {
            kit = try BackupRecoveryKit(parsing: request.recoveryKit ?? "")
            found = try NativeStoreBackup.find(kit: kit, root: request.folder ?? backup.locations.root)
        } catch {
            return failed(id, .invalidRequest, error)
        }
        var unlock: CacheUnlock?
        if apply {
            let auth = await approve(
                Self.restoreChange(items: found.bundles.count, folder: found.newestFolder, continues: await backup.isOff()),
                caller: caller
            )
            guard auth.isApproved else {
                return .failed(.consentDenied, message: "restore denied", requestID: id)
            }
            unlock = auth.unlock
        }
        defer { unlock?.invalidate() }
        // This Mac carries the backup on, under the same kit, when it keeps
        // no backup of its own. It writes into a new folder of its own, so no
        // bundle it writes can replace one in the folders it restored from.
        let continues = await backup.isOff()
        let localNames = await localStoreNames(Set(found.bundles.map(\.contents.item.name).filter { !$0.isEmpty }))
        func report(_ items: [NativeStoreBackupRestoredItem]) -> NativeStoreBackupRestoreReport {
            NativeStoreBackupRestoreReport(
                folder: found.newestFolder, items: items, unreadableBundles: found.unreadable,
                continuesBackup: continues, notDownloadedBundles: found.notDownloaded
            )
        }
        guard apply else {
            var plan: [NativeStoreBackupRestoredItem] = []
            var ignored: [SSHKeyMetadata] = []
            for bundle in found.bundles {
                plan.append(await restoreItem(bundle.contents, apply: false, localNames: localNames, keys: &ignored))
            }
            return reply(id, NativeStoreBackupReply(restore: report(plan)))
        }
        if continues {
            do {
                try await backup.configure(kit: kit, root: found.root)
            } catch {
                return failed(id, .providerUnavailable, error)
            }
        }
        var items: [NativeStoreBackupRestoredItem] = []
        var restoredKeys: [SSHKeyMetadata] = []
        for bundle in found.bundles {
            items.append(await restoreItem(bundle.contents, apply: true, localNames: localNames, keys: &restoredKeys))
        }
        if let catalog {
            // Only keys whose store this Mac now has (or that live outside
            // the native store) are offered to SSH; the rest could never sign.
            let local = await localStoreNames(Set(restoredKeys.compactMap {
                (try? NativeSecretReference(SecretRef($0.reference)))?.store.value
            }))
            let usable = restoredKeys.filter { key in
                guard let reference = try? NativeSecretReference(SecretRef(key.reference)) else {
                    return (try? SecretRef(key.reference))?.scheme != "csec"
                }
                return local.contains(reference.store.value)
            }
            if (try? await catalog.merge(usable)) == 0 { _ = try? await catalog.backUp() }
        }
        if continues, let unlock, unlock.isLocal { _ = await backfill(unlock) }
        let restored = items.filter { $0.outcome == .restored }.count
        await record("native-store backup restored (\(restored) of \(items.count) items)")
        return reply(id, NativeStoreBackupReply(status: await backup.status(), restore: report(items)))
    }

    /// `localNames` are the names this Mac held before the restore wrote
    /// anything, so restoring one tier of a name never blocks its other.
    private func restoreItem(
        _ contents: NativeStoreBackupContents,
        apply: Bool,
        localNames: Set<String>,
        keys restoredKeys: inout [SSHKeyMetadata]
    ) async -> NativeStoreBackupRestoredItem {
        func item(_ count: Int, _ outcome: NativeStoreBackupRestoredItem.Outcome) -> NativeStoreBackupRestoredItem {
            NativeStoreBackupRestoredItem(
                kind: contents.item.tag, store: contents.item.name, count: count,
                backedUpAt: contents.createdAt, outcome: outcome
            )
        }
        switch (contents.item, contents.body) {
        case let (.store(tier, store), .store(record, files)):
            let count: Int
            do {
                switch tier {
                case .documents:
                    count = try nativeStore.inspectBackup(store: store, record: record, files: files)
                case .blobs:
                    guard let blobStore else { return item(0, .invalid) }
                    count = try blobStore.inspectBackup(store: store, record: record, files: files)
                }
            } catch {
                return item(0, .invalid)
            }
            // Either tier of a name already here makes the name this Mac's:
            // restoring the other tier beside it could let one key name two
            // values.
            guard !localNames.contains(store.value) else { return item(count, .exists) }
            guard apply else { return item(count, .willRestore) }
            do {
                switch tier {
                case .documents:
                    _ = try await nativeStore.restoreFromBackup(store: store, record: record, files: files)
                case .blobs:
                    _ = try await blobStore?.restoreFromBackup(store: store, record: record, files: files)
                }
                return item(count, .restored)
            } catch NativeStoreBackupError.storeExists {
                return item(count, .exists)
            } catch {
                return item(count, .invalid)
            }
        case let (.sshCatalog, .sshCatalog(keys)):
            restoredKeys += keys
            return item(keys.count, apply ? .merged : .willRestore)
        default:
            return item(0, .invalid)
        }
    }

    /// Which of `names` this Mac holds, in either tier.
    private func localStoreNames(_ names: Set<String>) async -> Set<String> {
        var held = Set<String>()
        for name in names {
            guard let store = try? NativeStoreName(name) else { continue }
            if await nativeStore.holdsStore(store) {
                held.insert(name)
            } else if let blobStore, await blobStore.holdsStore(store) {
                held.insert(name)
            }
        }
        return held
    }

    // MARK: - Replies

    private func reply(_ requestID: String, _ backupReply: NativeStoreBackupReply) -> Response {
        Response(requestID: requestID, nativeStoreBackup: backupReply)
    }

    private func failed(_ requestID: String, _ code: WireErrorCode, _ error: Error) -> Response {
        let message = (error as? ProviderDiagnosableError)?.boundedReason ?? "the native-store backup failed"
        return .failed(code, message: message, requestID: requestID)
    }
}
