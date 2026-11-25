import Foundation
@preconcurrency import AppKit
import ConvenientSecurity

/// `csec backup setup|status|sync|restore|off [--folder PATH]`.
///
/// The recovery kit is shown and typed only in this signed launcher's own
/// windows, never on stdout or read from stdin or an argument: a coding agent
/// reads the terminal, and a kit it could see would open every bundle. What
/// the terminal gets is value-free: store names, counts and dates.
func runBackup(_ arguments: [String]) -> Never {
    guard let action = arguments.first else { usage("backup") }
    var folder: String?
    var rest = Array(arguments.dropFirst())
    while let option = rest.first {
        guard option == "--folder", rest.count >= 2, ["setup", "restore"].contains(action) else { usage("backup") }
        folder = URL(fileURLWithPath: (rest[1] as NSString).expandingTildeInPath).standardizedFileURL.path
        rest.removeFirst(2)
    }
    let client = makeAgentClient()
    do {
        switch action {
        case "status":
            let status = try client.nativeStoreBackup(NativeStoreBackupRequest(action: .status)).status ?? .off
            NativeStoreBackupStatusReport.lines(status).forEach { print($0) }
            exit(status.state == .unreadable || !(status.state == .off || status.problems.isEmpty) ? 1 : 0)
        case "setup":
            try runBackupSetup(client: client, folder: folder)
        case "sync":
            print("Touch ID on this Mac to back up every native store…")
            let reply = try client.nativeStoreBackup(NativeStoreBackupRequest(action: .sync))
            printBackupReport(reply)
            exit(reply.report?.failed == 0 ? 0 : 1)
        case "restore":
            try runBackupRestore(client: client, folder: folder)
        case "off":
            print("Touch ID on this Mac to stop backing up native stores…")
            _ = try client.nativeStoreBackup(NativeStoreBackupRequest(action: .off))
            print("Native-store backups are off. The backup folder and its recovery kit still restore what it holds;")
            print("delete the folder yourself to remove it.")
            exit(0)
        default:
            usage("backup")
        }
    } catch AgentClient.ClientError.denied {
        FileHandle.standardError.write(Data("csec backup: not approved; nothing changed\n".utf8))
        exit(1)
    } catch {
        FileHandle.standardError.write(Data("csec backup: \(error.localizedDescription)\n".utf8))
        exit(1)
    }
}

private func runBackupSetup(client: AgentClient, folder: String?) throws -> Never {
    let begun = try client.nativeStoreBackup(NativeStoreBackupRequest(action: .beginSetup, folder: folder))
    guard let sessionID = begun.setupSessionID, let kit = begun.recoveryKit else {
        throw AgentClient.ClientError.transportFailed
    }
    print("csec backup: your recovery key is in the window csec just opened.")
    let confirmed = BackupKitWindow.showAndConfirm(kit: kit)
    BackupKitWindow.clearPasteboard(ifItHolds: kit)
    guard confirmed else {
        _ = try? client.nativeStoreBackup(NativeStoreBackupRequest(action: .cancelSetup, sessionID: sessionID))
        print("Backup setup cancelled; nothing changed.")
        exit(1)
    }
    print("Touch ID on this Mac to turn backups on and back up every native store…")
    let reply = try client.nativeStoreBackup(NativeStoreBackupRequest(action: .completeSetup, sessionID: sessionID))
    printBackupReport(reply)
    exit(reply.report?.failed == 0 ? 0 : 1)
}

private func runBackupRestore(client: AgentClient, folder: String?) throws -> Never {
    print("csec backup: type or paste your recovery key into the window csec just opened.")
    guard let kit = BackupKitWindow.askForKit() else {
        print("Restore cancelled; nothing changed.")
        exit(1)
    }
    do {
        try restoreWithKit(kit, client: client, folder: folder)
    } catch {
        BackupKitWindow.clearPasteboard(ifItHolds: kit)
        throw error
    }
}

private func restoreWithKit(_ kit: String, client: AgentClient, folder: String?) throws -> Never {
    let preview = try client.nativeStoreBackup(
        NativeStoreBackupRequest(action: .previewRestore, recoveryKit: kit, folder: folder)
    )
    guard let found = preview.restore else { throw AgentClient.ClientError.transportFailed }
    let listing = found.items.map(describeRestoreItem)
    listing.forEach { print("  \($0)") }
    if found.notDownloadedBundles > 0 {
        print("\(found.notDownloadedBundles) bundle(s) are still downloading from iCloud Drive; csec asked for them.")
        print("Run csec backup restore again once they are here to restore what they hold too.")
    }
    guard found.items.contains(where: { $0.outcome == .willRestore }) else {
        BackupKitWindow.clearPasteboard(ifItHolds: kit)
        print("Nothing to restore: this Mac already has every store the backup holds.")
        exit(0)
    }
    guard BackupKitWindow.confirmRestore(
        folder: found.folder, listing: listing, continuesBackup: found.continuesBackup
    ) else {
        BackupKitWindow.clearPasteboard(ifItHolds: kit)
        print("Restore cancelled; nothing changed.")
        exit(1)
    }
    print("Touch ID on this Mac to restore…")
    let applied = try client.nativeStoreBackup(
        NativeStoreBackupRequest(action: .restore, recoveryKit: kit, folder: folder)
    )
    guard let report = applied.restore else { throw AgentClient.ClientError.transportFailed }
    report.items.map(describeRestoreItem).forEach { print("  \($0)") }
    if report.unreadableBundles > 0 {
        print("\(report.unreadableBundles) bundle(s) in the folder did not open under this recovery key.")
    }
    if report.continuesBackup {
        print("This Mac now backs up to a new folder under the same recovery key; the folders it restored from")
        print("are left exactly as they were.")
    } else {
        print("This Mac keeps its own backup settings; the stores it restored are backed up under them.")
    }
    BackupKitWindow.clearPasteboard(ifItHolds: kit)
    exit(report.items.contains { $0.outcome == .invalid } ? 1 : 0)
}

private func describeRestoreItem(_ item: NativeStoreBackupRestoredItem) -> String {
    let name = NativeStoreBackupStatusReport.itemName(kind: item.kind, store: item.store)
    let unit: String
    switch item.kind {
    case NativeStoreTier.documents.rawValue: unit = item.count == 1 ? "key" : "keys"
    case NativeStoreTier.blobs.rawValue: unit = item.count == 1 ? "file" : "files"
    default: unit = item.count == 1 ? "SSH key" : "SSH keys"
    }
    let outcome: String
    switch item.outcome {
    case .willRestore: outcome = "will be restored"
    case .restored: outcome = "restored"
    case .exists: outcome = "already on this Mac, left as it is"
    case .invalid: outcome = "its bundle did not check out, not restored"
    case .merged: outcome = "merged into this Mac's SSH key catalog"
    }
    return "\(name): \(item.count) \(unit), backed up \(NativeStoreBackupStatusReport.format(item.backedUpAt)), \(outcome)"
}

private func printBackupReport(_ reply: NativeStoreBackupReply) {
    if let report = reply.report {
        var parts = ["\(report.written) backed up"]
        if report.current > 0 { parts.append("\(report.current) already current") }
        if report.failed > 0 { parts.append("\(report.failed) failed") }
        print("Native-store backup: " + parts.joined(separator: ", ") + ".")
    }
    if let status = reply.status {
        NativeStoreBackupStatusReport.lines(status).forEach { print($0) }
    }
}

/// The launcher's recovery-kit windows. Each is an `NSAlert`, like the
/// native-store editor: the kit lives in this signed process's heap and its
/// window, and a copy out of the window is marked concealed and kept on this
/// Mac (`ConfidentialTextView`). The key goes back in through a
/// `RecoveryKeyEntryView`, whose line counts the groups pasted.
enum BackupKitWindow {
    /// Show the kit, then have the human paste it back from wherever they
    /// saved it: a kit nobody kept would leave every bundle unopenable.
    static func showAndConfirm(kit: String) -> Bool {
        prepare()
        while true {
            guard showKit(kit) else { return false }
            switch confirmKit(kit) {
            case .confirmed: return true
            case .cancelled: return false
            case .showAgain: continue
            }
        }
    }

    static func askForKit() -> String? {
        prepare()
        while true {
            let alert = makeAlert(
                title: "Restore csec's native stores",
                text: "Type or paste the recovery key from your csec recovery kit. csec finds the backup it opens in iCloud Drive (or the folder you named) and lists what it holds before anything changes."
            )
            alert.addButton(withTitle: "Find Backup")
            alert.addButton(withTitle: "Cancel")
            let entry = RecoveryKeyEntryView()
            alert.accessoryView = entry
            alert.window.initialFirstResponder = entry.field
            guard alert.runModal() == .alertFirstButtonReturn else { return nil }
            let typed = entry.typed
            entry.clear()
            if (try? BackupRecoveryKit(parsing: typed)) != nil { return typed }
            warn("That is not a csec recovery key", "Check each group of four characters against your recovery kit and try again.")
        }
    }

    static func confirmRestore(folder: String, listing: [String], continuesBackup: Bool) -> Bool {
        prepare()
        let after = continuesBackup
            ? "After the restore this Mac backs up to a new folder under the same recovery key."
            : "This Mac keeps its own backup settings, and the restored stores are backed up under them."
        let alert = makeAlert(
            title: "Restore these native stores?",
            text: "From \(folder):\n\n" + listing.joined(separator: "\n")
                + "\n\nStores this Mac already has are left as they are. " + after
        )
        alert.addButton(withTitle: "Restore")
        alert.addButton(withTitle: "Cancel")
        return alert.runModal() == .alertFirstButtonReturn
    }

    private enum Confirmation { case confirmed, cancelled, showAgain }

    private static func showKit(_ kit: String) -> Bool {
        let alert = makeAlert(
            title: "Save your csec recovery key",
            text: "This key is the only way to open csec's native-store backups on another Mac. Save it now in 1Password, in a vault no csec op:// reference reads, or print it and keep it safe. csec never shows it again, and it is never stored on this Mac."
        )
        alert.addButton(withTitle: "I've Saved It")
        alert.addButton(withTitle: "Cancel")
        let view = ConfidentialTextView(frame: NSRect(x: 0, y: 0, width: 600, height: 64))
        view.isEditable = false
        view.isSelectable = true
        view.isRichText = false
        view.font = NSFont.monospacedSystemFont(ofSize: 15, weight: .medium)
        view.string = kit
        view.isAutomaticDataDetectionEnabled = false
        view.isAutomaticLinkDetectionEnabled = false
        view.drawsBackground = false
        alert.accessoryView = view
        alert.window.initialFirstResponder = view
        view.selectAll(nil)
        let response = alert.runModal()
        view.string = ""
        return response == .alertFirstButtonReturn
    }

    private static func confirmKit(_ kit: String) -> Confirmation {
        let alert = makeAlert(
            title: "Paste your recovery key back",
            text: "Paste it from where you saved it, so csec knows you can get it back."
        )
        alert.addButton(withTitle: "Turn On Backups")
        alert.addButton(withTitle: "Show Key Again")
        alert.addButton(withTitle: "Cancel")
        let entry = RecoveryKeyEntryView()
        alert.accessoryView = entry
        alert.window.initialFirstResponder = entry.field
        let response = alert.runModal()
        let typed = entry.typed
        entry.clear()
        switch response {
        case .alertFirstButtonReturn:
            if let parsed = try? BackupRecoveryKit(parsing: typed), parsed.formatted == kit { return .confirmed }
            warn("That doesn't match", "Paste the recovery key exactly as you saved it, or show it again.")
            return .showAgain
        case .alertSecondButtonReturn:
            return .showAgain
        default:
            return .cancelled
        }
    }

    /// The kit, copied out of the window or pasted back from 1Password, is
    /// still on the general pasteboard, where any process on this Mac can
    /// read it: clear it, but only if it is still exactly that.
    static func clearPasteboard(ifItHolds kit: String) {
        let pasteboard = NSPasteboard.general
        guard let text = pasteboard.string(forType: .string),
              let held = try? BackupRecoveryKit(parsing: text),
              let wanted = try? BackupRecoveryKit(parsing: kit),
              held.formatted == wanted.formatted else { return }
        pasteboard.clearContents()
    }

    private static func prepare() {
        NSApplication.shared.setActivationPolicy(.accessory)
        MainActor.assumeIsolated { StandardEditMenu.installIfNeeded(in: NSApplication.shared) }
    }

    private static func makeAlert(title: String, text: String) -> NSAlert {
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = title
        alert.informativeText = text
        alert.window.title = "Convenient Security"
        alert.window.isRestorable = false
        NSApplication.shared.activate(ignoringOtherApps: true)
        return alert
    }

    private static func warn(_ title: String, _ text: String) {
        let alert = makeAlert(title: title, text: text)
        alert.alertStyle = .warning
        alert.addButton(withTitle: "OK")
        alert.runModal()
    }
}
