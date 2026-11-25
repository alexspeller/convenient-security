import Foundation

/// How `csec backup status` and the `csec status` / `csec doctor` row read a
/// `NativeStoreBackupStatus`. Value-free: store names, counts and dates only.
///
/// The row warns and never fails doctor: no install mends a backup, and an
/// install gated on iCloud Drive would stall on a sync hiccup. Off is only a
/// warning when this Mac holds native stores, since then losing the Mac loses
/// them.
public enum NativeStoreBackupStatusReport {
    public static let label = "Native-store backups"

    public static func doctorRow(_ status: NativeStoreBackupStatus?) -> StatusRow {
        guard let status else { return StatusRow(label: label, value: "unavailable", state: .neutral) }
        switch status.state {
        case .off:
            // Off, csecd lists the stores this Mac holds, none backed up.
            return !status.stores.isEmpty
                ? StatusRow(
                    label: label,
                    value: "off: native stores exist only on this Mac (csec backup setup)",
                    state: .warn
                )
                : StatusRow(label: label, value: "off", state: .neutral)
        case .unreadable:
            return StatusRow(
                label: label,
                value: "settings unreadable (\(status.unreadableReason ?? "unknown")); "
                    + "reinstall the current build, or run csec backup setup again",
                state: .warn
            )
        case .on:
            break
        }
        let problems = status.problems
        guard problems.isEmpty else {
            return StatusRow(label: label, value: problemSummary(problems), state: .warn)
        }
        let waiting = status.stores.filter { $0.uploaded == false }.count
        let count = status.stores.count
        let noun = count == 1 ? "bundle" : "bundles"
        return StatusRow(
            label: label,
            value: waiting == 0
                ? "on: \(count) \(noun) current"
                : "on: \(count) \(noun) current, \(waiting) still uploading to iCloud",
            state: .ok
        )
    }

    /// The lines `csec backup status` prints.
    public static func lines(_ status: NativeStoreBackupStatus) -> [String] {
        switch status.state {
        case .off:
            let count = Set(status.stores.map(\.store)).count
            return [
                "Native-store backups are off.",
                count == 0
                    ? "Turn them on with `csec backup setup`."
                    : "\(count) native store\(count == 1 ? "" : "s") on this Mac would be lost with it; "
                        + "turn backups on with `csec backup setup`.",
            ]
        case .unreadable:
            return [
                "Native-store backup settings cannot be read (\(status.unreadableReason ?? "unknown")).",
                "Reinstall the current build, or run `csec backup setup` again to replace them.",
            ]
        case .on:
            break
        }
        var lines = ["Native-store backups are on."]
        if let folder = status.folder { lines.append("Folder: \(folder)") }
        if let configuredAt = status.configuredAt { lines.append("Since: \(format(configuredAt))") }
        if status.stores.isEmpty { lines.append("No stores to back up yet.") }
        for store in status.stores {
            lines.append("  \(describe(store))")
        }
        let problems = status.problems
        if !problems.isEmpty {
            lines.append(problemSummary(problems))
        }
        if status.retiringFolders > 0 {
            lines.append("An earlier recovery key's folder is kept until every store's new bundle is in iCloud.")
        }
        return lines
    }

    public static func describe(_ store: NativeStoreBackupStatus.Store) -> String {
        let name = itemName(kind: store.kind, store: store.store)
        switch store.state {
        case .current:
            let when = store.writtenAt.map { " at \(format($0))" } ?? ""
            let upload: String
            switch store.uploaded {
            case true?: upload = ", in iCloud"
            case false?: upload = ", uploading to iCloud"
            case nil: upload = ""
            }
            return "\(name): backed up\(when)\(upload)"
        case .failed:
            return "\(name): last change not backed up (\(store.failureReason ?? "unknown"))"
        case .missingOrChanged:
            return "\(name): its bundle is missing from the folder or was changed"
        case .notBackedUp:
            return "\(name): not backed up yet"
        }
    }

    public static func itemName(kind: String, store: String) -> String {
        switch kind {
        case NativeStoreTier.documents.rawValue: return "store \(store)"
        case NativeStoreTier.blobs.rawValue: return "store \(store) (files)"
        case NativeStoreBackupItem.sshCatalogTag: return "SSH key catalog"
        default: return "\(kind) \(store)"
        }
    }

    static func problemSummary(_ problems: [NativeStoreBackupStatus.Store]) -> String {
        let noun = problems.count == 1 ? "store needs" : "stores need"
        return "\(problems.count) \(noun) a backup: run `csec backup sync` (one Touch ID)"
    }

    public static func format(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm"
        return formatter.string(from: date)
    }
}
