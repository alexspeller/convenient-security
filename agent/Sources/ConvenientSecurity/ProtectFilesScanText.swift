import Foundation

/// What `csec setup --protect-files` says before it scans and while it scans.
/// Every sentence of the notice is a claim about the code: the sweep in
/// `SecretFileDiscoveryEngine` reads names and bounded candidate contents in
/// this process, opens no connection and writes nothing; only an applied plan
/// stores values, and only csec's opt-in backup copies the store. Change the
/// notice whenever one of those stops being true.
public enum ProtectFilesScanText {
    public enum Mode: Sendable, Equatable {
        case interactive
        case dryRun
        case apply
    }

    /// The notice's lines: a headline, then indented paragraphs a caller
    /// wraps to the terminal.
    public static func notice(
        rootLabels: [String],
        coversHome: Bool,
        mode: Mode,
        knownLocationCount: Int = CredentialCatalog.entries.count
    ) -> [String] {
        let roots = rootLabels.map { ReviewDisplay.sanitized($0) }
        var scope: String
        if roots.isEmpty || roots == ["~"] {
            scope = "~, your whole home directory"
        } else {
            scope = roots.joined(separator: ", ")
        }
        scope += ", skipping build and cache folders such as node_modules and ~/Library"
        if coversHome {
            scope += "; also about \(knownLocationCount) known credential locations such as "
                + "~/.aws/credentials (some inside the skipped folders), ~/.ssh and your shell "
                + "startup files."
        } else {
            scope += ". Known credential locations outside \(roots.count == 1 ? "it" : "them") "
                + "are not checked."
        }
        let readLimit = SecretFileDiscoveryEngine.maximumContentSniffBytes >= 1024 * 1024
            ? "\(SecretFileDiscoveryEngine.maximumContentSniffBytes / (1024 * 1024)) MiB"
            : "\(SecretFileDiscoveryEngine.maximumContentSniffBytes / 1024) KiB"
        var lines = [
            "csec is about to scan this Mac for files holding secrets.",
            "  Where: " + scope,
            "  What it reads: the names of files and folders, and the contents of files that "
                + "look like secrets (up to \(readLimit) each), to tell real secrets from templates "
                + "and examples.",
            "  Privacy: the scan runs only on this Mac, inside this csec command. It sends "
                + "nothing over the network, copies nothing and changes nothing, and the list "
                + "it finds is shown here, never saved.",
        ]
        switch mode {
        case .interactive:
            lines.append("  After the scan: you pick files and confirm a plan. Nothing is protected "
                + "until you do. Then only the files you picked are encrypted into csec's store "
                + "on this Mac (or a 1Password vault you name), with Touch ID. csec's encrypted "
                + "backup copies them only if you turned it on with `csec backup setup`.")
        case .dryRun:
            lines.append("  After the scan: --dry-run prints the plan and changes nothing.")
        case .apply:
            lines.append("  After the scan: --apply protects the planned files, encrypting them "
                + "into csec's store on this Mac (or the 1Password vault a rule names), with "
                + "Touch ID. csec's encrypted backup copies them only if you turned it on with "
                + "`csec backup setup`.")
        }
        return lines
    }

    /// One status line for the scan, at most `width - 1` columns so a
    /// carriage-return redraw never wraps: where it is, how far through the
    /// folders it has measured, the counts, and the time so far.
    public static func progressLine(
        _ progress: SecretFileDiscoveryProgress,
        elapsed: TimeInterval,
        width: Int
    ) -> String {
        let limit = max(1, width - 1)
        let counts: [String]
        let lead: String
        var withNames: String?
        var withoutNames: String?
        var topOnly: String?
        switch progress.phase {
        case .knownLocations:
            lead = "Checking known credential locations"
            counts = ["\(count(progress.visitedEntries)) checked"]
        case .sweep:
            var root = "Scanning " + ReviewDisplay.sanitized(progress.rootLabel ?? "")
            if progress.rootCount > 1 {
                root += " (root \(progress.rootIndex) of \(progress.rootCount))"
            }
            lead = root
            counts = ["\(count(progress.visitedEntries)) entries"]
            if !progress.folders.isEmpty {
                func position(_ folder: SecretFileDiscoveryProgress.FolderPosition, named: Bool) -> String {
                    let base = "\(count(folder.index)) of \(count(folder.total))"
                    guard named else { return base }
                    return base + " (" + TerminalStyle.truncate(
                        ReviewDisplay.sanitized(folder.name), to: 24) + ")"
                }
                withNames = "folder " + progress.folders.map { position($0, named: true) }
                    .joined(separator: " › ")
                withoutNames = "folder " + progress.folders.map { position($0, named: false) }
                    .joined(separator: " › ")
                topOnly = "folder " + position(progress.folders[0], named: false)
            }
        }
        let tail = counts + ["\(count(progress.discoveredFiles)) found", duration(elapsed)]
        func line(_ folders: String?) -> String {
            ([lead] + [folders].compactMap { $0 } + tail).joined(separator: " · ")
        }
        // Shed the folder names, then the inner level, before cutting the end.
        for folders in [withNames, withoutNames].compactMap({ $0 }) where line(folders).count <= limit {
            return line(folders)
        }
        return TerminalStyle.truncate(line(topOnly), to: limit)
    }

    /// `45s`, `3m 07s`, `1h 02m`.
    public static func duration(_ seconds: TimeInterval) -> String {
        let total = max(0, Int(seconds.rounded(.down)))
        if total < 60 { return "\(total)s" }
        if total < 3600 { return "\(total / 60)m " + String(format: "%02ds", total % 60) }
        return "\(total / 3600)h " + String(format: "%02dm", total % 3600 / 60)
    }

    /// A count with thousands separators, independent of locale.
    public static func count(_ value: Int) -> String {
        let digits = String(abs(value))
        var grouped = ""
        for (offset, digit) in digits.enumerated() {
            if offset > 0, (digits.count - offset) % 3 == 0 { grouped.append(",") }
            grouped.append(digit)
        }
        return (value < 0 ? "-" : "") + grouped
    }
}
