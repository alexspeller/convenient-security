import Foundation

extension DomainJ_Leakage {
    /// Reads and classifies in-process. No child command, match, excerpt or
    /// source line can enter the finding or any diagnostic output.
    struct ShellHistoryExposure: HostCheck {
        static let maximumBytes = 8 * 1024 * 1024
        static let patterns: [(label: String, regex: NSRegularExpression)] = [
            ("userinfo URLs", #"(?i)\b[a-z][a-z0-9+.-]*://[^\s/:@\"'<>]+:[^\s/@\"'<>]+@"#),
            ("bearer headers", #"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/-]{8,}={0,2}"#),
            ("AWS access key IDs", #"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"#),
            ("GitHub tokens", #"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"#),
            ("API keys", #"\b(?:sk-[A-Za-z0-9_-]{16,}|[sr]k_(?:live|test)_[A-Za-z0-9]{16,})\b"#),
        ].map { (label: $0.0, regex: try! NSRegularExpression(pattern: $0.1)) }

        let meta = HostCheckMeta(
            id: "HA-J07", title: "Shell history has no supported credential patterns",
            severity: .high, tier: .runtimeReadable, onThesis: true,
            anchor: "Review history locally with your shell's history tools; rotate exposed credentials and remove their history entries. Prefer references or environment variables in commands.")

        func evaluate(_ ctx: HostAuditContext) async -> HostFinding {
            let home = ctx.files.homeDirectory
            var paths: Set<String> = [
                home + "/.zsh_history", home + "/.bash_history",
                home + "/.local/share/fish/fish_history", home + "/.config/fish/fish_history",
            ]
            if let histfile = ctx.environment["HISTFILE"],
               histfile.hasPrefix("/"), !histfile.utf8.contains(0) { paths.insert(histfile) }
            if let xdg = ctx.environment["XDG_DATA_HOME"],
               xdg.hasPrefix("/"), !xdg.utf8.contains(0) {
                paths.insert(xdg + "/fish/fish_history")
            }
            var counts = Array(repeating: 0, count: Self.patterns.count)
            var readable = 0
            var unreadable = 0
            var truncated = 0
            for path in paths.sorted() where ctx.files.fileExists(path) {
                guard ctx.files.isRegularFile(path),
                      let text = ctx.files.readText(path, maxBytes: Self.maximumBytes + 1) else {
                    unreadable += 1
                    continue
                }
                readable += 1
                if text.utf8.count > Self.maximumBytes { truncated += 1 }
                let bounded = String(decoding: text.utf8.prefix(Self.maximumBytes), as: UTF8.self)
                let range = NSRange(bounded.startIndex..<bounded.endIndex, in: bounded)
                for (index, pattern) in Self.patterns.enumerated() {
                    counts[index] += pattern.regex.numberOfMatches(in: bounded, range: range)
                }
            }
            let coverage = "Known zsh/bash/fish history locations and absolute HISTFILE/XDG_DATA_HOME overrides only; at most 8 MiB per file. \(unreadable) unreadable/non-regular, \(truncated) truncated. Other locations and credential formats are not covered. Counts are pattern occurrences, not distinct credentials."
            if counts.contains(where: { $0 > 0 }) {
                let summary = zip(Self.patterns, counts).map { "\($0.0.label): \($0.1)" }
                    .joined(separator: "; ")
                return meta.finding(.fail,
                    evidence: "Credential-shaped history occurrences in \(readable) readable file(s): \(summary).",
                    coverageNote: coverage)
            }
            if unreadable > 0 || truncated > 0 {
                return meta.finding(.unknown,
                    evidence: "No supported credential patterns found in the inspected history bytes, but coverage is incomplete.",
                    coverageNote: coverage)
            }
            if readable == 0 {
                return meta.finding(.notApplicable, evidence: "No history file was found at the known locations.",
                                    coverageNote: coverage)
            }
            return meta.finding(.pass,
                evidence: "No supported credential patterns found in \(readable) readable history file(s).",
                coverageNote: coverage)
        }
    }
}
