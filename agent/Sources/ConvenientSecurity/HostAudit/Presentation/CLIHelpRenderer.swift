import Foundation

// Pure terminal rendering of the CLI help catalog, mirroring `AuditReportRenderer`:
// it takes an explicit `color`/`width` and returns a String, so it renders the same
// to a pipe (no color) as to a terminal and is unit-testable without a TTY. The
// launcher (`csec`) chooses the stream, exit code, color, and width around these.
public enum CLIHelpRenderer {
    /// The whole-program help: title, usage, and every non-hidden command grouped
    /// under its category heading.
    public static func renderGlobal(color: Bool, width: Int) -> String {
        var lines: [String] = []
        lines.append(bold(CLICatalog.program, color) + "  " + dim(CLICatalog.tagline, color))
        lines.append("")
        lines.append(bold("Usage:", color) + " \(CLICatalog.program) <command> [options]")

        let visible = CLICatalog.commands.filter { !$0.hidden }
        let gutter = (visible.map { $0.name.count }.max() ?? 0) + 2
        for category in CLICategory.allCases {
            let commands = visible.filter { $0.category == category }
            guard !commands.isEmpty else { continue }
            lines.append("")
            lines.append(bold(category.title, color))
            for command in commands {
                lines.append(row(name: command.name, summary: command.summary,
                                 gutter: gutter, width: width, color: color))
            }
        }
        lines.append("")
        lines.append(dim(
            "Run \"\(CLICatalog.program) help <command>\" or "
                + "\"\(CLICatalog.program) <command> --help\" for details.", color))
        return lines.joined(separator: "\n")
    }

    /// One command's help: title, usage synopsis, wrapped discussion, aligned
    /// options, and any named sub-actions.
    public static func renderCommand(_ command: CLICommand, color: Bool, width: Int) -> String {
        var lines: [String] = []
        let title = "\(CLICatalog.program) \(command.name)"
        lines.append(bold(title, color) + " — " + command.summary)

        if !command.synopsis.isEmpty {
            lines.append("")
            lines.append(bold("Usage:", color))
            for line in command.synopsis { lines.append("  " + line) }
        }

        if !command.discussion.isEmpty {
            lines.append("")
            lines.append(contentsOf: wrap(command.discussion, width: textWidth(width)))
        }

        if !command.options.isEmpty {
            lines.append("")
            lines.append(bold("Options:", color))
            let gutter = (command.options.map { $0.flags.count }.max() ?? 0) + 2
            for option in command.options {
                lines.append(row(name: option.flags, summary: option.summary,
                                 gutter: gutter, width: width, color: color))
            }
        }

        if !command.subactions.isEmpty {
            lines.append("")
            lines.append(bold("Subcommands:", color))
            let gutter = (command.subactions.map { $0.name.count }.max() ?? 0) + 2
            for subaction in command.subactions {
                lines.append(row(name: subaction.name, summary: subaction.summary,
                                 gutter: gutter, width: width, color: color))
            }
        }

        return lines.joined(separator: "\n")
    }

    /// An unknown command: a sanitized echo of what the user typed, an optional
    /// "did you mean?", and the full global listing so they can pick a real one.
    public static func renderUnknownCommand(_ name: String, color: Bool, width: Int) -> String {
        var lines: [String] = []
        let safe = ReviewDisplay.sanitized(name)
        lines.append("\(CLICatalog.program): "
            + paint("error:", TerminalStyle.Code.red, color)
            + " unknown command \"\(safe)\"")
        if let suggestion = CLICatalog.suggestion(for: name) {
            lines.append("Did you mean \"\(suggestion)\"?")
        }
        lines.append("")
        lines.append(renderGlobal(color: color, width: width))
        return lines.joined(separator: "\n")
    }

    // MARK: - Pieces

    /// A `  name<pad>summary` row with the summary truncated to the terminal width.
    private static func row(
        name: String, summary: String, gutter: Int, width: Int, color: Bool
    ) -> String {
        let padded = name.padding(toLength: max(gutter, name.count + 1), withPad: " ", startingAt: 0)
        let budget = max(8, width - 2 - padded.count)
        return "  " + padded + dim(TerminalStyle.truncate(summary, to: budget), color)
    }

    /// Wrap a discussion into terminal lines: blank lines and already-short lines
    /// pass through unchanged (so aligned examples keep their alignment), while a
    /// long line is greedily word-wrapped at its own leading indentation.
    private static func wrap(_ text: String, width: Int) -> [String] {
        var result: [String] = []
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init) {
            if raw.count <= width {
                result.append(raw)
                continue
            }
            let prefix = String(raw.prefix(while: { $0 == " " }))
            let words = raw.dropFirst(prefix.count).split(separator: " ", omittingEmptySubsequences: true)
            guard !words.isEmpty else { result.append(raw); continue }
            var current = prefix
            for word in words {
                let candidate = current == prefix ? current + word : current + " " + word
                if candidate.count > width, current != prefix {
                    result.append(current)
                    current = prefix + word
                } else {
                    current = candidate
                }
            }
            if !current.isEmpty { result.append(current) }
        }
        return result
    }

    /// Clamp the wrapping width to a readable column count regardless of a very
    /// wide or very narrow terminal.
    private static func textWidth(_ width: Int) -> Int { max(40, min(width, 88)) }

    private static func bold(_ s: String, _ color: Bool) -> String {
        TerminalStyle.paint(s, TerminalStyle.Code.bold, color: color)
    }

    private static func dim(_ s: String, _ color: Bool) -> String {
        TerminalStyle.paint(s, TerminalStyle.Code.dim, color: color)
    }

    private static func paint(_ s: String, _ code: String, _ color: Bool) -> String {
        TerminalStyle.paint(s, code, color: color)
    }
}
