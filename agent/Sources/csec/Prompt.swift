import Foundation
import ConvenientSecurity
#if canImport(Darwin)
import Darwin
#endif

// The one interactive-output utility for the launcher's guided flows (`csec setup`
// and the guided audit helpers). Every message goes to stderr — so a wrapped
// tool's stdout, or copyable data like the audit prompt, stays clean — with color
// gated on stderr and body text wrapped to the terminal width. `confirm` reads a
// line from stdin (unchanged), which fixes the former helpers that wrote their
// prompt/narrative to stdout.
enum Prompt {
    private static var color: Bool { TerminalStyle.colorEnabled(STDERR_FILENO) }
    private static var width: Int { max(40, min(TerminalStyle.terminalWidth(fd: fileno(stderr)), 88)) }

    /// A bold header preceded by a blank line — the top of a guided flow.
    static func title(_ text: String) {
        write("\n" + paint(text, TerminalStyle.Code.bold) + "\n")
    }

    /// A bold section header for one guided step, preceded by a blank line.
    static func step(_ text: String) {
        write("\n" + paint(text, TerminalStyle.Code.bold) + "\n")
    }

    /// Dim explanatory body text, wrapped to the terminal width.
    static func note(_ text: String) {
        for line in wrapped(text) { write(paint(line, TerminalStyle.Code.dim) + "\n") }
    }

    /// A green success line marked with a check.
    static func success(_ text: String) {
        write(paint("✓ " + text, TerminalStyle.Code.green) + "\n")
    }

    /// A yellow warning line, wrapped to the terminal width.
    static func warn(_ text: String) {
        for line in wrapped(text) { write(paint(line, TerminalStyle.Code.yellow) + "\n") }
    }

    /// A yes/no confirmation. Returns `defaultValue` on empty input or EOF.
    static func confirm(_ question: String, default defaultValue: Bool = false) -> Bool {
        let suffix = defaultValue ? "[Y/n]" : "[y/N]"
        write(paint(question, TerminalStyle.Code.bold) + " \(suffix): ")
        guard let line = readLine(strippingNewline: true) else { return defaultValue }
        let trimmed = line.trimmingCharacters(in: .whitespaces).lowercased()
        if trimmed.isEmpty { return defaultValue }
        return trimmed == "y" || trimmed == "yes"
    }

    // MARK: - internals

    private static func paint(_ text: String, _ code: String) -> String {
        TerminalStyle.paint(text, code, color: color)
    }

    private static func write(_ text: String) {
        FileHandle.standardError.write(Data(text.utf8))
    }

    /// Greedy word-wrap that preserves each line's own leading indentation and
    /// passes short lines and blank lines through unchanged.
    private static func wrapped(_ text: String) -> [String] {
        let limit = width
        var result: [String] = []
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init) {
            if raw.count <= limit { result.append(raw); continue }
            let prefix = String(raw.prefix(while: { $0 == " " }))
            let words = raw.dropFirst(prefix.count).split(separator: " ", omittingEmptySubsequences: true)
            guard !words.isEmpty else { result.append(raw); continue }
            var current = prefix
            for word in words {
                let candidate = current == prefix ? current + word : current + " " + word
                if candidate.count > limit, current != prefix {
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
}
