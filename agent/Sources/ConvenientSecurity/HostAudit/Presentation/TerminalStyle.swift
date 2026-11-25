import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// Shared, dependency-free ANSI helpers for the `csec audit` terminal UI. The
/// package ships zero third-party dependencies by design (supply chain is its
/// threat model), so the terminal presenters are hand-rolled. These live in the
/// library — not the launcher — so the pure renderers/models that use them are
/// unit-testable from `cs-selftest`. Rendering functions take an explicit
/// `color`/`width` so they stay pure and produce identical output to a pipe.
public enum TerminalStyle {
    /// SGR color/style codes used across the audit UI.
    public enum Code {
        public static let bold = "1"
        public static let dim = "2"
        public static let red = "31"
        public static let green = "32"
        public static let yellow = "33"
        public static let blue = "34"
        public static let magenta = "35"
        public static let cyan = "36"
    }

    /// Color is on only when the stream is a terminal and `NO_COLOR` is unset.
    public static func colorEnabled(_ fd: Int32) -> Bool {
        ProcessInfo.processInfo.environment["NO_COLOR"] == nil && isatty(fd) == 1
    }

    /// Wrap `text` in an SGR code when `color` is on and the text is non-empty.
    public static func paint(_ text: String, _ code: String, color: Bool) -> String {
        color && !text.isEmpty ? "\u{1B}[\(code)m\(text)\u{1B}[0m" : text
    }

    /// Character-count truncation with an ellipsis. The audit strings are already
    /// sanitized to a narrow, mostly-ASCII repertoire, so Character count is a
    /// good-enough proxy for display width.
    public static func truncate(_ text: String, to limit: Int) -> String {
        guard limit > 0 else { return "" }
        if text.count <= limit { return text }
        if limit <= 1 { return "…" }
        return String(text.prefix(limit - 1)) + "…"
    }

    /// Terminal column count for `fd` (falls back to `$COLUMNS`, then 80).
    public static func terminalWidth(fd: Int32) -> Int {
        #if canImport(Darwin)
        var ws = winsize()
        if ioctl(fd, UInt(TIOCGWINSZ), &ws) == 0, ws.ws_col > 0 {
            return Int(ws.ws_col)
        }
        #endif
        if let columns = ProcessInfo.processInfo.environment["COLUMNS"], let value = Int(columns), value > 0 {
            return value
        }
        return 80
    }
}
