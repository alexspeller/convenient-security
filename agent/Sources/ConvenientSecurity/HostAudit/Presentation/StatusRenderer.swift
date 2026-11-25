import Foundation

// Pure terminal rendering of `csec status` / `csec doctor`, mirroring
// `AuditReportRenderer`: it takes explicit `color`/`width` and returns a String,
// so it renders the same to a pipe (no color) as to a terminal and is
// unit-testable without a TTY. The launcher maps its `CompleteStatus` fact struct
// into `StatusRow`s and chooses the stream/color/width around this.

/// The health class of one status row, driving its glyph and value color. Same
/// palette as `AuditReportRenderer`: green ok / yellow warn / red bad / dim
/// neutral.
public enum StatusRowState: Sendable, Equatable {
    case ok
    case warn
    case bad
    case neutral

    /// A filled dot for a graded row, a faint dot for a neutral one.
    public var glyph: String {
        switch self {
        case .ok, .warn, .bad: return "●"
        case .neutral: return "·"
        }
    }

    var code: String {
        switch self {
        case .ok: return TerminalStyle.Code.green
        case .warn: return TerminalStyle.Code.yellow
        case .bad: return TerminalStyle.Code.red
        case .neutral: return TerminalStyle.Code.dim
        }
    }
}

/// One labeled line of status.
public struct StatusRow: Sendable, Equatable {
    public let label: String
    public let value: String
    public let state: StatusRowState

    public init(label: String, value: String, state: StatusRowState) {
        self.label = label
        self.value = value
        self.state = state
    }
}

public enum StatusRenderer {
    /// Render a bold title, an overall badge, and aligned state-colored rows.
    /// `overallHealthy` is `true` (green "healthy"), `false` (red "needs
    /// attention"), or `nil` (dim, when a verdict is not applicable).
    public static func render(
        title: String,
        rows: [StatusRow],
        overallHealthy: Bool?,
        color: Bool,
        width: Int
    ) -> String {
        var lines: [String] = []
        lines.append(TerminalStyle.paint(title, TerminalStyle.Code.bold, color: color))
        lines.append("  " + badge(overallHealthy, color: color))
        lines.append("")

        let gutter = (rows.map { $0.label.count }.max() ?? 0) + 1
        for row in rows {
            let glyph = TerminalStyle.paint(row.state.glyph, row.state.code, color: color)
            let label = (row.label + ":").padding(
                toLength: gutter + 1, withPad: " ", startingAt: 0)
            // Truncate a runaway value so a narrow terminal never wraps a row, but
            // keep the label and glyph intact.
            let budget = max(8, width - 4 - label.count)
            let value = TerminalStyle.paint(
                TerminalStyle.truncate(row.value, to: budget), row.state.code, color: color)
            lines.append("  \(glyph) \(label) \(value)")
        }
        return lines.joined(separator: "\n")
    }

    private static func badge(_ healthy: Bool?, color: Bool) -> String {
        switch healthy {
        case .some(true):
            return TerminalStyle.paint("● healthy", TerminalStyle.Code.green, color: color)
        case .some(false):
            return TerminalStyle.paint("● needs attention", TerminalStyle.Code.red, color: color)
        case .none:
            return TerminalStyle.paint("· status unavailable", TerminalStyle.Code.dim, color: color)
        }
    }
}
