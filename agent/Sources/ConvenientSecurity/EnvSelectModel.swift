import Foundation

/// One picker row for `csec protect --env`. Rows never carry secret values —
/// only the variable name and value-free annotations (line number, commented
/// state, occurrence count, why a row is not selectable).
public struct EnvSelectRow: Equatable {
    public let name: String
    public let selectable: Bool
    public let annotation: String
    public let secretLike: Bool

    public init(name: String, selectable: Bool, annotation: String, secretLike: Bool) {
        self.name = name
        self.selectable = selectable
        self.annotation = annotation
        self.secretLike = secretLike
    }
}

/// Pure state machine for the env-var checkbox picker, mirroring
/// `AuditSelectModel` but with per-row initial selection (secret-looking vars
/// start checked, commented ones don't) and non-selectable info rows (values
/// that are already references, uninterpretable, or empty). The raw-mode
/// driver owns only I/O; every transition and the rendered block live here so
/// they are unit-testable without a TTY.
public struct EnvSelectModel: Equatable {
    public let rows: [EnvSelectRow]
    public private(set) var selected: Set<Int>
    public private(set) var cursor: Int

    public init(rows: [EnvSelectRow], initiallySelected: Set<Int>) {
        self.rows = rows
        self.selected = Set(initiallySelected.filter {
            rows.indices.contains($0) && rows[$0].selectable
        })
        self.cursor = 0
    }

    /// Build rows and the initial selection from parsed candidates.
    public static func rows(
        for candidates: [EnvFileDocument.Candidate]
    ) -> (rows: [EnvSelectRow], initiallySelected: Set<Int>) {
        var rows: [EnvSelectRow] = []
        var initiallySelected: Set<Int> = []
        for candidate in candidates {
            var notes = ["line \(candidate.lineNumber)"]
            if candidate.winningIsCommented { notes.append("commented") }
            if candidate.occurrenceCount > 1 {
                notes.append("\(candidate.occurrenceCount) occurrences")
            }
            if candidate.differingValues { notes.append("values differ") }

            var selectable = false
            var secretLike = SecretHeuristics.nameLooksSecretLike(candidate.name)
            switch candidate.kind {
            case .importable:
                selectable = true
                secretLike = secretLike
                    || SecretHeuristics.valueLooksSecretLike(candidate.importValue)
            case .alreadyReference(let scheme):
                notes.append("already \(scheme)://")
            case .unsupported:
                notes.append("unsupported value")
            case .empty:
                notes.append("empty")
            }
            if secretLike { notes.append("secret-like") }

            if candidate.preselect { initiallySelected.insert(rows.count) }
            rows.append(EnvSelectRow(
                name: candidate.name,
                selectable: selectable,
                annotation: notes.joined(separator: " · "),
                secretLike: secretLike
            ))
        }
        return (rows, initiallySelected)
    }

    public mutating func moveUp() { if cursor > 0 { cursor -= 1 } }
    public mutating func moveDown() { if cursor < rows.count - 1 { cursor += 1 } }

    public mutating func toggle() {
        guard rows.indices.contains(cursor), rows[cursor].selectable else { return }
        if selected.contains(cursor) { selected.remove(cursor) } else { selected.insert(cursor) }
    }

    /// Toggle across selectable rows only: if all are selected, clear;
    /// otherwise select them all.
    public mutating func toggleAll() {
        let selectable = Set(rows.indices.filter { rows[$0].selectable })
        selected = selected == selectable ? [] : selectable
    }

    /// The still-selected variable names, in list order.
    public var selectedNames: [String] {
        rows.indices.filter { selected.contains($0) }.map { rows[$0].name }
    }

    public var selectableCount: Int { rows.filter(\.selectable).count }

    /// Render the picker as a single redraw block (no trailing newline). Each
    /// line is truncated to `width` so the block never soft-wraps.
    public func render(color: Bool, width: Int) -> String {
        let clamp = max(8, width)
        var lines: [String] = []
        lines.append(TerminalStyle.paint(
            TerminalStyle.truncate("Select variables to protect", to: clamp),
            TerminalStyle.Code.bold, color: color))
        lines.append(TerminalStyle.paint(
            TerminalStyle.truncate("space toggle · ↑/↓ move · a all/none · enter import · q cancel", to: clamp),
            TerminalStyle.Code.dim, color: color))

        for (index, row) in rows.enumerated() {
            let onCursor = index == cursor
            let box = row.selectable ? (selected.contains(index) ? "[x]" : "[ ]") : " - "
            let marker = onCursor ? "▸ " : "  "
            let raw = "\(marker)\(box) \(row.name)  \(row.annotation)"
            var line = TerminalStyle.truncate(raw, to: clamp)
            if onCursor {
                line = TerminalStyle.paint(line, TerminalStyle.Code.bold, color: color)
            } else if !row.selectable {
                line = TerminalStyle.paint(line, TerminalStyle.Code.dim, color: color)
            } else if selected.contains(index) {
                line = TerminalStyle.paint(line, TerminalStyle.Code.green, color: color)
            }
            lines.append(line)
        }

        lines.append(TerminalStyle.paint(
            TerminalStyle.truncate("\(selected.count) of \(selectableCount) selected", to: clamp),
            TerminalStyle.Code.dim, color: color))
        return lines.joined(separator: "\n")
    }
}
