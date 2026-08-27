import Foundation

/// Pure state machine for the terminal checkbox picker that chooses which
/// reversible fixes to apply. All fixes start selected (the on-thesis default is
/// "apply everything safe"); the user deselects what they want to keep as-is. The
/// launcher's raw-mode driver owns only I/O — every state transition and the
/// rendered block live here, so they are unit-testable without a TTY.
public struct AuditSelectModel: Equatable {
    public let items: [HostRemediationItem]
    public private(set) var selected: Set<Int>
    public private(set) var cursor: Int

    public init(items: [HostRemediationItem]) {
        self.items = items
        self.selected = Set(items.indices)
        self.cursor = 0
    }

    public mutating func moveUp() { if cursor > 0 { cursor -= 1 } }
    public mutating func moveDown() { if cursor < items.count - 1 { cursor += 1 } }

    public mutating func toggle() {
        guard items.indices.contains(cursor) else { return }
        if selected.contains(cursor) { selected.remove(cursor) } else { selected.insert(cursor) }
    }

    /// Toggle the whole set: if everything is selected, clear; otherwise select all.
    public mutating func toggleAll() {
        selected = selected.count == items.count ? [] : Set(items.indices)
    }

    /// The catalog keys of the still-selected fixes, in list order.
    public var selectedKeys: [String] {
        items.indices.filter { selected.contains($0) }.map { items[$0].key }
    }

    /// Render the picker as a single redraw block (no trailing newline). Each line
    /// is truncated to `width` so the block never soft-wraps — the driver's cursor
    /// math counts one screen row per '\n'.
    public func render(color: Bool, width: Int) -> String {
        let clamp = max(8, width)
        var lines: [String] = []
        lines.append(TerminalStyle.paint(
            TerminalStyle.truncate("Select fixes to apply", to: clamp),
            TerminalStyle.Code.bold, color: color))
        lines.append(TerminalStyle.paint(
            TerminalStyle.truncate("space toggle · ↑/↓ move · a all/none · enter apply · q cancel", to: clamp),
            TerminalStyle.Code.dim, color: color))

        for (index, item) in items.enumerated() {
            let onCursor = index == cursor
            let box = selected.contains(index) ? "[x]" : "[ ]"
            let marker = onCursor ? "▸ " : "  "
            let root = item.requiresRoot ? " · root" : ""
            let raw = "\(marker)\(box) \(item.key)  \(ReviewDisplay.sanitized(item.title))\(root)"
            var title = TerminalStyle.truncate(raw, to: clamp)
            if onCursor {
                title = TerminalStyle.paint(title, TerminalStyle.Code.bold, color: color)
            } else if selected.contains(index) {
                title = TerminalStyle.paint(title, TerminalStyle.Code.green, color: color)
            }
            lines.append(title)
            let detail = TerminalStyle.truncate("      \(ReviewDisplay.sanitized(item.detail))", to: clamp)
            lines.append(TerminalStyle.paint(detail, TerminalStyle.Code.dim, color: color))
        }

        lines.append(TerminalStyle.paint(
            TerminalStyle.truncate("\(selected.count) of \(items.count) selected", to: clamp),
            TerminalStyle.Code.dim, color: color))
        return lines.joined(separator: "\n")
    }
}
