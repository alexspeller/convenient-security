import ConvenientSecurity
import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// Raw-mode driver for the checkbox picker. Owns only I/O: it reads keys, mutates
/// a pure `AuditSelectModel`, and redraws the block in place on stderr (so a piped
/// stdout stays clean). Returns the selected catalog keys on apply, an empty array
/// when there is nothing to pick, or nil when the user cancels or the terminal is
/// non-interactive.
enum AuditSelectView {
    static func run(items: [HostRemediationItem]) -> [String]? {
        guard !items.isEmpty else { return [] }
        guard let raw = TerminalRawMode() else { return nil }
        defer { raw.restore() }
        let color = TerminalStyle.colorEnabled(STDERR_FILENO)
        var model = AuditSelectModel(items: items)
        var previousLines = 0

        func redraw() {
            let width = max(20, TerminalStyle.terminalWidth(fd: STDERR_FILENO)) - 1
            previousLines = draw(model.render(color: color, width: width), previousLines: previousLines)
        }
        redraw()

        while true {
            switch raw.readKey() {
            case .up, .char("k"): model.moveUp(); redraw()
            case .down, .char("j"): model.moveDown(); redraw()
            case .space: model.toggle(); redraw()
            case .char("a"), .char("A"): model.toggleAll(); redraw()
            case .enter:
                clearBlock(previousLines)
                return model.selectedKeys
            case .char("q"), .char("Q"), .escape, .ctrlC, .eof:
                clearBlock(previousLines)
                return nil
            default:
                continue
            }
        }
    }

    /// Redraw the block in place: move up over the previous block, clear to the end
    /// of the screen, reprint. Returns the new block's screen-row count.
    private static func draw(_ block: String, previousLines: Int) -> Int {
        var out = ""
        if previousLines > 0 { out += "\u{1B}[\(previousLines)A" }
        out += "\r\u{1B}[0J" + block
        FileHandle.standardError.write(Data(out.utf8))
        return block.reduce(0) { $0 + ($1 == "\n" ? 1 : 0) }
    }

    private static func clearBlock(_ previousLines: Int) {
        var out = ""
        if previousLines > 0 { out += "\u{1B}[\(previousLines)A" }
        out += "\r\u{1B}[0J"
        FileHandle.standardError.write(Data(out.utf8))
    }
}
