import ConvenientSecurity
import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// Raw-mode driver for the env-var picker. Owns only I/O: it reads keys,
/// mutates a pure `EnvSelectModel`, and redraws the block in place on stderr
/// (so a piped stdout stays clean). Returns the selected variable names on
/// apply, an empty array when nothing is selected, or nil when the user
/// cancels or the terminal is non-interactive.
enum EnvSelectView {
    static func run(
        rows: [EnvSelectRow],
        initiallySelected: Set<Int>,
        valuesByName: [String: String]
    ) -> [String]? {
        guard !rows.isEmpty else { return [] }
        guard let raw = TerminalRawMode(captureInterrupt: true) else { return nil }
        defer { raw.restore() }
        let color = TerminalStyle.colorEnabled(STDERR_FILENO)
        var model = EnvSelectModel(rows: rows, initiallySelected: initiallySelected)
        var valuesRevealed = false
        var previousLines = 0

        func redraw() {
            let width = max(20, TerminalStyle.terminalWidth(fd: STDERR_FILENO)) - 1
            previousLines = draw(model.render(
                color: color,
                width: width,
                revealedValues: valuesRevealed ? valuesByName : nil
            ), previousLines: previousLines)
        }
        redraw()

        while true {
            switch raw.readKey() {
            case .up, .char("k"): model.moveUp(); redraw()
            case .down, .char("j"): model.moveDown(); redraw()
            case .space: model.toggle(); redraw()
            case .char("a"), .char("A"): model.toggleAll(); redraw()
            case .char("v"), .char("V"): valuesRevealed.toggle(); redraw()
            case .enter:
                clearBlock(previousLines)
                return model.selectedNames
            case .char("q"), .char("Q"), .escape, .ctrlC, .eof:
                clearBlock(previousLines)
                return nil
            default:
                continue
            }
        }
    }

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
