import ConvenientSecurity
import Foundation

#if canImport(Darwin)
import Darwin
#endif

// Terminal niceties for `csec audit`: an animated, value-free progress line for
// the streaming scan, and a small indeterminate spinner for the remediation step
// (which re-checks the host before presenting the Touch ID review). All drawing
// goes to stderr so a piped/`--json` stdout stays clean; nothing here renders a
// credential value — only catalog ids/titles and counts, sanitized once more at
// the display boundary via `auditSafe`.

/// Bytes for "show cursor + newline", written from the SIGINT handler (which must
/// stay async-signal-safe — a preallocated buffer, `write`, and `_exit` only).
private let showCursorInterruptBytes: [UInt8] = [0x1B, 0x5B, 0x3F, 0x32, 0x35, 0x68, 0x0A]

/// Restore the cursor if the user interrupts (Ctrl-C) mid-animation, so the
/// terminal is never left with a hidden cursor. Best-effort; the normal exit path
/// restores it too.
func installAuditInterruptCursorRestore() {
    signal(SIGINT) { _ in
        showCursorInterruptBytes.withUnsafeBytes { _ = write(2, $0.baseAddress, $0.count) }
        _exit(130)
    }
}

/// True when stderr is an interactive terminal — the only place the animation is
/// drawn. When false (piped, redirected, CI), the caller uses a quiet path.
func auditAnimationEnabled() -> Bool {
    isatty(fileno(stderr)) == 1
}

/// True when the launcher can drive an interactive picker: it reads keys from
/// stdin and draws the UI on stderr, so both must be terminals. Independent of
/// stdout, so `csec audit` can pipe its report/attestation while still prompting.
func auditInteractionEnabled() -> Bool {
    isatty(fileno(stdin)) == 1 && isatty(fileno(stderr)) == 1
}

/// A single, redraw-in-place progress line for the streaming audit.
struct AuditProgressView {
    private let start: Date
    private let useColor: Bool
    private var frame = 0
    private static let spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    private static let barCells = 16

    init(start: Date) {
        self.start = start
        self.useColor = ProcessInfo.processInfo.environment["NO_COLOR"] == nil
        // Hide the cursor for the duration of the animation.
        FileHandle.standardError.write(Data("\u{1B}[?25l".utf8))
    }

    /// Draw the current snapshot, advancing the spinner one frame.
    mutating func render(_ snapshot: HostAuditProgressSnapshot, now: Date = Date()) {
        defer { frame += 1 }
        let width = Self.terminalWidth()

        let spin = Self.spinner[frame % Self.spinner.count]
        let total = max(snapshot.total, 1)
        let completed = min(max(snapshot.completed, 0), total)
        let fraction = Double(completed) / Double(total)
        let filled = min(Self.barCells, Int(fraction * Double(Self.barCells)))
        let percent = Int((fraction * 100).rounded())

        let barFilled = String(repeating: "█", count: filled)
        let barEmpty = String(repeating: "░", count: Self.barCells - filled)
        let percentText = "\(percent)%"

        // Plain length of the fixed head: spinner + space + bar + space + percent.
        let headPlainCount = 1 + 1 + Self.barCells + 1 + percentText.count
        let head =
            paint(spin, "36") + " "
            + paint(barFilled, "32") + paint(barEmpty, "2") + " "
            + paint(percentText, "1")

        // Variable tail: counts, the domain phase, and the check now running.
        var tail = "  \(completed)/\(total)  \(phaseLabel(for: snapshot.currentID))"
        if !snapshot.currentID.isEmpty {
            let title = auditSafe(snapshot.currentTitle)
            tail += " · \(snapshot.currentID) \(title)"
        }
        tail += "  (\(elapsedText(now: now)))"

        // Truncate the tail to the remaining columns so the line never wraps.
        let budget = max(0, width - headPlainCount - 1)
        let clippedTail = truncate(tail, to: budget)

        let line = "\r\u{1B}[2K" + head + paint(clippedTail, "2")
        FileHandle.standardError.write(Data(line.utf8))
    }

    /// Clear the animation line and restore the cursor. Call once when finished.
    func finish() {
        FileHandle.standardError.write(Data("\r\u{1B}[2K\u{1B}[?25h".utf8))
    }

    // MARK: - helpers

    private func paint(_ text: String, _ code: String) -> String {
        useColor && !text.isEmpty ? "\u{1B}[\(code)m\(text)\u{1B}[0m" : text
    }

    private func elapsedText(now: Date) -> String {
        String(format: "%.1fs", max(0, now.timeIntervalSince(start)))
    }

    /// Map a catalog id ("HA-D03") to its human domain label. Purely presentational
    /// and value-free; the letter after "HA-" is the catalog domain.
    private func phaseLabel(for id: String) -> String {
        guard id.hasPrefix("HA-"), let letter = id.dropFirst(3).first else { return "finalizing" }
        switch letter {
        case "A": return "Platform integrity"
        case "B": return "Malware defenses"
        case "C": return "Network exposure"
        case "D": return "Privacy & TCC"
        case "E": return "Persistence"
        case "F": return "Developer surface"
        case "G": return "Accounts"
        case "H": return "Physical access"
        case "I": return "Logging"
        case "J": return "Data leakage"
        case "K": return "Coverage"
        default: return "Scanning"
        }
    }

    private func truncate(_ text: String, to limit: Int) -> String {
        guard limit > 0 else { return "" }
        if text.count <= limit { return text }
        if limit <= 1 { return "…" }
        return String(text.prefix(limit - 1)) + "…"
    }

    static func terminalWidth() -> Int {
        #if canImport(Darwin)
        var ws = winsize()
        if ioctl(fileno(stderr), UInt(TIOCGWINSZ), &ws) == 0, ws.ws_col > 0 {
            return Int(ws.ws_col)
        }
        #endif
        if let columns = ProcessInfo.processInfo.environment["COLUMNS"], let value = Int(columns), value > 0 {
            return value
        }
        return 80
    }
}

/// A small indeterminate spinner used while a blocking call runs (the remediation
/// review, whose csecd side re-checks the host before the Touch ID window). Draws
/// to stderr and clears itself when stopped.
struct IndeterminateSpinner {
    private let label: String
    private let useColor: Bool
    private var frame = 0
    private static let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

    init(label: String) {
        self.label = label
        self.useColor = ProcessInfo.processInfo.environment["NO_COLOR"] == nil
        FileHandle.standardError.write(Data("\u{1B}[?25l".utf8))
    }

    mutating func tick() {
        defer { frame += 1 }
        let spin = Self.frames[frame % Self.frames.count]
        let coloredSpin = useColor ? "\u{1B}[36m\(spin)\u{1B}[0m" : spin
        let line = "\r\u{1B}[2K\(coloredSpin) \(label)"
        FileHandle.standardError.write(Data(line.utf8))
    }

    func stop() {
        FileHandle.standardError.write(Data("\r\u{1B}[2K\u{1B}[?25h".utf8))
    }
}
