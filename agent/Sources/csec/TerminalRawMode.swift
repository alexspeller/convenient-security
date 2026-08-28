import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// One key event read from the terminal in raw mode.
enum TerminalKey: Equatable {
    case up, down, left, right
    case space, enter, escape, backspace
    case char(Character)
    case ctrlC
    case eof
    case unknown
}

/// Minimal `termios` raw-mode session for the interactive `csec audit` pickers.
/// Byte-at-a-time input with echo and canonical line editing off, but `ISIG` left
/// on so Ctrl-C still raises `SIGINT` — a handler then restores the terminal and
/// shows the cursor before exiting, so an interrupt never leaves the terminal raw
/// or the cursor hidden. Normal exit restores via `deinit`/`restore()`. Drawing
/// goes to stderr; keys come from stdin.
final class TerminalRawMode {
    private var saved = termios()
    private var active = false

    // The SIGINT handler is C and async-signal context: it can only touch these
    // process-globals plus `tcsetattr`/`write`/`_exit`.
    nonisolated(unsafe) private static var savedForSignal = termios()
    nonisolated(unsafe) private static var handlerInstalled = false
    private static let showCursorBytes: [UInt8] = [0x1B, 0x5B, 0x3F, 0x32, 0x35, 0x68, 0x0A]

    /// Enter raw mode. Returns nil when stdin is not a terminal (non-interactive),
    /// so callers fall back to a non-interactive path.
    init?() {
        guard isatty(STDIN_FILENO) == 1 else { return nil }
        guard tcgetattr(STDIN_FILENO, &saved) == 0 else { return nil }
        Self.savedForSignal = saved

        var raw = saved
        raw.c_lflag &= ~(UInt(ECHO) | UInt(ICANON))
        // Read one byte at a time with no inter-byte timeout.
        withUnsafeMutablePointer(to: &raw.c_cc) { tuple in
            tuple.withMemoryRebound(to: UInt8.self, capacity: Int(NCCS)) { cc in
                cc[Int(VMIN)] = 1
                cc[Int(VTIME)] = 0
            }
        }
        guard tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0 else { return nil }
        active = true
        Self.installSignalHandler()
        FileHandle.standardError.write(Data("\u{1B}[?25l".utf8))   // hide cursor
    }

    /// Restore cooked mode and the cursor. Idempotent.
    func restore() {
        guard active else { return }
        active = false
        tcsetattr(STDIN_FILENO, TCSANOW, &saved)
        FileHandle.standardError.write(Data("\u{1B}[?25h".utf8))
    }

    deinit { restore() }

    private static func installSignalHandler() {
        guard !handlerInstalled else { return }
        handlerInstalled = true
        signal(SIGINT) { _ in
            tcsetattr(STDIN_FILENO, TCSANOW, &TerminalRawMode.savedForSignal)
            TerminalRawMode.showCursorBytes.withUnsafeBytes { _ = write(2, $0.baseAddress, $0.count) }
            _exit(130)
        }
    }

    /// Read one key event (blocking). Decodes the common CSI arrow sequences and
    /// distinguishes a lone Esc from a sequence without blocking.
    func readKey() -> TerminalKey {
        var byte: UInt8 = 0
        guard read(STDIN_FILENO, &byte, 1) == 1 else { return .eof }
        switch byte {
        case 0x03: return .ctrlC
        case 0x0D, 0x0A: return .enter
        case 0x20: return .space
        case 0x7F, 0x08: return .backspace
        case 0x1B: return readEscape()
        default:
            if byte >= 0x20, byte < 0x7F { return .char(Character(UnicodeScalar(byte))) }
            return .unknown
        }
    }

    private func readEscape() -> TerminalKey {
        guard byteAvailable(timeoutMillis: 25) else { return .escape }
        var open: UInt8 = 0
        guard read(STDIN_FILENO, &open, 1) == 1, open == 0x5B else { return .escape }
        guard byteAvailable(timeoutMillis: 25) else { return .escape }
        var code: UInt8 = 0
        guard read(STDIN_FILENO, &code, 1) == 1 else { return .escape }
        switch code {
        case 0x41: return .up
        case 0x42: return .down
        case 0x43: return .right
        case 0x44: return .left
        default: return .unknown
        }
    }

    private func byteAvailable(timeoutMillis: Int32) -> Bool {
        var fds = pollfd(fd: STDIN_FILENO, events: Int16(POLLIN), revents: 0)
        return poll(&fds, 1, timeoutMillis) > 0
    }

    /// Read a single line without echoing anything (secret entry): no glyphs,
    /// no masking dots, nothing on screen until the final newline. Collected
    /// byte-accurately (unlike `readKey`, which drops non-ASCII), so pasted
    /// UTF-8 secrets survive; backspace removes one UTF-8 scalar. Escape
    /// sequences (arrows etc.) are swallowed rather than captured into the
    /// secret. Returns nil on Ctrl-D/EOF with nothing typed.
    func readHiddenLine(maxBytes: Int) -> Data? {
        var bytes: [UInt8] = []
        while true {
            var byte: UInt8 = 0
            guard read(STDIN_FILENO, &byte, 1) == 1 else { return nil }
            switch byte {
            case 0x0D, 0x0A:
                FileHandle.standardError.write(Data("\n".utf8))
                return Data(bytes)
            case 0x7F, 0x08:
                while let last = bytes.last, last & 0xC0 == 0x80 { bytes.removeLast() }
                if !bytes.isEmpty { bytes.removeLast() }
            case 0x04:
                if bytes.isEmpty { return nil }
            case 0x1B:
                while byteAvailable(timeoutMillis: 25) {
                    var discarded: UInt8 = 0
                    guard read(STDIN_FILENO, &discarded, 1) == 1 else { return nil }
                }
            default:
                if bytes.count < maxBytes { bytes.append(byte) }
            }
        }
    }

    /// Read a single cooked line (for a triage note): echoes printable characters
    /// and handles backspace, bounded to `maxLength`. Returns nil on Ctrl-C/EOF.
    func readLine(maxLength: Int) -> String? {
        var chars: [Character] = []
        while true {
            switch readKey() {
            case .enter:
                FileHandle.standardError.write(Data("\n".utf8))
                return String(chars)
            case .backspace:
                if !chars.isEmpty {
                    chars.removeLast()
                    FileHandle.standardError.write(Data("\u{8} \u{8}".utf8))   // erase one glyph
                }
            case let .char(character):
                if chars.count < maxLength {
                    chars.append(character)
                    FileHandle.standardError.write(Data(String(character).utf8))
                }
            case .ctrlC, .eof:
                return nil
            default:
                continue
            }
        }
    }
}
