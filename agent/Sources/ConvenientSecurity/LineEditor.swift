import Foundation

/// One editing action for a single-line text prompt, decoded from terminal
/// bytes by `LineEditKeyDecoder`. The bindings are the Emacs/readline ones a
/// macOS shell user expects, plus the arrow, Home/End and Delete keys.
public enum LineEditKey: Equatable, Sendable {
    case insert(Character)
    case backspace
    case deleteForward
    /// Ctrl-D: deletes forward, or cancels an empty line as readline's EOF does.
    case deleteForwardOrEnd
    case left, right
    case home, end
    case wordLeft, wordRight
    case killToEnd
    case killToStart
    /// Ctrl-W: back to whitespace, as the shell's does.
    case killWordBack
    /// Alt-Backspace: back one word of letters and digits, as readline's.
    case killPreviousWord
    case killWordForward
    case submit
    /// Esc on its own, or Ctrl-G: leave the prompt without submitting.
    case cancel
    /// Ctrl-C: leaves a prompt as `cancel` does; a picker around the prompt
    /// treats it as quitting, where Esc only steps back.
    case interrupt
    /// Keys a single line has no use for, which a list around it does: the
    /// picker's filter moves its cursor and picks rows with them.
    case up, down, pageUp, pageDown
    case tab
    case ignored
}

/// Pure single-line editor: the text, the cursor between characters, and the
/// readline editing operations. The raw-mode driver owns only I/O.
public struct LineEditor: Equatable, Sendable {
    public enum Outcome: Equatable, Sendable {
        case editing
        case submitted(String)
        case cancelled
    }

    public private(set) var characters: [Character]
    /// Insertion point, 0...characters.count.
    public private(set) var cursor: Int
    public let maximumLength: Int

    public init(text: String = "", maximumLength: Int = 512) {
        self.maximumLength = maximumLength
        self.characters = Array(text.prefix(maximumLength))
        self.cursor = characters.count
    }

    public var text: String { String(characters) }

    @discardableResult
    public mutating func apply(_ key: LineEditKey) -> Outcome {
        switch key {
        case .insert(let character):
            if characters.count < maximumLength {
                characters.insert(character, at: cursor)
                cursor += 1
            }
        case .backspace:
            if cursor > 0 {
                characters.remove(at: cursor - 1)
                cursor -= 1
            }
        case .deleteForward:
            if cursor < characters.count { characters.remove(at: cursor) }
        case .deleteForwardOrEnd:
            if characters.isEmpty { return .cancelled }
            if cursor < characters.count { characters.remove(at: cursor) }
        case .left:
            cursor = max(0, cursor - 1)
        case .right:
            cursor = min(characters.count, cursor + 1)
        case .home:
            cursor = 0
        case .end:
            cursor = characters.count
        case .wordLeft:
            cursor = previousWordStart()
        case .wordRight:
            cursor = nextWordEnd()
        case .killToEnd:
            characters.removeSubrange(cursor...)
        case .killToStart:
            characters.removeSubrange(..<cursor)
            cursor = 0
        case .killWordBack:
            // Ctrl-W stops at whitespace, as the shell's does, so it removes a
            // whole glob such as `~/work/**/.env` in one go.
            var start = cursor
            while start > 0, characters[start - 1].isWhitespace { start -= 1 }
            while start > 0, !characters[start - 1].isWhitespace { start -= 1 }
            characters.removeSubrange(start..<cursor)
            cursor = start
        case .killPreviousWord:
            let start = previousWordStart()
            characters.removeSubrange(start..<cursor)
            cursor = start
        case .killWordForward:
            let end = nextWordEnd()
            characters.removeSubrange(cursor..<end)
        case .submit:
            return .submitted(text)
        case .cancel, .interrupt:
            return .cancelled
        case .up, .down, .pageUp, .pageDown, .tab, .ignored:
            break
        }
        return .editing
    }

    /// The visible line and the cursor's column for a terminal `width`
    /// columns wide: the prompt, then as much of the text as fits, scrolled so
    /// the cursor stays on screen. One column is left free so writing the last
    /// one never wraps.
    public func render(prompt: String, width: Int) -> (line: String, cursorColumn: Int) {
        let promptText = Array(prompt)
        let usable = max(1, width - 1)
        let room = max(1, usable - promptText.count)
        let visiblePrompt = promptText.count < usable ? promptText : Array(promptText.prefix(usable - room))
        var start = 0
        if characters.count >= room { start = max(0, min(cursor - room + 1, characters.count - room + 1)) }
        let end = min(characters.count, start + room)
        let shown = Array(characters[start..<end])
        return (String(visiblePrompt + shown), visiblePrompt.count + (cursor - start))
    }

    // Words for Alt-B/Alt-F are runs of letters and digits, as in readline, so
    // they step through the components of a path.
    private func isWordCharacter(_ character: Character) -> Bool {
        character.isLetter || character.isNumber
    }

    private func previousWordStart() -> Int {
        var index = cursor
        while index > 0, !isWordCharacter(characters[index - 1]) { index -= 1 }
        while index > 0, isWordCharacter(characters[index - 1]) { index -= 1 }
        return index
    }

    private func nextWordEnd() -> Int {
        var index = cursor
        while index < characters.count, !isWordCharacter(characters[index]) { index += 1 }
        while index < characters.count, isWordCharacter(characters[index]) { index += 1 }
        return index
    }
}

/// Decodes terminal input bytes into `LineEditKey`s. `next` returns the next
/// byte, waiting at most `timeoutMillis` (nil waits indefinitely), or nil when
/// none arrived in time or input ended; it lets a lone Esc be told from the
/// start of an escape sequence without blocking.
public enum LineEditKeyDecoder {
    public static func decode(
        first: UInt8,
        next: (_ timeoutMillis: Int32?) -> UInt8?
    ) -> LineEditKey {
        switch first {
        case 0x01: return .home                 // Ctrl-A
        case 0x02: return .left                 // Ctrl-B
        case 0x03: return .interrupt            // Ctrl-C
        case 0x07: return .cancel               // Ctrl-G
        case 0x04: return .deleteForwardOrEnd   // Ctrl-D
        case 0x05: return .end                  // Ctrl-E
        case 0x06: return .right                // Ctrl-F
        case 0x08, 0x7F: return .backspace      // Ctrl-H, Delete/Backspace
        case 0x09: return .tab
        case 0x0A, 0x0D: return .submit
        case 0x0B: return .killToEnd            // Ctrl-K
        case 0x15: return .killToStart          // Ctrl-U
        case 0x17: return .killWordBack         // Ctrl-W
        case 0x1B: return decodeEscape(next: next)
        case 0x20...0x7E: return .insert(Character(UnicodeScalar(first)))
        case 0xC2...0xF4: return decodeUTF8(lead: first, next: next)
        default: return .ignored
        }
    }

    private static let escapeTimeoutMillis: Int32 = 25

    private static func decodeEscape(next: (Int32?) -> UInt8?) -> LineEditKey {
        guard let second = next(escapeTimeoutMillis) else { return .cancel }
        switch second {
        case UInt8(ascii: "["): return decodeCSI(next: next)
        case UInt8(ascii: "O"):
            switch next(escapeTimeoutMillis) {
            case UInt8(ascii: "A"): return .up
            case UInt8(ascii: "B"): return .down
            case UInt8(ascii: "C"): return .right
            case UInt8(ascii: "D"): return .left
            case UInt8(ascii: "H"): return .home
            case UInt8(ascii: "F"): return .end
            default: return .ignored
            }
        // Alt (Option as Meta) chords.
        case UInt8(ascii: "b"), UInt8(ascii: "B"): return .wordLeft
        case UInt8(ascii: "f"), UInt8(ascii: "F"): return .wordRight
        case UInt8(ascii: "d"), UInt8(ascii: "D"): return .killWordForward
        case 0x7F, 0x08: return .killPreviousWord
        default: return .ignored
        }
    }

    /// `ESC [` sequences: arrows (optionally with a modifier, `1;5C`), Home
    /// and End in both their letter and `~` forms, Delete (`3~`), and Page
    /// Up and Down (`5~`, `6~`). Anything
    /// else is consumed to its final byte and ignored, so its tail never lands
    /// in the text.
    private static func decodeCSI(next: (Int32?) -> UInt8?) -> LineEditKey {
        var parameters: [UInt8] = []
        while let byte = next(escapeTimeoutMillis) {
            if (0x30...0x3F).contains(byte) {
                guard parameters.count < 16 else { return .ignored }
                parameters.append(byte)
                continue
            }
            let fields = String(decoding: parameters, as: UTF8.self).split(separator: ";")
            let modifier = fields.count > 1 ? Int(fields[1]) ?? 1 : 1
            // Ctrl (5) or Alt (3, 9) arrows move by word.
            let byWord = [3, 5, 9].contains(modifier)
            switch byte {
            case UInt8(ascii: "A"): return .up
            case UInt8(ascii: "B"): return .down
            case UInt8(ascii: "C"): return byWord ? .wordRight : .right
            case UInt8(ascii: "D"): return byWord ? .wordLeft : .left
            case UInt8(ascii: "H"): return .home
            case UInt8(ascii: "F"): return .end
            case UInt8(ascii: "~"):
                switch fields.first.flatMap({ Int($0) }) {
                case 1, 7: return .home
                case 4, 8: return .end
                case 3: return .deleteForward
                case 5: return .pageUp
                case 6: return .pageDown
                default: return .ignored
                }
            default:
                return .ignored
            }
        }
        return .ignored
    }

    /// A multi-byte UTF-8 character, so a path with non-ASCII names can be
    /// typed or pasted. Malformed sequences and invisible control or format
    /// characters (bidi overrides among them) are dropped, never inserted.
    private static func decodeUTF8(lead: UInt8, next: (Int32?) -> UInt8?) -> LineEditKey {
        let length = lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : 2
        var bytes = [lead]
        while bytes.count < length {
            guard let byte = next(escapeTimeoutMillis), byte & 0xC0 == 0x80 else { return .ignored }
            bytes.append(byte)
        }
        guard let decoded = String(bytes: bytes, encoding: .utf8),
              let scalar = decoded.unicodeScalars.first,
              decoded.unicodeScalars.count == 1 else { return .ignored }
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate, .unassigned,
             .privateUse:
            return .ignored
        default:
            return .insert(Character(scalar))
        }
    }
}
