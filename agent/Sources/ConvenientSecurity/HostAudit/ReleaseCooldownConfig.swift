import Foundation

// The small, line-oriented config reading and editing HA-F13 needs: one key in
// an npmrc/pip.conf-style ini file, a top-level YAML mapping, or a TOML table.
// None of these is a general parser. Each reads only the lines in the scope the
// tool itself reads the key from, and each edit changes or adds that one line
// and leaves every other byte of the file as it was, so a file that also holds
// credentials (~/.npmrc, ~/.bundle/config, pip.conf) keeps them untouched.
// An edit returns nil when the file's shape is one it cannot change safely; the
// fix is then withheld rather than guessed at.

public enum CooldownConfigFormat: Sendable, Equatable {
    /// `key=value` lines; `section` nil means the lines before any `[section]`.
    case ini(section: String?)
    /// A top-level `key: value` in a block-style YAML mapping.
    case yaml
    /// `key = value` in a TOML table; `table` nil means the root table, the
    /// lines before the first `[table]` header.
    case toml(table: String?)
    /// Python configparser, as pip reads pip.conf: `key = value` or
    /// `key: value` in `[section]`, keys matched case-insensitively with `_`
    /// read as `-`, and an indented line continuing the previous value.
    case configparser(section: String)
}

public enum ReleaseCooldownConfig {
    /// The raw value of `key` in its scope, quotes and trailing comment removed,
    /// or nil when the key is absent. The last occurrence wins, as it does for
    /// npm's and pip's ini readers.
    public static func value(in text: String, key: String, format: CooldownConfigFormat) -> String? {
        var found: String?
        for line in scopedLines(text, format: format) where line.inScope {
            if let value = parse(line.text, key: key, format: format) { found = value }
        }
        return found
    }

    /// `text` with `key` set to `literal` (written exactly as given, quotes
    /// included). Replaces each existing line for the key in scope; otherwise adds
    /// one line where the tool reads it. `text` nil means the file does not exist
    /// yet. Returns nil when the file cannot be edited safely.
    public static func setting(
        _ text: String?, key: String, literal: String, format: CooldownConfigFormat
    ) -> String? {
        let newLine: String
        switch format {
        case .ini: newLine = "\(key)=\(literal)"
        case .configparser: newLine = "\(key) = \(literal)"
        case .yaml: newLine = "\(key): \(literal)"
        case .toml: newLine = "\(key) = \(literal)"
        }
        guard let text, !text.isEmpty else {
            switch format {
            case .ini(section: let section?), .toml(table: let section?), .configparser(section: let section):
                return "[\(section)]\n\(newLine)\n"
            default:
                return newLine + "\n"
            }
        }
        // Swift treats "\r\n" as one Character, so look at the scalars.
        if text.unicodeScalars.contains("\r") { return nil }
        var lines = text.components(separatedBy: "\n")
        let hadTrailingNewline = text.hasSuffix("\n")
        if hadTrailingNewline { lines.removeLast() }
        let scoped = scopedLines(text, format: format)

        var replaced = false
        for (index, line) in scoped.enumerated() where line.inScope {
            guard parse(line.text, key: key, format: format) != nil else { continue }
            // A YAML key whose value continues on the next, indented line is a
            // block this line-editor cannot replace.
            if case .yaml = format, rawValue(line.text, format: format).isEmpty { return nil }
            // A configparser value continued on indented lines would keep them.
            if case .configparser = format, index + 1 < scoped.count,
               let next = scoped[index + 1].text.first, next == " " || next == "\t" {
                return nil
            }
            lines[index] = newLine
            replaced = true
        }
        if !replaced {
            switch format {
            case .yaml:
                // A flow-style or non-mapping document has no top-level key lines
                // to add beside.
                guard isBlockMapping(scoped.map(\.text)) else { return nil }
                lines.append(newLine)
            case .toml(table: let table?) where definesTableOutsideIt(scoped.map(\.text), table):
                // `settings.x = …` or `settings = {…}` at the root already
                // defines the table; TOML forbids a `[settings]` header after it.
                return nil
            case .ini(section: nil), .toml(table: nil):
                // Root keys must come before the first section/table header.
                if let header = scoped.firstIndex(where: { isHeader($0.text) }) {
                    lines.insert(newLine, at: header)
                } else {
                    lines.append(newLine)
                }
            case .ini(section: let section?), .toml(table: let section?), .configparser(section: let section):
                if let header = scoped.firstIndex(where: { headerName($0.text) == section }) {
                    lines.insert(newLine, at: header + 1)
                } else {
                    if let last = lines.last, !last.trimmingCharacters(in: .whitespaces).isEmpty {
                        lines.append("")
                    }
                    lines.append("[\(section)]")
                    lines.append(newLine)
                }
            }
        }
        return lines.joined(separator: "\n") + "\n"
    }

    // MARK: Durations

    /// The window `raw` holds back, in days, reading a bare number in
    /// `bareUnitDays`; nil when it is not a rolling duration (a fixed date, an
    /// empty value, or a form none of the tools accepts). Accepts what the tools
    /// write: npm `7`, pnpm `10080`, Yarn `7d`, mise `7d`/`1w`, uv `7 days`/`P7D`,
    /// pip `P7D`, Bundler `7`.
    public static func durationDays(_ raw: String, bareUnitDays: Double) -> Double? {
        let value = raw.trimmingCharacters(in: .whitespaces).lowercased()
        guard !value.isEmpty else { return nil }
        if value.hasPrefix("p") { return isoDurationDays(String(value.dropFirst())) }
        if let number = plainNumber(value) { return number * bareUnitDays }
        // One or more `<number><unit>` terms, optionally space-separated:
        // `7d`, `7 days`, `1w`, `168h`, `1 week 2 days`.
        var total = 0.0
        var rest = Substring(value)
        var terms = 0
        while !rest.isEmpty {
            rest = rest.drop { $0 == " " }
            let digits = rest.prefix { ($0.isASCII && $0.isNumber) || $0 == "." }
            guard let number = plainNumber(String(digits)) else { return nil }
            rest = rest.dropFirst(digits.count).drop { $0 == " " }
            let unit = rest.prefix { $0.isLetter }
            guard let scale = unitDays[String(unit)] else { return nil }
            rest = rest.dropFirst(unit.count)
            total += number * scale
            terms += 1
        }
        return terms > 0 ? total : nil
    }

    private static let unitDays: [String: Double] = [
        "s": 1.0 / 86_400, "sec": 1.0 / 86_400, "secs": 1.0 / 86_400,
        "second": 1.0 / 86_400, "seconds": 1.0 / 86_400,
        "m": 1.0 / 1_440, "min": 1.0 / 1_440, "mins": 1.0 / 1_440,
        "minute": 1.0 / 1_440, "minutes": 1.0 / 1_440,
        "h": 1.0 / 24, "hr": 1.0 / 24, "hrs": 1.0 / 24, "hour": 1.0 / 24, "hours": 1.0 / 24,
        "d": 1, "day": 1, "days": 1,
        "w": 7, "week": 7, "weeks": 7,
    ]

    /// ISO 8601 `P…` duration body (after the `P`): `7D`, `1W`, `T168H`, `1DT12H`.
    /// Months and years are refused: their length is calendar-dependent and no
    /// tool's documentation suggests them for a cooldown.
    private static func isoDurationDays(_ body: String) -> Double? {
        var total = 0.0
        var inTime = false
        var number = ""
        var terms = 0
        for character in body {
            if character == "t" {
                guard number.isEmpty, !inTime else { return nil }
                inTime = true
                continue
            }
            if (character.isASCII && character.isNumber) || character == "." {
                number.append(character)
                continue
            }
            guard let value = plainNumber(number) else { return nil }
            number = ""
            switch (character, inTime) {
            case ("w", false): total += value * 7
            case ("d", false): total += value
            case ("h", true): total += value / 24
            case ("m", true): total += value / 1_440
            case ("s", true): total += value / 86_400
            default: return nil
            }
            terms += 1
        }
        return number.isEmpty && terms > 0 ? total : nil
    }

    // MARK: Line scanning

    private struct ScopedLine {
        let text: String
        let inScope: Bool
    }

    private static func scopedLines(_ text: String, format: CooldownConfigFormat) -> [ScopedLine] {
        var lines = text.components(separatedBy: "\n")
        if text.hasSuffix("\n") { lines.removeLast() }
        switch format {
        case .yaml:
            return lines.map { ScopedLine(text: $0, inScope: true) }
        case .ini, .toml, .configparser:
            let wanted: String?
            switch format {
            case let .ini(section): wanted = section
            case let .toml(table): wanted = table
            case let .configparser(section): wanted = section
            case .yaml: wanted = nil
            }
            var current: String?
            return lines.map { line in
                if isHeader(line) {
                    current = headerName(line)
                    return ScopedLine(text: line, inScope: false)
                }
                return ScopedLine(text: line, inScope: current == wanted)
            }
        }
    }

    private static func isHeader(_ line: String) -> Bool {
        line.trimmingCharacters(in: .whitespaces).hasPrefix("[")
    }

    /// `[name]` → `name`; TOML `[[array]]` headers get a name no key is read from.
    private static func headerName(_ line: String) -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("["), let close = trimmed.firstIndex(of: "]") else { return nil }
        if trimmed.hasPrefix("[[") { return "[[array]]" }
        return trimmed[trimmed.index(after: trimmed.startIndex)..<close]
            .trimmingCharacters(in: .whitespaces)
    }

    private static func parse(_ line: String, key: String, format: CooldownConfigFormat) -> String? {
        let separator: Character
        switch format {
        case .yaml:
            // Only unindented keys belong to the top-level mapping.
            if line.first == " " || line.first == "\t" { return nil }
            separator = ":"
        case .ini, .toml:
            separator = "="
        case .configparser:
            // An indented line continues the previous value; it is no key.
            if line.first == " " || line.first == "\t" { return nil }
            separator = configparserSeparator(line)
        }
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("#") || trimmed.hasPrefix(";") { return nil }
        guard let at = trimmed.firstIndex(of: separator) else { return nil }
        var name = trimmed[..<at].trimmingCharacters(in: .whitespaces)
        if name.count >= 2, let first = name.first, first == name.last, first == "\"" || first == "'" {
            name = String(name.dropFirst().dropLast())
        }
        if case .configparser = format {
            guard normalizedPipKey(name) == normalizedPipKey(key) else { return nil }
        } else {
            guard name == key else { return nil }
        }
        return unquoted(rawValue(line, format: format))
    }

    /// Everything after the separator. TOML and YAML drop a trailing comment
    /// outside quotes (YAML only after whitespace); ini keeps it, because npm's
    /// and pip's ini readers take an inline `#` as part of the value, and a
    /// value they would misread must not pass here.
    private static func rawValue(_ line: String, format: CooldownConfigFormat) -> String {
        let separator: Character
        switch format {
        case .yaml: separator = ":"
        case .ini, .toml: separator = "="
        case .configparser: separator = configparserSeparator(line)
        }
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard let at = trimmed.firstIndex(of: separator) else { return "" }
        let body = trimmed[trimmed.index(after: at)...]
        switch format {
        case .ini, .configparser: return body.trimmingCharacters(in: .whitespaces)
        case .yaml, .toml: break
        }
        var value = ""
        var quote: Character?
        var previous: Character = " "
        for character in body {
            if let open = quote {
                if character == open { quote = nil }
            } else if character == "\"" || character == "'" {
                quote = character
            } else if character == "#" {
                if case .toml = format { break }
                if previous == " " || previous == "\t" { break }
            }
            value.append(character)
            previous = character
        }
        return value.trimmingCharacters(in: .whitespaces)
    }

    /// configparser splits at the first `=` or `:`, whichever comes first.
    private static func configparserSeparator(_ line: String) -> Character {
        let equals = line.firstIndex(of: "=")
        let colon = line.firstIndex(of: ":")
        switch (equals, colon) {
        case let (e?, c?): return e < c ? "=" : ":"
        case (_?, nil): return "="
        case (nil, _?): return ":"
        default: return "="
        }
    }

    /// pip's `_normalize_name`: lower-case, `_` read as `-`.
    static func normalizedPipKey(_ key: String) -> String {
        key.lowercased().replacingOccurrences(of: "_", with: "-")
    }

    /// Whether the root of a TOML document already defines `table` by a dotted
    /// key (`settings.x = …`) or an inline table (`settings = {…}`).
    private static func definesTableOutsideIt(_ lines: [String], _ table: String) -> Bool {
        for line in lines {
            if isHeader(line) { return false }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("#"), let eq = trimmed.firstIndex(of: "=") else { continue }
            let name = trimmed[..<eq].trimmingCharacters(in: .whitespaces)
            if name == table || name.hasPrefix("\(table).") { return true }
        }
        return false
    }

    /// Whether a TOML document has a `[name]` table header.
    public static func hasTable(_ text: String, _ name: String) -> Bool {
        text.components(separatedBy: "\n").contains { headerName($0) == name }
    }

    /// A plain decimal number, as npm's and pnpm's `Number` settings take it:
    /// no unit, sign, exponent, `inf` or `nan`.
    public static func plainNumber(_ raw: String) -> Double? {
        let value = raw.trimmingCharacters(in: .whitespaces)
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        guard !value.isEmpty, parts.count <= 2,
              parts.allSatisfy({ !$0.isEmpty && $0.allSatisfy { $0.isASCII && $0.isNumber } })
        else { return nil }
        return Double(value)
    }

    private static func unquoted(_ value: String) -> String {
        if value.count >= 2, let first = value.first, first == value.last, first == "\"" || first == "'" {
            return String(value.dropFirst().dropLast())
        }
        return value
    }

    /// True when every meaningful line is a top-level `key: …`, an indented
    /// continuation, a comment or a `---` document start: the shape a top-level
    /// line can be appended to.
    private static func isBlockMapping(_ lines: [String]) -> Bool {
        var sawKey = false
        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed == "---" { continue }
            if line.first == " " || line.first == "\t" {
                guard sawKey else { return false }
                continue
            }
            if trimmed.hasPrefix("{") || trimmed.hasPrefix("[") || trimmed.hasPrefix("-")
                || trimmed.hasPrefix("...") || !trimmed.contains(":") {
                return false
            }
            sawKey = true
        }
        return true
    }
}
