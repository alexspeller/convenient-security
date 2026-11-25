import Foundation

/// A bounded, lossless outline editor for the Codex settings touched by setup.
/// It preserves unrelated TOML verbatim, including comments and multiline values.
/// Inline tables at an edited ancestor are refused rather than reinterpreted.
/// This is deliberately not a general TOML decoder or serializer.
struct SetupTOMLDocument {
    struct Entry {
        let range: Range<Int>
        let raw: String
    }

    private struct Table {
        let path: [String]
        let header: Range<Int>
        var end: Int
    }

    private struct Statement {
        let path: [String]
        let range: Range<Int>
        let raw: String
    }

    private let bytes: [UInt8]
    private var tables: [Table] = []
    private var statements: [Statement] = []
    private(set) var entries: [[String]: Entry] = [:]
    private var replacements: [Range<Int>: String] = [:]
    private var insertions: [Int: [String]] = [:]

    private static let managedRoots: Set<String> = [
        "features", "default_permissions", "permissions", "sandbox_mode", "sandbox_workspace_write",
    ]

    init(_ data: Data) throws {
        guard data.count <= CodingAgentSetup.maximumConfigurationBytes,
              String(data: data, encoding: .utf8) != nil else { throw Self.unsupported() }
        bytes = Array(data)
        var scanner = Scanner(bytes: bytes)
        var current: [String] = []
        var seenTables = Set<[String]>()
        tables = [Table(path: [], header: 0..<0, end: bytes.count)]
        while true {
            scanner.skipTrivia()
            guard !scanner.atEnd else { break }
            if scanner.peek == 91 { // [table] or [[array.of.tables]]
                let start = scanner.position
                tables[tables.count - 1].end = scanner.position
                scanner.position += 1
                let array = scanner.peek == 91
                if array { scanner.position += 1 }
                current = try scanner.key(until: 93)
                scanner.position += 1
                if array {
                    guard scanner.peek == 93 else { throw Self.unsupported() }
                    scanner.position += 1
                }
                if Self.isManaged(current) {
                    guard !array, seenTables.insert(current).inserted else { throw Self.unsupported() }
                }
                try scanner.endOfStatement()
                tables.append(Table(path: current, header: start..<scanner.position, end: bytes.count))
            } else {
                let start = scanner.position
                let path = current + (try scanner.key(until: 61))
                scanner.position += 1
                scanner.skipHorizontalSpace()
                let range = try scanner.value()
                if Self.isManaged(path) {
                    guard entries[path] == nil else { throw Self.unsupported() }
                    entries[path] = Entry(
                        range: range,
                        raw: String(decoding: bytes[range], as: UTF8.self)
                    )
                }
                try scanner.endOfStatement()
                statements.append(Statement(path: path, range: start..<scanner.position,
                                            raw: String(decoding: bytes[range], as: UTF8.self)))
            }
        }
    }

    func contains(_ prefix: [String]) -> Bool {
        entries.keys.contains { $0.starts(with: prefix) }
            || tables.contains { $0.path.starts(with: prefix) }
    }

    func tablePaths(beneath prefix: [String]) -> [[String]] {
        tables.map(\.path).filter { $0.starts(with: prefix) }
    }

    /// Look outside a candidate's own definition, including named launch
    /// profiles, inheritance, inline tables and arrays. Ambiguous string syntax
    /// keeps the candidate rather than risking deletion of a referenced profile.
    func references(_ name: String, outside prefix: [String]) -> Bool {
        if tables.contains(where: { !$0.path.starts(with: prefix) && $0.path.contains(name) }) { return true }
        return statements.contains { statement in
            guard !statement.path.starts(with: prefix) else { return false }
            if statement.path.contains(name) { return true }
            var scanner = Scanner(bytes: Array(statement.raw.utf8))
            while !scanner.atEnd {
                if scanner.peek == 34 || scanner.peek == 39 {
                    let start = scanner.position
                    guard (try? scanner.skipString(multilineAllowed: true)) != nil else { return true }
                    let raw = String(decoding: scanner.bytes[start..<scanner.position], as: UTF8.self)
                    guard let value = try? Self.decodeString(raw) else {
                        if raw.contains(name) || raw.contains("\\") { return true }
                        continue
                    }
                    if value == name { return true }
                } else { scanner.position += 1 }
            }
            return false
        }
    }

    /// Delete only the matching headers and assignments. Neighbouring tables,
    /// comments and multiline values keep their original bytes.
    mutating func remove(_ prefix: [String]) throws {
        guard !prefix.isEmpty,
              !entries.keys.contains(where: { $0.count < prefix.count && prefix.starts(with: $0) }) else {
            throw Self.unsupported()
        }
        for table in tables where table.path.starts(with: prefix) { replacements[table.header] = "" }
        for statement in statements where statement.path.starts(with: prefix) { replacements[statement.range] = "" }
        entries = entries.filter { !$0.key.starts(with: prefix) }
    }

    func string(_ path: [String]) throws -> String? {
        guard let entry = entries[path] else { return nil }
        return try Self.decodeString(entry.raw)
    }

    func boolean(_ path: [String]) throws -> Bool? {
        guard let entry = entries[path] else { return nil }
        switch entry.raw {
        case "true": return true
        case "false": return false
        default: throw Self.unsupported()
        }
    }

    func strings(_ path: [String]) throws -> [String]? {
        guard let entry = entries[path] else { return nil }
        var scanner = Scanner(bytes: Array(entry.raw.utf8))
        guard scanner.peek == 91 else { throw Self.unsupported() }
        scanner.position += 1
        var values: [String] = []
        while true {
            scanner.skipTrivia()
            if scanner.peek == 93 {
                scanner.position += 1
                guard scanner.atEnd else { throw Self.unsupported() }
                return values
            }
            let start = scanner.position
            try scanner.skipString(multilineAllowed: false)
            values.append(try Self.decodeString(String(
                decoding: scanner.bytes[start..<scanner.position], as: UTF8.self
            )))
            scanner.skipTrivia()
            if scanner.peek == 93 { continue }
            guard scanner.peek == 44 else { throw Self.unsupported() }
            scanner.position += 1
        }
    }

    /// The caller supplies only generated, value-free TOML scalar values.
    mutating func set(_ path: [String], _ value: String) throws {
        guard !path.isEmpty else { throw Self.unsupported() }
        // Defining a child beneath an inline table or a scalar is not an
        // additive TOML edit. Refuse it rather than creating conflicting keys.
        guard !entries.keys.contains(where: {
            $0.count < path.count && path.starts(with: $0)
        }) else { throw Self.unsupported() }
        if let existing = entries[path] {
            if existing.raw != value { replacements[existing.range] = value }
            return
        }
        guard !contains(path) else { throw Self.unsupported() }
        let table = tables.filter { path.starts(with: $0.path) }
            .max { $0.path.count < $1.path.count }!
        let key = path.dropFirst(table.path.count).map(Self.quote).joined(separator: ".")
        insertions[table.end, default: []].append("\(key) = \(value)")
    }

    func rendered() throws -> Data {
        var output = bytes
        var edits = replacements.map { ($0.key, $0.value) }
        for (offset, lines) in insertions {
            edits.append((offset..<offset, "\n" + lines.joined(separator: "\n") + "\n"))
        }
        for (range, value) in edits.sorted(by: { $0.0.lowerBound > $1.0.lowerBound }) {
            output.replaceSubrange(range, with: value.utf8)
        }
        guard output.count <= CodingAgentSetup.maximumConfigurationBytes else { throw Self.unsupported() }
        return Data(output)
    }

    static func quote(_ value: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return String(decoding: try! encoder.encode(value), as: UTF8.self)
    }

    static func unsupported() -> SetupOnboardingError {
        .configurationConflict(
            "cannot safely merge these Codex TOML settings; configure the csecd socket manually "
                + "(inline permission tables, duplicate settings, or unsupported syntax)"
        )
    }

    private static func isManaged(_ path: [String]) -> Bool {
        (path.first.map(managedRoots.contains) ?? false) || path.starts(with: ["hooks", "state"])
    }

    private static func decodeString(_ raw: String) throws -> String {
        if raw.hasPrefix("'"), raw.hasSuffix("'"), !raw.hasPrefix("'''") {
            let value = String(raw.dropFirst().dropLast())
            guard !value.contains("'"), !value.contains("\n"), !value.contains("\r") else {
                throw unsupported()
            }
            return value
        }
        guard raw.hasPrefix("\""), !raw.hasPrefix("\"\"\""),
              let value = try? JSONDecoder().decode(String.self, from: Data(raw.utf8)) else {
            throw unsupported()
        }
        return value
    }

    private struct Scanner {
        let bytes: [UInt8]
        var position = 0
        var atEnd: Bool { position == bytes.count }
        var peek: UInt8? { atEnd ? nil : bytes[position] }

        mutating func skipHorizontalSpace() {
            while peek == 32 || peek == 9 || peek == 13 { position += 1 }
        }

        mutating func skipTrivia() {
            while !atEnd {
                if peek == 35 { // comment
                    while !atEnd && peek != 10 { position += 1 }
                } else if [9, 10, 13, 32].contains(peek!) {
                    position += 1
                } else { return }
            }
        }

        mutating func endOfStatement() throws {
            skipHorizontalSpace()
            if peek == 35 { while !atEnd && peek != 10 { position += 1 } }
            guard atEnd || peek == 10 else { throw SetupTOMLDocument.unsupported() }
            if !atEnd { position += 1 }
        }

        mutating func key(until terminator: UInt8) throws -> [String] {
            var parts: [String] = []
            while true {
                skipHorizontalSpace()
                let start = position
                if peek == 34 || peek == 39 {
                    try skipString(multilineAllowed: false)
                    parts.append(try SetupTOMLDocument.decodeString(String(
                        decoding: bytes[start..<position], as: UTF8.self
                    )))
                } else {
                    while let byte = peek,
                          (48...57).contains(byte) || (65...90).contains(byte)
                            || (97...122).contains(byte) || byte == 45 || byte == 95 {
                        position += 1
                    }
                    guard position > start else { throw SetupTOMLDocument.unsupported() }
                    parts.append(String(decoding: bytes[start..<position], as: UTF8.self))
                }
                skipHorizontalSpace()
                if peek == terminator { return parts }
                guard peek == 46 else { throw SetupTOMLDocument.unsupported() }
                position += 1
            }
        }

        mutating func skipString(multilineAllowed: Bool) throws {
            guard let quote = peek, quote == 34 || quote == 39 else {
                throw SetupTOMLDocument.unsupported()
            }
            let triple = position + 2 < bytes.count
                && bytes[position + 1] == quote && bytes[position + 2] == quote
            guard multilineAllowed || !triple else { throw SetupTOMLDocument.unsupported() }
            position += triple ? 3 : 1
            while let byte = peek {
                if byte == 92 && quote == 34 {
                    position += 1
                    guard !atEnd else { throw SetupTOMLDocument.unsupported() }
                    position += 1
                } else if byte == quote {
                    var count = 1
                    while position + count < bytes.count && bytes[position + count] == quote { count += 1 }
                    if !triple { position += 1; return }
                    if count >= 3 {
                        guard count <= 5 else { throw SetupTOMLDocument.unsupported() }
                        position += count
                        return
                    }
                    position += count
                } else {
                    guard triple || (byte != 10 && byte != 13) else { throw SetupTOMLDocument.unsupported() }
                    position += 1
                }
            }
            throw SetupTOMLDocument.unsupported()
        }

        mutating func value() throws -> Range<Int> {
            let start = position
            var closers: [UInt8] = []
            while let byte = peek {
                if byte == 34 || byte == 39 {
                    try skipString(multilineAllowed: true)
                } else if byte == 35 {
                    if closers.isEmpty { break }
                    while !atEnd && peek != 10 { position += 1 }
                } else if byte == 10 && closers.isEmpty { break }
                else if byte == 91 || byte == 123 {
                    guard closers.count < 64 else { throw SetupTOMLDocument.unsupported() }
                    closers.append(byte == 91 ? 93 : 125)
                    position += 1
                } else if byte == 93 || byte == 125 {
                    guard closers.popLast() == byte else { throw SetupTOMLDocument.unsupported() }
                    position += 1
                } else { position += 1 }
            }
            guard closers.isEmpty else { throw SetupTOMLDocument.unsupported() }
            var end = position
            while end > start && [9, 13, 32].contains(bytes[end - 1]) { end -= 1 }
            guard end > start else { throw SetupTOMLDocument.unsupported() }
            return start..<end
        }
    }
}
