import Foundation

public enum EnvFileError: Error, Equatable, CustomStringConvertible, LocalizedError {
    case tooLarge
    case invalidEncoding
    case tooManyEntries
    case conflictingNames(name: String)

    public var errorDescription: String? { description }

    public var description: String {
        switch self {
        case .tooLarge:
            return "env file exceeds \(EnvFileDocument.maximumBytes) bytes"
        case .invalidEncoding:
            return "env file is not UTF-8 text (or contains NUL bytes)"
        case .tooManyEntries:
            return "env file has more than \(EnvFileDocument.maximumAssignments) assignments"
        case let .conflictingNames(name):
            return "env file contains both \(name) and csec_\(name); keep one definition before protecting it"
        }
    }
}

/// A position-preserving model of an env file (direnv/.envrc style). Unlike
/// the onboarding dotenv parser this keeps every line's exact bytes and the
/// byte span of each assignment's right-hand side, so selected values can be
/// spliced out and replaced with secret references while every other byte of
/// the file — comments, blank lines, arbitrary shell lines, quoting of
/// untouched assignments, CRLF vs LF, presence of a final newline — survives
/// the rewrite unchanged.
public struct EnvFileDocument: Equatable {
    public static let maximumBytes = 1024 * 1024
    public static let maximumAssignments = 4096
    /// Schemes whose references csec can resolve; values already in one of
    /// these forms are surfaced as "already a reference", never re-imported.
    public static let referenceSchemes: Set<String> = ["csec", "op"]

    public enum Quoting: Equatable {
        case none
        case single
        case double
    }

    public struct Assignment: Equatable {
        public let name: String
        public let nameRange: Range<Int>
        /// Parsed literal value; nil when the value cannot be interpreted
        /// without guessing (interpolation, stray quotes, unterminated
        /// strings). Unsupported occurrences are never rewritten.
        public let value: String?
        public let quoting: Quoting
        public let isCommented: Bool
        public let hasExportPrefix: Bool
        public let lineIndex: Int
        /// UTF-8 byte span within the line that a rewrite replaces: the whole
        /// quoted region for quoted values, the bare token otherwise. Leading
        /// whitespace and trailing ` # comment` text sit outside the span.
        public let valueRange: Range<Int>
        /// The store key this occurrence's value imports under, assigned after
        /// candidate grouping: live occurrences share the variable name (so
        /// shadowed plaintext is scrubbed by the winning reference); a
        /// secret-like commented occurrence carries its own `NAME_commented_N`
        /// key. Nil when the occurrence is never imported or rewritten
        /// (unsupported, already a reference, or commented without looking
        /// secret-like).
        public internal(set) var importKey: String?
    }

    public enum CandidateKind: Equatable {
        case importable
        case alreadyReference(scheme: String)
        case unsupported
        case empty
    }

    /// One entry per import key. Live occurrences of a name collapse onto one
    /// candidate keyed by the name itself with shell semantics (the last live
    /// occurrence wins; earlier live plaintext is dead and gets scrubbed by the
    /// same reference). Each distinct secret-like *commented* value is its own
    /// candidate under a `NAME_commented_N` key — a commented credential is a
    /// real secret sitting on disk, so it imports (preselected) rather than
    /// being shadowed away or silently scrubbed. A commented value equal to an
    /// already-keyed value reuses that key.
    public struct Candidate: Equatable {
        /// The environment variable name on the original line.
        public let name: String
        /// The store key the value imports under: the name for the live
        /// candidate, `NAME_commented_N` for commented ones.
        public let importKey: String
        /// The winning occurrence's parsed value ("" unless importable).
        public let importValue: String
        public let kind: CandidateKind
        /// True for a commented-value candidate.
        public let winningIsCommented: Bool
        /// 1-based line of the winning occurrence, for display.
        public let lineNumber: Int
        /// How many occurrences import under this candidate's key.
        public let occurrenceCount: Int
        /// True when this candidate's parsed occurrences disagree; a rewrite
        /// scrubs the stale shadowed values by pointing every occurrence at
        /// the same reference.
        public let differingValues: Bool
        /// One centralized name/value verdict, retained so picker rendering
        /// cannot drift from the initial-selection decision.
        public let secretLike: Bool
        public let preselect: Bool
    }

    private let lineBytes: [[UInt8]]
    private let terminators: [[UInt8]]
    public let assignments: [Assignment]
    public let candidates: [Candidate]

    public init(data: Data) throws {
        guard data.count <= Self.maximumBytes else { throw EnvFileError.tooLarge }
        guard !data.contains(0), String(data: data, encoding: .utf8) != nil else {
            throw EnvFileError.invalidEncoding
        }

        var lines: [[UInt8]] = []
        var terms: [[UInt8]] = []
        var current: [UInt8] = []
        for byte in data {
            if byte == 0x0A {
                if current.last == 0x0D {
                    current.removeLast()
                    terms.append([0x0D, 0x0A])
                } else {
                    terms.append([0x0A])
                }
                lines.append(current)
                current = []
            } else {
                current.append(byte)
            }
        }
        if !current.isEmpty {
            lines.append(current)
            terms.append([])
        }

        var parsed: [Assignment] = []
        for (index, line) in lines.enumerated() {
            guard let assignment = Self.parseLine(line, lineIndex: index) else { continue }
            parsed.append(assignment)
            guard parsed.count <= Self.maximumAssignments else {
                throw EnvFileError.tooManyEntries
            }
        }

        lineBytes = lines
        terminators = terms
        let (built, importKeys) = Self.buildCandidates(from: parsed)
        candidates = built
        assignments = parsed.map { assignment in
            var annotated = assignment
            annotated.importKey = importKeys[assignment.lineIndex]
            return annotated
        }
    }

    /// Existing references only need a name change; no provider access or
    /// re-import is necessary, and their original quoting is preserved.
    public var referenceNamesToPrefix: Set<String> {
        Set(existingReferenceAssignments.filter {
            !$0.name.hasPrefix(ExecPlanner.referencePrefix)
        }.map(\.name))
    }

    private var existingReferenceAssignments: [Assignment] {
        let liveNames = Set(candidates.compactMap { candidate -> String? in
            if case .alreadyReference = candidate.kind { return candidate.name }
            return nil
        })
        return assignments.filter {
            Self.isReference($0.value) && ($0.isCommented || liveNames.contains($0.name))
        }
    }

    private static func isReference(_ value: String?) -> Bool {
        guard let value, let ref = try? SecretRef(value) else { return false }
        return referenceSchemes.contains(ref.scheme)
    }

    /// Validate before committing to any destination, not after values have
    /// already been imported. Never merge two differently named definitions.
    public func validateRewrite(selectedKeys: Set<String>) throws {
        let names = Set(assignments.filter { !$0.isCommented }.map(\.name))
        let existingLines = Set(existingReferenceAssignments.map(\.lineIndex))
        for assignment in assignments where
            assignment.importKey.map(selectedKeys.contains) == true || existingLines.contains(assignment.lineIndex) {
            let name = try ExecPlanner.destinationName(assignment.name)
            let prefixed = ExecPlanner.referencePrefix + name
            if !assignment.isCommented, names.contains(name) && names.contains(prefixed) {
                throw EnvFileError.conflictingNames(name: name)
            }
        }
    }

    /// Splice selected references and their prefixed names, preserving all
    /// surrounding bytes. Commented imports keep their own references.
    public func rewritten(references: [String: String]) throws -> Data {
        try validateRewrite(selectedKeys: Set(references.keys))
        var lines = lineBytes
        let existingLines = Set(existingReferenceAssignments.map(\.lineIndex))
        // Rename all live occurrences of a renamed live variable, including
        // empty or unsupported shadowed assignments, so no stale NAME remains.
        let liveNames = Set(assignments.filter {
            !$0.isCommented && (($0.importKey.flatMap { references[$0] } != nil
                && $0.value != nil && $0.value != "")
                || existingLines.contains($0.lineIndex))
        }.map(\.name))
        for assignment in assignments {
            var line = lines[assignment.lineIndex]
            let reference = assignment.importKey.flatMap { references[$0] }
            if let reference, let value = assignment.value, !value.isEmpty {
                let replacement = [0x22] + Array(reference.utf8) + [0x22]
                line.replaceSubrange(assignment.valueRange, with: replacement)
            }
            if (reference != nil && assignment.value != nil && assignment.value != "")
                || existingLines.contains(assignment.lineIndex)
                || (!assignment.isCommented && liveNames.contains(assignment.name)) {
                let name = try ExecPlanner.destinationName(assignment.name)
                line.replaceSubrange(assignment.nameRange,
                                     with: Array((ExecPlanner.referencePrefix + name).utf8))
            }
            lines[assignment.lineIndex] = line
        }
        var output = Data()
        for (index, line) in lines.enumerated() {
            output.append(contentsOf: line)
            output.append(contentsOf: terminators[index])
        }
        return output
    }

    // MARK: - Parsing

    private static func parseLine(_ bytes: [UInt8], lineIndex: Int) -> Assignment? {
        var index = 0
        func skipBlanks() {
            while index < bytes.count, bytes[index] == 0x20 || bytes[index] == 0x09 {
                index += 1
            }
        }

        skipBlanks()
        guard index < bytes.count else { return nil }

        var isCommented = false
        if bytes[index] == 0x23 {
            isCommented = true
            index += 1
            skipBlanks()
        }

        var hasExport = false
        let exportKeyword: [UInt8] = Array("export".utf8)
        if index + exportKeyword.count < bytes.count,
           Array(bytes[index..<(index + exportKeyword.count)]) == exportKeyword,
           bytes[index + exportKeyword.count] == 0x20
            || bytes[index + exportKeyword.count] == 0x09 {
            hasExport = true
            index += exportKeyword.count
            skipBlanks()
        }

        let nameStart = index
        while index < bytes.count, isNameByte(bytes[index]) { index += 1 }
        // Strict shell assignment: the name must directly touch `=`. Lines
        // with whitespace around `=` are not live assignments in a shell, so
        // they are left untouched rather than guessed at.
        guard index > nameStart, index < bytes.count, bytes[index] == 0x3D,
              let name = String(bytes: bytes[nameStart..<index], encoding: .utf8),
              SecretHeuristics.isEnvironmentName(name) else { return nil }
        index += 1
        let afterEquals = index

        func assignment(
            value: String?, quoting: Quoting, valueRange: Range<Int>
        ) -> Assignment {
            Assignment(
                name: name, nameRange: nameStart..<(afterEquals - 1), value: value, quoting: quoting,
                isCommented: isCommented, hasExportPrefix: hasExport,
                lineIndex: lineIndex, valueRange: valueRange,
                importKey: nil
            )
        }
        func unsupported() -> Assignment {
            assignment(value: nil, quoting: .none, valueRange: afterEquals..<afterEquals)
        }

        skipBlanks()
        // Empty right-hand side, or whitespace followed by a comment. A `#`
        // with no whitespace after `=` is a literal bare value, not a comment.
        if index >= bytes.count || (bytes[index] == 0x23 && index > afterEquals) {
            return assignment(value: "", quoting: .none, valueRange: afterEquals..<afterEquals)
        }

        if bytes[index] == 0x27 { // single quote: literal until the close
            let open = index
            var close = index + 1
            while close < bytes.count, bytes[close] != 0x27 { close += 1 }
            guard close < bytes.count,
                  suffixIsBlankOrComment(bytes, from: close + 1),
                  let value = String(bytes: bytes[(open + 1)..<close], encoding: .utf8)
            else { return unsupported() }
            return assignment(value: value, quoting: .single, valueRange: open..<(close + 1))
        }

        if bytes[index] == 0x22 { // double quote: limited escapes, no interpolation
            let open = index
            var valueBytes: [UInt8] = []
            var escaped = false
            var close = -1
            var cursor = open + 1
            while cursor < bytes.count {
                let byte = bytes[cursor]
                if escaped {
                    switch byte {
                    case 0x6E: valueBytes.append(0x0A) // \n
                    case 0x72: valueBytes.append(0x0D) // \r
                    case 0x74: valueBytes.append(0x09) // \t
                    case 0x5C: valueBytes.append(0x5C) // backslash
                    case 0x22: valueBytes.append(0x22) // quote
                    default: return unsupported()
                    }
                    escaped = false
                } else if byte == 0x5C {
                    escaped = true
                } else if byte == 0x22 {
                    close = cursor
                    break
                } else {
                    valueBytes.append(byte)
                }
                cursor += 1
            }
            // Interpolation varies across shells and dotenv consumers; do not
            // import a possibly transformed value by guessing.
            guard close >= 0,
                  suffixIsBlankOrComment(bytes, from: close + 1),
                  !valueBytes.contains(0x24), !valueBytes.contains(0x60),
                  let value = String(bytes: valueBytes, encoding: .utf8)
            else { return unsupported() }
            return assignment(value: value, quoting: .double, valueRange: open..<(close + 1))
        }

        // Bare value: runs to end of line or to a whitespace-preceded `#`.
        let start = index
        var end = bytes.count
        var cursor = start + 1
        while cursor < bytes.count {
            if bytes[cursor] == 0x23,
               bytes[cursor - 1] == 0x20 || bytes[cursor - 1] == 0x09 {
                end = cursor
                break
            }
            cursor += 1
        }
        var valueEnd = end
        while valueEnd > start,
              bytes[valueEnd - 1] == 0x20 || bytes[valueEnd - 1] == 0x09 {
            valueEnd -= 1
        }
        let valueBytes = bytes[start..<valueEnd]
        // Refuse interpolation, escapes, and mid-word quoting (shell would
        // concatenate; importing the raw text would store the wrong value).
        guard !valueBytes.contains(where: {
            $0 == 0x24 || $0 == 0x60 || $0 == 0x5C || $0 == 0x27 || $0 == 0x22
        }), let value = String(bytes: valueBytes, encoding: .utf8)
        else { return unsupported() }
        return assignment(value: value, quoting: .none, valueRange: start..<valueEnd)
    }

    private static func suffixIsBlankOrComment(_ bytes: [UInt8], from index: Int) -> Bool {
        var cursor = index
        while cursor < bytes.count, bytes[cursor] == 0x20 || bytes[cursor] == 0x09 {
            cursor += 1
        }
        return cursor >= bytes.count || bytes[cursor] == 0x23
    }

    private static func isNameByte(_ byte: UInt8) -> Bool {
        (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122)
            || (byte >= 48 && byte <= 57) || byte == 95
    }

    // MARK: - Candidates

    private static func buildCandidates(
        from assignments: [Assignment]
    ) -> (candidates: [Candidate], importKeys: [Int: String]) {
        var order: [String] = []
        var byName: [String: [Assignment]] = [:]
        for assignment in assignments {
            if byName[assignment.name] == nil { order.append(assignment.name) }
            byName[assignment.name, default: []].append(assignment)
        }

        var candidates: [Candidate] = []
        var importKeys: [Int: String] = [:]

        for name in order {
            let occurrences = byName[name] ?? []
            let live = occurrences.filter { !$0.isCommented }
            let commented = occurrences.filter { $0.isCommented }

            // The live candidate, keyed by the name itself. Every live
            // occurrence maps to it so shadowed plaintext is scrubbed by the
            // winning reference.
            var liveImportValue = ""
            var liveKind: CandidateKind?
            var liveOccurrenceCount = live.count
            if let winning = live.last {
                for occurrence in live { importKeys[occurrence.lineIndex] = name }
                let kind: CandidateKind
                if let value = winning.value {
                    if value.isEmpty {
                        kind = .empty
                    } else if let reference = try? SecretRef(value),
                              referenceSchemes.contains(reference.scheme) {
                        kind = .alreadyReference(scheme: reference.scheme)
                    } else {
                        kind = .importable
                        liveImportValue = value
                    }
                } else {
                    kind = .unsupported
                }
                liveKind = kind
            }

            // Commented occurrences: a parseable, secret-looking value is a
            // real credential on disk, so it becomes its own preselected
            // candidate under a NAME_commented_N key. Values that equal an
            // already-keyed value reuse that key; references, empties,
            // unparseables, and non-secret-looking comments stay untouched.
            var keyByValue: [String: String] =
                liveKind == .importable ? [liveImportValue: name] : [:]
            var commentedCandidates: [Candidate] = []
            var commentedDuplicates: [String: Int] = [:]
            var commentedIndex = 0
            for occurrence in commented {
                guard let value = occurrence.value, !value.isEmpty else { continue }
                if let reference = try? SecretRef(value),
                   referenceSchemes.contains(reference.scheme) { continue }
                guard SecretHeuristics.environmentVariableLooksSecretLike(
                    name: name, value: value) else { continue }
                if let existingKey = keyByValue[value] {
                    importKeys[occurrence.lineIndex] = existingKey
                    if existingKey == name {
                        liveOccurrenceCount += 1
                    } else {
                        commentedDuplicates[existingKey, default: 0] += 1
                    }
                    continue
                }
                commentedIndex += 1
                let key = "\(name)_commented_\(commentedIndex)"
                keyByValue[value] = key
                importKeys[occurrence.lineIndex] = key
                commentedCandidates.append(Candidate(
                    name: name,
                    importKey: key,
                    importValue: value,
                    kind: .importable,
                    winningIsCommented: true,
                    lineNumber: occurrence.lineIndex + 1,
                    occurrenceCount: 1,
                    differingValues: false,
                    secretLike: true,
                    preselect: true
                ))
            }

            if let winning = live.last, let liveKind {
                let parsedValues = live.compactMap(\.value).filter { !$0.isEmpty }
                let secretLike = SecretHeuristics.environmentVariableLooksSecretLike(
                    name: name,
                    value: liveKind == .importable ? liveImportValue : nil
                )
                candidates.append(Candidate(
                    name: name,
                    importKey: name,
                    importValue: liveImportValue,
                    kind: liveKind,
                    winningIsCommented: false,
                    lineNumber: winning.lineIndex + 1,
                    occurrenceCount: liveOccurrenceCount,
                    differingValues: Set(parsedValues).count > 1,
                    secretLike: secretLike,
                    preselect: liveKind == .importable && secretLike
                ))
            }
            for candidate in commentedCandidates {
                let extra = commentedDuplicates[candidate.importKey] ?? 0
                guard extra > 0 else {
                    candidates.append(candidate)
                    continue
                }
                candidates.append(Candidate(
                    name: candidate.name,
                    importKey: candidate.importKey,
                    importValue: candidate.importValue,
                    kind: candidate.kind,
                    winningIsCommented: candidate.winningIsCommented,
                    lineNumber: candidate.lineNumber,
                    occurrenceCount: candidate.occurrenceCount + extra,
                    differingValues: candidate.differingValues,
                    secretLike: candidate.secretLike,
                    preselect: candidate.preselect
                ))
            }
        }
        return (candidates, importKeys)
    }
}
