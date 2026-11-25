import Foundation
import CTreeSitterBash

// The simple commands of a shell text, and argv matching against them.
//
// csecd reads the text Claude Code's auto-mode classifier approved to learn
// which commands it runs: a sudo's argv must match a `sudo` command of it
// (`SudoChainRule`), and the git passthrough, the credential guard and the
// worktree-escape check read the same commands. (The name is historical:
// this analysis once also pinned launcher scripts that started `ssh`, which
// csec-0.11 retired.)
//
// This file is the pure analysis behind them: it parses bash text with the
// vendored tree-sitter-bash grammar (`BashTree`), extracts simple commands,
// and matches argv against them.
//
// The adversary is an automated supply-chain attacker: a trojaned dependency,
// an edited repository file, an injected environment variable. Every rule fails
// CLOSED when unsure: an unparseable or ambiguous text yields no commands (so
// nothing matches).
//
// tree-sitter never throws on a syntax error; it builds ERROR and MISSING
// nodes, and in a few places it silently disagrees with bash without either.
// Each of these hides a command bash runs, with no ERROR node:
//   cat <<E'O'F … EOF <newline> cmd      the delimiter quoted mid-word: the
//                                        grammar looks for `E'O'F` and swallows
//                                        the rest of the file as the body
//   echo $'\\'; cmd #'                   `\\'` read as an escaped quote
//   echo ${x:-`cmd`}                     a backquote left as a word
//   echo "${x:-'$(cmd)'}"                bash keeps those quotes and expands
//   sour\<newline>ce x                   bash removes the continuation first
// and these misread a word: `cmd - <<EOF` (the `-` dropped), `cmd -<<EOF` (the
// `-` folded into `<<`), `"`a` `b`"` (read as one substitution), `$a\ `b``
// (the `\ ` dropped, the substitution made a command). And it refuses what
// bash runs: `cmd <<EOF 2>&1 | next` (redirects after the delimiter, then a
// pipe) is an ERROR, so the redirects are moved before the `<<` and the text
// parsed again (`heredocRedirectPipeRepair`); so is an empty backquote
// substitution inside double quotes (`"before `` after"`), so the pair is
// read as the end of one string and the start of the next
// (`emptyBackquoteRepair`). `ShellTextAnalysis`
// refuses or repairs each disagreement it knows of (see `parse` and
// `checkStructure`).

// MARK: - Commands and argument matching

/// One piece of a `ShellCommandWord.pattern`.
public enum ShellPatternPiece: Equatable, Sendable {
    case literal(String)
    /// Any substring, including the empty one.
    case wildcard
}

/// One argument word of a simple command, as a matcher against argv elements.
public enum ShellCommandWord: Equatable, Sendable {
    /// Matches exactly one argv element equal to the string (an unquoted literal
    /// word, or a fully quoted word with no expansion, after quote removal and
    /// escape processing).
    case exact(String)
    /// Matches exactly one argv element against a glob of literal segments and
    /// wildcards: a word whose expansions are all inside double quotes
    /// (`"cd $DIR && git pull"`).
    case pattern([ShellPatternPiece])
    /// Matches zero or more argv elements: a word with an unquoted expansion
    /// (`$x`, `${x}`, `$(…)`, backquotes), `"$@"`-style array expansion, an
    /// unquoted glob character, a tilde prefix, or brace expansion.
    case any
}

/// One simple command of a shell text, with its exec-ing prefixes stripped.
public struct ShellSimpleCommand: Equatable, Sendable {
    /// The command name after quote removal when it is literal; nil when it is
    /// not (`$cmd`, `"$(…)"`, a glob).
    public let name: String?
    public let arguments: [ShellCommandWord]
    /// 1-based line of the command's first word in the text.
    public let line: Int

    public init(name: String?, arguments: [ShellCommandWord], line: Int) {
        self.name = name
        self.arguments = arguments
        self.line = line
    }

    /// Whether `argumentTail` (argv[1...]; argv[0] is never compared) is one
    /// this command could have produced. `.exact` consumes one equal element,
    /// `.pattern` one element matching its glob, `.any` zero or more elements.
    /// Elements compare byte for byte (UTF-8), never by Unicode equivalence.
    public func matches(argumentTail: [String]) -> Bool {
        ShellArgumentMatcher.matches(arguments, argumentTail.map { .known(Array($0.utf8)) })
    }

    /// The same, for an argv some of whose elements are known only up to a
    /// prefix (`ShellArgumentElement.redacted`).
    public func matches(elements argumentTail: [ShellArgumentElement]) -> Bool {
        ShellArgumentMatcher.matches(arguments, argumentTail)
    }
}

/// One argv element as a matcher sees it.
public enum ShellArgumentElement: Equatable, Sendable {
    /// Every byte is known.
    case known([UInt8])
    /// Only the bytes before a redacted part are known; the rest could be
    /// anything (the sudo PAM module's `[csec:secret-like]`). Such an element
    /// matches only a word that matches every element starting with
    /// `prefix`: `.any`, or a pattern ending in a wildcard that matches the
    /// prefix itself. Never `.exact`, whatever its text.
    case redacted(prefix: [UInt8])
}

/// Sequence and glob matching without exponential blow-up.
enum ShellArgumentMatcher {
    private enum Compiled {
        case exact([UInt8])
        case pattern([[UInt8]])  // literal segments; a wildcard between each pair
        case any
    }

    /// Dynamic programming over (word, element) positions: O(words × elements)
    /// steps, each at most one linear glob match.
    static func matches(_ words: [ShellCommandWord], _ elements: [ShellArgumentElement]) -> Bool {
        let compiled = words.map(compile)
        let count = elements.count
        // `rest[j]`: the words after the current one match elements[j...].
        var rest = [Bool](repeating: false, count: count + 1)
        rest[count] = true
        for word in compiled.reversed() {
            var current = [Bool](repeating: false, count: count + 1)
            var index = count
            while index >= 0 {
                current[index] = step(word, index, elements, rest, current)
                index -= 1
            }
            rest = current
        }
        return rest[0]
    }

    private static func step(
        _ word: Compiled, _ index: Int, _ elements: [ShellArgumentElement], _ rest: [Bool], _ current: [Bool]
    ) -> Bool {
        let count = elements.count
        switch word {
        case .any:
            return rest[index] || (index < count && current[index + 1])
        case let .exact(bytes):
            guard index < count, rest[index + 1], case let .known(element) = elements[index] else { return false }
            return element == bytes
        case let .pattern(segments):
            guard index < count, rest[index + 1] else { return false }
            switch elements[index] {
            case let .known(element):
                return globMatches(segments, element)
            case let .redacted(prefix):
                // A trailing wildcard absorbs whatever followed the prefix, so
                // the glob matches every completion of the prefix exactly when
                // it matches the prefix alone. Without one, some completions
                // match and others don't, which is no match.
                return segments.count > 1 && segments.last?.isEmpty == true && globMatches(segments, prefix)
            }
        }
    }

    private static func compile(_ word: ShellCommandWord) -> Compiled {
        switch word {
        case let .exact(value):
            return .exact(Array(value.utf8))
        case .any:
            return .any
        case let .pattern(pieces):
            var segments: [[UInt8]] = [[]]
            for piece in pieces {
                switch piece {
                case let .literal(text): segments[segments.count - 1] += Array(text.utf8)
                case .wildcard: segments.append([])
                }
            }
            return .pattern(segments)
        }
    }

    /// A glob whose only metacharacter is `*` (between consecutive segments):
    /// the first segment is a prefix, the last a suffix, and each middle one is
    /// found leftmost-first, which is exact for star-only globs.
    static func globMatches(_ segments: [[UInt8]], _ element: [UInt8]) -> Bool {
        guard let first = segments.first, let last = segments.last else { return false }
        if segments.count == 1 { return element == first }
        guard element.count >= first.count + last.count,
              element.starts(with: first),
              element[(element.count - last.count)...].elementsEqual(last) else { return false }
        var low = first.count
        let high = element.count - last.count
        for middle in segments.dropFirst().dropLast() {
            guard let found = firstIndex(of: middle, in: element, from: low, to: high) else { return false }
            low = found + middle.count
        }
        return true
    }

    /// Knuth-Morris-Pratt search of `needle` in `haystack[from..<to]`.
    static func firstIndex(of needle: [UInt8], in haystack: [UInt8], from: Int, to: Int) -> Int? {
        if needle.isEmpty { return from <= to ? from : nil }
        guard to - from >= needle.count else { return nil }
        var failure = [Int](repeating: 0, count: needle.count)
        var length = 0
        var index = 1
        while index < needle.count {
            if needle[index] == needle[length] {
                length += 1
                failure[index] = length
                index += 1
            } else if length > 0 {
                length = failure[length - 1]
            } else {
                failure[index] = 0
                index += 1
            }
        }
        var matched = 0
        var position = from
        while position < to {
            if haystack[position] == needle[matched] {
                matched += 1
                position += 1
                if matched == needle.count { return position - matched }
            } else if matched > 0 {
                matched = failure[matched - 1]
            } else {
                position += 1
            }
        }
        return nil
    }
}

// MARK: - Simple commands of a text

public enum LauncherScript {
    /// Every simple command in `text`, in source order, or nil when the text
    /// does not parse cleanly.
    ///
    /// "Cleanly" means: no ERROR or MISSING node, no NUL byte, every heredoc's
    /// body and end line are where bash puts them, every `$'…'` and `"…"` ends
    /// where bash ends it, every operator token is spelled as its kind, and no
    /// non-blank source byte is left outside the tree (one known tree-sitter
    /// slip is repaired: a lone `-` word before a heredoc, which the grammar
    /// drops, is put back as an argument). Two ERRORs bash runs are repaired
    /// and parsed once more: redirects after a heredoc's delimiter before a
    /// pipe, and an empty backquote pair in a double-quoted argument.
    ///
    /// Every command node is walked: lists, pipelines, subshells, groups,
    /// if/while/until/for/case bodies, function bodies, command and process
    /// substitutions anywhere (inside double quotes, assignments, redirect
    /// targets, unquoted heredoc bodies) and negations. Redirects and heredoc
    /// bodies are not arguments. Leading assignments are dropped. The exec-ing
    /// prefixes `exec`, `command`, `builtin`, `noglob`, `nocorrect`, `nohup`,
    /// `time [-p]`, `nice [-n N | -N]` and `env [-i] [NAME=VALUE…]` are stripped
    /// repeatedly; a prefix followed by any other option is not (`env -u X`,
    /// `command -v` keep their own name and match nothing). A bare prefix
    /// yields no command. A command with an argument node kind this module does
    /// not model is left out, so it matches nothing.
    ///
    /// The list is a lower bound: a command tree-sitter leaves as text (a
    /// backquote inside `${x:-…}`, `bash -c '…'`) is missing, which can only make
    /// matching stricter, never looser.
    public static func simpleCommands(in text: String) -> [ShellSimpleCommand]? {
        guard case let .success(analysis) = ShellTextAnalysis.parse(text) else { return nil }
        return analysis.publicCommands(lineBase: 0)
    }
}

// MARK: - Byte helpers

enum ShellBytes {
    static let space = UInt8(ascii: " ")
    static let tab = UInt8(ascii: "\t")
    static let newline = UInt8(ascii: "\n")
    static let backslash = UInt8(ascii: "\\")
    static let dollar = UInt8(ascii: "$")
    static let backtick = UInt8(ascii: "`")
    static let doubleQuote = UInt8(ascii: "\"")
    static let singleQuote = UInt8(ascii: "'")
    static let hash = UInt8(ascii: "#")
    static let dash = UInt8(ascii: "-")

    static func isBlank(_ byte: UInt8) -> Bool { byte == space || byte == tab || byte == newline }

    static func isIdentifierStart(_ byte: UInt8) -> Bool {
        (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A) || byte == 0x5F
    }

    static func isIdentifierByte(_ byte: UInt8) -> Bool {
        isIdentifierStart(byte) || (byte >= 0x30 && byte <= 0x39)
    }

    static func isIdentifier(_ text: String) -> Bool {
        let bytes = Array(text.utf8)
        guard let first = bytes.first, isIdentifierStart(first) else { return false }
        return bytes.allSatisfy(isIdentifierByte)
    }

    /// Whether `source[start..<end]` holds only blanks and line continuations.
    static func isBlankGap(_ source: [UInt8], _ start: Int, _ end: Int) -> Bool {
        var index = start
        while index < end {
            if isBlank(source[index]) {
                index += 1
            } else if source[index] == backslash, index + 1 < end, source[index + 1] == newline {
                index += 2
            } else {
                return false
            }
        }
        return true
    }

    /// Whether `source[start..<end]` is empty or only line continuations, so
    /// the nodes on either side are one shell word.
    static func isJoiningGap(_ source: [UInt8], _ start: Int, _ end: Int) -> Bool {
        var index = start
        while index < end {
            guard source[index] == backslash, index + 1 < end, source[index + 1] == newline else { return false }
            index += 2
        }
        return true
    }

    static func string(_ bytes: [UInt8]) -> String { String(decoding: bytes, as: UTF8.self) }
}

fileprivate extension BashNode {
    var begin: Int { Int(startByte) }
    var finish: Int { Int(endByte) }
}

// MARK: - Word decoding

/// One shell word as the analysis sees it: possibly several adjacent tree
/// nodes (tree-sitter splits `a\<newline>b` and `$"…"`), classified for argv
/// matching.
struct ShellWordGroup {
    let startByte: Int
    let endByte: Int
    let word: ShellCommandWord
    /// The literal text before the first non-literal part (`FOO=` of `FOO="$x"`).
    let leadingLiteral: String
    /// The word holds a node kind this module does not model.
    let isOpaque: Bool

    var literal: String? {
        if case let .exact(value) = word { return value }
        return nil
    }
}

/// A byte of an unquoted word for brace-expansion detection: `special` when it
/// is unquoted and unescaped.
struct ShellShapeByte {
    let byte: UInt8
    let special: Bool
}

enum ShellBraces {
    /// `{a,b}` or `{1..3}` / `{a..e}` made of unquoted, unescaped characters.
    static func hasExpansion(_ shape: [ShellShapeByte]) -> Bool {
        var opens: [Int] = []
        for (index, item) in shape.enumerated() where item.special {
            if item.byte == UInt8(ascii: "{") {
                opens.append(index)
            } else if item.byte == UInt8(ascii: "}"), let open = opens.popLast() {
                let inner = shape[(open + 1)..<index]
                if inner.contains(where: { $0.special && $0.byte == UInt8(ascii: ",") }) { return true }
                if isSequence(inner) { return true }
            }
        }
        return false
    }

    private static func isSequence(_ inner: ArraySlice<ShellShapeByte>) -> Bool {
        guard inner.allSatisfy(\.special) else { return false }
        let fields = ShellBytes.string(inner.map(\.byte)).components(separatedBy: "..")
        guard fields.count == 2 || fields.count == 3 else { return false }
        if fields.count == 3, !isInteger(fields[2]) { return false }
        return (isInteger(fields[0]) && isInteger(fields[1])) || (isLetter(fields[0]) && isLetter(fields[1]))
    }

    private static func isInteger(_ text: String) -> Bool {
        var digits = Substring(text)
        if digits.first == "-" || digits.first == "+" { digits = digits.dropFirst() }
        return !digits.isEmpty && digits.allSatisfy { $0.isASCII && $0.isNumber }
    }

    private static func isLetter(_ text: String) -> Bool {
        text.count == 1 && text.allSatisfy { $0.isASCII && $0.isLetter }
    }
}

/// Accumulates one word group.
struct ShellWordBuilder {
    private var literal: [UInt8] = []
    private var run: [UInt8] = []
    private var pieces: [ShellPatternPiece] = []
    private var hasWildcard = false
    private var isAny = false
    private var isOpaque = false
    private var leading: [UInt8] = []
    private var sawNonLiteral = false
    private var shape: [ShellShapeByte] = []
    private(set) var hasContent = false

    mutating func appendUnquoted(_ byte: UInt8, special: Bool) {
        appendLiteralBytes([byte])
        shape.append(ShellShapeByte(byte: byte, special: special))
    }

    mutating func appendQuoted(_ bytes: [UInt8]) {
        hasContent = true
        guard !bytes.isEmpty else { return }
        appendLiteralBytes(bytes)
        shape.append(contentsOf: bytes.map { ShellShapeByte(byte: $0, special: false) })
    }

    private mutating func appendLiteralBytes(_ bytes: [UInt8]) {
        hasContent = true
        literal += bytes
        run += bytes
        if !sawNonLiteral { leading += bytes }
    }

    /// A quoted expansion: one argv element whatever its value.
    mutating func appendWildcard() {
        hasContent = true
        sawNonLiteral = true
        hasWildcard = true
        if !run.isEmpty {
            pieces.append(.literal(ShellBytes.string(run)))
            run = []
        }
        if pieces.last != .wildcard { pieces.append(.wildcard) }
        shape.append(ShellShapeByte(byte: 0, special: false))
    }

    /// Anything that can become zero or more argv elements.
    mutating func appendAny() {
        hasContent = true
        sawNonLiteral = true
        isAny = true
        shape.append(ShellShapeByte(byte: 0, special: false))
    }

    mutating func markOpaque() {
        isOpaque = true
        appendAny()
    }

    func finish(start: Int, end: Int) -> ShellWordGroup {
        let braces = ShellBraces.hasExpansion(shape)
        let word: ShellCommandWord
        if isAny || braces {
            word = .any
        } else if hasWildcard {
            var finalPieces = pieces
            if !run.isEmpty { finalPieces.append(.literal(ShellBytes.string(run))) }
            word = .pattern(finalPieces)
        } else {
            word = .exact(ShellBytes.string(literal))
        }
        return ShellWordGroup(
            startByte: start, endByte: end, word: word,
            leadingLiteral: ShellBytes.string(leading), isOpaque: isOpaque
        )
    }
}

/// Decodes argument nodes into word groups. Pure reads of the source bytes.
struct ShellWordDecoder {
    let source: [UInt8]

    /// Expansion kinds that stand for one value inside double quotes.
    static let quotedExpansionKinds: Set<String> = [
        "simple_expansion", "expansion", "command_substitution", "arithmetic_expansion",
    ]
    /// Expansion kinds that make an unquoted word `.any`.
    static let unquotedExpansionKinds: Set<String> = [
        "simple_expansion", "expansion", "command_substitution", "arithmetic_expansion",
        "process_substitution",
    ]

    func decode(_ nodes: [BashNode]) -> ShellWordGroup {
        var builder = ShellWordBuilder()
        for (index, node) in nodes.enumerated() {
            part(node, isLast: index == nodes.count - 1, into: &builder, depth: 0)
        }
        let start = nodes.first.map { contentStart(of: $0) } ?? 0
        let end = nodes.last?.finish ?? start
        return builder.finish(start: start, end: end)
    }

    /// Where a node's own bytes begin. Inside double quotes the grammar folds
    /// the blanks and line continuations before an expansion into it (`" $x"`
    /// has a `$` token spelled ` $`, `"\<newline>  ${x}"` a `${` token spelled
    /// with both); they belong to the string, not the expansion.
    func contentStart(of node: BashNode) -> Int {
        var index = node.begin
        let end = min(node.finish, source.count)
        while index < end {
            if ShellBytes.isBlank(source[index]) {
                index += 1
            } else if source[index] == ShellBytes.backslash, index + 1 < end, source[index + 1] == ShellBytes.newline {
                index += 2
            } else {
                break
            }
        }
        return index
    }

    /// The string content of those folded bytes: blanks kept, continuations
    /// removed.
    private func foldedContent(of node: BashNode) -> [UInt8] {
        var content: [UInt8] = []
        var index = node.begin
        let end = contentStart(of: node)
        while index < end {
            if source[index] == ShellBytes.backslash {
                index += 2
            } else {
                content.append(source[index])
                index += 1
            }
        }
        return content
    }

    private func part(_ node: BashNode, isLast: Bool, into builder: inout ShellWordBuilder, depth: Int) {
        guard depth < 64 else {
            builder.markOpaque()
            return
        }
        let kind = node.kind
        switch kind {
        case "word", "number", "variable_name":
            unquoted(node, isLast: isLast, into: &builder)
        case "subscript":
            // `a[0]` as an argument: `[` is a glob bracket.
            unquoted(node, isLast: isLast, into: &builder)
        case "raw_string":
            guard let content = interior(node, open: 1, close: 1) else {
                builder.markOpaque()
                return
            }
            builder.appendQuoted(content)
        case "string":
            doubleQuoted(node, into: &builder)
        case "ansi_c_string":
            ansiC(node, into: &builder)
        case _ where Self.unquotedExpansionKinds.contains(kind):
            builder.appendAny()
        case "brace_expression":
            builder.appendAny()
        case "concatenation", "variable_assignment":
            let children = node.children
            for (index, child) in children.enumerated() {
                let childIsLast = isLast && index == children.count - 1
                if child.isNamed || child.kind == "$" {
                    part(child, isLast: childIsLast, into: &builder, depth: depth + 1)
                } else if kind == "variable_assignment", child.kind == "=" || child.kind == "+=" {
                    for byte in child.kind.utf8 { builder.appendUnquoted(byte, special: true) }
                } else {
                    builder.markOpaque()
                }
            }
        case "$":
            // `$$` (the process ID) is a `$` token to the grammar. Otherwise a
            // `$` that ends the word is literal; before a quote it starts
            // `$"…"` (locale translation) or `$'…'`.
            if source[contentStart(of: node)..<min(node.finish, source.count)].elementsEqual("$$".utf8) {
                builder.appendAny()
            } else if isLast {
                builder.appendUnquoted(ShellBytes.dollar, special: true)
            } else {
                builder.appendAny()
            }
        default:
            builder.markOpaque()
        }
    }

    /// Unquoted text: a backslash escapes the next byte (a backslash-newline
    /// vanishes); `* ? [` glob; `$` or a backquote the grammar left in the text
    /// expands; a leading `~` is a tilde prefix.
    private func unquoted(_ node: BashNode, isLast: Bool, into builder: inout ShellWordBuilder) {
        let start = node.begin
        let end = min(node.finish, source.count)
        var index = start
        if !builder.hasContent, index < end, source[index] == UInt8(ascii: "~") {
            builder.appendAny()
            return
        }
        while index < end {
            let byte = source[index]
            switch byte {
            case ShellBytes.backslash:
                if index + 1 < end {
                    let next = source[index + 1]
                    if next != ShellBytes.newline { builder.appendUnquoted(next, special: false) }
                    index += 2
                } else {
                    builder.appendUnquoted(byte, special: false)
                    index += 1
                }
            case UInt8(ascii: "*"), UInt8(ascii: "?"), UInt8(ascii: "["), ShellBytes.backtick:
                builder.appendAny()
                index += 1
            case ShellBytes.dollar:
                if index + 1 < end || !isLast {
                    builder.appendAny()
                } else {
                    builder.appendUnquoted(byte, special: true)
                }
                index += 1
            default:
                builder.appendUnquoted(byte, special: true)
                index += 1
            }
        }
    }

    /// Double quotes, read from the raw bytes rather than `string_content`
    /// nodes: `\"`, `\\`, `\$`, `` \` `` and backslash-newline are processed;
    /// an expansion child is one wildcard (or `.any` for `"$@"`-style arrays);
    /// a `$` or backquote the grammar left as text is a wildcard too.
    private func doubleQuoted(_ node: BashNode, into builder: inout ShellWordBuilder) {
        let start = node.begin
        let end = node.finish
        guard end - start >= 2, end <= source.count, source[start] == ShellBytes.doubleQuote,
              source[end - 1] == ShellBytes.doubleQuote else {
            builder.markOpaque()
            return
        }
        builder.appendQuoted([])
        let children = node.namedChildren.filter { $0.kind != "string_content" }
        var childIndex = 0
        var pending: [UInt8] = []
        var position = start + 1
        let close = end - 1
        while position < close {
            if childIndex < children.count {
                let child = children[childIndex]
                if child.begin < position {
                    builder.markOpaque()
                    return
                }
                if child.begin == position {
                    pending += foldedContent(of: child)
                    builder.appendQuoted(pending)
                    pending = []
                    quotedExpansion(child, into: &builder)
                    position = child.finish
                    childIndex += 1
                    continue
                }
            }
            let byte = source[position]
            if byte == ShellBytes.backslash, position + 1 < close {
                let next = source[position + 1]
                if next == ShellBytes.doubleQuote || next == ShellBytes.backslash || next == ShellBytes.dollar
                    || next == ShellBytes.backtick {
                    pending.append(next)
                    position += 2
                    continue
                }
                if next == ShellBytes.newline {
                    position += 2
                    continue
                }
            }
            if (byte == ShellBytes.dollar && position + 1 < close && Self.startsParameter(source[position + 1]))
                || byte == ShellBytes.backtick {
                builder.appendQuoted(pending)
                pending = []
                builder.appendWildcard()
                // `$$`, `$?`, `$1`…: a one-character parameter is consumed whole.
                let isSpecial = byte == ShellBytes.dollar && "$?!#-*@0123456789".utf8.contains(source[position + 1])
                position += isSpecial ? 2 : 1
                continue
            }
            pending.append(byte)
            position += 1
        }
        builder.appendQuoted(pending)
        if childIndex < children.count { builder.markOpaque() }
    }

    private func quotedExpansion(_ child: BashNode, into builder: inout ShellWordBuilder) {
        if isArrayExpansion(child) {
            builder.appendAny()
        } else if Self.quotedExpansionKinds.contains(child.kind) {
            builder.appendWildcard()
        } else {
            builder.markOpaque()
        }
    }

    /// `"$@"`, `"${@:2}"`, `"${a[@]}"`, `"${!a[@]}"`, `"${!prefix@}"` expand to
    /// zero or more words even inside double quotes.
    private func isArrayExpansion(_ node: BashNode) -> Bool {
        let start = contentStart(of: node)
        let text = ShellBytes.string(Array(source[start..<max(start, min(node.finish, source.count))]))
        switch node.kind {
        case "simple_expansion":
            return text == "$@"
        case "expansion":
            return text.hasPrefix("${@") || text.contains("[@]") || (text.hasPrefix("${!") && text.hasSuffix("@}"))
        default:
            return false
        }
    }

    static func startsParameter(_ byte: UInt8) -> Bool {
        if ShellBytes.isIdentifierByte(byte) { return true }
        return "{(@*#?$!-".utf8.contains(byte)
    }

    /// `$'…'` with `\n \t \\ \' \"` and `\xH[H]` (ASCII only); anything else
    /// makes the word `.any` rather than guess.
    private func ansiC(_ node: BashNode, into builder: inout ShellWordBuilder) {
        let start = node.begin
        let end = node.finish
        guard end - start >= 3, end <= source.count, source[start] == ShellBytes.dollar,
              source[start + 1] == ShellBytes.singleQuote, source[end - 1] == ShellBytes.singleQuote else {
            builder.markOpaque()
            return
        }
        var output: [UInt8] = []
        var position = start + 2
        let close = end - 1
        while position < close {
            let byte = source[position]
            guard byte == ShellBytes.backslash else {
                output.append(byte)
                position += 1
                continue
            }
            guard position + 1 < close else {
                builder.appendAny()
                return
            }
            let next = source[position + 1]
            switch next {
            case UInt8(ascii: "n"): output.append(ShellBytes.newline)
            case UInt8(ascii: "t"): output.append(ShellBytes.tab)
            case ShellBytes.backslash, ShellBytes.singleQuote, ShellBytes.doubleQuote: output.append(next)
            case UInt8(ascii: "x"):
                guard let (value, digits) = hexEscape(at: position + 2, end: close) else {
                    builder.appendAny()
                    return
                }
                output.append(value)
                position += 2 + digits
                continue
            default:
                builder.appendAny()
                return
            }
            position += 2
        }
        builder.appendQuoted(output)
    }

    private func hexEscape(at start: Int, end: Int) -> (UInt8, Int)? {
        var value = 0
        var digits = 0
        while digits < 2, start + digits < end, let digit = hexValue(source[start + digits]) {
            value = value * 16 + digit
            digits += 1
        }
        guard digits > 0, value >= 1, value <= 0x7F else { return nil }
        return (UInt8(value), digits)
    }

    private func hexValue(_ byte: UInt8) -> Int? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return Int(byte - UInt8(ascii: "0"))
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return Int(byte - UInt8(ascii: "a")) + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return Int(byte - UInt8(ascii: "A")) + 10
        default: return nil
        }
    }

    private func interior(_ node: BashNode, open: Int, close: Int) -> [UInt8]? {
        let start = node.begin + open
        let end = node.finish - close
        guard start <= end, end <= source.count else { return nil }
        return Array(source[start..<end])
    }
}

// MARK: - Prefix rules

/// Which word of a command names the program.
enum ShellPrefixRules {
    /// `LauncherScript.simpleCommands`' program word, or nil when a bare prefix
    /// leaves no command.
    static func programIndex(_ words: [ShellWordGroup]) -> Int? {
        var index = 0
        for _ in 0...words.count {
            guard index < words.count else { return nil }
            guard let width = programPrefixWidth(words, at: index) else { return index }
            index += width
        }
        return nil
    }

    private static func startsOption(_ words: [ShellWordGroup], _ index: Int) -> Bool {
        index < words.count && words[index].leadingLiteral.hasPrefix("-")
    }

    private static func programPrefixWidth(_ words: [ShellWordGroup], at index: Int) -> Int? {
        guard let name = words[index].literal else { return nil }
        let next = index + 1 < words.count ? words[index + 1].literal : nil
        var width = 1
        switch name {
        case "exec", "command", "builtin", "noglob", "nocorrect", "nohup":
            break
        case "time":
            if next == "-p" { width = 2 }
        case "nice":
            if next == "-n" {
                width = 3
            } else if let next, isNiceAdjustment(next) {
                width = 2
            }
        case "env":
            if next == "-i" { width = 2 }
            while index + width < words.count, isEnvironmentAssignment(words[index + width]) {
                width += 1
            }
        case "mise":
            // `mise exec|x [tools and options] -- command…` execs the command
            // (mise src/cli/exec.rs, `exec::Command::exec`) after loading the
            // directory's mise environment. Only literal words before the
            // `--`, and never `-c`/`--command`, which runs a shell instead.
            guard next == "exec" || next == "x" else { return nil }
            var position = index + 2
            while position < words.count, let word = words[position].literal, word != "--" {
                guard !isMiseCommandOption(word) else { return nil }
                position += 1
            }
            guard position < words.count, words[position].literal == "--" else { return nil }
            width = position + 1 - index
        case "direnv":
            // `direnv exec DIR command…` loads DIR's allowed .envrc and execs
            // the command (direnv internal/cmd/cmd_exec.go, `syscall.Exec`).
            guard next == "exec", index + 2 < words.count, words[index + 2].literal != nil else { return nil }
            width = 3
        default:
            return nil
        }
        return startsOption(words, index + width) ? nil : width
    }

    /// `mise exec`'s `-c`/`--command`, which runs its value with a shell.
    static func isMiseCommandOption(_ word: String) -> Bool {
        word == "--command" || word.hasPrefix("--command=")
            || (word.hasPrefix("-") && !word.hasPrefix("--") && word.dropFirst().contains("c"))
    }

    private static func isNiceAdjustment(_ text: String) -> Bool {
        let bytes = Array(text.utf8)
        return bytes.count >= 2 && bytes[0] == ShellBytes.dash
            && bytes.dropFirst().allSatisfy { $0 >= 0x30 && $0 <= 0x39 }
    }

    private static func isEnvironmentAssignment(_ word: ShellWordGroup) -> Bool {
        let bytes = Array(word.leadingLiteral.utf8)
        guard let equals = bytes.firstIndex(of: UInt8(ascii: "=")), equals > 0,
              ShellBytes.isIdentifierStart(bytes[0]) else { return false }
        return bytes[..<equals].allSatisfy(ShellBytes.isIdentifierByte)
    }

}

// MARK: - Analysis of one shell text

/// One parse of a shell text and the simple commands in it. Built only
/// through `parse`, which refuses a text tree-sitter and bash would read
/// differently in the ways listed on `simpleCommands`.
final class ShellTextAnalysis {
    struct Problem: Error, Equatable {
        let byteOffset: Int
    }

    struct Command {
        let startByte: Int
        let line: Int
        let words: [ShellWordGroup]
        let isOpaque: Bool
        let programIndex: Int?

        func publicCommand(lineBase: Int) -> ShellSimpleCommand? {
            guard !isOpaque, let programIndex else { return nil }
            return ShellSimpleCommand(
                name: words[programIndex].literal,
                arguments: words[(programIndex + 1)...].map(\.word),
                line: lineBase + line
            )
        }
    }

    /// Far beyond any real script; bounds recursion on a hostile one.
    static let maximumNesting = 200

    let tree: BashTree
    let source: [UInt8]
    private let lineStarts: [Int]
    private(set) var commands: [Command] = []
    private var droppedDashes: [Int: [Int]] = [:]

    private init(tree: BashTree) {
        self.tree = tree
        source = tree.source
        var starts = [0]
        for (index, byte) in source.enumerated() where byte == ShellBytes.newline {
            starts.append(index + 1)
        }
        lineStarts = starts
    }

    static func parse(_ text: String) -> Result<ShellTextAnalysis, Problem> {
        parse(text, repairing: true)
    }

    private static func parse(_ text: String, repairing: Bool) -> Result<ShellTextAnalysis, Problem> {
        let bytes = Array(text.utf8)
        if let nul = bytes.firstIndex(of: 0) { return .failure(Problem(byteOffset: nul)) }
        guard let tree = try? BashTree(text) else { return .failure(Problem(byteOffset: 0)) }
        let analysis = ShellTextAnalysis(tree: tree)
        if tree.root.hasError {
            if repairing, let repair = heredocRedirectPipeRepair(tree),
               case let .success(repaired) = parse(repair.text, repairing: false),
               repaired.movedBytesAreRedirects(repair.moved) {
                return .success(repaired)
            }
            if repairing, let repair = emptyBackquoteRepair(tree),
               case let .success(repaired) = parse(repair.text, repairing: false),
               repaired.joinsArgumentStrings(at: repair.pairs) {
                return .success(repaired)
            }
            return .failure(Problem(byteOffset: analysis.firstErrorOffset()))
        }
        do {
            try analysis.checkStructure()
            try analysis.walk(tree.root, depth: 0)
        } catch let problem as Problem {
            return .failure(problem)
        } catch {
            return .failure(Problem(byteOffset: 0))
        }
        analysis.commands.sort { $0.startByte < $1.startByte }
        return .success(analysis)
    }

    /// tree-sitter-bash's `heredoc_redirect` accepts redirects after the
    /// delimiter only when `&&`/`||` or nothing follows them, so
    /// `cmd <<'EOF' 2>&1 | next` (which bash runs as a pipeline) leaves the
    /// `|` as an ERROR inside the last redirect. Bash applies the redirects in
    /// order, which decides only where the streams go, never which commands
    /// run or with what argv; so the text is rewritten with those redirects
    /// moved before the `<<` (`cmd 2>&1 <<'EOF' | next`, which the grammar
    /// reads), on the same line, and parsed once more with no further repair.
    /// Applies only when every ERROR node in the tree is that one `|`/`|&`
    /// token, under a redirect of the first line of a heredoc statement.
    private static func heredocRedirectPipeRepair(_ tree: BashTree) -> (text: String, moved: Range<Int>)? {
        // Every ERROR or MISSING node, and the heredoc redirects above them.
        var errors: [BashNode] = []
        var heredocs: [Int: BashNode] = [:]
        var stack: [(BashNode, BashNode?)] = [(tree.root, nil)]
        var visited = 0
        while let (node, heredoc) = stack.popLast() {
            visited += 1
            guard visited <= 1_000_000 else { return nil }
            if node.kind == "ERROR" || ts_node_is_missing(node.raw) {
                guard let heredoc else { return nil }
                errors.append(node)
                heredocs[heredoc.begin] = heredoc
                continue
            }
            guard node.hasError else { continue }
            let inside = node.kind == "heredoc_redirect" ? node : heredoc
            for child in node.children { stack.append((child, inside)) }
        }
        guard heredocs.count == 1, let heredoc = heredocs.values.first else { return nil }
        let children = heredoc.children
        guard let start = children.firstIndex(where: { $0.kind == "heredoc_start" }), start == 1,
              children[0].kind == "<<" || children[0].kind == "<<-", start + 1 < children.count else { return nil }
        // The first `|` or `|&` token after the delimiter, in source order.
        var pipe: BashNode?
        var pending = Array(children[(start + 1)...].reversed())
        while pipe == nil, let node = pending.popLast() {
            let below = node.children
            if below.isEmpty {
                if !node.isNamed, node.kind == "|" || node.kind == "|&" { pipe = node }
            } else {
                pending.append(contentsOf: below.reversed())
            }
        }
        guard let pipe else { return nil }
        let source = tree.source
        let operatorStart = children[0].begin
        let delimiterEnd = children[start].finish
        let redirectsStart = children[start + 1].begin
        guard redirectsStart < pipe.begin,
              errors.allSatisfy({ $0.begin >= redirectsStart && $0.finish <= pipe.finish }),
              !source[operatorStart..<pipe.begin].contains(ShellBytes.newline),
              !source[operatorStart..<pipe.begin].contains(ShellBytes.backslash) else { return nil }
        var redirectsEnd = pipe.begin
        while redirectsEnd > redirectsStart, ShellBytes.isBlank(source[redirectsEnd - 1]) { redirectsEnd -= 1 }
        var rewritten = Array(source[..<operatorStart])
        rewritten += source[redirectsStart..<redirectsEnd]
        let moved = operatorStart..<(operatorStart + redirectsEnd - redirectsStart)
        rewritten.append(ShellBytes.space)
        rewritten += source[operatorStart..<delimiterEnd]
        rewritten.append(ShellBytes.space)
        rewritten += source[pipe.begin...]
        guard let text = String(bytes: rewritten, encoding: .utf8) else { return nil }
        return (text, moved)
    }

    /// Whether `moved` is exactly a run of `file_redirect` nodes, children of
    /// one `redirected_statement` directly before its `heredoc_redirect`.
    private func movedBytesAreRedirects(_ moved: Range<Int>) -> Bool {
        var stack = [tree.root]
        var visited = 0
        while let node = stack.popLast() {
            visited += 1
            guard visited <= 1_000_000 else { return false }
            guard node.begin <= moved.lowerBound, node.finish >= moved.upperBound else { continue }
            let children = node.children
            if node.kind == "redirected_statement",
               let first = children.firstIndex(where: { $0.begin == moved.lowerBound }) {
                var index = first
                while index < children.count, children[index].kind == "file_redirect",
                      children[index].finish <= moved.upperBound {
                    if children[index].finish == moved.upperBound {
                        return index + 1 < children.count && children[index + 1].kind == "heredoc_redirect"
                    }
                    index += 1
                }
                return false
            }
            stack.append(contentsOf: children)
        }
        return false
    }

    /// tree-sitter-bash's backquote substitution needs a command between its
    /// backquotes, so an empty one inside double quotes
    /// (`git commit -m "before `` after"`, which bash and zsh both run with the
    /// argument `before  after`) is an ERROR. Each unescaped pair of adjacent
    /// backquotes inside the ERROR nodes is rewritten as `""`, which closes the
    /// string and opens the next with the same bytes before and after, and the
    /// text is parsed once more with no further repair; `joinsArgumentStrings`
    /// then proves every pair was such a boundary. Offsets and lines are kept.
    private static func emptyBackquoteRepair(_ tree: BashTree) -> (text: String, pairs: [Int])? {
        var errors: [Range<Int>] = []
        var stack = [tree.root]
        var visited = 0
        while let node = stack.popLast() {
            visited += 1
            guard visited <= 1_000_000 else { return nil }
            if node.kind == "ERROR" {
                errors.append(node.begin..<node.finish)
            } else if node.hasError {
                stack.append(contentsOf: node.children)
            }
        }
        var rewritten = tree.source
        var pairs: [Int] = []
        var index = 0
        while index + 1 < rewritten.count {
            let byte = rewritten[index]
            if byte == ShellBytes.backslash {
                index += 2
            } else if byte == ShellBytes.backtick, rewritten[index + 1] == ShellBytes.backtick,
                      errors.contains(where: { $0.contains(index) && $0.contains(index + 1) }) {
                rewritten[index] = ShellBytes.doubleQuote
                rewritten[index + 1] = ShellBytes.doubleQuote
                pairs.append(index)
                index += 2
            } else {
                index += 1
            }
        }
        guard !pairs.isEmpty, let text = String(bytes: rewritten, encoding: .utf8) else { return nil }
        return (text, pairs)
    }

    /// Whether every byte in `pairs` (and the one after it) is a `""` that
    /// closes a double-quoted string and opens the next one, two adjacent parts
    /// of one argument word of a command reached only through plain statement
    /// lists. Bash and zsh read the bytes before it identically in both texts,
    /// so the original backquotes there open and close an empty substitution
    /// inside that string, which adds nothing to the argument. Anything else is
    /// refused: a pair in single quotes, an unquoted word, a command name, an
    /// assignment, a redirect target, a heredoc, a substitution (inside
    /// backquotes a backquote ends the outer one) or a control-flow body; and a
    /// `$` just before the pair, which bash reads with the byte after it.
    private func joinsArgumentStrings(at pairs: [Int]) -> Bool {
        var boundaries: Set<Int> = []
        var stack = [tree.root]
        var visited = 0
        while let node = stack.popLast() {
            visited += 1
            guard visited <= 1_000_000 else { return false }
            switch node.kind {
            case "program", "list", "pipeline", "redirected_statement", "negated_command", "subshell",
                 "compound_statement":
                stack.append(contentsOf: node.children.filter(\.isNamed))
            case "command":
                for word in node.children where word.kind == "concatenation" {
                    let parts = word.children
                    for (left, right) in zip(parts, parts.dropFirst())
                    where left.kind == "string" && right.kind == "string" && left.finish == right.begin {
                        boundaries.insert(left.finish - 1)
                    }
                }
            default:
                continue
            }
        }
        return pairs.allSatisfy { pair in
            guard boundaries.contains(pair), pair > 0, source[pair - 1] != ShellBytes.dollar else { return false }
            var backslashes = 0
            while pair - backslashes > 0, source[pair - backslashes - 1] == ShellBytes.backslash { backslashes += 1 }
            return backslashes % 2 == 0
        }
    }

    func line(of offset: Int) -> Int {
        var low = 0
        var high = lineStarts.count - 1
        while low < high {
            let middle = (low + high + 1) / 2
            if lineStarts[middle] <= offset { low = middle } else { high = middle - 1 }
        }
        return low + 1
    }

    func text(_ node: BashNode) -> String {
        let end = min(node.finish, source.count)
        guard node.begin <= end else { return "" }
        return ShellBytes.string(Array(source[node.begin..<end]))
    }

    func decode(_ nodes: [BashNode]) -> ShellWordGroup {
        ShellWordDecoder(source: source).decode(nodes)
    }

    func publicCommands(lineBase: Int) -> [ShellSimpleCommand] {
        commands.compactMap { $0.publicCommand(lineBase: lineBase) }
    }

    private func firstErrorOffset() -> Int {
        var stack = [tree.root]
        var visited = 0
        while let node = stack.popLast(), visited < 1_000_000 {
            visited += 1
            if node.kind == "ERROR" || ts_node_is_missing(node.raw) { return node.begin }
            if node.hasError { stack.append(contentsOf: node.children.reversed()) }
        }
        return 0
    }

    // MARK: Structure: tokens, gaps, heredocs

    /// Refuses a tree that leaves source text out, spells an operator token
    /// differently from its kind, or places a heredoc where bash would not.
    private func checkStructure() throws {
        let root = tree.root
        guard ShellBytes.isBlankGap(source, 0, root.begin) else { throw Problem(byteOffset: 0) }
        try checkNode(root, depth: 0)
        guard ShellBytes.isBlankGap(source, root.finish, source.count) else {
            throw Problem(byteOffset: root.finish)
        }
    }

    private func checkNode(_ node: BashNode, depth: Int) throws {
        guard depth < Self.maximumNesting else { throw Problem(byteOffset: node.begin) }
        let children = node.children
        if children.isEmpty {
            // An operator token spelled differently from its kind: the grammar
            // folds `-` into `<<` (`cmd -<<EOF`) where bash reads a word, and
            // reads `` "`a` `b`" `` as one substitution with a `` ` ` `` token.
            // Allowed: blanks before the token (inside double quotes the
            // grammar folds the content space before `$` into the `$` token),
            // and `$$`, the process ID, which the grammar spells as a `$` token.
            if !node.isNamed {
                let spelled = source[contentStart(node)..<node.finish]
                guard spelled.elementsEqual(node.kind.utf8) || (node.kind == "$" && spelled.elementsEqual("$$".utf8))
                else { throw Problem(byteOffset: node.begin) }
            }
            if node.kind == "ansi_c_string" { try checkAnsiC(node) }
            return
        }
        if node.kind == "heredoc_redirect" { try checkHeredoc(node, children) }
        if node.kind == "string" { try checkString(node, children) }
        // Inside double quotes and heredoc bodies the gaps are content, and so
        // is the text of a number around its expansion (`10#${n}`).
        let isContent = node.kind == "string" || node.kind == "heredoc_body" || node.kind == "number"
        let hasHeredoc = node.kind == "redirected_statement" && children.contains { $0.kind == "heredoc_redirect" }
        var cursor = node.begin
        for child in children {
            guard child.begin >= cursor else { throw Problem(byteOffset: child.begin) }
            if !isContent { try checkGap(cursor, child.begin, in: node, children: children, hasHeredoc: hasHeredoc) }
            try checkNode(child, depth: depth + 1)
            cursor = child.finish
        }
        guard cursor <= node.finish else { throw Problem(byteOffset: node.finish) }
        if !isContent { try checkGap(cursor, node.finish, in: node, children: children, hasHeredoc: hasHeredoc) }
    }

    private func contentStart(_ node: BashNode) -> Int {
        ShellWordDecoder(source: source).contentStart(of: node)
    }

    /// The literal bytes of a double-quoted string (outside its expansion
    /// children) hold no unescaped `"`: one there is where bash closes the
    /// string, so the grammar would have read on past bash's end and could hide
    /// code as string content.
    private func checkString(_ node: BashNode, _ children: [BashNode]) throws {
        let start = node.begin
        let end = node.finish
        guard end - start >= 2, end <= source.count, source[start] == ShellBytes.doubleQuote,
              source[end - 1] == ShellBytes.doubleQuote else { throw Problem(byteOffset: start) }
        let expansions = children.filter { $0.isNamed && $0.kind != "string_content" }
        var childIndex = 0
        var position = start + 1
        while position < end - 1 {
            if childIndex < expansions.count, expansions[childIndex].begin <= position {
                position = max(position, contentStart(expansions[childIndex]), expansions[childIndex].finish)
                childIndex += 1
                continue
            }
            let byte = source[position]
            if byte == ShellBytes.doubleQuote { throw Problem(byteOffset: start) }
            if byte == ShellBytes.backslash, position + 1 < end - 1 {
                position += 2
                continue
            }
            position += 1
        }
    }

    /// The grammar's `$'…'` token reads `\\'` as an escaped quote, so
    /// `echo $'\\'; source evil #'` is one string to it and a backslash, a
    /// `source` and a comment to bash. The string must end at the first quote
    /// bash would end it at (a backslash escapes exactly one byte).
    private func checkAnsiC(_ node: BashNode) throws {
        let start = node.begin
        let end = node.finish
        guard end - start >= 3, end <= source.count, source[start] == ShellBytes.dollar,
              source[start + 1] == ShellBytes.singleQuote else { throw Problem(byteOffset: start) }
        var index = start + 2
        while index < end {
            if source[index] == ShellBytes.backslash {
                index += 2
            } else if source[index] == ShellBytes.singleQuote {
                break
            } else {
                index += 1
            }
        }
        guard index == end - 1 else { throw Problem(byteOffset: start) }
    }

    /// Bytes between two sibling nodes must be blanks or line continuations.
    /// The one repaired exception: tree-sitter drops a lone `-` word in a
    /// statement with a heredoc (`git commit -F - <<'EOF'`); it is put back as
    /// the last argument of the command bash gives it to (`dashOwner`).
    private func checkGap(
        _ start: Int, _ end: Int, in parent: BashNode, children: [BashNode], hasHeredoc: Bool
    ) throws {
        var index = start
        while index < end {
            let byte = source[index]
            if ShellBytes.isBlank(byte) {
                index += 1
            } else if byte == ShellBytes.backslash, index + 1 < end, source[index + 1] == ShellBytes.newline {
                index += 2
            } else if byte == ShellBytes.dash, hasHeredoc,
                      index == start || ShellBytes.isBlank(source[index - 1]),
                      index + 1 == end || ShellBytes.isBlank(source[index + 1]),
                      let body = children.first(where: \.isNamed), index >= body.finish,
                      let owner = Self.dashOwner(body) {
                droppedDashes[owner.begin, default: []].append(index)
                index += 1
            } else if byte == ShellBytes.backslash, parent.kind == "expansion" {
                // `${v//\\/x}`: the grammar leaves the first backslash of an
                // escaped backslash in a pattern or replacement between tokens.
                // A lone backslash there hides no code.
                index += 1
            } else {
                throw Problem(byteOffset: index)
            }
        }
    }

    /// The command a dropped `-` after a heredoc statement's body belongs to.
    /// After `&&`, `||`, `|` or `!` the grammar hangs the heredoc (and any
    /// redirect before it) on the whole list, pipeline or negation
    /// (`cd d && python3 - <<'EOF'`), while bash reads every word up to the
    /// heredoc as the last command's, so the owner is that last command. Any
    /// other body (a subshell, a group, a compound command) takes no word
    /// there: nil, and the gap is refused.
    private static func dashOwner(_ body: BashNode) -> BashNode? {
        var node = body
        for _ in 0..<maximumNesting {
            switch node.kind {
            case "command":
                return node
            case "list", "pipeline", "negated_command":
                guard let last = node.children.last(where: \.isNamed) else { return nil }
                node = last
            default:
                return nil
            }
        }
        return nil
    }

    /// The delimiter is what bash reads after quote removal, quoted when any
    /// part of it is. Its end line must be the first line equal to it (tabs
    /// stripped for `<<-`), must be the line the grammar ended on, and must end
    /// at a newline or the end of the text; a quoted heredoc's body must hold no
    /// parsed expansion. `cat <<E'O'F` is where the grammar fails all three: it
    /// looks for `E'O'F`, swallows the rest of the file as the body, and hides
    /// every later command from the walk.
    private func checkHeredoc(_ node: BashNode, _ children: [BashNode]) throws {
        guard let start = children.first(where: { $0.kind == "heredoc_start" }),
              let end = children.first(where: { $0.kind == "heredoc_end" }),
              let (delimiter, quoted) = heredocDelimiter(start) else {
            throw Problem(byteOffset: node.begin)
        }
        let stripsTabs = children.contains { $0.kind == "<<-" }
        let body = children.first { $0.kind == "heredoc_body" }
        guard Array(source[end.begin..<end.finish]) == delimiter,
              end.finish == source.count || source[end.finish] == ShellBytes.newline else {
            throw Problem(byteOffset: node.begin)
        }
        let endLine = lineStart(of: end.begin)
        let indent = source[endLine..<end.begin]
        guard indent.isEmpty || (stripsTabs && indent.allSatisfy { $0 == ShellBytes.tab }) else {
            throw Problem(byteOffset: node.begin)
        }
        let bodyStart = body.map { lineStart(of: $0.begin) } ?? endLine
        guard bodyStart <= endLine, bodyStart > start.finish else { throw Problem(byteOffset: node.begin) }
        var lineBegin = bodyStart
        while lineBegin < endLine {
            var lineEnd = lineBegin
            while lineEnd < endLine, source[lineEnd] != ShellBytes.newline { lineEnd += 1 }
            var content = lineBegin
            if stripsTabs { while content < lineEnd, source[content] == ShellBytes.tab { content += 1 } }
            if Array(source[content..<lineEnd]) == delimiter { throw Problem(byteOffset: node.begin) }
            lineBegin = lineEnd + 1
        }
        if quoted, let body, body.namedChildCount > 0 { throw Problem(byteOffset: node.begin) }
    }

    private func heredocDelimiter(_ node: BashNode) -> ([UInt8], Bool)? {
        let bytes = Array(source[node.begin..<min(node.finish, source.count)])
        var output: [UInt8] = []
        var quoted = false
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            switch byte {
            case ShellBytes.backslash:
                guard index + 1 < bytes.count else { return nil }
                output.append(bytes[index + 1])
                quoted = true
                index += 2
            case ShellBytes.singleQuote:
                guard let close = bytes[(index + 1)...].firstIndex(of: ShellBytes.singleQuote) else { return nil }
                output += bytes[(index + 1)..<close]
                quoted = true
                index = close + 1
            case ShellBytes.doubleQuote:
                guard let (content, next) = doubleQuotedDelimiter(bytes, from: index + 1) else { return nil }
                output += content
                quoted = true
                index = next
            case ShellBytes.dollar, ShellBytes.backtick:
                return nil
            default:
                output.append(byte)
                index += 1
            }
        }
        return output.isEmpty ? nil : (output, quoted)
    }

    private func doubleQuotedDelimiter(_ bytes: [UInt8], from start: Int) -> ([UInt8], Int)? {
        var output: [UInt8] = []
        var index = start
        while index < bytes.count {
            let byte = bytes[index]
            if byte == ShellBytes.doubleQuote { return (output, index + 1) }
            if byte == ShellBytes.dollar || byte == ShellBytes.backtick { return nil }
            if byte == ShellBytes.backslash, index + 1 < bytes.count,
               [ShellBytes.doubleQuote, ShellBytes.backslash].contains(bytes[index + 1]) {
                output.append(bytes[index + 1])
                index += 2
                continue
            }
            output.append(byte)
            index += 1
        }
        return nil
    }

    private func lineStart(of offset: Int) -> Int {
        lineStarts[line(of: offset) - 1]
    }

    // MARK: Walk

    /// Records every command node, depth first. Only the commands are kept;
    /// the recursion and its depth bound are what refuse a text nested
    /// beyond `maximumNesting`.
    private func walk(_ node: BashNode, depth: Int) throws {
        guard depth < Self.maximumNesting else { throw Problem(byteOffset: node.begin) }
        switch node.kind {
        case "command":
            analyzeCommand(node)
            try walkChildren(node, depth: depth)
        case "function_definition":
            // The name is not a command.
            let named = node.namedChildren
            let nameNode = named.first { $0.kind == "word" }
            for child in named where child.begin != nameNode?.begin {
                try walk(child, depth: depth + 1)
            }
        case "comment", "raw_string", "ansi_c_string", "variable_name", "word":
            return
        case "subscript":
            // `name[index]`: only the index can hold a command.
            for child in node.namedChildren.dropFirst() { try walk(child, depth: depth + 1) }
        default:
            try walkChildren(node, depth: depth)
        }
    }

    private func walkChildren(_ node: BashNode, depth: Int) throws {
        for child in node.children where child.isNamed {
            try walk(child, depth: depth + 1)
        }
    }

    // MARK: Commands

    private func analyzeCommand(_ node: BashNode) {
        var leading: [BashNode] = []
        var wordNodes: [BashNode] = []
        var opaque = false
        for child in node.children {
            switch child.kind {
            case "variable_assignment" where wordNodes.isEmpty:
                leading.append(child)
            case "command_name":
                if child.namedChildCount == 1, let inner = child.namedChild(0) {
                    wordNodes.append(inner)
                } else {
                    opaque = true
                }
            case "file_redirect", "herestring_redirect", "heredoc_redirect", "comment":
                continue
            default:
                if child.isNamed || child.kind == "$" { wordNodes.append(child) } else { opaque = true }
            }
        }
        guard !wordNodes.isEmpty else { return }
        var words = groupWords(wordNodes).map(decode)
        for dash in droppedDashes[node.begin] ?? [] {
            words.append(ShellWordGroup(
                startByte: dash, endByte: dash + 1, word: .exact("-"),
                leadingLiteral: "-", isOpaque: false
            ))
        }
        commands.append(Command(
            startByte: words[0].startByte, line: line(of: words[0].startByte), words: words,
            isOpaque: opaque || words.contains(where: \.isOpaque),
            programIndex: ShellPrefixRules.programIndex(words)
        ))
    }

    /// Adjacent nodes with nothing but line continuations between them are one
    /// shell word.
    private func groupWords(_ nodes: [BashNode]) -> [[BashNode]] {
        var groups: [[BashNode]] = []
        for node in nodes {
            if let previous = groups.last?.last, ShellBytes.isJoiningGap(source, previous.finish, node.begin) {
                groups[groups.count - 1].append(node)
            } else {
                groups.append([node])
            }
        }
        return groups
    }
}
