import Foundation
import CTreeSitterBash

/// Codex's shell-command parsing, ported line for line from openai/codex
/// `codex-rs/shell-command/src/bash.rs` and `shell_detect.rs` (tag
/// rust-v0.155.0-alpha.9.2; both files unchanged at rust-v0.155.0-alpha.16.4 and
/// rust-v0.156.1, re-checked 2026-09-24) over the
/// same tree-sitter runtime and bash grammar (`CTreeSitterBash`). Keep it a
/// transliteration: `CodexCommandGate` is only as exact as this is.
enum CodexShellSyntax {
    /// A tree-sitter parse that could not run (no parser, or cancelled). Codex's
    /// `try_parse_shell` returns `None` there; csec's callers treat it as "Codex
    /// may gate this" instead, which never happens with the vendored grammar.
    struct ParseFailure: Error {}

    // MARK: - shell_detect.rs

    enum ShellType: Equatable {
        case zsh, bash, sh, powerShell, cmd
    }

    /// shell_detect.rs:39-59 `detect_shell_type`: an exact name, else the
    /// path's file stem, retried while it differs from the path.
    static func detectShellType(_ shellPath: String) -> ShellType? {
        switch shellPath {
        case "zsh": return .zsh
        case "sh": return .sh
        case "cmd": return .cmd
        case "bash": return .bash
        case "pwsh": return .powerShell
        case "powershell": return .powerShell
        default:
            guard let stem = RustPath.fileStem(shellPath),
                  RustPath.components(stem) != RustPath.components(shellPath) else { return nil }
            return detectShellType(stem)
        }
    }

    // MARK: - bash.rs

    /// bash.rs:106-119 `extract_bash_command`: exactly `[shell, -lc|-c, script]`
    /// for zsh, bash or sh.
    static func extractBashCommand(_ command: [String]) -> (shell: String, script: String)? {
        guard command.count == 3 else { return nil }
        let (shell, flag, script) = (command[0], command[1], command[2])
        guard flag == "-lc" || flag == "-c",
              let type = detectShellType(shell),
              type == .zsh || type == .bash || type == .sh else { return nil }
        return (shell, script)
    }

    /// bash.rs:124-127 `parse_shell_lc_plain_commands`.
    static func parseShellLcPlainCommands(_ command: [String]) throws -> [[String]]? {
        guard let (_, script) = extractBashCommand(command) else { return nil }
        return try parseShellScriptIntoCommands(script)
    }

    /// bash.rs:101-104 `parse_shell_script_into_commands`.
    static func parseShellScriptIntoCommands(_ script: String) throws -> [[String]]? {
        let tree = try BashTree(script)
        return tryParseWordOnlyCommandsSequence(tree)
    }

    /// bash.rs:29-98 `try_parse_word_only_commands_sequence`: every command
    /// when the script is plain words joined by `&&`, `||`, `;`, `|`, else nil.
    static func tryParseWordOnlyCommandsSequence(_ tree: BashTree) -> [[String]]? {
        if tree.root.hasError { return nil }

        // List of allowed (named) node kinds for a "word only commands sequence".
        let allowedKinds: Set<String> = [
            "program", "list", "pipeline",
            "command", "command_name", "word", "string", "string_content", "raw_string", "number",
            "concatenation",
        ]
        // Allow only safe punctuation / operator tokens; anything else causes reject.
        let allowedPunctTokens: Set<String> = ["&&", "||", ";", "|", "\"", "'"]

        var stack = [tree.root]
        var commandNodes: [BashNode] = []
        while let node = stack.popLast() {
            let kind = node.kind
            if node.isNamed {
                if !allowedKinds.contains(kind) { return nil }
                if (kind == "word" || kind == "number") && !isLiteralWordOrNumber(node, tree) { return nil }
                if kind == "command" { commandNodes.append(node) }
            } else {
                if kind.unicodeScalars.contains(where: { "&;|".unicodeScalars.contains($0) }),
                   !allowedPunctTokens.contains(kind) {
                    return nil
                }
                if !(allowedPunctTokens.contains(kind) || rustTrim(kind).isEmpty) { return nil }
            }
            stack.append(contentsOf: node.children)
        }

        // Walk uses a stack (LIFO), so re-sort by position to restore source order.
        commandNodes.sort { $0.startByte < $1.startByte }

        var commands: [[String]] = []
        for node in commandNodes {
            guard let words = parsePlainCommandFromNode(node, tree) else { return nil }
            commands.append(words)
        }
        return commands
    }

    /// bash.rs:136-160 `parse_shell_lc_literal_commands`: the statically known
    /// words of every command node in a valid tree. Suitable for spotting a
    /// dangerous literal command, never for proving a command safe.
    static func parseShellLcLiteralCommands(_ command: [String]) throws -> [[String]]? {
        guard let (_, script) = extractBashCommand(command) else { return nil }
        return literalCommands(in: try BashTree(script))
    }

    /// The body of `parse_shell_lc_literal_commands` once the script is parsed.
    static func literalCommands(in tree: BashTree) -> [[String]]? {
        if tree.root.hasError { return nil }

        var commands: [[String]] = []
        var stack = [tree.root]
        while let node = stack.popLast() {
            if node.kind == "command", let command = parseLiteralCommandFromNode(node, tree) {
                commands.append(command)
            }
            stack.append(contentsOf: node.namedChildren)
        }
        return commands
    }

    /// bash.rs:162-218 `parse_plain_command_from_node`.
    static func parsePlainCommandFromNode(_ cmd: BashNode, _ tree: BashTree) -> [String]? {
        guard cmd.kind == "command" else { return nil }
        var words: [String] = []
        for child in cmd.namedChildren {
            switch child.kind {
            case "command_name":
                guard let wordNode = child.namedChild(0), wordNode.kind == "word",
                      let text = tree.text(wordNode) else { return nil }
                words.append(text)
            case "word", "number":
                guard let text = tree.text(child) else { return nil }
                words.append(text)
            case "string":
                guard let parsed = parseDoubleQuotedString(child, tree) else { return nil }
                words.append(parsed)
            case "raw_string":
                guard let parsed = parseRawString(child, tree) else { return nil }
                words.append(parsed)
            case "concatenation":
                // Handle concatenated arguments like -g"*.py"
                var concatenated = ""
                for part in child.namedChildren {
                    switch part.kind {
                    case "word", "number":
                        guard let text = tree.text(part) else { return nil }
                        concatenated += text
                    case "string":
                        guard let parsed = parseDoubleQuotedString(part, tree) else { return nil }
                        concatenated += parsed
                    case "raw_string":
                        guard let parsed = parseRawString(part, tree) else { return nil }
                        concatenated += parsed
                    default:
                        return nil
                    }
                }
                if concatenated.isEmpty { return nil }
                words.append(concatenated)
            default:
                return nil
            }
        }
        return words
    }

    /// bash.rs:220-239 `parse_literal_command_from_node`: nil (the command is
    /// skipped) when the program is not literal; later non-literal words are
    /// dropped, not fatal.
    static func parseLiteralCommandFromNode(_ cmd: BashNode, _ tree: BashTree) -> [String]? {
        guard cmd.kind == "command" else { return nil }
        var words: [String] = []
        var foundCommandName = false
        for child in cmd.namedChildren {
            if child.kind == "command_name" {
                guard let nameNode = child.namedChild(0),
                      let commandName = parseLiteralShellWord(nameNode, tree) else { return nil }
                words.append(commandName)
                foundCommandName = true
            } else if foundCommandName, let word = parseLiteralShellWord(child, tree) {
                words.append(word)
            }
        }
        return foundCommandName ? words : nil
    }

    /// bash.rs:241-258 `parse_literal_shell_word`.
    static func parseLiteralShellWord(_ node: BashNode, _ tree: BashTree) -> String? {
        switch node.kind {
        // Swift binds a `where` clause to the last pattern only, so the two
        // Rust arms `"word" | "number" if …` are spelled out.
        case "word" where isLiteralWordOrNumber(node, tree), "number" where isLiteralWordOrNumber(node, tree):
            return tree.text(node)
        case "string":
            return parseDoubleQuotedString(node, tree)
        case "raw_string":
            return parseRawString(node, tree)
        case "concatenation":
            var concatenated = ""
            for part in node.namedChildren {
                guard let word = parseLiteralShellWord(part, tree) else { return nil }
                concatenated += word
            }
            return concatenated.isEmpty ? nil : concatenated
        default:
            return nil
        }
    }

    /// bash.rs:260-274 `is_literal_word_or_number`: a word the shell would not
    /// expand or unescape (Zsh `=cmd` and extended-glob characters included).
    static func isLiteralWordOrNumber(_ node: BashNode, _ tree: BashTree) -> Bool {
        let kind = node.kind
        guard kind == "word" || kind == "number" else { return false }
        guard node.namedChildCount == 0, let word = tree.text(node) else { return false }
        let expanding: Set<Unicode.Scalar> = ["{", "}", "*", "?", "[", "]", "\\", "~", "^", "#", "$", "`"]
        return word.unicodeScalars.first != "=" && !word.unicodeScalars.contains(where: expanding.contains)
    }

    /// bash.rs:276-301 `parse_double_quoted_string`: only `string_content`, and
    /// no backslash escape the shell would remove.
    static func parseDoubleQuotedString(_ node: BashNode, _ tree: BashTree) -> String? {
        guard node.kind == "string" else { return nil }
        for part in node.namedChildren where part.kind != "string_content" {
            return nil
        }
        guard let raw = tree.text(node), let stripped = stripDelimiters(raw, UInt8(ascii: "\"")) else { return nil }
        // Double quotes suppress globbing and brace expansion, but not escape
        // removal. Only accept contents whose source spelling is already literal.
        if stripped.count >= 2 {
            for index in 0..<(stripped.count - 1) where stripped[index] == UInt8(ascii: "\\") {
                switch stripped[index + 1] {
                case UInt8(ascii: "$"), UInt8(ascii: "`"), UInt8(ascii: "\""), UInt8(ascii: "\\"), UInt8(ascii: "\n"):
                    return nil
                default:
                    continue
                }
            }
        }
        return String(decoding: stripped, as: UTF8.self)
    }

    /// bash.rs:303-313 `parse_raw_string`.
    static func parseRawString(_ node: BashNode, _ tree: BashTree) -> String? {
        guard node.kind == "raw_string", let raw = tree.text(node),
              let stripped = stripDelimiters(raw, UInt8(ascii: "'")) else { return nil }
        return String(decoding: stripped, as: UTF8.self)
    }

    /// `text.strip_prefix(c).and_then(|t| t.strip_suffix(c))` on bytes, as Rust
    /// does; Swift's `hasPrefix` compares grapheme clusters, which a combining
    /// mark after the quote would defeat.
    static func stripDelimiters(_ text: String, _ delimiter: UInt8) -> [UInt8]? {
        let bytes = Array(text.utf8)
        guard bytes.count >= 2, bytes.first == delimiter, bytes.last == delimiter else { return nil }
        return Array(bytes[1..<(bytes.count - 1)])
    }

    /// Rust `str::trim`: Unicode White_Space at both ends.
    static func rustTrim(_ text: String) -> Substring {
        let scalars = text.unicodeScalars
        guard let first = scalars.firstIndex(where: { !$0.properties.isWhitespace }) else { return "" }
        let last = scalars.lastIndex(where: { !$0.properties.isWhitespace }) ?? first
        return Substring(scalars[first...last])
    }
}

// MARK: - tree-sitter access

/// One bash parse: the source bytes and the tree over them, kept alive together
/// because every node borrows from the tree.
final class BashTree {
    let source: [UInt8]
    private let tree: OpaquePointer

    /// tree-sitter-rs `Parser::new` + `set_language(tree_sitter_bash)` +
    /// `parse(script, None)` as in bash.rs:13-20 `try_parse_shell`.
    init(_ script: String) throws {
        source = Array(script.utf8)
        guard source.count <= Int(UInt32.max) else { throw CodexShellSyntax.ParseFailure() }
        guard let parser = ts_parser_new() else { throw CodexShellSyntax.ParseFailure() }
        defer { ts_parser_delete(parser) }
        guard ts_parser_set_language(parser, tree_sitter_bash()) else { throw CodexShellSyntax.ParseFailure() }
        // A non-null buffer even for an empty script; the length says how much is source.
        let buffer = source.isEmpty ? [0] : source
        let length = UInt32(source.count)
        let parsed: OpaquePointer? = buffer.withUnsafeBufferPointer { bytes in
            bytes.withMemoryRebound(to: CChar.self) { characters in
                ts_parser_parse_string(parser, nil, characters.baseAddress, length)
            }
        }
        guard let parsed else { throw CodexShellSyntax.ParseFailure() }
        tree = parsed
    }

    deinit { ts_tree_delete(tree) }

    var root: BashNode { BashNode(ts_tree_root_node(tree)) }

    /// tree-sitter-rs `Node::utf8_text`: the node's bytes as a string, nil
    /// where they are not UTF-8. Decoded with `String(decoding:)` because
    /// Foundation's `String(bytes:encoding:)` drops a leading U+FEFF, which
    /// Rust keeps (a `\u{FEFF}--` argument is not `--` to Codex).
    func text(_ node: BashNode) -> String? {
        let start = Int(node.startByte)
        let end = Int(node.endByte)
        guard start <= end, end <= source.count else { return nil }
        let bytes = source[start..<end]
        let decoded = String(decoding: bytes, as: UTF8.self)
        // Invalid sequences decode to U+FFFD; Rust refuses them instead.
        guard decoded.utf8.elementsEqual(bytes) else { return nil }
        return decoded
    }
}

/// A node of a `BashTree`. It must not outlive the tree it came from.
struct BashNode {
    let raw: TSNode

    init(_ raw: TSNode) { self.raw = raw }

    var kind: String { String(cString: ts_node_type(raw)) }
    var isNamed: Bool { ts_node_is_named(raw) }
    var hasError: Bool { ts_node_has_error(raw) }
    var startByte: UInt32 { ts_node_start_byte(raw) }
    var endByte: UInt32 { ts_node_end_byte(raw) }
    var namedChildCount: UInt32 { ts_node_named_child_count(raw) }

    func namedChild(_ index: UInt32) -> BashNode? {
        let child = ts_node_named_child(raw, index)
        return ts_node_is_null(child) ? nil : BashNode(child)
    }

    /// tree-sitter-rs `Node::children`: every visible child, named or not,
    /// walked with a cursor (indexing each child would be quadratic).
    var children: [BashNode] {
        var cursor = ts_tree_cursor_new(raw)
        defer { ts_tree_cursor_delete(&cursor) }
        var result: [BashNode] = []
        guard ts_tree_cursor_goto_first_child(&cursor) else { return result }
        repeat {
            result.append(BashNode(ts_tree_cursor_current_node(&cursor)))
        } while ts_tree_cursor_goto_next_sibling(&cursor)
        return result
    }

    /// tree-sitter-rs `Node::named_children`.
    var namedChildren: [BashNode] { children.filter(\.isNamed) }
}

// MARK: - Rust std::path semantics

/// The parts of Rust's `std::path::Path` (Unix) that Codex's shell detection
/// relies on. Everything works on Unicode scalars, as Rust's `char` does, never
/// on Swift's grapheme clusters.
enum RustPath {
    enum Component: Equatable {
        case rootDir
        case curDir
        case parentDir
        case normal([Unicode.Scalar])
    }

    /// `Path::components`: repeated and trailing separators and interior `.`
    /// vanish; a leading `.` of a relative path is kept as `CurDir`.
    static func components(_ path: String) -> [Component] {
        let scalars = Array(path.unicodeScalars)
        var result: [Component] = []
        if scalars.first == "/" {
            result.append(.rootDir)
        } else if scalars.first == ".", scalars.count == 1 || scalars[1] == "/" {
            result.append(.curDir)
        }
        for part in scalars.split(separator: "/", omittingEmptySubsequences: true) {
            if part.elementsEqual(["."]) { continue }
            result.append(part.elementsEqual([".", "."]) ? .parentDir : .normal(Array(part)))
        }
        return result
    }

    /// `Path::file_name`: the last component when it is a normal name.
    static func fileName(_ path: String) -> [Unicode.Scalar]? {
        if case let .normal(name)? = components(path).last { return name }
        return nil
    }

    /// `Path::file_stem`: the file name without its last extension; a name
    /// whose only dot is the first character has no extension.
    static func fileStem(_ path: String) -> String? {
        guard let name = fileName(path) else { return nil }
        var stem = name
        if let dot = name.lastIndex(of: "."), dot > 0 {
            stem = Array(name[..<dot])
        }
        var result = String.UnicodeScalarView()
        result.append(contentsOf: stem)
        return String(result)
    }
}
