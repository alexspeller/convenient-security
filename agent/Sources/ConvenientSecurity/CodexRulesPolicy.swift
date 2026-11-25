import Foundation
import CoreFoundation

/// Reading Codex's execpolicy from disk for `CodexCommandGate`.
///
/// Ported from openai/codex `codex-rs/config/src/loader/mod.rs` and
/// `codex-rs/execpolicy` at rust-v0.155.0-alpha.9.2. Re-checked 2026-09-24 against
/// rust-v0.155.0-alpha.16.4 and rust-v0.156.1: execpolicy is unchanged, and the
/// loader's only changes (`discover_project_root`, `is_projectless`) keep
/// `find_project_root` and the trust keys as they were; `is_projectless` is read
/// only by the app server's auto-trust.
///
/// Codex rules files are Starlark programs. csec reads only the literal subset
/// Codex's own "always allow" writer produces and people write by hand: one
/// `prefix_rule(…)`, `host_executable(…)` or `network_rule(…)` call per
/// statement, with string and list literals. Any file outside that subset is
/// *opaque*: csec cannot tell whether it adds a `prompt` or `forbidden` rule,
/// so while it exists the Codex hook leaves every command to Codex. That only
/// ever costs output scanning; it never hides a Codex gate.
extension CodexCommandGate {
    public enum RulesParseError: Error, Equatable {
        case unsupported(line: Int)
    }

    /// Where Codex loads rules from, lowest precedence first: the System layer
    /// (`/etc/codex/rules`), the user layer (`$CODEX_HOME/rules`, default
    /// `~/.codex/rules`), and the `.codex/rules` of each directory from the
    /// project root down to the working directory that Codex trusts. Codex
    /// honours project rules only for trusted directories; honouring an
    /// untrusted clone's rules would let the clone choose commands for csec to
    /// leave unscanned. Requirements files that carry `prefix_rules` are opaque
    /// (their TOML is not read here).
    public static func loadPolicy(
        homeDirectory: String,
        codexHome: String? = nil,
        workingDirectory: String?,
        systemDirectory: String = "/etc/codex",
        includeManagedPreferences: Bool = true
    ) -> Policy {
        var policy = Policy()
        for directory in rulesDirectories(
            homeDirectory: homeDirectory, codexHome: codexHome,
            workingDirectory: workingDirectory, systemDirectory: systemDirectory) {
            for file in rulesFiles(in: directory) {
                guard let text = readText(file) else {
                    policy.opaqueSources.append(file)
                    continue
                }
                do {
                    policy.rules += try parseRules(text)
                } catch {
                    policy.opaqueSources.append(file)
                }
            }
        }
        for requirements in ["requirements.toml", "managed_config.toml"] {
            let path = (systemDirectory as NSString).appendingPathComponent(requirements)
            if let data = FileManager.default.contents(atPath: path),
               String(decoding: data, as: UTF8.self).contains("prefix_rules") {
                policy.opaqueSources.append(path)
            }
        }
        if includeManagedPreferences, managedRequirementsCarryRules() {
            policy.opaqueSources.append("managed preferences com.openai.codex requirements_toml_base64")
        }
        return policy
    }

    /// The `rules` directories Codex reads for a session in `workingDirectory`,
    /// lowest precedence first (Codex `load_exec_policy` over its config layers).
    public static func rulesDirectories(
        homeDirectory: String,
        codexHome: String? = nil,
        workingDirectory: String?,
        systemDirectory: String = "/etc/codex"
    ) -> [String] {
        let userDirectory = userCodexDirectory(homeDirectory: homeDirectory, codexHome: codexHome)
        var directories = [
            (systemDirectory as NSString).appendingPathComponent("rules"),
            (userDirectory as NSString).appendingPathComponent("rules"),
        ]
        guard let workingDirectory else { return directories }
        let cwd = URL(fileURLWithPath: workingDirectory).standardizedFileURL.path
        let trust = ProjectTrust(configurationFiles: [
            (systemDirectory as NSString).appendingPathComponent("config.toml"),
            (userDirectory as NSString).appendingPathComponent("config.toml"),
        ])
        let projectRoot = trust.projectRoot(for: cwd)
        let repositoryRoot = ProjectTrust.repositoryRootForTrust(cwd)
        let userCanonical = canonicalPath(userDirectory)
        // Codex considers the `.codex` directories from the project root down to
        // the working directory (config/src/loader/mod.rs `load_project_layers`).
        for directory in ancestors(of: cwd).reversed() where isWithin(directory, projectRoot) {
            let projectCodex = (directory as NSString).appendingPathComponent(".codex")
            var isDirectory: ObjCBool = false
            guard FileManager.default.fileExists(atPath: projectCodex, isDirectory: &isDirectory),
                  isDirectory.boolValue,
                  projectCodex != userDirectory, canonicalPath(projectCodex) != userCanonical,
                  trust.isTrusted(directory, projectRoot: projectRoot, repositoryRoot: repositoryRoot) else {
                continue
            }
            directories.append((projectCodex as NSString).appendingPathComponent("rules"))
        }
        return directories
    }

    static func userCodexDirectory(homeDirectory: String, codexHome: String?) -> String {
        codexHome.flatMap { $0.isEmpty ? nil : $0 }
            ?? (homeDirectory as NSString).appendingPathComponent(".codex")
    }

    static func isWithin(_ path: String, _ root: String) -> Bool {
        path == root || path.hasPrefix(root == "/" ? "/" : root + "/")
    }

    static func readText(_ path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path),
              data.count <= 1024 * 1024 else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Config files that set `hooks = false` under `[features]` (or a
    /// profile's `features`). Codex then keeps only its builtin hooks, so the
    /// managed csec hook does not run (hooks/src/engine/mod.rs). `-c` and
    /// `--disable hooks` on a Codex command line cannot be seen from here.
    public static func hooksDisabledSources(
        homeDirectory: String,
        codexHome: String? = nil,
        systemDirectory: String = "/etc/codex"
    ) -> [String] {
        let userDirectory = userCodexDirectory(homeDirectory: homeDirectory, codexHome: codexHome)
        return [
            (systemDirectory as NSString).appendingPathComponent("config.toml"),
            (userDirectory as NSString).appendingPathComponent("config.toml"),
        ].filter { path in
            guard let text = readText(path) else { return false }
            return TOMLLines(text).entries.contains { entry in
                let key = entry.table + entry.key
                if key.last == "hooks", key.dropLast().last == "features" {
                    return entry.value.hasPrefix("false")
                }
                if key.last == "features", entry.value.hasPrefix("{") {
                    return TOMLLines.inlineValue(entry.value, key: "hooks")?.hasPrefix("false") == true
                }
                return false
            }
        }
    }

    /// `*.rules` regular files (symlinks are skipped, as Codex skips them),
    /// sorted by path like Codex.
    static func rulesFiles(in directory: String) -> [String] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory) else { return [] }
        return names.filter { $0.hasSuffix(".rules") && $0 != ".rules" }.sorted().compactMap { name in
            let path = (directory as NSString).appendingPathComponent(name)
            var info = stat()
            guard lstat(path, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else { return nil }
            return path
        }
    }

    /// Forced MDM preferences can carry requirements rules for Codex.
    static func managedRequirementsCarryRules() -> Bool {
        let key = "requirements_toml_base64" as CFString
        let application = "com.openai.codex" as CFString
        guard CFPreferencesAppValueIsForced(key, application),
              let value = CFPreferencesCopyAppValue(key, application) as? String else { return false }
        guard let decoded = Data(base64Encoded: value) else { return true }
        return String(decoding: decoded, as: UTF8.self).contains("prefix_rules")
    }

    static func ancestors(of path: String) -> [String] {
        var result: [String] = []
        var directory = URL(fileURLWithPath: path).standardizedFileURL.path
        while directory.hasPrefix("/") {
            result.append(directory)
            if directory == "/" { break }
            directory = (directory as NSString).deletingLastPathComponent
        }
        return result
    }

    static func canonicalPath(_ path: String) -> String {
        URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath().path
    }

    // MARK: - Project trust

    /// Codex's project trust, from `[projects."<path>"] trust_level` in its
    /// System and user config (config/src/loader/mod.rs `decision_for_dir`): a
    /// directory's own entry, else its project root's, else its repository
    /// root's (a linked worktree's main checkout). The first entry found wins,
    /// `untrusted` included, and no entry means untrusted. A config this reader
    /// cannot interpret makes every directory count as trusted, which can only
    /// add rules and so only leave more commands to Codex.
    struct ProjectTrust {
        var levels: [String: String] = [:]
        var rootMarkers = [".git"]
        var unreadable = false

        init(configurationFiles: [String]) {
            for file in configurationFiles where FileManager.default.fileExists(atPath: file) {
                guard let text = readText(file) else {
                    unreadable = true
                    continue
                }
                let lines = TOMLLines(text)
                if lines.unreadable { unreadable = true }
                for entry in lines.entries {
                    let path = entry.table + entry.key
                    if path.count == 3, path[0] == "projects", path[2] == "trust_level" {
                        guard let level = TOMLLines.string(entry.value) else { unreadable = true; continue }
                        levels[path[1]] = level
                    } else if path.count == 2, path[0] == "projects" {
                        // `"<path>" = { trust_level = "…" }` under `[projects]`.
                        guard entry.value.hasPrefix("{"), entry.value.contains("}") else {
                            unreadable = true
                            continue
                        }
                        guard let raw = TOMLLines.inlineValue(entry.value, key: "trust_level") else { continue }
                        guard let level = TOMLLines.string(raw) else { unreadable = true; continue }
                        levels[path[1]] = level
                    } else if path == ["projects"] {
                        unreadable = true
                    } else if path == ["project_root_markers"] {
                        guard let markers = TOMLLines.stringArray(entry.value) else { unreadable = true; continue }
                        rootMarkers = markers
                    }
                }
            }
        }

        /// The nearest ancestor with a root marker (`.git` counts only as a
        /// file or as a directory containing `HEAD`), else `cwd`.
        func projectRoot(for cwd: String) -> String {
            guard !rootMarkers.isEmpty else { return cwd }
            for ancestor in ancestors(of: cwd) {
                for marker in rootMarkers {
                    let markerPath = (ancestor as NSString).appendingPathComponent(marker)
                    var isDirectory: ObjCBool = false
                    guard FileManager.default.fileExists(atPath: markerPath, isDirectory: &isDirectory) else {
                        continue
                    }
                    if marker == ".git", isDirectory.boolValue,
                       !FileManager.default.fileExists(
                           atPath: (markerPath as NSString).appendingPathComponent("HEAD")) {
                        continue
                    }
                    return ancestor
                }
            }
            return cwd
        }

        func isTrusted(_ directory: String, projectRoot: String, repositoryRoot: String?) -> Bool {
            if unreadable { return true }
            let candidates = Self.keys(directory) + Self.keys(projectRoot)
                + (repositoryRoot.map(Self.keys) ?? [])
            for key in candidates {
                if let level = levels[key] { return level == "trusted" }
            }
            return false
        }

        /// Canonical spelling first, then the literal one (Codex
        /// `normalized_project_trust_keys`).
        static func keys(_ path: String) -> [String] {
            let literal = URL(fileURLWithPath: path).standardizedFileURL.path
            let canonical = canonicalPath(path)
            return canonical == literal ? [canonical] : [canonical, literal]
        }

        /// The git checkout containing `cwd`, or for a linked worktree its main
        /// checkout (`.git` file → gitdir `<main>/.git/worktrees/<name>`).
        static func repositoryRootForTrust(_ cwd: String) -> String? {
            for candidate in ancestors(of: cwd) {
                let gitPath = (candidate as NSString).appendingPathComponent(".git")
                var isDirectory: ObjCBool = false
                guard FileManager.default.fileExists(atPath: gitPath, isDirectory: &isDirectory) else { continue }
                if isDirectory.boolValue {
                    guard FileManager.default.fileExists(
                        atPath: (gitPath as NSString).appendingPathComponent("HEAD")) else { continue }
                    return candidate
                }
                guard let contents = try? String(contentsOfFile: gitPath, encoding: .utf8),
                      let line = contents.split(separator: "\n").first(where: { $0.hasPrefix("gitdir:") }) else {
                    return candidate
                }
                var gitdir = line.dropFirst("gitdir:".count).trimmingCharacters(in: .whitespaces)
                if !gitdir.hasPrefix("/") { gitdir = (candidate as NSString).appendingPathComponent(gitdir) }
                let components = URL(fileURLWithPath: gitdir).standardizedFileURL.pathComponents
                if let index = components.lastIndex(of: "worktrees"), index >= 1, components[index - 1] == ".git" {
                    return NSString.path(withComponents: Array(components[..<(index - 1)]))
                }
                return candidate
            }
            return nil
        }
    }

    /// Just enough TOML to read Codex's `projects`, `project_root_markers` and
    /// `features` settings: `[table]` headers and one-line `key = value`
    /// entries with bare, quoted or dotted keys. A line it cannot split sets
    /// `unreadable` when it could hold one of those settings.
    struct TOMLLines {
        struct Entry {
            let table: [String]
            let key: [String]
            let value: String
        }

        static let tripleQuotes = [String(repeating: "\"", count: 3), String(repeating: "'", count: 3)]
        var entries: [Entry] = []
        var unreadable = false

        init(_ text: String) {
            var table: [String] = []
            var openMultiline: String?
            for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
                let line = rawLine.trimmingCharacters(in: .whitespaces)
                if let delimiter = openMultiline {
                    if line.contains(delimiter) { openMultiline = nil }
                    continue
                }
                if line.isEmpty || line.hasPrefix("#") { continue }
                let interesting = line.contains("projects") || line.contains("features")
                    || line.contains("project_root_markers") || line.contains("hooks")
                if line.hasPrefix("[") {
                    let inner = line.hasPrefix("[[") ? line.dropFirst(2) : line.dropFirst()
                    guard let close = Self.closingBracket(in: inner),
                          let parsed = Self.keyPath(String(inner[..<close])) else {
                        if interesting { unreadable = true }
                        table = []
                        continue
                    }
                    table = parsed
                    continue
                }
                guard let (keyText, value) = Self.splitAssignment(line), let key = Self.keyPath(keyText) else {
                    if interesting { unreadable = true }
                    continue
                }
                for delimiter in Self.tripleQuotes where value.hasPrefix(delimiter)
                    && !value.dropFirst(3).contains(delimiter) {
                    openMultiline = delimiter
                }
                if (value.hasPrefix("{") && !value.contains("}")) || (value.hasPrefix("[") && !value.contains("]")),
                   interesting || (table + key).contains(where: { $0 == "projects" || $0 == "features" }) {
                    unreadable = true
                }
                entries.append(Entry(table: table, key: key, value: value))
            }
        }

        /// The `]` closing a table header, skipping any inside quoted keys.
        static func closingBracket(in text: Substring) -> Substring.Index? {
            var quote: Character?
            var escaped = false
            for index in text.indices {
                let character = text[index]
                if let open = quote {
                    if open == "\"", character == "\\", !escaped { escaped = true; continue }
                    if character == open, !escaped { quote = nil }
                    escaped = false
                } else if character == "\"" || character == "'" {
                    quote = character
                } else if character == "]" {
                    return index
                }
            }
            return nil
        }

        /// `a.b."c.d"` → ["a", "b", "c.d"].
        static func keyPath(_ text: String) -> [String]? {
            var parts: [String] = []
            var rest = Substring(text.trimmingCharacters(in: .whitespaces))
            while !rest.isEmpty {
                if let quote = rest.first, quote == "\"" || quote == "'" {
                    var index = rest.index(after: rest.startIndex)
                    var escaped = false
                    while index < rest.endIndex {
                        let character = rest[index]
                        if quote == "\"", character == "\\", !escaped {
                            escaped = true
                        } else if character == quote, !escaped {
                            break
                        } else {
                            escaped = false
                        }
                        index = rest.index(after: index)
                    }
                    guard index < rest.endIndex, let key = string(String(rest[...index])) else { return nil }
                    parts.append(key)
                    rest = rest[rest.index(after: index)...]
                } else {
                    let end = rest.firstIndex(where: { $0 == "." || $0 == " " || $0 == "\t" }) ?? rest.endIndex
                    let bare = rest[..<end]
                    guard !bare.isEmpty,
                          bare.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" }) else {
                        return nil
                    }
                    parts.append(String(bare))
                    rest = rest[end...]
                }
                rest = rest.drop(while: { $0 == " " || $0 == "\t" })
                if rest.hasPrefix(".") {
                    rest = rest.dropFirst().drop(while: { $0 == " " || $0 == "\t" })
                    if rest.isEmpty { return nil }
                } else if !rest.isEmpty {
                    return nil
                }
            }
            return parts.isEmpty ? nil : parts
        }

        /// Split at the first `=` outside a quoted key.
        static func splitAssignment(_ line: String) -> (String, String)? {
            var quote: Character?
            for index in line.indices {
                let character = line[index]
                if let open = quote {
                    if character == open { quote = nil }
                } else if character == "\"" || character == "'" {
                    quote = character
                } else if character == "=" {
                    let value = line[line.index(after: index)...].trimmingCharacters(in: .whitespaces)
                    return (String(line[..<index]), value)
                }
            }
            return nil
        }

        /// A basic (`"…"`, JSON escapes) or literal (`'…'`) string at the start
        /// of `value`; anything after it (a comment) is ignored.
        static func string(_ value: String) -> String? {
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("'") {
                let body = trimmed.dropFirst()
                guard let close = body.firstIndex(of: "'") else { return nil }
                return String(body[..<close])
            }
            guard trimmed.hasPrefix("\"") else { return nil }
            var index = trimmed.index(after: trimmed.startIndex)
            var escaped = false
            while index < trimmed.endIndex {
                let character = trimmed[index]
                if character == "\\", !escaped {
                    escaped = true
                } else if character == "\"", !escaped {
                    break
                } else {
                    escaped = false
                }
                index = trimmed.index(after: index)
            }
            guard index < trimmed.endIndex else { return nil }
            let literal = String(trimmed[...index])
            return (try? JSONSerialization.jsonObject(with: Data(literal.utf8), options: .fragmentsAllowed)) as? String
        }

        /// The raw value of `key` in a one-line inline table `{ a = 1, key = … }`.
        static func inlineValue(_ value: String, key: String) -> String? {
            guard let open = value.firstIndex(of: "{"), let close = value.lastIndex(of: "}"), open < close else {
                return nil
            }
            for part in value[value.index(after: open)..<close].split(separator: ",") {
                guard let (entryKey, entryValue) = splitAssignment(String(part)),
                      keyPath(entryKey) == [key] else { continue }
                return entryValue
            }
            return nil
        }

        static func stringArray(_ value: String) -> [String]? {
            let trimmed = value.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("["), let close = trimmed.lastIndex(of: "]") else { return nil }
            let body = trimmed[trimmed.index(after: trimmed.startIndex)..<close]
            var result: [String] = []
            for item in body.split(separator: ",") {
                let text = item.trimmingCharacters(in: .whitespaces)
                if text.isEmpty { continue }
                guard let string = string(text) else { return nil }
                result.append(string)
            }
            return result
        }
    }

    // MARK: - Rules file subset

    /// Parse a rules file in the literal subset. Throws on anything else.
    public static func parseRules(_ text: String) throws -> [PrefixRule] {
        var parser = RulesParser(Array(text.unicodeScalars))
        return try parser.file()
    }

    private enum Value {
        case string(String)
        case list([Value])
    }

    private struct RulesParser {
        let scalars: [Unicode.Scalar]
        var index = 0
        var line = 1

        init(_ scalars: [Unicode.Scalar]) { self.scalars = scalars }

        var failure: RulesParseError { .unsupported(line: line) }

        mutating func file() throws -> [PrefixRule] {
            var rules: [PrefixRule] = []
            while true {
                skipBlank(newlines: true)
                guard index < scalars.count else { return rules }
                let name = try identifier()
                skipBlank(newlines: false)
                try expect("(")
                let arguments = try callArguments()
                switch name {
                case "prefix_rule": rules += try prefixRule(arguments)
                case "host_executable": try hostExecutable(arguments)
                case "network_rule": try networkRule(arguments)
                default: throw failure
                }
                // One statement per line or `;`.
                skipBlank(newlines: false)
                guard index >= scalars.count || scalars[index] == "\n" || scalars[index] == ";" else {
                    throw failure
                }
                if index < scalars.count, scalars[index] == ";" { index += 1 }
            }
        }

        private func bind(
            _ arguments: [(name: String?, value: Value)],
            to parameters: [String]
        ) throws -> [String: Value] {
            var bound: [String: Value] = [:]
            var position = 0
            var sawKeyword = false
            for argument in arguments {
                let name: String
                if let keyword = argument.name {
                    sawKeyword = true
                    name = keyword
                } else {
                    guard !sawKeyword, position < parameters.count else { throw failure }
                    name = parameters[position]
                    position += 1
                }
                guard parameters.contains(name), bound[name] == nil else { throw failure }
                bound[name] = argument.value
            }
            return bound
        }

        private func strings(_ value: Value?) -> [String]? {
            guard case let .list(items) = value else { return nil }
            var result: [String] = []
            for item in items {
                guard case let .string(string) = item else { return nil }
                result.append(string)
            }
            return result
        }

        private func prefixRule(_ arguments: [(name: String?, value: Value)]) throws -> [PrefixRule] {
            let bound = try bind(arguments, to: ["pattern", "decision", "match", "not_match", "justification"])
            guard case let .list(items)? = bound["pattern"], !items.isEmpty else { throw failure }
            var pattern: [[String]] = []
            for item in items {
                switch item {
                case let .string(token): pattern.append([token])
                case .list:
                    guard let alternatives = strings(item), !alternatives.isEmpty else { throw failure }
                    pattern.append(alternatives)
                }
            }
            var decision = Decision.allow
            if let value = bound["decision"] {
                guard case let .string(text) = value, let parsed = Decision(rawValue: text) else { throw failure }
                decision = parsed
            }
            if let value = bound["justification"] {
                guard case let .string(text) = value,
                      !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw failure }
            }
            for key in ["match", "not_match"] {
                guard let value = bound[key] else { continue }
                guard case let .list(examples) = value else { throw failure }
                for example in examples {
                    if case .list = example, strings(example) == nil { throw failure }
                }
            }
            return [PrefixRule(pattern: pattern, decision: decision)]
        }

        private func hostExecutable(_ arguments: [(name: String?, value: Value)]) throws {
            let bound = try bind(arguments, to: ["name", "paths"])
            guard case let .string(name)? = bound["name"], !name.isEmpty, !name.contains("/"),
                  let paths = strings(bound["paths"]),
                  paths.allSatisfy({ $0.hasPrefix("/") && ($0 as NSString).lastPathComponent == name }) else {
                throw failure
            }
        }

        private func networkRule(_ arguments: [(name: String?, value: Value)]) throws {
            let bound = try bind(arguments, to: ["host", "protocol", "decision", "justification"])
            guard case .string? = bound["host"], case .string? = bound["protocol"],
                  case .string? = bound["decision"] else { throw failure }
        }

        private mutating func callArguments() throws -> [(name: String?, value: Value)] {
            var arguments: [(name: String?, value: Value)] = []
            while true {
                skipBlank(newlines: true)
                guard index < scalars.count else { throw failure }
                if scalars[index] == ")" { index += 1; return arguments }
                var name: String?
                if isIdentifierStart(scalars[index]) {
                    name = try identifier()
                    skipBlank(newlines: true)
                    try expect("=")
                    skipBlank(newlines: true)
                }
                arguments.append((name, try value(depth: 0)))
                skipBlank(newlines: true)
                guard index < scalars.count else { throw failure }
                if scalars[index] == "," { index += 1; continue }
                guard scalars[index] == ")" else { throw failure }
            }
        }

        private mutating func value(depth: Int) throws -> Value {
            guard index < scalars.count else { throw failure }
            if scalars[index] == "\"" || scalars[index] == "'" { return .string(try string()) }
            guard scalars[index] == "[", depth < 2 else { throw failure }
            index += 1
            var items: [Value] = []
            while true {
                skipBlank(newlines: true)
                guard index < scalars.count else { throw failure }
                if scalars[index] == "]" { index += 1; return .list(items) }
                items.append(try value(depth: depth + 1))
                skipBlank(newlines: true)
                guard index < scalars.count else { throw failure }
                if scalars[index] == "," { index += 1; continue }
                guard scalars[index] == "]" else { throw failure }
            }
        }

        /// `"…"` or `'…'` on one line, with the escapes Codex's writer uses.
        private mutating func string() throws -> String {
            let quote = scalars[index]
            // Triple-quoted strings are outside the subset.
            if index + 2 < scalars.count, scalars[index + 1] == quote, scalars[index + 2] == quote {
                throw failure
            }
            index += 1
            var result = String.UnicodeScalarView()
            while index < scalars.count {
                let scalar = scalars[index]
                index += 1
                if scalar == quote { return String(result) }
                if scalar == "\n" { throw failure }
                guard scalar == "\\" else { result.append(scalar); continue }
                guard index < scalars.count else { throw failure }
                let escaped = scalars[index]
                index += 1
                switch escaped {
                case "\\", "\"", "'": result.append(escaped)
                case "n": result.append("\n")
                case "t": result.append("\t")
                case "r": result.append("\r")
                case "b": result.append("\u{08}")
                case "f": result.append("\u{0C}")
                case "u":
                    guard index + 4 <= scalars.count,
                          let code = UInt32(String(String.UnicodeScalarView(scalars[index..<index + 4])), radix: 16),
                          let decoded = Unicode.Scalar(code) else { throw failure }
                    result.append(decoded)
                    index += 4
                default:
                    throw failure
                }
            }
            throw failure
        }

        private mutating func identifier() throws -> String {
            guard index < scalars.count, isIdentifierStart(scalars[index]) else { throw failure }
            var result = String.UnicodeScalarView()
            while index < scalars.count,
                  isIdentifierStart(scalars[index]) || ("0"..."9").contains(scalars[index]) {
                result.append(scalars[index])
                index += 1
            }
            return String(result)
        }

        private func isIdentifierStart(_ scalar: Unicode.Scalar) -> Bool {
            scalar == "_" || ("a"..."z").contains(scalar) || ("A"..."Z").contains(scalar)
        }

        private mutating func expect(_ scalar: Unicode.Scalar) throws {
            guard index < scalars.count, scalars[index] == scalar else { throw failure }
            index += 1
        }

        /// Spaces, tabs, carriage returns and `#` comments; newlines too when
        /// asked (inside brackets and between statements).
        private mutating func skipBlank(newlines: Bool) {
            while index < scalars.count {
                let scalar = scalars[index]
                if scalar == " " || scalar == "\t" || scalar == "\r" {
                    index += 1
                } else if scalar == "\n", newlines {
                    line += 1
                    index += 1
                } else if scalar == "#" {
                    while index < scalars.count, scalars[index] != "\n" { index += 1 }
                } else {
                    return
                }
            }
        }
    }
}
