import Foundation

/// A value-free error: never interpolate an npmrc line or credential value.
public enum NpmUserConfigError: Error, LocalizedError, Equatable {
    case notText
    case authInsideSection
    case noAuthLines
    case tooLarge

    public var errorDescription: String? {
        switch self {
        case .notText:
            return "npm config is not UTF-8 text without NUL bytes; it was left untouched"
        case .authInsideSection:
            return "npm config has an auth line inside an [ini] section, which npm does not read; it was left untouched"
        case .noAuthLines:
            return "npm config holds no literal auth lines; nothing to protect"
        case .tooLarge:
            return "npm config is larger than the inherited-file limit"
        }
    }
}

/// npm's userconfig (`~/.npmrc`) mixes registry credentials with settings that
/// make plain `npm`, `pnpm` and `yarn` safer (`min-release-age`,
/// `ignore-scripts`, `registry`). Protecting it whole would delete those
/// settings for every unwrapped run, so csec splits it: the literal auth lines
/// go to a store as one value, every other line stays where it is, and
/// `csec exec-fd --preset npm=<ref>` streams the live file with the auth lines
/// put back on the private pipe.
public enum NpmUserConfig {
    /// npm's auth properties. A nerf-darted key (`//host/path/:_authToken`)
    /// ends in one of these after its last `:`.
    static let authProperties: Set<String> = ["_authtoken", "_auth", "_password"]

    /// Whether one npmrc line assigns a literal credential. Comments, empty
    /// values and whole-value `${ENV}` placeholders (npm substitutes those from
    /// the environment, so the file holds no secret) are not credentials. The
    /// discovery content gate and the splitter share this so a file csec has
    /// split is never rediscovered as plaintext.
    public static func isLiteralAuthLine<Line: StringProtocol>(_ line: Line) -> Bool {
        authValue(line) != nil
    }

    /// Whether a config holds any literal credential line.
    public static func containsLiteralAuth(_ data: Data) -> Bool {
        lines(String(decoding: data, as: UTF8.self)).contains(where: isLiteralAuthLine)
    }

    /// The literal credential a line assigns, unquoted, or nil.
    static func authValue<Line: StringProtocol>(_ line: Line) -> String? {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.hasPrefix("#"), !trimmed.hasPrefix(";"),
              let equals = trimmed.firstIndex(of: "=") else { return nil }
        let key = trimmed[..<equals].trimmingCharacters(in: .whitespaces).lowercased()
        let property = key.split(separator: ":").last.map(String.init) ?? key
        guard authProperties.contains(property) else { return nil }
        var value = trimmed[trimmed.index(after: equals)...].trimmingCharacters(in: .whitespaces)
        if value.count >= 2, let first = value.first, first == "\"" || first == "'", value.last == first {
            value = String(value.dropFirst().dropLast())
        }
        guard !value.isEmpty else { return nil }
        if value.hasPrefix("${"), value.hasSuffix("}"),
           SecretHeuristics.isEnvironmentName(String(value.dropFirst(2).dropLast())) {
            return nil
        }
        return value
    }

    static func isSectionHeader(_ line: String) -> Bool {
        line.trimmingCharacters(in: .whitespacesAndNewlines).hasPrefix("[")
    }

    /// Lines including their terminators, so rewriting keeps every byte of
    /// the lines it does not move. Split on the LF scalar: Swift reads CRLF as
    /// one Character, which a Character-level split never breaks.
    static func lines(_ text: String) -> [String] {
        var result: [String] = []
        var current = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            current.append(scalar)
            if scalar == "\n" {
                result.append(String(current))
                current = String.UnicodeScalarView()
            }
        }
        if !current.isEmpty { result.append(String(current)) }
        return result
    }

    static func endsWithNewline(_ text: String) -> Bool {
        text.unicodeScalars.last.map { $0 == "\n" } ?? true
    }

    static func text(_ data: Data) throws -> String {
        guard !data.contains(0), let text = String(data: data, encoding: .utf8) else {
            throw NpmUserConfigError.notText
        }
        return text
    }

    public struct Split: Equatable, Sendable {
        /// The auth lines, each newline-terminated, in file order: the value
        /// to store.
        public let authLines: String
        public let authLineCount: Int
        /// Everything else, byte for byte, without the marker.
        let keptLines: [String]
        /// Where the first auth line was, for the marker.
        let markerIndex: Int

        /// The file to write back: the kept lines, with a value-free comment
        /// naming the reference where the first auth line was, so whoever reads
        /// `~/.npmrc` later knows where its token went and how to use it.
        public func rewritten(reference: String) -> Data {
            let marker = "; csec: auth lines moved to \(reference); "
                + "use them with: csec exec-fd --preset npm=\(reference) -- npm <command>\n"
            var output = ""
            for (index, line) in keptLines.enumerated() {
                if index == markerIndex { output += marker }
                output += line
            }
            if markerIndex >= keptLines.count {
                if !NpmUserConfig.endsWithNewline(output) { output += "\n" }
                output += marker
            }
            return Data(output.utf8)
        }
    }

    /// Separate the literal auth lines from everything else. An auth line
    /// inside an `[ini]` section is refused rather than moved: npm reads auth
    /// only at the top level, and the merge puts the stored lines back there,
    /// so moving it would change what npm sees.
    public static func split(_ data: Data) throws -> Split {
        let all = lines(try text(data))
        var kept: [String] = []
        var auth = ""
        var count = 0
        var markerIndex: Int?
        var inSection = false
        for line in all {
            if isSectionHeader(line) { inSection = true }
            guard isLiteralAuthLine(line) else {
                kept.append(line)
                continue
            }
            guard !inSection else { throw NpmUserConfigError.authInsideSection }
            if markerIndex == nil { markerIndex = kept.count }
            auth += endsWithNewline(line) ? line : line + "\n"
            count += 1
        }
        guard count > 0, let markerIndex else { throw NpmUserConfigError.noAuthLines }
        return Split(authLines: auth, authLineCount: count, keptLines: kept, markerIndex: markerIndex)
    }

    /// The userconfig `exec-fd --preset npm` streams: the live file with the
    /// stored auth lines inserted at its top level, after every top-level line
    /// (so they win over any stale duplicate there) and before its first
    /// `[section]` (where npm would not read them). A missing live file is
    /// empty, so a value stored whole by an earlier csec still works alone.
    public static func merged(liveConfig: Data?, authLines: Data) throws -> Data {
        let base = try liveConfig.map(text) ?? ""
        let auth = try text(authLines)
        var output = ""
        var inserted = false
        func insertAuth() {
            if !endsWithNewline(output) { output += "\n" }
            output += auth
            if !endsWithNewline(output) { output += "\n" }
            inserted = true
        }
        for line in lines(base) {
            if !inserted, isSectionHeader(line) { insertAuth() }
            output += line
        }
        if !inserted { insertAuth() }
        let data = Data(output.utf8)
        guard data.count <= InheritedFilePreset.maximumFileBytes else {
            throw NpmUserConfigError.tooLarge
        }
        return data
    }

    /// Whether a live userconfig can be merged at all, checked before the
    /// access request so an unusable file fails before any panel appears.
    public static func validateLiveConfig(_ data: Data) throws {
        _ = try text(data)
        guard data.count < InheritedFilePreset.maximumFileBytes else {
            throw NpmUserConfigError.tooLarge
        }
    }

    /// The credentials in a stored auth fragment, so output masking can catch
    /// a token printed on its own, not only the whole multi-line value.
    public static func credentialValues(in authLines: Data) -> [String] {
        guard let text = try? text(authLines) else { return [] }
        return lines(text).compactMap(authValue)
    }

    /// Which userconfig npm would read: its override variable (any case, as
    /// npm matches `npm_config_*` case-insensitively), unless it already names
    /// a descriptor from an enclosing `exec-fd`, which reading would drain;
    /// otherwise `~/.npmrc`.
    public static func liveConfigPath(environment: [String: String], homeDirectory: String) -> String {
        let candidates = environment
            .filter { $0.key.lowercased() == "npm_config_userconfig" }
            .sorted { lhs, rhs in
                // The canonical upper-case spelling first, then a stable order.
                (lhs.key == "NPM_CONFIG_USERCONFIG" ? 0 : 1, lhs.key)
                    < (rhs.key == "NPM_CONFIG_USERCONFIG" ? 0 : 1, rhs.key)
            }
        if let path = candidates.first?.value, !path.isEmpty, !path.hasPrefix("/dev/") {
            return path
        }
        return (homeDirectory as NSString).appendingPathComponent(".npmrc")
    }
}
