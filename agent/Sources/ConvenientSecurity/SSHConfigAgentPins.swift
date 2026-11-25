import Darwin
import Foundation

/// A private-key file the user's ssh config pins to an agent other than csec's.
///
/// `ssh` asks only the agent `IdentityAgent` names, so a key named by
/// `IdentityFile` in a block with `IdentityAgent none` (or another agent's
/// socket) works only while the file itself exists. Moving that key into csec's
/// agent would break the host; protect leaves it in place and says why.
public struct SSHConfigAgentPin: Equatable, Sendable {
    public enum Agent: Equatable, Sendable {
        /// `IdentityAgent none`: no agent at all.
        case none
        /// A socket path or variable other than csec's socket and `SSH_AUTH_SOCK`.
        case other
    }

    /// The `IdentityFile` path with `~`, `%d` and `${HOME}` expanded.
    public let keyPath: String
    public let agent: Agent
    /// The config file and line of the `IdentityFile` directive.
    public let configPath: String
    public let line: Int

    public init(keyPath: String, agent: Agent, configPath: String, line: Int) {
        self.keyPath = keyPath
        self.agent = agent
        self.configPath = configPath
        self.line = line
    }

    /// Value-free, home-relative: `IdentityAgent none at ~/.ssh/config:12`.
    public func describe(homeDirectory: String) -> String {
        let agentText = agent == .none ? "IdentityAgent none" : "an IdentityAgent other than csec's"
        var path = configPath
        if path.hasPrefix(homeDirectory + "/") {
            path = "~" + path.dropFirst(homeDirectory.count)
        }
        return "\(agentText) at \(path):\(line)"
    }
}

/// Reads `~/.ssh/config` (following `Include`) for keys pinned away from
/// csec's agent. It models what decides the agent for a key: `ssh` takes the
/// first `IdentityAgent` it reads, so a block's own value applies unless the
/// top of the file or an earlier `Host *` set one first, and a later `Host *`
/// supplies it when the block sets none. Other `Host`/`Match` blocks may
/// apply to some hosts too; they are not guessed at.
public enum SSHConfigAgentPins {
    private struct Directive {
        let keyword: String
        let arguments: [String]
        let file: String
        let line: Int
    }

    private struct Section {
        /// Applies to every host: the top of the file, or `Host *`.
        let isUniversal: Bool
        var directives: [Directive] = []
    }

    /// `readText` returns a file's text (nil when absent); `directoryEntries`
    /// lists a directory for an `Include` glob.
    public static func scan(
        homeDirectory: String,
        csecSocketPath: String,
        readText: (String) -> String?,
        directoryEntries: (String) -> [String]
    ) -> [SSHConfigAgentPin] {
        let configPath = homeDirectory + "/.ssh/config"
        guard let text = readText(configPath) else { return [] }
        var sections = [Section(isUniversal: true)]
        parse(text, file: configPath, depth: 0, homeDirectory: homeDirectory,
              readText: readText, directoryEntries: directoryEntries, into: &sections)

        var pins: [SSHConfigAgentPin] = []
        for (index, section) in sections.enumerated() {
            let identityFiles = section.directives.filter { $0.keyword == "identityfile" }
            guard !identityFiles.isEmpty else { continue }
            let applicable = sections.enumerated()
                .filter { $0.offset == index || $0.element.isUniversal }
                .map(\.element)
            let agentDirective = applicable.lazy
                .flatMap(\.directives)
                .first { $0.keyword == "identityagent" && !$0.arguments.isEmpty }
            guard let agentDirective,
                  let agent = classify(agentDirective.arguments[0],
                                       homeDirectory: homeDirectory,
                                       csecSocketPath: csecSocketPath) else { continue }
            for directive in identityFiles {
                guard let argument = directive.arguments.first,
                      let path = expand(argument, homeDirectory: homeDirectory) else { continue }
                pins.append(SSHConfigAgentPin(
                    keyPath: path, agent: agent, configPath: directive.file, line: directive.line))
            }
        }
        return pins
    }

    /// The real files under `homeDirectory`, for the CLI.
    public static func scanLocal(homeDirectory: String) -> [SSHConfigAgentPin] {
        scan(
            homeDirectory: homeDirectory,
            csecSocketPath: SSHAgentSocket.defaultPath(),
            readText: { path in
                guard let data = FileManager.default.contents(atPath: path),
                      data.count <= 1_048_576 else { return nil }
                return String(data: data, encoding: .utf8)
            },
            directoryEntries: { (try? FileManager.default.contentsOfDirectory(atPath: $0)) ?? [] }
        )
    }

    private static func parse(
        _ text: String,
        file: String,
        depth: Int,
        homeDirectory: String,
        readText: (String) -> String?,
        directoryEntries: (String) -> [String],
        into sections: inout [Section]
    ) {
        // OpenSSH stops at 16 levels of Include.
        guard depth <= 16 else { return }
        for (offset, rawLine) in text.components(separatedBy: "\n").enumerated() {
            guard let (keyword, arguments) = tokenize(rawLine) else { continue }
            switch keyword {
            case "host":
                sections.append(Section(isUniversal: arguments == ["*"]))
            case "match":
                sections.append(Section(isUniversal: arguments.map { $0.lowercased() } == ["all"]))
            case "include":
                for argument in arguments {
                    for path in includePaths(argument, homeDirectory: homeDirectory,
                                             directoryEntries: directoryEntries) {
                        guard let included = readText(path) else { continue }
                        parse(included, file: path, depth: depth + 1, homeDirectory: homeDirectory,
                              readText: readText, directoryEntries: directoryEntries, into: &sections)
                    }
                }
            default:
                sections[sections.count - 1].directives.append(
                    Directive(keyword: keyword, arguments: arguments, file: file, line: offset + 1))
            }
        }
    }

    /// `Keyword args…` or `Keyword=args…`, lowercased keyword, double quotes
    /// grouping an argument. Nil for blank and comment lines.
    private static func tokenize(_ rawLine: String) -> (String, [String])? {
        var line = Substring(rawLine.trimmingCharacters(in: .whitespacesAndNewlines))
        guard !line.isEmpty, !line.hasPrefix("#") else { return nil }
        let keywordEnd = line.firstIndex { $0 == " " || $0 == "\t" || $0 == "=" } ?? line.endIndex
        let keyword = line[..<keywordEnd].lowercased()
        line = line[keywordEnd...].drop { $0 == " " || $0 == "\t" }
        if line.first == "=" { line = line.dropFirst().drop { $0 == " " || $0 == "\t" } }

        var arguments: [String] = []
        var current = ""
        var inQuotes = false
        var hasToken = false
        for character in line {
            if character == "\"" {
                inQuotes.toggle()
                hasToken = true
            } else if (character == " " || character == "\t") && !inQuotes {
                if hasToken { arguments.append(current) }
                current = ""
                hasToken = false
            } else if character == "#" && !inQuotes && !hasToken {
                break
            } else {
                current.append(character)
                hasToken = true
            }
        }
        if hasToken { arguments.append(current) }
        return (keyword, arguments)
    }

    /// Nil when the agent is csec's own (by socket path or `SSH_AUTH_SOCK`,
    /// which csec's setup points at its socket).
    private static func classify(
        _ value: String,
        homeDirectory: String,
        csecSocketPath: String
    ) -> SSHConfigAgentPin.Agent? {
        if value.lowercased() == "none" { return SSHConfigAgentPin.Agent.none }
        if ["SSH_AUTH_SOCK", "$SSH_AUTH_SOCK", "${SSH_AUTH_SOCK}"].contains(value) { return nil }
        if let path = expand(value, homeDirectory: homeDirectory),
           standardized(path) == standardized(csecSocketPath) {
            return nil
        }
        return .other
    }

    /// Absolute path for `~/…`, `%d/…`, `${HOME}/…` or an absolute path; nil
    /// for anything that depends on the host or the working directory.
    private static func expand(_ value: String, homeDirectory: String) -> String? {
        var path = value
        for prefix in ["~/", "%d/", "${HOME}/"] where path.hasPrefix(prefix) {
            path = homeDirectory + "/" + path.dropFirst(prefix.count)
            break
        }
        guard path.hasPrefix("/"), !path.contains("%"), !path.contains("${") else { return nil }
        return standardized(path)
    }

    private static func standardized(_ path: String) -> String {
        (path as NSString).standardizingPath
    }

    /// An `Include` argument: relative paths are under `~/.ssh`, and a glob
    /// in the last component matches that directory's entries, sorted as
    /// OpenSSH's glob(3) returns them.
    private static func includePaths(
        _ argument: String,
        homeDirectory: String,
        directoryEntries: (String) -> [String]
    ) -> [String] {
        var path = argument
        if path.hasPrefix("~/") {
            path = homeDirectory + "/" + path.dropFirst(2)
        } else if !path.hasPrefix("/") {
            path = homeDirectory + "/.ssh/" + path
        }
        let directory = (path as NSString).deletingLastPathComponent
        let pattern = (path as NSString).lastPathComponent
        guard !directory.contains(where: { "*?[".contains($0) }) else { return [] }
        guard pattern.contains(where: { "*?[".contains($0) }) else { return [path] }
        return directoryEntries(directory)
            .filter { !$0.hasPrefix(".") && fnmatch(pattern, $0, 0) == 0 }
            .sorted()
            .map { directory + "/" + $0 }
    }
}
