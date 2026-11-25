import Foundation

/// The Fly.io CLI's token handling, as flyctl's source has it (superfly/flyctl
/// `internal/config`). flyctl keeps its token in `config.yml`'s `access_token`
/// and rewrites that file during ordinary commands (token refreshes, org
/// tokens, WireGuard peers, secrets versions), each time by renaming a new
/// file over it, so the file cannot be protected whole. With `FLY_API_TOKEN`
/// set, flyctl uses that token instead, keeps what it refreshes in memory and
/// never writes a token back; it also uses it as the metrics token, so a
/// blanked `metrics_token` is never fetched again. csec therefore takes the
/// token out of the file and hands it to fly in its environment.
public enum FlyCLI {
    /// The variable `csec fly` delivers the token in. flyctl reads
    /// `FLY_ACCESS_TOKEN` first, then this.
    public static let tokenVariable = "FLY_API_TOKEN"
    public static let tokenVariables = ["FLY_ACCESS_TOKEN", "FLY_API_TOKEN"]
    /// Makes fly run its WireGuard agent as a child that exits with the
    /// command. The shared daemon agent fly otherwise starts keeps the token
    /// in its environment and serves it on `fly-agent.sock` after the command
    /// (and its grant's process) is gone.
    public static let isolatedAgentVariable = "FLY_AGENT_ISOLATED"
    public static let defaultStore = "fly"
    public static let defaultKey = "FLY_API_TOKEN"
    public static let registrationFileName = "csec.json"
    public static let reason = "Fly.io sign-in"

    /// flyctl's config directory: `FLY_CONFIG_DIR`, else `~/.fly`
    /// (`helpers.GetConfigDirectory`).
    public static func configDirectory(environment: [String: String], homeDirectory: String) -> String {
        if let configured = environment["FLY_CONFIG_DIR"], !configured.isEmpty {
            return (configured as NSString).expandingTildeInPath
        }
        return (homeDirectory as NSString).appendingPathComponent(".fly")
    }

    public static func configPath(configDirectory: String) -> String {
        (configDirectory as NSString).appendingPathComponent("config.yml")
    }

    public static func registrationPath(configDirectory: String) -> String {
        (configDirectory as NSString).appendingPathComponent(registrationFileName)
    }

    /// The fly commands `csec fly` handles itself rather than running with
    /// the registered token.
    public enum AuthAction: Equatable, Sendable {
        /// `auth login` / `auth signup`: fly saves a new token in the file,
        /// which csec then takes back out.
        case login
        /// `auth logout`: fly clears its file; csec forgets the registration.
        case logout
    }

    /// Reads the first two words of fly's command line. A flag that takes a
    /// value placed before the command word makes this miss, which only
    /// means the command runs with the registered token as any other does.
    public static func authAction(_ arguments: [String]) -> AuthAction? {
        let words = arguments.prefix { $0 != "--" }.filter { !$0.hasPrefix("-") }
        guard words.count >= 2, words[0] == "auth" else { return nil }
        switch words[1] {
        case "login", "signup": return .login
        case "logout": return .logout
        default: return nil
        }
    }

    /// The shell lines that route `fly` and `flyctl` through `csec fly`.
    /// csec prints them; it never edits a shell profile.
    public static func aliasLines(csecCommand: String = "csec") -> [String] {
        [
            "fish:      alias --save fly '\(csecCommand) fly'; alias --save flyctl '\(csecCommand) fly'",
            "zsh/bash:  alias fly='\(csecCommand) fly' flyctl='\(csecCommand) fly'   (in ~/.zshrc or ~/.bashrc)",
        ]
    }
}

public enum FlyConfigError: Error, Equatable, CustomStringConvertible {
    case duplicateKey(String)
    case unsupportedValue(String)

    public var description: String {
        switch self {
        case .duplicateKey(let key):
            return "config.yml sets \(key) more than once"
        case .unsupportedValue(let key):
            return "config.yml's \(key) is not a single-line value csec can rewrite"
        }
    }
}

/// The token lines of a flyctl `config.yml`. flyctl writes it with yaml.v3 as
/// top-level `key: value` lines, the tokens as single-line plain scalars, and
/// an empty token as `""`. Only those two keys are read; every other byte is
/// kept, so WireGuard state and settings survive. A shape flyctl does not
/// write (block or multi-line scalars, anchors, escapes, a repeated key) is
/// refused rather than guessed at.
public struct FlyConfigTokens: Sendable {
    public static let tokenKeys = ["access_token", "metrics_token"]

    private let lines: [Substring]
    private let tokenLines: [String: Int]
    private let values: [String: String]

    public init(_ data: Data) throws {
        let text = String(decoding: data, as: UTF8.self)
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        var tokenLines: [String: Int] = [:]
        var values: [String: String] = [:]
        for (index, line) in lines.enumerated() {
            guard let (key, rawValue) = Self.topLevelEntry(line), Self.tokenKeys.contains(key) else { continue }
            guard tokenLines[key] == nil else { throw FlyConfigError.duplicateKey(key) }
            // An indented line after it would continue the scalar or open a
            // nested block under the key.
            if index + 1 < lines.count, let next = lines[index + 1].first, next == " " || next == "\t",
               !lines[index + 1].trimmingCharacters(in: .whitespaces).isEmpty {
                throw FlyConfigError.unsupportedValue(key)
            }
            guard let value = Self.scalar(rawValue) else { throw FlyConfigError.unsupportedValue(key) }
            tokenLines[key] = index
            values[key] = value
        }
        self.lines = lines
        self.tokenLines = tokenLines
        self.values = values
    }

    /// The saved access token, or nil when the file holds none.
    public var accessToken: String? { nonEmpty("access_token") }
    public var hasMetricsToken: Bool { nonEmpty("metrics_token") != nil }
    public var holdsToken: Bool { accessToken != nil || hasMetricsToken }

    /// The file with both token lines emptied (`key: ""`, as flyctl writes an
    /// empty token) and every other line as it was.
    public func blanked() -> Data {
        var output = lines.map(String.init)
        for (key, index) in tokenLines where nonEmpty(key) != nil {
            output[index] = "\(key): \"\""
        }
        return Data(output.joined(separator: "\n").utf8)
    }

    private func nonEmpty(_ key: String) -> String? {
        guard let value = values[key], !value.isEmpty else { return nil }
        return value
    }

    private static func topLevelEntry(_ line: Substring) -> (String, Substring)? {
        guard let first = line.first, first != " ", first != "\t", first != "#", first != "-",
              let colon = line.firstIndex(of: ":") else { return nil }
        var key = line[..<colon].trimmingCharacters(in: .whitespaces)
        if key.count >= 2, let quote = key.first, quote == key.last, quote == "\"" || quote == "'" {
            key = String(key.dropFirst().dropLast())
        }
        let rest = line[line.index(after: colon)...]
        // `key:value` is not a mapping entry in YAML.
        guard rest.isEmpty || rest.first == " " || rest.first == "\t" else { return nil }
        return (key, rest)
    }

    /// A single-line scalar's value, or nil for a form csec does not rewrite.
    private static func scalar(_ raw: Substring) -> String? {
        var value = raw.trimmingCharacters(in: CharacterSet(charactersIn: " \t\r"))
        if value.isEmpty || value == "~" || value == "null" || value == "\"\"" || value == "''" { return "" }
        if let quote = value.first, quote == "\"" || quote == "'" {
            guard value.count >= 2, value.last == quote else { return nil }
            value = String(value.dropFirst().dropLast())
            guard !value.contains(quote), !(quote == "\"" && value.contains("\\")) else { return nil }
            return value
        }
        guard let first = value.first, !"|>&*!{[%@`#'\"".contains(first),
              !value.contains(" #"), !value.contains("\t#") else { return nil }
        return value
    }
}

/// `csec fly`'s registration: which reference holds the Fly token, kept beside
/// flyctl's config (so `FLY_CONFIG_DIR` selects it too). It holds only the
/// canonical reference, never a value. A same-user process that changed it
/// could make `csec fly` ask for a different reference, which the review
/// names; it gains nothing `csec exec` does not already offer it.
public struct FlyRegistration: Codable, Equatable, Sendable {
    public static let maximumBytes = 4096

    public let version: Int
    public let tokenReference: String

    enum CodingKeys: String, CodingKey {
        case version
        case tokenReference = "token_reference"
    }

    public init(reference: SecretRef) {
        version = 1
        tokenReference = reference.uri
    }

    public var reference: SecretRef? {
        guard version == 1, let reference = try? SecretRef(tokenReference),
              reference.uri == tokenReference else { return nil }
        return reference
    }

    public static func decode(_ data: Data) -> FlyRegistration? {
        guard data.count <= maximumBytes,
              let registration = try? JSONDecoder().decode(FlyRegistration.self, from: data),
              registration.reference != nil else { return nil }
        return registration
    }

    public func encoded() -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return ((try? encoder.encode(self)) ?? Data()) + Data("\n".utf8)
    }
}

extension SecretDestinationSpec {
    /// Where a value already registered under `reference` is written again,
    /// with the key or field it lives under, for the destinations csec can
    /// write. nil for any other reference: registering it is still fine,
    /// csec just cannot replace its value.
    public static func writeTarget(for reference: SecretRef) -> (spec: SecretDestinationSpec, key: String)? {
        switch reference.scheme {
        case "csec":
            guard let native = try? NativeSecretReference(reference) else { return nil }
            return (.native(native.store), native.key)
        case "op":
            let parts = reference.path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 3, let spec = try? parse("op://\(parts[0])/\(parts[1])", defaultItemTitle: parts[1]),
                  isValidOnePasswordComponent(parts[2]) else { return nil }
            return (spec, parts[2])
        default:
            return nil
        }
    }
}
