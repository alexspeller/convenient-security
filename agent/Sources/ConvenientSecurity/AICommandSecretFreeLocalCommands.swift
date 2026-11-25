import Foundation

extension AICommandSecretFree {
    /// Commands this Mac's administrator adds to the secret-free list: local
    /// tools of the form `<name> <subcommand> …` that take no global option,
    /// for the subcommands that need no secret and start no program their
    /// command line names. A session tool that every agent command runs (to
    /// read its work items, park, report) would otherwise wait on the project's
    /// panel whenever its secrets are locked.
    ///
    /// They come from `path`, which, like csec's other system configuration
    /// (`/etc/codex/hooks.json`), must be a root-owned regular file that no group
    /// or other user can write, in a root-owned directory that none can write
    /// either: an agent running as the user cannot add an entry, and an
    /// administrator's `sudo` goes through csec's sudo review. No file means
    /// only the built-in rules apply.
    ///
    /// ```json
    /// {
    ///   "version": 1,
    ///   "commands": {
    ///     "tasks": {
    ///       "subcommands": ["show", "list", "note"],
    ///       "subcommandsWithSecondWord": {"plugins": ["list", "read"]},
    ///       "credentialVariablePrefixes": ["TASKS_"]
    ///     }
    ///   }
    /// }
    /// ```
    ///
    /// A listed command, like bd, may start other programs only as it is built
    /// or configured to; the entry vouches that those need no secret (see
    /// `docs/threat-model.md`).
    public struct LocalCommands: Sendable, Equatable {
        public struct Command: Sendable, Equatable {
            /// Subcommands allowed with any arguments after them.
            public var subcommands: Set<String>
            /// Subcommands allowed only when their second word is one of these
            /// (`plugins list`, but not `plugins install`).
            public var subcommandsWithSecondWord: [String: Set<String>]
            /// While a reference variable's name starts with one of these, the
            /// command may read its own credential from it, so it keeps the
            /// ordinary path whatever the subcommand.
            public var credentialVariablePrefixes: [String]

            public init(
                subcommands: Set<String>,
                subcommandsWithSecondWord: [String: Set<String>] = [:],
                credentialVariablePrefixes: [String] = []
            ) {
                self.subcommands = subcommands
                self.subcommandsWithSecondWord = subcommandsWithSecondWord
                self.credentialVariablePrefixes = credentialVariablePrefixes
            }

            /// How many of the first arguments name what the command runs: its
            /// subcommand, and the second word of a `subcommandsWithSecondWord`
            /// one.
            func decidingWords(_ arguments: [String]) -> Int {
                arguments.first.flatMap { subcommandsWithSecondWord[$0] } == nil ? 1 : 2
            }

            func rejection(_ name: String, _ arguments: [String], referenceVariables: Set<String>) -> Rejection? {
                if let variable = referenceVariables.sorted().first(where: { variable in
                    credentialVariablePrefixes.contains { variable.hasPrefix($0) }
                }) {
                    return .readsCredential(command: name, variable: variable)
                }
                guard let subcommand = arguments.first else { return .localSubcommand(command: name, subcommand: "") }
                if subcommands.contains(subcommand) { return nil }
                guard let secondWords = subcommandsWithSecondWord[subcommand] else {
                    return .localSubcommand(command: name, subcommand: subcommand)
                }
                guard arguments.count > 1 else { return .localSubcommand(command: name, subcommand: subcommand) }
                return secondWords.contains(arguments[1])
                    ? nil : .localSubcommand(command: name, subcommand: "\(subcommand) \(arguments[1])")
            }
        }

        public var commands: [String: Command]

        public init(commands: [String: Command]) {
            self.commands = commands
        }

        public static let none = LocalCommands(commands: [:])

        /// `/etc` is a link to `/private/etc`; the checks read the real path.
        public static let path = "/private/etc/csec/secret-free-commands.json"

        /// Why the file was not used. Value-free: a path and the rule it broke.
        public enum LoadError: Error, Sendable, Equatable, CustomStringConvertible {
            /// Not a root-owned, single-link regular file in a root-owned
            /// directory, both writable by no group or other user, or unreadable.
            case unsafe(path: String)
            case invalid(path: String, reason: String)

            public var description: String {
                switch self {
                case let .unsafe(path):
                    return "\(path) is not a root-owned regular file, writable only by root, in a root-owned directory"
                case let .invalid(path, reason):
                    return "\(path) is not a valid list of secret-free commands: \(reason)"
                }
            }
        }

        /// The file at `path`, or `none` when there is none.
        /// `requireRootOwnership` is false only in tests, which cannot create a
        /// root-owned file; every other check still applies.
        public static func load(path: String = path, requireRootOwnership: Bool = true) throws -> LocalCommands {
            let data: Data?
            do {
                data = try CodingAgentSetup.readRootOwnedConfiguration(
                    path: path, requireRootOwnership: requireRootOwnership)
            } catch SetupOnboardingError.invalidConfiguration {
                throw LoadError.invalid(path: path, reason: "not a JSON object")
            } catch SetupOnboardingError.configurationTooLarge {
                throw LoadError.invalid(path: path, reason: "too large")
            } catch {
                throw LoadError.unsafe(path: path)
            }
            guard let data else { return .none }
            do {
                return try parse(data)
            } catch let reason as InvalidReason {
                throw LoadError.invalid(path: path, reason: reason.text)
            }
        }

        struct InvalidReason: Error {
            let text: String
            init(_ text: String) { self.text = text }
        }

        /// Names a shell reads as one plain word: no path, glob, quote or
        /// expansion, and no leading `-`, so a subcommand is never an option.
        private static let wordPattern = #/[A-Za-z0-9][A-Za-z0-9._:+-]*/#
        private static let prefixPattern = #/[A-Za-z_][A-Za-z0-9_]*/#

        static func parse(_ data: Data) throws -> LocalCommands {
            guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw InvalidReason("not a JSON object")
            }
            try onlyKeys(root, ["version", "commands"], in: "the file")
            guard let version = root["version"] as? NSNumber, !isBoolean(version),
                  version == 1 else {
                throw InvalidReason("\"version\" must be 1")
            }
            guard let entries = root["commands"] as? [String: Any] else {
                throw InvalidReason("\"commands\" must be an object")
            }
            let builtIn = listedCommands.union(bannedCommands).union(["git", "bd"])
            var commands: [String: Command] = [:]
            for (name, value) in entries {
                guard name.wholeMatch(of: wordPattern) != nil else {
                    throw InvalidReason("command \"\(name)\" is not a plain command name")
                }
                guard !builtIn.contains(name) else {
                    throw InvalidReason("command \"\(name)\" has built-in rules")
                }
                guard let entry = value as? [String: Any] else {
                    throw InvalidReason("command \"\(name)\" must be an object")
                }
                let place = "command \"\(name)\""
                try onlyKeys(entry, ["subcommands", "subcommandsWithSecondWord", "credentialVariablePrefixes"],
                             in: place)
                let subcommands = try words(entry["subcommands"] ?? [String](), "\(place) subcommands")
                var withSecondWord: [String: Set<String>] = [:]
                guard let nested = (entry["subcommandsWithSecondWord"] ?? [String: Any]()) as? [String: Any] else {
                    throw InvalidReason("\(place) subcommandsWithSecondWord must be an object")
                }
                for (subcommand, secondWords) in nested {
                    guard subcommand.wholeMatch(of: wordPattern) != nil else {
                        throw InvalidReason("\(place) subcommand \"\(subcommand)\" is not a plain word")
                    }
                    guard !subcommands.contains(subcommand) else {
                        throw InvalidReason("\(place) lists \"\(subcommand)\" both with and without a second word")
                    }
                    withSecondWord[subcommand] = try words(secondWords, "\(place) \(subcommand)")
                }
                guard let prefixes = (entry["credentialVariablePrefixes"] ?? [String]()) as? [String],
                      prefixes.allSatisfy({ $0.wholeMatch(of: prefixPattern) != nil }) else {
                    throw InvalidReason("\(place) credentialVariablePrefixes must be variable-name prefixes")
                }
                commands[name] = Command(
                    subcommands: subcommands, subcommandsWithSecondWord: withSecondWord,
                    credentialVariablePrefixes: prefixes)
            }
            return LocalCommands(commands: commands)
        }

        private static func onlyKeys(_ object: [String: Any], _ allowed: Set<String>, in place: String) throws {
            if let unknown = object.keys.sorted().first(where: { !allowed.contains($0) }) {
                throw InvalidReason("\(place) has an unknown key \"\(unknown)\"")
            }
        }

        private static func words(_ value: Any, _ place: String) throws -> Set<String> {
            guard let list = value as? [String], list.allSatisfy({ $0.wholeMatch(of: wordPattern) != nil }) else {
                throw InvalidReason("\(place) must be a list of plain words")
            }
            return Set(list)
        }

        private static func isBoolean(_ number: NSNumber) -> Bool {
            CFGetTypeID(number) == CFBooleanGetTypeID()
        }
    }
}
