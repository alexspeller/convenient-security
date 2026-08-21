import Foundation

public enum ExternalEditorCommandError: Error, LocalizedError, Equatable {
    case missingEditor
    case invalidEditor
    case executableUnavailable

    public var errorDescription: String? {
        switch self {
        case .missingEditor:
            return "$EDITOR is not set"
        case .invalidEditor:
            return "$EDITOR is not a valid bounded command line"
        case .executableUnavailable:
            return "the executable named by $EDITOR is unavailable"
        }
    }
}

/// A deliberately shell-free interpretation of `$EDITOR`. It supports the
/// quoting needed by ordinary values such as `code --wait` or
/// `'/Applications/My Editor.app/bin/editor' --wait`, but performs no command,
/// variable, glob, or operator expansion. The plaintext filename is appended as
/// one final argv element by the caller.
public struct ExternalEditorCommand: Sendable, Equatable {
    public static let maximumBytes = 4_096
    public static let maximumArguments = 64

    public let executablePath: String
    public let arguments: [String]

    public init(
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) throws {
        guard let value = environment["EDITOR"], !value.isEmpty else {
            throw ExternalEditorCommandError.missingEditor
        }
        try self.init(editorValue: value, environment: environment)
    }

    public init(
        editorValue: String,
        environment: [String: String] = ProcessInfo.processInfo.environment
    ) throws {
        let words = try Self.parse(editorValue)
        guard let executable = words.first, !executable.isEmpty else {
            throw ExternalEditorCommandError.invalidEditor
        }
        do {
            self.executablePath = try ExecutableInspection.resolve(
                command: executable,
                environment: environment
            )
        } catch {
            throw ExternalEditorCommandError.executableUnavailable
        }
        self.arguments = Array(words.dropFirst())
    }

    private enum Quote {
        case single
        case double
    }

    private static func parse(_ value: String) throws -> [String] {
        guard !value.isEmpty,
              value.utf8.count <= maximumBytes,
              !value.utf8.contains(0) else {
            throw ExternalEditorCommandError.invalidEditor
        }

        var words: [String] = []
        var current = ""
        var quote: Quote?
        var escaping = false
        var wordStarted = false

        func isUnsupportedControl(_ character: Character) -> Bool {
            character.unicodeScalars.contains {
                CharacterSet.controlCharacters.contains($0) && $0.value != 0x09
            }
        }

        func appendWord() throws {
            guard wordStarted else { return }
            guard current.utf8.count <= maximumBytes,
                  words.count < maximumArguments else {
                throw ExternalEditorCommandError.invalidEditor
            }
            words.append(current)
            current = ""
            wordStarted = false
        }

        for character in value {
            guard !isUnsupportedControl(character) else {
                throw ExternalEditorCommandError.invalidEditor
            }
            if escaping {
                current.append(character)
                wordStarted = true
                escaping = false
                continue
            }

            switch quote {
            case .single:
                if character == "'" {
                    quote = nil
                } else {
                    current.append(character)
                }
                wordStarted = true
            case .double:
                if character == "\"" {
                    quote = nil
                    wordStarted = true
                } else if character == "\\" {
                    escaping = true
                    wordStarted = true
                } else {
                    current.append(character)
                    wordStarted = true
                }
            case nil:
                switch character {
                case " ", "\t":
                    try appendWord()
                case "'":
                    quote = .single
                    wordStarted = true
                case "\"":
                    quote = .double
                    wordStarted = true
                case "\\":
                    escaping = true
                    wordStarted = true
                default:
                    current.append(character)
                    wordStarted = true
                }
            }
        }

        guard quote == nil, !escaping else {
            throw ExternalEditorCommandError.invalidEditor
        }
        try appendWord()
        guard !words.isEmpty else { throw ExternalEditorCommandError.invalidEditor }
        return words
    }
}
