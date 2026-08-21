import Foundation

public enum AICommandHookClient: String, Sendable, CaseIterable {
    case claude
    case codex
}

public enum AICommandHookError: Error, LocalizedError {
    case invalidInput
    case unsupportedEvent
    case unsupportedTool
    case invalidCommand
    case invalidExecutablePath

    public var errorDescription: String? {
        switch self {
        case .invalidInput: return "invalid hook JSON"
        case .unsupportedEvent: return "the hook input is not PreToolUse"
        case .unsupportedTool: return "the hook input is not a Bash command"
        case .invalidCommand: return "the hook command is empty or outside supported bounds"
        case .invalidExecutablePath: return "the csec executable path is invalid"
        }
    }
}

/// Deterministic adapters for Claude Code and Codex `PreToolUse`. They do no
/// secret work and never contact the agent: their only job is to replace the
/// proposed shell string with a fail-closed `csec tool-exec` invocation.
public enum AICommandHook {
    public static let maximumCommandBytes = 1024 * 1024

    public static func rewrite(
        input: Data,
        client: AICommandHookClient,
        csecExecutablePath: String
    ) throws -> Data {
        guard input.count <= maximumCommandBytes,
              let object = try JSONSerialization.jsonObject(with: input) as? [String: Any],
              let event = object["hook_event_name"] as? String else {
            throw AICommandHookError.invalidInput
        }
        guard event == "PreToolUse" else { throw AICommandHookError.unsupportedEvent }
        guard object["tool_name"] as? String == "Bash" else {
            throw AICommandHookError.unsupportedTool
        }
        guard var updatedInput = object["tool_input"] as? [String: Any],
              let command = updatedInput["command"] as? String,
              !command.isEmpty,
              command.utf8.count <= maximumCommandBytes,
              !command.utf8.contains(0) else {
            throw AICommandHookError.invalidCommand
        }
        let executable = URL(fileURLWithPath: csecExecutablePath)
            .standardizedFileURL.resolvingSymlinksInPath().path
        guard executable.hasPrefix("/"),
              !executable.utf8.contains(0),
              executable.utf8.count <= 4_096 else {
            throw AICommandHookError.invalidExecutablePath
        }

        let encoded = encodeShellCommand(command)
        updatedInput["command"] = "\(shellQuote(executable)) tool-exec "
            + "--destination ai --encoded-shell-command \(encoded)"
        let reason = "Route command output through the csec active-secret scanner"
        let hookOutput: [String: Any] = [
            "hookSpecificOutput": [
                "hookEventName": "PreToolUse",
                // Codex currently requires allow for input rewriting. Claude
                // still evaluates explicit deny/ask rules after an allow hook.
                "permissionDecision": "allow",
                "permissionDecisionReason": reason,
                "updatedInput": updatedInput,
            ],
        ]
        return try JSONSerialization.data(withJSONObject: hookOutput, options: [.sortedKeys])
    }

    public static func hookConfiguration(
        client: AICommandHookClient,
        csecExecutablePath: String
    ) throws -> Data {
        let executable = URL(fileURLWithPath: csecExecutablePath)
            .standardizedFileURL.resolvingSymlinksInPath().path
        guard executable.hasPrefix("/"),
              !executable.utf8.contains(0),
              executable.utf8.count <= 4_096 else {
            throw AICommandHookError.invalidExecutablePath
        }

        let handler: [String: Any]
        switch client {
        case .claude:
            // Exec form avoids an extra shell and quoting ambiguity in the hook
            // itself. The proposed tool command is still encoded in hook stdin.
            handler = [
                "type": "command",
                "command": executable,
                "args": ["hook", "claude"],
                "timeout": 5,
            ]
        case .codex:
            // Codex command hooks currently use a shell command string.
            handler = [
                "type": "command",
                "command": "\(shellQuote(executable)) hook codex",
                "timeout": 5,
                "statusMessage": "Enabling protected output scanning",
            ]
        }

        var configuration: [String: Any] = [
            "hooks": [
                "PreToolUse": [[
                    "matcher": "Bash",
                    "hooks": [handler],
                ]],
            ],
        ]
        // Codex documents optional top-level metadata in hooks.json. Claude's
        // settings schema does not need it, so keep its generated fragment to
        // the common `hooks` object only.
        if client == .codex {
            configuration["description"] =
                "Route Bash tool output through csec before it reaches an AI model."
        }
        return try JSONSerialization.data(
            withJSONObject: configuration,
            options: [.prettyPrinted, .sortedKeys]
        ) + Data("\n".utf8)
    }

    public static func encodeShellCommand(_ command: String) -> String {
        Data(command.utf8).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    public static func decodeShellCommand(_ encoded: String) throws -> String {
        guard !encoded.isEmpty,
              encoded.utf8.count <= maximumCommandBytes * 2,
              encoded.utf8.allSatisfy({
                  ($0 >= 65 && $0 <= 90) || ($0 >= 97 && $0 <= 122)
                      || ($0 >= 48 && $0 <= 57) || $0 == 45 || $0 == 95
              }) else {
            throw AICommandHookError.invalidCommand
        }
        var base64 = encoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.utf8.count % 4
        if remainder > 0 { base64 += String(repeating: "=", count: 4 - remainder) }
        guard let data = Data(base64Encoded: base64),
              data.count <= maximumCommandBytes,
              let command = String(data: data, encoding: .utf8),
              !command.isEmpty,
              !command.utf8.contains(0) else {
            throw AICommandHookError.invalidCommand
        }
        return command
    }

    private static func shellQuote(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'"
    }
}
