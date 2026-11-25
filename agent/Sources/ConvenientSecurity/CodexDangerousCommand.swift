import Foundation

/// Codex's POSIX dangerous-command heuristic, ported line for line from
/// openai/codex `codex-rs/shell-command/src/command_safety/is_dangerous_command.rs`
/// (tag rust-v0.155.0-alpha.9.2; unchanged at rust-v0.155.0-alpha.16.4 and
/// rust-v0.156.1, re-checked 2026-09-24). The Windows
/// branches never run on macOS and are not ported.
enum CodexDangerousCommand {
    /// is_dangerous_command.rs:34 `MAX_DANGEROUS_COMMAND_WRAPPER_DEPTH`.
    static let maximumWrapperDepth = 8

    /// is_dangerous_command.rs:37-39 `dangerous_command_match` (POSIX).
    static func match(_ command: [String]) -> CodexCommandGate.DangerousCommandMatch? {
        match(command, wrapperDepth: 0)
    }

    /// is_dangerous_command.rs:49-81 `dangerous_command_match_with_depth`.
    /// A parse that cannot run counts as a match, so a failure never lets the
    /// Codex hook wrap a command Codex might have gated.
    static func match(_ command: [String], wrapperDepth: Int) -> CodexCommandGate.DangerousCommandMatch? {
        if wrapperDepth > maximumWrapperDepth {
            return .other
        }

        if let dangerousMatch = matchForExec(command, wrapperDepth: wrapperDepth) {
            return dangerousMatch
        }

        // Support shell scripts where any literal command might be dangerous,
        // including commands nested in control flow or substitutions.
        let literalCommands: [[String]]?
        do {
            literalCommands = try CodexShellSyntax.parseShellLcLiteralCommands(command)
        } catch {
            return .other
        }
        return firstMatch(in: literalCommands, wrapperDepth: wrapperDepth + 1)
    }

    /// The literal-commands step of `dangerous_command_match_with_depth`:
    /// the first command, in Codex's walk order, that matches one level down.
    static func firstMatch(in literalCommands: [[String]]?, wrapperDepth: Int) -> CodexCommandGate.DangerousCommandMatch? {
        for literal in literalCommands ?? [] {
            if let dangerousMatch = match(literal, wrapperDepth: wrapperDepth) {
                return dangerousMatch
            }
        }
        return nil
    }

    /// is_dangerous_command.rs:96-102 `executable_name_lookup_key` (POSIX): the
    /// text after the last `/`, if any.
    static func executableNameLookupKey(_ raw: String) -> String? {
        let scalars = raw.unicodeScalars
        let name = scalars.lastIndex(of: "/").map { scalars[scalars.index(after: $0)...] } ?? scalars[...]
        return name.isEmpty ? nil : String(Substring(name))
    }

    /// is_dangerous_command.rs:123-151 `dangerous_command_match_for_exec`.
    static func matchForExec(_ command: [String], wrapperDepth: Int) -> CodexCommandGate.DangerousCommandMatch? {
        let cmd0 = command.first.flatMap(executableNameLookupKey)
        switch cmd0 {
        case "rm"? where rmArgsIncludeForceOption(command.dropFirst()):
            return .forcedRm
        // For sudo <cmd>, simply check <cmd>.
        case "sudo"?:
            return match(Array(command.dropFirst()), wrapperDepth: wrapperDepth + 1)
        // Skip environment assignments before checking the command run by env.
        case "env"?:
            return matchForEnv(command, wrapperDepth: wrapperDepth)
        // A trap action is shell source stored in the first operand.
        case "trap"?:
            return matchForTrap(command, wrapperDepth: wrapperDepth)
        default:
            return nil
        }
    }

    /// is_dangerous_command.rs:153-175 `dangerous_command_match_for_env`.
    static func matchForEnv(_ command: [String], wrapperDepth: Int) -> CodexCommandGate.DangerousCommandMatch? {
        var commandIndex = 1
        while commandIndex < command.count {
            let argument = command[commandIndex]
            if argument.unicodeScalars.elementsEqual("--".unicodeScalars) {
                commandIndex += 1
                break
            }
            if ["-i", "--ignore-environment"].contains(where: { argument.unicodeScalars.elementsEqual($0.unicodeScalars) })
                || isEnvAssignment(argument) {
                commandIndex += 1
                continue
            }
            break
        }
        return match(Array(command[min(commandIndex, command.count)...]), wrapperDepth: wrapperDepth + 1)
    }

    /// `argument.split_once('=').is_some_and(|(name, _)| !name.is_empty() && !name.starts_with('-'))`.
    static func isEnvAssignment(_ argument: String) -> Bool {
        let scalars = argument.unicodeScalars
        guard let equals = scalars.firstIndex(of: "=") else { return false }
        let name = scalars[..<equals]
        return !name.isEmpty && name.first != "-"
    }

    /// is_dangerous_command.rs:177-194 `dangerous_command_match_for_trap`.
    static func matchForTrap(_ command: [String], wrapperDepth: Int) -> CodexCommandGate.DangerousCommandMatch? {
        var actionIndex = 1
        if actionIndex < command.count, command[actionIndex].unicodeScalars.elementsEqual("--".unicodeScalars) {
            actionIndex += 1
        }
        guard actionIndex < command.count, command[actionIndex].unicodeScalars.first != "-" else { return nil }
        let shellCommand = ["sh", "-c", command[actionIndex]]
        return match(shellCommand, wrapperDepth: wrapperDepth + 1)
    }

    /// is_dangerous_command.rs:196-205 `rm_args_include_force_option`: before
    /// any `--`, `--force` or a short-option cluster containing `f`. Compared
    /// by Unicode scalar, as Rust compares `char`s: Swift's `hasPrefix` and
    /// `contains` on a `String` see grapheme clusters, so `-f` followed by a
    /// combining mark would not contain an `f`.
    static func rmArgsIncludeForceOption(_ args: ArraySlice<String>) -> Bool {
        for argument in args {
            let scalars = argument.unicodeScalars
            if scalars.elementsEqual("--".unicodeScalars) { return false }
            if scalars.elementsEqual("--force".unicodeScalars) { return true }
            if scalars.first == "-" {
                let flags = scalars.dropFirst()
                if flags.first != "-" && flags.contains("f") { return true }
            }
        }
        return false
    }
}
