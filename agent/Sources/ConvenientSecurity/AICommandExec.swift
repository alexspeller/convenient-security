import Foundation

/// The injection delivery plan for a hook-brokered AI command (`csec ai`).
///
/// `csec exec` and `csec ai` share one injection engine (resolve secret
/// references in the environment, hand the values to the child). They differ
/// only in *who* triggers them and in output posture: `exec` is human-invoked
/// with terminal-facing, disable-able redaction; `ai` is hook-invoked with
/// always-on, opaque, fail-closed AI-facing redaction.
///
/// This plan is deliberately built with a **stable release shape**. Every field
/// that `DeliveryPlan.releaseShapeDigest()` retains is constant here, and every
/// field it excludes (executable, requested TTL, operation context, command
/// digest) is the only thing allowed to vary per command. That is what lets a
/// single Touch ID — approved once at the coding-agent scope csecd offers by
/// default — cover every later `ai` command of the same shape in that session,
/// instead of prompting per command. Changing any of the constants below would
/// silently break that one-approval-per-session behavior.
public enum AICommandExec {
    /// Fixed operation context for every AI-brokered command. It must not carry
    /// the command (that would vary the release shape, and leak argv into
    /// protocol JSON); the visible command already appears in the wrapper argv.
    public static let operationContext = "AI tool command"

    /// Always-on, opaque output masking. Mandatory for the environment mechanism
    /// (`Agent.hasValidOutputGuard` rejects it without one) and constant so the
    /// release shape stays stable. Opaque labels keep reference metadata out of
    /// the AI's view, unlike `csec exec`'s operator-facing reference labels.
    public static let outputGuard = OutputGuardPlan(
        mode: .always,
        labelStyle: .opaque,
        includeShortValues: false
    )

    /// The shell `csec ai` runs every program under. Claude Code and Codex
    /// both submit a shell program string, not an argv vector; zsh is the
    /// native macOS user-shell superset, and `-l` sources login files while
    /// staying non-interactive, so direnv does not re-run and clobber the
    /// values `csec ai` just injected.
    public static let shellPath = "/bin/zsh"
    public static let shellFlag = "-lc"

    /// The requested shell argv bound to policy and delegation. The actual
    /// child launch adds AICommandCredentialGuard's fixed post-startup setup.
    public static func commandLine(forProgram program: String) -> [String] {
        [shellPath, shellFlag, program]
    }

    /// Build the injection delivery plan for one AI-brokered command.
    ///
    /// `executablePath`, `ttlSeconds` and `commandDigest` are excluded from the
    /// release-shape digest, so passing a different program or duration never
    /// defeats reuse — which is exactly the property the accompanying tests
    /// pin. `csec ai` passes the digest of its `commandLine`, so csecd holds the
    /// argv it shows (and a delegation binds) to the plan.
    public static func deliveryPlan(
        executablePath: String,
        ttlSeconds: Int?,
        commandDigest: String? = nil
    ) -> DeliveryPlan {
        DeliveryPlan(
            mechanism: .unrestrictedInitialEnvironment,
            executable: PlannedExecutable(
                canonicalPath: executablePath,
                assurance: .unverified
            ),
            root: .caller,
            descendantScope: .subtree,
            destination: .localDevelopment,
            requestedTTLSeconds: ttlSeconds,
            operationContext: operationContext,
            commandDigest: commandDigest,
            outputGuard: outputGuard,
            interactive: false
        )
    }

    /// Whether an access request has exactly the shape `csec ai` sends: its
    /// `/bin/zsh -lc <program>` argv, and the plan `deliveryPlan` builds for it
    /// with no TTL and that argv's digest. This is csec-authored shape, not a
    /// trust claim — any launcher can send it; csecd's trust comes from the
    /// peer and its kernel ancestry.
    ///
    /// The deprecated `csec tool-exec` runs the same broker, so its requests
    /// satisfy this too. What excludes it (and anything else sending this
    /// shape) is the cross-check against the peer's kernel argv:
    /// `program(fromProcessArguments:)` requires `argv[1] == "ai"`, and its
    /// program must equal `commandLine[2]` byte for byte (compare the UTF-8
    /// bytes, not `String ==`, which treats canonically equivalent strings as
    /// equal).
    public static func isAIRequest(plan: DeliveryPlan, commandLine: [String]?) -> Bool {
        guard let commandLine,
              commandLine.count == 3,
              commandLine[0] == shellPath,
              commandLine[1] == shellFlag,
              let digest = try? ExecutableInspection.commandDigest(commandLine) else { return false }
        return plan == deliveryPlan(executablePath: shellPath, ttlSeconds: nil, commandDigest: digest)
    }

    public enum ArgumentError: Error, Equatable {
        /// The arguments are not `[--destination ai] (--encoded-shell-command X | -- <program>…)`
        /// or `--claude-code-shell <argument>`.
        case usage
        /// A legacy `--encoded-shell-command` that does not decode.
        case invalidEncodedCommand
    }

    /// The program `csec ai` (or the legacy `tool-exec`) runs for the
    /// arguments after its verb: exactly one of the visible `-- <program>…`
    /// form, whose words are rejoined with `AICommandHook.launchedProgram`, or
    /// the legacy base64 `--encoded-shell-command`. `--destination` is
    /// accepted only as `ai`.
    public static func program(fromArguments arguments: [String]) throws -> String {
        var destination: String?
        var encodedShellCommand: String?
        var programArguments: [String]?
        var index = 0
        parse: while index < arguments.count {
            switch arguments[index] {
            case "--destination":
                index += 1
                guard index < arguments.count else { throw ArgumentError.usage }
                destination = arguments[index]
            case "--encoded-shell-command":
                index += 1
                guard index < arguments.count else { throw ArgumentError.usage }
                encodedShellCommand = arguments[index]
            case "--":
                programArguments = Array(arguments[(index + 1)...])
                break parse
            case ClaudeCodeShellPrefix.option:
                // Claude Code's prefix hands exactly one argument; nothing
                // else may come before or after it.
                guard index == 0, arguments.count == 2, !arguments[1].isEmpty else { throw ArgumentError.usage }
                return arguments[1]
            default:
                throw ArgumentError.usage
            }
            index += 1
        }
        guard destination == nil || destination == "ai" else { throw ArgumentError.usage }
        switch (encodedShellCommand, programArguments) {
        case let (.some(encoded), .none):
            guard let program = try? AICommandHook.decodeShellCommand(encoded) else {
                throw ArgumentError.invalidEncodedCommand
            }
            return program
        case let (.none, .some(words)):
            guard !words.isEmpty else { throw ArgumentError.usage }
            return AICommandHook.launchedProgram(fromWords: words)
        default:
            throw ArgumentError.usage
        }
    }

    /// The program a `csec ai` process runs, read from its whole argv (argv[0]
    /// included), or nil when the argv is not `<csec> ai …` with valid
    /// arguments. csecd uses it to hold a `csec ai` peer's kernel argv to the
    /// program its access request names.
    public static func program(fromProcessArguments argv: [String]) -> String? {
        guard argv.count >= 2, argv[1] == "ai" else { return nil }
        return try? program(fromArguments: Array(argv.dropFirst(2)))
    }

    /// Whether `csec ai`'s arguments are the shell prefix's
    /// `--claude-code-shell <argument>` form.
    public static func isShellPrefix(arguments: [String]) -> Bool {
        arguments.count == 2 && arguments[0] == ClaudeCodeShellPrefix.option
    }

    /// The program a hook registration names for a `csec ai` process, read
    /// from its whole argv, or nil: the program it runs for `-- <program>`
    /// (and the legacy forms), and for the shell prefix the command inside
    /// the Bash framing's `eval`, which is the command auto mode reviewed and
    /// the hook registered. A prefix argument that is not a framing csec can
    /// read names no registered program, so it binds nothing.
    public static func registeredProgram(fromProcessArguments argv: [String]) -> String? {
        guard argv.count >= 2, argv[1] == "ai" else { return nil }
        let arguments = Array(argv.dropFirst(2))
        guard isShellPrefix(arguments: arguments) else { return try? program(fromArguments: arguments) }
        return ClaudeCodeShellPrefix.framing(arguments[1])?.command
    }
}
