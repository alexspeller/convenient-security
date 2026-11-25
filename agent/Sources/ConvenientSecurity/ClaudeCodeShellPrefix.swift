import CSecuritySupport
import Darwin
import Foundation

/// csec as Claude Code's `CLAUDE_CODE_SHELL_PREFIX` (csec-0.83.1, av-e2sa).
///
/// The PreToolUse hook used to rewrite every Bash and Monitor command to
/// `csec ai -- …`. Claude Code's auto mode reviews the command the model
/// wrote, and a hook that changes it afterwards voids that review: up to
/// 2.1.305 a local classifier judged the call again (about 2 s a call), and
/// from 2.1.314 the call is blocked with no verdict and must be resubmitted.
/// The prefix is applied after the review instead, inside Claude Code's own
/// command builder, so the classifier, the worktree guard and content deny
/// rules all judge the command as typed while `csec ai` still runs it.
///
/// Claude Code applies the prefix in three places (2.1.305 and 2.1.319):
///
/// - the Bash and Monitor tools: `<shell> -c "'<prefix>' '<framing>'"`,
///   where the framing is `<setup> && eval '<command>' < /dev/null && pwd -P
///   >| <cwd file>`. zsh runs that single command by exec, so the prefix
///   process takes the tool shell's place, directly under Claude Code;
/// - shell-form hooks: `'<prefix>' '<hook command>'`;
/// - stdio MCP servers: the prefix string is the executable and its one
///   argument is the shell-quoted command line, so the prefix must be a bare
///   absolute path with no options.
///
/// The prefix is a csec-authored script in the app bundle that execs
/// `csec ai --claude-code-shell "$@"`, keeping its pid, so the kernel argv
/// csecd reads is csec's own. `csec ai` then reads its one argument:
///
/// - a Bash or Monitor framing (`framing(_:)`) runs under `csec ai` as its
///   program, with the direct-`op` guard set up just before the `eval`, after
///   the shell snapshot the framing sources; the hook's registration names
///   the command inside the `eval`, which is what csecd binds;
/// - text that names neither of the framing's markers (`eval`, `pwd -P >|`)
///   is a hook or an MCP command line and runs with `/bin/sh -c`, unwrapped,
///   exactly as it ran before the prefix;
/// - anything else (a framing csec cannot read, from a Claude Code release
///   that changed it) runs under `csec ai` as a whole, never unwrapped.
public enum ClaudeCodeShellPrefix {
    /// The `csec ai` option the prefix script passes before Claude Code's
    /// argument.
    public static let option = "--claude-code-shell"

    /// The prefix script's path relative to the app bundle's `Contents`.
    static let bundleRelativePath = "Resources/claude-code-shell/csec-claude-code-shell"

    /// The prefix script csec ships in the same app bundle as
    /// `csecExecutablePath` (`<bundle>/Contents/MacOS/csec` or `csecd`), or
    /// nil for any other layout (a SwiftPM build, the root-owned bridge copy).
    public static func prefixPath(csecExecutablePath: String) -> String? {
        let executable = URL(fileURLWithPath: csecExecutablePath)
        let macOS = executable.deletingLastPathComponent()
        let contents = macOS.deletingLastPathComponent()
        guard ["csec", "csecd"].contains(executable.lastPathComponent), macOS.lastPathComponent == "MacOS",
              contents.lastPathComponent == "Contents", contents.deletingLastPathComponent().pathExtension == "app"
        else { return nil }
        return contents.appendingPathComponent(bundleRelativePath).path
    }

    /// The prefix script of the bundle this process runs from, or nil when
    /// it runs from anything else: the one CLAUDE_CODE_SHELL_PREFIX value the
    /// delegation gates accept. The path is the kernel's, not `Bundle.main`'s:
    /// CoreFoundation takes an unrestricted process's path from the
    /// `CFProcessPath` environment variable, and nothing the environment
    /// says may choose which prefix the gates accept.
    public static var installedPrefixPath: String? {
        var buffer = [CChar](repeating: 0, count: 4 * 1_024)
        guard cs_proc_path(getpid(), &buffer, Int32(buffer.count)) > 0 else { return nil }
        return prefixPath(csecExecutablePath: URL(fileURLWithPath: String(cString: buffer)).resolvingSymlinksInPath().path)
    }

    /// Whether a CLAUDE_CODE_SHELL_PREFIX `value` is exactly csec's own
    /// prefix script, `accepted`. Bytes, not `String ==`, which would match a
    /// canonically equivalent spelling of another path.
    public static func isCsecPrefix(_ value: String?, accepted: String?) -> Bool {
        guard let value, let accepted else { return false }
        return Array(value.utf8) == Array(accepted.utf8)
    }

    /// The script the bundle ships at `prefixPath`. It names csec by its
    /// place in the same bundle, never by PATH.
    public static let scriptText = """
    #!/bin/sh
    exec "${0%/Resources/claude-code-shell/csec-claude-code-shell}/MacOS/csec" ai --claude-code-shell "$@"

    """

    /// Whether `csec ai --claude-code-shell <argument>` runs its argument
    /// with `/bin/sh -c`, unwrapped: a hook or MCP command line, which names
    /// neither of the framing's markers.
    public static func runsUnwrapped(_ argument: String) -> Bool {
        framing(argument) == nil && !namesFramingMarker(argument)
    }

    /// `framing` with `setup` run as one group just before its `eval`, in
    /// the same `&&` list: `… && { <setup> } && eval '<command>' < /dev/null
    /// && pwd -P >| <cwd file>`. `evalStart` is `framing(_:)`'s offset.
    public static func guarded(_ framing: String, evalStart: Int, setup: String) -> String {
        let bytes = Array(framing.utf8)
        return String(decoding: bytes[..<evalStart], as: UTF8.self)
            + "{ " + setup + " } && "
            + String(decoding: bytes[evalStart...], as: UTF8.self)
    }

    /// The command a Bash or Monitor framing evaluates and the byte offset
    /// of its `eval`, or nil. The framing must end with Claude Code's `&& pwd
    /// -P >| <cwd file>` (a word with no quote or space, or one single-quoted
    /// word) and hold exactly one command that can run `eval`, the plain
    /// `eval` with one literal argument (`ClaudeToolShell`), beside any quoted
    /// `eval` of literal text Claude Code adds for some commands. A model's command
    /// sits inside that argument's quotes, so it can neither add the ending
    /// nor remove it.
    public static func framing(_ argument: String) -> (command: String, evalStart: Int)? {
        guard hasFramingEnding(argument),
              let evaluated = ClaudeToolShell.evaluated(script: argument) else { return nil }
        return (evaluated.program, evaluated.evalStart)
    }

    static func hasFramingEnding(_ argument: String) -> Bool {
        let marker = Array(" && pwd -P >| ".utf8)
        let bytes = Array(argument.utf8)
        guard let start = lastRange(of: marker, in: bytes) else { return false }
        let path = bytes[(start + marker.count)...]
        guard !path.isEmpty else { return false }
        if path.first == UInt8(ascii: "'") {
            return path.count >= 3 && path.last == UInt8(ascii: "'")
                && !path.dropFirst().dropLast().contains(UInt8(ascii: "'"))
        }
        return path.allSatisfy { byte in
            (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A)
                || "/._-+,:=@%".utf8.contains(byte)
        }
    }

    /// Whether `argument` names `eval` as a word or Claude Code's `pwd -P >|`
    /// ending anywhere. Over-approximated on purpose: a hook that only
    /// mentions `eval` runs wrapped, which costs it nothing but the scan.
    static func namesFramingMarker(_ argument: String) -> Bool {
        if argument.range(of: "pwd -P >|", options: .literal) != nil { return true }
        var word: [UInt8] = []
        for byte in argument.utf8 + [0x20] {
            let isWordByte = (byte >= 0x30 && byte <= 0x39) || (byte >= 0x41 && byte <= 0x5A)
                || (byte >= 0x61 && byte <= 0x7A) || byte == UInt8(ascii: "_")
            if isWordByte {
                word.append(byte)
            } else {
                if word == Array("eval".utf8) { return true }
                word.removeAll(keepingCapacity: true)
            }
        }
        return false
    }

    private static func lastRange(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard haystack.count >= needle.count else { return nil }
        var index = haystack.count - needle.count
        while index >= 0 {
            if haystack[index..<(index + needle.count)].elementsEqual(needle) { return index }
            index -= 1
        }
        return nil
    }
}
