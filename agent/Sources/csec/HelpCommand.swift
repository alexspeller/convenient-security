import Foundation
import ConvenientSecurity
#if canImport(Darwin)
import Darwin
#endif

// Thin I/O wrappers around the pure `CLIHelpRenderer`: they choose the stream,
// exit code, color, and width from the target fd, so the launcher's dispatch stays
// declarative and the help text itself lives only in the library catalog.

/// Whether the user asked for help with `-h`/`--help` *before* any `--`, so
/// `csec exec --help` documents exec while `csec exec -- rails --help` forwards
/// `--help` on to rails.
func wantsHelp(_ arguments: [String]) -> Bool {
    for argument in arguments {
        if argument == "--" { return false }
        if argument == "-h" || argument == "--help" { return true }
    }
    return false
}

/// Print the whole-program help. `exitCode == 0` is the requested-help path
/// (stdout); a non-zero code is the error path (stderr).
func printGlobalHelp(exitCode: Int32) -> Never {
    let fd = exitCode == 0 ? STDOUT_FILENO : STDERR_FILENO
    writeHelp(CLIHelpRenderer.renderGlobal(
        color: TerminalStyle.colorEnabled(fd),
        width: TerminalStyle.terminalWidth(fd: fd)), to: fd)
    exit(exitCode)
}

/// Print one command's help. `explicit` (the user asked, e.g. `csec exec --help`)
/// prints to stdout and exits 0; otherwise it is the bad-args path — stderr, exit
/// 2. An unknown/absent command name falls back to the global help.
func printCommandHelp(_ command: String?, explicit: Bool) -> Never {
    guard let command, let entry = CLICatalog.command(named: command) else {
        printGlobalHelp(exitCode: explicit ? 0 : 2)
    }
    let fd = explicit ? STDOUT_FILENO : STDERR_FILENO
    writeHelp(CLIHelpRenderer.renderCommand(
        entry, color: TerminalStyle.colorEnabled(fd),
        width: TerminalStyle.terminalWidth(fd: fd)), to: fd)
    exit(explicit ? 0 : 2)
}

/// Print an "unknown command" error with a "did you mean?" hint and the global
/// listing, always to stderr and exit 2.
func printUnknownCommand(_ name: String) -> Never {
    writeHelp(CLIHelpRenderer.renderUnknownCommand(
        name, color: TerminalStyle.colorEnabled(STDERR_FILENO),
        width: TerminalStyle.terminalWidth(fd: STDERR_FILENO)), to: STDERR_FILENO)
    exit(2)
}

private func writeHelp(_ text: String, to fd: Int32) {
    let handle = fd == STDOUT_FILENO ? FileHandle.standardOutput : FileHandle.standardError
    handle.write(Data((text + "\n").utf8))
}
