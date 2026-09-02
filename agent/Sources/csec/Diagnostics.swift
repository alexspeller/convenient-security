import Foundation
import ConvenientSecurity
#if canImport(Darwin)
import Darwin
#endif

// Colored, normalized diagnostic output for the launcher. Both helpers write a
// `csec <command>: <label> <message>` line to stderr, with the label colored when
// stderr is a terminal. Interpolated untrusted metadata (paths, argv, identifiers)
// must be passed already neutralized via `ReviewDisplay.sanitized` — these helpers
// format, they do not sanitize.

func csecError(_ command: String, _ message: String) {
    let color = TerminalStyle.colorEnabled(STDERR_FILENO)
    let label = TerminalStyle.paint("error:", TerminalStyle.Code.red, color: color)
    FileHandle.standardError.write(Data("csec \(command): \(label) \(message)\n".utf8))
}

func csecWarning(_ command: String, _ message: String) {
    let color = TerminalStyle.colorEnabled(STDERR_FILENO)
    let label = TerminalStyle.paint("warning:", TerminalStyle.Code.yellow, color: color)
    FileHandle.standardError.write(Data("csec \(command): \(label) \(message)\n".utf8))
}
