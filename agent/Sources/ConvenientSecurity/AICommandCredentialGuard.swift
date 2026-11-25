import Darwin
import Foundation

/// Stops accidental direct 1Password CLI use in an AI command and its tools.
/// The daemon's provider runs outside this child PATH. This is a convenience
/// guard, not an execution sandbox: arbitrary code can replace PATH or use an
/// absolute executable path.
public final class AICommandCredentialGuard {
    public static let refusal =
        "op is disabled in AI commands; use csec exec -- <consumer> with secret references "
        + "in its environment, or the csec SDK instead."

    /// The shim every guard puts first on the child's PATH. The app bundle
    /// ships this exact text as `Contents/Resources/ai-guard/op`.
    public static let shimScript = "#!/bin/sh\nprintf '%s\\n' 'csec: \(refusal)' >&2\nexit 126\n"

    private let directory: URL
    /// False for the bundle's shipped shim, which cleanup must never remove.
    private let ownsDirectory: Bool

    /// Prefers the shim shipped beside `executablePath` in the app bundle, so a
    /// child whose sandbox allows no writes (Codex's read-only mode) is still
    /// guarded; otherwise writes a private per-command shim under TMPDIR.
    public init(executablePath: String? = nil, temporaryDirectory: URL? = nil) throws {
        if let executablePath, let shipped = Self.shippedDirectory(executablePath: executablePath),
           Self.isIntactShimDirectory(shipped) {
            directory = shipped
            ownsDirectory = false
            return
        }
        // Foundation can choose the per-user Darwin temp directory even when
        // the launch sandbox permits only its explicitly supplied TMPDIR.
        let ambient = ProcessInfo.processInfo.environment["TMPDIR"]
            .flatMap { $0.hasPrefix("/") ? URL(fileURLWithPath: $0, isDirectory: true) : nil }
        let root = temporaryDirectory ?? ambient ?? FileManager.default.temporaryDirectory
        var template = Array(root.appendingPathComponent("csec-ai-tools.XXXXXX").path.utf8CString)
        guard let path = mkdtemp(&template) else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        directory = URL(fileURLWithPath: String(cString: path), isDirectory: true)
        ownsDirectory = true
        do {
            let shim = directory.appendingPathComponent("op")
            try Data(Self.shimScript.utf8).write(to: shim, options: .withoutOverwriting)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: shim.path)
        } catch {
            try? FileManager.default.removeItem(at: directory)
            throw error
        }
    }

    /// `<bundle>/Contents/Resources/ai-guard` for an executable in
    /// `<bundle>/Contents/MacOS`; nil for any other layout (a SwiftPM build,
    /// the root-owned bridge copy).
    static func shippedDirectory(executablePath: String) -> URL? {
        let macOS = URL(fileURLWithPath: executablePath).deletingLastPathComponent()
        let contents = macOS.deletingLastPathComponent()
        guard macOS.lastPathComponent == "MacOS", contents.lastPathComponent == "Contents" else { return nil }
        return contents.appendingPathComponent("Resources/ai-guard", isDirectory: true)
    }

    /// The directory goes first on PATH, so it must hold nothing but the exact
    /// shim, and neither may be writable by anyone but its owner (root when
    /// installed, or this user, as for the temporary shim). Anything else falls
    /// back to the temporary shim rather than trusting it.
    static func isIntactShimDirectory(_ directory: URL) -> Bool {
        func ownedAndPrivate(_ path: String, type: mode_t) -> Bool {
            var info = stat()
            guard lstat(path, &info) == 0, info.st_mode & S_IFMT == type,
                  info.st_uid == 0 || info.st_uid == getuid() else { return false }
            return info.st_mode & (S_IWGRP | S_IWOTH) == 0
        }
        let shim = directory.appendingPathComponent("op")
        guard ownedAndPrivate(directory.path, type: S_IFDIR),
              (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) == ["op"],
              ownedAndPrivate(shim.path, type: S_IFREG),
              access(shim.path, X_OK) == 0,
              let contents = FileManager.default.contents(atPath: shim.path) else { return false }
        return contents == Data(shimScript.utf8)
    }

    /// Reject explicit calls (including absolute paths) before any secret
    /// request. Quoted text, comments and references are not commands.
    public static func invokesOPDirectly(_ program: String) -> Bool {
        invokesOPDirectly(program, depth: 0)
    }

    private static func invokesOPDirectly(_ program: String, depth: Int) -> Bool {
        guard depth < 8 else { return false }
        return (LauncherScript.simpleCommands(in: program) ?? []).contains { command in
            guard let name = command.name else { return false }
            let basename = (name as NSString).lastPathComponent.lowercased()
            if basename == "op" { return true }
            // A nested login shell can rebuild PATH again. Inspect literal -c
            // programs too; do not mistake script arguments or quoted prose
            // for executable commands.
            guard ["sh", "bash", "zsh"].contains(basename) else { return false }
            for (index, word) in command.arguments.enumerated() {
                guard case let .exact(option) = word, option.hasPrefix("-"),
                      !option.hasPrefix("--"), option.count > 1 else { return false }
                if option.dropFirst().contains("c") {
                    guard index + 1 < command.arguments.count,
                          case let .exact(inner) = command.arguments[index + 1] else { return false }
                    return invokesOPDirectly(inner, depth: depth + 1)
                }
                guard option.dropFirst().allSatisfy({ "aefilnrsuvx".contains($0) }) else { return false }
            }
            return false
        }
    }

    /// Login startup can reorder PATH. Apply the guard after it, preserving
    /// startup state and the original program's quoting, stdin and exit status.
    /// Policy and registration still bind the original requested program;
    /// only the launch uses this fixed csec-authored setup.
    public func commandLine(forProgram program: String) -> [String] {
        AICommandExec.commandLine(forProgram: setupStatements.map { $0 + "\n" }.joined() + program)
    }

    /// The same setup as `;`-terminated statements, for Claude Code's shell
    /// prefix (`ClaudeCodeShellPrefix`) to splice just before its framing's
    /// `eval`: the shell snapshot the framing sources first can reset PATH.
    public var framingSetup: String {
        setupStatements.map { $0 + ";" }.joined(separator: " ")
    }

    private var setupStatements: [String] {
        let quotedPath = "'" + directory.path.replacingOccurrences(of: "'", with: "'\\''", options: .literal) + "'"
        return [
            "builtin unalias op 2>/dev/null || :",
            "builtin unfunction op 2>/dev/null || :",
            "builtin export PATH=" + quotedPath + ":\"$PATH\"",
        ]
    }

    /// Called explicitly before _exit / signal termination, which skip defer.
    /// A killed launcher can leave a value-free temporary shim behind.
    public func cleanup() {
        guard ownsDirectory else { return }
        try? FileManager.default.removeItem(at: directory)
    }

    deinit { cleanup() }
}
