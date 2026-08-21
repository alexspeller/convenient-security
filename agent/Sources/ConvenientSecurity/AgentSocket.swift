import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Canonical location of the agent's unix socket, shared by the daemon and every
/// client: `<per-user temp dir>/convenient-security-<uid>/agent.sock`, inside a
/// private 0700 directory.
public enum AgentSocket {
    /// True only in a debug build when an isolated integration-test endpoint is
    /// selected. Release builds compile out both the lookup and this result.
    public static var isUsingDebugOverride: Bool {
        #if DEBUG
        if let override = ProcessInfo.processInfo.environment["CSEC_SOCKET"] {
            return !override.isEmpty
        }
        #endif
        return false
    }

    public static func directory() -> String {
        let base = userTemporaryDirectory()
        return (base as NSString).appendingPathComponent("convenient-security-\(getuid())")
    }

    /// The per-user Darwin temp dir (`/var/folders/…/T/`), resolved from the uid
    /// via `confstr(_CS_DARWIN_USER_TEMP_DIR)` rather than the `$TMPDIR` env var.
    /// This is deliberate: the agent runs as a launchd LaunchAgent and clients run
    /// from a shell, and the two can be handed different `$TMPDIR` values (or none,
    /// falling back to `/tmp`). `confstr` is keyed on the uid, so both processes
    /// compute the SAME directory regardless of their environment. Falls back to
    /// `$TMPDIR` then `/tmp` only if the syscall yields nothing.
    private static func userTemporaryDirectory() -> String {
        #if canImport(Darwin)
        let size = confstr(_CS_DARWIN_USER_TEMP_DIR, nil, 0)
        if size > 0 {
            var buffer = [Int8](repeating: 0, count: size)
            if confstr(_CS_DARWIN_USER_TEMP_DIR, &buffer, size) == size {
                let path = String(cString: buffer)
                if !path.isEmpty { return path }
            }
        }
        #endif
        return ProcessInfo.processInfo.environment["TMPDIR"] ?? "/tmp"
    }

    /// The socket clients connect to. Debug builds accept `CSEC_SOCKET` for
    /// isolated integration tests. Release builds always use the canonical path:
    /// a test endpoint selected from the environment would let same-uid malware
    /// redirect a shipping client or start a second signed agent on its own
    /// endpoint.
    public static func defaultPath() -> String {
        if isUsingDebugOverride {
            return ProcessInfo.processInfo.environment["CSEC_SOCKET"]!
        }
        return (directory() as NSString).appendingPathComponent("agent.sock")
    }

    /// Ensure the containing directory exists and is private (0700), whether it
    /// is being created now or already existed.
    public static func ensureDirectory() throws {
        let dir = directory()
        let fm = FileManager.default
        if fm.fileExists(atPath: dir) {
            try fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir)
        } else {
            try fm.createDirectory(
                atPath: dir,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
    }
}
