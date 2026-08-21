import Foundation
import CSecuritySupport

/// Verifies process ancestry for subtree-scoped grants.
///
/// A connection's PID (from the kernel audit token) is honored against a grant
/// iff walking `pid → ppid → …` reaches the grant's `rootPID` with a matching
/// start time. `ppid` is kernel-assigned at `fork` and cannot be self-reparented
/// onto an arbitrary process, so malware cannot graft itself into a granted
/// subtree. See DESIGN.md (Grant model).
public enum ProcessAncestry {
    /// Start time of `pid` (epoch microseconds), or nil if the process is gone.
    public static func startTime(of pid: pid_t) -> UInt64? {
        let t = cs_proc_start_time(pid)
        return t == 0 ? nil : t
    }

    /// Advisory lifecycle state used by supervisor diagnostics/tests. A stopped
    /// state is never sufficient for an authorization decision.
    public static func isStopped(_ pid: pid_t) -> Bool {
        cs_proc_status(pid) == 4 // SSTOP from <sys/proc.h>
    }

    /// Parent PID of `pid`, or nil if unavailable.
    public static func parent(of pid: pid_t) -> pid_t? {
        let p = cs_proc_ppid(pid)
        return p < 0 ? nil : p
    }

    /// Short process name (e.g. "ruby"), or nil. Advisory only — shown to the
    /// human in the consent prompt, never trusted as an identity gate.
    public static func name(of pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: 256)
        let written = cs_proc_name(pid, &buffer, Int32(buffer.count))
        guard written > 0 else { return nil }
        let name = String(cString: buffer)
        return name.isEmpty ? nil : name
    }

    /// Executable path guarded against PID reuse during the lookup.
    public static func executablePath(of pid: pid_t) -> String? {
        guard let before = startTime(of: pid) else { return nil }
        var buffer = [CChar](repeating: 0, count: 4 * 1_024)
        let written = cs_proc_path(pid, &buffer, Int32(buffer.count))
        guard written > 0, startTime(of: pid) == before else { return nil }
        let path = String(cString: buffer)
        return path.isEmpty ? nil : path
    }

    /// Whether `pid` is `root` or descends from it, with `root`'s start time
    /// matching `rootStartTime` (the PID-reuse guard).
    public static func descends(_ pid: pid_t, from root: pid_t, rootStartTime: UInt64) -> Bool {
        // The root must still be the same process that was granted.
        guard startTime(of: root) == rootStartTime else { return false }

        var current = pid
        var hops = 0
        while hops < 128 {
            if current == root { return true }
            // pid 1 is launchd; reaching it means we never hit `root`.
            if current <= 1 { return false }
            guard let next = parent(of: current), next != current else { return false }
            current = next
            hops += 1
        }
        return false
    }
}
