import Darwin
import Foundation

/// How `csec doctor`, and `csec setup` (csec-0.23), treat a csecd that has not
/// answered yet.
///
/// A csecd with nothing slowing it binds its sockets well within `settle`. On a
/// heavily loaded Mac it can take much longer: its first data-protection
/// Keychain read waits on secd before it binds anything (36 s at a load average
/// near 400, csec-tlnj). Doctor therefore keeps waiting while launchd still runs
/// the csecd it is waiting for, and does not restart one that is still young,
/// which would only throw away the startup work done so far. `ceiling` is a hang
/// guard: past it, a csecd that still does not answer is wedged, and doctor
/// restarts it or reports it as before.
public enum AgentStartupWait {
    /// Long enough for an unhindered csecd to answer.
    public static let settle: TimeInterval = 10
    /// The longest doctor waits on one csecd that launchd still runs.
    public static let ceiling: TimeInterval = 120

    /// Whether doctor should restart an unreachable csecd at once. One that
    /// failed identity verification is the old code image, which waiting cannot
    /// fix; one launchd is not running (`age` nil) has nothing to wait for.
    public static func restartNow(trustFailure: Bool, age: TimeInterval?) -> Bool {
        if trustFailure { return true }
        guard let age else { return true }
        return age >= ceiling
    }

    /// Whether doctor keeps waiting for csecd to answer, `elapsed` into this
    /// wait, while launchd's csecd has been running for `age` (nil when launchd
    /// runs none). Every wait ends by `ceiling`, even if launchd keeps
    /// relaunching a csecd that exits.
    public static func keepWaiting(elapsed: TimeInterval, age: TimeInterval?) -> Bool {
        if elapsed < settle { return true }
        guard let age, elapsed < ceiling else { return false }
        return age < ceiling
    }

    /// Whether a csecd that is still starting, or restarting for an update,
    /// could have caused `error`: nothing listening yet, a connection that
    /// broke or went silent, or a peer that failed identity verification (the
    /// previous build, still running until it notices the update and exits).
    /// A refused socket permission is a sandbox, and a protocol answer comes
    /// from a running csecd; waiting changes neither.
    public static func waitingCanFix(_ error: Error) -> Bool {
        guard let error = error as? AgentClient.ClientError else { return false }
        switch error {
        case .connectFailed, .untrustedServer, .transportFailed, .daemonUnresponsive, .connectionLost:
            return true
        case .connectPermissionDenied, .denied, .protocolFailure, .agentError:
            return false
        }
    }

    /// Ask `probe` until it answers, or fails in a way waiting cannot fix, or
    /// `keepWaiting` ends the wait for launchd's csecd, whose age `age` reads
    /// on each attempt. Returns the answer or the last failure, and how long
    /// the wait took.
    public static func poll<T>(
        interval: TimeInterval = 0.25,
        now: () -> Date = Date.init,
        sleep: (TimeInterval) -> Void = { usleep(useconds_t($0 * 1_000_000)) },
        age: () -> TimeInterval?,
        probe: () throws -> T
    ) -> (result: Result<T, Error>, waited: TimeInterval) {
        let started = now()
        while true {
            let result = Result { try probe() }
            let elapsed = now().timeIntervalSince(started)
            guard case let .failure(error) = result, waitingCanFix(error),
                  keepWaiting(elapsed: elapsed, age: age()) else {
                return (result, elapsed)
            }
            sleep(interval)
        }
    }

    /// The running pid in `launchctl print` output for the job, or nil when the
    /// job is not running. Only the job's own top-level fields count, never
    /// those of the endpoints or sockets nested inside it.
    public static func runningPID(launchctlPrint output: String) -> pid_t? {
        var running = false
        var pid: pid_t?
        for line in output.split(separator: "\n", omittingEmptySubsequences: false) {
            guard line.hasPrefix("\t"), !line.hasPrefix("\t\t") else { continue }
            let field = line.dropFirst().split(separator: "=", maxSplits: 1)
            guard field.count == 2 else { continue }
            let key = field[0].trimmingCharacters(in: .whitespaces)
            let value = field[1].trimmingCharacters(in: .whitespaces)
            switch key {
            case "state": running = value == "running"
            case "pid": pid = pid_t(value)
            default: break
            }
        }
        guard running, let pid, pid > 0 else { return nil }
        return pid
    }

    /// How long process `pid` has been running, or nil if it is gone.
    public static func processAge(pid: pid_t, now: Date = Date()) -> TimeInterval? {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0,
              size > 0, info.kp_proc.p_pid == pid else { return nil }
        let start = info.kp_proc.p_un.__p_starttime
        let started = Date(timeIntervalSince1970: TimeInterval(start.tv_sec)
            + TimeInterval(start.tv_usec) / 1_000_000)
        return max(0, now.timeIntervalSince(started))
    }
}
