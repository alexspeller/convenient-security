import Darwin

/// The PAM module runs inside set-id-root sudo and spawns the helper as the
/// login user. A pipe and a valid frame alone do not authenticate that sender.
public enum SudoReviewParentTrust {
    public static func isTrusted(
        originalParent: pid_t,
        currentParent: () -> pid_t = { getppid() }
    ) -> Bool {
        isTrusted(
            originalParent: originalParent,
            currentParent: currentParent,
            effectiveUID: { sudoKernelProcess($0)?.kp_eproc.e_ucred.cr_uid }
        )
    }

    /// Injectable kernel reads keep failures and reparenting testable without
    /// launching a privileged process. Re-read the parent after the UID lookup:
    /// an orphan belongs to launchd, not to the root process that used this PID.
    public static func isTrusted(
        originalParent: pid_t,
        currentParent: () -> pid_t,
        effectiveUID: (pid_t) -> uid_t?
    ) -> Bool {
        guard originalParent > 1, currentParent() == originalParent,
              effectiveUID(originalParent) == 0 else { return false }
        return currentParent() == originalParent
    }
}

/// Unlike libproc's BSD info, KERN_PROC_PID is readable by the login user for
/// a set-id-root parent. XNU fills e_ucred.cr_uid with its effective UID; sudo's
/// real UID is normally the login user. A short, missing or stale record fails
/// closed, including a zombie that has already reparented its children.
func sudoKernelProcess(_ pid: pid_t) -> kinfo_proc? {
    guard pid > 0 else { return nil }
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.stride
    guard sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0) == 0,
          size == MemoryLayout<kinfo_proc>.stride,
          info.kp_proc.p_pid == pid,
          Int32(info.kp_proc.p_stat) != SZOMB else { return nil }
    return info
}
