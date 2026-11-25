#ifndef CS_SECURITY_SUPPORT_H
#define CS_SECURITY_SUPPORT_H

#include <stdint.h>

/// Create, bind, and listen on a unix-domain stream socket at `path`.
/// Unlinks any stale path first. Returns the listening fd, or -1 (errno set).
int cs_listen_unix(const char *path);

/// Connect a unix-domain stream socket to `path`. Returns the fd, or -1 with
/// errno preserved so callers can distinguish permission denial from an outage.
int cs_connect_unix(const char *path);

/// The same connect, bounded by `timeout_ms`. A wedged server that never calls
/// accept() fills its listen backlog, after which a blocking connect() waits
/// forever; this performs the connect non-blocking, waits for writability with
/// poll(), and restores blocking mode on the returned fd. On expiry it returns
/// -1 with errno ETIMEDOUT, which the caller reports as an unresponsive daemon
/// rather than an outage. A non-positive timeout means "no bound".
int cs_connect_unix_timeout(const char *path, int32_t timeout_ms);

/// Accept a connection on `listen_fd`. Returns the connected fd, or -1.
int cs_accept(int listen_fd);

/// Send/receive the four-byte frame header together with a bounded SCM_RIGHTS
/// descriptor set. The JSON body is written/read with the ordinary framing
/// helpers after this header. Send returns 0; receive returns the descriptor
/// count (possibly zero), or -1 on failure.
int32_t cs_send_frame_header_with_fds(
    int32_t fd, uint32_t body_length, const int32_t *fds, int32_t fd_count
);
int32_t cs_receive_frame_header_with_fds(
    int32_t fd, uint32_t *body_length, int32_t *fds, int32_t maximum_fd_count
);

/// PID of the socket peer via LOCAL_PEERTOKEN (kernel audit token), or -1.
/// This is trustworthy (kernel-provided); never use the self-reported PID.
int32_t cs_peer_pid(int fd);

/// Copy the socket peer's complete opaque audit_token_t into `buf`. Returns the
/// number of bytes copied, or -1. Callers must preserve the complete token: its
/// PID version binds process identity across PID reuse and Security.framework
/// can resolve the corresponding live code object from these bytes.
int32_t cs_peer_audit_token(int fd, void *buf, int32_t bufsize);

/// Safely extract fields from bytes returned by cs_peer_audit_token. The token
/// representation remains opaque to Swift; libbsm performs all interpretation.
int32_t cs_audit_token_pid(const void *buf, int32_t length);
uint32_t cs_audit_token_euid(const void *buf, int32_t length);
uint32_t cs_audit_token_asid(const void *buf, int32_t length);
int32_t cs_audit_token_pidversion(const void *buf, int32_t length);

/// Resolve the executable path using the complete audit token rather than a
/// reusable PID. Returns bytes written (NUL-terminated), or 0 on failure.
int32_t cs_proc_path_audit_token(
    const void *token_buf, int32_t token_length, char *path_buf, int32_t path_bufsize
);

/// The kernel's own code-signing facts for the image an audit token names,
/// each read with csops_audittoken: the code directory hash of the running
/// main executable (`cdhash`, CS_OPS_CDHASH, 20 bytes), its signing identifier
/// and Team ID (CS_OPS_IDENTITY / CS_OPS_TEAMID, NUL-terminated; `has_team` is
/// 0 when the signature names no team), and the live status flags
/// (CS_OPS_STATUS: CS_VALID, CS_RUNTIME, ...). The kernel refuses every read
/// with ESRCH once the token's PID version is not the process's current one,
/// so all four describe exactly the image the token named, never one exec'd
/// after it. The status is read last: CS_VALID can be cleared but never set
/// again within one image, so a set bit held when every other fact was read.
/// Nothing here touches the disk or trustd. Returns 0, or the errno of the
/// first read that failed (EINVAL for bad arguments, ERANGE when a string
/// does not fit its buffer).
int32_t cs_audit_token_code_facts(
    const void *token_buf, int32_t token_length,
    uint32_t *status_flags,
    uint8_t *cdhash, int32_t cdhash_size,
    char *identifier, int32_t identifier_size,
    char *team, int32_t team_size, int32_t *has_team
);

/// The kernel's live code-signing status flags (CS_OPS_STATUS: CS_VALID,
/// CS_PLATFORM_BINARY, ...) for whatever image `pid` runs now. The kernel
/// answers this for any user's process, a set-id root one included, which
/// `csops_audittoken` cannot reach without a task name port. Not exec-exact:
/// the caller brackets it with start-time reads and treats it as the facts
/// of the image it named by path. Returns 0, or an errno.
int32_t cs_proc_code_status(int32_t pid, uint32_t *status_flags);

/// Best-effort executable path for a PID. Callers that use this for a security
/// decision must compare the process start time before and after the lookup.
int32_t cs_proc_path(int32_t pid, char *path_buf, int32_t path_bufsize);

/// Whether an fd is a FIFO/pipe or local socket rather than a regular file or
/// terminal. Used to keep bridge plaintext off accidental stdout destinations.
int32_t cs_fd_is_pipe_or_socket(int fd);

/// Whether an fd is an ordinary regular file. The path used to open it is not
/// inspected or returned.
int32_t cs_fd_is_regular_file(int fd);

/// Parent PID of `pid`, or -1 if unavailable.
int32_t cs_proc_ppid(int32_t pid);

/// Start time of `pid` as microseconds since the epoch, or 0 if unavailable.
/// Used as a PID-reuse guard alongside the PID itself.
uint64_t cs_proc_start_time(int32_t pid);

/// Kernel process state (`SRUN`, `SSTOP`, etc.), or 0 if unavailable. This is
/// advisory lifecycle information, never a code-identity decision.
uint32_t cs_proc_status(int32_t pid);

/// Controlling terminal device of `pid`, or -1 when it has none (or the lookup
/// failed). Only the presence of a terminal is used: it distinguishes a real
/// interactive terminal session from the transient, pipe-wired shell a coding
/// agent creates per tool call. Advisory grant-scope input, never an identity gate.
int32_t cs_proc_controlling_terminal(int32_t pid);

/// Short accounting name of `pid` (e.g. "ruby", "psql") into `buf`. Returns the
/// number of bytes written (NUL-terminated), or 0 if unavailable. Advisory only
/// — shown to the human in the consent prompt, never used as an identity gate.
int32_t cs_proc_name(int32_t pid, char *buf, int32_t bufsize);

/// Name of the controlling terminal device of `pid` (e.g. "ttys012") into
/// `buf`. Returns 1 when written, 0 when the process has no controlling
/// terminal, or -1 when the lookup failed. Display-only: it tells the human
/// which terminal a request came from and is never an identity gate.
int32_t cs_proc_controlling_terminal_name(int32_t pid, char *buf, int32_t bufsize);

/// Copy the values of an allow-listed subset of the exec-time environment of
/// `pid` into `buf` as consecutive NUL-terminated "KEY=VALUE" entries. Returns
/// the number of entries written, or -1 when the environment is unreadable
/// (process gone, different user, withheld by the kernel for a restricted
/// process, a block larger than kern.argmax, an argv layout this parser does
/// not recognize, or `buf` too small for every match). The first occurrence of
/// a key wins, as getenv does. See `cs_procargs_layout` for the layout rules.
///
/// The kernel hands back the whole initial argv+environment block, which for a
/// csec-launched consumer can include injected plaintext. Only the named keys
/// are ever copied out; the scratch block is wiped with memset_s before it is
/// freed. Values reflect the environment at exec time, not later setenv calls.
int32_t cs_proc_env_subset(
    int32_t pid, const char *const *keys, int32_t key_count, char *buf, int32_t bufsize
);

/// One PROC_PIDTBSDINFO snapshot of the job-control facts of a process. Every
/// field comes from the same kernel read, so `start_time` binds the rest to one
/// process incarnation. `terminal_device` is NODEV (UINT32_MAX) when the
/// process has no controlling terminal; `terminal_process_group` is then 0.
typedef struct {
    int32_t pid;
    int32_t parent;
    int32_t process_group;
    int32_t terminal_process_group;
    uint32_t terminal_device;
    int32_t has_controlling_terminal; /* PROC_FLAG_CONTROLT */
    int32_t is_session_leader;        /* PROC_FLAG_SLEADER */
    int32_t is_traced;                /* PROC_FLAG_TRACED */
    uint32_t effective_uid;
    uint64_t start_time;              /* microseconds since the epoch */
} cs_job_facts;

/// Fill `out` from one bsdinfo read of `pid`. Returns 0, or -1 when the process
/// is gone or unreadable.
int32_t cs_proc_job_facts(int32_t pid, cs_job_facts *out);

/// The facts that tie a process to the session it was forked in. `unique_id`
/// is the kernel's p_uniqueid: one per pid allocation, in allocation order,
/// never reused within a boot and kept across exec.
typedef struct {
    int32_t pid;
    int32_t parent;
    int32_t session;                  /* getsid(pid) */
    uint64_t unique_id;
    uint64_t start_time;              /* microseconds since the epoch */
} cs_lineage_facts;

/// Fill `out` for `pid`. The unique ID is read first and last, so every field
/// belongs to one process incarnation. Returns 0, or -1 when the process is
/// gone, belongs to another user, or was replaced during the read.
int32_t cs_proc_lineage_facts(int32_t pid, cs_lineage_facts *out);

/// kern.maxproc, the most processes (zombies included) that can exist at
/// once, or -1 when unreadable.
int32_t cs_max_processes(void);

/// Classify descriptor `fd` of `pid`. Returns 1 when it is a character device
/// (its device number in `rdev`), 0 when it is open but anything else (pipe,
/// socket, regular file, directory, kqueue), and -1 when the process is gone or
/// the descriptor is not open. `/dev/null` is a character device; callers that
/// mean "this terminal" compare `rdev` against the controlling terminal.
int32_t cs_proc_fd_char_device(int32_t pid, int32_t fd, uint64_t *rdev);

/// The kernel's path for the current working directory of `pid` into `buf`,
/// plus the device, inode and file-system ID (`fsid[2]`, the mount's f_fsid)
/// of that directory vnode, all from one PROC_PIDVNODEPATHINFO read. The path
/// is the kernel's own (vn_getpath from the name cache): symlinks and
/// firmlinks resolved, the on-disk case. It is not re-checked against the file
/// system; a directory removed after the process entered it keeps its last
/// path. Returns bytes written (NUL-terminated), or 0 when unavailable.
///
/// The read itself makes one getattr call on the directory vnode (xnu
/// fill_vnodeinfo → vn_stat), which a network file system may answer over the
/// network: this call is not guaranteed not to block on such a mount.
int32_t cs_proc_cwd(
    int32_t pid, char *buf, int32_t bufsize, uint64_t *device, uint64_t *inode, int32_t *fsid
);

/// The regular file open on descriptor `fd` of `pid`, from one
/// PROC_PIDFDVNODEPATHINFO read: the kernel's path for it into `buf`, plus its
/// device, inode, file-system ID (`fsid[2]`), size and status-change time.
/// The path is the kernel's own (vn_getpath), so symlinks are resolved, and
/// it is not re-checked against the file system. Returns bytes written
/// (NUL-terminated) for an open regular file whose whole path fits, 0 when the
/// descriptor is open but is not a regular file or its path is unavailable or
/// may be truncated (the kernel keeps only the tail of a path that fills
/// MAXPATHLEN), and -1 when the process is gone or the descriptor is not open
/// or is not a vnode.
///
/// Like cs_proc_cwd, the read makes one getattr call on the vnode, which a
/// network file system may answer over the network.
int32_t cs_proc_fd_vnode(
    int32_t pid, int32_t fd, char *buf, int32_t bufsize, uint64_t *device, uint64_t *inode,
    int32_t *fsid, int64_t *size, int64_t *ctime_seconds, int64_t *ctime_nanoseconds
);

/// The mount whose file-system ID is {fsid0, fsid1}, from the kernel's cached
/// mount table (getfsstat with MNT_NOWAIT, which never calls into a file
/// system): whether it is MNT_LOCAL, its mount point and its type name.
/// Returns 1 when found, 0 when no mount has that ID, -1 on error.
int32_t cs_mount_lookup(
    int32_t fsid0, int32_t fsid1, int32_t *is_local,
    char *mount_point, int32_t mount_point_size, char *type_name, int32_t type_name_size
);

/// Whether every mount whose mount point is `path` or one of its ancestors is
/// MNT_LOCAL, from the same cached mount table; a pure string comparison that
/// never touches a file system. For a canonical path (symlinks resolved), a
/// lookup of it only passes through those mounts, plus the local volumes the
/// system firmlinks join. Returns 1, 0, or -1 (error or relative path).
int32_t cs_path_mounts_local(const char *path);

/// Copy only the argv strings of `pid` from KERN_PROCARGS2 into `buf` as
/// consecutive NUL-terminated strings. The exec path and every environment
/// entry are skipped and never copied. Returns the number of strings written,
/// or -1 (process gone, another user's, a block larger than kern.argmax, a
/// layout `cs_procargs_layout` rejects, or `buf` too small). The kernel block
/// and, on failure, `buf` are wiped with memset_s: argv is caller-controlled
/// and can hold anything, so it is handled as untrusted, possibly sensitive
/// metadata.
int32_t cs_proc_argv(int32_t pid, char *buf, int32_t bufsize);

/// Report which exact environment names, and which name prefixes, occur in the
/// exec-time environment of `pid`, without copying any value. `name_present[i]`
/// and `prefix_present[j]` receive how many entries matched, saturating at 255,
/// so a duplicated name is visible. A prefix matches a name that starts with it
/// (the name may equal it). Names and prefixes must be non-empty. Returns 0, or
/// -1 when the environment is unreadable: withheld by the kernel, in a block
/// larger than kern.argmax, or in a layout `cs_procargs_layout` rejects. The
/// kernel block is wiped with memset_s.
int32_t cs_proc_env_names_present(
    int32_t pid,
    const char *const *names, int32_t name_count,
    const char *const *prefixes, int32_t prefix_count,
    uint8_t *name_present, uint8_t *prefix_present
);

/// The audit token of an arbitrary same-user process, via task_name_for_pid and
/// task_info(TASK_AUDIT_TOKEN). Unlike a PID, the token's PID version changes on
/// exec, so Security.framework resolves exactly the image that was running.
/// Returns the number of bytes copied; -1 when task_name_for_pid refused the
/// name port; -2 when the port was granted but the token could not be read or
/// names another PID (the task exited or the PID was reused in between). In
/// both failures `kern_status` receives the kern_return_t of the failing step.
int32_t cs_task_audit_token(
    int32_t pid, void *buf, int32_t bufsize, int32_t *kern_status
);

/// The layout rules every KERN_PROCARGS2 reader above applies, as a pure
/// function over a block the kernel returned: `size` bytes read into a buffer
/// of `capacity` bytes. Returns argc, with the offsets of argv[0] and of the
/// first byte after argv, or -1 when the block is unreadable:
///
/// - it fills the buffer: the kernel returns the *tail* of a block larger than
///   the buffer, argc still in front, so an exact fit is refused too;
/// - argv[0] does not start where xnu puts it (the pointer-aligned offset
///   after the exec path, with only NUL padding between) or is empty;
/// - argc is negative or its strings overrun the block;
/// - `require_environment` is set and nothing follows argv, which is how the
///   kernel withholds a restricted process's environment.
int32_t cs_procargs_layout(
    const char *block, uint64_t size, uint64_t capacity, int32_t require_environment,
    uint64_t *argv_offset, uint64_t *after_argv_offset
);

/// PIDs of every process whose effective UID is `uid` (zombies included; the
/// caller's start-time read drops them). Returns the total count, which may
/// exceed `maximum_pids`, or -1.
int32_t cs_list_user_pids(uint32_t uid, int32_t *pids, int32_t maximum_pids);

/// Snapshot the live process credential used by the kernel for filesystem
/// checks. Returns the number of groups, or -1. The effective/real/saved GIDs
/// are all included exactly once when room permits.
int32_t cs_proc_groups(int32_t pid, uint32_t *groups, int32_t maximum_groups);

/// Capability-GID allocation/lifecycle helpers. These inspect every live
/// process credential, including supplementary groups. `cs_pids_with_gid`
/// returns the total holder count (which may exceed `maximum_pids`) or -1.
int32_t cs_gid_is_assigned(uint32_t gid);
int32_t cs_gid_has_live_holder(uint32_t gid);
int32_t cs_pid_has_gid(int32_t pid, uint32_t gid);
int32_t cs_pids_with_gid(uint32_t gid, int32_t *pids, int32_t maximum_pids);

/// Boot time in microseconds since the epoch, used to scope the persistent
/// non-reuse cursor. Returns 0 if unavailable.
uint64_t cs_boot_time(void);

/// Observe an owned child's exit without reaping it (PID remains reserved).
/// Returns 1 exited, 0 still running, -1 error; status is exit code or 128+signal.
int32_t cs_peek_child_exit(int32_t pid, int32_t *status);

/// Current process audit session ID, or UINT32_MAX on failure.
uint32_t cs_self_audit_session_id(void);

/// Verify that `path` is a tmpfs mounted with nodev,nosuid,noexec,nobrowse and
/// bounded no larger than the supplied byte/node ceilings. Returns 1 when
/// secure, 0 when it is not a tmpfs/misses a property, and -1 on statfs failure.
int32_t cs_secure_tmpfs_status(
    const char *path, uint64_t maximum_bytes, uint64_t maximum_nodes
);

/// Child output wiring used by the csec process supervisor.
typedef enum {
    CS_OUTPUT_INHERIT = 0,
    CS_OUTPUT_PIPE = 1,
    CS_OUTPUT_PTY = 2,
} cs_output_mode;

/// The `cs_spawn_supervised` step whose failure ended a launch.
typedef enum {
    CS_SPAWN_STEP_NONE = 0,
    CS_SPAWN_STEP_SETUP = 1,
    CS_SPAWN_STEP_FORK = 2,
    CS_SPAWN_STEP_CHDIR = 3,
    CS_SPAWN_STEP_SETSID = 4,
    CS_SPAWN_STEP_CONTROLLING_TERMINAL = 5,
    CS_SPAWN_STEP_FOREGROUND_GROUP = 6,
    CS_SPAWN_STEP_PROCESS_GROUP = 7,
    CS_SPAWN_STEP_STANDARD_STREAMS = 8,
    CS_SPAWN_STEP_INHERITED_FDS = 9,
    CS_SPAWN_STEP_EXEC = 10,
    CS_SPAWN_STEP_EXEC_STATUS = 11,
} cs_spawn_step;

/// Spawn an executable in a new process group with an exact caller-supplied
/// environment. Captured streams are returned as parent-side read fds; PTY
/// streams share `pty_master_fd`. `inherited_fds` names already-open descriptors
/// whose close-on-exec flag is cleared in the child only. The function returns
/// success only after the kernel has replaced the child image with `execve`, so
/// the parent can begin writing inherited secret pipes after the target exists.
/// A non-NULL `working_directory` is entered in the child before exec.
/// No secret is installed into the supervisor's own environment.
/// On failure `failed_step` names the step that set errno, so a launch error
/// can say which call the kernel refused rather than only its errno.
int32_t cs_spawn_supervised(
    const char *executable_path,
    char *const argv[],
    char *const envp[],
    const char *working_directory,
    int32_t stdin_uses_pty,
    cs_output_mode stdout_mode,
    cs_output_mode stderr_mode,
    const int32_t *inherited_fds,
    int32_t inherited_fd_count,
    int32_t *child_pid,
    int32_t *pty_master_fd,
    int32_t *stdout_read_fd,
    int32_t *stderr_read_fd,
    cs_spawn_step *failed_step
);

/// Root-helper launch primitive. The caller has already authenticated and
/// validated the plan, opened cwd/stdio, created protected files, and selected
/// an unused capability GID. The child joins the launcher's audit session,
/// obtains its own process group (and controlling PTY when requested), drops to
/// `uid` with the capability as real/effective/saved primary GID, disables core
/// dumps, closes every unintended descriptor, and execs the exact path.
/// Success is returned only after execve closes the status pipe.
int32_t cs_spawn_with_capability_gid(
    const char *executable_path,
    char *const argv[],
    char *const envp[],
    int32_t cwd_fd,
    int32_t stdin_fd,
    int32_t stdout_fd,
    int32_t stderr_fd,
    uint32_t uid,
    uint32_t capability_gid,
    const uint32_t *supplementary_groups,
    int32_t supplementary_group_count,
    uint32_t audit_session_id,
    int32_t uses_pty,
    int32_t drop_credentials,
    int32_t *child_pid,
    uint64_t *child_start_time
);

/// Set O_NONBLOCK while preserving existing descriptor flags.
int32_t cs_fd_set_nonblocking(int32_t fd);

/// Prevent this process and its descendants from writing memory-bearing core dumps.
int32_t cs_disable_core_dumps(void);

/// Create a close-on-exec, nonblocking self-pipe and route supervisor-relevant
/// signals into it as one-byte signal numbers. The child must be spawned before
/// handlers are installed so it starts with the caller's original dispositions.
int32_t cs_supervisor_signal_pipe(int32_t fds[2]);
int32_t cs_supervisor_install_signal_handlers(int32_t write_fd);
void cs_supervisor_restore_signal_handlers(void);

/// Put the original input terminal into raw relay mode and later restore it.
/// Calls are idempotent so every supervisor exit path can safely clean up.
int32_t cs_terminal_enter_raw(int32_t fd);
void cs_terminal_restore(void);

/// Copy the size of the first available standard terminal onto the child PTY.
int32_t cs_resize_pty_from_standard_terminal(int32_t pty_master_fd);

/// Allocate a close-on-exec PTY pair using the first available standard
/// terminal's attributes and size. Returns 0 on success.
int32_t cs_open_standard_pty(int32_t *master_fd, int32_t *slave_fd);

/// Portable wrappers for wait status macros, which Swift cannot import.
int32_t cs_wait_status_exited(int32_t status);
int32_t cs_wait_status_exit_code(int32_t status);
int32_t cs_wait_status_signaled(int32_t status);
int32_t cs_wait_status_signal(int32_t status);
int32_t cs_wait_status_stopped(int32_t status);
int32_t cs_wait_status_stop_signal(int32_t status);
int32_t cs_wait_status_continued(int32_t status);

/// Stop the supervisor after its child stops, and finish with the same exit or
/// signal status as the child once all redacted output has been forwarded.
int32_t cs_supervisor_suspend_self(int32_t signal_number);
void cs_terminate_like_wait_status(int32_t status) __attribute__((noreturn));

#endif /* CS_SECURITY_SUPPORT_H */
