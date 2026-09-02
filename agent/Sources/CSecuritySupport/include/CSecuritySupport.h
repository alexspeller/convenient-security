#ifndef CS_SECURITY_SUPPORT_H
#define CS_SECURITY_SUPPORT_H

#include <stdint.h>

/// Create, bind, and listen on a unix-domain stream socket at `path`.
/// Unlinks any stale path first. Returns the listening fd, or -1 (errno set).
int cs_listen_unix(const char *path);

/// Connect a unix-domain stream socket to `path`. Returns the fd, or -1.
int cs_connect_unix(const char *path);

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

/// Spawn an executable in a new process group with an exact caller-supplied
/// environment. Captured streams are returned as parent-side read fds; PTY
/// streams share `pty_master_fd`. `inherited_fds` names already-open descriptors
/// whose close-on-exec flag is cleared in the child only. The function returns
/// success only after the kernel has replaced the child image with `execve`, so
/// the parent can begin writing inherited secret pipes after the target exists.
/// A non-NULL `working_directory` is entered in the child before exec.
/// No secret is installed into the supervisor's own environment.
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
    int32_t *stderr_read_fd
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
