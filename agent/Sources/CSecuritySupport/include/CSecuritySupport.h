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

/// Parent PID of `pid`, or -1 if unavailable.
int32_t cs_proc_ppid(int32_t pid);

/// Start time of `pid` as microseconds since the epoch, or 0 if unavailable.
/// Used as a PID-reuse guard alongside the PID itself.
uint64_t cs_proc_start_time(int32_t pid);

/// Kernel process state (`SRUN`, `SSTOP`, etc.), or 0 if unavailable. This is
/// advisory lifecycle information, never a code-identity decision.
uint32_t cs_proc_status(int32_t pid);

/// Short accounting name of `pid` (e.g. "ruby", "psql") into `buf`. Returns the
/// number of bytes written (NUL-terminated), or 0 if unavailable. Advisory only
/// — shown to the human in the consent prompt, never used as an identity gate.
int32_t cs_proc_name(int32_t pid, char *buf, int32_t bufsize);

/// Child output wiring used by the csec process supervisor.
typedef enum {
    CS_OUTPUT_INHERIT = 0,
    CS_OUTPUT_PIPE = 1,
    CS_OUTPUT_PTY = 2,
} cs_output_mode;

/// Spawn an executable in a new process group with an exact caller-supplied
/// environment. Captured streams are returned as parent-side read fds; PTY
/// streams share `pty_master_fd`. No secret is installed into the supervisor's
/// own environment.
int32_t cs_spawn_supervised(
    const char *executable_path,
    char *const argv[],
    char *const envp[],
    int32_t stdin_uses_pty,
    cs_output_mode stdout_mode,
    cs_output_mode stderr_mode,
    int32_t *child_pid,
    int32_t *pty_master_fd,
    int32_t *stdout_read_fd,
    int32_t *stderr_read_fd
);

/// Set O_NONBLOCK while preserving existing descriptor flags.
int32_t cs_fd_set_nonblocking(int32_t fd);

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
