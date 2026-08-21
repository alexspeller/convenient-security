#include "CSecuritySupport.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <termios.h>
#include <util.h>

static int cs_set_cloexec(int fd);

static int cs_disable_sigpipe(int fd) {
    int enabled = 1;
    return setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled));
}

int cs_listen_unix(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (cs_set_cloexec(fd) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    unlink(path);
    if (bind(fd, (struct sockaddr *)&addr, (socklen_t)SUN_LEN(&addr)) < 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 16) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int cs_connect_unix(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (cs_disable_sigpipe(fd) != 0 || cs_set_cloexec(fd) != 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(addr.sun_path)) {
        close(fd);
        errno = ENAMETOOLONG;
        return -1;
    }
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, (socklen_t)SUN_LEN(&addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int cs_accept(int listen_fd) {
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) return -1;
    if (cs_disable_sigpipe(fd) != 0 || cs_set_cloexec(fd) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int32_t cs_peer_pid(int fd) {
    audit_token_t token;
    socklen_t len = sizeof(token);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) != 0) return -1;
    return (int32_t)audit_token_to_pid(token);
}

int32_t cs_peer_audit_token(int fd, void *buf, int32_t bufsize) {
    if (buf == NULL || bufsize < (int32_t)sizeof(audit_token_t)) return -1;

    audit_token_t token;
    socklen_t len = sizeof(token);
    if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &len) != 0) return -1;
    if (len != sizeof(token)) return -1;

    memcpy(buf, &token, sizeof(token));
    return (int32_t)sizeof(token);
}

static int cs_copy_audit_token(const void *buf, int32_t length, audit_token_t *token) {
    if (buf == NULL || token == NULL || length != (int32_t)sizeof(audit_token_t)) return 0;
    memcpy(token, buf, sizeof(*token));
    return 1;
}

int32_t cs_audit_token_pid(const void *buf, int32_t length) {
    audit_token_t token;
    if (!cs_copy_audit_token(buf, length, &token)) return -1;
    return (int32_t)audit_token_to_pid(token);
}

uint32_t cs_audit_token_euid(const void *buf, int32_t length) {
    audit_token_t token;
    if (!cs_copy_audit_token(buf, length, &token)) return UINT32_MAX;
    return (uint32_t)audit_token_to_euid(token);
}

uint32_t cs_audit_token_asid(const void *buf, int32_t length) {
    audit_token_t token;
    if (!cs_copy_audit_token(buf, length, &token)) return UINT32_MAX;
    return (uint32_t)audit_token_to_asid(token);
}

int32_t cs_audit_token_pidversion(const void *buf, int32_t length) {
    audit_token_t token;
    if (!cs_copy_audit_token(buf, length, &token)) return -1;
    return (int32_t)audit_token_to_pidversion(token);
}

int32_t cs_proc_path_audit_token(
    const void *token_buf, int32_t token_length, char *path_buf, int32_t path_bufsize
) {
    if (path_buf == NULL || path_bufsize <= 0) return 0;
    path_buf[0] = '\0';

    audit_token_t token;
    if (!cs_copy_audit_token(token_buf, token_length, &token)) return 0;

    int n = proc_pidpath_audittoken(&token, path_buf, (uint32_t)path_bufsize);
    if (n <= 0) {
        path_buf[0] = '\0';
        return 0;
    }
    return (int32_t)n;
}

int32_t cs_proc_path(int32_t pid, char *path_buf, int32_t path_bufsize) {
    if (path_buf == NULL || path_bufsize <= 0 || pid <= 0) return 0;
    path_buf[0] = '\0';
    int n = proc_pidpath(pid, path_buf, (uint32_t)path_bufsize);
    if (n <= 0) {
        path_buf[0] = '\0';
        return 0;
    }
    return (int32_t)n;
}

int32_t cs_fd_is_pipe_or_socket(int fd) {
    struct stat info;
    if (fstat(fd, &info) != 0) return 0;
    return (S_ISFIFO(info.st_mode) || S_ISSOCK(info.st_mode)) ? 1 : 0;
}

int32_t cs_proc_ppid(int32_t pid) {
    struct proc_bsdshortinfo info;
    int n = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, sizeof(info));
    if (n != (int)sizeof(info)) return -1;
    return (int32_t)info.pbsi_ppid;
}

uint64_t cs_proc_start_time(int32_t pid) {
    struct proc_bsdinfo info;
    int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (n != (int)sizeof(info)) return 0;
    return (uint64_t)info.pbi_start_tvsec * 1000000ULL + (uint64_t)info.pbi_start_tvusec;
}

uint32_t cs_proc_status(int32_t pid) {
    struct proc_bsdshortinfo info;
    int n = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 0, &info, sizeof(info));
    if (n != (int)sizeof(info)) return 0;
    return info.pbsi_status;
}

int32_t cs_proc_name(int32_t pid, char *buf, int32_t bufsize) {
    if (buf == NULL || bufsize <= 0) return 0;
    buf[0] = '\0';
    int n = proc_name(pid, buf, (uint32_t)bufsize);
    if (n <= 0) {
        buf[0] = '\0';
        return 0;
    }
    return (int32_t)n;
}

static int cs_set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

int32_t cs_fd_set_nonblocking(int32_t fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 ? 0 : -1;
}

static int cs_make_pipe(int fds[2], int nonblocking) {
    if (pipe(fds) != 0) return -1;
    if (cs_set_cloexec(fds[0]) != 0 || cs_set_cloexec(fds[1]) != 0
            || (nonblocking && (cs_fd_set_nonblocking(fds[0]) != 0
                                || cs_fd_set_nonblocking(fds[1]) != 0))) {
        int saved_errno = errno;
        close(fds[0]);
        close(fds[1]);
        errno = saved_errno;
        return -1;
    }
    return 0;
}

static int cs_ensure_standard_fds(void) {
    for (int fd = STDIN_FILENO; fd <= STDERR_FILENO; fd++) {
        if (fcntl(fd, F_GETFD) >= 0) continue;
        if (errno != EBADF) return -1;
        int mode = fd == STDIN_FILENO ? O_RDONLY : O_WRONLY;
        int replacement = open("/dev/null", mode);
        if (replacement < 0) return -1;
        if (replacement != fd) {
            if (dup2(replacement, fd) < 0) {
                int saved_errno = errno;
                close(replacement);
                errno = saved_errno;
                return -1;
            }
            close(replacement);
        }
    }
    return 0;
}

static void cs_close_if_open(int fd) {
    if (fd >= 0) close(fd);
}

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
) {
    if (executable_path == NULL || argv == NULL || envp == NULL
            || child_pid == NULL || pty_master_fd == NULL
            || stdout_read_fd == NULL || stderr_read_fd == NULL
            || (stdout_mode != CS_OUTPUT_INHERIT && stdout_mode != CS_OUTPUT_PIPE
                && stdout_mode != CS_OUTPUT_PTY)
            || (stderr_mode != CS_OUTPUT_INHERIT && stderr_mode != CS_OUTPUT_PIPE
                && stderr_mode != CS_OUTPUT_PTY)) {
        errno = EINVAL;
        return -1;
    }
    if (cs_ensure_standard_fds() != 0) return -1;

    *child_pid = -1;
    *pty_master_fd = -1;
    *stdout_read_fd = -1;
    *stderr_read_fd = -1;

    int pty_master = -1, pty_slave = -1;
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    int needs_pty = stdin_uses_pty || stdout_mode == CS_OUTPUT_PTY
        || stderr_mode == CS_OUTPUT_PTY;

    if (needs_pty) {
        int terminal_fd = isatty(STDIN_FILENO) ? STDIN_FILENO
            : (isatty(STDOUT_FILENO) ? STDOUT_FILENO
                                     : (isatty(STDERR_FILENO) ? STDERR_FILENO : -1));
        struct termios attributes;
        struct winsize size;
        struct termios *attributes_ptr = NULL;
        struct winsize *size_ptr = NULL;
        if (terminal_fd >= 0 && tcgetattr(terminal_fd, &attributes) == 0) {
            attributes_ptr = &attributes;
        }
        if (terminal_fd >= 0 && ioctl(terminal_fd, TIOCGWINSZ, &size) == 0) {
            size_ptr = &size;
        }
        if (openpty(&pty_master, &pty_slave, NULL, attributes_ptr, size_ptr) != 0) goto fail;
        if (cs_set_cloexec(pty_master) != 0 || cs_set_cloexec(pty_slave) != 0) goto fail;
    }
    if (stdout_mode == CS_OUTPUT_PIPE && cs_make_pipe(stdout_pipe, 0) != 0) goto fail;
    if (stderr_mode == CS_OUTPUT_PIPE && cs_make_pipe(stderr_pipe, 0) != 0) goto fail;

    pid_t pid = fork();
    if (pid < 0) goto fail;
    if (pid == 0) {
        if (needs_pty) {
            if (setsid() < 0 || ioctl(pty_slave, TIOCSCTTY, 0) < 0
                    || tcsetpgrp(pty_slave, getpgrp()) < 0) _exit(126);
        } else if (setpgid(0, 0) != 0) {
            _exit(126);
        }

        if (stdin_uses_pty && dup2(pty_slave, STDIN_FILENO) < 0) _exit(126);
        if (stdout_mode == CS_OUTPUT_PTY && dup2(pty_slave, STDOUT_FILENO) < 0) _exit(126);
        if (stdout_mode == CS_OUTPUT_PIPE && dup2(stdout_pipe[1], STDOUT_FILENO) < 0) _exit(126);
        if (stderr_mode == CS_OUTPUT_PTY && dup2(pty_slave, STDERR_FILENO) < 0) _exit(126);
        if (stderr_mode == CS_OUTPUT_PIPE && dup2(stderr_pipe[1], STDERR_FILENO) < 0) _exit(126);

        cs_close_if_open(pty_master);
        cs_close_if_open(pty_slave);
        cs_close_if_open(stdout_pipe[0]);
        cs_close_if_open(stdout_pipe[1]);
        cs_close_if_open(stderr_pipe[0]);
        cs_close_if_open(stderr_pipe[1]);

        execve(executable_path, argv, envp);
        int exec_errno = errno;
        static const char message[] = "csec exec: target exec failed\n";
        (void)write(STDERR_FILENO, message, sizeof(message) - 1);
        _exit(exec_errno == ENOENT ? 127 : 126);
    }

    if (!needs_pty) (void)setpgid(pid, pid);
    cs_close_if_open(pty_slave);
    cs_close_if_open(stdout_pipe[1]);
    cs_close_if_open(stderr_pipe[1]);

    *child_pid = (int32_t)pid;
    *pty_master_fd = (int32_t)pty_master;
    *stdout_read_fd = (int32_t)stdout_pipe[0];
    *stderr_read_fd = (int32_t)stderr_pipe[0];
    return 0;

fail: {
        int saved_errno = errno;
        cs_close_if_open(pty_master);
        cs_close_if_open(pty_slave);
        cs_close_if_open(stdout_pipe[0]);
        cs_close_if_open(stdout_pipe[1]);
        cs_close_if_open(stderr_pipe[0]);
        cs_close_if_open(stderr_pipe[1]);
        errno = saved_errno;
        return -1;
    }
}

static const int cs_supervisor_signals[] = {
    SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGTSTP, SIGTTIN, SIGTTOU,
    SIGCONT, SIGWINCH, SIGCHLD
};
static struct sigaction cs_saved_signal_actions[
    sizeof(cs_supervisor_signals) / sizeof(cs_supervisor_signals[0])
];
static struct sigaction cs_saved_sigpipe_action;
static volatile sig_atomic_t cs_signal_write_fd = -1;
static int cs_signal_handlers_active = 0;

static void cs_supervisor_signal_handler(int signal_number) {
    int saved_errno = errno;
    if (cs_signal_write_fd >= 0) {
        uint8_t byte = (uint8_t)signal_number;
        (void)write((int)cs_signal_write_fd, &byte, sizeof(byte));
    }
    errno = saved_errno;
}

int32_t cs_supervisor_signal_pipe(int32_t fds[2]) {
    if (fds == NULL) {
        errno = EINVAL;
        return -1;
    }
    int raw[2];
    if (cs_make_pipe(raw, 1) != 0) return -1;
    fds[0] = raw[0];
    fds[1] = raw[1];
    return 0;
}

int32_t cs_supervisor_install_signal_handlers(int32_t write_fd) {
    if (write_fd < 0 || cs_signal_handlers_active) {
        errno = EINVAL;
        return -1;
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = cs_supervisor_signal_handler;
    sigemptyset(&action.sa_mask);

    cs_signal_write_fd = write_fd;
    size_t installed = 0;
    for (size_t i = 0; i < sizeof(cs_supervisor_signals) / sizeof(cs_supervisor_signals[0]); i++) {
        if (sigaction(cs_supervisor_signals[i], NULL, &cs_saved_signal_actions[i]) != 0
                || sigaction(cs_supervisor_signals[i], &action, NULL) != 0) {
            int saved_errno = errno;
            for (size_t j = 0; j < installed; j++) {
                (void)sigaction(cs_supervisor_signals[j], &cs_saved_signal_actions[j], NULL);
            }
            cs_signal_write_fd = -1;
            errno = saved_errno;
            return -1;
        }
        installed++;
    }

    if (sigaction(SIGPIPE, NULL, &cs_saved_sigpipe_action) != 0) goto restore_installed;
    struct sigaction ignore;
    memset(&ignore, 0, sizeof(ignore));
    ignore.sa_handler = SIG_IGN;
    sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGPIPE, &ignore, NULL) != 0) goto restore_installed;

    cs_signal_handlers_active = 1;
    return 0;

restore_installed: {
        int saved_errno = errno;
        for (size_t i = 0; i < installed; i++) {
            (void)sigaction(cs_supervisor_signals[i], &cs_saved_signal_actions[i], NULL);
        }
        cs_signal_write_fd = -1;
        errno = saved_errno;
        return -1;
    }
}

void cs_supervisor_restore_signal_handlers(void) {
    if (!cs_signal_handlers_active) return;
    cs_signal_write_fd = -1;
    for (size_t i = 0; i < sizeof(cs_supervisor_signals) / sizeof(cs_supervisor_signals[0]); i++) {
        (void)sigaction(cs_supervisor_signals[i], &cs_saved_signal_actions[i], NULL);
    }
    (void)sigaction(SIGPIPE, &cs_saved_sigpipe_action, NULL);
    cs_signal_handlers_active = 0;
}

static struct termios cs_saved_terminal_attributes;
static int cs_saved_terminal_fd = -1;

int32_t cs_terminal_enter_raw(int32_t fd) {
    if (cs_saved_terminal_fd >= 0) return cs_saved_terminal_fd == fd ? 0 : -1;
    struct termios attributes;
    if (tcgetattr(fd, &cs_saved_terminal_attributes) != 0) return -1;
    attributes = cs_saved_terminal_attributes;
    cfmakeraw(&attributes);
    if (tcsetattr(fd, TCSANOW, &attributes) != 0) return -1;
    cs_saved_terminal_fd = fd;
    return 0;
}

void cs_terminal_restore(void) {
    if (cs_saved_terminal_fd < 0) return;
    (void)tcsetattr(cs_saved_terminal_fd, TCSANOW, &cs_saved_terminal_attributes);
    cs_saved_terminal_fd = -1;
}

int32_t cs_resize_pty_from_standard_terminal(int32_t pty_master_fd) {
    int terminal_fd = isatty(STDIN_FILENO) ? STDIN_FILENO
        : (isatty(STDOUT_FILENO) ? STDOUT_FILENO
                                 : (isatty(STDERR_FILENO) ? STDERR_FILENO : -1));
    if (terminal_fd < 0 || pty_master_fd < 0) return -1;
    struct winsize size;
    if (ioctl(terminal_fd, TIOCGWINSZ, &size) != 0) return -1;
    return ioctl(pty_master_fd, TIOCSWINSZ, &size) == 0 ? 0 : -1;
}

int32_t cs_wait_status_exited(int32_t status) { return WIFEXITED(status) ? 1 : 0; }
int32_t cs_wait_status_exit_code(int32_t status) { return WEXITSTATUS(status); }
int32_t cs_wait_status_signaled(int32_t status) { return WIFSIGNALED(status) ? 1 : 0; }
int32_t cs_wait_status_signal(int32_t status) { return WTERMSIG(status); }
int32_t cs_wait_status_stopped(int32_t status) { return WIFSTOPPED(status) ? 1 : 0; }
int32_t cs_wait_status_stop_signal(int32_t status) { return WSTOPSIG(status); }
int32_t cs_wait_status_continued(int32_t status) { return WIFCONTINUED(status) ? 1 : 0; }

int32_t cs_supervisor_suspend_self(int32_t signal_number) {
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    if (sigaction(signal_number, &action, NULL) != 0) return -1;
    return raise(signal_number);
}

void cs_terminate_like_wait_status(int32_t status) {
    if (WIFEXITED(status)) _exit(WEXITSTATUS(status));
    if (WIFSIGNALED(status)) {
        int signal_number = WTERMSIG(status);
        struct sigaction action;
        memset(&action, 0, sizeof(action));
        action.sa_handler = SIG_DFL;
        sigemptyset(&action.sa_mask);
        (void)sigaction(signal_number, &action, NULL);
        (void)raise(signal_number);
        _exit(128 + signal_number);
    }
    _exit(1);
}
