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
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <termios.h>
#include <util.h>
#include <grp.h>
#include <bsm/audit.h>
#include <mach/mach.h>

static int cs_set_cloexec(int fd);

static int cs_clear_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
}

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

int32_t cs_disable_core_dumps(void) {
    struct rlimit limit = {0, 0};
    return setrlimit(RLIMIT_CORE, &limit);
}

int32_t cs_send_frame_header_with_fds(
    int32_t fd, uint32_t body_length, const int32_t *fds, int32_t fd_count
) {
    if (fd < 0 || body_length == 0 || body_length > 8U * 1024U * 1024U
            || fds == NULL || fd_count <= 0 || fd_count > 8) {
        errno = EINVAL;
        return -1;
    }
    unsigned char header[4] = {
        (unsigned char)((body_length >> 24) & 0xff),
        (unsigned char)((body_length >> 16) & 0xff),
        (unsigned char)((body_length >> 8) & 0xff),
        (unsigned char)(body_length & 0xff),
    };
    char control[CMSG_SPACE(sizeof(int) * 8)];
    memset(control, 0, sizeof(control));
    struct iovec iov = {.iov_base = header, .iov_len = sizeof(header)};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = CMSG_SPACE(sizeof(int) * (size_t)fd_count);
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * (size_t)fd_count);
    memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * (size_t)fd_count);

    ssize_t sent;
    do {
        sent = sendmsg(fd, &message, 0);
    } while (sent < 0 && errno == EINTR);
    if (sent != (ssize_t)sizeof(header)) {
        if (sent >= 0) errno = EIO;
        return -1;
    }
    return 0;
}

int32_t cs_receive_frame_header_with_fds(
    int32_t fd, uint32_t *body_length, int32_t *fds, int32_t maximum_fd_count
) {
    if (fd < 0 || body_length == NULL || fds == NULL
            || maximum_fd_count < 0 || maximum_fd_count > 8) {
        errno = EINVAL;
        return -1;
    }
    for (int i = 0; i < maximum_fd_count; i++) fds[i] = -1;
    unsigned char header[4];
    char control[CMSG_SPACE(sizeof(int) * 8)];
    memset(control, 0, sizeof(control));
    struct iovec iov = {.iov_base = header, .iov_len = sizeof(header)};
    struct msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);

    ssize_t received;
    do {
        received = recvmsg(fd, &message, MSG_WAITALL);
    } while (received < 0 && errno == EINTR);
    int received_fds[8];
    int received_fd_count = 0;
    int malformed_control = 0;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&message, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) continue;
        if (cmsg->cmsg_len < CMSG_LEN(0)) {
            malformed_control = 1;
            continue;
        }
        size_t payload = cmsg->cmsg_len - CMSG_LEN(0);
        if (payload % sizeof(int) != 0) malformed_control = 1;
        int count = (int)(payload / sizeof(int));
        int *rights = (int *)CMSG_DATA(cmsg);
        for (int i = 0; i < count; i++) {
            if (received_fd_count < 8) {
                received_fds[received_fd_count++] = rights[i];
            } else {
                close(rights[i]);
                malformed_control = 1;
            }
        }
    }
    if (received != (ssize_t)sizeof(header)
            || (message.msg_flags & MSG_CTRUNC) != 0 || malformed_control) {
        for (int i = 0; i < received_fd_count; i++) close(received_fds[i]);
        if (received >= 0) errno = EPROTO;
        return -1;
    }

    int copied = 0;
    for (int i = 0; i < received_fd_count; i++) {
        if (copied >= maximum_fd_count) {
            close(received_fds[i]);
            continue;
        }
        if (cs_set_cloexec(received_fds[i]) != 0) {
            int saved_errno = errno;
            for (int j = 0; j < received_fd_count; j++) close(received_fds[j]);
            for (int j = 0; j < copied; j++) fds[j] = -1;
            errno = saved_errno;
            return -1;
        }
        fds[copied++] = received_fds[i];
    }
    *body_length = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16)
        | ((uint32_t)header[2] << 8) | (uint32_t)header[3];
    if (*body_length == 0 || *body_length > 8U * 1024U * 1024U) {
        for (int i = 0; i < copied; i++) {
            close(fds[i]);
            fds[i] = -1;
        }
        errno = EMSGSIZE;
        return -1;
    }
    return copied;
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

int32_t cs_fd_is_regular_file(int fd) {
    struct stat info;
    if (fstat(fd, &info) != 0) return 0;
    return S_ISREG(info.st_mode) ? 1 : 0;
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

static int cs_group_array_contains(const gid_t *groups, int count, gid_t gid) {
    for (int i = 0; i < count; i++) {
        if (groups[i] == gid) return 1;
    }
    return 0;
}

static int cs_kinfo_processes(struct kinfo_proc **processes, size_t *count) {
    int mib[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    size_t bytes = 0;
    if (sysctl(mib, 3, NULL, &bytes, NULL, 0) != 0 || bytes == 0) return -1;
    // Processes may appear between sizing and reading. Leave headroom and retry
    // rather than accepting a truncated credential inventory.
    for (int attempt = 0; attempt < 4; attempt++) {
        size_t capacity = bytes + 32 * sizeof(struct kinfo_proc);
        struct kinfo_proc *buffer = calloc(1, capacity);
        if (buffer == NULL) return -1;
        size_t actual = capacity;
        if (sysctl(mib, 3, buffer, &actual, NULL, 0) == 0) {
            *processes = buffer;
            *count = actual / sizeof(struct kinfo_proc);
            return 0;
        }
        int saved_errno = errno;
        free(buffer);
        if (saved_errno != ENOMEM) {
            errno = saved_errno;
            return -1;
        }
        bytes = capacity * 2;
    }
    errno = EAGAIN;
    return -1;
}

static int cs_kinfo_holds_gid(const struct kinfo_proc *process, gid_t gid) {
    if (process->kp_proc.p_pid <= 0) return 0;
    if (process->kp_eproc.e_pcred.p_rgid == gid
            || process->kp_eproc.e_pcred.p_svgid == gid) return 1;
    int count = process->kp_eproc.e_ucred.cr_ngroups;
    if (count < 0) count = 0;
    if (count > NGROUPS) count = NGROUPS;
    return cs_group_array_contains(process->kp_eproc.e_ucred.cr_groups, count, gid);
}

int32_t cs_proc_groups(int32_t pid, uint32_t *groups, int32_t maximum_groups) {
    if (pid <= 0 || groups == NULL || maximum_groups <= 0) {
        errno = EINVAL;
        return -1;
    }
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc process;
    memset(&process, 0, sizeof(process));
    size_t length = sizeof(process);
    if (sysctl(mib, 4, &process, &length, NULL, 0) != 0
            || length != sizeof(process) || process.kp_proc.p_pid != pid) return -1;

    int written = 0;
    int count = process.kp_eproc.e_ucred.cr_ngroups;
    if (count < 0) count = 0;
    if (count > NGROUPS) count = NGROUPS;
    for (int i = 0; i < count && written < maximum_groups; i++) {
        gid_t candidate = process.kp_eproc.e_ucred.cr_groups[i];
        if (!cs_group_array_contains((gid_t *)groups, written, candidate)) {
            groups[written++] = (uint32_t)candidate;
        }
    }
    gid_t additional[2] = {
        process.kp_eproc.e_pcred.p_rgid,
        process.kp_eproc.e_pcred.p_svgid,
    };
    for (int i = 0; i < 2 && written < maximum_groups; i++) {
        if (!cs_group_array_contains((gid_t *)groups, written, additional[i])) {
            groups[written++] = (uint32_t)additional[i];
        }
    }
    return written;
}

int32_t cs_gid_is_assigned(uint32_t gid) {
    errno = 0;
    struct group *entry = getgrgid((gid_t)gid);
    if (entry != NULL) return 1;
    return errno == 0 ? 0 : -1;
}

int32_t cs_gid_has_live_holder(uint32_t gid) {
    struct kinfo_proc *processes = NULL;
    size_t count = 0;
    if (cs_kinfo_processes(&processes, &count) != 0) return -1;
    int result = 0;
    for (size_t i = 0; i < count; i++) {
        if (cs_kinfo_holds_gid(&processes[i], (gid_t)gid)) {
            result = 1;
            break;
        }
    }
    free(processes);
    return result;
}

int32_t cs_pid_has_gid(int32_t pid, uint32_t gid) {
    if (pid <= 0) {
        errno = EINVAL;
        return -1;
    }
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
    struct kinfo_proc process;
    memset(&process, 0, sizeof(process));
    size_t length = sizeof(process);
    if (sysctl(mib, 4, &process, &length, NULL, 0) != 0) return -1;
    if (length != sizeof(process) || process.kp_proc.p_pid != pid) return 0;
    return cs_kinfo_holds_gid(&process, (gid_t)gid) ? 1 : 0;
}

int32_t cs_pids_with_gid(uint32_t gid, int32_t *pids, int32_t maximum_pids) {
    if (maximum_pids < 0 || (maximum_pids > 0 && pids == NULL)) {
        errno = EINVAL;
        return -1;
    }
    struct kinfo_proc *processes = NULL;
    size_t count = 0;
    if (cs_kinfo_processes(&processes, &count) != 0) return -1;
    int holders = 0;
    for (size_t i = 0; i < count; i++) {
        if (!cs_kinfo_holds_gid(&processes[i], (gid_t)gid)) continue;
        if (holders < maximum_pids) pids[holders] = processes[i].kp_proc.p_pid;
        holders++;
    }
    free(processes);
    return holders;
}

uint64_t cs_boot_time(void) {
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    struct timeval value;
    size_t length = sizeof(value);
    if (sysctl(mib, 2, &value, &length, NULL, 0) != 0
            || length != sizeof(value) || value.tv_sec <= 0) return 0;
    return (uint64_t)value.tv_sec * 1000000ULL + (uint64_t)value.tv_usec;
}

uint32_t cs_self_audit_session_id(void) {
    auditinfo_addr_t info;
    memset(&info, 0, sizeof(info));
    if (getaudit_addr(&info, sizeof(info)) != 0 || info.ai_asid == AU_DEFAUDITSID) {
        return UINT32_MAX;
    }
    return (uint32_t)info.ai_asid;
}

int32_t cs_secure_tmpfs_status(
    const char *path, uint64_t maximum_bytes, uint64_t maximum_nodes
) {
    if (path == NULL || maximum_bytes == 0 || maximum_nodes == 0) {
        errno = EINVAL;
        return -1;
    }
    struct statfs info;
    if (statfs(path, &info) != 0) return -1;
    if (strcmp(info.f_fstypename, "tmpfs") != 0) return 0;
    uint64_t bytes = (uint64_t)info.f_blocks * (uint64_t)info.f_bsize;
    uint64_t nodes = (uint64_t)info.f_files;
    unsigned long required = MNT_NODEV | MNT_NOSUID | MNT_NOEXEC | MNT_DONTBROWSE;
    return (info.f_flags & required) == required
        && bytes > 0 && bytes <= maximum_bytes
        && nodes > 0 && nodes <= maximum_nodes ? 1 : 0;
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
) {
    if (executable_path == NULL || argv == NULL || envp == NULL
            || child_pid == NULL || pty_master_fd == NULL
            || stdout_read_fd == NULL || stderr_read_fd == NULL
            || inherited_fd_count < 0 || inherited_fd_count > 32
            || (inherited_fd_count > 0 && inherited_fds == NULL)
            || (stdout_mode != CS_OUTPUT_INHERIT && stdout_mode != CS_OUTPUT_PIPE
                && stdout_mode != CS_OUTPUT_PTY)
            || (stderr_mode != CS_OUTPUT_INHERIT && stderr_mode != CS_OUTPUT_PIPE
                && stderr_mode != CS_OUTPUT_PTY)) {
        errno = EINVAL;
        return -1;
    }
    if (cs_ensure_standard_fds() != 0) return -1;
    for (int32_t i = 0; i < inherited_fd_count; i++) {
        if (inherited_fds[i] <= STDERR_FILENO || fcntl(inherited_fds[i], F_GETFD) < 0) {
            errno = EINVAL;
            return -1;
        }
        for (int32_t j = 0; j < i; j++) {
            if (inherited_fds[i] == inherited_fds[j]) {
                errno = EINVAL;
                return -1;
            }
        }
    }

    *child_pid = -1;
    *pty_master_fd = -1;
    *stdout_read_fd = -1;
    *stderr_read_fd = -1;

    int pty_master = -1, pty_slave = -1;
    int stdout_pipe[2] = {-1, -1};
    int stderr_pipe[2] = {-1, -1};
    int exec_status_pipe[2] = {-1, -1};
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
    if (cs_make_pipe(exec_status_pipe, 0) != 0) goto fail;

    pid_t pid = fork();
    if (pid < 0) goto fail;
    if (pid == 0) {
        if (working_directory != NULL && chdir(working_directory) != 0) goto child_fail;
        if (needs_pty) {
            if (setsid() < 0 || ioctl(pty_slave, TIOCSCTTY, 0) < 0
                    || tcsetpgrp(pty_slave, getpgrp()) < 0) goto child_fail;
        } else if (setpgid(0, 0) != 0) {
            goto child_fail;
        }

        if (stdin_uses_pty && dup2(pty_slave, STDIN_FILENO) < 0) goto child_fail;
        if (stdout_mode == CS_OUTPUT_PTY && dup2(pty_slave, STDOUT_FILENO) < 0) goto child_fail;
        if (stdout_mode == CS_OUTPUT_PIPE && dup2(stdout_pipe[1], STDOUT_FILENO) < 0) goto child_fail;
        if (stderr_mode == CS_OUTPUT_PTY && dup2(pty_slave, STDERR_FILENO) < 0) goto child_fail;
        if (stderr_mode == CS_OUTPUT_PIPE && dup2(stderr_pipe[1], STDERR_FILENO) < 0) goto child_fail;

        cs_close_if_open(pty_master);
        cs_close_if_open(pty_slave);
        cs_close_if_open(stdout_pipe[0]);
        cs_close_if_open(stdout_pipe[1]);
        cs_close_if_open(stderr_pipe[0]);
        cs_close_if_open(stderr_pipe[1]);
        cs_close_if_open(exec_status_pipe[0]);

        for (int32_t i = 0; i < inherited_fd_count; i++) {
            if (cs_clear_cloexec(inherited_fds[i]) != 0) goto child_fail;
        }

        execve(executable_path, argv, envp);
        int exec_errno = errno;
        static const char message[] = "csec exec: target exec failed\n";
        (void)write(STDERR_FILENO, message, sizeof(message) - 1);
        (void)write(exec_status_pipe[1], &exec_errno, sizeof(exec_errno));
        _exit(exec_errno == ENOENT ? 127 : 126);

child_fail: {
            int child_errno = errno == 0 ? EIO : errno;
            (void)write(exec_status_pipe[1], &child_errno, sizeof(child_errno));
            _exit(126);
        }
    }

    if (!needs_pty) (void)setpgid(pid, pid);
    cs_close_if_open(exec_status_pipe[1]);
    exec_status_pipe[1] = -1;
    cs_close_if_open(pty_slave);
    pty_slave = -1;
    cs_close_if_open(stdout_pipe[1]);
    stdout_pipe[1] = -1;
    cs_close_if_open(stderr_pipe[1]);
    stderr_pipe[1] = -1;

    int exec_errno = 0;
    ssize_t exec_status;
    do {
        exec_status = read(exec_status_pipe[0], &exec_errno, sizeof(exec_errno));
    } while (exec_status < 0 && errno == EINTR);
    cs_close_if_open(exec_status_pipe[0]);
    exec_status_pipe[0] = -1;
    if (exec_status != 0) {
        int saved_errno = exec_status == (ssize_t)sizeof(exec_errno) ? exec_errno : EIO;
        (void)kill(pid, SIGKILL);
        while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
        cs_close_if_open(pty_master);
        cs_close_if_open(stdout_pipe[0]);
        cs_close_if_open(stderr_pipe[0]);
        errno = saved_errno;
        return -1;
    }

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
        cs_close_if_open(exec_status_pipe[0]);
        cs_close_if_open(exec_status_pipe[1]);
        errno = saved_errno;
        return -1;
    }
}

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
) {
    if (executable_path == NULL || argv == NULL || envp == NULL
            || cwd_fd < 0 || stdin_fd < 0 || stdout_fd < 0 || stderr_fd < 0
            || uid == UINT32_MAX || capability_gid == UINT32_MAX
            || supplementary_group_count < 0 || supplementary_group_count > NGROUPS_MAX
            || (supplementary_group_count > 0 && supplementary_groups == NULL)
            || (uses_pty != 0 && uses_pty != 1)
            || (drop_credentials != 0 && drop_credentials != 1)
            || child_pid == NULL || child_start_time == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (cs_ensure_standard_fds() != 0) return -1;
    struct stat cwd_info;
    if (fstat(cwd_fd, &cwd_info) != 0 || !S_ISDIR(cwd_info.st_mode)) {
        errno = ENOTDIR;
        return -1;
    }
    int status_pipe[2] = {-1, -1};
    if (cs_make_pipe(status_pipe, 0) != 0) return -1;
    int release_pipe[2] = {-1, -1};
    if (cs_make_pipe(release_pipe, 0) != 0) {
        int saved_errno = errno;
        close(status_pipe[0]);
        close(status_pipe[1]);
        errno = saved_errno;
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        int saved_errno = errno;
        close(status_pipe[0]);
        close(status_pipe[1]);
        close(release_pipe[0]);
        close(release_pipe[1]);
        errno = saved_errno;
        return -1;
    }
    if (pid == 0) {
        close(status_pipe[0]);
        close(release_pipe[1]);
        unsigned char released = 0;
        ssize_t release_count;
        do {
            release_count = read(release_pipe[0], &released, sizeof(released));
        } while (release_count < 0 && errno == EINTR);
        close(release_pipe[0]);
        if (release_count != (ssize_t)sizeof(released) || released != 1) {
            errno = EPROTO;
            goto capability_child_fail;
        }
        if (uses_pty) {
            if (setsid() < 0 || ioctl(stdin_fd, TIOCSCTTY, 0) < 0) goto capability_child_fail;
        } else if (setpgid(0, 0) != 0) {
            goto capability_child_fail;
        }

        if (audit_session_id != 0 && audit_session_id != UINT32_MAX) {
            mach_port_name_t session_port = MACH_PORT_NULL;
            if (audit_session_port((au_asid_t)audit_session_id, &session_port) != 0
                    || session_port == MACH_PORT_NULL
                    || audit_session_join(session_port) != (au_asid_t)audit_session_id) {
                if (session_port != MACH_PORT_NULL) {
                    mach_port_deallocate(mach_task_self(), session_port);
                }
                goto capability_child_fail;
            }
            mach_port_deallocate(mach_task_self(), session_port);
        }

        if (fchdir(cwd_fd) != 0
                || dup2(stdin_fd, STDIN_FILENO) < 0
                || dup2(stdout_fd, STDOUT_FILENO) < 0
                || dup2(stderr_fd, STDERR_FILENO) < 0) goto capability_child_fail;

        struct rlimit core_limit = {0, 0};
        if (setrlimit(RLIMIT_CORE, &core_limit) != 0) goto capability_child_fail;

        if (drop_credentials) {
            gid_t native_groups[NGROUPS_MAX];
            for (int32_t i = 0; i < supplementary_group_count; i++) {
                native_groups[i] = (gid_t)supplementary_groups[i];
            }
            if (setgroups(supplementary_group_count, native_groups) != 0
                    || setgid((gid_t)capability_gid) != 0
                    || setuid((uid_t)uid) != 0
                    || getuid() != (uid_t)uid || geteuid() != (uid_t)uid
                    || getgid() != (gid_t)capability_gid
                    || getegid() != (gid_t)capability_gid) goto capability_child_fail;
        }

        // Keep only stdio and the close-on-exec status writer. closefrom is not
        // exposed consistently across SDKs, so use the process's finite fd cap.
        int maximum_fd = getdtablesize();
        for (int fd = STDERR_FILENO + 1; fd < maximum_fd; fd++) {
            if (fd != status_pipe[1]) close(fd);
        }
        execve(executable_path, argv, envp);

capability_child_fail: {
            int child_errno = errno == 0 ? EIO : errno;
            ssize_t ignored;
            do {
                ignored = write(status_pipe[1], &child_errno, sizeof(child_errno));
            } while (ignored < 0 && errno == EINTR);
            _exit(126);
        }
    }

    close(status_pipe[1]);
    close(release_pipe[0]);
    uint64_t start_time = cs_proc_start_time((int32_t)pid);
    unsigned char released = 1;
    ssize_t release_count;
    do {
        release_count = write(release_pipe[1], &released, sizeof(released));
    } while (release_count < 0 && errno == EINTR);
    close(release_pipe[1]);
    if (start_time == 0 || release_count != (ssize_t)sizeof(released)) {
        int saved_errno = errno == 0 ? EIO : errno;
        kill(pid, SIGKILL);
        int status = 0;
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        close(status_pipe[0]);
        errno = saved_errno;
        return -1;
    }
    int child_errno = 0;
    ssize_t count;
    do {
        count = read(status_pipe[0], &child_errno, sizeof(child_errno));
    } while (count < 0 && errno == EINTR);
    close(status_pipe[0]);
    if (count == 0) {
        *child_pid = (int32_t)pid;
        *child_start_time = start_time;
        return 0;
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    errno = count == (ssize_t)sizeof(child_errno) ? child_errno : EIO;
    return -1;
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

int32_t cs_open_standard_pty(int32_t *master_fd, int32_t *slave_fd) {
    if (master_fd == NULL || slave_fd == NULL) {
        errno = EINVAL;
        return -1;
    }
    *master_fd = -1;
    *slave_fd = -1;
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
    int master = -1, slave = -1;
    if (openpty(&master, &slave, NULL, attributes_ptr, size_ptr) != 0) return -1;
    if (cs_set_cloexec(master) != 0 || cs_set_cloexec(slave) != 0) {
        int saved_errno = errno;
        close(master);
        close(slave);
        errno = saved_errno;
        return -1;
    }
    *master_fd = master;
    *slave_fd = slave;
    return 0;
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
