#include "CSecuritySupport.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
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
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
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
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    return fd;
}

static int cs_fd_set_blocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK) == 0 ? 0 : -1;
}

int cs_connect_unix_timeout(const char *path, int32_t timeout_ms) {
    if (timeout_ms <= 0) return cs_connect_unix(path);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (cs_disable_sigpipe(fd) != 0 || cs_set_cloexec(fd) != 0
            || cs_fd_set_nonblocking(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
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

    int connected = connect(fd, (struct sockaddr *)&addr, (socklen_t)SUN_LEN(&addr));
    if (connected < 0 && (errno == EINPROGRESS || errno == EALREADY)) {
        struct pollfd waiter = {.fd = fd, .events = POLLOUT, .revents = 0};
        int ready;
        do {
            ready = poll(&waiter, 1, timeout_ms);
        } while (ready < 0 && errno == EINTR);
        if (ready == 0) {
            close(fd);
            errno = ETIMEDOUT;
            return -1;
        }
        if (ready < 0) {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        int pending = 0;
        socklen_t pending_size = sizeof(pending);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &pending, &pending_size) != 0) {
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        if (pending != 0) {
            close(fd);
            errno = pending;
            return -1;
        }
        connected = 0;
    }
    if (connected < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }
    // Every later read/write on this descriptor waits with poll() and then
    // performs one blocking transfer, so hand it back in blocking mode.
    if (cs_fd_set_blocking(fd) != 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
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
    // A failed recvmsg (an SO_RCVTIMEO expiry included) leaves msg_controllen
    // as we set it, over our own zeroed buffer: there is nothing to parse, and
    // a zero cmsg_len would make Darwin's CMSG_NXTHDR return the same header
    // forever.
    if (received < 0) return -1;
    int received_fds[8];
    int received_fd_count = 0;
    int malformed_control = 0;
    unsigned char *control_end = (unsigned char *)control + message.msg_controllen;
    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&message, cmsg)) {
        // Checked before anything else: a header shorter than itself never
        // advances the walk.
        if (cmsg->cmsg_len < CMSG_LEN(0)) {
            malformed_control = 1;
            break;
        }
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS) continue;
        size_t payload = cmsg->cmsg_len - CMSG_LEN(0);
        if (payload % sizeof(int) != 0) malformed_control = 1;
        // A truncated message (MSG_CTRUNC) keeps the sender's cmsg_len, so
        // read only the descriptors that were actually copied out.
        unsigned char *data = (unsigned char *)CMSG_DATA(cmsg);
        size_t available = data < control_end ? (size_t)(control_end - data) : 0;
        if (payload > available) {
            malformed_control = 1;
            payload = available;
        }
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

// libsystem_kernel exports csops_audittoken, but only xnu's bsd/sys/codesign.h
// declares it, and the public SDK omits that header; so do its operation
// numbers, copied here from the same header.
int csops_audittoken(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token);
#define CS_SUPPORT_OPS_STATUS 0
#define CS_SUPPORT_OPS_CDHASH 5
#define CS_SUPPORT_OPS_IDENTITY 11
#define CS_SUPPORT_OPS_TEAMID 14
#define CS_SUPPORT_CDHASH_LENGTH 20

int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

int32_t cs_proc_code_status(int32_t pid, uint32_t *status_flags) {
    if (pid <= 0 || status_flags == NULL) return EINVAL;
    uint32_t flags = 0;
    if (csops((pid_t)pid, CS_SUPPORT_OPS_STATUS, &flags, sizeof(flags)) != 0) {
        return errno != 0 ? errno : EIO;
    }
    *status_flags = flags;
    return 0;
}

// One CS_OPS_IDENTITY or CS_OPS_TEAMID answer. The kernel writes an 8-byte
// blob header whose second word is the big-endian total length, then the
// NUL-terminated string (xnu kern_proc.c, csops_internal). Returns 0, or an
// errno: ENOENT when the signature has no such string.
static int cs_csops_string(
    pid_t pid, unsigned int op, audit_token_t *token, char *out, int32_t out_size
) {
    unsigned char answer[8 + 1024];
    memset(answer, 0, sizeof(answer));
    if (csops_audittoken(pid, op, answer, sizeof(answer), token) != 0) {
        return errno != 0 ? errno : EIO;
    }
    uint32_t total = 0;
    memcpy(&total, answer + 4, sizeof(total));
    total = ntohl(total);
    if (total <= 8 || total > sizeof(answer)) return EINVAL;
    size_t length = (size_t)total - 8; // the string and its NUL
    const char *string = (const char *)answer + 8;
    if (string[length - 1] != '\0' || strlen(string) != length - 1) return EINVAL;
    if (length > (size_t)out_size) return ERANGE;
    memcpy(out, string, length);
    return 0;
}

int32_t cs_audit_token_code_facts(
    const void *token_buf, int32_t token_length,
    uint32_t *status_flags,
    uint8_t *cdhash, int32_t cdhash_size,
    char *identifier, int32_t identifier_size,
    char *team, int32_t team_size, int32_t *has_team
) {
    if (status_flags == NULL || cdhash == NULL || cdhash_size != CS_SUPPORT_CDHASH_LENGTH
            || identifier == NULL || identifier_size <= 0
            || team == NULL || team_size <= 0 || has_team == NULL) return EINVAL;
    *status_flags = 0;
    memset(cdhash, 0, (size_t)cdhash_size);
    identifier[0] = '\0';
    team[0] = '\0';
    *has_team = 0;

    audit_token_t token;
    if (!cs_copy_audit_token(token_buf, token_length, &token)) return EINVAL;
    pid_t pid = audit_token_to_pid(token);
    if (pid <= 0) return EINVAL;

    if (csops_audittoken(pid, CS_SUPPORT_OPS_CDHASH, cdhash, CS_SUPPORT_CDHASH_LENGTH, &token) != 0) {
        int failure = errno != 0 ? errno : EIO;
        memset(cdhash, 0, (size_t)cdhash_size);
        return failure;
    }
    int failure = cs_csops_string(pid, CS_SUPPORT_OPS_IDENTITY, &token, identifier, identifier_size);
    if (failure != 0) {
        identifier[0] = '\0';
        return failure;
    }
    failure = cs_csops_string(pid, CS_SUPPORT_OPS_TEAMID, &token, team, team_size);
    if (failure == 0) {
        *has_team = 1;
    } else if (failure == ENOENT) {
        team[0] = '\0';
    } else {
        team[0] = '\0';
        return failure;
    }
    uint32_t flags = 0;
    if (csops_audittoken(pid, CS_SUPPORT_OPS_STATUS, &flags, sizeof(flags), &token) != 0) {
        return errno != 0 ? errno : EIO;
    }
    *status_flags = flags;
    return 0;
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

int32_t cs_proc_controlling_terminal(int32_t pid) {
    struct proc_bsdinfo info;
    int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (n != (int)sizeof(info)) return -1;
    // NODEV is the "no controlling terminal" sentinel; report it as absent so
    // callers cannot mistake it for a real device number.
    if (info.e_tdev == (uint32_t)NODEV) return -1;
    return (int32_t)info.e_tdev;
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

int32_t cs_proc_controlling_terminal_name(int32_t pid, char *buf, int32_t bufsize) {
    if (buf == NULL || bufsize <= 0) return -1;
    buf[0] = '\0';
    int32_t device = cs_proc_controlling_terminal(pid);
    if (device < 0) {
        struct proc_bsdinfo info;
        int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
        if (n != (int)sizeof(info)) return -1;
        return 0;
    }
    if (devname_r((dev_t)device, S_IFCHR, buf, bufsize) == NULL || buf[0] == '\0') {
        buf[0] = '\0';
        return -1;
    }
    return 1;
}

/// A KERN_PROCARGS2 block and the boundaries of its argv strings. The block
/// holds the whole exec-time environment, so it is always wiped before free.
typedef struct {
    char *block;
    size_t capacity;
    int argc;
    const char *argv;        /* argv[0] */
    const char *after_argv;  /* first byte after argv[argc - 1]'s NUL */
    const char *end;
} cs_procargs;

static void cs_procargs_release(cs_procargs *args) {
    if (args->block != NULL) {
        memset_s(args->block, args->capacity, 0, args->capacity);
        free(args->block);
    }
    memset(args, 0, sizeof(*args));
}

int32_t cs_procargs_layout(
    const char *block, uint64_t size, uint64_t capacity, int32_t require_environment,
    uint64_t *argv_offset, uint64_t *after_argv_offset
) {
    if (block == NULL || argv_offset == NULL || after_argv_offset == NULL) return -1;
    *argv_offset = 0;
    *after_argv_offset = 0;
    // A block that fills the buffer may be the tail of a larger one: the
    // kernel keeps the last `capacity` bytes, argc still in front, and drops
    // the exec path, argv and the start of the environment. The remainder can
    // parse cleanly, so a full buffer is never trusted, even an exact fit.
    if (size < sizeof(int) || size >= capacity) return -1;

    int argc = 0;
    memcpy(&argc, block, sizeof(int));
    const char *path = block + sizeof(int);
    const char *end = block + size;
    size_t path_length = strnlen(path, (size_t)(end - path));
    const size_t alignment = sizeof(void *);
    size_t argv_start = (path_length + 1 + alignment - 1) & ~(alignment - 1);
    if (argc < 0 || path_length >= (size_t)(end - path) || argv_start > (size_t)(end - path)) {
        return -1;
    }
    for (const char *padding = path + path_length; padding < path + argv_start; padding++) {
        if (*padding != '\0') return -1;
    }
    const char *cursor = path + argv_start;
    if (argc > 0 && (cursor >= end || *cursor == '\0')) return -1;
    const char *argv = cursor;
    for (int i = 0; i < argc; i++) {
        size_t length = strnlen(cursor, (size_t)(end - cursor));
        if (length >= (size_t)(end - cursor)) return -1;
        cursor += length + 1;
    }
    if (require_environment) {
        int has_strings = 0;
        for (const char *scan = cursor; scan < end; scan++) {
            if (*scan != '\0') {
                has_strings = 1;
                break;
            }
        }
        if (!has_strings) return -1;
    }
    *argv_offset = (uint64_t)(argv - block);
    *after_argv_offset = (uint64_t)(cursor - block);
    return argc;
}

/// Copy and delimit the exec-time argv and environment block of `pid`,
/// applying `cs_procargs_layout`'s rules; see its header comment.
static int cs_procargs_copy(int32_t pid, int require_environment, cs_procargs *out) {
    memset(out, 0, sizeof(*out));
    if (pid <= 0) return -1;
    int argmax_mib[2] = {CTL_KERN, KERN_ARGMAX};
    int argmax = 0;
    size_t argmax_size = sizeof(argmax);
    if (sysctl(argmax_mib, 2, &argmax, &argmax_size, NULL, 0) != 0 || argmax <= 0) return -1;

    out->capacity = (size_t)argmax;
    out->block = malloc(out->capacity);
    if (out->block == NULL) {
        out->capacity = 0;
        return -1;
    }
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    size_t size = out->capacity;
    uint64_t argv_offset = 0;
    uint64_t after_argv_offset = 0;
    int32_t argc = -1;
    // Concurrent KERN_PROCARGS2 reads of a block of tens of KiB or more fail
    // with EIO under load (measured: about one read in five with six readers
    // at 64 KiB; never for a lone reader or a small block). EIO is the copy
    // failing, not the process changing, so it is retried after a short
    // backoff (0.5 to 8 ms, under 16 ms in all). Any other error, or EIO on
    // every attempt, stays unreadable.
    int read_status = -1;
    for (int attempt = 0; attempt < 6; attempt++) {
        if (attempt > 0) usleep(500u << (attempt - 1));
        size = out->capacity;
        read_status = sysctl(mib, 3, out->block, &size, NULL, 0);
        if (read_status == 0 || errno != EIO) break;
    }
    if (read_status == 0) {
        argc = cs_procargs_layout(
            out->block, (uint64_t)size, (uint64_t)out->capacity, require_environment ? 1 : 0,
            &argv_offset, &after_argv_offset
        );
    }
    if (argc < 0) {
        cs_procargs_release(out);
        return -1;
    }
    out->argc = argc;
    out->argv = out->block + argv_offset;
    out->after_argv = out->block + after_argv_offset;
    out->end = out->block + size;
    return 0;
}

/// Advance past the next string after `cursor`, skipping empty strings, and
/// return it (with its length), or NULL at the end. Empty strings appear as
/// alignment padding and as literal empty environment entries; neither ends
/// the environment, so the scan continues to the end of the block.
static const char *cs_procargs_next_string(
    const char **cursor, const char *end, size_t *length
) {
    while (*cursor < end && **cursor == '\0') (*cursor)++;
    if (*cursor >= end) return NULL;
    const char *entry = *cursor;
    *length = strnlen(entry, (size_t)(end - entry));
    *cursor = entry + *length;
    if (*cursor < end) (*cursor)++;
    return entry;
}

int32_t cs_proc_env_subset(
    int32_t pid, const char *const *keys, int32_t key_count, char *buf, int32_t bufsize
) {
    if (pid <= 0 || keys == NULL || key_count <= 0 || buf == NULL || bufsize <= 0) return -1;
    buf[0] = '\0';

    cs_procargs args;
    if (cs_procargs_copy(pid, 1, &args) != 0) return -1;
    const char *cursor = args.after_argv;
    const char *end = args.end;

    int32_t written = 0;
    int32_t used = 0;
    int32_t result = 0;
    const char *entry;
    size_t entry_length = 0;
    while ((entry = cs_procargs_next_string(&cursor, end, &entry_length)) != NULL) {
        const char *equals = memchr(entry, '=', entry_length);
        if (equals == NULL) continue;
        size_t key_length = (size_t)(equals - entry);
        for (int32_t k = 0; k < key_count; k++) {
            const char *key = keys[k];
            if (key == NULL || strlen(key) != key_length || memcmp(key, entry, key_length) != 0) {
                continue;
            }
            // The first occurrence wins, matching getenv semantics.
            bool duplicate = false;
            int32_t scan = 0;
            while (scan < used) {
                const char *existing = buf + scan;
                size_t existing_length = strlen(existing);
                if (existing_length > key_length && existing[key_length] == '='
                    && memcmp(existing, key, key_length) == 0) {
                    duplicate = true;
                    break;
                }
                scan += (int32_t)existing_length + 1;
            }
            if (duplicate) break;
            if ((size_t)(bufsize - used) < entry_length + 1) {
                result = -1;
                break;
            }
            memcpy(buf + used, entry, entry_length);
            buf[used + (int32_t)entry_length] = '\0';
            used += (int32_t)entry_length + 1;
            written++;
            break;
        }
        if (result < 0) break;
    }

    cs_procargs_release(&args);
    if (result < 0) {
        memset_s(buf, (size_t)bufsize, 0, (size_t)bufsize);
        return -1;
    }
    return written;
}

int32_t cs_proc_job_facts(int32_t pid, cs_job_facts *out) {
    if (pid <= 0 || out == NULL) return -1;
    memset(out, 0, sizeof(*out));
    struct proc_bsdinfo info;
    int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (n != (int)sizeof(info) || (int32_t)info.pbi_pid != pid) return -1;
    out->pid = (int32_t)info.pbi_pid;
    out->parent = (int32_t)info.pbi_ppid;
    out->process_group = (int32_t)info.pbi_pgid;
    out->terminal_process_group = (int32_t)info.e_tpgid;
    out->terminal_device = info.e_tdev;
    out->has_controlling_terminal = (info.pbi_flags & PROC_FLAG_CONTROLT) != 0 ? 1 : 0;
    out->is_session_leader = (info.pbi_flags & PROC_FLAG_SLEADER) != 0 ? 1 : 0;
    out->is_traced = (info.pbi_flags & PROC_FLAG_TRACED) != 0 ? 1 : 0;
    out->effective_uid = (uint32_t)info.pbi_uid;
    out->start_time = (uint64_t)info.pbi_start_tvsec * 1000000ULL + (uint64_t)info.pbi_start_tvusec;
    return 0;
}

/* PROC_PIDUNIQIDENTIFIERINFO and its structure are declared in the private
 * <sys/proc_info_private.h>. The kernel marks the structure as API, sizes it
 * with a static assertion, and serves the flavor to any caller without a
 * same-user check (xnu bsd/kern/proc_info.c, proc_pidinfo_internal). */
#define CS_PROC_PIDUNIQIDENTIFIERINFO 17
struct cs_proc_uniqidentifierinfo {
    uint8_t p_uuid[16];
    uint64_t p_uniqueid;
    uint64_t p_puniqueid;
    int32_t p_idversion;
    int32_t p_orig_ppidversion;
    uint64_t p_reserve2;
    uint64_t p_reserve3;
};
_Static_assert(sizeof(struct cs_proc_uniqidentifierinfo) == 56,
               "proc_uniqidentifierinfo layout");

static int cs_proc_unique_id(int32_t pid, uint64_t *out) {
    struct cs_proc_uniqidentifierinfo info;
    int n = proc_pidinfo(pid, CS_PROC_PIDUNIQIDENTIFIERINFO, 0, &info, sizeof(info));
    if (n != (int)sizeof(info) || info.p_uniqueid == 0) return -1;
    *out = info.p_uniqueid;
    return 0;
}

int32_t cs_proc_lineage_facts(int32_t pid, cs_lineage_facts *out) {
    if (pid <= 0 || out == NULL) return -1;
    memset(out, 0, sizeof(*out));
    uint64_t first = 0;
    if (cs_proc_unique_id(pid, &first) != 0) return -1;
    struct proc_bsdinfo info;
    int n = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info));
    if (n != (int)sizeof(info) || (int32_t)info.pbi_pid != pid) return -1;
    pid_t session = getsid(pid);
    if (session <= 0) return -1;
    // A pid reused between the reads has a different unique ID.
    uint64_t last = 0;
    if (cs_proc_unique_id(pid, &last) != 0 || last != first) return -1;
    out->pid = pid;
    out->parent = (int32_t)info.pbi_ppid;
    out->session = (int32_t)session;
    out->unique_id = first;
    out->start_time = (uint64_t)info.pbi_start_tvsec * 1000000ULL + (uint64_t)info.pbi_start_tvusec;
    return 0;
}

int32_t cs_max_processes(void) {
    int value = 0;
    size_t size = sizeof(value);
    if (sysctlbyname("kern.maxproc", &value, &size, NULL, 0) != 0 || size != sizeof(value)) return -1;
    return value > 0 ? (int32_t)value : -1;
}

int32_t cs_proc_fd_char_device(int32_t pid, int32_t fd, uint64_t *rdev) {
    if (pid <= 0 || fd < 0 || rdev == NULL) return -1;
    *rdev = 0;
    struct vnode_fdinfo vnode;
    int n = proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEINFO, &vnode, sizeof(vnode));
    if (n == (int)sizeof(vnode)) {
        if (!S_ISCHR(vnode.pvi.vi_stat.vst_mode)) return 0;
        *rdev = (uint64_t)vnode.pvi.vi_stat.vst_rdev;
        return 1;
    }
    // The vnode flavor fails with EBADF both for a closed descriptor and for a
    // pipe or socket, so tell them apart from the descriptor table.
    int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
    if (bytes <= 0) return -1;
    size_t capacity = (size_t)bytes + 16 * sizeof(struct proc_fdinfo);
    struct proc_fdinfo *table = calloc(1, capacity);
    if (table == NULL) return -1;
    bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, table, (int)capacity);
    int32_t result = -1;
    if (bytes > 0) {
        int count = bytes / (int)sizeof(struct proc_fdinfo);
        for (int i = 0; i < count; i++) {
            if (table[i].proc_fd != fd) continue;
            result = table[i].proc_fdtype == PROX_FDTYPE_VNODE ? -1 : 0;
            break;
        }
    }
    free(table);
    return result;
}

int32_t cs_proc_cwd(
    int32_t pid, char *buf, int32_t bufsize, uint64_t *device, uint64_t *inode, int32_t *fsid
) {
    if (pid <= 0 || buf == NULL || bufsize <= 0 || device == NULL || inode == NULL
            || fsid == NULL) return 0;
    buf[0] = '\0';
    *device = 0;
    *inode = 0;
    fsid[0] = 0;
    fsid[1] = 0;
    struct proc_vnodepathinfo info;
    int n = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, sizeof(info));
    if (n != (int)sizeof(info)) return 0;
    size_t length = strnlen(info.pvi_cdir.vip_path, sizeof(info.pvi_cdir.vip_path));
    if (length == 0 || length >= sizeof(info.pvi_cdir.vip_path)
            || length >= (size_t)bufsize || !S_ISDIR(info.pvi_cdir.vip_vi.vi_stat.vst_mode)) {
        return 0;
    }
    memcpy(buf, info.pvi_cdir.vip_path, length);
    buf[length] = '\0';
    *device = (uint64_t)info.pvi_cdir.vip_vi.vi_stat.vst_dev;
    *inode = info.pvi_cdir.vip_vi.vi_stat.vst_ino;
    fsid[0] = info.pvi_cdir.vip_vi.vi_fsid.val[0];
    fsid[1] = info.pvi_cdir.vip_vi.vi_fsid.val[1];
    return (int32_t)length;
}

int32_t cs_proc_fd_vnode(
    int32_t pid, int32_t fd, char *buf, int32_t bufsize, uint64_t *device, uint64_t *inode,
    int32_t *fsid, int64_t *size, int64_t *ctime_seconds, int64_t *ctime_nanoseconds
) {
    if (pid <= 0 || fd < 0 || buf == NULL || bufsize <= 0 || device == NULL || inode == NULL
            || fsid == NULL || size == NULL || ctime_seconds == NULL
            || ctime_nanoseconds == NULL) return -1;
    buf[0] = '\0';
    *device = 0;
    *inode = 0;
    fsid[0] = 0;
    fsid[1] = 0;
    *size = 0;
    *ctime_seconds = 0;
    *ctime_nanoseconds = 0;
    struct vnode_fdinfowithpath info;
    int n = proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, &info, sizeof(info));
    // EBADF covers a closed descriptor and a non-vnode one (pipe, socket):
    // neither can be the script a shell is reading.
    if (n != (int)sizeof(info)) return -1;
    const struct vinfo_stat *stat = &info.pvip.vip_vi.vi_stat;
    if (!S_ISREG(stat->vst_mode)) return 0;
    // A path that fills the buffer may be only its tail end (proc_info.h).
    size_t length = strnlen(info.pvip.vip_path, sizeof(info.pvip.vip_path));
    if (length == 0 || length >= sizeof(info.pvip.vip_path) - 1 || length >= (size_t)bufsize) {
        return 0;
    }
    memcpy(buf, info.pvip.vip_path, length);
    buf[length] = '\0';
    *device = (uint64_t)stat->vst_dev;
    *inode = stat->vst_ino;
    fsid[0] = info.pvip.vip_vi.vi_fsid.val[0];
    fsid[1] = info.pvip.vip_vi.vi_fsid.val[1];
    *size = (int64_t)stat->vst_size;
    *ctime_seconds = stat->vst_ctime;
    *ctime_nanoseconds = stat->vst_ctimensec;
    return (int32_t)length;
}

/// The kernel's mount table as it stands, without refreshing any entry:
/// getfsstat with MNT_NOWAIT copies each mount's cached statfs and never calls
/// into a file system (xnu getfsstat64_callback), so an unresponsive network
/// mount cannot block it. The caller frees the result.
static int cs_cached_mounts(struct statfs **mounts, int *count) {
    *mounts = NULL;
    *count = 0;
    for (int attempt = 0; attempt < 4; attempt++) {
        int listed = getfsstat(NULL, 0, MNT_NOWAIT);
        if (listed < 0) return -1;
        int capacity = listed + 8;
        struct statfs *buffer = calloc((size_t)capacity, sizeof(struct statfs));
        if (buffer == NULL) return -1;
        int filled = getfsstat(buffer, capacity * (int)sizeof(struct statfs), MNT_NOWAIT);
        if (filled < 0) {
            free(buffer);
            return -1;
        }
        // A full buffer may have missed a mount that appeared in between.
        if (filled < capacity) {
            *mounts = buffer;
            *count = filled;
            return 0;
        }
        free(buffer);
    }
    return -1;
}

int32_t cs_mount_lookup(
    int32_t fsid0, int32_t fsid1, int32_t *is_local,
    char *mount_point, int32_t mount_point_size, char *type_name, int32_t type_name_size
) {
    if (is_local == NULL || mount_point == NULL || mount_point_size <= 0
            || type_name == NULL || type_name_size <= 0) return -1;
    *is_local = 0;
    mount_point[0] = '\0';
    type_name[0] = '\0';
    struct statfs *mounts = NULL;
    int count = 0;
    if (cs_cached_mounts(&mounts, &count) != 0) return -1;
    int32_t result = 0;
    for (int i = 0; i < count; i++) {
        if (mounts[i].f_fsid.val[0] != fsid0 || mounts[i].f_fsid.val[1] != fsid1) continue;
        size_t point_length = strnlen(mounts[i].f_mntonname, sizeof(mounts[i].f_mntonname));
        size_t type_length = strnlen(mounts[i].f_fstypename, sizeof(mounts[i].f_fstypename));
        if (point_length >= (size_t)mount_point_size || type_length >= (size_t)type_name_size) {
            result = -1;
            break;
        }
        memcpy(mount_point, mounts[i].f_mntonname, point_length);
        mount_point[point_length] = '\0';
        memcpy(type_name, mounts[i].f_fstypename, type_length);
        type_name[type_length] = '\0';
        *is_local = (mounts[i].f_flags & MNT_LOCAL) != 0 ? 1 : 0;
        result = 1;
        break;
    }
    free(mounts);
    return result;
}

int32_t cs_path_mounts_local(const char *path) {
    if (path == NULL || path[0] != '/') return -1;
    struct statfs *mounts = NULL;
    int count = 0;
    if (cs_cached_mounts(&mounts, &count) != 0) return -1;
    size_t path_length = strlen(path);
    int32_t result = 1;
    for (int i = 0; i < count && result == 1; i++) {
        const char *point = mounts[i].f_mntonname;
        size_t point_length = strnlen(point, sizeof(mounts[i].f_mntonname));
        // A mount point covers the path when it is the path itself or one of
        // its directory ancestors; "/" covers everything.
        int covers = (point_length == 1 && point[0] == '/')
            || (point_length > 0 && point_length <= path_length
                && memcmp(point, path, point_length) == 0
                && (path[point_length] == '\0' || path[point_length] == '/'));
        if (covers && (mounts[i].f_flags & MNT_LOCAL) == 0) result = 0;
    }
    free(mounts);
    return result;
}

int32_t cs_proc_argv(int32_t pid, char *buf, int32_t bufsize) {
    if (pid <= 0 || buf == NULL || bufsize <= 0) return -1;
    buf[0] = '\0';
    cs_procargs args;
    if (cs_procargs_copy(pid, 0, &args) != 0) return -1;
    size_t length = (size_t)(args.after_argv - args.argv);
    int32_t count = args.argc;
    if (length > (size_t)bufsize) {
        cs_procargs_release(&args);
        memset_s(buf, (size_t)bufsize, 0, (size_t)bufsize);
        return -1;
    }
    memcpy(buf, args.argv, length);
    cs_procargs_release(&args);
    return count;
}

int32_t cs_proc_env_names_present(
    int32_t pid,
    const char *const *names, int32_t name_count,
    const char *const *prefixes, int32_t prefix_count,
    uint8_t *name_present, uint8_t *prefix_present
) {
    if (pid <= 0 || name_count < 0 || prefix_count < 0
            || (name_count > 0 && (names == NULL || name_present == NULL))
            || (prefix_count > 0 && (prefixes == NULL || prefix_present == NULL))) {
        return -1;
    }
    for (int32_t i = 0; i < name_count; i++) {
        if (names[i] == NULL || names[i][0] == '\0') return -1;
        name_present[i] = 0;
    }
    for (int32_t j = 0; j < prefix_count; j++) {
        if (prefixes[j] == NULL || prefixes[j][0] == '\0') return -1;
        prefix_present[j] = 0;
    }

    cs_procargs args;
    if (cs_procargs_copy(pid, 1, &args) != 0) return -1;
    const char *cursor = args.after_argv;
    const char *entry;
    size_t entry_length = 0;
    while ((entry = cs_procargs_next_string(&cursor, args.end, &entry_length)) != NULL) {
        const char *equals = memchr(entry, '=', entry_length);
        if (equals == NULL) continue;
        size_t key_length = (size_t)(equals - entry);
        // Counts saturate so a caller can tell one occurrence from several.
        for (int32_t i = 0; i < name_count; i++) {
            if (strlen(names[i]) == key_length && memcmp(names[i], entry, key_length) == 0
                    && name_present[i] < UINT8_MAX) {
                name_present[i]++;
            }
        }
        for (int32_t j = 0; j < prefix_count; j++) {
            size_t prefix_length = strlen(prefixes[j]);
            if (prefix_length <= key_length && memcmp(prefixes[j], entry, prefix_length) == 0
                    && prefix_present[j] < UINT8_MAX) {
                prefix_present[j]++;
            }
        }
    }
    cs_procargs_release(&args);
    return 0;
}

int32_t cs_task_audit_token(
    int32_t pid, void *buf, int32_t bufsize, int32_t *kern_status
) {
    if (kern_status != NULL) *kern_status = KERN_INVALID_ARGUMENT;
    if (pid <= 0 || buf == NULL || kern_status == NULL
            || bufsize < (int32_t)sizeof(audit_token_t)) return -1;

    mach_port_name_t name = MACH_PORT_NULL;
    kern_return_t status = task_name_for_pid(mach_task_self(), pid, &name);
    if (status != KERN_SUCCESS || name == MACH_PORT_NULL) {
        *kern_status = status != KERN_SUCCESS ? (int32_t)status : KERN_FAILURE;
        return -1;
    }
    // From here the port was granted, so a failure means the task changed
    // underneath (it exited, or the PID now names another process), not that
    // the kernel refused: -2, which callers must not treat as a refusal.
    audit_token_t token;
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    status = task_info(name, TASK_AUDIT_TOKEN, (task_info_t)&token, &count);
    mach_port_deallocate(mach_task_self(), name);
    if (status != KERN_SUCCESS || count != TASK_AUDIT_TOKEN_COUNT) {
        *kern_status = status != KERN_SUCCESS ? (int32_t)status : KERN_FAILURE;
        return -2;
    }
    // The name port names a task, not a PID; a PID recycled between the two
    // calls would hand back another process's token.
    if ((int32_t)audit_token_to_pid(token) != pid) {
        *kern_status = KERN_FAILURE;
        return -2;
    }
    memcpy(buf, &token, sizeof(token));
    *kern_status = KERN_SUCCESS;
    return (int32_t)sizeof(token);
}

int32_t cs_list_user_pids(uint32_t uid, int32_t *pids, int32_t maximum_pids) {
    if (maximum_pids < 0 || (maximum_pids > 0 && pids == NULL)) {
        errno = EINVAL;
        return -1;
    }
    // The kernel's sizing answer is the whole process table plus headroom; a
    // full buffer might have been truncated, so grow and re-read until it is not.
    int estimate = proc_listpids(PROC_UID_ONLY, uid, NULL, 0);
    if (estimate <= 0) return -1;
    size_t capacity = (size_t)estimate / sizeof(int32_t) + 64;
    for (int attempt = 0; attempt < 4; attempt++) {
        int32_t *buffer = calloc(capacity, sizeof(int32_t));
        if (buffer == NULL) return -1;
        int bytes = proc_listpids(
            PROC_UID_ONLY, uid, buffer, (int)(capacity * sizeof(int32_t))
        );
        if (bytes < 0) {
            free(buffer);
            return -1;
        }
        size_t count = (size_t)bytes / sizeof(int32_t);
        if (count < capacity) {
            int32_t total = 0;
            for (size_t i = 0; i < count; i++) {
                if (buffer[i] <= 0) continue;
                if (total < maximum_pids) pids[total] = buffer[i];
                total++;
            }
            free(buffer);
            return total;
        }
        free(buffer);
        capacity *= 2;
    }
    errno = EAGAIN;
    return -1;
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

int32_t cs_peek_child_exit(int32_t pid, int32_t *status) {
    siginfo_t info;
    memset(&info, 0, sizeof(info));
    if (waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT) != 0) {
        return errno == EINTR ? 0 : -1;
    }
    if (info.si_pid == 0) return 0;
    *status = info.si_code == CLD_EXITED ? info.si_status : 128 + info.si_status;
    return 1;
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
    int32_t *stderr_read_fd,
    cs_spawn_step *failed_step
) {
    if (failed_step != NULL) *failed_step = CS_SPAWN_STEP_SETUP;
    if (executable_path == NULL || argv == NULL || envp == NULL
            || child_pid == NULL || pty_master_fd == NULL
            || stdout_read_fd == NULL || stderr_read_fd == NULL || failed_step == NULL
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
    if (pid < 0) {
        *failed_step = CS_SPAWN_STEP_FORK;
        goto fail;
    }
    if (pid == 0) {
        cs_spawn_step step = CS_SPAWN_STEP_CHDIR;
        if (working_directory != NULL && chdir(working_directory) != 0) goto child_fail;
        if (needs_pty) {
            step = CS_SPAWN_STEP_SETSID;
            if (setsid() < 0) goto child_fail;
            step = CS_SPAWN_STEP_CONTROLLING_TERMINAL;
            if (ioctl(pty_slave, TIOCSCTTY, 0) < 0) goto child_fail;
            step = CS_SPAWN_STEP_FOREGROUND_GROUP;
            if (tcsetpgrp(pty_slave, getpgrp()) < 0) goto child_fail;
        } else {
            step = CS_SPAWN_STEP_PROCESS_GROUP;
            if (setpgid(0, 0) != 0) goto child_fail;
        }

        step = CS_SPAWN_STEP_STANDARD_STREAMS;
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

        step = CS_SPAWN_STEP_INHERITED_FDS;
        for (int32_t i = 0; i < inherited_fd_count; i++) {
            if (cs_clear_cloexec(inherited_fds[i]) != 0) goto child_fail;
        }

        execve(executable_path, argv, envp);
        int exec_errno = errno;
        static const char message[] = "csec exec: target exec failed\n";
        (void)write(STDERR_FILENO, message, sizeof(message) - 1);
        int32_t exec_report[2] = {CS_SPAWN_STEP_EXEC, exec_errno};
        (void)write(exec_status_pipe[1], exec_report, sizeof(exec_report));
        _exit(exec_errno == ENOENT ? 127 : 126);

child_fail: {
            int32_t child_report[2] = {step, errno == 0 ? EIO : errno};
            (void)write(exec_status_pipe[1], child_report, sizeof(child_report));
            _exit(126);
        }
    }

    // Only the child sets its process group. The parent does not repeat the
    // call, as the usual idiom would: since macOS 27.2 the child's
    // setpgid(0, 0) intermittently fails with EPERM while the parent's
    // setpgid(pid, pid) is in flight (about 1 launch in 400), and the parent
    // needs nothing from the race. It waits on exec_status_pipe below, so the
    // child has already set its group, or reported why not, before this
    // function returns and the caller signals the group.
    cs_close_if_open(exec_status_pipe[1]);
    exec_status_pipe[1] = -1;
    cs_close_if_open(pty_slave);
    pty_slave = -1;
    cs_close_if_open(stdout_pipe[1]);
    stdout_pipe[1] = -1;
    cs_close_if_open(stderr_pipe[1]);
    stderr_pipe[1] = -1;

    int32_t exec_report[2] = {CS_SPAWN_STEP_NONE, 0};
    ssize_t exec_status;
    do {
        exec_status = read(exec_status_pipe[0], exec_report, sizeof(exec_report));
    } while (exec_status < 0 && errno == EINTR);
    cs_close_if_open(exec_status_pipe[0]);
    exec_status_pipe[0] = -1;
    if (exec_status != 0) {
        int complete = exec_status == (ssize_t)sizeof(exec_report);
        int saved_errno = complete ? exec_report[1] : EIO;
        *failed_step = complete ? (cs_spawn_step)exec_report[0] : CS_SPAWN_STEP_EXEC_STATUS;
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
    *failed_step = CS_SPAWN_STEP_NONE;
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
