/*
 * Contextual sudo authorization review for macOS.
 *
 * This PAM module never logs argv. Before rendering, raw arguments cross a
 * private pipe to the installed csec launcher's existing authenticated
 * active-secret matcher; secret-named and secret-shaped values receive the
 * same additional conservative filtering used elsewhere in csec. The frozen,
 * escaped display then crosses a separate private pipe to a root-owned csec UI
 * helper running as the login user. Any redaction or helper failure falls back
 * to Apple's Authorization Services UI; raw arguments never cross that UI
 * boundary.
 *
 * The review is a sufficient factor, followed immediately by this module's
 * requisite review_guard invocation, then stock pam_tid. Helper failures and
 * Use Password retain Apple's recovery path; an unanswered review's deadline
 * instead aborts this PAM transaction before any fallback can display UI. The
 * frame tells the helper how long is left, so its panel shows the deadline and
 * closes itself just before it (exit CSEC_REVIEW_EXPIRED_EXIT_STATUS), and the
 * terminal is told why sudo stopped.
 *
 * A Ctrl-C or Ctrl-\ at the terminal, or the terminal closing, while the csec
 * review is up closes the review and ends sudo the way expiry does: the review
 * latches the interrupt and the guard aborts the transaction, so neither
 * pam_tid's Touch ID sheet nor sudo's password prompt follows. The terminal is
 * told sudo stopped without authorizing anything.
 */

#include <Security/AuthSession.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <Security/CSCommon.h>
#include <Security/SecBase.h>
#include <Security/SecCode.h>
#include <Security/SecStaticCode.h>
#include "CSECSecretHeuristics.h"
#include <crt_externs.h>
#include <errno.h>
#include <fcntl.h>
#include <os/log.h>
#include <poll.h>
#include <spawn.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAM_SM_AUTH
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define CSEC_PROMPT_MAX 8192
#define CSEC_CWD_MAX 160
#define CSEC_TTY_MAX 80
#define CSEC_ARGUMENT_MAX 64
#define CSEC_ARGUMENT_INPUT_MAX 2048
#define CSEC_ARGUMENT_OUTPUT_MAX 4096
#define CSEC_REDACTOR_TIMEOUT_MILLISECONDS 3000
#define CSEC_REVIEW_TIMEOUT_MILLISECONDS 300000
#define CSEC_CLEANUP_TIMEOUT_MILLISECONDS 100
/* The helper's own "nobody answered in time" exit (SudoReviewDeadline). It is
 * believed only this close to the module's own deadline: earlier, it is a
 * helper fault, which keeps Apple's recovery rather than aborting sudo. */
#define CSEC_REVIEW_EXPIRED_EXIT_STATUS 75
#define CSEC_REVIEW_EXPIRY_CLAIM_MILLISECONDS 10000
#define CSEC_REVIEW_EXPIRED_MESSAGE \
    "csec: nobody answered the sudo review within 5 minutes, so sudo " \
    "stopped without authorizing anything."
_Static_assert(CSEC_REVIEW_TIMEOUT_MILLISECONDS == 300000,
    "CSEC_REVIEW_EXPIRED_MESSAGE names the review deadline");
#define CSEC_REVIEW_INTERRUPTED_MESSAGE \
    "csec: sudo was interrupted during its review, so it stopped without " \
    "authorizing anything."
#define CSEC_REVIEW_FRAME_VERSION 2
#define CSEC_REVIEW_FRAME_TIME_LIMIT_OFFSET 12
#define CSEC_REVIEW_FRAME_HEADER_BYTES 28
#define CSEC_REVIEW_FRAME_MAX \
    (CSEC_REVIEW_FRAME_HEADER_BYTES + CSEC_PROMPT_MAX - 1 + \
        CSEC_CWD_MAX - 1 + CSEC_TTY_MAX - 1)

#define CSEC_INSTALLED_LAUNCHER \
    "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
#define CSEC_SUDO_REVIEW_HELPER \
    "/usr/local/libexec/csec-sudo-review"
/* CSEC_IDENTIFIER is identity.xcconfig's, which build-sudo-pam.sh passes. */
#ifndef CSEC_IDENTIFIER
#error "build with -DCSEC_IDENTIFIER=\"...\" (packaging/bin/build-sudo-pam.sh)"
#endif
#define CSEC_SUDO_REVIEW_IDENTIFIER CSEC_IDENTIFIER ".sudo-review"

struct csec_redacted_arguments {
    size_t count;
    char *arguments[CSEC_ARGUMENT_MAX];
    char storage[CSEC_ARGUMENT_OUTPUT_MAX];
};

static void
csec_wipe(void *memory, size_t byte_count)
{
    volatile unsigned char *bytes = memory;
    while (byte_count > 0) {
        *bytes++ = 0;
        byte_count--;
    }
}

static void
csec_sanitize_metadata(const char *input, char *output, size_t output_size)
{
    if (output_size == 0) {
        return;
    }
    if (input == NULL || input[0] == '\0') {
        snprintf(output, output_size, "unknown");
        return;
    }

    size_t output_index = 0;
    for (size_t input_index = 0;
         input[input_index] != '\0' && output_index + 1 < output_size;
         input_index++) {
        const unsigned char byte = (unsigned char)input[input_index];
        if (byte < 0x20 || byte > 0x7e || byte == '[' || byte == ']') {
            output[output_index++] = '?';
        } else {
            output[output_index++] = (char)byte;
        }
    }
    output[output_index] = '\0';
}

struct csec_prompt_builder {
    char *output;
    size_t capacity;
    size_t length;
    bool complete;
};

static void
csec_prompt_append_bytes(struct csec_prompt_builder *builder, const char *bytes,
    size_t byte_count)
{
    if (!builder->complete || byte_count >= builder->capacity - builder->length) {
        builder->complete = false;
        return;
    }
    memcpy(builder->output + builder->length, bytes, byte_count);
    builder->length += byte_count;
    builder->output[builder->length] = '\0';
}

static void
csec_prompt_append(struct csec_prompt_builder *builder, const char *text)
{
    csec_prompt_append_bytes(builder, text, strlen(text));
}

static bool
csec_plain_argument_byte(unsigned char byte)
{
    return (byte >= 'A' && byte <= 'Z') ||
        (byte >= 'a' && byte <= 'z') ||
        (byte >= '0' && byte <= '9') ||
        strchr("_@%+=:,./-", byte) != NULL;
}

/*
 * Render one argv element without giving control characters, bidi controls, or
 * shell metacharacters a second interpretation in the authorization sheet.
 * Unsafe/non-ASCII bytes are escaped rather than dropped, so the display does
 * not silently turn one submitted argument into another.
 */
static void
csec_prompt_append_argument(struct csec_prompt_builder *builder,
    const char *argument)
{
    if (argument[0] == '\0') {
        csec_prompt_append(builder, "\"\"");
        return;
    }

    bool plain = true;
    for (size_t index = 0; argument[index] != '\0'; index++) {
        if (!csec_plain_argument_byte((unsigned char)argument[index])) {
            plain = false;
            break;
        }
    }
    if (plain) {
        csec_prompt_append(builder, argument);
        return;
    }

    csec_prompt_append(builder, "\"");
    for (size_t index = 0; argument[index] != '\0'; index++) {
        const unsigned char byte = (unsigned char)argument[index];
        if (byte >= 0x20 && byte <= 0x7e) {
            if (byte == '\\' || byte == '\"' || byte == '$' || byte == '`') {
                csec_prompt_append(builder, "\\");
            }
            const char printable = (char)byte;
            csec_prompt_append_bytes(builder, &printable, 1);
        } else {
            char escaped[5];
            snprintf(escaped, sizeof(escaped), "\\x%02X", byte);
            csec_prompt_append(builder, escaped);
        }
    }
    csec_prompt_append(builder, "\"");
}

static bool
csec_is_opaque_redaction_label(const char *value)
{
    static const char prefix[] = "[csec:secret-";
    if (strncmp(value, prefix, sizeof(prefix) - 1) != 0) {
        return false;
    }
    size_t index = sizeof(prefix) - 1;
    const size_t first_digit = index;
    while (value[index] >= '0' && value[index] <= '9') {
        index++;
    }
    return index > first_digit && value[index] == ']' && value[index + 1] == '\0';
}

static const char *
csec_argument_for_display(const char *argument, bool redact_entire,
    bool *redact_next, char replacement[256])
{
    static const char *const redacted = "[csec:secret-like]";
    *redact_next = false;
    if (csec_is_opaque_redaction_label(argument)) {
        return argument;
    }
    if (redact_entire) {
        return redacted;
    }

    const char *equals = strchr(argument, '=');
    if (equals != NULL) {
        const size_t name_length = (size_t)(equals - argument);
        if (csec_is_opaque_redaction_label(equals + 1)) {
            return argument;
        }
        if (cs_secret_name_looks_secret_like(
                (const uint8_t *)argument, name_length) ||
            cs_secret_value_looks_secret_like(
                (const uint8_t *)(equals + 1), strlen(equals + 1))) {
            if (name_length + 1 + strlen(redacted) < 256) {
                memcpy(replacement, argument, name_length + 1);
                strcpy(replacement + name_length + 1, redacted);
                return replacement;
            }
            return redacted;
        }
    }

    if (argument[0] == '-' && equals == NULL &&
        cs_secret_name_looks_secret_like(
            (const uint8_t *)argument, strlen(argument))) {
        *redact_next = true;
    }
    if (cs_secret_value_looks_secret_like(
            (const uint8_t *)argument, strlen(argument))) {
        return redacted;
    }
    return argument;
}

static bool
csec_build_redacted_command(const struct csec_redacted_arguments *redacted,
    char command[CSEC_PROMPT_MAX])
{
    struct csec_prompt_builder builder = {
        .output = command,
        .capacity = CSEC_PROMPT_MAX,
        .length = 0,
        .complete = true,
    };
    command[0] = '\0';
    csec_prompt_append(&builder, "sudo");

    bool redact_next = false;
    for (size_t index = 0; index < redacted->count; index++) {
        char replacement[256];
        bool next_is_sensitive = false;
        const char *display = csec_argument_for_display(
            redacted->arguments[index], redact_next, &next_is_sensitive,
            replacement);
        csec_prompt_append(&builder, " ");
        csec_prompt_append_argument(&builder, display);
        redact_next = next_is_sensitive;
        csec_wipe(replacement, sizeof(replacement));
    }
    return builder.complete;
}

static bool
csec_build_redacted_prompt_from_command(const char *command, const char *cwd,
    const char *tty, char prompt[CSEC_PROMPT_MAX])
{
    char safe_cwd[CSEC_CWD_MAX];
    char safe_tty[CSEC_TTY_MAX];
    csec_sanitize_metadata(cwd, safe_cwd, sizeof(safe_cwd));
    csec_sanitize_metadata(tty, safe_tty, sizeof(safe_tty));

    struct csec_prompt_builder builder = {
        .output = prompt,
        .capacity = CSEC_PROMPT_MAX,
        .length = 0,
        .complete = true,
    };
    prompt[0] = '\0';
    csec_prompt_append(&builder, "approve this sudo invocation:\n  ");
    csec_prompt_append(&builder, command);
    csec_prompt_append(&builder, "\nworking directory: ");
    csec_prompt_append_argument(&builder, safe_cwd);
    csec_prompt_append(&builder, "\nterminal: ");
    csec_prompt_append_argument(&builder, safe_tty);
    csec_prompt_append(&builder,
        "\narguments were filtered by the active csec secret catalog");
    return builder.complete;
}

#if (defined(CSEC_PAM_PROMPT_PREVIEW) && \
    !defined(CSEC_PAM_REVIEW_FRAME_PROBE)) || \
    defined(CSEC_PAM_REDACTOR_PROBE)
static bool
csec_build_redacted_prompt(const struct csec_redacted_arguments *redacted,
    const char *cwd, const char *tty, char prompt[CSEC_PROMPT_MAX])
{
    char command[CSEC_PROMPT_MAX];
    const bool success = csec_build_redacted_command(redacted, command) &&
        csec_build_redacted_prompt_from_command(command, cwd, tty, prompt);
    csec_wipe(command, sizeof(command));
    return success;
}
#endif

#if (!defined(CSEC_PAM_PROMPT_PREVIEW) && \
    !defined(CSEC_PAM_REDACTOR_PROBE)) || \
    defined(CSEC_PAM_REVIEW_FRAME_PROBE)
static void
csec_store_big_endian_u32(unsigned char output[4], uint32_t value)
{
    output[0] = (unsigned char)((value >> 24) & 0xff);
    output[1] = (unsigned char)((value >> 16) & 0xff);
    output[2] = (unsigned char)((value >> 8) & 0xff);
    output[3] = (unsigned char)(value & 0xff);
}

/*
 * The time limit is the milliseconds left until the module's review deadline.
 * The module rewrites it just before writing the frame
 * (csec_store_review_time_limit), so the helper's countdown starts from what
 * is really left after its launch and signature check.
 */
static void
csec_store_review_time_limit(unsigned char frame[CSEC_REVIEW_FRAME_MAX],
    uint32_t time_limit_milliseconds)
{
    csec_store_big_endian_u32(frame + CSEC_REVIEW_FRAME_TIME_LIMIT_OFFSET,
        time_limit_milliseconds);
}

static bool
csec_build_review_frame(const char *command, const char *cwd, const char *tty,
    uint32_t time_limit_milliseconds,
    unsigned char frame[CSEC_REVIEW_FRAME_MAX], size_t *frame_length)
{
    static const unsigned char magic[8] = {
        'C', 'S', 'E', 'C', 'S', 'U', 'D', 'O',
    };
    char safe_cwd[CSEC_CWD_MAX];
    char safe_tty[CSEC_TTY_MAX];
    csec_sanitize_metadata(cwd, safe_cwd, sizeof(safe_cwd));
    csec_sanitize_metadata(tty, safe_tty, sizeof(safe_tty));

    const size_t command_length = strlen(command);
    const size_t cwd_length = strlen(safe_cwd);
    const size_t tty_length = strlen(safe_tty);
    if (command_length == 0 || command_length >= CSEC_PROMPT_MAX ||
        cwd_length >= CSEC_CWD_MAX || tty_length >= CSEC_TTY_MAX ||
        time_limit_milliseconds == 0 ||
        time_limit_milliseconds > CSEC_REVIEW_TIMEOUT_MILLISECONDS) {
        csec_wipe(safe_cwd, sizeof(safe_cwd));
        csec_wipe(safe_tty, sizeof(safe_tty));
        return false;
    }

    size_t offset = 0;
    memcpy(frame + offset, magic, sizeof(magic));
    offset += sizeof(magic);
    csec_store_big_endian_u32(frame + offset, CSEC_REVIEW_FRAME_VERSION);
    offset += 4;
    csec_store_review_time_limit(frame, time_limit_milliseconds);
    offset += 4;
    csec_store_big_endian_u32(frame + offset, (uint32_t)command_length);
    offset += 4;
    csec_store_big_endian_u32(frame + offset, (uint32_t)cwd_length);
    offset += 4;
    csec_store_big_endian_u32(frame + offset, (uint32_t)tty_length);
    offset += 4;
    memcpy(frame + offset, command, command_length);
    offset += command_length;
    memcpy(frame + offset, safe_cwd, cwd_length);
    offset += cwd_length;
    memcpy(frame + offset, safe_tty, tty_length);
    offset += tty_length;

    csec_wipe(safe_cwd, sizeof(safe_cwd));
    csec_wipe(safe_tty, sizeof(safe_tty));
    *frame_length = offset;
    return true;
}
#endif

static void
csec_build_redactor_unavailable_prompt(const char *cwd, const char *tty,
    char prompt[CSEC_PROMPT_MAX])
{
    char safe_cwd[CSEC_CWD_MAX];
    char safe_tty[CSEC_TTY_MAX];
    csec_sanitize_metadata(cwd, safe_cwd, sizeof(safe_cwd));
    csec_sanitize_metadata(tty, safe_tty, sizeof(safe_tty));
    snprintf(prompt, CSEC_PROMPT_MAX,
        "authorize a submitted sudo request from [%s] on [%s]; arguments are "
        "withheld because the authenticated csec redactor is unavailable or "
        "the invocation exceeds safe review bounds",
        safe_cwd, safe_tty);
}

#if !defined(CSEC_PAM_PROMPT_PREVIEW) || defined(CSEC_PAM_REDACTOR_PROBE)

static void
csec_close_descriptor(int *descriptor)
{
    if (*descriptor >= 0) {
        close(*descriptor);
        *descriptor = -1;
    }
}

static bool
csec_make_cloexec_pipe(int descriptors[2])
{
    if (pipe(descriptors) != 0) {
        return false;
    }
    for (size_t index = 0; index < 2; index++) {
        const int flags = fcntl(descriptors[index], F_GETFD);
        if (flags < 0 ||
            fcntl(descriptors[index], F_SETFD, flags | FD_CLOEXEC) != 0) {
            csec_close_descriptor(&descriptors[0]);
            csec_close_descriptor(&descriptors[1]);
            return false;
        }
    }
    return true;
}

static bool
csec_set_nonblocking(int descriptor)
{
    const int flags = fcntl(descriptor, F_GETFL);
    return flags >= 0 && fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool
csec_write_all(int descriptor, const unsigned char *bytes, size_t byte_count)
{
    size_t offset = 0;
    while (offset < byte_count) {
        const ssize_t written = write(descriptor, bytes + offset,
            byte_count - offset);
        if (written > 0) {
            offset += (size_t)written;
        } else if (written < 0 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
}

static int64_t
csec_monotonic_milliseconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int
csec_poll_until(struct pollfd *descriptors, nfds_t count, int64_t deadline)
{
    for (;;) {
        const int64_t now = csec_monotonic_milliseconds();
        if (now < 0 || now >= deadline) {
            return 0;
        }
        const int result = poll(descriptors, count, (int)(deadline - now));
        if (result >= 0 || errno != EINTR) {
            return result;
        }
        /* Recompute the remaining budget on EVERY interrupted poll. */
    }
}

/*
 * The module's diagnostic trail: one value-free line per stage, in the
 * unified log's process-liveness category, beside the review helper's own
 * lines in sudo-review (SudoReviewLog). Every string is a fixed source label
 * and every number a PID, exit status, signal, errno or OSStatus — never
 * argv, cwd, tty, output or a child's stderr. The tests read the lines
 * through CSEC_PAM_LIVENESS_TEST_SINK.
 */
static void
csec_liveness_write(const char *line)
{
#ifdef CSEC_PAM_LIVENESS_TEST_SINK
    csec_liveness_test_sink(line);
#else
    os_log_t log = os_log_create(CSEC_IDENTIFIER, "process-liveness");
    os_log_with_type(log, OS_LOG_TYPE_DEFAULT, "%{public}s", line);
    os_release(log);
#endif
}

static void
csec_liveness_event(const char *stage, const char *event)
{
    char line[160];
    (void)snprintf(line, sizeof(line), "sudo stage=%s event=%s", stage, event);
    csec_liveness_write(line);
}

/* Why a stage ended as it did: `reason` is a fixed label. */
static void
csec_liveness_reason(const char *stage, const char *event, const char *reason)
{
    char line[160];
    (void)snprintf(line, sizeof(line), "sudo stage=%s event=%s reason=%s",
        stage, event, reason);
    csec_liveness_write(line);
}

/* A stage's number under a fixed name: pid, status, signal, errno, osstatus. */
static void
csec_liveness_value(const char *stage, const char *event, const char *name,
    long long value)
{
    char line[160];
    (void)snprintf(line, sizeof(line), "sudo stage=%s event=%s %s=%lld",
        stage, event, name, value);
    csec_liveness_write(line);
}

static bool
csec_kill_and_reap(pid_t child)
{
    if (child <= 0) {
        return true;
    }
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    const int64_t started = csec_monotonic_milliseconds();
    /* A child stuck in exec/kernel validation need not become waitable even
     * after SIGKILL. Never strand sudo in a blocking reap. An unreaped child
     * remains owned by sudo (no PID reuse) and is adopted when sudo exits. No
     * detached PAM thread may outlive pam_end/dlclose. */
    for (;;) {
        int status = 0;
        const pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child || (waited < 0 && errno == ECHILD)) {
            return true;
        }
        const int64_t now = csec_monotonic_milliseconds();
        if ((waited < 0 && errno != EINTR) || started < 0 || now < started ||
            now - started >= CSEC_CLEANUP_TIMEOUT_MILLISECONDS) {
            csec_liveness_event("cleanup", "reap-pending");
            return false;
        }
        const struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
    }
}

/*
 * Reuse csec's shipping active-secret matcher without moving its catalog into
 * this root process. The PAM module sends a NUL-delimited argv stream through
 * the installed, signed csec launcher's existing `tool-exec ... /bin/cat`
 * broker. POSIX_SPAWN_RESETIDS makes that launcher the invoking login user, so
 * csecd can authenticate it normally. Any error, warning (including skipped
 * short active values), timeout, malformed framing, or partial result fails
 * closed: no argv bytes are returned for display.
 */
static bool
csec_redact_arguments_with_active_catalog(int argc, char *const argv[],
    struct csec_redacted_arguments *redacted)
{
    memset(redacted, 0, sizeof(*redacted));
    if (argc < 1 || (size_t)(argc - 1) > CSEC_ARGUMENT_MAX) {
        csec_liveness_reason("redactor", "unavailable", "argument-count");
        return false;
    }

    unsigned char input[CSEC_ARGUMENT_INPUT_MAX] = {0};
    size_t input_length = 0;
    for (int index = 1; index < argc; index++) {
        if (argv[index] == NULL) {
            csec_wipe(input, sizeof(input));
            csec_liveness_reason("redactor", "unavailable", "argument-missing");
            return false;
        }
        const size_t length = strlen(argv[index]);
        if (length + 1 > sizeof(input) - input_length) {
            csec_wipe(input, sizeof(input));
            csec_liveness_reason("redactor", "unavailable", "arguments-too-long");
            return false;
        }
        memcpy(input + input_length, argv[index], length);
        input_length += length + 1;
    }
    redacted->count = (size_t)(argc - 1);
    if (redacted->count == 0) {
        csec_wipe(input, sizeof(input));
        return true;
    }

    struct stat launcher_status;
    if (lstat(CSEC_INSTALLED_LAUNCHER, &launcher_status) != 0 ||
        !S_ISREG(launcher_status.st_mode) || launcher_status.st_uid != 0 ||
        (launcher_status.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
        (launcher_status.st_mode & S_IXUSR) == 0) {
        csec_wipe(input, sizeof(input));
        csec_liveness_reason("redactor", "unavailable", "launcher-unprotected");
        return false;
    }

    int input_pipe[2] = {-1, -1};
    int output_pipe[2] = {-1, -1};
    int error_pipe[2] = {-1, -1};
    pid_t child = -1;
    bool child_reaped = false;
    bool actions_initialized = false;
    bool attributes_initialized = false;
    bool success = false;
    /* Why the redactor is unavailable, for the trail; set before each exit. */
    const char *failure = "pipe-setup";
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;

    if (!csec_make_cloexec_pipe(input_pipe) ||
        !csec_make_cloexec_pipe(output_pipe) ||
        !csec_make_cloexec_pipe(error_pipe)) {
        goto cleanup;
    }

    /* The bounded input fits in a macOS pipe; preload it before spawning. */
    failure = "input-write";
    if (!csec_write_all(input_pipe[1], input, input_length)) {
        goto cleanup;
    }
    csec_close_descriptor(&input_pipe[1]);
    csec_wipe(input, sizeof(input));

    failure = "spawn-setup";
    if (posix_spawn_file_actions_init(&actions) != 0) {
        goto cleanup;
    }
    actions_initialized = true;
    if (posix_spawn_file_actions_adddup2(&actions, input_pipe[0], STDIN_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(&actions, output_pipe[1], STDOUT_FILENO) != 0 ||
        posix_spawn_file_actions_adddup2(&actions, error_pipe[1], STDERR_FILENO) != 0 ||
        posix_spawn_file_actions_addclose(&actions, input_pipe[0]) != 0 ||
        posix_spawn_file_actions_addclose(&actions, output_pipe[0]) != 0 ||
        posix_spawn_file_actions_addclose(&actions, output_pipe[1]) != 0 ||
        posix_spawn_file_actions_addclose(&actions, error_pipe[0]) != 0 ||
        posix_spawn_file_actions_addclose(&actions, error_pipe[1]) != 0) {
        goto cleanup;
    }

    if (posix_spawnattr_init(&attributes) != 0) {
        goto cleanup;
    }
    attributes_initialized = true;
    short spawn_flags = POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP;
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    spawn_flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
#endif
    if (posix_spawnattr_setflags(&attributes, spawn_flags) != 0 ||
        posix_spawnattr_setpgroup(&attributes, 0) != 0) {
        goto cleanup;
    }

    char *const child_argv[] = {
        (char *)CSEC_INSTALLED_LAUNCHER,
        (char *)"tool-exec",
        (char *)"--destination",
        (char *)"ai",
        (char *)"--",
        (char *)"/bin/cat",
        NULL,
    };
    char *const child_environment[] = {
        (char *)"PATH=/usr/bin:/bin",
        (char *)"LANG=C",
        NULL,
    };
    failure = "clock";
    const int64_t started = csec_monotonic_milliseconds();
    if (started < 0) {
        goto cleanup;
    }
    const int64_t deadline = started + CSEC_REDACTOR_TIMEOUT_MILLISECONDS;
    csec_liveness_event("redactor", "launch-started");
    failure = "spawn";
    const int spawn_error = posix_spawn(&child, CSEC_INSTALLED_LAUNCHER,
        &actions, &attributes, child_argv, child_environment);
    if (spawn_error != 0) {
        child = -1;
        csec_liveness_value("redactor", "spawn-failed", "errno", spawn_error);
        goto cleanup;
    }
    csec_liveness_value("redactor", "launched", "pid", child);

    csec_close_descriptor(&input_pipe[0]);
    csec_close_descriptor(&output_pipe[1]);
    csec_close_descriptor(&error_pipe[1]);
    failure = "pipe-setup";
    if (!csec_set_nonblocking(output_pipe[0]) ||
        !csec_set_nonblocking(error_pipe[0])) {
        goto cleanup;
    }
    /* Reads and polls below end only by timeout or an I/O failure. */
    failure = "io-failure";

    bool output_open = true;
    bool error_open = true;
    size_t output_length = 0;
    bool output_overflow = false;
    bool had_error_output = false;

    while (output_open || error_open) {
        const int64_t now = csec_monotonic_milliseconds();
        if (now < 0 || now >= deadline) {
            csec_liveness_event("redactor", "timeout");
            failure = "timeout";
            goto cleanup;
        }
        struct pollfd descriptors[2] = {
            {
                .fd = output_open ? output_pipe[0] : -1,
                .events = POLLIN | POLLHUP | POLLERR,
                .revents = 0,
            },
            {
                .fd = error_open ? error_pipe[0] : -1,
                .events = POLLIN | POLLHUP | POLLERR,
                .revents = 0,
            },
        };
        const int poll_result = csec_poll_until(descriptors, 2, deadline);
        if (poll_result <= 0 ||
            (descriptors[0].revents & POLLNVAL) != 0 ||
            (descriptors[1].revents & POLLNVAL) != 0) {
            csec_liveness_event("redactor", poll_result == 0 ? "timeout" : "io-failure");
            failure = poll_result == 0 ? "timeout" : "io-failure";
            goto cleanup;
        }

        if (output_open && descriptors[0].revents != 0) {
            while (true) {
                const int64_t reading_at = csec_monotonic_milliseconds();
                if (reading_at < 0 || reading_at >= deadline) {
                    csec_liveness_event("redactor", "timeout");
                    failure = "timeout";
                    goto cleanup;
                }
                unsigned char overflow[512];
                const size_t remaining = sizeof(redacted->storage) - output_length;
                void *target = remaining > 0
                    ? (void *)(redacted->storage + output_length)
                    : (void *)overflow;
                const size_t capacity = remaining > 0 ? remaining : sizeof(overflow);
                const ssize_t count = read(output_pipe[0], target, capacity);
                if (count > 0) {
                    if (remaining > 0) {
                        output_length += (size_t)count;
                    } else {
                        output_overflow = true;
                    }
                } else if (count == 0) {
                    output_open = false;
                    csec_close_descriptor(&output_pipe[0]);
                    break;
                } else if (errno == EINTR) {
                    continue;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                } else {
                    goto cleanup;
                }
            }
        }

        if (error_open && descriptors[1].revents != 0) {
            while (true) {
                const int64_t reading_at = csec_monotonic_milliseconds();
                if (reading_at < 0 || reading_at >= deadline) {
                    csec_liveness_event("redactor", "timeout");
                    failure = "timeout";
                    goto cleanup;
                }
                unsigned char error_bytes[512];
                const ssize_t count = read(error_pipe[0], error_bytes,
                    sizeof(error_bytes));
                if (count > 0) {
                    had_error_output = true;
                    csec_wipe(error_bytes, sizeof(error_bytes));
                } else if (count == 0) {
                    error_open = false;
                    csec_close_descriptor(&error_pipe[0]);
                    break;
                } else if (errno == EINTR) {
                    continue;
                } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                } else {
                    csec_wipe(error_bytes, sizeof(error_bytes));
                    goto cleanup;
                }
            }
        }
    }

    int child_status = 0;
    while (true) {
        const pid_t waited = waitpid(child, &child_status, WNOHANG);
        if (waited == child) {
            child_reaped = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            failure = "wait-failed";
            goto cleanup;
        }
        const int64_t now = csec_monotonic_milliseconds();
        if (now < 0 || now >= deadline) {
            failure = "timeout";
            goto cleanup;
        }
        const struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
    }
    if (WIFSIGNALED(child_status)) {
        csec_liveness_value("redactor", "child-signal", "signal",
            WTERMSIG(child_status));
        failure = "child-signal";
        goto cleanup;
    }
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        csec_liveness_value("redactor", "child-exit", "status",
            WIFEXITED(child_status) ? WEXITSTATUS(child_status) : -1);
        failure = "child-exit";
        goto cleanup;
    }
    /* A warning (an identity complaint, a skipped short active value) fails
     * closed; its text was wiped unread, so only the fact is logged. */
    if (had_error_output) {
        failure = "stderr-output";
        goto cleanup;
    }
    if (output_overflow) {
        failure = "output-overflow";
        goto cleanup;
    }

    failure = "malformed-output";
    size_t offset = 0;
    for (size_t index = 0; index < redacted->count; index++) {
        if (offset >= output_length) {
            goto cleanup;
        }
        char *delimiter = memchr(redacted->storage + offset, '\0',
            output_length - offset);
        if (delimiter == NULL) {
            goto cleanup;
        }
        redacted->arguments[index] = redacted->storage + offset;
        offset = (size_t)(delimiter - redacted->storage) + 1;
    }
    if (offset != output_length) {
        goto cleanup;
    }
    success = true;

cleanup:
    csec_wipe(input, sizeof(input));
    if (actions_initialized) {
        posix_spawn_file_actions_destroy(&actions);
    }
    if (attributes_initialized) {
        posix_spawnattr_destroy(&attributes);
    }
    csec_close_descriptor(&input_pipe[0]);
    csec_close_descriptor(&input_pipe[1]);
    csec_close_descriptor(&output_pipe[0]);
    csec_close_descriptor(&output_pipe[1]);
    csec_close_descriptor(&error_pipe[0]);
    csec_close_descriptor(&error_pipe[1]);
    if (child > 0 && !child_reaped) {
        csec_kill_and_reap(child);
    }
    if (!success) {
        csec_wipe(redacted, sizeof(*redacted));
    }
    if (success) {
        csec_liveness_event("redactor", "completed");
    } else {
        csec_liveness_reason("redactor", "unavailable", failure);
    }
    return success;
}

#endif

/*
 * Supervision of a running review helper. The shipping module uses all of it;
 * packaging/tests/test-pam-cleanup.c compiles it against deterministic doubles
 * by defining CSEC_PAM_REVIEW_SUPERVISION_TEST.
 */
#if (!defined(CSEC_PAM_PROMPT_PREVIEW) && !defined(CSEC_PAM_REDACTOR_PROBE)) || \
    defined(CSEC_PAM_REVIEW_SUPERVISION_TEST)

#define CSEC_REVIEW_POLL_MILLISECONDS 20

enum csec_review_result {
    CSEC_REVIEW_UNSUCCESSFUL,
    CSEC_REVIEW_APPROVED,
    CSEC_REVIEW_INTERRUPTED,
    CSEC_REVIEW_EXPIRED,
};

enum csec_review_wait {
    CSEC_REVIEW_WAIT_EXITED,
    CSEC_REVIEW_WAIT_FAILED,
    CSEC_REVIEW_WAIT_INTERRUPTED,
    CSEC_REVIEW_WAIT_EXPIRED,
};

/* Per-authentication, value-free state shared by the sufficient review and
 * the requisite guard. Allocate it before any fallback, not at the deadline:
 * expiry and interrupts must latch even when allocation would fail then.
 * Missing state fails the guard closed. No wall-clock expiry is added to
 * grants or credentials. */
#define CSEC_REVIEW_STATE_KEY "csec-sudo-review-state"
struct csec_review_state {
    bool expired;
    /* Ctrl-C, Ctrl-\ or a terminal hangup during this authentication. */
    bool interrupted;
};

static void
csec_review_state_cleanup(pam_handle_t *pamh, void *data, int status)
{
    (void)pamh;
    (void)status;
    free(data);
}

static struct csec_review_state *
csec_prepare_review_state(pam_handle_t *pamh)
{
    const void *existing = NULL;
    if (pam_get_data(pamh, CSEC_REVIEW_STATE_KEY, &existing) == PAM_SUCCESS) {
        return (struct csec_review_state *)existing;
    }
    struct csec_review_state *state = calloc(1, sizeof(*state));
    if (state == NULL) {
        return NULL;
    }
    if (pam_set_data(pamh, CSEC_REVIEW_STATE_KEY, state,
            csec_review_state_cleanup) != PAM_SUCCESS) {
        free(state);
        return NULL;
    }
    return state;
}

/*
 * sudo treats authentication as a critical section: sudoers' verify_user()
 * (auth/sudo_auth.c in sudo 1.9.17p2, the installed version) blocks SIGINT and
 * SIGQUIT around pam_authenticate and looks for them only between attempts,
 * through sigpending(2) (user_interrupted()). A Ctrl-C or Ctrl-\ during the
 * csec review is therefore only pending — sudo cannot die of it, so the helper
 * never sees its parent exit — and this module must look at the same set.
 */
static bool
csec_user_interrupted(void)
{
    sigset_t pending;
    if (sigemptyset(&pending) != 0 || sigpending(&pending) != 0) {
        return false;
    }
    return sigismember(&pending, SIGINT) == 1 ||
        sigismember(&pending, SIGQUIT) == 1;
}

/*
 * A descriptor of our own on sudo's terminal, used only to notice the terminal
 * closing. sudo's SIGHUP handler records a hangup for later instead of dying
 * (its src/signal.c), so the signal never shows in sigpending and the tty is
 * watched directly. Only a character-device path under /dev/tty is opened, and
 * only as a tty: read-only, non-blocking, never as a controlling terminal.
 * Returns -1 when there is no terminal to watch; the review then runs as
 * before.
 */
static int
csec_open_tty_watch(const char *tty)
{
    struct stat status;
    if (tty == NULL || strncmp(tty, "/dev/tty", 8) != 0 ||
        lstat(tty, &status) != 0 || !S_ISCHR(status.st_mode)) {
        return -1;
    }
    int descriptor = open(tty, O_RDONLY | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
    if (descriptor >= 0 && isatty(descriptor) != 1) {
        csec_close_descriptor(&descriptor);
    }
    return descriptor;
}

/*
 * Wait up to `milliseconds` for the watched terminal to hang up; with no watch,
 * just pause. Measured on macOS 26.2 against a pty whose master closed:
 * poll(2) reports POLLHUP, and POLLNVAL once the tty is revoked, but only when
 * POLLHUP is requested — with events 0 it reports nothing, unlike POSIX. XNU
 * builds poll on kqueue, whose tty filter sets EV_EOF, so poll(2)'s "does not
 * support devices" caveat does not apply to ttys. Typed input never wakes a
 * POLLHUP-only poll, and nothing is read, so no keystroke is consumed.
 * select(2) cannot tell typed input from a hangup and is not used.
 */
static bool
csec_tty_hung_up(int tty_watch, int milliseconds)
{
    if (tty_watch < 0) {
        const struct timespec pause = {
            .tv_sec = milliseconds / 1000,
            .tv_nsec = (long)(milliseconds % 1000) * 1000000,
        };
        (void)nanosleep(&pause, NULL);
        return false;
    }
    struct pollfd watched = {.fd = tty_watch, .events = POLLHUP, .revents = 0};
    const int result = poll(&watched, 1, milliseconds);
    return result > 0 &&
        (watched.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0;
}

/*
 * Wait for the review helper to exit, for the deadline, for a Ctrl-C or
 * Ctrl-\ at the terminal, or for the terminal to close — whichever comes
 * first. The pause between reaps is the hangup watch itself.
 */
static enum csec_review_wait
csec_wait_for_review(pid_t child, int tty_watch, int64_t deadline,
    int *child_status)
{
    for (;;) {
        if (csec_user_interrupted()) {
            csec_liveness_event("review", "interrupted");
            return CSEC_REVIEW_WAIT_INTERRUPTED;
        }
        const pid_t waited = waitpid(child, child_status, WNOHANG);
        if (waited == child) {
            return CSEC_REVIEW_WAIT_EXITED;
        }
        if (waited < 0 && errno != EINTR) {
            return CSEC_REVIEW_WAIT_FAILED;
        }
        const int64_t now = csec_monotonic_milliseconds();
        if (now < 0) {
            return CSEC_REVIEW_WAIT_FAILED;
        }
        if (now >= deadline) {
            csec_liveness_event("review", "deadline-exceeded");
            return CSEC_REVIEW_WAIT_EXPIRED;
        }
        if (csec_tty_hung_up(tty_watch, CSEC_REVIEW_POLL_MILLISECONDS)) {
            csec_liveness_event("review", "terminal-hangup");
            return CSEC_REVIEW_WAIT_INTERRUPTED;
        }
    }
}

/*
 * What the helper's own exit means. Zero is the sole approval signal. The
 * helper closes an unanswered review just before the deadline and says so
 * with CSEC_REVIEW_EXPIRED_EXIT_STATUS, which ends sudo exactly as the
 * module's own deadline does; this module believes it only within
 * CSEC_REVIEW_EXPIRY_CLAIM_MILLISECONDS of that deadline, by its own clock,
 * so a helper fault that exits early with it keeps Apple's recovery instead
 * of aborting every sudo. Anything else is unsuccessful.
 */
static enum csec_review_result
csec_review_exit_result(int child_status, int64_t deadline)
{
    if (!WIFEXITED(child_status)) {
        if (WIFSIGNALED(child_status)) {
            csec_liveness_value("review", "helper-signal", "signal",
                WTERMSIG(child_status));
        }
        return CSEC_REVIEW_UNSUCCESSFUL;
    }
    csec_liveness_value("review", "helper-exit", "status",
        WEXITSTATUS(child_status));
    if (WEXITSTATUS(child_status) == 0) {
        return CSEC_REVIEW_APPROVED;
    }
    if (WEXITSTATUS(child_status) == CSEC_REVIEW_EXPIRED_EXIT_STATUS) {
        const int64_t now = csec_monotonic_milliseconds();
        if (now >= 0 && deadline - now <= CSEC_REVIEW_EXPIRY_CLAIM_MILLISECONDS) {
            csec_liveness_event("review", "helper-deadline");
            return CSEC_REVIEW_EXPIRED;
        }
    }
    return CSEC_REVIEW_UNSUCCESSFUL;
}

/*
 * Turn a running helper's end into the review result
 * (csec_review_exit_result). Every path that does not end in the helper's own
 * exit kills and reaps it, so no panel outlives the decision.
 */
static enum csec_review_result
csec_supervise_review(pid_t child, int tty_watch, int64_t deadline)
{
    int child_status = 0;
    switch (csec_wait_for_review(child, tty_watch, deadline, &child_status)) {
    case CSEC_REVIEW_WAIT_EXITED:
        return csec_review_exit_result(child_status, deadline);
    case CSEC_REVIEW_WAIT_INTERRUPTED:
        (void)csec_kill_and_reap(child);
        return CSEC_REVIEW_INTERRUPTED;
    case CSEC_REVIEW_WAIT_EXPIRED:
        (void)csec_kill_and_reap(child);
        return CSEC_REVIEW_EXPIRED;
    case CSEC_REVIEW_WAIT_FAILED:
    default:
        csec_liveness_reason("review", "unsuccessful", "wait-failed");
        (void)csec_kill_and_reap(child);
        return CSEC_REVIEW_UNSUCCESSFUL;
    }
}

/*
 * Whether a review result decides this module on its own, and how. Only an
 * unsuccessful review (Use Password or a helper failure) falls through to
 * Apple's fallback prompt. Expiry and an interrupt latch the guard and return
 * IGNORE so its requisite ABORT is the first PAM error: OpenPAM otherwise
 * retains an earlier sufficient-factor error, which sudo would count as a
 * failed attempt and retry, or, with a Ctrl-C pending, report as an incorrect
 * password. The human asked to stop, not for another dialog.
 */
static bool
csec_review_decides_module(enum csec_review_result result,
    struct csec_review_state *state, int *pam_status)
{
    switch (result) {
    case CSEC_REVIEW_APPROVED:
        *pam_status = PAM_SUCCESS;
        return true;
    case CSEC_REVIEW_INTERRUPTED:
        state->interrupted = true;
        *pam_status = PAM_IGNORE;
        return true;
    case CSEC_REVIEW_EXPIRED:
        state->expired = true;
        *pam_status = PAM_IGNORE;
        return true;
    case CSEC_REVIEW_UNSUCCESSFUL:
    default:
        return false;
    }
}

/*
 * Tell the terminal why sudo stopped (CSEC_REVIEW_EXPIRED_MESSAGE or
 * CSEC_REVIEW_INTERRUPTED_MESSAGE). sudo prints a module's PAM_ERROR_MSG to
 * the tty, or to stderr without one (sudo 1.9.17p2 auth/pam.c converse), just
 * before its own "PAM authentication error", which names no cause. A coding
 * agent's sudo reads the same line on stderr, as its secret and SSH requests
 * read csecd's timeout message. Best effort: a missing or failing
 * conversation changes nothing about the result. sudo passes PAM_SILENT by
 * default, yet prints error messages regardless; this one is sent whatever
 * the flags say, deliberately: the alternative is an abort that names no
 * cause, after a panel the human may have watched close.
 */
static void
csec_report_review_end(pam_handle_t *pamh, const char *text)
{
    const void *item = NULL;
    if (pam_get_item(pamh, PAM_CONV, &item) != PAM_SUCCESS || item == NULL) {
        return;
    }
    const struct pam_conv *conversation = (const struct pam_conv *)item;
    if (conversation->conv == NULL) {
        return;
    }
    struct pam_message message = {
        .msg_style = PAM_ERROR_MSG,
        .msg = (char *)text,
    };
    const struct pam_message *messages[] = {&message};
    struct pam_response *responses = NULL;
    if (conversation->conv(1, messages, &responses,
            conversation->appdata_ptr) == PAM_SUCCESS && responses != NULL) {
        free(responses[0].resp);
        free(responses);
    }
}

/*
 * The requisite factor right after the review. It stops the whole stack when
 * this authentication's review expired or was interrupted, so neither
 * pam_tid's Touch ID sheet nor sudo's password prompt runs. sudo maps
 * PAM_ABORT to a fatal error (auth/pam.c sudo_pam_verify), not a failed
 * attempt, so it neither retries nor waits at a prompt; the Ctrl-C still
 * pending is caught by sudo's own handler once its signal mask is restored.
 * A Ctrl-C still pending here that the review did not latch came outside the
 * review, typically during Apple's Use Password dialog: it ends sudo too,
 * rather than opening pam_tid. Missing state fails closed.
 */
static int
csec_review_guard(pam_handle_t *pamh)
{
    const void *data = NULL;
    if (pam_get_data(pamh, CSEC_REVIEW_STATE_KEY, &data) != PAM_SUCCESS ||
        data == NULL) {
        return PAM_ABORT;
    }
    struct csec_review_state *state = (struct csec_review_state *)data;
    if (!state->expired && !state->interrupted && csec_user_interrupted()) {
        state->interrupted = true;
        csec_report_review_end(pamh, CSEC_REVIEW_INTERRUPTED_MESSAGE);
    }
    return state->expired || state->interrupted ? PAM_ABORT : PAM_SUCCESS;
}

#endif

#if !defined(CSEC_PAM_PROMPT_PREVIEW) && !defined(CSEC_PAM_REDACTOR_PROBE)

static bool
csec_review_helper_is_protected(void)
{
    static const char *const directories[] = {
        "/", "/usr", "/usr/local", "/usr/local/libexec", NULL,
    };
    struct stat status;
    for (size_t index = 0; directories[index] != NULL; index++) {
        if (lstat(directories[index], &status) != 0 ||
            !S_ISDIR(status.st_mode) || status.st_uid != 0 ||
            (status.st_mode & (S_IWGRP | S_IWOTH)) != 0 ||
            access(directories[index], W_OK) == 0) {
            return false;
        }
    }

    return lstat(CSEC_SUDO_REVIEW_HELPER, &status) == 0 &&
        S_ISREG(status.st_mode) && status.st_uid == 0 &&
        (status.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
        (status.st_mode & S_IXUSR) != 0 &&
        access(CSEC_SUDO_REVIEW_HELPER, W_OK) != 0;
}

static bool
csec_write_all_until(int descriptor, const unsigned char *bytes,
    size_t byte_count, int64_t deadline)
{
    if (!csec_set_nonblocking(descriptor)) {
        return false;
    }
    size_t offset = 0;
    while (offset < byte_count) {
        const ssize_t written = write(descriptor, bytes + offset,
            byte_count - offset);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written >= 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            return false;
        }

        const int64_t now = csec_monotonic_milliseconds();
        if (now < 0 || now >= deadline) {
            return false;
        }
        struct pollfd writable = {
            .fd = descriptor,
            .events = POLLOUT | POLLHUP | POLLERR,
            .revents = 0,
        };
        const int poll_result = csec_poll_until(&writable, 1, deadline);
        if (poll_result <= 0 ||
            (writable.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            return false;
        }
    }
    return true;
}

static bool
csec_entitlement_is_true(CFDictionaryRef entitlements, CFStringRef key)
{
    if (entitlements == NULL) {
        return false;
    }
    const CFTypeRef value = CFDictionaryGetValue(entitlements, key);
    return value != NULL && CFGetTypeID(value) == CFBooleanGetTypeID() &&
        CFBooleanGetValue((CFBooleanRef)value);
}

/*
 * Validate the exact kernel guest created by posix_spawn while it is still
 * suspended. Hardened runtime supplies code-signing enforcement, hard/kill
 * identity stability, library validation, and debugger restrictions. The
 * weakening entitlements below are forbidden, matching ProductCodeIdentity.
 */
static bool
csec_review_process_is_hardened(pid_t child)
{
    CFNumberRef pid_number = NULL;
    CFDictionaryRef attributes = NULL;
    SecCodeRef dynamic_code = NULL;
    SecStaticCodeRef static_code = NULL;
    CFDictionaryRef information = NULL;
    bool valid = false;

    int process_identifier = child;
    pid_number = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType,
        &process_identifier);
    if (pid_number == NULL) {
        goto cleanup;
    }
    const void *attribute_keys[] = {kSecGuestAttributePid};
    const void *attribute_values[] = {pid_number};
    attributes = CFDictionaryCreate(kCFAllocatorDefault, attribute_keys,
        attribute_values, 1, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);
    if (attributes == NULL ||
        SecCodeCopyGuestWithAttributes(NULL, attributes, kSecCSDefaultFlags,
            &dynamic_code) != errSecSuccess || dynamic_code == NULL ||
        SecCodeCheckValidity(dynamic_code, kSecCSStrictValidate, NULL) !=
            errSecSuccess ||
        SecCodeCopyStaticCode(dynamic_code, kSecCSDefaultFlags, &static_code) !=
            errSecSuccess || static_code == NULL ||
        SecStaticCodeCheckValidity(static_code, kSecCSStrictValidate, NULL) !=
            errSecSuccess ||
        SecCodeCopySigningInformation(static_code, kSecCSSigningInformation,
            &information) != errSecSuccess || information == NULL) {
        goto cleanup;
    }

    const CFTypeRef flags_value = CFDictionaryGetValue(information,
        kSecCodeInfoFlags);
    int64_t signature_flags = 0;
    if (flags_value == NULL ||
        CFGetTypeID(flags_value) != CFNumberGetTypeID() ||
        !CFNumberGetValue((CFNumberRef)flags_value, kCFNumberSInt64Type,
            &signature_flags) ||
        ((uint64_t)signature_flags & kSecCodeSignatureRuntime) == 0) {
        goto cleanup;
    }

    const CFTypeRef identifier = CFDictionaryGetValue(information,
        kSecCodeInfoIdentifier);
    if (identifier == NULL || CFGetTypeID(identifier) != CFStringGetTypeID() ||
        !CFEqual(identifier, CFSTR(CSEC_SUDO_REVIEW_IDENTIFIER))) {
        goto cleanup;
    }

    CFDictionaryRef entitlements = NULL;
    const CFTypeRef entitlement_value = CFDictionaryGetValue(information,
        kSecCodeInfoEntitlementsDict);
    if (entitlement_value != NULL &&
        CFGetTypeID(entitlement_value) == CFDictionaryGetTypeID()) {
        entitlements = (CFDictionaryRef)entitlement_value;
    }
    static const CFStringRef forbidden_entitlements[] = {
        CFSTR("com.apple.security.get-task-allow"),
        CFSTR("com.apple.security.cs.disable-library-validation"),
        CFSTR("com.apple.security.cs.allow-dyld-environment-variables"),
        CFSTR("com.apple.security.cs.allow-jit"),
        CFSTR("com.apple.security.cs.allow-unsigned-executable-memory"),
        CFSTR("com.apple.security.cs.disable-executable-page-protection"),
        CFSTR("com.apple.security.cs.debugger"),
        NULL,
    };
    for (size_t index = 0; forbidden_entitlements[index] != NULL; index++) {
        if (csec_entitlement_is_true(entitlements,
                forbidden_entitlements[index])) {
            goto cleanup;
        }
    }
    valid = true;

cleanup:
    if (information != NULL) {
        CFRelease(information);
    }
    if (static_code != NULL) {
        CFRelease(static_code);
    }
    if (dynamic_code != NULL) {
        CFRelease(dynamic_code);
    }
    if (attributes != NULL) {
        CFRelease(attributes);
    }
    if (pid_number != NULL) {
        CFRelease(pid_number);
    }
    return valid;
}

/*
 * The helper runs with the invoking user's real IDs, owns the AppKit window
 * and embedded LAContext, and receives only the frozen redacted display. Exit
 * zero is the sole approval signal. Any other status or launch failure is
 * unsuccessful so this module can use its retained Apple
 * UI fallback. A running review's deadline expires the authentication;
 * Ctrl-C, Ctrl-\ or terminal hangup interrupts the review.
 */
static enum csec_review_result
csec_try_custom_review(const char *command, const char *cwd, const char *tty)
{
    /* A Ctrl-C during redaction already answers the review it would show. */
    if (csec_user_interrupted()) {
        csec_liveness_reason("review", "interrupted", "before-launch");
        return CSEC_REVIEW_INTERRUPTED;
    }
    if (!csec_review_helper_is_protected()) {
        csec_liveness_reason("review", "unsuccessful", "helper-unprotected");
        return CSEC_REVIEW_UNSUCCESSFUL;
    }

    unsigned char frame[CSEC_REVIEW_FRAME_MAX] = {0};
    size_t frame_length = 0;
    if (!csec_build_review_frame(command, cwd, tty,
            CSEC_REVIEW_TIMEOUT_MILLISECONDS, frame, &frame_length)) {
        csec_wipe(frame, sizeof(frame));
        csec_liveness_reason("review", "unsuccessful", "frame-build");
        return CSEC_REVIEW_UNSUCCESSFUL;
    }

    int input_pipe[2] = {-1, -1};
    int tty_watch = -1;
    pid_t child = -1;
    bool child_reaped = false;
    bool actions_initialized = false;
    bool attributes_initialized = false;
    enum csec_review_result result = CSEC_REVIEW_UNSUCCESSFUL;
    /* Why a review that never reached supervision failed, for the trail. */
    const char *failure = "spawn-setup";
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;

    if (!csec_make_cloexec_pipe(input_pipe)) {
        goto cleanup;
    }
#ifdef F_SETNOSIGPIPE
    if (fcntl(input_pipe[1], F_SETNOSIGPIPE, 1) != 0) {
        goto cleanup;
    }
#endif

    if (posix_spawn_file_actions_init(&actions) != 0) {
        goto cleanup;
    }
    actions_initialized = true;
    /* The helper writes its own value-free trail to the unified log
     * (SudoReviewLog), so its stdout and stderr go nowhere: relaying them
     * would bring unbounded child text into this root process. */
    if (posix_spawn_file_actions_adddup2(&actions, input_pipe[0], STDIN_FILENO) != 0 ||
        posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null",
            O_WRONLY, 0) != 0 ||
        posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null",
            O_WRONLY, 0) != 0 ||
        posix_spawn_file_actions_addclose(&actions, input_pipe[0]) != 0 ||
        posix_spawn_file_actions_addclose(&actions, input_pipe[1]) != 0) {
        goto cleanup;
    }

    if (posix_spawnattr_init(&attributes) != 0) {
        goto cleanup;
    }
    attributes_initialized = true;
    short spawn_flags = POSIX_SPAWN_RESETIDS | POSIX_SPAWN_SETPGROUP |
        POSIX_SPAWN_START_SUSPENDED;
#ifdef POSIX_SPAWN_CLOEXEC_DEFAULT
    spawn_flags |= POSIX_SPAWN_CLOEXEC_DEFAULT;
#endif
    if (posix_spawnattr_setflags(&attributes, spawn_flags) != 0 ||
        posix_spawnattr_setpgroup(&attributes, 0) != 0) {
        goto cleanup;
    }

    failure = "clock";
    const int64_t started = csec_monotonic_milliseconds();
    if (started < 0) {
        goto cleanup;
    }
    const int64_t deadline = started + CSEC_REVIEW_TIMEOUT_MILLISECONDS;

    char *const child_argv[] = {
        (char *)CSEC_SUDO_REVIEW_HELPER,
        NULL,
    };
    char *const child_environment[] = {
        (char *)"PATH=/usr/bin:/bin",
        (char *)"LANG=C",
        NULL,
    };
    csec_liveness_event("review", "launch-started");
    failure = "spawn";
    const int spawn_error = posix_spawn(&child, CSEC_SUDO_REVIEW_HELPER,
        &actions, &attributes, child_argv, child_environment);
    if (spawn_error != 0) {
        child = -1;
        csec_liveness_value("review", "spawn-failed", "errno", spawn_error);
        goto cleanup;
    }

    csec_liveness_value("review", "signature-check-started", "pid", child);
    failure = "signature-rejected";
    if (!csec_review_process_is_hardened(child)) {
        goto cleanup;
    }
    failure = "resume-failed";
    const int64_t validated_at = csec_monotonic_milliseconds();
    if (validated_at < 0 || validated_at >= deadline || kill(child, SIGCONT) != 0) {
        goto cleanup;
    }
    csec_liveness_event("review", "running");

    failure = "frame-write";
    csec_close_descriptor(&input_pipe[0]);
    const int64_t writing_at = csec_monotonic_milliseconds();
    if (writing_at < 0 || writing_at >= deadline) {
        goto cleanup;
    }
    csec_store_review_time_limit(frame, (uint32_t)(deadline - writing_at));
    if (!csec_write_all_until(input_pipe[1], frame, frame_length, deadline)) {
        goto cleanup;
    }
    csec_close_descriptor(&input_pipe[1]);
    csec_wipe(frame, sizeof(frame));

    tty_watch = csec_open_tty_watch(tty);
    result = csec_supervise_review(child, tty_watch, deadline);
    /* Supervision reaps the helper, or kills and reaps it, on every path, and
     * logs how the helper ended itself. */
    child_reaped = true;
    failure = NULL;

cleanup:
    csec_wipe(frame, sizeof(frame));
    if (actions_initialized) {
        posix_spawn_file_actions_destroy(&actions);
    }
    if (attributes_initialized) {
        posix_spawnattr_destroy(&attributes);
    }
    csec_close_descriptor(&input_pipe[0]);
    csec_close_descriptor(&input_pipe[1]);
    csec_close_descriptor(&tty_watch);
    if (child > 0 && !child_reaped) {
        csec_kill_and_reap(child);
    }
    if (failure != NULL) {
        csec_liveness_reason("review", "unsuccessful", failure);
    } else {
        csec_liveness_event("review",
            result == CSEC_REVIEW_APPROVED ? "approved"
                : result == CSEC_REVIEW_EXPIRED ? "expired"
                : result == CSEC_REVIEW_INTERRUPTED ? "interrupted"
                : "unsuccessful");
    }
    return result;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
    const char **module_arguments)
{
    (void)flags;

    const void *service_item = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, &service_item) != PAM_SUCCESS ||
        service_item == NULL || strcmp((const char *)service_item, "sudo") != 0) {
        return PAM_IGNORE;
    }

    if (argc == 1 && strcmp(module_arguments[0], "review_guard") == 0) {
        return csec_review_guard(pamh);
    }
    if (argc != 0) {
        return PAM_SERVICE_ERR;
    }
    struct csec_review_state *review_state = csec_prepare_review_state(pamh);
    if (review_state == NULL) {
        return PAM_BUF_ERR;
    }
    if (review_state->expired || review_state->interrupted) {
        return PAM_IGNORE;
    }

    const void *askpass = NULL;
    if (pam_get_data(pamh, "askpass-enabled", &askpass) == PAM_SUCCESS) {
        csec_liveness_reason("review", "skipped", "askpass");
        return PAM_IGNORE;
    }

    SessionAttributeBits session_attributes = 0;
    if (SessionGetInfo(callerSecuritySession, NULL, &session_attributes) !=
            errSessionSuccess ||
        (session_attributes & sessionHasGraphicAccess) == 0) {
        csec_liveness_reason("review", "skipped", "no-gui-session");
        return PAM_IGNORE;
    }

    const char *user = NULL;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL) {
        return PAM_AUTHINFO_UNAVAIL;
    }

    int process_argc = *_NSGetArgc();
    char **process_argv = *_NSGetArgv();
    if (process_argc <= 0 || process_argv == NULL) {
        return PAM_AUTHINFO_UNAVAIL;
    }

    char cwd[CSEC_CWD_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(cwd, sizeof(cwd), "unknown");
    }

    const void *tty_item = NULL;
    const char *tty = "no tty";
    if (pam_get_item(pamh, PAM_TTY, &tty_item) == PAM_SUCCESS &&
        tty_item != NULL && ((const char *)tty_item)[0] != '\0') {
        tty = (const char *)tty_item;
    }

    char command[CSEC_PROMPT_MAX] = {0};
    char prompt[CSEC_PROMPT_MAX] = {0};
    struct csec_redacted_arguments redacted;
    const bool redaction_available =
        csec_redact_arguments_with_active_catalog(process_argc, process_argv,
            &redacted);
    const bool command_available = redaction_available &&
        csec_build_redacted_command(&redacted, command);
    csec_wipe(&redacted, sizeof(redacted));

    if (command_available) {
        int review_status = PAM_AUTH_ERR;
        const enum csec_review_result review =
            csec_try_custom_review(command, cwd, tty);
        if (review == CSEC_REVIEW_EXPIRED) {
            csec_report_review_end(pamh, CSEC_REVIEW_EXPIRED_MESSAGE);
        } else if (review == CSEC_REVIEW_INTERRUPTED) {
            csec_report_review_end(pamh, CSEC_REVIEW_INTERRUPTED_MESSAGE);
        }
        if (csec_review_decides_module(review, review_state, &review_status)) {
            csec_wipe(command, sizeof(command));
            csec_wipe(prompt, sizeof(prompt));
            return review_status;
        }
    } else if (csec_user_interrupted()) {
        /* Interrupted during redaction: no review, and no fallback prompt. */
        csec_wipe(command, sizeof(command));
        csec_wipe(prompt, sizeof(prompt));
        int interrupted_status = PAM_IGNORE;
        (void)csec_review_decides_module(CSEC_REVIEW_INTERRUPTED, review_state,
            &interrupted_status);
        csec_report_review_end(pamh, CSEC_REVIEW_INTERRUPTED_MESSAGE);
        return interrupted_status;
    }

    if (!command_available ||
        !csec_build_redacted_prompt_from_command(command, cwd, tty, prompt)) {
        csec_wipe(prompt, sizeof(prompt));
        csec_build_redactor_unavailable_prompt(cwd, tty, prompt);
    }
    csec_wipe(command, sizeof(command));

    csec_liveness_reason("fallback", "apple-prompt",
        command_available ? "review-unsuccessful" : "redactor-unavailable");
    AuthorizationRef authorization = NULL;
    OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
        kAuthorizationFlagDefaults, &authorization);
    if (status != errAuthorizationSuccess || authorization == NULL) {
        csec_wipe(prompt, sizeof(prompt));
        csec_liveness_value("fallback", "unavailable", "osstatus", status);
        return PAM_AUTHINFO_UNAVAIL;
    }

    AuthorizationItem right_item = {
        "com.apple.security.sudo",
        0,
        NULL,
        0,
    };
    AuthorizationRights rights = {1, &right_item};
    AuthorizationItem environment_item = {
        kAuthorizationEnvironmentPrompt,
        strlen(prompt),
        prompt,
        0,
    };
    AuthorizationEnvironment environment = {1, &environment_item};
    AuthorizationRights *authorized_rights = NULL;
    const AuthorizationFlags authorization_flags =
        kAuthorizationFlagDefaults |
        kAuthorizationFlagInteractionAllowed |
        kAuthorizationFlagExtendRights;

    status = AuthorizationCopyRights(authorization, &rights, &environment,
        authorization_flags, &authorized_rights);
    csec_wipe(prompt, sizeof(prompt));
    if (authorized_rights != NULL) {
        AuthorizationFreeItemSet(authorized_rights);
    }
    AuthorizationFree(authorization, kAuthorizationFlagDefaults);
    csec_liveness_value("fallback", "finished", "osstatus", status);

    if (status == errAuthorizationSuccess) {
        return PAM_SUCCESS;
    }
    if (status == errAuthorizationInteractionNotAllowed) {
        return PAM_IGNORE;
    }
    return PAM_AUTH_ERR;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
    const char **module_arguments)
{
    (void)pamh;
    (void)flags;
    (void)argc;
    (void)module_arguments;
    return PAM_SUCCESS;
}

#elif defined(CSEC_PAM_REDACTOR_PROBE)

int
main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s [sudo arguments ...]\n", argv[0]);
        return 64;
    }

    char cwd[CSEC_CWD_MAX];
    if (getcwd(cwd, sizeof(cwd)) == NULL) {
        snprintf(cwd, sizeof(cwd), "unknown");
    }
    struct csec_redacted_arguments redacted;
    char prompt[CSEC_PROMPT_MAX];
    if (!csec_redact_arguments_with_active_catalog(argc, argv, &redacted) ||
        !csec_build_redacted_prompt(&redacted, cwd, "redactor probe", prompt)) {
        csec_build_redactor_unavailable_prompt(cwd, "redactor probe", prompt);
        csec_wipe(&redacted, sizeof(redacted));
        puts(prompt);
        csec_wipe(prompt, sizeof(prompt));
        return 69;
    }
    csec_wipe(&redacted, sizeof(redacted));
    puts(prompt);
    csec_wipe(prompt, sizeof(prompt));
    return 0;
}

#else

static bool
csec_copy_preview_arguments(int argc, char *const argv[],
    struct csec_redacted_arguments *redacted)
{
    memset(redacted, 0, sizeof(*redacted));
    if (argc < 1 || (size_t)(argc - 1) > CSEC_ARGUMENT_MAX) {
        return false;
    }
    redacted->count = (size_t)(argc - 1);
    size_t offset = 0;
    for (int index = 1; index < argc; index++) {
        const size_t length = strlen(argv[index]);
        if (length + 1 > sizeof(redacted->storage) - offset) {
            csec_wipe(redacted, sizeof(*redacted));
            return false;
        }
        redacted->arguments[index - 1] = redacted->storage + offset;
        memcpy(redacted->storage + offset, argv[index], length + 1);
        offset += length + 1;
    }
    return true;
}

int
main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s sudo [sudo arguments ...]\n", argv[0]);
        return 64;
    }

#ifdef CSEC_PAM_REVIEW_FRAME_PROBE
    char command[CSEC_PROMPT_MAX] = {0};
    unsigned char frame[CSEC_REVIEW_FRAME_MAX] = {0};
    size_t frame_length = 0;
    struct csec_redacted_arguments redacted;
    const bool success =
        csec_copy_preview_arguments(argc - 1, argv + 1, &redacted) &&
        csec_build_redacted_command(&redacted, command) &&
        csec_build_review_frame(command, "/Users/example/project",
            "/dev/ttys001", CSEC_REVIEW_TIMEOUT_MILLISECONDS, frame,
            &frame_length) &&
        fwrite(frame, frame_length, 1, stdout) == 1;
    csec_wipe(&redacted, sizeof(redacted));
    csec_wipe(command, sizeof(command));
    csec_wipe(frame, sizeof(frame));
    return success ? 0 : 1;
#else
    char prompt[CSEC_PROMPT_MAX];
    struct csec_redacted_arguments redacted;
    if (argc == 3 && strcmp(argv[2], "--redactor-unavailable-preview") == 0) {
        csec_build_redactor_unavailable_prompt(
            "/Users/example/project", "/dev/ttys001", prompt);
    } else if (!csec_copy_preview_arguments(argc - 1, argv + 1, &redacted) ||
        !csec_build_redacted_prompt(&redacted, "/Users/example/project",
            "/dev/ttys001", prompt)) {
        csec_build_redactor_unavailable_prompt(
            "/Users/example/project", "/dev/ttys001", prompt);
    }
    csec_wipe(&redacted, sizeof(redacted));
    puts(prompt);
    csec_wipe(prompt, sizeof(prompt));
    return 0;
#endif
}

#endif
