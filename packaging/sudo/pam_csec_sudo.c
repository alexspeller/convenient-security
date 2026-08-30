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
 * The module is deliberately installed as a sufficient factor immediately
 * before stock pam_tid. Any csec failure therefore leaves the normal Touch ID
 * and password path available.
 */

#include <Security/AuthSession.h>
#include <Security/Authorization.h>
#include <Security/AuthorizationTags.h>
#include <Security/CSCommon.h>
#include <Security/SecBase.h>
#include <Security/SecCode.h>
#include <Security/SecStaticCode.h>
#include <crt_externs.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <poll.h>
#include <spawn.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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
#define CSEC_REVIEW_FRAME_HEADER_BYTES 24
#define CSEC_REVIEW_FRAME_MAX \
    (CSEC_REVIEW_FRAME_HEADER_BYTES + CSEC_PROMPT_MAX - 1 + \
        CSEC_CWD_MAX - 1 + CSEC_TTY_MAX - 1)

#define CSEC_INSTALLED_LAUNCHER \
    "/Applications/ConvenientSecurity.app/Contents/MacOS/csec"
#define CSEC_SUDO_REVIEW_HELPER \
    "/usr/local/libexec/csec-sudo-review"
#define CSEC_SUDO_REVIEW_IDENTIFIER \
    "com.alexspeller.convenient-security.sudo-review"

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

static unsigned char
csec_upper_name_byte(unsigned char byte)
{
    if (byte >= 'a' && byte <= 'z') {
        return (unsigned char)(byte - ('a' - 'A'));
    }
    return byte == '-' ? '_' : byte;
}

static bool
csec_name_contains_marker(const char *name, size_t name_length,
    const char *marker)
{
    const size_t marker_length = strlen(marker);
    if (marker_length > name_length) {
        return false;
    }
    for (size_t start = 0; start + marker_length <= name_length; start++) {
        bool matches = true;
        for (size_t offset = 0; offset < marker_length; offset++) {
            if (csec_upper_name_byte((unsigned char)name[start + offset]) !=
                (unsigned char)marker[offset]) {
                matches = false;
                break;
            }
        }
        if (matches) {
            return true;
        }
    }
    return false;
}

/* Keep this marker set aligned with SecretHeuristics.nameLooksSecretLike. */
static bool
csec_name_looks_secret_like(const char *name, size_t name_length)
{
    static const char *const markers[] = {
        "TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "PRIVATE_KEY",
        "ACCESS_KEY", "CREDENTIAL", "AUTH", "SIGNING_KEY", "ENCRYPTION_KEY",
        "COOKIE", "WEBHOOK", "DATABASE_URL", "REDIS_URL", "DSN", NULL,
    };
    while (name_length > 0 && *name == '-') {
        name++;
        name_length--;
    }
    for (size_t index = 0; markers[index] != NULL; index++) {
        if (csec_name_contains_marker(name, name_length, markers[index])) {
            return true;
        }
    }
    return false;
}

static bool
csec_is_token_byte(unsigned char byte)
{
    return (byte >= 'A' && byte <= 'Z') ||
        (byte >= 'a' && byte <= 'z') ||
        (byte >= '0' && byte <= '9') ||
        byte == '+' || byte == '/' || byte == '=' || byte == '_' ||
        byte == '-' || byte == '.' || byte == ':';
}

static bool
csec_is_hex_byte(unsigned char byte)
{
    return (byte >= '0' && byte <= '9') ||
        (byte >= 'a' && byte <= 'f') ||
        (byte >= 'A' && byte <= 'F');
}

static bool
csec_is_base64_byte(unsigned char byte)
{
    return (byte >= 'A' && byte <= 'Z') ||
        (byte >= 'a' && byte <= 'z') ||
        (byte >= '0' && byte <= '9') ||
        byte == '+' || byte == '/' || byte == '=' || byte == '_' || byte == '-';
}

static bool
csec_has_known_secret_prefix(const char *value)
{
    static const char *const prefixes[] = {
        "sk-", "sk_live_", "sk_test_", "rk_live_",
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
        "glpat-", "npm_", "dop_v1_", "shpat_", "shpss_",
        "AKIA", "ASIA", "AIza", "eyJ", NULL,
    };
    for (size_t index = 0; prefixes[index] != NULL; index++) {
        if (strncmp(value, prefixes[index], strlen(prefixes[index])) == 0) {
            return true;
        }
    }
    return strlen(value) >= 5 && value[0] == 'x' && value[1] == 'o' &&
        value[2] == 'x' && value[4] == '-';
}

/* Keep this conservative detector aligned with SecretHeuristics. */
static bool
csec_value_looks_secret_like(const char *value)
{
    if (strstr(value, "-----BEGIN") != NULL &&
        strstr(value, "PRIVATE KEY") != NULL) {
        return true;
    }
    const size_t length = strlen(value);
    if (length < 8) {
        return false;
    }
    if (csec_has_known_secret_prefix(value)) {
        return true;
    }
    if (length < 20) {
        return false;
    }

    size_t token_byte_count = 0;
    bool has_letter = false;
    bool has_digit = false;
    bool all_hex = true;
    bool all_base64 = true;
    size_t counts[256] = {0};
    for (size_t index = 0; index < length; index++) {
        const unsigned char byte = (unsigned char)value[index];
        if (byte == ' ' || byte == '\t') {
            return false;
        }
        counts[byte]++;
        if (csec_is_token_byte(byte)) {
            token_byte_count++;
        }
        has_letter = has_letter ||
            (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z');
        has_digit = has_digit || (byte >= '0' && byte <= '9');
        all_hex = all_hex && csec_is_hex_byte(byte);
        all_base64 = all_base64 && csec_is_base64_byte(byte);
    }
    if ((double)token_byte_count < 0.9 * (double)length) {
        return false;
    }
    if (length >= 32 && all_hex) {
        return true;
    }
    if (!has_letter || !has_digit) {
        return false;
    }
    if (length >= 24 && all_base64) {
        return true;
    }

    double entropy = 0.0;
    for (size_t index = 0; index < 256; index++) {
        if (counts[index] == 0) {
            continue;
        }
        const double probability = (double)counts[index] / (double)length;
        entropy -= probability * log2(probability);
    }
    return entropy >= 3.5;
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
        if (csec_name_looks_secret_like(argument, name_length) ||
            csec_value_looks_secret_like(equals + 1)) {
            if (name_length + 1 + strlen(redacted) < 256) {
                memcpy(replacement, argument, name_length + 1);
                strcpy(replacement + name_length + 1, redacted);
                return replacement;
            }
            return redacted;
        }
    }

    if (argument[0] == '-' && equals == NULL &&
        csec_name_looks_secret_like(argument, strlen(argument))) {
        *redact_next = true;
    }
    if (csec_value_looks_secret_like(argument)) {
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

static bool
csec_build_review_frame(const char *command, const char *cwd, const char *tty,
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
        cwd_length >= CSEC_CWD_MAX || tty_length >= CSEC_TTY_MAX) {
        csec_wipe(safe_cwd, sizeof(safe_cwd));
        csec_wipe(safe_tty, sizeof(safe_tty));
        return false;
    }

    size_t offset = 0;
    memcpy(frame + offset, magic, sizeof(magic));
    offset += sizeof(magic);
    csec_store_big_endian_u32(frame + offset, 1);
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

static void
csec_kill_and_reap(pid_t child)
{
    if (child <= 0) {
        return;
    }
    (void)kill(-child, SIGKILL);
    (void)kill(child, SIGKILL);
    int status = 0;
    while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
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
        return false;
    }

    unsigned char input[CSEC_ARGUMENT_INPUT_MAX] = {0};
    size_t input_length = 0;
    for (int index = 1; index < argc; index++) {
        if (argv[index] == NULL) {
            csec_wipe(input, sizeof(input));
            return false;
        }
        const size_t length = strlen(argv[index]);
        if (length + 1 > sizeof(input) - input_length) {
            csec_wipe(input, sizeof(input));
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
    posix_spawn_file_actions_t actions;
    posix_spawnattr_t attributes;

    if (!csec_make_cloexec_pipe(input_pipe) ||
        !csec_make_cloexec_pipe(output_pipe) ||
        !csec_make_cloexec_pipe(error_pipe)) {
        goto cleanup;
    }

    /* The bounded input fits in a macOS pipe; preload it before spawning. */
    if (!csec_write_all(input_pipe[1], input, input_length)) {
        goto cleanup;
    }
    csec_close_descriptor(&input_pipe[1]);
    csec_wipe(input, sizeof(input));

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
    if (posix_spawn(&child, CSEC_INSTALLED_LAUNCHER, &actions, &attributes,
            child_argv, child_environment) != 0) {
        child = -1;
        goto cleanup;
    }

    csec_close_descriptor(&input_pipe[0]);
    csec_close_descriptor(&output_pipe[1]);
    csec_close_descriptor(&error_pipe[1]);
    if (!csec_set_nonblocking(output_pipe[0]) ||
        !csec_set_nonblocking(error_pipe[0])) {
        goto cleanup;
    }

    const int64_t started = csec_monotonic_milliseconds();
    if (started < 0) {
        goto cleanup;
    }
    const int64_t deadline = started + CSEC_REDACTOR_TIMEOUT_MILLISECONDS;
    bool output_open = true;
    bool error_open = true;
    size_t output_length = 0;
    bool output_overflow = false;
    bool had_error_output = false;

    while (output_open || error_open) {
        const int64_t now = csec_monotonic_milliseconds();
        if (now < 0 || now >= deadline) {
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
        int poll_result;
        do {
            poll_result = poll(descriptors, 2, (int)(deadline - now));
        } while (poll_result < 0 && errno == EINTR);
        if (poll_result <= 0 ||
            (descriptors[0].revents & POLLNVAL) != 0 ||
            (descriptors[1].revents & POLLNVAL) != 0) {
            goto cleanup;
        }

        if (output_open && descriptors[0].revents != 0) {
            while (true) {
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
            goto cleanup;
        }
        const int64_t now = csec_monotonic_milliseconds();
        if (now < 0 || now >= deadline) {
            goto cleanup;
        }
        const struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
        (void)nanosleep(&pause, NULL);
    }
    if (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0 ||
        had_error_output || output_overflow) {
        goto cleanup;
    }

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
    return success;
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
        int poll_result;
        do {
            poll_result = poll(&writable, 1, (int)(deadline - now));
        } while (poll_result < 0 && errno == EINTR);
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
 * zero is the sole approval signal. Any other status, launch failure, or
 * timeout returns false so this module can use its retained Apple UI fallback.
 */
static bool
csec_try_custom_review(const char *command, const char *cwd, const char *tty)
{
    if (!csec_review_helper_is_protected()) {
        return false;
    }

    unsigned char frame[CSEC_REVIEW_FRAME_MAX] = {0};
    size_t frame_length = 0;
    if (!csec_build_review_frame(command, cwd, tty, frame, &frame_length)) {
        csec_wipe(frame, sizeof(frame));
        return false;
    }

    int input_pipe[2] = {-1, -1};
    pid_t child = -1;
    bool child_reaped = false;
    bool actions_initialized = false;
    bool attributes_initialized = false;
    bool approved = false;
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
    if (posix_spawn(&child, CSEC_SUDO_REVIEW_HELPER, &actions, &attributes,
            child_argv, child_environment) != 0) {
        child = -1;
        goto cleanup;
    }

    if (!csec_review_process_is_hardened(child) || kill(child, SIGCONT) != 0) {
        goto cleanup;
    }

    csec_close_descriptor(&input_pipe[0]);
    if (!csec_write_all_until(input_pipe[1], frame, frame_length, deadline)) {
        goto cleanup;
    }
    csec_close_descriptor(&input_pipe[1]);
    csec_wipe(frame, sizeof(frame));

    int child_status = 0;
    while (true) {
        const pid_t waited = waitpid(child, &child_status, WNOHANG);
        if (waited == child) {
            child_reaped = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            goto cleanup;
        }
        const int64_t now = csec_monotonic_milliseconds();
        if (now < 0 || now >= deadline) {
            goto cleanup;
        }
        const struct timespec pause = {.tv_sec = 0, .tv_nsec = 20000000};
        (void)nanosleep(&pause, NULL);
    }
    approved = WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0;

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
    if (child > 0 && !child_reaped) {
        csec_kill_and_reap(child);
    }
    return approved;
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
    const char **module_arguments)
{
    (void)flags;
    (void)argc;
    (void)module_arguments;

    const void *service_item = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, &service_item) != PAM_SUCCESS ||
        service_item == NULL || strcmp((const char *)service_item, "sudo") != 0) {
        return PAM_IGNORE;
    }

    const void *askpass = NULL;
    if (pam_get_data(pamh, "askpass-enabled", &askpass) == PAM_SUCCESS) {
        return PAM_IGNORE;
    }

    SessionAttributeBits session_attributes = 0;
    if (SessionGetInfo(callerSecuritySession, NULL, &session_attributes) !=
            errSessionSuccess ||
        (session_attributes & sessionHasGraphicAccess) == 0) {
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

    if (command_available && csec_try_custom_review(command, cwd, tty)) {
        csec_wipe(command, sizeof(command));
        csec_wipe(prompt, sizeof(prompt));
        return PAM_SUCCESS;
    }

    if (!command_available ||
        !csec_build_redacted_prompt_from_command(command, cwd, tty, prompt)) {
        csec_wipe(prompt, sizeof(prompt));
        csec_build_redactor_unavailable_prompt(cwd, tty, prompt);
    }
    csec_wipe(command, sizeof(command));

    AuthorizationRef authorization = NULL;
    OSStatus status = AuthorizationCreate(NULL, kAuthorizationEmptyEnvironment,
        kAuthorizationFlagDefaults, &authorization);
    if (status != errAuthorizationSuccess || authorization == NULL) {
        csec_wipe(prompt, sizeof(prompt));
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
            "/dev/ttys001", frame, &frame_length) &&
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
