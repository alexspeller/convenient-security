/* Exercise the exact shipping cleanup and review supervision with
 * deterministic kernel-wait doubles, plus the tty hangup watch against a real
 * pty. No PAM stack, privilege, agent, keychain, or real credential is
 * involved. */
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <util.h>

/* Kernel-wait doubles. `wait_mode` picks what waitpid reports; the supervision
 * modes are driven by the call counts below. */
enum wait_mode {
    WAIT_NEVER_REAPED,      /* a killed child that the kernel still cannot reap */
    WAIT_REAPED_SECOND,     /* reaped on the second wait */
    WAIT_ECHILD,
    WAIT_EINTR,
    WAIT_CLOCK_FAILS,       /* the monotonic clock fails */
    WAIT_EXITS_ON_CALL,     /* the helper exits on its own at `exit_on_call` */
    WAIT_REAPED_AFTER_KILL, /* running until killed, then reaped */
};
enum poll_mode {
    POLL_EINTR,             /* the bounded-poll EINTR fixture */
    POLL_HANGUP_ON_CALL,    /* the tty hangs up at `hangup_on_call` */
    POLL_REAL,              /* the real poll(2), for the pty checks */
};

static int wait_calls, kill_calls, poll_calls, sigpending_calls;
static enum wait_mode wait_mode;
static enum poll_mode poll_mode;
static int exit_on_call, exit_status, hangup_on_call;
static int pending_signal, pending_on_call;
static long elapsed_ms, sleep_budget_ms = 100;

static pid_t fixture_waitpid(pid_t pid, int *status, int options)
{
    assert(options == WNOHANG);
    wait_calls++;
    switch (wait_mode) {
    case WAIT_REAPED_SECOND:
        if (wait_calls == 2) { *status = 0; return pid; }
        return 0;
    case WAIT_ECHILD: errno = ECHILD; return -1;
    case WAIT_EINTR: errno = EINTR; return -1;
    case WAIT_EXITS_ON_CALL:
        if (wait_calls == exit_on_call) { *status = exit_status; return pid; }
        return 0;
    case WAIT_REAPED_AFTER_KILL:
        if (kill_calls > 0) { *status = SIGKILL; return pid; }
        return 0;
    case WAIT_NEVER_REAPED:
    case WAIT_CLOCK_FAILS:
    default:
        return 0;
    }
}
static int fixture_kill(pid_t pid, int sig)
{
    assert(pid == 12345 || pid == -12345);
    assert(sig == SIGKILL);
    kill_calls++;
    return 0;
}
static int fixture_clock(clockid_t clock, struct timespec *now)
{
    assert(clock == CLOCK_MONOTONIC);
    if (wait_mode == WAIT_CLOCK_FAILS) { errno = EINVAL; return -1; }
    now->tv_sec = elapsed_ms / 1000;
    now->tv_nsec = (elapsed_ms % 1000) * 1000000;
    return 0;
}
static int fixture_pause(const struct timespec *pause, struct timespec *remaining)
{
    (void)remaining;
    elapsed_ms += pause->tv_sec * 1000 + pause->tv_nsec / 1000000;
    assert(elapsed_ms <= sleep_budget_ms); /* The test fails instead of hanging. */
    return 0;
}
static int fixture_poll(struct pollfd *descriptors, nfds_t count, int timeout)
{
    assert(count == 1);
    poll_calls++;
    switch (poll_mode) {
    case POLL_EINTR:
        assert(timeout == 30 - elapsed_ms);
        elapsed_ms += 10;
        errno = EINTR;
        return -1;
    case POLL_HANGUP_ON_CALL:
        /* Only a hangup may be asked for: typed input must never wake it. */
        assert(descriptors[0].events == POLLHUP);
        assert(timeout == 20);
        elapsed_ms += timeout;
        assert(elapsed_ms <= sleep_budget_ms);
        if (poll_calls == hangup_on_call) {
            descriptors[0].revents = POLLHUP;
            return 1;
        }
        descriptors[0].revents = 0;
        return 0;
    case POLL_REAL:
    default:
        return poll(descriptors, count, timeout);
    }
}
static int fixture_sigpending(sigset_t *set)
{
    sigpending_calls++;
    sigemptyset(set);
    if (pending_signal != 0 && sigpending_calls >= pending_on_call) {
        sigaddset(set, pending_signal);
    }
    return 0;
}

/* The module's diagnostic trail, read through its test sink. Every line the
 * whole run writes is held to the value-free shape: fixed lowercase labels
 * and numbers only. */
static char trail[64][160];
static int trail_count;
static void csec_liveness_test_sink(const char *line)
{
    assert(strncmp(line, "sudo stage=", 11) == 0);
    for (const char *character = line; *character != '\0'; character++) {
        assert((*character >= 'a' && *character <= 'z') ||
            (*character >= '0' && *character <= '9') ||
            *character == ' ' || *character == '=' || *character == '-');
    }
    assert(strlen(line) < sizeof(trail[0]));
    strcpy(trail[trail_count % 64], line);
    trail_count++;
}
static bool trail_contains(const char *line)
{
    const int first = trail_count > 64 ? trail_count - 64 : 0;
    for (int index = first; index < trail_count; index++) {
        if (strcmp(trail[index % 64], line) == 0) {
            return true;
        }
    }
    return false;
}

#define CSEC_PAM_LIVENESS_TEST_SINK 1
#define waitpid fixture_waitpid
#define kill fixture_kill
#define clock_gettime fixture_clock
#define nanosleep fixture_pause
#define poll fixture_poll
#define sigpending fixture_sigpending
#define CSEC_PAM_REDACTOR_PROBE 1
#define CSEC_PAM_REVIEW_SUPERVISION_TEST 1
#define main unused_redactor_probe_main
#include "../sudo/pam_csec_sudo.c"
#undef main

static void reset(enum wait_mode waits, enum poll_mode polls)
{
    wait_calls = kill_calls = poll_calls = sigpending_calls = 0;
    exit_on_call = exit_status = hangup_on_call = 0;
    pending_signal = pending_on_call = 0;
    elapsed_ms = 0;
    sleep_budget_ms = 100;
    wait_mode = waits;
    poll_mode = polls;
}

/* A running helper with no terminal to watch, supervised to its end. */
static enum csec_review_result supervise_without_tty(void)
{
    return csec_supervise_review(12345, -1, 300000);
}

static void check_interrupt(int signal_number)
{
    reset(WAIT_REAPED_AFTER_KILL, POLL_EINTR);
    sleep_budget_ms = 400;
    pending_signal = signal_number;
    pending_on_call = 3;
    const enum csec_review_result result = supervise_without_tty();
    assert(result == CSEC_REVIEW_INTERRUPTED);
    assert(kill_calls == 2);        /* its process group, then the helper */
    assert(wait_calls >= 3);        /* reaped after the kill */
    int status = PAM_SUCCESS;
    struct csec_review_state state = {0};
    assert(csec_review_decides_module(result, &state, &status));
    /* No Apple fallback, and IGNORE leaves the guard's ABORT as the result. */
    assert(status == PAM_IGNORE);
    assert(state.interrupted && !state.expired);
}

static int refuse_conversation(int count, const struct pam_message **messages,
    struct pam_response **responses, void *data)
{
    (void)count; (void)messages; (void)responses; (void)data;
    assert(!"the value-free PAM transaction test must never prompt");
    return PAM_CONV_ERR;
}

/* Expiry and an interrupt (Ctrl-C, Ctrl-\ or a hangup) both stop the
 * authentication: the review returns IGNORE and latches, the guard aborts. */
static void check_stopped_transaction(enum csec_review_result stopped)
{
    /* Use the real macOS PAM data/cleanup APIs, with no authentication, no
     * user lookup, and a conversation that cannot prompt. The guard must not
     * permit recovery if the first factor never initialized its state. */
    const bool expiry = stopped == CSEC_REVIEW_EXPIRED;
    assert(expiry || stopped == CSEC_REVIEW_INTERRUPTED);
    reset(WAIT_NEVER_REAPED, POLL_EINTR); /* no fixture signal left pending */
    pam_handle_t *pamh = NULL;
    const struct pam_conv conversation = {refuse_conversation, NULL};
    assert(pam_start("other", "csec-synthetic-user", &conversation, &pamh) == PAM_SUCCESS);
    assert(csec_review_guard(pamh) == PAM_ABORT);
    struct csec_review_state *state = csec_prepare_review_state(pamh);
    assert(state != NULL && !state->expired && !state->interrupted);
    assert(csec_review_guard(pamh) == PAM_SUCCESS);
    int status = PAM_SUCCESS;
    assert(csec_review_decides_module(stopped, state, &status));
    assert(status == PAM_IGNORE); /* preserve the guard's fatal ABORT */
    assert(csec_review_guard(pamh) == PAM_ABORT);
    assert(csec_prepare_review_state(pamh) == state);
    assert(state->expired == expiry && state->interrupted == !expiry);
    assert(csec_review_guard(pamh) == PAM_ABORT); /* no retry can reopen it */
    assert(pam_end(pamh, PAM_ABORT) == PAM_SUCCESS);

    /* The latch belongs to one authentication, never to a later sudo. */
    assert(pam_start("other", "csec-synthetic-user", &conversation, &pamh) == PAM_SUCCESS);
    state = csec_prepare_review_state(pamh);
    assert(state != NULL && !state->expired && !state->interrupted);
    assert(csec_review_guard(pamh) == PAM_SUCCESS);
    assert(pam_end(pamh, PAM_SUCCESS) == PAM_SUCCESS);
}

static int reported_messages;
static const char *expected_report;
static int capture_conversation(int count, const struct pam_message **messages,
    struct pam_response **responses, void *data)
{
    assert(data == &reported_messages);
    assert(count == 1);
    assert(messages[0]->msg_style == PAM_ERROR_MSG);
    assert(strcmp(messages[0]->msg, expected_report) == 0);
    reported_messages++;
    *responses = calloc(1, sizeof(struct pam_response));
    return *responses == NULL ? PAM_BUF_ERR : PAM_SUCCESS;
}
static int failing_conversation(int count, const struct pam_message **messages,
    struct pam_response **responses, void *data)
{
    (void)count; (void)messages; (void)responses;
    reported_messages++;
    (void)data;
    return PAM_CONV_ERR;
}

/* Expiry and an interrupt tell the terminal why sudo stopped, through sudo's
 * conversation, as one error message and never a prompt; a failing
 * conversation is harmless. */
static void check_review_end_report(const char *message)
{
    pam_handle_t *pamh = NULL;
    const struct pam_conv conversation = {capture_conversation, &reported_messages};
    reported_messages = 0;
    expected_report = message;
    assert(pam_start("other", "csec-synthetic-user", &conversation, &pamh) == PAM_SUCCESS);
    csec_report_review_end(pamh, message);
    assert(reported_messages == 1);
    assert(pam_end(pamh, PAM_ABORT) == PAM_SUCCESS);

    const struct pam_conv failing = {failing_conversation, NULL};
    reported_messages = 0;
    assert(pam_start("other", "csec-synthetic-user", &failing, &pamh) == PAM_SUCCESS);
    csec_report_review_end(pamh, message);
    assert(reported_messages == 1);
    assert(pam_end(pamh, PAM_ABORT) == PAM_SUCCESS);
}

/* A Ctrl-C or Ctrl-\ still pending when the guard runs, which the review did
 * not latch (it came during Apple's Use Password dialog), ends sudo too: the
 * guard latches it, tells the terminal once, and aborts. Other signals are
 * sudo's own and leave recovery in place. */
static void check_guard_sees_pending_interrupt(int signal_number, bool interrupts)
{
    pam_handle_t *pamh = NULL;
    const struct pam_conv conversation = {capture_conversation, &reported_messages};
    reset(WAIT_NEVER_REAPED, POLL_EINTR);
    reported_messages = 0;
    expected_report = CSEC_REVIEW_INTERRUPTED_MESSAGE;
    assert(pam_start("other", "csec-synthetic-user", &conversation, &pamh) == PAM_SUCCESS);
    struct csec_review_state *state = csec_prepare_review_state(pamh);
    assert(state != NULL);
    pending_signal = signal_number;
    pending_on_call = 1;
    if (interrupts) {
        assert(csec_review_guard(pamh) == PAM_ABORT);
        assert(state->interrupted && !state->expired);
        assert(reported_messages == 1);
        assert(csec_review_guard(pamh) == PAM_ABORT);
        assert(reported_messages == 1); /* told once per authentication */
    } else {
        assert(csec_review_guard(pamh) == PAM_SUCCESS);
        assert(!state->interrupted && reported_messages == 0);
    }
    assert(pam_end(pamh, PAM_ABORT) == PAM_SUCCESS);
    reset(WAIT_NEVER_REAPED, POLL_EINTR);
}

int main(void)
{
    /* Bounded cleanup of a helper that will not die cleanly. */
    const enum wait_mode cleanup_modes[] = {
        WAIT_NEVER_REAPED, WAIT_REAPED_SECOND, WAIT_ECHILD, WAIT_EINTR,
        WAIT_CLOCK_FAILS,
    };
    for (size_t index = 0; index < sizeof(cleanup_modes) / sizeof(cleanup_modes[0]); index++) {
        reset(cleanup_modes[index], POLL_EINTR);
        const bool reaped = csec_kill_and_reap(12345);
        assert(reaped == (cleanup_modes[index] == WAIT_REAPED_SECOND ||
            cleanup_modes[index] == WAIT_ECHILD));
        assert(kill_calls == 2);
        assert(wait_calls >= 1 && wait_calls <= 11);
        assert(elapsed_ms <= CSEC_CLEANUP_TIMEOUT_MILLISECONDS);
    }
    reset(WAIT_NEVER_REAPED, POLL_EINTR);
    struct pollfd descriptor = {.fd = -1, .events = 0, .revents = 0};
    assert(csec_poll_until(&descriptor, 1, 30) == 0);
    assert(poll_calls == 3 && elapsed_ms == 30);
    puts("PAM bounded cleanup checks: pass");

    /* sudo blocks SIGINT and SIGQUIT during authentication, so a Ctrl-C or
     * Ctrl-\ is only pending: each kills and reaps the helper and stops the
     * authentication before pam_tid or a password prompt. */
    check_interrupt(SIGINT);
    check_interrupt(SIGQUIT);
    check_stopped_transaction(CSEC_REVIEW_INTERRUPTED);
    check_review_end_report(CSEC_REVIEW_INTERRUPTED_MESSAGE);
    check_guard_sees_pending_interrupt(SIGINT, true);
    check_guard_sees_pending_interrupt(SIGQUIT, true);
    check_guard_sees_pending_interrupt(SIGHUP, false);
    check_guard_sees_pending_interrupt(SIGTERM, false);
    puts("PAM interrupted authentication guard checks: pass");

    /* SIGHUP and SIGTERM are sudo's own to handle; they are not interrupts. */
    const int not_interrupts[] = {SIGHUP, SIGTERM};
    for (size_t index = 0; index < 2; index++) {
        reset(WAIT_EXITS_ON_CALL, POLL_EINTR);
        sleep_budget_ms = 400;
        pending_signal = not_interrupts[index];
        pending_on_call = 1;
        exit_on_call = 5;
        exit_status = 0;
        assert(supervise_without_tty() == CSEC_REVIEW_APPROVED);
        assert(kill_calls == 0);
    }

    /* The terminal closing kills and reaps the helper and stops the
     * authentication the same way. */
    reset(WAIT_REAPED_AFTER_KILL, POLL_HANGUP_ON_CALL);
    sleep_budget_ms = 400;
    hangup_on_call = 3;
    const enum csec_review_result hung_up = csec_supervise_review(12345, 7, 300000);
    assert(hung_up == CSEC_REVIEW_INTERRUPTED);
    assert(poll_calls == 3 && kill_calls == 2 && wait_calls >= 4);
    int hangup_status = PAM_SUCCESS;
    struct csec_review_state state = {0};
    assert(csec_review_decides_module(hung_up, &state, &hangup_status));
    /* Aborted, not failed: sudo would otherwise retry a closed terminal. */
    assert(hangup_status == PAM_IGNORE);
    assert(state.interrupted && !state.expired);
    state.interrupted = false;

    /* The helper's own exit: zero approves, anything else falls back, and
     * neither is killed. */
    reset(WAIT_EXITS_ON_CALL, POLL_EINTR);
    sleep_budget_ms = 400;
    exit_on_call = 4;
    exit_status = 0;
    const enum csec_review_result approved = supervise_without_tty();
    assert(approved == CSEC_REVIEW_APPROVED && kill_calls == 0);
    int approved_status = PAM_AUTH_ERR;
    assert(csec_review_decides_module(approved, &state, &approved_status));
    assert(approved_status == PAM_SUCCESS);

    /* 75 is the helper's own expiry, but minutes before the module's deadline
     * it can only be a helper fault, so it keeps Apple's recovery. */
    const int unsuccessful_statuses[] = {
        69 << 8, 64 << 8, 1 << 8, SIGKILL, CSEC_REVIEW_EXPIRED_EXIT_STATUS << 8,
    };
    for (size_t index = 0;
         index < sizeof(unsuccessful_statuses) / sizeof(unsuccessful_statuses[0]);
         index++) {
        reset(WAIT_EXITS_ON_CALL, POLL_EINTR);
        sleep_budget_ms = 400;
        exit_on_call = 2;
        exit_status = unsuccessful_statuses[index];
        const enum csec_review_result fallback = supervise_without_tty();
        assert(fallback == CSEC_REVIEW_UNSUCCESSFUL && kill_calls == 0);
        int fallback_status = PAM_SUCCESS;
        assert(!csec_review_decides_module(fallback, &state, &fallback_status));
        assert(fallback_status == PAM_SUCCESS); /* the fallback decides */
        assert(!state.expired);
    }

    /* The helper closing its unanswered review just before the deadline
     * ends sudo as the deadline does, with nothing left to kill. */
    reset(WAIT_EXITS_ON_CALL, POLL_EINTR);
    sleep_budget_ms = 400;
    exit_on_call = 2;
    exit_status = CSEC_REVIEW_EXPIRED_EXIT_STATUS << 8;
    const enum csec_review_result helper_expired =
        csec_supervise_review(12345, -1, CSEC_REVIEW_EXPIRY_CLAIM_MILLISECONDS);
    assert(helper_expired == CSEC_REVIEW_EXPIRED && kill_calls == 0);
    check_stopped_transaction(helper_expired);
    /* Just outside the claim window it is a fault, not an expiry. */
    reset(WAIT_EXITS_ON_CALL, POLL_EINTR);
    sleep_budget_ms = 400;
    exit_on_call = 1;
    exit_status = CSEC_REVIEW_EXPIRED_EXIT_STATUS << 8;
    assert(csec_supervise_review(12345, -1,
        CSEC_REVIEW_EXPIRY_CLAIM_MILLISECONDS + 1) == CSEC_REVIEW_UNSUCCESSFUL);
    check_review_end_report(CSEC_REVIEW_EXPIRED_MESSAGE);
    puts("PAM expiry report checks: pass");

    /* A real deadline kills/reaps the helper and aborts the transaction,
     * whether it came from an agent without a tty or an attended terminal. */
    reset(WAIT_REAPED_AFTER_KILL, POLL_EINTR);
    sleep_budget_ms = 400;
    const enum csec_review_result expired = csec_supervise_review(12345, -1, 100);
    assert(expired == CSEC_REVIEW_EXPIRED);
    assert(kill_calls == 2);
    check_stopped_transaction(expired);
    reset(WAIT_REAPED_AFTER_KILL, POLL_HANGUP_ON_CALL);
    sleep_budget_ms = 400;
    assert(csec_supervise_review(12345, 7, 100) == CSEC_REVIEW_EXPIRED);
    assert(kill_calls == 2);

    /* A broken clock or wait is a helper failure, not a human deadline, and
     * retains recovery. A killed child that cannot be reaped stays bounded. */
    const enum wait_mode failure_modes[] = {WAIT_CLOCK_FAILS, WAIT_ECHILD};
    for (size_t index = 0; index < 2; index++) {
        reset(failure_modes[index], POLL_EINTR);
        assert(supervise_without_tty() == CSEC_REVIEW_UNSUCCESSFUL);
    }
    reset(WAIT_NEVER_REAPED, POLL_EINTR);
    sleep_budget_ms = 400;
    assert(csec_supervise_review(12345, -1, 100) == CSEC_REVIEW_EXPIRED);
    assert(elapsed_ms <= 100 + CSEC_CLEANUP_TIMEOUT_MILLISECONDS);
    puts("PAM expired authentication guard checks: pass");
    puts("PAM review interrupt and hangup supervision checks: pass");

    /* The hangup watch against a real pty: typed input is not a hangup, the
     * master closing is, and only a terminal is ever watched. */
    reset(WAIT_NEVER_REAPED, POLL_REAL);
    signal(SIGHUP, SIG_IGN);
    int master = -1, slave = -1;
    char name[128];
    assert(openpty(&master, &slave, name, NULL, NULL) == 0);
    int watch = csec_open_tty_watch(name);
    assert(watch >= 0);
    assert(!csec_tty_hung_up(watch, 0));
    assert(write(master, "typed ahead\n", 12) == 12);
    assert(!csec_tty_hung_up(watch, 50));
    close(master);
    assert(csec_tty_hung_up(watch, 1000));
    close(watch);
    close(slave);
    assert(csec_open_tty_watch("no tty") == -1);
    assert(csec_open_tty_watch("/dev/null") == -1);
    assert(csec_open_tty_watch(NULL) == -1);
    puts("PAM terminal hangup watch checks: pass");

    /* The trail says how the helper ended, which the review result alone
     * cannot: Use Password and a crash both fall back. */
    reset(WAIT_EXITS_ON_CALL, POLL_EINTR);
    sleep_budget_ms = 400;
    exit_on_call = 2;
    exit_status = 69 << 8;
    trail_count = 0;
    assert(supervise_without_tty() == CSEC_REVIEW_UNSUCCESSFUL);
    assert(trail_count == 1 &&
        trail_contains("sudo stage=review event=helper-exit status=69"));
    reset(WAIT_EXITS_ON_CALL, POLL_EINTR);
    sleep_budget_ms = 400;
    exit_on_call = 2;
    exit_status = SIGKILL;
    trail_count = 0;
    assert(supervise_without_tty() == CSEC_REVIEW_UNSUCCESSFUL);
    assert(trail_count == 1 &&
        trail_contains("sudo stage=review event=helper-signal signal=9"));
    reset(WAIT_ECHILD, POLL_EINTR);
    trail_count = 0;
    assert(supervise_without_tty() == CSEC_REVIEW_UNSUCCESSFUL);
    assert(trail_contains("sudo stage=review event=unsuccessful reason=wait-failed"));
    /* A refused redaction names its cause before anything is spawned. */
    char *too_many[CSEC_ARGUMENT_MAX + 2];
    for (size_t index = 0; index < CSEC_ARGUMENT_MAX + 1; index++) {
        too_many[index] = (char *)"x";
    }
    too_many[CSEC_ARGUMENT_MAX + 1] = NULL;
    struct csec_redacted_arguments refused;
    trail_count = 0;
    assert(!csec_redact_arguments_with_active_catalog(CSEC_ARGUMENT_MAX + 2,
        too_many, &refused));
    assert(trail_count == 1 &&
        trail_contains("sudo stage=redactor event=unavailable reason=argument-count"));
    puts("PAM diagnostic trail checks: pass");
    return 0;
}
