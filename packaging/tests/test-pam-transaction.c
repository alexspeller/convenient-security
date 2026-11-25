/* Exercise both shipping PAM entry points against a real, value-free macOS
 * PAM handle. No pam_authenticate, sudo, credential, GUI or host write occurs. */
#include <assert.h>
#include "../sudo/pam_csec_sudo.c"

static int interrupt_reports;
static int count_interrupt_report(int count, const struct pam_message **messages,
    struct pam_response **responses, void *data)
{
    assert(data == &interrupt_reports);
    assert(count == 1 && messages[0]->msg_style == PAM_ERROR_MSG);
    assert(strcmp(messages[0]->msg, CSEC_REVIEW_INTERRUPTED_MESSAGE) == 0);
    interrupt_reports++;
    *responses = calloc(1, sizeof(struct pam_response));
    return *responses == NULL ? PAM_BUF_ERR : PAM_SUCCESS;
}

static int refuse_conversation(int count, const struct pam_message **messages,
    struct pam_response **responses, void *data)
{
    (void)count; (void)messages; (void)responses; (void)data;
    assert(!"transaction tests must never ask for authentication");
    return PAM_CONV_ERR;
}

int main(void)
{
    pam_handle_t *pamh = NULL;
    const struct pam_conv conversation = {refuse_conversation, NULL};
    const char *guard[] = {"review_guard"};
    assert(pam_start("other", "csec-synthetic-user", &conversation, &pamh) == PAM_SUCCESS);
    assert(pam_set_item(pamh, PAM_SERVICE, "sudo") == PAM_SUCCESS);

    /* A guard alone must not silently let an uninitialized transaction on. */
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_ABORT);
    /* askpass is an existing recovery path which must initialize the guard,
     * while ensuring this test never launches a helper or reads the host. */
    assert(pam_set_data(pamh, "askpass-enabled", NULL, NULL) == PAM_SUCCESS);
    assert(pam_sm_authenticate(pamh, 0, 0, NULL) == PAM_IGNORE);
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_SUCCESS);
    struct csec_review_state *state = csec_prepare_review_state(pamh);
    assert(state != NULL);
    int status = PAM_SUCCESS;
    assert(!csec_review_decides_module(CSEC_REVIEW_UNSUCCESSFUL, state, &status));
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_SUCCESS);

    assert(csec_review_decides_module(CSEC_REVIEW_EXPIRED, state, &status));
    assert(status == PAM_IGNORE);
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_ABORT);
    assert(pam_sm_authenticate(pamh, 0, 0, NULL) == PAM_IGNORE);
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_ABORT);
    assert(pam_sm_setcred(pamh, 0, 1, guard) == PAM_SUCCESS);
    assert(pam_end(pamh, PAM_ABORT) == PAM_SUCCESS);

    /* An interrupted review stops the stack the same way, and re-entry never
     * reopens it. */
    assert(pam_start("other", "csec-synthetic-user", &conversation, &pamh) == PAM_SUCCESS);
    assert(pam_set_item(pamh, PAM_SERVICE, "sudo") == PAM_SUCCESS);
    assert(pam_set_data(pamh, "askpass-enabled", NULL, NULL) == PAM_SUCCESS);
    assert(pam_sm_authenticate(pamh, 0, 0, NULL) == PAM_IGNORE);
    state = csec_prepare_review_state(pamh);
    assert(state != NULL);
    assert(csec_review_decides_module(CSEC_REVIEW_INTERRUPTED, state, &status));
    assert(status == PAM_IGNORE);
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_ABORT);
    assert(pam_sm_authenticate(pamh, 0, 0, NULL) == PAM_IGNORE);
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_ABORT);
    assert(pam_end(pamh, PAM_ABORT) == PAM_SUCCESS);

    /* A real Ctrl-C held pending by a blocked SIGINT, as sudo blocks it while
     * it authenticates, ends the transaction at the guard with one message.
     * A shell starts a background job with SIGINT ignored, and an ignored
     * signal is discarded rather than left pending, so the default action is
     * set (while blocked) for the raise. Ignoring SIGINT before unblocking
     * discards it again, so nothing is delivered, and the inherited
     * disposition is then put back. */
    sigset_t interrupt_mask, previous_mask;
    struct sigaction default_action = {.sa_handler = SIG_DFL}, ignore_action = {.sa_handler = SIG_IGN},
        previous_action;
    assert(sigemptyset(&interrupt_mask) == 0 && sigaddset(&interrupt_mask, SIGINT) == 0);
    assert(sigemptyset(&default_action.sa_mask) == 0 && sigemptyset(&ignore_action.sa_mask) == 0);
    assert(sigprocmask(SIG_BLOCK, &interrupt_mask, &previous_mask) == 0);
    assert(sigaction(SIGINT, &default_action, &previous_action) == 0);
    const struct pam_conv reporting = {count_interrupt_report, &interrupt_reports};
    assert(pam_start("other", "csec-synthetic-user", &reporting, &pamh) == PAM_SUCCESS);
    assert(pam_set_item(pamh, PAM_SERVICE, "sudo") == PAM_SUCCESS);
    assert(pam_set_data(pamh, "askpass-enabled", NULL, NULL) == PAM_SUCCESS);
    assert(pam_sm_authenticate(pamh, 0, 0, NULL) == PAM_IGNORE);
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_SUCCESS);
    assert(raise(SIGINT) == 0);
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_ABORT);
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_ABORT);
    assert(interrupt_reports == 1);
    assert(pam_end(pamh, PAM_ABORT) == PAM_SUCCESS);
    assert(sigaction(SIGINT, &ignore_action, NULL) == 0);
    assert(sigprocmask(SIG_SETMASK, &previous_mask, NULL) == 0);
    assert(sigaction(SIGINT, &previous_action, NULL) == 0);

    /* The module remains specific to sudo and expiry is not global. */
    assert(pam_start("other", "csec-synthetic-user", &conversation, &pamh) == PAM_SUCCESS);
    assert(pam_sm_authenticate(pamh, 0, 0, NULL) == PAM_IGNORE);
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_IGNORE);
    assert(pam_set_item(pamh, PAM_SERVICE, "sudo") == PAM_SUCCESS);
    assert(pam_set_data(pamh, "askpass-enabled", NULL, NULL) == PAM_SUCCESS);
    assert(pam_sm_authenticate(pamh, 0, 0, NULL) == PAM_IGNORE);
    assert(pam_sm_authenticate(pamh, 0, 1, guard) == PAM_SUCCESS);
    assert(pam_end(pamh, PAM_SUCCESS) == PAM_SUCCESS);
    puts("PAM review and guard entry-point checks: pass");
    return 0;
}
