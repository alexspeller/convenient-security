<!-- Full text of an AGENTS.md topic, moved unchanged; paths and links in it are relative to the repository root. AGENTS.md keeps a summary and says when to read this file; where they differ, this file wins. -->

## Approval dialogs: one change, three surfaces

**The default: a change to one approval dialog is a change to all of them.**
A fix, guard, wording change or behaviour found on one surface — say the
typing guard on the SSH panel — is made on the secret-access, SSH and sudo
surfaces, every layout variant of each, every path that presents them, and the
iPhone mirror where it applies, in the same change, unless there is a stated
reason one cannot have it. "The bug was reported on the SSH panel" is not such
a reason. The rest of this section is how to do that without missing one.

csec draws three human approval dialogs, and they do not share one code path:

| Surface | Code | Runs in | Installed by |
| --- | --- | --- | --- |
| Secret-access review | `TrustedAccessReviewSession` in `agent/Sources/ConvenientSecurity/TrustedAccessReviewSession.swift` | `csecd` | the ConvenientSecurity.app bundle |
| SSH signing review | the same class, its `review.ssh != nil` branches — the SSH layout builds its own controls and sections | `csecd` | the ConvenientSecurity.app bundle |
| sudo review | `TrustedSudoAuthorizationReviewSession` in `agent/Sources/ConvenientSecurity/SudoAuthorizationReview.swift` | `csec-sudo-review`, a separate helper the PAM module (`packaging/sudo/pam_csec_sudo.c`) spawns | the guarded `install-sudo-review.sh` into `/usr/local`, from the payload the `.pkg` carries (built by `build-sudo-pam.sh` and `build-sudo-review.sh`), run through `sudo` by `csec setup` or the sudo stage of `packaging/bin/build-and-install.sh` — installing the `.pkg` alone puts only the payload in place, **not** the active helper |

The restore panel a restarted csecd raises to reopen what restored grants need
(`review.restore`, alone or as a section of a release panel) is a variant of
the secret-access surface, for secret and SSH grants alike. It never reaches
the sudo surface: sudo has no csec grants, so there is nothing to restore.

When Claude Code auto mode did not approve a request on its own (delegated
approvals), the secret-access and SSH layouts show why below their footnote
(`review.delegationNote`, "Auto mode didn't approve this: …") and, when
approving would pair the references with the project, the pairing line
(`review.pairingOffer`), which shows only while the default Claude Code scope
and the process lifetime are selected. For a decline pairing cannot end
(`DelegationDecline.pairingCondition`) the line ends "once …" instead of
"until you revoke them", on every surface, since csecd writes the text. csecd never offers one on an SSH
panel: an SSH signing auto mode approved signs with no pairing (csec-0.11). The phone
mirror carries both (the signed review's `delegation` block) and draws the line
by the same rule, `RemoteApprovalReview.pairingLineApplies`; an approval pairs
only when its surface showed the line (`AccessPolicyApproval.pairingLineShown`).
Neither appears on a restore-only panel or in the automation layout. The sudo
review shows both too, below its own footnote, for a sudo Claude Code ran
(`SudoAuthorizationReviewRequest.delegationNote` and `.pairingLine`, from
csecd's answer to the helper's `sudo_delegation`). A sudo panel selects no
scope or lifetime, so its line always shows; the phone carries it as an
unscoped line (`Delegation.Pairing.unscoped`), which `pairingLineApplies`
shows for the one approval there is. A Mac approval of a sudo panel that
showed the line is reported by the helper (`sudo_pairing`), a phone approval
by the phone's signed acknowledgement, and csecd pairs only for the helper it
made the offer to.

All three surfaces reach the paired iPhone. The secret-access and SSH reviews
(and the restore panel) are mirrored inside csecd by `MirroredPolicyReview`;
the sudo review is mirrored by its helper, which sends csecd one
`sudo_remote_review` request (csecd admits only the installed helper's code
identity for it) and races that answer against its own panel. A change to how
a phone decision ends a review — the panel closing when the phone wins, the
context invalidated, withdrawal when the local panel wins — lands on both
paths. Both reach the phone through csecd's one `RemoteApprovalRequester`, so
when the phone is alerted (`RemoteApprovalAlertTiming`: 30 s after the prompt
opened, at once while the Mac is locked or asleep or cannot take a touch) and
what the alert says (`RemoteApprovalNotificationText`, written by the phone's
notification service extension from the verified request) are the same for every
surface. So is the deadline line: a review the Mac closes unanswered carries that
moment to the phone (`closesAtMilliseconds`, from `HumanWait.current` in
`MirroredPolicyReview` and from the helper's `SudoReviewDeadline.closing` in
`SudoRemoteReviewRequest`), and the card draws the panels' own line from
`ReviewDeadlineText`, which `bin/ci` holds the card and `ReviewDeadline` to.

Any change to how an approval dialog looks or behaves — controls, keyboard
focus and timing guards, wording, what is displayed, deny/cancel/close
semantics, screen-lock handling, terminal-tab naming, phone mirroring — must
land on all three surfaces in the same change. If a surface is deliberately
left out, the commit message says which one and why. Where a behaviour can
live in shared code (`PromptInteractionGrace`, `PromptKeyboardSink`,
`ReviewFocusRecovery`, `ReviewAuthenticationContext`, `DeliveryReviewCopy`,
`ReviewSecretTree`, `ReviewTestBanner`), put it there, so the surfaces cannot drift apart; a
`bin/ci` guard then holds both panel files to using it. For every such change:

1. **Code.** Both classes, and inside `TrustedAccessReviewSession` every
   variant: `configureWindow` branches on `review.ssh`, `review.automation`,
   `review.settingsChange` and `review.restore` (`isRestoreOnly`) for the header, body, scope card,
   footnote and refusing-button title, so a change made in one branch is not
   made in the others. Keyboard focus is not per variant: each panel installs
   one `PromptKeyboardSink` as its content view before any branch, and focus
   rests there once the panel is live, so Space, Return and letters press
   nothing (Escape refuses, Tab reaches the controls). The typing guard's
   length is decided once, in `PromptInteractionGrace` — at least half a
   second, then until the keyboard counter reads `requiredKeyboardIdle`, the
   quiet period plus the counter's half-second step, which steady typing
   never reaches — and no panel passes its own delay, threshold or keyboard
   clock (`bin/ci` guards all three). Every `NSButton` /
   `NSPopUpButton` is appended to `interactiveControls` where it is built
   (`bin/ci` counts constructions against registrations in both files, and
   `cs-selftest --panel-controls-only` checks every layout's real window). A
   prompt is presented more than once: the unlock re-present path
   (`handleUnlockSignal`) needs the same guards as the first presentation,
   and re-checks that the requester is still running before it re-presents.
   So does the focus renewal (`windowDidBecomeKey`, `ReviewFocusRecovery`):
   Touch ID reaches only the key panel, and another prompt's later evaluation
   strands an armed one silently, so a panel renews Touch ID on a fresh
   context, one run-loop turn after it becomes key, whenever it was armed
   while the panel could not take a touch — on first presentation with no
   further guard, and after losing key (when it also says to click it) behind
   a fresh grace started at once whose focus step never activates the process
   (`refocusIfStillKey`). The replaced evaluation's callback is dropped by
   generation. A system cancel (`LAError.systemCancel`, another app forward
   or another prompt taking the sensor) with the screen unlocked and Touch ID
   still there is the same kind of event, never the human's Deny or Use
   Password: `ReviewTouchIDUnavailable.afterFailure` names it, and the panel
   stays up and renews through `ReviewFocusRecovery.onSystemCancel` (at once
   while key, once per key change; otherwise when it next becomes key).
   A prompt must also never outlive its requester: the csec and SSH agent
   sockets cancel a request whose peer has closed, and on the sudo surface
   the PAM module reads a pending Ctrl-C/Ctrl-\ and watches the tty for a
   hangup while the helper watches its parent sudo. A denial carries an
   `AccessPolicyDenialReason`; only `.human` (Deny, closing the window, a
   phone Deny) refuses the identical requests already waiting and ends an
   SSH connection's signing.
   Secret-access and SSH requests also retain their arrival-time
   `RequestAnchor`: loss of the original kernel parent or default scope
   withdraws a queued or shown request, even when session lineage still
   links the orphan. Setup variants use the same watch; restore waiter
   selection and unlock/focus rechecks use the anchored caller.
   A shared restore whose displayed caller is lost closes and re-presents
   for a surviving waiter, keeping the restore unused until a human decides.
   Sudo's own parent is deliberately excluded: PAM already bounds its queued
   and displayed review to 300 s, and early failure would fall through to `pam_tid`.
   The one thing the three surfaces *do* share is the `LAContext` factory,
   `ReviewAuthenticationContext.make(for:)` — every panel's first context and
   every unlock rebuild comes from it, and its invariant is that Touch ID
   reuse stays zero on all three: a nonzero
   `touchIDAuthenticationAllowableReuseDuration` would let a panel raised soon
   after a lock-screen unlock succeed with no touch and nothing read. A panel
   must not build its own `LAContext` (`bin/ci` guards both files).
2. **Tests.** `cs-selftest` coverage for each surface the change touches, not
   just the shared helper. `ApprovalPanelInspection` builds every surface's
   real window, parked offscreen with no Touch ID, for exactly this.
3. **On-device checks.** `cs-review-preview` (access and SSH scenarios;
   `CSEC_PREVIEW_GRACE_PROBE=1` for the typing guard, whose `firstResponder=`
   field must name `PromptKeyboardSink` in both samples, never a button;
   `CSEC_PREVIEW_TYPING_PROBE=1` while a human keeps typing as the panel
   appears, which must print `typing probe: PASS`; see
   `docs/development.md`);
   `CSEC_PREVIEW_SCOPE` / `CSEC_PREVIEW_DURATION` to capture a changed
   selection; `requester-gone` / `ssh-requester-gone` to watch a panel close
   when its requester exits; `CSEC_PREVIEW_UNLOCK_RECHECK=1` to hold a panel
   across a real lock and unlock and check it asks for Touch ID again,
   whether macOS cancelled it at the lock or only paused it (both branches
   are in `docs/development.md`); `CSEC_PREVIEW_FOCUS_PROBE=1` to take the
   focus away and give it back and check the re-arm, and
   `CSEC_PREVIEW_HOLD=1` to hold a panel for a real touch after another
   surface's probe strands it; `restore` for the restore-only panel and
   `restore-mixed` for a release panel with a restore section;
   `CSEC_PREVIEW_DELEGATION=<code>` for the delegation note and
   `CSEC_PREVIEW_PAIRING=1` for the pairing line, which the scope and
   lifetime knobs show hiding, in a PNG or as the grace probe's
   `pairingLine=hidden`; `CSEC_PREVIEW_DEADLINE=<seconds>` for the deadline
   line, which with `CSEC_PREVIEW_HOLD=1` runs the real withdrawal and closes
   the panel at the deadline),
   `csec-sudo-review --preview` / `--grace-probe` / `--typing-probe` /
   `--focus-probe` / `--screen-lock-probe` / `--unlock-probe` /
   `--deadline-probe` /
   `--no-touch-id-probe` (`--preview basic|long-argv|multi-line`, with
   `CSEC_PREVIEW_NO_TOUCH_ID=1` for the panel held up for the phone;
   `CSEC_PREVIEW_NO_TOUCH_ID` / `CSEC_PREVIEW_PHONE=1` and
   `CSEC_PREVIEW_TOUCH_ID_PROBE=1` / `CSEC_PREVIEW_TOUCH_ID_LOST_PROBE=1`
   are `cs-review-preview`'s equivalents),
   and `packaging/bin/sample-sudo-review-activation.sh`,
   which spawns the built helper the way the PAM module does and samples its
   activation timeline — the in-process probe cannot see what a fresh process
   does before its window exists. A change to how an SSH review waits or ends
   also runs `cs-ssh-e2e` with `CSEC_SSH_E2E_SCENARIO=concurrent` (three real
   `ssh`, one review) and `interrupted` (the review closes when its `ssh` is
   interrupted).
4. **`bin/ci` source-shape guards.** A guard on one review file gets its twin
   on the other, and the sudo helper's entry point is held to the same
   activation rule as the two panel classes.
5. **Docs that enumerate the surfaces.** `README.md`, `DESIGN.md`,
   `docs/development.md`, `packaging/README.md`.
6. **Deployment.** Reinstalling the `.pkg` alone does not touch the active
   sudo helper (it replaces only the payload `csec setup` installs from, and
   `csec status` then warns that the helper is not the package's build). `packaging/bin/build-and-install.sh`, which every change ends with
   (see "Finishing work"), rebuilds and reinstalls the sudo module and helper
   and gates on `csec doctor`, which fails on a stale helper; say so in the
   handoff. A helper left stale silently keeps the old behaviour while the
   source and the other two dialogs move on.

Changes to Claude Code auto-mode approvals (`enable`, `trust_build`,
`acknowledge_hooks`, and the rules-changed panel csecd raises itself when a
request declines on changed classifier rules or a newly added hook,
`cs-review-preview rules-changed` and `hooks-changed`) are the settings layout of the secret-access surface
(`review.settingsChange`, through `SettingsChangeConsent`), with no scope,
lifetime, delegation note or pairing line, so a change to the secret-access
surface lands on it too (`cs-review-preview settings`). All are Mac-only and
never mirrored except the rules- and hooks-changed panel, which reaches the
paired phone as a `settings` review (av-rcqg; the delegation service's
consent is over the mirrored reviewer, and only that change carries
`phoneOperationDigest`, which `bin/ci` guards, along with who calls
`changedRulesReview`). It reaches the phone only
when the panel lists every source whole (`changedRulesReview`'s `complete`,
which starts from each source's `ClaudeHookSource.shownWhole`, set only by
the settings gate when it cut nothing short and no command line leaves out a
handler setting, which `bin/ci` guards, and `SettingsChangeReviewDetails`
drops the digest from a line cut short) and
the phone's signed status lists `settings` (`remoteSettingsReadiness`): a change to its wording or what it lists lands on the
phone card too (`SettingsSummary` in `ios/ConvenientSecurityApproval/ApprovalCardView.swift`),
and its footnote names no one surface's biometric.
So are the other setup steps that take a touch (backups, a restore, phone
pairing, machine identities, removing an SSH key or an automation job,
deleting stored files, host fixes, the uninstall cleanup): they show the same
settings layout through
`settingsConsent` (csec-0.60), so `cs-review-preview settings` and the host
fixes panel in `--panel-controls-only` / `--prompt-grace-only` cover them. The
one bare OS Touch ID sheet left, `BiometricConsent` for a provider with no
panel (headless and injected consent), is drawn by macOS, not csec, and is
outside this rule. So is the `csec edit` store editor
(`NativeStoreEditor`): it is a text editor, not an approval, it opens only
after the secret-access review and its Touch ID have approved the edit, and
the human types into it on purpose.
