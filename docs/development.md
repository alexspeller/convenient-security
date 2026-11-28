# Development and verification

Install the pinned npm development toolchain, then run the complete synthetic
suite from the repository root:

```sh
mise exec -- npm ci --ignore-scripts
bin/ci
```

With Lefthook available, install the repository's commit guard once per
checkout:

```sh
mise exec -- lefthook install
```

It builds every Swift target, runs the framework-free core checks, exercises
mutual identity and protocol behavior over real Unix sockets, runs the Ruby and
Node.js unit suites, and performs Ruby → `csec bridge` → Swift and Node.js →
`csec bridge` → Swift fake-agent cross-stack round trips. It runs the real
gcloud CLI and google-auth, offline and sandboxed, on a credential file the
debug `csec identity setup google` wrote against the fake agent. It also runs
the installed fish/zsh/bash functions and gcloud wrapper: independent review
scopes, denial with a token already held, repeated credential loads, storage
commands, backend-neutral references, and no token database or file log
(`bin/test-google-token-cache.py`, with Python and gcloud pinned in `.tool-versions`).
`bin/ci` runs this harness explicitly under mise: the SDK's bundled libraries
cannot import under the macOS Python 3.9 that a runner's saved PATH may select.
To rerun it after the debug build, use
`mise exec -- python3 bin/test-google-token-cache.py "$(mise where gcloud)"`.
Failed library-consumer checks print bounded child stdout/stderr, its exit code
and report counts, including when an import failed before the report was written.
`cs-selftest --machine-identity-only` covers Google STS/impersonation wire
validation, token expiry/reuse, target removal and catalog compatibility. It also builds both npm
module formats and TypeScript declarations, inspects the npm tarball,
syntax-checks release scripts/plists, and proves the synthetic inherited-fd key
handoff used by Fastlane. It generates the iPhone approval app's Xcode project
with the XcodeGen pinned in `.tool-versions` (failing if generation does not
reproduce the tracked `Info.plist`) and builds it, unsigned and with warnings as
errors, for the iOS Simulator and for a device; that needs full Xcode, an iOS
Simulator runtime, and `mise`. It fails if the Debug device build contains any
string of the Simulator test mode (its launch arguments, counters, fixtures),
which compiles only under `DEBUG && targetEnvironment(simulator)`. It then runs
the app's XCUITests (`ios/ConvenientSecurityApprovalUITests`, listed in
[`ios/README.md`](../ios/README.md#ui-tests)) on a throwaway Simulator: the
smallest Face ID iPhone the newest iOS runtime offers, cloned for the run,
deleted after confirmed Shutdown. A shutdown clone left by a killed run is
reclaimed by the next admitted run; live and legacy devices are preserved.
It is cloned from a base device that has booted once and never had an app
installed (`bin/ci-ios-simulator.py`, tested by `bin/test-ci-ios-simulator.py`),
because a new device's first boot runs data migration, and while the Mac is
busy that takes minutes: at a load average near 900 locationd's migrator alone
took 449 s, where the clone booted in 11 s. The base, named
`csec-ci-uitests-base <runtime build> <device type>`, is made once per runtime
under a project lock that overlapping runs share, and stays in the default
device set. Shutdown bases for other runtimes are retained too. A contaminated
or live base is preserved and skipped.

On a Mac where coding-agent sessions share the simulators, local CI runs
every simulator lifetime through a shared host/user admission gate:
`CSEC_CI_SIMULATOR_RUN`, or else the running user's `git config
csec.simulatorRun` (`~` expands to their home), names its executable. The
gate takes `--helper SELECTOR --boot-log LOG -- COMMAND`, bounds selection and
boot by `SIMULATOR_RUN_BOOT_S` and admission by `SIMULATOR_RUN_WAIT_S`, and
hands `COMMAND` its device as `SIMULATOR_RUN_UDID` and `SIMULATOR_RUN_SET`
(`default` or an absolute device-set path). Its nonbooting selector runs after admission. Cold-base bootstrap and the
clone's complete `bin/ci-ios-ui-tests` build/test command have separate
exact-device leases; both retain admission through command reap and confirmed
Shutdown. Lock order is simulator lifetime → project base lock → any
DerivedData/native compiler gate; never request simulator admission while
holding the project lock. The generic Simulator/device builds do not boot a
device and need no simulator lease. Missing local admission fails before
selection, so a gate that went missing or was never configured is never
bypassed silently; on a Mac where nothing else boots simulators,
`git config --global csec.simulatorRun direct` (or
`CSEC_CI_SIMULATOR_RUN=direct`) asks for the built-in bounded lifetime adapter
instead. `CSEC_CI_SIMULATOR_WAIT_S` bounds how long all of a run's leases
together wait for admission (unset, each lease waits the shared helper's own
bound, a day). A run never admitted within it starts no simulator and exits 76;
`bin/ci` then runs its remaining checks and fails at the end, saying the
iPhone UI tests did not run. Disposable GitHub-hosted VMs with no gate configured use that adapter without asking
(`GITHUB_ACTIONS=true`, `RUNNER_ENVIRONMENT=github-hosted`).

Cancellation leaves shutdown to the lifetime owner. The outer runner deletes
only its exact Shutdown clone, never shuts down a device independently, and
preserves a device after an uncertain gate exit for the next admitted recovery.
It never deletes legacy numeric-PID clones, legacy pending bases, live devices
or another run's warmed base. Diagnose admission with the shared helper's
`--status`; never remove its host lock or stop another device to free capacity.
`bin/test-ci-ios-simulator.py` covers concurrent checkouts, lock order, cold/warm
stages, exit propagation, cancellation, uncertain cleanup and legacy preservation
with stand-ins. When the host configures a gate, its actual supervisor is also exercised
against fake devices, including orchestrator SIGKILL, isolated from the host's
own queue by `SIMULATOR_RUN_LOCK`, `SIMULATOR_RUN_STATE_DIR` and the gate's other
`SIMULATOR_RUN_*` bounds. `--set /absolute/path`
lets an owned real check isolate its device set without changing the normal
warm default-set base.
The tests simulate Face ID from inside the Simulator, so nothing on the host
has to answer them; each test is stopped after ten minutes, the run after
ninety, the clone's boot after five, the base's first boot after twenty.
A newly booted Simulator can lose the first Face ID sheet it raises, so one
setup test runs first as a warm-up whose result does not count, again until
one passes, at most three times, since a warm-up can fail before it raises a
sheet; the app is then removed, and the suite, which runs that test again,
still starts with notification permission undecided. A
boot that runs out of time prints where it was waiting (`Waiting on Data
Migration` and the plugin, say) and the load average. The run's time follows
the Mac's load: on 17 Oct, at load averages near 800 to 900, 31 tests took
1159 s and 33 took 1122 s. The tests where iCloud does not answer wait out
the app's own CloudKit bounds, a minute and more each. Add the Simulator clone and boot (about
20 s) and one first boot when the base is made; on
failure it prints the failed assertions and, for an element a test could not
find, the screen's accessibility tree.
`cs-selftest --remote-approval-only` and `--remote-unlock-only` run just
the iPhone remote-approval and phone-held unlock checks. Test values are unique
synthetic fixtures; the suite must never
enumerate or print the developer's real environment.

The output-guard portion covers binary and split writes, longest-prefix
selection, stdout/stderr, terminal escape sequences on the PTY stream (a
query forwarded whole, a value next to or inside a sequence still redacted),
canonical encodings, short-value policy, explicit
byte-exact bypass, PTY allocation/size, child exit and signal status, external
signal forwarding, and stop/continue. Assertions verify that a matched
synthetic value never reaches the downstream capture. The pre-AI suite also
checks exact hook-command quoting, active-registry cross-launch matching,
fail-closed scanner startup/interruption, and a synthetic Ruby process-title
fixture: raw `pgrep -fl` must expose the fake environment marker, while
`csec ai` must return only an opaque label.
Synthetic daemon-restart checks hold a command open until the harness observes
the withholding notice on stderr, proving both `ai` and its `tool-exec` alias
explain withholding before command exit. They also check one notice across
stdout/stderr, suppressed later output, the original nonzero exit status and
final byte count, and no waiting notice when a command holding delivered values
is terminated. Split-secret withholding and scanner-protocol failures retain
their existing coverage.

The native-store portion uses synthetic in-memory Keychain/file backends to
cover strict JSON parsing and canonicalization, mixed `op://` + `csec://`
resolution, caller-bound edit sessions, concurrent-edit rejection, AES-GCM
round trips, ciphertext mutation, valid-version replay, and restart behavior.
It also exercises the production `openat` filesystem backend in a temporary
directory, including atomic replacement, modes, and symlink rejection. These
checks do not substitute for the signed biometric Keychain gate below. External
editor checks cover bounded shell-free `$EDITOR` parsing, quoted paths, a real
edit/commit, an editor failure, the pre-edit warning, value-free output, and
temporary-workspace cleanup.

The onboarding portion uses temporary homes/projects and synthetic values to
cover supported-client detection (including `CLAUDE_CONFIG_DIR`, missing custom
settings, lexical/Unicode normalization, invalid overrides, and the doctor/host-audit
consumers in `cs-selftest --delegation-setup-only`; an account config dir linked to
`~/.claude` is the gate's "shared home" and setup's "shared account" checks, and
csecd's in `--claude-delegation-only`), additive/idempotent JSON
merges, explicit legacy-hook replacement, disabled-hook policy, duplicate decoded keys,
permissions and file identity, concurrent edits, dangling symlinks, bounded
dotenv/environment discovery, interpolation refusal, reference detection,
selected native-store merging, and prompt size/value exclusion. End-to-end tests
run the actual `csec setup` dry run and apply against the authenticated fake
agent, prove dry run mutates nothing, prove only the selected key is imported,
leave the source intact, protect an existing destination, and exercise explicit
replacement. All fixture values are synthetic and assertions require that they
never appear in setup stdout or stderr.

`cs-selftest --codex-sandbox-only` covers profile reuse and orphan cleanup,
preservation of custom and referenced profiles, removal of the superseded
csec user-hook state, exact private backups and restoration from those backups.
`cs-selftest --delegation-setup-only` also covers the managed hook and
removal of csec's description with surviving user hooks and after the handler
is already absent. Both suites use temporary synthetic configurations.

Prefixed-environment checks cover `csec_NAME` to `NAME` delivery for both native
and 1Password references, collision rejection before access, explicit overrides,
alias removal in supervised and exec-replacement launches, `ai` / `tool-exec`,
and combined env/sidecar delivery. Env protection tests exercise prefixing new
imports, reference-only migration without provider access, repeat runs, and
preservation of comments, quoting, exports, and line endings.

Environment-delivery notices in `cs-e2e` cover `ai` / `tool-exec`, explicit and
env-scanned `exec`, supervised and exec-replacement launches, both providers,
and combined env/sidecar delivery. They require exactly one value-free stderr
warning per injecting launch, with credential/file adapter guidance, while
preserving child stdout and exit status. Secret-free AI commands, launches with
no resolved environment values, file-only sidecars and inherited-fd delivery
must not emit this notice. CLI help checks require the same exposure explanation
and adapter recommendations for both commands.

Bulk hardlink checks in `cs-e2e` (`BulkProtectionHardlinkTests.swift`) use isolated
synthetic homes, explicit scan roots and scrubbed environments. They cover every
approach with and without `--keep-plaintext`: whole-file, file-preset and
env-token imports protect complete alias groups; per-var, SSH and AWS imports refuse
before consent or store/catalog mutation; skip leaves every path untouched.
They also cover explicit `--env`/`--ssh` planning, an `op://` per-var destination,
aliases outside the scan, and alias replacement, content edits or a new link
during the fake consent review. Changed groups and token files retain plaintext
and return a failure rather than reporting complete protection. The ordinary
single-link token cases check that import and cleanup still work and that
`csec exec` materializes the protected token file through its sidecar.

`cs-selftest --discovery-gaps-only` runs the environment heuristics, env parser,
bulk discovery/planning and history-audit regressions with synthetic files.
`DiscoveryGapTests.swift` covers the Quic/av/Crunchy Bridge/Runpod catalog,
reference-only configs, the public `OP_ACCOUNT` UUID exception, static wallet
structures and narrowed scan boundaries. `ShellStartupProtectionTests.swift`
covers skipped unsupported/unparseable startup files, linked startup files,
mixed supported/unsupported assignments and explicit whole-file choices. Its
`cs-e2e` counterpart verifies actual in-place rewrites, preserved startup bytes,
the per-var apply guard, unchanged dotenv/envrc fallbacks and deliberate
whole-file sidecars against the fake agent. `ShellHistoryAuditTests.swift` covers
HA-J07's fixed-pattern counts, output exclusion, unreadable/truncated coverage,
custom history locations, and bounded no-follow/nonblocking regular-file reads.
The suite never reads the developer's actual shell history or credential files.

Session-lineage checks (`cs-selftest --session-lineage-only`, which also runs
the SSH suite) cover the link from a detached job back to the tree that
started it (DESIGN.md §Detached jobs), over a synthetic kernel whose exits
re-parent children to launchd and whose spawns take the next unique ID: the
running-leader link; the recorded link to the leader's parent after the tool
shell exits, and none once Claude exits (with the scope offered then); a reused
session ID (the running new leader wins, the margin keeps the old record out, a
new leader replaces the record); the two races the unique IDs close (a leader
or a record newer than the job); the margin to the allocation; `kern.maxproc`
missing or too large; daemons and launchd's own session; a parent exiting
mid-record; and the capacity bound with its refresh on use. A live part starts
real session leaders the way Claude Code starts a tool shell, lets them detach
a job and exit, and checks the kernel facts, the link, `ProcessInspection.live`
and `GrantTable` coverage against an unrecorded twin. The SSH suite's
detached-job test signs once in the tool call and then from the detached job's
`ssh`: no second review with the record, a second one for that command only
without it.

Grant-scope checks run the ancestry walk over synthetic process trees shaped like
a measured `iTerm2 → login → fish → claude → per-tool-call zsh → csec` chain:
which roots are offered, that the pipe-wired per-tool-call shells (which own no
controlling terminal) are never mistaken for the terminal session, that the
nearest coding agent wins, that a non-ancestor candidate is dropped, and that a
forged option identifier resolves to the displayed default instead of an invented
root. Release-shape digests are checked to survive a command/TTL/context change,
to differ for every exposure-shaping field, and to be domain-separated from the
delivery-plan digest. An `Agent`-level test then proves the wiring end to end
against live ancestry: one approval at a widened root covers a *different* later
command of the same shape, a different delivery shape prompts again, and choosing
the requesting-process root still prompts per command. A companion test covers
capability-GID launches (`csec exec` over `*.csec` sidecars): they are offered the
same roots, a later launch of the same shape rides a widened grant, and the
narrow root still prompts for every launch even when the command is identical. The end-to-end suite
exercises `csec grants` and `csec revoke` over the real socket and asserts the
listing never contains a value. That suite pins scope discovery to "offer nothing
wider" so its per-invocation root assertions do not depend on whether it was
launched from a coding agent or an interactive terminal.

Terminal-session checks (`cs-selftest --terminal-session-only`) cover the
terminal context every review shows: identifying the terminal from the
exec-time environment, the controlling tty, multiplexers, and the iTerm2 and
Terminal.app AppleScript match programs run against synthetic tables. Run under
iTerm2, a live check asks the real `TerminalSessionInspector.live` to name this
tab. On a loaded Mac a cold `osascript` can miss the 2.5 s bound that keeps a
review panel from waiting longer (6 s at a load average near 750), so when the
title is missing the check says so with the load average and asks once more
with a 30 s bound, holding that answer to the same assertion; a broken script
or a declined Automation permission still fails. No other test asks a real
terminal: every service takes its `TerminalSessionInspector` without a default,
and tests pass `.unavailable` or a fake (`bin/ci` holds them to it). Under a CI
runner a live lookup would make macOS ask the runner for Automation control of
iTerm2, and that consent sheet blocks iTerm2 until someone answers it.

`csec edit`'s clipboard checks (`cs-selftest --confidential-text-only` runs
just these) write a `ConfidentialTextView`'s selections to private named
pasteboards, never the general one, and check that each copy carries the
concealed and transient markers in the same single pasteboard generation as its
text, keeps every type an ordinary `NSTextView` copy writes, pastes back
(a multiple selection included), and that copying an empty selection leaves the
previous copy in place.

Main run loop checks (`cs-selftest --main-run-loop-only` runs just these, and
`bin/ci` runs that before the full suite, killed if it hangs) cover
`MainRunLoopKeeper`. cs-selftest has an async `main`, which exits with status
0 when the runtime's run of the main run loop returns, and AppKit's event
thread stops that loop for every WindowServer event once a panel test has
connected. The keeper runs the loop again after each stop. It has to start in
the runtime's own run of the loop, before a panel suite first spins it, or a
standalone `--*-only` run hangs in that spin. The checks spin the loop as a
panel suite's first statement does, then send AppKit's stop three times while
the suite waits. A full run that ends before its last check any other way
fails with "the run was cut short, not passed".

Prompt typing-guard checks (`cs-selftest --prompt-grace-only` runs just these)
drive `PromptInteractionGrace` against a real, offscreen, transparent AppKit
panel built the way the approval panels are, with an injected keyboard clock:
while the grace period runs the window is shown but not key, every registered
control is disabled, and an Escape key equivalent routed through the window
presses nothing. A keyboard still busy past the shortest delay holds the panel
back, each key pressed while it is held starts the wait again, and the panel
goes live only once the reading reaches the threshold; a quiet keyboard adds
nothing to the shortest delay, and a reading that is not a duration holds
nothing back. A model of the real counter — key presses published only when
their step closes, dated to its start — under steady typing never reads quiet
against the quiet period plus one step, and the panel goes live once the
typing stops; against the quiet period alone, the threshold before the step
was measured, the same typing reads quiet and the panel goes live mid-sentence. Once the grace elapses the controls return to their prior state,
the focus step runs exactly once, keyboard focus rests on the
`PromptKeyboardSink`, Space, Return and a letter press nothing, Tab reaches the
controls, and Escape reaches Deny. A grace cancelled by an early finish — or
superseded — while it is held for typing never fires, a control already disabled
before the grace stays disabled after it, and the production constants are half
a second, one second of quiet and a half-second counter step (a 1.5 s
threshold), read by this process without Input Monitoring. The same keyboard checks then run on every surface's own window,
built as presenting it builds it but parked offscreen with no Touch ID
(`ApprovalPanelInspection`): the secret-access, SSH, restore-only,
release-with-restore and settings layouts and the sudo panel each rest focus on the sink,
press nothing on Space, Return or a letter, reach a control on Tab (Full
Keyboard Access on), refuse on Escape, and — the hazard the sink removes — close
when Space lands on a focused refusing button. The focus step is injected, so
the suite never activates the process or steals the developer's focus. A live
panel is the key window, and AppKit sends Tab, and Space on a focused button,
as nil-targeted actions that reach only the key window, so the suite delivers
those keys with `NSApp`'s `keyWindow` reporting the panel, for those
deliveries only, without making it key; on a panel that is not key every one
of these keys reaches nothing and the checks would prove nothing.

One-time codes have their own group (`cs-selftest --one-time-code-only`):
which references count as codes (wider than 1Password's grammar), RFC 6238's
appendix B vectors for SHA-1, SHA-256 and SHA-512, that a code is never cached
or held for auto mode, a restore or fetch ahead, that a provider which cannot
make codes is only ever asked for the seed reference, the seed guard on the
cache, providers and fetch ahead, the wording every surface draws, and,
through `Agent`, that no grant covers or names a code and that a code-only
panel offers only the requesting command and no lifetime. It also checks
that a phone approval is never offered for a value that would wait on its
provider's own prompt at the Mac (csec-0.65.5): the real 1Password provider
over a fake bridge says a reference is attended until a read or keepalive
proves its account's session, and again once the session may have lapsed,
and the remote approval manager keeps such a request on the Mac unless the
value is warm or the phone's unlock opens its cached copy. The 1Password
bridge's seed probe, and that a plain read costs one SDK call, are covered by its
Go tests (`go test ./...` in `bridge/`);
that a live 1Password answers it as the SDK's types say is checked on the M4.

How every surface names a review's secrets is checked the same way
(`cs-selftest --secret-tree-only`): the shared `ReviewSecretTree` folds
account › vault › item › field (this Mac › store › key for the native store),
each level once and a single vault on its account's line; a provider's
description is made display-safe, a reference no provider describes is shown
whole, and a backend the core has never heard of is drawn from its own
description. The release, automation, SSH and restore windows, built with
`ApprovalPanelInspection`, draw each item as one label in its source's colour in
both appearances, wrap a store's keys left to right, never clip a name, and never
show a described reference as a raw URI. To look at a layout without putting a
panel or Touch ID in front of anyone, `CSEC_PREVIEW_OFFSCREEN=1 cs-review-preview
<scenario> <png> [light|dark]` captures the same unpresented window; it has no
Touch ID view, and the probes below need a presented panel. A probe, a hold
or a live-requester unlock check reports on the panel and writes no PNG, so it
takes only `<scenario> [light|dark]` and refuses an output path (and
`CSEC_PREVIEW_OFFSCREEN`). Add
`CSEC_PREVIEW_EXPAND=1` to capture it with every disclosure open; opened
disclosures grow the window and scroll only past the screen's visible height
(`ReviewDisclosureFit`), which `cs-selftest --disclosure-fit-only` checks on the
SSH and release windows. The same run checks every command a panel shows
(`ReviewCommandText`: the sudo card, the full command line, an automation job's
exact command) and every list (`ReviewFittedList`: the release and automation
secrets, restore rows alone and beside a release, the SSH details) is whole on
a screen with room, and otherwise fills only the screen, keeps its scroller
drawn beside the rows rather than over them, starts at its first row, scrolls
to its last and shows its overflow cue; a long list with an opened long command,
and two long lists, share the screen (`ReviewScreenFit`). `cs-review-preview
exec-long` and `restore-long` show a list longer than any screen.

A panel a developer check puts on screen says so: every presented
`cs-review-preview` scenario and probe, and the debug `csec-sudo-review` live
probes (`--grace-probe`, `--typing-probe`, `--focus-probe`, `--unlock-probe`,
`--deadline-probe`, `--no-touch-id-probe`, `--synthetic-review-probe`), draw a
solid red "TEST — NOT A REAL REQUEST" banner as the panel's first row and title
the window "Convenient Security — TEST" (`ReviewTestBanner`). They are the real
windows, so without it a probe's panel and a request waiting on the human look
the same. Offscreen renders (`CSEC_PREVIEW_OFFSCREEN=1`, `csec-sudo-review
--preview`) are never on screen and stay unmarked, so use them for design
pictures. Only test entry points turn the marker on; csecd and the
PAM-spawned helper never do, and `bin/ci` holds every write to
`cs-review-preview`, the sudo helper's `#if DEBUG` block and the self-test.
`cs-selftest --test-banner-only` builds every surface and layout with and
without it.

Every button and pop-up a panel draws is held back by its typing guard.
`bin/ci` counts constructions against `interactiveControls` registrations in
each panel file; `cs-selftest --panel-controls-only` checks the windows
themselves, built with `ApprovalPanelInspection`: the secret-access layout
with several roots and with one, with a deadline, the setup panel (a
native-store edit, no scope or lifetime), the SSH layout with several roots
and with one, automation, restore-only, release-with-restore and the sudo
panel with and without Touch ID, each again with every disclosure opened. The
same run checks the scope radios read the release panel's words on the
release layouts and the SSH words (`ReviewDisplay.sshScopeTitle`) on the SSH
layout.

`cs-review-preview` release fixtures that spell out no scope choice are given
production's single-root shape (the requesting command only), as csecd offers
a request with nothing to widen to; `setup` is the one scenario with no scope
or lifetime, as csecd draws a native-store edit or SSH key registration.
`ssh-ambiguous` is an SSH key held in 1Password with the ambiguous-vault
warning, which stands under the SSH key fact with the details collapsed; the
details' secret card then leaves it out rather than repeat it, and
`cs-selftest --secret-tree-only` checks it is drawn once and shown.

The line beside the armed sensor on the secret-access and SSH layouts states
the grant the live selection would make, scope and lifetime ("Touch the sensor
to allow SSH from this fish terminal session for up to 12 hours"), built from
the same phrase as the SSH scope summary, and a scope or lifetime change
restates it while it shows the ready text. `cs-selftest --touch-id-status-only`
checks the wording for every scope kind and lifetime and the default line on
both real panels; `cs-review-preview ssh` or `scope` with `CSEC_PREVIEW_SCOPE` /
`CSEC_PREVIEW_DURATION` shows it following a changed selection. The sudo panel
keeps its own line: it grants nothing past the one invocation.

A request with no argv of its own whose root is its requester's direct parent
(a language client over `csec bridge`, a `csec get`) shows that requester's
process command line under the reason it wrote. `cs-selftest
--requester-command-only` covers it end to end: the start-time-bracketed argv
read against a real `bash` and its child, redaction of a value csecd already
released, the panel's decision-log `command`, no line when argv cannot be read
or the request is rooted at its caller, the phone mirror (`requesterCommand`,
its signing domain and bounds, refused on SSH and sudo reviews), the alert's
extra line, and, through `ApprovalPanelInspection`, the line on the release
layout (with or without a restore section) and none on the restore-only,
automation and SSH layouts. `cs-review-preview bridge` draws it.

The real panels are checked on-device through one shared probe
(`PromptInteractionGraceProbe`), which prints the panel's key/active state, what
holds keyboard focus, how long ago a key last went down (`keyboardIdle=`), and
every control's enabled state shortly after it appears and again after the
grace period (1.8 s, past the 1.5 s keyboard reading that the Return launching
the probe can make the grace wait for): `CSEC_PREVIEW_GRACE_PROBE=1 cs-review-preview <scenario>` for
the secret-access and SSH reviews, and `csec-sudo-review --grace-probe` for the
sudo review. The `firstResponder=` field is what proves focus lands somewhere
inert: both samples must name `PromptKeyboardSink` on every scenario and on the
sudo review, whatever `defaults read -g AppleKeyboardUIMode` says. A button
title there is a failure — with Full Keyboard Access on (2 or 3), Space presses
the focused button, so the refusing one (`Cancel`, `Deny`, `Forget these
approvals`, `Use Password…`) turns a resumed sentence into a denial — and so is
a scope radio or the lifetime popup, whose stray Space or arrow would reshape
the grant, or a `Show …` disclosure. A second sample still held with a small
`keyboardIdle=` means a key went down during the run; rerun without typing.

Only a human typing can show the hold reading the real keyboard:
`CSEC_PREVIEW_TYPING_PROBE=1 cs-review-preview <scenario>` and
`csec-sudo-review --typing-probe`. Launch one and keep typing (into the same
terminal without Return, or a TextEdit window) as the panel appears, for a few
seconds, then stop. It prints the first sample, the one where the panel went
live, and `typing probe: PASS — held …ms while you typed (… counter steps with
a key); live when the keyboard counter read …ms (needs 1500ms, …)`; it exits 1
on FAIL (live before the counter read 1.5 s, or never live) and 3 on
INCONCLUSIVE (nobody typed long enough to hold the panel past its shortest
delay). Keep your finger off the sensor: a touch exits 2. The counter works in
half-second steps, dated to the step's start, so `keyboardIdle=` jumps rather
than counting down from each key.

The `LAContext` behind those three panels comes from one factory,
`ReviewAuthenticationContext.make(for:)`, and the suite asserts per surface that
it reuses no lock-screen Touch ID match
(`touchIDAuthenticationAllowableReuseDuration == 0`), carries that surface's
refusing title, and offers no in-sheet password fallback; nothing there
evaluates a policy, so no run puts a Touch ID sheet on screen. A `bin/ci` guard
holds the shape: neither panel file may build its own `LAContext`, each names
its own surface, and no source anywhere may set a nonzero reuse duration.

Deny and requester-gone behavior is covered on every surface. The SSH suite
starts three concurrent same-shape signing requests against a gated review
wrapped in `QueuedPolicyReview` and expects one review and three valid
signatures, for a `csec://` and an `op://` key; a command-only selection, two
terminals, two host keys and two remote users each still give separate
reviews; a human Deny refuses the waiting identical requests and ends the
denied connection's signing, while a later request, another terminal, and a
`.requesterGone` or `.authenticationFailed` denial all get panels; a requester
that exits while its review is built is never reviewed or looked up. The
liveness suite runs the SSH agent socket's peer-exit watch over a real socket:
a closed client cancels its on-screen review within two polls, a queued one is
never presented, and the refusal logs `reason=requester_gone`. The propagation
suite covers `HumanDenialLedger`, the Touch ID error mapping, the unlock
re-present rule, the reasons through `QueuedPolicyReview` and
`MirroredPolicyReview` (a phone Deny is `.human`), and the access path's
identical, other-shape, other-reference and outside-the-root waiters. It also
orders a Deny by the instant the human decided: with a reviewer that returns
late, and through a `MirroredPolicyReview` whose phone leg is slow to withdraw,
a request that arrives after the decision gets its own panel (the SSH suite has
the same check). The sudo
side runs the real built `csec-sudo-review --parent-watch-probe` under a
throwaway shell and kills the shell, then quits another such probe as a
running application (`NSRunningApplication.terminate()`, as logout or any
process of the user can) and requires exit 69, never AppKit's exit(0), which
the PAM module would read as an approval (`cs-selftest --sudo-helper-only`
runs just these two), and `packaging/tests/test-pam-cleanup.c`
drives the PAM wait loop with a pending SIGINT, a pending SIGQUIT and a tty
hangup (each kills and reaps the helper and fails the module) plus a real pty
whose master closes. On-device, `cs-review-preview requester-gone` and
`ssh-requester-gone` show a real panel whose requester exits and check it
closes as `.denied(.requesterGone)`, and `cs-ssh-e2e` runs with
`CSEC_SSH_E2E_SCENARIO=concurrent` (three real `ssh`, one review) and
`interrupted` (`kill -INT` an `ssh` whose review is on screen; the next one is
reviewed afresh), plus `orphaned` (SIGKILL its waiting shell while the ssh stays
alive; withdraw its review and review the next connection afresh).

`cs-selftest --human-wait-only` also checks `RequestAnchor` against separate
kernel and lineage trees: parent, requester and scope pid reuse; launchd
parentage at arrival; queue re-entry; the shared cancellation watch; access
requests lost on screen, on the access turn and on the UI queue; and an
approval whose root fails, logged as approval plus `delivery_failed` with no
grant. The SSH suite covers shown and queued parent loss with a surviving
lineage link, original-root/cause/wait logging, an unrelated live request,
next-key refusal, pid reuse, and root loss between approval and signing for
native and other-provider references. `cs-review-preview requester-orphaned`
and `ssh-requester-orphaned` use a real sleep under a killed shell: each must
close through the shared watch while the requester itself is still alive.
Sudo retains its own-parent watch and 300 s PAM limit; watching sudo's parent
would make early failure fall through to macOS Touch ID.

`cs-selftest --review-presentation-only` checks the cross-process presentation
turn shared by csecd's FIFO and every sudo helper. It covers access, SSH,
automation, restore-only and release-with-restore reviews; retention through
authentication completion or cancellation; standalone biometrics; cancellation
while waiting; and unsafe lock paths. A queued sudo starts neither its Mac
panel nor its phone leg. The suite starts multiple real helpers with
`--presentation-lock-probe <private-directory>` and PAM's clean environment:
only one owns the turn, EOF releases it normally, and killing an owner releases
it without deleting the rendezvous file. These are windowless synthetic
reviews, with no Touch ID or real sudo. `bin/ci` guards both production entry
points' use of the same lock. The existing grace/focus and SSH concurrent and
interrupted checks continue to exercise the unchanged panel behavior.

The restore suite also drives parent loss through `HumanWait` with two callers
waiting: the orphan's displayed panel must cancel and re-present for the live
survivor, with no store opened until that new panel is approved. Two requests
from the same still-live caller continue to share one restore panel.

Every SSH scenario runs inside a terminal session of its own:
`cs-ssh-e2e` opens a pty, starts `/bin/sh` as a new session leader that takes
the pty as its controlling terminal, and runs itself again under it, so its
`ssh` share a terminal-session grant root (`GrantScopeInspector`) however the
run was started: in a foreground terminal, from a coding agent, or detached
under `nohup` or launchd. The inner run fails, never skips, if that session
has no controlling terminal or offers no root above `ssh`, and a signal that
ends it (the hangup when its outer run is killed) stops its `sshd` and removes
its fixture directory.

The GitHub token proxy ([`github-proxy.md`](github-proxy.md)) is covered by
`cs-selftest --github-proxy-only`: the request parser's refusals (ambiguous
framing, obs-fold, a second `Host`, upgrades, absolute targets, the placeholder
in an unrecognized form), the host table, chunk reframing, response heads,
redirect tickets, a live socket exchange against a recording fake GitHub, and
the Agent path with references of two schemes. It also covers the requests
that can give lasting access (`GitHubLastingAccess`): every listed endpoint,
the near misses that stay ordinary, the spellings that still count, the
routine GraphQL requests sessions send (review threads, pull request and issue
edits, comments) staying ordinary when sent chunked, why an unread one asks,
and the Agent path giving each its own review that mints nothing;
`cs-review-preview github-lasting` draws that panel. When `gh` is installed it also
runs the real `gh api user`, a GraphQL POST and `gh api graphql --input -`
(which sends its body chunked) through the socket to the fake
GitHub, with a private `GH_CONFIG_DIR` whose placeholder token keeps `gh` from
ever reading a real credential, and checks GitHub received the token and `gh`
only the placeholder. `cs-e2e` drives `csec github` and `csec protect --gh`
through the real launcher against a scripted `gh` (with `--keep-plaintext`, so
no keychain item is touched), and `cs-review-preview github` draws the
daemon-proxy panel: "Secret used, never released", the sensor line saying the
scope may use the value, and the footnote that the token stays in csec.

The delegation changes (`enable`, `trust_build`, `acknowledge_hooks`) are
csecd's settings panel, not a sheet: `--claude-delegation-only` checks that
each shows it (Mac-only, nothing released, the requesting tab named) and that
its Deny, a failure and a requester that went away answer as distinct reasons,
and `cs-review-preview settings` draws it (`rules-changed` draws the panel
csecd raises itself when the classifier rules change, `hooks-changed` the same
panel for a newly added hook, which `--remote-approval-only` checks is the one
settings change that reaches the phone, signed under `+settings` and bound to
the sources it acknowledges); with
`CSEC_PREVIEW_TYPING_PROBE=1` it is the on-device check that typing as it
appears refuses nothing. The other setup steps (backups, a restore, phone
pairing, machine identities, removing an SSH key or an automation job,
deleting stored files, the uninstall cleanup, host fixes) take the same panel:
`--settings-panel-flows-only` checks the uninstall, SSH key removal and host-fix
panels, and the backup, remote-approval, machine-identity, automation and
`--native-store-removal-only` suites check theirs, each
for the caller that asked and with no bare sheet; `--panel-controls-only` and
`--prompt-grace-only` build the host-fix panel's real window.

Why a bare Touch ID sheet (`BiometricConsent`, a provider with no panel) ended
is covered by `cs-selftest --consent-refusal-only`:
each `LAError` code's cause and words, the decision-log outcome, decider, cause
and time on screen, the rule that shows a sheet macOS dismissed with the screen
unlocked once more (a locked screen still waits), the shared queue passing the
reason through or turning it into `requester_gone`, and setup's "Touch ID was
not given: <why>" line. `--claude-delegation-only` checks that the `enable`,
`trust_build` and `acknowledge_hooks` sheets log and answer a Deny, a
dismissal and a finger not recognised as three distinct reasons. A real sheet
cannot be driven from a test: to see the reasons on the Mac, run `csec setup
auto-mode`, answer the sheet each way (Deny; click another window or let
another Touch ID prompt take it, twice; a finger Touch ID does not know), and
read setup's line and `csec log --kind settings`.

A coding agent's wait on a human (`HumanWait`, csec-ia3q) is covered by
`cs-selftest --human-wait-only`: the `defaults` setting and its bounds; the
decided/expired latch, including an approval that lands after the deadline
(answered as `.timedOut`, its authentication cancelled) and one before it
(never cut); the one waiting notice, never for a terminal's request; the notice
frame (opt-in, sanitized, bounded) over a real socket; the `withdrawn` record;
and, through `Agent` with the real `QueuedPolicyReview`, an unanswered request
withdrawn on screen at its deadline, three requests queued behind one panel
lapsing together, a terminal's request waiting past the limit, an answered one
released, and the board handing a waiting request's notice to the `csec ai`
above it once per session; and, over a real socket to a real `Agent`, the
notice channel reporting a waiting `ssh` under the session once, with a
refused poll leaving the output scanner beside it working. The SSH suite's W1–W3 cover an `ssh` under Claude
Code withdrawn on screen (its next key refused at once), a terminal's `ssh`
waiting past the limit, and a queued one lapsing unseen. Fixtures pass
`terminalInspection: .unavailable`: the live terminal lookup can take over a
second, which a short test deadline would otherwise measure.

The sudo review's phone leg (`sudo_remote_review`) is covered by
`cs-selftest --sudo-remote-only`: the wire and its bounds; the per-role gate
both ways (the helper may send only that request, the launcher never), through
the real `SocketServer` with `SocketPeerTrustPolicy.assumeRoleForTesting`; the
frozen `sudo` review and its operation digest (another helper pid or start time
is another operation); csecd's answers and the decision-log record; a signed
approval and Deny through the real requester and a synthetic phone key; the
race (a phone approval or Deny closes the panel, a Mac decision withdraws the
phone leg, an unreachable csecd or unready phone leaves the panel alone and
undelayed, and closing the helper's connection withdraws the phone's copy
within two peer-exit polls); and, in a debug build, the built helper's
`--phone-probe` against a stand-in csecd. Live synthetic panel and phone probes
are debug-only: use `agent/.build/debug/csec-sudo-review`. The installed release
helper rejects those flags; a real `sudo` with the phone paired checks the
panel closing on a phone decision.

`cs-selftest --sudo-helper-only` checks the helper's effective-root parent
requirement with root, non-root, unreadable and reparented facts, then starts
the real unprivileged helper with stdin held open and with a valid forged
frame. Both must exit 69 before any review. `build-sudo-review.sh` repeats
those entry checks on the shipping release and rejects every live probe flag.
It still renders every offscreen `--preview` fixture without Touch ID. The activation
sampler uses the debug-only `--synthetic-review-probe`, which accepts only its
fixed fixture and then shares the production review body; it cannot submit
arbitrary text to the installed helper. The parent trust check does not change
the secret-access/SSH panels or their authenticated csecd entry points.

The sudo PAM deadline is covered by `packaging/bin/build-sudo-pam.sh`: its
shipping-C harness distinguishes elapsed expiry from helper/clock/wait failure,
checks bounded cleanup with and without a tty, and uses real PAM transaction
data/cleanup APIs to prove the expiry latch persists only within that
authentication. The sufficient review returns `PAM_IGNORE` on expiry and on an
interrupt (Ctrl-C, Ctrl-\ or a hangup); the following requisite
`review_guard` returns fatal `PAM_ABORT`, before stock `pam_tid` or a password
conversation can run. The same harness drives the guard with a pending Ctrl-C
the review never saw (fixture `sigpending`), and `test-pam-transaction.c`
with a real one held by a blocked `SIGINT`, as sudo holds it: either aborts
with exactly one interrupt message. Explicit Use Password and helper
failures retain recovery. The build also runs `packaging/tests/test-sudo-policy.py`
for fresh policies, migration, idempotence, unsafe ordering, exact upgrade
rollback and the removal (`--uninstall`: the stock file back, edits kept, a
csec-created file deleted, every csec file swept, a failed or interrupted live
sudo restoring `sudo_local`, refusals changing nothing), and `packaging/tests/test-sudo-verification.py` for the installer's
live-check verdict: a concurrent sudo's approval, a helper started by another
sudo, helper refusal followed by Apple's fallback or `pam_tid`, fallback-only
and skipped reviews, missing helper exits and forged images are refused; Mac,
phone and delegated approvals and an approved retry keep the installation. `cs-selftest --sudo-integration-only` verifies doctor rejects a missing,
misordered or obsolete guard. The same harness checks the helper's own
expiry: exit 75 within ten seconds of the module's deadline ends sudo as the
deadline does, exit 75 earlier is a fault that keeps recovery, and expiry sends
exactly one `PAM_ERROR_MSG` through a capturing conversation (a failing
conversation changes nothing). `build-sudo-review.sh`'s C/Swift frame check
covers the version-2 frame's time limit.

Every panel with a deadline shows it (`ReviewDeadline`). `cs-selftest
--review-deadline-only` checks the line's text and timing, the helper's
`SudoReviewDeadline` latch and watch, the wire's time limit and its bounds,
and the real secret-access, SSH and sudo windows: the quiet line, the
countdown, the same window height either way, and no line without a deadline.
It also checks the phone's copy (`PhoneDeadlineTests.swift`): the card's line
is the panels' word for word (`ReviewDeadlineText`) and redraws only when it
changes, the deadline is signed under its own `+deadline` domain and bounded
to a day after the request, a restore carries none, the mirror freezes the
request's `HumanWait` deadline, and the sudo helper's closing moment reaches
the signed review (one no PAM frame could give is dropped). The iPhone UI test
`testDeadlineLineSaysWhenTheMacClosesTheRequest` runs the Simulator fixtures
`sudo` (the quiet line) and `sudo closing in 29 seconds` (the countdown), and
checks a terminal's request has no line; `MailboxUITests`'
`testAnAnsweredRequestIsNotActionableAfterARelaunch` checks a sent card, which
stays on screen there, drops it.
`CSEC_PREVIEW_DEADLINE=<seconds>` draws the line on any secret-access or SSH
scenario and on the sudo preview (30 or less draws the countdown). Presented
by `cs-review-preview`, it is the real `HumanWait` withdrawal: with
`CSEC_PREVIEW_HOLD=1` and nobody answering, the panel counts down and closes
at the deadline, printing `hold: denied(timedOut)`. `csec-sudo-review
--deadline-probe` runs the sudo helper's real close: the production race and
parent watch with a 35-second time limit, sampling the quiet line and the
countdown, and expecting the panel to close unanswered 32 seconds in with
nothing left on screen. Do not touch the sensor:

```sh
CSEC_PREVIEW_DEADLINE=20 agent/.build/debug/csec-sudo-review --preview basic /tmp/sudo-deadline.png light
CSEC_PREVIEW_DEADLINE=25 CSEC_PREVIEW_OFFSCREEN=1 agent/.build/debug/cs-review-preview ssh-agent /tmp/ssh-deadline.png
CSEC_PREVIEW_DEADLINE=35 CSEC_PREVIEW_HOLD=1 agent/.build/debug/cs-review-preview basic
agent/.build/debug/csec-sudo-review --deadline-probe
```

Secret-access and SSH withdrawal is otherwise unchanged; its tests and the
sudo phone disconnect tests cover withdrawal on those paths.

Delegated sudo is covered in three places. `cs-selftest
--claude-delegation-only` holds the pure parts (`SudoCommandDisplay`'s
decoding, which refuses anything the PAM module would not write;
`SudoInvocation`'s reading of sudo's options; matching an argv with redacted
arguments) and the service over a synthetic tree in which sudo is set-id root
(its `proc_pidinfo` and argv unreadable, as the kernel has them): the shapes a
text runs sudo in, every decline, the gates, the offer, recording an approval
and the pairing format's migration, plus a live read of setuid-root
`/usr/bin/top`'s kernel record. `cs-selftest --sudo-remote-only` holds the
`sudo_delegation`, `sudo_pairing`, `sudo_terminal` and `sudo_review_end` wire,
the role gate, the helper's bounded wait for csecd's terminal tab, the phone
card's note and unscoped line with a phone approval pairing, and how each
review's end is logged: the outcome the helper reports (none for a phone
decision, `requester_gone` once its sudo exited, `timed_out` once the deadline
won), the record of each, and its root, the coding agent above the sudo over a
synthetic tree, kept once the sudo has exited. `build-sudo-review.sh`
pipes the C PAM module's rendering of awkward arguments (spaces, quotes, `$`,
backquotes, backslashes, a tab, an empty and a non-ASCII argument) into the
built helper's `--display-round-trip`, which decodes it back with
`SudoCommandDisplay` and requires the same argv. The sudo helper's preview
names its fixture as `cs-review-preview` names a scenario: `basic`,
`long-argv` (the 64 arguments the module renders at most, which on most
screens grow the command card to the screen's height and leave it scrolling,
with its overflow cue) or `multi-line` (an `sh -c` script, whose newlines the module
writes as `\x0A`); each must be a frame the module could send, and
`build-sudo-review.sh` renders all three. There is no redactor-unavailable
fixture: when the module cannot render the command it raises Apple's prompt
instead of this panel, and `build-sudo-pam.sh` checks that prompt's text. The
preview takes the same knobs as `cs-review-preview`: `CSEC_PREVIEW_DELEGATION=<code>`
(one of `sudo_not_approved`, `sudo_indirect`, `sudo_option`,
`command_mismatch`, `not_auto_mode`, `not_registered`) and
`CSEC_PREVIEW_PAIRING=1`, which always shows on sudo:

```sh
CSEC_PREVIEW_DELEGATION=sudo_not_approved CSEC_PREVIEW_PAIRING=1 \
  agent/.build/debug/csec-sudo-review --preview basic /tmp/sudo-delegation.png light
```

With Touch ID unavailable on the Mac the sudo panel cannot approve, so it is
up only while the paired phone may still decide, and the review ends for
Apple's prompt the moment the phone cannot (`SudoReviewWithoutTouchID`;
`cs-selftest --sudo-remote-only` holds the decision, the race's word to the
panel and the real panel's no-window path). `CSEC_PREVIEW_NO_TOUCH_ID=1` draws
the panel held up for the phone, and `--no-touch-id-probe` runs both paths on
the real panel, then Touch ID coming back (the lid opened) while the panel
waits for the phone: the panel must arm it and stay up when the phone gives up
afterwards. Last, Touch ID goes away under an armed panel (the lid closed
with an external display, `ReviewTouchIDOverride.lostAfter`): with the phone
pending the panel must stay up for it, and with no phone the review must end
for the password. It needs nobody, but the screen must be unlocked; Touch ID
is armed for a few seconds in all, so do not touch the sensor. Expect `PASS`
(`INCONCLUSIVE` on a Mac that cannot take a touch at all):

```sh
CSEC_PREVIEW_NO_TOUCH_ID=1 agent/.build/debug/csec-sudo-review --preview basic /tmp/sudo-no-touch-id.png light
agent/.build/debug/csec-sudo-review --no-touch-id-probe
```

The secret-access, SSH and restore panels stay up without Touch ID, and their
line says whether the phone can still approve (`ReviewTouchIDUnavailable`;
`cs-selftest --touch-id-unavailable-only` holds the copy, the re-arm rule, the
mirror binding `ReviewPhoneStatus.current` and every layout's real window).
`CSEC_PREVIEW_NO_TOUCH_ID=1` draws a scenario that way (`CSEC_PREVIEW_PHONE=1`
for a phone that may decide; a number of seconds instead of `1` lets Touch ID
return then, for `CSEC_PREVIEW_HOLD=1`), and `CSEC_PREVIEW_TOUCH_ID_PROBE=1`
runs the live sequence: the phone line, the no-phone line once the phone leg
gives up, then Touch ID armed once it returns.
`CSEC_PREVIEW_TOUCH_ID_LOST_PROBE=1` runs the other direction: the panel arms
Touch ID, which goes away two seconds later and ends the evaluation as a lid
closed with an external display would; the panel must stay up with the phone
line, then the no-phone line once the phone leg gives up
(`ReviewTouchIDUnavailable.afterFailure`). Both need the screen unlocked. Do
not touch the sensor; expect `PASS`:

```sh
CSEC_PREVIEW_NO_TOUCH_ID=1 CSEC_PREVIEW_PHONE=1 CSEC_PREVIEW_OFFSCREEN=1 \
  agent/.build/debug/cs-review-preview ssh-agent /tmp/ssh-no-touch-id.png light
CSEC_PREVIEW_TOUCH_ID_PROBE=1 agent/.build/debug/cs-review-preview basic
CSEC_PREVIEW_TOUCH_ID_LOST_PROBE=1 agent/.build/debug/cs-review-preview ssh-agent
```

The unlock re-present checks its requester before asking for Touch ID again,
and both branches are checked on-device with the Mac actually locked. The
preview fixtures' requester is the preview process itself, so it is alive. All
three surfaces share one live-requester check (`PromptUnlockRecheckProbe`,
its decisions unit-tested in `cs-selftest --prompt-grace-only`). A panel
already up when the Mac locks is normally not cancelled: the lock shield takes
key and pauses its Touch ID, and the panel renews it on a fresh context once
key after unlock. Only an evaluation started behind the lock screen is
cancelled, and that panel says it is held for unlock. The probe prints the
lock, any hold and the unlock, makes the panel key as a click would if it is
not key five seconds after unlock, then prints `PASS` naming which way the
panel took; a panel that closes, or no lock, unlock and fresh Touch ID within
three minutes, fails it. The sudo panel
has no requester-gone variant: its helper watches the sudo that spawned it
and closes when it exits, locked or not:

```sh
# Live requester: lock while the panel is up, unlock; expect "PASS — the
# requester is alive; …" naming the path. Do not touch the sensor.
CSEC_PREVIEW_UNLOCK_RECHECK=1 agent/.build/debug/cs-review-preview basic
CSEC_PREVIEW_UNLOCK_RECHECK=1 agent/.build/debug/cs-review-preview ssh
agent/.build/debug/csec-sudo-review --unlock-probe
# Requester gone: lock at once, stay locked more than ten seconds, unlock;
# expect "…closed as denied(requesterGone)" and no Touch ID.
CSEC_PREVIEW_UNLOCK_RECHECK=1 agent/.build/debug/cs-review-preview requester-gone /tmp/rg.png
CSEC_PREVIEW_UNLOCK_RECHECK=1 agent/.build/debug/cs-review-preview ssh-requester-gone /tmp/rg.png
```

Touch ID answers only the key panel, and a later evaluation from any other
process strands an armed one with no callback, so every panel re-arms after
losing key while armed (`ReviewFocusRecovery`, unit-tested in
`cs-selftest --prompt-grace-only`; `bin/ci` holds both panel files to the
re-arm's order, its deferral, its non-activating focus step and its generation
guard). On-device, one shared probe (`PromptFocusRecoveryProbe`) brings Finder
to the front while Touch ID is armed, then makes the panel key again as a
click would, then leaves again inside the re-arm's grace. Do not touch the
sensor:

```sh
for s in basic ssh restore restore-mixed automation requester-gone ssh-requester-gone; do
  CSEC_PREVIEW_FOCUS_PROBE=1 agent/.build/debug/cs-review-preview $s
done
agent/.build/debug/csec-sudo-review --focus-probe
```

Each prints samples in the grace probe's format with `touchID=#N` (a new
number is a fresh context) and `clickToResume=shown|absent`:

- `shown`, inside the first grace, is usually not key, with `touchID=#1`
  (a preview launched from the active terminal can be activated at launch and
  read key with `#2` already);
- `armed` is key with `touchID=#2`: Touch ID armed before the panel was ever
  key is renewed the first time it is, since another prompt may have
  registered after it;
- `away` is not key, `touchID=#2`, `clickToResume=shown`;
- `back` is key with `touchID=#3` and every control disabled by the new grace;
- `left` comes after Finder was brought forward again inside that grace and
  the grace has ended: still `key=false active=false` with `touchID=#3` — the
  re-arm's grace never takes the focus back (if it did, two armed panels would
  trade the focus forever);
- `back-again` is key with `touchID=#4`;
- `settled` has the controls enabled and `firstResponder=PromptKeyboardSink`.

A touch that approves a probe's panel freezes its controls, so every grace and
focus probe run fails with `probe: APPROVED …` (exit 2) when one does; keep
your finger off the sensor. The focus probe makes the panel key itself, so it
can also take a touch meant for a real prompt and strand that prompt: run it
only when nothing else can prompt.

On `requester-gone` and `ssh-requester-gone` the requester exits while the
panel is away, and `back` closes it through the re-arm's requester check:
`…making it key again closed it as denied(requesterGone)`; a panel still up
fails the run.

The probe cannot show that the fresh evaluation takes a touch a stranded one
would not; that needs a finger and a second prompt. `CSEC_PREVIEW_HOLD=1` keeps
a preview panel up for a real decision and prints `hold: approved` or
`hold: denied(<reason>)`. The debug helper's `--synthetic-review-probe`, fed
its fixed fixture over a private pipe, exits 0 on approval and 69 on Use Password. Start one, then
raise the other surface's grace probe as the competing prompt; when it has
gone, click the held panel (it says to) and touch the sensor. In bash or zsh
(fish spells `$!` as `$last_pid`):

```sh
CSEC_PREVIEW_HOLD=1 agent/.build/debug/cs-review-preview basic &
sleep 2; agent/.build/debug/csec-sudo-review --grace-probe; wait   # expect "hold: approved"
packaging/build/sudo-review/csec-sudo-review-wire-probe sudo /usr/bin/true --api-key synthetic-short-value safe |
  agent/.build/debug/csec-sudo-review --synthetic-review-probe &
helper=$!
sleep 2; CSEC_PREVIEW_GRACE_PROBE=1 agent/.build/debug/cs-review-preview basic
wait "$helper"; echo "exit=$?"                                     # expect exit=0
```

The restore panel, the secret-access variant a restarted csecd raises to reopen
what restored grants need, is covered by `cs-selftest --restore-panel-only`
(with `--grant-persistence-only` for the persisted grants item it restores
from): concurrent secret and SSH requests wait on one panel, its one context
warms the listed batch and is invalidated, Forget and approval use it up, a
requester that leaves uses nothing up, a mixed panel is one review, and native,
`op://` and a third scheme need one touch between them. The suite also drives
`csec restore`'s installer waiter through repeated
secret/SSH cancellations on one review, joining an existing restore or mixed
panel, no pending rows, an already completed restore, requester loss, Forget,
authentication failure and incomplete warming. Wire/client/CLI checks prove
the request supplies no references and returns only status, with nonce and
peer-role checks. `packaging/tests/test-build-and-install.py` proves the new
`approval-restore` presence checkpoint follows runtime repair and precedes the
hook/sudo stages, and that failure stops without retrying. The restore stage
uses the existing access/SSH restore variant and phone mirror; sudo has no
persisted grants to restore. On-device,
`cs-review-preview restore` and `restore-mixed` show both layouts, each listing
restored grants and a paired Claude Code project (`mailer`, "Claude Code auto
mode in …", with its references), the row a delegated request's restore adds; with
`CSEC_PREVIEW_UNLOCK_RECHECK=1` the restore panel is held for unlock and
re-presented like the others. Whether a paired `op://` value is in the
biometric cache, and so restorable, is an attributes-only Keychain query that
cannot prompt (`KeychainBackend.contains`). The suite covers it only with fake
backends, and the unsigned development build has no access group, so it is
untested against the real data-protection Keychain until a signed build runs
it: restart csecd with a Claude Code session live in a paired project whose
`op://` value is cached (it gets no restore row: its next command fetches it
from 1Password with no csec panel), then with 1Password locked (its next
command declines as `not_held` with an ordinary panel), and read
`csec log --kind restore,decline`.

Claude Code delegated approvals are covered by
`cs-selftest --claude-delegation-only` (registration and binding, the gate
order, bounded fact collection, pairing, revocation, `configure_delegation`,
SSH, restore, and backend neutrality against in-memory stores, a fake settings
gate and fixture process trees). Pairing per git repository runs against real
layouts that `git` writes in a temporary directory (a checkout, linked
worktrees including one with relative pointers, a nested repository,
a submodule, a separate git directory, a pruned worktree) and against planted
`.git` pointers, so it needs `/usr/bin/git`. The SSH rule (csec-0.11) is
covered by `delegationSSHTests`. Shapes the old chain rule refused (an interpreter,
a git hook, `timeout` running something else, an unpinned or scratch script, a
heredoc, a deploy lock, steering environment, an unapproved destination,
unacknowledged classifier rules) must sign with no panel. A command that was
not registered, was approved in another mode, ran in a bypass session or an
unverified build, or an `ssh` from a terminal, must still get the panel. An
SSH panel offers no pairing line, and a pairing an earlier csecd wrote with SSH
uses and pinned launcher scripts still lists and revokes. The pure analysis of
shell text (simple commands and argument matching, which sudo, the git
passthrough, the credential guard and the worktree-escape check read) is
`cs-selftest --launcher-script-only`. Delegation's two review lines
render on the secret-access, SSH and sudo layouts (the sudo helper's own
preview takes the same knobs, below): `CSEC_PREVIEW_DELEGATION=<code>` adds the decline note for one
`DelegationDecline` code (`not_registered`, `not_held`, `command_mismatch`,
…), and `CSEC_PREVIEW_PAIRING=1` adds the pairing line to a secret-access
scenario whose default scope is Claude Code (`scope`), where it shows with the
process lifetime; add `CSEC_PREVIEW_SCOPE` or `CSEC_PREVIEW_DURATION` to
capture it hidden. With a code pairing can't end (`launch_option`, …) the line
takes that decline's condition ("… once Claude Code is started without …"),
as csecd writes it, on both previews. An SSH panel never offers one (csec-0.11), so the preview
refuses `CSEC_PREVIEW_PAIRING=1` on `ssh-agent`. Under
`CSEC_PREVIEW_GRACE_PROBE=1` those two selections are applied before the first
sample, and on a panel that carries a pairing offer both samples add
`pairingLine=shown` or `pairingLine=hidden` (the field is absent elsewhere),
so hiding can be checked from the probe's output. The
preview refuses both knobs on the restore-only and automation layouts:

```sh
CSEC_PREVIEW_DELEGATION=not_approved_for_project CSEC_PREVIEW_PAIRING=1 \
  agent/.build/debug/cs-review-preview scope /tmp/delegation.png
CSEC_PREVIEW_PAIRING=1 CSEC_PREVIEW_DURATION=3600 \
  agent/.build/debug/cs-review-preview scope /tmp/delegation-capped.png
CSEC_PREVIEW_DELEGATION=not_registered agent/.build/debug/cs-review-preview ssh /tmp/delegation-ssh.png
```

`cs-selftest --automation-only` covers the framework Python launcher/app
identity split, old catalog compatibility, changed-image refusals and a
synthetic signed app whose missing resources must not hide its cdhash or bypass
executable-page validation. `cs-e2e` also exercises installed Homebrew,
python.org and selected Xcode framework Pythons: a real bridge without an access
review, then a virtual environment across a fake csecd restart, including output
redaction. `CSEC_E2E_FRAMEWORK_PYTHON=/path/to/python` adds a specific framework
build; absent installations are skipped. `CSEC_E2E_PYTHON` continues to select
the non-framework runtime for the other restart regressions. Build the Node
client first (`mise exec -- npm run build`) before running `cs-e2e`.

`cs-e2e` has one opt-in scenario, `claude-delegation`, that drives a real Claude
Code through csec's hook, the registration and a delegated release. It runs
only with `CSEC_E2E_CLAUDE=1`, after the whole ordinary suite, makes model
calls (allow ten to fifteen extra minutes), and uses a synthetic reference and
value only. `CSEC_E2E_CLAUDE_PATH` chooses the binary (default
`~/.local/bin/claude`); it must be an Anthropic-signed build, because the
scenario trusts no cdhash. From the repo root, preferably in a normal terminal:

```sh
swift build --package-path agent -Xswiftc -warnings-as-errors
npm run build   # once per worktree: the automation checks need clients/node/dist
CSEC_E2E_CLAUDE=1 agent/.build/debug/cs-e2e
```

The scenario reaches its own in-process csecd, not the installed one: the hook
is this build's `csec` by absolute, resolved path, and the build directory
leads the session's `PATH`, so the bare `csec ai` the hook writes is the debug
build too (only a debug `csec` honours `CSEC_SOCKET`). Claude Code runs with a
scratch `CLAUDE_CONFIG_DIR` whose settings set `classifyAllShell`, default to
auto mode and accept the auto-mode opt-in, and whose `.claude.json` has
onboarding done and the project trusted. An empty
`CLAUDE_SECURESTORAGE_CONFIG_DIR` makes it use your own login (the default
`Claude Code-credentials` Keychain entry), so macOS may ask once to let
`claude` read it. The session's environment withholds the G5 names, a
code-loading `NODE_OPTIONS`, every `CLAUDE*` variable except
`CLAUDE_CODE_OAUTH_TOKEN` (so `CLAUDECODE`, `CLAUDE_CODE_ENTRYPOINT` and
`CLAUDE_PID` never mark it as nested, and it can run inside a Claude Code
session), and `ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` (an interactive
session would ask whether to use the key, with No focused). Every reason is
read from that csecd's decision log:

- `claude -p` must register and send its request through the debug `csec`,
  and declines as `not_interactive`.
- An interactive `claude --permission-mode auto` in a pty (up to 90 s to show
  "auto mode on") is released with no panel: a `delegated_release`, decider
  `delegated`.
- After Shift+Tab to default mode (which Claude Code shows as "manual mode"),
  Claude Code's own "Do you want to proceed?" (awaited up to 180 s) is
  answered Yes, and the command declines as `not_auto_mode` with "Claude Code
  was in manual mode.".

A passing run prints three `ok` lines under `# claude-delegation (opt-in)`. A
step that cannot start fails at once and prints what `claude` printed, or the
end of the session's screen; any failed check lists the declines recorded.

Run it after a Claude Code upgrade too: csecd binds a command only to a
registration that arrived before the command started, so a release that started
its Bash shells before running the hook would make every command decline as not
registered, and this check is what would show it.

The scenario drives Bash only. A Monitor command, which the hook wraps the same
way (matcher `Bash|Monitor`), is checked by hand in a Claude Code session after
`csec setup` has moved the installed hook to that matcher: a Monitor running
`p=$$; for i in 1 2 3; do ps -o pid=,args= -p $p; p=$(ps -o ppid= -p $p | tr
-d ' '); done` must show `csec ai -- …` under the `zsh -c … eval` tool shell,
and one running `ssh <approved host> true` must sign with no panel. After a
Claude Code upgrade, also check with `ps -ww` that a Monitor's shell is still
the Bash tool shell's `zsh -c source <snapshot> … && eval '<cmd>'`, which
csecd's chain walk and the unwrapped-git anchor both read.

Each suite behind grant persistence, the decision log and delegated approvals
runs alone with its own `cs-selftest` flag: `--protected-stores-only` (the
protected Keychain stores' queries, bounds, fail-safe decoding, write ordering
and uninstalled state, over in-memory and recording backends),
`--decision-log-only` (round trips, every tamper case, torn tails, caps, planted
and immovable files, the SIGTERM flush and uninstall), `--grant-persistence-only`,
`--restore-panel-only`, `--sealed-baseline-only`, `--claude-session-facts-only`
(the kernel-fact shims against real processes under a pty),
`--code-verdicts-only` (the per-cdhash code-signature verdict cache behind
every socket peer check: its key fields and bound, what may be filed, and,
against real `/bin/sleep`, `/bin/bash` and `/usr/bin/ssh` processes, that a
second process of a binary skips the static check while a token from an
exited or exec'd process never gets the cached verdict),
`--secret-free-only` (the classifier corpus, its two runs under the real
`/bin/zsh -lc` — clean startup files and a hostile `.zshenv` — the
real-tool check, the `av` subcommand rules, and, when `bd` is installed (`CSEC_SELFTEST_BD`, else the
first on `PATH`), bd's global options against its own parser),
`--delegation-protocol-only` (the wire types, hook
registration, the Monitor tool's rewrite and registration, and typed ids),
`--claude-delegation-only`,
`--delegation-setup-only` (the settings gate, setup step 3c, the status rows and
the typed-id CLI), and `--hook-wrapper-only` (the hook's `/bin/sh` wrapper run
as both clients run it: a launcher that stays missing is denied after the 5 s
wait, one an install puts back or the shell could not exec is retried, one that
refuses is not). With `CSEC_SELFTEST_LIVE_CLAUDE=1`,
`--claude-session-facts-only` also checks the pinned Anthropic requirement
against the installed `claude`, every build under `~/.local/share/claude/versions`
and every live Claude Code session on the Mac; it is never part of `bin/ci`.
`cs-selftest --claude-settings-gate-timing [dir] [home]` is a read-only probe,
not a suite: it evaluates the settings gate against a real Claude Code home and
prints its cold and warm cost, and runs in release builds too, which is what
csecd ships. `cs-selftest --claude-gateway-sign-in-timing` is its stored-sign-in
twin: it lists this Mac's Keychain by attribute, reads Claude Code's
credential records as csecd does (no prompt: they trust `security`), and
prints only the finding, the item counts and the cold and warm times
(one Mac, 8 Nov 2026: 31 items, 4 Claude Code records, 46 ms to list, a
443 ms cold check and a 0.6 ms warm median).

Claude release compatibility is an exact-image gate shared by secret, SSH and
sudo delegation. Its wire/status bounds and older-status decoding run in
`--delegation-protocol-only`; identity and all three callers run in
`--claude-delegation-only`, including an image admitted by the signed
manifest's `claude_code` list; native, mise, Homebrew and npm discovery runs in
`--delegation-setup-only`; the manifest section and its merge with the
compiled catalog run in `--release-manifest-only`, and
`bin/test-release-manifest.py` covers `bin/release-manifest.py claude`.
`bin/test-check-claude-release.py` verifies quiet, unknown, update,
deduplication and recovery behavior for the read-only release watch, and runs
in `bin/ci`. The [release-verification checklist](claude-release-verification.md)
defines the automatic session's source audit, gates and installed recovery
evidence; a passing fixture or signature alone cannot extend the catalog.
The [2.1.310 audit](claude-release-audits/2.1.310.md) traces the moved loaders,
standalone-proxy URL companion, expanded sealed middleware and compiled-off
HTTP plugin launch with 30 isolated source probes. Exact/neighbor admission
and independent relay, body-override, generated-policy and synced-hook controls
run on secret, SSH and sudo in `--claude-delegation-only`.
The [2.1.301 audit](claude-release-audits/2.1.301.md) identifies mise's `2`
image as the exact older release and checks its inactive model selectors with
26 isolated source probes. Exact/neighboring identities and independent relay,
body-override, generated-policy and synced-hook controls run on secret, SSH
and sudo in `--claude-delegation-only`.
The [2.1.305 audit](claude-release-audits/2.1.305.md) checks plugin containment,
mounted-plugin restrictions and the new classifier context selectors with
28 isolated source probes. Its exact/neighboring-image cases and independent
relay, body-override, generated-policy and synced-hook controls run on secret,
SSH and sudo in `--claude-delegation-only`.
The [2.1.302 audit](claude-release-audits/2.1.302.md) checks the newly active
client classifier model selector and the independent standalone relay.
Setup fixtures cover its selector across settings/global/inline env;
delegation checks cover exact/neighboring identity and ordinary secret, SSH
and sudo fallback even without `CLAUDE_CODE_REMOTE`.
The [2.1.278 audit](claude-release-audits/2.1.278.md) records the older mise
image's complete source trace and 16 isolated probes. Its exact-hash admission,
neighboring-hash refusal, remote selector, synced hooks and generated-policy
fallbacks run across secret, SSH and sudo in `--claude-delegation-only`.
The [2.1.282 audit](claude-release-audits/2.1.282.md) adds the disk-backed
synced account skill source: setup fixtures cover every account bucket,
changed hook acknowledgements and unreadable/oversized sources; delegation
checks cover the ordinary secret, SSH and sudo fallback for these hooks.
The [2.1.267 audit](claude-release-audits/2.1.267.md) records byte offsets and
isolated source probes. Its setup regressions cover generated policy,
marketplace alias/rename precedence and root skill fallback; delegation tests
cover the common secret, SSH and sudo refusal, while the real-panel
and signed-phone tests cover their shared settings-unreadable copy.

`cs-selftest`'s live screen-lock check holds whether or not the Mac is
locked: it compares `ScreenLockState.isScreenLocked` with this audit session's
`IOConsoleUsers` entry in the IORegistry, the record CoreGraphics' session
dictionary comes from, so an unattended run on a locked Mac checks the probe
rather than failing on it.

Secure no-root delivery checks exercise session registration over the real
socket, one-prompt descendant reuse, copied/forged/stale ID rejection, and
high-risk fallback to an exact per-command root. AWS checks cover separate
fields and a strict JSON bundle with byte-exact version-1 output. Git checks
cover exact host/repository matching, mismatch-before-resolution, bounded
parsing, response injection rejection, and read-only `store` behavior. The fd
suite covers generic `--fd` plus all four presets, exact bytes, multiple distinct
high-numbered descriptors, no value in initial environment/argv/current
directory, literal argv behavior, output masking, and rejection when an
unrelated same-UID process tries the same `/dev/fd/N` path.

`csec get` compatibility checks use synthetic values through the real launcher
and authenticated socket. They cover a reviewed pipe, command substitution, two
piped sibling gets reusing one live-shell grant, rejection/review in a different
shell, and refusal after the parent exits, reparents, or changes executable.
Terminal, pipe, and regular-file approvals are exercised as distinct shapes.
Regular-file denial occurs before provider resolution and leaves no plaintext;
explicit approval writes the exact synthetic value. A terminal or file shape
without `--reveal` / `--allow-plaintext-file`, and a non-interactive capture
without `--reveal`, is refused before resolution, and each remains usable once
acknowledged and approved. Malformed
requester/recipient metadata fails closed, and warnings, errors, protocol
metadata, and captured review state are checked for absence of synthetic values
and sensitive target filenames.

Secure regular-file checks use only synthetic payloads and an explicitly
unprivileged fake root daemon. Core checks cover plan canonicalization/tamper,
outer/nested request binding, path/environment rejection, bounded raw and
GitHub rendering, descriptor framing, kernel GID/process enumeration, boot-
scoped allocator inputs, descriptor-relative creation, exact modes/content,
symlink/traversal rejection, partial cleanup, and restart recovery. End-to-end
checks cover authenticated health, fresh consent/resolution per launch,
`stat`/open/reopen/seek/`mmap`, fork/exec reopen, output masking, protected
`GH_CONFIG_DIR`, ambient GitHub authority rejection before resolution, and
session cleanup. The release build is also checked to keep the root executable
free of AppKit, LocalAuthentication, ServiceManagement, Keychain/provider, and
agent-policy link/symbol dependencies. These checks do not exercise root or a
real tmpfs; the separate matrix below remains mandatory.


## The 1Password bridge is Go

`bridge/` builds `csec-op-bridge`, which holds one authorized 1Password SDK
session per account. It needs a **native** Go toolchain with CGO: the SDK
reaches the desktop app through 1Password's own dylib, which ships arm64-only,
so a Rosetta toolchain produces a binary that cannot load it. `bin/ci` and
`packaging/bin/build-bridge.sh` both refuse to proceed on a mismatch.

    mise install go@1.24
    cd bridge && CGO_ENABLED=1 go test ./...

Its tests are ordinary `go test`. Two of them verify the pinned 1Password
library really is signed by AgileBits and that a tampered or foreign-signed copy
is rejected — the check that stands in for the library validation this binary
disables. They skip when 1Password is not installed.

## Diagnosing slow or stuck process launches

The host-audit runner starts its 25-second deadline before executable lookup
and launch. A timeout returns an explicit unavailable result, discards partial
output, and kills the owned process group. Output is bounded while reading;
stdin is streamed without blocking the deadline. Child reaping never blocks the
caller. The shared pool allows at most 16 outstanding commands, and a worker
stuck inside macOS or a child still awaiting reaping retains its slot, so retries
cannot create an unlimited launch backlog.
Audit children start suspended; if a delayed spawn finally returns after its
deadline, the child is killed without being resumed.

Gatekeeper assessments use at most two slots across production audit runners,
stop submitting work after a timeout/tool error or a 60-second submission window,
and report incomplete coverage as unknown unless a real denial was observed.
Already submitted commands retain their own deadline. Background audit ticks
do not overlap. These bounds contain csec's load; they do not establish the
cause of the September 2026 system-wide launch hang.

Early slow-command notices and timeout/failure notices are persisted in the
unified log. They contain static operation labels, phases and elapsed seconds,
never command arguments, environment, stdin/stdout/stderr, or app paths. PAM
adds fixed launch/signature-check/running/cleanup stage labels (the whole sudo
trail is in [Diagnosing a sudo review](#diagnosing-a-sudo-review)). These examples
name `/usr/bin/log`, because in zsh, the shell `csec ai` runs agent commands in,
`log` is a builtin that rejects these arguments (`zsh:log:1: too many arguments`):

```sh
/usr/bin/log show --last 30m --style compact \
  --predicate 'subsystem == "com.alexspeller.convenient-security" AND category == "process-liveness"'
```

If new fish sessions and unrelated apps both stall, stop repeated launch/build
attempts and capture this log plus `syspolicyd`/`amfid` system logs while commands
still work. Preserve default privacy redaction. A service restart requires
explicit approval and working administrator authentication. If sudo and native
administrator authentication both hang, save work and restart through the Apple
menu; another privileged recovery command may also be unable to start.

The PAM module gives killed children at most 100 ms to become reapable before
returning to the existing authentication path. It does not leave a detached
thread running code from a module that PAM could unload. Native macOS spawn,
signature-validation and authorization calls, and sudo's own startup, cannot
be made interruptible by this cleanup deadline. Stage logs distinguish those
cases. An unreaped killed child remains owned by sudo until sudo exits.

Run the hermetic failure-path tests with `cs-selftest --process-reliability-only`
after building. `packaging/bin/build-sudo-pam.sh` also exercises the shipping
cleanup against a synthetic unreapable child, interrupted waits and clock failure.
`bin/ci` runs both through the normal acceptance gate.

## Diagnosing a sudo review

A sudo that went somewhere unexpected — Apple's prompt instead of the csec
panel, no panel at all, a panel that closed on its own — leaves a trail in the
unified log. The PAM module writes one line per stage from the `sudo` process
(category `process-liveness`, every line starting `sudo stage=`), and the
review helper writes its own from `csec-sudo-review` (category `sudo-review`).
Both are written at the default/notice level, which macOS persists:

```sh
/usr/bin/log show --last 30m --style compact --predicate \
  'subsystem == "com.alexspeller.convenient-security" AND ((process == "sudo" AND category == "process-liveness") OR (process == "csec-sudo-review" AND category == "sudo-review"))'
```

The module records each stage and why it ended: the redactor launching (with
its pid) and completing, or `event=unavailable reason=<label>` (the launcher
not root-protected, a nonzero `child-exit status=`, a `child-signal`, a
warning on its stderr as `reason=stderr-output`, overflow, malformed output,
timeout); a review `skipped` for askpass or a session without a GUI; the
helper's launch, its signature check (with its pid), `running`, and how it
ended (`helper-exit status=` or `helper-signal signal=`, then `approved`,
`expired`, `interrupted` or `unsuccessful reason=<label>` such as
`helper-unprotected` or `signature-rejected`); and, when the review did not
decide, Apple's fallback prompt and its `osstatus`. The helper records that it
started (with its parent's pid), csecd's delegation decision, Touch ID being
unavailable or cancelled behind the lock screen (with the `LAError` code),
the outcome (`approved` on the `mac` or `phone`, `use-password`,
`denied-on-phone`), a pairing, its parent exiting, the deadline passing, its
exit status, and any refusal before the panel (`rejected reason=`).

Every line is value-free: fixed labels and numbers, never the command, working
directory, terminal, delegation note, a child's stderr or a localized error.
The module keeps the helper's stderr at `/dev/null` and the helper logs for
itself (`SudoReviewLog`): a pipe the root module read would carry unbounded
child text into sudo, and a file root opened in the user's directory would
invite a symlink. Two common trails: a csecd that rejects the redactor's
identity shows `redactor event=unavailable reason=stderr-output`, then
`fallback event=apple-prompt reason=redactor-unavailable`; a sudo that Claude
Code auto mode approved shows `delegation decision=approved` and `exit
status=0` with no panel. `install-sudo-review.sh`'s live check decides from
these lines: it keeps an installation only when its own verification sudo's
module trail (by that sudo's PID) ends `helper-exit status=0`, `approved`, and
the helper named by `signature-check-started pid=` logged `started parent=`
that PID, an approval and `exit status=0`. When it fails, it prints the trail
of that sudo and its helpers before restoring.

## Diagnosing 1Password prompts

`bin/test-ai-sandbox.py` also tests the AI-session `op` guard using an executable
fixture and a private fake daemon. It covers direct/absolute calls, shell and
Python subprocesses, login startup that resets PATH and defines `op`, both
`ai` and `tool-exec`, the legacy encoded form, daemon-unavailable fallback,
ordinary command status and temporary-shim cleanup, and the bundle's shipped
shim in a sandbox that denies every write (refused instead when that shim is
tampered with and no temporary one can be made). No real `op` or provider
runs. Build the debug targets, then run:

    mise exec -- python3 bin/test-ai-sandbox.py

The broken-transport case allows 30 s for the client to connect, verify the
Python listener's code identity and send request bytes, within a 45 s command
limit. Fixture failures propagate to the test, and it requires both received
request bytes and the mid-request transport warning before accepting fallback.

csecd's stderr is discarded by launchd, so its 1Password diagnostics go to the
unified log under subsystem `com.alexspeller.convenient-security`, category
`onepassword`. Every line is value-free metadata and is written at `notice`,
the lowest level macOS persists, so it can be read after the fact:

    /usr/bin/log show --last 2h --style compact \
      --predicate 'subsystem == "com.alexspeller.convenient-security" AND category == "onepassword"'

What it records: which account each reference resolved from; when a bridge
process was created, started (with its pid), or exited (with its status and any
requests it stranded); every keepalive ping with its duration, and why a tick
did *not* ping (screen locked, activity lease expired, no bridge yet); and
every line the bridge wrote to its own stderr, prefixed `bridge[<account>]:`,
read to its EOF even after csecd has shut the bridge down.

Any process that can run `log show` reads this log, and every sysdiagnose
copies it, so it names references and accounts by tags, `ref#3` and
`account#1`, numbered by first use in that csecd process. The first line about
each tag pairs it with its text (`ref#3 is <private>`). References, vault
names, account labels, a failure's reason (its kind, such as
`OnePasswordError.vaultAmbiguous`, stays readable), any untrusted text the
bridge writes and the account UUID in its own lines are logged private, which
macOS shows as `<private>` unless private data logging was turned on for the
Mac. `bin/ci` holds every `.public` field in the adapter to a list, and
`cs-selftest --onepassword-log-privacy-only` reads the unified log back. A bridge's exit line
always follows its last stderr line: csecd handles the exit only once both of
the bridge's pipes are drained (or 5 s after the exit, if something else holds
them open). The bridge reports each request's outcome and duration, and flags any request
slower than a warm session, because the 1Password SDK re-creates its client —
a fresh authorization, so a Touch ID prompt — silently inside the call when the
desktop session has expired. csecd cannot see that happen; the timing is the
tell.

1Password's own log is the other half of the picture:

    ~/Library/Group Containers/2BUA8C4S2C.com.1password/Library/Application Support/1Password/Data/logs/1Password_rCURRENT.log

`Will validate remote process` is a client (CLI or SDK) connecting, `System
unlock proceeding with MemoryEnclave backend` is one Touch ID authorization,
and `Locked. Reason: Automatic(DeviceLocked)` is the app locking with the
screen, which revokes every authorization. Note that `op` CLI invocations from
other processes prompt independently of csecd and look similar in this log.

## Toolchain baseline

The last verified physical-machine baseline (2026-08-21) is below. It predates
macOS 27, which CI now builds on (the hosted `xcode-27` image and the
self-hosted runner alike), so it is not the release baseline: the signed
root-helper matrix
([`regular-file-security-matrix.md`](regular-file-security-matrix.md)) records
the macOS build, hardware and toolchain it runs on, and that record replaces
this one.

- macOS 26.2 (25C56), arm64;
- Apple Swift 6.2.4 / swiftlang 6.2.4.1.4 / clang 1700.6.4.2; and
- system Ruby 2.6.10 (the gem supports Ruby 3.0 and later for distribution;
  this older system runtime remains a useful compatibility test while present).

The Node.js client was additionally verified on 2026-08-25 with Node.js
24.11.1/npm 11.6.2 and Node.js 22.22.0. The npm package requires Node.js 22 or
later.

On that baseline, the Developer-ID-signed native-store spike passed its
signed-but-unentitled helper exclusion, non-interactive unauthenticated-read
rejection, one-touch context fold, and authenticated `.biometryAny` record
read/update checks.

SwiftPM invokes Apple's own sandbox. In an already sandboxed automation host,
the build may need to run outside that outer restriction; a failure containing
`sandbox_apply: Operation not permitted` is an execution-environment problem,
not a compiler failure.

## GitHub CI

`.github/workflows/ci.yml` runs on every push to `main`, every pull request, and
on demand (`workflow_dispatch`, or `gh workflow run CI --ref main`). Re-running
an old run replays its original event, including whether the repository was
private then, so after a change of visibility start a new run instead.
In a public repository both jobs run on GitHub-hosted macOS (the `xcode-27`
image), which is free there. In a private one they run on the repository's
own self-hosted Mac (labels `self-hosted`, `macOS`, `ARM64`), because GitHub
bills a private repository's hosted macOS minutes at ten times Linux's. Its
jobs provision Node.js 24 and 22 with setup-node rather than relying on the
runner's ambient Node installation. CI is synthetic and ad-hoc signed.
Developer-ID identity, hardened-runtime/provisioning, Touch ID, cold/warm
cache behavior, and native-store Keychain behavior remain a separate
physical-machine release gate.

- **One run per ref.** The workflow's concurrency group (`ci-<ref>`) leaves at
  most one running and one pending run per branch or pull request, because
  each full run holds its runner for about an hour. A newer push cancels the
  older pending run, whose commit the newer tree covers. On a pull request it
  also cancels the running one; on `main` the running run finishes, so `main`
  always ends with a complete result. A `main` run cancelled before it started
  was superseded, not failed: check the newest run instead.
- **Hosted tools.** A hosted VM gets the bridge's Go from `bridge/go.mod`
  (setup-go), mise's release binary checked against its published SHA-256,
  which installs the XcodeGen pinned in `.tool-versions`, and ripgrep. The
  UI tests use the built-in simulator lifetime adapter: nothing else runs on
  the VM.
- **Self-hosted runners run with their Mac's tools and sign-ins.** A pull
  request runs its own copy of the workflow, so no condition in it can keep a
  fork's code off a self-hosted runner: never register one on a public
  repository. A private repository's runs skip Dependabot's pull requests,
  whose third-party releases nobody has run yet, and keep fork pull request
  workflows off in its Actions settings. Such a Mac needs ripgrep, a native
  Go, mise, Xcode with an iOS Simulator runtime and, when its sessions share
  the simulators, the admission gate above, configured in the runner user's
  `git config --global csec.simulatorRun`; the Build and test step bounds the
  wait for it at 30 minutes (`CSEC_CI_SIMULATOR_WAIT_S`), so a loaded Mac
  ends the run with "iPhone UI tests did not run" instead of a timeout. The
  steps are bash, which never reads `~/.zshenv`, so the workflow exports the
  selected Xcode's `SDKROOT` itself: where the Command Line Tools are newer
  than Xcode, their default SDK breaks cgo and SwiftPM.

## Release-only checks

Before treating an artifact as protected, verify on the signed installed app:

1. `csecd` and `csec` satisfy their exact Team ID and signing identifiers;
2. a socket-replacement process is rejected before it receives references;
3. a non-product client is rejected before the agent decodes a request;
4. former environment controls cannot change consent, endpoint, or provider;
5. hardened runtime and required entitlements are present, and SIP is enabled;
6. a new reference uses one trusted policy window whose embedded real Touch ID
   is active as soon as the window is visible, without an Enter/click gate or a
   second csec authentication sheet; and
7. one touch permits a cold cache read, followed by a warm read with no second
   biometric prompt;
8. terminal, piped, command-substitution, and ordinary-file `csec get` show the
   live direct-parent shell as requester/grant owner and signed `csec` as
   emitter; pipe review identifies an unverified reader; two compatible piped
   siblings reuse one exact grant while another shell cannot; replaced, exited,
   or reparented parents fail before output; terminal, pipe, and file approvals
   do not cross-authorize; file denial precedes provider resolution and writes
   no plaintext; a terminal or file shape without `--reveal` /
   `--allow-plaintext-file`, or a non-interactive capture without `--reveal`, is
   refused before resolution; and no value or target filename enters warnings,
   errors, logs, or protocol metadata;
9. the native-store spike proves a signed-but-unentitled same-UID helper cannot
   query the provisioned access-group item, nor read, update, delete or add
   items shaped like csecd's protected stores, and that the `.biometryAny`,
   `WhenUnlockedThisDeviceOnly` record cannot be read without an authorized
   context, then can be loaded and atomically updated with the just-evaluated
   Touch ID context (for the protected stores alone, build with
   `RUN_SPIKE=0 packaging/bin/build-spike.sh` and run
   `packaging/build/KeychainSpike.app/Contents/MacOS/unentitled-keychain-probe`:
   every attempt, for each of the eight protected items, must print `refused`,
   the explicit-group ones with `OSStatus -34018`, and the probe exits 0);
10. `csec edit` creates only ciphertext under the documented directory, a cold
   daemon requires Touch ID, a warm granted read does not reprompt, and
   ciphertext modification plus replay of an older version both fail closed;
11. built-in editing and cancelling a synthetic store leaves no named plaintext,
    editor swap, backup, or autosave file; external `--editor` mode shows its
    plaintext warning before Touch ID, uses `0700`/`0600` workspace objects, and
    removes that exact workspace after success, invalid input, and editor failure
    (without claiming crash cleanup, secure erasure, or removal of copies);
12. the signed/notarized package installs the bridge at
   `/Library/Application Support/ConvenientSecurity/bin/csec` with every path
   component root-owned and non-user-writable, and both Ruby and Node.js reach
   the installed agent through it; and
13. provisioning consumes the real App Store Connect key through `/dev/fd/3`;
   notarization uses only a short-lived `0600` key file beneath an atomically
   created `0700` directory because `notarytool --key` requires a filesystem
   path; both leave no private-key environment entry, notarization removes its
   exact temporary path after success, ordinary failure, and handled signals,
   and the pipeline fails on a deliberately invalid signature/ticket check
   (without claiming cleanup after `SIGKILL`, process crash, or machine loss);
   and
14. interactive `csec exec` preserves input, terminal resize, Ctrl-C/Ctrl-Z,
    colors, and the target's exit status while replacing a synthetic output
    marker on both stdout and stderr; and
15. before enabling generated AI hooks globally, the installed Claude Code and
    Codex versions preserve normal allow/ask/deny and OS-sandbox behavior, run
    representative multiline Rails/Node/test shell programs correctly, block
    when the adapter exits 2, and return no raw synthetic value for the
    RuboCop/`pgrep` regression; and
16. a signed `csec session` gives its descendant helpers one grant that lasts
    as long as the registered session, and a copied session ID outside the
    registered subtree fails; and
17. real AWS `credential_process` and Git helper invocations receive their exact
    synthetic protocol response through a private pipe, reject a mismatched
    Git host/path without resolution, and create no credential cache or file;
    and the synthetic AWS migration checks cover explicit paths outside cwd,
    bulk setup, config preservation, interrupted/repeated migration, conflicts,
    hardlink/symlink refusal, and failures before plaintext cleanup; and
18. installed supported versions of libpq, kubectl, the AWS SDK/CLI, and Google
    authentication tooling each consume their preset once through `/dev/fd/N`,
    while a concurrent same-UID process cannot read that descriptor and no
    plaintext named file, argv, or initial-environment value is created; and
19. every signed/root row in
    [`regular-file-security-matrix.md`](regular-file-security-matrix.md) passes
    with synthetic data, including exact installed identities, verified tmpfs
    flags/caps and modes, unrelated same-UID denial, GID lifecycle/collision
    checks, daemonized descendants, launcher death, soft/hard TTL, cancellation,
    restart recovery, GUI/headless audit-session behavior, and real consumer
    compatibility; and
20. `csec setup` against fresh and existing user configurations produces the
    reviewed dry-run plan, preserves unrelated settings, appears in each
    client's effective hook/trust UI, and blocks a synthetic Bash call when
    installed `csec` or `csecd` is unavailable; a selected synthetic dotenv
    import requires Touch ID, changes only its named native-store key, emits no
    value, and leaves the source unchanged for separate remediation. Multi-account
    1Password is verified with at least two accounts signed in: `csec status`
    reports the authorized account and indexed vault counts, a reference into a
    non-default account's vault resolves, the review window names the account it
    will read from, and `csec edit op://…` edits the existing item rather than
    creating a duplicate in another account. Run `cs-selftest` once with
    `CSEC_OP_LIVE_ACCOUNTS=1` on such a machine; it is off by default so a
    locked 1Password app cannot block `bin/ci`. Prompt behaviour is verified
    separately, because it is the property most easily regressed: with csecd
    running and 1Password's app unlocked, lock the screen for longer than the
    keepalive interval and confirm **no** Touch ID prompt appears on return,
    then resolve one reference and confirm exactly one prompt appears. The
    1Password app's own log (`~/Library/Group Containers/2BUA8C4S2C.com.1password/
    Library/Application Support/1Password/Data/logs/1Password_rCURRENT.log`) is
    the ground truth: `System unlock proceeding` marks each authorization, and
    `AppCancel invoked by a timed-out prompt` marks one nobody answered. Neither
    should appear while the Mac sits locked.
