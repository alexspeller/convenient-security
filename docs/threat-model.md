# Threat model

Scope: a non-root process attacking another process of the same login UID on
Apple Silicon macOS with SIP enabled. Root, the Apple platform, a holder of the
Stateful Ltd signing identity, code already executing inside an authorized
consumer, and a user who approves a misleading request are outside the claimed
boundary.

## Same-UID attacker capabilities

- **Initial environment and argv are readable.** `KERN_PROCARGS2`, `ps`, and
  related tools can copy the target's original exec stack. Calling `unsetenv()`
  does not scrub that copy. Ruby process-title rewriting can also make tools such
  as `pgrep -fl` display environment bytes as if they were arguments; the test
  suite reproduces this with synthetic data.
- **Ordinary user files are readable.** A mode-`0600` file prevents other UIDs
  from reading it but is not a boundary against the owner UID. Dotfiles and a
  non-sandboxed application's normal Application Support directory receive no
  special same-user confidentiality from TCC or SIP.
- **A Unix-socket pathname is replaceable.** A `0700` parent blocks other UIDs,
  not another process running as the owner. Socket path ownership is therefore
  not peer authentication.
- **A clean process heap is not ordinarily readable.** On the supported hardened
  configuration, an unrelated, non-entitled same-UID process cannot obtain the
  task port needed to read another process's memory. Debuggable builds carrying
  `get-task-allow` do not satisfy this claim.
- **Ambient authority can be used without extracting bytes.** Malware may invoke
  a genuine already-authenticated tool or communicate with an accessible local
  agent. Keeping a token out of the environment does not by itself prevent use
  of the authority represented by that token.

## Implemented protections

### Peer authentication

Release `csec` and `csecd` mutually verify the complete kernel
`LOCAL_PEERTOKEN`, live Security.framework code identity, Team ID, exact signing
identifier, hardened runtime, entitlement posture, and login UID before
exchanging JSON. The daemon repeats the check immediately before every
response. Tests show that an unsigned replacement server receives no reference
metadata and an unsigned client does not reach the request handler.

The check has a dynamic half and a static half, and csecd (and the root
helper) run the static half once per binary. Per connection, and again before
every response, the kernel is asked about the exact image the audit token
names (`csops_audittoken`, which refuses a token from before an exec): it must
still be `CS_VALID`, and its cdhash, signing identifier, Team ID and path
select a verdict. The static half, the CMS signature, its certificate chain
and the Developer ID (or Apple) requirement, is what waits on trustd, which
under heavy load took seconds per connection, long enough for `csec hook
claude`'s one-second registration to give up. It is evaluated by
Security.framework the first time a cdhash connects, and a success is kept for
the daemon's lifetime (`CodeSignatureVerdictCache`); a failure is never kept.
Because the cdhash seals the code, entitlements, flags, identifier and Team ID,
a cached verdict only ever answers for an image running exactly the code
directory that was verified. The cdhash does not cover the signature envelope
itself or a bundle's resources, so the executable path is part of the key too:
verified code copied anywhere else, re-signed or not, is verified afresh, and
the product's own installed paths are root-owned. Nor is the file on disk
re-read for a verified cdhash: a process whose executable was replaced after
it started keeps the verdict of the code it is running, until the restart
that comes with every install.

**Revocation trade-off.** A cached verdict outlives a revocation of the
signing certificate until csecd restarts; every install restarts it. No
requested online check is given up: the check validates with
`kSecCSStrictValidate` alone, so Security.framework adds no revocation policy,
and trustd answers from its local Valid database and OCSP cache, fetching OCSP
itself only when that database flags the certificate as revoked or not
definitively covered. For csec's own Developer ID chain the trust result
reports no revocation check at all (no `TrustRevocationChecked`, which
`kSecCSEnforceRevocationChecks` does produce). A binary csecd has not verified,
such as one signed with a stolen and since-revoked key, has its own cdhash and
gets the full check. What is given up is noticing a revocation of a binary
csecd had already accepted before the revocation reached this Mac.

### Process-scoped consent

New references require Touch ID — a touch on the sensor while that review is on
screen, never one macOS already has. Every approval panel (secret access, SSH
signing, sudo) builds its `LAContext` with
`touchIDAuthenticationAllowableReuseDuration` at zero, so a prompt raised
shortly after the Mac is unlocked by biometry cannot be satisfied by that
lock-screen match: a review nobody answered would authorize a request nobody
read. The grant root is verified from kernel process
ancestry and bound to its start time. Existing compatible grants cover only the
recorded references and process subtree for as long as the grant lasts; a job
the subtree detached still counts as inside it while its session proves so (see
[Detached jobs](#detached-jobs)). csecd
also persists the grant table, value-free, so that a restart does not re-ask
(see [Persisted grants, pairings and settings](#persisted-grants-pairings-and-settings)).
With delegated approvals on, Claude Code's auto-mode classifier may stand in
for the touch for references a human already paired with the project (see
[Delegated approval](#delegated-approval)).

This limits which values the agent releases; it does not make every descendant
trustworthy. A process deliberately launched inside an approved subtree is part
of the authorized consumer boundary.

`csec automation` is the explicit exception to grants bound to a live,
human-approved process tree. One local attended enrollment stores device-only
copies of the values of exact canonical refs and permits the signed runner's
exact direct interpreter child to use them until revoke, with a bounded lease
for each run. A csecd restart restores a lease whose launcher incarnation is
still alive and whose job still has that revision, from a csecd-only protected
item. Framework Python jobs pin the launcher and the `Python.app` consumer
separately, including both cdhashes, and validate their framework layout.
Their explicitly unverified interpreter inspection validates the executable's
signature and code pages separately from mutable app resources (Homebrew may
omit the resource seal); ordinary executable inspection retains full bundle
validation. Re-exec does not relax the direct-child or PID/start-time checks. A restore
never brings a lease back live across a reboot, for an exited launcher, or
for a revoked or re-enrolled job (those come back as value-free tombstones or
not at all), so a restore cannot release more than the live
launcher already held. The script,
dependencies, ordinary inputs, and sanitized trigger environment are deliberately
not integrity-bound. Same-UID code that can modify them can obtain all refs in
that job; any same-UID process can also invoke the registered runner and choose
its remaining ordinary environment. Users who cannot accept that boundary must
not enroll it. Ordinary access stays bound to a live process tree and is
unchanged. See [`automation.md`](automation.md).

macOS attributes privacy access made by a supervised descendant to the signed
`csec` launcher. The release launcher therefore carries the Calendar hardened-
runtime entitlement needed by EventKit-backed Calendar and Reminders tools. A
separate user-granted TCC decision is still required, but once granted it is an
OS-level permission for csec's responsible-process identity rather than a
per-job capability. Automation enrollment constrains secret references, command
identity, overlap, interval, and runtime; it cannot subdivide that TCC grant.

`csec session` makes a wider boundary explicit for callers that want one without
the review window choosing it. The daemon records the
signed launcher's kernel PID, process start time, and audit session before the
launcher becomes the requested shell or command. Its inherited random ID is
non-secret and does not authorize anything by possession: each use must come
from the authenticated signed helper and pass a fresh lineage walk (kernel
parents, plus [Detached jobs](#detached-jobs)) to that exact live process
incarnation. Copying the ID to a sibling, racing PID reuse,
or inventing an ID fails closed. A grant may span descendants of the approved
root, bounded by its reuse digest and a fresh ancestry walk to that exact live
root incarnation.

### Detached jobs

A job a coding agent's tool shell detached (`( job & )`, `nohup job &`,
`disown`) is re-parented to launchd when the process that forked it exits, so a
kernel-parent walk no longer reaches the agent. csecd links it back through its
session (DESIGN.md §Detached jobs): session membership is inherited only through
fork and cannot be joined, so a member descends from the session's leader; a
session's ID is not handed out again while the session has a member; and a
dead session's ID can come back only after about `99,900 − 3 × kern.maxproc`
pid allocations, which the kernel's per-allocation unique process ID measures.
csecd trusts that link only while the session's leader runs, or, for a session
it recorded while the leader ran (a csec client inside it asked for the schemes
or for access; `csec ai` does before every command), while the leader's parent
is still the same process and for a job forked within half that margin of the
leader.

What this changes: before, anything a tool call left running lost the agent's
grants when the tool call ended, and its next request raised a panel. Now a job
that stays in the tool shell's session keeps them for as long as the agent's
process lives. That includes a trojaned dependency that backgrounds itself with
`( … & )` or `nohup` during a tool call and asks later, for a reference or an
SSH signature the human already approved for that agent session. It gets
nothing the agent session could not already get while the tool call ran, and
nothing once the agent exits. A job that leaves its session (`setsid`, the
`daemon(3)` idiom most daemonizers use) or was forked beyond the margin is
unlinked and reviewed as before, as is every job after a csecd restart, because
the session records are held in memory only. Delegated approval never follows
the link: it needs a live chain to the Claude process.

The same holds for a terminal whose shell leads its own session and runs as the
user (a tmux pane, VS Code's terminal): a job detached from that shell stays in
its terminal-session grants while the shell runs. iTerm2 and Terminal.app
sessions are led by root's `login`, whose facts csec cannot read, so theirs stay
unlinked.

Residuals:
- The margin assumes `kern.maxproc` has not been lowered since the leader was
  forked; only root can change it, and root is outside this model. A value that
  leaves no margin (above 33,299) turns the link off.
- csecd keeps at most 4,096 session records, least recently used first out. A
  same-user process can run csec from thousands of fresh sessions to push a
  record out; the job it belonged to is then unlinked and asks again, which
  fails closed.
- Like the kernel-parent walk, the link assumes no debugger re-parents a process
  (ptrace attach, or a detach that looks the original parent up by pid), and the
  reads of one hop are not bound to the next. A detached hop adds a few reads to
  that window.

### Release authorization and stale authorization

Before it consults a plaintext cache or provider, the daemon evaluates the
complete delivery plan: the grant lifetime (by default the lifetime of the
process/session it is granted to, with no wall-clock cap — `--for` sets an
explicit, uncapped bound and the human may narrow it to a bounded 1h/12h in the
review window), a mechanism-derived output policy, and the one hard `csec get`
plaintext-exposure gate. There is no risk classification and no compatibility
acceptance — the value-free review shows the references, delivery, scope,
destination, and any inspectable-shape warning, and embedded Touch ID starts when
the window becomes visible; a successful biometric is itself the authorization.
The window also names the terminal tab the request came from. Its title is the
tab's self-reported title — any process in that tab can set it with an escape
sequence, so a trojaned tool could pick a reassuring one — which is why the line
pairs it with the terminal application's own window/tab position and the kernel
controlling tty, which that process cannot rewrite. A request with no terminal
above it is labeled as such rather than left blank.

Every grant is bound to a process subtree and to a digest. The root is the one
the human selected in the review window — the requesting process, the nearest
coding agent, or the outermost shell owning a controlling terminal — resolved by
csecd from a live kernel ancestry walk, never proposed by the launcher. A
requesting-process grant is reusable only for an identical delivery-plan digest.
A deliberately widened grant is reusable by any command in that subtree whose
release *shape* matches — mechanism, descendant scope, destination, recipient
assurance, output guard, interactivity, plaintext acknowledgement — and whose
audit session matches the approving one. That is the point of widening: an agent
runs different commands, and binding to one command would make the choice
meaningless. It also means everything in the chosen subtree is inside the trusted
consumer boundary for those references until the grant expires; the narrower
per-command root remains one click away, and `csec revoke` drops a grant early.
A capability-GID launch is the one mechanism that reuses *only* a widened grant:
because it mints a new root of its own, covering it with a requesting-process
grant would let a nested launch outlive the authorization that created it.
A grant ends when its root exits, or at the 1- or 12-hour bound the human chose
(or `--for` set); none has a default clock. Protocol-v1 access is
recognized only to return `upgrade_required`, so an older or hand-written client
cannot omit a plan to select the legacy authorization path.

An inspectable delivery is warn-and-confirm rather than an integrity failure: the
review warns and one Touch ID authorizes it. Authorization still fails closed on
malformed or spoofed metadata, unverifiable/stale/reparented/replaced requesters,
invalid scope, denial, unavailable biometrics, and an unacknowledged raw `csec
get` shape. It cannot turn an approved environment, named-file, raw-output, or authorized-
consumer path into a confidentiality boundary. A Keychain cache item for an
`op://` value is named by the canonical reference and holds the value itself,
readable only through a biometric context; csecd's protected items hold
canonical references and value-free metadata, never a value.

Only a human's Deny — the button, closing the window, the Touch ID sheet's own
Deny, or a verified phone Deny — refuses other requests: the identical ones
already waiting behind that panel, and any further signature for a denied `ssh`
connection. A request that went away, or a Touch ID error, refuses nothing else.
"Already waiting" is judged against the instant the human decided, on a
monotonic clock. A phone Deny is stamped when this Mac receives it, because the
two devices' clocks cannot be compared, so a request made between the tap on
the phone and its arrival (relay latency plus the 750 ms poll) is still
refused.

### Delegated approval

Delegated approvals are off until `csec setup` turns them on under one Touch
ID. With them on, csecd releases references to a `csec ai` command with no panel
when Claude Code's auto-mode classifier approved the command and the kernel and
Claude Code's settings attest that nothing else could have: csec's hook
registered the exact program
from a verified Claude Code process (Anthropic's designated requirement, or a
build the human trusted by cdhash); that process is the foreground job of a
terminal, was started with no headless, bypass, settings or plugin override and
none of the listed code-loading, endpoint or redirect variables, and was in auto
mode; and its settings make the classifier judge every Bash call
(`autoMode.classifyAllShell`) with no other approving hook, and no auto-mode
classifier rules, the human has not acknowledged, no sandbox auto-allow and no
reachable bypass. Every released
reference must also be paired with the session's project — a human approved it
there, on this Mac — and already held by csecd; delegation never unlocks
anything and mints no grant. The mechanism, and the gate names used below (G1
`classifyAllShell`, G2 other hooks, G3 interactive, G4 launch options, G5
environment, G6 other settings), are in
[`DESIGN.md`](../DESIGN.md#delegated-approval).

Pairing is what makes this sound against a malicious repository. A cloned
repository's `.claude/settings.json` `env` block, or a SessionStart hook, is
applied to Claude Code's own environment and so decides which references
`csec ai` asks for, while the classifier never sees which secrets a command
receives. Without pairing, such a repository could name any reference a human
had unlocked elsewhere; with it, only references a human approved for that
project are released there. csecd's own use of a value it never releases
(`daemon_proxy`, the GitHub socket) is the exception: a use paired in any
project covers auto mode in every project (csec-0.46). A repository cannot
choose that reference, because csecd puts the one token its GitHub catalog
names on every request that carries the placeholder, and the classifier still
judges each command that reaches the socket. What is given up is the first
panel in each new project, so code running under a command auto mode approved
there (a trojaned dependency's test hook, say) can make GitHub API requests
with the user's token, as it could already sign with the user's SSH keys
(csec-0.11). It never receives the token, and a request that can give lasting
access (a key, a secret, a webhook, a workflow) is never auto mode's: each gets
its own panel (csec-0.49). Claude Code's own PR lookup, the
`gh pr view [<selector>] [--repo r] --json url` it runs as P's direct child
after a command that mentions a push, and its daily closed-issues check, `gh
issue list -R anthropics/claude-code --author @me --state closed --search
'closed:><date>' --json number,title,closedAt,stateReason --limit 30`, ride the
same use pairing with no classifier judgment (csec-0.47, csec-0.64.10). Each is
admitted only in that exact read-only shape, from an executable named `gh` whose verified parent is a Claude Code
session passing every gate. A `gh` on P's `PATH` replaced by same-user
malware could use that one connection to make other GitHub requests with the
token, which is the same exposure auto mode's `gh` commands already carry. A project is the git repository the session's
directory is in (its shared git directory's path, volume and inode), or that
directory outside a repository. So a new worktree of a paired repository, or
one at another branch, receives what was paired with the repository without a
panel: the exposure is that of switching branches in the paired checkout,
which never changed the project. A clone cannot plant a `.git` pointer (git
refuses to check out a path named `.git`), but a downloaded archive can, so a
`.git` file counts only for a linked worktree the repository lists and whose
back-link names it; any other pointer leaves the directory its own project.
Another user's `.git` (in `/tmp` or `/Users/Shared`) is ignored, as git
ignores it. Same-user code that edits a paired repository's own git directory
to vouch for a new worktree gains no more than starting Claude Code in the
paired checkout would. A repository nested in a paired one is its own project,
and a submodule keeps its own directory's key. The hook gate
(G2) is the other half: any hook's `allow` makes Claude Code skip the
classifier, so every other hook that can approve a Bash call must be
acknowledged by its exact contents. Classifier rules are the same kind of
approver inside the classifier: an `autoMode.allow` or `environment` entry in
user, `--settings` or policy settings is handed to the classifier as what the
user permits ("csec ai commands are pre-authorised"), and a `soft_deny` or
`hard_deny` list without `"$defaults"` deletes its built-in blocks. A trojaned
package that appends one line to `~/.claude/settings.json` would steer every
later verdict, so each source's rules are acknowledged by their exact contents
too, and any edit declines until the human sees what changed and acknowledges
it. csecd shows it unasked: the first secret request that declines only on
changed rules raises one settings panel (while the screen is locked, only
when the paired phone can decide it) listing the added rules and how many are
gone, which every other request declining on the same change waits behind;
one approval, Touch ID on the Mac or Face ID on the paired phone, acknowledges
exactly those rules and the waiting requests go through (Alex, csec-0.64:
before, each request went to its own panel while the change stayed
unacknowledged). The phone's copy is the Mac's signed request, bound to
exactly the sources acknowledged and single-use like every mirrored request,
and only a panel that lists every source whole reaches the phone (nothing
collapsed, no line cut short by the panel or by the settings gate's own
bounds, and no command handler setting left out of its line), so a phone
approval acknowledges nothing the phone did not show; a
hooks module is shown as its entry file's path and digest, which is the file
acknowledged, not the files it imports; pairing that
phone took Touch ID on the Mac and Face ID on the phone, so nothing on the
Mac alone can enrol another approver.
A newly added hook takes the same panel, which names it and shows what each
of its handlers runs (csec-0.64.7); an SSH signing declining on one takes it
too. `csec setup auto-mode` shows the same change. A Deny is kept for that csecd
run, and those requests get their own panels. While delegation waits,
`csec ai` tells the session so, which keeps a stale acknowledgement from
silently turning every request back into a panel nobody explains. A malicious
rule or hook is now on a panel that a request it steers can bring up, but it
is shown in full (a hook's command, more than setup lists), and a panel
approved without reading trusts it exactly as an unread setup run would. `processWrapper` (`CLAUDE_CODE_PROCESS_WRAPPER`) is not
gated: it prefixes only Claude Code's own re-spawns of the claude binary, never
a Bash tool command, and a wrapper is same-user code started by the session,
like the MCP servers in the first item below.

Disk-backed synced skills are another approving-hook source: Claude Code can
load their frontmatter from the user configuration home's
`skills/synced/<account>/<skill>/SKILL.md`. The gate scans every account bucket
within its existing directory and scan limits, without reading login state;
unreadable sources decline. The 2.1.282 disk loader's text sanitizer retains
hooks. Those hooks require the same per-source acknowledgement as ordinary
skills, including for SSH signing. Separate remote/memory skill factories
that erase executable capabilities do not establish that this disk source is
hook-free. See the [2.1.282 audit](claude-release-audits/2.1.282.md).

An acknowledgement is per source path, and extra Claude accounts each have a
`CLAUDE_CONFIG_DIR` that links its settings, skills and plugins to
`~/.claude`'s. A configuration-home file that is the same file as
`~/.claude/<rel>` (device and inode, checked on every request) is acknowledged
as `~/.claude/<rel>`, so one acknowledgement covers every account; what is
digested is still the bytes read, so a link retargeted to other contents, or to
the same bytes elsewhere, is a new source that declines until acknowledged. A
project's files never share this way: a cloned repository can commit
`.claude/settings.json` as a symlink to a trusted project's acknowledged file,
whose hooks would then run that repository's `$CLAUDE_PROJECT_DIR` scripts, so
project, local, `--add-dir` and project-tree sources, and anything under a
project's `.claude` inside a configuration home, keep their own paths. A skill
or plugin is shared only when its whole top-level directory is `~/.claude`'s,
because its hooks can name its own folder.

What delegation does not stop:

- **A direct child of the Claude Code session can forge the flow.** MCP and LSP
  servers, other plugins' hook processes and the statusline command are
  children of the Claude Code process P. Such a process can `exec /bin/sh`, run
  `csec hook claude` with forged input (it has the real session id from its own
  hook input), then run `/bin/zsh -c 'csec ai -- …'`: both ancestry shapes pass,
  and it gets every paired, held reference with no classifier involved. No
  kernel fact tells this apart from Claude Code's Bash tool. It is bespoke and
  csec-specific, and no worse than without delegation: after the first human
  approval in a session, the default coding-agent grant already lets any
  descendant of P run `csec ai` silently.
- **A malware-driven interactive session passes G3.** Malware in a paired
  project that starts `claude --permission-mode auto` in a pseudo-terminal it
  drives looks to the kernel like a person's session. The opportunistic pattern
  seen in the wild (the s1ngularity npm postinstall ran a headless `claude -p`
  with permissions bypassed) fails G3 and G4; driving a terminal and a model
  conversation is a bespoke step.
- **Code identity attests the binary, not what it runs.** `KERN_PROCARGS2` shows
  P's argv and environment as they were at exec, which code already running
  inside P can rewrite. G4 and G5 catch a launch-time injection (`BUN_OPTIONS`,
  `NODE_OPTIONS --require`, `DYLD_*`, a `--settings` file or hooks in inline
  `--settings`); an injection that scrubs its own traces afterwards passes.
  That scrubbing is a Claude-specific step.
- **Trusting a build Anthropic did not sign trusts whatever can load code into
  it.** A patched build such as tweakcc's is ad-hoc signed with no hardened
  runtime, so it lacks even the loader restrictions Anthropic's hardened build
  keeps (the dynamic loader honours `DYLD_*` injection into it); G5 still
  declines `DYLD_*` in its launch environment. Trust is by cdhash, so each
  re-patched build is asked about again.
- **Hook sources csecd cannot see.** An SDK callback hook (SDK sessions are
  declined anyway), and a skill Claude Code discovers mid-session below the
  working directory (a Read, Edit or Write under a subdirectory with its own
  `.claude/skills`), can register a hook that approves Bash calls; the gate
  walks only upward from the working directories. The gate also judges files on
  disk while Claude Code runs on a snapshot: its settings watcher lags a second
  or two, a directory with no settings at launch is not watched, and a skill's
  hooks stay registered after its file is deleted. A plugin hooks module is
  digested with its own bytes but not those of the modules it imports, and a
  hooks file a plugin names by an absolute path outside itself is read as an
  ordinary path. More broadly, the gate reimplements how Claude Code loads
  settings, hooks, plugins, marketplaces and frontmatter, checked against
  specific releases' source, so a Claude Code release can add a source it does
  not read. One is already visible: 2.1.280 carries a stubbed "v5" storage
  backend that could read the plugin and marketplace registries from a key store
  instead of the files the gate reads; it returns nothing in 2.1.280, but a
  build that turns it on would move those registries out of the gate's view.
  The signed daemon therefore admits delegation only from exact code identities
  in its checked-loader catalog, independently of publisher/custom-build trust.
  Unknown images use Touch ID on secret, SSH and sudo, with the same reason on
  the Mac and phone. A release watch on the maintainer's Mac starts a source
  audit and keeps it open through fixes and installation; a new version label
  or valid signature never certifies compatibility. Audited images reach
  every csec in the signed release manifest's `claude_code` list, verified
  against a pinned release key on every read and only ever adding to the
  compiled catalog. Whoever holds that key could admit an unaudited image,
  but only one that already passes the identity check (signed by Anthropic,
  or a custom build the human trusted): the harm is a skipped loader audit,
  not arbitrary code. The key is therefore held behind its holder's biometric
  approval, never in the release Mac's everyday Keychain
  ([release manifest](release-manifest.md#signing)). See
  [release verification](claude-release-verification.md).
- **Generated managed policy is not inspectable.** `policyHelper` and
  `policyHelpers` can replace or extend policy with refreshed helper output or
  nested fallback settings, including approving hooks, classifier rules and
  environment redirects. Any possible managed source containing either key
  therefore declines delegation on secret access, SSH and sudo; the ordinary
  review and phone share the settings-unreadable note. Acknowledging visible
  hooks never acknowledges unseen helper output. Marketplace aliases/renames
  and plugin root skill fallback are inspected as direct filesystem sources.
- **Remote runtime transport is outside the local-session attestation.** G5
  refuses `CLAUDE_CODE_REMOTE`, as G4 refuses remote argv drivers. That mode
  can supply tools with a relay proxy and CA after launch, independently of
  `ANTHROPIC_BASE_URL`; csec does not reconstruct that remote runtime from its
  local settings view. G5 also refuses `CCR_AGENT_PROXY_RELAY_MODE`:
  2.1.302's standalone relay can start without `CLAUDE_CODE_REMOTE` and
  apply its caller-selected proxy to subsequent runtime traffic. The
  [2.1.295 audit](claude-release-audits/2.1.295.md) and
  [2.1.302 audit](claude-release-audits/2.1.302.md) trace both paths and
  their shared secret/SSH/sudo refusals. This is not evidence that a live
  session was proxied or a classifier response was forged.
- **A stored Cloud-gateway sign-in routes the classifier with no
  environment.** Claude Code restores an `enterpriseGateway` sign-in from its
  secure storage at startup and sends every API request to the gateway, so a
  record same-user code plants would choose the verdict. csecd declines when
  any Claude Code credential record (every Claude Code Keychain item, and the
  session's `.credentials.json`) holds one, or when it cannot check them. It
  reads them inside its own process and keeps only that answer. A sign-in
  Claude Code holds only in memory, after an interactive `/login` whose write
  failed, is not seen; reaching that state needs the human's own login in the
  session. A gateway the human signed in to on purpose declines too, in
  whichever of this user's Claude Code configurations holds it.
- **Classifier tuning in the environment is not checked.** G5 declines the
  environment that can forge or steer the auto-mode verdict: a request-body
  override, a third-party provider or a socket route for the classifier's
  calls, and showing it the agent's own prose. The remaining
  `CLAUDE_CODE_AUTO_MODE_*` knobs pass, because each adds real context or
  changes format, temperature or concurrency. So does the main model
  (`ANTHROPIC_MODEL`, `--model`, `ANTHROPIC_DEFAULT_*_MODEL`), which can also
  select the classifier's model when no dedicated/server choice wins: a weaker
  main model is a weaker judge, but still Anthropic's model with Anthropic's
  prompt. In 2.1.302, `CLAUDE_CODE_AUTO_MODE_MODEL` explicitly chooses the
  client classifier's model, subordinate to vetted server configuration,
  organization policy and the escalated-check safeguard. It retains that
  model-quality policy and does not override server-side classification.
  `CLAUDE_CODE_BG_CLASSIFIER_MODEL`, `CLAUDE_CODE_TWO_STAGE_CLASSIFIER` and
  `CLAUDE_CODE_AUTO_MODE_EXTERNAL_PERMISSIONS` still have no behavioral reader.
  These findings are recorded by [release verification](claude-release-verification.md).
- **The classifier is fallible.** Anthropic's published figures for the full
  two-stage pipeline are a 17% false-negative rate on real overeager actions
  (52 cases; its engineering write-up calls this "the honest number") and 5.7%
  on synthetic data exfiltration; in a controlled study with 1,053 professional
  testers it caught 89% of dangerous commands where human review caught 13.6%.
  Delegation is only as strong as "the model was not steered, by prompt
  injection or otherwise, into a misuse of a secret the classifier approves".
  Pairing bounds the damage to secrets a human already approved for that
  project.
- **An SSH request under an auto-approved command signs, with nothing else
  checked** (Alex, csec-0.11). If auto mode approved the command in a verified
  Claude Code session, every process below it can use the agent's SSH keys for
  any destination with no panel: a trojaned npm or pip lifecycle script under
  an approved install, a git hook, an interpreter, a script the agent wrote, a
  planted `pushInsteadOf` or `GIT_*` environment, and a server nobody approved
  before. The same goes for classifier rules in user settings nobody
  re-acknowledged. Alex chose this trade-off over panels for approved work. What
  still gets a panel is an `ssh` that no auto-approved command started: one a
  human runs, Codex's, another permission mode's, a bypass session's, and one
  from a process adopted by launchd.
- **Acknowledged hooks are trusted as they stand.** Acknowledging a hook that
  runs `npx pkg` trusts whatever npx downloads next: a trojaned version
  returning `allow` would skip the classifier. Setup flags hooks that fetch and
  run unpinned code, and acknowledging one accepts exactly that risk, once.
  The digest covers a hook's command, not the scripts it runs: same-user code
  that edits a script an acknowledged hook calls changes what it does with no
  new acknowledgement. For a user hook shared with an extra Claude account, a
  command that names `$CLAUDE_CONFIG_DIR/…` runs that account's copy, which is
  the same exposure in the account's directory.
- **A mode switch between the hook and the permission check.** A user who
  presses Shift+Tab into bypass after the hook registered a command in auto
  mode, but before Claude Code's own permission check, gets a delegated release
  of a command that was not classified. Only the person at the keyboard can do
  this.
- **A stale registration.** Only a `csec ai` that asks csecd for references no
  grant covers, or whose `ssh` asks for a signature no grant covers, binds a
  registration. Every other call leaves its registration
  pending until P exits or 256 newer pending registrations of that session
  push it out: a command the classifier or a human blocked, and also one that
  ran — a secret-free program, a command whose environment names no reference,
  or one a live grant fully covered. A `csec ai` binds the newest pending
  registration of its own program, under its own Claude Code process, that
  csecd received before the `csec ai` started, and each registration is bound
  at most once; a registration received after a `csec ai` started is never
  that `csec ai`'s. What remains is a `csec ai` whose own registration never
  arrived in time (csecd unreachable within the hook's bound, busy past it, or
  its fact reads stuck when the hook registered): it may bind an older, stale
  registration of the byte-identical program, whose mode then applies, so a
  call Claude Code approved outside auto mode (a human at its prompt, an allow
  rule, `dontAsk`) could be released as though the classifier had. That needs
  the same program to have been registered earlier in auto mode and never
  bound, a mode switch since, and this call's registration lost. A restart
  never adds to it: csecd persists only registrations already bound, and puts
  one back only for the same boot session, the same P and the same running
  command, so a pending one never outlives the csecd that received it.
- **The identity lookup's fallback.** csecd reads P's code identity through its
  task audit token, which stays exact across an exec. Whether the signed,
  hardened csecd is refused `task_name_for_pid` has not yet been measured on an
  installed build; if it is, csecd falls back to a lookup by PID with start-time
  and parent re-reads, which is not exact across an exec (SSH lazy binding's
  launcher check falls back the same way). Every `decline` and
  `delegated_release` record that checked P's identity names the path it took
  (`delegation.identityLookup`), and `csec status` shows the latest ("Claude
  Code identity check"), so the first Claude Code command csecd judges on an
  installed build answers the question.
- **Old and new images need verification.** Anthropic's designated requirement
  is the same across versions. The exact-image compatibility gate therefore
  also excludes old genuine builds that predate `autoMode.classifyAllShell`,
  even when the key appears in their settings. Publisher trust alone admits
  neither an old loader nor a new one to delegation.
- **The environment reaches every descendant.** What a delegated `csec ai`
  receives is in its environment, and everything the command starts inherits
  it, a package's postinstall script included — the same as under a grant. A
  request that code makes to csec itself — a language client over `csec
  bridge`, a nested `csec get` or `csec exec` — rides the approval of the
  `csec ai` it runs under, however deep (csec-0.20, as SSH does since
  csec-0.11). So a postinstall script that speaks csec's protocol can get any
  reference paired with the project, not only those in its environment, with
  no panel. Pairing still bounds it to what a human approved for that project,
  and only values csecd already holds are released. Alex accepted this to stop
  a panel per Claude Code session for tools such as `av slack`.
- **A shell's environment is read where the kernel shows it.** macOS withholds
  the environment of a `CS_RESTRICT` process, which includes Apple's bash and
  zsh, so `ZDOTDIR` is read from the `csec ai` above it. A delegated
  secret release and a sudo read it that way (an SSH signing does not judge
  it, csec-0.11), from its own `csec ai`, since
  the program shell's startup files see every released value. What the
  program shell's own startup files export is not seen; the threat model
  already counts those files as the user's own code (a same-user writer of
  `~/.zshenv` can define a function named `git` as well).
- **A sudo auto mode approved runs as root with nobody reading it.** Once a
  human has let auto mode run sudo in a project (one panel there), the
  classifier is the only reader of a root command the approved text runs
  itself. What delegation adds is that missing human: a prompt-injected
  session in a paired project gets root if the classifier lets the command
  through. The per-project pairing keeps a project where nobody ran sudo through
  auto mode (a fresh clone of untrusted code) at one human look first. The rest
  is shared with a human-approved sudo, whose panel shows only the command
  line:
  - sudo keys its ticket on the parent pid and that parent's start time when
    there is no tty (sudo 1.9.17p2 `timestamp.c`), so for five minutes, and no
    longer than that program shell lives, a later sudo whose parent is the same
    program shell skips PAM and csec, one a command of the same text execs
    included;
  - a command of the approved text that execs `/usr/bin/sudo` with the
    approved argv looks exactly like the typed sudo, and can do it with another
    `PATH` or `HOME`;
  - Apple's sudoers keeps `HOME`, `EDITOR`, `VISUAL` and `SSH_AUTH_SOCK` and
    sets no `secure_path`, so root resolves a bare command on the agent's
    `PATH` (system directories first on this Mac's Claude Code sessions) and
    reads the account's dotfiles (`sudo git` reads `~/.gitconfig`).
  csecd reads sudo's argv only as the PAM module rendered it for the panel,
  since the kernel refuses it a root process's argv; a redacted argument
  matches only an expansion. sudo from a script, an interpreter, `xargs` or a
  git hook, and `sudo -E`, `-s`, `-i` and `-e`, always get the panel.
- **The program text is parsed with bash's grammar.** csec ai's program runs in
  zsh; csecd matches `ssh`, `scp`, `git`, `sudo` and scripts against it with
  tree-sitter-bash. Where the two disagree, a command either matches nothing
  (zsh-only syntax, which declines) or its arguments match as a run of
  unconstrained words (an expansion), never a command the text does not
  contain.

Every delegated release stays on the Mac: none reaches the phone. A request
delegation declined reaches the phone with its decline note and pairing line,
and a phone approval pairs only when the phone signed that its card showed the
line, which csecd checks against the signed scope and lifetime. That is the
app's own claim: a modified build of the development-signed app (below,
§Remote approval) that could already approve anything one Face ID covers could
also say it showed the line, and so plant a pairing that lasts until revoked.

### The sudo review surface

The sudo review is the one approval surface outside csecd and outside the
signed app bundle, and it sits in the authentication path of a privilege
escalation. `pam_csec_sudo.so` runs inside set-id-root `/usr/bin/sudo`; it
draws its review through a separate helper, `/usr/local/libexec/csec-sudo-review`,
which it spawns as the login user. Secret-access and SSH reviews enter through
csecd's authenticated sockets instead. The module and helper live under
`/usr/local`, are activated through `/etc/pam.d/sudo_local`, and are installed
by their own guarded stage of `build-and-install.sh`, not by the `.pkg`
(`packaging/README.md`, "Contextual sudo approval").

**A csec failure falls through; only an unanswered or interrupted review stops
sudo.** `sudo_local` carries the review as a `sufficient` factor, then the same
module as a `requisite` `review_guard`, then stock `pam_tid`; Apple's
`/etc/pam.d/sudo` goes on to the password after that. The installer refuses
any other order (`csec_sudo_policy`), activates the PAM lines only after both
binaries verify, and on removal takes the lines out before deleting the files,
so no PAM line ever names a missing module. Exit zero from the helper is the
module's only approval signal. Anything else (a helper that is missing, under
an unprotected path or fails its signature check, a frame that cannot be
written, a crash, Use Password, a phone Deny, a quit request, which the helper
answers by exiting 69) leaves the review unsuccessful, and the module shows
Apple's Authorization Services prompt for `com.apple.security.sudo` instead;
cancelling that goes on to `pam_tid` and the password. When the redactor
(below) fails there is no csec review at all, only that prompt with the
command withheld, and a sudo using askpass or outside a GUI session skips the
module entirely. So a defect in csec costs the user csec's panel, never their
way into root. Two endings are deliberate exceptions and stop sudo with no
further prompt: the review's five-minute deadline passing with nobody
answering, and a Ctrl-C, Ctrl-\ or terminal hangup while the review is up.
Each sets a value-free latch in the PAM transaction, which the guard turns
into `PAM_ABORT`, fatal to sudo rather than a failed attempt it would retry.
The module believes the helper's expiry exit (75) only within ten seconds of
its own deadline; an earlier one is a helper fault and keeps Apple's prompt.

The converse of falling through is that the csec review is an added route,
not a gate: whoever can answer Apple's prompt, `pam_tid` or the password can
still run sudo, exactly as without csec. What csec adds is a review showing
the command, a Touch ID that reuses no lock-screen match
([Process-scoped consent](#process-scoped-consent)), the phone mirror, and,
for a sudo Claude Code ran, auto-mode delegation and its risks
([Delegated approval](#delegated-approval)).

**Raw arguments never reach the helper.** The module reads sudo's own argv
and, before anything is drawn, sends it NUL-delimited over a private pipe to
the installed csec launcher, which must be a root-owned regular file not
writable by group or others. It is spawned with `POSIX_SPAWN_RESETIDS`, so it
runs as the login user and csecd authenticates it like any launcher
([Peer authentication](#peer-authentication)), and its `tool-exec … /bin/cat`
path applies csecd's active-secret matcher. Any error, warning (an active
value too short to match included), timeout, malformed framing or partial
result fails closed: no argv byte is used for display. The module then
redacts secret-named and secret-shaped arguments with the same heuristics
csec uses elsewhere and escapes the rest into a frozen command string. Only
that string, with the working directory and PAM tty reduced to printable
ASCII, crosses a second private pipe to the helper, as a bounded, versioned
frame that also says how long the review has left. The module never logs
argv, sends the helper's stdout and stderr to `/dev/null` rather than read
child text into root, and the helper's own unified-log trail is value-free.
The panel, the phone and the decision log, which records a phone or
delegation decision but not a Mac one ([Decision log](#decision-log)), see
only that redacted string. Redaction catches only what csecd's active catalog
and the heuristics recognise: a credential typed on sudo's command line that
neither knows is shown on the panel as typed.

**The module checks the helper before resuming it.** Before spawning, the
module requires `/`, `/usr`, `/usr/local`, `/usr/local/libexec` and the helper
to be root-owned, not group- or other-writable, and not writable by sudo's
real user; a Mac whose `/usr/local` belongs to the user gets Apple's prompt,
never the csec review. It spawns the helper suspended, with no arguments, a
two-variable environment (`PATH=/usr/bin:/bin`, `LANG=C`), its own process
group and descriptors closed by default, then asks Security.framework about
that exact kernel guest by PID: dynamic and static signatures valid under
`kSecCSStrictValidate`, the hardened-runtime flag, the signing identifier
exactly `com.alexspeller.convenient-security.sudo-review`, and none of
`get-task-allow`, `disable-library-validation`,
`allow-dyld-environment-variables`, `allow-jit`,
`allow-unsigned-executable-memory`, `disable-executable-page-protection` or
`debugger`. Only then does it resume the helper and write the frame. The
hardened runtime is what stops a same-UID process from injecting a library
into, or taking the task port of, a helper that runs as that user. The check
names no Team ID or certificate anchor, so any signer's binary carrying that
identifier and the runtime flag would pass it; what binds the review to csec's
own helper is that only root can place a file at that path, and root is
outside this threat model. csecd, unlike the module, admits only the team's
signature (below), so such a substitute would get neither the phone mirror
nor delegation.

**The helper authenticates its parent.** The helper is an ordinary `0755`
executable any user can run, so it authenticates its direct parent before
reading the private pipe and again after decoding the frame. The parent must
still be the same live process with effective UID zero, read from a complete,
PID-checked `KERN_PROC_PID` record; a missing, unreadable, non-root or
orphaned parent is refused before contacting csecd, arming Touch ID or
presenting a Mac or phone review. sudo's real UID can be the login user, so it
is not the check. A release helper also refuses any argument and any stdin
that is not a pipe or socket, and caps the frame at 9 KiB. The parent-exit
watch then withdraws the review if sudo dies. This stops a same-user process
from piping chosen text into the genuine helper to phish or habituate a
touch. It is not an attestation of a particular root executable: root is
outside this threat model. Live synthetic panel and phone modes exist only in
debug builds; shipping offscreen PNG previews never present a review or arm
Touch ID.

**csecd admits the helper for its own requests only.** The phone mirror
(`sudo_remote_review`), the auto-mode question (`sudo_delegation`, with the
pairing a Mac approval records), the terminal-tab lookup (`sudo_terminal`,
which names nothing: csecd looks up the asking helper itself) and the report
of how the review ended (`sudo_review_end`, for the decision log) are csecd
requests. csecd recognises a
peer as the sudo review helper only when its live code identity has the
product team and the helper's identifier (`ProductCodeRole.sudoReviewHelper`),
and permits that role those requests and nothing else; the launcher cannot
send them. csecd judges a delegation from its own kernel view of the sudo that
spawned the helper and the chain above it, not from anything the helper
claims, and pairs only for the helper it made the offer to.

**Deployment skew.** Installing the app or its `.pkg` does not touch the
module or the helper, so they can fall behind the rest of csec: on the
author's Mac a pre-release helper drew every sudo review for fifteen days
while the Touch-ID-for-sudo check (HA-G08) passed throughout.
`SudoIntegrationInspection`, shared by `csec doctor` and the host-audit check
HA-G11 ([host-audit catalog](host-audit-catalog.md)), runs whenever
`sudo_local` loads the module and reports a defect when the module will not
hand off to this source tree's helper: the module image lacks the
NUL-terminated helper path and identifier (so the `-spike` build fails) or
`review_guard`; `sudo_local` lacks the guard immediately after the review; or
the helper is missing, sits under an unprotected path, fails
`codesign --verify --strict`, carries another identifier, lacks the hardened
runtime, or is not signed by csec's team (the module still runs it, but csecd
mirrors none of its reviews). `csec doctor` fails on any of these. The
inspection compares no CDHash with a build, so an older helper that is
correctly identified and team-signed passes it; `build-and-install.sh` closes
that gap by reinstalling the sudo stage on every run and checking that the
installed module and helper are byte-identical to the build. The stage keeps
a new installation only when one sudo it runs as the login user was approved
by the helper it installed, read from that sudo's value-free unified-log
trail; anything else restores the previous module, helper and `sudo_local`.

### Persisted grants, pairings and settings

Grants, pairings, the delegation settings, the last-run record, the decision
log's key and checkpoints, and the sealed baseline's pointer live in
data-protection Keychain items in csecd's restricted access group. A same-UID
process outside that group cannot read, write, add, delete or roll back any of
them (measured with an unentitled probe; AMFI kills a binary that claims the
group without the matching provisioning), so it cannot forge a grant or a
pairing, resurrect a revoked one, or turn delegation on. The items carry no
biometric ACL, because csecd loads them at startup with no prompt, so a signed
build of this team holding the entitlement could read them; that holder is
outside this model. They hold canonical references and value-free metadata
only.

A restored grant matches exactly as it did before the restart — live root PID
and start time, boot session, audit session, reuse digest — so killing csecd
gains an attacker nothing but at most one restore panel per kill (without
persistence each kill would cost a re-ask per grant). A revocation is persisted
before it is acknowledged, and one that cannot be written deletes the whole
item, so a restart cannot resurrect a revoked grant, unless that delete fails
too: `csec revoke` then fails with an error saying the revocation holds only
for this csecd run, and a restart could bring the grant back. A same-UID
process can still drive the genuine `csec`: `csec grants` lists the live set with no Touch
ID, and `csec revoke --all` or disabling delegation only removes authority,
which is denial of service (more prompts), never a gain. Turning delegation on,
trusting a build or acknowledging a hook raises csecd's own Touch ID panel, the
ordinary consent risk.

A pairing is written only when a human approved, on a surface that showed the
pairing line (the Mac panel, or the paired phone's card), the default Claude
Code scope with the process lifetime; another scope or a lifetime cap never
pairs. Pairings survive restarts and reboots until
revoked. After a restart a paired value csecd's own stores seal is cold like any
other and is reopened only through the restore panel, for a live, verified
Claude Code session in that project. A paired `op://` value is fetched from
1Password for auto mode with no csec panel (csec-0.64.2): a production secret
paired with a project can leave 1Password after a restart with no Touch ID of
csec's, only 1Password's own check. That is the trade Alex chose, since the
pairing was already a human approval for that project; one 1Password cannot
serve gets an ordinary panel. The attended install's `csec restore` fetches
every such paired value ahead, in every project (csec-0.64.6), because
1Password authorizes a restarted bridge only with someone there to answer it,
and so does every panel approved at the Mac while one is still cold
(csec-0.64.13: a reboot has no install, and an install's prompt can go
unanswered). So csecd holds in memory, and in its biometric cache tier, paired
values no request has asked for yet, where before it held only those used
since the restart. A phone approval never starts a fetch: nobody need be at
the Mac to answer 1Password. Nothing is released by it: a later release passes
every gate, and the exposure is the warm cache's, for values a human already
paired. A
delegated request or signing that went to the restore panel starts over at the
present when it closes and never waits a second time, so a revocation, an
expiry, an unpairing or turning delegation off while the panel is up takes
effect for that request too.

### Decision log

The decision log is tamper-evident, not tamper-proof. A same-UID process sees
ciphertext, sizes and timing only. It cannot forge a record, and a modified,
reordered, spliced, truncated or rolled-back log, or a missing key or
checkpoint, is found at the next csecd start or `csec log --verify`, recorded
once and notified. Deleting the log is found but not prevented, and filling the
disk is denial of service; reuse volume cannot evict decisions, which have
their own cap. Known bounds:

- The `usage` checkpoint is coalesced to ten seconds, so after a crash the last
  few seconds of reuses and delegated releases can be cut or altered and look
  like a torn tail.
- A same-UID process can plant files csecd cannot remove (immutable files) where
  csecd sets files aside. They never cost verified history, but every prune pass
  still walks them: with 20,000 planted, a usage append was measured at about
  1.8 ms instead of about 0.06 ms (release build), a cost on every covered
  release, growing only with what is planted.
- A real segment whose first frame is damaged cannot be told apart from planted
  junk, so it is remembered on the checkpoint's list of 32 junk entries; while 32
  or more planted immutable files crowd it out, it is recorded
  (`spliced_segment`) and notified again at every start, though history written
  since stays live. Likewise, past 96 of csecd's own damaged segments that
  cannot be moved, a further one is recorded again at each start, and each
  start then sets aside the history written since the previous one. Filling
  that list takes at least four recorded, notified findings on real immutable
  segments.
- A `decisions` record is checkpointed before its append returns, but a
  checkpoint that cannot be written (a failed flush, or a Keychain write whose
  fallback delete also fails) leaves the older checkpoint in place. Records
  written after it can be cut with no finding until a later checkpoint is
  written; `csec status` warns that the checkpoint could not be written.
- One damaged segment costs the readable history after it: recovery sets aside
  the segment where verification failed and every later one, authentic ones
  included, so a disk error early in the log removes later history from
  `csec log` (the files stay on disk under the set-aside budget).
- Reading is ungated. `csec log`, like `csec grants`, needs the verified launcher
  and no Touch ID, so a same-UID process running the genuine `csec` can read
  references, scopes and the panels' redacted command lines. No confidentiality
  against it is claimed: the references are already in sidecars and `.envrc`
  files, and the commands in coding-agent transcripts. The encryption defeats
  the common copy-files-from-home theft.
- Refusals before a panel (`absent_reference`) arrive at socket speed, so a
  loop of requests for keys that do not exist could otherwise fill the
  decisions stream and prune its panel records. Each distinct refusal is
  recorded once per csecd run, and at most 64 per surface (secret access, SSH,
  automation) per run.
- Deleting it through csecd is gated: `csec uninstall` erases the log, its key
  and every protected item only after one Touch ID.
- A sudo decided on the phone, one delegation approved, and one it declined
  are logged (surface `sudo`, with the redacted command). So is every other end
  of a sudo review (a Mac approval, Use Password, the deadline, the sudo
  exiting), but only as the installed helper's report (`sudo_review_end`):
  csecd checks the reporter's code identity, not the report, so it cannot attest
  a Mac decision as it attests its own panels. A forged report could at most add
  a misleading sudo record; it approves and opens nothing. Each is rooted at the
  coding agent above the sudo when one ran it, from csecd's own kernel walk.

### Sealed host-audit baseline

The accepted host-audit baseline, with the user's exemptions, is AES-GCM-sealed
under a key derived from the decision log's, and a protected Keychain pointer
names its generation, file ID and digest. So a same-UID process can no longer
add an exemption before disabling a control to silence the pass → fail
regression notification: a modified, rolled-back, replaced or deleted sealed
file, or one made unreadable, is recorded, notified and treated as an absent
baseline (unless csecd can restore its own access and the file then verifies).
Residuals:

- Deleting the sealed files is found and notified and the baseline is resealed
  empty: denial of service against the accepted baseline, never a silent one.
- Any tampering buys a quiet period. Treated as absent, the baseline is reset
  to empty, and an empty baseline accepts no control as passing, so from the
  tamper notification until the user runs `csec audit` and re-accepts, no
  `pass → fail` regression is reported. An attacker who tampers with the
  baseline and then disables a control is announced by that one tamper
  notification, not a regression one; it says csecd discarded the baseline
  and starts again from an empty one, so regressions are not reported again
  until the user runs `csec audit` and re-accepts.
- The plaintext baseline an older csecd kept is trusted once, at the one-time
  import; whatever was done to it before the first sealed start is imported.
- A double Keychain failure — csecd's own pointer write fails and so does
  putting the previous pointer back — leaves `pointer_missing`, a notified
  finding. Until the next load, deleting the sealed files (or renaming them to
  `pending-*`) and planting a plaintext baseline would then be imported
  silently. An attacker can neither cause nor see those Keychain failures.
- A locked parent directory, or an immutable flag on csecd's objects, denies the
  baseline until the user clears it; it is found and notified at every start,
  and every audit or triage save that does not take is notified (a failed
  reminder stamp once per run).
- When csecd strips a deny ACL from its own directory and the no-follow call is
  refused, it uses `acl_set_file`, which follows a symbolic link at the last
  component, but only right after a no-follow check showed csecd's own
  directory there. A link swapped in between the two calls could redirect it;
  the only effect is removing an ACL from an object the same user could change
  anyway.
- If the decision log could not open its directory at startup, the baseline has
  no key and is unavailable with no notification of its own; the log's
  `directory_unusable` notification is the signal.

### Language-client heap delivery

The Ruby and Node.js clients do not trust the agent socket. They invoke the
fixed root-owned signed bridge, which uses a scrubbed environment and
close-on-exec private pipes. The agent verifies the bridge and its actual direct
language-runtime parent; the bridge rechecks the parent before writing its
response. Plaintext therefore arrives in the authorized process heap without
appearing in the initial environment or argv.

This protection ends if the application assigns the returned value to
`ENV`/`process.env`, passes it in argv, writes or logs it, sends it over an
unintended connection, or loads hostile code into the same language process.

### Tool-native credential protocols

AWS and Git launch a helper with private stdin/stdout pipes. The signed helper
binds the expected host/repository or AWS field references and the live direct
parent executable into the reviewed plan; the daemon and helper independently
recheck the parent before release. Output is refused when the credential stream
is a terminal or ordinary file. Git requests are bounded and exact-matched
before resolution, and its mutation operations do not resolve or persist data.

This keeps credentials out of initial environment, argv, and named files. It
does not make AWS, Git, their plugins, or anything executing inside those
authorized processes trustworthy. Those consumers receive plaintext and can
retain or disclose it. A malicious protected executable can also be invoked by
same-UID malware, but it cannot obtain a grant rooted outside the approved
process tree merely by naming that executable.

### Machine identity sign-ins

An identity's Secure Enclave key cannot be exported, but its handle lets any
same-user process holding it ask the enclave to sign, measured across two
differently signed binaries. The handle therefore lives only in the csecd-only
`machine-identity`/`catalog-v1` protected item, and a same-UID process can
neither read it nor add a target or an accepted key there. What it can do is
drive the genuine `csec` to ask for a sign-in, which raises the normal review
for a reference it names; a grant then covers that sign-in for the approved
scope, as for any secret. Removing a target revokes its grants and unpairs it
from every project, so a target added later under the same name starts with
no approvals. Adding a target, creating or removing an identity
and accepting a published key each take one Touch ID in csecd's settings panel
that names what changes, so an unattended process cannot widen what one approval reads as.

For AWS the trust root is the published key set: whoever can write the
issuer's `jwks.json` can mint tokens for any subject and become every role
that trusts the issuer, whatever csec does on the Mac. The S3 policy csec
writes denies every change but one named administrator's, and csecd's daily
check notifies on a key this Mac never accepted, comparing each published
key's own thumbprint so a key swapped in under a known `kid` is still flagged;
neither stops an administrator of the host, and the check reports nothing
while the host can't be reached. Google takes an uploaded key set, so its trust root
is the workload identity provider's configuration in the Google project.

A released sign-in is plaintext to its consumer, like any credential: a token
is good until it expires (at most an hour), and AWS credentials until theirs
(at most an hour, and only for that target's role). csec stores neither at
rest; csecd keeps AWS credentials in memory for reuse while more than 20
minutes remain. STS refusals are reported by documented error code only,
never STS's message text.

For wrapped gcloud, csecd exchanges the assertion with Google's fixed STS
endpoint and optionally impersonates the service account sealed in the
separate `google` target. The authenticated reference goes through ordinary
policy/consent on every release, even when csecd already holds its access
token in memory. The provider never persists it; redirects are refused and
response bodies never become diagnostics. The wrapper uses
`CLOUDSDK_AUTH_ACCESS_TOKEN` to bypass gcloud's token cache, forces file logging
off, clears configured impersonation and refuses credential export/management
and alternate authentication flags. A single-open descriptor is unsuitable:
storage transfers create additional transports that reload credentials.
The process environment remains readable to same-user inspection; neither
this nor an approved session is a defence against malware already inside it.
The token expires within an hour and cannot refresh inside one long command.

The client libraries' executable-source path retains its in-memory exchange.
Bypassing the gcloud function with `command gcloud` or using the credential
file with `auth login --cred-file` still caches tokens in `access_tokens.db`,
which other processes can reuse without a csec review; setup leaves old
credentials/caches untouched. Standalone gsutil keeps another copy in
`~/.gsutil/credstore2`; use wrapped `gcloud storage`. Standalone bq is also
outside the wrapper; use the Google client libraries. The offline
`bin/test-google-token-cache.py` exercises the real consumers, independent
review scopes, refusal, backend-neutral delivery and absence of cached/logged
tokens. The AWS CLI also caches a role assumed on top of a csec profile in
`~/.aws/cli/cache`; a `credential_process` profile's own credentials stay in memory.

### Inherited descriptor delivery

`csec exec-fd` creates anonymous pipes with close-on-exec parent ends and gives
only selected elevated read descriptors to the target. The environment exposes
non-secret `/dev/fd/N` paths, not values. File descriptors belong to a process's
descriptor table, so the same numeric path in an unrelated same-UID process
does not name the target's channel. An exec-status handshake prevents the
launcher from writing until the kernel has replaced the child image; partial or
abandoned delivery fails, the child group is reaped, unused ends close, and the
launcher's retained bytes are overwritten best-effort. No named plaintext file
is created.

The descriptor is intentionally a single-open stream, not a regular file. It
cannot seek, independent opens do not reset its offset, and the target can pass
the descriptor to descendants until it closes it or marks it close-on-exec. A
tool that closes inherited descriptors, insists on regular-file metadata, or
reopens its configuration is incompatible. The authorized target can always
read, copy, log, or transmit the bytes, and root can inspect the processes;
output masking only reduces accidental writes on supervised stdout/stderr.

### Capability-GID regular-file delivery

`csec exec-file` addresses consumers that require a regular file, independent
opens, seek, `mmap`, or descendant reopen. Plain mode-`0600` files would not
protect against the file owner's other processes, so the privileged helper
instead creates root-owned `0050` directories and `0040` files whose group is a
new per-launch capability. It launches the authorized tree as the normal login
UID with that GID as its primary group. An unrelated same-UID process does not
gain the group merely by learning the tmpfs pathname.

The root helper's production endpoint is fixed and its socket pathname is not
trusted as identity. It validates complete audit tokens and live code identity:
only exact signed `csec` may prepare/start/supervise a launch, and only exact
signed `csecd` may submit approval and file bytes or send the host audit's
closed-list privileged reads and digest-bound reversible changes, which run
fixed system tools and change system configuration, `/etc/pam.d/sudo_local` and
NVRAM `boot-args` included
([protocol](protocol.md#protected-regular-file-rendezvous)). A peer that is
neither signed role is refused before its request is read; a signed peer asking
for the other role's operation is refused once the request is decoded, before it
is handled. The prepared launch binds the original launcher PID/start
time/UID/audit session, exact executable metadata, argv, sanitized environment,
path mappings, output policy, TTL, and command digest. Four stdio/cwd
descriptors arrive only with prepare. A random nonce and canonical plan digest
bind the two independent requests; only the original launcher audit token can
consume them.

`csecd` does not return values to `csec` for this mechanism. It applies the
release policy, obtains fresh consent unless a grant the human widened to a
coding agent or terminal session already covers the launch, resolves the exact
set, renders bounded payloads, and transmits them directly to the authenticated
helper. The helper revalidates plan/path/size constraints, uses
descriptor-relative no-follow and exclusive creation on verified bounded
`nodev,nosuid,noexec` tmpfs, and closes all unintended descriptors before
exact-path `execve`. Its minimal binary does not link providers, Keychain
access, Touch ID, AppKit, or agent policy code.

A boot-scoped monotonic allocator persists and fsyncs its cursor before use,
skips GIDs assigned to accounts or held by any live process, and fails closed on
corruption or exhaustion. The GID remains attached across fork, exec, and normal
daemonization, so it identifies descendants after the direct child exits. The
helper unlinks names only after the complete GID tree is gone or at expiry, and
it removes stale UUID sessions on restart before serving. Launcher death,
cancellation, scanner failure, and hard-TTL expiry unlink and repeatedly kill
all GID holders; a soft TTL only unlinks names and cannot revoke an already-open
descriptor.

This boundary excludes an unrelated non-root same-UID process; it does not
protect against root, an administrator able to mutate installed privileged
paths, or code inside the authorized tree. That tree can read and disclose the
bytes, keep an open descriptor after unlink, alter its own primary/supplementary
groups subject to normal kernel rules, or deliberately pass descriptors/data to
another process. Executable identity also does not make user-writable scripts,
plugins, configuration, or inputs trustworthy. The signed installed behavior
must pass [`regular-file-security-matrix.md`](regular-file-security-matrix.md)
before real secrets are used.

`csec protect`/`csec exec` extend this mechanism to whole-file *sidecar
materialization* without changing the privileged helper. `csec protect` imports a
plaintext file into the store and leaves a `*.csec` pointer; `csec exec` scans the
project for those pointers and, at ordinary user privilege, installs a symlink
from each file's original path into the same root-owned tmpfs (the helper still
writes nothing outside its mount, so it is never a confused deputy). The
confidentiality boundary is unchanged — an unrelated same-UID process that
follows the symlink still gets `EACCES` on the `0040` target — but the symlink
itself sits in a user-writable directory and is therefore not an integrity
boundary: same-uid malware can replace it, which is out of scope for the same
reason a compromised consumer is. A sidecar is source-neutral — it may name any
secret reference, as either the strict JSON `csec protect` writes or a bare
reference — and a `*.csec` file that cannot be parsed is warned about, not silently
skipped, so a broken sidecar is visible rather than looking like a missing secret.
A home token file is restored the same way for the command that reads it, from
any directory: the command's name selects only its own catalog entries, so
`vault` is not handed the Cargo or Hugging Face token, and `--with-file` adds one
by name. Its link is rooted at the home directory, with the same integrity limit,
and it is one more reference in the same review. A sidecar planted beside a home
path is bound exactly as a project one is.
For a native `csec://` sidecar, because it sits in a hostile directory `csecd`
binds its value to the project-relative path its blob recorded at import, so a
planted or moved native sidecar that redirects a value to a different path fails
closed before any launch. A non-native reference (`op://`, …) has no recorded
protect-path and cannot be path-bound; a planted one is caught only by the Touch ID
review that shows the reference — the same protection an attacker-planted `op://`
env-scan line or `--set` already faces, so allowing source-neutral sidecars adds no
new capability for the automated, opportunistic adversary this model targets.

The same launch folds in `csec exec`'s ordinary environment injection (`--set`
and env-scanned references) as value-in-environment bindings: csecd resolves each
value and the helper — not the launcher — places it in the child environment.
This keeps the plaintext out of the launcher and behind one approval, but the
value re-enters the same-UID-inspectable environment exactly as plain `csec exec`
delivers it, so it carries that mechanism's weak-compatibility exposure and risk
policy, not the sidecar files' tmpfs isolation. Only bindings whose reference is
a native blob are path-bound; a value binding names any resolvable reference and
is not surfaced as a file.

### Keychain cache

The persistent cache uses the data-protection keychain and the daemon's
team-prefixed restricted access group. Each item is
`WhenUnlockedThisDeviceOnly` with `.biometryCurrentSet`. A process cannot gain
that access group merely by placing the entitlement in an ad-hoc signature; AMFI
requires the matching provisioning/signing authority. Hardened-runtime library
validation prevents unrelated code from being injected to borrow the daemon's
identity. Re-enrolling biometrics invalidates cached items.

An unsigned development daemon cannot use this cache and runs without
persistence. The warm plaintext cache exists only in the daemon process.

### 1Password account selection

An `op://VAULT/ITEM/FIELD` reference names no account, and a vault name is unique
only within one account. With several accounts signed in, an account-less `op
read` therefore resolves against whatever account `op`'s own configuration last
recorded — so the value a reference yields can change without the reference,
1Password, or csec changing at all.

csec resolves the account itself, from vault ownership, and passes it explicitly.
The residual risk is *value substitution*: an attacker who can get an account
signed in on this Mac (an invitation the user accepts, say) could place a vault
and item whose names match one the user already relies on, and offer their own
value in place of the real one. That substitutes a credential; it never discloses
the genuine one, since the two accounts cannot read each other's vaults.

Three properties bound it. The vault-to-account map is derived state kept only in
the daemon's memory — never a file, which same-uid malware could edit to redirect
a reference at an account it controls. A reference whose vault name several
accounts hold resolves only after a trusted review has displayed the account that
will be used and warned that the name is ambiguous; unattended and cold-index
paths fail closed instead. A review built before csec holds the vaults' item
listings names every account that has the vault rather than one, since listing
them could raise 1Password's prompt before the panel; the approved read then
proceeds only if exactly one of those accounts holds the item, which is the same
item-presence rule a warm review applies without a warning. And the account each reference resolved from is
remembered for the daemon's lifetime, so an approved reference cannot drift to a
different account later in the session. A reference that names its vault by the
globally unique vault id is unambiguous by construction.

One case is deliberately weaker. To avoid authorizing every signed-in account
before a reference that needs only one, csec first tries the account it has
honest reason to try — the one a review already settled on, the only signed-in
account, or the only one already warm — and builds the full index only when that
misses. While the index is incomplete, a vault name shared by an untried account
is not detected as ambiguous, so an optimistic hit can come from the tried
account without a warning. It never reaches past the accounts already
authorized, a single-account Mac cannot hit the case at all, and once any miss
or keepalive completes the index, ambiguity detection is exact again for the
daemon's lifetime. The trade bought is one prompt instead of one per account;
the reference form `op://<vault-id>/…` avoids it outright.

### The 1Password bridge's library-validation exemption

`csec-op-bridge` is the only csec binary signed with
`com.apple.security.cs.disable-library-validation`, an entitlement csec
otherwise treats as disqualifying. 1Password's desktop integration is reachable
only by `dlopen`ing `libop_sdk_ipc_client.dylib` from the 1Password app, which
AgileBits signs; library validation refuses a differently-signed library, and
the hardened runtime is mandatory for notarization. Without the exemption there
is no persistent session, and without a persistent session csec is back to
re-authorizing per read — which is what puts unrequested Touch ID prompts on
screen.

The exemption is contained rather than argued away. It is scoped to that binary:
`csecd`, `csec`, and `csec-rootd` carry none of the forbidden entitlements, the
release build fails if the exemption appears on any of them, and csec's own
trust check accepts it *only* on this signing identifier while still rejecting
every other forbidden entitlement. The check the loader would have made is
replaced by an explicit one — csecd verifies the library is validly signed by
AgileBits (team `2BUA8C4S2C`) before spawning a bridge, and the bridge verifies
it again in-process immediately before the load, refusing symlinks, non-regular
files, and any path but the one under `/Applications`.

Two gaps remain, both stated rather than closed. A window exists between the
bridge's verification and the `dlopen`; closing it would need a file-handle-based
loader API that macOS does not offer. And 1Password installed by drag-and-drop
stays owned by the installing user, so that library is writable by the same uid
an opportunistic attacker already has. Both are bounded by what an attacker in
that position already holds: the 1Password app is the root of trust for every
`op://` reference, and code that can rewrite it has compromised 1Password itself
long before csec is involved. The bridge is also a bare process — no keychain
entitlements, no TCC grants, no privileged helper access, only a pipe to csecd.
HA-B10 reports the user-writable condition so it is visible rather than assumed.

### Native encrypted stores

`csec://<store>/<key>` values are held in a flat strict-JSON document and stored
as an AES-256-GCM envelope. The authenticated data binds the store name, format,
generation, and random file ID. A SHA-256 digest and the sole active
generation/file pointer are stored beside the random 256-bit data key in one
data-protection Keychain item. Consequently, modifying an envelope, moving it
between stores, or replaying an older valid envelope fails before plaintext is
returned.

The Keychain item is in the provisioned daemon's restricted access group and is
`WhenUnlockedThisDeviceOnly` with `.biometryAny`. A cold daemon accepts the item
only with the `LAContext` from fresh Touch ID consent. Unlike the refillable
cache's `.biometryCurrentSet`, `.biometryAny` deliberately survives fingerprint
enrollment changes because invalidating this sole key would destroy the store.
This means any biometric currently trusted by macOS can unlock it. The loaded
record remains warm only in the hardened daemon; individual secret release is
still controlled by process-scoped grants.

Ciphertext lives in the user's Application Support directory. Store names are
visible in filenames, and a same-UID attacker can list, copy, delete, replace,
or permission-change those files. Modes `0700`/`0600`, `openat`, regular-file
and owner checks, and symlink rejection reduce mistakes and races but are not a
same-UID confidentiality boundary. Encryption protects copied bytes;
authenticated Keychain state rejects replacement and rollback. Deletion or
permission changes remain denial of service.

`csec edit` releases the whole decrypted document only to the mutually
authenticated signed launcher after separate fresh Touch ID consent. The edit
session is bound to that launcher's kernel PID/start time, lives exactly as long
as that launcher process — no clock ends an open edit, and csecd cancels the
session of an editor that is gone — and rejects stale concurrent saves. The
default built-in AppKit editor creates no named plaintext file and disables automatic spelling, replacement,
data detection, and window restoration. Plaintext nevertheless exists in
launcher and AppKit memory. A user-initiated copy is marked concealed and
transient and kept off Universal Clipboard, so clipboard managers that honour
the nspasteboard.org markers do not write it to their history; it is still an
ordinary pasteboard entry that any process on this Mac can read until the next
copy, and a manager that ignores the markers still records it. Copying,
screenshots, input methods, accessibility/screen-capture authority, and
compromise of the authorized UI process therefore remain outside the boundary.

`csec edit --remove` deletes stored whole-file values through csecd rather than
the files on disk, so the store's index, remote-unlock mirror and backup bundle
stay consistent. Anything that can run the launcher, a coding agent included,
can ask; only a fresh local Touch ID in csecd's settings panel, which names
every value and is never mirrored to the phone, deletes them, and it releases
nothing. csecd refuses values its SSH catalog, GitHub socket or automation jobs
use, and one whose sidecar is still where its file was protected from; a value
named anywhere else (a moved sidecar, an env file) is lost to it, which is the
human's call at the panel.

`csec edit --editor` deliberately weakens this boundary. It places the whole
document in a named `0600` file inside a randomized `0700` temporary workspace
and gives its pathname to the chosen editor. The modes deter other accounts but
not same-UID malware. The editor and plugins can read or copy every value; swap,
autosave, backup, recovery, snapshots, and copies outside the workspace may
survive csec's best-effort cleanup, and a crash or forced termination can leave
the workspace itself. Interactive editor display and output are not supervised
by csec's output masker. No implicit shell evaluates `$EDITOR`, but a user can
explicitly select a shell or an editor argument with its own effects. This mode
warns before biometric consent and should be used only when its editor
functionality is worth the edit-window exposure.

The external named-file editor mode is available for every store. Choosing
`--editor` is the plaintext-file acknowledgment, so one Touch ID authorizes it,
as it does the built-in editor; the review names the actual editor path, bound
before review, as an unverified complete consumer. The built-in signed editor is
treated as a verified-product heap consumer. Neither edit session has a clock:
it lasts as long as the launcher incarnation that opened it, and commit accepts
only that incarnation, and only while the store is unchanged since the edit
started.

Without `csec backup`, loss of the Mac or Keychain record is permanent data
loss. With it, sealed bundles of every store and the SSH catalog sit in iCloud
Drive (or a chosen folder):

- **Confidentiality.** A bundle opens only with the recovery kit's private key,
  which exists only in the kit the human keeps off the Mac. Apple, iCloud, and
  same-UID malware see ciphertext and opaque file names. A kit kept in a
  1Password vault that an `op://` reference reads would be one grant away from
  an agent, so the setup window says to keep it elsewhere.
- **Integrity.** csecd MACs every bundle with a key held only in its access
  group, so someone holding the public key cannot plant values for a restore to
  import. Swapping a bundle between names or backups, or changing a byte, fails.
  An older genuine bundle put back in the folder still authenticates: a restore
  could bring back stale values. On this Mac the manifest catches it (status
  compares the size, inode and modification time it wrote, and the next local
  open or sync rewrites it), and the restore listing shows each bundle's date.
  A process that rewrites a bundle in place and resets its times defeats the
  check; it still learns nothing and plants nothing.
- **Availability.** Same-UID malware can delete the folder. Status and doctor
  report a missing bundle, and the next local open or `csec backup sync`
  rewrites it. It cannot turn backups off or move them to its own key: setup,
  sync, restore and off each take a fresh Touch ID, and setup only ever adopts
  a kit csecd generated itself.
- **The kit in transit.** It crosses the authenticated socket to the signed
  launcher, as `csec edit` documents do, and is shown in an `NSAlert`. Saving
  it means copying it, and pasting it back to confirm; while it is on the
  general pasteboard any process on this Mac can read it, so the launcher
  clears the pasteboard afterwards if it still holds the kit (1Password clears
  its own copy). Screen capture and Accessibility reads of the window by a
  process holding those privileges are outside the boundary, as for the
  editor. Restore reads the kit from an `NSSecureTextField`, never stdin or
  arguments.
- **Restore.** Restore never overwrites a store or a bundle: a store name this
  Mac already has is skipped, a carried-on backup goes to a new folder, and no
  folder is ever written by two Macs. Rotation deletes only the bundles this
  Mac wrote in its old folder, and only after the new ones are uploaded. So a
  mistaken restore or rotation cannot destroy the last copy of a store.

A request for a key a store does not have is refused before any panel when
csecd has the store open, or when the store does not exist at all
(`reference_not_found`). That gives any same-UID process a silent check of
whether a key name exists in a store csecd opened since it started: a miss is
answered at once, while a hit still raises a panel and alerts the phone. The
check never reveals or compares a value. Key names are treated as non-secret
metadata already: `csec log` lists every reference ever requested to the signed
launcher with no Touch ID, store names are file names, and references sit in
sidecars and `.envrc` files. So the only new disclosure is whether a key nobody
has asked for exists in an open store, which is reconnaissance at most. Before
csecd has opened a store, it refuses only when the Keychain has no record for
it and its directory lists no file under its name, so a Keychain lookup that
wrongly reports a record missing, or a directory that cannot be listed, gets a
panel instead. (A phone approval that finds neither a record nor its mirror
already treats the store as absent for the rest of that csecd run; requests
fail the same way there, refused or not.)

### iPhone remote approval and the phone-held unlock factor

A paired iPhone can decide the same reviews the Mac panel decides
([remote-approval.md](remote-approval.md)). Authority comes only from
signatures: the Mac signs each request with a Secure Enclave key; the phone
answers with a Face-ID-gated Secure Enclave key (`.biometryCurrentSet`) whose
public half the Mac pinned under Touch ID. CloudKit's private database is an
untrusted mailbox. Someone who controls the iCloud account can read the
value-free review metadata, delete or delay records (denial of service), and
replay old ones, but cannot make a decision count: csecd accepts a response
only for a request it is still waiting on, once, bound to that request's
digest, from the pinned phone, selecting only a scope and lifetime the request
offered. The review metadata that crosses the mailbox — the redacted, bounded
command line, reference names, caller and terminal descriptions, SSH host
names — is the opt-in's accepted exposure; no value, key, cache key or
reusable capability ever does.

Cold storage opens after a phone approval through the phone-held unlock
factor. At pairing, under the same Touch ID, csecd makes a remote-unlock key
pair and wraps its private half under a secret only the phone's Face-ID-gated
key-agreement key can recompute, then seals a copy of each native key record
and cache entry to its public half. A request that needs cold storage carries
a freshly blinded point; the phone's answer is useless without the blinding
scalar that never leaves csecd, so the mailbox holds nothing that opens
anything, and the phone learns nothing it could reuse. That scalar together
with the answer would yield the enrollment's static unwrap secret, so csecd
inverts it with branch-free, fixed-iteration arithmetic whose timing does not
depend on it. A restore is mirrored only when the approval could reopen every
row it lists from local sealed state: a paired `op://` value that only the
biometric cache holds counts as cold, and only its copy covers it. A release
of an `op://` value that has a copy carries the blinded point too, and the
approval reads the copy before asking 1Password, as a Mac approval reads the
biometric cache: one Face ID on the pinned phone releases a value csecd
cached, with 1Password locked, just as one Touch ID does at the Mac. A value
csecd never cached still goes through 1Password's own authorization. The copies are
`AfterFirstUnlockThisDeviceOnly` items in csecd's restricted access group with
no biometric ACL, so for a user who paired a phone:

- same-UID code still cannot read, write, add or delete them (the access
  group), and cannot open them without a Face ID on the pinned phone;
- they are readable behind a locked screen, which is what lets a phone approve
  while the person is away; the phone's Face ID remains cryptographically
  required for every cold open;
- a remote unlock reads copies only and never writes a store: native writes
  still need the Mac's own Touch ID;
- the biometric items themselves are never changed, so a user who never pairs
  a phone keeps exactly the protection described above.

A copy is deleted before its key record or cache entry is written and sealed
again after, so a crash leaves no copy rather than a stale one; a cache
invalidation (a rotation) deletes the copy before the entry, and a read or
write already in flight can neither restore the old value nor re-seal its copy.
Every copy is dropped at startup if a build that does not keep them ran in
between (a rollback attempt through an older build) or if the previous run
could not read the enrollment; a start that cannot drop them serves none and
removes the epoch, so the next start drops them instead. Telling which build
ran last relies on the last-run record, which builds from before 2026-09-25
never write; a run of one of those reads as unknown, which drops the copies. Changing the phone's enrolled Face ID
invalidates both phone keys, and with them every wrap; a lost phone still
needs its owner's Face ID, and `csec remote disable` removes the pairing and
every copy. A copy whose delete fails can no longer open (the enrollment that
wraps its key is deleted regardless), and every start with no phone paired
deletes what is left. A daemon restart keeps nothing open: each approval's unlock is
dropped when its one release, signature or restore finishes.

A mailbox writer (anyone controlling the iCloud account) cannot crash csecd
with a malformed record, steer its sweeps, or block the pinned phone's answer:
record names are built only from canonical identifiers and checked before any
CloudKit call, csecd withdraws only records it can prove are its own (the
pairing's Mac key signs them), each phone answers in a slot named for it, and
csecd deletes a response it refuses or cannot decode. Such a writer can also
replay an older signed phone status after a csecd restart: csecd keeps the
newest status it has seen in memory only, so diagnostics can show an older app
version or notification state until the phone next publishes. That affects
`csec doctor`'s rows, never an approval. It can also make a request from a Mac
that stopped for good look live, by saving that record again, so the phone
shows a card nothing will act on: the save time decides only whether the phone
shows a request (`docs/remote-approval.md`, "Liveness"), and such a writer
could already put an old signed request back. The phone has one key-agreement key
for every Mac it pins, so a Mac whose csecd identity were taken over could use
the phone's answers as a key-agreement oracle against another pinned Mac's
enrollment; that needs a compromised csecd on one Mac, outside the
opportunistic attacker this design targets.

Pairing offers add no authority. A mailbox writer can leave the phone an offer
of their own Mac key, signed by that key and made to the phone's public ID and
keys — exactly what handing over a forged code to paste would do. The phone
shows it only with that key's fingerprint, to compare with the one `csec
remote enable` printed, and pins nothing without Face ID. An offer that would
replace a pinned Mac — its Mac ID, or its name — shows the key pinned now
beside the new one, so a key swapped under a known Mac is visible before the
Face ID. Even a phone that
pinned the wrong key gives its holder nothing on the real Mac, which accepts
only answers to its own signed requests. A writer can also delete an offer,
which only means the code is pasted instead.

Notifications add one surface. The alert push carries only fixed text; the
phone's notification service extension replaces it with the request's heading,
the pinned Mac's name, the command line and the requester only after the
request's Mac signature verifies against a pinned Mac, so a mailbox writer can
make the phone show a verified request's words or the fixed text, never its own.
The words are the same value-free review metadata the card shows, now also on
the lock screen as far as the iPhone's Show Previews setting allows; they pass
through Apple's push service only as the fixed text. The alert waits 30 seconds
while the Mac's prompt could be answered there (none while the Mac is locked or
asleep, or cannot evaluate Touch ID). That delay decides nothing — the request
is on the phone from the start — so a Mac that reports itself attended when it
is not only delays the notification, not the approval.

The iPhone app installed by `build-and-install.sh` is development-signed. The
installer re-signs it without `get-task-allow`, so no debugger can attach
through the phone's developer tunnel, but same-user code on this Mac that can
use the development signing identity can still re-sign and reinstall a
modified app that keeps the phone's Secure Enclave key handles, and have it
sign the Mac's own request on the next Face ID. That needs an attacker aimed at
csec. TestFlight or App Store distribution, which Apple signs, closes it only
together with Developer Mode turned off on the phone: Developer Mode is what
lets a development-signed build (from Xcode, or an .ipa through Apple
Configurator) install and run at all, so while it is on, this Mac can still
put such a build over the distributed app. Both are required before this is
called released (csec-vo4.14).

Outside this model, as elsewhere: code running with csecd's own signing
identity, and a person who approves on the phone a request they did not read.

### Output redaction

Supervised `csec exec` redacts eligible values from stdout, stderr, or a PTY that
it owns. `csec ai` (the coding-agent hook broker; `tool-exec` is its deprecated
alias) both injects resolved references into the child and scans its output
against `csecd`'s active-value registry before returning it to an AI tool. Both
handle split matches and a bounded set of canonical encodings. The AI broker
never forwards unscanned output. Its matcher holds every value `csecd` has
released in its lifetime, not only this command's, so a matcher a restarted
`csecd` would build starts empty and is never swapped in mid-command. If
scanning is lost while the command runs, a command `csecd` delivered values to
is terminated; one it delivered nothing to, whose `csecd` has exited (an update
restarts it), runs to the end with the rest of its output — including any start
of a secret the matcher was still holding back — withheld and its own exit
status, and any other scanner failure terminates the command. Selecting
withholding emits one fixed wrapper-authored stderr
notice explaining that it is waiting for the command's exit status. This notice
contains no child output, scanner error text or secret metadata; the final
withheld-byte summary is unchanged. Before the command starts, a transient
daemon restart gets a brief bounded reconnect. An automation run is the
exception: its lease survives the restart, so its
launcher holds the output, swaps in a scanner from the restarted csecd once
that csecd confirms the lease, primes it with the preceding output and scans
on. That matcher knows only the restored leases' values, so a value a
descendant got another way before the restart is not masked afterwards (see
[`automation.md`](automation.md)).

This prevents eligible bytes from crossing those specific supervised output
paths. It does not prevent the local read itself, detect every transformation,
or cover files, network writes, alternate descriptors, non-Bash AI tools, or
commands that bypass the optional hook. Registry entries are memory-only: one
released under a bounded grant expires with it, one released for a process
lifetime (the default) stays until the daemon restarts, and all disappear then.
A rotated reference keeps both values: the old one and the new one were both
released, so both are matched.
The matching interface also exposes a bounded equality oracle to callers able to
execute the genuine signed launcher.

A `csec ai` program the classifier finds secret-free receives no secrets, so it
activates none for redaction either. Its output is still scanned against every
value csecd released earlier and still holds, but a `cat` of a plaintext copy of
a reference csecd has not released in its current lifetime prints unredacted. A
secret-free command may also run programs its tools are configured, rather than
asked on the command line, to run — git textconv and external diff drivers,
`core.fsmonitor`, flags from `RIPGREP_CONFIG_PATH`, a pager when stdout is a
terminal — and aliases, functions and options from the user's zsh startup files
apply to `/bin/zsh -lc` without the classifier seeing them. The classifier also
cannot see what a listed bare name resolves to: with a project directory on
`PATH` (direnv's `PATH_add bin`), `cat` or `diff` may be the project's own
program. It checks the options of only some listed tools, so a listed tool
whose own script language runs programs (GNU `sed`'s `e` command, when `sed`
resolves to GNU sed) is not refused. `bd` runs what it is configured to: its
`.beads/hooks` scripts, a credential command, a pager, and the `gh` that
closing a gate issue checks; a `gh` that needed a token from a reference
fails visibly. A command in the administrator's local list
(`/etc/csec/secret-free-commands.json`) is taken on the administrator's word: it
runs what it is built and configured to, and nothing checks that its listed
subcommands need no secret. Were one to ask csec's bridge for a secret, its
nested request would still be judged as part of its command, as any command's
is (DESIGN.md, Nested requests).
And because the reference variables are
removed, an existence check such as `test -v NAME` sees them unset. All of this
is acceptable: such a program receives no secrets and no reference variables,
and its output is still scanned; a program that needed a secret fails visibly.

In Claude Code, a command made only of git commands
(`AICommandGitPassthrough`) runs unwrapped, so Claude Code's worktree isolation
can read the git it runs, and an agent isolated in a worktree can push. Its output is not scanned at all: a released value in a
tracked file, a commit message, git's configuration or a remote URL reaches the
model as it is, and so does the output of the programs git's configuration
starts (hooks, `!` aliases, pagers, diff and textconv drivers, `gpg.program`).
An agent that can write `.git/config` can therefore have git print what it
likes unmasked; output masking was never a boundary against a deliberate agent,
only against accidental disclosure on the supervised path, and this trade-off
is accepted for git alone. Such a command gets no secret either: its
environment keeps the references unresolved, so a git hook or credential helper
that needed an injected value fails visibly. An alias, an environment prefix,
an option that runs a program the command line names (`--upload-pack`,
`--receive-pack`, `clone --template`, `submodule foreach`, …), `ls-remote`,
`remote`, `lfs` and every compound with another program keep the wrapper:
Claude Code's auto mode approves a bare `git ls-remote` (which reaches the
remote), `git remote -v` and `git remote show -n` without its classifier, so a
registration of one would vouch for a command no classifier judged.

A wrapped command hides its git from that guard, which judges only the
`csec ai -- '…'` it is about to run, and refuses it only when the operand starts
with git or a shell, or holds a quote, backquote, `$` or backslash and has a
word that names git or a shell. So in a session or subagent Claude Code has isolated in a worktree,
csec's hook refuses (`permissionDecision: "deny"`, with a reason the agent sees)
any wrapped command that names git unless git can only run directly in the
worktree (`AICommandWorktreeEscape`): nothing that moves the shell out of the
worktree or changes what git reads, git with no `-C`, `--git-dir`,
`--work-tree`, `--bare` or `-c`, and every other mention of git reaching only
programs that never run what they read. Without it, `cd <main checkout> && git
commit && git push`, wrapped, committed and pushed in the shared checkout
(csec-jmjy). Isolation is read from the hook's `cwd` (inside
`<repo>/.claude/worktrees/<name>`) or its `transcript_path` (the project
directory Claude Code names after that worktree). A session whose shell has
left its own worktree (the guard passes a plain `git … && cd <dir>`) is refused
every wrapped command that names git until a plain `cd <worktree> && git …`
takes it back, and a missing `cwd` is refused the same way. A command naming
git that passed this check is wrapped with a leading space (`csec ai -- ' git
log | head'`), a no-op for the shell, so the guard no longer refuses it merely
for starting with git: it judges it as it already judged `true && git log |
head`, so nothing runs that could not run before. A command naming no git keeps
the ordinary form and every rule the guard has for it (csec-m8sl). Its limits are the
guard's: it is a check against accidents, so a program that runs git itself (a
build script, `make`, a git `!` alias defined earlier) or a name spelled to hide
it (`$'\x67it'`, a variable from the environment) passes, and a worktree Claude
Code placed elsewhere (a `WorktreeCreate` hook) is not recognised. The `bd` and
`gh` it trusts with text naming git can run programs of their own (`bd edit`'s
editor, `gh`'s git), which no command line here chooses.

An SSH signing such a command asks for has no `csec ai` above `ssh`. csecd
delegates it only when the command reaches a remote (`push`, `fetch`, `pull`,
`clone`, `submodule`), which the hook registered, marked
unwrapped, and only through Claude Code's Bash tool shell: the direct child of
P whose kernel argv is `/bin/zsh -c` with exactly one `eval` of one literal
word, that word being the registered text (`ClaudeToolShell`). The gates are
the same as under a `csec ai`, and as there (csec-0.11) nothing between the
anchor and `ssh` is judged and no pairing is asked for. What this anchor
rests on, beyond the `csec ai` one:

- **The tool shell is `/bin/zsh`, not csec.** Under a `csec ai` the signed csec
  launcher vouches that it runs the program in its argv. Here only the
  kernel's copy of the shell's argv says what it evaluates, and that copy can be
  rewritten by code running in that shell. Code that ran there first is Claude
  Code's shell snapshot (`~/.claude/shell-snapshots/…`, sourced before the
  `eval`) and `~/.zshenv`. Same-user code that can write either file can already
  steer a wrapped command the same way: the snapshot runs in the same shell
  before `csec ai`, and the program shell reads `~/.zshenv`, `.zprofile` and
  `.zlogin`, any of which can define a function named `git`. So the startup code
  upstream of git is the same code, and every git link's argv must still match
  the approved text.
- **Only a fresh shell binds.** The registration must reach csecd before the tool
  shell started, and an exec keeps the start time it was forked with. So a
  long-lived child of P (an MCP or LSP server, a hook process) that execs a
  look-alike shell cannot bind a registration made after it was started, and a
  direct child of P that is started later can be only what P starts: a Bash
  call's shell, a hook, the statusline command. The forgery of the delegation
  flow by a direct child of P (above) is unchanged by this.
- **Claude Code's framing is read with bash's grammar.** The script is Claude
  Code's own text, and the command sits inside single quotes in it, where
  neither shell reads anything; Claude Code spells each `'` as `'"'"'`, which
  never puts two single-quoted strings side by side, so zsh's `RC_QUOTES`
  cannot read it differently. A framing csecd cannot read (another shell, the
  `-l` Claude Code adds when it has no snapshot, a second `eval` such as the
  credential-scrub framing's `\builtin eval` probes, a sandbox wrapper, or a
  `CLAUDE_CODE_SHELL_PREFIX` other than csec's own) has no anchor, and the
  panel asks.
- **csec's own shell prefix is the `csec ai`, directly under P.** With
  `csec setup shell-prefix`, Claude Code runs each Bash call as
  `csec ai --claude-code-shell <framing>`. That process anchors only when its
  framing passes the same reading, and it binds only a wrapped registration of
  the framing's `eval` word that arrived before it started. A lazily bound one
  must also be the signed launcher. A forged prefix process is therefore no
  stronger than the direct child of P above. The prefix value comes from
  settings or the environment, which same-user code can write; the gates accept
  only the installed bundle's own script path, set once. Pointing the prefix
  there gives that code nothing it lacked. Any other value declines as an
  injected environment. Text with no framing markers (hooks, MCP servers) runs
  unwrapped, as it did before; csec never wrapped it. Claude Code also
  rewrites `>nul` to `>/dev/null` in a command with no `<`, `$` or backquote,
  so such a command's tool shell evaluates text the hook never registered, and
  the panel asks.

### Setup and onboarding

`csec setup` reports names, paths, logical references, modes, counts, and
posture—not discovered plaintext values. Its bounded environment/dotenv scan is
not a secret scanner and is intentionally incomplete. Secret material can still
exist in ignored syntax, non-secret-shaped names, Keychain, shell files/history,
credential helpers, cloud profiles, IDE state, containers, CI, logs, backups,
and provider-side copies. The generated prompt treats every discovered
identifier as untrusted metadata and asks a coding agent to investigate those
gaps without values or mutation; a filename can still disclose sensitive
business metadata even when it contains no credential bytes.

Agent-hook apply rejects symlinked, hard-linked, non-user-owned, or
group/other-writable configuration files, unsafe parent directories, ambiguous
or duplicate-key JSON, recognized csec-handler conflicts, and a file whose
bytes/mode/device/inode changed after planning. It atomically creates or replaces
one configuration file and preserves unrelated parsed JSON. Re-serialization
can change formatting. User-level configuration is not a same-UID boundary, and
setup cannot approve client trust, override managed or project settings, prove
which hook wins a competing rewrite, or make a disabled/non-running hook
effective. Those remain explicit post-setup verification targets.

Import accepts only an exact plaintext candidate selected in argv by its
value-free locator. The value itself is re-read into the signed launcher's heap,
bound to the dotenv file version observed in the same apply process,
reclassified, and sent only over the authenticated native-store edit protocol;
references are not resolved or copied. Touch ID gates the store edit, and
existing keys require explicit replacement. The source remains
ordinary plaintext and readable by the same-UID attacker until the user verifies
the new consumer and separately removes every original/copy. Setup does not
rotate a provider credential, prove the old source is unused, or make deletion
from APFS/backup history secure. Multiple target updates are not one transaction,
so a reported partial apply must be completed or reviewed by repeating setup.

### Release manifest and update notice

csecd fetches a small release manifest once a day and announces a newer
release; it never downloads or installs anything
([`release-manifest.md`](release-manifest.md)). A manifest counts only with an
OpenSSH file signature, in its own namespace, by an Ed25519 key compiled into
the running build, so the server, the network path or a same-UID process
writing csec's Updates folder cannot announce a release of their choosing. A
held manifest is verified again on every read, and one numbered below the held
copy is refused, so an older signed manifest replayed later cannot hide a
release; a first install, holding nothing, cannot detect a server that only
ever serves an old manifest. What an attacker with the signing key gains is
bounded by what csec does with a manifest: it can announce a release and its
download address (csec shows the address; the package it points to must still
be Developer-ID signed and notarized for macOS to open it, and installing it
is the user's act), and, once the audited Claude Code list shares this
manifest, admit a Claude Code image for delegated approval. That key is
therefore held by a signing service behind its holder's biometric approval,
never as a file on the release Mac or in its everyday Keychain, and a
replacement key reaches buyers only in a release signed by one they already
trust. The fetch carries no identifiers (no cookies, query, version or
per-install value); the server still sees the Mac's IP address and the time
of each daily check. The check's unsigned bookkeeping file can at worst
repeat or suppress one notification.

The package refuses to install over a higher release (`preinstall`), and its
postinstall restarts every running csecd so no user keeps the replaced code;
both run as root from the signed, notarized package and add no new privilege.

## Explicitly exposed interfaces

- `csec exec` places plaintext in the child's initial environment. Output
  masking does not make that environment private. The trusted review warns that
  the initial environment is inspectable by other same-user processes, and one
  Touch ID authorizes it; running the command is the intent.
- `csec get` prints plaintext to a terminal, a shell-delegated pipe (including
  command substitution), or an explicitly approved ordinary file. Signed
  `csec` is the emitter; the kernel-verified direct-parent shell is the
  requester, subtree grant owner, and authorization delegate. The daemon
  rechecks that shell incarnation before provider resolution and `csec` checks
  again before output, so a different, exited, reparented, PID-reused, or
  exec-replaced shell cannot use the grant.
- Generic Unix pipelines do not let `csec` identify or authenticate the sibling
  reader. The review calls it an unverified pipe reader; approval authorizes the
  shell's delegation, not the reader's identity or behavior. That reader can
  retain, copy, log, or forward the value.
- `csec get > file` is ordinary persistent plaintext, not protected
  `exec-file` delivery. Same-UID processes may read it, and later access,
  copying, synchronization, and backup are outside csec's control. The shell may
  create/truncate the target before csec runs; csec sends no filename in protocol
  metadata and resolves/writes no plaintext before approval.
- `csec setup --import` reads each explicitly selected plaintext source into the
  signed launcher's heap before merging it into the native encrypted store; it
  does not erase the source.
- The Ruby and Node.js clients return ordinary language strings to application
  code; neither can revoke or erase every runtime copy after delivery.
- `csec creds aws` and `csec creds git` intentionally return plaintext over the
  credential consumer's private stdout pipe.
- `csec exec-fd` authorizes the launched process and any descendants retaining
  its descriptor to read the complete file payload.
- `csec exec-file` authorizes the complete capability-GID process tree to open,
  reopen, map, and copy its root-owned regular-file payloads until unlink; open
  descriptors can remain readable afterwards.
- Claude Code and Codex hooks cover Bash command tool calls only. Claude Code's
  hook is opt-in user configuration; Codex's is a managed, root-owned
  `/etc/codex/hooks.json` installed by `build-and-install.sh`. Neither hook
  grants a command anything: Claude Code's rules, auto-mode classifier and
  prompts still decide on the rewritten command, and Codex's `allow` envelope
  carries no permission. The one decision Claude Code's hook writes is a deny,
  for a command whose git could leave a worktree-isolated session's worktree
  (`AICommandWorktreeEscape`). Client permission rules see the rewritten
  `csec ai -- <command>` (Claude Code sees a plain git command as typed,
  `AICommandGitPassthrough`), so a Claude deny rule on the inner command becomes a
  classifier hint (auto mode) or a prompt (manual mode) rather than a hard deny,
  allow rules written for bare commands stop matching (manual mode prompts on
  every Bash call), and an allow rule for `csec ai` pre-approves every command
  (`csec doctor` warns). The managed Codex hook applies to every account on the
  Mac; Codex's `features.hooks = false` or `--disable hooks` turns it off, and
  after the app is removed it blocks every Codex Bash call until an
  administrator removes `/etc/codex/hooks.json`. Codex commands its dangerous-command check, `prompt`/`forbidden`
  rules or `apply_patch` interception could catch run unwrapped, without output
  scanning, so Codex's gate still applies; a Codex rules file csec cannot read
  leaves every Codex command unwrapped. A hook that times out (30 s) lets the client run the original
  command unwrapped. With delegated approvals on, Claude Code's hook also
  registers each command with csecd, and a command the classifier approved may
  receive references paired with its project with no csec panel (see
  [Delegated approval](#delegated-approval)).
- A `csec ai` command classified secret-free runs with no reference variables
  and activates no value for output redaction.

## Required deployment posture

All security claims require a Developer-ID-signed, hardened, notarized,
provisioned build with the exact product identities, the restricted keychain
access group, no `get-task-allow`, no dangerous Hardened Runtime exception
entitlements, and SIP enabled. Protected-file claims additionally require the
exact signed helper under `/Library/PrivilegedHelperTools`, its root-owned and
non-writable system LaunchDaemon plist, the verified bounded tmpfs mount, and a
passing signed-device matrix. Sudo review claims additionally require the
module and helper this source tree builds, installed by `build-and-install.sh`
under a root-owned, non-writable `/usr/local`, with `sudo_local` ordering the
review, its `review_guard` and `pam_tid` as
[The sudo review surface](#the-sudo-review-surface) describes; `csec doctor`
reports the drift it can see. The production startup self-audit refuses to run
when its required posture is absent or when neither the native store nor a
verified official 1Password CLI is available.

Delegated approval additionally requires `autoMode.classifyAllShell: true` in
the Claude Code user settings, where `csec setup` writes it (managed policy
settings count only when every non-empty policy source sets it; project
settings never do): it is what stops Claude Code's allow rules, including the
session, command and argument rules no file shows, from approving a Bash call
without the classifier. csecd declines every request whose session's settings
lack it. It also requires a Claude Code build signed by
Anthropic, or one the human trusted by cdhash, and csecd's protected Keychain
items; without them delegation stays off.

## Irreducible boundary

Once an authorized consumer receives plaintext, it can use or disclose it. The
system narrows release to a human-approved reference set and process scope; it
cannot make compromised consumer code safe. Secret rotation and revocation also
remain provider operations rather than automatic consequences of a redaction
event.
