# Wire protocols

Convenient Security has three local protocols:

1. protocol v2 between the signed `csec` launcher/bridge and `csecd`; and
2. root-helper protocol v1 between exact signed `csec`/`csecd` roles and
   `csec-rootd`; and
3. a one-shot private-pipe protocol between a language client and `csec bridge`.

Neither treats a pathname, PID supplied in JSON, or same-UID ownership as an
identity boundary.

## Authenticated agent socket

**Transport.** `AF_UNIX` / `SOCK_STREAM` at the canonical per-user temporary
path `…/convenient-security-<uid>/agent.sock`, inside a `0700` directory.
Release binaries compile out `CSEC_SOCKET`; only debug integration builds can
select a synthetic endpoint.

**Framing.** Each message is a four-byte big-endian length followed by that many
bytes of UTF-8 JSON, capped at 8 MiB. Socket writes have `SO_NOSIGPIPE`, so a
rejected peer produces a transport failure rather than terminating the client.
Ordinary requests use one frame/response and close; an active-output redaction
session reuses one authenticated connection for bounded streaming chunks. All
listener, accepted, and client socket descriptors are close-on-exec so a
supervised child cannot inherit the authenticated channel.

**Mutual identity before JSON.** Both endpoints read the complete kernel
`audit_token_t` using `LOCAL_PEERTOKEN`. They retain PID, PID version, effective
UID, audit session, process start time, executable path, and the opaque token.
For every connection, and again before every response, the kernel reports
from that token whether the image is still `CS_VALID`, and its cdhash, signing
identifier and Team ID (`csops_audittoken`, which refuses a token from before
an exec). The first time a cdhash connects, Security.framework resolves the
live `SecCode` from the token and validates its signature, certificate chain
and requirement; a long-running endpoint (csecd, the root helper) keeps each
success for its lifetime and answers later connections of that cdhash from the
kernel's facts alone, with no trustd round trip. A cached verdict therefore
outlives a revocation of the signing certificate until the daemon restarts,
which every install does; see `docs/threat-model.md` §Peer authentication.

- `csecd` accepts only Team ID `8RS6GD89Y7` with signing identifier
  `com.alexspeller.convenient-security.csec` and the compiled Developer ID
  requirement, or the same Team ID and requirement with the sudo review
  helper's identifier `com.alexspeller.convenient-security.sudo-review`. Each
  role sends only its own requests: the helper nothing but
  `sudo_remote_review`, `sudo_delegation`, `sudo_pairing`, `sudo_terminal` and
  `sudo_review_end`, the launcher everything but those. Any other request from either is answered
  `unverified_peer` before its handler runs.
- `csec` (and the sudo review helper) accept only the same Team ID with
  signing identifier `com.alexspeller.convenient-security`.
- Both require the current login UID. An unsigned or replacement process is
  rejected before a request is read or written.
- Immediately before sending **each** response, `csecd` resolves the peer again
  and requires the same audit token and valid launcher (or helper) code. An
  image change during consent/provider resolution or a streaming session
  therefore cannot receive the response.

Fake peers are possible only through explicit test constructors in debug/test
executables. A shipping environment variable cannot relax trust.

## Liveness: bounding the daemon's silence, never the human's wait

A wedged `csecd` — a deadlocked main actor, a hung synchronous call, SIGSTOP, an
actor that never resumes — used to hang every `csec` command until the user
pressed Ctrl-C. A plain read timeout cannot fix that, because the legitimate
wait for a human is unbounded: a prompt cancelled behind the lock screen waits
for unlock and re-presents, and a remote approval on a phone may be answered an
hour later. So what is bounded is the daemon's **silence**.

**Opt-in.** A client that can read liveness frames says so with one extra
top-level boolean beside the request body:

```json
{"version":2,"type":"schemes","supportsHeartbeats":true}
```

The key is transport-level, not part of any verb's payload. `csecd` decodes
requests through a keyed container, which ignores keys it does not know, so an
older daemon reads the request exactly as before. A client that does not send
the key — every language client through `csec bridge`, and any future direct
foreign client — is never sent a heartbeat, and its exchange is byte-identical
to a pre-heartbeat daemon's.

**The frame.** While a request from an opted-in client is being handled, the
server writes this frame on that connection every 5 seconds until the real
response goes out:

```json
{"version":2,"type":"heartbeat"}
```

It carries no request id and no payload; its entire meaning is "this daemon is
still running your request". `Response` has no `type` key, so the discriminator
cannot collide with a real response. Frame writes on a connection are
serialized, and the heartbeats for a request are retired when its response is
written, so a heartbeat can never interleave with or follow a response.

**What a tick proves.** Every human-blocking path — the access, SSH and
automation reviews, and the re-present after a screen unlock — presents its
window on the main actor, so each tick round-trips through the main actor before
it is written. A tick emitted from a detached background task alone would keep
flowing while a deadlocked main actor held the prompt hostage, masking exactly
the wedge this exists to catch.

**The client side.** The Swift client opts in and reads with a deadline of 20
seconds (four intervals) of **silence**. Any frame — heartbeat or response —
restarts it, so an hour-long human wait is fine; only a daemon that has stopped
talking altogether trips it, and the client then fails with a message naming the
wedge and `csec doctor`, which restarts the daemon. The same bound applies to
every client read path (plain requests, the active-output redaction session, and
the streaming host-audit poll handle), along with a 5-second connect bound (a
wedged daemon that never calls `accept()` fills its listen backlog, after which
a blocking `connect()` waits forever) and a 10-second write bound. `csec ai`
never hard-gates on any of these: it warns on stderr, names `csec doctor`, and
runs the command with references left unresolved.

The deadline is armed from the first read rather than from the first heartbeat.
A newer `csec` cannot reach an older `csecd` in practice: replacing the
installed image makes the running daemon fail the socket peer code-identity
check ("the socket peer has an unexpected code identity") until `csec doctor`
restarts it, so a mismatched-but-valid pair does not occur. Were one to occur,
a long human wait would surface the unresponsive error and the named fix
restarts the daemon into a matching build.

**Connection lifetime.** An accepted connection must send its first frame within
30 seconds; a peer that connects and then says nothing is closed rather than
parking a handler for the life of the daemon. The gap *between* frames on an
established connection is deliberately unbounded — the active-output redaction
session holds one connection open for streaming chunks, and a long-running child
may legitimately produce no output for many minutes. The csec SSH-agent socket
applies the same rule for the same reason: `ssh` asks for identities as soon as
it connects, but one session may then go quiet between signatures for the length
of a transfer.

An open connection must therefore cost csecd nothing but its own thread. Every
call that blocks on a connection — its socket reads and writes, and the
code-signature checks of its peer — runs on that connection's own serial
dispatch queue, never on Swift's cooperative thread pool. The pool has one
thread per CPU, so when the reads ran there, as many quiet clients as the Mac
has CPUs (sixteen `csec ai` commands producing no output) left csecd accepting
connections it never answered.

**A requester that leaves.** While a request is in flight the server watches for
the requesting client going away (a non-destructive `MSG_PEEK`, which leaves a
queued next frame in place, so a streaming client is never mistaken for a dead
one) and cancels the handler when it does: a prompt whose requester has exited
is a decision nobody can act on, so the panel closes and the request resolves as
not-approved. This watch applies to every client, heartbeat opt-in or not,
because it reads nothing of the protocol.

**Notices.** A client that prints for a person (`csec ai`, `csec exec`,
`csec get`) may also send `"supportsNotices":true` beside
`supportsHeartbeats`. Only then may the server write, mid-request:

```json
{"version":2,"type":"notice","message":"waiting for approval on the Mac or iPhone: secret access to op://Example/item/password. If nobody answers, csec withdraws it at 22:14 (20 minutes after it was asked) and the command fails."}
```

A notice never satisfies the request; the client prints it and keeps reading.
It is sanitized and fitted to 512 bytes on both sides, retired with the
request's heartbeats when the response is written, and sent only for a coding
agent's request that has started waiting on a human (a queued turn, the UI
queue, a panel or the restore panel), once. It says "on the Mac" rather than
"on the Mac or iPhone" when the paired phone cannot carry the request
(`RemoteReviewReadiness.unavailable`, judged before the notice is sent), and a
request told the phone could answer that is judged again at its turn in the
queue and found not to be gets one more notice, "the iPhone cannot approve this
request, so it is waiting for approval on the Mac: …". A client that did not opt in is
never sent one, and one that arrives anyway is refused. Without the key the
request frame is byte-identical to before.

**A coding agent's request nobody answers.** A request with Claude Code or
Codex above its requester (judged from live ancestry, as the coding-agent
scope is) is withdrawn when nobody has decided it a set time after it reached
csecd: 20 minutes by default, `defaults write com.alexspeller.convenient-security
CodingAgentApprovalWaitMinutes -int <1–1440>`. Each request has its own clock, so
requests queued behind one unanswered panel all lapse together. Withdrawal is
the cancellation a departed requester gets (a queued request leaves its queue,
a panel closes and its phone copy is withdrawn), and the reply is
`consent_denied` with the message "approval was not given: nobody answered
within 20 minutes, so csec withdrew the request and released nothing (…)". An SSH signature fails, and the same `ssh` is refused its next key
at once. A human decision made before the deadline stands: the review marks the
request decided as it returns, and the deadline withdraws only an undecided one.
A request with no coding agent above it waits as long as it takes.

## Version and capability negotiation

The current version is 2. A client may send:

```json
{"version":2,"type":"capabilities"}
```

The response advertises supported versions and features:

```json
{
  "version": 2,
  "capabilities": {
    "supportedVersions": [2],
    "features": [
      "typed_failures",
      "delivery_plans",
      "peer_code_identity",
      "plan_digest_binding",
      "output_guard_binding",
      "active_output_redaction",
      "native_encrypted_store",
      "native_editor_policy",
      "registered_session_roots",
      "credential_protocols",
      "inherited_file_descriptors",
      "protected_regular_files",
      "unattended_automation",
      "liveness_heartbeats",
      "delegated_approvals"
    ]
  }
}
```

`schemes` remains a value-free provider capability query:

```json
{"version":2,"type":"schemes"}
```

With both providers available it returns
`{"version":2,"schemes":["csec","op"]}`.

The response may also carry `providerStatus`: one bounded, value-free health line
per provider that offers one, which `csec status` renders. It is optional, so a
client that does not know the field simply ignores it.

```json
{"version":2,"schemes":["csec","op"],
 "providerStatus":[{"label":"1Password",
                    "detail":"2 accounts, 18 vaults indexed","healthy":true}]}
```

## Access v2

An access request has a fresh UUID nonce, exact references, a bounded human
reason, an optional positive TTL (absent means a process-lifetime grant; it
must equal the plan's `requestedTTLSeconds`), and a complete delivery plan:

```json
{
  "version": 2,
  "type": "access",
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "references": ["op://Vault/Item/field"],
  "reason": "boot rails",
  "ttlSeconds": 3600,
  "deliveryPlan": {
    "mechanism": "direct_heap",
    "executable": {
      "canonicalPath": "/usr/bin/ruby",
      "assurance": "unverified"
    },
    "root": {
      "kind": "direct_parent",
      "pid": 1234,
      "startTime": 999999999
    },
    "descendantScope": "subtree",
    "destination": "local_development",
    "requestedTTLSeconds": 3600,
    "operationContext": "boot rails"
  },
  "deliveryPlanDigest": "<sha256-of-canonical-plan-json>"
}
```

The plan itself binds only a SHA-256 command digest, never argv. The request
may carry the argv beside the plan as a display-only `commandLine` array (at
most 65,536 arguments and 1 MiB in total, no NUL bytes); when the plan has a
`commandDigest`, csecd rejects a `commandLine` that does not hash to it, so the
command the human reads is the one the grant is keyed on. Before the review
window shows it, csecd passes every argument through the same output-redaction
catalog `csec exec` output goes through — built from the values it has already
released and still holds live — so a released value pasted into a command is
shown as its redaction label. A request without `commandLine` (an interactive
`csec get`, SSH signing) is reviewed under its `reason` as before. `csec exec`
and `csec ai` both bind their argv this way. `csec ai`'s request always has the
same shape: `commandLine` is `["/bin/zsh", "-lc", <program>]` and the plan is
`AICommandExec.deliveryPlan` for `/bin/zsh` with no TTL and that argv's
`commandDigest` (`AICommandExec.isAIRequest` recognizes exactly this shape, which
is what a delegated approval starts from; the shape is not itself trusted). The
digest is outside the release shape, so the coding-agent grant still covers
every later `csec ai` command of a session. Plaintext is
forbidden in the plan and all other metadata. Compatibility
output plans can additionally carry one of the value-free recipient assurances
`interactive_terminal`, `unverified_pipe_reader`, or
`ordinary_persistent_file`. A regular-file plan never carries or derives the
redirection pathname.

For unrestricted-environment `csec exec`, the plan must additionally bind the
exact value-free guard configuration declared for the launch:

```json
"outputGuard": {
  "mode": "always",
  "labelStyle": "opaque",
  "includeShortValues": false,
  "matcherVersion": 1
}
```

Changing `tty`/`always` to `never`, opting into reference metadata, changing
short-value handling, or changing matcher semantics therefore changes the
canonical plan digest and cannot reuse a grant for the previous policy.

The language-client bridge and generic `csec exec` conservatively report
`unverified` consumer assurance even when `/usr/bin/ruby`, the Node.js runtime,
a shell, or another executable is root-owned: scripts, packages, plugins,
configuration, and the checkout remain user-writable. Only a dedicated
verifier/root launcher may assert an independently protected whole consumer
context.

Before resolution, the agent verifies:

- exact protocol version, UUID, field/count/TTL bounds (including 4 KiB per
  reference), absolute bounded executable metadata, canonical digest shapes,
  supported output-matcher version, and plan/TTL agreement;
- a recomputed canonical plan digest;
- that the socket peer is the verified launcher;
- a caller root; for bridge/credential consumers and every `csec get` stdout shape, a
  requested direct parent that is the launcher's real PPID with the same process
  start time and canonical executable; or a registered-session ID whose live
  PID/start-time root is an ancestor of the caller in the same audit session;
- when the direct-parent requester differs from the byte consumer, a separate
  `requestingExecutable` identity whose path, signature metadata, and
  writable-path assurance csecd independently recomputes;
- for `credential_protocol`, that the plan's consumer executable is the
  helper's current direct parent's canonical executable path; and
- the plan's mechanism, recipient, descendant scope, and the optional wall-clock
  TTL (`requestedTTLSeconds`, nil by default ⇒ a process-lifetime grant with no
  cap; `--for` sets an explicit, uncapped bound; the review window offers process
  lifetime plus opt-in 1h/12h); and
- that any existing grant has the same delivery-plan digest plus a live
  lineage relationship (kernel parents, with a detached job linked back through
  its session; DESIGN.md §Detached jobs).

The grant records the request ID, plan digest, peer PID version/CDHash, and
planned executable. A grant ends when its root exits, or at the bounded lifetime
the review chose; reuse is purely delivery-plan-digest plus subtree ancestry, so
there is no risk-shaped binding to go stale.
Every `csec get` stdout shape keeps signed `csec` as the emitter, binds its
verified direct parent as `requestingExecutable`, and uses that parent's exact
PID/start-time as a subtree grant root. The daemon repeats the live
PID/start-time/ancestry/executable check after review and immediately before it
can resolve a provider; the launcher repeats it before writing the response.
Consecutive compatible sibling gets from the same live shell can therefore
reuse a grant, while another shell incarnation cannot.

The three accepted compatibility triples are deliberately exact:

| Mechanism | Destination | Recipient assurance |
|-----------|-------------|---------------------|
| `raw_stdout` | `human_output` | `interactive_terminal` |
| `raw_stdout` | `shell_delegated_pipe` | `unverified_pipe_reader` |
| `named_plaintext_file` | `persistent_plaintext_file` | `ordinary_persistent_file` |

A generic Unix pipeline does not expose the sibling reader's process identity
through its write descriptor. The shell is therefore the authenticated
requester and grant owner, `csec` is the emitter, and the recipient remains
explicitly unverified; command substitution uses the same shape. For ordinary
redirection, `fstat` identifies only that stdout is a regular file. The shell
may already have created or truncated it, but csec sends no pathname and no
plaintext is resolved or written unless review and authentication succeed.

There is no compatibility-acceptance ledger. Each raw-output shape carries a
digest-bound `interactive` flag and — only when the user passed the shape-matched
override (`--reveal` for an observing sink, `--allow-plaintext-file` for a file) —
a `plaintextExposureAcknowledged` flag; csecd re-derives whether the
acknowledgment is required and refuses a shape that needs one but lacks it. The
terminal, pipe, and file shapes have distinct plan digests, so one never
authorizes another.

Success echoes the request nonce:

```json
{
  "version": 2,
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "values": {"op://Vault/Item/field":"…"},
  "accessExpiresAt": "2026-08-22T12:34:56Z"
}
```

The client rejects a missing/mismatched nonce or a values map whose keys differ
from the requested reference set. `accessExpiresAt` is the absolute,
policy-capped end of this access decision; protected regular-file approval must
not outlive it.

## Registered session roots

The signed launcher registers its current process incarnation before replacing
itself with `csec session`'s target:

```json
{
  "version": 2,
  "type": "begin_session",
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
}
```

Success echoes the nonce and returns a fresh random identifier:

```json
{
  "version": 2,
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "registeredSessionID": "ffffffff-1111-2222-3333-444444444444"
}
```

The daemon accepts registration only from a live mutually authenticated
launcher and records its kernel PID, process start time, and audit-session ID.
At most 64 registrations are retained; dead process incarnations are pruned and
re-registering the same incarnation replaces its older ID.

A descendant access encodes the root as
`{"kind":"registered_session","id":"<uuid>"}` and must declare
`broad_session` scope. The identifier has no independent authority: every
access performs a fresh lineage walk from the authenticated caller to the
recorded PID/start-time pair. A malformed, stale, forged, copied-across-tree, or
cross-audit-session ID is rejected as `invalid_request`, with no fallback.

A registered `broad_session` plan and an ordinary caller-root plan have different
digests and cannot share a grant, so registering a session never silently widens
an existing per-command grant.

## Grant scope and grant control

`access` carries no scope field. After the plan root is verified, csecd walks
lineage parents above it (kernel parents, with a detached job linked back
through its session) and offers the trusted review window up to three roots —
the requesting process, the nearest coding agent, and the outermost shell owning
a controlling terminal — with the coding agent pre-selected, else the terminal
session, else the requesting process. The window returns the selected option's
identifier in-process only; it is resolved against the list csecd built and
re-proved against live lineage before the grant is minted, so it authorizes
nothing by possession. A phone mirroring the review offers the same choices
with the same default and signs the one chosen. The mirrored review also
carries `terminalDescription`,
the same bounded terminal-tab line the Mac window shows, inside the signed
request.

A grant rooted at the requesting process is reusable only for an identical
`deliveryPlanDigest`. A grant rooted at a coding agent or terminal session is
instead reusable for a matching *release-shape* digest — SHA-256 over the
mechanism, descendant scope, destination, recipient assurance, output-guard plan,
`interactive`, and `plaintextExposureAcknowledged`, domain-separated by
`csec-release-shape-v1` — plus a matching audit-session ID. The executable,
command digest, operation context, and requested TTL are deliberately excluded.

The daemon queues consent presentation in FIFO order across access reviews,
standalone biometrics, and host remediation. A local/phone review race owns one
turn until its authentication session is consumed or cancelled and its window
has closed. Cancelling a waiting request removes it from the queue; denial or
cancellation of the active request advances the queue without deciding any
other request.

Access requests needing new consent also wait through the preceding request's
grant creation and initial resolution. At the front they repeat caller/root
validation and check the current grant table with a fresh clock. A preceding
approval may therefore cover parallel commands in the same approved scope and
release shape; new references or different shapes still require their own
review. Revocations and exited callers are respected after waiting, and a new
grant's lifetime starts at approval. Requests already covered by a live grant
continue without joining the consent queue. Queuing never widens an approval
or resolves a reference before authorization, regardless of its provider.

The `grants` request inspects or drops the live set:

```json
{
  "version": 2,
  "type": "grants",
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "action": "list",
  "all": false
}
```

`action` is `list` or `revoke`; `revoke` takes either `grantID` or `all`.

Every entry has a typed id: `grant-…` (a secret grant), `ssh-…` (an SSH grant)
and, only while delegated approvals are on, `pair-…` (a project pairing),
`build-…` (a trusted Claude Code build, by cdhash) and `hook-…` (an acknowledged
hook, by digest). Within its kind an id is lowercase hex and dashes; `csec
grants` prints the kind's prefix and its first eight characters. `grantID` is a
typed id or a prefix of one, matched only against entries of its own kind; a bare
hex id still names a secret grant.

A `list` reply carries `grants`, a value-free array of secret and SSH grants
(`{id, kind, rootPID, rootProcessLabel, scopeKind, references, reason, expiresAt,
ssh, restored}`), and, while delegated approvals are on, `delegationGrants`:

```json
{"pairings": [{"id": "…", "projectPath": "/Users/me/src/app",
               "references": ["csec://app/API_TOKEN"],
               "ssh": [{"keyReference": "csec://app/deploy-key", "keyFingerprint": "SHA256:…",
                        "keyLabel": "deploy", "hostKeyFingerprint": "SHA256:…",
                        "hostNames": ["github.com"], "remoteUser": "git"}],
               "launchers": [{"path": "bin/deploy", "sources": ["bin/_common.sh"]}],
               "sudo": true}],
 "trustedBuilds": [{"cdHash": "<40 hex>", "versionLabel": "2.1.257", "path": "/…", "trustedAt": 0}],
 "acknowledgedHooks": [{"digest": "<64 hex>", "display": "cc-caffeine@samber · PreToolUse *",
                        "acknowledgedAt": 0}]}
```

`launchers` lists the project's pinned launcher scripts by checkout-relative
path, with the files each sources that were present when it was pinned; their
digests stay in csecd. Nothing pins one since csec-0.11 (an SSH signing auto
mode approved signs with no pin), so only a pairing written before then has
any, kept so it lists and revokes. A csecd that predates launchers sends none,
and the field decodes as empty. `ssh` is likewise only what a human approved
before csec-0.11. `sudo` says auto mode may run sudo in the project; a
csecd that predates sudo pairing omits it, read as `false`. `projectPath` is the path the pairing is keyed on: a repository's shared git
directory (`/Users/me/src/app/.git`, which `csec grants` shows as
`/Users/me/src/app (git repository)`), or a directory for a pairing outside a
repository or recorded before pairings were keyed on the repository. It is
kept out of `grants`, whose entries an older client decodes strictly.

A `revoke` reply carries `revokedGrantCount` and `grantRevocation.removed`, one
value-free `{kind, id, label}` per removed entry (the count equals the list's
length; a csecd without delegated approvals sends only the count). A prefix that
matches more than one entry of its kind removes nothing: the reply is an
`invalid_request` failure whose `grantRevocation.ambiguousMatches` lists every
match. `all` removes every secret grant, SSH grant and pairing; trusted builds
and acknowledged hooks are delegation settings, which only their own ids (or
`csec setup`) remove. Revoking a `build-` or `hook-` id does exactly what
`configure_delegation` `untrust_build` / `forget_hook` does.

Secret and SSH grants survive a csecd restart (not a reboot): csecd persists
them in a protected Keychain item and lists one it restored at startup with
`restored: true`. A `revoke` reply is sent only after
the removal is written there; if that write fails csecd deletes the whole item,
and if the deletion fails too the reply is an `internal_error` failure saying
the revocation holds only for this csecd run. Removing a pairing, a trusted
build or an acknowledged hook works the same way: it takes effect at once, and
if its item cannot be written the reply is that same failure.

Both actions require an authenticated launcher. Neither releases a value and
revocation only removes access, so neither is gated by Touch ID. The capabilities
`selectable_grant_scopes` and `grant_revocation` advertise this, and
`delegated_approvals` the delegation kinds.

## Delegated approvals

With delegated approvals on, csecd may release references a human already
approved for a project to a `csec ai` command that Claude Code's auto-mode
classifier approved, with no panel and no grant minted. The capability
`delegated_approvals` advertises the two verbs below. No environment variable,
argument or file can turn delegation on: only `configure_delegation` adds
authority, behind csecd's own Touch ID panel.

**`register_agent_command`.** `csec hook claude` sends it before it prints its
rewrite (or, for a git command it leaves unwrapped, before it exits with no
output). Claude Code runs nothing until the hook exits, so the registration
always precedes the `csec ai`, or the Bash tool shell, it describes.

```json
{"version": 2, "type": "register_agent_command",
 "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
 "client": "claude", "sessionID": "<session_id>", "toolUseID": "<tool_use_id>",
 "agentID": "<agent_id, subagents only>", "permissionMode": "auto",
 "hookCWD": "/Users/me/src/app", "programSHA256": "<64 lowercase hex>",
 "unwrapped": true}
```

- `programSHA256` is SHA-256 of the program `csec ai` will run
  (`AICommandHook.launchedProgram`): the hook's command, except that a bare word
  sequence has its spaces collapsed exactly as `csec ai` rejoins the words its
  caller's shell split, and that a command naming git, run in a worktree-isolated
  session's own worktree, is the command after one leading space
  (`AICommandHook.programToken`). The
  command text itself never crosses, and the digest is never logged.
- `unwrapped` is present, and `true`, only for a git command that reaches a
  remote and that the hook left unwrapped (`AICommandGitPassthrough`); its
  `programSHA256` is of the command exactly as typed, the text Claude Code's
  Bash tool shell evaluates. Absent, it is `false`; any other value is
  `invalid_request`. csecd binds an unwrapped registration only to the Bash
  tool shell that evaluates that text, when an `ssh` under it asks to sign
  (`ClaudeToolShell`), and any other registration only to a `csec ai`.
- The hook registers in every permission mode; csecd delegates only when it says
  `auto`, and declines any other mode with a reason the panel shows. A command
  the hook denies (a worktree-isolated session's git that could leave its
  worktree, `AICommandWorktreeEscape`) registers nothing.
- The ids are `[A-Za-z0-9_-]`, at most 128 bytes; `permissionMode` is
  `[A-Za-z]`, at most 32; `hookCWD` is absolute, at most 4 KiB, with no NUL; only
  `client: "claude"` is accepted. The hook sends nothing when a field is out of
  bounds, and csecd refuses such a request as `invalid_request`.
- The reply is `{"requestID": "…", "agentCommandRegistered": true}` (or `false`:
  delegation is off, or the peer is not eligible). The hook ignores it.
- csecd stores a registration only from the verified launcher whose kernel argv
  is exactly `<csec> hook claude`, run by a platform shell's `-c` under a Claude
  Code process. When that process's matching `csec ai` later sends an `access`
  request in exactly `csec ai`'s shape, csecd binds the newest pending
  registration whose digest matches the program in the request and in the
  peer's own kernel argv (compared byte for byte) and which csecd received
  before that `csec ai` started (both on the kernel's monotonic clock), then
  judges the command
  ([`DESIGN.md`](../DESIGN.md#delegated-approval)). An approved request gets its values in an
  ordinary access reply with no `accessExpiresAt`; a declined one gets its
  review panel, whose note names the reason.
- The hook's round trip has its own bounds (0.25 s to connect and write, 1 s of
  silence), does not opt into heartbeats (and treats one as a failure), is never
  retried and writes nothing to stderr, so a csecd that is down, stale or slow
  costs the hook at most about a second and a half, whatever its heartbeat
  interval, and means only that the command gets its ordinary panel. The check
  of csecd's signature before the request waits on trustd and has no bound of
  its own, so the whole registration runs under one more, 2 s overall: a stalled
  trustd otherwise held every hook until Claude Code's 30 s hook timeout, after
  which Claude Code runs the command without csec's wrapper. A registration
  given up on before it was sent is never sent; the hook still prints its
  rewrite, so the command stays wrapped and is only not delegated.

**`configure_delegation`.**

```json
{"version": 2, "type": "configure_delegation",
 "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "action": "status",
 "claudeConfigDirectory": "/Users/me/.claude-work", "projectDirectory": "/Users/me/src/app"}
```

`claudeConfigDirectory` (the launcher's `CLAUDE_CONFIG_DIR`) and
`projectDirectory` (its working directory) are optional absolute paths naming
whose Claude Code settings the status and the inventory cover.

| `action` | Also carries | Touch ID | Effect |
| --- | --- | --- | --- |
| `status` | — | no | reports the state |
| `enable` | `setClassifyAllShell` and `claudeSettingsPath` (both required) | yes | turns delegation on, trusting every untrusted build and acknowledging every other approving hook csecd finds; re-confirms after a policy version change |
| `trust_build` | `target`: the build's absolute path | yes | trusts that build by the cdhash csecd computes |
| `untrust_build` | `target`: a `build-` id | no | stops trusting it |
| `acknowledge_hooks` | — | yes | acknowledges every approving hook, and every source's auto-mode classifier rules, csecd finds that is not yet acknowledged |
| `forget_hook` | `target`: a `hook-` id | no | forgets that acknowledgement |
| `disable` | — | no | turns delegation off, deleting its settings and every pairing |

The Touch ID step is csecd's settings panel (the settings layout of its review
window, typing-guarded like every approval), listing what csecd found and naming
the terminal (and, for an `enable` whose
`claudeSettingsPath` differs from the recorded one, both files); a refusal fails with `consent_denied`, whose
message says why the sheet ended ("you pressed Deny", a sheet macOS dismissed, a finger not recognised, with how
long it was up), and changes nothing. An approval adds exactly what the sheet listed to the settings
as they are then, so an `untrust_build` or `forget_hook` made while the sheet
was up stays made; if delegation was disabled meanwhile, the approval changes
nothing and the reply is a `policy_denied` failure. `setClassifyAllShell`
records whether `csec setup` itself added
`autoMode.classifyAllShell`, and `claudeSettingsPath` the Claude Code user
settings file it edited (absolute, at most 4 KiB, no NUL, no empty, `.` or `..`
component, ending in `/settings.json`). csecd keeps both and returns them in the
status, so disabling and uninstalling revert exactly that file, and remove the key
only when csec added it, even if `CLAUDE_CONFIG_DIR` differs later. Every
successful reply carries `delegationStatus`, the state after the action:

```json
{"state": "on", "policyVersion": 1, "consentedPolicyVersion": 1,
 "setClassifyAllShell": true, "claudeSettingsPath": "/Users/me/.claude/settings.json",
 "trustedBuilds": [], "acknowledgedHooks": [],
 "discoveredUntrustedBuilds": [], "settings": {…}, "pairingCount": 2,
 "counters": {"approved": 14, "declined": 3}, "lastDecline": "…",
 "identityLookup": "audit-token (exec-exact)"}
```

`state` is `off`, `on`, `reconfirmation_required` (enabled under an older policy
version, so off until `csec setup` confirms again), `unreadable` (the settings
item cannot be read: off, and a bad status row) or `unavailable` (no protected
stores). `settings` is csecd's own reading of Claude Code's settings for the
scope: where `autoMode.classifyAllShell` is set, every other hook that can
approve a Bash call with its digest (with `kind` `classifier_rules`, a
settings source's auto-mode classifier rules, whose `ruleDigests` hold one
32-hex digest per rule), injected-environment names in settings
`env` blocks, sandbox, bypass and disabled-hook settings, and every file it
could not read. An acknowledged source of classifier rules carries
`classifierRules: {sourceID, ruleDigests}` in `acknowledgedHooks`, which
`csec setup` diffs the file against to show what changed; `grants` lists it
with no digests. `counters` and `lastDecline` cover this csecd run only.
`untrust_build` and `forget_hook` also carry `grantRevocation`, exactly as a
`grants` revoke does, including the ambiguity failure.

`lastDecline` is the last decline's panel text, bounded; `csec status` shows it
without the "Auto mode didn't approve this: " prefix. `identityLookup` is how
csecd located Claude Code's code for its most recent identity check this run,
absent until one has happened: `audit-token (exec-exact)`, or
`pid fallback (not exec-exact; task_name_for_pid refused: kern_return N)` when
the kernel refused the task name port. A `decline` or `delegated_release`
record whose decision checked that identity carries the same text as
`delegation.identityLookup`. A `not_registered` decline of a `csec ai` also
carries `delegation.registration`, why nothing bound: `unreadable_command`
(csec could not read the command out of Claude Code's framing),
`none_under_agent`, `late_by_<N>ms` (this program's registration reached the
delegation actor N ms after the `csec ai` started), `command_start_unreadable`
or `no_match`, followed by `; a registration was refused <N> ms earlier:
<reason>` when csecd refused one within the last minute. csecd also writes each
refused registration, and each it answered 750 ms or more after the hook
connected, to `csecd.log` with a UTC timestamp and where the time went: csecd's
check of the hook's code identity, the hook's own wait before it sent (it
checks csecd's signature first, which waits on trustd), csecd's queue and the
handling. A verified csec client that connects and closes without sending a
request 750 ms or more later is logged too: a hook that gave up before sending
leaves only that line. None of this names the command. Each decline also has
a stable code, which a `decline` record's `delegation.reason` and
`cs-review-preview`'s `CSEC_PREVIEW_DELEGATION` use:
`not_registered`, `not_auto_mode`, `not_interactive`, `launch_option`,
`injected_environment`, `environment_unreadable`, `home_mismatch`,
`config_directory_unusable`, `unverified_build`, `unchecked_build`, `project_not_local`,
`project_unavailable`, `facts_unavailable`, `settings_unreadable`,
`settings_environment`, `allow_rules_active`, `other_hook`, `classifier_rules`,
`sandbox_auto_allow`, `bypass_reachable`, `hooks_disabled`, `gateway_sign_in`,
`gateway_sign_in_unchecked`, `not_approved_for_project`, `not_held`, `command_mismatch`,
`environment_steering`, `sudo_indirect`, `sudo_option`, `sudo_not_approved`,
`agent_own_command` and `lasting_access`. A log written before csec-0.11 may also hold the retired
SSH codes `ssh_not_approved`, `ssh_indirect`, `launcher_not_trusted`,
`launcher_changed` and `launcher_unverifiable`.

`unverified_build`, `allow_rules_active`, `other_hook` and `classifier_rules`
are the reasons only `csec setup auto-mode` ends. csecd keeps such a reason's
notice, value-free and at most 1 KiB, for the `csec ai` the request ran under,
and hands it over once in `delegationNotice`: on that `csec ai`'s `access`
reply (approved or refused) and on its `end_output_redaction` reply, which
covers an SSH signature or sudo under the command. `csec ai` prints each one
once on stderr for the agent session.

## Delegated sudo

Before it draws a panel, the sudo review helper asks csecd whether Claude Code
auto mode's approval stands in for it:

```json
{"version": 2, "type": "sudo_delegation",
 "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
 "sudoDelegation": {"requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
   "command": "sudo fs_usage -w -f pathname -t 8"}}
```

`command` is exactly the PAM frame's command (at most 32 KiB), which csecd
decodes back into sudo's argv (`SudoCommandDisplay`); which sudo it is, and
everything above it, csecd reads from the kernel, never from the request. The
reply's `sudoDelegation` is `{"decision": "approved"}` (the helper exits 0 with
no panel), `{"decision": "not_applicable"}` (not a Claude Code sudo, or
delegation off: the panel as ever), or a decline:

```json
{"decision": "declined",
 "note": "Auto mode didn't approve this: sudo hasn't been approved for auto mode in alpha.",
 "pairingLine": "Approving also lets Claude Code auto mode run sudo in alpha until you revoke it"}
```

`note` (at most 1 KiB) goes below the panel's footnote; `pairingLine` (at most
512 bytes, only when approving would pair sudo with the project; for a decline
pairing cannot end it ends "once …" instead, "… once Claude Code is started
without --settings") is shown whole
below it. Any failure or a reply later than 2.5 s is read as `not_applicable`.
After a Touch ID on a panel that showed the line, the helper sends
`{"version": 2, "type": "sudo_pairing", "requestID": "…", "sudoPairing":
{"requestID": "…"}}`; csecd records the pairing only for the helper it offered
the line to, while that helper still serves a root sudo, and replies
`sudoPaired`. A phone approval needs no report: csecd sees the phone's signed
acknowledgement itself.

The helper also asks csecd which terminal tab the sudo came from, since the
helper itself sends no Apple event (DESIGN.md §Naming the requesting terminal tab):

```json
{"version": 2, "type": "sudo_terminal",
 "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
 "sudoTerminal": {"requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}
```

The request names nothing to look up: csecd walks up from the helper's own
process, as it does for any caller, and replies `sudoTerminal` with the
`TerminalSessionContext` the panel shows (application, tab title, position,
tty, multiplexer), or none. The helper sanitizes and bounds it again on
decoding. Any failure, or a reply later than 5 s (csecd's 2.5 s title query
plus the identity check), leaves the panel naming the PAM tty alone. csecd
also notes then, while the sudo runs, who the sudo is for (the nearest coding
agent above it), for the review's end record.

Just before it exits, the helper reports how its review ended, unless the
paired phone decided it (csecd logged that itself):

```json
{"version": 2, "type": "sudo_review_end",
 "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
 "sudoReviewEnd": {"requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
   "outcome": "timed_out", "command": "sudo /usr/bin/true",
   "terminal": "/dev/ttys001", "terminalSummary": "iTerm2 · window 1, tab 2 · ttys001",
   "ttdMs": 297000}}
```

`outcome` is `approved_mac`, `use_password` (the review ended without
approving and sudo went on to macOS's own authentication), `timed_out` (the
deadline) or `requester_gone` (the sudo exited first); `command`, `terminal`
and `terminalSummary` are the phone request's, with its bounds; `ttdMs` (at
most the longest frame's 600 s) runs from the panel's start to its end. csecd
logs it (DESIGN.md §Decision log) and replies `sudoReviewEnded`. The helper
waits at most 1 s for that, and sends nothing when the call could outlast the
PAM module's deadline; the sudo's outcome stands either way.

## Sudo review on the paired phone

`sudo_remote_review` is the one request the sudo review helper
(`csec-sudo-review`) sends, and the helper is the only peer allowed to send it
(see "Mutual identity before JSON"). The helper sends it while its own panel is
up and races the two: the first verified answer wins.

```json
{"version": 2, "type": "sudo_remote_review",
 "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
 "sudoReview": {"requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
   "command": "sudo /usr/bin/true --api-key \"[csec:secret-like]\"",
   "workingDirectory": "/Users/example/project", "terminal": "/dev/ttys001",
   "terminalSummary": "iTerm2 · window 1, tab 2 · ttys001"}}
```

`command` is the PAM module's redacted, escaped argv (at most 32 KiB, never a
raw argument); `workingDirectory` and `terminal` (at most 4 KiB each) are what
the helper's panel shows; `terminalSummary` is the tab the helper resolved, and
`targetUser` (at most 256 bytes) is omitted because the PAM frame does not carry
it. The two `requestID`s must match and be a lowercase UUID; anything else is
malformed. csecd builds a v3 review of kind `sudo` (headline `sudo …`, the
kernel's name and pid for the helper's parent as the caller, no credentials,
delivery, scope or lifetime choice) whose operation digest covers these fields
and the helper's kernel pid and start time, so two sudo invocations of one
command are two operations. It asks the remote provider directly, never through
the consent queue, and replies with `sudoRemoteReview`: `approved` (the pinned
phone's verified approval), `denied` (its verified Deny; sudo falls back to its
password prompt, as for Use Password), or `unavailable` (not paired or not
ready, relay trouble, or a request it would not mirror; never a denial). The
helper reads any failure the same way. Closing the connection withdraws the
phone's copy through csecd's peer-exit watch. A sudo approval mints no grant and
opens no store. For a Claude Code sudo that delegation declined, the review
also carries csecd's own note and, when approving pairs, its line, as an
unscoped pairing line (the review offers no scope or lifetime); a phone
approval that signed it showed the line pairs sudo with the project.

## Decision log and uninstall cleanup

csecd keeps a value-free decision log (`~/Library/Application Support/
ConvenientSecurity/DecisionLog/`): AEAD-sealed, hash-chained segments in two
streams, `decisions` (panels with their outcome, decider and time to decision;
refusals by an earlier Deny; delegation declines; revocations; settings changes;
restores; restarts; integrity findings) and `usage` (grant reuses and delegated
releases). The key and each stream's checkpoint live in protected Keychain items
only csecd can read or write.

The `decision_log` request reads, verifies or reports on it:

```json
{
  "version": 2,
  "type": "decision_log",
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "action": "read",
  "query": {
    "streams": ["decisions"],
    "kinds": ["panel"],
    "since": "2026-09-25T00:00:00.000Z",
    "after": {"decisions": 0, "usage": 0},
    "limit": 200
  }
}
```

`action` is `read`, `verify` or `status`, and `query` is present exactly when it
is `read` (1–200 records per page; `kinds` and `since` are optional filters). A
`read` reply carries `decisionLogPage`: `{records, next, incomplete}`. Each
stream's records come in sequence order, and the streams are merged by wall
time without ever putting a stream's later record before its earlier one.
`next` is the cursor for the following page, absent on the last. One page
decrypts a bounded number of frames, so a page can be empty and still carry a
`next`: keep paging until `next` is absent or stops moving. `incomplete` says a
frame failed to authenticate while reading. A record a newer csecd wrote reads
as kind (or outcome, decider, surface) `unrecognized` rather than failing.

A `verify` reply carries `decisionLogVerification`: `{status, findings,
tornTails, decisionsHeadSeq, usageHeadSeq, checkedAt, detail, recorded}`, where
`status` is `clean`, `first_run`, `repaired` (a partly written final frame was
cut), `discrepancy` or `unavailable`. Findings are `modified_record`,
`missing_segment`, `spliced_segment`, `behind_checkpoint`, `checkpoint_mismatch`,
`checkpoint_missing`, `key_missing`, `prune_gap`, `foreign_file` (a
segment-shaped name csecd never writes) and `directory_unusable`; each lists at
most 16 names and counts them all. A segment-named file with no authentic frame
(`spliced_segment`) and a foreign file are set aside only once their finding is
durable, and the chain carries on past them, so junk never costs authentic
history. A file csecd cannot move (an immutable entry), a damaged segment
included, is recorded once, left out of the chain at later starts, and named
in `csec status`; it never holds the log, and it is set aside quietly once it
can be moved. csecd remembers its own damaged segments (their first frame
authenticates) on a list of their own, up to 96, that planted files cannot
crowd out: one walked again would break the chain at every start. Junk and
foreign files share a list of 32; past that, one is recorded again at each
start, which breaks no chain. csecd never waits on a special file planted under a log name
(a FIFO swapped in for a segment): every open of an existing name is
non-blocking, and anything but a regular file is refused, then found as
foreign.
Only verified segments count toward a stream's size cap; set-aside files have
a budget of their own and are never charged against verified history. A
segment is pruned once: after its `prune` record is committed it leaves the
live history even if its file cannot be unlinked, which is then named in
`csec status` and removed at a later start when it can be. A discrepancy found by `verify`
is handled exactly as at startup: a `log_integrity` record, a fresh segment
chained to the checkpoint, the segment where verification failed and every
later one set aside (authentic later segments included, so they leave the
readable history), and a notification.
The checkpoint moves past a finding only once it is durably recorded; when it
cannot be (`recorded: false`), the checkpoint stays where it was, the log
records nothing more, and the next `verify` or start finds it again. A `status`
reply carries `decisionLogStatus` (`{state, detail, lastVerification,
integrityEvents, unrecordedFinding, droppedRecords, checkpointWriteFailures,
stuckFiles, heldItems}`) for `csec status`. `heldItems` (`[{name, cause,
reason, remedy}]`, absent from a csecd that predates it) lists every protected
item this csecd could not read and keeps as found, the log's own key and
checkpoint among them. `cause` is `newer_format`, `keychain` or `damaged` (an
unknown value reads as `unrecognized`); any but `damaged` fails `csec doctor`. Like `grants`, it needs the verified launcher and no Touch
ID. When csecd has no protected stores the log is off: `status` says so and
`read`/`verify` fail with `decision_log_unavailable`.

Each record has `v, seq, wallTime, bootSessionUUID, kind`, and as the kind
needs: `surface, requester {class, rootPID, rootLabel, terminal}, refs, shape,
mechanism, command, commandDigest, scope, duration, outcome, decider, ttdMs,
cause, grantIDs, delegation, detail, chain, resume, integrity, prune`. `refs`
are canonical references; `command` is the review panel's own redacted display
string, bounded; no field carries a value. A panel's `cause` says why it
appeared: `new_refs` (never approved this run), `new_release_shape` (approved
for this process tree, but for another release shape or, for SSH, another
server or user), `new_process` (approved for a process tree this request is not
in), `grant_expired`, `grant_revoked`, `restart_not_restored` (a grant
persisted before csecd restarted would have covered exactly this request, but
the load checks dropped it), `one_time_code` (every new reference was a
one-time code, which no approval covers), or `lasting_access` (a GitHub request
that can give lasting access, which no approval covers); a `restore` record's cause is `restart_restore`,
as is the cause of a `fetch_ahead` record the attended `csec restore` wrote. A
`fetch_ahead` record is what was fetched ahead from providers that need no
csec unlock, its `refs` the references it could not fetch (those the reply's
bounded `failures` lists) and its `detail` the counts and each distinct
value-free reason, counted over every failure. One that a panel approved at
the Mac started has no cause, and its `detail` begins "after an approval at
this Mac".
A `settings` record for a `configure_delegation` sheet that did not approve
has why it ended as its `cause` (`user_cancel`, `system_cancel`,
`app_cancel`, `auth_failed`, `user_fallback`, `biometry_lockout`,
`no_touch_id`, `not_interactive`, `requester_gone`, `not_shown`,
`unexplained` or `la_error_<code>`; only `user_cancel` has outcome `denied`)
and the sheet's time on screen in `ttdMs`; the `consent_denied` failure's
message is the same reason in words.

`kind` is one of `panel`, `refusal`, `mint`, `decline`, `settings`, `revoke`,
`reuse`, `delegated_release`, `restore`, `fetch_ahead`, `restart`, `prune`, `log_integrity`,
`chain_resume`, `torn_tail`, `uninstall`, `grant_eviction`,
`baseline_migration`, `baseline_integrity`, `delivery_failed` (an approved
release or signature that delivered nothing, so minted no grant),
`absent_reference` (a request refused before any panel because a reference in
it cannot resolve; no `outcome` or `decider`, the provider's reason in
`detail`; recorded once per surface, requester class and reference set in a
csecd run, and at most 64 per surface per run, the last saying so) and
`withdrawn` (a request that left with nobody having decided it: its requester
went away before any panel was shown, `requester_gone`, or a coding agent's
request reached its deadline queued or on screen, `timed_out`; `detail` says
whether a panel was shown and how long it waited); `reuse`, `delegated_release`
and `chain_resume` go to `usage`, and a `prune` to the stream it pruned.
`outcome` is `approved`, `denied`, `requester_gone`, `authentication_failed`,
`phone_approved` or `timed_out`; `decider` is `human_local` (this Mac's panel), `human_phone`,
`human` (a reviewer that reported no surface), `delegated`, `grant` or
`restored_grant`; `surface` is `secret_access`, `ssh_signing`, `automation`,
`native_edit`, `restore` or `sudo`. A `sudo` record is a `panel` the paired
phone decided (`phone_approved` or `denied`, decider `human_phone`; or
`requester_gone` when the helper had closed before the answer reached it), with
requester class `sudo` and terminal, and the redacted command. Every other end
is the helper's `sudo_review_end` report: a Mac approval (`panel`, `approved`,
`human_local`), `use_password` (`panel`), the deadline (`withdrawn`,
`timed_out`) or the sudo exiting (`panel`, `requester_gone`). A sudo record's
`rootPID` is the nearest coding agent above the sudo, with `rootLabel` (Claude
Code or Codex) and `scope` `coding_agent`, when one ran it, and otherwise the
sudo's pid. A `restart` record's `cause` is `first_start`,
`reboot`, `upgrade`, `restart`, `crash` or `unknown`, with the restored and
dropped grant counts.

The `uninstall_cleanup` request has only its `requestID`:

```json
{"version": 2, "type": "uninstall_cleanup", "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}
```

csecd shows one Touch ID panel (its settings panel) listing what it deletes and
what it keeps, and naming the requesting terminal. A refusal fails with `consent_denied` and changes nothing
(`csec uninstall` then writes back the Claude Code settings it reverted before
sending the request). On approval csecd
enters a terminal uninstalled state in which it writes nothing more (no log
append, checkpoint, last-run, grant, pairing or host-audit baseline write, and
nothing from its SIGTERM handler), drops its in-memory delegation settings and
pairings, deletes every protected item, the log
directory and the sealed host-audit baseline (with any plaintext baseline file
an older csecd left), and replies with `uninstallCleanup`: `{remainingItems,
logDirectoryRemoved, remainingFiles}`, naming anything it could not delete; a
csecd without its
Keychain access group this run reports every item as not deleted. `csec uninstall` then
unregisters the LaunchAgent.

## Secure no-root delivery plans

Credential helpers declare `credential_protocol` with destination
`credential_consumer` and normally use `exact_process` scope. AWS and Git wire
formats exist only between the helper and its direct tool parent; they are not
messages on the authenticated agent socket. Helper stdout must be a pipe or
socket, and the helper rechecks its parent's PID, start time, and executable
immediately before writing the resolved response.

`csec exec-fd` declares `inherited_fd` and binds the executable, command digest,
output-guard configuration, reference-to-variable mapping, and any preset name
into the plan. Secret file bytes cross the authenticated socket as ordinary
access values, remain in the launcher only long enough to feed anonymous pipes,
and are never encoded in the plan or child environment. The advertised
`inherited_file_descriptors` capability describes this launcher behavior; it
does not add another daemon message containing files or descriptor numbers.

## Protected regular-file rendezvous

The capability `protected_regular_files` adds one agent request and a separate
root-helper protocol. Production root traffic uses `AF_UNIX` at the fixed
`/private/var/run/convenient-security/rootd.sock`; release builds compile out
the debug endpoint override. The root-owned socket is mode `0666` so the two
normal-UID product roles can connect, but its pathname and permissions grant no
authority. Every connection is authenticated from the complete audit token and
live Security.framework code before its body is read, and refused unless the
peer is one of the two product roles below. The operation names the role it
needs, so that check comes once the frame is decoded, before any handling: a
signed peer of the other role has its frame and descriptors read, then the
descriptors are closed and the connection ends with no response. The peer is
rechecked against the operation's role before the response:

- exact signed `csec` may use `prepare`, `start`, `status`, `signal`, `cancel`,
  and `health`;
- exact signed `csecd` alone may use `approve`, `host_read` and `host_apply`;
  and
- both must be non-root peers, while clients require an exact signed helper
  whose effective UID is root.

`host_read` and `host_apply` serve the host posture audit (DESIGN.md, "Host
posture audit"). Each carries a closed enum that the helper maps to fixed system
tools at absolute paths, run with a fixed `PATH` and locale and bounded output;
no caller string reaches a command line. `host_read` returns that output for
csecd to parse value-free. `host_apply` makes one reversible change (the
application firewall, sharing services, software-update and login-window
preferences, removing the auto-login user with its `/etc/kcpassword`, the root
and guest accounts, network time, Touch ID for `sudo` in
`/etc/pam.d/sudo_local`, or a known-dangerous NVRAM `boot-args` token), and only
when its digest equals the one the helper recomputes for that exact change.
Outside its own runtime directory (the socket, the GID cursor and the tmpfs
mount), these are the only writes the helper makes.

Each request uses a fresh connection and one bounded length-prefixed JSON frame.
The listener admits at most 32 concurrent handlers and gives each socket read
and write call a five-second timeout; the coordinator retains at most 128 launch
records. Only `prepare` carries descriptors: exactly cwd, stdin, stdout, and
stderr in that order through `SCM_RIGHTS`. Every other operation must carry zero
descriptors.

Those caps, not the descriptor limit, are what refuse work under pressure.
launchd starts a daemon at a 256-file soft limit, below the 512 descriptors
that 128 retained launches hold, and once a process runs out the kernel's
`accept` drops each new connection unanswered. So the listener first raises
`RLIMIT_NOFILE` to a budget derived from the caps
(`RootHelperDescriptorBudget`: four per launch, sixteen per connection handler
and the one accepted socket waiting for a slot, and a fixed allowance), and
logs to stderr if it cannot.

A peer that sends nothing costs the helper one thread for five seconds and
nothing more. The timeout is per call, not a deadline for the request: a peer
that keeps sending a few bytes inside each five seconds holds its thread until
its frame is complete, so the 32-handler cap is what bounds slow peers. Each
handler runs on a thread of its own, and only its coordinator calls go to
Swift's cooperative pool, whose one thread per CPU would otherwise let as few as
sixteen silent clients stall every launch. The header receive parses control
messages only after `recvmsg` succeeds, never walks a control header shorter
than itself, and reads no further than the bytes the kernel copied out. A
message carrying more than eight descriptors comes back truncated (`MSG_CTRUNC`)
with the sender's length still in place, and is rejected.

The launch sequence is:

1. `csec` constructs and validates `ProtectedLaunchPlan`, including its own
   PID/start time/UID/audit session, exact executable metadata, complete argv,
   sanitized environment, one to sixty-four file bindings, delivery-plan/output-
   guard binding, TTL/hard-TTL flag, and PTY choice. It sends `prepare` with the
   canonical SHA-256 plan digest and four descriptors.
2. `csec-rootd` revalidates the plan, caller identity, executable claim, and
   descriptors, retains the descriptors, and returns a fresh rendezvous nonce
   plus the same digest in state `prepared`. An unapproved preparation has no
   clock: the approval panel may take as long as its own deadline allows (a
   terminal's request has none), so it lives until the launcher exits or
   cancels it, or the same launcher prepares again, which replaces it. It holds
   only the plan and the four descriptors, never a value.
3. `csec` submits `approve_protected_launch` to `csecd`. The outer request UUID
   must equal the nested approval UUID. The nested request repeats the nonce,
   complete launch plan/digest, and an ordinary v2 access request derived from
   exactly that plan.
4. `csecd` verifies that the authenticated caller is the launcher recorded in
   the plan and evaluates `capability_gid_file` policy. This mechanism may reuse
   only a grant the human deliberately widened to a coding agent or terminal
   session, never a requesting-process one; absent such a grant it obtains fresh
   consent. It then resolves the exact reference set and renders each payload.
   Raw payloads are non-empty and at most 1 MiB each/4 MiB total. GitHub mode
   emits a bounded, injection-safe `hosts.yml` selected by the reviewed binding.
5. `csecd` sends `approve` directly to the authenticated root helper with the
   nonce, plan digest, payloads, and policy-capped absolute expiry. On success it
   returns only `{"protectedLaunchApproved":true}` to `csec`; it never returns
   the values. The helper creates the files and enters state `ready`.
6. Only the exact original launcher audit token may send `start`. The response
   supplies the kernel child PID/start time in state `running`. The launcher
   supervises terminal or pipe I/O, polls `status`, forwards permitted signals,
   and sends `cancel` if scanning or supervision fails. Final status includes
   the raw wait status and no plaintext.

All requests carry a UUID and all rendezvous operations carry the nonce plus
digest; clients reject version, UUID, nonce, digest, state, or response-shape
mismatches. Root-helper failures use the single value-free `invalid_request`
code with generic text except the bounded expired-rendezvous distinction: a
rendezvous that is unknown, cancelled or whose launcher has exited. `csecd`
answers an approval that reaches such a launch with `invalid_request`, saying
nothing was delivered and to run the command again; any other root-helper
refusal stays `delivery_not_supported`.
Relative paths are fixed by product construction and independently reject
absolute paths, traversal, prefix collisions, duplicates, environment
collisions, and loader/product controls.

## Active-output redaction sessions

This protocol supports pre-recipient scanning for `csec ai` (the coding-agent
broker; `tool-exec` is its deprecated alias) and `csec exec-file`. It is not a
general secret-query API. When a v2 access
succeeds, `csecd` registers only the values it actually released, in memory:
one released under a bounded grant until that grant's expiry, even when the
consumer remains alive, and one released for a process lifetime (the default,
and every delegated release) until csecd restarts. It does not
unlock dormant cache/provider entries to populate the registry. Registry state
is lost on agent restart.

The signed launcher opens a session on a persistent authenticated socket:

```json
{
  "version": 2,
  "type": "begin_output_redaction",
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "destination": "ai_tool",
  "streams": ["stdout", "stderr", "terminal"],
  "includeShortValues": false
}
```

The current implementation accepts `ai_tool` for the fail-closed AI broker and
`local_development` for protected launch supervision, rejects duplicate/unknown
streams, and permits at most 256 live sessions. A session is never expired for
being idle: it lasts until it is ended or its owning launcher exits.
`includeShortValues` opts into matching below the normal eight-byte
floor and remains bound for subsequent catalog refreshes. The response contains
a fresh opaque session UUID plus eligible/skipped counts. It never contains the
registry values.

For each child-output read, `csec` sends at most 64 KiB:

```json
{
  "version": 2,
  "type": "redact_output_chunk",
  "requestID": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
  "sessionID": "<session-uuid>",
  "stream": "stdout",
  "data": "<JSON base64 Data>",
  "finish": false
}
```

The session is bound to the original launcher's kernel PID and process start
time. Separate streams cannot combine prefixes. A `terminal` stream's matcher
reads escape-sequence syntax and never starts a match on a sequence's own
structure bytes, so a terminal query is forwarded whole; `stdout` and `stderr`
match strictly byte for byte. An optional `prime: true`
scans the chunk only to set the matcher's state and returns no data or matches
(it cannot be combined with `finish`): a launcher that reopens its scanner after
a csecd restart primes it with the output just before, so a value split across
the restart is matched whole. `finish: true` flushes one
stream's withheld prefix and seals that stream. Before processing each chunk,
the agent adds newly registered values to every still-live streaming matcher;
it deliberately does not remove an old pattern mid-stream.

The response echoes the request nonce and returns only already-redacted `Data`
plus `[OutputRedactionMatch]` metadata. A match identifies an opaque ID and the
representation (`exact`, canonical base64/base64url, percent-encoded, or JSON
escaped), never the matching bytes or vault reference. `end_output_redaction`
removes the complete caller-bound session; its reply may carry
`delegationNotice` (see delegated approvals). While the command runs,
`csec ai` sends `take_approval_notices` (`requestID`, `sessionID`) about once a
second on a second connection of its own, so a poll that fails or stalls stops
only the notices and never the scanner; the reply's `approvalNotices` lists, once per
session, the notices of requests started under that `csec ai` that wait on a
human and cannot carry a notice of their own (an `ssh` signing for it, a
language client over `csec bridge`). Only the session's own launcher may ask. Disconnect/idle cleanup is bounded;
the client treats any malformed, failed, missing, or nonce-mismatched response
as scanner loss and stops forwarding child output.

This protocol exposes a bounded equality oracle to somebody able to run the
genuine signed launcher: they can observe whether chosen output is replaced.
Short-value exclusion, caller/destination binding, chunk/session limits, and
opaque matches reduce abuse but do not eliminate it. A scanner session is bound
to the launcher process, not to a separately authenticated AI parent, and the
protocol applies no per-caller rate limit beyond its session/chunk bounds.

## Native-store edit sessions

Native store management is separate from ordinary per-reference access. Only a
verified product launcher can begin an edit. `csecd` validates the path-safe
store name and always requests fresh Touch ID consent for the synthetic
`csec://<store>/*` reference; an existing secret grant cannot authorize an edit.

The launcher begins with:

```json
{
  "version": 2,
  "type": "begin_native_store_edit",
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "store": "development",
  "mode": "built_in_memory"
}
```

`mode` is `built_in_memory`, `onboarding_import`, `ssh_key_import`,
`github_token_import`, or `external_temporary_file`. External mode must also
include the canonical absolute `externalEditorPath`; it is modeled as an
unverified named-plaintext-file consumer. The built-in, onboarding-import,
SSH-key-import and GitHub-token-import modes reject that field and bind direct-heap delivery to the verified `csec`
launcher. The
dedicated onboarding value gives policy review and consent an exact operation
label; source selection/merge validation still happens in the launcher. The
embedded Touch ID view may authenticate while the policy window is visible, but
the exact selection is frozen at success and the release policy must accept it
before the authenticated context can decrypt the store. External mode is always
available: choosing it is the plaintext-file acknowledgment, so its plan carries
`plaintextExposureAcknowledged` and one Touch ID authorizes it, as for the
built-in editor.

Success returns a fresh edit-session UUID and the complete canonical JSON
document as JSON's base64 representation of `Data`. For a new empty store this
is:

```json
{
  "version": 2,
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "editSessionID": "11111111-2222-3333-4444-555555555555",
  "document": "e30K"
}
```

The session is bound to the launcher's kernel PID and start time, lasts as long
as that launcher incarnation does (no clock expires an open edit), and retains
the biometric context needed to authenticate the Keychain pointer update. What
frees a session is a save, a cancel, or `csecd` finding the launcher gone and
cancelling it; at most eight sessions exist at once. The document
is limited to 1 MiB and 1024 unique, path-safe keys with string values. The signed
launcher validates and canonicalizes it locally; the daemon independently
validates it again.

Save sends `commit_native_store_edit` with the session UUID and bounded `Data`.
Success reports only the new positive `generation` and `secretCount`. Invalid
JSON returns `invalid_store_document` without consuming the session so the UI
can correct it. A save whose baseline is no longer current returns
`edit_conflict`. `cancel_native_store_edit` removes a caller-owned session and
returns no document. Before a commit, the daemon recomputes the risk decision
and requires the exact original policy binding; a risk change also proactively
cancels matching edit sessions.

The plaintext document crosses only the existing mutually authenticated socket;
the protocol never puts it in argv, the environment, error text, or logs. The
default built-in editor keeps it in the daemon and signed launcher's heaps and
creates no temporary file. The explicit client-side `csec edit --editor` mode
instead writes it to a private named temporary file so an arbitrary editor can
operate on it; that weaker delivery is outside the wire protocol. The protocol
does not make the authorized launcher, editor, plugins, or user-directed
clipboard and screen actions confidential.

## GitHub token proxy

`csecd` serves a second socket for HTTP, `…/convenient-security-<uid>/github.sock`
(`0600`; `CSEC_GITHUB_SOCKET` selects another in debug builds only). It speaks
plaintext HTTP/1.1, one request per connection, to any process of the current
user; `gh` reaches it through its `http_unix_socket` setting. A request whose
`Authorization` is `token csec-github-proxy` (or `Bearer …`) for one of the
GitHub hosts `gh` authenticates to (`github.com`, `api.`, `uploads.`,
`codeload.` and `gist.github.com`) is authorized as an `access` for the registered token's reference
with a plan csecd builds itself, mechanism `daemon_proxy`; csecd forwards it
over TLS with the token in place of the placeholder and relays GitHub's
response. `Agent` refuses a `daemon_proxy` plan from any socket client with
`invalid_request`. Parsing, the host table and the responses csecd writes
itself are in [`github-proxy.md`](github-proxy.md).

The launcher manages the registration over the agent socket:

```json
{
  "version": 2,
  "type": "configure_github",
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "github": {
    "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "action": "register",
    "reference": "op://Private/GitHub CLI/token"
  }
}
```

`action` is `status`, `register` (with `reference`, at most 4 KiB) or `remove`;
the two request IDs must match. Only the verified launcher is served. `register`
shows one Mac-only review, resolves the reference with its Touch ID and requires
one line of printable ASCII. Every success answers with the registration:

```json
{
  "version": 2,
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "github": {
    "tokenReference": "op://Private/GitHub CLI/token",
    "socketPath": "/var/folders/…/convenient-security-501/github.sock"
  }
}
```

`csec protect --gh` instead begins a native-store edit in `github_token_import`
mode and commits one blob with `"githubTokenRegistration": "csec://github/gh-token"`,
the canonical reference of exactly that blob; csecd checks the value's shape
before writing anything, and registers it under the edit's one Touch ID. A
csecd with no protected stores answers `github_proxy_unavailable`.

## Native-store backups

`csec backup` sends one request type, `native_store_backup`, carrying a nested
`nativeStoreBackup` object whose `requestID` must equal the envelope's:

```json
{
  "version": 2,
  "type": "native_store_backup",
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "nativeStoreBackup": {
    "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "action": "status"
  }
}
```

`action` is `status`, `begin_setup`, `complete_setup`, `cancel_setup`, `sync`,
`preview_restore`, `restore` or `off`. `sessionID` is required by, and only
accepted with, `complete_setup` and `cancel_setup`. `recoveryKit` (at most 512
bytes) is required by, and only accepted with, `preview_restore` and
`restore`. An absolute `folder` (at most 1 KiB) is accepted only with
`begin_setup` and the two restore actions. Anything else fails to decode.

The reply's `nativeStoreBackup` holds `status` (value-free: state, folder,
and per store tier its state, generation, write time and iCloud upload state),
`report` (counts written, current and failed), or `restore` (per bundle its
kind, store, count, backup time and outcome, the counts of bundles that did not
open and that iCloud Drive has not downloaded yet, and `continuesBackup`). `begin_setup` alone carries `setupSessionID` and
`recoveryKit`: csecd generates the kit and holds it for the launcher's kernel
PID and start time (at most four waiting setups). `complete_setup` uses that
held kit and no other, so a caller cannot choose the key bundles are sealed to.
`complete_setup`, `sync`, `restore` and `off` each take one fresh Touch ID;
`status`, `begin_setup`, `cancel_setup` and `preview_restore` change nothing
and take none. The kit appears in no other reply, error text or log, and the
launcher shows and reads it only in its own windows.

## Machine identities

`csec identity` sends one request type, `configure_machine_identity`, carrying
a nested `machineIdentity` object whose `requestID` must equal the envelope's:

```json
{
  "version": 2,
  "type": "configure_machine_identity",
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "machineIdentity": {
    "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "action": "add_target",
    "target": {"name": "admin", "identity": "default", "kind": "aws",
               "audience": "sts.amazonaws.com", "lifetime": 3600,
               "roleARN": "arn:aws:iam::123456789012:role/admin", "region": "eu-west-2"}
  }
}
```

`action` is `status`, `create` (`identity`, `issuer`, `subject`), `remove`,
`check` and `public_files` (`identity`), `add_target` (`target`),
`remove_target` (`identity`, `targetName`) or `accept_keys` (`identity`, one to
16 `kids`, each a key's RFC 7638 thumbprint). Each action accepts exactly its fields, names are 1 to 64 of
`[a-z0-9._-]`, and anything else fails to decode. `create`, `add_target`,
`accept_keys` and `remove` each take one fresh Touch ID; `remove_target` takes
access away and takes none. Both removals revoke the grants covering the
removed sign-ins and unpair them from every Claude Code project.

The reply's `machineIdentity` holds `status` (identities with their issuer,
subject, public JWKs and accepted key ids; the targets; `hardwareKeys` and
`persistent`), `issuerReport` (`clear`, `compromiseSuspected`, a summary and
any unexpected key ids), the `discoveryDocument` and `keySet` to publish, or
`revokedGrants`. Everything in it is public: no key handle and no token ever
appears. Using a sign-in is an ordinary `access` for its `csec-identity://`
reference.

## Deleting whole-file values

`csec edit --remove` sends one request type, `remove_native_values`, carrying
a nested `nativeStoreRemoval` object whose `requestID` must equal the
envelope's:

```json
{
  "version": 2,
  "type": "remove_native_values",
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "nativeStoreRemoval": {
    "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "references": ["csec://ssh-keys/_Users_me_.ssh_id_rsa.old_8d268bf0ed90"]
  }
}
```

`references` holds one to six distinct `csec://` references in canonical form
(lower-case scheme), all in one store; anything else fails to decode. A
reference csecd's SSH catalog, GitHub socket or an automation job uses is
refused with `policy_denied`, as is one whose sidecar is still where its file
was protected from; a key the store's whole-file tier does not hold is
`reference_not_found`. csecd checks these before the one fresh Touch ID when it
already holds the store's index, and always again after it, before writing.
The reply's `nativeStoreRemoval` holds `removed` (each reference and the path
its import recorded) and `revokedGrants`. Nothing in it is a value.

## Typed, value-free failures

Protocol v2 never embeds a reference, provider stderr, or secret in a failure:

```json
{
  "version": 2,
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "failure": {
    "code": "delivery_not_supported",
    "message": "the requested delivery mechanism is not available"
  }
}
```

Codes are `upgrade_required`, `unverified_peer`, `policy_denied`,
`delivery_not_supported`, `invalid_request`, `consent_denied`,
`provider_unavailable`, `resolution_failed`, `reference_not_found`,
`native_store_unavailable`, `invalid_store_document`, `edit_conflict`,
`decision_log_unavailable`, and `internal_error`.

`reference_not_found` refuses a request before any panel because one of its
references cannot resolve, whatever a human would decide: its provider already
knows the key or store does not exist, or no provider claims its scheme. The
message names the first such reference and the provider's reason, "csec://harbor/RELAY_TOKEN:
the requested key does not exist in the native store; no approval was asked".
Asking again fails the same way until the reference or the store changes, so a
client should stop retrying and tell its human. Each provider answers from
state csecd already holds, with no unlock, prompt or network
(`SecretProvider.presence(of:)`): the native store answers for a store csecd
has opened since it started, or for one that does not exist at all; a store
csecd has not opened yet, and every 1Password reference, get a panel as before.
A value csecd caches is never refused, nor is a `csec://` reference while the
native store could not start (that is csecd's fault, not the reference's).
Secret access, SSH signing (the agent answers its generic failure, logged as
`reference_not_found`, and ssh moves on to its next identity), SSH key
registration and automation enrollment all refuse this way, and so does each
request again once it gets its turn, since the panel it waited behind may have
opened the store; `csec edit`, which creates missing keys, does not.

A `resolution_failed` message names the reference and, when
the provider can say why in a fixed sentence of its own, adds it: "the provider
could not resolve csec://harbor/RELAY_TOKEN: the requested key does not exist in
the native store". The decision log's `delivery_failed` detail carries the same
text. A tool's own error output never reaches it. An edit session
id that names no session owned by the caller is an `invalid_request`; there is no
expiry code, because an edit is never retired underneath a running caller.

The decoder recognizes a v1 flat `access` request only to return
`upgrade_required`. Production never invents a secure plan for v1. Fake agents
may opt into v1 solely for migration tests.

## Language-client/private bridge protocol

Ruby and Node.js do not perform the product's Security.framework peer check, so
their packages do not connect to `agent.sock`. Each executes
`/Library/Application Support/ConvenientSecurity/bin/csec bridge` by fixed
absolute path with a scrubbed environment and private stdin/stdout pipes. The
signed package installs that copy and every controlling directory root-owned
and non-writable by the login user; `/Applications` alone is not sufficient
because its `admin` group can replace directory entries.

The clients use close-on-exec parent-side pipe endpoints, so replacing the
language-runtime image closes the response channel in the kernel.

The request is one framed JSON object containing only `version`, `references`
(1 to 64), `reason` (1 to 512 bytes), and an optional `ttlSeconds`. Without it
(or with `null`) the grant lives as long as the scope root the human picks, as
for `csec exec`; a present value must be positive and is honoured as given, so
the 1 to 172,800-second bound the Ruby and Node.js clients apply is theirs, not
the bridge's. An older installed `csec` refuses a request with no
`ttlSeconds`. `csec bridge` refuses a terminal or regular-file
stdin/stdout, derives its language-runtime parent from `getppid()` plus kernel
process start time and executable path, submits a v2 `direct_heap` plan, then
rechecks all three before output so parent re-exec cannot change the reviewed
consumer. It writes one framed `BridgeResponse`; a failure uses the same
value-free typed failure shape.

The Ruby or Node.js heap receives plaintext; the helper's argv and environment
do not. If application code assigns a returned value to `ENV`/`process.env`,
launches a child with it, or writes it elsewhere, that disclosure is outside the
bridge boundary; see
[`threat-model.md`](threat-model.md#language-client-heap-delivery).

## Persistent automation control protocol

The v2 `configure_automation` request wraps a nonce-bound `AutomationRequest`
with one of `enroll`, `list`, `begin_run`, `finish_run`, `resume_run`, or
`revoke`. Production
csecd accepts it only from an authenticated product launcher. Responses carry
only value-free job metadata, a bounded run authorization, or the next eligible
time; resolved values never cross this control request.

Enrollment stores canonical refs and a bounded command recipe separately from
the automation-only Keychain materialization. `begin_run` creates a lease bound
to the socket caller's PID/start time, persisted value-free so a restarted csecd
restores it, and returns the stored recipe. `resume_run` (with `runID`) succeeds
only for the caller's own live lease, restored or not, and registers its values
with the output redactor; it returns nothing else.
Later ordinary bridge `access` messages retain their complete v2 delivery plan.
Before normal grant evaluation, csecd may match the plan's direct interpreter
parent to that exact leased runner and return only a registered subset from the
materialization. A shape that reaches the leased root but asks for another ref
is denied rather than falling through to ordinary consent. See
[`automation.md`](automation.md).
