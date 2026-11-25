# Convenient Security — current architecture

This document describes the behavior implemented in the repository. Security
claims apply only to a hardened, notarized, provisioned release build on macOS
with SIP enabled; unsigned development builds deliberately run without the
persistent keychain cache and with test-only trust seams compiled in.

## Scope

Convenient Security protects secret values from unrelated, non-root processes
running as the same login user. It provides per-reference Touch ID consent,
process-scoped grants, a code-identity-gated at-rest cache, heap delivery for
integrated Ruby and Node.js clients, tool-native AWS/Git credential adapters,
anonymous inherited-fd files, capability-GID regular files, an environment
compatibility launcher, destination-bound SSH signing, and exact-value output
redaction. Every delivery is gated by a Touch-ID-approved, value-free review
before provider or cache resolution, or by a live grant such a review minted.
The one exception is opt-in: Claude Code's auto-mode classifier may stand in
for the review, one command at a time, for references a human already approved
for that project (see §Delegated approval). It can resolve from the official
1Password CLI and from device-bound native encrypted files.

It does not protect a value from root, from code already executing inside an
authorized consumer, from a consumer the user deliberately launches, or from a
user who approves a misleading request.

## Design ethos

Convenient Security optimizes for **"more secure, conveniently"** — not minimal
privilege for its own sake, and not maximal hardening. Same-user malware is not a
fully solvable problem; the goal is to block the large majority of *automated,
opportunistic* supply-chain attacks (trojaned dependencies, postinstall scripts,
compromised extensions and CLIs going after easy, widespread targets) at a UX
cost low enough that the tool stays switched on. A control that blocks ~80% of
real attacks and is left enabled beats a "perfect" one that gets disabled. csec
will acquire a capability — for example Full Disk Access, to audit which apps
hold TCC grants — when doing so measurably improves the user's security
automatically; there is no goal of minimizing csec's own privilege footprint, and
the threat model is not a bespoke attacker studying csec's internals. Features are
judged on (security delivered × likelihood the user leaves it on), and the
preferred shape is a small number of commands that each do as much as possible
automatically after a single confirmation. The host posture audit built on this
principle is catalogued in [`docs/host-audit-catalog.md`](docs/host-audit-catalog.md).

## Components

- **`csecd`** is the resident Swift agent. It authenticates socket peers, obtains
  Touch ID consent, owns the grant table, resolves references through provider
  adapters, manages the keychain cache, holds the active-value registry used
  for output redaction, keeps the sealed decision log (§Decision log), judges
  Claude Code delegated approvals (§Delegated approval), and owns the
  host-posture audit engine (§Host posture audit) — running it under Full Disk
  Access and driving the root helper for its privileged reads and reversible
  fixes. It also owns a separate binary
  OpenSSH-agent socket whose only private operation is bounded SSH
  user-authentication signing, and a GitHub socket that puts the GitHub CLI's
  token on approved HTTPS requests it makes itself (§GitHub token proxy).
- **`csec`** is the signed CLI, bridge, launcher, output supervisor, and AI
  command broker. Its commands are listed by `csec help`; they include `csec
  setup` (onboarding) and `csec audit`, a thin client that asks `csecd` to run
  the host posture audit and render its value-free report.
- **`csec-rootd`** is a separately signed, root-owned LaunchDaemon used only to
  create bounded tmpfs files, launch/supervise a normal-UID process with a
  one-time capability GID, and serve the closed-enum host-audit `hostRead`/
  `hostApply` operations (§Host posture audit). Its Swift targets do not link the
  provider, Keychain, Touch ID, AppKit, ServiceManagement, or agent
  implementation.
- **`OnePasswordAdapter`** invokes a verified installation of the official
  1Password CLI with an allowlisted environment.
- **`NativeEncryptedFileProvider`** owns `csec://` parsing, strict JSON,
  AES-256-GCM encryption, per-store biometric Keychain records, immutable
  ciphertext versions, rollback detection, and bounded edit sessions. Both
  providers can be registered at once.
- **The Ruby and Node.js clients** invoke the independently protected `csec
  bridge` binary and receive framed values through a private pipe. They do not
  connect to the agent socket themselves.

## Backend-agnostic storage and delivery

Storage selection is orthogonal to authorization, policy, and delivery. Every
consumer operates on a canonical `SecretRef`; only `SecretResolver` dispatches
that reference to the `SecretProvider` registered for its scheme. `csec://`,
`op://`, and future schemes are peers at this boundary. No delivery adapter may
depend on native-store records, 1Password internals, or any other provider-
specific representation.

Provider-specific code is allowed at the storage edge: importing or updating a
value necessarily uses a destination's write API, and not every provider must
support writes. That capability must not leak into later use. A value written by
one import adapter, or created externally and named by an existing reference,
is consumed through the same authorization and delivery path as every other
backend.

Persistent plans, grants, sidecars, and adapter catalogs therefore contain the
canonical reference plus bounded value-free metadata, never a provider-private
record identifier. Resolution happens only after the complete request passes
policy and consent, and the plaintext remains inside the narrow delivery
implementation. Adding a provider must not require changes to SSH signing,
credential helpers, process launchers, or other consumers.

For example, an SSH-agent catalog records a secret reference together with the
derived public key and fingerprint. A signing request resolves the reference
through `SecretResolver` after approval, validates that the resolved private key
still matches the catalogued public identity, and returns only the signature.
The signing service does not know or care whether the reference is backed by
the native encrypted store, 1Password, or a future provider.

## SSH signing adapter

The SSH adapter is a second, binary protocol surface inside `csecd`; it does not
reuse the JSON access response that returns resolved values. The public catalog
contains a canonical `SecretRef`, public-key blob, algorithm, SHA-256
fingerprint, and bounded label. Registration resolves through `SecretResolver`
only after trusted policy review and Touch ID, derives the public identity in
the daemon, and persists no private bytes or provider-specific identifiers.

On the signing path, the socket accepts only the current user's live,
Apple-signed `/usr/bin/ssh`. It requires a verified, non-forwarded
`session-bind@openssh.com` extension and parses the complete SSH user-auth
packet before review or resolution; arbitrary-byte signing and SSH-wire catalog
mutation are refused. An approved grant is bound to the key fingerprint, server
host-key fingerprint, remote username, Apple SSH code identity/audit session, and
live parent process subtree, and lasts for that subtree's lifetime unless the
human chose a 1- or 12-hour bound; like a secret grant it is persisted across a
csecd restart (§Grants across a restart). The daemon then resolves the
reference, reparses the key, compares its derived public blob with both catalog
and request, signs the exact validated packet, and returns only the signature.

A request that no grant covers takes the SSH review turn — a FIFO permit held
from before its review until its grant is minted — and re-checks grants once it
holds it, so concurrent connections of the same shape (a parallel fetch, several
`ssh` at once) wait behind one panel. The re-check is the unchanged grant
match, so a "this command only" approval still reviews each connection. An
`ssh` that has exited is never shown: the agent socket cancels a request whose
peer has closed, and the service checks the requester's exact incarnation
before the terminal lookup and again before the review. A human Deny refuses
the identical requests (same key, server identity and remote user, offered the
same default scope) already waiting behind it, and the denied
`ssh` gets no further signature — it would otherwise offer the next catalog
key and raise a second panel. A request made after the Deny is asked afresh:
nothing here is a cooldown. Claude Code delegation is judged before the turn is
taken, so a delegated signature never waits behind a panel
(§Delegated approval).

`csec protect --ssh` is a provider-specific import convenience: it durably
writes to a chosen native store, registers the resulting canonical references,
preserves or derives `.pub` files, and only then removes unchanged originals.
It does not write a `.csec` sidecar because the SSH catalog is the durable owner
of that provider-neutral reference; avoiding a second pointer prevents lifecycle
drift. `csec ssh register` still accepts an existing generic sidecar or reference
from `csec://`, `op://`, or any future registered provider. This manual first
release does not modify global shell/SSH setup, proxy another agent, permit
forwarding, or support `ssh-add` mutations. The exact commands, supported key
formats, failure ordering, and first-release limitations are in
[`docs/ssh-agent.md`](docs/ssh-agent.md).

## GitHub token proxy

The GitHub proxy is a third socket inside `csecd`, `github.sock` beside the SSH
agent's, for `gh`'s `http_unix_socket` setting. `gh` writes plaintext HTTP/1.1
to it with a placeholder token; csecd replaces the placeholder with the token
and forwards the request over its own TLS connection, so no process holds the
token. It mirrors the SSH adapter's split: a catalog of one canonical
`SecretRef` (the `github-proxy`/`settings-v1` protected item), registration that
resolves only after a value-free review and Touch ID, and use that resolves the
reference per request after authorization and returns only GitHub's response.

Authorization is not a separate policy. A request carrying the placeholder for
one of the GitHub hosts `gh` authenticates to becomes an ordinary access request for the token's
reference with a plan csecd builds from kernel facts — the peer's executable
path and code identity from its audit token, its argv read by pid and start
time — and the delivery mechanism `daemon_proxy`, which a socket client can
never send (`Agent.handleAccess` refuses it). The request then takes the same
path as a secret release: grant reuse keyed on the `daemon_proxy` release shape,
the restore panel, the Deny ledger, `HumanWait`, Claude Code delegation as a
nested request, and the secret-access review with its phone mirror. That
review says the value is used, never released (§Trusted review and consent).
Its pairing line pairs that use only (`ProjectPairing.usedReferences`): a
pairing made on a panel that released nothing never lets auto mode release the
value, while a reference paired for release covers the use too. A use pairing
holds for auto mode in every project, not only the one it was approved in
(csec-0.46): pairing guards against a repository choosing which references its
commands receive, and here csecd chooses the reference, so a panel per project
would only re-ask what the human already decided. The panel's line says "in
every project", `csec grants` lists the use with "(every project)", and while
any Claude Code session is live the restore panel reopens it, in an "Every
project" row when no live project's row lists it. A release pairing stays
per project.

A request that can give access outlasting any grant is the exception to grant
reuse (csec-0.49). csecd classifies each request it is about to put the token
on (`GitHubLastingAccess`: keys, secrets, webhooks, collaborators and members,
app installations, runner registration, writes under `.github/`, a repository
made visible, and the GraphQL mutations that do the same), erring towards a
panel: the path is matched decoded, case-folded and dot-resolved, a method
override counts as a write, and a body that decides the answer but was not
read or cannot be parsed asks. Every body up to 1 MiB is read before the
decision, chunked ones included (`gh api --input -`), and an unread GraphQL
request's warning says why it could not be read. Such a request carries a marker only csecd sets
(`AccessRequest.githubLastingAccess`, never encoded or decoded) and its own
plan context, and `Agent.handlePolicyAccess` treats it as it treats a one-time
code: no grant or restore covers it, delegation declines it
(`DelegationDecline.lastingAccess`), its panel offers only the requesting
command and no lifetime, and its approval mints and pairs nothing. Its Deny
answers only identical lasting requests, and the decision log's cause is
`lasting_access`. The panel and the phone show a warning naming the request and
what it can add.

Two `gh` queries are not under a command the classifier judged. After a Bash
command whose text matches `git … push` (or a checkout), Claude Code itself runs
`gh pr view [<selector>] [--repo <owner>/<repo>] --json url`, a direct child of
P with a five-second timeout, to link the session to its PR. And at most once a
day per config it runs `gh issue list -R anthropics/claude-code --author @me
--state closed --search 'closed:><date>' --json number,title,closedAt,stateReason
--limit 30`, also as P's direct child, to say when issues you filed were fixed.
With no `csec ai` above them, each would raise a panel. Alex chose to let both
through (csec-0.47.1, csec-0.64.10).
`ClaudeDelegationService.evaluateOwnQuery` takes a `daemon_proxy` request with
no `csec ai` anchor as P's own request when the requester's executable is named
`gh`, its kernel argv is exactly one of those shapes
(`isClaudePullRequestLookup`, `isClaudeClosedIssuesCheck`, where only the date
varies), and its verified parent is P. It is then judged by every gate on P's
identity, launch, environment and settings, and on the reference's use pairing.
Only the permission mode goes unread, since no hook registered anything. Any
other `gh` P runs keeps its panel, and when P is named Claude Code the panel and
the log say so (`agent_own_command`, naming only `gh` and its subcommand words,
never an argument); the same argv anywhere else keeps its panel with no note.

Forwarding is deliberately narrow: one request per connection, a strictly parsed
head (RFC 9112 framing, no obs-fold, one `Host` on port 443, no upgrade), a
head csecd writes itself with `Connection: close` as the first bytes of a fresh
TLS connection, and only GitHub hosts — the token for the five names `gh`
authenticates to (`github.com`, `api.`, `uploads.`, `codeload.`, `gist.`;
any process in a grant's scope picks the host, so not every `*.github.com`
name), nothing for GitHub's other names and `*.githubusercontent.com`, and a
single-use ticket for a host GitHub redirected an authenticated request to
(csecd's token or the client's own). A request framed differently by csecd and
GitHub therefore cannot carry a token-bearing head
into a stored body. The commands, host table, interactions and limits are in
[`docs/github-proxy.md`](docs/github-proxy.md); `csec audit` HA-F12 counts a
token `gh` still keeps where any process can read it.

## Fly.io CLI token

flyctl needs its token itself (it attenuates deploy tokens, handles discharges,
and authenticates to its registry and WireGuard gateway), its API addresses are
plain URLs with no socket setting, and it has no keychain support, so a
GitHub-style proxy cannot serve it. It also rewrites `config.yml` during ordinary
commands by renaming a new file over it, which defeats whole-file protection.
What it does honour is `FLY_API_TOKEN`: with that set it uses the token for
everything, the metrics token included, keeps refreshed tokens in memory and
never writes a token back. So `csec protect --fly` imports `access_token`
through the ordinary write destination (native or 1Password, one review),
records only the resulting canonical reference in `csec.json` beside fly's
config (so `FLY_CONFIG_DIR` selects it too), and then empties `access_token` and
`metrics_token` in place, refusing any YAML shape flyctl does not write and any
change since its snapshot. `csec fly` is a consumer of that reference like the
gcloud wrapper: `csec exec --set FLY_API_TOKEN=<ref>`, so its review, grants and
output redaction are exec's, and a terminal-session grant covers later fly
commands. It sets `FLY_AGENT_ISOLATED=1` unless the user set it, because fly's
shared daemon agent gets `FLY_API_TOKEN` in its environment and serves its
socket long after the command and its grant's process are gone. A new
`auth login` runs fly with no token and then imports the new one into the
registered reference's own store. The registration file is user-writable
metadata: changing it makes `csec fly` ask for a different reference, which the
review names, and grants nothing `csec exec` does not.

## Machine identity

`csec identity` makes the Mac its own OpenID Connect issuer, and it is built
as a provider, not a new delivery path. `MachineIdentityProvider` claims
`csec-identity://<identity>/<target>`; resolving a reference mints a value on
demand from a Secure Enclave key whose handle lives only in the csecd-only
`machine-identity`/`catalog-v1` item (an enclave handle signs for any same-user
process that holds it). So the review, grants, Claude Code delegation, the
restore panel, the decision log, the phone mirror, output redaction and every
delivery adapter treat a sign-in exactly as they treat a stored secret, and
none of them knows the value was made rather than read. The provider's
`reviewDescription` names who it signs in as, to what and for how long, so no
approval surface changed: the secret-access panel draws it, the SSH panel never
sees one, and sudo never reviews an identity's use.

A `token` target resolves to an ES256 JWT (`iss`, `sub`, `aud`, `iat`, `nbf`,
`exp` at most an hour, a fresh `jti`, the RFC 7638 thumbprint as `kid`). An
`aws` target resolves to temporary credentials for one role: csecd mints a
five-minute token and calls STS `AssumeRoleWithWebIdentity` itself (an
unsigned form POST to the regional endpoint, the token in the body), returning
the bundle `csec creds aws --item` already serves. The token never leaves
csecd, and a grant for one role yields only that role. csecd reuses the
credentials in memory while more than 20 minutes remain, outside botocore's
15-minute refresh window; the expiry is the invalidation, and the key includes
the role, region, duration and signing key, so a changed target never reuses
another's; sessions last at least 30 minutes so that window exists. Neither
value is cached at rest (`CacheHint.noCache`), and the provider says its
values expire soon (`SecretProvider.valuesExpireSoon`), so automation
enrolment, which stores what it resolves, refuses a sign-in. Minting needs no
unlock and the exchange raises no authorization of its own, so a delegated
release resolves a sign-in as a reviewed one does: this provider is the one
documented exception to `resolveWithoutInteraction`'s no-network rule, and the
resolver's restore probe checks the cheap attributes first so it never mints
just to ask. Only the canonical lower-case reference parses, so no second
spelling of a target can escape a revocation keyed on the reference. Google's
external-account libraries take the token from `csec creds google`, an
ordinary credential-protocol adapter that accepts any reference. What a
consumer does with the access token it exchanges that for is outside csec.
For gcloud, setup registers a separate `google` target (`<target>-gcloud`),
sealing the provider audience and optional service account with its canonical
reference. The identity provider performs Google STS and, when selected, IAM
Credentials impersonation after authorization, with fixed HTTPS endpoints,
redirects refused, bounded replies and value-free errors. Tokens remain in
csecd memory, keyed by target, audience, service account and signing key, and
are reused while more than five minutes remain. They have `.noCache` and
`valuesExpireSoon` just like AWS credentials.

The installed fish/zsh/bash function calls `csec gcloud --item <reference>`,
which accepts any provider and uses the existing `exec --set` delivery. It
sets `CLOUDSDK_AUTH_ACCESS_TOKEN`, bypassing gcloud's cache, disables file logs
and refuses credential management/export and gcloud-side impersonation. A
single-open `exec-fd` pipe cannot serve the additional credential loads made
by storage transfer transports. The environment avoids that failure, at the
existing cost of same-user process inspection; it contains no refresh token
and cannot refresh during a long-running command. Setup preserves existing
shell startup content and installs one active gcloud function; cloud-side
setup commands explicitly use `command gcloud` with the human's existing
administrator credentials. The offline real-consumer regression is
`bin/test-google-token-cache.py`; see `docs/machine-identity.md` for limits.

Managing identities is setup at this Mac (`configure_machine_identity`,
`MachineIdentityService`): creating one, adding a target, accepting another
key in the published key set and removing an identity each take one bare
Touch ID and are written to the decision log; removing a target takes access
away, needs none, and revokes the grants that covered it and unpairs it from
every project (`ClaudeDelegationService.unpairEverywhere`), so a target added
later under the same name inherits nothing. For AWS the published key set is
the trust root of every role that trusts the issuer: `csec identity publish
--s3-bucket` writes a bucket policy that denies every change but one named
administrator's, and csecd's daily audit fetches the key set anonymously and
notifies when it holds a key this Mac never accepted. Published keys are
compared by the RFC 7638 thumbprint of their coordinates, never by the `kid`
they claim, and an accepted key is stored as that thumbprint. Google takes an uploaded
key set and fetches nothing. csec never holds cloud administrator
credentials: `csec identity setup aws|google` writes the local profile or
credential file and prints the cloud-side commands for the human to run.
Commands, setup and limits: [`docs/machine-identity.md`](docs/machine-identity.md).

## Authenticated agent socket

The agent listens on an `AF_UNIX` socket inside a per-user `0700` temporary
directory. A protected directory prevents other users from entering it but is
not treated as same-user authentication: same-UID malware can replace a socket
pathname.

Release `csec` and `csecd` therefore authenticate each other from the complete
kernel `LOCAL_PEERTOKEN` and live Security.framework code identity before JSON
is exchanged. They require the compiled Team ID, exact signing identifiers,
hardened runtime, the expected entitlement posture, and the current login UID.
The daemon rechecks the client immediately before each response. Release builds
compile out environment-controlled socket and provider overrides.

For a binary csecd has already verified, only the check's dynamic half runs
per connection. The kernel reports, for the
exact image the audit token names, whether it is still `CS_VALID` and its
cdhash, signing identifier and Team ID (`KernelCodeFacts`, a few
`csops_audittoken` calls). The static half, the signature, its certificate
chain and the role's requirement, is a trustd round trip, which a loaded Mac
answered in seconds; Security.framework evaluates it the first time a cdhash
connects, and csecd keeps each success for its lifetime
(`CodeSignatureVerdictCache`, keyed by cdhash, identifier, Team ID, path and
the requirement asked, bounded, least recently used evicted). Every `csec hook
claude` is a new process of the same binary, so after the first it costs no
trustd at all. A cached verdict outlives a revocation of the signing
certificate until csecd restarts (every install restarts it). The check never
requested a revocation check (no `kSecCSEnforceRevocationChecks`): trustd
consulted its local Valid database and OCSP cache, and fetched OCSP only when
that database flagged the certificate. An unseen cdhash still gets the full
check (`docs/threat-model.md` §Peer authentication).

Protocol v2 uses bounded, length-prefixed JSON with request nonces, typed
value-free failures, and a canonical digest of the delivery plan. See
[`docs/protocol.md`](docs/protocol.md).

A wedged daemon is bounded without bounding a human. While it handles a request
from a client that opted in, `csecd` writes a small heartbeat frame every five
seconds, and each tick round-trips through the main actor — the actor every
approval window is presented on — so a deadlocked main actor stops the ticks
instead of masking the wedge. The client fails only after twenty seconds of
complete silence, and *any* frame restarts that clock, so a prompt waiting on a
screen unlock or on a phone approval may take an hour without tripping it. The
failure names the wedge and `csec doctor`, which restarts the daemon; `csec ai`
degrades to an unprotected run rather than blocking the shell. Clients that did
not opt in are never sent a heartbeat, so the language clients are unaffected.
A request whose client goes away is cancelled, closing a prompt nobody is left
to act on; the SSH agent socket runs the same peer-exit watch.

A coding agent's wait on a human is bounded, and said out loud (csec-ia3q).
csecd shows one panel at a time, so a panel nobody is there to answer held up
every Claude Code session's request behind it for hours, each hanging every
command it ran with nothing on screen to say why. That hang is the concrete harm
this clock prevents; it re-verifies no decision. A request with Claude Code or
Codex above its requester (the coding-agent scope's own ancestry test, which
authorizes nothing here: it only shortens a wait) gets a `HumanWait` when it
reaches its service: the moment it starts waiting on a human — queued for a
turn, on the UI queue, on a panel or the restore panel — its session is told
once on stderr, by a `notice` frame its `csec ai`, `csec exec` or `csec get`
prints, or, for a requester that cannot carry one (an `ssh`, a bridge client),
by the `csec ai` above it asking csecd about once a second. If nobody has
decided it 20 minutes after it arrived (`defaults write
com.alexspeller.convenient-security CodingAgentApprovalWaitMinutes -int <n>`),
it is withdrawn: cancelled exactly as a departed requester is, so its queue slot
goes, its panel closes and its phone copy is withdrawn, logged as `withdrawn`
`timed_out`, and never counted as a Deny, so it answers no other request. Every
request has its own clock, so ten queued behind one unanswered panel lapse
together. A latch closes the race with a late decision: `QueuedPolicyReview`
marks the request decided as a human decision returns, and the deadline
withdraws only an undecided request. What it cannot see is the moment between
the decision and that return — milliseconds on the Mac, the withdrawal of the
phone's CloudKit request for a phone answer — where a lost approval costs one
re-asked panel and releases nothing. A withdrawn `ssh` is refused its next key
at once. A terminal's request has a person at the keyboard and keeps waiting;
the sudo review keeps its own 300-second bound, including its presentation wait. Claude Code's
plain `git push`/`fetch`/`pull`/`clone` run with no `csec ai` above them
(`AICommandGitPassthrough`), so their wait is bounded but not announced: when
it lapses, `ssh` reports that the agent refused.

## Grant model

A grant records a root PID and process start time, the approved references,
reason, optional expiry, the originating protocol-v2 delivery binding, the
approved scope kind, and the digest that bounds its reuse. `csecd` holds the
table in memory and also persists it, value-free, in a protected Keychain item,
so a daemon restart does not cost a re-ask (§Grants across a restart).

The daemon obtains the caller PID from the kernel rather than JSON. A grant is
usable only when a parent walk from the caller reaches the recorded root with
the same start time, which prevents PID reuse from reviving it. The walk follows
kernel parents, except that a job detached from its tree is linked back to the
tree that started it when its session proves it (§Detached jobs). References already
covered by a compatible live grant are returned without another prompt. Adding
a reference prompts for the delta and mints a grant for it beside the one that
already covers the rest. A grant lasts as long as its root process, with no
wall-clock cap, unless the human chose a 1- or 12-hour bound in the review (or
`--for` asked for one); once the root exits, nothing it leaves running is
covered. `csec grants` lists the live set, each with a typed id (`grant-…` for a
secret grant, `ssh-…` for an SSH grant), and `csec revoke` drops one, or all
with `--all`, early, writing the removal to the persisted item before it
replies; neither releases a value, and revocation only removes access, so
neither needs Touch ID.

The subtree model intentionally gives descendants of an approved root access to
the same granted references. Code running inside that subtree is therefore part
of the trusted consumer boundary.

### Detached jobs

A coding agent's tool shell can detach a job: `( job & )`, `nohup job &`,
`disown`. When the process that forked it exits, the kernel re-parents the job
to launchd, and a kernel-parent walk from anything the job runs stops there. So
each `ssh` such a job ran used to raise its own panel, offering only "This SSH
command", although the human had approved that connection for the agent's
session. `SessionLineage` links the job back through its session, from these
xnu rules (`setsid`, `forkproc`), measured on macOS 26:

- A process is in a session only by being forked from a member: `setsid` starts
  a new session named by the caller's pid, and nothing joins an existing one. So
  every member descends from the session's leader.
- The kernel never allocates a pid still in use as a process, process group or
  session ID, so a session's ID names only that session while it has a member.
- A dead session's ID can name a new session only after the pid allocator has
  gone round the whole ring, allocating every value except those in use from
  the old leader's fork until it passes them: at most three per process then
  alive, plus two per terminal and the few forks in flight past fork's
  process-count check. So a member of a newer session has a unique process ID
  (`p_uniqueid`, one per allocation, kept across exec) at least about
  `99,900 − 3 × kern.maxproc` above the old leader's. csec accepts half that,
  25,950 allocations at this Mac's `kern.maxproc` of 16,000. The ring comes
  round about every nine minutes on a busy Mac, so this margin is what keeps a
  reused ID from linking anything. Measured: a dead leader's pid came back
  98,838 allocations after its session's last member exited.

Claude Code starts every tool shell as a session leader, a direct child of
Claude. When a trusted csec client asks csecd for the schemes or for access —
`csec ai` does before every command it runs — csecd records the nearest session
leader on the caller's kernel-parent path and that leader's parent, each by
unique ID, while the leader runs. The lineage parent of a process whose kernel
parent is launchd and which does not lead its own session is its session's
leader while that still runs; once the leader has exited, and only if the
session was recorded and the process's unique ID is above the leader's and
within the margin, it is the leader's recorded parent, while that is still the
same process. That is what the kernel would say if the leader were still
running: when Claude exits, the survivors of its tree are orphaned, and so is
a job it detached. Every other process's lineage parent is its kernel parent.

Grant coverage (secret and SSH, restored grants included), the scope roots a
review offers, the scope-root re-check before minting, the Deny matching,
registered-session roots and the terminal line walk lineage parents, so a
detached job's `ssh` is covered by the Claude session's grant with no panel,
and a panel for it offers and names the Claude session. Delegation keeps kernel
parents: it needs a live chain to the Claude process, and a detached job has
none. Checks that mean "the direct parent now" (a credential-protocol consumer,
a `directParent` root, automation leases) keep the kernel parent.

The link is not specific to coding agents. Any terminal whose shell leads its
own session and runs as the user (a tmux pane, VS Code's terminal) keeps a job
it detached inside that shell's tree while the shell runs. iTerm2 and
Terminal.app sessions are led by root's `login`, which csec cannot read, so a
job detached from their shells stays unlinked.

Unlinked, and reviewed as before: a job that left its session (`setsid`, a
daemon), one forked beyond the margin, one whose leader and the leader's parent
have both exited, one whose leader exited before any csec client in the session
called csecd, and every job whose session record csecd no longer holds. Records
live in memory, at most 4,096, least recently recorded or used first out, so a
csecd restart forgets them all.

### Selectable grant scope

The launcher does not choose the root. `csecd` walks lineage parents (kernel
parents, plus §Detached jobs) above the already-verified plan root and offers
the human up to three roots in the trusted review window, narrowest first:

- **Requesting process** — the root the delivery plan asked for.
- **Coding agent** — the nearest Claude Code / Codex ancestor. An agent creates a
  fresh non-interactive shell for every tool call, so the agent, not that shell,
  is the stable boundary a human is actually approving.
- **Terminal session** — the outermost shell ancestor that owns a controlling
  terminal. The controlling-terminal test is what separates a real interactive
  session from the pipe-wired shells an agent spawns per tool call and from
  daemon `sh` wrappers.

The pre-selected default is the coding agent if one is present, else the terminal
session, else the requesting process. A candidate is offered only if a fresh
ancestry walk proves it still contains the plan root, and the same proof is
repeated before the grant is minted. The identifier the window returns is a
lookup hint resolved against the list `csecd` itself built: an unknown value
falls back to the displayed default and can never widen a grant.

The secret-access and SSH reviews carry two more lines for Claude Code
delegated approvals: the decline note saying why auto mode did not approve the
request, and the pairing line, shown while the default Claude Code scope and the
process lifetime are selected. A decline pairing cannot end, because the
session as a whole fails a gate that is judged before any pairing
(`DelegationDecline.pairingCondition`: a launch option, injected environment,
an unreviewed hook or setting, …), still offers the pairing, but its line says
when it starts to count ("… once Claude Code is started without --settings")
rather than promising it for this session; the sudo line does the same. A
hook only P's own launch brings in (a plugin its inline `--settings` enables,
an `--add-dir` directory's), which `csec setup` cannot see, is found by a
second gate evaluation without those options, run only on that decline, and
its note names the launch instead of `csec setup`. The phone mirror carries
both, in a signed `delegation` block, and draws the line by the same rule. The sudo review
carries both for a sudo Claude Code ran (see "Delegated sudo" below); it
selects no scope or lifetime, so its line always shows, and the phone carries
it unscoped. The restore panel (a secret-access variant) and the automation
layout carry neither.

### Naming the requesting terminal tab

Every approval surface shows one line for the terminal the request came from
(`TerminalSessionContext`): application, self-reported tab title, live window
and tab position, and tty. csecd resolves it only when a review is about to be
shown — never on the grant-reuse path — by walking lineage parents from the
caller (§Detached jobs) for the nearest exec-time environment naming a terminal (read through
`KERN_PROCARGS2`, copying out only an allow-list of keys and wiping the scratch
block, since a csec-launched consumer's environment can hold injected
plaintext) and the nearest controlling tty, then asking iTerm2 (by session GUID,
falling back to tty) or Terminal.app (by tty) over a bounded `osascript`
subprocess. That lookup sits in front of every prompt, so it takes the whole
window/tab/session tree in a fixed handful of Apple events — a plural specifier
such as `tty of sessions of tabs of windows` answers with one nested list — and
finds the session with no further events. Asking each session for its own `id`
and `tty` instead costs an Apple event round trip per property per session, and
a heavy iTerm2 user has enough sessions for that to become the dominant cost of
showing a prompt. The four tables arrive as separate events, so their counts are
compared at every level and a disagreement (a tab opened or closed mid-lookup)
answers with no match rather than another tab's title and position. The sudo
review takes its tab from csecd too (`sudo_terminal`): csecd walks up from the
helper that asked, past the root sudo whose environment it cannot read, exactly
as for any other caller. The helper itself sends no Apple event, because macOS
charges one to the sender's responsible application, which for the helper is
whatever ran sudo: a sudo in Terminal.app or Ghostty would otherwise make that
application ask to control iTerm2 mid-sudo, and a Yes would let it drive iTerm2
from then on. With no answer from csecd the sudo panel names the PAM tty alone
(`bin/ci` keeps Apple events out of the helper). The sudo panel leads with the
tab as the secret-access panel does, above the submitted command; csecd's walk
can name a tab whose tty is not sudo's own (a sudo from an agent's tool shell
has none), so the PAM tty joins the detail line whenever it differs. Under
tmux/screen the environment describes the multiplexer,
whose stale host-terminal variables are ignored rather than shown as the wrong
tab. Titles are attacker-influenced text and are sanitized and bounded like any
other; the position and tty beside them are what a process in the tab cannot
forge. A missing answer (app not running, Automation declined, timeout) never
blocks or alters an approval.

### Showing the whole command

The review's "Command" fact is the launcher's full argv, not the executable
basename `csec exec` puts in its `reason`. The client sends the argv with the
access request; csecd verifies it hashes to the plan's `commandDigest` (so what
the human reads is what the grant is bound to), passes each argument through
the standard output-redaction catalog built from every value it has already
released and still holds live, sanitizes and bounds the result, and hands the
review one display-ready string. Nothing new was built for that redaction: it
is the same `OutputRedactionCatalog`/`StreamingOutputRedactor` that scrubs
`csec exec` output, applied to argv instead of stdout. The values the request
itself asks for are not yet resolved at review time, so they cannot be in the
catalog; a literal csecd has never released is outside what any catalog can
recognize, which is why the window still says no secret values are shown
rather than promising none can be. A long command shows its first lines with a
"Show full command" disclosure that swaps in the complete text — the window
never silently cuts what a launcher is about to run. The sudo panel's submitted
command and an automation job's exact command are shown the same way
(`ReviewCommandText`): as tall as the command, scrolling only in what the
screen's visible height leaves, and then with a scroller that cannot fade and a
line under it saying the command continues. Lists get the same treatment
(`ReviewFittedList`): a release's or automation job's secrets, the approvals a
restore reopens and the SSH request's details are as long as they are, never a
fixed-height box, and a list too long for the screen scrolls with its scroller
drawn beside it (the rows are drawn again at the width that leaves) and a cue
under it. A panel fits all of these together (`ReviewScreenFit`), so when
several are too long they share what the screen leaves rather than one opened
command pushing the buttons and Touch ID off the bottom.

A request that carries no argv — a language client over `csec bridge`, a `csec
get` — has no launcher command to show, so its "Command" fact is the reason the
requester wrote, the one string on the panel it chooses outright. When the
plan's root is the requester's direct parent, csecd reads that requester's own
argv from the kernel (`KERN_PROCARGS2`, through `ProcessInspection`) by the
root's pid, bracketed by two reads of its start time so a pid reused in between
yields nothing, and shows it under the reason as the "Process command line",
through the same redaction, sanitizing and bound as a launcher's argv
(`AccessPolicyReview.requesterCommandLine`). Nothing the request says goes into
it. argv is still the process's own choice at exec, so it is display-only
metadata: never identity, never policy, never a grant key; what it buys is that
a reason claiming to be one program next to another program's command line is
visible. An unreadable argv (the process gone, another user's, a restricted
process) shows the reason alone and decides nothing. The line appears on the
release layout, including one with a restore section; the restore-only panel
names no request's command, the automation layout shows its job's command, and
the SSH and sudo reviews never carry a bridge request. The phone mirror carries
it as `requesterCommand` and the panel's decision-log record as its `command`.

The two widened roots also loosen *reuse*. A requesting-process grant keeps the
original rule — reusable only for an identical delivery-plan digest, which
includes the command. That is useless to an agent, whose whole job is running
different commands, so a widened grant is instead keyed on the plan's
**release-shape digest**: mechanism, descendant scope, destination, recipient
assurance, output guard, interactivity, and the plaintext-exposure
acknowledgement, with the executable, command digest, operation context, and
requested TTL removed. A widened grant additionally requires the caller's audit
session to match the approving one.

So one Touch ID lets an agent or a terminal session keep using the same
credentials for different commands for as long as the grant lasts, while an approved
sealed-environment, inherited-fd, or credential-protocol release can still never
be reused as a raw-plaintext `csec get`. Widening is a deliberate, displayed
choice: everything inside the chosen subtree is inside the trusted consumer
boundary for that reference set.

A capability-GID launch (`csec exec` in a project holding `*.csec` sidecars, and
`csec exec-file`) mints a fresh root of its own, so it is reusable **only** from a
widened grant — never from the incidental requesting-process grant its own outer
launcher left behind, which would let a nested launch outlive the authorization
that created it. Riding an explicitly widened grant is exactly what the human
chose, and exposes strictly less than the environment-injection mechanism the
same choice already covers: the bytes reach a root-owned tmpfs behind a one-time
capability GID instead of a child's environment, and never pass through the
launcher. Every other binding on that path — launcher audit-token identity, the
planted-sidecar path check, and the root helper's nonce and plan digest — is
still re-verified per launch.

### Grants across a restart

Every secret and SSH grant is also written to the `grants`/`live-v1` protected
item (§Protected state), with the facts a later csecd checks before it restores
it: the boot session, when it was minted and by which build, whether a Mac or a
phone approval minted it, and a compiled grant-policy epoch. One actor owns the
item: the grant table and the SSH service hand it snapshots, so every write
carries the newest state of both. Mints and sweeps are written behind, since a
lost write only costs a re-ask after a restart, and a reuse writes nothing. A
revocation is written before `csec revoke` replies, and if that write fails the
whole item is deleted, forgetting every persisted grant: a revocation that did
not stick would come back at the next start, the one way persistence could widen
access. If the delete fails too, `csec revoke` fails with `internal_error`,
saying the revocation holds only for this csecd run. The item holds at most
1,024 secret and 256 SSH grants in 1 MiB; a grant left out over those caps,
oldest first, still holds for the run but is not restored, and is recorded as
`grant_eviction`.

At startup, before it serves anything, csecd reads the item once and drops each
grant that fails, in this order: the policy epoch (a release that narrows grant
semantics bumps it), the boot session (a reboot restores nothing), the root's
exact PID and start time, its chosen lifetime, a reference no registered
provider serves (the grant keeps the others), and for SSH a key no longer in the
catalog. Survivors re-enter their tables and match by exactly the rules that
bound them before, so a restart never widens anything; the drops are counted per
reason on the `restart` record. So a restart after an upgrade, a `csec doctor`
restart, a crash or a kill restores, while a logout (the roots die) or a reboot
does not. Across builds, grants are trusted while the format version and epoch
match, never pinned to csecd's cdhash. Why csecd last stopped comes from the
`runtime`/`last-run-v1` item: a different boot session is a reboot, a different
cdhash an upgrade, a clean shutdown (SIGTERM, which `launchctl kickstart -k`,
`bootout` and `csec doctor` send) a restart, and anything else a crash.

A restored grant still matches, but the providers sealing its values start cold,
and a covered release carries no unlock. So the first request in a daemon
lifetime that a restored grant covers but that needs an unlock — or that
delegation would release but whose paired references are cold — raises the
restore panel, a variant of the secret-access review, and every concurrent
request that needs it, secret or SSH, waits on that one panel. It lists
everything that needs an unlock at that moment: each live restored grant (root
label and references, or SSH key, server and user) and, with delegated approvals
on, each paired project of a live, verified Claude Code session with the paired
references csecd does not hold but the touch can reopen (§Delegated approval;
a project with none gets no row), found by sweeping this
user's processes for interactive Claude Code sessions and reading each one's
working directory from the kernel. Its header names the cause — "csecd
restarted (upgrade | restart | crash | reboot): reopen what you approved" — and
its footnote says "Touch ID reopens N stores. Nothing new is approved." It has
no scope or duration control, because restoring never changes a scope.

During installation, `build-and-install.sh` runs `csec restore` just after
`csec doctor --runtime`, behind a fresh `approval-restore` presence checkpoint.
This launcher-only request supplies no references or delivery plan: csecd
collects the same eligible rows and raises or joins the same flight, including
a mixed panel already in progress. The installer waits for the entire listed
batch, so consumer requests timing out do not withdraw its review. Its socket
and arrival-time `RequestAnchor` bound it like the other waiters; losing every
requester still withdraws the review. The response is a bounded status
(reopened, forgotten, not needed, or already restored) and the value-free
summary of the fetch ahead below. Nothing creates a grant or delivers a secret
to the installer. Forget completes the stage; an
authentication, cancellation, transport or incomplete-reopen failure stops
the install with no retry. `--only-iphone` does not restart csecd and skips
restoration. Crash/manual restarts keep the request-triggered behavior.

After the restore's outcome (reopened, forgotten, not needed or already
restored; not after a failure or a requester that went away), the same request
fetches ahead, with delegated approvals on, every reference any pairing holds,
in every project, whose provider needs no csec unlock and whose values are not
made to expire soon (`SecretResolver.fetchAhead`; in practice the paired
`op://` values). One a delegated release can already serve without any
interaction (held warm by csecd, or held open by its provider, as a native
store is once the restore's touch opened it) counts as already held and is not
fetched. It is the moment the attended install waited for, so whatever
the provider's own app asks (1Password's authorization of the restarted
bridge, once per account) is answered by the person there rather than refused
hours later to nobody. It takes no csec touch and approves nothing: a fetched
value is only cached, as a release would cache it, and every later release
passes every gate as before. Each provider gets its references in one batch
(`SecretProvider.fetchAhead`), and 1Password asks an account at most once per
batch: after one refusal or timeout the rest of that account's references fail
at once, so a declined prompt is one prompt, not one per reference. A refusal
also outlasts the batch, until the next approval at the Mac (the 1Password
provider's third rule, §Resolution and cache). What could
not be fetched is reported on the reply (`restoreFetchAhead`), printed by
`csec restore` and logged as one `fetch_ahead` record; it never fails the
install, and those values are fetched on first use as before. An install
worker runs `csec restore` with nobody reading its output, so the person hears
of 1Password's prompt from csecd's own notifications instead: while it waits,
and when an account is held (§Resolution and cache). Pairings outlive
Forget, so the fetch follows it too. Values that need csec's touch stay the
restore panel's.

A restart with no attended install (a reboot, a crash, `csec doctor`) raises
its restore panel from a request instead, and an install's fetch can fail
(1Password not answering in time). So every panel a person approves at this
Mac, not on the phone, starts the same fetch ahead once that panel's own work
is done (`GrantRestoration.approvedAtMac`): the restore-only panel, a release
panel (mixed or not) and an SSH signing panel. It runs on its own, so the
approved request never waits for it, and one at a time: an approval while one
runs adds nothing, and the install's `csec restore` waits for a running one,
then finds held what it got. With every paired value held it asks the provider
nothing and logs nothing, since held values are counted from csecd's own
cache. Otherwise it asks only for what is cold, at most once per 1Password
account, and logs one `fetch_ahead` record whose detail says it followed an
approval at this Mac. While an account keeps refusing, each approval at the
Mac costs at most one 1Password prompt for it; the alternative is a csec panel
for each unattended request that wants the value. A phone approval never
starts it, because 1Password's prompt would come up on a Mac nobody may be at.
Measured before this (csec-0.64.12), every `op://` not-held decline in 48 hours
(94, and 91 panels overnight) followed the one reboot, whose restore panel was
approved at the Mac but fetched nothing ahead. The sudo review is not a
trigger: csecd hears of a Mac approval of one only in the helper's report of
how it ended (`sudo_review_end`), which it logs and does not act on.
Secret and SSH callers share this restore surface and its existing phone
mirror; sudo has no grants to restore, so its dialog does not participate.

- **Approve.** The touch's context reopens exactly the listed batch (local reads
  only; cold `op://` cache entries fold in), is then invalidated, and every
  waiter proceeds with no unlock. Only what it actually opened counts as
  reopened, in the decision log too. A grant that still could not be reopened
  is dropped, so its next request gets an ordinary panel; a paired project's
  row that stayed cold (a phone approval whose copy did not open) leaves the
  restore unused, so a later request raises it again for what is still cold.
- **"Forget these approvals"** is the panel's Deny. The listed restored
  grants are dropped (pairings stay: they are
  the human's standing decision about a project), the removal is persisted
  before anyone is answered, and every request that was waiting when the human
  decided fails with `consent_denied`; an `ssh` connection waiting on it gets no
  further signature, as after a Deny of its own panel. A request that joined
  afterwards gets its own panel.
- Either answer uses the restore up for that daemon lifetime (an approval,
  unless a paired project's row stayed cold). A later request
  whose references are still cold gets an ordinary panel, or, for a delegated
  one, declines as not held.
- Every waiter going away closes the panel without using it up or dropping
  anything, and a later covered request raises it again. A Touch ID error
  refuses only the request the panel was shown for; the others see it again.
- A lock-screen cancel is not a denial: the panel re-presents on unlock, after
  checking that its requester is still running, like every panel.
- A request that also asks for new references gets one panel for both: the
  normal credential section, where the delegation note and pairing line apply,
  and a restore section whose note reads "Touch ID also reopens N stores for
  approvals you already made. Deny refuses this request and forgets these
  approvals too." Its one Deny refuses the new references and forgets the
  restore section. A restore-only panel carries no note or pairing line
  (`bin/ci` guards it).
- Restored grants whose references are all `op://` never raise it: the
  1Password provider serves them with no csec panel (1Password itself may ask
  once after the restart). A paired `op://` reference never raises it either,
  and no paired-project row lists one: a delegated release fetches it from
  1Password itself (§Release), and if 1Password cannot serve it just then the
  request declines as not held and gets its ordinary panel, leaving the restore
  unused.
- It is mirrored to the paired phone when the phone-held unlock factor covers
  every listed reference; a phone approval then reopens them from their sealed
  remote-unlock copies (docs/remote-approval.md). Because a restore reopens
  from local sealed state only, a listed reference counts as needing that
  factor whenever csecd does not hold it and only cold storage could reopen it
  — a paired `op://` value in the biometric cache included, which only its
  cache copy covers. Otherwise it stays on the Mac, which alone can produce the
  context that opens the biometric items.

Each outcome is a `restore` record (cause `restart_restore`) in the decision
log, and a later panel that a grant dropped at load would have spared records
cause `restart_not_restored`.

### Explicit persistent automation exception

Unattended jobs are not represented as long ordinary grants. `csec automation`
uses a separate persistent, value-free job catalog plus a separate device-only
Keychain materialization. One attended local review opts an exact canonical ref
set and command recipe into the deliberately weaker `mutable_interpreted`
consumer class until revoke. Resolution still happens through `SecretResolver`
only after review; the catalog never stores provider-private identifiers.

Each trigger creates a lease for the authenticated signed csec runner's
PID/start time before it spawns the stored interpreter. The lease's value-free
half is written behind to the `automation`/`runs-v1` protected item, and a
restarted csecd restores it before serving anything, re-checked against the
live launcher and the current catalog revision: live if both still match, a
tombstone if the launcher runs but the job no longer releases it, dropped if
the launcher exited or the Mac rebooted; a record csecd cannot check because
the Keychain would not read is refused for now and kept as it was. The runner,
whose output scanner lived in the old csecd, notices the restart within about
a second whether or not its command prints, holds output until the restarted
csecd confirms the live lease, then primes a new scanner there with the preceding output and
scans what it held; a csecd that has no live lease for the run, or an update
that replaced the launcher's own binary (which csecd then never admits), stops
the command so launchd starts it again. The stored argv keeps the path the job was enrolled
with as argv[0] (a virtual environment's `bin/python` is a symlink Python finds
its environment from), while the runner executes the resolved interpreter and
refuses a run once that path leads to another one. Framework Python launchers
add a separately pinned `Python.app` consumer identity and cdhash; the runner
executes the invoked path so the launcher's own venv discovery also works.
Both images are rechecked before each run, and the bridge must identify the
enrolled app executable after its same-PID re-exec. Only that exact
direct child can use a language bridge, and only for a subset of the registered
refs until the maximum runtime, which the lease and the runner's cap both
measure in awake time so a sleeping Mac cannot separate them. A daemon enrolled
with `--max-runtime none` gets a process-lifetime lease instead: no awake
deadline and no runner kill, bound only by the launcher process's liveness (the
same prune that drops any lease when its launcher exits). A bridge whose
parent is a leased launcher always gets an automation answer: once the lease
has expired or been invalidated it is a typed denial, never the attended review
that would prompt for an unattended job. Job names and run IDs are lookup
hints, not bearer capabilities. Script, dependency, and input integrity is expressly
outside this boundary. See [`docs/automation.md`](docs/automation.md).

## Trusted review and consent

The production daemon owns one AppKit review-and-authentication window. It
contains no secret values and no editable policy controls: it shows the logical
credential references, the delivery mechanism, requester/emitter, recipient,
scope, destination, and requested duration, plus a plain-language warning
whenever the delivery is same-user-inspectable — terminal output, an unverified
pipe reader, a persistent plaintext file, or a non-interactive capture that a
coding agent or logger would receive. Because there is nothing to configure — no
risk classification and no separate compatibility checkbox — a successful
biometric is itself the authorization.

The window names each secret the way the provider that holds it describes it
(`SecretProvider.reviewDescription`): where the value resolves from, the vault
or store, the item and the field — for 1Password the account, vault, item and
field; for the native store this Mac, the store and the key. The core never
parses a reference to show it: it makes the description display-safe and draws
it, and a reference no provider describes is shown whole. Every surface that
lists secrets — the release, automation, SSH and restore layouts and the phone
card — draws them as one tree through `ReviewSecretTree`: each source (a
provider and its account) once, its vaults or stores beneath it, a single one
sharing the source's line, and each item a label in the colour its provider
chose (1Password teal, the native store purple, an undescribed reference grey),
its fields beside it. A provider's warning about where a value resolves from
sits under the vault it is about. A `daemon_proxy` review — a value csecd uses
on the requester's behalf and never returns to it, the GitHub token proxy —
heads its secrets "Secret used, never released", says beside the sensor that
the chosen scope may use the value, and its footnote
(`DeliveryReviewCopy.daemonUseFootnote`, mirrored to the phone) says the token
stays in csec. Only the secret-access layout ever shows one: the SSH layout and
the sudo review never review a daemon-proxy use. A description is a commitment: the provider
resolves exactly the source it named, so the window cannot name one account and
deliver from another.

A request that cannot be delivered never costs a panel. Before any review
(secret access, SSH signing and key registration, automation enrollment), and
before delegation or the consent queue can take the request, csecd asks each
provider whether its references exist (`SecretProvider.presence(of:)`, through
the scheme-blind `SecretResolver.referencesKnownAbsent`). A provider answers
only from state it already holds: no unlock, no prompt, no network, nothing
opened. The native store reads a document or blob index it holds open, inside
its actor, and says only whether the key is there; a store it has not opened
since csecd started is absent only when its Keychain record (an attributes-only
lookup) and its files are both missing. 1Password keeps the default,
`unknown`. A reference no provider claims is absent unless the cache holds it.
An absent reference refuses the whole request with `reference_not_found`, names
the reason, mints nothing and writes one `absent_reference` record. After a
restart a store's first request for a missing key still gets a panel, whose
failure after approval says why; its touch opens the store, so every later one
is refused up front.

The window creates a fresh `LAContext`, pairs it with Apple's embedded
`LAAuthenticationView`, and starts Touch ID as soon as the rendered panel is
visible; there is no preliminary button or Enter-key gate. Every context an
approval panel evaluates — the secret-access review (including its restore
variant, whose context reopens only the stores that panel lists and is then
invalidated), the SSH signing review, the sudo review, and each one rebuilt for
an unlock retry or a focus renewal — is built by
`ReviewAuthenticationContext` with `touchIDAuthenticationAllowableReuseDuration`
held at zero. The property would otherwise accept a biometric match the *device
lock screen* has already taken (it reuses nothing from within an application),
so a nonzero value would let a panel raised shortly after the Mac is unlocked
succeed with no finger on the sensor and nothing read. "Ask me once" is a grant
bound to the reviewed process or session, never a lock-screen match. The panel's buttons
and selectors, and keyboard focus, arrive only after a grace period
(`PromptInteractionGrace`): the panel is ordered front without becoming key and
csecd is not activated until then, so a sentence the human is mid-way through
typing — the prompt is usually raised by a coding agent, not by their own
Return key — cannot land a Space or Escape on the Deny button or change the
scope or duration. The grace lasts at least half a second and then until no key
has gone down anywhere in the session for a second (`keyboardQuietPeriod`), read
from the window server's keyboard counter
(`CGEventSource.secondsSinceLastEventType`), which reports when a key went down,
never which, and needs no Input Monitoring grant. That counter is coarse: it
publishes key presses in half-second steps (`keyboardCounterStep`), each dated
to the start of the half second it fell in and published at its end, so while
someone types steadily it reads anything from half a second to just over a
second. The grace therefore waits for a reading of one and a half seconds
(`requiredKeyboardIdle`), which steady typing never reaches; the panel goes
live one to one and a half seconds after the last key. A key pressed in the
half second the counter has not published yet is invisible to it, which is one
reason the live panel's focus presses nothing (below). Measured on this Mac by
sampling the counter every 5 ms through steady typing and pauses; the HID
layer's own activity throttle is 250 ms
(`IOHIDNXEventTranslatorSessionFilter`), so the half-second step is the window
server's. A fixed half-second was not
enough: a touch typist does not stop that fast, and a Space 598 ms after an SSH
panel appeared denied it. A human who was waiting for the prompt, not typing,
gets it at the half-second; one who keeps typing has not seen it, so it has no
cap and waits for them. Once a panel takes the keyboard, its focus rests on a
`PromptKeyboardSink`, the panel's content view, which takes first responder and
acts on nothing. With Full Keyboard Access on, Space presses whichever button
has focus, so focusing the refusing button turned a sentence resumed after a
pause into a denial, and focusing a scope radio or the lifetime popup would
reshape the grant. On the sink a Space, Return or letter only beeps; Escape is
still the refusing button's key equivalent, and Tab walks the key view loop to
every control. The same guard and sink cover the sudo review panel, and a prompt
re-presented after the Mac unlocks gets a fresh grace period, since the human has
just been typing at the lock screen. On biometric success
the daemon retains the evaluated context and hands the agent a plain approval;
the agent mints the subtree grant and calls back to release that context so a
cold cached value or cold native-store key is unlocked by the same tap. A denial,
unavailable biometrics, or lockout fails closed. A prompt cancelled because the
Mac locked or slept is none of those: the panel and its Deny button are behind
the lock screen, so the cancel can only be system-initiated. Every panel
therefore holds the request open, polls for unlock, and re-presents Touch ID on
a fresh context — the sudo review included, which waits rather than falling
through to sudo's own password prompt, bounded by the PAM module's five-minute
review deadline, at which the helper closes and the PAM transaction aborts
before Apple's fallback can open another prompt.

The preview and probe harnesses present these same real windows, so a panel a
developer check put up would otherwise look exactly like a request waiting on
the human. Each such panel carries a solid red "TEST — NOT A REAL REQUEST"
banner as its first row and "— TEST" in its title (`ReviewTestBanner`, shared
by all three surfaces). The marker is process-wide, off by default, and set
only by `cs-review-preview` and the debug sudo helper's live probes; csecd and
the release helper never set it (`bin/ci`), because a real request dressed as a
test would invite exactly the careless touch the panel exists to prevent.
Offscreen layout renders stay unmarked: nobody can mistake them for a request.
The phone mirror has no test variant: no test panel reaches it, since the
preview presents without `MirroredPolicyReview` and csecd takes a sudo phone
review only from the signed helper.

A panel nobody answers closes on its own in two cases: the sudo review at that
PAM deadline, and a coding agent's secret-access or SSH request when its wait
lapses (`HumanWait`, above). Every panel with a deadline shows one line about
it (`ReviewDeadline`, drawn by the shared `ReviewDeadlineCountdown`, which
`bin/ci` holds both panel files to): from the moment it appears a quiet line
names when it closes, and for the last 30 seconds that line counts down, so a
panel never vanishes from under a hand on the sensor. The line sits apart from
the status line, whose own messages (click to resume, waiting for unlock) it
never replaces, and is there from the start, so the countdown moves nothing
under the pointer. It adds no clock; it shows one that already ends the wait.
A terminal's request, the restore panel and setup have no deadline and show no
line. The phone copy carries the same moment in its signed request
(`closesAtMilliseconds`, the request's `HumanWait` deadline or the sudo
helper's closing moment) and its card shows the same line from the shared
`ReviewDeadlineText`, until an answer is sent from it. On the phone it is
display only: the card keeps its buttons and goes when the Mac withdraws the
request, when the phone says the request is no longer waiting. The localized Touch ID
reason carries the same bounded, value-free
delivery details as defense in depth, and all dynamic text is bounded with
control, newline, and bidirectional-formatting characters neutralized.

Touch ID answers only the active panel, and only the newest evaluation. An
embedded evaluation is paused, so a touch goes nowhere, while its process is not
active, its window is not key, or its view is covered by another window (so
during a panel's first grace, before it makes the panel key, a touch goes
nowhere — a human who stops typing to touch the sensor at once may need a
second touch); and whichever evaluation registers last, from any process (another
csec panel, the macOS Touch ID sheet that `pam_tid` or another app raises), owns
the sensor and strands the earlier one for good, with no callback, no error, and
nothing to recover even when the panel is clicked again. Only a fresh evaluation
answers. So each panel renews an evaluation armed while it could not take a
touch once it is key (`ReviewFocusRecovery`). A panel that loses key while
Touch ID is armed says "Touch ID answers only the active window. Click this
window to use Touch ID.", and when the human makes it key again it holds its
controls back at once behind a fresh grace and then re-arms Touch ID on a fresh
context, after the same requester check as the unlock re-present on the csecd
surfaces. That grace never takes the focus back: the human chose this panel, and
if they have left it before that grace ends the focus is theirs (two armed
panels that each took the focus back would trade it forever). A panel armed
before it was ever key (every first presentation, whose grace holds the focus
back) renews its evaluation, with no further grace, the first time it is key,
since another panel may have registered after it meanwhile. A callback from an
evaluation the panel replaced is dropped. Every competing prompt measured took
key status from the panel (a csec panel at the end of its grace, the macOS sheet
at once), so when prompts collide, whichever panel was made active last (by the
human, or by a new panel's own grace) is the one Touch ID answers. csecd's FIFO
and each independent sudo helper share a `ReviewPresentationLock`, an exclusive
advisory `flock` on the empty `review.lock` file in the canonical per-user
private runtime directory. The directory and file are checked for safe type,
ownership and permissions; symlinks and hard-linked lock files are refused.
The file is never unlinked: all waiters must keep using the same inode.
Nonblocking acquisition suspends asynchronously and cancels with the request,
without a new expiry. The turn covers the whole Mac/phone race, all csecd
layout variants, and any resulting live authentication session, so a queued
request builds no panel and publishes no phone copy. Closing the owning
descriptor, including on process death, releases the turn. This coordinates
presentation only; it grants no authorization and carries no secret values.
Other apps' macOS Touch ID sheets still compete, so both panel classes retain
the same focus recovery. Two costs
remain. A re-arm or a first-key renewal strands any other app's Touch ID sheet
still waiting (a sheet raised during a csec panel's first grace
included), which, unlike a csec panel, cannot be revived by a click. And a prompt that strands a
panel which stays key — a csec panel raised and dismissed inside its own grace,
before it ever took key — leaves the panel key and deaf to touches until the
human clicks another window and then this one.

A review that ends without an approval says why: `.human` (the Deny button or
Escape, closing the window, the Touch ID sheet's own Deny, or a phone Deny),
`.requesterGone` (its connection closed, or its process exited before an unlock
re-present or a focus renewal), or `.authenticationFailed` (any other Touch ID
error). A locked
panel waits and re-presents, so it has no outcome of its own. Only `.human` is a
decision about the request, and only it reaches other requests: the identical
ones already queued behind it — the same reference set and release shape, from
a caller inside the review's default scope — are refused without another panel,
while a request that arrives after the Deny gets its own. "After" is measured
against the instant the human decided (for a phone Deny, when this Mac received
it) on a monotonic clock, not when the outcome reaches the agent: a mirrored
review returns once its phone request has left the pending table (the mailbox
delete finishes in the background), and a retry made after that is a new
question. A prompt never
outlives its requester on any surface. The csec and SSH agent sockets cancel a
request whose peer has closed; before re-presenting after an unlock or
renewing Touch ID when the panel becomes key, a csecd review checks that the
requester's exact incarnation is still running.

Secret-access and SSH requests capture a `RequestAnchor` at arrival: the kernel
parent's pid and, when readable, start time (unless already parented by launchd),
and the default scope's incarnation. `HumanWait` polls it at the socket's one-second cadence,
including both queues and restore waits. Parent exit/reparenting or lost scope
containment cancels the request through the existing Mac/phone withdrawal path.
The kernel check is independent of `SessionLineage`: a surviving session link
cannot rescue an orphaned request. Display copies, restore waiter selection and
unlock/focus rechecks preserve and validate the same anchor. This does not
shorten a grant already delivered. A background request whose parent exits while
it is waiting is withdrawn too; one already under launchd at arrival has no
original-parent watch. An abandoned ssh cannot ask again with its next key.
An unreadable root-owned/setuid parent preserves the existing human-review
fallback: its kernel pid still detects reparenting, while a readable parent's
incarnation additionally detects pid reuse.
If a shared restore's displayed caller is abandoned while other callers wait,
its Mac/phone review closes and re-presents for a survivor; the restore remains
unused until a human decides. A departure by one request from the same live
caller can keep that caller's existing panel.
Never-shown requests log `withdrawn` / `requester_gone`, with the original root,
parent-loss cause and wait; shown reviews retain `panel` / `requester_gone` with
that cause. An approval whose requester or scope changes before delivery logs
the approval and `delivery_failed`, minting nothing.

Before accepting a frame, the installed sudo helper verifies that its direct
parent is still the captured parent and has effective UID zero. It reads a
complete, PID-checked `KERN_PROC_PID` record, which remains readable for set-id
sudo when libproc refuses it. A failed lookup, non-root parent or orphan fails
closed before stdin can block, and the helper repeats the check after decoding
the frame, before delegation, terminal lookup, Touch ID or either review copy.
The private PAM pipe alone is not sender authentication. This verifies a root
parent, not a particular executable; root is outside the same-user boundary.
Live synthetic panel/phone probes are debug-only, so the installed helper has
no alternate entry for a same-user caller. Its fixed-fixture PNG preview stays
offscreen. Secret-access and SSH already authenticate callers at csecd's
sockets and have no equivalent helper entry point.

The sudo review gets the same treatment from outside the panel, because sudo
(1.9.17p2) blocks SIGINT and SIGQUIT for the whole of authentication and only
records a SIGHUP for later, so a Ctrl-C or a closed tab never kills it. The PAM
module's wait loop therefore reads the pending signal set itself, as sudo does
between attempts, and polls its own descriptor on the PAM tty for a hangup; on
either it kills and reaps the helper and fails the module without Apple's
fallback prompt. The helper also watches its original parent (`EVFILT_PROC` /
`NOTE_EXIT`) and closes when sudo is killed outright (SIGKILL) or crashes. A
SIGTERM (`kill`, `timeout`) is handled by sudo itself and seen by neither, so
that review stays up until it is answered or the module's 300 s deadline
passes, at which point sudo fails without a second prompt. The deadline is the
module's, but the helper is told how much of it is left: the root→helper frame
(version 2) carries the milliseconds remaining, written just before the frame
is sent. The helper's `SudoReviewDeadline` closes the review three seconds before
the module would, wherever it is (the delegation ask, the wait for another
review's turn, the panel, whose deadline line counts down to that moment),
withdraws the phone copy and exits 75. The module treats 75 as expiry only
within ten seconds of its own deadline, by its own clock, so a faulty helper
that exits 75 early falls back to Apple's prompt instead of aborting every
sudo; a helper that is late is killed at the deadline as before. Either way the
module sends sudo one `PAM_ERROR_MSG` saying nobody answered the review within
five minutes and nothing was authorized, which sudo prints to the terminal (or
stderr) ahead of its own causeless "PAM authentication error". A decision that
wins the helper's latch first stands, as `HumanWait`'s does, and a Mac
approval that would pair skips the pairing when its call could outlast the
module's deadline. The expiry message is sent although sudo passes
`PAM_SILENT`, which sudo itself ignores for error messages: otherwise the abort
names no cause. The sufficient
review factor stores a value-free, per-transaction latch for expiry and for an
interrupt (Ctrl-C, Ctrl-\ or the terminal closing); its immediately
following requisite `review_guard` factor returns `PAM_ABORT` when either is
set. The review returns `PAM_IGNORE` in both cases so OpenPAM retains the guard's
fatal `PAM_ABORT`: OpenPAM keeps the first failing module's code, and sudo
1.9.17p2 counts a `PAM_AUTH_ERR` as a failed attempt, retrying it (a closed
terminal) or, with the Ctrl-C still pending, reporting "1 incorrect password
attempt", while it treats `PAM_ABORT` as fatal and stops at once. So neither
`pam_tid`'s Touch ID sheet nor sudo's password prompt follows an interrupt;
the module sends one `PAM_ERROR_MSG` saying sudo was interrupted during its
review and nothing was authorized, and sudo's own handler takes the pending
signal once its mask is restored. The guard also latches a Ctrl-C still
pending when it runs, which the review did not see because it arrived during
Apple's Use Password dialog: cancelling that dialog then ends sudo rather than
opening `pam_tid` (sudo reports that cancelled dialog as one incorrect
attempt). Missing transaction state also fails the guard closed. State is
initialized before any recovery path, so Use Password and helper failures
leave the guard passing and recovery intact.
The request-anchor rule deliberately excludes sudo's own parent: sudo already
has the 300 s bound over both its presentation wait and panel, while early failure would replace its
bounded review with the fallback macOS Touch ID sheet.

An explicitly paired iPhone may mirror this review — secret access, SSH
signing and the restore panel, whichever providers hold the references — when
a phone approval could carry it out (the providers say, through the resolver,
that nothing needs an unlock or that the phone-held unlock factor covers it,
and that no value would wait on its provider's own prompt at the Mac, such as
1Password's when csecd holds no open session for the account;
a value the factor's cache copy holds is read from it before its provider is
asked);
setup done at the Mac (automation enrollment, native edits and imports, SSH key
registration) stays local. csecd freezes the phone display model before starting
either path, signs its canonical protocol-v3 request with a device-bound Secure
Enclave key, and races the ordinary local review against a
CloudKit-private-database exchange polled every 750 ms. The phone signs the
scope and lifetime it selected (only an offered option is accepted) and, when
the request needs cold storage opened, the answer to its blinded unlock
challenge. The request has no expiry: csecd waits until the laptop or the
phone answers, or until it withdraws the request itself, which for a coding
agent's request or a sudo is at the deadline both copies show
(`closesAtMilliseconds`, signed when present, display only on the phone). The phone verifies its pinned Mac key before
showing an action and its Face-ID-gated Secure Enclave key signs the exact
decision, request ID, request digest, phone ID, and timestamp. csecd accepts a
decision only for a request it is *currently* waiting on, from the pinned phone,
once. The moment it stops waiting — the local window answered, the requesting
client went away, or csecd restarted and swept what it left behind — it deletes
the mailbox record, so the phone never shows an Approve button for a prompt
nobody is listening to. The request is on the phone at once, but its alert
waits 30 seconds while the Mac prompt can be answered at the Mac — none while
the Mac is locked or asleep, or Touch ID is unavailable on it — so a prompt
handled at the laptop never buzzes the phone; the alert's words come from the
verified request, written by the phone's notification service extension, never
from the push. CloudKit is an untrusted value-free mailbox, never an
authorization source. Missing enrollment or an unusable relay leaves the local
flow unchanged; rate limiting is waited through rather than treated as a
failure. Host remediation stays local-only. The sudo review reaches the phone
from its own helper: `csec-sudo-review` sends csecd one `sudo_remote_review`
request, which csecd accepts only from a peer whose live code identity is the
installed helper (and the helper accepts only from the product csecd), and
the helper races that answer against its own panel; a phone Deny falls back to
sudo's password prompt, like Use Password. With Touch ID unavailable on the
Mac the panel cannot approve, so it stays up only while the phone may still
decide: once the race hears the phone cannot, the review ends unsuccessful at
once (with no window at all when that is known first), rather than holding sudo behind a
panel nobody can approve until Use Password or the PAM deadline. The secret
and SSH panels keep theirs up instead: they have no fallback prompt to hand
over to, and their panel is where the person at the Mac learns why the
request cannot be approved. `MirroredPolicyReview` binds its phone leg's
`ReviewPhoneStatus` for the local panel (`ReviewPhoneStatus.current`, as
`HumanWait.current` carries the deadline), so their line says to approve on
the iPhone while the phone may decide and that the request cannot be
authorized once it cannot; all three surfaces draw that line from
`ReviewTouchIDUnavailable`. A panel up without Touch ID polls for it
(`TouchIDAvailabilityWatch`, every second, a fresh-context
`canEvaluatePolicy`) and, once it is back with the screen unlocked and the
requester running, arms it on a fresh context as its first presentation
would. Touch ID can also go away under an armed panel (the lid closed with an
external display): the evaluation ends with an error that is not the human's
refusal, and which code it is is undocumented, so the panel asks again rather
than reading the code (`ReviewTouchIDUnavailable.afterFailure`). If Touch ID
is now unavailable the panel carries on exactly as one opened without it,
instead of denying (secret and SSH) or falling to the password (sudo) while
the phone could still approve. If it is still available the failure stands,
unless it was a system cancel (`systemCancel`: another app came forward, or
another prompt took the sensor), which the human did not make: the panel stays
up and renews Touch ID on a fresh context, at once while it is key and
otherwise when it next becomes key, as after losing focus
(`ReviewFocusRecovery.onSystemCancel`). A panel that is cancelled again while
it stays key renews no more until it is clicked away from and back, so
something that keeps cancelling cannot make it loop.
See [`docs/remote-approval.md`](docs/remote-approval.md).

Editing a native file is a separate exact-launcher operation that asks for fresh
Touch ID and shows that every key in the named store will be exposed to the
editor; it does not create a reusable secret grant. The shipping daemon has no
environment- or argv-controlled approval switch: one would also be available to
same-UID malware launching the genuine signed binary, and automatic consent
otherwise exists only in separate test executables and injected test
dependencies. Its one automatic approver is Claude Code delegation
(§Delegated approval), which only a Touch-ID-confirmed setting csecd keeps in
its own protected item turns on: it approves one classifier-judged command at a
time, mints no grant, and releases only references a human paired with that
project on this Mac. A provider may still require its own
independent authorization — for example, the 1Password app can display a separate
account-access request — which csecd cannot merge into its window.

## Delegated approval

In auto mode, Claude Code's own classifier judges every Bash command against
what the user asked for before the command runs. With delegated approvals on,
csecd accepts that verdict in place of its panel for a `csec ai` command, but
only when it can attest, from the kernel and Claude Code's own settings, that
nothing except the classifier (or a human at Claude Code's own fallback prompt)
could have approved the command, and only for
references a human already approved for that project on this Mac. The same
judgment covers sudo (§Sudo); SSH signing asks only that auto mode approved
the command `ssh` runs under (§SSH). A secret request the approved command
makes itself — a language client over `csec bridge`, a nested `csec get` or
`csec exec` — is judged as part of that command (§Nested requests). It is opt-in and Claude
Code only: Codex's approvals cannot be attested. Whenever a condition fails the
request gets its ordinary panel, which says why.

Publisher/custom-build trust is separate from settings-loader compatibility.
The signed daemon's `ClaudeBuildVerification` catalog binds compatibility to
the live image's cdhash, never a version label or path. Unchecked images decline
secret, SSH and sudo delegation through the shared decline note, including the
phone mirror. Existing grants retain their normal lifetime. A release watch on
the maintainer's Mac starts a source audit for each unchecked image and new
upstream release; each audited image reaches every csec in the signed release
manifest's `claude_code` list, which only adds to the compiled catalog, so
support restores automatically without a csec update. See
[the audit and recovery contract](docs/claude-release-verification.md).

The settings gate follows marketplace aliases and bounded rename chains and
inspects a plugin's fallback root `SKILL.md`. A managed `policyHelper` or
`policyHelpers` configuration declines as uninspectable policy rather than
executing it or acknowledging its unseen output. That finding reaches secret,
SSH and sudo through the existing shared settings-unreadable note and phone
mirror; SSH's classifier-rule exemption does not skip it.

### Registration

`csec hook claude` already sees every Bash call. Before it prints its rewrite it
sends csecd `register_agent_command`: the session and tool-use ids, the
permission mode, its working directory, and the SHA-256 of the exact program
`csec ai` will run; the command text never crosses. Claude Code runs nothing
until the hook exits, so a registration always precedes the command it
describes. The round trip has its own bounds (0.25 s to connect and write, 1 s
of silence), is never retried and prints nothing, so a csecd that is down or
slow only means the command is not delegated. The hook registers in every
permission mode and passes the rewrite through with no permission decision in
all of them: a hook `allow` would skip the classifier and make every delegation
unsound.

csecd accepts a registration only with delegation on, from the verified launcher
whose kernel argv is exactly `<csec> hook claude`, run by a platform shell's
`-c` (`/bin/sh`, `bash`, `dash`, `zsh` or `ksh`) whose parent is a Claude Code
process, P. Every link is re-read after the walk, so a parent that died and had
its PID reused cannot slip in. Registrations are kept per P incarnation — at
most 64 P and 256 pending each, the oldest pending evicted first — and pruned
when P or the `csec ai` bound to one exits. No clock retires one.

A registration already bound to a running command is also written behind to the
`delegation`/`registrations-v1` protected item (§Protected state), so a
long-running command that asks again after csecd restarts (an install, `csec
doctor`, a crash) is not shown a panel for a call auto mode already approved.
At startup csecd puts one back only within the same boot session, while P and
the bound command are both the same incarnations (pid and start time), and
under the same caps; disabling delegated approvals deletes the item. It carries
only what the previous csecd already knew, that csec's hook saw P approve this
program for this command; every gate is judged again on each request, and the
paired references start cold, so the restore panel (§Grants across a restart)
reopens them as it does for grants. Pending registrations stay in memory: the
hook makes one per Bash call, and only a command that already asked binds one,
so a command that first asks after the restart still declines as not
registered.

### Judging a command

A `csec ai` request with references no grant covers, in exactly `csec ai`'s
request shape (`/bin/zsh -lc <program>` with the matching plan and command
digest), is judged before the consent queue. csecd walks `csec ai → shell → P`
and, before judging anything else, binds to this `csec ai` the newest pending
registration of that program under P that csecd received before the `csec ai`
started. The peer's own kernel argv must name the same program byte for byte
(which also keeps `csec tool-exec` out), and a second run of that program finds
nothing left to bind. It takes the newest because an older pending registration
belongs to an earlier call no `csec ai` bound, made in whatever mode Claude
Code was in then: one the classifier or a human blocked, and also one that ran
without reaching this point — a secret-free program, an environment naming no
reference (neither sends an access request), or a request a live grant fully
covered, unless an `ssh` under it asked for a signature no grant covers, which
binds it. Each such call leaves its registration pending until P exits or it is
evicted. It takes only one received before the `csec ai` started because
Claude Code runs a call's hook, which waits for
csecd's reply, before it starts the call's shell, so a newer registration
belongs to a later call. Both instants are on the kernel's monotonic clock:
csecd stamps a registration's arrival with `mach_absolute_time`, and the kernel
stamps a process's start on the same clock at fork (`ri_proc_start_abstime`,
read for exactly that incarnation); a start csecd cannot read binds nothing.
This fails closed: if a Claude Code release ever started its Bash shells before
running the hook, every registration would arrive after its command started and
every command would decline as not registered, which the opt-in
`cs-e2e claude-delegation` check would show. The rule binds the right
registration whenever the running call's own registration reached csecd before
its `csec ai` started. When it did not (lost, or handled only after the hook
stopped waiting), an older pending registration of the byte-identical program
can bind, with the mode it recorded; the threat model lists that residual.

Once a registration binds, the `csec ai`'s own environment must not name
`ZDOTDIR` (or `csec_ZDOTDIR`, which it resolves to `ZDOTDIR`), read for
presence only, and declines `environment_steering` if it does, or
`facts_unavailable` if csecd cannot read it. The program shell
`/bin/zsh -lc` runs `$ZDOTDIR/.zshenv`, `.zprofile` and `.zlogin` with every
released value in its environment before the approved text, and they can
define a function named like the approved command (zsh runs a function named
`bin/x`), so a release would hand its values to code the classifier never
saw. The settings gate (6) catches a settings `env` block that sets it; this
catches it however else it reached the `csec ai` (a terminal where direnv
loaded a repository's `.envrc`, `CLAUDE_ENV_FILE`, the shell snapshot). The
sudo path makes the same check (`SSHChainRule.shellSteering`); an SSH signing
does not (§SSH). bash's
startup names (`BASH_ENV`, `BASH_FUNC_*`, …) are not checked here: they reach
only a bash the approved command itself starts, and that is a script or tool
the classifier did not read either.

The checks then run in this order, and the first failure is the reason the
panel shows:

1. **Identity.** P's code, looked up from an exec-exact task audit token, is
   validly signed and satisfies Anthropic's designated requirement (pinned
   verbatim; `bin/ci` guards the literal), or its cdhash is one the human
   trusted. Genuine Claude Code carries entitlements the product-identity check
   refuses, so this is a separate `ForeignCodeIdentity`. If the kernel refuses
   the task name port, and only then (a process that changed under its token
   declines), csecd falls back to a lookup by PID with start-time and parent
   re-reads, which is not exact across an exec. It records which path it used:
   every `decline` and `delegated_release` record that checked P's identity
   carries `delegation.identityLookup` (`audit-token (exec-exact)` or
   `pid fallback (not exec-exact; task_name_for_pid refused: kern_return N)`),
   and `csec status` shows the latest as "Claude Code identity check". The SSH
   path's lazy binding checks its `csec ai` launcher with the same fallback.
2. **G3, interactive.** P is the foreground process-group leader of its
   controlling terminal and its fd 0 is that terminal. `claude -p`, an SDK
   driver and a session a postinstall script launched fail here.
3. **G4, launch options.** P's argv has no option that drives it headlessly or
   remotely (`-p`/`--print`, `--output-format`, `--sdk-url`, …), makes bypass
   reachable (`--dangerously-skip-permissions`,
   `--permission-mode bypassPermissions`, …), hands permission prompts to
   something else (`--permission-prompt-tool`), or loads settings, plugins,
   agents or channels csecd cannot see (a `--settings` file,
   `--setting-sources`, `--plugin-dir`, `--agents`, `--channels`, …). Claude
   Code reads a `--settings` file once at startup and keeps those bytes, so
   csecd reading it later could see others; inline `--settings` JSON (exactly
   `{`…`}`) is in P's argv, so the settings gate reads it instead, as one more
   layer with the user layer's reach (hooks, `disableAllHooks`, `env`,
   `defaultMode`, plugins, classifier rules) whose `classifyAllShell` never
   counts, and whose hooks and classifier rules decline as the launch, since
   `csec setup` never sees P's argv to offer them. `--restricted` (and
   `CLAUDE_CODE_RESTRICTED` in G5) declines too: restricted mode drops the user,
   project and local settings, csec's own hook with them.
4. **G5, environment.** P's exec-time environment, read from `KERN_PROCARGS2`
   for presence only, holds none of the listed names: Bun and JavaScriptCore
   loader controls, `DYLD_*`, custom CA settings, custom model endpoints
   (`ANTHROPIC_BASE_URL` and its Bedrock, Bedrock Mantle, AWS, Google Cloud,
   Vertex and Foundry siblings), anything that can forge or steer the
   auto-mode classifier's verdict (`CLAUDE_CODE_EXTRA_BODY`, which Claude Code
   spreads last into every API request body, the classifier's included; the
   third-party provider selectors `CLAUDE_CODE_USE_BEDROCK`, `_VERTEX`,
   `_FOUNDRY`, `_ANTHROPIC_AWS`, `_ANTHROPIC_GOOGLE_CLOUD`, `_MANTLE` and
   `_GATEWAY`, under which environment builds the classifier's endpoint;
   `ANTHROPIC_UNIX_SOCKET`; and `CLAUDE_CODE_AUTO_MODE_PRIOR_ASSISTANT_CONTEXT`,
   which shows the classifier the agent's own prose), shell launcher and
   sandbox overrides, settings and plugin redirects,
   `CLAUDE_CODE_ENTRYPOINT` (an SDK or IDE launched P) and `CLAUDECODE` (P runs
   inside another session), `CLAUDE_CODE_REMOTE` (a remote runtime can
   supply tools with a separate relay proxy/CA environment after launch),
   and `CCR_AGENT_PROXY_RELAY_MODE` (2.1.302's standalone relay can start
   without the remote selector). Both transports are outside the local
   session the gate attests.
   `NODE_OPTIONS` declines only with a code-loading flag. P's `HOME` must be the
   account's home, `CLAUDE_CONFIG_DIR`, if set, a local absolute path, and
   `CLAUDE_SECURESTORAGE_CONFIG_DIR`, if set, empty: any other value moves the
   plaintext record of Claude Code's sign-ins that step 8 reads. Those four are
   the only values csecd reads, and none is logged. An environment
   csecd cannot read in full declines. The other `CLAUDE_CODE_AUTO_MODE_*`
   knobs pass: they add real context (git status, repository visibility) or
   change format, temperature, concurrency or model choice, which moves the
   verdict's quality within the existing Anthropic prompt/provider policy.
5. **Project.** P's working directory is on a local disk.
6. **G1, G2 and G6, in P's settings.** Classifier rules are
   `autoMode.allow`, `soft_deny`, `hard_deny` and `environment`, which Claude
   Code concatenates from user, `--settings` and policy settings (ignoring
   project and local ones) and hands the classifier: a list without
   `"$defaults"` replaces the built-in section, so a rule can tell the
   classifier to approve, or delete its blocks — as strong as an approving
   hook. Each source's rules are one acknowledged item, digested over its
   non-default lists in order (`"$defaults"` where written). csec's own
   `autoMode.environment` entry, removed by exact text in the user settings
   only, and a list of only `"$defaults"` count as no rule; a non-array list or
   a non-string rule is unparseable, and more than 512 rules in one source too
   many. `processWrapper` needs no check: Claude Code puts it in front of its
   own re-spawns of the claude binary (daemon workers, teammates, the relaunch
   after login), never a Bash tool command, and csecd checks each such process
   on its own terms. csecd reads every source Claude Code
   applies for P that it can find: user, cowork and managed policy settings;
   project and local settings from P's and the hook's working directories up to
   their git root (and a worktree's main checkout); `--add-dir` directories;
   the global config files whose `env` block Claude Code applies; enabled
   plugins, from recorded marketplaces, marketplaces declared in settings
   (`extraKnownMarketplaces`) and the plugin cache; and skill, agent and command
   frontmatter. It reimplements Claude Code's loading rules, and where it cannot
   reproduce one exactly it over-approximates: any regex matcher counts as
   matching Bash, and any frontmatter line that could be a `hooks` key counts.
   That includes a line with a backslash (an escape can spell the key),
   except where every backslash is an escape inside a double-quoted value of
   a plain key or sequence entry, closed on the line with only a comment
   after it, which YAML decodes as the value's text, and only while every
   quoted value in the block stays on its own line. An explicit key (`? `)
   always counts: Bun makes a sequence it holds into its entries' text. The
   first failure, in
   this order: a file it cannot read; a settings `env` block that sets a G5 name
   (or `CLAUDE_CONFIG_DIR`, `HOME`, `ZDOTDIR` or
   `CLAUDE_SECURESTORAGE_CONFIG_DIR`); `autoMode.classifyAllShell` not `true` in
   the user settings or in every non-empty policy source (project settings
   cannot set it), which is what keeps allow rules — including the session,
   command and argument rules no file shows — from approving a Bash call without
   the classifier; another hook that can approve a Bash call (a `PreToolUse` or
   `PermissionRequest` group whose matcher can select Bash or Monitor, which
   runs its command in the same Bash tool shell, a plugin hooks
   module, or a `ConfigChange` hook, which can keep a deleted approving hook
   loaded) that the human has not acknowledged by digest, or auto-mode
   classifier rules in a user, cowork, `--settings` or policy source that the
   human has not acknowledged as they are now; `sandbox.enabled`;
   `permissions.defaultMode: bypassPermissions`; `disableAllHooks` or
   `allowManagedHooksOnly`.
7. **Mode.** The registration says `auto`. Every other mode — plan, default,
   acceptEdits, dontAsk, bypassPermissions — declines.
8. **Stored sign-ins** (csec-kpep). None of Claude Code's credential records
   holds a Cloud-gateway sign-in. Claude Code restores an `enterpriseGateway`
   sign-in from its secure storage at startup with no environment variable,
   then sends every API request, the classifier's included, to the gateway, so
   a planted record (or the unattended `claude auth login --gateway-json`) is
   the `CLAUDE_CODE_USE_GATEWAY` route without the variable. The records are
   every generic-password Keychain item whose service is Claude Code's
   (`Claude Code…-credentials…`, any configuration directory's or OAuth
   suffix's) under an account name Claude Code can read its item by, and
   `.credentials.json` in P's configuration home. csecd lists the items by
   attribute, which needs no item access, and reads each record as Claude Code
   does, with `/usr/bin/security find-generic-password -w`, whose access the
   item already trusts, so nothing prompts. Inside csecd, it then checks only
   whether the record's top level has the key with a value other than null,
   scanning keys itself because `JSON.parse` keeps the last of duplicate keys
   and `JSONSerialization` the first; nothing read or derived leaves csecd but
   the decline. A record csecd cannot list, read or parse declines as
   unchecked. Reads are cached by item creation and modification date, which
   securityd sets (to the second, so a date within two seconds of the listing
   is not cached), on their own queue with a two-second bound; this step runs
   last of the session's, so a request that fails another never lists the
   Keychain. A record another account's configuration keeps declines too.
   A sign-in Claude Code holds only in memory, after an interactive `/login`
   whose write failed, is not seen.
9. **Pairing.** Every new reference is paired with P's project, or recorded on
   P's own directory before pairings were keyed on the repository (§Pairing).

Settings reads are cached by file identity (path, device, inode, size,
modification and status-change time) and re-stat'ed on every request; code
identity is cached per P incarnation and exec. Nothing is cached on a clock.

An acknowledgement's digest includes the source's path, so a hook acknowledged
in one file is not acknowledged in another. Extra Claude accounts run side by
side with their own `CLAUDE_CONFIG_DIR`, whose `settings.json`, `skills` and
`plugins` are symlinks to `~/.claude`'s, and would otherwise each need every
hook and rule acknowledged again, at every change. So a file the gate reads at
`<CLAUDE_CONFIG_DIR>/<rel>` that is the same file (device and inode, stat'ed
on every request, never cached) as `~/.claude/<rel>` is digested and shown as
`~/.claude/<rel>`: one acknowledgement covers every account, and a default
session's digests are unchanged. The digest is still over the bytes read. Only
the configuration home's own files are shared this way: user, cowork and
server-managed settings, skill, agent and command frontmatter, skills-directory
plugin roots and plugin manifests and catalogues; never project, local,
`--add-dir`, `--settings` or managed sources, nor anything under a project's
`.claude`, even one inside the configuration home. A file whose hooks can name
where it sits (frontmatter, whose skill can use `${CLAUDE_SKILL_DIR}`, and a
plugin root, `${CLAUDE_PLUGIN_ROOT}`) is shared only when the home's top-level
entry holding it (`skills`, `plugins`, …) is the same directory as
`~/.claude`'s, so everything around it is the same too. A copy, a link
retargeted elsewhere, or a separate file with the same bytes keeps its own
path, and its own acknowledgement. The account's own global config, and any
regular settings file in it, are still the account's.

### Release

A one-time code is never released this way: a request with one declines
`one_time_code` and gets its panel (§One-time codes).

An approved command's new references resolve with no csec unlock: from csecd's
in-memory cache, from state a provider already holds open, or, when the owning
provider needs no csec unlock to resolve the reference (`requiresUnlockToResolve`
false: 1Password), from that provider, as a grant's covered reference is. That
fetch may contact the provider, and 1Password itself may ask once after a
restart, but it never raises a csec panel and never reads the biometric cache
tier. A paired value was already approved for its project once, so a restart
alone is no reason to ask again (csec-0.64.2). A reference whose provider needs
csec's touch (the native store, csec's own Keychain) stays warm-only.
1Password authorizes a restarted csecd's new bridge only with a person there to
answer it, and installs restart csecd, so the attended install's `csec restore`
fetches every paired reference of this kind ahead, as does every panel
approved at the Mac afterwards while one is still cold (§Grants across a
restart); a later release then finds it held. Measured before this (csec-0.64.11), 218 of
221 `op://` not-held declines in 48 hours fell between an unattended restart
and the next time someone was at the Mac.
References a live grant already covers resolve as the grant path resolves them.
When the provider cannot serve a value with no interaction (1Password locked,
say), the request declines `not_held` and its panel and log record say why, in
the provider's own value-free words (`ProviderDiagnosableError.boundedReason`,
csec-0.64.6). No grant is
minted: one registration authorizes exactly one classifier-judged command, and
the next command or an MCP server gets nothing from it; a request made inside
that command rides it (§Nested requests). The values are registered for output
redaction like a process-lifetime release, and the release is recorded as
`delegated_release`, decider `delegated`, in the log's usage stream. Because it
runs before the consent queue, a delegated release never waits behind a panel on
screen and never reaches the phone.

A value csecd does not hold and whose provider needs csec's touch — after a
restart every sealed store is cold — may still be reopened by that daemon
lifetime's one restore panel, which a request
delegation would otherwise release raises or joins (§Grants across a restart);
otherwise the request declines as not held and gets its panel, as does one
whose provider could not serve it just now (1Password locked or declined in its
own app), without the restore panel. A request that went to the restore panel is never released on the approval it had before: it
starts over at the present (coverage, the Deny ledger, delegation) and never
waits a second time. The panel may have been up for hours, so a covering grant
revoked or run out, a pairing revoked, delegation turned off, or a human Deny
of the same question meanwhile gets the request its ordinary panel (or the
Deny's refusal), and a value still cold declines as not held. An SSH signing
that went there starts over the same way before it signs: it re-checks the
Deny ledger and the covering grant (signing under one that now covers it) and
asks delegation again, which cannot wait a second time. A request that waited
for its consent turn is first checked against a human Deny it waited behind,
then judged again, since the panel ahead of it may have paired or reopened
what it needs.

### SSH

The rule for SSH is deliberately simple (Alex, csec-0.11): **an SSH signing
whose Claude Code command auto mode approved signs, with no panel.** csecd
checks only that auto mode, in a verified Claude Code session, approved the
command `ssh` runs under. It does not judge what runs between that command
and `ssh`, where `ssh` connects, or which classifier rules steered the
classifier.

A signing request from Apple `ssh` that no grant covers is judged before the
SSH review turn. csecd walks up from `ssh`, at most 32 processes, to the
command's anchor, which is one of these:

- the nearest `csec ai` under a shell under P. That is the `csec ai` already
  bound by its own access request, or else one bound lazily by the same
  newest-received-before-it-started rule. A `csec ai` bound lazily must also
  be the signed csec launcher: a `git push` from an environment with no
  references never sent an access request.
- with no `csec ai` above `ssh`, Claude Code's Bash tool shell, for a git
  command that reaches a remote, which the hook leaves unwrapped (§Output
  redaction and AI hooks) so that agents isolated in worktrees can push.

Claude Code (2.1.280, measured with `ps`) runs each Bash call as a child of P
with argv `/bin/zsh`, `-c` and a script. The script sources the session's
shell snapshot, sets a few options and runs
`eval '<command>' < /dev/null && pwd -P >| <file>`. The command is
single-quoted, with each `'` spelled `'"'"'`. ` < /dev/null` is left out for
a heredoc or an input redirection, and a one-word command is not quoted.

The tool-shell anchor is the nearest ancestor that meets all of these
(`ClaudeToolShell`):

- its executable is `/bin/zsh`, and its argv is exactly that shape;
- its script parses cleanly;
- exactly one command in the script can run `eval`, by any spelling
  (`\eval`, `builtin eval` and a computed name all count). That command is
  the plain `eval` with one word that is literal in both shells.

That word is the command, exactly as the hook saw it. A framing csecd cannot
read has no anchor, and the panel asks. Examples are the `-l` Claude Code adds
with no snapshot, the credential-scrub framing's `\builtin eval` probes, and
a sandbox wrapper or a shell prefix other than csec's own. csec's own prefix
(§Output redaction and AI hooks) is an anchor of its own: a `csec ai
--claude-code-shell <framing>` directly under P, whose framing the same
`ClaudeToolShell` reading accepts, binds a wrapped registration of its `eval`'s
word, exactly as a `csec ai` under a tool shell does.

A tool shell binds only a registration that meets all of these:

- the hook marked it unwrapped;
- it holds the SHA-256 of that text;
- csecd received it before that shell started;
- csecd's own reading of the text (`AICommandGitPassthrough`) says the hook
  registers it.

A `csec ai` never binds an unwrapped registration, and a tool shell never
binds any other.

Then the request signs when all of these hold. Each one is part of the fact
that auto mode, in a verified Claude Code session, approved the command:

- a registration from csec's hook is bound to the anchor (`not_registered`
  otherwise);
- P passes the identity check and G3, G4 and G5, with P's `HOME` and
  `CLAUDE_CONFIG_DIR`, as for a release. A `--dangerously-skip-permissions`
  session declines `launch_option`.
- P's project is on a local disk;
- the settings gate passes G1, G2's approving hooks and G6. A hook that can
  approve a Bash command means auto mode may not have approved it at all.
- the registration was made in `auto` mode;
- the key is held warm. A cold key waits on the restore panel, as before, or
  declines `not_held`.

Nothing else is asked:

- **The processes between the command and `ssh`.** An interpreter, a package
  manager, `sh -c`, a git hook, a wrapper such as `timeout` or a deploy lock,
  a script inside or outside the repository, or a bash heredoc all sign. No
  launcher script is pinned, and no argv is matched against the approved
  text.
- **The environment below the command** (`ZDOTDIR`, `GIT_*`, `HOME`,
  `BASH_ENV`).
- **The destination.** The key, the server's host key and the remote user
  need no earlier approval. A destination pairing that exists still counts as
  used, but none is required, and an SSH panel offers none.
- **Classifier rules** that a human has not acknowledged in user or policy
  settings, or `--settings` rules. These still decline a secret release and a
  sudo.

An `ssh` that csec cannot tie to an approved command still gets the panel.
That covers:

- an `ssh` a human runs in a terminal, and Codex's `ssh`;
- a Claude Code command run in another mode, or in a bypass session;
- a command whose registration never reached csecd;
- a process detached from the command, which launchd adopts once its parent
  exits;
- an `ssh` below a process csecd cannot read, such as a setuid program, which
  hides the anchor.

The walk stops at launchd or at the first process csecd cannot read. Root's
`login` above every iTerm2 and Terminal.app shell ends the walk above P,
which is fine. No SSH grant is minted, so concurrent connections are each
judged on their own.

**The trade-off.** Every process under an auto-approved command can use the
agent's SSH keys for any destination with no human look. That includes a
trojaned `postinstall` under an approved `npm install`, a `pre-push` hook
under `git push`, a script the agent wrote, and a `pushInsteadOf` planted in
a git configuration. Alex accepted this on csec-0.11, in exchange for no
panels on approved work.

The rule this replaced judged every link between `ssh` and the command. Each
`ssh` had to descend from git, an SSH client, `timeout` or a launcher script
a human had pinned, matching the approved text. It also required the
destination to have been approved once and the classifier rules to be
acknowledged. In practice it raised panels for approved work far more often
than for anything else.

Pairings written under that rule still carry their pinned launcher scripts
and SSH destinations. csecd keeps reading them, lists them and revokes them,
but no longer consults either for a decision.

### Sudo

A sudo Claude Code's text runs reaches csec's PAM module, which spawns the
sudo review helper as before; the helper now asks csecd (`sudo_delegation`)
before it draws anything or mirrors anything to the phone. csecd admits that
request only from the helper's code identity, and the helper takes the answer
only from the product csecd, as on the phone leg. An approval ends the review
with exit 0 and no panel; a decline gives the panel its note (and the pairing
line, below); anything else (not Claude Code's sudo, delegation off, no answer
within 2.5 s) leaves the panel as it was. The PAM module is unchanged.

sudo runs as root, so the kernel refuses csecd its `proc_pidinfo`
(`PROC_PIDTBSDINFO`; xnu `proc_security_policy` compares effective uids) and its
argv (`sysctl_procargsx`), and sudo's own start time with them. What it does
answer for any process (`KernelProcessRecord`, measured against setuid-root
`/usr/bin/top`) names the sudo: the helper's parent per `KERN_PROC_PID` must be
`/usr/bin/sudo` (`proc_pidpath`), valid and signed as part of the OS (`csops`
CS_OPS_STATUS), with effective uid 0 and this account as its real uid; the
helper and the sudo are read again after the walk, so the sudo judged is still
the helper's parent with the same parent of its own. The argv csecd judges is
the one the PAM module rendered for the panel (`csec_build_redacted_command`),
decoded by `SudoCommandDisplay`: that rendering is one-to-one (a display the
module would never write is refused; `build-sudo-review.sh` checks the C
rendering against the Swift decoder byte for byte), and an argument the module
redacted (`[csec:secret-like]`, or a released value's `[csec:secret-N]`) is
known only up to the marker, so it matches only a word with an expansion that
covers its known prefix, never literal text.

From sudo's parent the walk is the SSH walk's (`SudoChainRule`): sudo's parent
must be the `csec ai` that ran the approved text (a text that is the one
command, which zsh execs), its program shell (`X; Y`, `X | grep`, `X && Y`,
`$(X)`, measured), or `timeout` under either, whose command must then be
exactly sudo's argv (so a redacted argument there declines). Anything else is
a process the classifier never read and declines `sudo_indirect`: node,
python, a script (pinned or not), `xargs`, a git hook, a subshell (`(sudo X &)`
is reparented to launchd once its subshell exits). The hook never leaves sudo
unwrapped, so there is no tool-shell anchor. `ZDOTDIR` in the `csec ai`'s
environment declines as for SSH. The topmost link must match a simple command
of the text by the SSH word model: name `sudo` and its arguments, or the
`timeout` that runs it. sudo's own options are read as sudo 1.9.17p2's
`parse_args` reads them, and the four that hand root something the text does
not show decline `sudo_option`: `-E`/`--preserve-env` (the agent's whole
environment), `-s`/`--shell` (the shell `$SHELL` names), `-i`/`--login` and
`-e`/`--edit`; so does an option csecd cannot read (unknown, an ambiguous
abbreviation, or redacted where an option may stand). Then P's registration,
identity, gates, auto mode and project are judged exactly as for a release, and
last the consent: a human must have let auto mode run sudo in this project
(`sudo_not_approved` otherwise). Approved sudo is logged as a
`delegated_release` on the sudo surface with the redacted command; a decline
on the sudo surface with it too. However a sudo's review then ends, its record
names this same Claude Code process as its root (see "Decision log").

What this leaves, all of it shared with a human-approved sudo, whose panel
shows only the command line: sudo keys its ticket on the parent pid and its
start time when there is no tty (sudo `timestamp.c`), so for five minutes, and
no longer than that program shell lives, a later sudo whose parent is the same
program shell skips PAM and csec, including one a command of the same text
execs; a command of the text that execs `/usr/bin/sudo` with the same argv
looks exactly like the typed sudo, and could do so with another `PATH` or
`HOME`; and Apple's sudoers keeps `HOME`, `EDITOR`, `VISUAL` and
`SSH_AUTH_SOCK` and sets no `secure_path`, so root resolves a bare command on
the agent's `PATH` and reads the account's dotfiles. What is new is that no
human reads a root command the classifier approved, which is why sudo is
paired per project (csec-2rno.1): a project where nobody has run sudo through
auto mode yet still gets one human look.

### Pairing

An SSH panel offers no pairing line and pairs nothing (csec-0.11): SSH
signing never consults a pairing (§SSH). What follows about SSH destinations
and launcher scripts describes pairings written before that change. csecd
still reads, lists and revokes them.

A pairing is written only on the human-approval path, when all of these hold at
approval time: delegation is on; the panel was raised for a request delegation
declined, so a `csec ai` request whose chain reaches a Claude Code P (a nested
`csec get` or `csec exec` is never judged, so never pairs, and an SSH signing
never offers one); the
approval was made on a surface that showed the pairing line
(`AccessPolicyApproval.pairingLineShown`: the Mac panel from the line's own
visibility when Touch ID succeeded, the paired phone from the acknowledgement
it signed, which csecd checks against the signed selection by the shared rule
`RemoteApprovalReview.pairingLineApplies`); and the selection is exactly the
default Claude Code
scope with the process lifetime. It pairs what that approval authorized: the
new references, in that project. Before csec-0.11 an SSH approval paired its
key, server host key and remote user, recorded with the project it was
approved in but holding for every project (csec-1vmv.2), and pinned the
launcher scripts the line named in that project.
sudo is paired per project too (csec-2rno.1): a sudo panel raised for a sudo
delegation declined in a project with no sudo pairing carries "Approving also
lets Claude Code auto mode run sudo in <project> until you revoke it". The
panel selects no scope or lifetime, so the line always shows. csecd keeps the
offer for exactly the helper it answered; a Touch ID on that panel is reported
by the helper (`sudo_pairing`), a phone approval by the acknowledgement the
phone signed (its card carries the line unscoped,
`RemoteApprovalReview.Delegation.Pairing.unscoped`, which applies to the one
approval there is), and csecd pairs only while that helper still serves a
root sudo, spending the offer either way.
The panel shows the pairing line exactly when those conditions would hold and
approving would pair a reference the project does not have yet, and hides it
live when the scope or lifetime changes: "Approving also lets Claude Code auto
mode use these in <project> until you revoke them". It is never truncated.
`csec grants` lists an SSH destination an earlier csecd paired as `ssh (every
project)` under the pairing it was approved with; revoking that pairing
removes it unless another project's pairing holds it too.

A project is the git repository P's working directory is in, so one approval
covers the repository's main checkout, every linked worktree and any
subdirectory; outside a repository it is the working directory itself. csecd
walks up from the directory to the nearest `.git` without leaving its file
system (as git's discovery does) and keys the pairing on the repository's
shared git directory: the kernel's canonical path for it, the volume's UUID
(not `st_dev`, which APFS numbers per mount) and its inode. A `.git` directory
is the repository's own. A `.git` file is followed only for a linked worktree
the repository vouches for: its `gitdir:` names `<common>/worktrees/<id>`,
whose `commondir` names `<common>` and whose `gitdir` names this checkout's
`.git` back. A downloaded archive can carry any `.git` file, so a pointer
the repository did not write borrows nothing (Claude Code checks its project
identity the same way). A re-clone at the same path, a repository on another
volume, and one nested inside another are different projects. Everything
else falls back to the directory: a submodule or a separate git directory (a
`.git` file whose target has no `commondir`); a symlinked or unreadable
`.git`, or a `.git` directory holding a `commondir`; a pointer that does not
parse or exceeds 4 KiB; a target without `HEAD`, `objects` and `refs`; a
working tree, `.git` or git directory another user owns (git's ownership
rule); a git directory not on a local disk; a repository whose working tree is
`/` or the home directory or above it, which would take in every directory
beneath it; and an unknown home directory. A working directory that is not on
a local disk is never paired. The gates and Claude Code's settings scope still
read P's own working directory. A pairing recorded on a directory before
pairings were keyed on the repository is never moved: it still holds in that
directory, alongside the repository's pairing, and nowhere else, so the first
session elsewhere in the repository asks once. Pairings persist in the `pairing`/`v1` protected item
(§Protected state) until revoked: at most 256 projects, each with at most 256
references, 256 references for csecd's use only, 256 SSH uses and 64
launcher scripts, and whether sudo is paired, in 512 KiB. Format 2 of the
document added launchers, format 3 sudo and format 4 use-only references;
older items migrate with none and no sudo. A csecd that predates a
format reads such an item as unreadable and starts with no pairings, and the
store keeps the item as found (§Protected state): what that csecd pairs holds
for its run only, and the newer build finds every pairing it saved. A sudo
pairing alone keeps a pairing. Launchers alone do not keep a pairing, and
unpairing an SSH use leaves them.
Past the item's size, a pairing being written sheds its oldest references,
then launchers, then SSH uses. Recency is kept in memory only, so
the item is rewritten only when a pairing is added or removed; past a bound the
least recently used project goes first (stored order before any use), and every
eviction is logged. `invalidate_cached_references` leaves pairings alone. With
delegation off, pairings are never listed, used or reopened, and disabling
deletes them all.

`csec grants` lists pairings with `pair-…` ids beside grants, with each
launcher script by its path and the files it sources (never a digest), and
`sudo: auto mode may run sudo in this project` when sudo is paired. `csec
revoke pair-…` unpairs a project, launcher scripts included, `csec revoke --all` clears every pairing along with
every grant, and revoking a grant rooted at a Claude Code process also unpairs
what it covered from that process's project: its repository's pairing and any
pairing recorded on its own directory. Every change is written before
csec replies, and one that could not be written is reported.

### Opt-in and opt-out

Only csecd's `delegation`/`settings-v1` protected item holds the opt-in. No
environment variable, argument or file can turn delegation on: `bin/ci` pins
that the delegation code reads none, and that csecd builds the service only over
its protected stores. `csec setup` step 3c ("Auto-mode approvals"), offered when
csec's Claude hook is installed and csecd can delegate, explains the trade,
lists what enabling would trust — every other hook that can approve a Bash
command or keep Claude Code from reloading its hooks, flagging one that runs
fetched code with no pinned version (`npx pkg`,
a download piped to a shell), and every Claude Code build Anthropic did not sign
— and plans one atomic edit of the Claude Code user settings: add
`autoMode.classifyAllShell: true`, and replace csec's `autoMode.environment`
entry with a delegation-aware one telling the classifier that approving
`csec ai -- <cmd>` releases the project's secret environment values to
`<cmd>`. After confirmation it writes the file, then sends
`configure_delegation enable`. csecd computes the inventory again itself and
raises one Touch ID panel listing that inventory and naming the terminal: the
settings layout of the secret-access review (`SettingsChangeReviewDetails`,
through `SettingsChangeConsent`), Mac-only and never mirrored. It used to be a
bare OS sheet, which took a Space typed as it came up for its Deny; the panel
has every panel's typing guard, focus renewal and unlock re-present. A refusal
changes nothing in csecd, and setup undoes its own edit. A panel that does not
approve says why: csecd logs a
`settings` record with why it ended (the human's Deny, a sheet macOS
dismissed, a finger Touch ID did not recognise, and so on) and how long it was
up, and setup prints that reason after "Touch ID was not given", so whoever
ran setup can tell a Deny from a sheet worth showing again. A sheet macOS
takes down unanswered (`systemCancel`) with the screen unlocked is shown once
more before it counts; a locked screen waits for unlock, as the panels do. On approval csecd stores the opt-in, the policy version consented to,
every listed build by cdhash, every listed hook (and each source's classifier
rules) by digest, and the settings file setup edited with whether csec added
`classifyAllShell`. When that record names another file than the current
`CLAUDE_CONFIG_DIR` reads, setup names both and asks whether to move
delegation (default No; csecd's sheet names both files), and reverts the
recorded file only after csecd has recorded the new one, so a refused or
failed move leaves both as they were. A `CLAUDE_CONFIG_DIR` whose
`settings.json` is a link to `~/.claude/settings.json` reads that file, so
setup checks, edits and records `~/.claude/settings.json` (with its usual
owner, mode and single-link checks), never replaces the link, and offers no
move. A setup question whose input closes
(EOF) is answered by nobody: setup stops with exit status 1 rather than take
its default, since no default is safe for every question (Yes restores
settings behind a sheet, No to "Keep delegated approvals on?" turns them off). Trusting a later build (`trust_build`) or acknowledging a
later hook or changed rules (`acknowledge_hooks`) takes the same kind of sheet;
a changed hook has a new digest and declines until acknowledged; and a sheet
that was still up when delegation was disabled changes nothing. An
acknowledged source's rules replace its earlier acknowledgement and keep a
128-bit digest per rule, which is display only: `csec setup` reads the file
and shows, in full, every rule not in the last acknowledgement and how many of
those are gone, so the human acknowledges what changed rather than rereading
every rule. `csec setup auto-mode` runs step 3c alone. A csec release that widens what delegation approves bumps a compiled
policy version, and delegation then stays off (`reconfirmation_required`) until
setup confirms again. Version 2 lets pinned launcher scripts stand between
`ssh` and the command. Open Claude Code sessions pick up the settings when they
restart. The settings panel is a layout of the secret-access surface, so the
three-surface rule for approval panels applies to it; a provider with no panel
(an injected test consent) still asks with the one-line reason on a bare sheet.

Every other setup step csecd asks a touch for takes the same panel
(`settingsConsent` in `AgentRuntime`, `ConsentProvider.approveSettingsChange`):
turning native-store backups on, syncing, restoring and turning them off;
pairing and unpairing the phone; creating or removing a machine identity,
adding a sign-in and accepting a published key; removing a protected SSH key;
revoking an automation job; deleting stored files (`csec edit --remove`); the
uninstall cleanup; and host fixes. Each lists
what the touch changes, names the requesting tab, and closes if its requester
goes away. A step that is not a change to csec's settings says what it is in
its own footnote (a restore, deleting stored files, the uninstall cleanup, host
fixes). Backup sync, setup and restore and phone pairing keep the panel's local
unlock to read the stores they seal, and deleting stored files keeps it to
rewrite the store's index; the rest discard it. `bin/ci` holds csecd to this: only the
consent providers ask for a bare sheet, only the consent sheet and the two
review panels evaluate a Touch ID policy, and every service but the grant
restoration and the Agent gets the settings consent.

Turning delegation off needs no Touch ID, since it only removes authority. csec
reads csecd's record, reverts exactly the settings file it names — removing
`classifyAllShell` only when csec added it, and returning csec's
`autoMode.environment` entry to what enabling found (the standard entry, or
none) — and then csecd deletes the settings item and every pairing. The revert
restores the file's meaning; csec writes it in its own format.
`csec uninstall` runs the same revert first. `csec revoke build-…` and
`hook-…` untrust a build or forget a hook through the same path as
`configure_delegation`'s `untrust_build` and `forget_hook`.

### Decline notes

When delegation declines a Claude Code request, its panel says why below the
footnote — "Auto mode didn't approve this: …" — in fixed, csecd-authored copy
whose parameters (an option or name from the fixed lists, a settings path, the
project's name, a reference) are sanitized and bounded; raw argv is never
shown.
The note appears only with delegation on, only for a request that came from
Claude Code (a registration of its program, or P's identity, says so), and only
on the secret-access and SSH layouts. A terminal's `csec exec`, a bridge, an
automation enrollment and a restore-only panel never carry it; the phone mirror
carries it in the signed review's `delegation` block. Each decline is
counted and recorded once per requesting process as a `decline` record with its
reason code, and `csec status` shows the counts and, as "Claude auto-mode last
decline", the last reason this csecd run.

A decline only `csec setup auto-mode` can end — an untrusted build,
`classifyAllShell` off, a hook or classifier rules not acknowledged — repeats
for every delegated request until the human acts, and the human may not be
watching the panels. So csecd keeps that reason's notice for the `csec ai`
the request ran under, and hands it over once: on the `access` reply, approved
or refused, for a secret release, and on the `end_output_redaction` reply for
an SSH signature or sudo under the command. `csec ai` prints each notice once
on stderr ("delegated approvals are waiting on setup … Ask the user to run
`csec setup auto-mode`"), where the agent session reads it. An unwrapped git
command has no `csec ai` to receive one.

Changed classifier rules don't wait for setup (csec-0.64). When a secret
release declines because rules are unacknowledged, `Agent` asks the delegation service to show
the change before the request's own panel: one settings-layout panel ("Claude
Code's Auto-Mode Rules Changed", `ClaudeDelegationService.changedRulesReview`)
listing, per source, each rule not in its last acknowledgement, a
`soft_deny`/`hard_deny` that lost `"$defaults"`, and how many acknowledged
rules are gone. The rules are csecd's own reading, carried on the gate's
finding (`ClaudeHookSource.rules`, never on the wire), so the panel shows
what the acknowledged digest covers. Approving acknowledges exactly those
rules, as `acknowledge_hooks` does, and the request starts over and
delegates. Every request that declines on a change while its panel is up
waits for it. A Deny is kept for the csecd run; a panel that went with its
requester is shown again for a request still waiting. The paired phone can
decide it too (av-rcqg): it is the one settings change mirrored, as a
`settings` review bound to exactly the sources it acknowledges
(`acknowledgementDigest`), and a phone approval or Deny is logged
`human_phone`. While the screen is locked it is raised only when the phone can
decide it; otherwise the request's own panel serves. Only on a request's first pass, which holds no
consent turn, and once per request. An SSH signing ignores rules already; a
sudo is left to its own panel, whose helper PAM bounds to 300 s.

A hook added since the last acknowledgement takes the same panel (csec-0.64.7):
before, each request declined `other_hook` to a panel of its own until someone
ran `csec setup auto-mode` (one hook added on 1 Nov cost one session 1 h
40 min of panels). The panel lists each new hook by source, event and matcher,
with what each handler runs (`ClaudeHookSource.handlerSummaries`: a command
and its arguments, or the handler as written; display only, covered by the
digest, never on the wire), warns when it runs a package it downloads
unpinned, and is titled for hooks; changed rules and new hooks share one
panel. That is more than `csec setup auto-mode` lists, so a hook no longer needs
a terminal. An SSH signing declining on a new hook takes it too, before its
review turn; a sudo still does not.

### Nested requests

A request that is not itself a `csec ai` — a language client over `csec
bridge` (`av slack` reading its token), a nested `csec get` or `csec exec` —
is judged as part of the command it runs under (Alex, csec-0.20, extending
csec-0.11's SSH rule to secrets). csecd walks from the requesting peer, up to
32 processes, to the nearest ancestor whose argv is `csec ai …` under the Bash
tool shell under P, exactly as the SSH path finds its anchor. That `csec ai`'s
registration is used if one is bound to it already (its own release bound it),
or bound now when the `csec ai` is the signed launcher, by the same newest
pending, received-before-it-started rule. What runs between the request and
the `csec ai` is not judged. The rest is a secret release's judgment: P's
identity, G1–G6, auto mode, ZDOTDIR on the `csec ai` (its program shell's
startup files ran before the approved text), and every new reference paired
with the project. The release is the same `delegated_release`, resolving new
references with no csec unlock, with the same restore-panel wait. A decline gets the panel with its note and, under
the usual rule, the pairing line, so the first such request in a project pairs
it. A request with no `csec ai` above it — a terminal's, Codex's, an unwrapped
git command's credential helper — is not judged and its panel shows no note.

The trade-off: code the approved command starts can ask csec for any
reference paired with the project, not only those in its environment, with no
panel. Pairing still bounds it to what a human approved for that project, and
it releases only values csecd already holds.

### Bounded fact collection

Kernel facts are read off the delegation actor, on dedicated serial queues, with
bounds: 300 ms for a request, 1 s for the restore panel's sweep of live Claude Code sessions, and 2 s for the settings
and builds `csec setup` and `csec status` inspect. A healthy read takes microseconds to a few milliseconds;
the bound exists because the kernel's own working-directory and descriptor reads
stat what they name, so a session sitting in a hung network mount could stall a
read indefinitely. Each bound is on a read's own run, from when it starts:
reads queued behind one another (the requests a rules-changed acknowledgement
releases together) are not declined for their wait, which has its own limit
(1 s, or the queue's bound if longer) that answers a caller queued behind a
hung read without marking the queue stuck (csec-0.64.8, csec-0.68). A read
that outlives its bound declines the request
(`facts_unavailable`, attributed to Claude Code only when a registration of that
program exists), and while it stays stuck every later read on that queue
declines at once instead of piling up threads. The restore sweep keeps what it
found before a stuck read. This is a hang bound, not a re-verification clock.

What a delegated `csec ai` receives is in its environment, so it reaches every
descendant of that command, exactly as under a grant. The attacks delegation
does not stop, and the classifier's own error rates, are in
[`docs/threat-model.md`](docs/threat-model.md#delegated-approval).

## Delivery

### Language-client heap delivery

The Ruby gem and Node.js npm package send references, a reason and, optionally,
a TTL to the fixed root-owned
`/Library/Application Support/ConvenientSecurity/bin/csec` bridge. Without a TTL
the grant lives as long as the scope root the human picks, exactly as for
`csec exec`; an explicit one is honoured as given (the clients accept 1 to
172,800 seconds). The helper uses a scrubbed environment and private close-on-exec pipes.
It verifies the direct language-runtime parent PID, start time, and executable
path before requesting and again before returning a response. Plaintext reaches
the authorized process's heap, not its initial environment or argv.

Assigning a returned string to `ENV`/`process.env`, interpolating it into a
command, logging it, or loading hostile code into the language process is
outside this protection.

### Registered session roots

`csec session -- <command>` registers the signed launcher's current PID and
kernel process start time with `csecd`, installs a random non-secret
`CSEC_SESSION_ID`, and replaces itself with the requested command. The daemon
keeps at most 64 live registrations and removes one when that exact process
incarnation exits. A descendant helper may name the ID, but every access still
requires the caller's audit session to match and a fresh lineage walk
(§Detached jobs) to reach the registered PID/start-time pair. The ID is therefore a lookup hint,
not a bearer capability; copying or forging it outside the subtree fails.

The delivery plan and review distinguish a registered `broad_session` root from
an ordinary per-command root; a grant is reused across sibling descendants when
the delivery-plan digest matches. Grant TTLs, plan digests, and lineage
checks apply independently of registration lifetime.

### Credential protocols

Explicit `csec protect` paths use the same type-aware apply engine as bulk setup,
with storage scoped to the target's location. AWS migration uses a bounded,
position-preserving INI plan: import each static profile durably, install its
canonical reference in `credential_process`, then remove only that profile's
static credential fields. It preserves unrelated and derived-profile settings,
rejects ambiguous/conflicting configuration, and rechecks both input snapshots
after consent. A failed configuration write retains plaintext; a failed cleanup
can be retried against the already-installed process. Migration accepts injected
reference factories; native storage is the CLI's import destination, not an
assumption in the AWS delivery or configuration format.

Bulk protection accounts for hardlinks by inode and link count. Whole-file and
file-preset imports require the discovered canonical path and aliases to cover
every link, with unchanged source snapshots, before import. Each name gets a
sidecar for the same canonical reference. Cleanup rechecks the entire group
after consent, then checks each name against the open inode as its link count
and ctime change with each removal; changed or unremoved paths are reported.
Per-variable rewriting, SSH registration and AWS migration
refuse hardlinked inputs before import, even with `--keep-plaintext`. These
guards operate on source files independently of the storage provider. Cleanup
uses the exact snapshot read for import, retaining a changed source.

`csec creds aws` implements AWS `credential_process` version 1. It accepts either
separate field references or one strict flat JSON bundle, validates required and
optional fields, and writes sorted JSON only to a pipe or socket. `csec creds
git` implements the bounded line-oriented Git helper protocol for `get`, matches
an exact configured protocol/host and optional repository path before resolving,
and emits only safe username/password attributes. It advertises no optional Git
capabilities and deliberately consumes but ignores `store`, `erase`, and unknown
operations, so it never becomes another plaintext credential store.

Both adapters bind the configured references, constraints, and actual direct
consumer executable into the delivery plan. The daemon verifies that executable
against the helper's live parent; the helper repeats PID, start-time, and path
checks immediately before writing. Their stdout is classified as an intentional
credential channel and is not corrupted by the general output masker.

### Inherited file descriptors

`csec exec-fd` resolves one to sixteen complete file payloads, creates one
close-on-exec anonymous pipe per payload, and passes only elevated read
descriptors to the target. The child environment contains non-secret
`/dev/fd/N` paths under caller-selected variables, or under the bounded presets
`PGPASSFILE`, `KUBECONFIG`, `AWS_SHARED_CREDENTIALS_FILE`,
`GOOGLE_APPLICATION_CREDENTIALS`, and `NPM_CONFIG_USERCONFIG`. No pathname
names the bytes in the filesystem.

The npm preset is the one whose payload is not the stored value alone. Bulk
protection splits an npm userconfig instead of removing it, because the same
file carries settings that make every unwrapped `npm`, `pnpm` and `yarn` run
safer (`min-release-age`, `ignore-scripts`); deleting it would trade one token
for the whole machine's install cooldown, and HA-F03 would fail. Only literal
auth lines (`_authToken`, `_auth`, `_password`, nerf-darted or not) are stored,
as one value; one classifier (`NpmUserConfig`) decides that for both discovery
and the split, so a split file is never rediscovered as plaintext. At delivery
the CLI reads the live userconfig and inserts the resolved lines at its top
level, before any INI section npm would not read them from, and the child sees
only the descriptor path: other spellings of `npm_config_userconfig` are
removed. Each stored credential also joins the output-redaction catalog on its
own. A placeholder-plus-environment design was rejected: Yarn 1 fails every
command when a `${VAR}` in `.npmrc` is unset, and the environment is the weak
tier.

The supervisor waits for an exec-status close-on-exec handshake before it closes
its read copies and begins nonblocking writes. It multiplexes secret writes with
PTY/output and signal handling, closes unused ends, fails if the consumer exits
or closes a channel before delivery completes, forwards the real wait status,
and overwrites retained byte buffers best-effort. The generic and per-file limit
is 1 MiB, the aggregate limit is 4 MiB, and NUL-bearing or empty payloads fail.

This tier is intentionally limited to single-open streaming consumers. Pipes are
not seekable, duplicated `/dev/fd/N` opens share an offset, and child descendants
can inherit the descriptor until the consumer closes it or explicitly marks it
close-on-exec. A tool that needs independent reopen, seek, or regular-file
metadata uses the capability-GID tier below.

### Capability-GID regular files

`csec exec-file` serves tools that require regular-file metadata, independent
opens, seek, `mmap`, or descendant reopen. It builds a complete protected-
payload-free launch plan containing the original launcher's audit identity,
exact executable metadata, argv, sanitized environment, reference-to-relative-
path bindings, output guard, TTL, and command digest. The root helper accepts production
connections only on the fixed root-owned socket and authenticates the complete
audit token plus live product code identity before reading a body.

Authorization is a two-party rendezvous. The exact original `csec` prepares the
plan and passes only cwd/stdin/stdout/stderr descriptors with `SCM_RIGHTS`.
`csecd` separately receives a digest-bound approval request, evaluates the
release policy, obtains Touch ID unless a widened grant already covers the
release, resolves the exact reference set, renders bounded payloads, and sends
those bytes directly to the root helper. It returns
only a boolean approval to `csec`; neither values nor rendered files travel back
through the launcher. Only the original launcher's audit token can consume the
nonce and start, supervise, signal, or cancel that plan.

Production uses a 32 MiB, 2,048-node `nodev,nosuid,noexec,nobrowse` tmpfs below
`/private/var/run/convenient-security/files`. The helper allocates a boot-scoped
GID from a persisted monotonic cursor, rejects any GID assigned to an account or
held by a live process, and never recycles one. It creates each launch directory
and file descriptor-relatively with no-follow/exclusive operations, root:GID
ownership, directory mode `0050`, file mode `0040`, and regular/single-link
verification. It then joins the launcher's audit session and drops to the login
UID with the capability as primary GID, the user's ordinary supplementary
groups, core dumps disabled, only intended stdio, and exact-path `execve`.

The GID marks the complete descendant tree even if it daemonizes. Names are
removed when no live process retains the GID, when authorization expires, on
launcher death, or on cancellation. A soft expiry cannot invalidate an already-
open descriptor; `--hard-ttl`, launcher death, explicit cancellation, and
scanner failure also enumerate and kill all GID holders until none remain. The
allocator's persisted cursor and restart cleanup prevent stale plaintext from
making a prior GID useful after daemon restart. See the remaining signed-device
gate in [`docs/regular-file-security-matrix.md`](docs/regular-file-security-matrix.md).

`csec protect --whole-file` and `csec exec` build a whole-file workflow on this mechanism.
Whole-file protection imports plaintext files into the store as per-value AES-GCM blobs
(one Touch ID for the batch, durable before any plaintext is unlinked) and
replaces each with a tiny `*.csec` sidecar naming its `csec://` value. A sidecar
is **source-neutral** — it names any secret reference exactly as every other csec
surface does — and is recognized in either of two on-disk forms: the strict JSON
envelope `csec protect` writes, or a bare reference (a lone secret URL, tolerant of
surrounding whitespace and one layer of quotes) so a hand-written pointer just
works. `csec exec` scans the project subtree for those sidecars and, when any are
present, drives the same root-helper launch with symlink-delivered bindings: the
helper materializes each value into tmpfs exactly as above, and the launcher — at
ordinary user privilege, never the helper — installs a symlink from each file's
original path into that tmpfs and removes it on exit. The tmpfs copy is read-only to
the child, so a tool that saves its file either fails or writes a new file and
renames it over the link; teardown never deletes such a replacement (it may be one
the user wants) but warns that it may hold plaintext. For the same reason bulk
protect skips, by default, catalog token files whose tool saves them during
ordinary commands (an OAuth refresh, per-run state, a project link), and
`csec protect` names them only with `--whole-file`; Fly's config instead takes
its token out of the file (§Fly.io CLI token). A store rooted at home records
home-relative paths, which the project scan reaches only from `~` itself, and
materializing every home token on every launch would hand each command every
tool's token. So each catalog token file names the commands that read it, and
`csec exec -- <command>` from any directory also restores that command's protected
home files through home-rooted bindings (`homeSymlink`), which the launcher links
from the home directory instead of the working one; `--with-file <path>` names
one for a wrapper. They ride the same launch and review, and csecd binds each to
its home-relative path exactly as a project link is bound to its project path. A
project discovery of the same file (a launch from `~` or `~/.cargo`) is replaced
by the home binding. A `*.csec` file that looks
like a sidecar but cannot be parsed is reported and warned about, never silently
skipped — a broken sidecar otherwise looks identical to the secret simply not
being there. A hard-killed launcher skips that teardown, so a later launch reclaims
a leftover link — but only when it is a *dangling* symlink into csec's own mount,
never a real file, a link pointing elsewhere, or a live link a concurrent launch
still uses. A reference is one value whether it holds a short token or a whole
binary file; the storage tier (editable document vs. blob) is invisible at the
reference. A native `csec://` sidecar additionally gets the planted-sidecar
defense: because it lives in a hostile directory, csecd binds its value to the
project-relative path its blob recorded at import, so a planted or moved native
sidecar fails closed. A non-native reference (`op://`, …) has no recorded
protect-path and cannot be path-bound, so — like `op://` everywhere else in csec —
it relies on the Touch ID review that shows the reference before release. The
symlink itself is a confidentiality-only surface that same-uid malware can replace,
an accepted integrity limitation. The same launch also folds in
`csec exec`'s ordinary environment injection: each `--set` assignment or
env-scanned reference becomes a value-in-environment binding whose resolved value
the helper places directly into the child environment. csecd resolves everything
once, so a single approval covers both the materialized files and the injected
values, and the launcher still never holds a plaintext value.

### Environment compatibility

`csec exec` resolves environment values that are provider references and accepts
explicit `--set NAME=<reference>` assignments. It then places plaintext in the
child's initial environment. This works with unmodified tools, but macOS process
inspection can expose that original environment to unrelated same-UID
processes. This is weak compatibility delivery: the trusted review shows a
warning that the child's initial environment is inspectable by other same-user
processes, and one Touch ID authorizes it. There is no risk tier and no separate
acceptance — running the command is the intent. Output-guard configuration is
part of the delivery-plan digest but does not make the environment private.

Both `exec` and `ai` (including its `tool-exec` alias) emit one fixed, value-free
stderr warning before starting a launch with resolved environment values,
independent of output-guard mode or a cached approval. It explains same-user
inspection and recommends the AWS/Git credential adapters, inherited-fd delivery,
or protected regular files when supported. A launch that delivers only files,
an AI program classified secret-free, or a fallback without injection emits no
environment-exposure notice. This notice adds no consent step.

When the project also holds `*.csec` sidecars, this identical injection is folded
into the root-helper launch instead of being applied by the launcher: each
assignment becomes a value-in-environment binding the helper places in the child
environment, so the launcher never holds the plaintext. The environment's
same-UID inspectability is unchanged — it remains weak compatibility delivery
under the same one-Touch-ID review — but one approval now delivers both the injected
values and the materialized files.

When output policy is active, `csec` remains as the process supervisor and uses
a child PTY or pipes. All owned output — terminal and non-terminal — is guarded
by default (`--redact-output=always`). `--redact-output=tty` narrows guarding to
terminal streams, leaving non-terminal output byte-exact with a warning.
`--redact-output=never` is an explicit bypass.

### Raw output

`csec get` writes a requested plaintext value to standard output. Because an
echoed value lands in terminal scrollback — which a coding-agent session, logger,
or screen capture can later retain — the launcher gates the shape by what stdout
is and whether an interactive terminal is present (any of stdin/stdout/stderr a
tty):

- **interactive terminal** — refused by default; `--reveal` echoes it deliberately.
- **pipe to a command** (`csec get x | tool`, and command substitution) with a
  human present — allowed: the pipe expresses intent and the reader consumes the
  bytes rather than displaying them. The reader is a sibling process that cannot
  be authenticated from the write descriptor, so the plan names an **unverified
  pipe reader** as recipient and the review still warns.
- **persistent file** (`csec get x > file`) — refused by default;
  `--allow-plaintext-file` writes it. No pathname is resolved, logged, or sent to
  the daemon; the review warns that plaintext persists on disk and recommends
  `csec exec-file`.
- **non-interactive** (no controlling terminal — an agent, script, or logger is
  capturing the output) — refused by default and steered to `csec exec`/
  `exec-file`/`creds`, which hand the value to the consuming tool without
  returning it; the same shape-matched flag overrides under Touch ID.

The launcher records a value-free `interactive` flag and, only when the
shape-matched override flag is present, a `plaintextExposureAcknowledged` flag,
both digest-bound in the delivery plan. csecd independently re-derives whether an
acknowledgment is required from the mechanism, recipient, and `interactive` flag,
and refuses a raw-output shape that needs one but lacks it — so a launcher cannot
skip the gate by omitting it. In every shape the signed launcher records its real
direct parent's PID, start time, and canonical executable identity separately
from signed `csec`, which remains the byte emitter; the daemon independently
recomputes that parent, roots a digest-bound subtree grant there, and rechecks
the parent incarnation after approval and before provider resolution, and `csec`
rechecks it again immediately before output. Consecutive compatible gets from
that same live shell reuse the grant; a different shell process cannot. Terminal,
pipe, and file shapes have different canonical plan digests, so one cannot
silently authorize another.

### Native store editing

`csec edit <store>` asks `csecd` to begin a caller-bound edit session. After
Touch ID, the complete strict-JSON document crosses the
mutually authenticated socket into the signed launcher. By default a built-in
AppKit `NSTextView` edits it without a plaintext filesystem object. Automatic spelling,
grammar, replacement, data detection, smart punctuation, and window restoration
are disabled. The view is a `ConfidentialTextView`: whatever the human copies,
cuts, drags or sends to a Service out of it also carries the nspasteboard.org
`org.nspasteboard.ConcealedType` and `TransientType` markers, which clipboard
managers such as Raycast, Maccy, Paste and Alfred check before recording a
copy, and is written as one `.currentHostOnly` pasteboard generation, so
Universal Clipboard does not carry it to other devices. Pasting on this Mac is
unchanged, and nothing clears the copy on a timer. Save validates and canonicalizes the document in both the launcher
and daemon before the daemon encrypts it; Cancel tells the daemon to discard the
session. Sessions are bound to the launcher's kernel PID and start time, capped
at eight, and a stale concurrent editor cannot overwrite a newer generation. No
clock retires an open edit — an hour of typing is never thrown away — so a
session ends only when it is saved, cancelled, or when csecd notices the exact
launcher incarnation that opened it is gone and reclaims its slot.

`csec edit --editor <store>` is an explicit compatibility boundary for a user's
`$EDITOR`. The launcher resolves the actual executable without a shell and binds
its canonical path into an unverified-consumer delivery plan before review.
Before Touch ID it warns that the mode creates a named plaintext file. The
command is parsed into a bounded argv and executed directly, without an
implicit shell or expansion; the randomized document path is appended as the
last argument. The editor must remain in the foreground (for example,
`code --wait`) until editing is complete. Invalid JSON is reported without its
contents and reopens the same editor; a nonzero or signalled exit cancels the
edit session.

The external mode uses a randomized directory below csec's canonical per-user
temporary directory. The directory is `0700`; the initial document is created
with `openat`, `O_EXCL`, `O_NOFOLLOW`, and mode `0600`. After the editor exits,
csec reopens by directory descriptor, accepts only a bounded, current-user,
single-link regular file, and restores mode `0600`. It then unlinks the document
and removes editor artifacts within that exact workspace on normal success or
failure. A crash, `SIGKILL`, or forced termination can leave the workspace
behind. These controls reduce accidents and cross-account access; they do not
restore a same-UID boundary. The editor, plugins, same-UID malware, swap,
autosave, backup, recovery, and filesystem snapshots can retain plaintext, and
unlinking is not secure erasure on APFS/SSD storage. Copies outside the
workspace cannot be removed. The trusted review warns that this mode creates a
named plaintext file, and one Touch ID authorizes it; commit accepts only the
launcher incarnation that opened the session, and only while the store is
unchanged since the edit started.

The built-in editor still authorizes the user and AppKit/input stack to see the
plaintext; copying, screenshots, accessibility/screen-capture privileges, or a
compromised authorized process remain outside the boundary.

`csec edit --remove <reference>…` deletes whole-file values, which have no
editor of their own: what a failed import or a retired SSH key left behind
(`csec ssh remove` drops only the catalog entry). csecd's
`NativeStoreRemovalService` takes up to six canonical `csec://` references in
one store, so its settings panel names each, and the deletion is one index
write: all of them go, or none. Before the touch it refuses a value csecd's own
registrations use (the SSH catalog, the GitHub socket's token, an enrolled
automation job), a key the store's blob tier does not hold, and a value whose
sidecar is still at its recorded path under the home directory or the store's
origin, whenever this csecd already holds the store's index; after the touch,
with the store open, it checks all of it again just before the write. The
blob store then rewrites its index, the remote-unlock mirror and the store's
backup bundle without the values, and csecd revokes their grants, unpairs them
from every Claude Code project and drops any cached copy, since a file
protected later under the same reference may be a different one. The decision
log records the references. A sidecar copied elsewhere, or an env-file
reference to the value, is outside what csecd can see and stops resolving.

## Output redaction and AI hooks

`csec ai` refuses literal `op` commands before requesting secrets, including
absolute paths found by the shell parser. For indirect callers it prepends a
directory holding a value-free `op` refusal script to PATH **after** the login
shell has read its startup files. The app bundle ships that directory as
`Contents/Resources/ai-guard`, so a child whose sandbox allows no writes at all
(Codex's read-only mode, common for review agents) is still guarded and still
runs. csec uses it only while it holds exactly the expected script alone,
with neither writable by group or others; otherwise, and for builds outside the
bundle, it creates the same script in a private 0700 temporary directory, and
refuses the command if it cannot. The fixed launch prelude also removes startup
aliases/functions named `op`; it preserves the original program text and its
policy/registration digest. Protected and degraded launches use the same guard,
and remove a temporary shim before forwarding the child's exit status or
signal. A hard-killed launcher may leave only the value-free shim behind. This is an accidental-use
guard, not an OS execution boundary: deliberate PATH changes and absolute calls
inside arbitrary programs can bypass it. csecd's own provider is outside this
child environment, so canonical references still resolve through the normal
authorized provider abstraction. No authorization or cache lifetime changes.


For one supervised `csec exec` launch, the launcher builds redaction rules from
the values it resolved. It replaces exact values and supported canonical
base64, base64url, percent-encoded, and JSON-escaped representations before
forwarding owned stdout, stderr, or PTY bytes. Matches spanning read boundaries
are handled: a tail that could still begin a value is withheld until the next
byte decides it, and nothing else is held back. On the PTY stream, which a
terminal draws, the scanner reads escape-sequence syntax and never starts a
match on a sequence's own structure bytes (ESC, a CSI's parameters and final
byte, a string's introducer or BEL/ST terminator): the terminal consumes those
and never shows them, and withholding a query's final byte would leave the
program waiting for a reply the terminal never sends (fish's startup DA1 query,
csec-bpc). Text inside OSC/DCS strings is still scanned. Pipes keep strict
byte matching. A plain-text tail that could begin a value, written just before
a program waits for input, is still held until more output arrives; releasing
it on a timer would let a value written in two delayed parts leak its first
part. Values shorter than eight bytes are excluded unless explicitly
enabled. By default a match is replaced in-band with `[redacted: <reference>]`,
naming the reference the value resolved from — value-free metadata the user
already holds in the sidecar or environment, so no reference the redaction names
is new to a reader with access to that output. `--redact-output-label=opaque`
restores an ordinal `[csec:secret-N]` that keeps the reference out of the output
stream entirely. Per-match stderr warnings are opt-in (`--redact-output-warn`);
when enabled they also name the reference. The `csec tool-exec` AI broker is the
exception: its output recipient is the AI tool rather than the operator's own
terminal, so it keeps opaque labels and does not hand the AI reference metadata.

`csecd` also keeps a memory-only registry of the values released during its
current lifetime, each tagged with the reference it resolved from so an
agent-side redaction (where the plaintext never returns to the launcher) can
name the reference too. `csec tool-exec --destination ai` opens a caller-bound
streaming session before launching a command and sends each output chunk to the
daemon. The session stays bound to the launcher's exact PID and start time until
explicit close or owner exit; silent background commands do not expire. The
daemon reclaims sessions whose owning process has exited or whose PID was reused
before handling scanner requests, and permits at most 256 sessions. Existing
patterns and withheld prefixes remain available for the entire command, even
after their delivery-registry entries expire. Retaining the matcher does not
renew an access grant or resolve values again. Scanner loss stops forwarding
unscanned output: the child is terminated, except that a command csecd released
nothing to may finish with the rest of its output withheld, and an automation
run holds its output until the restarted csecd resumes its lease (§Explicit
persistent automation exception). When `csec ai` selects permanent withholding,
it immediately prints one fixed wrapper-generated status line on stderr,
explaining that output is withheld unscanned while it waits for the command's
own exit status. Its final notice still reports the withheld byte count. This
status neither forwards child output nor reconnects the scanner; it appears
when scanner loss is detected, on the next output or stream close. Generated
Claude Code and Codex PreToolUse adapters rewrite
Bash commands through this broker when the user installs their configuration
fragment. Claude Code's hook also matches its Monitor tool (`Bash|Monitor`):
Monitor runs its command through the same Bash tool shell (`zsh -c … eval
'<cmd>'` under the Claude Code process, verified with `ps` on 2.1.280), behind
Bash's permission check and with the command as the classifier's input, so a
Monitor command is rewritten, registered and delegated exactly as a Bash one,
and its output, each line of which is an event, is scanned the same way.
`csec ai` forwards each line as it arrives, so events are not held back. A
WebSocket monitor (`ws`, no `command`) runs no shell; the hook prints nothing
for it.

A rewrite must never carry more authority than the client's own permission
system would give the original command. Claude Code receives `updatedInput`
with no permission decision, so the rewritten `csec ai -- <command>` still goes
through its rules, auto-mode classifier and prompts; a PreToolUse `allow` would
skip the classifier, let every Bash call past content-matching deny rules
(which never match the wrapper) and suppress manual-mode prompts. `csec setup`
adds an `autoMode.environment` entry telling the classifier to judge the inner
command; with delegated approvals on, a variant that also says approving the
command releases the project's secrets to it. Before it prints the rewrite, the
Claude hook registers the command with csecd (§Delegated approval). A Claude
command the agent already wrote in the hook's own form (`csec ai -- <bare-safe
words>`, or `csec ai -- '<program>'` quoted exactly as the hook quotes) gets no
rewrite: the hook registers the program `csec ai` will receive, applies the
worktree check to it and prints nothing. Rewriting it would nest a second
`csec ai`, and any rewrite voids auto mode's server verdict for the call. Since
Claude Code 2.1.314 retired the local classifier, such a call is then blocked
with no verdict and must be resubmitted (av-e2sa). Codex
accepts `updatedInput` only inside an `allow` that grants
nothing — its sandbox, approval policy and reviewer run on the rewritten
command — but its dangerous-command heuristic and execpolicy `prompt`/
`forbidden` prefix rules evaluate argv and cannot see inside the wrapper, and a
wrapped `apply_patch` heredoc bypasses Codex's patch approval. The Codex adapter
therefore evaluates those gates on the original command with Codex's own logic
(`CodexCommandGate`: line-for-line ports of Codex's `bash.rs` plain-command split
and `is_dangerous_command.rs` heuristic over the same tree-sitter 0.25.10 and
tree-sitter-bash 0.25.1 Codex links, vendored unmodified in
`agent/Sources/CTreeSitterBash`; rules match by exact program or
host-executable basename, and any gating rule on a shell or any `apply_patch`
invocation leaves the command to Codex) and leaves a command they could catch
unwrapped, trading output scanning for that command for Codex's own gate. It
reads rules from `/etc/codex/rules`, `$CODEX_HOME/rules` and trusted projects'
`.codex/rules` only (an untrusted clone must not choose commands to leave
unscanned); a file outside the literal `prefix_rule` subset, or requirements
rules, make every Codex command unwrapped until removed. Allow rules are
ignored, which can only widen what is left to Codex. The Codex hook is installed in Codex's managed System
layer (`/etc/codex/hooks.json`) by `build-and-install.sh`: managed hooks carry
no per-hook trust hash and ignore per-hook disabling, whereas a user-level hook
stops running whenever its bytes change until the user re-trusts it. Codex's
`features.hooks = false` still turns every hook off, and the managed hook
applies to every account on the Mac. Every hook
failure exits 2 with a stderr reason (Codex treats a silent status 2 as a failed
hook and runs the original command), and both clients get 30 s before a timed-out
hook lets the original command run unwrapped.

**csec as Claude Code's shell prefix** (csec-0.83.1, av-e2sa). Any rewrite
voids auto mode's verdict, so on Claude Code 2.1.314 and later every rewritten
call is blocked with no verdict, and three in a row stop the session at a menu.
`csec setup shell-prefix` instead sets `env.CLAUDE_CODE_SHELL_PREFIX` in Claude
Code's user settings to the bundle's
`Contents/Resources/claude-code-shell/csec-claude-code-shell`, a two-line `sh`
script that execs the bundle's `csec ai --claude-code-shell "$@"`. Claude Code
(2.1.319, read in its source) runs each Bash and Monitor call as
`<shell> -c "'<prefix>' '<framing>'"`, where the framing is the script
§Delegated approval describes. It also hands the prefix the command line of
every shell-form hook, and of every stdio MCP server, which it runs as the
prefix string itself. So the value must be one absolute path with no flags.
Exec-form hooks, csec's own among them, are not prefixed. When the hook's
environment names exactly this csec's prefix, the Claude hook prints nothing:
it registers the command, wrapped, and auto mode's verdict stands. Any other
prefix, or none, keeps the rewrite, and Codex is unchanged.

`csec ai --claude-code-shell <text>` takes exactly that one argument and
handles three cases:

- **Hooks and MCP servers.** A text that names neither `eval` nor
  `pwd -P >|` is a hook or MCP command line. It is exec'd as
  `/bin/sh -c <text>`, exactly as Claude Code ran it before, and is neither
  resolved nor scanned.
- **Bash and Monitor calls.** A framing (exactly one literal `eval`, read as
  `ClaudeToolShell` reads it, ending ` && pwd -P >| <path>`) runs as a `csec ai`
  program. The command inside the `eval` is what is judged: the direct `op`
  refusal, the secret-free classification, and the digest delegation binds,
  which is what the hook registered. The credential guard's setup goes just
  before the `eval`, after the snapshot the framing sources.
- **Anything else.** A text that names a marker but is no framing runs whole
  as a `csec ai` program, never unwrapped.

zsh execs the single command its `-c` names, so the `csec ai` stands directly
under P, where the tool shell stood. csecd's release, SSH and sudo walks read
it as an anchor of its own (`csecShellPrefix`). G5 and the settings gate accept
`CLAUDE_CODE_SHELL_PREFIX` only when it is set once and byte-equal to the
installed csec's own prefix path. `csec uninstall` removes the setting first,
since a prefix naming a deleted script stops every Bash command. A command that
starts while an install swaps the bundle (tens of milliseconds) can fail to
exec, and is rerun.

A `csec ai` program that needs no secret asks for none. Every command an agent
runs inherits the project's reference variables, so a read-only `ls`, `rg` or
`git status` used to request the whole set, and the first one of a session
raised a panel. When the environment names references and a conservative
classifier (`AICommandSecretFree`) finds the program secret-free, `csec ai`
sends no access request and removes both the injected names and their `csec_`
aliases from the child's environment. The classifier parses with the vendored
tree-sitter-bash and accepts only what `/bin/zsh -lc` provably reads the same
way; it does not model zsh. Every command anywhere in the program must have a
literal name from a fixed list of tools that need no secret (bare, or under a
system tool directory such as `/usr/bin`). The list is about secrets, not side
effects: it includes `cp`, `mv`, `rm` and `chmod`. `git` is allowed only with a
read-only subcommand and no `-c`, `--config-env` or `--exec-path`. `bd` (the
beads issue tracker coding agents file their work in) is allowed with a
subcommand from a fixed list that reads or writes the issue database and starts
no program its command line names (`show`, `update`, `create`, `close`, `list`,
`dep`, `sql`, …; never `edit`, `hooks`, `gate`, `dolt`, `sync` or an
integration), after only the global options bd itself defines, read the way
its argument parser (cobra) reads them. The words up to the subcommand must be
literal; the operands after it may carry a quoted `$(date …)` or variable, as a
dated note does. bd keeps the ordinary path whenever a reference variable is
named `BD_*`, `BEADS_*` or `DOLT_*`, the names bd reads its own credentials
from. A Mac's administrator can allow more commands the same way in
`/etc/csec/secret-free-commands.json` (`AICommandSecretFree.LocalCommands`):
local tools of the form `<name> <subcommand> …` that take no global option,
each with the subcommands that need no secret and start no program their
command line names, the subcommands allowed only with a listed second word
(`plugins list` but not `plugins install`), and the variable-name prefixes the
tool reads its own credentials from. Without such a rule, a session tool every
agent command runs (to read its work items, park, report) would wait on the
project's panel whenever its secrets were locked. A listed command's first word
(and a second-word one's second) must be literal, and it keeps the ordinary
path while a reference variable has one of its prefixes. The file is read like
csec's other system configuration (`/etc/codex/hooks.json`): a root-owned,
single-link regular file, not followed through a link, in a root-owned
directory, neither writable by group or others, so the user's agents cannot add
an entry and an administrator's `sudo` goes through csec's sudo review. It may
not name a listed, banned or built-in command (`git`, `bd`), and a name,
subcommand or second word must be one plain word that is not an option. A file
that fails any check adds nothing, with a one-line warning, and no file means
only the built-in rules apply. For the
tools whose options are checked (`find`, `fd`, `rg`, `sort`, `jq`, `git` and
`printf`), no option on the command line may start another program
(`find -exec`, `fd -x`, `rg --pre`, `sort --compress-program`, `git grep -O`,
`git diff --ext-diff`, …); the other listed tools are taken as they are. None of
`eval`, `source`, `exec`, `env`, `xargs`, `sudo` and the like may appear, nor an
assignment, an expansion of a reference variable, or any expansion outside
double quotes other than `$?`, the exit status, which is always digits. Anything else keeps the ordinary path: request every reference,
inject, redact. Output scanning is unchanged, because the child still runs
under csecd's redaction session, which covers every value csecd has released
and still holds; the sudo PAM redactor's `tool-exec … -- /bin/cat` depends on
that. A secret-free command, though, activates no value for redaction of its
own (see `docs/threat-model.md`).

Plain git runs unwrapped in Claude Code. Claude Code (measured with
2.1.280) refuses, in a subagent or session isolated in a git worktree, every
Bash command whose git operations it cannot show stay in that worktree, and it
judges the command it is about to run, which is the hook's rewrite:
`csec ai -- '…'` is an unknown launcher with git text among its operands, so
every git command such an agent ran was refused, `git status` included, and its
commits had to be made by another session. So for a command
`AICommandGitPassthrough` accepts, the Claude adapter prints nothing (a no-op:
Claude Code runs the command as typed). It accepts one or more statements
joined by `&&`, `||`, `;` or newlines, each either `git` with a subcommand from
a fixed list of local ones or of those that reach a remote (`push`, `fetch`,
`pull`, `clone`, `submodule`; no alias; global options only from
the list `AICommandSecretFree` knows, never `-c`, `--config-env` or
`--exec-path`; never an option that runs a program the command line names:
`rebase --exec`, `grep -O`, `push --receive-pack`/`--exec`, `fetch`/`pull`
`--upload-pack`, `clone -u`/`--template`/`-c`, or `submodule foreach`, each of
which ran a planted command with Apple git 2.50.1)
or `cd` with one literal operand; every
word literal in both shells, read as the secret-free classifier reads it; output
redirections with one literal target; and one exception for the commit message
Claude Code is told to pass, an argument that is exactly `"$(cat <<'EOF' …
EOF)"` with a single-quoted delimiter. No assignment, pipe, subshell, group,
input redirection or other program passes, and `LauncherScript`'s stricter
analysis must read the same commands. cs-selftest runs every accepted command
under the real `/bin/zsh -c`, with and without a `.zshenv` that changes how
words expand, and checks it ran only git, the heredoc's `cat` and `cd`, and that
every git a command reaching a remote ran matches one of its text's simple
commands (`LauncherScript`). Codex has no such guard, and its git keeps the wrapper.

A list of only local git registers nothing: no `csec ai` will ask csecd for
anything, and Claude Code's auto mode approves read-only local git (`git
status`, `git log`, `git remote -v`) without its classifier, so nothing such a
command starts may be delegated. For the same reason `ls-remote` keeps its
wrapper: Claude Code approves a bare `git ls-remote`, which does reach the
remote, without its classifier. A list holding git that reaches a remote
registers the command as typed (no space normalising: it is the text the tool
shell's `eval` runs), marked `unwrapped`, before the hook returns, in every
permission mode, exactly like a wrapped registration. Claude Code sends each of
those subcommands to its classifier. The `ssh` it starts has no `csec ai` above
it, so csecd anchors the chain on the Bash tool shell instead (§Delegated
approval, SSH), and auto mode can stand in for the SSH panel as it does for a
wrapped `git push`.

Such a command gives up both halves of the wrapper. It gets no secret, which git
does not need: the references stay references in its environment, and `ssh`
reaches csec's agent through the `SSH_AUTH_SOCK` Claude Code itself was started
with. An HTTPS credential helper gets no injected environment either, so one
that needed a csec reference (a `GH_TOKEN` only `csec ai` resolves) fails
visibly; `gh auth git-credential` falls back to gh's own login. And its output
is not scanned: a value csecd has released that also sits in a tracked file, a
commit message or git's configuration reaches the model unmasked, as does the
output of anything git's configuration starts (hooks, `pre-push` included, `!`
aliases, pagers, diff and textconv drivers, `gpg.program`). That trade-off is
accepted for git and nothing else. `remote` (whose `show` and `update` reach a
remote), `lfs`, `archive` and the rest keep their wrapper; for a worktree-isolated
agent that wrapper passes the guard only after csec's own escape check (below). A local command that
reaches a remote anyway (a partial clone's lazy fetch) registered nothing, so
csecd binds nothing to its tool shell and the SSH panel asks, saying the hook
did not register the command. And a `cd` in such a command now moves Claude
Code's own shell, as it would without csec.

Everything else that names git keeps its wrapper, and in a worktree-isolated
session the guard cannot see inside it: its rule for an unknown launcher
refuses only an operand whose first word is git or a shell (or one with a
quote, backquote, `$` or backslash with a word that names git or a shell), so wrapped, `cd <main checkout> && git commit && git
push`, `true && git push` and `env git push` ran (csec-jmjy measured the first
committing and pushing in the shared checkout). So the Claude adapter does the
guard's job for what it wraps (`AICommandWorktreeEscape`). The session is
isolated when the hook's `cwd` is inside `<repo>/.claude/worktrees/<name>`
(where Claude Code puts `claude -w`, `EnterWorktree` and isolated subagents'
worktrees, and how it recognises them), or when `transcript_path` sits in the
project directory Claude Code names after such a worktree
(`…--claude-worktrees-…`). A session's Bash cwd can leave its worktree: the
guard lets a plain `git … && cd <dir>` through, since no git follows its `cd`,
and Claude Code keeps that directory; the transcript stays put. Such a session
is refused every wrapped command that names git until a plain `cd <worktree> &&
git status` (unwrapped, judged by the guard) takes it back: a `cd` csec wraps
runs in `csec ai`'s shell and moves nothing. A missing `cwd` is refused the
same way. In its own worktree, a wrapped command that names git as the guard
reads names (`git`, `git.exe`, `git-<word>`, also after removing quotes and `$`
expansions) is denied unless it can run git only directly in the worktree. The
adapter prints `permissionDecision: "deny"` with a reason the agent sees, which
grants nothing. To pass, the command parses cleanly in both analyses; nothing
in it changes the shell's directory, environment, options or command lookup
beyond a `cd` to an existing directory whose real path is inside the worktree
(by absolute path, or as the first `cd` by a relative one) and an assignment or
`export` of an upper-case name that is not `GIT_*`, `PATH`, `HOME` or another
the shell or git reads, whose value does not name git (no function, `case`,
arithmetic, `${x:=…}` or zsh `${(…)}`, `select`, `>(…)`, directory as a command
name for zsh's AUTO_CD, or builtin beyond a harmless set: `pushd`, `source`,
`eval`, `exec`, `command`, `noglob`, `setopt` and the rest are refused); no text
naming git sits where zsh could evaluate it as a subscript (`printf %d
'x[$(…)]'`, `[ -t … ]`, `$x[…]`), since arithmetic runs a `$(…)` even in quoted
text; git is spelled `git`, with no `-C`, `--git-dir`, `--work-tree`, `--bare`
or `-c` and no program option whose program names git; and every other mention
of git is text that reaches only programs that never run what they read (echo,
printf, cat, grep, rg, head, tail, wc, ls, jq, tee, bd, and `gh` with a core
subcommand), through their arguments, heredocs, pipes or substitutions, or a
file that nothing untrusted in the same command could run (a git program
option counts). So `true && git status`, `cd <worktree>/agent && swift build &&
git status`, `CI=1 npm test && git commit -m "…git…"` and `echo "$(git
rev-parse HEAD)"` pass, and `env git`, `xargs git`, `sh -c '… git …'`, `python3
<<EOF … git … EOF` and `echo 'git push' | sh` are refused. Like the guard, it is
for accidents: a program that runs git itself (a build script, a git alias) is
out of its reach. A command naming git that the check passes is wrapped with its
program after one space, `csec ai -- ' git log | head'`, a no-op for zsh that the registration
digests with it (`AICommandHook.programToken`): the guard's unknown-launcher rule
reads the operand's first whitespace-split word, so without the space it refused
`git log | head` and `git fetch && swift build` while passing `true && git log |
head` (and refused a bare `grep -rn git docs` for its git word among the
operands). With it the guard judges `' git log | head'` exactly as it judges
`'true && git log | head'`, so nothing runs that could not already, and the
guard's own rule for text with a quote, `$` or backslash that names git still
refuses `git log --format="%h" | head`, whatever the first word: run that git
as a plain git command, or without the quotes. A command naming no git, which the
check does not judge, keeps the ordinary form, so the guard's other rules (a
shell as the first word among them) still apply to it (csec-m8sl). cs-selftest runs every command the check accepts under the real
zsh with a sentinel git and checks that git ran only in the worktree, with no
git variable set. Codex, and Claude Code sessions that are not isolated, are
unchanged.

These controls reduce accidental stdout/stderr disclosure. They do not stop
local reads, network or file writes, alternate descriptors, partial or arbitrary
transformations, non-Bash tool paths, or a malicious authorized consumer.
User-level hook configuration is also user-modifiable. A registry entry released
under a bounded grant expires with it; one released for a process lifetime (the
default, and every delegated release) stays until csecd restarts, when the whole
registry is lost.

## Setup and onboarding

`csec setup` is a dry-run-first orchestration command. It detects Claude Code
and Codex from bounded executable search paths and their user configuration
files, then computes an additive merge of the generated `Bash|Monitor` `PreToolUse` hook
(and csec's `autoMode.environment` entry) into Claude Code's user settings. For
Codex it only configures sandbox access to csecd and removes a user-level csec
handler once the managed `/etc/codex` hook is installed.
The hook enters through `/bin/sh` and converts a missing launcher or every
nonzero adapter result to exit status 2, while the adapter rewrites the proposed
command through the fail-closed AI output broker. A launcher that is not
executable, or that the shell could not exec (126/127, so it read none of the
hook input), is retried every 0.1 s for 5 s first: PackageKit replaces the app
bundle by moving it out and the new one in, and the launcher path is missing
for about 25 ms in between. Configuration reads require a
user-owned, non-symlink regular file below a user-owned, non-group/other-writable
client directory. JSON is limited to 1 MiB, rejects duplicate decoded object
keys and excessive nesting, and is re-read by bytes, mode, device, and inode
immediately before atomic replacement. Setup preserves unrelated JSON and file
mode, prints only the exact value-free managed fragment rather than the complete
user configuration, is idempotent for the exact generated handler, and requires
explicit flags to replace a recognized older csec handler. It does not replace
other hooks or override an explicit Claude `disableAllHooks` policy. With the
Claude hook in place, setup's step 3c offers delegated approvals, and turns
them off again (§Delegated approval).

Local discovery is intentionally narrow and value-free at its output boundary.
It examines secret-shaped names in the inherited process environment and up to
32 non-symlink live dotenv files within a depth-four project walk, excluding
common dependency/build directories. Files and parsed entries have explicit
byte/count bounds. Supported `op://` and `csec://` references are reported as
metadata but never resolved. Dotenv interpolation, duplicates, and ambiguous
syntax are marked unsupported. Only a locator selected exactly with `--import`
may be loaded, and apply reclassifies its current value so a source changed into
a logical reference cannot be copied as plaintext. A selected dotenv file is
also bound to the filesystem device, inode, size, mode, modification time, and
status-change time observed during that apply process's discovery pass.

Selected plaintext can be merged into the native encrypted store through a
dedicated authenticated, exact-launcher, direct-heap edit mode. A fresh policy
review and Touch ID gate the edit. The strict store document protects every
existing key unless `--replace-secret` is explicit; the original environment or
dotenv source is deliberately left untouched for separate verify-then-remediate
work. Values never enter setup output or argv. The current importer does not
write to 1Password or resolve references.

The protect flows (`csec protect --env`, `csec setup --protect-files`) write
through a `SecretWriteDestination`, native or 1Password alike. That destination
never replaces a stored value. These flows rewrite their source to the returned
references and drop the plaintext, so replacing `NAME` would silently repoint
every file protected earlier against it. A name that is free, or already holds
the identical value, is reused. A different value goes to the first free
`NAME_2`, `NAME_3`, …, and callers use the references the destination returns.
The comparison happens inside the `csec` process, against the document or item
the write already opened. Only `csec edit <reference>` overwrites, because
replacing that one value is what the user asked for.

Bulk protection preserves shell startup files. It rewrites supported literal
assignments in place and reports unsupported assignments for manual migration.
Unsupported-only or unparseable startup files are listed but skipped by
default, including discovered aliases of the same file. Whole-file replacement
requires an explicit choice because ordinary shell startup cannot load its
sidecar. Dotenv and envrc files retain their automatic whole-file fallback.

The same snapshot generates a maximum-16-KiB audit prompt containing bounded,
sanitized identifiers and state only. It tells the coding agent to remain
read-only and value-free while checking signed-device posture, effective hook
sources/trust, missed secret locations, consumer delivery shape, and source
retention. This is necessary because setup cannot approve client trust, override
managed settings, establish competing-hook semantics, or exhaustively discover
local/provider/CI state. Each target update is atomic and repeatable, but a run
covering multiple agent files plus a store is not a cross-target transaction;
partial completion is reported explicitly.

## Host posture audit

`csec audit` runs a curated, severity-ordered host posture audit of the Mac
underneath csec — the secrets audit answers "where are my plaintext credentials,"
and this answers "is the host configured so that same-user malware can't trivially
win anyway." It evaluates roughly 65 stable-id checks (`HA-<domain><nn>`) across
platform and kernel integrity, Gatekeeper and malware defenses, network exposure,
privacy/TCC grants, persistence, developer attack surface, accounts, and csec's
own coverage. On-thesis (★) controls — the ones that shrink the blast radius of
csec's same-UID adversary — lead the report. The full catalog is in
[`docs/host-audit-catalog.md`](docs/host-audit-catalog.md) and the implementation
in [`docs/host-audit-implementation-plan.md`](docs/host-audit-implementation-plan.md).

The audit engine lives in `csecd`, not the launcher. `csec audit` is a thin
client: it asks the resident agent to run the value-free audit over the mutually
authenticated socket and renders the returned `HostAuditReport`. `csecd` holds
**Full Disk Access** (requested at setup per the "more secure, conveniently"
ethos) to enumerate the SIP-protected TCC databases for the privacy section, and
drives the signed root helper for the privileged reads and reversible mutations.
The launcher's flags are `--report-only` (read-only, no proposal — for CI or an
AI-agent consumer), `--json` (the report as stable JSON, ids being the contract;
implies read-only), and `--scan-filesystem` (opt into the bounded HA-F10
SUID/world-writable sweep, off by default because it is expensive and logs its
bound so partial coverage never reads as a pass).

The animated scan polls a background job in `csecd`, and that poll loop carries
one overall ceiling so a job that silently dies ends as an error naming
`csec doctor` instead of spinning a spinner forever. The ceiling is derived from
the engine rather than picked — every check is bounded by the command runner's
hard per-command timeout and at most twelve run at once, so the worst legitimate
wall-clock is that many waves of one timeout, and the ceiling is three times
that. Nothing in an audit waits on a person (remediation is a separate verb with
its own Touch ID), so this bound can never cut a decision short.

Privileged host operations are a **closed allow-list**, not a generic "run this as
root." Two new `csec-rootd` request cases, `hostRead` and `hostApply`, each carry
a closed enum (`HostRootRead` / `HostRootChange`) that maps inside the root server
to exactly one fixed, audited command or syscall. Both require the verified
**agent** role — only `csecd` may call them — and `hostApply` is **digest-bound**
to its own value-free change representation, which the helper independently
recomputes and requires to match before applying, exactly as the existing
`exec-file` approve path binds to a plan digest. The helper links no provider,
Keychain, or Touch ID dependency, so this preserves its minimal surface and adds
no dangerous entitlements. The helper runs these tools on the requesting
connection's own thread, one request at a time and outside its launch
coordinator, so an audit never delays a protected-file launch or the soft-TTL,
hard-TTL and launcher-death sweeps.

Reporting and remediation are one **terminal-native** flow. The report renders as
a formatted TUI (not raw markdown); the safe, reversible `.auto`/`.autoPrivileged`
fixes are then presented as an **in-terminal checkbox picker** (default-on,
deselectable), and the still-selected set is applied atomically per target, each
change digest-bound, under a **single Touch ID** in csecd's settings panel. There is
no implicit cross-target transaction. Selection moved out of the old AppKit
checklist window into the terminal deliberately: every remediation is a reversible,
security-positive change, so a tampered selection can only apply *more* hardening,
never leak a credential — the opposite direction of harm from the access-review
case, where the WYSIWYG-in-trusted-window property is load-bearing. Touch ID still
gates the privileged apply in csecd (physical presence a compromised launcher
cannot forge), and csecd re-derives the plan from live state before applying.

Two more-secure states that need a real choice or state transition get **guided
interactive helpers** instead: FileVault (HA-G03), which keeps the recovery key
local and never silently escrows it to iCloud, and Santa (HA-B08), which links to
the official signed package and describes a MONITOR-mode starting posture and never
sets LOCKDOWN. TCC-grant revocation, config-profile and root-CA removal, and
similar judgment calls are advise-only.

Whatever is still failing afterwards — non-auto-fixable, declined, or a fix that
didn't take — flows through **triage**: per finding, accept it as a documented
**exemption** (a value-free note, suppressed from re-nagging) or keep it as a
**TODO** (a weekly notification reminder while it stays unfixed, riding the daily
re-audit timer). Exemptions and TODOs persist in the accepted baseline and clear
automatically when the control later passes. The flow ends by printing a
copy-paste **attestation** — machine identity (model · macOS · hostname, no serial),
verified controls, accepted risks, planned remediation — suitable for showing the
laptop is properly configured; it honestly surfaces anything still needing
attention. `csec setup` runs the audit report-only on completion so onboarding
always ends with a host posture pass.

Because `csecd` is resident, it also re-audits on a daily dispatch timer against
an accepted baseline. It diffs each run and posts a `UNUserNotification` **only
on a `pass → fail` regression** of a previously-accepted control — a high-signal
event that can mean malware disabling defenses. It is notify-only: nothing is
mutated in the background, and the user re-runs `csec audit` to review and
re-apply. The baseline advances only through that interactive path, so
unreviewed drift keeps surfacing.

The baseline is sealed, because a same-UID process that could edit it could add
an exemption before disabling a control and silence that notification.
`SealedBaselineStore` keeps it AES-GCM-sealed, under a key the decision log
derives for it, in `~/Library/Application Support/ConvenientSecurity/HostAuditBaseline/`,
and the `baseline`/`pointer-v1` protected item holds the current file's
generation, ID and SHA-256. The actor serializes every operation (an audit, a
triage and the reminder stamp update atomically), and a write goes new file →
pointer → rename → delete old, so a crash at any point leaves a readable
baseline. The plaintext `host-audit-baseline.json` an older csecd kept is
imported only when the pointer is absent and no sealed file exists, then deleted
and recorded; one that appears later is deleted and recorded, never imported. A
missing, replaced, modified or rolled-back file, or a missing pointer beside a
sealed file, is recorded as `baseline_integrity`, notified once, and the baseline
is treated as absent, then resealed empty so the next scan is clean. That reset
has a cost: an empty baseline accepts no control as passing, so no
`pass → fail` regression is reported until the user runs `csec audit` and
re-accepts one. The notification says so: csecd discarded the baseline and
starts again from an empty one, so regressions are not reported again until
`csec audit` re-accepts. (While the finding is still unrecorded, the altered
files are kept as evidence and the baseline is treated as empty.) With a
pointer in place, a directory or file csecd cannot list or read (an ACL, a
mode, a locked parent) is the same kind of finding, `file_unreadable`, never a
quiet "unavailable". csecd first strips an ACL and restores the mode on its
own directory and file — a file only when, opened through the verified
directory without following a symbolic link, it is a regular file of this user
with exactly one link, so a hard link planted under csecd's name to another
file is left as it is — and a baseline that then verifies is kept, the denial
still reported. An unrecorded finding's files are evidence: no save seals over
them until the log takes the record. Every audit or triage save that does not
take is notified; the daily scan's note that it posted a deferred-fix reminder
is notified, when it does not take, once per csecd run until one succeeds.
When csecd's own pointer write fails (the protected store deletes an item it
could not write), the previous pointer is put straight back, so only a
second Keychain failure leaves `pointer_missing`. `csec uninstall` deletes the
directory and the pointer.

The whole audit is value-free like the rest of csec: every finding, evidence
string, log line, and notification is metadata only — counts, kinds, enum state,
stable check ids — never a credential value, CA name, path, or command output.
An `X`/`F`-unavailable check reports `unknown`, never a pass.

## Resolution and cache

`SecretResolver` dispatches each reference independently by scheme. The shipping
daemon always registers `op://`, so a missing CLI fails closed instead of letting
a reference pass through as ordinary process data, and registers `csec://` when
its provisioned Keychain group is usable. A single request, language-client call,
or `csec exec` launch can contain both schemes.

The 1Password provider holds one authorized SDK session per account, in a
separate `csec-op-bridge` process, and never reaches for one on its own.

The `op` CLI cannot serve this. It has no session that survives a process: every
invocation re-authorizes against the desktop app, and — by 1Password's own
design — *an authorization requested while the app is locked unlocks the app*.
Since the app locks with the device, a resident agent polling the CLI walks into
a locked app every time the Mac is locked and asks it to unlock, which puts a
Touch ID prompt on screen with nothing behind it. Measured on a two-account Mac,
an eight-minute CLI heartbeat produced 21 system-unlock attempts in one working
day, seven of them prompts nobody answered.

A bridge process instead creates one SDK client through 1Password's desktop
integration and keeps it. The first request authorizes; later reads travel the
live session in well under a second with no unlock round-trip at all. Each
bridge serves exactly one account — the desktop integration binds an
authorization to an account, and the SDK's library core is a per-process
singleton keyed by the first account it sees — so accounts stay isolated in
separate processes. Values cross only the bridge's stdout pipe: never argv,
never the environment, never a log.

Two rules keep prompts tied to intent. **Nothing contacts 1Password except in
response to a request csecd chose to make** — csecd no longer probes at launch,
so a Mac that boots and sits idle never sees a 1Password prompt from csec. The
attended install's `csec restore` is such a request: it fetches the paired
values ahead while the person who started the install is at the Mac
(§Grants across a restart). And
the **keepalive follows real use**: it touches only a session a real request
already opened, every four minutes, comfortably inside 1Password's documented
ten-minute idle window, and only while the screen is unlocked. Screen lock,
display sleep, and system sleep suspend it immediately, because 1Password
revokes every authorization when its app locks and a ping from that state could
only re-prompt. Nothing resumes the keepalive but another real
request — never the screen unlocking. A ping that cannot be served within two
seconds is abandoned and its bridge stopped, which withdraws the request and
takes any prompt down with it; the session is then left lapsed until demand
returns, rather than retried on a timer. Two seconds applies only where the
ping may be re-authorizing. A busy Mac slows a healthy session past it too,
and dropping that session is itself a prompt on the next request, so a
session that answered within the idle window, from a 1Password that cannot
have idle-locked (its auto-lock is "Never", or someone used the Mac more
recently than that lock's minutes, from IOHIDSystem's idle time), gets fifteen
seconds instead. An unreadable setting or idle time keeps the two seconds. A
read that answers while a ping waits proves the session alive, and the
keepalive never stops a bridge that a real request replaced meanwhile.

A third rule keeps a declined prompt declined. **An account that refused is
not asked again until a person approves a csec panel at this Mac.** When
1Password refuses an account's authorization, ends its session, or puts up a
prompt nobody answers in time, csecd holds that account as refused: no
request, attended or unattended, no re-read and no fetch ahead starts a bridge
for it, and each reference that needs it fails at once saying why. Approving
a csec panel at the Mac (not on the phone) lets the request it approved, and
the fetch ahead after it, ask once more, before that request resolves
(`SecretProvider.personApprovedAtMac`). No timer lifts it: a refusal says
nobody is there to answer, which only a person's approval contradicts. Before
this (csec-0.84, 7 Nov 2026) every reference of every request and every
unattended retry re-authorized both accounts, so one refusal became a dozen
within seconds.

1Password's prompt is its own window, which csec neither draws nor sees, so
**csecd tells the person when it is waiting and when an account is held**
(`ProviderAttention`, one macOS notification per account that each new state
replaces). A request that may be the authorizing one (its account's bridge has
not answered within the idle window, or a lock or sleep came since) and is
still unanswered after eight seconds raises a notification, with a sound,
asking the person to answer 1Password's prompt; it is withdrawn when 1Password
answers. An authorized first contact answers well inside that, so a session
already open never raises one. When an account is held, csecd says so once,
naming whether the prompt went unanswered or was declined and that an approval
at this Mac asks again, and `csec status` shows the held account on the
1Password row as a warning. The hold bounds both: nothing announces an account
again until an approval at the Mac lifts it. Before this (csec-0.64.17), the
prompt went unanswered after 4 of 6 installs from 7 Nov with the person at the
Mac, and the only record was `csec restore`'s output in the install worker's
log.

The one thing csec still asks the `op` CLI is which accounts are signed in
(`op account list`). That reads local configuration, and cannot prompt or
unlock anything.

Which account owns which vault is the **account index**. An
`op://VAULT/ITEM/FIELD` reference carries no account, and plain `op` resolves it
against whichever account its own config last recorded — a default that moves
when a different account is unlocked, and that silently points at the wrong
organization when several are signed in. csec decides instead. A reference is
first tried optimistically against the account there is honest reason to try:
the one a review already settled on, or the only signed-in account. With several
accounts the first request builds the index, which costs one authorization per
account, and the index is kept. Once built, selection is exact: an exact vault
id, else a vault name matched case-insensitively exactly as `op` matches it,
else — only for the two spellings 1Password gives a member's personal vault,
"Employee" and "Private" — each account's personal vault whatever it is titled,
because `op` shows one spelling and the SDK the other and the bridge already
reads either as that vault; else the account whose vault actually holds the
item (item titles and ids only, never a field). If several accounts still
qualify, the trusted review window names the one that will be used and warns
that the vault name is not unique; resolution proceeds only for a choice a
review displayed, so csec never silently picks between accounts. The review
breaks that tie only from item listings it already holds: listing a vault's
items opens a bridge, whose first request authorizes, and the review answers
from warm state. Without them it names every account that has the vault and
says the value will come from whichever holds the item; the read after approval
lists the items, reads from the one account that holds it, and fails closed if
none or several do. That read leaves the listings held, so the next review names
the account. The account
each reference resolved from is remembered for the daemon's lifetime, so an
approved reference cannot drift later. Refreshing a session and refreshing the
index are the same call, so the keepalive keeps selection exact for free. The
index is derived state held only in memory — writing a vault-to-account map to
disk would give same-uid malware a way to redirect a reference at an account it
controls. `csec status` reports how many accounts are authorized and how many
vaults are indexed.

A "not found" from the bridge is a claim, not a verdict. Every session
re-authorizes after the Mac sleeps, and for the first seconds after 1Password
unlocks an account is still loading: the SDK reports an item it has not loaded
yet as absent. So a miss is first checked against the account's own vault
list. A vault that is not there is settled — for a guessed account the index
decides; for an account a review displayed, the request fails closed and the
decision is forgotten, so the next request can show the new account rather
than deliver from one the window never named. A vault that is there means the
read is repeated on a short schedule (3.5 seconds in all, the most a genuine
typo can cost) before the miss is believed, and the failure then names the
account and vault that were asked, so "not found" is never mistaken for "wrong
account". Every account decision, miss, retry, and confirmation is written to
the unified log as value-free metadata, because launchd discards csecd's
stderr:
`/usr/bin/log show --last 1h --predicate 'subsystem == "com.alexspeller.convenient-security"'`.

The bridge is the one csec binary signed with
`com.apple.security.cs.disable-library-validation`: 1Password's desktop
integration is reached by `dlopen`ing a library that AgileBits signs, and the
loader would otherwise refuse it. The exemption is scoped to that binary and
checked against its exact signing identifier, every other forbidden entitlement
still disqualifies it, and the loader check it removes is replaced by an
explicit one — both csecd and the bridge verify the library is validly signed by
AgileBits before it is loaded, and the bridge refuses any path but the one in
`/Applications`. `docs/threat-model.md` carries the rationale and the residual
risk; HA-B10 reports the underlying condition.

This is best-effort continuity, not a bypass of 1Password policy: locking the
1Password app revokes every authorization, and the desktop integration applies
its own maximum session lifetime. Either event can require fresh local approval,
and csec waits for a real request before asking for it.

Writes stay on the `op` CLI. `csec protect --env` and `csec edit op://…` run in
the `csec` process, not the daemon, and cannot reach csecd's sessions; they
build their own account index and pass an explicit `--account`, prompting once
per invocation. That is acceptable where a read heartbeat is not: a write is
something the user just typed, so its prompt is attached to an action they
took.

For 1Password, resolution first reads the value over the account's session
when csecd already holds that session open, then checks the warm in-process
cache, then—only when a just-approved biometric context is present—the
data-protection keychain, then the provider. Resolved values repopulate both
cache tiers.

The open-session read is what keeps the cache honest about edits made in the
1Password app, which never pass through csec (csec-0.81: a fixed webhook was
served from the cache for as long as the old one stayed cached). It runs only
when every one of these holds: the reference's account is known from warm
state (a remembered decision, the only signed-in account, or a unique answer
from the account index); that account's bridge process is running; the
keepalive is not suspended by a lock or sleep; and the bridge answered within
1Password's ten-minute idle window. It never starts or restarts a bridge, so it
cannot authorize or raise a 1Password prompt. A value that differs replaces
the cached copy in both tiers; whether it differed never leaves csecd. A
release waits at most three seconds for it, then serves the cached copy; the
read still finishes and refreshes the cache for the next release. A read that
began before an invalidation never writes over it. With no open session (after
a sleep with 1Password set to lock with the device, or after csecd restarts
before any uncached read), a release a person has just approved at the Mac (a
local Touch ID, never a phone approval) asks 1Password itself before the cached
copy (Alex, csec-0.81.1): that may raise 1Password's own authorization once per
account, which the person who approved is there to answer, and the session it
opens confirms the rest of the release. If 1Password cannot answer, the cached
copy is served. In-grant fetches, phone approvals and delegated releases with
no open session get the cached copy, as before. `csec refresh <reference>...`
drops the cached copy outright (the `invalidate_cached_references` verb `csec
edit` sends after a write; value-free, no Touch ID), so the next release reads
the provider. A delegated release goes through the same open-session read.

The keychain stores one `kSecClassGenericPassword` item per canonical reference
with `kSecUseDataProtectionKeychain`, the provisioned application access group,
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, and `.biometryCurrentSet`.
Re-enrolling biometrics invalidates the item. Its account is the canonical
reference itself and its data the value, readable only through a biometric
context. The warm tier is memory-only; no tier has a wall-clock expiry, so a
cached value stays until something invalidates it (a rotation through
`csec edit` or `csec protect --env`) or an open-session read replaces it.

Native references use `csec://<store>/<key>`. The decrypted document is a flat
JSON object of string keys and string values. Store and key names use a bounded
path-safe ASCII grammar; duplicate keys, nested/non-string values, invalid JSON,
more than 1024 entries, and canonical documents over 1 MiB are rejected. Native
values use `.noCache`: the encrypted file remains the source of truth after an
edit, while the per-store data key is warm only in the provider actor.

Ciphertext is stored in
`~/Library/Application Support/ConvenientSecurity/Secrets/`. Each logical store
has a random 256-bit AES key in a data-protection Keychain item under the
daemon's provisioned access group, `WhenUnlockedThisDeviceOnly`, and
`.biometryAny`. The latter still requires Touch ID for a cold read but avoids
destroying the sole decryption key when enrolled fingerprints change. The item
does not migrate to a new device.

Every save canonicalizes JSON, generates a random 96-bit GCM nonce and random
128-bit file ID, authenticates the store name/version/generation/file ID as AAD,
writes the new envelope to a fresh `0600` file, fsyncs and atomically renames it,
then updates the biometric Keychain record to the new generation, file ID, and
SHA-256 ciphertext digest. Only after that switch is the previous file removed.
This order survives a crash without selecting a partially written file. A
same-UID attacker can read, delete, or replace ciphertext, but cannot modify the
Keychain pointer/digest; alteration, cross-store substitution, and replay of an
older valid envelope therefore fail closed. Deletion remains denial of service.
The directory is `0700`, operations reject symlinks and unexpected ownership or
permissions, and plaintext is never written there.

### One-time codes

A reference whose path ends in a query with `attribute=otp` or
`attribute=totp` (`SecretRef.isOneTimeCode`) asks for the current one-time code
(TOTP, RFC 6238), on any scheme. The spelling is 1Password's own; csec matches
it more widely than any provider resolves it (key and value without case, after
percent-decoding, any parameter of the query), and measured against the
1Password SDK's own parser (v0.4.1, offline `ValidateSecretReference`), which
accepts only the lowercase single-parameter forms, no spelling 1Password turns
into a code reads as an ordinary secret here. That matters because a code gets
the opposite of a stored value's treatment (csec-0.65):

- **Never cached.** The resolver reads and writes no cache tier for a code, and
  drops an entry an older csecd left; a provider's cache hint is ignored.
- **Never covered.** No grant covers a code, so every request for one is new
  and gets its panel; nothing minted names one, so a restart has nothing to
  restore. A panel that asks only for codes lists only them, offers only the
  requesting command as its root and no lifetime ("This command only"), and is
  headed "One-Time Code Requested"; on a panel with ordinary secrets too, the
  scope and lifetime chosen apply to those alone. Each code's row carries
  csec's note, first, saying it is made for this command and never kept, which
  the phone mirror draws as it draws every secret's notes.
- **Never delegated.** Claude Code auto mode never releases a code, whatever a
  pairing says (`DelegationDecline.oneTimeCode`), never offers to pair one and
  never records one in a pairing. A delegated release, a restore and the
  attended fetch ahead (`resolveWithoutInteraction`, `fetchAhead`) treat codes
  as not held. An unattended automation job cannot be enrolled with one.

A provider that makes codes itself says so (`SecretProvider.makesOneTimeCodes`):
1Password resolves `?attribute=otp` in its SDK, so the seed never leaves it. Any
other provider is only ever asked for the seed reference (the code reference
without its query: presence, review description, unlock state and resolution
alike), and csecd works the code out from the `otpauth://totp/…` value it
returns (SHA-1, SHA-256 or SHA-512; 6 to 8 digits; period up to an hour). The
seed stays inside that one resolver function.

**The seed guard.** A seed is a standing second factor, so csecd never releases
one through any reference. An ordinary reference whose value, from a provider
or the cache, is an `otpauth://` or `otpauth-migration://` URI fails with a
reason that names `?attribute=otp`, and fetch ahead never keeps one. 1Password
also stores bare base32 seeds, so when the bridge resolves a reference with no
query of its own it also asks for the same reference with `?attribute=otp`, in
the same `ResolveAll` (one round trip to the desktop app, and a typed answer
for each). A miss is read again on its own so its error keeps its kind, except
a session failure, which is returned at once rather than risk a second prompt.
The SDK makes a code only for a TOTP-type
field and refuses any other ("TOTP attribute can only be applied to TOTP-type
fields"). A code, or the SDK's own failure to make one from a malformed seed,
means the value is a seed: the bridge drops it and answers `otp_seed`, so it
never crosses the pipe. Any other outcome of the probe leaves the field
ordinary; the probe can only withhold a value, never add one.

Output masking skips values shorter than 8 bytes, so a printed 6-digit code is
not masked: an agent can see a code while it is valid, never the seed.

#### Native-store backups

Without a backup, losing the device or deleting the native-store Keychain record
makes its encrypted files unrecoverable: the key record is `ThisDeviceOnly`, so
Apple never migrates it, and `.biometryAny` has no passcode fallback. `csec
backup` (NativeStoreBackup.swift, NativeStoreBackupCrypto.swift) keeps a sealed
copy off the Mac without weakening either property.

The recovery kit is 32 random bytes, shown once as `CSEC-` and 14 groups of
Crockford base32 (the last a 20-bit check), in the signed launcher's own window,
never the terminal; the human pastes it back before setup completes. The
masked field it goes back into, at setup and at restore
(`RecoveryKeyEntryView`), is one scrolling line with a status line that counts
the groups and says whether the check group matches, never a character of the
key; the launcher installs a standard Edit menu (`StandardEditMenu`) so
Command-V and Command-C reach it, as they reach `csec edit`. HKDF from
it gives a P-256 recipient key pair, a MAC key and a file-name key. csecd keeps
only the public half and the MAC and name keys, with a random backup ID, in the
protected item `native-store-backup`/`v1`, so a same-UID process can neither
swap in a recipient of its own nor learn the MAC key; the kit's secret and
private key are never stored.

A bundle backs up one tier of one store (its key record and exactly the
ciphertext files the record pins: the document and its origin marker, or the
blob index and every blob) or the SSH key catalog. It is sealed with
`RemoteUnlockCrypto.seal` (ECIES, context binding the backup ID and file name)
and then HMAC'd. Restore checks the MAC before opening, so a bundle sealed to
the public key alone, moved to another name or backup, or changed by one byte
is refused. File names are a keyed hash of the tier and store, so the folder
names no store. Nothing about a bundle is decrypted to write it: the files are
copied as they are and checked against the record's digests.

Each provider calls the backup wherever a key record is current in its hands,
after every commit, blob import or removal, and every local record open. When
the manifest's bundle is older than the record (or of another lineage, a keyed
hash of the store's data key that never leaves the protected item), or is no
longer the file it wrote (size, inode and modification time), it writes a new
one atomically. Steady state therefore costs
no prompt, and a store changed while a write failed, or created before setup,
is backed up at its next local open. A failed bundle is recorded for `csec
backup status` and never fails the store write. Setup and `csec backup sync`
read every key record under the one Touch ID they take, like remote-unlock
backfill, and leave warm state as it was. A blob store whose bundle would pass
256 MiB is refused from its index before any blob is read, and not tried again
until it changes. Rotation (setup again) writes a new folder under a new kit;
the old folder keeps its bundles until every store has a current bundle in the
new one that iCloud Drive reports uploaded, and then loses only the files this
Mac's manifest named there.

A folder is written only by the Mac whose settings name it. Restore takes the
kit from the launcher's window and reads every folder under the root whose
bundles it opens, without changing anything there (iCloud Drive is asked to
download a bundle it has not yet, which the listing counts). It takes each
item's newest bundle and validates it against the real envelope code: the
record must pin exactly the files present, and the document or index must
open. After one Touch ID it writes the files, then a new device-bound Keychain
record holding the same record, through the provider actor, so warm and absent
state stay the actor's. It never overwrites. A name this Mac holds a Keychain
record for, in either tier, is skipped whole, so one key cannot come to name a
value in each tier. Files under a name with no record are accepted only when
they are this bundle's own, byte for byte, which is how a restore interrupted
before its record was made finishes. SSH keys whose store this Mac now has
merge into the catalog by fingerprint. A Mac with no backup of its own then
carries the backup on under the same kit, in a new folder of its own.

The backup is a native-provider feature behind `SecretProvider`: no
authorization, policy or delivery path sees it, and other providers (1Password)
keep their own recovery.

At startup, the daemon probes the restricted access group. A signed and
provisioned build enables persistence. An unsigned development build reports
`at-rest cache OFF` and uses a null persistent cache rather than weakening or
emulating the entitlement.

## Protected state

csecd keeps its own small documents in data-protection Keychain items in its
restricted access group, `8RS6GD89Y7.com.alexspeller.convenient-security`,
named explicitly on every item so that a second entitlement entry could never
move them:

| Item (service suffix / account) | Holds | Cap |
| --- | --- | --- |
| `delegation` / `settings-v1` | the delegated-approval opt-in, the policy version consented to, the Claude Code settings file setup edited and whether it added `classifyAllShell`, trusted builds (≤32), acknowledged hooks and classifier-rule sources (≤128, with ≤2,048 display-only rule digests; document format 2) | 256 KiB |
| `delegation` / `registrations-v1` | the Claude Code registrations bound to a running command: P's and the command's pid and start time, the program digest, the permission mode, the hook's working directory and launcher, arrival, boot session (≤1,024) | 1 MiB |
| `grants` / `live-v1` | every persisted secret and SSH grant | 1 MiB |
| `pairing` / `v1` | project pairings, their pinned launcher scripts, sudo and use-only references (document format 4) | 512 KiB |
| `runtime` / `last-run-v1` | the last run's boot session, cdhash and version, and whether it shut down cleanly | 4 KiB |
| `decision-log` / `key-v1` and `head-v1` | the decision log's key, and each stream's checkpoint | 512 B, 4 KiB |
| `baseline` / `pointer-v1` | the sealed host-audit baseline's generation, file ID and digest | 4 KiB |
| `automation` / `runs-v1` | every in-flight automation run lease: run ID, job name, ID and revision, launcher pid, start time and audit session, deadline, invalidation, boot session (≤128) | 128 KiB |
| `github-proxy` / `settings-v1` | the canonical reference of the token the GitHub proxy injects (§GitHub token proxy) | 8 KiB |
| `native-store-backup` / `v1` | the native-store backup: its random ID and folder, the recovery public key, the MAC and file-name keys, and the manifest of bundles written and failed (≤4,096 each) | 1 MiB |
| `machine-identity` / `catalog-v1` | the machine identities (≤8: name, issuer, subject, and up to two Secure Enclave key handles with their public JWKs) and their sign-in targets (≤64: name, identity, kind, audience, lifetime, and for AWS the role ARN and region). A key handle signs for any same-user process that holds it, which is why it lives here and nowhere else | 128 KiB |

Each is `AfterFirstUnlockThisDeviceOnly`, never synchronized, and carries no
biometric ACL, so csecd loads it at startup without a prompt, even after a crash
behind a locked screen; consent lives in csecd's code paths that change them,
never in the item. Only the app bundle's main executable holds the access group
— AMFI kills another binary that claims it — so a same-UID process can neither
read, write, add, delete nor roll back these items (measured with an unentitled
probe; `packaging/bin/build-spike.sh` re-proves it on a signed build). A
document is strict JSON in a versioned envelope whose bounds are checked on
every read and write. An item csecd cannot read (a Keychain error, a newer
format, damaged bytes) turns its feature off for the run, or restores nothing,
and is held for the rest of the run: neither written nor deleted, so an older
csecd, or a start whose Keychain read failed, can never write its empty state
over what the build that wrote it recorded. (On 14 Oct 2026 a downgrade
installed for 25 minutes erased every project pairing that way.) What is
approved meanwhile holds for the run only, and a revocation says the held item
may bring it back. A later load that reads the item lifts the hold. csecd logs
each held item once per start, and `csec status` / `csec doctor` name it and
the fix: reinstall the current build (a newer format; doctor fails), restart
csecd (a Keychain error; doctor does it), or the command that discards a
damaged item (doctor warns, since no install mends it). The runtime gate in
the middle of an install never fails on one, so the install finishes every
stage. Only a human's request to remove everything the item
grants deletes a held item: `csec revoke --all` (grants, pairings), turning
delegated approvals off (settings, pairings), and `csec uninstall`. An item
from an older format that no build reads any more is not held, and neither
are `last-run-v1`, the delegation `registrations-v1` and the automation
`runs-v1` leases, which record no
decision and which csecd rewrites whole from its own state. A write
that fails deletes the item rather than leave an
older document behind, and each item's changes are applied in the order its one
owning actor prepared them. A DEBUG build without the access group keeps them in
memory; a release build without it runs with these features off.

The phone-held unlock factor (docs/remote-approval.md) keeps its items in the
same group and class — `AfterFirstUnlockThisDeviceOnly`, no biometric ACL,
never synchronized — under services of its own: `remote-unlock` /
`enrollment-v1` (the enrollment's public point E, the remote-unlock key's
private half wrapped under a secret only the paired phone's Face-ID-gated
Secure Enclave key agreement can recompute, the remote public key, and the
pairing it is bound to), `remote-unlock` / `epoch-v1` (the cdhash of the last
run that kept the mirrors), and `remote-unlock-mirror` / `doc/<store>`,
`blob/<store>`, `cache/<uri>` (each native key record and cache entry, sealed to
the remote public key). None exists until a phone is enrolled, and nothing in
them opens without that phone's Face ID; the biometric native key records and
cache items are never changed. A mirror is deleted before its key record or
cache item is written and sealed again after, so a crash leaves no mirror
rather than a stale one. A cache invalidation deletes the mirror, then the
item, then the warm value, and a read or write it overtook promotes, re-seals
and keeps nothing. If a build that does not keep mirrors ran since the last one
that did (`epoch-v1` against `last-run-v1`), every mirror is dropped at startup
and comes back with the next local open or cache write; a start that cannot
read the enrollment deletes `epoch-v1`, so the next start drops them too, and
meanwhile each write removes its mirror instead of sealing one. Removing the
factor deletes the enrollment even when a mirror delete fails (without it no
mirror can open), and every start with no phone paired sweeps what is left. A
remote unlock reads mirrors only: it never queries a biometric item and never
writes a store.

## Decision log

csecd keeps a value-free record of what it decided and why, sealed so that a
same-UID process can neither read its files nor forge, alter, reorder, splice,
truncate or roll it back unnoticed. Records live in
`~/Library/Application Support/ConvenientSecurity/DecisionLog/` (a `0700`
directory of `0600` files) as AES-GCM frames in hash-chained segments of at most
4 MiB, in two streams with their own size caps:

- `decisions`, 32 MiB: review panels with their outcome, decider and time to
  decision; requests refused by an earlier Deny; delegation declines;
  revocations; settings changes, including pairings, trusted builds and
  acknowledged hooks; restores; restarts and their cause; grant-cap evictions;
  host-audit baseline events; integrity findings.
- `usage`, 64 MiB: grant reuses and delegated releases, one record per release
  or signature, kept apart so their volume can never evict decision history.

Retention is by size alone: a `prune` record raises the pruned-through sequence
before the oldest segment is deleted. No clock bounds the files, because they
are ciphertext under a key only csecd holds.

Each frame's associated data binds the stream, the segment, the sequence number
and the previous frame's tag, and each segment's first record carries an
authenticated link to the previous segment's last frame. The 32-byte key and each
stream's checkpoint (segment, sequence, tag, length, pruned-through sequence)
live in the `decision-log` protected items (§Protected state). A `decisions`
record is written, flushed to the disk (`F_FULLFSYNC`) and checkpointed before
the append returns. A checkpoint that cannot be written (a failed flush, or a
Keychain write that fails) does not hold the record back: it stays unanchored
until the next checkpoint that is written, and `csec status` counts the
failure. The `usage` checkpoint is coalesced to at most ten seconds
and flushed by csecd's SIGTERM handler, which waits at most three seconds, so
after a crash the last few seconds of usage can be lost without a finding.

Verification runs at startup and on `csec log --verify`: walk every chain,
authenticate every frame, compare with the checkpoint. It finds a modified or
reordered record, a missing, spliced or foreign segment, a tail behind the
checkpoint (truncation or rollback), a pruning gap, and a missing key or
checkpoint while segments exist. A partly written final frame after a crash is
cut and recorded as `torn_tail`, not as tampering. A finding is recorded once as
`log_integrity`, notified once, and shown in `csec status`; the segment where
verification failed and every later one, authentic or not, are set aside, and
the chain resumes from the checkpoint in a fresh segment, so the next start is
clean. Set-aside segments stay on disk under their own budget but leave
`csec log`'s readable history. The checkpoint moves past a finding only once the
finding is durably recorded; until then the log records nothing more and finds
it again. Planted files never cost verified history: only verified segments count
toward a stream's cap, set-aside files have a budget of their own, a file csecd
cannot move is recorded once and remembered by a digest in the checkpoint
(csecd's own damaged segments on a list of up to 96 that planted files cannot
crowd out, junk and foreign files on a list of 32), and every open of an
existing name is non-blocking, so a FIFO planted under a log name cannot hang
csecd. A record a newer build wrote reads as `unrecognized`, never as tampering.

A record carries its kind, sequence number, wall time and boot session and, as
the kind needs, the surface, the requester (class, root, terminal), canonical
references, the release shape, the mechanism, the panel's own redacted command
string (bounded), scope, duration, outcome (`approved`, `denied`,
`requester_gone`, `authentication_failed`, `phone_approved`, `timed_out`,
`use_password`), decider
(`human_local`, `human_phone`, `delegated`, `grant`, `restored_grant`), time to
decision, the grants a panel minted, a delegation decision and its reason, and
for a panel its `cause`: `new_refs`, `new_release_shape`, `new_process`,
`grant_expired`, `grant_revoked`, `restart_not_restored` (a grant dropped at
load would have covered this request), `restart_restore` (the restore panel) or
`one_time_code` (every new reference was a one-time code, which no approval
covers) or `lasting_access` (a GitHub request that can give lasting access,
which no approval covers). `csec log` marks a row whose references include
one-time codes.
A `settings` record for a delegation sheet that did not approve has why it
ended as its `cause` (`user_cancel`, the human's Deny, logged `denied`;
`requester_gone`; otherwise `authentication_failed` with `system_cancel` or
`app_cancel` for a sheet taken down unanswered, `auth_failed`,
`user_fallback`, `biometry_lockout`, `no_touch_id`, `not_interactive`,
`not_shown`, `unexplained` or `la_error_<code>`), and the sheet's time on
screen as its time to decision.
No field carries a value. A sudo decided on the paired phone passes through
csecd and is logged as a `panel` record with surface `sudo`. Every other end of
a sudo review is the review helper's own report (`sudo_review_end`), which
csecd takes only from the installed helper's code identity and logs as that
helper's word, not as a decision it attests the way it attests its own panels:
a Mac approval (`panel`, `approved`, `human_local`), a review that went on to
macOS's own authentication (`panel`, `use_password`: Use Password, a closed
panel, or no Touch ID and no phone to decide), the deadline (`withdrawn`,
`timed_out`) and the sudo exiting before anyone answered (`panel`,
`requester_gone`). Each sudo record's requester is class `sudo`, rooted at the
nearest coding agent above the sudo (`rootLabel` Claude Code or Codex, `scope`
`coding_agent`) when one ran it, else at the sudo itself. csecd notes that root
while the sudo still runs (its `sudo_terminal` lookup, before any panel), since
once the sudo exits its helper hangs from launchd; for a sudo delegation
declined it is the process the decline names. A supervisor can so raise again
a coding agent's sudo nobody answered.

`csec log [--since <time>] [--kind <kind>] [--json]` pages through it: the
`decisions` stream by default, and `usage` for `--kind reuse` or
`--kind delegated_release`. Like `csec grants` it needs the verified launcher
and no Touch ID. A same-UID process could run the genuine `csec` anyway; the
references are already in sidecars and `.envrc` files and the commands in the
coding agent's own transcripts, and the encryption still defeats the ordinary
copy-files-from-home theft.

### Uninstalling

`csec uninstall` runs in this order. It first reverts the Claude Code settings
exactly as disabling delegation does, reading csecd's record before anything is
deleted. A revert csec cannot write prints exactly what to remove by hand, and
with no record from csecd (unreachable, or delegation never enabled) the
current user settings file is reverted and `classifyAllShell` stays, so Claude
Code classifies more, never less. It then sends `uninstall_cleanup`, which
csecd gates with one Touch ID in its settings panel naming the terminal, what it
deletes and what it keeps. If Touch ID is refused, csecd deletes nothing, the agent stays
registered, and csec undoes step one: in one atomic write to the same file it
puts back exactly what the revert took out (the delegation-aware
`autoMode.environment` entry, and `classifyAllShell: true` only where the
revert removed it), so a refused uninstall changes nothing. A put-back csec
cannot write is reported with the keys to restore by hand, or `csec setup`
writes them again. On approval csecd enters a terminal uninstalled state
in which it writes nothing more — no log append, checkpoint, last-run, grant,
pairing, automation run lease or baseline write, and nothing from its SIGTERM handler — drops its
in-memory delegation settings and pairings, deletes every protected item, the
decision log and the sealed host-audit baseline (with any plaintext baseline an
older csecd left), and replies naming anything it could not delete. Nothing
else is deleted: the native stores and their keys, the Keychain cache of
`op://` values, the SSH and automation catalogs and the iPhone pairing stay,
and a reinstall resumes them. csec then unregisters the LaunchAgent, and the
SIGTERM that follows writes nothing. If csecd cannot be reached, csec
unregisters it anyway and says that csec's Keychain items, encrypted log and
sealed baseline remain: only csecd can delete them, and a reinstall reuses
them.

`csec uninstall --all` removes the rest without a checkout. It checks first
that the package's uninstaller (`libexec/uninstall-csec.sh`) is there and
root-owned, so a Mac that cannot finish is told before anything changes. After
the same Touch ID it takes csec's hook out of Claude Code's and Codex's user
settings, keeping every other hook; both fail closed, so if a hook cannot be
removed the app and system parts stay to keep it working. With csecd stopped it
runs that uninstaller through `sudo`, which removes the sudo review by the
same guarded steps as `--uninstall-sudo` (a harmless `sudo` must succeed
before the module and helper go), the managed Codex hook, `csec-rootd` and its
LaunchDaemon, the app, the support directory and the package receipt. It stops
at the first failing step, and every step skips what is already gone, so
running it again finishes the job. Secrets and stores stay, as above.

## Release policy

`ReleasePolicy` is a deterministic pre-resolution decision reduced to what the
threat model actually needs. It computes the grant lifetime — by default the
lifetime of the process/session the grant is rooted at, with no wall-clock cap
(the request carries no TTL); an explicit `--for` sets an uncapped bounded
lifetime instead — a mechanism-derived
output policy (redact-and-warn, or an intentional-credential-channel for the
AWS/Git helpers), and the single hard `csec get` plaintext-exposure gate
described under Raw output. There is no risk classification, no per-credential
judgment store, no compatibility-acceptance ledger, and no destination or
evidence escalation.

Those were removed deliberately. Against an automated, opportunistic same-user
supply-chain attacker, the load-bearing control is a physically-present Touch ID
over a value-free review bound to the process subtree — not a five-level taxonomy
that mostly produced confusing prompts (a first `csec get` used to demand a
classification popup *and* a compatibility checkbox *and* the tap, to print a
value the user had just asked for). Malformed metadata, requester-verification
failure, stale/reparented/replaced processes, an invalid scope, denial, or
unavailable biometrics remain hard pre-resolution failures; the structural
integrity of the delivery plan is still enforced before any value is resolved.

## Security requirements

The shipped agent and launcher require all of the following:

- Developer ID signing by the compiled team and exact signing identifiers;
- hardened runtime and notarization;
- an embedded provisioning profile authorizing the team-prefixed keychain
  access group for the daemon;
- no `get-task-allow` and no Hardened Runtime exception entitlements for library
  validation, DYLD environment variables, JIT or unsigned executable memory,
  executable-page protection, or debugging; and
- the exact root-helper identity installed root-owned/non-writable at
  `/Library/PrivilegedHelperTools/com.alexspeller.convenient-security.rootd`,
  loaded only from its root-owned system LaunchDaemon plist; and
- SIP enabled on the host.

The startup self-audit fails production startup when the required daemon posture
is absent. It registers only providers whose own requirements are satisfied and
refuses to start if neither the native store nor verified 1Password CLI is
available. The signed-package verification procedure is in
[`packaging/README.md`](packaging/README.md).

## Current security boundary

The strongest implemented paths deliver through private credential pipes into a
clean consumer heap, through a process-local inherited descriptor, or to a
root-owned regular file traversable only by one capability-GID process tree.
The environment launcher is a compatibility feature with an acknowledged
same-UID disclosure channel. Output redaction is an egress safeguard, not a
repair for any authorized consumer's ability to disclose a value. Release policy
uses a value-free warning plus a single Touch ID rather than a risk taxonomy; the
only categorical refusals left are an unacknowledged raw `csec get` shape and the
structural integrity checks. Approving an inspectable delivery does not make an
authorized recipient safe. Opt-in delegated approval lets Claude Code's
classifier stand in for that touch only for references a human already paired
with the project, and only as far as its gates attest; it is exactly as strong
as that classifier.
Native ciphertext and its rollback record protect durable data, while decrypted
editor buffers and values released to consumers remain subject to the
authorized-consumer boundary. The precise attacker capabilities and limits are
recorded in
[`docs/threat-model.md`](docs/threat-model.md).
