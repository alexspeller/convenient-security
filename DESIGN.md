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
compatibility launcher, and exact-value output redaction. Every delivery is
gated by a single Touch-ID-approved, value-free review before provider or cache
resolution. It can resolve from the official 1Password CLI and from device-bound
native encrypted files.

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
  for output redaction, and owns the host-posture audit engine (§Host posture
  audit) — running it under Full Disk Access and driving the root helper for its
  privileged reads and reversible fixes.
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

Protocol v2 uses bounded, length-prefixed JSON with request nonces, typed
value-free failures, and a canonical digest of the delivery plan. See
[`docs/protocol.md`](docs/protocol.md).

## Grant model

A grant is held only in `csecd` memory. It records a root PID and process start
time, the approved references, reason, expiry, the originating protocol-v2
delivery binding, and the delivery-plan digest that bounds its reuse.

The daemon obtains the caller PID from the kernel rather than JSON. A grant is
usable only when kernel parent traversal reaches the recorded root with the same
start time, which prevents PID reuse from reviving it. References already
covered by a compatible live grant are returned without another prompt. Adding
a reference prompts for the delta and then expands the grant. Grants expire by
TTL and disappear when the daemon exits; orphaned descendants no longer satisfy
the ancestry check. Reuse also requires the current delivery-plan digest to
match exactly.

The subtree model intentionally gives descendants of an approved root access to
the same granted references. Code running inside that subtree is therefore part
of the trusted consumer boundary.

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

The window creates a fresh `LAContext`, pairs it with Apple's embedded
`LAAuthenticationView`, and starts Touch ID as soon as the rendered panel is
visible; there is no preliminary button or Enter-key gate. On biometric success
the daemon retains the evaluated context and hands the agent a plain approval;
the agent mints the subtree grant and calls back to release that context so a
cold cached value or cold native-store key is unlocked by the same tap. A denial,
unavailable biometrics, or lockout fails closed. The localized Touch ID reason
carries the same bounded, value-free delivery details as defense in depth, and
all dynamic text is bounded with control, newline, and bidirectional-formatting
characters neutralized.

An explicitly paired iPhone may mirror this review for requests composed only
of `op://` references. csecd freezes the phone display model before starting
either path, signs its canonical request with a device-bound Secure Enclave key,
and races the ordinary local review against a 90-second CloudKit-private-database
exchange. The phone verifies its pinned Mac key before showing an action and its
Face-ID-gated Secure Enclave key signs the exact decision, request ID, request
digest, phone ID, and timestamp. csecd accepts only the pinned phone, matching
unexpired transaction, and a single use. CloudKit is an untrusted value-free
mailbox, never an authorization source. Missing enrollment or relay failure
leaves the local flow unchanged; host remediation and `csec://` stay local-only.
See [`docs/remote-approval.md`](docs/remote-approval.md).

Editing a native file is a separate exact-launcher operation that asks for fresh
Touch ID and shows that every key in the named store will be exposed to the
editor; it does not create a reusable secret grant. The shipping daemon has no
runtime auto-approval switch; automatic consent exists only in separate test
executables and injected test dependencies. A provider may still require its own
independent authorization — for example, the 1Password app can display a separate
account-access request — which csecd cannot merge into its window.

## Delivery

### Language-client heap delivery

The Ruby gem and Node.js npm package send references, reason, and TTL to the
fixed root-owned `/Library/Application Support/ConvenientSecurity/bin/csec`
bridge. The helper uses a scrubbed environment and private close-on-exec pipes.
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
requires the caller's audit session to match and a fresh kernel ancestry walk to
reach the registered PID/start-time pair. The ID is therefore a lookup hint,
not a bearer capability; copying or forging it outside the subtree fails.

The delivery plan and review distinguish a registered `broad_session` root from
an ordinary per-command root; a grant is reused across sibling descendants when
the delivery-plan digest matches. Grant TTLs, plan digests, and live ancestry
checks apply independently of registration lifetime.

### Credential protocols

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
`PGPASSFILE`, `KUBECONFIG`, `AWS_SHARED_CREDENTIALS_FILE`, and
`GOOGLE_APPLICATION_CREDENTIALS`. No pathname names the bytes in the filesystem.

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
release policy, obtains fresh Touch ID, resolves the exact reference set, renders
bounded payloads, and sends those bytes directly to the root helper. It returns
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

`csec protect` and `csec exec` build a whole-file workflow on this mechanism.
`csec protect` imports plaintext files into the store as per-value AES-GCM blobs
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
original path into that tmpfs and removes it on exit. A `*.csec` file that looks
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

`csec edit <store>` asks `csecd` to begin a caller-bound edit session for a
bounded 30-minute lifetime. After Touch ID, the complete strict-JSON document crosses the
mutually authenticated socket into the signed launcher. By default a built-in
AppKit `NSTextView` edits it without a plaintext filesystem object. Automatic spelling,
grammar, replacement, data detection, smart punctuation, and window restoration
are disabled. Save validates and canonicalizes the document in both the launcher
and daemon before the daemon encrypts it; Cancel tells the daemon to discard the
session. Sessions are bound to the launcher's kernel PID and start time, capped
at eight, and a stale concurrent editor cannot overwrite a newer generation.

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
named plaintext file, and one Touch ID authorizes it; commit re-checks that the
session has not expired before writing.

The built-in editor still authorizes the user and AppKit/input stack to see the
plaintext; copying, screenshots, accessibility/screen-capture privileges, or a
compromised authorized process remain outside the boundary.

## Output redaction and AI hooks

For one supervised `csec exec` launch, the launcher builds redaction rules from
the values it resolved. It replaces exact values and supported canonical
base64, base64url, percent-encoded, and JSON-escaped representations before
forwarding owned stdout, stderr, or PTY bytes. Matches spanning read boundaries
are handled. Values shorter than eight bytes are excluded unless explicitly
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
daemon. Scanner loss stops forwarding and terminates the child. Generated Claude
Code and Codex PreToolUse adapters rewrite Bash commands through this broker when
the user installs their configuration fragment.

These controls reduce accidental stdout/stderr disclosure. They do not stop
local reads, network or file writes, alternate descriptors, partial or arbitrary
transformations, non-Bash tool paths, or a malicious authorized consumer.
User-level hook configuration is also user-modifiable. Registry entries expire
at their delivery TTL and are lost when `csecd` restarts.

## Setup and onboarding

`csec setup` is a dry-run-first orchestration command. It detects Claude Code
and Codex from bounded executable search paths and their user configuration
files, then computes an additive merge of the generated Bash `PreToolUse` hook.
The hook enters through `/bin/sh` and converts a missing launcher or every
nonzero adapter result to exit status 2, while the adapter rewrites the proposed
command through the fail-closed AI output broker. Configuration reads require a
user-owned, non-symlink regular file below a user-owned, non-group/other-writable
client directory. JSON is limited to 1 MiB, rejects duplicate decoded object
keys and excessive nesting, and is re-read by bytes, mode, device, and inode
immediately before atomic replacement. Setup preserves unrelated JSON and file
mode, prints only the exact value-free managed fragment rather than the complete
user configuration, is idempotent for the exact generated handler, and requires
explicit flags to replace a recognized older csec handler. It does not replace
other hooks or override an explicit Claude `disableAllHooks` policy.

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

Privileged host operations are a **closed allow-list**, not a generic "run this as
root." Two new `csec-rootd` request cases, `hostRead` and `hostApply`, each carry
a closed enum (`HostRootRead` / `HostRootChange`) that maps inside the root server
to exactly one fixed, audited command or syscall. Both require the verified
**agent** role — only `csecd` may call them — and `hostApply` is **digest-bound**
to its own value-free change representation, which the helper independently
recomputes and requires to match before applying, exactly as the existing
`exec-file` approve path binds to a plan digest. The helper links no provider,
Keychain, or Touch ID dependency, so this preserves its minimal surface and adds
no dangerous entitlements.

Reporting and remediation are one **terminal-native** flow. The report renders as
a formatted TUI (not raw markdown); the safe, reversible `.auto`/`.autoPrivileged`
fixes are then presented as an **in-terminal checkbox picker** (default-on,
deselectable), and the still-selected set is applied atomically per target, each
change digest-bound, under a **single bare Touch ID** presented by csecd. There is
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
an accepted baseline at
`~/Library/Application Support/ConvenientSecurity/host-audit-baseline.json`. It
diffs each run and posts a `UNUserNotification` **only on a `pass → fail`
regression** of a previously-accepted control — a high-signal event that can mean
malware disabling defenses. It is notify-only: nothing is mutated in the
background, and the user re-runs `csec audit` to review and re-apply. The baseline
advances only through that interactive path, so unreviewed drift keeps surfacing.

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

The 1Password provider starts independently after the daemon begins serving. It
dynamically locates and signature-checks the official CLI, immediately runs a
metadata-only `op whoami --format=json`, discards that command's output, and
repeats the probe every eight minutes while access remains available. This stays
inside 1Password desktop integration's ten-minute inactivity window without
prefetching any secret. All CLI commands are serialized, concurrent reconnects
share one attempt, and every spawn rechecks the CLI's code identity. A failed
background probe retries after 5, 15, then at most 30 minutes; an actual secret
request does not wait for that backoff and reconnects immediately. Installing a
trusted CLI after launch is noticed on a later probe without restarting csecd.
Authentication probes have a 60-second deadline and reads a 120-second deadline,
including forced termination of an unresponsive CLI. Logs expose only fixed
connection states.

This is best-effort continuity, not a bypass of 1Password policy: locking the
1Password app revokes CLI authorization, and desktop integration still applies
its maximum session lifetime. Either event can require fresh local approval.

For 1Password, resolution checks the warm in-process cache, then—only when a
just-approved biometric context is present—the data-protection keychain, then
the provider. Resolved values repopulate both cache tiers.

The keychain stores one `kSecClassGenericPassword` item per canonical reference
with `kSecUseDataProtectionKeychain`, the provisioned application access group,
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, and `.biometryCurrentSet`.
Re-enrolling biometrics invalidates the item. The warm tier and grant table are
memory-only.

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

There is no recovery-key/export interface. Losing the device or deleting the
native-store Keychain record makes its encrypted files unrecoverable.

At startup, the daemon probes the restricted access group. A signed and
provisioned build enables persistence. An unsigned development build reports
`at-rest cache OFF` and uses a null persistent cache rather than weakening or
emulating the entitlement.

## Release policy

`ReleasePolicy` is a deterministic pre-resolution decision reduced to what the
threat model actually needs. It computes a bounded grant lifetime — the requested
`--for` duration, defaulting to 12 hours and capped at 24 — a mechanism-derived
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
authorized recipient safe.
Native ciphertext and its rollback record protect durable data, while decrypted
editor buffers and values released to consumers remain subject to the
authorized-consumer boundary. The precise attacker capabilities and limits are
recorded in
[`docs/threat-model.md`](docs/threat-model.md).
