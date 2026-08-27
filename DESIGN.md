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
compatibility launcher, and exact-value output redaction. A value-free risk
policy gates each delivery before provider or cache resolution. It can resolve
from the official 1Password CLI and from device-bound native encrypted files.

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
delivery binding, and the credential's effective risk level, policy version,
policy-decision digest, and output policy.

The daemon obtains the caller PID from the kernel rather than JSON. A grant is
usable only when kernel parent traversal reaches the recorded root with the same
start time, which prevents PID reuse from reviving it. References already
covered by a compatible live grant are returned without another prompt. Adding
a reference prompts for the delta and then expands the grant. Grants expire by
TTL and disappear when the daemon exits; orphaned descendants no longer satisfy
the ancestry check. Reuse also requires the current delivery-plan and policy
bindings to match exactly. A risk change revokes affected grants and resolver
entries; a policy-version change invalidates grants created under the old table.

The subtree model intentionally gives descendants of an approved root access to
the same granted references. Code running inside that subtree is therefore part
of the trusted consumer boundary.

## Policy review and consent

The production daemon owns one AppKit policy-and-authentication window. It
contains no values: it shows the logical credential references, stored risk,
delivery mechanism, requester/grant owner, emitter, recipient assurance,
destination, scope, and requested duration. A newly observed logical credential must be
classified as low, standard, high, or critical. Acceptance of a weak
compatibility delivery is a separate, initially unchecked decision rather than
part of the classification.

That window creates a fresh `LAContext`, pairs it with Apple's embedded
`LAAuthenticationView`, and starts Touch ID as soon as the rendered panel is
visible—there is no preliminary button or Enter-key gate. Policy controls remain
editable while Touch ID is active. On biometric success the daemon freezes the
exact visible choices and returns only that value-free snapshot to the agent
while retaining the evaluated context. The agent applies the authoritative risk
policy before persisting a choice, releasing a value, or handing out the context;
a denial closes and invalidates the session. The localized reason carries the
bounded requested details as defense in depth, while the trusted window is the
authoritative display of the selected risk and delivery. Dynamic text is bounded
and control, newline, and bidirectional-formatting characters are neutralized.

Approval returns the evaluated context to the cache read so a cold cached value
or cold native-store key can be unlocked by the same biometric action. Editing
a native file is a separate exact-launcher operation that always asks for fresh
Touch ID and displays that every key in the named store will be exposed to the
editor. It does not create a reusable secret grant. Denial, unavailable
biometrics, or lockout fails closed. The shipping daemon has no runtime
auto-approval switch; automatic consent exists only in separate test
executables and injected test dependencies. A provider may still require its own
independent authorization—for example, the 1Password app can display a separate
account-access request—which csecd cannot merge into its window.

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

The delivery plan and consent UI distinguish a registered `broad_session` root
from an ordinary per-command root. Low and standard credentials can reuse a
compatible grant across sibling descendants. If policy rejects the broad plan,
the launcher retries with its ordinary narrow root; high-impact credentials do
not gain wider session authority. Grant TTLs, plan/policy digests, risk changes,
and live ancestry checks still apply independently of registration lifetime.

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
`csecd` separately receives a digest-bound approval request, evaluates current
risk policy, obtains fresh Touch ID, resolves the exact reference set, renders
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
replaces each with a tiny strict-JSON `*.csec` sidecar naming its `csec://` value.
`csec exec` scans the project subtree for those sidecars and, when any are
present, drives the same root-helper launch with symlink-delivered bindings: the
helper materializes each value into tmpfs exactly as above, and the launcher — at
ordinary user privilege, never the helper — installs a symlink from each file's
original path into that tmpfs and removes it on exit. A reference is one native
value whether it holds a short token or a whole binary file; the storage tier
(editable document vs. blob) is invisible at the reference. Because a sidecar
lives in a hostile directory, csecd binds each value to the project-relative path
its blob recorded at import, so a planted or moved sidecar fails closed; the
symlink itself is a confidentiality-only surface that same-uid malware can
replace, an accepted integrity limitation.

### Environment compatibility

`csec exec` resolves environment values that are provider references and accepts
explicit `--set NAME=<reference>` assignments. It then places plaintext in the
child's initial environment. This works with unmodified tools, but macOS process
inspection can expose that original environment to unrelated same-UID
processes. Risk policy treats this as weak compatibility delivery: low risk is
allowed, standard risk requires a separate 30-day compatibility acceptance, and
high or critical risk is rejected before cache/provider resolution because the
generic complete consumer is unverified. The weak mechanism alone is not the
integrity failure. Output-guard configuration is part of both the delivery-plan
and policy digests but does not make the environment private.

When output policy is active, `csec` remains as the process supervisor and uses
a child PTY or pipes. Terminal output is guarded by default. Non-terminal output
remains byte-exact with a warning unless `--redact-output=always` is selected.
`--redact-output=never` is an explicit bypass.

### Raw output

`csec get` writes requested plaintext to standard output in three explicitly
modelled shapes: interactive terminal output, a shell-delegated pipe, or an
ordinary persistent plaintext file. In every shape, the signed launcher records
its real direct parent's PID, process start time, canonical executable identity,
signature metadata, and writable-path assurance separately from signed `csec`,
which remains the byte emitter. The daemon independently recomputes that parent
identity and roots a digest-bound subtree grant there. It repeats the
PID/start-time/ancestry/executable check immediately after approval and before
provider resolution, and `csec` checks the parent incarnation again immediately
before output. Consecutive compatible gets from that same live shell can reuse
the risk-capped grant; a different shell process cannot.

For a pipeline, the reader is normally a sibling process and cannot be recovered
or authenticated from the write descriptor. The plan and review therefore name
the shell as requester/grant owner, `csec` as emitter, and an **unverified pipe
reader** as recipient. Command substitution is the same shell-delegated pipe
shape. The pipe itself expresses user intent, so no second unsafe CLI flag is
required, but a new exact plan still requires normal trusted review and consent.

When `fstat(STDOUT_FILENO)` identifies a regular file, the plan instead declares
`named_plaintext_file` delivery to `persistent_plaintext_file` with an
`ordinary_persistent_file` recipient. No pathname is resolved, logged, or sent
to the daemon. The trusted review warns that plaintext persists, may be readable
by same-UID processes, and can be copied, synchronized, backed up, or accessed
later outside csec's control; it recommends `csec exec-file`. The shell can
create or truncate the target before launching csec, but denial occurs before
provider resolution and csec writes no plaintext unless approval succeeds.

Terminal, pipe, and ordinary-file shapes have different canonical plan and
policy digests. Compatibility acceptance is additionally keyed by mechanism,
destination, descendant scope, emitter/requester assurance, and recipient
assurance, so one shape cannot silently authorize another.

### Native store editing

`csec edit <store>` asks `csecd` to begin a caller-bound edit session, requesting
30 minutes but accepting the risk-policy cap (15 minutes for high and 5 minutes
for critical). After Touch ID, the complete strict-JSON document crosses the
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
workspace cannot be removed. Risk policy allows this mode for low-risk stores,
requires a separate compatibility acceptance for standard-risk stores, and
rejects it for high and critical stores because an arbitrary external editor is
an unverified complete consumer. A risk change revokes an open edit session,
and commit recomputes the policy binding before writing.

The built-in editor still authorizes the user and AppKit/input stack to see the
plaintext; copying, screenshots, accessibility/screen-capture privileges, or a
compromised authorized process remain outside the boundary.

## Output redaction and AI hooks

For one supervised `csec exec` launch, the launcher builds redaction rules from
the values it resolved. It replaces exact values and supported canonical
base64, base64url, percent-encoded, and JSON-escaped representations before
forwarding owned stdout, stderr, or PTY bytes. Matches spanning read boundaries
are handled. Values shorter than eight bytes are excluded unless explicitly
enabled. Opaque labels are the default; reference-shaped labels deliberately
expose reference metadata.

`csecd` also keeps a memory-only registry of values released during its current
lifetime. `csec tool-exec --destination ai` opens a caller-bound streaming
session before launching a command and sends each output chunk to the daemon.
Scanner loss stops forwarding and terminates the child. Generated Claude Code
and Codex PreToolUse adapters rewrite Bash commands through this broker when the
user installs their configuration fragment.

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
daemon registers `op://` when the verified official 1Password CLI is installed
and registers `csec://` when its provisioned Keychain group is usable. A single
request, language-client call, or `csec exec` launch can contain both schemes.

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

## Risk policy

`RiskPolicyV2` is a deterministic pre-resolution decision table. Logical
credentials are grouped independently of provider: 1Password fields share their
vault/item judgment, and native references share their store judgment. The
production judgment backend stores only agent-HMAC-derived account, credential,
and member identifiers in a ThisDeviceOnly Keychain item; raw references and
secret values are not persisted there. Unsigned development builds use an
in-memory backend.

Unknown credentials have an effective high floor and require classification in
the agent-owned review. Low, standard, high, and critical cap access at 12 hours,
4 hours, 15 minutes, and 5 minutes respectively. Destination evidence may raise
the effective level: production and unknown destinations floor at high, while
staging and AI floor at standard. High/critical disallow AI destinations and
require a verified, independently protected, or sealed complete consumer;
critical also normally requires exact-process scope. The narrow exception is
signed `csec get`: its independently verified direct-parent shell may own a
subtree grant while signed `csec` remains the emitter and the terminal, pipe, or
file recipient is described separately. Generic Ruby, Node.js, shell, and
checkout-driven complete consumers conservatively report unverified assurance
even when their executable is root-owned.

The agent loads judgments and any exact delivery-shape acceptance before
consulting a cache or provider. Low compatibility delivery follows normal
approval. Standard requires a separate compatibility acceptance, which can be
remembered for 30 days. High and critical show stronger warnings, require fresh
Touch ID, and do not persist that acceptance: only the resulting 15-minute or
5-minute exact live grant can be reused. A weaker choice is not itself an
integrity failure, but malformed metadata, requester verification failure,
stale/reparented/replaced processes, invalid scope/assurance, denial, or required
authentication failure remain hard pre-resolution failures.

Compatibility acceptance matches the mechanism, destination, descendant scope,
emitter assurance, requester assurance, and recipient assurance. The policy
version is 2, which invalidates old judgments, grants, and compatibility
acceptances rather than broadening their prior meaning. `csec risk
inspect|classify|raise|forget` operates on this metadata without resolving a
value. `raise` is monotonic; a downgrade or forget requires an additional
biometric authentication. Any change clears weak acceptances when appropriate,
revokes matching grants and native edit sessions, and invalidates known resolver
entries.

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
repair for any authorized consumer's ability to disclose a value. Risk policy
uses warnings, fresh authentication, shorter grants, assurance, and scope rather
than treating weakness alone as an irrevocable prohibition. It still rejects
unverified complete consumers and invalid broad scopes; approving a compatibility
shape does not strengthen that path or make an authorized recipient safe.
Native ciphertext and its rollback record protect durable data, while decrypted
editor buffers and values released to consumers remain subject to the
authorized-consumer boundary. The precise attacker capabilities and limits are
recorded in
[`docs/threat-model.md`](docs/threat-model.md).
