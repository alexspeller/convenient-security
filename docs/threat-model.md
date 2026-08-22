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

### Process-scoped consent

New references require Touch ID. The grant root is verified from kernel process
ancestry and bound to its start time. Existing compatible grants cover only the
recorded references and process subtree until expiry. The grant table is
memory-only.

This limits which values the agent releases; it does not make every descendant
trustworthy. A process deliberately launched inside an approved subtree is part
of the authorized consumer boundary.

`csec session` makes that wider boundary explicit. The daemon records the
signed launcher's kernel PID, process start time, and audit session before the
launcher becomes the requested shell or command. Its inherited random ID is
non-secret and does not authorize anything by possession: each use must come
from the authenticated signed helper and pass a fresh ancestry walk to that
exact live process incarnation. Copying the ID to a sibling, racing PID reuse,
or inventing an ID fails closed. Low/standard grants may span descendants;
policy rejection retries only with the helper's ordinary per-command root, so a
high-impact credential does not inherit broad session scope.

### Risk policy and stale authorization

Before it consults a plaintext cache or provider, the daemon groups each
reference into a logical credential, loads only opaque value-free judgment
metadata, and evaluates the complete delivery plan. Unknown credentials require
classification in a daemon-owned window. Weak compatibility acceptance is a
separate decision. The selected risk, delivery, scope, destination, consumer
assurance, and policy-capped duration are summarized again in the OS Touch ID
prompt before any new choice is persisted.

Every grant is bound to the delivery-plan digest and the exact effective-risk,
policy-version, policy-decision, and output-policy snapshot. A raised or
forgotten classification revokes matching grants, known cache entries, and open
native edit sessions. Reuse recomputes the binding; expired metadata and a policy
version change fail closed. Protocol-v1 access is recognized only to return
`upgrade_required`, so an older or hand-written client cannot omit a plan to
select the legacy authorization path.

This policy rejects a weak delivery; it cannot turn an allowed environment,
named-file, raw-output, or authorized-consumer path into a confidentiality
boundary. The production Keychain stores HMAC-derived logical identifiers and
value-free metadata, not raw references or values.

### Ruby heap delivery

Pure Ruby does not trust the agent socket. It invokes the fixed root-owned
signed bridge, which uses a scrubbed environment and close-on-exec private
pipes. The agent verifies the bridge and its actual direct Ruby parent; the
bridge rechecks the parent before writing its response. Plaintext therefore
arrives in the Ruby heap without appearing in the initial environment or argv.

This protection ends if the application assigns the returned value to `ENV`,
passes it in argv, writes or logs it, sends it over an unintended connection, or
loads hostile code into the same Ruby process.

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
signed `csecd` may submit approval and file bytes. The prepared launch binds the
original launcher PID/start time/UID/audit session, exact executable metadata,
argv, sanitized environment, path mappings, output policy, TTL, and command
digest. Four stdio/cwd descriptors arrive only with prepare. A random nonce and
canonical plan digest bind the two independent requests; only the original
launcher audit token can consume them.

`csecd` does not return values to `csec` for this mechanism. It applies current
risk policy, requires fresh consent, resolves the exact set, renders bounded
payloads, and transmits them directly to the authenticated helper. The helper
revalidates plan/path/size constraints, uses descriptor-relative no-follow and
exclusive creation on verified bounded `nodev,nosuid,noexec` tmpfs, and closes
all unintended descriptors before exact-path `execve`. Its minimal binary does
not link providers, Keychain access, Touch ID, AppKit, or agent policy code.

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
session is bound to that launcher's kernel PID/start time, expires at the
risk-policy cap (at most 30 minutes), and rejects stale concurrent saves. The
default built-in AppKit editor creates no named plaintext file and disables automatic spelling, replacement,
data detection, and window restoration. Plaintext nevertheless exists in
launcher and AppKit memory. User-initiated copying, screenshots, input methods,
accessibility/screen-capture authority, and compromise of the authorized UI
process remain outside the boundary.

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

The named-file mode is available for low risk, separately reviewable for
standard risk, and forbidden for high/critical stores. Its actual editor path is
bound before review. The built-in signed editor is treated as a verified-product
heap consumer; high and critical policy shortens its session. Commit revalidates
the policy binding, so a risk change cannot leave an earlier edit authorization
usable.

There is no key export or recovery path; loss of the Mac or Keychain record is
permanent data loss.

### Output redaction

Supervised `csec exec` redacts eligible values from stdout, stderr, or a PTY that
it owns. `csec tool-exec` scans another command against `csecd`'s active-value
registry before returning output to an AI tool. Both handle split matches and a
bounded set of canonical encodings; the AI broker fails closed if scanning is
lost.

This prevents eligible bytes from crossing those specific supervised output
paths. It does not prevent the local read itself, detect every transformation,
or cover files, network writes, alternate descriptors, non-Bash AI tools, or
commands that bypass the optional hook. Registry entries are memory-only,
expire at delivery TTL, and disappear on daemon restart. The matching interface
also exposes a bounded equality oracle to callers able to execute the genuine
signed launcher.

## Explicitly exposed interfaces

- `csec exec` places plaintext in the child's initial environment. Output
  masking does not make that environment private. Policy allows this for low
  risk and by separate acceptance for standard risk; high/critical are rejected.
- `csec get` prints plaintext to standard output.
- The Ruby client returns an ordinary mutable `String` to application code.
- `csec creds aws` and `csec creds git` intentionally return plaintext over the
  credential consumer's private stdout pipe.
- `csec exec-fd` authorizes the launched process and any descendants retaining
  its descriptor to read the complete file payload.
- `csec exec-file` authorizes the complete capability-GID process tree to open,
  reopen, map, and copy its root-owned regular-file payloads until unlink; open
  descriptors can remain readable afterwards.
- Claude Code and Codex hook fragments are opt-in user configuration and cover
  Bash command tool calls only.

## Required deployment posture

All security claims require a Developer-ID-signed, hardened, notarized,
provisioned build with the exact product identities, the restricted keychain
access group, no `get-task-allow`, no dangerous Hardened Runtime exception
entitlements, and SIP enabled. Protected-file claims additionally require the
exact signed helper under `/Library/PrivilegedHelperTools`, its root-owned and
non-writable system LaunchDaemon plist, the verified bounded tmpfs mount, and a
passing signed-device matrix. The production startup self-audit refuses to run
when its required posture is absent or when neither the native store nor a
verified official 1Password CLI is available.

## Irreducible boundary

Once an authorized consumer receives plaintext, it can use or disclose it. The
system narrows release to a human-approved reference set and process scope; it
cannot make compromised consumer code safe. Secret rotation and revocation also
remain provider operations rather than automatic consequences of a redaction
event.
