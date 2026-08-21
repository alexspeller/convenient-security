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

### Ruby heap delivery

Pure Ruby does not trust the agent socket. It invokes the fixed root-owned
signed bridge, which uses a scrubbed environment and close-on-exec private
pipes. The agent verifies the bridge and its actual direct Ruby parent; the
bridge rechecks the parent before writing its response. Plaintext therefore
arrives in the Ruby heap without appearing in the initial environment or argv.

This protection ends if the application assigns the returned value to `ENV`,
passes it in argv, writes or logs it, sends it over an unintended connection, or
loads hostile code into the same Ruby process.

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
session is bound to that launcher's kernel PID/start time, expires after 30
minutes, and rejects stale concurrent saves. The built-in AppKit editor creates
no named plaintext file and disables automatic spelling, replacement, data
detection, and window restoration. Plaintext nevertheless exists in launcher
and AppKit memory. User-initiated copying, screenshots, input methods,
accessibility/screen-capture authority, and compromise of the authorized UI
process remain outside the boundary. There is no key export or recovery path;
loss of the Mac or Keychain record is permanent data loss.

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
  masking does not make that environment private. Risk-policy source exists but
  is not enforced by the shipping request handler.
- `csec get` prints plaintext to standard output.
- The Ruby client returns an ordinary mutable `String` to application code.
- Claude Code and Codex hook fragments are opt-in user configuration and cover
  Bash command tool calls only.

## Required deployment posture

All security claims require a Developer-ID-signed, hardened, notarized,
provisioned build with the exact product identities, the restricted keychain
access group, no `get-task-allow`, no dangerous Hardened Runtime exception
entitlements, and SIP enabled. The production startup self-audit refuses to run
when its required posture is absent or when neither the native store nor a
verified official 1Password CLI is available.

## Irreducible boundary

Once an authorized consumer receives plaintext, it can use or disclose it. The
system narrows release to a human-approved reference set and process scope; it
cannot make compromised consumer code safe. Secret rotation and revocation also
remain provider operations rather than automatic consequences of a redaction
event.
