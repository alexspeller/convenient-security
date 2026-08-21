# Convenient Security — current architecture

This document describes the behavior implemented in the repository. Security
claims apply only to a hardened, notarized, provisioned release build on macOS
with SIP enabled; unsigned development builds deliberately run without the
persistent keychain cache and with test-only trust seams compiled in.

## Scope

Convenient Security protects secret values from unrelated, non-root processes
running as the same login user. It provides per-reference Touch ID consent,
process-scoped grants, a code-identity-gated at-rest cache, heap delivery for an
integrated Ruby client, an environment compatibility launcher, and exact-value
output redaction. It can resolve from the official 1Password CLI and from
device-bound native encrypted files.

It does not protect a value from root, from code already executing inside an
authorized consumer, from a consumer the user deliberately launches, or from a
user who approves a misleading request.

## Components

- **`csecd`** is the resident Swift agent. It authenticates socket peers, obtains
  Touch ID consent, owns the grant table, resolves references through provider
  adapters, manages the keychain cache, and holds the active-value registry used
  for output redaction.
- **`csec`** is the signed CLI, bridge, launcher, output supervisor, and AI
  command broker. Its commands are listed by `csec help`.
- **`OnePasswordAdapter`** invokes a verified installation of the official
  1Password CLI with an allowlisted environment.
- **`NativeEncryptedFileProvider`** owns `csec://` parsing, strict JSON,
  AES-256-GCM encryption, per-store biometric Keychain records, immutable
  ciphertext versions, rollback detection, and bounded edit sessions. Both
  providers can be registered at once.
- **The Ruby client** invokes the independently protected `csec bridge` binary
  and receives framed values through a private pipe. It does not connect to the
  agent socket itself.

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
time, the approved references, reason, expiry, and the originating protocol-v2
delivery binding.

The daemon obtains the caller PID from the kernel rather than JSON. A grant is
usable only when kernel parent traversal reaches the recorded root with the same
start time, which prevents PID reuse from reviving it. References already
covered by a compatible live grant are returned without another prompt. Adding
a reference prompts for the delta and then expands the grant. Grants expire by
TTL and disappear when the daemon exits; orphaned descendants no longer satisfy
the ancestry check.

The subtree model intentionally gives descendants of an approved root access to
the same granted references. Code running inside that subtree is therefore part
of the trusted consumer boundary.

## Consent

The production daemon creates a fresh `LAContext` for every request that adds
references and evaluates Touch ID without password fallback. The localized
reason shown by macOS includes the requesting process description, exact new
references, caller-supplied purpose, and duration. Dynamic text is bounded and
control, newline, and bidirectional-formatting characters are neutralized.

Approval returns the evaluated context to the cache read so a cold cached value
or cold native-store key can be unlocked by the same biometric action. Editing
a native file is a separate exact-launcher operation that always asks for fresh
Touch ID and displays that every key in the named store will be exposed to the
editor. It does not create a reusable secret grant. Denial, unavailable
biometrics, or lockout fails closed. The shipping daemon has no runtime
auto-approval switch; automatic consent exists only in separate test
executables and injected test dependencies.

## Delivery

### Ruby heap delivery

The Ruby gem sends references, reason, and TTL to the fixed root-owned
`/Library/Application Support/ConvenientSecurity/bin/csec` bridge. The helper
uses a scrubbed environment and private close-on-exec pipes. It verifies the
direct Ruby parent PID, start time, and executable path before requesting and
again before returning a response. Plaintext reaches a Ruby `String`, not Ruby's
initial environment or argv.

Assigning that string to `ENV`, interpolating it into a command, logging it, or
loading hostile code into the Ruby process is outside this protection.

### Environment compatibility

`csec exec` resolves environment values that are provider references and accepts
explicit `--set NAME=<reference>` assignments. It then places plaintext in the
child's initial environment. This works with unmodified tools, but macOS process
inspection can expose that original environment to unrelated same-UID
processes. The implemented risk-policy model is not consulted by the shipping
access path, so `csec exec` does not reject sensitive references according to a
risk classification.

When output policy is active, `csec` remains as the process supervisor and uses
a child PTY or pipes. Terminal output is guarded by default. Non-terminal output
remains byte-exact with a warning unless `--redact-output=always` is selected.
`--redact-output=never` is an explicit bypass.

### Raw output

`csec get` writes the requested plaintext to standard output. It is an explicit
raw-output interface intended for a deliberate receiver; shell history,
pipelines, redirection targets, and downstream commands remain the caller's
responsibility.

### Native store editing

`csec edit <store>` asks `csecd` to begin a caller-bound, 30-minute edit
session. After Touch ID, the complete strict-JSON document crosses the mutually
authenticated socket into the signed launcher. A built-in AppKit `NSTextView`
edits it without a plaintext filesystem object. Automatic spelling, grammar,
replacement, data detection, smart punctuation, and window restoration are
disabled. Save validates and canonicalizes the document in both the launcher
and daemon before the daemon encrypts it; Cancel tells the daemon to discard the
session. Sessions are bound to the launcher's kernel PID and start time, capped
at eight, and a stale concurrent editor cannot overwrite a newer generation.

There is no arbitrary `$EDITOR` mode. Ordinary editor contracts require a named
plaintext file and commonly add swap, backup, or autosave copies, which would
reopen the same-UID read channel this store is intended to close. The built-in
editor still authorizes the user and AppKit/input stack to see the plaintext;
copying, screenshots, accessibility/screen-capture privileges, or a compromised
authorized process remain outside the boundary.

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

## Resolution and cache

`SecretResolver` dispatches each reference independently by scheme. The shipping
daemon registers `op://` when the verified official 1Password CLI is installed
and registers `csec://` when its provisioned Keychain group is usable. A single
request, Ruby call, or `csec exec` launch can contain both schemes.

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

## Risk-policy code

The source contains risk levels, opaque keychain-backed judgment records,
delivery-acceptance records, and a deterministic `RiskPolicyV1` decision table.
They are covered by self-tests but are not called by the shipping agent's access
handler and are not represented in live grants. They provide no runtime
restriction or authorization in the current product.

## Security requirements

The shipped agent and launcher require all of the following:

- Developer ID signing by the compiled team and exact signing identifiers;
- hardened runtime and notarization;
- an embedded provisioning profile authorizing the team-prefixed keychain
  access group for the daemon;
- no `get-task-allow` and no Hardened Runtime exception entitlements for library
  validation, DYLD environment variables, JIT or unsigned executable memory,
  executable-page protection, or debugging; and
- SIP enabled on the host.

The startup self-audit fails production startup when the required daemon posture
is absent. It registers only providers whose own requirements are satisfied and
refuses to start if neither the native store nor verified 1Password CLI is
available. The signed-package verification procedure is in
[`packaging/README.md`](packaging/README.md).

## Current security boundary

The strongest implemented delivery is the Ruby private-pipe path into a clean,
hardened consumer heap. The environment launcher is a compatibility feature
with an acknowledged same-UID disclosure channel. Output redaction is an egress
safeguard, not a repair for that channel. Native ciphertext and its rollback
record protect durable data, while the decrypted editor buffer and values
released to consumers remain subject to the authorized-consumer boundary. The
precise attacker capabilities and limits are recorded in
[`docs/threat-model.md`](docs/threat-model.md).
