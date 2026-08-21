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
output redaction.

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
  1Password CLI with an allowlisted environment. It is the only provider adapter
  registered by the shipping daemon.
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
can be unlocked by the same biometric action. Denial, unavailable biometrics,
or lockout fails closed. The shipping daemon has no runtime auto-approval
switch; automatic consent exists only in separate test executables and injected
test dependencies.

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

`SecretResolver` dispatches references by scheme; the shipping daemon registers
only `op://`. It checks the warm in-process cache, then—only when a just-approved
biometric context is present—the data-protection keychain, then the provider.
Resolved provider values repopulate both cache tiers.

The keychain stores one `kSecClassGenericPassword` item per canonical reference
with `kSecUseDataProtectionKeychain`, the provisioned application access group,
`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, and `.biometryCurrentSet`.
Re-enrolling biometrics invalidates the item. The warm tier and grant table are
memory-only.

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

The startup self-audit fails production startup when the required daemon or
provider posture is absent. The signed-package verification procedure is in
[`packaging/README.md`](packaging/README.md).

## Current security boundary

The strongest implemented delivery is the Ruby private-pipe path into a clean,
hardened consumer heap. The environment launcher is a compatibility feature
with an acknowledged same-UID disclosure channel. Output redaction is an egress
safeguard, not a repair for that channel. The precise attacker capabilities and
limits are recorded in [`docs/threat-model.md`](docs/threat-model.md).
