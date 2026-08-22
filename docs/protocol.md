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
Security.framework resolves the live `SecCode` from that token.

- `csecd` accepts only Team ID `8RS6GD89Y7` with signing identifier
  `com.alexspeller.convenient-security.csec` and the compiled Developer ID
  requirement.
- `csec` accepts only the same Team ID with signing identifier
  `com.alexspeller.convenient-security`.
- Both require the current login UID. An unsigned or replacement process is
  rejected before a request is read or written.
- Immediately before sending **each** response, `csecd` resolves the peer again
  and requires the same audit token and valid launcher code. An image change
  during consent/provider resolution or a streaming session therefore cannot
  receive the response.

Fake peers are possible only through explicit test constructors in debug/test
executables. A shipping environment variable cannot relax trust.

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
      "risk_policy_v1",
      "risk_management",
      "native_editor_policy",
      "registered_session_roots",
      "credential_protocols",
      "inherited_file_descriptors",
      "protected_regular_files"
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

## Access v2

An access request has a fresh UUID nonce, exact references, a bounded human
reason, positive TTL (currently at most 86,400 seconds), and a complete delivery
plan:

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

The launcher sends only a SHA-256 command digest, not argv, where a command must
be bound. Plaintext is forbidden in the plan and all metadata.

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

The Ruby bridge and generic `csec exec` conservatively report `unverified`
consumer assurance even when `/usr/bin/ruby`, a shell, or another executable is
root-owned: scripts, gems, plugins, configuration, and the checkout remain
user-writable. Only a dedicated verifier/root launcher may assert an
independently protected whole consumer context.

Before resolution, the agent verifies:

- exact protocol version, UUID, field/count/TTL bounds (including 4 KiB per
  reference), absolute bounded executable metadata, canonical digest shapes,
  supported output-matcher version, and plan/TTL agreement;
- a recomputed canonical plan digest;
- that the socket peer is the verified launcher;
- a caller root; only for `csec bridge`, a requested direct parent that is the
  launcher's real PPID with the same process start time; or a registered-session
  ID whose live PID/start-time root is an ancestor of the caller in the same
  audit session;
- for `credential_protocol`, that the plan's consumer executable is the
  helper's current direct parent's canonical executable path; and
- the current logical-credential risk judgment, delivery acceptance, mechanism,
  consumer assurance, destination, descendant scope, and policy-capped TTL; and
- that any existing grant has the same delivery-plan and policy-decision digests
  plus a live kernel-verified ancestry relationship.

The grant records the request ID, plan digest, peer PID version/CDHash, and
planned executable, together with the opaque credential key, effective risk,
policy version/digest, and output policy. A risk change revokes matching grants;
reuse also recomputes the policy binding, so stale authorization fails closed.
Generic piped `csec get` cannot identify a shell-pipeline reader, so its delivery
plan declares an unknown, unverified destination and uses an exact-caller grant;
the high destination floor currently rejects that path before resolution.

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
access performs a fresh ancestry walk from the authenticated caller to the
recorded PID/start-time pair. A malformed, stale, forged, copied-across-tree, or
cross-audit-session ID is rejected as `invalid_request`, with no fallback.

Risk policy may reject broad scope before resolution. In that case only, the
product launcher may issue a new access request and plan using its ordinary
caller root. This preserves per-command treatment for high-impact credentials;
the broad and narrow plans have different digests and cannot share a grant.

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
live Security.framework code before its body is read, then rechecked before the
response:

- exact signed `csec` may use `prepare`, `start`, `status`, `signal`, `cancel`,
  and `health`;
- exact signed `csecd` alone may use `approve`; and
- both must be non-root peers, while clients require an exact signed helper
  whose effective UID is root.

Each request uses a fresh connection and one bounded length-prefixed JSON
frame. The listener admits at most 32 concurrent handlers and applies five-
second I/O timeouts; the coordinator retains at most 128 launch records. Only
`prepare` carries descriptors: exactly cwd, stdin, stdout, and stderr in that
order through `SCM_RIGHTS`. Every other operation must carry zero descriptors.

The launch sequence is:

1. `csec` constructs and validates `ProtectedLaunchPlan`, including its own
   PID/start time/UID/audit session, exact executable metadata, complete argv,
   sanitized environment, one to sixteen file bindings, delivery-plan/output-
   guard binding, TTL/hard-TTL flag, and PTY choice. It sends `prepare` with the
   canonical SHA-256 plan digest and four descriptors.
2. `csec-rootd` revalidates the plan, caller identity, executable claim, and
   descriptors, retains the descriptors, and returns a fresh rendezvous nonce
   plus the same digest in state `prepared`. An unapproved preparation expires
   after 60 seconds or launcher death.
3. `csec` submits `approve_protected_launch` to `csecd`. The outer request UUID
   must equal the nested approval UUID. The nested request repeats the nonce,
   complete launch plan/digest, and an ordinary v2 access request derived from
   exactly that plan.
4. `csecd` verifies that the authenticated caller is the launcher recorded in
   the plan, evaluates `capability_gid_file` policy with no grant reuse, obtains
   fresh consent, resolves the exact reference set, and renders each payload.
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
code with generic text except the bounded expired-rendezvous distinction.
Relative paths are fixed by product construction and independently reject
absolute paths, traversal, prefix collisions, duplicates, environment
collisions, and loader/product controls.

## Value-free risk management

Only a verified product launcher may inspect or mutate risk metadata. The
caller supplies one reference so `csecd` can derive its logical group; the agent
does not resolve the provider value. For example:

```json
{
  "version": 2,
  "type": "risk",
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "operation": "classify",
  "reference": "op://Vault/Item/field",
  "level": "standard"
}
```

Operations are `inspect`, `classify`, `raise`, and `forget`. `inspect` and
`forget` omit `level`; `classify` and `raise` require one of `low`, `standard`,
`high`, or `critical`. `raise` cannot lower the current effective level.
Mutations pass through an agent-owned value-free review. A classification that
lowers the effective floor, and every `forget`, additionally requires Touch ID.

The response contains `riskInspection`: provider kind, stored and effective
levels, decision/review timestamps, policy version, known member count, whether
the supplied reference is in the recorded scope, and any mechanism/assurance
acceptances with their review deadlines. It contains neither secret values,
opaque credential identifiers, nor other raw member references. A successful
change revokes matching live grants, resolver entries known in memory, and open
native-store edit sessions before returning the updated inspection.

## Active-output redaction sessions

This protocol supports pre-recipient scanning for `csec tool-exec` and
`csec exec-file`. It is not a general secret-query API. When a v2 access
succeeds, `csecd` registers only the values it actually released, in memory,
until the delivery TTL. It does not
unlock dormant cache/provider entries to populate the registry. Registry state
is lost on agent restart, and an entry expires at its delivery TTL even when the
consumer remains alive.

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
streams, permits at most 32 live sessions, and expires a session after five idle
minutes. `includeShortValues` opts into matching below the normal eight-byte
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
time. Separate streams cannot combine prefixes. `finish: true` flushes one
stream's withheld prefix and seals that stream. Before processing each chunk,
the agent adds newly registered values to every still-live streaming matcher;
it deliberately does not remove an old pattern mid-stream.

The response echoes the request nonce and returns only already-redacted `Data`
plus `[OutputRedactionMatch]` metadata. A match identifies an opaque ID and the
representation (`exact`, canonical base64/base64url, percent-encoded, or JSON
escaped), never the matching bytes or vault reference. `end_output_redaction`
removes the complete caller-bound session. Disconnect/idle cleanup is bounded;
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

`mode` is `built_in_memory` or `external_temporary_file`. External mode must
also include the canonical absolute `externalEditorPath`; it is modeled as an
unverified named-plaintext-file consumer. Built-in mode rejects that field and
binds delivery to the verified `csec` launcher. The risk policy is evaluated
before Touch ID or decryption. External mode is allowed at low risk, requires a
separate acceptance at standard risk, and is forbidden at high/critical risk.

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

The session is bound to the launcher's kernel PID and start time, lasts at most
the policy-capped authorization (30 minutes requested, 15 minutes at high, and
5 minutes at critical), and retains the biometric context needed to authenticate
the Keychain pointer update. At most eight sessions exist at once. The document
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
`provider_unavailable`, `resolution_failed`, `native_store_unavailable`,
`invalid_store_document`, `edit_session_expired`, `edit_conflict`, and
`internal_error`.

The decoder recognizes a v1 flat `access` request only to return
`upgrade_required`. Production never invents a secure plan for v1. Fake agents
may opt into v1 solely for migration tests.

## Ruby/private bridge protocol

Ruby cannot natively perform the Security.framework peer check, so the gem does
not connect to `agent.sock`. It executes
`/Library/Application Support/ConvenientSecurity/bin/csec bridge` by fixed
absolute path with a scrubbed environment and private stdin/stdout pipes. The
signed package installs that copy and every controlling directory root-owned
and non-writable by the login user; `/Applications` alone is not sufficient
because its `admin` group can replace directory entries.

Ruby marks every parent-side pipe endpoint close-on-exec, so replacing the Ruby
image closes the response channel in the kernel.

The request is one framed JSON object containing only `version`, `references`,
`reason`, and `ttlSeconds`. `csec bridge` refuses a terminal or regular-file
stdin/stdout, derives its Ruby parent from `getppid()` plus kernel process start
time and executable path, submits a v2 `direct_heap` plan, then rechecks all
three before output so parent re-exec cannot change the reviewed consumer. It
writes one framed `BridgeResponse`; a failure uses the same value-free typed
failure shape.

The Ruby heap receives plaintext; the helper's argv and environment do not. If
application code assigns a returned value to `ENV`, launches a child with it,
or writes it elsewhere, that disclosure is outside the bridge boundary; see
[`threat-model.md`](threat-model.md#ruby-heap-delivery).
