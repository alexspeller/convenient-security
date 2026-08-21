# Wire protocols

Convenient Security has two local protocols:

1. protocol v2 between the signed `csec` launcher/bridge and `csecd`; and
2. a one-shot private-pipe protocol between a language client and `csec bridge`.

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
      "native_encrypted_store"
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
- a caller root, or—only for `csec bridge`—that a requested direct parent is the
  launcher's real PPID with the same process start time; and
- that any existing grant has the same delivery-plan digest and a live
  kernel-verified ancestry relationship.

The grant records the request ID, plan digest, peer PID version/CDHash, and
planned executable. The implemented risk-policy model is not consulted by the
shipping request handler and no risk snapshot or policy digest is stored in a
live grant. Generic piped `csec get` cannot identify a shell-pipeline reader, so
its delivery plan declares an unknown, unverified destination and uses an
exact-caller grant; it never broadens the grant to the parent shell.

Success echoes the request nonce:

```json
{
  "version": 2,
  "requestID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "values": {"op://Vault/Item/field":"…"}
}
```

The client rejects a missing/mismatched nonce or a values map whose keys differ
from the requested reference set.

## Active-output redaction sessions

This protocol supports pre-recipient scanning for `csec tool-exec`. It is not a
general secret-query API. When a v2 access succeeds, `csecd` registers only the
values it actually released, in memory, until the delivery TTL. It does not
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
  "streams": ["stdout", "stderr", "terminal"]
}
```

The current implementation accepts only `ai_tool`, rejects duplicate/unknown
streams, permits at most 32 live sessions, and expires a session after five idle
minutes. The response contains a fresh opaque session UUID plus counts of
eligible values and values skipped for being shorter than the eight-byte
automatic-matching floor. It never contains the registry values.

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
  "store": "development"
}
```

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
30 minutes, and retains the biometric context needed to authenticate the
Keychain pointer update. At most eight sessions exist at once. The document is
limited to 1 MiB and 1024 unique, path-safe keys with string values. The signed
launcher validates and canonicalizes it locally; the daemon independently
validates it again.

Save sends `commit_native_store_edit` with the session UUID and bounded `Data`.
Success reports only the new positive `generation` and `secretCount`. Invalid
JSON returns `invalid_store_document` without consuming the session so the UI
can correct it. A save whose baseline is no longer current returns
`edit_conflict`. `cancel_native_store_edit` removes a caller-owned session and
returns no document.

The plaintext document crosses only the existing mutually authenticated socket
and then exists in the daemon and signed launcher's heaps. It is intentionally
never put in argv, the environment, protocol error text, logs, or a temporary
file. The protocol does not make the authorized launcher, AppKit editor, or
user-directed clipboard and screen actions confidential.

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
