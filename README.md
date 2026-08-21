# convenient-security

A resident, hardened macOS agent that lets local tools and long-running agent
sessions use secrets from a backing secret manager (1Password today) **without**
scattering those secrets across the environment of every process on the machine.

The name is the thesis: security people actually keep switched on because it
isn't in the way. One coarse provider unlock, then per-secret human consent with
Touch ID and an at-rest cache so you aren't re-prompted all day. Integrated
clients receive values in their process heap; the environment compatibility
launcher is explicitly documented as a weaker path.

## Status

The implemented system includes mutual live code-identity checks, protocol-v2
delivery-plan binding, per-reference Touch ID consent, subtree grants, a
Secure-Enclave-gated keychain cache, a signed Ruby heap-delivery bridge, typed
value-free failures, and a startup security audit.

`csec exec` resolves references into a child's initial environment. That is an
explicitly exposed compatibility path: unrelated same-UID processes can inspect
the original environment. When output policy is active, `csec` supervises the
child and masks eligible values in owned stdout/stderr pipes or a PTY, but
masking does not repair the environment disclosure. `csec tool-exec` provides a
fail-closed, pre-recipient output scanner for AI Bash commands using the
daemon's memory-only registry of released values. Claude Code and Codex hook
adapters generate opt-in configuration for that broker.

The Developer-ID-signed, hardened, provisioned `.app` path has run with real
1Password values and Touch ID on physical hardware. The repository also
contains the `.pkg` build, signing, notarization, and root-owned bridge install
pipeline; its required signed-machine checks are documented in
[`packaging/README.md`](packaging/README.md). See [`DESIGN.md`](DESIGN.md) for
the complete current architecture and limitations.

## Why

The ambient alternative — a broker that hands any same-uid process any secret on
request — means a single piece of user-level malware can read your entire vault
silently. This project draws the line at **per-secret human consent**, and makes
the *at-rest* and *in-use* footprint of a secret as small as macOS allows:

- **Protected in-use delivery goes to the heap, not the environment.** The Ruby
  client uses a signed bridge and private pipe. `csec exec` remains a labeled
  compatibility exception because its child environment is readable. (See
  [`docs/threat-model.md`](docs/threat-model.md).)
- **At-rest secrets live in a Secure-Enclave-gated cache** whose confidentiality
  rests on unforgeable *code identity* — the same model 1Password itself uses.
- **Only the agent talks to the secret manager**, behind a provider adapter, so
  backends are pluggable.

## Layout

| Path | What |
|------|------|
| `DESIGN.md` | Current architecture, guarantees, and limitations. |
| `docs/threat-model.md` | What same-uid malware can/can't read, and why this is safe. |
| `docs/protocol.md` | The unix-socket wire protocol. |
| `docs/development.md` | Toolchain baseline, CI entry point, and signed release gates. |
| `agent/` | Swift package: the `csecd` daemon, the `csec` launcher, and the core. |
| `agent/Sources/ConvenientSecurity/` | Provider-agnostic core (refs, grants, cache, resolver, protocol). |
| `agent/Sources/OnePasswordAdapter/` | All 1Password-specific code. |
| `clients/ruby/` | Heap-fetch client gem (for Rails and other Ruby consumers). |
| `packaging/` | Signing / notarization / `.pkg` pipeline + install. See [`packaging/README.md`](packaging/README.md). |

## Building

```sh
bin/ci                 # Swift build/self-tests/e2e + Ruby unit/cross-stack tests
```

See [`docs/development.md`](docs/development.md) for the pinned CI runner and
the separate signed physical-machine gate.

## Licence

Copyright 2026 Stateful Ltd. The source is available under the
[Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md)
(`FSL-1.1-ALv2`). The licence permits use, modification, and redistribution for
non-competing purposes; each released version becomes available under Apache
License 2.0 two years after that version is made available. This is a Fair
Source licence, not an OSI-approved open-source licence.

Security vulnerabilities should be reported privately as described in
[`SECURITY.md`](SECURITY.md). The project is not currently accepting external
code contributions; see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Using it

```sh
swift run csecd                              # start the agent (Touch ID consent)
swift run csec get 'op://Vault/Item/Field'   # fetch one secret to stdout
swift run csec exec -- bin/rails s           # run a tool with op:// env values resolved
swift run csec exec --redact-output=always -- bin/rspec # mask captured stdout/stderr too
swift run csec tool-exec --destination ai -- /usr/bin/pgrep -fl rubocop
swift run csec hook-config claude             # JSON fragment for ~/.claude/settings.json
swift run csec hook-config codex              # JSON fragment for ~/.codex/hooks.json
```

`csecd` authenticates peers via `LOCAL_PEERTOKEN`, tracks subtree grants, and
prompts for **Touch ID** on each newly-requested reference — one touch covers
the whole process subtree for the grant's duration. The shipping agent has no
runtime consent bypass; automated tests use the separate `cs-fake-agent`.
Release `csec` and `csecd` mutually require their exact Team ID and signing
identifiers before either side exchanges request metadata. SwiftPM debug builds
use compile-time-only relaxed trust so local development remains possible; that
branch is absent from release binaries.
`csec exec` resolves any `op://` value in the environment in place (like
`op run`) and injects it into the child. The agent listens at
`…/convenient-security-<uid>/agent.sock` in the per-user temp dir.

Output masking defaults to `--redact-output=tty`: terminal streams are relayed
through a child PTY and guarded automatically, while non-terminal streams remain
byte-exact with an explicit warning. Use `always` when a human-readable pipe or
captured log may reach an AI tool, and `never` only when byte-exact output is
required. Replacements default to `[csec:secret-N]`; the opt-in
`--redact-output-label=reference` exposes the corresponding `op://` metadata.
Values shorter than eight bytes are excluded with a warning unless
`--redact-short-values` explicitly accepts likely false positives.

`tool-exec` is the pre-recipient form for AI shell commands. It opens a
caller-bound scanner in `csecd` before launching the child, relays each output
chunk through the daemon, and fails closed if scanning cannot start or stops
working. The daemon matches values actually released during its current
lifetime; it does not unlock dormant vault/cache entries to build the matcher,
and the current registry lease ends with the delivery TTL. Run `hook-config`,
then **merge** its fragment into the corresponding settings file—the command
does not overwrite or install user configuration. The generated PreToolUse hook
rewrites Bash tool calls through `tool-exec`; it does not cover file-read, MCP,
hosted, or other non-Bash tool paths. See the precise guarantees and hook-host
caveats in [`DESIGN.md`](DESIGN.md#output-redaction-and-ai-hooks) and
[`docs/threat-model.md`](docs/threat-model.md#output-redaction).

The at-rest cache needs the provisioned keychain entitlement, so an unsigned
`swift run csecd` prints `at-rest cache OFF` and runs without persistence; the
signed, installed build (see [`packaging/README.md`](packaging/README.md)) prints
`at-rest cache on` and persists resolved values in the Secure-Enclave-gated
keychain. To install the real background agent rather than run it in the
foreground:

```sh
packaging/bin/build-agent.sh                         # build + sign the .app
/Applications/ConvenientSecurity.app/Contents/MacOS/csec install   # register the LaunchAgent
```

## Security requirements (non-negotiable)

The agent's protections only hold if it ships hardened-runtime + notarized +
provisioned (team-prefixed keychain access group), with no `get-task-allow`, no
Hardened Runtime exception entitlements (including library-validation, DYLD,
JIT/unsigned executable memory, executable-page protection, or debugger
exceptions), and only on a machine with SIP enabled. See
[`DESIGN.md`](DESIGN.md#security-requirements).
