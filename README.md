# Convenient Security

**Keep your secrets in 1Password or an encrypted file, use them in your local
tools, and give each secret away only when you tap Touch ID — never by scattering
plaintext into the environment of every process on your Mac.**

Convenient Security (`csec`) is a resident macOS agent that resolves secret
*references* like `op://Vault/DB/url` or `csec://development/API_TOKEN` into real
values, one human-approved touch at a time. It exists because the convenient way
to handle secrets and the safe way are usually opposites — and a security tool
you turn off because it's annoying protects nothing.

> macOS on Apple Silicon, with SIP enabled. Security guarantees apply to the
> signed, notarized release build; see [Security requirements](#security-requirements).

## The problem

Say you keep a database password in 1Password and want your local Rails app to
use it. The usual options all leak:

```sh
export DATABASE_URL="postgres://user:hunter2@…"   # now in your shell's environment
bin/rails server
```

A process's environment and command line are **readable by any other process
running as you** — via `ps`, `KERN_PROCARGS2`, or a peek at `/proc`-equivalent
APIs. So does a `.env` file (mode `0600` keeps out *other* users, not *your own*
processes). That means one malicious `npm install` postinstall script, one
trojaned CLI tool, one compromised VS Code extension — anything running as your
login user — can quietly read every secret you've exported and every dotfile you
own, and send them off. No prompt, no trace.

The popular alternative is an *ambient broker*: a background agent that hands any
same-user process any secret it asks for. That's convenient, but it's the same
hole with extra steps — the malware just asks the broker instead of reading your
environment, and still walks away with the whole vault silently.

## What Convenient Security does instead

It draws one hard line: **per-secret human consent.** The agent never releases a
value a human didn't just approve, and it keeps the footprint of each secret — at
rest and in use — as small as macOS allows.

- **Human in the loop.** The first time a process asks for a reference, the agent
  prompts for **Touch ID**, showing you exactly which secret, which process, and
  why. No password fallback, no auto-approve switch in the shipping build.
- **One touch, sensible scope.** A grant is bound to the approving process and
  its child processes (its "subtree") for a bounded lifetime, so a `rails server`
  and the migrations it spawns don't re-prompt you every few seconds — but an
  unrelated process gets nothing.
- **Risk-aware release.** On first use, an agent-owned window asks you to classify
  the logical credential as low, standard, high, or critical and reviews the
  proposed delivery. The agent applies that policy before reading a cache or
  provider, and binds every live grant to the resulting policy snapshot.
- **Narrow delivery without root.** The Ruby client and AWS/Git credential
  adapters use private pipes, while `exec-fd` gives file-oriented tools an
  anonymous inherited descriptor. Plaintext need not touch `ENV`, `argv`, or a
  named file.
- **Two backends, one interface.** References resolve from the official 1Password
  CLI (`op://…`) or from device-bound, AES-256-GCM encrypted files (`csec://…`).
  You can mix both in a single launch.
- **Encrypted at rest, gated by code identity.** The optional cache and the
  native store keys live in a Secure-Enclave-backed Keychain group that only the
  signed agent can open — the same code-identity model 1Password itself relies on.

The name is the whole thesis: security that's *convenient* enough to leave
switched on.

## How it protects you

| Threat | What stops it |
|--------|---------------|
| Malware reads secrets from your environment / `argv` | Ruby and credential-helper values cross private pipes; `exec-fd` puts only non-secret `/dev/fd/N` paths in the child environment. The explicit `csec exec` compatibility mode remains an exception. |
| Malware asks a broker for your whole vault | The agent releases only references a human just approved with Touch ID, scoped to the approving process subtree. |
| An old client or stale grant asks for a now-forbidden delivery | Protocol v1 fails closed; protocol v2 is evaluated against current risk metadata before resolution, and grants are reusable only with the same plan and policy digest. |
| Malware reads your encrypted files off disk | Files are AES-256-GCM envelopes; the keys live in a Keychain group only the signed, provisioned agent can access, gated by the Secure Enclave. |
| Malware tampers with or rolls back an encrypted file | Each store's Keychain record pins the current generation, file ID, and ciphertext digest, so modification, cross-store swaps, and replay of an old file fail closed. |
| A secret leaks into stdout that an AI tool then reads | Optional output redaction masks resolved values from supervised stdout/stderr and from Claude Code / Codex Bash tool calls. |
| An unsigned or tampered agent impersonates the real one | `csec` and `csecd` mutually verify Team ID, signing identity, hardened-runtime posture, and login UID over the socket before exchanging anything. |

## What it deliberately does *not* protect against

This is a security tool, so its limits matter as much as its features. Convenient
Security **cannot** protect a secret from:

- **root** or the Apple platform itself;
- **a consumer you deliberately authorized** — once your Rails app or your shell
  holds a plaintext value, it can log it, assign it to `ENV`, or send it anywhere;
- **`csec exec`'s environment channel** — this is an explicit, labeled
  *compatibility* path for unmodified tools that injects plaintext into the
  child's environment, where same-user process inspection can read it (output
  redaction reduces stdout leaks but does not repair this);
- **an inherited-fd consumer you authorize** — it can read, copy, log, or send
  the bytes, pass the descriptor to descendants, and deliberately expose them;
- **the external-editor mode** of the native store, which necessarily writes
  decrypted JSON to a temp file your editor and its plugins can read;
- **you approving a request that turns out to be misleading.**

The full attacker model — what a same-user, non-root process can and can't do,
and why each control holds — is in [`docs/threat-model.md`](docs/threat-model.md).

## Getting started

Build and run the agent, then fetch a secret:

```sh
bin/ci                                        # build + run the full test suite

swift run csecd                               # start the agent (foreground, dev mode)
swift run csec get 'op://Vault/Item/Field'    # fetch one secret to stdout — prompts for Touch ID
```

> An unsigned `swift run csecd` runs without the at-rest cache and the native
> store (it can't open the provisioned Keychain group) and prints
> `at-rest cache OFF`. For the full feature set, install the signed build — see
> [Installing the real agent](#installing-the-real-agent).

### Run an existing tool with secrets resolved

`csec exec` scans the environment for provider references and resolves them in
place before launching the child. This is the compatibility path — it works with
any unmodified tool, at the cost of putting plaintext in the child's environment:

```sh
DATABASE_URL='op://Engineering/Postgres/url' \
BUGSNAG_TOKEN='csec://development/BUGSNAG_TOKEN' \
  swift run csec exec -- bin/rails server
```

One Touch ID prompt covers `rails` and every process it spawns for the grant's
lifetime. Because this delivery is readable by unrelated same-UID processes, it
is allowed for low-risk credentials and requires a separate, time-bounded
compatibility acceptance for standard-risk credentials. It is forbidden for
high and critical credentials.

### Secure no-root delivery

Prefer a tool's credential protocol when it has one. AWS
[`credential_process`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html)
expects version-1 JSON from a command. A single referenced value may contain a
strict JSON object with `AccessKeyId`, `SecretAccessKey`, and optional
`SessionToken`/`Expiration` fields:

```ini
[profile engineering]
credential_process = /Applications/ConvenientSecurity.app/Contents/MacOS/csec creds aws --item op://Engineering/AWS/credential-process
```

Alternatively, use `--access-key-id-ref`, `--secret-access-key-ref`, and the
optional `--session-token-ref`/`--expiration-ref` flags for separate fields.
`csec` emits the credential only when stdout is a pipe or socket, and verifies
the live AWS parent immediately before release.

Git's
[`credential.helper`](https://git-scm.com/docs/gitcredentials#_custom_helpers)
can use a read-only, host-constrained adapter:

```sh
git config --global credential.https://github.com.helper \
  '/Applications/ConvenientSecurity.app/Contents/MacOS/csec creds git --host github.com --username-ref op://Engineering/GitHub/username --password-ref op://Engineering/GitHub/token'
```

Add `--path owner/repository.git` and enable `useHttpPath` when a credential must
be repository-specific. Non-matching requests return no credential; Git
`store` and `erase` operations are consumed but deliberately ignored.

For tools that accept a file path, `exec-fd` streams the complete referenced
file through a fresh anonymous descriptor and places only `/dev/fd/N` in the
tool's path variable:

```sh
csec exec-fd --preset pgpass=op://Engineering/Postgres/pgpass -- psql app
csec exec-fd --preset kubeconfig=op://Engineering/Kubernetes/config -- kubectl get pods
csec exec-fd --preset aws-shared-credentials=op://Engineering/AWS/credentials -- aws sts get-caller-identity
csec exec-fd --preset google-service-account=op://Engineering/GCP/service-account -- gcloud auth application-default print-access-token
csec exec-fd --fd TOOL_CONFIG=op://Engineering/Tool/config -- tool
```

Each reference is the complete intended file contents. This first no-root tier
supports single-open streaming consumers only: the descriptor is not seekable,
reopening shares a consumed offset, and a tool that closes inherited descriptors
at startup is incompatible. `csec` writes only after the target has successfully
executed, closes and wipes its buffer after delivery, forwards signals and exit
status, and creates no plaintext filesystem object.

Credential helpers normally start as fresh processes, so their default grant is
per invocation. Wrap a deliberate shell or command tree to reuse low/standard
grants across its descendants:

```sh
csec session -- zsh
```

The inherited `CSEC_SESSION_ID` is a non-secret lookup hint. `csecd` authorizes
it only after a live kernel ancestry walk reaches the registered PID and process
start time; copying the value outside that tree fails closed. If broad session
scope is rejected for a high-impact credential, the helper automatically falls
back to its normal per-command root.

### Classify delivery risk

The first access to a logical credential opens a trusted, value-free review in
`csecd`. For 1Password, fields under the same vault/item are grouped together;
for the native store, all keys in one store share a judgment. Unknown credentials
fail closed until you choose a level:

| Level | Current policy |
|-------|----------------|
| `low` | Up to 12 hours; compatibility environment and external-editor delivery are allowed. |
| `standard` | Up to 4 hours; weaker environment or named-file delivery needs a separately reviewed acceptance. |
| `high` | Up to 15 minutes; weak delivery and AI destinations are forbidden, and the complete consumer must have stronger assurance. |
| `critical` | Up to 5 minutes; exact-process scope and the narrowest delivery/consumer set are required. |

Inspect or change policy metadata without resolving the secret value:

```sh
csec risk inspect 'op://Engineering/Postgres/url'
csec risk classify standard 'op://Engineering/Postgres/url'
csec risk raise high 'csec://production-admin/*'
csec risk forget 'op://Engineering/Postgres/url'
```

`raise` cannot lower a classification. Lowering one with `classify`, or
forgetting it back to fail-safe unknown, requires Touch ID. Risk records contain
only HMAC-derived logical identities and value-free metadata. With the delivery
mechanisms currently shipped, a high or critical classification intentionally
blocks normal Ruby, raw-output, and environment access; those generic consumers
cannot claim the stronger assurance the policy requires.

### Deliver secrets to a Ruby app without touching the environment

For consumers you control — a Rails app at boot, say — the Ruby client is the
strongest path. It receives values over a private pipe into the process heap,
never via `ENV` or `argv`:

```ruby
require 'convenient_security'

secrets = ConvenientSecurity.access(
  ['op://Vault/DB/url', 'csec://development/LOCAL_API_TOKEN'],
  reason: 'boot rails',
  ttl: 8 * 3600
)

db_url = secrets.fetch('op://Vault/DB/url')             # a plain String, only in the heap
token  = secrets.fetch('csec://development/LOCAL_API_TOKEN')
```

See [`clients/ruby/README.md`](clients/ruby/README.md) for the delivery
guarantees and how the bridge verifies its Ruby parent.

## Native encrypted files

Prefer not to depend on 1Password? Convenient Security ships its own
device-bound encrypted store. References look like `csec://<store>/<key>`, and
you create or edit a store with a built-in editor that keeps plaintext in the
signed launcher's memory — no `$EDITOR`, no temp file:

```sh
csec edit development     # Touch ID, then edit a strict-JSON document in place
```

```json
{
  "DATABASE_URL": "postgres://…",
  "LOCAL_API_TOKEN": "…"
}
```

Each save writes a fresh AES-256-GCM envelope and atomically flips an agent-only
Keychain record to the new version. That record pins the store's device-bound
key, generation, file ID, and ciphertext digest — so tampering with, swapping, or
rolling back a file on disk fails closed. The strict JSON parser rejects
duplicate keys, nested or non-string values, more than 1024 entries, and
documents over 1 MiB, keeping the trusted agent's attack surface small.

> The native store needs the signed, provisioned build. There is no key export
> or recovery path: losing the Mac or deleting the Keychain record makes the
> ciphertext permanently unrecoverable.

If you need an editor feature the built-in one lacks, you can opt into your own
`$EDITOR` — but this is a weaker mode that writes decrypted JSON to a temp file:

```sh
EDITOR='code --wait' csec edit --editor development
```

The actual editor executable is included in the reviewed plan. External editing
is allowed for low risk, requires separate compatibility acceptance for standard
risk, and is forbidden for high and critical stores. The built-in editor remains
available with policy-capped sessions (15 minutes for high and 5 for critical).

## Keeping secrets out of AI tool output

If you use Claude Code or Codex, a stray `echo $TOKEN` or a verbose log line can
feed a live secret straight into an AI context. Two opt-in controls guard against
that:

```sh
# Mask resolved values from a supervised command's stdout/stderr:
csec exec --redact-output=always -- bin/rspec

# Scan an AI-issued Bash command's output against the daemon's registry of
# recently-released values, failing closed if scanning can't run:
csec tool-exec --destination ai -- /usr/bin/pgrep -fl rubocop

# Generate a hook fragment to merge into your AI tool's settings:
csec hook-config claude     # → merge into ~/.claude/settings.json
csec hook-config codex      # → merge into ~/.codex/hooks.json
```

These are egress safeguards, not a cure-all: they cover supervised stdout/stderr
and Bash tool calls, not file writes, network sends, or non-Bash tool paths. See
[`DESIGN.md`](DESIGN.md#output-redaction-and-ai-hooks) for the exact guarantees.

## Installing the real agent

The at-rest cache and native store require the signed, notarized, provisioned
`.app`, which registers as a background LaunchAgent:

```sh
packaging/bin/build-agent.sh                                        # build + sign the .app
/Applications/ConvenientSecurity.app/Contents/MacOS/csec install    # register the LaunchAgent
```

A signed agent prints `at-rest cache on` and persists resolved values in the
Secure-Enclave-gated Keychain. Signing, notarization, and the root-owned bridge
install pipeline are documented in [`packaging/README.md`](packaging/README.md).

## Security requirements

The agent's guarantees hold **only** when it ships as a Developer-ID-signed,
hardened-runtime, notarized build with an embedded provisioning profile for the
team-prefixed Keychain access group, **no** `get-task-allow`, **no** Hardened
Runtime exception entitlements (library validation, DYLD variables, JIT/unsigned
executable memory, executable-page protection, or debugging), and **only** on a
host with **SIP enabled**. A startup self-audit refuses to run in production if
this posture is absent. Unsigned development builds deliberately drop the
persistent cache and compile in test-only trust seams rather than fake the
entitlements. Details in [`DESIGN.md`](DESIGN.md#security-requirements).

## Learn more

| Document | What's in it |
|----------|--------------|
| [`DESIGN.md`](DESIGN.md) | Full architecture, components, guarantees, and limitations. |
| [`docs/threat-model.md`](docs/threat-model.md) | What same-user malware can and can't do, and why each control holds. |
| [`docs/protocol.md`](docs/protocol.md) | The authenticated Unix-socket wire protocol (protocol v2). |
| [`docs/development.md`](docs/development.md) | Toolchain baseline, CI entry point, and signed release gates. |
| [`clients/ruby/`](clients/ruby/) | The heap-delivery Ruby client gem. |
| [`packaging/`](packaging/README.md) | Signing, notarization, `.pkg` build, and install pipeline. |

### Repository layout

- `agent/Sources/ConvenientSecurity/` — provider-agnostic core: references,
  grants, cache, resolver, protocol, and the native encrypted store.
- `agent/Sources/OnePasswordAdapter/` — all 1Password-specific code.
- `agent/Sources/csecd/`, `agent/Sources/csec/` — the resident daemon and the
  signed CLI / launcher / output supervisor.
- `clients/ruby/` — the Ruby heap-fetch client.
- `packaging/` — the signing, notarization, and install pipeline.

## Licence

Copyright 2026 Stateful Ltd. The source is available under the
[Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md)
(`FSL-1.1-ALv2`). The licence permits use, modification, and redistribution for
non-competing purposes; each released version becomes Apache License 2.0 two
years after its release. This is a Fair Source licence, not an OSI-approved
open-source licence.

Report security vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md). The project is not currently accepting external
code contributions; see [`CONTRIBUTING.md`](CONTRIBUTING.md).
