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
  shows one trusted review window with exactly which secret, which process, and
  why, and activates embedded **Touch ID** as soon as the window is visible. No
  preliminary Enter press, password fallback, or auto-approve switch exists in
  the shipping build.
- **One touch, sensible scope.** A grant is bound to the approving process and
  its child processes (its "subtree") for a bounded lifetime, so a `rails server`
  and the migrations it spawns don't re-prompt you every few seconds — but an
  unrelated process gets nothing.
- **Risk-aware release.** On first use, an agent-owned window asks you to classify
  the logical credential as low, standard, high, or critical and reviews the
  proposed delivery. The agent applies that policy before reading a cache or
  provider, and binds every live grant to the resulting policy snapshot.
- **Narrow delivery without root.** The Ruby and Node.js clients and AWS/Git
  credential adapters use private pipes, while `exec-fd` gives file-oriented
  tools an anonymous inherited descriptor. Plaintext need not touch `ENV`,
  `argv`, or a named file.
- **Seekable files without same-UID ambient access.** The packaged `csec-rootd`
  can create root-owned regular files on bounded `nodev,nosuid,noexec` tmpfs and
  launch one approved process tree with a fresh, non-reused capability GID.
  Unrelated processes running as the login user do not receive that group.
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
| Malware reads secrets from your environment / `argv` | Ruby, Node.js, and credential-helper values cross private pipes; `exec-fd` puts only non-secret `/dev/fd/N` paths in the child environment. The explicit `csec exec` compatibility mode remains an exception. |
| Malware reads an ordinary same-user configuration file | `csec exec-file` creates root-owned `0050` directories and `0040` regular files on bounded tmpfs. Only the freshly launched capability-GID tree can traverse and read them; paths, not values, enter its environment. |
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
- **a pipe reader or ordinary redirection file you explicitly approve** — Unix
  does not identify a pipeline's sibling reader to `csec`, and an ordinary file
  can be read later, copied, synchronized, or backed up outside csec's control;
- **`csec exec`'s environment channel** — this is an explicit, labeled
  *compatibility* path for unmodified tools that injects plaintext into the
  child's environment, where same-user process inspection can read it (output
  redaction reduces stdout leaks but does not repair this);
- **an inherited-fd consumer you authorize** — it can read, copy, log, or send
  the bytes, pass the descriptor to descendants, and deliberately expose them;
- **a regular-file consumer you authorize** — it can reopen, map, copy, log, or
  send the file, retain an open descriptor after unlink, or deliberately pass
  the capability or bytes to its descendants;
- **the external-editor mode** of the native store, which necessarily writes
  decrypted JSON to a temp file your editor and its plugins can read;
- **plaintext sources reviewed or imported by `csec setup`** — setup leaves
  them intact until you verify the replacement and remediate them separately;
- **you approving a request that turns out to be misleading.**

The full attacker model — what a same-user, non-root process can and can't do,
and why each control holds — is in [`docs/threat-model.md`](docs/threat-model.md).

## Getting started

Build and run the agent, then fetch a secret:

```sh
bin/ci                                        # build + run the full test suite

swift run csecd                               # start the agent (foreground, dev mode)
swift run csec get 'op://Vault/Item/Field'    # terminal get — identifies the parent shell and prompts once per grant
```

> An unsigned `swift run csecd` runs without the at-rest cache and the native
> store (it can't open the provisioned Keychain group) and prints
> `at-rest cache OFF`. For the full feature set, install the signed build — see
> [Installing the real agent](#installing-the-real-agent).

### Deliberate plaintext output with `csec get`

`csec get` supports the ordinary shell shapes people actually use:

```sh
csec get 'op://Vault/Item/Field'                    # terminal output
csec get 'op://Vault/Item/Field' | command          # pipeline
value="$(csec get 'op://Vault/Item/Field')"         # command substitution
csec get 'op://Vault/Item/Field' > ./ordinary-file  # persistent plaintext file
```

For all four forms, the verified direct-parent shell is the requester, grant
owner, and subtree root; signed `csec` is the emitter. The daemon binds the
shell's PID, process start time, canonical executable identity, and subtree
scope, then `csec` rechecks that exact process incarnation immediately before
writing plaintext. Compatible consecutive gets from the same live shell can
reuse its risk-capped grant. A different, exited, reparented, or replaced shell
cannot.

A generic Unix pipe exposes no authenticated identity for the sibling process
that reads it. The review therefore says **unverified pipe reader**: approval is
delegated to the requesting shell and does not claim the reader was verified.
Command substitution has the same shell-delegated pipe semantics.

Regular-file stdout is reviewed separately as **persistent plaintext-file
delivery**. The file may be readable by other same-user processes, and csec
cannot control later reads, copies, backup, or synchronization. The shell may
create or truncate the target before `csec` starts, but csec neither resolves
the reference nor writes plaintext until approval succeeds, and it never sends
the target filename in protocol metadata. Prefer `csec exec-file` for a
protected regular file. Prefer `exec`, `exec-fd`, or a credential helper when
the consumer supports those narrower channels.

Terminal, pipe, and persistent-file approvals are distinct delivery shapes; an
approval for one never silently approves either of the others.

### Onboard a project and coding agents

The installed launcher has one dry-run-first bootstrap command. It detects
Claude Code and Codex, plans an additive user-level Bash hook merge, inventories
supported local source metadata, and emits a bounded prompt for a deeper
read-only coding-agent audit:

```sh
csec setup --project "$PWD"             # inspect only; changes nothing
csec setup --project "$PWD" --apply     # apply the reviewed hook plan
```

Auto-detection checks the client executable and its user configuration. Use
`--agent claude` or `--agent codex` to select an installed client explicitly,
or `--skip-agents` to review/import sources without changing hooks. Setup merges
only its generated `PreToolUse` Bash handler into `~/.claude/settings.json` or
`~/.codex/hooks.json`; unrelated JSON values and the existing file mode are
preserved, although JSON formatting is normalized. The dry run prints the exact
value-free managed fragment, but never echoes the complete user configuration.
It refuses symlinks, unsafe
ownership/permissions, duplicate JSON keys, concurrent file replacement, an
older csec handler, and Claude's `disableAllHooks: true`. Replacing only a
recognized old csec handler requires the separately explicit
`--replace-csec-hook` flag.

The value-free source review scans the current process environment and a bounded
set of live `.env` files beneath the project. It displays variable names,
logical `op://`/`csec://` references, file modes, counts, and warnings—never
discovered plaintext values. Ambiguous interpolation, duplicate assignments,
symlinks, oversized files, and unsupported syntax are not interpreted. Import
is opt-in per source and currently targets only the native encrypted store:

```sh
csec setup --project "$PWD" --skip-agents \
  --store development \
  --import API_TOKEN=dotenv:.env.local:LEGACY_API_TOKEN

# Repeat the exact reviewed command with --apply; Touch ID gates the store edit.
csec setup --project "$PWD" --skip-agents \
  --store development \
  --import API_TOKEN=dotenv:.env.local:LEGACY_API_TOKEN \
  --apply
```

Use `DEST=env:NAME` for a selected inherited environment value. Existing native
keys are protected unless `--replace-secret` is also explicit. Setup rechecks
the selected source and refuses a changed dotenv file during apply, never
resolves an existing logical reference, and never removes or rewrites the
original environment/dotenv source; verify the new `csec://` consumer before
remediating that source separately.

Setup cannot approve a client's hook trust, override managed policy, detect
every configuration source, or prove competing-hook order. Restart each client,
review its effective hook UI, and use the generated audit prompt to close those
gaps. Each config/store update is individually atomic, but a multi-target apply
is not one cross-file transaction; a failure reports any earlier completed
updates and the command is safe to repeat. Use the durable installed `csec`
path for applied hooks rather than a disposable SwiftPM build path.

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
compatibility acceptance for standard-risk credentials. High and critical
remain unavailable to this generic launcher because its complete environment
consumer is unverified, rather than merely because the channel is a
compatibility mechanism.

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

### Secure regular-file delivery

Some tools require real regular-file semantics: independent opens, seeking,
`mmap`, metadata checks, or reopening from a fork/exec descendant. The installed
package supplies a deliberately narrow root helper for those consumers:

```sh
csec exec-file \
  --file TOOL_CONFIG='op://Engineering/Tool/config' \
  -- tool

csec exec-file \
  --gh-config 'op://Engineering/GitHub/token' \
  -- gh api user
```

Every launch is a fresh, digest-bound rendezvous between the original signed
`csec`, signed `csecd`, and signed root helper. `csec` supplies the exact launch
plan and stdio descriptors; `csecd` independently repeats policy review, Touch
ID, and resolution, then sends the final bytes directly to the helper. The
launcher receives only approval and non-secret paths. The helper creates a
one-time root-owned directory and files on a 32 MiB/2,048-node tmpfs, drops the
child to the login UID with a newly allocated primary capability GID, and
preserves its ordinary supplementary groups.

Files are unlinked when the complete capability-GID process tree exits or the
authorization expires. `--hard-ttl` also terminates the complete tree at expiry;
without it, expiry cannot revoke a descriptor the authorized consumer already
opened. Launcher death, explicit cancellation, and output-scanner failure
terminate the capability tree. Supervised output is masked everywhere by
default — terminals, pipes, and captured stdout/stderr (`--redact-output=tty`
limits masking to terminals; `never` disables it). An authorized consumer can
always disclose what it reads.

The GitHub mode creates only a protected `GH_CONFIG_DIR/hosts.yml`, refuses
ambient GitHub token variables or existing config/keyring authority before
resolution, and is restricted to a direct `gh` executable outside its
authentication and extension-management commands. Run `csec root-status` to
verify that the authenticated helper endpoint is reachable.

The source and synthetic compatibility matrix are implemented. Do not use this
path for real credentials until the signed, installed root-helper matrix in
[`docs/regular-file-security-matrix.md`](docs/regular-file-security-matrix.md)
has passed on the target macOS release.

### Classify delivery risk

The first access to a logical credential opens a trusted, value-free review in
`csecd`. For 1Password, fields under the same vault/item are grouped together;
for the native store, all keys in one store share a judgment. Unknown credentials
fail closed until you choose a level:

| Level | Current policy |
|-------|----------------|
| `low` | Up to 12 hours; normal approval and normal capped reuse, including compatibility delivery. |
| `standard` | Up to 4 hours; compatibility delivery needs a separate, exact-shape acceptance. |
| `high` | Up to 15 minutes; strong warning, fresh Touch ID, and compatibility acceptance limited to the resulting live grant. AI destinations and insufficiently assured consumers still fail. |
| `critical` | Up to 5 minutes; strongest warning, fresh Touch ID, and compatibility acceptance limited to the resulting live grant. Scope and consumer-integrity requirements still apply. |

Inspect or change policy metadata without resolving the secret value:

```sh
csec risk inspect 'op://Engineering/Postgres/url'
csec risk classify standard 'op://Engineering/Postgres/url'
csec risk raise high 'csec://production-admin/*'
csec risk forget 'op://Engineering/Postgres/url'
```

`raise` cannot lower a classification. Lowering one with `classify`, or
forgetting it back to fail-safe unknown, requires Touch ID. Risk records contain
only HMAC-derived logical identities and value-free metadata. A compatibility
choice is warn-and-confirm, not a permanent denial solely because it is weaker.
Acceptance is bound to mechanism, destination, scope, emitter/requester
assurance, and recipient assurance. Standard acceptance can be remembered for
30 days; high and critical acceptance is represented only by the short-lived,
exact live-shell grant. Malformed metadata, unverifiable requesters, stale
process incarnations, insufficient consumer assurance, and unavailable or
denied authentication still fail closed before provider resolution.

### Deliver secrets to Ruby and Node.js apps without touching the environment

For consumers you control — a Rails or Node.js app at boot, say — the language
clients are the strongest path. They receive values over a private pipe into the
process heap, never via `ENV`/`process.env` or `argv`:

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

```ts
import { access } from 'convenient-security';

const secrets = await access(
  ['op://Vault/DB/url', 'csec://development/LOCAL_API_TOKEN'],
  { reason: 'boot node service', ttl: 8 * 60 * 60 },
);

const dbUrl = secrets['op://Vault/DB/url'];
const token = secrets['csec://development/LOCAL_API_TOKEN'];
```

See the [Ruby](clients/ruby/README.md) and [Node.js](clients/node/README.md)
client guides for their delivery guarantees, startup patterns, and error APIs.

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
risk, and remains unavailable for high and critical because the arbitrary editor
is an unverified complete consumer. The built-in editor remains available with
policy-capped sessions (15 minutes for high and 5 for critical).

## Keeping secrets out of AI tool output

If you use Claude Code or Codex, a stray `echo $TOKEN` or a verbose log line can
feed a live secret straight into an AI context. Two controls guard against
that:

```sh
# Resolved values are masked from a supervised command's stdout/stderr by
# default, whether it writes to a terminal, a pipe, or a captured log:
csec exec -- bin/rspec

# Scan an AI-issued Bash command's output against the daemon's registry of
# recently-released values, failing closed if scanning can't run:
csec tool-exec --destination ai -- /usr/bin/pgrep -fl rubocop

# Dry-run and safely merge detected clients' hook configuration:
csec setup
csec setup --apply

# Or generate one fragment for a manual merge:
csec hook-config claude     # → merge into ~/.claude/settings.json
csec hook-config codex      # → merge into ~/.codex/hooks.json
```

These are egress safeguards, not a cure-all: they cover supervised stdout/stderr
and Bash tool calls, not file writes, network sends, or non-Bash tool paths. See
[`DESIGN.md`](DESIGN.md#output-redaction-and-ai-hooks) for the exact guarantees.

## Audit host posture

csec protects your secret *values*, but the same-user malware it fights can still
win by other means — inheriting an app's Full Disk Access grant, hijacking a
writable `PATH`, MITMing your TLS through a rogue root CA, or persisting via a
`LaunchAgent`. `csec audit` checks whether the Mac underneath is configured so
that those attacks can't trivially succeed:

```sh
csec audit                 # report host posture, then offer the batched fixes
csec audit --report-only   # read-only: report only, propose nothing
csec audit --json          # stable JSON (finding ids are the contract); implies --report-only
csec audit --scan-filesystem   # also run the bounded SUID / world-writable sweep (off by default)
```

The audit runs **inside the resident agent** (`csecd`); the `csec` launcher is a
thin client. csecd holds Full Disk Access — requested at setup, worth it under the
"more secure, conveniently" ethos — to enumerate which apps hold privacy (TCC)
grants, and it drives the signed root helper for the privileged reads and the
reversible fixes. It runs ~65 checks across platform integrity, Gatekeeper,
network exposure, privacy grants, persistence, developer attack surface,
accounts, and csec's own coverage; the on-thesis (★) controls that shrink csec's
adversary's blast radius lead the report. The full catalog, with a stable id per
check, is in [`docs/host-audit-catalog.md`](docs/host-audit-catalog.md).

Reporting and remediation are one flow. After the report, csec collects the
safe, reversible fixes into a **single review under one Touch ID** — a checklist
you can deselect items from, applied atomically per target. Two more-secure
states that need a real choice or state transition get **guided interactive
helpers** instead: FileVault, which keeps the recovery key local and never
silently escrows it to iCloud, and Santa binary allow-listing, which links to the
official signed package and describes a MONITOR-mode starting posture (never
LOCKDOWN). Items that would risk breaking a legitimate setup — revoking a TCC
grant, removing a config profile or custom root CA — are surfaced with evidence
and a link, never auto-applied.

Because `csecd` is already resident, it re-audits on a daily timer against an
accepted baseline at
`~/Library/Application Support/ConvenientSecurity/host-audit-baseline.json`. It
stays quiet unless a previously-good control **regresses** (firewall turned off,
a new app granted Full Disk Access) — a high-signal event that can mean malware
disabling defenses. On a regression it **notifies only**; it never mutates
anything in the background, and you re-run `csec audit` to review and re-apply.
`csec setup` runs the audit (report-only) automatically when onboarding
completes.

The whole audit is value-free: every finding and evidence string is metadata only
— counts, kinds, enum state — never a credential value, CA name, path, or command
output.

## Installing the real agent

The at-rest cache and native store require the signed, notarized, provisioned
`.app`, which registers as a background LaunchAgent. Protected regular files
also require the signed `.pkg`; copying the app alone does not install or load
the root helper:

```sh
packaging/bin/build-and-install.sh    # build, notarize, package, install, register, and verify
```

The command reuses the existing provisioning profile, fetching one through the
configured 1Password-backed release tooling when it is missing. Pass
`--refresh-profile` to fetch a new profile or `--dry-run` to inspect the full
plan without signing, network access, installation, or service changes. It
invokes `sudo` only for Apple's package installer; LaunchAgent registration
runs as the login user. The individual release steps remain documented in
[`packaging/README.md`](packaging/README.md).

A signed agent prints `at-rest cache on` and persists resolved values in the
Secure-Enclave-gated Keychain. Signing, notarization, and the root-owned bridge
and helper install pipeline are documented in
[`packaging/README.md`](packaging/README.md).

## Security requirements

The agent's guarantees hold **only** when it ships as a Developer-ID-signed,
hardened-runtime, notarized build with an embedded provisioning profile for the
team-prefixed Keychain access group, **no** `get-task-allow`, **no** Hardened
Runtime exception entitlements (library validation, DYLD variables, JIT/unsigned
executable memory, executable-page protection, or debugging), and **only** on a
host with **SIP enabled**. A startup self-audit refuses to run in production if
this posture is absent. Protected `exec-file` guarantees additionally require the exact
signed root helper and system LaunchDaemon installed at root-owned, non-writable
paths by the verified package. Unsigned development builds deliberately drop
the persistent cache and compile in test-only trust seams rather than fake the
entitlements. Details in [`DESIGN.md`](DESIGN.md#security-requirements).

## Learn more

| Document | What's in it |
|----------|--------------|
| [`DESIGN.md`](DESIGN.md) | Full architecture, components, guarantees, and limitations. |
| [`docs/threat-model.md`](docs/threat-model.md) | What same-user malware can and can't do, and why each control holds. |
| [`docs/protocol.md`](docs/protocol.md) | The authenticated Unix-socket wire protocol (protocol v2). |
| [`docs/development.md`](docs/development.md) | Toolchain baseline, CI entry point, and signed release gates. |
| [`docs/regular-file-security-matrix.md`](docs/regular-file-security-matrix.md) | Synthetic evidence and the signed-device gate for regular-file delivery. |
| [`clients/ruby/`](clients/ruby/) | The heap-delivery Ruby client gem. |
| [`clients/node/`](clients/node/) | The heap-delivery Node.js npm package, written in TypeScript. |
| [`packaging/`](packaging/README.md) | Signing, notarization, `.pkg` build, and install pipeline. |

### Repository layout

- `agent/Sources/ConvenientSecurity/` — provider-agnostic core: references,
  grants, cache, resolver, protocol, and the native encrypted store.
- `agent/Sources/CSECRootProtocol/`, `agent/Sources/CSECRootServer/` — the
  protected-payload-free launch protocol and minimal privileged runtime/server.
- `agent/Sources/OnePasswordAdapter/` — all 1Password-specific code.
- `agent/Sources/csecd/`, `agent/Sources/csec/`, `agent/Sources/csec-rootd/` —
  the credential daemon, signed CLI/supervisor, and narrow root helper.
- `clients/ruby/` — the Ruby heap-fetch client.
- `clients/node/` — the TypeScript Node.js heap-fetch client; the root
  `package.json` owns the npm workspace and lockfile.
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
