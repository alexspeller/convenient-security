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

**New to csec?** The [user guide](docs/guide/README.md) is the short way in:
installing the package and the first `csec setup`, everyday use,
troubleshooting and uninstalling. Building, signing and installing it
yourself from source is in [Build it yourself](docs/guide/build-it-yourself.md).
This README is the full reference.

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
value a human didn't approve for that process tree (or, if you opt in, for that
Claude Code project), and it keeps the footprint of each secret — at rest and in
use — as small as macOS allows.

- **Human in the loop.** The first time a process asks for a reference, the agent
  shows one trusted review window with exactly which secret, which process, and
  why, and activates embedded **Touch ID** as soon as the window is visible. Its
  buttons and keyboard focus wait at least half a second, and then until you
  have stopped typing for a second or so, so the sentence you were typing when
  an agent raised the prompt cannot dismiss it; once the panel takes the
  keyboard, its focus rests where a stray Space, Return or letter presses
  nothing (Escape still refuses). No
  preliminary Enter press, password fallback, or environment- or
  argument-controlled auto-approve switch exists in the shipping build, and no
  review — secret access, SSH signing, or sudo —
  is ever satisfied by the Touch ID that unlocked your Mac: each one asks for
  its own touch, because a prompt nobody answered is not a decision. Touch ID
  answers only the active window, so a review that loses the focus to another
  app or another Touch ID prompt (1Password, macOS's own sheet, a second csec
  review) says "Click this window to use Touch ID", and asks for Touch ID
  afresh once you click it. The one
  automatic approver is opt-in: Claude Code's auto-mode classifier, for
  secrets you already approved for that project
  ([below](#let-claude-code-auto-mode-approve-secret-use)).
- **One touch, sensible scope.** A grant is bound to the approving process and
  its child processes (its "subtree") for as long as that process runs, so a
  `rails server` and the migrations it spawns don't re-prompt you every few
  seconds — but an unrelated process gets nothing. A csecd restart doesn't cost
  you your approvals either.
- **Risk-aware release.** On first use, an agent-owned window asks you to classify
  the logical credential as low, standard, high, or critical and reviews the
  proposed delivery. The agent applies that policy before reading a cache or
  provider, and binds every live grant to the resulting policy snapshot.
- **Narrow delivery without root.** The Ruby and Node.js clients and AWS/Git
  credential adapters use private pipes, while `exec-fd` gives file-oriented
  tools an anonymous inherited descriptor. Plaintext need not touch `ENV`,
  `argv`, or a named file.
- **Destination-bound SSH signing.** A manual csec SSH-agent socket accepts only
  Apple's signed `/usr/bin/ssh`, verifies OpenSSH's server/session binding,
  rejects forwarding and arbitrary signing, and reuses one Touch-ID-approved
  key + host-key + remote-user + process-subtree grant for the lifetime of the
  approved session by default (optionally a bounded 1 or 12 hours, chosen in the
  approval window like every secret release).
- **GitHub's token used, never released.** `csec protect --gh` moves the GitHub
  CLI's token into csec and points `gh` at csecd's GitHub socket with a
  placeholder; csecd puts the token on approved requests to GitHub and `gh`
  receives only the responses ([`docs/github-proxy.md`](docs/github-proxy.md)).
- **Fly's token off disk.** `csec protect --fly` moves the Fly.io CLI's token
  out of `~/.fly/config.yml` into csec, and `csec fly` (alias `fly` to it) runs
  fly with the token in its environment after one review per terminal session.
- **Seekable files without same-UID ambient access.** The packaged `csec-rootd`
  can create root-owned regular files on bounded `nodev,nosuid,noexec` tmpfs and
  launch one approved process tree with a fresh, non-reused capability GID.
  Unrelated processes running as the login user do not receive that group.
- **Two backends, one interface.** References resolve from the official 1Password
  CLI (`op://…`) or from device-bound, AES-256-GCM encrypted files (`csec://…`).
  You can mix both in a single launch.
- **1Password stays ready once you've used it.** csec contacts 1Password only
  when a request needs it, so an idle Mac never sees a 1Password prompt from
  csec. After the first approval the resident agent keeps that desktop-app
  session open with metadata-only checks while the screen is unlocked. It never
  prefetches a secret; app lock and 1Password's maximum session lifetime still
  require fresh approval.
- **More than one 1Password account works.** An `op://` reference names no
  account, so `op` on its own resolves it against whichever account it last
  recorded. csec finds the account that actually owns the vault and reads from
  exactly that one. When a vault name is not unique, the approval window names
  the account the value will come from and says so before you touch the sensor.
  If csec hasn't yet listed those vaults' items, which would mean asking
  1Password before the window appears, it names every account the value could
  come from instead, and reads only if exactly one of them holds the item.
- **1Password asks once, not all day.** csec holds an authorized 1Password
  session open instead of re-authorizing on every read, and it only ever
  contacts 1Password because you asked for something. It keeps that session
  warm while you are working and goes completely quiet when the screen locks —
  so csec never puts a Touch ID prompt in front of you that you did not
  trigger. Locking 1Password still ends the session; the next secret you ask
  for starts a new one.
- **iPhone approval.** A paired iPhone can mirror and Face-ID-approve the
  exact same value-free review — secret access from any provider (opening
  csec's own stored secrets through a phone-held unlock factor), SSH signing,
  sudo, and reopening approvals after a restart — while the local Touch ID
  window remains available; the first signed decision wins, and neither surface gives up while
  you are away — answer in a minute or in an hour. When the Mac stops waiting it
  takes the prompt off the phone, so there is never a stale Approve button, and
  a Mac that stops for good (it crashed, or was lost) drops off the phone ten
  minutes after it last checked in, coming back if it returns. The
  phone is alerted only if the Mac prompt is still open after 30 seconds (at
  once when the Mac is locked or asleep, or cannot take a touch), with the
  request's kind, Mac, command and requester, written on the phone from the
  verified request. Every build is capable of it and it stays off until you pair
  a phone (one command on the Mac, after which the open phone app shows the Mac
  to accept);
  `packaging/bin/build-and-install.sh` also installs the iPhone app on your
  paired phone. Provisioning and the physical-device release gate are tracked in
  [`docs/remote-approval.md`](docs/remote-approval.md).
- **Explicit unattended automation.** When cron or launchd cannot wait for
  Touch ID, one local review can register an exact command and exact references
  until revoked. This intentionally trusts mutable scripts and dependencies;
  ordinary bounded grants remain unchanged. See
  [`docs/automation.md`](docs/automation.md).
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
| Malware connects to your SSH agent and asks it to sign | The SSH socket accepts only live Apple `/usr/bin/ssh`, requires a verified non-forwarded destination binding, parses an exact user-auth request, and binds grants to the key, host key, remote user, and process subtree. |
| Malware runs `gh auth token` or reads gh's keychain item | After `csec protect --gh` neither holds a token: csecd adds it to approved requests on its GitHub socket, after the same review and grants as any secret, and forwards them over its own TLS connection to GitHub hosts only. A request that can add lasting access (an SSH key, a secret, a webhook, a workflow) is never covered by a grant: each gets its own review. |
| Malware reads `~/.fly/config.yml` | After `csec protect --fly` the file keeps fly's settings but no token; `csec fly` hands the token to the fly process you approved in `FLY_API_TOKEN`, where same-user process inspection can still read it while fly runs, and fly's agent exits with each command. |
| An old client or stale grant asks for a now-forbidden delivery | Protocol v1 fails closed; every protocol v2 delivery plan passes the release policy before anything is resolved, and a grant is reused only for the same references and release shape. |
| Malware reads your encrypted files off disk | Files are AES-256-GCM envelopes; the keys live in a Keychain group only the signed, provisioned agent can access, gated by the Secure Enclave. |
| Malware tampers with or rolls back an encrypted file | Each store's Keychain record pins the current generation, file ID, and ciphertext digest, so modification, cross-store swaps, and replay of an old file fail closed. |
| A secret leaks into stdout that an AI tool then reads | Optional output redaction masks resolved values from supervised stdout/stderr and from Claude Code / Codex Bash tool calls (and Claude Code Monitor commands). |
| An unsigned or tampered agent impersonates the real one | `csec` and `csecd` mutually verify Team ID, signing identity, hardened-runtime posture, and login UID over the socket before exchanging anything. |

## What it deliberately does *not* protect against

This is a security tool, so its limits matter as much as its features. Convenient
Security **cannot** protect a secret from:

- **root** or the Apple platform itself;
- **a consumer you deliberately authorized** — once your Rails app or your shell
  holds a plaintext value, it can log it, assign it to `ENV`, or send it anywhere;
- **a mutable unattended job you explicitly enrolled** — anything that can edit
  its script, dependencies, arguments' inputs, or working-directory contents can
  obtain every reference registered to that job on its next run;
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
- **an SSH key's source backend or an explicitly approved generic delivery** —
  the csec SSH socket is signature-only, but backend-neutral keys remain ordinary
  references rather than becoming hardware-backed, non-exportable identities;
- **plaintext sources reviewed or imported by `csec setup`** — setup leaves
  them intact until you verify the replacement and remediate them separately;
- **a Claude Code auto-mode approval, if you turn delegated approvals on** — the
  classifier can be wrong or be steered, and a command it approves can get the
  secrets you paired with that project, as can anything that command starts,
  whether from its environment or by asking csec itself;
- **you approving a request that turns out to be misleading.**

The full attacker model — what a same-user, non-root process can and can't do,
and why each control holds — is in [`docs/threat-model.md`](docs/threat-model.md).

The manual protected-key workflow and its limits are in
[`docs/ssh-agent.md`](docs/ssh-agent.md).

## Getting started

Installing the signed package? Follow [Install and set up](docs/guide/install.md).
From a checkout, build and run the agent, then fetch a secret:

```sh
bin/ci                                        # build + run the full test suite

swift run csecd                               # start the agent (foreground, dev mode)
swift run csec get 'op://Vault/Item/Field'    # terminal get — identifies the parent shell and prompts once per grant
```

To protect and use an SSH key manually (global setup is intentionally deferred):

```sh
csec protect --ssh ~/.ssh/id_ed25519
export SSH_AUTH_SOCK="$(csec ssh socket)"
ssh user@example.com
```

To keep the GitHub CLI's token in csec (one Touch ID; `gh` keeps working):

```sh
csec protect --gh
```

To take the Fly.io CLI's token out of its config file (one Touch ID), then run
fly through csec:

```sh
csec protect --fly
alias fly='csec fly'      # fish: alias --save fly 'csec fly'
fly deploy                # first use in this terminal: one review
```

flyctl rewrites `config.yml` during ordinary commands, so csec does not encrypt
the file: it moves `access_token` into the store (`csec://fly/FLY_API_TOKEN`, or
1Password with `--dest op://VAULT`), empties it and `metrics_token`, and keeps
every other setting. With `FLY_API_TOKEN` set, flyctl keeps the tokens it
refreshes in memory and never writes them back. `csec fly` also sets
`FLY_AGENT_ISOLATED=1`, so fly's WireGuard agent exits with each command instead
of holding the token in a background daemon. `csec fly auth login` takes the new
token back out of the file; `csec fly register <reference>` uses a token you
already keep elsewhere; `csec fly auth logout` forgets the registration.

SSH protection and registration detect when the launching shell is not using the
csec socket and print this profile/one-off activation guidance; csec does not
edit shell profiles itself. SSH protection preserves or creates the public-key
file but deliberately leaves no `.csec` sidecar: the SSH catalog already owns
the backend-neutral reference used for signing.

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
Claude Code and Codex, plans an additive user-level Bash hook merge for Claude
Code (Codex's managed hook is root's, see below), inventories
supported local source metadata, and emits a bounded prompt for a deeper
read-only coding-agent audit:

```sh
csec setup --project "$PWD"             # inspect only; changes nothing
csec setup --project "$PWD" --apply     # apply the reviewed hook plan
```

Auto-detection checks the client executable and its user configuration. Use
`--agent claude` or `--agent codex` to select an installed client explicitly,
or `--skip-agents` to review/import sources without changing hooks. For Claude
Code, setup merges only its generated `PreToolUse` handler (matcher
`Bash|Monitor`: Claude Code's Monitor tool runs its command in the same Bash
tool shell, under the same permission check and classifier, so it is wrapped
and delegated exactly as a Bash command is; a WebSocket monitor runs no shell
and is left alone) and one `autoMode.environment` entry into
`$CLAUDE_CONFIG_DIR/settings.json` when that variable names an absolute path,
or `~/.claude/settings.json` when it is unset. When `$CLAUDE_CONFIG_DIR/settings.json`
is a symlink to `~/.claude/settings.json` (as for an extra Claude account that
shares the default settings), setup edits `~/.claude/settings.json` itself and
leaves the link alone. Setup refuses an empty or relative
`CLAUDE_CONFIG_DIR` instead of editing the default file. Hook status and the
host audit use the same selection; an unusable override leaves coverage unknown.
A csec hook installed before Monitor was covered sits under `Bash` alone:
`csec status` reports it as an older csec hook, and
`csec setup` replaces it. Unrelated JSON
values and the existing file mode are preserved, although JSON formatting is
normalized. The entry tells Claude Code's auto-mode classifier that
`csec ai -- <command>` runs `<command>` unchanged, so it judges the inner
command; a new list starts with `"$defaults"` so Claude Code's built-in entries
stay in effect. For Codex, the hook lives in Codex's managed System layer,
`/etc/codex/hooks.json`, which setup installs with the package's guarded
installer through `sudo` when it is missing or stale (as
`packaging/bin/build-and-install.sh` does from a checkout):
Codex runs managed hooks without per-hook trust, whereas a user-level hook
stops running whenever its bytes change until the user re-trusts it. Setup configures Codex's
sandbox access and removes a csec handler an older csec left in
`~/.codex/hooks.json`, its leftover description and attributable obsolete trust
state. It reuses unchanged csec profiles and removes unreferenced generated
duplicates, keeping private pre-edit backups; see [Codex sandbox setup](docs/codex-sandbox.md).
The dry run prints the exact
value-free managed fragment, but never echoes the complete user configuration.
It refuses symlinks, unsafe
ownership/permissions, duplicate JSON keys, concurrent file replacement, an
older csec handler, and Claude's `disableAllHooks: true`. Replacing only a
recognized old csec handler requires the separately explicit
`--replace-csec-hook` flag.

The value-free source review scans the current process environment and a bounded
set of live env files (`.env`, `.env.*`, `*.env`) beneath the project. It
displays variable names, logical `op://`/`csec://` references, file modes,
counts, and warnings—never discovered plaintext values. Ambiguous
interpolation, duplicate assignments, symlinks, oversized files, and unsupported
syntax are not interpreted. Import is opt-in per source and currently targets
only the native encrypted store:

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

### Protect every secret file at once

`csec protect <path>…` accepts explicitly named, caller-owned files anywhere,
independent of the current directory. It uses the same credential catalog and
protection defaults as setup: AWS profiles use `credential_process`, env files
rewrite per variable as `csec_NAME="<reference>"`, SSH keys register with the signer, and unknown files
become encrypted blobs with sidecars. Default stores come from the target's
project or home, not the directory where you ran the command.

```sh
csec protect ~/.aws/credentials --dry-run
csec protect ~/.aws/credentials
csec protect --aws --aws-config /path/to/config /path/to/custom-credentials
csec protect --whole-file /path/to/opaque-secret
```

`--env` retains the interactive variable picker; `--whole-file` explicitly
selects the original whole-file behavior. Automatic file selection refuses
symlinks and hardlinks. Whole-file sidecars are discovered by `csec exec` within its
launch directory; protecting an external file does not add it to every launch.
A protected token file in your home directory is the exception: `csec exec`
restores it for the tool that reads it from any directory, so
`csec exec -- vault status` in `~/projects/app` brings back `~/.vault-token`
and no other tool's token. Each catalog token file names its commands (`vault`,
`hf`, `cargo`, `kaggle`, `sentry-cli`, `databricks`, `scw`, `hcloud`, `dog`,
`twine`, `hatch`, `flit`, `doctl`, `linode-cli`, `grafanactl`, `supabase`).
For a tool started through a wrapper or library (`npx`, a Python script using
`huggingface_hub`), name the file: `csec exec --with-file
~/.cache/huggingface/token -- python train.py`. Each restored file is one more
reference in the same review.

`csec setup --protect-files` sweeps for protectable secret files and applies
the right protection per kind in bulk, driving the same primitives as
`csec protect`, `protect --env`, and `protect --ssh`:

```sh
csec setup --protect-files --dry-run          # sweep $HOME; print the plan only
csec setup --protect-files                    # interactive bulk-select picker
csec setup --protect-files --scan-root ~/work/WebApp --dry-run   # narrow
csec setup --protect-files \
  --glob '~/work/**/.envrc=per-var' \
  --glob '*.pem=skip' \
  --apply                                     # deterministic, non-interactive
```

Before it scans, the command says where it will look, what it reads (names,
and the contents of files that look like secrets, up to 1 MiB each), and that
the scan runs only in that csec command: it sends nothing over the network,
copies nothing, changes nothing and saves no list. Nothing is stored until you
confirm a plan (or pass `--apply`). While it scans, one line shows where it is,
which top-level folder of how many (and which folder within it), the entries
and candidates so far, and the time taken; the walk finishes each folder before
the next, so the folder count is real progress rather than a time guess.

The picker works like the multi-select lists of fzf, ranger and Midnight
Commander. Files are grouped into folders: a folder of many files (200
worktree copies of one `.envrc`, say) is one row you can open with → and close
with ←, and Space on it picks or unpicks everything inside, shown `[x]`, `[-]`
or `[ ]`. `/` opens a filter that narrows the list as you type: every word
must appear somewhere in the path, ignoring case unless the word has a
capital, `!word` excludes, `word$` ties a word to the end of the path and `*`
stands for any characters. Up and Down move while you type, Tab picks the row
and moves on, Enter goes back to the list keeping the filter, and Esc clears
it. `a`, `n` and `i` select, deselect or invert every row shown, so you can
narrow, pick, narrow again and unpick. A find of up to 20 files starts with its
suggested protections selected; a larger one starts with nothing selected, so
keeping a few out of hundreds is a few filters and Tabs. The footer counts what
is selected and how many of the rows shown. `p` and `d` set the approach or
destination of the selected files in a prompt under the table; the filter and
prompts have the usual line editing keys (Ctrl-A/E, Ctrl-B/F and arrows,
Ctrl-K/U/W, Alt-B/F, Home, End, Delete). An unknown approach, or a destination
that is neither `csec://` nor `op://`, keeps the prompt open with a message;
Esc goes back without changing anything. Enter shows the plan and asks before
anything is changed; `q` or Ctrl-C leaves without changes.

The default sweep covers the whole home directory: the general walk finds
project secrets (`.env`/`.env.*`/`*.env`, `.envrc`, shell rc exports, key material,
`.git-credentials`, auth-bearing `.npmrc`), while a data-driven catalog of ~50
standard tool credential locations is probed by absolute path — including
inside directories the walk skips (`~/.cache/huggingface/token`,
`~/Library/**`, `~/.cargo`, `~/.m2`, `~/.gradle`). An explicit `--scan-root`
narrows the sweep and disables the home-global probes unless it covers home.
There is no entry-count, file-count, root-count or directory-depth cutoff.
Build/cache directories remain excluded, and content reads keep their size limits.
The catalog includes Quic, av, Crunchy Bridge and Runpod credentials. Mixed
JSON/YAML/TOML configs require a literal credential assignment; references,
empty values and environment selectors do not qualify. Static Solana keypair
JSON (`solana/id.json`) and Ethereum `UTC--…` key stores are checked by
structure, including in backup trees. Ethereum key stores are already
password-encrypted; csec adds its access gate when they are protected.
The plan is a table of **unique files**: symlinks resolve to their destinations,
stay in place, and do not get rows or sidecars of their own. Additional hardlink
paths are shown separately because each still exposes the same file. Whole-file
and file-preset protection put a sidecar at each hardlink and remove plaintext
only after the entire group has been imported. Every link must be discovered;
an alias outside the scan or excluded by its filters stops that file before
import. Expand the scan (review exclusions with `--include-excluded --dry-run`)
or remove unused aliases. Per-variable rewriting, SSH registration and AWS migration
refuse hardlinked inputs before import, including with
`--keep-plaintext`; choose `whole-file` explicitly when that delivery fits.
Changed files or aliases are retained and reported as incomplete protection.
When using `csec exec`, the destination
sidecar must be within the launch's project scan; an alias in another project
does not bring that destination into scope.

Default exclusions also omit Claude's `~/.claude/daemon/control.key`, installed
editor extensions and language runtimes, Elixir dependency trees, private-key
files under test/fixture directories, and env templates/encrypted files
(`.erb`, `.j2`, `.jinja`, `.jinja2`, `.enc`, `.encrypted`, `.gpg`, `.age`, `.csec`).
The summary counts these by reason. They are convenience defaults, not proof that
a file cannot contain a credential. Use `--include-excluded` with `--dry-run`
(and optionally `--scan-root`) to review these categories. Existing build/cache
exclusions still apply. Account credentials, project env files (including test
environments), Rails credentials and backups remain candidates. npm configs
containing only `${ENV_VAR}` auth placeholders are not plaintext credentials.

Per-kind defaults: env-style files rewrite per-variable to references. Dotenv
and envrc files fall back to whole-file when their secrets are interpolated or
command-substituted. Shell startup files stay in place: supported literals
rewrite per-variable, while unsupported-only or unparseable files are listed
but skipped, with a note to migrate manually. Unsupported assignments in a
mixed startup file are preserved and reported. Choose `whole-file` explicitly
if you want to replace a startup file with a sidecar; ordinary shell startup
does not load it. SSH keys register with the csec SSH agent (a key it
cannot use — DSA, RSA under 2048 bits, or a key wrapped in other text — is
encrypted whole instead, and a passphrase-protected key is left alone with a
warning, so one such key never fails the rest of the SSH batch), key material
and opaque tool files become encrypted blobs with sidecars, token files
(Hugging Face, Vault, Cargo, Kaggle, …) do too, so `csec exec` materializes them
where their tool reads them (a home token file for its own tool, from any
directory), and `~/.aws/credentials` profiles become
`csec creds aws` bundles. Fly's config gets `csec protect --fly`'s treatment:
its token moves to the store for `csec fly` and the file keeps everything
else. Other token files whose tool saves them during ordinary
commands (Stripe, Netlify, Vercel, Wrangler, Pulumi, Railway, Render,
Neon, Firebase, Grafana gcx) are listed but skipped unless you choose whole-file: the
materialized copy is read-only, so the tool would fail or put the plaintext
back, and `csec protect` refuses them without `--whole-file`. If a command
under `csec exec` replaces a protected file with its own, csec leaves it in
place and warns that it may hold plaintext. An npm config (`~/.npmrc`, or a project's) is split
rather than removed: only its literal `_authToken`, `_auth` and `_password`
lines move to the store, as one value, and every other line stays in place,
so plain `npm`, `pnpm` and `yarn` keep their `min-release-age`,
`ignore-scripts` and registry settings. A comment where the first auth line
was names the reference and the `csec exec-fd --preset npm=…` command that
puts the lines back. Auth lines inside an INI section, hardlinks and
concurrent edits stop the split, and `--keep-plaintext` stores the lines but
leaves the file as it was. SSH keys go to the shared `ssh-keys` store, as with
`csec protect --ssh`, unless a rule names a store. Both commands
durably import static profiles, configure `credential_process` in
`AWS_CONFIG_FILE` (default `~/.aws/config`), then remove only the migrated
credential fields. Comments, unrelated settings, and derived profiles remain.
Conflicting config, ambiguous INI, hardlinks, or concurrent edits stop migration;
a partial migration can be rerun. `--keep-plaintext` configures the process but
retains the static fields, so protection is incomplete until those are removed.
The config parent directory must already exist. Tools that default to the macOS
Keychain are flagged when a plaintext fallback file is present: a Grafana `gcx
login` config (or a repository `.gcx.yaml`) is a finding only when a credential
field holds a literal rather than gcx's `keychain:gcx:…` reference, as under
`GCX_KEYCHAIN=off`; the deprecated `grafanactl`'s always-plaintext config is
probed too. Glob rules
(`*`, `?`, `**`, `~`, `/`-anchored; approaches `per-var`, `whole-file`, `ssh`,
`creds-aws`, `preset:<name>`, `env-token:<VAR>`, `skip`; optional
`:csec://STORE` or `:op://VAULT` destination; `op://` takes per-var imports
and npm splits) adjust whole subsets at once.

Each store asks for one Touch ID per import kind (variables, files, SSH keys,
npm auth lines) and one per AWS credentials file. Values are always durable in the store before
any plaintext is touched. An import never replaces a value already stored under
the same name: a different value is stored as `NAME_2` (or the next free
suffix), so files protected earlier keep resolving to their own values. Only
`csec edit <reference>` overwrites. AWS configuration is installed directly;
other wire-up commands (`exec-fd --preset npm=…`, `exec-file --gh-config …`)
are printed as recipes, never executed. Default store names are legible transforms of
each file's project root (`work-WebApp`), disambiguated only on a real
collision.

### Run an existing tool with secrets resolved

Store references under a `csec_` prefix so ordinary commands do not mistake
them for real credentials. `csec exec`, `csec ai`, and its `tool-exec` alias
resolve them into the unprefixed name only in the child environment:

```sh
export csec_GITHUB_TOKEN='csec://development/GITHUB_TOKEN'
csec exec -- gh repo list
```

The child gets `GITHUB_TOKEN` and no `csec_GITHUB_TOKEN`; the parent shell keeps
only the reference. The prefix is case-sensitive and works with any configured
provider. Legacy `GITHUB_TOKEN=csec://…` references still resolve in place.
If both names are set, unset one or explicitly choose with `--set GITHUB_TOKEN=<ref>`.
Invalid prefixed names, malformed references, and unavailable schemes are rejected
before resolution. `ai` retains its existing warning-and-run-without-injection
fallback when protection is unavailable.

`csec protect` defaults to these prefixed names for env files, including
`protect --env` and `setup --protect-files`. Existing references are renamed
without re-importing, and rerunning protection never adds another prefix.
Live name collisions are rejected before import. Reload your env file after
migration and unset any old unprefixed variables still exported by your shell.

Environment injection is the compatibility path — it works with
any unmodified tool, at the cost of putting plaintext in the child's environment:

```sh
csec_DATABASE_URL='op://Engineering/Postgres/url' \
csec_BUGSNAG_TOKEN='csec://development/BUGSNAG_TOKEN' \
  swift run csec exec -- bin/rails server
```

One Touch ID prompt covers `rails` and every process it spawns. By default it
also covers the rest of the process tree you are working in — see
[grant scope](#choosing-how-wide-a-grant-is) — so a coding agent or a terminal
session does not re-prompt for every command. This delivery is readable by
unrelated same-UID processes, and the review window says so before you tap.

`csec exec` and `csec ai` also warn on stderr before each launch that injects
secrets, including when an earlier approval covers the request and when `exec`
combines environment values with protected files. Output masking does not hide
the child's initial environment. Prefer the
[credential and file adapters below](#secure-no-root-delivery) when the tool
supports them: `csec creds aws`, `csec creds git`, `csec exec-fd`, or
[`csec exec-file`](#secure-regular-file-delivery). The warning contains no secret
values or reference metadata. File-only launches and secret-free AI commands
that skip injection do not emit it.

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
csec exec-fd --preset npm=csec://home/NPMRC_AUTH -- npm publish
csec exec-fd --fd TOOL_CONFIG=op://Engineering/Tool/config -- tool
```

Each reference is the complete intended file contents, except for `npm`: its
reference holds only the auth lines, and the descriptor carries the live
userconfig (`NPM_CONFIG_USERCONFIG` when set, else `~/.npmrc`) with those
lines added at its top level, so npm keeps every setting in the file. npm
processes started inside the wrapped command re-open a drained descriptor and
see an empty user config; wrap the one command that needs the token. This first no-root tier
supports single-open streaming consumers only: the descriptor is not seekable,
reopening shares a consumed offset, and a tool that closes inherited descriptors
at startup is incompatible. `csec` writes only after the target has successfully
executed, closes and wipes its buffer after delivery, forwards signals and exit
status, and creates no plaintext filesystem object.

Credential helpers normally start as fresh processes, so their default grant is
per invocation. Wrap a deliberate shell or command tree to reuse one grant
across its descendants:

```sh
csec session -- zsh
```

The inherited `CSEC_SESSION_ID` is a non-secret lookup hint. `csecd` authorizes
it only after a live kernel ancestry walk reaches the registered PID and process
start time; copying the value outside that tree fails closed. The session's
grant reaches every descendant of that shell, so wrap only a tree you mean to
trust with those credentials.

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
plan and stdio descriptors; `csecd` independently repeats policy review and
resolution — asking for Touch ID unless a grant you widened to your shell or
coding agent already covers it — then sends the final bytes directly to the
helper. The
launcher receives only approval and non-secret paths. The helper creates a
one-time root-owned directory and files on a 32 MiB/2,048-node tmpfs, drops the
child to the login UID with a newly allocated primary capability GID, and
preserves its ordinary supplementary groups.

Files are unlinked when the complete capability-GID process tree exits. By
default that is the only end: the authorization lasts for the process. Bound it
with `--for <seconds>` and the files are also unlinked when it expires; add
`--hard-ttl` and expiry terminates the complete tree too, since otherwise it
cannot revoke a descriptor the authorized consumer already opened. Launcher
death, explicit cancellation, and output-scanner failure terminate the
capability tree. Supervised output is masked everywhere by
default — terminals, pipes, and captured stdout/stderr (`--redact-output=tty`
limits masking to terminals; `never` disables it). An authorized consumer can
always disclose what it reads.

The GitHub mode creates only a protected `GH_CONFIG_DIR/hosts.yml`, refuses
ambient GitHub token variables or existing config/keyring authority before
resolution, and is restricted to a direct `gh` executable outside its
authentication and extension-management commands. Run `csec status` for the
complete app/agent/provider/SSH/root report, or `csec doctor` to repair and
verify the installed services.

If the agent ever wedges — a hung daemon that accepts a connection and then goes
silent — a `csec` command no longer hangs on it. The daemon proves it is alive
with a heartbeat every few seconds while it works, so a prompt you leave sitting
behind the lock screen or approve from your phone an hour later is never cut
short; only a daemon that stops talking altogether is. The command then fails
saying csecd stopped responding and pointing at `csec doctor`, which restarts
it. `csec ai` never blocks your shell on this: it warns, names the fix, and runs
your command with `op://` / `csec://` references left unresolved.

The source and synthetic compatibility matrix are implemented. Do not use the
root helper's files for real credentials until the signed, installed
root-helper matrix in
[`docs/regular-file-security-matrix.md`](docs/regular-file-security-matrix.md)
has passed on the target macOS release. That covers `csec exec-file` and every
`csec exec` launch that brings back a protected file: a project's `*.csec`
sidecars, a home token file restored for its tool or named with `--with-file`,
and the `--set`/env-scan values folded into the same launch.

### One tap authorizes a release

The first access to a credential opens a trusted, value-free review in `csecd`:
it shows the references, where the value is going, and a warning if that
destination is same-user-inspectable — then a single Touch ID authorizes it.
There is no risk classification and no separate compatibility checkbox; the tap
is the decision. One approval lasts for the lifetime of the process or session it
is granted to — no wall-clock cap — so a credential stays usable without ever
re-prompting on a clock; the grant ends when that process subtree exits, and
survives a `csecd` restart ([after a restart](#after-csecd-restarts)). In the
approval window you can narrow it to a bounded 1 or 12 hours instead, or bound
it explicitly with `--for`.

A request through csecd's GitHub socket gets the same window, but nothing is
released: its secret is headed "Secret used, never released", the line beside
the sensor says the chosen scope may *use* the token, and the footnote says the
token stays in csec ([`docs/github-proxy.md`](docs/github-proxy.md)). A GitHub
request that can give access outlasting any approval (`gh ssh-key add`, `gh
secret set`, `gh repo deploy-key add`, a workflow edit) gets its own window
every time, headed "Lasting GitHub Access Requested", with a warning naming the
request; it covers that one request, and auto mode never approves one.

#### One-time codes

Some commands need a second-factor code as well as a token: `npm publish
--otp`, `aws sts get-session-token --token-code`. End a reference with
`?attribute=otp`, the line 1Password copies for a one-time password field, and
the command gets the current code, never the seed it is made from:

```sh
export csec_NPM_OTP='op://Private/npm/one-time password?attribute=otp'
csec exec -- sh -c 'npm publish --otp="$NPM_OTP"'
```

Each command that needs a code gets its own panel, on the Mac or the paired
iPhone, and the row says the code is for that command only. A code is made
fresh each time and never kept: no grant covers it, whatever scope you choose
for the secrets beside it, so the next command asks again; a panel that asks
only for codes offers no wider scope and no lifetime. A restart has nothing to
restore for one, and Claude Code auto mode never releases one, paired or not:
its panel says so and offers no pairing line. `?attribute=totp` works too, in
any capitalisation.

1Password works out its own codes, so the seed never leaves it. For a seed kept
in csec's own store, save the `otpauth://totp/…` URI the service gave you (the
text behind its QR code) and ask for `csec://store/KEY?attribute=otp`: csecd
works the code out itself (RFC 6238; SHA-1, SHA-256 or SHA-512, 6 to 8 digits)
and releases only that.

csec never releases a seed. A reference whose value is an `otpauth://` URI, or
a 1Password one-time password field read without `?attribute=otp`, is refused
with a message that points at the suffix, and an unattended automation job
cannot hold a code at all. One caveat: output masking skips values shorter than
8 characters, so a 6-digit code a command prints is not masked, and an agent
may see a code while it is still valid, though never the seed.

#### Choosing how wide a grant is

The same window asks *which process tree* the approval covers. `csecd` walks the
process tree above the request itself and offers up to three roots:

```
Grant scope
  ( ) Requesting process only     csec (pid 65060) and its descendants — this command only
  (•) Claude Code and everything it runs   Claude Code (pid 31163)
  ( ) This terminal session       fish (pid 2589) — everything started in this terminal
```

The default is the coding agent if one is running the command, else the terminal
session, else just the requesting process. The pre-selected default means the
usual flow is still a single tap; pick a different row before you touch the
sensor to narrow or widen it.

A job the agent started in the background and detached — `( job & )`,
`nohup job &` — stays inside Claude Code's tree even after the tool call that
started it has ended, so an `ssh` it runs later uses the approval you gave that
Claude session instead of asking once per connection. csecd proves the link
from the job's kernel session, only for a session it saw while the tool call
ran, and only while that Claude process runs; a job that starts its own session
(`setsid`, a daemon) is on its own and asks as before. The same goes for a job
detached from a tmux or VS Code terminal's shell. See
[DESIGN.md](DESIGN.md#detached-jobs).

#### Which tab is asking

Every approval surface — the review window (and its restore panel after a csecd
restart, and its settings layout for auto-mode approval changes and the other
setup steps: backups, a restore, phone pairing, machine identities, removing an
SSH key or an automation job, host fixes and the uninstall cleanup), the SSH
review, the sudo review, and the mirrored phone review — carries one line naming the terminal
tab the request came from:

```
⌨ iTerm2 · “◑ deploy preview — ~/opensource/mailer” · window 1, tab 5 · ttys012
```

`csecd` walks the process tree above the request (for a job the agent detached,
the tree that started it) for the nearest process whose
exec-time environment names a terminal (`ITERM_SESSION_ID`, `TERM_SESSION_ID`,
`TERM_PROGRAM`, …) and its nearest controlling tty, then asks iTerm2 or
Terminal.app over AppleScript which window and tab own that session. The first
time, macOS asks once whether ConvenientSecurity may control the terminal; declining
just leaves the title off. The tab's *title* is self-reported (any process in the
tab can set it) and is there to orient you; the window/tab position and tty
beside it come from the terminal application and the kernel. Under tmux or
screen the line names the pane and says the host tab cannot be identified, rather
than showing a stale one. A request with no terminal anywhere above it says so —
a daemon, launchd job, or GUI application asked, which is worth a second look.

Beneath the tab, the review shows the **whole command** the launcher is about to
run — the full `bash -c '…'` program, not just `bash`. `csecd` checks the argv
against the digest the grant is bound to and runs it through the same redaction
`csec exec` applies to command output, so a value it has already released never
appears on screen even if it was pasted into the command line. A long command
shows its first lines with a "Show full command" disclosure for the rest, which
grows the window to show all of it; only a command taller than the screen
scrolls, with a scroller that stays drawn and a line saying it continues. The
list of secrets, and on a restore the approvals it reopens, work the same way:
every one is on the panel, and only a list longer than the screen scrolls, with
its scroller drawn and a line saying there is more.

A request that carries no command of its own — a Python, Ruby or Node program
asking through `csec bridge`, or a `csec get` — leads with the reason the
program wrote itself, which is the one thing on the panel it chooses. Under
that reason the review shows the program's own **process command line**
(`python3 …/pytest -q`), which `csecd` reads from the kernel for the requesting
process by its pid, only while that pid is still the process that started at
the time the request names, and redacts and bounds exactly as it does a
launcher's command. So a request whose reason says "deploy bot" but whose command
line is a test suite looks like what it is. The command line is shown as text
and never used to identify the requester or decide anything; when it cannot be
read the panel shows the reason alone. The paired iPhone shows it under the
same reason, and the panel's `csec log` record keeps it as its `command`.

When Claude Code auto mode could have approved a request in your place but did
not (delegated approvals), the review says why below its footnote — "Auto mode
didn't approve this: …" — on the secret-access, SSH and sudo reviews. When
approving with the Claude Code scope and the process lifetime would also let
auto mode use those references in this project, a pairing line says so, and it
hides as soon as you pick another scope or a lifetime cap. The sudo review has
no scope or lifetime to pick, so its line ("Approving also lets Claude Code
auto mode run sudo in <project> until you revoke it") always shows when it is
offered. When the session fails a check pairing can't fix (a launch option
such as `--settings`, an injected environment variable, a hook or setting you
haven't reviewed), every request from it asks until that is fixed, so the line
says when the pairing starts to count instead ("… run sudo in <project> once
Claude Code is started without --settings"); approving still pairs. The
paired iPhone shows both lines the same way, and approving there with the line
shown pairs too. Neither line appears on the restore panel (a variant of the
secret-access review).

Choosing a wider root also lets *other commands* in that tree reuse the grant.
That is the point: an agent's next tool call is a different command, so a grant
bound to one command line would re-prompt constantly. Reuse still requires the
same delivery shape — mechanism, destination, recipient, output guard, and the
plaintext-exposure gate — so an approved `csec exec` can never be reused as a
`csec get --reveal`, a new reference still prompts for the delta, and the caller
must still descend from that exact live process.

`csec exec` in a project holding `*.csec` sidecars delivers through a
capability-GID launch, which creates a fresh root of its own. That mechanism
reuses a *widened* grant like any other, but never a requesting-process one — so
if you keep the narrow default there, every launch prompts.

Live grants are visible and cancellable:

```sh
csec grants          # root process, references, expiry, and reuse for each grant
csec revoke <id>     # drop one: grant-…, ssh-…, pair-…, build-… or hook-… (a prefix is enough)
csec revoke --all    # drop every grant and project pairing
```

A grant ends when its root process exits, or when a lifetime you chose runs
out. It is kept, with no secret value, in a Keychain item only `csecd` can read,
so it survives a `csecd` restart (not a reboot), and a revocation is written
there before `csec revoke` returns, so a restart cannot bring a revoked grant
back. In the rare case the Keychain refuses both that write and the fallback of
deleting every saved grant, `csec revoke` fails with an error saying the
revocation holds only until `csecd` restarts. `pair-…`, `build-…` and
`hook-…` entries appear only while Claude Code delegated approvals are on
([below](#let-claude-code-auto-mode-approve-secret-use)).

`csecd` keeps the 1Password values it resolves cached, so a release does not
wait on 1Password. A value edited in the 1Password app still reaches the next
release: `csecd` re-reads it over a 1Password session it already holds open,
and when you approve a release at the Mac with no session open it asks
1Password first (which may show 1Password's own prompt once). To make sure the
next release reads a value fresh anyway, drop the cached copy; nothing is shown
and no Touch ID is needed:

```sh
csec refresh 'op://Vault/Item/field'
```

#### After csecd restarts

An upgrade, `csec doctor`, a crash or a kill restarts `csecd`, and your grants
come back with it, but the stores sealing their values start locked. The
installer runs `csec restore` immediately after the runtime is repaired, while
you are at the Mac. It raises or joins **one** panel —
"csecd restarted (upgrade): reopen what you approved" — listing every restored
grant that needs an unlock (and, with delegated approvals on, every paired
project of a Claude Code session still running). One Touch ID reopens them all
and approves nothing new; every request waiting on it then proceeds. **Forget
these approvals** drops the listed grants instead and refuses the waiting
requests; the installer accepts Forget as your completed choice. There is no
prompt if nothing needs reopening or restoration already completed. The
installer's request keeps the panel alive while short-lived secret/SSH
requests come and go. It returns only a status, never values or a new grant,
and a cancelled or incomplete restore fails the install without retrying.

While you are still there, `csec restore` also fetches every value you paired
for Claude Code auto mode that 1Password serves, so 1Password asks you once
per account now rather than refusing an unattended session hours later. It
prints what it fetched and anything 1Password would not serve; those are
fetched on first use instead, and the install carries on.

A restart with no install behind it (a reboot, say) has no `csec restore`, and
1Password can miss the install's prompt. So whenever you approve a csec panel
on this Mac (not on your phone) and a paired 1Password value is still not
held, csec fetches it then too, and 1Password may ask you once more per
account. When everything is held this asks 1Password nothing.

After a crash or manual restart, the first request needing restoration still
raises this panel. If every waiting requester leaves, it closes without using
the restore up; a later request can raise it again. A completed restore stays
used until csecd restarts, unless a paired project's row could not be reopened.
The panel reaches your paired iPhone when it can reopen every listed row,
including cached `op://` references. Sudo has no csec grants to restore.

A csecd that cannot read what it saved (an older build installed over a newer
one, or a Keychain read that failed at startup) keeps it exactly as found
rather than starting over: your grants, pairings and settings come back once
the current build runs again. Meanwhile what you approve lasts until csecd
restarts, and `csec doctor` fails, naming the item and the fix.
`build-and-install.sh` refuses to install a checkout missing changes from the
installed build unless you pass `--allow-downgrade`. Equivalent rebased patches
and flattened merges pass once their patches and merge trees are accounted for
in the checkout's history.

#### What csecd decided

`csecd` keeps a log of every decision, in encrypted files that other programs
running as you can neither read nor edit, reorder, truncate or roll back without
`csecd` noticing:

```sh
csec log                        # panels, refusals, revocations, settings, restarts
csec log --since 2h --json      # one JSON record per line
csec log --kind reuse           # releases a live grant covered, with no panel
csec log --verify               # check the whole log now; non-zero on a finding
```

Each record says who decided — you on the Mac, your phone, auto mode, or an
earlier grant — and a panel's record also says how long it was on screen and
why it appeared at all (new secrets, another process, an expired or revoked
grant, a restart). Records never hold a secret, only references and the panel's
own redacted command line (for a `csec bridge` or `csec get` request, the
requesting program's command line the panel showed under its reason). Reading them needs no Touch ID, like `csec grants`,
so a program running as you could read them through `csec log` too. A tampered
log is recorded, reported in `csec status` and notified once, and the log
carries on from its last good point; the damaged segment and every segment
after it are set aside, kept on disk but no longer shown by `csec log`.

#### Deny, and requests that go away

The installed sudo review accepts requests only from a live parent running as
root. Another process of your login user cannot feed chosen text to the genuine
helper to raise its Administrator panel or phone review. Live synthetic review
tools are available only in development builds.

Secret-access, SSH (including restored approvals), and sudo share one review
turn across csecd and the separate sudo helpers. A queued request shows no Mac
panel or phone copy until the current review finishes. Sudo's existing
five-minute bound includes its wait for that turn; cancelling or losing a
requester removes its wait without showing a stale panel.

A panel never outlives the command that raised it. Interrupt a `csec` command or
an `ssh` with Ctrl-C, or close its tab, and its review closes; a review held
behind the lock screen checks that its requester is still running before it asks
for Touch ID again. Several `ssh` connections of the same kind started at once
wait behind one panel. Secret and SSH reviews also close, or leave their queue
unseen, if the process that started the request exits or its original approval
scope is lost. The Mac and phone copies are withdrawn together; the log says
what was abandoned and how long it waited. A process already detached when it
asks is allowed to wait. The sudo review closes on Ctrl-C, Ctrl-\, a closed
terminal, or sudo itself dying. A Ctrl-C or Ctrl-\ ends sudo there: no macOS
Touch ID sheet or password prompt follows, and the terminal says sudo was
interrupted without authorizing anything. A plain `kill` of sudo (SIGTERM), or `timeout … sudo`, does not close it:
sudo handles that signal itself and keeps running, so the review stays up until
you answer it or its five-minute limit passes. At that limit sudo fails and
the Mac and phone reviews close; it opens no Apple Touch ID sheet or password
prompt, and the terminal says nobody answered the review in time.

A panel a developer check put on screen (csec's own preview and probe
tools) carries a solid red "TEST — NOT A REAL REQUEST" banner above everything
else and "— TEST" in its title, on the secret-access, SSH and sudo reviews
alike. A real request never shows it: only those test tools can turn it on.
Approving a test panel releases, signs or runs nothing.

A panel that will close on its own says so. The sudo review shows from the
start when it closes if nobody answers (its five-minute limit, less three
seconds), and so does a coding agent's secret or SSH review (its 20-minute
wait). For the last 30 seconds the line turns into a countdown, so a panel
never vanishes from under you mid-touch. A request with no such limit, a
terminal's own, shows no line. The same request on your iPhone shows the same
line and countdown, until you answer it there. Use Password, a phone Deny and helper failures still offer Apple's
recovery path. When the Mac cannot take a touch (Touch ID locked out, or the
lid closed), the sudo panel waits only for your iPhone, and with no phone able
to answer sudo goes straight to Apple's prompt. A secret or SSH panel stays up
and says "Approve on your iPhone" while the request is on your phone, or that
it cannot be authorized when no phone can answer. Every panel arms Touch ID as
soon as it comes back (the lid opened) while it is up, and closing the lid on
a panel waiting for your touch leaves it waiting for your iPhone the same way. Sudo keeps the same bound when its own parent exits.

#### A coding agent's request nobody answers

csecd shows one panel at a time. When Claude Code or Codex asks for something
that needs you, its command prints, at once and once:

```text
csec ai: waiting for approval on the Mac or iPhone: secret access to op://Example/item/password. If nobody answers, csec withdraws it at 22:14 (20 minutes after it was asked) and the command fails.
```

so the session can see why it has stopped, file a note for you and wait.
When your iPhone cannot answer it (no phone is paired, or a provider such as
1Password would first have to authorize at the Mac), the line says "on the
Mac" instead, and a request first told the iPhone could answer, then found
when its panel comes up that it cannot, is told so once more. An
`ssh` it started (a `git push` inside a wrapped command, say) is reported the
same way by the `csec ai` above it. If nobody answers within 20 minutes of the
request, csec withdraws it — the panel closes, the phone's copy goes, and it is
logged as `withdrawn`, not as your Deny — and the command fails saying approval
was not given; each request has its own clock, so a pile of requests queued
behind one unanswered panel all lapse together rather than one at a time.
Change the time with
`defaults write com.alexspeller.convenient-security CodingAgentApprovalWaitMinutes -int 30`
(1 to 1440 minutes; `csec status` shows it). A request from your own terminal
keeps waiting as before, and sudo keeps its five-minute limit. Claude Code's
plain `git push`, `fetch`, `pull` and `clone` run without `csec ai`, so nothing
can print the waiting line for them; they are still withdrawn on time.

Pressing Deny also answers the identical requests already waiting behind that
panel — the same secrets and delivery shape from inside the scope the panel
offered, or the same SSH key, server and user offered that same scope — so a
burst of retries does not
raise the same question again, and a denied `ssh` is refused its next key
instead of prompting for it. A request made after the Deny is asked afresh.
Only your Deny does this: a panel that closed because its requester left, or a
Touch ID error, refuses nothing else.

`csec get` prints a raw value, so it is gated by where that value would land:

| `csec get SECRET …` | stdout is | behavior |
|---|---|---|
| bare | your terminal | refused — it would sit in scrollback (an agent or logger could capture it); pass `--reveal` to echo it deliberately |
| `\| cmd` | a pipe to a command | allowed — you are handing bytes to a tool, not displaying them |
| `> file` | a file | refused — durable plaintext on disk; pass `--allow-plaintext-file` |
| (no terminal) | an agent/script capture | refused and steered to `csec exec`/`exec-file`/`creds`; the same flags override under Touch ID |

For anything a program consumes, prefer the injection commands (`csec exec`,
`csec exec-file`, `csec creds`) over `csec get` — they hand the value to the tool
without it ever passing through your terminal or an agent's context. Malformed
metadata, unverifiable requesters, stale process incarnations, and denied or
unavailable authentication still fail closed before provider resolution.

### Deliver secrets to Ruby and Node.js apps without touching the environment

For consumers you control — a Rails or Node.js app at boot, say — the language
clients are the strongest path. They receive values over a private pipe into the
process heap, never via `ENV`/`process.env` or `argv`:

```ruby
require 'convenient_security'

secrets = ConvenientSecurity.access(
  ['op://Vault/DB/url', 'csec://development/LOCAL_API_TOKEN'],
  reason: 'boot rails'
)

db_url = secrets.fetch('op://Vault/DB/url')             # a plain String, only in the heap
token  = secrets.fetch('csec://development/LOCAL_API_TOKEN')
```

```ts
import { access } from 'convenient-security';

const secrets = await access(
  ['op://Vault/DB/url', 'csec://development/LOCAL_API_TOKEN'],
  { reason: 'boot node service' },
);

const dbUrl = secrets['op://Vault/DB/url'];
const token = secrets['csec://development/LOCAL_API_TOKEN'];
```

With no `ttl`, the approval lasts as long as the process tree you pick in the
review window, like every other grant; pass `ttl` (1 to 172,800 seconds) to
bound it. An installed `csec` older than these clients refuses a request with
no `ttl`.

See the [Ruby](clients/ruby/README.md) and [Node.js](clients/node/README.md)
client guides for their delivery guarantees, startup patterns, and error APIs.

### Run a mutable script from cron or launchd

Ordinary grants die with their process root, so cron cannot reuse yesterday's
approval. For jobs where unattended execution matters more than script
integrity, register one exact command and reference set:

```sh
/Library/Application\ Support/ConvenientSecurity/bin/csec automation add youtube-reminders \
  --ref 'op://Personal/YouTube/client_secret' \
  --ref 'csec://mailer/refresh_token' \
  --every 3600 \
  --max-runtime 300 \
  --cwd "$HOME/projects/mailer" \
  -- /opt/homebrew/bin/node dist/youtube-reminders.js
```

The attended review states the exception plainly and Touch ID materializes
device-only copies for those refs. Cron or launchd then invokes only:

```sh
/Library/Application\ Support/ConvenientSecurity/bin/csec automation run youtube-reminders
```

Do not schedule `node dist/youtube-reminders.js` directly: the unattended lease
exists only while signed csec directly supervises the stored command. The runner
uses the stored argv and cwd, strips loader and interpreter injection variables,
enforces the maximum runtime (or, for a daemon enrolled with `--max-runtime none`,
runs process-lifetime with no runtime kill), and sends output through the resident redactor.
A run outlives a csecd restart: csecd restores its lease and the runner resumes
scanning there. An update that replaces `csec` stops the run instead, so launchd
or cron starts it again under the new `csec`. A Python job may name its virtual environment's `bin/python`:
the runner keeps that path as argv[0], so Python finds the environment.
Homebrew, python.org and Xcode framework builds are supported by pinning both
their launcher and the `Python.app` executable they re-exec; their virtual
environments work too. For Xcode use the path from `xcrun --find python3`.
The script, dependency graph, ordinary inputs, and remaining environment are
deliberately mutable and therefore trusted. Re-run `automation add` with the
same name after a provider value or interpreter changes; inspect with
`automation list` and remove with `automation revoke NAME`. See
[`docs/automation.md`](docs/automation.md) for the complete boundary.

Do not put literal secrets in the reason or command arguments; those are stored
and displayed as metadata. A same-user process can also trigger a registered job
and supply its ordinary environment, which is part of this explicit trade.

## Sign in to clouds as this Mac

Long-lived cloud keys are what a trojaned dependency goes looking for:
`~/.aws/credentials`, a service-account JSON file, gcloud's tokens. csec can
make this Mac its own OpenID Connect issuer instead, with the key in the Secure
Enclave, so AWS and Google Cloud trust the Mac directly: there is no key or
refresh token on disk to steal and no SSO session to keep renewing. The gcloud
wrapper keeps its exchanged access token off disk too:

```sh
csec identity create --issuer https://macs.example.com          # one Touch ID
csec identity target add default/admin --aws-role arn:aws:iam::123456789012:role/admin --region eu-west-2
csec identity setup aws default/admin                            # AWS profile + the IAM commands to run
aws sts get-caller-identity --profile admin                      # first use in this terminal: one review
```

Each sign-in is a `csec-identity://<identity>/<target>` reference, reviewed and
granted like any secret. For AWS, csecd exchanges its token with STS itself
and hands `credential_process` the role's temporary credentials; for Google,
`csec identity setup google` installs a gcloud shell function and registers a
separate access-token reference. csecd exchanges and optionally impersonates
a service account after review; gcloud receives the access token in its process
environment, with its token cache and file logs bypassed. Same-user process
inspection can still read that environment. The client libraries retain the
executable credential file (`csec creds google`). Google takes the public key
as an upload, so nothing needs hosting. Anything else that accepts an OIDC token can take one
through `csec exec --env` or `csec get`. AWS fetches the public key from the
issuer, so whoever can write there can sign in as the Mac: `csec identity
publish --s3-bucket …` writes a bucket policy only you can change, and csecd
checks the published keys every day. The whole story is in
[`docs/machine-identity.md`](docs/machine-identity.md).

## Native encrypted files

Prefer not to depend on 1Password? Convenient Security ships its own
device-bound encrypted store. References look like `csec://<store>/<key>`, and
you create or edit a store with a built-in editor that keeps plaintext in the
signed launcher's memory — no `$EDITOR`, no temp file, and what you copy out of
it is marked so clipboard managers skip it and kept off Universal Clipboard:

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

> The native store needs the signed, provisioned build. Its keys are bound to
> this Mac and its Touch ID, and Apple never migrates them, even from a backup:
> without `csec backup`, losing the Mac or deleting the Keychain record makes
> the ciphertext permanently unrecoverable.

### Surviving the loss of this Mac

```sh
csec backup setup         # a recovery key, shown once in csec's window; one Touch ID
csec backup status        # which stores are backed up, and whether iCloud has them
csec backup restore       # on a new Mac: the recovery key in a window, one Touch ID
```

`csec backup setup` makes a recovery key and shows it once, in csec's own
window (never in the terminal, where a coding agent would read it). Keep it in
1Password, in a vault no `op://` reference of yours reads, or print it; the
window asks you to paste it back before it turns anything on, and the line
under its masked field counts the groups that went in and says when the key
checks out. One Touch ID
then seals every native store, its blob files and the SSH key catalog into
`iCloud Drive/Convenient Security Backups/<backup id>/` (`--folder` picks
another folder). From then on every store change refreshes its sealed bundle
with no extra prompt.

A bundle is the store's key record and ciphertext sealed to the recovery key's
public half and authenticated with a key only csecd holds. iCloud (and anything
else that reads the folder) sees opaque files whose names say nothing about
the stores; nothing on this Mac can open them, because the recovery key's
private half exists only in your kit.

On a new Mac, install csec and run `csec backup restore`. It takes the
recovery key in a window, lists what the backup holds (store names, counts and
backup dates, never values), and after one Touch ID puts back every store that
Mac lacks and its SSH keys. A store name the Mac already has, in either tier,
is left as it is. A Mac with no backup of its own then carries the backup on
under the same key, in a new folder of its own: no Mac ever replaces a bundle
another wrote, and a restore reads every folder its key opens, taking each
store's newest bundle. `csec backup sync` (one Touch ID) rewrites anything
`status` says is missing or changed, and `csec doctor` warns while native
stores exist with no backup. Running `setup` again moves to a new key; the old
key's folder keeps its bundles until every store's new bundle is in iCloud.
`csec backup off` stops writing bundles and leaves the folder for its key.

If you need an editor feature the built-in one lacks, you can opt into your own
`$EDITOR` — but this is a weaker mode that writes decrypted JSON to a temp file:

```sh
EDITOR='code --wait' csec edit --editor development
```

The actual editor executable is included in the reviewed plan as an unverified
consumer, and the review warns about the named plaintext file before you touch
the sensor. Choosing `--editor` is itself the acknowledgment of that file, so one
Touch ID authorizes the edit, as it does for the built-in editor; the editor and
its plugins can read every value in the store. Either editor's session lasts as
long as the editor does: nothing expires an edit you still have open, so a long
session never costs you your changes, and csec reclaims the session of an editor
that exits without saving.

A file `csec protect` stored stays in its store until you delete it, even after
`csec ssh remove` or a retired key. To delete it:

```sh
csec edit --remove csec://ssh-keys/_Users_me_.ssh_id_rsa.old_8d268bf0ed90
```

One Touch ID, in a panel that names every value it deletes (up to six from one
store at a time), and its grants go with it. csec refuses a value its SSH
agent, GitHub socket or an automation job still uses, and one whose `.csec`
sidecar is still where you protected the file from; it cannot see a copy of a
sidecar elsewhere, which stops resolving.

## Keeping secrets out of AI tool output

AI commands use csec to access secrets. `csec ai` and its `tool-exec` alias
refuse direct `op` commands with “use csec” guidance, including literal absolute
paths. A PATH shim shipped in the app bundle also refuses `op` invoked by child
tools, so it works even in a sandbox that allows no writes. It is applied after
login-shell startup and remains active if csecd is unavailable.
Use `csec exec -- <consumer>` with secret references in its environment, or the
csec SDK, so the resident provider can reuse its authorized connection.
The shim prevents accidental CLI use; arbitrary code can replace PATH or invoke
an absolute path internally. Ordinary terminal use of `op` is unchanged.


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
csec hook-config claude          # → merge into ~/.claude/settings.json
csec hook-config codex --system  # → the managed /etc/codex/hooks.json document
```

The hooks never grant a command more than the client's own permission system
would. Claude Code receives the rewrite with no permission decision, so its
permission rules, auto-mode classifier and prompts still decide on
`csec ai -- <command>` (an `allow` would have skipped all three for every Bash
call). A Claude Code command already written in the hook's own form
(`csec ai -- ls -la`, or `csec ai -- '<command>'` quoted as the hook quotes it)
runs as typed, registered the same way, so auto mode's verdict on it stands and
it is not wrapped twice. On Claude Code 2.1.314 and later, any rewrite leaves
auto mode with no verdict, so the call is blocked and must be resubmitted.
`csec setup shell-prefix` fixes that. It makes csec Claude Code's
`CLAUDE_CODE_SHELL_PREFIX`, so each Bash and Monitor command runs under
`csec ai` after auto mode has reviewed it, and the hook no longer rewrites it.
Hook and MCP server commands, which Claude Code also passes to the prefix, run
unwrapped as before. `csec setup shell-prefix --remove` takes it away again,
and `csec uninstall` removes it first. Codex requires an `allow` around a rewrite, but it grants nothing: the
sandbox, approval policy and reviewer still run. Because Codex's
dangerous-command check, its `prompt`/`forbidden` rules and its `apply_patch`
interception cannot see inside the wrapper, csec leaves commands those gates
could catch unwrapped, so Codex judges the original. csec reads Codex rules
files written as literal `prefix_rule(…)` calls; while a rules file uses
anything else, every Codex command is left unwrapped and `csec doctor` names the
file. The managed Codex hook applies to every macOS account on the Mac, and
Codex's `features.hooks = false` turns it off (`csec doctor` reports that). Client permission rules match the rewritten
`csec ai -- …` form (Claude Code sees a plain git command as typed; see
below). In Claude Code's manual mode that means every Bash call
prompts (the wrapped command is never recognized as read-only, and allow rules
written for bare commands no longer match), and a deny rule on the inner command
becomes a classifier hint in auto mode or a prompt in manual mode rather than a
hard deny. A rule that allows `csec ai` itself (for example `Bash(csec ai:*)`,
or a Codex `prefix_rule(["csec", "ai"])`) pre-approves every command;
`csec doctor` warns about one.
Every hook failure blocks the command with a reason, and the hook has 30 s
before a client gives up and runs the command unwrapped. A launcher that is
missing or cannot be started, as for the moment an install swaps the app
bundle, is tried again for 5 s before the command is blocked, so an install
does not deny the commands that land in it.

`csec setup` also configures Codex's sandbox to reach the current user's exact
`csecd` socket, even if its hook is already installed. A denied connection tells
the coding agent how to request an unsandboxed retry or add the socket allowance;
see [Codex sandbox setup](docs/codex-sandbox.md).

Quiet background commands retain their trusted scanner for the launcher's
process lifetime, including across hours without output. Matching state survives
the idle period. Scanner loss stops output and terminates a command that received
values. If the daemon stopped and delivered nothing to the command, the command
may finish with the remaining output withheld. When this withholding begins,
`csec ai` reports it once on stderr while waiting for the command to finish;
the final notice reports the withheld byte count and preserves the command's own
exit status. This does not extend secret access grants.

A command that cannot need a secret does not ask for any. Every command an
agent runs inherits your project's `csec_…` references, so a read-only `ls`,
`rg` or `git status` used to request them all, and the first one of a session
raised a Touch ID panel. When `csec ai` can prove a command only runs tools
that need no secret (from a fixed list, which also has file tools such as
`cp`, `mv` and `rm`, and with no checked option that starts another program),
uses `git` only to read, and expands no reference, it sends no request and runs
the command with the references removed from its environment. Anything it cannot
prove keeps the ordinary path. Its output is still scanned for every value
csecd has already released, but a command like that unlocks nothing, so it
makes no new value redactable.

Plain git commands are not wrapped in Claude Code. Claude Code refuses every
Bash command an agent isolated in a git worktree runs when it cannot tell that
its git stays in that worktree, and it cannot see inside `csec ai -- '…'`, so,
wrapped, every git command such an agent ran was refused. A command made only
of git (`status`, `log`, `diff`, `add`, `commit`, `rebase`, `worktree`, …, and
`push`, `fetch`, `pull`, `clone`, `submodule`, plus `cd`), with
literal words, joined by `&&`, `||`, `;` or newlines, with output redirections
and the `"$(cat <<'EOF' … EOF)"` commit message Claude Code writes, now reaches
Claude Code unchanged, so the agent can commit and push from its own worktree.
Its output is not masked, and it gets no secrets, which git does not need (an
HTTPS credential helper that relied on a secret `csec ai` injected fails). A
push still signs through csec's SSH agent, and auto mode can still approve it
in place of the panel (below): csecd finds the command in Claude Code's own
shell instead of under `csec ai`. `ls-remote`, `remote`, `lfs`, an alias, an option that
runs a program (`--upload-pack`, `--receive-pack`, `clone --template`,
`submodule foreach`, …), an environment prefix and anything mixed with another
program keep the wrapper. Codex is unchanged.

Because Claude Code's guard cannot see inside the wrapper, csec checks what it
wraps for an isolated agent itself. In a session or subagent Claude Code has
isolated in a worktree, a wrapped command that names git is refused, with a
reason the agent reads, unless git can only run directly in that worktree: a
`cd` only into the worktree, no `pushd`, `source`, `eval` or `export` of
`GIT_*`, `PATH` or `HOME`, no `git -C`, `--git-dir` or `--work-tree`, and git
not handed to another program (`env git`, `xargs git`, `sh -c '… git …'`, a
heredoc or pipe into an interpreter). `git log --oneline | head -3`, `git fetch
&& swift build` and `cd agent && swift build && git status` run (csec starts such a
wrapped program with a space so the guard does not take a leading git for a git
launch); a command with a quote, `$` or backslash in which git stands as a word,
such as `git log --format="%h" | head`, is still refused by Claude Code's guard,
so run that git as a plain git command. A
session whose shell has left its worktree must `cd` back with a plain `cd
<worktree> && git status` first. Without this, a wrapped `cd <main checkout> &&
git commit && git push` committed and pushed in the shared checkout.

These are egress safeguards, not a cure-all: they cover supervised stdout/stderr
and Bash and Monitor tool calls, not file writes, network sends, or other tool paths. See
[`DESIGN.md`](DESIGN.md#output-redaction-and-ai-hooks) for the exact guarantees.

### Let Claude Code auto mode approve secret use

In auto mode, Claude Code's classifier already judges every Bash command
against what you asked for. `csec setup` (step 3c, "Auto-mode approvals")
can let that verdict stand in for the Touch ID panel: after one confirmation,
a command in an interactive auto-mode session gets secrets you already
approved for the same project with no panel, one command at a time and with
no grant left behind. A project is the git repository the session runs in,
so one approval covers its main checkout, every worktree and any
subdirectory (outside a repository, it is the directory itself). You pair a
secret with a project by approving its panel
on the Mac with the Claude Code scope and the process lifetime selected; the
panel's line "Approving also lets Claude Code auto mode use these in
<project> until you revoke them" says so, and the pairing lasts until you
revoke it. SSH is simpler: any `ssh` (from `git push`, `scp`, `sftp`, `rsync`
or anything else) started under a command auto mode approved signs with no
panel, whatever ran in between (a wrapper, a script, `timeout`, an npm script,
a git hook) and whatever server it connects to. That includes the git `push`,
`fetch`, `pull` and `clone` Claude Code runs unwrapped (above). The trade-off,
which Alex chose (csec-0.11), is that anything running under an approved
command can use your SSH keys with no panel. A secret request the approved
command makes itself rides its approval the same way: a language client over
`csec bridge` (such as `av slack` reading its token), or a nested `csec get` or
`csec exec`, however deep under the command, gets secrets paired with the
project with no panel. Unlike SSH it still needs the pairing, so the first one
in a project raises one panel with the pairing line (csec-0.20). The GitHub
token behind `gh` ([GitHub token proxy](docs/github-proxy.md)) is used inside
csec and never released, so its pairing holds in every project: after one
panel anywhere, auto mode's `gh` commands in any repository use it with no
panel, and the classifier still judges each one (csec-0.46). Claude Code's own
PR lookup, the `gh pr view … --json url` it runs itself after a command that
mentions a push, and its daily closed-issues check (`gh issue list -R
anthropics/claude-code --author @me …`) use that pairing too, with no panel
(csec-0.47, csec-0.64.10). Auto mode never unlocks anything: it uses only
secrets `csecd` already holds. After a `csecd` restart the one restore panel
reopens the paired secrets of the Claude Code sessions still running that it
can; a paired `op://` secret missing from the Touch ID Keychain cache stays
locked instead, and the next command that needs it gets an ordinary panel.

Turning it on sets `autoMode.classifyAllShell` in your Claude Code user
settings (so no allow rule can approve a Bash command without the classifier;
csec records that it added the key and removes it again when you turn this
off) and switches csec's `autoMode.environment` entry to tell the classifier
that its approval now releases the project's secrets. Setup first lists what
you would be trusting: other hooks that can approve shell (Bash or Monitor) commands or keep
Claude Code from reloading its settings, in settings files, enabled plugins,
and skill, agent and command files (each acknowledged by its
exact contents, so a changed hook asks again; a hook that runs `npx pkg` with
no pinned version, or pipes a download into a shell, is flagged, because you
would be trusting whatever it downloads), and Claude Code builds that
Anthropic did not sign (trusted by their exact code hash), and the auto-mode
classifier rules your settings give the classifier (`autoMode.allow`,
`soft_deny`, `hard_deny` and `environment` in user or managed settings), which
can tell it to approve or remove its built-in blocks. One Touch ID covers
all of it; restart open Claude Code sessions afterwards. Turning it off puts
the settings back as they were in meaning, though csec rewrites the file in
its own format.

Delegation also requires that csec has checked the **exact Claude Code image**
against its settings gate. An unchecked update uses ordinary Touch ID approval
for secret access, SSH and sudo; status and doctor explain the pause. Each
new release's loader is audited, then added to a list of checked releases csec
fetches, signed, from its release server, with no csec update needed.
Delegation resumes by itself once the list includes your image, without
repeating setup. The native installer, Homebrew and npm all install the same
image, so all three are covered. See [release verification](docs/claude-release-verification.md).

A checked image still needs inspectable settings. A managed `policyHelper` or
`policyHelpers` source uses ordinary Touch ID review on secret access, SSH and
sudo, with the same explanation on the phone: its generated policy can carry
hooks or classifier rules that csec cannot inspect.

Each source's classifier rules are acknowledged as they are, so editing a rule
pauses delegated approvals until you look. csecd asks you itself: the first
Claude Code request that waits on the change brings up one panel, "Claude
Code's Auto-Mode Rules Changed", listing each added rule and how many are
gone, and one approval, Touch ID here or Face ID on your paired iPhone,
acknowledges them and lets the waiting requests through. While the Mac is
locked it's raised only when your phone can answer it (otherwise those
requests get their usual panels, which your phone also shows), and after a
Deny each request asks on its own until csecd restarts. `csec setup auto-mode` runs just
this step too: it shows every rule that is new or changed since you last
acknowledged them, says how many are gone, and asks for one Touch ID (it also
acknowledges new hooks and trusts new builds). Until then each `csec ai`
whose approval went to Touch ID for such a reason prints a warning that
delegated approvals are waiting on setup, so the agent session can tell you.
Run straight after an install, setup waits for the restarted csecd the way
`csec doctor` does; if csecd still does not answer, it says why and exits 1,
as it does whenever it skips this step.

When delegated approvals are on, setup finishes with
`Keep delegated approvals on? [Y/n]`: Return or Yes keeps them on; No turns
them off, reverts csec's Claude Code settings and forgets every project pairing.
A closed input (stdin closed, a terminal that hung up) answers no question:
setup stops there with exit status 1 instead of taking a default.

If csecd's delegated approvals were set up in a different Claude Code settings
file than the one this `CLAUDE_CONFIG_DIR` reads (a scratch config dir, say),
setup names both files and asks `Move delegated approvals to … [y/N]`; csecd's
Touch ID sheet names both too. Moving reverts csec's settings in the old file
once the sheet is approved, so sessions that read it lose delegated approvals;
declining, or refusing the sheet, leaves both files as they were.

A `CLAUDE_CONFIG_DIR` whose settings, skills and plugins are symlinks to
`~/.claude`'s shares its acknowledgements: hooks and classifier rules found
through those links are the same `~/.claude` sources csecd already
acknowledged, so a second Claude account needs no Touch ID of its own, and
`csec setup auto-mode` from either account acknowledges a change for both.
A copy of a file, or a link to anything else, is the account's own source.

sudo works the same way: the first sudo auto mode runs in a project shows the
sudo review with a line offering to let auto mode run sudo there; after one
approval, on the Mac or the phone, a sudo the approved command runs itself (not
from a script, an npm script or a git hook, and not `sudo -E`, `-s`, `-i` or
`-e`, which hand root more than the command shows) needs no panel in that
project. sudo still keys its own five-minute ticket on the command's shell
when there is no terminal, so a second sudo in the same command never reaches
csec, as before.

New secrets or projects, other permission modes, `claude -p` and SDK
sessions, an `ssh` no approved command started (one you run in a terminal),
the first sudo in a project, and Codex still ask you, and
the panel says why auto mode did not approve ("Auto mode didn't approve this:
…"). `csec status` shows
whether it is on and, if it is inactive, why, the last reason auto mode was
turned down since `csecd` started, and how `csecd` last checked Claude Code's
code identity; `csec log --kind
delegated_release` lists what auto mode released and `csec log --kind decline`
why it declined; `csec grants` lists the pairings, trusted builds and
acknowledged hooks as `pair-…`, `build-…` and `hook-…` (a pairing with any
scripts pinned before csec-0.11 by path), and `csec revoke` removes any of them (revoking a
grant Claude Code held also unpairs what it covered, from the repository and
from the session's own directory; pinned scripts go with the pairing). Re-run `csec setup` to review new hooks or builds, or to turn it off,
which reverts the settings and forgets every pairing; `csec uninstall` reverts
them too. What this does not protect against is in
[`docs/threat-model.md`](docs/threat-model.md#delegated-approval).

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
reversible fixes. It runs ~80 checks across platform integrity, Gatekeeper,
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
accepted baseline. It stays quiet unless a previously-good control
**regresses** (firewall turned off, a new app granted Full Disk Access) — a
high-signal event that can mean malware disabling defenses. On a regression it
**notifies only**; it never mutates anything in the background, and you re-run
`csec audit` to review and re-apply. The baseline, with your exemptions, is
sealed so other programs running as you cannot edit it to hide a regression: an
encrypted file under `~/Library/Application Support/ConvenientSecurity/HostAuditBaseline/`
whose exact bytes a Keychain item only `csecd` can reach vouches for. A changed,
missing, rolled-back or unreadable baseline is notified once, recorded in `csec
log`, and reset to empty (unless `csecd` can restore its own access and the
baseline then verifies). An empty baseline has no accepted control to regress
from, so after that notification no regression is reported until you run
`csec audit` and accept a baseline again; do that as soon as you see it. A
`csec audit` whose baseline cannot be saved is notified too, every time.
`csec setup` runs the audit (report-only) automatically when onboarding
completes.

Among the developer checks, HA-F11 counts the private keys still in plaintext in
`~/.ssh` — the first directory a credential stealer copies — by whether csec's
SSH agent can hold them or they are obsolete (DSA, short RSA) or unusable, and
points at `csec setup --protect-files --scan-root ~/.ssh`. Once you have
protected them and accepted the baseline, a key an installer or agent writes
there later is a regression, so you hear about it. HA-F12 fails while the
GitHub CLI keeps a github.com token in the login keychain or in plaintext in
`hosts.yml`, where any process can read it, and points at `csec protect --gh`.
HA-F13 checks that npm, pnpm, Yarn, uv, pip, mise and Bundler each refuse
releases younger than a week, the window in which most trojaned packages are
caught and pulled. Its fix adds the one missing line to each manager's user
config file, one row per manager, unless a copy on the Mac is too old to read
it and would fail every command. A copy too old to honour the setting leaves the
finding unknown rather than passing.

The whole audit is value-free: every finding and evidence string is metadata only
— counts, kinds, enum state — never a credential value, CA name, path, or command
output.

## Installing the real agent

The at-rest cache and native store require the signed, notarized, provisioned
`.app`, which registers as a background LaunchAgent. Protected regular files
also require the signed `.pkg`; copying the app alone does not install or load
the root helper.

### From the signed package

Open `ConvenientSecurity.pkg` and follow the installer. It needs an
administrator's name and password, and it installs only on a Mac with Apple
silicon running macOS 13 or later: on an Intel Mac or an older macOS it says so
and installs nothing. It puts the app in `/Applications`, the root helper and
its LaunchDaemon in place, and `csec` on your PATH (`/usr/local/bin/csec`, a
link to the app's own copy; if something else already has that name, the
installer leaves it alone and `csec setup` says so). Then, in a terminal:

```sh
csec setup
```

Setup first checks that this Mac can take a Touch ID touch: every approval
csec asks for is one, so without a sensor csec can use (a Mac with Touch ID, or
a Magic Keyboard with Touch ID) and an enrolled finger, nothing can be approved
yet, and setup says what to fix. It then registers `csecd`, and, each after
asking, installs csec's managed Codex hook in `/etc/codex/hooks.json` when
Codex is installed and turns on the sudo review. Both are root's files, so setup
runs the package's own guarded installers through `sudo` (macOS asks for your
password first); they are the same installers described below, and the sudo
review is kept only after a harmless `sudo` it runs was approved through the new
review panel. No checkout is needed. After a package upgrade, `csec status`
says when the installed sudo review is not the package's build, and `csec
setup` updates it.

### From a checkout

One command builds and installs everything, the contextual sudo review
included:

```sh
packaging/bin/build-and-install.sh    # build, notarize, package, install, register, and verify
```

The command reuses the existing provisioning profile, fetching one through the
configured 1Password-backed release tooling when it is missing. Pass
`--refresh-profile` to fetch a new profile, `--skip-sudo` to leave the sudo
integration alone, or `--dry-run` to inspect the full plan without signing,
network access, installation, or service changes. It invokes `sudo` for
Apple's package installer and for the package's guarded Codex-hook and
sudo-integration installers (the same copies `csec setup` runs); the sudo one
keeps the new PAM module and review helper only after the new helper
approved a harmless `sudo` it runs as you (its own log trail shows it, so
Apple's fallback or another `sudo`'s review cannot stand in); LaunchAgent
registration runs as the login user. It ends with `csec doctor`, which also
refuses to call the installation healthy while the active sudo PAM line
points at a missing or stale review helper, or while `/usr/local/bin/csec` is
missing. It is the only way to install from source;
the individual stages are documented in
[`packaging/README.md`](packaging/README.md).

A signed agent prints `at-rest cache on` and persists resolved values in the
Secure-Enclave-gated Keychain. Signing, notarization, and the root-owned bridge
and helper install pipeline are documented in
[`packaging/README.md`](packaging/README.md).

### Versions, upgrades and the update notice

Every release has a version (`MAJOR.MINOR.PATCH`) and a build number, and
every csec binary carries both, with the commit it was built from:

```sh
csec --version    # csec 0.9.0 (build 4567, commit ace53c8)
```

Installing a newer package is the whole upgrade. The installer refuses a
package older than the csec already installed (it changes nothing and says
so), then restarts every logged-in user's `csecd` on the new build, and asks
you once to reopen your approvals (the restore panel described in
[After csecd restarts](#after-csecd-restarts)). If that panel does not appear,
the first request that needs a reopened approval raises it.

csec tells you when a newer release exists; it never downloads or installs
one itself. A few minutes after `csecd` starts, and then once a day, it
fetches a small release manifest from `https://convenientsecurity.app` and
checks its signature against the release keys built into csec, so a manifest
anyone else wrote is ignored. The request is a plain HTTPS `GET` with no
cookies, no query, no version and a fixed `User-Agent`; it carries nothing
about you or your Mac beyond what any connection reveals (your IP address).
When a newer release appears, one notification says so, once per release,
and `csec doctor` shows it on its **Updates** row with the download link. An
available update never makes `csec doctor` fail. A build with no release key
built in (every build until the first release key is pinned) checks nothing,
and its Updates row says the check is off. The manifest format and the
signing route are in [`docs/release-manifest.md`](docs/release-manifest.md).

### Uninstalling

```sh
csec uninstall --all    # everything csec installed on this Mac
csec uninstall          # only this account's part
```

`csec uninstall` first puts back the Claude Code settings `csec setup` changed for delegated
approvals. If it cannot write the file it prints exactly what to remove by
hand, and if `csecd` cannot say whether csec added `autoMode.classifyAllShell`
that key stays (Claude Code then classifies more, never less). Then, under one
Touch ID, `csecd` deletes the state only it can delete — its protected Keychain
items (persisted grants, pairings, delegation settings, the last-run record,
the decision log's key and checkpoints, the baseline's pointer, the native-store
backup settings), the decision log and the sealed host-audit baseline — and
writes nothing more, and csec unregisters the agent. The backup folder in iCloud
Drive stays, and its recovery key still restores it; after a reinstall, `csec
backup setup` starts backing up again under a new key.

`--all` then removes the rest, with no source checkout. It takes csec's hook
out of Claude Code's and Codex's user settings, keeping every other hook (both
fail closed, so a hook left behind would block every Bash command once the app
is gone), deletes the update-check cache in
`~/Library/Application Support/ConvenientSecurity/Updates`, and then runs the
package's own uninstaller through `sudo`
(`/Library/Application Support/ConvenientSecurity/libexec/uninstall-csec.sh`),
which, for every account on this Mac:

1. removes the sudo review: csec's lines leave `/etc/pam.d/sudo_local` first
   (putting back the file you had before csec when nothing else in it has
   changed since), then a harmless `sudo` must succeed through Apple's Touch ID
   or your password. Only then are the PAM module and the review helper
   deleted; if that `sudo` fails, `sudo_local` goes back as it was and nothing
   else is removed;
2. takes csec's handler out of the managed Codex hook `/etc/codex/hooks.json`,
   keeping any other hook (the file goes when csec's was all it held);
3. stops the root helper and deletes it and its LaunchDaemon, unmounting its
   protected-file memory disk;
4. deletes `/usr/local/bin/csec` when it is csec's link, the app, and
   `/Library/Application Support/ConvenientSecurity`;
5. forgets the package receipt.

It stops at the first step that fails and says why; every step skips what is
already gone, so once that is fixed you run the same uninstaller again with
`sudo`. Other accounts on the Mac that use csec should run `csec uninstall`
before `--all` removes the app.

Neither touches your secrets or where they are kept: the native stores and
their keys, the Keychain cache of `op://` values, the SSH key and automation
catalogs and the iPhone pairing all stay, as do Google credential files, the
gcloud shell function and Codex's csec permission profile in
`~/.codex/config.toml` (which keeps working without csec). Files you protected
still hold csec references, and only csec reads native stores, so a reinstall
picks them all up again. `--all` lists what stayed when it finishes. Delete the
approval app on your iPhone there. From a checkout,
`packaging/bin/build-and-install.sh --uninstall-sudo` still removes only the
sudo integration, by the same guarded steps.

After a reinstall, run `csec audit` to accept a new host-audit baseline; until
then no regression is reported.

Refuse the Touch ID and nothing is uninstalled: csec writes back the Claude
Code settings it had just reverted (csec's auto-mode entry, and
`autoMode.classifyAllShell` only if csec had added it), so everything is as it
was; with `--all`, the hooks and everything system-wide stay too. If it cannot write them, it names the file and the keys to put back by
hand, or you can run `csec setup`, which writes them again. If `csecd` cannot be reached,
the agent is unregistered anyway and csec tells you its Keychain items,
encrypted log and sealed baseline remain; a reinstall picks them up again.

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
| [`docs/guide/`](docs/guide/README.md) | The user guide: install and set up, everyday use, troubleshooting, uninstall, and building it yourself. |
| [`DESIGN.md`](DESIGN.md) | Full architecture, components, guarantees, and limitations. |
| [`docs/threat-model.md`](docs/threat-model.md) | What same-user malware can and can't do, and why each control holds. |
| [`docs/protocol.md`](docs/protocol.md) | The authenticated Unix-socket wire protocol (protocol v2). |
| [`docs/github-proxy.md`](docs/github-proxy.md) | The GitHub token proxy: `csec protect --gh`, the review, and the forwarding boundary. |
| [`docs/machine-identity.md`](docs/machine-identity.md) | Machine identity: signing in to AWS, Google Cloud and others as this Mac, and keeping its issuer safe. |
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
open-source licence. It grants no right to use Stateful Ltd's trademarks or
product names, including Convenient Security and csec, beyond displaying the
licence details and identifying Stateful Ltd as the origin of the software.

Report security vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md). The project is not currently accepting external
code contributions; see [`CONTRIBUTING.md`](CONTRIBUTING.md).
