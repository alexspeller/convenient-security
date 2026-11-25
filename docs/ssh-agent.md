# Protected SSH keys

Convenient Security can keep an SSH private key behind any registered secret
backend and expose it to Apple OpenSSH as a destination-bound signing identity.
The SSH socket returns public identities and signatures only; private-key bytes
never cross that socket.

This is currently a manual workflow. It does not modify shell startup files,
`~/.ssh/config`, launchd configuration, or another SSH agent.

## Protect an existing key

The convenient import path uses the native encrypted store by default:

```sh
csec protect --ssh ~/.ssh/id_ed25519
export SSH_AUTH_SOCK="$(csec ssh socket)"
ssh user@example.com
```

`csec protect --ssh` first checks each key the way csecd's registration will,
and refuses, before any review, a key it would not register: passphrase-protected,
DSA, RSA under 2048 bits, a security-key handle, or a file whose private-key
content is not a readable key (wrapped in other text, truncated or corrupt).
csecd registers a batch only if every key in it parses, so without this one such
key would fail the whole batch after Touch ID. `csec setup --protect-files`
makes the same check: it encrypts an unusable plaintext key whole instead, and
leaves a passphrase-protected key alone with a warning. `csec audit` counts the
plaintext keys left in `~/.ssh` (HA-F11).

The catalog holds one entry per key, so two files holding the same key (a copy
kept as `id_rsa.old`, say) are imported and registered once, under the first
file's reference; both report that reference, both lose their plaintext and both
keep a `.pub`. csecd refuses a batch that names one key twice, or holds a key it
cannot parse, before it writes anything.

A key that `~/.ssh/config` (with its `Include`s) names by `IdentityFile` in a
block whose `IdentityAgent` is `none`, or another agent's socket, works only as a
file: `ssh` never asks csec's agent for it there. Bulk protect skips such a key,
dry run included, naming the config line, and `csec protect --ssh` refuses it
before any review. A deliberately agent-free key, such as one restricted to a
forced command so unattended pushes need no prompt, stays as it is; HA-F11 still
counts it as plaintext, apart from the keys csec can take.

`csec protect --ssh` performs one trusted review and Touch ID operation for the
whole batch. It then:

1. reads only caller-owned, non-symlink regular files;
2. imports the private keys durably into the native blob destination;
3. parses them inside `csecd` and atomically registers their canonical
   `csec://` references plus public metadata;
4. preserves an existing `.pub` file byte-for-byte, or creates one from the
   derived public metadata when it is missing; and
5. removes each original private-key file only if its identity, size, and
   modification time are unchanged since it was read.

It does not write a `.csec` sidecar. The SSH catalog already durably retains the
backend reference, and a second on-disk pointer could drift from it. Earlier
development builds did create these sidecars; SSH never reads them during
normal operation, so they may be deleted after `csec ssh list` confirms the key
is registered.

The default native store is `ssh-keys`. The useful migration controls are:

```sh
csec protect --ssh --dry-run ~/.ssh/id_ed25519
csec protect --ssh --keep-plaintext ~/.ssh/id_ed25519
csec protect --ssh --store work-ssh ~/.ssh/id_work
```

If import or registration fails, csec does not remove the originals. If a later
filesystem step fails or a source changes during review, the encrypted import
remains recoverable and the original private key remains in place; an unexpected
retained plaintext makes the command exit nonzero and names the retained path.
Unlinking a file is not secure erasure on APFS or SSD storage; backups, snapshots,
synchronized copies, and previously copied data remain outside csec's control.

## Register a key in any backend

Import and signing are separate. `csec protect --ssh` chooses a native import
destination for convenience, but SSH registration is backend-neutral:

```sh
csec ssh register 'op://Private/SSH key/private key'
csec ssh register 'future-provider://account/key'
csec ssh register ./key-protected-by-generic-csec-protect.csec
```

The named provider must already be registered with `csecd`, and the reference
must resolve to one supported private-key document. Registration presents a
trusted value-free review, obtains Touch ID, resolves through `SecretResolver`,
derives the public identity, and persists only:

- the canonical `SecretRef` URI;
- the public-key blob and algorithm;
- its SHA-256 fingerprint; and
- a bounded display label.

No SSH code depends on native blob IDs, 1Password record IDs, or provider
internals. Adding another `SecretProvider` requires no SSH signing changes.

An explicitly supplied `.csec` sidecar and the source backend retain their
ordinary semantics; `csec ssh register` accepts the sidecar as a convenient way
to read its provider-neutral reference. This is intentionally not a separate
hardware-backed or non-exportable key store: someone can still deliberately
request the referenced value through an authorized generic csec delivery, or
through the source backend's own tools. The narrower guarantee is that the
SSH-agent socket itself never exports the private key and cannot be used for
arbitrary signing.

## Manual socket and catalog commands

If csec is your SSH agent, put this in your shell profile. Otherwise, run it in
the current shell before the SSH commands that should use csec:

```sh
export SSH_AUTH_SOCK="$(csec ssh socket)"
# Equivalent:
eval "$(csec ssh env)"
```

After a successful `csec protect --ssh` or `csec ssh register`, csec checks the
launching shell's `SSH_AUTH_SOCK`. If it is unset or points elsewhere, the
command prints this profile/one-off guidance. It stays quiet when the shell is
already configured for the csec socket; it never edits a profile itself.

Catalog management stays on csec's authenticated JSON control socket rather
than the SSH wire protocol:

```sh
csec status
csec ssh list
csec ssh register --label work 'op://Private/SSH key/private key'
csec ssh remove 'SHA256:...'
```

`csec status` reports the installed app, LaunchAgent, authenticated control
channel, providers, SSH socket/key count, shell selection, remote approval, and
root helper together. `csec doctor` repairs a missing or stopped
per-user agent and verifies those live endpoints; `csec doctor --check` is
read-only. The old `csec ssh status` spelling remains only as a compatibility
alias to the complete report.

`remove` deletes only the public catalog registration and its live grants. It
does not delete the referenced value from its backend.

The catalog is a this-device-only Keychain item. With `csec backup` on, every
register and remove also rewrites a sealed bundle of the catalog (public
metadata only), and `csec backup restore` merges its keys back by fingerprint,
so keys restored to a new Mac's `ssh-keys` store are offered again without a
`register` each. `ssh-add` add/remove,
locking, agent chaining, global shell setup, and automatic SSH configuration are
not part of this first manual implementation. Setting `SSH_AUTH_SOCK` to csec's
socket also means identities from another agent are not visible through it.

## Approval and grant behavior

An import/registration approval proves that the reference contains the public
identity being catalogued. The first actual connection for a new authorization
tuple presents a separate trusted review before resolving the private key. The
tuple is:

- SSH public-key fingerprint;
- verified server host-key fingerprint;
- remote SSH username;
- the Apple SSH code identity and audit session; and
- the selected live process and its descendants.

The approved grant lasts for the lifetime of the approved session by default,
with no wall-clock cap — it is bound to the root process subtree, so it ends when
that subtree exits, not on a clock. The review offers
opt-in 1 or 12 hour bounds in the same lifetime selector every secret release
uses; the chosen value bounds the grant, and a value that was not offered falls
back to the displayed session-lifetime default. Another Apple `ssh` process in
that same subtree may reuse the grant only for the same key, host key, and remote
user. A different key, host key, username, process root, or expired process
requires a new review. This makes repeated Git/SSH operations usable
without turning the agent into ambient same-user signing authority.

SSH grants survive a `csecd` restart (not a reboot) exactly as secret grants do:
`csecd` keeps them, with no key material, in the same protected Keychain item,
and restores each one whose root process is still the same live process. A key
in a sealed store (the native store, for example) starts locked after the
restart, so the first signature a restored grant covers raises csecd's one
restore panel, a variant of the secret-access
review rather than the SSH layout, which lists the grant by key, host and user
and reopens everything it lists with one touch. "Forget these approvals" drops
the listed grants and ends the signing of each `ssh` waiting on it.
`csec grants` lists SSH grants with `ssh-` ids, and `csec revoke ssh-<id>`
drops one (a bare id names a secret grant; `--all` drops both kinds, and every
Claude Code project pairing too, SSH uses included), each written to its
Keychain item before `csec revoke` returns.

Concurrent connections of the same kind share one panel. A request no grant
covers waits its turn for the SSH review, then checks the grants again, so a
parallel fetch or several `ssh` started at once raise one review whose approval
covers the rest; a "this SSH command" approval still reviews each connection.
An `ssh` that exits while its request waits is never shown, and one that exits
while its panel is up closes the panel. A Deny ends that connection's signing — it would otherwise offer
the next catalogued key and raise a second panel — and refuses the identical
requests (same key, host key and user, offered the same default scope) already
waiting; a request made after the Deny is asked afresh. A panel that closed
because its `ssh` exited, or a Touch ID error, refuses nothing else.

The approval offers the same ancestry-based scope selector as other csec
requests. **This SSH command** roots the grant at the requesting `ssh` process;
a later sibling SSH command needs another approval. When a supported coding
agent launched SSH, its **Claude Code/Codex session** is also offered and is the
default. That scope includes the agent's commands across its temporary shells,
and jobs they detached (`( job & )`, `nohup job &`) that csecd can link back
through their session after the tool call ended (DESIGN.md §Detached jobs), but
excludes sibling coding-agent sessions.

The enclosing **terminal session**, such as fish, is offered when csec finds an
ancestor shell with a controlling terminal. It includes later SSH commands and
coding agents launched from that terminal. This is the default for direct SSH
from fish when no coding-agent ancestor exists. Only actual ancestors are
offered; an unrelated or sibling Claude process cannot be selected. With neither
a coding-agent nor a terminal ancestor, only the SSH command itself is offered.

Every option names a specific process incarnation (PID plus start time). The
dialog states the selected session and updates when a different option is
chosen. After approval, csec resolves the selection against its original offered
options and revalidates that root before resolving the key and before returning
the signature. A missing or unknown selection uses the displayed default, as
with other csec requests and phone approvals. Reused grants retain the root that
was actually approved, including an explicitly selected terminal scope.

The agent protocol supplies the cryptographic host key, not the DNS hostname.
For human context, csec reverse-matches that verified public key against concrete
names in the standard user and system `known_hosts` files, reading regular files
up to 16 MiB each. The **host** and registered **SSH key label** are the two
largest facts in the approval window. The remote username, key type, duration,
and known-host context are secondary; a **Show details** disclosure contains the
canonical secret reference and process/delivery details. Opening it grows the
window to show all of them, as the release review's delivery details do; they
scroll only when the grown window would not fit the screen
(`ReviewDisclosureFit`). Fingerprints are kept
out of the approval copy, while authorization remains bound to the verified
host-key fingerprint.

Hashed, negated, wildcard, marked, malformed, and oversized entries are omitted.
If no concrete name is available, the review explicitly shows **Unknown host**
as its headline, tinted like a warning, above an orange banner that names the
condition: no `known_hosts` name matches this server's identity, which is
expected only for a first connection or after the server's host key changed.
That banner is the SSH review's warning channel — the delivery-recipient
warnings have no meaning for a signature — and it is value-free, naming the
condition rather than the host-key fingerprint. It is also what the mirrored
phone approval renders, since both surfaces read the same review copy.
Hosts that deliberately share one host key produce multiple displayed names,
identified as sharing a server identity, and remain indistinguishable to the
authorization layer. These names are display-only. No SSH argv or process
environment is read for this context (Claude Code auto mode, below, reads
`ssh`'s argv only to match it against the approved command, and never shows
it).

## Claude Code auto mode

With delegated approvals on (`csec setup`, step 3c), an SSH signing is answered
with no panel when Claude Code's auto mode approved the command that led to it.
That is the whole rule (csec-0.11).

`csecd` judges the signing before the SSH review turn. It walks up from the
verified `ssh` to the command above it, which is one of these:

- the `csec ai` bound by its own access request;
- otherwise, the nearest `csec ai` under a shell under the Claude Code process,
  which must be the signed csec launcher;
- for a `git push` the hook left unwrapped, Claude Code's Bash tool shell.

It then checks only these facts about that command:

- csec's hook registered it;
- the hook registered it in auto mode;
- it ran in a verified Claude Code session. That means not a
  `--dangerously-skip-permissions` or Codex session, and no unacknowledged hook
  that could approve shell (Bash or Monitor) commands. The rest of
  [`DESIGN.md`](../DESIGN.md#delegated-approval)'s session checks also apply.

The key must also already be unlocked in `csecd`.

What runs between that command and `ssh` is not judged. A Python deploy lock, a
`timeout`, a script you never pinned, a script in `/tmp`, a bash heredoc,
`npm install → node → git`, or a git hook all sign. Neither is the destination:
a key, server and remote user nobody approved before sign too. Classifier rules
in your settings that `csec setup auto-mode` has not reviewed do not stop an SSH
signing, though they still stop a secret release and a sudo.

The trade-off, accepted on csec-0.11: anything running under an auto-approved
command can use your SSH keys for any server with no panel.

An `ssh` with no such command still gets the panel. That covers one you run in
a terminal, Codex's, one from a session in another mode, and one from a process
that outlived its command and was adopted by launchd. No SSH grant is minted,
so each connection is judged on its own. An SSH panel offers no pairing line.

Pairings from before csec-0.11 still list their SSH destinations and pinned
scripts in `csec grants`, and `csec revoke` still removes them, but neither
decides anything now. The rules are in [`DESIGN.md`](../DESIGN.md#ssh).

## Signing boundary

The release SSH socket is created inside csec's private `0700` runtime directory
and is mode `0600`. Every connection must be the current user's live,
Apple-signed, hardened `/usr/bin/ssh` process (`com.apple.ssh`); a copied binary,
`ssh-add`, a Homebrew SSH build, and unrelated same-user processes are refused.
The daemon revalidates the socket audit token and code identity after an
asynchronous approval/signing operation and before returning a response. Each
of those checks reads the kernel's facts for the token (`CS_VALID`, cdhash,
identifier); Apple's requirement is evaluated by Security.framework once per
`ssh` cdhash and kept for csecd's lifetime (`LiveCodeRequirement`), so a
loaded trustd delays only the first `ssh` csecd sees.

Before policy review or provider resolution, the server requires and verifies
OpenSSH's `session-bind@openssh.com` message. It checks the server host-key
signature over the SSH session identifier, rejects forwarding, and accepts only
an exact SSH user-authentication signing packet whose session, key, algorithm,
service, method, username, and host-bound key are consistent. For an OpenSSH host
certificate, csec validates its bounded canonical structure and CA signature,
verifies the session with the embedded host key, and retains the exact
certificate blob for the host-bound packet. The review fingerprint is the
underlying host-key fingerprint, matching OpenSSH's agent behavior. Unknown
agent messages and all SSH-wire catalog mutations fail closed. Agent frames are
capped at 256 KiB, and `csecd` disables core dumps before starting either socket.

After approval, the signing service resolves the canonical reference through
`SecretResolver`, reparses the private key, verifies that its public blob still
matches the catalog and the request, signs the exact validated authentication
packet, revalidates the caller/process root, and returns one SSH signature blob.

## Supported keys and current limits

The first release accepts one unencrypted private key in any of these encodings:

- OpenSSH `openssh-key-v1`;
- legacy PEM RSA PKCS#1 or EC SEC1; or
- PKCS#8 RSA, EC, or Ed25519.

Supported identities are Ed25519, ECDSA P-256/P-384/P-521, and RSA keys of at
least 2048 bits. Protected RSA identity signatures require RSA-SHA2-256 or
RSA-SHA2-512; csec never produces SHA-1 `ssh-rsa` signatures. For destination
binding only, csec can verify an `ssh-rsa` host signature when Apple SSH has
already negotiated and accepted it. This compatibility path does not enable the
algorithm or use it to sign with a protected key; it preserves destination
binding for hosts that still require a legacy RSA host signature.

Encrypted private-key documents, DSA, Ed448, FIDO/SK identity keys, identity
certificates, multi-key OpenSSH files, unknown signature flags, forwarded agent
use, and FIDO/SK host keys are not supported. Host certificates whose embedded
host and CA keys use the supported Ed25519, ECDSA, or RSA algorithms are
supported. The catalog is capped at 64 identities. These limits fail closed
rather than silently falling back to ordinary signing.

The automated suite uses generated synthetic keys at two levels. The focused
checks exercise malformed and adversarial SSH-agent frames directly. The
`cs-ssh-e2e` check removes a generated RSA private-key file, then authenticates
Apple’s real `/usr/bin/ssh` through the csec socket to an isolated, unprivileged
localhost `sshd`. The gate runs with plain Ed25519, ECDSA P-256, RSA-SHA2, and a
legacy RSA/SHA-1 host signature, plus a synthetic Ed25519 host certificate. This
is the release gate for OpenSSH framing, plain and certificate session binding,
RSA flags, and signature interoperability without touching a developer key or
an external host.

A signed/notarized physical-Mac run remains the release gate for the shipping
code-identity, Touch ID, Keychain, and provider boundaries. If OpenSSH reports
only `agent refused operation`, csecd records a value-free line in `csecd.log`
with the request type and stable reason code. A refused session binding also
records only fixed algorithm-family categories and boolean forwarding/binding
state; it never echoes an untrusted wire algorithm, key bytes, signed data,
usernames, hosts, or provider values.
