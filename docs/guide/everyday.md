# Everyday use

Once [setup](install.md) is done, most of csec is a panel now and then and a
touch. This page covers what the panel is asking, how to put your secrets
behind references, and the handful of commands worth knowing. `csec help`
lists every command, and `csec help <command>` explains one.

## Approving a request

The first time a program asks for a secret, csec shows one panel. Before you
touch the sensor, it shows:

- **which secrets**, by reference (`op://Work/Database/password`), never
  the value;
- **who is asking**: the terminal tab it came from, and the whole command
  about to run;
- **where the value goes**, with a warning when other programs running as
  you could read it there (an environment variable, say);
- **how wide the approval is**: just this command, Claude Code (or Codex) and
  everything it runs, or everything started in this terminal. The default is
  the coding agent if one is running the command, otherwise the terminal.

Touch the sensor to approve. Press **Deny** or Escape to refuse. A refused
request gets nothing, and identical requests already queued behind it are
refused with it, so a burst of retries does not ask the same question again.

The panel's buttons wait until you have stopped typing for a moment, and
keyboard focus rests where a stray Space or Return does nothing, so a
sentence you were typing when the panel appeared cannot answer it. The
Touch ID you used to unlock the Mac never counts: each request asks for its
own touch.

**How long an approval lasts.** By default, as long as the process you
approved keeps running: close the terminal or quit the agent and the
approval goes with it. There is no clock on it, so a long session is not
interrupted. On the panel you can choose 1 or 12 hours instead. Approvals
survive a `csecd` restart (after an update, say: one panel reopens them all)
but not a reboot.

A panel never outlives the command that raised it: press Ctrl-C or close
the tab and it closes. A request from Claude Code or Codex that nobody
answers is withdrawn after 20 minutes, and the agent's command fails saying
approval was not given; a request from your own terminal waits until you
answer.

To see and cancel approvals:

```sh
csec grants          # every live approval, what it covers and until when
csec revoke <id>     # cancel one (the start of its id is enough)
csec revoke --all    # cancel everything
csec log             # what was approved, refused or withdrawn, and by whom
```

The log never holds a secret value.

## Secret references

A reference names a secret without containing it:

- `op://Vault/Item/field` reads from 1Password. csec talks to the 1Password
  app through its desktop integration: in 1Password, open **Settings →
  Developer** and turn on **Integrate with other apps** and **Integrate with
  1Password CLI**, and install the [1Password CLI](https://developer.1password.com/docs/cli/get-started/)
  (`op`), which csec uses to list your accounts. If you have more than one
  1Password account, csec finds the one that holds the vault.
- `csec://store/KEY` reads from csec's own encrypted store on this Mac.
  `csec edit <store>` opens a store for editing; `csec edit csec://store/KEY`
  sets one value from a hidden prompt.

csec's own stores are tied to this Mac. **Back them up**, or losing the Mac
loses them:

```sh
csec backup setup     # shows a recovery key once, in csec's own window
```

Keep the recovery key somewhere safe away from this Mac (a password manager
vault no reference of yours reads, or on paper). From then on every change
is backed up, sealed to that key, in iCloud Drive. On a new Mac, install csec
and run `csec backup restore`. `csec doctor` warns while you have stores with
no backup.

## Using secrets in commands

Keep references in your environment under a `csec_` prefix, so nothing
mistakes them for real credentials, and run the command through `csec exec`:

```sh
export csec_DATABASE_URL='op://Work/Database/url'
csec exec -- bin/rails server
```

The command gets `DATABASE_URL` with the real value; your shell keeps only
the reference. One approval covers the server and everything it starts.

`csec exec` puts the value in the command's environment, which other
programs running as you can read while it runs, and the panel says so. Where
a tool supports something narrower, prefer it:

| Tool | Narrower route |
|------|----------------|
| AWS CLI and SDKs | `credential_process` with `csec creds aws`, or sign in as this Mac with no stored key (`csec identity`, see [machine identity](../machine-identity.md)) |
| Git over HTTPS | a credential helper: `csec creds git` |
| Tools that read a config file (`psql`, `kubectl`, `npm`) | `csec exec-fd --preset …`, which hands over the file through a descriptor, never the disk |
| GitHub CLI | `csec protect --gh`: the token stays inside csec and `gh` never sees it |
| Fly.io CLI | `csec protect --fly`, then run `csec fly` |
| SSH | `csec protect --ssh ~/.ssh/id_ed25519`, then use csec's SSH agent (`eval "$(csec ssh env)"`) |
| Your own Ruby or Node.js app | the language clients in `clients/`, which receive values straight into memory |

The README's [Run an existing tool with secrets resolved](../../README.md#run-an-existing-tool-with-secrets-resolved)
and the sections after it show each one.

To print a value yourself, `csec get` works into a pipe or a variable:

```sh
csec get 'op://Work/API/token' | pbcopy
token="$(csec get 'op://Work/API/token')"
```

It refuses to print straight to the terminal, where it would sit in the
scrollback, unless you add `--reveal`, and refuses to write it to a file
unless you add `--allow-plaintext-file`.

## Protecting your existing secrets

```sh
csec setup --protect-files --dry-run   # see what it would do; changes nothing
csec setup --protect-files             # pick files and confirm
csec protect <file>                    # protect one file you name
```

The sweep looks through your home folder for `.env` and `.envrc` files,
secrets exported from shell profiles, SSH keys, cloud credentials and around
fifty well-known tool token files. In the list, Space picks a file, `/`
filters, and Enter shows the plan before anything changes. For each kind it
does the sensible thing:

- **env files and shell exports**: each secret moves into an encrypted store
  and the line becomes a `csec_NAME="reference"`; the rest of the file stays;
- **SSH keys**: held by csec's SSH agent, which signs only for Apple's `ssh`
  and only after you approve the server;
- **AWS credentials**: moved into the store, with `credential_process` set up
  in `~/.aws/config`;
- **other key and token files**: encrypted whole, and put back for the tool
  that reads them when you run it through `csec exec`.

Values are always safely stored before any plaintext is removed, an import
never overwrites a value already stored, and `--keep-plaintext` stores
copies without touching the originals. Files with more than one hard link
are refused, unless every link is found and you choose whole-file
protection.

> **Preview.** Files encrypted whole are put back for each launch by csec's
> root helper, on a small memory disk only that launch can read. The helper's
> release check on a signed, installed Mac has not been run yet, so treat
> whole-file protection as a preview: keep your own copy of anything it
> protects until a release says the check has passed. References in env
> files, SSH keys and AWS profiles do not depend on the helper.

Bulk setup reports credential-shaped environment fields in Claude and Gemini MCP
server settings. Review those fields in the client and use the server's supported
sign-in method where available. The client can rewrite its settings during use.
Bitcoin Core and Electrum also update their wallet files. Use Bitcoin Core's
wallet backup or Electrum's **File → Save backup** to make a consistent copy.
These findings stay out of the bulk picker and glob rules.

### Backing up a GnuPG key

GnuPG manages its live key directory. Its entries can represent software keys
or pointers to a hardware token. For an exportable software key, you can protect
a separate backup with csec. In a new, private directory on an encrypted volume,
substitute the fingerprint of the one key to back up for `YOUR_FULL_FINGERPRINT`.

```sh
umask 077
gpg --output key-backup.gpg --export-secret-keys YOUR_FULL_FINGERPRINT &&
  csec protect --whole-file ./key-backup.gpg
```

If protection is interrupted, the export may still be in that directory. Keep
the live key and your existing recovery copy. To import the snapshot, run this
from the backup directory on a Mac with access to its csec store.

```sh
csec exec -- gpg --import ./key-backup.gpg
```

csec gates access to the export. The live or restored key is still available to
GnuPG under its own passphrase and agent-cache rules. Later changes need a fresh
backup. A smartcard stub cannot restore a lost hardware key. [GnuPG export and import commands](https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html)

## Coding agents

With the hook from `csec setup`, every shell command Claude Code or Codex
runs goes through `csec ai`. It resolves the `csec_` references the command
needs (one panel, then covered for that session) and masks any value csec
released from the command's output, so a stray `echo` or a verbose log does
not put a live secret in the agent's context. Commands that provably need no
secret, like `ls` or `git status`, ask for nothing. Direct `op` commands are
refused with a pointer to csec, so the agent does not open 1Password behind
your back.

When an agent's command is waiting for you, it prints one line saying so and
when it will give up, so the agent can tell you it is stuck.

These are safeguards on shell output, not a cure-all: they do not cover
files an agent writes or what it sends over the network.

### Claude Code auto mode

In auto mode, Claude Code's classifier already judges each command against
what you asked for. If you turn on delegated approvals (`csec setup`, or
`csec setup auto-mode` on its own), that verdict can stand in for the panel,
but only for secrets you have already approved for the same project: approve
a panel once with the Claude Code scope and the default lifetime, and the
panel's pairing line says that auto mode may use those secrets in that
project from then on. SSH signing under a command auto mode approved needs no
panel at all.

This is a real trade-off. The classifier can be wrong or be talked round, and
a command it approves gets every secret paired with the project. Setup lists
the other hooks and settings you would be trusting before you turn it on.
`csec revoke` cancels a project's pairing (`csec grants` lists them), and
`csec setup auto-mode` turns delegated approvals off again. When Claude Code
updates to a build csec has not checked, delegated approvals pause, and you
get ordinary panels until you trust the new build in `csec setup auto-mode`
(one touch).

## Checking your Mac

```sh
csec audit                # report, then offer the safe fixes under one touch
csec audit --report-only  # report only
```

The audit runs about eighty value-free checks: firewall, Gatekeeper,
FileVault, which apps hold Full Disk Access or Accessibility, launch agents,
writable folders on your PATH, plaintext keys in `~/.ssh`, whether your
package managers refuse brand-new releases (a week's wait catches most
poisoned packages), and more. Safe, reversible fixes are offered as one
checklist under one touch. Anything that could break a legitimate setup
(revoking an app's permission, removing a certificate) is shown with the
evidence and left to you.

Once you have accepted a result, csec re-checks every day and notifies you
only when something that was fine gets worse, such as the firewall being
turned off or a new app getting Full Disk Access. It never changes anything
in the background; run `csec audit` to look and put it right.

## sudo

With the sudo review on, `sudo` in a terminal opens a csec panel showing the
exact command, the directory and the terminal tab. Touch to approve, or press
**Use Password** for the ordinary macOS prompt. An unanswered sudo review
closes after five minutes and sudo fails.

## When something seems wrong

`csec status` shows every part, `csec doctor` repairs what it can, and
[Troubleshooting](troubleshooting.md) covers the common problems.
