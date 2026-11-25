# Troubleshooting

Start here:

```sh
csec doctor
```

It checks every part csec installed, repairs what it safely can (it
restarts a `csecd` that is stuck, for example), and names what is wrong and
what to do about the rest. `csec doctor --check` diagnoses without changing
anything, and `csec status` shows the whole picture read-only.

## `csec: command not found`

Open a new terminal window: one opened before the install has an older
PATH. If it still is not found, `csec setup` says why. The package links
`/usr/local/bin/csec` only when that name is free, so if another program
already had it, use the full path,
`/Applications/ConvenientSecurity.app/Contents/MacOS/csec`, or add an alias.
If the link is simply missing, reinstalling the package puts it back.

## No panel appears, or it will not take a touch

- **"Click this window to use Touch ID"**: another app, or another Touch ID
  prompt (1Password's, say), took the focus. Click the panel and touch again.
- **The lid is closed**, or the Magic Keyboard with Touch ID is not
  connected: open the lid or connect the keyboard. The panel asks again.
- **Touch ID is locked** after too many failed attempts: lock the screen and
  unlock it with your password.
- **No fingerprint enrolled**: add one in **System Settings → Touch ID &
  Password**. `csec setup` checks all of these at its first step.
- **Only one panel shows at a time.** A request queued behind an open panel
  appears when that one is answered.
- **The panel closed by itself**: the command that asked for it ended (you
  pressed Ctrl-C, or closed the tab), or a coding agent's request waited
  20 minutes with no answer. Run the command again.

If nothing appears at all, run `csec doctor`: `csecd` may not be running.

## `csecd` is not running or not answering

- **"awaiting your approval"**: macOS is holding the login item. Turn on
  ConvenientSecurity in **System Settings → General → Login Items**, then run
  `csec setup` again.
- **System Integrity Protection is off**: `csec doctor` reports this because
  `csecd` requires it to start. Turn it on in macOS Recovery, restart the
  Mac, then run `csec doctor` again.
- Otherwise `csec doctor` restarts it. On a very busy Mac it can take a
  minute or two to start; doctor waits for it.

`csecd` keeps a log, which never contains secret values but does include
program paths from your Mac:

```sh
tail -n 50 "$(getconf DARWIN_USER_TEMP_DIR)convenient-security-$(id -u)/csecd.log"
```

## 1Password references fail

- **"the 1Password app is not running, or its app integration is turned
  off"**: open 1Password, unlock it, and in **Settings → Developer** turn on
  **Integrate with other apps** and **Integrate with 1Password CLI**.
- **"has no such vault, item, or field"**: check the reference. It is
  `op://Vault/Item/field`, with the names as 1Password shows them.
- csec needs the official, signed 1Password CLI (`op`) installed in
  `/opt/homebrew/bin`, `/usr/local/bin` or `/usr/bin`; it ignores copies
  anywhere else.
- **1Password asks you to authorize csec**: that is 1Password's own prompt,
  shown once when csec first opens a session with an account, and again
  after 1Password locks. csec never contacts 1Password unless a request you
  made needs it.

## Coding agents

- **A command fails saying approval was not given**: its request waited
  20 minutes with no answer and was withdrawn. Run it again and answer the
  panel. To give agents longer:
  `defaults write com.alexspeller.convenient-security CodingAgentApprovalWaitMinutes -int 30`
  (1 to 1440 minutes).
- **In Claude Code auto mode, every shell command is blocked and has to be
  resubmitted**: newer Claude Code builds do this to commands a hook
  rewrites. Run `csec setup shell-prefix`, which runs commands under csec
  after auto mode has reviewed them, instead of rewriting them.
- **Delegated approvals stopped and panels came back**: Claude Code updated
  to a build csec has not checked, or a hook or setting changed. Run
  `csec setup auto-mode` to see what changed and trust it.
- **`csec status` says the hook is out of date**: run `csec setup`.
- **Codex says it cannot reach csecd from its sandbox**: run `csec setup`,
  which gives Codex's sandbox access to csec's socket.

## sudo

- **The sudo review is out of date** (`csec status` says so after an
  update): run `csec setup` and accept its sudo step.
- **You need to get past the panel**: press **Use Password** for the
  ordinary macOS prompt.
- An unanswered sudo review closes after five minutes, and sudo fails
  without asking anything else.

## After installing an older package

The installer refuses a package older than the one installed. If an older
`csecd` ever does run (restored from a backup, say), it cannot read what a
newer one saved, so it keeps it untouched, and `csec doctor` names the item
and the fix. Approvals you make meanwhile last until `csecd` restarts.
Reinstalling the current package brings everything back.

## The update check

`csec doctor`'s **Updates** row says whether a newer release is out. When
it says the check is off, this build has no release key built in, so it
checks nothing; that is
expected for builds made before the first signed release, and for builds you
made yourself. An available update never makes `csec doctor` fail.

## Asking for help

Run `csec doctor --report` in a directory where you can save a file. Open
the text file it names and read it before attaching it to a support email.
Include what you ran and what you expected. The command performs a read-only
check and writes the report locally, even when the agent is unavailable.

The report includes component versions and signing status, doctor check
grades, recognised events from the last 100 daemon log lines, and recent
csec crash stacks. The local log can contain executable paths and account
metadata. Its current file and two older generations each hold up to 1 MiB.

Suspected security vulnerabilities go privately, as [SECURITY.md](../../SECURITY.md)
describes, never in a public issue.
