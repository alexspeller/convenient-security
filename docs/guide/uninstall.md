# Uninstall

```sh
csec uninstall --all    # everything csec installed on this Mac
csec uninstall          # only your account's part
```

Both need no download and no source checkout.

## What `csec uninstall` does

For your account:

1. It puts back the Claude Code settings `csec setup` changed for delegated
   approvals and the shell prefix. If it cannot write the file, it prints
   exactly what to remove by hand.
2. Under one touch, `csecd` deletes what only it can delete: your saved
   approvals and project pairings, its settings, its decision log and the
   host-audit baseline.
3. It stops `csecd` and removes it from your login items.

Refuse the touch and nothing is uninstalled: the Claude Code settings are
written back as they were, and with `--all` the hooks and everything the
whole Mac shares stay too.

## What `--all` adds

After your account's part, it takes csec's hook out of your Claude Code and
Codex settings, keeping every other hook (a csec hook left behind with csec
gone would block every shell command those agents run), and deletes csec's
update-check cache. Then it runs the package's own uninstaller through
`sudo`, so macOS asks for your password.
That uninstaller, in order:

1. removes the sudo review. csec's lines leave `/etc/pam.d/sudo_local`
   first, then a harmless `sudo` must still work through Apple's own Touch ID
   or your password. Only then are the review's files deleted. If that `sudo`
   fails, `sudo_local` goes back as it was and nothing else is removed, so
   `sudo` keeps working either way;
2. takes csec's hook out of Codex's system file, `/etc/codex/hooks.json`,
   keeping any other hook;
3. stops the root helper and deletes it;
4. deletes the `csec` command link, the app and
   `/Library/Application Support/ConvenientSecurity`;
5. tells macOS the package is no longer installed.

It stops at the first step that fails and says why. Every step skips what is
already gone, so once you have fixed the problem, run it again: `csec
uninstall --all` while the app is there, or the line it printed,
`sudo "/Library/Application Support/ConvenientSecurity/libexec/uninstall-csec.sh"`.

If other accounts on this Mac use csec, have each of them run
`csec uninstall` first: `--all` removes the app they share.

## What stays, on purpose

Uninstalling never touches your secrets or where they are kept:

- csec's encrypted stores and their keys, and its cache of 1Password values;
- your SSH key and automation lists;
- the encrypted backup in iCloud Drive (your recovery key still restores it);
- Google Cloud credential files and the gcloud shell function, if you set
  them up, and Codex's csec permission profile in `~/.codex/config.toml`,
  which keeps working without csec.

`--all` lists what stayed when it finishes. Files you protected still hold
csec references, and only csec can read its stores, so if you reinstall,
everything picks up where it left off. After a reinstall, run `csec audit`
once to accept a new baseline for the daily check.

**If you are leaving csec for good**, put your secrets back where your tools
expect them *before* you uninstall, while csec can still read them: open
each store with `csec edit <store>` and copy the values out, or move them
into 1Password. Once csec is gone, nothing else can open its stores.