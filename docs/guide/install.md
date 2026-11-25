# Install and set up

Installing csec is two steps: the package puts the files in place, and
`csec setup`, run in a terminal, switches each part on after asking you.
Check [What you need](README.md#what-you-need) first. Building it yourself
instead? See [Build it yourself](build-it-yourself.md); once your own package
is built and installed, the setup below is the same.

## 1. Install the package

Download `ConvenientSecurity.pkg` from
[convenientsecurity.app](https://convenientsecurity.app). The package is
signed by Stateful Ltd and notarized by Apple, so macOS checks it before it
opens. To check it yourself first:

```sh
pkgutil --check-signature ~/Downloads/ConvenientSecurity.pkg
```

It should say `signed by a developer certificate issued by Apple` and
`Notarization: trusted by the Apple notary service`, with the first
certificate `Developer ID Installer: Stateful Ltd (8RS6GD89Y7)`. If it says
anything else, do not install it.

Open the package and follow the installer. It asks for an administrator's
name and password. On an Intel Mac or a macOS older than 13 it says so and
installs nothing. It puts in place:

- the app, `/Applications/ConvenientSecurity.app`, which holds `csecd` (the
  agent that runs in the background while you are logged in) and the `csec`
  command;
- `csec` on your PATH, as `/usr/local/bin/csec`. If another program already
  has that name the installer leaves it alone, and `csec setup` tells you; use
  `/Applications/ConvenientSecurity.app/Contents/MacOS/csec` instead;
- a small root helper that protected files need, started by macOS;
- the installers `csec setup` uses for the parts that need root, under
  `/Library/Application Support/ConvenientSecurity`.

Nothing is switched on for your account yet.

## 2. Run `csec setup`

Open a new terminal window (so it finds `csec` on your PATH) and run:

```sh
csec setup
```

Setup is a guided walk-through. It explains each step, asks before it
changes anything, and is safe to run again whenever you like: steps that are
already done just say so. In order, it:

1. **Checks Touch ID.** Every approval is a touch. If this Mac cannot take
   one right now (the lid is closed, there is no Magic Keyboard with Touch ID,
   or no fingerprint is enrolled), setup says what to fix. It carries on with
   the rest, but nothing can be approved until Touch ID works.
2. **Starts the agent.** It asks to register `csecd` to start at login. If
   macOS says it is awaiting your approval, turn on ConvenientSecurity in
   **System Settings → General → Login Items**, then run `csec setup` again.
   It also tells you whether `csec` is on your PATH.
3. **Full Disk Access.** csec's host audit needs it to see which apps hold
   powerful privacy permissions. Setup opens the settings pane; turn on
   ConvenientSecurity there. Without it, those checks say "could not verify"
   instead of giving a result. Nothing else depends on it.
4. **Coding agents.** If Claude Code or Codex is installed, setup offers to
   add csec's hook, so the shell commands they run get secrets through csec
   and have released values masked from their output. Claude Code's hook goes
   in your own `~/.claude/settings.json`; setup shows the change first. Codex's
   goes in `/etc/codex/hooks.json`, which belongs to root and applies to every
   account on this Mac, so setup runs the package's installer through `sudo`
   and macOS asks for your password.
5. **Protect secret files** (optional). A sweep of your home folder for
   `.env` files, shell profile exports, SSH keys, cloud credentials and other
   tool tokens. It says where it will look and what it reads before it starts,
   sends nothing anywhere, and changes nothing until you pick files and
   confirm a plan. See [Protecting your existing secrets](everyday.md#protecting-your-existing-secrets)
   for what it does to each kind of file, and the preview note there.
6. **Claude Code auto mode** (only if Claude Code is installed, and off unless
   you turn it on). Lets Claude Code's auto-mode classifier approve secrets you
   have already approved for a project, instead of a panel each time. Read
   [Claude Code auto mode](everyday.md#claude-code-auto-mode) before you
   choose; it is a trade of some safety for fewer interruptions.
7. **The sudo review.** With it on, each `sudo` in a terminal opens a csec
   panel showing the exact command, directory and terminal before you touch
   Touch ID, instead of a password prompt that says nothing about what it is
   for. **Use Password** on the panel still falls back to the ordinary macOS
   prompt. Installing it needs root, so setup runs the package's installer
   through `sudo`; macOS asks for your password, then the installer runs a
   harmless `sudo` that you approve on the new panel. If that does not work,
   everything is put back as it was.
8. **Checks your Mac.** It can show a short, value-free prompt to paste into
   a coding agent for a deeper read-only review of the project, and then runs
   `csec audit`, which reports how this Mac is configured and offers the safe
   fixes under one touch. See [Checking your Mac](everyday.md#checking-your-mac).

It ends with a summary of what is on and what is still to do.

## 3. Check it works

```sh
csec doctor
```

`csec doctor` checks every part csec installed and repairs what it can on
its own (it restarts a stuck `csecd`, for example). When everything is
healthy it says so; otherwise each row names what is wrong and what to do.
`csec status` shows the same picture without repairing anything.

Then try a secret. Make an encrypted store called `test`:

```sh
csec edit test
```

csec asks for a touch, then a small editing window opens with the store as
JSON. Make it read `{"GREETING": "hello from csec"}` and press **Save
Encrypted**. The plaintext stays in that window's memory; only the encrypted
store is written to disk. Then:

```sh
csec_GREETING='csec://test/GREETING' csec exec -- printenv GREETING
```

A panel appears naming the secret and the command. Touch the sensor and the
command runs with `GREETING` set. It prints `[redacted: csec://test/GREETING]`
rather than the value: csec masks the values it released (eight bytes or
longer) from a command's output, so a stray `echo` cannot put them in a log or an AI tool's context.
Run it again in the same terminal and it does not ask again. That is the
whole idea; [Everyday use](everyday.md) builds on it. Remove the test store
afterwards with `csec edit test` (delete the line and save).

## Updates

```sh
csec --version
```

prints the version, build number and the commit csec was built from.

csec tells you when a newer release is out; it never downloads or installs
anything by itself. A few minutes after `csecd` starts, and then once a day,
it fetches a small signed release notice from `convenientsecurity.app`. The
request carries no cookies and nothing about you or your Mac beyond what any
connection shows (your IP address), and a notice not signed with a release
key built into csec is ignored. When a newer release appears you get one
notification, and `csec doctor` shows it on its **Updates** row with the
download link. A build with no release key built in checks nothing, and its
Updates row says the check is off.

To update, download the new package and install it over the old one. The
installer restarts `csecd` on the new version and shows one panel asking
you to reopen your existing approvals (one touch), so you do not have to
approve everything again. If that panel does not appear, the first request
that needs it raises it. Then run `csec setup` again if `csec status` says
the sudo review or a hook is out of date.

The installer refuses a package older than the one installed, and changes
nothing.
