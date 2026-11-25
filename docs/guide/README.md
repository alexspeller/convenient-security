# Convenient Security user guide

This guide is for people who use Convenient Security (`csec`) on their own
Mac: whether you bought the signed package or built it yourself. The
repository's [README](../../README.md) is the full reference; this guide is
the short way in.

| Page | What it covers |
|------|----------------|
| [Install and set up](install.md) | What you need, installing the package, the first `csec setup`, checking it works, and updates. |
| [Everyday use](everyday.md) | Approving a request, putting secrets behind references, coding agents, and the commands you will use most. |
| [Troubleshooting](troubleshooting.md) | What to do when a panel does not appear, `csecd` is not answering, or a tool stops working. |
| [Uninstall](uninstall.md) | Taking csec off this Mac, and what it leaves behind on purpose. |
| [Build it yourself](build-it-yourself.md) | Building, signing and installing csec from source under your own Apple developer account, and what the licence lets you do with it. |

## What csec is for

Most of us keep API keys, database passwords and cloud credentials where any
program running as us can read them: in shell profiles, `.env` files and
tool config files. That has always been a risk, and the steady flow of
poisoned packages and compromised extensions makes it a common one. One bad
`npm install` can copy every secret in your home folder without a prompt.

csec moves those secrets out of plain sight and hands each one over only
when you approve it with a touch. The program asking, the secret it wants
and where the value is going are all shown on the panel before you touch
the sensor. One approval lasts as long as the process you approved, so a
dev server or a coding agent session asks once, not every few seconds.
It also checks how your Mac is set up (`csec audit`) and offers to fix
the safe, reversible things it finds.

Think of it as an umbrella. It is there to keep off the wide-scale,
automated attacks that try the same tricks on thousands of machines: malware
that reads environment variables, dotfiles and keychains as you, or that asks
an always-on secrets agent for everything it holds.

## What it does not do

It is not a guarantee, and it is not a defence against someone targeting
your Mac in particular. It cannot protect a secret from:

- root, or macOS itself;
- a program you approved: once it has the value, it can do what it likes
  with it;
- you approving a request that turns out to be misleading, so read the
  panel before you touch the sensor;
- an unattended job you enrolled on purpose, or a Claude Code auto-mode
  approval if you turn delegated approvals on.

The complete list is in the README's
[What it deliberately does not protect against](../../README.md#what-it-deliberately-does-not-protect-against),
and the attacker model is in [the threat model](../threat-model.md).

## What you need

- A Mac with Apple silicon (M1 or later), running macOS 13 or later. Intel
  Macs are not supported: the installer refuses them and installs nothing.
- Touch ID that works for your account: a Mac with a built-in sensor, or a
  Magic Keyboard with Touch ID, with a fingerprint enrolled. Every approval
  is a touch, and this release has no password fallback for approvals.
- System Integrity Protection turned on, which is how Macs ship. csec
  refuses to start without it.
- An administrator's name and password, once, to install the package.

Optional:

- [1Password](https://1password.com) for Mac, if you want csec to read
  secrets you keep there. csec also has its own encrypted store, so you do
  not need 1Password.
- Claude Code or Codex, if you use them: `csec setup` connects them so the
  commands they run get secrets through csec instead of your environment.

This release is for the Mac only. Approvals happen at the Mac.

## Reporting a problem

For a suspected security vulnerability, follow [SECURITY.md](../../SECURITY.md)
and report it privately; please do not open a public issue. For anything
else, [Troubleshooting](troubleshooting.md) ends with what to include when
you ask for help. Never include a real secret value in a report.
