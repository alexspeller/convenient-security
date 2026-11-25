# Codex sandbox access to csecd

Run `csec setup` in a terminal. Its Codex step configures both the protected-output
hook and local agent access under one confirmation, including when the hook is
already installed. Setup obtains the socket path from the same macOS per-user
lookup as the daemon, so no machine-specific path needs to be copied. Different
users and Macs have different paths; setup recomputes it on each run.

Setup updates the selected permission profile, or creates a profile inheriting
Codex's workspace/read-only filesystem rules. It preserves existing comments,
unrelated settings, file modes, and active network rules. Symlinks, hard links,
concurrent edits, unsupported inline permission tables, and configurations whose
dormant permissions would be activated unexpectedly are refused. A new hook is
not installed if its socket configuration cannot be prepared safely.

Repeated setup reuses an unreferenced, unchanged csec-generated profile rather
than creating another numbered copy. It also removes unused copies matching
the original generated shape. Selected profiles, inheritance and named launch
references, customized profiles, and profiles for another socket are preserved.
After the managed hook is installed, setup removes csec's user-hook description
even when other hooks remain, and removes its obsolete positional trust state
only when that slot has no surviving handler and its ownership can be established.
Other hooks and their trust records remain intact.

Before changing an existing Codex file, setup saves its exact original bytes in
an owner-only sibling named `config.toml.csec-backup-<uuid>` or
`hooks.json.csec-backup-<uuid>` and prints the path. These copies can restore the
pre-setup configuration. Setup writes the TOML before removing the old hook and
description; if the TOML cannot be prepared or written safely, that migration
evidence remains for the next run.

`csec ai` needs the authenticated `csecd` Unix socket even for a command such as
`cat docs/architecture.md`: scanning starts before the command runs. A Codex
sandbox with networking disabled also denies this local socket. Adding its
directory to writable roots does not permit the connection. Retrying or running
`csec doctor` cannot change that sandbox policy.

A permission-denied connection (`EPERM` or `EACCES`) is not retried. `csec ai`
never refuses to run a command, so it warns at once, naming the denied socket,
and runs the command without csec: its `op://` and `csec://` references stay
unresolved, so no secret is injected, and its output is not scanned. The warning
tells the coding agent to retry the original command through its normal approval
flow without the sandbox (`sandbox_permissions="require_escalated"` in Codex), or
add the displayed socket entry to the active profile. It also points to
`csec setup` for automatic configuration. A daemon that cannot be reached gets a
reconnect window of up to 2 seconds before the same warn-and-run, with
service-repair advice (`csec doctor`). Trust and protocol errors retain their own
diagnostic instead of being reported as a daemon outage.

For a supported Codex configuration, allow the **exact agent socket** in the
selected [permission profile](https://learn.chatgpt.com/docs/permissions#network-permissions).
Its pathname is value-free and can be obtained in an ordinary terminal:

```sh
printf '%sconvenient-security-%s/agent.sock\n' "$(getconf DARWIN_USER_TEMP_DIR)" "$(id -u)"
```

For manual configuration, merge the following into the existing profile,
retaining its filesystem rules and any existing network policy; substitute that
socket pathname and the actual profile name. The hook itself never changes
permissions:

```toml
[features]
network_proxy = true

[permissions.my-profile.network]
enabled = true

[permissions.my-profile.network.unix_sockets]
"/private/var/folders/EXAMPLE/T/convenient-security-501/agent.sock" = "allow"
```

On the verified Codex 0.153.4 runtime, both the active network proxy and
`network.enabled = true` are required for the profile's socket allowlist to take
effect. With no allowed domains the proxy denies external destinations; keep
the proxy enabled, because `network.enabled = true` alone permits unrestricted
direct network access. Do not set `dangerously_allow_all_unix_sockets`. Select
the amended permission profile in Codex and start a new chat if the active
session still carries its old policy. App-managed profiles can override local
defaults, so verify the effective policy with a sandboxed `csec ai` command:
with the socket allowed it runs with no `agent socket access denied` warning.

For an isolated check, the same installed runtime supports
`codex sandbox -P my-profile --allow-unix-socket /exact/path/to/agent.sock -- csec ai -- 'printf sandbox-ok'`.
This adds one socket exception for that test without editing configuration or
enabling network access in the profile. The supervised command inherits the
remaining filesystem and network restrictions. A real macOS sandbox regression
checks that permitted socket access restores redaction while a denied child
write remains denied; live Codex checks also rejected unrelated Unix sockets,
direct TCP, and proxy requests to local services.

Desktop visibility is separate from socket access. If `bigarrow doctor` sees
no displays or an app-window target reports an empty app list, see
[Desktop pointers from coding-agent commands](desktop-pointing.md) for the
tested per-command escalation route. Drawing and app-only window targeting
can work without Accessibility or Screen Recording grants.
