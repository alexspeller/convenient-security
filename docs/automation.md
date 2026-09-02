# Unattended automation

`csec automation` is an explicit security exception for cron, launchd, and
similar jobs that cannot wait for Touch ID. It supports arbitrary commands such
as `node dist/youtube-reminders.js` without trying to hash a mutable script or
its dependency graph.

This is intentionally weaker than ordinary csec access. Enrollment trusts the
registered script, all code it loads, its arguments' inputs, its working
directory, and its ordinary environment with every registered reference until
the job is revoked. Anything running as the login user that can modify those
inputs can arrange for the next job run to disclose the values. csec cannot
make mutable same-user code safe; this command makes that trade visible and
bounded instead of silently weakening every access request.

The job name is not secret. Any process running as the login user can invoke the
signed `csec automation run NAME` entrypoint itself and choose the ordinary
trigger environment. That still launches only the stored command, but because
the command and its inputs are deliberately mutable, enrollment must treat such
a process as able to exercise the registered job on demand.

## Register and schedule a job

Use the signed installed launcher for both enrollment and execution:

```sh
/Library/Application\ Support/ConvenientSecurity/bin/csec automation add youtube-reminders \
  --ref 'op://Personal/YouTube/client_secret' \
  --ref 'csec://mailai/refresh_token' \
  --reason 'Send scheduled YouTube reminders' \
  --every 3600 \
  --max-runtime 300 \
  --cwd "$HOME/projects/mailai" \
  -- /opt/homebrew/bin/node dist/youtube-reminders.js
```

`--ref` is repeatable. `--every` is a minimum trigger interval in seconds; zero
allows every trigger. The interval and no-overlap state are memory-only and
reset if csecd restarts. `--max-runtime` defaults to one hour. The command is an
argv vector, not a shell string. For language-client access, store the Node,
Ruby, or Python runtime itself as the command rather than adding a shell wrapper.
The reason and argv are persistent review metadata: never put a literal secret
in either one. Register it with `--ref` and fetch it through the language client.

The local csecd-owned review displays the complete value-free transaction:
canonical refs, command, working directory, interpreter identity, interval,
runtime, environment mode, and the until-revoked warning. Remote phone approval
is not accepted because it cannot unlock the local materialization Keychain.

After approval, put this exact invocation in cron or launchd:

```sh
/Library/Application\ Support/ConvenientSecurity/bin/csec automation run youtube-reminders
```

Calling the stored Node, Python, or Ruby command directly is not equivalent and
does not receive unattended access.

Inspect and revoke jobs with:

```sh
csec automation list
csec automation revoke youtube-reminders
```

Re-running `automation add` with the same name performs a fresh attended review,
re-resolves every reference, installs a new revision, and deletes the old value
copy only after the replacement is durable. Use this after provider rotation or
an interpreter upgrade.

## Authorization and storage boundary

Persistent job metadata is value-free. It contains canonical `SecretRef` URIs,
the bounded command recipe, and dates; it contains no provider-private record
identifier. Enrollment resolves each ref only after the complete review and
Touch ID succeed, using `SecretResolver` exactly like ordinary access. This
keeps native, 1Password, and future providers interchangeable.

Resolved values are stored separately in csecd's Data Protection Keychain as
device-only, non-synchronizing automation materializations. They are accessible
after the first device unlock following a reboot, which permits a locked-screen
job but not a pre-unlock boot job. The combined materialization is capped at 1
MiB and 64 refs. A provider change is not fetched automatically: re-add the job
to refresh it.

Revocation invalidates any in-flight lease, deletes the materialization, and
then removes the value-free authorization metadata. If interrupted between the
last two steps, the remaining metadata has no values to release and retrying the
idempotent revoke completes cleanup. A daemon restart reloads persistent jobs
and materializations but never restores an in-flight run lease.

## Per-run checks

`automation run` asks csecd for the stored job before executing anything. csecd
requires a live authenticated product launcher, verifies the stored interpreter
path and available signing identity, refuses overlapping runs, applies the
minimum interval, and creates a memory-only lease bound to that csec PID and
process start time.

The signed runner then spawns the stored executable as its direct child with the
stored argv and working directory. A Ruby or Node language bridge can receive a
registered subset only while all of these remain true:

- the interpreter is that exact live direct child of the leased csec process;
- both PID/start-time pairs still match, preventing PID-reuse replay;
- the bridge presents the same unverified interpreter identity and standard
  direct-heap, subtree, local-development delivery shape;
- every requested canonical ref belongs to the stored job; and
- the run lease has not expired.

The automation path returns only the stored materialization. It never falls back
to a live provider without attended re-enrollment. A copied job name or run UUID
is not a bearer credential, and an independently launched interpreter has no
matching csec parent lease.

The trigger environment is supplied by whoever invokes `automation run` and is
retained for cron usefulness after removing csec,
dynamic-loader, Node, Bun, Python, Ruby, and Perl code-injection controls. This
sanitization reduces accidental substitution but is not an integrity claim: the
remaining variables and every file the command reads are trusted inputs.

Stdout and stderr use csecd's dynamic active-value redactor. A consumer can still
encode, transform, send, or otherwise disclose a value, so redaction is a leak
mitigation rather than a confidentiality boundary. The maximum runtime sends
SIGTERM to the command's process group and escalates to SIGKILL after five
seconds.
