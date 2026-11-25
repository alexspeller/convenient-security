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

On macOS, privacy access used by a supervised command is attributed to the
signed `csec` launcher. The release launcher carries the hardened-runtime
Calendar entitlement so explicitly enrolled jobs may use EventKit-backed
Calendar and Reminders tools, but it receives no access automatically: the user
must separately approve ConvenientSecurity in System Settings. That TCC grant
applies to any command launched under csec's responsible-process identity, not
only to one automation job. Enrollment still limits which secret references a
job can receive; it does not narrow an OS privacy grant by job name.

## Register and schedule a job

Use the signed installed launcher for both enrollment and execution:

```sh
/Library/Application\ Support/ConvenientSecurity/bin/csec automation add youtube-reminders \
  --ref 'op://Personal/YouTube/client_secret' \
  --ref 'csec://mailer/refresh_token' \
  --reason 'Send scheduled YouTube reminders' \
  --every 3600 \
  --max-runtime 300 \
  --cwd "$HOME/projects/mailer" \
  -- /opt/homebrew/bin/node dist/youtube-reminders.js
```

`--ref` is repeatable. `--every` is a minimum trigger interval in seconds; zero
allows every trigger. The interval is memory-only and resets if csecd restarts;
a run in flight keeps blocking an overlapping trigger across a restart (see
"csecd restarts during a run"). `--max-runtime` defaults to 12 hours and is measured
in awake time: a Mac that sleeps mid-run pauses the runner's cap and csecd's
lease together, and neither resumes counting until it wakes. A bounded cap stays
justified for a cron-style run that could hang with no human present. For a
long-running **daemon**, pass `--max-runtime none`: the job is authorized once at
enrollment and its secrets stay releasable for as long as the daemon process
lives, with no runtime kill and no wall-clock lease expiry — the lease ends only
when that process exits; a csecd restart does not end it. The command is an
argv vector, not a shell string. For language-client access, store the Node,
Ruby, or Python runtime itself as the command rather than adding a shell wrapper.

The interpreter is identified by its resolved path, but the job keeps the path
you gave as argv[0], symlinks and all, and the runner passes it to the
interpreter. Python finds a virtual environment from argv[0], so enrolling
`.venv/bin/python -m app` runs the venv's interpreter with the venv's packages.
Every run re-resolves that path and is refused (`policy_denied`) once it leads
to a different interpreter, as after the venv is rebuilt over a newer Python;
re-enroll then. Framework builds of Python (Homebrew, python.org, Xcode) are
supported too. Their launcher re-executes inside `Python.app` without changing
PID. Enrollment records both the resolved launcher and the app executable,
with each image's signing identity and cdhash; both must still match before a
run starts. The bridge must identify that exact app executable as the runner's
direct child. The runner executes the enrolled invoked path for these launchers
so a framework-backed virtual environment still finds its packages.

For Xcode, enroll the framework interpreter returned by `xcrun --find python3`;
`/usr/bin/python3` is Apple's developer-tool selector, not that interpreter.
Framework jobs enrolled before this support require re-enrollment. Existing
jobs do not acquire a second executable identity automatically. Custom wrappers
and other re-exec layouts are not inferred.
The reason and argv are persistent review metadata: never put a literal secret
in either one. Register it with `--ref` and fetch it through the language client.

The local csecd-owned review displays the complete value-free transaction:
canonical refs, command, working directory, interpreter identity, interval,
runtime, environment mode, and the until-revoked warning. Remote phone approval
is not offered: enrolling unattended automation is setup done at the Mac, like
editing a native store or registering an SSH key, and `csec automation run`
itself shows no review, so it has no phone leg either.

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
idempotent revoke completes cleanup. A csecd restart reloads persistent jobs and
materializations, and restores the run leases whose launchers outlived it (next
section).

## csecd restarts during a run

An update, a crash or `csec doctor` restarts csecd while jobs run, and a daemon
job runs for days. So csecd persists each run lease, value-free, in its
`automation`/`runs-v1` protected item: the run ID, the job's name, ID and
revision, the launcher's PID, start time and audit session, the awake-time
deadline and whether the lease was already invalidated. It writes behind each
change, so a lost write only means one lease is not restored. Before a
restarted csecd serves anything it reads the item once:

- a lease from an earlier boot, or whose launcher (PID and start time) has
  exited, is dropped;
- a lease whose job still has that ID and revision, whose materialization still
  matches, and whose deadline has not passed comes back live, and its values
  are registered with csecd's output redactor;
- anything else whose launcher still runs (the job was revoked or re-enrolled,
  its materialization is gone, its runtime ran out, or it was already a
  tombstone) comes back as a tombstone, so its child gets the typed automation
  denial rather than an attended panel;
- a lease csecd cannot check because the Keychain would not read the catalog
  or the materialization just then also refuses its child, but its record is
  written back as it was, so a later csecd that can read them restores it.

An item this csecd cannot read at all (a newer format, a Keychain error,
damaged bytes) restores nothing. Unlike saved approvals it is not held: it
records no decision, so the next lease change replaces it with this csecd's
own leases. A launcher whose lease was not restored stops its command, and
launchd starts the job again on a fresh lease.

A revoke writes the lease's tombstone before it deletes the job's values, and
fails, keeping them, when that write does not land, so no restart finds the
revoked run live. A retried revoke writes it again.

A restored lease never holds more than the launcher held: every record is
re-checked against the live launcher and the current catalog, and the item is
csecd-only, so a same-UID process can neither forge nor roll back a lease.

The launcher scans its command's output with a scanner that lived in the old
csecd. It checks once per turn of its loop (every 250 ms) whether that csecd
still runs, so it notices the restart within about a second even when the
command is quiet, and stderr says it is holding the output. From then on it
holds the output (up to 1 MiB per stream; past that the oldest is withheld
unscanned and counted) and, once a second, asks the restarted csecd to confirm
it holds the run's live lease (`resume_run`, which also registers the lease's
values with the redactor). When it does, the launcher opens a scanner there,
primes it with the last 256 KiB of output the old scanner saw (`prime`; csecd
returns none of it), so a value split across the restart is still matched
whole, then scans and forwards what it held, and stderr says scanning resumed.
A csecd that confirms the lease but cannot open a scanner yet (it already holds
its 32 scanner sessions, say) is asked again a second later. A stream that ends
while csecd is away waits up to 15 seconds, across the whole command, for it
to come back, so the command's last output, often what says why it ended, is
scanned rather than withheld.

Two answers stop the command instead, with SIGTERM and SIGKILL five seconds
later: a restarted csecd that holds no live lease for the run, which would not
mask the values the command already holds; and an update that replaced the
`csec` binary the launcher runs from. csecd admits only a peer whose live code
still matches its file, so it will never accept that launcher again. Either way
stderr says why, and a launchd `KeepAlive` job starts afresh under the current
`csec` with a new lease, still with no panel.

The restored matcher knows the values csecd released to automation runs that
it restored, not every value the old csecd released. A process under the
launcher that got a value some other way before the restart (through an
attended grant, say) and prints it afterwards is not masked. Output redaction
is a leak mitigation, not a confidentiality boundary.

## Per-run checks

`automation run` asks csecd for the stored job before executing anything. csecd
requires a live authenticated product launcher, verifies the stored interpreter
path and available signing identity (both launcher and consumer for framework
Python), refuses overlapping runs, applies the
minimum interval, and creates a lease bound to that csec PID and
process start time. The lease clock starts after csecd's own interpreter check
and Keychain read, on the awake-time clock the runner enforces the maximum
runtime with (`AutomationClock`), so csecd's cost is not charged to the job and
a sleeping Mac neither expires a lease the runner still honours nor extends one.

The signed runner then spawns the stored executable as its direct child with the
stored argv and working directory. A Ruby, Node or Python language bridge can receive a
registered subset only while all of these remain true:

- the interpreter is that exact live direct child of the leased csec process;
- both PID/start-time pairs still match, preventing PID-reuse replay;
- the bridge presents the same unverified interpreter identity and standard
  direct-heap, subtree, local-development delivery shape;
- every requested canonical ref belongs to the stored job; and
- the run lease is live: not past its maximum runtime, and not invalidated by
  a revoke or re-enrollment during the run (a lease restored after a csecd
  restart counts, on the same terms).

Once a bridge's parent is recognised as a leased launcher, every failure is a
typed automation error: `automation_run_expired` past the maximum runtime,
`automation_run_invalidated` after a mid-run revoke or re-enrollment, and
`policy_denied` for an interpreter change. csecd never falls through to the
attended secret-access review for such a process, which would raise an
interactive prompt for a job enrolled precisely because nobody is there to
answer one. The expired or invalidated lease stays as a value-free tombstone
until its launcher exits, and it does not block the job's next trigger.

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
mitigation rather than a confidentiality boundary. The maximum runtime, in
awake seconds, sends SIGTERM to the command's process group and escalates to
SIGKILL after five seconds.
