# Secure regular-file delivery matrix

Status date: 2026-08-22

Release decision: **HOLD for real secrets.** The source implementation and
synthetic test harness are complete. The signed, root-running physical-machine
rows below have not yet been executed. Use unique synthetic payloads only until
every pending row passes on the exact artifact and macOS versions being shipped.

## Boundary under test

`csec exec-file` is intended to keep a named regular-file payload unreadable by
an unrelated non-root process with the same login UID. It does this with a
root-owned file tree on bounded tmpfs and a one-time primary GID given only to
the approved process tree. This is not a boundary from root, an administrator
who can mutate installed privileged paths, or code inside the authorized tree.

The release claim requires all of these invariants together:

- exact signed `csec` prepares and consumes one launch, while exact signed
  `csecd` alone resolves and directly approves its payloads;
- the canonical plan/digest binds executable, argv, sanitized environment,
  cwd/stdio descriptors, file mappings, policy/output settings, caller process
  incarnation, audit session, and TTL;
- root-owned `0050` directories and `0040` single-link regular files exist only
  on a verified 32 MiB/2,048-node `nodev,nosuid,noexec,nobrowse` tmpfs;
- a boot-scoped GID is persisted before use, is neither assigned nor live, is
  never reused during that boot, and remains the complete descendant-tree tag;
- expiry, cancellation, launcher death, scanner failure, direct-child exit,
  daemonization, and helper restart fail closed according to the documented
  soft/hard-TTL semantics; and
- protected payload values never return from `csecd` to `csec`, enter argv or
  the initial environment, or appear in product diagnostics and supervised
  output.

## Automated source and synthetic evidence

`bin/ci` is the acceptance command for this section. Its fixtures contain only
synthetic bytes and the fake root helper runs unprivileged.

Automated gate: **PASS on 2026-08-22** (`bin/ci`, debug and release builds).

| Area | Evidence exercised | Gate |
|---|---|---|
| Plan and wire | Canonical digest/tamper rejection, exact outer/nested UUID binding, root wire version/nonce/digest/state shapes, bounded framing, and `SCM_RIGHTS` descriptor counts | `cs-selftest` |
| Metadata and payloads | Path traversal/prefix/duplicate rejection, environment and loader-control rejection, exact reference sets, 1 MiB/file and 4 MiB total bounds, safe GitHub `hosts.yml` quoting/injection rejection | `cs-selftest` |
| Kernel primitives | Boot-time, audit-session, supplemental/primary GID enumeration, assigned-GID and live-holder lookup | `cs-selftest` |
| File store | Descriptor-relative creation, exact synthetic modes/content, regular/single-link checks, symlink/traversal rejection, partial-failure cleanup, clean restart recovery, unexpected-entry fail-closed behavior | `cs-selftest` |
| Consumer semantics | `stat`, independent open/reopen, seek, `mmap`, fork/exec descendant reopen, clean exit, and session cleanup | `cs-e2e` + `cs-file-probe` |
| Consent and plaintext flow | Every launch repeats consent and resolution; output leak is masked; diagnostics contain no raw fixture; `root-status` reaches the authenticated synthetic endpoint | `cs-e2e` |
| GitHub profile | Ambient token authority rejected before resolution; protected `GH_CONFIG_DIR/hosts.yml` accepted by a direct synthetic `gh`; raw token absent from output | `cs-e2e` + `cs-gh-fixture` |
| Privileged attack surface | Release `csec-rootd` has no AppKit, LocalAuthentication, ServiceManagement, provider, Keychain-item, policy/UI, or agent implementation dependency | release link/symbol checks in `bin/ci` |
| Package shape | Root helper and plist paths/modes, shell syntax, plist syntax, exact code-requirement checks, and verify-before-bootstrap ordering | static checks in `bin/ci` |

Synthetic mode cannot prove root credential changes, kernel enforcement against
another same-UID process, real tmpfs flags/caps, Developer ID identity, launchd
audit-session behavior, or third-party tool compatibility.

## Signed physical-machine gate

Run these rows with a signed, notarized `.pkg` and unique non-secret markers.
Record artifact hashes, macOS build, hardware, tool versions, commands, and
value-free results. A failure blocks real-secret use; do not weaken an identity,
mode, mount, or lifecycle assertion to make a row pass.

| Area | Required observation | Status |
|---|---|---|
| Installed paths | Helper and plist are regular/non-symlink, root:wheel, non-user-writable, modes `0755`/`0644`; every controlling path is root-owned/non-writable | **PENDING** |
| Code identity | App, `csec`, and root helper satisfy exact Team ID and identifiers with hardened runtime, no `get-task-allow`, and no dangerous exception entitlements | **PENDING** |
| Minimal root image | Installed helper dependency/symbol audit matches CI and contains no provider, Keychain, Touch ID, AppKit, ServiceManagement, shell, or user-config loading path | **PENDING** |
| launchd and health | Only the verified system plist loads the root:wheel helper; `csec root-status` succeeds as the login user and refuses an unsigned/replacement server | **PENDING** |
| Peer roles | Unsigned clients, wrong signed roles, root peers, altered/re-execed peers, and agent/launcher operation swaps are rejected before body handling or response | **PENDING** |
| Socket pressure | More than 32 stalled/malformed connections or 128 retained launches cannot grow descriptors/memory without bound; five-second I/O deadlines and 60-second preparation expiry recover capacity | **PENDING** |
| tmpfs | Mount is the fixed path/type with `nodev,nosuid,noexec,nobrowse`, byte cap no greater than 32 MiB, node cap no greater than 2,048, and root-owned non-writable parents | **PENDING** |
| File metadata | Live launch has root:capability-GID `0050` directories and `0040` regular, single-link files; no path component is attacker-controlled or writable | **PENDING** |
| Same-UID rejection | Concurrent unrelated process with the same login UID gets `EACCES` for traversal/open even with the exact pathname, while the approved child and fork/exec descendant can reopen | **PENDING** |
| Credential drop | Target has login real/effective UID, capability real/effective primary GID, expected ordinary supplementary groups, joined audit session, core limit zero, only intended inherited descriptors, cwd, and stdio | **PENDING** |
| GID collisions | Assigned account groups and live process groups in `50000...59999` are skipped; cursor is fsynced before use; corruption/exhaustion fail closed | **PENDING** |
| No reuse | Repeated launches never reuse a GID in one boot, including helper crash/restart; reboot reset cannot collide with a surviving prior-boot process | **PENDING** |
| Direct and daemonized exit | Names remain while any daemonized descendant retains the GID and disappear promptly after the final holder exits; direct child exit alone does not orphan or remove them early | **PENDING** |
| Soft TTL | Names disappear at policy expiry, no new opens succeed, the tree remains alive, and a deliberately retained open descriptor remains readable only as the documented residual authority | **PENDING** |
| Hard TTL | Names disappear and every GID holder, including fork-racing/daemonized descendants, is killed; no holder remains after bounded rescans | **PENDING** |
| Launcher/scanner failure | Launcher death, explicit cancel, and injected scanner loss unlink names, terminate all holders, preserve no raw output, and leave no reusable rendezvous | **PENDING** |
| Helper restart | Restart removes stale UUID sessions before accepting work, preserves the current-boot cursor, rejects unexpected mount entries, and cannot expose old payloads to a later launch | **PENDING** |
| Terminal and audit session | GUI Terminal/iTerm and headless supported launch contexts preserve PTY input, resize, job control, signal/exit status, and expected audit session without gaining login-window UI/provider ability in rootd | **PENDING** |
| Generic consumers | Supported regular-file consumers exercise metadata, independent reopen, seek, `mmap`, fork/exec, and close/reopen patterns without plaintext in argv/environment/output | **PENDING** |
| GitHub CLI | Supported `gh` versions use only protected `hosts.yml`; ambient token/config/keyring authority is rejected pre-resolution; `auth`/`extension` paths are refused; no token enters logs/caches | **PENDING** |
| Ecosystem compatibility | Installed supported versions that cannot use `/dev/fd` (candidate libpq, kubectl, AWS, Google, or other tools) pass their real access patterns, or are documented unsupported | **PENDING** |
| Upgrade/failure recovery | Package upgrade verifies the new payload before bootout, replaces/restarts cleanly, preserves no stale file session, and a failed verification leaves no untrusted service running | **PENDING** — deterministic CI covers asynchronous bootout plus transient bootstrap rejection; signed physical upgrade and failure-injection evidence remain required |

## Acceptance record

Change the release decision only after every physical row has a linked,
value-free evidence record. Never record payloads, references, credential
values, or unredacted process environments. A supported macOS or consumer-tool
version change reopens the affected rows. Source/CI success alone is not
approval to use real secrets.
