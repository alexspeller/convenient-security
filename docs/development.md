# Development and verification

Run the complete synthetic suite from the repository root:

```sh
bin/ci
```

It builds every Swift target, runs the framework-free core checks, exercises
mutual identity and protocol behavior over real Unix sockets, runs the Ruby
unit suite, and performs a Ruby → `csec bridge` → Swift fake-agent cross-stack
round trip. It also syntax-checks release scripts/plists and proves the
synthetic inherited-fd key handoff used by Fastlane. Test values are unique
synthetic fixtures; the suite must never enumerate or print the developer's
real environment.

The output-guard portion covers binary and split writes, longest-prefix
selection, stdout/stderr, canonical encodings, short-value policy, explicit
byte-exact bypass, PTY allocation/size, child exit and signal status, external
signal forwarding, and stop/continue. Assertions verify that a matched
synthetic value never reaches the downstream capture. The pre-AI suite also
checks exact hook-command quoting, active-registry cross-launch matching,
fail-closed scanner startup/interruption, and a synthetic Ruby process-title
fixture: raw `pgrep -fl` must expose the fake environment marker, while
`csec tool-exec` must return only an opaque label.

The native-store portion uses synthetic in-memory Keychain/file backends to
cover strict JSON parsing and canonicalization, mixed `op://` + `csec://`
resolution, caller-bound edit sessions, concurrent-edit rejection, AES-GCM
round trips, ciphertext mutation, valid-version replay, and restart behavior.
It also exercises the production `openat` filesystem backend in a temporary
directory, including atomic replacement, modes, and symlink rejection. These
checks do not substitute for the signed biometric Keychain gate below. External
editor checks cover bounded shell-free `$EDITOR` parsing, quoted paths, a real
edit/commit, an editor failure, the pre-edit warning, value-free output, and
temporary-workspace cleanup.

The onboarding portion uses temporary homes/projects and synthetic values to
cover supported-client detection, additive/idempotent JSON merges, explicit
legacy-hook replacement, disabled-hook policy, duplicate decoded keys,
permissions and file identity, concurrent edits, dangling symlinks, bounded
dotenv/environment discovery, interpolation refusal, reference detection,
selected native-store merging, and prompt size/value exclusion. End-to-end tests
run the actual `csec setup` dry run and apply against the authenticated fake
agent, prove dry run mutates nothing, prove only the selected key is imported,
leave the source intact, protect an existing destination, and exercise explicit
replacement. All fixture values are synthetic and assertions require that they
never appear in setup stdout or stderr.

Secure no-root delivery checks exercise session registration over the real
socket, one-prompt descendant reuse, copied/forged/stale ID rejection, and
high-risk fallback to an exact per-command root. AWS checks cover separate
fields and a strict JSON bundle with byte-exact version-1 output. Git checks
cover exact host/repository matching, mismatch-before-resolution, bounded
parsing, response injection rejection, and read-only `store` behavior. The fd
suite covers generic `--fd` plus all four presets, exact bytes, multiple distinct
high-numbered descriptors, no value in initial environment/argv/current
directory, literal argv behavior, output masking, and rejection when an
unrelated same-UID process tries the same `/dev/fd/N` path.

Secure regular-file checks use only synthetic payloads and an explicitly
unprivileged fake root daemon. Core checks cover plan canonicalization/tamper,
outer/nested request binding, path/environment rejection, bounded raw and
GitHub rendering, descriptor framing, kernel GID/process enumeration, boot-
scoped allocator inputs, descriptor-relative creation, exact modes/content,
symlink/traversal rejection, partial cleanup, and restart recovery. End-to-end
checks cover authenticated health, fresh consent/resolution per launch,
`stat`/open/reopen/seek/`mmap`, fork/exec reopen, output masking, protected
`GH_CONFIG_DIR`, ambient GitHub authority rejection before resolution, and
session cleanup. The release build is also checked to keep the root executable
free of AppKit, LocalAuthentication, ServiceManagement, Keychain/provider, and
agent-policy link/symbol dependencies. These checks do not exercise root or a
real tmpfs; the separate matrix below remains mandatory.

## Toolchain baseline

The current physical-machine baseline (verified 2026-08-21) is:

- macOS 26.2 (25C56), arm64;
- Apple Swift 6.2.4 / swiftlang 6.2.4.1.4 / clang 1700.6.4.2; and
- system Ruby 2.6.10 (the gem supports Ruby 3.0 and later for distribution;
  this older system runtime remains a useful compatibility test while present).

On that baseline, the Developer-ID-signed native-store spike passed its
signed-but-unentitled helper exclusion, non-interactive unauthenticated-read
rejection, one-touch context fold, and authenticated `.biometryAny` record
read/update checks.

GitHub CI uses the explicit `macos-15` runner label rather than the moving
`macos-latest` alias. CI is synthetic and ad-hoc signed. Developer-ID identity,
hardened-runtime/provisioning, Touch ID, cold/warm cache behavior, and native
store Keychain behavior remain a separate physical-machine release gate.

SwiftPM invokes Apple's own sandbox. In an already sandboxed automation host,
the build may need to run outside that outer restriction; a failure containing
`sandbox_apply: Operation not permitted` is an execution-environment problem,
not a compiler failure.

## Release-only checks

Before treating an artifact as protected, verify on the signed installed app:

1. `csecd` and `csec` satisfy their exact Team ID and signing identifiers;
2. a socket-replacement process is rejected before it receives references;
3. a non-product client is rejected before the agent decodes a request;
4. former environment controls cannot change consent, endpoint, or provider;
5. hardened runtime and required entitlements are present, and SIP is enabled;
6. a new reference uses one trusted policy window whose embedded real Touch ID
   is active as soon as the window is visible, without an Enter/click gate or a
   second csec authentication sheet; and
7. one touch permits a cold cache read, followed by a warm read with no second
   biometric prompt;
8. two interactive `csec get` children of one shell show that shell as the
   requester and reuse one compatible grant, while piped get cannot reuse it;
9. the native-store spike proves a signed-but-unentitled same-UID helper cannot
   query the provisioned access-group item, and that the `.biometryAny`,
   `WhenUnlockedThisDeviceOnly` record cannot be read without an authorized
   context, then can be loaded and atomically updated with the just-evaluated
   Touch ID context;
10. `csec edit` creates only ciphertext under the documented directory, a cold
   daemon requires Touch ID, a warm granted read does not reprompt, and
   ciphertext modification plus replay of an older version both fail closed;
11. built-in editing and cancelling a synthetic store leaves no named plaintext,
    editor swap, backup, or autosave file; external `--editor` mode shows its
    plaintext warning before Touch ID, uses `0700`/`0600` workspace objects, and
    removes that exact workspace after success, invalid input, and editor failure
    (without claiming crash cleanup, secure erasure, or removal of copies);
12. the signed/notarized package installs the bridge at
   `/Library/Application Support/ConvenientSecurity/bin/csec` with every path
   component root-owned and non-user-writable, and Ruby reaches the installed
   agent through it; and
13. provisioning consumes the real App Store Connect key through `/dev/fd/3`;
   notarization uses only a short-lived `0600` key file beneath an atomically
   created `0700` directory because `notarytool --key` requires a filesystem
   path; both leave no private-key environment entry, notarization removes its
   exact temporary path after success, ordinary failure, and handled signals,
   and the pipeline fails on a deliberately invalid signature/ticket check
   (without claiming cleanup after `SIGKILL`, process crash, or machine loss);
   and
14. interactive `csec exec` preserves input, terminal resize, Ctrl-C/Ctrl-Z,
    colors, and the target's exit status while replacing a synthetic output
    marker on both stdout and stderr; and
15. before enabling generated AI hooks globally, the installed Claude Code and
    Codex versions preserve normal allow/ask/deny and OS-sandbox behavior, run
    representative multiline Rails/Node/test shell programs correctly, block
    when the adapter exits 2, and return no raw synthetic value for the
    RuboCop/`pgrep` regression; and
16. a signed `csec session` gives compatible low/standard descendant helpers one
    bounded grant, a copied session ID outside the registered subtree fails, and
    high-impact access uses a fresh per-command root; and
17. real AWS `credential_process` and Git helper invocations receive their exact
    synthetic protocol response through a private pipe, reject a mismatched
    Git host/path without resolution, and create no credential cache or file;
    and
18. installed supported versions of libpq, kubectl, the AWS SDK/CLI, and Google
    authentication tooling each consume their preset once through `/dev/fd/N`,
    while a concurrent same-UID process cannot read that descriptor and no
    plaintext named file, argv, or initial-environment value is created; and
19. every signed/root row in
    [`regular-file-security-matrix.md`](regular-file-security-matrix.md) passes
    with synthetic data, including exact installed identities, verified tmpfs
    flags/caps and modes, unrelated same-UID denial, GID lifecycle/collision
    checks, daemonized descendants, launcher death, soft/hard TTL, cancellation,
    restart recovery, GUI/headless audit-session behavior, and real consumer
    compatibility; and
20. `csec setup` against fresh and existing user configurations produces the
    reviewed dry-run plan, preserves unrelated settings, appears in each
    client's effective hook/trust UI, and blocks a synthetic Bash call when
    installed `csec` or `csecd` is unavailable; a selected synthetic dotenv
    import requires Touch ID, changes only its named native-store key, emits no
    value, and leaves the source unchanged for separate remediation.
