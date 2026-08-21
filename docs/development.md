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
6. real Touch ID gates a new reference; and
7. one touch permits a cold cache read, followed by a warm read with no second
   biometric prompt;
8. the native-store spike proves a signed-but-unentitled same-UID helper cannot
   query the provisioned access-group item, and that the `.biometryAny`,
   `WhenUnlockedThisDeviceOnly` record cannot be read without an authorized
   context, then can be loaded and atomically updated with the just-evaluated
   Touch ID context;
9. `csec edit` creates only ciphertext under the documented directory, a cold
   daemon requires Touch ID, a warm granted read does not reprompt, and
   ciphertext modification plus replay of an older version both fail closed;
10. built-in editing and cancelling a synthetic store leaves no named plaintext,
    editor swap, backup, or autosave file; external `--editor` mode shows its
    plaintext warning before Touch ID, uses `0700`/`0600` workspace objects, and
    removes that exact workspace after success, invalid input, and editor failure
    (without claiming crash cleanup, secure erasure, or removal of copies);
11. the signed/notarized package installs the bridge at
   `/Library/Application Support/ConvenientSecurity/bin/csec` with every path
   component root-owned and non-user-writable, and Ruby reaches the installed
   agent through it; and
12. provisioning/notarization consume the real App Store Connect key through
   `/dev/fd/3`, leave no key file or private-key environment entry, and fail on
   a deliberately invalid signature/ticket check; and
13. interactive `csec exec` preserves input, terminal resize, Ctrl-C/Ctrl-Z,
    colors, and the target's exit status while replacing a synthetic output
    marker on both stdout and stderr; and
14. before enabling generated AI hooks globally, the installed Claude Code and
    Codex versions preserve normal allow/ask/deny and OS-sandbox behavior, run
    representative multiline Rails/Node/test shell programs correctly, block
    when the adapter exits 2, and return no raw synthetic value for the
    RuboCop/`pgrep` regression.
