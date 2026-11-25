# Packaging, signing & install

How the resident agent is turned into a Developer-ID-signed, hardened, notarized,
provisioned `.app` + `.pkg`, how `csecd` registers as a login-item LaunchAgent,
how the package installs the separate minimal `csec-rootd` system
LaunchDaemon, and how the same wrapper builds the iPhone remote-approval app and
installs it on the paired iPhone. The signed `.app`, provisioning profile, LaunchAgent, Touch ID,
and keychain path have been proven on real hardware. The native-store access-
group exclusion, biometric ACL, and authenticated record update passed the
signed hardware spike on 21 August 2026. The `.pkg` root-owned bridge, root
helper, and inherited-fd App Store Connect key handoff are covered in source/CI;
the root helper still has the explicit signed physical-machine gate in
[`../docs/regular-file-security-matrix.md`](../docs/regular-file-security-matrix.md).

This is the maintainers' reference, and its identities (team, App IDs,
container) are the official build's. Building under your own Apple account
starts at [Build it yourself](../docs/guide/build-it-yourself.md), which says
what to change.

## What ships

```
ConvenientSecurity.app/
  Contents/Info.plist                        CFBundleExecutable = csecd
  Contents/Resources/LICENSE.md              FSL-1.1-ALv2 terms
  Contents/Resources/ai-guard/op             csec ai's direct-op refusal shim (first on AI children's PATH)
  Contents/Resources/ThirdParty/             MIT (tree-sitter, tree-sitter-bash) and ICU notices,
                                             and csec-op-bridge/: Go's and its modules' licences
  Contents/embedded.provisionprofile         authorizes the keychain access group and CloudKit container
  Contents/MacOS/csecd                        MAIN executable — the resident agent
  Contents/MacOS/csec                         the CLI + `csec install`
  Contents/MacOS/csec-op-bridge               holds one 1Password SDK session per account
  Contents/Library/LaunchAgents/com.alexspeller.convenient-security.plist

/Library/Application Support/ConvenientSecurity/bin/
  csec                                      root-owned language-client bridge copy

/Library/Application Support/ConvenientSecurity/libexec/
  install-codex-hook.sh                     the guarded installers `csec setup` (and
  install-sudo-review.sh                    build-and-install) run through sudo, and the
  sudo-review-policy.sh                     sudo_local renderer the second one sources

/Library/Application Support/ConvenientSecurity/sudo-review/
  pam_csec_sudo.so                          the sudo review's payload: what
  csec-sudo-review                          install-sudo-review.sh installs into /usr/local

/usr/local/bin/
  csec                                      link to the app's csec, made by postinstall
                                            only when the name is free (or already csec's)

/Library/PrivilegedHelperTools/
  com.alexspeller.convenient-security.rootd signed minimal root helper

/Library/LaunchDaemons/
  com.alexspeller.convenient-security.rootd.plist

/etc/codex/
  hooks.json                                managed Codex PreToolUse hook (csec's handler merged
                                            in by the package's install-codex-hook.sh, which
                                            csec setup and build-and-install run; not the .pkg)

/usr/local/lib/pam/pam_csec_sudo.so,        the active sudo review, installed from the package's
/usr/local/libexec/csec-sudo-review,        payload by install-sudo-review.sh after its live
/etc/pam.d/sudo_local (two lines)           check (csec setup or build-and-install; not the .pkg)

the paired iPhone
  Convenient Security                       com.alexspeller.convenient-security.approval, the
                                            remote-approval app: dev-signed by Xcode and installed
                                            by build-and-install's iPhone stage, not the .pkg
```

Delivered by a signed `ConvenientSecurity.pkg`, a product archive whose
distribution (`packaging/installer/Distribution.xml`) installs only on Apple
silicon and on the app's `LSMinimumSystemVersion` or later, refusing anything
else with a plain message before a file is written, and only into the system
domain, so the installer asks for an administrator. It installs the app into
`/Applications` and a second byte-identical, signed `csec` bridge at
`/Library/Application Support/ConvenientSecurity/bin/csec`, the standalone
root helper plus system LaunchDaemon plist, the setup payload beside the
bridge, and `csec` on PATH. The package makes the bridge/helper/payload and
their controlling paths root-owned/non-user-writable, verifies exact code
requirements, and loads the root helper only after those checks pass. This
matters because `/Applications` is normally group-writable by `admin`, so its
pathname alone is not a same-UID integrity boundary. The user then runs `csec
setup`, which registers the credential agent and, after asking, runs the
payload's guarded installers through sudo for the managed Codex hook and the
sudo review, so a buyer needs no checkout.

Four structural rules, each load-bearing:

- **It must be a `.app` bundle, not a bare `csecd` binary.** The restricted
  `keychain-access-groups` entitlement is only authorized by an *embedded
  provisioning profile*, which can only live at `Contents/embedded.provisionprofile`.
- **`csecd` must be the bundle's main executable** (`CFBundleExecutable`). The
  embedded profile authorizes the restricted entitlement only for the main
  executable; a *secondary* binary that claims `keychain-access-groups` is
  **SIGKILLed by AMFI at launch**. `csec` has no restricted entitlements; its
  only capability entitlement is Calendar access for supervised automation,
  which remains subject to a separate user-granted TCC decision.
- **The credential daemon remains a per-user LaunchAgent, never root.** The
  Secure Enclave, data-protection keychain, provider adapters, policy UI, and
  Touch ID are login-session-only. The separate LaunchDaemon has no provider,
  Keychain, UI, or policy capability; it only verifies two signed roles, creates
  bounded files, drops credentials, supervises the launched tree, and runs the
  host audit's closed list of fixed privileged reads and digest-bound
  reversible changes for csecd.
- **Language clients use the root-owned bridge copy.** Ruby cannot verify a
  replacement executable itself. The protected path prevents pre-launch
  replacement; the daemon then verifies the bridge's live audit token, exact
  signing requirement, hardened runtime, and entitlements before reading JSON.

## One-time prerequisites

| Thing | How | Notes |
|-------|-----|-------|
| Apple Developer membership | — | Paid. Team **Stateful Ltd**, Team ID **8RS6GD89Y7**. |
| The team and identifier in `identity.xcconfig` | the repository root: `CSEC_TEAM_ID` and `CSEC_IDENTIFIER` | The one place they are written. Every stage, the package's scripts, the plist and entitlement templates, the iPhone project, Fastlane and the tests derive the rest from them; `bin/ci` fails on a copy anywhere else. The official values are below; a build under another team changes only this file ([`docs/guide/build-it-yourself.md`](../docs/guide/build-it-yourself.md)). |
| **Developer ID Application** cert | Keychain Access → Certificate Assistant → *Request a Certificate from a CA* (save CSR to disk) → developer.apple.com → Certificates → Developer ID Application → upload CSR → download → double-click | Signs the `.app`. **Account-Holder only.** Verify: `security find-identity -v -p codesigning`. |
| **G2 intermediate CA** | Download over HTTPS from [Apple's certificate-authority page](https://www.apple.com/certificateauthority/) and verify it as shown below before importing. | A fresh Developer ID cert shows **0 valid identities** until this intermediate is installed. |
| **Developer ID Installer** cert | same CSR flow, pick *Developer ID Installer* in the portal | Signs the `.pkg`. **Different cert** from the Application one. Account-Holder only. |
| App ID `com.alexspeller.convenient-security` | developer.apple.com → Identifiers → register manually | `produce` can't (no API-key support). The access group is its default `application-identifier`. |
| CloudKit container on both App IDs | Create `iCloud.com.alexspeller.convenient-security`; enable iCloud (CloudKit) with that container on `com.alexspeller.convenient-security`, on the iPhone App ID `com.alexspeller.convenient-security.approval`, and on its notification extension's App ID `com.alexspeller.convenient-security.approval.notifications` (register either if Xcode has not); enable Push Notifications on the iPhone App ID | Every build signs csecd with the container (Production). Enabling iCloud invalidates the Developer ID profile: run `build-and-install.sh --refresh-profile`. Until the profile authorizes the container, `build-agent.sh` stops before building and names the missing keys. |
| App Store Connect **API key** (Team, Admin role) | portal → Users and Access → Integrations → App Store Connect API → Team key | Drives provisioning *and* notarization. A **Team** key (not Individual). |
| API key in 1Password | item with fields `key_id`, `issuer_id`, `key` (the `.p8` PEM) | Referenced from `packaging/.env`; private-key bytes are read just in time, never placed in env or passed as key data in argv, and use the constrained transports described below. |
| [mise](https://mise.jdx.dev) | `brew install mise` | Runs the pinned tools: XcodeGen from the repository's `.tool-versions`, and Ruby 3.3.11 from `packaging/.tool-versions` for Fastlane (Bundler 4.0.15 is recorded in `Gemfile.lock`; system Ruby 2.6 cannot run this bundle). mise installs a missing pinned version on first use; `.tool-versions` needs no `mise trust`. |
| Full Xcode signed into the team | Xcode › Settings › Accounts: the Apple ID of team 8RS6GD89Y7 | The iPhone stage builds with Xcode's automatic signing (`-allowProvisioningUpdates`): Xcode creates the Apple Development certificate and the iPhone app's development profile. |
| The iPhone | Passcode and Face ID enrolled, Developer Mode on, paired with Xcode (Window › Devices and Simulators), signed into the same iCloud account as the Mac | It must show as *available (paired)* in `xcrun devicectl list devices`; Wi-Fi pairing is enough. The phone must also be registered to the team: running any app on it from Xcode once does that. |
| Installed csec, or 1Password's CLI for a first build | A healthy resident agent and bundled CLI; on a Mac where `/Applications/ConvenientSecurity.app` does not exist, `op` with the 1Password app's CLI integration on | Packaging uses the installed broker and its normal approval policy, and fails if that broker is unavailable. Only a first build, inside `build-and-install.sh` with no csec app present, reads `op://` references with `op` instead (see the delivery paragraphs below). |
| `packaging/.env` (gitignored) | `OP_ASC_ITEM="op://<Vault>/<Item Title>"`<br>or `ASC_KEY_ID_REF`, `ASC_ISSUER_ID_REF`, `ASC_KEY_REF`<br>optionally `CSEC_IPHONE_DEVICE=<name, UDID or identifier>` | Keeps personal 1Password paths out of git. `CSEC_IPHONE_DEVICE` picks the phone when more than one is paired. See `.env.example`. |

Install the Developer ID G2 intermediate only after checking the immutable
certificate bytes currently published by Apple:

```sh
curl -fsSL \
  https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer \
  -o /tmp/DeveloperIDG2CA.cer
printf '%s  %s\n' \
  f16cd3c54c7f83cea4bf1a3e6a0819c8aaa8e4a1528fd144715f350643d2df3a \
  /tmp/DeveloperIDG2CA.cer | shasum -a 256 -c -
security import /tmp/DeveloperIDG2CA.cer \
  -k "$HOME/Library/Keychains/login.keychain-db"
```

The expected certificate subject is Apple's Developer ID Certification
Authority G2 and it expires on 17 September 2031. Re-check Apple's official page
instead of bypassing the hash check if Apple replaces it.

## The pipeline

For a complete build and local installation, use the single-command wrapper:

```sh
packaging/bin/build-and-install.sh
```

It is the one script that installs anything; the other scripts in
`packaging/bin` are the stages it runs. Before anything else it refuses a
checkout whose HEAD lacks a commit already on `origin/main` (as last fetched;
pushes move it too, so the check needs no network), naming the missing commits:
installing an unpulled `main` would replace csec with an older build and
silently take back what those commits fixed. Pull first; a rollback is a revert
on `main`. It also refuses a checkout that lacks the commit the installed app
was built from: `build-agent.sh` stamps `CSECSourceCommit` (the checkout's
HEAD) into the bundle's `Info.plist`. An ancestor passes immediately. When
rebase has rewritten the installed history, every absent non-merge commit must
have a patch-equivalent commit in HEAD (`git cherry`), and every absent merge
must have its full tree in HEAD's history. That accepts a flattened merge or
rebased branch without losing the check on merge resolutions and amendments;
a missing change or unknown commit still refuses. Use `git pull --rebase=merges`
when updating local merges, and finish pulling and pushing before installing,
so the stamp names the final history. `--allow-downgrade`
installs anyway, for a deliberate rollback; the older csecd then keeps the
saved approvals it cannot read as found, and the final `csec doctor` fails until
the newer build is back (the runtime gate mid-install does not, so every stage
still runs). A rollback to a build from before the stamp loses that
protection: such a csecd overwrites what it cannot read. An app installed
before the stamp is not compared. It then
checks that the App Store Connect key can be delivered (csec's runtime health,
or on a first build `op` and `op://` references), without reading it, so a
missing broker fails before the expensive release build, and checks that the iPhone stage at the end can run
(mise, full Xcode, and exactly one available paired iPhone). It then reuses
`packaging/build/convenient-security.mobileprovision` when present, fetches it
through `provision.sh` when absent, and — before building anything — requires
that profile to authorize every restricted entitlement csecd is signed with
(below). It builds and signs every binary, builds and
verifies the sudo PAM module and the sudo review helper, notarizes the app,
builds and notarizes the full package, and installs it with Apple's `installer`.
Immediately afterward, `csec doctor --runtime` registers or restarts the per-user
agent as needed and authenticates the control, SSH, and root-helper endpoints.
This repairs an old agent process left running against the replaced app before
any later stage can fail. A fresh `approval-restore` presence checkpoint then
runs the installed `csec restore`: the installer owns one existing restore
review while short-lived secret/SSH requests join and leave it, with the same
Mac/phone approval and requester-lifetime checks. No prompt appears if nothing
needs reopening or restoration already completed. Forget completes this stage;
cancellation, authentication, transport or incomplete reopening fails it,
and recovery does not retry the restore. The same stage then fetches the
paired values that need no csec unlock (1Password's) while someone is at the
Mac, so 1Password's own authorization of the restarted bridge is answered
now; anything not fetched is printed and never fails the stage, and is
fetched after the next csec panel approved at the Mac. Only bounded
status and a value-free fetch summary are returned; no values or new grants
reach the installer. Sudo has no csec grants to restore.
The `--only-iphone` path skips this stage because it does not restart csecd.
It then installs the managed Codex hook through
`install-codex-hook.sh` (described below) and the sudo integration through the
guarded installer described below (a further `sudo`, plus one Touch ID in the new review window for the
live check it runs as you). It verifies that every installed payload — app,
bridge, root helper, managed Codex hook, sudo module, sudo helper — matches the
build, and that the installed csecd's signature carries the CloudKit container
in the Production environment, then runs `csec doctor`, which registers or restarts the per-user
LaunchAgent, authenticates the live control channel and root helper, requires
the protected SSH socket, requires the current managed Codex hook, and requires
the installed sudo review helper to be the one the active PAM line hands off
to. Only then does it run the iPhone stage (below). Use `--refresh-profile` to force a profile refresh, `--skip-sudo` to leave
the sudo integration alone (an already active but stale integration then still
fails `csec doctor` at the end, by design; the Codex hook is still installed),
`--skip-iphone` to leave the phone alone, `--only-iphone` to run just the
iPhone stage, `--uninstall-sudo` to remove the sudo integration and do nothing
else (see [the sudo stage](#removing-the-sudo-integration)), and `--dry-run`
to print the complete plan without changing anything. Run the
wrapper as the login user: only the package, Codex-hook and sudo-integration
installers are elevated; running the LaunchAgent registration under `sudo`
would register it for the wrong user.

Rolling back is the same command run from the older tree: there is no
separate downgrade path. What a rollback keeps and what it drops for remote
approval (the pairing, the phone-held unlock and its sealed copies) is in
[`docs/remote-approval.md`](../docs/remote-approval.md), "Deployment coupling".

### Provisioning-profile preflight

AMFI kills csecd at launch when its signature claims a restricted entitlement
the embedded profile does not authorize; `codesign` itself never checks. So
`build-agent.sh` first decodes the profile's `Entitlements` (`security cms -D`,
metadata only) and compares every key of `packaging/agent/csecd.entitlements`
outside `com.apple.security.*` — application identifier, team identifier,
keychain access group, and the three iCloud keys — accepting the profile's
string, array, or wildcard (`*`, `8RS6GD89Y7.*`) values. A mismatch stops the
build before anything is compiled or signed, names each key, and gives the fix;
for the iCloud keys that is to enable iCloud with the container on the App ID
and rerun with `--refresh-profile`. A Developer ID profile issued before iCloud
was enabled on the App ID fails this check by design.

### iPhone stage

The iPhone remote-approval app is part of the stack, so the wrapper installs it
too, after the Mac side has passed `csec doctor` and `csec status`. It has no
stage script; the wrapper runs:

1. `mise exec -- xcodegen generate` on `ios/project.yml` with the XcodeGen
   pinned in `.tool-versions` (the generated `.xcodeproj` is untracked; the
   generated `Info.plist` is tracked and reproduced byte for byte);
2. `xcodebuild` of the Debug configuration for `generic/platform=iOS` into
   `packaging/build/ios/DerivedData`, with `-allowProvisioningUpdates
   -allowProvisioningDeviceRegistration`, so Xcode's automatic signing
   produces an Apple Development build, and a build number of
   `CURRENT_PROJECT_VERSION` plus a per-build stamp;
3. re-signs the embedded notification extension and then the app (whose seal
   covers the extension) without `get-task-allow`: for each, `codesign
   --display --extract-certificates --entitlements -` reads the entitlements
   Xcode signed and the certificate it signed with, and `codesign --force
   --sign <that certificate's SHA-1> --entitlements <the same, minus
   get-task-allow> --timestamp=none --generate-entitlement-der` replaces the
   signature; it then checks that the app and the extension are this run's
   build, are signed for the Mac's CloudKit container in Production, and carry
   no `get-task-allow` — a debuggable or missing extension stops the stage like
   a debuggable app;
4. picks the phone: `CSEC_IPHONE_DEVICE` from `packaging/.env` when set,
   otherwise the one physical, paired, available iPhone `xcrun devicectl list
   devices` reports (none, or more than one, stops with guidance);
5. `xcrun devicectl device install app`;
6. reads the installed app back with `xcrun devicectl device info apps` and
   requires the build number and version it just built.

The Debug configuration is the dev-signed build: CloudKit **Production** (the
only environment a Developer ID Mac can reach, so both sides share one
mailbox) with the **development** push environment, the only one a development
profile allows. Release keeps production push for a future App Store build.
The Simulator-only test backend is compiled out of a device build.

Why the re-sign: development signing always adds `get-task-allow`, which would
let a debugger attach to the approval app from this Mac through the paired
phone's developer tunnel. `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO` does not
remove it from an iOS device build (the development profile's value is merged
in regardless; checked with Xcode 26.6), and Xcode refuses an entitlements file
that sets it false. The development profile permits `get-task-allow` without
requiring it, so the re-signed app installs under the same profile. What
remains: a development-signed app can still be re-signed and reinstalled from
this Mac by anything holding the developer identity and the phone's pairing —
`get-task-allow` included. TestFlight or App Store distribution, signed by
Apple, closes that; it is not set up.

If the phone stage fails, the Mac side is already installed and verified; the
wrapper says so and does not touch it again. Fix the reported problem and run
`packaging/bin/build-and-install.sh --only-iphone`, which runs the same stage
and nothing else.

### Managed Codex hook stage

`install-codex-hook.sh` installs csec's Codex `PreToolUse` hook as a managed System-layer hook in
`/etc/codex/hooks.json`. Codex runs a user-level hook from `~/.codex/hooks.json`
only while its bytes match a trust hash the user recorded, and skips it after
any change until the user re-trusts it; managed hooks need no trust hash, and
same-user code cannot edit a root-owned file. Codex's own `features.hooks =
false` setting (or `--disable hooks`) still turns every hook off, the managed
one included; `csec doctor` reports the config-file form. The managed hook
applies to every macOS account and every Codex front end on the Mac. The
package carries a copy at `/Library/Application Support/ConvenientSecurity/
libexec/install-codex-hook.sh`, and both the wrapper and `csec setup` (when
the hook is missing or stale and the user agrees) run that root-owned copy
through `sudo`, so a buyer needs no checkout and every install here runs the
same script; the wrapper first checks it is byte-identical to the checkout's.
It is never run on its own otherwise. The stage copies the installed csec into a root-only temporary directory, verifies the
copy's signature and runs only the copy (so nothing can swap the binary between
check and use), requires `/`, `/private`, `/private/etc`, `/private/etc/codex`
and the file to be root-owned and not group/other-writable, and generates the
document as root with `csec hook-config codex --system --launcher <installed
csec>`, which merges csec's handler into any existing file and keeps every
other hook and key. It installs the result
atomically, regenerates it to prove the merge converged, and restores the
previous file (or removes the new file and directory) on any failure. The
wrapper then regenerates the document as the login user into
`packaging/build/codex-hooks.json` and compares it byte for byte with the
installed file; `csec doctor` fails while the managed hook is stale, unsafe
or unreadable, or missing on a Mac where Codex is installed (a Codex executable,
or a hooks or config file in `~/.codex` or `$CODEX_HOME`); without Codex it
reports the hook as not needed.
`csec setup` no longer writes a user-level Codex hook, and removes a csec
handler left in `~/.codex/hooks.json` by an older csec once the managed hook is
installed. It also cleans up the exact csec description and attributable,
unoccupied user-hook trust slots in `config.toml`, preserving other hooks and
their state. Setup keeps owner-only pre-edit backups of both user files;
[`docs/codex-sandbox.md`](../docs/codex-sandbox.md) describes profile reuse,
cleanup boundaries and restoring the previous configuration.

Apple's “upgrade was successful” message applies only to its package stage.
The wrapper prints **Build and installation complete** only after payload
verification, the final, complete `csec doctor` and `csec status` checks, and
the iPhone stage (unless `--skip-iphone`) pass.
Any error or catchable interruption reports the failed stage and exits nonzero.
An iPhone stage failure reports that the Mac side is installed and verified,
skips the Mac recovery below (nothing there changed), and names `--only-iphone`.
Once package installation has been attempted, its failure handler also attempts
runtime repair and reports the remaining complete-installation health, preserving
the original failure even if recovery succeeds. The sudo stage restores its own
prior PAM/module/helper state; the wrapper does not roll back the app package.
If recovery fails, the result explicitly says the runtime is not verified healthy.
Power loss and uncatchable termination cannot run this recovery handler.

Only one run installs at a time. A real run (not `--dry-run`) holds a lock,
`~/Library/Caches/convenient-security/build-and-install.lock`, from before its
first stage until it exits, waits included. Another run, by hand or from
an install worker, exits 75 at once, naming the holder's pid, owner, checkout and start
time, with nothing attempted. The lock is a `flock` on the script's own
descriptor, which the stages it runs do not inherit, so it ends with the
script however the script ends; a leftover file holds nothing.

The wrapper reads `packaging/.env` and defaults the two signing identity names
to the Stateful Ltd identities below. The underlying individual stages remain
available for release diagnosis or artifact-only builds, but none of them is an
alternative install path: a component that is not wired into
`build-and-install.sh` is not installed. Do not add another install script;
add a stage to this one (see the rule in [`../AGENTS.md`](../AGENTS.md)).

Each step is one script. Two env vars name the signing identities (the scripts
read the API key from 1Password themselves):

```sh
export SIGN_IDENTITY="Developer ID Application: Stateful Ltd (8RS6GD89Y7)"
export INSTALLER_IDENTITY="Developer ID Installer: Stateful Ltd (8RS6GD89Y7)"
```

```sh
# 0. (once, whenever the profile expires, and after enabling a capability on
#    the App ID) fetch the Developer ID profile. Runs Fastlane on the Ruby in
#    packaging/.tool-versions through mise. Reads the ASC key from 1Password;
#    needs you present for the 1Password Touch ID.
packaging/bin/provision.sh
#    → packaging/build/convenient-security.mobileprovision
#    (packaging/bin/provision.sh testflight runs the iPhone app's App Store
#    lane instead, with the same credentials: ios/README.md, "App Store
#    release".)
export PROFILE_PATH=packaging/build/convenient-security.mobileprovision

# 1. build + assemble + sign the app and standalone root helper.
#    It first requires the profile to authorize csecd's restricted
#    entitlements (see "Provisioning-profile preflight" above).
#    Signing is inside-out: csec, rootd, then the csecd bundle. It first runs
#    packaging/bin/build-bridge.sh, which builds csec-op-bridge (the Go process
#    holding one 1Password SDK session per account) with CGO for this Mac's
#    architecture; build-agent.sh copies it into the bundle and signs it.
packaging/bin/build-agent.sh
#    → packaging/build/ConvenientSecurity.app
#    → packaging/build/csec-rootd

# 2. build + verify the sudo PAM module and the sudo review helper
#    (unprivileged), Developer ID signed: the package carries both.
packaging/bin/build-sudo-pam.sh
packaging/bin/build-sudo-review.sh
#    → packaging/build/sudo-pam/pam_csec_sudo.so
#    → packaging/build/sudo-review/csec-sudo-review

# 3. notarize + staple the .app (so first launch works offline / on other Macs).
packaging/bin/notarize.sh packaging/build/ConvenientSecurity.app

# 4. build + sign the .pkg: a component package (app, root-owned bridge,
#    helper and plist, the setup payload, the PATH link helper in its
#    scripts) wrapped by productbuild in packaging/installer/Distribution.xml
#    (Apple silicon, the app's minimum macOS, system domain), signed with the
#    Installer cert.
packaging/bin/build-pkg.sh
#    → packaging/build/ConvenientSecurity.pkg

# 5. notarize + staple the .pkg.
packaging/bin/notarize.sh packaging/build/ConvenientSecurity.pkg
#    build-and-install.sh runs steps 3 to 5 as one notarize.sh call, so one
#    csec request delivers the key for both notarizations:
#    packaging/bin/notarize.sh packaging/build/ConvenientSecurity.app \
#      --build-package packaging/bin/build-pkg.sh packaging/build/ConvenientSecurity.pkg

# 6. after the .pkg is installed: the package's guarded, self-verifying
#    sudo-integration installer (see below), which csec setup also runs.
sudo "/Library/Application Support/ConvenientSecurity/libexec/install-sudo-review.sh"

# 7. the iPhone app: no stage script of its own. This runs the wrapper's iPhone
#    stage and nothing else.
packaging/bin/build-and-install.sh --only-iphone
```

`packaging/bin/build-spike.sh` is separate — a minimal signed keychain spike that
proves the data-protection-keychain + biometric foundation (and the AMFI /
provisioning chain) independently of the full agent. It exercises both the
cache's `.biometryCurrentSet` cold-read fold and the native store's device-only
`.biometryAny` access-group exclusion, unauthenticated-read rejection, and
authenticated read/update. Its separately signed helper deliberately has no
restricted entitlement and must be unable to query the item. The helper also
tries to read, update, delete and add items shaped like csecd's protected stores
(`ProtectedStores.swift`: explicit group, no biometric ACL,
`AfterFirstUnlockThisDeviceOnly`), printing one value-free status line per
attempt; every line must read `refused`. Its reads ask for attributes only, and
its writes target a fresh probe-only account, never a real item. It uses the
same Developer ID profile as the pipeline: `PROFILE_PATH` defaults to
`packaging/build/convenient-security.mobileprovision`, the file `provision.sh`
fetches, and a missing profile stops it with a pointer to `provision.sh`
(build-spike.sh embeds the profile under the bundle's
`embedded.provisionprofile` name itself). Use `RUN_SPIKE=0` to build + sign
without the interactive Touch ID run, then run the probe directly: it exits 0
only when every attempt was refused.

```sh
SIGN_IDENTITY="Developer ID Application: Stateful Ltd (8RS6GD89Y7)" \
RUN_SPIKE=0 packaging/bin/build-spike.sh
packaging/build/KeychainSpike.app/Contents/MacOS/unentitled-keychain-probe
```

### Unattended runs (presence checkpoints)

An install worker can run this script unattended and have it wait for someone
at the Mac before each stage that can raise a native request,
so builds and notary waits need nobody there and every panel appears only once
someone is. The worker sets `INSTALL_CHECKPOINT` (the absolute path of its
checkpoint program), `INSTALL_CHECKPOINT_JOB` and
`INSTALL_CHECKPOINT_ATTEMPT`. Right before each such stage the script then runs
`"$INSTALL_CHECKPOINT" checkpoint "$INSTALL_CHECKPOINT_JOB" --attempt
"$INSTALL_CHECKPOINT_ATTEMPT" --stage STAGE`, with no stdin, which returns
once the Mac is attended:

| `STAGE` | Before |
| --- | --- |
| `notarization-authorization` | the csec health check, and provisioning, which can ask for the App Store Connect key |
| `app-notarization` | the app's notarization, the package build and the package's notarization: the key, once, after the build |
| `package-install` | `sudo installer` |
| `codex-hook-install` | `sudo install-codex-hook.sh` (the package's copy) |
| `sudo-integration-install` | `sudo install-sudo-review.sh` (the package's copy) and its live sudo (not with `--skip-sudo`) |
| `sudo-integration-uninstall` | `sudo install-sudo-review.sh --uninstall` and its live sudo (only with `--uninstall-sudo`) |
| `iphone-install` | `devicectl` installing the app on the phone (also with `--only-iphone`) |

Builds and notary waits between them run unattended. The checkpoint only says
the Mac is attended: every request still needs its own approval on its panel
or the phone. A checkpoint that exits nonzero (the worker cancelled or replaced
the attempt) fails the run as `presence checkpoint before <stage>`, with the
usual recovery once the package was attempted; waiting between the sudo stages
leaves the host as such a failure would, the new app with its runtime repaired
and the older hook and sudo helper. A stage whose request is denied or times
out fails the run, and nothing retries it; a new attempt is a new run.
Unattended, csec roots a grant at the command that asked for it, so the
checkpoint, a sibling of that command, can use none. Set all three variables
or none: anything in between, a relative path, or an id that is not 1-128
letters, digits, `.`, `_` or `-` starting with a letter or digit, is refused
before anything runs. While it runs, the install lock names the run's owner as
`install job <JOB>`.
The script carries the marker line `# install-checkpoint-v1`, which a worker
can check before it queues an install. `--dry-run` prints each checkpoint in
the plan without calling it.

## Contextual sudo approval

PAM child cleanup has a 100 ms bounded, nonblocking reap after `SIGKILL`, so
an unreapable helper cannot trap sudo in `waitpid`. Redactor deadlines include
elapsed launch time and noisy pipe reads. Fixed, value-free stage notices go to
the `process-liveness` unified-log category; see
[process-launch diagnosis](../docs/development.md#diagnosing-slow-or-stuck-process-launches)
for collection and recovery limits. Each stage line also says why it ended (a
redactor or helper failure's reason, the helper's pid and exit status, Apple's
fallback result), and the review helper, whose stderr the module points at
`/dev/null`, writes its own value-free lines to the `sudo-review` category; see
[Diagnosing a sudo review](../docs/development.md#diagnosing-a-sudo-review).
A failed live check in `install-sudo-review.sh` prints both for its
verification sudo. This does not change approval-panel controls,
consent decisions, or the retained Apple recovery for helper failures. The PAM build
stage tests an unreapable child without changing the live PAM configuration.

sudo blocks SIGINT and SIGQUIT while it authenticates and only records a
SIGHUP, so neither a Ctrl-C nor a closed tab ends it while the csec review is
up. The module's wait loop reads the pending signal set and polls its own
read-only descriptor on the PAM tty for `POLLHUP` (measured on macOS 26.2: a
pty whose master closes reports it, typed input does not, and `select` cannot
tell the two apart). On either it kills and reaps the helper, latches the interrupt
and returns `PAM_IGNORE`, so the requisite `review_guard` aborts the
transaction (below) before Apple's fallback prompt, `pam_tid` or sudo's
password prompt; the terminal is told sudo was interrupted without authorizing
anything. A Ctrl-C still pending when the guard runs, from Apple's Use
Password dialog, aborts it too. The helper watches its original parent with `EVFILT_PROC`/`NOTE_EXIT`
for the case the module cannot cover, sudo itself killed or crashed;
`csec-sudo-review --parent-watch-probe` arms that watch without a window, which
`cs-selftest` uses. Exit zero is the module's only approval signal, and AppKit
ends an application that agrees to quit with exit(0), so the helper runs every
AppKit loop with a delegate that answers a quit request (logout, or a quit
Apple Event any process of the user can send) by exiting 69 itself, at any
point of the review: sudo falls back to its password prompt, a logout goes on,
and the phone copy is withdrawn as the helper's csecd connection closes. The build stage's harness proves both interrupts and the
hangup against deterministic doubles and a real pty. A SIGTERM to sudo (a plain
`kill`, or `timeout … sudo`) is outside all three: sudo handles it itself and
the module does not look for it, so the review stays up until it is answered
or the module's 300 s review deadline passes. The frame (version 2) tells the
helper how much of that is left; its panel shows when it will close and counts
down the last 30 seconds, and the helper closes the review three seconds early,
withdraws the phone copy and exits 75. The module believes 75 only within ten
seconds of its own deadline (earlier it is a helper fault, which keeps Apple's
recovery) and kills a helper that is late. Expiry then aborts sudo without
opening Apple's sheet or a password prompt, after one `PAM_ERROR_MSG` telling
the terminal nobody answered the review within five minutes. A value-free transaction latch, for expiry or an interrupt, connects the
sufficient review to the immediately following requisite `review_guard`
invocation of the same module. The first factor returns `PAM_IGNORE`, so the guard's fatal `PAM_ABORT`
stops the whole stack and sudo does not retry. Use Password, phone Deny and
helper failures leave the guard passing and retain Apple recovery.

The sudo integration is installed by `build-and-install.sh` but is not a
package payload: it lives under `/usr/local`, is activated through
`/etc/pam.d/sudo_local`, and is installed by its own guarded, reversible stage
rather than by Apple's `installer`. It shows a csec review window for the
submitted invocation, gates approval with Touch ID, and leaves Apple's normal
Touch ID/password path immediately behind the csec PAM factor. A redaction,
transport, helper, or UI failure therefore falls through instead of locking the
user out. Raw arguments are never logged or sent to the review helper; the PAM
module sends only the frozen, filtered display over a private pipe. The helper
builds its `LAContext` through the same `ReviewAuthenticationContext` factory as
the two csecd review windows, so this review reuses no lock-screen Touch ID
match either: a `sudo` raised shortly after the Mac is unlocked still asks for
its own touch.

With an iPhone paired, the helper also mirrors the review to the phone through
csecd (`sudo_remote_review`, docs/remote-approval.md) and takes the first
verified answer. csecd answers only a helper whose live code identity is the
product team's (`ProductCodeRole.sudoReviewHelper`), so `build-sudo-review.sh`
signs it with `SIGN_IDENTITY` (Developer ID, hardened runtime, timestamped) and
checks it against the requirement csecd evaluates; `build-and-install.sh`
exports that identity, and the stage refuses to build for installation without
it. Built standalone without `SIGN_IDENTITY` (as `bin/ci` does), the helper is
ad-hoc signed: the PAM module still runs it, but its review stays on the Mac.

Before it draws anything, the helper also asks csecd whether Claude Code auto
mode's approval stands in for the review (`sudo_delegation`, DESIGN.md
§Delegated approval / Sudo): an approved sudo exits 0 with no panel, and a
declined one shows csecd's note, and the pairing line when approving would let
auto mode run sudo in the project. The PAM module is unchanged: csecd decodes
the same frozen display it already sends, so `build-sudo-review.sh` pipes the C
module's rendering of awkward arguments into the built helper's
`--display-round-trip`, which must decode it back to the same argv. The
panel's terminal tab comes from csecd too (`sudo_terminal`): the helper sends
no Apple event, which macOS would charge to whichever application ran sudo.
Just before it exits the helper reports how its review ended
(`sudo_review_end`), which csecd logs under the coding agent above the sudo; its
trail says whether csecd logged it (`event=end-report`), before `event=exit`.

An unchecked Claude Code image also declines delegation through csecd, using
the same release-verification note on sudo, secret-access, SSH and phone
reviews. The checked-loader catalog ships inside csecd and grows from the
signed release manifest's `claude_code` list, so a newer list or an updated
catalog restores delegation without repeating setup. The release watch that
starts each audit runs on the maintainer's Mac; it adds no csec install stage
or helper. See
[Claude release verification](../docs/claude-release-verification.md).
Checked images with an uninspectable managed policy helper also use the
ordinary shared review path on all three Mac surfaces and the phone. Catalog
verification does not acknowledge a helper's generated hooks or rules.

Reinstalling the `.pkg` or copying the app does not touch the module or the
helper, which is how a machine can keep running an old helper while the app
moves on. `csec doctor` and `csec status` therefore report the sudo review
helper (present, root-owned, hardened, carrying the expected identifier, and
named by the installed module) whenever the csec PAM line is active, and
doctor refuses to call the installation healthy otherwise; the host audit's
HA-G11 reports the same condition.

The non-privileged build and verification stages:

```sh
packaging/bin/build-sudo-pam.sh
packaging/bin/build-sudo-review.sh
```

The built helper doubles as the sudo review's design and typing-guard harness,
the counterpart of `cs-review-preview` for the other two review windows (whose
scenarios include the secret-access surface's `restore` and `restore-mixed`
layouts; sudo has no csec grants to restore).
The installed release helper checks that its captured parent is still live and
effective-root before reading stdin and again before using the decoded frame.
The private pipe and a valid frame cannot authorize a same-user caller. Its
live panel/phone probes are debug-only; use `agent/.build/debug/csec-sudo-review`
for the live probes below. The release build retains offscreen `--preview` and
windowless checks. `build-sudo-review.sh` proves that the shipping helper refuses
an open empty pipe, a valid forged frame, and every live synthetic probe flag
from an unprivileged parent. `cs-selftest --sudo-helper-only` also covers root,
non-root, unreadable and reparented kernel facts and the real helper entry point.
The helper's Mac/phone race and csecd's presentation FIFO share an advisory
lock in the canonical private per-user runtime directory. A helper waiting for
that turn shows neither copy; its parent watch and the PAM 300 s limit remain
active while it waits. The lock is released after both review legs finish or
when the owner exits. `--presentation-lock-probe <private-directory>` is a
windowless synthetic harness: stdin held open keeps its turn, EOF releases it,
and `cs-selftest --review-presentation-only` checks contention and crashed-owner
recovery across real helper processes. Reinstalling only the app package
cannot update this admission rule: the wrapper reinstalls the sudo helper too.
The `requester-orphaned` and `ssh-requester-orphaned` scenarios prove that the shared
arrival-time parent/scope watch closes the other two surfaces even when the
requester survives. Sudo deliberately retains its existing parent watch and
300 s PAM limit: an early failure for sudo's own parent would fall through to
macOS Touch ID. The wrapper still reinstalls and verifies the sudo helper on
every deployment, alongside the updated csecd.

`packaging/build/sudo-review/csec-sudo-review --preview <basic|long-argv|multi-line> <out.png> [light|dark]`
renders that synthetic review to a PNG without showing it or starting Touch ID
(`long-argv` grows the command card to the screen and scrolls the rest, under
its overflow cue, `multi-line` shows a
script's escaped newlines; `CSEC_PREVIEW_DELEGATION=<code>` and
`CSEC_PREVIEW_PAIRING=1` add the delegation note and the pairing line, as
`cs-review-preview` does for the other two; they apply to `--grace-probe`'s
`basic` fixture too; `CSEC_PREVIEW_NO_TOUCH_ID=1` draws it
as a Mac that cannot take a touch shows it while the phone may still decide),
and `csec-sudo-review --grace-probe` shows it for real and prints the panel's
key/active/control state before and after the grace period, with keyboard
focus on the panel's `PromptKeyboardSink` in both samples. Every live probe's
panel carries the red "TEST — NOT A REAL REQUEST" banner (`ReviewTestBanner`),
as `cs-review-preview`'s presented panels do; `--preview` renders offscreen and
stays unmarked, and the release helper, which PAM spawns, can never mark a
panel.
`csec-sudo-review --typing-probe` shows it for real while you keep typing as it
appears, then stop: it must stay held until the keyboard counter reads 1.5 s
(a second or so after your last key; the counter works in half-second steps),
and prints `typing probe: PASS`, `FAIL` or `INCONCLUSIVE`.
`csec-sudo-review --focus-probe` shows it for real, brings Finder to the front,
makes the panel key again, and prints whether the panel said to click it,
re-armed Touch ID on a fresh context behind its grace period, and left the
focus alone when Finder came forward again inside that grace (the probe
`CSEC_PREVIEW_FOCUS_PROBE=1 cs-review-preview` runs on the other two windows).
`csec-sudo-review --screen-lock-probe` reports, in booleans only, whether this
helper's own process can read the login session's lock state, the check that
decides whether a review cancelled by a screen lock is held open for a Touch ID
retry or falls through to sudo's password prompt; under PAM's spawn shape
(`sudo env -i PATH=/usr/bin:/bin LANG=C … --screen-lock-probe`) it reads the
lock state as root too. `csec-sudo-review --unlock-probe` shows the panel for
real and needs a human to lock the Mac and unlock it: it prints the lock, a
hold for unlock if macOS cancelled Touch ID behind the lock screen, and the
unlock, then `PASS` once the panel, still up and key, has asked for Touch ID
again on either path (the probe `CSEC_PREVIEW_UNLOCK_RECHECK=1
cs-review-preview` runs on the other two windows).
`csec-sudo-review --no-touch-id-probe` treats Touch ID as unavailable and
needs nobody: with no phone the review must end at once with no window shown,
then, through the production race with a phone leg that answers unavailable
after two seconds, the panel must be up with the unavailable line until then
and close as it answers, falling back with exit 69. Last, Touch ID comes back
two seconds into a panel waiting for the phone: the panel must arm it and stay
up when the phone gives up later. Then Touch ID goes away under an armed
panel (the lid closed with an external display): with the phone pending the
panel must stay up for it, and with no phone the review must end for the
password. It prints `PASS`, `FAIL` or (on a Mac that cannot take a touch at
all) `INCONCLUSIVE`; Touch ID is armed for a few seconds in all, so do not
touch the sensor (the probes `CSEC_PREVIEW_TOUCH_ID_PROBE=1` and
`CSEC_PREVIEW_TOUCH_ID_LOST_PROBE=1 cs-review-preview` run on the other two
windows).
`packaging/bin/sample-sudo-review-activation.sh` goes one step further out: it
builds the debug helper and spawns its fixed `--synthetic-review-probe` (a
synthetic frame on a private pipe, no activation policy set up front), sharing
the production review body without bypassing the release parent check. It prints the process's
activation policy, active state and on-screen window count every 50 ms, so the
typing guard can be checked on the production code path, including the terminal
lookup that runs before the window exists.

Installation is one guarded, self-verifying stage, run through `sudo` from
the login user. The package carries the script with the module and helper it
installs (`/Library/Application Support/ConvenientSecurity/libexec/` and
`sudo-review/`), and `csec setup` and `build-and-install.sh` both run that
root-owned copy, which installs the package's payload and requires it to be
signed by the product team; the wrapper first checks the copy and the payload
are byte-identical to the checkout's script and build. A checkout's own copy
installs the checkout's build instead. The script's location decides which,
never an argument or the environment:

```sh
sudo "/Library/Application Support/ConvenientSecurity/libexec/install-sudo-review.sh"
```

`csec setup` offers it when the review is not installed, will not hand off,
or is not the package's build, and only while Touch ID can approve the live
check; `csec status` warns while an active review is not the package's build.

On a Mac without the integration it adds the `sufficient` csec module
followed by its requisite `review_guard`, before stock `pam_tid` in
`/etc/pam.d/sudo_local` (adding `pam_tid` when it is not active yet, so Touch ID
stays the fallback), keeping
the stock file at `/etc/pam.d/sudo_local.csec-context-backup`, and installs the
module and the hardened helper. On a Mac that already has the line it replaces
the module and helper in place and adds the guard when upgrading the old
one-line integration. A failed live check restores that transaction's exact
prior configuration and binaries; the permanent pre-csec stock backup stays
intact. Doctor rejects a missing or misordered guard and a module too old to
implement it. The installer validates root ownership, directory modes,
code signatures, the hardened-runtime flag and signing identifier of the
helper, that the module names that exact helper, architectures, and the
fallback ordering before changing the active path. There is no typed
`keep`/`restore` decision: the installer then runs a harmless `sudo` as the
login user. Approve the Convenient Security review that appears. The verdict
comes from that one `sudo`'s value-free unified-log trail, found by its PID
(the login user's shell prints its PID and `exec`s the `sudo`): the module's
lines must end in the installed helper's approval, and that helper must have
been started by this `sudo`, recorded an approval (on the Mac, on the phone,
or by auto-mode delegation) and exited 0. The helper's lines are found by the
PID the module named and the process name, never by image path: logd
attributes an image by its UUID, so the installed helper's lines carry the
build tree's path once the build stage has run the identical binary, and the
module already checked the signature of the process it spawned at that PID. Only that keeps the installation; a
denied, failed, or timed-out `sudo`, or one approved any other way (Apple's
fallback or `pam_tid` after the helper refused or failed, or no hand-off at
all), restores the prior module, helper, and PAM configuration and exits
non-zero, which also fails `build-and-install.sh`. Another `sudo`'s review
running at the same time is not evidence for this one. The decision functions
live in `lib/sudo-review-policy.sh`; `tests/test-sudo-verification.py`, which
the PAM build stage runs, drives them and the installer's own live check
against a fake log and a fake `sudo`. On
success it prints the installed helper's and module's CDHash;
`packaging/bin/install-sudo-review.sh --print-installed-digests` prints the
same facts read-only, without root.

### Removing the sudo integration

`packaging/bin/build-and-install.sh --uninstall-sudo` runs the same stage in
reverse (`sudo packaging/bin/install-sudo-review.sh --uninstall`) and nothing
else: no build, package, Codex hook or iPhone stage. After the same root,
ownership and directory checks it refuses, changing nothing, while any other
file in `/etc/pam.d` loads the module or `sudo_local` names it in a form the
installer never writes. It then takes csec's two lines out of
`/etc/pam.d/sudo_local`. When the live file is exactly what an install from
the stock backup `/etc/pam.d/sudo_local.csec-context-backup` produces, the
stock bytes go back (so a `pam_tid` line csec added goes too); a file edited
since keeps the edits and loses only csec's lines, and a `sudo_local` csec
created is deleted. The same harmless `sudo` as the login user then has to
succeed through Apple's Touch ID or password. If it fails or is interrupted,
that transaction's exact prior `sudo_local` goes back, the module and helper
were never touched, and the stage exits non-zero. Only after it succeeds are
`/usr/local/lib/pam/pam_csec_sudo.so*` and every `/usr/local/libexec/csec-sudo-review*`
(the canonical helper, the August 2026 `-spike` build, temporaries an
interrupted install left) deleted, `/usr/local/lib/pam` removed if empty, and
the stock backup deleted when it is identical to the restored file (kept, and
named, otherwise). A symlink or directory in place of one of those files is
left and reported, and the stage exits non-zero. With no csec line active the
stage deletes those leftovers without a live `sudo`. The wrapper then checks,
unprivileged, that nothing matching those paths remains and that no file in
`/etc/pam.d` loads the module. `tests/test-sudo-policy.py` drives the removal's
own definitions over a temporary tree with a fake `sudo`.

The provisioning and notarization wrappers source `lib/asc-credentials.sh`,
which asks the installed `csec exec-fd` for all three App Store Connect
references in one request under its normal authorization policy. Each reference
may use any supported backend. Existing `OP_ASC_ITEM` configurations supply the
three field references by default; explicit `ASC_KEY_ID_REF`,
`ASC_ISSUER_ID_REF` and `ASC_KEY_REF` override them. While csec is installed,
neither wrapper invokes `op`, signs into a provider, changes TCC, or falls back
to direct provider access, and `OP_ACCOUNT` is ignored. The installer's
`notarize.sh --check-auth` checks configuration and csec runtime health without
resolving credentials; a first consumer request may need csec approval. An
installed but unhealthy csec fails before the build.

A first build, on a Mac with no `/Applications/ConvenientSecurity.app` at all,
has no broker to ask. Inside `build-and-install.sh` (which exports
`CSEC_BUILD_AND_INSTALL_PIPELINE=1`), and only there, the wrappers then read the
three references with 1Password's CLI: `op read --no-newline`, with
`--account "$OP_ACCOUNT"` when that is set, each into a process substitution
whose own `/dev/fd/N` path is the consumer's descriptor, under the same contract
as csec's delivery. All three must be `op://` references; anything else, or no
`op` on `PATH`, stops at `--check-auth` before the build, without reading
anything. `OP_SERVICE_ACCOUNT_TOKEN`, `OP_CONNECT_HOST` and `OP_CONNECT_TOKEN`
are cleared for those reads, so the Admin key is released only through the
user's approval in the 1Password app. One read of the key ID, discarded, comes
first so that approval is asked once rather than by three concurrent reads.
Moving an installed app aside to reach this route gains nothing: the key is
still released only by that approval.

A caller that already holds a key for the run can supply it instead:
`NOTARY_KEY` (a readable `.p8` file), `NOTARY_KEY_ID` and `NOTARY_ISSUER`,
for example from a signing wrapper that releases the key once its owner has
approved that build. The wrappers then read the key from that file
under the same `/dev/fd/N` contract, ask csec for nothing, and give the consumer
none of those three names. If the key is named but incomplete, the wrappers
refuse rather than fall back to csec. The caller owns the file and removes it.

The child wrappers receive only inherited `/dev/fd/N` paths. Provisioning passes
the private-key descriptor to Fastlane; its environment contains the non-secret
key/issuer IDs and the fd marker, never private-key bytes. The locked Fastlane
2.237.0 action reads `key_filepath` once with `File.binread`
([upstream source](https://github.com/fastlane/fastlane/blob/2.237.0/fastlane/lib/fastlane/actions/app_store_connect_api_key.rb)).
The wrapper explicitly asks Bundler to preserve inherited descriptors.

`notarytool --key` requires a filesystem path and does not reliably accept that
descriptor path. `notarize.sh` reads each delivered descriptor once, closes it,
and keeps the values in unexported shell variables, so one delivery serves both
of the installer's notarizations: with `--build-package` it notarizes the app,
runs `build-pkg.sh` (which inherits no descriptor and no key) and notarizes the
package, raising one csec request per install where there were two.
Provisioning, when the profile is missing or refreshed, remains a request of
its own before the build. Immediately before each submission, `notarize.sh`
streams the key into `AuthKey.p8` beneath an atomically created `0700` temporary
directory with file mode `0600`. It removes the file and directory immediately
after `notarytool` returns and from its exit and handled-signal paths. The key is
never stored in an environment variable, included as key data in argv, or
printed. A process crash or `SIGKILL` can prevent trap cleanup, and filesystem
copies, swap, backup, or snapshots remain outside the script's control.
Signature, Gatekeeper, and stapler verification failures are fatal; the scripts
never print a success message after a failed release check.

## Install & register

From the signed `.pkg` (double-click, or `installer -pkg … -target /`), the app
lands in `/Applications`. Its postinstall script checks root ownership/modes
(the setup payload and the package's uninstaller beside the bridge included),
the exact Team/identifier requirements of app, bridge, helper and the sudo
payload (`com.alexspeller.convenient-security.sudo-review` and `.sudo-pam`),
and the root plist. Before replacing the system LaunchDaemon it records the verified
helper's and bridge's exact bytes in a root-owned, world-readable install
receipt, `/Library/Application Support/ConvenientSecurity/install-receipt.json`
(`{"schema": 1, "producer": "csec", "artifacts": {"<helper path>": "<sha256>",
"<bridge path>": "<sha256>"}}`, written by `pkg-scripts/write-install-receipt`
as one atomic rename). A persistence watch, such as a malware watch, can
then tell a csec upgrade of either launch target from someone else replacing
it; user-level code cannot forge the receipt. A watch that reads a receipt
naming a path it does not pin as invalid records a new artifact only once it
pins that path. `build-and-install.sh` checks the receipt names
exactly the built helper and bridge. On upgrade the
postinstall waits for launchd's asynchronous `bootout` transaction to finish
and retries transient `bootstrap` rejection within a bounded interval before
kickstarting the new job. It then restarts every logged-in user's running
`csecd` on the new code (`pkg-scripts/restart-user-agents`) and, for the user
at the Mac, starts `csec doctor --runtime` and `csec restore` in the
background, so a package installed by hand upgrades the way
`build-and-install.sh` does. Last, `pkg-scripts/link-command` links
`/usr/local/bin/csec` to the app's `csec` when that name is free or already
csec's link, and leaves anything else there alone; `csec doctor` fails while
the link is missing and warns when another file holds the name. None of these
last steps can fail the install (the helper is loaded by then). Before any of
this, `pkg-scripts/preinstall` refuses a package whose release is below the
installed app's, using the `package-release` file `build-pkg.sh` writes beside
the scripts (version, build, and whether this package was built with
`--allow-downgrade`). The package's version, in the component and in the
distribution, is `VERSION.BUILD`. Versions, the build number and the release
manifest are described in
[`docs/release-manifest.md`](../docs/release-manifest.md).

A buyer then runs `csec setup` (through that link), which registers the
per-user LaunchAgent and offers the Codex hook and the sudo review from the
package's payload. Registration alone is `csec install`; whichever runs it,
**run the CLI from the bundle** (directly or through the link, which csec
resolves to the bundle) so `SMAppService` can find the per-user LaunchAgent
plist:

```sh
/Applications/ConvenientSecurity.app/Contents/MacOS/csec install
# → "agent registered — enabled — starts at login"
#   (if it says "awaiting your approval", approve ConvenientSecurity in
#    System Settings › General › Login Items)

/Applications/ConvenientSecurity.app/Contents/MacOS/csec status       # complete read-only status
/Applications/ConvenientSecurity.app/Contents/MacOS/csec doctor       # repair and verify services/sockets
/Applications/ConvenientSecurity.app/Contents/MacOS/csec uninstall  # revert, delete csecd's state, unregister
```

`csec uninstall` first reverts the Claude Code settings `csec setup` changed
for delegated approvals, then has `csecd` delete, under one Touch ID, its
protected Keychain items, decision log and sealed host-audit baseline, and
finally unregisters the per-user credential LaunchAgent (see
[Uninstalling](../README.md#uninstalling) for what stays; a refused Touch ID
uninstalls nothing and puts the settings back). On its own it leaves the
package's files, the root helper, the managed Codex hook and the sudo
integration, which every account shares.

`csec uninstall --all` removes those too, with no checkout. After the same
steps it takes csec's hook out of the login user's Claude Code and Codex
settings, then runs the package's uninstaller through `sudo`. The package
installs it as
`/Library/Application Support/ConvenientSecurity/libexec/uninstall-csec.sh`
(source: `packaging/libexec/uninstall-csec.sh`), beside the bridge under
directories only root can write; `csec` checks that before running it, and the
postinstall checks its shape and ownership. The app carries the same script in
`Contents/Resources/uninstall/`, sealed by its signature, so `csec doctor`
fails on a missing, unprotected or stale installed copy, and
`build-and-install.sh` verifies the installed copy against the checkout. In
order, stopping at the first failure (each step skips what is already gone, so
it can simply be run again with `sudo`), it: refuses while the login user's
csecd is still loaded (that account's part comes first); runs the package's
guarded sudo removal (`libexec/install-sudo-review.sh --uninstall`, below);
takes csec's handler out of `/etc/codex/hooks.json` through the
signature-verified bridge copy (`csec hook-config codex --system --remove`),
deleting the file when csec's was its only hook, because once the app is gone
that hook fails closed and blocks every Codex Bash call; boots out
`csec-rootd`, deletes it and its LaunchDaemon, unmounts its tmpfs and removes
`/private/var/run/convenient-security` without recursing (a busy tmpfs stays
until the next restart); deletes `/usr/local/bin/csec` only when it is csec's
link, the app (only when its bundle identifier is csec's) and
`/Library/Application Support/ConvenientSecurity`; and forgets every
`com.alexspeller.convenient-security*` package receipt.
`packaging/tests/test-uninstall-csec.py` drives the real script against a fake
root with command doubles.
Copying only the `.app` deliberately leaves `root-status` unavailable and
cannot enable `exec-file`.
Until the signed/root matrix passes, exercise `exec-file` with synthetic data
only.

`csec doctor` is deliberately narrower than reinstalling the package: it can
register or restart the per-user agent and verify all live endpoints, but it
does not rewrite shell profiles, touch secret stores, or silently replace a
missing root-owned app/helper. It gives csecd 10 s to answer, and keeps waiting
while launchd still runs a csecd that is starting, up to 120 s: on a heavily
loaded Mac csecd's first Keychain read can wait on secd for half a minute
before csecd binds its sockets. For the same reason it does not restart a
csecd launchd started less than 120 s ago, unless that csecd failed identity
verification (the old code image left running after an upgrade); past 120 s a
csecd that still does not answer is restarted. `csec doctor --check` performs the same diagnosis
without changing service state. `csec doctor --runtime` excludes the sudo
integration for the installer's intermediate gate; it labels that narrower
scope explicitly and does not replace the final full health check.

Once the agent is running, create a native encrypted store with:

```sh
/Applications/ConvenientSecurity.app/Contents/MacOS/csec edit development
```

That command uses the fileless built-in editor. If its editing features are too
limited, `csec edit --editor development` invokes the command in `$EDITOR`
directly and appends a temporary JSON pathname. For example, use
`EDITOR='code --wait'`; an editor that forks and returns without waiting is not
compatible. This mode warns because the named plaintext is readable by same-UID
processes and may be copied by plugins, swap, autosave, backup, or snapshots.
The private workspace is removed after the editor exits, but cleanup is not
secure erasure, cannot reach copies elsewhere, and cannot run after a crash or
forced termination.

Only ciphertext is written beneath
`~/Library/Application Support/ConvenientSecurity/Secrets/`; the per-store data
key and authenticated active-version pointer use the provisioned Keychain group.

`csec install` calls `SMAppService.agent(plistName:).register()`. That resolves
the plist relative to the **calling process's** `Bundle.main`, which is why `csec`
must be run from inside the `.app`. Once registered, launchd starts `csecd` at
login (and immediately, `RunAtLoad`), keeps it alive (`KeepAlive`), and it listens
on the shared socket. For everyday use you can symlink the CLI onto your `PATH`
(`ln -s /Applications/ConvenientSecurity.app/Contents/MacOS/csec /usr/local/bin/csec`)
— `csec get` / `csec exec` don't care where they're run from; only `install` needs
the bundle context.

## How it works

- **Entitlements** (`packaging/agent/csecd.entitlements`, the one file csecd is
  signed with in every build, its team and identifier filled in from
  `identity.xcconfig` by `build-agent.sh`): `application-identifier`
  + `keychain-access-groups`, both `8RS6GD89Y7.com.alexspeller.convenient-security`,
  `team-identifier`, and the CloudKit container
  `iCloud.com.alexspeller.convenient-security` (`icloud-container-identifiers`,
  `icloud-services` = CloudKit, `icloud-container-environment` = Production: a
  Developer ID app may use CloudKit only in Production). Every Mac build is
  remote-approval capable; csecd makes no CloudKit request until a phone is
  paired. `bin/ci` requires the iPhone app's Debug and Release entitlements to
  name the same container in Production.
  **No App Sandbox** (Developer ID doesn't need it, and the agent may shell out
  to `op` and shares a per-user socket). The same restricted default group holds
  refillable cache entries and native-store key/pointer records; their distinct
  biometric ACLs are verified by `packaging/spike`. Hardened runtime is enabled
  via `codesign --options runtime`. Never change the team prefix or group after
  native stores exist—it makes their ciphertext unrecoverable.
- **Full Disk Access for the privacy audit**: `csec audit` enumerates the
  SIP-protected TCC databases (privacy grants), which needs `csecd` to hold
  **Full Disk Access**. FDA is a *user-granted TCC permission*, **not an
  entitlement** — `csecd.entitlements` is unchanged — but macOS only lets the user
  grant it to a launchable signed `.app`, so it is granted after install from
  System Settings → Privacy & Security → Full Disk Access. Without the grant the
  audit's privacy section degrades to `unknown` + Settings deep-links rather than
  failing or silently passing.
- **Automation privacy capability** (`packaging/agent/csec.entitlements`): the
  signed launcher has the Calendar hardened-runtime entitlement required when
  its supervised descendants use EventKit-backed Calendar or Reminders tools.
  The bundle declares legacy and current Calendar/Reminders purpose strings.
  Access remains denied until the user grants ConvenientSecurity permission in
  System Settings. That TCC permission covers csec's responsible-process
  identity across commands; it is not scoped to an automation job or secret
  reference set.
- **Signing order** (`build-agent.sh`): sign `csec` (secondary, only the Calendar
  automation entitlement),
  sign standalone `csec-rootd` with identifier
  `com.alexspeller.convenient-security.rootd` and no entitlements, then sign the
  bundle — which signs `csecd` (the main executable) *with* the keychain and
  CloudKit entitlements the embedded profile authorizes (checked before the
  build starts). All are hardened and verified with strict `codesign` checks.
- **LaunchAgent plist** (`packaging/agent/LaunchAgents/…plist`): `BundleProgram`
  is bundle-relative (survives relocation), `RunAtLoad` + `KeepAlive`, and
  `ProcessType=Interactive` (it presents Touch ID). It supplies no provider or
  credential environment. `csecd` enables the native provider when its Keychain
  group is usable. Independently, it locates fixed absolute `op` candidates,
  verifies the official Team/identifier requirement, hardened runtime, and
  absence of dangerous entitlements, then spawns `op` with a small allowlist.
  Production requires at least one of those providers, not necessarily both.
- **LaunchDaemon plist** (`packaging/root/LaunchDaemons/…plist`): a fixed
  `/Library/PrivilegedHelperTools` program, root:wheel execution,
  `RunAtLoad`/`KeepAlive`, umask `077`, and no credential environment. The
  postinstall script loads it into the system domain only after path, mode,
  signature, requirement, and plist checks. The helper serves the fixed
  `/private/var/run/convenient-security/rootd.sock`, verifies product audit
  tokens on every short connection, and mounts only the fixed bounded tmpfs.
- **Host-audit privileged ops in `csec-rootd`**: the signed root helper now also
  serves two additional closed-enum operations for the host posture audit —
  `hostRead` (value-free privileged reads) and `hostApply` (reversible,
  digest-bound mutations) — both callable only by the verified agent role. This
  is a helper-code change, so the root helper must be **re-signed and
  re-notarized**, but it adds **no new dangerous entitlements** (still no
  `get-task-allow`, DYLD, JIT, or debugger entitlements), which preserves
  `StartupSecurityReport.productionReady`. The operations are a fixed allow-list
  with no generic "run as root," keeping the helper's audited surface minimal.
- **Socket path**: derived from `confstr(_CS_DARWIN_USER_TEMP_DIR)` (keyed on the
  uid), *not* `$TMPDIR` — so the launchd-spawned `csecd` and a shell-spawned `csec`
  always agree on `…/convenient-security-<uid>/agent.sock` regardless of the
  environment either was launched with.
- **Logging**: `csecd` writes to `csecd.log` inside its private `0700` socket dir
  when it has no controlling terminal (i.e. under launchd), and to the terminal
  when run interactively. It is deliberately **not** a world-readable `/tmp` path —
  log lines are value/reference-free but still contain local security metadata.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `csecd` dies instantly at launch, no output, `launchctl` shows exit `-9` | AMFI SIGKILL: an entitled binary that isn't the bundle's main executable, or a missing/invalid profile, or the missing **G2 intermediate**. Ensure `CFBundleExecutable = csecd` and the profile authorizes the access group (`security cms -D -i …/embedded.provisionprofile`). |
| `csec status` reports the LaunchAgent but the agent is unavailable | A registered job may be stopped or crash-looping; run `csec doctor`. Installation succeeds only after doctor authenticates the live control, SSH, and root-helper endpoints. |
| `csec root-status` says the helper is unavailable | The `.app` was copied without installing the `.pkg`, the system job failed, or the live server does not satisfy the exact root-helper identity. Check `launchctl print system/com.alexspeller.convenient-security.rootd`, the root-owned helper/plist paths, and the Installer log; do not bypass the identity check. |
| `csec edit` says the native store is unavailable | The daemon could not use its provisioned Keychain group. Check the embedded profile, signed entitlements, startup log, and the native-store `build-spike` gate. An unsigned SwiftPM daemon intentionally has no native provider. |
| Agent runs but `op` fetches fail | Install the official signed CLI at `/opt/homebrew/bin/op`, `/usr/local/bin/op`, or `/usr/bin/op`; unlock 1Password, enable **Developer > Integrate with 1Password CLI**, and run `op signin`; arbitrary provider paths are intentionally rejected in release builds. |
| `codesign` shows `0 valid identities` for a cert that's installed | Missing **G2 intermediate CA** — see prerequisites. |
| Notarization rejected | Check for `get-task-allow` / missing hardened runtime / missing timestamp — the scripts set `--options runtime --timestamp`; don't strip them. |
| `build-agent.sh`: the provisioning profile does not authorize every restricted entitlement | The profile predates a capability csecd is signed with, usually iCloud. Enable iCloud (CloudKit) with container `iCloud.com.alexspeller.convenient-security` on App ID `com.alexspeller.convenient-security`, then `packaging/bin/build-and-install.sh --refresh-profile`. |
| `this checkout lacks N commits the installed csec (…) was built with` / `…a commit this checkout does not have` | The installed app has changes this checkout cannot account for (another worktree's branch, say), or its commit is unavailable. Equivalent rebased patches and flattened merge trees pass automatically. `git merge <commit>` first; `--allow-downgrade` only for a deliberate rollback. |
| `csec doctor`: Saved approvals — `csecd cannot read … and keeps it as found` | An older build is running over items a newer one wrote (reinstall the current build), a Keychain read failed at startup (restart csecd), or the item is damaged (the named command discards it). Approvals made meanwhile last only until csecd restarts. |
| `this checkout lacks N commits already on origin/main` | The checkout is behind what was pushed (often the shared checkout's `main`, while worktrees pushed past it). `git pull --ff-only` on `main`, or `git merge origin/main` on a branch, then rerun. |
| `installed csecd is not signed for CloudKit container …` | The app in `/Applications` was not built from this tree's entitlements; rerun the wrapper. |
| iPhone stage: no available paired iPhone / several available | Unlock the phone, keep it on the Mac's network (or cable), check it is paired in Xcode › Window › Devices and Simulators, or set `CSEC_IPHONE_DEVICE` in `packaging/.env`; then `build-and-install.sh --only-iphone`. `--skip-iphone` installs everything else. |
| iPhone build or install fails on signing / "no valid provisioning profile" | Xcode must be signed into the team (Settings › Accounts), and the phone registered to it: open `ios/ConvenientSecurityApproval.xcodeproj` (after `mise exec -- xcodegen generate --spec ios/project.yml`) and run the app on the phone once, then `build-and-install.sh --only-iphone`. |
| Inspect the running agent | `launchctl print gui/$(id -u)/com.alexspeller.convenient-security`; tail `…/convenient-security-<uid>/csecd.log`. |
