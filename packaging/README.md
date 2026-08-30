# Packaging, signing & install

How the resident agent is turned into a Developer-ID-signed, hardened, notarized,
provisioned `.app` + `.pkg`, how `csecd` registers as a login-item LaunchAgent,
and how the package installs the separate minimal `csec-rootd` system
LaunchDaemon. The signed `.app`, provisioning profile, LaunchAgent, Touch ID,
and keychain path have been proven on real hardware. The native-store access-
group exclusion, biometric ACL, and authenticated record update passed the
signed hardware spike on 21 August 2026. The `.pkg` root-owned bridge, root
helper, and inherited-fd App Store Connect key handoff are covered in source/CI;
the root helper still has the explicit signed physical-machine gate in
[`../docs/regular-file-security-matrix.md`](../docs/regular-file-security-matrix.md).

## What ships

```
ConvenientSecurity.app/
  Contents/Info.plist                        CFBundleExecutable = csecd
  Contents/Resources/LICENSE.md              FSL-1.1-ALv2 terms
  Contents/embedded.provisionprofile         authorizes the keychain access group
  Contents/MacOS/csecd                        MAIN executable — the resident agent
  Contents/MacOS/csec                         the CLI + `csec install`
  Contents/Library/LaunchAgents/com.alexspeller.convenient-security.plist

/Library/Application Support/ConvenientSecurity/bin/
  csec                                      root-owned language-client bridge copy

/Library/PrivilegedHelperTools/
  com.alexspeller.convenient-security.rootd signed minimal root helper

/Library/LaunchDaemons/
  com.alexspeller.convenient-security.rootd.plist
```

Delivered by a signed `ConvenientSecurity.pkg` that installs the app into
`/Applications` and a second byte-identical, signed `csec` bridge at
`/Library/Application Support/ConvenientSecurity/bin/csec`, and the standalone
root helper plus system LaunchDaemon plist. The package makes the bridge/helper
and their controlling paths root-owned/non-user-writable, verifies exact code
requirements, and loads the root helper only after those checks pass. This
matters because `/Applications` is normally group-writable by `admin`, so its
pathname alone is not a same-UID integrity boundary. The user then registers
the credential agent with `csec install` from inside the app bundle.

Four structural rules, each load-bearing:

- **It must be a `.app` bundle, not a bare `csecd` binary.** The restricted
  `keychain-access-groups` entitlement is only authorized by an *embedded
  provisioning profile*, which can only live at `Contents/embedded.provisionprofile`.
- **`csecd` must be the bundle's main executable** (`CFBundleExecutable`). The
  embedded profile authorizes the restricted entitlement only for the main
  executable; a *secondary* binary that claims `keychain-access-groups` is
  **SIGKILLed by AMFI at launch**. `csec` (no restricted entitlements) is the
  secondary binary and runs fine.
- **The credential daemon remains a per-user LaunchAgent, never root.** The
  Secure Enclave, data-protection keychain, provider adapters, policy UI, and
  Touch ID are login-session-only. The separate LaunchDaemon has no provider,
  Keychain, UI, or policy capability; it only verifies two signed roles, creates
  bounded files, drops credentials, and supervises the launched tree.
- **Language clients use the root-owned bridge copy.** Ruby cannot verify a
  replacement executable itself. The protected path prevents pre-launch
  replacement; the daemon then verifies the bridge's live audit token, exact
  signing requirement, hardened runtime, and entitlements before reading JSON.

## One-time prerequisites

| Thing | How | Notes |
|-------|-----|-------|
| Apple Developer membership | — | Paid. Team **Stateful Ltd**, Team ID **8RS6GD89Y7**. |
| **Developer ID Application** cert | Keychain Access → Certificate Assistant → *Request a Certificate from a CA* (save CSR to disk) → developer.apple.com → Certificates → Developer ID Application → upload CSR → download → double-click | Signs the `.app`. **Account-Holder only.** Verify: `security find-identity -v -p codesigning`. |
| **G2 intermediate CA** | Download over HTTPS from [Apple's certificate-authority page](https://www.apple.com/certificateauthority/) and verify it as shown below before importing. | A fresh Developer ID cert shows **0 valid identities** until this intermediate is installed. |
| **Developer ID Installer** cert | same CSR flow, pick *Developer ID Installer* in the portal | Signs the `.pkg`. **Different cert** from the Application one. Account-Holder only. |
| App ID `com.alexspeller.convenient-security` | developer.apple.com → Identifiers → register manually | `produce` can't (no API-key support). The access group is its default `application-identifier`. |
| Remote approval App ID + CloudKit container (optional gate) | Register `com.alexspeller.convenient-security.approval`; create `iCloud.com.alexspeller.convenient-security`; associate it with both App IDs using CloudKit support; enable iOS push | Enabling iCloud invalidates existing profiles. Refresh them before setting `CSEC_REMOTE_APPROVAL=1`; see [`../docs/remote-approval.md`](../docs/remote-approval.md). |
| App Store Connect **API key** (Team, Admin role) | portal → Users and Access → Integrations → App Store Connect API → Team key | Drives provisioning *and* notarization. A **Team** key (not Individual). |
| API key in 1Password | item with fields `key_id`, `issuer_id`, `key` (the `.p8` PEM) | Referenced from `packaging/.env`; private-key bytes are read just in time, never placed in env or passed as key data in argv, and use the constrained transports described below. |
| Release Ruby tooling | Ruby >= 3.2.0, RubyGems >= 3.4.1, and Bundler 4.0.15 | The exact Bundler version is recorded in `Gemfile.lock`; system Ruby 2.6 cannot run this release-only bundle. |
| `packaging/.env` (gitignored) | `OP_ACCOUNT=my.1password.com`<br>`OP_ASC_ITEM="op://<Vault>/<Item Title>"` | Keeps personal 1Password paths out of git. See `.env.example`. |

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

It reuses `packaging/build/convenient-security.mobileprovision` when present,
fetches it through `provision.sh` when absent, then builds and signs every
binary, notarizes the app, builds and notarizes the full package, installs it
with Apple's `installer`, registers or restarts the per-user LaunchAgent, and
verifies that the installed payloads match the build and that the root helper
is reachable. Use `--refresh-profile` to force a profile refresh and `--dry-run`
to print the complete plan without changing anything. Run the wrapper as the
login user: only the package installation is elevated; running the LaunchAgent
registration under `sudo` would register it for the wrong user.

The wrapper reads `packaging/.env` and defaults the two signing identity names
to the Stateful Ltd identities below. The underlying individual steps remain
available for release diagnosis or artifact-only builds.

Each step is one script. Two env vars name the signing identities (the scripts
read the API key from 1Password themselves):

```sh
export SIGN_IDENTITY="Developer ID Application: Stateful Ltd (8RS6GD89Y7)"
export INSTALLER_IDENTITY="Developer ID Installer: Stateful Ltd (8RS6GD89Y7)"
```

```sh
# 0. (once, and whenever the profile expires) fetch the Developer ID profile.
#    Reads the ASC key from 1Password; needs you present for the 1Password Touch ID.
packaging/bin/provision.sh
#    → packaging/build/convenient-security.mobileprovision
export PROFILE_PATH=packaging/build/convenient-security.mobileprovision

# 1. build + assemble + sign the app and standalone root helper.
#    Signing is inside-out: csec, rootd, then the csecd bundle.
packaging/bin/build-agent.sh
#    → packaging/build/ConvenientSecurity.app
#    → packaging/build/csec-rootd

# 2. notarize + staple the .app (so first launch works offline / on other Macs).
packaging/bin/notarize.sh packaging/build/ConvenientSecurity.app

# 3. build + sign the .pkg (app + root-owned bridge/helper/plist; Installer cert).
packaging/bin/build-pkg.sh
#    → packaging/build/ConvenientSecurity.pkg

# 4. notarize + staple the .pkg.
packaging/bin/notarize.sh packaging/build/ConvenientSecurity.pkg
```

`packaging/bin/build-spike.sh` is separate — a minimal signed keychain spike that
proves the data-protection-keychain + biometric foundation (and the AMFI /
provisioning chain) independently of the full agent. It exercises both the
cache's `.biometryCurrentSet` cold-read fold and the native store's device-only
`.biometryAny` access-group exclusion, unauthenticated-read rejection, and
authenticated read/update. Its separately signed helper deliberately has no
restricted entitlement and must be unable to query the item. Use `RUN_SPIKE=0`
to build + sign without the interactive Touch ID run.

The provisioning and notarization wrappers launch `op` with an allowlisted
environment. Provisioning passes the App Store Connect private key to Fastlane
as `/dev/fd/3`; its environment contains only the non-secret key/issuer IDs and
fd marker. The locked Fastlane 2.237.0 action accepts `key_filepath` and reads it
with `File.binread`
([upstream source](https://github.com/fastlane/fastlane/blob/2.237.0/fastlane/lib/fastlane/actions/app_store_connect_api_key.rb)).
The wrapper explicitly asks Bundler to preserve inherited descriptors.

`notarytool --key` requires a filesystem path and does not reliably accept that
descriptor path. Immediately before each submission, `notarize.sh` therefore
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
lands in `/Applications`. Its postinstall script checks root ownership/modes,
the exact Team/identifier requirements of app, bridge, and helper, and the root
plist before replacing the system LaunchDaemon. On upgrade it waits for
launchd's asynchronous `bootout` transaction to finish and retries transient
`bootstrap` rejection within a bounded interval before kickstarting the new
job. Then,
**run the CLI from inside the bundle** so `SMAppService` can find the per-user
LaunchAgent plist:

```sh
/Applications/ConvenientSecurity.app/Contents/MacOS/csec install
# → "agent registered — enabled — starts at login"
#   (if it says "awaiting your approval", approve ConvenientSecurity in
#    System Settings › General › Login Items)

/Applications/ConvenientSecurity.app/Contents/MacOS/csec status     # check
/Applications/ConvenientSecurity.app/Contents/MacOS/csec root-status # root helper protocol check
/Applications/ConvenientSecurity.app/Contents/MacOS/csec uninstall  # unregister
```

`csec uninstall` unregisters the per-user credential LaunchAgent; it does not
remove package-owned files or unload the system root helper. Removing those
components requires a separate administrative package-removal procedure.
Copying only the `.app` deliberately leaves `root-status` unavailable and
cannot enable `exec-file`.
Until the signed/root matrix passes, exercise `exec-file` with synthetic data
only.

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

- **Entitlements** (`packaging/agent/csecd.entitlements`): `application-identifier`
  + `keychain-access-groups`, both `8RS6GD89Y7.com.alexspeller.convenient-security`.
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
- **Signing order** (`build-agent.sh`): sign `csec` (secondary, no entitlements),
  sign standalone `csec-rootd` with identifier
  `com.alexspeller.convenient-security.rootd` and no entitlements, then sign the
  bundle — which signs `csecd` (the main executable) *with* the keychain
  entitlements the embedded profile authorizes. All are hardened and verified
  with strict `codesign` checks.
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
| `csec status` says *not installed* / `.notFound` | Normal **before the first** `csec install`. Otherwise: `csec` isn't being run from inside the installed `.app`. |
| `csec root-status` says the helper is unavailable | The `.app` was copied without installing the `.pkg`, the system job failed, or the live server does not satisfy the exact root-helper identity. Check `launchctl print system/com.alexspeller.convenient-security.rootd`, the root-owned helper/plist paths, and the Installer log; do not bypass the identity check. |
| `csec edit` says the native store is unavailable | The daemon could not use its provisioned Keychain group. Check the embedded profile, signed entitlements, startup log, and the native-store `build-spike` gate. An unsigned SwiftPM daemon intentionally has no native provider. |
| Agent runs but `op` fetches fail | Install the official signed CLI at `/opt/homebrew/bin/op`, `/usr/local/bin/op`, or `/usr/bin/op`; arbitrary provider paths are intentionally rejected in release builds. |
| `codesign` shows `0 valid identities` for a cert that's installed | Missing **G2 intermediate CA** — see prerequisites. |
| Notarization rejected | Check for `get-task-allow` / missing hardened runtime / missing timestamp — the scripts set `--options runtime --timestamp`; don't strip them. |
| Inspect the running agent | `launchctl print gui/$(id -u)/com.alexspeller.convenient-security`; tail `…/convenient-security-<uid>/csecd.log`. |
