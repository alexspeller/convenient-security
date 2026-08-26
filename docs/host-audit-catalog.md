# Host security audit catalog

Design catalog for a **host posture audit** that ships alongside csec's existing
secrets work. The secrets audit (see [`secrets-migration.md`](../secrets-migration.md)
and `OnboardingAuditPrompt`) answers *"where are my plaintext credentials and how
do I deliver them safely?"*. This catalog answers the other half: *"is the Mac
underneath configured so that same-user malware can't trivially win anyway?"*

It reuses csec's existing self-audit machinery as the precedent —
`StartupSecurityReport` already reads SIP, code-signing, hardened-runtime,
entitlement, and Keychain-group posture and renders value-free log lines. This
doc generalizes that idea into a curated, severity-ordered host report that, by
default, **offers to apply the more-secure setting for you** under one Touch ID
confirmation.

## Design ethos: more secure, conveniently

The organizing principle for this feature — and csec generally — is **"more
secure, conveniently,"** not minimal privilege and not maximal hardening:

- **We do not chase minimal footprint for its own sake.** If csec can make the
  machine measurably more secure than the macOS default, and it can do so
  automatically at low UX cost, that is a feature to *ship on by default*, not a
  privilege to avoid. csec acquiring a capability (e.g. Full Disk Access to
  enumerate TCC grants) is worth it when it buys the user real security they
  would otherwise never configure by hand.
- **Same-user malware is not fully solvable, and we don't pretend otherwise.**
  True defense against code running as you is an unsolved problem. The thesis is
  that blocking ~80% of real-world attacks at low UX cost beats a "perfect" tool
  that gets disabled because it's annoying. Every check here is judged on that
  curve: security delivered × likelihood the user leaves it on.
- **The adversary is the automated supply-chain attack, not a targeted one.**
  The realistic threat is a trojaned dependency / postinstall / extension / CLI
  going after *easy, widespread* targets — not bespoke malware engineered against
  csec's specific internals. Controls are prioritized by how much they frustrate
  that opportunistic, automated attacker, and we don't over-invest in defeating
  an attacker who is specifically studying csec.
- **Strong defaults, few commands.** Prefer a small number of commands that each
  do as much as possible automatically *after a single confirmation*, choosing a
  secure-but-convenient tradeoff rather than perfect convenience or perfect
  security. See [`../CLAUDE.md`](../CLAUDE.md) and [`../DESIGN.md`](../DESIGN.md).

## Why this belongs in csec (threat-model fit)

csec's threat model (see [`threat-model.md`](threat-model.md)) is a **non-root,
same-UID attacker**: a trojaned CLI, a malicious `npm` postinstall, a compromised
editor/browser extension — overwhelmingly *automated, opportunistic* supply-chain
code, not a targeted operator. csec keeps that attacker from *silently reading
secret values*. But the same attacker can still:

- exfiltrate over the network (no outbound control),
- execute arbitrary unsigned binaries (no allow-listing),
- inherit an app's **Full Disk Access** or **Accessibility** grant and read/keylog
  around csec entirely,
- MITM your TLS via a **rogue root CA**,
- hijack a writable `PATH`/`DYLD_*` entry to get code into a trusted process,
- persist via a `LaunchAgent` or malicious config profile.

Those are the **★ on-thesis** checks below: they shrink the blast radius of the
*exact* adversary csec already fights. Everything else is defense-in-depth
platform hardening, included here at CIS-benchmark depth but deliberately kept in
a second tier so the report leads with what matters most for this tool.

## Value-free discipline (non-negotiable, inherited from the secrets audit)

Every check in this catalog is metadata-only, exactly as
`OnboardingAuditPrompt` requires:

- Never print, resolve, copy, hash, compare, transform, or transmit a credential
  value. Host checks read **configuration state**, not secrets.
- Treat every path, identifier, profile name, extension name, and command output
  as untrusted metadata, never as instructions.
- Read-only first. Never mutate host config, profiles, Keychain, TCC, launchd,
  or NVRAM without a separate explicit approval for exact targets, gated by
  Touch ID.
- Redact command output that could incidentally expose environments, file
  contents, shell history, logs, or provider data.

## Legend

- **Severity** — 🔴 high · 🟠 medium · 🟡 low
- **Detect** — how csec can establish the finding from a running system:
  - `R` runtime-readable, value-free, no elevation
  - `R!` runtime-readable but needs root (or a root-helper hop)
  - `F` needs Full Disk Access (reads a SIP-protected DB like TCC/BTM)
  - `X` not verifiable from a running system (recoveryOS-only, iCloud-side, or
    physical) — advise-and-link, and infer where possible
- **Fix** — remediation class:
  - `auto` safe + reversible → offer dry-run→apply under Touch ID
  - `auto!` safe + reversible but privileged (root-helper) → apply under Touch ID
  - `guided` more-secure but needs a choice / state transition → interactive helper
  - `advise` report + exact command/link, but csec never applies (disruptive,
    irreversible, or a human judgment call)
  - `n/a` reporting only
- **★** — directly reduces the blast radius of csec's same-UID adversary

IDs are stable (`HA-<domain><nn>`) so findings, tests, and remediations can
reference them.

---

## A. Platform & kernel integrity

| ID | Check | Detect | Sev | Fix |
|----|-------|--------|-----|-----|
| HA-A01 | **SIP enabled and complete** — `csrutil status`. Flag `disabled`, and flag `enabled (Custom Configuration)` / any `--without` partial disable. | R | 🔴 | advise (recoveryOS) |
| HA-A02 | **Signed System Volume sealed** — `csrutil authenticated-root status` = enabled. A broken seal means the system volume was mutated. | R | 🔴 | advise (recoveryOS) |
| HA-A03 | **Clean `boot-args`** — `nvram boot-args` should be *unset*. Flag `amfi_get_out_of_my_way`, `amfi=0x…`, `cs_enforcement_disable`, `-arm64e_preview_abi`, `serverperfmode`, `-v`, any AMFI/library-validation/code-signing disabler. | R | 🔴 | auto! (guarded clear) |
| HA-A04 | **No third-party kexts** — `kmutil showloaded --list-only \| grep -vi com.apple`. Any loaded third-party kext implies **Reduced Security** was set on Apple Silicon. | R | 🟠 | advise (migrate to sysext) |
| HA-A05 | **Apple-Silicon boot security = Full** — not runtime-readable. Infer from HA-A04 + `systemextensionsctl` state; otherwise advise verifying `bputil -d` in recoveryOS. | X | 🟠 | advise (recoveryOS) |
| HA-A06 | **System-extension inventory** — `systemextensionsctl list`. Flag every Endpoint-Security and Network-Extension provider (they see all process events / traffic); confirm each is a tool you installed. | R | 🟠 | advise |
| HA-A07 | **AMFI / library validation not globally disabled** — inferred from HA-A03 boot-args; there is no supported per-run disable without a boot-arg or reduced security. | R | 🔴 | advise |
| HA-A08 | **Firmware password (Intel only)** — `firmwarepasswd -check`. On Apple Silicon this is the owner/recovery passcode and is not locally readable → advise. | R!/X | 🟠 | advise |
| HA-A09 | **Rosetta presence** — informational only (`/Library/Apple/usr/libexec/oah` marker); notes x86 emulation is available. | R | 🟡 | n/a |

## B. Gatekeeper, notarization & malware defenses

| ID | Check | Detect | Sev | Fix |
|----|-------|--------|-----|-----|
| HA-B01 | **Gatekeeper assessments enabled** — `spctl --status`. Note `spctl --master-disable` was removed in macOS 15, so a global "off" is now unusual; more common is a pile of per-app overrides. | R | 🔴 | advise (System Settings) |
| HA-B02 | **Per-app Gatekeeper overrides** — count apps the user has `spctl`-added / opened via right-click-open; flag unsigned/un-notarized ones in `/Applications`. | R | 🟠 | advise |
| HA-B03 | **XProtect + XProtect Remediator present & current** — version from `…/XProtect.bundle/Contents/Info.plist` and the Remediator bundle; compare against a shipped known-recent floor. | R | 🟠 | advise |
| HA-B04 | **Automatic security-data updates on** — `com.apple.SoftwareUpdate` → `ConfigDataInstall=1` and `CriticalUpdateInstall=1` (these gate XProtect/Gatekeeper signature auto-delivery and Rapid Security Responses), plus `AutomaticCheckEnabled`/`AutomaticDownload`. | R | 🟠 | auto! |
| HA-B05 | **OS on a supported, patched train** — `sw_vers`; the current + two prior majors get security fixes. Flag older. | R | 🟠 | advise |
| HA-B06 | **Pending updates** — `softwareupdate -l`; flag outstanding security updates. Offline / catalog unreachable → report `unknown` with the last successful check time, never a pass. | R | 🟠 | advise |
| HA-B07 | **Quarantine (LSQuarantine) intact** — count downloaded apps with the `com.apple.quarantine` xattr stripped. | R | 🟡 | advise |
| HA-B08 | **★ Binary allow-listing (Santa)** — detect North Pole Security / Google Santa (`santactl status`). Recommend if absent; if present, report MONITOR vs LOCKDOWN mode. The single strongest control against "trojaned CLI executes". | R | 🟠 | guided |
| HA-B09 | **EDR/AV presence** — informational: detect common Endpoint-Security agents; report which vendor holds the ES entitlement (overlaps HA-A06). | R | 🟡 | n/a |

## C. Network exposure

| ID | Check | Detect | Sev | Fix |
|----|-------|--------|-----|-----|
| HA-C01 | **Inbound Application Firewall on** — `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`. | R | 🟠 | auto! |
| HA-C02 | **Stealth mode + block-all + logging** — `--getstealthmode`, `--getblockall`, `--getloggingmode`; flag "automatically allow signed/downloaded software" which quietly punches holes. | R | 🟡 | auto! |
| HA-C03 | **★ Outbound firewall present** — Little Snitch or LuLu (Objective-See). The direct exfiltration tripwire for same-user malware. Recommend if absent; note default-allow rulesets weaken it. | R | 🟠 | advise (install) |
| HA-C04 | **★ Exposed local services** — `lsof -nP -iTCP -sTCP:LISTEN` (+ UDP). Flag anything bound to `0.0.0.0`/`*`/a LAN IP rather than loopback — dev Postgres/Redis/Mongo/Elasticsearch with default creds reachable off-box. | R | 🟠 | advise |
| HA-C05 | **Sharing services off unless needed** — Remote Login/SSH (`systemsetup -getremotelogin`), Remote Management/ARD, Screen Sharing, File Sharing (SMB/AFP), Printer/Media Sharing, Internet Sharing, Remote Apple Events, Content Caching. Enumerate via `launchctl print-disabled system` + per-service daemons. | R! | 🟠 | auto! |
| HA-C06 | **AirDrop / AirPlay Receiver / Bonjour** — AirDrop not "Everyone", AirPlay Receiver scope, mDNS advertisement footprint. | R | 🟡 | advise |
| HA-C07 | **Resolver integrity** — `scutil --dns`; flag unexpected/injected nameservers or a search domain that could hijack lookups; note whether encrypted DNS (DoH/DoT) profile is present. | R | 🟡 | advise |
| HA-C08 | **★ Custom root CAs / trust anchors** — `security dump-trust-settings -d` (admin) and `-s` (system) plus the user domain. Every non-Apple root anchor enables silent TLS interception of your secrets in transit. Flag each; corporate-proxy CAs are legitimate-but-worth-surfacing. | R | 🔴 | advise |
| HA-C09 | **Global HTTP(S) proxy** — `scutil --proxy`; flag an unexpected system proxy or PAC URL (classic MITM persistence). | R | 🟠 | advise |
| HA-C10 | **VPN / relay posture** — enumerate active tunnels (e.g. Tailscale/WireGuard network extensions from HA-A06); informational, plus flag `utun`/PF rules that route traffic unexpectedly. | R | 🟡 | n/a |

## D. Privacy / TCC — **★ high-value, needs Full Disk Access**

An app holding any of these grants bypasses much of what csec protects (it can
read csec's own files, capture the consent window, or keylog the Touch ID
moment). This is the most valuable *new* surface. The system TCC DB lives at
`/Library/Application Support/com.apple.TCC/TCC.db` and the per-user DB at
`~/Library/Application Support/com.apple.TCC/TCC.db`; both are SIP-protected, so
enumerating them requires csec itself to hold Full Disk Access (even the root
helper cannot read `TCC.db` without it).

Per the "more secure, conveniently" ethos, **csec requests Full Disk Access as
part of first-run/setup and enumerates section D automatically** — the capability
is worth the security it unlocks, and it is not a footprint we avoid. If the
grant is absent, degrade gracefully to deep-links into the exact
System Settings > Privacy panes rather than silently skipping the section.

| ID | Check | Detect | Sev |
|----|-------|--------|-----|
| HA-D01 | **Full Disk Access grantees** — read every app sandbox, Mail, Messages, Safari history, *and csec's files*. Enumerate `kTCCServiceSystemPolicyAllFiles`; flag unexpected holders. csec lists **its own** FDA grant explicitly as `csec (this tool) — expected; required for the privacy audit`, never as a finding. | F | 🔴 |
| HA-D02 | **Accessibility grantees** — `kTCCServiceAccessibility`: synthetic input + full UI control (keylogging, dismissing prompts). | F | 🔴 |
| HA-D03 | **Screen Recording grantees** — `kTCCServiceScreenCapture`: can capture the consent window and any on-screen secret. | F | 🔴 |
| HA-D04 | **Input Monitoring grantees** — `kTCCServiceListenEvent`: raw keystroke access. | F | 🔴 |
| HA-D05 | **Automation (AppleEvents)** — `kTCCServiceAppleEvents`: app A scripting app B (privilege chaining). | F | 🟠 |
| HA-D06 | **Developer Tools / debugger** — `kTCCServiceDeveloperTool` holders; overlaps `com.apple.security.cs.debugger` entitlement scanning. | F | 🟠 |
| HA-D07 | **Camera / Microphone** grantees — `kTCCServiceCamera`, `kTCCServiceMicrophone`. | F | 🟡 |
| HA-D08 | **Location Services** enabled + per-app grants; system services using location. | R/F | 🟡 |

All TCC remediations are **advise** — revoking a grant can break a legitimate
workflow, so csec surfaces and links, never auto-revokes.

## E. Persistence & background execution — **★**

Where a same-user attacker hides to survive reboot; also the first place to look
after a suspected compromise.

| ID | Check | Detect | Sev |
|----|-------|--------|-----|
| HA-E01 | **LaunchAgents/Daemons** — `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`. Flag non-Apple, unsigned `Program`/`ProgramArguments` targets, user-writable plists, `RunAtLoad`+`KeepAlive`, and `EnvironmentVariables` carrying `DYLD_INSERT_LIBRARIES`. | R | 🟠 |
| HA-E02 | **Login items & SMAppService background items** — `sfltool dumpbtm` (root/FDA, macOS 13+); flag developer-unknown items. | F | 🟠 |
| HA-E03 | **Configuration profiles** — `profiles list -all` / `profiles show`. Flag installed root certs, HTTP proxies, unexpected MDM enrollment, or any profile the user didn't install. | R! | 🔴 |
| HA-E04 | **cron / at / periodic** — user + system crontabs, `/etc/periodic`, `at` queue; flag unexpected jobs. | R | 🟡 |
| HA-E05 | **Login/logout hooks** — deprecated `com.apple.loginwindow` `LoginHook`/`LogoutHook`; any presence is suspicious. | R | 🟡 |
| HA-E06 | **Shell startup persistence** — `.zshenv`/`.zprofile`/`.zshrc`/fish `config.fish`/`.bashrc` sourcing unknown scripts, prepending writable dirs to `PATH`, or exporting `DYLD_*`. (Coordinates with the secrets history audit.) | R | 🟠 |
| HA-E07 | **launchd overrides & disabled-service tampering** — `/var/db/com.apple.xpc.launchd/` overrides re-enabling a service the OS ships disabled. | R! | 🟡 |

## F. Developer attack surface — **★ least covered by generic guides, most relevant here**

| ID | Check | Detect | Sev |
|----|-------|--------|-----|
| HA-F01 | **`PATH` hijack** — for each `$PATH` entry `ls -ld`; flag `.`/empty/relative entries, group/other-writable dirs, and writable dirs ahead of `/usr/bin`. A writable early-PATH dir lets malware shadow `git`, `ssh`, `op`, even `csec`. | R | 🟠 |
| HA-F02 | **Global `DYLD_*` / `LD_*` preload** — exported in shell profiles, `launchctl setenv`, or launchd plists (dylib injection into trusted processes). | R | 🟠 |
| HA-F03 | **Package-manager script execution** — `npm config get ignore-scripts` (and yarn/pnpm equivalents); recommend disabling lifecycle scripts globally. The exact "malicious postinstall" vector csec's README cites. | R | 🟠 |
| HA-F04 | **Editor extensions** — enumerate VS Code / Cursor (`~/.vscode/extensions`, `code --list-extensions`) and JetBrains plugins. Flag unverified publishers, broad filesystem/network access, sideloaded VSIX, and recently-updated extensions. | R | 🟠 |
| HA-F05 | **Browser extensions** — Chrome/Edge/Brave/Firefox/Safari profiles. Flag "read & change all data on all websites", `<all_urls>`/`cookies`/`webRequest` permissions, unpacked/sideloaded, and low-reputation IDs (session-cookie / token theft). | R | 🟠 |
| HA-F06 | **Git config hygiene** — plaintext `credential.helper store`, `core.hooksPath` pointing outside the repo, global `insteadOf` URL rewrites, `core.fsmonitor` invoking a script, over-broad `safe.directory=*`. | R | 🟠 |
| HA-F07 | **Docker exposure** — daemon bound to a TCP socket, `DOCKER_HOST` over TCP, containers run `--privileged` or with the docker socket mounted. | R | 🟠 |
| HA-F08 | **SSH client hardening** — `~/.ssh` perms, `StrictHostKeyChecking no`, `ForwardAgent yes` defaults, `IdentitiesOnly`, `AddKeysToAgent`; unexpected `authorized_keys` on this host. (Key passphrases stay in the secrets audit.) | R | 🟡 |
| HA-F09 | **Homebrew** — outdated formulae/casks (`brew outdated`), untrusted/third-party taps, `/usr/local` or `/opt/homebrew` writable by non-owner. | R | 🟡 |
| HA-F10 | **SUID/SGID & world-writable** — bounded scan for unexpected SUID/SGID binaries and world-writable files in `$HOME`, `/usr/local`, `/opt`. Expensive → run opt-in / time-boxed, and *log the bound* rather than implying full coverage. | R! | 🟡 |

## G. Accounts, authentication & physical

| ID | Check | Detect | Sev | Fix |
|----|-------|--------|-----|-----|
| HA-G01 | **No auto-login** — `com.apple.loginwindow autoLoginUser` unset; `DisableFDEAutoLogin=1`. Auto-login defeats FileVault-at-rest + physical security. | R | 🔴 | auto! |
| HA-G02 | **Screen lock immediate/short** — `sysadminctl -screenLock status`; screensaver `askForPassword`+delay; no screensaver-disabling hot corner. | R | 🟠 | auto |
| HA-G03 | **FileVault on** — `fdesetup status`; report recovery-key escrow posture and secure/bootstrap-token presence. Enable needs a state transition (recovery-key handling, restart) → guided helper. | R | 🔴 | guided |
| HA-G04 | **Root account disabled** — `dscl . -read /Users/root AuthenticationAuthority` shows disabled. | R! | 🟠 | auto! |
| HA-G05 | **Guest account off**; login window shows name+password not the user list; password hints off; no automatic "Other…". | R | 🟡 | auto! |
| HA-G06 | **Admin surface** — count admin users; flag if the daily-driver account is admin (running standard shrinks blast radius, though most devs won't). | R | 🟡 | advise |
| HA-G07 | **`sudo` posture** — `tty_tickets` on, sane `timestamp_timeout`, no unexpected `NOPASSWD`, review `#includedir /etc/sudoers.d`. | R! | 🟠 | advise |
| HA-G08 | **Touch ID for `sudo`** — add `pam_tid.so` via `/etc/pam.d/sudo_local` (survives OS updates, unlike editing `/etc/pam.d/sudo`). On-brand with csec's Touch-ID consent model. | R! | 🟡 | auto! |
| HA-G09 | **Apple ID 2FA / iCloud** — not locally verifiable → advise enabling. | X | 🟠 | advise |
| HA-G10 | **Password policy** — `pwpolicy` min length/complexity where org-relevant; no blank passwords. | R! | 🟡 | advise |

## H. Physical / theft / device

| ID | Check | Detect | Sev | Fix |
|----|-------|--------|-----|-----|
| HA-H01 | **Find My Mac / Activation Lock** — `system_profiler SPHardwareDataType` reports Activation Lock status; advise enabling Find My. | R/X | 🟠 | advise |
| HA-H02 | **USB/Thunderbolt "Allow accessories"** — macOS 13+ setting (Ask / Always); DMA protection posture. Restricting new-accessory auto-connect mitigates malicious USB while locked. | R | 🟡 | advise |
| HA-H03 | **Lockdown Mode** — report state; advise only for high-risk/targeted users (breaks a lot). | R | — | advise |
| HA-H04 | **Secure boot chain integrity** — surfaces HA-A01/A02/A05 together as a single "boot & recovery" verdict for the physical-threat lens. | R/X | 🔴 | advise |

## I. Time, logging & auditability

| ID | Check | Detect | Sev | Fix |
|----|-------|--------|-----|-----|
| HA-I01 | **Network time on** — `systemsetup -getusingnetworktime` / `-getnetworktimeserver`; trusted NTP source (cert/token validation depends on correct clock). | R! | 🟡 | auto! |
| HA-I02 | **Audit trail** — note OpenBSM/`auditd` is deprecated on modern macOS; recommend an Endpoint-Security-based tool (ties to HA-B08/HA-A06) instead of relying on `/etc/security/audit_control`. | R | 🟡 | advise |
| HA-I03 | **Crash/analytics sharing** — diagnostic submission to Apple/third parties; flag if crash reports (which can contain memory) are shared externally. | R | 🟡 | advise |

## J. Data leakage / sync (CIS-depth completeness, mostly advisory)

| ID | Check | Detect | Sev |
|----|-------|--------|-----|
| HA-J01 | **Clipboard-manager history** — detect managers persisting clipboard to disk (secrets leak); Universal Clipboard/Handoff on. | R | 🟡 |
| HA-J02 | **Time Machine encryption** — `tmutil destinationinfo`; flag unencrypted backup destinations (secrets restore-able off a stolen drive). | R! | 🟠 |
| HA-J03 | **Safari "open safe files after downloading"** off — auto-open is a drive-by vector. | R | 🟡 |
| HA-J04 | **Spotlight indexing** of sensitive dirs; Siri suggestions surfacing file contents. | R | 🟡 |
| HA-J05 | **iCloud sync scope** — Desktop/Documents sync, iCloud Keychain (informational vs csec), iCloud Private Relay state. | R | 🟡 |
| HA-J06 | **Screenshot defaults** — location and whether screenshots of secret-bearing windows sync to iCloud. | R | 🟡 |

## K. csec's own coverage & integration — **★**

The audit also verifies that csec itself is actually protecting what it claims,
so a silently-removed hook or an un-onboarded tool gets caught. Shares its check
+ remediation code with `csec setup` (one source of truth), so setup gaps surface
here even when the user never re-runs setup.

| ID | Check | Detect | Sev |
|----|-------|--------|-----|
| HA-K01 | **Redaction active in each detected coding agent** — for every installed Claude Code / Codex (etc.) client, confirm the csec `PreToolUse` hook is present, points at the durable installed `csec`, and fails closed when csecd/csec is unavailable. Flag agents where it's missing, disabled, or superseded. | R | 🟠 |
| HA-K02 | **Hook not shadowed** — competing hooks, `disableAllHooks`, or untrusted hook trust state that would stop the csec hook from running. | R | 🟠 |
| HA-K03 | **Agent + helpers healthy** — `csecd`, `csec`, and `csec-rootd` signatures/notarization/ownership/launchd state match the signed-device release gates (generalizes `StartupSecurityReport` to a user-facing verdict). | R | 🟠 |
| HA-K04 | **Consumers on a strong delivery path** — flag high-impact references still delivered via `csec exec` environment compatibility when a heap / credential-protocol / inherited-fd / protected-file path is available. | R | 🟡 |
| HA-K05 | **Known plaintext originals not yet remediated** — cross-reference the secrets migration tracker: references imported into a store whose plaintext original still exists (M/V done, R outstanding). | R | 🟡 |

---

## Remediation model: secure-convenient defaults, batched confirmation

Per the ethos, the audit does not merely report — it **proposes the secure
default and applies it for you after one confirmation**. Findings sort into three
remediation classes:

**1. Auto-fix (one review, one Touch ID).** Safe, reversible, low-blast changes.
csec presents them as a single batched **checklist the user can deselect items
from** (each change shown explicitly, dry-run first); one Touch ID then applies
everything still selected, atomically per target, and never bundles privileged
mutations into one implicit transaction. Eligible:

| ID | Change | Why safe |
|----|--------|----------|
| HA-C01/C02 | Enable inbound firewall + stealth + logging | Fully reversible toggle; no data loss |
| HA-C05 | Turn off unused sharing services | Reversible; user re-enables on demand |
| HA-B04 | Enable auto security-data / critical updates | Reversible pref flip; strictly safer |
| HA-G01 | Remove `autoLoginUser`, set `DisableFDEAutoLogin` | Reversible; only tightens |
| HA-G02 | Set screen-lock delay immediate/short | Reversible pref |
| HA-G04/G05 | Disable root + guest accounts | Reversible; both should already be off |
| HA-G08 | Add Touch ID for `sudo` via `/etc/pam.d/sudo_local` | Additive, reversible, update-safe |
| HA-I01 | Enable network time | Reversible |
| HA-A03 | Clear an unexpected `boot-args` | Reversible NVRAM write — **guarded**: only when a known-dangerous token is present, always shown pre-apply |

**2. Guided helper (interactive).** More-secure but needs a choice or a state
transition csec should walk the user through rather than silently flip:

| ID | Helper |
|----|--------|
| HA-G03 | **FileVault** — drive `fdesetup enable`, capture/escrow the recovery key, and prompt the restart. High value and on-brand for a Touch-ID security tool; the interaction *is* the recovery-key handling. |
| HA-B08 | **Santa** — install plus a sane **MONITOR-mode** starting ruleset. Deliberately never auto-flips to LOCKDOWN (a bad rule can lock the user out of their own binaries); the helper is bounded to a safe starting posture the user can tighten later. |

**3. Advise-only (surface + link, never mutate).** Either unautomatable, or a
judgment call where auto-applying would risk breaking a legitimate setup:

- SIP / SSV / Apple-Silicon boot policy (HA-A01/A02/A05) — recoveryOS only.
- Revoking TCC grants (HA-D*) — can break a legitimate workflow.
- Removing config profiles or custom root CAs (HA-C08/E03) — may be legitimate
  corporate/MDM policy.
- Unloading kexts, removing browser/editor extensions (HA-A04/F04/F05) — user
  judgment; csec flags with evidence.
- Installing LuLu / Little Snitch (HA-C03) — third-party; their own onboarding is
  good, so csec links rather than drives.

## Detection-feasibility summary

- **Most checks are `R` — runtime-readable and value-free.** csec can assert
  these directly, exactly as `StartupSecurityReport` already asserts SIP/signing.
- **`R!` needs root** (sharing services, some account/audit reads, boot-args
  clear). Route through the existing signed root-helper (`csec-rootd`) so the
  privileged read/write stays inside the verified code path.
- **`F` needs Full Disk Access** — the entire TCC section (D) and BTM login items
  (HA-E02). csec holds FDA (requested at setup/first-run per the ethos) and
  enumerates these automatically; if the grant is missing it degrades to the
  manual System-Settings panes rather than skipping silently.
- **`X` is not verifiable at runtime** — Apple-Silicon boot policy (`bputil`,
  recoveryOS), owner passcode, iCloud 2FA. Report honestly as *unverifiable*,
  advise + link, and infer where a proxy signal exists (e.g. a loaded
  third-party kext ⇒ Reduced Security).

Be explicit in the report about which tier each finding came from — never let an
`X` "couldn't check" render as a green "pass," and never let a bounded scan
(HA-F10) imply full coverage.

## Proposed surface

A single **`csec audit`** command (no subcommand namespace yet), which
`csec setup` runs automatically once onboarding completes:

- **Report + propose in one pass.** Each finding = `id · severity · value-free
  evidence · exact anchor · remediation-class`, severity-ordered, grouped so the
  ★ tier-1 controls lead. By default `csec audit` then offers the batched
  auto-fix set under one Touch ID and launches any guided helpers the user opts
  into — reporting and remediation are one flow, not two commands, per the
  strong-defaults ethos.
- **`--report-only`** for the read-only view with no proposal (CI, or an AI-agent
  consumer that wants findings as data).
- **Bounded/expensive scans** (SUID sweep HA-F10) stay opt-in behind a flag and
  log their bound so partial coverage never reads as a pass.
- Ends with an overall posture verdict and an explicit list of *unverifiable*
  items (the `X` tier), never claiming coverage it couldn't prove — same
  discipline as the secrets audit's ship/hold recommendation.

### Integration with `csec setup`

`csec audit` is a **superset** of setup's own posture checks, so setup gaps
surface in the audit too (domain K). Setup remains the place that *installs*
integrations; audit is the place that *verifies* them and flags regressions —
e.g. a detected coding agent whose csec redaction hook was removed, disabled, or
never installed shows up as an `HA-K01` finding even if the user never re-runs
setup. Both call the same check + remediation code; there is one source of truth
for "is redaction active in this agent," used at install time and at audit time.

### Periodic re-audit and regression detection

Because `csecd` is already resident, `csec audit` also runs on a schedule against
a stored **accepted baseline**. It stays quiet unless a previously-good control
**regresses** — firewall turned off, a new app granted Full Disk Access, a
redaction hook removed — which is a high-signal event (it can mean malware
disabling defenses). On a regression csec **notifies only** (surfacing the exact
finding); it does not mutate anything in the background, and the user re-runs
`csec audit` to re-apply the fix. The baseline advances only when the user
accepts the new state; unreviewed drift keeps surfacing.

## Decisions (resolved)

1. **Command:** a single `csec audit`; `csec setup` runs it automatically on
   completion. No subcommand namespace yet. Audit is a superset of setup's checks
   (domain K).
2. **Privacy/FDA:** csec takes Full Disk Access (requested at setup/first-run)
   and enumerates section D automatically, with a graceful manual fallback if
   absent. Rationale: the "more secure, conveniently" ethos — the capability buys
   real security the user wouldn't configure by hand; minimal footprint is *not*
   a goal for csec's own privileges.
3. **Version currency (HA-B03/B05):** report raw XProtect/OS versions and derive
   the verdict from `softwareupdate -l` + the auto-update flags. No bundled floor,
   no runtime fetch — all-local, nothing rots.
4. **Guided helpers:** FileVault (HA-G03) and Santa MONITOR-mode (HA-B08) get
   guided helpers; LuLu / Little Snitch stay doc-links.
5. **Auto-fix confirmation:** one review + one Touch ID — the batched auto-fix set
   is a checklist the user can deselect from, then a single tap applies the rest.
6. **Periodic re-audit:** runs on a schedule against a stored accepted baseline;
   on a regression it **notifies only** (no background mutation), and the user
   re-runs `csec audit` to remediate.
7. **Offline version currency:** report `unknown` with the last successful check
   time; never render an unreachable catalog as a pass.
8. **csec's own FDA grant:** shown in HA-D01 as `expected-self`, never a finding.
9. **Delivery:** all domains A–K ship in the first release (full catalog, not
   phased).

## Open questions

None outstanding — every design decision is resolved above. Implementation is
specified in [`host-audit-implementation-plan.md`](host-audit-implementation-plan.md).
