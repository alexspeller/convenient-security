# Claude Code release verification

Delegation requires both a trusted Claude Code identity and a settings loader
checked against csec's gate. `ClaudeBuildVerification.shipped` records exact
host-slice code-directory hashes inside signed csecd. Version labels and paths
are display metadata. Publisher signatures and `csec setup` custom-build trust
do not certify a loader. There is no inferred version range or expiry timer.

Claude Code updates itself far more often than csec ships, so the checked list
also arrives on its own: the `claude_code` section of the signed release
manifest ([release manifest](release-manifest.md)) lists every audited image,
and csecd adds the ones its compiled catalog lacks. The manifest is verified
against a release key pinned in csec on every read, so a file replaced on disk
adds nothing; it can only add images, never withdraw a compiled one; and csec
keeps working offline from the last copy it verified. csecd fetches it a few
minutes after it starts and daily, and sooner (at most every 30 minutes) while
requests are declining on an unchecked image, so an image audited since the
last check delegates again within the hour. A build that pins no release key
uses its compiled catalog alone.

An unchecked image sends secret access, SSH signing and sudo to their ordinary
Touch ID reviews. All three Mac layouts and the phone use the same
`DelegationDecline.uncheckedBuild` reason, which says that auto mode resumes by
itself once csec's list of checked releases includes the image. Existing grants
retain their normal lifetime. A newer signed list or an installed catalog
restores delegation automatically; the human does not repeat setup or re-enable
it.

The native installer, Homebrew's `claude-code` cask and npm's
`@anthropic-ai/claude-code` package all run the same Anthropic-signed image with
the same code-directory hash (checked for 2.1.325: all three are
`cb0b92a2ee6314aeadf4303ca2b503a181ad9f7f`), so one audit covers every route.
npm's `bin/claude.exe` is recognised as Claude Code like the native installer's
version-named binary, and Homebrew's runs as `claude`.

`csec status` and `csec doctor` warn about unchecked images. This is a safe
fallback, so it does not itself make doctor fail. The read-only
`csec status --claude-builds-json` reports only csecd's bounded compatibility
inventory: native versions, mise's standalone npm installations, Homebrew's
cask versions under `/opt/homebrew/Caskroom/claude-code`, global npm installs
under `/opt/homebrew/lib/node_modules` and `/usr/local/lib/node_modules`, and
live Claude images with exec-bound identities. Discovery does not execute
Claude. Other inactive install locations (a per-user Node manager's, say) are
not searched; a live Claude image is checked wherever it runs.
Unreadable/truncated discovery is reported explicitly. The installed daemon
supplies the catalog, so an updated source checkout cannot make a stale
installed daemon appear recovered.

## Verified images

| Release | Architecture | cdhash | Evidence |
| --- | --- | --- | --- |
| 2.1.267 | macOS arm64 | `21209468e54034262a7f049c21983dca5f06ed09` | [Complete source audit and synthetic probes](claude-release-audits/2.1.267.md), `csec-cc-21209468e54034262a7f049c21983dca5f06ed09`. Includes generated-policy refusal, marketplace alias/rename discovery and root-skill corrections. |
| 2.1.278 | macOS arm64 | `af5e0f66b9fd8fdc7e615959dc602cd6386d8d11` | [Complete source audit and 16 isolated probes](claude-release-audits/2.1.278.md), `csec-cc-af5e0f66b9fd8fdc7e615959dc602cd6386d8d11`. Requires the shared generated-policy, marketplace/root-skill, remote-session and disk-synced-hook corrections. |
| 2.1.280 | macOS arm64 | `a2a0746b3c279794afb4eb104aaa6bb88a252a34` | Existing C2 source audit (`csec-q3v.9`), follow-up loader fixes in `ClaudeSettingsGate.swift` and its regression suite; original report `~/.claude/plans/rosy-stargazing-micali-research/impl/C2-report.md`. The installed image's complete signature and Anthropic requirement were checked again for csec-a1k. |
| 2.1.282 | macOS arm64 | `aec6b146f0cd2378b1489dd316f69d16e11591aa` | [Complete source audit, synced-skill correction and synthetic probes](claude-release-audits/2.1.282.md), `csec-cc-aec6b146f0cd2378b1489dd316f69d16e11591aa`. Disk-backed synced account skills retain approving hooks and require the bounded account-root scan. |
| 2.1.295 | macOS arm64 | `7bfc0b1005fbcb70382ca4e4dd3ae9f7ff2f119b` | [Complete source audit and 16 synthetic probes](claude-release-audits/2.1.295.md), `csec-cc-7bfc0b1005fbcb70382ca4e4dd3ae9f7ff2f119b`. Official archive matches the installed mise image; requires the shared remote-relay refusal and synced account skill scan. |
| 2.1.301 | macOS arm64 | `c17da5ef4bfdb3894ec64fee484b9de17127def8` | [Complete source audit and 26 isolated probes](claude-release-audits/2.1.301.md), `csec-cc-c17da5ef4bfdb3894ec64fee484b9de17127def8`. Official archive matches mise's `2` image; existing helper/plugin/synced-skill/relay guards remain required. This does not certify 2.1.310. |
| 2.1.302 | macOS arm64 | `3759f6c69569d1685ffcd6eea1c7e20539c2d4b5` | [Complete source audit and 22 isolated probes](claude-release-audits/2.1.302.md), `csec-cc-v2-1-302`. Requires the standalone-relay selector refusal; the newly active classifier model selector retains the existing model-quality policy. |
| 2.1.305 | macOS arm64 | `78d6b9ed85da6de5b0847587570cb3ae268a5c96` | [Complete source audit and 28 isolated probes](claude-release-audits/2.1.305.md), `csec-cc-v2-1-305`. Existing helper, plugin, synced-skill and relay corrections remain required; new containment and mounted-plugin restrictions narrow capabilities. |
| 2.1.310 | macOS arm64 | `62f3298fb35e54f02451657e7bfbcd0b795657c7` | [Complete source audit and 30 isolated probes](claude-release-audits/2.1.310.md), `csec-cc-v2-1-310`. Existing source/transport boundaries remain required; the new standalone-proxy URL retains the refused relay selector, expanded sealed middleware preserves decisions, and HTTP plugin launch remains compiled off. |
| 2.1.311 | macOS arm64 | `a9faecb664dd8b01e19cdfc12af95da1b267f10e` | [Complete source audit and 35 isolated probes](claude-release-audits/2.1.311.md), `csec-cc-v2-1-311`. Existing source/transport boundaries remain required; the new removal waiver requires refused bypass mode, the dispatch shortcut retains settings hooks, and moved HTTP plugin launch remains compiled off. |
| 2.1.312 | macOS arm64 | `9d4c442a850897e6cf0e68c0d022b98859161d2e` | [Complete source audit and 40 isolated probes](claude-release-audits/2.1.312.md), `csec-cc-v2-1-312`. Existing source/transport boundaries remain required; managed-policy invalidation and model-hook admission add no source, synced skills retain hooks, and HTTP plugin launch remains compiled off. |
| 2.1.314 | macOS arm64 | `33bc52834785912c4ff7dd9e2b9e8c1dd38ef9fd` | [Complete source audit and 48 isolated probes](claude-release-audits/2.1.314.md), `csec-cc-v2-1-314`. Existing source/transport boundaries remain required; family-only Monitor hooks cannot allow or rewrite, incomplete fast-stage allows are set aside, selected rules stay source-filtered, and HTTP plugin launch remains compiled off. No published 2.1.313 image was found. |
| 2.1.315 | macOS arm64 | `0be2f7d3dad265d1ef590ee83623569caab5fcdd` | [Complete source audit and 53 isolated probes](claude-release-audits/2.1.316.md), `csec-cc-v2-1-316`. Published on npm only and replaced by 2.1.316 hours later; existing source/transport boundaries remain required. |
| 2.1.316 | macOS arm64 | `e49e58a1feeb798a46fcdd8d07bcac4ee5ad1428` | [Complete source audit and 53 isolated probes](claude-release-audits/2.1.316.md), `csec-cc-v2-1-316`. Existing source/transport boundaries remain required; per-source classifier allow lists only narrow, a refused remote copy's helper-tier `env` still declines, the new diskless hook shortcut has no setter, and HTTP plugin launch remains compiled off. |
| 2.1.317 | macOS arm64 | `9fd02acbf815f7259d78c4f779c2930ad33ca9aa` | [Source delta audit and 64 isolated probes](claude-release-audits/2.1.317.md), `csec-cc-v2-1-317`. Existing source/transport boundaries remain required; plugin anchors narrow paths, callback failures can block explicitly, native credential storage retains its existing legs, and the new unnamed-403 retry needs an independently refused custom endpoint/socket. |
| 2.1.318 | macOS arm64 | `f9106e5a4887c4904a64d3b9dd15e7154f6120d7` | [Source delta audit and 68 isolated probes](claude-release-audits/2.1.318.md), `csec-cc-v2-1-318`. Existing source/transport boundaries remain required; REPL joins the filtered tool family, MCP policy lifting stays in acceptEdits, and HTTP hook previews add no execution source. |
| 2.1.319 | macOS arm64 | `c3fca2f1fef791c80f93c36ca7b029950614005b` | [Sequential source delta audit and 79 isolated probes](claude-release-audits/2.1.318.md), `csec-cc-v2-1-319` folded into `csec-cc-v2-1-318`. Existing source/transport boundaries remain required; public classifier allow sources stay fixed, trust/root filters narrow sources, and explicit outside server-off retains precedence. |
| 2.1.325 | macOS arm64 | `cb0b92a2ee6314aeadf4303ca2b503a181ad9f7f` | [Source delta audit from 2.1.319 and 79 isolated probes](claude-release-audits/2.1.325.md), `csec-cc-v2-1-325`. Requires the new `CLAUDE_CODE_USER_DELEGATED_SESSION` family to decline on presence (it picks the classifier model before server/org precedence); existing source/transport boundaries remain required, and the rewritten privacy middleware only adds denies. 2.1.321–2.1.323 are not certified by this row. |

Add an image to this table and the compiled catalog only after completing the
checklist. Keep evidence for older entries when adding a release.

The custom tweakcc 2.1.257 image
(`64a09464023aa47514a78be456da5b89e01b50a6`, [its audit](claude-release-audits/2.1.257-custom.md))
was a developer's own build, never one buyers run, and is no longer in the
catalog. A custom image is admitted only by an audit and the human's own
custom-build trust; neither ships to anyone else.

Legacy npm JavaScript entrypoints have no native code-directory hash. The
[0.2.126 and 1.0.41 inventory investigation](claude-release-audits/legacy-npm-entrypoints.md)
records their official-source comparison, inactive launch selection and
retirement recommendation. Neither is certified: a Node runtime's signature
does not identify the mutable script it loads. Keep these entries unchecked
until their actual installations are removed; never suppress them by path,
version label or the absence of a running process.

## Automatic detection and recovery

[`bin/check-claude-release.py`](../bin/check-claude-release.py) is the release
watch: run on a schedule every five minutes on a maintainer's Mac, without
model inference for clear checks. It reads the installed daemon's inventory
and Anthropic's official `claude-code-releases/latest` endpoint. An unknown
installed/live identity or an unchecked latest release trips the watch. A
release label is sufficient to schedule research; it is never sufficient to
authorize a process.

A tripped watch starts one audit for that identity or release, kept through
lost responses and restarts. The audit rechecks the current inventory,
performs the source/probe checklist, fixes mismatches, updates the catalog,
passes gates, installs and publishes the next signed list. It records the
installed daemon's matching identity before resolving recovery. A failed
audit stays tracked with Touch ID available; no checker or agent simply
whitelists a new signature/version. Custom-build publisher trust still
requires the existing human setup flow.

The watch belongs to the maintainer's scheduler: it adds no csec installer,
helper, launchd job or privileged endpoint. Buyers' Macs run no watch; they
receive each audit as the signed list above, with the safe Touch ID fallback
until it arrives. Errors, unsupported inventory, unavailable upstream metadata
and timeouts never report clear. Known unchecked local images still trip when
upstream is unreachable. The check reads no credential, settings value or
Claude login file and never executes a candidate; csecd inspects
code-signature metadata and validity. What it reports contains bounded image
identity/path/version metadata and the public upstream release label only.

## Source and probe checklist

Release notes identify leads; they do not establish loader compatibility.
On a Mac in use, check memory pressure and swap before parsing or building.
Parse source trees one at a time with a bounded heap (3 GiB suffices for the
2.1.317 audit), and use at most two build jobs. Keep total RSS below a quarter
of physical RAM; stop if pressure rises to yellow/red or swap grows.
For each actual image that will be allowed to delegate:

1. Record its origin, architecture, complete code-signature validity,
   Anthropic requirement (or existing custom-build trust), and host-slice
   cdhash. Do not run the candidate to obtain a version. Read public package
   metadata or source instead, treating labels as untrusted metadata.
2. Obtain its source from the official distribution. Current native Bun
   executables contain UTF-8 source chunks beginning `// @bun @bytecode`;
   extract those without executing the binary. Retain source offsets/module
   identities and a comparison with the previous checked image in the audit
   bead. Do not commit the upstream executable or bundled source into csec.
3. Trace every settings source and precedence rule: user, policy/MDM/remote,
   cowork, project/local/ancestor/worktree, additional directories and inline
   settings. Check global config and settings-applied environment changes.
   Trace `policyHelper` / `policyHelpers`, including refreshes and nested
   fallback payloads: a managed source containing either key currently
   declines because the gate cannot inspect the policy it produces. Never
   acknowledge the helper's configuration as proof of its output.
4. Trace plugin/marketplace registries, in-place and seeded plugin roots,
   manifest hooks/modules, built-ins and skill/agent/command frontmatter. Check
   the `CLAUDE_CODE_HOVER_REST` / `tengu_hover_rest` v5 storage factory and its
   callers. An active backend the gate cannot inspect keeps the image paused.
   Include `additionalMarketplaces` alias precedence, catalog rename chains
   and their bounds, both names' recorded/cache roots, and a plugin's fallback
   `SKILL.md` at its root.
   Trace disk-backed `skills/synced/<account>/<skill>/SKILL.md` separately
   from memory/remote skill factories. A text-sanitizing helper does not
   imply hooks are stripped; follow parsing through actual hook registration.
5. Recheck argv/environment selectors, code injection/loading, disabled hooks,
   sandbox auto-allow, bypass modes, classifier rules and models. Recheck that
   `autoMode.classifyAllShell` removes every Bash/Monitor allow path and that
   csec's PreToolUse registration still precedes Claude's permission decision.
   Account for both client-side and server-side auto mode. Trace the
   environment that reaches the classifier's request: body overrides
   (`CLAUDE_CODE_EXTRA_BODY`), provider selection and endpoint companions,
   transport (`ANTHROPIC_UNIX_SOCKET`), what context it is shown, and whether
   `CLAUDE_CODE_AUTO_MODE_MODEL`, `CLAUDE_CODE_BG_CLASSIFIER_MODEL`,
   `CLAUDE_CODE_TWO_STAGE_CLASSIFIER` or
   `CLAUDE_CODE_AUTO_MODE_EXTERNAL_PERMISSIONS`, unread in 2.1.280, now have
   a reader. Also trace the `CLAUDE_CODE_REMOTE` session's tool relay and
   its endpoint/CA environment separately from the classifier's transport.
   Trace every route that sets the API provider without the environment,
   above all the stored Cloud-gateway sign-in (csec-kpep, 2.1.316 `IRn`,
   `Wre`): that the secure-storage record's key is still `enterpriseGateway`
   at its top level; the Keychain service and account names
   (`ClaudeGatewaySignIn.isCredentialService` / `isCredentialAccount`), read
   through `security find-generic-password -w`; the plaintext fallback's path
   and `CLAUDE_SECURESTORAGE_CONFIG_DIR`; and any new setter of the gateway
   slot or other stored provider route.
6. Add synthetic regressions for each discovered loader or policy difference.
   Unknown/unreadable sources must decline. Check source behavior with small
   isolated probes using synthetic settings and values, never real login data.
   Record what each probe establishes and its limitations.
7. Add only the exact audited image hashes to `ClaudeBuildVerification.swift`
   and this table. One audit covers the native, Homebrew and npm routes only
   when their hashes match; record any that differ separately. Run the delegation setup, protocol, session-facts and
   delegation suites and the warnings-as-errors build, followed by the
   project's required gate. New approval wording/behavior must cover secret,
   SSH, sudo and phone through their shared copy and tests.
8. Commit and install it the way
   [Finishing work](agents/finishing-work.md) says. Record the final doctor
   result, then re-read `csec status --claude-builds-json`: the actual
   live/new image must be checked by the installed daemon. No manual re-enable
   should be necessary. Keep the watch's audit tracked until its affected
   images are checked or a factual disposition is recorded; recheck before
   resolving it.
9. Publish it to buyers: `bin/release-manifest.py claude --previous
   manifest.json manifest.json.next` writes the next manifest with this
   checkout's whole catalog as its `claude_code` list, carrying the announced
   release over; then sign, verify and publish it as
   [Publishing a release](release-manifest.md#signing) steps 4 to 6 say.

The audit's work bead must stand alone: exact identity, evidence, discovered
differences, probes/gates, commit/push/install and observed recovery. If a
release requires a new security/UX trade-off, file the normal human decision
and continue independent verification; an automatic session grants no extra
permission and cannot answer native approvals.
