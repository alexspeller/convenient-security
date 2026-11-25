<!-- Full text of an AGENTS.md topic, moved unchanged; paths and links in it are relative to the repository root. AGENTS.md keeps a summary and says when to read this file; where they differ, this file wins. -->

## Building and installing: one script

On a Mac Alex may be using, check free memory before a heavy build. Use at
most two build workers and keep their total RSS below about 25% of physical
RAM. Monitor memory pressure and swap; stop the owned build if pressure turns
yellow/red or swap grows. Keep the normal build and simulator admission gates.

`packaging/bin/build-and-install.sh` is the only entry point that installs
anything. It builds, signs, notarizes, packages, and installs the app bundle,
the root-owned bridge, the package's uninstaller beside it, the root helper, the managed Codex hook, the sudo PAM
module, the sudo review helper, and the iPhone approval app with its
notification service extension (onto the paired phone, dev-signed by Xcode,
both re-signed without `get-task-allow`), verifies every installed payload
against the build (the phone app by reading its stamped build number back with
`devicectl`), and gates on `csec doctor`. The Codex-hook and sudo stages run the copies of
`install-codex-hook.sh` and `install-sudo-review.sh` the package installs
under `/Library/Application Support/ConvenientSecurity/libexec/`, the ones
`csec setup` runs on a buyer's Mac with no checkout, so a privileged stage a
buyer needs ships in the package's payload, not only in the checkout. The other scripts in `packaging/bin` are stages it runs
(`build-agent.sh`, `build-sudo-pam.sh`, `build-sudo-review.sh`, `build-pkg.sh`,
`notarize.sh`, `provision.sh`, `install-codex-hook.sh`, `install-sudo-review.sh`); they are not
alternative install paths.

Do not add a new build or install script. A new shipping component — a helper,
a module, a daemon, a configuration file — is wired into
`build-and-install.sh`: a build stage, an install stage (guarded and
reversible if it is privileged), an entry in the `--dry-run` plan, a
`verify_same_file` line against the installed path, a row in `csec doctor` /
`csec status` (which must fail on a missing or stale install of it), and the
matching assertion in `bin/ci`'s dry-run check. A stage may be a separate
script under `packaging/bin` only if `build-and-install.sh` calls it and
`packaging/README.md` documents it as a stage. A component that a human has to
remember to install with a second command will be left stale; that is how this
Mac ran an August spike of the sudo review helper for two weeks.
