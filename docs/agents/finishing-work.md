<!-- Full text of an AGENTS.md topic; paths and links in it are relative to the repository root. AGENTS.md keeps a summary and says when to read this file; where they differ, this file wins. -->

## Finishing work: gates, commit, install

csec is finished when it is running on the Mac it is for. After every piece
of work, once its quality gates pass, commit it and install it straight away.
Do not wait to be asked, and do not leave the install as an attended step for
later. Local guidance may add where to push and a route that runs the install
for you; it adds to these steps and never skips one.

1. **Gates.** Run what the change needs: `bin/ci`, or, when `bin/ci` cannot
   finish here (a locked Mac, a foreground-only check), the suites the change
   touches plus `swift build --package-path agent -Xswiftc
   -warnings-as-errors`, and say which.
2. **Commit.** Stage only the files the change touched (never `git add -A`),
   then commit. When the work is pushed, `git pull --rebase=merges` and push
   before installing, preserving merge history, so the installed commit
   stamp names the final history.
3. **Install.** `packaging/bin/build-and-install.sh` builds, signs,
   notarizes and installs every component, including the sudo helper and the
   iPhone app, and gates on `csec doctor`. Its privileged stages go through
   `sudo`, so the csec sudo review asks for a touch, and notarizing and
   installing on the phone take minutes: say before starting it that panels
   are about to appear. Run by an unattended worker, it waits at presence
   checkpoints for someone at the Mac (`packaging/README.md`, "Unattended
   runs"). Its options
   (`--refresh-profile`, `--allow-downgrade`, `--skip-sudo`, `--skip-iphone`,
   `--only-iphone`) are for the cases its usage text names. A Mac without a
   signing identity or a paired phone cannot install; say so, and leave the
   install to a Mac that can.
4. **Report.** The handoff names the commit, any push, how it was installed
   and the install's `csec doctor` result: run `csec doctor` yourself after
   the script exits 0, and check that the installed `CSECSourceCommit`
   covers the commit. If a step could not run (a failed notarization, an
   unreachable phone, a declined touch), say which and why, and do not report
   the work as done.
