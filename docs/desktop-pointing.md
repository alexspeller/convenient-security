# Desktop pointers from coding-agent commands

Run big-arrow through the coding agent's normal command tool, keeping csec's
hook and output scanning in place. A Codex command sandbox can hide displays
and running apps even though csec is reachable and the process belongs to the
login user's Aqua bootstrap session. This is separate from macOS privacy
permissions.

## Diagnose the command context

Start with `bigarrow doctor`. If its display list is empty, compare the same
diagnostic through Codex's normal per-command escalation flow:

```json
{
  "cmd": "bigarrow doctor",
  "sandbox_permissions": "require_escalated",
  "justification": "Check desktop visibility for the requested pointer."
}
```

Then test the intended target with `--dry-run --json` in that context. For
example, with an iTerm window visible:

```sh
bigarrow start --window iTerm2 --text "Desktop pointer diagnostic" --dry-run --json
```

Use that same per-command escalation setting for the real pointer and its
cleanup. It does not grant Accessibility or Screen Recording, change the
session's default sandbox, or remove csec wrapping. Native approval and
automatic command review still apply; a refused retry is a blocker, not
permission to launch through another process. Follow the active approval
workflow if it refuses.

Check the Mac's lock state before raising apps or pointing at a real request;
`/usr/local/libexec/csec-sudo-review --screen-lock-probe` reports it without
opening a panel. A display list can remain available while the Mac is locked.
Use the existing phone approval or wait for unlock when it is locked.

If the escalated diagnostic also sees no displays or target windows, check
whether the target has closed. Do not change bootstrap domains, grant privacy
access, or remove security controls to make it work.
Keep the existing human-action/native/phone approval route while investigating.

## Point without a new privacy grant

In big-arrow 0.4.3, these routes need no Accessibility or Screen Recording:

- `--window App` resolves an ordinary app window's visible bounds. Use the
  application name or bundle identifier, not an assumed executable name.
- `--at X,Y --app App` or `--rect X,Y,W,H --app App` uses coordinates already
  established by an authorized desktop tool. Coordinates are global top-left
  logical points; recheck the target if its window moves. Do not guess a
  button's coordinates from a window's center.

An app-only window target points at the window, not a particular button. Name
the actual action and its consequences in the sign. Pointing never answers an
approval; the decision remains with the user. Do not click an approval control or
touch the sensor on his behalf.

Record the returned arrow `pid` and, as soon as the step ends, run
`bigarrow stop --pid <pid>` through the same command context. Scope cleanup to
that arrow so another session's pointer stays intact. A detached `start`
return proves startup only; verify the underlying human step separately.

## Point at csec's modal panels

Csec's secret-access, SSH and sudo windows use `NSWindow.Level.modalPanel`.
Big-arrow 0.4.3's window matcher accepts only layer 0, so `--window` can report
no visible window for a real approval panel at layer 8. Its app-binding cover
check uses that same filter, so adding `--app` to a coordinate pointer can
also hide the arrow behind an ordinary window it sees underneath the panel.

For this version, raise the app separately, then use a **brief, unbound**
coordinate pointer. This is an exception to the big-arrow skill's usual
`--app` rule for this verified modal-window limitation. The daemon's app name
is `ConvenientSecurity`; the sudo helper is `csec-sudo-review`:

```sh
bigarrow front --app csec-sudo-review --json
```

Obtain the current panel rectangle from an already authorized desktop tool or
from CoreGraphics metadata for its verified live process. This reads only
PID, visibility and geometry; it does not capture the screen, read window
titles or inspect UI elements. In the following command, replace `12345` with
the verified review PID (`csecd` for secret-access/SSH, `csec-sudo-review` for
sudo). Run it in the same escalated command context, after raising the app:

```sh
mise exec -- swift - 12345 <<'SWIFT'
import CoreGraphics
import Darwin
import Foundation

guard CommandLine.arguments.count == 2,
      let pid = Int32(CommandLine.arguments[1]), pid > 1 else { exit(2) }
let windows = CGWindowListCopyWindowInfo(
    [.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID
) as? [[String: Any]] ?? []
let rects = windows.compactMap { entry -> CGRect? in
    guard (entry[kCGWindowOwnerPID as String] as? Int32) == pid,
          (entry[kCGWindowAlpha as String] as? Double ?? 0) > 0,
          let bounds = entry[kCGWindowBounds as String] as? NSDictionary,
          let rect = CGRect(dictionaryRepresentation: bounds),
          rect.width >= 40, rect.height >= 40 else { return nil }
    return rect
}
guard rects.count == 1 else {
    fputs("Expected one visible review window; recheck the target.\n", stderr)
    exit(3)
}
let rect = rects[0]
print("\(rect.minX),\(rect.minY),\(rect.width),\(rect.height)")
SWIFT
```

Use the fresh rectangle with `--rect`, omitting `--app`. For example, **only
when the visible sudo request is for `/usr/bin/true`**, substituting the
rectangle just returned:

```sh
bigarrow start --rect X,Y,W,H --text "Use Touch ID to allow sudo /usr/bin/true" --duration 5 --json
```

For secret-access or SSH, raise `ConvenientSecurity` and describe the actual
release or signing request. This points at the whole panel; an exact control
needs coordinates independently established by the authorized desktop tool.
The unbound pointer cannot follow the window or hide on app changes. Keep it
brief, watch the target, and stop its exact PID immediately if the panel
closes, moves or is covered. Do not leave a detached unbound arrow waiting
indefinitely. A missing or ambiguous rectangle is a reason to recheck the UI,
not to substitute old coordinates.

## Distinguish TCC from the display failure

`--element` and `--until-click` require Accessibility. Matching a window by
title (`--window App:title`) requires Screen Recording; raising a particular
window or tab by title uses Accessibility too. Prefer the permission-free
route when it identifies the target adequately. A genuinely needed new grant
requires its own exact security authorization.

Big-arrow 0.4.3's `permissions belong to` line walks parent processes to an
app bundle. It does not query TCC's responsible identity. Treat it as a clue,
especially under csec: do not ask for a broad grant to ConvenientSecurity or
the shell based on that line alone. Correlate the diagnostic's PID and time
with fresh TCC logs, starting with this metadata-only query outside the
command sandbox:

```sh
/usr/bin/log show --last 3m --info --style compact --predicate 'process == "tccd" AND eventMessage CONTAINS "bigarrow"'
```

Read the matching `AttributionChain` and service result. A parent-chain label,
an empty log or an old event does not establish the current responsible app.
Do not read protected app containers or reset TCC to diagnose this.

## Verified comparison

On 20 October 2026, big-arrow 0.4.3 on macOS 26.2, through the same csec-wrapped
Codex command path, produced:

| Observation | Default command sandbox | Per-command escalation |
| --- | --- | --- |
| `launchctl managername` / `manageruid` | Aqua / 501 | Aqua / 501 |
| `bigarrow doctor` displays | Empty | One 2056 × 1329 display at 2× |
| App-only iTerm window dry run | Exit 3, empty app list | Exit 0, `ok=true` |
| Accessibility / Screen Recording preflights | Both missing | Both missing |

A real two-second iTerm overlay in the escalated context returned exit 0,
`dryRun=false`, and `dismissedReason=timeout`; detached startup and PID-scoped
cleanup also passed. The installed sudo helper's synthetic no-Touch-ID probe
reported one visible panel at layer 8, while `--window csec-sudo-review`
reported none. Its exact-PID rectangle was targetable without a new grant.
An unbound rectangle arrow remained in the on-screen CoreGraphics list with
alpha 1 after 600 ms and its exact-PID stop succeeded. These are renderer and
window-metadata checks; the Mac was locked at the later checks, so app raising
failed and no human visual confirmation was obtained.

TCC events for the escalated doctor identified fish as responsible and
big-arrow as accessing, although big-arrow printed ConvenientSecurity.
No privacy grant or bootstrap change
was made. These observations establish the working route for this command
context; recheck it after runtime or tool upgrades.

The matching release source explains these diagnostics:
[window targeting](https://github.com/franzenzenhofer/big-arrow-on-the-screen/blob/v0.4.3/Sources/BigArrowTargeting/WindowTarget.swift),
[display enumeration](https://github.com/franzenzenhofer/big-arrow-on-the-screen/blob/v0.4.3/Sources/BigArrowOverlay/ScreenReader.swift),
[modal-window filtering](https://github.com/franzenzenhofer/big-arrow-on-the-screen/blob/v0.4.3/Sources/BigArrowCore/WindowMatcher.swift),
[app binding](https://github.com/franzenzenhofer/big-arrow-on-the-screen/blob/v0.4.3/Sources/bigarrow/HomeBinder.swift),
and [responsible-app inference](https://github.com/franzenzenhofer/big-arrow-on-the-screen/blob/v0.4.3/Sources/BigArrowTargeting/ResponsibleProcess.swift).
