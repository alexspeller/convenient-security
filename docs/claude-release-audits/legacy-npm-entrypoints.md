# Legacy npm Claude entrypoints: inventory disposition

These are unsupported JavaScript installations, not native images eligible
for the checked-build catalog. The investigation recommends retiring the two
inactive installations through mise, subject to the exact host-change
decision `csec-cc-path-f9cb36f78344.1`. No code identity is added or inferred.
The related `csec-cc-path-c233eaa46a9e` investigation is folded into that work.

## Observed installations

Read-only observations on the author's Mac, 20 October 2026:

| Inventory path below `~/.local/share/mise/installs/npm-anthropic-ai-claude-code/` | Actual package | Entrypoint |
| --- | --- | --- |
| `0/bin/claude` | `0.2.126` (`0 -> ./0.2.126`) | `lib/node_modules/@anthropic-ai/claude-code/cli.js` |
| `1.0.41/bin/claude` | `1.0.41` | `lib/node_modules/@anthropic-ai/claude-code/cli.js` |

Both `bin/claude` links are relative links to `../lib/node_modules/@anthropic-ai/claude-code/cli.js`.
Both scripts start with `#!/usr/bin/env -S node --no-warnings --enable-source-maps`.
`codesign -d --verbose=4` reports **code object is not signed at all** for each.
The absent cdHash is therefore expected, not an unrecognized native signature.

Each installed `cli.js` equals the one in its official public npm archive.
The complete compressed archives also match the registry's `dist.shasum`:

| Package metadata | Archive bytes | CLI bytes |
| --- | ---: | ---: |
| [0.2.126](https://registry.npmjs.org/@anthropic-ai/claude-code/0.2.126) | 55,873,913 | 7,239,275 |
| [1.0.41](https://registry.npmjs.org/@anthropic-ai/claude-code/1.0.41) | 56,053,871 | 7,661,788 |

The comparison downloaded bounded archives and read only `package/cli.js`
in memory; it executed no upstream code and read no login data. It establishes
origin and byte equality, not loader compatibility or permission to delegate.
Neither script contains `autoMode` or `classifyAllShell`; these observations
are not a substitute for a complete loader audit.

## Launch selection and its limits

`MISE_OFFLINE=1 mise ls --json npm:@anthropic-ai/claude-code` marks both
versions inactive. The active global mise selection is `latest`, resolving to
2.1.295. `command -v claude` selects `~/.local/bin/claude`, whose target is
the native `~/.local/share/claude/versions/2.1.280` executable.

At the process observation, all 34 live Claude executable paths were native
2.1.280. Inspecting the arguments of 28 Node/Bun processes without printing
their arguments found no reference to either legacy installation path.
Scoped searches of `~/.config/mise`, `~/.config/fish` and the session
launcher's sources found no explicit selection of either legacy version.
These checks establish current inactivity within those sources; they do not
prove that a script was never used or cannot be selected explicitly later.
The daemon's `running=false` alone cannot establish this: a script runs under
its interpreter, whose live executable identity differs from the script path.

## Disposition and authorization boundary

Retiring these inactive tools avoids keeping obsolete entrypoints and clears
their actual inventory condition. The concrete read-only plan exits 0:

```sh
MISE_OFFLINE=1 mise uninstall --dry-run \
  npm:@anthropic-ai/claude-code@0.2.126 \
  npm:@anthropic-ai/claude-code@1.0.41
```

It names exactly the `0.2.126` and `1.0.41` installation directories. Mise's
uninstall command does not edit `mise.toml`; the selected native launcher and
active 2.1.295 installation are separate. The actual uninstall requires the
host-change decision; this report does not claim it has run. Check mise's
aliases afterwards and re-read the installed daemon's
`csec status --claude-builds-json`, requiring the two original paths to be
absent while retaining every other unresolved image and unreadable-path
diagnostic. Record the observed output on the owning bead.

Keeping the scripts is also possible, but they remain unsupported and
unchecked. No path exception, invented cdHash, interpreter whitelist or
watchdog suppression is justified. Full settings/hook/plugin/frontmatter,
registry, launch-selector and approval-order auditing was not performed:
neither script is being admitted for delegation. Supporting script delivery
would require a separately designed identity binding that covers the loaded
code, not merely its Node executable or a mutable package label.

## Regression coverage

`--delegation-setup-only` reproduces the alias, relative `bin/claude` links
and executable Node scripts with synthetic data. It checks inode
deduplication, missing signature/hash, continued refusal despite native trust
records, removal from a warm inventory (including a dangling alias), refusal
after renaming to an audited release label, and absence of candidate execution.

`bin/test-check-claude-release.py` keeps two null-hash paths as two unresolved
items. Removing one must retain the other's trip, and only removal of both
clears this synthetic condition. A forged checked version without a code
identity is rejected. No production admission behavior changes.
