# convenient_security (Ruby client)

Heap-delivery client for the [convenient-security](../../README.md) agent. It
spawns the root-owned signed `csec bridge` installed at
`/Library/Application Support/ConvenientSecurity/bin/csec`, then receives
secrets over a private pipe into this process's heap — never into `ENV` or
`argv`, which are readable by same-uid processes. Ruby does not connect to the
agent socket directly because it cannot authenticate a replacement server with
Security.framework.

Use this for consumers we control (Rails at boot). For unmodified tools, use
`csec exec` (environment injection) instead.

## Usage

```ruby
require 'convenient_security'

secrets = ConvenientSecurity.access(
  ['op://Vault/DB/url', 'csec://development/LOCAL_API_TOKEN'],
  reason: 'boot rails',
  ttl: 8 * 3600
)
db_url = secrets.fetch('op://Vault/DB/url') # a plain String, only in the heap
token = secrets.fetch('csec://development/LOCAL_API_TOKEN')
```

References from 1Password and native encrypted files can be requested together;
the agent dispatches each URI by scheme. Native stores must first be created
with the signed installed `csec edit <store>` command.

The first call for a new reference triggers the agent's Touch ID consent. The
signed bridge asks for a grant rooted at its Ruby parent; the agent verifies that
actual kernel ancestry and process start time, so later bridge calls from the
same Ruby subtree can reuse the bounded grant. The bridge child receives a
scrubbed environment, so unrelated ambient variables are not copied into it.
The parent pipe ends are close-on-exec, and the bridge rechecks the parent's
PID, start time, and executable path before writing, so a parent image
replacement cannot inherit the response channel.

Raises:

- `ConvenientSecurity::Denied` — consent was refused.
- `ConvenientSecurity::Error` — anything else (bridge/agent unavailable,
  policy failure, unknown reference, malformed response).

## Tests

```sh
cd agent && swift build           # builds cs-fake-agent for the cross-stack test
cd ../clients/ruby && rake test   # hermetic Ruby-fake suite + Ruby↔Swift interop
```

The cross-stack test runs both the real Swift bridge and `cs-fake-agent`
(in-memory demo values), so a Ruby/bridge or bridge/agent protocol divergence
fails the build. It skips if the Swift binaries aren't built.
