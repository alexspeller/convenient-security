# convenient-security (Node.js client)

Heap-delivery client for the [Convenient Security](../../README.md) agent. The
package spawns the root-owned signed `csec bridge` installed at
`/Library/Application Support/ConvenientSecurity/bin/csec`, then receives
secrets over a private pipe into the Node.js process — never into `process.env`
or `argv`, which are readable by unrelated same-UID processes.

This package is for server-side Node.js applications you control. It does not
work in browsers, edge runtimes, or browser bundles. For unmodified command-line
tools, use `csec exec` or one of the narrower tool-native delivery mechanisms.

## Installation

```sh
npm install convenient-security
```

The package requires macOS and Node.js 22 or later. It has no runtime npm
dependencies and includes ESM, CommonJS, and TypeScript declarations.

## Usage

Call `access` during startup and let a failure stop startup rather than falling
back to an ambient secret source:

```ts
import { access } from 'convenient-security';

export const secrets = await access(
  ['op://Vault/DB/url', 'csec://development/LOCAL_API_TOKEN'],
  {
    reason: 'boot node service',
    ttl: 8 * 60 * 60,
  },
);

const dbUrl = secrets['op://Vault/DB/url'];
const token = secrets['csec://development/LOCAL_API_TOKEN'];
```

CommonJS callers use the same asynchronous API:

```js
const { access } = require('convenient-security');

async function start() {
  const secrets = await access(['op://Vault/DB/url'], {
    reason: 'boot node service',
    ttl: 3_600,
  });
  // Construct the database client from secrets['op://Vault/DB/url'] here.
}

start().catch((error) => {
  console.error('service startup failed:', error.name);
  process.exitCode = 1;
});
```

References from 1Password and native encrypted stores can be requested
together; the agent dispatches each URI by scheme. Native stores must first be
created with the signed installed `csec edit <store>` command.

The first call for a new reference triggers the agent's Touch ID consent. The
signed bridge asks for a grant rooted at its Node.js parent; the agent verifies
the live kernel ancestry and process start time, so later bridge calls from the
same Node.js subtree can reuse the bounded grant. The bridge child receives a
scrubbed environment, and the bridge rechecks the parent's PID, start time, and
executable path before writing its response.

The returned values are ordinary JavaScript strings in the authorized process.
Do not assign them to `process.env`, pass them in arguments, log them, or write
them to disk unless you deliberately accept that weaker delivery boundary.

## Errors

- `DeniedError` means consent was refused and has code `consent_denied`.
- `ConvenientSecurityError` covers bridge/agent unavailability, policy failure,
  unknown references, invalid requests, and malformed responses. Typed bridge
  failures retain their value-free protocol code in `error.code`.

The `bridgePath` and `testSocketPath` options are explicit integration-test
seams. Production callers should leave both unset so the fixed independently
protected bridge and production agent endpoint are used.

## Development

From the repository root:

```sh
mise exec -- npm ci
mise exec -- npm test
```

The test suite builds both module formats and declarations, runs hermetic fake
bridge tests, and performs a Node.js → real Swift bridge → Swift fake-agent
round trip when the Swift binaries have been built. `npm run pack:check` shows
the exact files that would be published.
