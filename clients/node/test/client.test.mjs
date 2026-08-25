import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import {
  access,
  ConvenientSecurityError,
  DEFAULT_BRIDGE_PATH,
  DeniedError,
} from '../dist/esm/index.js';

async function withFakeBridge(
  response,
  callback,
  { status = 0, declaredLength, extra = Buffer.alloc(0) } = {},
) {
  const directory = await mkdtemp(join(tmpdir(), 'cs-node-bridge-test-'));
  const bridgePath = join(directory, 'fake-bridge');
  const capturePath = join(directory, 'capture.json');
  const payload = Buffer.isBuffer(response)
    ? response
    : Buffer.from(JSON.stringify({ version: 1, ...response }), 'utf8');
  const script = `#!${process.execPath}
const { writeFileSync } = require('node:fs');
const chunks = [];
process.stdin.on('data', (chunk) => chunks.push(chunk));
process.stdin.on('end', () => {
  const input = Buffer.concat(chunks);
  const requestLength = input.readUInt32BE(0);
  const request = JSON.parse(input.subarray(4, 4 + requestLength).toString('utf8'));
  writeFileSync(
    ${JSON.stringify(capturePath)},
    JSON.stringify({
      request,
      ambientPresent: Object.hasOwn(process.env, 'CSEC_TEST_AMBIENT_SECRET'),
      path: process.env.PATH,
      testSocketPath: process.env.CSEC_SOCKET ?? null,
    }),
  );
  const payload = Buffer.from(${JSON.stringify(payload.toString('base64'))}, 'base64');
  const header = Buffer.alloc(4);
  header.writeUInt32BE(${declaredLength ?? payload.length});
  process.stdout.write(header);
  process.stdout.write(payload);
  process.stdout.write(Buffer.from(${JSON.stringify(extra.toString('base64'))}, 'base64'));
  process.exitCode = ${status};
});
`;

  await writeFile(bridgePath, script, { mode: 0o700 });
  await chmod(bridgePath, 0o700);

  try {
    return await callback(bridgePath, capturePath);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('access returns exact values and sends a well-formed bridge request', async () => {
  await withFakeBridge(
    { values: { 'op://demo/db/url': 'postgres://synthetic' } },
    async (bridgePath, capturePath) => {
      const values = await access(['op://demo/db/url'], {
        reason: 'boot node',
        ttl: 3_600,
        bridgePath,
      });
      const captured = JSON.parse(await readFile(capturePath, 'utf8'));

      assert.deepEqual(values, { 'op://demo/db/url': 'postgres://synthetic' });
      assert.deepEqual(captured.request, {
        version: 1,
        references: ['op://demo/db/url'],
        reason: 'boot node',
        ttlSeconds: 3_600,
      });
    },
  );
});

test('the bridge receives a scrubbed environment and the explicit debug socket only', async () => {
  const previous = process.env.CSEC_TEST_AMBIENT_SECRET;
  process.env.CSEC_TEST_AMBIENT_SECRET = 'synthetic-marker-not-a-real-secret';

  try {
    await withFakeBridge(
      { values: { 'op://demo/key': 'synthetic' } },
      async (bridgePath, capturePath) => {
        await access(['op://demo/key'], {
          reason: 'environment scrub test',
          ttl: 60,
          bridgePath,
          testSocketPath: '/tmp/csec-synthetic-test.sock',
        });
        const captured = JSON.parse(await readFile(capturePath, 'utf8'));

        assert.equal(captured.ambientPresent, false);
        assert.equal(captured.path, '/usr/bin:/bin:/usr/sbin:/sbin');
        assert.equal(captured.testSocketPath, '/tmp/csec-synthetic-test.sock');
      },
    );
  } finally {
    if (previous === undefined) {
      delete process.env.CSEC_TEST_AMBIENT_SECRET;
    } else {
      process.env.CSEC_TEST_AMBIENT_SECRET = previous;
    }
  }
});

test('consent denial has a dedicated error type and code', async () => {
  await withFakeBridge(
    { failure: { code: 'consent_denied', message: 'consent denied' } },
    async (bridgePath) => {
      await assert.rejects(
        access(['op://demo/key'], { reason: 'x', ttl: 60, bridgePath }),
        (error) => {
          assert.ok(error instanceof DeniedError);
          assert.ok(error instanceof ConvenientSecurityError);
          assert.equal(error.code, 'consent_denied');
          return true;
        },
      );
    },
    { status: 1 },
  );
});

test('other typed failures retain their value-free bridge code', async () => {
  await withFakeBridge(
    { failure: { code: 'policy_denied', message: 'delivery is not allowed' } },
    async (bridgePath) => {
      await assert.rejects(
        access(['op://demo/key'], { reason: 'x', ttl: 60, bridgePath }),
        (error) => {
          assert.ok(error instanceof ConvenientSecurityError);
          assert.ok(!(error instanceof DeniedError));
          assert.equal(error.code, 'policy_denied');
          assert.match(error.message, /^policy_denied:/);
          return true;
        },
      );
    },
    { status: 1 },
  );
});

test('a successful payload cannot hide a non-zero bridge exit', async () => {
  await withFakeBridge(
    { values: { 'op://demo/key': 'synthetic' } },
    async (bridgePath) => {
      await assert.rejects(
        access(['op://demo/key'], { reason: 'x', ttl: 60, bridgePath }),
        /exited without a typed failure/,
      );
    },
    { status: 1 },
  );
});

test('missing and relative bridge paths are rejected before launch', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'cs-node-missing-'));
  try {
    await assert.rejects(
      access(['op://demo/key'], {
        reason: 'x',
        ttl: 60,
        bridgePath: join(directory, 'missing'),
      }),
      /not executable/,
    );
    await assert.rejects(
      access(['op://demo/key'], {
        reason: 'x',
        ttl: 60,
        bridgePath: 'relative/csec',
      }),
      /must be absolute/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('request bounds are checked before the bridge path', async () => {
  const invalidRequests = [
    access([], { reason: 'x', ttl: 60, bridgePath: '/missing' }),
    access(['not-a-uri'], { reason: 'x', ttl: 60, bridgePath: '/missing' }),
    access(['op://demo/key'], { reason: '', ttl: 60, bridgePath: '/missing' }),
    access(['op://demo/key'], { reason: 'x', ttl: 0, bridgePath: '/missing' }),
    access(['op://demo/key'], { reason: 'x', ttl: 1.5, bridgePath: '/missing' }),
    access(new Array(65).fill('op://demo/key'), {
      reason: 'x',
      ttl: 60,
      bridgePath: '/missing',
    }),
  ];

  for (const request of invalidRequests) {
    await assert.rejects(request, /invalid request/);
  }
});

test('reason limits count UTF-8 bytes rather than JavaScript characters', async () => {
  await assert.rejects(
    access(['op://demo/key'], {
      reason: 'é'.repeat(257),
      ttl: 60,
      bridgePath: '/missing',
    }),
    /reason must be between 1 and 512 bytes/,
  );
});

test('responses must have the expected version, keys, and string values', async () => {
  const cases = [
    { response: { version: 2, values: { 'op://demo/key': 'synthetic' } }, error: /version/ },
    { response: { values: {} }, error: /do not match/ },
    { response: { values: { 'op://demo/key': 123 } }, error: /do not match/ },
    {
      response: { values: { 'op://demo/key': 'synthetic', 'op://demo/extra': 'extra' } },
      error: /do not match/,
    },
  ];

  for (const { response, error } of cases) {
    await withFakeBridge(response, async (bridgePath) => {
      await assert.rejects(
        access(['op://demo/key'], { reason: 'x', ttl: 60, bridgePath }),
        error,
      );
    });
  }
});

test('malformed, truncated, oversized, and multi-frame output fails closed', async () => {
  await withFakeBridge(Buffer.from('{', 'utf8'), async (bridgePath) => {
    await assert.rejects(
      access(['op://demo/key'], { reason: 'x', ttl: 60, bridgePath }),
      /malformed JSON/,
    );
  });

  await withFakeBridge(
    Buffer.from('{}', 'utf8'),
    async (bridgePath) => {
      await assert.rejects(
        access(['op://demo/key'], { reason: 'x', ttl: 60, bridgePath }),
        /mid-response/,
      );
    },
    { declaredLength: 10 },
  );

  await withFakeBridge(
    Buffer.from('{}', 'utf8'),
    async (bridgePath) => {
      await assert.rejects(
        access(['op://demo/key'], { reason: 'x', ttl: 60, bridgePath }),
        /out-of-range frame length/,
      );
    },
    { declaredLength: 8 * 1024 * 1024 + 1 },
  );

  await withFakeBridge(
    { values: { 'op://demo/key': 'synthetic' } },
    async (bridgePath) => {
      await assert.rejects(
        access(['op://demo/key'], { reason: 'x', ttl: 60, bridgePath }),
        /after its response frame/,
      );
    },
    { extra: Buffer.from('x') },
  );
});

test('the installed bridge path is fixed and both package module formats load', async () => {
  const previous = process.env.CSEC_BIN;
  process.env.CSEC_BIN = '/tmp/attacker-csec';
  try {
    assert.equal(
      DEFAULT_BRIDGE_PATH,
      '/Library/Application Support/ConvenientSecurity/bin/csec',
    );

    const esmClient = await import('convenient-security');
    const require = createRequire(import.meta.url);
    const commonJsClient = require('convenient-security');
    assert.equal(typeof esmClient.access, 'function');
    assert.equal(typeof commonJsClient.access, 'function');
  } finally {
    if (previous === undefined) {
      delete process.env.CSEC_BIN;
    } else {
      process.env.CSEC_BIN = previous;
    }
  }
});
