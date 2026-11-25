import assert from 'node:assert/strict';
import { constants as fsConstants } from 'node:fs';
import test from 'node:test';

test('a read-only root filesystem is accepted during default bridge validation', async (t) => {
  const writeChecks = [];
  const spawnFailure = new Error('validation reached bridge launch');

  t.mock.module('node:fs/promises', {
    namedExports: {
      async access(path, mode) {
        if (mode === fsConstants.X_OK) {
          return;
        }

        assert.equal(mode, fsConstants.W_OK);
        writeChecks.push(path);
        const error = new Error(path === '/' ? 'read-only filesystem' : 'permission denied');
        error.code = path === '/' ? 'EROFS' : 'EACCES';
        throw error;
      },
      async realpath(path) {
        return path;
      },
      async stat() {
        return {
          isFile: () => true,
          mode: 0o755,
          uid: 0,
        };
      },
    },
  });
  t.mock.module('node:child_process', {
    namedExports: {
      spawn() {
        throw spawnFailure;
      },
    },
  });

  const { access, DEFAULT_BRIDGE_PATH } = await import(
    '../dist/esm/index.js?erofs-regression'
  );

  await assert.rejects(
    access(['op://demo/key'], { reason: 'EROFS regression test', ttl: 60 }),
    (error) => error === spawnFailure,
  );
  assert.equal(writeChecks.at(-1), '/');
  assert.ok(writeChecks.includes(DEFAULT_BRIDGE_PATH));
});
