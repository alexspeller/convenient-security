import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { constants as fsConstants } from 'node:fs';
import { access as checkFileAccess, mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import { access, ConvenientSecurityError } from '../dist/esm/index.js';

const testDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = resolve(testDirectory, '../../..');
const agentBinary = join(repositoryRoot, 'agent/.build/debug/cs-fake-agent');
const csecBinary = join(repositoryRoot, 'agent/.build/debug/csec');

async function binariesAreBuilt() {
  try {
    await Promise.all([
      checkFileAccess(agentBinary, fsConstants.X_OK),
      checkFileAccess(csecBinary, fsConstants.X_OK),
    ]);
    return true;
  } catch {
    return false;
  }
}

test(
  'Node client uses the real Swift bridge protocol to reach the fake agent',
  { skip: (await binariesAreBuilt()) ? false : 'build the Swift package first' },
  async () => {
    const directory = await mkdtemp(join(tmpdir(), 'cs-node-xstack-'));
    const socketPath = join(directory, 'agent.sock');
    const agent = spawn(agentBinary, [], {
      env: { ...process.env, CSEC_SOCKET: socketPath },
      stdio: 'ignore',
    });

    try {
      await waitForSocket(socketPath, agent);

      const values = await access(['op://demo/db/url'], {
        reason: 'cross-stack test',
        ttl: 60,
        bridgePath: csecBinary,
        testSocketPath: socketPath,
      });
      assert.equal(values['op://demo/db/url'], 'postgres://s3cr3t');

      const again = await access(['op://demo/db/url'], {
        reason: 'cross-stack test',
        ttl: 60,
        bridgePath: csecBinary,
        testSocketPath: socketPath,
      });
      assert.equal(again['op://demo/db/url'], 'postgres://s3cr3t');

      await assert.rejects(
        access(['op://demo/missing'], {
          reason: 'cross-stack test',
          ttl: 60,
          bridgePath: csecBinary,
          testSocketPath: socketPath,
        }),
        ConvenientSecurityError,
      );
    } finally {
      if (agent.exitCode === null && agent.signalCode === null) {
        const exitPromise = once(agent, 'exit');
        agent.kill('SIGTERM');
        await exitPromise.catch(() => undefined);
      }
      await rm(directory, { recursive: true, force: true });
    }
  },
);

async function waitForSocket(path, agent, timeoutMilliseconds = 5_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (Date.now() <= deadline) {
    if (agent.exitCode !== null || agent.signalCode !== null) {
      throw new Error('fake agent exited before creating its socket');
    }
    try {
      if ((await stat(path)).isSocket()) {
        return;
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        throw error;
      }
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 20));
  }
  throw new Error('fake agent never created its socket');
}
