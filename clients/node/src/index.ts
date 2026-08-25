import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { constants as fsConstants } from 'node:fs';
import { access as checkFileAccess, realpath, stat } from 'node:fs/promises';
import { dirname, isAbsolute } from 'node:path';
import type { Readable } from 'node:stream';

export const DEFAULT_BRIDGE_PATH =
  '/Library/Application Support/ConvenientSecurity/bin/csec';

const MAX_FRAME_BYTES = 8 * 1024 * 1024;
const MINIMAL_PATH = '/usr/bin:/bin:/usr/sbin:/sbin';

interface BridgeRequest {
  version: 1;
  references: string[];
  reason: string;
  ttlSeconds: number;
}

interface ErrorDetails {
  code?: string;
  cause?: unknown;
}

export interface AccessOptions {
  /** Human-readable, value-free reason shown during consent. */
  reason: string;
  /** Requested grant lifetime in seconds, between 1 and 86,400. */
  ttl: number;
  /** Test seam. Production callers should use the fixed installed bridge. */
  bridgePath?: string;
  /** Debug-only cross-stack test seam. Production callers should omit this. */
  testSocketPath?: string;
}

export class ConvenientSecurityError extends Error {
  readonly code: string | undefined;

  constructor(message: string, details: ErrorDetails = {}) {
    if (details.cause === undefined) {
      super(message);
    } else {
      super(message, { cause: details.cause });
    }
    this.name = 'ConvenientSecurityError';
    this.code = details.code;
  }
}

export class DeniedError extends ConvenientSecurityError {
  constructor() {
    super('consent denied', { code: 'consent_denied' });
    this.name = 'DeniedError';
  }
}

/**
 * Request one or more references from the installed Convenient Security agent.
 * Values arrive through a private pipe and are returned only to this process.
 */
export async function access(
  references: readonly string[],
  options: AccessOptions,
): Promise<Record<string, string>> {
  const request = validateRequest(references, options);
  const bridgePath = options.bridgePath ?? DEFAULT_BRIDGE_PATH;
  await validateBridgePath(bridgePath, options.bridgePath !== undefined);

  const { payload, status, signal } = await runBridge(
    request,
    bridgePath,
    options.testSocketPath,
  );
  const response = parseResponse(payload);

  if (response.version !== 1) {
    throw new ConvenientSecurityError('unsupported bridge response version');
  }

  if (response.failure !== undefined && response.failure !== null) {
    if (!isRecord(response.failure)) {
      throw new ConvenientSecurityError('malformed bridge response: invalid failure');
    }
    const code = typeof response.failure.code === 'string' ? response.failure.code : undefined;
    if (code === 'consent_denied') {
      throw new DeniedError();
    }
    const message =
      typeof response.failure.message === 'string'
        ? response.failure.message
        : 'bridge request failed';
    throw new ConvenientSecurityError(
      `${code ?? 'bridge_error'}: ${message}`,
      code === undefined ? {} : { code },
    );
  }

  if (status !== 0 || signal !== null) {
    throw new ConvenientSecurityError('signed csec bridge exited without a typed failure');
  }

  if (!isRecord(response.values)) {
    throw new ConvenientSecurityError('malformed bridge response: missing values');
  }

  const values = response.values;
  const expectedKeys = [...new Set(request.references)].sort();
  const actualKeys = Object.keys(values).sort();
  if (
    expectedKeys.length !== actualKeys.length ||
    expectedKeys.some((key, index) => key !== actualKeys[index]) ||
    actualKeys.some((key) => typeof values[key] !== 'string')
  ) {
    throw new ConvenientSecurityError(
      'malformed bridge response: values do not match requested references',
    );
  }

  return values as Record<string, string>;
}

function validateRequest(
  references: readonly string[],
  options: AccessOptions,
): BridgeRequest {
  if (!Array.isArray(references)) {
    throw new ConvenientSecurityError('invalid request: references must be an array');
  }
  if (references.length === 0) {
    throw new ConvenientSecurityError('invalid request: at least one reference is required');
  }
  if (references.length > 64) {
    throw new ConvenientSecurityError('invalid request: too many references');
  }
  if (
    references.some(
      (reference) => typeof reference !== 'string' || !reference.includes('://'),
    )
  ) {
    throw new ConvenientSecurityError('invalid request: every reference must be a URI string');
  }
  if (!isRecord(options)) {
    throw new ConvenientSecurityError('invalid request: options must be an object');
  }
  if (!Number.isInteger(options.ttl) || options.ttl < 1 || options.ttl > 86_400) {
    throw new ConvenientSecurityError(
      'invalid request: ttl must be an integer between 1 and 86400 seconds',
    );
  }
  if (
    typeof options.reason !== 'string' ||
    Buffer.byteLength(options.reason, 'utf8') < 1 ||
    Buffer.byteLength(options.reason, 'utf8') > 512
  ) {
    throw new ConvenientSecurityError('invalid request: reason must be between 1 and 512 bytes');
  }
  if (
    options.testSocketPath !== undefined &&
    (typeof options.testSocketPath !== 'string' || options.testSocketPath.length === 0)
  ) {
    throw new ConvenientSecurityError('invalid request: test socket path must be non-empty');
  }

  return {
    version: 1,
    references: [...references],
    reason: options.reason,
    ttlSeconds: options.ttl,
  };
}

async function validateBridgePath(path: string, testingOverride: boolean): Promise<void> {
  if (typeof path !== 'string' || !isAbsolute(path)) {
    throw new ConvenientSecurityError('bridge path must be absolute');
  }

  try {
    await checkFileAccess(path, fsConstants.X_OK);
    const bridgeStat = await stat(path);
    if (!bridgeStat.isFile()) {
      throw new ConvenientSecurityError(`signed csec bridge is not executable at ${path}`);
    }
  } catch (cause) {
    if (cause instanceof ConvenientSecurityError) {
      throw cause;
    }
    throw new ConvenientSecurityError(`signed csec bridge is not executable at ${path}`, {
      cause,
    });
  }

  if (testingOverride) {
    return;
  }

  try {
    let current = await realpath(path);
    while (true) {
      const currentStat = await stat(current);
      if (
        currentStat.uid !== 0 ||
        (currentStat.mode & 0o022) !== 0 ||
        (await isWritable(current))
      ) {
        throw new ConvenientSecurityError(`installed bridge path is user-writable: ${current}`);
      }

      const parent = dirname(current);
      if (parent === current) {
        break;
      }
      current = parent;
    }
  } catch (cause) {
    if (cause instanceof ConvenientSecurityError) {
      throw cause;
    }
    throw new ConvenientSecurityError(`cannot validate signed csec bridge: ${errorMessage(cause)}`, {
      cause,
    });
  }
}

async function isWritable(path: string): Promise<boolean> {
  try {
    await checkFileAccess(path, fsConstants.W_OK);
    return true;
  } catch (cause) {
    if (isNodeError(cause) && (cause.code === 'EACCES' || cause.code === 'EPERM')) {
      return false;
    }
    throw cause;
  }
}

async function runBridge(
  request: BridgeRequest,
  path: string,
  testSocketPath: string | undefined,
): Promise<{ payload: Buffer; status: number | null; signal: NodeJS.Signals | null }> {
  const environment: Record<string, string> = { PATH: MINIMAL_PATH };
  if (testSocketPath !== undefined) {
    environment.CSEC_SOCKET = testSocketPath;
  }

  const requestPayload = Buffer.from(JSON.stringify(request), 'utf8');
  if (requestPayload.length === 0 || requestPayload.length > MAX_FRAME_BYTES) {
    throw new ConvenientSecurityError('invalid request: encoded request exceeds frame limit');
  }
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(requestPayload.length);
  const frame = Buffer.concat([header, requestPayload]);

  const child = spawn(path, ['bridge'], {
    env: environment,
    shell: false,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  child.stderr.resume();
  // A bridge that rejects before consuming its complete request can close stdin.
  // The framed stdout response remains the authoritative, value-free failure.
  child.stdin.on('error', () => undefined);

  const closePromise = once(child, 'close') as Promise<
    [status: number | null, signal: NodeJS.Signals | null]
  >;
  child.stdin.end(frame);

  try {
    const [payload, [status, signal]] = await Promise.all([
      readFrame(child.stdout),
      closePromise,
    ]);
    return { payload, status, signal };
  } catch (cause) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill();
    }
    await closePromise.catch(() => undefined);

    if (cause instanceof ConvenientSecurityError) {
      throw cause;
    }
    if (isNodeError(cause) && (cause.code === 'ENOENT' || cause.code === 'EACCES')) {
      throw new ConvenientSecurityError(`cannot launch signed csec bridge: ${cause.message}`, {
        cause,
      });
    }
    throw new ConvenientSecurityError(`signed csec bridge failed: ${errorMessage(cause)}`, {
      cause,
    });
  }
}

async function readFrame(stream: Readable): Promise<Buffer> {
  const header = Buffer.alloc(4);
  let headerOffset = 0;
  let payload: Buffer | undefined;
  let payloadOffset = 0;

  for await (const chunk of stream) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    let chunkOffset = 0;

    while (chunkOffset < bytes.length) {
      if (headerOffset < header.length) {
        const count = Math.min(header.length - headerOffset, bytes.length - chunkOffset);
        bytes.copy(header, headerOffset, chunkOffset, chunkOffset + count);
        headerOffset += count;
        chunkOffset += count;

        if (headerOffset === header.length) {
          const length = header.readUInt32BE(0);
          if (length === 0 || length > MAX_FRAME_BYTES) {
            throw new ConvenientSecurityError(
              `bridge sent an out-of-range frame length (${length})`,
            );
          }
          payload = Buffer.alloc(length);
        }
        continue;
      }

      if (payload === undefined) {
        throw new ConvenientSecurityError('bridge response framing failed');
      }
      if (payloadOffset === payload.length) {
        throw new ConvenientSecurityError('bridge sent data after its response frame');
      }

      const count = Math.min(payload.length - payloadOffset, bytes.length - chunkOffset);
      bytes.copy(payload, payloadOffset, chunkOffset, chunkOffset + count);
      payloadOffset += count;
      chunkOffset += count;
    }
  }

  if (headerOffset !== header.length || payload === undefined || payloadOffset !== payload.length) {
    payload?.fill(0);
    throw new ConvenientSecurityError('bridge closed its private pipe mid-response');
  }
  return payload;
}

function parseResponse(payload: Buffer): Record<string, unknown> {
  try {
    const response: unknown = JSON.parse(payload.toString('utf8'));
    if (!isRecord(response)) {
      throw new ConvenientSecurityError('signed csec bridge returned malformed JSON');
    }
    return response;
  } catch (cause) {
    if (cause instanceof ConvenientSecurityError) {
      throw cause;
    }
    throw new ConvenientSecurityError('signed csec bridge returned malformed JSON', { cause });
  } finally {
    payload.fill(0);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isNodeError(value: unknown): value is NodeJS.ErrnoException {
  return value instanceof Error && 'code' in value;
}

function errorMessage(value: unknown): string {
  return value instanceof Error ? value.message : 'unknown error';
}
