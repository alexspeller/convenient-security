import { mkdir, writeFile } from 'node:fs/promises';

const commonJsDirectory = new URL('../dist/cjs/', import.meta.url);
await mkdir(commonJsDirectory, { recursive: true });
await writeFile(new URL('package.json', commonJsDirectory), '{"type":"commonjs"}\n');
