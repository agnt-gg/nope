import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

const projectRoot = process.env.NOPE_PROJECT_ROOT;
const safeRoot = process.env.NOPE_SAFE_TEST_ROOT;
assert.ok(projectRoot && safeRoot, 'safe harness environment is required');

const { NOPE } = await import(pathToFileURL(join(projectRoot, 'dist', 'index.js')).href);
let passed = 0;
let failed = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (error) {
    console.error(`  ❌ ${name}`);
    console.error(`     ${error.message}`);
    failed++;
  }
}

console.log('\n── Sandbox security (safe harness; no destructive commands) ──');

await test('sandbox() fails closed instead of defaulting to host execution', () => {
  const nope = new NOPE({ mode: 'strict' });
  assert.throws(() => nope.sandbox(), /backend.*required|host-process/i);
});

await test('legacy process backend is rejected', () => {
  const nope = new NOPE({ mode: 'strict' });
  assert.throws(() => nope.sandbox({ backend: 'process' }), /host-process|no longer/i);
});

await test('host-process requires explicit acknowledgement', () => {
  const nope = new NOPE({ mode: 'strict' });
  assert.throws(() => nope.sandbox({ backend: 'host-process' }), /acknowledgeHostAccess/i);
});

await test('explicit host-process executes only an inert Node command inside disposable temp root', async () => {
  const marker = join(safeRoot, 'host-process-marker.txt');
  const script = join(safeRoot, 'write-marker.mjs');
  await writeFile(script, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'safe');`);
  const nope = new NOPE({ mode: 'strict' });
  const sandbox = nope.sandbox({
    backend: 'host-process',
    acknowledgeHostAccess: true,
    executable: process.execPath,
    args: [script],
    cwd: safeRoot,
    timeout: 5000,
  });
  const result = await sandbox.exec();
  assert.equal(result.exitCode, 0, result.stderr);
  assert.equal(await readFile(marker, 'utf8'), 'safe');
});

await test('WASM backend fails closed and never executes an inert host marker command', async () => {
  const marker = join(safeRoot, 'wasm-must-not-exist.txt');
  const script = join(safeRoot, 'forbidden-wasm-fallback.mjs');
  await writeFile(script, `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(marker)}, 'unsafe fallback');`);
  const nope = new NOPE({ mode: 'strict' });
  const sandbox = nope.sandbox({ backend: 'wasm' });
  const result = await sandbox.exec(`${JSON.stringify(process.execPath)} ${JSON.stringify(script)}`);
  assert.notEqual(result.exitCode, 0);
  assert.match(result.stderr, /unavailable|does not execute|WASI/i);
  await assert.rejects(readFile(marker, 'utf8'), /ENOENT/);
});

await test('source uses argument-array process creation for Docker and SSH', async () => {
  const source = await readFile(join(projectRoot, 'src', 'NOPE.ts'), 'utf8');
  assert.doesNotMatch(source, /execSync\(`docker/);
  assert.doesNotMatch(source, /execSync\(dockerCmd/);
  assert.doesNotMatch(source, /execSync\(sshCmd/);
  assert.doesNotMatch(source, /execSync\(command/);
  assert.match(source, /runExecutable\(['"]docker['"],\s*args/);
  assert.match(source, /runExecutable\(['"]ssh['"],\s*args/);
  assert.match(source, /spawn\(executable,\s*args/);
  assert.match(source, /shell:\s*false/);
});

await test('default Docker image is pinned and not latest', async () => {
  const source = await readFile(join(projectRoot, 'src', 'NOPE.ts'), 'utf8');
  assert.doesNotMatch(source, /alpine:latest/);
  assert.match(source, /alpine:\d+\.\d+/);
});

console.log(`\n  ${passed} passed, ${failed} failed`);
if (failed > 0) process.exitCode = 1;
