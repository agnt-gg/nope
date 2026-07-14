import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import process from 'node:process';

const tarball = process.argv[2];
if (!tarball) throw new Error('Usage: node scripts/verify-packed-artifact.mjs <tarball>');

const absoluteTarball = resolve(tarball);
const safeRoot = mkdtempSync(join(tmpdir(), 'nope-packed-test-'));
const npmCli = process.platform === 'win32'
  ? join(process.execPath, '..', 'node_modules', 'npm', 'bin', 'npm-cli.js')
  : undefined;
const runNpm = (args, options) => process.platform === 'win32'
  ? execFileSync(process.execPath, [npmCli, ...args], options)
  : execFileSync('npm', args, options);

try {
  runNpm(['init', '-y'], { cwd: safeRoot, stdio: 'ignore', shell: false });
  runNpm(['install', '--ignore-scripts', '--no-audit', '--no-fund', absoluteTarball], {
    cwd: safeRoot,
    stdio: 'inherit',
    shell: false,
  });

  writeFileSync(join(safeRoot, 'smoke.mjs'), `
import assert from 'node:assert/strict';
import { NOPE, NopeSandboxError } from '@agnt-gg/nope';
const nope = new NOPE({ mode: 'strict' });
assert.throws(() => nope.sandbox(), error => error instanceof NopeSandboxError && error.code === 'BACKEND_REQUIRED');
assert.throws(() => nope.sandbox({ backend: 'process' }), error => error.code === 'UNSAFE_HOST_EXECUTION');
assert.throws(() => nope.sandbox({ backend: 'host-process' }), error => error.code === 'UNSAFE_HOST_EXECUTION');
const wasm = nope.sandbox({ backend: 'wasm' });
const wasmResult = await wasm.exec('inert-marker-only');
assert.equal(wasmResult.exitCode, 127);
assert.match(wasmResult.stderr, /BACKEND_UNAVAILABLE/);
const safeScript = ${JSON.stringify(join(safeRoot, 'safe-child.mjs'))};
const marker = ${JSON.stringify(join(safeRoot, 'marker.txt'))};
const host = nope.sandbox({
  backend: 'host-process',
  acknowledgeHostAccess: true,
  executable: process.execPath,
  args: [safeScript],
  cwd: ${JSON.stringify(safeRoot)},
});
const hostResult = await host.exec();
assert.equal(hostResult.exitCode, 0, hostResult.stderr);
console.log('packed artifact runtime smoke: PASS');
`);
  writeFileSync(join(safeRoot, 'safe-child.mjs'), `import { writeFileSync } from 'node:fs'; writeFileSync(${JSON.stringify(join(safeRoot, 'marker.txt'))}, 'safe');`);

  const smoke = spawnSync(process.execPath, [join(safeRoot, 'smoke.mjs')], {
    cwd: safeRoot,
    env: { PATH: process.env.PATH, SystemRoot: process.env.SystemRoot },
    shell: false,
    encoding: 'utf8',
  });
  process.stdout.write(smoke.stdout ?? '');
  process.stderr.write(smoke.stderr ?? '');
  assert.equal(smoke.status, 0, 'packed artifact runtime smoke failed');
  assert.equal(readFileSync(join(safeRoot, 'marker.txt'), 'utf8'), 'safe');

  const types = `import { NOPE, NopeSandboxError } from '@agnt-gg/nope';\nconst nope = new NOPE();\nconst error: NopeSandboxError | undefined = undefined;\nvoid nope; void error;\n`;
  writeFileSync(join(safeRoot, 'type-smoke.ts'), types);
  writeFileSync(join(safeRoot, 'tsconfig.json'), JSON.stringify({ compilerOptions: { target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', strict: true, noEmit: true }, include: ['type-smoke.ts'] }, null, 2));
  execFileSync(process.execPath, [resolve('node_modules/typescript/bin/tsc'), '-p', join(safeRoot, 'tsconfig.json')], { cwd: safeRoot, stdio: 'inherit', shell: false });
  console.log('packed artifact type smoke: PASS');
} finally {
  rmSync(safeRoot, { recursive: true, force: true });
}
