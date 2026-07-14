import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join, resolve } from 'node:path';
import process from 'node:process';

const projectRoot = resolve(new URL('..', import.meta.url).pathname.replace(/^\/(?:([A-Za-z]:))/, '$1'));
const safeRoot = await mkdtemp(join(tmpdir(), 'nope-safe-test-'));
const dangerousPrograms = new Set([
  'bash', 'cmd', 'cmd.exe', 'docker', 'docker.exe', 'diskpart', 'diskpart.exe',
  'format', 'format.com', 'mkfs', 'mkfs.ext4', 'powershell', 'powershell.exe',
  'pwsh', 'pwsh.exe', 'rm', 'sh', 'ssh', 'ssh.exe', 'sudo', 'wsl', 'wsl.exe',
]);
const safePrograms = new Set(['node', 'node.exe']);
const forbiddenText = /(?:^|[\s;&|])(?:rm\s+-rf|del\s+\/s|rmdir\s+\/s|format\b|diskpart\b|mkfs\b|shutdown\b|reboot\b)|[A-Za-z]:\\(?:Windows|Program Files)|\/home\/|\/Users\//i;

const originalSpawn = spawn;
function guardedSpawn(command, args = [], options = {}) {
  const program = basename(String(command)).toLowerCase();
  const rendered = [command, ...args].join(' ');
  const argumentsText = args.join(' ');
  if (!safePrograms.has(program) || dangerousPrograms.has(program) || options.shell || forbiddenText.test(argumentsText)) {
    throw new Error(`SAFE_TEST_HARNESS_BLOCKED: ${rendered}`);
  }
  const cwd = resolve(options.cwd ?? safeRoot);
  const allowedRoots = [resolve(safeRoot), resolve(projectRoot)];
  if (!allowedRoots.some(root => cwd.toLowerCase().startsWith(root.toLowerCase()))) {
    throw new Error(`SAFE_TEST_HARNESS_BLOCKED_CWD: ${cwd}`);
  }
  return originalSpawn(command, args, {
    ...options,
    cwd,
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      NOPE_PROJECT_ROOT: options.env?.NOPE_PROJECT_ROOT,
      NOPE_SAFE_TEST_ROOT: options.env?.NOPE_SAFE_TEST_ROOT,
    },
    shell: false,
  });
}

try {
  const child = guardedSpawn(process.execPath, [join(projectRoot, 'test', 'sandbox-security.mjs')], {
    cwd: safeRoot,
    env: {
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      NOPE_PROJECT_ROOT: projectRoot,
      NOPE_SAFE_TEST_ROOT: safeRoot,
    },
    stdio: 'inherit',
  });
  const exitCode = await new Promise((resolveExit, reject) => {
    child.once('error', reject);
    child.once('exit', code => resolveExit(code ?? 1));
  });
  process.exitCode = exitCode;
} finally {
  await rm(safeRoot, { recursive: true, force: true });
}
