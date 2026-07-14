// ============================================================
// @agnt-gg/nope — test suite
// Covers the 2026-07-13 review fixes + core engine behavior.
// Plain Node asserts against the compiled dist/ — no test framework.
// ============================================================
import { strict as assert } from 'node:assert';
import { NOPE, BUILTIN_RULES } from '../dist/index.js';

let passed = 0;
let failed = 0;
const fails = [];

async function test(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  ✅ ${name}`);
  } catch (e) {
    failed++;
    fails.push({ name, error: e.message });
    console.log(`  ❌ ${name}: ${e.message}`);
  }
}

console.log('\n── Core rule engine ──');

await test('rm -rf is blocked in strict mode', () => {
  const nope = new NOPE();
  const r = nope.check({ command: 'rm -rf /home/user' });
  assert.equal(r.allowed, false);
  assert.ok(r.violations.some(v => v.rule === 'fs-rm-rf'));
});

await test('DROP TABLE is blocked in strict mode', () => {
  const nope = new NOPE();
  const r = nope.check({ command: 'DROP TABLE users;' });
  assert.equal(r.allowed, false);
  assert.ok(r.violations.some(v => v.rule === 'db-drop-table'));
});

await test('benign command is allowed', () => {
  const nope = new NOPE();
  const r = nope.check({ command: 'ls -la && git status' });
  assert.equal(r.allowed, true);
  assert.equal(r.violations.length, 0);
});

await test('BUILTIN_RULES export is intact (>= 60 rules)', () => {
  assert.ok(BUILTIN_RULES.length >= 60, `got ${BUILTIN_RULES.length}`);
});

console.log('\n── Review fix: SQL no-WHERE rules (Edge 5) ──');

await test('DELETE without WHERE, no semicolon, is flagged (old rule missed this)', () => {
  const nope = new NOPE();
  const r = nope.check({ command: 'DELETE FROM users' });
  assert.ok(r.violations.some(v => v.rule === 'db-delete-no-where'));
});

await test('DELETE without WHERE, with semicolon, is flagged', () => {
  const nope = new NOPE();
  const r = nope.check({ command: 'DELETE FROM users;' });
  assert.ok(r.violations.some(v => v.rule === 'db-delete-no-where'));
});

await test('DELETE WITH a WHERE clause is NOT flagged', () => {
  const nope = new NOPE();
  const r = nope.check({ command: 'DELETE FROM users WHERE id = 42' });
  assert.ok(!r.violations.some(v => v.rule === 'db-delete-no-where'));
});

await test('UPDATE without WHERE is flagged', () => {
  const nope = new NOPE();
  const r = nope.check({ command: 'UPDATE users SET banned = 1' });
  assert.ok(r.violations.some(v => v.rule === 'db-update-no-where'));
});

await test('UPDATE WITH a WHERE clause is NOT flagged', () => {
  const nope = new NOPE();
  const r = nope.check({ command: 'UPDATE users SET banned = 1 WHERE id = 42;' });
  assert.ok(!r.violations.some(v => v.rule === 'db-update-no-where'));
});

console.log('\n── Review fix: sanitize() binary safety (Bug 1) ──');

await test('OpenAI key is redacted in a small string (enforce mode)', () => {
  const nope = new NOPE();
  const out = nope.sanitize({ msg: 'my key is sk-abcdefghij1234567890XYZ ok' }, 'test');
  assert.ok(out.msg.includes('[REDACTED:OpenAI key]'));
  assert.ok(!out.msg.includes('sk-abcdefghij'));
});

await test('base64 blob containing an accidental key-shaped run is NOT touched', () => {
  const nope = new NOPE();
  // Build a >512-char unbroken base64 run with an embedded sk- lookalike
  const blob = 'iVBORw0KGgoAAAANSUhEUg' + 'A'.repeat(300) + 'sk' + 'B'.repeat(30) + 'C'.repeat(300) + '==';
  const out = nope.sanitize({ image_b64: blob }, 'test');
  assert.equal(out.image_b64, blob, 'base64 payload must pass through unmodified');
});

await test('oversized string (> maxSanitizeLength) is skipped', () => {
  const nope = new NOPE({ maxSanitizeLength: 1000 });
  const big = 'x '.repeat(1000) + ' sk-abcdefghij1234567890XYZ';
  const out = nope.sanitize({ data: big }, 'test');
  assert.equal(out.data, big, 'oversized string must pass through unmodified');
});

await test('JWT is redacted in a small string', () => {
  const nope = new NOPE();
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
  const out = nope.sanitize({ token: `auth: ${jwt}` }, 'test');
  assert.ok(out.token.includes('[REDACTED:JWT token]'));
});

await test('Groq gsk_ key is redacted (typo fix: was gsk-)', () => {
  const nope = new NOPE();
  const out = nope.sanitize({ k: 'gsk_abcdefghij1234567890XYZplus' }, 'test');
  assert.ok(out.k.includes('[REDACTED:Groq key]'));
});

console.log('\n── Review fix: regex global-flag safety (Bug 2) ──');

await test('caller-supplied pattern WITHOUT /g does not hang and still redacts', () => {
  const nope = new NOPE({
    outputPatterns: [{ pattern: /MYSECRET-\d{4}/, label: 'Custom' }], // note: no /g
  });
  const start = Date.now();
  const out = nope.sanitize({ a: 'x MYSECRET-1234 y MYSECRET-5678 z' }, 'test');
  const elapsed = Date.now() - start;
  assert.ok(elapsed < 2000, `took ${elapsed}ms — possible hang`);
  const redactedCount = (out.a.match(/\[REDACTED:Custom\]/g) || []).length;
  assert.equal(redactedCount, 2, 'both occurrences redacted (global forced)');
});

console.log('\n── Review fix: sanitizeMode report / audit preset (Edge 4) ──');

await test("audit preset returns output UNMODIFIED but reports redactions", () => {
  let reported = null;
  const nope = NOPE.preset('audit', { onSanitize: (r) => { reported = r; } });
  const input = { msg: 'key: sk-abcdefghij1234567890XYZ' };
  const out = nope.sanitize(input, 'test');
  assert.equal(out.msg, input.msg, 'report mode must not mutate output');
  assert.ok(reported && reported.length === 1, 'onSanitize must still fire');
  assert.equal(reported[0].label, 'OpenAI key');
});

await test("sanitizeMode 'off' disables scanning entirely", () => {
  let fired = false;
  const nope = new NOPE({ sanitizeMode: 'off', onSanitize: () => { fired = true; } });
  const out = nope.sanitize({ msg: 'sk-abcdefghij1234567890XYZ' }, 'test');
  assert.ok(out.msg.includes('sk-'));
  assert.equal(fired, false);
});

await test("legacy sanitizeOutput:false still maps to 'off' (back-compat)", () => {
  const nope = new NOPE({ sanitizeOutput: false });
  const out = nope.sanitize({ msg: 'sk-abcdefghij1234567890XYZ' }, 'test');
  assert.ok(out.msg.includes('sk-'), 'no redaction when sanitizeOutput === false');
});

await test('audit preset never blocks even on critical violations', () => {
  const nope = NOPE.preset('audit');
  const r = nope.check({ command: 'rm -rf / && DROP TABLE users;' });
  assert.equal(r.allowed, true, 'audit mode must always allow');
  assert.ok(r.violations.length > 0, 'but violations must still be reported');
});

console.log('\n── Review fix: circular-ref params (Edge 3) ──');

await test('check() with circular params does not throw (terminalInjection scanner on)', () => {
  const nope = new NOPE({ scanners: { terminalInjection: true } });
  const params = { name: 'test' };
  params.self = params; // circular
  const r = nope.check({ tool: 'some_tool', params });
  assert.ok(typeof r.allowed === 'boolean', 'check must return a normal result');
});

console.log('\n── SSRF ──');

await test('cloud metadata IP is blocked', async () => {
  const nope = new NOPE();
  const r = await nope.resolveAndCheck('http://169.254.169.254/latest/meta-data/');
  assert.equal(r.blocked, true);
});

console.log('\n══════════════════════════════════');
console.log(`  ${passed} passed, ${failed} failed`);
console.log('══════════════════════════════════');
if (failed > 0) {
  console.log('\nFailures:');
  for (const f of fails) console.log(`  • ${f.name}: ${f.error}`);
  process.exit(1);
}
