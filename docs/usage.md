# NOPE — Neutralize Operations Prior to Execution

Agent security in one import. Presets to start, fluent builder to customize, one method to scan everything.

```
npm install @agnt-gg/nope
```

---

## Quick Start

```typescript
import { NOPE } from '@agnt-gg/nope';

const nope = NOPE.preset('standard');

nope.check({ command: 'DROP TABLE users;' });
// → { allowed: false, violations: [{ rule: 'db-drop-table', severity: 'critical' }] }

nope.scan(contextText);                                    // prompt injection
nope.scan({ name: 'shell', description: 'Run commands' }); // MCP tool

const safe = nope.wrap(plug.tools);                         // wrap tools
```

### Presets

| Preset     | Mode   | Threshold | SSRF     | Scanners | Telemetry |
| ---------- | ------ | --------- | -------- | -------- | --------- |
| `paranoid` | strict | medium    | enforced | all on   | on        |
| `standard` | strict | high      | on       | off      | on        |
| `minimal`  | strict | high      | off      | off      | off       |
| `audit`    | audit  | low       | on + log | all on   | on        |

Presets accept overrides:

```typescript
const nope = NOPE.preset('standard', { auth: { verifyToken: myFn } });
```

### Fluent builder

```typescript
const nope = new NOPE()
  .withRole('admin', 'critical', 'warn')
  .withRole('agent', 'medium', 'strict')
  .withRateLimit('1m', 60, { admin: 200, agent: 30 })
  .withLockout(5)
  .withSSRF({ enforced: true })
  .withScanners({ homograph: true, terminalInjection: true })
  .withTelemetry({ store: 'memory', retention: '7d' })
  .withTrust('@agnt-gg/*');
```

---

## Core API

### check(action, context?)

Test an action against all rules.

```typescript
nope.check({ command: 'DROP TABLE users;' });
nope.check({ tool: 'exec', params: { command: 'shutdown -h now' } });
nope.check({ code: 'eval(userInput)' });
nope.check({ command: 'shutdown -h now' }, { role: 'developer' });  // identity-aware
```

### wrap(tools)

Wrap tools — inputs checked, outputs sanitized. All layers apply automatically.

```typescript
const safe = nope.wrap(plug.tools);
for (const t of safe) ai.tool(t.name, t.description, t.input, t.run);
```

Pipeline: external scanner → built-in rules → identity context → trust level → LLM approval → onBlock → execute → sanitize output.

### scan(input)

One method, dispatches by input type:

```typescript
nope.scan('ignore previous instructions...');          // → prompt injection
nope.scan({ name: 'shell', description: '...' });      // → MCP tool scan
nope.scan({ code: pluginSource });                      // → plugin code scan
await nope.scan({ binary: '/usr/local/bin/tirith' });   // → binary checksum
```

### sanitize(value, toolName?)

Scrub secrets from any value. 17 built-in patterns (OpenAI, Anthropic, AWS, GitHub, Stripe, JWT, PEM, etc.).

```typescript
const clean = nope.sanitize(toolOutput, 'my-tool');
```

---

## Configuration

Start with a preset, then layer on what you need. Every feature is opt-in.

### Modes & thresholds

```typescript
new NOPE({ mode: 'strict' })          // block violations (default)
new NOPE({ mode: 'warn' })            // log but allow
new NOPE({ mode: 'audit' })           // silent
new NOPE({ threshold: 'critical' })   // only block critical
```

### Identity & auth

Role-based thresholds, token verification, rate limiting, allow/deny lists, approval memory, lockout.

```typescript
const nope = NOPE.preset('standard')
  .withRole('admin', 'critical', 'warn')
  .withRole('agent', 'medium', 'strict')
  .withRateLimit('1m', 60, { admin: 200, agent: 30 })
  .withLockout(5)
  .withAuth({
    verifyToken: async (t) => jwt.verify(t, SECRET),
    allowlist: ['user_abc'],
    denylist: ['user_bad'],
  });

await nope.checkWithToken(action, 'eyJhbG...');  // auto-verify + check
nope.recordApproval('user_abc', 'fs-rm-rf', 'always');  // approval memory
```

### SSRF protection

DNS resolution, redirect chain validation, cloud metadata blocking (AWS, GCP, Azure, Alibaba), IPv6 private ranges, custom blocklists, enforced mode.

```typescript
nope.withSSRF({
  enforced: true,
  customBlocklist: ['evil.internal'],
  allowlist: ['safe-api.com'],
});

await nope.resolveAndCheck('https://suspicious.com');
// → { safe: false, reason: 'DNS rebinding: resolves to 10.0.0.1' }
```

### Sandbox

4 backends: process, Docker, SSH, WASM. Docker supports custom images, `--pids-limit`, `--read-only`, `--user`, seccomp, AppArmor, volumes, persistent containers.

```typescript
const sb = nope.sandbox({
  backend: 'docker', image: 'node:20-slim',
  pidsLimit: 256, readonlyRoot: true, user: 'nobody',
});
await sb.exec('echo hello');
```

### Scanners

Built-in homograph detection, terminal injection scanning, binary verification.

```typescript
nope.withScanners({ homograph: true, terminalInjection: true });
```

### Telemetry & dashboard

```typescript
nope.withTelemetry({ store: 'memory', retention: '7d' });
nope.report();     // → { totalChecks, blocked, riskScore, topViolations, ... }
nope.dashboard();  // → self-contained HTML dashboard
```

### Smart LLM approval

```typescript
new NOPE({
  llmApprove: async (cmd, violations) => {
    const r = await llm.chat('Safe? ' + cmd);
    return r.includes('safe') ? 'approve' : 'escalate';
  },
});
```

LLM can only raise severity, never lower. Throws → fail-safe. Verdicts: `approve`, `deny`, `escalate`.

### All config options

| Option            | Default    | Description                                           |
| ----------------- | ---------- | ----------------------------------------------------- |
| `mode`            | `'strict'` | strict blocks, warn logs, audit silent                |
| `threshold`       | `'high'`   | Minimum severity to block                             |
| `onBlock`         | --         | Override callback (return true to allow)              |
| `sanitizeOutput`  | `true`     | Scrub secrets from tool output                        |
| `outputPatterns`  | `[]`       | Additional secret patterns                            |
| `onSanitize`      | --         | Callback when secrets redacted                        |
| `llmApprove`      | --         | Smart LLM approval (approve/deny/escalate)            |
| `externalScanner` | --         | External scanner hook (allow/warn/block)              |
| `trustedSources`  | `[]`       | Glob patterns for trusted tools                       |
| `identity`        | --         | Role-based security profiles                          |
| `ssrf`            | `{}`       | DNS, redirects, enforced mode, blocklists             |
| `telemetry`       | --         | Event tracking and reporting                          |
| `auth`            | --         | Token verification, rate limiting, allow/deny, lockout |
| `scanners`        | `{}`       | Homograph, terminal injection, binary verification    |

---

## Built-in Rules

60+ rules across 10 categories. All active by default.

| Category     | Rules | Covers                                                    |
| ------------ | ----- | --------------------------------------------------------- |
| filesystem   | 9     | rm -rf, format, dd, shred, chmod 777, config deletion     |
| database     | 6     | DROP, TRUNCATE, DELETE/UPDATE without WHERE, GRANT ALL    |
| system       | 7     | shutdown, kill, iptables flush, crontab, passwd, SELinux  |
| credentials  | 15    | API keys (OpenAI, AWS, Stripe, etc.), JWT, PEM, SSH, .env |
| injection    | 5     | eval, exec, Function constructor, curl\|bash, base64      |
| exfiltration | 4     | upload secrets, tar pipe, reverse shell, DNS tunneling    |
| network      | 8     | Private IPs, localhost, cloud metadata, IPv6, headers     |
| git          | 4     | force push, hard reset, clean, delete remote branch       |
| packages     | 2     | global install, untrusted npx                             |
| containers   | 3     | privileged, rm all, host root mount                       |

```typescript
nope.add('no-prod-db', {
  description: 'Block production database writes',
  severity: 'critical',
  category: 'custom',
  match: (a) => /prod/i.test(String(a.params?.database || '')),
});

nope.remove('pkg-global-install');
```

---

## Advanced

### Guard a single function

```typescript
const safeExec = nope.guard(async ({ command }) => execSync(command).toString());
await safeExec({ command: 'ls' });       // works
await safeExec({ command: 'shutdown -h now' }); // throws
```

### External scanner

Runs before built-in rules. Verdict is authoritative. Fails open if unavailable.

```typescript
new NOPE({
  externalScanner: async (action) => ({
    action: (await runBinary(action)).exitCode === 0 ? 'allow' : 'block',
  }),
});
```

### Red team testing

50+ built-in attack vectors with fuzzing.

```typescript
const r = await nope.redTeam({ attacks: 'all', iterations: 200 });
// → { passed: 187, failed: 13, coverage: { command: { tested: 48, caught: 45 }, ... } }
```

### Consent callback

```typescript
new NOPE({
  onBlock: async (violations, action) => {
    return await prompt('Allow? (y/n)') === 'y';
  },
});
```
