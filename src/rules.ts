// ============================================================
//  @agnt-gg/nope — Built-in Rules
//  Pattern-based guardrails for common dangerous operations.
// ============================================================

import type { Rule, Action } from './types.js';

// ── Helpers ─────────────────────────────────────────────────

/** Check if any string value in params matches a regex */
function paramsMatch(action: Action, pattern: RegExp): boolean {
  const check = (val: any): boolean => {
    if (typeof val === 'string') return pattern.test(val);
    if (Array.isArray(val)) return val.some(check);
    if (val && typeof val === 'object') return Object.values(val).some(check);
    return false;
  };
  if (action.command && pattern.test(action.command)) return true;
  if (action.code && pattern.test(action.code)) return true;
  if (action.params) return check(action.params);
  return false;
}

/** Check if tool name matches a pattern */
function toolMatch(action: Action, pattern: RegExp): boolean {
  return action.tool ? pattern.test(action.tool) : false;
}

// ── Filesystem Rules ────────────────────────────────────────

const filesystem: Rule[] = [
  {
    id: 'fs-rm-rf',
    description: 'Recursive force delete (rm -rf)',
    severity: 'critical',
    category: 'filesystem',
    match: (a) => paramsMatch(a, /rm\s+(-[a-z]*r[a-z]*f|--recursive\s+--force|-[a-z]*f[a-z]*r)\b/i),
  },
  {
    id: 'fs-rm-root',
    description: 'Delete root or home directory',
    severity: 'critical',
    category: 'filesystem',
    match: (a) => paramsMatch(a, /rm\s+.*\s+(\/|\/home|\/root|~|\$HOME|C:\\|%USERPROFILE%)/i),
  },
  {
    id: 'fs-format',
    description: 'Disk format operation',
    severity: 'critical',
    category: 'filesystem',
    match: (a) => paramsMatch(a, /\b(mkfs|format\s+[a-z]:|fdisk|diskpart)\b/i),
  },
  {
    id: 'fs-dd',
    description: 'Raw disk write (dd)',
    severity: 'critical',
    category: 'filesystem',
    match: (a) => paramsMatch(a, /\bdd\s+.*of=\/dev\//i),
  },
  {
    id: 'fs-shred',
    description: 'Secure file destruction (shred/wipe)',
    severity: 'high',
    category: 'filesystem',
    match: (a) => paramsMatch(a, /\b(shred|wipe|srm|secure-delete)\b/i),
  },
  {
    id: 'fs-chmod-777',
    description: 'Setting world-writable permissions',
    severity: 'high',
    category: 'filesystem',
    match: (a) => paramsMatch(a, /chmod\s+(\+[rwx]*a|777|666|a\+[rwx])/i),
  },
  {
    id: 'fs-chown-root',
    description: 'Changing ownership to root',
    severity: 'medium',
    category: 'filesystem',
    match: (a) => paramsMatch(a, /chown\s+.*root/i),
  },
  {
    id: 'fs-delete-config',
    description: 'Deleting configuration or credentials files',
    severity: 'high',
    category: 'filesystem',
    match: (a) => paramsMatch(a, /rm\s+.*(\.(env|ssh|aws|credentials|config|gitconfig|npmrc)|\/(\.ssh|\.aws|\.config)\/)/i),
  },
  {
    id: 'fs-overwrite-system',
    description: 'Writing to system directories',
    severity: 'high',
    category: 'filesystem',
    match: (a) => paramsMatch(a, />\s*\/(etc|boot|sys|proc|usr\/bin|usr\/sbin)\//i),
  },
];

// ── Database Rules ──────────────────────────────────────────

const database: Rule[] = [
  {
    id: 'db-drop-table',
    description: 'DROP TABLE statement',
    severity: 'critical',
    category: 'database',
    match: (a) => paramsMatch(a, /\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b/i),
  },
  {
    id: 'db-truncate',
    description: 'TRUNCATE TABLE statement',
    severity: 'critical',
    category: 'database',
    match: (a) => paramsMatch(a, /\bTRUNCATE\s+(TABLE\s+)?\w/i),
  },
  {
    id: 'db-delete-no-where',
    description: 'DELETE without WHERE clause',
    severity: 'critical',
    category: 'database',
    match: (a) => paramsMatch(a, /\bDELETE\s+FROM\s+[\w."'`\[\]]+(?![^;]*\bWHERE\b)/i),
  },
  {
    id: 'db-update-no-where',
    description: 'UPDATE without WHERE clause',
    severity: 'high',
    category: 'database',
    match: (a) => paramsMatch(a, /\bUPDATE\s+[\w."'`\[\]]+\s+SET\b(?![^;]*\bWHERE\b)/i),
  },
  {
    id: 'db-alter-drop-column',
    description: 'ALTER TABLE DROP COLUMN',
    severity: 'high',
    category: 'database',
    match: (a) => paramsMatch(a, /\bALTER\s+TABLE\s+\w+\s+DROP\s+COLUMN\b/i),
  },
  {
    id: 'db-grant-all',
    description: 'GRANT ALL PRIVILEGES',
    severity: 'high',
    category: 'database',
    match: (a) => paramsMatch(a, /\bGRANT\s+ALL\s+(PRIVILEGES\s+)?ON\b/i),
  },
];

// ── System/Network Rules ────────────────────────────────────

const system: Rule[] = [
  {
    id: 'sys-shutdown',
    description: 'System shutdown/reboot',
    severity: 'critical',
    category: 'system',
    match: (a) => paramsMatch(a, /\b(shutdown|halt|reboot|poweroff|init\s+[06])\b/i),
  },
  {
    id: 'sys-kill-all',
    description: 'Kill all processes',
    severity: 'critical',
    category: 'system',
    match: (a) => paramsMatch(a, /\b(killall|pkill\s+-9|kill\s+-9\s+-1)\b/i),
  },
  {
    id: 'sys-iptables-flush',
    description: 'Flush firewall rules',
    severity: 'critical',
    category: 'system',
    match: (a) => paramsMatch(a, /\biptables\s+(-F|--flush)\b/i),
  },
  {
    id: 'sys-crontab-remove',
    description: 'Remove all cron jobs',
    severity: 'high',
    category: 'system',
    match: (a) => paramsMatch(a, /\bcrontab\s+-r\b/i),
  },
  {
    id: 'sys-passwd-change',
    description: 'Changing system passwords',
    severity: 'high',
    category: 'system',
    match: (a) => paramsMatch(a, /\b(passwd|chpasswd|usermod\s+-p)\b/i),
  },
  {
    id: 'sys-sudo-su',
    description: 'Privilege escalation (sudo su)',
    severity: 'medium',
    category: 'system',
    match: (a) => paramsMatch(a, /\b(sudo\s+su|sudo\s+-i|su\s+-\s*$|su\s+root)\b/i),
  },
  {
    id: 'sys-disable-selinux',
    description: 'Disabling security features',
    severity: 'high',
    category: 'system',
    match: (a) => paramsMatch(a, /\b(setenforce\s+0|disable.*selinux|ufw\s+disable)\b/i),
  },
];

// ── Credential/Secret Rules ─────────────────────────────────

const credentials: Rule[] = [
  {
    id: 'cred-api-key-leak',
    description: 'API key or token in command output/params',
    severity: 'high',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\b(sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9-]{20,}|xoxb-[0-9-]+|ghp_[a-zA-Z0-9]{36}|gsk-[a-zA-Z0-9]{20,})\b/),
  },
  {
    id: 'cred-aws-key',
    description: 'AWS access key ID detected',
    severity: 'critical',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\bAKIA[0-9A-Z]{16}\b/),
  },
  {
    id: 'cred-google-api-key',
    description: 'Google API key detected',
    severity: 'high',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\bAIza[0-9A-Za-z\-_]{35}\b/),
  },
  {
    id: 'cred-stripe-key',
    description: 'Stripe live API key detected',
    severity: 'critical',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\b(sk_live_[0-9a-zA-Z]{24,}|rk_live_[0-9a-zA-Z]{24,})\b/),
  },
  {
    id: 'cred-replicate-key',
    description: 'Replicate API token detected',
    severity: 'high',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\br8_[0-9a-zA-Z]{36,}\b/),
  },
  {
    id: 'cred-jwt-token',
    description: 'JWT token detected in params',
    severity: 'high',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/),
  },
  {
    id: 'cred-bearer-token',
    description: 'Bearer token in HTTP request',
    severity: 'high',
    category: 'credentials',
    match: (a) => paramsMatch(a, /[Aa]uthorization[:\s]+Bearer\s+[A-Za-z0-9_\-\.]{20,}/),
  },
  {
    id: 'cred-private-key-pem',
    description: 'Private key material (PEM) detected',
    severity: 'critical',
    category: 'credentials',
    match: (a) => paramsMatch(a, /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/),
  },
  {
    id: 'cred-twilio-token',
    description: 'Twilio auth token detected',
    severity: 'high',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\b(SK[0-9a-fA-F]{32}|AC[0-9a-fA-F]{32})\b/),
  },
  {
    id: 'cred-sendgrid-key',
    description: 'SendGrid API key detected',
    severity: 'high',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b/),
  },
  {
    id: 'cred-generic-secret-assignment',
    description: 'Potential secret in key=value assignment (API_KEY=, SECRET=, TOKEN=)',
    severity: 'medium',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\b(API_KEY|API_SECRET|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY)=\S{10,}/i),
  },
  {
    id: 'cred-env-dump',
    description: 'Dumping environment variables (may contain secrets)',
    severity: 'medium',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\b(printenv|env\s*$|set\s*$|\$ENV|process\.env(?!\.))\b/i),
  },
  {
    id: 'cred-ssh-key-read',
    description: 'Reading SSH private keys',
    severity: 'high',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\bcat\s+.*id_(rsa|ed25519|ecdsa|dsa)(?!\.pub)\b/i),
  },
  {
    id: 'cred-password-in-command',
    description: 'Password passed via command line',
    severity: 'high',
    category: 'credentials',
    match: (a) => paramsMatch(a, /(-p\s*['"][^'"]+['"]|--password[= ]['"]|PASS(WORD)?=['"][^'"]+)/i),
  },
  {
    id: 'cred-env-file-send',
    description: 'Sending .env or credentials files',
    severity: 'critical',
    category: 'credentials',
    match: (a) => paramsMatch(a, /\b(curl|wget|http|fetch).*\.(env|credentials|pem|key)\b/i),
  },
];

// ── Code Injection Rules ────────────────────────────────────

const injection: Rule[] = [
  {
    id: 'inject-eval',
    description: 'Dynamic code evaluation (eval)',
    severity: 'high',
    category: 'injection',
    match: (a) => paramsMatch(a, /\beval\s*\(/i),
  },
  {
    id: 'inject-exec',
    description: 'Shell command execution',
    severity: 'high',
    category: 'injection',
    match: (a) => paramsMatch(a, /\b(child_process|exec|execSync|spawn|popen|os\.system)\s*\(/i),
  },
  {
    id: 'inject-function-constructor',
    description: 'Function constructor (code injection vector)',
    severity: 'high',
    category: 'injection',
    match: (a) => paramsMatch(a, /\bnew\s+Function\s*\(/i),
  },
  {
    id: 'inject-curl-pipe-bash',
    description: 'Piping remote content to shell (curl | bash)',
    severity: 'critical',
    category: 'injection',
    match: (a) => paramsMatch(a, /\b(curl|wget)\s+.*\|\s*(bash|sh|zsh|exec|python|node|perl)\b/i),
  },
  {
    id: 'inject-base64-decode-exec',
    description: 'Decoding and executing base64 content',
    severity: 'high',
    category: 'injection',
    match: (a) => paramsMatch(a, /\b(base64\s+-d|atob)\b.*\|\s*(bash|sh|exec|eval)\b/i),
  },
];

// ── Data Exfiltration Rules ─────────────────────────────────

const exfiltration: Rule[] = [
  {
    id: 'exfil-upload-secrets',
    description: 'Uploading sensitive files to external URLs',
    severity: 'critical',
    category: 'exfiltration',
    match: (a) => paramsMatch(a, /\b(curl|wget|http).*(-F|--upload-file|--data-binary)\s+.*\.(env|pem|key|credentials)\b/i),
  },
  {
    id: 'exfil-tar-pipe',
    description: 'Archiving and piping to remote destination',
    severity: 'high',
    category: 'exfiltration',
    match: (a) => paramsMatch(a, /\btar\b.*\|\s*(curl|wget|nc|ncat|netcat)\b/i),
  },
  {
    id: 'exfil-nc-listen',
    description: 'Opening reverse shell / netcat listener',
    severity: 'critical',
    category: 'exfiltration',
    match: (a) => paramsMatch(a, /\b(nc|ncat|netcat)\s+(-l|-e|--exec)\b/i),
  },
  {
    id: 'exfil-dns-tunnel',
    description: 'DNS tunneling (data exfiltration via DNS)',
    severity: 'high',
    category: 'exfiltration',
    match: (a) => paramsMatch(a, /\b(dig|nslookup|host)\s+.*\$\(/i),
  },
];

// ── Network/SSRF Rules ────────────────────

const network: Rule[] = [
  {
    id: 'net-ssrf-private-10',
    description: 'URL targeting RFC 1918 private network (10.x.x.x)',
    severity: 'critical',
    category: 'network',
    match: (a) => paramsMatch(a, /https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}/i),
  },
  {
    id: 'net-ssrf-private-172',
    description: 'URL targeting RFC 1918 private network (172.16-31.x.x)',
    severity: 'critical',
    category: 'network',
    match: (a) => paramsMatch(a, /https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/i),
  },
  {
    id: 'net-ssrf-private-192',
    description: 'URL targeting RFC 1918 private network (192.168.x.x)',
    severity: 'critical',
    category: 'network',
    match: (a) => paramsMatch(a, /https?:\/\/192\.168\.\d{1,3}\.\d{1,3}/i),
  },
  {
    id: 'net-ssrf-localhost',
    description: 'URL targeting localhost / loopback',
    severity: 'high',
    category: 'network',
    match: (a) => paramsMatch(a, /https?:\/\/(127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[::1\]|localhost)/i),
  },
  {
    id: 'net-ssrf-metadata',
    description: 'URL targeting cloud metadata endpoint (AWS/GCP/Azure/Alibaba SSRF)',
    severity: 'critical',
    category: 'network',
    match: (a) => paramsMatch(a, /https?:\/\/(169\.254\.169\.254|metadata\.google\.internal|metadata\.goog|169\.254\.170\.2|100\.100\.100\.200|169\.254\.169\.123)/i),
  },
  {
    id: 'net-ssrf-link-local',
    description: 'URL targeting link-local / CGNAT range',
    severity: 'high',
    category: 'network',
    match: (a) => paramsMatch(a, /https?:\/\/(169\.254\.\d{1,3}\.\d{1,3}|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})/i),
  },
  {
    id: 'net-ssrf-ipv6-private',
    description: 'URL targeting IPv6 private/link-local address',
    severity: 'critical',
    category: 'network',
    match: (a) => paramsMatch(a, /https?:\/\/\[?(fe80:|fc00:|fd00:|fd00:ec2::254|::1|::ffff:(?:10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.))/i),
  },
  {
    id: 'net-ssrf-header-injection',
    description: 'HTTP header injection via URL parameters',
    severity: 'high',
    category: 'network',
    match: (a) => paramsMatch(a, /\b(Host|X-Forwarded-For|X-Real-IP|X-Original-URL)\s*:\s*/i) && paramsMatch(a, /https?:\/\//i),
  },
];

// ── Git/Version Control Rules ───────────────────────────────

const git: Rule[] = [
  {
    id: 'git-force-push',
    description: 'Force push (can destroy remote history)',
    severity: 'high',
    category: 'git',
    match: (a) => paramsMatch(a, /\bgit\s+push\s+.*(-f|--force)\b/i),
  },
  {
    id: 'git-reset-hard',
    description: 'Hard reset (destroys uncommitted changes)',
    severity: 'high',
    category: 'git',
    match: (a) => paramsMatch(a, /\bgit\s+reset\s+--hard\b/i),
  },
  {
    id: 'git-clean-force',
    description: 'Force clean untracked files',
    severity: 'medium',
    category: 'git',
    match: (a) => paramsMatch(a, /\bgit\s+clean\s+.*-f/i),
  },
  {
    id: 'git-branch-delete-remote',
    description: 'Deleting remote branches',
    severity: 'medium',
    category: 'git',
    match: (a) => paramsMatch(a, /\bgit\s+push\s+.*--delete\b/i),
  },
];

// ── Package Manager Rules ───────────────────────────────────

const packages: Rule[] = [
  {
    id: 'pkg-global-install',
    description: 'Global package installation',
    severity: 'medium',
    category: 'packages',
    match: (a) => paramsMatch(a, /\b(npm\s+i(nstall)?\s+.*-g|pip\s+install(?!.*--user))\b/i),
  },
  {
    id: 'pkg-npm-run-untrusted',
    description: 'Running npm scripts from untrusted sources',
    severity: 'medium',
    category: 'packages',
    match: (a) => paramsMatch(a, /\bnpx\s+[a-z].*@/i),
  },
];

// ── Docker/Container Rules ──────────────────────────────────

const containers: Rule[] = [
  {
    id: 'docker-privileged',
    description: 'Running privileged container',
    severity: 'high',
    category: 'containers',
    match: (a) => paramsMatch(a, /\bdocker\s+run\s+.*--privileged\b/i),
  },
  {
    id: 'docker-rm-all',
    description: 'Removing all containers/images',
    severity: 'high',
    category: 'containers',
    match: (a) => paramsMatch(a, /\bdocker\s+(rm|rmi)\s+.*\$\(docker\b/i),
  },
  {
    id: 'docker-host-mount',
    description: 'Mounting host root filesystem',
    severity: 'critical',
    category: 'containers',
    match: (a) => paramsMatch(a, /\bdocker\s+run\s+.*-v\s+\/:/i),
  },
];

// ── Export All Rules ────────────────────────────────────────

export const BUILTIN_RULES: Rule[] = [
  ...filesystem,
  ...database,
  ...system,
  ...credentials,
  ...injection,
  ...exfiltration,
  ...network,
  ...git,
  ...packages,
  ...containers,
];
