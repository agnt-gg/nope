type Scalar = 'string' | 'number' | 'boolean' | 'object' | 'array';
export type Param = Scalar | `${Scalar}?` | {
    type: Scalar;
    description?: string;
    required?: boolean;
    default?: unknown;
};
export interface Tool<TIn = any, TOut = any> {
    name: string;
    description: string;
    input: Record<string, Param>;
    run: (params: TIn) => TOut | Promise<TOut>;
}
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export interface Action {
    /** Tool name being called */
    tool?: string;
    /** Parameters being passed */
    params?: Record<string, any>;
    /** Raw command string (for shell/exec tools) */
    command?: string;
    /** Code string (for eval/exec tools) */
    code?: string;
}
export interface Rule {
    /** Unique rule ID */
    id: string;
    /** Human-readable description */
    description: string;
    /** Risk severity */
    severity: Severity;
    /** Category for grouping */
    category: string;
    /** Check function — returns true if the action violates this rule */
    match: (action: Action) => boolean;
}
export interface Violation {
    rule: string;
    description: string;
    severity: Severity;
    category: string;
}
export interface CheckResult {
    /** Whether the action is allowed to proceed */
    allowed: boolean;
    /** List of rule violations found */
    violations: Violation[];
}
/** Pattern used to detect and redact secrets in tool output */
export interface OutputPattern {
    /** Regex to match (should use global flag for replacement) */
    pattern: RegExp;
    /** Human-readable label for the type of secret (e.g. 'OpenAI key') */
    label: string;
}
/** Record of a single secret that was redacted from tool output */
export interface Redaction {
    /** What type of secret was found */
    label: string;
    /** Dot-path where it was found (e.g. 'response.headers.authorization') */
    path: string;
    /** Number of characters redacted */
    length: number;
}
/** Verdict from the smart LLM approval or external scanner */
export type ApprovalVerdict = 'approve' | 'deny' | 'escalate';
/** Result from the external scanner hook */
export interface ScannerResult {
    /** The action verdict — exit code is truth */
    action: 'allow' | 'warn' | 'block';
    /** Optional enrichment summary */
    summary?: string;
}
export type Mode = 'strict' | 'warn' | 'audit';
/** Named presets for NOPE.preset() */
export type PresetName = 'paranoid' | 'standard' | 'minimal' | 'audit';
/** How sanitize() treats matches: 'off' disables scanning, 'report' records
 *  redactions (telemetry + onSanitize) without mutating output, 'enforce'
 *  redacts in place. */
export type SanitizeMode = 'off' | 'report' | 'enforce';
export interface NopeConfig {
    /** Blocking mode:
     *  - 'strict': block all flagged operations (throw on critical/high)
     *  - 'warn': log warnings but allow execution
     *  - 'audit': silent logging only
     */
    mode?: Mode;
    /** Minimum severity to block in strict mode. Default: 'high' */
    threshold?: Severity;
    /** Callback when an action is blocked. Return true to override and allow. */
    onBlock?: (violations: Violation[], action: Action) => boolean | Promise<boolean>;
    /** Whether to scrub secrets from tool outputs before they reach the LLM. Default: true.
     *  Back-compat shim: false → sanitizeMode 'off', true → 'enforce'.
     *  Prefer sanitizeMode, which takes precedence when both are set. */
    sanitizeOutput?: boolean;
    /**
     * Sanitization mode (takes precedence over sanitizeOutput):
     *  - 'off': no output scanning
     *  - 'report': detect secrets, fire telemetry/onSanitize, return output UNMODIFIED
     *  - 'enforce': redact matches in place with [REDACTED:label] (default)
     */
    sanitizeMode?: SanitizeMode;
    /** Strings longer than this many chars are skipped by sanitize() — binary/base64
     *  guard against payload corruption and multi-MB regex sweeps. Default: 65536 */
    maxSanitizeLength?: number;
    /** Additional patterns to scan for in tool output (merged with built-in patterns) */
    outputPatterns?: OutputPattern[];
    /** Called when secrets are redacted from output. For logging/auditing. */
    onSanitize?: (redactions: Redaction[], toolName: string) => void;
    /**
     * Smart LLM approval — use an auxiliary LLM to assess risk on flagged commands.
     * Called when an action triggers violations but before blocking.
     * - 'approve': allow execution (LLM deems safe despite pattern match)
     * - 'deny': block execution (LLM confirms dangerous)
     * - 'escalate': fall through to onBlock callback or default block behavior
     *
     * Best-effort: if this throws, falls through to normal block logic.
     */
    llmApprove?: (command: string, violations: Violation[]) => Promise<ApprovalVerdict>;
    /**
     * External command scanner — delegate to an external binary or service
     * for deeper semantic analysis (e.g. homograph URLs, terminal injection).
     * Called before built-in rules. If it returns 'block', the action is blocked
     * regardless of built-in rules.
     *
     * The action field in the result is authoritative (exit code is truth).
     */
    externalScanner?: (action: Action) => Promise<ScannerResult>;
    /**
     * Trusted tool sources — glob patterns for tool names that should use
     * a relaxed threshold. Tools matching any pattern get threshold lowered
     * to 'critical' only (ignoring high/medium).
     *
     * Example: ['@agnt-gg/*', 'builtin.*']
     */
    trustedSources?: string[];
    /**
     * Identity-aware security — role-based thresholds and modes.
     * Different callers (admin, developer, agent, untrusted) get
     * different security profiles.
     */
    identity?: IdentityConfig;
    /**
     * SSRF configuration — DNS resolution and redirect chain validation.
     * Elevates URL checking from pattern matching to network-layer protection.
     */
    ssrf?: SSRFConfig;
    /**
     * Telemetry configuration — event tracking, aggregation, and reporting.
     * Enables security observability with metrics, timelines, and dashboards.
     */
    telemetry?: TelemetryConfig;
    /**
     * Authentication — token verification, rate limiting, allow/deny lists,
     * approval memory, and lockout. Portable auth primitives for any platform.
     */
    auth?: AuthConfig;
    /**
     * Built-in scanners — homograph detection, terminal injection,
     * binary verification. No external binary needed.
     */
    scanners?: ScannersConfig;
}
export interface RuleInfo {
    id: string;
    description: string;
    severity: Severity;
    category: string;
}
export type ContextFindingType = 'unicode' | 'hijacking' | 'exfiltration' | 'encoded_payload';
export interface ContextFinding {
    /** Type of injection detected */
    type: ContextFindingType;
    /** Risk severity */
    severity: Severity;
    /** Human-readable description */
    description: string;
    /** Line number where finding was detected (1-based) */
    line?: number;
    /** The matched text */
    match: string;
}
export interface ContextScanResult {
    /** Whether the context is safe (no findings) */
    safe: boolean;
    /** List of injection findings */
    findings: ContextFinding[];
}
export interface SSRFConfig {
    /** Resolve DNS before allowing requests. Default: true */
    resolveDNS?: boolean;
    /** Follow redirect chains and re-validate. Default: true */
    followRedirects?: boolean;
    /** Max number of redirects to follow. Default: 5 */
    maxRedirects?: number;
    /** When true, SSRF checks cannot be disabled or relaxed. Default: false */
    enforced?: boolean;
    /** Additional hostnames/IPs to block */
    customBlocklist?: string[];
    /** Explicit allowlist (overrides blocks for specific hosts) */
    allowlist?: string[];
    /** Log all SSRF check attempts to telemetry. Default: true */
    logAttempts?: boolean;
    /** Enable IPv6 private range checking. Default: true */
    ipv6?: boolean;
}
export interface SSRFCheckResult {
    /** Whether the URL is safe to access */
    safe: boolean;
    /** The resolved IP address (if DNS resolution was performed) */
    resolvedIP?: string;
    /** Whether the URL was blocked */
    blocked: boolean;
    /** Reason for blocking */
    reason?: string;
    /** Chain of redirect URLs followed */
    redirectChain?: string[];
}
export interface SandboxConfig {
    /** Sandbox backend. Default: 'process' */
    backend?: 'process' | 'docker' | 'wasm' | 'ssh';
    /** CPU limit (e.g. '0.5'). Docker only. */
    cpu?: string;
    /** Memory limit (e.g. '256m'). Docker only. */
    memory?: string;
    /** Execution timeout in ms. Default: 30000 */
    timeout?: number;
    /** Allow network access. Default: false */
    network?: boolean;
    /** Custom Docker image (e.g. 'node:20-slim', 'python:3.12-slim'). Default: 'alpine:latest' */
    image?: string;
    /** Max PIDs inside container (fork bomb protection). Docker only. */
    pidsLimit?: number;
    /** tmpfs mounts (e.g. ['/tmp:size=64m']). Docker only. */
    tmpfs?: string[];
    /** Make root filesystem read-only. Docker only. Default: false */
    readonlyRoot?: boolean;
    /** Volume bind mounts (e.g. ['/data:/workspace:ro']). Docker only. */
    volumes?: string[];
    /** Run as specific user inside container (e.g. 'nobody'). Docker only. */
    user?: string;
    /** Path to seccomp profile JSON. Docker only. */
    seccomp?: string;
    /** AppArmor profile name. Docker only. */
    apparmorProfile?: string;
    /** Custom capabilities to drop (overrides default 'ALL'). Docker only. */
    dropCapabilities?: string[];
    /** SSH host for remote execution (e.g. 'user@host'). SSH backend only. */
    sshHost?: string;
    /** SSH key path for authentication. SSH backend only. */
    sshKey?: string;
    /** Container name for persistent sandboxes (omit for ephemeral). Docker only. */
    persistent?: string;
}
export interface SandboxResult {
    /** Standard output */
    stdout: string;
    /** Standard error */
    stderr: string;
    /** Exit code (0 = success) */
    exitCode: number;
    /** Execution duration in ms */
    duration: number;
}
export interface Sandbox {
    /** Execute a command string in the sandbox */
    exec(command: string): Promise<SandboxResult>;
    /** Destroy / clean up the sandbox */
    destroy(): void;
}
export interface RoleConfig {
    /** Severity threshold for this role */
    threshold: Severity;
    /** Execution mode for this role */
    mode: Mode;
}
export interface IdentityConfig {
    /** Map of role name → security profile */
    roles: Record<string, RoleConfig>;
}
export interface SecurityContext {
    /** Caller's role (must match a key in identity.roles) */
    role?: string;
    /** Optional session identifier for audit/tracking */
    sessionId?: string;
    /** Auth token (JWT, API key, etc.) — auto-verified if auth.verifyToken configured */
    token?: string;
    /** User ID (set automatically from token verification, or manually) */
    userId?: string;
}
export type ApprovalChoice = 'once' | 'session' | 'always' | 'deny';
export interface RateLimitConfig {
    /** Time window (e.g. '1m', '5m', '1h'). Default: '1m' */
    window?: string;
    /** Max requests per window (default for all roles). Default: 60 */
    maxRequests?: number;
    /** Per-role overrides for max requests */
    byRole?: Record<string, number>;
}
export interface ApprovalMemoryConfig {
    /** Storage backend. Default: 'memory' */
    store?: 'memory' | 'file' | 'custom';
    /** Available choices for approval prompts */
    options?: ApprovalChoice[];
}
export interface VerifiedIdentity {
    /** User ID extracted from token */
    id: string;
    /** Role extracted from token */
    role: string;
    /** Scopes/permissions extracted from token */
    scopes?: string[];
}
export interface AuthConfig {
    /** Token verification function — bring your own JWT/session/API key verifier */
    verifyToken?: (token: string) => VerifiedIdentity | Promise<VerifiedIdentity>;
    /** Rate limiting configuration */
    rateLimit?: RateLimitConfig;
    /** User IDs that are always allowed */
    allowlist?: string[];
    /** User IDs that are always denied */
    denylist?: string[];
    /** Approval memory — remember user's approval choices */
    approvalMemory?: ApprovalMemoryConfig;
    /** Auto-lockout after N consecutive denied actions. Default: 0 (disabled) */
    lockoutAfter?: number;
    /** Lockout duration in ms. Default: 300000 (5 min) */
    lockoutDuration?: number;
}
export interface BinaryChecksums {
    /** Map of binary name → expected SHA-256 hash */
    [binary: string]: string;
}
export interface ScannersConfig {
    /** Detect IDN homograph attacks in URLs. Default: false */
    homograph?: boolean;
    /** Detect ANSI escape sequences and terminal injection. Default: false */
    terminalInjection?: boolean;
    /** Verify external tool/binary checksums before execution */
    binaryVerification?: {
        /** Map of binary name → SHA-256 hash */
        checksums?: BinaryChecksums;
        /** Require signature verification (cosign/sigstore). Default: false */
        requireSignature?: boolean;
    };
}
export type PluginFindingType = 'broad_description' | 'suspicious_default' | 'exfiltration' | 'privilege_escalation' | 'injection';
export interface PluginFinding {
    /** Type of finding */
    type: PluginFindingType;
    /** Risk severity */
    severity: Severity;
    /** Human-readable description */
    description: string;
    /** The matched text */
    match?: string;
}
export interface PluginScanResult {
    /** Whether the plugin/tool is considered safe */
    safe: boolean;
    /** Overall risk level */
    risk: Severity;
    /** List of findings */
    findings: PluginFinding[];
}
export interface MCPToolDef {
    /** Tool name */
    name: string;
    /** Tool description (checked for injection patterns) */
    description: string;
    /** Input schema (checked for suspicious defaults) */
    inputSchema?: Record<string, any>;
    /** Allow additional properties */
    [key: string]: any;
}
export interface TelemetryConfig {
    /** Storage backend. Default: 'memory' */
    store?: 'memory' | 'file' | 'custom';
    /** Retention period (e.g. '7d', '24h'). Default: '7d' */
    retention?: string;
    /** Callback fired on each event */
    onEvent?: (event: TelemetryEvent) => void;
}
export interface TelemetryEvent {
    /** Unix timestamp (ms) */
    timestamp: number;
    /** Event type */
    type: 'check' | 'block' | 'warn' | 'sanitize' | 'scan' | 'injection';
    /** Rule that triggered (if applicable) */
    rule?: string;
    /** Severity of the event */
    severity?: Severity;
    /** Tool involved */
    tool?: string;
    /** Additional details */
    details?: string;
    /** Identity context */
    role?: string;
}
export interface SecurityReport {
    /** Total checks performed */
    totalChecks: number;
    /** Number of blocked actions */
    blocked: number;
    /** Number of warnings issued */
    warned: number;
    /** Number of allowed actions */
    allowed: number;
    /** Top violated rules sorted by count */
    topViolations: {
        rule: string;
        count: number;
    }[];
    /** Overall risk score 0-100 */
    riskScore: number;
    /** Recent telemetry events */
    timeline: TelemetryEvent[];
    /** Per-tool breakdown */
    perTool: Record<string, {
        checks: number;
        blocks: number;
    }>;
}
export type AttackCategory = 'injection' | 'exfiltration' | 'ssrf' | 'credentials' | 'command' | 'encoding';
export interface RedTeamConfig {
    /** Additional tools to test against */
    tools?: Tool[];
    /** Attack categories to run. Default: 'all' */
    attacks?: 'all' | AttackCategory[];
    /** Number of fuzzing iterations. Default: 100 */
    iterations?: number;
}
export interface RedTeamVulnerability {
    /** The attack payload */
    attack: string;
    /** Attack category */
    category: AttackCategory;
    /** Severity of the gap */
    severity: Severity;
    /** Description of the vulnerability */
    description: string;
    /** Whether the attack bypassed the rules */
    bypassed: boolean;
}
export interface RedTeamResult {
    /** Number of attacks caught */
    passed: number;
    /** Number of attacks that bypassed */
    failed: number;
    /** Total attacks tested */
    total: number;
    /** Detailed vulnerability list */
    vulnerabilities: RedTeamVulnerability[];
    /** Coverage per category */
    coverage: Record<string, {
        tested: number;
        caught: number;
    }>;
}
export {};
