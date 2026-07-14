import type { Rule, RuleInfo, Action, CheckResult, Tool, NopeConfig, Mode, Severity, ContextScanResult, SSRFCheckResult, SSRFConfig, SandboxConfig, Sandbox, SecurityContext, PluginScanResult, MCPToolDef, TelemetryConfig, SecurityReport, RedTeamConfig, RedTeamResult, AuthConfig, ApprovalChoice, ScannersConfig } from './types.js';
export declare class NOPE {
    private _rules;
    private _mode;
    private _threshold;
    private _onBlock?;
    private _sanitizeMode;
    private _maxSanitizeLength;
    private _outputPatterns;
    private _onSanitize?;
    private _llmApprove?;
    private _externalScanner?;
    private _trustedSources;
    private _identity?;
    private _ssrf;
    private _telemetry?;
    private _events;
    private _auth?;
    private _scanners;
    private _rateLimitBuckets;
    private _lockouts;
    private _approvalMemory;
    private _failureCounts;
    constructor(config?: NopeConfig);
    /** Preset name → config */
    static readonly PRESETS: Record<string, NopeConfig>;
    /**
     * Create a NOPE instance from a named preset.
     * Presets: 'paranoid' | 'standard' | 'minimal' | 'audit'
     * Pass overrides to merge on top of the preset.
     */
    static preset(name: string, overrides?: Partial<NopeConfig>): NOPE;
    /** Add a role with threshold and mode. Chainable. */
    withRole(name: string, threshold: Severity, mode: Mode): this;
    /** Configure rate limiting. Chainable. */
    withRateLimit(window: string, maxRequests: number, byRole?: Record<string, number>): this;
    /** Configure lockout after N failures. Chainable. */
    withLockout(after: number, duration?: number): this;
    /** Configure SSRF protection. Chainable. */
    withSSRF(config: SSRFConfig): this;
    /** Configure auth. Chainable. */
    withAuth(config: AuthConfig): this;
    /** Configure built-in scanners. Chainable. */
    withScanners(config: ScannersConfig): this;
    /** Configure telemetry. Chainable. */
    withTelemetry(config: TelemetryConfig): this;
    /** Add trusted source patterns. Chainable. */
    withTrust(...patterns: string[]): this;
    /** Add a custom rule */
    add(id: string, rule: Omit<Rule, 'id'>): this;
    /** Remove a rule (including built-in) */
    remove(id: string): this;
    /** List all active rules */
    get rules(): RuleInfo[];
    private _record;
    private _pruneEvents;
    /** Check if a tool name matches any trusted source pattern */
    private _isTrusted;
    /**
     * Check an action against all rules.
     * Returns whether the action is allowed and any violations found.
     * Optionally accepts a SecurityContext for identity-aware checking.
     * Supports token verification, rate limiting, allow/deny lists, and lockout.
     */
    check(action: Action, context?: SecurityContext): CheckResult;
    /**
     * Verify a token and return a SecurityContext with the resolved identity.
     * Uses the auth.verifyToken function configured in NopeConfig.
     */
    verifyToken(token: string): Promise<SecurityContext>;
    /**
     * Check an action with automatic token verification.
     * Resolves the token to a SecurityContext, then runs the check.
     */
    checkWithToken(action: Action, token: string): Promise<CheckResult>;
    /**
     * Record a user's approval choice for a specific rule.
     * Supports 'once' (no memory), 'session', 'always', and 'deny'.
     */
    recordApproval(userId: string, ruleId: string, choice: ApprovalChoice): void;
    /**
     * Check if a user has a stored approval for a specific rule.
     * Returns the stored choice, or undefined if none.
     */
    getApproval(userId: string, ruleId: string): ApprovalChoice | undefined;
    /**
     * Clear all stored approvals for a user.
     */
    clearApprovals(userId: string): void;
    /**
     * Scrub secrets from any value (typically tool output).
     * Recursively walks objects, arrays, and strings, replacing
     * any matches against the output patterns with [REDACTED:label].
     */
    sanitize<T>(value: T, toolName?: string): T;
    /**
     * Wrap tools with NOPE protection.
     * Returns new Tool[] where each tool's run function is guarded.
     */
    wrap(tools: Tool[]): Tool[];
    /**
     * Guard a single function.
     * Useful for wrapping shell exec, eval, or any dangerous operation.
     */
    guard<TIn extends Record<string, any>, TOut>(fn: (params: TIn) => TOut | Promise<TOut>): (params: TIn) => Promise<TOut>;
    /**
     * Scan a context string for prompt injection attempts.
     * Detects invisible Unicode, instruction hijacking, exfiltration
     * instructions, and encoded payloads.
     * Works on any text: context files, user messages, RAG chunks,
     * skill documents, MCP tool descriptions.
     */
    scanContext(text: string): ContextScanResult;
    /**
     * Wrap a context loader function so context is scanned for injection
     * before it reaches the LLM. If dangerous content is found, the
     * findings are included in the returned text as warnings.
     */
    wrapContext(loader: () => string | Promise<string>): () => Promise<string>;
    /**
     * Resolve a URL's hostname via DNS and validate the resolved IP
     * is not a private/internal address. Follows redirects if configured
     * and re-validates at each hop.
     */
    resolveAndCheck(url: string): Promise<SSRFCheckResult>;
    /**
     * Create a sandboxed execution environment.
     * Returns a Sandbox object with exec() for running commands in isolation.
     */
    sandbox(config?: SandboxConfig): Sandbox;
    private _dockerSandbox;
    private _sshSandbox;
    private _wasmSandbox;
    /**
     * Scan plugin or skill source code for security issues.
     * Detects exfiltration, privilege escalation, injection,
     * and suspicious patterns before the code is loaded.
     */
    scanPlugin(code: string): PluginScanResult;
    /**
     * Scan an MCP tool definition for security issues.
     * Checks the tool description for injection attempts,
     * input schema for suspicious defaults, and overall risk.
     */
    scanMCPTool(tool: MCPToolDef): PluginScanResult;
    private _worstSeverity;
    /**
     * Get a security report aggregating all telemetry events.
     * Returns metrics, top violations, risk score, and timeline.
     */
    report(): SecurityReport;
    /**
     * Generate a self-contained HTML security dashboard.
     * Can be served directly or written to a file.
     */
    dashboard(): string;
    /**
     * Verify a binary's SHA-256 checksum against the configured checksums.
     * Returns true if the checksum matches (or no verification configured).
     */
    verifyBinary(binaryPath: string): Promise<{
        verified: boolean;
        reason?: string;
    }>;
    /**
     * Universal scan dispatcher. Detects input type and routes to the
     * right scanner:
     *
     *   nope.scan('some context text')           → scanContext
     *   nope.scan({ name, description })          → scanMCPTool
     *   nope.scan({ code: '...' })                → scanPlugin
     *   nope.scan({ binary: '/path/to/bin' })     → verifyBinary
     */
    scan(input: string): ContextScanResult;
    scan(input: {
        code: string;
    }): PluginScanResult;
    scan(input: {
        binary: string;
    }): Promise<{
        verified: boolean;
        reason?: string;
    }>;
    scan(input: MCPToolDef): PluginScanResult;
    /**
     * Run adversarial tests against NOPE's guardrails.
     * Tests a corpus of known attack vectors + fuzzing variations
     * to find gaps in rule coverage.
     */
    redTeam(config?: RedTeamConfig): Promise<RedTeamResult>;
    private _fuzzPayload;
}
