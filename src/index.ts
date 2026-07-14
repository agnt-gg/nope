// ============================================================
// @agnt-gg/nope — Neutralize Operations Prior to Execution
//
//   import { NOPE } from '@agnt-gg/nope';
//   const nope = new NOPE();
//   const safe = nope.wrap(tools);
// ============================================================

// Facade
export { NOPE, NopeSandboxError } from './NOPE.js';
export type { NopeSandboxErrorCode } from './NOPE.js';

// Built-in rules
export { BUILTIN_RULES } from './rules.js';

// Types
export type {
  // Core
  Param,
  Tool,
  Severity,
  Action,
  Rule,
  RuleInfo,
  Violation,
  CheckResult,
  Mode,
  PresetName,
  NopeConfig,
  OutputPattern,
  SanitizeMode,
  Redaction,
  ApprovalVerdict,
  ScannerResult,
  // Prompt injection detection
  ContextFinding,
  ContextFindingType,
  ContextScanResult,
  // DNS-aware SSRF
  SSRFConfig,
  SSRFCheckResult,
  // Sandbox
  SandboxConfig,
  SandboxErrorCode,
  SandboxResult,
  Sandbox,
  // Identity-aware security
  RoleConfig,
  IdentityConfig,
  SecurityContext,
  VerifiedIdentity,
  // Authentication
  AuthConfig,
  RateLimitConfig,
  ApprovalChoice,
  ApprovalMemoryConfig,
  // Built-in scanners
  ScannersConfig,
  BinaryChecksums,
  // Plugin / MCP scanner
  PluginFinding,
  PluginFindingType,
  PluginScanResult,
  MCPToolDef,
  // Telemetry
  TelemetryConfig,
  TelemetryEvent,
  SecurityReport,
  // Red team
  AttackCategory,
  RedTeamConfig,
  RedTeamResult,
  RedTeamVulnerability,
} from './types.js';
