/**
 * @module schemas
 * Zod runtime schemas mirroring shared/contracts/*.schema.json.
 * These are the single source of truth for TypeScript type validation.
 * Every field, enum, and constraint is 1:1 with the JSON Schema contracts.
 */

import { z } from "zod";

// ═════════════════════════════════════════════════════════════════════
// Tool Call Contract — mirrors shared/contracts/tool-call.schema.json
// ═════════════════════════════════════════════════════════════════════

export const ToolNameSchema = z.enum([
  "prometheus_query",
  "datadog_query",
  "kubernetes_status",
  "graph_temporal_query",
  "log_search",
  "alert_list",
]);
export type ToolName = z.infer<typeof ToolNameSchema>;

export const ToolCallStatusSchema = z.enum([
  "pending",
  "running",
  "success",
  "error",
  "timeout",
]);
export type ToolCallStatus = z.infer<typeof ToolCallStatusSchema>;

export const ToolResultSchema = z.object({
  data: z.unknown(),
  truncated: z.boolean(),
  row_count: z.number().int().nonnegative(),
  token_estimate: z.number().int().nonnegative().optional(),
});
export type ToolResult = z.infer<typeof ToolResultSchema>;

export const ToolErrorSchema = z.object({
  code: z.string(),
  message: z.string().max(2000),
  retryable: z.boolean(),
  upstream_status: z.number().int().optional(),
});
export type ToolError = z.infer<typeof ToolErrorSchema>;

export const ToolCallSchema = z.object({
  id: z.string().uuid(),
  tool_name: ToolNameSchema,
  arguments: z.record(z.string(), z.unknown()),
  timestamp: z.string().datetime(),
  session_id: z.string().uuid(),
  status: ToolCallStatusSchema,
  masked: z.boolean(),
  result: ToolResultSchema.nullable().default(null),
  error: ToolErrorSchema.nullable().default(null),
  duration_ms: z.number().int().nonnegative().optional(),
  retry_count: z.number().int().nonnegative().default(0),
  max_retries: z.number().int().nonnegative().default(3),
});
export type ToolCall = z.infer<typeof ToolCallSchema>;

// ═════════════════════════════════════════════════════════════════════
// Telemetry Contract — mirrors shared/contracts/telemetry.schema.json
// ═════════════════════════════════════════════════════════════════════

export const TelemetrySourceSchema = z.enum([
  "prometheus",
  "datadog",
  "kubernetes",
  "cloudwatch",
  "custom",
]);
export type TelemetrySource = z.infer<typeof TelemetrySourceSchema>;

export const SeveritySchema = z.enum(["info", "warning", "critical", "fatal"]);
export type Severity = z.infer<typeof SeveritySchema>;

export const DataPointSchema = z.object({
  timestamp: z.string().datetime(),
  value: z.number(),
  unit: z.string().optional(),
});
export type DataPoint = z.infer<typeof DataPointSchema>;

export const FilterMethodSchema = z.enum(["regex", "pyarrow", "hybrid", "none"]);
export type FilterMethod = z.infer<typeof FilterMethodSchema>;

export const FilterStatsSchema = z.object({
  raw_line_count: z.number().int().nonnegative(),
  filtered_line_count: z.number().int().nonnegative(),
  filter_method: FilterMethodSchema,
  compression_ratio: z.number().min(0).max(1),
  duplicate_lines_removed: z.number().int().nonnegative().optional(),
  token_estimate_before: z.number().int().nonnegative().optional(),
  token_estimate_after: z.number().int().nonnegative().optional(),
});
export type FilterStats = z.infer<typeof FilterStatsSchema>;

export const TelemetryEventSchema = z.object({
  event_id: z.string().uuid(),
  source: TelemetrySourceSchema,
  metric_name: z.string().min(1).max(512),
  data_points: z.array(DataPointSchema).min(1).max(10000),
  labels: z.record(z.string(), z.string()),
  severity: SeveritySchema,
  timestamp: z.string().datetime(),
  session_id: z.string().uuid(),
  masking_applied: z.boolean(),
  filter_stats: FilterStatsSchema,
  trace_id: z.string().max(128).optional(),
  span_id: z.string().max(64).optional(),
  anomaly_score: z.number().min(0).max(1).optional(),
  deduplicated: z.boolean().default(false),
});
export type TelemetryEvent = z.infer<typeof TelemetryEventSchema>;

// ═════════════════════════════════════════════════════════════════════
// Approval Contract — mirrors shared/contracts/approval.schema.json
// ═════════════════════════════════════════════════════════════════════

export const ScriptLanguageSchema = z.enum([
  "bash",
  "python",
  "yaml",
  "terraform",
  "kubectl",
  "helm",
]);
export type ScriptLanguage = z.infer<typeof ScriptLanguageSchema>;

export const FixScriptSchema = z.object({
  language: ScriptLanguageSchema,
  content: z.string().min(1).max(100000),
  checksum: z.string().regex(/^sha256:[a-f0-9]{64}$/),
  blocked_patterns_scanned: z.boolean(),
  blocked_patterns_found: z.array(z.string()).optional(),
  generated_by_state: z.string().optional(),
});
export type FixScript = z.infer<typeof FixScriptSchema>;

export const SandboxStatusSchema = z.enum(["pass", "fail", "timeout", "error"]);
export type SandboxStatus = z.infer<typeof SandboxStatusSchema>;

export const ResourceUsageSchema = z.object({
  cpu_ms: z.number().int().nonnegative().optional(),
  memory_peak_mb: z.number().int().nonnegative().optional(),
  network_egress_bytes: z.number().int().nonnegative().optional(),
});
export type ResourceUsage = z.infer<typeof ResourceUsageSchema>;

export const SandboxResultSchema = z.object({
  sandbox_id: z.string(),
  status: SandboxStatusSchema,
  exit_code: z.number().int(),
  stdout: z.string().max(50000).optional(),
  stderr: z.string().max(50000).optional(),
  duration_ms: z.number().int().nonnegative(),
  started_at: z.string().datetime(),
  finished_at: z.string().datetime(),
  resource_usage: ResourceUsageSchema.optional(),
});
export type SandboxResult = z.infer<typeof SandboxResultSchema>;

export const RiskLevelSchema = z.enum(["low", "medium", "high", "critical"]);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

export const ServiceTierSchema = z.enum(["tier0", "tier1", "tier2", "tier3"]);
export type ServiceTier = z.infer<typeof ServiceTierSchema>;

export const BlastRadiusSchema = z.object({
  affected_services: z.array(z.string()),
  affected_node_count: z.number().int().nonnegative(),
  service_tier: ServiceTierSchema,
  estimated_downtime_seconds: z.number().int().nonnegative().optional(),
});
export type BlastRadius = z.infer<typeof BlastRadiusSchema>;

export const ApprovalDecisionSchema = z.enum([
  "pending",
  "approved",
  "rejected",
  "expired",
]);
export type ApprovalDecision = z.infer<typeof ApprovalDecisionSchema>;

export const ApprovalRequestorSchema = z.enum([
  "state_machine",
  "manual_escalation",
]);
export type ApprovalRequestor = z.infer<typeof ApprovalRequestorSchema>;

export const ApprovalRequestSchema = z.object({
  approval_id: z.string().uuid(),
  incident_id: z.string().uuid(),
  fix_script: FixScriptSchema,
  sandbox_result: SandboxResultSchema,
  worktree_branch: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._/-]*$/).min(1).max(256),
  diff_summary: z.string().max(50000),
  post_mortem_md: z.string().max(100000).optional(),
  requested_by: ApprovalRequestorSchema,
  requested_at: z.string().datetime(),
  decision: ApprovalDecisionSchema,
  decided_by: z.string().max(256).optional(),
  decided_at: z.string().datetime().optional(),
  decision_reason: z.string().max(2000).optional(),
  ttl_seconds: z.number().int().min(60).max(86400).default(3600),
  slack_channel: z.string().max(128).optional(),
  slack_message_ts: z.string().max(64).optional(),
  risk_level: RiskLevelSchema.optional(),
  blast_radius: BlastRadiusSchema.optional(),
});
export type ApprovalRequest = z.infer<typeof ApprovalRequestSchema>;

// ═════════════════════════════════════════════════════════════════════
// Prometheus Tool Input/Output Schemas
// ═════════════════════════════════════════════════════════════════════

export const PrometheusQueryInputSchema = z.object({
  query: z.string().min(1).describe("PromQL expression"),
  start: z.string().datetime().describe("Range start (ISO 8601)"),
  end: z.string().datetime().describe("Range end (ISO 8601)"),
  step: z.string().default("60s").describe("Query resolution step (e.g. '15s', '1m', '5m')"),
});
export type PrometheusQueryInput = z.infer<typeof PrometheusQueryInputSchema>;

export const DatadogQueryInputSchema = z.object({
  query: z.string().min(1).describe("Datadog metric query expression"),
  from_ts: z.number().int().describe("Start Unix timestamp"),
  to_ts: z.number().int().describe("End Unix timestamp"),
});
export type DatadogQueryInput = z.infer<typeof DatadogQueryInputSchema>;

export const KubernetesStatusInputSchema = z.object({
  resource_type: z
    .enum(["pod", "deployment", "service", "node", "daemonset", "statefulset", "job", "cronjob"])
    .describe("Kubernetes resource type"),
  namespace: z.string().default("default").describe("Kubernetes namespace"),
  name: z.string().optional().describe("Specific resource name (omit for all)"),
  label_selector: z.string().optional().describe("Label selector (e.g. 'app=nginx')"),
});
export type KubernetesStatusInput = z.infer<typeof KubernetesStatusInputSchema>;

export const GraphTemporalQueryInputSchema = z.object({
  entity_type: z.string().min(1).describe("Node type in the bi-temporal graph"),
  valid_at: z.string().datetime().describe("Point-in-time for the valid-time axis"),
  recorded_after: z.string().datetime().optional().describe("Only include facts recorded after this time"),
  depth: z.number().int().min(1).max(5).default(2).describe("Graph traversal depth"),
});
export type GraphTemporalQueryInput = z.infer<typeof GraphTemporalQueryInputSchema>;

export const LogSearchInputSchema = z.object({
  pattern: z.string().min(1).describe("Search regex pattern"),
  source: z.enum(["stdout", "stderr", "syslog", "application", "all"]).default("all"),
  since: z.string().datetime().describe("Search logs after this timestamp"),
  until: z.string().datetime().optional().describe("Search logs before this timestamp"),
  limit: z.number().int().min(1).max(1000).default(100).describe("Maximum log entries to return"),
});
export type LogSearchInput = z.infer<typeof LogSearchInputSchema>;

export const AlertListInputSchema = z.object({
  state: z.enum(["firing", "pending", "resolved", "all"]).default("firing"),
  severity: SeveritySchema.optional().describe("Filter by severity"),
  since: z.string().datetime().optional().describe("Alerts created after this timestamp"),
});
export type AlertListInput = z.infer<typeof AlertListInputSchema>;
