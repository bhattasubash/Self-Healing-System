/**
 * @module registry
 * Declarative tool registration manifest for the MCP server.
 *
 * Each tool is defined with:
 * - name: Enum from the shared contract
 * - description: Human-readable purpose
 * - inputSchema: Zod schema for parameter validation
 * - handler: Async function that executes the tool query
 *
 * Tool handlers receive UNMASKED parameters (masking is applied at the
 * transport boundary in index.ts) and return raw results which are then
 * masked before being sent to the brain.
 */

import { z } from "zod";
import type { ZodRawShape } from "zod";

import {
  ToolNameSchema,
  PrometheusQueryInputSchema,
  DatadogQueryInputSchema,
  KubernetesStatusInputSchema,
  GraphTemporalQueryInputSchema,
  LogSearchInputSchema,
  AlertListInputSchema,
  type ToolName,
  type ToolResult,
} from "../types/schemas.js";

// ─── Tool Handler Interface ──────────────────────────────────────────

export interface ToolHandlerResult {
  data: unknown;
  truncated: boolean;
  rowCount: number;
  tokenEstimate?: number;
}

export type ToolHandler<TInput = unknown> = (
  input: TInput,
  context: ToolExecutionContext,
) => Promise<ToolHandlerResult>;

export interface ToolExecutionContext {
  sessionId: string;
  timeoutMs: number;
  signal: AbortSignal;
}

// ─── Tool Definition ─────────────────────────────────────────────────

export interface ToolDefinition<TSchema extends ZodRawShape = ZodRawShape> {
  name: ToolName;
  description: string;
  inputSchema: z.ZodObject<TSchema>;
  handler: ToolHandler<z.infer<z.ZodObject<TSchema>>>;
}

// ─── Prometheus Query Handler ────────────────────────────────────────

async function handlePrometheusQuery(
  input: z.infer<typeof PrometheusQueryInputSchema>,
  context: ToolExecutionContext,
): Promise<ToolHandlerResult> {
  const prometheusBaseUrl = process.env["PROMETHEUS_URL"] ?? "http://localhost:9090";
  const url = new URL("/api/v1/query_range", prometheusBaseUrl);
  url.searchParams.set("query", input.query);
  url.searchParams.set("start", input.start);
  url.searchParams.set("end", input.end);
  url.searchParams.set("step", input.step);

  const response = await fetch(url.toString(), {
    method: "GET",
    headers: { Accept: "application/json" },
    signal: context.signal,
  });

  if (!response.ok) {
    throw new ToolExecutionError(
      "PROMETHEUS_QUERY_FAILED",
      `Prometheus returned HTTP ${response.status}: ${response.statusText}`,
      response.status >= 500,
      response.status,
    );
  }

  const body = (await response.json()) as {
    status: string;
    data: { resultType: string; result: unknown[] };
  };

  const results = body.data?.result ?? [];
  return {
    data: body.data,
    truncated: false,
    rowCount: results.length,
  };
}

// ─── Datadog Query Handler ───────────────────────────────────────────

async function handleDatadogQuery(
  input: z.infer<typeof DatadogQueryInputSchema>,
  context: ToolExecutionContext,
): Promise<ToolHandlerResult> {
  const ddApiUrl = process.env["DATADOG_API_URL"] ?? "https://api.datadoghq.com";
  const ddApiKey = process.env["DATADOG_API_KEY"] ?? "";
  const ddAppKey = process.env["DATADOG_APP_KEY"] ?? "";

  const url = new URL("/api/v1/query", ddApiUrl);
  url.searchParams.set("query", input.query);
  url.searchParams.set("from", input.from_ts.toString());
  url.searchParams.set("to", input.to_ts.toString());

  const response = await fetch(url.toString(), {
    method: "GET",
    headers: {
      Accept: "application/json",
      "DD-API-KEY": ddApiKey,
      "DD-APPLICATION-KEY": ddAppKey,
    },
    signal: context.signal,
  });

  if (!response.ok) {
    throw new ToolExecutionError(
      "DATADOG_QUERY_FAILED",
      `Datadog returned HTTP ${response.status}: ${response.statusText}`,
      response.status >= 500,
      response.status,
    );
  }

  const body = (await response.json()) as { series: unknown[] };
  const series = body.series ?? [];
  return {
    data: body,
    truncated: false,
    rowCount: series.length,
  };
}

// ─── Kubernetes Status Handler ───────────────────────────────────────

async function handleKubernetesStatus(
  input: z.infer<typeof KubernetesStatusInputSchema>,
  context: ToolExecutionContext,
): Promise<ToolHandlerResult> {
  const k8sApiUrl = process.env["KUBERNETES_API_URL"] ?? "https://kubernetes.default.svc";
  const k8sToken = process.env["KUBERNETES_TOKEN"] ?? "";

  const resourcePathMap: Record<string, string> = {
    pod: "pods",
    deployment: "deployments",
    service: "services",
    node: "nodes",
    daemonset: "daemonsets",
    statefulset: "statefulsets",
    job: "jobs",
    cronjob: "cronjobs",
  };

  const apiGroup = ["deployment", "daemonset", "statefulset"].includes(input.resource_type)
    ? "apis/apps/v1"
    : ["job", "cronjob"].includes(input.resource_type)
      ? "apis/batch/v1"
      : "api/v1";

  const resourcePath = resourcePathMap[input.resource_type] ?? input.resource_type;
  const namespacePath =
    input.resource_type === "node" ? "" : `/namespaces/${input.namespace}`;

  let urlPath = `${apiGroup}${namespacePath}/${resourcePath}`;
  if (input.name) {
    urlPath += `/${input.name}`;
  }

  const url = new URL(urlPath, k8sApiUrl);
  if (input.label_selector) {
    url.searchParams.set("labelSelector", input.label_selector);
  }

  const response = await fetch(url.toString(), {
    method: "GET",
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${k8sToken}`,
    },
    signal: context.signal,
  });

  if (!response.ok) {
    throw new ToolExecutionError(
      "KUBERNETES_STATUS_FAILED",
      `Kubernetes API returned HTTP ${response.status}: ${response.statusText}`,
      response.status >= 500,
      response.status,
    );
  }

  const body = (await response.json()) as { items?: unknown[] };
  const items = body.items ?? [body];
  return {
    data: body,
    truncated: false,
    rowCount: items.length,
  };
}

// ─── Graph Temporal Query Handler ────────────────────────────────────

async function handleGraphTemporalQuery(
  input: z.infer<typeof GraphTemporalQueryInputSchema>,
  context: ToolExecutionContext,
): Promise<ToolHandlerResult> {
  const brainUrl = process.env["BRAIN_URL"] ?? "http://127.0.0.1:8000";
  const url = new URL("/api/v1/graph/temporal", brainUrl);

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      entity_type: input.entity_type,
      valid_at: input.valid_at,
      recorded_after: input.recorded_after,
      depth: input.depth,
    }),
    signal: context.signal,
  });

  if (!response.ok) {
    throw new ToolExecutionError(
      "GRAPH_QUERY_FAILED",
      `Graph temporal query returned HTTP ${response.status}`,
      response.status >= 500,
      response.status,
    );
  }

  const body = (await response.json()) as { nodes: unknown[]; edges: unknown[] };
  return {
    data: body,
    truncated: false,
    rowCount: (body.nodes?.length ?? 0) + (body.edges?.length ?? 0),
  };
}

// ─── Log Search Handler ──────────────────────────────────────────────

async function handleLogSearch(
  input: z.infer<typeof LogSearchInputSchema>,
  context: ToolExecutionContext,
): Promise<ToolHandlerResult> {
  const brainUrl = process.env["BRAIN_URL"] ?? "http://127.0.0.1:8000";
  const url = new URL("/api/v1/logs/search", brainUrl);

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify({
      pattern: input.pattern,
      source: input.source,
      since: input.since,
      until: input.until,
      limit: input.limit,
    }),
    signal: context.signal,
  });

  if (!response.ok) {
    throw new ToolExecutionError(
      "LOG_SEARCH_FAILED",
      `Log search returned HTTP ${response.status}`,
      response.status >= 500,
      response.status,
    );
  }

  const body = (await response.json()) as { entries: unknown[]; total_count: number };
  const entries = body.entries ?? [];
  return {
    data: body,
    truncated: entries.length < (body.total_count ?? 0),
    rowCount: body.total_count ?? entries.length,
  };
}

// ─── Alert List Handler ──────────────────────────────────────────────

async function handleAlertList(
  input: z.infer<typeof AlertListInputSchema>,
  context: ToolExecutionContext,
): Promise<ToolHandlerResult> {
  const prometheusBaseUrl = process.env["PROMETHEUS_URL"] ?? "http://localhost:9090";
  const url = new URL("/api/v1/alerts", prometheusBaseUrl);

  const response = await fetch(url.toString(), {
    method: "GET",
    headers: { Accept: "application/json" },
    signal: context.signal,
  });

  if (!response.ok) {
    throw new ToolExecutionError(
      "ALERT_LIST_FAILED",
      `Alert list returned HTTP ${response.status}`,
      response.status >= 500,
      response.status,
    );
  }

  const body = (await response.json()) as {
    data: { alerts: Array<{ state: string; labels: Record<string, string> }> };
  };

  let alerts = body.data?.alerts ?? [];

  if (input.state !== "all") {
    alerts = alerts.filter(
      (alert: { state: string }) => alert.state === input.state,
    );
  }

  if (input.severity) {
    alerts = alerts.filter(
      (alert: { labels: Record<string, string> }) =>
        alert.labels["severity"] === input.severity,
    );
  }

  return {
    data: { alerts },
    truncated: false,
    rowCount: alerts.length,
  };
}

// ─── Tool Execution Error ────────────────────────────────────────────

export class ToolExecutionError extends Error {
  readonly code: string;
  readonly retryable: boolean;
  readonly upstreamStatus?: number | undefined;

  constructor(
    code: string,
    message: string,
    retryable: boolean,
    upstreamStatus?: number,
  ) {
    super(message);
    this.name = "ToolExecutionError";
    this.code = code;
    this.retryable = retryable;
    if (upstreamStatus !== undefined) {
      this.upstreamStatus = upstreamStatus;
    }
  }
}

// ─── Tool Registry ───────────────────────────────────────────────────

/**
 * Complete tool registry. Each entry binds a tool name (from the shared
 * contract enum) to its Zod input schema and async handler.
 */
export const TOOL_REGISTRY: ReadonlyArray<ToolDefinition> = [
  {
    name: "prometheus_query",
    description:
      "Execute a PromQL range query against the local Prometheus instance. " +
      "Returns time-series data points for the given metric expression and time window.",
    inputSchema: PrometheusQueryInputSchema,
    handler: handlePrometheusQuery as ToolHandler,
  },
  {
    name: "datadog_query",
    description:
      "Execute a metric query against the Datadog API. " +
      "Returns time-series data for the given query expression and time range.",
    inputSchema: DatadogQueryInputSchema,
    handler: handleDatadogQuery as ToolHandler,
  },
  {
    name: "kubernetes_status",
    description:
      "Read the current status of Kubernetes resources (pods, deployments, services, nodes). " +
      "Strictly read-only — no mutations are permitted.",
    inputSchema: KubernetesStatusInputSchema,
    handler: handleKubernetesStatus as ToolHandler,
  },
  {
    name: "graph_temporal_query",
    description:
      "Query the bi-temporal state graph for infrastructure entities at a specific point in time. " +
      "Returns nodes and edges valid at the given timestamp with configurable traversal depth.",
    inputSchema: GraphTemporalQueryInputSchema,
    handler: handleGraphTemporalQuery as ToolHandler,
  },
  {
    name: "log_search",
    description:
      "Search application and system logs using a regex pattern within a time window. " +
      "Returns matching log entries up to the specified limit.",
    inputSchema: LogSearchInputSchema,
    handler: handleLogSearch as ToolHandler,
  },
  {
    name: "alert_list",
    description:
      "List active alerts from the monitoring stack. " +
      "Supports filtering by alert state (firing, pending, resolved) and severity.",
    inputSchema: AlertListInputSchema,
    handler: handleAlertList as ToolHandler,
  },
] as const;

/**
 * Look up a tool definition by name. Returns undefined if the tool is not registered.
 */
export function getToolByName(name: string): ToolDefinition | undefined {
  const parsed = ToolNameSchema.safeParse(name);
  if (!parsed.success) {
    return undefined;
  }
  return TOOL_REGISTRY.find((t) => t.name === parsed.data);
}

/**
 * Get all registered tool names.
 */
export function getRegisteredToolNames(): readonly ToolName[] {
  return TOOL_REGISTRY.map((t) => t.name);
}
