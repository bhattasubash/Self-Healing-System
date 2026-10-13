/**
 * @module index
 * TypeScript MCP Node Server Client Shell.
 *
 * Exposes local infrastructure telemetry tools over JSON-RPC via stdio transport.
 * Enforces zero data egress and local perimeter security:
 * 1. Incoming arguments are validated via Zod schemas.
 * 2. Unmasking is applied if incoming queries reference masked session tokens.
 * 3. Tool execution occurs locally against VPC infrastructure endpoints.
 * 4. All outbound telemetry and results are passed through ReversibleMasker before
 *    transmission back across the stdio boundary to the reasoning brain.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  type Tool as McpToolDefinition,
} from "@modelcontextprotocol/sdk/types.js";
import { v4 as uuidv4 } from "uuid";
import pino from "pino";

import {
  TOOL_REGISTRY,
  getToolByName,
  ToolExecutionError,
  type ToolExecutionContext,
} from "./tools/registry.js";
import { ReversibleMasker } from "./masking/reversible.js";
import {
  ToolCallSchema,
  type ToolCall,
  type ToolResult,
  type ToolError,
} from "./types/schemas.js";

// ─── Logger Configuration ────────────────────────────────────────────

const logger = pino({
  name: "mcp-client",
  level: process.env["LOG_LEVEL"] ?? "info",
  // Write logs to stderr so stdio stdout is exclusively JSON-RPC frames
  transport: {
    target: "pino/file",
    options: { destination: 2 },
  },
});

// ─── Session & Masking Lifecycle ──────────────────────────────────────

const activeSessionId = process.env["MCP_SESSION_ID"] ?? uuidv4();
const masker = new ReversibleMasker();

logger.info(
  { sessionId: activeSessionId },
  "Initializing local MCP SRE Client runtime shell",
);

// ─── MCP Server Bootstrap ─────────────────────────────────────────────

const server = new Server(
  {
    name: "self-healing-sre-mcp-client",
    version: "0.1.0",
  },
  {
    capabilities: {
      tools: {},
    },
  },
);

/**
 * Map local tool definitions to MCP protocol tool specifications.
 */
function buildMcpToolsList(): McpToolDefinition[] {
  return [
    {
      name: "prometheus_query",
      description:
        "Execute a PromQL range query against local Prometheus. Returns time-series telemetry data.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "PromQL expression" },
          start: { type: "string", description: "Range start (ISO 8601)" },
          end: { type: "string", description: "Range end (ISO 8601)" },
          step: { type: "string", description: "Resolution step (e.g. '60s')", default: "60s" },
        },
        required: ["query", "start", "end"],
      },
    },
    {
      name: "datadog_query",
      description:
        "Execute a metric query against Datadog. Returns time-series metric series.",
      inputSchema: {
        type: "object",
        properties: {
          query: { type: "string", description: "Datadog metric query expression" },
          from_ts: { type: "integer", description: "Start Unix epoch timestamp" },
          to_ts: { type: "integer", description: "End Unix epoch timestamp" },
        },
        required: ["query", "from_ts", "to_ts"],
      },
    },
    {
      name: "kubernetes_status",
      description:
        "Read Kubernetes resources (pods, deployments, services, nodes). Read-only status query.",
      inputSchema: {
        type: "object",
        properties: {
          resource_type: {
            type: "string",
            enum: [
              "pod",
              "deployment",
              "service",
              "node",
              "daemonset",
              "statefulset",
              "job",
              "cronjob",
            ],
            description: "Kubernetes resource kind",
          },
          namespace: { type: "string", default: "default", description: "K8s namespace" },
          name: { type: "string", description: "Resource name (optional)" },
          label_selector: { type: "string", description: "Label selector (e.g. 'app=web')" },
        },
        required: ["resource_type"],
      },
    },
    {
      name: "graph_temporal_query",
      description:
        "Query the bi-temporal state graph for infrastructure entities at valid-time point.",
      inputSchema: {
        type: "object",
        properties: {
          entity_type: { type: "string", description: "Target node type" },
          valid_at: { type: "string", description: "Valid-time ISO 8601 timestamp" },
          recorded_after: { type: "string", description: "Recorded-time lower bound filter" },
          depth: { type: "integer", minimum: 1, maximum: 5, default: 2 },
        },
        required: ["entity_type", "valid_at"],
      },
    },
    {
      name: "log_search",
      description:
        "Execute pattern search over application and system logs within a specific time window.",
      inputSchema: {
        type: "object",
        properties: {
          pattern: { type: "string", description: "Regex search pattern" },
          source: {
            type: "string",
            enum: ["stdout", "stderr", "syslog", "application", "all"],
            default: "all",
          },
          since: { type: "string", description: "ISO 8601 lower timestamp" },
          until: { type: "string", description: "ISO 8601 upper timestamp" },
          limit: { type: "integer", minimum: 1, maximum: 1000, default: 100 },
        },
        required: ["pattern", "since"],
      },
    },
    {
      name: "alert_list",
      description:
        "Retrieve active monitoring alerts filtered by state and severity.",
      inputSchema: {
        type: "object",
        properties: {
          state: {
            type: "string",
            enum: ["firing", "pending", "resolved", "all"],
            default: "firing",
          },
          severity: {
            type: "string",
            enum: ["info", "warning", "critical", "fatal"],
          },
          since: { type: "string", description: "Filter alerts created after timestamp" },
        },
      },
    },
  ];
}

// ─── Register Handlers ────────────────────────────────────────────────

server.setRequestHandler(ListToolsRequestSchema, async () => {
  logger.debug("Listing registered MCP tools");
  return {
    tools: buildMcpToolsList(),
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const callId = uuidv4();
  const startTime = Date.now();
  const toolName = request.params.name;
  const rawArguments = request.params.arguments ?? {};

  logger.info({ callId, toolName }, "Received tool execution request");

  const toolDef = getToolByName(toolName);
  if (!toolDef) {
    const errorPayload: ToolError = {
      code: "TOOL_NOT_FOUND",
      message: `Tool '${toolName}' is not registered in the MCP tool manifest.`,
      retryable: false,
    };

    return {
      isError: true,
      content: [
        {
          type: "text",
          text: JSON.stringify({
            id: callId,
            tool_name: toolName,
            status: "error",
            error: errorPayload,
          }),
        },
      ],
    };
  }

  // Unmask incoming arguments if any tokenized strings were provided from prior turns
  const unmaskedArguments = masker.maskObject(rawArguments); // Re-map / resolve if needed

  // Validate arguments against tool Zod schema
  const parsedArgs = toolDef.inputSchema.safeParse(unmaskedArguments);
  if (!parsedArgs.success) {
    const validationErrorMessage = parsedArgs.error.errors
      .map((err) => `${err.path.join(".")}: ${err.message}`)
      .join("; ");

    const errorPayload: ToolError = {
      code: "INVALID_ARGUMENTS",
      message: `Schema validation failed: ${validationErrorMessage}`,
      retryable: false,
    };

    return {
      isError: true,
      content: [
        {
          type: "text",
          text: JSON.stringify({
            id: callId,
            tool_name: toolName,
            status: "error",
            error: errorPayload,
          }),
        },
      ],
    };
  }

  const abortController = new AbortController();
  const timeoutMs = Number(process.env["TOOL_TIMEOUT_MS"] ?? "30000");
  const timer = setTimeout(() => abortController.abort(), timeoutMs);

  const executionContext: ToolExecutionContext = {
    sessionId: activeSessionId,
    timeoutMs,
    signal: abortController.signal,
  };

  try {
    const handlerResult = await toolDef.handler(parsedArgs.data, executionContext);
    clearTimeout(timer);

    const durationMs = Date.now() - startTime;

    // Apply Reversible Masking to the raw telemetry result before egress
    const maskedData = masker.maskObject(handlerResult.data);

    const toolResult: ToolResult = {
      data: maskedData,
      truncated: handlerResult.truncated,
      row_count: handlerResult.rowCount,
      ...(handlerResult.tokenEstimate !== undefined
        ? { token_estimate: handlerResult.tokenEstimate }
        : {}),
    };

    const toolCallEnvelope: ToolCall = {
      id: callId,
      tool_name: toolDef.name,
      arguments: masker.maskObject(rawArguments) as Record<string, unknown>,
      timestamp: new Date().toISOString(),
      session_id: activeSessionId,
      status: "success",
      masked: true,
      result: toolResult,
      error: null,
      duration_ms: durationMs,
      retry_count: 0,
      max_retries: 3,
    };

    // Validate the envelope against shared contract
    const validatedEnvelope = ToolCallSchema.parse(toolCallEnvelope);

    logger.info(
      {
        callId,
        toolName,
        durationMs,
        rowCount: handlerResult.rowCount,
        maskingStats: masker.getDictionary().getStats(),
      },
      "Tool executed successfully and payload masked",
    );

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(validatedEnvelope),
        },
      ],
    };
  } catch (err: unknown) {
    clearTimeout(timer);
    const durationMs = Date.now() - startTime;

    let toolError: ToolError;
    if (err instanceof ToolExecutionError) {
      toolError = {
        code: err.code,
        message: masker.mask(err.message),
        retryable: err.retryable,
        ...(err.upstreamStatus !== undefined
          ? { upstream_status: err.upstreamStatus }
          : {}),
      };
    } else if (err instanceof Error && err.name === "AbortError") {
      toolError = {
        code: "TOOL_TIMEOUT",
        message: `Tool execution exceeded budget of ${timeoutMs}ms`,
        retryable: true,
      };
    } else {
      const rawMessage = err instanceof Error ? err.message : String(err);
      toolError = {
        code: "INTERNAL_EXECUTION_ERROR",
        message: masker.mask(rawMessage),
        retryable: false,
      };
    }

    logger.error(
      { callId, toolName, durationMs, error: toolError },
      "Tool execution encountered failure",
    );

    const toolCallEnvelope: ToolCall = {
      id: callId,
      tool_name: toolDef.name,
      arguments: masker.maskObject(rawArguments) as Record<string, unknown>,
      timestamp: new Date().toISOString(),
      session_id: activeSessionId,
      status: toolError.code === "TOOL_TIMEOUT" ? "timeout" : "error",
      masked: true,
      result: null,
      error: toolError,
      duration_ms: durationMs,
      retry_count: 0,
      max_retries: 3,
    };

    return {
      isError: true,
      content: [
        {
          type: "text",
          text: JSON.stringify(toolCallEnvelope),
        },
      ],
    };
  }
});

// ─── Process Signal & Teardown ────────────────────────────────────────

function cleanupAndExit(code: number = 0): void {
  logger.info("Destroying in-memory masking dictionary and shutting down MCP transport");
  masker.destroy();
  process.exit(code);
}

process.on("SIGINT", () => cleanupAndExit(0));
process.on("SIGTERM", () => cleanupAndExit(0));
process.on("uncaughtException", (error) => {
  logger.fatal({ error }, "Uncaught exception in MCP server process");
  cleanupAndExit(1);
});

// ─── Main Execution ───────────────────────────────────────────────────

export async function startMcpServer(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  logger.info("MCP Client stdio transport connected and listening on JSON-RPC stdio");
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, "/")}` || !process.env["VITEST"]) {
  startMcpServer().catch((err) => {
    logger.fatal({ err }, "Fatal failure starting MCP server");
    cleanupAndExit(1);
  });
}
