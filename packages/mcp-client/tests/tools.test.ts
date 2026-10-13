/**
 * @module tools.test
 * Unit test suite verifying MCP Tool Manifest registration and Zod input schemas.
 */

import { describe, it, expect } from "vitest";
import {
  TOOL_REGISTRY,
  getToolByName,
  getRegisteredToolNames,
} from "../src/tools/registry.js";
import {
  PrometheusQueryInputSchema,
  DatadogQueryInputSchema,
  KubernetesStatusInputSchema,
} from "../src/types/schemas.js";

describe("MCP Tool Manifest & Registry", () => {
  it("should contain all 6 registered tools", () => {
    const names = getRegisteredToolNames();
    expect(names).toEqual([
      "prometheus_query",
      "datadog_query",
      "kubernetes_status",
      "graph_temporal_query",
      "log_search",
      "alert_list",
    ]);
  });

  it("should correctly find tools by name", () => {
    const prom = getToolByName("prometheus_query");
    expect(prom).toBeDefined();
    expect(prom?.name).toBe("prometheus_query");
    expect(prom?.description).toContain("PromQL");
  });

  it("should validate valid Prometheus queries", () => {
    const valid = {
      query: "rate(http_requests_total[5m])",
      start: new Date().toISOString(),
      end: new Date().toISOString(),
      step: "30s",
    };
    const parsed = PrometheusQueryInputSchema.safeParse(valid);
    expect(parsed.success).toBe(true);
  });

  it("should reject invalid Prometheus queries missing required fields", () => {
    const invalid = {
      query: "up",
      // start and end missing
    };
    const parsed = PrometheusQueryInputSchema.safeParse(invalid);
    expect(parsed.success).toBe(false);
  });

  it("should validate Kubernetes status input kinds", () => {
    const validPod = {
      resource_type: "pod",
      namespace: "kube-system",
    };
    expect(KubernetesStatusInputSchema.safeParse(validPod).success).toBe(true);

    const invalidKind = {
      resource_type: "ingress_controller", // Not in enum
    };
    expect(KubernetesStatusInputSchema.safeParse(invalidKind).success).toBe(false);
  });
});
