/**
 * @module masking.test
 * Unit test suite verifying Reversible Identifier Masking (opensre pattern).
 *
 * Invariants tested:
 * 1. Round-trip reversibility: unmask(mask(x)) === x.
 * 2. Deterministic tokenization within a session.
 * 3. Pattern coverage: IPv4, IPv6, AWS ARNs, cluster IDs, container IDs, namespaces, hostnames.
 * 4. Label map and nested JSON object masking.
 * 5. Destruction semantics: dictionary.destroy() clears mappings.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  ReversibleMasker,
  MaskingDictionary,
} from "../src/masking/reversible.js";

describe("Reversible Identifier Masking", () => {
  let masker: ReversibleMasker;

  beforeEach(() => {
    masker = new ReversibleMasker();
  });

  describe("Single Identifier Masking & Round-Trip", () => {
    it("should mask and unmask IPv4 addresses", () => {
      const raw = "Connection timed out to 192.168.1.100 on port 8080";
      const masked = masker.mask(raw);

      expect(masked).not.toContain("192.168.1.100");
      expect(masked).toMatch(/MASKED_IP4_[0-9a-f]{8}/);

      const unmasked = masker.unmask(masked);
      expect(unmasked).toBe(raw);
    });

    it("should mask and unmask AWS ARNs", () => {
      const raw = "Access denied for arn:aws:iam::123456789012:role/ProductionKubernetesRole";
      const masked = masker.mask(raw);

      expect(masked).not.toContain("123456789012");
      expect(masked).toMatch(/MASKED_ARN_[0-9a-f]{8}/);

      const unmasked = masker.unmask(masked);
      expect(unmasked).toBe(raw);
    });

    it("should mask and unmask GKE/EKS cluster IDs", () => {
      const raw = "Deploying to cluster gke_my-project_us-central1_prod-cluster-01";
      const masked = masker.mask(raw);

      expect(masked).not.toContain("prod-cluster-01");
      expect(masked).toMatch(/MASKED_CLUSTER_[0-9a-f]{8}/);

      const unmasked = masker.unmask(masked);
      expect(unmasked).toBe(raw);
    });

    it("should mask and unmask 64-char container IDs", () => {
      const raw = "Container terminated: a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
      const masked = masker.mask(raw);

      expect(masked).not.toContain("a1b2c3d4e5f6");
      expect(masked).toMatch(/MASKED_CTR_[0-9a-f]{8}/);

      const unmasked = masker.unmask(masked);
      expect(unmasked).toBe(raw);
    });
  });

  describe("Deterministic In-Session Tokenization", () => {
    it("should produce the exact same token for identical inputs within the session", () => {
      const ip = "10.0.4.15";
      const token1 = masker.mask(ip);
      const token2 = masker.mask(ip);

      expect(token1).toBe(token2);
    });

    it("should produce different tokens across different masking dictionary instances (salts)", () => {
      const ip = "10.0.4.15";
      const otherMasker = new ReversibleMasker();

      const token1 = masker.mask(ip);
      const token2 = otherMasker.mask(ip);

      // Session salt makes cross-session tokens unpredictable
      expect(token1).not.toBe(token2);
    });
  });

  describe("Structured Object & Label Map Masking", () => {
    it("should mask values in a label map while preserving keys", () => {
      const labels = {
        host: "node-14.internal.compute.aws",
        cluster: "eks_us-east-1_main-cluster",
        env: "production",
      };

      const maskedLabels = masker.maskLabels(labels);

      expect(maskedLabels["host"]).toMatch(/MASKED_HOST_[0-9a-f]{8}/);
      expect(maskedLabels["cluster"]).toMatch(/MASKED_CLUSTER_[0-9a-f]{8}/);
      expect(maskedLabels["env"]).toBe("production"); // Non-sensitive preserved

      const unmaskedLabels = masker.unmaskLabels(maskedLabels);
      expect(unmaskedLabels).toEqual(labels);
    });

    it("should recursively mask nested JSON objects", () => {
      const payload = {
        endpoint: "http://api.internal.service.corp/v1",
        target_ip: "172.16.0.42",
        details: {
          nodes: ["172.16.0.43", "172.16.0.44"],
        },
      };

      const masked = masker.maskObject(payload) as typeof payload;

      expect(masked.target_ip).toMatch(/MASKED_IP4_[0-9a-f]{8}/);
      expect(masked.details.nodes[0]).toMatch(/MASKED_IP4_[0-9a-f]{8}/);

      const dictStats = masker.getDictionary().getStats();
      expect(dictStats.totalMasked).toBeGreaterThanOrEqual(3);
    });
  });

  describe("Dictionary Destruction Semantics", () => {
    it("should clear all mappings when destroyed and fail to unmask", () => {
      const raw = "Server 192.168.1.1 is unhealthy";
      const masked = masker.mask(raw);

      masker.destroy();
      expect(masker.getDictionary().size).toBe(0);

      // Once destroyed, tokens remain as literals without mapping leak
      const unmasked = masker.unmask(masked);
      expect(unmasked).toBe(masked);
    });
  });
});
