/**
 * @module reversible
 * Reversible Identifier Masking (opensre pattern).
 *
 * All infrastructure identifiers (IPs, hostnames, cluster IDs, container IDs,
 * Kubernetes namespaces, file paths) are tokenized before any data crosses a
 * process boundary. The token ↔ original mapping lives exclusively in memory,
 * scoped to a single session, and is destroyed on disconnect.
 *
 * SECURITY INVARIANTS:
 * - The dictionary is NEVER serialized to disk or transmitted over the network.
 * - Tokens are deterministic within a session (same input → same token) for
 *   correlation consistency, but unpredictable across sessions.
 * - The mask/unmask cycle is fully reversible: unmask(mask(x)) === x.
 */

import { randomBytes } from "node:crypto";

// ─── Types ───────────────────────────────────────────────────────────

export type MaskCategory =
  | "ipv4"
  | "ipv6"
  | "hostname"
  | "cluster_id"
  | "container_id"
  | "namespace"
  | "filepath"
  | "arn";

export interface MaskEntry {
  readonly original: string;
  readonly token: string;
  readonly category: MaskCategory;
  readonly createdAt: Date;
}

export interface MaskingStats {
  totalMasked: number;
  byCategory: Record<MaskCategory, number>;
  dictionarySize: number;
}

// ─── Detection Patterns ──────────────────────────────────────────────
// Each pattern is designed to match infrastructure identifiers that must
// be masked before data leaves the client VPC.

const DETECTION_PATTERNS: ReadonlyArray<{
  category: MaskCategory;
  pattern: RegExp;
  priority: number;
}> = [
  {
    category: "ipv4",
    pattern: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    priority: 10,
  },
  {
    category: "ipv6",
    pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
    priority: 10,
  },
  {
    category: "arn",
    pattern: /\barn:aws:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[a-zA-Z0-9/_+=.@:-]+\b/g,
    priority: 20,
  },
  {
    category: "cluster_id",
    pattern: /\b(?:gke_|eks_|aks_)[a-zA-Z0-9_-]{4,128}\b/g,
    priority: 30,
  },
  {
    category: "container_id",
    pattern: /\b[a-f0-9]{64}\b/g,
    priority: 40,
  },
  {
    category: "hostname",
    pattern:
      /\b[a-zA-Z][a-zA-Z0-9-]*(?:\.[a-zA-Z][a-zA-Z0-9-]*){2,}\b/g,
    priority: 50,
  },
  {
    category: "filepath",
    pattern: /(?:\/[a-zA-Z0-9._-]+){3,}/g,
    priority: 60,
  },
  {
    category: "namespace",
    pattern:
      /\b(?:kube-system|kube-public|kube-node-lease|istio-system|monitoring|logging)\b/g,
    priority: 70,
  },
];

// ─── Category Prefixes ───────────────────────────────────────────────

const CATEGORY_PREFIX: Readonly<Record<MaskCategory, string>> = {
  ipv4: "MASKED_IP4",
  ipv6: "MASKED_IP6",
  hostname: "MASKED_HOST",
  cluster_id: "MASKED_CLUSTER",
  container_id: "MASKED_CTR",
  namespace: "MASKED_NS",
  filepath: "MASKED_PATH",
  arn: "MASKED_ARN",
};

// ─── Masking Dictionary ──────────────────────────────────────────────

export class MaskingDictionary {
  private readonly originalToToken = new Map<string, MaskEntry>();
  private readonly tokenToOriginal = new Map<string, MaskEntry>();
  private readonly sessionSalt: string;
  private readonly prefix: string;

  constructor(prefix: string = "MASKED_") {
    this.sessionSalt = randomBytes(16).toString("hex");
    this.prefix = prefix;
  }

  /**
   * Get or create a masked token for a given original value.
   * Deterministic within a session: same input always returns the same token.
   */
  getOrCreateToken(original: string, category: MaskCategory): string {
    const existing = this.originalToToken.get(original);
    if (existing) {
      return existing.token;
    }

    const tokenSuffix = this.generateTokenSuffix(original);
    const token = `${CATEGORY_PREFIX[category]}_${tokenSuffix}`;

    const entry: MaskEntry = {
      original,
      token,
      category,
      createdAt: new Date(),
    };

    this.originalToToken.set(original, entry);
    this.tokenToOriginal.set(token, entry);

    return token;
  }

  /**
   * Reverse a masked token back to its original value.
   * Returns undefined if the token is not in the dictionary.
   */
  resolve(token: string): string | undefined {
    return this.tokenToOriginal.get(token)?.original;
  }

  /**
   * Check if a string is a masked token managed by this dictionary.
   */
  isToken(value: string): boolean {
    return this.tokenToOriginal.has(value);
  }

  /**
   * Return the number of entries in the dictionary.
   */
  get size(): number {
    return this.originalToToken.size;
  }

  /**
   * Get statistics about the current dictionary state.
   */
  getStats(): MaskingStats {
    const byCategory: Record<string, number> = {};
    for (const entry of this.originalToToken.values()) {
      byCategory[entry.category] = (byCategory[entry.category] ?? 0) + 1;
    }
    return {
      totalMasked: this.originalToToken.size,
      byCategory: byCategory as Record<MaskCategory, number>,
      dictionarySize: this.originalToToken.size,
    };
  }

  /**
   * Destroy all mappings. Called on session disconnect.
   * After this, no tokens can be resolved.
   */
  destroy(): void {
    this.originalToToken.clear();
    this.tokenToOriginal.clear();
  }

  /**
   * Generate a short, deterministic-within-session suffix for a value.
   * Uses the session salt so tokens are unpredictable across sessions.
   */
  private generateTokenSuffix(value: string): string {
    let hash = 0x811c9dc5; // FNV-1a offset basis
    const combined = this.sessionSalt + value;
    for (let i = 0; i < combined.length; i++) {
      hash ^= combined.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193); // FNV-1a prime
    }
    const unsigned = hash >>> 0;
    return unsigned.toString(16).padStart(8, "0");
  }
}

// ─── Reversible Masker ───────────────────────────────────────────────

export class ReversibleMasker {
  private readonly dictionary: MaskingDictionary;
  private readonly patterns: ReadonlyArray<{
    category: MaskCategory;
    pattern: RegExp;
    priority: number;
  }>;

  constructor(dictionary?: MaskingDictionary) {
    this.dictionary = dictionary ?? new MaskingDictionary();
    this.patterns = [...DETECTION_PATTERNS].sort(
      (a, b) => a.priority - b.priority,
    );
  }

  /**
   * Mask all detectable infrastructure identifiers in a string.
   * Applies patterns in priority order (lower priority number first)
   * to handle overlapping matches correctly.
   */
  mask(input: string): string {
    let result = input;

    for (const { category, pattern } of this.patterns) {
      const freshPattern = new RegExp(pattern.source, pattern.flags);
      result = result.replace(freshPattern, (match: string) => {
        return this.dictionary.getOrCreateToken(match, category);
      });
    }

    return result;
  }

  /**
   * Unmask all tokens in a string back to their original values.
   * Scans for all known token prefixes and replaces them.
   */
  unmask(input: string): string {
    let result = input;

    const tokenPattern = new RegExp(
      `(?:${Object.values(CATEGORY_PREFIX).join("|")})_[0-9a-f]{8}`,
      "g",
    );

    result = result.replace(tokenPattern, (match: string) => {
      return this.dictionary.resolve(match) ?? match;
    });

    return result;
  }

  /**
   * Mask all string values in a key-value label map.
   * Keys are preserved (metric label names are not sensitive).
   */
  maskLabels(labels: Record<string, string>): Record<string, string> {
    const masked: Record<string, string> = {};
    for (const [key, value] of Object.entries(labels)) {
      masked[key] = this.mask(value);
    }
    return masked;
  }

  /**
   * Unmask all string values in a key-value label map.
   */
  unmaskLabels(labels: Record<string, string>): Record<string, string> {
    const unmasked: Record<string, string> = {};
    for (const [key, value] of Object.entries(labels)) {
      unmasked[key] = this.unmask(value);
    }
    return unmasked;
  }

  /**
   * Mask all detectable identifiers in an arbitrary JSON-serializable object.
   * Recursively walks the structure and masks string values.
   */
  maskObject<T>(obj: T): T {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj === "string") {
      return this.mask(obj) as T;
    }

    if (Array.isArray(obj)) {
      return obj.map((item: unknown) => this.maskObject(item)) as T;
    }

    if (typeof obj === "object") {
      const result: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
        result[key] = this.maskObject(value);
      }
      return result as T;
    }

    return obj;
  }

  /**
   * Get the underlying dictionary for stats or lifecycle management.
   */
  getDictionary(): MaskingDictionary {
    return this.dictionary;
  }

  /**
   * Destroy the masking session. After this call, no tokens can be reversed.
   */
  destroy(): void {
    this.dictionary.destroy();
  }
}
