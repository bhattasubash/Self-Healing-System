// ═════════════════════════════════════════════════════════════════════
// Self-Healing AI SRE Agent — Bi-Temporal Graph Schema Initialization
// ═════════════════════════════════════════════════════════════════════
// Enforces bi-temporal constraints across all infrastructure topology:
//   - Valid-Time Axis: valid_from (state birth), valid_to (state mutation/death)
//   - Transaction-Time Axis: recorded_at (immutable audit write timestamp)
//
// Active state invariant: (valid_to IS NULL OR valid_to > $query_time)
// ═════════════════════════════════════════════════════════════════════

// ─── Constraints ─────────────────────────────────────────────────────

// Unique version identity per entity version
CREATE CONSTRAINT unique_service_version IF NOT EXISTS
FOR (s:Service)
REQUIRE (s.entity_id, s.valid_from) IS UNIQUE;

CREATE CONSTRAINT unique_pod_version IF NOT EXISTS
FOR (p:Pod)
REQUIRE (p.entity_id, p.valid_from) IS UNIQUE;

CREATE CONSTRAINT unique_config_version IF NOT EXISTS
FOR (c:Config)
REQUIRE (c.entity_id, c.valid_from) IS UNIQUE;

CREATE CONSTRAINT unique_node_version IF NOT EXISTS
FOR (n:Node)
REQUIRE (n.entity_id, n.valid_from) IS UNIQUE;

CREATE CONSTRAINT unique_cluster_version IF NOT EXISTS
FOR (cl:Cluster)
REQUIRE (cl.entity_id, cl.valid_from) IS UNIQUE;

CREATE CONSTRAINT unique_incident_id IF NOT EXISTS
FOR (i:Incident)
REQUIRE i.incident_id IS UNIQUE;

// ─── Indexes for Point-in-Time Temporal Queries ───────────────────────

// Composite temporal index on Service entities
CREATE INDEX idx_service_temporal IF NOT EXISTS
FOR (s:Service)
ON (s.entity_id, s.valid_from, s.valid_to);

// Composite temporal index on Pod entities
CREATE INDEX idx_pod_temporal IF NOT EXISTS
FOR (p:Pod)
ON (p.entity_id, p.valid_from, p.valid_to);

// Composite temporal index on Config entities
CREATE INDEX idx_config_temporal IF NOT EXISTS
FOR (c:Config)
ON (c.entity_id, c.valid_from, c.valid_to);

// Composite temporal index on Node entities
CREATE INDEX idx_node_temporal IF NOT EXISTS
FOR (n:Node)
ON (n.entity_id, n.valid_from, n.valid_to);

// Audit transaction-time index for change detection / replication replay
CREATE INDEX idx_recorded_at IF NOT EXISTS
FOR (n:InfrastructureEntity)
ON (n.recorded_at);

// Lookup index for label resolution
CREATE INDEX idx_entity_id IF NOT EXISTS
FOR (n:InfrastructureEntity)
ON (n.entity_id);

// ─── Seed Baseline Infrastructure Topology ───────────────────────────

// Seed a reference Cluster
MERGE (cl:Cluster:InfrastructureEntity {
  entity_id: "MASKED_CLUSTER_prod_us_east_1",
  valid_from: datetime("2026-01-01T00:00:00Z"),
  valid_to: null,
  recorded_at: datetime()
})
ON CREATE SET
  cl.name = "production-us-east-1",
  cl.provider = "aws",
  cl.region = "us-east-1",
  cl.status = "active";

// Seed Kubernetes Node
MERGE (n1:Node:InfrastructureEntity {
  entity_id: "MASKED_NODE_worker_01",
  valid_from: datetime("2026-01-01T00:00:00Z"),
  valid_to: null,
  recorded_at: datetime()
})
ON CREATE SET
  n1.name = "ip-10-0-1-10.ec2.internal",
  n1.instance_type = "m6i.2xlarge",
  n1.status = "Ready";

// Seed Tier-0 Core Payment Gateway Service
MERGE (s1:Service:InfrastructureEntity {
  entity_id: "MASKED_SVC_payment_gateway",
  valid_from: datetime("2026-01-01T00:00:00Z"),
  valid_to: null,
  recorded_at: datetime()
})
ON CREATE SET
  s1.name = "payment-gateway",
  s1.namespace = "payments",
  s1.tier = "tier0",
  s1.status = "healthy",
  s1.version = "v2.14.0";

// Seed Tier-1 Order Processor Service
MERGE (s2:Service:InfrastructureEntity {
  entity_id: "MASKED_SVC_order_processor",
  valid_from: datetime("2026-01-01T00:00:00Z"),
  valid_to: null,
  recorded_at: datetime()
})
ON CREATE SET
  s2.name = "order-processor",
  s2.namespace = "orders",
  s2.tier = "tier1",
  s2.status = "healthy",
  s2.version = "v1.8.2";

// Seed Service Config
MERGE (cfg:Config:InfrastructureEntity {
  entity_id: "MASKED_CFG_payment_db_pool",
  valid_from: datetime("2026-01-01T00:00:00Z"),
  valid_to: null,
  recorded_at: datetime()
})
ON CREATE SET
  cfg.name = "payment-gateway-config",
  cfg.namespace = "payments",
  cfg.pool_size = 50,
  cfg.timeout_ms = 3000,
  cfg.version = "rev-4";

// Seed Relationships with Bi-Temporal Tracking
MERGE (s2)-[r1:DEPENDS_ON {
  valid_from: datetime("2026-01-01T00:00:00Z"),
  valid_to: null,
  recorded_at: datetime()
}]->(s1);

MERGE (s1)-[r2:DEPENDS_ON {
  valid_from: datetime("2026-01-01T00:00:00Z"),
  valid_to: null,
  recorded_at: datetime()
}]->(cfg);

MERGE (n1)-[r3:MANAGED_BY {
  valid_from: datetime("2026-01-01T00:00:00Z"),
  valid_to: null,
  recorded_at: datetime()
}]->(cl);
