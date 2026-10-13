"""
Bi-Temporal Structural State Graph Service (Neo4j).

Provides temporal graph persistence and point-in-time topology lookups.
Every node and edge enforces bi-temporal dimensions:
  - Valid Time: valid_from (system event occurrence) -> valid_to (superseded/terminated)
  - Transaction Time: recorded_at (immutable write audit timestamp)

Uses explicit, async Neo4j transaction scopes:
  async with session.begin_transaction() as tx:
      ...
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final

import neo4j
from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncManagedTransaction, AsyncTransaction
from pydantic import BaseModel, Field
import structlog

from app.config import Neo4jSettings, Settings, get_settings

logger = structlog.get_logger()

# ─── Pydantic Transfer Models ──────────────────────────────────────────


class TemporalNode(BaseModel):
    """Normalized temporal graph node."""

    entity_id: str
    labels: list[str]
    properties: dict[str, Any]
    valid_from: datetime
    valid_to: datetime | None = None
    recorded_at: datetime


class TemporalRelationship(BaseModel):
    """Normalized temporal relationship connecting two entities."""

    source_id: str
    target_id: str
    type: str
    properties: dict[str, Any] = Field(default_factory=dict)
    valid_from: datetime
    valid_to: datetime | None = None
    recorded_at: datetime


class TemporalSnapshot(BaseModel):
    """Point-in-time structural graph slice."""

    valid_at: datetime
    nodes: list[TemporalNode]
    relationships: list[TemporalRelationship]
    node_count: int
    relationship_count: int


class TemporalEntityDiff(BaseModel):
    """Differences observed for an entity between two points in valid time."""

    entity_id: str
    diff_type: str  # "CREATED", "MUTATED", "TERMINATED"
    t1_properties: dict[str, Any] | None = None
    t2_properties: dict[str, Any] | None = None
    modified_keys: list[str] = Field(default_factory=list)


class TemporalGraphDiff(BaseModel):
    """Comprehensive topology diff between two timestamps (t1 -> t2)."""

    t1: datetime
    t2: datetime
    node_diffs: list[TemporalEntityDiff]
    relationship_changes: list[dict[str, Any]]


# ─── Graph Store Service ───────────────────────────────────────────────


class BiTemporalGraphStore:
    """
    Async Neo4j Bi-Temporal Graph Storage Engine.
    Executes all queries through explicit transaction boundaries.
    """

    DEFAULT_DATABASE: Final = "selfhealing"

    def __init__(
        self,
        driver: AsyncDriver | None = None,
        settings: Neo4jSettings | None = None,
    ) -> None:
        self._settings = settings or get_settings().neo4j
        self._database = self._settings.database or self.DEFAULT_DATABASE

        if driver is not None:
            self._driver = driver
            self._owns_driver = False
        else:
            auth = (
                (self._settings.username, self._settings.password.get_secret_value())
                if self._settings.username
                else None
            )
            self._driver = AsyncGraphDatabase.driver(
                self._settings.uri,
                auth=auth,
            )
            self._owns_driver = True

        self._log = logger.bind(component="graph_store", db=self._database)

    async def close(self) -> None:
        """Close driver connection pool upon shutdown."""
        if self._owns_driver and self._driver:
            await self._driver.close()
            self._log.info("graph_driver_closed")

    # ─── Bi-Temporal Node Operations ───────────────────────────────────

    async def create_entity(
        self,
        label: str,
        entity_id: str,
        properties: dict[str, Any],
        valid_from: datetime | None = None,
    ) -> TemporalNode:
        """
        Insert an initial version of an infrastructure entity.
        Enforces valid_to = NULL (active state) and recorded_at = NOW.
        """
        now = datetime.now(timezone.utc)
        v_from = valid_from or now

        clean_props = {k: v for k, v in properties.items() if not k.startswith("valid_") and k != "recorded_at"}

        cypher = f"""
        CREATE (n:{label}:InfrastructureEntity)
        SET n = $props,
            n.entity_id = $entity_id,
            n.valid_from = datetime($valid_from),
            n.valid_to = null,
            n.recorded_at = datetime($recorded_at)
        RETURN n, labels(n) as node_labels
        """

        async with self._driver.session(database=self._database) as session:
            async with await session.begin_transaction() as tx:
                result = await tx.run(
                    cypher,
                    props=clean_props,
                    entity_id=entity_id,
                    valid_from=v_from.isoformat(),
                    recorded_at=now.isoformat(),
                )
                record = await result.single()
                if not record:
                    raise RuntimeError(f"Failed to create entity {entity_id}")
                await tx.commit()

        node_data = dict(record["n"])
        return self._record_to_node(node_data, record["node_labels"])

    async def supersede_entity(
        self,
        label: str,
        entity_id: str,
        new_properties: dict[str, Any],
        valid_time_cutoff: datetime | None = None,
    ) -> TemporalNode:
        """
        Atomic bi-temporal update:
        1. Close the current active version by setting valid_to = valid_time_cutoff.
        2. Insert the new version node with valid_from = valid_time_cutoff, valid_to = NULL.
        """
        cutoff = valid_time_cutoff or datetime.now(timezone.utc)
        now = datetime.now(timezone.utc)
        clean_props = {k: v for k, v in new_properties.items() if not k.startswith("valid_") and k != "recorded_at"}

        cypher_close = f"""
        MATCH (n:{label} {{entity_id: $entity_id}})
        WHERE n.valid_to IS NULL OR n.valid_to > datetime($cutoff)
        SET n.valid_to = datetime($cutoff),
            n.recorded_at = datetime($now)
        RETURN count(n) as closed_count
        """

        cypher_create = f"""
        CREATE (n:{label}:InfrastructureEntity)
        SET n = $props,
            n.entity_id = $entity_id,
            n.valid_from = datetime($cutoff),
            n.valid_to = null,
            n.recorded_at = datetime($now)
        RETURN n, labels(n) as node_labels
        """

        async with self._driver.session(database=self._database) as session:
            async with await session.begin_transaction() as tx:
                # Step 1: Close active version
                res_close = await tx.run(
                    cypher_close,
                    entity_id=entity_id,
                    cutoff=cutoff.isoformat(),
                    now=now.isoformat(),
                )
                await res_close.consume()

                # Step 2: Create new version
                res_create = await tx.run(
                    cypher_create,
                    props=clean_props,
                    entity_id=entity_id,
                    cutoff=cutoff.isoformat(),
                    now=now.isoformat(),
                )
                record = await res_create.single()
                if not record:
                    await tx.rollback()
                    raise RuntimeError(f"Failed to supersede entity {entity_id}")

                await tx.commit()

        node_data = dict(record["n"])
        self._log.info(
            "entity_superseded",
            entity_id=entity_id,
            cutoff=cutoff.isoformat(),
        )
        return self._record_to_node(node_data, record["node_labels"])

    async def get_entity_at_time(
        self,
        entity_id: str,
        valid_at: datetime | None = None,
    ) -> TemporalNode | None:
        """Look up the exact state of an entity at a given valid-time moment."""
        target_time = valid_at or datetime.now(timezone.utc)

        cypher = """
        MATCH (n:InfrastructureEntity {entity_id: $entity_id})
        WHERE n.valid_from <= datetime($valid_at)
          AND (n.valid_to IS NULL OR n.valid_to > datetime($valid_at))
        RETURN n, labels(n) as node_labels
        LIMIT 1
        """

        async with self._driver.session(database=self._database) as session:
            async with await session.begin_transaction() as tx:
                result = await tx.run(
                    cypher,
                    entity_id=entity_id,
                    valid_at=target_time.isoformat(),
                )
                record = await result.single()
                if not record:
                    return None

        node_data = dict(record["n"])
        return self._record_to_node(node_data, record["node_labels"])

    # ─── Bi-Temporal Relationship Operations ───────────────────────────

    async def link_entities(
        self,
        source_id: str,
        target_id: str,
        rel_type: str,
        properties: dict[str, Any] | None = None,
        valid_from: datetime | None = None,
    ) -> TemporalRelationship:
        """Create a bi-temporal edge between two entities."""
        now = datetime.now(timezone.utc)
        v_from = valid_from or now
        props = properties or {}

        cypher = f"""
        MATCH (src:InfrastructureEntity {{entity_id: $source_id}})
        WHERE src.valid_to IS NULL OR src.valid_to > datetime($valid_from)
        MATCH (tgt:InfrastructureEntity {{entity_id: $target_id}})
        WHERE tgt.valid_to IS NULL OR tgt.valid_to > datetime($valid_from)
        CREATE (src)-[r:{rel_type}]->(tgt)
        SET r = $props,
            r.valid_from = datetime($valid_from),
            r.valid_to = null,
            r.recorded_at = datetime($now)
        RETURN r, type(r) as rel_name
        """

        async with self._driver.session(database=self._database) as session:
            async with await session.begin_transaction() as tx:
                result = await tx.run(
                    cypher,
                    source_id=source_id,
                    target_id=target_id,
                    props=props,
                    valid_from=v_from.isoformat(),
                    now=now.isoformat(),
                )
                record = await result.single()
                if not record:
                    raise RuntimeError(
                        f"Failed to create relationship {source_id} -[{rel_type}]-> {target_id}"
                    )
                await tx.commit()

        rel_data = dict(record["r"])
        return self._record_to_rel(source_id, target_id, rel_data, record["rel_name"])

    # ─── Point-In-Time Topology Snapshots ──────────────────────────────

    async def get_temporal_snapshot(
        self,
        valid_at: datetime | None = None,
        entity_type: str | None = None,
        recorded_after: datetime | None = None,
        depth: int = 2,
    ) -> TemporalSnapshot:
        """
        Extract the complete structural state topology valid at a specific timestamp.
        Only traverses nodes and edges active during the specified temporal moment.
        """
        target_time = valid_at or datetime.now(timezone.utc)
        label_filter = f":{entity_type}" if entity_type else ""

        cypher_nodes = f"""
        MATCH (n{label_filter}:InfrastructureEntity)
        WHERE n.valid_from <= datetime($valid_at)
          AND (n.valid_to IS NULL OR n.valid_to > datetime($valid_at))
          AND ($recorded_after IS NULL OR n.recorded_at >= datetime($recorded_after))
        RETURN n, labels(n) as node_labels
        """

        cypher_rels = """
        MATCH (src:InfrastructureEntity)-[r]->(tgt:InfrastructureEntity)
        WHERE src.valid_from <= datetime($valid_at)
          AND (src.valid_to IS NULL OR src.valid_to > datetime($valid_at))
          AND tgt.valid_from <= datetime($valid_at)
          AND (tgt.valid_to IS NULL OR tgt.valid_to > datetime($valid_at))
          AND r.valid_from <= datetime($valid_at)
          AND (r.valid_to IS NULL OR r.valid_to > datetime($valid_at))
        RETURN src.entity_id as source_id, tgt.entity_id as target_id, r, type(r) as rel_type
        """

        async with self._driver.session(database=self._database) as session:
            async with await session.begin_transaction() as tx:
                # Query nodes
                nodes_res = await tx.run(
                    cypher_nodes,
                    valid_at=target_time.isoformat(),
                    recorded_after=recorded_after.isoformat() if recorded_after else None,
                )
                node_records = await nodes_res.data()

                # Query relationships
                rels_res = await tx.run(
                    cypher_rels,
                    valid_at=target_time.isoformat(),
                )
                rel_records = await rels_res.data()

        nodes: list[TemporalNode] = [
            self._record_to_node(dict(r["n"]), r["node_labels"]) for r in node_records
        ]
        relationships: list[TemporalRelationship] = [
            self._record_to_rel(r["source_id"], r["target_id"], dict(r["r"]), r["rel_type"])
            for r in rel_records
        ]

        return TemporalSnapshot(
            valid_at=target_time,
            nodes=nodes,
            relationships=relationships,
            node_count=len(nodes),
            relationship_count=len(relationships),
        )

    # ─── Bi-Temporal State Diff Engine ─────────────────────────────────

    async def diff_snapshots(
        self,
        t1: datetime,
        t2: datetime,
    ) -> TemporalGraphDiff:
        """
        Detects structural mutations between two points in time (t1 -> t2).
        Crucial for root cause discovery (e.g., identifying config drift or deployment
        mutations that immediately preceded an incident alert).
        """
        snap1 = await self.get_temporal_snapshot(valid_at=t1)
        snap2 = await self.get_temporal_snapshot(valid_at=t2)

        s1_map = {n.entity_id: n for n in snap1.nodes}
        s2_map = {n.entity_id: n for n in snap2.nodes}

        node_diffs: list[TemporalEntityDiff] = []

        # Find Created or Mutated entities
        for entity_id, n2 in s2_map.items():
            if entity_id not in s1_map:
                node_diffs.append(
                    TemporalEntityDiff(
                        entity_id=entity_id,
                        diff_type="CREATED",
                        t1_properties=None,
                        t2_properties=n2.properties,
                    )
                )
            else:
                n1 = s1_map[entity_id]
                modified = [
                    k for k in set(n1.properties.keys()).union(n2.properties.keys())
                    if n1.properties.get(k) != n2.properties.get(k)
                ]
                if modified:
                    node_diffs.append(
                        TemporalEntityDiff(
                            entity_id=entity_id,
                            diff_type="MUTATED",
                            t1_properties=n1.properties,
                            t2_properties=n2.properties,
                            modified_keys=modified,
                        )
                    )

        # Find Terminated entities
        for entity_id, n1 in s1_map.items():
            if entity_id not in s2_map:
                node_diffs.append(
                    TemporalEntityDiff(
                        entity_id=entity_id,
                        diff_type="TERMINATED",
                        t1_properties=n1.properties,
                        t2_properties=None,
                    )
                )

        # Diff relationships
        r1_set = {(r.source_id, r.target_id, r.type) for r in snap1.relationships}
        r2_set = {(r.source_id, r.target_id, r.type) for r in snap2.relationships}

        rel_changes = []
        for src, tgt, rtype in r2_set - r1_set:
            rel_changes.append({"action": "ADDED", "source_id": src, "target_id": tgt, "type": rtype})
        for src, tgt, rtype in r1_set - r2_set:
            rel_changes.append({"action": "REMOVED", "source_id": src, "target_id": tgt, "type": rtype})

        return TemporalGraphDiff(
            t1=t1,
            t2=t2,
            node_diffs=node_diffs,
            relationship_changes=rel_changes,
        )

    # ─── Record Parsers ────────────────────────────────────────────────

    def _record_to_node(self, data: dict[str, Any], labels: list[str]) -> TemporalNode:
        v_from = self._parse_neo4j_dt(data.get("valid_from"))
        v_to = self._parse_neo4j_dt(data.get("valid_to")) if data.get("valid_to") else None
        rec_at = self._parse_neo4j_dt(data.get("recorded_at")) or datetime.now(timezone.utc)

        props = {
            k: v for k, v in data.items()
            if not k.startswith("valid_") and k not in ("recorded_at", "entity_id")
        }

        return TemporalNode(
            entity_id=data.get("entity_id", "UNKNOWN"),
            labels=[l for l in labels if l != "InfrastructureEntity"],
            properties=props,
            valid_from=v_from or datetime.now(timezone.utc),
            valid_to=v_to,
            recorded_at=rec_at,
        )

    def _record_to_rel(
        self, source_id: str, target_id: str, data: dict[str, Any], rel_type: str
    ) -> TemporalRelationship:
        v_from = self._parse_neo4j_dt(data.get("valid_from"))
        v_to = self._parse_neo4j_dt(data.get("valid_to")) if data.get("valid_to") else None
        rec_at = self._parse_neo4j_dt(data.get("recorded_at")) or datetime.now(timezone.utc)

        props = {
            k: v for k, v in data.items()
            if not k.startswith("valid_") and k != "recorded_at"
        }

        return TemporalRelationship(
            source_id=source_id,
            target_id=target_id,
            type=rel_type,
            properties=props,
            valid_from=v_from or datetime.now(timezone.utc),
            valid_to=v_to,
            recorded_at=rec_at,
        )

    @staticmethod
    def _parse_neo4j_dt(val: Any) -> datetime | None:
        if val is None:
            return None
        if isinstance(val, datetime):
            return val
        if hasattr(val, "to_native"):
            return val.to_native()
        try:
            return datetime.fromisoformat(str(val))
        except Exception:
            return None
