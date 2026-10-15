"""
SQLite Bi-Temporal State & Change Timeline Storage Engine (PRD F-04).

Replaces external graph database with a lightweight, relational bi-temporal store
hosted locally on cluster PVC or in-memory for testing.

Maintains two distinct time dimensions:
1. Valid Time (valid_from, valid_to): When an infrastructure state was true in reality.
2. Recorded Time (recorded_at): When the self-healing agent observed/recorded that state.

Core Capabilities:
- state_at(entity_uid, t): Point-in-time state reconstruction.
- diff(t1, t2): Structural and attribute diff between baseline and incident onset.
- changes_before(alert_time, window): Chronological change timeline for root-cause triage.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from pydantic import BaseModel, Field

logger = structlog.get_logger()


# ─── Pydantic Domain Models ───────────────────────────────────────────


class EntityRecord(BaseModel):
    """Cluster object entity tracked across time."""

    uid: str
    kind: str
    namespace: str
    name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ChangeRecord(BaseModel):
    """Bi-temporal infrastructure mutation or lifecycle transition."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_uid: str
    change_type: str
    summary: str
    before_state: dict[str, Any] = Field(default_factory=dict)
    after_state: dict[str, Any] = Field(default_factory=dict)
    valid_from: datetime
    valid_to: datetime | None = None
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source: str = "k8s_collector"
    actor: str = "system"


class ObservationRecord(BaseModel):
    """Health telemetry or probe observation."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    entity_uid: str
    timestamp: datetime
    metric_name: str
    value: float
    status: str = "healthy"


class TemporalEntityDiff(BaseModel):
    """Mutation delta for a single entity between t1 and t2."""

    entity_id: str
    diff_type: str  # "CREATED" | "MUTATED" | "TERMINATED"
    kind: str = ""
    namespace: str = ""
    name: str = ""
    modified_keys: list[str] = Field(default_factory=list)
    before_state: dict[str, Any] = Field(default_factory=dict)
    after_state: dict[str, Any] = Field(default_factory=dict)
    summary: str = ""


class TemporalDiff(BaseModel):
    """Aggregated structural mutation diff across the cluster."""

    t1: datetime
    t2: datetime
    node_diffs: list[TemporalEntityDiff] = Field(default_factory=list)
    total_mutations: int = 0


# Backward compatibility aliases
TemporalGraphDiff = TemporalDiff


# ─── SQLite Bi-Temporal Engine ─────────────────────────────────────────


class TemporalStore:
    """
    SQLite-backed bi-temporal store managing entity histories and change timelines.
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = sqlite3.connect(
            db_path, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._log = logger.bind(component="temporal_store", db_path=db_path)
        self._init_db_sync()

    def _get_connection(self) -> sqlite3.Connection:
        if self._conn is None:
            raise sqlite3.ProgrammingError("Cannot operate on a closed database.")
        return self._conn

    def _init_db_sync(self) -> None:
        """Initializes tables and indices synchronously."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS entities (
                    uid TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS changes (
                    id TEXT PRIMARY KEY,
                    entity_uid TEXT NOT NULL REFERENCES entities(uid),
                    change_type TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    before_state TEXT NOT NULL,
                    after_state TEXT NOT NULL,
                    valid_from TEXT NOT NULL,
                    valid_to TEXT,
                    recorded_at TEXT NOT NULL,
                    source TEXT NOT NULL,
                    actor TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS observations (
                    id TEXT PRIMARY KEY,
                    entity_uid TEXT NOT NULL REFERENCES entities(uid),
                    timestamp TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    value REAL NOT NULL,
                    status TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_changes_entity_valid
                    ON changes (entity_uid, valid_from, valid_to);
                CREATE INDEX IF NOT EXISTS idx_changes_valid_from
                    ON changes (valid_from);
                CREATE INDEX IF NOT EXISTS idx_changes_recorded_at
                    ON changes (recorded_at);
                CREATE INDEX IF NOT EXISTS idx_entities_ns_name
                    ON entities (namespace, name);
                CREATE INDEX IF NOT EXISTS idx_observations_entity_time
                    ON observations (entity_uid, timestamp);
            """)

    # ── 1. Entity Management ──

    async def record_entity(self, entity: EntityRecord) -> None:
        """Registers or updates an entity."""
        await asyncio.to_thread(self._record_entity_sync, entity)

    def _record_entity_sync(self, entity: EntityRecord) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO entities (uid, kind, namespace, name, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(uid) DO UPDATE SET
                    kind = excluded.kind,
                    namespace = excluded.namespace,
                    name = excluded.name;
                """,
                (
                    entity.uid,
                    entity.kind,
                    entity.namespace,
                    entity.name,
                    entity.created_at.isoformat(),
                ),
            )

    async def get_entity(self, entity_uid: str) -> EntityRecord | None:
        """Retrieves entity metadata by UID."""
        return await asyncio.to_thread(self._get_entity_sync, entity_uid)

    def _get_entity_sync(self, entity_uid: str) -> EntityRecord | None:
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT uid, kind, namespace, name, created_at FROM entities WHERE uid = ?",
                (entity_uid,),
            ).fetchone()
            if not row:
                return None
            return EntityRecord(
                uid=row["uid"],
                kind=row["kind"],
                namespace=row["namespace"],
                name=row["name"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )

    async def get_entity_by_name(
        self, namespace: str, name: str, kind: str | None = None
    ) -> EntityRecord | None:
        """Retrieves entity metadata by namespace and name (optional kind filter)."""
        return await asyncio.to_thread(self._get_entity_by_name_sync, namespace, name, kind)

    def _get_entity_by_name_sync(
        self, namespace: str, name: str, kind: str | None = None
    ) -> EntityRecord | None:
        with self._get_connection() as conn:
            if kind:
                query = (
                    "SELECT uid, kind, namespace, name, created_at FROM entities "
                    "WHERE namespace = ? AND name = ? AND kind = ?"
                )
                row = conn.execute(query, (namespace, name, kind)).fetchone()
            else:
                query = (
                    "SELECT uid, kind, namespace, name, created_at FROM entities "
                    "WHERE namespace = ? AND name = ?"
                )
                row = conn.execute(query, (namespace, name)).fetchone()
            if not row:
                return None
            return EntityRecord(
                uid=row["uid"],
                kind=row["kind"],
                namespace=row["namespace"],
                name=row["name"],
                created_at=datetime.fromisoformat(row["created_at"]),
            )

    async def get_changes_for_entity(self, entity_uid: str) -> list[ChangeRecord]:
        """Retrieves all changes recorded for an entity ordered by valid_from."""
        return await asyncio.to_thread(self._get_changes_for_entity_sync, entity_uid)

    def _get_changes_for_entity_sync(self, entity_uid: str) -> list[ChangeRecord]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, entity_uid, change_type, summary, before_state,
                       after_state, valid_from, valid_to, recorded_at, source, actor
                FROM changes
                WHERE entity_uid = ?
                ORDER BY valid_from ASC
                """,
                (entity_uid,),
            ).fetchall()
            return [
                ChangeRecord(
                    id=row["id"],
                    entity_uid=row["entity_uid"],
                    change_type=row["change_type"],
                    summary=row["summary"],
                    before_state=json.loads(row["before_state"]),
                    after_state=json.loads(row["after_state"]),
                    valid_from=datetime.fromisoformat(row["valid_from"]),
                    valid_to=datetime.fromisoformat(row["valid_to"]) if row["valid_to"] else None,
                    recorded_at=datetime.fromisoformat(row["recorded_at"]),
                    source=row["source"],
                    actor=row["actor"],
                )
                for row in rows
            ]

    # ── 2. Change Lifecycle Management ──

    async def record_change(self, change: ChangeRecord) -> None:
        """
        Inserts a bi-temporal change record and automatically adjusts previous valid_to.
        """
        await asyncio.to_thread(self._record_change_sync, change)

    def _record_change_sync(self, change: ChangeRecord) -> None:
        with self._get_connection() as conn:
            # Close any currently open active changes prior to this change's valid_from
            conn.execute(
                """
                UPDATE changes
                SET valid_to = ?
                WHERE entity_uid = ? AND valid_to IS NULL AND valid_from < ?
                """,
                (change.valid_from.isoformat(), change.entity_uid, change.valid_from.isoformat()),
            )

            valid_to_str = change.valid_to.isoformat() if change.valid_to else None
            conn.execute(
                """
                INSERT INTO changes (
                    id, entity_uid, change_type, summary, before_state,
                    after_state, valid_from, valid_to, recorded_at, source, actor
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    change.id,
                    change.entity_uid,
                    change.change_type,
                    change.summary,
                    json.dumps(change.before_state),
                    json.dumps(change.after_state),
                    change.valid_from.isoformat(),
                    valid_to_str,
                    change.recorded_at.isoformat(),
                    change.source,
                    change.actor,
                ),
            )

    # ── 3. Health Observations ──

    async def record_observation(self, obs: ObservationRecord) -> None:
        """Records a metric or status health observation."""
        await asyncio.to_thread(self._record_observation_sync, obs)

    def _record_observation_sync(self, obs: ObservationRecord) -> None:
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO observations (id, entity_uid, timestamp, metric_name, value, status)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    obs.id,
                    obs.entity_uid,
                    obs.timestamp.isoformat(),
                    obs.metric_name,
                    obs.value,
                    obs.status,
                ),
            )

    async def get_observations(self, entity_uid: str, limit: int = 100) -> list[ObservationRecord]:
        """Retrieves recent health observations for an entity."""
        return await asyncio.to_thread(self._get_observations_sync, entity_uid, limit)

    def _get_observations_sync(self, entity_uid: str, limit: int) -> list[ObservationRecord]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, entity_uid, timestamp, metric_name, value, status
                FROM observations
                WHERE entity_uid = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (entity_uid, limit),
            ).fetchall()
            return [
                ObservationRecord(
                    id=row["id"],
                    entity_uid=row["entity_uid"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    metric_name=row["metric_name"],
                    value=row["value"],
                    status=row["status"],
                )
                for row in rows
            ]

    async def get_observations_for_entity(
        self, entity_uid: str, limit: int = 100
    ) -> list[ObservationRecord]:
        """Retrieves recent observations recorded for an entity."""
        return await asyncio.to_thread(self._get_observations_for_entity_sync, entity_uid, limit)

    def _get_observations_for_entity_sync(
        self, entity_uid: str, limit: int = 100
    ) -> list[ObservationRecord]:
        with self._get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, entity_uid, timestamp, metric_name, value, status
                FROM observations
                WHERE entity_uid = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (entity_uid, limit),
            ).fetchall()
            return [
                ObservationRecord(
                    id=row["id"],
                    entity_uid=row["entity_uid"],
                    timestamp=datetime.fromisoformat(row["timestamp"]),
                    metric_name=row["metric_name"],
                    value=row["value"],
                    status=row["status"],
                )
                for row in rows
            ]

    def get_latest_observation_time(self) -> datetime | None:
        """Returns the most recent observation timestamp recorded in the store."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT MAX(timestamp) as latest FROM observations").fetchone()
            if row and row["latest"]:
                try:
                    return datetime.fromisoformat(row["latest"])
                except Exception:
                    return None
            return None

    # ── 4. Bi-Temporal Query: state_at ──

    async def state_at(self, entity_uid: str, t: datetime) -> dict[str, Any] | None:
        """
        Reconstructs the active state of an entity at valid time t.
        Returns None if entity was not yet created or has been terminated.
        """
        return await asyncio.to_thread(self._state_at_sync, entity_uid, t)

    def _state_at_sync(self, entity_uid: str, t: datetime) -> dict[str, Any] | None:
        t_str = t.isoformat()
        with self._get_connection() as conn:
            row = conn.execute(
                """
                SELECT after_state, change_type, valid_to
                FROM changes
                WHERE entity_uid = ?
                  AND valid_from <= ?
                  AND (valid_to > ? OR valid_to IS NULL)
                ORDER BY valid_from DESC
                LIMIT 1
                """,
                (entity_uid, t_str, t_str),
            ).fetchone()

            if not row:
                return None

            # If the change was a deletion or termination, state is None
            if row["change_type"] in ("DELETE", "TERMINATED"):
                return None

            try:
                state = json.loads(row["after_state"])
                return state if isinstance(state, dict) and state else None
            except json.JSONDecodeError:
                return None

    # ── 5. Bi-Temporal Query: diff ──

    async def diff(
        self,
        t1: datetime,
        t2: datetime,
        namespace: str | None = None,
    ) -> TemporalDiff:
        """
        Computes structural mutation diff between valid times t1 and t2.
        Identifies CREATED, MUTATED, and TERMINATED entities.
        """
        return await asyncio.to_thread(self._diff_sync, t1, t2, namespace)

    # Alias for drop-in compatibility with BiTemporalGraphStore interface
    async def diff_snapshots(
        self,
        t1: datetime,
        t2: datetime,
        namespace: str | None = None,
    ) -> TemporalDiff:
        return await self.diff(t1=t1, t2=t2, namespace=namespace)

    def _diff_sync(
        self,
        t1: datetime,
        t2: datetime,
        namespace: str | None = None,
    ) -> TemporalDiff:
        with self._get_connection() as conn:
            if namespace:
                rows = conn.execute(
                    "SELECT uid, kind, namespace, name FROM entities WHERE namespace = ?",
                    (namespace,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT uid, kind, namespace, name FROM entities").fetchall()

            node_diffs: list[TemporalEntityDiff] = []

            for ent in rows:
                uid = ent["uid"]
                state1 = self._state_at_sync(uid, t1)
                state2 = self._state_at_sync(uid, t2)

                if state1 is None and state2 is not None:
                    # Entity introduced between t1 and t2
                    node_diffs.append(
                        TemporalEntityDiff(
                            entity_id=uid,
                            diff_type="CREATED",
                            kind=ent["kind"],
                            namespace=ent["namespace"],
                            name=ent["name"],
                            modified_keys=sorted(state2.keys()),
                            before_state={},
                            after_state=state2,
                            summary=f"Created {ent['kind']} {ent['namespace']}/{ent['name']}",
                        )
                    )
                elif state1 is not None and state2 is None:
                    # Entity deleted between t1 and t2
                    node_diffs.append(
                        TemporalEntityDiff(
                            entity_id=uid,
                            diff_type="TERMINATED",
                            kind=ent["kind"],
                            namespace=ent["namespace"],
                            name=ent["name"],
                            modified_keys=sorted(state1.keys()),
                            before_state=state1,
                            after_state={},
                            summary=f"Terminated {ent['kind']} {ent['namespace']}/{ent['name']}",
                        )
                    )
                elif state1 is not None and state2 is not None:
                    # Check for attribute mutation
                    all_keys = set(state1.keys()) | set(state2.keys())
                    changed_keys = [
                        k for k in all_keys if state1.get(k) != state2.get(k)
                    ]
                    if changed_keys:
                        node_diffs.append(
                            TemporalEntityDiff(
                                entity_id=uid,
                                diff_type="MUTATED",
                                kind=ent["kind"],
                                namespace=ent["namespace"],
                                name=ent["name"],
                                modified_keys=sorted(changed_keys),
                                before_state=state1,
                                after_state=state2,
                                summary=(
                                    f"Mutated {ent['kind']} {ent['namespace']}/{ent['name']} "
                                    f"({', '.join(sorted(changed_keys))})"
                                ),
                            )
                        )

            return TemporalDiff(
                t1=t1,
                t2=t2,
                node_diffs=node_diffs,
                total_mutations=len(node_diffs),
            )

    # ── 6. Diagnostic Timeline: changes_before ──

    async def changes_before(
        self,
        alert_time: datetime,
        window_minutes: int = 60,
        entity_uid: str | None = None,
        namespace: str | None = None,
    ) -> list[ChangeRecord]:
        """
        Retrieves all infrastructure changes within [alert_time - window_minutes, alert_time].
        Answers 'what changed before this alert' ordered by valid_from DESC.
        """
        return await asyncio.to_thread(
            self._changes_before_sync, alert_time, window_minutes, entity_uid, namespace
        )

    def _changes_before_sync(
        self,
        alert_time: datetime,
        window_minutes: int,
        entity_uid: str | None,
        namespace: str | None,
    ) -> list[ChangeRecord]:
        start_time = alert_time - timedelta(minutes=window_minutes)
        t_start = start_time.isoformat()
        t_end = alert_time.isoformat()

        query = """
            SELECT c.id, c.entity_uid, c.change_type, c.summary, c.before_state,
                   c.after_state, c.valid_from, c.valid_to, c.recorded_at, c.source, c.actor
            FROM changes c
            JOIN entities e ON c.entity_uid = e.uid
            WHERE c.valid_from >= ? AND c.valid_from <= ?
        """
        params: list[Any] = [t_start, t_end]

        if entity_uid:
            query += " AND c.entity_uid = ?"
            params.append(entity_uid)
        if namespace:
            query += " AND e.namespace = ?"
            params.append(namespace)

        query += " ORDER BY c.valid_from DESC"

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [
                ChangeRecord(
                    id=row["id"],
                    entity_uid=row["entity_uid"],
                    change_type=row["change_type"],
                    summary=row["summary"],
                    before_state=json.loads(row["before_state"]),
                    after_state=json.loads(row["after_state"]),
                    valid_from=datetime.fromisoformat(row["valid_from"]),
                    valid_to=datetime.fromisoformat(row["valid_to"]) if row["valid_to"] else None,
                    recorded_at=datetime.fromisoformat(row["recorded_at"]),
                    source=row["source"],
                    actor=row["actor"],
                )
                for row in rows
            ]

    def close(self) -> None:
        """Closes the underlying database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __del__(self) -> None:
        if getattr(self, "_conn", None) is not None:
            self.close()

