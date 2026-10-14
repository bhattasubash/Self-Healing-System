"""
Unit tests for the SQLite Bi-Temporal State and Change Timeline Store (PRD F-04).

Verifies:
- Entity registration and bi-temporal change lifecycle.
- state_at(entity, t) at different valid times.
- diff(t1, t2) detecting CREATED, MUTATED, and TERMINATED entities.
- changes_before(alert_time, window) diagnostic query.
- Health observation recording.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from app.services.temporal_store import (
    ChangeRecord,
    EntityRecord,
    ObservationRecord,
    TemporalStore,
)

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def store() -> Generator[TemporalStore, None, None]:
    s = TemporalStore(db_path=":memory:")
    yield s
    s.close()


@pytest.mark.asyncio
async def test_entity_registration_and_retrieval(store: TemporalStore) -> None:
    entity = EntityRecord(
        uid="uid-payment-001",
        kind="Deployment",
        namespace="payments",
        name="payment-gateway",
    )
    await store.record_entity(entity)

    retrieved = await store.get_entity("uid-payment-001")
    assert retrieved is not None
    assert retrieved.uid == "uid-payment-001"
    assert retrieved.name == "payment-gateway"
    assert retrieved.namespace == "payments"


@pytest.mark.asyncio
async def test_bi_temporal_change_lifecycle_and_state_at(store: TemporalStore) -> None:
    entity = EntityRecord(
        uid="uid-payment-001",
        kind="Deployment",
        namespace="payments",
        name="payment-gateway",
    )
    await store.record_entity(entity)

    t0 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=UTC)
    t1 = datetime(2026, 10, 1, 10, 15, 0, tzinfo=UTC)

    # Initial state at 10:00
    await store.record_change(
        ChangeRecord(
            entity_uid="uid-payment-001",
            change_type="IMAGE_DEPLOY",
            summary="Initial deploy v1.0",
            before_state={},
            after_state={"image": "payments:v1.0", "replicas": 3, "timeout_ms": 1000},
            valid_from=t0,
        )
    )

    # Mutation at 10:15
    await store.record_change(
        ChangeRecord(
            entity_uid="uid-payment-001",
            change_type="CONFIG_MUTATION",
            summary="Bad config update: lowered timeout to 50ms",
            before_state={"image": "payments:v1.0", "replicas": 3, "timeout_ms": 1000},
            after_state={"image": "payments:v1.0", "replicas": 3, "timeout_ms": 50},
            valid_from=t1,
        )
    )

    # Query before initial deploy -> None
    state_before = await store.state_at("uid-payment-001", t0 - timedelta(minutes=5))
    assert state_before is None

    # Query at 10:05 (between t0 and t1) -> v1.0 with timeout_ms=1000
    state_mid1 = await store.state_at("uid-payment-001", t0 + timedelta(minutes=5))
    assert state_mid1 is not None
    assert state_mid1["timeout_ms"] == 1000

    # Query at 10:20 (after t1) -> timeout_ms=50
    state_mid2 = await store.state_at("uid-payment-001", t1 + timedelta(minutes=5))
    assert state_mid2 is not None
    assert state_mid2["timeout_ms"] == 50


@pytest.mark.asyncio
async def test_diff_detects_created_mutated_and_terminated(store: TemporalStore) -> None:
    t1 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=UTC)
    t2 = datetime(2026, 10, 1, 11, 0, 0, tzinfo=UTC)

    # 1. Stable entity (exists across t1 and t2 with no change)
    await store.record_entity(
        EntityRecord(uid="e-stable", kind="Service", namespace="payments", name="svc-stable")
    )
    await store.record_change(
        ChangeRecord(
            entity_uid="e-stable",
            change_type="INIT",
            summary="Init stable",
            before_state={},
            after_state={"status": "healthy"},
            valid_from=t1 - timedelta(hours=1),
        )
    )

    # 2. Mutated entity (version modified between t1 and t2)
    await store.record_entity(
        EntityRecord(uid="e-mutated", kind="Deployment", namespace="payments", name="svc-mutated")
    )
    await store.record_change(
        ChangeRecord(
            entity_uid="e-mutated",
            change_type="INIT",
            summary="Init mutated",
            before_state={},
            after_state={"version": "v1.0", "replicas": 3},
            valid_from=t1 - timedelta(hours=1),
        )
    )
    await store.record_change(
        ChangeRecord(
            entity_uid="e-mutated",
            change_type="IMAGE_UPDATE",
            summary="Update to v2.0",
            before_state={"version": "v1.0", "replicas": 3},
            after_state={"version": "v2.0", "replicas": 3},
            valid_from=t1 + timedelta(minutes=30),  # In between t1 and t2
        )
    )

    # 3. Created entity (introduced at t1 + 45m)
    await store.record_entity(
        EntityRecord(
            uid="e-created",
            kind="ConfigMap",
            namespace="payments",
            name="cm-new",
            created_at=t1 + timedelta(minutes=45),
        )
    )
    await store.record_change(
        ChangeRecord(
            entity_uid="e-created",
            change_type="CREATE",
            summary="Created new configmap",
            before_state={},
            after_state={"feature_flag": "enabled"},
            valid_from=t1 + timedelta(minutes=45),
        )
    )

    # 4. Terminated entity (deleted at t1 + 15m)
    await store.record_entity(
        EntityRecord(uid="e-terminated", kind="Pod", namespace="payments", name="pod-old")
    )
    await store.record_change(
        ChangeRecord(
            entity_uid="e-terminated",
            change_type="INIT",
            summary="Init pod",
            before_state={},
            after_state={"phase": "Running"},
            valid_from=t1 - timedelta(hours=1),
        )
    )
    await store.record_change(
        ChangeRecord(
            entity_uid="e-terminated",
            change_type="DELETE",
            summary="Pod terminated",
            before_state={"phase": "Running"},
            after_state={},
            valid_from=t1 + timedelta(minutes=15),
            valid_to=t1 + timedelta(minutes=15),
        )
    )

    # Compute diff between t1 and t2
    diff_res = await store.diff(t1=t1, t2=t2)
    assert len(diff_res.node_diffs) == 3

    diffs_by_id = {d.entity_id: d for d in diff_res.node_diffs}
    assert "e-stable" not in diffs_by_id

    # Check mutated
    assert "e-mutated" in diffs_by_id
    assert diffs_by_id["e-mutated"].diff_type == "MUTATED"
    assert "version" in diffs_by_id["e-mutated"].modified_keys

    # Check created
    assert "e-created" in diffs_by_id
    assert diffs_by_id["e-created"].diff_type == "CREATED"

    # Check terminated
    assert "e-terminated" in diffs_by_id
    assert diffs_by_id["e-terminated"].diff_type == "TERMINATED"


@pytest.mark.asyncio
async def test_changes_before_window_query(store: TemporalStore) -> None:
    entity = EntityRecord(uid="e-cart", kind="Deployment", namespace="shop", name="cart")
    await store.record_entity(entity)

    alert_time = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)

    # Changes at different times
    times_and_types = [
        (alert_time - timedelta(minutes=90), "OLD_CHANGE"),  # Outside 60m window
        (alert_time - timedelta(minutes=45), "CONFIG_CHANGE"),  # Inside
        (alert_time - timedelta(minutes=15), "BAD_DEPLOY"),  # Inside
        (alert_time + timedelta(minutes=5), "FUTURE_CHANGE"),  # After alert
    ]

    for valid_time, ctype in times_and_types:
        await store.record_change(
            ChangeRecord(
                entity_uid="e-cart",
                change_type=ctype,
                summary=f"Change {ctype}",
                before_state={},
                after_state={"val": ctype},
                valid_from=valid_time,
            )
        )

    # Query with default 60-minute window
    changes = await store.changes_before(alert_time=alert_time, window_minutes=60)
    assert len(changes) == 2
    # Ordered descending by valid_from
    assert changes[0].change_type == "BAD_DEPLOY"
    assert changes[1].change_type == "CONFIG_CHANGE"


@pytest.mark.asyncio
async def test_observations_recording_and_retrieval(store: TemporalStore) -> None:
    entity = EntityRecord(uid="e-db", kind="StatefulSet", namespace="db", name="postgres")
    await store.record_entity(entity)

    now = datetime.now(UTC)
    obs = ObservationRecord(
        entity_uid="e-db",
        timestamp=now,
        metric_name="container_cpu_usage",
        value=0.92,
        status="degraded",
    )
    await store.record_observation(obs)

    observations = await store.get_observations("e-db")
    assert len(observations) == 1
    assert observations[0].metric_name == "container_cpu_usage"
    assert observations[0].value == 0.92
    assert observations[0].status == "degraded"
