"""
Unit tests for the BiTemporalGraphStore service.

Tests verify:
- Bi-temporal record parsing and conversion to Pydantic models.
- Transaction handling and execution patterns.
- Temporal snapshot diffing logic (CREATED, MUTATED, TERMINATED entities).
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
import pytest

from app.services.graph_store import (
    BiTemporalGraphStore,
    TemporalEntityDiff,
    TemporalNode,
    TemporalRelationship,
    TemporalSnapshot,
)


def _make_dummy_node(
    entity_id: str,
    props: dict,
    valid_from: datetime,
    valid_to: datetime | None = None,
) -> TemporalNode:
    return TemporalNode(
        entity_id=entity_id,
        labels=["Service"],
        properties=props,
        valid_from=valid_from,
        valid_to=valid_to,
        recorded_at=datetime.now(timezone.utc),
    )


@pytest.mark.asyncio
async def test_diff_snapshots_detects_created_mutated_and_terminated() -> None:
    t1 = datetime(2026, 10, 1, 0, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 1, 1, 0, 0, tzinfo=timezone.utc)

    # In t1:
    # - node_stable exists
    # - node_mutated exists with version 1
    # - node_terminated exists
    snap1 = TemporalSnapshot(
        valid_at=t1,
        nodes=[
            _make_dummy_node("node_stable", {"status": "healthy"}, t1),
            _make_dummy_node("node_mutated", {"version": "v1.0", "replicas": 3}, t1),
            _make_dummy_node("node_terminated", {"status": "deprecated"}, t1),
        ],
        relationships=[],
        node_count=3,
        relationship_count=0,
    )

    # In t2:
    # - node_stable unchanged
    # - node_mutated has version 2 and replicas 5
    # - node_created is newly added
    # - node_terminated is missing
    snap2 = TemporalSnapshot(
        valid_at=t2,
        nodes=[
            _make_dummy_node("node_stable", {"status": "healthy"}, t1),
            _make_dummy_node("node_mutated", {"version": "v2.0", "replicas": 5}, t2),
            _make_dummy_node("node_created", {"status": "new"}, t2),
        ],
        relationships=[],
        node_count=3,
        relationship_count=0,
    )

    # Mock get_temporal_snapshot on the store
    store = BiTemporalGraphStore(driver=MagicMock())
    store.get_temporal_snapshot = AsyncMock(side_effect=[snap1, snap2])

    diff = await store.diff_snapshots(t1=t1, t2=t2)

    diff_map = {d.entity_id: d for d in diff.node_diffs}

    assert "node_created" in diff_map
    assert diff_map["node_created"].diff_type == "CREATED"
    assert diff_map["node_created"].t2_properties == {"status": "new"}

    assert "node_mutated" in diff_map
    assert diff_map["node_mutated"].diff_type == "MUTATED"
    assert set(diff_map["node_mutated"].modified_keys) == {"version", "replicas"}
    assert diff_map["node_mutated"].t1_properties["version"] == "v1.0"
    assert diff_map["node_mutated"].t2_properties["version"] == "v2.0"

    assert "node_terminated" in diff_map
    assert diff_map["node_terminated"].diff_type == "TERMINATED"

    # node_stable must not be in diff
    assert "node_stable" not in diff_map


@pytest.mark.asyncio
async def test_create_entity_executes_within_explicit_tx() -> None:
    mock_driver = MagicMock()
    mock_session = AsyncMock()
    mock_tx = AsyncMock()

    mock_driver.session.return_value.__aenter__.return_value = mock_session
    mock_session.begin_transaction = AsyncMock(return_value=mock_tx)
    mock_tx.__aenter__.return_value = mock_tx
    mock_tx.__aexit__.return_value = None

    fake_record = {
        "n": {
            "entity_id": "MASKED_SVC_billing",
            "name": "billing-service",
            "valid_from": "2026-10-13T10:00:00Z",
            "valid_to": None,
            "recorded_at": "2026-10-13T10:00:00Z",
        },
        "node_labels": ["Service", "InfrastructureEntity"],
    }
    mock_result = AsyncMock()
    mock_result.single.return_value = fake_record
    mock_tx.run.return_value = mock_result

    store = BiTemporalGraphStore(driver=mock_driver)
    node = await store.create_entity(
        label="Service",
        entity_id="MASKED_SVC_billing",
        properties={"name": "billing-service"},
    )

    assert node.entity_id == "MASKED_SVC_billing"
    assert node.properties["name"] == "billing-service"
    assert node.valid_to is None
    assert "Service" in node.labels

    # Verify tx.commit() was explicitly invoked
    mock_tx.commit.assert_awaited_once()
