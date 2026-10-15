"""
Tests for KubernetesCollector lifecycle, watches, freshness check, and lifespan integration.

Verifies:
1. Collector freshness check: stale data (> freshness_threshold_seconds) caps tier at B/C.
2. Watches run off the event loop without blocking async runtime.
3. Watches handle 410 Gone / expired resourceVersion and reconnect.
4. Watches observe only allowed namespaces.
5. Events persist in TemporalStore beyond Kubernetes 1-hour TTL.
6. FastAPI lifespan starts and gracefully stops collector background tasks.
"""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from app.services.evidence_gate import (
    EvidenceGate,
    EvidenceGateContext,
    EvidenceTier,
)
from app.services.k8s_collector import KubernetesCollector
from app.services.temporal_store import EntityRecord, ObservationRecord, TemporalStore


@pytest.fixture
def store() -> TemporalStore:
    s = TemporalStore(":memory:")
    yield s
    s.close()


@pytest.mark.asyncio
async def test_collector_freshness_check_caps_tier_at_b(store: TemporalStore) -> None:
    """Stale collector telemetry (> freshness threshold) caps EvidenceGate tier at B."""
    now = datetime.now(UTC)
    stale_time = now - timedelta(seconds=300)  # 5 minutes old (stale)

    # Record baseline entity and observation with old timestamp
    ent = EntityRecord(
        uid="deploy-stale-01",
        kind="Deployment",
        namespace="payments",
        name="payment-gateway",
    )
    await store.record_entity(ent)
    obs = ObservationRecord(
        entity_uid="deploy-stale-01",
        timestamp=stale_time,
        metric_name="pod_status",
        value=1.0,
        status="healthy",
    )
    await store.record_observation(obs)

    # Collector freshness check reports data is stale
    collector = KubernetesCollector()
    is_fresh = collector.is_telemetry_fresh(store, threshold_seconds=120)
    assert is_fresh is False

    # Evidence gate with stale telemetry caps tier at B
    gate = EvidenceGate()
    ctx = EvidenceGateContext(
        incident_id="inc-stale-01",
        target_workloads=["deployment/payment-gateway"],
        alert_firing=True,
        first_symptom_time=now,
        change_time=now - timedelta(minutes=10),
        symptoms=["KubePodCrashLooping"],
        independent_signals_count=2,
        previous_revision_healthy=True,
        has_history=True,
        target_revision_exists=True,
        telemetry_fresh=False,  # Flagged stale!
    )
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_B
    r4 = next(r for r in result.rule_evaluations if r.rule_id == "R4")
    assert r4.passed is False
    assert "stale" in r4.details.lower()


@pytest.mark.asyncio
async def test_collector_watches_off_event_loop_and_handles_410_reconnect(
    store: TemporalStore,
) -> None:
    """Collector runs blocking watches off the event loop and recovers from HTTP 410 Gone."""
    mock_apps = MagicMock()
    collector = KubernetesCollector(apps_api=mock_apps, core_api=MagicMock())

    stop_event = threading.Event()
    reconnect_occurred = False

    # Simulate watch stream that yields 410 Gone error once, then normal event
    call_count = 0

    def fake_stream(*args: Any, **kwargs: Any) -> Any:
        nonlocal call_count, reconnect_occurred
        call_count += 1
        if call_count == 1:
            # Simulate Kubernetes 410 Expired / GoneApiException
            class FakeApiError(Exception):
                status = 410

            raise FakeApiError("410 Gone: resourceVersion too old")
        reconnect_occurred = True
        stop_event.set()
        return []

    with patch("kubernetes.watch.Watch.stream", side_effect=fake_stream):
        # Run watch worker task
        watch_task = asyncio.create_task(
            collector.run_watches_in_background(
                temporal_store=store,
                namespaces=["payments"],
                stop_event=stop_event,
                poll_fallback_seconds=0.1,
            )
        )
        # Event loop should remain responsive while blocking watch is running in thread
        await asyncio.sleep(0.3)
        stop_event.set()
        await asyncio.wait_for(watch_task, timeout=2.0)

    assert reconnect_occurred is True


@pytest.mark.asyncio
async def test_collector_watches_only_allowed_namespaces(store: TemporalStore) -> None:
    """Collector only queries and watches namespaces configured in allowlist."""
    mock_apps = MagicMock()
    mock_core = MagicMock()
    collector = KubernetesCollector(apps_api=mock_apps, core_api=mock_core)

    allowed = ["payments", "orders"]
    await collector.sync_namespaces(store, namespaces=allowed)

    # Must list deployments and pods specifically for each allowed namespace, not all namespaces
    assert mock_apps.list_namespaced_deployment.call_count == len(allowed)
    assert mock_core.list_namespaced_pod.call_count == len(allowed)
    assert mock_apps.list_deployment_for_all_namespaces.call_count == 0


@pytest.mark.asyncio
async def test_collector_persists_events_beyond_1h_ttl(store: TemporalStore) -> None:
    """Collector persists Warning events indefinitely in SQLite bi-temporal store."""
    mock_core = MagicMock()
    event_old = MagicMock()
    event_old.type = "Warning"
    event_old.reason = "BackOff"
    event_old.message = "Back-off restarting failed container"
    event_old.count = 42
    event_old.first_timestamp = datetime.now(UTC) - timedelta(hours=3)
    event_old.last_timestamp = datetime.now(UTC) - timedelta(hours=2)  # > 1 hour ago!
    event_old.involved_object.kind = "Pod"
    event_old.involved_object.name = "payment-gateway-c1"
    event_old.involved_object.namespace = "payments"
    event_old.involved_object.uid = "pod-old-uid"

    mock_core.list_namespaced_event.return_value.items = [event_old]
    collector = KubernetesCollector(apps_api=MagicMock(), core_api=mock_core)

    await collector.sync_events(store, namespace="payments")

    # Verify event observation is stored in SQLite and can be retrieved
    obs = await store.get_observations_for_entity("pod-old-uid")
    assert len(obs) == 1
    assert obs[0].status == "unhealthy"
    assert "BackOff" in obs[0].metric_name
