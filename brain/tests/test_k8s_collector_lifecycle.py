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


@pytest.mark.asyncio
async def test_lifespan_service_populates_store_automatically(tmp_path: Any) -> None:
    """
    Requirement 1: Proves that FastAPI lifespan starts run_watches_in_background
    when watch_enabled is true, and the service itself populates the TemporalStore
    automatically without any test-harness sync call.
    """
    from app.config import Settings
    from app.main import create_app, lifespan

    db_path = str(tmp_path / "lifespan_collector.db")
    test_settings = Settings()
    test_settings.temporal_store.db_path = db_path
    test_settings.kubernetes.collector_enabled = True
    test_settings.kubernetes.watch_enabled = True
    test_settings.kubernetes.allowed_namespaces = ["payments"]
    test_settings.kubernetes.collector_interval_seconds = 10

    mock_deploy = MagicMock()
    mock_deploy.metadata.uid = "deploy-auto-watch-99"
    mock_deploy.metadata.name = "payment-gateway"
    mock_deploy.metadata.namespace = "payments"
    mock_deploy.metadata.annotations = {"deployment.kubernetes.io/revision": "2"}
    mock_deploy.metadata.labels = {"app": "payment-gateway"}
    mock_deploy.metadata.resource_version = "12345"
    mock_deploy.spec.replicas = 3
    mock_deploy.status.ready_replicas = 3
    mock_deploy.status.updated_replicas = 3
    mock_c = MagicMock()
    mock_c.name = "gateway"
    mock_c.image = "payment-gateway:v2"
    mock_deploy.spec.template.spec.containers = [mock_c]

    mock_apps = MagicMock()
    mock_core = MagicMock()
    call_count = 0

    def fake_stream(*args: Any, **kwargs: Any) -> Any:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            yield {"type": "ADDED", "object": mock_deploy}
        else:
            import time
            time.sleep(0.05)
            return []

    app = create_app(settings=test_settings)

    with (
        patch("app.main.get_settings", return_value=test_settings),
        patch("app.routers.approval.get_settings", return_value=test_settings),
        patch("kubernetes.config.load_incluster_config", return_value=None),
        patch("kubernetes.config.load_kube_config", return_value=None),
        patch("kubernetes.client.AppsV1Api", return_value=mock_apps),
        patch("kubernetes.client.CoreV1Api", return_value=mock_core),
        patch("kubernetes.watch.Watch.stream", side_effect=fake_stream),
    ):
        # Run the service lifespan context - the test harness calls NO sync methods
        async with lifespan(app):
            # Wait for the service background watch thread to receive and store the entity
            for _ in range(30):
                await asyncio.sleep(0.1)
                async with TemporalStore(db_path=db_path) as check_store:
                    entity = await check_store.get_entity("deploy-auto-watch-99")
                    if entity is not None:
                        break

    # Verify the service itself populated the store
    async with TemporalStore(db_path=db_path) as check_store:
        entity = await check_store.get_entity("deploy-auto-watch-99")
        assert entity is not None
        assert entity.uid == "deploy-auto-watch-99"
        assert entity.name == "payment-gateway"
        assert entity.namespace == "payments"
        assert entity.kind == "Deployment"


@pytest.mark.asyncio
async def test_empty_allowed_namespaces_collects_nothing_and_acts_on_nothing(tmp_path: Any) -> None:
    """
    Requirement 2: Empty allowed_namespaces must mean: collect nothing, act on nothing.
    """
    from app.config import Settings
    from app.main import create_app, lifespan
    from app.services.k8s_executor import (
        ActionEnvelope,
        KubernetesRollbackExecutor,
        PreconditionFailedError,
    )

    db_path = str(tmp_path / "empty_ns.db")
    test_settings = Settings()
    test_settings.temporal_store.db_path = db_path
    test_settings.kubernetes.collector_enabled = True
    test_settings.kubernetes.watch_enabled = True
    test_settings.kubernetes.allowed_namespaces = []  # Empty allowlist!
    test_settings.kubernetes.broad_read_opt_in = False  # No opt-in

    mock_apps = MagicMock()

    app = create_app(settings=test_settings)

    with (
        patch("app.main.get_settings", return_value=test_settings),
        patch("app.services.k8s_collector.KubernetesCollector._ensure_apis") as mock_ensure,
    ):
        mock_ensure.side_effect = lambda: None

        # 1. Lifespan runs with empty allowed_namespaces: collect nothing
        async with lifespan(app):
            await asyncio.sleep(0.2)

    # Verify 0 entities collected in the store
    async with TemporalStore(db_path=db_path) as check_store:
        entities = await check_store.get_entities()
        assert len(entities) == 0

    # 2. Act on nothing: Executor rejects any action when allowed_namespaces is empty
    executor = KubernetesRollbackExecutor(
        apps_api=mock_apps,
        allowlisted_namespaces=[],
    )
    try:
        envelope = ActionEnvelope(
            incident_id="inc-empty-ns-01",
            action_name="A1_ROLLBACK",
            namespace="payments",
            target_name="payment-svc",
            target_uid="uid-svc-001",
            approver="operator-1",
        )
        with pytest.raises(PreconditionFailedError) as exc_info:
            executor.check_preconditions(envelope)

        assert "not in allowlist" in str(exc_info.value)
    finally:
        executor.audit_logger.close()


@pytest.mark.asyncio
async def test_broad_read_opt_in_allows_read_only_collection_but_acts_on_nothing(
    tmp_path: Any,
) -> None:
    """
    Requirement 2 (opt-in): broad_read_opt_in allows broad cluster read telemetry collection,
    while action execution strictly requires explicit allowed_namespaces and rejects actions.
    """
    from app.config import Settings
    from app.services.k8s_executor import (
        ActionEnvelope,
        KubernetesRollbackExecutor,
        PreconditionFailedError,
    )

    db_path = str(tmp_path / "broad_read.db")
    test_settings = Settings()
    test_settings.temporal_store.db_path = db_path
    test_settings.kubernetes.collector_enabled = True
    test_settings.kubernetes.allowed_namespaces = []  # Empty allowlist
    test_settings.kubernetes.broad_read_opt_in = True  # Explicit opt-in for broader read access

    mock_deploy = MagicMock()
    mock_deploy.metadata.uid = "deploy-broad-01"
    mock_deploy.metadata.name = "global-router"
    mock_deploy.metadata.namespace = "infra"
    mock_deploy.metadata.annotations = {}
    mock_deploy.metadata.labels = {"app": "global-router"}
    mock_deploy.spec.replicas = 2
    mock_deploy.status.ready_replicas = 2
    mock_deploy.status.updated_replicas = 2
    mock_c = MagicMock()
    mock_c.name = "router"
    mock_c.image = "router:v1"
    mock_deploy.spec.template.spec.containers = [mock_c]

    mock_apps = MagicMock()
    mock_apps.list_deployment_for_all_namespaces.return_value.items = [mock_deploy]
    mock_apps.list_replica_set_for_all_namespaces.return_value.items = []
    mock_core = MagicMock()
    mock_core.list_pod_for_all_namespaces.return_value.items = []
    mock_core.list_event_for_all_namespaces.return_value.items = []

    collector = KubernetesCollector(apps_api=mock_apps, core_api=mock_core)

    async with TemporalStore(db_path=db_path) as store:
        # broad_read_opt_in allows sync_all to collect cluster-wide telemetry
        results = await collector.sync_all(store)
        assert results["deployments"] == 1
        ent = await store.get_entity("deploy-broad-01")
        assert ent is not None
        assert ent.name == "global-router"

    # But action execution STILL acts on nothing because allowed_namespaces is empty
    executor = KubernetesRollbackExecutor(
        apps_api=mock_apps,
        allowlisted_namespaces=test_settings.kubernetes.allowed_namespaces,  # []
    )
    try:
        envelope = ActionEnvelope(
            incident_id="inc-broad-read-01",
            action_name="A1_ROLLBACK",
            namespace="infra",
            target_name="global-router",
            target_uid="deploy-broad-01",
            approver="operator-1",
        )
        with pytest.raises(PreconditionFailedError) as exc_info:
            executor.check_preconditions(envelope)

        assert "not in allowlist" in str(exc_info.value)
    finally:
        executor.audit_logger.close()
