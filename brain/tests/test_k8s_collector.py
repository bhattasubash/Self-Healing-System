"""
Unit tests for KubernetesCollector service (PRD Section 8, F-04).

Verifies cluster resource discovery and bi-temporal store population:
- Deployments revisions, replicas, and rollout state
- ReplicaSets revisions and ownership binding
- Pods phase, container crash loops, and health observations
- Events Warning and Normal telemetry
- HorizontalPodAutoscalers target and replica metrics
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.services.k8s_collector import KubernetesCollector
from app.services.temporal_store import TemporalStore


@pytest.fixture
def temporal_store() -> TemporalStore:
    store = TemporalStore(":memory:")
    yield store
    store.close()


def _make_mock_deployment(
    name: str = "payment-gateway",
    namespace: str = "payments",
    uid: str = "deploy-uid-1",
    revision: str = "2",
    replicas: int = 2,
    ready_replicas: int = 2,
) -> MagicMock:
    d = MagicMock()
    d.metadata.name = name
    d.metadata.namespace = namespace
    d.metadata.uid = uid
    d.metadata.annotations = {"deployment.kubernetes.io/revision": revision}
    c = MagicMock()
    c.image = f"{name}:v{revision}"
    d.spec.template.spec.containers = [c]
    d.spec.replicas = replicas
    d.status.ready_replicas = ready_replicas
    d.status.updated_replicas = replicas
    return d


def _make_mock_rs(
    name: str = "payment-gateway-rev2",
    namespace: str = "payments",
    uid: str = "rs-uid-2",
    revision: str = "2",
    owner_uid: str = "deploy-uid-1",
) -> MagicMock:
    rs = MagicMock()
    rs.metadata.name = name
    rs.metadata.namespace = namespace
    rs.metadata.uid = uid
    rs.metadata.annotations = {"deployment.kubernetes.io/revision": revision}
    owner = MagicMock()
    owner.uid = owner_uid
    rs.metadata.owner_references = [owner]
    c = MagicMock()
    c.image = f"payment-gateway:v{revision}"
    rs.spec.template.spec.containers = [c]
    rs.spec.replicas = 2
    return rs


def _make_mock_pod(
    name: str = "payment-gateway-xyz",
    namespace: str = "payments",
    uid: str = "pod-uid-1",
    phase: str = "Running",
    crash_looping: bool = False,
) -> MagicMock:
    p = MagicMock()
    p.metadata.name = name
    p.metadata.namespace = namespace
    p.metadata.uid = uid
    p.metadata.labels = {"app": "payment-gateway"}
    p.status.phase = phase

    cs = MagicMock()
    if crash_looping:
        cs.state.waiting.reason = "CrashLoopBackOff"
        cs.restart_count = 5
        cs.ready = False
    else:
        cs.state.waiting = None
        cs.restart_count = 0
        cs.ready = True
    p.status.container_statuses = [cs]
    return p


@pytest.mark.asyncio
async def test_collector_sync_deployments(temporal_store: TemporalStore) -> None:
    mock_apps = MagicMock()
    mock_deploy = _make_mock_deployment()
    mock_apps.list_deployment_for_all_namespaces.return_value.items = [mock_deploy]

    collector = KubernetesCollector(apps_api=mock_apps, core_api=MagicMock())
    records = await collector.sync_deployments(temporal_store)

    assert len(records) == 1
    assert records[0].name == "payment-gateway"

    ent = await temporal_store.get_entity_by_name(namespace="payments", name="payment-gateway")
    assert ent is not None
    assert ent.uid == "deploy-uid-1"

    changes = await temporal_store.get_changes_for_entity("deploy-uid-1")
    assert len(changes) == 1
    assert changes[0].after_state["revision"] == "2"


@pytest.mark.asyncio
async def test_collector_sync_replica_sets(temporal_store: TemporalStore) -> None:
    mock_apps = MagicMock()
    mock_rs = _make_mock_rs()
    mock_apps.list_replica_set_for_all_namespaces.return_value.items = [mock_rs]

    collector = KubernetesCollector(apps_api=mock_apps, core_api=MagicMock())
    records = await collector.sync_replica_sets(temporal_store)

    assert len(records) == 1
    assert records[0].kind == "ReplicaSet"

    ent = await temporal_store.get_entity_by_name(
        namespace="payments", name="payment-gateway-rev2", kind="ReplicaSet"
    )
    assert ent is not None


@pytest.mark.asyncio
async def test_collector_sync_pods_healthy_and_unhealthy(
    temporal_store: TemporalStore,
) -> None:
    # First seed the parent deployment so pod correlation works
    mock_apps = MagicMock()
    mock_deploy = _make_mock_deployment()
    mock_apps.list_deployment_for_all_namespaces.return_value.items = [mock_deploy]
    collector = KubernetesCollector(apps_api=mock_apps, core_api=MagicMock())
    await collector.sync_deployments(temporal_store)

    # Sync pods
    mock_core = MagicMock()
    pod_healthy = _make_mock_pod("payment-gateway-h1", uid="pod-h1", crash_looping=False)
    pod_crash = _make_mock_pod("payment-gateway-c1", uid="pod-c1", crash_looping=True)
    mock_core.list_pod_for_all_namespaces.return_value.items = [pod_healthy, pod_crash]

    collector.core_api = mock_core
    pods = await collector.sync_pods(temporal_store)

    assert len(pods) == 2

    # Check observations on the parent deployment
    deploy_obs = await temporal_store.get_observations_for_entity("deploy-uid-1")
    assert len(deploy_obs) >= 1
    unhealthy = [o for o in deploy_obs if o.status == "unhealthy"]
    assert len(unhealthy) == 1
    assert "CrashLoopBackOff" in unhealthy[0].metric_name


@pytest.mark.asyncio
async def test_collector_sync_events(temporal_store: TemporalStore) -> None:
    mock_core = MagicMock()
    event = MagicMock()
    event.type = "Warning"
    event.reason = "BackOff"
    event.involved_object.kind = "Pod"
    event.involved_object.uid = "pod-c1"
    event.involved_object.name = "payment-gateway-c1"
    event.involved_object.namespace = "payments"
    mock_core.list_event_for_all_namespaces.return_value.items = [event]

    collector = KubernetesCollector(apps_api=MagicMock(), core_api=mock_core)
    events = await collector.sync_events(temporal_store)

    assert len(events) == 1
    assert events[0].status == "unhealthy"
    assert "BackOff" in events[0].metric_name


@pytest.mark.asyncio
async def test_collector_sync_hpa(temporal_store: TemporalStore) -> None:
    mock_hpa_api = MagicMock()
    hpa = MagicMock()
    hpa.metadata.name = "payment-hpa"
    hpa.metadata.namespace = "payments"
    hpa.metadata.uid = "hpa-uid-1"
    hpa.spec.scale_target_ref.name = "payment-gateway"
    hpa.status.current_replicas = 2
    hpa.status.desired_replicas = 4
    mock_hpa_api.list_horizontal_pod_autoscaler_for_all_namespaces.return_value.items = [hpa]

    collector = KubernetesCollector(
        apps_api=MagicMock(), core_api=MagicMock(), autoscaling_api=mock_hpa_api
    )
    records = await collector.sync_hpa(temporal_store)

    assert len(records) == 1
    assert records[0].kind == "HorizontalPodAutoscaler"

    changes = await temporal_store.get_changes_for_entity("hpa-uid-1")
    assert len(changes) == 1
    assert changes[0].after_state["desired_replicas"] == 4


@pytest.mark.asyncio
async def test_collector_sync_all(temporal_store: TemporalStore) -> None:
    mock_apps = MagicMock()
    mock_apps.list_deployment_for_all_namespaces.return_value.items = [_make_mock_deployment()]
    mock_apps.list_replica_set_for_all_namespaces.return_value.items = [_make_mock_rs()]

    mock_core = MagicMock()
    mock_core.list_pod_for_all_namespaces.return_value.items = [_make_mock_pod()]
    mock_core.list_event_for_all_namespaces.return_value.items = []

    mock_autoscaling = MagicMock()
    mock_autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces.return_value.items = []
    collector = KubernetesCollector(
        apps_api=mock_apps, core_api=mock_core, autoscaling_api=mock_autoscaling
    )

    stats = await collector.sync_all(temporal_store)
    assert stats["deployments"] == 1
    assert stats["replica_sets"] == 1
    assert stats["pods"] == 1
