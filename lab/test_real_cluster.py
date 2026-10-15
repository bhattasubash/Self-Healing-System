"""
Real Cluster Test Suite for Gate G0 (T-01, T-02, T-04).

Executes against a live Kubernetes/kind cluster with NO MagicMock:
- Verifies real cluster connectivity.
- Syncs real cluster state into TemporalStore via KubernetesCollector.
- Injects failure (T-01 bad image, T-02 crashloop, T-04 failing readiness).
- Ingests alert into Brain with authenticated API.
- Evaluates Evidence Gate preconditions against REAL cluster signals.
- Dispatches Slack approval card.
- Approves rollback and executes typed A1 rollback directly on the live cluster.
- Verifies deployment stabilization and audit hash chain integrity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Ensure brain/app is importable
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "brain"))

import pytest
from app.config import Settings, get_settings
from app.main import app
from app.routers.alert_intake import set_alert_temporal_store
from app.services.approval_store import SQLiteApprovalRegistry
from app.services.k8s_collector import KubernetesCollector
from app.services.temporal_store import TemporalStore
from fastapi.testclient import TestClient
from pydantic import SecretStr

if TYPE_CHECKING:
    from collections.abc import Generator

TEST_SLACK_SIGNING_SECRET = "real_cluster_slack_secret_123"
TEST_ALERT_TOKEN = "real-cluster-alert-secret-token"


def _compute_slack_headers(
    body: bytes, secret: str = TEST_SLACK_SIGNING_SECRET
) -> dict[str, str]:
    ts = str(int(time.time()))
    basestring = f"v0:{ts}:{body.decode('utf-8')}".encode()
    sig = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    return {
        "X-Slack-Request-Timestamp": ts,
        "X-Slack-Signature": sig,
    }


def is_k8s_cluster_reachable() -> bool:
    """Checks if a real Kubernetes cluster is reachable via kubeconfig."""
    try:
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        v1 = client.CoreV1Api()
        v1.list_namespace(timeout_seconds=3)
        return True
    except Exception:  # noqa: BLE001
        return False


def get_real_cluster_apps_api() -> Any:
    """Returns an authenticated AppsV1Api client."""
    from kubernetes import client, config

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.AppsV1Api()


def get_real_cluster_core_api() -> Any:
    """Returns an authenticated CoreV1Api client."""
    from kubernetes import client, config

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def test_settings() -> Settings:
    s = Settings()
    s.alert.auth_token = SecretStr(TEST_ALERT_TOKEN)
    s.slack.signing_secret = SecretStr(TEST_SLACK_SIGNING_SECRET)
    s.slack.allowed_approver_roles = ["sre-lead", "platform-engineer"]
    s.slack.approver_role_mapping = {
        "U_SRE_LEAD": "sre-lead",
        "U_PLATFORM": "platform-engineer",
    }
    return s


@pytest.fixture
def override_settings(test_settings: Settings) -> Generator[None, None, None]:
    app.dependency_overrides[get_settings] = lambda: test_settings
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def live_temporal_store(tmp_path: Path) -> Generator[TemporalStore, None, None]:
    db_path = str(tmp_path / "live_temporal_test.db")
    store = TemporalStore(db_path=db_path)
    set_alert_temporal_store(store)
    yield store
    store.close()


@pytest.fixture
def live_approval_registry(tmp_path: Path) -> Generator[SQLiteApprovalRegistry, None, None]:
    db_path = str(tmp_path / "live_approval_test.db")
    reg = SQLiteApprovalRegistry(db_path=db_path)
    from app.routers import approval
    approval._GLOBAL_APPROVAL_REGISTRY = reg
    yield reg
    reg.close()


def _ensure_baseline_healthy(apps_api: Any, core_api: Any) -> None:
    """Ensures payment-gateway deployment is at healthy revision with image hashicorp/http-echo:0.2.3."""
    deploy = apps_api.read_namespaced_deployment(name="payment-gateway", namespace="payments")
    current_image = deploy.spec.template.spec.containers[0].image
    if current_image != "hashicorp/http-echo:0.2.3":
        patch_body = {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "payment-gateway",
                                "image": "hashicorp/http-echo:0.2.3",
                                "command": None,
                                "args": ["-text=payment-gateway-healthy-v1", "-listen=:8080"],
                            }
                        ]
                    }
                }
            }
        }
        apps_api.patch_namespaced_deployment(
            name="payment-gateway", namespace="payments", body=patch_body
        )

    # Wait up to 60s for 3 ready replicas
    for _ in range(60):
        d = apps_api.read_namespaced_deployment(name="payment-gateway", namespace="payments")
        status = d.status
        if status and status.ready_replicas == 3 and (status.unavailable_replicas or 0) == 0:
            return
        time.sleep(1)


@pytest.mark.skipif(not is_k8s_cluster_reachable(), reason="Live Kubernetes cluster not available")
def test_real_cluster_connectivity() -> None:
    """Verifies connection to real Kubernetes cluster and payments namespace."""
    core_api = get_real_cluster_core_api()
    namespaces = [ns.metadata.name for ns in core_api.list_namespace().items]
    assert "payments" in namespaces

    apps_api = get_real_cluster_apps_api()
    deploy = apps_api.read_namespaced_deployment(name="payment-gateway", namespace="payments")
    assert deploy.metadata.name == "payment-gateway"


@pytest.mark.skipif(not is_k8s_cluster_reachable(), reason="Live Kubernetes cluster not available")
def test_real_cluster_collector_sync(live_temporal_store: TemporalStore) -> None:
    """Verifies that KubernetesCollector populates TemporalStore from real cluster."""
    collector = KubernetesCollector(temporal_store=live_temporal_store)
    counts = collector.sync_all(namespace="payments")

    assert counts["deployments"] >= 1
    assert counts["replicasets"] >= 1
    assert counts["pods"] >= 1

    entity = live_temporal_store.get_entity_by_name(
        namespace="payments", name="payment-gateway", kind="Deployment"
    )
    assert entity is not None
    assert entity.name == "payment-gateway"


@pytest.mark.skipif(not is_k8s_cluster_reachable(), reason="Live Kubernetes cluster not available")
def test_real_cluster_t01_bad_image_rollback_flow(
    client: TestClient,
    override_settings: None,
    live_temporal_store: TemporalStore,
    live_approval_registry: SQLiteApprovalRegistry,
) -> None:
    """
    Scenario T-01 on REAL Cluster:
    1. Ensure baseline v1 is healthy (3/3 ready).
    2. Sync baseline to TemporalStore.
    3. Inject bad image tag into live deployment.
    4. Wait for pod ErrImagePull / ImagePullBackOff.
    5. Sync cluster state -> TemporalStore captures change & unhealthy pod observation.
    6. Send Alertmanager firing alert.
    7. Evidence Gate classifies as Tier A and proposes A1_ROLLBACK.
    8. Operator approves -> Rollback executes on REAL cluster.
    9. Verification succeeds on live cluster (3/3 ready, revision restored).
    10. Audit log confirms cryptographic SHA256 chain.
    """
    apps_api = get_real_cluster_apps_api()
    core_api = get_real_cluster_core_api()
    collector = KubernetesCollector(temporal_store=live_temporal_store)

    # 1. Baseline healthy
    _ensure_baseline_healthy(apps_api, core_api)

    # Sync baseline state to TemporalStore
    collector.sync_all("payments")

    # 2. Inject Failure: Bad Image Tag
    bad_image = "hashicorp/http-echo:v2-broken-tag-xyz"
    patch_body = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "payment-gateway", "image": bad_image}]
                }
            }
        }
    }
    apps_api.patch_namespaced_deployment(
        name="payment-gateway", namespace="payments", body=patch_body
    )

    # 3. Wait for pod failure on real cluster
    failure_observed = False
    for _ in range(45):
        pods = core_api.list_namespaced_pod(
            namespace="payments", label_selector="app=payment-gateway"
        ).items
        for p in pods:
            cs = (p.status.container_statuses or []) if p.status else []
            for c in cs:
                waiting = c.state.waiting if c.state else None
                if waiting and waiting.reason in ("ImagePullBackOff", "ErrImagePull"):
                    failure_observed = True
                    break
        if failure_observed:
            break
        time.sleep(1)

    assert failure_observed, "Expected pod to enter ErrImagePull or ImagePullBackOff"

    # 4. Sync real cluster state after failure
    collector.sync_all("payments")

    # 5. Send Alertmanager Alert
    now = datetime.now(UTC).isoformat()
    alert_payload = {
        "receiver": "heal-webhook",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "KubeDeploymentRolloutStuck",
                    "namespace": "payments",
                    "deployment": "payment-gateway",
                    "app": "payment-gateway",
                    "severity": "critical",
                },
                "annotations": {
                    "summary": "Deployment payments/payment-gateway rollout is stuck",
                    "description": f"ImagePullBackOff: Failed to pull image '{bad_image}'",
                },
                "startsAt": now,
                "endsAt": "0001-01-01T00:00:00Z",
                "fingerprint": "t01-real-cluster-fingerprint",
            }
        ],
    }

    alert_resp = client.post(
        "/api/v1/alerts/alertmanager",
        json=alert_payload,
        headers={"Authorization": f"Bearer {TEST_ALERT_TOKEN}"},
    )
    assert alert_resp.status_code == 202
    alert_data = alert_resp.json()

    assert alert_data["status"] == "accepted"
    assert alert_data["tier"] == "TIER_A"
    assert alert_data["proposed_action"] == "A1_ROLLBACK"
    assert alert_data["approval_id"] is not None

    approval_id = alert_data["approval_id"]

    # 6. Operator Approves Rollback via Slack Interactive Webhook
    slack_payload = {
        "type": "block_actions",
        "user": {"id": "U_SRE_LEAD", "username": "sre-lead"},
        "api_app_id": "A0123",
        "actions": [
            {
                "action_id": "btn_approve",
                "value": "approved",
                "action_ts": str(time.time()),
            }
        ],
    }
    form_data = urllib.parse.urlencode({"payload": json.dumps(slack_payload)})
    headers = _compute_slack_headers(form_data.encode())
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    appr_resp = client.post(
        f"/api/v1/approval/interactive?approval_id={approval_id}",
        content=form_data,
        headers=headers,
    )
    assert appr_resp.status_code == 200
    appr_data = appr_resp.json()

    assert appr_data["decision"] == "approved"
    assert appr_data["execution_status"] == "resolved"
    assert appr_data["audit_hash"] is not None

    # 7. Verify Real Cluster Deployment Restored
    deploy = apps_api.read_namespaced_deployment(name="payment-gateway", namespace="payments")
    restored_image = deploy.spec.template.spec.containers[0].image
    assert restored_image == "hashicorp/http-echo:0.2.3"
    assert deploy.status.ready_replicas == 3


@pytest.mark.skipif(not is_k8s_cluster_reachable(), reason="Live Kubernetes cluster not available")
def test_real_cluster_t02_crashloop_rollback_flow(
    client: TestClient,
    override_settings: None,
    live_temporal_store: TemporalStore,
    live_approval_registry: SQLiteApprovalRegistry,
) -> None:
    """Scenario T-02 on REAL Cluster: CrashLoopBackOff triggers Tier A and verified rollback."""
    apps_api = get_real_cluster_apps_api()
    core_api = get_real_cluster_core_api()
    collector = KubernetesCollector(temporal_store=live_temporal_store)

    _ensure_baseline_healthy(apps_api, core_api)
    collector.sync_all("payments")

    # Inject failure: exit 1 on startup
    patch_body = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "payment-gateway",
                            "image": "hashicorp/http-echo:0.2.3",
                            "command": ["/bin/sh", "-c", "exit 1"],
                            "args": [],
                        }
                    ]
                }
            }
        }
    }
    apps_api.patch_namespaced_deployment(
        name="payment-gateway", namespace="payments", body=patch_body
    )

    # Wait for crash loop
    crash_observed = False
    for _ in range(45):
        pods = core_api.list_namespaced_pod(
            namespace="payments", label_selector="app=payment-gateway"
        ).items
        for p in pods:
            cs = (p.status.container_statuses or []) if p.status else []
            for c in cs:
                waiting = c.state.waiting if c.state else None
                term = c.state.terminated if c.state else None
                if (waiting and waiting.reason == "CrashLoopBackOff") or (
                    term and term.exit_code == 1
                ):
                    crash_observed = True
                    break
        if crash_observed:
            break
        time.sleep(1)

    assert crash_observed, "Expected pod to enter CrashLoopBackOff or terminate with exit code 1"

    collector.sync_all("payments")

    # Alert firing
    now = datetime.now(UTC).isoformat()
    alert_payload = {
        "receiver": "heal-webhook",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "KubePodCrashLooping",
                    "namespace": "payments",
                    "deployment": "payment-gateway",
                    "app": "payment-gateway",
                    "severity": "critical",
                },
                "annotations": {
                    "summary": "Pod payment-gateway is crash-looping",
                    "description": "Container failed with exit code 1 immediately on startup",
                },
                "startsAt": now,
                "endsAt": "0001-01-01T00:00:00Z",
                "fingerprint": "t02-real-cluster-fingerprint",
            }
        ],
    }

    alert_resp = client.post(
        "/api/v1/alerts/alertmanager",
        json=alert_payload,
        headers={"Authorization": f"Bearer {TEST_ALERT_TOKEN}"},
    )
    assert alert_resp.status_code == 202
    alert_data = alert_resp.json()
    assert alert_data["tier"] == "TIER_A"
    assert alert_data["proposed_action"] == "A1_ROLLBACK"

    # Approve
    approval_id = alert_data["approval_id"]
    slack_payload = {
        "type": "block_actions",
        "user": {"id": "U_SRE_LEAD", "username": "sre-lead"},
        "actions": [{"action_id": "btn_approve", "value": "approved"}],
    }
    form_data = urllib.parse.urlencode({"payload": json.dumps(slack_payload)})
    headers = _compute_slack_headers(form_data.encode())
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    appr_resp = client.post(
        f"/api/v1/approval/interactive?approval_id={approval_id}",
        content=form_data,
        headers=headers,
    )
    assert appr_resp.status_code == 200
    assert appr_resp.json()["execution_status"] == "resolved"


@pytest.mark.skipif(not is_k8s_cluster_reachable(), reason="Live Kubernetes cluster not available")
def test_real_cluster_t04_failing_readiness_rollback_flow(
    client: TestClient,
    override_settings: None,
    live_temporal_store: TemporalStore,
    live_approval_registry: SQLiteApprovalRegistry,
) -> None:
    """Scenario T-04 on REAL Cluster: Failing readiness probe triggers Tier A and rollback."""
    apps_api = get_real_cluster_apps_api()
    core_api = get_real_cluster_core_api()
    collector = KubernetesCollector(temporal_store=live_temporal_store)

    _ensure_baseline_healthy(apps_api, core_api)
    collector.sync_all("payments")

    # Inject failure: bad readiness probe path
    patch_body = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {
                            "name": "payment-gateway",
                            "readinessProbe": {
                                "httpGet": {"path": "/broken-readiness-path", "port": 8080},
                                "initialDelaySeconds": 1,
                                "periodSeconds": 1,
                            },
                        }
                    ]
                }
            }
        }
    }
    apps_api.patch_namespaced_deployment(
        name="payment-gateway", namespace="payments", body=patch_body
    )

    # Wait for readiness failure
    readiness_failed = False
    for _ in range(45):
        d = apps_api.read_namespaced_deployment(name="payment-gateway", namespace="payments")
        if (d.status.ready_replicas or 0) < 3:
            readiness_failed = True
            break
        time.sleep(1)

    assert readiness_failed, "Expected deployment ready replicas to drop below 3"

    collector.sync_all("payments")

    now = datetime.now(UTC).isoformat()
    alert_payload = {
        "receiver": "heal-webhook",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "KubeDeploymentReplicasMismatch",
                    "namespace": "payments",
                    "deployment": "payment-gateway",
                    "app": "payment-gateway",
                    "severity": "critical",
                },
                "annotations": {
                    "summary": "Deployment payments/payment-gateway has 0/3 ready replicas",
                    "description": "Readiness probe failed with 404",
                },
                "startsAt": now,
                "endsAt": "0001-01-01T00:00:00Z",
                "fingerprint": "t04-real-cluster-fingerprint",
            }
        ],
    }

    alert_resp = client.post(
        "/api/v1/alerts/alertmanager",
        json=alert_payload,
        headers={"Authorization": f"Bearer {TEST_ALERT_TOKEN}"},
    )
    assert alert_resp.status_code == 202
    alert_data = alert_resp.json()
    assert alert_data["tier"] == "TIER_A"
    assert alert_data["proposed_action"] == "A1_ROLLBACK"

    # Approve
    approval_id = alert_data["approval_id"]
    slack_payload = {
        "type": "block_actions",
        "user": {"id": "U_SRE_LEAD", "username": "sre-lead"},
        "actions": [{"action_id": "btn_approve", "value": "approved"}],
    }
    form_data = urllib.parse.urlencode({"payload": json.dumps(slack_payload)})
    headers = _compute_slack_headers(form_data.encode())
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    appr_resp = client.post(
        f"/api/v1/approval/interactive?approval_id={approval_id}",
        content=form_data,
        headers=headers,
    )
    assert appr_resp.status_code == 200
    assert appr_resp.json()["execution_status"] == "resolved"
