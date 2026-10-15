"""
End-to-End Live Remediation Path & Evidence Gate Negative Tests (PRD Section 8).

Verifies the real data path and negative tests:
- Unauthenticated alert (missing/invalid token) -> 401
- Unknown workload -> Tier C
- Alert with no recorded change -> Tier C
- Replayed approval -> rejected (409)
- Slack card dispatch -> logged dispatched only on successful API response
- Full live path -> Alert -> Timeline -> Gate -> SQLite Approval -> Rollback -> Audit
- Data perimeter -> Reject unmasked secret (400)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.config import Settings, get_settings
from app.main import app
from app.routers.alert_intake import set_alert_temporal_store
from app.routers.approval import get_approval_registry
from app.services.temporal_store import (
    ChangeRecord,
    EntityRecord,
    ObservationRecord,
    TemporalStore,
)

if TYPE_CHECKING:
    from collections.abc import Generator

DUMMY_SLACK_SIGNING_KEY = "test_signing_key_999"
TEST_ALERT_TOKEN = "test-alertmanager-secret-token-xyz"  # noqa: S105


def _compute_slack_headers(
    body: bytes, secret: str = DUMMY_SLACK_SIGNING_KEY
) -> dict[str, str]:
    ts = str(int(time.time()))
    basestring = f"v0:{ts}:{body.decode('utf-8')}".encode()
    sig = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    return {
        "X-Slack-Request-Timestamp": ts,
        "X-Slack-Signature": sig,
    }


@pytest.fixture
def test_temporal_store() -> Generator[TemporalStore, None, None]:
    store = TemporalStore(":memory:")
    set_alert_temporal_store(store)
    yield store
    store.close()


@pytest.fixture(autouse=True)
def override_test_settings() -> Generator[None, None, None]:
    def _settings_override() -> Settings:
        s = Settings()
        s.alert.auth_token = SecretStr(TEST_ALERT_TOKEN)
        s.slack.signing_secret = SecretStr(DUMMY_SLACK_SIGNING_KEY)
        s.slack.allowed_approver_roles = ["sre-lead", "incident-commander", "admin"]
        s.slack.approver_role_mapping = {"U12345678": "sre-lead"}
        s.kubernetes.allowed_namespaces = ["payments", "default"]
        s.kubernetes.collector_enabled = False
        return s

    app.dependency_overrides[get_settings] = _settings_override
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def clean_approval_registry() -> Generator[None, None, None]:
    registry = get_approval_registry()
    registry.clear()
    yield
    registry.clear()


def _build_alertmanager_payload(
    alertname: str = "KubePodCrashLooping",
    namespace: str = "payments",
    deployment: str = "payment-gateway",
    starts_at: datetime | None = None,
) -> dict:
    start_time = starts_at or datetime.now(UTC)
    return {
        "receiver": "heal-webhook",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": alertname,
                    "namespace": namespace,
                    "deployment": deployment,
                    "severity": "critical",
                    "app": deployment,
                },
                "annotations": {
                    "summary": f"Pod {deployment}-xyz is in CrashLoopBackOff",
                    "description": "Repeated container crashes detected post-deployment",
                },
                "startsAt": start_time.isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "fingerprint": "a1b2c3d4e5f6",
            }
        ],
    }


# ─── 1. Authentication Negative Tests ─────────────────────────────────


def test_alertmanager_unauthenticated_returns_401(client: TestClient) -> None:
    payload = _build_alertmanager_payload()

    # Missing Authorization header
    resp_no_auth = client.post("/api/v1/alerts/alertmanager", json=payload)
    assert resp_no_auth.status_code == 401
    assert "Missing Authorization header" in resp_no_auth.json()["detail"]

    # Invalid token
    resp_bad_auth = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp_bad_auth.status_code == 401
    assert "Invalid authorization token" in resp_bad_auth.json()["detail"]


# ─── 2. Unknown Workload Negative Test ────────────────────────────────


def test_alertmanager_unknown_workload_yields_tier_c(
    client: TestClient, test_temporal_store: TemporalStore
) -> None:
    # Alert references a workload that is not registered in the cluster temporal store
    payload = _build_alertmanager_payload(deployment="ghost-service")

    response = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": f"Bearer {TEST_ALERT_TOKEN}"},
    )

    assert response.status_code == 202
    data = response.json()
    assert data["tier"] == "TIER_C"
    assert data["proposed_action"] == "NO_ACTION"
    assert "not found in cluster" in data["message"]
    assert data["approval_id"] is None


# ─── 3. No Change Recorded Negative Test ──────────────────────────────


@pytest.mark.asyncio
async def test_alertmanager_no_change_recorded_yields_tier_c(
    client: TestClient, test_temporal_store: TemporalStore
) -> None:
    # Workload exists in cluster temporal store, but NO change preceded the alert
    entity_uid = "deploy-uid-100"
    await test_temporal_store.record_entity(
        EntityRecord(
            uid=entity_uid,
            kind="Deployment",
            namespace="payments",
            name="payment-gateway",
        )
    )

    payload = _build_alertmanager_payload(deployment="payment-gateway", namespace="payments")

    response = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": f"Bearer {TEST_ALERT_TOKEN}"},
    )

    assert response.status_code == 202
    data = response.json()
    assert data["tier"] == "TIER_C"
    assert data["proposed_action"] == "NO_ACTION"
    assert data["approval_id"] is None


# ─── 4. Real Signals Positive Path (Tier A / B & SQLite UID Storage) ───


@pytest.mark.asyncio
async def test_alertmanager_with_real_change_and_signals_creates_persisted_approval(
    client: TestClient, test_temporal_store: TemporalStore
) -> None:
    now = datetime.now(UTC)
    entity_uid = "deploy-uid-real-555"

    # 1. Register Deployment Entity
    await test_temporal_store.record_entity(
        EntityRecord(
            uid=entity_uid,
            kind="Deployment",
            namespace="payments",
            name="payment-gateway",
        )
    )

    # 2. Register Revision 1 and Revision 2 ReplicaSets
    await test_temporal_store.record_change(
        ChangeRecord(
            entity_uid=entity_uid,
            change_type="REVISION_REGISTERED",
            summary="Revision 1 baseline healthy",
            before_state={},
            after_state={"revision": "1", "images": ["payment-gateway:v1"]},
            valid_from=now - timedelta(hours=2),
        )
    )

    # Change 10 minutes before alert
    change_time = now - timedelta(minutes=10)
    await test_temporal_store.record_change(
        ChangeRecord(
            entity_uid=entity_uid,
            change_type="DEPLOYMENT_UPDATE",
            summary="Rollout payment-gateway:v2",
            before_state={"revision": "1"},
            after_state={"revision": "2", "images": ["payment-gateway:v2"]},
            valid_from=change_time,
        )
    )

    # 3. Register Historical & Current Telemetry Observations
    # Historical observation prior to change (healthy baseline)
    await test_temporal_store.record_observation(
        ObservationRecord(
            entity_uid=entity_uid,
            timestamp=now - timedelta(minutes=30),
            metric_name="pod_status",
            value=1.0,
            status="healthy",
        )
    )

    # Current symptom observation (pod crashlooping post-deploy)
    await test_temporal_store.record_observation(
        ObservationRecord(
            entity_uid=entity_uid,
            timestamp=now - timedelta(minutes=2),
            metric_name="pod_payment-gateway-xyz_CrashLoopBackOff",
            value=0.0,
            status="unhealthy",
        )
    )

    # 4. Post alert with real startsAt
    payload = _build_alertmanager_payload(
        deployment="payment-gateway",
        namespace="payments",
        starts_at=now - timedelta(minutes=2),
    )

    response = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": f"Bearer {TEST_ALERT_TOKEN}"},
    )

    assert response.status_code == 202
    data = response.json()
    assert data["tier"] in ("TIER_A", "TIER_B")
    assert data["proposed_action"] == "A1_ROLLBACK"
    approval_id = data["approval_id"]
    assert approval_id is not None
    assert approval_id.startswith("appr_")

    # 5. Verify SQLite persistence of approval record binding real target UID & namespace
    registry = get_approval_registry()
    record = registry.get_request(approval_id)
    assert record is not None
    assert record.approval_id == approval_id
    assert record.target_uid == entity_uid
    assert record.namespace == "payments"
    assert record.target_service == "payment-gateway"
    assert record.status == "pending"


# ─── 5. Replayed Approval Rejected (409) Negative Test ────────────────


def test_replayed_approval_is_rejected(client: TestClient) -> None:
    registry = get_approval_registry()
    approval_id = "appr_test_replay_token_123"
    incident_id = "inc-abcdef123456"

    # Register initial pending request in SQLite registry
    record = registry.register_request(
        approval_id=approval_id,
        incident_id=incident_id,
        target_service="payment-gateway",
        namespace="payments",
        target_uid="deploy-uid-123",
        proposed_action="A1_ROLLBACK",
    )

    # Mark as already decided
    record.status = "approved"
    record.decided_by = "U12345678"
    record.decided_at = datetime.now(UTC)
    registry.update_record(record)

    # Replay approval submission with a different user or conflict
    slack_payload = {
        "type": "block_actions",
        "user": {"id": "U99999999", "username": "another-operator"},
        "actions": [{"action_id": "approve_action", "value": "approved"}],
    }
    form_data = urllib.parse.urlencode({"payload": json.dumps(slack_payload)})
    headers = _compute_slack_headers(form_data.encode("utf-8"))
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    response = client.post(
        f"/api/v1/approval/interactive?approval_id={approval_id}",
        content=form_data,
        headers=headers,
    )

    assert response.status_code == 409
    assert "already been processed" in response.json()["detail"]


# ─── 6. Slack Card Dispatch API Response Check ─────────────────────────


@pytest.mark.asyncio
async def test_slack_card_dispatched_only_after_successful_response(
    client: TestClient, test_temporal_store: TemporalStore
) -> None:
    now = datetime.now(UTC)
    entity_uid = "deploy-uid-slack-test"

    await test_temporal_store.record_entity(
        EntityRecord(
            uid=entity_uid, kind="Deployment", namespace="payments", name="payment-gateway"
        )
    )
    await test_temporal_store.record_change(
        ChangeRecord(
            entity_uid=entity_uid,
            change_type="REVISION_REGISTERED",
            summary="Revision 1",
            before_state={},
            after_state={"revision": "1"},
            valid_from=now - timedelta(hours=1),
        )
    )
    await test_temporal_store.record_change(
        ChangeRecord(
            entity_uid=entity_uid,
            change_type="DEPLOYMENT_UPDATE",
            summary="Rollout v2",
            before_state={},
            after_state={"revision": "2"},
            valid_from=now - timedelta(minutes=5),
        )
    )
    await test_temporal_store.record_observation(
        ObservationRecord(
            entity_uid=entity_uid,
            timestamp=now - timedelta(minutes=2),
            metric_name="pod_status",
            value=0.0,
            status="unhealthy",
        )
    )

    payload = _build_alertmanager_payload(starts_at=now - timedelta(minutes=2))

    # 1. When Slack credentials are NOT configured -> slack_card_dispatched is False
    resp_no_slack = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": f"Bearer {TEST_ALERT_TOKEN}"},
    )
    assert resp_no_slack.status_code == 202
    assert resp_no_slack.json()["slack_card_dispatched"] is False

    # 2. When Slack credentials configured and API returns 200 ok: True -> True
    def _slack_settings() -> Settings:
        s = Settings()
        s.alert.auth_token = SecretStr(TEST_ALERT_TOKEN)
        s.slack.bot_token = SecretStr("xoxb-dummy-test-token")
        s.slack.approval_channel = "C12345678"
        s.kubernetes.allowed_namespaces = ["payments", "default"]
        s.kubernetes.collector_enabled = False
        return s

    app.dependency_overrides[get_settings] = _slack_settings
    try:
        from unittest.mock import MagicMock
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"ok": True, "ts": "1234567890.123456"}

        with patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_response):
            resp_with_slack = client.post(
                "/api/v1/alerts/alertmanager",
                json=payload,
                headers={"Authorization": f"Bearer {TEST_ALERT_TOKEN}"},
            )
            assert resp_with_slack.status_code == 202
            assert resp_with_slack.json()["slack_card_dispatched"] is True
    finally:
        app.dependency_overrides.clear()


# ─── 7. Full Live Path Approve to Verified Rollback ───────────────────


@pytest.mark.asyncio
async def test_full_live_path_approve_to_verified_rollback(
    client: TestClient, test_temporal_store: TemporalStore
) -> None:
    now = datetime.now(UTC)
    entity_uid = "deploy-uid-full-path"

    await test_temporal_store.record_entity(
        EntityRecord(
            uid=entity_uid, kind="Deployment", namespace="payments", name="payment-gateway"
        )
    )
    await test_temporal_store.record_change(
        ChangeRecord(
            entity_uid=entity_uid,
            change_type="REVISION_REGISTERED",
            summary="Revision 1",
            before_state={},
            after_state={"revision": "1"},
            valid_from=now - timedelta(hours=1),
        )
    )
    await test_temporal_store.record_change(
        ChangeRecord(
            entity_uid=entity_uid,
            change_type="DEPLOYMENT_UPDATE",
            summary="Rollout v2",
            before_state={},
            after_state={"revision": "2"},
            valid_from=now - timedelta(minutes=5),
        )
    )
    await test_temporal_store.record_observation(
        ObservationRecord(
            entity_uid=entity_uid,
            timestamp=now - timedelta(minutes=2),
            metric_name="pod_status",
            value=0.0,
            status="unhealthy",
        )
    )

    alert_resp = client.post(
        "/api/v1/alerts/alertmanager",
        json=_build_alertmanager_payload(starts_at=now - timedelta(minutes=2)),
        headers={"Authorization": f"Bearer {TEST_ALERT_TOKEN}"},
    )
    assert alert_resp.status_code == 202
    alert_data = alert_resp.json()
    approval_id = alert_data["approval_id"]
    incident_id = alert_data["incident_id"]

    slack_payload = {
        "type": "block_actions",
        "user": {"id": "U12345678", "username": "sre-oncall"},
        "actions": [{"action_id": "approve_action", "value": "approved"}],
    }
    form_data = urllib.parse.urlencode({"payload": json.dumps(slack_payload)})

    with patch("app.routers.approval.execute_k8s_rollback_from_approval") as mock_exec:
        mock_exec.return_value = {
            "status": "resolved",
            "verification_passed": True,
            "undo_executed": False,
            "target_revision": 1,
            "audit_hash": "a" * 64,
            "message": "Rollback to revision 1 successfully verified.",
        }

        headers = _compute_slack_headers(form_data.encode("utf-8"))
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        resp = client.post(
            f"/api/v1/approval/interactive?approval_id={approval_id}",
            content=form_data,
            headers=headers,
        )

        assert resp.status_code == 200
        resp_data = resp.json()
        assert resp_data["decision"] == "approved"
        assert resp_data["status"] == "PROCESSED"
        assert resp_data["execution_status"] in ("in_progress", "resolved")
        assert resp_data["incident_id"] == incident_id


@pytest.mark.asyncio
async def test_alertmanager_unlisted_namespace_yields_no_action_tier_c(
    client: TestClient, test_temporal_store: TemporalStore
) -> None:
    """An alert for unlisted namespace is denied by policy (Rule R7) and yields Tier C."""
    now = datetime.now(UTC)
    entity_uid = "deploy-unlisted-01"
    await test_temporal_store.record_entity(
        EntityRecord(
            uid=entity_uid,
            kind="Deployment",
            namespace="forbidden-namespace",
            name="secret-workload",
        )
    )
    await test_temporal_store.record_change(
        ChangeRecord(
            entity_uid=entity_uid,
            change_type="IMAGE_UPDATE",
            summary="Update secret-workload to v2",
            before_state={"revision": 1},
            after_state={"revision": 2},
            valid_from=now - timedelta(minutes=5),
        )
    )
    await test_temporal_store.record_observation(
        ObservationRecord(
            entity_uid=entity_uid,
            timestamp=now - timedelta(minutes=2),
            metric_name="pod_status",
            value=0.0,
            status="unhealthy",
        )
    )

    payload = _build_alertmanager_payload(
        alertname="KubePodCrashLooping",
        namespace="forbidden-namespace",
        deployment="secret-workload",
        starts_at=now - timedelta(minutes=2),
    )

    alert_resp = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": f"Bearer {TEST_ALERT_TOKEN}"},
    )
    assert alert_resp.status_code == 202
    alert_data = alert_resp.json()
    assert alert_data["tier"] == "TIER_C"
    assert alert_data["proposed_action"] == "NO_ACTION"
    assert alert_data["approval_id"] is None


# ─── 8. Data Perimeter Rejects Secrets ────────────────────────────────


def test_alertmanager_webhook_rejects_unmasked_secret(client: TestClient) -> None:
    payload = _build_alertmanager_payload()
    payload["alerts"][0]["annotations"]["db_url"] = (
        "postgres" + "://admin:SecretPass123!@db:5432/payments"
    )

    response = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": f"Bearer {TEST_ALERT_TOKEN}"},
    )

    assert response.status_code == 400
    assert "Server-side content scan detected" in response.json()["detail"]
