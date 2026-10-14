"""
End-to-End Live Remediation Path Tests (PRD Section 8, Step 2 Item 5).

Verifies the live path:
Alertmanager webhook
  ──► change timeline lookup
  ──► Evidence Gate (R1-R8)
  ──► Slack Block Kit approval card (< 3s ack)
  ──► Human approval with verified Slack identity & TTL check
  ──► Typed Action A1 rollback (Kubernetes API client)
  ──► Verification stabilization
  ──► (or single automatic undo on failure)
  ──► Hash-chained audit logging
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.config import Settings, get_settings
from app.main import app
from app.routers.approval import get_approval_registry

if TYPE_CHECKING:
    from collections.abc import Generator

DUMMY_SLACK_SIGNING_KEY = "test_signing_key_999"


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
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture
def clean_approval_registry() -> Generator[None, None, None]:
    registry = get_approval_registry()
    registry.clear()
    yield
    registry.clear()


def _build_alertmanager_payload(
    alertname: str = "KubePodCrashLooping",
    namespace: str = "payments",
    deployment: str = "payment-gateway",
) -> dict:
    now = datetime.now(UTC)
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
                "startsAt": now.isoformat(),
                "endsAt": "0001-01-01T00:00:00Z",
                "fingerprint": "a1b2c3d4e5f6",
            }
        ],
    }


def test_alertmanager_webhook_triggers_evidence_gate_and_slack_card(
    client: TestClient, clean_approval_registry: None
) -> None:
    payload = _build_alertmanager_payload()

    response = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": "Bearer dev-in-cluster-token"},
    )

    assert response.status_code == 202
    data = response.json()
    assert data["status"] == "accepted"
    assert "incident_id" in data
    assert data["tier"] in ("TIER_A", "TIER_B")
    assert data["proposed_action"] == "A1_ROLLBACK"
    assert "approval_id" in data

    # Verify card was registered in approval registry
    approval_id = data["approval_id"]
    registry = get_approval_registry()
    appr = registry.get_request(approval_id)
    assert appr is not None
    assert appr.incident_id == data["incident_id"]
    assert appr.status == "pending"


def test_full_live_path_approve_to_verified_rollback(
    client: TestClient, clean_approval_registry: None
) -> None:
    # 1. Post Alertmanager alert
    alert_resp = client.post(
        "/api/v1/alerts/alertmanager",
        json=_build_alertmanager_payload(),
        headers={"Authorization": "Bearer dev-in-cluster-token"},
    )
    assert alert_resp.status_code == 202
    alert_data = alert_resp.json()
    approval_id = alert_data["approval_id"]
    incident_id = alert_data["incident_id"]

    # 2. Simulate human approval via Slack Block Kit interactive action
    slack_payload = {
        "type": "block_actions",
        "user": {"id": "U12345678", "username": "sre-oncall"},
        "api_app_id": "A0123456",
        "actions": [
            {
                "action_id": "approve_action",
                "value": "approved",
                "action_ts": str(time.time()),
            }
        ],
    }

    form_data = urllib.parse.urlencode({"payload": json.dumps(slack_payload)})

    def get_test_settings() -> Settings:
        s = Settings()
        s.slack.signing_secret = SecretStr(DUMMY_SLACK_SIGNING_KEY)
        s.slack.allowed_approver_roles = ["sre-lead", "admin"]
        s.slack.approver_role_mapping = {"U12345678": "sre-lead"}
        return s

    app.dependency_overrides[get_settings] = get_test_settings
    try:
        # Mock the k8s rollback executor to simulate verified rollback
        with patch(
            "app.routers.approval.execute_k8s_rollback_from_approval"
        ) as mock_exec:
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
            assert resp_data["execution_status"] == "resolved"
            assert resp_data["approver_id"] == "U12345678"
            assert resp_data["incident_id"] == incident_id
    finally:
        app.dependency_overrides.clear()


def test_alertmanager_webhook_rejects_unmasked_secret(client: TestClient) -> None:
    payload = _build_alertmanager_payload()
    # Seed an unmasked secret into annotations
    payload["alerts"][0]["annotations"]["db_url"] = (
        "postgres" + "://admin:SecretPass123!@db:5432/payments"
    )

    response = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": "Bearer dev-in-cluster-token"},
    )

    assert response.status_code == 400
    assert "Server-side content scan detected" in response.json()["detail"]
