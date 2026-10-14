"""
Lab Scenarios Test Suite: T-01, T-02, T-04 and GitOps / Migration Gates.

Verifies acceptance criteria for PRD Section 13.1 scenarios:
- T-01: Bad image tag deploy -> Tier A, A1 Rollback proposed, verified, audited.
- T-02: New version crash-loops -> Tier A, A1 Rollback proposed, verified.
- T-04: Failing readiness probe -> Tier A, A1 Rollback proposed, verified.
- T-09: Deploy labeled as containing migration -> R5 fails, Tier C escalation.
- GitOps guard: Argo CD managed workload blocks direct rollback.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
import time
import urllib.parse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

# Ensure brain/app is importable when running from root or lab
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "brain"))

import pytest
from app.config import Settings, get_settings
from app.main import app
from app.routers.approval import get_approval_registry
from app.services.audit_logger import AuditLogger
from app.services.evidence_gate import (
    EvidenceGate,
    EvidenceGateContext,
    EvidenceTier,
    RemediationActionType,
)
from app.services.k8s_executor import (
    ActionEnvelope,
    KubernetesRollbackExecutor,
    PreconditionFailedError,
)
from fastapi.testclient import TestClient
from pydantic import SecretStr

if TYPE_CHECKING:
    from collections.abc import Generator

DUMMY_SIGNING_KEY = "test_lab_signing_key_777"


def _compute_slack_headers(body: bytes, secret: str = DUMMY_SIGNING_KEY) -> dict[str, str]:
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


@pytest.fixture(autouse=True)
def clean_registry() -> Generator[None, None, None]:
    reg = get_approval_registry()
    reg.clear()
    yield
    reg.clear()


@pytest.fixture
def audit_logger() -> Generator[AuditLogger, None, None]:
    logger = AuditLogger(db_path=":memory:")
    yield logger
    logger.close()


def _build_alert(
    alertname: str,
    summary: str,
    description: str,
    deployment: str = "payment-gateway",
    namespace: str = "payments",
) -> dict:
    now = datetime.now(UTC).isoformat()
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
                    "app": deployment,
                    "severity": "critical",
                },
                "annotations": {
                    "summary": summary,
                    "description": description,
                },
                "startsAt": now,
                "endsAt": "0001-01-01T00:00:00Z",
                "fingerprint": f"fingerprint-{alertname}",
            }
        ],
    }


def test_lab_scenario_t01_bad_image_tag_flow(client: TestClient) -> None:
    """T-01: Bad image tag deploy triggers Tier A rollback proposal and verified execution."""
    payload = _build_alert(
        alertname="KubeDeploymentRolloutStuck",
        summary="Deployment payments/payment-gateway rollout is stuck",
        description="ImagePullBackOff: Failed to pull image 'hashicorp/http-echo:v2-broken-tag'",
    )

    alert_resp = client.post("/api/v1/alerts/alertmanager", json=payload)
    assert alert_resp.status_code == 202
    data = alert_resp.json()

    assert data["status"] == "accepted"
    assert data["tier"] == "TIER_A"
    assert data["proposed_action"] == "A1_ROLLBACK"
    assert data["approval_id"] is not None

    approval_id = data["approval_id"]

    # Operator approves via Slack interactive webhook
    slack_payload = {
        "type": "block_actions",
        "user": {"id": "U9988", "username": "sre-lead"},
        "api_app_id": "A0123",
        "actions": [{"action_id": "btn_approve", "value": "approved", "action_ts": str(time.time())}],
    }
    form_data = urllib.parse.urlencode({"payload": json.dumps(slack_payload)})

    def get_test_settings() -> Settings:
        s = Settings()
        s.slack.signing_secret = SecretStr(DUMMY_SIGNING_KEY)
        s.slack.allowed_approver_roles = ["sre-lead"]
        s.slack.approver_role_mapping = {"U9988": "sre-lead"}
        return s

    mock_rollback_res = {
        "status": "verified",
        "verification_passed": True,
        "undo_executed": False,
        "target_revision": 1,
        "message": "Deployment payments/payment-gateway rolled back to revision 1 and verified healthy.",
        "audit_hash": "sha256:lab_t01_audit_hash_abc",
        "dry_run_diff": "- image: hashicorp/http-echo:v2-broken-tag\n+ image: hashicorp/http-echo:0.2.3",
    }

    app.dependency_overrides[get_settings] = get_test_settings
    try:
        with patch(
            "app.routers.approval.execute_k8s_rollback_from_approval",
            return_value=mock_rollback_res,
        ):
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
            assert appr_data["execution_status"] == "verified"
            assert appr_data["audit_hash"] == "sha256:lab_t01_audit_hash_abc"
    finally:
        app.dependency_overrides.clear()


def test_lab_scenario_t02_crashloop_flow(client: TestClient) -> None:
    """T-02: New version crash-loops after deploy -> Tier A proposal."""
    payload = _build_alert(
        alertname="KubePodCrashLooping",
        summary="Pod payment-gateway-crash-xyz is in CrashLoopBackOff",
        description="Container failed with exit code 1 immediately following revision deploy",
    )

    alert_resp = client.post("/api/v1/alerts/alertmanager", json=payload)
    assert alert_resp.status_code == 202
    data = alert_resp.json()

    assert data["status"] == "accepted"
    assert data["tier"] == "TIER_A"
    assert data["proposed_action"] == "A1_ROLLBACK"


def test_lab_scenario_t04_failing_readiness_flow(client: TestClient) -> None:
    """T-04: Failing readiness probe after deploy -> Tier A proposal."""
    payload = _build_alert(
        alertname="KubeDeploymentReplicasMismatch",
        summary="Deployment payments/payment-gateway has 0/3 ready replicas",
        description="Readiness probe failed: HTTP GET /broken-probe-endpoint returned 404",
    )

    alert_resp = client.post("/api/v1/alerts/alertmanager", json=payload)
    assert alert_resp.status_code == 202
    data = alert_resp.json()

    assert data["status"] == "accepted"
    assert data["tier"] == "TIER_A"
    assert data["proposed_action"] == "A1_ROLLBACK"


def test_lab_scenario_t09_migration_blocked_from_rollback() -> None:
    """T-09: Deploy labeled as containing a database migration fails R5 and escalates to Tier C."""
    now = datetime.now(UTC)
    gate = EvidenceGate()
    ctx = EvidenceGateContext(
        incident_id="inc-t09-migration",
        target_workloads=["deployment/payment-gateway"],
        alert_firing=True,
        first_symptom_time=now,
        change_time=now - timedelta(minutes=5),
        symptoms=["KubePodCrashLooping"],
        independent_signals_count=2,
        previous_revision_healthy=True,
        has_history=True,
        target_revision_exists=True,
        has_irreversible_migration=True,  # Migration present!
    )

    result = gate.evaluate(ctx)
    r5 = next(r for r in result.rule_evaluations if r.rule_id == "R5")
    assert r5.passed is False
    assert result.tier == EvidenceTier.TIER_C
    assert result.proposed_action == RemediationActionType.NO_ACTION
    assert "irreversible database/schema migration" in r5.details


def test_lab_scenario_gitops_managed_workload_blocks_direct_rollback(
    audit_logger: AuditLogger,
) -> None:
    """GitOps management guard (Argo CD) prevents manual rollback and directs to revert PR."""
    mock_apps = MagicMock()
    mock_deploy = MagicMock()
    mock_deploy.metadata.name = "payment-gateway"
    mock_deploy.metadata.namespace = "payments"
    mock_deploy.metadata.uid = "uid-gitops-deploy"
    # Labeled as managed by Argo CD
    mock_deploy.metadata.labels = {"argocd.argoproj.io/instance": "payments-app"}
    mock_deploy.metadata.annotations = {}
    mock_apps.read_namespaced_deployment.return_value = mock_deploy

    executor = KubernetesRollbackExecutor(apps_api=mock_apps, audit_logger=audit_logger)
    envelope = ActionEnvelope(
        incident_id="inc-gitops-01",
        action_name="A1_ROLLBACK",
        namespace="payments",
        target_name="payment-gateway",
        target_uid="uid-gitops-deploy",
        approver="sre-operator",
    )

    with pytest.raises(PreconditionFailedError, match=r"GitOps-managed workload"):
        executor.check_preconditions(envelope)
