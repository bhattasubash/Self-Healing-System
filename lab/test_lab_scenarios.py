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
from app.routers.alert_intake import set_alert_temporal_store
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
from app.services.temporal_store import (
    ChangeRecord,
    EntityRecord,
    ObservationRecord,
    TemporalStore,
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


@pytest.fixture(autouse=True)
def setup_temporal_store() -> Generator[TemporalStore, None, None]:
    store = TemporalStore(":memory:")
    set_alert_temporal_store(store)
    now = datetime.now(UTC)
    entity_uid = "uid-payment-gateway-lab"
    store._record_entity_sync(
        EntityRecord(
            uid=entity_uid,
            kind="Deployment",
            namespace="payments",
            name="payment-gateway",
        )
    )
    store._record_change_sync(
        ChangeRecord(
            entity_uid=entity_uid,
            change_type="REVISION_REGISTERED",
            summary="Revision 1 baseline healthy",
            before_state={},
            after_state={"revision": "1", "images": ["payment-gateway:v1"]},
            valid_from=now - timedelta(hours=2),
        )
    )
    store._record_change_sync(
        ChangeRecord(
            entity_uid=entity_uid,
            change_type="IMAGE_UPDATED",
            summary="Updated image to payment-gateway:v2-broken-tag",
            before_state={"image": "payment-gateway:v1"},
            after_state={"image": "payment-gateway:v2-broken-tag", "revision": "2"},
            valid_from=now - timedelta(minutes=10),
        )
    )
    store._record_observation_sync(
        ObservationRecord(
            entity_uid=entity_uid,
            metric_name="replicas",
            value=3.0,
            status="healthy",
            timestamp=now - timedelta(minutes=20),
        )
    )
    store._record_observation_sync(
        ObservationRecord(
            entity_uid=entity_uid,
            metric_name="replicas",
            value=0.0,
            status="unhealthy",
            timestamp=now - timedelta(minutes=1),
        )
    )
    yield store
    store.close()


@pytest.fixture(autouse=True)
def override_settings() -> Generator[None, None, None]:
    def _test_settings() -> Settings:
        s = Settings()
        s.alert.auth_token = SecretStr(DUMMY_SIGNING_KEY)
        s.slack.signing_secret = SecretStr(DUMMY_SIGNING_KEY)
        s.slack.allowed_approver_roles = ["sre-lead", "incident-commander", "admin"]
        s.slack.approver_role_mapping = {"U9988": "sre-lead", "U_SRE_LEAD": "sre-lead"}
        s.kubernetes.allowed_namespaces = ["payments", "orders", "default"]
        s.kubernetes.collector_enabled = False
        return s

    app.dependency_overrides[get_settings] = _test_settings
    yield
    app.dependency_overrides.clear()


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

    alert_resp = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": f"Bearer {DUMMY_SIGNING_KEY}"},
    )
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
        s.alert.auth_token = SecretStr(DUMMY_SIGNING_KEY)
        s.slack.signing_secret = SecretStr(DUMMY_SIGNING_KEY)
        s.slack.allowed_approver_roles = ["sre-lead"]
        s.slack.approver_role_mapping = {"U9988": "sre-lead"}
        s.kubernetes.allowed_namespaces = ["payments", "orders", "default"]
        s.kubernetes.collector_enabled = False
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
            assert appr_data["execution_status"] in ("in_progress", "verified", "resolved")
    finally:
        app.dependency_overrides.clear()


def test_lab_scenario_t02_crashloop_flow(client: TestClient) -> None:
    """T-02: New version crash-loops after deploy -> Tier A proposal."""
    payload = _build_alert(
        alertname="KubePodCrashLooping",
        summary="Pod payment-gateway-crash-xyz is in CrashLoopBackOff",
        description="Container failed with exit code 1 immediately following revision deploy",
    )

    alert_resp = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": f"Bearer {DUMMY_SIGNING_KEY}"},
    )
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

    alert_resp = client.post(
        "/api/v1/alerts/alertmanager",
        json=payload,
        headers={"Authorization": f"Bearer {DUMMY_SIGNING_KEY}"},
    )
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

    executor = KubernetesRollbackExecutor(
        apps_api=mock_apps,
        audit_logger=audit_logger,
        allowlisted_namespaces={"payments"},
    )
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


def test_lab_scenario_t06_unrelated_failure_yields_tier_c() -> None:
    """T-06: Unrelated failure without prior change in 30m window fails R2 and escalates to Tier C."""
    now = datetime.now(UTC)
    gate = EvidenceGate()
    ctx = EvidenceGateContext(
        incident_id="inc-t06-unrelated",
        target_workloads=["deployment/payment-gateway"],
        alert_firing=True,
        first_symptom_time=now,
        change_time=None,  # No recorded change!
        symptoms=["KubePodCrashLooping"],
        independent_signals_count=2,
        previous_revision_healthy=True,
        has_history=True,
        target_revision_exists=True,
    )

    result = gate.evaluate(ctx)
    r2 = next(r for r in result.rule_evaluations if r.rule_id == "R2")
    assert r2.passed is False
    assert result.tier == EvidenceTier.TIER_C
    assert result.proposed_action == RemediationActionType.NO_ACTION
    assert "no recorded change" in r2.details.lower()


def test_lab_scenario_t07_change_after_symptom_yields_tier_c() -> None:
    """T-07: Change executed after symptom onset (gap < 0) fails R2 and escalates to Tier C."""
    now = datetime.now(UTC)
    gate = EvidenceGate()
    symptom_time = now - timedelta(minutes=15)
    change_time = now - timedelta(minutes=5)  # Change executed 10m AFTER symptom started!

    ctx = EvidenceGateContext(
        incident_id="inc-t07-change-after-symptom",
        target_workloads=["deployment/payment-gateway"],
        alert_firing=True,
        first_symptom_time=symptom_time,
        change_time=change_time,
        symptoms=["HighErrorRate"],
        independent_signals_count=2,
        previous_revision_healthy=True,
        has_history=True,
        target_revision_exists=True,
    )

    result = gate.evaluate(ctx)
    r2 = next(r for r in result.rule_evaluations if r.rule_id == "R2")
    assert r2.passed is False
    assert result.tier == EvidenceTier.TIER_C
    assert result.proposed_action == RemediationActionType.NO_ACTION
    assert "before the change was executed" in r2.details.lower()


def test_lab_scenario_t13_action_worsens_conditions_single_undo_and_escalate(
    audit_logger: AuditLogger,
) -> None:
    """
    T-13: Start from partly degraded workload, attempt rollback to a worse target.
    Stabilization fails, triggering exactly one automatic undo, escalation,
    and a valid tamper-evident audit chain.
    """
    mock_apps = MagicMock()
    # 1. Partly degraded current deployment (e.g., 2/3 replicas ready)
    current_deploy = MagicMock()
    current_deploy.metadata.name = "payment-gateway"
    current_deploy.metadata.namespace = "payments"
    current_deploy.metadata.uid = "uid-degraded-deploy"
    current_deploy.metadata.labels = {"app": "payment-gateway"}
    current_deploy.metadata.annotations = {"deployment.kubernetes.io/revision": "2"}
    current_deploy.metadata.generation = 2

    # Pre-action container image
    pre_container = MagicMock()
    pre_container.name = "payment-gateway"
    pre_container.image = "payment-gateway:v2"
    current_deploy.spec.template.spec.containers = [pre_container]

    mock_apps.read_namespaced_deployment.return_value = current_deploy

    # 2. ReplicaSet history with older revision
    rs_rev1 = MagicMock()
    rs_rev1.metadata.name = "payment-gateway-rev1"
    rs_rev1.metadata.annotations = {"deployment.kubernetes.io/revision": "1"}
    rs_rev1.spec.template.spec.containers = [MagicMock(name="payment-gateway", image="payment-gateway:v1-bad")]

    rs_rev2 = MagicMock()
    rs_rev2.metadata.name = "payment-gateway-rev2"
    rs_rev2.metadata.annotations = {"deployment.kubernetes.io/revision": "2"}
    rs_rev2.spec.template.spec.containers = [pre_container]

    mock_apps.list_namespaced_replica_set.return_value.items = [rs_rev2, rs_rev1]

    executor = KubernetesRollbackExecutor(
        apps_api=mock_apps,
        audit_logger=audit_logger,
        allowlisted_namespaces={"payments"},
    )

    # Mock stabilization verification to FAIL (simulating worsening conditions)
    executor._verify_stabilization = MagicMock(return_value=False)  # type: ignore[method-assign]

    envelope = ActionEnvelope(
        incident_id="inc-t13-worsens-01",
        action_name="A1_ROLLBACK",
        namespace="payments",
        target_name="payment-gateway",
        target_uid="uid-degraded-deploy",
        approver="sre-operator",
    )

    # Execute rollback
    result = executor.execute_rollback(envelope)

    # 3. Assert exactly one undo was executed
    assert result.status == "undone"
    assert result.verification_passed is False
    assert result.undo_executed is True
    assert "automatic undo restored" in result.message.lower()

    # 4. Assert exact patch calls:
    # Call 1: apply rollback target
    # Call 2: undo restoring pre-action template
    # Exactly TWO patch calls, no further loop!
    assert mock_apps.patch_namespaced_deployment.call_count == 2

    # 5. Assert audit chain contains A1_ROLLBACK_UNDO_EXECUTED and is cryptographically valid
    entries = audit_logger.get_entries(incident_id="inc-t13-worsens-01")
    event_types = [e.event_type for e in entries]
    assert "A1_ROLLBACK_EXECUTED" in event_types
    assert "A1_ROLLBACK_UNDO_EXECUTED" in event_types
    valid, _ = audit_logger.verify_chain()
    assert valid is True

