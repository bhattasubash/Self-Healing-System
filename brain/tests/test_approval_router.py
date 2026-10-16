"""
Unit and integration tests for the Human Verification Gateway (approval router).

Verifies:
- HMAC-SHA256 signature calculation and verification.
- Rejection of expired timestamps (replay attack prevention).
- Fail closed behavior when signing secret is missing (unless dev_mode=True).
- Slack Block Kit message structure generation and registry tracking.
- Enforcement of approval existence (404).
- Enforcement of 15-minute TTL expiry (410).
- Enforcement of single-use and idempotency (409 on conflicting resubmission).
- Enforcement of approver role gating (403 on unauthorized user).
- Parsing of real Slack interactive form payload (application/x-www-form-urlencoded).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.config import Settings, get_settings
from app.main import app
from app.routers.approval import (
    build_slack_approval_card,
    get_approval_registry,
    reconcile_in_progress_approvals_on_startup,
    verify_slack_signature,
)
from app.sandbox.e2b_runner import ResourceUsage, SandboxExecutionResult
from app.services.temporal_store import (
    TemporalDiff as TemporalGraphDiff,
)
from app.services.temporal_store import (
    TemporalEntityDiff,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.fixture(autouse=True)
def clean_registry() -> None:
    registry = get_approval_registry()
    registry.clear()


def _compute_slack_headers(
    body: bytes,
    signing_key: str,
    timestamp: int | None = None,
) -> dict[str, str]:
    ts = str(timestamp or int(time.time()))
    basestring = f"v0:{ts}:".encode() + body
    sig = "v0=" + hmac.new(signing_key.encode("utf-8"), basestring, hashlib.sha256).hexdigest()
    return {
        "X-Slack-Request-Timestamp": ts,
        "X-Slack-Signature": sig,
    }


def test_verify_slack_signature_valid() -> None:
    dummy_signing_key = "test_signing_key_12345"
    body = b'{"action": "approve"}'
    ts = int(time.time())

    headers = _compute_slack_headers(body, dummy_signing_key, ts)
    is_valid = verify_slack_signature(
        request_body=body,
        slack_timestamp=headers["X-Slack-Request-Timestamp"],
        slack_signature=headers["X-Slack-Signature"],
        signing_secret=dummy_signing_key,
    )
    assert is_valid is True


def test_verify_slack_signature_rejects_replay_attack() -> None:
    dummy_signing_key = "test_signing_key_12345"
    body = b'{"action": "approve"}'
    old_ts = int(time.time()) - 600

    headers = _compute_slack_headers(body, dummy_signing_key, old_ts)
    is_valid = verify_slack_signature(
        request_body=body,
        slack_timestamp=headers["X-Slack-Request-Timestamp"],
        slack_signature=headers["X-Slack-Signature"],
        signing_secret=dummy_signing_key,
    )
    assert is_valid is False


def test_verify_slack_signature_fails_closed_without_secret() -> None:
    body = b'{"action": "approve"}'
    ts = str(int(time.time()))
    # With empty secret and dev_mode=False, returns False
    assert not verify_slack_signature(
        request_body=body,
        slack_timestamp=ts,
        slack_signature="v0=fake",
        signing_secret="",
        dev_mode=False,
    )
    # With dev_mode=True, returns True
    assert verify_slack_signature(
        request_body=body,
        slack_timestamp=ts,
        slack_signature="v0=fake",
        signing_secret="",
        dev_mode=True,
    )


def test_build_slack_approval_card_structure_and_registration() -> None:
    sandbox_res = SandboxExecutionResult(
        sandbox_id="sbx-123",
        status="pass",
        exit_code=0,
        stdout="Pod rollout completed successfully.",
        stderr="",
        duration_ms=450,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        resource_usage=ResourceUsage(cpu_ms=450, memory_peak_mb=64),
        checksum="sha256:abcd1234abcd1234",
    )

    graph_diff = TemporalGraphDiff(
        t1=datetime.now(UTC),
        t2=datetime.now(UTC),
        node_diffs=[
            TemporalEntityDiff(
                entity_id="MASKED_SVC_payment",
                diff_type="MUTATED",
                modified_keys=["version", "timeout_ms"],
            )
        ],
        relationship_changes=[],
    )

    card = build_slack_approval_card(
        incident_id="inc-9999",
        approval_id="appr-8888",
        severity="critical",
        service_tier="tier0",
        fix_script_language="bash",
        fix_script_content="kubectl rollout restart deploy/payment",
        sandbox_result=sandbox_res,
        graph_diff=graph_diff,
    )

    assert "blocks" in card
    block_types = [b["type"] for b in card["blocks"]]
    assert "header" in block_types
    assert "actions" in block_types

    # Verify request was registered in the registry with pending status
    registry = get_approval_registry()
    record = registry.get_request("appr-8888")
    assert record is not None
    assert record.incident_id == "inc-9999"
    assert record.status == "pending"
    assert record.expires_at > datetime.now(UTC)


def test_approval_endpoint_fails_closed_when_secret_missing(client: TestClient) -> None:
    # Default settings has empty signing_secret and dev_mode=False
    def get_test_settings() -> Settings:
        s = Settings()
        s.slack.signing_secret = SecretStr("")
        s.slack.dev_mode = False
        return s

    app.dependency_overrides[get_settings] = get_test_settings
    try:
        payload = {
            "approval_id": "appr-001",
            "incident_id": "inc-001",
            "decision": "approved",
            "decided_by": "U123_SRE_Lead",
        }
        response = client.post("/api/v1/approval/decision", json=payload)
        assert response.status_code == 500
        assert "Failing closed" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_approval_endpoint_requires_valid_hmac_when_secret_set(client: TestClient) -> None:
    signing_key = "test_signing_secret_xyz"

    def get_test_settings() -> Settings:
        s = Settings()
        s.slack.signing_secret = SecretStr(signing_key)
        s.slack.dev_mode = False
        return s

    app.dependency_overrides[get_settings] = get_test_settings
    try:
        payload = {
            "approval_id": "appr-001",
            "incident_id": "inc-001",
            "decision": "approved",
            "decided_by": "U123_SRE_Lead",
        }
        # 1. Missing HMAC headers
        response = client.post("/api/v1/approval/decision", json=payload)
        assert response.status_code == 401
        assert "Missing required Slack HMAC" in response.json()["detail"]

        # 2. Invalid signature
        headers = {
            "X-Slack-Request-Timestamp": str(int(time.time())),
            "X-Slack-Signature": "v0=badbadbad",
        }
        response = client.post("/api/v1/approval/decision", json=payload, headers=headers)
        assert response.status_code == 401
        assert "signature verification failed" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_approval_endpoint_rejects_nonexistent_approval_id(client: TestClient) -> None:
    def get_dev_settings() -> Settings:
        s = Settings()
        s.slack.dev_mode = True
        return s

    app.dependency_overrides[get_settings] = get_dev_settings
    try:
        payload = {
            "approval_id": "nonexistent-appr",
            "incident_id": "inc-001",
            "decision": "approved",
            "decided_by": "U123_SRE_Lead",
        }
        response = client.post("/api/v1/approval/decision", json=payload)
        assert response.status_code == 404
        assert "not found" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_approval_endpoint_rejects_expired_ttl(client: TestClient) -> None:
    registry = get_approval_registry()
    rec = registry.register_request(
        approval_id="appr-expired",
        incident_id="inc-001",
        ttl_seconds=-10,  # Already expired
    )
    assert rec.expires_at < datetime.now(UTC)

    def get_dev_settings() -> Settings:
        s = Settings()
        s.slack.dev_mode = True
        return s

    app.dependency_overrides[get_settings] = get_dev_settings
    try:
        payload = {
            "approval_id": "appr-expired",
            "incident_id": "inc-001",
            "decision": "approved",
            "decided_by": "U123_SRE_Lead",
        }
        response = client.post("/api/v1/approval/decision", json=payload)
        assert response.status_code == 410
        assert "expired" in response.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_approval_endpoint_enforces_single_use_and_idempotency(client: TestClient) -> None:
    registry = get_approval_registry()
    registry.register_request(
        approval_id="appr-single-use",
        incident_id="inc-001",
        ttl_seconds=900,
    )

    def get_dev_settings() -> Settings:
        s = Settings()
        s.slack.dev_mode = True
        return s

    app.dependency_overrides[get_settings] = get_dev_settings
    try:
        # First decision: Approved
        payload = {
            "approval_id": "appr-single-use",
            "incident_id": "inc-001",
            "decision": "approved",
            "decided_by": "U123_SRE_Lead",
        }
        res1 = client.post("/api/v1/approval/decision", json=payload)
        assert res1.status_code == 200
        assert res1.json()["decision"] == "approved"

        # Idempotent second call: Same decision & same user -> returns 200 with IDEMPOTENT status
        res2 = client.post("/api/v1/approval/decision", json=payload)
        assert res2.status_code == 200
        assert res2.json()["status"] == "PROCESSED_IDEMPOTENT"

        # Conflicting second call: Different decision -> 409 Conflict
        conflicting = {
            "approval_id": "appr-single-use",
            "incident_id": "inc-001",
            "decision": "rejected",
            "decided_by": "U123_SRE_Lead",
        }
        res3 = client.post("/api/v1/approval/decision", json=conflicting)
        assert res3.status_code == 409
        assert "already been processed" in res3.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_approval_endpoint_enforces_approver_role(client: TestClient) -> None:
    registry = get_approval_registry()
    registry.register_request(
        approval_id="appr-role-test",
        incident_id="inc-001",
        allowed_roles=["sre-lead", "incident-commander"],
    )

    def get_test_settings() -> Settings:
        s = Settings()
        s.slack.dev_mode = False
        s.slack.signing_secret = SecretStr("mock_secret")
        s.slack.approver_role_mapping = {
            "U_AUTHORIZED": "sre-lead",
            "U_UNAUTHORIZED": "intern_viewer",
        }
        return s

    app.dependency_overrides[get_settings] = get_test_settings
    try:
        # Unauthorized role -> 403
        body_unauth = json.dumps({
            "approval_id": "appr-role-test",
            "incident_id": "inc-001",
            "decision": "approved",
            "decided_by": "U_UNAUTHORIZED",
        }).encode("utf-8")
        headers_unauth = _compute_slack_headers(body_unauth, "mock_secret")
        headers_unauth["Content-Type"] = "application/json"

        res_unauth = client.post(
            "/api/v1/approval/decision",
            content=body_unauth,
            headers=headers_unauth,
        )
        assert res_unauth.status_code == 403
        assert "not have an authorized approver role" in res_unauth.json()["detail"]

        # Authorized role -> 200
        body_auth = json.dumps({
            "approval_id": "appr-role-test",
            "incident_id": "inc-001",
            "decision": "approved",
            "decided_by": "U_AUTHORIZED",
        }).encode("utf-8")
        headers_auth = _compute_slack_headers(body_auth, "mock_secret")
        headers_auth["Content-Type"] = "application/json"

        res_auth = client.post(
            "/api/v1/approval/decision",
            content=body_auth,
            headers=headers_auth,
        )
        assert res_auth.status_code == 200
        assert res_auth.json()["decision"] == "approved"
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_approval_endpoint_parses_real_slack_interactive_payload(client: TestClient) -> None:
    registry = get_approval_registry()
    registry.register_request(
        approval_id="appr-slack-interactive",
        incident_id="inc-slack-01",
        allowed_roles=["sre-lead"],
    )

    signing_key = "slack_interactivity_secret"

    def get_test_settings() -> Settings:
        s = Settings()
        s.slack.dev_mode = False
        s.slack.signing_secret = SecretStr(signing_key)
        s.slack.approver_role_mapping = {"U998877": "sre-lead"}
        return s

    app.dependency_overrides[get_settings] = get_test_settings
    try:
        # Slack sends POST with Content-Type: application/x-www-form-urlencoded
        # Body: payload=<url-encoded-json>
        slack_payload_dict = {
            "type": "block_actions",
            "user": {
                "id": "U998877",
                "username": "lead_operator",
                "name": "Alex",
            },
            "actions": [
                {
                    "action_id": "approve_and_deploy_action",
                    "value": "appr-slack-interactive:approved",
                    "type": "button",
                }
            ],
            "trigger_id": "123456.789",
        }
        raw_payload_str = json.dumps(slack_payload_dict)
        form_body_str = urllib.parse.urlencode({"payload": raw_payload_str})
        form_body_bytes = form_body_str.encode("utf-8")

        headers = _compute_slack_headers(form_body_bytes, signing_key)
        headers["Content-Type"] = "application/x-www-form-urlencoded"

        response = client.post(
            "/api/v1/approval/decision",
            content=form_body_bytes,
            headers=headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["approval_id"] == "appr-slack-interactive"
        assert data["incident_id"] == "inc-slack-01"
        assert data["decision"] == "approved"
        assert data["status"] == "PROCESSED"
        assert "U998877" in data["message"]
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_decision_endpoint_validates_response_url_host(client: TestClient) -> None:
    """The decision/interactive endpoint rejects untrusted response_url hosts with HTTP 400."""
    reg = get_approval_registry()
    reg.clear()
    reg.register_request(
        approval_id="appr-url-check",
        incident_id="inc-url-01",
        target_service="payment-service",
        allowed_roles=["admin"],
    )

    def get_test_settings() -> Settings:
        s = Settings()
        s.slack.dev_mode = True
        return s

    app.dependency_overrides[get_settings] = get_test_settings
    try:
        # 1. Malicious / untrusted response_url
        evil_payload = {
            "type": "block_actions",
            "user": {"id": "U12345", "username": "admin_user"},
            "response_url": "https://malicious-internal-server.local/ssrf",
            "actions": [
                {
                    "action_id": "approve_and_deploy_action",
                    "value": "appr-url-check:approved",
                    "type": "button",
                }
            ],
        }
        form_evil = urllib.parse.urlencode({"payload": json.dumps(evil_payload)}).encode("utf-8")
        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        resp_evil = client.post("/api/v1/approval/decision", content=form_evil, headers=headers)
        assert resp_evil.status_code == 400
        assert "Invalid response_url" in resp_evil.json()["detail"]
        assert "hooks.slack.com" in resp_evil.json()["detail"]

        # 2. Valid response_url on hooks.slack.com
        valid_payload = {
            "type": "block_actions",
            "user": {"id": "U12345", "username": "admin_user"},
            "response_url": "https://hooks.slack.com/actions/T123/B456/abcdef123456",
            "actions": [
                {
                    "action_id": "approve_and_deploy_action",
                    "value": "appr-url-check:approved",
                    "type": "button",
                }
            ],
        }
        form_valid = urllib.parse.urlencode({"payload": json.dumps(valid_payload)}).encode("utf-8")

        resp_valid = client.post("/api/v1/approval/decision", content=form_valid, headers=headers)
        assert resp_valid.status_code == 200
        assert resp_valid.json()["status"] == "PROCESSED"
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_crash_recovery_on_startup_reconciles_in_progress_approvals() -> None:
    """
    Requirement 3: Crash recovery finds approvals left in 'in_progress' state
    (simulating a crash mid-execution), reconciles against cluster state,
    marks them as 'needs_human_review', creates an audit entry, and alerts Slack.
    """
    from unittest.mock import MagicMock, patch

    reg = get_approval_registry()
    reg.clear()

    # Create an approval that was mid-execution when brain was killed
    reg.register_request(
        approval_id="appr-crash-01",
        incident_id="inc-crash-01",
        target_service="order-processor",
        namespace="checkout",
        allowed_roles=["sre-lead"],
    )
    rec = reg.get_request("appr-crash-01")
    assert rec is not None
    rec.status = "APPROVED"
    rec.execution_status = "in_progress"
    rec.decided_by = "U_SRE_LEAD"
    rec.decided_at = datetime.now(UTC)
    reg.update_record(rec)

    # Verify get_in_progress_approvals finds it
    in_progress = reg.get_in_progress_approvals()
    assert len(in_progress) == 1
    assert in_progress[0].approval_id == "appr-crash-01"

    # Mock cluster state
    mock_apps = MagicMock()
    mock_deploy = MagicMock()
    mock_deploy.metadata.annotations = {"deployment.kubernetes.io/revision": "4"}
    mock_deploy.spec.replicas = 3
    mock_deploy.status.ready_replicas = 3
    mock_apps.read_namespaced_deployment.return_value = mock_deploy

    test_settings = Settings()
    test_settings.slack.approval_channel = "C_ALERTS"
    test_settings.slack.bot_token = SecretStr("xoxb-fake-token")

    slack_posted_payloads: list[dict] = []

    def mock_post(url: str, **kwargs: Any) -> Any:
        slack_posted_payloads.append(kwargs)
        res = MagicMock()
        res.status_code = 200
        return res

    with (
        patch("httpx.Client.post", side_effect=mock_post),
    ):
        reconciled = reconcile_in_progress_approvals_on_startup(
            registry=reg,
            settings=test_settings,
            apps_api=mock_apps,
        )

    assert len(reconciled) == 1
    updated_rec = reg.get_request("appr-crash-01")
    assert updated_rec is not None
    assert updated_rec.execution_status == "needs_human_review"
    assert "Crash recovery reconcile" in (updated_rec.decision_reason or "")
    assert updated_rec.audit_hash is not None
    assert len(updated_rec.audit_hash) == 64

    # Verify Slack was notified
    assert len(slack_posted_payloads) == 1
    posted_text = slack_posted_payloads[0]["json"]["text"]
    assert "CRASH RECOVERY ALERT" in posted_text
    assert "appr-crash-01" in posted_text
    assert "needs_human_review" in posted_text
    assert "checkout/order-processor" in posted_text


def test_concurrent_approvals_for_same_workload_rejected(client: TestClient) -> None:
    """
    Requirement 4 (F-09/F-10): Concurrent approvals for the same workload:
    second one is rejected with a clear explanation (HTTP 409).
    """
    reg = get_approval_registry()
    reg.clear()

    # 1. Register first approval and set it to in_progress
    reg.register_request(
        approval_id="appr-workload-active",
        incident_id="inc-wk-01",
        target_service="payment-gw",
        namespace="payments",
        allowed_roles=["admin"],
    )
    rec1 = reg.get_request("appr-workload-active")
    assert rec1 is not None
    rec1.status = "APPROVED"
    rec1.execution_status = "in_progress"
    rec1.decided_by = "U_ADMIN_1"
    reg.update_record(rec1)

    # 2. Register second approval for the same workload (payments/payment-gw)
    reg.register_request(
        approval_id="appr-workload-second",
        incident_id="inc-wk-02",
        target_service="payment-gw",
        namespace="payments",
        allowed_roles=["admin"],
    )

    def get_test_settings() -> Settings:
        s = Settings()
        s.slack.dev_mode = True
        return s

    app.dependency_overrides[get_settings] = get_test_settings
    try:
        # Attempt to approve the second request while the first is in progress
        response = client.post(
            "/api/v1/approval/decision",
            json={
                "approval_id": "appr-workload-second",
                "incident_id": "inc-wk-02",
                "decision": "approved",
                "decided_by": "U_ADMIN_2",
            },
        )
        assert response.status_code == 409
        detail = response.json()["detail"]
        assert "active remediation in progress" in detail
        assert "payments/payment-gw" in detail
        assert "appr-workload-active" in detail
    finally:
        app.dependency_overrides.pop(get_settings, None)


def test_workload_cooldown_enforced(client: TestClient) -> None:
    """
    Requirement 4 (F-09/F-10): Per-workload cooldown window prevents rapid-fire
    sequential actions on the same workload.
    """
    reg = get_approval_registry()
    reg.clear()

    # 1. Complete an approval for payments/payment-gw just now
    reg.register_request(
        approval_id="appr-cd-completed",
        incident_id="inc-cd-01",
        target_service="payment-gw",
        namespace="payments",
        allowed_roles=["admin"],
    )
    rec1 = reg.get_request("appr-cd-completed")
    assert rec1 is not None
    rec1.status = "APPROVED"
    rec1.execution_status = "completed"
    rec1.decided_by = "U_ADMIN_1"
    rec1.decided_at = datetime.now(UTC)
    reg.update_record(rec1)

    # 2. Register a new approval for the same workload
    reg.register_request(
        approval_id="appr-cd-next",
        incident_id="inc-cd-02",
        target_service="payment-gw",
        namespace="payments",
        allowed_roles=["admin"],
    )

    def get_test_settings() -> Settings:
        s = Settings()
        s.slack.dev_mode = True
        s.kubernetes.workload_cooldown_seconds = 1800  # 30 minutes
        return s

    app.dependency_overrides[get_settings] = get_test_settings
    try:
        response = client.post(
            "/api/v1/approval/decision",
            json={
                "approval_id": "appr-cd-next",
                "incident_id": "inc-cd-02",
                "decision": "approved",
                "decided_by": "U_ADMIN_2",
            },
        )
        assert response.status_code == 409
        detail = response.json()["detail"]
        assert "is in cooldown until" in detail
        assert "payments/payment-gw" in detail
        assert "PRD F-09/F-10" in detail
    finally:
        app.dependency_overrides.pop(get_settings, None)


