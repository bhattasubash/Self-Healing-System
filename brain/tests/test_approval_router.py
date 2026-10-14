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
    verify_slack_signature,
)
from app.sandbox.e2b_runner import ResourceUsage, SandboxExecutionResult
from app.services.graph_store import TemporalEntityDiff, TemporalGraphDiff


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
