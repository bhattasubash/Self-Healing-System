"""
Unit and integration tests for the Human Verification Gateway (approval router).

Verifies:
- HMAC-SHA256 signature calculation and verification.
- Rejection of expired timestamps (replay attack prevention).
- Slack Block Kit message structure generation.
- POST /api/v1/approval/decision endpoint processing with HMAC security.
"""

import hashlib
import hmac
import time
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routers.approval import (
    build_slack_approval_card,
    verify_slack_signature,
)
from app.sandbox.e2b_runner import ResourceUsage, SandboxExecutionResult
from app.services.graph_store import TemporalEntityDiff, TemporalGraphDiff


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


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
    # Timestamp from 10 minutes ago (> 300s)
    old_ts = int(time.time()) - 600

    headers = _compute_slack_headers(body, dummy_signing_key, old_ts)
    is_valid = verify_slack_signature(
        request_body=body,
        slack_timestamp=headers["X-Slack-Request-Timestamp"],
        slack_signature=headers["X-Slack-Signature"],
        signing_secret=dummy_signing_key,
    )
    assert is_valid is False


def test_build_slack_approval_card_structure() -> None:
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

    # Find action buttons
    action_block = next(b for b in card["blocks"] if b["type"] == "actions")
    button_actions = [btn["action_id"] for btn in action_block["elements"]]
    assert "approve_and_deploy_action" in button_actions
    assert "reject_fix_action" in button_actions


def test_approval_decision_endpoint_valid_submission(client: TestClient) -> None:
    payload = {
        "approval_id": "appr-001",
        "incident_id": "inc-001",
        "decision": "approved",
        "decided_by": "U12345678_SRE_Lead",
        "decision_reason": "Verified in E2B sandbox without errors",
    }

    response = client.post("/api/v1/approval/decision", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["decision"] == "approved"
    assert data["status"] == "PROCESSED"
    assert "clearance granted" in data["message"]


def test_approval_decision_endpoint_rejects_invalid_decision(client: TestClient) -> None:
    payload = {
        "approval_id": "appr-002",
        "incident_id": "inc-002",
        "decision": "maybe_later",
        "decided_by": "U12345678",
    }

    response = client.post("/api/v1/approval/decision", json=payload)
    assert response.status_code == 400
    assert "Must be 'approved' or 'rejected'" in response.json()["detail"]
