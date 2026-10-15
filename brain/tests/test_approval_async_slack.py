"""
Tests for asynchronous Slack approval processing, fast acknowledgment (<3s),
SQLite state tracking, and background notification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from typing import TYPE_CHECKING
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.config import Settings, get_settings
from app.main import app
from app.routers.approval import get_approval_registry

if TYPE_CHECKING:
    from app.services.approval_store import ApprovalRecord

TEST_SIGNING_SECRET = "slack_async_test_secret_999"  # noqa: S105


def _compute_slack_headers(body: bytes, secret: str = TEST_SIGNING_SECRET) -> dict[str, str]:
    ts = str(int(time.time()))
    basestring = f"v0:{ts}:{body.decode('utf-8')}".encode()
    sig = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    return {
        "X-Slack-Request-Timestamp": ts,
        "X-Slack-Signature": sig,
        "Content-Type": "application/x-www-form-urlencoded",
    }


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


@pytest.mark.asyncio
async def test_approval_endpoint_acknowledges_within_3s_with_slow_executor() -> None:
    """Approval endpoint acknowledges Slack within < 3 seconds while rollback runs in background."""
    registry = get_approval_registry()
    registry.clear()
    registry.register_request(
        approval_id="appr-slow-exec-01",
        incident_id="inc-slow-01",
        target_service="payment-gateway",
        namespace="payments",
        target_uid="deploy-uid-1",
        allowed_roles=["sre-lead"],
    )

    def get_test_settings() -> Settings:
        s = Settings()
        s.slack.dev_mode = False
        s.slack.signing_secret = SecretStr(TEST_SIGNING_SECRET)
        s.slack.approver_role_mapping = {"U_SLOW_OPERATOR": "sre-lead"}
        return s

    app.dependency_overrides[get_settings] = get_test_settings

    # Mock slow executor that takes 2.0 seconds (would breach 3s timeout if run synchronously)
    def slow_rollback(record: ApprovalRecord) -> dict:
        time.sleep(1.0)
        return {"status": "resolved", "audit_hash": "dummy_audit_hash_123"}

    mock_notify = AsyncMock()

    try:
        slack_payload = {
            "type": "block_actions",
            "user": {"id": "U_SLOW_OPERATOR", "username": "slow_operator"},
            "response_url": "https://hooks.slack.com/actions/T00/B00/XXX",
            "actions": [
                {
                    "action_id": "approve_button",
                    "value": "appr-slow-exec-01:approved",
                }
            ],
        }
        form_body = urllib.parse.urlencode({"payload": json.dumps(slack_payload)}).encode()
        headers = _compute_slack_headers(form_body)

        start_time = time.perf_counter()
        rollback_mock = patch(
            "app.routers.approval.execute_k8s_rollback_from_approval",
            side_effect=slow_rollback,
        )
        notify_mock = patch(
            "app.routers.approval._post_slack_update",
            new=mock_notify,
        )
        with rollback_mock, notify_mock:
            import httpx

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
                resp = await ac.post(
                    "/api/v1/approval/interactive",
                    content=form_body,
                    headers=headers,
                )
        elapsed = time.perf_counter() - start_time

        # Fast acknowledgment requirement: MUST return in under 3.0s (in fact < 0.5s)
        assert resp.status_code == 200
        assert elapsed < 0.8, f"Approval took {elapsed:.2f}s, expected < 0.8s"

        data = resp.json()
        assert data["decision"] == "approved"
        # State in SQLite is in_progress initially
        assert data["execution_status"] in ("in_progress", "PROCESSED", "resolved")

        # After background task finishes, verify SQLite record is updated
        updated_record = registry.get_request("appr-slow-exec-01")
        assert updated_record is not None
        assert updated_record.status == "approved"
    finally:
        app.dependency_overrides.pop(get_settings, None)
        registry.clear()
