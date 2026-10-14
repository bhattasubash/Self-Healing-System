"""
Human Verification Gateway & Slack Block Kit Integration Router.

Provides the human-in-the-loop write-access gate:
1. Secure HMAC signature validation against Slack signing secret.
2. Replay attack prevention via strict timestamp drift verification (< 300s).
3. Slack Block Kit message generator combining:
   - Incident severity badge and service tier.
   - Graph state mutation diff (from BiTemporalGraphStore).
   - E2B Micro-Sandbox validation logs and exit status.
   - Interactive [Approve & Deploy Fix] and [Reject] action buttons.
4. Decision callback processing at POST /api/v1/approval/decision.
"""

from __future__ import annotations

import hashlib
import hmac
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

from app.config import Settings, get_settings

if TYPE_CHECKING:
    from app.sandbox.e2b_runner import SandboxExecutionResult
    from app.services.graph_store import TemporalGraphDiff

router = APIRouter(prefix="/api/v1/approval", tags=["Approval Gate"])
logger = structlog.get_logger()

# Maximum allowed clock drift for Slack webhook requests (5 minutes)
SLACK_TIMESTAMP_TOLERANCE_SECONDS = 300


# ─── Request / Response Models ─────────────────────────────────────────


class ApprovalDecisionPayload(BaseModel):
    """Payload submitted when a human operator makes an approval decision."""

    approval_id: str
    incident_id: str
    decision: str = Field(description="'approved' | 'rejected'")
    decided_by: str = Field(description="Slack User ID or Email of human operator")
    decision_reason: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ApprovalDecisionResponse(BaseModel):
    """Response returned post-human validation."""

    approval_id: str
    incident_id: str
    decision: str
    status: str
    recorded_at: datetime
    message: str


# ─── HMAC Verification Guard ──────────────────────────────────────────


def verify_slack_signature(
    request_body: bytes,
    slack_timestamp: str,
    slack_signature: str,
    signing_secret: str,
) -> bool:
    """
    Verifies incoming webhook requests against Slack's HMAC-SHA256 protocol:
    1. Replay attack check: abs(now - slack_timestamp) <= 300s.
    2. Basestring construction: "v0:{timestamp}:{body}".
    3. HMAC-SHA256 digest comparison using constant-time compare_digest.
    """
    if not signing_secret:
        # Development fallback only if no secret is configured
        return True

    # 1. Check for replay attack
    try:
        ts = int(slack_timestamp)
        now = int(time.time())
        if abs(now - ts) > SLACK_TIMESTAMP_TOLERANCE_SECONDS:
            logger.warning("slack_timestamp_out_of_bounds", request_ts=ts, current_ts=now)
            return False
    except (ValueError, TypeError):
        return False

    # 2. Build canonical base string
    sig_basestring = f"v0:{slack_timestamp}:".encode() + request_body

    # 3. Compute HMAC digest
    computed_digest = hmac.new(
        signing_secret.encode("utf-8"),
        sig_basestring,
        hashlib.sha256,
    ).hexdigest()
    expected_signature = f"v0={computed_digest}"

    # 4. Constant-time comparison
    return hmac.compare_digest(expected_signature, slack_signature)


# ─── Slack Block Kit Card Generator ───────────────────────────────────


def build_slack_approval_card(
    incident_id: str,
    approval_id: str,
    severity: str,
    service_tier: str,
    fix_script_language: str,
    fix_script_content: str,
    sandbox_result: SandboxExecutionResult,
    graph_diff: TemporalGraphDiff | None = None,
) -> dict[str, Any]:
    """
    Generates a rich Slack Block Kit interactive message card combining:
    - Incident status & service tier badge.
    - Graph structural mutation diff (root-cause evidence).
    - E2B Sandbox validation status and logs.
    - Full fix script preview with SHA-256 checksum.
    - Interactive [Approve & Deploy Fix] and [Reject] action buttons.
    """
    status_emoji = "🟢 PASS" if sandbox_result.status == "pass" else "🔴 FAIL"
    severity_badge = f"*{severity.upper()}* ({service_tier.upper()})"

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "🚨 Human Verification Required — Infrastructure Remediation",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Incident ID:*\n`{incident_id}`"},
                {"type": "mrkdwn", "text": f"*Severity & Tier:*\n{severity_badge}"},
                {
                    "type": "mrkdwn",
                    "text": (
                        f"*Sandbox Validation:*\n{status_emoji} "
                        f"(Exit: {sandbox_result.exit_code})"
                    ),
                },
                {"type": "mrkdwn", "text": f"*Execution Runtime:*\n{sandbox_result.duration_ms}ms"},
            ],
        },
        {"type": "divider"},
    ]

    # Topology Graph Diff Section (if available)
    if graph_diff and graph_diff.node_diffs:
        diff_lines = []
        for d in graph_diff.node_diffs[:5]:  # Show top 5 mutated entities
            if d.diff_type == "MUTATED":
                diff_lines.append(
                    f"• `[MUTATED]` {d.entity_id} (keys: {', '.join(d.modified_keys)})"
                )
            elif d.diff_type == "CREATED":
                diff_lines.append(f"• `[CREATED]` {d.entity_id}")
            elif d.diff_type == "TERMINATED":
                diff_lines.append(f"• `[TERMINATED]` {d.entity_id}")

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    "*Bi-Temporal State Graph Diffs (Baseline ➔ Incident):*\n"
                    + "\n".join(diff_lines)
                ),
            },
        })

    # Sandbox Logs Section
    log_sample = (
        sandbox_result.stdout.strip()
        or sandbox_result.stderr.strip()
        or "No output logged."
    )
    truncated_logs = log_sample[:1000] + ("..." if len(log_sample) > 1000 else "")

    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": f"*E2B Micro-Sandbox Logs:*\n```{truncated_logs}```",
        },
    })

    # Proposed Fix Script Section
    truncated_script = fix_script_content[:1200] + ("..." if len(fix_script_content) > 1200 else "")
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": (
                f"*Proposed Remediation Script ({fix_script_language}):*\n"
                f"```{truncated_script}```\n"
                f"*Checksum:* `{sandbox_result.checksum}`"
            ),
        },
    })

    blocks.append({"type": "divider"})

    # Interactive Action Buttons
    blocks.append({
        "type": "actions",
        "elements": [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Approve & Deploy Fix", "emoji": True},
                "style": "primary",
                "value": f"{approval_id}:approved",
                "action_id": "approve_and_deploy_action",
            },
            {
                "type": "button",
                "text": {"type": "plain_text", "text": "Reject Fix", "emoji": True},
                "style": "danger",
                "value": f"{approval_id}:rejected",
                "action_id": "reject_fix_action",
            },
        ],
    })

    return {
        "text": f"Remediation approval required for incident {incident_id}",
        "blocks": blocks,
    }


# ─── Approval Decision Endpoint ────────────────────────────────────────


@router.post(
    "/decision",
    response_model=ApprovalDecisionResponse,
    status_code=status.HTTP_200_OK,
    summary="Process human approval or rejection decision from Slack Block Kit gateway",
)
async def process_approval_decision(
    request: Request,
    payload: ApprovalDecisionPayload,
    settings: Annotated[Settings, Depends(get_settings)],
    x_slack_signature: str | None = Header(None, alias="X-Slack-Signature"),
    x_slack_request_timestamp: str | None = Header(None, alias="X-Slack-Request-Timestamp"),
) -> ApprovalDecisionResponse:
    """
    Validates human approval decision with HMAC authentication:
    1. Validates Slack HMAC-SHA256 signature when secret is configured.
    2. Rejects invalid or expired callbacks.
    3. Records approval decision in audit logs and returns deployment clearance.
    """
    body_bytes = await request.body()
    secret = settings.slack.signing_secret.get_secret_value()

    # Verify HMAC if secret is configured
    if secret:
        if not x_slack_signature or not x_slack_request_timestamp:
            logger.error("missing_slack_hmac_headers")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed: Missing required Slack HMAC signature headers",
            )

        if not verify_slack_signature(
            request_body=body_bytes,
            slack_timestamp=x_slack_request_timestamp,
            slack_signature=x_slack_signature,
            signing_secret=secret,
        ):
            logger.error("invalid_slack_hmac_signature")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed: Slack HMAC signature verification failed",
            )

    decision_norm = payload.decision.lower().strip()
    if decision_norm not in ("approved", "rejected"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid decision '{payload.decision}'. Must be 'approved' or 'rejected'.",
        )

    logger.info(
        "approval_decision_recorded",
        approval_id=payload.approval_id,
        incident_id=payload.incident_id,
        decision=decision_norm,
        decided_by=payload.decided_by,
        reason=payload.decision_reason,
    )

    msg = (
        f"Fix approved by {payload.decided_by}. Deployment clearance granted."
        if decision_norm == "approved"
        else f"Fix rejected by {payload.decided_by}. Deployment aborted."
    )

    return ApprovalDecisionResponse(
        approval_id=payload.approval_id,
        incident_id=payload.incident_id,
        decision=decision_norm,
        status="PROCESSED",
        recorded_at=datetime.now(UTC),
        message=msg,
    )
