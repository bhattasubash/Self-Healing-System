"""
Human Verification Gateway & Slack Block Kit Integration Router.

Provides the human-in-the-loop write-access gate:
1. Secure HMAC signature validation against Slack signing secret (fails closed).
2. Replay attack prevention via strict timestamp drift verification (< 300s).
3. Slack Block Kit message generator combining:
   - Incident severity badge and service tier.
   - Graph state mutation diff (from BiTemporalGraphStore / TemporalStore).
   - E2B Micro-Sandbox validation logs and exit status.
   - Interactive [Approve & Deploy Fix] and [Reject] action buttons.
4. Decision callback processing at POST /api/v1/approval/decision:
   - Real Slack Block Kit interactive payload parsing (application/x-www-form-urlencoded).
   - Approver identity extracted directly from verified Slack payload.
   - Enforces approval existence, 15-minute TTL, single-use, and approver role.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.parse
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Annotated, Any

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from app.config import Settings, get_settings
from app.utils.validation import validate_incident_id

if TYPE_CHECKING:
    from app.sandbox.e2b_runner import SandboxExecutionResult
    from app.services.temporal_store import TemporalDiff as TemporalGraphDiff

router = APIRouter(prefix="/api/v1/approval", tags=["Approval Gate"])
logger = structlog.get_logger()

# Maximum allowed clock drift for Slack webhook requests (5 minutes)
SLACK_TIMESTAMP_TOLERANCE_SECONDS = 300


# ─── Stateful Approval Registry ────────────────────────────────────────


class ApprovalRecord(BaseModel):
    """Tracked state for a human remediation approval request."""

    approval_id: str
    incident_id: str
    status: str = "pending"  # "pending" | "approved" | "rejected" | "expired"
    created_at: datetime
    expires_at: datetime
    target_service: str = ""
    proposed_action: str = ""
    allowed_roles: list[str] = Field(
        default_factory=lambda: ["sre-lead", "incident-commander", "admin"]
    )
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_reason: str | None = None


class ApprovalRegistry:
    """
    Registry enforcing existence, TTL, single-use, and role gating for approvals.
    """

    def __init__(self, default_ttl_seconds: int = 900) -> None:
        self._records: dict[str, ApprovalRecord] = {}
        self._default_ttl_seconds = default_ttl_seconds

    def register_request(
        self,
        approval_id: str,
        incident_id: str,
        target_service: str = "",
        proposed_action: str = "",
        ttl_seconds: int | None = None,
        allowed_roles: list[str] | None = None,
    ) -> ApprovalRecord:
        now = datetime.now(UTC)
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds
        record = ApprovalRecord(
            approval_id=approval_id,
            incident_id=validate_incident_id(incident_id),
            status="pending",
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            target_service=target_service,
            proposed_action=proposed_action,
            allowed_roles=allowed_roles or ["sre-lead", "incident-commander", "admin"],
        )
        self._records[approval_id] = record
        return record

    def get_request(self, approval_id: str) -> ApprovalRecord | None:
        return self._records.get(approval_id)

    def clear(self) -> None:
        self._records.clear()


_GLOBAL_APPROVAL_REGISTRY = ApprovalRegistry()


def get_approval_registry() -> ApprovalRegistry:
    return _GLOBAL_APPROVAL_REGISTRY


# ─── Request / Response Models ─────────────────────────────────────────


class ApprovalDecisionPayload(BaseModel):
    """Payload submitted when a human operator makes an approval decision."""

    approval_id: str
    incident_id: str
    decision: str = Field(description="'approved' | 'rejected'")
    decided_by: str = Field(description="Slack User ID or Email of human operator")
    decision_reason: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("incident_id")
    @classmethod
    def check_incident_id(cls, v: str) -> str:
        return validate_incident_id(v)


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
    dev_mode: bool = False,
) -> bool:
    """
    Verifies incoming webhook requests against Slack's HMAC-SHA256 protocol:
    1. Replay attack check: abs(now - slack_timestamp) <= 300s.
    2. Basestring construction: "v0:{timestamp}:{body}".
    3. HMAC-SHA256 digest comparison using constant-time compare_digest.
    Fails closed if signing_secret is empty unless explicit dev_mode is True.
    """
    if not signing_secret:
        return dev_mode

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


# ─── Role Resolution Helper ───────────────────────────────────────────


def resolve_approver_role(user_identifier: str, settings: Settings) -> str | None:
    """
    Resolves the approver role for a user identifier.
    Checks direct mapping first, then role keywords, then dev_mode fallback.
    """
    if user_identifier in settings.slack.approver_role_mapping:
        return settings.slack.approver_role_mapping[user_identifier]

    lower_id = user_identifier.lower()
    for role in settings.slack.allowed_approver_roles:
        norm_role = role.replace("-", "_").lower()
        if norm_role in lower_id:
            return role

    if settings.slack.dev_mode:
        return "admin"

    return None


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
    registry: ApprovalRegistry | None = None,
    ttl_seconds: int = 900,
    allowed_roles: list[str] | None = None,
) -> dict[str, Any]:
    """
    Generates a rich Slack Block Kit interactive message card and registers the
    approval request in the ApprovalRegistry.
    """
    validate_incident_id(incident_id)

    # Register in approval store with 15m default TTL (PRD D-19, Section 8)
    reg = registry or get_approval_registry()
    reg.register_request(
        approval_id=approval_id,
        incident_id=incident_id,
        target_service=service_tier,
        proposed_action=fix_script_content[:200],
        ttl_seconds=ttl_seconds,
        allowed_roles=allowed_roles,
    )

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
        for d in graph_diff.node_diffs[:5]:
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
    settings: Annotated[Settings, Depends(get_settings)],
    registry: Annotated[ApprovalRegistry, Depends(get_approval_registry)],
    x_slack_signature: str | None = Header(None, alias="X-Slack-Signature"),
    x_slack_request_timestamp: str | None = Header(None, alias="X-Slack-Request-Timestamp"),
) -> ApprovalDecisionResponse:
    """
    Validates human approval decision with HMAC authentication:
    1. Fails closed if signing secret is missing (unless explicit dev_mode is True).
    2. Validates Slack HMAC-SHA256 signature when secret is configured.
    3. Parses Slack interactive payload (application/x-www-form-urlencoded) or JSON.
    4. Extracts verified approver identity from Slack payload.
    5. Enforces approval existence, 15-minute TTL, single-use, and approver role.
    """
    secret = settings.slack.signing_secret.get_secret_value()
    body_bytes = await request.body()

    # Fail closed if signing secret is missing and dev_mode is off
    if not secret:
        if not settings.slack.dev_mode:
            logger.critical("slack_signing_secret_missing_fail_closed")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Slack signing secret is not configured and dev_mode is False. "
                    "Failing closed."
                ),
            )
    else:
        # Secret is configured: enforce HMAC signature
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
            dev_mode=settings.slack.dev_mode,
        ):
            logger.error("invalid_slack_hmac_signature")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication failed: Slack HMAC signature verification failed",
            )

    # Parse Slack interactive payload or JSON
    content_type = request.headers.get("content-type", "").lower()
    approval_id: str = ""
    decision_str: str = ""
    decided_by: str = ""
    decision_reason: str | None = None
    incident_id: str | None = None

    if "application/x-www-form-urlencoded" in content_type or body_bytes.startswith(b"payload="):
        # Slack Block Kit interactive callback
        parsed_form = urllib.parse.parse_qs(body_bytes.decode("utf-8"))
        if "payload" not in parsed_form:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Missing 'payload' form field in Slack interactive request.",
            )
        try:
            slack_data = json.loads(parsed_form["payload"][0])
        except Exception as json_err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Malformed Slack JSON payload: {json_err}",
            ) from json_err

        user = slack_data.get("user", {})
        decided_by = user.get("id") or user.get("username") or ""
        if not decided_by:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not extract approver identity from Slack payload.",
            )

        actions = slack_data.get("actions", [])
        if not actions:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No actions found in Slack interactive payload.",
            )
        action = actions[0]
        action_val = action.get("value", "")
        if ":" in action_val:
            approval_id, decision_str = action_val.split(":", 1)
        else:
            approval_id = action_val
            decision_str = "approved" if "approve" in action.get("action_id", "") else "rejected"
    else:
        # JSON payload (direct API submission / dev_mode)
        try:
            json_body = json.loads(body_bytes.decode("utf-8"))
        except Exception as json_err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Malformed JSON body: {json_err}",
            ) from json_err

        approval_id = json_body.get("approval_id", "")
        incident_id = json_body.get("incident_id")
        decision_str = json_body.get("decision", "")
        decided_by = json_body.get("decided_by", "")
        decision_reason = json_body.get("decision_reason")

    decision_norm = decision_str.lower().strip()
    if decision_norm not in ("approved", "rejected"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid decision '{decision_str}'. Must be 'approved' or 'rejected'.",
        )

    # 1. Enforce Approval Existence
    record = registry.get_request(approval_id)
    if not record:
        logger.warning("approval_request_not_found", approval_id=approval_id)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Approval request '{approval_id}' not found.",
        )

    # Validate incident_id match if provided in JSON
    if incident_id and incident_id != record.incident_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Mismatched incident_id: expected '{record.incident_id}', got '{incident_id}'.",
        )

    # 2. Enforce TTL (15 minutes default, PRD Section 8)
    now = datetime.now(UTC)
    if now > record.expires_at:
        record.status = "expired"
        logger.warning(
            "approval_request_expired",
            approval_id=approval_id,
            expires_at=record.expires_at.isoformat(),
        )
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail=(
                f"Approval request '{approval_id}' has expired at "
                f"{record.expires_at.isoformat()}."
            ),
        )

    # 3. Enforce Single-Use & Idempotency
    if record.status in ("approved", "rejected"):
        if record.status == decision_norm and record.decided_by == decided_by:
            return ApprovalDecisionResponse(
                approval_id=record.approval_id,
                incident_id=record.incident_id,
                decision=record.status,
                status="PROCESSED_IDEMPOTENT",
                recorded_at=record.decided_at or now,
                message=(
                    f"Idempotent: decision '{record.status}' already "
                    f"recorded by {record.decided_by}."
                ),
            )
        logger.warning(
            "approval_single_use_violation",
            approval_id=approval_id,
            current_status=record.status,
            current_decided_by=record.decided_by,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Approval request '{approval_id}' has already been processed with "
                f"decision '{record.status}' by {record.decided_by}."
            ),
        )

    # 4. Enforce Approver Role
    approver_role = resolve_approver_role(decided_by, settings)
    if not approver_role or approver_role not in record.allowed_roles:
        logger.warning(
            "unauthorized_approver_role",
            decided_by=decided_by,
            resolved_role=approver_role,
            allowed_roles=record.allowed_roles,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"User '{decided_by}' does not have an authorized approver role "
                f"(allowed: {record.allowed_roles})."
            ),
        )

    # Finalize record
    record.status = decision_norm
    record.decided_by = decided_by
    record.decided_at = now
    record.decision_reason = decision_reason

    logger.info(
        "approval_decision_recorded",
        approval_id=record.approval_id,
        incident_id=record.incident_id,
        decision=decision_norm,
        decided_by=decided_by,
        role=approver_role,
        reason=decision_reason,
    )

    msg = (
        f"Fix approved by {decided_by} ({approver_role}). Deployment clearance granted."
        if decision_norm == "approved"
        else f"Fix rejected by {decided_by} ({approver_role}). Deployment aborted."
    )

    return ApprovalDecisionResponse(
        approval_id=record.approval_id,
        incident_id=record.incident_id,
        decision=decision_norm,
        status="PROCESSED",
        recorded_at=now,
        message=msg,
    )
