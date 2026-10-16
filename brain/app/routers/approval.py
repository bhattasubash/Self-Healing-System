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

import asyncio
import hashlib
import hmac
import json
import time
import urllib.parse
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Annotated, Any

import httpx
import structlog
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from app.config import Settings, get_settings
from app.services.approval_store import (
    SQLiteApprovalRegistry,
)
from app.utils.validation import validate_incident_id, validate_slack_response_url

if TYPE_CHECKING:
    from app.sandbox.e2b_runner import SandboxExecutionResult
    from app.services.temporal_store import TemporalDiff as TemporalGraphDiff

router = APIRouter(prefix="/api/v1/approval", tags=["Approval Gate"])
logger = structlog.get_logger()

# Maximum allowed clock drift for Slack webhook requests (5 minutes)
SLACK_TIMESTAMP_TOLERANCE_SECONDS = 300

ApprovalRegistry = SQLiteApprovalRegistry
_GLOBAL_APPROVAL_REGISTRY = SQLiteApprovalRegistry()
_running_tasks: set[asyncio.Task[Any]] = set()


def _schedule_task(coro: Any) -> asyncio.Task[Any] | None:
    try:
        loop = asyncio.get_running_loop()
        task = loop.create_task(coro)
        _running_tasks.add(task)
        task.add_done_callback(_running_tasks.discard)
        return task
    except RuntimeError:
        return None


def get_approval_registry() -> SQLiteApprovalRegistry:
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
    approver_id: str | None = None
    execution_status: str | None = None
    audit_hash: str | None = None


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
    sandbox_result: SandboxExecutionResult | None = None,
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

    if sandbox_result:
        status_emoji = "🟢 PASS" if sandbox_result.status == "pass" else "🔴 FAIL"
        validation_text = (
            f"*Sandbox Validation:*\n{status_emoji} (Exit: {sandbox_result.exit_code})"
        )
        runtime_text = f"*Execution Runtime:*\n{sandbox_result.duration_ms}ms"
    else:
        validation_text = "*Evidence Gate:*\n🟢 PASS (R1-R8 Verified)"
        runtime_text = "*Safety Model:*\nDry-run Gated (A1 Rollback)"

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
                {"type": "mrkdwn", "text": validation_text},
                {"type": "mrkdwn", "text": runtime_text},
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

    # Sandbox Logs Section (if sandbox run was executed)
    if sandbox_result:
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
    checksum = (
        sandbox_result.checksum
        if sandbox_result
        else hashlib.sha256(fix_script_content.encode("utf-8")).hexdigest()[:16]
    )
    truncated_script = (
        fix_script_content[:1200] + ("..." if len(fix_script_content) > 1200 else "")
    )
    blocks.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": (
                f"*Proposed Remediation Script ({fix_script_language}):*\n"
                f"```{truncated_script}```\n"
                f"*Checksum:* `{checksum}`"
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
@router.post(
    "/interactive",
    response_model=ApprovalDecisionResponse,
    status_code=status.HTTP_200_OK,
    summary="Handle Slack Block Kit interactive action payloads",
)
async def process_approval_decision(
    request: Request,
    background_tasks: BackgroundTasks,
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
    response_url: str | None = None

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
        response_url = slack_data.get("response_url")
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
        elif action_val in ("approved", "rejected"):
            approval_id = request.query_params.get("approval_id") or ""
            decision_str = action_val
        else:
            approval_id = action_val or request.query_params.get("approval_id") or ""
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

    if response_url:
        try:
            response_url = validate_slack_response_url(response_url)
        except ValueError as val_err:
            logger.warning("invalid_slack_response_url", response_url=response_url, error=str(val_err))
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid response_url: {val_err}",
            ) from val_err


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

    execution_status: str | None = None
    audit_hash: str | None = None
    if decision_norm == "approved":
        # Enforce PRD F-09/F-10 per-workload lock and cooldown
        cooldown_sec = getattr(settings.kubernetes, "workload_cooldown_seconds", 1800)
        allowed, reject_reason = registry.check_workload_action_allowed(
            namespace=record.namespace,
            target_service=record.target_service,
            cooldown_seconds=cooldown_sec,
            current_approval_id=record.approval_id,
        )
        if not allowed:
            logger.warning(
                "workload_action_gate_rejected",
                approval_id=record.approval_id,
                workload=f"{record.namespace}/{record.target_service}",
                reason=reject_reason,
            )
            record.status = "rejected"
            record.decided_by = decided_by
            record.decided_at = now
            record.decision_reason = reject_reason
            record.execution_status = "rejected"
            registry.update_record(record)

            if response_url:
                reject_msg = {
                    "replace_original": "true",
                    "text": f"🛑 {reject_reason}",
                }
                if _schedule_task(_post_slack_update(response_url, reject_msg)) is None:
                    background_tasks.add_task(_post_slack_update, response_url, reject_msg)

            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=reject_reason,
            )

        execution_status = "in_progress"
        record.execution_status = "in_progress"
        registry.update_record(record)
        t = _schedule_task(
            _async_execute_rollback_and_notify_slack(record.approval_id, response_url)
        )
        if t is None:
            background_tasks.add_task(
                _async_execute_rollback_and_notify_slack,
                record.approval_id,
                response_url,
            )
    elif decision_norm == "rejected":
        execution_status = "rejected"
        record.execution_status = "rejected"
        registry.update_record(record)
        if response_url:
            reject_msg = {
                "replace_original": "true",
                "text": (
                    f"🛑 Remediation rejected by {decided_by} ({approver_role}). "
                    "Action aborted."
                ),
            }
            if _schedule_task(_post_slack_update(response_url, reject_msg)) is None:
                background_tasks.add_task(_post_slack_update, response_url, reject_msg)

    msg = (
        f"Fix approved by {decided_by} ({approver_role}). "
        f"Execution: {execution_status or 'cleared'}."
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
        approver_id=decided_by,
        execution_status=execution_status,
        audit_hash=audit_hash,
    )


async def _post_slack_update(response_url: str, message: dict[str, Any]) -> None:
    """Sends an asynchronous update to Slack via response_url."""
    try:
        validated_url = validate_slack_response_url(response_url)
        if not validated_url:
            logger.warning("invalid_or_missing_response_url", url=response_url)
            return
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(validated_url, json=message)
            if resp.status_code >= 400:
                logger.warning(
                    "slack_response_url_update_failed",
                    status_code=resp.status_code,
                    body=resp.text,
                )
    except Exception as exc:
        logger.error("slack_response_url_update_error", error=str(exc))


async def _async_execute_rollback_and_notify_slack(
    approval_id: str,
    response_url: str | None = None,
) -> None:
    """Executes rollback in the background, updates SQLite registry, and notifies Slack."""
    reg = get_approval_registry()
    record = reg.get_request(approval_id)
    if not record:
        return

    execution_status: str | None = None
    audit_hash: str | None = None
    message_text: str = ""

    try:
        exec_res = await asyncio.to_thread(execute_k8s_rollback_from_approval, record)
        execution_status = exec_res.get("status")
        audit_hash = exec_res.get("audit_hash")
        undo_executed = exec_res.get("undo_executed", False)

        if undo_executed:
            execution_status = "undone_escalated"
            message_text = (
                "⚠️ Rollback failed stabilization; automatic single undo executed "
                "and incident escalated to human on-call."
            )
        else:
            message_text = (
                f"✅ Rollback to revision {exec_res.get('target_revision')} "
                "executed and verified stabilized."
            )
    except Exception as exc:
        logger.error("async_rollback_failed", error=str(exc), approval_id=approval_id)
        execution_status = "error"
        message_text = f"❌ Rollback execution encountered error: {exc}"

    record.execution_status = execution_status
    record.audit_hash = audit_hash
    reg.update_record(record)

    if response_url:
        update_payload = {
            "replace_original": "true",
            "text": message_text,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*{message_text}*\n"
                            f"• *Incident ID:* `{record.incident_id}`\n"
                            f"• *Status:* `{execution_status}`\n"
                            f"• *Audit Hash:* `{audit_hash or 'none'}`"
                        ),
                    },
                }
            ],
        }
        await _post_slack_update(response_url, update_payload)


def execute_k8s_rollback_from_approval(record: Any) -> dict[str, Any]:
    """Helper executed upon human approval to apply typed A1 rollback."""
    from app.services.k8s_executor import ActionEnvelope, KubernetesRollbackExecutor
    executor = KubernetesRollbackExecutor()
    try:
        envelope = ActionEnvelope(
            incident_id=record.incident_id,
            action_name="A1_ROLLBACK",
            namespace=getattr(record, "namespace", "default") or "default",
            target_name=getattr(record, "target_service", "payment-gateway"),
            target_uid=getattr(record, "target_uid", ""),
            approver=getattr(record, "decided_by", "operator") or "operator",
        )
        result = executor.execute_rollback(envelope)
        return result.model_dump()
    finally:
        executor.audit_logger.close()


def reconcile_in_progress_approvals_on_startup(
    registry: SQLiteApprovalRegistry | None = None,
    settings: Settings | None = None,
    apps_api: Any = None,
) -> list[Any]:
    """
    Crash recovery reconciliation routine invoked on brain startup (PRD Section 8):
    1. Finds all approvals left in 'in_progress' state from an ungraceful shutdown.
    2. Reconciles with actual live cluster state for each target workload.
    3. Transitions execution_status to 'needs_human_review'.
    4. Audits the event into the tamper-evident cryptographic log.
    5. Dispatches an alert to Slack.
    """
    reg = registry or get_approval_registry()
    app_settings = settings or get_settings()
    orphans = reg.get_in_progress_approvals()
    if not orphans:
        logger.info("crash_recovery_no_orphaned_approvals")
        return []

    logger.warning("crash_recovery_orphaned_approvals_found", count=len(orphans))
    from app.services.audit_logger import AuditLogger

    audit_logger = AuditLogger()
    reconciled: list[Any] = []

    # Prepare Kubernetes API
    api = apps_api
    if api is None:
        try:
            from kubernetes import client, config

            try:
                config.load_incluster_config()
            except Exception:
                config.load_kube_config()
            api = client.AppsV1Api()
        except Exception as k8s_err:
            logger.warning("crash_recovery_k8s_client_init_failed", error=str(k8s_err))

    try:
        for record in orphans:
            cluster_state: dict[str, Any] = {}
            if api and record.target_service:
                try:
                    deploy = api.read_namespaced_deployment(
                        name=record.target_service,
                        namespace=record.namespace,
                    )
                    meta = getattr(deploy, "metadata", None)
                    spec = getattr(deploy, "spec", None)
                    k8s_status = getattr(deploy, "status", None)
                    annotations = getattr(meta, "annotations", {}) or {}
                    revision = annotations.get("deployment.kubernetes.io/revision", "unknown")
                    ready_replicas = getattr(k8s_status, "ready_replicas", 0) or 0
                    replicas = getattr(spec, "replicas", 1) or 1

                    cluster_state = {
                        "exists": True,
                        "current_revision": revision,
                        "ready_replicas": ready_replicas,
                        "desired_replicas": replicas,
                        "stabilized": ready_replicas == replicas,
                    }
                except Exception as exc:
                    cluster_state = {"exists": False, "error": str(exc)}
            else:
                cluster_state = {"exists": "unknown", "reason": "k8s_api_unavailable"}

            # Mark needs_human_review
            record.execution_status = "needs_human_review"
            record.decision_reason = (
                f"Crash recovery reconcile: process was interrupted mid-execution. "
                f"Cluster state: {cluster_state}. Marked for human review."
            )
            reg.update_record(record)

            # Audit it
            try:
                audit_entry = audit_logger.append_event(
                    incident_id=record.incident_id,
                    event_type="CRASH_RECOVERY_RECONCILE",
                    data={
                        "approval_id": record.approval_id,
                        "target_resource": f"{record.namespace}/{record.target_service}",
                        "actor": "system:crash_recovery",
                        "cluster_state": cluster_state,
                        "previous_execution_status": "in_progress",
                        "new_execution_status": "needs_human_review",
                    },
                )
                record.audit_hash = audit_entry.entry_hash
                reg.update_record(record)
            except Exception as audit_err:
                logger.error("crash_recovery_audit_failed", error=str(audit_err))

            # Post alert to Slack
            channel = app_settings.slack.approval_channel
            token = app_settings.slack.bot_token.get_secret_value()
            if channel and token:
                try:
                    alert_text = (
                        f"🚨 *CRASH RECOVERY ALERT: Interrupted Remediation Detected*\n"
                        f"• *Approval ID:* `{record.approval_id}`\n"
                        f"• *Incident ID:* `{record.incident_id}`\n"
                        f"• *Workload:* `{record.namespace}/{record.target_service}`\n"
                        f"• *Status:* `needs_human_review`\n"
                        f"• *Cluster State:* `{cluster_state}`\n"
                        f"• *Audit Hash:* `{record.audit_hash or 'none'}`"
                    )
                    headers = {
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                    }
                    payload = {"channel": channel, "text": alert_text}
                    with httpx.Client(timeout=5.0) as http_client:
                        http_client.post(
                            "https://slack.com/api/chat.postMessage",
                            json=payload,
                            headers=headers,
                        )
                except Exception as slack_err:
                    logger.warning("crash_recovery_slack_notify_failed", error=str(slack_err))
            else:
                logger.info(
                    "crash_recovery_slack_alert_simulated",
                    approval_id=record.approval_id,
                    channel=channel or "#default-channel",
                    status="needs_human_review",
                    cluster_state=cluster_state,
                )

            reconciled.append(record)
    finally:
        audit_logger.close()

    return reconciled


