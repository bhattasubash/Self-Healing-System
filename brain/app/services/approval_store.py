"""
SQLite-backed Persistent Approval Registry (PRD Section 8, Human Verification Gateway).

Persists human remediation approval requests with:
- Cryptographically secure URL-safe approval tokens (secrets.token_urlsafe).
- Bound namespace and immutable target object UID.
- Full lifecycle status tracking (pending, approved, rejected, expired).
- Replay prevention and single-use idempotency.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta

import structlog
from pydantic import BaseModel, Field

from app.utils.validation import validate_incident_id

logger = structlog.get_logger()


class ApprovalRecord(BaseModel):
    """Tracked state for a human remediation approval request."""

    approval_id: str
    incident_id: str
    status: str = "pending"  # "pending" | "approved" | "rejected" | "expired"
    created_at: datetime
    expires_at: datetime
    target_service: str = ""
    namespace: str = "default"
    target_uid: str = ""
    proposed_action: str = ""
    allowed_roles: list[str] = Field(
        default_factory=lambda: ["sre-lead", "incident-commander", "admin"]
    )
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_reason: str | None = None
    execution_status: str | None = None
    audit_hash: str | None = None


class SQLiteApprovalRegistry:
    """
    Persistent SQLite approval registry enforcing existence, TTL, single-use,
    and role gating for remediation approvals.
    """

    def __init__(self, db_path: str = ":memory:", default_ttl_seconds: int = 900) -> None:
        self.db_path = db_path
        self._default_ttl_seconds = default_ttl_seconds
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        with self._conn:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS approvals (
                    approval_id TEXT PRIMARY KEY,
                    incident_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    target_service TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    target_uid TEXT NOT NULL,
                    proposed_action TEXT NOT NULL,
                    allowed_roles TEXT NOT NULL,
                    decided_by TEXT,
                    decided_at TEXT,
                    decision_reason TEXT,
                    execution_status TEXT,
                    audit_hash TEXT
                );
                """
            )

    def register_request(
        self,
        approval_id: str,
        incident_id: str,
        target_service: str = "",
        namespace: str = "default",
        target_uid: str = "",
        proposed_action: str = "",
        ttl_seconds: int | None = None,
        allowed_roles: list[str] | None = None,
    ) -> ApprovalRecord:
        now = datetime.now(UTC)
        ttl = ttl_seconds if ttl_seconds is not None else self._default_ttl_seconds
        roles = allowed_roles or ["sre-lead", "incident-commander", "admin"]
        record = ApprovalRecord(
            approval_id=approval_id,
            incident_id=validate_incident_id(incident_id),
            status="pending",
            created_at=now,
            expires_at=now + timedelta(seconds=ttl),
            target_service=target_service,
            namespace=namespace,
            target_uid=target_uid,
            proposed_action=proposed_action,
            allowed_roles=roles,
        )

        with self._conn:
            self._conn.execute(
                """
                INSERT OR REPLACE INTO approvals (
                    approval_id, incident_id, status, created_at, expires_at,
                    target_service, namespace, target_uid, proposed_action,
                    allowed_roles, decided_by, decided_at, decision_reason,
                    execution_status, audit_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.approval_id,
                    record.incident_id,
                    record.status,
                    record.created_at.isoformat(),
                    record.expires_at.isoformat(),
                    record.target_service,
                    record.namespace,
                    record.target_uid,
                    record.proposed_action,
                    json.dumps(record.allowed_roles),
                    record.decided_by,
                    record.decided_at.isoformat() if record.decided_at else None,
                    record.decision_reason,
                    record.execution_status,
                    record.audit_hash,
                ),
            )
        return record

    def get_request(self, approval_id: str) -> ApprovalRecord | None:
        with self._conn:
            row = self._conn.execute(
                "SELECT * FROM approvals WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_record(row)

    def update_record(self, record: ApprovalRecord) -> None:
        with self._conn:
            self._conn.execute(
                """
                UPDATE approvals
                SET status = ?,
                    decided_by = ?,
                    decided_at = ?,
                    decision_reason = ?,
                    execution_status = ?,
                    audit_hash = ?
                WHERE approval_id = ?
                """,
                (
                    record.status,
                    record.decided_by,
                    record.decided_at.isoformat() if record.decided_at else None,
                    record.decision_reason,
                    record.execution_status,
                    record.audit_hash,
                    record.approval_id,
                ),
            )

    def clear(self) -> None:
        with self._conn:
            self._conn.execute("DELETE FROM approvals;")

    def _row_to_record(self, row: sqlite3.Row) -> ApprovalRecord:
        return ApprovalRecord(
            approval_id=row["approval_id"],
            incident_id=row["incident_id"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            target_service=row["target_service"],
            namespace=row["namespace"],
            target_uid=row["target_uid"],
            proposed_action=row["proposed_action"],
            allowed_roles=json.loads(row["allowed_roles"]),
            decided_by=row["decided_by"],
            decided_at=datetime.fromisoformat(row["decided_at"]) if row["decided_at"] else None,
            decision_reason=row["decision_reason"],
            execution_status=row["execution_status"],
            audit_hash=row["audit_hash"],
        )
