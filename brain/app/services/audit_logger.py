"""
Append-only Audit Hash Chain Service (PRD Section 8, Non-negotiable Invariants).

Guarantees:
1. Append-only sequential chaining using SHA-256 hashes.
2. Tamper-evident verification across all stored audit entries.
3. Fail-closed execution invariant:
   If an audit record cannot be written, remediation actions are strictly blocked.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, TypeVar

import structlog

from app.utils.validation import validate_incident_id

if TYPE_CHECKING:
    from collections.abc import Callable

logger = structlog.get_logger()
T = TypeVar("T")


class AuditWriteError(Exception):
    """Raised when an append-only audit log write fails."""


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    incident_id: str
    timestamp: str
    event_type: str
    data: dict[str, Any]
    prev_hash: str
    entry_hash: str


def compute_entry_hash(
    sequence: int,
    prev_hash: str,
    timestamp: str,
    incident_id: str,
    event_type: str,
    data_json: str,
) -> str:
    """Computes deterministic SHA-256 hash of an audit entry."""
    canonical_repr = (
        f"{sequence}|{prev_hash}|{timestamp}|{incident_id}|{event_type}|{data_json}"
    )
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()


class AuditLogger:
    """Manages an append-only, tamper-evident hash chain in SQLite."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self.db_path = db_path
        self._conn: sqlite3.Connection | None = sqlite3.connect(
            db_path, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._init_schema(self._conn)

    def get_connection(self) -> sqlite3.Connection:
        """Returns the active SQLite connection."""
        if self._conn is None:
            raise sqlite3.ProgrammingError("Cannot operate on a closed database.")
        return self._conn

    def close(self) -> None:
        """Closes the database connection."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_chain (
                sequence INTEGER PRIMARY KEY,
                incident_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                data_json TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );
            """
        )
        conn.commit()

    def append_event(
        self,
        incident_id: str,
        event_type: str,
        data: dict[str, Any],
        timestamp: datetime | None = None,
    ) -> AuditEntry:
        """
        Appends an event to the hash chain.
        Fails closed with AuditWriteError if anything goes wrong.
        """
        validate_incident_id(incident_id)
        ts_str = (timestamp or datetime.now(UTC)).isoformat()
        canonical_data_json = json.dumps(data, sort_keys=True, separators=(",", ":"))

        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            # Retrieve highest sequence and last hash
            cursor.execute(
                "SELECT sequence, entry_hash FROM audit_chain ORDER BY sequence DESC LIMIT 1"
            )
            row = cursor.fetchone()

            if row is None:
                sequence = 1
                prev_hash = "0" * 64
            else:
                sequence = row[0] + 1
                prev_hash = row[1]

            entry_hash = compute_entry_hash(
                sequence=sequence,
                prev_hash=prev_hash,
                timestamp=ts_str,
                incident_id=incident_id,
                event_type=event_type,
                data_json=canonical_data_json,
            )

            cursor.execute(
                """
                INSERT INTO audit_chain (
                    sequence, incident_id, timestamp, event_type, data_json, prev_hash, entry_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    sequence,
                    incident_id,
                    ts_str,
                    event_type,
                    canonical_data_json,
                    prev_hash,
                    entry_hash,
                ),
            )
            conn.commit()

            return AuditEntry(
                sequence=sequence,
                incident_id=incident_id,
                timestamp=ts_str,
                event_type=event_type,
                data=data,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )
        except Exception as exc:
            logger.error("audit_write_failed", incident_id=incident_id, error=str(exc))
            raise AuditWriteError(f"Failed to append audit record: {exc}") from exc

    def verify_chain(
        self, incident_id: str | None = None
    ) -> tuple[bool, str | None]:
        """
        Validates the cryptographic integrity of the entire audit chain.
        Returns (True, None) if clean, or (False, error_reason) if tampered.
        """
        try:
            conn = self.get_connection()
            cursor = conn.cursor()

            query = (
                "SELECT sequence, incident_id, timestamp, event_type, "
                "data_json, prev_hash, entry_hash FROM audit_chain"
            )
            params: list[Any] = []
            if incident_id:
                query += " WHERE incident_id = ?"
                params.append(incident_id)
            query += " ORDER BY sequence ASC"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            expected_sequence = 1
            expected_prev_hash = "0" * 64

            for row in rows:
                seq, inc_id, ts, ev_type, data_str, p_hash, stored_hash = row

                # Check sequence continuity
                if not incident_id and seq != expected_sequence:
                    return (
                        False,
                        f"Sequence gap or chain break at sequence {seq} "
                        f"(expected {expected_sequence})",
                    )

                # Check prev_hash linkage
                if not incident_id and p_hash != expected_prev_hash:
                    return False, f"Hash chain linkage broken at sequence {seq}: prev_hash mismatch"

                # Recalculate hash
                recomputed_hash = compute_entry_hash(
                    sequence=seq,
                    prev_hash=p_hash,
                    timestamp=ts,
                    incident_id=inc_id,
                    event_type=ev_type,
                    data_json=data_str,
                )

                if recomputed_hash != stored_hash:
                    return (
                        False,
                        f"Hash mismatch at sequence {seq}: "
                        f"expected {stored_hash}, recomputed {recomputed_hash}",
                    )

                expected_sequence = seq + 1
                expected_prev_hash = stored_hash

            return True, None
        except Exception as exc:
            return False, f"Error verifying audit chain: {exc}"

    def get_entries(self, incident_id: str | None = None) -> list[AuditEntry]:
        """Returns all audit entries, optionally filtered by incident_id."""
        conn = self.get_connection()
        cursor = conn.cursor()

        query = (
            "SELECT sequence, incident_id, timestamp, event_type, "
            "data_json, prev_hash, entry_hash FROM audit_chain"
        )
        params: list[Any] = []
        if incident_id:
            query += " WHERE incident_id = ?"
            params.append(incident_id)
        query += " ORDER BY sequence ASC"

        cursor.execute(query, params)
        entries: list[AuditEntry] = []
        for row in cursor.fetchall():
            entries.append(
                AuditEntry(
                    sequence=row[0],
                    incident_id=row[1],
                    timestamp=row[2],
                    event_type=row[3],
                    data=json.loads(row[4]),
                    prev_hash=row[5],
                    entry_hash=row[6],
                )
            )
        return entries

    def execute_with_audit(
        self,
        incident_id: str,
        event_type: str,
        action_data: dict[str, Any],
        action_fn: Callable[[], T],
    ) -> tuple[T, AuditEntry]:
        """
        Executes an action strictly gated by audit chain persistence.
        If writing to the audit chain fails, action_fn is never invoked.
        """
        entry = self.append_event(
            incident_id=incident_id,
            event_type=event_type,
            data=action_data,
        )
        result = action_fn()
        return result, entry
