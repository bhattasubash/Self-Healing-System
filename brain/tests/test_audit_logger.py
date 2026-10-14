"""
Tests for Append-Only Audit Hash Chain (PRD Section 8, Non-negotiable Invariants).

Verifies:
1. Append-only sequential chaining with SHA-256 integrity.
2. Genesis block initialization and deterministic hashing.
3. Full chain verification (tamper detection).
4. Sequence break / gap detection upon record deletion.
5. Content tamper detection upon unauthorized modification.
6. Fail-closed invariant: If audit record cannot be written, execution is aborted.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from app.services.audit_logger import (
    AuditLogger,
    AuditWriteError,
)

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def audit_logger() -> Generator[AuditLogger, None, None]:
    """Fixture providing an in-memory AuditLogger with clean teardown."""
    logger = AuditLogger(db_path=":memory:")
    yield logger
    logger.close()


def test_genesis_record_created_and_hashed(audit_logger: AuditLogger) -> None:
    entry = audit_logger.append_event(
        incident_id="inc-test-01",
        event_type="INCIDENT_TRIGGERED",
        data={"service": "payment-api", "severity": "CRITICAL"},
    )

    assert entry.sequence == 1
    assert entry.prev_hash == "0" * 64
    assert len(entry.entry_hash) == 64
    assert entry.event_type == "INCIDENT_TRIGGERED"

    is_valid, err = audit_logger.verify_chain()
    assert is_valid is True
    assert err is None


def test_sequential_chaining(audit_logger: AuditLogger) -> None:
    e1 = audit_logger.append_event(
        incident_id="inc-test-01",
        event_type="DRY_RUN_COMPLETED",
        data={"diff": "- image: v2\n+ image: v1"},
    )
    e2 = audit_logger.append_event(
        incident_id="inc-test-01",
        event_type="APPROVAL_GRANTED",
        data={"approver": "U123456", "role": "sre-lead"},
    )
    e3 = audit_logger.append_event(
        incident_id="inc-test-01",
        event_type="ACTION_EXECUTED",
        data={"action": "ROLLBACK_DEPLOYMENT", "target": "payment-api"},
    )

    assert e1.sequence == 1
    assert e2.sequence == 2
    assert e3.sequence == 3

    assert e2.prev_hash == e1.entry_hash
    assert e3.prev_hash == e2.entry_hash

    is_valid, err = audit_logger.verify_chain()
    assert is_valid is True
    assert err is None


def test_tamper_detection_on_modified_data(audit_logger: AuditLogger) -> None:
    audit_logger.append_event("inc-01", "STEP_1", {"v": 1})
    audit_logger.append_event("inc-01", "STEP_2", {"v": 2})
    audit_logger.append_event("inc-01", "STEP_3", {"v": 3})

    # Directly tamper with SQLite data behind the scenes
    conn = audit_logger.get_connection()
    conn.execute("UPDATE audit_chain SET data_json = '{\"v\": 999}' WHERE sequence = 2")
    conn.commit()

    is_valid, err = audit_logger.verify_chain()
    assert is_valid is False
    assert err is not None
    assert "Hash mismatch at sequence 2" in err


def test_tamper_detection_on_deleted_record(audit_logger: AuditLogger) -> None:
    audit_logger.append_event("inc-01", "STEP_1", {"v": 1})
    audit_logger.append_event("inc-01", "STEP_2", {"v": 2})
    audit_logger.append_event("inc-01", "STEP_3", {"v": 3})

    # Delete middle record
    conn = audit_logger.get_connection()
    conn.execute("DELETE FROM audit_chain WHERE sequence = 2")
    conn.commit()

    is_valid, err = audit_logger.verify_chain()
    assert is_valid is False
    assert err is not None
    assert "Sequence gap or chain break" in err or "Hash mismatch" in err


def test_fail_closed_blocks_action_on_audit_failure() -> None:
    """Non-negotiable invariant: If audit write fails, action execution is blocked."""
    logger = AuditLogger(db_path=":memory:")
    # Close connection to force failure
    logger.close()

    executed = False

    def critical_remediation() -> str:
        nonlocal executed
        executed = True
        return "rolled_back"

    with pytest.raises(AuditWriteError):
        logger.execute_with_audit(
            incident_id="inc-fail-closed",
            event_type="ACTION_A1_ROLLBACK",
            action_data={"deployment": "orders"},
            action_fn=critical_remediation,
        )

    # Action must NOT have executed because audit write failed
    assert executed is False


def test_execute_with_audit_success(audit_logger: AuditLogger) -> None:
    executed = False

    def remediation() -> dict[str, Any]:
        nonlocal executed
        executed = True
        return {"status": "reverted", "target_revision": 3}

    result, entry = audit_logger.execute_with_audit(
        incident_id="inc-success-01",
        event_type="ACTION_A1_ROLLBACK",
        action_data={"deployment": "payments"},
        action_fn=remediation,
    )

    assert executed is True
    assert result == {"status": "reverted", "target_revision": 3}
    assert entry.event_type == "ACTION_A1_ROLLBACK"
    assert entry.incident_id == "inc-success-01"

    is_valid, err = audit_logger.verify_chain()
    assert is_valid is True
    assert err is None
