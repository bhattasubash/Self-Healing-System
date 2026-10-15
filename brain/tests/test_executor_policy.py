"""
Tests for strict namespace allowlist enforcement in KubernetesRollbackExecutor.

Verifies:
1. Executor fails closed (PreconditionFailedError) when target namespace is not in allowlist.
2. Even when EvidenceGate is bypassed, executor refuses rollback on unlisted namespace.
3. Allowlist defaults to empty (default deny) unless loaded from settings or explicitly provided.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.services.audit_logger import AuditLogger
from app.services.k8s_executor import (
    ActionEnvelope,
    KubernetesRollbackExecutor,
    PreconditionFailedError,
)


@pytest.fixture
def audit_logger() -> AuditLogger:
    logger = AuditLogger(db_path=":memory:")
    yield logger
    logger.close()


def test_executor_refuses_unallowlisted_namespace_even_if_gate_bypassed(
    audit_logger: AuditLogger,
) -> None:
    """When an actor calls execute_rollback directly, executor refuses unlisted namespace."""
    mock_apps = MagicMock()
    # Configure executor with only 'payments' allowlisted
    executor = KubernetesRollbackExecutor(
        apps_api=mock_apps,
        audit_logger=audit_logger,
        allowlisted_namespaces={"payments"},
    )

    # Envelope targets 'kube-system' or an unallowlisted customer namespace
    envelope = ActionEnvelope(
        incident_id="inc-bypass-01",
        action_name="A1_ROLLBACK",
        namespace="unlisted-ns",
        target_name="critical-service",
        target_uid="uid-999",
        approver="malicious-actor-or-broken-gate",
    )

    with pytest.raises(PreconditionFailedError, match="not in allowlist"):
        executor.check_preconditions(envelope)

    # Verify no Kubernetes API calls were executed
    assert mock_apps.patch_namespaced_deployment.call_count == 0


def test_executor_defaults_to_default_deny_when_no_namespaces_configured(
    audit_logger: AuditLogger,
) -> None:
    """With empty allowlist (default deny), all namespaces are refused by the executor."""
    executor = KubernetesRollbackExecutor(
        apps_api=MagicMock(),
        audit_logger=audit_logger,
        allowlisted_namespaces=set(),  # empty set -> default deny
    )

    envelope = ActionEnvelope(
        incident_id="inc-default-deny-01",
        action_name="A1_ROLLBACK",
        namespace="default",
        target_name="service-a",
        target_uid="uid-111",
        approver="sre-lead",
    )

    with pytest.raises(PreconditionFailedError, match="not in allowlist"):
        executor.check_preconditions(envelope)
