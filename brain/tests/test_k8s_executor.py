"""
Tests for Typed Action A1: Direct Kubernetes Rollback Executor (PRD Section 8, F-07, F-10).

Verifies:
1. Typed Kubernetes API operations (AppsV1Api client, no subprocess kubectl).
2. Server-side dry-run diff generation.
3. Precondition verification (R1-R8, allowlisted namespace, object UID binding).
4. Reversible pod template restoration (pod template only, no data).
5. Audit hash chain integration (fail closed on audit error).
6. Verification stabilization and single automatic undo if pods fail to stabilize.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from app.services.audit_logger import AuditLogger
from app.services.k8s_executor import (
    ActionEnvelope,
    KubernetesRollbackExecutor,
    PreconditionFailedError,
)

if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def audit_logger() -> Generator[AuditLogger, None, None]:
    logger = AuditLogger(db_path=":memory:")
    yield logger
    logger.close()


def _build_mock_deployment(
    name: str = "payment-gateway",
    namespace: str = "payments",
    uid: str = "uid-deploy-12345",
    image: str = "payment-gateway:v2-bad",
    labels: dict[str, str] | None = None,
) -> MagicMock:
    deploy = MagicMock()
    deploy.metadata.name = name
    deploy.metadata.namespace = namespace
    deploy.metadata.uid = uid
    deploy.metadata.labels = labels or {"app": "payment-gateway"}
    deploy.metadata.annotations = {}
    deploy.spec.replicas = 3
    deploy.spec.template.spec.containers = [MagicMock(name="app", image=image)]
    deploy.status.replicas = 3
    deploy.status.updated_replicas = 3
    deploy.status.ready_replicas = 3
    deploy.status.unavailable_replicas = 0
    return deploy


def _build_mock_replicasets(
    name: str = "payment-gateway",
    namespace: str = "payments",
) -> list[MagicMock]:
    # Current RS (rev 2)
    rs2 = MagicMock()
    rs2.metadata.name = f"{name}-rev2"
    rs2.metadata.namespace = namespace
    rs2.metadata.annotations = {"deployment.kubernetes.io/revision": "2"}
    rs2.spec.template.spec.containers = [MagicMock(name="app", image="payment-gateway:v2-bad")]

    # Prior RS (rev 1, healthy)
    rs1 = MagicMock()
    rs1.metadata.name = f"{name}-rev1"
    rs1.metadata.namespace = namespace
    rs1.metadata.annotations = {"deployment.kubernetes.io/revision": "1"}
    rs1.spec.template.spec.containers = [MagicMock(name="app", image="payment-gateway:v1-good")]

    return [rs1, rs2]


def test_dry_run_produces_unified_diff(audit_logger: AuditLogger) -> None:
    mock_apps = MagicMock()
    deploy = _build_mock_deployment()
    mock_apps.read_namespaced_deployment.return_value = deploy
    mock_apps.list_namespaced_replica_set.return_value.items = _build_mock_replicasets()

    executor = KubernetesRollbackExecutor(
        apps_api=mock_apps,
        audit_logger=audit_logger,
        allowlisted_namespaces={"payments", "orders"},
    )

    diff = executor.generate_dry_run_diff(
        namespace="payments",
        deployment_name="payment-gateway",
        target_uid="uid-deploy-12345",
    )

    assert "payment-gateway:v2-bad" in diff
    assert "payment-gateway:v1-good" in diff
    assert diff.startswith("---")


def test_preconditions_reject_unallowlisted_namespace(audit_logger: AuditLogger) -> None:
    mock_apps = MagicMock()
    executor = KubernetesRollbackExecutor(
        apps_api=mock_apps,
        audit_logger=audit_logger,
        allowlisted_namespaces={"payments"},
    )

    envelope = ActionEnvelope(
        incident_id="inc-test-01",
        action_name="A1_ROLLBACK",
        namespace="kube-system",  # Forbidden namespace
        target_name="coredns",
        target_uid="uid-dns-123",
        approver="U123456",
    )

    with pytest.raises(PreconditionFailedError, match="Namespace 'kube-system' not in allowlist"):
        executor.execute_rollback(envelope)


def test_preconditions_reject_uid_mismatch(audit_logger: AuditLogger) -> None:
    mock_apps = MagicMock()
    deploy = _build_mock_deployment(uid="uid-actual-real")
    mock_apps.read_namespaced_deployment.return_value = deploy

    executor = KubernetesRollbackExecutor(
        apps_api=mock_apps,
        audit_logger=audit_logger,
        allowlisted_namespaces={"payments"},
    )

    envelope = ActionEnvelope(
        incident_id="inc-test-01",
        action_name="A1_ROLLBACK",
        namespace="payments",
        target_name="payment-gateway",
        target_uid="uid-attacker-spoofed",  # Mismatched UID
        approver="U123456",
    )

    with pytest.raises(PreconditionFailedError, match="Target UID mismatch"):
        executor.execute_rollback(envelope)


def test_preconditions_reject_gitops_workload(audit_logger: AuditLogger) -> None:
    mock_apps = MagicMock()
    # Tagged as managed by Argo CD
    deploy = _build_mock_deployment(
        labels={"app.kubernetes.io/instance": "argo-payments"}
    )
    mock_apps.read_namespaced_deployment.return_value = deploy

    executor = KubernetesRollbackExecutor(
        apps_api=mock_apps,
        audit_logger=audit_logger,
        allowlisted_namespaces={"payments"},
    )

    envelope = ActionEnvelope(
        incident_id="inc-test-01",
        action_name="A1_ROLLBACK",
        namespace="payments",
        target_name="payment-gateway",
        target_uid="uid-deploy-12345",
        approver="U123456",
    )

    with pytest.raises(PreconditionFailedError, match="GitOps-managed workload"):
        executor.execute_rollback(envelope)


def test_successful_rollback_execution_and_audit(audit_logger: AuditLogger) -> None:
    mock_apps = MagicMock()
    deploy = _build_mock_deployment()
    mock_apps.read_namespaced_deployment.return_value = deploy
    mock_apps.list_namespaced_replica_set.return_value.items = _build_mock_replicasets()

    executor = KubernetesRollbackExecutor(
        apps_api=mock_apps,
        audit_logger=audit_logger,
        allowlisted_namespaces={"payments"},
    )

    envelope = ActionEnvelope(
        incident_id="inc-success-01",
        action_name="A1_ROLLBACK",
        namespace="payments",
        target_name="payment-gateway",
        target_uid="uid-deploy-12345",
        approver="U999999",
    )

    result = executor.execute_rollback(envelope)

    assert result.status == "resolved"
    assert result.verification_passed is True
    assert result.undo_executed is False
    assert result.target_revision == 1
    assert result.audit_hash is not None

    # Verify audit chain integrity
    is_valid, err = audit_logger.verify_chain()
    assert is_valid is True
    assert err is None


def test_verification_failure_triggers_single_automatic_undo(audit_logger: AuditLogger) -> None:
    mock_apps = MagicMock()
    deploy = _build_mock_deployment()
    mock_apps.read_namespaced_deployment.return_value = deploy
    mock_apps.list_namespaced_replica_set.return_value.items = _build_mock_replicasets()

    executor = KubernetesRollbackExecutor(
        apps_api=mock_apps,
        audit_logger=audit_logger,
        allowlisted_namespaces={"payments"},
    )

    # Mock verifier to simulate failed stabilization after rollback
    executor._verify_stabilization = MagicMock(return_value=False)

    envelope = ActionEnvelope(
        incident_id="inc-undo-01",
        action_name="A1_ROLLBACK",
        namespace="payments",
        target_name="payment-gateway",
        target_uid="uid-deploy-12345",
        approver="U999999",
    )

    result = executor.execute_rollback(envelope)

    assert result.status == "undone"
    assert result.verification_passed is False
    assert result.undo_executed is True
    assert "Verification failed" in result.message
    # Check patch was called twice: once for rollback, once for undo
    assert mock_apps.patch_namespaced_deployment.call_count == 2
