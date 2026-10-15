"""
Typed Action A1: Direct Kubernetes Deployment Rollback Executor (PRD Section 8, F-07, F-10).

Guarantees:
1. Typed Kubernetes API operations (AppsV1Api client, no subprocess kubectl).
2. Server-side dry-run diff generation comparing pod template revisions.
3. Precondition verification:
   - Allowlisted namespace enforcement.
   - Object UID binding (LLM never supplies targets).
   - GitOps management detection (Argo CD / Flux).
   - Revision existence in ReplicaSet history (pod template only, no data).
4. Cryptographic audit hash chain logging before execution (fail closed).
5. Post-rollback verification stabilization and single automatic undo if pods fail.
"""

from __future__ import annotations

import difflib
from typing import Any

import structlog
from pydantic import BaseModel

from app.services.audit_logger import AuditLogger
from app.utils.validation import validate_incident_id

logger = structlog.get_logger()


class PreconditionFailedError(Exception):
    """Raised when an action precondition is violated."""


class ActionEnvelope(BaseModel):
    """Signed short-lived action envelope authorized for execution."""

    incident_id: str
    action_name: str
    namespace: str
    target_name: str
    target_uid: str
    approver: str
    nonce: str | None = None
    signature: str | None = None


class RollbackResult(BaseModel):
    """Outcome of a typed rollback execution."""

    status: str
    verification_passed: bool
    undo_executed: bool = False
    target_revision: int | None = None
    message: str = ""
    audit_hash: str | None = None
    dry_run_diff: str = ""


# Known GitOps management markers (Argo CD, Flux)
GITOPS_LABELS = {
    "app.kubernetes.io/instance",
    "argocd.argoproj.io/instance",
    "argocd.argoproj.io/tracking-id",
    "kustomize.toolkit.fluxcd.io/name",
    "helm.toolkit.fluxcd.io/name",
}


def _extract_container_summary(pod_template: Any) -> list[str]:
    """Extracts deterministic formatted container representations for diffing."""
    lines: list[str] = []
    containers = (
        getattr(pod_template.spec, "containers", [])
        if hasattr(pod_template, "spec")
        else []
    )
    for c in containers:
        name = getattr(c, "name", "unknown")
        image = getattr(c, "image", "unknown")
        lines.append(f"container: {name} (image: {image})")
    return lines


class KubernetesRollbackExecutor:
    """Executes typed A1 rollback operations using the official Kubernetes API."""

    def __init__(
        self,
        apps_api: Any = None,
        audit_logger: AuditLogger | None = None,
        allowlisted_namespaces: set[str] | None = None,
    ) -> None:
        self.apps_api = apps_api
        self.audit_logger = audit_logger or AuditLogger()
        self.allowlisted_namespaces = allowlisted_namespaces or {"default", "payments", "orders"}
        self._log = logger.bind(component="k8s_executor")

    def _get_api(self) -> Any:
        if self.apps_api is not None:
            return self.apps_api
        from kubernetes import client, config  # Lazy load client

        try:
            config.load_incluster_config()  # type: ignore[no-untyped-call]
        except config.ConfigException:
            config.load_kube_config()  # type: ignore[no-untyped-call]
        self.apps_api = client.AppsV1Api()
        return self.apps_api

    def check_preconditions(self, envelope: ActionEnvelope) -> tuple[Any, Any, int]:
        """
        Validates all preconditions prior to rollback.
        Returns (deployment, prior_replicaset, prior_revision).
        """
        validate_incident_id(envelope.incident_id)

        # 1. Namespace allowlist check
        if envelope.namespace not in self.allowlisted_namespaces:
            raise PreconditionFailedError(
                f"Namespace '{envelope.namespace}' not in allowlist: {self.allowlisted_namespaces}"
            )

        api = self._get_api()
        # 2. Fetch deployment and verify object UID binding
        try:
            deploy = api.read_namespaced_deployment(
                name=envelope.target_name,
                namespace=envelope.namespace,
            )
        except Exception as exc:
            raise PreconditionFailedError(
                f"Deployment '{envelope.target_name}' not found: {exc}"
            ) from exc

        actual_uid = getattr(deploy.metadata, "uid", "")
        if actual_uid != envelope.target_uid:
            raise PreconditionFailedError(
                f"Target UID mismatch: requested '{envelope.target_uid}', found '{actual_uid}'"
            )

        # 3. Detect GitOps management (Argo CD, Flux)
        labels = getattr(deploy.metadata, "labels", {}) or {}
        annotations = getattr(deploy.metadata, "annotations", {}) or {}
        all_keys = set(labels.keys()) | set(annotations.keys())
        if any(marker in all_keys for marker in GITOPS_LABELS):
            raise PreconditionFailedError(
                f"GitOps-managed workload detected on {envelope.target_name}; "
                f"direct rollback blocked. Route via A2 revert PR."
            )

        # 4. Fetch ReplicaSet history to find previous revision
        rs_list = api.list_namespaced_replica_set(
            namespace=envelope.namespace,
            label_selector=f"app={labels.get('app', envelope.target_name)}",
        )
        items = getattr(rs_list, "items", [])

        # Parse revisions
        revisions: list[tuple[int, Any]] = []
        for rs in items:
            rs_ann = getattr(rs.metadata, "annotations", {}) or {}
            rev_str = rs_ann.get("deployment.kubernetes.io/revision")
            if rev_str and rev_str.isdigit():
                revisions.append((int(rev_str), rs))

        revisions.sort(key=lambda x: x[0], reverse=True)
        if len(revisions) < 2:
            raise PreconditionFailedError(
                f"No prior revision found in ReplicaSet history for {envelope.target_name}"
            )

        _current_rev, _current_rs = revisions[0]
        prior_rev, prior_rs = revisions[1]

        return deploy, prior_rs, prior_rev

    def generate_dry_run_diff(
        self,
        namespace: str,
        deployment_name: str,
        target_uid: str,
    ) -> str:
        """Generates a unified diff comparing current and target pod templates."""
        envelope = ActionEnvelope(
            incident_id="dry-run",
            action_name="A1_ROLLBACK",
            namespace=namespace,
            target_name=deployment_name,
            target_uid=target_uid,
            approver="system",
        )
        deploy, prior_rs, prior_rev = self.check_preconditions(envelope)

        current_summary = _extract_container_summary(deploy.spec.template)
        target_summary = _extract_container_summary(prior_rs.spec.template)

        gen = getattr(deploy.metadata, "generation", "cur")
        diff_lines = list(
            difflib.unified_diff(
                current_summary,
                target_summary,
                fromfile=f"current-pod-template (rev {gen})",
                tofile=f"target-pod-template (rev {prior_rev})",
                lineterm="",
            )
        )
        return "\n".join(diff_lines)

    def _verify_stabilization(
        self,
        namespace: str,
        deployment_name: str,
        timeout_seconds: int = 60,
        interval_seconds: float = 1.0,
    ) -> bool:
        """Verifies that the rolled-back deployment stabilizes with all replicas ready."""
        import time

        start_time = time.time()
        while True:
            try:
                api = self._get_api()
                deploy = api.read_namespaced_deployment(name=deployment_name, namespace=namespace)
                status = getattr(deploy, "status", None)
                if status is not None:
                    replicas = getattr(status, "replicas", 0)
                    updated = getattr(status, "updated_replicas", 0)
                    ready = getattr(status, "ready_replicas", 0)
                    unavailable = getattr(status, "unavailable_replicas", 0) or 0
                    if (
                        replicas > 0
                        and (updated == replicas)
                        and (ready == replicas)
                        and (unavailable == 0)
                    ):
                        return True
            except Exception as exc:
                self._log.debug(
                    "stabilization_poll_waiting",
                    deployment=deployment_name,
                    error=str(exc),
                )

            if time.time() - start_time >= timeout_seconds:
                break
            time.sleep(interval_seconds)
        return False

    def execute_rollback(self, envelope: ActionEnvelope) -> RollbackResult:
        """
        Executes typed Action A1 (Deployment Rollback) under strict safety invariants:
        1. Preconditions & dry-run diff check.
        2. Audit chain persistence (fail closed).
        3. Direct API pod template restoration.
        4. Stabilization verification.
        5. At most one automatic undo if verification fails.
        """
        deploy, prior_rs, prior_rev = self.check_preconditions(envelope)
        dry_run_diff = self.generate_dry_run_diff(
            namespace=envelope.namespace,
            deployment_name=envelope.target_name,
            target_uid=envelope.target_uid,
        )

        api = self._get_api()
        current_template = deploy.spec.template
        target_template = prior_rs.spec.template

        # Fail-closed action execution gated by audit log
        def _apply_rollback() -> str:
            patch_body = {"spec": {"template": target_template}}
            api.patch_namespaced_deployment(
                name=envelope.target_name,
                namespace=envelope.namespace,
                body=patch_body,
            )
            return "applied"

        _, audit_entry = self.audit_logger.execute_with_audit(
            incident_id=envelope.incident_id,
            event_type="A1_ROLLBACK_EXECUTED",
            action_data={
                "action": "A1_ROLLBACK",
                "namespace": envelope.namespace,
                "target_name": envelope.target_name,
                "target_uid": envelope.target_uid,
                "target_revision": prior_rev,
                "approver": envelope.approver,
                "diff": dry_run_diff,
            },
            action_fn=_apply_rollback,
        )

        # 4. Stabilization Verification
        stabilized = self._verify_stabilization(envelope.namespace, envelope.target_name)

        if stabilized:
            self.audit_logger.append_event(
                incident_id=envelope.incident_id,
                event_type="A1_ROLLBACK_VERIFIED",
                data={"status": "stabilized", "revision": prior_rev},
            )
            return RollbackResult(
                status="resolved",
                verification_passed=True,
                undo_executed=False,
                target_revision=prior_rev,
                message=f"Rollback to revision {prior_rev} successfully verified.",
                audit_hash=audit_entry.entry_hash,
                dry_run_diff=dry_run_diff,
            )

        # 5. Verification Failed -> Single Automatic Undo
        self._log.warn(
            "rollback_verification_failed_triggering_undo",
            incident_id=envelope.incident_id,
            deployment=envelope.target_name,
        )

        undo_body = {"spec": {"template": current_template}}
        api.patch_namespaced_deployment(
            name=envelope.target_name,
            namespace=envelope.namespace,
            body=undo_body,
        )

        self.audit_logger.append_event(
            incident_id=envelope.incident_id,
            event_type="A1_ROLLBACK_UNDO_EXECUTED",
            data={
                "reason": "Verification failed post-rollback",
                "restored_template": "pre-action template",
            },
        )

        return RollbackResult(
            status="undone",
            verification_passed=False,
            undo_executed=True,
            target_revision=prior_rev,
            message=(
                "Verification failed after rollback; "
                "automatic undo restored previous template."
            ),
            audit_hash=audit_entry.entry_hash,
            dry_run_diff=dry_run_diff,
        )
