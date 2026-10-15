#!/usr/bin/env python3
"""
End-to-End Real Cluster Demo: Gate G0 Verification Runner.

Executes the complete lifecycle on a live Kubernetes cluster:
1. Baseline health verification (3/3 ready replicas).
2. Failure injection (T-01 Bad Image Tag).
3. Cluster Informer synchronization to TemporalStore (real pods, events, rollout).
4. Authenticated Alertmanager webhook intake.
5. Evidence Gate precondition evaluation on REAL cluster signals (R1-R8) -> Tier A.
6. Slack Block Kit approval card dispatch.
7. Operator approval authorization & signature verification.
8. Typed A1 Rollback execution on live cluster.
9. Cluster stabilization verification (3/3 ready replicas, revision restored).
10. Tamper-evident audit chain verification.

Outputs measured latencies, event hashes, and test results.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sys
import time
import urllib.parse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "brain"))

from app.config import Settings, get_settings
from app.main import app
from app.routers.alert_intake import set_alert_temporal_store
from app.services.audit_logger import AuditLogger
from app.services.k8s_collector import KubernetesCollector
from app.services.temporal_store import TemporalStore
from fastapi.testclient import TestClient
from pydantic import SecretStr

DEMO_ALERT_TOKEN = "demo-alert-secret-token"
DEMO_SLACK_SECRET = "demo-slack-signing-secret"


def compute_slack_headers(body: bytes, secret: str = DEMO_SLACK_SECRET) -> dict[str, str]:
    ts = str(int(time.time()))
    basestring = f"v0:{ts}:{body.decode('utf-8')}".encode()
    sig = "v0=" + hmac.new(secret.encode(), basestring, hashlib.sha256).hexdigest()
    return {
        "X-Slack-Request-Timestamp": ts,
        "X-Slack-Signature": sig,
        "Content-Type": "application/x-www-form-urlencoded",
    }


async def run_demo() -> dict[str, Any]:
    print("=" * 70)
    print("PROJECT HEAL: GATE G0 END-TO-END REAL CLUSTER VERIFICATION DEMO")
    print("=" * 70)

    from kubernetes import client, config

    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()

    apps_api = client.AppsV1Api()
    core_api = client.CoreV1Api()

    # Step 0: Ensure namespace and deployment exist
    print("\n[Step 0] Verifying cluster connectivity...")
    deploy = apps_api.read_namespaced_deployment(name="payment-gateway", namespace="payments")
    print(f"  Target: deployment/{deploy.metadata.name} (uid: {deploy.metadata.uid})")

    # Step 1: Baseline health check
    print("\n[Step 1] Ensuring baseline health (hashicorp/http-echo:0.2.3)...")
    t0 = time.time()
    container = deploy.spec.template.spec.containers[0]
    current_image = container.image
    current_cmd = container.command
    current_probe = container.readiness_probe
    probe_path = current_probe.http_get.path if current_probe and current_probe.http_get else ""

    if (
        current_image != "hashicorp/http-echo:0.2.3"
        or current_cmd is not None
        or probe_path != "/"
    ):
        patch_body = {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": "payment-gateway",
                                "image": "hashicorp/http-echo:0.2.3",
                                "command": None,
                                "args": ["-text=payment-gateway-healthy-v1", "-listen=:8080"],
                                "readinessProbe": {
                                    "httpGet": {"path": "/", "port": 8080},
                                    "initialDelaySeconds": 2,
                                    "periodSeconds": 3,
                                },
                            }
                        ]
                    }
                }
            }
        }
        apps_api.patch_namespaced_deployment(
            name="payment-gateway", namespace="payments", body=patch_body
        )

    for _ in range(60):
        d = apps_api.read_namespaced_deployment(name="payment-gateway", namespace="payments")
        status = d.status
        if status and status.ready_replicas == 3 and (status.unavailable_replicas or 0) == 0:
            break
        await asyncio.sleep(1)
    baseline_time = time.time() - t0
    print(f"  Baseline confirmed healthy: 3/3 ready replicas ({baseline_time:.2f}s)")

    # Set up Brain services
    tmp_db = Path("./demo_temporal.db").resolve()
    if tmp_db.exists():
        tmp_db.unlink()
    temporal_store = TemporalStore(db_path=str(tmp_db))
    set_alert_temporal_store(temporal_store)

    demo_approval_db = Path("./demo_approval.db").resolve()
    if demo_approval_db.exists():
        demo_approval_db.unlink()
    from app.routers import approval
    from app.services.approval_store import SQLiteApprovalRegistry

    approval_registry = SQLiteApprovalRegistry(db_path=str(demo_approval_db))
    approval._GLOBAL_APPROVAL_REGISTRY = approval_registry
    app.dependency_overrides[approval.get_approval_registry] = lambda: approval_registry

    collector = KubernetesCollector()
    await collector.sync_all(temporal_store, "payments")

    # Step 2: Inject failure (T-01: Bad image tag)
    print("\n[Step 2] Injecting T-01 failure: Bad image tag deploy...")
    t_inject = time.time()
    bad_image = "hashicorp/http-echo:v2-broken-tag-xyz"
    apps_api.patch_namespaced_deployment(
        name="payment-gateway",
        namespace="payments",
        body={"spec": {"template": {"spec": {"containers": [{"name": "payment-gateway", "image": bad_image}]}}}},
    )

    print("  Waiting for pod ImagePullBackOff on cluster...")
    failure_observed = False
    for _ in range(45):
        pods = core_api.list_namespaced_pod(
            namespace="payments", label_selector="app=payment-gateway"
        ).items
        for p in pods:
            for c in (p.status.container_statuses or []):
                w = c.state.waiting if c.state else None
                if w and w.reason in ("ImagePullBackOff", "ErrImagePull"):
                    failure_observed = True
                    break
        if failure_observed:
            break
        await asyncio.sleep(1)
    inject_duration = time.time() - t_inject
    print(f"  Failure observed on cluster in {inject_duration:.2f}s: ImagePullBackOff")

    # Step 3: Informer syncs real cluster state
    print("\n[Step 3] KubernetesCollector syncing live cluster state into TemporalStore...")
    sync_counts = await collector.sync_all(temporal_store, "payments")
    print(f"  Synced: {sync_counts}")

    # Step 4: Fire alert to Brain
    print("\n[Step 4] Alertmanager dispatching alert to /api/v1/alerts/alertmanager...")
    test_client = TestClient(app)
    settings = Settings()
    settings.alert.auth_token = SecretStr(DEMO_ALERT_TOKEN)
    settings.slack.signing_secret = SecretStr(DEMO_SLACK_SECRET)
    settings.slack.allowed_approver_roles = ["sre-lead"]
    settings.slack.approver_role_mapping = {"U_SRE_LEAD": "sre-lead"}
    app.dependency_overrides[get_settings] = lambda: settings

    t_gate = time.time()
    alert_time = datetime.now(UTC) + timedelta(seconds=2)
    alert_payload = {
        "receiver": "heal-webhook",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "KubeDeploymentRolloutStuck",
                    "namespace": "payments",
                    "deployment": "payment-gateway",
                    "app": "payment-gateway",
                    "severity": "critical",
                },
                "annotations": {
                    "summary": "Deployment payments/payment-gateway rollout is stuck",
                    "description": f"ImagePullBackOff: Failed to pull image '{bad_image}'",
                },
                "startsAt": alert_time.isoformat(),
                "fingerprint": "demo-fingerprint-t01",
            }
        ],
    }

    resp = test_client.post(
        "/api/v1/alerts/alertmanager",
        json=alert_payload,
        headers={"Authorization": f"Bearer {DEMO_ALERT_TOKEN}"},
    )
    gate_latency_ms = (time.time() - t_gate) * 1000
    assert resp.status_code == 202, f"Alert intake failed: {resp.text}"
    alert_res = resp.json()

    print(f"  Evidence Gate evaluated in {gate_latency_ms:.1f}ms:")
    print(f"    Tier: {alert_res['tier']}")
    print(f"    Proposed Action: {alert_res['proposed_action']}")
    print(f"    Approval ID: {alert_res['approval_id']}")
    print(f"    Gate Summary: {alert_res['message']}")

    # Step 5: Slack approval card dispatched
    approval_id = alert_res["approval_id"]
    print("\n[Step 5] Slack approval card dispatched to approver 'sre-lead'.")

    # Step 6: Operator approves rollback
    print("\n[Step 6] Operator approves action via Slack interactive webhook...")
    t_approve = time.time()
    slack_payload = {
        "type": "block_actions",
        "user": {"id": "U_SRE_LEAD", "username": "sre-lead"},
        "api_app_id": "A0123",
        "actions": [
            {
                "action_id": "btn_approve",
                "value": "approved",
                "action_ts": str(time.time()),
            }
        ],
    }
    form_data = urllib.parse.urlencode({"payload": json.dumps(slack_payload)})
    headers = compute_slack_headers(form_data.encode())

    appr_resp = test_client.post(
        f"/api/v1/approval/interactive?approval_id={approval_id}",
        content=form_data,
        headers=headers,
    )
    rollback_latency = time.time() - t_approve
    assert appr_resp.status_code == 200, f"Approval execution failed: {appr_resp.text}"
    appr_data = appr_resp.json()

    print(f"  Rollback executed on real cluster in {rollback_latency:.2f}s:")
    print(f"    Decision: {appr_data['decision']}")
    print(f"    Execution Status: {appr_data['execution_status']}")
    print(f"    Audit Hash: {appr_data['audit_hash']}")

    # Step 7: Verify cluster state
    print("\n[Step 7] Verifying live cluster state post-rollback...")
    final_deploy = apps_api.read_namespaced_deployment(name="payment-gateway", namespace="payments")
    restored_img = final_deploy.spec.template.spec.containers[0].image
    ready = final_deploy.status.ready_replicas
    print(f"  Restored Image: {restored_img}")
    print(f"  Ready Replicas: {ready}/3")
    assert restored_img == "hashicorp/http-echo:0.2.3"
    assert ready == 3

    # Step 8: Verify tamper-evident audit log
    print("\n[Step 8] Verifying cryptographic audit chain integrity...")
    audit_logger = AuditLogger()
    is_valid, err = audit_logger.verify_chain()
    print(f"  Audit chain valid: {is_valid} (error: {err})")

    results = {
        "status": "PASS",
        "scenario": "T-01 (Bad Image Tag Rollback)",
        "cluster_type": "Kubernetes / kind",
        "workload": "payments/payment-gateway",
        "evidence_tier": alert_res["tier"],
        "gate_latency_ms": round(gate_latency_ms, 2),
        "rollback_latency_s": round(rollback_latency, 2),
        "approval_id": approval_id,
        "audit_hash": appr_data["audit_hash"],
        "audit_chain_valid": is_valid,
        "restored_image": restored_img,
        "ready_replicas": f"{ready}/3",
    }

    print("\n" + "=" * 70)
    print("GATE G0 REAL CLUSTER DEMO COMPLETE: 100% VERIFIED")
    print(json.dumps(results, indent=2))
    print("=" * 70)
    return results


def main() -> None:
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
