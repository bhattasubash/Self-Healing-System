#!/usr/bin/env python3
"""
Failure Injection Script: T-04 Failing Readiness Probe After Deploy (PRD Section 13.1).

Scenario:
A new deployment revision specifies an unfulfillable readiness probe path,
preventing pods from being marked Ready and taking traffic.
Expected Behavior:
- Pods stay Running but 0/3 Ready.
- Alertmanager fires alert KubeDeploymentReplicasMismatch / ReadinessProbeFailed.
- Evidence Gate evaluates preconditions (R1-R8) -> Tier A.
- Action A1 Rollback proposed with dry-run diff.
- Rollback execution restores working readinessProbe path.
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any


def build_t04_alert(
    deployment: str = "payment-gateway",
    namespace: str = "payments",
) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    return {
        "receiver": "heal-webhook",
        "status": "firing",
        "alerts": [
            {
                "status": "firing",
                "labels": {
                    "alertname": "KubeDeploymentReplicasMismatch",
                    "namespace": namespace,
                    "deployment": deployment,
                    "app": deployment,
                    "severity": "critical",
                },
                "annotations": {
                    "summary": f"Deployment {namespace}/{deployment} has 0/3 ready replicas",
                    "description": "Readiness probe failed: HTTP GET /broken-probe-endpoint returned 404 Not Found",
                },
                "startsAt": now,
                "endsAt": "0001-01-01T00:00:00Z",
                "fingerprint": "t04-readiness-fingerprint",
            }
        ],
    }


def patch_k8s_deployment(
    deployment: str = "payment-gateway",
    namespace: str = "payments",
) -> bool:
    try:
        from kubernetes import client, config
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        apps_api = client.AppsV1Api()
        patch_body = {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [
                            {
                                "name": deployment,
                                "readinessProbe": {
                                    "httpGet": {
                                        "path": "/broken-probe-endpoint",
                                        "port": 8080,
                                    },
                                    "initialDelaySeconds": 1,
                                    "periodSeconds": 2,
                                },
                            }
                        ]
                    }
                }
            }
        }
        apps_api.patch_namespaced_deployment(
            name=deployment,
            namespace=namespace,
            body=patch_body,
        )
        print(f"[T-04] Successfully patched {namespace}/{deployment} with broken readiness probe")
        return True
    except Exception as err:  # noqa: BLE001
        print(f"[T-04] Note: Could not apply live K8s patch ({err}). Continuing in simulation mode.")
        return False


def dispatch_alert(endpoint: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode("utf-8")
            result = json.loads(body)
            print(f"[T-04] Alert dispatched to {endpoint}. Response: {result}")
            return result
    except urllib.error.URLError as err:
        print(f"[T-04] Brain endpoint {endpoint} not reachable ({err}). Printed payload only.")
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject T-04 Failing Readiness Probe failure")
    parser.add_argument("--deployment", default="payment-gateway", help="Target deployment name")
    parser.add_argument("--namespace", default="payments", help="Target namespace")
    parser.add_argument("--endpoint", default="http://localhost:8000/api/v1/alerts/alertmanager", help="Brain alert intake URL")
    parser.add_argument("--dry-run", action="store_true", help="Print alert payload without modifying cluster or network")
    args = parser.parse_args()

    print(f"=== [T-04] Starting Readiness Probe Failure Injection for {args.namespace}/{args.deployment} ===")
    if not args.dry_run:
        patch_k8s_deployment(args.deployment, args.namespace)

    alert_payload = build_t04_alert(args.deployment, args.namespace)
    print("\n[T-04] Alertmanager Webhook Payload:")
    print(json.dumps(alert_payload, indent=2))

    if not args.dry_run:
        dispatch_alert(args.endpoint, alert_payload)


if __name__ == "__main__":
    main()
