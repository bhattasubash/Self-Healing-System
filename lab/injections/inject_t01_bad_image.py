#!/usr/bin/env python3
"""
Failure Injection Script: T-01 Bad Image Tag Deploy (PRD Section 13.1).

Scenario:
A new deployment revision specifies an invalid/non-existent container image tag.
Expected Behavior:
- Pods enter ErrImagePull / ImagePullBackOff.
- Alertmanager fires alert KubePodCrashLooping / KubeDeploymentRolloutStuck.
- Evidence Gate evaluates preconditions (R1-R8) -> Tier A.
- Action A1 Rollback is proposed with dry-run diff showing restoration of healthy image.
- Operator approves -> Rollback executes -> Verified healthy -> Audited.
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from datetime import UTC, datetime
from typing import Any


def build_t01_alert(
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
                    "alertname": "KubeDeploymentRolloutStuck",
                    "namespace": namespace,
                    "deployment": deployment,
                    "app": deployment,
                    "severity": "critical",
                },
                "annotations": {
                    "summary": f"Deployment {namespace}/{deployment} rollout is stuck (bad image tag)",
                    "description": "ImagePullBackOff: Failed to pull image 'hashicorp/http-echo:v2-broken-tag-xyz'",
                },
                "startsAt": now,
                "endsAt": "0001-01-01T00:00:00Z",
                "fingerprint": "t01-bad-image-fingerprint",
            }
        ],
    }


def patch_k8s_deployment(
    deployment: str = "payment-gateway",
    namespace: str = "payments",
    bad_image: str = "hashicorp/http-echo:v2-broken-tag-xyz",
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
                            {"name": deployment, "image": bad_image}
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
        print(f"[T-01] Successfully patched {namespace}/{deployment} with bad image: {bad_image}")
        return True
    except Exception as err:  # noqa: BLE001
        print(f"[T-01] Note: Could not apply live K8s patch ({err}). Continuing in simulation mode.")
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
            print(f"[T-01] Alert dispatched to {endpoint}. Response: {result}")
            return result
    except urllib.error.URLError as err:
        print(f"[T-01] Brain endpoint {endpoint} not reachable ({err}). Printed payload only.")
        return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject T-01 Bad Image Tag failure")
    parser.add_argument("--deployment", default="payment-gateway", help="Target deployment name")
    parser.add_argument("--namespace", default="payments", help="Target namespace")
    parser.add_argument("--endpoint", default="http://localhost:8000/api/v1/alerts/alertmanager", help="Brain alert intake URL")
    parser.add_argument("--dry-run", action="store_true", help="Print alert payload without modifying cluster or network")
    args = parser.parse_args()

    print(f"=== [T-01] Starting Bad Image Tag Injection for {args.namespace}/{args.deployment} ===")
    if not args.dry_run:
        patch_k8s_deployment(args.deployment, args.namespace)

    alert_payload = build_t01_alert(args.deployment, args.namespace)
    print("\n[T-01] Alertmanager Webhook Payload:")
    print(json.dumps(alert_payload, indent=2))

    if not args.dry_run:
        dispatch_alert(args.endpoint, alert_payload)


if __name__ == "__main__":
    main()
