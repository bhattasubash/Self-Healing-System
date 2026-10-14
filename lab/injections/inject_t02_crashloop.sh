#!/usr/bin/env bash
# Inject T-02: Crashing startup command/arguments
set -euo pipefail

NAMESPACE="${1:-payments}"
DEPLOYMENT="${2:-payment-gateway}"

echo "=== [T-02] Patching ${NAMESPACE}/${DEPLOYMENT} with crashing arguments ==="
kubectl patch deployment "${DEPLOYMENT}" -n "${NAMESPACE}" --type='json' -p='[
  {"op": "replace", "path": "/spec/template/spec/containers/0/args", "value": ["-invalid-flag-crash"]}
]'
echo "[T-02] Applied crashing argument. Pods will enter CrashLoopBackOff."
