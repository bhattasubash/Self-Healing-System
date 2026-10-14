#!/usr/bin/env bash
# Inject T-04: Failing readiness probe
set -euo pipefail

NAMESPACE="${1:-payments}"
DEPLOYMENT="${2:-payment-gateway}"

echo "=== [T-04] Patching ${NAMESPACE}/${DEPLOYMENT} with failing readiness probe ==="
kubectl patch deployment "${DEPLOYMENT}" -n "${NAMESPACE}" --type='json' -p='[
  {"op": "replace", "path": "/spec/template/spec/containers/0/readinessProbe/httpGet/path", "value": "/broken-probe-endpoint"}
]'
echo "[T-04] Applied failing probe. Pods will fail readiness checks (0/3 ready)."
