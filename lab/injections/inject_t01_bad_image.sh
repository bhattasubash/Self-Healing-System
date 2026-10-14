#!/usr/bin/env bash
# Inject T-01: Bad image tag deploy
set -euo pipefail

NAMESPACE="${1:-payments}"
DEPLOYMENT="${2:-payment-gateway}"
BAD_IMAGE="${3:-hashicorp/http-echo:v2-broken-tag-xyz}"

echo "=== [T-01] Patching ${NAMESPACE}/${DEPLOYMENT} with bad image: ${BAD_IMAGE} ==="
kubectl set image deployment/"${DEPLOYMENT}" "${DEPLOYMENT}"="${BAD_IMAGE}" -n "${NAMESPACE}"
echo "[T-01] Applied bad image. Pods will fail to pull image."
