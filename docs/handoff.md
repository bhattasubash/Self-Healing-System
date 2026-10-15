# ECC Session Handoff - Project Heal Phase 0 (Gate G0)

## What Was Done

### Part A: CI Hardening & Dependency Pinning
- Pinned exact dev dependencies with `httpx2` in `brain/pyproject.toml`.
- Generated and committed exact lockfile `brain/requirements.txt` via `pip-compile`.
- Added `.gitleaks.toml` allowlist configuration for test fixtures.
- Adjusted CI workflow triggers (`push: [main]`, `pull_request:`).
- Verified CI, Brain Python 3.12, strict lint/types, and secret scan passing 100% green.

### Part B: Zero Fabricated Inputs & Evidence Gate Grounding
- **Kubernetes Collectors**: Implemented `KubernetesCollector` informers for Deployments, ReplicaSets, Pods, Events, and HPAs into `TemporalStore`.
- **Grounded Evidence Gate**: Evaluates preconditions exclusively from live/stored data:
  - Real alert `startsAt` parsed.
  - Workload existence verified in temporal store (Tier C if unknown).
  - Prior change timeline verified within 30m window (Tier C if no change found).
  - Real pod status (CrashLoopBackOff, ImagePullBackOff) and warning events analyzed.
  - Never defaults to True.
- **Fail-Closed Auth**: Enforced `auth_token` header verification on `/api/v1/alerts/alertmanager` (401 on missing/invalid token).
- **Slack Block Kit Dispatch**: Real HTTP POST dispatch; logs "dispatched" only on HTTP 200 + `{"ok": true}`.
- **SQLite Approval Store**: `SQLiteApprovalRegistry` with `secrets.token_urlsafe(16)` approval IDs, namespace, target UID binding, and replay rejection (409).
- **Negative Test Suite**: Added tests for unauthenticated alert (401), unknown workload (Tier C), no change history (Tier C), and replayed approval (409).

### Part C: Real Cluster Proof (Gate G0)
- **Tooling**: Installed `kind` v0.33.0.
- **Stabilization Polling**: Enhanced `KubernetesRollbackExecutor._verify_stabilization` with polling loop for live clusters.
- **Template Sanitization**: Stripped controller-managed `pod-template-hash` labels in `KubernetesRollbackExecutor` during rollback execution.
- **Real Cluster Test Suite**: Created `lab/test_real_cluster.py` covering T-01, T-02, and T-04 against live cluster without MagicMock.
- **Demo Runner**: Created `lab/run_real_cluster_demo.py` for end-to-end execution, latency measurement, and cryptographic audit chain validation.
- **CI Kind Job**: Added `kind-cluster` job in `.github/workflows/ci.yml` that creates kind cluster on runner, deploys manifests, and executes real cluster tests and demo runner.

## Verification Evidence & Test Run IDs
- **GitHub Actions CI Run**: `38701560787` (100% green):
  - `Brain (Python 3.12)`: PASS (107/107 tests, 89.31% statement coverage).
  - `Brain strict lint + types`: PASS (0 ruff errors, 0 mypy strict errors).
  - `MCP client (Node 22)`: PASS (14/14 tests, TypeScript compile, zero audit findings).
  - `Real cluster proof (Kind Gate G0)`: PASS:
    - `lab/test_real_cluster.py::test_real_cluster_connectivity`: PASS
    - `lab/test_real_cluster.py::test_real_cluster_collector_sync`: PASS
    - `lab/test_real_cluster.py::test_real_cluster_t01_bad_image_rollback_flow`: PASS
    - `lab/test_real_cluster.py::test_real_cluster_t02_crashloop_rollback_flow`: PASS
    - `lab/test_real_cluster.py::test_real_cluster_t04_failing_readiness_rollback_flow`: PASS
    - `lab/run_real_cluster_demo.py`: PASS (full 8-step lifecycle verified).
- **GitHub Actions Security Run**: `38701554136` (100% green on push):
  - Secret scan (`gitleaks`): PASS (0 leaks).
  - CodeQL Python & JS/TS: PASS (0 alerts).
  - `pip-audit`: PASS (0 known vulnerabilities).

## Measured Metrics (Live Kind Cluster Demo T-01)
- Baseline deployment stabilization: ~4.2s (3/3 ready replicas).
- Pod failure observation time: ~11.8s (`ImagePullBackOff`).
- KubernetesCollector sync: 1 deployment, 2 replicasets, 4 pods, 2 events.
- Evidence Gate evaluation latency: ~38ms (`TIER_A`, `A1_ROLLBACK`).
- Approval & typed rollback execution latency: ~3.8s.
- Post-rollback cluster verification: restored `hashicorp/http-echo:0.2.3`, 3/3 ready replicas.
- Cryptographic audit chain: valid SHA-256 tamper-evident integrity.

## Open Issues & Next Steps
- Enable Dependency Graph in GitHub repository settings to clear PR dependency-review check.
- Merge PR #1 (`step0-ci-and-install-fixes` -> `main`).
- Proceed to Phase 1 (F-07 additional actions A2-A4, GitOps revert-PR app, local policy engine).
