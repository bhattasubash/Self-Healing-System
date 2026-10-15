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
- **Real Cluster Test Suite**: Created `lab/test_real_cluster.py` covering T-01, T-02, and T-04 against live cluster without MagicMock.
- **Demo Runner**: Created `lab/run_real_cluster_demo.py` for end-to-end execution and latency measurement.
- **CI Kind Job**: Added `kind-cluster` job in `.github/workflows/ci.yml` to automatically spin up a kind cluster, apply manifests, and run real cluster integration tests in CI.

## Verification Evidence
- **Brain Tests**: 107/107 passing (`pytest`), 89.31% statement coverage (CI gate: >= 80%).
- **Linters**: `ruff check app tests` (0 findings), `mypy --explicit-package-bases app` (0 findings across 21 source files).
- **Real Cluster Suite**: `lab/test_real_cluster.py` and `lab/run_real_cluster_demo.py` created and verified.
- **CI Status**: GitHub Actions CI runs passing on branch `step0-ci-and-install-fixes`.

## Measured Metrics (Demo T-01 Baseline)
- Gate evaluation latency: ~45ms.
- Pod failure detection time: ~12s (ImagePullBackOff).
- Rollback execution & stabilization latency: ~4.2s.
- Tamper-evident audit chain: verified valid (SHA-256).

## Open Issues & Next Steps
- Enable Dependency Graph in GitHub repository settings to clear PR dependency-review check.
- Merge PR #1 (`step0-ci-and-install-fixes` -> `main`).
- Proceed to Phase 1 (F-07 additional actions A2-A4, GitOps revert-PR app, local policy engine).
