# Project Heal: Edge-First Kubernetes Remediation Agent

An edge-first, safety-critical Kubernetes remediation agent that detects bad-change incidents, evaluates deterministic evidence gates on historical telemetry, and executes a strictly allowlisted set of reversible actions under customer-owned policy.

---

## 🏛️ Architecture Overview

```
                      [ Cluster Infrastructure / Alertmanager ]
                                        │
                                        ▼
                         [ Edge Ingress & Content Scanner ]
                           (Fail-closed secret detection)
                                        │
                                        ▼
                        [ SQLite Bi-Temporal Store ]
                   (valid_from, valid_to, recorded_at timeline)
                                        │
                                        ▼
                        [ Deterministic Evidence Gate ]
                       (Rules R1–R8: Tier A / B / C triage)
                                        │
                     ┌──────────────────┴──────────────────┐
                     ▼                                     ▼
           [ Tier A / B Eligible ]               [ Tier C Escalation ]
                     │                            (Irreversible / GitOps /
                     ▼                             Concurrent rollout)
            [ Slack Block Kit Card ]
         (HMAC signature + 15m TTL)
                     │
           ┌─────────┴─────────┐
           ▼                   ▼
      [ Approved ]        [ Rejected ]
           │                   │
           ▼                   ▼
    [ Typed Action A1 ]     [ Abort & Audit ]
    - Server dry-run diff
    - Namespaced UID bind
    - AppsV1Api rollback
    - Verification check
    - (Single auto-undo)
           │
           ▼
    [ SHA-256 Audit Chain ]
  (Tamper-evident append-only)
           │
           ▼
    [ RunLore Post-Mortem ]
  (.incidents/incident-<id>.md)
```

---

## 🛡️ Core Safety Invariants & Claim Grounding (PRD Section 6.3)

Every claim in Project Heal is tagged as **[M] Measured**, **[T] Target**, or **[A] Assumption**. We never claim a number or capability we have not verified.

| Subject | Claim / Posture | PRD Replacement & Reality | Status |
| --- | --- | --- | --- |
| **Data Privacy** | Raw telemetry stays in your environment. | Only masked, minimized context leaves; you can preview every outbound payload. Server-side content scanner fails closed on unmasked secrets. | **[M]** 100% recall on 7-class synthetic secret test corpus |
| **Production Safety** | Typed action allowlist with dry-run diff. | Sandboxes validate generated artifacts (manifests, policy tests), not production safety. Production safety comes from server-side dry-run diffs, policy gates, verification stabilization, and at most one automatic undo. | **[M]** 96 automated tests + 5 lab chaos tests green |
| **Root Cause & Execution** | Deterministic Evidence Gate (Rules R1–R8). | Best LLMs achieve ~25% accuracy on root-cause analysis; therefore deterministic rules decide proposals. The LLM only explains, cites evidence IDs, and lists unknowns. No LLM-authored text is ever executed. | **[M]** Evaluated deterministically across T-01 to T-28 matrix |
| **Telemetry History** | Relational bi-temporal change timeline. | Kubernetes events expire after 1 hour. Project Heal tracks change records with `valid_from`, `valid_to`, and `recorded_at` in an append-only relational SQLite store. | **[M]** Bi-temporal snapshot and diff verified |
| **GitOps Awareness** | Argo CD & Flux automatic detection. | If automated sync / self-heal is active, direct Kubernetes rollback is blocked. The agent routes to an A2 GitOps revert PR instead. | **[M]** Argo CD instance label guard verified |
| **Audit Integrity** | SHA-256 append-only hash chain. | Every triage decision, dry-run diff, human approval, execution, and verification result is hashed into an immutable chain. If an audit write fails, execution aborts. | **[M]** Tamper detection and fail-closed audit verified |

---

## 📦 Project Structure

```text
.
├── brain/                             # Analytical Reasoning Brain (FastAPI)
│   ├── app/
│   │   ├── main.py                    # Application entrypoint & lifespan
│   │   ├── config.py                  # Pydantic v2 settings & role mappings
│   │   ├── routers/
│   │   │   ├── alert_intake.py        # POST /api/v1/alerts/alertmanager (< 3s ack)
│   │   │   ├── analysis.py            # POST /api/v1/analyze (regex pre-filtering)
│   │   │   └── approval.py            # POST /api/v1/approval/interactive (Slack HMAC)
│   │   ├── sandbox/
│   │   │   ├── e2b_runner.py          # E2B micro-sandbox driver for artifact simulation
│   │   │   └── worktree.py            # Detached git worktree isolation
│   │   ├── schemas/telemetry.py       # Pydantic v2 telemetry, FSM, and event schemas
│   │   └── services/
│   │       ├── audit_logger.py        # SHA-256 append-only tamper-evident audit hash chain
│   │       ├── content_scanner.py     # Server-side regex + Shannon entropy secret scanner
│   │       ├── evidence_gate.py       # Deterministic rules evaluator (R1–R8)
│   │       ├── k8s_executor.py        # Typed Action A1 rollback (AppsV1Api, dry-run, undo)
│   │       ├── orchestrator.py        # End-to-end incident orchestration loop
│   │       ├── post_mortem.py         # RunLore automated markdown post-mortem generator
│   │       ├── pre_filter.py          # Zero-token regex trace pre-filter
│   │       ├── state_machine.py       # Deterministic SRE finite-state machine
│   │       └── temporal_store.py      # SQLite bi-temporal relational store
│   ├── tests/                         # Pytest test suite (96 tests, 90.38% coverage)
│   └── pyproject.toml
│
├── lab/                               # Local Chaos Lab & Scenario Verification
│   ├── kind-config.yaml               # kind local cluster configuration
│   ├── manifests/                     # Sample 'payments' microservice manifests
│   │   ├── 00-namespace.yaml
│   │   ├── 01-configmap.yaml
│   │   ├── 02-payment-gateway-deployment.yaml
│   │   └── 03-service.yaml
│   ├── injections/                    # Scripted failure injection drivers
│   │   ├── inject_t01_bad_image.py    # T-01: Bad image tag (ImagePullBackOff)
│   │   ├── inject_t02_crashloop.py    # T-02: Crashing startup args (CrashLoopBackOff)
│   │   └── inject_t04_failing_readiness.py # T-04: Broken readiness probe (0/3 ready)
│   ├── test_lab_scenarios.py          # Automated verification for T-01, T-02, T-04, T-09
│   └── README.md
│
├── packages/                          # TypeScript MCP Client
│   └── mcp-client/
│       ├── src/
│       │   ├── index.ts               # MCP Server entrypoint (stdio JSON-RPC)
│       │   ├── masking/reversible.ts  # Reversible ID tokenizer
│       │   └── tools/registry.ts      # Read-only Kubernetes & Prometheus tools
│       └── tests/                     # Vitest test suite (14 tests)
│
└── .github/workflows/                 # CI/CD and Security Gates
    ├── ci.yml                         # Brain tests, coverage gate (>= 80%), MCP client
    └── security.yml                   # Bandit, pip-audit, and secret scanning
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Python >= 3.12
- Node.js >= 20.0.0
- Docker & kind (optional, for live cluster lab)

### 2. Run Python Brain Service
```bash
cd brain
pip install -e ".[dev]"

# Run full test suite with coverage gate
pytest -q --cov=app --cov-report=term-missing --cov-fail-under=80

# Start brain service
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### 3. Run Chaos Lab Scenarios
```bash
# Run automated scenario tests (T-01, T-02, T-04, T-09, GitOps guard)
pytest lab/test_lab_scenarios.py -v
```

---

## 🧪 Verification Matrix

- **Brain Tests**: 96/96 passing (`brain/tests/`), **90.38% statement coverage** (exceeds 80% CI requirement).
- **Chaos Lab Scenarios**: 5/5 passing (`lab/test_lab_scenarios.py`).
- **MCP Client**: 14/14 passing (`packages/mcp-client/`), strict TypeScript compile clean.
- **Static Security & Linting**:
  - `ruff check app tests` clean (0 findings).
  - `mypy --explicit-package-bases app` clean (0 findings across 19 source files).
  - Secret scanning recall: 100% across 7 secret classes on seeded corpus.

---

## 📄 License
MIT
