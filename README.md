# Privacy-First, Simulation-Gated AI SRE Agent Framework

An autonomous, decentralized Site Reliability Engineering (SRE) agent designed to query production infrastructure safely without centralizing customer telemetry or infrastructure topology.

---

## 🏛️ Architecture Overview

```
                      [ Client Infrastructure Mesh ]
                                   │
                                   ▼
                    [ Local TypeScript MCP Client ]
                       (@modelcontextprotocol/sdk)
                                   │
                        Reversible ID Masking (opensre pattern)
                                   │
                                   ▼
                    [ Zero-Token Regex Pre-Filter ]
                    (Deduplication & Noise Scrubbing)
                                   │
                                   ▼
                   [ Python FastAPI Analytical Brain ]
                                   │
                ┌──────────────────┴──────────────────┐
                ▼                                     ▼
    [ Neo4j Bi-Temporal Graph ]             [ Deterministic FSM ]
   (Graphiti State Tracking)             (INGEST ➔ FILTER ➔ ANALYZE...)
                │                                     │
                └──────────────────┬──────────────────┘
                                   │
                                   ▼
                     [ Simulation Validation Gate ]
                   ┌───────────────┴───────────────┐
                   ▼                               ▼
       [ E2B Micro-Sandbox Runner ]     [ Git Worktree Zone (YYLO) ]
       (Static Security Barrier)        (Detached config isolation)
                   │                               │
                   └───────────────┬───────────────┘
                                   │
                                   ▼
                     [ Human Verification Gate ]
                      (Slack Block Kit + HMAC)
                                   │
                        ┌──────────┴──────────┐
                        ▼                     ▼
                  [ Approved ]           [ Rejected ]
                        │                     │
                        ▼                     ▼
                 [ Worktree Commit ]    [ Teardown & Abort ]
                        │
                        ▼
            [ RunLore Post-Mortem MD ]
           (.incidents/incident-<id>.md)
```

---

## 🛡️ Core Security & Privacy Invariants

1. **Zero Data Centralization**: Telemetry vectors and host configurations stay inside the client's internal network mesh. External AI models only receive tokenized, regex-scrubbed context envelopes via local JSON-RPC.
2. **Reversible Identifier Masking (opensre pattern)**: Infrastructure identifiers (IPs, ARNs, cluster IDs, hostnames, container hashes) are replaced with deterministic session tokens in-memory. The token dictionary lives in volatile RAM and is destroyed on disconnect.
3. **Deterministic FSM Engine Pathways**: No autonomous agentic route hopping. State flow strictly follows explicit transitions: `INGEST ➔ FILTER ➔ ANALYZE ➔ SANDBOX ➔ APPROVE ➔ DEPLOY ➔ COMPLETED`.
4. **Static Security Barrier**: Static regex scanner intercepts and blocks destructive commands (`rm -rf /`, `mkfs`, `dd if=`, `kubectl delete namespace --all`, `DROP DATABASE`, fork bombs) *before* any runtime container is spun up.
5. **Simulation-Gated Write Access**: Zero blind production modifications. Every fix is simulated in an ephemeral E2B micro-sandbox, staged in a detached git worktree, and requires explicit human verification via Slack HMAC-authenticated Block Kit cards.

---

## 📦 Project Structure

```text
.
├── packages/
│   └── mcp-client/                    # TypeScript MCP Node Client
│       ├── src/
│       │   ├── index.ts               # MCP Server entrypoint (stdio JSON-RPC)
│       │   ├── tools/registry.ts      # Declarative tool manifest (Prometheus, K8s, etc.)
│       │   ├── masking/reversible.ts  # Reversible ID tokenizer
│       │   └── types/schemas.ts       # Zod runtime schemas
│       ├── tests/                     # Vitest unit tests
│       ├── tsconfig.json
│       └── package.json
│
├── brain/                             # Python FastAPI Analytical Brain
│   ├── app/
│   │   ├── main.py                    # FastAPI application & lifespan
│   │   ├── config.py                  # Pydantic v2 settings
│   │   ├── routers/
│   │   │   ├── analysis.py            # POST /api/v1/analyze
│   │   │   └── approval.py            # POST /api/v1/approval/decision (HMAC)
│   │   ├── sandbox/
│   │   │   ├── e2b_runner.py          # E2B micro-sandbox driver & security barrier
│   │   │   └── worktree.py            # Git worktree manager (YYLO pattern)
│   │   ├── schemas/telemetry.py       # Pydantic v2 telemetry & FSM models
│   │   └── services/
│   │       ├── graph_store.py         # Async Neo4j bi-temporal graph service
│   │       ├── orchestrator.py        # End-to-end incident orchestration loop
│   │       ├── post_mortem.py         # RunLore automated markdown post-mortem generator
│   │       ├── pre_filter.py          # Regex-first trace pre-filter
│   │       └── state_machine.py       # Deterministic FSM controller
│   ├── tests/                         # Pytest test suite (38 tests)
│   └── pyproject.toml
│
├── shared/
│   └── contracts/                     # Shared canonical JSON Schema contracts
│       ├── tool-call.schema.json
│       ├── telemetry.schema.json
│       └── approval.schema.json
│
├── infra/
│   └── neo4j/
│       └── init.cypher                # Bi-temporal schema constraints & seed graph
├── .env.example                       # Environment configuration template
└── README.md
```

---

## 🚀 Quick Start

### 1. Prerequisites
- Node.js >= 20.0.0
- Python >= 3.12
- Git

### 2. TypeScript MCP Client
```bash
cd packages/mcp-client
npm install
npm run build
npm test
```

### 3. Python Brain Service
```bash
cd brain
pip install -e .
pytest tests/
```

### 4. Running the Brain Service
```bash
cp .env.example .env
# Edit .env with your environment settings
brain
# Or run with uvicorn:
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

---

## 🧪 Test Verification Matrix

- **Python Tests**: 38/38 passing across 8 suites (`test_analysis_router`, `test_approval_router`, `test_e2b_runner`, `test_e2e_orchestration`, `test_graph_store`, `test_pre_filter`, `test_state_machine`, `test_worktree`).
- **TypeScript Tests**: 14/14 passing across 2 suites (`masking.test.ts`, `tools.test.ts`), with strict `tsc --noEmit` clean compile.

---

## 📄 License
MIT
