# Project Heal — Decision Log

> **Purpose**: Track every significant decision, why we chose it, and why we rejected alternatives.
> **Rule**: Every new decision gets appended to this file with a date, context, and rationale.

---

## How to Use This File

When a new decision is made:
1. Add it under the appropriate category
2. Include: **Date**, **Decision**, **Why This**, **Why Not Other**, **Status** (active/superseded/deferred)
3. If a decision is reversed, don't delete — mark as `superseded` and link to the new decision

---

## Architecture Decisions

### D-01 · Wedge = Bad-change incidents on Kubernetes
- **Date**: 13 Oct 2026 (PRD v1.0)
- **Decision**: Focus exclusively on incidents caused by changes (deployments, config edits) on Kubernetes
- **Why This**: ~70% of Google incidents trace to system changes (IEEE study). Rollback is reversible and checkable. Kubernetes provides a standard API.
- **Why Not Other**:
  - ❌ General AIOps/observability — too broad, crowded, no differentiation
  - ❌ Multi-platform (VMs, serverless) — fragments effort, K8s has the largest surface
  - ❌ All incident types — resource exhaustion, network partitions etc. are harder to auto-remediate safely
- **Status**: ✅ Active

### D-02 · LLMs never authorize or execute; deterministic Evidence Gate decides
- **Date**: 13 Oct 2026
- **Decision**: A deterministic rules engine (R1-R8) decides what may be proposed. The LLM only explains, cites evidence, and lists unknowns.
- **Why This**: Best LLMs identify root causes correctly ~25% of the time on medium-difficulty incidents (ORCA-bench). ClickHouse found no LLM consistently finds root causes without human guidance. Hallucinated causes in 40% of reports on one benchmark.
- **Why Not Other**:
  - ❌ LLM-driven RCA — unreliable (25% accuracy), hallucination risk
  - ❌ Fully autonomous AI agent — 60% of practitioners cite lack of trust as main blocker
  - ❌ Hybrid LLM+rules (LLM overrides rules) — still exposes to hallucination
- **Status**: ✅ Active

### D-03 · Shadow mode by default; each action type graduates separately
- **Date**: 13 Oct 2026
- **Decision**: Every new tenant and action type starts in shadow mode. Graduation to approve/auto is per action type and scope, never global.
- **Why This**: 73% of practitioners don't use AIOps, 60% cite trust. Shadow mode lets us prove accuracy on the customer's own data before any action.
- **Why Not Other**:
  - ❌ Skip straight to approve mode — too risky, violates trust ladder
  - ❌ Global graduation toggle — one bad action type shouldn't block others
- **Status**: ✅ Active

### D-04 · Two rollback paths: direct K8s and GitOps revert PR
- **Date**: 13 Oct 2026
- **Decision**: If Argo CD auto-sync/self-heal is active, direct K8s rollback is blocked. Route to A2 (revert PR) instead.
- **Why This**: Argo CD cannot perform an application rollback while automated sync is on, and self-heal reverts manual cluster changes. A direct rollback would be silently undone.
- **Why Not Other**:
  - ❌ Direct rollback only — silently fails with GitOps
  - ❌ Always use PR path — slower, unnecessary for non-GitOps workloads
  - ❌ Disable auto-sync temporarily — too dangerous, breaks GitOps guarantee
- **Status**: ✅ Active

### D-05 · Four P0 actions only (A1-A4)
- **Date**: 13 Oct 2026
- **Decision**: P0 actions: A1 Rollback, A2 GitOps Revert PR, A3 Rollout Restart, A4 Scale (bounded). Feature-flag toggle, config revert, Argo Rollouts abort, and customer runbooks are P1.
- **Why This**: Each additional action adds credentials and attack surface. Start narrow and safe.
- **Why Not Other**:
  - ❌ Larger action library (5-8) — more credentials, more attack surface
  - ❌ Arbitrary shell/kubectl — violates least-agency (OWASP Top 10 for agentic AI)
  - ❌ Rollback only — too limited to be useful across workload types
- **Status**: ✅ Active

### D-06 · Dual policy enforcement with signed envelopes; default deny
- **Date**: 13 Oct 2026
- **Decision**: Cloud issues Ed25519 signed action envelopes. Agent verifies signature, expiry, nonce, then checks local RemediationPolicy. Both must allow. Local deny always wins.
- **Why This**: Makes our cloud unable to exceed customer-owned policy. Even if our cloud is compromised, the local policy blocks unauthorized actions.
- **Why Not Other**:
  - ❌ Cloud-only policy — customer has no control
  - ❌ Local-only policy — no centralized management
  - ❌ Default allow — too dangerous for production
- **Status**: ✅ Active

### D-07 · Alert sources: PagerDuty, Alertmanager, Datadog, Grafana, generic. No Opsgenie.
- **Date**: 13 Oct 2026
- **Decision**: Drop Opsgenie intake.
- **Why This**: Opsgenie end of sale 4 Jun 2025, end of support 5 Apr 2027. Not worth building for a dying product.
- **Why Not Other**:
  - ❌ Include Opsgenie — end-of-life product
  - ❌ Build our own alerting — non-goal (NG-2), don't build detection
- **Status**: ✅ Active

### D-08 · Telemetry P0: Kubernetes API, Prometheus, GitHub, Argo CD
- **Date**: 13 Oct 2026
- **Decision**: Datadog read API is P1.
- **Why This**: K8s API and Prometheus cover the critical path. Datadog read API requires additional authentication complexity.
- **Status**: ✅ Active

### D-09 · No Secrets and no ConfigMap data by default
- **Date**: 13 Oct 2026
- **Decision**: heal-reader has an explicit allowlist that excludes Secrets and ConfigMaps.
- **Why This**: RBAC cannot limit ConfigMap access to metadata only. The built-in view role excludes Secrets. Minimizes trust ask.
- **Why Not Other**:
  - ❌ Include Secrets — massive trust/security problem
  - ❌ ConfigMaps by default — can't limit to metadata only via RBAC
- **Status**: ✅ Active

### D-10 · Open-source the agent; support BYO model; publish flat pricing
- **Date**: 13 Oct 2026
- **Decision**: Open-source agent, flat per-cluster pricing, BYO model.
- **Why This**: Security teams can read what runs in their cluster. Public pricing addresses competitor opacity. BYO model respects enterprise approved-model lists.
- **Why Not Other**:
  - ❌ Closed-source — blocks security review, reduces trust
  - ❌ Per-investigation pricing — unpredictable during alert storms (Datadog problem)
  - ❌ Per-seat pricing — penalizes large teams (incident.io problem)
  - ❌ Our model only — enterprises have approved model lists
- **Status**: ✅ Active

### D-11 · Persist Kubernetes Events ourselves (30 days)
- **Date**: 13 Oct 2026
- **Decision**: Store K8s events in our SQLite temporal store for 30 days.
- **Why This**: K8s Events expire after 1 hour by default. You can't diagnose "what changed before this alert" if the events are gone.
- **Status**: ✅ Active

### D-12 · Day-1 Replay is the primary activation hook
- **Date**: 13 Oct 2026
- **Decision**: First value within 24 hours by replaying last 30 days of incident history.
- **Why This**: Shadow mode alone takes 2-4 weeks to show value. Replay gives the champion data to forward to their manager on day 1.
- **Status**: ✅ Active

---

## Technical Decisions

### D-13 · Replace Neo4j with SQLite temporal tables
- **Date**: 13 Oct 2026
- **Decision**: Remove Neo4j, use SQLite bi-temporal tables on PVC.
- **Why This**: Neo4j Community is GPLv3 and single-database. Multi-database needs commercial Enterprise edition. The config used a custom DB name, which requires Enterprise. The MVP's queries (what changed on this workload before this alert) are joins, not graph traversals. Kùzu was archived after Apple acquisition.
- **Why Not Other**:
  - ❌ Neo4j Community — GPLv3, single-database limitation
  - ❌ Neo4j Enterprise — commercial license, operational overhead
  - ❌ Kùzu — archived, no longer maintained
  - ❌ Postgres — adds external dependency for MVP; optional later
- **Status**: ✅ Active (implemented)

### D-14 · Server-side content scan at brain boundary; fail closed
- **Date**: 13 Oct 2026
- **Decision**: Brain runs its own content scan on every inbound event. The client-side masking flag is advisory only.
- **Why This**: A boolean masking flag is not evidence that content is actually masked. Defense in depth.
- **Implemented**: Yes — `content_scanner.py` with regex + Shannon entropy, 100% recall on 7-class synthetic secret test corpus
- **Status**: ✅ Active (implemented)

### D-15 · Typed action allowlist replaces command blocklists
- **Date**: 13 Oct 2026
- **Decision**: The LLM cannot emit commands. Only typed actions (A1-A4) with defined parameters, preconditions, and undo. Old regex command blocklist kept as a tripwire.
- **Why This**: Matches OWASP least-agency guidance. Blocklists have gaps; allowlists are complete.
- **Status**: ✅ Active (implemented)

### D-16 · Sandbox validates artifacts, not production safety
- **Date**: 13 Oct 2026
- **Decision**: E2B sandbox validates generated artifacts (revert PR CI, manifests, policy tests). It is never evidence that a production action is safe.
- **Why This**: An isolated sandbox lacks production data, traffic, and dependencies.
- **Status**: ✅ Active

### D-17 · Wording: "raw telemetry stays in your environment"
- **Date**: 13 Oct 2026
- **Decision**: Never say "zero egress." Masked context does go to an external LLM.
- **Why This**: "Zero data egress" is false — masked context leaves. Honesty prevents credibility damage.
- **Status**: ✅ Active

### D-18 · "Deploy" = change executed on target, verified, undoable
- **Date**: 13 Oct 2026
- **Decision**: A git commit is not a deploy. Deploy means executed, verified, and undoable.
- **Status**: ✅ Active

### D-19 · Actions reference cluster object UIDs, not LLM-supplied targets
- **Date**: 13 Oct 2026
- **Decision**: The LLM sees masked tokens for explanation only. Actions bind to UIDs resolved by the agent at proposal time.
- **Why This**: A poisoned log line cannot redirect an action. A restarted process cannot strand an approval.
- **Status**: ✅ Active (implemented — `k8s_executor.py` UID binding)

### D-20 · Git: pull-request-only, audit in ops store not app repo
- **Date**: 13 Oct 2026
- **Decision**: Only open PRs (never direct push). Audit records go to ops store, not the application repository.
- **Status**: ✅ Active

### D-21 · Deterministic groundedness checks; LLM judge optional
- **Date**: 13 Oct 2026
- **Decision**: Evaluate with code that checks every cited entity and timestamp exists in the evidence. LLM judge adds signal but is never a gate.
- **Status**: ✅ Active

### D-22 · Egress ledger: every outbound call logged
- **Date**: 13 Oct 2026
- **Decision**: Every outbound call (LLM, sandbox, Slack, cloud relay) recorded with payload hash and size.
- **Status**: 🔲 Not yet implemented (P1)

### D-23 · Measure before claiming
- **Date**: 13 Oct 2026
- **Decision**: Every number in marketing traces to a test in the eval harness.
- **Status**: ✅ Active (principle applied)

### D-24 · Edge-first architecture
- **Date**: 13 Oct 2026
- **Decision**: Analysis, evidence storage, and execution run in the customer cluster. Thin cloud handles Slack routing, auth, billing, incident metadata. Raw evidence fetched on demand.
- **Why This**: Preserves privacy-first novelty. Customer data stays in their boundary.
- **Status**: ✅ Active

### D-25 · Reuse TypeScript + Python stack; Go only if image size blocks adoption
- **Date**: 13 Oct 2026
- **Decision**: TypeScript MCP client + Python FastAPI brain. Don't rewrite in Go unless image size or memory becomes an adoption blocker.
- **Status**: 🔄 Superseded in live path by D-26

### D-26 · Park MCP Client as Optional / P2
- **Date**: 18 Oct 2026
- **Decision**: Park the TypeScript MCP client (`packages/mcp-client`) as optional/P2 rather than a live-path dependency. The Python Brain communicates directly with the Kubernetes API and SQLite bi-temporal store. Do not remove its tests.
- **Why This**:
  1. **Not in live path**: The production remediation path (intake → content scan → temporal store → evidence gate → Slack approval → direct K8s rollback) runs natively in the Python Brain and talks directly to the Kubernetes API (`AppsV1Api`, `CoreV1Api`). The brain never calls the MCP client.
  2. **Second runtime**: Coupling a Node.js process with the Python Brain introduces a second runtime, complicating process lifecycles, healthchecks, and crash recovery.
  3. **Install footprint**: Adding Node.js, `npm`, and `@modelcontextprotocol/sdk` dramatically increases the container image footprint, dependency surface, and CVE exposure at the customer cluster edge.
- **Why Not Other**:
  - ❌ Remove MCP client and tests — keep the package and its tests for optional desktop/IDE LLM integration in P2.
  - ❌ Force Brain to query K8s through MCP client — adds unnecessary local RPC latency, serialization overhead, and failure points without security gain.
- **Status**: 🔲 Parked (Optional / P2)

---

## Engineering Decisions (Post-PRD, During Implementation)

### E-01 · Background K8s watches with `asyncio.to_thread` + 410 recovery
- **Date**: ~15 Oct 2026
- **Decision**: Run blocking K8s watch calls off the event loop via `asyncio.to_thread`. Auto-recover from 410 Gone / expired resourceVersion.
- **Why This**: K8s watch API blocks. Running in the event loop would block all async handlers.
- **Status**: ✅ Active (implemented)

### E-02 · Default-deny namespace policy
- **Date**: ~15 Oct 2026
- **Decision**: Empty `allowed_namespaces` collects nothing and acts on nothing. Added `broad_read_opt_in` for cluster-wide read telemetry.
- **Why This**: Least privilege. No accidental exposure of unintended namespaces.
- **Status**: ✅ Active (implemented)

### E-03 · Crash recovery: reconcile orphaned in_progress approvals on startup
- **Date**: ~17 Oct 2026
- **Decision**: On startup, reconcile any approvals left `in_progress` with live cluster state. Set `needs_human_review`, create audit entry, alert Slack.
- **Why This**: If the agent crashes mid-rollback, we need to know the actual state.
- **Status**: ✅ Active (implemented)

### E-04 · Workload lock & cooldown (HTTP 409)
- **Date**: ~17 Oct 2026
- **Decision**: Block concurrent or rapid-fire executions on the same workload with HTTP 409 response.
- **Why This**: PRD F-09/F-10 require one action per workload at a time and cooldown periods.
- **Status**: ✅ Active (implemented)

### E-05 · `response_url` host validated against `hooks.slack.com`
- **Date**: ~17 Oct 2026
- **Decision**: Strictly validate Slack `response_url` host against `hooks.slack.com` (HTTPS only, no userinfo/ports).
- **Why This**: SSRF prevention. A crafted `response_url` could redirect approval callbacks.
- **Status**: ✅ Active (implemented)

### E-06 · Approval TTL reduced from 3600s to 900s (15 min)
- **Date**: ~15 Oct 2026
- **Decision**: Reduced approval TTL from 1 hour to 15 minutes.
- **Why This**: PRD specifies 15-minute TTL. Longer TTLs increase replay risk.
- **Why Not Other**:
  - ❌ 3600s (original) — too long, stale approvals are dangerous
  - ❌ 5 min — too short, on-call might miss it
- **Status**: ✅ Active (implemented)

### E-07 · Atomic workload lock via SQLite unique partial index and immediate transaction
- **Date**: 18 Oct 2026
- **Decision**: Enforce workload lock atomicity using a SQLite UNIQUE partial index (`idx_active_workload_lock ON approvals (namespace, target_service) WHERE execution_status = 'in_progress' AND target_service != ''`) and an atomic `acquire_workload_lock` transaction with thread mutex synchronization.
- **Why This**: Prevents TOCTOU (time-of-check to time-of-use) race conditions when concurrent approvals arrive simultaneously. Verified with `asyncio.gather`.
- **Status**: ✅ Active (implemented)

---

## Deferred Decisions

### D-DEFER-01 · Product name
- **Status**: 🔲 Open — "Project Heal" is the working name

### D-DEFER-02 · Agent license
- **Status**: 🔲 Open — currently MIT

### D-DEFER-03 · Default temporal store (SQLite vs Postgres)
- **Status**: ✅ Decided — SQLite for MVP, Postgres optional

### D-DEFER-04 · Hosted sandbox vs self-hosted vs drop
- **Status**: 🔲 Open — currently E2B hosted

### D-DEFER-05 · Default model provider
- **Status**: ✅ Decided — Gemini 2.5 Flash default, BYO supported

### D-DEFER-06 · Full sync mode (raw evidence to cloud opt-in)
- **Status**: 🔲 Open

---

*Last updated: 17 October 2026*
