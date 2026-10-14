"""
End-to-End SRE Incident Orchestration Coordinator.

Drives the unified event lifecycle across all subsystems:
  INGEST ──► FILTER ──► ANALYZE ──► SANDBOX ──► APPROVE ──► DEPLOY ──► COMPLETED

Integrates:
- TracePreFilter (regex-first deduplication & noise removal)
- BiTemporalGraphStore / TemporalStore (topology diff lookups)
- E2BMicroSandboxRunner (Static security barrier & simulation validation)
- GitWorktreeManager (YYLO pattern code & config isolation)
- build_slack_approval_card (Human verification card dispatch)
- RunLorePostMortemGenerator (Automated markdown post-mortem compilation)

SAFETY INVARIANTS (Step 1):
- DEPLOY is strictly reachable only via real executed, verified action.
- Never write "resolved" unless verification passed.
- No canned root cause, no fake commit hashes, no hard-coded namespace.
- Explicit errors on graph and worktree failures (no silent fallbacks).
- Validated incident IDs across all paths.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog
from pydantic import BaseModel, Field

from app.config import Settings, get_settings
from app.routers.approval import build_slack_approval_card
from app.sandbox.e2b_runner import E2BMicroSandboxRunner
from app.sandbox.worktree import GitWorktreeManager, GitWorktreeSession
from app.schemas.telemetry import (
    FSMStateName,
    Severity,
    TelemetryEvent,
)
from app.utils.validation import validate_incident_id

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from app.services.temporal_store import (
        TemporalDiff as TemporalGraphDiff,
    )
    from app.services.temporal_store import (
        TemporalStore as BiTemporalGraphStore,
    )

from app.services.post_mortem import RunLorePostMortemGenerator
from app.services.pre_filter import TracePreFilter
from app.services.state_machine import (
    IncidentContext,
    SREStateMachine,
)

logger = structlog.get_logger()


class RemediationExecutionResult(BaseModel):
    """Result of a real executed and verified remediation action."""

    action_type: str
    target_uid: str
    verification_passed: bool
    details: str
    undo_available: bool = False
    audit_hash: str | None = None
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SREOrchestrationCoordinator:
    """
    Coordinates end-to-end incident triage, simulation validation, and resolution.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        graph_store: BiTemporalGraphStore | None = None,
        sandbox_runner: E2BMicroSandboxRunner | None = None,
        worktree_manager: GitWorktreeManager | None = None,
        post_mortem_gen: RunLorePostMortemGenerator | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.graph_store = graph_store
        self.sandbox_runner = sandbox_runner or E2BMicroSandboxRunner(settings=self.settings.e2b)
        self.worktree_manager = worktree_manager or GitWorktreeManager()
        self.post_mortem_gen = post_mortem_gen or RunLorePostMortemGenerator()
        self.pre_filter = TracePreFilter(
            context_budget_max_tokens=self.settings.pre_filter.context_budget_max_tokens,
            compression_target=self.settings.pre_filter.compression_target,
        )
        self._log = logger.bind(component="orchestrator")

    async def run_triage_pipeline(
        self,
        events: list[TelemetryEvent],
        session_id: str | None = None,
        incident_id: str | None = None,
    ) -> IncidentContext:
        """
        Executes stages 1 through 4 of the incident lifecycle:
        INGEST ──► FILTER ──► ANALYZE ──► SANDBOX ──► APPROVE
        """
        if incident_id:
            validate_incident_id(incident_id)

        context = IncidentContext(incident_id=incident_id, session_id=session_id)
        context.events = events
        fsm = SREStateMachine(context=context, initial_state=FSMStateName.INGEST)

        # ── 1. INGEST & DATA PERIMETER VERIFICATION ──
        unmasked = [e for e in events if not e.masking_applied]
        if unmasked:
            fsm.fail("Data perimeter violation: unmasked telemetry received.")
            raise ValueError(f"Found {len(unmasked)} unmasked telemetry events")

        target_services = sorted({
            e.labels.get("app") or e.labels.get("service") or e.metric_name
            for e in events
            if (e.labels.get("app") or e.labels.get("service") or e.metric_name)
        })
        context.target_services = target_services
        target_svc = target_services[0] if target_services else "unknown-service"

        # Resolve namespace dynamically from event labels (never hardcode)
        target_namespace = next(
            (e.labels.get("namespace") for e in events if e.labels.get("namespace")),
            "default",
        )
        context.severity = max((e.severity.value for e in events), default=Severity.CRITICAL.value)

        # ── 2. FILTER: REGEX-FIRST PRE-FILTERING ──
        fsm.transition_to(
            FSMStateName.FILTER,
            reason="Beginning regex-first pre-filtering and noise scrubbing",
        )

        raw_lines = self._flatten_events_to_lines(events)
        context.raw_line_count = len(raw_lines)
        filter_result = self.pre_filter.filter(raw_lines)

        context.filtered_lines = filter_result.filtered_lines
        context.filtered_line_count = len(filter_result.filtered_lines)
        context.prefilter_compression_ratio = filter_result.stats.compression_ratio

        # ── 3. ANALYZE: BI-TEMPORAL TOPOLOGY & EVIDENCE ──
        fsm.transition_to(
            FSMStateName.ANALYZE,
            reason="Pre-filtering complete; inspecting bi-temporal state graph",
            metadata={"compression_ratio": filter_result.stats.compression_ratio},
        )

        now = datetime.now(UTC)
        graph_diff: TemporalGraphDiff | None = None
        if self.graph_store:
            try:
                t_baseline = datetime.fromtimestamp(now.timestamp() - 600, tz=UTC)
                graph_diff = await self.graph_store.diff_snapshots(t1=t_baseline, t2=now)
                context.graph_diff = graph_diff
            except Exception as graph_err:
                self._log.error("graph_diff_extraction_failed", error=str(graph_err))
                fsm.fail(f"Bi-temporal graph store query failed: {graph_err}")
                raise RuntimeError(
                    f"Bi-temporal graph store query failed: {graph_err}"
                ) from graph_err

        # Factual telemetry-backed summary (no canned claims)
        svc_list = ", ".join(context.target_services)
        context.root_cause_summary = (
            f"Observed incident across {len(context.target_services)} service(s): {svc_list}. "
            f"Namespace: {target_namespace}. Pre-filter preserved "
            f"{context.filtered_line_count} error frame(s) "
            f"from {context.raw_line_count} raw line(s). Evidence Gate evaluation pending."
        )

        # Candidate simulation script generated dynamically from target service & namespace
        fix_script_code = (
            f"#!/usr/bin/env bash\n"
            f"# Remediation verification check for {target_svc} in namespace {target_namespace}\n"
            f"kubectl rollout status deployment/{target_svc} -n {target_namespace} --timeout=60s\n"
        )
        context.proposed_fix_script = {
            "language": "bash",
            "content": fix_script_code,
            "target_service": target_svc,
            "target_namespace": target_namespace,
        }

        # ── 4. SANDBOX: SIMULATION & GIT WORKTREE ISOLATION ──
        fsm.transition_to(
            FSMStateName.SANDBOX,
            reason="Executing simulation validation inside E2B sandbox and isolated worktree",
        )

        # 4a. Isolate patch inside git worktree (fail explicitly if worktree fails)
        worktree_session: GitWorktreeSession | None = None
        try:
            worktree_session = await self.worktree_manager.create_worktree(
                incident_id=context.incident_id
            )
            patch_file = f"deploy/{target_svc}/remediation.sh"
            await worktree_session.apply_file(patch_file, fix_script_code)
            context.worktree_diff = await worktree_session.get_diff()
        except Exception as wt_err:
            self._log.error("worktree_isolation_failed", error=str(wt_err))
            fsm.fail(f"Worktree isolation failed: {wt_err}")
            raise RuntimeError(
                f"Failed to isolate remediation patch in worktree: {wt_err}"
            ) from wt_err
        finally:
            if worktree_session:
                await worktree_session.cleanup()

        # 4b. Execute simulation inside E2B Micro-Sandbox
        sbx_result = await self.sandbox_runner.execute_simulation(
            script_content=fix_script_code,
            language="bash",
        )
        context.sandbox_result = sbx_result.model_dump()

        if sbx_result.status != "pass":
            fsm.fail(f"E2B sandbox validation failed with exit code {sbx_result.exit_code}")
            return context

        # ── 5. APPROVE: DISPATCH HUMAN VERIFICATION CARD ──
        fsm.transition_to(
            FSMStateName.APPROVE,
            reason="Sandbox simulation passed; awaiting human operator approval",
            metadata={"sandbox_status": sbx_result.status, "duration_ms": sbx_result.duration_ms},
        )

        approval_id = f"appr-{context.incident_id[:8]}"
        slack_card = build_slack_approval_card(
            incident_id=context.incident_id,
            approval_id=approval_id,
            severity=context.severity,
            service_tier=context.service_tier,
            fix_script_language="bash",
            fix_script_content=fix_script_code,
            sandbox_result=sbx_result,
            graph_diff=graph_diff,
        )
        context.metadata["slack_card"] = slack_card
        context.metadata["fsm_instance"] = fsm
        context.metadata["approval_id"] = approval_id

        self._log.info(
            "triage_pipeline_awaiting_approval",
            incident_id=context.incident_id,
            state=fsm.current_state,
        )

        return context

    async def resolve_incident_approval(
        self,
        context: IncidentContext,
        decision: str,
        decided_by: str,
        reason: str | None = None,
        action_executor: (
            Callable[[IncidentContext], Awaitable[RemediationExecutionResult]] | None
        ) = None,
    ) -> IncidentContext:
        """
        Executes final stages post-human decision:
        APPROVE ──► DEPLOY ──► COMPLETED (or ERROR if rejected / execution unverified)

        SAFETY INVARIANT (Step 1):
        DEPLOY is only reachable via a real executed, verified action. Never writes "resolved"
        unless verification passed.
        """
        fsm: SREStateMachine = context.metadata.get("fsm_instance") or SREStateMachine(
            context=context, initial_state=FSMStateName.APPROVE
        )

        context.approval_decision = decision.lower().strip()
        context.decided_by = decided_by
        context.decided_at = datetime.now(UTC)
        context.decision_reason = reason

        if context.approval_decision == "approved":
            if action_executor is None:
                raise RuntimeError(
                    "Cannot deploy: No action executor provided. DEPLOY is only reachable "
                    "via real executed, verified action."
                )

            # ── 6. DEPLOY: EXECUTE ACTION ──
            fsm.transition_to(
                FSMStateName.DEPLOY,
                reason=f"Approved by {decided_by}; executing remediation action",
                metadata={"decided_by": decided_by},
            )

            exec_result = await action_executor(context)

            # VERIFICATION GATE: Never write "resolved" unless verification passed
            if not exec_result.verification_passed:
                fsm.fail(
                    reason=f"Remediation action failed verification: {exec_result.details}",
                    metadata={
                        "action_type": exec_result.action_type,
                        "details": exec_result.details,
                    },
                )
                self._log.error(
                    "remediation_verification_failed",
                    incident_id=context.incident_id,
                    details=exec_result.details,
                )
                context.deployment_result = {
                    "status": "failed_verification",
                    "details": exec_result.details,
                    "timestamp": datetime.now(UTC).isoformat(),
                }
                return context

            context.deployment_result = {
                "status": "verified",
                "action_type": exec_result.action_type,
                "target_uid": exec_result.target_uid,
                "details": exec_result.details,
                "audit_hash": exec_result.audit_hash,
                "timestamp": exec_result.executed_at.isoformat(),
            }

            # ── 7. COMPLETED & RUNLORE POST-MORTEM ──
            fsm.transition_to(
                FSMStateName.COMPLETED,
                reason=f"Action verified successfully: {exec_result.details}",
            )

            # Auto-compile RunLore Post-Mortem Report
            pm_file, _ = self.post_mortem_gen.generate(
                context=context,
                transitions=fsm.transitions,
            )
            context.post_mortem_path = str(pm_file)

            self._log.info(
                "incident_fully_resolved",
                incident_id=context.incident_id,
                post_mortem=str(pm_file),
            )

        else:
            reason_text = reason or "No reason provided"
            fsm.fail(
                reason=f"Remediation rejected by human operator {decided_by}: {reason_text}"
            )
            self._log.warning(
                "incident_remediation_rejected",
                incident_id=context.incident_id,
                decided_by=decided_by,
            )

        return context

    def _flatten_events_to_lines(self, events: list[TelemetryEvent]) -> list[str]:
        """Flattens structured telemetry events into lines for regex pre-filtering."""
        lines: list[str] = []
        for ev in events:
            lines.append(
                f"[{ev.timestamp.isoformat()}] [{ev.severity.upper()}] metric={ev.metric_name}"
            )
            for k, v in ev.labels.items():
                lines.append(f"  label: {k}={v}")
            for pt in ev.data_points[:5]:
                lines.append(f"  datapoint: {pt.timestamp.isoformat()} value={pt.value}")
            if len(ev.data_points) > 5:
                lines.append(f"  ... [{len(ev.data_points) - 5} points collapsed] ...")
        return lines
