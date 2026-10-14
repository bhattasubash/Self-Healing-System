"""
End-to-End Orchestration & RunLore Post-Mortem Integration Tests.

Verifies the complete incident lifecycle from telemetry triage to post-mortem:
  INGEST ──► FILTER ──► ANALYZE ──► SANDBOX ──► APPROVE ──► DEPLOY ──► COMPLETED
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.sandbox.e2b_runner import E2BMicroSandboxRunner, ResourceUsage, SandboxExecutionResult
from app.schemas.telemetry import (
    DataPoint,
    FilterMethod,
    FilterStats,
    FSMStateName,
    Severity,
    TelemetryEvent,
    TelemetrySource,
)
from app.services.graph_store import BiTemporalGraphStore, TemporalEntityDiff, TemporalGraphDiff
from app.services.orchestrator import SREOrchestrationCoordinator
from app.services.post_mortem import RunLorePostMortemGenerator


def _build_test_event(
    metric: str = "container_cpu_usage_seconds_total",
    severity: Severity = Severity.CRITICAL,
    masking: bool = True,
) -> TelemetryEvent:
    return TelemetryEvent(
        source=TelemetrySource.PROMETHEUS,
        metric_name=metric,
        data_points=[
            DataPoint(timestamp=datetime.now(UTC), value=0.99),
            DataPoint(timestamp=datetime.now(UTC), value=0.98),
        ],
        labels={
            "app": "payment-gateway",
            "node": "MASKED_NODE_worker_01",
            "namespace": "MASKED_NS_payments",
        },
        severity=severity,
        timestamp=datetime.now(UTC),
        masking_applied=masking,
        filter_stats=FilterStats(
            raw_line_count=20,
            filtered_line_count=2,
            filter_method=FilterMethod.REGEX,
            compression_ratio=0.1,
        ),
        anomaly_score=0.95,
    )


@pytest.mark.asyncio
async def test_e2e_successful_triage_to_resolution_and_post_mortem(tmp_path: Path) -> None:
    # 1. Setup Mocked Graph Store
    mock_graph_store = MagicMock(spec=BiTemporalGraphStore)
    mock_graph_diff = TemporalGraphDiff(
        t1=datetime.now(UTC),
        t2=datetime.now(UTC),
        node_diffs=[
            TemporalEntityDiff(
                entity_id="MASKED_SVC_payment_gateway",
                diff_type="MUTATED",
                modified_keys=["version", "db_pool_timeout"],
            )
        ],
        relationship_changes=[],
    )
    mock_graph_store.diff_snapshots = AsyncMock(return_value=mock_graph_diff)

    # 2. Setup Custom Sandbox Runner
    mock_sandbox_runner = E2BMicroSandboxRunner()
    fake_sbx_result = SandboxExecutionResult(
        sandbox_id="sbx-e2e-test",
        status="pass",
        exit_code=0,
        stdout="Rollout verification succeeded. Pods running.",
        stderr="",
        duration_ms=520,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        resource_usage=ResourceUsage(cpu_ms=520, memory_peak_mb=128),
        checksum="sha256:e2etest1234567890",
    )
    mock_sandbox_runner.execute_simulation = AsyncMock(return_value=fake_sbx_result)

    # 3. Setup Post-Mortem Generator in tmp_path
    post_mortem_gen = RunLorePostMortemGenerator(output_dir=tmp_path / ".incidents")

    coordinator = SREOrchestrationCoordinator(
        graph_store=mock_graph_store,
        sandbox_runner=mock_sandbox_runner,
        post_mortem_gen=post_mortem_gen,
    )

    events = [
        _build_test_event(metric="container_cpu_usage_seconds_total"),
        _build_test_event(metric="http_request_duration_seconds_bucket", severity=Severity.WARNING),
    ]

    # Step A: Run Triage Pipeline (INGEST -> FILTER -> ANALYZE -> SANDBOX -> APPROVE)
    context = await coordinator.run_triage_pipeline(
        events=events,
        incident_id="inc-e2e-84920",
        session_id="sess-e2e-001",
    )

    fsm: Any = context.metadata["fsm_instance"]
    assert fsm.current_state == FSMStateName.APPROVE
    assert context.prefilter_compression_ratio <= 1.0
    assert context.sandbox_result["status"] == "pass"
    assert "slack_card" in context.metadata
    assert context.worktree_diff is not None

    # Step B: Human Approves Resolution (APPROVE -> DEPLOY -> COMPLETED)
    resolved_context = await coordinator.resolve_incident_approval(
        context=context,
        decision="approved",
        decided_by="U9988_Principal_SRE",
        reason="Verified restart script in sandbox without regression.",
    )

    assert fsm.current_state == FSMStateName.COMPLETED
    assert resolved_context.commit_hash is not None
    assert resolved_context.post_mortem_path is not None

    # Step C: Verify Generated RunLore Post-Mortem Report
    pm_path = Path(resolved_context.post_mortem_path)
    assert pm_path.exists()
    pm_content = pm_path.read_text(encoding="utf-8")

    assert "# Incident Post-Mortem Report: `inc-e2e-84920`" in pm_content
    assert "U9988_Principal_SRE" in pm_content
    assert "sha256:e2etest1234567890" in pm_content
    assert "MASKED_SVC_payment_gateway" in pm_content
    assert "Rollout verification succeeded" in pm_content
    assert resolved_context.commit_hash in pm_content


@pytest.mark.asyncio
async def test_e2e_rejection_halts_deployment(tmp_path: Path) -> None:
    mock_sandbox_runner = E2BMicroSandboxRunner()
    fake_sbx_result = SandboxExecutionResult(
        sandbox_id="sbx-e2e-test",
        status="pass",
        exit_code=0,
        stdout="Syntax verified.",
        stderr="",
        duration_ms=200,
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
        checksum="sha256:testchecksum12345678",
    )
    mock_sandbox_runner.execute_simulation = AsyncMock(return_value=fake_sbx_result)

    coordinator = SREOrchestrationCoordinator(
        sandbox_runner=mock_sandbox_runner,
        post_mortem_gen=RunLorePostMortemGenerator(output_dir=tmp_path / ".incidents"),
    )
    events = [_build_test_event()]

    context = await coordinator.run_triage_pipeline(events=events)
    fsm: Any = context.metadata["fsm_instance"]
    assert fsm.current_state == FSMStateName.APPROVE

    # Operator Rejects
    resolved = await coordinator.resolve_incident_approval(
        context=context,
        decision="rejected",
        decided_by="U1234_Auditor",
        reason="Remediation script parameter needs manual tuning.",
    )

    assert fsm.current_state == FSMStateName.ERROR
    assert resolved.commit_hash is None
    assert resolved.post_mortem_path is None


@pytest.mark.asyncio
async def test_e2e_unmasked_telemetry_aborts_pipeline() -> None:
    coordinator = SREOrchestrationCoordinator()
    unmasked_event = _build_test_event(masking=False)

    with pytest.raises(ValueError) as exc_info:
        await coordinator.run_triage_pipeline(events=[unmasked_event])

    assert "unmasked telemetry events" in str(exc_info.value)
