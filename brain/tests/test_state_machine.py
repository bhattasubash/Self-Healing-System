"""
Unit tests for the Deterministic State Machine Controller.

Verifies:
- Hardened deterministic pathways (no jumping states).
- Preconditions strictly enforced for safety gates (sandbox pass, human approval).
- Audit trail correctly populated.
- Rejection of illegal transitions.
"""

from datetime import datetime, timezone
import pytest

from app.schemas.telemetry import (
    DataPoint,
    FilterMethod,
    FilterStats,
    FSMStateName,
    Severity,
    TelemetryEvent,
    TelemetrySource,
)
from app.services.state_machine import (
    IncidentContext,
    InvalidStateTransitionError,
    SREStateMachine,
)


def _make_sample_event() -> TelemetryEvent:
    return TelemetryEvent(
        source=TelemetrySource.PROMETHEUS,
        metric_name="node_cpu_utilization_ratio",
        data_points=[
            DataPoint(
                timestamp=datetime.now(timezone.utc),
                value=0.98,
            )
        ],
        labels={"host": "MASKED_HOST_1234"},
        severity=Severity.CRITICAL,
        timestamp=datetime.now(timezone.utc),
        masking_applied=True,
        filter_stats=FilterStats(
            raw_line_count=10,
            filtered_line_count=2,
            filter_method=FilterMethod.REGEX,
            compression_ratio=0.2,
        ),
    )


def test_state_machine_valid_full_lifecycle() -> None:
    context = IncidentContext()
    context.events = [_make_sample_event()]

    fsm = SREStateMachine(context=context, initial_state=FSMStateName.INGEST)
    assert fsm.current_state == FSMStateName.INGEST

    # INGEST -> FILTER
    fsm.transition_to(FSMStateName.FILTER, "Filtering ingested telemetry")
    assert fsm.current_state == FSMStateName.FILTER

    # Populate filtered content for ANALYZE precondition
    context.filtered_lines = ["Critical error line"]

    # FILTER -> ANALYZE
    fsm.transition_to(FSMStateName.ANALYZE, "Analyzing root cause")
    assert fsm.current_state == FSMStateName.ANALYZE

    # Populate fix script for SANDBOX precondition
    context.proposed_fix_script = {
        "language": "bash",
        "content": "kubectl rollout restart deployment/web",
    }

    # ANALYZE -> SANDBOX
    fsm.transition_to(FSMStateName.SANDBOX, "Executing simulation in E2B sandbox")
    assert fsm.current_state == FSMStateName.SANDBOX

    # Simulate passing sandbox result for APPROVE precondition
    context.sandbox_result = {"status": "pass", "exit_code": 0}

    # SANDBOX -> APPROVE
    fsm.transition_to(FSMStateName.APPROVE, "Opening human approval gate")
    assert fsm.current_state == FSMStateName.APPROVE

    # Simulate human approval for DEPLOY precondition
    context.approval_decision = "approved"

    # APPROVE -> DEPLOY
    fsm.transition_to(FSMStateName.DEPLOY, "Human approved; deploying fix")
    assert fsm.current_state == FSMStateName.DEPLOY

    # DEPLOY -> COMPLETED
    fsm.transition_to(FSMStateName.COMPLETED, "Deployment verified")
    assert fsm.current_state == FSMStateName.COMPLETED

    # Verify audit ledger records every step: 1 initial + 6 transitions = 7 total
    assert len(fsm.transitions) == 7
    assert fsm.transitions[-1].to_state == FSMStateName.COMPLETED


def test_illegal_state_jump_is_blocked() -> None:
    context = IncidentContext()
    context.events = [_make_sample_event()]
    fsm = SREStateMachine(context=context, initial_state=FSMStateName.INGEST)

    # Attempting to bypass straight from INGEST to DEPLOY must throw
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        fsm.transition_to(FSMStateName.DEPLOY, "Attempting rogue bypass")

    assert "Transition not allowed by security matrix" in str(exc_info.value)
    assert fsm.current_state == FSMStateName.INGEST


def test_sandbox_failure_blocks_approval_gate() -> None:
    context = IncidentContext()
    context.events = [_make_sample_event()]
    context.filtered_lines = ["Error trace"]
    context.proposed_fix_script = {"language": "bash", "content": "bad script"}

    fsm = SREStateMachine(context=context, initial_state=FSMStateName.INGEST)
    fsm.transition_to(FSMStateName.FILTER, "Filtering")
    fsm.transition_to(FSMStateName.ANALYZE, "Analyzing")
    fsm.transition_to(FSMStateName.SANDBOX, "Simulating")

    # Simulation failed in sandbox
    context.sandbox_result = {"status": "fail", "exit_code": 1}

    # APPROVE transition must be blocked
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        fsm.transition_to(FSMStateName.APPROVE, "Attempting to approve failed script")

    assert "Sandbox validation failed with status 'fail'" in str(exc_info.value)


def test_deploy_blocked_without_human_approval() -> None:
    context = IncidentContext()
    context.events = [_make_sample_event()]
    context.filtered_lines = ["Error trace"]
    context.proposed_fix_script = {"language": "bash", "content": "restart"}
    context.sandbox_result = {"status": "pass", "exit_code": 0}

    fsm = SREStateMachine(context=context, initial_state=FSMStateName.INGEST)
    fsm.transition_to(FSMStateName.FILTER, "Filtering")
    fsm.transition_to(FSMStateName.ANALYZE, "Analyzing")
    fsm.transition_to(FSMStateName.SANDBOX, "Simulating")
    fsm.transition_to(FSMStateName.APPROVE, "Waiting for human")

    # Decision is still pending or rejected
    context.approval_decision = "pending"

    # DEPLOY transition must be rejected
    with pytest.raises(InvalidStateTransitionError) as exc_info:
        fsm.transition_to(FSMStateName.DEPLOY, "Attempting deploy without approval")

    assert "Write gate violation" in str(exc_info.value)
