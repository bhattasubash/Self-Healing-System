"""
Tests for Deterministic Evidence Gate (PRD Section 8.1, D-02).

Verifies:
- Rules R1 to R8 deterministic evaluation.
- Classification into Tier A, Tier B, Tier C, and Healthy.
- GitOps delivery path routing (A1 direct vs A2 revert PR).
- Exact evidence ID citations and unknowns reporting.
- Default-deny safety on ambiguous alerts, migrations, and policy violations.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.services.evidence_gate import (
    EvidenceGate,
    EvidenceGateContext,
    EvidenceTier,
    RemediationActionType,
)


@pytest.fixture
def gate() -> EvidenceGate:
    return EvidenceGate()


def _valid_context(**overrides: object) -> EvidenceGateContext:
    now = datetime.now(UTC)
    ctx = EvidenceGateContext(
        incident_id="inc-gate-001",
        target_workloads=["deployment/payment-service"],
        alert_firing=True,
        first_symptom_time=now,
        change_time=now - timedelta(minutes=10),
        symptoms=["CrashLoopBackOff", "restarts_increasing"],
        independent_signals_count=2,
        previous_revision_healthy=True,
        previous_revision_duration_minutes=60.0,
        has_history=True,
        target_revision_exists=True,
        is_first_revision=False,
        has_irreversible_migration=False,
        rollout_in_flight=False,
        recent_rollback_in_30m=False,
        hpa_flapping=False,
        local_policy_allowed=True,
        freeze_window_active=False,
        is_gitops_managed=False,
    )
    for k, v in overrides.items():
        setattr(ctx, k, v)
    return ctx


def test_tier_a_direct_rollback_when_all_rules_pass(gate: EvidenceGate) -> None:
    ctx = _valid_context()
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_A
    assert result.proposed_action == RemediationActionType.A1_ROLLBACK
    assert len(result.rule_evaluations) == 8
    assert all(r.passed for r in result.rule_evaluations)
    assert any("EVD-R1" in r.evidence_id for r in result.rule_evaluations)
    assert any("EVD-R8" in r.evidence_id for r in result.rule_evaluations)


def test_tier_a_routes_to_gitops_revert_pr(gate: EvidenceGate) -> None:
    ctx = _valid_context(is_gitops_managed=True)
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_A
    assert result.proposed_action == RemediationActionType.A2_REVERT_PR


def test_tier_b_when_no_prior_history(gate: EvidenceGate) -> None:
    ctx = _valid_context(has_history=False)
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_B
    assert result.proposed_action == RemediationActionType.A1_ROLLBACK
    # R4 should fail or be incomplete
    r4 = next(r for r in result.rule_evaluations if r.rule_id == "R4")
    assert r4.passed is False
    assert "no history" in r4.details.lower() or "capped at b" in r4.details.lower()


def test_tier_b_when_only_one_signal_present(gate: EvidenceGate) -> None:
    ctx = _valid_context(independent_signals_count=1)
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_B
    r4 = next(r for r in result.rule_evaluations if r.rule_id == "R4")
    assert r4.passed is False


def test_tier_c_when_ambiguous_workloads(gate: EvidenceGate) -> None:
    ctx = _valid_context(target_workloads=["deployment/orders", "deployment/payments"])
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_C
    assert result.proposed_action == RemediationActionType.NO_ACTION
    r1 = next(r for r in result.rule_evaluations if r.rule_id == "R1")
    assert r1.passed is False


def test_tier_c_when_symptom_preceded_change(gate: EvidenceGate) -> None:
    now = datetime.now(UTC)
    ctx = _valid_context(
        first_symptom_time=now - timedelta(minutes=15),
        change_time=now,  # Change happened AFTER symptoms
    )
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_C
    r2 = next(r for r in result.rule_evaluations if r.rule_id == "R2")
    assert r2.passed is False


def test_tier_c_when_change_exceeds_30m_window(gate: EvidenceGate) -> None:
    now = datetime.now(UTC)
    ctx = _valid_context(
        first_symptom_time=now,
        change_time=now - timedelta(minutes=45),  # 45m > 30m gap
    )
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_C
    r2 = next(r for r in result.rule_evaluations if r.rule_id == "R2")
    assert r2.passed is False


def test_tier_c_when_irreversible_migration_flagged(gate: EvidenceGate) -> None:
    ctx = _valid_context(has_irreversible_migration=True)
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_C
    assert result.proposed_action == RemediationActionType.NO_ACTION
    r5 = next(r for r in result.rule_evaluations if r.rule_id == "R5")
    assert r5.passed is False


def test_tier_c_when_system_not_quiet(gate: EvidenceGate) -> None:
    ctx = _valid_context(recent_rollback_in_30m=True)
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_C
    r6 = next(r for r in result.rule_evaluations if r.rule_id == "R6")
    assert r6.passed is False


def test_tier_c_when_policy_denied(gate: EvidenceGate) -> None:
    ctx = _valid_context(local_policy_allowed=False)
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_C
    r7 = next(r for r in result.rule_evaluations if r.rule_id == "R7")
    assert r7.passed is False


def test_tier_c_when_in_freeze_window(gate: EvidenceGate) -> None:
    ctx = _valid_context(freeze_window_active=True)
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.TIER_C
    r7 = next(r for r in result.rule_evaluations if r.rule_id == "R7")
    assert r7.passed is False


def test_healthy_outcome_when_no_active_symptoms(gate: EvidenceGate) -> None:
    ctx = _valid_context(alert_firing=False, symptoms=[])
    result = gate.evaluate(ctx)

    assert result.tier == EvidenceTier.HEALTHY
    assert result.proposed_action == RemediationActionType.NO_ACTION
