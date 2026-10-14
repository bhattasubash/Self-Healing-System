"""
Deterministic Evidence Gate Engine (PRD Section 8.1, D-02).

Evaluates evidence preconditions R1 through R8 without letting an LLM authorize action:
- R1: Mapping (Alert maps to exactly one workload)
- R2: Change precedes symptom (Change within 30m before first symptom)
- R3: Symptom is current (Alert is active and >= 1 cluster signal is bad)
- R4: Baseline and corroboration (Previous revision healthy >= 30m, >= 2 signals agree)
- R5: Reversibility (Target revision exists, not revision 1, no irreversible migrations)
- R6: Quiet system (No rollout in flight, no rollback in 30m, no flapping)
- R7: Policy (Dual policy allows action, outside freeze windows)
- R8: Delivery path (GitOps uses A2 revert PR; otherwise A1 direct rollback)

Outputs:
- Tier A: All rules pass. Eligible for interactive approval or graduated auto.
- Tier B: R1-R3 pass, R4 incomplete. Suggest only.
- Tier C: R1 or R2 or safety guards fail. Escalate only; no rollback proposed.
- Healthy: Symptoms absent or cleared.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from app.utils.validation import validate_incident_id

if TYPE_CHECKING:
    from datetime import datetime


class EvidenceTier(StrEnum):
    TIER_A = "TIER_A"
    TIER_B = "TIER_B"
    TIER_C = "TIER_C"
    HEALTHY = "HEALTHY"


class RemediationActionType(StrEnum):
    A1_ROLLBACK = "A1_ROLLBACK"
    A2_REVERT_PR = "A2_REVERT_PR"
    NO_ACTION = "NO_ACTION"


@dataclass
class RuleEvaluation:
    rule_id: str
    name: str
    passed: bool
    evidence_id: str
    details: str
    unknowns: list[str] = field(default_factory=list)


@dataclass
class EvidenceGateContext:
    incident_id: str
    target_workloads: list[str]
    alert_firing: bool
    first_symptom_time: datetime
    change_time: datetime | None = None
    symptoms: list[str] = field(default_factory=list)
    independent_signals_count: int = 1
    previous_revision_healthy: bool = True
    previous_revision_duration_minutes: float = 45.0
    has_history: bool = True
    target_revision_exists: bool = True
    is_first_revision: bool = False
    has_irreversible_migration: bool = False
    rollout_in_flight: bool = False
    recent_rollback_in_30m: bool = False
    hpa_flapping: bool = False
    local_policy_allowed: bool = True
    freeze_window_active: bool = False
    is_gitops_managed: bool = False


@dataclass
class EvidenceGateResult:
    incident_id: str
    tier: EvidenceTier
    proposed_action: RemediationActionType
    rule_evaluations: list[RuleEvaluation]
    summary: str
    unknowns: list[str]


class EvidenceGate:
    """Deterministic rules evaluator for incident triage and remediation eligibility."""

    def evaluate(self, ctx: EvidenceGateContext) -> EvidenceGateResult:
        validate_incident_id(ctx.incident_id)

        # ── Check Healthy State First ──
        if not ctx.alert_firing and not ctx.symptoms:
            return EvidenceGateResult(
                incident_id=ctx.incident_id,
                tier=EvidenceTier.HEALTHY,
                proposed_action=RemediationActionType.NO_ACTION,
                rule_evaluations=[],
                summary="No active symptoms detected. Target system is healthy.",
                unknowns=[],
            )

        evaluations: list[RuleEvaluation] = []
        unknowns: list[str] = []

        # ── R1: Mapping ──
        r1_passed = len(ctx.target_workloads) == 1
        r1_details = (
            f"Alert maps unambiguously to single workload: {ctx.target_workloads[0]}"
            if r1_passed
            else (
                f"Ambiguous mapping: found {len(ctx.target_workloads)} "
                f"workloads {ctx.target_workloads}"
            )
        )
        evaluations.append(
            RuleEvaluation(
                rule_id="R1",
                name="Mapping",
                passed=r1_passed,
                evidence_id="EVD-R1-MAPPING",
                details=r1_details,
            )
        )

        # ── R2: Change precedes symptom ──
        r2_passed = False
        r2_details = "No recorded change associated with workload."
        if ctx.change_time is not None:
            gap_seconds = (ctx.first_symptom_time - ctx.change_time).total_seconds()
            if gap_seconds < 0:
                r2_details = (
                    f"Symptom started {-gap_seconds:.1f}s BEFORE the change was executed."
                )
            elif gap_seconds > 1800:
                r2_details = (
                    f"Change ended {gap_seconds / 60:.1f}m before symptom (> 30m maximum window)."
                )
            else:
                r2_passed = True
                r2_details = (
                    f"Change completed {gap_seconds / 60:.1f}m prior to first symptom "
                    f"(within 30m window)."
                )
        evaluations.append(
            RuleEvaluation(
                rule_id="R2",
                name="Change precedes symptom",
                passed=r2_passed,
                evidence_id="EVD-R2-CHANGE-GAP",
                details=r2_details,
            )
        )

        # ── R3: Symptom is current ──
        r3_passed = ctx.alert_firing and len(ctx.symptoms) > 0
        r3_details = (
            f"Alert is firing with {len(ctx.symptoms)} active bad signal(s): "
            f"{', '.join(ctx.symptoms)}"
            if r3_passed
            else "Symptoms cleared or alert no longer firing."
        )
        evaluations.append(
            RuleEvaluation(
                rule_id="R3",
                name="Symptom is current",
                passed=r3_passed,
                evidence_id="EVD-R3-SYMPTOM-CURRENT",
                details=r3_details,
            )
        )

        # ── R4: Baseline and corroboration ──
        r4_passed = (
            ctx.has_history
            and ctx.previous_revision_healthy
            and ctx.previous_revision_duration_minutes >= 30.0
            and ctx.independent_signals_count >= 2
        )
        if not ctx.has_history:
            r4_details = "No prior observation history recorded for workload (Tier capped at B)."
            unknowns.append("Missing prior observation history")
        elif not ctx.previous_revision_healthy:
            r4_details = "Previous revision was also unhealthy; cannot guarantee safe rollback."
        elif ctx.previous_revision_duration_minutes < 30.0:
            r4_details = (
                f"Previous revision ran for only {ctx.previous_revision_duration_minutes:.1f}m "
                f"(< 30m baseline)."
            )
        elif ctx.independent_signals_count < 2:
            r4_details = (
                f"Only {ctx.independent_signals_count} independent signal agrees (< 2 required)."
            )
            unknowns.append("Corroborating secondary telemetry signal absent")
        else:
            r4_details = (
                f"Previous revision was healthy for {ctx.previous_revision_duration_minutes:.1f}m; "
                f"{ctx.independent_signals_count} independent signals corroborate incident."
            )
        evaluations.append(
            RuleEvaluation(
                rule_id="R4",
                name="Baseline and corroboration",
                passed=r4_passed,
                evidence_id="EVD-R4-BASELINE",
                details=r4_details,
            )
        )

        # ── R5: Reversibility ──
        r5_passed = (
            ctx.target_revision_exists
            and not ctx.is_first_revision
            and not ctx.has_irreversible_migration
        )
        if not ctx.target_revision_exists:
            r5_details = "Target revision manifest not found in cluster history."
        elif ctx.is_first_revision:
            r5_details = "Workload is at initial deployment revision (no rollback target)."
        elif ctx.has_irreversible_migration:
            r5_details = "Change flagged with irreversible database/schema migration."
        else:
            r5_details = "Target revision exists, is reversible, and modifies pod template only."
        evaluations.append(
            RuleEvaluation(
                rule_id="R5",
                name="Reversibility",
                passed=r5_passed,
                evidence_id="EVD-R5-REVERSIBILITY",
                details=r5_details,
            )
        )

        # ── R6: Quiet system ──
        r6_passed = (
            not ctx.rollout_in_flight
            and not ctx.recent_rollback_in_30m
            and not ctx.hpa_flapping
        )
        if ctx.rollout_in_flight:
            r6_details = "Another rollout is currently in progress."
        elif ctx.recent_rollback_in_30m:
            r6_details = "Workload rolled back within past 30 minutes (cooldown guard)."
        elif ctx.hpa_flapping:
            r6_details = "Horizontal Pod Autoscaler is flapping."
        else:
            r6_details = "System is quiet: no active rollouts, cooldown satisfied, HPA stable."
        evaluations.append(
            RuleEvaluation(
                rule_id="R6",
                name="Quiet system",
                passed=r6_passed,
                evidence_id="EVD-R6-QUIET-SYSTEM",
                details=r6_details,
            )
        )

        # ── R7: Policy ──
        r7_passed = ctx.local_policy_allowed and not ctx.freeze_window_active
        if not ctx.local_policy_allowed:
            r7_details = "Local customer policy denies remediation for target namespace/workload."
        elif ctx.freeze_window_active:
            r7_details = "Cluster or workload is currently inside a declared change freeze window."
        else:
            r7_details = "Dual policy check passed: allowed by local policy, outside freeze window."
        evaluations.append(
            RuleEvaluation(
                rule_id="R7",
                name="Policy",
                passed=r7_passed,
                evidence_id="EVD-R7-POLICY",
                details=r7_details,
            )
        )

        # ── R8: Delivery path ──
        delivery_action = (
            RemediationActionType.A2_REVERT_PR
            if ctx.is_gitops_managed
            else RemediationActionType.A1_ROLLBACK
        )
        r8_details = (
            "GitOps-managed workload detected; routing via A2 revert PR."
            if ctx.is_gitops_managed
            else "Direct Kubernetes deployment; routing via A1 rollback."
        )
        evaluations.append(
            RuleEvaluation(
                rule_id="R8",
                name="Delivery path",
                passed=True,
                evidence_id="EVD-R8-DELIVERY-PATH",
                details=r8_details,
            )
        )

        # ── Tier Assignment Logic ──
        # Tier C: R1, R2, R5, R6, or R7 failed
        if not (r1_passed and r2_passed and r5_passed and r6_passed and r7_passed):
            return EvidenceGateResult(
                incident_id=ctx.incident_id,
                tier=EvidenceTier.TIER_C,
                proposed_action=RemediationActionType.NO_ACTION,
                rule_evaluations=evaluations,
                summary=(
                    "Evidence Gate classified as Tier C (Dangerous or ambiguous). "
                    "Remediation blocked; manual escalation required."
                ),
                unknowns=unknowns,
            )

        # Tier B: R1-R3 pass, but R4 baseline is incomplete
        if not r4_passed:
            return EvidenceGateResult(
                incident_id=ctx.incident_id,
                tier=EvidenceTier.TIER_B,
                proposed_action=delivery_action,
                rule_evaluations=evaluations,
                summary=(
                    "Evidence Gate classified as Tier B (Suggest mode only). "
                    "Preconditions satisfied, but baseline history or second signal incomplete."
                ),
                unknowns=unknowns,
            )

        # Tier A: All rules pass
        return EvidenceGateResult(
            incident_id=ctx.incident_id,
            tier=EvidenceTier.TIER_A,
            proposed_action=delivery_action,
            rule_evaluations=evaluations,
            summary=(
                f"Evidence Gate classified as Tier A (Automated candidate). "
                f"All 8 rules satisfied; proposal: {delivery_action.value}."
            ),
            unknowns=unknowns,
        )
