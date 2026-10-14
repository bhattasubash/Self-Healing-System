"""
Deterministic Finite State Machine (FSM) Controller.

Guarantees hardened, deterministic engine pathways for incident triage.
Autonomous LLM execution is strictly confined to analysis tasks; all state
transitions follow explicit transition rules and preconditions.

State Lifecycle:
  INGEST ──► FILTER ──► ANALYZE ──► SANDBOX ──► APPROVE ──► DEPLOY ──► COMPLETED
    │          │          │           │           │          │
    └──────────┴──────────┴───────────┴───────────┴──────────┴────► ERROR
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

if TYPE_CHECKING:
    from collections.abc import Callable

import structlog

from app.schemas.telemetry import (
    FSMStateName,
    TelemetryEvent,
    TransitionRecord,
)
from app.utils.validation import validate_incident_id

logger = structlog.get_logger()

# ─── Allowed State Transition Matrix ───────────────────────────────────

ALLOWED_TRANSITIONS: Final[dict[FSMStateName, set[FSMStateName]]] = {
    FSMStateName.INGEST: {FSMStateName.FILTER, FSMStateName.ERROR},
    FSMStateName.FILTER: {FSMStateName.ANALYZE, FSMStateName.ERROR},
    FSMStateName.ANALYZE: {FSMStateName.SANDBOX, FSMStateName.ERROR},
    FSMStateName.SANDBOX: {FSMStateName.APPROVE, FSMStateName.ANALYZE, FSMStateName.ERROR},
    FSMStateName.APPROVE: {FSMStateName.DEPLOY, FSMStateName.ERROR},
    FSMStateName.DEPLOY: {FSMStateName.COMPLETED, FSMStateName.ERROR},
    FSMStateName.ERROR: set(),      # Terminal failure state
    FSMStateName.COMPLETED: set(),  # Terminal success state
}


class InvalidStateTransitionError(Exception):
    """Raised when an illegal state transition is attempted."""

    def __init__(self, from_state: FSMStateName, to_state: FSMStateName, reason: str) -> None:
        super().__init__(
            f"Illegal state transition attempted: '{from_state}' -> '{to_state}'. Reason: {reason}"
        )
        self.from_state = from_state
        self.to_state = to_state
        self.reason = reason


class IncidentContext:
    """
    Mutable state container carried throughout the FSM execution lifecycle.
    Keeps historical trace snapshots, generated scripts, sandbox runs, and approvals.
    """

    def __init__(
        self,
        incident_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        self.incident_id: str = (
            validate_incident_id(incident_id) if incident_id else str(uuid.uuid4())
        )
        self.session_id: str = session_id or str(uuid.uuid4())
        self.events: list[TelemetryEvent] = []
        self.filtered_lines: list[str] = []
        self.prefilter_compression_ratio: float = 1.0
        self.raw_line_count: int = 0
        self.filtered_line_count: int = 0
        self.analysis_findings: dict[str, Any] = {}
        self.root_cause_summary: str | None = None
        self.proposed_fix_script: dict[str, Any] | None = None
        self.sandbox_result: dict[str, Any] | None = None
        self.approval_decision: str | None = None
        self.decided_by: str | None = None
        self.decided_at: datetime | None = None
        self.decision_reason: str | None = None
        self.deployment_result: dict[str, Any] | None = None
        self.worktree_diff: str | None = None
        self.commit_hash: str | None = None
        self.graph_diff: Any | None = None
        self.target_services: list[str] = []
        self.severity: str = "critical"
        self.service_tier: str = "tier0"
        self.post_mortem_path: str | None = None
        self.metadata: dict[str, Any] = {}


class SREStateMachine:
    """
    Deterministic State Machine enforcing deterministic transition pathways.
    Prevents autonomous routing hallucinations and maintains an immutable audit ledger.
    """

    def __init__(
        self,
        context: IncidentContext,
        initial_state: FSMStateName = FSMStateName.INGEST,
    ) -> None:
        self.context = context
        self._current_state = initial_state
        self._transitions: list[TransitionRecord] = []
        self._hooks: dict[FSMStateName, list[Callable[[IncidentContext], None]]] = {
            state: [] for state in FSMStateName
        }
        self._log = logger.bind(
            component="state_machine",
            incident_id=self.context.incident_id,
            session_id=self.context.session_id,
        )

        # Record initial creation
        self._record_transition(
            from_state=FSMStateName.INGEST,
            to_state=initial_state,
            reason="Incident state machine initialized",
        )

    @property
    def current_state(self) -> FSMStateName:
        return self._current_state

    @property
    def transitions(self) -> list[TransitionRecord]:
        return list(self._transitions)

    def register_hook(
        self,
        state: FSMStateName,
        hook: Callable[[IncidentContext], None],
    ) -> None:
        """Register an observer callback hook triggered when entering a given state."""
        self._hooks[state].append(hook)

    def transition_to(
        self,
        target_state: FSMStateName,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """
        Transition to a new state after verifying transition matrix rules and preconditions.
        """
        valid_destinations = ALLOWED_TRANSITIONS.get(self._current_state, set())
        if target_state not in valid_destinations:
            self._log.error(
                "invalid_transition_attempt",
                from_state=self._current_state,
                target_state=target_state,
                reason=reason,
            )
            raise InvalidStateTransitionError(
                from_state=self._current_state,
                to_state=target_state,
                reason=f"Transition not allowed by security matrix from '{self._current_state}'",
            )

        # Enforce prerequisite guard conditions
        self._verify_preconditions(target_state)

        from_state = self._current_state
        self._current_state = target_state
        self._record_transition(from_state, target_state, reason, metadata or {})

        self._log.info(
            "state_transition_committed",
            from_state=from_state,
            to_state=target_state,
            reason=reason,
        )

        # Execute registered hooks
        for hook in self._hooks[target_state]:
            try:
                hook(self.context)
            except Exception as hook_err:
                self._log.error(
                    "hook_execution_failed",
                    target_state=target_state,
                    error=str(hook_err),
                )

    def fail(self, reason: str, metadata: dict[str, Any] | None = None) -> None:
        """Explicitly transition to the ERROR state from any non-terminal state."""
        if self._current_state in (FSMStateName.ERROR, FSMStateName.COMPLETED):
            return
        from_state = self._current_state
        self._current_state = FSMStateName.ERROR
        self._record_transition(
            from_state=from_state,
            to_state=FSMStateName.ERROR,
            reason=reason,
            metadata=metadata or {},
        )
        self._log.error("state_machine_aborted", reason=reason, from_state=from_state)

    def _verify_preconditions(self, target_state: FSMStateName) -> None:
        """
        Hardened safety checks executed before allowing state transitions.
        """
        if target_state == FSMStateName.FILTER:
            if not self.context.events:
                raise InvalidStateTransitionError(
                    self._current_state,
                    target_state,
                    "Cannot filter telemetry: no telemetry events ingested in context.",
                )

        elif target_state == FSMStateName.ANALYZE:
            if not self.context.filtered_lines and not self.context.events:
                raise InvalidStateTransitionError(
                    self._current_state,
                    target_state,
                    "Cannot trigger analysis: pre-filter yielded 0 actionable lines.",
                )

        elif target_state == FSMStateName.SANDBOX:
            if not self.context.proposed_fix_script:
                raise InvalidStateTransitionError(
                    self._current_state,
                    target_state,
                    "Cannot execute sandbox simulation: no fix script was generated.",
                )

        elif target_state == FSMStateName.APPROVE:
            if not self.context.sandbox_result:
                raise InvalidStateTransitionError(
                    self._current_state,
                    target_state,
                    "Cannot open human gate: fix script has not completed sandbox simulation.",
                )
            if self.context.sandbox_result.get("status") != "pass":
                raise InvalidStateTransitionError(
                    self._current_state,
                    target_state,
                    f"Sandbox validation failed with status "
                    f"'{self.context.sandbox_result.get('status')}'. Human approval gate blocked.",
                )

        elif (
            target_state == FSMStateName.DEPLOY
            and self.context.approval_decision != "approved"
        ):
            raise InvalidStateTransitionError(
                self._current_state,
                target_state,
                "Write gate violation: Deployment attempted without verified human approval.",
            )

    def _record_transition(
        self,
        from_state: FSMStateName,
        to_state: FSMStateName,
        reason: str,
        metadata: dict[str, Any] | None = None,
    ) -> TransitionRecord:
        record = TransitionRecord(
            from_state=from_state,
            to_state=to_state,
            timestamp=datetime.now(UTC),
            reason=reason,
            metadata=metadata or {},
        )
        self._transitions.append(record)
        return record
