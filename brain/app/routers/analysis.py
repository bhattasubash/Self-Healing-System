"""
Analysis router for incident telemetry ingestion and triage.

Endpoint:
  POST /api/v1/analyze - Ingests masked telemetry, executes regex pre-filtering,
                         drives deterministic state machine transitions, and outputs
                         structured reasoning summaries.
"""

from __future__ import annotations

from typing import Annotated

import structlog
from fastapi import APIRouter, Depends, HTTPException, status

from app.config import Settings, get_settings
from app.schemas.telemetry import (
    AnalysisRequest,
    AnalysisResponse,
    FSMStateName,
)
from app.services.pre_filter import TracePreFilter
from app.services.state_machine import (
    IncidentContext,
    InvalidStateTransitionError,
    SREStateMachine,
)

router = APIRouter(prefix="/api/v1", tags=["Analysis"])
logger = structlog.get_logger()


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze masked telemetry events through deterministic FSM and regex pre-filtering",
)
async def analyze_telemetry(
    request: AnalysisRequest,
    settings: Annotated[Settings, Depends(get_settings)],
) -> AnalysisResponse:
    """
    Ingests masked telemetry events and drives the incident through deterministic FSM states:
    1. Ingestion validation: verifies masking integrity.
    2. Regex-first pre-filtering: collapses repeated lines, strips noise, prioritizes errors.
    3. State transition from INGEST -> FILTER -> ANALYZE.
    4. Structured analytical synthesis for root-cause hypothesis generation.
    """
    req_logger = logger.bind(
        session_id=request.session_id,
        event_count=len(request.events),
    )
    req_logger.info("received_analysis_request")

    # Safety validation: Verify all incoming events have been masked
    unmasked_events = [e for e in request.events if not e.masking_applied]
    if unmasked_events:
        req_logger.error(
            "unmasked_telemetry_detected",
            unmasked_count=len(unmasked_events),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Data perimeter violation: {len(unmasked_events)} telemetry event(s) "
                f"did not have reversible masking applied."
            ),
        )

    # Initialize Context and State Machine
    context = IncidentContext(session_id=request.session_id)
    context.events = request.events
    fsm = SREStateMachine(context=context, initial_state=FSMStateName.INGEST)

    # Initialize Pre-Filter using configured budget
    pre_filter = TracePreFilter(
        context_budget_max_tokens=settings.pre_filter.context_budget_max_tokens,
        compression_target=settings.pre_filter.compression_target,
    )

    try:
        # ── State Transition: INGEST -> FILTER ──
        fsm.transition_to(
            target_state=FSMStateName.FILTER,
            reason="Beginning regex-first pre-filtering on telemetry labels and time-series data",
        )

        # Flatten telemetry into lines for high-throughput regex scrubbing
        raw_trace_lines: list[str] = []
        for event in request.events:
            header = (
                f"[{event.timestamp.isoformat()}] [{event.severity.upper()}] "
                f"metric={event.metric_name}"
            )
            raw_trace_lines.append(header)
            for k, v in event.labels.items():
                raw_trace_lines.append(f"  label: {k}={v}")
            # Sample up to first 5 and last 5 datapoints to avoid bloating raw line feeds
            points = event.data_points
            if len(points) <= 10:
                for pt in points:
                    raw_trace_lines.append(f"  data: {pt.timestamp.isoformat()} val={pt.value}")
            else:
                for pt in points[:5]:
                    raw_trace_lines.append(f"  data: {pt.timestamp.isoformat()} val={pt.value}")
                raw_trace_lines.append(f"  ... [{len(points) - 10} data points collapsed] ...")
                for pt in points[-5:]:
                    raw_trace_lines.append(f"  data: {pt.timestamp.isoformat()} val={pt.value}")

        # Execute regex pre-filter
        filter_result = pre_filter.filter(raw_trace_lines)
        context.filtered_lines = filter_result.filtered_lines
        context.prefilter_compression_ratio = filter_result.stats.compression_ratio

        # ── State Transition: FILTER -> ANALYZE ──
        fsm.transition_to(
            target_state=FSMStateName.ANALYZE,
            reason="Pre-filtering complete; entering deterministic analytical synthesis",
            metadata={
                "compression_ratio": filter_result.stats.compression_ratio,
                "filtered_lines": filter_result.stats.filtered_line_count,
            },
        )

        # Analytical Synthesis: Evaluate findings across filtered lines and anomaly scores
        critical_lines = [
            line for line in filter_result.filtered_lines
            if any(term in line.upper() for term in ("CRITICAL", "FATAL", "ERROR", "PANIC"))
        ]

        metrics_observed = sorted({e.metric_name for e in request.events})
        highest_anomaly = max(
            (e.anomaly_score for e in request.events if e.anomaly_score is not None),
            default=0.0,
        )

        analysis_summary_text = (
            f"Analyzed {len(request.events)} telemetry event(s) across metrics: "
            f"{', '.join(metrics_observed)}. "
            f"Pre-filter achieved {filter_result.stats.compression_ratio:.2%} compression ratio. "
            f"Identified {len(critical_lines)} critical line(s). "
            f"Max anomaly score: {highest_anomaly:.2f}."
        )

        context.analysis_findings = {
            "metrics": metrics_observed,
            "max_anomaly_score": highest_anomaly,
            "critical_lines_count": len(critical_lines),
            "destructive_patterns_flagged": len(filter_result.destructive_commands),
        }
        context.root_cause_summary = analysis_summary_text

        req_logger.info(
            "analysis_completed",
            incident_id=context.incident_id,
            metrics_count=len(metrics_observed),
            compression_ratio=filter_result.stats.compression_ratio,
        )

        return AnalysisResponse(
            incident_id=context.incident_id,
            current_state=fsm.current_state,
            transitions=fsm.transitions,
            filtered_event_count=len(request.events),
            total_raw_lines=filter_result.stats.raw_line_count,
            total_filtered_lines=filter_result.stats.filtered_line_count,
            compression_ratio=filter_result.stats.compression_ratio,
            analysis_summary=analysis_summary_text,
            error=None,
        )

    except InvalidStateTransitionError as transition_err:
        req_logger.error(
            "fsm_transition_rejected",
            error=str(transition_err),
        )
        fsm.fail(reason=str(transition_err))
        return AnalysisResponse(
            incident_id=context.incident_id,
            current_state=fsm.current_state,
            transitions=fsm.transitions,
            filtered_event_count=len(request.events),
            total_raw_lines=len(raw_trace_lines) if "raw_trace_lines" in locals() else 0,
            total_filtered_lines=len(context.filtered_lines),
            compression_ratio=context.prefilter_compression_ratio,
            analysis_summary=None,
            error=str(transition_err),
        )
    except Exception as exc:
        req_logger.exception("unhandled_analysis_error", error=str(exc))
        fsm.fail(reason=f"Unhandled internal error during analysis: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis pipeline failed: {exc}",
        ) from exc
