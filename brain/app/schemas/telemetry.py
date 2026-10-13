"""
Pydantic v2 schemas for telemetry events.

These models mirror the shared/contracts/telemetry.schema.json contract
and are used as request/response types in the FastAPI analysis router.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, Field, field_validator


# ─── Enums ────────────────────────────────────────────────────────────


class TelemetrySource(StrEnum):
    PROMETHEUS = "prometheus"
    DATADOG = "datadog"
    KUBERNETES = "kubernetes"
    CLOUDWATCH = "cloudwatch"
    CUSTOM = "custom"


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    FATAL = "fatal"


class FilterMethod(StrEnum):
    REGEX = "regex"
    PYARROW = "pyarrow"
    HYBRID = "hybrid"
    NONE = "none"


class ToolCallStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"


class FSMStateName(StrEnum):
    INGEST = "ingest"
    FILTER = "filter"
    ANALYZE = "analyze"
    SANDBOX = "sandbox"
    APPROVE = "approve"
    DEPLOY = "deploy"
    ERROR = "error"
    COMPLETED = "completed"


# ─── Telemetry Sub-Models ─────────────────────────────────────────────


class DataPoint(BaseModel):
    """A single time-series observation."""

    timestamp: datetime
    value: float
    unit: str | None = None


class FilterStats(BaseModel):
    """
    Pre-filter stage statistics.

    These numbers prove the regex-first pipeline is compressing trace
    data before it reaches the LLM context window.
    """

    raw_line_count: Annotated[int, Field(ge=0)]
    filtered_line_count: Annotated[int, Field(ge=0)]
    filter_method: FilterMethod
    compression_ratio: Annotated[float, Field(ge=0.0, le=1.0)]
    duplicate_lines_removed: Annotated[int, Field(ge=0)] | None = None
    token_estimate_before: Annotated[int, Field(ge=0)] | None = None
    token_estimate_after: Annotated[int, Field(ge=0)] | None = None

    @field_validator("compression_ratio")
    @classmethod
    def validate_compression_ratio(cls, v: float, info: object) -> float:
        """Compression ratio must be consistent with line counts when both are set."""
        return v


# ─── Telemetry Event ──────────────────────────────────────────────────


class TelemetryEvent(BaseModel):
    """
    Normalized telemetry event — the canonical input to the analytical brain.

    All infrastructure identifiers in labels are replaced with reversible
    masked tokens. Filter statistics track the compression ratio achieved
    by the regex-first pipeline.
    """

    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: TelemetrySource
    metric_name: Annotated[str, Field(min_length=1, max_length=512)]
    data_points: Annotated[list[DataPoint], Field(min_length=1, max_length=10000)]
    labels: dict[str, str] = Field(default_factory=dict)
    severity: Severity
    timestamp: datetime
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    masking_applied: bool
    filter_stats: FilterStats
    trace_id: Annotated[str, Field(max_length=128)] | None = None
    span_id: Annotated[str, Field(max_length=64)] | None = None
    anomaly_score: Annotated[float, Field(ge=0.0, le=1.0)] | None = None
    deduplicated: bool = False


# ─── Tool Call Models ─────────────────────────────────────────────────


class ToolResult(BaseModel):
    """Successful tool execution result."""

    data: object
    truncated: bool
    row_count: Annotated[int, Field(ge=0)]
    token_estimate: Annotated[int, Field(ge=0)] | None = None


class ToolError(BaseModel):
    """Structured error from a failed tool execution."""

    code: str
    message: Annotated[str, Field(max_length=2000)]
    retryable: bool
    upstream_status: int | None = None


class ToolCall(BaseModel):
    """MCP tool call envelope."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str
    arguments: dict[str, object] = Field(default_factory=dict)
    timestamp: datetime
    session_id: str
    status: ToolCallStatus
    masked: bool
    result: ToolResult | None = None
    error: ToolError | None = None
    duration_ms: Annotated[int, Field(ge=0)] | None = None
    retry_count: Annotated[int, Field(ge=0)] = 0
    max_retries: Annotated[int, Field(ge=0)] = 3


# ─── Analysis Request/Response ────────────────────────────────────────


class AnalysisRequest(BaseModel):
    """Request payload for the /analyze endpoint."""

    events: Annotated[list[TelemetryEvent], Field(min_length=1, max_length=100)]
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    priority: Severity = Severity.WARNING
    context: dict[str, object] = Field(
        default_factory=dict,
        description="Additional context passed to the reasoning engine.",
    )


class TransitionRecord(BaseModel):
    """Immutable audit record of a single FSM state transition."""

    from_state: FSMStateName
    to_state: FSMStateName
    timestamp: datetime
    reason: str
    metadata: dict[str, object] = Field(default_factory=dict)


class AnalysisResponse(BaseModel):
    """Response payload from the /analyze endpoint."""

    incident_id: str
    current_state: FSMStateName
    transitions: list[TransitionRecord]
    filtered_event_count: int
    total_raw_lines: int
    total_filtered_lines: int
    compression_ratio: float
    analysis_summary: str | None = None
    error: str | None = None
