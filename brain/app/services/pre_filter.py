"""
Regex-first trace pre-filter (regex-vs-llm-structured-text pattern).

Architecture:
  Raw Trace Lines
       │
       ▼
  [Deduplication] ─── Collapse identical consecutive lines
       │
       ▼
  [Pattern Router] ── Route by severity / structure
       │
       ▼
  [Regex Extractor] ── Extract structured fields (95%+ handled here)
       │
       ▼
  [Token Estimator] ── Compute approximate LLM token count
       │
       ▼
  [Budget Enforcer] ── Truncate if exceeding context budget
       │
       ▼
  Filtered Output + FilterStats

The LLM never sees raw, unfiltered trace data. Only anomalous or
ambiguous spans that survive the regex pipeline reach the reasoning layer.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Final

import structlog

from app.schemas.telemetry import FilterMethod, FilterStats

logger = structlog.get_logger()

# ─── Compiled Regex Patterns ──────────────────────────────────────────

# Timestamp extraction (ISO 8601, syslog, epoch)
TIMESTAMP_RE: Final = re.compile(
    r"(?P<ts>"
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
    r"|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"
    r"|\d{10,13}"
    r")"
)

# Log level extraction
LEVEL_RE: Final = re.compile(
    r"\b(?P<level>DEBUG|TRACE|INFO|NOTICE|WARN(?:ING)?|ERROR|FATAL|CRITICAL|EMERG(?:ENCY)?|ALERT|PANIC)\b",
    re.IGNORECASE,
)

# Stack trace frame detection (Java, Python, Go, Node.js)
STACK_FRAME_RE: Final = re.compile(
    r"(?:"
    r"^\s+at\s+"                             # Java / Node.js
    r"|^\s+File\s+\""                        # Python
    r"|^\s+\S+\.go:\d+"                      # Go
    r"|^Traceback\s+\(most\s+recent"         # Python traceback header
    r"|^Caused\s+by:"                        # Java chained exception
    r"|^goroutine\s+\d+"                     # Go goroutine dump
    r")",
    re.MULTILINE,
)

# Prometheus metric line: metric_name{labels} value [timestamp]
METRIC_LINE_RE: Final = re.compile(
    r"^(?P<metric>[a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:\{(?P<labels>[^}]*)\})?\s+"
    r"(?P<value>[-+]?[0-9]*\.?[0-9]+(?:[eE][-+]?[0-9]+)?)"
    r"(?:\s+(?P<ts>\d+))?$"
)

# Kubernetes event log line
K8S_EVENT_RE: Final = re.compile(
    r"^(?P<ts>\S+)\s+"
    r"(?P<ns>\S+)\s+"
    r"(?P<kind>\S+)\s+"
    r"(?P<name>\S+)\s+"
    r"(?P<reason>\S+)\s+"
    r"(?P<message>.*)$"
)

# Noise patterns that should always be filtered out
NOISE_PATTERNS: Final[list[re.Pattern[str]]] = [
    re.compile(r"^\s*$"),                                       # blank lines
    re.compile(r"^#"),                                          # comment lines
    re.compile(r"^---\s*$"),                                    # YAML separators
    re.compile(r"^\s*\.\.\.\s*$"),                              # YAML end markers
    re.compile(r"^\d{4}-\d{2}-\d{2}.*\bDEBUG\b", re.I),        # debug-level lines
    re.compile(r"^\d{4}-\d{2}-\d{2}.*\bTRACE\b", re.I),        # trace-level lines
    re.compile(r"^\s*healthcheck\s", re.I),                     # healthcheck noise
    re.compile(r"\bkube-probe/", re.I),                         # k8s liveness probes
    re.compile(r"\"GET /health\w*\s+HTTP/", re.I),              # health endpoint logs
    re.compile(r"\"GET /ready\w*\s+HTTP/", re.I),               # readiness endpoint logs
    re.compile(r"\"GET /metrics\s+HTTP/", re.I),                # metrics scrape logs
]

# Destructive command patterns (for safety alerting, not filtering)
DESTRUCTIVE_CMD_RE: Final = re.compile(
    r"(?:"
    r"\brm\s+-[rf]"
    r"|\bkubectl\s+delete\b"
    r"|\bDROP\s+(?:TABLE|DATABASE)\b"
    r"|\bTRUNCATE\s+TABLE\b"
    r"|\bdocker\s+(?:rm|rmi|system\s+prune)\b"
    r"|\bsystemctl\s+(?:stop|disable|mask)\b"
    r"|\bkill\s+-(?:9|SIGKILL)\b"
    r")",
    re.IGNORECASE,
)


# ─── Data Structures ─────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ParsedLine:
    """A single trace line after regex extraction."""

    raw: str
    timestamp: str | None
    level: str | None
    is_stack_frame: bool
    is_noise: bool
    is_metric: bool
    is_k8s_event: bool
    has_destructive_cmd: bool
    extracted_fields: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class PreFilterResult:
    """Complete result of the pre-filter pipeline."""

    filtered_lines: list[str]
    parsed_lines: list[ParsedLine]
    stats: FilterStats
    severity_counts: dict[str, int]
    destructive_commands: list[str]
    deduplicated_groups: dict[str, int]


# ─── Pre-Filter Service ──────────────────────────────────────────────


class TracePreFilter:
    """
    Regex-first trace scrubber following the regex-vs-llm-structured-text skill.

    The filter processes raw trace/log lines through a pipeline:
    1. Deduplication — collapse identical consecutive lines
    2. Noise removal — strip blank lines, comments, debug-level, health checks
    3. Pattern extraction — parse timestamps, levels, structured fields
    4. Token estimation — approximate LLM token count
    5. Budget enforcement — truncate to stay within context limits

    The LLM only receives lines that survive all five stages.
    """

    APPROX_CHARS_PER_TOKEN: Final = 4

    def __init__(
        self,
        context_budget_max_tokens: int = 32000,
        compression_target: float = 0.05,
    ) -> None:
        self._budget = context_budget_max_tokens
        self._target = compression_target
        self._log = logger.bind(component="pre_filter")

    def filter(self, raw_lines: list[str]) -> PreFilterResult:
        """
        Execute the full pre-filter pipeline on raw trace lines.

        Returns a ``PreFilterResult`` with filtered lines, statistics,
        and any destructive command warnings.
        """
        raw_count = len(raw_lines)

        if raw_count == 0:
            return self._empty_result()

        # Stage 1: Deduplication
        deduped_lines, dedup_groups = self._deduplicate(raw_lines)
        duplicates_removed = raw_count - len(deduped_lines)

        # Stage 2: Parse and classify each line
        parsed = [self._parse_line(line) for line in deduped_lines]

        # Stage 3: Remove noise lines
        significant = [p for p in parsed if not p.is_noise]

        # Stage 4: Prioritize — errors and warnings first, then info
        significant = self._prioritize(significant)

        # Stage 5: Enforce token budget
        significant, _ = self._enforce_budget(significant)

        # Collect results
        filtered_lines = [p.raw for p in significant]
        severity_counts = self._count_severities(significant)
        destructive = [
            p.raw for p in significant if p.has_destructive_cmd
        ]

        filtered_count = len(filtered_lines)
        compression_ratio = filtered_count / raw_count if raw_count > 0 else 0.0

        token_estimate_before = self._estimate_tokens(raw_lines)
        token_estimate_after = self._estimate_tokens(filtered_lines)

        stats = FilterStats(
            raw_line_count=raw_count,
            filtered_line_count=filtered_count,
            filter_method=FilterMethod.REGEX,
            compression_ratio=round(compression_ratio, 4),
            duplicate_lines_removed=duplicates_removed,
            token_estimate_before=token_estimate_before,
            token_estimate_after=token_estimate_after,
        )

        self._log.info(
            "pre_filter_complete",
            raw=raw_count,
            filtered=filtered_count,
            ratio=compression_ratio,
            duplicates_removed=duplicates_removed,
            destructive_commands=len(destructive),
        )

        return PreFilterResult(
            filtered_lines=filtered_lines,
            parsed_lines=significant,
            stats=stats,
            severity_counts=severity_counts,
            destructive_commands=destructive,
            deduplicated_groups=dedup_groups,
        )

    def filter_text(self, raw_text: str) -> PreFilterResult:
        """Convenience wrapper that accepts a single multi-line string."""
        lines = raw_text.splitlines()
        return self.filter(lines)

    # ─── Pipeline Stages ──────────────────────────────────────────────

    def _deduplicate(
        self, lines: list[str]
    ) -> tuple[list[str], dict[str, int]]:
        """
        Collapse consecutive identical lines into a single representative.

        Returns the deduplicated line list and a mapping of line content
        to occurrence count (only for lines that appeared more than once).
        """
        if not lines:
            return [], {}

        deduped: list[str] = []
        counts: Counter[str] = Counter()
        prev: str | None = None

        for line in lines:
            stripped = line.strip()
            counts[stripped] += 1
            if stripped != prev:
                deduped.append(line)
                prev = stripped

        groups = {k: v for k, v in counts.items() if v > 1}
        return deduped, groups

    def _parse_line(self, line: str) -> ParsedLine:
        """Parse a single line through all detection patterns."""
        ts_match = TIMESTAMP_RE.search(line)
        level_match = LEVEL_RE.search(line)
        is_stack = bool(STACK_FRAME_RE.search(line))
        is_noise = any(p.search(line) for p in NOISE_PATTERNS)
        is_metric = bool(METRIC_LINE_RE.match(line))
        is_k8s = bool(K8S_EVENT_RE.match(line))
        has_destructive = bool(DESTRUCTIVE_CMD_RE.search(line))

        extracted: dict[str, str] = {}

        if is_metric:
            m = METRIC_LINE_RE.match(line)
            if m:
                extracted["metric"] = m.group("metric")
                extracted["value"] = m.group("value")
                labels = m.group("labels")
                if labels:
                    extracted["labels"] = labels

        if is_k8s:
            m = K8S_EVENT_RE.match(line)
            if m:
                extracted["namespace"] = m.group("ns")
                extracted["kind"] = m.group("kind")
                extracted["reason"] = m.group("reason")

        return ParsedLine(
            raw=line,
            timestamp=ts_match.group("ts") if ts_match else None,
            level=level_match.group("level").upper() if level_match else None,
            is_stack_frame=is_stack,
            is_noise=is_noise,
            is_metric=is_metric,
            is_k8s_event=is_k8s,
            has_destructive_cmd=has_destructive,
            extracted_fields=extracted,
        )

    def _prioritize(self, lines: list[ParsedLine]) -> list[ParsedLine]:
        """
        Sort lines by severity priority: FATAL/CRITICAL/ERROR first,
        then WARNING, then everything else. Within each tier, preserve
        original order (stable sort).
        """
        priority_map: dict[str | None, int] = {
            "FATAL": 0,
            "CRITICAL": 0,
            "EMERGENCY": 0,
            "EMERG": 0,
            "ALERT": 0,
            "PANIC": 0,
            "ERROR": 1,
            "WARNING": 2,
            "WARN": 2,
            "NOTICE": 3,
            "INFO": 4,
            None: 5,
        }
        return sorted(
            lines,
            key=lambda p: priority_map.get(p.level, 5),
        )

    def _enforce_budget(
        self, lines: list[ParsedLine]
    ) -> tuple[list[ParsedLine], bool]:
        """
        Truncate the line list if the estimated token count exceeds
        the configured context budget.
        """
        budget_chars = self._budget * self.APPROX_CHARS_PER_TOKEN
        accumulated = 0
        cutoff = len(lines)

        for i, parsed_line in enumerate(lines):
            accumulated += len(parsed_line.raw) + 1  # +1 for newline
            if accumulated > budget_chars:
                cutoff = i
                break

        was_truncated = cutoff < len(lines)
        if was_truncated:
            self._log.warning(
                "budget_truncation",
                total_lines=len(lines),
                kept_lines=cutoff,
                budget_tokens=self._budget,
            )

        return lines[:cutoff], was_truncated

    # ─── Helpers ──────────────────────────────────────────────────────

    def _estimate_tokens(self, lines: list[str]) -> int:
        """Approximate token count using a chars-per-token heuristic."""
        total_chars = sum(len(line) for line in lines)
        return total_chars // self.APPROX_CHARS_PER_TOKEN

    def _count_severities(self, lines: list[ParsedLine]) -> dict[str, int]:
        """Count occurrences of each log severity level."""
        counts: dict[str, int] = {}
        for line in lines:
            key = line.level or "UNKNOWN"
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _empty_result(self) -> PreFilterResult:
        """Return an empty result for zero-length input."""
        return PreFilterResult(
            filtered_lines=[],
            parsed_lines=[],
            stats=FilterStats(
                raw_line_count=0,
                filtered_line_count=0,
                filter_method=FilterMethod.REGEX,
                compression_ratio=0.0,
                duplicate_lines_removed=0,
                token_estimate_before=0,
                token_estimate_after=0,
            ),
            severity_counts={},
            destructive_commands=[],
            deduplicated_groups={},
        )
