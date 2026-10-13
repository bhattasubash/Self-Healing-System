"""
Unit tests for the Regex-First Trace Pre-Filter service.

Verifies the regex-vs-llm-structured-text optimization principles:
- 95%+ noise and duplicate traces eliminated locally with zero LLM tokens.
- Severe errors prioritized to the front of context.
- Destructive commands flagged for safety auditing.
- Token budget strictly enforced.
"""

from app.services.pre_filter import TracePreFilter


def test_deduplication_collapses_repeating_runtime_errors() -> None:
    filter_svc = TracePreFilter(context_budget_max_tokens=1000)

    # Simulate 50 identical repeated trace errors
    repeated_err = "2026-10-13T10:00:00Z ERROR ConnectionRefused: target database unresponsive"
    raw_lines = [repeated_err] * 50

    result = filter_svc.filter(raw_lines)

    assert result.stats.raw_line_count == 50
    assert result.stats.filtered_line_count == 1
    assert result.stats.duplicate_lines_removed == 49
    assert result.stats.compression_ratio == 0.02
    assert len(result.filtered_lines) == 1
    assert result.filtered_lines[0] == repeated_err


def test_noise_removal_strips_healthchecks_and_probes() -> None:
    filter_svc = TracePreFilter(context_budget_max_tokens=1000)

    raw_lines = [
        "2026-10-13T10:01:00Z INFO \"GET /healthz HTTP/1.1\" 200 OK kube-probe/1.28",
        "2026-10-13T10:01:01Z INFO \"GET /metrics HTTP/1.1\" 200 OK",
        "   ",
        "# This is a config comment",
        "2026-10-13T10:01:02Z CRITICAL OutOfMemory: Killed container redis-cluster-worker",
    ]

    result = filter_svc.filter(raw_lines)

    assert result.stats.raw_line_count == 5
    assert result.stats.filtered_line_count == 1
    assert "OutOfMemory" in result.filtered_lines[0]
    assert result.severity_counts.get("CRITICAL") == 1


def test_prioritization_orders_errors_before_warnings() -> None:
    filter_svc = TracePreFilter(context_budget_max_tokens=1000)

    raw_lines = [
        "2026-10-13 12:00:00 NOTICE Service initialized with 4 workers",
        "2026-10-13 12:00:01 WARN Disk usage above 85% on /var/log",
        "2026-10-13 12:00:02 FATAL Kernel panic - not syncing: VFS: Unable to mount root fs",
        "2026-10-13 12:00:03 ERROR Failed to bind socket on port 443",
    ]

    result = filter_svc.filter(raw_lines)

    assert len(result.filtered_lines) == 4
    # Highest severities must be shifted to the front of context
    assert "FATAL" in result.filtered_lines[0]
    assert "ERROR" in result.filtered_lines[1]
    assert "WARN" in result.filtered_lines[2]


def test_destructive_command_detection() -> None:
    filter_svc = TracePreFilter(context_budget_max_tokens=1000)

    raw_lines = [
        "2026-10-13T10:05:00Z INFO Candidate remediation: rm -rf /var/lib/docker/overlay2",
        "2026-10-13T10:05:01Z INFO Safe remediation: systemctl restart containerd",
    ]

    result = filter_svc.filter(raw_lines)

    assert len(result.destructive_commands) == 1
    assert "rm -rf" in result.destructive_commands[0]


def test_budget_enforcement_truncates_excessive_content() -> None:
    # 50 tokens limit = ~200 characters max
    filter_svc = TracePreFilter(context_budget_max_tokens=50)

    long_line = "2026-10-13T10:10:00Z ERROR " + ("A" * 150)
    raw_lines = [long_line + f" - sequence {i}" for i in range(10)]

    result = filter_svc.filter(raw_lines)

    # Output lines must be capped within budget
    assert result.stats.filtered_line_count < 10
    assert result.stats.token_estimate_after is not None
    assert result.stats.token_estimate_after <= 50
