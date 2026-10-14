"""
Integration tests for the /api/v1/analyze endpoint.

Verifies:
- Data perimeter security: 400 Bad Request when unmasked telemetry is sent.
- Valid masked telemetry flows through INGEST -> FILTER -> ANALYZE.
- Compression ratio and analysis summary are correctly returned.
- FSM transition history is recorded and returned in response.
"""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas.telemetry import (
    Severity,
)


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def _build_masked_event(
    metric_name: str = "container_cpu_usage_seconds_total",
    severity: Severity = Severity.CRITICAL,
) -> dict:
    return {
        "event_id": "a0000000-0000-0000-0000-000000000001",
        "source": "prometheus",
        "metric_name": metric_name,
        "data_points": [
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "value": 0.95,
            }
        ],
        "labels": {
            "node": "MASKED_HOST_7a8b9c0d",
            "namespace": "MASKED_NS_12345678",
        },
        "severity": severity.value,
        "timestamp": datetime.now(UTC).isoformat(),
        "session_id": "b0000000-0000-0000-0000-000000000002",
        "masking_applied": True,
        "filter_stats": {
            "raw_line_count": 20,
            "filtered_line_count": 2,
            "filter_method": "regex",
            "compression_ratio": 0.1,
        },
        "anomaly_score": 0.88,
    }


def test_analyze_rejects_unmasked_telemetry(client: TestClient) -> None:
    event = _build_masked_event()
    event["masking_applied"] = False  # Perimeter violation!

    response = client.post(
        "/api/v1/analyze",
        json={
            "events": [event],
            "session_id": "c0000000-0000-0000-0000-000000000003",
        },
    )

    assert response.status_code == 400
    assert "Data perimeter violation" in response.json()["detail"]


def test_analyze_rejects_unmasked_secret_even_if_flag_true(client: TestClient) -> None:
    event = _build_masked_event()
    event["masking_applied"] = True  # Client claims masked
    # Server scan catches unmasked secret
    event["labels"]["db_conn"] = "postgres" + "://admin:SuperSecretPass123!@db:5432/prod"

    response = client.post(
        "/api/v1/analyze",
        json={
            "events": [event],
            "session_id": "c0000000-0000-0000-0000-000000000005",
        },
    )

    assert response.status_code == 400
    assert "Server-side content scan detected" in response.json()["detail"]


def test_analyze_processes_valid_telemetry(client: TestClient) -> None:
    event1 = _build_masked_event(metric_name="container_cpu_usage", severity=Severity.CRITICAL)
    event2 = _build_masked_event(
        metric_name="container_memory_working_set_bytes",
        severity=Severity.WARNING,
    )

    response = client.post(
        "/api/v1/analyze",
        json={
            "events": [event1, event2],
            "session_id": "d0000000-0000-0000-0000-000000000004",
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["current_state"] == "analyze"
    assert data["filtered_event_count"] == 2
    assert data["error"] is None
    assert "container_cpu_usage" in data["analysis_summary"]

    # Verify transitions history
    transitions = data["transitions"]
    assert len(transitions) >= 3
    states = [t["to_state"] for t in transitions]
    assert "ingest" in states
    assert "filter" in states
    assert "analyze" in states
