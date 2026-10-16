"""
Tests for input validation helpers, specifically validate_incident_id.
"""

import pytest

from app.utils.validation import validate_incident_id, validate_slack_response_url


def test_validate_incident_id_valid_slugs() -> None:
    assert validate_incident_id("inc-1234") == "inc-1234"
    uuid_val = "550e8400-e29b-41d4-a716-446655440000"
    assert validate_incident_id(uuid_val) == uuid_val
    assert validate_incident_id("INC-ABCD_1234") == "INC-ABCD_1234"


def test_validate_incident_id_rejects_path_traversal() -> None:
    with pytest.raises(ValueError, match="Invalid incident_id"):
        validate_incident_id("../escape")

    with pytest.raises(ValueError, match="Invalid incident_id"):
        validate_incident_id("..\\escape")

    with pytest.raises(ValueError, match="Invalid incident_id"):
        validate_incident_id("/etc/passwd")

    with pytest.raises(ValueError, match="Invalid incident_id"):
        validate_incident_id("../../incident-001")


def test_validate_incident_id_rejects_empty_or_whitespace() -> None:
    with pytest.raises(ValueError, match="Invalid incident_id"):
        validate_incident_id("")

    with pytest.raises(ValueError, match="Invalid incident_id"):
        validate_incident_id("   ")


def test_validate_incident_id_rejects_special_characters() -> None:
    for invalid in ["inc;rm -rf", "inc$id", "inc`cat`", "inc/test", "inc\\test", "inc*"]:
        with pytest.raises(ValueError, match="Invalid incident_id"):
            validate_incident_id(invalid)


def test_validate_incident_id_rejects_overlong() -> None:
    overlong = "a" * 65
    with pytest.raises(ValueError, match="Invalid incident_id"):
        validate_incident_id(overlong)


def test_validate_slack_response_url_valid() -> None:
    valid_url = "https://hooks.slack.com/actions/T123/B456/abcdef"
    assert validate_slack_response_url(valid_url) == valid_url
    assert validate_slack_response_url(None) is None


def test_validate_slack_response_url_rejects_insecure_or_untrusted_hosts() -> None:
    # Scheme must be https
    with pytest.raises(ValueError, match="must use https"):
        validate_slack_response_url("http://hooks.slack.com/actions/T123/B456/abcdef")

    # Untrusted domain
    with pytest.raises(ValueError, match="must be hooks.slack.com"):
        validate_slack_response_url("https://malicious.example.com/webhook")

    # Subdomain spoofing
    with pytest.raises(ValueError, match="must be hooks.slack.com"):
        validate_slack_response_url("https://hooks.slack.com.attacker.com/webhook")

    # Non-standard port or credentials
    with pytest.raises(ValueError, match="must be hooks.slack.com"):
        validate_slack_response_url("https://hooks.slack.com:8443/actions/T123")
    with pytest.raises(ValueError, match="must be hooks.slack.com"):
        validate_slack_response_url("https://user:pass@hooks.slack.com/actions/T123")

