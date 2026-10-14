"""
Tests for input validation helpers, specifically validate_incident_id.
"""

import pytest

from app.utils.validation import validate_incident_id


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
