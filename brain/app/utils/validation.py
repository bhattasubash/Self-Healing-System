"""
Validation utilities for security boundaries and identifiers.
"""

from __future__ import annotations

import re

INCIDENT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def validate_incident_id(incident_id: str) -> str:
    """
    Validates an incident ID to prevent path traversal, command injection, and malformed paths.

    Requirements:
    - Must be a non-empty string between 1 and 64 characters.
    - Must match regex '^[a-zA-Z0-9_-]{1,64}$'.
    - Disallows path separators ('/', '\\'), whitespace, dots ('.'), and special shell characters.
    """
    if not isinstance(incident_id, str):
        raise ValueError(f"incident_id must be a string, got {type(incident_id).__name__}")

    cleaned = incident_id.strip()
    if not INCIDENT_ID_PATTERN.match(cleaned):
        raise ValueError(
            f"Invalid incident_id {incident_id!r}. Must match '^[a-zA-Z0-9_-]{{1,64}}$'."
        )

    return cleaned
