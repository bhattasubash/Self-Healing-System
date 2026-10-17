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


ALLOWED_SLACK_HOST = "hooks.slack.com"


def validate_slack_response_url(url: str | None) -> str | None:
    """
    Validates a Slack response_url ensuring:
    - If None or empty, returns None.
    - URL must strictly start with 'https://hooks.slack.com/'.
    - Scheme must be strictly 'https'.
    - Hostname must be strictly 'hooks.slack.com' (no port, no userinfo, no alternate domains).
    - Prevents SSRF attacks.
    """
    if not url:
        return None

    cleaned = url.strip()

    # CodeQL SSRF recognition check: must start with the trusted base URL prefix
    if not cleaned.startswith("https://hooks.slack.com/"):
        raise ValueError(
            f"Invalid response_url: must start with 'https://{ALLOWED_SLACK_HOST}/'"
        )

    try:
        import urllib.parse

        parsed = urllib.parse.urlsplit(cleaned)
    except Exception as exc:
        raise ValueError(f"Malformed response_url: {exc}") from exc

    if parsed.scheme.lower() != "https":
        raise ValueError(f"Invalid response_url scheme '{parsed.scheme}': must use https")

    if (
        parsed.netloc.lower() != ALLOWED_SLACK_HOST
        or (parsed.hostname or "").lower() != ALLOWED_SLACK_HOST
    ):
        raise ValueError(
            f"Invalid response_url host '{parsed.netloc}': host must be {ALLOWED_SLACK_HOST}"
        )

    if parsed.port is not None:
        raise ValueError("Invalid response_url: custom ports are not allowed")

    if parsed.username or parsed.password:
        raise ValueError("Invalid response_url: user credentials in URL are not allowed")

    return cleaned

