"""
Server-side content scanner and secret detector (PRD D-14, F-05, T-16).

Implements deterministic fail-closed scanning for incoming telemetry and evidence.
Detects unmasked secrets across 7 core classes:
1. AWS Keys
2. GitHub Tokens
3. Slack Tokens
4. Database URLs with credentials
5. Private Keys & Certificates
6. JSON Web Tokens (JWT)
7. API Keys and Explicit Password Assignments
"""

from __future__ import annotations

import collections
import math
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class SecretClass(StrEnum):
    AWS_KEY = "aws_key"
    GITHUB_TOKEN = "github_token"  # noqa: S105
    SLACK_TOKEN = "slack_token"  # noqa: S105
    DATABASE_URL = "database_url"
    PRIVATE_KEY = "private_key"
    JWT_TOKEN = "jwt_token"  # noqa: S105
    CREDENTIALS_AND_KEYS = "credentials_and_keys"


def compute_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string."""
    if not data:
        return 0.0
    freq = collections.Counter(data)
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


@dataclass
class Finding:
    secret_class: str
    matched_preview: str
    entropy: float
    location: str = ""


@dataclass
class ScanResult:
    is_clean: bool
    findings: list[Finding] = field(default_factory=list)


# Compiled pattern definitions for performance
PATTERNS: dict[SecretClass, list[re.Pattern[str]]] = {
    SecretClass.AWS_KEY: [
        re.compile(r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16,28})\b"),
    ],
    SecretClass.GITHUB_TOKEN: [
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{30,255})\b"),
        re.compile(r"\b(github_pat_[A-Za-z0-9_]{30,255})\b"),
    ],
    SecretClass.SLACK_TOKEN: [
        re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,120})\b"),
    ],
    SecretClass.DATABASE_URL: [
        re.compile(
            r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^/\s:@]*:[^/\s@]+@[^\s]+"
        ),
    ],
    SecretClass.PRIVATE_KEY: [
        re.compile(r"-----BEGIN [A-Z0-9_ ]*(?:KEY|CERTIFICATE|CRL)[A-Z0-9_ ]*-----"),
    ],
    SecretClass.JWT_TOKEN: [
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ],
    SecretClass.CREDENTIALS_AND_KEYS: [
        re.compile(r"\bsk-(?:ant-api03-|proj-)?[A-Za-z0-9_-]{20,}\b"),
        re.compile(
            r"""(?i)\b(?:api_key|password|passwd|db_password|admin_password|client_secret|secret_token|passphrase|api_secret)\s*[:=]\s*["']([^"'\r\n]{6,})["']"""
        ),
    ],
}


class ContentScanner:
    """Deterministic server-side secret scanner."""

    def __init__(self) -> None:
        self._patterns = PATTERNS

    def scan_text(self, text: str, location: str = "") -> ScanResult:
        """Scan a text string for known secret signatures."""
        if not text:
            return ScanResult(is_clean=True, findings=[])

        findings: list[Finding] = []
        for secret_class, patterns in self._patterns.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    matched_str = match.group(0)
                    # Create safe preview (e.g. first 4 and last 2 chars)
                    if len(matched_str) > 8:
                        preview = f"{matched_str[:4]}...{matched_str[-2:]}"
                    else:
                        preview = f"{matched_str[:2]}..."
                    entropy = compute_shannon_entropy(matched_str)
                    findings.append(
                        Finding(
                            secret_class=secret_class.value,
                            matched_preview=preview,
                            entropy=entropy,
                            location=location,
                        )
                    )

        return ScanResult(is_clean=len(findings) == 0, findings=findings)

    def scan_payload(self, payload: Any, path: str = "") -> ScanResult:
        """Recursively scan an arbitrary nested dictionary or list."""
        all_findings: list[Finding] = []

        if isinstance(payload, str):
            res = self.scan_text(payload, location=path)
            all_findings.extend(res.findings)
        elif isinstance(payload, dict):
            for key, val in payload.items():
                current_path = f"{path}.{key}" if path else str(key)
                # Scan key as well if string
                if isinstance(key, str):
                    key_res = self.scan_text(key, location=f"{current_path}[key]")
                    all_findings.extend(key_res.findings)
                val_res = self.scan_payload(val, path=current_path)
                all_findings.extend(val_res.findings)
        elif isinstance(payload, (list, tuple, set)):
            for idx, item in enumerate(payload):
                current_path = f"{path}[{idx}]"
                item_res = self.scan_payload(item, path=current_path)
                all_findings.extend(item_res.findings)

        return ScanResult(is_clean=len(all_findings) == 0, findings=all_findings)
