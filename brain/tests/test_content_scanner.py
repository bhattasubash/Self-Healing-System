"""
Seed secret test corpus for content scanner verification.
Stored as base64-encoded vectors to prevent false positives in repository push protection.
"""

# ruff: noqa: E501

from __future__ import annotations

import base64

import pytest

from app.services.content_scanner import (
    ContentScanner,
    SecretClass,
    compute_shannon_entropy,
)


@pytest.fixture
def scanner() -> ContentScanner:
    return ContentScanner()


ENCODED_CORPUS: dict[str, list[str]] = {
    "aws_key": [
        "ZXhwb3J0IEFXU19BQ0NFU1NfS0VZX0lEPUFLSUFJT1NGT0ROTjdFWEFNUExF",
        "YXdzX2FjY2Vzc19rZXlfaWQgPSBBS0lBMTIzNDU2Nzg5MEFCQ0RFRg==",
        "RmFpbGVkIGNvbm5lY3Rpb24gdXNpbmcgQUtJQUk0NFFIOERIQkVYQU1QTEUgYW5kIHNlY3JldCB3SmFsclhVdG5GRU1JL0s3TURFTkcvYlB4UmZpQ1lFWEFNUExFS0VZ",
        "Rm91bmQgQVdTX0tFWTogQUtJQUlPU0ZPRE5ON0VYQU1QTEUgaW4gbG9nIGxpbmU=",
        "a2V5OiBBS0lBQUJDREVGR0hJSktMTU5PUA==",
        "QUtJQTAxMjM0NTY3ODlBQkNERUYgaW5pdGlhbGl6ZWQ=",
        "Q29uZmlndXJlZCBrZXkgQUtJQVBBWU1FTlRTU0VSVklDRTAx",
        "czM6Ly9idWNrZXQgd2l0aCBrZXkgQUtJQVpaWlpaWlpaWlpaWlpaWlo=",
        "Q3JlZGVudGlhbCBBS0lBQUJDRDEyMzRFRkdINTY3OCBsb2FkZWQ=",
        "QVdTIGVycm9yIGZvciBBS0lBOTg3NjU0MzIxMFpZWFdWVQ==",
    ],
    "credentials_and_keys": [
        "c2stYW50LWFwaTAzLTEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Njc4OTBhYmNkZWY=",
        "c2stcHJvai0xMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0NTY3ODkw",
        "YXBpX2tleTogc2stMTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6",
        "cGFzc3dvcmQ6ICJTdXBlclNlY3JldFBhc3N3b3JkOTkhIg==",
        "ZGJfcGFzc3dvcmQgPSAnTXlFeHRyZW1lbHlDb21wbGV4UGFzc3dvcmQxMjMkJSc=",
        "Y2xpZW50X3NlY3JldDogImExYjJjM2Q0ZTVmNmc3aDhpOWowazFsMm0zbjRvNXA2cTdyOHM5dDAi",
        "c2VjcmV0X3Rva2VuOiAnU2VjcmV0VG9rZW5TdHJpbmdfMTIzNDU2Nzg5MF9TYWZlUGFzcyc=",
        "cGFzc3BocmFzZSA9ICdjb3JyZWN0LWhvcnNlLWJhdHRlcnktc3RhcGxlLXBhc3Mn",
        "YXBpX3NlY3JldDogIjk5ODg3NzY2NTU0NDMzMjIxMTAwYWFiYmNjZGRlZWZmIg==",
        "YWRtaW5fcGFzc3dvcmQgPSAiSGFyZGNvZGVkQWRtaW5QYXNzMTIzISI=",
    ],
    "database_url": [
        "cG9zdGdyZXM6Ly9kYnVzZXI6c3VwZXJTZWNyZXRQQHNzMUBsb2NhbGhvc3Q6NTQzMi9wYXltZW50cw==",
        "cG9zdGdyZXNxbDovL2FkbWluOlBAc3N3MHJkMTIzIUBkYi5pbnRlcm5hbC52cGM6NTQzMi9wcm9kX2Ri",
        "bXlzcWw6Ly9yb290OnJvb3RfcGFzc180NTZAMTAuMC4wLjU6MzMwNi9jdXN0b21lcnM=",
        "bW9uZ29kYjovL2FwcF91c2VyOk1vbmdvUGFzczk5OSFAY2x1c3RlcjAubW9uZ29kYi5uZXQ6MjcwMTcvYW5hbHl0aWNz",
        "cmVkaXM6Ly86YXV0aFBhc3N3b3JkOTg3QHJlZGlzLW1hc3Rlci5jYWNoZS5sb2NhbDo2Mzc5LzA=",
        "YW1xcDovL2d1ZXN0OnZlcnlTZWNyZXRQYXNzQHJhYmJpdG1xLmluZnJhLmludGVybmFsOjU2NzIv",
        "cG9zdGdyZXM6Ly9zZXJ2aWNlX2FjY291bnQ6azhzX3NlY3JldF9wYXNzX3dvcmRAMTI3LjAuMC4xOjU0MzIvb3JkZXJz",
        "bXlzcWw6Ly93cml0ZXI6ZGJfc2VjcmV0X3Bhc3NAbXlzcWwtcHJpbWFyeTozMzA2L2JpbGxpbmc=",
        "bW9uZ29kYjovL2RiYWRtaW46U2VjdXJlUGFzc3cwcmQhQDEwLjEwLjEwLjEwOjI3MDE3L3Byb2Q=",
        "cG9zdGdyZXNxbDovL2RlcGxveWVyOm15cGFzc3dvcmQxMjNAYXVyb3JhLWNsdXN0ZXIudXMtZWFzdC0xLnJkcy5hbWF6b25hd3MuY29tOjU0MzIvZGI=",
    ],
    "github_token": [
        "Z2hwXzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==",
        "QXV0aG9yaXphdGlvbjogdG9rZW4gZ2hwX0FCQ0RlZmdoMTIzNDU2Nzg5MGlqa2xtbm9wUVJTVFVW",
        "Z2l0IHJlbW90ZSBhZGQgb3JpZ2luIGh0dHBzOi8vZ2hwXzk4NzY1NDMyMTB6eXh3dnV0c3JxcG9ubWxramloZ2ZlZGNiYUBnaXRodWIuY29tL3JlcG8uZ2l0",
        "R0lUSFVCX1RPS0VOPWdocF9hYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Ng==",
        "Z2l0aHViX3BhdF8xMUFBQUFBQUEwMTIzNDU2Nzg5MF9hYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ekFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaMTIzNDU2Nzg5MA==",
        "dG9rZW46IGdob18xMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
        "QmVhcmVyIGdoc18xMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=",
        "Z2hyXzEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==",
        "Z2hwXzk5OTk5OTk5OTlhYWFhYWFhYWFhYmJiYmJiYmJiYmNjY2Nj",
        "aHR0cHM6Ly9hcGkuZ2l0aHViLmNvbT90b2tlbj1naHBfc2VjcmV0VG9rZW5IZXJlMTIzNDU2Nzg5MDEyMzQ1Njc4OTA=",
    ],
    "jwt_token": [
        "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnpkV0lpT2lJeE1qTTBOVFkzT0Rrd0lpd2libUZ0WlNJNklrcHZhRzRnUkc5bElpd2lhV0YwSWpveE5URTJNak01TURJeWZRLlNmbEt4d1JKU01lS0tGMlFUNGZ3cE1lSmYzNlBPazZ5SlZfYWRRc3N3NWM=",
        "QXV0aG9yaXphdGlvbjogQmVhcmVyIGV5SmhiR2NpT2lKU1V6STFOaUlzSW10cFpDSTZJakVpZlEuZXlKcGMzTWlPaUpoZFhSb01DSXNJbk4xWWlJNkluVnpjakV5TXlKOS5BQUJCQ0NEREVFRkZHR0hISUlKSktLTExNTU5OT09QUFFRUlJTU1RUVVVWVldXWFhZWVpa",
        "dG9rZW4gPSAnZXlKaGJHY2lPaUpGVXpJMU5pSjkuZXlKMWMyVnlJam9pWVdSdGFXNGlMQ0p5YjJ4bElqb2lVMUpGWDB4bFlXUWlmUS4xMjM0NTY3ODkwYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXpBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWic=",
        "aWRfdG9rZW46IGV5SmhiR2NpT2lKSVV6STFOaUo5LmV5SmxiV0ZwYkNJNkluTnlaVUJsZUdGdGNHeGxMbU52YlNKOS5hYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejEyMzQ1Njc4OTBfLQ==",
        "SldUPWV5SmhiR2NpT2lKSVV6VXhNaUo5LmV5SmhkV1FpT2lKaGNHa3VjR0Y1YldWdWRITXVZMjl0SW4wLmFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6MTIzNDU2Nzg5MGFiY2RlZmdoaWo=",
        "QmVhcmVyIGV5SmhiR2NpT2lKU1V6STFOaUo5LmV5SjBaVzVoYm5RaU9pSmpkWE4wYjIxbGNpMHdNU0o5LnNpZ25hdHVyZV9wYXJ0X2hlcmVfd2l0aF9tYW55X2NoYXJhY3RlcnNfMTIzNDU2Nzg5",
        "YWNjZXNzX3Rva2VuOiBleUpoYkdjaU9pSklVekkxTmlKOS5leUpsZUhBaU9qRTVPVGs1T1RrNU9UbDkuYTFiMmMzZDRlNWY2ZzdoOGk5ajBrMWwybTNuNG81cDZxN3I4czl0MA==",
        "c2Vzc2lvbl9qd3QgPSAnZXlKMGVYQWlPaUpLVjFRaUxDSmhiR2NpT2lKSVV6STFOaUo5LmV5SnpkV0lpT2lKelpYTnphVzl1TFRFeU15SjkuYWJjZGVmZ2hpamtsbW5vcHFyc3R1dic=",
        "Y29va2llOiBhdXRoPWV5SmhiR2NpT2lKSVV6STFOaUo5LmV5SnBjM01pT2lKdmNHVnVhV1F0WTI5dWJtVmpkQ0o5LnNlY3JldF9zaWduYXR1cmVfand0X3Rva2VuXzEyMzQ1Njc4OTA=",
        "ZXlKaGJHY2lPaUp1YjI1bEluMC5leUp6ZFdJaU9pSmhaRzFwYmlJc0luSnZiR1VpT2lKemRYQmxjblZ6WlhJaWZRLnNpZ25hdHVyZV9jb21wb25lbnRfaGVyZV8xMjM0NTY3ODkw",
    ],
    "private_key": [
        "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBMFkzLi4uCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t",
        "LS0tLS1CRUdJTiBPUEVOU1NIIFBSSVZBVEUgS0VZLS0tLS0KYjNCbGJuTnphQzFyWlhrdGRqRUFBQUEuLi4KLS0tLS1FTkQgT1BFTlNTSCBQUklWQVRFIEtFWS0tLS0t",
        "LS0tLS1CRUdJTiBFQyBQUklWQVRFIEtFWS0tLS0tCk1IY0NBUUVFSS4uLgotLS0tLUVORCBFQyBQUklWQVRFIEtFWS0tLS0t",
        "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktnd2dnU2tBZ0VBQW9JQkFRQy4uLgotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0t",
        "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURYVENDQWtXZ0F3SUJBZ0lKQVAuLi4KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==",
        "LS0tLS1CRUdJTiBQR1AgUFJJVkFURSBLRVkgQkxPQ0stLS0tLQpWZXJzaW9uOiBHbnVQRyB2MgouLi4KLS0tLS1FTkQgUEdQIFBSSVZBVEUgS0VZIEJMT0NLLS0tLS0=",
        "LS0tLS1CRUdJTiBEU0EgUFJJVkFURSBLRVktLS0tLQpNSUlCdkFJQkFBS0JnUUQuLi4KLS0tLS1FTkQgRFNBIFBSSVZBVEUgS0VZLS0tLS0=",
        "LS0tLS1CRUdJTiBFTkNSWVBURUQgUFJJVkFURSBLRVktLS0tLQpNSUlGRGpCQUJna3Foa2lHOXcwQkJRMHdNekFiQmdrcWhraUc5dzBCQlF3d0RnUUkuLi4KLS0tLS1FTkQgRU5DUllQVEVEIFBSSVZBVEUgS0VZLS0tLS0=",
        "LS0tLS1CRUdJTiBYNTA5IENSTC0tLS0tCk1JSUNXRENDQVVBd0RRWUpLb1pJaHZjTkFRRUVCUUF3Li4uCi0tLS0tRU5EIFg1MDkgQ1JMLS0tLS0=",
        "LS0tLS1CRUdJTiBTU0gyIEVOQ1JZUFRFRCBQUklWQVRFIEtFWS0tLS0tCkNvbW1lbnQ6ICJpbXBvcnRlZCBrZXkiCi4uLgotLS0tLUVORCBTU0gyIEVOQ1JZUFRFRCBQUklWQVRFIEtFWS0tLS0t",
    ],
    "slack_token": [
        "eG94Yi0xMjM0NTY3ODkwLTEyMzQ1Njc4OTAxMjMtYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4",
        "U0xBQ0tfQk9UX1RPS0VOPXhveGItOTg3NjU0MzIxMC05ODc2NTQzMjEwMTIzLXp5eHd2dXRzcnFwb25tbGtqaWhnZmVkYw==",
        "eG94cC0xMjM0NTY3ODkwLTEyMzQ1Njc4OTAxMjMtMTIzNDU2Nzg5MDEyMy1hYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3g=",
        "dG9rZW46IHhveGEtMi0xMjM0NTY3ODkwMTIzLTEyMzQ1Njc4OTAxMjMtYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4",
        "c2xhY2tfd2ViaG9va190b2tlbiB4b3hyLTEyMzQ1Njc4OTAtYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4",
        "eG94Yi0wMDAwMDAwMDAwLTExMTExMTExMTExMTEtMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIy",
        "Ym90X3Rva2VuOiB4b3hiLTU1NTU1NTU1NTUtNjY2NjY2NjY2NjY2Ni03Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc=",
        "QXV0aG9yaXphdGlvbjogQmVhcmVyIHhveHAtOTk5OTk5OTk5OS04ODg4ODg4ODg4ODg4LTc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nw==",
        "eG94Yi0xMTIyMzM0NDU1LTY2Nzc4ODk5MDAxMTItYWFiYmNjZGRlZWZmZ2doaGlpampra2xs",
        "c2xhY2tUb2tlbiA9ICd4b3hiLTEyMzEyMzEyMzQtNDU2NDU2NDU2NDU2Ny1hYmNkZWYxMjM0NTZhYmNkZWYxMjM0NTYn",
    ],
}

SEEDED_CORPUS: dict[SecretClass, list[str]] = {
    SecretClass(k): [base64.b64decode(b).decode("utf-8") for b in v]
    for k, v in ENCODED_CORPUS.items()
}

BENIGN_SAMPLES: list[str] = [
    "container_cpu_usage_seconds_total{app=\"payment-gateway\"} 0.85",
    "kubectl rollout status deployment/payment-gateway -n payments",
    "Normal application log: connection accepted from 192.168.1.10",
    "HTTP GET /api/v1/health returned status 200 OK duration_ms=12",
    "Pod payment-gateway-7d8b9c6d5-xyz12 entered state Running",
    "Event: Scaled up replica set payment-gateway-7d8b9c6d5 to 3",
    "Node worker-01 status Ready, disk pressure False",
    "ConfigMap payment-config version 14 reloaded successfully",
    "Cluster autoscaler checked 12 nodes, no scale down needed",
    "Trace ID: 4bf92f3577b34da6a3ce929d0e0e4736 span ID: 00f067aa0ba902b7",
]


# ─── 2. Recall Measurement Tests (Target >= 95%) ───────────────────────


@pytest.mark.parametrize("secret_class", list(SEEDED_CORPUS.keys()))
def test_seeded_secret_recall_per_class(
    scanner: ContentScanner, secret_class: SecretClass
) -> None:
    samples = SEEDED_CORPUS[secret_class]
    detected_count = 0

    for sample in samples:
        result = scanner.scan_text(sample)
        if not result.is_clean and any(f.secret_class == secret_class.value for f in result.findings):
            detected_count += 1

    recall = detected_count / len(samples)
    # AC: At least 95% on structured secrets (PRD D-14, Section 8)
    assert recall >= 0.95, (
        f"Recall failure for secret class '{secret_class.value}': "
        f"detected {detected_count}/{len(samples)} ({recall:.1%}), required >= 95%"
    )


def test_benign_samples_zero_false_positives(scanner: ContentScanner) -> None:
    for benign in BENIGN_SAMPLES:
        result = scanner.scan_text(benign)
        assert result.is_clean, (
            f"False positive on benign line: {benign!r}. "
            f"Findings: {[f.secret_class for f in result.findings]}"
        )


def test_shannon_entropy_calculation() -> None:
    # Low entropy (repeated characters)
    low_entropy = compute_shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
    assert low_entropy == 0.0

    # High entropy (random base64 string)
    high_entropy = compute_shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    assert high_entropy > 4.0


def test_scan_payload_recursively_detects_nested_secrets(scanner: ContentScanner) -> None:
    nested_payload = {
        "incident_id": "inc-test-01",
        "labels": {
            "app": "auth-service",
            "debug_env": "AWS_KEY=" + "AKIAIOSFODNN7EXAMPLE",
        },
        "logs": [
            "Normal log 1",
            "Failed DB connect: " + "postgres://user:secret123@db:5432/app",
        ],
    }

    result = scanner.scan_payload(nested_payload)
    assert not result.is_clean
    detected_classes = {f.secret_class for f in result.findings}
    assert SecretClass.AWS_KEY.value in detected_classes
    assert SecretClass.DATABASE_URL.value in detected_classes
