"""
Unit tests for E2B Ephemeral Micro-Sandbox Runner.

Verifies:
- Static Security Barrier blocks destructive command patterns.
- Safe commands pass validation and produce valid SandboxExecutionResult.
- Checksums and timestamps are computed accurately.
"""

import pytest

from app.sandbox.e2b_runner import (
    E2BMicroSandboxRunner,
    SecurityViolationError,
    scan_script_safety,
)


@pytest.mark.parametrize(
    "dangerous_cmd,expected_rule",
    [
        ("rm -rf /", "RECURSIVE_FILE_DESTRUCTION"),
        ("rm -r -f /var/lib", "RECURSIVE_FILE_DESTRUCTION"),
        (":(){ :|:& };:", "FORK_BOMB"),
        ("mkfs.ext4 /dev/sda1", "FILESYSTEM_FORMATTING"),
        ("dd if=/dev/zero of=/dev/sda", "RAW_DEVICE_OVERWRITE"),
        ("kubectl delete namespace default", "KUBERNETES_NAMESPACE_PURGE"),
        ("kubectl delete ns kube-system", "KUBERNETES_NAMESPACE_PURGE"),
        ("kubectl delete all --all", "KUBERNETES_ALL_RESOURCES_PURGE"),
        ("DROP DATABASE production;", "DATABASE_DROP_OR_TRUNCATE"),
        ("TRUNCATE TABLE users;", "DATABASE_DROP_OR_TRUNCATE"),
        ("docker system prune -f", "FORCE_CONTAINER_PRUNE"),
        ("iptables -F", "FIREWALL_FLUSH"),
        ("echo malicious > /dev/sda", "RAW_DISK_REDIRECTION"),
    ],
)
def test_static_security_barrier_blocks_dangerous_commands(
    dangerous_cmd: str,
    expected_rule: str,
) -> None:
    flagged = scan_script_safety(dangerous_cmd)
    assert len(flagged) >= 1
    assert expected_rule in flagged


@pytest.mark.asyncio
async def test_runner_raises_security_violation_error() -> None:
    runner = E2BMicroSandboxRunner()
    with pytest.raises(SecurityViolationError) as exc_info:
        await runner.execute_simulation("rm -rf / --no-preserve-root")

    assert "SECURITY BARRIER VIOLATION" in str(exc_info.value)
    assert "RECURSIVE_FILE_DESTRUCTION" in exc_info.value.flagged_rules


@pytest.mark.asyncio
async def test_safe_script_executes_simulation_successfully() -> None:
    runner = E2BMicroSandboxRunner()
    safe_script = """
    kubectl rollout status deployment/payment-gateway --timeout=60s
    kubectl get pods -l app=payment-gateway
    """

    result = await runner.execute_simulation(safe_script, language="bash")

    assert result.status == "pass"
    assert result.exit_code == 0
    assert result.checksum.startswith("sha256:")
    assert result.duration_ms >= 0
    assert result.finished_at >= result.started_at
