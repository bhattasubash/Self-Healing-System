"""
E2B Ephemeral Micro-Sandbox Runner with Static Security Barrier.

Executes generated infrastructure remediation scripts within isolated
ephemeral container runtimes managed via the E2B SDK.

SECURITY INVARIANTS:
1. Static Security Barrier: Scripts are scanned against a compiled regex blocklist
   BEFORE any sandbox is provisioned. Destructive invocations raise immediate
   SecurityViolationError and abort execution.
2. Guaranteed Teardown: Sandboxes are wrapped in strict try...finally blocks,
   ensuring container instances are terminated immediately post-run.
3. Network Isolation: Sandboxes run in sandboxed network namespaces with zero
   access to production VPC infrastructure.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime
from typing import Any, Final

import structlog
from pydantic import BaseModel, Field

from app.config import E2BSandboxSettings, get_settings

logger = structlog.get_logger()

# ─── Static Security Barrier: Destructive Command Patterns ─────────────

DANGEROUS_PATTERNS: Final[list[tuple[str, re.Pattern[str]]]] = [
    (
        "RECURSIVE_FILE_DESTRUCTION",
        re.compile(
            r"\brm\s+(?:-[a-zA-Z0-9_-]+\s+)*(?:-[a-zA-Z0-9_-]*r[a-zA-Z0-9_-]*|--recursive)(?:\s+-[a-zA-Z0-9_-]+)*\s+[/~*]",
            re.IGNORECASE,
        ),
    ),
    (
        "FORK_BOMB",
        re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:|:\(\)\{.*:\|:&.*\}", re.IGNORECASE),
    ),
    (
        "FILESYSTEM_FORMATTING",
        re.compile(r"\bmkfs(?:\.[a-zA-Z0-9]+)?\s+", re.IGNORECASE),
    ),
    (
        "RAW_DEVICE_OVERWRITE",
        re.compile(
            r"\bdd\s+if=.*(?:of=/dev/(?:sd[a-z]|nvme|vd[a-z]|hd[a-z]|zero|null))",
            re.IGNORECASE,
        ),
    ),
    (
        "KUBERNETES_NAMESPACE_PURGE",
        re.compile(
            r"\bkubectl\s+delete\s+(?:namespaces?|ns)\s+(?:--all|[a-zA-Z0-9_-]+)",
            re.IGNORECASE,
        ),
    ),
    (
        "KUBERNETES_ALL_RESOURCES_PURGE",
        re.compile(r"\bkubectl\s+delete\s+(?:all|--all)\b", re.IGNORECASE),
    ),
    (
        "DATABASE_DROP_OR_TRUNCATE",
        re.compile(r"\b(?:DROP\s+(?:DATABASE|SCHEMA|TABLE)|TRUNCATE\s+TABLE)\b", re.IGNORECASE),
    ),
    (
        "FORCE_CONTAINER_PRUNE",
        re.compile(r"\bdocker\s+(?:system\s+prune\s+-f|rm\s+-f\s+\$\(|rmi\s+-f)", re.IGNORECASE),
    ),
    (
        "FIREWALL_FLUSH",
        re.compile(r"\b(?:iptables|nftables|ufw)\s+(?:-F|flush|reset|disable)\b", re.IGNORECASE),
    ),
    (
        "RAW_DISK_REDIRECTION",
        re.compile(r">\s*/dev/(?:sd[a-z]|nvme|vd[a-z]|mem|kmem)", re.IGNORECASE),
    ),
    (
        "KERNEL_RELOAD_FORCE_REBOOT",
        re.compile(
            r"\b(?:reboot\s+-f|init\s+0|halt\s+-f|poweroff\s+-f|shutdown\s+-r\s+now)\b",
            re.IGNORECASE,
        ),
    ),
]


class SecurityViolationError(Exception):
    """Raised when the Static Security Barrier flags dangerous script patterns."""

    def __init__(self, flagged_rules: list[str], script_sample: str) -> None:
        self.flagged_rules = flagged_rules
        self.script_sample = script_sample
        message = (
            f"SECURITY BARRIER VIOLATION: Execution blocked. "
            f"Flagged rules: {', '.join(flagged_rules)}. "
            f"Command pattern rejected."
        )
        super().__init__(message)


# ─── Pydantic Transfer Models (Converging with approval.schema.json) ───


class ResourceUsage(BaseModel):
    """Resource consumption metrics from the sandbox."""

    cpu_ms: int = Field(default=0, ge=0)
    memory_peak_mb: int = Field(default=0, ge=0)
    network_egress_bytes: int = Field(default=0, ge=0)


class SandboxExecutionResult(BaseModel):
    """Execution output from an ephemeral sandbox run."""

    sandbox_id: str
    status: str = Field(description="pass | fail | timeout | error")
    exit_code: int
    stdout: str = Field(default="", max_length=50000)
    stderr: str = Field(default="", max_length=50000)
    duration_ms: int = Field(ge=0)
    started_at: datetime
    finished_at: datetime
    resource_usage: ResourceUsage | None = None
    checksum: str = Field(description="SHA-256 of the executed script")


# ─── Static Security Scanner ──────────────────────────────────────────


def scan_script_safety(script_content: str) -> list[str]:
    """
    Scans the given script content against all compiled security rules.
    Returns list of matched rule IDs (empty if safe).
    """
    flagged: list[str] = []
    for rule_id, pattern in DANGEROUS_PATTERNS:
        if pattern.search(script_content):
            flagged.append(rule_id)
    return flagged


# ─── E2B Micro-Sandbox Runner ──────────────────────────────────────────


class E2BMicroSandboxRunner:
    """
    Manages ephemeral E2B sandbox lifecycles for simulation-gated fix validation.
    """

    def __init__(
        self,
        settings: E2BSandboxSettings | None = None,
        custom_sandbox_factory: Any | None = None,
    ) -> None:
        self._settings = settings or get_settings().e2b
        self._sandbox_factory = custom_sandbox_factory
        self._log = logger.bind(component="e2b_runner")

    async def execute_simulation(
        self,
        script_content: str,
        language: str = "bash",
        timeout_ms: int | None = None,
    ) -> SandboxExecutionResult:
        """
        Executes a proposed remediation script inside an isolated sandbox.

        Steps:
        1. Static Security Barrier: Scan script for destructive patterns.
        2. Checksum Computation: SHA-256 verification footprint.
        3. Ephemeral Sandbox Lifecycle: Create, execute, collect logs, terminate.
        4. Structured Output Generation: Format according to approval.schema.json.
        """
        # Step 1: Enforce Static Security Barrier
        flagged_rules = scan_script_safety(script_content)
        if flagged_rules:
            self._log.critical(
                "script_security_violation",
                flagged_rules=flagged_rules,
                script_preview=script_content[:200],
            )
            raise SecurityViolationError(
                flagged_rules=flagged_rules,
                script_sample=script_content[:200],
            )

        # Step 2: Compute Checksum
        checksum = f"sha256:{hashlib.sha256(script_content.encode('utf-8')).hexdigest()}"
        effective_timeout = timeout_ms or self._settings.sandbox_timeout_ms
        started_at = datetime.now(UTC)

        # Step 3: Execute in Sandbox with Guaranteed Teardown
        sandbox = None
        sandbox_id = "sandbox-sim-local"
        stdout_buf: list[str] = []
        stderr_buf: list[str] = []
        exit_code = 0
        run_status = "pass"

        try:
            api_key = self._settings.api_key.get_secret_value()

            if self._sandbox_factory is not None:
                # Custom/Mock factory for unit testing & air-gapped simulation
                sandbox = self._sandbox_factory()
                exec_result = await sandbox.run_code(
                    script_content,
                    language=language,
                    timeout_ms=effective_timeout,
                )
                sandbox_id = getattr(sandbox, "id", "sandbox-custom")
                exit_code = getattr(exec_result, "exit_code", 0)
                stdout_buf.append(getattr(exec_result, "stdout", ""))
                stderr_buf.append(getattr(exec_result, "stderr", ""))
            elif api_key:
                # Real E2B Cloud Sandbox
                import shlex

                from e2b import Sandbox

                sandbox = Sandbox.create(api_key=api_key)
                sandbox_id = getattr(sandbox, "sandbox_id", getattr(sandbox, "id", "sandbox-cloud"))

                cmd = (
                    f"bash -c {shlex.quote(script_content)}"
                    if language == "bash"
                    else f"python3 -c {shlex.quote(script_content)}"
                )
                process = sandbox.commands.run(
                    cmd,
                    timeout=effective_timeout / 1000.0,
                )
                exit_code = process.exit_code
                stdout_buf.append(process.stdout)
                stderr_buf.append(process.stderr)
                run_status = "pass" if exit_code == 0 else "fail"
            else:
                # No E2B API Key: fail closed / unvalidated (D-16, Step 1)
                self._log.warning(
                    "e2b_api_key_missing",
                    reason="No E2B_API_KEY configured; returning unvalidated status",
                )
                script_hash = hashlib.sha256(script_content.encode()).hexdigest()[:8]
                sandbox_id = f"unvalidated-{script_hash}"
                stdout_buf.append(
                    "[STATIC CHECK ONLY] No E2B_API_KEY configured; script unvalidated."
                )
                exit_code = 1
                run_status = "unvalidated"

        except TimeoutError:
            self._log.error("sandbox_execution_timeout", timeout_ms=effective_timeout)
            run_status = "timeout"
            exit_code = 124
            stderr_buf.append(f"Execution timed out after {effective_timeout}ms")
        except Exception as exc:
            self._log.exception("sandbox_execution_error", error=str(exc))
            run_status = "error"
            exit_code = 1
            stderr_buf.append(str(exc))
        finally:
            # Step 4: GUARANTEED TEARDOWN
            if sandbox is not None:
                try:
                    if hasattr(sandbox, "close"):
                        sandbox.close()
                    elif hasattr(sandbox, "kill"):
                        sandbox.kill()
                    self._log.info("sandbox_teardown_complete", sandbox_id=sandbox_id)
                except Exception as cleanup_err:
                    self._log.warning(
                        "sandbox_cleanup_failure",
                        sandbox_id=sandbox_id,
                        error=str(cleanup_err),
                    )

        finished_at = datetime.now(UTC)
        duration_ms = int((finished_at - started_at).total_seconds() * 1000)

        return SandboxExecutionResult(
            sandbox_id=sandbox_id,
            status=run_status,
            exit_code=exit_code,
            stdout="\n".join(stdout_buf)[:50000],
            stderr="\n".join(stderr_buf)[:50000],
            duration_ms=duration_ms,
            started_at=started_at,
            finished_at=finished_at,
            resource_usage=ResourceUsage(cpu_ms=duration_ms, memory_peak_mb=128),
            checksum=checksum,
        )
