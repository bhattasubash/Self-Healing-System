"""
Git Worktree Isolation Layer (YYLO Pattern).

Isolates configuration mutations and infrastructure remediation scripts within
dedicated, ephemeral git worktree directories. Prevents direct mutation of the
primary repository working tree while enabling precise diff generation.

Lifecycle:
1. Spawn worktree: git worktree add --detach .git-worktrees/fix-<incident_id>
2. Apply changes: write proposed files / patches into worktree
3. Audit diff: execute git diff to generate human-reviewable patch
4. Teardown: git worktree remove --force .git-worktrees/fix-<incident_id>
"""

from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import structlog

logger = structlog.get_logger()

DEFAULT_WORKTREE_ROOT: Final = ".git-worktrees"


class WorktreeError(Exception):
    """Raised when git worktree operations fail."""


@dataclass(slots=True)
class WorktreeStatus:
    """Status metadata for an active worktree zone."""

    incident_id: str
    worktree_path: Path
    branch_name: str
    is_active: bool
    diff: str = ""


class GitWorktreeManager:
    """
    Manages ephemeral git worktree lifecycles for safe remediation validation.
    """

    def __init__(
        self,
        repo_root: Path | str | None = None,
        worktree_root: str = DEFAULT_WORKTREE_ROOT,
    ) -> None:
        self.repo_root = Path(repo_root or Path.cwd()).resolve()
        self.worktree_base = self.repo_root / worktree_root
        self._log = logger.bind(component="worktree_mgr", repo=str(self.repo_root))

    async def create_worktree(
        self,
        incident_id: str,
        commit_ref: str = "HEAD",
    ) -> GitWorktreeSession:
        """
        Creates and returns an active isolated worktree session.
        """
        # Sanitize incident ID for path & branch safety
        safe_id = re.sub(r"[^a-zA-Z0-9_-]", "", incident_id)[:32]
        worktree_dir = self.worktree_base / f"fix-{safe_id}"
        branch_name = f"fix/{safe_id}"

        session = GitWorktreeSession(
            manager=self,
            incident_id=safe_id,
            worktree_dir=worktree_dir,
            branch_name=branch_name,
            commit_ref=commit_ref,
        )
        await session.setup()
        return session


class GitWorktreeSession:
    """
    Represents a single active git worktree instance.
    Supports asynchronous context management:
        async with worktree_session:
            await worktree_session.apply_file(...)
            diff = await worktree_session.get_diff()
    """

    def __init__(
        self,
        manager: GitWorktreeManager,
        incident_id: str,
        worktree_dir: Path,
        branch_name: str,
        commit_ref: str = "HEAD",
    ) -> None:
        self.manager = manager
        self.incident_id = incident_id
        self.worktree_dir = worktree_dir
        self.branch_name = branch_name
        self.commit_ref = commit_ref
        self._is_active = False
        self._log = logger.bind(
            component="worktree_session",
            incident_id=self.incident_id,
            path=str(self.worktree_dir),
        )

    @property
    def is_active(self) -> bool:
        return self._is_active

    async def __aenter__(self) -> GitWorktreeSession:
        if not self._is_active:
            await self.setup()
        return self

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        await self.cleanup()

    async def setup(self) -> None:
        """
        Spawns the isolated git worktree using --detach to avoid branch collisions.
        """
        # Ensure worktrees parent folder exists
        self.manager.worktree_base.mkdir(parents=True, exist_ok=True)

        # Clean any stale previous worktree at this path
        if self.worktree_dir.exists():
            await self.cleanup()

        cmd = [
            "git",
            "worktree",
            "add",
            "--detach",
            str(self.worktree_dir),
            self.commit_ref,
        ]

        stdout, stderr, code = await self._run_command(cmd, cwd=self.manager.repo_root)
        if code != 0:
            self._log.error("worktree_creation_failed", stdout=stdout, stderr=stderr, code=code)
            raise WorktreeError(f"Failed to create git worktree at {self.worktree_dir}: {stderr}")

        self._is_active = True
        self._log.info("worktree_created_successfully", worktree=str(self.worktree_dir))

    async def apply_file(self, relative_path: str, content: str) -> Path:
        """
        Writes a remediation file or patch directly inside the worktree zone.
        Path traversal outside the worktree is strictly prevented.
        """
        if not self._is_active:
            raise WorktreeError("Worktree session is not active")

        target_file = (self.worktree_dir / relative_path).resolve()

        # Security check: Ensure target does not escape the worktree directory
        if not str(target_file).startswith(str(self.worktree_dir.resolve())):
            raise WorktreeError(
                f"Path traversal detected: {relative_path} resolves outside worktree"
            )

        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(content, encoding="utf-8")
        self._log.info("applied_remediation_file", file=relative_path)
        return target_file

    async def get_diff(self) -> str:
        """
        Generates a unified git diff showing all staged and unstaged modifications
        within the worktree sandbox compared to the parent commit.
        """
        if not self._is_active:
            raise WorktreeError("Worktree session is not active")

        # Stage untracked and modified files to include them in the diff
        await self._run_command(["git", "add", "-N", "."], cwd=self.worktree_dir)

        cmd = ["git", "diff", self.commit_ref]
        stdout, stderr, code = await self._run_command(cmd, cwd=self.worktree_dir)

        if code != 0:
            self._log.error("git_diff_failed", stderr=stderr)
            raise WorktreeError(f"Failed to generate git diff: {stderr}")

        return stdout

    async def stage_and_commit(self, message: str) -> str:
        """
        Stages all changes and creates an isolated commit in the detached worktree.
        Returns the new commit hash.
        """
        if not self._is_active:
            raise WorktreeError("Worktree session is not active")

        await self._run_command(["git", "add", "-A"], cwd=self.worktree_dir)
        _, stderr, code = await self._run_command(
            ["git", "commit", "-m", message],
            cwd=self.worktree_dir,
        )
        if code != 0:
            raise WorktreeError(f"Failed to commit worktree changes: {stderr}")

        out_rev, _, _ = await self._run_command(["git", "rev-parse", "HEAD"], cwd=self.worktree_dir)
        return out_rev.strip()

    async def cleanup(self) -> None:
        """
        Guaranteed teardown hook: forcefully removes the git worktree and directory.
        """
        self._log.info("cleaning_up_worktree", path=str(self.worktree_dir))

        if self.worktree_dir.exists():
            cmd = ["git", "worktree", "remove", "--force", str(self.worktree_dir)]
            _, _, _ = await self._run_command(cmd, cwd=self.manager.repo_root)

            # Extra cleanup fallback if directory lock left remnants
            if self.worktree_dir.exists():
                try:
                    shutil.rmtree(self.worktree_dir, ignore_errors=True)
                except Exception as rmtree_err:
                    self._log.warning("manual_rmtree_cleanup_failed", error=str(rmtree_err))

        # Prune dead worktree metadata
        await self._run_command(["git", "worktree", "prune"], cwd=self.manager.repo_root)
        self._is_active = False

    async def _run_command(
        self, cmd: list[str], cwd: Path
    ) -> tuple[str, str, int]:
        """Execute a git CLI command asynchronously."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=str(cwd),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await proc.communicate()
        return (
            stdout_b.decode("utf-8", errors="replace"),
            stderr_b.decode("utf-8", errors="replace"),
            proc.returncode or 0,
        )
