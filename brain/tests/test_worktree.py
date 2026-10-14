"""
Unit tests for Git Worktree Isolation Layer (YYLO Pattern).

Verifies:
- Creation of detached worktree without touching main branch.
- Application of file patches inside the worktree zone.
- Guard against path traversal outside the worktree.
- Unified diff generation.
- Clean and guaranteed teardown.
"""

from pathlib import Path

import pytest

from app.sandbox.worktree import GitWorktreeManager, WorktreeError


@pytest.mark.asyncio
async def test_worktree_lifecycle_and_diff_generation(tmp_path: Path) -> None:
    # Use the active git repository
    mgr = GitWorktreeManager()
    incident_id = "inc-test-48201"

    session = await mgr.create_worktree(incident_id=incident_id)
    assert session.is_active
    assert session.worktree_dir.exists()

    try:
        # Apply a remediation change
        patch_path = await session.apply_file(
            "infra/remediation_patch.yaml",
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: fix-pool\n",
        )
        assert patch_path.exists()

        # Generate diff
        diff_output = await session.get_diff()
        assert "infra/remediation_patch.yaml" in diff_output
        assert "+kind: ConfigMap" in diff_output

    finally:
        # Guaranteed cleanup
        await session.cleanup()
        assert not session.is_active
        assert not session.worktree_dir.exists()


@pytest.mark.asyncio
async def test_worktree_blocks_path_traversal_escape() -> None:
    mgr = GitWorktreeManager()
    session = await mgr.create_worktree(incident_id="inc-traversal-guard")

    try:
        # Attempt writing outside worktree
        with pytest.raises(WorktreeError) as exc_info:
            await session.apply_file("../../malicious_escape.sh", "echo bad")

        assert "Path traversal detected" in str(exc_info.value)
    finally:
        await session.cleanup()
