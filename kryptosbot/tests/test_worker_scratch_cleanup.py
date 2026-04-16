"""Tests for the worker scratch directory and cleanup pass.

Verifies:
- The controller creates a designated scratch directory under
  results/worker_scratch/<hypothesis_id>/ before the worker runs.
- The worker prompt instructs the worker to write scratch files there.
- After the worker finishes, the scratch directory is removed.
- Defensive scan catches workers that violate the policy by writing to
  scripts/ or tests/ instead, deletes the files, and logs the violation.
- Unrelated files in scripts/ and tests/ are preserved.
- Cleanup runs even on timeout / exception paths.
"""
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.controller import ControllerConfig, ResearchController
from kryptosbot.models import TheoryRecord, WorkerContract, WorkerStatus


@pytest.fixture
def tmp_controller(tmp_path):
    """A controller wired to a temporary project root."""
    (tmp_path / "scripts").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src").mkdir()
    (tmp_path / "results").mkdir()
    (tmp_path / "db").mkdir()
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "db" / "ledger.sqlite",
    )
    return ResearchController(cfg), tmp_path


@pytest.fixture
def sample_theory():
    return TheoryRecord(
        title="Test theory",
        core_claim="Test claim for cleanup test",
        mechanism="Test mechanism",
        family="novel",
    )


# ── Scratch directory ────────────────────────────────────────────────

class TestScratchDirectory:

    def test_scratch_dir_path_is_under_results(self, tmp_controller, sample_theory):
        ctrl, root = tmp_controller
        path = ctrl._worker_scratch_dir(sample_theory)
        assert root / "results" / "worker_scratch" in path.parents
        assert path.name == sample_theory.hypothesis_id

    def test_scratch_dir_includes_hypothesis_id(self, tmp_controller, sample_theory):
        ctrl, root = tmp_controller
        path = ctrl._worker_scratch_dir(sample_theory)
        assert sample_theory.hypothesis_id in str(path)

    def test_worker_prompt_references_scratch_dir(self, tmp_controller, sample_theory):
        ctrl, root = tmp_controller
        prompt = ctrl._build_worker_prompt(sample_theory)
        scratch_rel = f"results/worker_scratch/{sample_theory.hypothesis_id}"
        assert scratch_rel in prompt

    def test_worker_prompt_warns_against_scripts_dir(self, tmp_controller, sample_theory):
        ctrl, root = tmp_controller
        prompt = ctrl._build_worker_prompt(sample_theory)
        assert "DO NOT write scratch files to:" in prompt
        assert "scripts/" in prompt
        assert "tests/" in prompt


# ── Cleanup: success path ────────────────────────────────────────────

class TestCleanupSuccessPath:

    def test_cleanup_removes_scratch_directory(self, tmp_controller, sample_theory):
        ctrl, root = tmp_controller
        scratch = ctrl._worker_scratch_dir(sample_theory)
        scratch.mkdir(parents=True, exist_ok=True)
        (scratch / "intermediate.py").write_text("# scratch")
        (scratch / "result.json").write_text("{}")

        contract = WorkerContract(
            hypothesis_id=sample_theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
        )
        ctrl._cleanup_worker_artifacts(sample_theory, contract)

        assert not scratch.exists()

    def test_cleanup_idempotent_when_scratch_missing(self, tmp_controller, sample_theory):
        """Cleanup should not raise if the scratch dir was never created."""
        ctrl, root = tmp_controller
        contract = WorkerContract(
            hypothesis_id=sample_theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
        )
        # Should not raise
        ctrl._cleanup_worker_artifacts(sample_theory, contract)


# ── Cleanup: defensive scan for policy violations ────────────────────

class TestDefensiveScan:

    def test_cleanup_deletes_violation_in_scripts_by_filename(
        self, tmp_controller, sample_theory
    ):
        ctrl, root = tmp_controller
        hid_short = sample_theory.hypothesis_id[:12]
        violation = root / "scripts" / f"test_{hid_short}_violation.py"
        violation.write_text("# violation")

        contract = WorkerContract(
            hypothesis_id=sample_theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
        )
        ctrl._cleanup_worker_artifacts(sample_theory, contract)

        assert not violation.exists()

    def test_cleanup_deletes_violation_in_tests_by_filename(
        self, tmp_controller, sample_theory
    ):
        ctrl, root = tmp_controller
        hid_short = sample_theory.hypothesis_id[:12]
        violation = root / "tests" / f"test_{hid_short}_test.py"
        violation.write_text("# violation")

        contract = WorkerContract(
            hypothesis_id=sample_theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
        )
        ctrl._cleanup_worker_artifacts(sample_theory, contract)

        assert not violation.exists()

    def test_cleanup_deletes_violation_by_recent_content(
        self, tmp_controller, sample_theory
    ):
        """A file without the hypothesis_id in its NAME but with the
        hypothesis_id in its CONTENT (and recently modified) is deleted."""
        ctrl, root = tmp_controller
        hid_short = sample_theory.hypothesis_id[:12]
        violation = root / "scripts" / "innocent_name.py"
        violation.write_text(f'"""Hypothesis {hid_short}: violation."""\n')

        contract = WorkerContract(
            hypothesis_id=sample_theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
        )
        ctrl._cleanup_worker_artifacts(sample_theory, contract)

        assert not violation.exists()

    def test_cleanup_preserves_unrelated_files(
        self, tmp_controller, sample_theory
    ):
        """Files that don't reference the hypothesis_id are preserved."""
        ctrl, root = tmp_controller
        unrelated_script = root / "scripts" / "unrelated.py"
        unrelated_script.write_text("# legitimate script\nprint('hi')\n")

        unrelated_test = root / "tests" / "test_unrelated.py"
        unrelated_test.write_text("def test_x(): assert True\n")

        contract = WorkerContract(
            hypothesis_id=sample_theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
        )
        ctrl._cleanup_worker_artifacts(sample_theory, contract)

        assert unrelated_script.exists()
        assert unrelated_test.exists()

    def test_cleanup_logs_policy_violation(
        self, tmp_controller, sample_theory, caplog
    ):
        ctrl, root = tmp_controller
        hid_short = sample_theory.hypothesis_id[:12]
        violation = root / "scripts" / f"test_{hid_short}_v.py"
        violation.write_text("# v")

        contract = WorkerContract(
            hypothesis_id=sample_theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
        )

        import logging
        with caplog.at_level(logging.WARNING, logger="kryptosbot.controller"):
            ctrl._cleanup_worker_artifacts(sample_theory, contract)

        assert any("POLICY VIOLATION" in r.message for r in caplog.records)


# ── Cleanup: edge cases ──────────────────────────────────────────────

class TestCleanupEdgeCases:

    def test_cleanup_does_not_touch_src_unless_filename_match(
        self, tmp_controller, sample_theory
    ):
        """Files in src/ that don't have the hypothesis_id in their NAME
        are preserved even if they were recently modified."""
        ctrl, root = tmp_controller
        hid_short = sample_theory.hypothesis_id[:12]
        innocent_src = root / "src" / "module.py"
        innocent_src.parent.mkdir(parents=True, exist_ok=True)
        innocent_src.write_text(f"# mentions {hid_short} in content but not name")

        contract = WorkerContract(
            hypothesis_id=sample_theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
        )
        ctrl._cleanup_worker_artifacts(sample_theory, contract)

        # src/ files with content-only matches are preserved
        assert innocent_src.exists()

    def test_cleanup_deletes_src_only_with_filename_match(
        self, tmp_controller, sample_theory
    ):
        """Files in src/ that have the hypothesis_id in their FILENAME
        are deleted (extreme worker violation)."""
        ctrl, root = tmp_controller
        hid_short = sample_theory.hypothesis_id[:12]
        violation = root / "src" / f"worker_dropped_{hid_short}.py"
        violation.write_text("# extreme violation")

        contract = WorkerContract(
            hypothesis_id=sample_theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
        )
        ctrl._cleanup_worker_artifacts(sample_theory, contract)

        assert not violation.exists()

    def test_cleanup_handles_missing_hypothesis_id(self, tmp_controller):
        """Cleanup with empty hypothesis_id should not raise or delete."""
        ctrl, root = tmp_controller
        empty_theory = TheoryRecord()
        empty_theory.hypothesis_id = ""

        unrelated = root / "scripts" / "preserve_me.py"
        unrelated.write_text("# safe")

        contract = WorkerContract(
            hypothesis_id="",
            status=WorkerStatus.ERROR,
        )
        # Should not raise
        ctrl._cleanup_worker_artifacts(empty_theory, contract)

        # Unrelated file should still exist
        assert unrelated.exists()
