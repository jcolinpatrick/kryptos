"""
Tests for the post-Day-5 stabilization pass.

Covers:
  1. Red-team summary distinguishes PASS / CONCERNED / REJECT / ERROR
  2. WorkerStatus.SUCCESS with verified crib_score below SIGNAL does
     NOT promote the theory to PROMISING
  3. WorkerStatus.SUCCESS with verified crib_score >= SIGNAL DOES
     promote the theory to PROMISING
  4. _defensive_artifact_scan preserves canonical empty subdirs and
     removes non-canonical empty subdirs
  5. Worker contract `score` field is documented as a mirror of
     crib_score, not an aggregate score

NOTE: The original Day 5 hardening pass pinned a lexicon-based
_classify_concern_risk classifier. Priority 5 replaced that lexicon
with a structured search_space_risk field on RedTeamVerdict. The
lexicon tests AND the lexicon-based prompt-injection tests have been
removed from this file; the replacement coverage lives in
test_priority5_search_space_risk.py.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.models import (
    TheoryRecord, TheoryStatus,
    WorkerContract, WorkerStatus,
)


# ---------------------------------------------------------------------------
# 1. Red-team summary display semantics
# ---------------------------------------------------------------------------

class TestRedteamSummary:
    """print_redteam_summary must distinguish CONCERNED from cleanly passed."""

    def test_all_clean_passes_say_all_passed_cleanly(self, capsys):
        from kryptosbot import display
        display.print_redteam_summary(
            survivors=3, total=3, rejected=0, concerned=0, errors=0,
        )
        out = capsys.readouterr().out
        assert "all passed cleanly" in out
        assert "3/3" in out

    def test_concerned_is_not_collapsed_into_passed(self, capsys):
        from kryptosbot import display
        display.print_redteam_summary(
            survivors=2, total=2, rejected=0, concerned=1, errors=0,
        )
        out = capsys.readouterr().out
        # The bug: previously CONCERNED was collapsed into "all passed".
        # The fix: must surface the concern explicitly.
        assert "all passed" not in out
        assert "concerned" in out.lower()
        # Must also tell the operator the concerned ones are dispatching.
        assert "unresolved red-team concern" in out

    def test_mixed_outcome_lists_each_bucket(self, capsys):
        from kryptosbot import display
        display.print_redteam_summary(
            survivors=2, total=4, rejected=2, concerned=1, errors=0,
        )
        out = capsys.readouterr().out
        assert "1 pass" in out
        assert "1 concerned" in out
        assert "2 rejected" in out

    def test_all_rejected(self, capsys):
        from kryptosbot import display
        display.print_redteam_summary(
            survivors=0, total=3, rejected=3, concerned=0, errors=0,
        )
        out = capsys.readouterr().out
        assert "rejected" in out


# (Lexicon + bounded-search injection tests removed in Priority 5;
#  see test_priority5_search_space_risk.py for replacement coverage.)


# ---------------------------------------------------------------------------
# 2 & 3. SUCCESS → PROMISING gating on SIGNAL_THRESHOLD
# ---------------------------------------------------------------------------

class TestSuccessPromotionGate:
    """SUCCESS without a verified signal must not become PROMISING."""

    def _make_minimal_controller(self, tmp_path):
        from kryptosbot.controller import ResearchController, ControllerConfig
        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
        )
        from kryptosbot.theory_ledger import TheoryLedger
        ctrl = ResearchController.__new__(ResearchController)
        ctrl.config = cfg
        ctrl.ledger = TheoryLedger(cfg.ledger_db_path)
        ctrl.state = MagicMock()
        ctrl.state.recent_outcomes = []
        ctrl.state.cycle_number = 1
        return ctrl

    def test_success_below_signal_becomes_completed(self, tmp_path):
        ctrl = self._make_minimal_controller(tmp_path)
        theory = TheoryRecord(
            hypothesis_id="t1", title="t", core_claim="c",
            mechanism="m", family="f",
        )
        ctrl.ledger.upsert_theory(theory)
        contract = WorkerContract(
            hypothesis_id="t1",
            status=WorkerStatus.SUCCESS,
            crib_score=8,           # well below SIGNAL=18
            score=8.0,
            bean_passed=False,
            best_plaintext="A" * 97,
        )
        ctrl._absorb_outcomes([contract])
        reloaded = ctrl.ledger.get_theory("t1")
        assert reloaded.status == TheoryStatus.COMPLETED
        assert reloaded.status != TheoryStatus.PROMISING

    def test_success_at_signal_becomes_promising(self, tmp_path):
        ctrl = self._make_minimal_controller(tmp_path)
        theory = TheoryRecord(
            hypothesis_id="t2", title="t", core_claim="c",
            mechanism="m", family="f",
        )
        ctrl.ledger.upsert_theory(theory)
        contract = WorkerContract(
            hypothesis_id="t2",
            status=WorkerStatus.SUCCESS,
            crib_score=18,          # exactly at SIGNAL
            score=18.0,
            bean_passed=False,
            best_plaintext="A" * 97,
        )
        ctrl._absorb_outcomes([contract])
        reloaded = ctrl.ledger.get_theory("t2")
        assert reloaded.status == TheoryStatus.PROMISING


# ---------------------------------------------------------------------------
# 6. Defensive artifact scan canonical preservation
# ---------------------------------------------------------------------------

class TestDefensiveArtifactScan:
    def _make_controller(self, tmp_path):
        from kryptosbot.controller import ResearchController, ControllerConfig
        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "ledger.sqlite",
        )
        ctrl = ResearchController.__new__(ResearchController)
        ctrl.config = cfg
        return ctrl

    def test_preserves_canonical_empty_subdirs(self, tmp_path):
        ctrl = self._make_controller(tmp_path)
        canonical_dir = tmp_path / "scripts" / "hypothesis_tests"
        canonical_dir.mkdir(parents=True)
        theory = TheoryRecord(hypothesis_id="abcdef123456", title="t")

        ctrl._defensive_artifact_scan(theory)

        # Canonical empty dir must STILL exist
        assert canonical_dir.exists(), (
            "canonical scripts/hypothesis_tests was removed; the "
            "defensive cleanup condition is inverted again"
        )

    def test_removes_non_canonical_empty_subdirs(self, tmp_path):
        ctrl = self._make_controller(tmp_path)
        rogue_dir = tmp_path / "scripts" / "worker_scratch_rogue"
        rogue_dir.mkdir(parents=True)
        theory = TheoryRecord(hypothesis_id="abcdef123456", title="t")

        ctrl._defensive_artifact_scan(theory)

        assert not rogue_dir.exists(), (
            "non-canonical empty dir was not cleaned up"
        )


# ---------------------------------------------------------------------------
# 7. Worker contract score field documentation
# ---------------------------------------------------------------------------

class TestScoreFieldDocumentation:
    """Sanity check that the score field documentation lives in models.py
    so future readers cannot miss it."""

    def test_models_documents_score_mirrors_crib(self):
        models_src = (
            Path(__file__).resolve().parent.parent / "models.py"
        ).read_text()
        assert "MIRROR of crib_score" in models_src
