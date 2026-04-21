"""
Tests for kryptosbot.pantheon_siblings.run_results_synthesis and the
CycleSynthesis dataclass added in Day 5.

Focus: the dataclass shape, the formatter helpers that build the
synthesis user prompt, and the to_landscape_block rendering used by
the next cycle's _assess_landscape. SDK calls are not exercised here.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.pantheon_siblings import (
    CycleSynthesis,
    StatAuditVerdict,
    RedTeamVerdict,
    _normalize_w_focus_recommendation,
    _format_outcomes_for_synthesis,
    _format_redteam_for_synthesis,
    _format_stat_audit_for_synthesis,
    _format_alerts_for_synthesis,
)
from kryptosbot.models import TheoryRecord, WorkerContract, WorkerStatus


# ---------------------------------------------------------------------------
# CycleSynthesis dataclass
# ---------------------------------------------------------------------------

class TestCycleSynthesisShape:

    def test_default_is_empty_but_valid(self):
        s = CycleSynthesis()
        assert s.headline == ""
        assert s.family_movements == []
        assert s.evidence_added == []
        assert s.recommended_next_focus == ""
        assert s.dispatched_count == 0
        assert s.disproved_count == 0
        assert s.signal_count == 0
        assert s.error is None

    def test_landscape_block_renders_minimal_synthesis(self):
        s = CycleSynthesis(
            headline="Cycle 5: 5 disproved, 0 signal",
            recommended_next_focus="shift to grille widths 19-23",
            family_movements=["key_tape -1 active", "grille +2 explored"],
        )
        block = s.to_landscape_block()
        assert "Cycle 5" in block
        assert "Suggested focus" in block
        assert "key_tape -1 active" in block
        assert "grille +2 explored" in block

    def test_landscape_block_caps_family_movements_at_three(self):
        s = CycleSynthesis(
            headline="x",
            family_movements=[f"movement {i}" for i in range(10)],
        )
        block = s.to_landscape_block()
        # Should include first 3, not all 10
        assert "movement 0" in block
        assert "movement 2" in block
        assert "movement 5" not in block

    def test_landscape_block_omits_empty_fields(self):
        s = CycleSynthesis()
        block = s.to_landscape_block()
        assert block == ""  # all fields empty → empty block


# ---------------------------------------------------------------------------
# Synthesis prompt formatters
# ---------------------------------------------------------------------------

class TestSynthesisPromptFormatters:

    def _theory(self, family: str = "test", title: str = "T") -> TheoryRecord:
        return TheoryRecord(
            title=title, core_claim=f"claim-{family}",
            mechanism="m", family=family,
        )

    def test_outcomes_block_empty_when_no_contracts(self):
        block = _format_outcomes_for_synthesis([], [])
        assert "no contracts" in block

    def test_outcomes_block_includes_kernel_verified_scores(self):
        t = self._theory(family="key_tape", title="boustrophedon M4")
        c = WorkerContract(
            hypothesis_id=t.hypothesis_id,
            status=WorkerStatus.DISPROVED,
            crib_score=4, bean_passed=False, score=4.0,
        )
        block = _format_outcomes_for_synthesis([t], [c])
        assert t.hypothesis_id[:8] in block
        assert "family=key_tape" in block
        assert "status=disproved" in block
        assert "crib=4/24" in block

    def test_outcomes_block_flags_fields_overwritten(self):
        # The synthesis agent should see the [overwritten] flag — it's
        # diagnostic of worker fabrication attempts.
        t = self._theory()
        c = WorkerContract(
            hypothesis_id=t.hypothesis_id,
            status=WorkerStatus.SUCCESS,
            crib_score=11, bean_passed=False, score=11.0,
            fields_overwritten=True,
        )
        block = _format_outcomes_for_synthesis([t], [c])
        assert "[overwritten]" in block

    def test_redteam_block_empty_when_no_verdicts(self):
        assert "(none)" in _format_redteam_for_synthesis({})

    def test_redteam_block_compact_per_verdict(self):
        v = RedTeamVerdict(
            verdict="reject", confidence=0.92,
            reasons=["already eliminated by E-FRAC-35"],
        )
        block = _format_redteam_for_synthesis({"abc12345xyz0": v})
        assert "abc12345" in block
        assert "reject" in block
        assert "0.92" in block
        assert "E-FRAC-35" in block

    def test_stat_audit_block_empty_means_no_signal_contracts(self):
        block = _format_stat_audit_for_synthesis({})
        assert "no contracts hit the SIGNAL threshold" in block

    def test_stat_audit_block_per_verdict(self):
        v = StatAuditVerdict(
            verdict="rejected", confidence=0.88,
            methodology_concerns=["null model mismatch"],
        )
        block = _format_stat_audit_for_synthesis({"def67890xyz0": v})
        assert "def67890" in block
        assert "rejected" in block
        assert "null model mismatch" in block

    def test_alerts_block_empty_when_no_alerts(self):
        assert "(none)" in _format_alerts_for_synthesis([])

    def test_alerts_block_caps_at_ten(self):
        alerts = [f"alert {i}" for i in range(20)]
        block = _format_alerts_for_synthesis(alerts)
        assert "alert 0" in block
        assert "alert 9" in block
        assert "alert 11" not in block


class TestWFocusSynthesisGuard:

    def _w_theory(self, title: str = "W-delimited segment trial") -> TheoryRecord:
        return TheoryRecord(
            title=title,
            core_claim="The carved W positions bound six segments for a delimiter-style mechanism.",
            mechanism="Preserve CT97 crib positions under W-bounded segment geometry.",
            family="grille",
            anomalies_exploited=["w_delimiter_segments"],
        )

    def test_negative_w_cycle_cannot_recommend_moving_away(self):
        theory = self._w_theory()
        contract = WorkerContract(
            hypothesis_id=theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
            crib_score=0,
            bean_passed=False,
            score=0.0,
        )
        focus = _normalize_w_focus_recommendation(
            "Theorist should move away from W-delimiter structural interpretations entirely.",
            [theory],
            [contract],
        )
        assert "move away" not in focus.lower()
        assert "continue aggressively" in focus.lower()
        assert "x/q/z" in focus.lower()

    def test_w_geometry_demotions_are_narrowed_not_globalized(self):
        theory = self._w_theory("W geometry trial")
        contract = WorkerContract(
            hypothesis_id=theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
            crib_score=0,
            bean_passed=False,
            score=0.0,
        )
        focus = _normalize_w_focus_recommendation(
            "Avoid further W-segment geometry variants until a width constraint can be independently justified from the sculpture.",
            [theory],
            [contract],
        )
        assert "avoid new width-specific geometry variants" in focus.lower()
        assert "delimiter-marker" in focus.lower()
        assert "crib-bridge geometry" in focus.lower()

    def test_non_w_cycle_focus_is_left_unchanged(self):
        theory = TheoryRecord(
            title="Compass rose keyed tableau",
            core_claim="Use compass bearings as tableau selectors.",
            mechanism="Finite keyed tableau walk.",
            family="geometry",
            anomalies_exploited=["aaa_compass_cipher"],
        )
        contract = WorkerContract(
            hypothesis_id=theory.hypothesis_id,
            status=WorkerStatus.DISPROVED,
            crib_score=0,
            bean_passed=False,
            score=0.0,
        )
        focus = _normalize_w_focus_recommendation(
            "Bias toward families with no recent clean sweeps.",
            [theory],
            [contract],
        )
        assert focus == "Bias toward families with no recent clean sweeps."

    def test_w_signal_cycle_is_left_unchanged(self):
        theory = self._w_theory()
        contract = WorkerContract(
            hypothesis_id=theory.hypothesis_id,
            status=WorkerStatus.SUCCESS,
            crib_score=18,
            bean_passed=True,
            score=18.0,
        )
        focus = _normalize_w_focus_recommendation(
            "Escalate the strongest W survivor with stat-audit support.",
            [theory],
            [contract],
        )
        assert focus == "Escalate the strongest W survivor with stat-audit support."
