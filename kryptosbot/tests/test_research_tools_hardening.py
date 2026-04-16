"""
Regression tests for research_tools.record_experiment_result_tool hardening
(April 2026 audit, response to the worker-backdoor promotion finding).

Background
----------
The original record_experiment_result_tool built a WorkerContract directly
from caller arguments and mapped WorkerStatus.SUCCESS -> TheoryStatus.PROMISING
unconditionally. This bypassed both:

  (a) contracts._verify_against_kernel() — which recomputes crib_score,
      bean_passed, and score from best_plaintext against the kernel, so
      worker self-reports cannot manufacture a BREAKTHROUGH or signal.

  (b) controller._absorb_outcomes() — which gates PROMISING on kernel-
      verified crib_score >= SIGNAL_THRESHOLD.

The tool is exposed to Agent SDK workers. A worker can call it and
self-report any fields it wants. Before the fix, a worker could promote
a theory to PROMISING by reporting SUCCESS with a fabricated crib_score=24
and an empty or junk plaintext.

These tests pin the fixed behavior so the regression cannot silently
re-appear.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.models import (
    TheoryRecord, TheoryStatus,
    WorkerStatus,
)
from kryptosbot.theory_ledger import TheoryLedger
from kryptosbot import research_tools


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_ledger(tmp_path):
    db = tmp_path / "research_tools_test.sqlite"
    ledger = TheoryLedger(db)
    research_tools.set_ledger(ledger)
    yield ledger
    research_tools.set_ledger(None)


def _seed_theory(ledger: TheoryLedger, hyp_id: str = "hyp-test-1") -> TheoryRecord:
    theory = TheoryRecord(
        hypothesis_id=hyp_id,
        title="Test theory",
        core_claim="placeholder",
        mechanism="placeholder",
        family="test_family",
        status=TheoryStatus.RUNNING,
    )
    ledger.upsert_theory(theory)
    return theory


def _call_tool(args: dict) -> dict:
    """Invoke the async tool handler synchronously and parse the JSON result."""
    handler = research_tools.record_experiment_result_tool.handler
    envelope = asyncio.run(handler(args))
    text = envelope["content"][0]["text"]
    return json.loads(text)


# ---------------------------------------------------------------------------
# Regression tests for the audit backdoor
# ---------------------------------------------------------------------------

class TestRecordExperimentResultHardening:
    """Pins the post-audit behavior of record_experiment_result_tool."""

    def test_fabricated_success_with_empty_plaintext_is_not_promising(self, tmp_ledger):
        """
        A worker reports SUCCESS with crib_score=24, bean_passed=True, but
        empty best_plaintext. _verify_against_kernel should zero the score
        fields and flag the contract. The tool must NOT promote to PROMISING.
        """
        theory = _seed_theory(tmp_ledger, "hyp-fab-empty")

        result = _call_tool({
            "hypothesis_id": theory.hypothesis_id,
            "status": "success",
            "score": 24.0,
            "crib_score": 24,
            "bean_passed": True,
            "best_plaintext": "",
            "narrative_summary": "totally solved it trust me",
        })

        assert result["status"] == "recorded"
        assert result["theory_status"] == TheoryStatus.COMPLETED.value
        assert result["theory_status"] != TheoryStatus.PROMISING.value
        assert result["verified_crib_score"] == 0
        assert result["verified_bean_passed"] is False
        assert result["fields_overwritten"] is True
        assert result["verification_error"]  # non-empty

        persisted = tmp_ledger.get_theory(theory.hypothesis_id)
        assert persisted.status == TheoryStatus.COMPLETED
        assert persisted.status != TheoryStatus.PROMISING
        assert persisted.best_score == 0.0

    def test_fabricated_success_with_wrong_length_plaintext_is_not_promising(self, tmp_ledger):
        """
        Worker reports SUCCESS with a plaintext that is NOT 97 characters.
        Kernel verification refuses to trust it and zeros the score fields.
        """
        theory = _seed_theory(tmp_ledger, "hyp-fab-wronglen")

        result = _call_tool({
            "hypothesis_id": theory.hypothesis_id,
            "status": "success",
            "score": 24.0,
            "crib_score": 24,
            "bean_passed": True,
            "best_plaintext": "EASTNORTHEASTBERLINCLOCK",  # 24 chars, not 97
            "narrative_summary": "pasted the cribs in",
        })

        assert result["theory_status"] == TheoryStatus.COMPLETED.value
        assert result["verified_crib_score"] == 0
        assert result["fields_overwritten"] is True
        assert "97" in result["verification_error"]

        persisted = tmp_ledger.get_theory(theory.hypothesis_id)
        assert persisted.status == TheoryStatus.COMPLETED

    def test_success_with_97char_noise_plaintext_is_completed_not_promising(self, tmp_ledger):
        """
        Worker reports SUCCESS with a legitimately-shaped 97-char plaintext
        that does not match the cribs. Verified crib_score is well below
        SIGNAL_THRESHOLD (18), so the theory should be COMPLETED.
        """
        theory = _seed_theory(tmp_ledger, "hyp-noise-97")

        noise_pt = "A" * 97
        result = _call_tool({
            "hypothesis_id": theory.hypothesis_id,
            "status": "success",
            "score": 20.0,      # self-reported, should be ignored
            "crib_score": 20,   # self-reported, should be ignored
            "bean_passed": True,
            "best_plaintext": noise_pt,
        })

        assert result["theory_status"] == TheoryStatus.COMPLETED.value
        assert result["verified_crib_score"] < 18
        # Self-report of 20 disagreed with reality → fields overwritten
        assert result["fields_overwritten"] is True

        persisted = tmp_ledger.get_theory(theory.hypothesis_id)
        assert persisted.status == TheoryStatus.COMPLETED
        # best_score is the verified score, not the fabricated 20.0
        assert persisted.best_score < 18.0

    def test_success_with_real_crib_bearing_plaintext_is_promising(self, tmp_ledger):
        """
        Sanity check the positive path: a 97-char plaintext that actually
        places EASTNORTHEAST and BERLINCLOCK at the canonical crib
        positions (21-33 and 63-73, 0-indexed) should produce a verified
        crib_score of 24 and legitimately promote to PROMISING.

        This also guards against an over-aggressive fix that refuses to
        ever promote via this tool.
        """
        theory = _seed_theory(tmp_ledger, "hyp-real-signal")

        # Build a 97-char plaintext with cribs at the canonical 0-indexed
        # positions. Filler is 'X' so it cannot accidentally look like
        # extra cribs.
        filler = ["X"] * 97
        east = "EASTNORTHEAST"
        bclk = "BERLINCLOCK"
        for i, c in enumerate(east):
            filler[21 + i] = c
        for i, c in enumerate(bclk):
            filler[63 + i] = c
        pt = "".join(filler)
        assert len(pt) == 97

        result = _call_tool({
            "hypothesis_id": theory.hypothesis_id,
            "status": "success",
            "score": 0.0,           # deliberately under-report
            "crib_score": 0,        # deliberately under-report
            "bean_passed": False,   # deliberately under-report
            "best_plaintext": pt,
            "narrative_summary": "crib-anchored candidate",
        })

        # Kernel verification recomputes crib_score upward from 0 to 24
        assert result["verified_crib_score"] == 24
        assert result["theory_status"] == TheoryStatus.PROMISING.value
        assert result["fields_overwritten"] is True  # we under-reported

        persisted = tmp_ledger.get_theory(theory.hypothesis_id)
        assert persisted.status == TheoryStatus.PROMISING

    def test_disproved_still_maps_to_eliminated(self, tmp_ledger):
        """DISPROVED contracts should still eliminate regardless of plaintext."""
        theory = _seed_theory(tmp_ledger, "hyp-disproved")

        result = _call_tool({
            "hypothesis_id": theory.hypothesis_id,
            "status": "disproved",
            "best_plaintext": "",
            "disproof_evidence": ["tested exhaustively, no signal"],
            "narrative_summary": "dead",
        })

        assert result["theory_status"] == TheoryStatus.ELIMINATED.value
        persisted = tmp_ledger.get_theory(theory.hypothesis_id)
        assert persisted.status == TheoryStatus.ELIMINATED

    def test_timeout_does_not_eliminate(self, tmp_ledger):
        """
        TIMEOUT must not be treated as elimination. The audit's related
        finding was that timeouts should remain inconclusive/completed so
        that a slow worker cannot prune a viable hypothesis.
        """
        theory = _seed_theory(tmp_ledger, "hyp-timeout")

        result = _call_tool({
            "hypothesis_id": theory.hypothesis_id,
            "status": "timeout",
            "narrative_summary": "hit 30min wall",
        })

        assert result["theory_status"] == TheoryStatus.COMPLETED.value
        assert result["theory_status"] != TheoryStatus.ELIMINATED.value

    def test_unknown_hypothesis_id_returns_error(self, tmp_ledger):
        """Calling the tool on an unknown hypothesis_id should error, not crash."""
        result = _call_tool({
            "hypothesis_id": "hyp-does-not-exist",
            "status": "success",
            "best_plaintext": "",
        })
        assert "error" in result
