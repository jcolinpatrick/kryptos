"""
Tests for kryptosbot.contracts boundary validation.

Focus: the kernel-verification path added 2026-04-13 in response to the
Day-4 BREAKTHROUGH-fabrication incident (hypothesis e2784dc9). The worker
LLM emitted a CT73-space plaintext with cribs textually pasted in and
self-reported crib_score=24 + bean_passed=True; the controller fired a
BREAKTHROUGH alert despite score=0.0 on the same line. Root cause:
validate_worker_contract trusted the worker's self-reported numbers
without recomputing them against the kernel.

Policy under test: kernel always overrules worker self-report. These tests
lock in that policy so future controller work cannot regress it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Bootstrap — kryptosbot lives one level up from tests/, src/ is at repo root
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.contracts import validate_worker_contract, validate_theory_proposals
from kryptosbot.models import WorkerStatus


def _wrap(payload: dict) -> str:
    """Wrap a dict in the fenced JSON block format the worker produces."""
    return f"Some narrative prose.\n\n```json\n{json.dumps(payload)}\n```\n"


# ---------------------------------------------------------------------------
# Fabrication: cribs in CT73 space + claimed scores
# ---------------------------------------------------------------------------

class TestE2784dc9Regression:
    """Regression for the 2026-04-13 BREAKTHROUGH-fabrication incident."""

    def test_ct73_length_plaintext_is_unverifiable(self):
        # Reproduces the exact e2784dc9 payload shape: 80-char CT73-space PT
        # with cribs pasted at CT73 positions and a self-reported
        # crib_score=24 + bean_passed=True.
        fabricated_pt = (
            "OUFSZHVWZLMTC"          # filler 0-12
            "EASTNORTHEAST"          # cribs at CT73 positions 13-25
            "WRRESXOLWFBKEYRABDMYYGPJE"  # filler 26-49
            "BERLINCLOCK"            # cribs at CT73 positions ~50-60
            "AZOQFBBWQNQKQHAIKD"     # filler tail
        )
        assert len(fabricated_pt) == 80, f"setup error: {len(fabricated_pt)}"

        raw = _wrap({
            "hypothesis_id": "e2784dc990b5",
            "status": "inconclusive",
            "score": 0.0,
            "crib_score": 24,
            "bean_passed": True,
            "best_plaintext": fabricated_pt,
            "narrative_summary": "boustrophedon tape M4",
        })

        result = validate_worker_contract(raw, "e2784dc990b5")
        assert result.is_valid, f"parse should succeed; errors: {result.errors}"
        c = result.value

        # Kernel cannot score a 80-char CT73-space PT against fixed CT97 cribs.
        # Verification must zero the score fields and flag the discrepancy.
        assert c.crib_score == 0
        assert c.bean_passed is False
        assert c.score == 0.0
        assert c.fields_overwritten is True
        assert c.worker_self_report == {
            "crib_score": 24, "bean_passed": True, "score": 0.0,
        }
        assert "97" in c.verification_error  # explains length mismatch


# ---------------------------------------------------------------------------
# Length and shape edge cases
# ---------------------------------------------------------------------------

class TestVerificationLengthGate:

    def test_empty_plaintext_with_zero_claims_is_clean(self):
        # Honest "I have nothing" — no overwrite, no error.
        raw = _wrap({
            "hypothesis_id": "h1",
            "status": "disproved",
            "score": 0.0,
            "crib_score": 0,
            "bean_passed": False,
            "best_plaintext": "",
        })
        c = validate_worker_contract(raw, "h1").value
        assert c.crib_score == 0
        assert c.bean_passed is False
        assert c.fields_overwritten is False
        assert c.verification_error == ""
        assert c.worker_self_report == {}

    def test_empty_plaintext_with_nonzero_claims_is_overwritten(self):
        # Worker reports a score with no plaintext — pure hallucination.
        raw = _wrap({
            "hypothesis_id": "h2",
            "status": "success",
            "score": 17.0,
            "crib_score": 19,
            "bean_passed": False,
            "best_plaintext": "",
        })
        c = validate_worker_contract(raw, "h2").value
        assert c.crib_score == 0
        assert c.fields_overwritten is True
        assert c.worker_self_report["crib_score"] == 19
        assert "empty best_plaintext" in c.verification_error

    def test_wrong_length_plaintext_is_overwritten(self):
        # 50-char plaintext, claimed crib_score=22 — kernel cannot verify
        # against CT97 fixed positions, so the claim is discarded.
        raw = _wrap({
            "hypothesis_id": "h3",
            "status": "success",
            "score": 22.0,
            "crib_score": 22,
            "bean_passed": False,
            "best_plaintext": "A" * 50,
        })
        c = validate_worker_contract(raw, "h3").value
        assert c.crib_score == 0
        assert c.fields_overwritten is True
        assert c.worker_self_report["crib_score"] == 22


# ---------------------------------------------------------------------------
# Honest CT97 plaintexts
# ---------------------------------------------------------------------------

def _ct97_with_cribs_only() -> str:
    """Build a 97-char plaintext with all 24 crib characters at the correct
    CT97 positions and 'X' filler elsewhere. Crib score is 24 by construction;
    Bean will not pass on the resulting noise keystream."""
    from kryptos.kernel.constants import CRIB_DICT
    pt = list("X" * 97)
    for pos, ch in CRIB_DICT.items():
        pt[pos] = ch
    return "".join(pt)


class TestVerificationKernelPath:
    """Kernel-recompute path on CT97-shaped plaintexts.

    PHASE 1 GAP (closed in Phase 2, 2026-05-16): Bean was derived from the
    cribs themselves and is variant-independent. Therefore ANY CT97
    plaintext with correct crib characters at the canonical positions
    21-33 and 63-73 will satisfy Bean, even if the surrounding filler is
    gibberish. Phase 1 verification narrowed the fabrication surface
    from "any worker that types crib_score=24 in JSON" to "any worker
    that types correctly-positioned CT97-space cribs", which was a major
    improvement but not airtight. The Phase 2 crib-paste detector
    (`_is_crib_paste_artifact` + `_non_crib_ngram_per_char`) closes the
    residual gap by re-scoring the non-crib positions; an X-filler or
    random-garbage paste produces a non-crib ngram per-char below -6.2
    and is reclassified as `artifact_class=crib_paste` with status
    INCONCLUSIVE and zeroed score fields.
    """

    def test_ct97_with_all_cribs_pasted_is_classified_as_paste_artifact(self):
        # Phase 2: X-filler crib paste with verified_crib=24 must be
        # reclassified as a crib-paste artifact. The signal fields are
        # zeroed and status is forced to INCONCLUSIVE so no alert can
        # fire and the controller cannot promote it to BREAKTHROUGH.
        pt = _ct97_with_cribs_only()
        raw = _wrap({
            "hypothesis_id": "h4",
            "status": "success",
            "score": 24.0,
            "crib_score": 24,
            "bean_passed": True,
            "best_plaintext": pt,
        })
        c = validate_worker_contract(raw, "h4").value
        # Detector fires → signal fields zeroed.
        assert c.crib_score == 0
        assert c.bean_passed is False
        assert c.score == 0.0
        # Status downgraded to INCONCLUSIVE (NOT DISPROVED — paste is an
        # artifact, not exhaustion).
        from kryptosbot.models import WorkerStatus
        assert c.status == WorkerStatus.INCONCLUSIVE
        # Audit trail.
        assert c.fields_overwritten is True
        assert "crib_paste_artifact:v1" in c.verification_error
        assert c.raw_artifacts.get("artifact_class") == "crib_paste"
        snapshot = c.raw_artifacts.get("kernel_verified_before_artifact_filter")
        assert isinstance(snapshot, dict)
        assert snapshot.get("crib_score") == 24
        assert snapshot.get("bean_passed") is True

    def test_ct97_with_cribs_underreported_bean_still_paste_artifact(self):
        # Worker honestly pastes cribs but underreports bean_passed=False.
        # Phase 2: the kernel STILL detects the crib-paste shape (ngram
        # floor below -6.2) and reclassifies as artifact. The worker's
        # underreported bean=False is moot — the result is INCONCLUSIVE
        # regardless of what the worker claimed.
        pt = _ct97_with_cribs_only()
        raw = _wrap({
            "hypothesis_id": "h5",
            "status": "inconclusive",
            "score": 0.0,
            "crib_score": 24,
            "bean_passed": False,  # worker is wrong here
            "best_plaintext": pt,
        })
        c = validate_worker_contract(raw, "h5").value
        # Detector fires before the disagreement comparison runs.
        assert c.crib_score == 0
        assert c.bean_passed is False
        assert c.raw_artifacts.get("artifact_class") == "crib_paste"
        # Pre-mutation kernel values preserved for audit.
        snapshot = c.raw_artifacts.get("kernel_verified_before_artifact_filter")
        assert snapshot.get("crib_score") == 24
        assert snapshot.get("bean_passed") is True
        # Worker self-report preserved.
        assert c.worker_self_report["bean_passed"] is False

    def test_ct97_random_text_collapses_inflated_crib_claim(self):
        # 97-char plaintext that is nothing but X's. Worker fabricates
        # crib_score=18. Kernel returns crib_score=0 → overwrite.
        raw = _wrap({
            "hypothesis_id": "h6",
            "status": "success",
            "score": 18.0,
            "crib_score": 18,
            "bean_passed": False,
            "best_plaintext": "X" * 97,
        })
        c = validate_worker_contract(raw, "h6").value
        assert c.crib_score == 0
        assert c.fields_overwritten is True
        assert c.worker_self_report["crib_score"] == 18


# ---------------------------------------------------------------------------
# Theory proposal array extraction (fail-closed)
# ---------------------------------------------------------------------------

class TestTheoryArrayExtraction:
    """Tests for validate_theory_proposals() JSON array extraction.

    The pre-fix code used raw.rfind("]") to find the closing bracket,
    which could cross array boundaries when multiple arrays appeared
    in the output (e.g., SDK repr blocks before the actual JSON).
    """

    def _theory(self, **overrides):
        base = {
            "core_claim": "Test claim",
            "mechanism": "Test mechanism",
            "family": "test_family",
        }
        base.update(overrides)
        return base

    def test_simple_json_array(self):
        raw = json.dumps([self._theory()])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1
        assert report.valid[0].family == "test_family"

    def test_fenced_json_block(self):
        raw = f"Some prose.\n\n```json\n{json.dumps([self._theory()])}\n```\n"
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1

    def test_multiple_arrays_selects_object_array(self):
        """The old rfind(']') bug: two arrays in output, first is a Python
        repr list [ThinkingBlock(...)], second is the actual JSON array.
        The fix must select the JSON array of objects, not cross-pair."""
        decoy = '[1, 2, 3]'
        real = json.dumps([self._theory(family="correct")])
        raw = f"Here is a list: {decoy}\n\nNow the theories:\n{real}\n"
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1
        assert report.valid[0].family == "correct"

    def test_multiple_object_arrays_selects_first(self):
        """When two object arrays appear, select the first one."""
        first = json.dumps([self._theory(family="first")])
        second = json.dumps([self._theory(family="second")])
        raw = f"{first}\n\nAnother array:\n{second}\n"
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1
        assert report.valid[0].family == "first"

    def test_nested_brackets_in_strings(self):
        """Brackets inside JSON string values must not confuse the parser."""
        t = self._theory(core_claim="Test [with brackets] inside")
        raw = json.dumps([t])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1
        assert "[with brackets]" in report.valid[0].core_claim

    def test_python_repr_prefix_skipped(self):
        """[ThinkingBlock(...)] should be skipped (letter after [)."""
        raw = '[ThinkingBlock(type="thinking")]\n' + json.dumps([self._theory()])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1

    def test_no_json_array_returns_error(self):
        raw = "Just some prose with no JSON at all."
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 0
        assert len(report.errors) > 0

    def test_decoy_non_object_array_rejected(self):
        """An array of strings [\"a\", \"b\"] should not be selected;
        only arrays of objects qualify as theory proposals."""
        raw = '["not", "theories"]\n\nNo real theories here.'
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 0

    def test_unmatched_bracket_skipped(self):
        """An opening [ without a matching ] should not crash."""
        raw = "Broken [array without end\n" + json.dumps([self._theory()])
        report = validate_theory_proposals(raw)
        assert len(report.valid) == 1


# ---------------------------------------------------------------------------
# Worker contract nested-field validation
# ---------------------------------------------------------------------------

class TestWorkerContractNestedFields:
    """Tighten validation: list-of-strings, dict for raw_artifacts."""

    def test_disproof_evidence_rejects_list_of_ints(self):
        raw = _wrap({
            "hypothesis_id": "h_nested_1",
            "status": "disproved",
            "disproof_evidence": [1, 2, 3],
        })
        result = validate_worker_contract(raw, "h_nested_1")
        assert not result.ok or any(
            "disproof_evidence" in e for e in (result.errors or [])
        )

    def test_supporting_evidence_rejects_list_of_dicts(self):
        raw = _wrap({
            "hypothesis_id": "h_nested_2",
            "status": "success",
            "supporting_evidence": [{"nested": "dict"}],
        })
        result = validate_worker_contract(raw, "h_nested_2")
        assert not result.ok or any(
            "supporting_evidence" in e for e in (result.errors or [])
        )

    def test_raw_artifacts_rejects_list(self):
        raw = _wrap({
            "hypothesis_id": "h_nested_3",
            "status": "inconclusive",
            "raw_artifacts": ["not", "a", "dict"],
        })
        result = validate_worker_contract(raw, "h_nested_3")
        assert not result.ok or any(
            "raw_artifacts" in e for e in (result.errors or [])
        )

    def test_valid_nested_fields_pass(self):
        raw = _wrap({
            "hypothesis_id": "h_nested_ok",
            "status": "disproved",
            "disproof_evidence": ["evidence string 1", "evidence string 2"],
            "supporting_evidence": [],
            "raw_artifacts": {"key": "value"},
        })
        result = validate_worker_contract(raw, "h_nested_ok")
        assert result.value is not None
