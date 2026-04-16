"""
Tests for kryptosbot.pantheon_siblings.run_stat_audit and the
StatAuditVerdict + alert-gating integration added in Day 5.

Focus: the parsing layer, the verdict dataclass semantics, and the
alert-gating contract that rejected verdicts MUST suppress alerts.
SDK calls are not exercised here — they are async and require a
running Anthropic API.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Bootstrap — kryptosbot lives one level up from tests/, src/ is at repo root
_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.pantheon_siblings import (
    StatAuditVerdict,
    _normalize_stat_audit_dict,
    _build_stat_audit_user_prompt,
    _serialize_contract_for_stat_audit,
)
from kryptosbot.models import TheoryRecord, WorkerContract, WorkerStatus


# ---------------------------------------------------------------------------
# Verdict normalization
# ---------------------------------------------------------------------------

class TestStatAuditVerdictNormalization:

    def test_canonical_verdicts_pass_through(self):
        for v in ("confirmed", "concerned", "rejected"):
            d = {"verdict": v, "confidence": 0.5}
            result = _normalize_stat_audit_dict(d)
            assert result.verdict == v

    def test_tolerant_verdict_aliases(self):
        # Common variations the model might emit.
        cases = {
            "confirm": "confirmed",
            "OK": "confirmed",
            "pass": "confirmed",
            "valid": "confirmed",
            "warn": "concerned",
            "warning": "concerned",
            "review": "concerned",
            "reject": "rejected",
            "fail": "rejected",
            "invalid": "rejected",
            "block": "rejected",
        }
        for raw, expected in cases.items():
            result = _normalize_stat_audit_dict({"verdict": raw})
            assert result.verdict == expected, (raw, expected, result.verdict)

    def test_unknown_verdict_defaults_to_concerned(self):
        # Unknown verdict strings should land on "concerned" — the
        # safe default that allows alerts but flags the contract.
        result = _normalize_stat_audit_dict({"verdict": "wat"})
        assert result.verdict == "concerned"

    def test_confidence_clamped_to_unit_interval(self):
        assert _normalize_stat_audit_dict({"confidence": -0.5}).confidence == 0.0
        assert _normalize_stat_audit_dict({"confidence": 1.5}).confidence == 1.0
        assert _normalize_stat_audit_dict({"confidence": 0.42}).confidence == 0.42

    def test_confidence_invalid_type_defaults_to_half(self):
        result = _normalize_stat_audit_dict({"confidence": "hot"})
        assert result.confidence == 0.5

    def test_methodology_concerns_accepts_string_or_list(self):
        v = _normalize_stat_audit_dict({
            "verdict": "concerned",
            "methodology_concerns": "single string concern",
        })
        assert v.methodology_concerns == ["single string concern"]

        v2 = _normalize_stat_audit_dict({
            "verdict": "rejected",
            "methodology_concerns": ["a", "b", "c"],
        })
        assert v2.methodology_concerns == ["a", "b", "c"]

    def test_alternative_concerns_field_name(self):
        # Tolerate `concerns` as an alias for `methodology_concerns`
        v = _normalize_stat_audit_dict({
            "verdict": "rejected",
            "concerns": ["accepts alias"],
        })
        assert v.methodology_concerns == ["accepts alias"]


# ---------------------------------------------------------------------------
# Alert-gating contract
# ---------------------------------------------------------------------------

class TestStatAuditAlertGating:
    """The core Day 5 invariant: rejected verdicts MUST suppress alerts."""

    def test_should_alert_true_for_confirmed(self):
        v = StatAuditVerdict(verdict="confirmed", confidence=0.9)
        assert v.should_alert is True

    def test_should_alert_true_for_concerned(self):
        v = StatAuditVerdict(verdict="concerned", confidence=0.6)
        assert v.should_alert is True

    def test_should_alert_false_for_rejected(self):
        v = StatAuditVerdict(verdict="rejected", confidence=0.95)
        assert v.should_alert is False

    def test_should_alert_true_for_error(self):
        # Error verdicts must NOT silently suppress alerts. The flaky-
        # auditor case should fall through as if the audit said
        # "concerned" — alert fires, gets recorded, human reviews.
        v = StatAuditVerdict(verdict="error", confidence=0.0)
        assert v.should_alert is True

    def test_log_line_format_includes_marker_and_verdict(self):
        v = StatAuditVerdict(
            verdict="rejected", confidence=0.92,
            methodology_concerns=["multiple-testing burden uncorrected"],
            wall_time_sec=12.3, turn_count=8, tool_count=1,
        )
        line = v.to_log_line("e2784dc990b5")
        assert "✗" in line
        assert "e2784dc9" in line
        assert "rejected" in line
        assert "0.92" in line


# ---------------------------------------------------------------------------
# Prompt building
# ---------------------------------------------------------------------------

class TestStatAuditPromptBuilding:

    def _make_pair(self, **contract_kwargs) -> tuple[TheoryRecord, WorkerContract]:
        t = TheoryRecord(
            title="Boustrophedon tape M4",
            core_claim="finite key tape with serpentine traversal",
            mechanism="K[i] from b(i,L) under SKIP nulls",
            family="key_tape",
        )
        defaults = dict(
            hypothesis_id=t.hypothesis_id,
            status=WorkerStatus.SUCCESS,
            crib_score=24,
            bean_passed=True,
            score=24.0,
            best_plaintext="X" * 97,
            duration_seconds=720.0,
            narrative_summary="boustrophedon tape M4 evaluated",
        )
        defaults.update(contract_kwargs)
        c = WorkerContract(**defaults)
        return t, c

    def test_prompt_contains_kernel_verified_scores(self):
        t, c = self._make_pair()
        prompt = _build_stat_audit_user_prompt(c, t)
        assert "crib_score          : 24 / 24" in prompt
        assert "bean_passed         : True" in prompt
        assert "score               : 24.00" in prompt

    def test_prompt_surfaces_overwrite_signal(self):
        # When the verification fix overrode worker self-report, the
        # auditor should see the discrepancy explicitly — it's diagnostic.
        t, c = self._make_pair(
            crib_score=11,
            bean_passed=False,
            score=11.0,
            fields_overwritten=True,
            worker_self_report={
                "crib_score": 24, "bean_passed": True, "score": 0.0,
            },
            verification_error="length mismatch",
        )
        prompt = _build_stat_audit_user_prompt(c, t)
        assert "fields_overwritten  : True" in prompt
        assert "worker_self_report" in prompt
        assert '"crib_score": 24' in prompt
        assert "length mismatch" in prompt

    def test_long_plaintext_is_truncated(self):
        t, c = self._make_pair(best_plaintext="A" * 500)
        prompt = _build_stat_audit_user_prompt(c, t)
        assert "500 chars total" in prompt
        # The full 500-char filler should NOT be inlined verbatim.
        assert "A" * 400 not in prompt

    def test_serializer_handles_empty_fields_gracefully(self):
        t = TheoryRecord(title="", core_claim="", mechanism="", family="")
        c = WorkerContract(
            hypothesis_id=t.hypothesis_id,
            status=WorkerStatus.INCONCLUSIVE,
        )
        out = _serialize_contract_for_stat_audit(c, t)
        assert out["title"] == "(no title)"
        assert out["family"] == "(no family)"
        assert out["best_plaintext"] == "(empty)"
