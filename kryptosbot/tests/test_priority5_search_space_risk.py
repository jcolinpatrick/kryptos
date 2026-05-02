"""
Tests for Priority 5: structured RedTeamVerdict.search_space_risk field.

Replaces the Day 5 lexicon-based classifier that was falsified by the
Day 6 6x5 verification run. See:
  - memory/project_priority5_search_space_risk_design.md (design spec)
  - memory/feedback_concerned_vs_search_space_risk_separation.md
    (empirical data justifying the replacement)
  - memory/feedback_day7_epistemic_safety_blockers.md (why it blocks Day 7)

Covers:
  1. SEARCH_SPACE_RISK_VALUES enum contents and ordering
  2. _normalize_verdict_dict parses the field across the full taxonomy,
     missing field, unknown values, and PASS-with-risk shape errors
  3. ResearchController._build_risk_warning_block dispatches the correct
     warning block per risk value
  4. _build_worker_prompt reads the verdict directly (no lexicon, no
     _cycle_concern_risk side channel)
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.models import TheoryRecord, WorkerContract, WorkerStatus
from kryptosbot.pantheon_siblings import (
    SEARCH_SPACE_RISK_VALUES,
    RedTeamVerdict,
    _normalize_verdict_dict,
)
from kryptosbot.theory_ledger import TheoryLedger


# ---------------------------------------------------------------------------
# 1. Enum
# ---------------------------------------------------------------------------

class TestSearchSpaceRiskEnum:
    def test_exact_seven_values(self):
        assert set(SEARCH_SPACE_RISK_VALUES) == {
            "none",
            "unbounded_search",
            "exhausted_source_material",
            "underconstrained",
            "duplicate_family",
            "residual_caution",
            "other",
        }

    def test_none_is_present(self):
        assert "none" in SEARCH_SPACE_RISK_VALUES

    def test_default_value_on_redteam_verdict(self):
        v = RedTeamVerdict(verdict="pass", confidence=0.9)
        assert v.search_space_risk == "none"


# ---------------------------------------------------------------------------
# 2. _normalize_verdict_dict
# ---------------------------------------------------------------------------

class TestNormalizeVerdictSearchSpaceRisk:
    @pytest.mark.parametrize("risk", SEARCH_SPACE_RISK_VALUES)
    def test_all_taxonomy_values_round_trip(self, risk):
        # PASS verdicts get their risk coerced to "none"; use "concerned"
        # so arbitrary values round-trip.
        parsed = {
            "verdict": "concerned",
            "confidence": 0.7,
            "reasons": ["test"],
            "search_space_risk": risk,
        }
        v = _normalize_verdict_dict(parsed)
        assert v.search_space_risk == risk

    def test_missing_field_defaults_to_none(self):
        parsed = {"verdict": "concerned", "confidence": 0.7, "reasons": ["test"]}
        v = _normalize_verdict_dict(parsed)
        assert v.search_space_risk == "none"

    def test_unknown_value_becomes_other(self, caplog):
        parsed = {
            "verdict": "concerned",
            "confidence": 0.7,
            "reasons": ["test"],
            "search_space_risk": "narrow_source_space",
        }
        v = _normalize_verdict_dict(parsed)
        assert v.search_space_risk == "other"

    def test_hyphenated_value_is_normalized(self):
        parsed = {
            "verdict": "concerned",
            "confidence": 0.7,
            "reasons": ["test"],
            "search_space_risk": "Unbounded-Search",
        }
        v = _normalize_verdict_dict(parsed)
        assert v.search_space_risk == "unbounded_search"

    def test_pass_with_risk_is_coerced_to_none(self):
        parsed = {
            "verdict": "pass",
            "confidence": 0.9,
            "reasons": [],
            "search_space_risk": "unbounded_search",
        }
        v = _normalize_verdict_dict(parsed)
        assert v.verdict == "pass"
        assert v.search_space_risk == "none"

    def test_reject_with_risk_is_preserved(self):
        parsed = {
            "verdict": "reject",
            "confidence": 0.9,
            "reasons": ["Gronsfeld algebraically eliminated"],
            "search_space_risk": "duplicate_family",
        }
        v = _normalize_verdict_dict(parsed)
        assert v.verdict == "reject"
        assert v.search_space_risk == "duplicate_family"


# ---------------------------------------------------------------------------
# 3. _build_risk_warning_block
# ---------------------------------------------------------------------------

def _make_minimal_controller(tmp_path):
    from kryptosbot.controller import ResearchController, ControllerConfig
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "ledger.sqlite",
    )
    ctrl = ResearchController.__new__(ResearchController)
    ctrl.config = cfg
    ctrl.ledger = TheoryLedger(cfg.ledger_db_path)
    ctrl.state = MagicMock()
    ctrl.state.cycle_number = 10
    ctrl._cycle_redteam_verdicts = {}
    ctrl._cycle_stat_audit_verdicts = {}
    ctrl._cycle_alert_summaries = []
    ctrl._cycle_pursuit_verdicts = {}
    ctrl._cycle_pursuit_leads_opened = []
    return ctrl


class TestRiskWarningBlockDispatch:
    def test_unbounded_search_injects_bounded_search_policy(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        block = ctrl._build_risk_warning_block(
            "unbounded_search",
            "Free parameters with no stated budget.",
            Path("results/worker_scratch/abc123"),
        )
        assert "BOUNDED-SEARCH POLICY" in block
        assert "test_envelope.json" in block
        assert "needs_bounded_design" in block
        assert "Free parameters with no stated budget." in block
        # Confirm the config cap flows through.
        assert str(ctrl.config.bounded_search_max_configurations) in block

    def test_exhausted_source_material_injects_exhaustion_warning(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        block = ctrl._build_risk_warning_block(
            "exhausted_source_material",
            "DESPARATLY misspelling already mined.",
            Path("results/worker_scratch/abc123"),
        )
        assert "EXHAUSTION-OVERLAP WARNING" in block
        assert "duplicate_of_exhausted" in block
        assert "DESPARATLY misspelling already mined." in block
        # Must NOT contain bounded-search machinery.
        assert "BOUNDED-SEARCH POLICY" not in block

    def test_underconstrained_injects_tighten_kill_criterion(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        block = ctrl._build_risk_warning_block(
            "underconstrained",
            "Consistency check is effectively vacuous.",
            Path("results/worker_scratch/abc123"),
        )
        assert "TIGHTEN-KILL-CRITERION WARNING" in block
        assert "pre-register" in block.lower()
        assert "Consistency check is effectively vacuous." in block
        assert "BOUNDED-SEARCH POLICY" not in block
        assert "EXHAUSTION-OVERLAP WARNING" not in block

    @pytest.mark.parametrize("risk", [
        "none",
        "residual_caution",
        "duplicate_family",
        "other",
        "unknown_garbage_value",  # defensive default
    ])
    def test_clean_dispatch_categories_emit_empty_block(self, tmp_path, risk):
        ctrl = _make_minimal_controller(tmp_path)
        block = ctrl._build_risk_warning_block(
            risk,
            "some rationale",
            Path("results/worker_scratch/abc123"),
        )
        assert block == ""


# ---------------------------------------------------------------------------
# 4. _build_worker_prompt reads the verdict, not a side channel
# ---------------------------------------------------------------------------

class TestWorkerPromptReadsVerdict:
    def test_no_verdict_means_clean_prompt(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        theory = TheoryRecord(
            hypothesis_id="abc123", title="t", core_claim="c",
            mechanism="m", family="f", kill_criteria=["k"],
            expected_signal="s",
        )
        prompt = ctrl._build_worker_prompt(theory)
        assert "BOUNDED-SEARCH POLICY" not in prompt
        assert "EXHAUSTION-OVERLAP WARNING" not in prompt
        assert "TIGHTEN-KILL-CRITERION WARNING" not in prompt

    def test_concerned_with_unbounded_search_injects_bounded(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        ctrl._cycle_redteam_verdicts["abc123"] = RedTeamVerdict(
            verdict="concerned",
            confidence=0.7,
            reasons=["Free parameters with no stated budget."],
            search_space_risk="unbounded_search",
        )
        theory = TheoryRecord(
            hypothesis_id="abc123", title="t", core_claim="c",
            mechanism="m", family="f", kill_criteria=["k"],
            expected_signal="s",
        )
        prompt = ctrl._build_worker_prompt(theory)
        assert "BOUNDED-SEARCH POLICY" in prompt
        assert "Free parameters with no stated budget." in prompt

    def test_concerned_with_exhausted_injects_exhaustion(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        ctrl._cycle_redteam_verdicts["abc123"] = RedTeamVerdict(
            verdict="concerned",
            confidence=0.7,
            reasons=["DESPARATLY misspelling already mined."],
            search_space_risk="exhausted_source_material",
        )
        theory = TheoryRecord(
            hypothesis_id="abc123", title="t", core_claim="c",
            mechanism="m", family="f", kill_criteria=["k"],
            expected_signal="s",
        )
        prompt = ctrl._build_worker_prompt(theory)
        assert "EXHAUSTION-OVERLAP WARNING" in prompt
        assert "BOUNDED-SEARCH POLICY" not in prompt

    def test_concerned_with_residual_caution_is_clean(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        ctrl._cycle_redteam_verdicts["abc123"] = RedTeamVerdict(
            verdict="concerned",
            confidence=0.7,
            reasons=["I checked and mod-21 is genuinely different."],
            search_space_risk="residual_caution",
        )
        theory = TheoryRecord(
            hypothesis_id="abc123", title="t", core_claim="c",
            mechanism="m", family="f", kill_criteria=["k"],
            expected_signal="s",
        )
        prompt = ctrl._build_worker_prompt(theory)
        assert "BOUNDED-SEARCH POLICY" not in prompt
        assert "EXHAUSTION-OVERLAP WARNING" not in prompt
        assert "TIGHTEN-KILL-CRITERION WARNING" not in prompt

    def test_concerned_with_duplicate_family_is_clean(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        ctrl._cycle_redteam_verdicts["abc123"] = RedTeamVerdict(
            verdict="concerned",
            confidence=0.7,
            reasons=["Restates Vigenère with mixed CT alphabet."],
            search_space_risk="duplicate_family",
        )
        theory = TheoryRecord(
            hypothesis_id="abc123", title="t", core_claim="c",
            mechanism="m", family="f", kill_criteria=["k"],
            expected_signal="s",
        )
        prompt = ctrl._build_worker_prompt(theory)
        assert "BOUNDED-SEARCH POLICY" not in prompt
        assert "EXHAUSTION-OVERLAP WARNING" not in prompt
        assert "TIGHTEN-KILL-CRITERION WARNING" not in prompt


# ---------------------------------------------------------------------------
# Priority 3: ngram floor in alerts.classify_outcome
# ---------------------------------------------------------------------------
#
# P3 is the second Day 7 blocker alongside P5 — see
# feedback_day7_epistemic_safety_blockers.md. Pair it with D6-FU-7
# (stat-audit downgrade): together they harden against the crib-paste
# fabrication failure mode that surfaced in Day 5 cycle 64.

class TestPriority3NgramFloor:
    def _make_contract(self, plaintext: str) -> WorkerContract:
        return WorkerContract(
            hypothesis_id="hid123",
            status=WorkerStatus.SUCCESS,
            crib_score=24,
            score=24.0,
            bean_passed=True,
            best_plaintext=plaintext,
        )

    def test_real_english_plaintext_fires_breakthrough_when_ngram_passes(self, monkeypatch):
        # High-quality English that includes the K4 cribs. This is the
        # shape a real solution would have: all-English, cribs in place,
        # crib_score=24 with bean_passed. Use the K2 solved plaintext
        # style — proven to score well above the floor.
        from kryptosbot import alerts
        from kryptosbot.alerts import classify_outcome, AlertLevel
        monkeypatch.setattr(alerts, "_ngram_per_char_safe", lambda _pt: -3.0)
        english = (
            "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHE"
            "EARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDAND"
            "TRANSMITTEDUNDERGRUUN"
        )
        assert len(english) >= 97, f"test setup: need >=97 chars, got {len(english)}"
        contract = self._make_contract(english[:97])
        level, _ = classify_outcome(contract, AlertLevel.BREAKTHROUGH)
        assert level == AlertLevel.BREAKTHROUGH

    def test_crib_paste_fabrication_downgrades_to_signal(self, monkeypatch):
        # Crib-paste fabrication: the four crib regions are English,
        # but the rest is random garbage. Hits crib_score=24 and
        # bean_passed=True because the worker lied about both. Ngram
        # per char should be well below the floor.
        from kryptosbot import alerts
        from kryptosbot.alerts import classify_outcome, AlertLevel
        monkeypatch.setattr(alerts, "_ngram_per_char_safe", lambda _pt: -6.0)
        # Build a 97-char string: 20 chars junk, crib1, junk, crib2,
        # trailing junk. "BERLINCLOCK" at 63-73 and "EASTNORTHEAST" at 25-38.
        junk = "QZXJKVWQZXJKVWQZXJK"
        pt = list("Q" * 97)
        for i, ch in enumerate("EASTNORTHEAST", start=25):
            pt[i] = ch
        for i, ch in enumerate("BERLINCLOCK", start=63):
            pt[i] = ch
        fabrication = "".join(pt)
        contract = self._make_contract(fabrication)
        level, _ = classify_outcome(contract, AlertLevel.BREAKTHROUGH)
        # Downgraded — still SIGNAL, not BREAKTHROUGH.
        assert level == AlertLevel.SIGNAL

    def test_ngram_floor_does_not_block_pure_signal_level(self):
        # crib=20, bean=False — never reaches BREAKTHROUGH at all.
        # The ngram floor must not affect SIGNAL classification for
        # contracts that wouldn't have been BREAKTHROUGH anyway.
        from kryptosbot.alerts import classify_outcome, AlertLevel
        contract = WorkerContract(
            hypothesis_id="hid123",
            status=WorkerStatus.SUCCESS,
            crib_score=20,
            score=20.0,
            bean_passed=False,
            best_plaintext="Q" * 97,
        )
        level, _ = classify_outcome(contract, AlertLevel.BREAKTHROUGH)
        assert level == AlertLevel.SIGNAL

    def test_missing_plaintext_fails_down_to_signal(self):
        # If best_plaintext is empty the scorer returns None. A full
        # crib+Bean hit still surfaces, but as SIGNAL rather than
        # BREAKTHROUGH because the ngram floor could not vet it.
        from kryptosbot.alerts import classify_outcome, AlertLevel
        contract = self._make_contract("")
        level, _ = classify_outcome(contract, AlertLevel.BREAKTHROUGH)
        assert level == AlertLevel.SIGNAL


# ---------------------------------------------------------------------------
# 5. Controller-side escalation: CONCERNED+duplicate_family → REJECT
# ---------------------------------------------------------------------------
#
# Added 2026-04-17. The Priority-5 taxonomy defines duplicate_family as
# "the mechanism has been structurally eliminated; re-running under a
# new name would produce the same result." Logically that is a REJECT,
# not a dispatch decision. Pre-2026-04-17 the controller dispatched
# duplicate_family theories anyway; the 2026-04-17 run (cycles 94-102
# and cycle 102 validation) showed each such dispatch burned 3-8 min
# of compute and produced noise as predicted.
#
# This is NOT a lexicon rule — the controller reads the structured
# search_space_risk field emitted by the red-team agent directly.

import asyncio

from kryptosbot.models import TheoryStatus
from kryptosbot.pantheon import AgentSpec


def _make_redteam_roster() -> dict[str, AgentSpec]:
    """Minimal Pantheon roster with a red-team-disprover spec.

    `_red_team_filter` calls `select_redteam(self._pantheon_roster)` and
    then uses `rt_model, _ = resolve_model_for_phase(redteam_spec, "red_team")`.
    We need a real AgentSpec (not MagicMock) so that resolution works.
    """
    return {
        "red-team-disprover": AgentSpec(
            name="red-team-disprover",
            description="test fixture",
            body="adversarial pre-check",
            model="sonnet",
        )
    }


def _make_controller_for_redteam(tmp_path):
    from kryptosbot.controller import ResearchController, ControllerConfig
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "ledger.sqlite",
    )
    ctrl = ResearchController.__new__(ResearchController)
    ctrl.config = cfg
    ctrl.ledger = TheoryLedger(cfg.ledger_db_path)
    ctrl.state = MagicMock()
    ctrl.state.cycle_number = 10
    ctrl._cycle_redteam_verdicts = {}
    ctrl._pantheon_roster = _make_redteam_roster()
    return ctrl


def _make_theory(hid: str, title: str = "test theory") -> TheoryRecord:
    from kryptosbot.models import CriticVerdict, CriticDecision
    theory = TheoryRecord(
        hypothesis_id=hid,
        title=title,
        core_claim="c",
        mechanism="m",
        family="f",
        kill_criteria=["k"],
        expected_signal="s",
    )
    theory.critic_verdict = CriticVerdict(
        decision=CriticDecision.APPROVE,
        confidence=0.95,
        reasons=["prior critic: approved"],
    )
    return theory


def _patch_redteam_call(monkeypatch, verdict_by_hid: dict[str, RedTeamVerdict]):
    """Replace run_red_team_precheck with a lookup against verdict_by_hid."""
    async def _fake_precheck(theory, **_kwargs):
        v = verdict_by_hid.get(theory.hypothesis_id)
        if v is None:
            raise AssertionError(
                f"no verdict stubbed for {theory.hypothesis_id}"
            )
        return v
    monkeypatch.setattr(
        "kryptosbot.controller.run_red_team_precheck",
        _fake_precheck,
    )


class TestDuplicateFamilyAutoRejectInFilter:
    """CONCERNED+duplicate_family must escalate to REJECT before dispatch."""

    def test_concerned_duplicate_family_is_escalated_to_reject(
        self, tmp_path, monkeypatch
    ):
        ctrl = _make_controller_for_redteam(tmp_path)
        t_dup = _make_theory("dup-1", "Wheatstone disk cipher")
        _patch_redteam_call(monkeypatch, {
            "dup-1": RedTeamVerdict(
                verdict="concerned",
                confidence=0.7,
                reasons=["Structurally a stepping polyalphabetic cipher."],
                search_space_risk="duplicate_family",
            ),
        })
        survivors = asyncio.run(ctrl._red_team_filter([t_dup]))
        assert survivors == []
        assert t_dup.status == TheoryStatus.CRITICIZED

    def test_escalated_theory_is_persisted_with_escalation_reason(
        self, tmp_path, monkeypatch
    ):
        ctrl = _make_controller_for_redteam(tmp_path)
        t_dup = _make_theory("dup-2", "Rebranded Vigenère")
        _patch_redteam_call(monkeypatch, {
            "dup-2": RedTeamVerdict(
                verdict="concerned",
                confidence=0.8,
                reasons=["Reduces to Vigenère with mixed alphabet."],
                search_space_risk="duplicate_family",
            ),
        })
        asyncio.run(ctrl._red_team_filter([t_dup]))
        # Ledger should have the downgraded theory with the escalation
        # reason appended to its critic_verdict audit trail.
        reloaded = ctrl.ledger.get_theory("dup-2")
        assert reloaded is not None
        assert reloaded.status == TheoryStatus.CRITICIZED
        assert reloaded.critic_verdict is not None
        reasons_text = " ".join(reloaded.critic_verdict.reasons)
        assert "duplicate_family" in reasons_text
        assert "controller escalated" in reasons_text

    def test_concerned_residual_caution_still_dispatches(
        self, tmp_path, monkeypatch
    ):
        ctrl = _make_controller_for_redteam(tmp_path)
        t_ok = _make_theory("resid-1")
        _patch_redteam_call(monkeypatch, {
            "resid-1": RedTeamVerdict(
                verdict="concerned",
                confidence=0.7,
                reasons=["I checked duplication; this is genuinely novel."],
                search_space_risk="residual_caution",
            ),
        })
        survivors = asyncio.run(ctrl._red_team_filter([t_ok]))
        assert survivors == [t_ok]
        assert t_ok.status != TheoryStatus.CRITICIZED

    def test_concerned_unbounded_search_is_escalated_to_reject(
        self, tmp_path, monkeypatch
    ):
        """2026-04-30 policy change: unbounded_search now escalates.

        Live-run audit (cycles 176-250) found unbounded_search verdicts
        repeatedly dispatched anyway and consumed 5-7 minute long-sweep
        slots producing noise. Escalation now matches duplicate_family.
        """
        ctrl = _make_controller_for_redteam(tmp_path)
        t_unb = _make_theory("unb-1")
        _patch_redteam_call(monkeypatch, {
            "unb-1": RedTeamVerdict(
                verdict="concerned",
                confidence=0.7,
                reasons=["Free parameters with no stated budget."],
                search_space_risk="unbounded_search",
            ),
        })
        survivors = asyncio.run(ctrl._red_team_filter([t_unb]))
        assert survivors == []
        assert t_unb.status == TheoryStatus.CRITICIZED
        reloaded = ctrl.ledger.get_theory("unb-1")
        reasons_text = " ".join(reloaded.critic_verdict.reasons)
        assert "unbounded_search" in reasons_text
        assert "controller escalated" in reasons_text

    def test_concerned_exhausted_source_material_is_escalated_to_reject(
        self, tmp_path, monkeypatch
    ):
        """2026-04-30: exhausted_source_material also escalates.

        The CT-perturbation v4→v7 pivot loop in cycles 176-250 was the
        canonical example: red-team flagged exhausted_source_material
        on every cycle, controller dispatched anyway, all produced 0/24.
        """
        ctrl = _make_controller_for_redteam(tmp_path)
        t_exh = _make_theory("exh-1")
        _patch_redteam_call(monkeypatch, {
            "exh-1": RedTeamVerdict(
                verdict="concerned",
                confidence=0.7,
                reasons=["Source anomaly already exhausted by prior scripts."],
                search_space_risk="exhausted_source_material",
            ),
        })
        survivors = asyncio.run(ctrl._red_team_filter([t_exh]))
        assert survivors == []
        assert t_exh.status == TheoryStatus.CRITICIZED
        reloaded = ctrl.ledger.get_theory("exh-1")
        reasons_text = " ".join(reloaded.critic_verdict.reasons)
        assert "exhausted_source_material" in reasons_text

    def test_concerned_underconstrained_still_dispatches(
        self, tmp_path, monkeypatch
    ):
        """underconstrained is borderline (kill criteria vacuous), worker
        gets a prompt-side note and still runs. Distinguishes 'risky but
        could yield' from 'logically rejected'."""
        ctrl = _make_controller_for_redteam(tmp_path)
        t_und = _make_theory("und-1")
        _patch_redteam_call(monkeypatch, {
            "und-1": RedTeamVerdict(
                verdict="concerned",
                confidence=0.7,
                reasons=["Kill criterion is effectively vacuous."],
                search_space_risk="underconstrained",
            ),
        })
        survivors = asyncio.run(ctrl._red_team_filter([t_und]))
        assert set(s.hypothesis_id for s in survivors) == {"und-1"}

    def test_reject_verdict_still_downgrades_regardless_of_risk(
        self, tmp_path, monkeypatch
    ):
        # Baseline: the existing verdict="reject" path must still
        # downgrade the theory. The new escalation code must not
        # short-circuit or conflict with explicit rejects.
        ctrl = _make_controller_for_redteam(tmp_path)
        t_rej = _make_theory("rej-1")
        _patch_redteam_call(monkeypatch, {
            "rej-1": RedTeamVerdict(
                verdict="reject",
                confidence=0.9,
                reasons=["Relies on CONSENSUS_NULL_POSITIONS."],
                search_space_risk="duplicate_family",
            ),
        })
        survivors = asyncio.run(ctrl._red_team_filter([t_rej]))
        assert survivors == []
        assert t_rej.status == TheoryStatus.CRITICIZED
        # The explicit-reject path should be the one that fired (not
        # the new escalation path). Check by ensuring the reason trail
        # does NOT contain the escalation-specific string.
        reloaded = ctrl.ledger.get_theory("rej-1")
        assert reloaded is not None
        reasons_text = " ".join(reloaded.critic_verdict.reasons)
        assert "controller escalated" not in reasons_text

    def test_pass_verdict_unchanged(self, tmp_path, monkeypatch):
        ctrl = _make_controller_for_redteam(tmp_path)
        t_pass = _make_theory("pass-1")
        _patch_redteam_call(monkeypatch, {
            "pass-1": RedTeamVerdict(
                verdict="pass",
                confidence=0.9,
                reasons=["Bounded search, novel mechanism."],
                search_space_risk="none",
            ),
        })
        survivors = asyncio.run(ctrl._red_team_filter([t_pass]))
        assert survivors == [t_pass]
        assert t_pass.status != TheoryStatus.CRITICIZED

    def test_taxonomy_docstring_documents_auto_reject_policy(self):
        """The red-team agent's taxonomy docstring must explain the
        auto-reject policy, so the agent can decide between
        duplicate_family (escalates) and residual_caution (dispatches)
        correctly. Without this block the agent would have no way to
        know its duplicate_family tags trigger rejection.
        """
        from kryptosbot.pantheon import _REDTEAM_PRECHECK_PREFACE
        assert "duplicate_family" in _REDTEAM_PRECHECK_PREFACE
        assert "AUTO-REJECT POLICY" in _REDTEAM_PRECHECK_PREFACE
        assert "2026-04-17" in _REDTEAM_PRECHECK_PREFACE
