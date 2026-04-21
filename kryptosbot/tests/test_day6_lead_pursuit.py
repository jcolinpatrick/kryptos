"""
Tests for Day 6 of the Pantheon integration.

Covers:
  P1  — bounded_search_max_configurations ControllerConfig field flows
        into _build_worker_prompt when a CONCERNED theory is dispatched.
  P2  — Lead-pursuit plumbing:
          - PursuitLead dataclass round-trip
          - pursuit_leads ledger schema + CRUD (insert, get_open,
            close, auto_close_stale, count_by_status)
          - PursuitVerdict normalization (pursue/skip/alias paths)
          - _close_referenced_pursuit_leads closes by tag convention
          - _render_pursuit_leads_for_prompt surfaces open leads and
            omits (none) when empty
          - get_open_pursuit_leads is picked up in _assess_landscape
            output
  P4  — CycleSynthesis.budget_risky_count is wired into the synthesis
        formatter and landscape block.
  P6  — Stat-audit REJECTED verdict downgrades PROMISING → COMPLETED
        and annotates failure_reason.
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
    PursuitLead, PursuitLeadStatus,
)
from kryptosbot.pantheon_siblings import RedTeamVerdict
from kryptosbot.theory_ledger import TheoryLedger


def _concerned_verdict(risk: str, reason: str) -> RedTeamVerdict:
    """Build a CONCERNED RedTeamVerdict with a Priority-5 risk value."""
    return RedTeamVerdict(
        verdict="concerned",
        confidence=0.7,
        reasons=[reason],
        search_space_risk=risk,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_minimal_controller(tmp_path):
    """Bypass __init__ so tests don't need a real roster / DB / tools."""
    from kryptosbot.controller import ResearchController, ControllerConfig
    cfg = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "ledger.sqlite",
    )
    ctrl = ResearchController.__new__(ResearchController)
    ctrl.config = cfg
    ctrl.ledger = TheoryLedger(cfg.ledger_db_path)
    ctrl.state = MagicMock()
    ctrl.state.recent_outcomes = []
    ctrl.state.cycle_number = 10
    ctrl._cycle_redteam_verdicts = {}
    ctrl._cycle_stat_audit_verdicts = {}
    ctrl._cycle_alert_summaries = []
    ctrl._cycle_pursuit_verdicts = {}
    ctrl._cycle_pursuit_leads_opened = []
    return ctrl


# ---------------------------------------------------------------------------
# P1: bounded_search_max_configurations flows into worker prompt
# ---------------------------------------------------------------------------

class TestBoundedSearchConfigField:
    def test_default_value_renders_in_prompt(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        ctrl._cycle_redteam_verdicts["abc123"] = _concerned_verdict(
            "unbounded_search",
            "Free parameters with no stated budget.",
        )
        theory = TheoryRecord(
            hypothesis_id="abc123", title="t", core_claim="c",
            mechanism="m", family="f", kill_criteria=["k"],
            expected_signal="s",
        )
        prompt = ctrl._build_worker_prompt(theory)
        # Default is 5000
        assert "5000" in prompt
        assert "BOUNDED-SEARCH POLICY" in prompt

    def test_custom_value_overrides_hardcode(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        ctrl.config.bounded_search_max_configurations = 250
        ctrl._cycle_redteam_verdicts["abc123"] = _concerned_verdict(
            "unbounded_search", "Free parameters.",
        )
        theory = TheoryRecord(
            hypothesis_id="abc123", title="t", core_claim="c",
            mechanism="m", family="f", kill_criteria=["k"],
            expected_signal="s",
        )
        prompt = ctrl._build_worker_prompt(theory)
        assert "250" in prompt
        # The old hardcoded literal must NOT appear when the custom
        # cap is used.
        assert "exceeds 5000" not in prompt


# ---------------------------------------------------------------------------
# P2: PursuitLead dataclass + ledger CRUD
# ---------------------------------------------------------------------------

class TestPursuitLeadDataclass:
    def test_round_trip_to_dict(self):
        lead = PursuitLead(
            lead_id="pl-abc-c5",
            source_theory_id="abcdef123456",
            source_cycle=5,
            crib_score=12,
            rationale="because",
            suggested_variants=["try width 11", "swap Beaufort"],
            status=PursuitLeadStatus.OPEN,
        )
        d = lead.to_dict()
        assert d["status"] == "open"
        assert d["suggested_variants"] == ["try width 11", "swap Beaufort"]
        reloaded = PursuitLead.from_dict(d)
        assert reloaded.status == PursuitLeadStatus.OPEN
        assert reloaded.lead_id == "pl-abc-c5"


class TestPursuitLeadsLedger:
    def test_insert_get_and_status_count(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        lead = PursuitLead(
            lead_id="pl-1", source_theory_id="t1", source_cycle=1,
            crib_score=10, rationale="r1",
            suggested_variants=["v1"], status=PursuitLeadStatus.OPEN,
        )
        ledger.insert_pursuit_lead(lead)
        got = ledger.get_pursuit_lead("pl-1")
        assert got is not None
        assert got.source_theory_id == "t1"
        assert got.crib_score == 10
        assert got.suggested_variants == ["v1"]
        open_leads = ledger.get_open_pursuit_leads(limit=10)
        assert len(open_leads) == 1
        counts = ledger.count_pursuit_leads_by_status()
        assert counts.get("open") == 1

    def test_close_pursued(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        ledger.insert_pursuit_lead(PursuitLead(
            lead_id="pl-2", source_theory_id="t2", source_cycle=2,
            crib_score=8, status=PursuitLeadStatus.OPEN,
        ))
        ledger.close_pursuit_lead(
            "pl-2",
            status=PursuitLeadStatus.PURSUED,
            closed_cycle=3,
        )
        got = ledger.get_pursuit_lead("pl-2")
        assert got.status == PursuitLeadStatus.PURSUED
        assert got.closed_cycle == 3
        # OPEN list should now be empty
        assert ledger.get_open_pursuit_leads() == []

    def test_close_open_status_rejected(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        ledger.insert_pursuit_lead(PursuitLead(
            lead_id="pl-3", source_theory_id="t3", source_cycle=1,
            crib_score=7, status=PursuitLeadStatus.OPEN,
        ))
        with pytest.raises(ValueError):
            ledger.close_pursuit_lead(
                "pl-3",
                status=PursuitLeadStatus.OPEN,
                closed_cycle=2,
            )

    def test_auto_close_stale(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        for i, cyc in enumerate([1, 2, 5, 8]):
            ledger.insert_pursuit_lead(PursuitLead(
                lead_id=f"pl-{i}",
                source_theory_id=f"t{i}",
                source_cycle=cyc,
                crib_score=10,
                status=PursuitLeadStatus.OPEN,
            ))
        # current_cycle=10, stale_after=3 → close leads opened at <= 7
        closed = ledger.auto_close_stale_pursuit_leads(
            current_cycle=10, stale_after_cycles=3,
        )
        assert set(closed) == {"pl-0", "pl-1", "pl-2"}
        # pl-3 (cycle 8) should still be OPEN
        assert ledger.get_pursuit_lead("pl-3").status == PursuitLeadStatus.OPEN
        # closed ones should now be STALE
        for lid in closed:
            assert ledger.get_pursuit_lead(lid).status == PursuitLeadStatus.STALE

    def test_auto_close_disabled_with_zero(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        ledger.insert_pursuit_lead(PursuitLead(
            lead_id="pl-z", source_theory_id="t", source_cycle=1,
            crib_score=10, status=PursuitLeadStatus.OPEN,
        ))
        closed = ledger.auto_close_stale_pursuit_leads(
            current_cycle=100, stale_after_cycles=0,
        )
        assert closed == []
        assert ledger.get_pursuit_lead("pl-z").status == PursuitLeadStatus.OPEN


# ---------------------------------------------------------------------------
# PursuitVerdict normalization
# ---------------------------------------------------------------------------

class TestPursuitVerdictNormalization:
    def test_pursue_path(self):
        from kryptosbot.pantheon_siblings import _normalize_pursuit_dict
        v = _normalize_pursuit_dict({
            "verdict": "pursue",
            "confidence": 0.8,
            "rationale": "worth it",
            "suggested_variants": ["a", "b", "c", "d"],
        })
        assert v.verdict == "pursue"
        assert v.worth_pursuing is True
        # At-most-3 cap
        assert len(v.suggested_variants) == 3

    def test_skip_alias_yes_becomes_pursue(self):
        from kryptosbot.pantheon_siblings import _normalize_pursuit_dict
        v = _normalize_pursuit_dict({"verdict": "yes"})
        assert v.verdict == "pursue"

    def test_unknown_defaults_to_skip(self):
        from kryptosbot.pantheon_siblings import _normalize_pursuit_dict
        v = _normalize_pursuit_dict({"verdict": "lol"})
        assert v.verdict == "skip"
        assert v.worth_pursuing is False

    def test_confidence_clamped(self):
        from kryptosbot.pantheon_siblings import _normalize_pursuit_dict
        high = _normalize_pursuit_dict({"verdict": "pursue", "confidence": 99})
        assert high.confidence == 1.0
        low = _normalize_pursuit_dict({"verdict": "pursue", "confidence": -1})
        assert low.confidence == 0.0

    def test_rationale_trimmed_to_500(self):
        from kryptosbot.pantheon_siblings import _normalize_pursuit_dict
        v = _normalize_pursuit_dict({
            "verdict": "pursue",
            "rationale": "x" * 2000,
        })
        assert len(v.rationale) == 500


# ---------------------------------------------------------------------------
# _close_referenced_pursuit_leads
# ---------------------------------------------------------------------------

class TestCloseReferencedLeads:
    def test_tagged_theory_closes_lead(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        lead = PursuitLead(
            lead_id="pl-close-1", source_theory_id="src", source_cycle=5,
            crib_score=10, status=PursuitLeadStatus.OPEN,
        )
        ctrl.ledger.insert_pursuit_lead(lead)

        approved = [
            TheoryRecord(
                hypothesis_id="follower1", title="variant",
                core_claim="c", mechanism="m", family="f",
                tags=["pursuit_lead:pl-close-1", "other"],
            )
        ]
        ctrl._close_referenced_pursuit_leads(approved)

        reloaded = ctrl.ledger.get_pursuit_lead("pl-close-1")
        assert reloaded.status == PursuitLeadStatus.PURSUED
        assert reloaded.closed_cycle == ctrl.state.cycle_number

    def test_untagged_theory_does_not_close(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        ctrl.ledger.insert_pursuit_lead(PursuitLead(
            lead_id="pl-untouched", source_theory_id="src", source_cycle=5,
            crib_score=10, status=PursuitLeadStatus.OPEN,
        ))
        approved = [
            TheoryRecord(
                hypothesis_id="unrelated", title="t", core_claim="c",
                mechanism="m", family="f",
                tags=["noise", "crib_analysis"],
            )
        ]
        ctrl._close_referenced_pursuit_leads(approved)
        assert ctrl.ledger.get_pursuit_lead("pl-untouched").status == PursuitLeadStatus.OPEN

    def test_reference_to_already_closed_lead_is_noop(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        ctrl.ledger.insert_pursuit_lead(PursuitLead(
            lead_id="pl-already", source_theory_id="src", source_cycle=5,
            crib_score=10, status=PursuitLeadStatus.OPEN,
        ))
        ctrl.ledger.close_pursuit_lead(
            "pl-already",
            status=PursuitLeadStatus.STALE,
            closed_cycle=7,
        )
        approved = [
            TheoryRecord(
                hypothesis_id="t", title="t", core_claim="c",
                mechanism="m", family="f",
                tags=["pursuit_lead:pl-already"],
            )
        ]
        # Must not raise and must not revive a stale lead
        ctrl._close_referenced_pursuit_leads(approved)
        assert ctrl.ledger.get_pursuit_lead("pl-already").status == PursuitLeadStatus.STALE


# ---------------------------------------------------------------------------
# Landscape / theorist prompt integration
# ---------------------------------------------------------------------------

class TestPursuitLeadsPromptRendering:
    def test_empty_block_shows_none_open(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        block = ctrl._render_pursuit_leads_for_prompt([])
        assert "PRIORITY PURSUIT LEADS" in block
        assert "(none open)" in block

    def test_populated_block_lists_leads_and_variants(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        leads = [
            {
                "lead_id": "pl-x",
                "source_theory_id": "abcdef123456",
                "source_cycle": 42,
                "crib_score": 8,
                "rationale": "worker identified width 11 as next step",
                "suggested_variants": ["try width 11", "swap Beaufort"],
            }
        ]
        block = ctrl._render_pursuit_leads_for_prompt(leads)
        assert "pl-x" in block
        assert "width 11" in block
        assert "opened_in_cycle=42" in block
        assert "pursuit_lead:<lead_id>" in block  # tag convention hint

    def test_safe_get_open_leads_returns_empty_on_error(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        ctrl.ledger = MagicMock()
        ctrl.ledger.get_open_pursuit_leads.side_effect = RuntimeError("boom")
        assert ctrl._safe_get_open_pursuit_leads() == []


# ---------------------------------------------------------------------------
# Soft pursuit leads: skip-with-variants preservation
# ---------------------------------------------------------------------------

class TestSoftPursuitLeads:
    """Verify that SKIP verdicts with non-empty suggested_variants are
    persisted as soft pursuit leads (source_verdict='skip_variants')
    rather than being discarded at the cycle boundary.

    Closes the information leak where cycle N's evaluator suggestions
    never reach cycle N+1's theorist prompt.
    """

    def test_pursuit_lead_default_source_verdict_is_pursue(self):
        lead = PursuitLead(lead_id="x", source_theory_id="t", source_cycle=1)
        assert lead.source_verdict == "pursue"

    def test_pursuit_lead_from_dict_rejects_unknown_source_verdict(self):
        d = {
            "lead_id": "x",
            "source_theory_id": "t",
            "source_cycle": 1,
            "status": "open",
            "source_verdict": "not-a-real-value",
        }
        lead = PursuitLead.from_dict(d)
        assert lead.source_verdict == "pursue"

    def test_ledger_round_trips_soft_lead(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        lead = PursuitLead(
            lead_id="pls-1", source_theory_id="t1", source_cycle=1,
            crib_score=6, rationale="skip, but try width 23",
            suggested_variants=["width 23", "ABSCISSA substring"],
            status=PursuitLeadStatus.OPEN,
            source_verdict="skip_variants",
        )
        ledger.insert_pursuit_lead(lead)
        got = ledger.get_pursuit_lead("pls-1")
        assert got is not None
        assert got.source_verdict == "skip_variants"
        assert got.suggested_variants == ["width 23", "ABSCISSA substring"]

    def test_ledger_insert_normalizes_unknown_source_verdict(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        ledger.insert_pursuit_lead(PursuitLead(
            lead_id="pl-bad-insert", source_theory_id="t1", source_cycle=1,
            crib_score=6, status=PursuitLeadStatus.OPEN,
            source_verdict="not-a-real-value",
        ))
        got = ledger.get_pursuit_lead("pl-bad-insert")
        assert got is not None
        assert got.source_verdict == "pursue"

    def test_ledger_load_normalizes_corrupt_source_verdict_row(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        with ledger._connect() as conn:
            conn.execute(
                """
                INSERT INTO pursuit_leads (
                    lead_id, source_theory_id, source_cycle, crib_score,
                    rationale, suggested_variants, status, source_verdict,
                    opened_at, closed_at, closed_cycle
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "pl-corrupt-row", "t1", 1, 6,
                    "", "[]", "open", "corrupt-value",
                    "2026-01-01T00:00:00+00:00", "", None,
                ),
            )
        got = ledger.get_pursuit_lead("pl-corrupt-row")
        assert got is not None
        assert got.source_verdict == "pursue"

    def test_get_open_pursuit_leads_filter_separates_hard_and_soft(self, tmp_path):
        ledger = TheoryLedger(tmp_path / "ledger.sqlite")
        ledger.insert_pursuit_lead(PursuitLead(
            lead_id="pl-hard-1", source_theory_id="t1", source_cycle=1,
            crib_score=10, status=PursuitLeadStatus.OPEN,
            source_verdict="pursue",
        ))
        ledger.insert_pursuit_lead(PursuitLead(
            lead_id="pls-soft-1", source_theory_id="t2", source_cycle=1,
            crib_score=6, status=PursuitLeadStatus.OPEN,
            source_verdict="skip_variants",
            suggested_variants=["v"],
        ))
        hard = ledger.get_open_pursuit_leads(source_verdict="pursue")
        soft = ledger.get_open_pursuit_leads(source_verdict="skip_variants")
        all_open = ledger.get_open_pursuit_leads()
        assert [l.lead_id for l in hard] == ["pl-hard-1"]
        assert [l.lead_id for l in soft] == ["pls-soft-1"]
        assert {l.lead_id for l in all_open} == {"pl-hard-1", "pls-soft-1"}

    def test_open_pursuit_lead_from_verdict_writes_soft_lead(self, tmp_path):
        from kryptosbot.pantheon_siblings import PursuitVerdict
        ctrl = _make_minimal_controller(tmp_path)
        contract = WorkerContract(
            hypothesis_id="abc123def456",
            status=WorkerStatus.DISPROVED,
            crib_score=6,
        )
        verdict = PursuitVerdict(
            verdict="skip",
            confidence=0.87,
            rationale="near-noise, but three specific variants worth noting",
            suggested_variants=["width 23 variant", "ABSCISSA substring"],
        )
        ctrl._open_pursuit_lead_from_verdict(
            contract=contract,
            verdict=verdict,
            source_verdict="skip_variants",
            lead_id_prefix="pls-",
        )
        soft = ctrl.ledger.get_open_pursuit_leads(source_verdict="skip_variants")
        assert len(soft) == 1
        assert soft[0].source_verdict == "skip_variants"
        assert soft[0].suggested_variants == [
            "width 23 variant", "ABSCISSA substring",
        ]
        assert soft[0].lead_id.startswith("pls-")

    def test_rendering_two_sections_when_both_present(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        hard = [{
            "lead_id": "pl-hard", "source_theory_id": "aaa11111",
            "source_cycle": 5, "crib_score": 10,
            "rationale": "worth pursuing",
            "suggested_variants": ["do X"],
        }]
        soft = [{
            "lead_id": "pls-soft", "source_theory_id": "bbb22222",
            "source_cycle": 6, "crib_score": 6,
            "rationale": "skip parent, nearby variant",
            "suggested_variants": ["try width 23", "swap read order"],
        }]
        block = ctrl._render_pursuit_leads_for_prompt(hard, soft)
        assert "PRIORITY PURSUIT LEADS" in block
        assert "SOFT PURSUIT LEADS" in block
        assert "pl-hard" in block
        assert "pls-soft" in block
        assert "try width 23" in block
        # SOFT section appears after the hard section
        assert block.index("PRIORITY PURSUIT LEADS") < block.index("SOFT PURSUIT LEADS")

    def test_rendering_soft_section_absent_when_empty(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        hard = [{
            "lead_id": "pl-only", "source_theory_id": "aaa",
            "source_cycle": 5, "crib_score": 10, "rationale": "r",
            "suggested_variants": [],
        }]
        block = ctrl._render_pursuit_leads_for_prompt(hard, [])
        assert "PRIORITY PURSUIT LEADS" in block
        assert "SOFT PURSUIT LEADS" not in block

    def test_landscape_fetches_hard_and_soft_separately(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        ctrl.config.soft_pursuit_leads_prompt_cap = 3
        ctrl.ledger.insert_pursuit_lead(PursuitLead(
            lead_id="pl-a", source_theory_id="t1", source_cycle=1,
            crib_score=10, status=PursuitLeadStatus.OPEN,
            source_verdict="pursue", rationale="hard",
        ))
        ctrl.ledger.insert_pursuit_lead(PursuitLead(
            lead_id="pls-b", source_theory_id="t2", source_cycle=1,
            crib_score=6, status=PursuitLeadStatus.OPEN,
            source_verdict="skip_variants", rationale="soft",
            suggested_variants=["v1"],
        ))
        hard = ctrl._safe_get_open_pursuit_leads(source_verdict="pursue")
        soft = ctrl._safe_get_open_pursuit_leads(source_verdict="skip_variants")
        assert [l.lead_id for l in hard] == ["pl-a"]
        assert [l.lead_id for l in soft] == ["pls-b"]

    def test_close_referenced_closes_soft_lead_by_tag(self, tmp_path):
        """Tag-based closure must work for soft leads too."""
        ctrl = _make_minimal_controller(tmp_path)
        ctrl.ledger.insert_pursuit_lead(PursuitLead(
            lead_id="pls-close-me", source_theory_id="src",
            source_cycle=5, crib_score=6,
            status=PursuitLeadStatus.OPEN,
            source_verdict="skip_variants",
            suggested_variants=["v"],
        ))
        approved = [
            TheoryRecord(
                hypothesis_id="variant-follower", title="v",
                core_claim="c", mechanism="m", family="f",
                tags=["pursuit_lead:pls-close-me"],
            )
        ]
        ctrl._close_referenced_pursuit_leads(approved)
        reloaded = ctrl.ledger.get_pursuit_lead("pls-close-me")
        assert reloaded.status == PursuitLeadStatus.PURSUED

    def test_migration_adds_source_verdict_column_to_existing_db(self, tmp_path):
        """Pre-existing DBs without the column must gain it on init,
        with rows defaulting to 'pursue' (historical semantics)."""
        import sqlite3
        db_path = tmp_path / "ledger.sqlite"
        # Simulate pre-migration state: create only the old schema.
        conn = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
            CREATE TABLE pursuit_leads (
                lead_id TEXT PRIMARY KEY,
                source_theory_id TEXT NOT NULL,
                source_cycle INTEGER NOT NULL,
                crib_score INTEGER NOT NULL,
                rationale TEXT NOT NULL DEFAULT '',
                suggested_variants TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'open',
                opened_at TEXT NOT NULL,
                closed_at TEXT NOT NULL DEFAULT '',
                closed_cycle INTEGER
            );
        """)
        conn.execute(
            "INSERT INTO pursuit_leads "
            "(lead_id, source_theory_id, source_cycle, crib_score, opened_at) "
            "VALUES (?, ?, ?, ?, ?)",
            ("pl-legacy", "t", 1, 10, "2026-01-01T00:00:00+00:00"),
        )
        conn.commit()
        conn.close()

        # Now open via TheoryLedger — migration should run.
        ledger = TheoryLedger(db_path)
        lead = ledger.get_pursuit_lead("pl-legacy")
        assert lead is not None
        assert lead.source_verdict == "pursue"


# ---------------------------------------------------------------------------
# P4 (rewritten under Priority 5): CycleSynthesis.risk_breakdown
# ---------------------------------------------------------------------------

class TestSynthesisRiskBreakdown:
    def test_dataclass_default_is_empty_dict(self):
        from kryptosbot.pantheon_siblings import CycleSynthesis
        s = CycleSynthesis()
        assert s.risk_breakdown == {}

    def test_landscape_block_shows_risk_breakdown_when_present(self):
        from kryptosbot.pantheon_siblings import CycleSynthesis
        s = CycleSynthesis(
            headline="test",
            recommended_next_focus="shift",
            risk_breakdown={
                "unbounded_search": 2,
                "exhausted_source_material": 1,
                "none": 7,  # must be suppressed
            },
        )
        block = s.to_landscape_block()
        assert "risk-flagged dispatches" in block
        assert "unbounded_search=2" in block
        assert "exhausted_source_material=1" in block
        # "none" is not a risk and must not appear
        assert "none=" not in block

    def test_landscape_block_hides_when_empty(self):
        from kryptosbot.pantheon_siblings import CycleSynthesis
        s = CycleSynthesis(
            headline="test",
            recommended_next_focus="shift",
            risk_breakdown={},
        )
        block = s.to_landscape_block()
        assert "risk-flagged" not in block

    def test_landscape_block_hides_when_only_none_bucket(self):
        from kryptosbot.pantheon_siblings import CycleSynthesis
        s = CycleSynthesis(
            headline="test",
            recommended_next_focus="shift",
            risk_breakdown={"none": 5},
        )
        block = s.to_landscape_block()
        assert "risk-flagged" not in block

    def test_format_risk_breakdown_helper(self):
        from kryptosbot.pantheon_siblings import (
            _format_risk_breakdown_for_synthesis,
        )
        inline, block, breakdown = _format_risk_breakdown_for_synthesis({
            "abcdef123456": ("unbounded_search", "Free parameters."),
            "fedcba654321": ("exhausted_source_material", "Already mined."),
        })
        assert breakdown == {
            "unbounded_search": 1,
            "exhausted_source_material": 1,
        }
        assert "unbounded_search=1" in inline
        assert "exhausted_source_material=1" in inline
        assert "abcdef12" in block
        assert "fedcba65" in block

    def test_format_risk_breakdown_helper_empty(self):
        from kryptosbot.pantheon_siblings import (
            _format_risk_breakdown_for_synthesis,
        )
        inline, block, breakdown = _format_risk_breakdown_for_synthesis({})
        assert breakdown == {}
        assert inline == "none=0"
        assert "no risk-flagged" in block

    def test_format_risk_breakdown_helper_skips_none_bucket(self):
        from kryptosbot.pantheon_siblings import (
            _format_risk_breakdown_for_synthesis,
        )
        # A "none" entry should not make it into the breakdown — only
        # dispatched theories with an actual risk should be passed in,
        # but the helper defends against a stray "none" just in case.
        inline, block, breakdown = _format_risk_breakdown_for_synthesis({
            "a" * 12: ("none", "cleared"),
        })
        assert breakdown == {}


# ---------------------------------------------------------------------------
# P6 / D6-FU-7: stat-audit REJECTED downgrades theory.status
# ---------------------------------------------------------------------------

class TestStatAuditDowngradesPromising:
    def test_promising_gets_downgraded(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        theory = TheoryRecord(
            hypothesis_id="fakebreak", title="crib-paste fabrication",
            core_claim="c", mechanism="m", family="f",
            status=TheoryStatus.PROMISING,
        )
        ctrl.ledger.upsert_theory(theory)

        # Stub stat-audit verdict
        from kryptosbot.pantheon_siblings import StatAuditVerdict
        ctrl._cycle_stat_audit_verdicts["fakebreak"] = StatAuditVerdict(
            verdict="rejected",
            confidence=0.97,
            methodology_concerns=["crib-pasting fingerprint detected"],
        )

        contract = WorkerContract(
            hypothesis_id="fakebreak",
            status=WorkerStatus.SUCCESS,
            crib_score=24,
            score=24.0,
            bean_passed=True,
            best_plaintext="A" * 97,
        )

        ctrl._run_alerts([theory], [contract])

        reloaded = ctrl.ledger.get_theory("fakebreak")
        assert reloaded.status == TheoryStatus.COMPLETED
        assert "stat-audit rejected" in reloaded.failure_reason

    def test_promising_gets_downgraded_when_alerts_disabled(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        ctrl.config.alert_threshold = "none"
        theory = TheoryRecord(
            hypothesis_id="noalertfake", title="crib-paste fabrication",
            core_claim="c", mechanism="m", family="f",
            status=TheoryStatus.PROMISING,
        )
        ctrl.ledger.upsert_theory(theory)

        from kryptosbot.pantheon_siblings import StatAuditVerdict
        ctrl._cycle_stat_audit_verdicts["noalertfake"] = StatAuditVerdict(
            verdict="rejected",
            confidence=0.97,
            methodology_concerns=["crib-pasting fingerprint detected"],
        )

        contract = WorkerContract(
            hypothesis_id="noalertfake",
            status=WorkerStatus.SUCCESS,
            crib_score=24,
            score=24.0,
            bean_passed=True,
            best_plaintext="A" * 97,
        )

        ctrl._run_alerts([theory], [contract])

        reloaded = ctrl.ledger.get_theory("noalertfake")
        assert reloaded.status == TheoryStatus.COMPLETED
        assert "stat-audit rejected" in reloaded.failure_reason

    def test_non_rejected_does_not_downgrade(self, tmp_path):
        ctrl = _make_minimal_controller(tmp_path)
        theory = TheoryRecord(
            hypothesis_id="realsig", title="real signal",
            core_claim="c", mechanism="m", family="f",
            status=TheoryStatus.PROMISING,
        )
        ctrl.ledger.upsert_theory(theory)

        from kryptosbot.pantheon_siblings import StatAuditVerdict
        ctrl._cycle_stat_audit_verdicts["realsig"] = StatAuditVerdict(
            verdict="confirmed",
            confidence=0.9,
        )

        contract = WorkerContract(
            hypothesis_id="realsig",
            status=WorkerStatus.SUCCESS,
            crib_score=22,
            score=22.0,
            bean_passed=False,
            best_plaintext="B" * 97,
        )

        ctrl._run_alerts([theory], [contract])
        reloaded = ctrl.ledger.get_theory("realsig")
        assert reloaded.status == TheoryStatus.PROMISING
