"""Tests for ResearchController._truncate_blocked_families and
_write_cycle_escape_summary.

Covers truncation cap, streak increment/reset semantics, and per-EscapeStatus
field updates."""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from kryptosbot.controller import ResearchController, ControllerConfig
from kryptosbot.family_yield import FamilyYieldStats


def _make_controller(tmp_path):
    cfg = ControllerConfig(
        project_root=Path(tmp_path),
        ledger_db_path=Path(tmp_path) / "l.sqlite",
        max_cycles=1,
        theories_per_cycle=1,
    )
    return ResearchController(cfg)


def _stats_for(family, blocked_count):
    # Use the eliminated count as a proxy for "blocked count" so the
    # severity sort key works.
    return FamilyYieldStats(family, blocked_count, 0.0, 0.0, 0, blocked_count)


class TestTruncateBlockedFamilies:

    def test_returns_all_when_under_cap(self, tmp_path):
        c = _make_controller(tmp_path)
        out = c._truncate_blocked_families([
            ("encoding", _stats_for("encoding", 826)),
            ("key_tape", _stats_for("key_tape", 207)),
        ])
        assert out == ["encoding", "key_tape"]

    def test_truncates_at_10(self, tmp_path):
        c = _make_controller(tmp_path)
        rows = [(f"f{i:02d}", _stats_for(f"f{i:02d}", 100 - i)) for i in range(15)]
        out = c._truncate_blocked_families(rows)
        assert len(out) == 10
        # Severity order: higher blocked_count first.
        assert out[0] == "f00"
        assert out[9] == "f09"

    def test_tie_break_by_trials_then_family_id(self, tmp_path):
        c = _make_controller(tmp_path)
        # Same blocked_count (==eliminated); ties by trials desc, then family id asc.
        rows = [
            ("zeta",  FamilyYieldStats("zeta",  100, 0.0, 0.0, 0, 50)),
            ("alpha", FamilyYieldStats("alpha", 200, 0.0, 0.0, 0, 50)),  # higher trials
            ("beta",  FamilyYieldStats("beta",  100, 0.0, 0.0, 0, 50)),
        ]
        out = c._truncate_blocked_families(rows)
        # alpha (more trials) first; then beta and zeta tie on trials -> family id asc.
        assert out == ["alpha", "beta", "zeta"]


class TestWriteCycleEscapeSummary:

    def test_no_pressure_resets_streak(self, tmp_path):
        c = _make_controller(tmp_path)
        c.state.escape_needed_streak = 3
        c._write_cycle_escape_summary(status="none", families_blocked=[])
        assert c.state.escape_needed_streak == 0
        assert c.state.last_escape_status == "none"

    def test_needed_but_unavailable_increments_streak(self, tmp_path):
        c = _make_controller(tmp_path)
        c.state.escape_needed_streak = 1
        c._write_cycle_escape_summary(
            status="needed_but_unavailable",
            families_blocked=["encoding", "key_tape"],
            blocked_stats=[
                ("encoding", _stats_for("encoding", 826)),
                ("key_tape", _stats_for("key_tape", 207)),
            ],
        )
        assert c.state.escape_needed_streak == 2
        assert c.state.last_escape_status == "needed_but_unavailable"
        assert c.state.last_escape_families_blocked == ["encoding", "key_tape"]
        assert c.state.last_escape_families_blocked_total == 2

    def test_partial_empirical_block_resets_streak(self, tmp_path):
        c = _make_controller(tmp_path)
        c.state.escape_needed_streak = 4
        c._write_cycle_escape_summary(
            status="partial_empirical_block",
            families_blocked=["encoding"],
            blocked_stats=[("encoding", _stats_for("encoding", 826))],
        )
        assert c.state.escape_needed_streak == 0
        assert c.state.last_partial_empirical_block_count == 1

    def test_no_candidates_resets_streak(self, tmp_path):
        c = _make_controller(tmp_path)
        c.state.escape_needed_streak = 2
        c._write_cycle_escape_summary(status="no_candidates", families_blocked=[])
        assert c.state.escape_needed_streak == 0
        assert c.state.last_escape_status == "no_candidates"

    def test_total_preserved_when_truncated(self, tmp_path):
        c = _make_controller(tmp_path)
        rows = [(f"f{i:02d}", _stats_for(f"f{i:02d}", 100 - i)) for i in range(17)]
        c._write_cycle_escape_summary(
            status="needed_but_unavailable",
            families_blocked=[f for f, _ in rows],
            blocked_stats=rows,
        )
        assert len(c.state.last_escape_families_blocked) == 10
        assert c.state.last_escape_families_blocked_total == 17


class TestAssessLandscapeYield:

    def test_landscape_includes_family_yield_packet(self, tmp_path):
        from kryptosbot.controller import ControllerConfig, ResearchController
        from kryptosbot.theory_ledger import TheoryLedger
        from kryptosbot.models import TheoryRecord, TheoryStatus

        cfg = ControllerConfig(
            project_root=Path(tmp_path),
            ledger_db_path=Path(tmp_path) / "l.sqlite",
            max_cycles=1,
            theories_per_cycle=1,
        )
        c = ResearchController(cfg)
        # Seed 50+ encoding theories to drive an empirically_dead verdict.
        for i in range(60):
            c.ledger.upsert_theory(TheoryRecord(
                hypothesis_id=f"hid_{i:03d}",
                title=f"t{i}", core_claim="c", mechanism="m",
                family="encoding", subfamily="vigenere",
                status=TheoryStatus.ELIMINATED, best_score=0.5,
            ))
        landscape = c._assess_landscape()
        assert "family_yield" in landscape
        text = landscape["family_yield"]
        assert "EMPIRICALLY DEAD" in text
        assert "encoding" in text

    def test_landscape_caches_indices_on_controller(self, tmp_path):
        from kryptosbot.controller import ControllerConfig, ResearchController
        cfg = ControllerConfig(
            project_root=Path(tmp_path),
            ledger_db_path=Path(tmp_path) / "l.sqlite",
            max_cycles=1, theories_per_cycle=1,
        )
        c = ResearchController(cfg)
        c._assess_landscape()
        assert hasattr(c, "_cycle_yield_index")
        assert hasattr(c, "_cycle_prior_subfamilies")
        assert hasattr(c, "_cycle_prior_signatures")

    def test_fail_open_when_yield_stats_raises(self, tmp_path, monkeypatch):
        from kryptosbot.controller import ControllerConfig, ResearchController
        cfg = ControllerConfig(
            project_root=Path(tmp_path),
            ledger_db_path=Path(tmp_path) / "l.sqlite",
            max_cycles=1, theories_per_cycle=1,
        )
        c = ResearchController(cfg)

        def boom(self):
            raise RuntimeError("simulated query failure")
        monkeypatch.setattr(
            "kryptosbot.theory_ledger.TheoryLedger.family_yield_stats",
            boom,
        )
        landscape = c._assess_landscape()
        # Brake is off; landscape is non-empty; indices are empty dicts.
        assert c._cycle_yield_index == {}
        assert "family_yield" in landscape


class TestCycleExitTelemetry:
    """The three cycle-exit paths each write _write_cycle_escape_summary."""

    def test_no_candidates_exit_writes_summary(self, tmp_path, monkeypatch):
        # Force theorist to return zero candidates.
        from kryptosbot.controller import ControllerConfig, ResearchController
        cfg = ControllerConfig(
            project_root=Path(tmp_path),
            ledger_db_path=Path(tmp_path) / "l.sqlite",
            max_cycles=1, theories_per_cycle=1, dry_run=True,
        )
        c = ResearchController(cfg)

        async def empty_theories(*_a, **_kw):
            return []
        monkeypatch.setattr(c, "_generate_theories", empty_theories)

        import asyncio
        asyncio.run(c.run())

        assert c.state.last_escape_status == "no_candidates"
        assert c.state.escape_needed_streak == 0  # reset

    def test_all_rejected_by_empirical_death_writes_needed_but_unavailable(
        self, tmp_path, monkeypatch,
    ):
        # Seed enough encoding theories to drive empirically_dead, then
        # have the theorist generate a single encoding theory that fails
        # bypass.
        from kryptosbot.controller import ControllerConfig, ResearchController
        from kryptosbot.models import TheoryRecord, TheoryStatus
        cfg = ControllerConfig(
            project_root=Path(tmp_path),
            ledger_db_path=Path(tmp_path) / "l.sqlite",
            max_cycles=1, theories_per_cycle=1, dry_run=True,
        )
        c = ResearchController(cfg)
        for i in range(60):
            c.ledger.upsert_theory(TheoryRecord(
                hypothesis_id=f"hid_seed_{i:03d}",
                title=f"t{i}", core_claim="c", mechanism="m",
                family="encoding", subfamily="vigenere",
                status=TheoryStatus.ELIMINATED, best_score=0.5,
            ))

        async def dead_candidate(*_a, **_kw):
            return [TheoryRecord(
                hypothesis_id="hid_new",
                title="t", core_claim="c", mechanism="m",
                family="encoding", subfamily="vigenere",
                status=TheoryStatus.PROPOSED,
            )]
        monkeypatch.setattr(c, "_generate_theories", dead_candidate)

        import asyncio
        asyncio.run(c.run())

        assert c.state.last_escape_status == "needed_but_unavailable"
        assert c.state.escape_needed_streak == 1
        assert "encoding" in c.state.last_escape_families_blocked
