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
