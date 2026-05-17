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


class TestKBDBMissingLoggedOncePerCycle:
    """Phase 2 yield-feedback Task 17: ResearchController.

    `_kb_db_missing_logged_this_cycle` is a per-cycle latch so the
    KB-missing WARNING (raised when ``db/cipher_discovery.sqlite`` is
    absent during the empirical-death KB query) fires at most once per
    cycle instead of once per rejected theory. The flag must reset at
    the cycle-boundary chokepoint `_begin_cycle_phase_state`.
    """

    def test_flag_resets_in_begin_cycle_phase_state(self):
        from kryptosbot.controller import ResearchController

        c = ResearchController.__new__(ResearchController)
        # Minimal state required by _begin_cycle_phase_state.
        c._cycle_empirical_dead_rejections = []
        # Pre-set the flag to True; the cycle-boundary call must clear it.
        c._kb_db_missing_logged_this_cycle = True
        c.critic = None
        c._begin_cycle_phase_state()
        assert c._kb_db_missing_logged_this_cycle is False


class TestCriticKBCacheClearedBetweenCycles:
    """Per the Task 15 review: TheoryCritic's _kb_cache must be cleared at
    cycle boundary because the controller does not re-instantiate the
    critic. Without this clear, suggestions cached in cycle N would be
    returned verbatim in cycle N+1 even though prior_signatures may have
    grown to include some of those mechanisms.
    """

    def test_kb_cache_cleared_at_cycle_boundary(self):
        from kryptosbot.controller import ResearchController
        from kryptosbot.critic import TheoryCritic

        c = ResearchController.__new__(ResearchController)
        c._cycle_empirical_dead_rejections = []
        c._kb_db_missing_logged_this_cycle = False

        # Bare critic with a populated cache; bypass __init__ so we don't
        # need a real ledger for this state-transition test.
        critic = TheoryCritic.__new__(TheoryCritic)
        critic._kb_cache = {("encoding", "abc123"): ("dummy_suggestion",)}
        # Yield_index empty → blocked_families_in_cycle empty, which is
        # the cycle-boundary refresh contract.
        critic.yield_index = {}
        critic.blocked_families_in_cycle = frozenset({"stale_family_from_prev_cycle"})
        c.critic = critic

        c._begin_cycle_phase_state()
        assert critic._kb_cache == {}

    def test_blocked_families_in_cycle_refreshed_from_yield_index(self):
        """The critic.blocked_families_in_cycle must be refreshed from the
        CURRENT cycle's yield_index at the injection site
        (``_refresh_critic_cycle_state``), not from a stale set carried
        over from the previous cycle.

        Task 17a: the derivation was originally placed inside
        ``_begin_cycle_phase_state``, which runs BEFORE
        ``_assess_landscape`` populates ``_cycle_yield_index``. This test
        exercises the corrected injection site that runs AFTER
        ``_assess_landscape``.
        """
        from kryptosbot.controller import ResearchController
        from kryptosbot.critic import TheoryCritic
        from kryptosbot.family_yield import FamilyYieldVerdict, FamilyYieldStats

        c = ResearchController.__new__(ResearchController)
        c._cycle_empirical_dead_rejections = []
        c._kb_db_missing_logged_this_cycle = False

        critic = TheoryCritic.__new__(TheoryCritic)
        critic._kb_cache = {}
        # Simulate the critic entering the cycle with stale state from
        # the prior cycle: a non-empty blocked_families_in_cycle snapshot
        # and a different yield_index than the one ``_assess_landscape``
        # is about to compute.
        critic.yield_index = {}
        critic.prior_subfamilies = {}
        critic.prior_signatures = {}
        critic.blocked_families_in_cycle = frozenset({"stale_only"})
        c.critic = critic

        # ``_assess_landscape`` writes the fresh per-cycle indices onto
        # the controller; ``_refresh_critic_cycle_state`` then installs
        # them onto the critic. Simulate that ordering here.
        stats_dead = FamilyYieldStats("encoding", 100, 0.0, 0.0, 0, 100)
        stats_healthy = FamilyYieldStats("key_tape", 10, 8.0, 12.0, 1, 0)
        c._cycle_yield_index = {
            "encoding": FamilyYieldVerdict(
                family="encoding", status="empirically_dead", stats=stats_dead,
                reasons=("n>=50, no_signal",),
            ),
            "key_tape": FamilyYieldVerdict(
                family="key_tape", status="healthy", stats=stats_healthy,
                reasons=(),
            ),
        }
        c._cycle_prior_subfamilies = {}
        c._cycle_prior_signatures = {}

        c._refresh_critic_cycle_state()
        assert critic.blocked_families_in_cycle == frozenset({"encoding"})
        # yield_index, prior_subfamilies, prior_signatures must be
        # installed too — this is the single critic-state injection
        # chokepoint.
        assert critic.yield_index is c._cycle_yield_index
        assert critic.prior_subfamilies == {}
        assert critic.prior_signatures == {}

    def test_begin_cycle_phase_state_does_not_use_stale_yield_index(self):
        """Regression guard for Task 17a: ``_begin_cycle_phase_state``
        must NOT derive ``blocked_families_in_cycle`` from the critic's
        currently-installed (possibly previous-cycle) yield_index.

        If a future change re-introduces a derivation at the cycle-start
        chokepoint, the staleness bug returns. This test pins the
        contract: with a stale yield_index already on the critic at
        cycle start, the cycle-start chokepoint must leave
        blocked_families_in_cycle untouched (the value will be refreshed
        later by ``_refresh_critic_cycle_state``).
        """
        from kryptosbot.controller import ResearchController
        from kryptosbot.critic import TheoryCritic
        from kryptosbot.family_yield import FamilyYieldVerdict, FamilyYieldStats

        c = ResearchController.__new__(ResearchController)
        c._cycle_empirical_dead_rejections = []
        c._kb_db_missing_logged_this_cycle = False

        critic = TheoryCritic.__new__(TheoryCritic)
        critic._kb_cache = {}
        # Stale yield_index from a previous cycle, plus a stale
        # blocked_families_in_cycle that doesn't match it.
        stats_dead = FamilyYieldStats("prev_dead", 100, 0.0, 0.0, 0, 100)
        critic.yield_index = {
            "prev_dead": FamilyYieldVerdict(
                family="prev_dead", status="empirically_dead",
                stats=stats_dead, reasons=("stale",),
            ),
        }
        sentinel_before = frozenset({"sentinel_unchanged"})
        critic.blocked_families_in_cycle = sentinel_before
        c.critic = critic

        c._begin_cycle_phase_state()

        # _begin_cycle_phase_state must NOT have re-derived blocked_
        # families_in_cycle from the stale yield_index (which would
        # have produced frozenset({"prev_dead"})). The sentinel passes
        # through untouched until _refresh_critic_cycle_state runs.
        assert critic.blocked_families_in_cycle is sentinel_before


class TestEscapeSummaryAggregatesSuggestions:
    def _bare_controller(self):
        from kryptosbot.controller import ResearchController, ControllerState
        c = ResearchController.__new__(ResearchController)
        c.state = ControllerState(cycle_number=1)
        c._cycle_empirical_dead_rejections = []
        c._kb_db_missing_logged_this_cycle = False
        return c

    def _example_rejection(self, family, n_suggestions=2):
        from kryptosbot.models import EmpiricalDeathRejectionPayload
        from kryptosbot.kb_injection import (
            KB_SIGNATURE_SCHEMA_VERSION,
            CipherDiscoverySuggestion,
        )
        suggestions = tuple(
            CipherDiscoverySuggestion(
                kb_record_id=f"rec-{family}-{i}",
                canonical_name=f"Cipher {family} {i}",
                kb_cipher_family="columnar",
                mapped_ledger_families=("columnar_single",),
                mechanism_signature=f"sig-{family}-{i:02d}".ljust(16, "x")[:16],
                signature_schema_version=KB_SIGNATURE_SCHEMA_VERSION,
                dispatcher_testable=True,
                k4_relevance_score=50.0 - i,
                sketch_class="dsl_testable",
                one_line_sketch="sketch",
                bounded_kill_criterion="kill",
                source_verdict="allow",
            )
            for i in range(n_suggestions)
        )
        return EmpiricalDeathRejectionPayload(
            family=family,
            verdict=None,
            bypass_failed_reasons=("x",),
            suggested_mechanism_records=suggestions,
            suggestion_source="cipher_discovery_kb",
            suggestion_query_scope={},
        )

    def test_aggregates_suggestions_into_state(self):
        c = self._bare_controller()
        rejections = [
            self._example_rejection("encoding", n_suggestions=2),
            self._example_rejection("k2_coords", n_suggestions=2),
        ]
        c._write_cycle_escape_summary(
            status="needed_but_unavailable",
            families_blocked=["encoding", "k2_coords"],
            rejections=rejections,
        )
        stored = c.state.last_escape_suggestions
        assert isinstance(stored, list)
        # All entries are dicts (JSON-storage shape).
        for d in stored:
            assert isinstance(d, dict)
            assert "blocked_family" in d
            assert "canonical_name" in d
        assert {d["blocked_family"] for d in stored} == {"encoding", "k2_coords"}

    def test_caps_storage_at_3_per_family(self):
        c = self._bare_controller()
        big = self._example_rejection("encoding", n_suggestions=10)
        c._write_cycle_escape_summary(
            status="needed_but_unavailable",
            families_blocked=["encoding"],
            rejections=[big],
        )
        encoding_entries = [d for d in c.state.last_escape_suggestions if d["blocked_family"] == "encoding"]
        assert len(encoding_entries) <= 3

    def test_caps_storage_at_24_total(self):
        c = self._bare_controller()
        # 10 families with 10 suggestions each — 100 total before cap.
        rejections = [self._example_rejection(f"fam_{i}", n_suggestions=10) for i in range(10)]
        c._write_cycle_escape_summary(
            status="needed_but_unavailable",
            families_blocked=[r.family for r in rejections],
            rejections=rejections,
        )
        assert len(c.state.last_escape_suggestions) <= 24

    def test_dedupe_by_mechanism_signature_within_family(self):
        c = self._bare_controller()
        dup = self._example_rejection("encoding", n_suggestions=1)
        # Two payloads carrying the same signature in encoding.
        c._write_cycle_escape_summary(
            status="needed_but_unavailable",
            families_blocked=["encoding"],
            rejections=[dup, dup],
        )
        sigs = {d["mechanism_signature"] for d in c.state.last_escape_suggestions}
        assert len(sigs) == 1

    def test_none_status_clears_or_skips(self):
        c = self._bare_controller()
        # Empty rejections + status=none should NOT populate suggestions.
        c._write_cycle_escape_summary(status="none", families_blocked=[], rejections=[])
        assert c.state.last_escape_suggestions == []
