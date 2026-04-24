from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "_infra" / "k4_run_dashboard.py"
SPEC = importlib.util.spec_from_file_location("k4_run_dashboard", MODULE_PATH)
dashboard = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(dashboard)


def test_source_badges_report_waiting_sources():
    snap = {"theories": [], "experiments": [], "error": "ledger not yet created"}
    logdata = {"last_modified": 0.0}

    badges = dashboard._source_badges(snap, logdata, now=100.0)

    assert ("ledger waiting", dashboard.C_WATCH) in badges
    assert ("log waiting", dashboard.C_WATCH) in badges


def test_source_badges_report_schema_failure_and_stale_log():
    snap = {"theories": [], "experiments": [], "error": "sqlite: no such table: theories"}
    logdata = {"last_modified": 80.0}

    badges = dashboard._source_badges(snap, logdata, now=100.0)

    assert ("ledger schema", dashboard.C_CRITICAL) in badges
    assert ("log cold", dashboard.C_CRITICAL) in badges


def test_activity_panel_surfaces_ledger_error():
    panel = dashboard._activity_panel(
        {"theories": [], "experiments": [], "error": "sqlite: no such table: theories"},
        {"workers": {}, "current_stage": "", "current_persona": ""},
        frame=0,
        now=100.0,
    )

    renderable = panel.renderable
    texts = [part.plain for part in renderable.renderables]
    assert any("ledger unavailable" in text for text in texts)
    assert any("no such table" in text for text in texts)


def test_mortality_panel_hides_zero_classification_during_ledger_error():
    panel = dashboard._mortality_panel(
        {"theories": [], "experiments": [], "error": "ledger not yet created"},
        frame=0,
        now=100.0,
    )

    renderable = panel.renderable
    texts = [part.plain for part in renderable.renderables]
    assert any("classification paused" in text for text in texts)
    assert all("total proposals" not in text for text in texts)


# ─── Dashboard hardening (2026-04-22) ──────────────────────────────────────
# Make the default `PYTHONPATH=src python3 scripts/_infra/k4_run_dashboard.py`
# work flawlessly: auto-detect paths, avoid false HALTED during theorist
# generate-phase silence, parse the cycle ceiling from the log directly.


class TestCycleInfoFromLog:
    def test_slash_format_from_controller(self):
        # Real controller prints: ═════ CYCLE 151/165 ═════
        log = (
            "irrelevant prelude\n"
            "════════════ CYCLE 151/165 ════════════\n"
            "more output\n"
            "════════════ CYCLE 154/165 ════════════\n"
        )
        info = dashboard._parse_cycle_info_from_log(log)
        assert info == (154, 165), (
            f"expected last-match wins on multi-cycle log; got {info!r}"
        )

    def test_of_format_from_display_rendering(self):
        # The dashboard's own event-tape rewrites to "CYCLE N of M"; the
        # parser tolerates both shapes so mixed-source logs still work.
        log = "CYCLE 10 of 15\n"
        assert dashboard._parse_cycle_info_from_log(log) == (10, 15)

    def test_no_cycle_line_returns_none(self):
        assert dashboard._parse_cycle_info_from_log("no cycle banner here") is None


class TestHaltLogicWithControllerAlive:
    """The HALTED banner must ONLY fire when the controller process has
    actually exited. A silent log window while the theorist is mid-API-
    call is NOT a halt condition."""

    def test_is_run_halted_false_when_controller_alive(self):
        # log stale for 5 minutes but controller is still alive (theorist
        # deep-generate phase) — must not report halted.
        import time
        now = time.time()
        stale = now - 300
        assert dashboard._is_run_halted(stale, now, controller_alive=True) is False

    def test_is_run_halted_true_when_controller_dead(self):
        import time
        now = time.time()
        stale = now - 300
        assert dashboard._is_run_halted(stale, now, controller_alive=False) is True

    def test_log_liveness_shows_thinking_when_controller_alive(self):
        import time
        now = time.time()
        stale = now - 300
        label, _color, _spin = dashboard._log_liveness(
            stale, now, controller_alive=True,
        )
        assert label == "thinking", (
            f"stale log + alive controller must label 'thinking', "
            f"not 'halted'; got {label!r}"
        )

    def test_log_liveness_halted_when_controller_dead_and_stale(self):
        import time
        now = time.time()
        stale = now - 300
        label, _color, _spin = dashboard._log_liveness(
            stale, now, controller_alive=False,
        )
        assert label == "halted"


class TestAutoDetectPaths:
    def test_detect_active_db_returns_canonical_when_exists(self, tmp_path, monkeypatch):
        # Point _ROOT at a tmp tree with the canonical db layout.
        fake_root = tmp_path
        (fake_root / "db").mkdir()
        (fake_root / "db" / "theory_ledger.sqlite").write_bytes(b"")
        monkeypatch.setattr(dashboard, "_ROOT", fake_root)
        # No live controller → falls through to canonical.
        monkeypatch.setattr(
            dashboard, "_detect_controller_process", lambda: None,
        )
        assert dashboard._detect_active_db() == (
            fake_root / "db" / "theory_ledger.sqlite"
        )

    def test_detect_active_db_returns_none_when_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dashboard, "_ROOT", tmp_path)
        monkeypatch.setattr(
            dashboard, "_detect_controller_process", lambda: None,
        )
        assert dashboard._detect_active_db() is None

    def test_detect_active_db_prefers_running_controllers_db_arg(
        self, tmp_path, monkeypatch,
    ):
        """Campaign-C attempt-2 fix: when a controller is running with
        --db pointing at a campaign-specific ledger, the dashboard's
        auto-detect must return THAT ledger, not the canonical main
        ledger. Prior behaviour silently ignored --db and surfaced
        stale data from the main ledger."""
        fake_root = tmp_path
        (fake_root / "db").mkdir()
        (fake_root / "db" / "theory_ledger.sqlite").write_bytes(b"")
        attempt_db = fake_root / "db" / "k4_campaign_c_attempt2.sqlite"
        attempt_db.write_bytes(b"")
        monkeypatch.setattr(dashboard, "_ROOT", fake_root)
        # Simulate a live controller launched with --db pointing at the
        # campaign-specific file.
        fake_argv = [
            "python3", "-u", "kryptosbot/run_controller.py",
            "--cycles", "15", "--theories", "5",
            "--no-oranchak-corpora",
            "--db", "db/k4_campaign_c_attempt2.sqlite",
        ]
        monkeypatch.setattr(
            dashboard, "_detect_controller_process",
            lambda: (12345, fake_argv),
        )
        assert dashboard._detect_active_db() == attempt_db

    def test_detect_active_db_falls_back_to_canonical_when_db_arg_missing(
        self, tmp_path, monkeypatch,
    ):
        """Controller launched without --db (default main ledger) →
        dashboard returns canonical. No argv-less match should treat
        a non-existent path as valid."""
        fake_root = tmp_path
        (fake_root / "db").mkdir()
        (fake_root / "db" / "theory_ledger.sqlite").write_bytes(b"")
        monkeypatch.setattr(dashboard, "_ROOT", fake_root)
        fake_argv = [
            "python3", "-u", "kryptosbot/run_controller.py",
            "--cycles", "10",
        ]
        monkeypatch.setattr(
            dashboard, "_detect_controller_process",
            lambda: (12345, fake_argv),
        )
        assert dashboard._detect_active_db() == (
            fake_root / "db" / "theory_ledger.sqlite"
        )

    def test_detect_active_db_falls_back_when_db_arg_points_to_missing_file(
        self, tmp_path, monkeypatch,
    ):
        """If the controller's --db points at a file that doesn't exist
        yet (e.g. race at launch before the ledger is written),
        dashboard falls back to canonical rather than returning a
        non-existent path. This keeps the dashboard's resolve
        contract consistent with the rest of the codebase."""
        fake_root = tmp_path
        (fake_root / "db").mkdir()
        (fake_root / "db" / "theory_ledger.sqlite").write_bytes(b"")
        monkeypatch.setattr(dashboard, "_ROOT", fake_root)
        fake_argv = [
            "python3", "-u", "kryptosbot/run_controller.py",
            "--db", "db/does_not_exist.sqlite",
        ]
        monkeypatch.setattr(
            dashboard, "_detect_controller_process",
            lambda: (12345, fake_argv),
        )
        assert dashboard._detect_active_db() == (
            fake_root / "db" / "theory_ledger.sqlite"
        )


    def test_detect_active_log_picks_newest_campaign_log(self, tmp_path, monkeypatch):
        # Create three logs across two campaigns with different mtimes.
        import os, time
        fake_root = tmp_path
        (fake_root / "logs" / "campaign_a").mkdir(parents=True)
        (fake_root / "logs" / "campaign_b").mkdir(parents=True)
        old = fake_root / "logs" / "campaign_a" / "run_older.log"
        old.write_text("old")
        os.utime(old, (time.time() - 3600, time.time() - 3600))
        newer = fake_root / "logs" / "campaign_a" / "run_newer.log"
        newer.write_text("newer")
        os.utime(newer, (time.time() - 1800, time.time() - 1800))
        newest = fake_root / "logs" / "campaign_b" / "run_newest.log"
        newest.write_text("newest")
        os.utime(newest, (time.time() - 60, time.time() - 60))

        monkeypatch.setattr(dashboard, "_ROOT", fake_root)
        assert dashboard._detect_active_log() == newest

    def test_detect_active_log_returns_none_when_no_logs(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dashboard, "_ROOT", tmp_path)
        assert dashboard._detect_active_log() is None


class TestExtractDbArgFromArgv:
    """_extract_db_arg_from_argv is pure parsing — exercise every shape."""

    def test_space_separated_db_arg(self):
        argv = ["python3", "run_controller.py", "--db", "foo.sqlite"]
        assert dashboard._extract_db_arg_from_argv(argv) == Path("foo.sqlite")

    def test_equals_form_db_arg(self):
        argv = ["python3", "run_controller.py", "--db=bar.sqlite"]
        assert dashboard._extract_db_arg_from_argv(argv) == Path("bar.sqlite")

    def test_no_db_arg_returns_none(self):
        argv = ["python3", "run_controller.py", "--cycles", "10"]
        assert dashboard._extract_db_arg_from_argv(argv) is None

    def test_db_arg_without_value_returns_none(self):
        argv = ["python3", "run_controller.py", "--db"]
        assert dashboard._extract_db_arg_from_argv(argv) is None

    def test_db_arg_at_end_with_value(self):
        argv = ["python3", "run_controller.py", "--cycles", "10", "--db", "end.sqlite"]
        assert dashboard._extract_db_arg_from_argv(argv) == Path("end.sqlite")


class TestControllerPidDetection:
    def test_is_pid_alive_false_for_impossible_pid(self):
        # PID 0 is the scheduler / swapper; never a user process, not alive
        # for any non-root probe. Verifies the defensive guard, not POSIX semantics.
        assert dashboard._is_pid_alive(0) is False
        assert dashboard._is_pid_alive(-1) is False

    def test_is_pid_alive_true_for_current_process(self):
        import os
        assert dashboard._is_pid_alive(os.getpid()) is True

    def test_detect_controller_pid_returns_optional_int(self):
        # Returns Optional[int] regardless of whether a controller is running;
        # the dashboard must never crash on this probe.
        result = dashboard._detect_controller_pid()
        assert result is None or isinstance(result, int)


class TestMortalityEBandFiltering:
    """The mortality panel's score-band (E) rows must only surface
    theories that still warrant investigation. Completed / eliminated
    theories are resolved history; including their historical scores in
    the live display misleads the operator into thinking there's an
    unresolved SIGNAL to chase.

    Regression target: user-reported 2026-04-22 — dashboard showed
    "E score 18-23: 1" for a Nihilist experiment that had been
    ELIMINATED 10 days earlier, plus 7 entries in the BREAKTHROUGH
    band that were all known crib-paste fabrications already stat-
    audited out.
    """

    def _panel_text(self, panel) -> str:
        """Render panel to a plain-text string so assertions can look
        for substrings without caring about Rich widget types."""
        from io import StringIO
        from rich.console import Console
        console = Console(file=StringIO(), width=200, color_system=None)
        console.print(panel)
        return console.file.getvalue()

    def _row_count(self, rendered: str, row_label: str) -> int:
        """Extract the count from a mortality row like
        'E  score 18-23  │  SIGNAL  │ ▕▰...▏ │     1 │     2.1%'.
        Returns 0 when the row is present with count 0 or missing."""
        import re
        for line in rendered.splitlines():
            if row_label in line:
                # The count is the second-to-last pipe-separated column.
                # We take the last number-only token before the pct column.
                m = re.findall(r"\│\s*(\d+)\s*\│\s*\d", line)
                if m:
                    return int(m[-1])
        return 0

    def _snap_with(self, theory_status: str, crib_score: int) -> dict:
        return {
            "theories": [{
                "hypothesis_id": "h1", "title": "t", "status": theory_status,
                "critic_verdict": {"decision": "approve", "reasons": []},
                "best_score": 0.0,
            }],
            "experiments": [{
                "hypothesis_id": "h1",
                "result": {"crib_score": crib_score, "bean_passed": False},
            }],
            "error": None,
        }

    def test_eliminated_theory_does_not_populate_e_bands(self):
        # ELIMINATED at crib=19 (SIGNAL-range historical) must NOT show up.
        snap = self._snap_with("eliminated", 19)
        panel = dashboard._mortality_panel(snap, frame=0, now=100.0)
        rendered = self._panel_text(panel)
        assert "18-23" in rendered
        assert self._row_count(rendered, "18-23") == 0, (
            "eliminated theory leaked into E 18-23 band; the panel now shows "
            "a spurious historical SIGNAL"
        )

    def test_completed_theory_does_not_populate_e_bands(self):
        # COMPLETED at crib=24 (BREAKTHROUGH historical crib-paste) must NOT show.
        snap = self._snap_with("completed", 24)
        panel = dashboard._mortality_panel(snap, frame=0, now=100.0)
        rendered = self._panel_text(panel)
        assert self._row_count(rendered, "score 24") == 0, (
            "completed theory leaked into E 24 band"
        )

    def test_promising_theory_still_populates_e_bands(self):
        # PROMISING means "stat-audit says investigate" — must remain
        # visible so the operator can find it.
        snap = self._snap_with("promising", 19)
        panel = dashboard._mortality_panel(snap, frame=0, now=100.0)
        rendered = self._panel_text(panel)
        assert self._row_count(rendered, "18-23") == 1, (
            "PROMISING theory must still surface in E 18-23 band"
        )

    def test_running_theory_goes_to_in_flight_not_score_bands(self):
        # Running theories should land in row A; their score bands stay empty.
        snap = self._snap_with("running", 15)
        panel = dashboard._mortality_panel(snap, frame=0, now=100.0)
        rendered = self._panel_text(panel)
        assert self._row_count(rendered, "in flight") == 1, (
            "running theory must show in A in-flight row"
        )
        # And MUST NOT also pollute the 10-17 score band.
        assert self._row_count(rendered, "10-17") == 0


class TestBestCribFiltering:
    """Telemetry's "best crib" must only reflect theories that still
    warrant investigation. Historical crib-paste fabrications — high-
    crib theories already ELIMINATED or COMPLETED after stat-audit —
    must not inflate the live display.

    Regression target 2026-04-22: dashboard displayed "best crib 24/24"
    because the ledger held 7 historical BREAKTHROUGH-scored theories
    all resolved as crib-paste noise."""

    def _snap(self, theories: list[dict], experiments: list[dict]) -> dict:
        return {"theories": theories, "experiments": experiments, "error": None}

    def test_eliminated_theory_does_not_contribute(self):
        snap = self._snap(
            theories=[{"hypothesis_id": "h1", "status": "eliminated",
                       "best_score": 24.0, "critic_verdict": None}],
            experiments=[{"hypothesis_id": "h1",
                          "result": {"crib_score": 24}}],
        )
        assert dashboard._best_crib(snap) == 0, (
            "eliminated theory with crib=24 must not surface as best_crib"
        )

    def test_completed_theory_does_not_contribute(self):
        snap = self._snap(
            theories=[{"hypothesis_id": "h1", "status": "completed",
                       "best_score": 24.0, "critic_verdict": None}],
            experiments=[{"hypothesis_id": "h1",
                          "result": {"crib_score": 24}}],
        )
        assert dashboard._best_crib(snap) == 0

    def test_promising_theory_does_contribute(self):
        snap = self._snap(
            theories=[{"hypothesis_id": "h1", "status": "promising",
                       "best_score": 19.0, "critic_verdict": None}],
            experiments=[{"hypothesis_id": "h1",
                          "result": {"crib_score": 19}}],
        )
        assert dashboard._best_crib(snap) == 19

    def test_running_theory_does_contribute(self):
        # A theory mid-dispatch may not yet have an experiment row; the
        # theory-level best_score fallback must still count.
        snap = self._snap(
            theories=[{"hypothesis_id": "h1", "status": "running",
                       "best_score": 15.0, "critic_verdict": None}],
            experiments=[],
        )
        assert dashboard._best_crib(snap) == 15

    def test_mixed_live_and_resolved(self):
        # Live theory at 11, eliminated theory at 24 — best_crib = 11.
        snap = self._snap(
            theories=[
                {"hypothesis_id": "h1", "status": "running",
                 "best_score": 11.0, "critic_verdict": None},
                {"hypothesis_id": "h2", "status": "eliminated",
                 "best_score": 24.0, "critic_verdict": None},
            ],
            experiments=[
                {"hypothesis_id": "h1", "result": {"crib_score": 11}},
                {"hypothesis_id": "h2", "result": {"crib_score": 24}},
            ],
        )
        assert dashboard._best_crib(snap) == 11, (
            "live theory's 11 must beat the resolved theory's 24"
        )

    def test_withdrawn_theory_filtered(self):
        snap = self._snap(
            theories=[{"hypothesis_id": "h1", "status": "withdrawn",
                       "best_score": 22.0, "critic_verdict": None}],
            experiments=[{"hypothesis_id": "h1",
                          "result": {"crib_score": 22}}],
        )
        assert dashboard._best_crib(snap) == 0

    def test_unknown_status_counted_defensively(self):
        # A theory with an unexpected / empty status should still
        # contribute — silently filtering an unrecognized state would
        # hide live signal. Only explicit resolved-states filter.
        snap = self._snap(
            theories=[{"hypothesis_id": "h1", "status": "",
                       "best_score": 17.0, "critic_verdict": None}],
            experiments=[{"hypothesis_id": "h1",
                          "result": {"crib_score": 17}}],
        )
        assert dashboard._best_crib(snap) == 17
