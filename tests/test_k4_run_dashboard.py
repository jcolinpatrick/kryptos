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
# work flawlessly: auto-detect paths, avoid false HALTED during candidate generator
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
    actually exited. A silent log window while the candidate generator is mid-API-
    call is NOT a halt condition."""

    def test_is_run_halted_false_when_controller_alive(self):
        # log stale for 5 minutes but controller is still alive (candidate generator
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
        assert dashboard._detect_active_db() == (
            fake_root / "db" / "theory_ledger.sqlite"
        )

    def test_detect_active_db_returns_none_when_missing(self, tmp_path, monkeypatch):
        monkeypatch.setattr(dashboard, "_ROOT", tmp_path)
        assert dashboard._detect_active_db() is None

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
