"""Tests for the operations-grade k4_monitor dashboard.

The script lives at the repo root (not under src/), so we add the parent
directory to sys.path explicitly. These tests intentionally cover only
helpers and non-interactive render paths — no Rich Live, no terminal, no
real DB writes.
"""

from __future__ import annotations

import io
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import k4_monitor as km  # noqa: E402


# ─── helpers ────────────────────────────────────────────────────────


class TestTruncateMiddle:
    def test_short_string_unchanged(self):
        assert km.truncate_middle("hello", 20) == "hello"

    def test_preserves_prefix_and_suffix(self):
        s = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        out = km.truncate_middle(s, 12)
        assert out.startswith("ABC") or out.startswith("ABCD")
        assert out.endswith("YZ") or out.endswith("XYZ") or out.endswith("WXYZ")
        assert "…" in out
        assert len(out) <= 12

    def test_zero_width(self):
        assert km.truncate_middle("anything", 0) == ""

    def test_marker_wider_than_max(self):
        out = km.truncate_middle("hello", 1)
        assert len(out) <= 1


class TestTruncateEnd:
    def test_short_string_unchanged(self):
        assert km.truncate_end("hi", 20) == "hi"

    def test_truncates_with_marker(self):
        out = km.truncate_end("a" * 50, 10)
        assert len(out) == 10
        assert out.endswith("…")


class TestHumanizeAge:
    def test_none(self):
        assert km.humanize_age(None) == "—"

    def test_seconds(self):
        assert km.humanize_age(0) == "0s"
        assert km.humanize_age(45) == "45s"

    def test_minutes(self):
        out = km.humanize_age(90)
        assert "m" in out
        assert "1m" in out

    def test_hours(self):
        out = km.humanize_age(7200)
        assert "h" in out


class TestHumanizeDuration:
    def test_zero(self):
        assert km.humanize_duration(0) == "00:00:00"

    def test_none(self):
        assert km.humanize_duration(None) == "--:--:--"

    def test_format(self):
        assert km.humanize_duration(3661) == "01:01:01"


class TestParseIso:
    def test_none(self):
        assert km.parse_iso(None) is None
        assert km.parse_iso("") is None

    def test_with_z_suffix(self):
        dt = km.parse_iso("2026-04-30T12:00:00Z")
        assert dt is not None
        assert dt.tzinfo is not None

    def test_naive_iso_attaches_utc(self):
        dt = km.parse_iso("2026-04-30T12:00:00")
        assert dt is not None
        assert dt.tzinfo is timezone.utc

    def test_invalid_returns_none(self):
        assert km.parse_iso("not-a-date") is None


# ─── layout selection ──────────────────────────────────────────────


class TestPickLayout:
    @pytest.mark.parametrize(
        "w,h,expected",
        [
            (50, 20, "tiny"),       # too narrow
            (90, 22, "tiny"),       # narrow
            (130, 30, "compact"),   # mid
            (170, 35, "wide"),      # wide
            (250, 60, "ultrawide"), # 4K-ish
            (310, 80, "ultrawide"), # 4K
        ],
    )
    def test_breakpoints(self, w, h, expected):
        assert km.pick_layout(w, h) == expected

    def test_too_short_height_picks_tiny(self):
        assert km.pick_layout(200, 18) == "tiny"


class TestTooSmall:
    def test_normal_terminals_ok(self):
        assert not km.too_small(160, 45)
        assert not km.too_small(120, 35)

    def test_extreme_small_flagged(self):
        assert km.too_small(70, 14)
        assert km.too_small(100, 10)


# ─── event classification ──────────────────────────────────────────


class TestClassifyEvent:
    @pytest.mark.parametrize(
        "line,expected",
        [
            ("✗ KERNEL OVERRULE detected on hypothesis abc123", "KERNEL"),
            ("FABRICATION caught: worker self-report rejected", "KERNEL"),
            ("BREAKTHROUGH candidate scored 24/24", "BREAKTHROUGH"),
            ("SIGNAL crib_score=22 Bean PASS", "SIGNAL"),
            ("⚠ Red-team CONCERNED about ...", "REDTEAM"),
            ("verifier APPROVE cribs 7/24", "VERIFIER"),
            ("▸ CRITIC 9/10 theories APPROVED", "CRITIC"),
            ("CYCLE 15/100 beginning dispatch", "DISPATCH"),
            ("Worker abc123 completed (best_score=4)", "WORKER"),
            ("ledger wrote 3 rows", "LEDGER"),
            ("Anomaly 'foo' updated", "ANOMALY"),
            ("Traceback (most recent call last):", "WARN"),
            ("Fatal error in message reader: Command failed with exit code 1", "WARN"),
            ("Error output: Check stderr output for details", "WARN"),
            ("WARNING: low memory", "WARN"),
            ("[ERROR] worker subprocess died", "WARN"),
            # Content-reference false-positives — these MUST NOT classify as WARN.
            # K1 deliberately misspells ILLUSION as IQLUSION; K2 misspells
            # UNDERGROUND as UNDERGRUUND. Theory titles refer to these as
            # "error" content, not system errors.
            ("▶ a8ff924b  CT-perturbation single-Q-substitution analog of K1 IQLUSION error then Vigenere KA", None),
            ("▶ b08c383f  CT-perturbation analog of K2 UNDERGRUUND error then Beaufort KA", None),
            ("Sanborn hand-error perturbation: archival comparison of carved K4 vs Sanborn's working copy", None),
            ("CT perturbation evidence: transcription errors provable from published coding charts", None),
            ("CT-perturbation analog-of-K1/K2-error approach exhausted for single/double-letter variants", None),
            ("▸ GENERATE  theorist starting", "PHASE"),
            ("just an idle line of nothing-special prose", None),
        ],
    )
    def test_classification(self, line, expected):
        assert km.classify_event(line) == expected


# ─── snapshot + activity inference ─────────────────────────────────


class TestActivity:
    def test_empty_snapshot_no_crash(self):
        snap = km.Snapshot()
        tail = km.LogTail(path=None)
        a = km.derive_activity(snap, tail)
        assert a.state in ("STARTING", "IDLE", "RUNNING", "PAUSED", "ERROR")
        assert isinstance(a.phase, str)

    def test_halt_reason_yields_error(self):
        snap = km.Snapshot()
        snap.controller_halt_reason = "synthetic-mode taint mismatch"
        a = km.derive_activity(snap, km.LogTail(path=None))
        assert a.state == "ERROR"
        assert "synthetic-mode" in a.detail.lower() or "taint" in a.detail.lower()

    def test_recent_kernel_event_flagged(self):
        snap = km.Snapshot()
        tail = km.LogTail(path=None)
        tail.last_by_category["KERNEL"] = datetime.now()
        tail.last_event_at = datetime.now()
        a = km.derive_activity(snap, tail)
        assert "KERNEL" in a.phase.upper()

    def test_ledger_age_uses_freshest_timestamp(self):
        """Workers writing experiments must register as fresh ledger activity
        even when theories.updated_at is stale (best_score didn't change).
        """
        snap = km.Snapshot()
        snap.last_theory_update = datetime.now(timezone.utc) - timedelta(minutes=5)
        snap.last_exp_start = datetime.now(timezone.utc) - timedelta(seconds=4)
        snap.last_exp_complete = datetime.now(timezone.utc) - timedelta(seconds=10)
        a = km.derive_activity(snap, km.LogTail(path=None))
        # Should report ~4s, not 5min.
        assert a.last_ledger_write_age_s is not None
        assert a.last_ledger_write_age_s < 30

    def test_real_mode_does_not_force_paused(self):
        """Real-K4 mode is a data-taint badge, not engine state.

        If 8 workers are dispatching every 1s, the engine is RUNNING — the
        dashboard must reflect that. The REAL-K4 badge already warns the
        operator about data taint; collapsing state to PAUSED would hide a
        healthy engine and was a real bug observed in a live screenshot.
        """
        snap = km.Snapshot()
        snap.mode = "real"
        snap.total_theories = 800
        snap.active_experiments = 8
        tail = km.LogTail(path=None)
        # Recent dispatch + worker activity.
        tail.last_event_at = datetime.now()
        tail.last_by_category["DISPATCH"] = datetime.now()
        tail.last_by_category["WORKER"] = datetime.now()
        a = km.derive_activity(snap, tail)
        assert a.state == "RUNNING"
        assert a.show_spinner is True
        assert a.active_workers == 8


# ─── demo-state generator ──────────────────────────────────────────


class TestDemoState:
    def test_deterministic(self):
        s1, t1, a1 = km.make_demo_state(seed=42, cycle_phase=0)
        s2, t2, a2 = km.make_demo_state(seed=42, cycle_phase=0)
        assert s1.total_theories == s2.total_theories
        assert s1.status == s2.status
        assert s1.score_bins == s2.score_bins
        assert [r.hypothesis_id for r in s1.top_rows] == [r.hypothesis_id for r in s2.top_rows]

    def test_phases_advance(self):
        s0, _, _ = km.make_demo_state(seed=1, cycle_phase=0)
        s5, _, _ = km.make_demo_state(seed=1, cycle_phase=5)
        assert s5.controller_cycle != s0.controller_cycle

    def test_kernel_override_appears_in_late_phase(self):
        s, _, _ = km.make_demo_state(seed=1, cycle_phase=6)
        assert any(r.is_kernel_override for r in s.top_rows)
        assert s.fab_count >= 1


# ─── log tail ──────────────────────────────────────────────────────


class TestLogTail:
    def test_missing_file_safe(self):
        tail = km.LogTail(path=Path("/nonexistent/path/to.log"))
        tail.poll()  # should not raise
        assert not tail.events

    def test_none_path_safe(self):
        tail = km.LogTail(path=None)
        tail.poll()
        assert not tail.events

    def test_processes_classified_events(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text(
            "12:00:00 startup chatter (uninteresting)\n"
            "12:00:01 CYCLE 1/10 beginning dispatch\n"
            "12:00:02 ✗ KERNEL OVERRULE on abc\n"
            "12:00:03 ▸ CRITIC 5/10 approved\n",
        )
        tail = km.LogTail(path=log)
        tail.poll()
        cats = [ev.category for ev in tail.events]
        assert "KERNEL" in cats
        assert "DISPATCH" in cats or "PHASE" in cats
        assert "CRITIC" in cats
        # Cycle parsed from log.
        assert tail.cycle_current == 1
        assert tail.cycle_total == 10
        # Alerts include the kernel event.
        assert any(ev.category == "KERNEL" for ev in tail.alerts)


# ─── snapshot read-only DB ─────────────────────────────────────────


def _build_minimal_ledger(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE theories (
            hypothesis_id TEXT PRIMARY KEY,
            title TEXT, family TEXT, status TEXT,
            best_score REAL, best_plaintext TEXT,
            critic_verdict TEXT, created_at TEXT, updated_at TEXT,
            outcome_summary TEXT DEFAULT '', failure_reason TEXT DEFAULT ''
        );
        CREATE TABLE experiments (
            experiment_id TEXT PRIMARY KEY,
            hypothesis_id TEXT, started_at TEXT, completed_at TEXT,
            worker_role TEXT
        );
        CREATE TABLE pursuit_leads (
            lead_id TEXT PRIMARY KEY, status TEXT, opened_at TEXT
        );
        CREATE TABLE anomalies (
            anomaly_id TEXT PRIMARY KEY, status TEXT
        );
        """
    )
    now = datetime.now(timezone.utc).isoformat()
    # Non-terminal theory: experiment with empty completed_at = genuinely active.
    long_outcome = (
        "The hypothesis was tested across 5 preregistered CT perturbations. "
        "All 30 configs scored 0-2/24. Bean equality k[27]=k[65] failed in 28 of 30."
    )
    conn.execute(
        "INSERT INTO theories VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            "abc123",
            "Demo",
            "encoding",
            "approved",
            18.0,
            "PLAINTEXT_TEST",
            '{"decision":"approve","reasons":["passed all checks"]}',
            now,
            now,
            long_outcome,
            "",
        ),
    )
    conn.execute(
        "INSERT INTO theories VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (
            "def456",
            "Override",
            "grille",
            "eliminated",
            24.0,
            "FABRICATED_PT",
            '{"decision":"reject","reasons":["fabrication"]}',
            now,
            now,
            "",
            "Worker self-reported BREAKTHROUGH; kernel re-derived crib_score=4.",
        ),
    )
    conn.execute(
        "INSERT INTO experiments VALUES (?,?,?,?,?)",
        ("e1", "abc123", now, now, "cryptanalyst"),
    )
    conn.execute(
        "INSERT INTO experiments VALUES (?,?,?,?,?)",
        ("e2", "abc123", now, "", "verifier"),
    )
    # Leaked-row case: experiment with empty completed_at, theory eliminated.
    # Should count as audit_unclosed, NOT as active.
    conn.execute(
        "INSERT INTO experiments VALUES (?,?,?,?,?)",
        ("e3-leaked", "def456", now, "", "local_rerun"),
    )
    conn.commit()
    conn.close()


class TestTakeSnapshot:
    def test_minimal_ledger(self, tmp_path):
        db = tmp_path / "ledger.sqlite"
        _build_minimal_ledger(db)
        conn = km.open_db(db)
        assert conn is not None
        try:
            snap = km.take_snapshot(conn)
        finally:
            conn.close()
        assert snap.total_theories == 2
        assert snap.total_experiments == 3
        # e2 (abc123 verifier, theory completed) → active=1
        # e3-leaked (def456 local_rerun, theory eliminated) → audit_unclosed=1, NOT active
        assert snap.active_experiments == 1
        assert snap.audit_unclosed == 1
        assert snap.fab_count == 1            # the override row
        # abc123 is approved (non-terminal, score 18) → signal bin
        # def456 is eliminated (terminal, score 24) → counted in fab_count, not bins
        assert snap.score_bins["signal"] == 1
        assert snap.score_bins["review_24"] == 0
        # Top rows should reflect override flag.
        ids = {r.hypothesis_id: r.is_kernel_override for r in snap.top_rows}
        assert ids.get("def456") is True
        assert ids.get("abc123") is False
        # Outcome and failure reason flow through from DB (richer than log).
        by_id = {r.hypothesis_id: r for r in snap.top_rows}
        assert "Bean equality" in by_id["abc123"].outcome_summary
        assert "kernel re-derived" in by_id["def456"].failure_reason

    def test_card_render_includes_outcome_text(self):
        """The card renderer must surface the un-truncated outcome_summary
        from the DB; this is the dashboard fix for the upstream log
        truncation that clips synthesis previews mid-word.
        """
        from rich.console import Console as RichConsole

        snap, _, _ = km.make_demo_state(seed=11, cycle_phase=2)
        c = RichConsole(record=True, width=240, height=70, file=io.StringIO(), safe_box=True)
        c.print(km.render_top_hypotheses_cards(snap, max_rows=5, inner_width=220))
        out = c.export_text()
        # The demo's first 3 cards have an outcome_summary block.
        assert "outcome" in out
        assert "Bean equality k[27]=k[65]" in out

    def test_open_db_missing(self, tmp_path):
        assert km.open_db(tmp_path / "nope.sqlite") is None


# ─── render smoke tests ─────────────────────────────────────────────


def _render_once(layout_name: str, width: int, height: int, demo: bool = True) -> str:
    """Render one frame to a recording Console; return the captured text."""
    from rich.console import Console as RichConsole

    console = RichConsole(record=True, width=width, height=height, file=io.StringIO(), safe_box=True)
    snap, tail, activity = km.make_demo_state(seed=7, cycle_phase=4)
    rend = km.compose(
        snap=snap,
        tail=tail,
        activity=activity,
        db_path=Path("(demo)"),
        log_path=None,
        width=width,
        height=height,
        frame=3,
        fps=8.0,
        db_interval=1.5,
        last_render_s=0.005,
        layout_name=layout_name,
        demo=True,
    )
    console.print(rend)
    return console.export_text()


class TestRenderSmoke:
    def test_compact(self):
        out = _render_once("compact", 130, 35)
        assert "KryptosBot" in out
        assert "DEMO" in out

    def test_wide(self):
        out = _render_once("wide", 180, 45)
        assert "KryptosBot" in out
        assert "DEMO" in out

    def test_ultrawide(self):
        out = _render_once("ultrawide", 280, 80)
        assert "KryptosBot" in out
        assert "DEMO" in out
        # Top hypotheses should appear
        assert "Top Hypotheses" in out

    def test_tiny(self):
        out = _render_once("tiny", 100, 22)
        assert "KryptosBot" in out

    def test_too_small_renders_warning(self):
        from rich.console import Console as RichConsole

        c = RichConsole(record=True, width=70, height=14, file=io.StringIO(), safe_box=True)
        rend = km.compose(
            snap=None,
            tail=km.LogTail(path=None),
            activity=km.Activity(state="IDLE", phase="idle", detail="", show_spinner=False),
            db_path=Path("(demo)"),
            log_path=None,
            width=70,
            height=14,
            frame=0,
            fps=8.0,
            db_interval=1.5,
            last_render_s=0.0,
            layout_name="tiny",
            demo=True,
        )
        c.print(rend)
        out = c.export_text()
        assert "too small" in out.lower() or "Terminal" in out

    def test_kernel_override_visible_in_render(self):
        out = _render_once("ultrawide", 260, 70)
        snap, _, _ = km.make_demo_state(seed=7, cycle_phase=4)
        # cycle_phase=4 has fab_count=1
        assert snap.fab_count >= 1
        # Either the score bin or the operational state surfaces overrides.
        assert "KERNEL" in out or "OVERRIDE" in out or "kernel" in out

    def test_safe_renderable_catches_exception(self):
        def boom():
            raise RuntimeError("boom")

        renderable = km.safe_renderable("test", boom)
        from rich.console import Console as RichConsole

        c = RichConsole(record=True, width=80, height=20, file=io.StringIO(), safe_box=True)
        c.print(renderable)
        out = c.export_text()
        assert "render error in test" in out
        assert "boom" in out


class TestMainOnce:
    def test_demo_once_returns_zero(self):
        rc = km.main(["--demo", "--once", "--layout", "wide"])
        assert rc == 0
