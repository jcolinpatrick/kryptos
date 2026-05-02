#!/usr/bin/env python3
"""KryptosBot Telemetry — operations-grade live monitor.

Reads the theory ledger SQLite database and the controller log to render
a NOC/SOC-style dashboard for long-running KryptosBot campaigns.
Designed for Windows Terminal / PowerShell at 4K resolution but adapts
to compact and tiny terminal sizes.

Telemetry sources (read-only):
  * theories, experiments, anomalies, pursuit_leads tables
  * ledger_metadata.synthetic_mode (real-K4 vs synthetic taint)
  * controller_state.state JSON (cycle, halt reason, active experiments)
  * log file event stream (tail-and-classify)

Activity indicators are driven by observed state only; a spinner only
animates while the matching event is recent.

Usage:
    python3 k4_monitor.py
    python3 k4_monitor.py --log results/long_run_*.log
    python3 k4_monitor.py --db db/theory_ledger.sqlite --fps 8
    python3 k4_monitor.py --demo                       # synthetic preview
    python3 k4_monitor.py --once                       # single-frame render
    python3 k4_monitor.py --layout compact             # force layout
"""

from __future__ import annotations

import argparse
import glob
import io
import json
import logging
import os
import random
import re
import sqlite3
import sys
import time
import traceback
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

from rich import box
from rich.align import Align
from rich.columns import Columns
from rich.console import Console, Group, RenderableType
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


# ─────────────────────────────────────────────────────────────────────
# Palette — restrained operational semantics. Named colors prefered for
# Windows Terminal compatibility; hex used only for subtle backgrounds.
# ─────────────────────────────────────────────────────────────────────

GREEN = "green"          # healthy / approved / completed / signal
GREEN_DIM = "dark_green"
AMBER = "yellow"         # warning / review / interesting / in-progress
AMBER_DIM = "dark_goldenrod"
RED = "red"              # rejection / error / kernel override / contradiction
RED_DIM = "dark_red"
CYAN = "cyan"            # neutral identifiers
BLUE = "blue"            # links / paths
WHITE = "white"          # primary numerics / values
LABEL = "grey62"         # field labels
DIM = "grey50"           # historical / muted
DARK = "grey37"          # inactive scaffolding
TITLE = "bold white"

# Status to color mapping for ledger / verdict words.
STATUS_COLOR = {
    "proposed": CYAN,
    "approved": GREEN,
    "completed": GREEN,
    "criticized": AMBER,
    "promising": AMBER,
    "eliminated": DIM,
    "withdrawn": DARK,
    "fabricated": RED,
}
VERDICT_COLOR = {
    "approve": GREEN,
    "concern": AMBER,
    "concerned": AMBER,
    "reject": RED,
    "fabrication": RED,
    "skip": DIM,
    "skip_low_information": DIM,
    "pass": GREEN,
}

SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SCORE_NOISE_MAX = 9
SCORE_INTEREST_MAX = 17
SCORE_SIGNAL_MAX = 23

LOG = logging.getLogger("k4_monitor")


# ─────────────────────────────────────────────────────────────────────
# Helpers — truncation, wrapping, time formatting, rendering safety.
# ─────────────────────────────────────────────────────────────────────


def truncate_middle(s: str, max_width: int, marker: str = "…") -> str:
    """Truncate keeping prefix and suffix; loses the middle, not the tail.

    Verdict text and hash IDs commonly live at the END of long lines, so
    prefix-only ellipsis discards the most informative portion.
    """
    if max_width <= 0 or not s:
        return ""
    if len(s) <= max_width:
        return s
    if max_width <= len(marker):
        return marker[:max_width]
    keep = max_width - len(marker)
    head = keep // 2 + (keep % 2)
    tail = keep - head
    if tail == 0:
        return s[:head] + marker
    return s[:head] + marker + s[-tail:]


def truncate_end(s: str, max_width: int, marker: str = "…") -> str:
    if max_width <= 0 or not s:
        return ""
    if len(s) <= max_width:
        return s
    if max_width <= len(marker):
        return marker[:max_width]
    return s[: max_width - len(marker)] + marker


def humanize_age(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    s = int(max(0, seconds))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m{s % 60:02d}s"
    h, r = divmod(s, 3600)
    return f"{h}h{r // 60:02d}m"


def humanize_duration(seconds: float | None) -> str:
    if seconds is None:
        return "--:--:--"
    s = int(max(0, seconds))
    h, r = divmod(s, 3600)
    m, sec = divmod(r, 60)
    return f"{h:02d}:{m:02d}:{sec:02d}"


def parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


def age_seconds(when: datetime | None, now: datetime | None = None) -> float | None:
    if when is None:
        return None
    if now is None:
        now = datetime.now(timezone.utc)
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (now - when).total_seconds())


def safe_renderable(label: str, fn, *args, **kwargs) -> RenderableType:
    """Wrap a render call so a single panel failure cannot crash the loop."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 — final UI layer must not throw
        LOG.warning("render %s failed: %s", label, exc)
        body = Text()
        body.append(f"[render error in {label}]\n", style=f"bold {RED}")
        body.append(truncate_end(str(exc), 200), style=DIM)
        return body


# ─────────────────────────────────────────────────────────────────────
# Log tail — classifies events by category, keeps bounded ring buffers.
# ─────────────────────────────────────────────────────────────────────

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
CYCLE_RE = re.compile(r"CYCLE\s+(\d+)\s*/\s*(\d+)")
LOG_TS_RE = re.compile(r"^\s*(\d{2}:\d{2}:\d{2})")

# Categories ordered roughly by severity / interest.
EVENT_CATEGORIES = (
    "KERNEL",     # kernel override / fabrication caught
    "SIGNAL",     # high-score event
    "BREAKTHROUGH",
    "REDTEAM",    # red-team verdicts
    "VERIFIER",   # verifier rejection / approval
    "CRITIC",     # critic decisions
    "DISPATCH",   # cycle/dispatch markers
    "WORKER",     # worker completions
    "LEDGER",     # ledger writes
    "ANOMALY",    # anomaly opened/closed
    "WARN",       # warnings/errors
    "PHASE",      # phase markers
)

EVENT_STYLE = {
    "KERNEL": f"bold {RED}",
    "SIGNAL": f"bold {GREEN}",
    "BREAKTHROUGH": f"bold {AMBER}",
    "REDTEAM": AMBER,
    "VERIFIER": AMBER,
    "CRITIC": CYAN,
    "DISPATCH": CYAN,
    "WORKER": WHITE,
    "LEDGER": DIM,
    "ANOMALY": AMBER,
    "WARN": RED,
    "PHASE": CYAN,
    "OTHER": DIM,
}

EVENT_GLYPH = {
    "KERNEL": "✗",
    "SIGNAL": "▲",
    "BREAKTHROUGH": "?",
    "REDTEAM": "⚠",
    "VERIFIER": "·",
    "CRITIC": "✓",
    "DISPATCH": "▸",
    "WORKER": "·",
    "LEDGER": "·",
    "ANOMALY": "◆",
    "WARN": "!",
    "PHASE": "▸",
    "OTHER": "·",
}


# System-error phrases. Bare "error" is too loose — KryptosBot theories
# routinely reference K1 IQLUSION / K2 UNDERGRUUND / hand-error / transcription
# error / error analog as content, none of which are system errors.
SYSTEM_ERROR_PHRASES = (
    "fatal error",
    "traceback (most recent call last)",
    "exception in worker",
    "uncaught exception",
    "error output:",
    "exit code 1",
    "command failed with exit code",
    "internal error:",
)
# Strict WARN patterns: starts with ERROR/WARN, all-caps WARNING, or has the
# distinctive bracketed forms.
SYSTEM_WARN_RE = re.compile(
    r"(^\s*(ERROR|WARN(ING)?)\b|"
    r"\bWARNING:\s|\bWARN:\s|"
    r"\[ERROR\]|\[WARN\]|\[WARNING\])"
)


def classify_event(line: str) -> str | None:
    """Return event category or None if line is uninteresting.

    Order matters: highest-severity / least-ambiguous categories come first.
    System-error detection precedes WORKER/CRITIC/DISPATCH so a line like
    "[ERROR] worker subprocess died" classifies as WARN rather than WORKER.
    Content references to plaintext typos (K1 IQLUSION error, K2 UNDERGRUUND
    error, hand-error perturbation, transcription error) deliberately fall
    through to None — they are not system events.
    """
    upper = line.upper()
    lower = line.lower()
    if "KERNEL OVERRULE" in upper or "KERNEL OVERRIDE" in upper:
        return "KERNEL"
    if "FABRICATION" in upper or "FABRICATED" in upper:
        return "KERNEL"
    if "BREAKTHROUGH" in upper:
        return "BREAKTHROUGH"
    if re.search(r"\bSIGNAL\b", line) and ("crib" in lower or "score" in lower or "PROMISING" in upper):
        return "SIGNAL"
    # System errors / warnings before content categories.
    if any(p in lower for p in SYSTEM_ERROR_PHRASES):
        return "WARN"
    if SYSTEM_WARN_RE.search(line):
        return "WARN"
    if "RED-TEAM" in upper or "RED_TEAM" in upper or "REDTEAM" in upper:
        return "REDTEAM"
    if "VERIFIER" in upper or " VERIF" in upper:
        return "VERIFIER"
    if "CRITIC" in upper or "APPROVED" in upper or "REJECTED" in upper:
        return "CRITIC"
    if "DISPATCH" in upper or CYCLE_RE.search(line):
        return "DISPATCH"
    if "WORKER" in upper or "COMPLETED" in upper:
        return "WORKER"
    if "LEDGER" in upper or "WROTE" in upper:
        return "LEDGER"
    if "ANOMALY" in upper or "ANOMALIES" in upper:
        return "ANOMALY"
    if "PHASE" in upper or "GENERATE" in upper:
        return "PHASE"
    return None


@dataclass
class Event:
    when: datetime
    category: str
    line: str

    def timestamp(self) -> str:
        return self.when.strftime("%H:%M:%S")


class LogTail:
    """Bounded log tailer that classifies events and tracks cycle progress."""

    def __init__(
        self,
        path: Path | None,
        max_events: int = 200,
        max_alerts: int = 30,
    ) -> None:
        self.path = path
        self.pos = 0
        self.tail_buf = ""
        self.events: deque[Event] = deque(maxlen=max_events)
        self.alerts: deque[Event] = deque(maxlen=max_alerts)
        self.cycle_current = 0
        self.cycle_total = 0
        self.run_start: datetime | None = None
        self.eta_first_seen: datetime | None = None
        self.eta_first_value: int | None = None
        self.last_event_at: datetime | None = None
        # Per-category last-seen timestamps drive activity inference.
        self.last_by_category: dict[str, datetime] = {}
        if path and path.exists():
            try:
                self.run_start = datetime.fromtimestamp(path.stat().st_ctime)
            except OSError:
                pass

    def poll(self) -> None:
        if self.path is None or not self.path.exists():
            return
        if self.run_start is None:
            try:
                self.run_start = datetime.fromtimestamp(self.path.stat().st_ctime)
            except OSError:
                pass
        try:
            size = self.path.stat().st_size
            if size < self.pos:
                # File truncated/rotated.
                self.pos = 0
                self.tail_buf = ""
            with self.path.open("r", errors="replace") as f:
                f.seek(self.pos)
                chunk = f.read()
                self.pos = f.tell()
        except OSError:
            return
        if not chunk:
            return
        text = self.tail_buf + chunk
        if text.endswith("\n"):
            self.tail_buf = ""
            raw_lines = text.splitlines()
        else:
            raw_lines = text.splitlines()
            self.tail_buf = raw_lines[-1] if raw_lines else ""
            raw_lines = raw_lines[:-1]
        for raw in raw_lines:
            line = ANSI_RE.sub("", raw).rstrip()
            if not line or len(line.strip()) < 3:
                continue
            self._process(line)

    def _process(self, line: str) -> None:
        m = CYCLE_RE.search(line)
        if m:
            cur, total = int(m.group(1)), int(m.group(2))
            self.cycle_current = cur
            self.cycle_total = total
            if self.eta_first_seen is None:
                self.eta_first_seen = datetime.now()
                self.eta_first_value = cur
        category = classify_event(line)
        if category is None:
            return
        now = datetime.now()
        ev = Event(when=now, category=category, line=line)
        self.events.append(ev)
        self.last_event_at = now
        self.last_by_category[category] = now
        if category in ("KERNEL", "SIGNAL", "BREAKTHROUGH", "REDTEAM", "WARN"):
            self.alerts.append(ev)

    def eta(self) -> tuple[float | None, str]:
        """Return (remaining_seconds, finish_clock_HH:MM)."""
        if (
            self.eta_first_seen is None
            or self.eta_first_value is None
            or self.cycle_total == 0
            or self.cycle_current <= self.eta_first_value
        ):
            return (None, "--:--")
        elapsed = (datetime.now() - self.eta_first_seen).total_seconds()
        done = self.cycle_current - self.eta_first_value
        remaining = max(0, self.cycle_total - self.cycle_current)
        if done <= 0:
            return (None, "--:--")
        per_cycle = elapsed / done
        rem_seconds = per_cycle * remaining
        finish_dt = datetime.now() + timedelta(seconds=rem_seconds)
        return (rem_seconds, finish_dt.strftime("%H:%M"))


# ─────────────────────────────────────────────────────────────────────
# Snapshot + take_snapshot — read-only DB inspection.
# ─────────────────────────────────────────────────────────────────────


@dataclass
class TopRow:
    hypothesis_id: str
    family: str
    status: str
    score: float
    plaintext: str
    title: str
    verdict: str  # "approve" / "concern" / "reject" / "skip" / ""
    verdict_reason: str
    outcome_summary: str  # full untruncated synthesis text from DB
    failure_reason: str   # full untruncated failure reason from DB
    updated_at: datetime | None
    is_kernel_override: bool


@dataclass
class Snapshot:
    mode: str = "unknown"
    total_theories: int = 0
    total_experiments: int = 0
    active_experiments: int = 0       # in flight: no completed_at AND theory.status not terminal
    audit_unclosed: int = 0           # leaked: no completed_at BUT theory.status IS terminal
    status: dict[str, int] = field(default_factory=dict)
    fab_count: int = 0                # score>=24 AND eliminated (kernel override caught)
    families: list[tuple[str, int]] = field(default_factory=list)
    workers: list[tuple[str, int]] = field(default_factory=list)
    score_bins: dict[str, int] = field(default_factory=dict)
    critic: Counter = field(default_factory=Counter)
    critic_total: int = 0
    pursuit_open: int = 0
    pursuit_recent: int = 0
    pursuit_closed: int = 0
    anomaly_open: int = 0
    anomaly_total: int = 0
    top_rows: list[TopRow] = field(default_factory=list)
    throughput_history: list[int] = field(default_factory=list)
    rate_5: float = 0.0
    n_5: int = 0
    rate_60: float = 0.0
    n_60: int = 0
    session_start: datetime | None = None
    last_theory_update: datetime | None = None
    last_exp_start: datetime | None = None
    last_exp_complete: datetime | None = None
    # Controller state JSON (if present).
    controller_cycle: int | None = None
    controller_proposed: int | None = None
    controller_tested: int | None = None
    controller_eliminated: int | None = None
    controller_promising: int | None = None
    controller_active_exps: int | None = None
    controller_last_cycle_at: datetime | None = None
    controller_halt_reason: str = ""
    controller_consecutive_d_zero: int = 0
    controller_theorist_fallbacks: int = 0
    controller_underexplored: list[str] = field(default_factory=list)
    controller_open_anomalies: list[str] = field(default_factory=list)
    taken_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def open_db(path: Path) -> sqlite3.Connection | None:
    if not path.exists():
        return None
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.Error as exc:
        LOG.warning("open_db failed: %s", exc)
        return None


def _safe_query(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    try:
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []


def _safe_scalar(conn: sqlite3.Connection, sql: str, params: tuple = (), default=0):
    try:
        row = conn.execute(sql, params).fetchone()
        return row[0] if row and row[0] is not None else default
    except sqlite3.OperationalError:
        return default


def _parse_critic_verdict(blob: str) -> tuple[str, str]:
    if not blob or blob in ("", "{}"):
        return ("", "")
    try:
        v = json.loads(blob)
    except (json.JSONDecodeError, TypeError):
        return ("", "")
    decision = (v.get("decision") or "").lower()
    reasons = v.get("reasons") or []
    reason = reasons[0] if reasons else ""
    if isinstance(reason, str):
        reason = reason.strip()
    return (decision, reason)


def take_snapshot(conn: sqlite3.Connection) -> Snapshot:
    s = Snapshot()
    row = _safe_query(conn, "SELECT value FROM ledger_metadata WHERE key='synthetic_mode'")
    s.mode = row[0][0] if row else "unknown"

    s.total_theories = _safe_scalar(conn, "SELECT COUNT(*) FROM theories")
    s.total_experiments = _safe_scalar(conn, "SELECT COUNT(*) FROM experiments")
    # An experiment is in flight only if (a) it has no completed_at AND
    # (b) its owning theory is still in a non-terminal status. Otherwise the
    # experiment row was leaked by a worker codepath that closed the theory
    # without closing the experiment (e.g. SDK transport failures, bootstrap
    # local_rerun path), and counting it as active misleads the operator.
    TERMINAL_STATUSES = (
        "eliminated", "completed", "withdrawn", "rejected_admissibility",
        "rejected", "fabricated",
    )
    placeholders = ",".join("?" * len(TERMINAL_STATUSES))
    s.active_experiments = _safe_scalar(
        conn,
        f"""
        SELECT COUNT(*) FROM experiments e
        LEFT JOIN theories t ON e.hypothesis_id = t.hypothesis_id
        WHERE (e.completed_at IS NULL OR e.completed_at = '')
          AND (t.status IS NULL OR t.status NOT IN ({placeholders}))
        """,
        TERMINAL_STATUSES,
    )
    s.audit_unclosed = _safe_scalar(
        conn,
        f"""
        SELECT COUNT(*) FROM experiments e
        JOIN theories t ON e.hypothesis_id = t.hypothesis_id
        WHERE (e.completed_at IS NULL OR e.completed_at = '')
          AND t.status IN ({placeholders})
        """,
        TERMINAL_STATUSES,
    )
    s.last_theory_update = parse_iso(
        _safe_scalar(conn, "SELECT MAX(updated_at) FROM theories", default=None)
    )
    s.last_exp_complete = parse_iso(
        _safe_scalar(
            conn,
            "SELECT MAX(completed_at) FROM experiments WHERE completed_at != ''",
            default=None,
        )
    )
    s.last_exp_start = parse_iso(
        _safe_scalar(
            conn,
            "SELECT MAX(started_at) FROM experiments WHERE started_at != ''",
            default=None,
        )
    )

    for r in _safe_query(conn, "SELECT status, COUNT(*) FROM theories GROUP BY status"):
        s.status[r[0]] = r[1]

    s.fab_count = _safe_scalar(
        conn,
        "SELECT COUNT(*) FROM theories WHERE best_score >= 24 AND status = 'eliminated'",
    )

    s.families = [
        (r[0], r[1])
        for r in _safe_query(
            conn,
            "SELECT family, COUNT(*) FROM theories WHERE family != '' "
            "GROUP BY family ORDER BY COUNT(*) DESC LIMIT 8",
        )
    ]
    s.workers = [
        (r[0], r[1])
        for r in _safe_query(
            conn,
            "SELECT worker_role, COUNT(*) FROM experiments WHERE worker_role != '' "
            "GROUP BY worker_role ORDER BY COUNT(*) DESC LIMIT 8",
        )
    ]

    bins = {"noise": 0, "interesting": 0, "signal": 0, "review_24": 0}
    for r in _safe_query(conn, "SELECT best_score, status FROM theories"):
        sc = r[0] or 0
        st = r[1]
        if sc >= 24 and st == "eliminated":
            continue  # counted in fab
        if sc >= 24:
            bins["review_24"] += 1
        elif sc >= 18:
            bins["signal"] += 1
        elif sc >= 10:
            bins["interesting"] += 1
        elif sc > 0:
            bins["noise"] += 1
    s.score_bins = bins

    crit_counts: Counter = Counter()
    crit_total = 0
    for r in _safe_query(
        conn,
        "SELECT critic_verdict FROM theories WHERE critic_verdict NOT IN ('', '{}')",
    ):
        decision, _ = _parse_critic_verdict(r[0])
        if decision:
            crit_counts[decision] += 1
            crit_total += 1
    s.critic = crit_counts
    s.critic_total = crit_total

    s.pursuit_open = _safe_scalar(
        conn, "SELECT COUNT(*) FROM pursuit_leads WHERE status = 'open'"
    )
    s.pursuit_closed = _safe_scalar(
        conn, "SELECT COUNT(*) FROM pursuit_leads WHERE status != 'open'"
    )
    s.pursuit_recent = _safe_scalar(
        conn,
        "SELECT COUNT(*) FROM pursuit_leads WHERE opened_at >= ?",
        ((datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),),
    )
    s.anomaly_open = _safe_scalar(
        conn, "SELECT COUNT(*) FROM anomalies WHERE status = 'open'"
    )
    s.anomaly_total = _safe_scalar(conn, "SELECT COUNT(*) FROM anomalies")

    rows = _safe_query(
        conn,
        "SELECT hypothesis_id, family, status, best_score, best_plaintext, "
        "title, critic_verdict, updated_at, outcome_summary, failure_reason "
        "FROM theories WHERE best_score > 0 "
        "ORDER BY best_score DESC, updated_at DESC LIMIT 12",
    )
    for r in rows:
        decision, reason = _parse_critic_verdict(r[6] or "")
        sc = r[3] or 0
        is_override = sc >= 24 and r[2] == "eliminated"
        s.top_rows.append(
            TopRow(
                hypothesis_id=r[0] or "",
                family=r[1] or "",
                status=r[2] or "",
                score=sc,
                plaintext=r[4] or "",
                title=r[5] or "",
                verdict=decision,
                verdict_reason=reason,
                outcome_summary=(r[8] or "").strip(),
                failure_reason=(r[9] or "").strip(),
                updated_at=parse_iso(r[7]),
                is_kernel_override=is_override,
            )
        )

    cutoff_60 = (datetime.now(timezone.utc) - timedelta(minutes=60)).isoformat()
    bins60 = [0] * 60
    now_utc = datetime.now(timezone.utc)
    for r in _safe_query(
        conn, "SELECT created_at FROM theories WHERE created_at >= ?", (cutoff_60,)
    ):
        ts = parse_iso(r[0])
        if ts is None:
            continue
        delta = int((now_utc - ts).total_seconds() // 60)
        if 0 <= delta < 60:
            bins60[60 - 1 - delta] += 1
    s.throughput_history = bins60

    cutoff_5 = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
    s.n_5 = _safe_scalar(conn, "SELECT COUNT(*) FROM theories WHERE created_at >= ?", (cutoff_5,))
    s.rate_5 = s.n_5 / 5.0
    s.n_60 = sum(bins60)
    s.rate_60 = s.n_60 / 60.0

    s.session_start = parse_iso(_safe_scalar(conn, "SELECT MIN(created_at) FROM theories", default=None))

    rows = _safe_query(conn, "SELECT state FROM controller_state ORDER BY id DESC LIMIT 1")
    if rows:
        try:
            d = json.loads(rows[0][0])
        except (json.JSONDecodeError, TypeError):
            d = {}
        s.controller_cycle = d.get("cycle_number")
        s.controller_proposed = d.get("theories_proposed")
        s.controller_tested = d.get("theories_tested")
        s.controller_eliminated = d.get("theories_eliminated")
        s.controller_promising = d.get("theories_promising")
        ae = d.get("active_experiments") or []
        if isinstance(ae, list):
            s.controller_active_exps = len(ae)
        s.controller_last_cycle_at = parse_iso(d.get("last_cycle_at"))
        s.controller_halt_reason = d.get("halt_reason_hardening") or ""
        s.controller_consecutive_d_zero = d.get("consecutive_d_zero_cycles") or 0
        s.controller_theorist_fallbacks = d.get("theorist_fallbacks") or 0
        s.controller_underexplored = list(d.get("underexplored_families") or [])
        s.controller_open_anomalies = list(d.get("open_anomalies") or [])

    return s


# ─────────────────────────────────────────────────────────────────────
# Activity inference — derives operational phase strictly from observed
# state (event recency, active workers, halt reason). No fakery.
# ─────────────────────────────────────────────────────────────────────


@dataclass
class Activity:
    state: str            # RUNNING / PAUSED / IDLE / ERROR / STARTING
    phase: str            # human label of currently-active phase
    detail: str           # short context
    show_spinner: bool
    bottleneck: str | None = None
    last_event_age_s: float | None = None
    active_workers: int = 0
    pending_workers: int = 0
    last_ledger_write_age_s: float | None = None
    last_verifier_age_s: float | None = None
    last_dispatch_age_s: float | None = None


def _category_age(tail: LogTail, category: str) -> float | None:
    when = tail.last_by_category.get(category)
    if when is None:
        return None
    return max(0.0, (datetime.now() - when).total_seconds())


def derive_activity(snap: Snapshot, tail: LogTail) -> Activity:
    last_event_age = (
        (datetime.now() - tail.last_event_at).total_seconds()
        if tail.last_event_at
        else None
    )
    # Ledger age is the freshest of any DB write — any of the three timestamps
    # signals recent ledger activity. Using only theories.updated_at understates
    # liveness when workers are writing experiments without bumping best_score.
    ledger_ts_candidates = [
        ts for ts in (snap.last_theory_update, snap.last_exp_start, snap.last_exp_complete)
        if ts is not None
    ]
    last_ledger_age = (
        min(age_seconds(ts) for ts in ledger_ts_candidates) if ledger_ts_candidates else None
    )
    last_verifier_age = _category_age(tail, "VERIFIER") or _category_age(tail, "CRITIC")
    last_dispatch_age = _category_age(tail, "DISPATCH") or _category_age(tail, "PHASE")
    last_redteam_age = _category_age(tail, "REDTEAM")
    last_kernel_age = _category_age(tail, "KERNEL")
    active_workers = max(snap.active_experiments, snap.controller_active_exps or 0)

    # Hard signals first.
    if snap.controller_halt_reason:
        return Activity(
            state="ERROR",
            phase="HALTED",
            detail=truncate_end(snap.controller_halt_reason, 90),
            show_spinner=False,
            bottleneck="halt_reason_hardening",
            last_event_age_s=last_event_age,
            active_workers=active_workers,
            last_ledger_write_age_s=last_ledger_age,
            last_verifier_age_s=last_verifier_age,
            last_dispatch_age_s=last_dispatch_age,
        )
    if last_kernel_age is not None and last_kernel_age < 30:
        return Activity(
            state="RUNNING",
            phase="KERNEL OVERRIDE",
            detail="verifier rejected worker self-report",
            show_spinner=False,
            bottleneck=None,
            last_event_age_s=last_event_age,
            active_workers=active_workers,
            last_ledger_write_age_s=last_ledger_age,
            last_verifier_age_s=last_verifier_age,
            last_dispatch_age_s=last_dispatch_age,
        )

    # State == engine operational state. Mode (REAL-K4 vs SYNTHETIC/DEMO) is
    # tracked separately as a data-taint badge in the header; we deliberately
    # do NOT collapse "running real-K4 work" into PAUSED based on project
    # doctrine, because that hides whether the engine is actually healthy.

    # Phase inference by recency: nearest-recent category wins.
    candidates: list[tuple[float, str, str]] = []  # (age_seconds, phase, detail)
    if last_redteam_age is not None and last_redteam_age < 60:
        candidates.append((last_redteam_age, "RED-TEAM", "adversarial review"))
    if last_verifier_age is not None and last_verifier_age < 60:
        candidates.append((last_verifier_age, "VERIFY", "critic / verifier checks"))
    if last_dispatch_age is not None and last_dispatch_age < 60:
        candidates.append((last_dispatch_age, "DISPATCH", "theorist generating"))
    worker_age = _category_age(tail, "WORKER")
    if worker_age is not None and worker_age < 60:
        candidates.append((worker_age, "WORKER", "worker completion stream"))
    if active_workers > 0:
        candidates.append((0.0, "WORKERS", f"{active_workers} active experiment(s)"))

    if not candidates:
        if last_event_age is None:
            state = "STARTING" if snap.total_theories == 0 else "IDLE"
            phase = "starting" if state == "STARTING" else "idle"
            detail = "awaiting first event"
            spin = state == "STARTING"
        elif last_event_age > 120:
            state = "IDLE"
            phase = "idle"
            detail = f"no events for {humanize_age(last_event_age)}"
            spin = False
        else:
            state = "RUNNING"
            phase = "running"
            detail = "between phases"
            spin = True
        return Activity(
            state=state,
            phase=phase,
            detail=detail,
            show_spinner=spin,
            last_event_age_s=last_event_age,
            active_workers=active_workers,
            last_ledger_write_age_s=last_ledger_age,
            last_verifier_age_s=last_verifier_age,
            last_dispatch_age_s=last_dispatch_age,
        )

    candidates.sort(key=lambda c: c[0])
    age, phase, detail = candidates[0]
    state = "RUNNING"
    show_spinner = age < 30

    bottleneck = None
    if active_workers > 0 and worker_age is not None and worker_age > 90:
        bottleneck = f"{active_workers} workers in flight, no completion >{int(worker_age)}s"
    elif last_dispatch_age is not None and last_dispatch_age > 180 and last_event_age is not None and last_event_age < 30:
        bottleneck = "no dispatch markers; verifier loop only"
    elif snap.controller_consecutive_d_zero > 3:
        bottleneck = f"D=0 for {snap.controller_consecutive_d_zero} consecutive cycles"

    return Activity(
        state=state,
        phase=phase,
        detail=detail,
        show_spinner=show_spinner,
        bottleneck=bottleneck,
        last_event_age_s=last_event_age,
        active_workers=active_workers,
        last_ledger_write_age_s=last_ledger_age,
        last_verifier_age_s=last_verifier_age,
        last_dispatch_age_s=last_dispatch_age,
    )


# ─────────────────────────────────────────────────────────────────────
# Layout selection — adapts to terminal width.
# ─────────────────────────────────────────────────────────────────────


def pick_layout(width: int, height: int) -> str:
    if width < 100 or height < 20:
        return "tiny"
    if width < 160:
        return "compact"
    if width < 210:
        return "wide"
    return "ultrawide"


def too_small(width: int, height: int) -> bool:
    return width < 80 or height < 14


# ─────────────────────────────────────────────────────────────────────
# Rendering — stateless, deterministic from (snap, tail, activity, frame).
# ─────────────────────────────────────────────────────────────────────


def spinner_char(frame: int) -> str:
    return SPINNER_FRAMES[frame % len(SPINNER_FRAMES)]


def render_state_badge(activity: Activity) -> Text:
    state = activity.state
    if state == "RUNNING":
        return Text(" RUNNING ", style=f"bold reverse {GREEN}")
    if state == "PAUSED":
        return Text(" PAUSED ", style=f"bold reverse {AMBER}")
    if state == "IDLE":
        return Text(" IDLE ", style=f"bold reverse {DIM}")
    if state == "ERROR":
        return Text(" ERROR ", style=f"bold reverse {RED}")
    if state == "STARTING":
        return Text(" STARTING ", style=f"bold reverse {CYAN}")
    return Text(f" {state} ", style=f"bold reverse {DIM}")


def render_mode_badge(mode: str) -> Text:
    m = (mode or "unknown").lower()
    if m == "real":
        return Text(" REAL-K4 ", style=f"bold reverse {RED}")
    if m in ("k4bench", "synthetic"):
        return Text(f" {m.upper()} ", style=f"bold reverse {AMBER}")
    if m == "demo":
        return Text(" DEMO ", style=f"bold reverse {CYAN}")
    return Text(f" {m.upper()} ", style=f"bold reverse {DIM}")


def render_header(
    snap: Snapshot,
    activity: Activity,
    tail: LogTail,
    db_path: Path,
    log_path: Path | None,
    frame: int,
    demo: bool,
) -> RenderableType:
    title = Text()
    title.append("KryptosBot Telemetry", style=TITLE)
    if demo:
        title.append("  ")
        title.append("[DEMO / SYNTHETIC]", style=f"bold {CYAN}")

    badges = Text()
    badges.append_text(render_state_badge(activity))
    badges.append("  ")
    badges.append_text(render_mode_badge("demo" if demo else snap.mode))

    elapsed_str = "--:--:--"
    if tail.run_start is not None:
        elapsed_str = humanize_duration((datetime.now() - tail.run_start).total_seconds())
    elif snap.session_start is not None:
        elapsed_str = humanize_duration(
            (datetime.now(timezone.utc) - snap.session_start).total_seconds()
        )

    rem_seconds, finish_clock = tail.eta()
    eta_str = humanize_duration(rem_seconds)

    meta = Text()
    meta.append("db ", style=LABEL)
    meta.append(db_path.name, style=BLUE)
    if log_path is not None:
        meta.append("   log ", style=LABEL)
        meta.append(log_path.name, style=BLUE)
    meta.append("\n")
    meta.append("now ", style=LABEL)
    meta.append(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), style=WHITE)
    meta.append("   elapsed ", style=LABEL)
    meta.append(elapsed_str, style=WHITE)
    meta.append("   eta ", style=LABEL)
    meta.append(eta_str, style=AMBER if rem_seconds else DIM)
    if finish_clock != "--:--":
        meta.append(f" (~{finish_clock})", style=DIM)

    grid = Table.grid(expand=True, padding=(0, 1))
    grid.add_column(justify="left", ratio=3)
    grid.add_column(justify="right", no_wrap=True, width=28)
    grid.add_row(title, badges)
    grid.add_row(meta, Text(""))
    return Panel(grid, box=box.SQUARE, border_style=DIM, padding=(0, 1))


def render_run_progress(snap: Snapshot, tail: LogTail, frame: int) -> RenderableType:
    """Cycle progress + throughput KPIs."""
    cycle_cur = tail.cycle_current or snap.controller_cycle or 0
    cycle_tot = tail.cycle_total or 0
    pct = (cycle_cur / cycle_tot * 100.0) if cycle_tot else 0.0

    bar_w = 32
    if cycle_tot:
        full = int((cycle_cur / cycle_tot) * bar_w)
    else:
        full = 0
    cycle_line = Text(no_wrap=True)
    cycle_line.append("█" * full, style=GREEN_DIM)
    cycle_line.append("░" * max(0, bar_w - full), style=DARK)
    cycle_line.append("  ")
    cycle_line.append(f"{cycle_cur:>4}", style=f"bold {WHITE}")
    cycle_line.append(" / ", style=DIM)
    cycle_line.append(f"{cycle_tot:<4}" if cycle_tot else "?   ", style=WHITE)
    cycle_line.append(f"  {pct:5.1f}%", style=AMBER if pct > 0 else DIM)

    body = Table.grid(expand=True, padding=(0, 1))
    body.add_column(style=LABEL, no_wrap=True, width=12)
    body.add_column(no_wrap=False, overflow="fold")

    body.add_row("cycle", cycle_line)

    th_line = Text()
    th_line.append(f"{snap.total_theories}", style=f"bold {WHITE}")
    th_line.append(f"   +{snap.n_5} in 5m", style=GREEN if snap.n_5 else DIM)
    th_line.append(f"   {snap.rate_5:.2f}/min", style=DIM)
    body.add_row("theories", th_line)

    ex_line = Text()
    ex_line.append(f"{snap.total_experiments}", style=f"bold {WHITE}")
    ex_line.append(f"   {snap.active_experiments} active", style=AMBER if snap.active_experiments else DIM)
    ex_line.append(f"   {snap.rate_60:.2f}/min (60m)", style=DIM)
    body.add_row("experiments", ex_line)

    if snap.controller_proposed is not None:
        ctrl_line = Text()
        ctrl_line.append(f"proposed {snap.controller_proposed}", style=DIM)
        ctrl_line.append(f"   tested {snap.controller_tested}", style=DIM)
        ctrl_line.append(f"   elim {snap.controller_eliminated}", style=DIM)
        ctrl_line.append(f"   promising {snap.controller_promising}", style=AMBER if (snap.controller_promising or 0) > 0 else DIM)
        body.add_row("controller", ctrl_line)
    return Panel(body, title="Run Progress", title_align="left", border_style=DIM, box=box.SQUARE, padding=(0, 1))


def render_operational_state(activity: Activity, snap: Snapshot, frame: int) -> RenderableType:
    body = Table.grid(expand=True, padding=(0, 1))
    body.add_column(style=LABEL, no_wrap=True, width=12)
    body.add_column()

    phase_text = Text()
    if activity.show_spinner:
        phase_text.append(spinner_char(frame), style=AMBER)
        phase_text.append(" ")
    else:
        phase_text.append("· ", style=DIM)
    phase_color = AMBER if activity.show_spinner else DIM
    if activity.state == "ERROR":
        phase_color = RED
    elif activity.state == "PAUSED":
        phase_color = AMBER
    elif activity.state == "RUNNING":
        phase_color = GREEN
    phase_text.append(activity.phase.upper(), style=f"bold {phase_color}")
    if activity.detail:
        phase_text.append("  ")
        phase_text.append(activity.detail, style=DIM)

    body.add_row("phase", phase_text)

    workers_text = Text()
    workers_text.append(f"{activity.active_workers} active", style=WHITE if activity.active_workers else DIM)
    if activity.active_workers > 0:
        workers_text.append("  ")
        workers_text.append(spinner_char(frame + 3), style=AMBER)
    body.add_row("workers", workers_text)

    body.add_row(
        "ledger",
        Text(
            f"last write {humanize_age(activity.last_ledger_write_age_s)} ago",
            style=DIM if activity.last_ledger_write_age_s and activity.last_ledger_write_age_s > 60 else WHITE,
        ),
    )
    body.add_row(
        "verifier",
        Text(f"last result {humanize_age(activity.last_verifier_age_s)} ago", style=DIM),
    )
    body.add_row(
        "dispatch",
        Text(f"last marker {humanize_age(activity.last_dispatch_age_s)} ago", style=DIM),
    )

    if snap.fab_count > 0:
        body.add_row(
            "kernel",
            Text(f"{snap.fab_count} override(s) caught lifetime", style=f"bold {RED}"),
        )
    else:
        body.add_row("kernel", Text("no overrides this run", style=DIM))

    if snap.audit_unclosed > 0:
        body.add_row(
            "audit",
            Text(
                f"{snap.audit_unclosed} unclosed experiment row(s) — theory terminal but completed_at empty",
                style=f"bold {AMBER}",
            ),
        )

    if activity.bottleneck:
        body.add_row(
            "bottleneck",
            Text(activity.bottleneck, style=f"bold {AMBER}"),
        )
    elif snap.controller_consecutive_d_zero > 0:
        body.add_row(
            "D-streak",
            Text(
                f"{snap.controller_consecutive_d_zero} consecutive D=0 cycle(s)",
                style=AMBER if snap.controller_consecutive_d_zero >= 3 else DIM,
            ),
        )

    border = RED if activity.state == "ERROR" else (AMBER if activity.bottleneck else DIM)
    return Panel(body, title="Operational State", title_align="left", border_style=border, box=box.SQUARE, padding=(0, 1))


def _bin_label(name: str, count: int, color: str) -> Text:
    t = Text()
    t.append(f"{name:<18}", style=LABEL)
    t.append(f"{count:>5}", style=f"bold {color}")
    return t


def render_research_summary(snap: Snapshot, columns: int = 3, sections: int = 6) -> RenderableType:
    """Compact KPI grid: status / scores / verdicts / leads / families / workers."""
    status_lines: list[Text] = []
    if snap.status:
        for st, n in sorted(snap.status.items(), key=lambda kv: -kv[1]):
            status_lines.append(_bin_label(st, n, STATUS_COLOR.get(st, WHITE)))
    else:
        status_lines.append(Text("(empty)", style=DIM))
    if snap.fab_count > 0:
        status_lines.append(_bin_label("KERNEL OVR", snap.fab_count, RED))

    bins = snap.score_bins or {}
    score_lines = [
        _bin_label("0–9   noise", bins.get("noise", 0), DIM),
        _bin_label("10–17 interest", bins.get("interesting", 0), CYAN),
        _bin_label("18–23 signal", bins.get("signal", 0), GREEN),
        _bin_label("24    review", bins.get("review_24", 0), AMBER),
    ]

    verdict_lines: list[Text] = []
    if snap.critic_total > 0:
        for d, n in snap.critic.most_common(6):
            color = WHITE
            for prefix, c in VERDICT_COLOR.items():
                if d.startswith(prefix):
                    color = c
                    break
            pct = n / snap.critic_total * 100
            t = Text()
            t.append(f"{d:<14}", style=LABEL)
            t.append(f"{n:>4}", style=f"bold {color}")
            t.append(f"  {pct:5.1f}%", style=DIM)
            verdict_lines.append(t)
    else:
        verdict_lines.append(Text("(none yet)", style=DIM))

    leads_lines = [
        _bin_label("open leads", snap.pursuit_open, AMBER if snap.pursuit_open else DIM),
        _bin_label("opened 60m", snap.pursuit_recent, GREEN if snap.pursuit_recent else DIM),
        _bin_label("closed", snap.pursuit_closed, DIM),
        _bin_label("anomalies open", snap.anomaly_open, AMBER if snap.anomaly_open else DIM),
        _bin_label("anomalies tot", snap.anomaly_total, DIM),
    ]

    families_lines: list[Text] = []
    if snap.families:
        for fam, n in snap.families[:6]:
            families_lines.append(_bin_label(fam, n, WHITE))
    else:
        families_lines.append(Text("(none)", style=DIM))

    workers_lines: list[Text] = []
    if snap.workers:
        for role, n in snap.workers[:6]:
            workers_lines.append(_bin_label(truncate_end(role, 16), n, WHITE))
    else:
        workers_lines.append(Text("(none)", style=DIM))

    all_sections: list[tuple[str, list[Text]]] = [
        ("STATUS", status_lines),
        ("SCORES", score_lines),
        ("VERDICTS", verdict_lines),
        ("LEADS / ANOMALIES", leads_lines),
        ("FAMILIES", families_lines),
        ("WORKER ROLES", workers_lines),
    ]
    selected = all_sections[:max(1, sections)]

    if columns >= 3:
        rows = [selected[i : i + 3] for i in range(0, len(selected), 3)]
    elif columns == 2:
        rows = [selected[i : i + 2] for i in range(0, len(selected), 2)]
    else:
        rows = [[sec] for sec in selected]

    grid = Table.grid(expand=True, padding=(0, 2))
    for _ in range(columns):
        grid.add_column(ratio=1)
    for row in rows:
        cells = []
        for label, lines in row:
            block = Text()
            block.append(label + "\n", style=f"bold {LABEL}")
            for ln in lines:
                block.append_text(ln)
                block.append("\n")
            cells.append(block)
        # pad if last row is short
        while len(cells) < columns:
            cells.append(Text(""))
        grid.add_row(*cells)
    return Panel(
        grid, title="Research Summary", title_align="left", border_style=DIM, box=box.SQUARE, padding=(0, 1)
    )


def _score_badge(row: TopRow) -> Text:
    sc = row.score
    if row.is_kernel_override:
        return Text(f" ✗ {sc:>3.0f} ", style=f"bold reverse {RED}")
    if sc >= 24:
        return Text(f" ? {sc:>3.0f} ", style=f"bold reverse {AMBER}")
    if sc >= 18:
        return Text(f" ▲ {sc:>3.0f} ", style=f"bold reverse {GREEN}")
    if sc >= 10:
        return Text(f"   {sc:>3.0f} ", style=f"bold {CYAN}")
    return Text(f"   {sc:>3.0f} ", style=DIM)


def _format_pt_preview(pt: str, max_width: int) -> str:
    if not pt:
        return "(no plaintext)"
    pt = pt.strip()
    if len(pt) <= max_width:
        return pt
    return truncate_middle(pt, max_width)


def render_top_hypotheses_cards(
    snap: Snapshot,
    max_rows: int,
    inner_width: int,
) -> RenderableType:
    rows = snap.top_rows[:max_rows]
    if not rows:
        return Panel(
            Text("awaiting first scored theory ...", style=DIM, justify="center"),
            title="Top Hypotheses",
            title_align="left",
            border_style=DIM,
            box=box.SQUARE,
        )

    blocks: list[RenderableType] = []
    for i, r in enumerate(rows, 1):
        head = Text()
        head.append(f"#{i:<2} ", style=DIM)
        head.append_text(_score_badge(r))
        head.append("  ")
        head.append(r.hypothesis_id[:12] or "—", style=BLUE)
        head.append("  ")
        head.append(r.family or "—", style=CYAN)
        head.append("   ")
        st_color = STATUS_COLOR.get(r.status, WHITE)
        head.append(f"{r.status.upper()}", style=f"bold {st_color}")
        if r.verdict:
            head.append("   verdict ", style=LABEL)
            v_color = WHITE
            for prefix, c in VERDICT_COLOR.items():
                if r.verdict.startswith(prefix):
                    v_color = c
                    break
            head.append(r.verdict.upper(), style=f"bold {v_color}")
        if r.updated_at:
            age = age_seconds(r.updated_at)
            head.append(f"   {humanize_age(age)} ago", style=DIM)

        # Title (wrapped, full text preserved by Rich's word wrap).
        title_block = Text(f"  {r.title}" if r.title else "  (untitled)", style=WHITE)
        title_block.no_wrap = False
        title_block.overflow = "fold"

        # Detail lines, in order of value: outcome (full synthesis), then
        # failure_reason (only if it adds info beyond outcome), then
        # verdict_reason as fallback. Each capped at ~500 chars via middle-
        # truncation so a single 1200-char outcome doesn't dominate the panel.
        body_lines: list[Text] = []
        outcome_cap = 500

        def _append_detail(label: str, text: str, color: str) -> None:
            if not text:
                return
            t = Text()
            t.append(f"  {label:<8}", style=LABEL)
            t.append(truncate_middle(text, outcome_cap), style=color)
            t.no_wrap = False
            t.overflow = "fold"
            body_lines.append(t)

        if r.outcome_summary:
            _append_detail("outcome", r.outcome_summary, WHITE)
        if r.failure_reason and (
            not r.outcome_summary
            or r.failure_reason[:120] not in r.outcome_summary
        ):
            _append_detail("failure", r.failure_reason, DIM)
        if not r.outcome_summary and not r.failure_reason and r.verdict_reason:
            _append_detail("verdict", r.verdict_reason, DIM)

        # Plaintext / state.
        if r.is_kernel_override:
            kt = Text()
            kt.append("  KERNEL OVERRIDE  ", style=f"bold reverse {RED}")
            kt.append("  verifier rejected worker self-report", style=DIM)
            body_lines.append(kt)
            if r.plaintext:
                pt_text = Text()
                pt_text.append("  PT      ", style=LABEL)
                pt_text.append(_format_pt_preview(r.plaintext, max(40, inner_width - 14)), style=RED)
                pt_text.no_wrap = False
                pt_text.overflow = "fold"
                body_lines.append(pt_text)
        elif r.score >= 24:
            kt = Text()
            kt.append("  REVIEW  ", style=f"bold reverse {AMBER}")
            kt.append("  cribs match, full PT unverified", style=DIM)
            body_lines.append(kt)
            if r.plaintext:
                pt_text = Text()
                pt_text.append("  PT      ", style=LABEL)
                pt_text.append(_format_pt_preview(r.plaintext, max(40, inner_width - 14)), style=AMBER)
                pt_text.no_wrap = False
                pt_text.overflow = "fold"
                body_lines.append(pt_text)
        elif r.plaintext:
            pt_text = Text()
            pt_text.append("  PT      ", style=LABEL)
            color = GREEN if r.score >= 18 else (CYAN if r.score >= 10 else DIM)
            pt_text.append(_format_pt_preview(r.plaintext, max(40, inner_width - 14)), style=color)
            pt_text.no_wrap = False
            pt_text.overflow = "fold"
            body_lines.append(pt_text)

        block = Group(head, title_block, *body_lines, Text(""))
        blocks.append(block)

    body = Group(*blocks)
    return Panel(
        body,
        title=f"Top Hypotheses ({len(rows)} of {len(snap.top_rows)})",
        title_align="left",
        border_style=DIM,
        box=box.SQUARE,
        padding=(0, 1),
    )


def render_top_hypotheses_compact(snap: Snapshot, max_rows: int) -> RenderableType:
    """Single-line table fallback for narrow layouts."""
    rows = snap.top_rows[:max_rows]
    if not rows:
        return Panel(
            Text("(no scored theories yet)", style=DIM, justify="center"),
            title="Top Hypotheses",
            title_align="left",
            border_style=DIM,
            box=box.SQUARE,
        )
    tbl = Table(
        box=box.SIMPLE,
        expand=True,
        pad_edge=False,
        show_header=True,
        header_style=f"bold {LABEL}",
    )
    tbl.add_column("#", justify="right", width=3, style=DIM)
    tbl.add_column("score", justify="right", width=6)
    tbl.add_column("hypothesis", width=12, style=BLUE, no_wrap=True)
    tbl.add_column("family", width=14, no_wrap=True)
    tbl.add_column("status", width=11)
    tbl.add_column("plaintext / state", overflow="ellipsis", no_wrap=True)
    for i, r in enumerate(rows, 1):
        if r.is_kernel_override:
            preview = "KERNEL OVERRIDE  " + (r.plaintext or "")
            preview_color = RED
        elif r.score >= 24:
            preview = "REVIEW  " + (r.plaintext or "")
            preview_color = AMBER
        else:
            preview = r.plaintext or r.title or ""
            preview_color = GREEN if r.score >= 18 else (CYAN if r.score >= 10 else DIM)
        # Middle-truncate so we keep the right-hand side of the plaintext.
        preview = truncate_middle(preview, 80)
        tbl.add_row(
            f"{i}",
            _score_badge(r),
            r.hypothesis_id[:12] or "—",
            truncate_end(r.family or "—", 14),
            Text(r.status.upper(), style=STATUS_COLOR.get(r.status, WHITE)),
            Text(preview, style=preview_color),
        )
    return Panel(
        tbl,
        title=f"Top Hypotheses ({len(rows)} of {len(snap.top_rows)})",
        title_align="left",
        border_style=DIM,
        box=box.SQUARE,
        padding=(0, 0),
    )


def render_event_stream(tail: LogTail, max_lines: int, max_width: int) -> RenderableType:
    if not tail.events:
        if tail.path is None:
            body: RenderableType = Text(
                "(no log file specified — pass --log to enable)", style=DIM, justify="center"
            )
        else:
            body = Text(
                f"(awaiting events in {tail.path.name} ...)", style=DIM, justify="center"
            )
        return Panel(body, title="Event Stream", title_align="left", border_style=DIM, box=box.SQUARE)

    lines: list[Text] = []
    # Show newest at the bottom (most recent on screen edge).
    recent = list(tail.events)[-max_lines:]
    for ev in recent:
        t = Text(no_wrap=False, overflow="fold")
        t.append(ev.timestamp(), style=DIM)
        t.append("  ")
        glyph = EVENT_GLYPH.get(ev.category, "·")
        style = EVENT_STYLE.get(ev.category, EVENT_STYLE["OTHER"])
        t.append(f"{glyph} ", style=style)
        t.append(f"{ev.category:<10}", style=style)
        t.append(" ")
        # Trim ANSI/timestamp prefix from the line, preserve the verdict tail.
        body_text = ev.line
        body_text = LOG_TS_RE.sub("", body_text).strip()
        # If extremely long, prefer middle-truncation so we keep the verdict text.
        if len(body_text) > max_width * max(1, max_lines):
            body_text = truncate_middle(body_text, max_width * 2)
        t.append(body_text, style=DIM)
        lines.append(t)
    body = Group(*lines)
    title = f"Event Stream  •  {tail.path.name}" if tail.path is not None else "Event Stream  •  (synthetic)"
    return Panel(body, title=title, title_align="left", border_style=DIM, box=box.SQUARE, padding=(0, 1))


def render_alerts(tail: LogTail, max_lines: int) -> RenderableType:
    if not tail.alerts:
        body: RenderableType = Text(
            "(no alerts — run is quiet)", style=DIM, justify="center"
        )
        return Panel(body, title="Alerts", title_align="left", border_style=DIM, box=box.SQUARE)
    lines: list[Text] = []
    recent = list(tail.alerts)[-max_lines:]
    for ev in recent:
        t = Text(no_wrap=False, overflow="fold")
        t.append(ev.timestamp(), style=DIM)
        t.append("  ")
        style = EVENT_STYLE.get(ev.category, EVENT_STYLE["OTHER"])
        glyph = EVENT_GLYPH.get(ev.category, "·")
        t.append(f"{glyph} ", style=style)
        body_text = LOG_TS_RE.sub("", ev.line).strip()
        t.append(body_text, style=style)
        lines.append(t)
    body = Group(*lines)
    border = RED if any(ev.category == "KERNEL" for ev in tail.alerts) else AMBER
    return Panel(body, title="Alerts", title_align="left", border_style=border, box=box.SQUARE, padding=(0, 1))


def render_footer(
    fps: float,
    db_interval: float,
    last_render_s: float,
    layout_name: str,
    width: int,
    height: int,
    frame: int,
    activity: Activity,
) -> RenderableType:
    t = Text()
    t.append("[Ctrl-C] quit", style=LABEL)
    t.append("   refresh ", style=LABEL)
    t.append(f"{fps:g}fps", style=WHITE)
    t.append("   db poll ", style=LABEL)
    t.append(f"{db_interval:g}s", style=WHITE)
    t.append("   layout ", style=LABEL)
    t.append(layout_name, style=WHITE)
    t.append(f" ({width}×{height})", style=DIM)
    t.append("   render ", style=LABEL)
    t.append(f"{last_render_s * 1000:.1f}ms", style=DIM)
    t.append("   ", style=DIM)
    if activity.show_spinner:
        t.append(spinner_char(frame), style=AMBER)
    else:
        t.append("·", style=DIM)
    return t


def render_too_small(width: int, height: int) -> RenderableType:
    body = Text()
    body.append("KryptosBot Telemetry\n", style=TITLE)
    body.append("\nTerminal too small for dashboard\n", style=f"bold {AMBER}")
    body.append(f"current size: {width}×{height}   need ≥80×14\n", style=DIM)
    body.append("\nResize Windows Terminal or zoom out (Ctrl+-)\n", style=DIM)
    return Panel(body, border_style=AMBER, box=box.SQUARE, padding=(1, 2))


# ─────────────────────────────────────────────────────────────────────
# Compose — build a Layout for the chosen breakpoint.
# ─────────────────────────────────────────────────────────────────────


def compose(
    snap: Snapshot | None,
    tail: LogTail,
    activity: Activity,
    db_path: Path,
    log_path: Path | None,
    width: int,
    height: int,
    frame: int,
    fps: float,
    db_interval: float,
    last_render_s: float,
    layout_name: str,
    demo: bool,
) -> RenderableType:
    if too_small(width, height):
        return render_too_small(width, height)

    if snap is None:
        snap = Snapshot()

    # Region renderables, each guarded.
    header = safe_renderable(
        "header",
        render_header,
        snap, activity, tail, db_path, log_path, frame, demo,
    )
    progress = safe_renderable("progress", render_run_progress, snap, tail, frame)
    op_state = safe_renderable("op_state", render_operational_state, activity, snap, frame)
    if layout_name == "ultrawide":
        summary_cols, summary_sections = 3, 6
    elif layout_name == "wide":
        summary_cols, summary_sections = 3, 6
    elif layout_name == "compact":
        summary_cols, summary_sections = 3, 3
    else:
        summary_cols, summary_sections = 1, 3
    summary = safe_renderable("summary", render_research_summary, snap, summary_cols, summary_sections)

    if layout_name == "tiny":
        # Single column: header / phase line / brief stats / latest 5 events.
        top = safe_renderable("top_compact", render_top_hypotheses_compact, snap, 5)
        events = safe_renderable("events", render_event_stream, tail, 6, max(60, width - 4))
        footer = safe_renderable(
            "footer",
            render_footer,
            fps, db_interval, last_render_s, layout_name, width, height, frame, activity,
        )
        return Group(header, op_state, progress, summary, top, events, footer)

    # Build a Layout for compact / wide / ultrawide.
    if layout_name == "compact":
        top_count = 5
        top = safe_renderable(
            "top_compact", render_top_hypotheses_compact, snap, top_count,
        )
    else:
        top_count = 8 if layout_name == "wide" else 10
        inner = max(80, int(width * 0.95) - 6)
        top = safe_renderable(
            "top_cards", render_top_hypotheses_cards, snap, top_count, inner,
        )

    events = safe_renderable(
        "events",
        render_event_stream,
        tail,
        14 if layout_name == "ultrawide" else 10,
        max(80, width - 4),
    )
    alerts = safe_renderable("alerts", render_alerts, tail, 10)

    footer = safe_renderable(
        "footer",
        render_footer,
        fps, db_interval, last_render_s, layout_name, width, height, frame, activity,
    )

    if layout_name == "compact":
        kpi_size, summary_size, events_size = 9, 9, 8
    elif layout_name == "wide":
        kpi_size, summary_size, events_size = 10, 16, 12
    else:  # ultrawide
        kpi_size, summary_size, events_size = 10, 16, 16

    layout = Layout()
    layout.split_column(
        Layout(header, name="header", size=4),
        Layout(name="kpi", size=kpi_size),
        Layout(summary, name="summary", size=summary_size),
        Layout(top, name="top", ratio=1, minimum_size=8),
        Layout(name="events_row", size=events_size),
        Layout(footer, name="footer", size=1),
    )
    layout["kpi"].split_row(
        Layout(progress, name="progress", ratio=1),
        Layout(op_state, name="op", ratio=1),
    )
    layout["events_row"].split_row(
        Layout(events, name="events", ratio=2),
        Layout(alerts, name="alerts", ratio=1),
    )
    return layout


# ─────────────────────────────────────────────────────────────────────
# Demo mode — synthetic state generator. Does NOT touch real DB/log.
# Clearly labeled DEMO. Produces a Snapshot + LogTail look-alike with
# rotating data so the user can see spinners/animations/state changes.
# ─────────────────────────────────────────────────────────────────────


_DEMO_FAMILIES = [
    "encoding", "archive_evidence", "k3_continuity", "antipodes", "grille",
    "k2_coords", "geodetic", "physical_overlay",
]
_DEMO_WORKERS = [
    "dispatcher", "verifier", "stego-analyst", "cryptanalyst", "red-team-disprover",
    "statistical-auditor", "lead-pursuit",
]
_DEMO_STATUSES = ["proposed", "approved", "completed", "criticized", "eliminated"]
_DEMO_PT_GOOD = "OBKRUOXOGHULBSOLIFBBWFLR VQQPRNGKSSO TWTQSJQSSEKZZWATJKLUDIAWINFBNYP VTTMZFPK"
_DEMO_PT_BAD = "QKGCSWBQFEDGRSIVWERSYUREKSEFGQASDFSDFGHJKLAQWERTYUIOPZXCVBNMABCDEFGHIJKLMNOPQR"


def make_demo_state(
    seed: int = 42,
    cycle_phase: int = 0,
) -> tuple[Snapshot, LogTail, Activity]:
    """Build a synthetic snapshot/tail tuned to look like a live run.

    Deterministic given (seed, cycle_phase) — useful for tests and reviews.
    """
    rng = random.Random(seed + cycle_phase)
    snap = Snapshot()
    snap.mode = "demo"
    snap.total_theories = 38 + cycle_phase * 2
    snap.total_experiments = 27 + cycle_phase
    snap.active_experiments = rng.randint(0, 3)
    snap.status = {
        "proposed": 6 + (cycle_phase % 3),
        "approved": 4,
        "completed": 12,
        "criticized": 2,
        "eliminated": 13 + cycle_phase,
        "withdrawn": 1,
    }
    snap.fab_count = 0 if cycle_phase < 4 else 1
    snap.families = [
        ("encoding", 12 + cycle_phase),
        ("archive_evidence", 8),
        ("grille", 5),
        ("k2_coords", 4),
        ("antipodes", 3),
        ("k3_continuity", 3),
    ]
    snap.workers = [(w, rng.randint(2, 18)) for w in _DEMO_WORKERS]
    snap.score_bins = {
        "noise": 22 + cycle_phase,
        "interesting": 6,
        "signal": 1 if cycle_phase >= 3 else 0,
        "review_24": 1 if cycle_phase >= 6 else 0,
    }
    snap.critic = Counter(
        {
            "approve": 28 + cycle_phase,
            "concern": 4,
            "reject": 2,
            "skip_low_information": 3,
        }
    )
    snap.critic_total = sum(snap.critic.values())
    snap.pursuit_open = max(0, 2 - cycle_phase % 4)
    snap.pursuit_recent = 1 if cycle_phase % 5 == 0 else 0
    snap.pursuit_closed = 7
    snap.anomaly_open = 5
    snap.anomaly_total = 17

    base = datetime.now(timezone.utc) - timedelta(hours=2, minutes=14)
    snap.session_start = base
    snap.last_theory_update = datetime.now(timezone.utc) - timedelta(seconds=rng.randint(2, 25))
    snap.last_exp_complete = datetime.now(timezone.utc) - timedelta(seconds=rng.randint(8, 60))
    snap.controller_cycle = 14 + cycle_phase
    snap.controller_proposed = snap.total_theories
    snap.controller_tested = snap.total_experiments
    snap.controller_eliminated = snap.status.get("eliminated", 0)
    snap.controller_promising = 0
    snap.controller_active_exps = snap.active_experiments
    snap.controller_consecutive_d_zero = 1 if cycle_phase % 4 == 3 else 0
    snap.controller_underexplored = ["crib_analysis", "key_tape", "geodetic"]
    snap.controller_open_anomalies = ["aaa_coordinate_lie", "w_delimiter_segments"]
    snap.controller_halt_reason = "" if cycle_phase != 7 else "demo halt: synthetic-mode taint mismatch"

    # Top hypothesis cards: include an override demonstration in later phases.
    rows: list[TopRow] = []
    for i in range(8):
        sc = max(0.0, 17 - i * 1.5 + (3 if (i == 0 and cycle_phase >= 3) else 0))
        is_override = (i == 0 and cycle_phase >= 6)
        if is_override:
            sc = 24
            status = "eliminated"
            verdict = "fabrication"
            reason = "Worker self-reported BREAKTHROUGH (24/24); kernel re-derived crib_score=4 — worker output rejected."
            pt = _DEMO_PT_BAD
        elif i == 0 and cycle_phase >= 3:
            sc = 18
            status = "approved"
            verdict = "approve"
            reason = "Bean PASS, ngram floor met (-3.8), preregistered kill criteria not triggered."
            pt = _DEMO_PT_GOOD
        else:
            status = rng.choice(_DEMO_STATUSES)
            verdict = rng.choice(["approve", "approve", "concern", "skip_low_information"])
            reason = (
                "Search bounded: 5 preregistered perturbations × archive keyword pool × Vigenere variants — no signal at any config."
                if rng.random() < 0.5
                else "Family adjacent to columnar+sub elimination; ngram floor not met after 630 configs."
            )
            pt = _DEMO_PT_BAD
        rows.append(
            TopRow(
                hypothesis_id=f"{rng.randrange(0x1000_0000, 0xFFFF_FFFF):08x}",
                family=rng.choice(_DEMO_FAMILIES),
                status=status,
                score=sc,
                plaintext=pt,
                title=(
                    "K3-continuity via serpentine route + narrow columnar (AAA archive bridge)"
                    if i % 3 == 0
                    else "Compass-bearing Quagmire III with physically-anchored 4-indicator rotation"
                    if i % 3 == 1
                    else "CT perturbation v6: archive-attested 5-variant list + Quagmire III with KRYPTOS-keyed alphabets"
                ),
                verdict=verdict,
                verdict_reason=reason,
                outcome_summary=(
                    "The hypothesis was tested across 5 preregistered archive-attested CT perturbations × Quagmire III "
                    "keyword pool × 3 cipher variants. All 30 configs scored 0-2/24 (deep noise). Bean equality "
                    "k[27]=k[65] failed in 28 of 30 configs; the 2 passing configs had zero ngram support "
                    "(quadgram log-prob below -8.5)."
                    if i < 3 else ""
                ),
                failure_reason=(
                    "Search bounded but mechanism rationale rests on archive co-occurrence not procedural "
                    "instruction; all configs produced random-text statistics."
                    if i < 5 else ""
                ),
                updated_at=datetime.now(timezone.utc) - timedelta(seconds=rng.randint(5, 600)),
                is_kernel_override=is_override,
            )
        )
    snap.top_rows = rows

    # Synthetic LogTail.
    tail = LogTail(path=None)
    tail.cycle_current = snap.controller_cycle
    tail.cycle_total = 100
    tail.run_start = datetime.now() - timedelta(hours=2, minutes=14, seconds=cycle_phase * 7)
    tail.eta_first_seen = tail.run_start
    tail.eta_first_value = 0
    now = datetime.now()
    demo_events = [
        ("DISPATCH", f"CYCLE {tail.cycle_current}/{tail.cycle_total}  beginning"),
        ("PHASE", "▸ GENERATE  theorist [persona] cryptanalyst (claude-opus-4-7)"),
        ("CRITIC", "▸ CRITIC  9/10 theories approved   1 UNDERCONSTRAINED"),
        ("REDTEAM", "⚠ Red-team CONCERNED about CT perturbation v4 — variant list overlap with v1-v3 dispatches"),
        ("WORKER", "Worker 48a4b2c1 completed (best_score=4, 642 configs in 18s)"),
        ("LEDGER", "ledger write: 3 rows (theories), 1 row (experiments)"),
        ("VERIFIER", "verifier APPROVE  cribs 7/24, ngram -7.2, Bean PASS"),
        ("ANOMALY", "Anomaly 'w_delimiter_segments' updated (status=open, +2 evidence_for)"),
    ]
    if cycle_phase >= 3:
        demo_events.append(
            ("SIGNAL", "▲ SIGNAL  hypothesis a3f4d2 crib_score=18 Bean PASS pursuing")
        )
    if cycle_phase >= 6:
        demo_events.append(
            ("KERNEL", "✗ KERNEL OVERRULE  hypothesis 7c89e2 worker reported 24/24, kernel re-derived 4/24 — fabrication caught")
        )
    if cycle_phase == 7:
        demo_events.append(("WARN", "ERROR halt_reason_hardening triggered: synthetic-mode taint mismatch"))
    for i, (cat, line) in enumerate(demo_events):
        ts = now - timedelta(seconds=(len(demo_events) - i) * 8 + rng.randint(0, 4))
        ev = Event(when=ts, category=cat, line=line)
        tail.events.append(ev)
        if cat in ("KERNEL", "SIGNAL", "BREAKTHROUGH", "REDTEAM", "WARN"):
            tail.alerts.append(ev)
        tail.last_by_category[cat] = ts
        tail.last_event_at = ts

    activity = derive_activity(snap, tail)
    return snap, tail, activity


# ─────────────────────────────────────────────────────────────────────
# Main loop.
# ─────────────────────────────────────────────────────────────────────


def resolve_log_path(spec: str | None) -> Path | None:
    if not spec:
        return None
    matches = glob.glob(spec)
    if not matches:
        return Path(spec) if Path(spec).exists() else None
    return Path(max(matches, key=lambda p: Path(p).stat().st_mtime))


def _layout_for_console(console: Console, override: str | None) -> tuple[str, int, int]:
    width = console.size.width
    height = console.size.height
    if override and override != "auto":
        return (override, width, height)
    return (pick_layout(width, height), width, height)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="KryptosBot Telemetry — operations-grade live monitor.")
    ap.add_argument("--db", default="db/theory_ledger.sqlite", help="path to theory_ledger SQLite DB")
    ap.add_argument("--log", default=None, help="path or glob for controller log file")
    ap.add_argument("--fps", type=float, default=8.0, help="render frame rate (default 8)")
    ap.add_argument("--db-interval", type=float, default=1.5, help="DB poll interval seconds (default 1.5)")
    ap.add_argument("--demo", action="store_true", help="run with synthetic data (no real DB read)")
    ap.add_argument("--demo-cycle-seconds", type=float, default=4.0, help="demo phase rotation seconds")
    ap.add_argument("--once", action="store_true", help="render a single frame and exit (for review/tests)")
    ap.add_argument(
        "--layout",
        choices=["auto", "tiny", "compact", "wide", "ultrawide"],
        default="auto",
        help="force a layout breakpoint",
    )
    ap.add_argument("--no-screen", action="store_true", help="don't take over the terminal (inline mode)")
    ap.add_argument("--width", type=int, default=None, help="force console width (preview / 4K demo)")
    ap.add_argument("--height", type=int, default=None, help="force console height (preview / 4K demo)")
    args = ap.parse_args(argv)

    db_path = Path(args.db)
    log_path = resolve_log_path(args.log) if not args.demo else None
    tail = LogTail(log_path) if not args.demo else LogTail(path=None)
    console_kwargs: dict = {"safe_box": True}
    if args.width:
        console_kwargs["width"] = args.width
    if args.height:
        console_kwargs["height"] = args.height
    console = Console(**console_kwargs)

    fps = max(1.0, args.fps)
    frame_dt = 1.0 / fps
    last_db_poll = 0.0
    snapshot: Snapshot | None = None
    last_render_s = 0.0
    frame = 0
    start_real = time.monotonic()
    demo_phase = 0
    last_demo_phase_t = time.monotonic()

    def build_frame() -> RenderableType:
        nonlocal demo_phase, last_demo_phase_t
        if args.demo:
            now_t = time.monotonic()
            if now_t - last_demo_phase_t >= args.demo_cycle_seconds:
                demo_phase = (demo_phase + 1) % 8
                last_demo_phase_t = now_t
            snap, demo_tail, activity = make_demo_state(cycle_phase=demo_phase)
            layout_name, w, h = _layout_for_console(console, args.layout)
            return compose(
                snap=snap,
                tail=demo_tail,
                activity=activity,
                db_path=Path("(demo)"),
                log_path=None,
                width=w,
                height=h,
                frame=frame,
                fps=fps,
                db_interval=args.db_interval,
                last_render_s=last_render_s,
                layout_name=layout_name,
                demo=True,
            )

        # Real telemetry
        try:
            tail.poll()
        except Exception as exc:  # noqa: BLE001
            LOG.warning("log poll failed: %s", exc)

        activity = derive_activity(snapshot or Snapshot(), tail)
        layout_name, w, h = _layout_for_console(console, args.layout)
        return compose(
            snap=snapshot,
            tail=tail,
            activity=activity,
            db_path=db_path,
            log_path=log_path,
            width=w,
            height=h,
            frame=frame,
            fps=fps,
            db_interval=args.db_interval,
            last_render_s=last_render_s,
            layout_name=layout_name,
            demo=False,
        )

    if args.once:
        # One-shot render; do a single DB poll if we can.
        if not args.demo:
            conn = open_db(db_path)
            if conn is not None:
                try:
                    snapshot = take_snapshot(conn)
                finally:
                    conn.close()
            tail.poll()
        t0 = time.monotonic()
        renderable = build_frame()
        last_render_s = time.monotonic() - t0
        console.print(renderable)
        return 0

    use_screen = not args.no_screen
    try:
        with Live(refresh_per_second=fps, screen=use_screen, console=console) as live:
            while True:
                frame += 1
                if not args.demo:
                    now_t = time.monotonic()
                    if now_t - last_db_poll >= args.db_interval:
                        conn = open_db(db_path)
                        if conn is not None:
                            try:
                                snapshot = take_snapshot(conn)
                            except Exception as exc:  # noqa: BLE001
                                LOG.warning("snapshot failed: %s", exc)
                            finally:
                                conn.close()
                        last_db_poll = now_t
                t0 = time.monotonic()
                try:
                    renderable = build_frame()
                    live.update(renderable)
                except Exception as exc:  # noqa: BLE001 — never crash the dashboard loop
                    LOG.error("frame failed: %s\n%s", exc, traceback.format_exc())
                    fallback = Panel(
                        Text(
                            f"render failed: {exc}\nfalling back to plain status",
                            style=RED,
                        ),
                        border_style=RED,
                    )
                    try:
                        live.update(fallback)
                    except Exception:  # last-resort
                        pass
                last_render_s = time.monotonic() - t0
                time.sleep(frame_dt)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
