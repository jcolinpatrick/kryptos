#!/usr/bin/env python3
"""Live tradecraft ops-console for a K4 run in progress.

Run in a separate shell while the controller is executing. Reads the
run's SQLite ledger + stdout log, refreshes 3x / second. Optimized for
ultrawide / 4K displays (≥ 200 columns, ≥ 60 rows) with an alternate
narrow layout below that threshold.

    source venv/bin/activate
    PYTHONPATH=src python3 scripts/_infra/k4_run_dashboard.py

Custom paths:
    PYTHONPATH=src python3 scripts/_infra/k4_run_dashboard.py \\
        --db db/k4_run_2026_04_21.sqlite \\
        --log results/k4_run_2026_04_21/run.log \\
        --max-cycles 15 --max-usd 25.00

Ctrl+C exits; the K4 run in the other shell is unaffected.
"""

from __future__ import annotations

import argparse
import itertools
import json
import math
import re
import sqlite3
import sys
import time
from collections import Counter, deque
from pathlib import Path
from typing import Optional

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

try:
    from rich import box
    from rich.console import Console, Group
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
except ImportError as exc:
    sys.exit(
        f"rich not available ({exc}). Activate the venv: "
        "`source venv/bin/activate`, then rerun."
    )


# ─── Palette ────────────────────────────────────────────────────────────────
C_BONE      = "#d6cbb8"
C_BONE_HOT  = "#ece4d2"
C_DIM       = "#7f7869"
C_WHISPER   = "#4a453d"
C_NOMINAL   = "#7aa095"
C_WATCH     = "#c9a959"
C_CRITICAL  = "#b8414a"
C_BRASS     = "#d4b254"
C_BRASS_HOT = "#f1d27f"
C_COPPER    = "#b87333"
C_COPPER_HOT = "#d89556"
C_VERDIGRIS = "#5f8776"
C_VERD_HOT  = "#88b09e"
C_CHIP_BG   = "#1f1c16"
C_PANEL_BG  = "#15130f"
C_INK       = "#0a0908"
C_HALT      = "#7a1a1f"  # deep-blood red for HALTED chip backgrounds


# ─── Motion primitives ──────────────────────────────────────────────────────
# Spinner alphabets. Different cadences so stacked spinners aren't in lock-step.

_SPIN_BRAILLE = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
_SPIN_ARC     = "◜◠◝◞◡◟"
_SPIN_DOT     = "·∴⁘⁙⁙⁘∴·"
_SPIN_PULSE   = "▁▂▃▄▅▆▇█▇▆▅▄▃▂▁"
_SPIN_WAVE    = "⠀⢀⢠⢰⢸⣸⣼⣾⣿⣾⣼⣸⢸⢰⢠⢀"
_SPIN_COMPASS = "◐◓◑◒"


def _spin(frame: int, kind: str = "braille") -> str:
    table = {
        "braille": _SPIN_BRAILLE,
        "arc":     _SPIN_ARC,
        "dot":     _SPIN_DOT,
        "pulse":   _SPIN_PULSE,
        "wave":    _SPIN_WAVE,
        "compass": _SPIN_COMPASS,
    }.get(kind, _SPIN_BRAILLE)
    return table[frame % len(table)]


def _heartbeat(t: float) -> tuple[str, str]:
    """Two-phase heartbeat. Returns (glyph, color)."""
    phase = (t * 1.5) % 2.0
    if phase < 0.15:
        return "●", C_CRITICAL
    if phase < 0.55:
        return "●", C_COPPER_HOT
    if phase < 1.15:
        return "●", C_CRITICAL
    return "○", C_WHISPER


def _breathe(t: float, period: float = 2.0,
             cold: str = C_VERDIGRIS, hot: str = C_VERD_HOT) -> str:
    """Return cold or hot color based on sine phase. Useful for 'alive' pulse."""
    phase = 0.5 + 0.5 * math.sin((t * 2 * math.pi) / period)
    return hot if phase > 0.55 else cold


def _log_liveness(
    last_mtime: float, now: float, controller_alive: bool = False,
) -> tuple[str, str, str]:
    """Classify log liveness. Returns (label, color, spinner_kind).

    States:
      'live'     = log updated within 4s                  → verdigris, braille
      'stale'    = 4-15s stale                             → amber, arc
      'cold'     = 15-60s stale                            → signal-red, dot
      'thinking' = >60s stale BUT controller PID is alive → amber, arc
                   (theorist deep-generate on opus can go 3-10 min silent)
      'halted'   = >60s stale AND controller PID is dead  → dim slate, static

    Campaign-B dashboard-hardening (2026-04-22): prior behaviour flipped
    to HALTED on any 60s+ silence, which false-triggered every time the
    theorist was mid-API-call (generate phase produces no stdout until
    the SDK returns). Cross-checking the controller PID distinguishes a
    silent-but-working run from an actually-dead one.
    """
    age = now - last_mtime
    if age < 4:
        return ("live", C_VERD_HOT, "braille")
    if age < 15:
        return ("stale", C_WATCH, "arc")
    if age < 60:
        return ("cold", C_CRITICAL, "dot")
    if controller_alive:
        return ("thinking", C_WATCH, "arc")
    return ("halted", C_DIM, "static")


def _is_run_halted(
    last_mtime: float, now: float, controller_alive: bool = False,
) -> bool:
    """True when the log has been static long enough AND the controller
    process is not alive — meaning we're confident the controller exited
    (or crashed).

    A long silent window on its own does NOT imply halt: theorist
    generate phases routinely produce no stdout for minutes while the
    SDK call runs. Only report halted when the controller PID is
    actually dead. See _detect_controller_pid."""
    if controller_alive:
        return False
    return (now - last_mtime) >= 60.0


def _detect_controller_process() -> Optional[tuple[int, list[str]]]:
    """Return ``(pid, argv)`` of a running run_controller.py / solve.py
    where ``argv`` is the controller's command-line tokens as read from
    ``/proc/<pid>/cmdline``. Returns ``None`` if no controller is found
    or if the probe fails (e.g. non-Linux platform).

    Exists so callers that need the controller's actual arguments (e.g.
    ``--db <path>``) can read them from the live process without re-
    parsing a separate launch-command log. The PID-only helper
    ``_detect_controller_pid`` remains for callers that only need
    liveness.
    """
    import os
    import glob
    try:
        for pid_dir in glob.glob("/proc/[0-9]*"):
            try:
                pid = int(os.path.basename(pid_dir))
                with open(f"{pid_dir}/cmdline", "rb") as f:
                    raw = f.read()
                # /proc/<pid>/cmdline is NUL-separated, trailing NUL
                # terminator.
                tokens = [
                    t.decode("utf-8", errors="replace")
                    for t in raw.split(b"\x00") if t
                ]
                # Match on a token that IS the controller script path,
                # not on a string containing the script name anywhere.
                # This rules out bash wrappers like
                # ``/bin/bash -c "... run_controller.py --db foo.sqlite"``
                # where the argv tokens are only ``['/bin/bash', '-c',
                # '<body>']`` and ``--db`` is not a separable token —
                # the dashboard needs the flat-argv shape to extract
                # ``--db``. Campaign-C attempt-2 (2026-04-24) surfaced
                # this footgun: the bash wrapper PID matched first,
                # returned with no ``--db`` in tokens, and the
                # dashboard fell through to the main ledger while the
                # real run wrote to a campaign-specific DB.
                if any(
                    t.endswith("run_controller.py")
                    or t.endswith("kryptosbot/solve.py")
                    or t == "kryptosbot.run_controller"
                    for t in tokens
                ):
                    return (pid, tokens)
            except (OSError, ValueError):
                continue
    except Exception:
        return None
    return None


def _detect_controller_pid() -> Optional[int]:
    """Return the PID of a running run_controller.py / solve.py, else None.

    Thin wrapper over ``_detect_controller_process`` that drops the argv
    when the caller only needs liveness. Preserved for backwards
    compatibility with callers (and tests) that expect the pid-only
    shape. Best-effort; a None return is treated as "no controller
    detected", which for halt-detection means the 60s stale rule kicks
    in normally.
    """
    result = _detect_controller_process()
    return result[0] if result is not None else None


def _extract_db_arg_from_argv(argv: list[str]) -> Optional[Path]:
    """Extract the ``--db PATH`` value from a controller argv list.

    Handles both space-separated (``--db foo.sqlite``) and equals
    (``--db=foo.sqlite``) forms. Returns ``None`` if no ``--db`` was
    passed — i.e. the controller is using the default main-ledger
    path. Caller decides whether to fall back to canonical or report
    "no override detected".
    """
    for i, tok in enumerate(argv):
        if tok == "--db" and i + 1 < len(argv):
            return Path(argv[i + 1])
        if tok.startswith("--db="):
            return Path(tok.split("=", 1)[1])
    return None


def _is_pid_alive(pid: int) -> bool:
    """Best-effort liveness probe. Safe on any Unix; returns False on
    non-POSIX platforms without raising."""
    if pid <= 0:
        return False
    try:
        import os
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


# ─── Auto-detect active run paths ──────────────────────────────────────────

def _detect_active_db() -> Optional[Path]:
    """Return the ledger path the running controller is actually using.

    Detection order:
      1. Running controller's ``--db`` argv (authoritative — the
         dashboard reads what the controller is writing).
      2. Canonical main ledger ``db/theory_ledger.sqlite`` as fallback.
      3. ``None`` if neither exists.

    Campaign-C attempt-2 hardening (2026-04-24): prior behaviour always
    returned the canonical main ledger, which ignored attempt-specific
    campaign DBs (e.g. ``db/k4_campaign_c_*_attempt2.sqlite``) and left
    the dashboard silently showing stale data from the main ledger
    while the live run wrote to a different file. The
    ``Compass-rose``-stuck-in-Activity observation that surfaced this
    bug is documented in the Campaign C postmortem §Z.
    """
    proc = _detect_controller_process()
    if proc is not None:
        _pid, argv = proc
        live_db = _extract_db_arg_from_argv(argv)
        if live_db is not None:
            # Resolve relative paths against repo root so the dashboard
            # can find them from any cwd.
            if not live_db.is_absolute():
                live_db = _ROOT / live_db
            if live_db.exists():
                return live_db

    canonical = _ROOT / "db" / "theory_ledger.sqlite"
    return canonical if canonical.exists() else None


def _detect_active_log() -> Optional[Path]:
    """Most recent campaign log by mtime.

    Search order:
      1. ``logs/campaign_*/run_*.log`` — canonical Campaign-era paths
      2. ``logs/**/run_*.log`` — any nested run log
      3. ``results/*/run.log`` — legacy pre-Campaign paths
    Returns the newest match, or None if nothing found.
    """
    candidates: list[Path] = []
    for pattern in (
        "logs/campaign_*/run_*.log",
        "logs/**/run_*.log",
        "results/*/run.log",
    ):
        candidates.extend(_ROOT.glob(pattern))
    candidates = [p for p in candidates if p.is_file()]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


# ─── Cycle-counter parsing ──────────────────────────────────────────────────

_CYCLE_OF_RE = None  # lazy — compile on first use


def _parse_cycle_info_from_log(log_text: str) -> Optional[tuple[int, int]]:
    """Extract (current_cycle, max_cycle) from the log's most recent
    ``── CYCLE N of M ──`` line.

    The controller prints this at each cycle boundary; it already carries
    the absolute cycle number AND the absolute ceiling computed from
    session-start + ``--cycles``. The dashboard used to compute its own
    ratio as ``cycle_number / args.max_cycles`` which silently misread
    the CLI's relative ``--cycles N`` (N new cycles added) as an absolute
    ceiling — producing nonsense like "154 / 15" when the true ratio was
    154/165. Parsing the log directly fixes that.

    Returns None if no matching line is found; caller falls back to the
    old behaviour.
    """
    global _CYCLE_OF_RE
    if _CYCLE_OF_RE is None:
        import re
        # Controller prints the banner as "CYCLE 151/165". Older logs
        # and the dashboard's own event-tape rendering use
        # "CYCLE 151 of 165"; tolerate both shapes so a mixed-source
        # log still parses cleanly.
        _CYCLE_OF_RE = re.compile(
            r"CYCLE\s+(\d+)\s*(?:/|of)\s*(\d+)", re.IGNORECASE,
        )
    # Scan from the tail so the *most recent* cycle wins.
    matches = list(_CYCLE_OF_RE.finditer(log_text))
    if not matches:
        return None
    m = matches[-1]
    try:
        return (int(m.group(1)), int(m.group(2)))
    except (TypeError, ValueError):
        return None


# ─── K4 reference ───────────────────────────────────────────────────────────
# Imported from canonical kernel constants. Per CLAUDE.md "Always import
# constants, never hardcode": CT and crib positions live in one place.

from kryptos.kernel.constants import (
    CT as _K4_CT,
    CRIB_POSITIONS as _CRIB_POSITIONS,
    SELF_ENCRYPTING as _SELF_ENCRYPTING,
)

_SELF_ENCRYPTING_POSITIONS = frozenset(_SELF_ENCRYPTING.keys())
assert len(_K4_CT) == 97


# ─── Data: ledger ───────────────────────────────────────────────────────────

def _query_ledger(db_path: Path) -> dict:
    snap: dict = {"theories": [], "experiments": [], "error": None}
    if not db_path.exists():
        snap["error"] = "ledger not yet created"
        return snap
    try:
        conn = sqlite3.connect(db_path, timeout=1.0)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT hypothesis_id, title, core_claim, family, status, "
            "critic_verdict, best_score, created_at, updated_at "
            "FROM theories ORDER BY updated_at DESC"
        ).fetchall()
        snap["theories"] = [dict(r) for r in rows]
        for t in snap["theories"]:
            try:
                t["critic_verdict"] = json.loads(t.get("critic_verdict") or "{}")
            except json.JSONDecodeError:
                t["critic_verdict"] = {}
        rows = conn.execute(
            "SELECT hypothesis_id, started_at, completed_at, result "
            "FROM experiments"
        ).fetchall()
        snap["experiments"] = [dict(r) for r in rows]
        for e in snap["experiments"]:
            try:
                e["result"] = json.loads(e.get("result") or "{}")
            except json.JSONDecodeError:
                e["result"] = {}
        conn.close()
    except sqlite3.Error as exc:
        snap["error"] = f"sqlite: {exc}"
    return snap


# ─── Data: Claude Code subscription token meter ─────────────────────────────
# kryptosbot dispatches workers via claude-agent-sdk, which spawns the
# Claude Code CLI as a subprocess. That CLI authenticates against the
# user's Claude Code SUBSCRIPTION — not the Anthropic API — so no
# per-call USD is emitted anywhere. BUT every worker's Claude Code
# session writes a JSONL transcript under ~/.claude/projects/
# -home-cpatrick-kryptos/<uuid>.jsonl, and every assistant turn in
# that transcript carries a `usage` dict with input_tokens /
# output_tokens / cache_read_input_tokens / cache_creation_input_tokens.
# Aggregating across all JSONL files whose mtime falls inside the run
# window gives the same totals Claude Code's own `/status` command
# would show — and that's what the user cares about.

_CLAUDE_PROJECT_DIR = Path.home() / ".claude" / "projects" / "-home-cpatrick-kryptos"

# Cache: file path -> (mtime_seen, totals dict). Skip re-parsing files
# whose mtime has not advanced since the last refresh.
_TOKEN_CACHE: dict[Path, tuple[float, dict]] = {}


def _parse_jsonl_usage(path: Path) -> dict:
    """Sum the usage dicts in one Claude Code session JSONL.

    Returns a dict with input / output / cache_read / cache_creation /
    model (most recent) and turn_count.
    """
    totals = {
        "input": 0, "output": 0,
        "cache_read": 0, "cache_create": 0,
        "model": "", "turns": 0,
    }
    try:
        with path.open("r", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or '"usage"' not in line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Claude Code message format: { "type": "assistant",
                #   "message": { "model": "...", "usage": {...} } }
                msg = obj.get("message") if isinstance(obj, dict) else None
                if not isinstance(msg, dict):
                    continue
                usage = msg.get("usage") or {}
                if not isinstance(usage, dict):
                    continue
                totals["input"] += int(usage.get("input_tokens", 0) or 0)
                totals["output"] += int(usage.get("output_tokens", 0) or 0)
                totals["cache_read"] += int(
                    usage.get("cache_read_input_tokens", 0) or 0
                )
                totals["cache_create"] += int(
                    usage.get("cache_creation_input_tokens", 0) or 0
                )
                totals["turns"] += 1
                if msg.get("model"):
                    totals["model"] = msg["model"]
    except OSError:
        pass
    return totals


def _query_subscription_tokens(first_seen: Optional[float]) -> dict:
    """Aggregate Claude Code subscription token burn across the run's
    worker sessions. Returns totals suitable for dashboard display.

    ``first_seen`` is the run-start epoch. Files older than that are
    pre-run sessions and excluded.
    """
    agg = {
        "input": 0, "output": 0,
        "cache_read": 0, "cache_create": 0,
        "sessions": 0, "turns": 0,
        "by_model": {},  # model -> {input, output}
    }
    if not _CLAUDE_PROJECT_DIR.exists():
        return agg
    cutoff = first_seen or 0
    try:
        paths = list(_CLAUDE_PROJECT_DIR.glob("*.jsonl"))
    except OSError:
        return agg
    for path in paths:
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime < cutoff:
            continue
        cached = _TOKEN_CACHE.get(path)
        if cached is not None and cached[0] == mtime:
            totals = cached[1]
        else:
            totals = _parse_jsonl_usage(path)
            _TOKEN_CACHE[path] = (mtime, totals)
        if totals["turns"] == 0:
            continue
        agg["input"] += totals["input"]
        agg["output"] += totals["output"]
        agg["cache_read"] += totals["cache_read"]
        agg["cache_create"] += totals["cache_create"]
        agg["sessions"] += 1
        agg["turns"] += totals["turns"]
        m = totals.get("model") or "unknown"
        bucket = agg["by_model"].setdefault(
            m, {"input": 0, "output": 0, "turns": 0}
        )
        bucket["input"] += totals["input"]
        bucket["output"] += totals["output"]
        bucket["turns"] += totals["turns"]
    return agg


# ─── Data: log parse ────────────────────────────────────────────────────────

_CYCLE_RE = re.compile(r"cycle\s+(\d+)\s*/\s*(\d+)", re.IGNORECASE)
# Left-over for the direct-API path (not used by the agent-SDK path).
_API_RE = re.compile(
    r"API call:\s+(\d+)\s+in\s+\+\s+(\d+)\s+out\s+\+\s+(\d+)\s+cached\s+=\s+\$([\d.]+)"
)
_CUM_RE = re.compile(r"cumulative:.*\$([\d.]+)")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_STAGE_RE = re.compile(
    r"▸\s+(GENERATE|CRITICIZE|CRITIC|DISPATCH|SCORE|SYNTHESIZE|"
    r"SYNTHESIS|ASSESS|OUTCOME|RED[- ]?TEAM)",
    re.IGNORECASE,
)
_PERSONA_RE = re.compile(
    r"persona[:\s]+(\w[\w\-_]+)|Theorist:\s*\[?persona\]?\s*([\w\-_]+)",
    re.IGNORECASE,
)

# Agent-SDK worker heartbeat:
#   "12:54:43 ♡ 6356caa0  still running... 2m00s elapsed, 30 stream events"
_WORKER_HB_RE = re.compile(
    r"♡\s+([0-9a-f]{8})\s+still running\.\.\.\s+(\d+)m(\d+)s elapsed,\s+(\d+)\s+stream events"
)
# Worker completion (■ disproved / approved / complete / error ... in N seconds):
#   "12:56:42 ■ 082f67ef  disproved score=3.0 in 239s"
_WORKER_DONE_RE = re.compile(
    r"■\s+([0-9a-f]{8})\s+(disproved|approved|complete|error|timeout|eliminated|promising)"
    r"(?:\s+score=([\d.]+))?(?:.+?in\s+(\d+)s)?"
)


def _parse_log(log_path: Path) -> dict:
    out: dict = {
        "cycle_current": 0,
        "cycle_max_from_log": 0,  # dashboard-hardening 2026-04-22
        "total_usd": 0.0,
        "api_calls": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "recent": [],
        "last_modified": 0.0,
        "current_stage": "",
        "current_persona": "",
        "first_seen": None,
        # Agent-SDK worker state. Keyed by 8-hex worker id.
        "workers": {},
        "stream_events_total": 0,
    }
    if not log_path.exists():
        return out
    try:
        stat = log_path.stat()
        out["last_modified"] = stat.st_mtime
        # Real run start = the log's first-line HH:MM:SS timestamp combined
        # with today's date (the log is rotated per-run, not per-day). We
        # read the first 8 KB of the log for that first stamp. Fall back to
        # st_ctime if no timestamp is visible — that's better than the
        # dashboard-launch default but still imprecise.
        with log_path.open("r", errors="replace") as f:
            head = f.read(8192)
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, 300_000)
            f.seek(max(0, size - chunk))
            text_tail = f.read()
        m = re.search(r"(\d{2}):(\d{2}):(\d{2})", head)
        if m:
            hh, mm, ss = (int(x) for x in m.groups())
            today = time.localtime()
            run_start = time.mktime((
                today.tm_year, today.tm_mon, today.tm_mday,
                hh, mm, ss, 0, 0, -1,
            ))
            # Guard against clock-crossing-midnight (negative elapsed).
            now_ts = time.time()
            if run_start > now_ts:
                run_start -= 86400
            out["first_seen"] = run_start
        else:
            out["first_seen"] = stat.st_ctime
    except OSError:
        return out

    lines = text_tail.splitlines()
    last_stage = ""
    last_persona = ""
    workers: dict[str, dict] = {}
    max_stream_events = 0
    for line in lines:
        m = _CYCLE_RE.search(line)
        if m:
            try:
                n = int(m.group(1))
                if n > out["cycle_current"]:
                    out["cycle_current"] = n
            except ValueError:
                pass
        m = _API_RE.search(line)
        if m:
            inp, out_tok, _cache, _cost = m.groups()
            out["api_calls"] += 1
            out["input_tokens"] += int(inp)
            out["output_tokens"] += int(out_tok)
        m = _CUM_RE.search(line)
        if m:
            try:
                out["total_usd"] = float(m.group(1))
            except ValueError:
                pass
        m = _STAGE_RE.search(line)
        if m:
            raw = m.group(1).upper()
            # Normalize common noise ("CRITIC" vs "CRITICIZE") to one label.
            norm = {
                "CRITIC": "CRITICIZE",
                "SYNTHESIS": "SYNTHESIZE",
                "OUTCOME": "ASSESS",
                "RED-TEAM": "RED-TEAM",
                "RED TEAM": "RED-TEAM",
            }.get(raw, raw)
            last_stage = norm
        m = _PERSONA_RE.search(line)
        if m:
            last_persona = (m.group(1) or m.group(2) or "").strip()

        # Agent-SDK worker heartbeat — update that worker's live state.
        m = _WORKER_HB_RE.search(line)
        if m:
            wid, mm, ss, events = m.groups()
            elapsed = int(mm) * 60 + int(ss)
            n_events = int(events)
            w = workers.setdefault(wid, {
                "id": wid, "status": "running",
                "elapsed": 0, "events": 0,
                "outcome": None, "score": None, "done_at": None,
            })
            if w["status"] == "running":
                w["elapsed"] = max(w["elapsed"], elapsed)
                w["events"] = max(w["events"], n_events)
            max_stream_events = max(max_stream_events, n_events)

        m = _WORKER_DONE_RE.search(line)
        if m:
            wid, outcome, score, in_s = m.groups()
            w = workers.setdefault(wid, {
                "id": wid, "status": "done",
                "elapsed": int(in_s) if in_s else 0,
                "events": 0, "outcome": outcome,
                "score": float(score) if score else None,
                "done_at": int(in_s) if in_s else None,
            })
            w["status"] = "done"
            w["outcome"] = outcome
            if score:
                try:
                    w["score"] = float(score)
                except ValueError:
                    pass
            if in_s:
                try:
                    w["done_at"] = int(in_s)
                    w["elapsed"] = max(w["elapsed"], int(in_s))
                except ValueError:
                    pass

    out["workers"] = workers
    out["stream_events_total"] = sum(
        w.get("events", 0) for w in workers.values()
    )

    out["current_stage"] = last_stage
    out["current_persona"] = last_persona

    event_re = re.compile(
        r"(cycle|CYCLE|Cycle|GENERATE|CRITICIZE|DISPATCH|SCORE|SYNTHESIZE|"
        r"theorist|critic|worker|SIGNAL|BREAKTHROUGH|ALERT|Error|Traceback|"
        r"verdict|API call|approved|rejected|discover|proposed|persona)",
        re.IGNORECASE,
    )
    # Box-drawing chars that mean "this line is inside a Rich panel chrome."
    # Controllers draw landscape/status panels with box-drawing borders; the
    # text INSIDE those panels isn't an event, it's annotation, and should
    # not end up on the event tape.
    _BOX_CHARS = set("│┃┏┓┗┛┣┫┳┻╋║╔╗╚╝╠╣╦╩╬━─╭╮╯╰═╪╡╞╤╧")

    events: list[tuple[str, str]] = []
    # Match the controller's ═════ CYCLE N/M ═════ banner to promote to
    # a dedicated CYCLE event with the decoration stripped. Runs before
    # the box-drawing skip so we don't lose the cycle markers.
    cycle_banner_re = re.compile(
        r"═+\s*CYCLE\s+(\d+)\s*/\s*(\d+)\s*═+", re.IGNORECASE,
    )

    for line in lines[-300:]:
        clean = _ANSI_RE.sub("", line).rstrip()
        if not clean:
            continue
        stripped = clean.lstrip()
        # Promote ═══ CYCLE n/m ═══ banners before the box-drawing skip.
        m = cycle_banner_re.search(stripped)
        if m:
            n, total = m.groups()
            events.append(("CYCLE", f"── CYCLE {n} of {total} ──"))
            continue
        # Skip lines that START with a box-drawing char (panel interior text).
        if stripped and stripped[0] in _BOX_CHARS:
            continue
        # Skip decoration-only lines.
        if not re.search(r"[A-Za-z]", stripped):
            continue
        if not event_re.search(line):
            continue
        tag = _tag_for_line(clean)
        events.append((tag, clean))
    out["recent"] = events[-18:]

    # Dashboard-hardening (2026-04-22): pull the absolute cycle ceiling
    # from the log's "CYCLE N of M" banner. The controller prints this
    # at each cycle boundary, and it already accounts for session-start
    # cycle + --cycles (so a run launched with --cycles 15 from cycle
    # 151 will print "CYCLE 151 of 165"). Reading this directly avoids
    # the old "154 / 15" display bug where the dashboard treated the
    # CLI's --cycles as an absolute ceiling.
    cycle_info = _parse_cycle_info_from_log(text_tail)
    if cycle_info:
        out["cycle_current"] = max(out["cycle_current"], cycle_info[0])
        out["cycle_max_from_log"] = cycle_info[1]

    return out


def _tag_for_line(line: str) -> str:
    """Tag a log line by its most distinctive event type.

    Uses word-boundary matching rather than substring match to avoid
    false positives like 'transcription errors' tagging ERROR or
    'residual_caution' tagging ALERT. Checks are ordered from most to
    least specific.
    """
    low = line.lower()
    # ERROR: real program errors, not vocabulary mentions like
    # "transcription errors". Matches:
    #   - stack-trace intros ("Traceback")
    #   - CamelCase exception types ("ValueError", "RuntimeError")
    #   - the bare word "exception", "failed", "errored", or "error!"
    # Notably does NOT match "errors" (plural) or "transcription errors".
    if re.search(
        r"\btraceback\b|\w+error\b|\bexception\b|\bfailed\b|\berrored\b",
        low,
    ):
        return "ERROR"
    # SIGNAL: genuine alert markers, not the word "signal" anywhere.
    if re.search(r"\bsignal alert\b|\bbreakthrough\b|^⚠\s*alert\b|crib_score=(2[0-4])\b", low):
        return "SIGNAL"
    if "api call" in low or "cumulative:" in low:
        return "API"
    # RED-TEAM sits between critic and dispatch conceptually; the ⚠
    # marker + "red-team" phrase is the reliable signal.
    if re.search(r"red[- ]?team\s+concerned|red[- ]?team\s+disprov", low):
        return "DISPATCH"  # dispatching-with-concern events
    if re.search(r"\bverdict\b|\brejected\b|\bapproved\b|▸\s*critic", low):
        return "CRITIC"
    if re.search(r"▸\s*dispatch|dispatching|\bworker\b", low):
        return "DISPATCH"
    if re.search(r"\bdiscover\b|discovered=|\bbest score\b", low):
        return "SCORE"
    if re.search(r"▸\s*generate|\btheorist\b|generated \d+|\bpersona\b|\bproposed\b", low):
        return "PROPOSAL"
    return "LOG"


# ─── Sparkline with glow tail ───────────────────────────────────────────────

_SPARK_CHARS = "▁▂▃▄▅▆▇█"


def _shorten(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _ledger_health(snap: dict) -> tuple[str, str]:
    """Return a compact ledger health label and color for operator-facing UI."""
    error = (snap.get("error") or "").strip()
    if error:
        low = error.lower()
        if "not yet created" in low:
            return "ledger waiting", C_WATCH
        if "no such table" in low:
            return "ledger schema", C_CRITICAL
        return "ledger error", C_CRITICAL
    if not snap.get("theories") and not snap.get("experiments"):
        return "ledger empty", C_WATCH
    return "ledger ok", C_VERDIGRIS


def _source_badges(snap: dict, logdata: dict, now: float) -> list[tuple[str, str]]:
    """Compact source-health badges for the banner/event tape."""
    badges: list[tuple[str, str]] = []
    ledger_label, ledger_color = _ledger_health(snap)
    if ledger_label != "ledger ok":
        badges.append((ledger_label, ledger_color))

    if not logdata.get("last_modified"):
        badges.append(("log waiting", C_WATCH))
    else:
        log_label, log_color, _ = _log_liveness(
            logdata["last_modified"], now,
            controller_alive=bool(logdata.get("controller_alive")),
        )
        if log_label != "live":
            badges.append((f"log {log_label}", log_color))

    if snap.get("error"):
        badges.append((_shorten(str(snap["error"]), 28), C_DIM))
    return badges[:3]


def _sparkline_pretty(values: list[float], width: int,
                      base: str, hot: str) -> Text:
    """Sparkline where the rightmost char (most recent) glows hotter."""
    if not values:
        dots = Text("·" * width, style=C_WHISPER)
        return dots
    if len(values) > width:
        step = len(values) / width
        sampled = [values[int(i * step)] for i in range(width)]
    else:
        sampled = [None] * (width - len(values)) + list(values)  # type: ignore
    vnums = [v for v in sampled if v is not None]
    if not vnums:
        return Text("·" * width, style=C_WHISPER)
    lo, hi = min(vnums), max(vnums)
    rng = hi - lo
    out = Text()
    last_idx = max(i for i, v in enumerate(sampled) if v is not None)
    for i, v in enumerate(sampled):
        if v is None:
            out.append("·", style=C_WHISPER)
            continue
        if rng <= 1e-9:
            ch = _SPARK_CHARS[4]
        else:
            pos = int(((v - lo) / rng) * (len(_SPARK_CHARS) - 1))
            ch = _SPARK_CHARS[max(0, min(len(_SPARK_CHARS) - 1, pos))]
        # Tail glow: the last 3 real points gradient from base→hot.
        if i >= last_idx - 2:
            weight = (i - (last_idx - 2)) / 2 if i >= last_idx - 2 else 0
            out.append(ch, style=f"bold {hot}" if weight >= 0.9 else hot)
        else:
            out.append(ch, style=base)
    return out


# ─── Panels ─────────────────────────────────────────────────────────────────

def _banner(cycle_cur: int, cycle_max: int,
            usd: float, usd_max: float,
            elapsed_sec: float,
            frame: int,
            log_last_mtime: float,
            now: float,
            stream_events_total: int,
            active_workers: int,
            source_badges: list[tuple[str, str]],
            subscription: Optional[dict] = None,
            controller_alive: bool = False) -> Panel:
    cycle_pct = min(1.0, cycle_cur / max(1, cycle_max))
    cyc_color = C_NOMINAL if cycle_pct < 0.8 else (C_WATCH if cycle_pct < 1.0 else C_CRITICAL)

    halted = _is_run_halted(log_last_mtime, now, controller_alive=controller_alive)
    liveness_label, liveness_color, liveness_spin = _log_liveness(
        log_last_mtime, now, controller_alive=controller_alive,
    )
    # When halted: static heartbeat + static glyph instead of spinner.
    if halted:
        hb_glyph, hb_color = "◌", C_DIM
        spin_ch = "•"  # dead marker, no animation
    else:
        hb_glyph, hb_color = _heartbeat(now)
        spin_ch = _spin(frame, liveness_spin)

    line = Text()
    line.append(f" {hb_glyph} ", style=f"bold {hb_color}")
    line.append("OPERATION ", style=f"{C_DIM} italic")
    # Dim the headline colour when halted — dashboard is showing an
    # archived snapshot, not an active operation.
    title_color = C_DIM if halted else C_BONE_HOT
    line.append("KRYPTOS·K4  ", style=f"bold {title_color}")
    line.append("│ ", style=C_WHISPER)
    # Explicit HALTED chip takes priority over everything else once the
    # log has been static for >60s. Left here so the operator sees it
    # first, rather than reading a misleading "cycle 4/15 active" line.
    if halted:
        line.append(" HALTED ", style=f"bold {C_BONE_HOT} on {C_HALT}")
        line.append("  ", style="")
        line.append("│ ", style=C_WHISPER)
    line.append("CYCLE ", style=C_DIM)
    cyc_render_color = C_DIM if halted else cyc_color
    line.append(f"{cycle_cur:02d}", style=f"bold {cyc_render_color}")
    line.append(f" / {cycle_max:02d} ", style=cyc_render_color)
    line.append(spin_ch + " ", style=f"bold {liveness_color}")
    line.append("│ ", style=C_WHISPER)
    # Real subscription usage from Claude Code session JSONL transcripts.
    # This replaces the fake "$25 cap" — the run uses subscription auth,
    # not API billing, so tokens are the meaningful unit.
    sub = subscription or {}
    tok_in = int(sub.get("input", 0))
    tok_out = int(sub.get("output", 0))
    tok_cache = int(sub.get("cache_read", 0) + sub.get("cache_create", 0))
    line.append("TOKENS ", style=C_DIM)
    line.append("in ", style=f"{C_DIM} italic")
    line.append(_fmt_tokens(tok_in), style=f"bold {C_BRASS}")
    line.append("  out ", style=f"{C_DIM} italic")
    line.append(_fmt_tokens(tok_out), style=f"bold {C_BRASS_HOT}")
    line.append("  cache ", style=f"{C_DIM} italic")
    line.append(_fmt_tokens(tok_cache), style=f"bold {C_COPPER}")
    line.append("  ", style="")
    line.append("│ ", style=C_WHISPER)
    line.append("ELAPSED ", style=C_DIM)
    line.append(_fmt_elapsed(elapsed_sec), style=f"bold {C_BONE}")
    line.append(" │ ", style=C_WHISPER)
    # Workers count reads from log heartbeats. Post-halt, "active" is
    # semantically wrong — those workers were orphaned when the run
    # ended. Relabel + freeze the spinner.
    if halted and active_workers > 0:
        line.append("ORPHANED ", style=C_DIM)
        line.append(f"{active_workers}", style=f"bold {C_WATCH}")
    else:
        line.append("WORKERS ", style=C_DIM)
        wcolor = C_VERDIGRIS if active_workers > 0 else C_WHISPER
        line.append(f"{active_workers}", style=f"bold {wcolor}")
        if active_workers > 0 and not halted:
            line.append(" " + _spin(frame + 5, "braille"),
                        style=f"bold {wcolor}")
    line.append(" │ ", style=C_WHISPER)
    line.append("STREAM ", style=C_DIM)
    line.append(f"{stream_events_total:,}ev", style=f"bold {C_BONE}")
    line.append(" │ ", style=C_WHISPER)
    line.append("LOG ", style=C_DIM)
    line.append(liveness_label, style=f"bold {liveness_color}")
    if source_badges:
        line.append(" │ ", style=C_WHISPER)
        line.append("DATA ", style=C_DIM)
        for idx, (badge, color) in enumerate(source_badges):
            if idx:
                line.append(" · ", style=C_WHISPER)
            line.append(badge.upper(), style=f"bold {color}")
    line.append(" │ ", style=C_WHISPER)
    line.append("GATE ", style=C_DIM)
    line.append("SIGNAL · p≤1e-6", style=f"bold {C_VERDIGRIS}")

    return Panel(
        line,
        box=box.HEAVY,
        border_style=C_WHISPER,
        padding=(0, 0),
    )


def _fmt_tokens(n: int) -> str:
    """Compact thousands/millions for token display."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.2f}M"
    if n >= 10_000:
        return f"{n / 1_000:.1f}k"
    if n >= 1_000:
        return f"{n / 1_000:.2f}k"
    return f"{n}"


def _fmt_elapsed(seconds: float) -> str:
    if seconds < 0:
        seconds = 0
    h = int(seconds // 3600)
    m = int((seconds % 3600) // 60)
    s = int(seconds % 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def _k4_ct_panel() -> Panel:
    rows: list[Text] = []
    pos_header = Text()
    pos_header.append("      ", style=C_DIM)
    for col in range(14):
        pos_header.append(f" {col:02d}", style=f"{C_WHISPER} italic")
    rows.append(pos_header)
    for row_idx in range(7):
        row = Text()
        row.append(f"{row_idx * 14:02d}:  ", style=f"{C_DIM} italic")
        for col_idx in range(14):
            pos = row_idx * 14 + col_idx
            if pos >= 97:
                row.append("   ", style=C_WHISPER)
                continue
            ch = _K4_CT[pos]
            if pos in _SELF_ENCRYPTING_POSITIONS:
                row.append(f" {ch} ", style=f"bold underline {C_COPPER_HOT}")
            elif pos in _CRIB_POSITIONS:
                row.append(f" {ch} ", style=f"bold {C_COPPER}")
            else:
                row.append(f" {ch} ", style=C_BONE)
        rows.append(row)
    # Crib labels sourced from kernel.constants.CRIB_DICT. Block A (21-33,
    # 13 chars) decrypts to EASTNORTHEAST; Block B (63-73, 11 chars) to
    # BERLINCLOCK. Previously had these swapped + truncated.
    legend = Text("\n  ", style="")
    legend.append("■", style=C_COPPER)
    legend.append(" crib  ", style=C_DIM)
    legend.append("■", style=f"underline {C_COPPER_HOT}")
    legend.append(" self-encrypt  ", style=C_DIM)
    legend.append("21-33 ", style=C_BONE)
    legend.append("EASTNORTHEAST", style=f"{C_COPPER} italic")
    legend.append("   ·   ", style=C_WHISPER)
    legend.append("63-73 ", style=C_BONE)
    legend.append("BERLINCLOCK", style=f"{C_COPPER} italic")

    title = Text("  K4 CIPHERTEXT  ", style=f"bold {C_BONE} on {C_CHIP_BG}")
    return Panel(
        Group(*rows, legend),
        box=box.HEAVY, border_style=C_WHISPER,
        title=title, title_align="left",
        padding=(1, 2),
    )


def _posture_panel() -> Panel:
    chips: list[tuple[str, str, bool]] = [
        ("CRITIC",       "tier 1/2",  True),
        ("RED-TEAM",     "siblings",  True),
        ("STAT-AUDIT",   "≥18 crib",  True),
        ("NULL-GATE",    "p≤1e-6",    True),
        ("LEAD-PURSUE",  "6-17 band", True),
        ("EXH-OVERRIDE", "R2-3",      True),
        ("DSL-ROUTE",    "loop-lite", False),
    ]
    rows: list[Text] = []
    for name, sub, active in chips:
        row = Text("  ")
        dot = "◆" if active else "◇"
        row.append(f"{dot} ", style=f"bold {C_VERDIGRIS if active else C_WATCH}")
        row.append(f"{name:<13}", style=f"bold {C_BONE}")
        row.append(f"{sub}", style=f"{C_DIM} italic")
        rows.append(row)
    title = Text("  POSTURE  ", style=f"bold {C_BONE} on {C_CHIP_BG}")
    return Panel(
        Group(*rows),
        box=box.HEAVY, border_style=C_WHISPER,
        title=title, title_align="left",
        padding=(1, 1),
    )


def _activity_panel(snap: dict, logdata: dict,
                    frame: int, now: float) -> Panel:
    """Foreground 'thinking' indicator. Shows the current controller stage,
    persona, and per-worker live state (elapsed, stream events, outcome).

    Uses the SAME in-flight definition as the mortality panel: a theory is
    in-flight only if its status is running/proposed/etc. AND its critic
    verdict is not a reject. Otherwise the two panels disagree.
    """
    if snap.get("error"):
        body = Group(
            Text("   ledger unavailable", style=f"bold {C_CRITICAL}"),
            Text(""),
            Text(f"   {snap['error']}", style=f"{C_DIM} italic", overflow="fold"),
            Text(""),
            Text("   activity resumes once the ledger is readable",
                 style=f"{C_WHISPER} italic"),
        )
        title = Text("  ACTIVITY  ", style=f"bold {C_BONE_HOT} on {C_CHIP_BG}")
        return Panel(
            body,
            box=box.HEAVY,
            border_style=C_CRITICAL,
            title=title, title_align="left",
            padding=(1, 1),
        )

    # Consistent in-flight filter — mirrors the mortality panel logic.
    in_flight: list[dict] = []
    for t in snap["theories"]:
        cv = t.get("critic_verdict") or {}
        if cv.get("decision", "").startswith("reject_"):
            continue
        # Vetoed by red-team — stored inside critic_verdict.reasons as
        # free text. Same treatment as the mortality C-row.
        if _is_redteam_rejected(t):
            continue
        if t.get("status") in ("proposed", "criticized", "approved", "running"):
            in_flight.append(t)
    current = in_flight[0] if in_flight else None

    stage = logdata.get("current_stage") or ""
    persona = logdata.get("current_persona") or ""
    workers = logdata.get("workers") or {}
    halted = _is_run_halted(
        logdata.get("last_modified") or now, now,
        controller_alive=bool(logdata.get("controller_alive")),
    )

    if not stage and current:
        stage = {
            "proposed":   "GENERATE",
            "criticized": "CRITICIZE",
            "approved":   "DISPATCH",
            "running":    "WORKER",
        }.get(current.get("status", ""), "")

    # Freeze colour + stage label when halted — no more copper breathing.
    if halted:
        stage_color = C_DIM
    elif stage:
        stage_color = _breathe(now, period=1.2,
                               cold=C_COPPER, hot=C_COPPER_HOT)
    else:
        stage_color = C_WHISPER

    # Spinners become static glyphs in halted state so the panel no
    # longer LOOKS like a running campaign.
    if halted:
        big_spin = "◌"
        braille_spin = "•"
    else:
        big_spin = _spin(frame, "wave")
        braille_spin = _spin(frame + 3, "braille")

    rows: list[Text] = []

    # Giant active indicator.
    active_row = Text()
    active_row.append("   ")
    if halted:
        active_row.append("◌", style=f"bold {C_DIM}")
        active_row.append(" ", style="")
        active_row.append("RUN HALTED ", style=f"bold {C_BONE_HOT} on {C_HALT}")
        active_row.append(" ◌", style=f"bold {C_DIM}")
    elif stage:
        active_row.append(big_spin, style=f"bold {stage_color}")
        active_row.append(" ", style="")
        active_row.append(f"{stage:<11}", style=f"bold {C_BONE_HOT}")
        active_row.append(braille_spin, style=f"bold {stage_color}")
    else:
        active_row.append("·", style=C_WHISPER)
        active_row.append(" IDLE        ", style=f"bold {C_DIM}")
        active_row.append("·", style=C_WHISPER)
    rows.append(active_row)
    rows.append(Text(""))

    # Persona.
    persona_row = Text()
    persona_row.append("   persona  ", style=f"{C_DIM} italic")
    if persona:
        persona_row.append(persona, style=f"bold {C_VERDIGRIS}")
    elif current and current.get("family"):
        persona_row.append(f"[{current['family']}]", style=f"{C_VERDIGRIS} italic")
    else:
        persona_row.append("—", style=C_WHISPER)
    rows.append(persona_row)

    # Theory — full title, hypothesis_id with explicit ellipsis.
    theory_row = Text(overflow="fold")
    theory_row.append("   theory   ", style=f"{C_DIM} italic")
    if current:
        hid = current.get("hypothesis_id") or ""
        hid_show = hid[:10] + "…" if len(hid) > 10 else hid
        title = current.get("title") or current.get("core_claim") or ""
        theory_row.append(f"H-{hid_show}  ", style=f"bold {C_BONE}")
        theory_row.append(title, style=f"{C_BONE} italic")
    else:
        theory_row.append("—", style=C_WHISPER)
    rows.append(theory_row)
    rows.append(Text(""))

    # Per-worker live state — this is the real "thinking" signal.
    #   ⠧ ID · 07:30 · 67 events · running      (animated spinner)
    #   ■ ID · 03:59 · 47 events · disproved 3.0 (fixed check mark)
    running_workers = [
        w for w in workers.values() if w.get("status") == "running"
    ]
    done_workers = [
        w for w in workers.values() if w.get("status") == "done"
    ]
    # Most-recent running workers first; limit to 6 for panel fit.
    running_workers.sort(key=lambda w: -int(w.get("elapsed") or 0))
    done_workers.sort(key=lambda w: -int(w.get("done_at") or 0))

    if running_workers or done_workers:
        rows.append(Text("   workers", style=f"{C_DIM} italic"))
        for i, w in enumerate(running_workers[:6]):
            r = Text("   ", overflow="fold")
            # Halted: spinner becomes static "✗" glyph, id dims, trailing
            # tag reads "orphaned". Live: each worker gets its own
            # spinner phase so they don't beat in lockstep.
            if halted:
                r.append("✗", style=f"bold {C_CRITICAL}")
            else:
                r.append(_spin(frame + i * 2, "braille"),
                         style=f"bold {C_BRASS_HOT}")
            r.append(" ", style="")
            r.append(w["id"], style=f"bold {C_DIM if halted else C_BONE}")
            r.append("  ", style="")
            r.append(_fmt_mmss(w.get("elapsed") or 0),
                     style=f"{C_DIM if halted else C_VERDIGRIS}")
            r.append("  ", style="")
            r.append(f"{w.get('events', 0):>3}ev",
                     style=f"{C_DIM} italic")
            if halted:
                r.append("  orphaned", style=f"{C_CRITICAL} italic")
            rows.append(r)

        if done_workers[:4]:
            for w in done_workers[:4]:
                r = Text("   ", overflow="fold")
                outcome = (w.get("outcome") or "").lower()
                color = {
                    "disproved":  C_VERDIGRIS,
                    "eliminated": C_VERDIGRIS,
                    "approved":   C_WATCH,
                    "promising":  C_WATCH,
                    "complete":   C_BONE,
                    "error":      C_CRITICAL,
                    "timeout":    C_CRITICAL,
                }.get(outcome, C_DIM)
                r.append("■ ", style=f"bold {color}")
                r.append(w["id"], style=f"bold {C_BONE}")
                r.append("  ", style="")
                r.append(_fmt_mmss(w.get("done_at") or 0),
                         style=f"{C_DIM}")
                r.append("  ", style="")
                score = w.get("score")
                tag = outcome + (f" {score:.1f}" if score is not None else "")
                r.append(tag, style=f"italic {color}")
                rows.append(r)
    else:
        rows.append(Text("   workers  —", style=f"{C_DIM} italic"))

    # Footer: in-flight count (consistent with mortality).
    rows.append(Text(""))
    flight_row = Text()
    label = "   orphaned   " if halted else "   in flight  "
    flight_row.append(label, style=f"{C_DIM} italic")
    n = len(in_flight)
    if n > 0:
        flight_row.append(
            f"{n}",
            style=f"bold {C_WATCH if halted else C_BRASS_HOT}",
        )
        flight_row.append("   ", style="")
        if not halted:
            for i in range(min(n, 8)):
                flight_row.append(_spin(frame + i * 3, "braille"),
                                  style=f"bold {C_BRASS}")
    else:
        flight_row.append("0", style=C_WHISPER)
    rows.append(flight_row)

    title = Text("  ACTIVITY  ", style=f"bold {C_BONE_HOT} on {C_CHIP_BG}")
    # Border breathes copper when the run is active and in a stage;
    # stays static whisper when halted or idle.
    if halted or not stage:
        border = C_WHISPER
    else:
        border = _breathe(now, period=2.5, cold=C_WHISPER, hot=C_COPPER)
    return Panel(
        Group(*rows),
        box=box.HEAVY,
        border_style=border,
        title=title, title_align="left",
        padding=(1, 1),
    )


def _fmt_mmss(seconds: int) -> str:
    m, s = divmod(max(0, int(seconds)), 60)
    return f"{m:02d}:{s:02d}"


def _halt_gauge(cycles_cur: int, cycles_max: int,
                usd: float, usd_max: float,
                critic_streak: int,
                overrule_24_events: int,
                signal_events: int,
                frame: int,
                now: float) -> Panel:
    tbl = Table(
        show_header=False, show_edge=False, show_lines=False,
        pad_edge=False, padding=(0, 1), expand=True,
    )
    tbl.add_column("cond", justify="left", overflow="fold",
                   style=f"{C_DIM} italic", ratio=1, min_width=20)
    tbl.add_column("gauge", justify="left", no_wrap=True, width=20)
    tbl.add_column("value", justify="right", no_wrap=True, min_width=8)

    def _bar(ratio: float, width: int = 18, tripped: bool = False,
             moving: bool = False) -> Text:
        ratio = max(0.0, min(1.0, ratio))
        filled = int(ratio * width)
        t = Text()
        if tripped:
            # Tripped bars pulse between deep red and signal red.
            hot = _breathe(now, period=0.8, cold="#6b1419", hot=C_CRITICAL)
            t.append("━" * width, style=f"bold {hot}")
            return t
        color = C_NOMINAL if ratio < 0.5 else (C_WATCH if ratio < 0.8 else C_CRITICAL)
        if moving and filled > 0:
            # Single wavefront moving across the filled portion.
            wave_pos = (frame // 2) % max(1, filled)
            for i in range(filled):
                if i == wave_pos:
                    t.append("━", style=f"bold {C_BRASS_HOT}")
                else:
                    t.append("━", style=color)
        else:
            t.append("━" * filled, style=color)
        t.append("·" * (width - filled), style=C_WHISPER)
        return t

    ratio = cycles_cur / max(1, cycles_max)
    tbl.add_row(
        "cycles",
        _bar(ratio, tripped=cycles_cur >= cycles_max, moving=True),
        Text(f"{cycles_cur}/{cycles_max}", style=f"bold {C_BRASS}"),
    )
    # Budget row: subscription-auth run, no dollar meter exists. The
    # actual guardrail is the cycle cap above. Keep the row visible
    # as a §5.1 halt-condition slot but show it as unused.
    tbl.add_row(
        "budget",
        Text.assemble(
            ("━" * 8, C_DIM),
            ("  subscription run · cycle-cap is the guardrail",
             f"{C_DIM} italic"),
        ),
        Text("—", style=f"{C_DIM} italic"),
    )
    tbl.add_row(
        "critic reject-streak",
        _bar(critic_streak / 3.0, tripped=critic_streak >= 3),
        Text(f"{critic_streak}/3", style=f"bold {C_BRASS}"),
    )
    tbl.add_row(
        "overrule claim=24",
        _bar(1.0 if overrule_24_events else 0.0,
             tripped=overrule_24_events > 0),
        Text(f"{overrule_24_events}",
             style=f"bold {C_CRITICAL if overrule_24_events else C_BRASS}"),
    )
    tbl.add_row(
        "signal p≤1e-6",
        _bar(1.0 if signal_events else 0.0, tripped=signal_events > 0),
        Text(f"{signal_events}",
             style=f"bold {C_CRITICAL if signal_events else C_BRASS}"),
    )
    title = Text("  HALT CONDITIONS  ", style=f"bold {C_BONE} on {C_CHIP_BG}")
    return Panel(
        tbl,
        box=box.HEAVY, border_style=C_WHISPER,
        title=title, title_align="left",
        padding=(1, 1),
    )


_REDTEAM_REJECT_RE = re.compile(r"red[- ]?team\s*:\s*reject", re.IGNORECASE)


def _is_redteam_rejected(theory: dict) -> bool:
    """Return True if this theory was vetoed by the red-team-disprover.

    The controller stores red-team outcomes as free-text in the critic
    verdict's ``reasons`` list (e.g. ``"red-team:reject (conf=0.88)"``),
    not as a dedicated field. A vetoed theory typically retains
    ``status='criticized'`` and ``decision='approve'`` — it passed the
    critic but red-team killed it before dispatch. Without this check
    the dashboard's C bucket reads 0 even when red-team is actively
    rejecting, which masks a real signal.
    """
    cv = theory.get("critic_verdict") or {}
    reasons = cv.get("reasons") or []
    if not isinstance(reasons, list):
        return False
    return any(_REDTEAM_REJECT_RE.search(str(r)) for r in reasons)


def _mortality_panel(snap: dict, frame: int, now: float,
                     bar_width: int = 54) -> Panel:
    if snap.get("error"):
        title = Text("  PROPOSAL MORTALITY  §6.1.2  ",
                     style=f"bold {C_BONE_HOT} on {C_CHIP_BG}")
        body = Group(
            Text("  classification paused", style=f"bold {C_CRITICAL}"),
            Text(""),
            Text(f"  {snap['error']}", style=f"{C_DIM} italic", overflow="fold"),
            Text(""),
            Text("  zero counts are hidden until the ledger is readable",
                 style=f"{C_WHISPER} italic"),
        )
        return Panel(
            body,
            box=box.HEAVY, border_style=C_CRITICAL,
            title=title, title_align="left",
            padding=(1, 1),
        )

    theories = snap["theories"]
    experiments = snap["experiments"]
    exp_by_hid: dict[str, dict] = {}
    for e in experiments:
        hid = e.get("hypothesis_id") or ""
        if hid and hid not in exp_by_hid:
            exp_by_hid[hid] = e

    # Ordered buckets (preserve protocol §6.1.2 order).
    stages: list[tuple[str, str, int]] = [
        ("A  in flight",           "proposed/running",      0),
        ("B  critic reject",       "duplicate / elim",      0),
        ("C  red-team killed",     "withdrawn",             0),
        ("D  dispatcher reject",   "admissibility",         0),
        ("E  score <6",            "noise",                 0),
        ("E  score 6-9",           "low",                   0),
        ("E  score 10-17",         "lead",                  0),
        ("E  score 18-23",         "SIGNAL",                0),
        ("E  score 24",            "BREAK",                 0),
        ("F  error / timeout",     "infra",                 0),
    ]

    def _bump(name: str) -> None:
        for i, (n, sub, c) in enumerate(stages):
            if n == name:
                stages[i] = (n, sub, c + 1)
                return

    for t in theories:
        cv = t.get("critic_verdict") or {}
        decision = cv.get("decision", "")
        status = t.get("status", "")
        # Critic-level reject first — if critic kills, red-team never sees it.
        if decision and decision.startswith("reject_"):
            _bump("B  critic reject"); continue
        # Red-team veto is stored inside critic_verdict.reasons as
        # free text like "red-team:reject (conf=0.88)". These theories
        # typically retain status='criticized' + decision='approve' so
        # they LOOK in-flight; _is_redteam_rejected() catches them.
        if _is_redteam_rejected(t):
            _bump("C  red-team killed"); continue
        if status in ("proposed", "criticized", "approved", "running"):
            _bump("A  in flight"); continue
        if status in ("withdrawn", "superseded"):
            _bump("C  red-team killed"); continue
        exp = exp_by_hid.get(t.get("hypothesis_id") or "")
        if exp is None:
            _bump("F  error / timeout"); continue
        r = exp.get("result") or {}
        est = (r.get("status") or "").lower()
        if est in ("error", "timeout"):
            _bump("F  error / timeout"); continue
        notes = (r.get("notes") or "").lower()
        if "admissibility" in notes or "exhaustion overlap" in notes or "translation" in notes:
            _bump("D  dispatcher reject"); continue
        # Dashboard-hardening 2026-04-22: only surface theories that
        # still warrant investigation in the score-band E-rows. A
        # theory whose lifecycle settled into ``completed`` or
        # ``eliminated`` has already been resolved — stat-audit /
        # red-team / operator review left it in a terminal state, and
        # showing its historical score as a live band entry misleads
        # the operator into thinking there's an unresolved SIGNAL to
        # chase. Only PROMISING (explicit "deserves follow-up") survives
        # into the score-based rows.
        if status in ("completed", "eliminated"):
            continue
        cs = r.get("crib_score") or t.get("best_score") or 0
        try:
            cs = int(cs)
        except (TypeError, ValueError):
            cs = 0
        if cs < 6:
            _bump("E  score <6")
        elif cs <= 9:
            _bump("E  score 6-9")
        elif cs <= 17:
            _bump("E  score 10-17")
        elif cs <= 23:
            _bump("E  score 18-23")
        else:
            _bump("E  score 24")

    total = max(1, sum(c for _, _, c in stages))

    tbl = Table(
        show_header=False, show_edge=False, show_lines=False,
        pad_edge=False, padding=(0, 1), expand=True,
    )
    # stage takes any excess horizontal space (ratio=1) so labels can
    # grow; bar column is fixed at bar_width+2 brackets so it's always
    # flush (no trailing whitespace); everything else is min_width only.
    tbl.add_column("stage", overflow="fold", ratio=1, min_width=22,
                   style=f"{C_DIM} italic")
    tbl.add_column("sub", overflow="fold", min_width=18,
                   style=f"{C_WHISPER} italic")
    tbl.add_column("bar", no_wrap=True, width=bar_width + 2)
    tbl.add_column("n", justify="right", min_width=6, no_wrap=True)
    tbl.add_column("pct", justify="right", min_width=8, no_wrap=True,
                   style=f"{C_DIM} italic")

    highlight = {
        "A  in flight":        ("▰▱", C_BRASS, C_BRASS_HOT, True),
        "B  critic reject":    ("▰▱", C_VERDIGRIS, C_VERD_HOT, False),
        "C  red-team killed":  ("▰▱", C_VERDIGRIS, C_VERD_HOT, False),
        "D  dispatcher reject":("▰▱", C_COPPER, C_COPPER_HOT, False),
        "E  score <6":         ("▰▱", C_DIM, C_BONE, False),
        "E  score 6-9":        ("▰▱", C_VERDIGRIS, C_VERD_HOT, False),
        "E  score 10-17":      ("▰▱", C_WATCH, C_BRASS_HOT, False),
        "E  score 18-23":      ("▰▱", C_WATCH, C_CRITICAL, False),
        "E  score 24":         ("▰▱", C_CRITICAL, C_CRITICAL, False),
        "F  error / timeout":  ("▰▱", C_COPPER, C_COPPER_HOT, False),
    }

    for name, sub, count in stages:
        filled_char, cold_c, hot_c, animate = highlight[name]
        pct = count / total if total else 0.0
        filled = int(pct * bar_width)
        bar = Text()
        bar.append("▕", style=C_WHISPER)
        if animate and count > 0 and filled > 0:
            # Pulsing wavefront that moves across the filled portion.
            wave_pos = (frame // 2) % max(1, filled)
            for i in range(filled):
                if i == wave_pos:
                    bar.append(filled_char[0], style=f"bold {hot_c}")
                else:
                    bar.append(filled_char[0], style=cold_c)
        else:
            if count > 0:
                bar.append(filled_char[0] * filled, style=cold_c)
        bar.append(filled_char[1] * (bar_width - filled), style=C_WHISPER)
        bar.append("▏", style=C_WHISPER)

        count_style = f"bold {C_BRASS}" if count > 0 else C_WHISPER
        if name == "E  score 18-23" and count > 0:
            count_style = f"bold {C_WATCH}"
        if name == "E  score 24" and count > 0:
            count_style = f"bold {C_CRITICAL}"

        tbl.add_row(
            name, sub, bar,
            Text(str(count), style=count_style),
            f"{pct*100:5.1f}%",
        )

    total_t = Text()
    total_t.append("  total proposals   ", style=f"{C_DIM} italic")
    total_t.append(f"{sum(c for _, _, c in stages):>4}",
                   style=f"bold {C_BRASS}")
    total_t.append(f"       target : failure-mode classification on dominant row",
                   style=f"{C_WHISPER} italic")

    title = Text("  PROPOSAL MORTALITY  §6.1.2  ",
                 style=f"bold {C_BONE_HOT} on {C_CHIP_BG}")
    return Panel(
        Group(tbl, Text(""), total_t),
        box=box.HEAVY, border_style=C_WHISPER,
        title=title, title_align="left",
        padding=(1, 1),
    )


def _telemetry_panel(history: "_History",
                     best_crib: int,
                     stream_events: int,
                     active_workers: int,
                     completed_workers: int,
                     frame: int) -> Panel:
    """Activity telemetry driven by agent-SDK worker stream events.

    We deliberately do NOT show a dollar figure here: this run's log does
    not surface per-call USD, and the protocol's actual guardrail is the
    cycle cap (shown on the banner). Showing a zero-valued cost meter
    would be misleading; better to show what we *can* measure — the raw
    agent activity in the form of stream events.
    """
    spark_w = 20

    score_color = (
        C_CRITICAL if best_crib >= 18 else
        (C_WATCH if best_crib >= 10 else
         (C_VERDIGRIS if best_crib >= 6 else C_DIM))
    )
    score_color_hot = (
        C_CRITICAL if best_crib >= 18 else
        (C_BRASS_HOT if best_crib >= 10 else
         (C_VERD_HOT if best_crib >= 6 else C_BONE))
    )

    tbl = Table(
        show_header=False, show_edge=False, show_lines=False,
        pad_edge=False, padding=(0, 1), expand=True,
    )
    tbl.add_column("lbl", style=f"{C_DIM} italic", overflow="fold",
                   min_width=14)
    tbl.add_column("val", no_wrap=True, overflow="ignore", ratio=1)

    tbl.add_row(
        "stream events",
        Text.assemble(
            _sparkline_pretty(history.events(), spark_w, C_BRASS, C_BRASS_HOT),
            ("  ", ""),
            (f"{stream_events:,}", f"bold {C_BRASS_HOT}"),
            (" total", C_DIM),
        ),
    )
    tbl.add_row(
        "best crib",
        Text.assemble(
            _sparkline_pretty(history.best(), spark_w, score_color, score_color_hot),
            ("  ", ""),
            (f"{best_crib:>2}", f"bold {score_color_hot}"),
            (" / 24", C_DIM),
        ),
    )
    tbl.add_row(
        "active workers",
        Text.assemble(
            _sparkline_pretty(history.workers(), spark_w, C_VERDIGRIS, C_VERD_HOT),
            ("  ", ""),
            (f"{active_workers}", f"bold {C_VERD_HOT if active_workers else C_DIM}"),
            ("  (+", C_DIM),
            (f"{completed_workers}", C_BONE),
            (" done)", C_DIM),
        ),
    )
    title = Text("  TELEMETRY  ", style=f"bold {C_BONE} on {C_CHIP_BG}")
    return Panel(
        tbl,
        box=box.HEAVY, border_style=C_WHISPER,
        title=title, title_align="left",
        padding=(1, 1),
    )


def _status_panel(logdata: dict, frame: int, now: float) -> Panel:
    """Claude Code /status-equivalent: real subscription token meter
    broken down per model, with turn + session counts. Data sourced
    from ~/.claude/projects/.../<uuid>.jsonl usage dicts — same
    source Claude Code itself uses for /status.
    """
    sub = logdata.get("subscription") or {}
    tok_in = int(sub.get("input", 0))
    tok_out = int(sub.get("output", 0))
    tok_cr = int(sub.get("cache_read", 0))
    tok_cc = int(sub.get("cache_create", 0))
    sessions = int(sub.get("sessions", 0))
    turns = int(sub.get("turns", 0))
    by_model = sub.get("by_model") or {}

    grand_total = tok_in + tok_out + tok_cr + tok_cc

    rows: list = []

    # Header chip — "slash" and "status" styled like a Claude Code prompt.
    hdr = Text()
    hdr.append("   / ", style=f"{C_DIM} italic")
    hdr.append("status", style=f"bold {C_VERD_HOT}")
    hdr.append("     ", style=C_WHISPER)
    hdr.append(_spin(frame, "braille"), style=f"bold {C_BRASS_HOT}")
    hdr.append("  subscription · ", style=f"{C_DIM} italic")
    hdr.append("Claude Code ", style=f"bold {C_BONE}")
    hdr.append("(not API billing)", style=f"{C_WATCH} italic")
    rows.append(hdr)
    rows.append(Text(""))

    # Per-model breakdown table.
    tbl = Table(
        show_header=True, header_style=f"{C_DIM} italic bold",
        show_edge=False, show_lines=False, pad_edge=False,
        padding=(0, 1), expand=True,
    )
    tbl.add_column("model", overflow="fold", min_width=18,
                   style=f"{C_BONE}")
    tbl.add_column("input", justify="right", min_width=9,
                   no_wrap=True, style=C_BRASS)
    tbl.add_column("output", justify="right", min_width=9,
                   no_wrap=True, style=C_BRASS_HOT)
    tbl.add_column("turns", justify="right", min_width=6,
                   no_wrap=True, style=f"{C_DIM} italic")
    tbl.add_column("out%", justify="right", min_width=6,
                   no_wrap=True, style=C_COPPER)

    total_out_across = sum(v.get("output", 0) for v in by_model.values()) or 1
    if by_model:
        for m, v in sorted(by_model.items(),
                           key=lambda x: -x[1].get("input", 0) - x[1].get("output", 0)):
            inp = v.get("input", 0)
            out = v.get("output", 0)
            trn = v.get("turns", 0)
            out_pct = 100.0 * out / total_out_across
            tbl.add_row(
                m or "unknown",
                _fmt_tokens(inp),
                _fmt_tokens(out),
                f"{trn:,}",
                f"{out_pct:5.1f}%",
            )
    else:
        tbl.add_row("—", "—", "—", "—", "—")

    rows.append(tbl)
    rows.append(Text(""))

    # Aggregate totals footer.
    tot_tbl = Table(
        show_header=False, show_edge=False, show_lines=False,
        pad_edge=False, padding=(0, 1), expand=True,
    )
    tot_tbl.add_column("k", overflow="fold", min_width=14,
                       style=f"{C_DIM} italic")
    tot_tbl.add_column("v", no_wrap=True, ratio=1)
    tot_tbl.add_row(
        "  cache read",
        Text.assemble(
            (_fmt_tokens(tok_cr), f"bold {C_COPPER}"),
            ("  ", ""),
            (f"({tok_cr:,} raw)", f"{C_DIM} italic"),
        ),
    )
    tot_tbl.add_row(
        "  cache create",
        Text.assemble(
            (_fmt_tokens(tok_cc), f"bold {C_COPPER}"),
            ("  ", ""),
            (f"({tok_cc:,} raw)", f"{C_DIM} italic"),
        ),
    )
    tot_tbl.add_row(
        "  sessions · turns",
        Text.assemble(
            (f"{sessions:,}", f"bold {C_BONE}"),
            (" sessions  ", C_DIM),
            (f"{turns:,}", f"bold {C_BONE}"),
            (" turns", C_DIM),
        ),
    )
    tot_tbl.add_row(
        "  grand total",
        Text.assemble(
            (_fmt_tokens(grand_total), f"bold {C_BRASS_HOT}"),
            ("  tokens", f"{C_DIM} italic"),
            (f"   ({grand_total:,} raw)", f"{C_DIM} italic"),
        ),
    )
    rows.append(tot_tbl)

    title = Text("  SUBSCRIPTION  §/status  ",
                 style=f"bold {C_BONE_HOT} on {C_CHIP_BG}")
    return Panel(
        Group(*rows),
        box=box.HEAVY, border_style=C_WHISPER,
        title=title, title_align="left",
        padding=(1, 1),
    )


_TAG_COLOR = {
    "CYCLE":    C_BONE_HOT,    # cycle-boundary markers (most important)
    "PROPOSAL": C_DIM,
    "CRITIC":   C_VERDIGRIS,
    "DISPATCH": C_BRASS,
    "API":      C_WHISPER,
    "SIGNAL":   C_WATCH,
    "ERROR":    C_CRITICAL,
    "SCORE":    C_COPPER,
    "LOG":      C_DIM,
    "WARNING":  C_WATCH,
}

# Full-name chip width: " DISPATCH " / " PROPOSAL " / " WARNING  " — all
# padded to 10 chars so the tag column is perfectly flush. Each event row's
# message column starts at col 13 and wraps within its own column; this
# prevents long lines from bleeding into the tag column on the next line.
_TAG_CHIP_WIDTH = 10


def _event_ticker(events: list[tuple[str, str]],
                  frame: int, now: float,
                  source_badges: list[tuple[str, str]] | None = None) -> Panel:
    """Render recent events with full-word tag chips and column-safe wrap.

    The previous Group(Text) implementation had two problems: (a) when a
    message wrapped, the continuation line started at column 0 and
    visually collided with the tag column of the next event; (b) tags
    were 3-5 letter abbreviations (ERR / CRIT / DISP / SIG).

    Fix: use a Rich Table with TWO columns (tag, message). Rich Tables
    wrap each cell within its own column, so a wrapped message stays
    inside the message column — continuation rows are naturally indented
    under the message-column start, never touching the tag column.
    Tag chips are now full words (ERROR / CRITIC / DISPATCH / SIGNAL /
    PROPOSAL / WARNING / LOG / API / SCORE), all padded to the same
    width for a clean left edge.
    """
    title = Text("  EVENT TAPE  ", style=f"bold {C_BONE} on {C_CHIP_BG}")
    if not events and not source_badges:
        return Panel(
            Text("  · awaiting events ·", style=f"{C_WHISPER} italic"),
            box=box.HEAVY, border_style=C_WHISPER,
            title=title, title_align="left",
            padding=(0, 1),
        )

    tbl = Table(
        show_header=False, show_edge=False, show_lines=False,
        pad_edge=False, padding=(0, 0), expand=True, box=None,
    )
    # Tag column: fixed width that fits ` {TAG:<8} ` + 2 trailing spaces
    # = 12 cells. no_wrap ensures the chip never wraps.
    tbl.add_column("tag", no_wrap=True, width=_TAG_CHIP_WIDTH + 3,
                   overflow="ellipsis")
    # Message column: takes the rest of the panel, wraps inside itself.
    tbl.add_column("msg", overflow="fold", ratio=1)

    def _mk_tag_cell(tag: str, color: str) -> Text:
        t = Text()
        t.append(f" {tag:<{_TAG_CHIP_WIDTH - 2}} ",
                 style=f"bold on {C_CHIP_BG} {color}")
        t.append("  ", style="")
        return t

    # Optional WARNING row at the top (source badges).
    if source_badges:
        msg = Text(overflow="fold")
        for idx, (badge, color) in enumerate(source_badges):
            if idx:
                msg.append(" · ", style=C_WHISPER)
            msg.append(badge, style=f"bold {color}")
        tbl.add_row(_mk_tag_cell("WARNING", C_WATCH), msg)

    tail = events[-14:]
    for i, (tag, line) in enumerate(tail):
        color = _TAG_COLOR.get(tag, C_BONE)
        # Strip leading whitespace + timestamp ("13:29:01 ...") so the
        # event text starts with its content, not a clock. Allow indent
        # before the stamp — controller output is often padded.
        line_trim = re.sub(r"^\s*\d{2}:\d{2}:\d{2}\s+", "", line)
        # Strip trailing residue from box-drawn panels in case something
        # slipped through the parser-level filter.
        line_trim = line_trim.rstrip("│┃ ").lstrip("│┃ ")
        is_latest = (i == len(tail) - 1)
        row_style = C_BONE if tag not in ("ERROR", "SIGNAL") else color

        msg = Text(overflow="fold")
        msg.append(line_trim, style=row_style)
        if is_latest:
            # Cursor blinks at 2Hz on the tip of the latest line.
            cursor = "▮" if int(now * 2) % 2 == 0 else " "
            msg.append(" ", style="")
            msg.append(cursor, style=f"bold {C_BRASS_HOT}")

        tbl.add_row(_mk_tag_cell(tag, color), msg)

    return Panel(
        tbl,
        box=box.HEAVY, border_style=C_WHISPER,
        title=title, title_align="left",
        padding=(0, 1),
    )


# ─── History buffer ─────────────────────────────────────────────────────────

class _History:
    """Ring buffers of (stream events total, best crib, active workers)
    sampled each refresh. Used to draw sparklines in the TELEMETRY panel.
    """
    def __init__(self, capacity: int = 96):
        self._events: deque[float] = deque(maxlen=capacity)
        self._best: deque[float] = deque(maxlen=capacity)
        self._workers: deque[float] = deque(maxlen=capacity)

    def push(self, events: float, best: float, workers: float) -> None:
        self._events.append(events)
        self._best.append(best)
        self._workers.append(workers)

    def events(self) -> list[float]:
        return list(self._events)

    def best(self) -> list[float]:
        return list(self._best)

    def workers(self) -> list[float]:
        return list(self._workers)


# ─── Halt counters ──────────────────────────────────────────────────────────

def _halt_counters(snap: dict, events: list[tuple[str, str]]) -> dict:
    streak = 0
    for t in snap["theories"]:
        cv = t.get("critic_verdict") or {}
        d = cv.get("decision", "")
        if d.startswith("reject_"):
            streak += 1
        elif d == "approve" or t.get("status") in ("running", "completed",
                                                    "eliminated", "promising"):
            break
        else:
            break
    overrule_24 = 0
    signal_events = 0
    for tag, line in events:
        low = line.lower()
        if "fields_overwritten" in low and "crib_score=24" in low:
            overrule_24 += 1
        if "signal" in low and "alert" in low:
            signal_events += 1
    for e in snap["experiments"]:
        r = e.get("result") or {}
        try:
            cs = int(r.get("crib_score") or 0)
        except (TypeError, ValueError):
            cs = 0
        p = r.get("p_value_vs_null")
        if cs >= 24 and p is not None and p <= 1e-6:
            signal_events += 1
    return {
        "critic_streak": streak,
        "overrule_24_events": overrule_24,
        "signal_events": signal_events,
    }


# Dashboard-hardening 2026-04-22: statuses that indicate the theory has
# been resolved and no longer deserves to drive live telemetry. A high
# crib_score attached to one of these is archived history, not a live
# signal — per the user's explicit direction, if it's truly noise /
# resolved, it doesn't belong on the dashboard.
_RESOLVED_THEORY_STATUSES: frozenset[str] = frozenset({
    "completed", "eliminated", "withdrawn", "superseded",
})


def _best_crib(snap: dict) -> int:
    """Best crib_score across theories that still warrant investigation.

    Filters out experiments / theories whose owning theory settled into
    a resolved lifecycle state (``completed``, ``eliminated``,
    ``withdrawn``, ``superseded``). Without this filter, the dashboard's
    "best crib" telemetry would display historical crib-paste
    fabrications (crib_score=24 results that stat-audit already rejected
    as noise) as if they were live signal — the opposite of what the
    operator needs to see.

    When no investigable theory has a score yet, returns 0. A legitimate
    new PROMISING theory at crib_score N will immediately surface.
    """
    status_by_hid: dict[str, str] = {}
    for t in snap["theories"]:
        hid = (t.get("hypothesis_id") or "").strip()
        if hid:
            status_by_hid[hid] = (t.get("status") or "").lower()

    def _investigable(hid: str) -> bool:
        status = status_by_hid.get(hid, "")
        return status not in _RESOLVED_THEORY_STATUSES

    best = 0
    for e in snap["experiments"]:
        hid = (e.get("hypothesis_id") or "").strip()
        if not _investigable(hid):
            continue
        r = e.get("result") or {}
        try:
            cs = int(r.get("crib_score") or 0)
        except (TypeError, ValueError):
            cs = 0
        if cs > best:
            best = cs
    for t in snap["theories"]:
        status = (t.get("status") or "").lower()
        if status in _RESOLVED_THEORY_STATUSES:
            continue
        try:
            bs = int(t.get("best_score") or 0)
        except (TypeError, ValueError):
            bs = 0
        if bs > best:
            best = bs
    return best


# ─── Layout composition ─────────────────────────────────────────────────────

def _compose_wide(snap: dict, logdata: dict, max_cycles: int, max_usd: float,
                  history: _History, start_time: float,
                  frame: int, now: float) -> Layout:
    """Layout for ≥200 cols (4K / 16:9).

    Banner · Row A (CT | ACTIVITY | POSTURE) · Row B (MORTALITY | STATUS |
    HALT | TELEMETRY) · Tape. MORTALITY sits alongside STATUS so the 16:9
    horizontal real estate is used evenly instead of leaving mortality
    as a thin full-width strip.
    """
    run_start = logdata.get("first_seen") or start_time
    # Freeze elapsed at the last log write once we decide the run is
    # halted — otherwise the clock keeps climbing after the controller
    # exited, giving the misleading impression that the run is still
    # progressing.
    _last_mtime = logdata.get("last_modified") or now
    _ctrl_alive = bool(logdata.get("controller_alive"))
    if _is_run_halted(_last_mtime, now, controller_alive=_ctrl_alive):
        elapsed = max(0.0, _last_mtime - run_start)
    else:
        elapsed = max(0.0, now - run_start)
    workers = logdata.get("workers") or {}
    active_workers = sum(1 for w in workers.values() if w.get("status") == "running")
    completed_workers = sum(1 for w in workers.values() if w.get("status") == "done")
    stream_events = logdata.get("stream_events_total", 0)
    history.push(stream_events, _best_crib(snap), active_workers)
    halts = _halt_counters(snap, logdata["recent"])
    source_badges = _source_badges(snap, logdata, now)

    # Pull live subscription token totals from Claude Code JSONL sessions.
    # Attach to logdata so downstream panels can read it.
    logdata["subscription"] = _query_subscription_tokens(run_start)

    root = Layout()
    root.split_column(
        Layout(_banner(
            cycle_cur=logdata["cycle_current"], cycle_max=max_cycles,
            usd=logdata["total_usd"], usd_max=max_usd,
            elapsed_sec=elapsed, frame=frame,
            log_last_mtime=logdata["last_modified"], now=now,
            stream_events_total=stream_events,
            active_workers=active_workers,
            source_badges=source_badges,
            subscription=logdata.get("subscription"),
            controller_alive=bool(logdata.get("controller_alive")),
        ), name="banner", size=3),
        Layout(name="row_a", size=14),      # CT + ACTIVITY + POSTURE
        Layout(name="row_b", size=18),      # MORTALITY + STATUS + HALT + TELEMETRY
        Layout(_event_ticker(logdata["recent"], frame, now, source_badges),
               name="tape", size=18),
    )

    # Row A: K4 CT (wide) | ACTIVITY (medium) | POSTURE (medium)
    root["row_a"].split_row(
        Layout(_k4_ct_panel(), ratio=3),
        Layout(_activity_panel(snap, logdata, frame, now), ratio=2),
        Layout(_posture_panel(), ratio=2),
    )

    # Row B: mortality on the left gets the most width, status next,
    # halt + telemetry stacked on the right.
    root["row_b"].split_row(
        Layout(
            _mortality_panel(snap, frame, now, bar_width=22),
            ratio=5,
        ),
        Layout(
            _status_panel(logdata, frame, now),
            ratio=4,
        ),
        Layout(name="right", ratio=3),
    )
    root["row_b"]["right"].split_column(
        Layout(_halt_gauge(
            cycles_cur=logdata["cycle_current"], cycles_max=max_cycles,
            usd=logdata["total_usd"], usd_max=max_usd,
            critic_streak=halts["critic_streak"],
            overrule_24_events=halts["overrule_24_events"],
            signal_events=halts["signal_events"],
            frame=frame, now=now,
        ), ratio=1),
        Layout(_telemetry_panel(
            history,
            best_crib=_best_crib(snap),
            stream_events=stream_events,
            active_workers=active_workers,
            completed_workers=completed_workers,
            frame=frame,
        ), ratio=1),
    )
    return root


def _compose_narrow(snap: dict, logdata: dict, max_cycles: int, max_usd: float,
                    history: _History, start_time: float,
                    frame: int, now: float) -> Layout:
    """Fallback for < 200 cols: original 2-column layout, minor tweaks."""
    # Anchor elapsed to log creation-time (= run start) so the clock
    # reflects the REAL run duration regardless of when the dashboard
    # was launched. Fall back to dashboard-launch time on first read.
    run_start = logdata.get("first_seen") or start_time
    # Freeze elapsed at the last log write once we decide the run is
    # halted — otherwise the clock keeps climbing after the controller
    # exited, giving the misleading impression that the run is still
    # progressing.
    _last_mtime = logdata.get("last_modified") or now
    _ctrl_alive = bool(logdata.get("controller_alive"))
    if _is_run_halted(_last_mtime, now, controller_alive=_ctrl_alive):
        elapsed = max(0.0, _last_mtime - run_start)
    else:
        elapsed = max(0.0, now - run_start)
    workers = logdata.get("workers") or {}
    active_workers = sum(1 for w in workers.values() if w.get("status") == "running")
    completed_workers = sum(1 for w in workers.values() if w.get("status") == "done")
    stream_events = logdata.get("stream_events_total", 0)
    history.push(stream_events, _best_crib(snap), active_workers)
    halts = _halt_counters(snap, logdata["recent"])
    source_badges = _source_badges(snap, logdata, now)
    logdata["subscription"] = _query_subscription_tokens(run_start)

    root = Layout()
    root.split_column(
        Layout(_banner(
            cycle_cur=logdata["cycle_current"], cycle_max=max_cycles,
            usd=logdata["total_usd"], usd_max=max_usd,
            elapsed_sec=elapsed, frame=frame,
            log_last_mtime=logdata["last_modified"], now=now,
            stream_events_total=stream_events,
            active_workers=active_workers,
            source_badges=source_badges,
            subscription=logdata.get("subscription"),
            controller_alive=bool(logdata.get("controller_alive")),
        ), name="banner", size=3),
        Layout(name="middle"),
        Layout(_event_ticker(logdata["recent"], frame, now, source_badges),
               name="tape", size=15),
    )
    root["middle"].split_row(
        Layout(name="left", ratio=3),
        Layout(name="right", ratio=2),
    )
    root["middle"]["left"].split_column(
        Layout(_k4_ct_panel(), name="ct", size=12),
        Layout(_activity_panel(snap, logdata, frame, now),
               name="act", size=10),
        Layout(_posture_panel(), name="posture"),
    )
    root["middle"]["right"].split_column(
        Layout(_halt_gauge(
            cycles_cur=logdata["cycle_current"], cycles_max=max_cycles,
            usd=logdata["total_usd"], usd_max=max_usd,
            critic_streak=halts["critic_streak"],
            overrule_24_events=halts["overrule_24_events"],
            signal_events=halts["signal_events"],
            frame=frame, now=now,
        ), size=9),
        Layout(_mortality_panel(snap, frame, now, bar_width=36)),
        Layout(_telemetry_panel(
            history,
            best_crib=_best_crib(snap),
            stream_events=stream_events,
            active_workers=active_workers,
            completed_workers=completed_workers,
            frame=frame,
        ), size=10),
    )
    return root


def _compose_frame(db_path: Path, log_path: Path,
                   max_cycles: int, max_usd: float,
                   history: _History, start_time: float,
                   frame: int, console_width: int) -> Layout:
    snap = _query_ledger(db_path)
    logdata = _parse_log(log_path)
    now = time.time()

    # Dashboard-hardening (2026-04-22): detect live controller once per
    # frame and attach to logdata so halt/liveness checks can use it
    # without signature churn across panel composers.
    pid = _detect_controller_pid()
    logdata["controller_pid"] = pid
    logdata["controller_alive"] = bool(pid and _is_pid_alive(pid))

    # If the log carried an explicit "CYCLE N of M" ceiling, prefer
    # that over the CLI's --max-cycles (which is typically a relative
    # increment rather than an absolute ceiling).
    cycle_max_effective = int(logdata.get("cycle_max_from_log") or 0) or max_cycles

    if console_width >= 200:
        return _compose_wide(
            snap, logdata, cycle_max_effective, max_usd,
            history, start_time, frame, now,
        )
    return _compose_narrow(
        snap, logdata, cycle_max_effective, max_usd,
        history, start_time, frame, now,
    )


# ─── Entry point ────────────────────────────────────────────────────────────

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    # Dashboard-hardening (2026-04-22): defaults now auto-detect the
    # current active run. Pass --db / --log explicitly only when you
    # want to point the dashboard at a non-canonical location (e.g.
    # a historical ledger copy or a diverted log).
    ap.add_argument(
        "--db", type=Path, default=None,
        help="ledger sqlite path (default: auto-detect db/theory_ledger.sqlite)",
    )
    ap.add_argument(
        "--log", type=Path, default=None,
        help="controller log path (default: auto-detect newest logs/campaign_*/run_*.log)",
    )
    ap.add_argument("--max-cycles", type=int, default=15,
                    help="fallback cycle ceiling when the log lacks a "
                         "'CYCLE N of M' banner (the log's value always wins)")
    ap.add_argument("--max-usd", type=float, default=25.00)
    ap.add_argument("--refresh", type=float, default=0.33,
                    help="refresh interval seconds (default 0.33 = 3 Hz)")
    args = ap.parse_args(argv)

    # Resolve paths. Flag overrides take priority; auto-detect fills in
    # defaults. Missing paths are tolerated — the composers render a
    # graceful "waiting" state rather than crashing.
    if args.db is None:
        args.db = _detect_active_db() or (_ROOT / "db" / "theory_ledger.sqlite")
    if args.log is None:
        detected_log = _detect_active_log()
        if detected_log is not None:
            args.log = detected_log
        else:
            # Give composers a path to stat against; Path.exists() returns
            # False for non-existent paths and the composers handle that.
            args.log = _ROOT / "logs" / "campaign_pending.log"

    console = Console(color_system="truecolor")
    history = _History()
    start_time = time.time()
    frame_counter = itertools.count()
    width = console.size.width

    try:
        with Live(
            _compose_frame(
                args.db, args.log, args.max_cycles, args.max_usd,
                history, start_time, next(frame_counter), width,
            ),
            console=console,
            refresh_per_second=1.0 / max(0.1, args.refresh),
            screen=True, transient=False,
        ) as live:
            while True:
                time.sleep(args.refresh)
                width = console.size.width  # re-measure in case of SIGWINCH
                live.update(_compose_frame(
                    args.db, args.log, args.max_cycles, args.max_usd,
                    history, start_time, next(frame_counter), width,
                ))
    except KeyboardInterrupt:
        console.print(
            "\n[dim italic]dashboard stopped · run continues[/]"
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
