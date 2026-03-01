#!/usr/bin/env python3
"""
KryptosBot Live Monitor v2

Real-time campaign dashboard. Queries the hypotheses table directly
(not the unreliable sessions table) for ground-truth worker status.

Usage:
    python monitor.py                  # Refresh every 3 seconds
    python monitor.py --interval 1     # Faster refresh
    python monitor.py --db path.db     # Explicit DB path
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


# ── ANSI codes ──────────────────────────────────────────────────────
CLEAR   = "\033[2J\033[H"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
RESET   = "\033[0m"
BG_RED  = "\033[41m"
BG_GREEN = "\033[42m"

STATUS_STYLE = {
    "queued":       (CYAN,   "○"),
    "running":      (YELLOW, "⚡"),
    "promising":    (GREEN,  "★"),
    "disproved":    (RED,    "✗"),
    "inconclusive": (DIM,    "·"),
    "solved":       (BG_GREEN + WHITE, "!!!"),
}

WIDTH = 78


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _elapsed(iso_str: str) -> str:
    """Human-readable elapsed time from an ISO timestamp."""
    try:
        start = datetime.fromisoformat(iso_str)
        secs = (datetime.now(timezone.utc) - start).total_seconds()
        if secs < 60:
            return f"{int(secs)}s"
        elif secs < 3600:
            return f"{int(secs // 60)}m{int(secs % 60):02d}s"
        else:
            return f"{int(secs // 3600)}h{int((secs % 3600) // 60):02d}m"
    except Exception:
        return "?"


def _bar(done: int, total: int, width: int = 30) -> str:
    """Render a progress bar."""
    if total == 0:
        return "░" * width
    filled = int(width * done / total)
    return "█" * filled + "░" * (width - filled)


def render(db_path: Path, campaign_start: datetime | None) -> str:
    """Build the full dashboard from a single DB snapshot."""
    conn = _connect(db_path)
    lines: list[str] = []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # ── Header ──────────────────────────────────────────────────────
    lines.append(f"{BOLD}{CYAN}{'─' * WIDTH}")
    lines.append(f"  KryptosBot Monitor  {DIM}│{RESET}{BOLD}{CYAN}  {now_str} UTC")
    lines.append(f"{'─' * WIDTH}{RESET}")

    # ── Status counts ───────────────────────────────────────────────
    rows = conn.execute(
        "SELECT status, COUNT(*) as n FROM hypotheses GROUP BY status"
    ).fetchall()
    counts = {r["status"]: r["n"] for r in rows}
    total = sum(counts.values())
    running = counts.get("running", 0)
    done = total - running - counts.get("queued", 0)

    parts = []
    for status in ["running", "promising", "disproved", "inconclusive", "queued", "solved"]:
        n = counts.get(status, 0)
        if n:
            color, icon = STATUS_STYLE.get(status, (RESET, "?"))
            parts.append(f"{color}{icon} {status}:{n}{RESET}")

    lines.append(f"  {BOLD}{total}{RESET} hypotheses  │  " + "  ".join(parts))

    # Progress bar
    bar = _bar(done, total)
    pct = (done / total * 100) if total else 0
    elapsed = ""
    if campaign_start:
        elapsed = f"  {DIM}elapsed: {_elapsed(campaign_start.isoformat())}{RESET}"
    lines.append(f"  [{bar}] {pct:.0f}% complete ({done}/{total}){elapsed}")
    lines.append("")

    # ── Active workers (from hypotheses, not sessions) ──────────────
    active = conn.execute(
        "SELECT id, strategy, worker_id, updated_at, created_at "
        "FROM hypotheses WHERE status = 'running' ORDER BY id ASC"
    ).fetchall()

    if active:
        lines.append(f"  {BOLD}{YELLOW}Active Workers ({len(active)}):{RESET}")
        for h in active:
            age = _elapsed(h["created_at"])
            wid = h["worker_id"] or "pending"
            # Truncate strategy name to fit
            name = h["strategy"]
            if len(name) > 38:
                name = name[:35] + "..."
            lines.append(
                f"    {YELLOW}⚡{RESET} {DIM}#{h['id']:>3}{RESET} "
                f"{name:<40} {DIM}{wid}  {age}{RESET}"
            )
        lines.append("")
    else:
        lines.append(f"  {DIM}No active workers{RESET}\n")

    # ── Recently completed (last 8, newest first) ───────────────────
    recent = conn.execute(
        "SELECT id, strategy, status, score, summary, updated_at "
        "FROM hypotheses "
        "WHERE status NOT IN ('running', 'queued') "
        "ORDER BY updated_at DESC LIMIT 8"
    ).fetchall()

    if recent:
        lines.append(f"  {BOLD}Recent Activity:{RESET}")
        for r in recent:
            color, icon = STATUS_STYLE.get(r["status"], (RESET, "?"))
            age = _elapsed(r["updated_at"])
            summary = (r["summary"] or "")[:52]
            score_str = ""
            if r["score"] and r["score"] > 0:
                score_str = f" {WHITE}score={r['score']:.0f}{RESET}"
            lines.append(
                f"    {color}{icon}{RESET} {DIM}#{r['id']:>3}{RESET} "
                f"{r['strategy'][:30]:<30} "
                f"{color}{r['status']:<13}{RESET}"
                f"{score_str}  {DIM}{age} ago{RESET}"
            )
            if summary:
                lines.append(f"         {DIM}{summary}{RESET}")
        lines.append("")

    # ── New disproofs this session (not pre-existing) ───────────────
    new_disproofs = conn.execute(
        "SELECT strategy, criteria, evidence, disproved_at "
        "FROM disproof_log "
        "WHERE evidence NOT LIKE 'Imported from framework%' "
        "AND criteria NOT LIKE 'Pre-existing:%' "
        "ORDER BY disproved_at DESC LIMIT 5"
    ).fetchall()

    if new_disproofs:
        lines.append(f"  {BOLD}{RED}New Disproofs:{RESET}")
        for d in new_disproofs:
            age = _elapsed(d["disproved_at"])
            lines.append(
                f"    {RED}✗{RESET} {d['strategy'][:35]:<35}  {DIM}{age} ago{RESET}"
            )
            ev = (d["evidence"] or d["criteria"] or "")[:65]
            if ev:
                lines.append(f"      {DIM}{ev}{RESET}")
        lines.append("")

    # ── Disproof ledger count ───────────────────────────────────────
    total_disproofs = conn.execute(
        "SELECT COUNT(*) as n FROM disproof_log"
    ).fetchone()["n"]
    pre_existing = conn.execute(
        "SELECT COUNT(*) as n FROM disproof_log "
        "WHERE criteria LIKE 'Pre-existing:%' "
        "OR evidence LIKE 'Imported from framework%'"
    ).fetchone()["n"]
    new_count = total_disproofs - pre_existing
    lines.append(
        f"  {DIM}Disproof ledger: {total_disproofs} total "
        f"({pre_existing} inherited, {new_count} new){RESET}"
    )

    # ── SOLVED alert ────────────────────────────────────────────────
    solved = conn.execute(
        "SELECT strategy, score, best_plaintext FROM hypotheses "
        "WHERE status = 'solved'"
    ).fetchall()
    if solved:
        lines.append("")
        lines.append(f"  {BG_GREEN}{WHITE}{BOLD}{'!' * WIDTH}{RESET}")
        lines.append(f"  {BG_GREEN}{WHITE}{BOLD}  SOLUTION DETECTED — ORACLE VALIDATED  {RESET}")
        lines.append(f"  {BG_GREEN}{WHITE}{BOLD}{'!' * WIDTH}{RESET}")
        for s in solved:
            lines.append(f"  {GREEN}{BOLD}Strategy:{RESET}  {s['strategy']}")
            lines.append(f"  {GREEN}{BOLD}Score:{RESET}     {s['score']}")
            lines.append(f"  {GREEN}{BOLD}Plaintext:{RESET} {s['best_plaintext']}")
        lines.append("")

    # ── Footer ──────────────────────────────────────────────────────
    lines.append(f"{CYAN}{DIM}{'─' * WIDTH}")
    lines.append(f"  DB: {db_path.name}  │  Ctrl+C to stop{RESET}")

    conn.close()
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="KryptosBot Live Monitor")
    parser.add_argument("--interval", type=int, default=3,
                        help="Refresh interval in seconds (default: 3)")
    parser.add_argument("--db", type=str, default=None,
                        help="Path to results database")
    args = parser.parse_args()

    if args.db:
        db_path = Path(args.db)
    else:
        script_dir = Path(__file__).resolve().parent
        db_path = script_dir.parent / "kryptosbot_results.db"

    if not db_path.exists():
        print(f"Database not found at {db_path}")
        print("Run from the project root, or specify --db path.")
        sys.exit(1)

    # Detect campaign start from earliest running hypothesis
    campaign_start = None
    try:
        conn = _connect(db_path)
        row = conn.execute(
            "SELECT MIN(created_at) as t FROM hypotheses WHERE status = 'running'"
        ).fetchone()
        if row and row["t"]:
            campaign_start = datetime.fromisoformat(row["t"])
        conn.close()
    except Exception:
        pass

    print(f"Monitoring {db_path} (Ctrl+C to stop)\n")

    try:
        while True:
            try:
                dashboard = render(db_path, campaign_start)
                print(CLEAR + dashboard, flush=True)
            except sqlite3.OperationalError:
                # DB locked momentarily — skip this tick
                pass
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n{DIM}Monitor stopped.{RESET}")


if __name__ == "__main__":
    main()
