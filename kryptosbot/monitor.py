#!/usr/bin/env python3
"""
KryptosBot Live Monitor

Run this in a separate terminal to watch campaign progress in real time.
Polls the SQLite database and displays a live status dashboard.

Usage:
    python monitor.py                  # Refresh every 5 seconds
    python monitor.py --interval 10    # Refresh every 10 seconds
    python monitor.py --watch-log      # Also tail the log file
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from kryptosbot.database import ResultsDB


CLEAR = "\033[2J\033[H"  # ANSI clear screen
BOLD = "\033[1m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"

STATUS_COLORS = {
    "queued": CYAN,
    "running": YELLOW,
    "promising": GREEN + BOLD,
    "disproved": RED,
    "inconclusive": RESET,
    "solved": GREEN + BOLD,
}


def render_dashboard(db: ResultsDB) -> str:
    """Build a text dashboard from current database state."""
    report = db.summary_report()
    lines: list[str] = []

    lines.append(f"{BOLD}{'=' * 72}")
    lines.append(f"  KryptosBot Live Monitor — {report['generated_at'][:19]} UTC")
    lines.append(f"{'=' * 72}{RESET}\n")

    # Status summary bar
    by_status = report["by_status"]
    total = report["total_hypotheses"]
    parts = []
    for status, color in STATUS_COLORS.items():
        count = by_status.get(status, 0)
        if count:
            parts.append(f"{color}{status}: {count}{RESET}")
    lines.append(f"  Total: {total}  |  " + "  |  ".join(parts))
    lines.append(f"  Disproofs logged: {report['total_disproofs']}\n")

    # Currently running
    running = db.get_running_sessions()
    if running:
        lines.append(f"{BOLD}  Active Workers ({len(running)}):{RESET}")
        for s in running:
            elapsed = ""
            if s.get("started_at"):
                # Simple elapsed time display
                try:
                    from datetime import datetime, timezone
                    start = datetime.fromisoformat(s["started_at"])
                    delta = datetime.now(timezone.utc) - start
                    mins = int(delta.total_seconds() // 60)
                    elapsed = f" ({mins}m)"
                except Exception:
                    pass
            lines.append(
                f"    {YELLOW}⚡{RESET} {s['worker_id']}: {s['strategy']}{elapsed}"
            )
        lines.append("")

    # Top candidates
    if report["top_candidates"]:
        lines.append(f"{BOLD}  Top Candidates:{RESET}")
        for c in report["top_candidates"][:5]:
            lines.append(
                f"    {GREEN}★{RESET} {c['strategy']}: "
                f"score={c['score']:.2f}  "
                f"text={c['best_plaintext'][:40]}"
            )
        lines.append("")

    # Recent disproofs
    disproofs = db.get_disproof_log()
    if disproofs:
        lines.append(f"{BOLD}  Recent Disproofs:{RESET}")
        for d in disproofs[:8]:
            lines.append(
                f"    {RED}✗{RESET} {d['strategy']}: {d['criteria'][:55]}"
            )
        lines.append("")

    # Solved?!
    solved = db.get_by_status(
        __import__("kryptosbot.config", fromlist=["HypothesisStatus"]).HypothesisStatus.SOLVED
    )
    if solved:
        lines.append(f"\n{GREEN}{BOLD}{'!' * 72}")
        lines.append(f"  POTENTIAL SOLUTION DETECTED")
        lines.append(f"{'!' * 72}{RESET}")
        for s in solved:
            lines.append(f"  Strategy: {s['strategy']}")
            lines.append(f"  Plaintext: {s['best_plaintext']}")
            lines.append(f"  Review immediately!")

    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="KryptosBot Live Monitor")
    parser.add_argument("--interval", type=int, default=5, help="Refresh interval in seconds")
    parser.add_argument("--db", type=str, default=None, help="Path to results database")
    args = parser.parse_args()

    project_root = Path(os.environ.get("KBOT_PROJECT_ROOT", ".")).resolve()
    db_path = Path(args.db) if args.db else project_root / "kryptosbot_results.db"

    if not db_path.exists():
        print(f"Database not found at {db_path}")
        print("Start a campaign first, or specify --db path.")
        sys.exit(1)

    db = ResultsDB(db_path)
    print(f"Monitoring {db_path} (Ctrl+C to stop)\n")

    try:
        while True:
            dashboard = render_dashboard(db)
            print(CLEAR + dashboard, flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nMonitor stopped.")


if __name__ == "__main__":
    main()
