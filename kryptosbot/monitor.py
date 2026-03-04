#!/usr/bin/env python3
"""
KryptosBot Live Monitor v3

Real-time campaign dashboard. Scans the results/campaigns/ directory for
active and completed agent sessions. Works with solve.py's JSON output.

Usage:
    python monitor.py                  # Auto-detect latest campaign
    python monitor.py --interval 1     # Faster refresh
    python monitor.py --campaign DIR   # Explicit campaign directory
"""

from __future__ import annotations

import argparse
import json
import os
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
BG_GREEN = "\033[42m"

WIDTH = 78


def _elapsed_since(ts: str | float | datetime) -> str:
    """Human-readable elapsed time."""
    try:
        if isinstance(ts, (int, float)):
            secs = ts
        elif isinstance(ts, datetime):
            secs = (datetime.now(timezone.utc) - ts).total_seconds()
        else:
            start = datetime.fromisoformat(ts)
            secs = (datetime.now(timezone.utc) - start).total_seconds()
        if secs < 0:
            secs = 0
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


def _file_size_str(path: Path) -> str:
    """Human-readable file size."""
    try:
        size = path.stat().st_size
        if size < 1024:
            return f"{size}B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f}K"
        else:
            return f"{size / (1024 * 1024):.1f}M"
    except Exception:
        return "?"


def _agent_status(agent_dir: Path, agent_name: str) -> dict:
    """Determine status of a single agent from its output files."""
    result_file = agent_dir / f"{agent_name}_result.json"
    raw_file = agent_dir / f"{agent_name}_raw.txt"

    info: dict = {
        "name": agent_name,
        "status": "queued",
        "elapsed": 0,
        "output_size": 0,
        "crib_found": False,
        "best_score": None,
        "verdict": None,
    }

    # If result JSON exists, agent is done
    if result_file.exists():
        try:
            data = json.loads(result_file.read_text())
            info["status"] = "completed"
            info["elapsed"] = data.get("elapsed_seconds", 0)
            info["output_size"] = data.get("output_length", 0)
            info["crib_found"] = data.get("crib_found", False)
            info["best_score"] = data.get("best_score")
            info["verdict"] = data.get("verdict")
            return info
        except Exception:
            info["status"] = "completed"
            return info

    # If raw file exists and is growing, agent is running
    if raw_file.exists():
        info["status"] = "running"
        info["output_size"] = raw_file.stat().st_size
        # Estimate elapsed from file mtime - ctime
        try:
            ctime = raw_file.stat().st_ctime
            mtime = raw_file.stat().st_mtime
            info["elapsed"] = mtime - ctime
            info["last_update"] = mtime
        except Exception:
            pass
        return info

    # No files yet — still queued/starting
    return info


def render(campaign_dir: Path, campaign_start: datetime | None) -> str:
    """Build the dashboard from a campaign directory snapshot."""
    lines: list[str] = []
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # ── Header ──────────────────────────────────────────────────────
    lines.append(f"{BOLD}{CYAN}{'─' * WIDTH}")
    lines.append(f"  KryptosBot Monitor  {DIM}│{RESET}{BOLD}{CYAN}  {now_str} UTC")
    lines.append(f"{'─' * WIDTH}{RESET}")

    # ── Scan agent directories ──────────────────────────────────────
    agents: list[dict] = []
    for entry in sorted(campaign_dir.iterdir()):
        if entry.is_dir() and not entry.name.startswith("."):
            agents.append(_agent_status(entry, entry.name))

    if not agents:
        lines.append(f"  {DIM}No agents found in {campaign_dir.name}{RESET}")
        lines.append(f"{CYAN}{DIM}{'─' * WIDTH}{RESET}")
        return "\n".join(lines)

    total = len(agents)
    running = sum(1 for a in agents if a["status"] == "running")
    completed = sum(1 for a in agents if a["status"] == "completed")
    queued = sum(1 for a in agents if a["status"] == "queued")
    crib_found = any(a["crib_found"] for a in agents)

    # ── Status summary ──────────────────────────────────────────────
    parts = []
    if running:
        parts.append(f"{YELLOW}⚡ running:{running}{RESET}")
    if completed:
        parts.append(f"{GREEN}✓ done:{completed}{RESET}")
    if queued:
        parts.append(f"{CYAN}○ queued:{queued}{RESET}")
    if crib_found:
        parts.append(f"{BG_GREEN}{WHITE}!!! CRIB !!!{RESET}")

    lines.append(f"  {BOLD}{total}{RESET} agents  │  " + "  ".join(parts))

    # Progress bar
    bar = _bar(completed, total)
    pct = (completed / total * 100) if total else 0
    elapsed_str = ""
    if campaign_start:
        elapsed_str = f"  {DIM}elapsed: {_elapsed_since(campaign_start)}{RESET}"
    lines.append(f"  [{bar}] {pct:.0f}% complete ({completed}/{total}){elapsed_str}")
    lines.append("")

    # ── Active agents ───────────────────────────────────────────────
    active = [a for a in agents if a["status"] == "running"]
    if active:
        lines.append(f"  {BOLD}{YELLOW}Active Agents ({len(active)}):{RESET}")
        for a in active:
            elapsed = _elapsed_since(a.get("elapsed", 0))
            size = a["output_size"]
            size_str = f"{size / 1024:.1f}K" if size > 1024 else f"{size}B"
            lines.append(
                f"    {YELLOW}⚡{RESET} {a['name']:<28} "
                f"{DIM}output: {size_str}  running: {elapsed}{RESET}"
            )
        lines.append("")

    # ── Queued agents ───────────────────────────────────────────────
    waiting = [a for a in agents if a["status"] == "queued"]
    if waiting:
        names = ", ".join(a["name"] for a in waiting)
        lines.append(f"  {DIM}Queued: {names}{RESET}")
        lines.append("")

    # ── Completed agents ────────────────────────────────────────────
    done_agents = [a for a in agents if a["status"] == "completed"]
    if done_agents:
        lines.append(f"  {BOLD}Completed ({len(done_agents)}):{RESET}")
        for a in done_agents:
            elapsed = _elapsed_since(a.get("elapsed", 0))
            score_str = ""
            if a["best_score"] is not None:
                score_str = f"  score={a['best_score']:.2f}"
            crib_str = f"  {GREEN}{BOLD}CRIB!{RESET}" if a["crib_found"] else ""
            verdict = ""
            if a["verdict"] and isinstance(a["verdict"], dict):
                vs = a["verdict"].get("verdict_status", "")
                if vs:
                    verdict = f"  [{vs}]"
            lines.append(
                f"    {GREEN}✓{RESET} {a['name']:<28} "
                f"{DIM}{elapsed}{RESET}{score_str}{verdict}{crib_str}"
            )
        lines.append("")

    # ── CRIB alert ──────────────────────────────────────────────────
    crib_agents = [a for a in agents if a["crib_found"]]
    if crib_agents:
        lines.append(f"  {BG_GREEN}{WHITE}{BOLD}{'!' * WIDTH}{RESET}")
        lines.append(f"  {BG_GREEN}{WHITE}{BOLD}  CRIB HIT DETECTED — CHECK RESULTS  {RESET}")
        lines.append(f"  {BG_GREEN}{WHITE}{BOLD}{'!' * WIDTH}{RESET}")
        for a in crib_agents:
            lines.append(f"  {GREEN}{BOLD}Agent:{RESET}  {a['name']}")
        lines.append("")

    # ── Tail hint ───────────────────────────────────────────────────
    if active:
        first_active = active[0]["name"]
        raw_path = campaign_dir / first_active / f"{first_active}_raw.txt"
        lines.append(f"  {DIM}Live output: tail -f {raw_path}{RESET}")

    # ── Footer ──────────────────────────────────────────────────────
    lines.append(f"{CYAN}{DIM}{'─' * WIDTH}")
    lines.append(f"  Campaign: {campaign_dir.name}  │  Ctrl+C to stop{RESET}")

    return "\n".join(lines)


def _find_latest_campaign(project_root: Path) -> Path | None:
    """Find the most recent campaign directory."""
    campaigns_dir = project_root / "results" / "campaigns"
    if not campaigns_dir.exists():
        return None
    dirs = sorted(
        (d for d in campaigns_dir.iterdir() if d.is_dir()),
        reverse=True,
    )
    return dirs[0] if dirs else None


def main() -> None:
    parser = argparse.ArgumentParser(description="KryptosBot Live Monitor v3")
    parser.add_argument("--interval", type=int, default=3,
                        help="Refresh interval in seconds (default: 3)")
    parser.add_argument("--campaign", type=str, default=None,
                        help="Path to campaign directory")
    # Legacy support
    parser.add_argument("--db", type=str, default=None,
                        help="(Legacy) Path to results database — ignored")
    args = parser.parse_args()

    if args.db:
        print(f"{YELLOW}Warning: --db is deprecated. Use --campaign instead.{RESET}")

    project_root = Path(__file__).resolve().parent.parent

    if args.campaign:
        campaign_dir = Path(args.campaign)
    else:
        campaign_dir = _find_latest_campaign(project_root)

    if campaign_dir is None or not campaign_dir.exists():
        print("No campaign found.")
        print(f"Run a campaign first: python3 kryptosbot/solve.py")
        print(f"Or specify a directory: python3 kryptosbot/monitor.py --campaign results/campaigns/YYYYMMDD_HHMMSS")
        sys.exit(1)

    # Estimate campaign start from directory name (YYYYMMDD_HHMMSS)
    campaign_start = None
    try:
        ts = campaign_dir.name
        campaign_start = datetime.strptime(ts, "%Y%m%d_%H%M%S").replace(
            tzinfo=timezone.utc
        )
    except Exception:
        pass

    print(f"Monitoring {campaign_dir} (Ctrl+C to stop)\n")

    try:
        while True:
            try:
                dashboard = render(campaign_dir, campaign_start)
                print(CLEAR + dashboard, flush=True)
            except Exception as e:
                print(f"  {RED}Error: {e}{RESET}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n{DIM}Monitor stopped.{RESET}")


if __name__ == "__main__":
    main()
